"""Payload mutation when a WAF blocks a probe.

Adaptive rate limiting already backs off when the edge pushes back. This is
the other half: a 403/406/429 on a payload that the baseline reached is a
signature match, not an answer, so the same probe is re-sent with a mutation
that preserves its semantics in the target language.

Two families, both deterministic and bounded:

* syntactic (padding, tabs, newlines, operator spacing) — decoded by the
  engine exactly like the original, but a naive signature regex no longer
  matches;
* transport (percent-encoding case, double encoding) — only the app's own
  decoding decides whether the payload survives.

Nothing here judges success. The caller re-runs its oracle on the mutated
response; a mutation that merely changes the status from 403 to 200 is not
a bypass and must not become a finding.
"""

from urllib.parse import parse_qsl, quote, urlsplit, urlunsplit

DEFAULT_PAYLOAD_BLOCK_CODES = (403, 406, 429, 501, 503)


def payload_block_codes(config: dict | None) -> set:
    """Status codes that mean "the edge rejected the payload", not "no".

    Separate from `waf.block_codes` (429/503) because a 403 is the normal
    signature-match answer for a probe while still being an authorization
    answer elsewhere. Callers opt in by asking for this set.
    """
    waf_cfg = (config or {}).get("waf") or {}
    raw = waf_cfg.get("payload_block_codes")
    codes = raw if raw else DEFAULT_PAYLOAD_BLOCK_CODES
    parsed = set()
    for code in codes:
        try:
            parsed.add(int(code))
        except (TypeError, ValueError):
            continue
    return parsed or set(DEFAULT_PAYLOAD_BLOCK_CODES)


def is_payload_blocked(result: dict, codes) -> bool:
    try:
        return int((result or {}).get("status") or 0) in set(codes)
    except (TypeError, ValueError):
        return False


def ssti_variants(payload: str) -> list[tuple[str, str]]:
    """Semantics-preserving template mutations, most likely first."""
    candidates = [
        ("spaced_operators", payload.replace("*", " * ")),
        ("outer_space", payload.replace("{{", "{{ ").replace("}}", " }}")),
        ("tab_padding", payload.replace("{{", "{{\t").replace("}}", "\t}}")),
        ("newline_padding",
         payload.replace("{{", "{{\n").replace("}}", "\n}}")),
        ("mixed_whitespace",
         payload.replace("{{", "{{ ").replace("}}", "\t}}")),
    ]
    seen = {payload}
    variants = []
    for name, value in candidates:
        if value != payload and value not in seen:
            seen.add(value)
            variants.append((name, value))
    return variants


def percent_encode(value: str, *, upper: bool = True,
                   keep_star: bool = False) -> str:
    out = []
    for char in value or "":
        if char.isalnum() or char in "-._~" or (keep_star and char == "*"):
            out.append(char)
            continue
        for byte in char.encode("utf-8"):
            out.append(f"%{byte:02X}" if upper else f"%{byte:02x}")
    return "".join(out)


def encoded_variants(payload: str) -> list[tuple[str, str]]:
    """(label, wire_value) pairs; wire_value is already percent-encoded."""
    once = percent_encode(payload, upper=False, keep_star=True)
    double = quote(quote(payload, safe=""), safe="")
    variants = []
    if once != payload:
        variants.append(("percent_lower", once))
    if double != once:
        variants.append(("double_percent", double))
    return variants


def raw_param_url(url: str, param: str, wire_value: str) -> str:
    """Set one query parameter to an already-encoded wire value.

    `inject_param` percent-encodes its input, which is right for normal
    probes and wrong for transport mutations: it would turn `%7B` into
    `%257B`. Here the caller supplies the exact bytes the server should
    receive, and everything else in the URL is preserved.
    """
    parts = urlsplit(url)
    pairs = [(k, v) for k, v in parse_qsl(parts.query, keep_blank_values=True)
             if k != param]
    pairs.append((param, wire_value))
    query = "&".join(f"{quote(k, safe='')}={v}" for k, v in pairs)
    return urlunsplit((parts.scheme, parts.netloc, parts.path, query,
                       parts.fragment))

