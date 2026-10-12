"""Stage 5: Business-logic flaws on the operator's own account.

Two halves with different risk profiles:

A. Privilege-field surface (read-only, always on). The mass_assignment
   write test stays opt-in because it mutates the test account, which
   means most runs never learn where it *would* apply. This pass reads
   the caller's own record and reports which privilege-bearing fields
   exist on it — INFO recon that turns enabling the write test from a
   blind flag into a pointed decision.

B. Cart tamper probes (own account, reversible). Quantity, price and
   discount fields the client controls are replayed with hostile
   values and the totals compared. Proof is differential — the total
   moved in the attacker's favour — never "the parameter exists".
   Every probe is restored (quantity reset, test items removed) and
   the restore is verified, so the test account is left as found.

Safety rules: a verified identity is required (anonymous carts prove
nothing attributable); only the caller's own objects are touched;
no checkout is ever completed (totals are read, never paid); request
volume is bounded by max_probes.
"""

from __future__ import annotations

import json

from core.auth_harness import AuthHarness, Identity
from modules.base import BaseModule
from modules.mass_assignment import PRIVILEGE_FIELDS


# Path tokens that suggest a transactional surface worth probing.
CART_TOKENS = (
    "cart", "basket", "checkout", "order", "payment", "purchase",
)

# Small guess list when recon found no cart endpoints. Bounded and
# conventional; configured endpoints win when present.
CART_PATHS = (
    "/api/cart", "/api/basket", "/api/checkout", "/api/orders",
    "/api/v1/cart", "/api/v1/orders", "/rest/basket",
)

# (label, field, hostile values): each value must be reversible by
# re-setting a sane one afterwards.
TAMPER_PROBES = (
    ("zero-quantity", "quantity", [0]),
    ("negative-quantity", "quantity", [-1]),
    ("bulk-quantity", "quantity", [999999]),
    ("price-override", "price", [0.01]),
    ("amount-override", "amount", [0.01]),
    ("total-override", "total", [0.01]),
    ("discount-override", "discount", [100]),
)


class BusinessLogic(BaseModule):
    id = "business_logic"
    name = "Business Logic"
    stage = 5
    detectability = "medium"
    depends_on = ["parameter_discovery"]
    active = True

    async def run(self) -> str:
        cfg = self._cfg()
        if cfg.get("enabled", True) is False:
            self.state.skip_module(self.id, "disabled in config")
            return "skipped"

        harness = AuthHarness(self.config)
        harness.adopt_discovered(self.state, log=self.log)
        identities = await harness.establish_all(self._base_url())
        if not identities:
            self.state.skip_module(self.id, "no verified identity to test with")
            return "skipped"
        attacker = identities[0]

        surface = await self._surface_pass(harness, attacker, cfg)
        tamper = await self._tamper_pass(harness, attacker, cfg)

        for finding in surface + tamper:
            self.state.add_finding(**finding)

        self.state.complete_module(self.id)
        self.log(
            f"business logic: {len(surface)} surface note(s) | "
            f"{len(tamper)} tamper finding(s)"
        )
        return "done"

    # ── A. Privilege-field surface (read-only) ────────────────────

    async def _surface_pass(self, harness: AuthHarness, attacker: Identity,
                            cfg: dict) -> list:
        """Which privilege-bearing fields exist on our own record.

        INFO either way: presence is recon for the mass_assignment write
        test, not a vulnerability — the server may whitelist perfectly
        well. Absence is still recorded so the operator knows the write
        test has nothing to aim at.
        """
        found: dict[str, list] = {}
        for target in await self._self_endpoints(harness, attacker, cfg):
            record = await self._get_json(harness, attacker.name, target)
            if not isinstance(record, dict):
                continue
            present = sorted({f for cand in self._records(record)
                              for f in PRIVILEGE_FIELDS if f in cand})
            if present:
                found[target] = present
        self.state.add_asset(
            "logic_surface",
            f"logic_surface:{self.domain}",
            self.domain,
            confidence="CONFIRMED",
            sources=[self.id],
            attrs={"self_endpoints": sorted(found),
                   "privilege_fields": sorted(
                       {f for fields in found.values() for f in fields})},
        )
        if not found:
            return []
        total = sum(len(fields) for fields in found.values())
        return [{
            "title": f"Mass-assignment surface: {total} privilege "
                     f"field(s) on the caller's own record(s)",
            "severity": "INFO",
            "confidence": "FIRM",
            "category": "Business Logic",
            "description": (
                f"{len(found)} readable self-record(s) contain "
                f"privilege-bearing fields: "
                + "; ".join(f"{url}: {', '.join(fields)}"
                            for url, fields in sorted(found.items()))
                + ". Presence is not a bug — the endpoint may whitelist "
                f"writes — but it is where the mass_assignment write test "
                f"applies. Enable modules.mass_assignment.enabled to test "
                f"binding."
            ),
            "evidence": [f"{url}: {', '.join(fields)}"
                         for url, fields in sorted(found.items())],
            "asset_keys": [f"url:{url}" for url in sorted(found)],
            "remediation": "No action unless the write test confirms "
                           "binding; then allowlist update fields.",
        }]

    # ── B. Cart tamper probes (reversible) ────────────────────────

    async def _tamper_pass(self, harness: AuthHarness, attacker: Identity,
                           cfg: dict) -> list:
        try:
            max_probes = max(1, min(40, int(cfg.get("max_probes", 12))))
        except (TypeError, ValueError):
            max_probes = 12
        endpoints = self._cart_endpoints(cfg)
        if not endpoints:
            self.log("  no cart endpoints discovered or configured")
            return []

        findings = []
        sent = 0
        for endpoint in endpoints:
            baseline = await self._cart_state(harness, attacker, endpoint)
            if baseline is None:
                continue
            for label, field, values in TAMPER_PROBES:
                for hostile in values:
                    if sent >= max_probes:
                        break
                    sent += 1
                    outcome = await self._tamper_once(
                        harness, attacker, endpoint, baseline,
                        label, field, hostile)
                    if outcome:
                        findings.append(outcome)
                if sent >= max_probes:
                    break
            if sent >= max_probes:
                break
        self.log(f"  cart probes sent: {sent}")
        return findings

    async def _tamper_once(self, harness: AuthHarness, attacker: Identity,
                           endpoint: str, baseline: dict,
                           label: str, field: str, hostile) -> dict | None:
        """Send one hostile value, compare, restore, verify restore."""
        base_total = self._total_of(baseline)
        probe = await self._write_json(
            harness, attacker.name, endpoint, {field: hostile})
        if not isinstance(probe, dict):
            return None
        new_total = self._total_of(probe)
        restored = await self._restore_cart(harness, attacker, endpoint,
                                            baseline)
        if not self._moved_in_attacker_favour(base_total, new_total,
                                              label, hostile,
                                              self._field_of(probe,
                                                             "quantity")):
            return None
        if not restored:
            self.log(f"  WARNING: cart restore unverified after {label} "
                     f"on {endpoint} — check the test account")
        return {
            "title": f"Cart logic flaw: {label} accepted "
                     f"({endpoint})",
            "severity": "HIGH",
            "confidence": "CONFIRMED",
            "category": "Business Logic",
            "description": (
                f"Sending {field}={hostile!r} to the caller's own cart at "
                f"{endpoint} moved the total from {base_total!r} to "
                f"{new_total!r}. The server trusts client-side commercial "
                f"values."
                + ("" if restored else " The cart could NOT be restored "
                   "automatically — remove test items by hand.")
            ),
            "evidence": [
                f"Endpoint: {endpoint}",
                f"Probe: {field}={hostile!r}",
                f"Total before: {base_total!r}",
                f"Total after: {new_total!r}",
                f"Restored: {restored}",
            ],
            "asset_keys": [f"url:{endpoint}"],
            "remediation": "Price, quantity and discount arithmetic belongs "
                           "server-side: recompute totals from catalogue "
                           "prices, reject non-positive quantities, and "
                           "validate coupon state transitions.",
            "verified": True,
            "verification": {"method": "cart_total_changed",
                             "url": endpoint, "param": field},
        }

    # ── Proof rules ───────────────────────────────────────────────

    @staticmethod
    def _records(cart: dict) -> list:
        """The record plus one envelope level beneath it.

        APIs wrap payloads ({"status":..,"data":{..}}); the commercial
        fields live in the inner dict. Top level first, then each
        nested dict — one level covers the envelope convention without
        chasing arbitrary depth.
        """
        if not isinstance(cart, dict):
            return []
        return [cart] + [v for v in cart.values()
                         if isinstance(v, dict)]

    @classmethod
    def _field_of(cls, cart: dict, *names):
        """First matching field across the envelope, else None."""
        for record in cls._records(cart):
            for name in names:
                if name in record:
                    return record[name]
        return None

    @classmethod
    def _total_of(cls, cart: dict) -> object:
        """The payable figure, or a marker that none was found."""
        if not isinstance(cart, dict):
            return "<absent>"
        for key in ("total", "amount", "grand_total", "payable",
                    "total_price", "order_total"):
            value = cls._field_of(cart, key)
            if isinstance(value, (int, float)):
                return value
        items = cls._field_of(cart, "items")
        if isinstance(items, list) and items:
            first = items[0] if isinstance(items[0], dict) else {}
            for key in ("total", "price", "amount", "quantity"):
                if key in first and isinstance(first[key], (int, float)):
                    return first[key]
        return "<absent>"

    @staticmethod
    def _moved_in_attacker_favour(before: object, after: object,
                                  label: str, hostile,
                                  echoed=None) -> bool:
        """Did the hostile value take effect against the attacker's
        interest? Two shapes: totals that moved the attacker's way
        (price/amount/total/discount), and invalid quantities the server
        stored (zero/negative — storing them is the flaw even before any
        total recomputes). Bulk additionally requires the server to have
        taken the quantity, and the total not to have scaled with it. A
        total that vanishes, turns textual, or stays put is not proof —
        except a stored zero/negative quantity, which is proof by
        itself."""
        if label in ("zero-quantity", "negative-quantity"):
            return echoed == hostile
        if not isinstance(before, (int, float)) or \
                not isinstance(after, (int, float)):
            return False
        if label == "bulk-quantity":
            return echoed == hostile and after <= before and before > 0
        return after < before

    # ── Discovery & plumbing ──────────────────────────────────────

    def _cart_endpoints(self, cfg: dict) -> list[str]:
        """Configured endpoints, recon api_endpoints with cart tokens,
        then the conventional guess list — always, capped at 8.

        The guesses run even when recon found something: a discovered
        page like /order-history is not a cart API, and skipping the
        guesses because a page matched would leave the known shapes
        untested.
        """
        found: list[str] = []
        for candidate in cfg.get("endpoints") or []:
            url = self._absolute(str(candidate))
            if url and url not in found:
                found.append(url)
        for asset in self.state.get_assets_by_type("api_endpoint"):
            value = str(asset.get("value", "") or "")
            if not value.startswith(("http://", "https://")):
                continue
            if self.domain not in value:
                continue
            lowered = value.lower()
            if any(token in lowered for token in CART_TOKENS):
                if value not in found:
                    found.append(value)
        for path in CART_PATHS:
            if len(found) >= 8:
                break
            url = self._absolute(path)
            if url and url not in found:
                found.append(url)
        return found[:8]

    async def _cart_state(self, harness: AuthHarness, attacker: Identity,
                          endpoint: str) -> dict | None:
        """GET the cart; empty write when GET is not JSON (some carts are
        write-only views). None means no readable state to compare."""
        result = await self._get_json(harness, attacker.name, endpoint)
        if isinstance(result, dict):
            return result
        return await self._write_json(harness, attacker.name, endpoint, {})

    async def _restore_cart(self, harness: AuthHarness, attacker: Identity,
                            endpoint: str, baseline: dict) -> bool:
        """Write the baseline's commercial fields back and verify.

        Resetting only quantity/items leaves price/amount/total/discount
        probes in place — the next item added can inherit a poisoned
        price. The restore replays every commercial field the baseline
        had, then requires the total and quantity to match the baseline
        exactly. Anything less reports unverified so the operator checks
        the test account by hand.
        """
        try:
            # Envelope-aware: the baseline's quantity may live under
            # "data" while the write endpoint takes it top-level (Juice
            # reads {"quantity"} and returns {"status","data"}). Replay
            # flat; verification below compares across the envelope.
            replay = {}
            for key in ("quantity", "price", "amount", "total",
                        "discount", "items"):
                value = self._field_of(baseline, key)
                if value is not None:
                    replay[key] = value
            if replay:
                await self._write_json(harness, attacker.name, endpoint,
                                       replay)
            state = await self._cart_state(harness, attacker, endpoint)
            if not isinstance(state, dict):
                return False
            for key in ("total", "quantity"):
                if self._field_of(baseline, key) is not None and \
                        self._field_of(state, key) != \
                        self._field_of(baseline, key):
                    return False
            # Keys the probe introduced that the baseline never had stay
            # behind: replay cannot delete what the API has no delete
            # for, and a lingering amount/discount can poison the next
            # item added. Non-empty leftovers fail the restore openly.
            # Compared across the envelope, like everything else here.
            base_keys = set()
            for record in self._records(baseline):
                base_keys.update(record.keys())
            for record in self._records(state):
                for key in ("price", "amount", "total", "discount",
                            "quantity"):
                    if key not in base_keys and key in record:
                        value = record.get(key)
                        if value not in (None, "", 0, 0.0, [], {}):
                            return False
            return True
        except Exception:
            return False

    async def _self_endpoints(self, harness: AuthHarness, attacker: Identity,
                              cfg: dict) -> list[str]:
        """Readable self-record URLs: configured ones first, then the
        usual /me shapes. All of them, not just the first hit — a cart
        endpoint answers 200 without carrying any privilege fields."""
        found = []
        from modules.mass_assignment import SELF_PATHS
        candidates = [self._absolute(str(c))
                      for c in cfg.get("endpoints") or []]
        candidates += [self._absolute(path) for path in SELF_PATHS]
        for url in candidates:
            if not url or url in found:
                continue
            result = await self._get(harness, attacker.name, url)
            if result.get("status") == 200 and result.get("body"):
                found.append(url)
        return found

    async def _self_endpoint(self, harness: AuthHarness, attacker: Identity,
                             cfg: dict) -> str:
        endpoints = await self._self_endpoints(harness, attacker, cfg)
        return endpoints[0] if endpoints else ""

    def _base_url(self) -> str:
        return str(self.target.get("base_url")
                   or (self.base_url if self.domain else ""))

    def _absolute(self, path: str) -> str:
        path = (path or "").strip()
        if not path:
            return ""
        if path.startswith(("http://", "https://")):
            return path
        base = self._base_url().rstrip("/")
        return f"{base}/{path.lstrip('/')}" if base else ""

    async def _get(self, harness: AuthHarness, identity_name: str,
                   url: str) -> dict:
        result = await harness.request(identity_name, url, method="GET")
        if result.get("status", 0) in self._waf_codes():
            self.state.record_waf_block(url, result.get("status", 0))
        return result

    async def _get_json(self, harness: AuthHarness, identity_name: str,
                        url: str):
        result = await self._get(harness, identity_name, url)
        if result.get("status", 0) != 200 or not result.get("body"):
            return None
        try:
            return json.loads(result["body"])
        except (TypeError, ValueError):
            return None

    async def _write_json(self, harness: AuthHarness, identity_name: str,
                          url: str, payload: dict):
        """POST, then PUT when POST yields nothing carts accept.

        Cart updates speak PUT as often as POST (/api/Baskets/:id), and
        trying only one verb mistakes a method mismatch for a whitelist.
        The fallback costs one extra request per hostile value, inside
        the same probe budget.
        """
        for method in ("POST", "PUT"):
            result = await harness.request(
                identity_name, url, method=method,
                headers={"Content-Type": "application/json"},
                data=json.dumps(payload),
            )
            if result.get("status", 0) in self._waf_codes():
                self.state.record_waf_block(url, result.get("status", 0))
            if result.get("status", 0) >= 400 or not result.get("body"):
                continue
            try:
                return json.loads(result["body"])
            except (TypeError, ValueError):
                continue
        return None

    async def _post_json(self, harness: AuthHarness, identity_name: str,
                         url: str, payload: dict):
        return await self._write_json(harness, identity_name, url, payload)

    def _waf_codes(self) -> set:
        codes = (self.waf_config or {}).get("block_codes") or [429, 503]
        return set(codes) if isinstance(codes, (list, tuple, set)) else {429, 503}

    def _cfg(self) -> dict:
        cfg = self.config.get("modules", {}).get(self.id, {})
        return cfg if isinstance(cfg, dict) else {}
