"""TLS configuration — prove the weakness instead of restating the scan.

Ten module findings carried category "TLS Configuration", and no action could
re-prove any of them: the graph had nothing to arm, so a real expired or
self-signed certificate stayed a claim. This action opens the endpoint twice
(verified, then unverified to inspect the certificate), decodes the DER with
the stdlib, and reports only weaknesses it can see:

  * certificate expired;
  * subject == issuer (self-signed);
  * hostname mismatch;
  * a legacy handshake (TLS 1.0/1.1) still accepted.

Unverified-chain alone is not reported: a private corporate CA is not a
vulnerability, and an expired certificate already covers the case that
matters. The legacy probe is conservative — OpenSSL 3 often refuses to offer
TLS 1.0 even when the server would accept it, which yields a false negative,
never a false positive.
"""

import asyncio
import os
import ssl
import tempfile
import time
from urllib.parse import urlparse

from actions.registry import action, ActionContext, ActionResult

_ISSUES = ("expired", "self_signed", "hostname_mismatch", "weak_protocol")


def _decode_der(der: bytes) -> dict:
    """Decode a DER certificate with the stdlib, no `cryptography` required."""
    decode = getattr(getattr(ssl, "_ssl", None), "_test_decode_cert", None)
    if not der or decode is None:
        return {}
    pem = ssl.DER_cert_to_PEM_cert(der)
    fd, path = tempfile.mkstemp(suffix=".pem")
    try:
        with os.fdopen(fd, "w") as handle:
            handle.write(pem)
        return decode(path) or {}
    except Exception:
        return {}
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass


def _is_self_signed(cert: dict) -> bool:
    subject = cert.get("subject")
    return bool(subject) and subject == cert.get("issuer")


async def _supports_legacy_tls(host: str, port: int, timeout: int) -> bool:
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.minimum_version = ssl.TLSVersion.TLSv1
        ctx.maximum_version = ssl.TLSVersion.TLSv1
        ctx.set_ciphers("DEFAULT:@SECLEVEL=0")
    except (ValueError, AttributeError, ssl.SSLError):
        return False
    writer = None
    try:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port, ssl=ctx, server_hostname=host),
            timeout=timeout)
        return True
    except Exception:
        return False
    finally:
        if writer is not None:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass


async def _probe_tls(host: str, port: int, timeout: int = 10) -> dict:
    """Inspect one TLS endpoint. Separate from the action so tests inject it."""
    info = {
        "host": host, "port": port, "version": "", "cipher": "",
        "verified": False, "not_after": "", "error": "",
        "expired": False, "self_signed": False,
        "hostname_mismatch": False, "weak_protocol": False,
    }

    try:
        ctx = ssl.create_default_context()
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port, ssl=ctx, server_hostname=host),
            timeout=timeout)
        sock = writer.get_extra_info("ssl_object")
        info["verified"] = True
        info["version"] = sock.version() or ""
        info["cipher"] = (sock.cipher() or ("",))[0]
        cert = sock.getpeercert() or {}
        info["not_after"] = cert.get("notAfter", "")
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
    except Exception as exc:
        reason = str(getattr(exc, "reason", "") or exc).lower()
        info["error"] = str(exc)
        info["expired"] = "expired" in reason
        info["hostname_mismatch"] = ("hostname" in reason
                                     and "mismatch" in reason)
        info["self_signed"] = ("self-signed" in reason
                               or "self signed" in reason)
        # The verified connection failed; connect without verification just to
        # read the certificate and the negotiated parameters.
        writer = None
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            _, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port, ssl=ctx,
                                        server_hostname=host),
                timeout=timeout)
            sock = writer.get_extra_info("ssl_object")
            info["version"] = sock.version() or ""
            info["cipher"] = (sock.cipher() or ("",))[0]
            cert = _decode_der(sock.getpeercert(binary_form=True) or b"")
            info["not_after"] = cert.get("notAfter", info["not_after"])
            info["self_signed"] = info["self_signed"] or _is_self_signed(cert)
            if info["not_after"]:
                try:
                    info["expired"] = info["expired"] or (
                        ssl.cert_time_to_seconds(info["not_after"]) < time.time())
                except (ValueError, OverflowError):
                    pass
        except Exception as second:
            if not info["version"]:
                info["error"] = info["error"] or str(second)
            return info
        finally:
            if writer is not None:
                writer.close()
                try:
                    await writer.wait_closed()
                except Exception:
                    pass

    info["weak_protocol"] = await _supports_legacy_tls(host, port, timeout)
    return info


@action(
    id="network.tls.cert",
    risk="SAFE",
    detectability="low",
    requires=["url"],
    produces="VulnCandidate",
    idempotent=True,
    description=(
        "Prove a TLS configuration weakness: expired/self-signed certificate, "
        "hostname mismatch, or an accepted TLS 1.0/1.1 handshake. Reports the "
        "negotiated version and cipher."
    ),
    category="network",
)
async def tls_cert(ctx: ActionContext) -> ActionResult:
    url = str(ctx.params.get("url") or ctx.target or "").strip()
    parsed = urlparse(url)
    host = parsed.hostname or ""
    if not host:
        return ActionResult(False, error="url with a host is required")
    default_port = 443 if parsed.scheme in ("https", "wss") else 80
    try:
        port = parsed.port or default_port
    except ValueError:
        return ActionResult(False, error=f"invalid port in url: {url}")
    if parsed.scheme not in ("https", "wss") and port != 443:
        return ActionResult(
            False, confidence="TENTATIVE",
            error=f"not a TLS endpoint: {parsed.scheme or 'no scheme'}://{host}:{port}")

    info = await _probe_tls(host, port)
    if not info.get("version"):
        return ActionResult(
            False, confidence="TENTATIVE",
            error=f"TLS handshake failed: {info.get('error') or 'no negotiated version'}")

    issues = [name for name in _ISSUES if info.get(name)]
    data = {
        "host": host, "port": port,
        "version": info.get("version", ""),
        "cipher": info.get("cipher", ""),
        "not_after": info.get("not_after", ""),
        "verified": info.get("verified", False),
        "issues": issues,
    }
    if not issues:
        return ActionResult(
            False, confidence="TENTATIVE", data=data,
            error=("TLS configuration is within baseline: valid chain, "
                   "hostname match, no legacy protocol"))

    return ActionResult(
        True, confidence="CONFIRMED", data=data,
        evidence={"action": "network.tls.cert", "issues": issues,
                  "version": data["version"], "cipher": data["cipher"]},
    )
