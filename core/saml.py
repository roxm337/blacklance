"""SAML message analysis — structure, never signature verification.

A SAML response is an XML document in which the identity is a *claim* and the
signature is the only thing that makes it more than that. Almost every SAML
break in the wild comes from the gap between those two: the SP reads an
assertion that the IdP did not sign (signature exclusion / XML wrapping), or
it reads a NameID an attacker could influence (comment injection), or it never
enforces the audience and expiry conditions the assertion carries.

This module reports that structure. It deliberately does **not** verify
signatures: verification needs the IdP's certificate and exact
canonicalisation rules, and a wrong "valid" would be worse than no answer.
`signature_exclusion` therefore means "the response is signed and an assertion
inside it is not", which is the precondition a wrapping attack needs, not proof
that one works. Only a replay against the real ACS can prove that.

Parsing is locked down: DTDs and entity declarations are rejected outright and
lxml runs with entity resolution and network access disabled, so a hostile
message cannot expand into a memory bomb or fetch anything.
"""

from __future__ import annotations

import base64
import binascii
import zlib
from urllib.parse import unquote, unquote_plus

MAX_MESSAGE_BYTES = 2 * 1024 * 1024

_NAMEID_FORMATS = {
    "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress": "emailAddress",
    "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified": "unspecified",
    "urn:oasis:names:tc:SAML:1.1:nameid-format:transient": "transient",
    "urn:oasis:names:tc:SAML:1.1:nameid-format:persistent": "persistent",
    "urn:oasis:names:tc:SAML:2.0:nameid-format:entity": "entity",
    "urn:oasis:names:tc:SAML:2.0:nameid-format:kerberos": "kerberos",
}

_STATUS_SUCCESS = "urn:oasis:names:tc:SAML:2.0:status:Success"

# Codes and their structural meaning. Severity describes impact *if the SP
# accepts this message*, which is exactly the assumption a captured response
# makes; the detail text says so.
_FINDING_SEVERITY = {
    "signature_exclusion": "HIGH",
    "no_signature_anywhere": "MEDIUM",
    "nameid_comment_injection": "MEDIUM",
    "conditions_missing": "MEDIUM",
    "audience_missing": "MEDIUM",
    "acs_plaintext": "MEDIUM",
    "no_signing_key": "MEDIUM",
    "want_assertions_signed_false": "MEDIUM",
    "authn_requests_unsigned": "LOW",
    "want_assertions_signed_absent": "LOW",
    "nameid_format_unspecified": "LOW",
    "subject_confirmation_missing": "LOW",
    "status_not_success": "LOW",
    "no_encryption_key": "LOW",
}


class SamlError(ValueError):
    """The value is not a usable SAML message."""


def _etree():
    try:
        from lxml import etree
    except ImportError as exc:  # pragma: no cover - lxml is a hard dependency
        raise SamlError("lxml is required to parse SAML messages") from exc
    return etree


def _b64_bytes(candidate: str):
    compact = candidate.rstrip("=")
    try:
        return base64.b64decode(compact + "=" * (-len(compact) % 4),
                                validate=True)
    except (binascii.Error, ValueError):
        return None


def _inflate(raw: bytes):
    try:
        return zlib.decompress(raw, -15)
    except zlib.error:
        return None


def decode_message(value: str) -> bytes:
    """Normalise what an HTTP binding delivers into XML bytes.

    Accepts raw XML, base64 (POST binding, possibly URL-encoded and
    line-wrapped), and base64 of raw DEFLATE (HTTP-Redirect binding).

    A literal `+` is valid base64 and is also what a form decoder produces
    from a space, so both the raw and percent-decoded forms are tried; the
    first one that yields XML wins. Whitespace is stripped before decoding
    because base64 line wrapping is common and never significant.
    """
    text = str(value or "").strip()
    if not text:
        raise SamlError("empty message")
    if len(text) > MAX_MESSAGE_BYTES:
        raise SamlError("message too large")
    if text.lstrip().startswith("<"):
        return text.encode("utf-8", errors="replace")

    compact = "".join(text.split())
    tried = []
    for candidate in (compact, unquote(compact), unquote_plus(compact)):
        if candidate in tried:
            continue
        tried.append(candidate)
        decoded = _b64_bytes(candidate)
        if decoded is None:
            continue
        if decoded.lstrip().startswith(b"<"):
            return decoded
        inflated = _inflate(decoded)
        if inflated is not None and inflated.lstrip().startswith(b"<"):
            return inflated
    raise SamlError("value is neither XML nor base64")


def parse(xml_bytes: bytes):
    """Parse one SAML document with entity expansion and DTDs disabled."""
    raw = bytes(xml_bytes or b"")
    if not raw:
        raise SamlError("empty message")
    if len(raw) > MAX_MESSAGE_BYTES:
        raise SamlError("message too large")
    head = raw[:4096].lower()
    if b"<!doctype" in head or b"<!entity" in head:
        raise SamlError("DTD/entity declarations are not allowed")
    etree = _etree()
    parser = etree.XMLParser(resolve_entities=False, no_network=True,
                             load_dtd=False, huge_tree=False, recover=False)
    try:
        return etree.fromstring(raw, parser=parser)
    except etree.XMLSyntaxError as exc:
        raise SamlError(f"invalid XML: {exc}") from exc


def _local(tag) -> str:
    tag = str(tag or "")
    return tag.rsplit("}", 1)[-1]


def _children(element, name: str) -> list:
    return [child for child in list(element) if _local(child.tag) == name]


def _descendants(element, name: str) -> list:
    return [node for node in element.iter() if _local(node.tag) == name]


def _first(element, path: list):
    node = element
    for name in path:
        found = _children(node, name)
        if not found:
            return None
        node = found[0]
    return node


def _text(element) -> str:
    if element is None:
        return ""
    return "".join(element.itertext()).strip()


def _has_signature(element) -> bool:
    return any(_local(child.tag) == "Signature" for child in list(element))


def _finding(code: str, detail: str) -> dict:
    return {"code": code, "severity": _FINDING_SEVERITY.get(code, "LOW"),
            "detail": detail}


def _assertion_element(element) -> dict:
    name_id = _first(element, ["Subject", "NameID"])
    name_id_xml = ""
    if name_id is not None:
        etree = _etree()
        name_id_xml = etree.tostring(name_id, encoding="unicode")
    restrictions = _descendants(element, "AudienceRestriction")
    audiences = []
    for restriction in restrictions:
        audiences += [_text(audience)
                      for audience in _children(restriction, "Audience")]
    conditions = _first(element, ["Conditions"])
    confirmation = _first(element, ["Subject", "SubjectConfirmation"])
    confirmation_data = _first(element, ["Subject", "SubjectConfirmation",
                                         "SubjectConfirmationData"])
    return {
        "id": str(element.get("ID") or ""),
        "signed": _has_signature(element),
        "issuer": _text(_first(element, ["Issuer"])),
        "name_id": _text(name_id),
        "name_id_format": str(name_id.get("Format") or "")
        if name_id is not None else "",
        "name_id_kind": _NAMEID_FORMATS.get(
            str(name_id.get("Format") or "") if name_id is not None else "",
            ""),
        "name_id_xml": name_id_xml,
        "audiences": [audience for audience in audiences if audience],
        "not_before": str(conditions.get("NotBefore") or "")
        if conditions is not None else "",
        "not_on_or_after": str(conditions.get("NotOnOrAfter") or "")
        if conditions is not None else "",
        "has_conditions": conditions is not None,
        "has_subject_confirmation": confirmation is not None,
        "recipient": str(confirmation_data.get("Recipient") or "")
        if confirmation_data is not None else "",
        "in_response_to": str(confirmation_data.get("InResponseTo") or "")
        if confirmation_data is not None else "",
        "status": "",
    }


def _response_status(root) -> str:
    status = _first(root, ["Status", "StatusCode"])
    return str(status.get("Value") or "") if status is not None else ""


def analyze(xml_bytes: bytes) -> dict:
    """Report the identity-bearing structure of one SAML message.

    Raises `SamlError` when the value is not a parseable SAML document.
    """
    root = parse(xml_bytes)
    message_type = _local(root.tag)
    response_signed = _has_signature(root)

    if message_type == "Assertion":
        elements = [root]
    else:
        elements = _descendants(root, "Assertion")
    assertions = [_assertion_element(element) for element in elements]

    status_value = _response_status(root)
    findings = []
    if message_type == "Response":
        if response_signed and any(not item["signed"] for item in assertions):
            findings.append(_finding(
                "signature_exclusion",
                "The Response carries a signature but at least one contained "
                "Assertion does not. An SP that reads identity from the "
                "unsigned assertion accepts a claim nobody signed; this is "
                "the precondition for XML signature wrapping."))
        if not response_signed and assertions and \
                not any(item["signed"] for item in assertions):
            findings.append(_finding(
                "no_signature_anywhere",
                "Neither the Response nor any Assertion is signed. As "
                "received, the identity in this message is unauthenticated."))
        if status_value and status_value != _STATUS_SUCCESS:
            findings.append(_finding(
                "status_not_success",
                f"StatusCode is {status_value}, not Success."))

    for item in assertions:
        if "<!--" in item["name_id_xml"]:
            findings.append(_finding(
                "nameid_comment_injection",
                "The NameID contains an XML comment. A comment injected into "
                f"{item['name_id'] or 'the NameID'} is the classic SAML "
                "comment-injection payload; it only matters if the SP reads "
                "the NameID through a parser that drops comments, so replay "
                "it to confirm."))
        if not item["has_conditions"]:
            findings.append(_finding(
                "conditions_missing",
                "No Conditions element: the assertion carries no "
                "NotBefore/NotOnOrAfter window for the SP to enforce."))
        if not item["audiences"]:
            findings.append(_finding(
                "audience_missing",
                "No AudienceRestriction: the assertion is not bound to the "
                "intended SP, so a response for another SP can be replayed."))
        if item["name_id"] and item["name_id_kind"] in ("", "unspecified"):
            findings.append(_finding(
                "nameid_format_unspecified",
                "NameID has no specific format; the SP has to guess which "
                "identifier it is reading."))
        if not item["has_subject_confirmation"]:
            findings.append(_finding(
                "subject_confirmation_missing",
                "No SubjectConfirmation: nothing binds the assertion to a "
                "browser session, and no Recipient/InResponseTo is present."))

    return {
        "message_type": message_type,
        "response_signed": response_signed,
        "status": status_value,
        "assertions": assertions,
        "findings": findings,
        "codes": [finding["code"] for finding in findings],
        "severity": _max_severity(findings),
    }


def _max_severity(findings: list) -> str:
    order = {"HIGH": 3, "MEDIUM": 2, "LOW": 1}
    severity = "INFO"
    for finding in findings:
        if order.get(finding["severity"], 0) > order.get(severity, 0):
            severity = finding["severity"]
    return severity


def analyze_metadata(xml_bytes: bytes) -> dict:
    """Weak spots in an SP/IdP metadata document.

    These are configuration observations, not vulnerabilities: metadata says
    what an SP *asks* for, and a missing signature requirement is only real if
    the SP also accepts the resulting unsigned messages.
    """
    root = parse(xml_bytes)
    sp_descriptors = _descendants(root, "SPSSODescriptor")
    idp_descriptors = _descendants(root, "IDPSSODescriptor")
    descriptor = (sp_descriptors or idp_descriptors or [None])[0]

    findings = []
    acs_endpoints = []
    signing_keys = 0
    encryption_keys = 0
    want_assertions_signed = None
    authn_requests_signed = None

    if descriptor is not None:
        raw_want = descriptor.get("WantAssertionsSigned")
        if raw_want is not None:
            want_assertions_signed = str(raw_want).strip().lower() == "true"
        raw_requests = descriptor.get("AuthnRequestsSigned")
        if raw_requests is not None:
            authn_requests_signed = \
                str(raw_requests).strip().lower() == "true"

        for key in _descendants(descriptor, "KeyDescriptor"):
            use = str(key.get("use") or "signing").lower()
            if use == "encryption":
                encryption_keys += 1
            else:
                signing_keys += 1

        for endpoint in (_descendants(descriptor, "AssertionConsumerService")
                         + _descendants(descriptor, "SingleSignOnService")):
            location = str(endpoint.get("Location") or "")
            if not location:
                continue
            acs_endpoints.append({
                "binding": str(endpoint.get("Binding") or ""),
                "location": location,
            })
            if location.lower().startswith("http://"):
                findings.append(_finding(
                    "acs_plaintext",
                    f"{location} is plaintext HTTP: the SAML message and the "
                    "session it establishes cross the network unencrypted."))

    if want_assertions_signed is False:
        findings.append(_finding(
            "want_assertions_signed_false",
            "WantAssertionsSigned is false: the SP does not require the "
            "assertion itself to be signed."))
    elif want_assertions_signed is None:
        findings.append(_finding(
            "want_assertions_signed_absent",
            "WantAssertionsSigned is absent; whether assertions must be "
            "signed depends on the SP's profile."))
    if authn_requests_signed is False:
        findings.append(_finding(
            "authn_requests_unsigned",
            "AuthnRequestsSigned is false: authentication requests can be "
            "forged or modified in transit."))
    if descriptor is not None and signing_keys == 0:
        findings.append(_finding(
            "no_signing_key",
            "No signing KeyDescriptor: the SP publishes no key with which "
            "signatures can be validated."))
    if descriptor is not None and encryption_keys == 0:
        findings.append(_finding(
            "no_encryption_key",
            "No encryption KeyDescriptor: assertions cannot be encrypted to "
            "the SP."))

    return {
        "entity_id": str(root.get("entityID") or ""),
        "role": ("sp" if sp_descriptors else
                 "idp" if idp_descriptors else "unknown"),
        "want_assertions_signed": want_assertions_signed,
        "authn_requests_signed": authn_requests_signed,
        "acs": acs_endpoints,
        "signing_keys": signing_keys,
        "encryption_keys": encryption_keys,
        "findings": findings,
        "codes": [finding["code"] for finding in findings],
        "severity": _max_severity(findings),
    }


def looks_like_saml(body: str, content_type: str = "") -> bool:
    """Cheap discriminator for module discovery, not a parser."""
    lowered = (content_type or "").lower()
    if "saml" in lowered:
        return True
    head = str(body or "")[:4000].lower()
    return any(marker in head for marker in (
        "urn:oasis:names:tc:saml", "samlp:response", "samlp:authnrequest",
        "entitydescriptor", "samlrequest=", "samlresponse=",
    ))
