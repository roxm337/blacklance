"""Tests for SAML analysis: message structure, metadata, action, module.

The fixtures are hand-built because the claims under test are structural.
Nothing here verifies a signature — the module deliberately does not — so a
"valid" fixture only has to be shaped like a real message.
"""

import base64
import tempfile
import zlib

import pytest

from core.saml import (SamlError, analyze, analyze_metadata, decode_message,
                       looks_like_saml)
from state.manager import StateManager

SIGNED_RESPONSE = """<samlp:Response
    xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
    xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
    xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
  <saml:Issuer>https://idp.test/metadata</saml:Issuer>
  <samlp:Status>
    <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
  </samlp:Status>
  <ds:Signature><ds:SignedInfo/></ds:Signature>
  <saml:Assertion ID="_a1">
    <saml:Issuer>https://idp.test/metadata</saml:Issuer>
    <saml:Subject>
      <saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">alice@test</saml:NameID>
      <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
        <saml:SubjectConfirmationData NotOnOrAfter="2030-01-01T00:00:00Z"
            Recipient="https://sp.test/acs"/>
      </saml:SubjectConfirmation>
    </saml:Subject>
    <saml:Conditions NotBefore="2020-01-01T00:00:00Z"
                     NotOnOrAfter="2030-01-01T00:00:00Z">
      <saml:AudienceRestriction>
        <saml:Audience>https://sp.test</saml:Audience>
      </saml:AudienceRestriction>
    </saml:Conditions>
  </saml:Assertion>
</samlp:Response>"""

UNSIGNED_ASSERTION = """<saml:Assertion
    xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
  <saml:Issuer>https://idp.test</saml:Issuer>
  <saml:Subject><saml:NameID>alice@test</saml:NameID></saml:Subject>
</saml:Assertion>"""

COMMENT_NAMEID = SIGNED_RESPONSE.replace(
    "alice@test<", "alice@test<!--injected-->@evil.test<")

METADATA_WEAK = """<md:EntityDescriptor
    xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"
    entityID="https://sp.test/saml/metadata">
  <md:SPSSODescriptor WantAssertionsSigned="false"
                      AuthnRequestsSigned="false">
    <md:AssertionConsumerService
        Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
        Location="http://sp.test/acs" index="0"/>
  </md:SPSSODescriptor>
</md:EntityDescriptor>"""

METADATA_STRONG = """<md:EntityDescriptor
    xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"
    xmlns:ds="http://www.w3.org/2000/09/xmldsig#"
    entityID="https://sp.test/saml/metadata">
  <md:SPSSODescriptor WantAssertionsSigned="true"
                      AuthnRequestsSigned="true">
    <md:KeyDescriptor use="signing">
      <ds:KeyInfo><ds:X509Data><ds:X509Certificate>MIIB</ds:X509Certificate>
      </ds:X509Data></ds:KeyInfo>
    </md:KeyDescriptor>
    <md:KeyDescriptor use="encryption">
      <ds:KeyInfo><ds:X509Data><ds:X509Certificate>MIIC</ds:X509Certificate>
      </ds:X509Data></ds:KeyInfo>
    </md:KeyDescriptor>
    <md:AssertionConsumerService
        Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
        Location="https://sp.test/acs" index="0"/>
  </md:SPSSODescriptor>
</md:EntityDescriptor>"""


# ── message analysis ────────────────────────────────────────────

def test_signed_response_with_unsigned_assertion_is_signature_exclusion():
    result = analyze(SIGNED_RESPONSE.encode())
    assert result["message_type"] == "Response"
    assert result["response_signed"] is True
    assert result["assertions"][0]["signed"] is False
    assert "signature_exclusion" in result["codes"]
    assert result["severity"] == "HIGH"
    assert result["status"].endswith(":Success")


def test_bare_assertion_is_analysed_without_response_claims():
    result = analyze(UNSIGNED_ASSERTION.encode())
    assert result["message_type"] == "Assertion"
    assert result["response_signed"] is False
    # No enclosing Response means no wrapper verdict.
    assert "signature_exclusion" not in result["codes"]
    assert "no_signature_anywhere" not in result["codes"]
    # A bare assertion with no Conditions still says so.
    assert "conditions_missing" in result["codes"]
    assert "audience_missing" in result["codes"]


def test_comment_in_nameid_is_reported_with_its_replay_caveat():
    result = analyze(COMMENT_NAMEID.encode())
    assert "nameid_comment_injection" in result["codes"]
    detail = next(finding["detail"] for finding in result["findings"]
                  if finding["code"] == "nameid_comment_injection")
    assert "replay" in detail


def test_conditions_and_audience_are_read_from_the_assertion():
    assertion = analyze(SIGNED_RESPONSE.encode())["assertions"][0]
    assert assertion["audiences"] == ["https://sp.test"]
    assert assertion["not_on_or_after"] == "2030-01-01T00:00:00Z"
    assert assertion["recipient"] == "https://sp.test/acs"
    assert assertion["name_id_format"].endswith("emailAddress")


# ── decoding ────────────────────────────────────────────────────

def test_decode_accepts_raw_base64_urlencoded_and_deflated():
    raw = SIGNED_RESPONSE.encode()
    assert decode_message(SIGNED_RESPONSE) == raw
    encoded = base64.b64encode(raw).decode()
    assert decode_message(encoded) == raw
    assert decode_message(encoded.replace("=", "%3D")) == raw
    compressor = zlib.compressobj(9, zlib.DEFLATED, -15)
    deflated = compressor.compress(raw) + compressor.flush()
    assert decode_message(base64.b64encode(deflated).decode()) == raw


def test_decode_rejects_junk():
    with pytest.raises(SamlError):
        decode_message("")
    with pytest.raises(SamlError):
        decode_message("not base64 !!!")
    with pytest.raises(SamlError):
        decode_message(base64.b64encode(b"plain text").decode())


def test_parse_rejects_dtd_and_entity_declarations():
    bomb = b'<!DOCTYPE x [<!ENTITY a "aaaa">]><x>&a;</x>'
    with pytest.raises(SamlError):
        analyze(bomb)


# ── metadata ───────────────────────────────────────────────────

def test_weak_metadata_reports_configuration_codes():
    result = analyze_metadata(METADATA_WEAK.encode())
    assert result["role"] == "sp"
    assert result["entity_id"] == "https://sp.test/saml/metadata"
    assert result["want_assertions_signed"] is False
    assert result["authn_requests_signed"] is False
    assert result["acs"][0]["location"] == "http://sp.test/acs"
    for code in ("want_assertions_signed_false", "authn_requests_unsigned",
                 "no_signing_key", "acs_plaintext"):
        assert code in result["codes"]
    assert result["severity"] == "MEDIUM"


def test_strong_metadata_is_clean():
    result = analyze_metadata(METADATA_STRONG.encode())
    assert result["want_assertions_signed"] is True
    assert result["authn_requests_signed"] is True
    assert result["signing_keys"] == 1
    assert result["codes"] == []
    assert result["severity"] == "INFO"


def test_looks_like_saml_uses_body_and_content_type():
    assert looks_like_saml(METADATA_STRONG)
    assert looks_like_saml("<html>", "application/samlmetadata+xml")
    assert not looks_like_saml("<html>nope</html>", "text/html")


# ── action ─────────────────────────────────────────────────────

def _run_action(action_id, params):
    import asyncio
    import actions
    from actions.registry import ActionContext, ActionRegistry
    ctx = ActionContext(action_id=action_id, params=params, target="sp.test")
    return asyncio.run(ActionRegistry.execute(action_id, ctx))


def test_saml_analyze_action_is_registered_safe_and_offline():
    import actions
    from actions.registry import get_action

    meta, _fn = get_action("auth.saml.analyze")
    assert meta.risk.value == "SAFE"
    assert meta.category == "auth"
    result = _run_action("auth.saml.analyze",
                         {"saml_response": SIGNED_RESPONSE})
    assert result.success is True
    assert result.confidence == "FIRM"
    assert result.data["assertion_count"] == 1
    assert result.data["unsigned_assertions"] == 1
    assert result.evidence["codes"] == ["signature_exclusion"]


def test_saml_analyze_action_reports_bad_input_without_raising():
    result = _run_action("auth.saml.analyze", {"saml_response": "garbage"})
    assert result.success is False
    assert "neither XML nor base64" in result.error


def test_saml_metadata_action_reads_metadata_document():
    result = _run_action("auth.saml.metadata", {"metadata": METADATA_WEAK})
    assert result.success is True
    assert result.data["role"] == "sp"
    assert "acs_plaintext" in result.data["codes"]


# ── module ─────────────────────────────────────────────────────

def _module_config(extra=None):
    return {
        "target": {"domain": "sp.test", "base_url": "https://sp.test"},
        "auth": {"identities": []},
        "waf": {"block_codes": [429, 503]},
        "modules": {"saml_audit": dict(extra or {})},
    }


def _fake_get(metadata):
    async def get(url, **kwargs):
        if url.rstrip("/").endswith("/saml/metadata"):
            return {"status": 200, "body": metadata,
                    "headers": "Content-Type: application/xml"}
        return {"status": 404, "body": "", "headers": ""}
    return get


def test_module_reports_one_tentative_finding_per_entity(monkeypatch):
    from modules.saml_audit import SamlAudit

    state = StateManager(tempfile.mkdtemp())
    module = SamlAudit(state, _module_config())
    monkeypatch.setattr("modules.base.curl", _fake_get(METADATA_WEAK))
    import asyncio
    assert asyncio.run(module.run()) == "done"

    findings = state.findings["findings"]
    assert len(findings) == 1
    finding = findings[0]
    assert finding["severity"] == "MEDIUM"
    assert finding["confidence"] == "TENTATIVE"
    assert finding["category"] == "SAML"
    assert "want_assertions_signed_false" in finding["description"]
    assets = state.get_assets_by_type("saml_endpoint")
    assert len(assets) == 1
    assert assets[0]["attrs"]["role"] == "sp"


def test_module_strong_metadata_is_evidence_not_a_finding(monkeypatch):
    from modules.saml_audit import SamlAudit

    state = StateManager(tempfile.mkdtemp())
    module = SamlAudit(state, _module_config())
    monkeypatch.setattr("modules.base.curl", _fake_get(METADATA_STRONG))
    import asyncio
    assert asyncio.run(module.run()) == "done"
    assert state.findings["findings"] == []
    assert len(state.get_assets_by_type("saml_endpoint")) == 1


def test_module_disabled_skips():
    from modules.saml_audit import SamlAudit

    state = StateManager(tempfile.mkdtemp())
    module = SamlAudit(state, _module_config({"enabled": False}))
    import asyncio
    assert asyncio.run(module.run()) == "skipped"
    assert state.module["skipped"][0]["reason"] == "disabled in config"


def test_module_is_registered_active_in_stage_five():
    from modules import MODULE_REGISTRY
    entry = MODULE_REGISTRY["saml_audit"]
    assert entry["stage"] == 5
    assert entry["active"] is True
    assert entry["detectability"] == "medium"


def test_config_doctor_knows_the_module_keys():
    from core.config_doctor import unknown_warnings
    warnings = unknown_warnings(
        {"modules": {"saml_audit": {"enabled": True, "max_endpoints": 0}}})
    assert warnings == []
