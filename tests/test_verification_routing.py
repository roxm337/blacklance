"""Verification re-proves with the same action the finding was routed to.

`verify_finding` used to know only SQLi/XSS/SSRF, so a confirmed-looking SSTI,
LFI, redirect or authorization hypothesis fell through to the generic
composite oracle and re-tested something else. The mapping is now a function
and pinned here.
"""

import pytest

from agents.verification_agent import action_for_technique


@pytest.mark.parametrize("technique,expected", [
    ("NoSQL operator injection", "web.nosql.detect"),
    ("SQLi", "web.sqli.detect"),
    ("blind sql injection", "web.sqli.detect"),
    ("reflected XSS", "web.xss.reflected"),
    ("SSRF via image proxy", "web.ssrf.oob_detect"),
    ("server-side template injection", "web.ssti.detect"),
    ("SSTI (Jinja2)", "web.ssti.detect"),
    ("path traversal", "web.lfi.detect"),
    ("local file inclusion", "web.lfi.detect"),
    ("open redirect", "web.redirect.probe"),
    ("broken access control", "auth.bypass.probe"),
    ("authorization bypass", "auth.bypass.probe"),
    ("jwt weakness", "verify.composite_oracle"),
    ("", "verify.composite_oracle"),
])
def test_technique_maps_to_the_proving_action(technique, expected):
    assert action_for_technique(technique) == expected
