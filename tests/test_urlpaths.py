"""I4 urlpath tests: RFC 3986 dot-segment resolution, segment-boundary
escape checks, and payload effect extraction."""

from __future__ import annotations

from core.urlpaths import (effect_segments, escaped, path_segments,
                           remove_dot_segments, server_view_path,
                           stable_prefix, templatize)


def test_rfc3986_remove_dot_segments_examples():
    # RFC 3986 §5.4.1 normal examples
    assert remove_dot_segments("/a/b/c/./../../g") == "/a/g"
    assert remove_dot_segments("mid/content=5/../6") == "mid/6"
    assert remove_dot_segments("/a/b/c/../../../g") == "/g"
    assert remove_dot_segments("/./g") == "/g"
    assert remove_dot_segments("/../g") == "/g"
    assert remove_dot_segments("/a/./b/../../c/") == "/c/"
    assert remove_dot_segments("") == ""
    assert remove_dot_segments("/") == "/"


def test_server_view_decodes_once_then_resolves():
    assert server_view_path("http://h/api/../../admin/secrets") == "/admin/secrets"
    assert server_view_path("http://h/api/%2e%2e/%2e%2e/admin/secrets") == "/admin/secrets"
    # Double-encoded: one decode leaves literal %2e%2e, no resolution.
    assert server_view_path("http://h/api/%252e%252e/admin") == "/api/%2e%2e/admin"
    # Query never participates in path resolution.
    assert server_view_path("http://h/api/..?x=../admin") == "/"


def test_path_segments_and_prefix():
    assert path_segments("/api/reports/cz9f2a") == ["api", "reports", "cz9f2a"]
    assert stable_prefix("/api/reports/cz9f2a71", "cz9f2a71") == ["api", "reports"]
    assert stable_prefix("/api/cz1", "cz1") == ["api"]
    assert stable_prefix("/cz1", "cz1") == []


def test_escaped_is_segment_aware():
    assert escaped(["api", "reports"], "/admin/secrets") is True
    assert escaped(["api", "reports"], "/api/admin") is True
    # A sibling sharing a STRING prefix is still a different directory —
    # segment awareness is what catches it (str.startswith would miss it).
    assert escaped(["api", "reports"], "/api/reports-archive/1") is True
    assert escaped(["api", "reports"], "/api/reports/1") is False
    assert escaped(["api"], "/api") is False
    assert escaped([], "/anything") is True


def test_effect_segments_strips_traversal_machinery():
    assert effect_segments("../../admin/secrets") == ["admin", "secrets"]
    assert effect_segments("..%2f..%2fadmin%2fsecrets") == ["admin", "secrets"]
    assert effect_segments("reports/1") == ["reports", "1"]
    assert effect_segments("../%2e%2e/internal/users?x=1") == ["internal", "users"]


def test_templatize_replaces_token_segment():
    assert templatize("/api/reports/cz9f2a71", "cz9f2a71") == "/api/reports/{input}"
    assert templatize("/api/cz1/details", "cz1") == "/api/{input}/details"
    assert templatize("/api/reports", "cz1") == "/api/reports"


def test_has_traversal_requires_dot_segments():
    from core.urlpaths import has_traversal
    assert has_traversal("../../admin/secrets")
    assert has_traversal("..%2f..%2fadmin%2fsecrets")
    assert has_traversal("..\\..\\admin")
    assert not has_traversal("reports-archive/1")
    assert not has_traversal("..foo/bar")
    assert not has_traversal("")
