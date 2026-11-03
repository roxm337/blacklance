"""`cloud.bucket.list` — anonymous listing proof across the three providers.

The important property is that a 200 that is not a listing is not a finding,
and that the request is anonymous: an authenticated fetch would "prove" a
private bucket.
"""

import asyncio
import json

import pytest

from actions.cloud import buckets
from actions.registry import ActionContext


def _ctx(url="https://bucket.s3.amazonaws.com/"):
    return ActionContext(action_id="cloud.bucket.list", params={"url": url},
                         target=url)


@pytest.fixture
def curl_calls(monkeypatch):
    calls = []
    replies = []

    async def fake(url, **kwargs):
        calls.append({"url": url, **kwargs})
        return replies.pop(0)

    monkeypatch.setattr(buckets, "curl", fake)
    return calls, replies


def _xml(*keys):
    body = ('<?xml version="1.0"?><ListBucketResult>'
            + "".join(f"<Contents><Key>{k}</Key></Contents>" for k in keys)
            + "</ListBucketResult>")
    return {"status": 200, "body": body, "headers": ""}


def test_s3_listing_is_confirmed_anonymously(curl_calls):
    calls, replies = curl_calls
    replies.extend([_xml("a.txt", "backups/db.zip"), _xml("a.txt", "backups/db.zip")])

    result = asyncio.run(buckets.bucket_list(_ctx()))

    assert result.success is True
    assert result.confidence == "CONFIRMED"
    assert result.data["object_count"] == 2
    assert all(call["no_session"] is True for call in calls)


def test_gcs_json_listing_is_confirmed(curl_calls):
    _, replies = curl_calls
    body = json.dumps({"kind": "storage#objects",
                       "items": [{"name": "a.txt"}, {"name": "b.txt"}]})
    replies.extend([
        {"status": 200, "body": body, "headers": ""},
        {"status": 200, "body": body, "headers": ""},
    ])

    result = asyncio.run(buckets.bucket_list(_ctx(
        "https://storage.googleapis.com/bucket")))

    assert result.success is True
    assert result.data["objects"] == ["a.txt", "b.txt"]


def test_azure_listing_is_recognised(curl_calls):
    _, replies = curl_calls
    body = ('<?xml version="1.0"?><EnumerationResults>'
            "<Blobs><Blob><Name>x.bin</Name></Blob></Blobs>"
            "</EnumerationResults>")
    replies.extend([{"status": 200, "body": body, "headers": ""}] * 2)

    result = asyncio.run(buckets.bucket_list(_ctx("https://acct.blob.core.windows.net/c")))

    assert result.success is True
    assert result.data["objects"] == ["x.bin"]


def test_denied_listing_is_not_a_finding(curl_calls):
    _, replies = curl_calls
    replies.append({"status": 403, "body": "AccessDenied", "headers": ""})

    result = asyncio.run(buckets.bucket_list(_ctx()))

    assert result.success is False
    assert "denied" in result.error


def test_html_200_is_not_a_listing(curl_calls):
    _, replies = curl_calls
    replies.append({"status": 200, "body": "<html>hello</html>", "headers": ""})

    result = asyncio.run(buckets.bucket_list(_ctx()))

    assert result.success is False
    assert "not a bucket listing" in result.error


def test_empty_listing_is_not_data_exposure(curl_calls):
    _, replies = curl_calls
    replies.append(_xml())

    result = asyncio.run(buckets.bucket_list(_ctx()))

    assert result.success is False
    assert "no object names" in result.error
