"""The module deadline is enforced at the I/O boundary.

These pin the behaviour that turns a guillotined timeout into partial,
persisted coverage: once the deadline passes, no HTTP request or tool
subprocess is launched, so a scan loop drains in milliseconds and reaches
its finding-flush instead of being cancelled mid-run.
"""

import asyncio
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import core.deadline as dl
import tools.external as ext
import tools.wrappers as wrappers


def teardown_function(_):
    dl.clear_deadline()


def test_no_deadline_is_infinite():
    dl.clear_deadline()
    assert dl.deadline_remaining() == float("inf")
    assert not dl.deadline_reached()


def test_curl_short_circuits_past_deadline():
    dl.set_deadline(time.monotonic() - 1)
    r = asyncio.run(wrappers.curl("https://example.com", output="status"))
    assert r["status"] == 0
    assert r["error"] == "deadline_exceeded"
    assert r["url"] == "https://example.com"  # shape stays caller-compatible


def test_bash_does_not_launch_past_deadline():
    dl.set_deadline(time.monotonic() - 1)
    r = asyncio.run(wrappers.bash("echo should_not_run"))
    assert r["error"] == "deadline_exceeded"
    assert r["stdout"] == ""


def test_run_command_does_not_launch_past_deadline():
    dl.set_deadline(time.monotonic() - 1)
    r = asyncio.run(ext.run_command(["echo", "nope"]))
    assert r["error"] == "deadline_exceeded"


def test_scan_loop_drains_fast_instead_of_hanging():
    # A module-shaped loop that would make 500 HTTP calls finishes almost
    # instantly once the deadline has passed, because every call returns the
    # fast-fail shape rather than hitting the network.
    dl.set_deadline(time.monotonic() - 1)

    async def scan():
        hits = 0
        for i in range(500):
            r = await wrappers.curl(f"https://example.com/{i}", output="status")
            if r["status"] == 200:
                hits += 1
        return hits

    started = time.monotonic()
    hits = asyncio.run(scan())
    assert hits == 0
    assert time.monotonic() - started < 2.0  # no 500 real requests


def test_base_module_helpers_track_the_global_deadline():
    from modules.base import BaseModule

    dl.set_deadline(time.monotonic() + 100)
    m = BaseModule.__new__(BaseModule)
    assert 90 < m.time_left() <= 100
    assert not m.should_stop()
    assert m.should_stop(reserve=200)  # reserve exceeds time left
