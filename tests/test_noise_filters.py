"""Regression tests for core/noise_filters.

Fixtures are the exact garbage the example.com run surfaced: millisecond
epoch "phones", plugin-credit "people", `?ver=` cache-buster "parameters",
and jQuery/GSAP "JS files". Each assertion pins one piece of that noise out
of the asset graph while keeping the one real value in the same class.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.noise_filters import (
    is_noise_parameter,
    is_probable_person_name,
    is_probable_phone,
    is_vendor_js,
)


# ── Phones ──────────────────────────────────────────────────────────

def test_real_formatted_phone_is_kept():
    assert is_probable_phone("+33 1 44 90 25 55")
    assert is_probable_phone("(555) 123-4567")
    assert is_probable_phone("555-123-4567")
    assert is_probable_phone("+1 212 555 0199")


def test_millisecond_epoch_is_rejected():
    # The 15 phantom phones from a past report — all bare ms epochs.
    for junk in ("1499763626209", "1508502157074", "1609250087616",
                 "1609250157453"):
        assert not is_probable_phone(junk), junk


def test_cache_buster_and_short_ids_rejected():
    assert not is_probable_phone("1482404872")   # ?ver= unix seconds
    assert not is_probable_phone("12345")         # too short
    assert not is_probable_phone("")


# ── People ──────────────────────────────────────────────────────────

def test_real_person_name_is_kept():
    assert is_probable_person_name("Roland Branquart")
    assert is_probable_person_name("Jean-Pierre Dupont")
    assert is_probable_person_name("Denis de la Rue")


def test_plugin_and_chrome_credits_rejected():
    for junk in ("Page Builder", "Slider Plugin", "Google Analytics",
                 "Cookie Policy", "Privacy Policy", "Powered By"):
        assert not is_probable_person_name(junk), junk


def test_single_word_or_junk_rejected():
    assert not is_probable_person_name("Angola")
    assert not is_probable_person_name("Edf")
    assert not is_probable_person_name("SEO Report 2024")


# ── Parameters ──────────────────────────────────────────────────────

def test_cache_buster_param_is_noise():
    assert is_noise_parameter("ver", "https://x.com/style.css?ver=5.4")
    assert is_noise_parameter("v", "https://x.com/app.js?v=2")
    assert is_noise_parameter("utm_source", "https://x.com/?utm_source=fb")


def test_param_on_static_asset_is_noise():
    # Any param on a static asset is versioning, not input.
    assert is_noise_parameter("foo", "https://x.com/theme/main.js?foo=1")
    assert is_noise_parameter("x", "https://x.com/a.css?x=1")


def test_real_app_parameter_is_kept():
    assert not is_noise_parameter("id", "https://x.com/product?id=5")
    assert not is_noise_parameter("q", "https://x.com/search?q=test")
    assert not is_noise_parameter("redirect", "https://x.com/login?redirect=/a")


# ── JS files ────────────────────────────────────────────────────────

def test_vendor_libraries_flagged():
    for lib in (
        "https://example.com/wp-content/themes/bridge/js/jquery.stretch.js?ver=5.4.9",
        "https://example.com/wp-content/themes/bridge/js/TweenLite.min.js",
        "https://example.com/wp-includes/js/zxcvbn-async.min.js",
    ):
        assert is_vendor_js(lib), lib


def test_first_party_js_kept():
    assert not is_vendor_js("https://example.com/assets/app.bundle.js")
    assert not is_vendor_js("https://example.com/static/checkout.js")
