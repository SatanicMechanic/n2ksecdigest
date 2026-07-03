"""Tests for render.py — HTML escaping and URL validation."""

from render import render_html, render_text, subject_line, _safe_url


def test_html_escapes_headline_script():
    items = [{
        "headline": "<script>alert('x')</script>",
        "category": "threat",
        "severity": "high",
        "why": "Dangerous & untrusted",
        "action": 'Patch "now"',
        "url": "https://example.com/x",
    }]
    out = render_html(items, "Apr 15, 2026")
    assert "<script>alert" not in out
    assert "&lt;script&gt;" in out
    assert "&amp;" in out
    assert "&quot;" in out or "&#x27;" in out


def test_html_escapes_url_in_href():
    items = [{
        "headline": "x", "category": "threat", "severity": "high",
        "why": "y", "action": "z",
        "url": "https://example.com/x?a=1&b=2",
    }]
    out = render_html(items, "Apr 15, 2026")
    # The raw & must be escaped in the href attribute
    assert 'href="https://example.com/x?a=1&amp;b=2"' in out


def test_safe_url_accepts_http_and_https():
    assert _safe_url("https://example.com/x") == "https://example.com/x"
    assert _safe_url("http://example.com/x") == "http://example.com/x"


def test_safe_url_rejects_dangerous_schemes():
    assert _safe_url("javascript:alert(1)") == "#"
    assert _safe_url("data:text/html,<script>") == "#"
    assert _safe_url("file:///etc/passwd") == "#"
    assert _safe_url("ftp://example.com/x") == "#"
    assert _safe_url("") == "#"
    assert _safe_url(None) == "#"


def test_javascript_url_does_not_leak_into_html():
    items = [{
        "headline": "x", "category": "threat", "severity": "high",
        "why": "y", "action": "z",
        "url": "javascript:alert(1)",
    }]
    out = render_html(items, "Apr 15, 2026")
    assert "javascript:" not in out
    assert 'href="#"' in out


def test_render_text_basic():
    items = [{
        "headline": "CVE-2026-1234 in OpenSSL",
        "category": "threat", "severity": "critical",
        "why": "Affects appliance VMs.",
        "action": "Patch immediately.",
        "url": "https://example.com/x",
    }]
    txt = render_text(items, "Apr 15, 2026")
    assert "CRITICAL" in txt
    assert "CVE-2026-1234" in txt
    assert "https://example.com/x" in txt


def test_render_text_omits_dangerous_url():
    items = [{
        "headline": "x", "category": "threat", "severity": "high",
        "why": "y", "action": "z",
        "url": "javascript:alert(1)",
    }]
    txt = render_text(items, "Apr 15, 2026")
    assert "javascript:" not in txt


def _make_item(sev):
    return {"headline": "x", "category": "threat", "severity": sev,
            "why": "y", "action": "z", "url": "https://example.com"}


def test_subject_line_critical_prefix():
    assert "🔴" in subject_line([_make_item("critical")], "Apr 15, 2026")


def test_subject_line_high_prefix():
    out = subject_line([_make_item("high")], "Apr 15, 2026")
    assert "🟠" in out
    assert "🔴" not in out


def test_subject_line_medium_prefix():
    out = subject_line([_make_item("medium")], "Apr 15, 2026")
    assert "🟠" not in out
    assert "🔴" not in out


def test_subject_line_critical_wins_over_high():
    items = [_make_item("high"), _make_item("critical"), _make_item("medium")]
    assert "🔴" in subject_line(items, "Apr 15, 2026")


def test_subject_line_item_count():
    assert "(1 item)" in subject_line([_make_item("medium")], "Apr 15, 2026")
    assert "(3 items)" in subject_line([_make_item("medium")] * 3, "Apr 15, 2026")
