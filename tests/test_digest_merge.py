"""Tests for digest._merge_triage_results."""

import pytest
from digest import _merge_triage_results


def _item(url, category="threat", headline=None):
    return {
        "headline": headline or f"headline for {url}",
        "category": category,
        "severity": "high",
        "why": "why",
        "action": "act",
        "url": url,
    }


# --- both-skip path ---

def test_both_none_returns_empty():
    assert _merge_triage_results(None, None) == []


def test_both_empty_returns_empty():
    assert _merge_triage_results([], []) == []


def test_a_none_b_has_items():
    b = [_item("https://b.com", "tooling")]
    result = _merge_triage_results(None, b)
    assert len(result) == 1
    assert result[0]["url"] == "https://b.com"


def test_b_none_a_has_items():
    a = [_item("https://a.com", "threat")]
    result = _merge_triage_results(a, None)
    assert len(result) == 1
    assert result[0]["url"] == "https://a.com"


# --- URL dedupe: A wins on tie ---

def test_url_dedupe_a_wins():
    shared_url = "https://shared.com"
    a = [_item(shared_url, "threat", "threat headline")]
    b = [_item(shared_url, "tooling", "tooling headline")]
    result = _merge_triage_results(a, b)
    assert len(result) == 1
    assert result[0]["category"] == "threat"
    assert result[0]["headline"] == "threat headline"


def test_url_dedupe_case_insensitive():
    a = [_item("https://Example.COM/path", "threat")]
    b = [_item("https://example.com/path", "tooling")]
    result = _merge_triage_results(a, b)
    assert len(result) == 1


# --- tooling cap = 1 ---

def test_tooling_cap_is_one(monkeypatch):
    import digest
    monkeypatch.setattr(digest, "TRIAGE_TOOLING_CAP", 1)
    monkeypatch.setattr(digest, "TRIAGE_GLOBAL_CAP", 3)
    b = [_item("https://t1.com", "tooling"), _item("https://t2.com", "tooling")]
    result = _merge_triage_results([], b)
    assert len(result) == 1
    assert result[0]["url"] == "https://t1.com"


# --- global cap = 3 ---

def test_global_cap_is_three(monkeypatch):
    import digest
    monkeypatch.setattr(digest, "TRIAGE_TOOLING_CAP", 1)
    monkeypatch.setattr(digest, "TRIAGE_GLOBAL_CAP", 3)
    a = [
        _item("https://a1.com"), _item("https://a2.com"), _item("https://a3.com"),
    ]
    b = [_item("https://b1.com", "tooling")]
    result = _merge_triage_results(a, b)
    assert len(result) == 3
    assert all(r["url"] != "https://b1.com" for r in result)


# --- ordering: threat first, then tooling ---

def test_ordering_threat_before_tooling():
    a = [_item("https://threat.com", "threat")]
    b = [_item("https://tool.com", "tooling")]
    result = _merge_triage_results(a, b)
    assert result[0]["url"] == "https://threat.com"
    assert result[1]["url"] == "https://tool.com"


# --- items with missing or blank url are skipped in dedup ---

def test_items_with_no_url_are_excluded():
    a = [{"headline": "x", "category": "threat", "severity": "high",
          "why": "w", "action": "a", "url": ""}]
    result = _merge_triage_results(a, None)
    assert result == []


def test_items_with_none_url_are_excluded():
    a = [{"headline": "x", "category": "threat", "severity": "high",
          "why": "w", "action": "a", "url": None}]
    result = _merge_triage_results(a, None)
    assert result == []
