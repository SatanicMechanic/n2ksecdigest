"""Tests for the second-pass enrichment: article fetch + why/action rewrite.

Enrichment is strictly best-effort — the invariants under test are:
  - fetch_article_text never raises and enforces http(s)
  - enrich_items only rewrites why/action when the LLM returns usable JSON
  - any failure (fetch, LLM, parse) leaves the triage-time item untouched
  - selection-identity fields (headline/category/severity/url) are never changed
"""

import json

import fetchers
import llm


# --- fetch_article_text ---

class _FakeRaw:
    def __init__(self, data: bytes):
        self._data = data

    def read(self, *_args, **_kwargs):
        return self._data


class _FakeResp:
    def __init__(self, body: str, status_code: int = 200,
                 content_type: str = "text/html; charset=utf-8"):
        self.status_code = status_code
        self.headers = {"Content-Type": content_type}
        self.encoding = "utf-8"
        self.raw = _FakeRaw(body.encode("utf-8"))


def test_fetch_article_text_rejects_non_http_schemes():
    # No network call should even be attempted; URL is rejected up front.
    assert fetchers.fetch_article_text("file:///etc/passwd") == ""
    assert fetchers.fetch_article_text("javascript:alert(1)") == ""
    assert fetchers.fetch_article_text("") == ""


def test_fetch_article_text_strips_script_and_style(monkeypatch):
    body = (
        "<html><head><style>body{color:red}</style>"
        "<script>steal()</script></head>"
        "<body><p>Real article text.</p><noscript>enable js</noscript></body></html>"
    )
    monkeypatch.setattr(fetchers.requests, "get",
                        lambda *a, **k: _FakeResp(body))
    out = fetchers.fetch_article_text("https://example.com/story")
    assert out == "Real article text."


def test_fetch_article_text_non_html_content_type_returns_empty(monkeypatch):
    monkeypatch.setattr(
        fetchers.requests, "get",
        lambda *a, **k: _FakeResp("binary", content_type="application/pdf"))
    assert fetchers.fetch_article_text("https://example.com/x.pdf") == ""


def test_fetch_article_text_non_200_returns_empty(monkeypatch):
    monkeypatch.setattr(fetchers.requests, "get",
                        lambda *a, **k: _FakeResp("nope", status_code=404))
    assert fetchers.fetch_article_text("https://example.com/gone") == ""


def test_fetch_article_text_respects_max_chars(monkeypatch):
    monkeypatch.setattr(fetchers.requests, "get",
                        lambda *a, **k: _FakeResp("<p>" + "x" * 9000 + "</p>"))
    out = fetchers.fetch_article_text("https://example.com/long", max_chars=100)
    assert len(out) == 100


# --- enrich_items ---

def _item():
    return {
        "headline": "Original headline",
        "category": "threat",
        "severity": "high",
        "why": "original why",
        "action": "original action",
        "url": "https://example.com/story",
    }


_LONG_TEXT = "word " * 100  # > 200-char usability floor


def test_enrich_items_rewrites_why_and_action(monkeypatch):
    monkeypatch.setattr(fetchers, "fetch_article_text", lambda url: _LONG_TEXT)
    monkeypatch.setattr(
        llm, "call_llm",
        lambda *a, **k: json.dumps({"why": "better why", "action": "better action"}))
    out = llm.enrich_items([_item()])
    assert out[0]["why"] == "better why"
    assert out[0]["action"] == "better action"
    # Selection-identity fields untouched.
    assert out[0]["headline"] == "Original headline"
    assert out[0]["severity"] == "high"
    assert out[0]["url"] == "https://example.com/story"


def test_enrich_items_keeps_originals_when_article_unusable(monkeypatch):
    monkeypatch.setattr(fetchers, "fetch_article_text", lambda url: "short")
    monkeypatch.setattr(
        llm, "call_llm",
        lambda *a, **k: (_ for _ in ()).throw(AssertionError("must not be called")))
    out = llm.enrich_items([_item()])
    assert out[0]["why"] == "original why"
    assert out[0]["action"] == "original action"


def test_enrich_items_keeps_originals_on_bad_llm_json(monkeypatch):
    monkeypatch.setattr(fetchers, "fetch_article_text", lambda url: _LONG_TEXT)
    monkeypatch.setattr(llm, "call_llm", lambda *a, **k: "not json at all")
    out = llm.enrich_items([_item()])
    assert out[0]["why"] == "original why"
    assert out[0]["action"] == "original action"


def test_enrich_items_keeps_originals_on_missing_fields(monkeypatch):
    monkeypatch.setattr(fetchers, "fetch_article_text", lambda url: _LONG_TEXT)
    monkeypatch.setattr(llm, "call_llm",
                        lambda *a, **k: json.dumps({"why": "only why"}))
    out = llm.enrich_items([_item()])
    assert out[0]["why"] == "original why"
    assert out[0]["action"] == "original action"


def test_enrich_items_keeps_originals_when_llm_raises(monkeypatch):
    monkeypatch.setattr(fetchers, "fetch_article_text", lambda url: _LONG_TEXT)
    monkeypatch.setattr(
        llm, "call_llm",
        lambda *a, **k: (_ for _ in ()).throw(RuntimeError("provider down")))
    out = llm.enrich_items([_item()])
    assert out[0]["why"] == "original why"
    assert out[0]["action"] == "original action"


def test_enrich_items_caps_field_length(monkeypatch):
    monkeypatch.setattr(fetchers, "fetch_article_text", lambda url: _LONG_TEXT)
    monkeypatch.setattr(
        llm, "call_llm",
        lambda *a, **k: json.dumps({"why": "w" * 5000, "action": "a" * 5000}))
    out = llm.enrich_items([_item()])
    assert len(out[0]["why"]) == llm._ENRICH_FIELD_MAX_CHARS
    assert len(out[0]["action"]) == llm._ENRICH_FIELD_MAX_CHARS
