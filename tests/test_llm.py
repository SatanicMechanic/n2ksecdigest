"""Tests for llm.py — output parsing and retry semantics."""

import json
from unittest import mock

import pytest

import llm


# --- parse_query_json ---

def test_parse_query_json_plain_array():
    raw = '["query 1", "query 2", "query 3"]'
    assert llm.parse_query_json(raw) == ["query 1", "query 2", "query 3"]


def test_parse_query_json_with_markdown_fence():
    raw = '```json\n["a", "b"]\n```'
    assert llm.parse_query_json(raw) == ["a", "b"]


def test_parse_query_json_with_plain_fence():
    raw = '```\n["a", "b"]\n```'
    assert llm.parse_query_json(raw) == ["a", "b"]


def test_strip_fences_handles_single_line_form():
    """Older bug: `"```{...}```"` with no newline raised IndexError."""
    assert llm._strip_fences('```["a","b"]```') == '["a","b"]'


def test_strip_fences_passes_through_unfenced():
    assert llm._strip_fences('{"key": "value"}') == '{"key": "value"}'


def test_strip_fences_handles_lang_tag_with_newline():
    assert llm._strip_fences('```json\n{"k": 1}\n```') == '{"k": 1}'


def test_parse_query_json_single_line_fenced():
    """End-to-end: single-line-fenced output must parse, not crash."""
    assert llm.parse_query_json('```["a","b"]```') == ["a", "b"]


def test_parse_triage_output_tolerates_fenced_json():
    """Defense-in-depth: provider regressions to fenced output shouldn't blow up."""
    payload = '```json\n{"items": [{"headline":"x","category":"threat","severity":"high","why":"y","action":"z","url":"https://example.com"}]}\n```'
    items = llm.parse_triage_output(payload)
    assert len(items) == 1
    assert items[0]["headline"] == "x"


def test_parse_query_json_strips_empty_values():
    raw = '["", "a", null, "b"]'
    out = llm.parse_query_json(raw)
    assert "a" in out
    assert "b" in out
    assert "" not in out


def test_parse_query_json_returns_empty_on_garbage():
    assert llm.parse_query_json("not json at all") == []
    assert llm.parse_query_json("{}") == []
    assert llm.parse_query_json("") == []


# --- parse_triage_output ---

def test_parse_triage_output_skip_returns_none():
    assert llm.parse_triage_output('{"skip": true}') is None


def test_parse_triage_output_valid():
    payload = {"items": [{
        "headline": "x", "category": "threat", "severity": "high",
        "why": "y", "action": "z", "url": "https://example.com",
    }]}
    items = llm.parse_triage_output(json.dumps(payload))
    assert len(items) == 1
    assert items[0]["headline"] == "x"


def test_parse_triage_output_drops_incomplete_items():
    payload = {"items": [
        {"headline": "complete", "category": "threat", "severity": "high",
         "why": "w", "action": "a", "url": "https://example.com"},
        {"headline": "missing-url", "category": "threat", "severity": "high",
         "why": "w", "action": "a"},  # no url
        {"headline": "", "category": "threat", "severity": "high",
         "why": "w", "action": "a", "url": "https://example.com"},  # blank headline
    ]}
    items = llm.parse_triage_output(json.dumps(payload))
    assert len(items) == 1
    assert items[0]["headline"] == "complete"


def test_parse_triage_output_invalid_json_raises():
    with pytest.raises(RuntimeError):
        llm.parse_triage_output("{invalid json")


def test_parse_triage_output_non_dict_raises():
    with pytest.raises(RuntimeError):
        llm.parse_triage_output("[1, 2, 3]")


# --- build_triage_input ---

def test_build_triage_input_basic_format():
    articles = [{
        "title": "OpenSSL emergency patch", "source": "Krebs",
        "published": "2026-04-14", "link": "https://example.com",
        "summary": "urgent stuff",
    }]
    out = llm.build_triage_input(articles)
    assert "1. [Krebs] OpenSSL emergency patch" in out
    assert "https://example.com" in out
    assert "urgent stuff" in out


def test_build_triage_input_no_enrichment_tags():
    """No KEV/EPSS/CVE bracketed tags — triage reads article text only."""
    articles = [{
        "title": "CVE-2026-1234 exploited", "source": "src",
        "published": "date", "link": "u", "summary": "s",
    }]
    out = llm.build_triage_input(articles)
    assert "[KEV]" not in out
    assert "[EPSS" not in out
    # The CVE ID appears in the title (fine) but not as an injected tag
    assert "[CVE-2026-1234]" not in out  # no bracketed tag
    assert "CVE-2026-1234 exploited" in out  # still in title


def test_build_triage_input_multiple_items():
    articles = [
        {"title": "A", "source": "s1", "published": "p1", "link": "u1", "summary": "sum1"},
        {"title": "B", "source": "s2", "published": "p2", "link": "u2", "summary": "sum2"},
    ]
    out = llm.build_triage_input(articles)
    assert "1. [s1] A" in out
    assert "2. [s2] B" in out


def test_build_triage_input_surfaces_also_sources():
    """When cross-feed dedup collapsed a story, additional sources are visible to the LLM."""
    articles = [{
        "title": "Critical OpenSSL flaw exploited",
        "source": "GitHub Security Blog",
        "also_sources": ["AWS Security Blog", "Acme Security"],
        "published": "2026-04-14",
        "link": "https://example.com",
        "summary": "convergence detected",
    }]
    out = llm.build_triage_input(articles)
    assert "GitHub Security Blog" in out
    assert "also covered by:" in out
    assert "AWS Security Blog" in out
    assert "Acme Security" in out


def test_build_triage_input_no_also_sources_block_when_empty():
    articles = [{
        "title": "Routine post", "source": "Solo",
        "published": "p", "link": "u", "summary": "s",
    }]
    out = llm.build_triage_input(articles)
    assert "also covered by" not in out


# --- generate_slow_queries ---

def test_generate_slow_queries_parses_combined_response(monkeypatch):
    monkeypatch.setenv("GH_MODELS_TOKEN", "x")
    payload = '{"compliance": ["NVD operational change"], "pqc": ["NIST FIPS 203 rollout"]}'
    with mock.patch.object(llm, "call_github_models", return_value=payload):
        comp, pqc = llm.generate_slow_queries(24)
    assert comp == ["NVD operational change"]
    assert pqc == ["NIST FIPS 203 rollout"]


def test_generate_slow_queries_handles_garbage(monkeypatch):
    monkeypatch.setenv("GH_MODELS_TOKEN", "x")
    with mock.patch.object(llm, "call_github_models", return_value="not json"):
        comp, pqc = llm.generate_slow_queries(24)
    assert comp == []
    assert pqc == []


def test_generate_slow_queries_handles_missing_keys(monkeypatch):
    monkeypatch.setenv("GH_MODELS_TOKEN", "x")
    with mock.patch.object(llm, "call_github_models", return_value='{"compliance": ["x"]}'):
        comp, pqc = llm.generate_slow_queries(24)
    assert comp == ["x"]
    assert pqc == []


def test_generate_slow_queries_caps_to_configured_counts(monkeypatch):
    monkeypatch.setenv("GH_MODELS_TOKEN", "x")
    monkeypatch.setattr(llm, "COMPLIANCE_QUERIES", 1)
    monkeypatch.setattr(llm, "PQC_QUERIES", 1)
    payload = '{"compliance": ["a", "b", "c"], "pqc": ["x", "y"]}'
    with mock.patch.object(llm, "call_github_models", return_value=payload):
        comp, pqc = llm.generate_slow_queries(24)
    assert len(comp) == 1
    assert len(pqc) == 1


# --- generate_tooling_scan_queries ---

def test_generate_tooling_scan_queries_parses_array(monkeypatch):
    monkeypatch.setenv("GH_MODELS_TOKEN", "x")
    with mock.patch.object(llm, "call_xai", return_value='["AI exploit chain model release"]'):
        out = llm.generate_tooling_scan_queries(24)
    assert out == ["AI exploit chain model release"]


def test_generate_tooling_scan_queries_handles_garbage(monkeypatch):
    monkeypatch.setenv("GH_MODELS_TOKEN", "x")
    with mock.patch.object(llm, "call_xai", return_value="not json"):
        out = llm.generate_tooling_scan_queries(24)
    assert out == []


def test_generate_tooling_scan_queries_caps_to_configured_count(monkeypatch):
    monkeypatch.setenv("GH_MODELS_TOKEN", "x")
    monkeypatch.setattr(llm, "TOOLING_SCAN_QUERIES", 1)
    with mock.patch.object(llm, "call_xai", return_value='["a", "b", "c"]'):
        out = llm.generate_tooling_scan_queries(24)
    assert len(out) == 1


# --- generate_ai_lab_queries ---

def test_generate_ai_lab_queries_parses_array(monkeypatch):
    monkeypatch.setenv("GH_MODELS_TOKEN", "x")
    with mock.patch.object(llm, "call_xai", return_value='["Anthropic Claude Mythos cyber capability"]'):
        out = llm.generate_ai_lab_queries(24)
    assert out == ["Anthropic Claude Mythos cyber capability"]


def test_generate_ai_lab_queries_handles_garbage(monkeypatch):
    monkeypatch.setenv("GH_MODELS_TOKEN", "x")
    with mock.patch.object(llm, "call_xai", return_value="not json"):
        out = llm.generate_ai_lab_queries(24)
    assert out == []


def test_generate_ai_lab_queries_caps_to_configured_count(monkeypatch):
    monkeypatch.setenv("GH_MODELS_TOKEN", "x")
    monkeypatch.setattr(llm, "AI_LAB_QUERIES", 1)
    with mock.patch.object(llm, "call_xai", return_value='["a", "b", "c"]'):
        out = llm.generate_ai_lab_queries(24)
    assert len(out) == 1


# --- call_xai ---

def _make_mock_openai_client(content="result"):
    mock_response = mock.MagicMock()
    mock_response.choices[0].message.content = content
    mock_client = mock.MagicMock()
    mock_client.chat.completions.create.return_value = mock_response
    return mock_client


def _make_mock_azure_client(content="result"):
    mock_response = mock.MagicMock()
    mock_response.choices[0].message.content = content
    mock_client = mock.MagicMock()
    mock_client.complete.return_value = mock_response
    return mock_client


def test_call_xai_succeeds(monkeypatch):
    monkeypatch.setenv("XAI_API_KEY", "tok")
    mock_client = _make_mock_openai_client("result")
    with mock.patch("llm.OpenAI", return_value=mock_client):
        result = llm.call_xai("sys", "user")
    assert result == "result"
    mock_client.chat.completions.create.assert_called_once()


def test_call_xai_sets_reasoning_effort_low(monkeypatch):
    monkeypatch.setenv("XAI_API_KEY", "tok")
    mock_client = _make_mock_openai_client()
    with mock.patch("llm.OpenAI", return_value=mock_client):
        llm.call_xai("sys", "user")
    _, kwargs = mock_client.chat.completions.create.call_args
    assert kwargs.get("reasoning_effort") == "low"


def test_call_xai_sets_json_mode(monkeypatch):
    monkeypatch.setenv("XAI_API_KEY", "tok")
    mock_client = _make_mock_openai_client()
    with mock.patch("llm.OpenAI", return_value=mock_client):
        llm.call_xai("sys", "user", json_mode=True)
    _, kwargs = mock_client.chat.completions.create.call_args
    assert kwargs.get("response_format") == {"type": "json_object"}


# --- call_github_models (Azure AI Inference SDK fallback) ---

def test_call_github_models_succeeds(monkeypatch):
    monkeypatch.setenv("GH_MODELS_TOKEN", "tok")
    mock_client = _make_mock_azure_client("result")
    with mock.patch("llm.ChatCompletionsClient", return_value=mock_client):
        result = llm.call_github_models("sys", "user")
    assert result == "result"
    mock_client.complete.assert_called_once()


def test_call_github_models_uses_pat_env_var(monkeypatch):
    monkeypatch.setenv("GH_MODELS_TOKEN", "my-pat")
    mock_client = _make_mock_azure_client()
    with mock.patch("llm.ChatCompletionsClient", return_value=mock_client), \
         mock.patch("llm.AzureKeyCredential") as mock_cred:
        llm.call_github_models("sys", "user")
    mock_cred.assert_called_once_with("my-pat")


def test_call_github_models_sets_json_mode(monkeypatch):
    monkeypatch.setenv("GH_MODELS_TOKEN", "tok")
    mock_client = _make_mock_azure_client()
    with mock.patch("llm.ChatCompletionsClient", return_value=mock_client):
        llm.call_github_models("sys", "user", json_mode=True)
    _, kwargs = mock_client.complete.call_args
    assert kwargs.get("response_format") == "json_object"


def test_call_github_models_no_json_mode_by_default(monkeypatch):
    monkeypatch.setenv("GH_MODELS_TOKEN", "tok")
    mock_client = _make_mock_azure_client()
    with mock.patch("llm.ChatCompletionsClient", return_value=mock_client):
        llm.call_github_models("sys", "user")
    _, kwargs = mock_client.complete.call_args
    assert "response_format" not in kwargs


# --- call_llm (dispatcher + fallback) ---

def test_call_llm_uses_xai_primary(monkeypatch):
    monkeypatch.setenv("XAI_API_KEY", "tok")
    mock_client = _make_mock_openai_client("from-xai")
    with mock.patch("llm.OpenAI", return_value=mock_client):
        result = llm.call_llm("sys", "user")
    assert result == "from-xai"


def test_call_llm_falls_back_on_xai_failure(monkeypatch):
    monkeypatch.setenv("XAI_API_KEY", "tok")
    monkeypatch.setenv("GH_MODELS_TOKEN", "tok")
    mock_azure = _make_mock_azure_client("from-fallback")
    with mock.patch("llm.OpenAI", side_effect=Exception("xai down")), \
         mock.patch("llm.ChatCompletionsClient", return_value=mock_azure):
        result = llm.call_llm("sys", "user")
    assert result == "from-fallback"
