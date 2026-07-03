"""Quick smoke test for xAI (grok-4.3) and GitHub Models fallback.

Manual: hits the real APIs. Filename is intentionally not `test_*.py` so
pytest's auto-collection skips it; run it directly when you want to verify
provider connectivity.

Run with:  XAI_API_KEY=<key> GH_MODELS_TOKEN=<pat> .venv/bin/python3 xai_smoke.py
"""

import json
import time
from dotenv import load_dotenv

import llm


def check(label, raw, elapsed, expect_type):
    print(f"\n{'='*60}")
    print(f"[{label}]  {elapsed:.1f}s")
    print(f"Raw: {raw[:300]}{'...' if len(raw) > 300 else ''}")
    clean = llm._strip_fences(raw)
    try:
        parsed = json.loads(clean)
        if isinstance(parsed, expect_type):
            print(f"  OK: valid JSON {expect_type.__name__}")
        else:
            print(f"  FAIL: expected {expect_type.__name__}, got {type(parsed).__name__}")
    except json.JSONDecodeError as e:
        print(f"  FAIL: invalid JSON — {e}")


def main():
    load_dotenv()

    t0 = time.monotonic()
    raw = llm.call_xai("You are a helpful assistant.", "Say hello.")
    print(f"\n[xAI plain]  {time.monotonic()-t0:.1f}s  →  {raw!r}")

    t0 = time.monotonic()
    raw = llm.call_xai(
        "Generate exactly 2 security search queries. Return ONLY a JSON array of strings. No preamble.",
        "Generate 2 queries targeting actively exploited vulnerabilities.",
        temperature=0.4,
    )
    check("xAI JSON array", raw, time.monotonic()-t0, list)

    t0 = time.monotonic()
    raw = llm.call_xai(
        'Return ONLY a JSON object: {"compliance": ["q1"], "pqc": ["q1"]}',
        "Generate 1 compliance query and 1 PQC query.",
        temperature=0.3, json_mode=True,
    )
    check("xAI JSON object (json_mode)", raw, time.monotonic()-t0, dict)

    t0 = time.monotonic()
    raw = llm.call_github_models("You are a security analyst.", "Reply with exactly: ok")
    print(f"\n[GH Models fallback]  {time.monotonic()-t0:.1f}s  →  {raw!r}")

    print(f"\n{'='*60}\nDone.")


if __name__ == "__main__":
    main()
