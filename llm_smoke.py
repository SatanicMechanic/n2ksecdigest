"""Quick smoke test for the configured LLM provider.

Manual: hits the real APIs. Filename is intentionally not `test_*.py` so
pytest's auto-collection skips it; run it directly when you want to verify
provider connectivity.

Run with:  LLM_MODEL=<model> <PROVIDER_KEY>=<key> .venv/bin/python3 llm_smoke.py
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
    raw = llm.call_llm("You are a helpful assistant.", "Say hello.")
    print(f"\n[plain]  {time.monotonic()-t0:.1f}s  →  {raw!r}")

    t0 = time.monotonic()
    raw = llm.call_llm(
        "Generate exactly 2 security search queries. Return ONLY a JSON array of strings. No preamble.",
        "Generate 2 queries targeting actively exploited vulnerabilities.",
        temperature=0.4,
    )
    check("JSON array", raw, time.monotonic()-t0, list)

    t0 = time.monotonic()
    raw = llm.call_llm(
        'Return ONLY a JSON object: {"compliance": ["q1"], "pqc": ["q1"]}',
        "Generate 1 compliance query and 1 PQC query.",
        temperature=0.3, json_mode=True,
    )
    check("JSON object (json_mode)", raw, time.monotonic()-t0, dict)

    print(f"\n{'='*60}\nDone.")


if __name__ == "__main__":
    main()
