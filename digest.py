#!/usr/bin/env python3
"""Need to Know — daily security digest orchestrator.

Pipeline:
  1. Fetch RSS articles (round-robin across feeds, state + blocklist filter)
  2. Generate web-search queries (RSS-anchored + independent horizon scan,
     both biased toward unfolding/on-fire events)
  3. Execute Brave Search and merge results
  4. Triage with two parallel GitHub Models calls: threat/compliance and tooling
  5. Render HTML + plain text and send via Resend
  6. Persist state (sent URLs -> 30-day suppression, candidate URLs -> cooldown)
"""

import os
import datetime
import concurrent.futures
from dotenv import load_dotenv

from llm import (
    generate_anchored_queries, generate_independent_queries,
    generate_slow_queries, generate_tooling_scan_queries,
    generate_ai_lab_queries,
    build_triage_input, parse_triage_output, call_llm, enrich_items,
    ANCHORED_QUERIES, INDEPENDENT_QUERIES,
    STACK_SUMMARY,
)
from config import (
    COMPLIANCE_QUERIES, PQC_QUERIES, TOOLING_SCAN_QUERIES, AI_LAB_QUERIES,
    TRIAGE_GLOBAL_CAP, TRIAGE_TOOLING_CAP,
    LLM_TIMEOUT_SEC,
    MAX_SEARCH_RESULTS, BROAD_SEARCH_RESULTS, SLOW_QUERIES_WEEKLY_ONLY,
)
from fetchers import fetch_rss_articles, fetch_search_articles
from state import load_state, save_state, record_candidates, record_sent, recent_sent_headlines, sent_today
from render import render_html, render_text, subject_line
from mailer import send_email

load_dotenv()


# Required env vars: the run cannot send a digest without these.
_REQUIRED_ENV = ("XAI_API_KEY", "GH_MODELS_TOKEN", "RESEND_API_KEY",
                 "DIGEST_TO_EMAIL", "DIGEST_FROM_EMAIL")


def _check_env() -> None:
    missing = [name for name in _REQUIRED_ENV if not os.environ.get(name)]
    if missing:
        raise RuntimeError(
            f"Missing required environment variable(s): {', '.join(missing)}. "
            f"See .env.example for the full list."
        )
    if not os.environ.get("BRAVE_API_KEY"):
        print("Warning: BRAVE_API_KEY is unset; web search stage will be a no-op.")


def _load_prompt(filename: str, today_str: str, lookback_hours: int) -> str:
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), filename)
    with open(path) as f:
        text = f.read()
    return (text
            .replace("{{DATE}}", today_str)
            .replace("{{LOOKBACK_HOURS}}", str(lookback_hours))
            .replace("{{STACK}}", STACK_SUMMARY))


def _merge_triage_results(items_a, items_b) -> list:
    """Merge threat-triage and tooling-triage outputs with dedup and slot caps."""
    a = items_a or []
    b = items_b or []

    seen: set = set()
    deduped_a: list = []
    deduped_b: list = []
    for it in a:
        u = (it.get("url") or "").strip().lower()
        if u and u not in seen:
            seen.add(u)
            deduped_a.append(it)
    for it in b:
        u = (it.get("url") or "").strip().lower()
        if u and u not in seen:
            seen.add(u)
            deduped_b.append(it)

    # Threats fill first; tooling contributes at most TRIAGE_TOOLING_CAP items.
    a_picks = deduped_a[:TRIAGE_GLOBAL_CAP]
    b_picks = deduped_b[:TRIAGE_TOOLING_CAP]
    return (a_picks + b_picks)[:TRIAGE_GLOBAL_CAP]


def get_lookback_hours() -> int:
    """72 hours on Monday (covers the weekend), 24 hours otherwise."""
    return 72 if datetime.date.today().weekday() == 0 else 24


def run() -> None:
    _check_env()
    lookback_hours = get_lookback_hours()
    mode = "Monday catchup" if lookback_hours == 72 else "standard"
    print(f"Lookback: {lookback_hours}h ({mode})")

    state = load_state()
    print(f"Loaded state: {len(state)} URLs in dedup/cooldown window.")

    # Skip the entire pipeline if an earlier run today already delivered.
    # Both scheduled runs (11:00 and 23:00 UTC) fall on the same UTC date,
    # so date-equality is a sound check; revisit if the schedule changes.
    if sent_today(state):
        print("An earlier run today already delivered a digest. Skipping pipeline.")
        return

    # --- RSS ---
    rss_articles, rss_stats = fetch_rss_articles(lookback_hours, state)
    print(f"RSS: {len(rss_articles)} articles after dedup/blocklist.")

    # --- Query generation ---
    print(f"Generating {ANCHORED_QUERIES} RSS-anchored queries...")
    anchored = generate_anchored_queries(rss_articles)
    for q in anchored:
        print(f"  [anchored] → {q}")

    print(f"Generating {INDEPENDENT_QUERIES} independent queries...")
    independent = generate_independent_queries(lookback_hours)
    for q in independent:
        print(f"  [independent] → {q}")

    # Compliance + PQC are slow-moving beats with little genuinely new coverage
    # day-to-day, so daily polling just guarantees backfill noise. Restrict them
    # to the Monday catch-up run (72h lookback) when SLOW_QUERIES_WEEKLY_ONLY.
    weekly_run = lookback_hours >= 48
    run_slow = weekly_run or not SLOW_QUERIES_WEEKLY_ONLY
    if run_slow:
        print(f"Generating {COMPLIANCE_QUERIES} compliance + {PQC_QUERIES} PQC queries (combined call)...")
        compliance, pqc = generate_slow_queries(lookback_hours)
        for q in compliance:
            print(f"  [compliance] → {q}")
        for q in pqc:
            print(f"  [pqc] → {q}")
    else:
        compliance, pqc = [], []
        print("Skipping compliance + PQC queries (weekly-only; not a Monday catch-up run).")

    print(f"Generating {TOOLING_SCAN_QUERIES} tooling-scan queries...")
    tooling_scan = generate_tooling_scan_queries(lookback_hours)
    for q in tooling_scan:
        print(f"  [tooling-scan] → {q}")

    print(f"Generating {AI_LAB_QUERIES} AI-lab queries...")
    ai_lab = generate_ai_lab_queries(lookback_hours)
    for q in ai_lab:
        print(f"  [ai-lab] → {q}")

    # --- Search ---
    # Labeled query specs carry a per-type result count and a label so the SKIP
    # report can attribute each candidate to the query that produced it. Abstract
    # horizon-scan types (independent urgency phrases, compliance, PQC) fetch fewer
    # results because Brave backfills their empty slots with trending noise; types
    # with concrete anchors keep the full count.
    def _specs(label: str, queries: list[str], count: int) -> list[dict]:
        return [{"label": label, "query": q, "count": count} for q in queries]

    query_specs = (
        _specs("anchored", anchored, MAX_SEARCH_RESULTS)
        + _specs("independent", independent, BROAD_SEARCH_RESULTS)
        + _specs("compliance", compliance, BROAD_SEARCH_RESULTS)
        + _specs("pqc", pqc, BROAD_SEARCH_RESULTS)
        + _specs("tooling-scan", tooling_scan, MAX_SEARCH_RESULTS)
        + _specs("ai-lab", ai_lab, MAX_SEARCH_RESULTS)
    )

    search_articles: list[dict] = []
    search_stats: dict = {"fetched": 0, "after_rss_dedup": 0, "after_state_dedup": 0, "after_blocklist": 0}
    if query_specs:
        search_articles, search_stats = fetch_search_articles(
            query_specs, lookback_hours, state, rss_articles,
        )

    all_articles = rss_articles + search_articles
    print(f"Total candidates for triage: {len(all_articles)} "
          f"({len(rss_articles)} RSS + {len(search_articles)} web search)")

    if not all_articles:
        print("No articles found. Exiting.")
        return

    # Record every candidate URL that reached triage. This drives cooldown:
    # near-misses won't recycle into the pool every day. Sent URLs later
    # override this with a longer TTL.
    record_candidates(state, [a["link"] for a in all_articles])

    # --- Load and interpolate analyst prompts ---
    today_str = datetime.date.today().strftime("%B %d, %Y")
    threat_prompt = _load_prompt("prompt_threat.txt", today_str, lookback_hours)
    tooling_prompt = _load_prompt("prompt_tooling.txt", today_str, lookback_hours)

    recent_headlines = recent_sent_headlines(state)
    recent_block = ""
    if recent_headlines:
        lines = "\n".join(f"- {h}" for h in recent_headlines)
        recent_block = (
            "Recently delivered digest items (last 7 days). The reader has already "
            "seen these events covered. Do NOT re-cover the same underlying event, "
            "even if a new article or source has appeared. The following are NOT new "
            "developments that override this suppression — exclude follow-up coverage "
            "describing: additional victims; additional compromises; expanded scope "
            "within the same campaign; newly discovered packages, payloads, or IOCs "
            "within an already-reported operation; 'still ongoing', 'still unfolding', "
            "'continues to spread', 'no sign of slowing'; updated incident-response "
            "timelines; retrospective analysis or post-mortems. Re-cover ONLY if the "
            "new article reports a genuinely distinct attack vector, a previously "
            "unaffected ecosystem newly drawn in (not 'more victims in the same "
            "ecosystem'), or a vendor-confirmed material change to remediation guidance.\n\n"
            f"Already covered:\n{lines}\n\n"
        )

    article_preamble = (
        f"Today is {today_str}. "
        f"Here are {len(all_articles)} articles from the last {lookback_hours} hours "
        f"({len(rss_articles)} from RSS feeds, {len(search_articles)} from web search).\n\n"
    )
    article_body = build_triage_input(all_articles)

    threat_user_msg = (
        f"{article_preamble}"
        f"Apply the fire-tier bar. SKIP is a better answer than marginal inclusions.\n\n"
        f"{recent_block}"
        f"{article_body}"
    )
    tooling_user_msg = (
        f"{article_preamble}"
        f"Select at most one tooling item worth the reader's time today. SKIP if nothing qualifies.\n\n"
        f"{recent_block}"
        f"{article_body}"
    )

    # --- Parallel triage ---
    print("Triaging (threat + tooling in parallel)...")
    raw_threat: str = ""
    raw_tooling: str = ""
    # call_llm tries xAI then falls back to GitHub Models, so worst-case wall
    # time for one future is roughly 2 * LLM_TIMEOUT_SEC. Add slack and let
    # the future-level timeout act as a hard backstop if both SDKs misbehave.
    triage_deadline = (LLM_TIMEOUT_SEC * 2) + 10
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
        fut_threat = executor.submit(
            call_llm, threat_prompt, threat_user_msg,
            temperature=0.15, json_mode=True,
        )
        fut_tooling = executor.submit(
            call_llm, tooling_prompt, tooling_user_msg,
            temperature=0.15, json_mode=True,
        )
        try:
            raw_threat = fut_threat.result(timeout=triage_deadline)
        except Exception as exc:
            print(f"Threat triage call failed: {exc}")
        try:
            raw_tooling = fut_tooling.result(timeout=triage_deadline)
        except Exception as exc:
            print(f"Tooling triage call failed: {exc}")

    pool_summary = (
        f"RSS pool: {rss_stats['fetched']} fetched"
        f" -> {rss_stats['after_state_dedup']} after state dedup"
        f" -> {rss_stats['after_blocklist']} after blocklist"
        f" -> {rss_stats['after_cross_feed_dedup']} after cross-feed dedup\n"
        f"Search pool: {search_stats['fetched']} fetched"
        f" -> {search_stats['after_rss_dedup']} after RSS dedup"
        f" -> {search_stats['after_state_dedup']} after state dedup"
        f" -> {search_stats['after_blocklist']} after blocklist\n"
        f"Queries: {len(anchored)} anchored, {len(independent)} independent,"
        f" {len(compliance)} compliance, {len(pqc)} pqc,"
        f" {len(tooling_scan)} tooling-scan, {len(ai_lab)} ai-lab\n"
        f"Triage candidates: {len(all_articles)} total"
        f" ({len(rss_articles)} RSS + {len(search_articles)} search)\n"
    )

    log_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "last_run.txt")
    with open(log_path, "w") as f:
        f.write(pool_summary)
        f.write("\n=== THREAT ===\n")
        f.write(raw_threat)
        f.write("\n\n=== TOOLING ===\n")
        f.write(raw_tooling)
    print(f"Raw LLM output written to {log_path}")

    if not raw_threat and not raw_tooling:
        print("Both triage calls failed. Persisting state and exiting.")
        save_state(state)
        return

    # Parse each call independently: bad JSON from one must not discard the
    # other's good output or crash the run before save_state.
    def _safe_parse(raw: str, label: str):
        if not raw:
            return None
        try:
            return parse_triage_output(raw)
        except RuntimeError as exc:
            print(f"{label} triage output unusable: {exc}")
            return None

    items_threat = _safe_parse(raw_threat, "Threat")
    items_tooling = _safe_parse(raw_tooling, "Tooling")

    items = _merge_triage_results(items_threat, items_tooling)
    if not items:
        print("Nothing noteworthy today (SKIP). Persisting state and exiting.")
        save_state(state)
        return

    # --- Second-pass enrichment ---
    # Triage selected on title + short summary; fetch the chosen articles and
    # let the LLM sharpen why/action with full text. Best-effort: any failure
    # ships the triage-time fields. Selection itself is never re-litigated.
    print(f"Enriching {len(items)} item(s) with article text...")
    try:
        items = enrich_items(items)
    except Exception as exc:
        print(f"Enrichment pass failed (continuing with triage output): {exc}")

    # --- Render and send ---
    print(f"Rendering and sending {len(items)} item(s).")
    html_body = render_html(items, today_str)
    text_body = render_text(items, today_str)
    subject = subject_line(items, today_str)
    send_email(html_body, text_body, subject)

    # --- Promote sent URLs (longer TTL) and persist ---
    sent_count = 0
    for item in items:
        url = item.get("url")
        if url:
            record_sent(state, [url], headline=item.get("headline", ""))
            sent_count += 1
    save_state(state)
    print(f"Recorded {sent_count} sent URLs. State now: {len(state)} entries.")


if __name__ == "__main__":
    run()
