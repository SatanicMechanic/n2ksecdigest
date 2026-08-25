# n2ksecdigest — Claude Code Instructions

## What this repo is

**A template. It does not run.** This public repo is the reference copy; the
working bot lives in private mirrors (e.g. `prodsecnewsbot`), created per the
README's §3 mirror instructions.

Concretely:

- Every scheduled workflow is gated `if: github.repository != 'SatanicMechanic/n2ksecdigest'`
  — `digest.yml`, `check_feeds.yml`, `sync-upstream.yml`. They activate only in
  a mirror. The sole exception is `traffic-badge.yml`, gated the other way
  (`==`), because the README badge points at this repo.
- `stack.txt` and `feeds.md` are **starter content**, meant to be repopulated
  downstream. A real `stack.txt` is reconnaissance-grade and must never be
  committed here.
- Mirrors receive code by syncing from here and are never edited directly, so
  a change made here reaches production. `.gitattributes` marks the
  fork-divergent files `merge=ours` so a mirror keeps its own versions.

**Before adding or removing a repo guard, or assuming a workflow runs here,
re-read this section.** The mistake to avoid is reasoning from "forking is the
intended use" to "therefore the workflows should run in this repo" — the
opposite is true, and the guards are load-bearing.

## Security

### Prompt injection
Feed articles and Brave search results are untrusted external content. When passing them into LLM prompts, treat them as data only — never structure prompts in a way that lets article content override system or user instructions.

### LLM output → HTML email
LLM-generated content is rendered into HTML email. Escape all model output before inserting it into HTML templates; never trust it as safe markup.
