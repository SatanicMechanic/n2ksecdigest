# config.py — single source of truth for tuning constants.
# Imported by digest.py, fetchers.py, state.py, llm.py, and check_feeds.py.
#
# Feed philosophy: RSS covers primary sources we want systematic coverage of.
# Web search (Brave) supplements with targeted follow-ups and independent
# horizon-scan queries. Triage uses two parallel LLM calls: prompt_threat.txt
# (fire-tier threats + compliance) and prompt_tooling.txt (GitHub/AWS/OSS features).

import os
import re

# ---------------------------------------------------------------------------
# RSS feeds — loaded from feeds.md (markdown link list)
# ---------------------------------------------------------------------------
# Each `[name](url)` pair in feeds.md becomes a feed URL. Headings, plain
# text, and other non-link lines are ignored, so the file doubles as its own
# documentation. Forks edit feeds.md directly to change the feed set.

_LINK_RE = re.compile(r"\[[^\]]+\]\((https?://[^)]+)\)")


def _load_feeds() -> list[str]:
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "feeds.md")
    try:
        with open(path) as f:
            return _LINK_RE.findall(f.read())
    except FileNotFoundError:
        print("Warning: feeds.md not found; RSS pool will be empty.")
        return []


FEEDS = _load_feeds()

# ---------------------------------------------------------------------------
# Candidate pool sizing
# ---------------------------------------------------------------------------
# Tuned for signal
# quality: too many candidates dilutes the LLM's ranking; too few starves it.

MAX_RSS_ARTICLES = 40
SUMMARY_MAX_CHARS = 350
PER_FEED_CAP = 8        # round-robin: max items pulled per feed per run

# ---------------------------------------------------------------------------
# Block list (applied before LLM triage)
# ---------------------------------------------------------------------------
# Word-boundary regex match (case-insensitive) on title; suffix match on link host.
# Use sparingly — over-blocking hides news you'd want to see.

BLOCKLIST_TITLE_TERMS: list[str] = [
    # Scheduled patch-cycle recaps are scanner territory by definition —
    # prompt_threat.txt already excludes them; blocking saves the pool slot.
    "patch tuesday",
    "monthly security update",
]
BLOCKLIST_DOMAINS: list[str] = [
    "wikipedia.org",  # reference encyclopedia, never news
    "upstract.com",   # feed-of-feeds aggregator landing page
    "okx.com",        # crypto exchange / price pages, never prodsec
    "stocktwits.com", # retail-stock sentiment, never prodsec
    "youtube.com",    # video content; triage can only read the title
]

# Full-URL regex patterns (matched case-insensitively against the whole link).
# Targets evergreen index / section / price / marketing pages that ALWAYS look
# fresh to the search engine (their page_age updates daily) but never contain a
# single fire-tier article. These slip past a title-term or domain match because
# the host also serves real news — the give-away is the path, not the domain.
# Keep precise; over-broad patterns hide news you'd want to see.
BLOCKLIST_URL_PATTERNS: list[str] = [
    r"/price[s]?/",                                   # crypto/stock price pages
    r"/quote/",                                       # ticker quote pages
    r"/cryptocurrency/",                              # crypto market sections
    r"reuters\.com/markets/",                         # finance section index
    r"reuters\.com/technology/artificial-intelligence",  # AI section index
    r"sciencedaily\.com/news/",                       # topic listing pages
    r"aws\.amazon\.com/compliance/",                  # evergreen compliance marketing
    # Bare homepages are never articles (aws.amazon.com/, trust.wiz.io/, ...).
    # Operator-heavy queries used to pull these as backfill; belt and
    # suspenders alongside the query-prompt operator ban.
    r"^https?://[^/]+/?(\?.*)?$",
    # One-segment newsroom/section indexes (anthropic.com/news, openai.com/blog).
    # Path ends at the segment, so real articles (/news/some-story) still pass.
    r"^https?://[^/]+/(news|blog|blogs|newsroom|press|updates|research)/?(\?.*)?$",
    # Section/index/listing roots whose page_age always looks fresh.
    r"aws\.amazon\.com/(new|blogs|resources)/([a-z-]+/)?(\?.*)?$",
    r"github\.com/advisories/?$",
    r"/release-notes/?$",
    # Status dashboards — operational state, never news.
    r"^https?://status\.",
]

# ---------------------------------------------------------------------------
# LLM (GitHub Models)
# ---------------------------------------------------------------------------

GITHUB_MODELS_BASE_URL = "https://models.github.ai/inference"
XAI_BASE_URL = "https://api.x.ai/v1"
XAI_MODEL = "grok-4.5"                  # primary model (all calls)
FALLBACK_MODEL = "openai/gpt-4.1-nano"  # GitHub Models fallback (all calls)
# nano over mini: GitHub Models free-tier budgets can 403 ("budget limit
# reached") on mini/4o-class models partway through a billing cycle; nano is
# the cheapest fallback that keeps the pipeline alive. Bump back up if your
# tier's budget allows.
LLM_TIMEOUT_SEC = 60                    # per-provider request budget
TRIAGE_GLOBAL_CAP = 3                   # max total items across both triage calls
TRIAGE_TOOLING_CAP = 1                  # max items from the tooling triage call

# ---------------------------------------------------------------------------
# Cross-run state (URL dedup + candidate cooldown)
# ---------------------------------------------------------------------------
# Two TTL classes:
#   sent      — articles delivered in a digest, suppressed for SENT_TTL days
#   candidate — articles that reached triage but weren't chosen, cooled down
#               so daily near-misses don't recycle into the pool every run

STATE_PATH = "state.json"
STATE_SENT_TTL_DAYS = 30
STATE_CANDIDATE_COOLDOWN_DAYS = 5

# ---------------------------------------------------------------------------
# Brave Search
# ---------------------------------------------------------------------------

BRAVE_SEARCH_URL = "https://api.search.brave.com/res/v1/web/search"
MAX_SEARCH_QUERIES = 6      # anchored (1) + independent (5); compliance/PQC/tooling-scan/AI-lab are separate
COMPLIANCE_QUERIES = 1  # separate from MAX_SEARCH_QUERIES
PQC_QUERIES = 1
TOOLING_SCAN_QUERIES = 1  # cloud/CI/CD platform features + engineering security write-ups; separate from MAX_SEARCH_QUERIES
AI_LAB_QUERIES = 1  # major AI lab security-capability releases (Anthropic, OpenAI, DeepMind, etc.); separate slot so it's not crowded out by general tooling
MAX_SEARCH_RESULTS = 5      # Brave results fetched per query (default / focused)
# Abstract horizon-scan queries (independent urgency phrases, compliance, PQC)
# have far fewer than 5 genuine fresh matches on a normal day, so Brave backfills
# the empty slots with whatever trending content loosely token-matches. Fetching
# fewer results from these query types shrinks that backfill surface. Anchored,
# tooling-scan, and AI-lab queries have concrete anchors and keep the full count.
BROAD_SEARCH_RESULTS = 3

# Optional Brave "goggle" (hosted re-ranking/allowlist definition). When set to a
# goggle URL, it biases results toward a curated source set — e.g. a security-news
# allowlist. Left empty by default; no goggle is applied unless configured.
BRAVE_GOGGLES = os.environ.get("BRAVE_GOGGLES", "").strip()

# Slow-moving beats (compliance, post-quantum crypto) rarely have genuinely new
# coverage day-to-day, so polling them every run guarantees backfill noise.
# Restrict them to the Monday catch-up run (the 72h lookback window).
SLOW_QUERIES_WEEKLY_ONLY = True

# ---------------------------------------------------------------------------
# HTTP fetch tuning
# ---------------------------------------------------------------------------

FEED_FETCH_TIMEOUT_SEC = 10
HTTP_USER_AGENT = "n2ksecdigest/2.0 (+github.com)"
