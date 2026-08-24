#!/usr/bin/env python3
"""Maintain a cumulative clone-count badge from GitHub's traffic API.

GitHub only exposes a rolling 14-day window with no history before that, so
this script snapshots it daily into badges/clone-history.json (one entry per
calendar day) and sums the ledger for an all-time total. Run daily via
traffic-badge.yml; today's entry is always skipped since its count is still
incomplete mid-day.
"""

import json
import os
import subprocess
from datetime import date, datetime

HISTORY_PATH = "badges/clone-history.json"
BADGE_PATH = "badges/clones.json"


def fetch_daily_clones(repo: str) -> list[dict]:
    raw = subprocess.run(
        ["gh", "api", f"repos/{repo}/traffic/clones"],
        stdout=subprocess.PIPE, text=True, check=True,
    ).stdout
    return json.loads(raw)["clones"]


def load_history(path: str = HISTORY_PATH) -> dict[str, int]:
    try:
        with open(path) as f:
            return json.load(f)
    except FileNotFoundError:
        return {}


def merge(history: dict[str, int], daily: list[dict], today: str | None = None) -> dict[str, int]:
    today = today or date.today().isoformat()
    for entry in daily:
        day = entry["timestamp"][:10]
        if day == today:
            continue
        history[day] = entry["uniques"]
    return history


def badge_payload(history: dict[str, int]) -> dict:
    total = sum(history.values())
    since = min(history) if history else date.today().isoformat()
    since_label = datetime.fromisoformat(since).strftime("%b %Y")
    return {
        "schemaVersion": 1,
        "label": f"clones since {since_label}",
        "message": str(total),
        "color": "blue",
    }


if __name__ == "__main__":
    repo = os.environ["GITHUB_REPOSITORY"]
    history = merge(load_history(), fetch_daily_clones(repo))
    os.makedirs("badges", exist_ok=True)
    with open(HISTORY_PATH, "w") as f:
        json.dump(history, f, indent=2, sort_keys=True)
    with open(BADGE_PATH, "w") as f:
        json.dump(badge_payload(history), f, indent=2)
