"""Optional Slack notification via incoming webhook.

No-op unless SLACK_WEBHOOK_URL is set. Best-effort: a Slack failure never
fails the run — email (mailer.py) is the delivery of record.
"""

import os
import requests

_TIMEOUT_SEC = 10


def send_slack(text_body: str) -> None:
    webhook_url = os.environ.get("SLACK_WEBHOOK_URL", "").strip()
    if not webhook_url:
        return
    try:
        resp = requests.post(webhook_url, json={"text": text_body}, timeout=_TIMEOUT_SEC)
        resp.raise_for_status()
        print("Slack notification sent.")
    except requests.RequestException as exc:
        print(f"Slack notification failed (non-fatal): {exc}")
