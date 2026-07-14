"""Resend email delivery with both HTML and plain-text bodies."""

import os
import requests
from requests.adapters import HTTPAdapter
from urllib3.util import Retry


_RESEND_URL = "https://api.resend.com/emails"
_TIMEOUT_SEC = 15
# 1 initial + 2 retries on connection errors and retryable statuses.
# Non-429 4xx is a permanent payload/auth problem — not in the forcelist,
# so it fails immediately via raise_for_status below.
_RETRIES = Retry(
    total=2,
    backoff_factor=2,
    status_forcelist=[429, 500, 502, 503, 504],
    allowed_methods=["POST"],
)


def send_email(html_body: str, text_body: str, subject: str) -> None:
    api_key = os.environ["RESEND_API_KEY"]
    to_addresses = [
        addr.strip()
        for addr in os.environ["DIGEST_TO_EMAIL"].split(",")
        if addr.strip()
    ]
    from_address = os.environ["DIGEST_FROM_EMAIL"]

    session = requests.Session()
    session.mount("https://", HTTPAdapter(max_retries=_RETRIES))
    try:
        resp = session.post(
            _RESEND_URL,
            headers={"Authorization": f"Bearer {api_key}"},
            json={
                "from": from_address,
                "to": to_addresses,
                "subject": subject,
                "html": html_body,
                "text": text_body,
            },
            timeout=_TIMEOUT_SEC,
        )
        resp.raise_for_status()
    except requests.RequestException as exc:
        raise RuntimeError("Resend delivery failed after retries") from exc
    print("Email sent.")
