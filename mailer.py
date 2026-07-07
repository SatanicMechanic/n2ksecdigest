"""Resend email delivery with both HTML and plain-text bodies."""

import os
import time
import requests


_RESEND_URL = "https://api.resend.com/emails"
_TIMEOUT_SEC = 15
_RETRY_ATTEMPTS = 3   # 1 initial + 2 retries
_RETRY_BACKOFF_SEC = (2, 5)


def send_email(html_body: str, text_body: str, subject: str) -> None:
    api_key = os.environ["RESEND_API_KEY"]
    to_addresses = [
        addr.strip()
        for addr in os.environ["DIGEST_TO_EMAIL"].split(",")
        if addr.strip()
    ]
    from_address = os.environ["DIGEST_FROM_EMAIL"]

    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
    }
    payload = {
        "from": from_address,
        "to": to_addresses,
        "subject": subject,
        "html": html_body,
        "text": text_body,
    }

    last_exc: Exception | None = None
    for attempt in range(_RETRY_ATTEMPTS):
        try:
            resp = requests.post(
                _RESEND_URL, headers=headers, json=payload, timeout=_TIMEOUT_SEC,
            )
        except requests.RequestException as exc:
            last_exc = exc
        else:
            if resp.status_code in (200, 201):
                print("Email sent.")
                return
            # 4xx (other than 429) is a permanent problem with our payload
            # or auth — no point retrying.
            if 400 <= resp.status_code < 500 and resp.status_code != 429:
                resp.raise_for_status()
            last_exc = requests.HTTPError(
                f"Resend returned {resp.status_code}: {resp.text[:200]}",
                response=resp,
            )

        if attempt < _RETRY_ATTEMPTS - 1:
            delay = _RETRY_BACKOFF_SEC[attempt]
            print(f"Resend attempt {attempt + 1} failed ({last_exc}); retrying in {delay}s.")
            time.sleep(delay)

    raise RuntimeError(f"Resend delivery failed after {_RETRY_ATTEMPTS} attempts") from last_exc
