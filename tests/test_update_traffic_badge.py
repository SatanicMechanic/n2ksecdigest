"""Tests for update_traffic_badge.py — daily ledger merge and badge payload."""

import update_traffic_badge as badge


def test_merge_skips_today():
    daily = [
        {"timestamp": "2026-08-20T00:00:00Z", "count": 5, "uniques": 3},
        {"timestamp": "2026-08-21T00:00:00Z", "count": 2, "uniques": 2},
    ]
    result = badge.merge({}, daily, today="2026-08-21")
    assert result == {"2026-08-20": 3}


def test_merge_upserts_past_days_and_keeps_untouched_history():
    history = {"2026-08-01": 1}
    daily = [{"timestamp": "2026-08-20T00:00:00Z", "count": 5, "uniques": 4}]
    result = badge.merge(history, daily, today="2026-08-21")
    assert result == {"2026-08-01": 1, "2026-08-20": 4}


def test_badge_payload_sums_and_labels_earliest_month():
    history = {"2026-08-20": 3, "2026-08-21": 2, "2026-09-01": 5}
    payload = badge.badge_payload(history)
    assert payload["message"] == "10"
    assert payload["label"] == "clones since Aug 2026"
    assert payload["schemaVersion"] == 1


def test_badge_payload_empty_history():
    payload = badge.badge_payload({})
    assert payload["message"] == "0"
