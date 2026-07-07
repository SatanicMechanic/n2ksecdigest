"""Tests for slack.py — optional webhook notification."""

from unittest import mock

import slack


def test_send_slack_noop_when_unset(monkeypatch):
    monkeypatch.delenv("SLACK_WEBHOOK_URL", raising=False)
    with mock.patch.object(slack.requests, "post") as mock_post:
        slack.send_slack("digest body")
    mock_post.assert_not_called()


def test_send_slack_posts_text_when_set(monkeypatch):
    monkeypatch.setenv("SLACK_WEBHOOK_URL", "https://hooks.slack.com/services/x")
    with mock.patch.object(slack.requests, "post") as mock_post:
        mock_post.return_value = mock.Mock(status_code=200)
        slack.send_slack("digest body")
    mock_post.assert_called_once()
    args, kwargs = mock_post.call_args
    assert args[0] == "https://hooks.slack.com/services/x"
    assert kwargs["json"] == {"text": "digest body"}


def test_send_slack_failure_is_non_fatal(monkeypatch):
    monkeypatch.setenv("SLACK_WEBHOOK_URL", "https://hooks.slack.com/services/x")
    with mock.patch.object(slack.requests, "post", side_effect=slack.requests.RequestException("down")):
        slack.send_slack("digest body")  # must not raise
