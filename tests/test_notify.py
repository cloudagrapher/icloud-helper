"""Tests for icloud_helper.notify.

All HTTP calls are mocked — no real network requests are made.
"""
from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Dict, List
from unittest.mock import MagicMock, patch

import pytest

from icloud_helper.notify import (
    _build_message_body,
    _SECRETS_DIR,
    send_pending_notification,
)
from icloud_helper.state import StateStore


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def store(tmp_path: Path) -> StateStore:
    """Return an initialised StateStore backed by a tmp_path database."""
    db_path = tmp_path / "test_mailcleaner.db"
    s = StateStore(db_path=db_path)
    s.init_db()
    return s


@pytest.fixture()
def store_with_pending(store: StateStore) -> StateStore:
    """Return a store pre-populated with one unnotified pending sender."""
    store.upsert_pending(
        "news@example.com",
        "Example News",
        "example.com",
        "one-click",
        "newsletter",
        10,
    )
    return store


# ---------------------------------------------------------------------------
# _build_message_body unit tests
# ---------------------------------------------------------------------------


class TestBuildMessageBody:
    """Unit tests for the internal message builder."""

    def test_includes_sender_address(self) -> None:
        """Body must contain the sender email address."""
        rows: List[Dict] = [
            {
                "sender": "news@example.com",
                "display_name": "Example News",
                "classification": "newsletter",
                "unsub_method": "one-click",
                "message_count": 5,
            }
        ]
        body = _build_message_body(rows)
        assert "news@example.com" in body

    def test_includes_classification_and_method(self) -> None:
        """Body must show classification and unsubscribe method."""
        rows: List[Dict] = [
            {
                "sender": "spam@bad.com",
                "display_name": "",
                "classification": "spam",
                "unsub_method": "none",
                "message_count": 2,
            }
        ]
        body = _build_message_body(rows)
        assert "spam" in body
        assert "none" in body

    def test_includes_message_count(self) -> None:
        """Body must include the message count."""
        rows: List[Dict] = [
            {
                "sender": "a@b.com",
                "display_name": "",
                "classification": "unknown",
                "unsub_method": "mailto",
                "message_count": 42,
            }
        ]
        body = _build_message_body(rows)
        assert "42" in body

    def test_overflow_suffix_appended(self) -> None:
        """Overflow count must appear when non-zero."""
        rows: List[Dict] = [
            {
                "sender": "a@b.com",
                "display_name": "",
                "classification": "newsletter",
                "unsub_method": "one-click",
                "message_count": 1,
            }
        ]
        body = _build_message_body(rows, overflow_count=3)
        assert "3 more" in body

    def test_policy_toml_snippet_present(self) -> None:
        """Body must contain the policy.toml key snippet for the sender."""
        rows: List[Dict] = [
            {
                "sender": "a@b.com",
                "display_name": "",
                "classification": "newsletter",
                "unsub_method": "one-click",
                "message_count": 1,
            }
        ]
        body = _build_message_body(rows)
        assert '["a@b.com"]' in body


# ---------------------------------------------------------------------------
# send_pending_notification integration tests (all HTTP mocked)
# ---------------------------------------------------------------------------


class TestSendPendingNotification:
    """Integration tests for send_pending_notification."""

    def test_dry_run_no_http_post(
        self, store_with_pending: StateStore, tmp_path: Path
    ) -> None:
        """In dry_run mode no HTTP POST must be made."""
        secret_file = tmp_path / "discord_webhook_url"
        secret_file.write_text("https://discord.com/api/webhooks/fake/url")

        with patch("icloud_helper.notify._SECRETS_DIR", tmp_path):
            with patch("urllib.request.urlopen") as mock_urlopen:
                result = send_pending_notification(
                    store_with_pending, dry_run=True
                )

        mock_urlopen.assert_not_called()
        assert result == 1

    def test_dry_run_logs_would_post(
        self,
        store_with_pending: StateStore,
        tmp_path: Path,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """Dry-run must log a message indicating what would be posted."""
        secret_file = tmp_path / "discord_webhook_url"
        secret_file.write_text("https://discord.com/api/webhooks/fake/url")

        with patch("icloud_helper.notify._SECRETS_DIR", tmp_path):
            with caplog.at_level(logging.INFO, logger="icloud_helper.notify"):
                send_pending_notification(store_with_pending, dry_run=True)

        assert any("DRY-RUN" in r.message for r in caplog.records)

    def test_live_posts_correct_json_payload(
        self, store_with_pending: StateStore, tmp_path: Path
    ) -> None:
        """Live mode must POST JSON with a 'content' key to the webhook."""
        secret_file = tmp_path / "discord_webhook_url"
        secret_file.write_text("https://discord.com/api/webhooks/fake/url")

        mock_response = MagicMock()
        mock_response.status = 200
        mock_response.__enter__ = lambda s: s
        mock_response.__exit__ = MagicMock(return_value=False)

        with patch("icloud_helper.notify._SECRETS_DIR", tmp_path):
            with patch("urllib.request.urlopen", return_value=mock_response):
                with patch("urllib.request.Request") as mock_request_cls:
                    result = send_pending_notification(
                        store_with_pending, dry_run=False
                    )

        assert result == 1
        _, kwargs = mock_request_cls.call_args
        payload = json.loads(kwargs.get("data") or mock_request_cls.call_args[0][1])
        assert "content" in payload

    def test_absent_secret_file_returns_zero_no_crash(
        self,
        store_with_pending: StateStore,
        tmp_path: Path,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """When secrets/discord_webhook_url is absent the function must return 0
        without raising an exception, and must log a WARNING."""
        # tmp_path has no discord_webhook_url file
        with patch("icloud_helper.notify._SECRETS_DIR", tmp_path):
            with caplog.at_level(logging.WARNING, logger="icloud_helper.notify"):
                result = send_pending_notification(
                    store_with_pending, dry_run=False
                )

        assert result == 0
        assert any("not found" in r.message for r in caplog.records)

    def test_empty_secret_returns_zero_with_warning(
        self,
        store_with_pending: StateStore,
        tmp_path: Path,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """When secrets/discord_webhook_url exists but is empty the function
        must return 0 and log a WARNING."""
        secret_file = tmp_path / "discord_webhook_url"
        secret_file.write_text("   ")  # whitespace only — read_secret strips it

        with patch("icloud_helper.notify._SECRETS_DIR", tmp_path):
            with caplog.at_level(logging.WARNING, logger="icloud_helper.notify"):
                result = send_pending_notification(
                    store_with_pending, dry_run=False
                )

        assert result == 0
        assert any("empty" in r.message for r in caplog.records)

    def test_no_pending_senders_returns_zero(
        self, store: StateStore, tmp_path: Path
    ) -> None:
        """With no unnotified pending senders the function must return 0."""
        secret_file = tmp_path / "discord_webhook_url"
        secret_file.write_text("https://discord.com/api/webhooks/fake/url")

        with patch("icloud_helper.notify._SECRETS_DIR", tmp_path):
            with patch("urllib.request.urlopen") as mock_urlopen:
                result = send_pending_notification(store, dry_run=False)

        mock_urlopen.assert_not_called()
        assert result == 0

    def test_http_error_returns_zero(
        self, store_with_pending: StateStore, tmp_path: Path
    ) -> None:
        """HTTP error from Discord must return 0 without raising."""
        import urllib.error

        secret_file = tmp_path / "discord_webhook_url"
        secret_file.write_text("https://discord.com/api/webhooks/fake/url")

        with patch("icloud_helper.notify._SECRETS_DIR", tmp_path):
            with patch(
                "urllib.request.urlopen",
                side_effect=urllib.error.HTTPError(
                    url="https://x.com", code=400, msg="Bad Request",
                    hdrs=None, fp=None,  # type: ignore[arg-type]
                ),
            ):
                result = send_pending_notification(
                    store_with_pending, dry_run=False
                )

        assert result == 0
