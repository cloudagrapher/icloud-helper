"""Regression tests for actor._uid_fetch_headers key normalisation.

Verifies that _uid_fetch_headers always returns lowercase-keyed header
dicts, and that mixed-case IMAP headers are correctly detected as bulk
by the downstream pipeline (is_bulk -> triage_messages).

No live network connections are made; the IMAP connection is fully mocked.
"""
from __future__ import annotations

import email.message
import imaplib
from typing import Dict
from unittest.mock import MagicMock

import sys
import os

# actor.py lives at the project root, not inside a package.
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from actor import _uid_fetch_headers  # noqa: E402
from icloud_helper.headers import is_bulk, triage_messages  # noqa: E402


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_raw_headers(headers: Dict[str, str]) -> bytes:
    """Build a raw RFC email header block from a plain dict.

    Args:
        headers: Header name -> value pairs in any case.

    Returns:
        Raw bytes suitable as the body of an IMAP BODY.PEEK[HEADER] response.
    """
    msg = email.message.Message()
    for name, val in headers.items():
        msg[name] = val
    return msg.as_bytes()


def _make_imap_uid_fetch_response(uid: int, raw_headers: bytes) -> list:
    """Build the response list that imaplib.IMAP4_SSL.uid('FETCH',...) returns.

    Args:
        uid: The UID to embed in the FETCH metadata.
        raw_headers: Raw header bytes for the message.

    Returns:
        A list matching the shape imaplib returns for a single-message fetch.
    """
    meta = f"1 (UID {uid} BODY[HEADER] {{{len(raw_headers)}}})"
    return [(meta.encode("ascii"), raw_headers), b")"]


def _fetch(uid: int, headers: Dict[str, str]) -> Dict[str, str]:
    """Convenience: run _uid_fetch_headers for a single mocked message.

    Args:
        uid: UID to use for the mocked message.
        headers: Header name -> value pairs (may be mixed case).

    Returns:
        The header dict returned by _uid_fetch_headers for that UID.
    """
    raw = _make_raw_headers(headers)
    mock_imap = MagicMock(spec=imaplib.IMAP4_SSL)
    mock_imap.uid.return_value = (
        "OK",
        _make_imap_uid_fetch_response(uid, raw),
    )
    result = _uid_fetch_headers(mock_imap, [uid])
    return result.get(uid, {})


# ---------------------------------------------------------------------------
# Tests: _uid_fetch_headers key normalisation
# ---------------------------------------------------------------------------

class TestUidFetchHeadersKeyNormalisation:
    """_uid_fetch_headers must return dicts with only lowercase keys."""

    def test_from_key_is_lowercase(self) -> None:
        hdrs = _fetch(1, {"From": "Sender <sender@example.com>"})
        assert "from" in hdrs, "Expected lowercase 'from' key"
        assert "From" not in hdrs, "Mixed-case 'From' must not appear"

    def test_list_unsubscribe_key_is_lowercase(self) -> None:
        hdrs = _fetch(2, {"List-Unsubscribe": "<https://example.com/unsub>"})
        assert "list-unsubscribe" in hdrs
        assert "List-Unsubscribe" not in hdrs

    def test_list_unsubscribe_post_key_is_lowercase(self) -> None:
        hdrs = _fetch(3, {"List-Unsubscribe-Post": "List-Unsubscribe=One-Click"})
        assert "list-unsubscribe-post" in hdrs
        assert "List-Unsubscribe-Post" not in hdrs

    def test_precedence_key_is_lowercase(self) -> None:
        hdrs = _fetch(4, {"Precedence": "bulk"})
        assert "precedence" in hdrs
        assert "Precedence" not in hdrs

    def test_all_returned_keys_are_lowercase(self) -> None:
        """Every key in the returned dict must be fully lowercase."""
        raw_headers = {
            "From": "Sender <s@example.com>",
            "Subject": "Weekly Digest",
            "Date": "Thu, 01 Jan 2026 00:00:00 +0000",
            "List-Unsubscribe": "<https://example.com/unsub>",
            "List-Unsubscribe-Post": "List-Unsubscribe=One-Click",
            "List-Id": "<digest.example.com>",
            "Precedence": "bulk",
            "Auto-Submitted": "auto-generated",
        }
        hdrs = _fetch(5, raw_headers)
        assert hdrs, "Expected non-empty header dict"
        for key in hdrs:
            assert key == key.lower(), (
                f"Header key {key!r} is not fully lowercase"
            )

    def test_value_preserved_after_normalisation(self) -> None:
        """Lowercasing the key must not corrupt the value."""
        hdrs = _fetch(6, {"List-Unsubscribe": "<https://example.com/u>"})
        assert hdrs.get("list-unsubscribe") == "<https://example.com/u>"


# ---------------------------------------------------------------------------
# Tests: end-to-end bulk detection through the actor pipeline
# ---------------------------------------------------------------------------

class TestActorPipelineBulkDetection:
    """Headers fetched via actor's path must be detected as bulk correctly."""

    def _pipeline(self, uid: int, raw_headers: Dict[str, str]) -> dict:
        """Run _uid_fetch_headers -> triage_messages and return the result.

        Args:
            uid: Message UID for the mock.
            raw_headers: Header name -> value pairs (may be mixed case).

        Returns:
            Dict of sender address -> SenderRecord from triage_messages.
        """
        raw = _make_raw_headers(raw_headers)
        mock_imap = MagicMock(spec=imaplib.IMAP4_SSL)
        mock_imap.uid.return_value = (
            "OK",
            _make_imap_uid_fetch_response(uid, raw),
        )
        uid_headers = _uid_fetch_headers(mock_imap, [uid])
        return triage_messages(list(uid_headers.values()))

    def test_list_unsubscribe_detected_as_bulk(self) -> None:
        """Mixed-case List-Unsubscribe from IMAP must trigger bulk detection."""
        result = self._pipeline(
            101,
            {
                "From": "Newsletter <news@example.com>",
                "List-Unsubscribe": "<https://example.com/unsub>",
                "List-Id": "<news.example.com>",
            },
        )
        assert result, (
            "Expected at least one sender; got none. "
            "is_bulk() returned False for a List-Unsubscribe message — "
            "key-case mismatch likely not fixed."
        )
        sender = next(iter(result.values()))
        assert sender.unsubscribe_method != "none", (
            "Expected a real unsubscribe method, not 'none'"
        )

    def test_one_click_unsubscribe_method_resolved(self) -> None:
        """List-Unsubscribe + List-Unsubscribe-Post should yield one-click."""
        result = self._pipeline(
            102,
            {
                "From": "Promo <promo@shop.com>",
                "List-Unsubscribe": "<https://shop.com/unsub>",
                "List-Unsubscribe-Post": "List-Unsubscribe=One-Click",
                "List-Id": "<promo.shop.com>",
            },
        )
        assert result
        sender = next(iter(result.values()))
        assert sender.unsubscribe_method == "one-click", (
            f"Expected one-click, got {sender.unsubscribe_method!r}. "
            "list-unsubscribe-post key lookup may be broken."
        )

    def test_precedence_bulk_detected(self) -> None:
        """Precedence: bulk header (mixed case) must be detected."""
        result = self._pipeline(
            103,
            {
                "From": "Bulk <bulk@vendor.com>",
                "Precedence": "bulk",
            },
        )
        assert result, "Expected Precedence: bulk message to be detected"

    def test_plain_message_not_detected_as_bulk(self) -> None:
        """Ordinary message with no bulk signals must not appear in results."""
        result = self._pipeline(
            104,
            {
                "From": "Friend <friend@example.com>",
                "Subject": "Hey there",
            },
        )
        assert not result, (
            f"Non-bulk message falsely detected: {result}"
        )

    def test_from_address_extracted_correctly_after_fix(self) -> None:
        """The From address extracted via actor path must match sender key."""
        result = self._pipeline(
            105,
            {
                "From": "Corp Newsletter <corp@newsletter.example.com>",
                "List-Unsubscribe": "<https://newsletter.example.com/u>",
                "List-Id": "<nl.example.com>",
            },
        )
        assert result, "Expected a detected sender"
        assert "corp@newsletter.example.com" in result, (
            f"Expected addr key 'corp@newsletter.example.com', got: "
            f"{list(result.keys())}"
        )
