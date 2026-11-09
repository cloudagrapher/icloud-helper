"""Tests for icloud_helper.read_surface.

All tests are offline — no IMAP connections are made.
Compatible with Python 3.9 (.venv).
"""
from __future__ import annotations

import email
import email.mime.multipart
import email.mime.text
import email.message
import imaplib
from email.message import Message
from typing import Dict
from unittest.mock import MagicMock, patch

import pytest

from icloud_helper.read_surface import header_signals, search_uids


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_msg(headers: Dict[str, str], body: str = "Hello") -> Message:
    """Build a Message with the given headers and a text/plain body."""
    msg = email.mime.text.MIMEText(body, "plain", "utf-8")
    for name, value in headers.items():
        if name.lower() in msg:
            del msg[name]
        msg[name] = value
    return msg


def _make_html_msg(
    headers: Dict[str, str], html: str = "<p>Hello</p>"
) -> Message:
    """Build a multipart/alternative Message with text/html only."""
    outer = email.mime.multipart.MIMEMultipart("alternative")
    outer.attach(
        email.mime.text.MIMEText(html, "html", "utf-8")
    )
    for name, value in headers.items():
        outer[name] = value
    return outer


def _make_no_body_msg(headers: Dict[str, str]) -> Message:
    """Build a Message with no body parts."""
    msg = email.message.Message()
    for name, value in headers.items():
        msg[name] = value
    return msg


# ---------------------------------------------------------------------------
# Tests: snippet truncation via list_messages (tested via flagged helpers)
# ---------------------------------------------------------------------------

class TestSnippetTruncation:
    """Verify snippet is UTF-8-safe and honours max_snippet_bytes."""

    def test_snippet_within_limit_not_truncated(self) -> None:
        """Short body: snippet_truncated=False."""
        body = "Short body"
        msg = email.mime.text.MIMEText(body, "plain", "utf-8")
        # Use flagged.select_body_text to get body, then simulate truncation.
        from icloud_helper.flagged import select_body_text
        body_text, _ = select_body_text(msg)
        max_bytes = 8192
        encoded = body_text.encode("utf-8")
        truncated = len(encoded) > max_bytes
        assert not truncated
        assert body in body_text

    def test_snippet_truncation_utf8_safe(self) -> None:
        """Body exceeding limit is truncated at a UTF-8 boundary."""
        # Multi-byte characters: 3 bytes each in UTF-8.
        body = "€" * 4000  # 12 000 bytes > 8192
        msg = email.mime.text.MIMEText(body, "plain", "utf-8")
        from icloud_helper.flagged import select_body_text
        body_text, _ = select_body_text(msg)
        max_bytes = 8192
        encoded = body_text.encode("utf-8")
        truncated = len(encoded) > max_bytes
        assert truncated
        # Truncated slice must decode cleanly.
        snippet = encoded[:max_bytes].decode("utf-8", errors="ignore")
        assert snippet  # not empty
        # No partial multi-byte sequences survive (errors="ignore" drops them).
        snippet.encode("utf-8")  # must not raise


# ---------------------------------------------------------------------------
# Tests: header_signals
# ---------------------------------------------------------------------------

class TestHeaderSignals:
    """Verify header_signals output for various message types."""

    def test_plain_newsletter_signals(self) -> None:
        """Bulk newsletter message produces structural facts; label is 'bulk'."""
        msg = _make_msg(
            {
                "From": "Acme Newsletters <news@acme.com>",
                "List-Unsubscribe": "<https://acme.com/unsub>",
                "List-Unsubscribe-Post": "List-Unsubscribe=One-Click",
                "List-Id": "<news.acme.com>",
                "Precedence": "bulk",
            }
        )
        sigs = header_signals(msg)
        assert sigs["list_unsubscribe_method"] == "one-click"
        assert sigs["has_list_id"] is True
        assert sigs["precedence_bulk"] is True
        assert sigs["is_bulk"] is True
        # Tranche 3: read surface emits "bulk" only — no category verdict.
        assert sigs["heuristic_classification"] == "bulk"

    def test_html_only_bulk_signals(self) -> None:
        """HTML-only bulk message: is_bulk True from list-unsubscribe."""
        msg = _make_html_msg(
            {
                "From": "Promo <promo@shop.example.com>",
                "List-Unsubscribe": "<mailto:unsub@shop.example.com>",
            }
        )
        sigs = header_signals(msg)
        assert sigs["is_bulk"] is True
        assert sigs["list_unsubscribe_method"] == "mailto"
        assert sigs["has_list_id"] is False

    def test_plain_non_bulk_signals(self) -> None:
        """Message with no bulk headers: is_bulk False, classification unknown."""
        msg = _make_msg({"From": "Alice <alice@example.com>"})
        sigs = header_signals(msg)
        assert sigs["is_bulk"] is False
        assert sigs["list_unsubscribe_method"] == "none"
        assert sigs["has_list_id"] is False
        assert sigs["precedence_bulk"] is False

    def test_no_body_message_signals(self) -> None:
        """Message with no body parts still returns all expected signal keys."""
        msg = _make_no_body_msg(
            {
                "From": "Bulk <bulk@example.com>",
                "List-Unsubscribe": "<https://example.com/unsub>",
                "Precedence": "bulk",
            }
        )
        sigs = header_signals(msg)
        # Structural keys must be present.
        for key in (
            "list_unsubscribe_method",
            "has_list_id",
            "precedence_bulk",
            "is_bulk",
            "heuristic_classification",
        ):
            assert key in sigs, f"missing key: {key}"
        # New keys from Tranche 3.
        assert "auth" in sigs
        assert "local_part_looks_like_email" in sigs
        assert "from_domain_mismatch" in sigs
        assert "display_name_has_email" in sigs
        assert "has_otp_pattern" in sigs
        assert "has_receipt_pattern" in sigs
        assert "currency_total_present" in sigs
        assert "marketing_cta_density" in sigs
        assert sigs["is_bulk"] is True
        assert sigs["precedence_bulk"] is True

    def test_http_only_method(self) -> None:
        """http-only URL without one-click post header."""
        msg = _make_msg(
            {
                "From": "Ads <ads@example.com>",
                "List-Unsubscribe": "<http://example.com/unsub>",
            }
        )
        sigs = header_signals(msg)
        assert sigs["list_unsubscribe_method"] == "http-only"

    def test_classification_is_advisory_label(self) -> None:
        """heuristic_classification is present and one of the structural values.

        Tranche 3: only 'bulk' or 'not_bulk' are permitted — no category
        verdict (spam/newsletter/transactional) is emitted by the read surface.
        """
        msg = _make_msg({"From": "test@example.com"})
        sigs = header_signals(msg)
        assert sigs["heuristic_classification"] in ("bulk", "not_bulk")
        # Explicit: category verdicts are banned from the read surface.
        assert sigs["heuristic_classification"] not in (
            "spam", "newsletter", "unknown"
        )

    # ------------------------------------------------------------------
    # Bulk-gate hotfix tests
    # ------------------------------------------------------------------

    def test_non_bulk_otp_classified_not_bulk(self) -> None:
        """Non-bulk message (OTP/receipt shape) gets 'not_bulk', never 'spam'.

        Before the hotfix, classify_sender's first rule returned "spam"
        for any message lacking List-Unsubscribe.  OTPs, tax docs, and
        personal mail have no such header, so they were mislabeled.
        """
        msg = _make_msg(
            {
                "From": "no-reply@bank.example.com",
                "Subject": "Your one-time login code: 483920",
            }
        )
        sigs = header_signals(msg)
        assert sigs["is_bulk"] is False
        assert sigs["heuristic_classification"] == "not_bulk"
        assert sigs["heuristic_classification"] != "spam"

    def test_bulk_newsletter_label_is_bulk_not_verdict(self) -> None:
        """Bulk newsletter (List-Unsubscribe + List-Id): label is 'bulk' only.

        Tranche 3: the read surface no longer calls classify_sender.  All bulk
        mail receives the structural label 'bulk'; the model decides category.
        """
        msg = _make_msg(
            {
                "From": "Weekly Digest <digest@newsletter.example.com>",
                "List-Unsubscribe": "<https://newsletter.example.com/unsub>",
                "List-Unsubscribe-Post": "List-Unsubscribe=One-Click",
                "List-Id": "<digest.newsletter.example.com>",
                "Precedence": "bulk",
            }
        )
        sigs = header_signals(msg)
        assert sigs["is_bulk"] is True
        assert sigs["heuristic_classification"] == "bulk"
        assert sigs["heuristic_classification"] != "not_bulk"
        # No category verdict on the read surface.
        assert "newsletter" not in sigs.values()
        assert "spam" not in sigs.values()

    def test_bulk_without_list_unsub_is_still_bulk(self) -> None:
        """Bulk sender identified by List-Id/Precedence: label is 'bulk'.

        Tranche 3: classify_sender is no longer called from the read surface.
        The message is structurally bulk (is_bulk=True) → label='bulk'.
        """
        msg = _make_msg(
            {
                "From": "Bulk Sender <bulk@marketing.example.com>",
                "List-Id": "<promos.marketing.example.com>",
                "Precedence": "bulk",
            }
        )
        sigs = header_signals(msg)
        assert sigs["is_bulk"] is True
        assert sigs["heuristic_classification"] == "bulk"
        assert sigs["heuristic_classification"] != "not_bulk"
        # No 'spam' label from the read surface.
        assert "spam" not in sigs.values()


# ---------------------------------------------------------------------------
# Tests: search_uids
# ---------------------------------------------------------------------------

class TestSearchUids:
    """Verify search_uids thin-wrapper behaviour."""

    def test_returns_sorted_integers(self) -> None:
        """search_uids returns a sorted list of ints from the mock imap."""
        imap = MagicMock(spec=imaplib.IMAP4_SSL)
        imap.uid.return_value = ("OK", [b"103 101 102"])
        result = search_uids(imap, "ALL")
        assert result == [101, 102, 103]

    def test_unseen_criterion_passed_through(self) -> None:
        """search_uids passes the criterion to uid_search without modification."""
        imap = MagicMock(spec=imaplib.IMAP4_SSL)
        imap.uid.return_value = ("OK", [b"200"])
        result = search_uids(imap, "UNSEEN")
        # Should have called imap.uid("SEARCH", None, "UNSEEN")
        imap.uid.assert_called_once_with("SEARCH", None, "UNSEEN")
        assert result == [200]

    def test_empty_result_on_error(self) -> None:
        """search_uids returns [] on IMAP error."""
        imap = MagicMock(spec=imaplib.IMAP4_SSL)
        imap.uid.side_effect = imaplib.IMAP4.error("search failed")
        result = search_uids(imap, "ALL")
        assert result == []


# ---------------------------------------------------------------------------
# Tests: read-folder allowlist in list_messages MCP tool
# ---------------------------------------------------------------------------

class TestReadFolderAllowlist:
    """Verify list_messages / get_message_body reject non-allowlisted folders."""

    def test_list_messages_rejects_unlisted_folder(self) -> None:
        """list_messages returns error for a folder not in the allowlist."""
        pytest.importorskip(
            "mcp.server.fastmcp",
            reason="mcp requires Python >=3.10; run with .venv-mcp",
        )
        import icloud_helper.mcp_server as srv

        data = srv.list_messages(folder="Secret Projects")
        assert "error" in data
        assert data["error"] == "folder_not_allowed"

    def test_get_message_body_rejects_unlisted_folder(self) -> None:
        """get_message_body returns error for a folder not in the allowlist."""
        pytest.importorskip(
            "mcp.server.fastmcp",
            reason="mcp requires Python >=3.10; run with .venv-mcp",
        )
        import icloud_helper.mcp_server as srv

        data = srv.get_message_body(folder="Sent Messages", uid="42")
        assert "error" in data
        assert data["error"] == "folder_not_allowed"

    def test_list_messages_allows_inbox(self) -> None:
        """INBOX is in the allowlist; should pass the folder gate."""
        pytest.importorskip(
            "mcp.server.fastmcp",
            reason="mcp requires Python >=3.10; run with .venv-mcp",
        )
        import icloud_helper.mcp_server as srv

        # We patch the IMAP session so no real connection is made.
        with patch(
            "icloud_helper.flagged.open_readonly_session"
        ) as mock_session:
            mock_imap = MagicMock()
            mock_imap.uid.return_value = ("OK", [b""])
            mock_session.return_value.__enter__ = MagicMock(
                return_value=(mock_imap, 12345)
            )
            mock_session.return_value.__exit__ = MagicMock(return_value=False)

            # fetch_messages_batch returns empty dict → no messages.
            with patch(
                "icloud_helper.flagged.fetch_messages_batch",
                return_value={},
            ):
                with patch(
                    "icloud_helper.read_surface.search_uids",
                    return_value=[],
                ):
                    data = srv.list_messages(folder="INBOX", limit=5)
                    # Should NOT be an error dict.
                    assert "error" not in data
                    assert data["folder"] == "INBOX"


# ---------------------------------------------------------------------------
# Tests: get_message_body uidvalidity mismatch
# ---------------------------------------------------------------------------

class TestGetMessageBodyUidvalidity:
    """Verify uidvalidity mismatch is detected and reported."""

    def test_uidvalidity_mismatch_returns_error(self) -> None:
        """Mismatched uidvalidity produces uidvalidity_changed error."""
        pytest.importorskip(
            "mcp.server.fastmcp",
            reason="mcp requires Python >=3.10; run with .venv-mcp",
        )
        import icloud_helper.mcp_server as srv

        with patch(
            "icloud_helper.flagged.open_readonly_session"
        ) as mock_session:
            mock_imap = MagicMock()
            mock_session.return_value.__enter__ = MagicMock(
                return_value=(mock_imap, 99999)  # server says 99999
            )
            mock_session.return_value.__exit__ = MagicMock(return_value=False)

            # caller passes uidvalidity=12345 — mismatch
            data = srv.get_message_body(
                folder="INBOX", uid="42", uidvalidity=12345
            )
            assert data["error"] == "uidvalidity_changed"
            assert data["expected"] == 12345
            assert data["actual"] == 99999


# ---------------------------------------------------------------------------
# Tests: attachment manifest alignment
# ---------------------------------------------------------------------------

class TestAttachmentManifest:
    """Verify has_attachments and attachments keys are consistent."""

    def test_no_attachment_message(self) -> None:
        """Plain text message: has_attachments=False, attachments=[]."""
        from icloud_helper.flagged import build_manifest
        msg = email.mime.text.MIMEText("Hello", "plain", "utf-8")
        manifest = build_manifest(msg)
        assert manifest == []

    def test_message_with_attachment(self) -> None:
        """Message with PDF attachment: has_attachments=True, len=1."""
        import email.mime.application
        from icloud_helper.flagged import build_manifest
        outer = email.mime.multipart.MIMEMultipart("mixed")
        outer.attach(email.mime.text.MIMEText("Body", "plain", "utf-8"))
        pdf = email.mime.application.MIMEApplication(b"%PDF", "pdf")
        pdf.add_header("Content-Disposition", "attachment", filename="doc.pdf")
        outer.attach(pdf)
        manifest = build_manifest(outer)
        assert len(manifest) == 1
        assert bool(manifest) is True


# ---------------------------------------------------------------------------
# Tranche 3 regression and new-signal tests
# ---------------------------------------------------------------------------


def _make_msg_with_ar_headers(
    ar_values: list[str],
    from_header: str = "sender@example.com",
) -> "email.message.Message":
    """Build a message with multiple Authentication-Results headers.

    Each value in ar_values becomes a separate AR header in the message.
    This mirrors how iCloud stamps one AR header per verifier.

    Args:
        ar_values: Authentication-Results header values to add.
        from_header: From header value.  Provide a complete value; do not
            set msg["From"] separately after calling this helper, as
            duplicate From headers produce a multi-value joined string that
            confuses parseaddr.
    """
    msg = email.message.Message()
    msg["From"] = from_header
    msg["Subject"] = "Test"
    for ar_val in ar_values:
        msg["Authentication-Results"] = ar_val
    return msg


class TestAuthSignalARCollapse:
    """Regression tests for the Authentication-Results collapse bug.

    The old dict-comprehension collapsed iCloud's separate SPF/DKIM/DMARC
    AR headers into one value.  Routing through parse_message_headers fixes
    this via the NUL-delimited authentication-results-list key.
    """

    def test_three_ar_headers_all_populated(self) -> None:
        """Three separate AR headers → spf, dkim, dmarc all resolved."""
        msg = _make_msg_with_ar_headers([
            "spf.icloud.com; spf=pass smtp.mailfrom=sender@example.com",
            "dkim-verifier.icloud.com; dkim=pass header.d=example.com",
            "dmarc.icloud.com; dmarc=pass header.from=example.com",
        ])
        sigs = header_signals(msg)
        auth = sigs["auth"]
        assert auth["spf"] == "pass", f"spf={auth['spf']!r}"
        assert auth["dkim"] == "pass", f"dkim={auth['dkim']!r}"
        assert auth["dmarc"] == "pass", f"dmarc={auth['dmarc']!r}"
        assert auth["trusted_results_present"] is True

    def test_three_ar_headers_individual_verdicts_not_last_only(self) -> None:
        """SPF result comes from its own header, not collapsed to DMARC value."""
        msg = _make_msg_with_ar_headers([
            "spf.icloud.com; spf=fail smtp.mailfrom=attacker@evil.com",
            "dkim-verifier.icloud.com; dkim=pass header.d=example.com",
            "dmarc.icloud.com; dmarc=pass header.from=example.com",
        ])
        sigs = header_signals(msg)
        auth = sigs["auth"]
        # SPF must be 'fail' from its own header, not overridden by DMARC.
        assert auth["spf"] == "fail"
        assert auth["dkim"] == "pass"
        assert auth["dmarc"] == "pass"

    def test_no_ar_headers_returns_unknown(self) -> None:
        """Absent AR headers → all verdicts 'unknown', trusted_results=False."""
        msg = _make_msg({"From": "user@example.com"})
        sigs = header_signals(msg)
        auth = sigs["auth"]
        assert auth["spf"] == "unknown"
        assert auth["dkim"] == "unknown"
        assert auth["dmarc"] == "unknown"
        assert auth["trusted_results_present"] is False


class TestOtpPatternFacts:
    """OTP and verification-code content pattern facts."""

    def test_non_bulk_otp_message_has_otp_pattern(self) -> None:
        """Non-bulk OTP message: has_otp_pattern=True, classification=not_bulk."""
        msg = _make_msg(
            {
                "From": "no-reply@bank.example.com",
                "Subject": "Your one-time code: 482910",
            },
            body="Your one-time code is 482910. Do not share it.",
        )
        sigs = header_signals(msg, body_text="Your one-time code is 482910. Do not share it.")
        assert sigs["has_otp_pattern"] is True
        assert sigs["heuristic_classification"] == "not_bulk"
        assert "spam" not in str(sigs.values())
        assert "category" not in sigs
        assert "confidence" not in sigs

    def test_otp_in_subject_only_no_body(self) -> None:
        """OTP phrase in subject with no body still fires has_otp_pattern."""
        msg = _make_msg(
            {"From": "noreply@auth.com", "Subject": "Your OTP is 1234"},
        )
        sigs = header_signals(msg, body_text="")
        assert sigs["has_otp_pattern"] is True
        assert sigs["heuristic_classification"] == "not_bulk"

    def test_no_otp_in_plain_email(self) -> None:
        """Generic personal email: has_otp_pattern=False."""
        msg = _make_msg(
            {"From": "friend@example.com", "Subject": "Lunch tomorrow?"},
            body="Are you free for lunch tomorrow?",
        )
        sigs = header_signals(msg, body_text="Are you free for lunch tomorrow?")
        assert sigs["has_otp_pattern"] is False


class TestReceiptAndCurrencyFacts:
    """Receipt and currency content-pattern facts."""

    def test_receipt_with_currency_total(self) -> None:
        """Non-bulk receipt with $12.34: has_receipt_pattern and currency=True."""
        body = "Thank you for your order. Receipt #ORD-9821. Total: $12.34"
        msg = _make_msg(
            {"From": "orders@shop.example.com", "Subject": "Your Receipt"},
            body=body,
        )
        sigs = header_signals(msg, body_text=body)
        assert sigs["has_receipt_pattern"] is True
        assert sigs["currency_total_present"] is True
        assert sigs["heuristic_classification"] == "not_bulk"

    def test_no_receipt_plain_email(self) -> None:
        """Plain personal email: has_receipt_pattern=False, currency=False."""
        body = "See you at the meeting!"
        msg = _make_msg({"From": "alice@example.com"}, body=body)
        sigs = header_signals(msg, body_text=body)
        assert sigs["has_receipt_pattern"] is False
        assert sigs["currency_total_present"] is False


class TestSpoofFacts:
    """Spoof-signal facts: local_part_looks_like_email, from_domain_mismatch."""

    def test_gmail_embedded_in_local_part(self) -> None:
        """leanneallenrealestate.gmail.com@tafv5o.ff02.fdske.com → lple=True."""
        msg = _make_msg(
            {
                "From": (
                    "Leanne Allen "
                    "<leanneallenrealestate.gmail.com@tafv5o.ff02.fdske.com>"
                ),
            }
        )
        sigs = header_signals(msg)
        assert sigs["local_part_looks_like_email"] is True

    def test_normal_address_lple_false(self) -> None:
        """Normal address: local_part_looks_like_email=False."""
        msg = _make_msg({"From": "alice@example.com"})
        sigs = header_signals(msg)
        assert sigs["local_part_looks_like_email"] is False

    def test_display_name_has_email_detected(self) -> None:
        """Display name containing @-address: display_name_has_email=True."""
        msg = _make_msg(
            {"From": '"alice@legit.com" <relay@bulk.example.com>'},
        )
        sigs = header_signals(msg)
        assert sigs["display_name_has_email"] is True

    def test_display_name_no_email(self) -> None:
        """Plain display name: display_name_has_email=False."""
        msg = _make_msg({"From": "Alice Smith <alice@example.com>"})
        sigs = header_signals(msg)
        assert sigs["display_name_has_email"] is False

    def test_from_domain_mismatch_misaligned(self) -> None:
        """DMARC pass but From-domain != authenticated_from_domain → mismatch."""
        msg = _make_msg_with_ar_headers(
            ["dmarc.icloud.com; dmarc=pass header.from=trusted.com"],
            from_header="Spoofed Sender <info@different-domain.com>",
        )
        sigs = header_signals(msg)
        assert sigs["auth"]["dmarc_aligned"] is True
        assert sigs["auth"]["authenticated_from_domain"] == "trusted.com"
        # from_header_domain is different-domain.com ≠ trusted.com
        assert sigs["from_domain_mismatch"] is True

    def test_from_domain_aligned_no_mismatch(self) -> None:
        """DMARC pass and From-domain matches → from_domain_mismatch=False."""
        msg = _make_msg_with_ar_headers(
            ["dmarc.icloud.com; dmarc=pass header.from=example.com"],
            from_header="Sender <info@example.com>",
        )
        sigs = header_signals(msg)
        assert sigs["from_domain_mismatch"] is False


class TestDmarcAlignment:
    """DMARC alignment signals in auth sub-dict."""

    def test_strict_alignment_detected(self) -> None:
        """From-domain == authenticated_from_domain → from_alignment=aligned."""
        msg = _make_msg_with_ar_headers(
            ["dmarc.icloud.com; dmarc=pass header.from=example.com"],
            from_header="Sender <info@example.com>",
        )
        sigs = header_signals(msg)
        auth = sigs["auth"]
        assert auth["from_alignment"] == "aligned"
        assert auth["authenticated_from_domain"] == "example.com"

    def test_relaxed_alignment_detected(self) -> None:
        """Subdomain match → from_alignment=relaxed."""
        msg = _make_msg_with_ar_headers(
            ["dmarc.icloud.com; dmarc=pass header.from=example.com"],
            from_header="Sender <info@mail.example.com>",
        )
        sigs = header_signals(msg)
        auth = sigs["auth"]
        assert auth["from_alignment"] == "relaxed"

    def test_misaligned_dmarc_pass(self) -> None:
        """DMARC pass but From-domain shares no registrable domain → misaligned."""
        msg = _make_msg_with_ar_headers(
            ["dmarc.icloud.com; dmarc=pass header.from=legit.com"],
            from_header="Sender <info@attacker.evil>",
        )
        sigs = header_signals(msg)
        auth = sigs["auth"]
        assert auth["from_alignment"] == "misaligned"

    def test_unknown_alignment_no_trusted_dmarc(self) -> None:
        """No trusted DMARC → from_alignment=unknown."""
        msg = _make_msg({"From": "sender@example.com"})
        sigs = header_signals(msg)
        assert sigs["auth"]["from_alignment"] == "unknown"


class TestMetadataViewContentFacts:
    """Content facts degrade gracefully when body_text is empty."""

    def test_empty_body_text_no_crash(self) -> None:
        """view=metadata path: body_text='' → content facts False/0.0."""
        msg = _make_msg(
            {
                "From": "Bulk <news@newsletter.example.com>",
                "List-Unsubscribe": "<https://newsletter.example.com/unsub>",
                "Subject": "Weekly deals",
            }
        )
        sigs = header_signals(msg, body_text="")
        # Must not raise; content facts must be falsy.
        assert sigs["has_otp_pattern"] is False
        assert sigs["has_receipt_pattern"] is False
        assert sigs["currency_total_present"] is False
        assert sigs["marketing_cta_density"] == 0.0

    def test_no_category_or_confidence_key(self) -> None:
        """header_signals must never emit 'category' or 'confidence' keys."""
        msg = _make_msg({"From": "bulk@example.com", "List-Unsubscribe": "<https://x.com/unsub>"})
        sigs = header_signals(msg)
        assert "category" not in sigs
        assert "confidence" not in sigs


class TestBulkNewsletterStructural:
    """Bulk newsletter: structural facts set, label='bulk'."""

    def test_bulk_newsletter_heuristic_classification(self) -> None:
        """Bulk newsletter → heuristic_classification='bulk', no verdict."""
        msg = _make_msg(
            {
                "From": "Acme News <news@acme.com>",
                "List-Unsubscribe": "<https://acme.com/unsub>",
                "List-Unsubscribe-Post": "List-Unsubscribe=One-Click",
                "List-Id": "<news.acme.com>",
                "Precedence": "bulk",
            }
        )
        sigs = header_signals(msg)
        assert sigs["heuristic_classification"] == "bulk"
        assert sigs["is_bulk"] is True
        assert sigs["has_list_id"] is True
        assert sigs["precedence_bulk"] is True
        # Confirm category verdicts are absent.
        assert "newsletter" not in sigs.values()
        assert "spam" not in sigs.values()
        assert "category" not in sigs
        assert "confidence" not in sigs


class TestBackCompatKeys:
    """Back-compat: original signal keys still present in all cases."""

    _REQUIRED_KEYS = (
        "list_unsubscribe_method",
        "has_list_id",
        "precedence_bulk",
        "is_bulk",
        "heuristic_classification",
    )

    def test_non_bulk_has_all_keys(self) -> None:
        """Non-bulk message exposes all original keys."""
        msg = _make_msg({"From": "alice@example.com"})
        sigs = header_signals(msg)
        for k in self._REQUIRED_KEYS:
            assert k in sigs, f"Missing key: {k}"

    def test_bulk_has_all_keys(self) -> None:
        """Bulk message exposes all original keys."""
        msg = _make_msg(
            {
                "From": "news@bulk.com",
                "List-Unsubscribe": "<https://bulk.com/unsub>",
                "List-Id": "<news.bulk.com>",
            }
        )
        sigs = header_signals(msg)
        for k in self._REQUIRED_KEYS:
            assert k in sigs, f"Missing key: {k}"
