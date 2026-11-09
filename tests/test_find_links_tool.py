"""Tests for the find_unsubscribe_links MCP tool (ADR-016 Phase 1).

find_unsubscribe_links must be read-only: it never issues an outbound
network request (only egress_check, which is DNS-resolve + policy only).
"""
from __future__ import annotations

import socket
import unittest
from unittest.mock import MagicMock, patch

import icloud_helper.mcp_server as srv


_UIDVALIDITY = 12345
_UID = 4242
_FOLDER = "INBOX"


def _raw_message(
    sender: str = "newsletter@example.com",
    href: str = "https://legit.example.com/unsubscribe?id=1",
    dmarc_domain: str = "example.com",
) -> bytes:
    """Build a raw RFC822 message with an HTML unsubscribe anchor.

    Args:
        sender: From-header email address.
        href: The unsubscribe anchor href to embed in the HTML body.
        dmarc_domain: Domain to stamp as the DMARC-authenticated header.from=.

    Returns:
        Raw message bytes suitable as a BODY.PEEK[] fetch result.
    """
    html = f'<html><body><a href="{href}">Unsubscribe</a></body></html>'
    return (
        f"From: Newsletter <{sender}>\r\n"
        f"To: me@example.com\r\n"
        f"Subject: Weekly update\r\n"
        f"List-Unsubscribe: <{href}>\r\n"
        f"Authentication-Results: icloud.com; dmarc=pass "
        f"header.from={dmarc_domain}; dkim=pass header.d={dmarc_domain}\r\n"
        f"MIME-Version: 1.0\r\n"
        f"Content-Type: text/html; charset=utf-8\r\n"
        f"\r\n"
        f"{html}\r\n"
    ).encode("utf-8")


def _patch_readonly_session(raw_bytes: bytes, uidvalidity: int = _UIDVALIDITY):
    """Return a patch() context manager for flagged.open_readonly_session.

    Args:
        raw_bytes: Raw message bytes fetch_message should return.
        uidvalidity: Server UIDVALIDITY to yield alongside the mock IMAP.

    Returns:
        A contextlib-compatible patcher (use with `with`).
    """
    mock_imap = MagicMock()
    mock_cm = MagicMock()
    mock_cm.__enter__ = MagicMock(return_value=(mock_imap, uidvalidity))
    mock_cm.__exit__ = MagicMock(return_value=False)
    return (
        patch(
            "icloud_helper.flagged.open_readonly_session",
            return_value=mock_cm,
        ),
        patch(
            "icloud_helper.flagged.fetch_message",
            return_value=(raw_bytes, "01-Jan-2026 00:00:00 +0000"),
        ),
    )


def _public_getaddrinfo(_host: str, _port: object) -> list:
    """Return a getaddrinfo result for a truly public IP (1.1.1.1)."""
    return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("1.1.1.1", 0))]


def _private_getaddrinfo(_host: str, _port: object) -> list:
    """Return a getaddrinfo result for a private IP (192.168.1.1)."""
    return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("192.168.1.1", 0))]


class TestFindUnsubscribeLinksShape(unittest.TestCase):
    """Read-only response shape."""

    def test_returns_expected_shape(self) -> None:
        """Response contains all documented top-level keys."""
        raw = _raw_message()
        p1, p2 = _patch_readonly_session(raw)
        with p1, p2, patch("socket.getaddrinfo", side_effect=_public_getaddrinfo):
            with patch("urllib.request.urlopen") as mock_urlopen:
                result = srv.find_unsubscribe_links(
                    folder=_FOLDER, uid=str(_UID), uidvalidity=_UIDVALIDITY
                )
                mock_urlopen.assert_not_called()

        for key in (
            "folder",
            "uid",
            "uidvalidity",
            "from",
            "has_list_unsubscribe_header",
            "auth_signals",
            "candidates",
            "candidate_count",
            "note",
        ):
            self.assertIn(key, result, f"missing key {key!r}")

        self.assertEqual(result["candidate_count"], 1)
        self.assertTrue(result["has_list_unsubscribe_header"])
        candidate = result["candidates"][0]
        self.assertIn("egress_preview", candidate)
        self.assertIn("url_sha256", candidate)

    def test_auth_signals_present(self) -> None:
        """auth_signals dict carries the documented keys."""
        raw = _raw_message()
        p1, p2 = _patch_readonly_session(raw)
        with p1, p2, patch("socket.getaddrinfo", side_effect=_public_getaddrinfo):
            result = srv.find_unsubscribe_links(
                folder=_FOLDER, uid=str(_UID), uidvalidity=_UIDVALIDITY
            )
        auth = result["auth_signals"]
        for key in (
            "spf",
            "dkim",
            "dmarc",
            "dmarc_aligned",
            "authenticated_from_domain",
            "dkim_d_domain",
            "from_header_domain",
            "from_alignment",
            "trusted_results_present",
        ):
            self.assertIn(key, auth, f"missing auth_signals key {key!r}")


class TestFindUnsubscribeLinksNoNetwork(unittest.TestCase):
    """Verify absolutely no outbound HTTP request is ever issued."""

    def test_no_request_even_with_https_candidate(self) -> None:
        """urlopen/build_opener must never be called by this read-only tool."""
        raw = _raw_message()
        p1, p2 = _patch_readonly_session(raw)
        with p1, p2, patch("socket.getaddrinfo", side_effect=_public_getaddrinfo):
            with patch("urllib.request.urlopen") as mock_urlopen, patch(
                "urllib.request.build_opener"
            ) as mock_build_opener:
                srv.find_unsubscribe_links(
                    folder=_FOLDER, uid=str(_UID), uidvalidity=_UIDVALIDITY
                )
                mock_urlopen.assert_not_called()
                mock_build_opener.assert_not_called()


class TestFindUnsubscribeLinksEgressPreview(unittest.TestCase):
    """egress_preview reflects allowed vs denied host resolution."""

    def test_public_ip_allowed_preview(self) -> None:
        """A candidate resolving to a public IP gets an allow-shaped preview."""
        raw = _raw_message()
        p1, p2 = _patch_readonly_session(raw)
        with p1, p2, patch("socket.getaddrinfo", side_effect=_public_getaddrinfo):
            result = srv.find_unsubscribe_links(
                folder=_FOLDER, uid=str(_UID), uidvalidity=_UIDVALIDITY
            )
        preview = result["candidates"][0]["egress_preview"]
        self.assertEqual(preview["outcome"], "allow")
        self.assertIsNone(preview["block_class"])

    def test_private_ip_denied_preview(self) -> None:
        """A candidate resolving to a private IP gets a hard_block preview."""
        raw = _raw_message()
        p1, p2 = _patch_readonly_session(raw)
        with p1, p2, patch("socket.getaddrinfo", side_effect=_private_getaddrinfo):
            result = srv.find_unsubscribe_links(
                folder=_FOLDER, uid=str(_UID), uidvalidity=_UIDVALIDITY
            )
        preview = result["candidates"][0]["egress_preview"]
        self.assertEqual(preview["outcome"], "hard_block")
        self.assertIsNotNone(preview["block_class"])


class TestFindUnsubscribeLinksUidvalidity(unittest.TestCase):
    """Uidvalidity mismatch handling."""

    def test_uidvalidity_mismatch_returns_error(self) -> None:
        """A stale uidvalidity yields an error dict, no candidates."""
        raw = _raw_message()
        p1, p2 = _patch_readonly_session(raw, uidvalidity=99999)
        with p1, p2:
            result = srv.find_unsubscribe_links(
                folder=_FOLDER, uid=str(_UID), uidvalidity=_UIDVALIDITY
            )
        self.assertEqual(result.get("error"), "uidvalidity_changed")

    def test_uidvalidity_zero_skips_check(self) -> None:
        """uidvalidity=0 is accepted for read-only calls."""
        raw = _raw_message()
        p1, p2 = _patch_readonly_session(raw, uidvalidity=99999)
        with p1, p2, patch("socket.getaddrinfo", side_effect=_public_getaddrinfo):
            result = srv.find_unsubscribe_links(
                folder=_FOLDER, uid=str(_UID), uidvalidity=0
            )
        self.assertNotIn("error", result)


class TestFindUnsubscribeLinksFolderValidation(unittest.TestCase):
    """Folder-allowlist and charset gates run before any IMAP session opens."""

    def test_non_allowlisted_folder_rejected(self) -> None:
        """A folder outside the read allowlist is rejected before IMAP I/O."""
        with patch("icloud_helper.flagged.open_readonly_session") as mock_ro:
            result = srv.find_unsubscribe_links(
                folder="Sent Messages", uid=str(_UID), uidvalidity=0
            )
            mock_ro.assert_not_called()
        self.assertEqual(result.get("error"), "folder_not_allowed")

    def test_invalid_uid_rejected(self) -> None:
        """A non-integer uid is rejected with invalid_uid."""
        result = srv.find_unsubscribe_links(
            folder=_FOLDER, uid="not-a-number", uidvalidity=0
        )
        self.assertEqual(result.get("error"), "invalid_uid")


if __name__ == "__main__":
    unittest.main()
