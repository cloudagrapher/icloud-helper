"""Tests for the probe_unsubscribe_link MCP tool (ADR-016 Phase 1.5).

Covers the full cloned gate chain: egress hard-block, dry-run/simulate,
auth-gate fail-closed, URL-provenance rejection, the allow_body_link_
unsubscribe master switch, body-capture truncation, and the always-present
untrusted-content warning.
"""
from __future__ import annotations

import socket
import unittest
from unittest.mock import MagicMock, patch

import icloud_helper.mcp_server as srv
from icloud_helper.policy import (
    ActionsConfig,
    EgressConfig,
    FlaggedConfig,
    GlobalConfig,
    RateLimitConfig,
    ReadConfig,
)

_UIDVALIDITY = 12345
_UID = 4242
_FOLDER = "INBOX"
_URL = "https://legit.example.com/unsubscribe?id=1"
_SENDER = "newsletter@example.com"
_DOMAIN = "example.com"


def _raw_message(href: str = _URL, dmarc_domain: str = _DOMAIN) -> bytes:
    """Build a raw RFC822 message with an HTML unsubscribe anchor.

    Args:
        href: The unsubscribe anchor href to embed in the HTML body.
        dmarc_domain: Domain to stamp as the DMARC-authenticated header.from=.

    Returns:
        Raw message bytes suitable as a BODY.PEEK[] fetch result.
    """
    html = f'<html><body><a href="{href}">Unsubscribe</a></body></html>'
    return (
        f"From: Newsletter <{_SENDER}>\r\n"
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


def _raw_message_no_auth(href: str = _URL) -> bytes:
    """Build a raw message with NO Authentication-Results header (auth-gate fail)."""
    html = f'<html><body><a href="{href}">Unsubscribe</a></body></html>'
    return (
        f"From: Newsletter <{_SENDER}>\r\n"
        f"To: me@example.com\r\n"
        f"Subject: Weekly update\r\n"
        f"List-Unsubscribe: <{href}>\r\n"
        f"MIME-Version: 1.0\r\n"
        f"Content-Type: text/html; charset=utf-8\r\n"
        f"\r\n"
        f"{html}\r\n"
    ).encode("utf-8")


def _patch_readonly_session(raw_bytes: bytes, uidvalidity: int = _UIDVALIDITY):
    """Return a pair of patch() context managers for the read-only IMAP path.

    Args:
        raw_bytes: Raw message bytes fetch_message should return.
        uidvalidity: Server UIDVALIDITY to yield alongside the mock IMAP.

    Returns:
        A 2-tuple of patchers (use both with nested `with`).
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


def _make_config(
    allow_confirmed_actions: bool = True,
    allow_body_link_unsubscribe: bool = True,
    protected_domains: list | None = None,
) -> GlobalConfig:
    """Build a real GlobalConfig for probe_unsubscribe_link tests.

    Args:
        allow_confirmed_actions: Master confirmed-action switch.
        allow_body_link_unsubscribe: ADR-016 body-link master switch.
        protected_domains: Optional protected-domain list.

    Returns:
        A fully-populated GlobalConfig instance.
    """
    return GlobalConfig(
        folders=["INBOX"],
        dry_run=True,
        allow_delete=False,
        rate_limits=RateLimitConfig(),
        disposition="move_to_unsubscribed",
        protected_domains=protected_domains or [],
        allow_mcp_policy_writes=False,
        unsubscribe_allowed_domains=["legit.example.com"],
        flagged=FlaggedConfig(),
        allow_confirmed_actions=allow_confirmed_actions,
        read=ReadConfig(folders=["INBOX", "Junk", "Archive"]),
        actions=ActionsConfig(),
        egress=EgressConfig(),
        allow_body_link_unsubscribe=allow_body_link_unsubscribe,
        probe_excerpt_bytes=4096,
        probe_max_capture_bytes=65536,
    )


class TestProbeUnsubscribeLinkEgressHardBlock(unittest.TestCase):
    """Egress hard-block must prevent any fetch."""

    def test_denied_ip_blocks_before_fetch(self) -> None:
        """A private-IP-resolving host is hard-blocked; no fetch occurs."""
        cfg = _make_config()
        raw = _raw_message()
        p1, p2 = _patch_readonly_session(raw)
        with patch.object(srv, "_config", cfg), p1, p2, patch(
            "socket.getaddrinfo", side_effect=_private_getaddrinfo
        ), patch("urllib.request.build_opener") as mock_build_opener:
            result = srv.probe_unsubscribe_link(
                folder=_FOLDER,
                uid=str(_UID),
                uidvalidity=_UIDVALIDITY,
                url=_URL,
                confirm=True,
            )
            mock_build_opener.assert_not_called()
        self.assertEqual(result.get("http_status"), None)
        self.assertIsNotNone(result.get("block_class"))


class TestProbeUnsubscribeLinkDryRun(unittest.TestCase):
    """confirm=False must simulate without any network I/O."""

    def test_confirm_false_no_network(self) -> None:
        """confirm=False returns a simulated preview and never opens a socket call for fetch."""
        cfg = _make_config()
        raw = _raw_message()
        p1, p2 = _patch_readonly_session(raw)
        with patch.object(srv, "_config", cfg), p1, p2, patch(
            "socket.getaddrinfo", side_effect=_public_getaddrinfo
        ), patch("urllib.request.build_opener") as mock_build_opener, patch(
            "urllib.request.urlopen"
        ) as mock_urlopen:
            result = srv.probe_unsubscribe_link(
                folder=_FOLDER,
                uid=str(_UID),
                uidvalidity=_UIDVALIDITY,
                url=_URL,
                confirm=False,
            )
            mock_build_opener.assert_not_called()
            mock_urlopen.assert_not_called()
        self.assertTrue(result["simulated"])
        self.assertFalse(result["confirmed"])
        self.assertIn("egress_preview", result)


class TestProbeUnsubscribeLinkAuthGate(unittest.TestCase):
    """DKIM/DMARC gate must fail closed."""

    def test_missing_auth_header_refuses(self) -> None:
        """A message with no Authentication-Results header is refused."""
        cfg = _make_config()
        raw = _raw_message_no_auth()
        p1, p2 = _patch_readonly_session(raw)
        with patch.object(srv, "_config", cfg), p1, p2:
            result = srv.probe_unsubscribe_link(
                folder=_FOLDER,
                uid=str(_UID),
                uidvalidity=_UIDVALIDITY,
                url=_URL,
                confirm=True,
            )
        self.assertEqual(result.get("error"), "auth_gate_failed")
        self.assertEqual(result.get("block_class"), "auth_failed")


class TestProbeUnsubscribeLinkUrlProvenance(unittest.TestCase):
    """The passed url must match a candidate extracted from the message."""

    def test_url_not_in_message_rejected(self) -> None:
        """A url that isn't a candidate in this message is rejected."""
        cfg = _make_config()
        raw = _raw_message()
        p1, p2 = _patch_readonly_session(raw)
        with patch.object(srv, "_config", cfg), p1, p2:
            result = srv.probe_unsubscribe_link(
                folder=_FOLDER,
                uid=str(_UID),
                uidvalidity=_UIDVALIDITY,
                url="https://attacker.example.net/phish",
                confirm=True,
            )
        self.assertEqual(result.get("error"), "url_not_in_message")


class TestProbeUnsubscribeLinkMasterSwitch(unittest.TestCase):
    """allow_body_link_unsubscribe=false must refuse/simulate the probe."""

    def test_refused_when_switch_off(self) -> None:
        """The probe is refused (simulated) when the master switch is off."""
        cfg = _make_config(allow_body_link_unsubscribe=False)
        raw = _raw_message()
        p1, p2 = _patch_readonly_session(raw)
        with patch.object(srv, "_config", cfg), p1, p2, patch(
            "urllib.request.build_opener"
        ) as mock_build_opener:
            result = srv.probe_unsubscribe_link(
                folder=_FOLDER,
                uid=str(_UID),
                uidvalidity=_UIDVALIDITY,
                url=_URL,
                confirm=True,
            )
            mock_build_opener.assert_not_called()
        self.assertTrue(result["simulated"])
        self.assertEqual(result["blocked_by"], "allow_body_link_unsubscribe")


class TestProbeUnsubscribeLinkBodyCaptureTruncation(unittest.TestCase):
    """max_capture_bytes bounds the body read from the live fetch."""

    def test_body_capture_bounded_by_config(self) -> None:
        """The captured body is never larger than probe_max_capture_bytes."""
        cfg = _make_config()
        cfg.probe_max_capture_bytes = 50
        raw = _raw_message()
        p1, p2 = _patch_readonly_session(raw)

        big_html = ("<html><body><p>" + ("Z" * 500) + "</p></body></html>").encode()

        def fake_open(_req, timeout=None):  # pylint: disable=unused-argument
            mock_resp = MagicMock()
            mock_resp.status = 200
            mock_resp.read = MagicMock(
                side_effect=lambda n=None: big_html[: n if n else len(big_html)]
            )
            mock_resp.__enter__ = lambda s: s
            mock_resp.__exit__ = MagicMock(return_value=False)
            return mock_resp

        mock_opener = MagicMock()
        mock_opener.open.side_effect = fake_open

        with patch.object(srv, "_config", cfg), p1, p2, patch(
            "socket.getaddrinfo", side_effect=_public_getaddrinfo
        ), patch("urllib.request.build_opener", return_value=mock_opener):
            result = srv.probe_unsubscribe_link(
                folder=_FOLDER,
                uid=str(_UID),
                uidvalidity=_UIDVALIDITY,
                url=_URL,
                confirm=True,
            )

        self.assertTrue(result["confirmed"])
        # The excerpt must never exceed what a 50-byte capture could produce.
        excerpt = result["results"][0]["page_text_excerpt"]
        self.assertLessEqual(len(excerpt), 50)


class TestProbeUnsubscribeLinkScriptsNeverSurfaced(unittest.TestCase):
    """Script content must never appear in the probe's returned excerpt."""

    def test_script_stripped_from_response(self) -> None:
        """A malicious <script> in the fetched page never reaches the caller."""
        cfg = _make_config()
        raw = _raw_message()
        p1, p2 = _patch_readonly_session(raw)

        html = (
            b"<html><head><script>alert('xss-should-not-appear')</script></head>"
            b"<body><p>You have been unsubscribed successfully.</p></body></html>"
        )

        def fake_open(_req, timeout=None):  # pylint: disable=unused-argument
            mock_resp = MagicMock()
            mock_resp.status = 200
            mock_resp.read = MagicMock(return_value=html)
            mock_resp.__enter__ = lambda s: s
            mock_resp.__exit__ = MagicMock(return_value=False)
            return mock_resp

        mock_opener = MagicMock()
        mock_opener.open.side_effect = fake_open

        with patch.object(srv, "_config", cfg), p1, p2, patch(
            "socket.getaddrinfo", side_effect=_public_getaddrinfo
        ), patch("urllib.request.build_opener", return_value=mock_opener):
            result = srv.probe_unsubscribe_link(
                folder=_FOLDER,
                uid=str(_UID),
                uidvalidity=_UIDVALIDITY,
                url=_URL,
                confirm=True,
            )

        excerpt = result["results"][0]["page_text_excerpt"]
        self.assertNotIn("alert", excerpt)
        self.assertNotIn("xss-should-not-appear", excerpt)


class TestProbeUnsubscribeLinkWarnings(unittest.TestCase):
    """The untrusted-content warning must always be present."""

    def test_untrusted_warning_present_on_live_result(self) -> None:
        """A successful live probe still carries the untrusted-content warning."""
        cfg = _make_config()
        raw = _raw_message()
        p1, p2 = _patch_readonly_session(raw)

        html = b"<html><body><p>You have been unsubscribed.</p></body></html>"

        def fake_open(_req, timeout=None):  # pylint: disable=unused-argument
            mock_resp = MagicMock()
            mock_resp.status = 200
            mock_resp.read = MagicMock(return_value=html)
            mock_resp.__enter__ = lambda s: s
            mock_resp.__exit__ = MagicMock(return_value=False)
            return mock_resp

        mock_opener = MagicMock()
        mock_opener.open.side_effect = fake_open

        with patch.object(srv, "_config", cfg), p1, p2, patch(
            "socket.getaddrinfo", side_effect=_public_getaddrinfo
        ), patch("urllib.request.build_opener", return_value=mock_opener):
            result = srv.probe_unsubscribe_link(
                folder=_FOLDER,
                uid=str(_UID),
                uidvalidity=_UIDVALIDITY,
                url=_URL,
                confirm=True,
            )

        page_warnings = result["results"][0]["warnings"]
        self.assertTrue(any("untrusted" in w.lower() for w in page_warnings))


class TestProbeUnsubscribeLinkProtectedDomain(unittest.TestCase):
    """Protected-domain senders must be hard-blocked before any fetch."""

    def test_protected_domain_hard_blocked(self) -> None:
        """A sender whose domain is protected is refused before egress_check."""
        cfg = _make_config(protected_domains=[_DOMAIN])
        raw = _raw_message()
        p1, p2 = _patch_readonly_session(raw)
        with patch.object(srv, "_config", cfg), p1, p2, patch(
            "urllib.request.build_opener"
        ) as mock_build_opener:
            result = srv.probe_unsubscribe_link(
                folder=_FOLDER,
                uid=str(_UID),
                uidvalidity=_UIDVALIDITY,
                url=_URL,
                confirm=True,
            )
            mock_build_opener.assert_not_called()
        self.assertEqual(result.get("error"), "protected_domain")


if __name__ == "__main__":
    unittest.main()
