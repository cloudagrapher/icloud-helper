"""Tests for icloud_helper.unsubscribe."""
from __future__ import annotations

import unittest
from unittest.mock import MagicMock, patch

from icloud_helper.unsubscribe import (
    UnsubscribeResult,
    effective_mailto_domains,
    effective_unsubscribe_domains,
    perform_unsubscribe,
    unsubscribe_mailto,
    unsubscribe_one_click,
)


class _FakeGlobalConfig:
    """Minimal stand-in for GlobalConfig."""

    def __init__(
        self,
        dry_run: bool = False,
        mailto_allowed_domains: list | None = None,
    ) -> None:
        self.dry_run = dry_run
        self.allow_delete = True
        self.disposition = "mark_read"
        # C1: provide an allowlist so existing tests don't hit the
        # domain-allowlist guard with the module default (which omits
        # example.com to avoid test-domain collisions with real traffic).
        self.unsubscribe_allowed_domains = ["example.com"]
        # B.1: denylist / review lists (empty = no extra blocks).
        self.unsubscribe_denied_domains: list = []
        self.unsubscribe_review_domains: list = []
        # T1.3: mailto fallback allowlist (empty = use module defaults).
        self.mailto_allowed_domains: list = (
            mailto_allowed_domains if mailto_allowed_domains is not None else []
        )
        self.mailto_denied_domains: list = []

        # B.6: Egress config stand-in. prefer_mailto=False preserves the old
        # routing semantics (one-click first) for the existing test suite.
        class _Egress:  # pylint: disable=too-few-public-methods
            prefer_mailto = False
            max_redirects = 3
            http_timeout_seconds = 30
            smtp_timeout_seconds = 30

        self.egress = _Egress()


class TestUnsubscribeOneClick(unittest.TestCase):
    """Tests for unsubscribe_one_click."""

    def test_dry_run_one_click_no_network(self) -> None:
        """Dry-run returns success-simulated with zero network calls."""
        with patch("urllib.request.urlopen") as mock_urlopen:
            result = unsubscribe_one_click(
                "a@b.com",
                "https://example.com/unsub",
                dry_run=True,
                allowed_domains=["example.com"],
            )

        self.assertEqual(result.result, "success-simulated")
        self.assertTrue(result.dry_run)
        self.assertEqual(result.method, "one-click")
        mock_urlopen.assert_not_called()

    def test_http_url_rejected(self) -> None:
        """Non-HTTPS URL must be rejected with result=deferred."""
        result = unsubscribe_one_click(
            "a@b.com",
            "http://example.com/unsub",
            dry_run=False,
            allowed_domains=["example.com"],
        )

        self.assertEqual(result.result, "deferred")
        self.assertIn("SSRF", result.detail)

    def test_empty_hostname_rejected(self) -> None:
        """URL with no hostname must return deferred."""
        result = unsubscribe_one_click(
            "a@b.com",
            "https://",
            dry_run=False,
            allowed_domains=["example.com"],
        )
        self.assertEqual(result.result, "deferred")

    def test_default_post_behaviour_unchanged(self) -> None:
        """Default http_method="POST" still sends the RFC 8058 body byte-for-byte."""
        captured_requests = []

        def fake_open(req, timeout=None):  # pylint: disable=unused-argument
            captured_requests.append(req)
            mock_resp = MagicMock()
            mock_resp.status = 200
            mock_resp.read = MagicMock(return_value=b"")
            mock_resp.__enter__ = lambda s: s
            mock_resp.__exit__ = MagicMock(return_value=False)
            return mock_resp

        mock_opener = MagicMock()
        mock_opener.open.side_effect = fake_open

        with patch(
            "socket.getaddrinfo",
            return_value=[(2, 1, 6, "", ("1.1.1.1", 0))],
        ), patch("urllib.request.build_opener", return_value=mock_opener):
            result = unsubscribe_one_click(
                "a@b.com",
                "https://example.com/unsub",
                dry_run=False,
                allowed_domains=["example.com"],
            )

        self.assertEqual(result.result, "success")
        self.assertIsNone(result.body_capture)
        self.assertIsNone(result.final_url)
        self.assertEqual(len(captured_requests), 1)
        self.assertEqual(captured_requests[0].get_method(), "POST")
        self.assertEqual(
            captured_requests[0].data, b"List-Unsubscribe=One-Click"
        )

    def test_get_method_sends_no_body(self) -> None:
        """http_method="GET" issues a GET request with no request body."""
        captured_requests = []

        def fake_open(req, timeout=None):  # pylint: disable=unused-argument
            captured_requests.append(req)
            mock_resp = MagicMock()
            mock_resp.status = 200
            mock_resp.read = MagicMock(return_value=b"<html>ok</html>")
            mock_resp.__enter__ = lambda s: s
            mock_resp.__exit__ = MagicMock(return_value=False)
            return mock_resp

        mock_opener = MagicMock()
        mock_opener.open.side_effect = fake_open

        with patch(
            "socket.getaddrinfo",
            return_value=[(2, 1, 6, "", ("1.1.1.1", 0))],
        ), patch("urllib.request.build_opener", return_value=mock_opener):
            result = unsubscribe_one_click(
                "a@b.com",
                "https://example.com/unsub",
                dry_run=False,
                allowed_domains=["example.com"],
                http_method="GET",
            )

        self.assertEqual(result.result, "success")
        self.assertEqual(len(captured_requests), 1)
        self.assertEqual(captured_requests[0].get_method(), "GET")
        self.assertIsNone(captured_requests[0].data)

    def test_capture_body_returns_bounded_body(self) -> None:
        """capture_body=True attaches a body_capture bounded by max_capture_bytes."""
        full_body = b"<html><body>" + b"X" * 1000 + b"</body></html>"

        def fake_open(req, timeout=None):  # pylint: disable=unused-argument
            mock_resp = MagicMock()
            mock_resp.status = 200
            mock_resp.read = MagicMock(
                side_effect=lambda n=None: full_body[: n if n else len(full_body)]
            )
            mock_resp.__enter__ = lambda s: s
            mock_resp.__exit__ = MagicMock(return_value=False)
            return mock_resp

        mock_opener = MagicMock()
        mock_opener.open.side_effect = fake_open

        with patch(
            "socket.getaddrinfo",
            return_value=[(2, 1, 6, "", ("1.1.1.1", 0))],
        ), patch("urllib.request.build_opener", return_value=mock_opener):
            result = unsubscribe_one_click(
                "a@b.com",
                "https://example.com/unsub",
                dry_run=False,
                allowed_domains=["example.com"],
                http_method="GET",
                capture_body=True,
                max_capture_bytes=50,
            )

        self.assertEqual(result.result, "success")
        self.assertIsNotNone(result.body_capture)
        self.assertLessEqual(len(result.body_capture.encode("utf-8")), 50)
        self.assertEqual(result.final_url, "https://example.com/unsub")

    def test_capture_body_false_never_reads_response(self) -> None:
        """capture_body=False (default) never calls response.read()."""
        responses = []

        def fake_open(req, timeout=None):  # pylint: disable=unused-argument
            mock_resp = MagicMock()
            mock_resp.status = 200
            mock_resp.__enter__ = lambda s: s
            mock_resp.__exit__ = MagicMock(return_value=False)
            responses.append(mock_resp)
            return mock_resp

        mock_opener = MagicMock()
        mock_opener.open.side_effect = fake_open

        with patch(
            "socket.getaddrinfo",
            return_value=[(2, 1, 6, "", ("1.1.1.1", 0))],
        ), patch("urllib.request.build_opener", return_value=mock_opener):
            result = unsubscribe_one_click(
                "a@b.com",
                "https://example.com/unsub",
                dry_run=False,
                allowed_domains=["example.com"],
            )

        self.assertIsNone(result.body_capture)
        responses[0].read.assert_not_called()


class TestUnsubscribeMailto(unittest.TestCase):
    """Tests for unsubscribe_mailto."""

    def test_dry_run_mailto_no_network(self) -> None:
        """Dry-run returns success-simulated without touching SMTP."""
        with patch("smtplib.SMTP") as mock_smtp_cls:
            result = unsubscribe_mailto(
                sender="a@b.com",
                mailto_uri="mailto:unsub@example.com?subject=Unsubscribe",
                smtp_host="smtp.mail.me.com",
                smtp_port=587,
                username="user@icloud.com",
                password="hunter2",
                dry_run=True,
            )

        self.assertEqual(result.result, "success-simulated")
        self.assertTrue(result.dry_run)
        mock_smtp_cls.assert_not_called()


class TestPerformUnsubscribe(unittest.TestCase):
    """Tests for perform_unsubscribe."""

    def test_perform_unsubscribe_deferred_http_only(self) -> None:
        """HTTP-only List-Unsubscribe must be deferred for SSRF safety."""
        config = _FakeGlobalConfig(dry_run=False)

        with patch(
            "icloud_helper.unsubscribe.determine_unsubscribe_method",
            return_value="http-only",
        ):
            result = perform_unsubscribe(
                sender="spammer@example.com",
                unsubscribe_header="<http://example.com/unsub>",
                unsubscribe_post_header="",
                global_config=config,
                smtp_username="user",
                smtp_password="pass",
            )

        self.assertEqual(result.result, "deferred")
        self.assertIn("SSRF", result.detail)

    def test_perform_unsubscribe_deferred_no_mechanism(self) -> None:
        """Missing unsubscribe mechanism must yield result=deferred."""
        config = _FakeGlobalConfig(dry_run=False)

        with patch(
            "icloud_helper.unsubscribe.determine_unsubscribe_method",
            return_value="none",
        ):
            result = perform_unsubscribe(
                sender="spammer@example.com",
                unsubscribe_header="",
                unsubscribe_post_header="",
                global_config=config,
                smtp_username="user",
                smtp_password="pass",
            )

        self.assertEqual(result.result, "deferred")
        self.assertIn("no unsubscribe mechanism", result.detail)

    def test_perform_unsubscribe_one_click_dry_run(self) -> None:
        """One-click path in dry-run must not make network calls."""
        config = _FakeGlobalConfig(dry_run=True)

        with patch(
            "icloud_helper.unsubscribe.determine_unsubscribe_method",
            return_value="one-click",
        ), patch(
            "icloud_helper.unsubscribe.extract_urls_from_list_unsubscribe",
            return_value=(["https://example.com/unsub"], []),
        ), patch(
            "urllib.request.urlopen"
        ) as mock_urlopen:
            result = perform_unsubscribe(
                sender="a@b.com",
                unsubscribe_header="<https://example.com/unsub>",
                unsubscribe_post_header="List-Unsubscribe=One-Click",
                global_config=config,
                smtp_username="user",
                smtp_password="pass",
            )

        self.assertEqual(result.result, "success-simulated")
        mock_urlopen.assert_not_called()


# ---------------------------------------------------------------------------
# T1.3 — fork-C mailto fallback and effective_unsubscribe_domains
# ---------------------------------------------------------------------------


class TestEffectiveUnsubscribeDomains(unittest.TestCase):
    """effective_unsubscribe_domains returns the real applied list."""

    def test_non_empty_config_returned_as_is(self) -> None:
        """When config supplies domains those are returned."""
        cfg = _FakeGlobalConfig()
        cfg.unsubscribe_allowed_domains = ["mylist.example.com"]
        result = effective_unsubscribe_domains(cfg)
        self.assertEqual(result, ["mylist.example.com"])

    def test_empty_config_falls_back_to_module_defaults(self) -> None:
        """Empty config list triggers the module-level defaults (non-empty)."""
        cfg = _FakeGlobalConfig()
        cfg.unsubscribe_allowed_domains = []
        result = effective_unsubscribe_domains(cfg)
        self.assertIsInstance(result, list)
        self.assertGreater(len(result), 0)


class TestEffectiveMailtoDomains(unittest.TestCase):
    """effective_mailto_domains returns the real applied list (FIX 3)."""

    def test_non_empty_config_returned_as_is(self) -> None:
        """When config supplies mailto domains those are returned."""
        cfg = _FakeGlobalConfig()
        cfg.mailto_allowed_domains = ["mail.example.com"]
        result = effective_mailto_domains(cfg)
        self.assertEqual(result, ["mail.example.com"])

    def test_empty_config_falls_back_to_module_defaults(self) -> None:
        """Empty config list triggers the module-level _ALLOWED_MAILTO_DOMAINS."""
        cfg = _FakeGlobalConfig()
        cfg.mailto_allowed_domains = []
        result = effective_mailto_domains(cfg)
        self.assertIsInstance(result, list)
        self.assertGreater(len(result), 0, (
            "effective_mailto_domains must return non-empty module defaults"
        ))


class TestMailtoFallbackChaining(unittest.TestCase):
    """T1.3: mailto fallback fires when one-click is allowlist-blocked."""

    _SENDER = "news@blocked-domain.example.net"
    _MAILTO = "mailto:unsub@blocked-domain.example.net"
    _HEADER = f"<https://blocked-domain.example.net/unsub>, <{_MAILTO}>"
    _POST = "List-Unsubscribe=One-Click"

    def _config(self, **kw: object) -> _FakeGlobalConfig:
        """Build a config with example.net NOT in the one-click allowlist."""
        cfg = _FakeGlobalConfig(**kw)  # type: ignore[arg-type]
        # Override so example.net is blocked for one-click
        cfg.unsubscribe_allowed_domains = ["example.com"]
        return cfg

    def test_one_click_blocked_mailto_succeeds(self) -> None:
        """When one-click is blocked and mailto target matches sender domain,
        the fallback fires and returns a success result — no network calls."""
        cfg = self._config(dry_run=True)

        # Patch unsubscribe_one_click to return deferred (allowlist block)
        blocked = UnsubscribeResult(
            sender=self._SENDER,
            method="one-click",
            target="https://blocked-domain.example.net/unsub",
            result="deferred",
            http_status=None,
            dry_run=True,
            detail="host blocked-domain.example.net not in unsubscribe_allowed_domains",
        )

        with patch(
            "icloud_helper.unsubscribe.unsubscribe_one_click",
            return_value=blocked,
        ), patch(
            "icloud_helper.unsubscribe.unsubscribe_mailto"
        ) as mock_mailto:
            mock_mailto.return_value = UnsubscribeResult(
                sender=self._SENDER,
                method="mailto",
                target=self._MAILTO,
                result="success-simulated",
                http_status=None,
                dry_run=True,
                detail="dry-run mailto ok",
            )
            result = perform_unsubscribe(
                sender=self._SENDER,
                unsubscribe_header=self._HEADER,
                unsubscribe_post_header=self._POST,
                global_config=cfg,
                smtp_username="user",
                smtp_password="pass",
                # fork-C: sender domain matches mailto target domain
                verified_sender_domain="blocked-domain.example.net",
            )

        self.assertEqual(result.result, "success-simulated")
        self.assertIn("mailto", result.methods_attempted)
        self.assertEqual(result.method_used, "mailto")
        mock_mailto.assert_called_once()

    def test_one_click_blocked_no_mailto_returns_deferred(self) -> None:
        """When one-click is blocked and no mailto URI exists, result stays
        deferred — no fallback attempted."""
        cfg = self._config(dry_run=True)
        blocked = UnsubscribeResult(
            sender=self._SENDER,
            method="one-click",
            target="https://blocked-domain.example.net/unsub",
            result="deferred",
            http_status=None,
            dry_run=True,
            detail="host blocked-domain.example.net not in unsubscribe_allowed_domains",
        )

        with patch(
            "icloud_helper.unsubscribe.unsubscribe_one_click",
            return_value=blocked,
        ), patch(
            "icloud_helper.unsubscribe.unsubscribe_mailto"
        ) as mock_mailto:
            # Header has NO mailto URI
            result = perform_unsubscribe(
                sender=self._SENDER,
                unsubscribe_header="<https://blocked-domain.example.net/unsub>",
                unsubscribe_post_header=self._POST,
                global_config=cfg,
                smtp_username="user",
                smtp_password="pass",
                verified_sender_domain="blocked-domain.example.net",
            )

        self.assertEqual(result.result, "deferred")
        mock_mailto.assert_not_called()

    def test_fork_c_sender_domain_match_authorized(self) -> None:
        """Mailto target domain matching verified_sender_domain is authorized
        even when NOT in the mailto_allowed_domains list."""
        cfg = self._config(dry_run=True)
        # Empty mailto allowlist — only sender-domain match can authorize
        cfg.mailto_allowed_domains = []

        blocked = UnsubscribeResult(
            sender=self._SENDER,
            method="one-click",
            target="https://blocked-domain.example.net/unsub",
            result="deferred",
            http_status=None,
            dry_run=True,
            detail="host blocked-domain.example.net not in unsubscribe_allowed_domains",
        )

        with patch(
            "icloud_helper.unsubscribe.unsubscribe_one_click",
            return_value=blocked,
        ), patch(
            "icloud_helper.unsubscribe.unsubscribe_mailto"
        ) as mock_mailto:
            mock_mailto.return_value = UnsubscribeResult(
                sender=self._SENDER,
                method="mailto",
                target=self._MAILTO,
                result="success-simulated",
                http_status=None,
                dry_run=True,
                detail="dry-run ok",
            )
            result = perform_unsubscribe(
                sender=self._SENDER,
                unsubscribe_header=self._HEADER,
                unsubscribe_post_header=self._POST,
                global_config=cfg,
                smtp_username="user",
                smtp_password="pass",
                # Exact match: target domain == sender domain
                verified_sender_domain="blocked-domain.example.net",
            )

        # Fallback must have fired
        mock_mailto.assert_called_once()
        self.assertEqual(result.result, "success-simulated")

    def test_fork_c_domain_mismatch_now_authorized(self) -> None:
        """B.4 redesign: cross-domain mailto targets are now authorized when the
        sender passed DKIM/DMARC and the target is not in mailto_denied_domains.
        The old domain-match requirement is dropped (B.4 spec).
        Delivery goes via iCloud SMTP, not the target host."""
        cfg = self._config(dry_run=True)
        cfg.mailto_allowed_domains = []  # empty legacy allowlist

        blocked = UnsubscribeResult(
            sender=self._SENDER,
            method="one-click",
            target="https://blocked-domain.example.net/unsub",
            result="deferred",
            http_status=None,
            dry_run=True,
            detail="host blocked-domain.example.net not in unsubscribe_allowed_domains",
        )

        # Mailto target points to a DIFFERENT domain than the sender.
        # Under B.4 this must be authorized (no domain-match requirement).
        mismatched_header = (
            "<https://blocked-domain.example.net/unsub>,"
            " <mailto:unsub@other-domain.example.net>"
        )

        with patch(
            "icloud_helper.unsubscribe.unsubscribe_one_click",
            return_value=blocked,
        ), patch(
            "icloud_helper.unsubscribe.unsubscribe_mailto"
        ) as mock_mailto, patch(
            # Suppress DNS resolution in _mailto_domain_authorized for dry-run.
            "icloud_helper.unsubscribe._mailto_domain_authorized",
            return_value=(True, None),
        ):
            mock_mailto.return_value = UnsubscribeResult(
                sender=self._SENDER,
                method="mailto",
                target="host:other-domain.example.net",
                result="success-simulated",
                http_status=None,
                dry_run=True,
                detail="dry-run ok",
            )
            result = perform_unsubscribe(
                sender=self._SENDER,
                unsubscribe_header=mismatched_header,
                unsubscribe_post_header=self._POST,
                global_config=cfg,
                smtp_username="user",
                smtp_password="pass",
                # Sender domain does NOT match the mailto target domain.
                # Under B.4, this no longer blocks the fallback.
                verified_sender_domain="blocked-domain.example.net",
            )

        # B.4: cross-domain mailto is now authorized — fallback must fire.
        mock_mailto.assert_called_once()
        self.assertEqual(result.result, "success-simulated")

    def test_ssrf_block_does_not_trigger_mailto_fallback(self) -> None:
        """An SSRF-triggered deferred result must never fall through to mailto
        fallback — SSRF is a security gate, not an allowlist gate."""
        cfg = self._config(dry_run=False)

        ssrf_blocked = UnsubscribeResult(
            sender=self._SENDER,
            method="one-click",
            target="https://192.168.1.1/unsub",
            result="deferred",
            http_status=None,
            dry_run=False,
            detail="SSRF guard: private IP 192.168.1.1 blocked",
        )

        with patch(
            "icloud_helper.unsubscribe.unsubscribe_one_click",
            return_value=ssrf_blocked,
        ), patch(
            "icloud_helper.unsubscribe.unsubscribe_mailto"
        ) as mock_mailto:
            # Include a mailto URI — fallback must still NOT fire for SSRF
            header = (
                "<https://192.168.1.1/unsub>,"
                f" <{self._MAILTO}>"
            )
            result = perform_unsubscribe(
                sender=self._SENDER,
                unsubscribe_header=header,
                unsubscribe_post_header=self._POST,
                global_config=cfg,
                smtp_username="user",
                smtp_password="pass",
                verified_sender_domain="blocked-domain.example.net",
            )

        mock_mailto.assert_not_called()
        self.assertEqual(result.result, "deferred")
        self.assertIn("SSRF", result.detail)

    def test_fallback_reason_set_on_successful_fallback(self) -> None:
        """UnsubscribeResult.fallback_reason must describe the one-click block
        reason when the mailto fallback succeeds."""
        cfg = self._config(dry_run=True)

        block_detail = (
            "host blocked-domain.example.net not in unsubscribe_allowed_domains"
        )
        blocked = UnsubscribeResult(
            sender=self._SENDER,
            method="one-click",
            target="https://blocked-domain.example.net/unsub",
            result="deferred",
            http_status=None,
            dry_run=True,
            detail=block_detail,
        )

        with patch(
            "icloud_helper.unsubscribe.unsubscribe_one_click",
            return_value=blocked,
        ), patch(
            "icloud_helper.unsubscribe.unsubscribe_mailto"
        ) as mock_mailto:
            mock_mailto.return_value = UnsubscribeResult(
                sender=self._SENDER,
                method="mailto",
                target=self._MAILTO,
                result="success-simulated",
                http_status=None,
                dry_run=True,
                detail="dry-run ok",
            )
            result = perform_unsubscribe(
                sender=self._SENDER,
                unsubscribe_header=self._HEADER,
                unsubscribe_post_header=self._POST,
                global_config=cfg,
                smtp_username="user",
                smtp_password="pass",
                verified_sender_domain="blocked-domain.example.net",
            )

        self.assertIsNotNone(result.fallback_reason)
        self.assertIn("one-click blocked", result.fallback_reason or "")


class TestMailtoFallbackDenyListFix(unittest.TestCase):
    """FIX 2: transport/malformed deferred outcomes must NOT trigger mailto fallback."""

    _SENDER = "news@blocked-domain.example.net"
    _MAILTO = "mailto:unsub@blocked-domain.example.net"
    _POST = "List-Unsubscribe=One-Click"

    def _config(self, **kw: object) -> _FakeGlobalConfig:
        cfg = _FakeGlobalConfig(**kw)  # type: ignore[arg-type]
        cfg.unsubscribe_allowed_domains = ["example.com"]
        return cfg

    def _header_with_mailto(self, https_url: str) -> str:
        return f"<{https_url}>, <{self._MAILTO}>"

    def test_redirect_refused_does_not_trigger_mailto_fallback(self) -> None:
        """A 'redirect refused' deferred result is a transport error, not an
        allowlist block; the mailto fallback must NOT fire."""
        cfg = self._config(dry_run=True)

        redirect_refused = UnsubscribeResult(
            sender=self._SENDER,
            method="one-click",
            target="https://blocked-domain.example.net/unsub",
            result="deferred",
            http_status=302,
            dry_run=True,
            detail="redirect refused",
        )
        header = self._header_with_mailto(
            "https://blocked-domain.example.net/unsub"
        )

        with patch(
            "icloud_helper.unsubscribe.unsubscribe_one_click",
            return_value=redirect_refused,
        ), patch(
            "icloud_helper.unsubscribe.unsubscribe_mailto"
        ) as mock_mailto:
            result = perform_unsubscribe(
                sender=self._SENDER,
                unsubscribe_header=header,
                unsubscribe_post_header=self._POST,
                global_config=cfg,
                smtp_username="user",
                smtp_password="pass",
                verified_sender_domain="blocked-domain.example.net",
            )

        mock_mailto.assert_not_called()
        self.assertIsNone(result.method_used, (
            f"method_used must be None (no mailto attempt); got {result.method_used}"
        ))

    def test_url_has_no_hostname_does_not_trigger_mailto_fallback(self) -> None:
        """A 'URL has no hostname' deferred result is a malformed-URL error, not
        an allowlist block; the mailto fallback must NOT fire."""
        cfg = self._config(dry_run=True)

        no_hostname = UnsubscribeResult(
            sender=self._SENDER,
            method="one-click",
            target="",
            result="deferred",
            http_status=None,
            dry_run=True,
            detail="URL has no hostname",
        )
        header = self._header_with_mailto("https://blocked-domain.example.net/unsub")

        with patch(
            "icloud_helper.unsubscribe.unsubscribe_one_click",
            return_value=no_hostname,
        ), patch(
            "icloud_helper.unsubscribe.unsubscribe_mailto"
        ) as mock_mailto:
            result = perform_unsubscribe(
                sender=self._SENDER,
                unsubscribe_header=header,
                unsubscribe_post_header=self._POST,
                global_config=cfg,
                smtp_username="user",
                smtp_password="pass",
                verified_sender_domain="blocked-domain.example.net",
            )

        mock_mailto.assert_not_called()
        self.assertIsNone(result.method_used, (
            f"method_used must be None (no mailto attempt); got {result.method_used}"
        ))

    def test_genuine_allowlist_block_still_triggers_mailto_fallback(self) -> None:
        """A genuine 'not in unsubscribe_allowed_domains' deferred result must
        still trigger the mailto fallback (regression guard)."""
        cfg = self._config(dry_run=True)

        allowlist_block = UnsubscribeResult(
            sender=self._SENDER,
            method="one-click",
            target="https://blocked-domain.example.net/unsub",
            result="deferred",
            http_status=None,
            dry_run=True,
            detail=(
                "host blocked-domain.example.net not in unsubscribe_allowed_domains"
            ),
        )
        header = self._header_with_mailto(
            "https://blocked-domain.example.net/unsub"
        )

        with patch(
            "icloud_helper.unsubscribe.unsubscribe_one_click",
            return_value=allowlist_block,
        ), patch(
            "icloud_helper.unsubscribe.unsubscribe_mailto"
        ) as mock_mailto:
            mock_mailto.return_value = UnsubscribeResult(
                sender=self._SENDER,
                method="mailto",
                target=self._MAILTO,
                result="success-simulated",
                http_status=None,
                dry_run=True,
                detail="dry-run mailto ok",
            )
            perform_unsubscribe(
                sender=self._SENDER,
                unsubscribe_header=header,
                unsubscribe_post_header=self._POST,
                global_config=cfg,
                smtp_username="user",
                smtp_password="pass",
                verified_sender_domain="blocked-domain.example.net",
            )

        mock_mailto.assert_called_once()


if __name__ == "__main__":
    unittest.main()
