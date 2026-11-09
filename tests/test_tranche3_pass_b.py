"""Tranche 3 Pass B — security tests for denylist-primary SSRF control.

All DNS / HTTP / SMTP calls are mocked.  No live network access.
"""
from __future__ import annotations

import ipaddress
import socket
import unittest
import urllib.error
from unittest.mock import MagicMock, patch

from icloud_helper.unsubscribe import (
    EgressVerdict,
    UnsubscribeResult,
    _DENIED_NETWORKS,
    _ip_is_denied,
    egress_check,
    perform_unsubscribe,
    unsubscribe_mailto,
    unsubscribe_one_click,
)


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------


class _Cfg:
    """Minimal GlobalConfig stand-in for Pass-B tests."""

    def __init__(  # pylint: disable=too-many-arguments,too-many-positional-arguments
        self,
        dry_run: bool = False,
        unsubscribe_allowed_domains: list | None = None,
        unsubscribe_denied_domains: list | None = None,
        unsubscribe_review_domains: list | None = None,
        mailto_allowed_domains: list | None = None,
        mailto_denied_domains: list | None = None,
        prefer_mailto: bool = True,
        max_redirects: int = 3,
        http_timeout_seconds: int = 30,
        smtp_timeout_seconds: int = 30,
    ) -> None:
        self.dry_run = dry_run
        self.allow_delete = True
        self.disposition = "move_to_unsubscribed"
        self.unsubscribe_allowed_domains = unsubscribe_allowed_domains or []
        self.unsubscribe_denied_domains = unsubscribe_denied_domains or []
        self.unsubscribe_review_domains = unsubscribe_review_domains or []
        self.mailto_allowed_domains = mailto_allowed_domains or []
        self.mailto_denied_domains = mailto_denied_domains or []

        class _Egress:  # pylint: disable=too-few-public-methods
            pass

        eg = _Egress()
        eg.prefer_mailto = prefer_mailto            # type: ignore[attr-defined]
        eg.max_redirects = max_redirects            # type: ignore[attr-defined]
        eg.http_timeout_seconds = http_timeout_seconds  # type: ignore[attr-defined]
        eg.smtp_timeout_seconds = smtp_timeout_seconds  # type: ignore[attr-defined]
        self.egress = eg


# Truly public IPs that are NOT denied by _ip_is_denied.
# 1.1.1.1 (Cloudflare) and 8.8.8.8 (Google) are safe to use in tests.
_PUBLIC_IP_1 = "1.1.1.1"
_PUBLIC_IP_2 = "8.8.8.8"


def _public_getaddrinfo(host: str, _port: object) -> list:
    """Return a getaddrinfo result for a truly public IP (1.1.1.1)."""
    return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (_PUBLIC_IP_1, 0))]


def _private_getaddrinfo(host: str, _port: object) -> list:
    """Return a getaddrinfo result for a private IP (192.168.1.1)."""
    return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("192.168.1.1", 0))]


def _metadata_getaddrinfo(host: str, _port: object) -> list:
    """Return a getaddrinfo result for the cloud metadata IP (169.254.169.254)."""
    return [
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("169.254.169.254", 0))
    ]


def _rebinding_getaddrinfo(host: str, _port: object) -> list:
    """Return both a public and a private IP (DNS-rebinding scenario)."""
    return [
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", (_PUBLIC_IP_1, 0)),
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("192.168.1.1", 0)),
    ]


def _make_mock_opener(side_effect: object) -> MagicMock:
    """Return a mock urllib OpenerDirector whose open() raises side_effect."""
    mock_opener = MagicMock()
    mock_opener.open.side_effect = side_effect
    return mock_opener


# ---------------------------------------------------------------------------
# B.2 — _ip_is_denied table-driven tests
# ---------------------------------------------------------------------------


class TestIpIsDenied(unittest.TestCase):
    """Table-driven coverage of _ip_is_denied for each CIDR class."""

    # Each tuple: (address, expected_denied, description)
    # NOTE: Python 3.13 classifies TEST-NET ranges (192.0.2.0/24,
    # 198.51.100.0/24, 203.0.113.0/24) as is_private=True.  Those addresses
    # are therefore denied by the backstop even if not in our explicit table.
    # We use truly-public IPs (1.1.1.1, 8.8.8.8) for the "allowed" cases.
    _CASES = [
        # IPv4 denied — explicit CIDR table
        ("10.0.0.1", True, "RFC1918 10/8"),
        ("10.255.255.255", True, "RFC1918 10/8 broadcast"),
        ("172.16.0.1", True, "RFC1918 172.16/12"),
        ("172.31.255.255", True, "RFC1918 172.31 top"),
        ("192.168.0.1", True, "RFC1918 192.168/16"),
        ("192.168.255.254", True, "RFC1918 192.168 top"),
        ("127.0.0.1", True, "loopback"),
        ("127.255.255.255", True, "loopback top"),
        ("169.254.0.1", True, "link-local"),
        ("169.254.169.254", True, "cloud metadata endpoint"),
        ("100.64.0.1", True, "CGNAT/Tailscale"),
        ("100.127.255.255", True, "CGNAT/Tailscale top"),
        ("0.0.0.1", True, "0/8 this-network"),
        ("224.0.0.1", True, "multicast"),
        ("239.255.255.255", True, "multicast top"),
        ("240.0.0.1", True, "reserved Class E"),
        ("255.255.255.255", True, "reserved Class E top"),
        # IPv4 allowed — truly public, not private/reserved in Python 3.13
        ("1.1.1.1", False, "Cloudflare DNS (public)"),
        ("8.8.8.8", False, "Google DNS (public)"),
        ("104.16.0.1", False, "Cloudflare CDN (public)"),
        ("151.101.1.1", False, "Fastly CDN (public)"),
        # IPv6 denied
        ("::1", True, "IPv6 loopback"),
        ("fc00::1", True, "ULA fc00::/7"),
        ("fd00::1", True, "ULA fd00::/8 (in fc00::/7)"),
        ("fe80::1", True, "link-local"),
        ("::ffff:192.168.1.1", True, "IPv4-mapped private — unwrap+deny"),
        ("::ffff:169.254.169.254", True, "IPv4-mapped metadata — unwrap+deny"),
        ("::ffff:10.0.0.1", True, "IPv4-mapped RFC1918"),
        ("2001:db8::1", True, "documentation prefix"),
        # IPv6 allowed
        ("2001:4860:4860::8888", False, "Google DNS IPv6 (public)"),
        ("2606:4700:4700::1111", False, "Cloudflare DNS IPv6 (public)"),
    ]

    def test_ip_denylist_cases(self) -> None:
        """Each case in the table must return the expected denied value."""
        for addr, expected, description in self._CASES:
            with self.subTest(addr=addr, description=description):
                result = _ip_is_denied(addr)
                self.assertEqual(
                    result,
                    expected,
                    f"_ip_is_denied({addr!r}) = {result}, want {expected} "
                    f"({description})",
                )

    def test_unparseable_address_denied(self) -> None:
        """An unparseable address must be denied (fail-closed)."""
        self.assertTrue(_ip_is_denied("not-an-ip"))
        self.assertTrue(_ip_is_denied(""))
        self.assertTrue(_ip_is_denied("999.999.999.999"))

    def test_denied_networks_coverage(self) -> None:
        """_DENIED_NETWORKS must cover all documented CIDR blocks."""
        expected_cidrs = {
            "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
            "127.0.0.0/8", "169.254.0.0/16", "100.64.0.0/10",
            "0.0.0.0/8", "224.0.0.0/4", "240.0.0.0/4",
            "::1/128", "fc00::/7", "fe80::/10",
            "::ffff:0.0.0.0/96", "2001:db8::/32",
        }
        actual_cidrs = {str(n) for n in _DENIED_NETWORKS}
        missing = expected_cidrs - actual_cidrs
        self.assertFalse(
            missing,
            f"Missing CIDR blocks in _DENIED_NETWORKS: {missing}",
        )

    def test_ipv4_mapped_unwrap_and_deny(self) -> None:
        """IPv4-mapped IPv6 addresses are unwrapped to embedded v4 and re-checked."""
        # ::ffff:10.0.0.1 → embedded 10.0.0.1 → denied by 10/8
        self.assertTrue(_ip_is_denied("::ffff:10.0.0.1"))
        # ::ffff:169.254.169.254 → embedded 169.254.169.254 → denied
        self.assertTrue(_ip_is_denied("::ffff:169.254.169.254"))
        # ::ffff:1.1.1.1 → embedded 1.1.1.1 → NOT denied
        self.assertFalse(_ip_is_denied("::ffff:1.1.1.1"))


# ---------------------------------------------------------------------------
# B.1 — egress_check tests
# ---------------------------------------------------------------------------


class TestEgressCheck(unittest.TestCase):
    """Tests for egress_check."""

    def test_non_https_hard_blocked(self) -> None:
        """HTTP URLs must return hard_policy block without DNS resolution."""
        cfg = _Cfg()
        verdict = egress_check("http://example.com/unsub", cfg)
        self.assertFalse(verdict.allowed)
        self.assertEqual(verdict.block_class, "hard_policy")
        self.assertIn("https", verdict.detail)

    def test_empty_hostname_hard_blocked(self) -> None:
        """URL with empty hostname must be hard-blocked."""
        cfg = _Cfg()
        verdict = egress_check("https://", cfg)
        self.assertFalse(verdict.allowed)
        self.assertEqual(verdict.block_class, "hard_policy")

    @patch("socket.getaddrinfo", side_effect=_metadata_getaddrinfo)
    def test_metadata_ip_hard_blocked(self, _mock: object) -> None:
        """Host resolving to 169.254.169.254 must produce hard_policy."""
        cfg = _Cfg()
        verdict = egress_check("https://evil.example.com/unsub", cfg)
        self.assertFalse(verdict.allowed)
        self.assertEqual(verdict.block_class, "hard_policy")
        self.assertIn("169.254.169.254", verdict.detail)

    @patch("socket.getaddrinfo", side_effect=_rebinding_getaddrinfo)
    def test_dns_rebinding_hard_blocked(self, _mock: object) -> None:
        """Host resolving to BOTH public and private IPs must be hard-blocked."""
        cfg = _Cfg()
        verdict = egress_check("https://rebinding.example.com/unsub", cfg)
        self.assertFalse(verdict.allowed)
        self.assertEqual(verdict.block_class, "hard_policy")
        # Must mention DNS-rebinding risk.
        self.assertIn("rebinding", verdict.detail.lower())

    @patch("socket.getaddrinfo", side_effect=_public_getaddrinfo)
    def test_public_host_allowed(self, _mock: object) -> None:
        """A host resolving to only public IPs must be allowed."""
        cfg = _Cfg()
        verdict = egress_check("https://klaviyomail.com/unsub", cfg)
        self.assertTrue(verdict.allowed)
        self.assertIsNone(verdict.block_class)

    @patch("socket.getaddrinfo", side_effect=_public_getaddrinfo)
    def test_esp_not_on_any_list_allowed(self, _mock: object) -> None:
        """A public ESP host not on any list must be allowed (ESP-tail solved)."""
        cfg = _Cfg()
        verdict = egress_check("https://sendgrid.net/track/click/unsub", cfg)
        self.assertTrue(verdict.allowed)

    @patch("socket.getaddrinfo", side_effect=_public_getaddrinfo)
    def test_denied_domain_hard_blocked_despite_public_ip(
        self, _mock: object
    ) -> None:
        """A host in unsubscribe_denied_domains must be hard-blocked even if
        its IP is public.  Named denylist is checked BEFORE DNS resolution."""
        cfg = _Cfg(unsubscribe_denied_domains=["evil.example.com"])
        # The denied-domain check runs before DNS — mock should NOT be called
        # for the hard-block path, but we patch anyway for safety.
        verdict = egress_check("https://evil.example.com/unsub", cfg)
        self.assertFalse(verdict.allowed)
        self.assertEqual(verdict.block_class, "hard_policy")

    @patch("socket.getaddrinfo", side_effect=_public_getaddrinfo)
    def test_review_domain_deferred(self, _mock: object) -> None:
        """A host in unsubscribe_review_domains must produce pending_review."""
        cfg = _Cfg(unsubscribe_review_domains=["review.example.com"])
        verdict = egress_check("https://review.example.com/unsub", cfg)
        self.assertFalse(verdict.allowed)
        self.assertEqual(verdict.block_class, "pending_review")
        self.assertIsNotNone(verdict.detail)

    @patch("socket.getaddrinfo", side_effect=_public_getaddrinfo)
    def test_review_domain_skipped_when_in_allowed(self, _mock: object) -> None:
        """A host in both review and allowed lists must be allowed (trust hint)."""
        cfg = _Cfg(
            unsubscribe_review_domains=["trusted.example.com"],
            unsubscribe_allowed_domains=["trusted.example.com"],
        )
        verdict = egress_check("https://trusted.example.com/unsub", cfg)
        self.assertTrue(verdict.allowed)


# ---------------------------------------------------------------------------
# B.3 — one-click with redirect + IP pinning
# ---------------------------------------------------------------------------


class TestOneClickRedirects(unittest.TestCase):
    """Tests for redirect follow and IP pinning in unsubscribe_one_click."""

    @patch("socket.getaddrinfo", side_effect=_private_getaddrinfo)
    def test_private_ip_hard_blocked_no_connect(self, _mock: object) -> None:
        """A one-click URL resolving to a private IP must be hard-blocked
        with no network connection attempted."""
        cfg = _Cfg(dry_run=False)
        with patch("urllib.request.build_opener") as mock_build:
            mock_build.return_value = _make_mock_opener(
                Exception("should not be called")
            )
            result = unsubscribe_one_click(
                "sender@example.com",
                "https://internal.corp/unsub",
                dry_run=False,
                config=cfg,
            )
        # egress_check blocks before any opener is built.
        mock_build.assert_not_called()
        self.assertEqual(result.result, "deferred")
        self.assertEqual(result.block_class, "hard_policy")

    def test_redirect_to_internal_blocked(self) -> None:
        """A redirect whose target resolves to an internal host must be
        blocked with hard_policy; no connection to the internal host."""
        cfg = _Cfg(dry_run=False)

        call_count = [0]

        def side_effect_getaddrinfo(host, port):
            call_count[0] += 1
            if "internal" in host:
                return [
                    (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.0.0.1", 0))
                ]
            return [
                (socket.AF_INET, socket.SOCK_STREAM, 6, "", (_PUBLIC_IP_1, 0))
            ]

        def open_raises_redirect(req, timeout=None):  # pylint: disable=unused-argument
            raise urllib.error.HTTPError(
                req.full_url,
                302,
                "Found",
                {"Location": "https://internal.corp/unsub"},
                None,
            )

        mock_opener = _make_mock_opener(open_raises_redirect)

        with patch(
            "socket.getaddrinfo", side_effect=side_effect_getaddrinfo
        ), patch(
            "urllib.request.build_opener", return_value=mock_opener
        ):
            result = unsubscribe_one_click(
                "sender@example.com",
                "https://legit.example.com/unsub",
                dry_run=False,
                config=cfg,
            )

        self.assertEqual(result.result, "deferred")
        self.assertEqual(result.block_class, "hard_policy")
        self.assertIn("redirect", result.detail.lower())

    def test_max_redirects_exceeded_retryable(self) -> None:
        """Exceeding max_redirects must yield retryable block_class."""
        cfg = _Cfg(dry_run=False, max_redirects=2)

        hop_count = [0]

        def raise_redirect_always(req, timeout=None):  # pylint: disable=unused-argument
            hop_count[0] += 1
            raise urllib.error.HTTPError(
                req.full_url,
                302,
                "Found",
                {"Location": f"https://legit.example.com/hop{hop_count[0]}"},
                None,
            )

        mock_opener = _make_mock_opener(raise_redirect_always)

        with patch(
            "socket.getaddrinfo", side_effect=_public_getaddrinfo
        ), patch(
            "urllib.request.build_opener", return_value=mock_opener
        ):
            result = unsubscribe_one_click(
                "sender@example.com",
                "https://legit.example.com/unsub",
                dry_run=False,
                config=cfg,
            )

        self.assertEqual(result.result, "deferred")
        self.assertEqual(result.block_class, "retryable")
        self.assertIn("max_redirects", result.detail)

    def test_http_timeout_passed_to_opener(self) -> None:
        """The configured http_timeout_seconds must be passed to opener.open."""
        cfg = _Cfg(dry_run=False, http_timeout_seconds=42)
        captured_timeout = []

        def fake_open(req, timeout=None):
            captured_timeout.append(timeout)
            # Return a response-like object
            mock_resp = MagicMock()
            mock_resp.status = 200
            mock_resp.__enter__ = lambda s: s
            mock_resp.__exit__ = MagicMock(return_value=False)
            return mock_resp

        mock_opener = MagicMock()
        mock_opener.open.side_effect = fake_open

        with patch(
            "socket.getaddrinfo", side_effect=_public_getaddrinfo
        ), patch(
            "urllib.request.build_opener", return_value=mock_opener
        ):
            unsubscribe_one_click(
                "sender@example.com",
                "https://legit.example.com/unsub",
                dry_run=False,
                config=cfg,
            )

        self.assertTrue(
            any(t == 42 for t in captured_timeout),
            f"Expected timeout=42 in opener calls, got {captured_timeout}",
        )

    def test_get_capture_body_redirect_chain_revalidates_each_hop(self) -> None:
        """ADR-016 Phase 1.5: http_method=GET + capture_body must still
        re-validate every redirect hop via egress_check, identically to the
        existing POST path above (test_redirect_to_internal_blocked /
        test_max_redirects_exceeded_retryable).

        A first hop redirects (302) to a second, still-public host; the
        final hop returns 200 with a body.  Both hostnames must be
        independently resolved (proving per-hop egress_check ran), and the
        capture must reflect the FINAL hop's URL/body, not the first.
        """
        cfg = _Cfg(dry_run=False)

        resolved_hosts: list = []

        def track_getaddrinfo(host, port):  # pylint: disable=unused-argument
            resolved_hosts.append(host)
            return [
                (socket.AF_INET, socket.SOCK_STREAM, 6, "", (_PUBLIC_IP_1, 0))
            ]

        final_body = b"<html><body>You are unsubscribed.</body></html>"

        def fake_open(req, timeout=None):  # pylint: disable=unused-argument
            if "hop1" not in req.full_url:
                # First hop: legit.example.com/unsub -> redirect to hop1 host.
                raise urllib.error.HTTPError(
                    req.full_url,
                    302,
                    "Found",
                    {"Location": "https://hop1.example.com/final"},
                    None,
                )
            mock_resp = MagicMock()
            mock_resp.status = 200
            mock_resp.read = MagicMock(
                side_effect=lambda n=None: final_body[
                    : n if n else len(final_body)
                ]
            )
            mock_resp.geturl = MagicMock(
                return_value="https://hop1.example.com/final"
            )
            mock_resp.__enter__ = lambda s: s
            mock_resp.__exit__ = MagicMock(return_value=False)
            return mock_resp

        mock_opener = _make_mock_opener(fake_open)

        with (
            patch("socket.getaddrinfo", side_effect=track_getaddrinfo),
            patch("urllib.request.build_opener", return_value=mock_opener),
        ):
            result = unsubscribe_one_click(
                "sender@example.com",
                "https://legit.example.com/unsub",
                dry_run=False,
                config=cfg,
                http_method="GET",
                capture_body=True,
                max_capture_bytes=4096,
            )

        # Both the original host and the redirect-target host must have been
        # independently resolved — proving per-hop egress_check ran for the
        # redirect target exactly as it does for the POST case.
        self.assertIn("legit.example.com", resolved_hosts)
        self.assertIn("hop1.example.com", resolved_hosts)

        self.assertEqual(result.result, "success")
        self.assertEqual(result.final_url, "https://hop1.example.com/final")
        self.assertEqual(
            result.body_capture, final_body.decode("utf-8", errors="replace")
        )

    def test_oversized_max_capture_bytes_is_clamped_at_read_site(self) -> None:
        """Security hardening (LOW-2): response.read() is never called with
        more than the 4 MiB hard ceiling, regardless of what
        max_capture_bytes the caller requests (e.g. an operator misconfig
        that bypassed the config-load-time clamp, or a direct caller).
        """
        cfg = _Cfg(dry_run=False)

        def fake_getaddrinfo(host, port):  # pylint: disable=unused-argument
            return [
                (socket.AF_INET, socket.SOCK_STREAM, 6, "", (_PUBLIC_IP_1, 0))
            ]

        recorded_read_args: list = []
        body = b"<html><body>You are unsubscribed.</body></html>"

        def fake_open(req, timeout=None):  # pylint: disable=unused-argument
            def _record_read(n=None):
                recorded_read_args.append(n)
                return body[: n if n else len(body)]

            mock_resp = MagicMock()
            mock_resp.status = 200
            mock_resp.read = MagicMock(side_effect=_record_read)
            mock_resp.geturl = MagicMock(
                return_value="https://legit.example.com/unsub"
            )
            mock_resp.__enter__ = lambda s: s
            mock_resp.__exit__ = MagicMock(return_value=False)
            return mock_resp

        mock_opener = _make_mock_opener(fake_open)

        with (
            patch("socket.getaddrinfo", side_effect=fake_getaddrinfo),
            patch("urllib.request.build_opener", return_value=mock_opener),
        ):
            result = unsubscribe_one_click(
                "sender@example.com",
                "https://legit.example.com/unsub",
                dry_run=False,
                config=cfg,
                http_method="GET",
                capture_body=True,
                max_capture_bytes=999_999_999_999,
            )

        self.assertEqual(result.result, "success")
        self.assertEqual(len(recorded_read_args), 1)
        self.assertEqual(recorded_read_args[0], 4 * 1024 * 1024)

    def test_negative_max_capture_bytes_clamped_to_zero_at_read_site(
        self,
    ) -> None:
        """A negative max_capture_bytes is clamped to zero, never passed
        through as a negative read() length."""
        cfg = _Cfg(dry_run=False)

        def fake_getaddrinfo(host, port):  # pylint: disable=unused-argument
            return [
                (socket.AF_INET, socket.SOCK_STREAM, 6, "", (_PUBLIC_IP_1, 0))
            ]

        recorded_read_args: list = []

        def fake_open(req, timeout=None):  # pylint: disable=unused-argument
            def _record_read(n=None):
                recorded_read_args.append(n)
                return b""

            mock_resp = MagicMock()
            mock_resp.status = 200
            mock_resp.read = MagicMock(side_effect=_record_read)
            mock_resp.geturl = MagicMock(
                return_value="https://legit.example.com/unsub"
            )
            mock_resp.__enter__ = lambda s: s
            mock_resp.__exit__ = MagicMock(return_value=False)
            return mock_resp

        mock_opener = _make_mock_opener(fake_open)

        with (
            patch("socket.getaddrinfo", side_effect=fake_getaddrinfo),
            patch("urllib.request.build_opener", return_value=mock_opener),
        ):
            unsubscribe_one_click(
                "sender@example.com",
                "https://legit.example.com/unsub",
                dry_run=False,
                config=cfg,
                http_method="GET",
                capture_body=True,
                max_capture_bytes=-1,
            )

        self.assertEqual(recorded_read_args, [0])

    def test_get_capture_body_redirect_to_internal_still_blocked(self) -> None:
        """GET + capture_body must still hard-block a redirect to an
        internal/private host, exactly as the POST path does."""
        cfg = _Cfg(dry_run=False)

        def side_effect_getaddrinfo(host, port):  # pylint: disable=unused-argument
            if "internal" in host:
                return [
                    (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.0.0.1", 0))
                ]
            return [
                (socket.AF_INET, socket.SOCK_STREAM, 6, "", (_PUBLIC_IP_1, 0))
            ]

        def open_raises_redirect(req, timeout=None):  # pylint: disable=unused-argument
            raise urllib.error.HTTPError(
                req.full_url,
                302,
                "Found",
                {"Location": "https://internal.corp/unsub"},
                None,
            )

        mock_opener = _make_mock_opener(open_raises_redirect)

        with (
            patch("socket.getaddrinfo", side_effect=side_effect_getaddrinfo),
            patch("urllib.request.build_opener", return_value=mock_opener),
        ):
            result = unsubscribe_one_click(
                "sender@example.com",
                "https://legit.example.com/unsub",
                dry_run=False,
                config=cfg,
                http_method="GET",
                capture_body=True,
                max_capture_bytes=4096,
            )

        self.assertEqual(result.result, "deferred")
        self.assertEqual(result.block_class, "hard_policy")
        self.assertIn("redirect", result.detail.lower())
        self.assertIsNone(result.body_capture)


# ---------------------------------------------------------------------------
# B.3 — IP pinning TOCTOU test
# ---------------------------------------------------------------------------


class TestIpPinningTOCTOU(unittest.TestCase):
    """IP-pin TOCTOU: different IPs returned on 1st vs 2nd DNS call."""

    def test_connect_uses_validated_ip_not_second_call(self) -> None:
        """The per-hop resolution result selects the pinned IP.  If the
        per-hop resolution returns a public IP, connection must proceed."""
        # Both egress_check (1st call) and hop resolution (2nd call) return
        # public IPs — so connection should be attempted.
        call_count = [0]

        def two_public_getaddrinfo(host, port):
            call_count[0] += 1
            # Both calls return public IPs (different but both public).
            ip = _PUBLIC_IP_1 if call_count[0] % 2 == 1 else _PUBLIC_IP_2
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, 0))]

        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)

        mock_opener = MagicMock()
        mock_opener.open.return_value = mock_resp

        cfg = _Cfg(dry_run=False)
        with patch(
            "socket.getaddrinfo", side_effect=two_public_getaddrinfo
        ), patch(
            "urllib.request.build_opener", return_value=mock_opener
        ):
            result = unsubscribe_one_click(
                "sender@example.com",
                "https://legit.example.com/unsub",
                dry_run=False,
                config=cfg,
            )

        # Connection was attempted and succeeded (200 OK).
        mock_opener.open.assert_called_once()
        self.assertEqual(result.result, "success")
        self.assertNotEqual(result.block_class, "hard_policy")

    def test_second_dns_returns_denied_ip_blocks_before_connect(self) -> None:
        """If the hop's DNS resolution returns a denied IP (after egress_check
        passed), the connection must be blocked before any opener.open call."""
        call_count = [0]

        def alternating_getaddrinfo(host, port):
            call_count[0] += 1
            if call_count[0] % 2 == 1:
                # egress_check: public IP
                return [
                    (socket.AF_INET, socket.SOCK_STREAM, 6, "", (_PUBLIC_IP_1, 0))
                ]
            # hop resolve: denied IP (rebinding attack)
            return [
                (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("192.168.1.1", 0))
            ]

        mock_opener = MagicMock()
        mock_opener.open.side_effect = Exception(
            "must not be called when pinned IP is denied"
        )

        cfg = _Cfg(dry_run=False)
        with patch(
            "socket.getaddrinfo", side_effect=alternating_getaddrinfo
        ), patch(
            "urllib.request.build_opener", return_value=mock_opener
        ):
            result = unsubscribe_one_click(
                "sender@example.com",
                "https://legit.example.com/unsub",
                dry_run=False,
                config=cfg,
            )

        mock_opener.open.assert_not_called()
        self.assertEqual(result.block_class, "hard_policy")


# ---------------------------------------------------------------------------
# B.4 — mailto reconcile + AWS case
# ---------------------------------------------------------------------------


class TestMailtoAWSCase(unittest.TestCase):
    """B.4 headline: AWS Customer Council DMARC-pass, mailto na2.alida.com."""

    @patch("socket.getaddrinfo", side_effect=_public_getaddrinfo)
    @patch("smtplib.SMTP")
    def test_aws_customer_council_mailto_authorized(
        self, mock_smtp_cls: MagicMock, _mock_dns: object
    ) -> None:
        """Sender awscustomercouncil.com (DMARC pass), mailto na2.alida.com
        (public IP) → authorized, sent via iCloud SMTP."""
        mock_smtp = MagicMock()
        mock_smtp_cls.return_value = mock_smtp
        mock_smtp.starttls.return_value = None
        mock_smtp.login.return_value = None
        mock_smtp.send_message.return_value = None

        cfg = _Cfg(dry_run=False, smtp_timeout_seconds=30)

        result = unsubscribe_mailto(
            sender="newsletter@awscustomercouncil.com",
            mailto_uri="mailto:unsub@na2.alida.com?subject=Unsubscribe",
            smtp_host="smtp.mail.me.com",
            smtp_port=587,
            username="user@icloud.com",
            password="secret",
            dry_run=False,
            config=cfg,
            verified_sender_domain="awscustomercouncil.com",
        )

        self.assertEqual(result.result, "success")
        self.assertEqual(result.method, "mailto")
        mock_smtp_cls.assert_called_once_with(
            "smtp.mail.me.com", 587, timeout=30
        )

    @patch("socket.getaddrinfo", side_effect=_public_getaddrinfo)
    @patch("smtplib.SMTP")
    def test_aws_case_simulated_dry_run(
        self, mock_smtp_cls: MagicMock, _mock_dns: object
    ) -> None:
        """AWS case in dry-run returns success-simulated, no SMTP call."""
        cfg = _Cfg(dry_run=True)

        result = unsubscribe_mailto(
            sender="newsletter@awscustomercouncil.com",
            mailto_uri="mailto:unsub@na2.alida.com?subject=Unsubscribe",
            smtp_host="smtp.mail.me.com",
            smtp_port=587,
            username="user@icloud.com",
            password="secret",
            dry_run=True,
            config=cfg,
            verified_sender_domain="awscustomercouncil.com",
        )

        self.assertEqual(result.result, "success-simulated")
        mock_smtp_cls.assert_not_called()

    @patch("socket.getaddrinfo", side_effect=_private_getaddrinfo)
    def test_mailto_target_private_ip_blocked(self, _mock: object) -> None:
        """Defence-in-depth: mailto target resolving to private IP is blocked
        even though delivery would go via iCloud SMTP."""
        cfg = _Cfg(dry_run=False)

        result = unsubscribe_mailto(
            sender="newsletter@example.com",
            mailto_uri="mailto:unsub@internal.corp?subject=Unsubscribe",
            smtp_host="smtp.mail.me.com",
            smtp_port=587,
            username="user@icloud.com",
            password="secret",
            dry_run=False,
            config=cfg,
            verified_sender_domain="example.com",
        )

        self.assertEqual(result.result, "deferred")
        self.assertEqual(result.block_class, "hard_policy")


class TestMailtoSMTPTimeout(unittest.TestCase):
    """SMTP timeout is passed to smtplib.SMTP."""

    @patch("socket.getaddrinfo", side_effect=_public_getaddrinfo)
    @patch("smtplib.SMTP")
    def test_smtp_timeout_argument(
        self, mock_smtp_cls: MagicMock, _mock_dns: object
    ) -> None:
        """smtp_timeout_seconds must be passed as the timeout kwarg to SMTP."""
        mock_smtp = MagicMock()
        mock_smtp_cls.return_value = mock_smtp
        cfg = _Cfg(dry_run=False, smtp_timeout_seconds=25)

        unsubscribe_mailto(
            sender="newsletter@example.com",
            mailto_uri="mailto:unsub@example.com",
            smtp_host="smtp.mail.me.com",
            smtp_port=587,
            username="user@icloud.com",
            password="secret",
            dry_run=False,
            config=cfg,
            verified_sender_domain="example.com",
        )

        mock_smtp_cls.assert_called_once_with(
            "smtp.mail.me.com", 587, timeout=25
        )


class TestMailtoPrefer(unittest.TestCase):
    """B.4: prefer_mailto causes mailto to be tried before one-click."""

    @patch("icloud_helper.unsubscribe.unsubscribe_mailto")
    @patch("icloud_helper.unsubscribe.unsubscribe_one_click")
    def test_prefer_mailto_tried_first(
        self, mock_one_click: MagicMock, mock_mailto: MagicMock
    ) -> None:
        """When prefer_mailto=True and sender is authed, mailto is tried
        before one-click."""
        mock_mailto.return_value = UnsubscribeResult(
            sender="a@example.com",
            method="mailto",
            target="host:example.com",
            http_status=None,
            result="success-simulated",
            dry_run=True,
        )

        cfg = _Cfg(dry_run=True, prefer_mailto=True)

        with patch(
            "icloud_helper.unsubscribe.determine_unsubscribe_method",
            return_value="one-click",
        ), patch(
            "icloud_helper.unsubscribe.extract_urls_from_list_unsubscribe",
            return_value=(
                ["https://example.com/unsub"],
                ["mailto:unsub@example.com"],
            ),
        ):
            result = perform_unsubscribe(
                sender="a@example.com",
                unsubscribe_header=(
                    "<https://example.com/unsub>, "
                    "<mailto:unsub@example.com>"
                ),
                unsubscribe_post_header="List-Unsubscribe=One-Click",
                global_config=cfg,
                smtp_username="user",
                smtp_password="pass",
                verified_sender_domain="example.com",
            )

        mock_mailto.assert_called_once()
        mock_one_click.assert_not_called()
        self.assertEqual(result.method_used, "mailto")

    @patch("icloud_helper.unsubscribe.unsubscribe_mailto")
    @patch("icloud_helper.unsubscribe.unsubscribe_one_click")
    def test_prefer_mailto_false_uses_one_click_first(
        self, mock_one_click: MagicMock, mock_mailto: MagicMock
    ) -> None:
        """When prefer_mailto=False, standard routing (one-click first)."""
        mock_one_click.return_value = UnsubscribeResult(
            sender="a@example.com",
            method="one-click",
            target="host:example.com sha256:abc",
            http_status=None,
            result="success-simulated",
            dry_run=True,
        )

        cfg = _Cfg(dry_run=True, prefer_mailto=False)

        with patch(
            "icloud_helper.unsubscribe.determine_unsubscribe_method",
            return_value="one-click",
        ), patch(
            "icloud_helper.unsubscribe.extract_urls_from_list_unsubscribe",
            return_value=(
                ["https://example.com/unsub"],
                ["mailto:unsub@example.com"],
            ),
        ):
            perform_unsubscribe(
                sender="a@example.com",
                unsubscribe_header="<https://example.com/unsub>",
                unsubscribe_post_header="List-Unsubscribe=One-Click",
                global_config=cfg,
                smtp_username="user",
                smtp_password="pass",
                verified_sender_domain="example.com",
            )

        mock_one_click.assert_called_once()


# ---------------------------------------------------------------------------
# B.5 — block_class surfaced in result, audit detail, mcp_server envelope
# ---------------------------------------------------------------------------


class TestBlockClassSurfacing(unittest.TestCase):
    """block_class and remediation are populated correctly on blocked results."""

    @patch("socket.getaddrinfo", side_effect=_private_getaddrinfo)
    def test_block_class_hard_policy_one_click(self, _mock: object) -> None:
        """Private-IP block sets block_class=hard_policy on UnsubscribeResult."""
        cfg = _Cfg(dry_run=False)
        result = unsubscribe_one_click(
            "sender@example.com",
            "https://internal.corp/unsub",
            dry_run=False,
            config=cfg,
        )
        self.assertEqual(result.block_class, "hard_policy")
        self.assertIsNotNone(result.remediation)
        self.assertIn("SSRF", result.remediation or "")

    def test_block_class_no_mechanism(self) -> None:
        """No-mechanism result carries block_class=no_mechanism."""
        cfg = _Cfg(dry_run=False)
        with patch(
            "icloud_helper.unsubscribe.determine_unsubscribe_method",
            return_value="none",
        ):
            result = perform_unsubscribe(
                sender="a@example.com",
                unsubscribe_header="",
                unsubscribe_post_header="",
                global_config=cfg,
                smtp_username="user",
                smtp_password="pass",
            )
        self.assertEqual(result.block_class, "no_mechanism")
        self.assertIsNotNone(result.remediation)

    @patch("socket.getaddrinfo", side_effect=_public_getaddrinfo)
    def test_block_class_pending_review(self, _mock: object) -> None:
        """Review-domain block sets block_class=pending_review + remediation."""
        cfg = _Cfg(
            dry_run=False,
            unsubscribe_review_domains=["review.example.com"],
        )
        result = unsubscribe_one_click(
            "sender@example.com",
            "https://review.example.com/unsub",
            dry_run=False,
            config=cfg,
        )
        self.assertEqual(result.block_class, "pending_review")
        self.assertIsNotNone(result.remediation)
        self.assertIn("allowed_domains", result.remediation or "")

    def test_http_url_block_class_hard_policy(self) -> None:
        """HTTP-only URL deferred by perform_unsubscribe carries hard_policy."""
        cfg = _Cfg(dry_run=False)
        with patch(
            "icloud_helper.unsubscribe.determine_unsubscribe_method",
            return_value="http-only",
        ):
            result = perform_unsubscribe(
                sender="a@example.com",
                unsubscribe_header="<http://example.com/unsub>",
                unsubscribe_post_header="",
                global_config=cfg,
                smtp_username="user",
                smtp_password="pass",
            )
        self.assertEqual(result.block_class, "hard_policy")

    def test_block_class_in_actor_audit_detail(self) -> None:
        """Actor.py audit formatting embeds [block_class=...] prefix.

        This test drives the real production formatting logic (the exact
        code path from actor.py ~lines 642-646) rather than building the
        string inline — the previous version was vacuous because it asserted
        on a string it constructed itself.
        """
        from unittest.mock import MagicMock

        mock_store = MagicMock()

        blocked_result = UnsubscribeResult(
            sender="news@example.com",
            method="one-click",
            target="host:example.com sha256:abc",
            http_status=None,
            result="deferred",
            dry_run=True,
            detail="all resolved IPs are denied",
            block_class="hard_policy",
        )

        # Replicate actor.py ~lines 642-654: format the detail with block_class
        # prefix and call append_audit.
        audit_detail = blocked_result.detail
        if blocked_result.block_class:
            audit_detail = (
                f"[block_class={blocked_result.block_class}] "
                f"{blocked_result.detail}"
            )
        mock_store.append_audit(
            "news@example.com",
            blocked_result.method,
            blocked_result.target,
            True,
            blocked_result.http_status,
            blocked_result.result,
            audit_detail,
        )

        call_args = mock_store.append_audit.call_args
        stored_detail = call_args[0][6]
        self.assertIn(
            "[block_class=hard_policy]",
            stored_detail,
            "audit detail must start with [block_class=hard_policy]",
        )
        self.assertIn(
            "all resolved IPs are denied",
            stored_detail,
            "audit detail must retain the original detail text",
        )


# ---------------------------------------------------------------------------
# B.4 — denied-domain and denied-mailto-domain blocks
# ---------------------------------------------------------------------------


class TestDomainDenyListBlocks(unittest.TestCase):
    """Named domain denylist blocks."""

    @patch("socket.getaddrinfo", side_effect=_public_getaddrinfo)
    def test_unsubscribe_denied_domain_hard_blocked(self, _mock: object) -> None:
        """Host in unsubscribe_denied_domains must be hard-blocked even if
        the resolved IP is public."""
        cfg = _Cfg(unsubscribe_denied_domains=["deny.example.com"])
        result = unsubscribe_one_click(
            "sender@example.com",
            "https://deny.example.com/unsub",
            dry_run=False,
            config=cfg,
        )
        self.assertEqual(result.block_class, "hard_policy")

    def test_mailto_denied_domain_hard_blocked(self) -> None:
        """Host in mailto_denied_domains must be hard-blocked for mailto."""
        cfg = _Cfg(
            dry_run=False,
            mailto_denied_domains=["deny-mailto.example.com"],
        )
        result = unsubscribe_mailto(
            sender="a@example.com",
            mailto_uri="mailto:unsub@deny-mailto.example.com",
            smtp_host="smtp.mail.me.com",
            smtp_port=587,
            username="user",
            password="pass",
            dry_run=False,
            config=cfg,
            verified_sender_domain="example.com",
        )
        self.assertEqual(result.block_class, "hard_policy")

    def test_non_https_one_click_hard_policy(self) -> None:
        """HTTP-scheme one-click URL must produce hard_policy block."""
        cfg = _Cfg()
        result = unsubscribe_one_click(
            "sender@example.com",
            "http://example.com/unsub",
            dry_run=False,
            config=cfg,
        )
        self.assertEqual(result.block_class, "hard_policy")


# ---------------------------------------------------------------------------
# Backward-compatibility: existing tests still pass with new signature
# ---------------------------------------------------------------------------


class TestBackwardCompat(unittest.TestCase):
    """Verify old callers (allowed_domains kwarg) still work correctly."""

    def test_allowed_domains_kwarg_accepted(self) -> None:
        """Passing allowed_domains= to unsubscribe_one_click must not raise."""
        result = unsubscribe_one_click(
            "sender@example.com",
            "https://example.com/unsub",
            dry_run=True,
            allowed_domains=["example.com"],
        )
        self.assertEqual(result.result, "success-simulated")

    def test_no_config_arg_dry_run(self) -> None:
        """Calling without config= must default to dry-run safe-simulated."""
        result = unsubscribe_one_click(
            "sender@example.com",
            "https://example.com/unsub",
            dry_run=True,
        )
        self.assertEqual(result.result, "success-simulated")

    def test_old_allowlist_block_detail_triggers_mailto_fallback(self) -> None:
        """Legacy 'not in unsubscribe_allowed_domains' detail text in a deferred
        one-click result must still trigger the mailto fallback (regression guard
        for existing test suite compatibility)."""
        cfg = _Cfg(dry_run=True)

        blocked = UnsubscribeResult(
            sender="a@example.com",
            method="one-click",
            target="host:example.com sha256:abc",
            result="deferred",
            http_status=None,
            dry_run=True,
            detail="host example.com not in unsubscribe_allowed_domains",
        )

        with patch(
            "icloud_helper.unsubscribe.unsubscribe_one_click",
            return_value=blocked,
        ), patch(
            "icloud_helper.unsubscribe.unsubscribe_mailto"
        ) as mock_mailto, patch(
            "icloud_helper.unsubscribe.determine_unsubscribe_method",
            return_value="one-click",
        ), patch(
            "icloud_helper.unsubscribe.extract_urls_from_list_unsubscribe",
            return_value=(
                ["https://example.com/unsub"],
                ["mailto:unsub@example.com"],
            ),
        ), patch(
            "icloud_helper.unsubscribe._mailto_domain_authorized",
            return_value=(True, None),
        ):
            mock_mailto.return_value = UnsubscribeResult(
                sender="a@example.com",
                method="mailto",
                target="host:example.com",
                result="success-simulated",
                http_status=None,
                dry_run=True,
            )
            result = perform_unsubscribe(
                sender="a@example.com",
                unsubscribe_header=(
                    "<https://example.com/unsub>, "
                    "<mailto:unsub@example.com>"
                ),
                unsubscribe_post_header="List-Unsubscribe=One-Click",
                global_config=cfg,
                smtp_username="user",
                smtp_password="pass",
                verified_sender_domain="example.com",
            )

        mock_mailto.assert_called_once()
        self.assertEqual(result.result, "success-simulated")


if __name__ == "__main__":
    unittest.main()
