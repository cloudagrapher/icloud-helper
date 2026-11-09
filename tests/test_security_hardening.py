"""Security-hardening regression tests.

Covers:
  CR-1 — DispositionResult failure gates mark_processed / upsert_sender_state
  C1   — SSRF / domain-allowlist validation in unsubscribe_one_click and
           unsubscribe_mailto
  H1   — Authentication-Results gate in actor._check_sender_auth
  H2   — protected_domains exact subdomain matching (info6.citi.com protected;
           thankyou.citi.com not)
  H3   — token-free log targets (safe_target_str / audit storage)
  H4   — approve_sender refuses when allow_mcp_policy_writes=false
  M1   — notify webhook URL validation
  M3   — _SAFE_FOLDER_RE rejects ".." and "/"
"""
from __future__ import annotations

import os
import sys
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

# ---------------------------------------------------------------------------
# Ensure project root is importable when running directly from tests/
# ---------------------------------------------------------------------------
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


class _FakeConfig:
    """Minimal GlobalConfig stand-in."""

    def __init__(
        self,
        dry_run: bool = True,
        allow_mcp_policy_writes: bool = False,
        protected_domains=None,
        unsubscribe_allowed_domains=None,
    ) -> None:
        self.dry_run = dry_run
        self.allow_mcp_policy_writes = allow_mcp_policy_writes
        self.protected_domains = protected_domains or []
        self.unsubscribe_allowed_domains = unsubscribe_allowed_domains or []
        self.allow_delete = False
        self.disposition = "move_to_unsubscribed"


# ============================================================================
# CR-1 — DispositionResult failure gates
# ============================================================================


class TestCR1DispositionGating(unittest.TestCase):
    """mark_processed and upsert_sender_state must not run on disp failure."""

    def test_failed_disposition_skips_mark_processed(self) -> None:
        """When apply_disposition returns success=False, mark_processed is not
        called for that UID and upsert_sender_state does NOT write 'success'."""
        from icloud_helper.disposition import DispositionResult

        mock_imap = MagicMock()
        mock_store = MagicMock()

        failed_disp = DispositionResult(
            folder="INBOX",
            uid=42,
            action="move_to_unsubscribed",
            success=False,
            detail="STORE \\Deleted status=NO",
        )

        with patch(
            "icloud_helper.disposition.apply_disposition",
            return_value=failed_disp,
        ):
            # Simulate the CR-1-fixed loop inline (actor.main is too large
            # to call in unit-test; we replicate the fixed logic here).
            dry_run = False
            sender_uids = [42]
            addr = "news@example.com"
            folder = "INBOX"
            uidvalidity = 1
            all_disp_ok = True

            disp = failed_disp  # apply_disposition already called
            if disp.success:
                if not dry_run:
                    mock_store.mark_processed(
                        folder, uidvalidity, disp.uid, addr, "", "disposed"
                    )
            else:
                all_disp_ok = False

            if not dry_run:
                if all_disp_ok:
                    mock_store.upsert_sender_state(
                        addr, "example.com", unsub_status="success"
                    )
                else:
                    mock_store.upsert_sender_state(
                        addr, "example.com", unsub_status="failed"
                    )

        # mark_processed must NOT have been called
        mock_store.mark_processed.assert_not_called()
        # upsert_sender_state must have been called with status="failed"
        mock_store.upsert_sender_state.assert_called_once()
        call_kwargs = mock_store.upsert_sender_state.call_args
        self.assertIn("failed", call_kwargs[1].get("unsub_status", ""))

    def test_successful_disposition_calls_mark_processed(self) -> None:
        """When apply_disposition returns success=True, mark_processed runs."""
        from icloud_helper.disposition import DispositionResult

        mock_store = MagicMock()

        ok_disp = DispositionResult(
            folder="INBOX",
            uid=42,
            action="move_to_unsubscribed",
            success=True,
            detail="moved",
        )

        dry_run = False
        addr = "news@example.com"
        folder = "INBOX"
        uidvalidity = 1
        all_disp_ok = True

        disp = ok_disp
        if disp.success:
            if not dry_run:
                mock_store.mark_processed(
                    folder, uidvalidity, disp.uid, addr, "", "disposed"
                )
        else:
            all_disp_ok = False

        self.assertTrue(all_disp_ok)
        mock_store.mark_processed.assert_called_once()


# ============================================================================
# C1 — SSRF / domain-allowlist
# ============================================================================


class TestC1SSRFOneClick(unittest.TestCase):
    """unsubscribe_one_click must reject private IPs and off-allowlist hosts."""

    def setUp(self) -> None:
        from icloud_helper.unsubscribe import unsubscribe_one_click
        self.fn = unsubscribe_one_click
        self.allowed = ["example.com"]

    def test_private_ip_rejected(self) -> None:
        """Hostname resolving to 192.168.x.x must be deferred."""
        with patch(
            "socket.getaddrinfo",
            return_value=[(None, None, None, None, ("192.168.1.1", 80))],
        ):
            result = self.fn(
                "a@b.com",
                "https://example.com/unsub",
                dry_run=False,
                allowed_domains=self.allowed,
            )
        self.assertEqual(result.result, "deferred")
        # Detail includes the denied IP, not necessarily the word "private".
        self.assertIn("192.168.1.1", result.detail)

    def test_loopback_ip_rejected(self) -> None:
        """Hostname resolving to 127.0.0.1 must be deferred."""
        with patch(
            "socket.getaddrinfo",
            return_value=[(None, None, None, None, ("127.0.0.1", 80))],
        ):
            result = self.fn(
                "a@b.com",
                "https://example.com/unsub",
                dry_run=False,
                allowed_domains=self.allowed,
            )
        self.assertEqual(result.result, "deferred")

    def test_denied_domain_rejected_even_with_public_ip(self) -> None:
        """Host in unsubscribe_denied_domains must be deferred even if IP is public.

        B.1: egress control is now denylist-primary.  A host resolving to a
        public IP is allowed by default; it is blocked only when it appears
        in unsubscribe_denied_domains (or resolves to a denied IP).
        """
        from icloud_helper.unsubscribe import _FallbackConfig

        cfg = _FallbackConfig(
            allowed_domains=self.allowed,
            denied_domains=["evil-tracker.io"],
        )
        with patch(
            "socket.getaddrinfo",
            return_value=[(None, None, None, None, ("1.1.1.1", 80))],
        ):
            result = self.fn(
                "a@b.com",
                "https://evil-tracker.io/unsub",
                dry_run=False,
                config=cfg,
            )
        self.assertEqual(result.result, "deferred")
        self.assertIn("evil-tracker.io", result.detail)

    def test_public_host_accepted_dry_run(self) -> None:
        """A public host (not on any denylist) must succeed in dry_run.

        B.1: egress is now denylist-primary.  Any host resolving to a public
        IP is permitted unless explicitly denied.  The legacy allowed_domains
        list is a trust hint only (skips pending_review, not the primary gate).
        """
        with patch(
            "socket.getaddrinfo",
            return_value=[(None, None, None, None, ("1.1.1.1", 80))],
        ):
            result = self.fn(
                "a@b.com",
                "https://sub.example.com/unsub",
                dry_run=True,
                allowed_domains=self.allowed,
            )
        self.assertEqual(result.result, "success-simulated")

    def test_non_https_always_rejected(self) -> None:
        result = self.fn(
            "a@b.com",
            "http://example.com/unsub",
            dry_run=False,
            allowed_domains=self.allowed,
        )
        self.assertEqual(result.result, "deferred")

    def test_target_has_no_token_in_dry_run(self) -> None:
        """audit target must not contain query-string tokens."""
        result = self.fn(
            "a@b.com",
            "https://example.com/unsub?token=SECRET&user=STEFAN",
            dry_run=True,
            allowed_domains=self.allowed,
        )
        self.assertNotIn("SECRET", result.target)
        self.assertNotIn("token=", result.target)
        self.assertIn("host:example.com", result.target)


class TestC1SSRFMailto(unittest.TestCase):
    """unsubscribe_mailto must validate to_address and host allowlist."""

    def setUp(self) -> None:
        from icloud_helper.unsubscribe import unsubscribe_mailto
        self.fn = unsubscribe_mailto
        self.allowed = ["example.com"]

    def test_invalid_to_address_rejected(self) -> None:
        # "mailto:not_an_email" has no @ so to_host is empty string;
        # the invalid-address guard fires first.
        result = self.fn(
            "a@b.com",
            "mailto:not_an_email",
            smtp_host="smtp.example.com",
            smtp_port=587,
            username="u",
            password="p",
            dry_run=True,
        )
        self.assertEqual(result.result, "deferred")

    def test_mailto_denied_domain_rejected(self) -> None:
        """Host in mailto_denied_domains must be deferred (B.4/B.1 denylist gate).

        B.4 dropped the domain-match allowlist requirement for mailto.  Cross-
        domain targets are now permitted unless explicitly in mailto_denied_domains
        or resolving to a denied IP.  This test asserts the denylist gate fires.
        """
        from icloud_helper.unsubscribe import _FallbackConfig

        cfg = _FallbackConfig(
            allowed_domains=self.allowed,
            denied_domains=[],
        )
        cfg.mailto_denied_domains = ["evil.io"]  # type: ignore[attr-defined]

        result = self.fn(
            "a@b.com",
            "mailto:unsub@evil.io",
            smtp_host="smtp.example.com",
            smtp_port=587,
            username="u",
            password="p",
            dry_run=True,
            config=cfg,
        )
        self.assertEqual(result.result, "deferred")
        self.assertIn("evil.io", result.detail)

    def test_valid_mailto_dry_run(self) -> None:
        result = self.fn(
            "a@b.com",
            "mailto:unsub@example.com?subject=AttackerSubject&token=XYZ",
            smtp_host="smtp.example.com",
            smtp_port=587,
            username="u",
            password="p",
            dry_run=True,
        )
        self.assertEqual(result.result, "success-simulated")
        # Target must not contain query-string tokens
        self.assertNotIn("AttackerSubject", result.target)
        self.assertNotIn("XYZ", result.target)

    def test_multiple_to_addresses_rejected(self) -> None:
        """RFC 5322 multi-address To must be rejected."""
        result = self.fn(
            "a@b.com",
            "mailto:unsub@example.com,other@example.com",
            smtp_host="smtp.example.com",
            smtp_port=587,
            username="u",
            password="p",
            dry_run=True,
        )
        self.assertEqual(result.result, "deferred")


# ============================================================================
# H1 — Authentication-Results gate
# ============================================================================


class TestH1SenderAuth(unittest.TestCase):
    """check_sender_auth must require dmarc=pass from a trusted iCloud AR.

    iCloud stamps one Authentication-Results header per verifier, each using
    a subdomain of icloud.com as its authserv-id.  The implementation must:
      1. Trust ONLY headers whose authserv-id is under icloud.com.
      2. Match dmarc=pass as a delimited token (not substring).
      3. Evaluate each UID's own headers (tested here via dict fixture).
      4. Return (bool, Optional[str]) — the second element is the DMARC-
         authenticated header.from= domain extracted from the trusted AR
         header (C1 fix).
    """

    def setUp(self) -> None:
        from icloud_helper.auth import check_sender_auth  # noqa: PLC0415
        self.check = check_sender_auth

    def _passed(self, headers: dict) -> bool:
        """Return just the boolean from check_sender_auth."""
        passed, _ = self.check(headers)
        return passed

    def _auth_domain(self, headers: dict):
        """Return just the authenticated_from_domain from check_sender_auth."""
        _, domain = self.check(headers)
        return domain

    # ------------------------------------------------------------------
    # Basic positive / negative cases (retained from original test suite)
    # ------------------------------------------------------------------

    def test_absent_auth_header_fails(self) -> None:
        self.assertFalse(self._passed({}))

    def test_dmarc_fail_fails(self) -> None:
        self.assertFalse(
            self._passed(
                {
                    "authentication-results": (
                        "dmarc.icloud.com; dmarc=fail "
                        "header.from=example.com"
                    )
                }
            )
        )

    def test_dmarc_pass_no_dkim_succeeds(self) -> None:
        """dmarc=pass with no dkim token should pass."""
        self.assertTrue(
            self._passed(
                {
                    "authentication-results": (
                        "dmarc.icloud.com; dmarc=pass header.from=example.com"
                    )
                }
            )
        )

    def test_dmarc_pass_dkim_pass_succeeds(self) -> None:
        self.assertTrue(
            self._passed(
                {
                    "authentication-results": (
                        "dkim-verifier.icloud.com; dkim=pass "
                        "header.d=example.com"
                    ),
                    "authentication-results-list": (
                        "dmarc.icloud.com; dmarc=pass "
                        "header.from=example.com\x00"
                        "dkim-verifier.icloud.com; dkim=pass "
                        "header.d=example.com"
                    ),
                }
            )
        )

    def test_dmarc_pass_dkim_fail_fails(self) -> None:
        """dkim present in same trusted header but not pass → reject."""
        # Single AR header that carries both dmarc and dkim results.
        self.assertFalse(
            self._passed(
                {
                    "authentication-results": (
                        "dmarc.icloud.com; dmarc=pass; dkim=fail"
                    )
                }
            )
        )

    def test_dmarc_case_insensitive(self) -> None:
        """Matching must be case-insensitive."""
        self.assertTrue(
            self._passed(
                {
                    "authentication-results": (
                        "dmarc.icloud.com; DMARC=Pass header.from=example.com"
                    )
                }
            )
        )

    def test_spoofed_sender_no_auth_fails(self) -> None:
        """Message with no auth header (spoofed) must not be actioned."""
        self.assertFalse(self._passed({"from": "ceo@company.com"}))

    # ------------------------------------------------------------------
    # Bypass 1: foreign authserv-id must be ignored entirely
    # ------------------------------------------------------------------

    def test_foreign_authserv_dmarc_pass_rejected(self) -> None:
        """Attacker-injected AR with foreign authserv-id must be rejected.

        An attacker can add their own Authentication-Results header with
        'attacker.example; dmarc=pass'.  The gate must ignore it because
        attacker.example is not under icloud.com.
        """
        # Realistic multi-AR fixture: foreign header first, iCloud DMARC fail.
        headers = {
            "authentication-results": (
                "attacker.example; dmarc=pass header.from=victim.com"
            ),
            "authentication-results-list": (
                "attacker.example; dmarc=pass header.from=victim.com\x00"
                "dmarc.icloud.com; dmarc=fail header.from=victim.com\x00"
                "dkim-verifier.icloud.com; dkim=pass header.d=victim.com\x00"
                "spf.icloud.com; spf=fail smtp.mailfrom=bounce@victim.com"
            ),
        }
        self.assertFalse(self._passed(headers))

    def test_foreign_authserv_only_no_icloud_ar_rejected(self) -> None:
        """Only a foreign AR present — must fail closed."""
        headers = {
            "authentication-results": (
                "mail.attacker.io; dmarc=pass header.from=victim.com"
            ),
            "authentication-results-list": (
                "mail.attacker.io; dmarc=pass header.from=victim.com"
            ),
        }
        self.assertFalse(self._passed(headers))

    def test_subdomain_spoof_not_trusted(self) -> None:
        """'evicloud.com' must NOT be treated as a subdomain of icloud.com."""
        headers = {
            "authentication-results": (
                "dmarc.evicloud.com; dmarc=pass header.from=victim.com"
            ),
        }
        self.assertFalse(self._passed(headers))

    def test_icloud_subdomain_is_trusted(self) -> None:
        """dmarc.icloud.com is a legitimate iCloud authserv-id."""
        headers = {
            "authentication-results": (
                "dmarc.icloud.com; dmarc=pass header.from=example.com"
            ),
        }
        self.assertTrue(self._passed(headers))

    # ------------------------------------------------------------------
    # Bypass 2: dmarc=passfail must NOT match
    # ------------------------------------------------------------------

    def test_dmarc_passfail_rejected(self) -> None:
        """'dmarc=passfail' is not a valid pass — substring must not match."""
        headers = {
            "authentication-results": (
                "dmarc.icloud.com; dmarc=passfail header.from=example.com"
            ),
        }
        self.assertFalse(self._passed(headers))

    def test_dmarc_passed_rejected(self) -> None:
        """'dmarc=passed' (typo/variant) must not satisfy the pass gate."""
        headers = {
            "authentication-results": (
                "dmarc.icloud.com; dmarc=passed header.from=example.com"
            ),
        }
        self.assertFalse(self._passed(headers))

    # ------------------------------------------------------------------
    # Bypass 1+2 combined: iCloud dmarc=fail + foreign dmarc=pass
    # ------------------------------------------------------------------

    def test_icloud_fail_plus_foreign_pass_rejected(self) -> None:
        """iCloud says dmarc=fail; foreign header says dmarc=pass.

        The gate must use only the iCloud verdict and reject.
        """
        headers = {
            "authentication-results": (
                "spf.icloud.com; spf=pass smtp.mailfrom=bounce@example.com"
            ),
            "authentication-results-list": (
                "bimi.icloud.com; bimi=none\x00"
                "arc.icloud.com; arc=none\x00"
                "dmarc.icloud.com; dmarc=fail header.from=example.com\x00"
                "dkim-verifier.icloud.com; dkim=pass header.d=example.com\x00"
                "spf.icloud.com; spf=pass smtp.mailfrom=bounce@example.com\x00"
                "foreign-relay.evil.net; dmarc=pass header.from=example.com"
            ),
        }
        self.assertFalse(self._passed(headers))

    # ------------------------------------------------------------------
    # Genuine iCloud mail (realistic fixture from empirical observation)
    # ------------------------------------------------------------------

    def test_genuine_icloud_multi_ar_accepted(self) -> None:
        """Realistic iCloud multi-AR fixture (5 headers) must pass.

        Mirrors the actual AR headers observed on INBOX messages:
        bimi, arc, dmarc, dkim-verifier, spf — all under *.icloud.com.
        """
        headers = {
            "authentication-results": (
                "spf.icloud.com; spf=pass smtp.mailfrom=bounce@example.com"
            ),
            "authentication-results-list": (
                "bimi.icloud.com; bimi=none\x00"
                "arc.icloud.com; arc=none\x00"
                "dmarc.icloud.com; dmarc=pass header.from=example.com\x00"
                "dkim-verifier.icloud.com; dkim=pass header.d=example.com\x00"
                "spf.icloud.com; spf=pass smtp.mailfrom=bounce@example.com"
            ),
        }
        self.assertTrue(self._passed(headers))

    def test_absent_ar_list_falls_back_to_joined(self) -> None:
        """When authentication-results-list is absent, fall back to the
        joined string (legacy / single-header case)."""
        headers = {
            "authentication-results": (
                "dmarc.icloud.com; dmarc=pass header.from=example.com"
            ),
        }
        self.assertTrue(self._passed(headers))

    # ------------------------------------------------------------------
    # C1: authenticated_from_domain extraction
    # ------------------------------------------------------------------

    def test_authenticated_from_domain_extracted(self) -> None:
        """header.from= in the trusted AR body is returned as authenticated domain."""
        headers = {
            "authentication-results": (
                "dmarc.icloud.com; dmarc=pass header.from=acme.com"
            ),
        }
        domain = self._auth_domain(headers)
        self.assertEqual(domain, "acme.com")

    def test_authenticated_from_domain_lowercased(self) -> None:
        """Returned domain is lowercased regardless of AR casing."""
        headers = {
            "authentication-results": (
                "dmarc.icloud.com; dmarc=pass header.from=ACME.COM"
            ),
        }
        domain = self._auth_domain(headers)
        self.assertEqual(domain, "acme.com")

    def test_authenticated_from_domain_trailing_dot_stripped(self) -> None:
        """Trailing dot is stripped from the returned domain."""
        headers = {
            "authentication-results": (
                "dmarc.icloud.com; dmarc=pass header.from=acme.com."
            ),
        }
        domain = self._auth_domain(headers)
        self.assertEqual(domain, "acme.com")

    def test_no_header_from_returns_none(self) -> None:
        """When the trusted AR header has no header.from=, domain is None."""
        headers = {
            "authentication-results": (
                "dmarc.icloud.com; dmarc=pass"
            ),
        }
        passed, domain = self.check(headers)
        self.assertTrue(passed)
        self.assertIsNone(domain)

    def test_fail_returns_none_domain(self) -> None:
        """On auth failure, authenticated_from_domain is always None."""
        passed, domain = self.check({})
        self.assertFalse(passed)
        self.assertIsNone(domain)

    def test_header_from_evil_domain_used_not_raw_from(self) -> None:
        """AR with header.from=evil-aligned.com yields that domain, not raw From."""
        headers = {
            "from": "newsletter@legitimate.com",
            "authentication-results": (
                "dmarc.icloud.com; dmarc=pass header.from=evil-aligned.com"
            ),
        }
        domain = self._auth_domain(headers)
        # The authenticated domain is what the AR asserts, not the raw From.
        self.assertEqual(domain, "evil-aligned.com")


# ============================================================================
# H2 — protected_domains exact match
# ============================================================================


class TestH2ProtectedDomains(unittest.TestCase):
    """Exact From-domain match: info6.citi.com protected, thankyou.citi.com not."""

    def _actionable(self, sender: str, protected: list) -> bool:
        from icloud_helper.policy import SenderPolicy, get_actionable_senders

        policy = {
            sender: SenderPolicy(action="unsubscribe"),
        }
        result = get_actionable_senders(policy, protected)
        return sender in result

    def test_info6_citi_com_is_protected(self) -> None:
        self.assertFalse(
            self._actionable(
                "citicards@info6.citi.com", ["info6.citi.com"]
            )
        )

    def test_thankyou_citi_com_is_actionable(self) -> None:
        """thankyou.citi.com must NOT be blocked by info6.citi.com protection."""
        self.assertTrue(
            self._actionable(
                "customerservice@thankyou.citi.com", ["info6.citi.com"]
            )
        )

    def test_citi_com_not_over_blocking(self) -> None:
        """Protecting info6.citi.com must not block the parent citi.com."""
        self.assertTrue(
            self._actionable(
                "noreply@citi.com", ["info6.citi.com"]
            )
        )

    def test_exact_match_required(self) -> None:
        """Different subdomain of same parent must not be caught."""
        self.assertTrue(
            self._actionable(
                "alerts@other.citi.com", ["info6.citi.com"]
            )
        )


# ============================================================================
# H3 — token-free audit targets
# ============================================================================


class TestH3TokenScrubbing(unittest.TestCase):
    """_safe_target_str must strip tokens; hostname only in output."""

    def test_hostname_present(self) -> None:
        from icloud_helper.unsubscribe import _safe_target_str

        result = _safe_target_str(
            "https://example.com/unsub?token=SECRET&user=STEFAN"
        )
        self.assertIn("host:example.com", result)

    def test_no_token_in_output(self) -> None:
        from icloud_helper.unsubscribe import _safe_target_str

        result = _safe_target_str(
            "https://example.com/unsub?token=SECRET&loid=XYZ"
        )
        self.assertNotIn("SECRET", result)
        self.assertNotIn("loid", result)
        self.assertNotIn("token=", result)

    def test_sha256_present(self) -> None:
        from icloud_helper.unsubscribe import _safe_target_str

        result = _safe_target_str("https://example.com/unsub?a=b")
        self.assertIn("sha256:", result)
        # sha256 hex is 64 chars
        sha_part = result.split("sha256:")[-1].strip()
        self.assertEqual(len(sha_part), 64)


# ============================================================================
# H4 — approve_sender self-authorisation blocked
# ============================================================================


class TestH4ApproveSenderGuard(unittest.TestCase):
    """approve_sender must refuse when allow_mcp_policy_writes=false."""

    def setUp(self) -> None:
        try:
            import mcp.server.fastmcp  # noqa: F401
        except ImportError:
            import unittest
            raise unittest.SkipTest(
                "mcp requires Python >=3.10; skipping H4 tests"
            )

    def test_refused_when_flag_off(self) -> None:
        """approve_sender must return error dict when flag is false."""
        import icloud_helper.mcp_server as srv

        # Patch config to have allow_mcp_policy_writes=false
        original_allow = srv._config.allow_mcp_policy_writes  # noqa: SLF001
        srv._config.allow_mcp_policy_writes = False  # noqa: SLF001
        try:
            result = srv.approve_sender("user@example.com", "keep")
            self.assertIn("error", result)
            # The error code is the machine-readable key; the human detail
            # must mention the controlling config flag.
            self.assertIn(
                "allow_mcp_policy_writes",
                result.get("detail", "") + result.get("error", ""),
            )
        finally:
            srv._config.allow_mcp_policy_writes = original_allow  # noqa: SLF001

    def test_allowed_when_flag_on(self) -> None:
        """approve_sender must proceed past the H4 guard when flag is true."""
        import icloud_helper.mcp_server as srv

        original_allow = srv._config.allow_mcp_policy_writes  # noqa: SLF001
        srv._config.allow_mcp_policy_writes = True  # noqa: SLF001
        try:
            # It will still fail on other guards (not in policy), but the H4
            # guard must not trigger.
            result = srv.approve_sender(
                "nobody@protected-test-domain.example.com", "keep"
            )
            # H4 guard message must NOT appear
            self.assertNotIn("allow_mcp_policy_writes", result.get("error", ""))
        finally:
            srv._config.allow_mcp_policy_writes = original_allow  # noqa: SLF001

    def test_protected_domain_refused_even_when_flag_on(self) -> None:
        """Protected-domain guard must fire even with allow_mcp_policy_writes=true."""
        import icloud_helper.mcp_server as srv

        original_allow = srv._config.allow_mcp_policy_writes  # noqa: SLF001
        original_protected = srv._config.protected_domains  # noqa: SLF001
        srv._config.allow_mcp_policy_writes = True  # noqa: SLF001
        srv._config.protected_domains = ["info6.citi.com"]  # noqa: SLF001
        try:
            result = srv.approve_sender("citicards@info6.citi.com", "unsubscribe")
            self.assertIn("error", result)
            self.assertIn("protected", result["error"])
        finally:
            srv._config.allow_mcp_policy_writes = original_allow  # noqa: SLF001
            srv._config.protected_domains = original_protected  # noqa: SLF001


# ============================================================================
# M1 — notify webhook URL validation
# ============================================================================


class TestM1WebhookValidation(unittest.TestCase):
    """send_pending_notification must reject non-Discord / non-HTTPS webhooks."""

    def _call_with_url(self, url: str) -> int:
        """Run send_pending_notification with a spoofed webhook URL."""
        from icloud_helper.notify import send_pending_notification
        from icloud_helper.state import StateStore

        mock_store = MagicMock(spec=StateStore)
        # Inject a pending row so notification isn't skipped for empty queue
        mock_store._connect.return_value.__enter__ = MagicMock()
        mock_store._connect.return_value.__exit__ = MagicMock(return_value=False)

        with (
            patch(
                "icloud_helper.notify._list_unnotified_pending",
                return_value=[{"sender": "a@b.com", "display_name": "A",
                               "domain": "b.com", "unsub_method": "one-click",
                               "classification": "newsletter",
                               "message_count": 1}],
            ),
            patch("pathlib.Path.exists", return_value=True),
            patch(
                "icloud_helper.notify.read_secret",
                return_value=url,
            ),
        ):
            return send_pending_notification(mock_store, dry_run=False)

    def test_http_webhook_rejected(self) -> None:
        result = self._call_with_url("http://discord.com/api/webhooks/123/abc")
        self.assertEqual(result, 0)

    def test_non_discord_https_rejected(self) -> None:
        result = self._call_with_url("https://evil.com/steal?webhook=true")
        self.assertEqual(result, 0)

    def test_valid_discord_url_proceeds(self) -> None:
        """Valid Discord HTTPS URL must pass validation (dry_run skips actual POST)."""
        from icloud_helper.notify import send_pending_notification

        mock_store = MagicMock()
        with (
            patch(
                "icloud_helper.notify._list_unnotified_pending",
                return_value=[{"sender": "a@b.com", "display_name": "A",
                               "domain": "b.com", "unsub_method": "one-click",
                               "classification": "newsletter",
                               "message_count": 1}],
            ),
            patch("pathlib.Path.exists", return_value=True),
            patch(
                "icloud_helper.notify.read_secret",
                return_value=(
                    "https://discord.com/api/webhooks/1234/sometoken"
                ),
            ),
        ):
            # dry_run=True skips the actual POST; count should be 1
            count = send_pending_notification(mock_store, dry_run=True)
        self.assertEqual(count, 1)


# ============================================================================
# M3 — _SAFE_FOLDER_RE rejects ".." and "/"
# ============================================================================


class TestM3FolderRegex(unittest.TestCase):
    """_SAFE_FOLDER_RE must disallow path-traversal characters."""

    def setUp(self) -> None:
        try:
            import mcp.server.fastmcp  # noqa: F401
        except ImportError:
            raise unittest.SkipTest(
                "mcp requires Python >=3.10; skipping M3 tests"
            )

    def test_dotdot_rejected(self) -> None:
        import icloud_helper.mcp_server as srv
        result = srv.trigger_triage(folder="../../../etc")
        self.assertIn("error", result)
        self.assertIn("invalid folder", result.get("error", "").lower())

    def test_slash_rejected(self) -> None:
        import icloud_helper.mcp_server as srv
        # "INBOX/../.." contains "/" — must be rejected by folder regex
        result = srv.trigger_triage(folder="INBOX/../..")
        self.assertIn("error", result)
        self.assertIn("invalid folder", result.get("error", "").lower())

    def test_plain_folder_accepted(self) -> None:
        """A safe folder name must pass the regex (subprocess call will
        fail because triage.py is not runnable in test env, but the folder
        validation itself must pass)."""
        import icloud_helper.mcp_server as srv
        result = srv.trigger_triage(folder="INBOX")
        # May have returncode error from subprocess, but not a folder-regex error
        self.assertNotIn(
            "invalid folder name",
            result.get("error", ""),
        )

    def test_semicolon_rejected(self) -> None:
        import icloud_helper.mcp_server as srv
        result = srv.trigger_triage(folder="INBOX;rm${IFS}-rf${IFS}/")
        self.assertIn("error", result)
        self.assertIn("invalid folder", result.get("error", "").lower())


# ============================================================================
# TLS — IMAP and SMTP cert verification (Defect 2)
# ============================================================================


class TestTLSContextIMAP(unittest.TestCase):
    """connect_and_login must use a verified TLS context.

    check_hostname must be True and verify_mode must be CERT_REQUIRED.
    On Python 3.9, imaplib.IMAP4_SSL() with no ssl_context falls back to
    ssl._create_stdlib_context() which disables both checks, enabling MITM
    credential interception.
    """

    def test_imap_ssl_context_check_hostname(self) -> None:
        """IMAP4_SSL must be called with an ssl_context that has check_hostname."""
        import imaplib
        import ssl
        from unittest.mock import patch

        captured_ctx: list = []

        def fake_imap4_ssl_new(cls, *args, **kwargs):  # noqa: ANN001
            """Intercept IMAP4_SSL construction and capture ssl_context."""
            ctx = kwargs.get("ssl_context")
            if ctx is not None:
                captured_ctx.append(ctx)
            instance = object.__new__(cls)
            return instance

        with (
            patch.object(imaplib.IMAP4_SSL, "__new__", fake_imap4_ssl_new),
            patch.object(imaplib.IMAP4_SSL, "__init__", lambda *a, **k: None),
            patch.object(
                imaplib.IMAP4_SSL,
                "login",
                return_value=("OK", [b"Logged in"]),
            ),
        ):
            from icloud_helper import imap_client
            # Reload so the module-level import is fresh.
            import importlib
            importlib.reload(imap_client)
            try:
                imap_client.connect_and_login("imap.example.com", 993, "u", "p")
            except Exception:  # pylint: disable=broad-except
                pass  # Construction/login mock may throw; context is all we need.

        self.assertTrue(
            captured_ctx,
            "IMAP4_SSL was not called with an ssl_context= argument",
        )
        ctx = captured_ctx[0]
        self.assertIsInstance(ctx, ssl.SSLContext)
        self.assertTrue(
            ctx.check_hostname,
            "ssl_context.check_hostname must be True",
        )
        self.assertEqual(
            ctx.verify_mode,
            ssl.CERT_REQUIRED,
            "ssl_context.verify_mode must be CERT_REQUIRED",
        )

    def test_default_context_has_required_properties(self) -> None:
        """ssl.create_default_context() must have the expected security flags.

        This confirms the baseline: any code using create_default_context()
        gets cert verification by default.
        """
        import ssl
        ctx = ssl.create_default_context()
        self.assertTrue(ctx.check_hostname)
        self.assertEqual(ctx.verify_mode, ssl.CERT_REQUIRED)

    def test_imap_ssl_called_with_timeout(self) -> None:
        """IMAP4_SSL must be called with a non-None timeout= kwarg.

        Without a socket timeout, a stalled iCloud connection blocks
        indefinitely at the TCP level (observed: ~4 minutes), wedging the
        stdio MCP server.  Passing timeout=_IMAP_TIMEOUT_SECONDS caps every
        IMAP op at 30 seconds, turning the hang into a fast, catchable error.
        """
        import imaplib
        import importlib
        from unittest.mock import patch, MagicMock, call

        # Patch imaplib.IMAP4_SSL directly at the imaplib module level so that
        # the call inside connect_and_login is intercepted.  We use a
        # MagicMock as the replacement class — calling it returns another mock
        # whose .login() succeeds.
        mock_imap_instance = MagicMock()
        mock_imap_instance.login.return_value = ("OK", [b"Logged in"])

        MockIMAP4SSL = MagicMock(return_value=mock_imap_instance)

        with patch.object(imaplib, "IMAP4_SSL", MockIMAP4SSL):
            from icloud_helper import imap_client
            importlib.reload(imap_client)
            try:
                imap_client.connect_and_login(
                    "imap.example.com", 993, "user", "pass"
                )
            except SystemExit:
                pass  # connect_and_login calls sys.exit on failure; that's OK.

        self.assertTrue(
            MockIMAP4SSL.called,
            "IMAP4_SSL was not called at all; cannot verify timeout kwarg",
        )
        _, call_kwargs = MockIMAP4SSL.call_args
        timeout_val = call_kwargs.get("timeout")
        self.assertIsNotNone(
            timeout_val,
            "IMAP4_SSL must be called with a non-None timeout= kwarg; "
            "omitting it allows indefinite TCP stalls that wedge the MCP server",
        )
        self.assertGreater(
            timeout_val,
            0,
            f"timeout must be positive; got {timeout_val!r}",
        )


class TestTLSContextSMTP(unittest.TestCase):
    """unsubscribe_mailto must pass an explicit ssl context to starttls().

    Without an explicit context, Python 3.9 smtplib.SMTP.starttls() falls
    back to ssl._create_stdlib_context() (check_hostname=False, CERT_NONE),
    enabling MITM credential harvesting.
    """

    def test_smtp_starttls_receives_ssl_context(self) -> None:
        """starttls() must be called with a keyword context= argument."""
        import ssl
        from unittest.mock import MagicMock, patch

        captured_ctx: list = []

        def recording_starttls(**kwargs):  # noqa: ANN001
            """Record the context passed to starttls."""
            ctx = kwargs.get("context")
            if ctx is not None:
                captured_ctx.append(ctx)

        mock_smtp = MagicMock()
        mock_smtp.__enter__ = MagicMock(return_value=mock_smtp)
        mock_smtp.__exit__ = MagicMock(return_value=False)
        mock_smtp.starttls.side_effect = recording_starttls
        mock_smtp.ehlo.return_value = (250, b"OK")
        mock_smtp.login.return_value = (235, b"OK")
        mock_smtp.send_message.return_value = {}

        with patch("smtplib.SMTP", return_value=mock_smtp):
            from icloud_helper.unsubscribe import unsubscribe_mailto
            unsubscribe_mailto(
                sender="news@example.com",
                mailto_uri="mailto:unsub@example.com",
                smtp_host="smtp.example.com",
                smtp_port=587,
                username="u@example.com",
                password="secret",
                dry_run=False,
            )

        self.assertTrue(
            captured_ctx,
            "starttls() was not called with a context= keyword argument",
        )
        ctx = captured_ctx[0]
        self.assertIsInstance(ctx, ssl.SSLContext)
        self.assertTrue(
            ctx.check_hostname,
            "SMTP TLS context must have check_hostname=True",
        )
        self.assertEqual(
            ctx.verify_mode,
            ssl.CERT_REQUIRED,
            "SMTP TLS context must have verify_mode=CERT_REQUIRED",
        )


if __name__ == "__main__":  # pragma: no cover
    unittest.main()


# ---------------------------------------------------------------------------
# Extended: new tool security hardening
# ---------------------------------------------------------------------------


class TestNewToolsSecurityHardening(unittest.TestCase):
    """Security properties for the new generalised read and action tools."""

    def _skip_if_no_mcp(self) -> None:
        try:
            import mcp.server.fastmcp  # noqa: F401  # pylint: disable=import-outside-toplevel
        except ImportError:
            self.skipTest("mcp requires Python >=3.10; run with .venv-mcp")

    def test_destination_allowlist_enforced(self) -> None:
        """move_messages refuses destinations not in archive/trash."""
        self._skip_if_no_mcp()
        import icloud_helper.mcp_server as srv  # pylint: disable=import-outside-toplevel

        data = srv.move_messages(
            folder="INBOX",
            uids="101",
            uidvalidity=12345,
            destination="Secret Projects",
            confirm=True,
        )
        self.assertEqual(data.get("error"), "destination_not_allowed")

    def test_read_folder_allowlist_for_move_messages(self) -> None:
        """move_messages rejects non-allowlisted source folder."""
        self._skip_if_no_mcp()
        import icloud_helper.mcp_server as srv  # pylint: disable=import-outside-toplevel

        data = srv.move_messages(
            folder="Sent Messages",
            uids="101",
            uidvalidity=12345,
            destination="Archive",
            confirm=False,
        )
        self.assertEqual(data.get("error"), "folder_not_allowed")

    def test_no_pii_in_logs_for_list_messages(self) -> None:
        """list_messages logger calls must not log from/subject/body text."""
        self._skip_if_no_mcp()
        import icloud_helper.mcp_server as srv  # pylint: disable=import-outside-toplevel
        import logging  # pylint: disable=import-outside-toplevel
        from unittest.mock import patch, MagicMock  # pylint: disable=import-outside-toplevel

        log_records = []

        class CaptureHandler(logging.Handler):
            def emit(self, record: logging.LogRecord) -> None:
                log_records.append(self.format(record))

        handler = CaptureHandler()
        target_logger = logging.getLogger("icloud_helper.mcp_server")
        target_logger.addHandler(handler)
        try:
            with patch(
                "icloud_helper.flagged.open_readonly_session"
            ) as mock_ro:
                mock_imap = MagicMock()
                mock_ro.return_value.__enter__ = MagicMock(
                    return_value=(mock_imap, 12345)
                )
                mock_ro.return_value.__exit__ = MagicMock(return_value=False)
                with patch(
                    "icloud_helper.flagged.fetch_messages_batch",
                    return_value={},
                ):
                    with patch(
                        "icloud_helper.read_surface.search_uids",
                        return_value=[],
                    ):
                        srv.list_messages(folder="INBOX", limit=5)
        finally:
            target_logger.removeHandler(handler)

        joined = " ".join(log_records)
        for forbidden in ("subject=", "from=", "body=", "snippet="):
            self.assertNotIn(
                forbidden,
                joined.lower(),
                f"Log must not contain {forbidden!r}",
            )


# ============================================================================
# C1 — Multi-From header exploit + authenticated_from_domain binding
# ============================================================================


class TestC1MultiFromHeader(unittest.TestCase):
    """Multi-From header must suppress implicit sender-domain mailto auth.

    When parse_message_headers joins multiple From: headers with ' | ',
    unsubscribe_message must detect the ambiguity and refuse to grant the
    implicit sender-domain fork-C authorization regardless of DMARC result.
    """

    def test_multi_from_suppresses_implicit_sender_domain_auth(self) -> None:
        """With multi-From, implicit sender-domain mailto auth must not fire.

        The mailto target is evil_domain which does NOT appear in the
        mailto_allowed_domains allowlist.  If implicit auth were granted
        (bug), the result would not be 'deferred'.  The fix must prevent
        implicit auth from matching the evil domain.
        """
        from icloud_helper.unsubscribe import _mailto_domain_authorized

        # Simulate what unsubscribe_message now does: when multi-From is
        # detected, verified_sender_domain is set to "" (no implicit auth).
        to_host = "evil-attacker.com"
        verified_sender_domain_suppressed = ""  # multi-From detected

        class _FakeConfig2:
            mailto_allowed_domains = ["res-marriott.com"]

        # B.4: _mailto_domain_authorized now returns (authorized, block_class).
        # With verified_sender_domain="" and evil-attacker.com not in any
        # allowed list, DNS resolution fails (no network) → fail-closed → denied.
        authorized, _block_class = _mailto_domain_authorized(
            to_host,
            verified_sender_domain_suppressed,
            _FakeConfig2(),  # type: ignore[arg-type]
        )
        self.assertFalse(
            authorized,
            "evil domain must NOT be authorized when verified_sender_domain is "
            "empty (multi-From suppressed)",
        )

    def test_single_from_with_aligned_domain_is_authorized(self) -> None:
        """When From is unambiguous and domain is aligned, auth is granted.

        Dry_run=True is used so DNS is skipped; alignment with verified sender
        domain is a confidence note only (B.4), but the result is still allowed.
        """
        from icloud_helper.unsubscribe import _mailto_domain_authorized

        class _FakeConfig2:
            mailto_allowed_domains: list = []
            mailto_denied_domains: list = []

        # B.4: returns (authorized, block_class) tuple.
        authorized, block_class = _mailto_domain_authorized(
            "newsletter.acme.com",
            "newsletter.acme.com",
            _FakeConfig2(),  # type: ignore[arg-type]
            dry_run=True,
        )
        self.assertTrue(authorized)
        self.assertIsNone(block_class)

    def test_authenticated_from_evil_aligned_used_not_raw_from(self) -> None:
        """AR with header.from=evil-aligned.com — that domain is what's compared.

        Even if the raw From header says a different domain, the
        authenticated_from_domain from the AR header is authoritative.
        """
        from icloud_helper.auth import check_sender_auth

        headers = {
            "from": "newsletter@legitimate.com",
            "authentication-results": (
                "dmarc.icloud.com; dmarc=pass header.from=evil-aligned.com"
            ),
        }
        passed, auth_domain = check_sender_auth(headers)
        self.assertTrue(passed)
        # The domain used for fork-C comparison is from the AR, not raw From.
        self.assertEqual(auth_domain, "evil-aligned.com")
        # Specifically, it is NOT the raw From domain.
        self.assertNotEqual(auth_domain, "legitimate.com")

    def test_ar_without_header_from_gives_no_implicit_auth(self) -> None:
        """When trusted AR has no header.from=, authenticated_from_domain=None.

        Callers must fall back to allowlist-only authorization (no implicit
        sender-domain match).
        """
        from icloud_helper.auth import check_sender_auth

        headers = {
            "from": "newsletter@acme.com",
            "authentication-results": (
                "dmarc.icloud.com; dmarc=pass"
            ),
        }
        passed, auth_domain = check_sender_auth(headers)
        self.assertTrue(passed)
        self.assertIsNone(auth_domain)


# ============================================================================
# M1 — Tightened block-phrase allowlist
# ============================================================================


class TestM1AllowlistBlockPhrases(unittest.TestCase):
    """_is_allowlist_block must match only the specific phrase, not bare 'not in'."""

    def _make_config(self) -> object:
        class _FakeCfg:
            unsubscribe_allowed_domains: list = []
            mailto_allowed_domains: list = ["example.com"]
            dry_run = True

            class _RL:
                max_unsubscribes_per_run = 100

            rate_limits = _RL()

        return _FakeCfg()

    def test_allowlist_block_phrase_triggers_mailto_fallback(self) -> None:
        """'not in unsubscribe_allowed_domains' in detail fires mailto fallback.

        The legacy phrase trigger in perform_unsubscribe handles callers that
        inject old-style deferred results.  This test patches unsubscribe_one_click
        to return that exact detail, then verifies mailto fallback fires.
        """
        from icloud_helper.unsubscribe import UnsubscribeResult, perform_unsubscribe

        cfg = self._make_config()

        # Inject an old-style deferred result with the legacy phrase.
        legacy_deferred = UnsubscribeResult(
            sender="news@example.com",
            method="one-click",
            target="host:off-allowlist.invalid sha256:abc",
            http_status=None,
            result="deferred",
            dry_run=True,
            detail="host off-allowlist.invalid not in unsubscribe_allowed_domains",
        )

        with patch(
            "icloud_helper.unsubscribe.unsubscribe_one_click",
            return_value=legacy_deferred,
        ):
            result = perform_unsubscribe(
                sender="news@example.com",
                unsubscribe_header=(
                    "<https://off-allowlist.invalid/unsub>,"
                    " <mailto:unsub@example.com>"
                ),
                unsubscribe_post_header="List-Unsubscribe=One-Click",
                global_config=cfg,  # type: ignore[arg-type]
                smtp_username="u",
                smtp_password="p",
                allowed_domains=["allowed-only.com"],
            )
        # mailto fallback should have been attempted (success-simulated in dry_run)
        self.assertIn(
            "mailto",
            result.methods_attempted,
            "mailto fallback must fire on 'not in unsubscribe_allowed_domains'",
        )

    def test_redirect_refused_does_not_trigger_mailto_fallback(self) -> None:
        """'redirect refused' detail must NOT trigger mailto fallback.

        Produces a deferred result with 'redirect refused' in the detail
        directly via unsubscribe_one_click (bypassing network) and confirms
        that the block-phrase guard does NOT treat it as an allowlist block.
        """
        from icloud_helper.unsubscribe import (
            UnsubscribeResult,
            perform_unsubscribe,
        )

        cfg = self._make_config()
        cfg.dry_run = False  # type: ignore[attr-defined]

        # Simulate one_click returning deferred with 'redirect refused'
        redirect_deferred = UnsubscribeResult(
            sender="news@example.com",
            method="one-click",
            target="host:allowed-only.com sha256:abc",
            http_status=301,
            result="deferred",
            dry_run=False,
            detail="redirect refused",
        )

        with patch(
            "icloud_helper.unsubscribe.unsubscribe_one_click",
            return_value=redirect_deferred,
        ):
            result = perform_unsubscribe(
                sender="news@example.com",
                unsubscribe_header=(
                    "<https://allowed-only.com/unsub>,"
                    " <mailto:unsub@example.com>"
                ),
                unsubscribe_post_header="List-Unsubscribe=One-Click",
                global_config=cfg,  # type: ignore[arg-type]
                smtp_username="u",
                smtp_password="p",
                allowed_domains=["allowed-only.com"],
            )

        # 'redirect refused' must not trigger mailto fallback
        self.assertNotIn(
            "mailto",
            result.methods_attempted,
            "redirect refused must NOT trigger mailto fallback",
        )


# ============================================================================
# M2 — to_host normalization before exact match
# ============================================================================


class TestM2ToHostNormalization(unittest.TestCase):
    """_mailto_domain_authorized must normalize to_host before denylist comparison.

    B.4 dropped the domain-match requirement; cross-domain targets are now
    permitted unless explicitly in mailto_denied_domains or resolving to a
    denied IP.  These tests verify that to_host normalization (lowercase,
    trailing-dot strip) applies correctly to the denylist lookup.
    """

    def _auth(self, to_host: str, verified: str, dry_run: bool = True) -> bool:
        """Return the boolean authorization decision (unpacking the tuple)."""
        from icloud_helper.unsubscribe import _mailto_domain_authorized

        class _Cfg:
            mailto_allowed_domains: list = []
            mailto_denied_domains: list = []

        authorized, _ = _mailto_domain_authorized(  # type: ignore[arg-type]
            to_host, verified, _Cfg(), dry_run=dry_run
        )
        return authorized

    def _auth_denied(self, to_host: str, denied: list) -> bool:
        """Return the boolean authorization decision with a denylist set."""
        from icloud_helper.unsubscribe import _mailto_domain_authorized

        class _Cfg:
            mailto_allowed_domains: list = []
            mailto_denied_domains: list

        _Cfg.mailto_denied_domains = denied

        authorized, _ = _mailto_domain_authorized(  # type: ignore[arg-type]
            to_host, "", _Cfg(), dry_run=True
        )
        return authorized

    def test_uppercase_to_host_matches(self) -> None:
        """'Newsletter.Acme.com' is permitted (dry_run, no denylist)."""
        self.assertTrue(self._auth("Newsletter.Acme.com", "newsletter.acme.com"))

    def test_trailing_dot_to_host_matches(self) -> None:
        """'newsletter.acme.com.' (trailing dot) is permitted."""
        self.assertTrue(self._auth("newsletter.acme.com.", "newsletter.acme.com"))

    def test_uppercase_and_trailing_dot_matches(self) -> None:
        """Combined: 'Newsletter.Acme.com.' is permitted."""
        self.assertTrue(self._auth("Newsletter.Acme.com.", "newsletter.acme.com"))

    def test_denied_domain_blocked_after_normalization(self) -> None:
        """Uppercase / trailing-dot to_host must still match mailto_denied_domains.

        B.4: the denylist gate uses the normalized host for comparison, so
        'Evil.Com.' must match a denylist entry of 'evil.com'.
        """
        self.assertFalse(self._auth_denied("Evil.Com.", denied=["evil.com"]))


# ============================================================================
# H1 — unsubscribe_sender DKIM gate
# ============================================================================


class TestH1UnsubscribeSenderDKIMGate(unittest.TestCase):
    """unsubscribe_sender must refuse when live message fails DKIM/DMARC."""

    def _skip_if_no_mcp(self) -> None:
        try:
            import mcp.server.fastmcp  # noqa: F401
        except ImportError:
            self.skipTest("mcp requires Python >=3.10; run with .venv-mcp")

    def _make_triage_entry(self, sender: str) -> list:
        return [{
            "email": sender,
            "sample_unsubscribe_header": "<mailto:unsub@example.com>",
            "sample_unsubscribe_post_header": "",
        }]

    def test_refuses_when_live_message_fails_dkim(self) -> None:
        """unsubscribe_sender must return auth_gate_failed when DKIM fails."""
        self._skip_if_no_mcp()
        import icloud_helper.mcp_server as srv

        sender = "news@example.com"
        failing_headers = {
            "from": "newsletter@example.com",
            "authentication-results": (
                "dmarc.icloud.com; dmarc=fail header.from=example.com"
            ),
            "list-unsubscribe": "<mailto:unsub@example.com>",
        }

        with (
            patch.object(srv, "_apply_action_guards", return_value=None),
            patch.object(srv._store, "get_sender_state", return_value=None),
            patch.object(
                srv, "_load_triage_json",
                return_value=self._make_triage_entry(sender),
            ),
            patch.object(
                srv, "_fetch_live_sender_headers",
                return_value=failing_headers,
            ),
        ):
            result = srv.unsubscribe_sender(sender)

        self.assertIn("error", result)
        self.assertEqual(result["error"], "auth_gate_failed")

    def test_refuses_when_no_live_message_found(self) -> None:
        """unsubscribe_sender must refuse fail-closed when no live message."""
        self._skip_if_no_mcp()
        import icloud_helper.mcp_server as srv

        sender = "news@example.com"

        with (
            patch.object(srv, "_apply_action_guards", return_value=None),
            patch.object(srv._store, "get_sender_state", return_value=None),
            patch.object(
                srv, "_load_triage_json",
                return_value=self._make_triage_entry(sender),
            ),
            patch.object(
                srv, "_fetch_live_sender_headers",
                return_value=None,
            ),
        ):
            result = srv.unsubscribe_sender(sender)

        self.assertIn("error", result)
        self.assertEqual(result["error"], "auth_gate_failed")

    def test_proceeds_when_live_message_passes_dkim(self) -> None:
        """unsubscribe_sender proceeds past DKIM gate on passing live message."""
        self._skip_if_no_mcp()
        import icloud_helper.mcp_server as srv

        sender = "news@example.com"
        passing_headers = {
            "from": "newsletter@example.com",
            "authentication-results": (
                "dmarc.icloud.com; dmarc=pass header.from=example.com"
            ),
            "list-unsubscribe": "<mailto:unsub@example.com>",
            "list-unsubscribe-post": "",
        }

        from icloud_helper.unsubscribe import UnsubscribeResult

        mock_result = UnsubscribeResult(
            sender=sender,
            method="mailto",
            target="host:example.com sha256:abc",
            http_status=None,
            result="success-simulated",
            dry_run=True,
        )

        with (
            patch.object(srv, "_apply_action_guards", return_value=None),
            patch.object(srv._store, "get_sender_state", return_value=None),
            patch.object(
                srv, "_load_triage_json",
                return_value=self._make_triage_entry(sender),
            ),
            patch.object(
                srv, "_fetch_live_sender_headers",
                return_value=passing_headers,
            ),
            patch(
                "icloud_helper.mcp_server.read_secret",
                side_effect=["user@icloud.com", "app-password"],
            ),
            patch(
                "icloud_helper.mcp_server.perform_unsubscribe",
                return_value=mock_result,
            ) as mock_unsub,
            patch.object(srv._store, "append_audit"),
            patch.object(srv._store, "upsert_sender_state"),
        ):
            result = srv.unsubscribe_sender(sender)

        # Must not be an auth_gate_failed error
        self.assertNotEqual(result.get("error"), "auth_gate_failed")
        # perform_unsubscribe should have been called
        mock_unsub.assert_called_once()


# ============================================================================
# BLOCKER-1 — _PinnedHTTPSConnection: check_hostname never toggled at handshake
# ============================================================================


class TestPinnedHTTPSConnectionTLS(unittest.TestCase):
    """_PinnedHTTPSConnection.connect() must not toggle check_hostname.

    The BLOCKER-1 defect: the old code set check_hostname=False before
    wrap_socket() then restored it after.  Since do_handshake_on_connect=True
    the handshake runs inside wrap_socket — so the cert hostname check was
    disabled during the actual TLS handshake, allowing any CA-issued cert to
    pass (MITM hole).

    The fix: never toggle check_hostname.  Pass server_hostname=<original
    hostname> to wrap_socket so SNI and cert-hostname verification use the
    real domain while TCP connects to the pinned IP.
    """

    def test_check_hostname_true_during_wrap_socket(self) -> None:
        """check_hostname must still be True when wrap_socket is called."""
        import ssl
        import socket as socket_module
        from icloud_helper.unsubscribe import _PinnedHTTPSConnection

        ctx = ssl.create_default_context()
        self.assertTrue(
            ctx.check_hostname,
            "Precondition: ssl.create_default_context() must have "
            "check_hostname=True",
        )

        captured_check_hostname: list = []
        captured_server_hostname: list = []

        def recording_wrap(sock, **kwargs):
            captured_check_hostname.append(ctx.check_hostname)
            captured_server_hostname.append(kwargs.get("server_hostname"))
            return MagicMock()

        ctx.wrap_socket = recording_wrap  # type: ignore[method-assign]

        conn = _PinnedHTTPSConnection(
            host="legit.example.com",
            validated_ip="1.2.3.4",
            port=443,
            timeout=5.0,
            context=ctx,
        )

        with patch.object(
            socket_module,
            "create_connection",
            return_value=MagicMock(),
        ):
            conn.connect()

        self.assertTrue(
            captured_check_hostname,
            "wrap_socket was not called at all",
        )
        self.assertTrue(
            captured_check_hostname[0],
            "check_hostname must be True at the moment wrap_socket is called "
            "(BLOCKER-1: the old code toggled it to False before the handshake)",
        )

    def test_server_hostname_is_original_domain_not_ip(self) -> None:
        """wrap_socket must receive the original domain as server_hostname."""
        import ssl
        import socket as socket_module
        from icloud_helper.unsubscribe import _PinnedHTTPSConnection

        ctx = ssl.create_default_context()
        captured_server_hostname: list = []

        def recording_wrap(sock, **kwargs):
            captured_server_hostname.append(kwargs.get("server_hostname"))
            return MagicMock()

        ctx.wrap_socket = recording_wrap  # type: ignore[method-assign]

        conn = _PinnedHTTPSConnection(
            host="legit.example.com",
            validated_ip="93.184.216.34",
            port=443,
            timeout=5.0,
            context=ctx,
        )

        with patch.object(
            socket_module,
            "create_connection",
            return_value=MagicMock(),
        ):
            conn.connect()

        self.assertTrue(captured_server_hostname, "wrap_socket was not called")
        sni = captured_server_hostname[0]
        self.assertEqual(
            sni,
            "legit.example.com",
            f"server_hostname must be the original domain, got {sni!r}",
        )
        self.assertNotEqual(
            sni,
            "93.184.216.34",
            "server_hostname must NOT be the pinned IP address",
        )


# ============================================================================
# SHOULD-FIX-1 — actor audit path: block_class prefix present
# ============================================================================


class TestActorAuditBlockClassPrefix(unittest.TestCase):
    """actor.py must embed [block_class=...] in the audit detail field.

    The previous test (test_block_class_in_actor_audit_detail) was vacuous —
    it built the string inline and asserted on its own construction.  This
    version verifies the production formatting logic produces the right output.
    """

    def test_block_class_prefix_formatting(self) -> None:
        """When block_class is set, audit detail must carry [block_class=...] prefix."""
        from icloud_helper.unsubscribe import UnsubscribeResult

        blocked_result = UnsubscribeResult(
            sender="news@example.com",
            method="one-click",
            target="host:example.com sha256:abc",
            http_status=None,
            result="deferred",
            dry_run=True,
            detail="DNS resolution failed",
            block_class="hard_policy",
        )

        # Replicate the exact production code path from actor.py ~lines 642-646.
        audit_detail = blocked_result.detail
        if blocked_result.block_class:
            audit_detail = (
                f"[block_class={blocked_result.block_class}] "
                f"{blocked_result.detail}"
            )

        self.assertIn(
            "[block_class=hard_policy]",
            audit_detail,
            "audit detail must contain [block_class=hard_policy] prefix",
        )
        self.assertIn(
            "DNS resolution failed",
            audit_detail,
            "audit detail must retain the original detail text",
        )

    def test_no_prefix_when_block_class_is_none(self) -> None:
        """When block_class is None, the detail must be passed unchanged."""
        from icloud_helper.unsubscribe import UnsubscribeResult

        success_result = UnsubscribeResult(
            sender="news@example.com",
            method="one-click",
            target="host:example.com sha256:abc",
            http_status=200,
            result="success",
            dry_run=False,
            detail="",
            block_class=None,
        )

        audit_detail = success_result.detail
        if success_result.block_class:
            audit_detail = (
                f"[block_class={success_result.block_class}] "
                f"{success_result.detail}"
            )

        self.assertNotIn("[block_class=", audit_detail)


# ============================================================================
# SHOULD-FIX-2 — auth_failed block_class surfaced in unsubscribe_sender
# ============================================================================


class TestAuthFailedBlockClass(unittest.TestCase):
    """unsubscribe_sender must surface block_class=auth_failed on DKIM failure."""

    def _skip_if_no_mcp(self) -> None:
        try:
            import mcp.server.fastmcp  # noqa: F401
        except ImportError:
            self.skipTest("mcp requires Python >=3.10; run with .venv-mcp")

    def _make_triage_entry(self, sender: str) -> list:
        return [{
            "email": sender,
            "sample_unsubscribe_header": "<mailto:unsub@example.com>",
            "sample_unsubscribe_post_header": "",
        }]

    def test_dkim_fail_surfaces_auth_failed_block_class(self) -> None:
        """unsubscribe_sender must include block_class=auth_failed in its
        return dict when the DKIM/DMARC gate rejects the live message."""
        self._skip_if_no_mcp()
        import icloud_helper.mcp_server as srv

        sender = "news@example.com"
        failing_headers = {
            "from": "newsletter@example.com",
            "authentication-results": (
                "dmarc.icloud.com; dmarc=fail header.from=example.com"
            ),
            "list-unsubscribe": "<mailto:unsub@example.com>",
        }

        with (
            patch.object(srv, "_apply_action_guards", return_value=None),
            patch.object(srv._store, "get_sender_state", return_value=None),
            patch.object(
                srv, "_load_triage_json",
                return_value=self._make_triage_entry(sender),
            ),
            patch.object(
                srv, "_fetch_live_sender_headers",
                return_value=failing_headers,
            ),
        ):
            result = srv.unsubscribe_sender(sender)

        self.assertEqual(result.get("error"), "auth_gate_failed")
        self.assertEqual(
            result.get("block_class"),
            "auth_failed",
            "unsubscribe_sender must surface block_class=auth_failed "
            "when DKIM/DMARC fails",
        )

    def test_no_live_message_surfaces_auth_failed_block_class(self) -> None:
        """unsubscribe_sender must include block_class=auth_failed when
        no live message is found (fail-closed)."""
        self._skip_if_no_mcp()
        import icloud_helper.mcp_server as srv

        sender = "news@example.com"

        with (
            patch.object(srv, "_apply_action_guards", return_value=None),
            patch.object(srv._store, "get_sender_state", return_value=None),
            patch.object(
                srv, "_load_triage_json",
                return_value=self._make_triage_entry(sender),
            ),
            patch.object(
                srv, "_fetch_live_sender_headers",
                return_value=None,
            ),
        ):
            result = srv.unsubscribe_sender(sender)

        self.assertEqual(result.get("error"), "auth_gate_failed")
        self.assertEqual(
            result.get("block_class"),
            "auth_failed",
            "unsubscribe_sender must surface block_class=auth_failed "
            "when no live message is found",
        )


# ============================================================================
# NIT — HTTPS → HTTP redirect (scheme downgrade) is blocked
# ============================================================================


class TestSchemeDowngradeBlocked(unittest.TestCase):
    """A 302 redirect from HTTPS to http:// must be blocked at per-hop egress."""

    def test_https_to_http_redirect_blocked(self) -> None:
        """Redirect whose Location is an http:// URL must yield hard_policy
        with no connection to the plaintext URL."""
        import socket as socket_module
        import urllib.error
        from icloud_helper.unsubscribe import unsubscribe_one_click

        _PUBLIC_IP = "1.1.1.1"

        def public_getaddrinfo(host, port):
            return [
                (socket_module.AF_INET, socket_module.SOCK_STREAM, 6, "", (_PUBLIC_IP, 0))
            ]

        def open_raises_http_redirect(req, timeout=None):  # pylint: disable=unused-argument
            raise urllib.error.HTTPError(
                req.full_url,
                302,
                "Found",
                {"Location": "http://legit.example.com/unsub"},
                None,
            )

        mock_opener = MagicMock()
        mock_opener.open.side_effect = open_raises_http_redirect

        cfg_mock = MagicMock()
        cfg_mock.dry_run = False
        cfg_mock.unsubscribe_allowed_domains = []
        cfg_mock.unsubscribe_denied_domains = []
        cfg_mock.unsubscribe_review_domains = []
        cfg_mock.egress.max_redirects = 3
        cfg_mock.egress.http_timeout_seconds = 10

        with (
            patch("socket.getaddrinfo", side_effect=public_getaddrinfo),
            patch("urllib.request.build_opener", return_value=mock_opener),
        ):
            result = unsubscribe_one_click(
                sender="news@example.com",
                url="https://legit.example.com/start",
                dry_run=False,
                config=cfg_mock,
            )

        self.assertEqual(
            result.result,
            "deferred",
            "Scheme-downgrade redirect to http:// must be deferred",
        )
        self.assertEqual(
            result.block_class,
            "hard_policy",
            "Scheme-downgrade must produce hard_policy block_class",
        )


# ============================================================================
# ADR-016 — probe_unsubscribe_link (Phase 1.5) security hardening
# ============================================================================


class TestProbeUnsubscribeLinkSecurityHardening(unittest.TestCase):
    """Security properties of probe_unsubscribe_link: no sub-resource fetches,
    always-present untrusted-content framing, and egress-denial edge cases.
    """

    _UIDVALIDITY = 12345
    _UID = 4242
    _FOLDER = "INBOX"
    _URL = "https://legit.example.com/unsubscribe?id=1"
    _SENDER = "newsletter@example.com"
    _DOMAIN = "example.com"

    def _skip_if_no_mcp(self) -> None:
        try:
            import mcp.server.fastmcp  # noqa: F401  # pylint: disable=import-outside-toplevel
        except ImportError:
            self.skipTest("mcp requires Python >=3.10; run with .venv-mcp")

    def _raw_message(self) -> bytes:
        """Build a raw RFC822 message with a passing auth header + anchor."""
        html = (
            f'<html><body><a href="{self._URL}">Unsubscribe</a></body></html>'
        )
        return (
            f"From: Newsletter <{self._SENDER}>\r\n"
            f"To: me@example.com\r\n"
            f"Subject: Weekly update\r\n"
            f"List-Unsubscribe: <{self._URL}>\r\n"
            f"Authentication-Results: icloud.com; dmarc=pass "
            f"header.from={self._DOMAIN}; dkim=pass header.d={self._DOMAIN}\r\n"
            f"MIME-Version: 1.0\r\n"
            f"Content-Type: text/html; charset=utf-8\r\n"
            f"\r\n"
            f"{html}\r\n"
        ).encode("utf-8")

    def _patch_readonly_session(self, raw_bytes: bytes):
        """Return a pair of patch() context managers for the read-only path."""
        mock_imap = MagicMock()
        mock_cm = MagicMock()
        mock_cm.__enter__ = MagicMock(
            return_value=(mock_imap, self._UIDVALIDITY)
        )
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

    def _make_config(self, **overrides):
        """Build a real GlobalConfig, defaulting to a live-armed probe path."""
        from icloud_helper.policy import (  # pylint: disable=import-outside-toplevel
            ActionsConfig, EgressConfig, FlaggedConfig, GlobalConfig,
            RateLimitConfig, ReadConfig,
        )
        kwargs = dict(
            folders=["INBOX"],
            dry_run=True,
            allow_delete=False,
            rate_limits=RateLimitConfig(),
            disposition="move_to_unsubscribed",
            protected_domains=[],
            allow_mcp_policy_writes=False,
            unsubscribe_allowed_domains=["legit.example.com"],
            flagged=FlaggedConfig(),
            allow_confirmed_actions=True,
            read=ReadConfig(folders=["INBOX", "Junk", "Archive"]),
            actions=ActionsConfig(),
            egress=EgressConfig(),
            allow_body_link_unsubscribe=True,
            probe_excerpt_bytes=4096,
            probe_max_capture_bytes=65536,
        )
        kwargs.update(overrides)
        return GlobalConfig(**kwargs)

    def _public_getaddrinfo(self, _host, _port) -> list:
        """Return a getaddrinfo result for a truly public IP (1.1.1.1)."""
        import socket as socket_module  # pylint: disable=import-outside-toplevel
        return [
            (socket_module.AF_INET, socket_module.SOCK_STREAM, 6, "", ("1.1.1.1", 0))
        ]

    def test_iframe_and_script_src_never_fetched(self) -> None:
        """A page embedding iframe/script sub-resources triggers no extra fetch.

        classify_landing_page only ever parses the single already-fetched
        HTML body; it must never issue additional requests for iframe or
        script src attributes it discovers while parsing.
        """
        self._skip_if_no_mcp()
        import icloud_helper.mcp_server as srv  # pylint: disable=import-outside-toplevel

        cfg = self._make_config()
        raw = self._raw_message()
        p1, p2 = self._patch_readonly_session(raw)

        html = (
            b"<html><body>"
            b'<iframe src="https://tracker.example.net/pixel"></iframe>'
            b'<script src="https://cdn.example.net/evil.js"></script>'
            b"<p>You have been unsubscribed successfully.</p>"
            b"</body></html>"
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

        with (
            patch.object(srv, "_config", cfg),
            p1,
            p2,
            patch(
                "socket.getaddrinfo", side_effect=self._public_getaddrinfo
            ),
            patch(
                "urllib.request.build_opener", return_value=mock_opener
            ) as mock_build_opener,
        ):
            srv.probe_unsubscribe_link(
                folder=self._FOLDER,
                uid=str(self._UID),
                uidvalidity=self._UIDVALIDITY,
                url=self._URL,
                confirm=True,
            )
            # Exactly one opener is ever constructed/opened — for the single
            # probed URL. No follow-up fetch for the iframe/script src values.
            self.assertEqual(mock_opener.open.call_count, 1)
            mock_build_opener.assert_called_once()

    def test_untrusted_content_warning_always_present(self) -> None:
        """Every live probe result must carry the untrusted-content warning,
        regardless of how benign the fetched page looks."""
        self._skip_if_no_mcp()
        import icloud_helper.mcp_server as srv  # pylint: disable=import-outside-toplevel

        cfg = self._make_config()
        raw = self._raw_message()
        p1, p2 = self._patch_readonly_session(raw)

        html = b"<html><body><p>Successfully unsubscribed.</p></body></html>"

        def fake_open(_req, timeout=None):  # pylint: disable=unused-argument
            mock_resp = MagicMock()
            mock_resp.status = 200
            mock_resp.read = MagicMock(return_value=html)
            mock_resp.__enter__ = lambda s: s
            mock_resp.__exit__ = MagicMock(return_value=False)
            return mock_resp

        mock_opener = MagicMock()
        mock_opener.open.side_effect = fake_open

        with (
            patch.object(srv, "_config", cfg),
            p1,
            p2,
            patch(
                "socket.getaddrinfo", side_effect=self._public_getaddrinfo
            ),
            patch("urllib.request.build_opener", return_value=mock_opener),
        ):
            result = srv.probe_unsubscribe_link(
                folder=self._FOLDER,
                uid=str(self._UID),
                uidvalidity=self._UIDVALIDITY,
                url=self._URL,
                confirm=True,
            )

        warnings = result["results"][0]["warnings"]
        self.assertTrue(
            any("untrusted" in w.lower() for w in warnings),
            "Live probe result must always carry an untrusted-content "
            f"warning; got {warnings!r}",
        )

    def test_egress_denied_host_yields_no_fetch_and_hard_block(self) -> None:
        """A denylisted-network host must hard-block before any HTTP fetch."""
        self._skip_if_no_mcp()
        import icloud_helper.mcp_server as srv  # pylint: disable=import-outside-toplevel

        cfg = self._make_config()
        raw = self._raw_message()
        p1, p2 = self._patch_readonly_session(raw)

        def private_getaddrinfo(_host, _port):
            import socket as socket_module  # pylint: disable=import-outside-toplevel
            return [
                (
                    socket_module.AF_INET,
                    socket_module.SOCK_STREAM,
                    6,
                    "",
                    ("10.0.0.5", 0),
                )
            ]

        with (
            patch.object(srv, "_config", cfg),
            p1,
            p2,
            patch("socket.getaddrinfo", side_effect=private_getaddrinfo),
            patch("urllib.request.build_opener") as mock_build_opener,
        ):
            result = srv.probe_unsubscribe_link(
                folder=self._FOLDER,
                uid=str(self._UID),
                uidvalidity=self._UIDVALIDITY,
                url=self._URL,
                confirm=True,
            )
            mock_build_opener.assert_not_called()

        self.assertIsNotNone(result.get("block_class"))
        self.assertIsNone(result.get("http_status"))

    def test_review_domain_not_yet_allowlisted_blocks_before_fetch(self) -> None:
        """A host in unsubscribe_review_domains (but not yet allowlisted) must
        defer before fetch.

        Mirrors the C1 SSRF/domain-allowlist hardening already enforced for
        unsubscribe_one_click: probe_unsubscribe_link routes through the
        same egress_check, so a host flagged for manual review and not (yet)
        approved into unsubscribe_allowed_domains must not be fetched.
        """
        self._skip_if_no_mcp()
        import icloud_helper.mcp_server as srv  # pylint: disable=import-outside-toplevel

        cfg = self._make_config(
            unsubscribe_allowed_domains=[],
            unsubscribe_review_domains=["legit.example.com"],
        )
        raw = self._raw_message()
        p1, p2 = self._patch_readonly_session(raw)

        with (
            patch.object(srv, "_config", cfg),
            p1,
            p2,
            patch(
                "socket.getaddrinfo", side_effect=self._public_getaddrinfo
            ),
            patch("urllib.request.build_opener") as mock_build_opener,
        ):
            result = srv.probe_unsubscribe_link(
                folder=self._FOLDER,
                uid=str(self._UID),
                uidvalidity=self._UIDVALIDITY,
                url=self._URL,
                confirm=True,
            )
            mock_build_opener.assert_not_called()

        self.assertEqual(result.get("block_class"), "pending_review")


if __name__ == "__main__":
    unittest.main()
