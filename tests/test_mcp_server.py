"""Tests for icloud_helper.mcp_server.

All tests in this file require the mcp package (Python >=3.10 / .venv-mcp).
They are automatically skipped when mcp is not importable, so the standard
pytest run under Python 3.9 passes cleanly.

No real server startup or network calls are made.
"""
from __future__ import annotations

import importlib
import sys
from typing import Set
from unittest.mock import MagicMock, patch

import pytest

# Skip the entire module when mcp is not available (Python 3.9 / main venv).
pytest.importorskip(
    "mcp.server.fastmcp",
    reason="mcp requires Python >=3.10; run with .venv-mcp for these tests",
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_EXPECTED_TOOL_NAMES: Set[str] = {
    "list_bulk_senders",
    "get_triage_report",
    "show_pending_senders",
    "get_audit_log",
    "get_sender_status",
    "unsubscribe_sender",
    "run_cleanup",
    "trigger_triage",
    "approve_sender",
    "list_flagged_messages",
    "get_attachment",
    "save_message_pdf",
    # New generalised read + confirmed-action tools (architecture shift).
    "list_messages",
    "get_message_body",
    "move_messages",
    "trash_messages",
    "unsubscribe_message",
    # T1.2: capabilities tool.
    "get_config",
}


# ---------------------------------------------------------------------------
# Import test
# ---------------------------------------------------------------------------


class TestMcpServerImport:
    """Verify the mcp_server module can be imported."""

    def test_import_succeeds(self) -> None:
        """icloud_helper.mcp_server must be importable without raising."""
        try:
            importlib.import_module("icloud_helper.mcp_server")
        except ImportError as exc:
            pytest.fail(f"import icloud_helper.mcp_server raised ImportError: {exc}")

    def test_mcp_object_exists(self) -> None:
        """The module-level 'mcp' FastMCP instance must exist."""
        import icloud_helper.mcp_server as server

        assert hasattr(server, "mcp"), "mcp attribute missing from mcp_server"

    def test_mcp_object_is_named(self) -> None:
        """The FastMCP instance must be named 'icloud-helper'."""
        import icloud_helper.mcp_server as server

        assert server.mcp.name == "icloud-helper"


# ---------------------------------------------------------------------------
# Tool registration tests
# ---------------------------------------------------------------------------


class TestToolRegistrations:
    """Verify that all expected tools are registered on the mcp server."""

    def test_read_tools_registered(self) -> None:
        """All read tools must be importable as callables from the module."""
        import icloud_helper.mcp_server as server

        read_tool_names = [
            "list_bulk_senders",
            "get_triage_report",
            "show_pending_senders",
            "get_audit_log",
            "get_sender_status",
            "list_flagged_messages",
            "get_attachment",
            "save_message_pdf",
            "list_messages",
            "get_message_body",
        ]
        for name in read_tool_names:
            assert hasattr(server, name), f"Missing read tool: {name}"
            assert callable(getattr(server, name)), f"Not callable: {name}"

    def test_action_tools_registered(self) -> None:
        """Action tools must be importable as callables from the module."""
        import icloud_helper.mcp_server as server

        action_tool_names = [
            "unsubscribe_sender",
            "run_cleanup",
            "trigger_triage",
            "approve_sender",
            "move_messages",
            "trash_messages",
            "unsubscribe_message",
        ]
        for name in action_tool_names:
            assert hasattr(server, name), f"Missing action tool: {name}"
            assert callable(getattr(server, name)), f"Not callable: {name}"

    def test_server_tool_names_via_tool_manager(self) -> None:
        """If FastMCP exposes _tool_manager, all expected tool names must appear."""
        import icloud_helper.mcp_server as server

        mcp = server.mcp
        if not (
            hasattr(mcp, "_tool_manager")
            and hasattr(mcp._tool_manager, "tools")
        ):
            pytest.skip("FastMCP does not expose _tool_manager in this version")

        registered = set(mcp._tool_manager.tools.keys())
        missing = _EXPECTED_TOOL_NAMES - registered
        assert not missing, f"Tools not registered on mcp server: {missing}"


# ---------------------------------------------------------------------------
# Guard tests — safety checks in action tools (no real network calls)
# ---------------------------------------------------------------------------


class TestActionGuards:
    """Smoke-test the safety guards without real network calls."""

    def test_unsubscribe_sender_permits_sender_with_no_policy_entry(self) -> None:
        """unsubscribe_sender must NOT refuse a sender absent from policy.toml
        (default-allow; see ADR-015). It should proceed past the guards and
        fail later only because no triage snapshot mentions the sender."""
        import icloud_helper.mcp_server as server

        result = server.unsubscribe_sender("nobody@notinpolicy.example.com")
        assert result.get("error") != "sender_not_in_allowlist"
        # Guards passed; the deterministic downstream outcome (no triage
        # entry for this made-up address) is a deferred status, not a
        # guard-based refusal.
        assert result.get("status") == "deferred"

    def test_unsubscribe_sender_rejects_sender_marked_keep(self) -> None:
        """unsubscribe_sender must refuse a sender explicitly marked
        action="keep" in policy.toml, even under default-allow."""
        from unittest.mock import MagicMock, patch

        import icloud_helper.mcp_server as server

        mock_policy_entry = MagicMock()
        mock_policy_entry.action = "keep"

        with (
            patch.object(server._store, "get_sender_state", return_value=None),
            patch.object(
                server, "_policy", {"keepme@example.com": mock_policy_entry}
            ),
        ):
            result = server.unsubscribe_sender("keepme@example.com")

        assert result.get("error") == "sender_marked_keep"
        assert result.get("sender") == "keepme@example.com"

    def test_approve_sender_rejects_invalid_action(self) -> None:
        """approve_sender must reject actions other than 'unsubscribe' or 'keep'."""
        import icloud_helper.mcp_server as server

        result = server.approve_sender("valid@example.com", "delete")
        assert "error" in result

    def test_run_cleanup_rejects_negative_limit(self) -> None:
        """run_cleanup must reject a negative limit parameter."""
        import icloud_helper.mcp_server as server

        result = server.run_cleanup(limit=-1)
        assert "error" in result

    def test_validate_folder_rejects_shell_injection_chars(self) -> None:
        """trigger_triage must reject folder names containing shell-injection
        characters (semicolon, pipe, etc.) that are outside the safe-name set."""
        import icloud_helper.mcp_server as server

        # The safe-folder regex allows [A-Za-z0-9_./ -] only.
        # A semicolon is NOT allowed and must be rejected before any subprocess call.
        result = server.trigger_triage(folder="INBOX;rm${IFS}-rf${IFS}/")
        assert "error" in result


class TestApplyActionGuardsDefaultAllow:
    """Unit tests for _apply_action_guards under default-allow (ADR-015).

    Default-allow: a sender with no policy entry is permitted. Only an
    explicit action="keep" policy entry or a protected domain refuses.
    """

    def test_sender_with_no_policy_entry_is_permitted(self) -> None:
        """A sender absent from policy.toml must return None (no refusal)."""
        import icloud_helper.mcp_server as server

        with (
            patch.object(server, "_policy", {}),
            patch.object(server._store, "append_audit") as mock_audit,
        ):
            result = server._apply_action_guards(
                "stranger@example.com", "unknown", "unknown"
            )

        assert result is None
        mock_audit.assert_not_called()

    def test_sender_marked_keep_is_refused(self) -> None:
        """A sender with an explicit action="keep" entry must be refused
        with the sender_marked_keep error and a 'refused' audit entry."""
        import icloud_helper.mcp_server as server

        mock_policy_entry = MagicMock()
        mock_policy_entry.action = "keep"

        with (
            patch.object(
                server, "_policy", {"keepme@example.com": mock_policy_entry}
            ),
            patch.object(server._store, "append_audit") as mock_audit,
        ):
            result = server._apply_action_guards(
                "keepme@example.com", "unknown", "unknown"
            )

        assert result == {
            "error": "sender_marked_keep",
            "detail": "sender is marked keep in policy",
            "sender": "keepme@example.com",
        }
        mock_audit.assert_called_once()
        audit_args = mock_audit.call_args[0]
        assert audit_args[0] == "keepme@example.com"
        assert audit_args[5] == "refused"
        assert audit_args[6] == "sender marked keep"

    def test_sender_with_unsubscribe_entry_is_still_permitted(self) -> None:
        """A sender explicitly marked action="unsubscribe" must still be
        permitted (pre-existing allowlist entries keep working)."""
        import icloud_helper.mcp_server as server

        mock_policy_entry = MagicMock()
        mock_policy_entry.action = "unsubscribe"

        with (
            patch.object(
                server, "_policy", {"news@example.com": mock_policy_entry}
            ),
            patch.object(server._store, "append_audit") as mock_audit,
        ):
            result = server._apply_action_guards(
                "news@example.com", "unknown", "unknown"
            )

        assert result is None
        mock_audit.assert_not_called()

    def test_protected_domain_is_still_refused(self) -> None:
        """Guard 2 (protected_domains) must remain unchanged: a sender with
        no policy entry but a protected domain is still refused."""
        import icloud_helper.mcp_server as server

        with (
            patch.object(server, "_policy", {}),
            patch.object(
                server._config, "protected_domains", ["protected.example.com"]
            ),
            patch.object(server._store, "append_audit") as mock_audit,
        ):
            result = server._apply_action_guards(
                "someone@protected.example.com", "unknown", "unknown"
            )

        assert result == {
            "error": "sender_domain_is_protected",
            "detail": "domain protected.example.com is protected",
            "domain": "protected.example.com",
        }
        mock_audit.assert_called_once()


# ---------------------------------------------------------------------------
# Policy-write correctness tests (I-5)
# ---------------------------------------------------------------------------


class TestAtomicWritePolicy:
    """_atomic_write_policy must handle values containing '[' without corruption."""

    def test_block_with_bracket_in_value_is_removed_cleanly(
        self, tmp_path: Path
    ) -> None:
        """I-5: Removing a block whose value contains '[' must not corrupt TOML.

        The old regex approach used ``[^\\[]*`` which stopped at the first '[' in
        a value (e.g. notes = "category [marketing]"), leaving a stray table
        header and breaking load_policy for all subsequent senders.

        The tomllib+tomli_w approach must produce a valid TOML file with the
        entry updated and all other entries preserved.
        """
        import tomllib as _tomllib

        import icloud_helper.mcp_server as server

        # Policy file with a bracket inside a value — the old regex breaks here.
        policy_path = tmp_path / "policy.toml"
        policy_path.write_text(
            '["bracket@example.com"]\n'
            'action = "keep"\n'
            'notes = "category [marketing]"\n'
            '\n'
            '["other@example.com"]\n'
            'action = "unsubscribe"\n',
            encoding="utf-8",
        )

        # Update the entry that has the bracket value.
        server._atomic_write_policy(
            policy_path, "bracket@example.com", "unsubscribe"
        )

        # The resulting file must be valid TOML.
        raw = policy_path.read_bytes()
        try:
            parsed = _tomllib.loads(raw.decode("utf-8"))
        except _tomllib.TOMLDecodeError as exc:
            pytest.fail(
                f"policy.toml is invalid TOML after _atomic_write_policy: {exc}"
            )

        # The updated entry must have the new action.
        entry = parsed.get("bracket@example.com", {})
        assert entry.get("action") == "unsubscribe", (
            f"Expected action=unsubscribe for bracket@example.com, "
            f"got: {entry!r}"
        )

        # The other entry must be preserved.
        other = parsed.get("other@example.com", {})
        assert other.get("action") == "unsubscribe", (
            f"other@example.com must be preserved, got: {other!r}"
        )

    def test_add_new_entry_produces_valid_toml(self, tmp_path: Path) -> None:
        """Adding a new entry to a non-empty policy must produce valid TOML."""
        import tomllib as _tomllib

        import icloud_helper.mcp_server as server

        policy_path = tmp_path / "policy.toml"
        policy_path.write_text(
            '["existing@example.com"]\naction = "keep"\n',
            encoding="utf-8",
        )

        server._atomic_write_policy(
            policy_path, "new@example.com", "unsubscribe"
        )

        raw = policy_path.read_bytes()
        parsed = _tomllib.loads(raw.decode("utf-8"))
        assert parsed.get("new@example.com", {}).get("action") == "unsubscribe"
        assert parsed.get("existing@example.com", {}).get("action") == "keep"


# ---------------------------------------------------------------------------
# Bug-fix regression tests
# ---------------------------------------------------------------------------


class TestBugFixes:
    """Regression tests for Bug 1 (stale data) and Bug 2 (already-done senders)."""

    def test_list_bulk_senders_excludes_success_senders(self) -> None:
        """list_bulk_senders must exclude senders with unsub_status=success."""
        from unittest.mock import MagicMock, patch

        import icloud_helper.mcp_server as server

        triage_snapshot = {
            "generated_at": "2026-01-01T00:00:00Z",
            "senders": [
                {"email": "done@example.com", "classification": "newsletter"},
                {"email": "pending@example.com", "classification": "newsletter"},
            ],
        }

        def fake_get_state(email: str):
            if email == "done@example.com":
                return {"unsub_status": "success"}
            return None

        with (
            patch.object(server, "_load_triage_json", return_value=triage_snapshot),
            patch.object(server._store, "get_sender_state", side_effect=fake_get_state),
        ):
            result = server.list_bulk_senders()

        assert isinstance(result, dict), f"Expected dict, got {type(result)}"
        senders = result.get("senders", [])
        emails = [s.get("email") for s in senders]
        assert "done@example.com" not in emails, (
            "done@example.com (success) must be excluded"
        )
        assert "pending@example.com" in emails, (
            "pending@example.com must be included"
        )
        assert result.get("freshness_note") == (
            "snapshot may be stale; call trigger_triage to refresh"
        )

    def test_unsubscribe_sender_returns_already_unsubscribed_for_success_state(
        self,
    ) -> None:
        """unsubscribe_sender must return already_unsubscribed without calling
        perform_unsubscribe when the state DB shows unsub_status=success."""
        from unittest.mock import MagicMock, patch

        import icloud_helper.mcp_server as server

        success_state = {
            "unsub_status": "success",
            "last_attempt_at": "2026-06-13T00:00:00+00:00",
        }

        with (
            patch.object(
                server._store, "get_sender_state", return_value=success_state
            ),
            patch.object(server, "perform_unsubscribe") as mock_perform,
        ):
            result = server.unsubscribe_sender("done@example.com")

        assert result.get("status") == "already_unsubscribed", (
            f"Expected already_unsubscribed, got {result}"
        )
        mock_perform.assert_not_called()

    def test_unsubscribe_sender_no_mechanism_returns_distinct_error(self) -> None:
        """When the sender is in policy but the triage snapshot has an empty
        sample_unsubscribe_header, unsubscribe_sender must return deferred with
        the 'no unsubscribe mechanism found' detail from perform_unsubscribe."""
        from unittest.mock import MagicMock, patch

        import icloud_helper.mcp_server as server
        from icloud_helper.unsubscribe import UnsubscribeResult

        # Build a minimal policy entry so _apply_action_guards passes.
        mock_policy_entry = MagicMock()
        mock_policy_entry.action = "unsubscribe"
        mock_policy = {"nomech@example.com": mock_policy_entry}

        triage_snapshot = {
            "generated_at": "2026-01-01T00:00:00Z",
            "senders": [
                {
                    "email": "nomech@example.com",
                    "sample_unsubscribe_header": "",
                    "sample_unsubscribe_post_header": "",
                }
            ],
        }

        deferred_result = UnsubscribeResult(
            sender="nomech@example.com",
            method="none",
            target="",
            http_status=None,
            result="deferred",
            dry_run=True,
            detail="no unsubscribe mechanism found",
        )

        # Provide a passing live-header fixture so the H1 DKIM gate is
        # cleared and the test reaches perform_unsubscribe.
        passing_live_headers = {
            "from": "newsletter@example.com",
            "authentication-results": (
                "dmarc.icloud.com; dmarc=pass header.from=example.com"
            ),
            "list-unsubscribe": "",
            "list-unsubscribe-post": "",
        }

        with (
            patch.object(server._store, "get_sender_state", return_value=None),
            patch.object(server, "_policy", mock_policy),
            patch.object(server, "_load_triage_json", return_value=triage_snapshot),
            patch.object(
                server, "_fetch_live_sender_headers",
                return_value=passing_live_headers,
            ),
            patch.object(
                server, "perform_unsubscribe", return_value=deferred_result
            ) as mock_perform,
            patch.object(server, "read_secret", return_value="fake"),
            patch.object(server._store, "append_audit"),
            patch.object(server._store, "upsert_sender_state"),
        ):
            result = server.unsubscribe_sender("nomech@example.com")

        assert result.get("status") != "already_unsubscribed", (
            "Must not return already_unsubscribed for a deferred sender"
        )
        assert result.get("detail") == "no unsubscribe mechanism found", (
            f"Expected 'no unsubscribe mechanism found' in detail, got: {result}"
        )
        mock_perform.assert_called_once()


# ---------------------------------------------------------------------------
# Flagged-message tool tests (tests 15-21)
# ---------------------------------------------------------------------------


def _make_flagged_session(mock_imap: MagicMock, uidvalidity: int = 12345):
    """Return a context-manager factory that yields (mock_imap, uidvalidity)."""
    from contextlib import contextmanager

    @contextmanager
    def _session(folder, base):  # pylint: disable=unused-argument
        yield mock_imap, uidvalidity

    return _session


class TestListFlaggedMessages:
    """Tests 15, 19-21: list_flagged_messages wrapper."""

    def test_empty_flagged_set(self) -> None:
        """Test 15: empty FLAGGED search returns flagged_total=0, messages=[]."""
        import icloud_helper.mcp_server as server
        from icloud_helper import flagged

        mock_imap = MagicMock()
        with (
            patch.object(
                flagged,
                "open_readonly_session",
                new=_make_flagged_session(mock_imap),
            ),
            patch.object(flagged, "search_flagged_uids", return_value=[]),
            patch.object(flagged, "fetch_messages_batch", return_value={}),
        ):
            result = server.list_flagged_messages()

        assert result["flagged_total"] == 0
        assert result["returned"] == 0
        assert result["messages"] == []

    def test_invalid_folder_rejected(self) -> None:
        """Test 19: invalid folder name returns error before opening session."""
        import icloud_helper.mcp_server as server

        result = server.list_flagged_messages(folder="INBOX;rm -rf /")
        assert "error" in result

    def test_flagged_error_from_session(self) -> None:
        """Test 20: FlaggedError from open_readonly_session returns JSON error."""
        import icloud_helper.mcp_server as server
        from icloud_helper import flagged

        def _raise(*args, **kwargs):
            raise flagged.FlaggedError("connection refused")

        with patch.object(flagged, "open_readonly_session", side_effect=_raise):
            result = server.list_flagged_messages()

        assert "error" in result
        assert result["error"] == "imap session failed"

    def test_limit_clamping_zero_uses_default(self) -> None:
        """Test 21a: limit=0 is replaced by default_limit."""
        import icloud_helper.mcp_server as server
        from icloud_helper import flagged

        mock_imap = MagicMock()
        captured: list = []

        def _fake_batch(imap, uids):
            captured.append(list(uids))
            return {}

        # 30 UIDs available; limit=0 should select default_limit (25).
        all_uids = list(range(1, 31))
        with (
            patch.object(
                flagged,
                "open_readonly_session",
                new=_make_flagged_session(mock_imap),
            ),
            patch.object(
                flagged, "search_flagged_uids", return_value=all_uids
            ),
            patch.object(flagged, "fetch_messages_batch", side_effect=_fake_batch),
        ):
            result = server.list_flagged_messages(limit=0)

        assert result["flagged_total"] == 30
        # default_limit = 25, so at most 25 UIDs should be fetched.
        if captured:
            assert len(captured[0]) <= _config_default_limit()

    def test_limit_clamping_large_uses_max(self) -> None:
        """Test 21b: limit=9999 is clamped to max_limit."""
        import icloud_helper.mcp_server as server
        from icloud_helper import flagged

        mock_imap = MagicMock()
        captured: list = []

        def _fake_batch(imap, uids):
            captured.append(list(uids))
            return {}

        all_uids = list(range(1, 201))  # 200 UIDs
        with (
            patch.object(
                flagged,
                "open_readonly_session",
                new=_make_flagged_session(mock_imap),
            ),
            patch.object(
                flagged, "search_flagged_uids", return_value=all_uids
            ),
            patch.object(flagged, "fetch_messages_batch", side_effect=_fake_batch),
        ):
            result = server.list_flagged_messages(limit=9999)

        assert result["flagged_total"] == 200
        if captured:
            assert len(captured[0]) <= _config_max_limit()

    def test_internaldate_sort_newest_first(self) -> None:
        """SHOULD-FIX 1: Aug message sorts before Jun message (newest-first)."""
        import email.mime.text

        import icloud_helper.mcp_server as server
        from icloud_helper import flagged

        jun_raw = email.mime.text.MIMEText(
            "June body", "plain", "utf-8"
        ).as_bytes()
        aug_raw = email.mime.text.MIMEText(
            "August body", "plain", "utf-8"
        ).as_bytes()

        # UIDs are close together; the fix must sort by parsed datetime, not
        # lexicographically (which would order "Aug" < "Jun" alphabetically).
        raw_messages = {
            100: (jun_raw, "01-Jun-2024 10:00:00 +0000"),
            101: (aug_raw, "01-Aug-2024 10:00:00 +0000"),
        }

        mock_imap = MagicMock()
        with (
            patch.object(
                flagged,
                "open_readonly_session",
                new=_make_flagged_session(mock_imap),
            ),
            patch.object(
                flagged, "search_flagged_uids", return_value=[100, 101]
            ),
            patch.object(
                flagged, "fetch_messages_batch", return_value=raw_messages
            ),
        ):
            result = server.list_flagged_messages()

        messages = result["messages"]
        assert len(messages) == 2
        # August (newer) must be first in the response.
        assert messages[0]["internaldate"] == "01-Aug-2024 10:00:00 +0000"
        assert messages[1]["internaldate"] == "01-Jun-2024 10:00:00 +0000"

    def test_parse_loop_error_returns_message_parse_error(self) -> None:
        """SHOULD-FIX 2: parse loop exception returns JSON error, never escapes."""
        import icloud_helper.mcp_server as server
        from icloud_helper import flagged

        mock_imap = MagicMock()
        raw_messages = {42: (b"dummy-raw", "01-Jan-2024 10:00:00 +0000")}

        with (
            patch.object(
                flagged,
                "open_readonly_session",
                new=_make_flagged_session(mock_imap),
            ),
            patch.object(
                flagged, "search_flagged_uids", return_value=[42]
            ),
            patch.object(
                flagged, "fetch_messages_batch", return_value=raw_messages
            ),
            patch.object(
                flagged,
                "select_body_text",
                side_effect=RuntimeError("parse boom"),
            ),
        ):
            # Must not raise; must return a dict.
            result = server.list_flagged_messages()

        assert result.get("error") == "message_parse_error"


def _config_default_limit() -> int:
    """Return the configured default_limit from the loaded GlobalConfig."""
    import icloud_helper.mcp_server as server

    return server._config.flagged.default_limit  # pylint: disable=protected-access


def _config_max_limit() -> int:
    """Return the configured max_limit from the loaded GlobalConfig."""
    import icloud_helper.mcp_server as server

    return server._config.flagged.max_limit  # pylint: disable=protected-access


class TestGetAttachment:
    """Tests 16-18: get_attachment wrapper."""

    def _raw_pdf_message(self) -> bytes:
        """Build a minimal multipart/mixed message with one PDF attachment."""
        import email.mime.application
        import email.mime.multipart
        import email.mime.text

        msg = email.mime.multipart.MIMEMultipart("mixed")
        msg.attach(email.mime.text.MIMEText("body", "plain", "utf-8"))
        msg.attach(
            email.mime.application.MIMEApplication(b"%PDF-tiny", Name="tiny.pdf")
        )
        return msg.as_bytes()

    def _big_raw_pdf_message(self, size: int) -> bytes:
        """Build a multipart message with an oversized attachment."""
        import email.mime.application
        import email.mime.multipart
        import email.mime.text

        msg = email.mime.multipart.MIMEMultipart("mixed")
        msg.attach(email.mime.text.MIMEText("body", "plain", "utf-8"))
        part = email.mime.application.MIMEApplication(
            b"X" * size, Name="big.pdf"
        )
        part.add_header("Content-Disposition", "attachment", filename="big.pdf")
        msg.attach(part)
        return msg.as_bytes()

    def test_size_cap_rejection(self) -> None:
        """Test 16: attachment exceeding max_attachment_bytes returns error."""
        import icloud_helper.mcp_server as server
        from icloud_helper import flagged

        # Build a raw message whose attachment is bigger than the cap.
        cap = server._config.flagged.max_attachment_bytes  # pylint: disable=protected-access
        raw = self._big_raw_pdf_message(cap + 1)

        mock_imap = MagicMock()
        with (
            patch.object(
                flagged,
                "open_readonly_session",
                new=_make_flagged_session(mock_imap),
            ),
            patch.object(
                flagged,
                "fetch_message",
                return_value=(raw, "Mon, 01 Jan 2024 12:00:00 +0000"),
            ),
        ):
            result = server.get_attachment(uid="42", index=0)

        assert result.get("error") == "attachment_too_large"
        assert "size_bytes" in result
        assert "max_bytes" in result

    def test_uid_not_found(self) -> None:
        """Test 17: fetch_message returning None yields uid_not_found error."""
        import icloud_helper.mcp_server as server
        from icloud_helper import flagged

        mock_imap = MagicMock()
        with (
            patch.object(
                flagged,
                "open_readonly_session",
                new=_make_flagged_session(mock_imap),
            ),
            patch.object(flagged, "fetch_message", return_value=None),
        ):
            result = server.get_attachment(uid="9999", index=0)

        assert result.get("error") == "uid_not_found"

    def test_uidvalidity_mismatch(self) -> None:
        """Test 18: mismatched uidvalidity returns uidvalidity_changed error."""
        import icloud_helper.mcp_server as server
        from icloud_helper import flagged

        mock_imap = MagicMock()
        # Server returns uidvalidity=99999, caller passes 11111.
        with patch.object(
            flagged,
            "open_readonly_session",
            new=_make_flagged_session(mock_imap, uidvalidity=99999),
        ):
            result = server.get_attachment(uid="1", index=0, uidvalidity=11111)

        assert result.get("error") == "uidvalidity_changed"
        assert result.get("expected") == 11111
        assert result.get("actual") == 99999

    def test_flagged_error_from_session(self) -> None:
        """Test 20 (get_attachment path): FlaggedError yields JSON error."""
        import icloud_helper.mcp_server as server
        from icloud_helper import flagged

        def _raise(*args, **kwargs):
            raise flagged.FlaggedError("auth failed")

        with patch.object(flagged, "open_readonly_session", side_effect=_raise):
            result = server.get_attachment(uid="1", index=0)

        assert "error" in result

    def test_parse_failure_returns_structured_json(self) -> None:
        """LOW 4: parse/extract errors return attachment_parse_error dict, never escape."""
        import icloud_helper.mcp_server as server
        from icloud_helper import flagged

        # feed garbage bytes that email.message_from_bytes can parse but
        # extract_attachment will fail on via our patched side_effect.
        garbage_raw = b"garbage bytes that look nothing like a real email"

        mock_imap = MagicMock()
        with (
            patch.object(
                flagged,
                "open_readonly_session",
                new=_make_flagged_session(mock_imap),
            ),
            patch.object(
                flagged,
                "fetch_message",
                return_value=(garbage_raw, "01-Jan-2024 10:00:00 +0000"),
            ),
            patch.object(
                flagged,
                "extract_attachment",
                side_effect=ValueError("simulated parse failure"),
            ),
        ):
            result = server.get_attachment(uid="1", index=0)

        assert result.get("error") == "attachment_parse_error"
        assert "detail" in result
        # detail must be a string (capped at 200 chars).
        assert isinstance(result["detail"], str)
        assert len(result["detail"]) <= 200


# ---------------------------------------------------------------------------
# Folder validation security tests (LOW 2, LOW 3)
# ---------------------------------------------------------------------------


class TestFolderValidation:
    """LOW 2 & LOW 3: folder validation rejects bad names before opening IMAP.

    list_flagged_messages now runs _validate_read_folder (allowlist) before
    _validate_folder (charset check), consistent with all other tools.  Names
    that are both not in the allowlist AND malformed are rejected at the
    allowlist stage, which comes first.  The charset validator still fires for
    names that pass the allowlist but contain illegal characters (tested via
    the _validate_folder unit helper below).
    """

    def test_trailing_newline_rejected(self) -> None:
        """LOW 2: folder name with trailing newline must be rejected."""
        import icloud_helper.mcp_server as server

        # "INBOX\n" is not in the allowlist, so allowlist check fires first.
        result = server.list_flagged_messages(folder="INBOX\n")
        assert "error" in result
        # After the validator-order swap, allowlist check fires first.
        assert result["error"] in ("invalid folder name", "folder_not_allowed")

    def test_empty_folder_rejected(self) -> None:
        """LOW 3: empty folder string must be rejected."""
        import icloud_helper.mcp_server as server

        result = server.list_flagged_messages(folder="")
        assert "error" in result
        assert result["error"] in ("invalid folder name", "folder_not_allowed")

    def test_whitespace_only_folder_rejected(self) -> None:
        """LOW 3: whitespace-only folder string must be rejected."""
        import icloud_helper.mcp_server as server

        result = server.list_flagged_messages(folder="   ")
        assert "error" in result
        assert result["error"] in ("invalid folder name", "folder_not_allowed")

    def test_valid_folder_accepted(self) -> None:
        """Regression: valid folder names still pass validation."""
        import icloud_helper.mcp_server as server

        # _validate_folder returns None for valid names.
        assert server._validate_folder("INBOX") is None  # pylint: disable=protected-access
        assert server._validate_folder("Sent Messages") is None  # pylint: disable=protected-access


# ---------------------------------------------------------------------------
# Body truncation test (MEDIUM 1b)
# ---------------------------------------------------------------------------


class TestBodyTruncation:
    """MEDIUM 1b: list_flagged_messages truncates body_text to max_body_bytes."""

    def test_long_body_is_truncated(self) -> None:
        """body_truncated=True and body_text fits within max_body_bytes."""
        import email.mime.text

        import icloud_helper.mcp_server as server
        from icloud_helper import flagged

        # Create a message with a body larger than 256 KiB.
        big_body = "A" * (300 * 1024)  # 300 KiB ASCII — exceeds 256 KiB cap
        raw = email.mime.text.MIMEText(big_body, "plain", "utf-8").as_bytes()

        mock_imap = MagicMock()
        with (
            patch.object(
                flagged,
                "open_readonly_session",
                new=_make_flagged_session(mock_imap),
            ),
            patch.object(flagged, "search_flagged_uids", return_value=[1]),
            patch.object(
                flagged,
                "fetch_messages_batch",
                return_value={1: (raw, "01-Jan-2024 10:00:00 +0000")},
            ),
        ):
            result = server.list_flagged_messages()

        assert result["returned"] == 1
        msg = result["messages"][0]
        assert msg["body_truncated"] is True
        assert len(msg["body_text"].encode("utf-8")) <= server._config.flagged.max_body_bytes  # pylint: disable=protected-access

    def test_short_body_not_truncated(self) -> None:
        """body_truncated=False when body is within max_body_bytes."""
        import email.mime.text

        import icloud_helper.mcp_server as server
        from icloud_helper import flagged

        short_body = "Hello world"
        raw = email.mime.text.MIMEText(short_body, "plain", "utf-8").as_bytes()

        mock_imap = MagicMock()
        with (
            patch.object(
                flagged,
                "open_readonly_session",
                new=_make_flagged_session(mock_imap),
            ),
            patch.object(flagged, "search_flagged_uids", return_value=[2]),
            patch.object(
                flagged,
                "fetch_messages_batch",
                return_value={2: (raw, "01-Jan-2024 10:00:00 +0000")},
            ),
        ):
            result = server.list_flagged_messages()

        assert result["returned"] == 1
        msg = result["messages"][0]
        assert msg["body_truncated"] is False
        assert "Hello world" in msg["body_text"]


# ---------------------------------------------------------------------------
# T1.2 — TestGetConfig
# ---------------------------------------------------------------------------


class TestGetConfig:
    """get_config must return all required keys with correct values."""

    def test_required_keys_present(self) -> None:
        """All documented keys must be present in the get_config response."""
        import icloud_helper.mcp_server as server

        result = server.get_config()
        required_keys = {
            "read_folders",
            "archive_folder",
            "trash_folder",
            "allow_confirmed_actions",
            "allow_delete",
            "allow_mcp_policy_writes",
            "dry_run",
            "size_caps",
            "unsubscribe_allowed_domains",
            "mailto_allowed_domains",
            "protected_domains",
        }
        missing = required_keys - set(result.keys())
        assert not missing, f"Missing keys in get_config response: {missing}"

    def test_size_caps_subkeys_present(self) -> None:
        """size_caps dict must contain all documented sub-keys."""
        import icloud_helper.mcp_server as server

        result = server.get_config()
        size_caps = result.get("size_caps", {})
        required_caps = {
            "max_snippet_bytes",
            "max_body_bytes",
            "max_attachment_bytes",
            "max_moves_per_run",
            "max_trashes_per_run",
            "max_unsubscribes_per_run",
            "list_default_limit",
            "list_max_limit",
        }
        missing = required_caps - set(size_caps.keys())
        assert not missing, f"Missing size_caps keys: {missing}"

    def test_values_match_loaded_config(self) -> None:
        """Returned values must match the module-level _config singleton."""
        import icloud_helper.mcp_server as server

        cfg = server._config  # pylint: disable=protected-access
        result = server.get_config()

        assert result["read_folders"] == cfg.read.folders
        assert result["archive_folder"] == cfg.actions.archive_folder
        assert result["trash_folder"] == cfg.actions.trash_folder
        assert result["allow_confirmed_actions"] == cfg.allow_confirmed_actions
        assert result["allow_delete"] == cfg.allow_delete
        assert result["dry_run"] == cfg.dry_run
        assert result["protected_domains"] == cfg.protected_domains

    def test_no_secret_like_fields(self) -> None:
        """Response must not contain passwords, tokens, or filesystem paths."""
        import icloud_helper.mcp_server as server

        result = server.get_config()
        forbidden_substrings = [
            "password", "secret", "token", "credential",
            "/Users", "/home", "/opt",
        ]
        result_str = str(result).lower()
        for forbidden in forbidden_substrings:
            assert forbidden.lower() not in result_str, (
                f"get_config must not expose {forbidden!r}"
            )

    def test_unsubscribe_domains_non_empty(self) -> None:
        """unsubscribe_allowed_domains must be non-empty (falls back to module defaults)."""
        import icloud_helper.mcp_server as server

        result = server.get_config()
        # Even when config is [], effective_unsubscribe_domains returns the
        # module defaults which are always non-empty.
        assert isinstance(result["unsubscribe_allowed_domains"], list)
        assert len(result["unsubscribe_allowed_domains"]) > 0, (
            "unsubscribe_allowed_domains must report effective list, not []"
        )


# ---------------------------------------------------------------------------
# T1.0 — Wire-contract test (no-wrapper guarantee)
# ---------------------------------------------------------------------------


class TestWireContract:
    """The mcp.call_tool path must return structuredContent with no 'result' wrapper."""

    def test_no_result_wrapper_in_structured_content(self) -> None:
        """A representative tool's structuredContent must have no top-level 'result' key.

        FastMCP 1.27.2 wraps list returns in {"result": [...]}, but dict
        returns go through without wrapping.  This test locks in the contract.
        """
        import asyncio
        import icloud_helper.mcp_server as server

        async def _call() -> dict:
            result = await server.mcp.call_tool(
                "get_config", {}
            )
            # result is a list of content objects; find the structured one.
            for item in result:
                if hasattr(item, "type") and item.type == "text":
                    import json as _json
                    return _json.loads(item.text)
                if hasattr(item, "data"):
                    return item.data
            return {}

        data = asyncio.run(_call())
        # The no-wrapper guarantee: top-level must NOT be {"result": ...}.
        assert "result" not in data or isinstance(data.get("result"), (str, bool, int, float)), (
            f"Structured content must not have a top-level 'result' list wrapper: {list(data.keys())}"
        )
        # Positive check: get_config returns known keys directly.
        assert "read_folders" in data or "dry_run" in data, (
            f"Expected get_config keys directly in response, got: {list(data.keys())}"
        )


# ---------------------------------------------------------------------------
# FIX 1 — get_triage_report list-format upgrade
# ---------------------------------------------------------------------------


class TestGetTriageReportListFormat:
    """get_triage_report must never return a bare list."""

    def test_list_format_returns_dict_with_senders_key(self) -> None:
        """When triage-latest.json is the old list format, get_triage_report
        must wrap it in a dict with 'senders' and 'freshness_note' keys."""
        from unittest.mock import patch

        import icloud_helper.mcp_server as server

        old_list_data = [
            {"email": "a@example.com", "classification": "newsletter"},
            {"email": "b@example.com", "classification": "newsletter"},
        ]
        with patch.object(server, "_load_triage_json", return_value=old_list_data):
            result = server.get_triage_report()

        assert isinstance(result, dict), (
            f"get_triage_report must return a dict, not {type(result)}"
        )
        assert "senders" in result, (
            f"Result must contain 'senders' key; got keys: {list(result.keys())}"
        )
        assert result["senders"] == old_list_data, (
            "senders value must be the original list"
        )
        assert "freshness_note" in result, (
            "freshness_note must be present on list-format path"
        )

    def test_list_format_no_result_wrapper(self) -> None:
        """A list-format triage file must produce no top-level 'result' key
        when passed through the FastMCP wire path (T1.0 no-wrapper contract)."""
        import asyncio
        from unittest.mock import patch

        import icloud_helper.mcp_server as server
        import json as _json

        old_list_data = [{"email": "x@example.com", "classification": "newsletter"}]

        async def _call() -> dict:
            with patch.object(
                server, "_load_triage_json", return_value=old_list_data
            ):
                items = await server.mcp.call_tool("get_triage_report", {})
            for item in items:
                if hasattr(item, "type") and item.type == "text":
                    return _json.loads(item.text)
                if hasattr(item, "data"):
                    return item.data
            return {}

        data = asyncio.run(_call())
        assert "result" not in data or not isinstance(data.get("result"), list), (
            f"No top-level 'result' list wrapper allowed; got keys: {list(data.keys())}"
        )
        assert "senders" in data, (
            f"Expected 'senders' key directly in response; got: {list(data.keys())}"
        )


# ---------------------------------------------------------------------------
# FIX 3 — get_config reports effective mailto_allowed_domains
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# T2.6 — list_messages view parameter tests
# ---------------------------------------------------------------------------


def _make_raw_message_with_body(body: str = "snippet body") -> bytes:
    """Build a minimal RFC 822 message with a text/plain body."""
    import email.mime.text as _mt
    return _mt.MIMEText(body, "plain", "utf-8").as_bytes()


class TestListMessagesView:
    """T2.6: list_messages view / snippet_bytes / max_total_bytes."""

    def _session_patch(self, mock_imap, uidvalidity: int = 42000):
        """Return a context-manager that yields (mock_imap, uidvalidity)."""
        from contextlib import contextmanager

        @contextmanager
        def _ctx(folder, base):  # pylint: disable=unused-argument
            yield mock_imap, uidvalidity

        return _ctx

    def test_view_metadata_no_snippet_key(self) -> None:
        """view='metadata' must produce entries without snippet/body_source."""
        from unittest.mock import MagicMock, patch

        import icloud_helper.mcp_server as server
        from icloud_helper import flagged
        from icloud_helper import read_surface

        raw = _make_raw_message_with_body("body content")
        mock_imap = MagicMock()
        with (
            patch.object(
                flagged, "open_readonly_session",
                new=self._session_patch(mock_imap),
            ),
            patch.object(read_surface, "search_uids", return_value=[1]),
            patch.object(
                flagged, "fetch_messages_batch",
                return_value={1: (raw, "01-Jan-2024 10:00:00 +0000")},
            ),
        ):
            result = server.list_messages(folder="INBOX", view="metadata")

        assert result.get("returned") == 1
        msg_entry = result["messages"][0]
        # Metadata view must NOT include snippet or body_source.
        assert "snippet" not in msg_entry
        assert "body_source" not in msg_entry
        # Must include metadata fields.
        assert "uid" in msg_entry
        assert "from" in msg_entry
        assert "has_attachments" in msg_entry

    def test_view_full_uses_max_snippet(self) -> None:
        """view='full' uses max_snippet_bytes as the snippet cap."""
        from unittest.mock import MagicMock, patch

        import icloud_helper.mcp_server as server
        from icloud_helper import flagged
        from icloud_helper import read_surface

        # Body larger than default_snippet_bytes (1500) but well under max (8192).
        body = "X" * 5000
        raw = _make_raw_message_with_body(body)
        mock_imap = MagicMock()
        with (
            patch.object(
                flagged, "open_readonly_session",
                new=self._session_patch(mock_imap),
            ),
            patch.object(read_surface, "search_uids", return_value=[1]),
            patch.object(
                flagged, "fetch_messages_batch",
                return_value={1: (raw, "01-Jan-2024 10:00:00 +0000")},
            ),
        ):
            result = server.list_messages(folder="INBOX", view="full")

        assert result.get("returned") == 1
        msg_entry = result["messages"][0]
        snippet = msg_entry.get("snippet", "")
        # Full view should have the body (or at least more than default_snippet).
        assert len(snippet.encode("utf-8")) > server._config.read.default_snippet_bytes  # pylint: disable=protected-access

    def test_view_snippet_default_shorter_than_full(self) -> None:
        """view='snippet' default is shorter than view='full' for large bodies."""
        from unittest.mock import MagicMock, patch

        import icloud_helper.mcp_server as server
        from icloud_helper import flagged
        from icloud_helper import read_surface

        body = "Y" * 6000
        raw = _make_raw_message_with_body(body)
        mock_imap = MagicMock()

        session = self._session_patch(mock_imap)

        def _run(view_name: str) -> dict:
            with (
                patch.object(
                    flagged, "open_readonly_session", new=session,
                ),
                patch.object(read_surface, "search_uids", return_value=[1]),
                patch.object(
                    flagged, "fetch_messages_batch",
                    return_value={1: (raw, "01-Jan-2024 10:00:00 +0000")},
                ),
            ):
                return server.list_messages(folder="INBOX", view=view_name)

        snippet_result = _run("snippet")
        full_result = _run("full")

        snip_len = len(
            (snippet_result["messages"][0].get("snippet", "")).encode("utf-8")
        )
        full_len = len(
            (full_result["messages"][0].get("snippet", "")).encode("utf-8")
        )
        assert snip_len <= full_len

    def test_invalid_view_returns_error(self) -> None:
        """Invalid view value returns error dict."""
        import icloud_helper.mcp_server as server

        result = server.list_messages(folder="INBOX", view="raw")
        assert "error" in result
        assert result["error"] == "invalid_view"

    def test_max_total_bytes_triggers_truncated(self) -> None:
        """max_total_bytes cap causes truncated=True with fewer messages."""
        from unittest.mock import MagicMock, patch

        import icloud_helper.mcp_server as server
        from icloud_helper import flagged
        from icloud_helper import read_surface

        # Use a very small max_total_bytes to force early truncation.
        body = "Z" * 500
        raw = _make_raw_message_with_body(body)
        mock_imap = MagicMock()
        # 5 messages; set max_total_bytes tiny so only first fits.
        raw_messages = {i: (raw, "01-Jan-2024 10:00:00 +0000") for i in range(1, 6)}

        with (
            patch.object(
                flagged, "open_readonly_session",
                new=self._session_patch(mock_imap),
            ),
            patch.object(read_surface, "search_uids", return_value=list(range(1, 6))),
            patch.object(
                flagged, "fetch_messages_batch", return_value=raw_messages,
            ),
        ):
            # 1 byte is too small to fit any message — truncated immediately.
            result = server.list_messages(
                folder="INBOX", view="snippet", max_total_bytes=1
            )

        assert result.get("truncated") is True
        assert result.get("returned", 0) < 5


# ---------------------------------------------------------------------------
# T2.5 — get_attachment new return keys
# ---------------------------------------------------------------------------


class TestGetAttachmentT25:
    """T2.5: get_attachment returns new keys (detected_mime, sha256, etc.)."""

    def _make_pdf_message(self) -> bytes:
        """Build a multipart message with a PDF attachment."""
        import email.mime.application
        import email.mime.multipart
        import email.mime.text

        msg = email.mime.multipart.MIMEMultipart("mixed")
        msg.attach(email.mime.text.MIMEText("body", "plain", "utf-8"))
        msg.attach(
            email.mime.application.MIMEApplication(
                b"%PDF-tiny-fixture", Name="doc.pdf"
            )
        )
        return msg.as_bytes()

    def test_new_keys_present_in_response(self) -> None:
        """get_attachment response includes detected_mime, full_sha256, chunk_sha256."""
        from unittest.mock import MagicMock, patch
        from contextlib import contextmanager

        import icloud_helper.mcp_server as server
        from icloud_helper import flagged

        raw = self._make_pdf_message()
        mock_imap = MagicMock()

        @contextmanager
        def _session(folder, base):  # pylint: disable=unused-argument
            yield mock_imap, 99999

        with (
            patch.object(flagged, "open_readonly_session", new=_session),
            patch.object(
                flagged, "fetch_message",
                return_value=(raw, "01-Jan-2024"),
            ),
        ):
            result = server.get_attachment(uid="1", index=0)

        assert "error" not in result, f"Unexpected error: {result}"
        assert "detected_mime" in result
        assert "full_sha256" in result
        assert "chunk_sha256" in result
        assert "total_size_bytes" in result
        # Default: include_base64=True → data_base64 present.
        assert "data_base64" in result

    def test_include_base64_false_omits_data(self) -> None:
        """include_base64=False removes data_base64 from response."""
        from unittest.mock import MagicMock, patch
        from contextlib import contextmanager

        import icloud_helper.mcp_server as server
        from icloud_helper import flagged

        raw = self._make_pdf_message()
        mock_imap = MagicMock()

        @contextmanager
        def _session(folder, base):  # pylint: disable=unused-argument
            yield mock_imap, 99999

        with (
            patch.object(flagged, "open_readonly_session", new=_session),
            patch.object(
                flagged, "fetch_message",
                return_value=(raw, "01-Jan-2024"),
            ),
        ):
            result = server.get_attachment(
                uid="1", index=0, include_base64=False
            )

        assert "error" not in result, f"Unexpected error: {result}"
        assert "data_base64" not in result

    def test_invalid_save_to_returns_error(self) -> None:
        """save_to with path traversal returns invalid_save_to error without IMAP."""
        import icloud_helper.mcp_server as server

        result = server.get_attachment(
            uid="1", index=0, save_to="../evil.pdf"
        )
        assert result.get("error") == "invalid_save_to"

    def test_invalid_absolute_save_to_returns_error(self) -> None:
        """save_to with absolute path returns invalid_save_to error."""
        import icloud_helper.mcp_server as server

        result = server.get_attachment(
            uid="1", index=0, save_to="/etc/passwd"
        )
        assert result.get("error") == "invalid_save_to"

    def test_negative_offset_returns_error(self) -> None:
        """Negative offset is rejected before IMAP is opened."""
        import icloud_helper.mcp_server as server

        result = server.get_attachment(uid="1", index=0, offset=-1)
        assert result.get("error") == "invalid_offset"


class TestGetConfigMailtoDomains:
    """get_config must report the effective mailto_allowed_domains list."""

    def test_empty_config_returns_module_defaults(self) -> None:
        """When mailto_allowed_domains=[] in config, get_config must return
        the module-level _ALLOWED_MAILTO_DOMAINS, not an empty list."""
        import icloud_helper.mcp_server as server
        from icloud_helper.unsubscribe import effective_mailto_domains

        result = server.get_config()
        reported = result.get("mailto_allowed_domains", [])
        cfg = server._config  # pylint: disable=protected-access
        expected = effective_mailto_domains(cfg)
        assert reported == expected, (
            f"get_config must report effective list {expected}, got {reported}"
        )
        if not cfg.mailto_allowed_domains:
            # Config empty → module defaults must be non-empty.
            assert len(reported) > 0, (
                "mailto_allowed_domains must be non-empty (module defaults)"
            )

    def test_populated_config_returned_as_is(self) -> None:
        """When mailto_allowed_domains is non-empty in config, that exact list
        is returned by get_config."""
        from unittest.mock import patch

        import icloud_helper.mcp_server as server
        import dataclasses

        custom_domains = ["mail.example.com", "unsub.example.org"]
        patched_cfg = dataclasses.replace(
            server._config,  # pylint: disable=protected-access
            mailto_allowed_domains=custom_domains,
        )
        with patch.object(server, "_config", patched_cfg):
            result = server.get_config()

        assert result["mailto_allowed_domains"] == custom_domains, (
            f"Expected {custom_domains}, got {result['mailto_allowed_domains']}"
        )

