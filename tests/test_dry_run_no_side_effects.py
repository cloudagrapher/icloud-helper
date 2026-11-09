"""Regression tests: dry-run must not persist any state to the database.

Verifies that actor.main() with dry_run=True writes zero rows to
processed_messages and zero rows with unsub_status="success" to
sender_state, while still writing audit_log rows with dry_run=1.

Also verifies that dry_run=False (live mode) correctly persists all
state: processed_messages, sender_state with unsub_status="success",
and audit_log with dry_run=0.

No live network connections are made. IMAP and HTTP are fully mocked.
"""
from __future__ import annotations

import email.message
import imaplib
import os
import sys
from pathlib import Path
from typing import Dict, List, Tuple
from unittest.mock import MagicMock, patch

import pytest

# actor.py lives at the project root, not inside a package.
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import actor  # noqa: E402
from icloud_helper.state import StateStore  # noqa: E402
from icloud_helper.unsubscribe import UnsubscribeResult  # noqa: E402


# ---------------------------------------------------------------------------
# Constants for synthetic messages
# ---------------------------------------------------------------------------

_SENDER_A = "newsletter@example.com"
_SENDER_B = "promo@shop.example.com"
_UNSUB_URL = "https://example.com/unsubscribe"

_UID_A = 1001
_UID_B = 1002
_UIDVALIDITY = 12345


# ---------------------------------------------------------------------------
# Helpers: build synthetic IMAP-shaped data
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


def _make_fetch_response(
    uid_raw_pairs: List[Tuple[int, bytes]],
) -> list:
    """Build the IMAP FETCH response list for one or more messages.

    Args:
        uid_raw_pairs: (uid, raw_header_bytes) for each message.

    Returns:
        List matching the shape imaplib returns for a multi-message FETCH.
    """
    result: list = []
    for uid, raw_headers in uid_raw_pairs:
        meta = f"1 (UID {uid} BODY[HEADER] {{{len(raw_headers)}}})"
        result.append((meta.encode("ascii"), raw_headers))
        result.append(b")")
    return result


def _headers_for_sender(sender_email: str) -> bytes:
    """Build one-click-unsubscribable headers for a synthetic newsletter.

    Args:
        sender_email: Sender email address to embed in From header.

    Returns:
        Raw header bytes.
    """
    domain = sender_email.split("@", 1)[-1]
    return _make_raw_headers(
        {
            "From": f"Newsletter <{sender_email}>",
            "List-Unsubscribe": f"<{_UNSUB_URL}>",
            "List-Unsubscribe-Post": "List-Unsubscribe=One-Click",
            "List-Id": f"<list.{domain}>",
            "Subject": "Weekly update",
            "Precedence": "bulk",
            # H1 (CR-security): iCloud stamps this; synthetic messages must
            # include it so the auth gate passes in integration tests.
            "Authentication-Results": (
                f"icloud.com; dmarc=pass header.from={domain}; "
                f"dkim=pass header.d={domain}"
            ),
        }
    )


def _make_mock_imap() -> MagicMock:
    """Return a fully configured mock IMAP4_SSL.

    Handles SEARCH, FETCH, MOVE, COPY, STORE for the two synthetic
    messages from _SENDER_A (UID 1001) and _SENDER_B (UID 1002).

    Returns:
        MagicMock that mimics imaplib.IMAP4_SSL behaviour.
    """
    uid_to_raw: Dict[int, bytes] = {
        _UID_A: _headers_for_sender(_SENDER_A),
        _UID_B: _headers_for_sender(_SENDER_B),
    }
    fetch_resp = _make_fetch_response(
        [(_UID_A, uid_to_raw[_UID_A]), (_UID_B, uid_to_raw[_UID_B])]
    )

    def _uid_side_effect(command: str, *args: object) -> tuple:
        cmd = command.upper()
        if cmd == "SEARCH":
            return ("OK", [f"{_UID_A} {_UID_B}".encode("ascii")])
        if cmd == "FETCH":
            return ("OK", fetch_resp)
        # MOVE / COPY / STORE — disposition path (live mode)
        return ("OK", [None])

    mock_imap = MagicMock(spec=imaplib.IMAP4_SSL)
    mock_imap.select.return_value = ("OK", [b"2"])
    mock_imap.untagged_responses = {"UIDVALIDITY": [str(_UIDVALIDITY).encode()]}
    mock_imap.uid.side_effect = _uid_side_effect
    mock_imap.create.return_value = ("OK", [None])
    return mock_imap


def _make_unsub_result(dry_run: bool) -> UnsubscribeResult:
    """Return a synthetic UnsubscribeResult matching the given dry_run state.

    Args:
        dry_run: Whether to return success-simulated or success.

    Returns:
        UnsubscribeResult with appropriate result string.
    """
    return UnsubscribeResult(
        sender=_SENDER_A,
        method="one-click",
        target=_UNSUB_URL,
        http_status=None if dry_run else 200,
        result="success-simulated" if dry_run else "success",
        dry_run=dry_run,
        detail="",
    )


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def temp_base(tmp_path: Path) -> Path:
    """Temporary directory acting as actor._SCRIPT_DIR.

    Creates the state/ and logs/ sub-directories that actor.main()
    and _append_heartbeat expect to exist (or will create).

    Args:
        tmp_path: pytest-provided temporary directory.

    Returns:
        Path used as the actor's _SCRIPT_DIR.
    """
    (tmp_path / "state").mkdir()
    (tmp_path / "logs").mkdir()
    return tmp_path


@pytest.fixture()
def config_file(tmp_path: Path) -> Path:
    """Path to a temporary config.toml (content written per test).

    Args:
        tmp_path: pytest-provided temporary directory.

    Returns:
        Path object (file not yet written).
    """
    return tmp_path / "config.toml"


@pytest.fixture()
def policy_file(tmp_path: Path) -> Path:
    """Temporary policy.toml with both synthetic senders set to unsubscribe.

    Args:
        tmp_path: pytest-provided temporary directory.

    Returns:
        Path to the written policy.toml.
    """
    p = tmp_path / "policy.toml"
    p.write_text(
        f'["{_SENDER_A}"]\naction = "unsubscribe"\n\n'
        f'["{_SENDER_B}"]\naction = "unsubscribe"\n',
        encoding="utf-8",
    )
    return p


# ---------------------------------------------------------------------------
# Core test runner
# ---------------------------------------------------------------------------


def _run_actor_and_get_store(
    temp_base: Path,
    config_file: Path,
    policy_file: Path,
    dry_run: bool,
) -> StateStore:
    """Write config, run actor.main() with full mocking, return the StateStore.

    The DB is in temp_base/state/mailcleaner.db. The store is opened and
    init_db() is called so the caller can query it immediately.

    Args:
        temp_base: Temporary directory used as actor._SCRIPT_DIR.
        config_file: Path where config.toml will be written.
        policy_file: Path to the pre-written policy.toml.
        dry_run: Whether to run in dry-run or live mode.

    Returns:
        Initialised StateStore pointing at the test DB.
    """
    # Write config with the desired dry_run setting.
    config_file.write_text(
        f"folders = [\"INBOX\"]\n"
        f"dry_run = {str(dry_run).lower()}\n"
        f"allow_delete = false\n"
        f"disposition = \"move_to_unsubscribed\"\n"
        f"protected_domains = []\n"
        f"# discord_webhook_url removed; use secrets/discord_webhook_url\n"
        f"\n[rate_limits]\n"
        f"max_unsubscribes_per_run = 10\n"
        f"request_sleep_seconds = 0.0\n",
        encoding="utf-8",
    )

    argv = [
        "actor.py",
        "--config", str(config_file),
        "--policy", str(policy_file),
        "--folder", "INBOX",
        "--dry-run" if dry_run else "--no-dry-run",
    ]

    with (
        patch("sys.argv", argv),
        patch("actor._SCRIPT_DIR", temp_base),
        patch("actor.connect_and_login", return_value=_make_mock_imap()),
        patch("actor.read_secret", return_value="dummy-credential"),
        patch(
            "actor.perform_unsubscribe",
            return_value=_make_unsub_result(dry_run),
        ),
        patch("actor.send_pending_notification", return_value=0),
    ):
        actor.main()

    db_path = temp_base / "state" / "mailcleaner.db"
    store = StateStore(db_path=db_path)
    store.init_db()
    return store


# ---------------------------------------------------------------------------
# Test class
# ---------------------------------------------------------------------------


class TestDryRunNoSideEffects:
    """dry_run=True must produce zero state mutations; dry_run=False must not."""

    def test_dry_run_leaves_no_state(
        self,
        temp_base: Path,
        config_file: Path,
        policy_file: Path,
    ) -> None:
        """dry_run=True: processed_messages empty, no success sender_state rows.

        The actor must still write audit_log rows (with dry_run=1) as the
        preview record, but must not touch processed_messages or
        sender_state.unsub_status='success'.
        """
        store = _run_actor_and_get_store(
            temp_base, config_file, policy_file, dry_run=True
        )

        with store._connect() as conn:
            pm_count: int = conn.execute(
                "SELECT COUNT(*) FROM processed_messages"
            ).fetchone()[0]
            ss_success: int = conn.execute(
                "SELECT COUNT(*) FROM sender_state"
                " WHERE unsub_status='success'"
            ).fetchone()[0]
            al_dry: int = conn.execute(
                "SELECT COUNT(*) FROM audit_log WHERE dry_run=1"
            ).fetchone()[0]

        assert pm_count == 0, (
            f"dry_run=True must not insert into processed_messages; "
            f"found {pm_count} row(s). "
            "The dry-run guard on mark_processed may be missing."
        )
        assert ss_success == 0, (
            f"dry_run=True must not set sender_state.unsub_status='success'; "
            f"found {ss_success} row(s). "
            "The dry-run guard on upsert_sender_state may be missing."
        )
        assert al_dry > 0, (
            f"dry_run=True must still write audit_log rows with dry_run=1; "
            f"found {al_dry}. "
            "The audit_log write must remain ungated."
        )

    def test_live_run_persists_state(
        self,
        temp_base: Path,
        config_file: Path,
        policy_file: Path,
    ) -> None:
        """dry_run=False: processed_messages and sender_state are written.

        Confirms the live-mode path is unchanged: both messages must appear
        in processed_messages, both senders must have unsub_status='success'
        in sender_state, and audit_log rows must have dry_run=0.
        """
        store = _run_actor_and_get_store(
            temp_base, config_file, policy_file, dry_run=False
        )

        with store._connect() as conn:
            pm_count: int = conn.execute(
                "SELECT COUNT(*) FROM processed_messages"
            ).fetchone()[0]
            ss_success: int = conn.execute(
                "SELECT COUNT(*) FROM sender_state"
                " WHERE unsub_status='success'"
            ).fetchone()[0]
            al_live: int = conn.execute(
                "SELECT COUNT(*) FROM audit_log WHERE dry_run=0"
            ).fetchone()[0]

        assert pm_count > 0, (
            f"dry_run=False must insert into processed_messages; "
            f"found {pm_count} row(s)."
        )
        assert ss_success > 0, (
            f"dry_run=False must set sender_state.unsub_status='success'; "
            f"found {ss_success} row(s)."
        )
        assert al_live > 0, (
            f"dry_run=False must write audit_log rows with dry_run=0; "
            f"found {al_live}."
        )

    def test_upsert_sender_state_not_called_before_disposition(
        self,
        temp_base: Path,
        config_file: Path,
        policy_file: Path,
    ) -> None:
        """I-2: upsert_sender_state must be ordered AFTER apply_disposition.

        Simulates a crash inside apply_disposition by raising an IMAP4.error.
        After the fix (reorder), upsert_sender_state has not yet been called
        when apply_disposition raises, so:
        - processed_messages must be empty (mark_processed never reached)
        - sender_state must have no success rows (upsert_sender_state deferred)

        If upsert_sender_state were called BEFORE apply_disposition (the old
        order), sender_state would already have unsub_status='success' when
        apply_disposition raises, stranding the message on the next run.
        """
        config_file.write_text(
            'folders = ["INBOX"]\n'
            'dry_run = false\n'
            'allow_delete = false\n'
            'disposition = "move_to_unsubscribed"\n'
            'protected_domains = []\n'
            '# discord_webhook_url removed; use secrets/discord_webhook_url\n'
            '\n[rate_limits]\n'
            'max_unsubscribes_per_run = 10\n'
            'request_sleep_seconds = 0.0\n',
            encoding="utf-8",
        )
        argv = [
            "actor.py",
            "--config", str(config_file),
            "--policy", str(policy_file),
            "--no-dry-run",
            "--folder", "INBOX",
        ]
        db_path = temp_base / "state" / "mailcleaner.db"

        # apply_disposition raising simulates a crash between the network
        # action (perform_unsubscribe) and the IMAP move.
        with pytest.raises(Exception):
            with (
                patch("sys.argv", argv),
                patch("actor._SCRIPT_DIR", temp_base),
                patch("actor.connect_and_login", return_value=_make_mock_imap()),
                patch("actor.read_secret", return_value="dummy-credential"),
                patch(
                    "actor.perform_unsubscribe",
                    return_value=_make_unsub_result(dry_run=False),
                ),
                patch(
                    "actor.apply_disposition",
                    side_effect=imaplib.IMAP4.error("simulated IMAP crash"),
                ),
                patch("actor.send_pending_notification", return_value=0),
            ):
                actor.main()

        store = StateStore(db_path=db_path)
        store.init_db()
        with store._connect() as conn:
            pm_count: int = conn.execute(
                "SELECT COUNT(*) FROM processed_messages"
            ).fetchone()[0]
            ss_success: int = conn.execute(
                "SELECT COUNT(*) FROM sender_state"
                " WHERE unsub_status='success'"
            ).fetchone()[0]

        assert pm_count == 0, (
            f"processed_messages must be empty when apply_disposition raises; "
            f"found {pm_count} row(s). mark_processed must not be called "
            "before apply_disposition completes."
        )
        assert ss_success == 0, (
            f"sender_state must have no 'success' rows when apply_disposition "
            f"raises; found {ss_success} row(s). upsert_sender_state must be "
            "ordered AFTER apply_disposition + mark_processed (I-2 fix)."
        )



# ---------------------------------------------------------------------------
# Extended: new MCP tools must not mutate when dry_run=True
# AND allow_confirmed_actions=False
# ---------------------------------------------------------------------------


class TestNewToolsDryRunNoSideEffects:
    """Verify new batch tools do not open rw sessions when gate is off.

    This tests the invariant: dry_run=True AND allow_confirmed_actions=False
    → no new tool mutates IMAP state.
    """

    def test_move_messages_no_rw_session_when_gate_off(self) -> None:
        """move_messages must not open a read-write session when gate is off."""
        pytest.importorskip(
            "mcp.server.fastmcp",
            reason="mcp requires Python >=3.10; run with .venv-mcp",
        )
        import icloud_helper.mcp_server as srv

        from icloud_helper.policy import (
            ActionsConfig, FlaggedConfig, GlobalConfig, RateLimitConfig,
            ReadConfig,
        )
        cfg = GlobalConfig(
            folders=["INBOX"],
            dry_run=True,
            allow_delete=False,
            rate_limits=RateLimitConfig(),
            disposition="move_to_unsubscribed",
            protected_domains=[],
            allow_mcp_policy_writes=False,
            unsubscribe_allowed_domains=[],
            flagged=FlaggedConfig(),
            allow_confirmed_actions=False,
            read=ReadConfig(folders=["INBOX", "Junk", "Archive"]),
            actions=ActionsConfig(),
        )
        with patch.object(srv, "_config", cfg):
            with patch(
                "icloud_helper.actions.open_readwrite_session"
            ) as mock_rw:
                from unittest.mock import MagicMock
                srv.move_messages(
                    folder="INBOX",
                    uids="101",
                    uidvalidity=12345,
                    destination="Archive",
                    confirm=True,
                )
                mock_rw.assert_not_called()

    def test_trash_messages_no_rw_session_when_gate_off(self) -> None:
        """trash_messages must not open a read-write session when gate is off."""
        pytest.importorskip(
            "mcp.server.fastmcp",
            reason="mcp requires Python >=3.10; run with .venv-mcp",
        )
        import icloud_helper.mcp_server as srv

        from icloud_helper.policy import (
            ActionsConfig, FlaggedConfig, GlobalConfig, RateLimitConfig,
            ReadConfig,
        )
        cfg = GlobalConfig(
            folders=["INBOX"],
            dry_run=True,
            allow_delete=True,
            rate_limits=RateLimitConfig(),
            disposition="move_to_unsubscribed",
            protected_domains=[],
            allow_mcp_policy_writes=False,
            unsubscribe_allowed_domains=[],
            flagged=FlaggedConfig(),
            allow_confirmed_actions=False,
            read=ReadConfig(folders=["INBOX", "Junk", "Archive"]),
            actions=ActionsConfig(),
        )
        with patch.object(srv, "_config", cfg):
            with patch(
                "icloud_helper.actions.open_readwrite_session"
            ) as mock_rw:
                from unittest.mock import MagicMock
                srv.trash_messages(
                    folder="INBOX",
                    uids="200",
                    uidvalidity=12345,
                    confirm=True,
                )
                mock_rw.assert_not_called()


# ---------------------------------------------------------------------------
# Extended: probe_unsubscribe_link (ADR-016 Phase 1.5) must not fetch when
# dry_run is effectively active (confirm=False, or allow_body_link_unsubscribe
# is off). find_unsubscribe_links (Phase 1) is inherently read-only and is
# covered separately in test_find_links_tool.py.
# ---------------------------------------------------------------------------


class TestProbeUnsubscribeLinkDryRunNoSideEffects:
    """probe_unsubscribe_link must never fetch when a gate keeps it simulated.

    Mirrors TestNewToolsDryRunNoSideEffects above, adapted for probe's
    read-only IMAP fetch (BODY.PEEK, never Seen) plus its gated live-GET
    dispatch. Both scenarios below must simulate: no urllib.request.build_opener
    call, and no read-write IMAP session (probe never opens one at all).
    """

    _UIDVALIDITY = 12345
    _UID = 4242
    _FOLDER = "INBOX"
    _URL = "https://legit.example.com/unsubscribe?id=1"
    _SENDER = "newsletter@example.com"
    _DOMAIN = "example.com"

    def _raw_message(self) -> bytes:
        """Build a raw RFC822 message with an HTML unsubscribe anchor.

        Returns:
            Raw message bytes suitable as a BODY.PEEK[] fetch result, with
            a passing Authentication-Results header so the auth gate is not
            what causes the simulated result in these tests.
        """
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
        """Return a pair of patch() context managers for the read-only path.

        Args:
            raw_bytes: Raw message bytes fetch_message should return.

        Returns:
            A 2-tuple of patchers (use both with nested `with`).
        """
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

    def _make_config(self, allow_body_link_unsubscribe: bool) -> "GlobalConfig":
        """Build a real GlobalConfig for the gate-off scenarios below.

        Args:
            allow_body_link_unsubscribe: ADR-016 body-link master switch.

        Returns:
            A fully-populated GlobalConfig instance.
        """
        from icloud_helper.policy import (
            ActionsConfig, EgressConfig, FlaggedConfig, GlobalConfig,
            RateLimitConfig, ReadConfig,
        )
        return GlobalConfig(
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
            allow_body_link_unsubscribe=allow_body_link_unsubscribe,
            probe_excerpt_bytes=4096,
            probe_max_capture_bytes=65536,
        )

    def test_confirm_false_never_opens_opener(self) -> None:
        """confirm=False must simulate: no build_opener/urlopen call at all."""
        pytest.importorskip(
            "mcp.server.fastmcp",
            reason="mcp requires Python >=3.10; run with .venv-mcp",
        )
        import icloud_helper.mcp_server as srv

        cfg = self._make_config(allow_body_link_unsubscribe=True)
        raw = self._raw_message()
        p1, p2 = self._patch_readonly_session(raw)
        with (
            patch.object(srv, "_config", cfg),
            p1,
            p2,
            patch("urllib.request.build_opener") as mock_build_opener,
            patch("urllib.request.urlopen") as mock_urlopen,
        ):
            result = srv.probe_unsubscribe_link(
                folder=self._FOLDER,
                uid=str(self._UID),
                uidvalidity=self._UIDVALIDITY,
                url=self._URL,
                confirm=False,
            )
            mock_build_opener.assert_not_called()
            mock_urlopen.assert_not_called()
        assert result["simulated"] is True
        assert result["confirmed"] is False

    def test_master_switch_off_never_opens_opener(self) -> None:
        """allow_body_link_unsubscribe=False must simulate even with confirm=True."""
        pytest.importorskip(
            "mcp.server.fastmcp",
            reason="mcp requires Python >=3.10; run with .venv-mcp",
        )
        import icloud_helper.mcp_server as srv

        cfg = self._make_config(allow_body_link_unsubscribe=False)
        raw = self._raw_message()
        p1, p2 = self._patch_readonly_session(raw)
        with (
            patch.object(srv, "_config", cfg),
            p1,
            p2,
            patch("urllib.request.build_opener") as mock_build_opener,
            patch("urllib.request.urlopen") as mock_urlopen,
        ):
            result = srv.probe_unsubscribe_link(
                folder=self._FOLDER,
                uid=str(self._UID),
                uidvalidity=self._UIDVALIDITY,
                url=self._URL,
                confirm=True,
            )
            mock_build_opener.assert_not_called()
            mock_urlopen.assert_not_called()
        assert result["simulated"] is True
        assert result["blocked_by"] == "allow_body_link_unsubscribe"
