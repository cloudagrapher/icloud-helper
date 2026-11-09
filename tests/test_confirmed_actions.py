"""Tests for the confirmed-action gate in mcp_server.py.

Verifies that move_messages, trash_messages, and unsubscribe_message
correctly gate on allow_confirmed_actions + confirm + uidvalidity, and
that protected-domain / DKIM / cap rules are enforced.

Requires mcp (Python >=3.10 / .venv-mcp).  Tests are skipped under
Python 3.9 where mcp is not available.
"""
from __future__ import annotations

import email
import email.message
import email.mime.text
import imaplib
from contextlib import contextmanager
from pathlib import Path
from typing import Dict, Iterator, Tuple
from unittest.mock import MagicMock, patch

import pytest

pytest.importorskip(
    "mcp.server.fastmcp",
    reason="mcp requires Python >=3.10; run with .venv-mcp",
)

import icloud_helper.actions as _actions
import icloud_helper.mcp_server as srv
from icloud_helper.policy import ActionsConfig, GlobalConfig, ReadConfig


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_global_config(
    allow_confirmed_actions: bool = False,
    allow_delete: bool = False,
    protected_domains=None,
    archive_folder: str = "Archive",
    trash_folder: str = "Deleted Messages",
    read_folders=None,
) -> GlobalConfig:
    """Return a GlobalConfig with the given settings."""
    from icloud_helper.policy import (
        ActionsConfig,
        FlaggedConfig,
        GlobalConfig,
        RateLimitConfig,
        ReadConfig,
    )
    return GlobalConfig(
        folders=["INBOX"],
        dry_run=True,
        allow_delete=allow_delete,
        rate_limits=RateLimitConfig(),
        disposition="move_to_unsubscribed",
        protected_domains=[d.lower() for d in (protected_domains or [])],
        allow_mcp_policy_writes=False,
        unsubscribe_allowed_domains=[],
        flagged=FlaggedConfig(),
        allow_confirmed_actions=allow_confirmed_actions,
        read=ReadConfig(
            folders=read_folders or ["INBOX", "Junk", "Archive"],
            max_snippet_bytes=8192,
        ),
        actions=ActionsConfig(
            archive_folder=archive_folder,
            trash_folder=trash_folder,
            max_moves_per_run=50,
            max_trashes_per_run=50,
        ),
    )


def _make_raw_message(
    from_header: str = "news@example.com",
    list_unsub: str = "<https://example.com/unsub>",
    list_unsub_post: str = "List-Unsubscribe=One-Click",
    auth_results: str = (
        "dmarc.icloud.com; dmarc=pass dkim=pass"
    ),
) -> bytes:
    """Build raw RFC 2822 message bytes for mocking fetch_message."""
    msg = email.message.Message()
    msg["From"] = from_header
    msg["Subject"] = "Test"
    msg["List-Unsubscribe"] = list_unsub
    if list_unsub_post:
        msg["List-Unsubscribe-Post"] = list_unsub_post
    if auth_results:
        msg["Authentication-Results"] = auth_results
    msg.set_payload("Body text")
    return msg.as_bytes()


@contextmanager
def _mock_readonly_session(
    uidvalidity: int = 12345,
    raw_message: bytes = b"",
) -> Iterator[Tuple[MagicMock, int]]:
    """Context manager that yields (mock_imap, uidvalidity)."""
    imap = MagicMock(spec=imaplib.IMAP4_SSL)
    imap.uid.return_value = ("OK", [b""])
    yield imap, uidvalidity


# ---------------------------------------------------------------------------
# Tests: allow_confirmed_actions=False → simulate
# ---------------------------------------------------------------------------


class TestConfirmedGateOff:
    """When allow_confirmed_actions=False, all action tools must simulate."""

    def test_move_messages_simulates_when_gate_off(self) -> None:
        """move_messages returns simulated when allow_confirmed_actions=false."""
        cfg = _make_global_config(allow_confirmed_actions=False)
        with patch.object(srv, "_config", cfg):
            data = srv.move_messages(
                folder="INBOX",
                uids="101,102",
                uidvalidity=12345,
                destination="Archive",
                confirm=True,  # even with confirm=True, gate is off
            )
        assert data.get("confirmed") is False
        assert data.get("simulated") is True
        # No rw session should have been opened.
        for r in data.get("results", []):
            assert r["status"] == "simulated"

    def test_trash_messages_simulates_when_gate_off(self) -> None:
        """trash_messages returns simulated when allow_confirmed_actions=false."""
        cfg = _make_global_config(
            allow_confirmed_actions=False, allow_delete=True
        )
        with patch.object(srv, "_config", cfg):
            data = srv.trash_messages(
                folder="INBOX",
                uids="200",
                uidvalidity=12345,
                confirm=True,
            )
        assert data.get("confirmed") is False
        assert data.get("simulated") is True

    def test_move_messages_simulates_when_confirm_false(self) -> None:
        """move_messages simulates when confirm=False regardless of gate."""
        cfg = _make_global_config(allow_confirmed_actions=True)
        with patch.object(srv, "_config", cfg):
            with patch(
                "icloud_helper.flagged.open_readonly_session"
            ) as mock_ro:
                mock_ro.return_value.__enter__ = MagicMock(
                    return_value=(MagicMock(), 12345)
                )
                mock_ro.return_value.__exit__ = MagicMock(return_value=False)
                data = srv.move_messages(
                    folder="INBOX",
                    uids="101",
                    uidvalidity=12345,
                    destination="Archive",
                    confirm=False,
                )
        assert data.get("confirmed") is False
        assert data.get("simulated") is True


# ---------------------------------------------------------------------------
# Tests: both gates true + valid uidvalidity → live
# ---------------------------------------------------------------------------


class TestConfirmedGateOn:
    """When both gates pass, action is live and audit row is written."""

    def test_move_messages_live_when_confirmed(self) -> None:
        """move_messages executes live and writes an audit row."""
        cfg = _make_global_config(allow_confirmed_actions=True)

        mock_rw_imap = MagicMock(spec=imaplib.IMAP4_SSL)
        mock_rw_imap.uid.return_value = ("OK", [b""])
        mock_rw_imap.create.return_value = ("OK", [b""])

        audit_calls = []

        def _fake_audit(**kwargs) -> None:
            audit_calls.append(kwargs)

        with patch.object(srv, "_config", cfg):
            with patch(
                "icloud_helper.flagged.open_readonly_session"
            ) as mock_ro:
                mock_ro.return_value.__enter__ = MagicMock(
                    return_value=(MagicMock(), 12345)
                )
                mock_ro.return_value.__exit__ = MagicMock(return_value=False)

                with patch(
                    "icloud_helper.actions.open_readwrite_session"
                ) as mock_rw:
                    mock_rw.return_value.__enter__ = MagicMock(
                        return_value=(mock_rw_imap, 12345)
                    )
                    mock_rw.return_value.__exit__ = MagicMock(
                        return_value=False
                    )

                    with patch.object(
                        srv._store, "append_audit"
                    ) as mock_audit:
                        data = srv.move_messages(
                            folder="INBOX",
                            uids="101",
                            uidvalidity=12345,
                            destination="Archive",
                            confirm=True,
                        )
                        assert mock_audit.called, "append_audit must be called"

        assert data.get("confirmed") is True
        assert data.get("simulated") is False
        assert len(data["results"]) == 1
        assert data["results"][0]["status"] == "done"


# ---------------------------------------------------------------------------
# Tests: allow_delete=False → trash simulates/skips
# ---------------------------------------------------------------------------


class TestAllowDeleteGate:
    """When allow_delete=False, trash_messages always simulates."""

    def test_trash_simulates_when_allow_delete_false(self) -> None:
        """trash_messages simulates when allow_delete=false."""
        cfg = _make_global_config(
            allow_confirmed_actions=True, allow_delete=False
        )
        with patch.object(srv, "_config", cfg):
            data = srv.trash_messages(
                folder="INBOX",
                uids="300,301",
                uidvalidity=12345,
                confirm=True,
            )
        assert data.get("confirmed") is False
        assert data.get("simulated") is True
        assert data.get("blocked_by") == "allow_delete"
        for r in data.get("results", []):
            assert r["status"] == "simulated"


# ---------------------------------------------------------------------------
# Tests: protected domain → unsubscribe_message hard-blocked
# ---------------------------------------------------------------------------


class TestProtectedDomainBlock:
    """Protected-domain messages must be refused by unsubscribe_message."""

    def test_protected_domain_refused(self) -> None:
        """unsubscribe_message hard-blocks protected domain senders."""
        cfg = _make_global_config(
            allow_confirmed_actions=True,
            protected_domains=["info6.citi.com"],
        )
        raw = _make_raw_message(from_header="alerts@info6.citi.com")

        with patch.object(srv, "_config", cfg):
            with patch(
                "icloud_helper.flagged.open_readonly_session"
            ) as mock_ro:
                mock_imap = MagicMock()
                mock_ro.return_value.__enter__ = MagicMock(
                    return_value=(mock_imap, 12345)
                )
                mock_ro.return_value.__exit__ = MagicMock(return_value=False)

                with patch(
                    "icloud_helper.flagged.fetch_message",
                    return_value=(raw, "15-Jun-2025 10:00:00 +0000"),
                ):
                    data = srv.unsubscribe_message(
                        folder="INBOX",
                        uid="42",
                        uidvalidity=12345,
                        confirm=True,
                    )

        assert data.get("error") in ("protected_domain", "auth_gate_failed"), (
            f"Expected protected_domain or auth_gate_failed, got: {data}"
        )


# ---------------------------------------------------------------------------
# Tests: DKIM fail → unsubscribe_message refused
# ---------------------------------------------------------------------------


class TestDkimGate:
    """DKIM/DMARC failure must refuse unsubscribe_message (fail-closed)."""

    def test_dkim_fail_refused(self) -> None:
        """unsubscribe_message refused when DKIM/DMARC gate fails."""
        cfg = _make_global_config(allow_confirmed_actions=True)
        raw = _make_raw_message(
            from_header="news@example.com",
            auth_results="",  # no auth results → DMARC gate fails
        )

        with patch.object(srv, "_config", cfg):
            with patch(
                "icloud_helper.flagged.open_readonly_session"
            ) as mock_ro:
                mock_imap = MagicMock()
                mock_ro.return_value.__enter__ = MagicMock(
                    return_value=(mock_imap, 12345)
                )
                mock_ro.return_value.__exit__ = MagicMock(return_value=False)

                with patch(
                    "icloud_helper.flagged.fetch_message",
                    return_value=(raw, "15-Jun-2025 10:00:00 +0000"),
                ):
                    data = srv.unsubscribe_message(
                        folder="INBOX",
                        uid="55",
                        uidvalidity=12345,
                        confirm=True,
                    )

        assert data.get("error") == "auth_gate_failed"


# ---------------------------------------------------------------------------
# Tests: per-run caps enforced
# ---------------------------------------------------------------------------


class TestPerRunCaps:
    """move_messages and trash_messages enforce per-run caps."""

    def test_move_cap_stops_after_max(self) -> None:
        """move_messages stops after max_moves_per_run."""
        from icloud_helper.policy import ActionsConfig, GlobalConfig

        cfg = _make_global_config(allow_confirmed_actions=True)
        # Patch max_moves_per_run to 2.
        cfg.actions.max_moves_per_run = 2

        mock_rw_imap = MagicMock(spec=imaplib.IMAP4_SSL)
        mock_rw_imap.uid.return_value = ("OK", [b""])
        mock_rw_imap.create.return_value = ("OK", [b""])

        with patch.object(srv, "_config", cfg):
            with patch(
                "icloud_helper.flagged.open_readonly_session"
            ) as mock_ro:
                mock_ro.return_value.__enter__ = MagicMock(
                    return_value=(MagicMock(), 12345)
                )
                mock_ro.return_value.__exit__ = MagicMock(return_value=False)

                with patch(
                    "icloud_helper.actions.open_readwrite_session"
                ) as mock_rw:
                    mock_rw.return_value.__enter__ = MagicMock(
                        return_value=(mock_rw_imap, 12345)
                    )
                    mock_rw.return_value.__exit__ = MagicMock(
                        return_value=False
                    )

                    with patch.object(srv._store, "append_audit"):
                        data = srv.move_messages(
                            folder="INBOX",
                            uids="1,2,3,4",  # 4 UIDs
                            uidvalidity=12345,
                            destination="Archive",
                            confirm=True,
                        )

        results = data["results"]
        assert len(results) == 4
        done = [r for r in results if r["status"] == "done"]
        skipped = [r for r in results if r["status"] == "skipped"]
        assert len(done) == 2
        assert len(skipped) == 2


# ---------------------------------------------------------------------------
# Tests: batch partial failure reported per-uid
# ---------------------------------------------------------------------------


class TestPartialFailure:
    """Batch results report per-uid success/failure independently."""

    def test_partial_failure_per_uid(self) -> None:
        """Failed UID has status='error'; others have status='done'."""
        cfg = _make_global_config(allow_confirmed_actions=True)

        call_count = [0]

        def _uid_side(command: str, *args: object) -> tuple:
            call_count[0] += 1
            if command.upper() == "MOVE":
                # Fail for uid 200, succeed for others.
                if "200" in str(args):
                    raise imaplib.IMAP4.error("forced failure")
                return ("OK", [b""])
            if command.upper() == "COPY":
                return ("FAIL", [b""])  # fallback also fails for uid 200
            return ("OK", [b""])

        mock_rw_imap = MagicMock(spec=imaplib.IMAP4_SSL)
        mock_rw_imap.uid.side_effect = _uid_side
        mock_rw_imap.create.return_value = ("OK", [b""])

        with patch.object(srv, "_config", cfg):
            with patch(
                "icloud_helper.flagged.open_readonly_session"
            ) as mock_ro:
                mock_ro.return_value.__enter__ = MagicMock(
                    return_value=(MagicMock(), 12345)
                )
                mock_ro.return_value.__exit__ = MagicMock(return_value=False)

                with patch(
                    "icloud_helper.actions.open_readwrite_session"
                ) as mock_rw:
                    mock_rw.return_value.__enter__ = MagicMock(
                        return_value=(mock_rw_imap, 12345)
                    )
                    mock_rw.return_value.__exit__ = MagicMock(
                        return_value=False
                    )

                    with patch.object(srv._store, "append_audit"):
                        data = srv.move_messages(
                            folder="INBOX",
                            uids="199,200,201",
                            uidvalidity=12345,
                            destination="Archive",
                            confirm=True,
                        )

        results_by_uid = {r["uid"]: r for r in data["results"]}
        # uid 200 should fail; 199 and 201 should succeed
        assert results_by_uid["200"]["status"] == "error"
        assert results_by_uid["199"]["status"] == "done"
        assert results_by_uid["201"]["status"] == "done"


# ---------------------------------------------------------------------------
# Tests: BLOCKER — unsubscribe_message cred failure returns JSON, no SystemExit
# ---------------------------------------------------------------------------


class TestUnsubscribeMessageCredFailure:
    """unsubscribe_message must return a JSON error if creds are unreadable."""

    def test_missing_creds_returns_json_error_not_systemexit(self) -> None:
        """read_secret raising must not propagate SystemExit out of the tool."""
        cfg = _make_global_config(allow_confirmed_actions=True)
        raw = _make_raw_message(
            from_header="news@example.com",
            auth_results="dmarc.icloud.com; dmarc=pass dkim=pass",
        )

        with patch.object(srv, "_config", cfg):
            with patch(
                "icloud_helper.flagged.open_readonly_session"
            ) as mock_ro:
                mock_ro.return_value.__enter__ = MagicMock(
                    return_value=(MagicMock(), 12345)
                )
                mock_ro.return_value.__exit__ = MagicMock(return_value=False)

                with patch(
                    "icloud_helper.flagged.fetch_message",
                    return_value=(raw, "15-Jun-2025 10:00:00 +0000"),
                ):
                    with patch(
                        "icloud_helper.mcp_server.read_secret",
                        side_effect=Exception("no such file"),
                    ):
                        # Must not raise — must return a dict.
                        data = srv.unsubscribe_message(
                            folder="INBOX",
                            uid="77",
                            uidvalidity=12345,
                            confirm=True,
                        )

        # Verify it returned a dict with an error key rather than exploding.
        assert "error" in data, f"Expected error key in: {data}"
        assert "smtp" in data["error"].lower() or "credential" in data["error"].lower() or (
            "could not" in data["error"].lower()
        ), f"Unexpected error message: {data['error']}"


# ---------------------------------------------------------------------------
# Tests: SHOULD-FIX 1 — failed moves do not consume the cap
# ---------------------------------------------------------------------------


class TestFailedMoveDoesNotConsumeCap:
    """A failed move must not count toward moves_done cap."""

    def test_failed_move_does_not_consume_cap(self) -> None:
        """Batch where first move fails still allows subsequent moves up to cap.

        With max_moves_per_run=2 and three UIDs where UID 101 fails, UIDs 102
        and 103 must both succeed (cap is not consumed by the failure).
        """
        cfg = _make_global_config(allow_confirmed_actions=True)
        cfg.actions.max_moves_per_run = 2

        def _uid_side(command: str, *args: object) -> tuple:
            if command.upper() == "MOVE":
                if "101" in str(args):
                    raise imaplib.IMAP4.error("forced failure for 101")
                return ("OK", [b""])
            if command.upper() == "COPY":
                # COPY fallback also fails for uid 101.
                if "101" in str(args):
                    return ("FAIL", [b""])
                return ("OK", [b""])
            return ("OK", [b""])

        mock_rw_imap = MagicMock(spec=imaplib.IMAP4_SSL)
        mock_rw_imap.uid.side_effect = _uid_side
        mock_rw_imap.create.return_value = ("OK", [b""])

        with patch.object(srv, "_config", cfg):
            with patch(
                "icloud_helper.flagged.open_readonly_session"
            ) as mock_ro:
                mock_ro.return_value.__enter__ = MagicMock(
                    return_value=(MagicMock(), 12345)
                )
                mock_ro.return_value.__exit__ = MagicMock(return_value=False)

                with patch(
                    "icloud_helper.actions.open_readwrite_session"
                ) as mock_rw:
                    mock_rw.return_value.__enter__ = MagicMock(
                        return_value=(mock_rw_imap, 12345)
                    )
                    mock_rw.return_value.__exit__ = MagicMock(return_value=False)

                    with patch.object(srv._store, "append_audit"):
                        data = srv.move_messages(
                            folder="INBOX",
                            uids="101,102,103",
                            uidvalidity=12345,
                            destination="Archive",
                            confirm=True,
                        )

        results_by_uid = {r["uid"]: r for r in data["results"]}
        # 101 fails; 102 and 103 both fit within the cap because 101 didn't
        # consume it.
        assert results_by_uid["101"]["status"] == "error"
        assert results_by_uid["102"]["status"] == "done"
        assert results_by_uid["103"]["status"] == "done"
        skipped = [r for r in data["results"] if r["status"] == "skipped"]
        assert not skipped, f"No UIDs should be skipped; got: {skipped}"


# ---------------------------------------------------------------------------
# Tests: SHOULD-FIX 2 — list_flagged_messages rejects non-allowlisted folder
# ---------------------------------------------------------------------------


class TestListFlaggedReadFolderAllowlist:
    """list_flagged_messages must reject folders not in the read allowlist."""

    def test_non_allowlisted_folder_rejected(self) -> None:
        """list_flagged_messages rejects 'Sent Messages' (not in allowlist)."""
        cfg = _make_global_config(
            read_folders=["INBOX", "Junk", "Archive"],
        )
        with patch.object(srv, "_config", cfg):
            data = srv.list_flagged_messages(folder="Sent Messages")

        assert "error" in data, f"Expected error key in: {data}"
        assert data["error"] == "folder_not_allowed", (
            f"Expected folder_not_allowed, got: {data}"
        )


# ---------------------------------------------------------------------------
# BLOCKER regression tests — SystemExit must never escape action tools
# ---------------------------------------------------------------------------


class TestSystemExitMoveMessages:
    """SystemExit from open_readwrite_session must not escape move_messages."""

    def test_systemexit_during_session_open_returns_json_error(self) -> None:
        """move_messages returns dict error when open_readwrite_session raises SystemExit."""
        cfg = _make_global_config(allow_confirmed_actions=True)

        with patch.object(srv, "_config", cfg):
            with patch(
                "icloud_helper.flagged.open_readonly_session"
            ) as mock_ro:
                mock_ro.return_value.__enter__ = MagicMock(
                    return_value=(MagicMock(), 12345)
                )
                mock_ro.return_value.__exit__ = MagicMock(return_value=False)

                with patch.object(
                    _actions,
                    "open_readwrite_session",
                    side_effect=SystemExit(1),
                ):
                    data = srv.move_messages(
                        folder="INBOX",
                        uids="101,102",
                        uidvalidity=12345,
                        destination="Archive",
                        confirm=True,
                    )

        assert "error" in data, f"Expected error key in: {data}"

    def test_systemexit_in_open_readwrite_session_internals_returns_json(
        self,
    ) -> None:
        """SystemExit from read_secret inside open_readwrite_session returns dict."""
        cfg = _make_global_config(allow_confirmed_actions=True)

        with patch.object(srv, "_config", cfg):
            with patch(
                "icloud_helper.flagged.open_readonly_session"
            ) as mock_ro:
                mock_ro.return_value.__enter__ = MagicMock(
                    return_value=(MagicMock(), 12345)
                )
                mock_ro.return_value.__exit__ = MagicMock(return_value=False)

                with patch(
                    "icloud_helper.actions.read_secret",
                    side_effect=SystemExit(1),
                ):
                    data = srv.move_messages(
                        folder="INBOX",
                        uids="500",
                        uidvalidity=12345,
                        destination="Archive",
                        confirm=True,
                    )

        assert "error" in data, f"Expected error key in: {data}"
        assert data["error"] in ("imap_session_failed", "imap_error"), (
            f"Unexpected error: {data['error']}"
        )


class TestSystemExitTrashMessages:
    """SystemExit from open_readwrite_session must not escape trash_messages."""

    def test_systemexit_during_session_open_returns_json_error(self) -> None:
        """trash_messages returns dict error when open_readwrite_session raises SystemExit."""
        cfg = _make_global_config(
            allow_confirmed_actions=True, allow_delete=True
        )

        with patch.object(srv, "_config", cfg):
            with patch(
                "icloud_helper.flagged.open_readonly_session"
            ) as mock_ro:
                mock_ro.return_value.__enter__ = MagicMock(
                    return_value=(MagicMock(), 12345)
                )
                mock_ro.return_value.__exit__ = MagicMock(return_value=False)

                with patch.object(
                    _actions,
                    "open_readwrite_session",
                    side_effect=SystemExit(1),
                ):
                    data = srv.trash_messages(
                        folder="INBOX",
                        uids="200,201",
                        uidvalidity=12345,
                        confirm=True,
                    )

        assert "error" in data, f"Expected error key in: {data}"

    def test_systemexit_in_open_readwrite_session_internals_returns_json(
        self,
    ) -> None:
        """SystemExit from read_secret inside open_readwrite_session returns dict for trash."""
        cfg = _make_global_config(
            allow_confirmed_actions=True, allow_delete=True
        )

        with patch.object(srv, "_config", cfg):
            with patch(
                "icloud_helper.flagged.open_readonly_session"
            ) as mock_ro:
                mock_ro.return_value.__enter__ = MagicMock(
                    return_value=(MagicMock(), 12345)
                )
                mock_ro.return_value.__exit__ = MagicMock(return_value=False)

                with patch(
                    "icloud_helper.actions.read_secret",
                    side_effect=SystemExit(1),
                ):
                    data = srv.trash_messages(
                        folder="INBOX",
                        uids="600",
                        uidvalidity=12345,
                        confirm=True,
                    )

        assert "error" in data, f"Expected error key in: {data}"
        assert data["error"] in ("imap_session_failed", "imap_error"), (
            f"Unexpected error: {data['error']}"
        )


class TestSystemExitUnsubscribeMessageReadSecret:
    """SystemExit from read_secret must not escape unsubscribe_message."""

    def test_systemexit_from_read_secret_returns_json_error(self) -> None:
        """unsubscribe_message returns JSON error when read_secret raises SystemExit.

        The security reviewer confirmed that the original ``except Exception``
        guard did not catch ``SystemExit``.  After the fix,
        ``except (Exception, SystemExit)`` must intercept it.
        """
        cfg = _make_global_config(allow_confirmed_actions=True)
        raw = _make_raw_message(
            from_header="news@example.com",
            auth_results="dmarc.icloud.com; dmarc=pass dkim=pass",
        )

        with patch.object(srv, "_config", cfg):
            with patch(
                "icloud_helper.flagged.open_readonly_session"
            ) as mock_ro:
                mock_ro.return_value.__enter__ = MagicMock(
                    return_value=(MagicMock(), 12345)
                )
                mock_ro.return_value.__exit__ = MagicMock(return_value=False)

                with patch(
                    "icloud_helper.flagged.fetch_message",
                    return_value=(raw, "15-Jun-2025 10:00:00 +0000"),
                ):
                    with patch(
                        "icloud_helper.mcp_server.read_secret",
                        side_effect=SystemExit(1),
                    ):
                        # Must NOT raise SystemExit.
                        data = srv.unsubscribe_message(
                            folder="INBOX",
                            uid="77",
                            uidvalidity=12345,
                            confirm=True,
                        )

        assert "error" in data, f"Expected error key in: {data}"
        assert "could not" in data["error"].lower() or (
            "smtp" in data["error"].lower()
        ) or "credential" in data["error"].lower(), (
            f"Unexpected error message: {data['error']}"
        )


# ---------------------------------------------------------------------------
# FOLLOWUP 1 — live warning field present/absent
# ---------------------------------------------------------------------------


class TestLiveWarningField:
    """LIVE confirmed actions emit a 'warnings' list; simulated emit empty list."""

    def test_move_messages_live_has_warning_field(self) -> None:
        """move_messages response includes LIVE warning when executed live."""
        cfg = _make_global_config(allow_confirmed_actions=True)

        mock_rw_imap = MagicMock(spec=imaplib.IMAP4_SSL)
        mock_rw_imap.uid.return_value = ("OK", [b""])
        mock_rw_imap.create.return_value = ("OK", [b""])

        with patch.object(srv, "_config", cfg):
            with patch(
                "icloud_helper.flagged.open_readonly_session"
            ) as mock_ro:
                mock_ro.return_value.__enter__ = MagicMock(
                    return_value=(MagicMock(), 12345)
                )
                mock_ro.return_value.__exit__ = MagicMock(return_value=False)

                with patch(
                    "icloud_helper.actions.open_readwrite_session"
                ) as mock_rw:
                    mock_rw.return_value.__enter__ = MagicMock(
                        return_value=(mock_rw_imap, 12345)
                    )
                    mock_rw.return_value.__exit__ = MagicMock(
                        return_value=False
                    )

                    with patch.object(srv._store, "append_audit"):
                        data = srv.move_messages(
                            folder="INBOX",
                            uids="101",
                            uidvalidity=12345,
                            destination="Archive",
                            confirm=True,
                        )

        assert data.get("confirmed") is True
        warnings = data.get("warnings", [])
        assert len(warnings) > 0, (
            f"Expected non-empty 'warnings' in live response; got: {data}"
        )
        assert any("LIVE" in w for w in warnings), (
            f"Expected 'LIVE' in a warning; got warnings={warnings}"
        )

    def test_move_messages_simulated_has_no_warning_field(self) -> None:
        """move_messages response has empty warnings list when simulated."""
        cfg = _make_global_config(allow_confirmed_actions=False)

        with patch.object(srv, "_config", cfg):
            data = srv.move_messages(
                folder="INBOX",
                uids="101",
                uidvalidity=12345,
                destination="Archive",
                confirm=True,
            )

        assert data.get("confirmed") is False
        assert data.get("warnings", []) == [], (
            f"'warnings' must be empty on simulated path; got: {data}"
        )

    def test_unsubscribe_message_live_has_warning_field(self) -> None:
        """unsubscribe_message response includes LIVE warning when executed live."""
        cfg = _make_global_config(allow_confirmed_actions=True)
        raw = _make_raw_message(
            from_header="news@example.com",
            auth_results="dmarc.icloud.com; dmarc=pass dkim=pass",
        )

        with patch.object(srv, "_config", cfg):
            with patch(
                "icloud_helper.flagged.open_readonly_session"
            ) as mock_ro:
                mock_ro.return_value.__enter__ = MagicMock(
                    return_value=(MagicMock(), 12345)
                )
                mock_ro.return_value.__exit__ = MagicMock(return_value=False)

                with patch(
                    "icloud_helper.flagged.fetch_message",
                    return_value=(raw, "15-Jun-2025 10:00:00 +0000"),
                ):
                    with patch(
                        "icloud_helper.mcp_server.read_secret",
                        return_value="dummy",
                    ):
                        with patch(
                            "icloud_helper.mcp_server.perform_unsubscribe"
                        ) as mock_unsub:
                            from icloud_helper.unsubscribe import (
                                UnsubscribeResult,
                            )
                            mock_unsub.return_value = UnsubscribeResult(
                                sender="news@example.com",
                                method="mailto",
                                target="unsub@example.com",
                                result="success",
                                http_status=None,
                                dry_run=False,
                                detail="simulated ok",
                            )
                            with patch.object(srv._store, "append_audit"):
                                data = srv.unsubscribe_message(
                                    folder="INBOX",
                                    uid="42",
                                    uidvalidity=12345,
                                    confirm=True,
                                )

        assert data.get("confirmed") is True
        warnings = data.get("warnings", [])
        assert len(warnings) > 0, (
            f"Expected non-empty 'warnings' in live response; got: {data}"
        )
        assert any("LIVE" in w for w in warnings), (
            f"Expected 'LIVE' in a warning; got warnings={warnings}"
        )

    def test_unsubscribe_message_simulated_has_no_warning_field(self) -> None:
        """unsubscribe_message response has empty warnings list when simulated."""
        cfg = _make_global_config(allow_confirmed_actions=False)
        raw = _make_raw_message(
            from_header="news@example.com",
            auth_results="dmarc.icloud.com; dmarc=pass dkim=pass",
        )

        with patch.object(srv, "_config", cfg):
            with patch(
                "icloud_helper.flagged.open_readonly_session"
            ) as mock_ro:
                mock_ro.return_value.__enter__ = MagicMock(
                    return_value=(MagicMock(), 12345)
                )
                mock_ro.return_value.__exit__ = MagicMock(return_value=False)

                with patch(
                    "icloud_helper.flagged.fetch_message",
                    return_value=(raw, "15-Jun-2025 10:00:00 +0000"),
                ):
                    with patch(
                        "icloud_helper.mcp_server.read_secret",
                        return_value="dummy",
                    ):
                        with patch(
                            "icloud_helper.mcp_server.perform_unsubscribe"
                        ) as mock_unsub:
                            from icloud_helper.unsubscribe import (
                                UnsubscribeResult,
                            )
                            mock_unsub.return_value = UnsubscribeResult(
                                sender="news@example.com",
                                method="mailto",
                                target="unsub@example.com",
                                result="success-simulated",
                                http_status=None,
                                dry_run=True,
                                detail="dry run",
                            )
                            with patch.object(srv._store, "append_audit"):
                                data = srv.unsubscribe_message(
                                    folder="INBOX",
                                    uid="42",
                                    uidvalidity=0,  # gate blocked
                                    confirm=True,
                                )

        assert data.get("confirmed") is False
        assert data.get("warnings", []) == [], (
            f"'warnings' must be empty on simulated path; got: {data}"
        )


# ---------------------------------------------------------------------------
# FIX 5 — unsubscribe_message gates_evaluated includes pre-gates
# ---------------------------------------------------------------------------


class TestUnsubscribeMessageGatesEvaluated:
    """gates_evaluated in unsubscribe_message response must include pre-gate names."""

    def test_gates_evaluated_includes_dkim_dmarc_and_egress_policy(
        self,
    ) -> None:
        """When unsubscribe_message processes normally (past DKIM + protected-domain
        checks), gates_evaluated must prepend 'dkim_dmarc' and 'egress_policy'
        ahead of the confirmed-action gate's own names."""
        cfg = _make_global_config(allow_confirmed_actions=True)
        raw = _make_raw_message(
            from_header="news@example.com",
            auth_results="dmarc.icloud.com; dmarc=pass dkim=pass",
        )

        with patch.object(srv, "_config", cfg):
            with patch(
                "icloud_helper.flagged.open_readonly_session"
            ) as mock_ro:
                mock_ro.return_value.__enter__ = MagicMock(
                    return_value=(MagicMock(), 12345)
                )
                mock_ro.return_value.__exit__ = MagicMock(return_value=False)

                with patch(
                    "icloud_helper.flagged.fetch_message",
                    return_value=(raw, "15-Jun-2025 10:00:00 +0000"),
                ):
                    with patch(
                        "icloud_helper.mcp_server.read_secret",
                        return_value="dummy",
                    ):
                        with patch(
                            "icloud_helper.mcp_server.perform_unsubscribe"
                        ) as mock_unsub:
                            from icloud_helper.unsubscribe import (
                                UnsubscribeResult,
                            )
                            mock_unsub.return_value = UnsubscribeResult(
                                sender="news@example.com",
                                method="one-click",
                                target="https://example.com/unsub",
                                result="success",
                                http_status=200,
                                dry_run=False,
                                detail="ok",
                            )
                            with patch.object(srv._store, "append_audit"):
                                data = srv.unsubscribe_message(
                                    folder="INBOX",
                                    uid="42",
                                    uidvalidity=12345,
                                    confirm=True,
                                )

        gates = data.get("gates_evaluated", [])
        assert "dkim_dmarc" in gates, (
            f"'dkim_dmarc' must appear in gates_evaluated; got: {gates}"
        )
        assert "egress_policy" in gates, (
            f"'egress_policy' must appear in gates_evaluated; got: {gates}"
        )
        # Pre-gates must come before the confirmed-action gate names.
        assert gates.index("dkim_dmarc") < gates.index("master_switch"), (
            f"'dkim_dmarc' must precede 'master_switch' in gates_evaluated; got: {gates}"
        )
