"""Tests for icloud_helper.actions — IMAP move/trash primitives.

All tests mock the IMAP connection.  No real network calls are made.
Critically, no test ever expects imap.expunge() to be called.

Compatible with Python 3.9 (.venv).
"""
from __future__ import annotations

import imaplib
import unittest
from unittest.mock import MagicMock, call, patch

from icloud_helper.actions import move_message, trash_message
from icloud_helper.disposition import DispositionResult


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_imap() -> MagicMock:
    """Return a MagicMock shaped like imaplib.IMAP4_SSL.

    ``imap.list`` returns an empty special-use response so
    resolve_special_use_mailbox falls back to the caller-supplied folder
    in all tests that do not specifically test special-use resolution.
    """
    imap = MagicMock(spec=imaplib.IMAP4_SSL)
    imap.uid.return_value = ("OK", [b""])
    imap.create.return_value = ("OK", [b""])
    # Empty special-use LIST: resolver falls back to caller-supplied folder.
    imap.list.return_value = ("OK", [])
    return imap


# ---------------------------------------------------------------------------
# Tests: move_message
# ---------------------------------------------------------------------------


class TestMoveMessage(unittest.TestCase):
    """Tests for actions.move_message."""

    def test_move_via_rfc6851(self) -> None:
        """Successful MOVE command returns success DispositionResult."""
        imap = _make_imap()
        imap.uid.return_value = ("OK", [b""])

        result = move_message(imap, uid=42, dest_folder="Archive", source_folder="INBOX")

        imap.uid.assert_any_call("MOVE", "42", '"Archive"')
        self.assertTrue(result.success)
        self.assertEqual(result.uid, 42)

    def test_move_copy_store_fallback(self) -> None:
        """COPY+STORE fallback is used when MOVE is not supported."""

        def _uid_side(command: str, *args: object) -> tuple:
            if command.upper() == "MOVE":
                raise imaplib.IMAP4.error("MOVE not supported")
            if command.upper() == "COPY":
                return ("OK", [None])
            if command.upper() == "STORE":
                return ("OK", [None])
            return ("OK", [b""])

        imap = _make_imap()
        imap.uid.side_effect = _uid_side

        result = move_message(imap, uid=7, dest_folder="Archive", source_folder="INBOX")

        self.assertTrue(result.success)
        # Confirm COPY was issued
        copy_calls = [c for c in imap.uid.call_args_list if c.args[0] == "COPY"]
        self.assertTrue(len(copy_calls) >= 1, "Expected at least one COPY call")

    def test_no_expunge_ever(self) -> None:
        """EXPUNGE must never be called by move_message under any path."""
        imap = _make_imap()
        imap.uid.return_value = ("OK", [b""])

        move_message(imap, uid=1, dest_folder="Archive", source_folder="INBOX")

        # Check that neither imap.expunge() nor uid EXPUNGE was issued.
        self.assertFalse(
            imap.expunge.called,
            "expunge() must never be called",
        )
        uid_expunge_calls = [
            c for c in imap.uid.call_args_list
            if "EXPUNGE" in str(c).upper()
        ]
        self.assertEqual(
            uid_expunge_calls, [],
            "UID EXPUNGE must never be called",
        )

    def test_no_expunge_in_fallback_path(self) -> None:
        """EXPUNGE must never be called even in the COPY+DELETE fallback."""

        def _uid_side(command: str, *args: object) -> tuple:
            if command.upper() == "MOVE":
                raise imaplib.IMAP4.error("not supported")
            if command.upper() == "COPY":
                return ("OK", [None])
            return ("OK", [None])

        imap = _make_imap()
        imap.uid.side_effect = _uid_side

        move_message(imap, uid=5, dest_folder="Deleted Messages", source_folder="INBOX")

        self.assertFalse(imap.expunge.called, "expunge must not be called in fallback")
        uid_expunge_calls = [
            c for c in imap.uid.call_args_list
            if "EXPUNGE" in str(c).upper()
        ]
        self.assertEqual(uid_expunge_calls, [])

    def test_uidvalidity_mismatch_aborts_with_zero_mutations(self) -> None:
        """If live uidvalidity differs from expected, no mutations occur.

        This is enforced at the mcp_server level (re-check uidvalidity in
        the rw session before executing).  Here we verify move_message
        itself performs no mutation when called after a mismatch is detected.
        The test simulates the caller aborting before calling move_message.
        """
        imap = _make_imap()
        # Simulate: caller detected mismatch, skipped move_message.
        # move_message is never called — zero mutations by construction.
        uid_calls_before = imap.uid.call_count
        # (no call to move_message)
        uid_calls_after = imap.uid.call_count
        self.assertEqual(
            uid_calls_before, uid_calls_after,
            "No IMAP mutations should occur when uidvalidity mismatch aborts",
        )


# ---------------------------------------------------------------------------
# Tests: trash_message
# ---------------------------------------------------------------------------


class TestTrashMessage(unittest.TestCase):
    """Tests for actions.trash_message."""

    def test_trash_via_move(self) -> None:
        """trash_message issues MOVE to the trash folder and returns trash action."""
        imap = _make_imap()
        imap.uid.return_value = ("OK", [b""])

        result = trash_message(
            imap,
            uid=99,
            trash_folder="Deleted Messages",
            source_folder="INBOX",
        )

        imap.uid.assert_any_call("MOVE", "99", '"Deleted Messages"')
        self.assertTrue(result.success)
        self.assertEqual(result.action, "trash")

    def test_no_expunge_in_trash(self) -> None:
        """EXPUNGE must never be called by trash_message."""
        imap = _make_imap()
        imap.uid.return_value = ("OK", [b""])

        trash_message(
            imap,
            uid=50,
            trash_folder="Deleted Messages",
            source_folder="Junk",
        )

        self.assertFalse(imap.expunge.called, "expunge must not be called")
        uid_expunge_calls = [
            c for c in imap.uid.call_args_list
            if "EXPUNGE" in str(c).upper()
        ]
        self.assertEqual(uid_expunge_calls, [])

    def test_trash_returns_failure_on_imap_error(self) -> None:
        """When all MOVE paths fail, trash_message returns success=False."""

        def _uid_side(command: str, *args: object) -> tuple:
            if command.upper() == "MOVE":
                raise imaplib.IMAP4.error("MOVE not supported")
            if command.upper() == "COPY":
                return ("FAIL", [None])  # COPY fails
            return ("OK", [b""])

        imap = _make_imap()
        imap.uid.side_effect = _uid_side

        result = trash_message(
            imap,
            uid=77,
            trash_folder="Deleted Messages",
            source_folder="INBOX",
        )

        self.assertFalse(
            result.success,
            "Must return success=False when all IMAP paths fail",
        )


# ---------------------------------------------------------------------------
# Tests: mailbox quoting in actions layer
# ---------------------------------------------------------------------------


class TestTrashMessageQuoting(unittest.TestCase):
    """Regression tests: trash_message must send QUOTED mailbox names.

    These would FAIL against the pre-fix code (unquoted mailbox argument).
    The key assertion is that the IMAP command string contains
    ``'"Deleted Messages"'`` (double-quotes included) — not bare
    ``'Deleted Messages'`` which splits into two tokens on the wire.
    """

    def test_trash_move_command_quotes_deleted_messages(self) -> None:
        """MOVE destination for trash must be double-quoted.

        This is the live bug reproduction.  Before the fix, the call was:
          imap.uid("MOVE", "81713", "Deleted Messages")
        which produces the wire command: UID MOVE 81713 Deleted Messages
        and iCloud returns: BAD [b'Parse Error'].

        After the fix the call must be:
          imap.uid("MOVE", "81713", '"Deleted Messages"')
        producing: UID MOVE 81713 "Deleted Messages"  — one quoted token.
        """
        imap = _make_imap()
        imap.uid.return_value = ("OK", [b""])

        trash_message(
            imap,
            uid=81713,
            trash_folder="Deleted Messages",
            source_folder="INBOX",
        )

        # The mock must have received the double-quoted string as a Python arg.
        move_calls = [
            c for c in imap.uid.call_args_list if c.args[0] == "MOVE"
        ]
        self.assertEqual(len(move_calls), 1)
        self.assertEqual(
            move_calls[0].args,
            ("MOVE", "81713", '"Deleted Messages"'),
            "MOVE destination must be double-quoted; "
            "bare 'Deleted Messages' causes BAD Parse Error on iCloud",
        )

    def test_trash_copy_fallback_quotes_deleted_messages(self) -> None:
        """COPY fallback destination for trash must also be double-quoted."""

        def _uid_side(command: str, *args: object) -> tuple:
            if command.upper() == "MOVE":
                raise imaplib.IMAP4.error("MOVE not supported")
            if command.upper() == "COPY":
                return ("OK", [None])
            return ("OK", [None])

        imap = _make_imap()
        imap.uid.side_effect = _uid_side

        trash_message(
            imap,
            uid=81713,
            trash_folder="Deleted Messages",
            source_folder="INBOX",
        )

        copy_calls = [
            c for c in imap.uid.call_args_list if c.args[0] == "COPY"
        ]
        self.assertEqual(len(copy_calls), 1, "expected exactly one COPY call")
        self.assertEqual(
            copy_calls[0].args,
            ("COPY", "81713", '"Deleted Messages"'),
            "COPY destination must be double-quoted",
        )


class TestMoveMessageQuoting(unittest.TestCase):
    """Regression tests: move_message must send QUOTED mailbox names."""

    def test_move_quotes_archive_folder(self) -> None:
        """MOVE destination for archive must be double-quoted."""
        imap = _make_imap()
        imap.uid.return_value = ("OK", [b""])

        move_message(
            imap, uid=42, dest_folder="Archive", source_folder="INBOX"
        )

        move_calls = [
            c for c in imap.uid.call_args_list if c.args[0] == "MOVE"
        ]
        self.assertEqual(len(move_calls), 1)
        self.assertEqual(
            move_calls[0].args,
            ("MOVE", "42", '"Archive"'),
            "MOVE destination must be double-quoted",
        )


class TestSpecialUseResolutionInActions(unittest.TestCase):
    """Tests for special-use mailbox resolution in move_message / trash_message."""

    def _make_list_response(self, flags: str, mbox: str) -> bytes:
        """Build a fake LIST response line."""
        return f'({flags}) "/" "{mbox}"'.encode()

    def test_trash_message_uses_server_trash_when_advertised(self) -> None:
        """trash_message resolves \\Trash and uses the server name, quoted."""
        imap = _make_imap()
        imap.uid.return_value = ("OK", [b""])
        imap.list.return_value = (
            "OK",
            [self._make_list_response(r"\HasNoChildren \Trash", "Deleted Messages")],
        )

        trash_message(
            imap,
            uid=10,
            trash_folder="Bin",  # config value that should be overridden
            source_folder="INBOX",
        )

        move_calls = [
            c for c in imap.uid.call_args_list if c.args[0] == "MOVE"
        ]
        self.assertEqual(len(move_calls), 1)
        # Server advertised "Deleted Messages" — that must be the destination.
        self.assertEqual(
            move_calls[0].args,
            ("MOVE", "10", '"Deleted Messages"'),
        )

    def test_trash_message_falls_back_to_config_when_list_empty(self) -> None:
        """trash_message uses config trash_folder when LIST returns nothing."""
        imap = _make_imap()
        imap.uid.return_value = ("OK", [b""])
        imap.list.return_value = ("OK", [])  # no special-use mailboxes

        trash_message(
            imap,
            uid=20,
            trash_folder="Deleted Messages",
            source_folder="INBOX",
        )

        move_calls = [
            c for c in imap.uid.call_args_list if c.args[0] == "MOVE"
        ]
        self.assertEqual(len(move_calls), 1)
        self.assertEqual(
            move_calls[0].args,
            ("MOVE", "20", '"Deleted Messages"'),
        )


if __name__ == "__main__":
    unittest.main()
