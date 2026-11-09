"""Tests for icloud_helper.disposition."""
from __future__ import annotations

import imaplib
import unittest
from unittest.mock import MagicMock

from icloud_helper.disposition import (
    _SPECIAL_USE_ARCHIVE,
    _SPECIAL_USE_TRASH,
    _encode_mailbox,
    apply_disposition,
    mark_message_read,
    move_to_folder,
    resolve_special_use_mailbox,
    soft_delete,
)


class _FakeGlobalConfig:
    """Minimal stand-in for GlobalConfig."""

    def __init__(
        self,
        allow_delete: bool = True,
        disposition: str = "mark_read",
    ) -> None:
        self.allow_delete = allow_delete
        self.disposition = disposition
        self.dry_run = False


def _make_imap() -> MagicMock:
    """Return a MagicMock shaped like imaplib.IMAP4_SSL.

    ``imap.list`` returns an empty special-use response so
    resolve_special_use_mailbox falls back to the config value in all
    tests that do not specifically test special-use resolution.
    """
    imap = MagicMock(spec=imaplib.IMAP4_SSL)
    imap.uid.return_value = ("OK", [b"1 (FLAGS (\\Seen))"])
    imap.create.return_value = ("OK", [b""])
    # Empty special-use LIST: resolver falls back to caller-supplied folder.
    imap.list.return_value = ("OK", [])
    return imap


class TestMarkMessageRead(unittest.TestCase):
    """Tests for mark_message_read."""

    def test_mark_read_dry_run(self) -> None:
        """Dry-run must not call imap.uid and return action=dry_run."""
        imap = _make_imap()
        result = mark_message_read(imap, uid=42, dry_run=True, folder="INBOX")

        imap.uid.assert_not_called()
        self.assertEqual(result.action, "dry_run")
        self.assertTrue(result.success)

    def test_mark_read_live(self) -> None:
        """Live call must issue correct STORE command and return success."""
        imap = _make_imap()
        imap.uid.return_value = ("OK", [b"42 (FLAGS (\\Seen))"])

        result = mark_message_read(
            imap, uid=42, dry_run=False, folder="INBOX"
        )

        imap.uid.assert_called_once_with(
            "STORE", "42", "+FLAGS", r"(\Seen)"
        )
        self.assertTrue(result.success)
        self.assertEqual(result.action, "mark_read")
        self.assertEqual(result.uid, 42)


class TestMoveToFolder(unittest.TestCase):
    """Tests for move_to_folder."""

    def test_move_to_folder_dry_run(self) -> None:
        """Dry-run must not call imap and return action=dry_run."""
        imap = _make_imap()
        result = move_to_folder(
            imap, uid=7, target_folder="Unsubscribed", dry_run=True
        )

        imap.uid.assert_not_called()
        imap.create.assert_not_called()
        self.assertEqual(result.action, "dry_run")
        self.assertTrue(result.success)

    def test_move_via_rfc6851(self) -> None:
        """Successful MOVE must return action=move_to_unsubscribed."""
        imap = _make_imap()
        imap.uid.return_value = ("OK", [b""])

        result = move_to_folder(
            imap,
            uid=7,
            target_folder="Unsubscribed",
            dry_run=False,
            source_folder="INBOX",
        )

        imap.uid.assert_called_once_with("MOVE", "7", '"Unsubscribed"')
        self.assertEqual(result.action, "move_to_unsubscribed")
        self.assertTrue(result.success)

    def test_copy_store_fallback_store_deleted_fail_returns_failure(
        self,
    ) -> None:
        """C-1: When COPY succeeds but STORE \\Deleted fails, success=False.

        The caller must NOT mark the message as processed when STORE
        \\Deleted returns a non-OK status, preventing stranding.
        """

        def _uid_side(command: str, *args: object) -> tuple:
            cmd = command.upper()
            if cmd == "MOVE":
                raise imaplib.IMAP4.error("MOVE not supported by server")
            if cmd == "COPY":
                return ("OK", [None])
            # STORE \Deleted — simulate failure
            return ("FAIL", [None])

        imap = _make_imap()
        imap.uid.side_effect = _uid_side

        result = move_to_folder(
            imap,
            uid=7,
            target_folder="Unsubscribed",
            dry_run=False,
            source_folder="INBOX",
        )

        self.assertFalse(
            result.success,
            "success must be False when STORE \\Deleted returns non-OK",
        )
        self.assertEqual(result.action, "move_to_unsubscribed")


class TestSoftDelete(unittest.TestCase):
    """Tests for soft_delete."""

    def test_soft_delete_allow_delete_false(self) -> None:
        """Must skip and refuse delete when allow_delete=False."""
        imap = _make_imap()
        config = _FakeGlobalConfig(allow_delete=False)

        result = soft_delete(
            imap,
            uid=10,
            trash_folder="Trash",
            global_config=config,
            sender_disposition="delete",
            dry_run=False,
        )

        imap.uid.assert_not_called()
        self.assertEqual(result.action, "skipped")
        self.assertTrue(result.success)
        self.assertIn("allow_delete=false", result.detail)

    def test_soft_delete_wrong_disposition(self) -> None:
        """Must skip when sender_disposition is not 'delete'."""
        imap = _make_imap()
        config = _FakeGlobalConfig(allow_delete=True)

        result = soft_delete(
            imap,
            uid=10,
            trash_folder="Trash",
            global_config=config,
            sender_disposition="keep",
            dry_run=False,
        )

        imap.uid.assert_not_called()
        self.assertEqual(result.action, "skipped")
        self.assertTrue(result.success)

    def test_soft_delete_dry_run_both_gates_pass(self) -> None:
        """Dry-run with both gates passing must return dry_run action."""
        imap = _make_imap()
        config = _FakeGlobalConfig(allow_delete=True)

        result = soft_delete(
            imap,
            uid=10,
            trash_folder="Trash",
            global_config=config,
            sender_disposition="delete",
            dry_run=True,
        )

        imap.uid.assert_not_called()
        self.assertEqual(result.action, "dry_run")
        self.assertTrue(result.success)


class TestApplyDisposition(unittest.TestCase):
    """Tests for apply_disposition."""

    def test_apply_disposition_unknown(self) -> None:
        """Unknown disposition string must return action=skipped."""
        imap = _make_imap()
        config = _FakeGlobalConfig(disposition="unknown_value")

        result = apply_disposition(
            imap,
            uid=99,
            folder="INBOX",
            global_config=config,
            sender_disposition=None,
            dry_run=False,
        )

        imap.uid.assert_not_called()
        self.assertEqual(result.action, "skipped")
        self.assertTrue(result.success)
        self.assertIn("unknown_value", result.detail)

    def test_apply_disposition_mark_read_dry_run(self) -> None:
        """mark_read disposition in dry-run must not call imap.uid."""
        imap = _make_imap()
        config = _FakeGlobalConfig(disposition="mark_read")

        result = apply_disposition(
            imap,
            uid=5,
            folder="INBOX",
            global_config=config,
            sender_disposition=None,
            dry_run=True,
        )

        imap.uid.assert_not_called()
        self.assertEqual(result.action, "dry_run")

    def test_apply_disposition_sender_overrides_global(self) -> None:
        """sender_disposition must take precedence over global disposition."""
        imap = _make_imap()
        imap.uid.return_value = ("OK", [b""])
        config = _FakeGlobalConfig(disposition="mark_read")

        result = apply_disposition(
            imap,
            uid=5,
            folder="INBOX",
            global_config=config,
            sender_disposition="move_to_unsubscribed",
            dry_run=False,
        )

        imap.uid.assert_called_with("MOVE", "5", '"Unsubscribed"')
        self.assertEqual(result.action, "move_to_unsubscribed")


class TestEncodeMailbox(unittest.TestCase):
    """Tests for _encode_mailbox.

    This is the regression suite for the BAD [Parse Error] bug: iCloud (and
    RFC 3501-compliant servers generally) parse an unquoted mailbox argument
    token-by-token, so ``Deleted Messages`` is two tokens and causes a parse
    error.  Every IMAP command that takes a mailbox name must pass through
    _encode_mailbox so the server always receives a single quoted atom.
    """

    def test_ascii_no_space_is_double_quoted(self) -> None:
        """Single-word ASCII mailbox is wrapped in double-quotes."""
        result = _encode_mailbox("Archive")
        self.assertEqual(result, '"Archive"')

    def test_ascii_with_space_is_double_quoted(self) -> None:
        """Multi-word ASCII mailbox (the bug case) is double-quoted.

        Before the fix: ``imap.uid("MOVE", uid, "Deleted Messages")``
        → IMAP command: ``UID MOVE 81713 Deleted Messages``
        → server sees two tokens, returns BAD Parse Error.

        After the fix: ``imap.uid("MOVE", uid, '"Deleted Messages"')``
        → IMAP command: ``UID MOVE 81713 "Deleted Messages"``
        → single quoted string, server accepts it.
        """
        result = _encode_mailbox("Deleted Messages")
        self.assertEqual(result, '"Deleted Messages"')

    def test_unsubscribed_no_space_is_quoted(self) -> None:
        """Existing cron destination (no space) is also quoted correctly."""
        result = _encode_mailbox("Unsubscribed")
        self.assertEqual(result, '"Unsubscribed"')

    def test_embedded_double_quote_is_escaped(self) -> None:
        """Double-quotes inside the name are backslash-escaped per RFC 3501."""
        result = _encode_mailbox('My "Special" Folder')
        self.assertEqual(result, '"My \\"Special\\" Folder"')

    def test_non_ascii_encodes_to_modified_utf7(self) -> None:
        """Non-ASCII mailbox names are encoded to IMAP modified-UTF-7.

        Verifies the result is pure ASCII (7-bit clean) and still quoted.
        The exact encoded value depends on the imap4-utf-7 codec, but the
        result must be all-ASCII and wrapped in double-quotes.
        """
        result = _encode_mailbox("Gelöschte Objekte")  # German trash name
        self.assertTrue(result.startswith('"'), "must be double-quoted")
        self.assertTrue(result.endswith('"'), "must be double-quoted")
        inner = result[1:-1]
        self.assertTrue(
            inner.isascii(),
            f"encoded mailbox must be 7-bit ASCII, got: {inner!r}",
        )


class TestMoveToFolderQuoting(unittest.TestCase):
    """Regression tests: move_to_folder must send QUOTED mailbox names.

    These tests assert the exact IMAP command strings received by the mock.
    They would FAIL against the pre-fix code (unquoted mailbox argument).
    """

    def test_move_quoted_destination_space_in_name(self) -> None:
        """MOVE command must quote a mailbox name that contains a space.

        This is the direct reproduction of the live BAD [Parse Error] bug.
        The mock captures what would be sent over the wire; the expected
        argument is ``'"Deleted Messages"'`` (a Python string whose value
        is ``"Deleted Messages"`` with surrounding double-quotes).
        """
        imap = _make_imap()
        imap.uid.return_value = ("OK", [b""])

        move_to_folder(
            imap,
            uid=81713,
            target_folder="Deleted Messages",
            dry_run=False,
            source_folder="INBOX",
        )

        imap.uid.assert_called_once_with(
            "MOVE", "81713", '"Deleted Messages"'
        )

    def test_copy_fallback_quoted_destination_space_in_name(self) -> None:
        """COPY fallback must also quote a space-containing destination.

        Verifies the COPY+STORE-deleted path sends the quoted mailbox name,
        not the bare multi-word string.
        """

        def _uid_side(command: str, *args: object) -> tuple:
            if command.upper() == "MOVE":
                raise imaplib.IMAP4.error("MOVE not supported")
            if command.upper() == "COPY":
                return ("OK", [None])
            # STORE \Deleted
            return ("OK", [None])

        imap = _make_imap()
        imap.uid.side_effect = _uid_side

        move_to_folder(
            imap,
            uid=81713,
            target_folder="Deleted Messages",
            dry_run=False,
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

    def test_create_quoted_destination_space_in_name(self) -> None:
        """imap.create must receive a quoted mailbox name for multi-word names."""
        imap = _make_imap()
        imap.uid.return_value = ("OK", [b""])

        move_to_folder(
            imap,
            uid=1,
            target_folder="Deleted Messages",
            dry_run=False,
            source_folder="INBOX",
        )

        imap.create.assert_called_once_with('"Deleted Messages"')

    def test_move_quoted_destination_no_space(self) -> None:
        """MOVE command also quotes a single-word mailbox (consistent quoting)."""
        imap = _make_imap()
        imap.uid.return_value = ("OK", [b""])

        move_to_folder(
            imap,
            uid=7,
            target_folder="Unsubscribed",
            dry_run=False,
            source_folder="INBOX",
        )

        imap.uid.assert_called_once_with("MOVE", "7", '"Unsubscribed"')


class TestResolveSpecialUseMailbox(unittest.TestCase):
    """Tests for resolve_special_use_mailbox."""

    def _make_list_response(self, flags: str, mbox: str) -> bytes:
        """Build a fake LIST response line."""
        return f'({flags}) "/" "{mbox}"'.encode()

    def test_returns_server_trash_when_advertised(self) -> None:
        """When LIST reports \\Trash, that mailbox name is returned."""
        imap = MagicMock(spec=imaplib.IMAP4_SSL)
        imap.list.return_value = (
            "OK",
            [self._make_list_response(r"\HasNoChildren \Trash", "Deleted Messages")],
        )

        result = resolve_special_use_mailbox(
            imap, _SPECIAL_USE_TRASH, fallback="Trash"
        )

        self.assertEqual(result, "Deleted Messages")

    def test_returns_server_archive_when_advertised(self) -> None:
        """When LIST reports \\Archive, that mailbox name is returned."""
        imap = MagicMock(spec=imaplib.IMAP4_SSL)
        imap.list.return_value = (
            "OK",
            [self._make_list_response(r"\HasNoChildren \Archive", "Archive")],
        )

        result = resolve_special_use_mailbox(
            imap, _SPECIAL_USE_ARCHIVE, fallback="Archive"
        )

        self.assertEqual(result, "Archive")

    def test_falls_back_when_list_empty(self) -> None:
        """When LIST returns no mailboxes, fallback config value is used."""
        imap = MagicMock(spec=imaplib.IMAP4_SSL)
        imap.list.return_value = ("OK", [])

        result = resolve_special_use_mailbox(
            imap, _SPECIAL_USE_TRASH, fallback="Deleted Messages"
        )

        self.assertEqual(result, "Deleted Messages")

    def test_falls_back_when_list_fails(self) -> None:
        """When LIST raises an exception, fallback config value is used."""
        imap = MagicMock(spec=imaplib.IMAP4_SSL)
        imap.list.side_effect = imaplib.IMAP4.error("not supported")

        result = resolve_special_use_mailbox(
            imap, _SPECIAL_USE_TRASH, fallback="Deleted Messages"
        )

        self.assertEqual(result, "Deleted Messages")

    def test_falls_back_when_list_status_not_ok(self) -> None:
        """When LIST returns non-OK status, fallback config value is used."""
        imap = MagicMock(spec=imaplib.IMAP4_SSL)
        imap.list.return_value = ("NO", [])

        result = resolve_special_use_mailbox(
            imap, _SPECIAL_USE_TRASH, fallback="Deleted Messages"
        )

        self.assertEqual(result, "Deleted Messages")

    def test_no_match_returns_fallback(self) -> None:
        """When LIST has entries but none match the flag, fallback is used."""
        imap = MagicMock(spec=imaplib.IMAP4_SSL)
        imap.list.return_value = (
            "OK",
            [self._make_list_response(r"\HasNoChildren \Sent", "Sent Messages")],
        )

        result = resolve_special_use_mailbox(
            imap, _SPECIAL_USE_TRASH, fallback="Deleted Messages"
        )

        self.assertEqual(result, "Deleted Messages")

    def test_list_called_with_two_arg_form(self) -> None:
        """LIST must be called as imap.list('""', '*'), not the broken 3-arg form.

        The 3-arg ``imap.list('(SPECIAL-USE)', '""', '"*"')`` is not a valid
        imaplib signature; imaplib rejects it and special-use lookup silently
        returns nothing.  The plain 2-arg form carries special-use flags in
        the standard LIST response and works on all servers including iCloud.
        """
        imap = MagicMock(spec=imaplib.IMAP4_SSL)
        imap.list.return_value = (
            "OK",
            [self._make_list_response(r"\HasNoChildren \Trash", "Deleted Messages")],
        )

        resolve_special_use_mailbox(imap, _SPECIAL_USE_TRASH, fallback="Trash")

        imap.list.assert_called_once_with('""', '*')

    def test_standard_list_response_resolves_trash(self) -> None:
        r"""Standard LIST line with \Trash flag resolves to the mailbox name.

        Exercises the full parse path: a ``(\Trash) "/" "Deleted Messages"``
        response line is parsed by _LIST_FLAGS_RE / _LIST_MBOX_RE and the
        unquoted mailbox name is returned.
        """
        imap = MagicMock(spec=imaplib.IMAP4_SSL)
        line = rb'(\Trash) "/" "Deleted Messages"'
        imap.list.return_value = ("OK", [line])

        result = resolve_special_use_mailbox(
            imap, _SPECIAL_USE_TRASH, fallback="Trash"
        )

        self.assertEqual(result, "Deleted Messages")

    def test_empty_list_response_uses_fallback(self) -> None:
        """Empty LIST data (no matching mailbox) causes fallback to be returned."""
        imap = MagicMock(spec=imaplib.IMAP4_SSL)
        imap.list.return_value = ("OK", [])

        result = resolve_special_use_mailbox(
            imap, _SPECIAL_USE_TRASH, fallback="Deleted Messages"
        )

        self.assertEqual(result, "Deleted Messages")


if __name__ == "__main__":
    unittest.main()
