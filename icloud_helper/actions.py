"""Read-write IMAP action primitives for icloud-helper.

This module owns all read-write IMAP access.  It is the only place in
the package that opens a read-write IMAP session.  flagged.py retains
its read-only contract and is never imported here for write purposes.

Actions:
- move_message: RFC 6851 MOVE (COPY+FLAG fallback, no EXPUNGE).
- trash_message: Move to the configured trash folder (MOVE only; same
  no-EXPUNGE guarantee).

All callers must validate the folder allowlist and uidvalidity BEFORE
calling into this module.  This module trusts its inputs.

Compatible with Python 3.9 (.venv) and Python 3.13 (.venv-mcp).
"""

from __future__ import annotations

import imaplib
import logging
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator, Tuple

from icloud_helper.disposition import (
    DispositionResult,
    move_to_folder,
    resolve_special_use_mailbox,
    _SPECIAL_USE_ARCHIVE,
    _SPECIAL_USE_TRASH,
)
from icloud_helper.flagged import get_uidvalidity
from icloud_helper.imap_client import (
    connect_and_login,
    select_folder_readwrite,
)
from icloud_helper.secrets import read_secret

log = logging.getLogger(__name__)

_IMAP_HOST = "imap.mail.me.com"
_IMAP_PORT = 993


class ActionsError(Exception):
    """Raised when open_readwrite_session encounters a fatal error.

    Mirrors FlaggedError in flagged.py.  Callers should catch this rather
    than SystemExit so a credential or IMAP failure does not kill the
    shared MCP server process.
    """


@contextmanager
def open_readwrite_session(
    folder: str,
    secrets_base: Path,
) -> Iterator[Tuple[imaplib.IMAP4_SSL, int]]:
    """Open a read-write IMAP session and yield (imap, uidvalidity).

    Credentials are read from ``secrets_base/icloud_email`` and
    ``secrets_base/icloud_app_password``.  The folder is selected in
    read-write mode so MOVE and STORE commands are available.

    The connection is always logged out on exit, even if the body raises.

    Any ``SystemExit`` raised by ``read_secret``, ``connect_and_login``, or
    ``select_folder_readwrite`` is converted to ``ActionsError`` so that
    transient credential/IMAP failures do not kill the shared stdio MCP
    server process.

    Args:
        folder: IMAP mailbox folder to select (read-write).
        secrets_base: Directory containing ``icloud_email`` and
            ``icloud_app_password`` secrets files.

    Yields:
        Tuple of (authenticated IMAP4_SSL connection, UIDVALIDITY integer).

    Raises:
        ActionsError: On credential read failure, connection failure,
            login failure, or folder-selection failure.
    """
    try:
        username = read_secret(secrets_base / "icloud_email")
        password = read_secret(secrets_base / "icloud_app_password")
    except SystemExit as exc:
        raise ActionsError("could not read IMAP credentials") from exc

    try:
        imap = connect_and_login(_IMAP_HOST, _IMAP_PORT, username, password)
    except SystemExit as exc:
        raise ActionsError("imap connect/login failed") from exc

    try:
        try:
            select_folder_readwrite(imap, folder)
        except SystemExit as exc:
            raise ActionsError("folder selection failed") from exc
        uidvalidity = get_uidvalidity(imap)
        yield imap, uidvalidity
    finally:
        try:
            imap.logout()
        except Exception:  # pylint: disable=broad-except
            pass


def move_message(
    imap: imaplib.IMAP4_SSL,
    uid: int,
    dest_folder: str,
    source_folder: str,
) -> DispositionResult:
    """Move a single message to ``dest_folder`` via RFC 6851 MOVE.

    Falls back to COPY + STORE \\Deleted if the server does not support
    MOVE.  EXPUNGE is never issued — the fallback leaves a struck-through
    copy in the source folder (reversible via undelete/expunge from the
    client side if needed).

    Attempts special-use resolution for archive destinations: if the server
    advertises a ``\\Archive`` mailbox via LIST (SPECIAL-USE), it takes
    precedence over the caller-supplied name.

    Args:
        imap: Authenticated IMAP4_SSL connection with ``source_folder``
            selected in read-write mode.
        uid: Message UID to move.
        dest_folder: Destination IMAP folder name (plain, unquoted).
        source_folder: Source folder name for result metadata and logs.

    Returns:
        DispositionResult with action ``"move_to_unsubscribed"`` on
        success (re-uses the existing action label from disposition.py).
    """
    resolved = resolve_special_use_mailbox(
        imap, _SPECIAL_USE_ARCHIVE, dest_folder
    )
    # dry_run=False because callers have already checked the confirmed gate.
    return move_to_folder(
        imap,
        uid,
        resolved,
        dry_run=False,
        source_folder=source_folder,
    )


def trash_message(
    imap: imaplib.IMAP4_SSL,
    uid: int,
    trash_folder: str,
    source_folder: str,
) -> DispositionResult:
    """Move a single message to the trash folder.

    Uses the same RFC 6851 MOVE + COPY+FLAG fallback path as
    move_message.  EXPUNGE is never issued.

    Attempts special-use resolution: if the server advertises a ``\\Trash``
    mailbox via LIST (SPECIAL-USE), that name is used instead of the
    caller-supplied ``trash_folder``.  Falls back to ``trash_folder``
    (now correctly quoted via ``_encode_mailbox``) when resolution fails.

    Args:
        imap: Authenticated IMAP4_SSL connection with ``source_folder``
            selected in read-write mode.
        uid: Message UID to trash.
        trash_folder: Destination trash folder name (plain, unquoted,
            from config).
        source_folder: Source folder name for result metadata.

    Returns:
        DispositionResult with action ``"trash"`` and detail indicating
        the resolved trash destination.
    """
    resolved = resolve_special_use_mailbox(
        imap, _SPECIAL_USE_TRASH, trash_folder
    )
    result = move_to_folder(
        imap,
        uid,
        resolved,
        dry_run=False,
        source_folder=source_folder,
    )
    # Relabel the action so callers can distinguish trash from generic move.
    return DispositionResult(
        folder=result.folder,
        uid=result.uid,
        action="trash",
        success=result.success,
        detail=result.detail,
    )
