"""IMAP-based mail disposition: mark-read, move, and soft-delete."""
from __future__ import annotations

import base64
import dataclasses
import imaplib
import logging
import re
from typing import Optional

from icloud_helper.policy import GlobalConfig

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# IMAP mailbox name helpers
# ---------------------------------------------------------------------------

# RFC 3501 §9: modified UTF-7 base64 alphabet uses '+' not '/' as shift char.
_MBOX_SAFE = re.compile(r'^[\x20-\x7e]*$')  # printable ASCII including space


def _modified_utf7(name: str) -> str:
    """Encode a mailbox name using IMAP modified-UTF-7 (RFC 3501 §5.1.3).

    Modified-UTF-7 represents non-ASCII characters as ``&<base64>-`` where
    the base64 alphabet replaces ``/`` with ``,``.  ASCII printable characters
    (excluding ``&``) are passed through unchanged; ``&`` is represented as
    ``&-``.

    Args:
        name: Mailbox name string (may contain non-ASCII codepoints).

    Returns:
        Modified-UTF-7 encoded string (pure ASCII).
    """
    result: list[str] = []
    non_ascii_buf: list[str] = []

    def _flush_buf() -> None:
        if non_ascii_buf:
            raw = "".join(non_ascii_buf).encode("utf-16-be")
            b64 = base64.b64encode(raw).decode("ascii").replace("/", ",")
            result.append(f"&{b64}-")
            non_ascii_buf.clear()

    for ch in name:
        if ch == "&":
            _flush_buf()
            result.append("&-")
        elif "\x20" <= ch <= "\x7e":
            _flush_buf()
            result.append(ch)
        else:
            non_ascii_buf.append(ch)

    _flush_buf()
    return "".join(result)


def _encode_mailbox(name: str) -> str:
    """Encode an IMAP mailbox name and wrap it in double-quotes.

    All mailbox arguments to MOVE, COPY, and CREATE must go through this
    function.  It handles two concerns:

    1. **Quoting**: imaplib does not auto-quote mailbox names that contain
       spaces or other special characters.  Without quotes,
       ``UID MOVE 81713 Deleted Messages`` causes iCloud to parse ``Deleted``
       as the mailbox and choke on ``Messages`` → ``BAD Parse Error``.
    2. **Encoding**: Non-ASCII names are encoded to IMAP modified-UTF-7
       (RFC 3501 §5.1.3) so the IMAP command stays 7-bit clean.

    The result is always a double-quoted string, e.g.
    ``"Deleted Messages"`` or ``"Gel&APY=-schte Objekte"``.

    Args:
        name: The human-readable mailbox name (UTF-8 / ASCII).

    Returns:
        A double-quoted, 7-bit IMAP mailbox string.
    """
    if _MBOX_SAFE.match(name):
        # Pure ASCII printable: escape any embedded double-quotes and wrap.
        escaped = name.replace("\\", "\\\\").replace('"', '\\"')
        return f'"{escaped}"'

    # Non-ASCII: apply IMAP modified-UTF-7 encoding.
    encoded = _modified_utf7(name)
    return f'"{encoded}"'


# RFC 3501 SPECIAL-USE flag we care about, as returned by LIST.
_SPECIAL_USE_TRASH = r"\Trash"
_SPECIAL_USE_ARCHIVE = r"\Archive"

# Pattern to extract the special-use attribute from a LIST response line, e.g.
#   (\HasNoChildren \Trash) "/" "Deleted Messages"
_LIST_FLAGS_RE = re.compile(r'\(([^)]*)\)')
_LIST_MBOX_RE = re.compile(r'"([^"]+)"\s*$|(\S+)\s*$')


def resolve_special_use_mailbox(
    imap: imaplib.IMAP4_SSL,
    special_use_flag: str,
    fallback: str,
) -> str:
    """Return the server's mailbox for *special_use_flag*, or *fallback*.

    Queries ``LIST "" "*"`` and scans the response for the requested
    attribute (e.g. ``\\Trash`` or ``\\Archive``).  Standard LIST responses
    include special-use flags (RFC 6154), so the plain two-argument form
    works on all servers including iCloud.  The three-argument
    ``LIST (SPECIAL-USE) "" "*"`` form is not a valid imaplib call and
    silently produces no results.  If the server reports a matching mailbox,
    that name is returned; otherwise *fallback* is returned unchanged.  Any
    IMAP error silently returns *fallback* so callers always get a usable
    name.

    Args:
        imap: Authenticated IMAP4_SSL connection (any folder state).
        special_use_flag: RFC 6154 attribute, e.g. ``r"\\Trash"``.
        fallback: Config-supplied folder name used when lookup fails.

    Returns:
        Server mailbox name (unquoted plain string), or *fallback*.
    """
    try:
        status, data = imap.list('""', '*')
        if status != "OK" or not data:
            return fallback
        for item in data:
            if item is None:
                continue
            line = item.decode("ascii", errors="replace") if isinstance(
                item, bytes
            ) else str(item)
            flags_match = _LIST_FLAGS_RE.search(line)
            if not flags_match:
                continue
            flags = flags_match.group(1)
            # Case-insensitive match on the special-use flag.
            if special_use_flag.lower() not in flags.lower():
                continue
            # Extract the mailbox name — last token, possibly quoted.
            mbox_match = _LIST_MBOX_RE.search(line)
            if not mbox_match:
                continue
            mbox_name = mbox_match.group(1) or mbox_match.group(2)
            if mbox_name:
                logger.debug(
                    "Special-use %s resolved to %r", special_use_flag, mbox_name
                )
                return mbox_name
    except Exception:  # pylint: disable=broad-except
        logger.debug(
            "Special-use LIST for %s failed; using fallback %r",
            special_use_flag, fallback,
        )
    return fallback


@dataclasses.dataclass
class DispositionResult:
    """Result of a mail disposition action.

    Attributes:
        folder: The source IMAP folder.
        uid: The message UID acted upon.
        action: The disposition action taken.
        success: Whether the action succeeded.
        detail: Additional detail about the outcome.
    """

    folder: str
    uid: int
    action: str  # "mark_read"|"move_to_unsubscribed"|"soft_delete"|"skipped"|"dry_run"
    success: bool
    detail: str = ""


def mark_message_read(
    imap: imaplib.IMAP4_SSL,
    uid: int,
    dry_run: bool,
    folder: str = "",
) -> DispositionResult:
    """Mark a message as read via IMAP UID STORE.

    Args:
        imap: Authenticated IMAP4_SSL connection with the target folder
            selected in READ-WRITE mode.
        uid: The message UID to mark as read.
        dry_run: If True, return without issuing any IMAP commands.
        folder: Source folder name for result metadata.

    Returns:
        DispositionResult describing the outcome.
    """
    if dry_run:
        logger.info(
            "DRY RUN: would mark UID %d as read in %s", uid, folder
        )
        return DispositionResult(
            folder=folder,
            uid=uid,
            action="dry_run",
            success=True,
            detail="would mark read",
        )

    try:
        status, _data = imap.uid("STORE", str(uid), "+FLAGS", r"(\Seen)")
    except imaplib.IMAP4.error as exc:
        logger.error("IMAP error marking UID %d as read: %s", uid, exc)
        return DispositionResult(
            folder=folder,
            uid=uid,
            action="mark_read",
            success=False,
            detail=str(exc),
        )

    if status != "OK":
        logger.warning(
            "IMAP STORE returned %s for UID %d; expected OK", status, uid
        )
        return DispositionResult(
            folder=folder,
            uid=uid,
            action="mark_read",
            success=False,
            detail=f"STORE status={status}",
        )

    logger.info("Marked UID %d as read in %s", uid, folder)
    return DispositionResult(
        folder=folder, uid=uid, action="mark_read", success=True,
    )


def move_to_folder(
    imap: imaplib.IMAP4_SSL,
    uid: int,
    target_folder: str,
    dry_run: bool,
    source_folder: str = "",
) -> DispositionResult:
    """Move a message to a target IMAP folder.

    Attempts RFC 6851 UID MOVE first; falls back to COPY + flag-deleted if
    MOVE is unsupported. Never calls EXPUNGE.

    Args:
        imap: Authenticated IMAP4_SSL connection with the source folder
            selected in READ-WRITE mode.
        uid: The message UID to move.
        target_folder: Destination IMAP folder name.
        dry_run: If True, return without issuing any IMAP commands.
        source_folder: Source folder name for result metadata.

    Returns:
        DispositionResult describing the outcome.
    """
    if dry_run:
        logger.info(
            "DRY RUN: would move UID %d from %s to %s",
            uid, source_folder, target_folder,
        )
        return DispositionResult(
            folder=source_folder,
            uid=uid,
            action="dry_run",
            success=True,
            detail=f"would move to {target_folder}",
        )

    encoded_target = _encode_mailbox(target_folder)

    try:
        imap.create(encoded_target)
    except imaplib.IMAP4.error as exc:
        logger.debug(
            "Folder create for %s: %s (may be ALREADYEXISTS)",
            target_folder, exc,
        )

    try:
        status, _data = imap.uid("MOVE", str(uid), encoded_target)
        if status == "OK":
            logger.info(
                "Moved UID %d to %s via MOVE", uid, target_folder
            )
            return DispositionResult(
                folder=source_folder,
                uid=uid,
                action="move_to_unsubscribed",
                success=True,
                detail=f"moved to {target_folder} via MOVE",
            )
        raise imaplib.IMAP4.error(f"MOVE returned {status}")
    except imaplib.IMAP4.error as exc:
        logger.info(
            "MOVE not available for UID %d (%s); falling back to COPY+DELETE",
            uid, exc,
        )

    try:
        copy_status, _cd = imap.uid("COPY", str(uid), encoded_target)
        if copy_status != "OK":
            logger.error(
                "COPY failed for UID %d to %s: status=%s",
                uid, target_folder, copy_status,
            )
            return DispositionResult(
                folder=source_folder,
                uid=uid,
                action="move_to_unsubscribed",
                success=False,
                detail=f"COPY status={copy_status}",
            )

        store_status, _sd = imap.uid(
            "STORE", str(uid), "+FLAGS", r"(\Deleted)"
        )
        if store_status != "OK":
            logger.warning(
                "STORE +FLAGS \\Deleted returned %s for UID %d; "
                "message may be stranded in source folder",
                store_status, uid,
            )
            return DispositionResult(
                folder=source_folder,
                uid=uid,
                action="move_to_unsubscribed",
                success=False,
                detail=f"STORE \\Deleted status={store_status}",
            )

        logger.info(
            "Moved UID %d to %s via COPY+DELETE", uid, target_folder
        )
        return DispositionResult(
            folder=source_folder,
            uid=uid,
            action="move_to_unsubscribed",
            success=True,
            detail=f"moved to {target_folder} via COPY+DELETE",
        )
    except imaplib.IMAP4.error as exc:
        logger.error(
            "COPY+DELETE fallback failed for UID %d: %s", uid, exc
        )
        return DispositionResult(
            folder=source_folder,
            uid=uid,
            action="move_to_unsubscribed",
            success=False,
            detail=str(exc),
        )


def soft_delete(  # pylint: disable=too-many-arguments,too-many-positional-arguments
    imap: imaplib.IMAP4_SSL,
    uid: int,
    trash_folder: str,
    global_config: GlobalConfig,
    sender_disposition: Optional[str],
    dry_run: bool,
    source_folder: str = "",
) -> DispositionResult:
    """Move a message to Trash if both safety gates pass.

    Both conditions must be True before any IMAP command is issued:
    global_config.allow_delete must be True AND sender_disposition must
    equal "delete".

    Args:
        imap: Authenticated IMAP4_SSL connection with the source folder
            selected in READ-WRITE mode.
        uid: The message UID to soft-delete.
        trash_folder: Destination trash folder name.
        global_config: Global policy; checked for allow_delete flag.
        sender_disposition: Per-sender disposition override.
        dry_run: If True, return without issuing any IMAP commands.
        source_folder: Source folder name for result metadata.

    Returns:
        DispositionResult; action="skipped" if either safety gate fails.
    """
    if not global_config.allow_delete:
        logger.info(
            "Skipping delete for UID %d: allow_delete=false", uid
        )
        return DispositionResult(
            folder=source_folder,
            uid=uid,
            action="skipped",
            success=True,
            detail="allow_delete=false; delete refused",
        )

    if sender_disposition != "delete":
        logger.info(
            "Skipping delete for UID %d: sender_disposition=%r",
            uid, sender_disposition,
        )
        return DispositionResult(
            folder=source_folder,
            uid=uid,
            action="skipped",
            success=True,
            detail=(
                f"sender_disposition={sender_disposition!r}; "
                "delete not requested"
            ),
        )

    if dry_run:
        logger.info(
            "DRY RUN: would soft-delete UID %d to %s", uid, trash_folder
        )
        return DispositionResult(
            folder=source_folder,
            uid=uid,
            action="dry_run",
            success=True,
            detail=f"would move to {trash_folder}",
        )

    move_result = move_to_folder(
        imap, uid, trash_folder, dry_run=False, source_folder=source_folder
    )
    return DispositionResult(
        folder=move_result.folder,
        uid=move_result.uid,
        action="soft_delete",
        success=move_result.success,
        detail=move_result.detail,
    )


def apply_disposition(  # pylint: disable=too-many-arguments,too-many-positional-arguments
    imap: imaplib.IMAP4_SSL,
    uid: int,
    folder: str,
    global_config: GlobalConfig,
    sender_disposition: Optional[str],
    dry_run: bool,
) -> DispositionResult:
    """Apply the effective disposition policy to a single message.

    The effective disposition is sender_disposition if non-empty, otherwise
    global_config.disposition.

    Args:
        imap: Authenticated IMAP4_SSL connection with the folder selected
            in READ-WRITE mode.
        uid: The message UID to act upon.
        folder: The source IMAP folder name.
        global_config: Global policy configuration.
        sender_disposition: Per-sender disposition override; may be None.
        dry_run: If True, simulate without issuing IMAP commands.

    Returns:
        DispositionResult describing the action taken.
    """
    effective = (
        sender_disposition if sender_disposition else global_config.disposition
    )

    try:
        if effective == "mark_read":
            return mark_message_read(imap, uid, dry_run, folder=folder)

        if effective == "move_to_unsubscribed":
            return move_to_folder(
                imap, uid, "Unsubscribed", dry_run, source_folder=folder
            )

        if effective == "archive":
            archive_folder = getattr(
                getattr(global_config, "actions", None),
                "archive_folder",
                "Archive",
            )
            archive_folder = resolve_special_use_mailbox(
                imap, _SPECIAL_USE_ARCHIVE, archive_folder
            )
            return move_to_folder(
                imap, uid, archive_folder, dry_run, source_folder=folder
            )

        if effective == "delete":
            trash_folder = getattr(
                getattr(global_config, "actions", None),
                "trash_folder",
                "Deleted Messages",
            )
            trash_folder = resolve_special_use_mailbox(
                imap, _SPECIAL_USE_TRASH, trash_folder
            )
            return soft_delete(
                imap, uid, trash_folder, global_config,
                sender_disposition, dry_run, source_folder=folder,
            )

    except imaplib.IMAP4.error as exc:
        logger.error(
            "IMAP error applying disposition %r to UID %d: %s",
            effective, uid, exc,
        )
        return DispositionResult(
            folder=folder,
            uid=uid,
            action=str(effective),
            success=False,
            detail=str(exc),
        )

    logger.warning(
        "Unknown disposition %r for UID %d in %s; skipping",
        effective, uid, folder,
    )
    return DispositionResult(
        folder=folder,
        uid=uid,
        action="skipped",
        success=True,
        detail=f"unknown disposition: {effective!r}",
    )
