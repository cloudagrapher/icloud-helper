"""SQLite state store for mail-cleaner.

Provides a DAO for tracking processed messages, per-sender state,
audit log entries, and pending (unreviewed) senders.

All timestamps are ISO8601 UTC strings produced via
datetime.now(timezone.utc).isoformat().

The database file is created at ~/icloud-helper/state/mailcleaner.db
with mode 0o600 (owner read/write only).

Schema is fixed and created idempotently by StateStore.init_db().
"""

from __future__ import annotations

import logging
import os
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Generator, Optional

log = logging.getLogger(__name__)

_DEFAULT_DB_PATH = Path.home() / "icloud-helper" / "state" / "mailcleaner.db"

_DDL = """
CREATE TABLE IF NOT EXISTS processed_messages (
    folder        TEXT    NOT NULL,
    uid           INTEGER NOT NULL,
    uidvalidity   INTEGER NOT NULL,
    sender        TEXT,
    message_id    TEXT,
    processed_at  TEXT    NOT NULL,
    disposition   TEXT,
    PRIMARY KEY (folder, uidvalidity, uid)
);

CREATE INDEX IF NOT EXISTS idx_processed_message_id
    ON processed_messages (message_id);

CREATE TABLE IF NOT EXISTS sender_state (
    sender           TEXT PRIMARY KEY,
    domain           TEXT,
    first_seen       TEXT,
    last_seen        TEXT,
    unsub_status     TEXT,
    unsub_method     TEXT,
    last_attempt_at  TEXT,
    attempt_count    INTEGER DEFAULT 0,
    policy_action    TEXT
);

CREATE TABLE IF NOT EXISTS audit_log (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    ts          TEXT    NOT NULL,
    sender      TEXT,
    method      TEXT,
    target      TEXT,
    dry_run     INTEGER NOT NULL,
    http_status INTEGER,
    result      TEXT,
    detail      TEXT
);

CREATE TABLE IF NOT EXISTS pending_senders (
    sender         TEXT PRIMARY KEY,
    display_name   TEXT,
    domain         TEXT,
    unsub_method   TEXT,
    classification TEXT,
    message_count  INTEGER DEFAULT 0,
    first_seen     TEXT,
    notified_at    TEXT
);

CREATE TABLE IF NOT EXISTS folder_uidvalidity (
    folder       TEXT PRIMARY KEY,
    uidvalidity  INTEGER NOT NULL
);
"""


def _now_utc() -> str:
    """Return current UTC time as ISO8601 string."""
    return datetime.now(timezone.utc).isoformat()


class StateStore:
    """DAO for the mail-cleaner SQLite state database.

    Usage::

        store = StateStore()
        store.init_db()
        store.mark_processed("INBOX", 1001, 123456, "a@b.com", "<id>", "keep")

    Args:
        db_path: Path to the SQLite database file. Created if absent.
    """

    def __init__(
        self, db_path: Path = _DEFAULT_DB_PATH
    ) -> None:
        self._db_path = db_path

    def init_db(self) -> None:
        """Create tables and indexes idempotently.

        Also sets the database file to mode 0o600 after creation.
        """
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as conn:
            conn.executescript(_DDL)
        os.chmod(self._db_path, 0o600)
        log.info("State DB initialised at %s", self._db_path)

    @contextmanager
    def _connect(self) -> Generator[sqlite3.Connection, None, None]:
        """Context manager yielding an auto-committing connection.

        Yields:
            sqlite3.Connection with WAL journal mode enabled.
        """
        conn = sqlite3.connect(str(self._db_path))
        conn.execute("PRAGMA journal_mode=WAL")
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    # ------------------------------------------------------------------
    # processed_messages
    # ------------------------------------------------------------------

    def is_processed(
        self, folder: str, uidvalidity: int, uid: int
    ) -> bool:
        """Return True if this (folder, uidvalidity, uid) has been processed.

        Args:
            folder: Mailbox folder name.
            uidvalidity: IMAP UIDVALIDITY value for the folder.
            uid: IMAP UID of the message.

        Returns:
            True if a matching row exists.
        """
        with self._connect() as conn:
            row = conn.execute(
                "SELECT 1 FROM processed_messages "
                "WHERE folder=? AND uidvalidity=? AND uid=?",
                (folder, uidvalidity, uid),
            ).fetchone()
        return row is not None

    # pylint: disable=too-many-arguments,too-many-positional-arguments
    def mark_processed(
        self,
        folder: str,
        uidvalidity: int,
        uid: int,
        sender: str,
        message_id: str,
        disposition: str,
    ) -> None:
        """Insert a processed-message record (idempotent via INSERT OR IGNORE).

        Args:
            folder: Mailbox folder name.
            uidvalidity: IMAP UIDVALIDITY value.
            uid: IMAP UID.
            sender: Sender email address.
            message_id: Message-ID header value.
            disposition: Action taken (e.g. "keep", "unsubscribed").
        """
        with self._connect() as conn:
            conn.execute(
                "INSERT OR IGNORE INTO processed_messages "
                "(folder, uid, uidvalidity, sender, message_id, "
                " processed_at, disposition) "
                "VALUES (?,?,?,?,?,?,?)",
                (
                    folder,
                    uid,
                    uidvalidity,
                    sender,
                    message_id,
                    _now_utc(),
                    disposition,
                ),
            )

    # ------------------------------------------------------------------
    # sender_state
    # ------------------------------------------------------------------

    def get_sender_state(
        self, sender: str
    ) -> Optional[Dict[str, object]]:
        """Return the sender_state row for this sender, or None.

        Args:
            sender: Lowercase sender email address.

        Returns:
            Dict of column name -> value, or None if not found.
        """
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM sender_state WHERE sender=?", (sender,)
            ).fetchone()
        return dict(row) if row else None

    # pylint: disable=too-many-arguments,too-many-positional-arguments
    def upsert_sender_state(
        self,
        sender: str,
        domain: str,
        unsub_status: Optional[str] = None,
        unsub_method: Optional[str] = None,
        last_attempt_at: Optional[str] = None,
        attempt_count_delta: int = 0,
        policy_action: Optional[str] = None,
    ) -> None:
        """Insert or update a sender_state row.

        Sets first_seen on insert, always updates last_seen. Increments
        attempt_count by attempt_count_delta.

        Args:
            sender: Lowercase sender email address.
            domain: Sender domain.
            unsub_status: New unsub status string, if any.
            unsub_method: Unsubscribe method, if any.
            last_attempt_at: ISO8601 timestamp of last attempt, if any.
            attempt_count_delta: Amount to add to attempt_count (0 = no change).
            policy_action: Policy action string, if any.
        """
        now = _now_utc()
        with self._connect() as conn:
            existing = conn.execute(
                "SELECT attempt_count, first_seen FROM sender_state"
                " WHERE sender=?",
                (sender,),
            ).fetchone()
            if existing:
                new_count = (
                    (existing["attempt_count"] or 0) + attempt_count_delta
                )
                conn.execute(
                    """
                    UPDATE sender_state SET
                        domain=COALESCE(?,domain),
                        last_seen=?,
                        unsub_status=COALESCE(?,unsub_status),
                        unsub_method=COALESCE(?,unsub_method),
                        last_attempt_at=COALESCE(?,last_attempt_at),
                        attempt_count=?,
                        policy_action=COALESCE(?,policy_action)
                    WHERE sender=?
                    """,
                    (
                        domain or None,
                        now,
                        unsub_status,
                        unsub_method,
                        last_attempt_at,
                        new_count,
                        policy_action,
                        sender,
                    ),
                )
            else:
                conn.execute(
                    """
                    INSERT INTO sender_state
                        (sender, domain, first_seen, last_seen,
                         unsub_status, unsub_method, last_attempt_at,
                         attempt_count, policy_action)
                    VALUES (?,?,?,?,?,?,?,?,?)
                    """,
                    (
                        sender,
                        domain,
                        now,
                        now,
                        unsub_status,
                        unsub_method,
                        last_attempt_at,
                        attempt_count_delta,
                        policy_action,
                    ),
                )

    # ------------------------------------------------------------------
    # audit_log
    # ------------------------------------------------------------------

    # pylint: disable=too-many-arguments,too-many-positional-arguments
    def append_audit(
        self,
        sender: str,
        method: str,
        target: str,
        dry_run: bool,
        http_status: Optional[int],
        result: str,
        detail: str = "",
    ) -> None:
        """Append an audit log entry.

        Args:
            sender: Sender email address.
            method: Unsubscribe method used (e.g. "one-click").
            target: URL or mailto target.
            dry_run: True if this was a dry-run (no real action taken).
            http_status: HTTP response status code, or None.
            result: Outcome string (e.g. "success", "error").
            detail: Additional detail string.
        """
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO audit_log
                    (ts, sender, method, target, dry_run,
                     http_status, result, detail)
                VALUES (?,?,?,?,?,?,?,?)
                """,
                (
                    _now_utc(),
                    sender,
                    method,
                    target,
                    int(dry_run),
                    http_status,
                    result,
                    detail,
                ),
            )

    # ------------------------------------------------------------------
    # pending_senders
    # ------------------------------------------------------------------

    # pylint: disable=too-many-arguments,too-many-positional-arguments
    def upsert_pending(
        self,
        sender: str,
        display_name: str,
        domain: str,
        unsub_method: str,
        classification: str,
        message_count: int,
    ) -> None:
        """Insert or update a pending_senders row.

        Sets first_seen on insert, increments message_count on update.

        Args:
            sender: Sender email address.
            display_name: Display name from email headers.
            domain: Sender domain.
            unsub_method: Detected unsubscribe method.
            classification: Triage classification (newsletter/spam/unknown).
            message_count: Number of messages seen in this triage run.
        """
        now = _now_utc()
        with self._connect() as conn:
            existing = conn.execute(
                "SELECT message_count FROM pending_senders WHERE sender=?",
                (sender,),
            ).fetchone()
            if existing:
                conn.execute(
                    """
                    UPDATE pending_senders SET
                        display_name=COALESCE(?,display_name),
                        domain=COALESCE(?,domain),
                        unsub_method=COALESCE(?,unsub_method),
                        classification=COALESCE(?,classification),
                        message_count=message_count+?
                    WHERE sender=?
                    """,
                    (
                        display_name or None,
                        domain or None,
                        unsub_method or None,
                        classification or None,
                        message_count,
                        sender,
                    ),
                )
            else:
                conn.execute(
                    """
                    INSERT INTO pending_senders
                        (sender, display_name, domain, unsub_method,
                         classification, message_count, first_seen)
                    VALUES (?,?,?,?,?,?,?)
                    """,
                    (
                        sender,
                        display_name,
                        domain,
                        unsub_method,
                        classification,
                        message_count,
                        now,
                    ),
                )

    # ------------------------------------------------------------------
    # folder UIDVALIDITY reconciliation
    # ------------------------------------------------------------------

    def get_uidvalidity(self, folder: str) -> Optional[int]:
        """Return stored UIDVALIDITY for a folder, or None if unknown.

        Args:
            folder: Mailbox folder name.

        Returns:
            Stored UIDVALIDITY integer, or None.
        """
        with self._connect() as conn:
            row = conn.execute(
                "SELECT uidvalidity FROM folder_uidvalidity WHERE folder=?",
                (folder,),
            ).fetchone()
        return int(row["uidvalidity"]) if row else None

    def set_uidvalidity(self, folder: str, uidvalidity: int) -> None:
        """Store or update UIDVALIDITY for a folder.

        If the new value differs from the stored value, logs a WARNING
        because UIDs may have been reused (full rescan required).

        Args:
            folder: Mailbox folder name.
            uidvalidity: New UIDVALIDITY value from the IMAP server.
        """
        stored = self.get_uidvalidity(folder)
        if stored is not None and stored != uidvalidity:
            log.warning(
                "UIDVALIDITY for %r changed from %d to %d — "
                "UIDs may have been reused; deleting stale processed_messages",
                folder,
                stored,
                uidvalidity,
            )
            with self._connect() as conn:
                conn.execute(
                    "DELETE FROM processed_messages "
                    "WHERE folder=? AND uidvalidity=?",
                    (folder, stored),
                )
        with self._connect() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO folder_uidvalidity"
                " (folder, uidvalidity) VALUES (?,?)",
                (folder, uidvalidity),
            )
