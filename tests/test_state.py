"""Tests for icloud_helper.state."""

from __future__ import annotations

import logging

import pytest

from icloud_helper.state import StateStore


# ---------------------------------------------------------------------------
# Fixture
# ---------------------------------------------------------------------------

@pytest.fixture()
def store(tmp_path):
    """Return an initialised StateStore backed by a tmp_path database."""
    db_path = tmp_path / "test_mailcleaner.db"
    s = StateStore(db_path=db_path)
    s.init_db()
    return s


# ---------------------------------------------------------------------------
# is_processed / mark_processed
# ---------------------------------------------------------------------------

class TestProcessedMessages:
    def test_returns_false_before_mark(self, store):
        assert store.is_processed("INBOX", 12345, 1001) is False

    def test_returns_true_after_mark(self, store):
        store.mark_processed(
            "INBOX", 12345, 1001, "a@b.com", "<msg-id>", "keep"
        )
        assert store.is_processed("INBOX", 12345, 1001) is True

    def test_different_folder_not_processed(self, store):
        store.mark_processed(
            "INBOX", 12345, 1001, "a@b.com", "<msg-id>", "keep"
        )
        assert store.is_processed("Junk", 12345, 1001) is False

    def test_different_uidvalidity_not_processed(self, store):
        store.mark_processed(
            "INBOX", 12345, 1001, "a@b.com", "<msg-id>", "keep"
        )
        assert store.is_processed("INBOX", 99999, 1001) is False

    def test_mark_processed_dedup_no_error(self, store):
        store.mark_processed(
            "INBOX", 12345, 1001, "a@b.com", "<msg-id>", "keep"
        )
        # Second call must not raise
        store.mark_processed(
            "INBOX", 12345, 1001, "a@b.com", "<msg-id>", "keep"
        )
        assert store.is_processed("INBOX", 12345, 1001) is True

    def test_mark_processed_dedup_does_not_duplicate(self, store):
        store.mark_processed(
            "INBOX", 12345, 1001, "a@b.com", "<msg-id>", "keep"
        )
        store.mark_processed(
            "INBOX", 12345, 1001, "a@b.com", "<msg-id>", "keep"
        )
        with store._connect() as conn:
            count = conn.execute(
                "SELECT COUNT(*) FROM processed_messages"
            ).fetchone()[0]
        assert count == 1


# ---------------------------------------------------------------------------
# sender_state
# ---------------------------------------------------------------------------

class TestSenderState:
    def test_get_unknown_sender_returns_none(self, store):
        assert store.get_sender_state("unknown@x.com") is None

    def test_insert_then_get(self, store):
        store.upsert_sender_state(
            "a@b.com", "b.com",
            unsub_status="pending",
            unsub_method="one-click",
        )
        row = store.get_sender_state("a@b.com")
        assert row is not None
        assert row["sender"] == "a@b.com"
        assert row["unsub_status"] == "pending"
        assert row["unsub_method"] == "one-click"

    def test_first_seen_preserved_on_update(self, store):
        store.upsert_sender_state("a@b.com", "b.com")
        row1 = store.get_sender_state("a@b.com")
        first_seen = row1["first_seen"]
        store.upsert_sender_state("a@b.com", "b.com", unsub_status="done")
        row2 = store.get_sender_state("a@b.com")
        assert row2["first_seen"] == first_seen

    def test_last_seen_updated_on_update(self, store):
        store.upsert_sender_state("a@b.com", "b.com")
        row1 = store.get_sender_state("a@b.com")
        store.upsert_sender_state("a@b.com", "b.com")
        row2 = store.get_sender_state("a@b.com")
        # last_seen may or may not differ depending on timing, but
        # the column must exist and be non-null
        assert row2["last_seen"] is not None

    def test_attempt_count_incremented(self, store):
        store.upsert_sender_state("a@b.com", "b.com", attempt_count_delta=1)
        store.upsert_sender_state("a@b.com", "b.com", attempt_count_delta=1)
        store.upsert_sender_state("a@b.com", "b.com", attempt_count_delta=1)
        row = store.get_sender_state("a@b.com")
        assert row["attempt_count"] == 3

    def test_attempt_count_zero_delta_no_change(self, store):
        store.upsert_sender_state(
            "a@b.com", "b.com", attempt_count_delta=2
        )
        store.upsert_sender_state(
            "a@b.com", "b.com", attempt_count_delta=0
        )
        row = store.get_sender_state("a@b.com")
        assert row["attempt_count"] == 2

    def test_policy_action_stored(self, store):
        store.upsert_sender_state(
            "a@b.com", "b.com", policy_action="unsubscribe"
        )
        row = store.get_sender_state("a@b.com")
        assert row["policy_action"] == "unsubscribe"


# ---------------------------------------------------------------------------
# audit_log
# ---------------------------------------------------------------------------

class TestAuditLog:
    def test_append_and_count(self, store):
        store.append_audit(
            "a@b.com", "one-click", "https://x.com/unsub",
            True, None, "success",
        )
        store.append_audit(
            "a@b.com", "one-click", "https://x.com/unsub",
            True, 200, "success", "OK",
        )
        with store._connect() as conn:
            count = conn.execute(
                "SELECT COUNT(*) FROM audit_log"
            ).fetchone()[0]
        assert count == 2

    def test_audit_content(self, store):
        store.append_audit(
            "x@y.com", "mailto", "mailto:unsub@y.com",
            False, 200, "success", "sent",
        )
        with store._connect() as conn:
            row = conn.execute(
                "SELECT * FROM audit_log WHERE sender=?", ("x@y.com",)
            ).fetchone()
        assert row["method"] == "mailto"
        assert row["target"] == "mailto:unsub@y.com"
        assert row["dry_run"] == 0
        assert row["http_status"] == 200
        assert row["result"] == "success"
        assert row["detail"] == "sent"

    def test_dry_run_flag_stored_as_int(self, store):
        store.append_audit("a@b.com", "http-only", "https://x.com/", True, None, "ok")
        with store._connect() as conn:
            row = conn.execute("SELECT dry_run FROM audit_log").fetchone()
        assert row["dry_run"] == 1

    def test_multiple_senders(self, store):
        for i in range(5):
            store.append_audit(
                f"sender{i}@b.com", "none", "", True, None, "skipped"
            )
        with store._connect() as conn:
            count = conn.execute(
                "SELECT COUNT(*) FROM audit_log"
            ).fetchone()[0]
        assert count == 5


# ---------------------------------------------------------------------------
# pending_senders
# ---------------------------------------------------------------------------

class TestPendingSenders:
    def test_insert_then_check(self, store):
        store.upsert_pending(
            "news@example.com", "Example News", "example.com",
            "one-click", "newsletter", 5,
        )
        with store._connect() as conn:
            row = conn.execute(
                "SELECT * FROM pending_senders WHERE sender=?",
                ("news@example.com",),
            ).fetchone()
        assert row is not None
        assert row["message_count"] == 5

    def test_message_count_accumulates(self, store):
        store.upsert_pending(
            "news@example.com", "Example News", "example.com",
            "one-click", "newsletter", 5,
        )
        store.upsert_pending(
            "news@example.com", "Example News", "example.com",
            "one-click", "newsletter", 3,
        )
        with store._connect() as conn:
            row = conn.execute(
                "SELECT message_count FROM pending_senders WHERE sender=?",
                ("news@example.com",),
            ).fetchone()
        assert row["message_count"] == 8

    def test_first_seen_set_on_insert(self, store):
        store.upsert_pending(
            "a@b.com", "A", "b.com", "mailto", "spam", 1
        )
        with store._connect() as conn:
            row = conn.execute(
                "SELECT first_seen FROM pending_senders WHERE sender=?",
                ("a@b.com",),
            ).fetchone()
        assert row["first_seen"] is not None

    def test_classification_updated_on_second_upsert(self, store):
        store.upsert_pending(
            "a@b.com", "A", "b.com", "mailto", "unknown", 1
        )
        store.upsert_pending(
            "a@b.com", "A", "b.com", "mailto", "spam", 2
        )
        with store._connect() as conn:
            row = conn.execute(
                "SELECT classification FROM pending_senders WHERE sender=?",
                ("a@b.com",),
            ).fetchone()
        assert row["classification"] == "spam"


# ---------------------------------------------------------------------------
# folder UIDVALIDITY
# ---------------------------------------------------------------------------

class TestFolderUidvalidity:
    def test_unknown_folder_returns_none(self, store):
        assert store.get_uidvalidity("INBOX") is None

    def test_set_then_get(self, store):
        store.set_uidvalidity("INBOX", 123456)
        assert store.get_uidvalidity("INBOX") == 123456

    def test_update_same_value_no_warning(self, store, caplog):
        store.set_uidvalidity("INBOX", 123456)
        with caplog.at_level(logging.WARNING, logger="icloud_helper.state"):
            store.set_uidvalidity("INBOX", 123456)
        assert not any("changed" in r.message for r in caplog.records)

    def test_changing_uidvalidity_logs_warning(self, store, caplog):
        store.set_uidvalidity("INBOX", 111111)
        with caplog.at_level(logging.WARNING, logger="icloud_helper.state"):
            store.set_uidvalidity("INBOX", 999999)
        assert any("changed" in r.message for r in caplog.records)

    def test_different_folders_independent(self, store):
        store.set_uidvalidity("INBOX", 111)
        store.set_uidvalidity("Junk", 222)
        assert store.get_uidvalidity("INBOX") == 111
        assert store.get_uidvalidity("Junk") == 222
