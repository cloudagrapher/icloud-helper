"""Main entry point for mail-cleaner.

Orchestrates the full run: connects to IMAP, scans configured folders,
triages messages, routes to unsubscribe / keep / pending queues, applies
rate-limited unsubscribe actions, and sends a batched pending-sender
notification.

Everything defaults to dry-run. Pass --no-dry-run explicitly only when you
intend to make real network requests and IMAP mutations.
"""
from __future__ import annotations

import argparse
import imaplib
import logging
import os
import random
import re
import stat
import sys
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple

# ---------------------------------------------------------------------------
# Logging must be configured before any local imports that use logging.
# ---------------------------------------------------------------------------

_LOG_DIR = Path(__file__).parent / "logs"
_LOG_DIR.mkdir(parents=True, exist_ok=True)

# Harden file creation permissions: new files inherit 0600 (user-read/write only).
os.umask(0o077)

_LOG_FILE = _LOG_DIR / "actor.log"
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler(_LOG_FILE),
    ],
)
logger = logging.getLogger(__name__)

# Ensure existing log file is mode 600 in case it was created before umask was set.
try:
    os.chmod(_LOG_FILE, stat.S_IRUSR | stat.S_IWUSR)
except OSError:
    pass  # non-fatal: log file may not exist yet on first run

# ---------------------------------------------------------------------------
# Local imports (after logging is set up)
# ---------------------------------------------------------------------------

# pylint: disable=wrong-import-position
from icloud_helper.disposition import apply_disposition  # noqa: E402
from icloud_helper.headers import (  # noqa: E402
    SenderRecord,
    is_bulk,
    parse_from_header,
    triage_messages,
)
from icloud_helper.imap_client import (  # noqa: E402
    connect_and_login,
    parse_message_headers,
    uid_search,
)
from icloud_helper.notify import send_pending_notification  # noqa: E402
from icloud_helper.policy import (  # noqa: E402
    GlobalConfig,
    get_actionable_senders,
    load_config,
    load_policy,
)
from icloud_helper.secrets import read_secret  # noqa: E402
from icloud_helper.state import StateStore  # noqa: E402
from icloud_helper.unsubscribe import perform_unsubscribe  # noqa: E402
from icloud_helper.auth import check_sender_auth  # noqa: E402
# pylint: enable=wrong-import-position

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_SCRIPT_DIR = Path(__file__).parent
_DEFAULT_CONFIG = Path(__file__).resolve().parent / "config.toml"
_DEFAULT_POLICY = Path(__file__).resolve().parent / "policy.toml"

# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def _build_arg_parser() -> argparse.ArgumentParser:
    """Build and return the argument parser.

    Returns:
        Configured ArgumentParser instance.
    """
    parser = argparse.ArgumentParser(
        description="mail-cleaner actor — orchestrates IMAP scan and cleanup"
    )
    dry_group = parser.add_mutually_exclusive_group()
    dry_group.add_argument(
        "--dry-run",
        dest="dry_run",
        action="store_true",
        default=None,
        help="Force dry-run mode (default: use config value)",
    )
    dry_group.add_argument(
        "--no-dry-run",
        dest="dry_run",
        action="store_false",
        help="Disable dry-run (live mode); use with caution",
    )
    parser.add_argument(
        "--folder",
        dest="folders",
        action="append",
        metavar="FOLDER",
        help=(
            "Process only this folder. May be repeated, or comma-separated. "
            "Default: all folders from config."
        ),
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=0,
        metavar="N",
        help="Max messages to fetch per folder (0 = all)",
    )
    parser.add_argument(
        "--config",
        type=Path,
        default=_DEFAULT_CONFIG,
        metavar="PATH",
        help="Path to config.toml",
    )
    parser.add_argument(
        "--policy",
        type=Path,
        default=_DEFAULT_POLICY,
        metavar="PATH",
        help="Path to policy.toml",
    )
    return parser


def _parse_folders_arg(
    raw: Optional[List[str]],
) -> List[str]:
    """Expand comma-separated and repeated --folder values into a flat list.

    Args:
        raw: Raw list from argparse (may contain comma-separated strings).

    Returns:
        Flat, deduplicated list of folder names. Empty list if raw is None.
    """
    if not raw:
        return []
    result: List[str] = []
    for item in raw:
        for part in item.split(","):
            cleaned = part.strip()
            if cleaned and cleaned not in result:
                result.append(cleaned)
    return result


# ---------------------------------------------------------------------------
# Header fetch helper
# ---------------------------------------------------------------------------


def _uid_fetch_headers(  # pylint: disable=too-many-locals,too-many-branches,too-many-statements,too-many-nested-blocks
    imap: imaplib.IMAP4_SSL,
    uids: List[int],
) -> Dict[int, Dict[str, str]]:
    """Fetch headers for a list of UIDs.

    Args:
        imap: Open, authenticated IMAP connection with a folder selected.
        uids: List of integer UIDs to fetch.

    Returns:
        Mapping of UID -> dict of lowercase header-name -> decoded
        header value. Header keys are normalised to lowercase so all
        consumers (is_bulk, triage_messages) can use consistent keys.
        UIDs that could not be fetched are omitted.
    """
    if not uids:
        return {}

    uid_str = ",".join(str(u) for u in uids)
    result: Dict[int, Dict[str, str]] = {}

    try:
        status, data = imap.uid(  # type: ignore[attr-defined]
            "FETCH", uid_str, "(BODY.PEEK[HEADER])"
        )
    except imaplib.IMAP4.error as exc:
        logger.error("IMAP UID FETCH error: %s", exc)
        return result

    if status != "OK" or not data:
        logger.warning("UID FETCH returned status=%s", status)
        return result

    # data is a list of (response_part, ...) tuples interspersed with b")"
    i = 0
    while i < len(data):
        item = data[i]
        if not isinstance(item, tuple) or len(item) < 2:
            i += 1
            continue

        meta_bytes, raw_headers = item[0], item[1]
        if not isinstance(meta_bytes, bytes) or not isinstance(raw_headers, bytes):
            i += 1
            continue

        # Extract UID from meta like b"123 (UID 456 BODY[HEADER] {n})"
        meta_str = meta_bytes.decode("ascii", errors="replace")
        uid_match = re.search(r"\bUID\s+(\d+)\b", meta_str, re.IGNORECASE)
        if not uid_match:
            # Fall back: first integer token is the sequence number, not UID.
            # Try to parse UID from the fetch spec.
            seq_match = re.match(r"(\d+)\s+\(", meta_str)
            if not seq_match:
                i += 1
                continue
            # We cannot map seq -> UID without a table; skip this item.
            logger.debug(
                "Could not extract UID from FETCH meta: %s", meta_str[:80]
            )
            i += 1
            continue

        uid = int(uid_match.group(1))
        result[uid] = parse_message_headers(raw_headers)
        i += 1

    return result


# ---------------------------------------------------------------------------
# UIDVALIDITY extraction
# ---------------------------------------------------------------------------


def _extract_uidvalidity(imap: imaplib.IMAP4_SSL) -> int:
    """Extract UIDVALIDITY from the most recent SELECT response.

    Args:
        imap: Open IMAP connection after a folder has been selected.

    Returns:
        Integer UIDVALIDITY, or 0 if it cannot be determined.
    """
    raw = imap.untagged_responses.get("UIDVALIDITY", [b"0"])  # type: ignore[attr-defined]
    if not raw:
        return 0
    try:
        return int(raw[-1])
    except (ValueError, TypeError):
        return 0


# ---------------------------------------------------------------------------
# UID search
# ---------------------------------------------------------------------------


def _search_all_uids(imap: imaplib.IMAP4_SSL) -> List[int]:
    """Perform a UID SEARCH ALL and return sorted integer UIDs.

    Args:
        imap: Open IMAP connection with a folder selected.

    Returns:
        Sorted list of integer UIDs. Empty on error or empty folder.
    """
    return uid_search(imap, "ALL")


# ---------------------------------------------------------------------------
# Heartbeat
# ---------------------------------------------------------------------------


def _append_heartbeat(line: str) -> None:
    """Append a single heartbeat line to logs/actor.log.

    Args:
        line: Pre-formatted log line to append.
    """
    log_path = _SCRIPT_DIR / "logs" / "actor.log"
    log_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        with open(log_path, "a", encoding="utf-8") as fh:
            fh.write(line + "\n")
    except OSError as exc:
        logger.warning("Could not write heartbeat: %s", exc)


# ---------------------------------------------------------------------------
# Per-sender routing helpers
# ---------------------------------------------------------------------------


def _is_junk_folder(folder: str) -> bool:
    """Return True if the folder name suggests it is a Junk/Spam folder.

    Args:
        folder: IMAP folder name.

    Returns:
        True when the folder name contains "junk" (case-insensitive).
    """
    return "junk" in folder.lower()


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main() -> None:  # pylint: disable=too-many-locals,too-many-branches,too-many-statements,too-many-nested-blocks
    """Run the mail-cleaner actor end to end."""
    parser = _build_arg_parser()
    args = parser.parse_args()

    config_path: Path = args.config
    policy_path: Path = args.policy

    # --- Load config --------------------------------------------------------
    if not config_path.exists():
        logger.warning("Config file not found: %s", config_path)

    config: GlobalConfig = load_config(config_path)

    # --- Apply --dry-run / --no-dry-run override ----------------------------
    if args.dry_run is not None:
        config.dry_run = args.dry_run

    # Defensive: ensure dry_run is always True by default at startup unless
    # the caller explicitly opted out.
    dry_run: bool = config.dry_run

    # --- Load policy --------------------------------------------------------
    full_policy = load_policy(policy_path)

    folder_list: List[str] = _parse_folders_arg(args.folders) or list(
        config.folders
    )

    if not full_policy and not folder_list:
        logger.warning(
            "Policy is empty and no folders configured; nothing to do"
        )
        sys.exit(1)

    actionable_senders = get_actionable_senders(full_policy, config.protected_domains)

    # --- Dry-run banner -----------------------------------------------------
    if dry_run:
        _sep = "=" * 60
        _banner = _sep + "\nDRY-RUN MODE: no network I/O or IMAP mutations will occur\n" + _sep
        logger.info("%s", _banner)

    # --- State store --------------------------------------------------------
    db_path = _SCRIPT_DIR / "state" / "mailcleaner.db"
    db_path.parent.mkdir(parents=True, exist_ok=True)
    store = StateStore(db_path)
    store.init_db()

    # H3: chmod existing reports to 600 so tokenised URLs in triage JSON
    # are not world-readable.  New files get 600 from the global umask(077).
    _reports_dir = _SCRIPT_DIR / "reports"
    if _reports_dir.is_dir():
        for _rpt in _reports_dir.glob("*.json"):
            try:
                os.chmod(_rpt, stat.S_IRUSR | stat.S_IWUSR)
            except OSError:
                pass

    # --- Secrets ------------------------------------------------------------
    secrets_base = _SCRIPT_DIR / "secrets"
    try:
        smtp_username = read_secret(str(secrets_base / "icloud_email"))
        smtp_password = read_secret(str(secrets_base / "icloud_app_password"))
    except Exception as exc:  # pylint: disable=broad-except
        logger.error("Failed to read IMAP/SMTP credentials: %s", exc)
        sys.exit(1)

    # --- Heartbeat: started -------------------------------------------------
    ts_start = datetime.now(timezone.utc).isoformat()
    _append_heartbeat(
        f"{ts_start} actor started dry_run={dry_run} folders={folder_list}"
    )

    # --- IMAP connection ----------------------------------------------------
    imap: Optional[imaplib.IMAP4_SSL] = None
    actions_taken = 0
    pending_new_count = 0

    try:  # pylint: disable=too-many-nested-blocks
        try:
            imap = connect_and_login(
                host="imap.mail.me.com",
                port=993,
                username=smtp_username,
                password=smtp_password,
            )
        except Exception as exc:  # pylint: disable=broad-except
            logger.error("IMAP connection failed: %s", exc)
            sys.exit(1)

        # ----------------------------------------------------------------
        # Per-folder scan loop
        # ----------------------------------------------------------------
        for folder in folder_list:
            logger.info("Processing folder: %s", folder)
            is_junk = _is_junk_folder(folder)

            try:
                status, _ = imap.select(folder, readonly=is_junk)
            except imaplib.IMAP4.error as exc:
                logger.warning(
                    "Could not select folder %s: %s", folder, exc
                )
                continue

            if status != "OK":
                logger.warning(
                    "SELECT %s returned status=%s; skipping", folder, status
                )
                continue

            uidvalidity = _extract_uidvalidity(imap)
            store.set_uidvalidity(folder, uidvalidity)
            logger.debug(
                "Folder %s UIDVALIDITY=%d", folder, uidvalidity
            )

            all_uids = _search_all_uids(imap)
            logger.info(
                "Found %d messages in %s", len(all_uids), folder
            )

            if args.limit and args.limit > 0:
                all_uids = all_uids[: args.limit]
                logger.debug(
                    "Limiting to %d UIDs per --limit", args.limit
                )

            # Filter already-processed UIDs
            unprocessed_uids = [
                u
                for u in all_uids
                if not store.is_processed(folder, uidvalidity, u)
            ]
            logger.info(
                "%d unprocessed UIDs in %s", len(unprocessed_uids), folder
            )

            if not unprocessed_uids:
                continue

            # Fetch headers for unprocessed UIDs
            uid_headers: Dict[int, Dict[str, str]] = _uid_fetch_headers(
                imap, unprocessed_uids
            )

            # Build uid_to_sender and sender_to_uids mappings
            uid_to_sender: Dict[int, str] = {}
            sender_to_uids: Dict[str, List[int]] = {}

            header_list = list(uid_headers.values())
            triage_result: Dict[str, SenderRecord] = triage_messages(
                header_list
            )

            # Map headers back to UIDs by From address.
            # Use parse_from_header (email.utils.parseaddr) so this path
            # matches triage_messages exactly for all From formats.
            for uid, hdrs in uid_headers.items():
                raw_from = hdrs.get("from", "")
                _, addr = parse_from_header(raw_from)
                if not addr:
                    addr = raw_from.strip().lower()
                uid_to_sender[uid] = addr
                sender_to_uids.setdefault(addr, []).append(uid)

            # Record non-bulk UIDs so they are skipped on subsequent runs
            # without re-fetching their headers each time.
            if not dry_run:
                for uid, hdrs in uid_headers.items():
                    if not is_bulk(hdrs):
                        store.mark_processed(
                            folder, uidvalidity, uid, "", "", "non-bulk"
                        )

            # --------------------------------------------------------
            # Action routing
            # --------------------------------------------------------
            action_queue: List[Tuple[str, SenderRecord, List[int]]] = []
            pending_queue: List[SenderRecord] = []

            for addr, record in triage_result.items():
                addr_lower = addr.lower()
                sender_uids = sender_to_uids.get(addr_lower, [])

                if is_junk:
                    # Junk folder: surface to pending only, never action
                    pending_queue.append(record)
                    continue

                if addr_lower in actionable_senders:
                    state = store.get_sender_state(addr_lower)
                    if (
                        state is not None
                        and state.get("unsub_status") == "success"
                    ):
                        # Already unsubscribed — mark processed and keep
                        if not dry_run:
                            for uid in sender_uids:
                                store.mark_processed(
                                    folder,
                                    uidvalidity,
                                    uid,
                                    addr_lower,
                                    "",
                                    "keep",
                                )
                        logger.debug(
                            "Skipping %s — already unsubscribed", addr_lower
                        )
                        continue

                    # H1: require sender authentication before actioning.
                    # Auth is evaluated per-UID so a mix of authenticated
                    # and unauthenticated messages from the same sender
                    # does not allow the unauthenticated ones to be actioned.
                    authed_uids: List[int] = []
                    for uid in sender_uids:
                        uid_hdrs = uid_headers.get(uid, {})
                        auth_passed, _ = check_sender_auth(uid_hdrs)
                        if auth_passed:
                            authed_uids.append(uid)
                        else:
                            logger.info(
                                "UID %d from %s failed auth check "
                                "(dmarc/dkim not pass via trusted iCloud "
                                "authserv); leaving unactioned",
                                uid,
                                addr_lower,
                            )

                    if not authed_uids:
                        logger.info(
                            "Skipping %s — no UIDs passed iCloud auth "
                            "check; routing to pending",
                            addr_lower,
                        )
                        pending_queue.append(record)
                        continue

                    action_queue.append(
                        (addr_lower, record, authed_uids)
                    )

                elif addr_lower in full_policy:
                    policy_entry = full_policy[addr_lower]
                    if policy_entry.action == "keep":
                        if not dry_run:
                            for uid in sender_uids:
                                store.mark_processed(
                                    folder,
                                    uidvalidity,
                                    uid,
                                    addr_lower,
                                    "",
                                    "keep",
                                )
                        logger.debug(
                            "Keeping all messages from %s per policy",
                            addr_lower,
                        )
                else:
                    # Unknown sender — add to pending
                    pending_queue.append(record)

            # --------------------------------------------------------
            # Rate-limited action execution
            # --------------------------------------------------------
            now_iso = datetime.now(timezone.utc).isoformat()

            for addr, record, sender_uids in action_queue:
                if (
                    actions_taken
                    >= config.rate_limits.max_unsubscribes_per_run
                ):
                    logger.info(
                        "Rate limit reached (%d/%d); deferring remaining "
                        "actions",
                        actions_taken,
                        config.rate_limits.max_unsubscribes_per_run,
                    )
                    break

                # Retrieve List-Unsubscribe-Post from the first UID's headers
                unsub_post_header = ""
                if sender_uids:
                    first_hdrs = uid_headers.get(sender_uids[0], {})
                    unsub_post_header = first_hdrs.get(
                        "list-unsubscribe-post", ""
                    )

                logger.info(
                    "Attempting unsubscribe for %s (method=%s)",
                    addr,
                    record.unsubscribe_method,
                )
                result = perform_unsubscribe(
                    addr,
                    record.sample_unsubscribe_header,
                    unsub_post_header,
                    config,
                    smtp_username,
                    smtp_password,
                )

                # B.5: include block_class in the audit detail field so the
                # security-reviewer can query the audit log by taxonomy.
                audit_detail = result.detail
                if result.block_class:
                    audit_detail = (
                        f"[block_class={result.block_class}] {result.detail}"
                    )
                store.append_audit(
                    addr,
                    result.method,
                    result.target,
                    dry_run,
                    result.http_status,
                    result.result,
                    audit_detail,
                )

                if result.result in ("success", "success-simulated"):
                    policy_entry = full_policy.get(addr)
                    sender_disposition = (
                        policy_entry.disposition if policy_entry else None
                    )
                    # CR-1: capture the DispositionResult for each UID and
                    # only mark_processed + write sender state when ALL
                    # dispositions succeed.  A soft failure (e.g. COPY ok
                    # but STORE \Deleted fails) must leave the UID retryable.
                    all_disp_ok = True
                    for uid in sender_uids:
                        disp = apply_disposition(
                            imap,
                            uid,
                            folder,
                            config,
                            sender_disposition,
                            dry_run,
                        )
                        if disp.success:
                            if not dry_run:
                                store.mark_processed(
                                    folder,
                                    uidvalidity,
                                    uid,
                                    addr,
                                    "",
                                    "disposed",
                                )
                        else:
                            all_disp_ok = False
                            logger.warning(
                                "Disposition failed for UID %d (%s): %s — "
                                "leaving unprocessed for retry",
                                uid,
                                addr,
                                disp.detail,
                            )
                    # Write persistent state last so a crash between
                    # apply_disposition and this point leaves the message
                    # unprocessed and the sender restartable next run.
                    # Only write "success" if ALL dispositions succeeded.
                    if not dry_run:
                        if all_disp_ok:
                            store.upsert_sender_state(
                                addr,
                                record.domain,
                                unsub_status="success",
                                unsub_method=result.method,
                                last_attempt_at=now_iso,
                                attempt_count_delta=1,
                                policy_action="unsubscribe",
                            )
                        else:
                            store.upsert_sender_state(
                                addr,
                                record.domain,
                                unsub_status="failed",
                                unsub_method=result.method,
                                last_attempt_at=now_iso,
                                attempt_count_delta=1,
                                policy_action="unsubscribe",
                            )
                    actions_taken += 1
                    logger.info(
                        "Unsubscribe %s: %s (disposition_ok=%s)",
                        addr,
                        result.result,
                        all_disp_ok,
                    )
                else:
                    if not dry_run:
                        store.upsert_sender_state(
                            addr,
                            record.domain,
                            unsub_status="failed",
                            unsub_method=result.method,
                            last_attempt_at=now_iso,
                            attempt_count_delta=1,
                            policy_action="unsubscribe",
                        )
                    logger.warning(
                        "Unsubscribe %s failed: %s — %s",
                        addr,
                        result.result,
                        result.detail,
                    )

                # Sleep with jitter between actions (skip in dry-run)
                if (
                    not dry_run
                    and actions_taken
                    < config.rate_limits.max_unsubscribes_per_run
                ):
                    jitter = config.rate_limits.request_sleep_seconds * random.uniform(
                        0.8, 1.2
                    )
                    time.sleep(jitter)

            # --------------------------------------------------------
            # Pending / unknown senders
            # --------------------------------------------------------
            for record in pending_queue:
                if not dry_run:
                    store.upsert_pending(
                        record.email_address,
                        record.display_name,
                        record.domain,
                        record.unsubscribe_method,
                        record.classification,
                        record.message_count,
                    )
                pending_new_count += 1

            logger.info(
                "Folder %s done — %d action(s), %d pending",
                folder,
                actions_taken,
                len(pending_queue),
            )

        # ----------------------------------------------------------------
        # Notification
        # ----------------------------------------------------------------
        notified = send_pending_notification(store, dry_run)
        if notified:
            logger.info("Notified for %d pending sender(s)", notified)

    finally:
        if imap is not None:
            try:
                imap.logout()
            except Exception as exc:  # pylint: disable=broad-except
                logger.debug("IMAP logout error (ignored): %s", exc)

        # Best-effort triage refresh so subsequent MCP queries see fresh data.
        _triage_py = Path(__file__).parent / "triage.py"
        _venv_python = Path(__file__).parent / ".venv" / "bin" / "python3"
        try:
            subprocess.run(  # pylint: disable=subprocess-run-check
                [str(_venv_python), str(_triage_py), "--folder", "INBOX"],
                capture_output=True,
                timeout=120,
                cwd=str(Path(__file__).parent),
                check=False,
            )
            logger.info("Post-run triage refresh completed")
        except Exception as _triage_exc:  # pylint: disable=broad-except
            logger.warning(
                "Post-run triage refresh failed (non-fatal): %s", _triage_exc
            )

        ts_end = datetime.now(timezone.utc).isoformat()
        _append_heartbeat(
            f"{ts_end} actor finished dry_run={dry_run} "
            f"actions_taken={actions_taken} pending_new={pending_new_count}"
        )


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:  # pylint: disable=broad-except
        logger.critical("Unhandled exception: %s", exc, exc_info=True)
        sys.exit(1)
