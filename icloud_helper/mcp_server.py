"""stdio MCP server wrapping core icloud-helper modules.

Exposes read and action tools for the icloud-helper project via the FastMCP
interface. All action tools are guarded: they refuse senders explicitly
marked "keep" in policy.toml, refuse protected domains, and never override
dry_run to False.

Registration command (run once manually):
  openclaw mcp add icloud-helper \\
    --command /Users/ollama/icloud-helper/.venv-mcp/bin/python3.13 \\
    --arg -m --arg icloud_helper.mcp_server \\
    --cwd /Users/ollama/icloud-helper
"""
# pylint: disable=too-many-lines
from __future__ import annotations

import base64
import dataclasses
import email
import email.policy
from email.utils import parsedate_to_datetime
import hashlib
import html
import json
import logging
import os
import re
import subprocess
import tomllib  # pylint: disable=import-error  # stdlib since 3.11; runs under .venv-mcp
import urllib.parse
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional

from mcp.server.fastmcp import FastMCP  # pylint: disable=import-error  # requires Python >=3.10; runs under .venv-mcp

from icloud_helper import attachments as _attachments
from icloud_helper import flagged
from icloud_helper import render_pdf
from icloud_helper.flagged import clean_body_text
from icloud_helper.policy import GlobalConfig, load_config, load_policy
from icloud_helper.secrets import read_secret
from icloud_helper.state import StateStore
from icloud_helper.unsubscribe import (
    egress_check,
    effective_mailto_domains,
    effective_unsubscribe_domains,
    perform_unsubscribe,
    unsubscribe_one_click,
)
from icloud_helper import actions as _actions
from icloud_helper.actions import ActionsError
from icloud_helper import read_surface
from icloud_helper.auth import check_sender_auth, extract_auth_signals
from icloud_helper.body_links import (
    classify_landing_page,
    extract_unsubscribe_candidates,
)
from icloud_helper.imap_client import (
    fetch_headers_batch,
    parse_message_headers,
    uid_search,
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Module-level singletons (loaded once at import time)
# ---------------------------------------------------------------------------

_BASE = Path(__file__).parent.parent  # ~/icloud-helper/
_config: GlobalConfig = load_config(_BASE / "config.toml")
_policy = load_policy(_BASE / "policy.toml")
_store = StateStore(_BASE / "state" / "mailcleaner.db")
_store.init_db()
_action_count: int = 0  # module-level rate-limit counter  # pylint: disable=invalid-name

mcp = FastMCP("icloud-helper")

# F6: Emit a clear startup warning when allow_confirmed_actions is ON so
# the operator sees it in server logs.
if _config.allow_confirmed_actions:
    logger.warning(
        "allow_confirmed_actions is ON — confirm-gated live actions are "
        "possible.  Ensure this is intentional before production use."
    )

# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

# M3: disallow ".." (parent-directory traversal) and "/" (path separator)
# to prevent path traversal in folder names passed to subprocess.
# The original had a double-space in the character class (cosmetic bug);
# corrected to a single space.
_SAFE_FOLDER_RE = re.compile(r"^(?!.*\.\.)[A-Za-z0-9_. -]+$")


def _now_iso() -> str:
    """Return the current UTC time as an ISO-8601 string.

    Returns:
        ISO-8601 formatted UTC timestamp string.
    """
    return datetime.now(timezone.utc).isoformat()


def _parse_internaldate(s: str) -> datetime:
    """Parse an IMAP INTERNALDATE string to a timezone-aware datetime.

    Handles the RFC 2822-compatible format produced by IMAP servers
    (e.g. "15-Jun-2024 10:00:00 +0000"). Falls back to datetime.min
    (UTC) for any string that cannot be parsed, so unknown dates sort
    oldest rather than crashing the sort key.

    Args:
        s: INTERNALDATE string from an IMAP FETCH response.

    Returns:
        Timezone-aware datetime, or datetime.min (UTC) on parse failure.
    """
    try:
        return parsedate_to_datetime(s)
    except Exception:  # pylint: disable=broad-except
        return datetime.min.replace(tzinfo=timezone.utc)


def _load_triage_json() -> Optional[Dict]:
    """Load the latest triage JSON report from disk.

    Returns:
        Parsed dict from triage-latest.json, or None if absent or unreadable.
    """
    triage_path = _BASE / "reports" / "triage-latest.json"
    if not triage_path.exists():
        return None
    try:
        with open(triage_path, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, json.JSONDecodeError) as exc:
        logger.warning("Could not load triage-latest.json: %s", exc)
        return None


def _fetch_live_sender_headers(
    sender: str,
    folder: str,
) -> Optional[Dict[str, str]]:
    """Fetch the most recent live message headers for *sender* from *folder*.

    Opens a read-only IMAP session, runs ``UID SEARCH FROM "<sender>"`` to
    locate all messages from that address, and fetches the headers of the
    highest (most recent) UID via ``BODY.PEEK[HEADER]``.

    This mirrors the per-UID auth pattern used in ``actor.py`` and the
    ``unsubscribe_message`` read-only fetch path.

    Args:
        sender: Lowercase bare email address (no display name).
        folder: IMAP folder to search within (e.g. ``"INBOX"``).

    Returns:
        Lowercase-keyed header dict for the most recent message, or ``None``
        when no live message is found or an IMAP error occurs.
    """
    secrets_base = _BASE / "secrets"
    try:
        with flagged.open_readonly_session(folder, secrets_base) as (imap, _uv):
            criterion = f'FROM "{sender}"'
            matching_uids = uid_search(imap, criterion)
            if not matching_uids:
                logger.info(
                    "_fetch_live_sender_headers: no live message for %s "
                    "in folder %s",
                    sender,
                    folder,
                )
                return None
            # Use only the most recent UID.
            newest_uid = max(matching_uids)
            header_list = fetch_headers_batch(imap, [newest_uid])
            if not header_list:
                logger.warning(
                    "_fetch_live_sender_headers: header fetch returned "
                    "nothing for uid=%d sender=%s",
                    newest_uid,
                    sender,
                )
                return None
            return header_list[0]
    except (flagged.FlaggedError, OSError) as exc:
        logger.warning(
            "_fetch_live_sender_headers: IMAP session failed for %s: %s",
            sender,
            exc,
        )
        return None


def _apply_action_guards(
    sender: str,
    method: str,
    target: str,
) -> Optional[Dict]:
    """Apply safety guards for action tools.

    Default-allow: a sender with no policy entry (or a policy entry with
    action="unsubscribe") is permitted. The only sender-level refusal is an
    explicit ``action="keep"`` entry in policy.toml, which is always
    honoured. Also checks that the sender domain is not in the protected
    list. Appends a "refused" audit entry on rejection.

    Args:
        sender: Normalised (lowercase) sender email address.
        method: Method string for the audit log.
        target: Target string for the audit log.

    Returns:
        Error dict if the action is refused, None if all checks pass.
    """
    # Guard 1: an explicit "keep" policy entry always blocks the action.
    # No policy entry (or an "unsubscribe" entry) is permitted by default.
    policy_entry = _policy.get(sender)
    if policy_entry is not None and policy_entry.action == "keep":
        _store.append_audit(
            sender,
            method,
            target,
            _config.dry_run,
            None,
            "refused",
            "sender marked keep",
        )
        logger.info("Action refused for %s — sender marked keep", sender)
        return {
            "error": "sender_marked_keep",
            "detail": "sender is marked keep in policy",
            "sender": sender,
        }

    # Guard 2: domain must not be protected
    at_idx = sender.rfind("@")
    domain = sender[at_idx + 1:] if at_idx != -1 else ""
    if domain in _config.protected_domains:
        _store.append_audit(
            sender,
            method,
            target,
            _config.dry_run,
            None,
            "refused",
            f"domain {domain} is protected",
        )
        logger.info(
            "Action refused for %s — domain %s is protected", sender, domain
        )
        return {
            "error": "sender_domain_is_protected",
            "detail": f"domain {domain} is protected",
            "domain": domain,
        }

    return None


def _validate_folder(folder: str) -> Optional[Dict]:
    """Validate a folder name against the safe-name pattern.

    Rejects empty strings, whitespace-only strings, names containing '..'
    or '/', and names with characters outside [A-Za-z0-9_. -]. Uses
    ``re.fullmatch`` so a trailing newline (which ``re.match`` with ``$``
    would accept) is correctly rejected.

    Args:
        folder: Folder name to validate.

    Returns:
        Error dict if invalid, None if valid.
    """
    if not folder or not folder.strip() or not _SAFE_FOLDER_RE.fullmatch(folder):
        return {
            "error": "invalid folder name",
            "detail": (
                "Folder must match [A-Za-z0-9_. -]+ "
                "and must not contain '..' or '/'"
            ),
        }
    return None


# ---------------------------------------------------------------------------
# READ tools
# ---------------------------------------------------------------------------


def _validate_read_folder(folder: str) -> Optional[Dict]:
    """Validate that folder is in the read-folder allowlist.

    This is the OUTER gate applied before the charset check in every new
    read and action tool.  The allowlist is sourced from
    ``_config.read.folders`` so config.toml governs which folders the
    model can touch.

    Args:
        folder: IMAP folder name to check.

    Returns:
        Error dict if the folder is not in the allowlist, None otherwise.
    """
    allowed = _config.read.folders
    if folder not in allowed:
        return {
            "error": "folder_not_allowed",
            "detail": f"folder {folder!r} not in read_folders allowlist",
            "folder": folder,
            "allowed": allowed,
        }
    return None


def _validate_destination(destination: str) -> Optional[Dict]:
    """Validate that a move destination is one of the configured action folders.

    Permitted destinations are ``_config.actions.archive_folder`` and
    ``_config.actions.trash_folder`` only.  This prevents the model from
    directing messages to arbitrary folders.

    Args:
        destination: Proposed destination folder name.

    Returns:
        Error dict if the destination is not allowed, None otherwise.
    """
    allowed = {_config.actions.archive_folder, _config.actions.trash_folder}
    if destination not in allowed:
        return {
            "error": "destination_not_allowed",
            "detail": (
                f"destination {destination!r} must be archive_folder or "
                "trash_folder from config"
            ),
            "destination": destination,
            "allowed": sorted(allowed),
        }
    return None


@mcp.tool()
def list_bulk_senders(classification: str = "") -> dict:
    """List bulk senders from the latest triage report.

    Senders already marked unsub_status="success" in the state DB are
    excluded.  The response includes freshness metadata to signal that the
    snapshot may be stale.

    Args:
        classification: Optional classification filter. When non-empty,
            only senders matching this classification are returned.

    Returns:
        Dict with keys "senders", "snapshot_generated_at",
        and "freshness_note", or an error object if the triage report is
        absent.
    """
    data = _load_triage_json()
    if data is None:
        return {
            "error": "no_triage_report",
            "detail": "no triage report found; run trigger_triage first",
        }

    snapshot_generated_at: str = (
        data.get("generated_at", "") if isinstance(data, dict) else ""
    )
    senders: List[Dict] = (
        data if isinstance(data, list) else data.get("senders", [])
    )

    # Exclude senders already successfully unsubscribed.
    filtered: List[Dict] = []
    for sender_entry in senders:
        email_addr = str(sender_entry.get("email", "")).lower()
        if not email_addr:
            filtered.append(sender_entry)
            continue
        state = _store.get_sender_state(email_addr)
        if state is not None and state.get("unsub_status") == "success":
            continue
        filtered.append(sender_entry)

    if classification:
        filtered = [
            s
            for s in filtered
            if str(s.get("classification", "")).lower()
            == classification.lower()
        ]

    return {
        "senders": filtered,
        "snapshot_generated_at": snapshot_generated_at,
        "freshness_note": (
            "snapshot may be stale; call trigger_triage to refresh"
        ),
    }


@mcp.tool()
def get_triage_report() -> dict:
    """Return the full latest triage report as JSON.

    The returned dict includes a "freshness_note" field to signal that the
    snapshot may be stale.

    Returns:
        Dict of the full triage-latest.json augmented with
        "freshness_note", or an error object if absent.
    """
    data = _load_triage_json()
    if data is None:
        return {
            "error": "no_triage_report",
            "detail": "no triage report found; run trigger_triage first",
        }
    if isinstance(data, list):
        return {
            "senders": data,
            "freshness_note": "snapshot may be stale; call trigger_triage to refresh",
        }
    data = dict(data)
    data.setdefault(
        "freshness_note",
        "snapshot may be stale; call trigger_triage to refresh",
    )
    return data


@mcp.tool()
def show_pending_senders() -> dict:
    """Return all pending senders from the state DB.

    Returns:
        Dict with "pending_senders" list of rows (all columns as dicts).
    """
    rows: List[Dict] = []
    try:
        with _store._connect() as conn:  # pylint: disable=protected-access
            conn.row_factory = __import__("sqlite3").Row
            cur = conn.execute(
                "SELECT * FROM pending_senders ORDER BY message_count DESC"
            )
            rows = [dict(row) for row in cur.fetchall()]
    except Exception as exc:  # pylint: disable=broad-except
        logger.error("Error querying pending_senders: %s", exc)
        return {"error": "db_error", "detail": str(exc)[:200]}
    return {"pending_senders": rows}


@mcp.tool()
def get_audit_log(limit: int = 50) -> dict:
    """Return recent audit log entries.

    Args:
        limit: Maximum number of rows to return (most recent first).

    Returns:
        Dict with "audit_log" list of rows.
    """
    if limit <= 0:
        limit = 50
    rows: List[Dict] = []
    try:
        with _store._connect() as conn:  # pylint: disable=protected-access
            conn.row_factory = __import__("sqlite3").Row
            cur = conn.execute(
                "SELECT * FROM audit_log ORDER BY id DESC LIMIT ?",
                (limit,),
            )
            rows = [dict(row) for row in cur.fetchall()]
    except Exception as exc:  # pylint: disable=broad-except
        logger.error("Error querying audit_log: %s", exc)
        return {"error": "db_error", "detail": str(exc)[:200]}
    return {"audit_log": rows}


@mcp.tool()
def get_sender_status(sender: str) -> dict:
    """Return the current state for a specific sender.

    Args:
        sender: Sender email address (case-insensitive).

    Returns:
        Dict of sender state, or an error object if not found.
    """
    sender = sender.strip().lower()
    state = _store.get_sender_state(sender)
    if state is None:
        return {
            "error": "sender_not_found",
            "detail": "sender not found in state DB",
            "sender": sender,
        }
    return state


# ---------------------------------------------------------------------------
# ACTION tools
# ---------------------------------------------------------------------------


@mcp.tool()
def unsubscribe_sender(sender: str) -> dict:  # pylint: disable=too-many-locals,too-many-return-statements,too-many-branches,too-many-statements
    """Attempt to unsubscribe from a sender.

    Permitted by default. Refused only if the sender is explicitly marked
    action="keep" in policy.toml, or if the sender's domain is in the
    protected list. Dry-run behaviour is controlled by the loaded config;
    it is never overridden here.

    Args:
        sender: Sender email address to unsubscribe from.

    Returns:
        Dict with the UnsubscribeResult fields, or an error object.
    """
    global _action_count  # pylint: disable=global-statement

    sender = sender.strip().lower()
    logger.info("unsubscribe_sender called for %s", sender)

    # Short-circuit: already successfully unsubscribed.
    existing_state = _store.get_sender_state(sender)
    if (
        existing_state is not None
        and existing_state.get("unsub_status") == "success"
    ):
        return {
            "status": "already_unsubscribed",
            "sender": sender,
            "when": existing_state.get("last_attempt_at"),
        }

    err = _apply_action_guards(sender, "unknown", "unknown")
    if err is not None:
        return err

    if _action_count >= _config.rate_limits.max_unsubscribes_per_run:
        return {
            "error": "rate_limit_reached",
            "detail": "rate limit reached for this session",
        }

    # Retrieve unsubscribe headers from triage report.
    unsubscribe_header = ""
    unsubscribe_post_header = ""
    found_in_triage = False
    triage_data = _load_triage_json()
    if triage_data is not None:
        sender_list: List[Dict] = (
            triage_data
            if isinstance(triage_data, list)
            else triage_data.get("senders", [])
        )
        for entry in sender_list:
            if str(entry.get("email", "")).lower() == sender:
                unsubscribe_header = str(
                    entry.get("sample_unsubscribe_header", "")
                )
                unsubscribe_post_header = str(
                    entry.get("sample_unsubscribe_post_header", "")
                )
                found_in_triage = True
                break

    # Sender is in policy but absent from triage snapshot — message gone.
    if not found_in_triage:
        return {
            "status": "deferred",
            "detail": (
                "message no longer in INBOX (may have been moved)"
            ),
            "sender": sender,
        }

    # H1: Fetch the most recent live message headers and run the same
    # DKIM/DMARC gate that actor.py and unsubscribe_message apply.
    # This prevents a stale triage snapshot (which holds no auth data)
    # from being acted on without verifying current sender authentication.
    # Fail-closed: refuse if no live message is found or auth fails.
    # Also use the LIVE List-Unsubscribe header from the live message so
    # stale snapshot headers are not trusted for the actual action.
    live_folder = list(_config.folders)[0] if _config.folders else "INBOX"
    live_headers = _fetch_live_sender_headers(sender, live_folder)
    if live_headers is None:
        _store.append_audit(
            sender=sender[:200],
            method="unsubscribe_sender",
            target="",
            dry_run=_config.dry_run,
            http_status=None,
            result="refused_dkim",
            detail=(
                "[block_class=auth_failed] "
                "no live message found for sender auth check (fail-closed)"
            ),
        )
        return {
            "error": "auth_gate_failed",
            "block_class": "auth_failed",
            "detail": (
                "no live message found for sender; DKIM/DMARC check "
                "cannot be performed (fail-closed)"
            ),
            "sender": sender,
        }

    auth_passed, authenticated_from_domain = check_sender_auth(live_headers)
    if not auth_passed:
        _store.append_audit(
            sender=sender[:200],
            method="unsubscribe_sender",
            target="",
            dry_run=_config.dry_run,
            http_status=None,
            result="refused_dkim",
            detail="[block_class=auth_failed] dkim/dmarc gate failed on live message",
        )
        return {
            "error": "auth_gate_failed",
            "block_class": "auth_failed",
            "detail": (
                "DKIM/DMARC check failed on live message; "
                "unsubscribe refused (fail-closed)"
            ),
            "sender": sender,
        }

    # Use LIVE List-Unsubscribe header if present; fall back to triage snapshot.
    live_list_unsub = live_headers.get("list-unsubscribe", "")
    live_list_unsub_post = live_headers.get("list-unsubscribe-post", "")
    if live_list_unsub:
        unsubscribe_header = live_list_unsub
        unsubscribe_post_header = live_list_unsub_post

    # Derive verified_sender_domain from DMARC-authenticated header.from=
    # (C1: do not use raw From header).
    # Multi-From ambiguity check: the joined from header uses " | " as separator.
    all_from_values = live_headers.get("from", "")
    multi_from = " | " in all_from_values
    if multi_from or authenticated_from_domain is None:
        verified_sender_domain_us = ""
        if multi_from:
            logger.warning(
                "unsubscribe_sender: multiple From: headers detected "
                "for %s — suppressing implicit sender-domain mailto auth",
                sender,
            )
    else:
        verified_sender_domain_us = authenticated_from_domain

    try:
        smtp_user = read_secret(
            str(_BASE / "secrets" / "icloud_email")
        )
        smtp_pass = read_secret(
            str(_BASE / "secrets" / "icloud_app_password")
        )
    except (Exception, SystemExit) as exc:  # pylint: disable=broad-except
        logger.error("Failed to read SMTP credentials: %s", exc)
        return {
            "error": "smtp_credentials_unavailable",
            "detail": str(exc)[:200],
        }

    result = perform_unsubscribe(
        sender,
        unsubscribe_header,
        unsubscribe_post_header,
        _config,
        smtp_user,
        smtp_pass,
        verified_sender_domain=verified_sender_domain_us,
    )

    # B.5: include block_class prefix in the audit detail so the log is
    # consistent with the actor.py audit path (~line 642-646).
    _audit_detail = result.detail
    if result.block_class:
        _audit_detail = f"[block_class={result.block_class}] {result.detail}"

    _store.append_audit(
        sender,
        result.method,
        result.target,
        _config.dry_run,
        result.http_status,
        result.result,
        _audit_detail,
    )

    at_idx = sender.rfind("@")
    domain = sender[at_idx + 1:] if at_idx != -1 else ""

    _store.upsert_sender_state(
        sender,
        domain,
        unsub_status=result.result,
        unsub_method=result.method,
        last_attempt_at=_now_iso(),
        attempt_count_delta=1,
        policy_action="unsubscribe",
    )

    if result.result in ("success", "success-simulated"):
        _action_count += 1
        logger.info(
            "Unsubscribe %s: %s (session total: %d)",
            sender,
            result.result,
            _action_count,
        )

    return dataclasses.asdict(result)


@mcp.tool()
def run_cleanup(folder: str = "", limit: int = 0) -> dict:
    """Shell out to actor.py to run a full cleanup pass.

    Passes --dry-run or --no-dry-run based on the loaded config; never
    upgrades to live mode if the config says dry_run=True.

    Args:
        folder: Optional IMAP folder name to restrict to. Empty = all folders.
        limit: Max messages per folder (0 = all).

    Returns:
        Dict with returncode, stdout (truncated), and stderr (truncated).
    """
    if limit < 0:
        return {
            "error": "invalid_limit",
            "detail": "limit must be >= 0",
            "limit": limit,
        }

    if folder:
        folder_error = _validate_folder(folder)
        if folder_error is not None:
            return folder_error

    cmd: List[str] = [
        str(_BASE / ".venv" / "bin" / "python3"),
        str(_BASE / "actor.py"),
    ]
    if folder:
        cmd += ["--folder", folder]
    if limit > 0:
        cmd += ["--limit", str(limit)]

    # Safety: always mirror the loaded config's dry_run value.
    if _config.dry_run:
        cmd.append("--dry-run")
    else:
        cmd.append("--no-dry-run")

    logger.info("run_cleanup: %s", " ".join(cmd))

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=300,
            cwd=str(_BASE),
            check=False,
        )
    except subprocess.TimeoutExpired:
        return {
            "error": "subprocess_timeout",
            "detail": "actor.py timed out after 300 seconds",
        }
    except FileNotFoundError as exc:
        return {"error": "subprocess_not_found", "detail": str(exc)}

    return {
        "returncode": proc.returncode,
        "stdout": proc.stdout[:2000],
        "stderr": proc.stderr[:1000],
    }


@mcp.tool()
def trigger_triage(folder: str = "INBOX") -> dict:
    """Shell out to triage.py to run a triage scan on a single folder.

    Args:
        folder: IMAP folder name to triage. Default: INBOX.

    Returns:
        Dict with returncode, stdout (truncated), and stderr (truncated).
    """
    folder_error = _validate_folder(folder)
    if folder_error is not None:
        return folder_error

    cmd: List[str] = [
        str(_BASE / ".venv" / "bin" / "python3"),
        str(_BASE / "triage.py"),
        "--folder",
        folder,
    ]

    logger.info("trigger_triage: %s", " ".join(cmd))

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=120,
            cwd=str(_BASE),
            check=False,
        )
    except subprocess.TimeoutExpired:
        return {
            "error": "subprocess_timeout",
            "detail": "triage.py timed out after 120 seconds",
        }
    except FileNotFoundError as exc:
        return {"error": "subprocess_not_found", "detail": str(exc)}

    return {
        "returncode": proc.returncode,
        "stdout": proc.stdout[:2000],
        "stderr": proc.stderr[:1000],
    }


# ---------------------------------------------------------------------------
# Policy-write helpers
# ---------------------------------------------------------------------------

# Characters forbidden in sender email addresses in TOML table keys.
# Allows printable ASCII except " (quote), \ (backslash), and control chars.
_SAFE_SENDER_RE = re.compile(r'^[a-zA-Z0-9._%+\-@]+$')


def _validate_sender_for_toml(sender: str) -> Optional[Dict]:
    """Validate that a sender string is safe to write as a TOML key.

    SECURITY NOTE (for reviewer): TOML table-key injection risk. We
    validate against a strict allowlist of characters before writing.
    The sender key is quoted in TOML (["sender@example.com"]), but we
    still restrict to an email-address character set to prevent escape
    sequences or newline injection.

    Args:
        sender: Normalised lowercase sender email address.

    Returns:
        Error dict if invalid, None if safe.
    """
    if not _SAFE_SENDER_RE.match(sender):
        return {
            "error": "invalid_sender_chars",
            "detail": "sender contains characters unsafe for policy.toml",
            "sender": sender,
        }
    if "@" not in sender:
        return {
            "error": "invalid_sender_format",
            "detail": "sender must be a valid email address",
            "sender": sender,
        }
    return None


def _atomic_write_policy(
    policy_path: "Path",
    new_entry_key: str,
    new_entry_action: str,
) -> str:
    """Read-modify-write policy.toml atomically, adding or updating one entry.

    Parses the existing TOML with tomllib, updates the target key, then
    serialises back with tomli_w. Comments in the original file are not
    preserved (a deliberate trade-off for correctness; the regex-based
    approach corrupted files whose values contained '[').

    The write is atomic via a temp-file rename (os.replace).

    SECURITY NOTE (for reviewer): policy_path is a fixed constant (_BASE /
    "policy.toml"); it is never constructed from caller input. The
    new_entry_key has been validated against _SAFE_SENDER_RE before this
    function is called. File permissions should be reviewed — policy.toml
    is currently mode 644; tightening to 600 is recommended.

    Args:
        policy_path: Absolute path to policy.toml.
        new_entry_key: Validated sender email address (the TOML table key).
        new_entry_action: "unsubscribe" or "keep".

    Returns:
        The TOML snippet that was written (for confirmation echo).

    Raises:
        OSError: On file read/write failure.
        ValueError: If action is not a recognised value.
    """
    import tomli_w  # pylint: disable=import-outside-toplevel

    if new_entry_action not in ("unsubscribe", "keep"):
        raise ValueError(f"Invalid action: {new_entry_action!r}")

    # Parse existing TOML (empty dict when file is absent or empty).
    try:
        raw_bytes = policy_path.read_bytes()
    except FileNotFoundError:
        raw_bytes = b""

    if raw_bytes.strip():
        try:
            data: dict = tomllib.loads(raw_bytes.decode("utf-8"))
        except tomllib.TOMLDecodeError as exc:
            logger.warning(
                "policy.toml is malformed; starting fresh: %s", exc
            )
            data = {}
    else:
        data = {}

    # Insert or overwrite the entry.
    data[new_entry_key] = {"action": new_entry_action}

    # Serialise and write atomically via temp file + os.replace.
    new_bytes = tomli_w.dumps(data).encode("utf-8")
    tmp_path = policy_path.parent / (policy_path.name + ".tmp")
    try:
        with open(tmp_path, "wb") as fh:
            fh.write(new_bytes)
        os.replace(tmp_path, policy_path)
    except OSError:
        try:
            tmp_path.unlink(missing_ok=True)
        except OSError:
            pass
        raise

    snippet = f'["{new_entry_key}"]\naction = "{new_entry_action}"'
    return snippet


# ---------------------------------------------------------------------------
# approve_sender tool
# ---------------------------------------------------------------------------


@mcp.tool()
def approve_sender(  # pylint: disable=too-many-return-statements
    sender: str, action: str
) -> dict:
    """Add or update a sender in policy.toml (human-authorised path).

    This is the explicit human-approval path. Unlike unsubscribe_sender
    (which requires the sender to already be in the allowlist),
    approve_sender CREATES the policy entry. It may only be invoked by
    a human via the openclaw agent — autonomous callers should not call
    this without explicit user instruction.

    Safety gates enforced server-side:
    - action must be "unsubscribe" or "keep".
    - Sender must pass character validation (no TOML injection).
    - action="unsubscribe" is refused for protected domains.
    - Every call is logged to the audit_log.
    - The policy write is atomic (temp-file + rename).

    SECURITY NOTE (for reviewer): policy.toml write path. Sender string
    is validated against _SAFE_SENDER_RE before use as a TOML key. The
    file is written atomically. policy.toml permissions should be 600.

    Args:
        sender: Sender email address to approve. Case-insensitive.
        action: "unsubscribe" to allowlist for cleanup, or "keep" to
            silence alerts without acting.

    Returns:
        Dict with the written TOML snippet and confirmation.
    """
    sender = sender.strip().lower()
    logger.info(
        "approve_sender called: sender=%s action=%s", sender, action
    )

    # H4: block autonomous policy writes when the flag is off.
    # This prevents the MCP server (running as cron) from self-authorising
    # new unsubscribe targets without explicit human approval via the flag.
    if not _config.allow_mcp_policy_writes:
        _store.append_audit(
            sender, "policy-write", "", _config.dry_run, None,
            "refused", "allow_mcp_policy_writes is false",
        )
        logger.info(
            "approve_sender refused: allow_mcp_policy_writes=false"
        )
        return {
            "error": "approve_sender_disabled",
            "detail": (
                "approve_sender is disabled; set allow_mcp_policy_writes=true"
                " in config.toml to permit MCP policy writes"
            ),
            "sender": sender,
        }

    # Validate action
    if action not in ("unsubscribe", "keep"):
        _store.append_audit(
            sender, "policy-write", "", _config.dry_run, None,
            "refused", f"invalid action: {action!r}",
        )
        return {
            "error": "invalid_action",
            "detail": "action must be 'unsubscribe' or 'keep'",
            "action": action,
        }

    # Validate sender characters (TOML injection guard)
    char_error = _validate_sender_for_toml(sender)
    if char_error is not None:
        _store.append_audit(
            sender, "policy-write", "", _config.dry_run, None,
            "refused", "sender failed character validation",
        )
        return char_error

    # Refuse unsubscribe for protected domains
    at_idx = sender.rfind("@")
    domain = sender[at_idx + 1:] if at_idx != -1 else ""
    if action == "unsubscribe" and domain in _config.protected_domains:
        _store.append_audit(
            sender, "policy-write", "", _config.dry_run, None,
            "refused", f"domain {domain} is protected",
        )
        logger.info(
            "approve_sender refused: %s domain is protected", sender
        )
        return {
            "error": "sender_domain_is_protected",
            "detail": "sender domain is protected; cannot set action=unsubscribe",
            "domain": domain,
        }

    policy_path = _BASE / "policy.toml"

    # Dry-run: show what would be written without touching the file.
    if _config.dry_run:
        snippet = f'["{sender}"]\naction = "{action}"'
        _store.append_audit(
            sender, "policy-write", str(policy_path),
            True, None, "success-simulated",
            f"would write action={action}",
        )
        logger.info(
            "DRY RUN: would write to policy.toml for %s action=%s",
            sender, action,
        )
        return {
            "dry_run": True,
            "sender": sender,
            "action": action,
            "would_write": snippet,
            "policy_path": str(policy_path),
        }

    # Live write
    try:
        written_snippet = _atomic_write_policy(policy_path, sender, action)
    except (OSError, ValueError) as exc:
        _store.append_audit(
            sender, "policy-write", str(policy_path),
            _config.dry_run, None, "failed", str(exc)[:200],
        )
        logger.error("Failed to write policy.toml for %s: %s", sender, exc)
        return {
            "error": "policy_write_failed",
            "detail": str(exc)[:200],
        }

    # Reload in-memory policy so subsequent tool calls see the new entry.
    global _policy  # pylint: disable=global-statement
    _policy = load_policy(policy_path)

    _store.append_audit(
        sender, "policy-write", str(policy_path),
        _config.dry_run, None, "success",
        f"wrote action={action}",
    )
    logger.info(
        "Policy updated: %s -> action=%s", sender, action
    )

    return {
        "sender": sender,
        "action": action,
        "written_snippet": written_snippet,
        "policy_path": str(policy_path),
        "dry_run": False,
    }


# ---------------------------------------------------------------------------
# Flagged-message read tools
# ---------------------------------------------------------------------------


@mcp.tool()
def list_flagged_messages(  # pylint: disable=too-many-locals,too-many-branches,too-many-statements,too-many-arguments
    folder: str = "INBOX",
    limit: int = 25,
    view: str = "snippet",
    snippet_bytes: int = 0,
    max_total_bytes: int = 0,
) -> dict:
    """List flagged messages from the given IMAP folder.

    Returns message metadata, decoded body text, and an attachment
    manifest. Uses BODY.PEEK[] so no Seen flags are modified. Newest
    messages first (highest UIDs as recency proxy, final sort by
    INTERNALDATE). Includes a UIDVALIDITY token for safe subsequent
    get_attachment calls.

    Fetches full messages from IMAP. Practical memory bound is
    ``max_limit × message_size``; keep ``max_limit`` default (100)
    conservative. Body text is truncated to ``max_body_bytes`` (256 KiB)
    per message to bound per-response memory use.

    Args:
        folder: IMAP mailbox folder. Default: INBOX.
        limit: Maximum number of messages to return. 0 or negative uses
            the configured default_limit. Values above max_limit are
            clamped to max_limit.
        view: One of "metadata" (no body/snippet), "snippet" (default,
            1.5 KiB default snippet), or "full" (snippet at max_body_bytes).
            Unlike list_messages, the attachment manifest is always included
            regardless of view — flagged mail is attachment-centric.
        snippet_bytes: Override for snippet size.  0 uses default.
            Clamped to max_snippet_bytes.
        max_total_bytes: Approximate response size cap.  0 = no cap.
            When exceeded, stops adding messages and sets truncated=true.

    Returns:
        Dict with keys: folder, uidvalidity, flagged_total,
        returned, truncated, messages (list of message dicts). Each message
        dict contains uid, internaldate, from, subject, body_text (view !=
        metadata), body_source, body_truncated, attachments.
    """
    err = _validate_read_folder(folder)
    if err is not None:
        return err
    err = _validate_folder(folder)
    if err is not None:
        return err

    valid_views = {"metadata", "snippet", "full"}
    if view not in valid_views:
        return {
            "error": "invalid_view",
            "detail": f"view must be one of {sorted(valid_views)}",
            "view": view,
        }

    if limit <= 0:
        limit = _config.flagged.default_limit
    limit = min(limit, _config.flagged.max_limit)

    max_body = _config.flagged.max_body_bytes
    max_snippet_hard = _config.read.max_snippet_bytes
    default_snip = _config.read.default_snippet_bytes

    # Determine effective snippet cap.
    if view == "metadata":
        effective_snippet = 0
    elif view == "full":
        effective_snippet = max_body
    else:
        if snippet_bytes > 0:
            effective_snippet = min(snippet_bytes, max_snippet_hard)
        else:
            effective_snippet = min(default_snip, max_snippet_hard)

    try:
        with flagged.open_readonly_session(
            folder, _BASE / "secrets"
        ) as (imap, uidvalidity):
            all_uids = flagged.search_flagged_uids(imap)
            selected_uids = sorted(all_uids)[-limit:]
            raw_messages = flagged.fetch_messages_batch(imap, selected_uids)
    except (flagged.FlaggedError, OSError) as exc:
        return {
            "error": "imap session failed",
            "detail": str(exc)[:200],
        }

    out: List[Dict] = []
    approx_total = 0
    capped_by_bytes = False
    uid = 0  # track last uid for error reporting
    try:
        for uid, (raw, internaldate) in raw_messages.items():
            msg = email.message_from_bytes(raw, policy=email.policy.default)
            manifest = flagged.build_manifest(msg)

            entry: Dict = {
                "uid": str(uid),
                "internaldate": internaldate,
                "from": str(msg.get("from", "")),
                "subject": str(msg.get("subject", "")),
                "has_attachments": bool(manifest),
                "attachments": manifest,
            }

            if view != "metadata":
                body_text, body_source = flagged.select_body_text(msg)
                # T2.7: clean BEFORE truncate.
                body_text = clean_body_text(body_text, body_source)
                encoded = body_text.encode("utf-8")
                body_truncated = len(encoded) > effective_snippet
                if body_truncated:
                    body_text = encoded[:effective_snippet].decode(
                        "utf-8", errors="ignore"
                    )
                entry["body_text"] = body_text
                entry["body_source"] = body_source
                entry["body_truncated"] = body_truncated

            # max_total_bytes accounting.
            if max_total_bytes > 0:
                entry_size = len(
                    entry.get("body_text", "").encode("utf-8")
                ) + len(str(entry).encode("utf-8"))
                if approx_total + entry_size > max_total_bytes:
                    capped_by_bytes = True
                    break
                approx_total += entry_size

            out.append(entry)

    except Exception as exc:  # pylint: disable=broad-except
        logger.error("message parse error uid=%s: %s", uid, exc)
        return {
            "error": "message_parse_error",
            "detail": str(exc)[:200],
        }

    out.sort(
        key=lambda x: _parse_internaldate(x["internaldate"]), reverse=True
    )

    logger.info(
        "list_flagged: folder=%s view=%s matched=%d returned=%d capped=%s",
        folder, view, len(all_uids), len(out), capped_by_bytes,
    )

    return {
        "folder": folder,
        "uidvalidity": uidvalidity,
        "flagged_total": len(all_uids),
        "returned": len(out),
        "truncated": capped_by_bytes,
        "messages": out,
    }


@mcp.tool()
def get_attachment(  # pylint: disable=too-many-return-statements,too-many-branches,too-many-statements,too-many-locals,too-many-arguments,too-many-positional-arguments
    uid: str,
    index: int,
    folder: str = "INBOX",
    uidvalidity: int = 0,
    save_to: str = "",
    offset: int = 0,
    length: int = 0,
    extract_text: bool = False,
    include_base64: bool = True,
) -> dict:
    """Fetch a single attachment from a flagged message by UID and index.

    The index corresponds to the attachment manifest returned by
    list_flagged_messages. Pass the uidvalidity token from that call to
    detect folder state changes between list and fetch.  Supports
    INBOX, Junk, and Archive (the read-folder allowlist).

    save_to (security-critical): a FILENAME ONLY — no path components.
    The file is written atomically (temp + os.replace) at mode 600 inside
    the configured downloads_dir (mode 700).  Containment is verified via
    os.path.realpath after joining.  max_attachment_bytes is enforced
    before any write or extraction.  save_to always writes the FULL attachment
    to disk; offset/length affect only data_base64 and chunk_sha256, not the
    saved file.

    offset/length: slice the decoded bytes for ranged reads.  length=0 means
    to end.  Returns chunk_sha256 (the slice), full_sha256 (whole attachment),
    and total_size_bytes so the caller can reassemble and verify.

    extract_text: for text/* parts, decodes charset-aware.  For
    application/pdf or PDF-sniffed content, extracts via pypdf.  Text is
    capped at max_body_bytes.

    include_base64: when False, omits data_base64 from the response.  When
    save_to is used, defaults to omitting base64 unless explicitly True.

    Args:
        uid: Message UID as a string (from list_flagged_messages).
        index: Zero-based attachment index from the manifest.
        folder: IMAP mailbox folder. Default: INBOX.
        uidvalidity: UIDVALIDITY from the preceding list_flagged_messages
            call. Pass 0 to skip the check.
        save_to: Bare filename to save the attachment on disk (optional).
        offset: Byte offset for ranged reads (0-based). Default 0.
        length: Number of bytes to return. 0 means to end. Default 0.
        extract_text: When True, attempt to extract plain text. Default False.
        include_base64: When True, include base64 data in response. Default True.

    Returns:
        Dict with uid, index, filename, content_type, detected_mime,
        size_bytes and total_size_bytes (both report the full attachment
        size; total_size_bytes exists for chunk-reassembly clarity),
        full_sha256, and optionally data_base64, chunk_sha256, path, sha256,
        extracted_text, text_truncated, extract_note; or an error object.
    """
    err = _validate_read_folder(folder)
    if err is not None:
        return err
    err = _validate_folder(folder)
    if err is not None:
        return err

    try:
        uid_int = int(uid)
    except (ValueError, TypeError):
        return {
            "error": "invalid_uid",
            "detail": "uid must be an integer",
            "uid": uid,
        }

    # Validate save_to before opening IMAP (fail fast).
    save_to = save_to.strip()
    if save_to:
        fn_error = _attachments.validate_save_filename(save_to)
        if fn_error:
            return {
                "error": "invalid_save_to",
                "detail": fn_error,
                "save_to": save_to,
            }

    # Validate offset/length types (negative check before IMAP).
    if offset < 0:
        return {
            "error": "invalid_offset",
            "detail": "offset must be >= 0",
            "offset": offset,
        }
    if length < 0:
        return {
            "error": "invalid_length",
            "detail": "length must be >= 0",
            "length": length,
        }

    uidvalidity_error: Optional[Dict] = None
    fetch_result: Optional[object] = None

    try:
        with flagged.open_readonly_session(
            folder, _BASE / "secrets"
        ) as (imap, server_uidvalidity):
            if uidvalidity not in (0, server_uidvalidity):
                uidvalidity_error = {
                    "error": "uidvalidity_changed",
                    "detail": (
                        "folder state changed; "
                        "call list_flagged_messages again"
                    ),
                    "expected": uidvalidity,
                    "actual": server_uidvalidity,
                }
            else:
                fetch_result = flagged.fetch_message(imap, uid_int)
    except (flagged.FlaggedError, OSError) as exc:
        return {
            "error": "imap_session_failed",
            "detail": str(exc)[:200],
        }

    if uidvalidity_error is not None:
        return uidvalidity_error

    if fetch_result is None:
        return {
            "error": "uid_not_found",
            "detail": f"uid {uid!r} not found in folder {folder!r}",
            "uid": uid,
            "folder": folder,
        }

    raw_bytes, _ = fetch_result  # type: ignore[misc]
    try:
        msg = email.message_from_bytes(raw_bytes, policy=email.policy.default)
        attachment = flagged.extract_attachment(msg, index)
    except Exception as exc:  # pylint: disable=broad-except
        logger.error(
            "get_attachment parse error uid=%s: %s", uid, str(exc)[:200]
        )
        return {
            "error": "attachment_parse_error",
            "detail": str(exc)[:200],
        }

    if attachment is None:
        return {
            "error": "attachment_index_out_of_range",
            "detail": f"no attachment at index {index}",
            "index": index,
        }

    att_bytes: bytes = attachment["bytes"]
    max_att = _config.flagged.max_attachment_bytes

    # Enforce size cap BEFORE any write or extraction (DoS guard).
    if len(att_bytes) > max_att:
        return {
            "error": "attachment_too_large",
            "detail": "attachment exceeds max_attachment_bytes",
            "size_bytes": len(att_bytes),
            "max_bytes": max_att,
        }

    # Sniff MIME from the actual decoded bytes.
    detected_mime = _attachments.sniff_mime(att_bytes)

    # Compute hashes.
    full_sha256 = _attachments.sha256_hex(att_bytes)

    # Range-read slice.
    try:
        chunk, total_size = _attachments.slice_bytes(att_bytes, offset, length)
    except ValueError as exc:
        return {
            "error": "invalid_range",
            "detail": str(exc),
            "offset": offset,
            "length": length,
            "total_size_bytes": len(att_bytes),
        }
    chunk_sha256 = _attachments.sha256_hex(chunk)

    logger.info(
        "get_attachment: uid=%s index=%d content_type=%s detected=%s "
        "size=%d offset=%d length=%d",
        uid,
        index,
        attachment["content_type"],
        detected_mime,
        len(att_bytes),
        offset,
        length,
    )

    response: Dict = {
        "uid": uid,
        "index": index,
        "filename": attachment["filename"],
        "content_type": attachment["content_type"],
        "detected_mime": detected_mime,
        "size_bytes": len(att_bytes),
        "total_size_bytes": total_size,
        "full_sha256": full_sha256,
        "chunk_sha256": chunk_sha256,
    }

    # include_base64: when save_to is active, omit base64 by default to
    # avoid shipping bytes twice unless explicitly requested.
    emit_base64 = include_base64
    if save_to and not include_base64:
        emit_base64 = False

    if emit_base64:
        response["data_base64"] = base64.b64encode(chunk).decode("ascii")

    # save_to: atomic write with containment check.
    if save_to:
        downloads_dir = Path(_config.attachments.downloads_dir)
        try:
            saved_path = _attachments.atomic_write_attachment(
                downloads_dir, save_to, att_bytes
            )
        except (ValueError, OSError) as exc:
            logger.error(
                "get_attachment save_to failed: %s", str(exc)[:200]
            )
            return {
                "error": "save_failed",
                "detail": str(exc)[:200],
            }
        saved_sha256 = _attachments.sha256_hex(att_bytes)
        response["path"] = str(saved_path)
        response["sha256"] = saved_sha256

    # extract_text: attempt text extraction.
    if extract_text:
        declared_mime = attachment["content_type"]
        charset = None
        # charset is not recoverable from the manifest; extract_text_from_attachment
        # falls back to UTF-8 with errors=replace.
        max_body = _config.flagged.max_body_bytes
        extraction = _attachments.extract_text_from_attachment(
            att_bytes, declared_mime, charset, max_body
        )
        response["extracted_text"] = extraction.get("text")
        response["text_truncated"] = extraction.get("text_truncated", False)
        response["extract_note"] = extraction.get("extract_note")

    return response


@mcp.tool()
def save_message_pdf(  # pylint: disable=too-many-return-statements,too-many-branches,too-many-statements,too-many-locals
    folder: str,
    uid: str,
    uidvalidity: int = 0,
    save_to: str = "",
) -> dict:
    """Render a flagged message's original HTML to PDF and save it to disk.

    This is a true "print to PDF" of the message as authored — it renders
    the message's original text/html body (not a plain-text
    transcription) using WeasyPrint, an in-process, pure-Python renderer
    with NO JavaScript engine. Every external resource reference (images,
    stylesheets) in the HTML is resolved through a default-deny scheme
    allowlist: only ``cid:`` references (resolved against inline parts of
    THIS SAME message) and ``data:`` URIs (decoded locally) are permitted.
    Remote references (``http:``, ``https:``, ``file:``, protocol-relative
    ``//host/...``, etc.) are refused — WeasyPrint drops just that
    resource and renders a broken-image placeholder rather than aborting.
    No network egress is possible during rendering.

    When the message has no text/html body, falls back to the first
    text/plain leaf, HTML-escaped and wrapped in a minimal
    ``<pre>``-based HTML document (``body_source`` reports which path was
    used).

    save_to (security-critical, REQUIRED): a FILENAME ONLY — no path
    components. Validated BEFORE any IMAP session is opened. The rendered
    PDF is written atomically (temp + os.replace) at mode 600 inside the
    configured ``downloads_dir`` (mode 700); containment is verified via
    ``os.path.realpath`` after joining. ``max_attachment_bytes`` is
    enforced against the RENDERED PDF before any file is written.

    Args:
        folder: IMAP mailbox folder. Must be in the read-folder allowlist
            (INBOX, Junk, Archive).
        uid: Message UID as a string (from list_flagged_messages or
            list_messages).
        uidvalidity: UIDVALIDITY from a preceding list call. Pass 0 to
            skip the check.
        save_to: Bare filename to save the rendered PDF (required).

    Returns:
        On success, a dict with uid, folder, uidvalidity, path, sha256,
        size_bytes, body_source ("html" or "text-fallback"),
        dropped_remote_refs (count of blocked remote resource references),
        and warning (notes that egress was blocked and remote references
        were not fetched). On failure, an error dict with keys "error"
        and "detail" — one of folder_not_allowed, invalid_uid,
        invalid_save_to, uidvalidity_changed, uid_not_found,
        message_parse_error, no_renderable_body, weasyprint_unavailable,
        render_failed, pdf_too_large, or save_failed.
    """
    err = _validate_read_folder(folder)
    if err is not None:
        return err
    err = _validate_folder(folder)
    if err is not None:
        return err

    try:
        uid_int = int(uid)
    except (ValueError, TypeError):
        return {
            "error": "invalid_uid",
            "detail": "uid must be an integer",
            "uid": uid,
        }

    # save_to is REQUIRED for this tool (there is no in-band way to return
    # a rendered PDF otherwise). Validate before opening IMAP (fail fast).
    save_to = save_to.strip()
    if not save_to:
        return {
            "error": "invalid_save_to",
            "detail": "save_to is required",
            "save_to": save_to,
        }
    fn_error = _attachments.validate_save_filename(save_to)
    if fn_error:
        return {
            "error": "invalid_save_to",
            "detail": fn_error,
            "save_to": save_to,
        }

    uidvalidity_error: Optional[Dict] = None
    fetch_result: Optional[object] = None

    try:
        with flagged.open_readonly_session(
            folder, _BASE / "secrets"
        ) as (imap, server_uidvalidity):
            if uidvalidity not in (0, server_uidvalidity):
                uidvalidity_error = {
                    "error": "uidvalidity_changed",
                    "detail": (
                        "folder state changed; "
                        "call list_flagged_messages again"
                    ),
                    "expected": uidvalidity,
                    "actual": server_uidvalidity,
                }
            else:
                fetch_result = flagged.fetch_message(imap, uid_int)
    except (flagged.FlaggedError, OSError) as exc:
        return {
            "error": "imap_session_failed",
            "detail": str(exc)[:200],
        }

    if uidvalidity_error is not None:
        return uidvalidity_error

    if fetch_result is None:
        return {
            "error": "uid_not_found",
            "detail": f"uid {uid!r} not found in folder {folder!r}",
            "uid": uid,
            "folder": folder,
        }

    raw_bytes, _ = fetch_result  # type: ignore[misc]
    try:
        msg = email.message_from_bytes(raw_bytes, policy=email.policy.default)
    except Exception as exc:  # pylint: disable=broad-except
        logger.error(
            "save_message_pdf parse error uid=%s: %s", uid, str(exc)[:200]
        )
        return {
            "error": "message_parse_error",
            "detail": str(exc)[:200],
        }

    html_src, body_source = flagged.select_body_html(msg)
    if html_src is None:
        plain_src = flagged.select_plain_source(msg)
        if plain_src is None:
            return {
                "error": "no_renderable_body",
                "detail": (
                    "message has neither a text/html nor text/plain body"
                ),
            }
        escaped = html.escape(plain_src)
        html_src = (
            "<!DOCTYPE html><html><head>"
            '<meta charset="utf-8"></head>'
            f"<body><pre>{escaped}</pre></body></html>"
        )
        body_source = "text-fallback"

    cid_map = flagged.build_cid_map(msg)
    dropped_urls: List[str] = []

    try:
        pdf_bytes = render_pdf.render_html_to_pdf(
            html_src, cid_map, base_url=None, dropped_urls=dropped_urls
        )
    except render_pdf.WeasyPrintUnavailableError as exc:
        logger.error("save_message_pdf: weasyprint unavailable: %s", exc)
        return {
            "error": "weasyprint_unavailable",
            "detail": str(exc)[:200],
        }
    except render_pdf.RenderFailedError as exc:
        logger.error("save_message_pdf: render failed uid=%s: %s", uid, exc)
        return {
            "error": "render_failed",
            "detail": str(exc)[:200],
        }

    max_att = _config.flagged.max_attachment_bytes

    # Enforce size cap on the RENDERED PDF before any write (DoS guard).
    if len(pdf_bytes) > max_att:
        return {
            "error": "pdf_too_large",
            "detail": "rendered pdf exceeds max_attachment_bytes",
            "size_bytes": len(pdf_bytes),
            "max_bytes": max_att,
        }

    downloads_dir = Path(_config.attachments.downloads_dir)
    try:
        saved_path = _attachments.atomic_write_attachment(
            downloads_dir, save_to, pdf_bytes
        )
    except (ValueError, OSError) as exc:
        logger.error(
            "save_message_pdf save_to failed: %s", str(exc)[:200]
        )
        return {
            "error": "save_failed",
            "detail": str(exc)[:200],
        }

    saved_sha256 = _attachments.sha256_hex(pdf_bytes)

    logger.info(
        "save_message_pdf: uid=%s folder=%s body_source=%s size=%d "
        "dropped_remote_refs=%d",
        uid,
        folder,
        body_source,
        len(pdf_bytes),
        len(dropped_urls),
    )

    return {
        "uid": uid,
        "folder": folder,
        "uidvalidity": server_uidvalidity,
        "path": str(saved_path),
        "sha256": saved_sha256,
        "size_bytes": len(pdf_bytes),
        "body_source": body_source,
        "dropped_remote_refs": len(dropped_urls),
        "warning": (
            "remote images/stylesheets were not fetched; rendering is "
            "fully offline (only cid: and data: references are resolved)"
        ),
    }


# ---------------------------------------------------------------------------
# New generalised read + confirmed-action tools (architecture shift F1-F6)
# ---------------------------------------------------------------------------


@mcp.tool()
def list_messages(  # pylint: disable=too-many-locals,too-many-branches,too-many-statements,too-many-return-statements,too-many-arguments,too-many-positional-arguments
    folder: str = "INBOX",
    limit: int = 25,
    unread_only: bool = False,
    bulk_only: bool = False,
    view: str = "snippet",
    snippet_bytes: int = 0,
    max_total_bytes: int = 0,
) -> dict:
    """List messages from INBOX, Junk, or Archive with heuristic signals.

    Returns a capped snippet (default 1.5 KiB) per message; use
    get_message_body for the full body.  Newest messages first
    (highest UIDs, ties broken by INTERNALDATE).

    Args:
        folder: IMAP folder to read.  Must be in the read-folder allowlist
            (INBOX, Junk, Archive).
        limit: Maximum messages to return.  0 or negative uses the
            configured default_limit (25).  Clamped to max_limit (100).
        unread_only: When True, fetch only UNSEEN messages.
        bulk_only: When True, filter results to messages where
            signals.is_bulk is True.
        view: One of "metadata" (no body/snippet), "snippet" (default,
            1.5 KiB default snippet), or "full" (snippet capped at
            max_snippet_bytes 8 KiB).
        snippet_bytes: Override for snippet size in bytes.  0 uses the
            configured default_snippet_bytes.  Clamped to max_snippet_bytes.
        max_total_bytes: Approximate cap on total response size.  0 = no
            cap.  Once exceeded, iteration stops and truncated=true is set.

    Returns:
        Dict with keys: folder, uidvalidity, total_in_folder,
        returned, truncated, messages.  Each message: uid, uidvalidity,
        folder, internaldate, from, subject, has_attachments, signals, and
        (when view != metadata) snippet, body_source, snippet_truncated,
        attachments.  Or an error object.
    """
    err = _validate_read_folder(folder)
    if err is not None:
        return err
    err = _validate_folder(folder)
    if err is not None:
        return err

    valid_views = {"metadata", "snippet", "full"}
    if view not in valid_views:
        return {
            "error": "invalid_view",
            "detail": f"view must be one of {sorted(valid_views)}",
            "view": view,
        }

    default_limit = _config.flagged.default_limit
    max_limit = _config.flagged.max_limit
    max_snippet_hard = _config.read.max_snippet_bytes  # 8192
    default_snip = _config.read.default_snippet_bytes  # 1500

    if limit <= 0:
        limit = default_limit
    limit = min(limit, max_limit)

    # Determine effective snippet cap for this request.
    if view == "metadata":
        effective_snippet = 0  # no body decoding
    elif view == "full":
        effective_snippet = max_snippet_hard
    else:
        # view == "snippet"
        if snippet_bytes > 0:
            effective_snippet = min(snippet_bytes, max_snippet_hard)
        else:
            effective_snippet = min(default_snip, max_snippet_hard)

    criterion = "UNSEEN" if unread_only else "ALL"

    try:
        with flagged.open_readonly_session(
            folder, _BASE / "secrets"
        ) as (imap, uidvalidity):
            total_uids = read_surface.search_uids(imap, criterion)
            selected_uids = sorted(total_uids)[-limit:]
            raw_messages = flagged.fetch_messages_batch(imap, selected_uids)
    except (flagged.FlaggedError, OSError) as exc:
        return {
            "error": "imap_session_failed",
            "detail": str(exc)[:200],
        }

    out: List[Dict] = []
    approx_total = 0
    capped_by_bytes = False

    for uid, (raw, internaldate) in raw_messages.items():
        try:
            msg = email.message_from_bytes(raw, policy=email.policy.default)
        except Exception as exc:  # pylint: disable=broad-except
            logger.error(
                "list_messages: parse error uid=%d folder=%s: %s",
                uid, folder, exc,
            )
            continue

        # Compute the decoded body snippet before header_signals so it can be
        # passed as body_text for content-pattern fact extraction.  For the
        # metadata view, pass "" — content facts fall back to subject only.
        if view != "metadata":
            body_text, body_source = flagged.select_body_text(msg)
            # T2.7: clean before truncate.
            body_text = clean_body_text(body_text, body_source)
            encoded = body_text.encode("utf-8")
            snippet_truncated = len(encoded) > effective_snippet
            if snippet_truncated:
                snippet = encoded[:effective_snippet].decode(
                    "utf-8", errors="ignore"
                )
            else:
                snippet = body_text
            signals_body = body_text
        else:
            body_text = ""
            body_source = ""
            snippet = ""
            snippet_truncated = False
            signals_body = ""

        signals = read_surface.header_signals(msg, signals_body)
        if bulk_only and not signals["is_bulk"]:
            continue

        manifest = flagged.build_manifest(msg)

        entry: Dict = {
            "uid": str(uid),
            "uidvalidity": uidvalidity,
            "folder": folder,
            "internaldate": internaldate,
            "from": str(msg.get("from", "")),
            "subject": str(msg.get("subject", "")),
            "has_attachments": bool(manifest),
            "signals": signals,
        }

        if view != "metadata":
            entry["snippet"] = snippet
            entry["body_source"] = body_source
            entry["snippet_truncated"] = snippet_truncated
            entry["attachments"] = manifest

        # max_total_bytes cap: estimate this entry's contribution.
        if max_total_bytes > 0:
            entry_size = len(
                entry.get("snippet", "").encode("utf-8")
            ) + len(str(entry).encode("utf-8"))
            if approx_total + entry_size > max_total_bytes:
                capped_by_bytes = True
                break
            approx_total += entry_size

        out.append(entry)

    out.sort(
        key=lambda x: _parse_internaldate(x["internaldate"]), reverse=True
    )

    logger.info(
        "list_messages: folder=%s view=%s criterion=%s returned=%d "
        "capped=%s",
        folder, view, criterion, len(out), capped_by_bytes,
    )

    return {
        "folder": folder,
        "uidvalidity": uidvalidity,
        "total_in_folder": len(total_uids),
        "returned": len(out),
        "truncated": capped_by_bytes,
        "messages": out,
    }


@mcp.tool()
def get_message_body(  # pylint: disable=too-many-locals,too-many-return-statements
    folder: str,
    uid: str,
    uidvalidity: int = 0,
) -> dict:
    """Return the full body of a single message (up to 256 KiB).

    Read-only.  Uses BODY.PEEK[] so the Seen flag is never set.

    Args:
        folder: IMAP folder (must be in the read-folder allowlist).
        uid: Message UID as a string (from list_messages).
        uidvalidity: UIDVALIDITY token from the preceding list_messages
            call.  Pass 0 to skip the check.

    Returns:
        Dict with keys uid, folder, uidvalidity, body_text,
        body_source, body_truncated; or an error object.
    """
    err = _validate_read_folder(folder)
    if err is not None:
        return err
    err = _validate_folder(folder)
    if err is not None:
        return err

    try:
        uid_int = int(uid)
    except (ValueError, TypeError):
        return {
            "error": "invalid_uid",
            "detail": "uid must be an integer string",
            "uid": uid,
        }

    max_body = _config.flagged.max_body_bytes
    uidvalidity_error: Optional[Dict] = None
    fetch_result = None

    try:
        with flagged.open_readonly_session(
            folder, _BASE / "secrets"
        ) as (imap, server_uidvalidity):
            if uidvalidity not in (0, server_uidvalidity):
                uidvalidity_error = {
                    "error": "uidvalidity_changed",
                    "detail": (
                        "folder state changed; call list_messages again"
                    ),
                    "expected": uidvalidity,
                    "actual": server_uidvalidity,
                }
            else:
                fetch_result = flagged.fetch_message(imap, uid_int)
    except (flagged.FlaggedError, OSError) as exc:
        return {
            "error": "imap_session_failed",
            "detail": str(exc)[:200],
        }

    if uidvalidity_error is not None:
        return uidvalidity_error

    if fetch_result is None:
        return {
            "error": "uid_not_found",
            "detail": f"uid {uid!r} not found in folder {folder!r}",
            "uid": uid,
            "folder": folder,
        }

    raw_bytes, _ = fetch_result
    try:
        msg = email.message_from_bytes(
            raw_bytes, policy=email.policy.default
        )
        body_text, body_source = flagged.select_body_text(msg)
        # T2.7: clean before truncate.
        body_text = clean_body_text(body_text, body_source)
    except Exception as exc:  # pylint: disable=broad-except
        logger.error(
            "get_message_body: parse error uid=%s folder=%s: %s",
            uid, folder, exc,
        )
        return {
            "error": "message_parse_error",
            "detail": str(exc)[:200],
        }

    encoded = body_text.encode("utf-8")
    body_truncated = len(encoded) > max_body
    if body_truncated:
        body_text = encoded[:max_body].decode("utf-8", errors="ignore")

    logger.info(
        "get_message_body: uid=%s folder=%s body_source=%s truncated=%s",
        uid, folder, body_source, body_truncated,
    )

    return {
        "uid": uid,
        "folder": folder,
        "uidvalidity": uidvalidity,
        "body_text": body_text,
        "body_source": body_source,
        "body_truncated": body_truncated,
    }


# ---------------------------------------------------------------------------
# Confirmed-action gate helpers (T1.1)
# ---------------------------------------------------------------------------


class _GateResult:  # pylint: disable=too-few-public-methods
    """Outcome of _confirmed_gate_check.

    Attributes:
        blocked_by: Name of the first failing gate, or None if all pass.
        gates_evaluated: Ordered list of gate names that were checked.
        reason: Human-readable reason for blockage, or None if all pass.
    """

    __slots__ = ("blocked_by", "gates_evaluated", "reason")

    def __init__(
        self,
        blocked_by: Optional[str],
        gates_evaluated: List[str],
        reason: Optional[str],
    ) -> None:
        self.blocked_by = blocked_by
        self.gates_evaluated = gates_evaluated
        self.reason = reason

    @property
    def blocked(self) -> bool:
        """Return True when any gate is blocking."""
        return self.blocked_by is not None


def _confirmed_gate_check(
    allow_confirmed_actions: bool,
    confirm: bool,
    uidvalidity: int,
    check_allow_delete: bool = False,
) -> _GateResult:
    """Evaluate the confirmed-action gate sequence and return a _GateResult.

    Canonical gate order (T1.1 spec):
      master_switch → allow_delete (trash only) → confirm → uidvalidity

    Args:
        allow_confirmed_actions: From _config.
        confirm: Per-call caller flag.
        uidvalidity: Per-call uidvalidity (must be non-zero to act live).
        check_allow_delete: When True, also check allow_delete gate.

    Returns:
        _GateResult with blocked_by/gates_evaluated/reason populated.
    """
    gates: List[str] = []

    gates.append("master_switch")
    if not allow_confirmed_actions:
        return _GateResult(
            blocked_by="master_switch",
            gates_evaluated=gates,
            reason="allow_confirmed_actions=false in config",
        )

    if check_allow_delete:
        gates.append("allow_delete")
        if not _config.allow_delete:
            return _GateResult(
                blocked_by="allow_delete",
                gates_evaluated=gates,
                reason="allow_delete=false in config; trash simulated",
            )

    gates.append("confirm")
    if not confirm:
        return _GateResult(
            blocked_by="confirm",
            gates_evaluated=gates,
            reason="confirm=false; set confirm=true to execute",
        )

    gates.append("uidvalidity")
    if uidvalidity == 0:
        return _GateResult(
            blocked_by="uidvalidity",
            gates_evaluated=gates,
            reason=(
                "uidvalidity=0 is not accepted for live actions; "
                "pass the uidvalidity from list_messages"
            ),
        )

    return _GateResult(
        blocked_by=None,
        gates_evaluated=gates,
        reason=None,
    )


def _build_simulated_envelope(
    folder: str,
    uids: List[int],
    gate: _GateResult,
    destination: Optional[str] = None,
) -> Dict:
    """Build the standard T1.1 envelope for a fully-simulated batch.

    Args:
        folder: Source folder.
        uids: List of UID integers.
        gate: _GateResult from _confirmed_gate_check (must be blocked).
        destination: Move destination, if applicable.

    Returns:
        T1.1 envelope dict with simulated=True, confirmed=False.
    """
    results = [
        {
            "uid": str(u),
            "status": "simulated",
            "reason": gate.reason or "dry-run",
        }
        for u in uids
    ]
    payload: Dict = {
        "simulated": True,
        "confirmed": False,
        "allow_confirmed_actions": _config.allow_confirmed_actions,
        "blocked_by": gate.blocked_by,
        "gates_evaluated": gate.gates_evaluated,
        "remediation": None,
        "folder": folder,
        "results": results,
        "warnings": [],
    }
    if destination is not None:
        payload["destination"] = destination
    return payload


def _parse_uids(uids_str: str) -> Optional[List[int]]:
    """Parse a comma-separated UID string into a list of integers.

    Args:
        uids_str: Comma-separated UID string, e.g. ``"101,102,103"``.

    Returns:
        List of integer UIDs, or None if any token is not a valid integer.
    """
    try:
        return [int(u.strip()) for u in uids_str.split(",") if u.strip()]
    except ValueError:
        return None


@mcp.tool()
def move_messages(  # pylint: disable=too-many-return-statements,too-many-branches,too-many-statements,too-many-locals
    folder: str,
    uids: str,
    uidvalidity: int,
    destination: str,
    confirm: bool = False,
) -> dict:
    """Move a batch of messages to archive or trash.

    When not confirmed (or when allow_confirmed_actions=false), returns a
    simulated result with no IMAP session opened.  When confirmed and live,
    each move is audited.

    Protected-domain messages are ALLOWED to be moved but produce an audit
    WARNING entry.

    Args:
        folder: Source IMAP folder (must be in read-folder allowlist).
        uids: Comma-separated UID string, e.g. "101,102,103".
        uidvalidity: UIDVALIDITY from list_messages.  Must be non-zero for
            live execution.
        destination: Target folder.  Must be archive_folder or trash_folder
            from config.
        confirm: Set True to execute live (also requires
            allow_confirmed_actions=true in config).

    Returns:
        T1.1 envelope dict with simulated, confirmed, allow_confirmed_actions,
        blocked_by, gates_evaluated, remediation, results (per-uid list),
        and warnings.
    """
    err = _validate_read_folder(folder)
    if err is not None:
        return err
    err = _validate_folder(folder)
    if err is not None:
        return err
    err = _validate_destination(destination)
    if err is not None:
        return err

    uid_list = _parse_uids(uids)
    if uid_list is None:
        return {
            "error": "invalid_uids",
            "detail": "uids must be a comma-separated list of integers",
            "uids": uids,
        }

    gate = _confirmed_gate_check(
        _config.allow_confirmed_actions, confirm, uidvalidity
    )
    if gate.blocked:
        return _build_simulated_envelope(folder, uid_list, gate, destination)

    # Read-only uidvalidity check first.
    try:
        with flagged.open_readonly_session(
            folder, _BASE / "secrets"
        ) as (_, server_uv):
            if server_uv != uidvalidity:
                return {
                    "error": "uidvalidity_changed",
                    "detail": "folder state changed; call list_messages again",
                    "expected": uidvalidity,
                    "actual": server_uv,
                }
    except (flagged.FlaggedError, OSError) as exc:
        return {
            "error": "imap_session_failed",
            "detail": str(exc)[:200],
        }

    # Execute live.
    results: List[Dict] = []
    warnings: List[str] = []
    moves_done = 0
    max_moves = _config.actions.max_moves_per_run

    try:
        with _actions.open_readwrite_session(
            folder, _BASE / "secrets"
        ) as (imap_rw, live_uv):
            if live_uv != uidvalidity:
                return {
                    "error": "uidvalidity_changed",
                    "detail": "folder state changed during session open",
                    "expected": uidvalidity,
                    "actual": live_uv,
                }

            for uid_int in uid_list:
                if moves_done >= max_moves:
                    results.append(
                        {
                            "uid": str(uid_int),
                            "status": "skipped",
                            "reason": (
                                f"cap reached: max_moves_per_run={max_moves}"
                            ),
                        }
                    )
                    continue

                action_result = _actions.move_message(
                    imap_rw, uid_int, destination, folder
                )
                if action_result.success:
                    moves_done += 1

                # Audit the live action.
                _store.append_audit(
                    sender="",
                    method="move",
                    target=destination,
                    dry_run=False,
                    http_status=None,
                    result="success" if action_result.success else "error",
                    detail=f"uid={uid_int} folder={folder}",
                )
                logger.info(
                    "LIVE move: uid=%d folder=%s dest=%s success=%s",
                    uid_int, folder, destination, action_result.success,
                )

                results.append(
                    {
                        "uid": str(uid_int),
                        "status": "done" if action_result.success else "error",
                        "reason": action_result.detail,
                    }
                )
    except (ActionsError, SystemExit) as exc:
        logger.error("move_messages session failed: %s", exc)
        return {
            "error": "imap_session_failed",
            "detail": str(exc)[:200],
        }
    except Exception as exc:  # pylint: disable=broad-except
        logger.error("move_messages live error: %s", exc)
        return {
            "error": "imap_error",
            "detail": str(exc)[:200],
            "results": results,
        }

    warnings.append("LIVE action executed — confirmed-actions mode is ON")
    return {
        "simulated": False,
        "confirmed": True,
        "allow_confirmed_actions": _config.allow_confirmed_actions,
        "blocked_by": None,
        "gates_evaluated": gate.gates_evaluated,
        "remediation": None,
        "folder": folder,
        "destination": destination,
        "results": results,
        "warnings": warnings,
    }


@mcp.tool()
def trash_messages(  # pylint: disable=too-many-return-statements,too-many-branches,too-many-statements,too-many-locals
    folder: str,
    uids: str,
    uidvalidity: int,
    confirm: bool = False,
) -> dict:
    """Move a batch of messages to the configured trash folder.

    Soft delete only — messages are MOVED to trash (no EXPUNGE ever).
    Gated by allow_delete=true in config PLUS the confirmed-action gate.

    Protected-domain messages are allowed but produce an audit warning.

    Args:
        folder: Source IMAP folder (must be in read-folder allowlist).
        uids: Comma-separated UID string.
        uidvalidity: UIDVALIDITY from list_messages.  Non-zero required for
            live execution.
        confirm: Set True to execute live.

    Returns:
        T1.1 envelope dict with simulated, confirmed, allow_confirmed_actions,
        blocked_by, gates_evaluated, remediation, results (per-uid list),
        and warnings.
    """
    err = _validate_read_folder(folder)
    if err is not None:
        return err
    err = _validate_folder(folder)
    if err is not None:
        return err

    uid_list = _parse_uids(uids)
    if uid_list is None:
        return {
            "error": "invalid_uids",
            "detail": "uids must be a comma-separated list of integers",
            "uids": uids,
        }

    trash_folder = _config.actions.trash_folder

    gate = _confirmed_gate_check(
        _config.allow_confirmed_actions,
        confirm,
        uidvalidity,
        check_allow_delete=True,
    )
    if gate.blocked:
        return _build_simulated_envelope(folder, uid_list, gate)

    # Read-only uidvalidity check.
    try:
        with flagged.open_readonly_session(
            folder, _BASE / "secrets"
        ) as (_, server_uv):
            if server_uv != uidvalidity:
                return {
                    "error": "uidvalidity_changed",
                    "detail": "folder state changed; call list_messages again",
                    "expected": uidvalidity,
                    "actual": server_uv,
                }
    except (flagged.FlaggedError, OSError) as exc:
        return {
            "error": "imap_session_failed",
            "detail": str(exc)[:200],
        }

    results: List[Dict] = []
    warnings: List[str] = []
    trashes_done = 0
    max_trashes = _config.actions.max_trashes_per_run

    try:
        with _actions.open_readwrite_session(
            folder, _BASE / "secrets"
        ) as (imap_rw, live_uv):
            if live_uv != uidvalidity:
                return {
                    "error": "uidvalidity_changed",
                    "detail": "folder state changed during session open",
                    "expected": uidvalidity,
                    "actual": live_uv,
                }

            for uid_int in uid_list:
                if trashes_done >= max_trashes:
                    results.append(
                        {
                            "uid": str(uid_int),
                            "status": "skipped",
                            "reason": (
                                f"cap reached: "
                                f"max_trashes_per_run={max_trashes}"
                            ),
                        }
                    )
                    continue

                action_result = _actions.trash_message(
                    imap_rw, uid_int, trash_folder, folder
                )
                if action_result.success:
                    trashes_done += 1

                _store.append_audit(
                    sender="",
                    method="trash",
                    target=trash_folder,
                    dry_run=False,
                    http_status=None,
                    result="success" if action_result.success else "error",
                    detail=f"uid={uid_int} folder={folder}",
                )
                logger.info(
                    "LIVE trash: uid=%d folder=%s trash_folder=%s success=%s",
                    uid_int, folder, trash_folder, action_result.success,
                )

                results.append(
                    {
                        "uid": str(uid_int),
                        "status": (
                            "done" if action_result.success else "error"
                        ),
                        "reason": action_result.detail,
                    }
                )
    except (ActionsError, SystemExit) as exc:
        logger.error("trash_messages session failed: %s", exc)
        return {
            "error": "imap_session_failed",
            "detail": str(exc)[:200],
        }
    except Exception as exc:  # pylint: disable=broad-except
        logger.error("trash_messages live error: %s", exc)
        return {
            "error": "imap_error",
            "detail": str(exc)[:200],
            "results": results,
        }

    warnings.append("LIVE action executed — confirmed-actions mode is ON")
    return {
        "simulated": False,
        "confirmed": True,
        "allow_confirmed_actions": _config.allow_confirmed_actions,
        "blocked_by": None,
        "gates_evaluated": gate.gates_evaluated,
        "remediation": None,
        "folder": folder,
        "results": results,
        "warnings": warnings,
    }


def _run_header_unsubscribe(  # pylint: disable=too-many-return-statements,too-many-branches,too-many-statements,too-many-locals
    folder: str,
    uid: str,
    uidvalidity: int,
    confirm: bool = False,
) -> dict:
    """Unsubscribe via the List-Unsubscribe headers of a specific message.

    Unlike unsubscribe_sender (which requires the sender to be in
    policy.toml), this helper lets the model propose an unsubscribe for ANY
    bulk sender.  Human approval (confirm=True + allow_confirmed_actions=True)
    permits the action.

    Gates applied in order:
    1. Folder allowlist + charset check.
    2. Read-only fetch of the message headers.
    3. DKIM/DMARC gate via auth.check_sender_auth (FAIL-CLOSED).
    4. Protected-domain HARD-BLOCK on unsubscribe.
    5. Confirmed-action gate (allow_confirmed_actions AND confirm AND
       uidvalidity != 0).
    6. SSRF + domain-allowlist enforcement inside perform_unsubscribe.

    This is the T1.1 header-unsubscribe body, extracted verbatim from the
    ``unsubscribe_message`` tool so it can be reused by both the public
    ``unsubscribe_message`` tool and the ``unsubscribe_with_fallback``
    orchestrator.  Its return contract is byte-identical to the previous
    inline implementation.

    Args:
        folder: Source IMAP folder (read-folder allowlist).
        uid: Message UID as a string.
        uidvalidity: UIDVALIDITY from list_messages.
        confirm: True to execute live; False to simulate.

    Returns:
        T1.1 envelope dict when the action gate is evaluated; a plain error
        dict when a security hard-block (DKIM/DMARC or protected-domain) fires
        before the gate.
    """
    err = _validate_read_folder(folder)
    if err is not None:
        return err
    err = _validate_folder(folder)
    if err is not None:
        return err

    try:
        uid_int = int(uid)
    except (ValueError, TypeError):
        return {
            "error": "invalid_uid",
            "detail": "uid must be an integer string",
            "uid": uid,
        }

    # Fetch headers read-only to evaluate gates.
    raw_headers_bytes: Optional[bytes] = None
    try:
        with flagged.open_readonly_session(
            folder, _BASE / "secrets"
        ) as (imap_ro, server_uv):
            if uidvalidity not in (0, server_uv):
                return {
                    "error": "uidvalidity_changed",
                    "detail": "folder state changed; call list_messages again",
                    "expected": uidvalidity,
                    "actual": server_uv,
                }
            fetch_result = flagged.fetch_message(imap_ro, uid_int)
            if fetch_result is None:
                return {
                    "error": "uid_not_found",
                    "detail": f"uid {uid!r} not found in folder {folder!r}",
                    "uid": uid,
                    "folder": folder,
                }
            raw_headers_bytes, _ = fetch_result
    except (flagged.FlaggedError, OSError) as exc:
        return {
            "error": "imap_session_failed",
            "detail": str(exc)[:200],
        }

    # Parse headers for gate checks.
    headers = parse_message_headers(raw_headers_bytes)

    # Parse sender address up-front so all audit rows use the bare address.
    from_header = headers.get("from", "")
    _, sender_addr = _parse_from_header_local(from_header)
    domain = (
        sender_addr.split("@", 1)[-1] if "@" in sender_addr else ""
    )

    # C1: Reject messages with multiple From: headers before auth.
    # parse_message_headers joins duplicate headers with " | "; the presence
    # of that delimiter signals ambiguity that the DMARC binding cannot resolve.
    all_from_values = headers.get("from", "")
    multi_from = " | " in all_from_values

    # F5: DKIM/DMARC gate — fail-closed.
    auth_passed, authenticated_from_domain = check_sender_auth(headers)
    if not auth_passed:
        _store.append_audit(
            sender=sender_addr[:200],
            method="unsubscribe_message",
            target="",
            dry_run=False,
            http_status=None,
            result="refused_dkim",
            detail="[block_class=auth_failed] dkim/dmarc gate failed",
        )
        return {
            "error": "auth_gate_failed",
            "block_class": "auth_failed",
            "detail": (
                "DKIM/DMARC check failed; unsubscribe refused "
                "(fail-closed)"
            ),
        }

    # C1: Derive verified_sender_domain from the DMARC-authenticated
    # header.from= token, not the raw From header.  When the message has
    # multiple From: headers, or the trusted AR header carried no
    # header.from= token, skip the implicit sender-domain authorization
    # (fall back to mailto_allowed_domains only).
    if multi_from or authenticated_from_domain is None:
        verified_sender_domain = ""
        if multi_from:
            logger.warning(
                "unsubscribe_message: multiple From: headers detected for "
                "uid=%s — suppressing implicit sender-domain mailto auth",
                uid,
            )
    else:
        verified_sender_domain = authenticated_from_domain

    # F4: Protected-domain HARD-BLOCK on unsubscribe.
    if domain in _config.protected_domains:
        _store.append_audit(
            sender=sender_addr[:200],
            method="unsubscribe_message",
            target="",
            dry_run=False,
            http_status=None,
            result="refused_protected",
            detail=f"protected domain: {domain}",
        )
        return {
            "error": "protected_domain",
            "detail": "unsubscribe hard-blocked for protected domain",
            "domain": domain,
        }

    list_unsub = headers.get("list-unsubscribe", "")
    list_unsub_post = headers.get("list-unsubscribe-post", "")

    if not list_unsub:
        return {
            "error": "no_unsubscribe_header",
            "detail": "message has no List-Unsubscribe header",
        }

    # Confirmed-action gate (domain_allowlist/dkim_dmarc already checked above).
    gate = _confirmed_gate_check(
        _config.allow_confirmed_actions, confirm, uidvalidity
    )
    is_dry = gate.blocked
    dry_run_mode = is_dry

    try:
        smtp_username = read_secret(_BASE / "secrets" / "icloud_email")
        smtp_password = read_secret(_BASE / "secrets" / "icloud_app_password")
    except (Exception, SystemExit) as exc:  # pylint: disable=broad-except
        logger.error("Failed to read SMTP credentials: %s", exc)
        return {
            "error": "smtp_credentials_unavailable",
            "detail": str(exc)[:200],
        }

    # Build a transient GlobalConfig with dry_run reflecting gate state.
    cfg_for_unsub = dataclasses.replace(_config, dry_run=dry_run_mode)

    result = perform_unsubscribe(
        sender=sender_addr,
        unsubscribe_header=list_unsub,
        unsubscribe_post_header=list_unsub_post,
        global_config=cfg_for_unsub,
        smtp_username=smtp_username,
        smtp_password=smtp_password,
        verified_sender_domain=verified_sender_domain,
    )

    _store.append_audit(
        sender=sender_addr[:200],
        method=result.method,
        target=result.target[:200] if result.target else "",
        dry_run=dry_run_mode,
        http_status=result.http_status,
        result=result.result,
        detail=(
            f"uid={uid} folder={folder} "
            f"confirmed={confirm} gate_blocked={is_dry}"
        ),
    )

    if not dry_run_mode:
        logger.warning(
            "LIVE unsubscribe: uid=%s folder=%s sender=%s method=%s result=%s",
            uid, folder, sender_addr, result.method, result.result,
        )

    # Map UnsubscribeResult to T1.1 envelope.
    _result_to_status = {
        "success": "done",
        "success-simulated": "simulated",
        "deferred": "skipped",
        "failed": "error",
    }
    uid_status = _result_to_status.get(result.result, "skipped")

    warnings: List[str] = []

    if result.fallback_reason:
        warnings.append(f"mailto fallback attempted: {result.fallback_reason}")
    if result.method_used == "mailto":
        warnings.append("unsubscribe completed via mailto fallback")

    # Determine remediation hint: prefer block_class-driven remediation from
    # UnsubscribeResult; fall back to legacy heuristics for backward compat.
    remediation: Optional[str] = result.remediation
    if remediation is None and result.result == "deferred":
        if "not in unsubscribe_allowed_domains" in result.detail:
            remediation = "approve host in unsubscribe_allowed_domains"
        elif (
            result.methods_attempted
            and "mailto" not in result.methods_attempted
            and "mailto-refused" not in " ".join(result.methods_attempted)
        ):
            remediation = "use_mailto"

    if not dry_run_mode:
        warnings.append("LIVE action executed — confirmed-actions mode is ON")

    return {
        "simulated": dry_run_mode,
        "confirmed": not dry_run_mode,
        "allow_confirmed_actions": _config.allow_confirmed_actions,
        "blocked_by": gate.blocked_by,
        "gates_evaluated": ["dkim_dmarc", "egress_policy"] + gate.gates_evaluated,
        "remediation": remediation,
        # B.5: block_class taxonomy surfaced in the envelope.
        "block_class": result.block_class,
        "results": [
            {
                "uid": uid,
                "status": uid_status,
                "reason": result.detail,
                "block_class": result.block_class,
            }
        ],
        "warnings": warnings,
        # Additional unsubscribe-specific context.
        "sender": sender_addr,
        "method": result.method,
        "method_used": result.method_used,
        "methods_attempted": result.methods_attempted,
        "http_status": result.http_status,
    }


@mcp.tool()
def unsubscribe_message(
    folder: str,
    uid: str,
    uidvalidity: int,
    confirm: bool = False,
) -> dict:
    """Unsubscribe via the List-Unsubscribe headers of a specific message.

    Thin wrapper around ``_run_header_unsubscribe``; see that helper's
    docstring for the full gate sequence and return-envelope semantics.
    Its public contract is unchanged by the refactor: this tool returns the
    helper's output verbatim.

    Args:
        folder: Source IMAP folder (read-folder allowlist).
        uid: Message UID as a string.
        uidvalidity: UIDVALIDITY from list_messages.
        confirm: True to execute live; False to simulate.

    Returns:
        T1.1 envelope dict when the action gate is evaluated; a plain error
        dict when a security hard-block (DKIM/DMARC or protected-domain) fires
        before the gate.
    """
    return _run_header_unsubscribe(
        folder=folder, uid=uid, uidvalidity=uidvalidity, confirm=confirm
    )


# ---------------------------------------------------------------------------
# ADR-016 Phase 1 — find_unsubscribe_links (read-only body-link discovery)
# ---------------------------------------------------------------------------


def _surface_body_links(  # pylint: disable=too-many-return-statements,too-many-locals
    folder: str,
    uid: str,
    uidvalidity: int = 0,
) -> dict:
    """Surface candidate unsubscribe/preferences links found in a message body.

    Read-only.  This helper NEVER issues an outbound HTTP request — for each
    HTTPS candidate it only calls ``egress_check`` (DNS resolution + policy
    evaluation) so a caller can see whether a follow-up probe would be
    blocked, without ever connecting to the target.  It also never sets the
    IMAP \\Seen flag (uses BODY.PEEK[] via ``flagged.fetch_message``).

    This is the surfacing half of the ADR-016 body-link unsubscribe flow;
    it does not classify a landing page or take any action — see
    ``probe_unsubscribe_link`` for the gated GET probe.  Extracted verbatim
    from the ``find_unsubscribe_links`` tool so it can be reused by both that
    tool and the ``unsubscribe_with_fallback`` orchestrator.

    Args:
        folder: Source IMAP folder (read-folder allowlist).
        uid: Message UID as a string.
        uidvalidity: UIDVALIDITY from list_messages. 0 skips the check
            (read-only tools tolerate a stale uidvalidity).

    Returns:
        Dict with folder, uid, uidvalidity, from, has_list_unsubscribe_header,
        auth_signals, candidates (each with an egress_preview), candidate_count,
        and a note. Or an error dict on a gate failure.
    """
    err = _validate_read_folder(folder)
    if err is not None:
        return err
    err = _validate_folder(folder)
    if err is not None:
        return err

    try:
        uid_int = int(uid)
    except (ValueError, TypeError):
        return {
            "error": "invalid_uid",
            "detail": "uid must be an integer string",
            "uid": uid,
        }

    try:
        with flagged.open_readonly_session(
            folder, _BASE / "secrets"
        ) as (imap_ro, server_uv):
            if uidvalidity not in (0, server_uv):
                return {
                    "error": "uidvalidity_changed",
                    "detail": "folder state changed; call list_messages again",
                    "expected": uidvalidity,
                    "actual": server_uv,
                }
            fetch_result = flagged.fetch_message(imap_ro, uid_int)
            if fetch_result is None:
                return {
                    "error": "uid_not_found",
                    "detail": f"uid {uid!r} not found in folder {folder!r}",
                    "uid": uid,
                    "folder": folder,
                }
            raw_bytes, _ = fetch_result
    except (flagged.FlaggedError, OSError) as exc:
        return {
            "error": "imap_session_failed",
            "detail": str(exc)[:200],
        }

    headers = parse_message_headers(raw_bytes)
    from_header = headers.get("from", "")
    _, sender_addr = _parse_from_header_local(from_header)

    try:
        msg = email.message_from_bytes(raw_bytes, policy=email.policy.default)
        candidates = extract_unsubscribe_candidates(msg)
    except Exception as exc:  # pylint: disable=broad-except
        logger.error(
            "find_unsubscribe_links: parse error uid=%s: %s", uid, str(exc)[:200]
        )
        return {
            "error": "message_parse_error",
            "detail": str(exc)[:200],
        }

    auth_signals = extract_auth_signals(headers)

    candidate_dicts: List[Dict] = []
    for candidate in candidates:
        entry = dataclasses.asdict(candidate)
        if candidate.scheme == "https":
            verdict = egress_check(candidate.url, _config)
            entry["egress_preview"] = {
                "outcome": verdict.outcome.value
                if hasattr(verdict.outcome, "value")
                else str(verdict.outcome),
                "block_class": verdict.block_class,
                "detail": verdict.detail,
            }
        else:
            entry["egress_preview"] = None
        candidate_dicts.append(entry)

    _store.append_audit(
        sender=sender_addr[:200],
        method="find_unsubscribe_links",
        target="",
        dry_run=True,
        http_status=None,
        result="surfaced",
        detail=f"uid={uid} folder={folder} candidate_count={len(candidates)}",
    )

    return {
        "folder": folder,
        "uid": uid,
        "uidvalidity": uidvalidity,
        "from": sender_addr,
        "has_list_unsubscribe_header": bool(headers.get("list-unsubscribe", "")),
        "auth_signals": auth_signals,
        "candidates": candidate_dicts,
        "candidate_count": len(candidate_dicts),
        "note": (
            "read-only: no outbound request was made; egress_preview reflects "
            "DNS resolution + policy evaluation only"
        ),
    }


@mcp.tool()
def find_unsubscribe_links(
    folder: str,
    uid: str,
    uidvalidity: int = 0,
) -> dict:
    """Surface candidate unsubscribe/preferences links found in a message body.

    Thin wrapper around ``_surface_body_links``; see that helper's docstring
    for the read-only guarantees and return shape. Its public contract is
    unchanged by the refactor: this tool returns the helper's output
    verbatim.

    Args:
        folder: Source IMAP folder (read-folder allowlist).
        uid: Message UID as a string.
        uidvalidity: UIDVALIDITY from list_messages. 0 skips the check
            (read-only tools tolerate a stale uidvalidity).

    Returns:
        Dict with folder, uid, uidvalidity, from, has_list_unsubscribe_header,
        auth_signals, candidates (each with an egress_preview), candidate_count,
        and a note. Or an error dict on a gate failure.
    """
    return _surface_body_links(folder=folder, uid=uid, uidvalidity=uidvalidity)


# ---------------------------------------------------------------------------
# ADR-016 Phase 1.5 — probe_unsubscribe_link (gated GET probe + classify)
# ---------------------------------------------------------------------------


@mcp.tool()
def probe_unsubscribe_link(  # pylint: disable=too-many-return-statements,too-many-branches,too-many-statements,too-many-locals
    folder: str,
    uid: str,
    uidvalidity: int,
    url: str,
    confirm: bool = False,
) -> dict:
    """Fetch (GET) a body-link unsubscribe candidate and classify the landing page.

    Never auto-submits any form found on the landing page — this tool only
    fetches the ONE url passed in and reports what it found.  Acting on a
    discovered form is out of scope (see the ADR-016 Phase 2 design, not
    implemented here).

    Gates applied in order (cloned from ``unsubscribe_message`` plus two
    probe-specific additions):
    1. Folder allowlist + charset check.
    2. Read-only fetch of the message + uidvalidity check.
    3. URL-provenance check: ``url`` must be byte-identical to one of the
       candidates ``extract_unsubscribe_candidates`` finds in THIS message.
    4. DKIM/DMARC gate via auth.check_sender_auth (FAIL-CLOSED).
    5. Protected-domain HARD-BLOCK.
    6. ``allow_body_link_unsubscribe`` master switch (config.toml).
    7. Confirmed-action gate (allow_confirmed_actions AND confirm AND
       uidvalidity != 0).

    When the gate is not fully satisfied (dry_run), only ``egress_check`` is
    evaluated and reported — no fetch is made.

    Args:
        folder: Source IMAP folder (read-folder allowlist).
        uid: Message UID as a string.
        uidvalidity: UIDVALIDITY from list_messages.
        url: The candidate URL to probe. Must match a candidate surfaced by
            find_unsubscribe_links for this exact message.
        confirm: True to execute the live GET; False to simulate.

    Returns:
        T1.1-style envelope dict with the probe outcome, or a plain error
        dict when a security hard-block fires before the gate.
    """
    err = _validate_read_folder(folder)
    if err is not None:
        return err
    err = _validate_folder(folder)
    if err is not None:
        return err

    try:
        uid_int = int(uid)
    except (ValueError, TypeError):
        return {
            "error": "invalid_uid",
            "detail": "uid must be an integer string",
            "uid": uid,
        }

    try:
        with flagged.open_readonly_session(
            folder, _BASE / "secrets"
        ) as (imap_ro, server_uv):
            if uidvalidity not in (0, server_uv):
                return {
                    "error": "uidvalidity_changed",
                    "detail": "folder state changed; call list_messages again",
                    "expected": uidvalidity,
                    "actual": server_uv,
                }
            fetch_result = flagged.fetch_message(imap_ro, uid_int)
            if fetch_result is None:
                return {
                    "error": "uid_not_found",
                    "detail": f"uid {uid!r} not found in folder {folder!r}",
                    "uid": uid,
                    "folder": folder,
                }
            raw_bytes, _ = fetch_result
    except (flagged.FlaggedError, OSError) as exc:
        return {
            "error": "imap_session_failed",
            "detail": str(exc)[:200],
        }

    headers = parse_message_headers(raw_bytes)
    from_header = headers.get("from", "")
    _, sender_addr = _parse_from_header_local(from_header)
    domain = sender_addr.split("@", 1)[-1] if "@" in sender_addr else ""

    try:
        msg = email.message_from_bytes(raw_bytes, policy=email.policy.default)
        candidates = extract_unsubscribe_candidates(msg)
    except Exception as exc:  # pylint: disable=broad-except
        logger.error(
            "probe_unsubscribe_link: parse error uid=%s: %s", uid, str(exc)[:200]
        )
        return {
            "error": "message_parse_error",
            "detail": str(exc)[:200],
        }

    # URL-provenance check: the passed url must be byte-identical to a
    # candidate this message actually contains. Prevents probing an
    # arbitrary caller-supplied URL under the guise of "unsubscribing".
    if url not in {c.url for c in candidates}:
        return {
            "error": "url_not_in_message",
            "detail": (
                "url does not match any candidate extracted from this "
                "message; call find_unsubscribe_links first"
            ),
        }

    all_from_values = headers.get("from", "")
    multi_from = " | " in all_from_values

    # F5: DKIM/DMARC gate — fail-closed.
    auth_passed, authenticated_from_domain = check_sender_auth(headers)
    if not auth_passed:
        _store.append_audit(
            sender=sender_addr[:200],
            method="probe_unsubscribe_link",
            target="",
            dry_run=False,
            http_status=None,
            result="refused_dkim",
            detail="[block_class=auth_failed] dkim/dmarc gate failed",
        )
        return {
            "error": "auth_gate_failed",
            "block_class": "auth_failed",
            "detail": (
                "DKIM/DMARC check failed; probe refused (fail-closed)"
            ),
        }
    del authenticated_from_domain, multi_from  # not needed beyond the gate

    # Protected-domain HARD-BLOCK.
    if domain in _config.protected_domains:
        _store.append_audit(
            sender=sender_addr[:200],
            method="probe_unsubscribe_link",
            target="",
            dry_run=False,
            http_status=None,
            result="refused_protected",
            detail=f"protected domain: {domain}",
        )
        return {
            "error": "protected_domain",
            "detail": "probe hard-blocked for protected domain",
            "domain": domain,
        }

    safe_url_sha256 = hashlib.sha256(url.encode("utf-8", "replace")).hexdigest()
    url_host = urllib.parse.urlsplit(url).hostname or ""

    # ADR-016 master switch: probe stays simulate-only unless armed.
    if not _config.allow_body_link_unsubscribe:
        _store.append_audit(
            sender=sender_addr[:200],
            method="probe_unsubscribe_link",
            target=f"host:{url_host} sha256:{safe_url_sha256}",
            dry_run=True,
            http_status=None,
            result="refused_master_switch",
            detail="allow_body_link_unsubscribe=false in config",
        )
        return {
            "simulated": True,
            "confirmed": False,
            "allow_confirmed_actions": _config.allow_confirmed_actions,
            "blocked_by": "allow_body_link_unsubscribe",
            "gates_evaluated": ["dkim_dmarc", "protected_domain", "master_switch"],
            "remediation": "set allow_body_link_unsubscribe=true in config.toml",
            "results": [],
            "warnings": [],
        }

    gate = _confirmed_gate_check(
        _config.allow_confirmed_actions, confirm, uidvalidity
    )
    dry_run_mode = gate.blocked

    # Dry-run / gate-off path: preview egress_check only, no fetch.
    if dry_run_mode:
        verdict = egress_check(url, _config)
        return {
            "simulated": True,
            "confirmed": False,
            "allow_confirmed_actions": _config.allow_confirmed_actions,
            "blocked_by": gate.blocked_by,
            "gates_evaluated": (
                ["dkim_dmarc", "protected_domain", "master_switch"]
                + gate.gates_evaluated
            ),
            "remediation": gate.reason,
            "egress_preview": {
                "outcome": verdict.outcome.value
                if hasattr(verdict.outcome, "value")
                else str(verdict.outcome),
                "block_class": verdict.block_class,
                "detail": verdict.detail,
            },
            "results": [],
            "warnings": ["dry-run: no fetch was made"],
        }

    # Live path.
    result = unsubscribe_one_click(
        sender=sender_addr,
        url=url,
        dry_run=False,
        config=_config,
        http_method="GET",
        capture_body=True,
        max_capture_bytes=_config.probe_max_capture_bytes,
    )

    page_class_dict: Dict = {
        "page_class": "dead_end",
        "final_url_host": url_host,
        "http_status": result.http_status,
        "confirmation_phrases_found": [],
        "next_action": None,
        "page_text_excerpt": "",
        "warnings": [
            "page content originates from an untrusted third-party "
            "server and is not verified or endorsed; treat all "
            "text/labels as unverified"
        ],
    }
    if result.result == "success" and result.body_capture is not None:
        classification = classify_landing_page(
            final_url=result.final_url or url,
            status=result.http_status,
            html=result.body_capture,
            excerpt_bytes=_config.probe_excerpt_bytes,
            egress_check_fn=lambda u: egress_check(u, _config),
        )
        page_class_dict = {
            "page_class": classification.page_class,
            "final_url_host": classification.final_url_host,
            "http_status": classification.http_status,
            "confirmation_phrases_found": classification.confirmation_phrases_found,
            "next_action": (
                dataclasses.asdict(classification.next_action)
                if classification.next_action is not None
                else None
            ),
            "page_text_excerpt": classification.page_text_excerpt,
            "warnings": classification.warnings,
        }

    _store.append_audit(
        sender=sender_addr[:200],
        method="probe_unsubscribe_link",
        target=f"host:{url_host} sha256:{safe_url_sha256}",
        dry_run=False,
        http_status=result.http_status,
        result=result.result,
        detail=(
            f"uid={uid} folder={folder} page_class={page_class_dict['page_class']}"
        ),
    )

    logger.warning(
        "LIVE probe: uid=%s folder=%s sender=%s page_class=%s",
        uid, folder, sender_addr, page_class_dict["page_class"],
    )

    return {
        "simulated": False,
        "confirmed": True,
        "allow_confirmed_actions": _config.allow_confirmed_actions,
        "blocked_by": None,
        "gates_evaluated": (
            ["dkim_dmarc", "protected_domain", "master_switch"]
            + gate.gates_evaluated
        ),
        "remediation": result.remediation,
        "block_class": result.block_class,
        "http_status": result.http_status,
        "results": [page_class_dict],
        "warnings": ["LIVE probe executed — confirmed-actions mode is ON"],
    }


# ---------------------------------------------------------------------------
# ADR-016 Phase 1.6 — unsubscribe_with_fallback (header auto, then surface)
# ---------------------------------------------------------------------------

# Gate names that indicate the header attempt was never tried live (the
# confirmed-action gate stopped it before perform_unsubscribe ran a real
# network call). These must TERMINATE with the simulated envelope as-is —
# there is nothing live to escalate from.
_HEADER_GATE_BLOCK_NAMES = frozenset({"master_switch", "confirm", "uidvalidity"})

# block_class values on a LIVE (non-simulated) header result that indicate
# the header path itself failed/was refused for a reason a body-link
# fallback cannot help with — these TERMINATE rather than escalate.
_HEADER_TERMINAL_BLOCK_CLASSES = frozenset({"auth_failed"})


def _classify_header_envelope(header_result: dict) -> str:
    """Classify a header-unsubscribe envelope into an escalation verdict.

    Args:
        header_result: The dict returned by ``_run_header_unsubscribe``.

    Returns:
        One of ``"terminate"``, ``"fallback"``, or ``"done"``.
    """
    # Plain (pre-gate) error dicts: no "simulated" key present.
    if "simulated" not in header_result:
        error = header_result.get("error")
        if error == "no_unsubscribe_header":
            return "fallback"
        # auth_gate_failed, protected_domain, uidvalidity_changed,
        # uid_not_found, invalid_uid, imap_session_failed,
        # smtp_credentials_unavailable, invalid_folder, etc.
        return "terminate"

    # Gate-blocked simulation: the header path was never tried live.
    if header_result.get("simulated") and (
        header_result.get("blocked_by") in _HEADER_GATE_BLOCK_NAMES
    ):
        return "terminate"

    block_class = header_result.get("block_class")
    if block_class in _HEADER_TERMINAL_BLOCK_CLASSES:
        return "terminate"

    results = header_result.get("results") or [{}]
    status = results[0].get("status")

    if status in ("done", "simulated"):
        # "done" is a live success (result="success"). "simulated" here
        # means the header attempt mapped a "success-simulated" outcome —
        # i.e. it would have succeeded had confirmed-actions been armed.
        # Neither case reflects a live failure, so neither escalates.
        return "done"

    # Anything else — "error" (failed/retryable/hard_policy/no_mechanism)
    # or "skipped" (deferred, e.g. pending_review) — escalates to the
    # read-only body-link surface.
    return "fallback"


def _fallback_reason_for(header_result: dict) -> str:
    """Derive the human-readable ``fallback.reason`` string.

    Args:
        header_result: The dict returned by ``_run_header_unsubscribe``.

    Returns:
        A short snake_case-ish reason string describing why the fallback
        path was taken.
    """
    if "simulated" not in header_result:
        if header_result.get("error") == "no_unsubscribe_header":
            return "no_list_unsubscribe_header"
        return str(header_result.get("error") or "header_unsubscribe_error")

    block_class = header_result.get("block_class")
    if block_class:
        return f"header_{block_class}"

    results = header_result.get("results") or [{}]
    status = results[0].get("status")
    if status == "error":
        return "header_failed"
    if status == "skipped":
        return "header_deferred"
    return "header_unsubscribe_unsuccessful"


@mcp.tool()
def unsubscribe_with_fallback(
    folder: str,
    uid: str,
    uidvalidity: int,
    confirm: bool = False,
) -> dict:
    """Try standards-based header unsubscribe, then surface body links on failure.

    Pure composition over two already-reviewed primitives:
    ``_run_header_unsubscribe`` (the full T1.1 header-unsubscribe gate chain
    and live action) and ``_surface_body_links`` (the ADR-016 read-only
    body-link discovery surface). This orchestrator performs AT MOST ONE
    live action — the header attempt — and NEVER itself fetches a body
    link; it only surfaces candidates for a caller to probe explicitly via
    ``probe_unsubscribe_link``.

    Escalation matrix:

    TERMINATE (header envelope returned as-is, fallback NOT surfaced):
        - DKIM/DMARC auth-gate failure (``auth_failed``).
        - Protected-domain block.
        - State errors (uidvalidity changed / uid not found / invalid
          folder / invalid uid / IMAP or SMTP-credential failure).
        - Gate-blocked simulation (master switch off / confirm=false /
          uidvalidity=0): the header path was never tried live, so there
          is nothing to escalate from.

    FALLBACK-SURFACE (body-link candidates surfaced, read-only, no confirm
    needed to surface):
        - No List-Unsubscribe header / no usable mechanism (``no_mechanism``).
        - One-click blocked by egress/SSRF/denied domain/private IP
          (``hard_policy``).
        - One-click deferred pending review (``pending_review``).
        - One-click 4xx/403/transient/timeout/5xx (``retryable``/failed).
        - Mailto egress-blocked (``hard_policy``).

    DONE (header envelope returned, no escalation needed):
        - Header success: one-click 2xx or mailto sent
          (``success``/``success-simulated``).

    Args:
        folder: Source IMAP folder (read-folder allowlist).
        uid: Message UID as a string.
        uidvalidity: UIDVALIDITY from list_messages.
        confirm: True to allow the header attempt to execute live; False to
            simulate it. Fallback surfacing (when reached) is always
            read-only regardless of this flag.

    Returns:
        A dict discriminated by top-level ``path`` ("header" or
        "fallback_surface"):

        - ``path="header"``: includes ``header_result`` (the header
          envelope, verbatim) plus top-level ``status``, ``block_class``,
          and ``gates_evaluated`` mirrored from it for existing consumers.
        - ``path="fallback_surface"``: ``status="fallback_available"`` plus
          a ``fallback`` object with ``reason``, ``header_block_class``,
          ``header_http_status``, ``candidates``, ``candidate_count``,
          ``auth_signals``, ``probe_enabled``, and ``next_step``.
    """
    header_result = _run_header_unsubscribe(
        folder=folder, uid=uid, uidvalidity=uidvalidity, confirm=confirm
    )

    verdict = _classify_header_envelope(header_result)

    if verdict in ("terminate", "done"):
        return {
            "path": "header",
            "header_result": header_result,
            "status": header_result.get("error")
            or (header_result.get("results") or [{}])[0].get("status"),
            "block_class": header_result.get("block_class"),
            "gates_evaluated": header_result.get("gates_evaluated"),
        }

    # Fallback-surface: read-only, no live action beyond the single header
    # attempt already made above. Never calls probe_unsubscribe_link and
    # never passes capture_body=True — only composes _surface_body_links.
    surface = _surface_body_links(folder=folder, uid=uid, uidvalidity=uidvalidity)

    results = header_result.get("results") or [{}]
    probe_enabled = _config.allow_body_link_unsubscribe
    if probe_enabled:
        next_step = (
            "call probe_unsubscribe_link(folder, uid, uidvalidity, url, "
            "confirm=true) with a chosen candidate url"
        )
    else:
        next_step = (
            "body-link probing is disabled; set "
            "allow_body_link_unsubscribe=true in config.toml to proceed"
        )

    fallback: Dict = {
        "reason": _fallback_reason_for(header_result),
        "header_block_class": header_result.get("block_class"),
        "header_http_status": header_result.get("http_status"),
        "candidates": surface.get("candidates", []),
        "candidate_count": surface.get("candidate_count", 0),
        "auth_signals": surface.get("auth_signals"),
        "probe_enabled": probe_enabled,
        "next_step": next_step,
    }
    if results[0].get("block_class") == "pending_review":
        fallback["remediation"] = header_result.get("remediation")

    return {
        "path": "fallback_surface",
        "status": "fallback_available",
        "header_result": header_result,
        "fallback": fallback,
    }


# ---------------------------------------------------------------------------
# T1.2 — get_config capabilities tool
# ---------------------------------------------------------------------------


@mcp.tool()
def get_config() -> dict:
    """Return the effective server configuration visible to MCP callers.

    Read-only.  No secrets or filesystem paths beyond folder names are
    exposed.  The ``unsubscribe_allowed_domains`` field reports the REAL
    effective list (module defaults when config falls back to []).

    Returns:
        Dict with read_folders, archive_folder, trash_folder,
        allow_confirmed_actions, allow_delete, allow_mcp_policy_writes,
        dry_run, size_caps, unsubscribe_allowed_domains, mailto_allowed_domains,
        protected_domains, and the ADR-016 body-link switches
        (allow_body_link_unsubscribe, probe_excerpt_bytes,
        probe_max_capture_bytes).
    """
    return {
        "read_folders": _config.read.folders,
        "archive_folder": _config.actions.archive_folder,
        "trash_folder": _config.actions.trash_folder,
        "allow_confirmed_actions": _config.allow_confirmed_actions,
        "allow_delete": _config.allow_delete,
        "allow_mcp_policy_writes": _config.allow_mcp_policy_writes,
        "dry_run": _config.dry_run,
        "size_caps": {
            "max_snippet_bytes": _config.read.max_snippet_bytes,
            "max_body_bytes": _config.flagged.max_body_bytes,
            "max_attachment_bytes": _config.flagged.max_attachment_bytes,
            "max_moves_per_run": _config.actions.max_moves_per_run,
            "max_trashes_per_run": _config.actions.max_trashes_per_run,
            "max_unsubscribes_per_run": (
                _config.rate_limits.max_unsubscribes_per_run
            ),
            "list_default_limit": _config.flagged.default_limit,
            "list_max_limit": _config.flagged.max_limit,
        },
        # B.1: Trust-hint allowlist (module defaults when config=[]).
        "unsubscribe_allowed_domains": effective_unsubscribe_domains(_config),
        # B.1: Hard-block and review domain lists.
        "unsubscribe_denied_domains": list(_config.unsubscribe_denied_domains),
        "unsubscribe_review_domains": list(_config.unsubscribe_review_domains),
        # B.4: Legacy trust-hint allowlist (module defaults when config=[]).
        "mailto_allowed_domains": effective_mailto_domains(_config),
        # B.4: Hard-block list for mailto targets.
        "mailto_denied_domains": list(_config.mailto_denied_domains),
        "protected_domains": list(_config.protected_domains),
        "egress": {
            "follow_redirects": _config.egress.follow_redirects,
            "max_redirects": _config.egress.max_redirects,
            "prefer_mailto": _config.egress.prefer_mailto,
            "http_timeout_seconds": _config.egress.http_timeout_seconds,
            "smtp_timeout_seconds": _config.egress.smtp_timeout_seconds,
        },
        # ADR-016: body-link unsubscribe discovery/probing switches.
        "allow_body_link_unsubscribe": _config.allow_body_link_unsubscribe,
        "probe_excerpt_bytes": _config.probe_excerpt_bytes,
        "probe_max_capture_bytes": _config.probe_max_capture_bytes,
    }


def _parse_from_header_local(raw_from: str) -> tuple:
    """Extract (display_name, email_address) from a From header string.

    Thin local shim so mcp_server.py doesn't import parse_from_header
    from headers.py (avoiding a circular dependency risk).  Uses the
    same email.utils.parseaddr path.

    Args:
        raw_from: Decoded From header string.

    Returns:
        Tuple of (display_name, normalised_lowercase_email).
    """
    import email.utils as _eu  # pylint: disable=import-outside-toplevel
    from icloud_helper.headers import decode_header_value  # pylint: disable=import-outside-toplevel
    decoded = decode_header_value(raw_from)
    name, addr = _eu.parseaddr(decoded)
    return name.strip(), addr.strip().lower()


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    mcp.run()
