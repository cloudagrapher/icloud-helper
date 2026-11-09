"""Batched new-sender notifications via Discord incoming webhook.

Security: the webhook URL is read from secrets/discord_webhook_url
(never from config.toml) and validated against the Discord hostname
allowlist before any HTTP request is made.

Queries the state DB for pending senders that have not yet been notified,
builds a formatted message body with policy.toml snippets, and POSTs to
the Discord webhook URL stored in config.toml.

Everything defaults to dry-run. The webhook URL is treated as a credential
and is never logged.

SECURITY NOTE (for reviewer): discord_webhook_url is currently stored in
config.toml (plain text, mode depending on file permissions). Ideally it
should live in secrets/ at mode 0600 and be read via read_secret(). This
is tracked as a known gap pending the secrets/ refactor.
"""
from __future__ import annotations

import json
import logging
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List

from icloud_helper.secrets import read_secret
from icloud_helper.state import StateStore

logger = logging.getLogger(__name__)

_DISCORD_MAX_CONTENT = 2000  # Discord message content limit in characters
_SECRETS_DIR = Path(__file__).parent.parent / "secrets"


# ---------------------------------------------------------------------------
# DB helpers
# ---------------------------------------------------------------------------


def _list_unnotified_pending(
    store: StateStore,
) -> List[Dict[str, object]]:
    """Fetch pending_senders rows where notified_at IS NULL.

    Args:
        store: Initialised StateStore instance.

    Returns:
        List of row dicts ordered by message_count descending.
        Empty list if none found or on DB error.
    """
    rows: List[Dict[str, object]] = []
    try:
        with store._connect() as conn:  # pylint: disable=protected-access
            cur = conn.execute(
                "SELECT sender, display_name, domain, unsub_method, "
                "       classification, message_count "
                "FROM   pending_senders "
                "WHERE  notified_at IS NULL "
                "ORDER  BY message_count DESC"
            )
            rows = [dict(row) for row in cur.fetchall()]
    except Exception as exc:  # pylint: disable=broad-except
        logger.error("Error querying pending_senders: %s", exc)
    return rows


def _mark_notified(store: StateStore, senders: List[str]) -> None:
    """Set notified_at to now for the given sender list.

    Args:
        store: Initialised StateStore instance.
        senders: Lowercase sender email addresses to stamp.
    """
    if not senders:
        return
    now_iso = datetime.now(timezone.utc).isoformat()
    try:
        with store._connect() as conn:  # pylint: disable=protected-access
            conn.executemany(
                "UPDATE pending_senders SET notified_at = ? WHERE sender = ?",
                [(now_iso, s) for s in senders],
            )
    except Exception as exc:  # pylint: disable=broad-except
        logger.error("Error updating notified_at: %s", exc)


# ---------------------------------------------------------------------------
# Message builder
# ---------------------------------------------------------------------------


def _build_message_body(
    rows: List[Dict[str, object]],
    overflow_count: int = 0,
) -> str:
    """Build the Discord notification body.

    Args:
        rows: Pending-sender rows to include in this message.
        overflow_count: Number of additional senders omitted due to length.

    Returns:
        Formatted plain-text message body (within Discord's 2000-char limit).
    """
    lines: List[str] = [
        "**New bulk senders need policy decisions:**",
        "",
    ]
    for row in rows:
        sender = str(row.get("sender", ""))
        display_name = str(row.get("display_name", ""))
        classification = str(row.get("classification", ""))
        unsub_method = str(row.get("unsub_method", ""))
        message_count = row.get("message_count", 0)

        lines.append(f"`{sender}`")
        if display_name:
            lines.append(f"  Name: {display_name}")
        lines.append(f"  Class: {classification}  Method: {unsub_method}  ({message_count} msgs)")
        lines.append("  Add to policy.toml:")
        lines.append(f'  `["{sender}"]`')
        lines.append('  `action = "unsubscribe"   # or "keep"`')
        lines.append("")

    if overflow_count > 0:
        lines.append(f"…and {overflow_count} more. Check pending_senders table.")

    return "\n".join(lines)


def _truncate_to_discord_limit(body: str) -> str:
    """Truncate body to Discord's 2000-character content limit.

    Args:
        body: Full message body.

    Returns:
        Body truncated to 2000 chars with a suffix if needed.
    """
    if len(body) <= _DISCORD_MAX_CONTENT:
        return body
    suffix = "\n…(truncated)"
    return body[: _DISCORD_MAX_CONTENT - len(suffix)] + suffix


# ---------------------------------------------------------------------------
# Main public function
# ---------------------------------------------------------------------------


def send_pending_notification(  # pylint: disable=too-many-return-statements
    store: StateStore,
    dry_run: bool,
) -> int:
    """Send a batched Discord notification for unnotified pending senders.

    Reads the Discord webhook URL from secrets/discord_webhook_url.
    If the file is absent or empty the function logs a WARNING and
    returns 0 without raising. In dry-run mode the message body is
    logged at INFO but no HTTP request is made.

    The webhook URL is never logged (treated as a credential).

    Args:
        store: Initialised StateStore instance.
        dry_run: When True, log only — do not POST to Discord.

    Returns:
        Count of senders included in the notification batch (0 if skipped).
    """
    webhook_path = _SECRETS_DIR / "discord_webhook_url"
    if not webhook_path.exists():
        logger.warning(
            "secrets/discord_webhook_url not found; Discord notification skipped"
        )
        return 0
    discord_webhook_url = read_secret(str(webhook_path))
    if not discord_webhook_url:
        logger.warning(
            "secrets/discord_webhook_url is empty; Discord notification skipped"
        )
        return 0

    # M1: validate webhook URL before use — must be HTTPS and target Discord.
    _parsed_wh = urllib.parse.urlparse(discord_webhook_url)
    _wh_host = (_parsed_wh.hostname or "").lower()
    _discord_hosts = ("discord.com", "discordapp.com")
    if _parsed_wh.scheme != "https" or not any(
        _wh_host == h or _wh_host.endswith("." + h)
        for h in _discord_hosts
    ):
        logger.error(
            "Discord webhook URL is not a valid Discord HTTPS endpoint "
            "(host=%s scheme=%s); notification skipped",
            _wh_host,
            _parsed_wh.scheme,
        )
        return 0

    rows = _list_unnotified_pending(store)
    if not rows:
        logger.debug("No unnotified pending senders; nothing to notify")
        return 0

    count = len(rows)
    body = _build_message_body(rows)
    body = _truncate_to_discord_limit(body)

    if dry_run:
        logger.info(
            "[DRY-RUN] Would POST Discord notification for %d sender(s). "
            "Body (webhook URL redacted):\n%s",
            count,
            body,
        )
        # Do not call _mark_notified in dry-run: a live run must still
        # see these senders as unnotified and deliver the real notification.
        return count

    payload = json.dumps({"content": body}).encode("utf-8")
    req = urllib.request.Request(
        discord_webhook_url,
        data=payload,
        method="POST",
        headers={"Content-Type": "application/json"},
    )

    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            status = resp.status
            if status not in (200, 204):
                logger.warning(
                    "Discord webhook returned unexpected status %d", status
                )
                return 0
    except urllib.error.HTTPError as exc:
        logger.warning(
            "Discord webhook HTTP error %d: %s", exc.code, exc.reason
        )
        return 0
    except urllib.error.URLError as exc:
        logger.warning("Discord webhook URL error: %s", exc.reason)
        return 0
    except OSError as exc:
        logger.warning("Discord webhook OS error: %s", exc)
        return 0

    logger.info(
        "Discord notification sent for %d sender(s)", count
    )
    _mark_notified(store, [str(r["sender"]) for r in rows])
    return count
