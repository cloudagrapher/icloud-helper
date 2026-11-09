"""Config and policy loader for mail-cleaner.

Loads global settings from config.toml and per-sender policy from
policy.toml. Uses tomli for TOML parsing (Python 3.9 stdlib has no
tomllib).

FAIL-CLOSED contract
--------------------
- A missing, malformed, or empty policy.toml yields zero actionable
  senders. The caller must treat an empty allowlist as "nothing to act
  on" — never as "act on everything".
- Validation errors are logged at ERROR level; no exception propagates
  to the caller.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

import tomli

log = logging.getLogger(__name__)

# ADR-016: Hard ceiling on probe_max_capture_bytes, regardless of what an
# operator configures in config.toml. Without this, a misconfigured (or
# malicious) config value could make probe_unsubscribe_link read an
# arbitrarily large response body into memory. Mirrors the backstop already
# applied at the unsubscribe.py response.read() call site
# (_CAPTURE_HARD_CAP_BYTES) so the clamp holds even if this loader is
# bypassed by a future caller.
_PROBE_MAX_CAPTURE_BYTES_CEILING = 4 * 1024 * 1024  # 4 MiB


@dataclass
class RateLimitConfig:
    """Rate-limiting settings."""

    max_unsubscribes_per_run: int = 5
    request_sleep_seconds: float = 2.0


@dataclass
class FlaggedConfig:
    """Settings for the flagged-message retrieval feature."""

    max_attachment_bytes: int = 10 * 1024 * 1024  # 10 MiB
    default_limit: int = 25
    max_limit: int = 100
    max_body_bytes: int = 262144  # 256 KiB per-message body truncation cap


@dataclass
class AttachmentsConfig:
    """Settings for the attachment save and extract features (T2.5)."""

    downloads_dir: str = (
        "/Users/stefanbekker/Claude/icloud-helper-attachments"
    )


@dataclass
class ReadConfig:
    """Settings for the generalised read surface (list_messages etc.)."""

    folders: List[str] = field(
        default_factory=lambda: ["INBOX", "Junk", "Archive"]
    )
    max_snippet_bytes: int = 8192
    # T2.6 (fork F): default snippet for view="snippet".  Hard ceiling is
    # max_snippet_bytes (8192).
    default_snippet_bytes: int = 1500


@dataclass
class ActionsConfig:
    """Settings for the confirmed-action batch tools."""

    archive_folder: str = "Archive"
    trash_folder: str = "Deleted Messages"
    max_moves_per_run: int = 50
    max_trashes_per_run: int = 50


@dataclass
class EgressConfig:
    """Egress policy settings for the unsubscribe engine (B.6)."""

    follow_redirects: bool = True
    max_redirects: int = 3
    prefer_mailto: bool = True
    http_timeout_seconds: int = 30
    smtp_timeout_seconds: int = 30


@dataclass
class GlobalConfig:  # pylint: disable=too-many-instance-attributes
    """Global mail-cleaner settings loaded from config.toml."""

    folders: List[str] = field(default_factory=lambda: ["INBOX"])
    dry_run: bool = True
    allow_delete: bool = False
    rate_limits: RateLimitConfig = field(default_factory=RateLimitConfig)
    disposition: str = "move_to_unsubscribed"
    protected_domains: List[str] = field(default_factory=list)
    # M1: discord_webhook_url removed from config to prevent secrets ending
    # up in the world-readable config.toml.  Read from secrets/discord_webhook_url
    # via read_secret() instead (see icloud_helper/notify.py).
    # H4: MCP server policy-write guard.  When False, approve_sender refuses.
    allow_mcp_policy_writes: bool = False
    # B.1/B.4: Trust-hint allowlist for one-click POST targets.
    # An empty list means fall back to the module-level defaults in
    # icloud_helper.unsubscribe.  No longer a primary egress gate — the IP
    # denylist is.  Hosts on this list skip pending_review.
    unsubscribe_allowed_domains: List[str] = field(default_factory=list)
    # B.1: Hard-block list of named domains for one-click targets.
    unsubscribe_denied_domains: List[str] = field(default_factory=list)
    # B.1: Domains that produce a pending_review deferred result (not a gate).
    unsubscribe_review_domains: List[str] = field(default_factory=list)
    # T1.3 (fork C): Legacy trust-hint allowlist for mailto targets.
    # No longer a gate — the IP denylist + mailto_denied_domains are.
    mailto_allowed_domains: List[str] = field(default_factory=list)
    # B.4: Hard-block list of named domains for mailto targets.
    mailto_denied_domains: List[str] = field(default_factory=list)
    flagged: FlaggedConfig = field(default_factory=FlaggedConfig)
    # F6: Gate for the confirmed-action MCP tools.  Default false (safe).
    allow_confirmed_actions: bool = False
    read: ReadConfig = field(default_factory=ReadConfig)
    actions: ActionsConfig = field(default_factory=ActionsConfig)
    attachments: AttachmentsConfig = field(default_factory=AttachmentsConfig)
    # B.6: Egress policy (redirect follow, timeouts, prefer_mailto).
    egress: EgressConfig = field(default_factory=EgressConfig)
    # ADR-016: Master switch for body-link unsubscribe discovery/probing.
    # When False, find_unsubscribe_links still surfaces candidates (read-only,
    # no network I/O) but probe_unsubscribe_link refuses/simulates instead
    # of issuing a GET.
    allow_body_link_unsubscribe: bool = False
    # ADR-016: Max bytes of a probed landing page's visible text surfaced
    # back to the caller (page_text_excerpt).
    probe_excerpt_bytes: int = 4096
    # ADR-016: Max bytes of the raw HTML response body read from a probed
    # landing page (bounds memory and caps what classify_landing_page sees).
    # Hard-clamped to _PROBE_MAX_CAPTURE_BYTES_CEILING (4 MiB) at load time
    # regardless of what config.toml requests.
    probe_max_capture_bytes: int = 524288


@dataclass
class SenderPolicy:
    """Policy for a single sender."""

    action: str  # "unsubscribe" | "keep"
    disposition: Optional[str] = None  # overrides global if set


def load_config(config_path: Path) -> GlobalConfig:
    """Load and validate global config from config.toml.

    Falls back to safe defaults if the file is missing or malformed.
    Missing file is a WARNING; malformed TOML is an ERROR.

    Args:
        config_path: Path to config.toml.

    Returns:
        GlobalConfig instance (defaults if file absent or invalid).
    """
    if not config_path.exists():
        log.warning(
            "config.toml not found at %s, using defaults", config_path
        )
        return GlobalConfig()
    try:
        data = tomli.loads(config_path.read_text(encoding="utf-8"))
    except tomli.TOMLDecodeError as exc:
        log.error("Malformed config.toml: %s — using defaults", exc)
        return GlobalConfig()

    rl_data = data.get("rate_limits", {})
    rate_limits = RateLimitConfig(
        max_unsubscribes_per_run=int(
            rl_data.get("max_unsubscribes_per_run", 5)
        ),
        request_sleep_seconds=float(
            rl_data.get("request_sleep_seconds", 2.0)
        ),
    )
    fl_data = data.get("flagged", {})
    flagged_cfg = FlaggedConfig(
        max_attachment_bytes=int(
            fl_data.get("max_attachment_bytes", 10 * 1024 * 1024)
        ),
        default_limit=int(fl_data.get("default_limit", 25)),
        max_limit=int(fl_data.get("max_limit", 100)),
        max_body_bytes=int(fl_data.get("max_body_bytes", 262144)),
    )
    rd_data = data.get("read", {})
    read_cfg = ReadConfig(
        folders=list(
            rd_data.get("folders", ["INBOX", "Junk", "Archive"])
        ),
        max_snippet_bytes=int(rd_data.get("max_snippet_bytes", 8192)),
        default_snippet_bytes=int(rd_data.get("default_snippet_bytes", 1500)),
    )
    att_data = data.get("attachments", {})
    attachments_cfg = AttachmentsConfig(
        downloads_dir=str(
            att_data.get(
                "downloads_dir",
                "/Users/stefanbekker/Claude/icloud-helper-attachments",
            )
        ),
    )
    ac_data = data.get("actions", {})
    actions_cfg = ActionsConfig(
        archive_folder=str(ac_data.get("archive_folder", "Archive")),
        trash_folder=str(
            ac_data.get("trash_folder", "Deleted Messages")
        ),
        max_moves_per_run=int(ac_data.get("max_moves_per_run", 50)),
        max_trashes_per_run=int(ac_data.get("max_trashes_per_run", 50)),
    )
    eg_data = data.get("egress", {})
    egress_cfg = EgressConfig(
        follow_redirects=bool(eg_data.get("follow_redirects", True)),
        max_redirects=int(eg_data.get("max_redirects", 3)),
        prefer_mailto=bool(eg_data.get("prefer_mailto", True)),
        http_timeout_seconds=int(eg_data.get("http_timeout_seconds", 30)),
        smtp_timeout_seconds=int(eg_data.get("smtp_timeout_seconds", 30)),
    )
    return GlobalConfig(
        folders=list(data.get("folders", ["INBOX"])),
        dry_run=bool(data.get("dry_run", True)),
        allow_delete=bool(data.get("allow_delete", False)),
        rate_limits=rate_limits,
        disposition=str(data.get("disposition", "move_to_unsubscribed")),
        protected_domains=[
            d.lower() for d in data.get("protected_domains", [])
        ],
        allow_mcp_policy_writes=bool(
            data.get("allow_mcp_policy_writes", False)
        ),
        unsubscribe_allowed_domains=[
            d.lower()
            for d in data.get("unsubscribe_allowed_domains", [])
        ],
        unsubscribe_denied_domains=[
            d.lower()
            for d in data.get("unsubscribe_denied_domains", [])
        ],
        unsubscribe_review_domains=[
            d.lower()
            for d in data.get("unsubscribe_review_domains", [])
        ],
        mailto_allowed_domains=[
            d.lower()
            for d in data.get("mailto_allowed_domains", [])
        ],
        mailto_denied_domains=[
            d.lower()
            for d in data.get("mailto_denied_domains", [])
        ],
        flagged=flagged_cfg,
        allow_confirmed_actions=bool(
            data.get("allow_confirmed_actions", False)
        ),
        read=read_cfg,
        actions=actions_cfg,
        attachments=attachments_cfg,
        egress=egress_cfg,
        allow_body_link_unsubscribe=bool(
            data.get("allow_body_link_unsubscribe", False)
        ),
        probe_excerpt_bytes=int(data.get("probe_excerpt_bytes", 4096)),
        probe_max_capture_bytes=min(
            max(int(data.get("probe_max_capture_bytes", 524288)), 0),
            _PROBE_MAX_CAPTURE_BYTES_CEILING,
        ),
    )


def load_policy(policy_path: Path) -> Dict[str, SenderPolicy]:
    """Load and validate per-sender policy from policy.toml.

    FAIL-CLOSED: any parse or validation error yields an empty dict with
    an ERROR log. A missing file is acceptable (empty policy).

    Args:
        policy_path: Path to policy.toml.

    Returns:
        Dict mapping lowercase sender email -> SenderPolicy.
        Only senders with action="unsubscribe" are actionable.
    """
    if not policy_path.exists():
        log.info(
            "policy.toml not found at %s — no actionable senders",
            policy_path,
        )
        return {}
    try:
        data = tomli.loads(policy_path.read_text(encoding="utf-8"))
    except tomli.TOMLDecodeError as exc:
        log.error(
            "Malformed policy.toml: %s — treating as zero actionable senders",
            exc,
        )
        return {}

    if not isinstance(data, dict):
        log.error(
            "policy.toml root must be a TOML table, got %s — "
            "treating as zero actionable senders",
            type(data).__name__,
        )
        return {}

    result: Dict[str, SenderPolicy] = {}
    valid_actions = {"unsubscribe", "keep"}

    for sender_key, entry in data.items():
        if not isinstance(entry, dict):
            log.error(
                "Policy entry for %r is not a table — skipping", sender_key
            )
            continue
        action = entry.get("action", "")
        if action not in valid_actions:
            log.error(
                "Policy entry for %r has invalid action %r (must be "
                "'unsubscribe' or 'keep') — skipping",
                sender_key,
                action,
            )
            continue
        disposition = entry.get("disposition")
        if disposition is not None and not isinstance(disposition, str):
            log.error(
                "Policy entry for %r has non-string disposition — skipping",
                sender_key,
            )
            continue
        result[sender_key.lower()] = SenderPolicy(
            action=action,
            disposition=disposition,
        )

    log.info(
        "Loaded policy: %d entries, %d actionable",
        len(result),
        sum(1 for p in result.values() if p.action == "unsubscribe"),
    )
    return result


def get_actionable_senders(
    policy: Dict[str, SenderPolicy],
    protected_domains: List[str],
) -> Dict[str, SenderPolicy]:
    """Filter policy to only senders that should be acted on.

    A sender is actionable if:
    - action == "unsubscribe"
    - their domain is NOT in protected_domains

    Args:
        policy: Full policy dict from load_policy().
        protected_domains: Lowercase domain list from GlobalConfig.

    Returns:
        Filtered dict of actionable senders only.
    """
    result: Dict[str, SenderPolicy] = {}
    for sender, sp in policy.items():
        if sp.action != "unsubscribe":
            continue
        domain = sender.split("@", 1)[-1] if "@" in sender else ""
        if domain in protected_domains:
            log.warning(
                "Sender %r is in protected_domains — skipping", sender
            )
            continue
        result[sender] = sp
    return result
