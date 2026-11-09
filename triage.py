"""iCloud IMAP read-only triage tool.

Connects to an IMAP server using SSL, fetches message headers without
marking messages as read (BODY.PEEK[HEADER]), and produces a categorized
report of bulk mail senders alongside a structured JSON output for
downstream automation.

STRICT READ-ONLY GUARANTEES
----------------------------
- Every folder is opened with SELECT readonly=True so the server treats
  the session as read-only; the IMAP Seen flag is never set.
- Only BODY.PEEK[HEADER] fetches are issued; PEEK prevents the Seen
  flag from being set even on servers that ignore the readonly flag.
- No STORE, COPY, EXPUNGE, MOVE, or DELETE commands appear anywhere in
  this module.

BULK-MAIL HEURISTIC (for human review, not automated action)
-------------------------------------------------------------
A message is considered "bulk" when it carries at least one of:
  - List-Unsubscribe header
  - List-Id header
  - Precedence header containing the word "bulk"

Within bulk messages the classification is:

  newsletter
    Must satisfy ALL of:
      1. Has a List-Unsubscribe header.
      2. Has List-Id OR Precedence:bulk.
      3. The sender domain does not look throwaway -- the domain label
         must be at least 4 characters and must not look like a random
         alphanumeric string (heuristic: >= 60% alphabetic characters in
         the domain SLD).
    Rationale: legitimate ESPs (Mailchimp, Substack, etc.) always
    include RFC 2369 headers and use recognisable brand domains.

  spam
    Any of:
      - Bulk signals present but List-Unsubscribe is absent.
      - The unsubscribe URL/mailto looks malformed (cannot be parsed as a
        valid http/https URL or valid mailto: link).
      - The sender local-part looks auto-generated: purely alphanumeric,
        8+ characters, with no vowels, or matching a UUID-like pattern.
    Rationale: spam often mimics newsletter headers partially but fails
    on RFC conformance details.

  unknown
    Everything else that is bulk but does not clearly fit newsletter or
    spam. Requires human review.
"""

from __future__ import annotations

import argparse
import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List

from icloud_helper.headers import (
    SenderRecord,
    HEADERS_TO_FETCH,
    decode_header_value,
    parse_from_header,
    is_bulk,
    triage_messages,
    classify_sender,
)
from icloud_helper.secrets import read_secret
from icloud_helper.imap_client import (
    connect_and_login,
    select_folder_readonly,
    fetch_all_message_ids,
    fetch_headers_batch,
)

# Suppress F401 for names imported for re-export / historical API surface.
__all__ = [
    "SenderRecord",
    "HEADERS_TO_FETCH",
    "decode_header_value",
    "parse_from_header",
    "is_bulk",
    "triage_messages",
    "classify_sender",
    "read_secret",
    "connect_and_login",
    "select_folder_readonly",
    "fetch_all_message_ids",
    "fetch_headers_batch",
]

# ---------------------------------------------------------------------------
# Logging setup
# ---------------------------------------------------------------------------

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
log = logging.getLogger("triage")


# ---------------------------------------------------------------------------
# Report generation
# ---------------------------------------------------------------------------

def _format_spam_section(
    sep: str,
    spam_senders: List[SenderRecord],
) -> List[str]:
    """Build the spam sender section lines for the text report.

    Args:
        sep: Separator string for section headers.
        spam_senders: List of SenderRecord instances classified as spam.

    Returns:
        List of formatted report lines for the spam section.
    """
    lines: List[str] = []
    if spam_senders:
        lines.append("")
        lines.append(sep)
        lines.append("  LIKELY SPAM SENDERS")
        lines.append(sep)
        spam_sorted = sorted(
            spam_senders, key=lambda r: r.message_count, reverse=True
        )
        for rec in spam_sorted:
            name_suffix = (
                f"  ({rec.display_name[:40]})" if rec.display_name else ""
            )
            lines.append(
                f"  [{rec.message_count:>3} msg]  {rec.email_address}"
                + name_suffix
            )
    else:
        lines.append("")
        lines.append("  No senders flagged as likely spam.")
    return lines


def build_report(
    folder: str,
    total_messages: int,
    senders: Dict[str, SenderRecord],
    top_n: int = 20,
) -> str:
    """Build the human-readable text report.

    Args:
        folder: Name of the IMAP folder triaged.
        total_messages: Total message count in the folder.
        senders: Per-sender SenderRecord dict from triage_messages().
        top_n: Number of top senders to list by message count.

    Returns:
        Formatted multi-line report string.
    """
    bulk_count = sum(r.message_count for r in senders.values())
    personal_count = total_messages - bulk_count
    method_counts: Dict[str, int] = {
        "one-click": 0, "mailto": 0, "http-only": 0, "none": 0
    }
    for rec in senders.values():
        method_counts[rec.unsubscribe_method] = (
            method_counts.get(rec.unsubscribe_method, 0) + 1
        )
    spam_senders = [r for r in senders.values() if r.classification == "spam"]
    sorted_senders = sorted(
        senders.values(), key=lambda r: r.message_count, reverse=True
    )
    sep = "-" * 70
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    lines: List[str] = [
        sep,
        f"  ICLOUD IMAP TRIAGE REPORT  --  Folder: {folder}",
        sep,
        f"  Generated at        : {ts}",
        f"  Total messages      : {total_messages}",
        f"  Bulk messages       : {bulk_count}",
        f"  Personal/other      : {personal_count}",
        f"  Unique bulk senders : {len(senders)}",
        "",
        "  UNSUBSCRIBE METHOD BREAKDOWN (unique senders)",
        f"    one-click : {method_counts.get('one-click', 0)}",
        f"    mailto    : {method_counts.get('mailto', 0)}",
        f"    http-only : {method_counts.get('http-only', 0)}",
        f"    none      : {method_counts.get('none', 0)}",
        "",
        sep,
        f"  TOP {top_n} BULK SENDERS BY MESSAGE COUNT",
        sep,
        f"  {'COUNT':>5}  {'METHOD':>10}  {'CLASS':>12}  ADDRESS / NAME",
        f"  {'-----':>5}  {'----------':>10}  {'------------':>12}  ---",
    ]
    for rec in sorted_senders[:top_n]:
        name_part = repr(rec.display_name[:28]) if rec.display_name else ""
        lines.append(
            f"  {rec.message_count:>5}  {rec.unsubscribe_method:>10}  "
            f"{rec.classification:>12}  {rec.email_address}  {name_part}"
        )
    lines.extend(_format_spam_section(sep, spam_senders))
    lines.append(sep)
    return "\n".join(lines)


def build_json_output(
    folder: str,
    total_messages: int,
    senders: Dict[str, SenderRecord],
) -> Dict:
    """Build the structured JSON report dict.

    Args:
        folder: IMAP folder name.
        total_messages: Total message count in the folder.
        senders: Per-sender SenderRecord dict.

    Returns:
        Dict ready for json.dumps().
    """
    bulk_count = sum(r.message_count for r in senders.values())
    method_counts: Dict[str, int] = {
        "one-click": 0, "mailto": 0, "http-only": 0, "none": 0
    }
    for rec in senders.values():
        key = rec.unsubscribe_method
        method_counts[key] = method_counts.get(key, 0) + 1
    sorted_senders = sorted(
        senders.values(), key=lambda r: r.message_count, reverse=True
    )
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    return {
        "generated_at": ts,
        "folder": folder,
        "total_messages": total_messages,
        "bulk_count": bulk_count,
        "personal_count": total_messages - bulk_count,
        "unsubscribe_method_counts": method_counts,
        "senders": [r.to_dict() for r in sorted_senders],
    }


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def parse_args() -> argparse.Namespace:
    """Parse command-line arguments.

    Returns:
        Parsed argument namespace.
    """
    parser = argparse.ArgumentParser(
        description="Read-only iCloud IMAP triage tool.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "--host", default="imap.mail.me.com", help="IMAP hostname"
    )
    parser.add_argument("--port", type=int, default=993, help="IMAP port")
    parser.add_argument(
        "--folder", default="INBOX", help="Mailbox folder to analyse"
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=0,
        help="Max messages to process (0 = all)",
    )
    parser.add_argument(
        "--output",
        default=str(
            Path(__file__).resolve().parent / "reports" / "triage-latest.json"
        ),
        help="Path to write JSON report",
    )
    return parser.parse_args()


def main() -> None:
    """Main entry point for the iCloud IMAP triage tool."""
    args = parse_args()

    # Resolve secrets relative to this file so the path survives directory
    # renames (was a hardcoded absolute path to the old project location).
    secrets_dir = Path(__file__).resolve().parent / "secrets"
    email_file = str(secrets_dir / "icloud_email")
    password_file = str(secrets_dir / "icloud_app_password")

    username = read_secret(email_file)
    password = read_secret(password_file)

    imap = connect_and_login(args.host, args.port, username, password)
    try:
        total_messages = select_folder_readonly(imap, args.folder)
        msg_ids = fetch_all_message_ids(imap)

        if args.limit > 0:
            msg_ids = msg_ids[: args.limit]
            log.info("Limiting to %d messages per --limit flag", args.limit)

        all_headers = fetch_headers_batch(imap, msg_ids)
    finally:
        try:
            imap.logout()
        except Exception:  # pylint: disable=broad-except
            pass

    senders = triage_messages(all_headers)
    report_text = build_report(args.folder, total_messages, senders)
    print(report_text)

    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    json_data = build_json_output(args.folder, total_messages, senders)
    output_path.write_text(
        json.dumps(json_data, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    log.info("JSON report written to %s", output_path)


if __name__ == "__main__":
    main()
