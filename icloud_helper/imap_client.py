"""IMAP connection and header-fetch utilities for mail-cleaner.

Provides SSL connection management, folder selection, and batched
header fetching. All fetches use BODY.PEEK[HEADER] to avoid setting
the Seen flag.
"""

from __future__ import annotations

import email
import email.header
import imaplib
import logging
import ssl
import sys
from typing import Dict, List

log = logging.getLogger(__name__)

# Maximum seconds to wait for any single IMAP socket operation.  imaplib
# passes this directly to socket.create_connection() (Python 3.9+).  A 30s
# bound converts the previously unbounded 4-minute hang (TCP stall during
# iCloud throttling) into a fast, catchable socket.timeout / OSError.
_IMAP_TIMEOUT_SECONDS: int = 30


def connect_and_login(
    host: str, port: int, username: str, password: str
) -> imaplib.IMAP4_SSL:
    """Open an SSL connection to the IMAP server and log in.

    The SSL context is created with ``ssl.create_default_context()`` which
    sets ``check_hostname=True`` and ``verify_mode=CERT_REQUIRED``.  This
    prevents a MITM attacker from presenting a forged certificate and
    harvesting the iCloud app password (CVE class: credential interception
    via untrusted certificate).

    Args:
        host: IMAP server hostname.
        port: IMAP server port (typically 993).
        username: IMAP login username.
        password: IMAP login password.

    Returns:
        Authenticated IMAP4_SSL connection.
    """
    ssl_ctx = ssl.create_default_context()
    # Confirm the context has the expected security settings before use.
    # These are guaranteed by create_default_context() but we assert
    # defensively so a future Python change or monkey-patch is caught early.
    assert ssl_ctx.check_hostname, (
        "SSL context must have check_hostname=True"
    )
    assert ssl_ctx.verify_mode == ssl.CERT_REQUIRED, (
        "SSL context must have verify_mode=CERT_REQUIRED"
    )
    log.info("Connecting to %s:%d (TLS, cert verification enabled)", host, port)
    try:
        imap = imaplib.IMAP4_SSL(
            host, port, ssl_context=ssl_ctx, timeout=_IMAP_TIMEOUT_SECONDS
        )
    except OSError as exc:
        log.error("Connection failed: %s", exc)
        sys.exit(1)
    log.info("Logging in as %s", username)
    try:
        imap.login(username, password)
    except imaplib.IMAP4.error as exc:
        log.error("Login failed (check credentials): %s", exc)
        imap.logout()
        sys.exit(1)
    return imap


def select_folder_readonly(imap: imaplib.IMAP4_SSL, folder: str) -> int:
    """Select a mailbox folder in read-only mode.

    Args:
        imap: Authenticated IMAP4_SSL connection.
        folder: Mailbox folder name to select.

    Returns:
        Total number of messages in the folder.
    """
    status, data = imap.select(folder, readonly=True)
    if status != "OK":
        log.error("Failed to select folder %r: %s", folder, data)
        imap.logout()
        sys.exit(1)
    total = int(data[0]) if data and data[0] else 0
    log.info("Folder %r selected (read-only), %d messages", folder, total)
    return total


def uid_search(imap: imaplib.IMAP4_SSL, criterion: str) -> List[int]:
    """Run ``UID SEARCH <criterion>`` and return sorted integer UIDs.

    Read-only (SEARCH never mutates the mailbox). Shared by
    ``fetch_all_message_ids`` ("ALL") and the flagged-message retriever
    ("FLAGGED") so all SEARCH responses are parsed identically.

    Args:
        imap: Authenticated IMAP connection with a folder already selected.
        criterion: IMAP SEARCH criterion, e.g. "ALL" or "FLAGGED".

    Returns:
        Sorted ascending list of UID integers; empty on error or no match.
    """
    try:
        status, data = imap.uid(  # type: ignore[attr-defined]
            "SEARCH", None, criterion
        )
    except imaplib.IMAP4.error as exc:
        log.warning("UID SEARCH %s error: %s", criterion, exc)
        return []

    if status != "OK" or not data or not data[0]:
        return []

    raw = data[0]
    if isinstance(raw, bytes):
        raw = raw.decode("ascii", errors="ignore")
    return sorted(int(p) for p in str(raw).split() if p.isdigit())


def fetch_all_message_ids(imap: imaplib.IMAP4_SSL) -> List[int]:
    """Return all UIDs in the selected folder via ``UID SEARCH ALL``.

    Read-only. Used by triage so it classifies the same UID set the actor does.

    Args:
        imap: Authenticated IMAP connection with a folder already selected.

    Returns:
        Sorted list of integer UIDs; empty on error or empty folder.
    """
    return uid_search(imap, "ALL")


def parse_message_headers(  # pylint: disable=too-many-locals,too-many-branches,too-many-nested-blocks
    raw_headers: bytes,
) -> Dict[str, str]:
    """Parse raw RFC822 header bytes into a lowercase-keyed dict.

    Header names are normalised to lowercase and multi-valued headers joined
    with " | " so all consumers (``is_bulk``, ``triage_messages``,
    ``check_sender_auth``) use consistent keys. For ``Authentication-Results``
    the individual per-verifier values are also preserved NUL-delimited under
    ``authentication-results-list`` (NUL cannot appear in a decoded MIME header
    value, so it is a safe delimiter) so sender auth can inspect each header
    independently without trusting a joined blob. Shared by ``fetch_headers_batch``
    and the actor's UID fetch so both classify messages identically.

    Args:
        raw_headers: Raw header bytes from a BODY.PEEK[HEADER] fetch.

    Returns:
        Dict of lowercase header name -> decoded value.
    """
    msg = email.message_from_bytes(raw_headers)
    headers: Dict[str, str] = {}
    # Use get_all() so multi-valued headers (iCloud delivers a separate
    # Authentication-Results per verifier) are all captured. Deduplicate
    # header names but collect all values.
    seen_names: List[str] = list(dict.fromkeys(msg.keys()))
    for header_name in seen_names:
        all_raw_vals = msg.get_all(header_name) or []
        combined_parts: List[str] = []
        for raw_val in all_raw_vals:
            if raw_val is None:
                continue
            try:
                decoded_parts = email.header.decode_header(raw_val)
                parts: List[str] = []
                for part_bytes, charset in decoded_parts:
                    if isinstance(part_bytes, bytes):
                        enc = charset or "utf-8"
                        try:
                            parts.append(part_bytes.decode(enc, errors="replace"))
                        except (LookupError, UnicodeDecodeError):
                            parts.append(
                                part_bytes.decode("utf-8", errors="replace")
                            )
                    else:
                        parts.append(str(part_bytes))
                combined_parts.append(" ".join(parts))
            except Exception as exc:  # pylint: disable=broad-except
                log.debug("Header decode error for %s: %s", header_name, exc)
                combined_parts.append(str(raw_val))
        key_lower = header_name.lower()
        headers[key_lower] = " | ".join(combined_parts)
        if key_lower == "authentication-results" and len(combined_parts) > 1:
            headers["authentication-results-list"] = "\x00".join(combined_parts)
    return headers


def fetch_headers_batch(
    imap: imaplib.IMAP4_SSL, msg_ids: List[int]
) -> List[Dict[str, str]]:
    """Fetch and parse headers for a list of UIDs (read-only).

    Issues one batched ``UID FETCH (BODY.PEEK[HEADER])`` so the Seen flag is
    never set. Header names are normalised to lowercase and multi-valued
    headers joined with " | " so all consumers (``is_bulk``,
    ``triage_messages``) use consistent keys. For ``Authentication-Results``
    the individual per-verifier values are also preserved NUL-delimited under
    ``authentication-results-list`` so sender auth can inspect each header
    independently. Parsing mirrors the actor's ``_uid_fetch_headers``; the
    only difference is the return shape (a list, not a UID->dict map) to match
    ``headers.triage_messages``.

    Args:
        imap: Authenticated IMAP connection with a folder already selected.
        msg_ids: Integer UIDs to fetch.

    Returns:
        List of per-message header dicts (lowercase name -> value), in server
        order. Unparseable messages are omitted. Empty input -> empty list.
    """
    if not msg_ids:
        return []

    uid_str = ",".join(str(u) for u in msg_ids)
    try:
        status, data = imap.uid(  # type: ignore[attr-defined]
            "FETCH", uid_str, "(BODY.PEEK[HEADER])"
        )
    except imaplib.IMAP4.error as exc:
        log.error("IMAP UID FETCH error: %s", exc)
        return []

    if status != "OK" or not data:
        log.warning("UID FETCH returned status=%s", status)
        return []

    results: List[Dict[str, str]] = []
    for item in data:
        if not isinstance(item, tuple) or len(item) < 2:
            continue
        meta_bytes, raw_headers = item[0], item[1]
        if not isinstance(meta_bytes, bytes) or not isinstance(raw_headers, bytes):
            continue

        results.append(parse_message_headers(raw_headers))

    return results


def select_folder_readwrite(imap: imaplib.IMAP4_SSL, folder: str) -> int:
    """Select a mailbox folder in read-write mode.

    Mirror of select_folder_readonly with readonly=False.  Used by the
    confirmed-action tools (move_messages, trash_messages,
    unsubscribe_message) which need write access to execute IMAP MOVE.
    Callers must already have authenticated via connect_and_login.

    Args:
        imap: Authenticated IMAP4_SSL connection.
        folder: Mailbox folder name to select.

    Returns:
        Total number of messages in the folder.

    Raises:
        SystemExit: If the SELECT command fails (mirrors
            select_folder_readonly behaviour so callers need not handle
            the imap logout separately).
    """
    status, data = imap.select(folder, readonly=False)
    if status != "OK":
        log.error("Failed to select folder %r (rw): %s", folder, data)
        imap.logout()
        sys.exit(1)
    total = int(data[0]) if data and data[0] else 0
    log.info("Folder %r selected (read-write), %d messages", folder, total)
    return total
