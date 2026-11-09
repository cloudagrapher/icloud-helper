"""Generalised read surface for icloud-helper.

Provides utilities to search, fetch, and annotate IMAP messages across
the allowed read folders (INBOX, Junk, Archive).  All operations here
are strictly read-only; no IMAP mutations are performed.

This module re-uses flagged.py's session helpers and MIME utilities so
the read surface shares the same tested primitives.  Do NOT add writes
to flagged.py — its read-only contract is a design invariant.

Compatible with Python 3.9 (.venv) and Python 3.13 (.venv-mcp).
"""

from __future__ import annotations

import imaplib
import logging
from email.message import Message
from typing import Dict

from icloud_helper.auth import extract_auth_signals
from icloud_helper.headers import (
    content_pattern_facts,
    decode_header_value,
    determine_unsubscribe_method,
    display_name_has_email,
    is_bulk,
    local_part_looks_like_email,
    parse_from_header,
)
from icloud_helper.imap_client import (
    parse_message_headers,
    uid_search,
)

log = logging.getLogger(__name__)

# Re-export uid_search so callers can import from here without touching
# imap_client directly.
__all__ = [
    "search_uids",
    "header_signals",
    "uid_search",
]


def search_uids(imap: imaplib.IMAP4_SSL, criterion: str) -> list:
    """Thin wrapper over uid_search for explicit criterion passing.

    Allows callers to pass ``"ALL"`` or ``"UNSEEN"`` without importing
    imap_client directly.  Read-only: UID SEARCH never mutates the
    mailbox.

    Args:
        imap: Authenticated IMAP connection with a folder already selected.
        criterion: IMAP SEARCH criterion, e.g. ``"ALL"`` or ``"UNSEEN"``.

    Returns:
        Sorted ascending list of UID integers; empty on error or no match.
    """
    return uid_search(imap, criterion)


def _spoof_facts(parsed_headers: Dict[str, str], auth: Dict) -> Dict:
    """Return spoof-indicator facts from From header and auth signals.

    Args:
        parsed_headers: Lowercase-keyed header dict from parse_message_headers.
        auth: Auth signals dict from extract_auth_signals.

    Returns:
        Dict with local_part_looks_like_email, from_domain_mismatch,
        display_name_has_email keys.
    """
    from_header_raw = parsed_headers.get("from", "")
    display_name, from_addr = parse_from_header(from_header_raw)

    auth_from_domain = auth.get("authenticated_from_domain")
    from_hdr_domain = auth.get("from_header_domain")
    if auth_from_domain and from_hdr_domain:
        from_domain_mismatch = from_hdr_domain != auth_from_domain
    else:
        from_domain_mismatch = False

    return {
        "local_part_looks_like_email": local_part_looks_like_email(from_addr),
        "from_domain_mismatch": from_domain_mismatch,
        "display_name_has_email": display_name_has_email(display_name),
    }


def header_signals(msg: Message, body_text: str = "") -> Dict:
    """Build a factual signal dict from an already-parsed MIME message.

    No extra IMAP round-trip is performed — all information comes from
    the ``Message`` object and the optional decoded ``body_text``.

    The deterministic code emits FACTS only.  It does NOT render a
    classification verdict for individual mail categories (spam /
    newsletter / transactional).  The single ``heuristic_classification``
    field carries only the structural label ``"bulk"`` or ``"not_bulk"``
    based on bulk-mail header presence.  The model (Cowork) reads the
    facts and body together to judge category.

    Signal keys
    -----------
    Structural (bulk detection):
    - ``list_unsubscribe_method``: ``"one-click"``, ``"mailto"``,
      ``"http-only"``, or ``"none"``.
    - ``has_list_id``: bool — ``List-Id`` header present.
    - ``precedence_bulk``: bool — ``Precedence: bulk`` header present.
    - ``is_bulk``: bool — any bulk signal fires.
    - ``heuristic_classification``: ``"bulk"`` or ``"not_bulk"`` only.
      No spam / newsletter / transactional verdict is emitted here.

    Authentication (``auth`` dict — see ``auth.extract_auth_signals``):
    - ``spf``: str — SPF verdict from trusted iCloud authserv.
    - ``dkim``: str — DKIM verdict from trusted iCloud authserv.
    - ``dmarc``: str — DMARC verdict from trusted iCloud authserv.
    - ``dmarc_aligned``: bool — dmarc=pass from trusted iCloud authserv.
    - ``authenticated_from_domain``: Optional[str] — header.from= on the
      DMARC-passing trusted AR header.
    - ``dkim_d_domain``: Optional[str] — DKIM signing domain.
    - ``envelope_from_domain``: Optional[str] — smtp.mailfrom= domain.
    - ``from_header_domain``: Optional[str] — domain parsed from From:.
    - ``from_alignment``: ``"aligned"``, ``"relaxed"``, ``"misaligned"``,
      or ``"unknown"``.  Only ``"aligned"`` is a strong signal; ``"relaxed"``
      uses a non-PSL last-two-labels heuristic (imprecise for ccSLD domains
      such as ``co.uk`` and ``com.au``) — see ``auth._last_two_labels``.
    - ``trusted_results_present``: bool — at least one trusted AR header.

    Spoof facts:
    - ``local_part_looks_like_email``: bool — local-part embeds a domain
      or known mail-brand token.
    - ``from_domain_mismatch``: bool — From-domain differs from
      ``authenticated_from_domain`` (populated by auth).
    - ``display_name_has_email``: bool — display name contains an @.

    Content-pattern facts (model-interpreted, NOT a verdict):
    - ``has_otp_pattern``: bool — OTP/verification-code language + digit.
    - ``has_receipt_pattern``: bool — receipt/order/invoice language.
    - ``currency_total_present``: bool — currency figure present.
    - ``marketing_cta_density``: float — CTAs per 1000 body chars.

    Args:
        msg: Parsed ``email.message.Message`` for a single IMAP message.
        body_text: Decoded plain-text body, already cleaned and decoded by
            the caller (e.g. via ``flagged.clean_body_text``).  Pass ``""``
            when the view is metadata-only; content-pattern facts then
            operate on the subject alone and density is 0.0 — no crash.

    Returns:
        Dict with all signal keys described above.
    """
    # Route through parse_message_headers so that multiple
    # Authentication-Results headers (dmarc / spf / dkim — one per verifier
    # in iCloud) are preserved in authentication-results-list (NUL-delimited)
    # rather than collapsed to the last value by a dict comprehension.
    # This is the regression fix for the AR-collapse bug.
    parsed_headers: Dict[str, str] = parse_message_headers(msg.as_bytes())

    unsub_method = determine_unsubscribe_method(
        parsed_headers.get("list-unsubscribe", ""),
        parsed_headers.get("list-unsubscribe-post", ""),
    )
    has_list_id = bool(parsed_headers.get("list-id", ""))
    precedence_bulk = "bulk" in parsed_headers.get("precedence", "").lower()
    bulk_flag = is_bulk(parsed_headers)

    # Authentication facts.
    auth = extract_auth_signals(parsed_headers)

    # Spoof facts (extracted via helper to stay within local-var limit).
    spoof = _spoof_facts(parsed_headers, auth)

    # Content-pattern facts (factual booleans/counts — NOT a verdict).
    content_facts = content_pattern_facts(
        decode_header_value(parsed_headers.get("subject", "")),
        body_text,
    )

    return {
        # Structural
        "list_unsubscribe_method": unsub_method,
        "has_list_id": has_list_id,
        "precedence_bulk": precedence_bulk,
        "is_bulk": bulk_flag,
        "heuristic_classification": "bulk" if bulk_flag else "not_bulk",
        # Authentication
        "auth": auth,
        # Spoof
        "local_part_looks_like_email": spoof["local_part_looks_like_email"],
        "from_domain_mismatch": spoof["from_domain_mismatch"],
        "display_name_has_email": spoof["display_name_has_email"],
        # Content-pattern facts
        "has_otp_pattern": content_facts["has_otp_pattern"],
        "has_receipt_pattern": content_facts["has_receipt_pattern"],
        "currency_total_present": content_facts["currency_total_present"],
        "marketing_cta_density": content_facts["marketing_cta_density"],
    }
