"""Header parsing, classification helpers, and triage logic for mail-cleaner.

Contains all IMAP header-level utilities: decoding RFC 2047 values,
parsing From headers, extracting List-Unsubscribe URLs, classifying
bulk senders, and running the full triage pass over a list of header
dicts.
"""

from __future__ import annotations

import email
import email.header
import email.utils
import re
from typing import Dict, List, Optional, Tuple


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

HEADERS_TO_FETCH = (
    "From",
    "Subject",
    "Date",
    "List-Unsubscribe",
    "List-Unsubscribe-Post",
    "List-Id",
    "Precedence",
    "Auto-Submitted",
)

THROWAWAY_DOMAIN_RE = re.compile(r"^[a-z0-9]{1,3}$", re.IGNORECASE)
RANDOM_LOCAL_RE = re.compile(r"^[a-z0-9]{8,}$", re.IGNORECASE)
UUID_RE = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
    re.IGNORECASE,
)

# ---------------------------------------------------------------------------
# Spoof-signal patterns
# ---------------------------------------------------------------------------

# Detects a domain-shaped substring in the local-part of an email address.
# Catches the "leanneallenrealestate.gmail.com@tafv5o.ff02.fdske.com" pattern
# where the local-part itself contains a domain name (has a dot and a TLD).
_DOMAIN_IN_LOCAL_RE = re.compile(
    r"\.(com|net|org|io|co|me|info|biz|edu|gov|app|dev|us|uk|ca)$",
    re.IGNORECASE,
)

# Known mail-brand tokens that are suspicious in a local-part because
# legitimate mail from those brands comes from the actual brand domain.
_MAIL_BRAND_RE = re.compile(
    r"\b(gmail|yahoo|hotmail|outlook|icloud|aol|protonmail|zoho)\b",
    re.IGNORECASE,
)

# ---------------------------------------------------------------------------
# Content-pattern regexes (factual signals, NOT a verdict)
# ---------------------------------------------------------------------------

# OTP / verification-code language patterns.
_OTP_PHRASE_RE = re.compile(
    r"one[\s\-]?time\s+(code|password)"
    r"|verification\s+code"
    r"|security\s+code"
    r"|your\s+code\s+is"
    r"|\bOTP\b"
    r"|\b2fa\b"
    r"|\bauthentication\s+code\b"
    r"|\bsign[\s\-]in\s+code\b",
    re.IGNORECASE,
)
_OTP_DIGIT_RE = re.compile(r"\b\d{4,8}\b")

# Receipt / order / itinerary language patterns.
_RECEIPT_RE = re.compile(
    r"\b(receipt|order|invoice|itinerary|reservation|confirmation"
    r"|claim\s+number|booking\s+ref|tracking\s+number|reference\s+number)\b",
    re.IGNORECASE,
)

# Currency total patterns.
_CURRENCY_RE = re.compile(
    r"[$€£]\s?\d[\d,]*\.\d{2}"
    r"|(?:total|amount|balance|charge|due)[^\n]{0,30}[$€£]\s?\d[\d,]*\.\d{2}",
    re.IGNORECASE,
)

# Marketing CTA tokens (count per 1000 chars gives density).
_CTA_RE = re.compile(
    r"shop\s+now"
    r"|buy\s+now"
    r"|save\s+\d+\s*%"
    r"|\d+\s*%\s+off"
    r"|limited\s+time"
    r"|view\s+in\s+browser"
    r"|unsubscribe",
    re.IGNORECASE,
)


# ---------------------------------------------------------------------------
# SenderRecord
# ---------------------------------------------------------------------------

class SenderRecord:  # pylint: disable=too-many-instance-attributes
    """Aggregated data for a single bulk sender (keyed on email address)."""

    __slots__ = (
        "email_address",
        "display_name",
        "domain",
        "message_count",
        "unsubscribe_method",
        "classification",
        "sample_unsubscribe_header",
        "sample_unsubscribe_post_header",
    )

    def __init__(self, email_address: str, display_name: str) -> None:
        self.email_address: str = email_address
        self.display_name: str = display_name
        self.domain: str = (
            email_address.split("@", 1)[-1] if "@" in email_address else ""
        )
        self.message_count: int = 0
        self.unsubscribe_method: str = "none"
        self.classification: str = "unknown"
        self.sample_unsubscribe_header: str = ""
        self.sample_unsubscribe_post_header: str = ""

    def to_dict(self) -> Dict:
        """Return a JSON-serialisable dictionary."""
        return {
            "email": self.email_address,
            "display_name": self.display_name,
            "domain": self.domain,
            "message_count": self.message_count,
            "unsubscribe_method": self.unsubscribe_method,
            "classification": self.classification,
            "sample_unsubscribe_header": self.sample_unsubscribe_header,
            "sample_unsubscribe_post_header": self.sample_unsubscribe_post_header,
        }

    def update_display_name(self, name: str) -> None:
        """Set display_name if the current value is empty.

        Args:
            name: Candidate display name string.
        """
        if not self.display_name and name:
            self.display_name = name


# ---------------------------------------------------------------------------
# Header parsing helpers
# ---------------------------------------------------------------------------

def decode_header_value(raw: Optional[str]) -> str:
    """Decode a potentially RFC 2047-encoded header value to a plain string.

    Args:
        raw: Raw header value string, possibly containing encoded words.

    Returns:
        A decoded Unicode string, or an empty string if raw is None.
    """
    if raw is None:
        return ""
    parts = email.header.decode_header(raw)
    decoded_parts: List[str] = []
    for fragment, charset in parts:
        if isinstance(fragment, bytes):
            try:
                decoded_parts.append(
                    fragment.decode(charset or "utf-8", errors="replace")
                )
            except (LookupError, UnicodeDecodeError):
                decoded_parts.append(
                    fragment.decode("latin-1", errors="replace")
                )
        else:
            decoded_parts.append(fragment)
    return "".join(decoded_parts).strip()


def parse_from_header(raw_from: str) -> Tuple[str, str]:
    """Extract display name and email address from a From header.

    Args:
        raw_from: Decoded From header string, e.g.
            'Alice <alice@example.com>' or 'alice@example.com'.

    Returns:
        Tuple of (display_name, email_address) both normalised to
        lowercase for the address part.
    """
    decoded = decode_header_value(raw_from)
    name, addr = email.utils.parseaddr(decoded)
    return name.strip(), addr.strip().lower()


def extract_urls_from_list_unsubscribe(
    header_value: str,
) -> Tuple[List[str], List[str]]:
    """Parse List-Unsubscribe header and extract http(s) and mailto URLs.

    The header value is a comma-separated list of angle-bracket-enclosed
    URIs, e.g.: <https://example.com/unsub>, <mailto:unsub@example.com>

    Args:
        header_value: Raw List-Unsubscribe header string.

    Returns:
        Tuple of (http_urls, mailto_urls).
    """
    http_urls: List[str] = []
    mailto_urls: List[str] = []
    for chunk in header_value.split(","):
        chunk = chunk.strip()
        match = re.search(r"<([^>]+)>", chunk)
        if not match:
            continue
        uri = match.group(1).strip()
        if uri.lower().startswith("https://") or uri.lower().startswith(
            "http://"
        ):
            http_urls.append(uri)
        elif uri.lower().startswith("mailto:"):
            mailto_urls.append(uri)
    return http_urls, mailto_urls


def determine_unsubscribe_method(
    list_unsub: str,
    list_unsub_post: str,
) -> str:
    """Determine the unsubscribe method from List-Unsubscribe headers.

    Args:
        list_unsub: Value of the List-Unsubscribe header.
        list_unsub_post: Value of the List-Unsubscribe-Post header.

    Returns:
        One of: 'one-click', 'mailto', 'http-only', 'none'.
    """
    if not list_unsub:
        return "none"
    http_urls, mailto_urls = extract_urls_from_list_unsubscribe(list_unsub)
    post_val = list_unsub_post.lower()
    has_one_click_post = "list-unsubscribe=one-click" in post_val
    has_https = any(u.lower().startswith("https://") for u in http_urls)
    if has_one_click_post and has_https:
        return "one-click"
    if mailto_urls:
        return "mailto"
    if http_urls:
        return "http-only"
    return "none"


# ---------------------------------------------------------------------------
# Classification helpers
# ---------------------------------------------------------------------------

def _domain_looks_throwaway(domain: str) -> bool:
    """Return True if the sender domain SLD looks like a throwaway label."""
    if not domain:
        return True
    parts = domain.rstrip(".").split(".")
    sld = parts[-2] if len(parts) >= 2 else parts[0]
    if len(sld) < 4:
        return True
    alpha_ratio = sum(1 for c in sld if c.isalpha()) / len(sld)
    return alpha_ratio < 0.6


def _local_part_looks_generated(local: str) -> bool:
    """Return True if the email local-part looks auto-generated."""
    if UUID_RE.search(local):
        return True
    if RANDOM_LOCAL_RE.match(local):
        vowels = set("aeiou")
        if not any(c in vowels for c in local.lower()):
            return True
    return False


def _unsubscribe_looks_malformed(list_unsub: str, method: str) -> bool:
    """Return True if the unsubscribe link appears malformed or garbage."""
    if method == "none":
        return False
    http_urls, mailto_urls = extract_urls_from_list_unsubscribe(list_unsub)
    for url in http_urls:
        if not re.match(r"https?://[a-zA-Z0-9.-]+/", url):
            return True
    for mailto in mailto_urls:
        addr = mailto[len("mailto:"):]
        addr = addr.split("?")[0]
        pattern = r"[^@]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"
        if "@" not in addr or not re.match(pattern, addr):
            return True
    return False


def classify_sender(
    record: SenderRecord,
    has_list_unsub: bool,
    has_list_id: bool,
    has_precedence_bulk: bool,
) -> str:
    """Classify a bulk sender as newsletter, spam, or unknown.

    Args:
        record: SenderRecord for this sender.
        has_list_unsub: True if any message had a List-Unsubscribe header.
        has_list_id: True if any message had a List-Id header.
        has_precedence_bulk: True if any message had Precedence: bulk.

    Returns:
        One of: 'newsletter', 'spam', 'unknown'.
    """
    local_part = (
        record.email_address.split("@")[0]
        if "@" in record.email_address
        else ""
    )
    if not has_list_unsub:
        return "spam"
    if _unsubscribe_looks_malformed(
        record.sample_unsubscribe_header, record.unsubscribe_method
    ):
        return "spam"
    if _local_part_looks_generated(local_part):
        return "spam"
    has_secondary = has_list_id or has_precedence_bulk
    if (
        has_list_unsub
        and has_secondary
        and not _domain_looks_throwaway(record.domain)
    ):
        return "newsletter"
    return "unknown"


# ---------------------------------------------------------------------------
# Spoof-signal helpers (read-only facts for the model)
# ---------------------------------------------------------------------------


def local_part_looks_like_email(addr: str) -> bool:
    """Return True when the local-part of *addr* looks like an embedded address.

    Targets the spoofing pattern where the entire local-part mimics a domain
    name (e.g. ``leanneallenrealestate.gmail.com@tafv5o.ff02.fdske.com``).
    The check fires when the local-part:
    - ends with a TLD-shaped suffix (``.com``, ``.net``, etc.), OR
    - contains a known mail-brand token (``gmail``, ``yahoo``, etc.)

    Combined with ``_domain_looks_throwaway`` on the real sending domain,
    callers can surface spoofed-realtor and similar patterns.

    Args:
        addr: Bare email address string (not a display-name form).

    Returns:
        True if the local-part appears to embed a domain or brand name.
    """
    if "@" not in addr:
        return False
    local = addr.split("@", 1)[0]
    if _DOMAIN_IN_LOCAL_RE.search(local):
        return True
    if _MAIL_BRAND_RE.search(local):
        return True
    return False


def display_name_has_email(display_name: str) -> bool:
    """Return True when the display name contains an @-address.

    A display name containing an email address (e.g. ``"Alice
    <alice@evil.com>" <relay@bulk.net>``) is a common spoofing indicator —
    the visible name tricks the reader while the actual envelope is different.

    Args:
        display_name: Decoded display name from a From header.

    Returns:
        True when an @-sign is present in the display name.
    """
    return "@" in display_name


def content_pattern_facts(subject: str, body_text: str) -> Dict:
    """Return factual content-pattern signals from subject and body.

    These are FACTS the model interprets — they are NOT combined into a
    verdict here.  When ``body_text`` is empty (e.g. metadata-only view),
    signals are computed from ``subject`` alone and content-density is 0.0.

    Signals:
    - ``has_otp_pattern``: bool — OTP/verification-code language AND a 4–8
      digit code appear near each other.  The phrase check uses subject +
      body; the digit check applies to the same combined text.
    - ``has_receipt_pattern``: bool — receipt/order/invoice/itinerary/
      reservation/confirmation/claim-number language in subject or body.
    - ``currency_total_present``: bool — a currency figure (``$12.34``,
      ``€9.99``, etc.) or a total/amount/balance label near one.
    - ``marketing_cta_density``: float — count of marketing CTAs per 1000
      chars of body text; 0.0 when body is empty.

    Args:
        subject: Decoded subject string (may be empty).
        body_text: Decoded plain-text body (may be empty).

    Returns:
        Dict with the four signal keys described above.
    """
    combined = f"{subject}\n{body_text}".strip()

    has_otp_pattern: bool = False
    if _OTP_PHRASE_RE.search(combined):
        # Require at least one digit cluster nearby as corroboration.
        if _OTP_DIGIT_RE.search(combined):
            has_otp_pattern = True

    has_receipt_pattern: bool = bool(_RECEIPT_RE.search(combined))

    currency_total_present: bool = bool(_CURRENCY_RE.search(combined))

    marketing_cta_density: float = 0.0
    if body_text:
        cta_count = len(_CTA_RE.findall(body_text))
        marketing_cta_density = round(
            cta_count / max(len(body_text), 1) * 1000, 4
        )

    return {
        "has_otp_pattern": has_otp_pattern,
        "has_receipt_pattern": has_receipt_pattern,
        "currency_total_present": currency_total_present,
        "marketing_cta_density": marketing_cta_density,
    }


# ---------------------------------------------------------------------------
# Bulk detection
# ---------------------------------------------------------------------------

def is_bulk(headers: Dict[str, str]) -> bool:
    """Return True if the message exhibits bulk-mail signals.

    Args:
        headers: Dict of lowercase header name -> decoded value.

    Returns:
        True if at least one bulk signal is present.
    """
    if headers.get("list-unsubscribe"):
        return True
    if headers.get("list-id"):
        return True
    if "bulk" in headers.get("precedence", "").lower():
        return True
    return False


# ---------------------------------------------------------------------------
# Triage helpers
# ---------------------------------------------------------------------------

def _init_sender(
    senders: Dict[str, SenderRecord],
    sender_signals: Dict[str, Dict[str, bool]],
    addr: str,
    display_name: str,
) -> None:
    """Initialise sender and signal dicts for a new address.

    Args:
        senders: Accumulator dict of addr -> SenderRecord.
        sender_signals: Accumulator dict of addr -> signal bools.
        addr: Normalised lowercase email address.
        display_name: Display name parsed from the From header.
    """
    if addr not in senders:
        senders[addr] = SenderRecord(addr, display_name)
        sender_signals[addr] = {
            "has_list_unsub": False,
            "has_list_id": False,
            "has_precedence_bulk": False,
        }


def _accumulate_signals(
    rec: SenderRecord,
    signals: Dict[str, bool],
    headers: Dict[str, str],
) -> None:
    """Update signal flags and sample header from a message's headers.

    Args:
        rec: SenderRecord to update.
        signals: Mutable signal dict for this sender.
        headers: Parsed header dict for the current message.
    """
    list_unsub = headers.get("list-unsubscribe", "")
    list_unsub_post = headers.get("list-unsubscribe-post", "")
    list_id = headers.get("list-id", "")
    precedence = headers.get("precedence", "")
    if list_unsub:
        signals["has_list_unsub"] = True
    if list_id:
        signals["has_list_id"] = True
    if "bulk" in precedence.lower():
        signals["has_precedence_bulk"] = True
    if not rec.sample_unsubscribe_header and list_unsub:
        rec.sample_unsubscribe_header = list_unsub
        rec.sample_unsubscribe_post_header = list_unsub_post
        rec.unsubscribe_method = determine_unsubscribe_method(
            list_unsub, list_unsub_post
        )


def triage_messages(
    all_headers: List[Dict[str, str]],
) -> Dict[str, SenderRecord]:
    """Run triage over a list of parsed header dicts.

    Filters to bulk messages only, aggregates per-sender signal flags,
    then classifies each sender.

    Args:
        all_headers: List of header dicts as returned by
            fetch_headers_batch().

    Returns:
        Dict of lowercase email address -> classified SenderRecord.
    """
    sender_signals: Dict[str, Dict[str, bool]] = {}
    senders: Dict[str, SenderRecord] = {}
    for headers in all_headers:
        if not is_bulk(headers):
            continue
        raw_from = headers.get("from", "")
        display_name, addr = parse_from_header(raw_from)
        if not addr:
            addr = "unknown@unknown"
        _init_sender(senders, sender_signals, addr, display_name)
        rec = senders[addr]
        rec.message_count += 1
        rec.update_display_name(display_name)
        _accumulate_signals(rec, sender_signals[addr], headers)
    for addr, rec in senders.items():
        signals = sender_signals[addr]
        rec.classification = classify_sender(
            rec,
            has_list_unsub=signals["has_list_unsub"],
            has_list_id=signals["has_list_id"],
            has_precedence_bulk=signals["has_precedence_bulk"],
        )
    return senders
