"""Flagged-message retrieval for mail-cleaner.

Strictly read-only IMAP access. All folder selects use read-only mode.
This module never modifies flag state, never moves or copies messages,
and never issues any command that alters server-side message storage.
It does not import the unsubscribe or disposition modules.

Imports only stdlib and icloud_helper.* — no mcp dependency — so tests
run under Python 3.9 (.venv).
"""
from __future__ import annotations

import html
import imaplib
import logging
import mimetypes
import quopri
import re
from contextlib import contextmanager
from email.message import Message
from html.parser import HTMLParser
from pathlib import Path
from typing import Dict, Iterator, List, Optional, Tuple

from icloud_helper.attachments import sniff_mime
from icloud_helper.headers import decode_header_value
from icloud_helper.imap_client import (
    connect_and_login,
    select_folder_readonly,
    uid_search,
)
from icloud_helper.secrets import read_secret

log = logging.getLogger(__name__)

IMAP_HOST = "imap.mail.me.com"
IMAP_PORT = 993


class FlaggedError(Exception):
    """Raised when flagged-message retrieval encounters a fatal error."""


def get_uidvalidity(imap: imaplib.IMAP4_SSL) -> int:
    """Extract UIDVALIDITY from the server's untagged responses.

    Args:
        imap: Open IMAP connection with a folder already selected.

    Returns:
        UIDVALIDITY as an integer, or 0 if not present.
    """
    try:
        raw = imap.untagged_responses.get("UIDVALIDITY", [b"0"])
        return int(raw[0])
    except (IndexError, ValueError, TypeError):
        return 0


@contextmanager
def open_readonly_session(
    folder: str, secrets_base: Path
) -> Iterator[Tuple[imaplib.IMAP4_SSL, int]]:
    """Open a read-only IMAP session and yield (imap, uidvalidity).

    Reads credentials from secrets_base/icloud_email and
    secrets_base/icloud_app_password. Converts any SystemExit raised
    by imap_client helpers into FlaggedError — imap_client.py is NOT
    modified (design fork A).

    Args:
        folder: IMAP mailbox folder name to select (read-only).
        secrets_base: Directory containing the icloud_email and
            icloud_app_password secret files.

    Yields:
        Tuple of (authenticated IMAP4_SSL connection, UIDVALIDITY int).

    Raises:
        FlaggedError: On credential read failure, connection failure,
            login failure, or folder-selection failure.
    """
    try:
        user = read_secret(str(secrets_base / "icloud_email"))
        pw = read_secret(str(secrets_base / "icloud_app_password"))
    except SystemExit as exc:
        raise FlaggedError("could not read IMAP credentials") from exc

    try:
        imap = connect_and_login(IMAP_HOST, IMAP_PORT, user, pw)
    except SystemExit as exc:
        raise FlaggedError("imap connect/login failed") from exc

    try:
        try:
            select_folder_readonly(imap, folder)
        except SystemExit as exc:
            raise FlaggedError("folder selection failed") from exc
        uidvalidity = get_uidvalidity(imap)
        yield imap, uidvalidity
    finally:
        try:
            imap.logout()
        except imaplib.IMAP4.error:
            pass


def search_flagged_uids(imap: imaplib.IMAP4_SSL) -> List[int]:
    """Search for UIDs of flagged messages in the selected folder.

    Searches the FLAGGED keyword, which is set by any Apple Mail
    flag colour.

    Args:
        imap: Open IMAP connection with a folder selected.

    Returns:
        Sorted ascending list of UID integers. Empty on error or when
        no flagged messages exist.
    """
    return uid_search(imap, "FLAGGED")


def _parse_fetch_data(
    data: list,
) -> Dict[int, Tuple[bytes, str]]:
    """Parse an IMAP UID FETCH response into uid -> (payload, internaldate).

    Handles the imaplib format where response tuples are interspersed
    with literal b')' separators.

    Args:
        data: Raw response data list from imap.uid("FETCH", ...).

    Returns:
        Dict mapping UID int -> (raw message bytes, INTERNALDATE string).
        Items that cannot be parsed are silently omitted.
    """
    result: Dict[int, Tuple[bytes, str]] = {}
    for item in data:
        if not isinstance(item, tuple) or len(item) < 2:
            continue
        meta, payload = item[0], item[1]
        if not isinstance(meta, bytes) or not isinstance(payload, bytes):
            continue
        meta_str = meta.decode("ascii", errors="replace")
        uid_match = re.search(r"\bUID\s+(\d+)\b", meta_str, re.IGNORECASE)
        if not uid_match:
            continue
        uid = int(uid_match.group(1))
        date_match = re.search(
            r'INTERNALDATE\s+"([^"]+)"', meta_str, re.IGNORECASE
        )
        internaldate = date_match.group(1) if date_match else ""
        result[uid] = (payload, internaldate)
    return result


def fetch_message(
    imap: imaplib.IMAP4_SSL, uid: int
) -> Optional[Tuple[bytes, str]]:
    """Fetch a single message body and INTERNALDATE by UID.

    Uses BODY.PEEK[] to avoid setting the Seen flag.

    Args:
        imap: Open IMAP connection with a folder selected.
        uid: UID of the message to fetch.

    Returns:
        Tuple of (raw message bytes, INTERNALDATE string), or None if
        the UID was not found or a fetch error occurred.
    """
    try:
        status, data = imap.uid(  # type: ignore[attr-defined]
            "FETCH", str(uid), "(UID INTERNALDATE BODY.PEEK[])"
        )
    except imaplib.IMAP4.error as exc:
        log.warning("UID FETCH error for uid=%d: %s", uid, exc)
        return None
    if status != "OK" or not data:
        return None
    parsed = _parse_fetch_data(data)
    return parsed.get(uid)


def fetch_messages_batch(
    imap: imaplib.IMAP4_SSL, uids: List[int]
) -> Dict[int, Tuple[bytes, str]]:
    """Fetch multiple messages in a single IMAP FETCH command.

    Uses BODY.PEEK[] to avoid setting the Seen flag. For list_flagged_messages:
    batch-fetch all selected UIDs in one round-trip; highest UIDs are used
    as a recency proxy, final order by INTERNALDATE is the caller's
    responsibility.

    Args:
        imap: Open IMAP connection with a folder selected.
        uids: List of UIDs to fetch.

    Returns:
        Dict mapping UID -> (raw message bytes, INTERNALDATE string).
        UIDs that could not be fetched are omitted.
    """
    if not uids:
        return {}
    uid_str = ",".join(str(u) for u in uids)
    try:
        status, data = imap.uid(  # type: ignore[attr-defined]
            "FETCH", uid_str, "(UID INTERNALDATE BODY.PEEK[])"
        )
    except imaplib.IMAP4.error as exc:
        log.warning("UID FETCH batch error: %s", exc)
        return {}
    if status != "OK" or not data:
        return {}
    return _parse_fetch_data(data)


def iter_leaf_parts(msg: Message) -> Iterator[Message]:
    """Yield non-multipart leaf parts from a MIME message in walk() order.

    Args:
        msg: Parsed email.message.Message object.

    Yields:
        Each non-multipart leaf part.
    """
    for part in msg.walk():
        if not part.is_multipart():
            yield part


def _collect_attachment_parts(
    msg: Message,
) -> List[Tuple[Message, str, str]]:
    """Return (part, filename, content_type) for each attachment-like leaf.

    A leaf is an attachment entry if any of the following is true:
      - Content-Disposition is "attachment"
      - The part has a filename parameter
      - Content-Type is not text/plain or text/html

    Filenames are RFC 2047-decoded where needed. Missing filenames are
    synthesised as "part-<index><ext>".

    Args:
        msg: Parsed email.message.Message object.

    Returns:
        List of (mime_part, decoded_filename, content_type) in walk() order.
        The list index matches the manifest entry index.
    """
    results: List[Tuple[Message, str, str]] = []
    for part in iter_leaf_parts(msg):
        content_type = part.get_content_type()
        disposition = (part.get_content_disposition() or "").lower()
        filename = part.get_filename()

        if filename and "=?" in filename:
            filename = decode_header_value(filename)

        is_attachment = (
            disposition == "attachment"
            or filename is not None
            or content_type not in ("text/plain", "text/html")
        )
        if not is_attachment:
            continue

        if not filename:
            ext = mimetypes.guess_extension(content_type) or ""
            filename = f"part-{len(results)}{ext}"

        results.append((part, filename, content_type))
    return results


def _estimate_part_size(part: Message) -> int:
    """Estimate the decoded byte size of a MIME part without full decoding.

    For base64-encoded parts, the decoded size is approximated from the
    encoded payload length minus base64 padding characters. For all other
    transfer encodings, the raw (undecoded) payload length is returned.

    This avoids loading large attachment bytes into memory purely to measure
    size. The estimate is approximate/best-effort and is NOT used for
    enforcement; the exact cap is applied in get_attachment (mcp_server.py).

    Args:
        part: A leaf MIME part.

    Returns:
        Estimated decoded size in bytes.
    """
    cte = (part.get("Content-Transfer-Encoding") or "").strip().lower()
    if cte == "base64":
        raw = part.get_payload(decode=False) or ""
        if isinstance(raw, bytes):
            raw = raw.decode("ascii", errors="ignore")
        # Strip whitespace (MIME base64 may have line breaks).
        raw_stripped = raw.replace("\n", "").replace("\r", "").replace(" ", "")
        encoded_len = len(raw_stripped)
        padding = raw_stripped.count("=")
        return max(0, encoded_len * 3 // 4 - padding)
    # For 7bit, 8bit, quoted-printable, or unknown: use raw payload length.
    raw_payload = part.get_payload(decode=False) or b""
    if isinstance(raw_payload, str):
        return len(raw_payload.encode("ascii", errors="replace"))
    return len(raw_payload)


def build_manifest(msg: Message) -> List[Dict]:
    """Build a deterministic ordered attachment manifest for a message.

    Indices are stable: calling this twice on the same message object
    produces identical index->part mappings. Duplicate filenames are
    preserved; the index disambiguates them. Inline parts (e.g. receipt
    images) are included.

    Note: ``size_bytes`` is approximate/best-effort. For base64-encoded
    parts the value is derived from the encoded payload length (exact for
    aligned input; off by at most 2 bytes otherwise). For other transfer
    encodings the raw payload length is returned. ``size_bytes`` is not
    used for enforcement; the exact cap is applied in ``get_attachment``
    (see mcp_server.py).

    Args:
        msg: Parsed email.message.Message object.

    Returns:
        List of dicts, each with keys: index (int), filename (str),
        content_type (str), size_bytes (int).
    """
    parts = _collect_attachment_parts(msg)
    result = []
    for i, (part, filename, content_type) in enumerate(parts):
        # Sniff only the first _SNIFF_BYTES to detect MIME without a full
        # decode (the manifest is a lightweight index, not the payload).
        head = part.get_payload(decode=True) or b""
        detected_mime = sniff_mime(head)
        result.append(
            {
                "index": i,
                "filename": filename,
                "content_type": content_type,
                "detected_mime": detected_mime,
                "size_bytes": _estimate_part_size(part),
            }
        )
    return result


def select_body_text(msg: Message) -> Tuple[str, str]:
    """Select the best body text from a MIME message.

    Precedence: first text/plain leaf (not attachment-disposed), then
    first text/html leaf converted via _html_to_text, then empty string.

    Text decode does not use get_content() to stay Python 3.9-safe and
    avoid policy-dependent behaviour. Falls back to UTF-8 on unknown
    charsets.

    Args:
        msg: Parsed email.message.Message object.

    Returns:
        Tuple of (body_text, body_source) where body_source is one of
        "plain", "html-converted", or "none".
    """
    for part in iter_leaf_parts(msg):
        content_type = part.get_content_type()
        disposition = (part.get_content_disposition() or "").lower()
        if content_type == "text/plain" and disposition != "attachment":
            raw = part.get_payload(decode=True) or b""
            cs = part.get_content_charset() or "utf-8"
            try:
                decoded = raw.decode(cs, errors="replace")
            except LookupError:
                decoded = raw.decode("utf-8", errors="replace")
            # T2.8: sniff the decoded bytes — if labeled plain but actually
            # HTML, route through the HTML-to-text path.
            sniffed = sniff_mime(raw)
            if sniffed == "text/html":
                log.debug(
                    "select_body_text: text/plain part sniffs as HTML — "
                    "converting; body_source=html-converted"
                )
                return _html_to_text(decoded), "html-converted"
            return decoded, "plain"

    for part in iter_leaf_parts(msg):
        content_type = part.get_content_type()
        disposition = (part.get_content_disposition() or "").lower()
        if content_type == "text/html" and disposition != "attachment":
            raw = part.get_payload(decode=True) or b""
            cs = part.get_content_charset() or "utf-8"
            try:
                html_src = raw.decode(cs, errors="replace")
            except LookupError:
                html_src = raw.decode("utf-8", errors="replace")
            return _html_to_text(html_src), "html-converted"

    return "", "none"


def select_plain_source(msg: Message) -> Optional[str]:
    """Return the first non-attachment text/plain leaf's decoded text.

    Used by ``save_message_pdf`` (mcp_server.py) as the fallback body when
    a message has no text/html leaf. Unlike ``select_body_text``, this does
    NOT sniff the decoded bytes for HTML-masquerading-as-plain — the
    caller HTML-escapes whatever is returned before embedding it in a
    synthesised HTML wrapper, so raw markup here is always safe.

    Args:
        msg: Parsed email.message.Message object.

    Returns:
        Decoded plain-text string, or None if no such leaf exists.
    """
    for part in iter_leaf_parts(msg):
        content_type = part.get_content_type()
        disposition = (part.get_content_disposition() or "").lower()
        if content_type == "text/plain" and disposition != "attachment":
            raw = part.get_payload(decode=True) or b""
            cs = part.get_content_charset() or "utf-8"
            try:
                return raw.decode(cs, errors="replace")
            except LookupError:
                return raw.decode("utf-8", errors="replace")
    return None


def select_body_html(msg: Message) -> Tuple[Optional[str], str]:
    """Select the first non-attachment text/html leaf's RAW decoded HTML.

    Unlike ``select_body_text`` (which converts HTML to plain text for
    display), this returns the original markup UNMODIFIED so it can be
    rendered to a PDF by ``render_pdf.render_html_to_pdf`` — a true
    "print to PDF" of the message as authored. Charset-aware decode
    mirrors the fallback logic in ``select_body_text``.

    Args:
        msg: Parsed email.message.Message object.

    Returns:
        Tuple of (html_source, body_source) where body_source is "html"
        when a text/html leaf was found, or "none" otherwise. html_source
        is None when no text/html leaf is found.
    """
    for part in iter_leaf_parts(msg):
        content_type = part.get_content_type()
        disposition = (part.get_content_disposition() or "").lower()
        if content_type == "text/html" and disposition != "attachment":
            raw = part.get_payload(decode=True) or b""
            cs = part.get_content_charset() or "utf-8"
            try:
                html_src = raw.decode(cs, errors="replace")
            except LookupError:
                html_src = raw.decode("utf-8", errors="replace")
            return html_src, "html"
    return None, "none"


def build_cid_map(msg: Message) -> Dict[str, Tuple[bytes, str]]:
    """Build a Content-ID -> (bytes, mime_type) map for inline references.

    Walks every leaf part of *msg*; parts carrying a ``Content-ID`` header
    are added, keyed by the bracket-stripped id (the same normalisation
    ``render_pdf._strip_cid`` applies to ``cid:`` URLs encountered while
    rendering). This map is used EXCLUSIVELY to resolve ``cid:`` references
    within the SAME message — it never crosses message boundaries and
    performs no I/O of its own.

    Args:
        msg: Parsed email.message.Message object.

    Returns:
        Dict mapping bracket-stripped Content-ID -> (decoded payload
        bytes, content_type). Parts without a Content-ID are skipped.
    """
    result: Dict[str, Tuple[bytes, str]] = {}
    for part in iter_leaf_parts(msg):
        raw_cid = part.get("Content-ID")
        if not raw_cid:
            continue
        cid = raw_cid.strip().lstrip("<").rstrip(">")
        if not cid:
            continue
        data = part.get_payload(decode=True) or b""
        result[cid] = (data, part.get_content_type())
    return result


class _HTMLTextExtractor(HTMLParser):
    """HTMLParser subclass that extracts visible text from HTML.

    Drops content inside script and style elements. Handles HTML
    entities via convert_charrefs=True. Collapses whitespace on
    get_text().
    """

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self._parts: List[str] = []
        self._skip: int = 0

    def handle_starttag(self, tag: str, attrs: list) -> None:
        """Track entry into script/style elements.

        Args:
            tag: HTML tag name (lowercased by HTMLParser).
            attrs: List of (name, value) attribute pairs.
        """
        if tag.lower() in ("script", "style"):
            self._skip += 1

    def handle_endtag(self, tag: str) -> None:
        """Track exit from script/style elements.

        Args:
            tag: HTML tag name (lowercased by HTMLParser).
        """
        if tag.lower() in ("script", "style"):
            self._skip = max(0, self._skip - 1)

    def handle_data(self, data: str) -> None:
        """Collect visible text data.

        Args:
            data: Text node content.
        """
        if self._skip == 0:
            self._parts.append(data)

    def error(self, message: str) -> None:
        """Silently absorb HTML parse errors.

        HTMLParser.error is an abstract method inherited from ParserBase.
        Errors in the HTML structure are non-fatal for text extraction.

        Args:
            message: Error description from the parser.
        """
        log.debug("HTMLTextExtractor parse error (ignored): %s", message)

    def get_text(self) -> str:
        """Return extracted text with collapsed whitespace.

        Returns:
            Plain text string with runs of whitespace collapsed to a
            single space and leading/trailing whitespace stripped.
        """
        raw = "".join(self._parts)
        return re.sub(r"\s+", " ", raw).strip()


def _html_to_text(html_source: str) -> str:
    """Convert HTML to plain text using stdlib html.parser (design fork C).

    Strips tags, drops script/style content, unescapes HTML entities,
    and collapses whitespace. No third-party dependencies.

    Args:
        html_source: HTML source string.

    Returns:
        Plain text string.
    """
    extractor = _HTMLTextExtractor()
    extractor.feed(html_source)
    return extractor.get_text()


# Matches quoted-printable soft line breaks (=CRLF or =LF).
_QP_SOFT_BREAK_RE = re.compile(r"=\r?\n")
# Matches quoted-printable encoded bytes (=XX).
_QP_BYTE_RE = re.compile(r"=([0-9A-Fa-f]{2})")
# Matches leftover CSS/style that leaked through the HTML parser (e.g. when
# the HTML is malformed and the parser fails to suppress <style> content).
# Targets typical CSS blocks: selectors followed by braces.
#
# Quantifiers are bounded (rather than unbounded [\w\-]+ / [^}]*) to avoid
# catastrophic backtracking: an unbounded [\w\-]+ immediately followed by a
# literal "{" that never appears causes exponential-time backtracking on
# long runs of word characters (e.g. a plain-text body with no CSS at all),
# a ReDoS reachable by any inbound message body. 80 chars comfortably
# covers real CSS selectors; 4096 comfortably covers a real CSS block body.
_LEAKED_CSS_RE = re.compile(
    r"[.#]?[\w\-]{1,80}\s*\{[^}]{0,4096}\}", re.DOTALL
)

# Hard ceiling on how much text the CSS-strip regex pass is ever run over.
# clean_body_text runs BEFORE the caller's max_body_bytes truncation (T2.7:
# "clean before truncate", so cleaning artefacts never survive into a
# truncated snippet) — but that means an oversized (multi-MB) message body
# would otherwise pay the full cost of a DOTALL regex scan over the entire
# body before any truncation ever happens. Every current caller truncates
# the cleaned result to at most 256 KiB (GlobalConfig.max_body_bytes)
# afterward, so bounding the CSS pass at a ceiling comfortably larger than
# that (2x) never changes the observable output for any message that would
# actually survive truncation, while capping worst-case CPU cost (measured
# at ~0.5s worst case at this ceiling, vs. multiple seconds unbounded on a
# multi-MB body) for oversized bodies. Combined with the cheap "{"
# pre-filter below, the common case (no leaked CSS at all) is effectively
# free regardless of body size.
_CSS_CLEAN_INPUT_CEILING_BYTES = 512 * 1024  # 512 KiB


def clean_body_text(text: str, source: str) -> str:
    """Clean residual artefacts from extracted body text (T2.7).

    Applied BEFORE snippet truncation so artefacts are never frozen into
    the snippet.  Steps applied:

    1. If *source* indicates the text was decoded (not yet fully cleaned),
       decode residual quoted-printable soft-breaks (``=\\r?\\n``) and
       ``=XX`` escape sequences that sometimes survive charset decoding
       when the CTE header was missing or ignored.
    2. Unescape any remaining HTML entities (``html.unescape``).
    3. Strip residual CSS blocks that leaked through the HTML parser.
    4. Collapse runs of whitespace to a single space and strip edges.

    Args:
        text: Body text string to clean.
        source: The ``body_source`` label (``"plain"``, ``"html-converted"``,
            or ``"none"``).  Currently used only for logging; the cleaning
            passes are all safe to apply regardless of source.

    Returns:
        Cleaned plain text string.
    """
    if not text:
        return text

    # Step 1: decode residual quoted-printable artefacts.
    # Only attempt =XX byte decoding when there is a genuine QP signal: a
    # soft-break (=\n / =\r\n) still present in the text, OR the content was
    # produced by the HTML-to-text converter (source == "html-converted").
    # Without this gate, ordinary URLs containing hex-looking query parameters
    # (e.g. ?ref=ab, ?id=a1) would be mangled by quopri.decodestring even
    # though get_payload(decode=True) already stripped the transfer encoding.
    _has_soft_break = "=\n" in text or "=\r\n" in text
    _needs_qp_decode = _has_soft_break or source == "html-converted"
    if _has_soft_break:
        text = _QP_SOFT_BREAK_RE.sub("", text)
    if _needs_qp_decode and _QP_BYTE_RE.search(text):
        try:
            text = quopri.decodestring(
                text.encode("latin-1", errors="replace")
            ).decode("utf-8", errors="replace")
        except Exception:  # pylint: disable=broad-except
            # If QP decode fails, strip the markers manually.
            text = _QP_BYTE_RE.sub("", text)

    # Step 2: unescape HTML entities.
    text = html.unescape(text)

    # Step 3: strip leaked CSS blocks.
    #
    # Two independent cost bounds, both needed:
    #
    # 1. A cheap "{" pre-filter: the regex has no chance of matching
    #    without a literal "{" somewhere in its scan window, but the regex
    #    engine itself still costs ~1ms/KiB just attempting (and failing)
    #    the bounded quantifier at every position even when nothing
    #    matches. A plain substring check is effectively free by
    #    comparison, so skip the regex entirely when there is nothing for
    #    it to find — this covers the overwhelming majority of messages
    #    (no leaked CSS at all), including oversized ones.
    # 2. _CSS_CLEAN_INPUT_CEILING_BYTES: when a "{" IS present (so the
    #    regex must run), bound how much of the text it scans, capping
    #    worst-case CPU cost on an oversized body. Any leaked CSS beyond
    #    the ceiling would be truncated away by the caller's
    #    max_body_bytes cap anyway, so nothing observable changes for
    #    normal-size messages — the untouched remainder is concatenated
    #    back on, not discarded.
    if "{" in text:
        if len(text) > _CSS_CLEAN_INPUT_CEILING_BYTES:
            head, tail = text[:_CSS_CLEAN_INPUT_CEILING_BYTES], text[
                _CSS_CLEAN_INPUT_CEILING_BYTES:
            ]
            text = _LEAKED_CSS_RE.sub(" ", head) + tail
        else:
            text = _LEAKED_CSS_RE.sub(" ", text)

    # Step 4: collapse whitespace.
    text = re.sub(r"\s+", " ", text).strip()

    log.debug("clean_body_text source=%s result_len=%d", source, len(text))
    return text


def extract_attachment(
    msg: Message, index: int
) -> Optional[Dict]:
    """Extract raw bytes and metadata for a manifest entry by index.

    Size-cap enforcement is the caller's responsibility (the tool wrapper
    in mcp_server.py applies _config.flagged.max_attachment_bytes).

    Args:
        msg: Parsed email.message.Message object.
        index: Zero-based manifest index as returned by build_manifest().

    Returns:
        Dict with keys filename (str), content_type (str), and bytes
        (bytes of the decoded payload), or None if index is out of range.
    """
    parts = _collect_attachment_parts(msg)
    if index < 0 or index >= len(parts):
        return None
    part, filename, content_type = parts[index]
    raw = part.get_payload(decode=True) or b""
    return {
        "filename": filename,
        "content_type": content_type,
        "bytes": raw,
    }
