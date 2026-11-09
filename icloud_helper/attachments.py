"""Attachment save, extract, and MIME helpers for icloud-helper.

Provides security-hardened save_attachment(), range-read helpers,
text extraction (text/* charset-aware + PDF via pypdf), and hand-rolled
magic-byte MIME sniffing (fork G — no new deps beyond pypdf).

Security contract for save_to:
  - Accepts a FILENAME ONLY (no path components).
  - Rejects any name containing '/', '\\\\', '..', NUL, or that is absolute.
  - Joins to the configured downloads_dir, resolves realpath, and asserts
    the result still lives inside downloads_dir (defeats traversal + symlink
    escape).
  - Creates downloads_dir at mode 700 if absent.
  - Enforces max_attachment_bytes BEFORE writing (DoS guard).
  - Writes atomically via temp-file + os.replace, mode 600.
"""
from __future__ import annotations

import hashlib
import logging
import os
import re
import tempfile
from pathlib import Path
from typing import Dict, Optional, Tuple

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Safe filename validation (security-critical)
# ---------------------------------------------------------------------------

# Allow printable ASCII that is safe as a filename: letters, digits, and
# the subset of punctuation that appears in document filenames.
# Explicitly forbids: / \\ .. NUL (0x00) and anything that would be
# interpreted as a path component.  The regex is anchored (fullmatch) so
# there is no leading/trailing character escape.
_SAFE_FILENAME_RE = re.compile(
    r"^[A-Za-z0-9][A-Za-z0-9 ._\-()[\]{}@#~!+=,;'`^$%&]*$"
)

# Maximum number of PDF pages to extract text from (DoS guard).
_PDF_PAGE_CAP = 50


# ---------------------------------------------------------------------------
# Magic-byte MIME sniffing (fork G — hand-rolled, zero new deps)
# ---------------------------------------------------------------------------

# Each entry: (declared_mime, magic_bytes_at_offset_0, sniffed_mime)
# Ordered most-specific first.  Longer patterns take precedence via ordering.
_MAGIC_TABLE: Tuple[Tuple[bytes, str], ...] = (
    (b"%PDF", "application/pdf"),
    (b"\xff\xd8\xff", "image/jpeg"),
    (b"\x89PNG\r\n\x1a\n", "image/png"),
    (b"GIF87a", "image/gif"),
    (b"GIF89a", "image/gif"),
    # ZIP-based (OOXML, ODT, EPUB, etc.) — sniff as application/zip; callers
    # can further discriminate by declared content_type if needed.
    (b"PK\x03\x04", "application/zip"),
    (b"PK\x05\x06", "application/zip"),
    # HTML — case-insensitive prefix check handled separately below.
)

# HTML prefixes (case-insensitive, whitespace-stripped).
_HTML_PREFIXES = (b"<!doctype", b"<html")

# How many bytes to sniff for magic detection.
_SNIFF_BYTES = 16


def sniff_mime(data: bytes) -> Optional[str]:
    """Detect MIME type from the first few bytes of *data* (fork G).

    Uses a hand-rolled magic-byte table.  Returns None when the data is
    too short or no signature matches.

    Args:
        data: Raw bytes to inspect (only the first _SNIFF_BYTES are read).

    Returns:
        Detected MIME type string, or None if unrecognised.
    """
    head = data[:_SNIFF_BYTES]
    if not head:
        return None

    for magic, mime in _MAGIC_TABLE:
        if head[: len(magic)] == magic:
            return mime

    # HTML: case-insensitive, allow leading whitespace.
    stripped = head.lstrip()
    lower = stripped.lower()
    for prefix in _HTML_PREFIXES:
        if lower.startswith(prefix):
            return "text/html"

    return None


# ---------------------------------------------------------------------------
# Text extraction helpers (T2.5 / fork E)
# ---------------------------------------------------------------------------


def _extract_text_from_pdf(data: bytes, max_bytes: int) -> Tuple[str, bool]:
    """Extract plain text from PDF bytes using pypdf.

    Enforces a per-page cap (_PDF_PAGE_CAP) as a secondary DoS guard in
    addition to the byte-level size check that the caller performs before
    reaching this function.

    Args:
        data: Raw PDF bytes (already size-capped by caller).
        max_bytes: Maximum number of UTF-8 bytes of text to return.

    Returns:
        Tuple of (extracted_text, text_truncated).  On parse error returns
        ("", False) — the caller adds extract_note.
    """
    try:
        import io  # pylint: disable=import-outside-toplevel

        import pypdf  # pylint: disable=import-outside-toplevel

        reader = pypdf.PdfReader(io.BytesIO(data))
        parts = []
        total = 0
        page_limit = min(len(reader.pages), _PDF_PAGE_CAP)
        for page in reader.pages[:page_limit]:
            chunk = page.extract_text() or ""
            chunk_bytes = chunk.encode("utf-8")
            if total + len(chunk_bytes) > max_bytes:
                # Trim to fit.
                remaining = max_bytes - total
                chunk = chunk_bytes[:remaining].decode("utf-8", errors="ignore")
                parts.append(chunk)
                total += len(chunk.encode("utf-8"))
                return " ".join(parts), True
            parts.append(chunk)
            total += len(chunk_bytes)
        text = " ".join(p for p in parts if p)
        return text, False
    except Exception as exc:  # pylint: disable=broad-except
        log.warning("PDF text extraction failed: %s", exc)
        return "", False


def extract_text_from_attachment(  # pylint: disable=too-many-return-statements
    data: bytes,
    declared_mime: str,
    charset: Optional[str],
    max_bytes: int,
) -> Dict:
    """Extract text from attachment bytes (fork E).

    Supports:
    - text/* — charset-aware decode.
    - application/pdf OR sniffed-as-PDF — pypdf extraction.
    - Anything else — returns text=null with extract_note.

    The byte-level size cap (max_attachment_bytes) must be enforced by
    the caller BEFORE calling this function (DoS guard: do not parse
    multi-megabyte payloads unconditionally).

    Args:
        data: Decoded attachment bytes (already size-capped).
        declared_mime: MIME type as declared in the email part header.
        charset: Charset hint from the part header, or None.
        max_bytes: Maximum UTF-8 bytes of extracted text to return.

    Returns:
        Dict with keys: text (str or None), text_truncated (bool),
        extract_note (str or None).
    """
    sniffed = sniff_mime(data)

    # Determine effective type: trust sniffed over declared for extraction
    # routing, but only when sniffed is concrete.
    effective_pdf = declared_mime == "application/pdf" or sniffed == "application/pdf"
    effective_text = declared_mime.startswith("text/") or sniffed == "text/html"

    if effective_pdf:
        text, truncated = _extract_text_from_pdf(data, max_bytes)
        if not text:
            return {
                "text": None,
                "text_truncated": False,
                "extract_note": "pdf_extraction_returned_empty",
            }
        return {"text": text, "text_truncated": truncated, "extract_note": None}

    if effective_text:
        cs = charset or "utf-8"
        try:
            raw_text = data.decode(cs, errors="replace")
        except LookupError:
            raw_text = data.decode("utf-8", errors="replace")
        encoded = raw_text.encode("utf-8")
        truncated = len(encoded) > max_bytes
        if truncated:
            raw_text = encoded[:max_bytes].decode("utf-8", errors="ignore")
        return {"text": raw_text, "text_truncated": truncated, "extract_note": None}

    return {
        "text": None,
        "text_truncated": False,
        "extract_note": "unsupported_type_for_extraction",
    }


# ---------------------------------------------------------------------------
# Filename validation (security-critical)
# ---------------------------------------------------------------------------


def validate_save_filename(  # pylint: disable=too-many-return-statements
    name: str,
) -> Optional[str]:
    """Validate that *name* is a safe bare filename for save_to.

    Rejects names that contain '/', '\\\\', '..', NUL (\\x00), are absolute
    paths, contain whitespace-only content, or do not match the safe-filename
    character allowlist.

    Args:
        name: Proposed filename string supplied by the caller.

    Returns:
        None when valid.  An error-reason string when invalid.
    """
    if not name or not name.strip():
        return "filename must not be empty"
    if "\x00" in name:
        return "filename must not contain NUL"
    if "/" in name:
        return "filename must not contain '/'"
    if "\\" in name:
        return "filename must not contain '\\\\'"
    if ".." in name:
        return "filename must not contain '..'"
    if os.path.isabs(name):
        return "filename must not be an absolute path"
    if not _SAFE_FILENAME_RE.fullmatch(name):
        return (
            "filename contains disallowed characters; "
            "use letters, digits, spaces, and common punctuation"
        )
    return None


# ---------------------------------------------------------------------------
# Atomic file write with containment check (security-critical)
# ---------------------------------------------------------------------------


def _ensure_downloads_dir(downloads_dir: Path) -> None:
    """Create downloads_dir at mode 700 if it does not exist.

    Args:
        downloads_dir: Absolute path to the directory to create.

    Raises:
        OSError: If creation fails.
    """
    if not downloads_dir.exists():
        downloads_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        log.info("Created downloads_dir %s (mode 700)", downloads_dir)


def _containment_check(candidate: Path, parent: Path) -> bool:
    """Assert that *candidate* is inside *parent* after realpath resolution.

    Resolves both paths with os.path.realpath (follows symlinks, normalises
    '..') and checks that candidate starts with the normalised parent prefix.
    This defeats both classical traversal (../evil) and symlink escape.

    Args:
        candidate: The file path to check.
        parent: The allowed parent directory.

    Returns:
        True when candidate is inside parent; False otherwise.
    """
    real_candidate = os.path.realpath(str(candidate))
    real_parent = os.path.realpath(str(parent))
    # Ensure the separator is appended to avoid prefix false-positives like
    # /safe-dir-ext/ matching /safe-dir/.
    return real_candidate.startswith(real_parent + os.sep) or (
        real_candidate == real_parent
    )


def atomic_write_attachment(
    downloads_dir: Path,
    filename: str,
    data: bytes,
) -> Path:
    """Write *data* atomically to downloads_dir/filename at mode 600.

    Uses a named temp file in the same directory + os.replace for atomicity.
    The containment check is performed on the final path (after joining to
    downloads_dir) to defeat any residual traversal.

    Args:
        downloads_dir: Directory where the file should land (realpath-checked).
        filename: Validated bare filename (no path components).
        data: File contents to write.

    Returns:
        The final Path of the written file.

    Raises:
        ValueError: If the containment check fails.
        OSError: If directory creation or file write fails.
    """
    _ensure_downloads_dir(downloads_dir)

    target = downloads_dir / filename

    # Containment check BEFORE writing.
    if not _containment_check(target, downloads_dir):
        raise ValueError(
            f"containment check failed: resolved path for {filename!r} "
            f"escapes downloads_dir"
        )

    # Write atomically: temp file in same dir + os.replace.
    fd, tmp_path = tempfile.mkstemp(dir=str(downloads_dir), prefix=".tmp-")
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
        fd = -1  # fdopen took ownership; do not close again.
        os.replace(tmp_path, str(target))
    except BaseException:
        if fd != -1:
            try:
                os.close(fd)
            except OSError:
                pass
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise

    log.info(
        "Saved attachment %s (%d bytes) to %s",
        filename,
        len(data),
        target,
    )
    return target


# ---------------------------------------------------------------------------
# SHA-256 helpers
# ---------------------------------------------------------------------------


def sha256_hex(data: bytes) -> str:
    """Return the lowercase hex SHA-256 digest of *data*.

    Args:
        data: Bytes to hash.

    Returns:
        Lowercase hex string (64 characters).
    """
    return hashlib.sha256(data).hexdigest()


# ---------------------------------------------------------------------------
# Range-read helper
# ---------------------------------------------------------------------------


def slice_bytes(
    data: bytes,
    offset: int,
    length: int,
) -> Tuple[bytes, int]:
    """Slice *data* to the requested byte range.

    Args:
        data: Full decoded bytes.
        offset: Starting byte offset (inclusive, 0-based).
        length: Number of bytes to return.  0 means to end of data.

    Returns:
        Tuple of (chunk, total_size_bytes).  chunk may be shorter than
        length when offset + length exceeds total.

    Raises:
        ValueError: When offset or length are negative, or offset > total.
    """
    total = len(data)
    if offset < 0:
        raise ValueError(f"offset must be >= 0, got {offset}")
    if length < 0:
        raise ValueError(f"length must be >= 0, got {length}")
    if offset > total:
        raise ValueError(
            f"offset {offset} exceeds total size {total}"
        )
    if length == 0:
        chunk = data[offset:]
    else:
        chunk = data[offset: offset + length]
    return chunk, total
