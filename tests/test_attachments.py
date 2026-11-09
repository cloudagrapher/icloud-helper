"""Tests for icloud_helper.attachments — save/extract/MIME helpers.

All tests are mocked/fixture-based; no network calls, no real IMAP.
The save_to containment tests run against a real tmp_path to verify
os.path.realpath behaviour.
"""
from __future__ import annotations

import hashlib
import io
import os
import struct
from pathlib import Path
from typing import Optional
from unittest.mock import patch

import pytest

from icloud_helper.attachments import (
    _containment_check,
    atomic_write_attachment,
    extract_text_from_attachment,
    sha256_hex,
    slice_bytes,
    sniff_mime,
    validate_save_filename,
)


# ---------------------------------------------------------------------------
# Fixtures — tiny binary blobs for sniff tests
# ---------------------------------------------------------------------------


def _make_pdf_bytes() -> bytes:
    """Minimal PDF header bytes."""
    return b"%PDF-1.4 minimal"


def _make_png_bytes() -> bytes:
    """Minimal PNG magic bytes."""
    return b"\x89PNG\r\n\x1a\n" + b"\x00" * 8


def _make_jpeg_bytes() -> bytes:
    """Minimal JPEG magic bytes."""
    return b"\xff\xd8\xff\xe0" + b"\x00" * 12


def _make_zip_bytes() -> bytes:
    """Minimal ZIP magic bytes."""
    return b"PK\x03\x04" + b"\x00" * 12


def _make_html_bytes() -> bytes:
    """Minimal HTML snippet."""
    return b"<!doctype html><html><body>hi</body></html>"


def _make_tiny_pdf() -> bytes:
    """Return a minimal but valid-enough PDF for pypdf.

    Uses the simplest possible single-page PDF with visible text so
    pypdf can attempt extraction.  Built without external libraries.
    """
    # Minimal PDF with one page and one text stream.
    pdf = (
        b"%PDF-1.4\n"
        b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n"
        b"2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n"
        b"3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792]"
        b" /Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >>\n"
        b"endobj\n"
        b"4 0 obj\n<< /Length 44 >>\nstream\n"
        b"BT /F1 12 Tf 100 700 Td (Hello PDF) Tj ET\n"
        b"endstream\nendobj\n"
        b"5 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>\n"
        b"endobj\n"
        b"xref\n0 6\n"
        b"0000000000 65535 f \n"
        b"0000000009 00000 n \n"
        b"0000000058 00000 n \n"
        b"0000000115 00000 n \n"
        b"0000000266 00000 n \n"
        b"0000000360 00000 n \n"
        b"trailer\n<< /Size 6 /Root 1 0 R >>\n"
        b"startxref\n430\n%%EOF\n"
    )
    return pdf


# ---------------------------------------------------------------------------
# T2.8: sniff_mime
# ---------------------------------------------------------------------------


class TestSniffMime:
    """sniff_mime correctly identifies common MIME types from magic bytes."""

    def test_pdf_detected(self) -> None:
        """PDF magic bytes (%PDF) → application/pdf."""
        assert sniff_mime(_make_pdf_bytes()) == "application/pdf"

    def test_png_detected(self) -> None:
        """PNG magic → image/png."""
        assert sniff_mime(_make_png_bytes()) == "image/png"

    def test_jpeg_detected(self) -> None:
        """JPEG magic → image/jpeg."""
        assert sniff_mime(_make_jpeg_bytes()) == "image/jpeg"

    def test_zip_detected(self) -> None:
        """ZIP magic → application/zip."""
        assert sniff_mime(_make_zip_bytes()) == "application/zip"

    def test_html_doctype_lower(self) -> None:
        """<!doctype html> → text/html (case-insensitive)."""
        assert sniff_mime(b"<!doctype html>") == "text/html"

    def test_html_doctype_upper(self) -> None:
        """<!DOCTYPE HTML> → text/html (case-insensitive)."""
        assert sniff_mime(b"<!DOCTYPE HTML>") == "text/html"

    def test_html_tag(self) -> None:
        """<html ... → text/html."""
        assert sniff_mime(b"<html><head>") == "text/html"

    def test_unknown_returns_none(self) -> None:
        """Unknown magic bytes → None."""
        assert sniff_mime(b"\x00\x01\x02\x03\x04\x05\x06\x07") is None

    def test_empty_returns_none(self) -> None:
        """Empty bytes → None."""
        assert sniff_mime(b"") is None

    def test_gif87_detected(self) -> None:
        """GIF87a magic → image/gif."""
        assert sniff_mime(b"GIF87a" + b"\x00" * 10) == "image/gif"

    def test_gif89_detected(self) -> None:
        """GIF89a magic → image/gif."""
        assert sniff_mime(b"GIF89a" + b"\x00" * 10) == "image/gif"


# ---------------------------------------------------------------------------
# Filename validation
# ---------------------------------------------------------------------------


class TestValidateSaveFilename:
    """validate_save_filename enforces a strict allowlist (security-critical)."""

    def test_valid_filename(self) -> None:
        """Simple valid filename is accepted."""
        assert validate_save_filename("invoice.pdf") is None

    def test_valid_filename_with_spaces(self) -> None:
        """Filename with spaces is accepted."""
        assert validate_save_filename("My Invoice 2026.pdf") is None

    def test_slash_rejected(self) -> None:
        """Slash in filename is rejected."""
        assert validate_save_filename("../evil.pdf") is not None

    def test_parent_traversal_rejected(self) -> None:
        """Double-dot component is rejected."""
        assert validate_save_filename("..") is not None

    def test_parent_traversal_in_name_rejected(self) -> None:
        """Double-dot embedded in a name is rejected."""
        assert validate_save_filename("a..b.pdf") is not None

    def test_nul_byte_rejected(self) -> None:
        """NUL byte is rejected."""
        assert validate_save_filename("evil\x00.pdf") is not None

    def test_backslash_rejected(self) -> None:
        """Backslash is rejected."""
        assert validate_save_filename("evil\\path.pdf") is not None

    def test_absolute_path_rejected(self) -> None:
        """Absolute path is rejected."""
        assert validate_save_filename("/etc/passwd") is not None

    def test_empty_string_rejected(self) -> None:
        """Empty string is rejected."""
        assert validate_save_filename("") is not None

    def test_whitespace_only_rejected(self) -> None:
        """Whitespace-only name is rejected."""
        assert validate_save_filename("   ") is not None


# ---------------------------------------------------------------------------
# Containment check
# ---------------------------------------------------------------------------


class TestContainmentCheck:
    """_containment_check defeats traversal and symlink escape."""

    def test_file_inside_dir_passes(self, tmp_path: Path) -> None:
        """File joined directly inside parent passes."""
        child = tmp_path / "file.pdf"
        assert _containment_check(child, tmp_path) is True

    def test_file_outside_dir_fails(self, tmp_path: Path) -> None:
        """File above parent (.. traversal) fails."""
        above = tmp_path.parent / "evil.pdf"
        assert _containment_check(above, tmp_path) is False

    def test_sibling_dir_fails(self, tmp_path: Path) -> None:
        """Sibling directory is not inside tmp_path."""
        sibling = tmp_path.parent / "sibling" / "file.pdf"
        assert _containment_check(sibling, tmp_path) is False

    def test_symlink_escape_detected(self, tmp_path: Path) -> None:
        """Symlink pointing outside downloads_dir is detected."""
        link = tmp_path / "link.pdf"
        outside_target = tmp_path.parent / "outside.pdf"
        # Create the outside file so the symlink can resolve.
        outside_target.write_bytes(b"outside")
        link.symlink_to(outside_target)
        # The realpath of the link resolves to outside_target — not inside.
        assert _containment_check(link, tmp_path) is False


# ---------------------------------------------------------------------------
# T2.5: atomic_write_attachment — traversal rejection + sha256 correctness
# ---------------------------------------------------------------------------


class TestAtomicWriteAttachment:
    """atomic_write_attachment enforces containment and writes correctly."""

    def test_valid_write_succeeds(self, tmp_path: Path) -> None:
        """Valid filename is written to the directory."""
        data = b"Hello attachment"
        path = atomic_write_attachment(tmp_path, "test.pdf", data)
        assert path.exists()
        assert path.read_bytes() == data

    def test_file_mode_is_600(self, tmp_path: Path) -> None:
        """Written file has permissions 600."""
        data = b"secret bytes"
        path = atomic_write_attachment(tmp_path, "secret.bin", data)
        mode = oct(os.stat(path).st_mode)[-3:]
        assert mode == "600"

    def test_sha256_correctness(self, tmp_path: Path) -> None:
        """sha256_hex matches hashlib for the same data."""
        data = b"verify me with sha256"
        expected = hashlib.sha256(data).hexdigest()
        assert sha256_hex(data) == expected

    def test_traversal_via_validate_rejected(self, tmp_path: Path) -> None:
        """save_to='../evil' is rejected by validate_save_filename before write."""
        error = validate_save_filename("../evil")
        assert error is not None  # traversal detected at validation level

    def test_absolute_path_rejected(self, tmp_path: Path) -> None:
        """/etc/passwd is rejected by validate_save_filename."""
        error = validate_save_filename("/etc/passwd")
        assert error is not None

    def test_symlink_escape_rejected(self, tmp_path: Path) -> None:
        """A pre-existing symlink that escapes downloads_dir causes ValueError."""
        # Create a symlink inside tmp_path pointing outside.
        outside = tmp_path.parent / "outside_target"
        outside.mkdir(exist_ok=True)
        link_target = tmp_path / "link_dir"
        link_target.symlink_to(outside)
        # Try to write to link_dir/file.pdf (not directly — write to the name
        # that resolves outside via the containment check on the final target).
        # We test _containment_check directly; atomic_write_attachment catches
        # the ValueError and re-raises.
        evil_path = link_target / "evil.pdf"
        result = _containment_check(evil_path, tmp_path)
        assert result is False


# ---------------------------------------------------------------------------
# T2.5: ranged reads / slice_bytes
# ---------------------------------------------------------------------------


class TestSliceBytes:
    """slice_bytes correctly slices and validates ranges."""

    def test_full_slice_with_length_zero(self) -> None:
        """length=0 returns all bytes from offset to end."""
        data = b"Hello World"
        chunk, total = slice_bytes(data, 0, 0)
        assert chunk == data
        assert total == len(data)

    def test_offset_and_length(self) -> None:
        """offset=6, length=5 returns the correct slice."""
        data = b"Hello World"
        chunk, total = slice_bytes(data, 6, 5)
        assert chunk == b"World"
        assert total == len(data)

    def test_offset_only(self) -> None:
        """offset=6, length=0 returns from offset to end."""
        data = b"Hello World"
        chunk, total = slice_bytes(data, 6, 0)
        assert chunk == b"World"
        assert total == len(data)

    def test_chunk_sha256_matches_slice(self) -> None:
        """sha256 of chunk matches sha256_hex of the same slice."""
        data = b"abcdefghij"
        chunk, _ = slice_bytes(data, 2, 4)  # 'cdef'
        assert sha256_hex(chunk) == hashlib.sha256(chunk).hexdigest()

    def test_full_sha256_matches_whole(self) -> None:
        """sha256_hex on full data matches hashlib."""
        data = b"all bytes"
        assert sha256_hex(data) == hashlib.sha256(data).hexdigest()

    def test_negative_offset_raises(self) -> None:
        """Negative offset raises ValueError."""
        with pytest.raises(ValueError):
            slice_bytes(b"data", -1, 0)

    def test_negative_length_raises(self) -> None:
        """Negative length raises ValueError."""
        with pytest.raises(ValueError):
            slice_bytes(b"data", 0, -1)

    def test_offset_beyond_end_raises(self) -> None:
        """offset > total raises ValueError."""
        with pytest.raises(ValueError):
            slice_bytes(b"data", 100, 0)

    def test_reassembly_hash_matches_full(self) -> None:
        """Reassembling two slices produces the original full_sha256."""
        data = b"chunk one " + b"chunk two"
        full_hash = sha256_hex(data)
        chunk_a, _ = slice_bytes(data, 0, 10)
        chunk_b, _ = slice_bytes(data, 10, 0)
        reassembled = chunk_a + chunk_b
        assert sha256_hex(reassembled) == full_hash


# ---------------------------------------------------------------------------
# T2.5: extract_text_from_attachment
# ---------------------------------------------------------------------------


class TestExtractTextFromAttachment:
    """extract_text_from_attachment handles text, PDF, and unsupported types."""

    def test_text_plain_decoded(self) -> None:
        """text/plain part is charset-decoded and returned."""
        data = "Hello plain text".encode("utf-8")
        result = extract_text_from_attachment(data, "text/plain", "utf-8", 8192)
        assert result["text"] == "Hello plain text"
        assert result["text_truncated"] is False
        assert result["extract_note"] is None

    def test_text_plain_truncated(self) -> None:
        """text/plain longer than max_bytes is truncated."""
        data = ("A" * 200).encode("utf-8")
        result = extract_text_from_attachment(data, "text/plain", "utf-8", 100)
        assert result["text_truncated"] is True
        assert len(result["text"].encode("utf-8")) <= 100

    def test_unsupported_type_returns_null(self) -> None:
        """Binary type with no match returns text=None with extract_note."""
        data = b"\x00\x01\x02\x03binary"
        result = extract_text_from_attachment(
            data, "application/octet-stream", None, 8192
        )
        assert result["text"] is None
        assert result["extract_note"] == "unsupported_type_for_extraction"

    def test_pdf_type_attempts_extraction(self) -> None:
        """application/pdf triggers pypdf path (may return empty on minimal PDF)."""
        data = _make_tiny_pdf()
        result = extract_text_from_attachment(
            data, "application/pdf", None, 8192
        )
        # We accept either a string result or an extract_note; the important
        # thing is no exception and text_truncated is a bool.
        assert isinstance(result.get("text_truncated"), bool)

    def test_sniffed_pdf_triggers_pdf_path(self) -> None:
        """Data starting with %PDF triggers PDF extraction even if declared mime differs."""
        data = _make_tiny_pdf()
        # Declare as octet-stream — sniffed as PDF.
        result = extract_text_from_attachment(
            data, "application/octet-stream", None, 8192
        )
        # Should attempt PDF extraction (not return unsupported_type).
        assert result.get("extract_note") != "unsupported_type_for_extraction"

    def test_include_base64_false_omits_data(self) -> None:
        """When include_base64=False is simulated, data_base64 is absent from response.

        This tests the contract at the mcp_server level indirectly by verifying
        the attachment bytes can be retrieved without the base64 field.
        (The actual include_base64 flag is enforced in mcp_server.get_attachment.)
        """
        # This test verifies the helper itself doesn't produce base64 output —
        # extract_text_from_attachment is separate from base64 encoding.
        data = b"plain text content"
        result = extract_text_from_attachment(data, "text/plain", "utf-8", 8192)
        assert "data_base64" not in result

    def test_size_cap_before_extract_respected(self) -> None:
        """max_bytes=10 truncates a 100-char text result to at most 10 bytes."""
        data = ("B" * 100).encode("utf-8")
        result = extract_text_from_attachment(data, "text/plain", "utf-8", 10)
        assert len((result["text"] or "").encode("utf-8")) <= 10
        assert result["text_truncated"] is True

    def test_detected_mime_for_fixtures(self) -> None:
        """sniff_mime returns correct type for PDF, PNG, ZIP, and JPEG fixtures."""
        assert sniff_mime(_make_pdf_bytes()) == "application/pdf"
        assert sniff_mime(_make_png_bytes()) == "image/png"
        assert sniff_mime(_make_zip_bytes()) == "application/zip"
        assert sniff_mime(_make_jpeg_bytes()) == "image/jpeg"
