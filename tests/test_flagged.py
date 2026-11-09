"""Tests for icloud_helper.flagged — MIME parsing and manifest logic.

All tests are Python 3.9-safe and do not touch the network. IMAP
interactions are exercised via mocks in tests/test_mcp_server.py.
"""
from __future__ import annotations

import email
import email.encoders
import email.mime.application
import email.mime.base
import email.mime.image
import email.mime.multipart
import email.mime.text
import time
from email.message import Message
from typing import List

import pytest

from unittest.mock import MagicMock

from icloud_helper.flagged import (
    build_manifest,
    clean_body_text,
    extract_attachment,
    get_uidvalidity,
    select_body_text,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_plain_text(body: str, charset: str = "utf-8") -> Message:
    """Return a simple text/plain Message."""
    msg = email.mime.text.MIMEText(body, "plain", charset)
    return msg  # type: ignore[return-value]


def _make_pdf_attachment(data: bytes, filename: str = "doc.pdf") -> Message:
    """Return an application/pdf attachment Message."""
    part: Message = email.mime.application.MIMEApplication(
        data, "pdf", Name=filename
    )
    part.add_header(
        "Content-Disposition", "attachment", filename=filename
    )
    return part


# ---------------------------------------------------------------------------
# Test 1: multipart/alternative — plain body, empty manifest
# ---------------------------------------------------------------------------


class TestMultipartAlternative:
    """Test 1: multipart/alternative with text/plain and text/html."""

    def test_body_from_plain_part(self) -> None:
        """Body comes from text/plain; manifest is empty."""
        msg: Message = email.mime.multipart.MIMEMultipart("alternative")
        msg.attach(email.mime.text.MIMEText("Hello plain", "plain", "utf-8"))
        msg.attach(
            email.mime.text.MIMEText("<p>Hello html</p>", "html", "utf-8")
        )

        body_text, body_source = select_body_text(msg)
        assert body_source == "plain"
        assert "Hello plain" in body_text

    def test_manifest_empty_for_text_only(self) -> None:
        """No attachment entries when the message is text only."""
        msg: Message = email.mime.multipart.MIMEMultipart("alternative")
        msg.attach(email.mime.text.MIMEText("Hello", "plain", "utf-8"))
        msg.attach(
            email.mime.text.MIMEText("<p>Hello</p>", "html", "utf-8")
        )

        assert build_manifest(msg) == []


# ---------------------------------------------------------------------------
# Test 2: multipart/mixed with text and PDF attachment
# ---------------------------------------------------------------------------


class TestMultipartMixedWithPdf:
    """Test 2: multipart/mixed — text body + PDF attachment."""

    def test_body_correct(self) -> None:
        """Body text comes from the text/plain part."""
        msg: Message = email.mime.multipart.MIMEMultipart("mixed")
        msg.attach(email.mime.text.MIMEText("Invoice body", "plain", "utf-8"))
        msg.attach(_make_pdf_attachment(b"%PDF-1.4 test"))

        body_text, body_source = select_body_text(msg)
        assert body_source == "plain"
        assert "Invoice body" in body_text

    def test_pdf_in_manifest_index_zero(self) -> None:
        """PDF attachment appears at manifest index 0 with correct fields."""
        pdf_data = b"%PDF-1.4 content"
        msg: Message = email.mime.multipart.MIMEMultipart("mixed")
        msg.attach(email.mime.text.MIMEText("Body", "plain", "utf-8"))
        msg.attach(_make_pdf_attachment(pdf_data, "invoice.pdf"))

        manifest = build_manifest(msg)
        assert len(manifest) == 1
        entry = manifest[0]
        assert entry["index"] == 0
        assert entry["content_type"] == "application/pdf"
        assert entry["size_bytes"] == len(pdf_data)


# ---------------------------------------------------------------------------
# Test 3: nested multipart — body at depth, attachment indexed
# ---------------------------------------------------------------------------


class TestNestedMultipart:
    """Test 3: mixed -> (alternative + attachment) nesting."""

    def test_body_found_at_depth(self) -> None:
        """select_body_text walks nested parts to find text/plain."""
        inner: Message = email.mime.multipart.MIMEMultipart("alternative")
        inner.attach(
            email.mime.text.MIMEText("Nested body", "plain", "utf-8")
        )
        inner.attach(
            email.mime.text.MIMEText("<b>Nested</b>", "html", "utf-8")
        )

        outer: Message = email.mime.multipart.MIMEMultipart("mixed")
        outer.attach(inner)
        outer.attach(_make_pdf_attachment(b"%PDF", "report.pdf"))

        body_text, body_source = select_body_text(outer)
        assert body_source == "plain"
        assert "Nested body" in body_text

    def test_attachment_indexed_correctly(self) -> None:
        """Attachment in nested structure has a valid manifest index."""
        inner: Message = email.mime.multipart.MIMEMultipart("alternative")
        inner.attach(
            email.mime.text.MIMEText("Body text", "plain", "utf-8")
        )

        outer: Message = email.mime.multipart.MIMEMultipart("mixed")
        outer.attach(inner)
        outer.attach(_make_pdf_attachment(b"%PDF", "nested.pdf"))

        manifest = build_manifest(outer)
        assert len(manifest) == 1
        assert extract_attachment(outer, manifest[0]["index"]) is not None


# ---------------------------------------------------------------------------
# Test 4: bogus charset falls back without exception
# ---------------------------------------------------------------------------


class TestCharsetFallback:
    """Test 4: bogus content charset does not raise."""

    def test_no_exception_on_unknown_charset(self) -> None:
        """Unknown charset is silently replaced with UTF-8 errors='replace'."""
        part: Message = email.mime.text.MIMEText.__new__(
            email.mime.text.MIMEText
        )
        # Build manually so we can inject an invalid charset parameter.
        raw_msg = (
            b"MIME-Version: 1.0\r\n"
            b"Content-Type: text/plain; charset=x-unknown\r\n"
            b"Content-Transfer-Encoding: 7bit\r\n"
            b"\r\n"
            b"Hello world\r\n"
        )
        msg = email.message_from_bytes(raw_msg)
        # Must not raise regardless of charset.
        body_text, body_source = select_body_text(msg)
        assert body_source == "plain"
        assert isinstance(body_text, str)


# ---------------------------------------------------------------------------
# Test 5: HTML-only message — tags stripped, entities unescaped
# ---------------------------------------------------------------------------


class TestHtmlToText:
    """Test 5: HTML-only message — body_source='html-converted'."""

    def test_tags_stripped(self) -> None:
        """HTML tags are removed from the body text."""
        html = "<p>Hello <b>world</b></p>"
        msg: Message = email.mime.text.MIMEText(html, "html", "utf-8")
        body_text, body_source = select_body_text(msg)
        assert body_source == "html-converted"
        assert "<p>" not in body_text
        assert "<b>" not in body_text
        assert "Hello" in body_text
        assert "world" in body_text

    def test_html_entities_unescaped(self) -> None:
        """HTML entities like &amp; and &lt; are unescaped."""
        html = "<p>AT&amp;T &lt;rocks&gt;</p>"
        msg: Message = email.mime.text.MIMEText(html, "html", "utf-8")
        body_text, _ = select_body_text(msg)
        assert "AT&T" in body_text
        assert "<rocks>" in body_text

    def test_script_content_dropped(self) -> None:
        """Content inside <script> is not included in body text."""
        html = "<p>Visible</p><script>alert('xss')</script>"
        msg: Message = email.mime.text.MIMEText(html, "html", "utf-8")
        body_text, _ = select_body_text(msg)
        assert "alert" not in body_text
        assert "Visible" in body_text


# ---------------------------------------------------------------------------
# Test 6: missing filename synthesised as part-<index><ext>
# ---------------------------------------------------------------------------


class TestMissingFilenameSynthesis:
    """Test 6: attachment without a filename gets a synthesised name."""

    def test_synthesised_filename_format(self) -> None:
        """Part with no filename gets 'part-<index>' with optional extension."""
        msg: Message = email.mime.multipart.MIMEMultipart("mixed")
        msg.attach(email.mime.text.MIMEText("Body", "plain", "utf-8"))

        # Attachment without any filename hint.
        part: Message = email.mime.application.MIMEApplication(
            b"\x00\x01\x02", _subtype="octet-stream"
        )
        part.add_header("Content-Disposition", "attachment")
        # Deliberately do NOT set a filename.
        del part["Content-Type"]
        part["Content-Type"] = "application/octet-stream"
        msg.attach(part)

        manifest = build_manifest(msg)
        assert len(manifest) == 1
        assert manifest[0]["filename"].startswith("part-0")


# ---------------------------------------------------------------------------
# Test 7: duplicate filenames — both entries present, both extractable
# ---------------------------------------------------------------------------


class TestDuplicateFilenames:
    """Test 7: two attachments with the same filename get distinct indices."""

    def test_two_entries_with_distinct_indices(self) -> None:
        """Duplicate filenames produce two manifest entries."""
        msg: Message = email.mime.multipart.MIMEMultipart("mixed")
        msg.attach(email.mime.text.MIMEText("Body", "plain", "utf-8"))
        msg.attach(_make_pdf_attachment(b"first", "duplicate.pdf"))
        msg.attach(_make_pdf_attachment(b"second", "duplicate.pdf"))

        manifest = build_manifest(msg)
        assert len(manifest) == 2
        assert manifest[0]["filename"] == "duplicate.pdf"
        assert manifest[1]["filename"] == "duplicate.pdf"
        assert manifest[0]["index"] != manifest[1]["index"]

    def test_both_extractable_by_index(self) -> None:
        """Each duplicate entry can be extracted by its own index."""
        msg: Message = email.mime.multipart.MIMEMultipart("mixed")
        msg.attach(email.mime.text.MIMEText("Body", "plain", "utf-8"))
        msg.attach(_make_pdf_attachment(b"first-payload", "dup.pdf"))
        msg.attach(_make_pdf_attachment(b"second-payload", "dup.pdf"))

        manifest = build_manifest(msg)
        result_0 = extract_attachment(msg, manifest[0]["index"])
        result_1 = extract_attachment(msg, manifest[1]["index"])
        assert result_0 is not None
        assert result_1 is not None
        assert result_0["bytes"] == b"first-payload"
        assert result_1["bytes"] == b"second-payload"


# ---------------------------------------------------------------------------
# Test 8: no text part — body_text='', manifest has PDF at index 0
# ---------------------------------------------------------------------------


class TestNoTextPart:
    """Test 8: message with only a PDF — no text body."""

    def test_empty_body_and_pdf_manifest(self) -> None:
        """body_text='' and body_source='none' when no text leaf exists."""
        pdf_data = b"%PDF-binary"
        msg: Message = email.mime.multipart.MIMEMultipart("mixed")
        msg.attach(_make_pdf_attachment(pdf_data))

        body_text, body_source = select_body_text(msg)
        assert body_text == ""
        assert body_source == "none"

        manifest = build_manifest(msg)
        assert len(manifest) == 1
        assert manifest[0]["index"] == 0
        assert manifest[0]["content_type"] == "application/pdf"


# ---------------------------------------------------------------------------
# Test 9: inline image disposition appears in manifest
# ---------------------------------------------------------------------------


class TestInlineImageInManifest:
    """Test 9: inline images (receipts etc.) appear in the manifest."""

    def test_inline_image_included(self) -> None:
        """Content-Disposition: inline image/jpeg part appears in manifest."""
        msg: Message = email.mime.multipart.MIMEMultipart("related")
        msg.attach(email.mime.text.MIMEText("Body", "plain", "utf-8"))

        img_data = b"\xff\xd8\xff\xe0" + b"\x00" * 12  # JPEG header stub
        img_part: Message = email.mime.image.MIMEImage(img_data, "jpeg")
        img_part.add_header("Content-Disposition", "inline")
        msg.attach(img_part)

        manifest = build_manifest(msg)
        ct_list: List[str] = [e["content_type"] for e in manifest]
        assert "image/jpeg" in ct_list

    def test_inline_image_is_extractable(self) -> None:
        """Inline image bytes can be recovered via extract_attachment."""
        img_data = b"\xff\xd8\xff" + b"\xab" * 8
        msg: Message = email.mime.multipart.MIMEMultipart("related")
        msg.attach(email.mime.text.MIMEText("Body", "plain", "utf-8"))
        img_part: Message = email.mime.image.MIMEImage(img_data, "jpeg")
        img_part.add_header("Content-Disposition", "inline")
        msg.attach(img_part)

        manifest = build_manifest(msg)
        result = extract_attachment(msg, manifest[0]["index"])
        assert result is not None
        assert result["bytes"] == img_data


# ---------------------------------------------------------------------------
# Test 10: RFC 2047-encoded filename decoded in manifest
# ---------------------------------------------------------------------------


class TestRfc2047Filename:
    """Test 10: RFC 2047-encoded filename is decoded in the manifest."""

    def test_encoded_filename_decoded(self) -> None:
        """=?UTF-8?...?= filename is decoded to Unicode in manifest entry."""
        # "Résumé.pdf" encoded in QP form.
        encoded = "=?UTF-8?q?R=C3=A9sum=C3=A9=2Epdf?="

        msg: Message = email.mime.multipart.MIMEMultipart("mixed")
        msg.attach(email.mime.text.MIMEText("Body", "plain", "utf-8"))

        part: Message = email.mime.application.MIMEApplication(
            b"%PDF-content", Name=encoded
        )
        # Set Content-Disposition with the raw encoded filename so that
        # get_filename() returns the encoded form (compat32 policy).
        part.add_header(
            "Content-Disposition",
            "attachment",
            filename=encoded,
        )
        msg.attach(part)

        manifest = build_manifest(msg)
        assert len(manifest) == 1
        filename = manifest[0]["filename"]
        # The encoded form must not appear in the final filename.
        assert "=?" not in filename
        # Decoded form must contain the expected characters.
        assert "sum" in filename


# ---------------------------------------------------------------------------
# Test 11: size_bytes accuracy with transfer-encoded payloads
# ---------------------------------------------------------------------------


class TestSizeBytesAccuracy:
    """Test 11: size_bytes is an approximate/best-effort estimate.

    Since MEDIUM-1a, size_bytes is no longer an exact decoded byte count.
    For base64-encoded parts the estimate is derived from the encoded payload
    length and is exact for payloads whose decoded length is a multiple of 3
    (or within 2 bytes). For other transfer encodings the raw payload length
    is returned. The exact cap is enforced in get_attachment, not here.
    """

    def test_base64_encoded_payload_size(self) -> None:
        """size_bytes estimate for a base64 part is close to the original size."""
        original = b"This is binary data: \x00\x01\x02\x03" * 10  # 40 bytes
        msg: Message = email.mime.multipart.MIMEMultipart("mixed")
        msg.attach(email.mime.text.MIMEText("Body", "plain", "utf-8"))

        part: Message = email.mime.application.MIMEApplication(
            original, Name="data.bin"
        )
        part.add_header("Content-Disposition", "attachment", filename="data.bin")
        msg.attach(part)

        manifest = build_manifest(msg)
        assert len(manifest) == 1
        # For 40-byte input: base64 encodes to 56 chars (2 '=' padding),
        # so estimate = 56*3//4 - 2 = 40, which is exact.
        size = manifest[0]["size_bytes"]
        assert isinstance(size, int)
        assert abs(size - len(original)) <= 2, (
            f"size_bytes estimate {size} is more than 2 bytes off "
            f"from actual {len(original)}"
        )

    def test_transfer_encoded_attachment_size_is_positive_int(self) -> None:
        """size_bytes for any transfer-encoded attachment is a non-negative int.

        Since size_bytes is now approximate (raw payload length for non-base64
        parts), we only assert that it is a non-negative integer rather than
        checking for an exact decoded byte count.
        """
        text_content = "Héllo Wörld"

        part: Message = email.mime.text.MIMEText(
            text_content, "plain", "utf-8"
        )
        part.add_header("Content-Disposition", "attachment")

        msg: Message = email.mime.multipart.MIMEMultipart("mixed")
        msg.attach(email.mime.text.MIMEText("Body", "plain", "utf-8"))
        msg.attach(part)

        manifest = build_manifest(msg)
        assert len(manifest) == 1
        size = manifest[0]["size_bytes"]
        assert isinstance(size, int)
        assert size >= 0


# ---------------------------------------------------------------------------
# Test 12: extract_attachment out-of-range returns None
# ---------------------------------------------------------------------------


class TestExtractAttachmentOutOfRange:
    """Test 12: out-of-range index returns None."""

    def test_negative_index_returns_none(self) -> None:
        """Negative index returns None."""
        msg: Message = email.mime.multipart.MIMEMultipart("mixed")
        msg.attach(email.mime.text.MIMEText("Body", "plain", "utf-8"))
        msg.attach(_make_pdf_attachment(b"%PDF", "test.pdf"))

        assert extract_attachment(msg, -1) is None

    def test_index_beyond_manifest_returns_none(self) -> None:
        """Index >= len(manifest) returns None."""
        msg: Message = email.mime.multipart.MIMEMultipart("mixed")
        msg.attach(email.mime.text.MIMEText("Body", "plain", "utf-8"))
        msg.attach(_make_pdf_attachment(b"%PDF", "test.pdf"))

        manifest = build_manifest(msg)
        assert extract_attachment(msg, len(manifest)) is None
        assert extract_attachment(msg, 99) is None

    def test_empty_manifest_any_index_returns_none(self) -> None:
        """Returns None when the message has no attachment entries."""
        msg: Message = email.mime.text.MIMEText("plain only", "plain", "utf-8")
        assert extract_attachment(msg, 0) is None


# ---------------------------------------------------------------------------
# Test 14: get_uidvalidity — extracts UIDVALIDITY from untagged_responses
# ---------------------------------------------------------------------------


class TestGetUidvalidity:
    """NIT 3: get_uidvalidity reads UIDVALIDITY from mock IMAP connection."""

    def test_returns_parsed_int_when_present(self) -> None:
        """Returns correct integer when UIDVALIDITY key is in untagged_responses."""
        mock_imap = MagicMock()
        mock_imap.untagged_responses = {"UIDVALIDITY": [b"99999"]}
        assert get_uidvalidity(mock_imap) == 99999

    def test_returns_zero_when_key_absent(self) -> None:
        """Returns 0 when UIDVALIDITY key is absent from untagged_responses."""
        mock_imap = MagicMock()
        mock_imap.untagged_responses = {}
        assert get_uidvalidity(mock_imap) == 0


# ---------------------------------------------------------------------------
# Test 13: build_manifest determinism — same index always maps to same part
# ---------------------------------------------------------------------------


class TestBuildManifestDeterminism:
    """Test 13: repeated calls on the same message yield identical mappings."""

    def test_same_index_same_filename(self) -> None:
        """Two calls to build_manifest produce identical index->filename."""
        msg: Message = email.mime.multipart.MIMEMultipart("mixed")
        msg.attach(email.mime.text.MIMEText("Body", "plain", "utf-8"))
        msg.attach(_make_pdf_attachment(b"p1", "first.pdf"))
        msg.attach(_make_pdf_attachment(b"p2", "second.pdf"))

        manifest_a = build_manifest(msg)
        manifest_b = build_manifest(msg)

        assert len(manifest_a) == len(manifest_b)
        for a_entry, b_entry in zip(manifest_a, manifest_b):
            assert a_entry["index"] == b_entry["index"]
            assert a_entry["filename"] == b_entry["filename"]
            assert a_entry["content_type"] == b_entry["content_type"]

    def test_same_index_same_bytes(self) -> None:
        """extract_attachment with the same index always returns the same bytes."""
        payload_a = b"payload-alpha"
        payload_b = b"payload-beta"

        msg: Message = email.mime.multipart.MIMEMultipart("mixed")
        msg.attach(email.mime.text.MIMEText("Body", "plain", "utf-8"))
        msg.attach(_make_pdf_attachment(payload_a, "a.pdf"))
        msg.attach(_make_pdf_attachment(payload_b, "b.pdf"))

        manifest = build_manifest(msg)
        idx_0 = manifest[0]["index"]
        idx_1 = manifest[1]["index"]

        first_call_0 = extract_attachment(msg, idx_0)
        second_call_0 = extract_attachment(msg, idx_0)
        assert first_call_0 is not None
        assert second_call_0 is not None
        assert first_call_0["bytes"] == second_call_0["bytes"] == payload_a

        first_call_1 = extract_attachment(msg, idx_1)
        assert first_call_1 is not None
        assert first_call_1["bytes"] == payload_b


# ---------------------------------------------------------------------------
# T2.7: clean_body_text — QP artefacts, entities, style/script, whitespace
# ---------------------------------------------------------------------------


class TestCleanBodyText:
    """T2.7: clean_body_text removes artefacts before truncation."""

    def test_empty_string_returned_unchanged(self) -> None:
        """Empty string is returned as-is."""
        assert clean_body_text("", "plain") == ""

    def test_html_entities_decoded(self) -> None:
        """HTML entities like &amp; and &lt; are unescaped."""
        result = clean_body_text("AT&amp;T &lt;rocks&gt;", "plain")
        assert "AT&T" in result
        assert "<rocks>" in result

    def test_whitespace_collapsed(self) -> None:
        """Multiple spaces and newlines are collapsed to single space."""
        result = clean_body_text("hello   world\n\nfoo", "plain")
        assert "  " not in result
        assert "\n" not in result

    def test_qp_soft_breaks_removed(self) -> None:
        """Quoted-printable soft line breaks (=\\n) are removed."""
        text = "Hello=\nWorld"
        result = clean_body_text(text, "plain")
        # After removing the soft break, 'HelloWorld' or 'Hello World' is
        # expected; there must be no '=\\n' artefact.
        assert "=\n" not in result

    def test_leaked_css_stripped(self) -> None:
        """Leaked CSS blocks (selector + braces) are removed."""
        text = "Hello .btn{color:red;font-size:12px} World"
        result = clean_body_text(text, "html-converted")
        assert "{" not in result or "color" not in result
        assert "Hello" in result
        assert "World" in result

    def test_plain_source_entities_decoded(self) -> None:
        """Entities in plain source are still decoded."""
        result = clean_body_text("&quot;quoted&quot;", "plain")
        assert '"quoted"' in result

    def test_url_hex_params_not_mangled_without_soft_break(self) -> None:
        """Plain text with hex-looking URL params and no QP soft-break is
        returned with URL intact — no replacement characters introduced."""
        text = "Visit https://x.com/p?ref=ab&id=12 for details."
        result = clean_body_text(text, "plain")
        assert "ref=ab" in result, f"URL mangled: {result!r}"
        assert "id=12" in result, f"URL mangled: {result!r}"
        assert "�" not in result, f"Replacement char present: {result!r}"

    def test_qp_byte_sequences_decoded_with_soft_break(self) -> None:
        """Text containing genuine QP soft-breaks and =XX escapes is correctly
        decoded even when source is 'plain'."""
        # =41 is QP for 'A'; the soft-break (=\n) signals genuine QP encoding.
        text = "Hello=\nWor=41d"
        result = clean_body_text(text, "plain")
        assert "=\n" not in result, "Soft-break not removed"
        assert "=41" not in result, "=XX escape not decoded"
        assert "HelloWord" in result or "Hello" in result

    def test_large_body_no_brace_css_strip_stays_bounded(self) -> None:
        """Security hardening (LOW-1): clean_body_text runs BEFORE the
        caller's max_body_bytes truncation, so an oversized (multi-MB) body
        with no leaked-CSS content must not pay any CSS-regex cost at all
        (the cheap "{" pre-filter should skip the regex entirely)."""
        large_text = "A" * (6 * 1024 * 1024)  # 6 MiB, no CSS-like content.
        start = time.monotonic()
        result = clean_body_text(large_text, "plain")
        elapsed = time.monotonic() - start
        assert elapsed < 1.0, f"clean_body_text took too long: {elapsed:.2f}s"
        assert len(result) > 0

    def test_large_body_with_brace_css_strip_stays_bounded(self) -> None:
        """Security hardening (LOW-1): an oversized body that DOES contain a
        "{" (so the CSS regex must run) is still bounded by the input
        ceiling rather than scanning the full multi-MB body."""
        large_text = "{" + "A" * (6 * 1024 * 1024)  # 6 MiB, one stray brace.
        start = time.monotonic()
        result = clean_body_text(large_text, "plain")
        elapsed = time.monotonic() - start
        assert elapsed < 2.0, f"clean_body_text took too long: {elapsed:.2f}s"
        assert len(result) > 0

    def test_leaked_css_within_ceiling_still_stripped_on_large_body(
        self,
    ) -> None:
        """Leaked CSS inside the bounded prefix is still stripped even on
        an oversized overall body (no behaviour change for content that
        would survive normal truncation)."""
        padding = "A" * (3 * 1024 * 1024)
        text = f"Hello .btn{{color:red;font-size:12px}} World {padding}"
        result = clean_body_text(text, "html-converted")
        assert "color:red" not in result
        assert "Hello" in result
        assert "World" in result

    def test_normal_size_body_css_strip_unaffected_by_ceiling(self) -> None:
        """A normal-size body (well under the ceiling) behaves identically
        to before the bound was introduced."""
        text = "Hello .btn{color:red;font-size:12px} World"
        result = clean_body_text(text, "html-converted")
        assert "{" not in result or "color" not in result
        assert "Hello" in result
        assert "World" in result


# ---------------------------------------------------------------------------
# T2.8: mislabeled text/plain body_source → html-converted
# ---------------------------------------------------------------------------


class TestMislabeledPlainAsHtml:
    """T2.8: text/plain part whose bytes are HTML → body_source=html-converted."""

    def test_html_bytes_in_plain_part_rerouted(self) -> None:
        """A part declared text/plain but containing HTML is converted."""
        html_body = b"<!doctype html><html><body><p>Hello</p></body></html>"
        raw_msg = (
            b"MIME-Version: 1.0\r\n"
            b"Content-Type: text/plain; charset=utf-8\r\n"
            b"Content-Transfer-Encoding: 7bit\r\n"
            b"\r\n"
        ) + html_body
        import email as _email
        msg = _email.message_from_bytes(raw_msg)
        body_text, body_source = select_body_text(msg)
        # The mislabeled part sniffs as HTML → routes through html-to-text.
        assert body_source == "html-converted"
        assert "<html>" not in body_text
        assert "Hello" in body_text

    def test_real_plain_text_stays_plain(self) -> None:
        """Actual plain text content keeps body_source=plain."""
        plain_body = b"Just a normal plain text message."
        raw_msg = (
            b"MIME-Version: 1.0\r\n"
            b"Content-Type: text/plain; charset=utf-8\r\n"
            b"Content-Transfer-Encoding: 7bit\r\n"
            b"\r\n"
        ) + plain_body
        import email as _email
        msg = _email.message_from_bytes(raw_msg)
        _, body_source = select_body_text(msg)
        assert body_source == "plain"


# ---------------------------------------------------------------------------
# T2.8: detected_mime in build_manifest
# ---------------------------------------------------------------------------


class TestDetectedMimeInManifest:
    """T2.8: build_manifest includes detected_mime for each attachment."""

    def test_pdf_attachment_detected_mime(self) -> None:
        """PDF attachment has detected_mime='application/pdf'."""
        pdf_data = b"%PDF-1.4 tiny"
        msg: Message = email.mime.multipart.MIMEMultipart("mixed")
        msg.attach(email.mime.text.MIMEText("Body", "plain", "utf-8"))
        msg.attach(_make_pdf_attachment(pdf_data, "doc.pdf"))

        manifest = build_manifest(msg)
        assert len(manifest) == 1
        assert manifest[0]["detected_mime"] == "application/pdf"

    def test_jpeg_attachment_detected_mime(self) -> None:
        """JPEG attachment has detected_mime='image/jpeg'."""
        jpeg_data = b"\xff\xd8\xff\xe0" + b"\x00" * 12
        msg: Message = email.mime.multipart.MIMEMultipart("mixed")
        msg.attach(email.mime.text.MIMEText("Body", "plain", "utf-8"))
        part: Message = email.mime.image.MIMEImage(jpeg_data, "jpeg")
        part.add_header("Content-Disposition", "attachment", filename="photo.jpg")
        msg.attach(part)

        manifest = build_manifest(msg)
        assert any(
            e["detected_mime"] == "image/jpeg" for e in manifest
        )

    def test_unknown_type_detected_mime_none(self) -> None:
        """Unknown binary attachment has detected_mime=None."""
        unknown_data = b"\x00\x01\x02\x03unknown"
        msg: Message = email.mime.multipart.MIMEMultipart("mixed")
        msg.attach(email.mime.text.MIMEText("Body", "plain", "utf-8"))
        part: Message = email.mime.application.MIMEApplication(
            unknown_data, _subtype="octet-stream"
        )
        part.add_header("Content-Disposition", "attachment", filename="data.bin")
        msg.attach(part)

        manifest = build_manifest(msg)
        assert len(manifest) == 1
        # detected_mime key must be present (may be None for unknown types).
        assert "detected_mime" in manifest[0]
        assert manifest[0]["detected_mime"] is None
