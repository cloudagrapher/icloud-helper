"""Tests for the save_message_pdf MCP tool (icloud_helper.mcp_server).

Mirrors the get_attachment test conventions in test_mcp_server.py: IMAP is
always mocked, no real network calls are made. Requires the mcp package
(skipped automatically otherwise, same as test_mcp_server.py).
"""
from __future__ import annotations

import email.mime.application
import email.mime.multipart
import email.mime.text
from contextlib import contextmanager
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

pytest.importorskip(
    "mcp.server.fastmcp",
    reason="mcp requires Python >=3.10; run with .venv-mcp for these tests",
)


# ---------------------------------------------------------------------------
# Message builders
# ---------------------------------------------------------------------------


def _html_message() -> bytes:
    """A simple multipart/alternative message with a text/html body."""
    msg = email.mime.multipart.MIMEMultipart("alternative")
    msg.attach(email.mime.text.MIMEText("Receipt (plain)", "plain", "utf-8"))
    msg.attach(
        email.mime.text.MIMEText(
            "<html><body><h1>Receipt</h1><p>Total: $10</p></body></html>",
            "html",
            "utf-8",
        )
    )
    return msg.as_bytes()


def _plain_only_message() -> bytes:
    """A message with only a text/plain body — exercises the fallback path."""
    msg = email.mime.multipart.MIMEMultipart("mixed")
    msg.attach(email.mime.text.MIMEText("Plain-only receipt body", "plain", "utf-8"))
    return msg.as_bytes()


def _attachment_only_message() -> bytes:
    """A message with neither text/plain nor text/html — no_renderable_body."""
    msg = email.mime.multipart.MIMEMultipart("mixed")
    msg.attach(
        email.mime.application.MIMEApplication(b"%PDF-tiny", Name="tiny.pdf")
    )
    return msg.as_bytes()


def _session(mock_imap: MagicMock, uidvalidity: int = 12345):
    """Return a context-manager factory yielding (mock_imap, uidvalidity)."""

    @contextmanager
    def _cm(folder, base):  # pylint: disable=unused-argument
        yield mock_imap, uidvalidity

    return _cm


# ---------------------------------------------------------------------------
# save_to validation (fail-fast, before any IMAP session)
# ---------------------------------------------------------------------------


class TestSaveToValidation:
    """save_to is REQUIRED and must be validated before IMAP is opened."""

    def test_empty_save_to_is_rejected(self) -> None:
        """save_to="" (the default) is required, not optional, for this tool."""
        import icloud_helper.mcp_server as server

        result = server.save_message_pdf(folder="INBOX", uid="1")

        assert result.get("error") == "invalid_save_to"

    def test_path_traversal_save_to_rejected_without_opening_imap(self) -> None:
        """save_to="../../evil.pdf" is rejected before any IMAP session opens."""
        import icloud_helper.mcp_server as server
        from icloud_helper import flagged

        with patch.object(
            flagged, "open_readonly_session", side_effect=AssertionError(
                "IMAP session must not be opened for an invalid save_to"
            ),
        ):
            result = server.save_message_pdf(
                folder="INBOX", uid="1", save_to="../../evil.pdf"
            )

        assert result.get("error") == "invalid_save_to"

    def test_absolute_save_to_rejected(self) -> None:
        """An absolute path save_to is rejected."""
        import icloud_helper.mcp_server as server

        result = server.save_message_pdf(
            folder="INBOX", uid="1", save_to="/etc/passwd"
        )

        assert result.get("error") == "invalid_save_to"

    def test_invalid_folder_rejected_before_save_to_check(self) -> None:
        """An unlisted folder is refused by the outer allowlist gate."""
        import icloud_helper.mcp_server as server

        result = server.save_message_pdf(
            folder="NotAllowed", uid="1", save_to="receipt.pdf"
        )

        assert result.get("error") == "folder_not_allowed"

    def test_invalid_uid_rejected(self) -> None:
        """A non-integer uid is rejected."""
        import icloud_helper.mcp_server as server

        result = server.save_message_pdf(
            folder="INBOX", uid="not-a-number", save_to="receipt.pdf"
        )

        assert result.get("error") == "invalid_uid"


# ---------------------------------------------------------------------------
# IMAP-session-level errors (uidvalidity, uid not found)
# ---------------------------------------------------------------------------


class TestSessionErrors:
    """uidvalidity mismatch and missing UID must mirror get_attachment."""

    def test_uidvalidity_changed(self) -> None:
        """A mismatched uidvalidity token yields uidvalidity_changed."""
        import icloud_helper.mcp_server as server
        from icloud_helper import flagged

        mock_imap = MagicMock()
        with patch.object(
            flagged,
            "open_readonly_session",
            new=_session(mock_imap, uidvalidity=99999),
        ):
            result = server.save_message_pdf(
                folder="INBOX", uid="1", uidvalidity=11111, save_to="receipt.pdf"
            )

        assert result.get("error") == "uidvalidity_changed"
        assert result.get("expected") == 11111
        assert result.get("actual") == 99999

    def test_uid_not_found(self) -> None:
        """fetch_message returning None yields uid_not_found."""
        import icloud_helper.mcp_server as server
        from icloud_helper import flagged

        mock_imap = MagicMock()
        with (
            patch.object(flagged, "open_readonly_session", new=_session(mock_imap)),
            patch.object(flagged, "fetch_message", return_value=None),
        ):
            result = server.save_message_pdf(
                folder="INBOX", uid="9999", save_to="receipt.pdf"
            )

        assert result.get("error") == "uid_not_found"

    def test_message_parse_error_returns_structured_json(self) -> None:
        """A parse failure never escapes as a raw exception."""
        import icloud_helper.mcp_server as server
        from icloud_helper import flagged

        mock_imap = MagicMock()
        with (
            patch.object(flagged, "open_readonly_session", new=_session(mock_imap)),
            patch.object(
                flagged,
                "fetch_message",
                return_value=(b"garbage", "01-Jan-2024 10:00:00 +0000"),
            ),
            patch(
                "icloud_helper.mcp_server.email.message_from_bytes",
                side_effect=ValueError("simulated parse failure"),
            ),
        ):
            result = server.save_message_pdf(
                folder="INBOX", uid="1", save_to="receipt.pdf"
            )

        assert result.get("error") == "message_parse_error"
        assert isinstance(result.get("detail"), str)


# ---------------------------------------------------------------------------
# Body selection
# ---------------------------------------------------------------------------


class TestNoRenderableBody:
    """A message with neither text/html nor text/plain leaves is refused."""

    def test_attachment_only_message_returns_no_renderable_body(self) -> None:
        """An attachment-only message yields no_renderable_body."""
        import icloud_helper.mcp_server as server
        from icloud_helper import flagged

        raw = _attachment_only_message()
        mock_imap = MagicMock()
        with (
            patch.object(flagged, "open_readonly_session", new=_session(mock_imap)),
            patch.object(
                flagged,
                "fetch_message",
                return_value=(raw, "01-Jan-2024 10:00:00 +0000"),
            ),
        ):
            result = server.save_message_pdf(
                folder="INBOX", uid="1", save_to="receipt.pdf"
            )

        assert result.get("error") == "no_renderable_body"


# ---------------------------------------------------------------------------
# weasyprint_unavailable / render_failed / pdf_too_large
# ---------------------------------------------------------------------------


class TestRenderErrorMapping:
    """render_pdf exceptions must map to the documented error keys."""

    def test_weasyprint_unavailable_mapped_cleanly(self) -> None:
        """An ImportError inside render_html_to_pdf surfaces as weasyprint_unavailable."""
        import icloud_helper.mcp_server as server
        from icloud_helper import flagged, render_pdf

        raw = _html_message()
        mock_imap = MagicMock()
        with (
            patch.object(flagged, "open_readonly_session", new=_session(mock_imap)),
            patch.object(
                flagged,
                "fetch_message",
                return_value=(raw, "01-Jan-2024 10:00:00 +0000"),
            ),
            patch.object(
                render_pdf,
                "render_html_to_pdf",
                side_effect=render_pdf.WeasyPrintUnavailableError("no native lib"),
            ),
        ):
            result = server.save_message_pdf(
                folder="INBOX", uid="1", save_to="receipt.pdf"
            )

        assert result.get("error") == "weasyprint_unavailable"

    def test_render_failed_mapped_cleanly(self) -> None:
        """A RenderFailedError surfaces as render_failed."""
        import icloud_helper.mcp_server as server
        from icloud_helper import flagged, render_pdf

        raw = _html_message()
        mock_imap = MagicMock()
        with (
            patch.object(flagged, "open_readonly_session", new=_session(mock_imap)),
            patch.object(
                flagged,
                "fetch_message",
                return_value=(raw, "01-Jan-2024 10:00:00 +0000"),
            ),
            patch.object(
                render_pdf,
                "render_html_to_pdf",
                side_effect=render_pdf.RenderFailedError("boom"),
            ),
        ):
            result = server.save_message_pdf(
                folder="INBOX", uid="1", save_to="receipt.pdf"
            )

        assert result.get("error") == "render_failed"

    def test_pdf_too_large_no_file_written(self, tmp_path: Path) -> None:
        """An oversized rendered PDF is rejected and no file is written."""
        import icloud_helper.mcp_server as server
        from icloud_helper import flagged, render_pdf

        raw = _html_message()
        mock_imap = MagicMock()
        oversized = b"%PDF" + b"X" * (server._config.flagged.max_attachment_bytes + 1)  # pylint: disable=protected-access

        with (
            patch.object(
                server._config.attachments, "downloads_dir", str(tmp_path)  # pylint: disable=protected-access
            ),
            patch.object(flagged, "open_readonly_session", new=_session(mock_imap)),
            patch.object(
                flagged,
                "fetch_message",
                return_value=(raw, "01-Jan-2024 10:00:00 +0000"),
            ),
            patch.object(
                render_pdf, "render_html_to_pdf", return_value=oversized
            ),
        ):
            result = server.save_message_pdf(
                folder="INBOX", uid="1", save_to="receipt.pdf"
            )

        assert result.get("error") == "pdf_too_large"
        assert not any(tmp_path.iterdir()), "no file should be written on overflow"


# ---------------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------------


class TestHappyPath:
    """A well-formed HTML message is rendered and saved successfully."""

    def test_html_message_written_to_disk(self, tmp_path: Path) -> None:
        """html message -> file written; sha256/size_bytes match on-disk bytes."""
        import hashlib

        import icloud_helper.mcp_server as server
        from icloud_helper import flagged

        pytest.importorskip(
            "weasyprint",
            reason="weasyprint is required for the real-render happy path",
        )

        raw = _html_message()
        mock_imap = MagicMock()

        with (
            patch.object(
                server._config.attachments, "downloads_dir", str(tmp_path)  # pylint: disable=protected-access
            ),
            patch.object(flagged, "open_readonly_session", new=_session(mock_imap)),
            patch.object(
                flagged,
                "fetch_message",
                return_value=(raw, "01-Jan-2024 10:00:00 +0000"),
            ),
        ):
            result = server.save_message_pdf(
                folder="INBOX", uid="1", save_to="receipt.pdf"
            )

        assert "error" not in result, f"Unexpected error: {result}"
        assert result["body_source"] == "html"

        saved_path = Path(result["path"])
        assert saved_path.exists()
        on_disk = saved_path.read_bytes()
        assert on_disk.startswith(b"%PDF")
        assert result["size_bytes"] == len(on_disk)
        assert result["sha256"] == hashlib.sha256(on_disk).hexdigest()

    def test_plain_only_message_uses_text_fallback(self, tmp_path: Path) -> None:
        """A plain-only message falls back to body_source=='text-fallback'."""
        import icloud_helper.mcp_server as server
        from icloud_helper import flagged

        pytest.importorskip(
            "weasyprint",
            reason="weasyprint is required for the real-render happy path",
        )

        raw = _plain_only_message()
        mock_imap = MagicMock()

        with (
            patch.object(
                server._config.attachments, "downloads_dir", str(tmp_path)  # pylint: disable=protected-access
            ),
            patch.object(flagged, "open_readonly_session", new=_session(mock_imap)),
            patch.object(
                flagged,
                "fetch_message",
                return_value=(raw, "01-Jan-2024 10:00:00 +0000"),
            ),
        ):
            result = server.save_message_pdf(
                folder="INBOX", uid="1", save_to="receipt.pdf"
            )

        assert "error" not in result, f"Unexpected error: {result}"
        assert result["body_source"] == "text-fallback"
        assert Path(result["path"]).read_bytes().startswith(b"%PDF")
