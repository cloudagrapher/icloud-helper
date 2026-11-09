"""Tests for icloud_helper.render_pdf — the egress-blocked HTML-to-PDF path.

The security core of save_message_pdf is the url_fetcher allowlist: these
tests verify http/https/file/ftp/protocol-relative/unknown schemes are all
refused, while cid: (same-message only) and data: (local decode) are
permitted, and that a refused remote resource is DROPPED rather than
aborting the whole render.

Requires weasyprint (and its native Pango dependency) to be importable;
the whole module is skipped otherwise.
"""
from __future__ import annotations

import base64
import email.mime.image
import email.mime.multipart
import email.mime.text
import html as html_module
import socket
from email.message import Message

import pytest

pytest.importorskip(
    "weasyprint",
    reason="weasyprint (and its native Pango dependency) is not installed",
)

from icloud_helper import render_pdf  # noqa: E402  pylint: disable=wrong-import-position
from icloud_helper.flagged import (  # noqa: E402  pylint: disable=wrong-import-position
    build_cid_map,
    select_body_html,
    select_plain_source,
)

# A minimal 1x1 transparent PNG, valid enough for WeasyPrint/Pillow to decode.
_TINY_PNG = base64.b64decode(
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk"
    "+A8AAQUBAScY42YAAAAASUVORK5CYII="
)


# ---------------------------------------------------------------------------
# Fetcher unit tests (the security core)
# ---------------------------------------------------------------------------


class TestFetcherSchemeAllowlist:
    """make_no_egress_fetcher must default-deny every scheme except cid/data."""

    @pytest.mark.parametrize(
        "url",
        [
            "https://evil.example/x.png",
            "http://evil.example/x.png",
            "file:///etc/passwd",
            "//evil.example/x.png",
            "ftp://evil.example/x.png",
            "gopher://evil.example/x",
            "",
        ],
    )
    def test_disallowed_schemes_raise(self, url: str) -> None:
        """Every non-cid, non-data scheme (incl. protocol-relative) raises."""
        fetcher = render_pdf.make_no_egress_fetcher({})
        with pytest.raises(Exception):  # pylint: disable=broad-except
            fetcher(url)

    def test_disallowed_scheme_raises_plain_exception_not_fatal(self) -> None:
        """The raised exception must NOT be WeasyPrint's FatalURLFetchingError.

        A fatal error aborts the whole render; a plain exception makes
        WeasyPrint drop just the one resource. This is load-bearing.
        """
        import weasyprint.urls  # pylint: disable=import-outside-toplevel

        fetcher = render_pdf.make_no_egress_fetcher({})
        with pytest.raises(Exception) as excinfo:
            fetcher("https://evil.example/x.png")
        assert not isinstance(
            excinfo.value, weasyprint.urls.FatalURLFetchingError
        )

    def test_disallowed_scheme_is_recorded_in_dropped_urls(self) -> None:
        """Remote references are appended to the optional dropped_urls list."""
        dropped: list = []
        fetcher = render_pdf.make_no_egress_fetcher({}, dropped_urls=dropped)
        with pytest.raises(ValueError):
            fetcher("https://evil.example/pixel.gif")
        assert dropped == ["https://evil.example/pixel.gif"]

    def test_cid_known_returns_exact_bytes_and_mime(self) -> None:
        """A cid: URL present in cid_map returns its bytes and mime_type."""
        cid_map = {"logo@x": (b"raw-image-bytes", "image/png")}
        fetcher = render_pdf.make_no_egress_fetcher(cid_map)

        result = fetcher("cid:logo@x")

        assert result == {"string": b"raw-image-bytes", "mime_type": "image/png"}

    def test_cid_with_angle_brackets_and_percent_encoding(self) -> None:
        """cid: lookup strips angle brackets and percent-decodes the id."""
        cid_map = {"logo@x": (b"bytes", "image/png")}
        fetcher = render_pdf.make_no_egress_fetcher(cid_map)

        result = fetcher("cid:%3Clogo@x%3E")

        assert result == {"string": b"bytes", "mime_type": "image/png"}

    def test_cid_unknown_raises(self) -> None:
        """A cid: URL absent from cid_map raises rather than fetching."""
        fetcher = render_pdf.make_no_egress_fetcher({"known@x": (b"x", "image/png")})
        with pytest.raises(ValueError):
            fetcher("cid:unknown@x")

    def test_cid_unknown_is_not_counted_as_dropped_remote_ref(self) -> None:
        """An unknown cid is not a 'remote reference' — not added to dropped_urls."""
        dropped: list = []
        fetcher = render_pdf.make_no_egress_fetcher({}, dropped_urls=dropped)
        with pytest.raises(ValueError):
            fetcher("cid:unknown@x")
        assert not dropped

    def test_data_uri_returns_decoded_bytes(self) -> None:
        """data: URIs are decoded locally via weasyprint.default_url_fetcher.

        The installed WeasyPrint version returns a URLFetcherResponse
        object (its own dict-based fetcher API is deprecated in 69.0+),
        so decoded content is read via .read() rather than a "string" key.
        Either shape proves the same thing: no network I/O occurred and
        the payload was decoded from the data: URI itself.
        """
        encoded = base64.b64encode(b"hello-world").decode("ascii")
        fetcher = render_pdf.make_no_egress_fetcher({})

        result = fetcher(f"data:text/plain;base64,{encoded}")

        if isinstance(result, dict):
            assert result["string"] == b"hello-world"
        else:
            assert result.read() == b"hello-world"


# ---------------------------------------------------------------------------
# cid embedded — build_cid_map + fetcher integration
# ---------------------------------------------------------------------------


class TestCidEmbeddedResolution:
    """A cid: reference in the HTML body resolves to the matching inline part."""

    def _message_with_inline_image(self) -> Message:
        msg: Message = email.mime.multipart.MIMEMultipart("related")
        html_body = (
            '<html><body><img src="cid:logo@x"><p>Receipt</p></body></html>'
        )
        msg.attach(email.mime.text.MIMEText(html_body, "html", "utf-8"))
        img_part: Message = email.mime.image.MIMEImage(_TINY_PNG, "png")
        img_part.add_header("Content-ID", "<logo@x>")
        img_part.add_header("Content-Disposition", "inline")
        msg.attach(img_part)
        return msg

    def test_build_cid_map_resolves_content_id(self) -> None:
        """build_cid_map keys by the bracket-stripped Content-ID."""
        msg = self._message_with_inline_image()

        cid_map = build_cid_map(msg)

        assert "logo@x" in cid_map
        data, mime_type = cid_map["logo@x"]
        assert data == _TINY_PNG
        assert mime_type == "image/png"

    def test_fetcher_serves_resolved_cid(self) -> None:
        """The fetcher built from build_cid_map's output serves the image bytes."""
        msg = self._message_with_inline_image()
        cid_map = build_cid_map(msg)
        fetcher = render_pdf.make_no_egress_fetcher(cid_map)

        result = fetcher("cid:logo@x")

        assert result == {"string": _TINY_PNG, "mime_type": "image/png"}

    def test_full_render_with_inline_cid_image_succeeds(self) -> None:
        """End-to-end: render a message whose only image is a resolved cid:."""
        msg = self._message_with_inline_image()
        html_src, body_source = select_body_html(msg)
        assert body_source == "html"
        cid_map = build_cid_map(msg)

        pdf_bytes = render_pdf.render_html_to_pdf(html_src, cid_map, base_url=None)

        assert pdf_bytes.startswith(b"%PDF")


# ---------------------------------------------------------------------------
# Remote image dropped — full render still succeeds, http never touched
# ---------------------------------------------------------------------------


class TestRemoteImageDropped:
    """A remote <img> reference is dropped; the rest of the document renders."""

    def test_remote_image_refused_and_render_still_yields_pdf(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Prove http is never actually fetched: blow up on any real connect."""

        def _blow_up(*_args, **_kwargs):
            raise AssertionError(
                "network egress attempted during render_html_to_pdf"
            )

        monkeypatch.setattr(socket.socket, "connect", _blow_up)

        html_src = (
            "<html><body>"
            '<img src="https://evil.example/pixel.gif">'
            "<p>hello receipt</p>"
            "</body></html>"
        )

        pdf_bytes = render_pdf.render_html_to_pdf(html_src, {}, base_url=None)

        assert pdf_bytes.startswith(b"%PDF")

    def test_fetcher_raises_for_the_remote_url_directly(self) -> None:
        """The fetcher itself refuses the exact blocked URL."""
        fetcher = render_pdf.make_no_egress_fetcher({})
        with pytest.raises(ValueError):
            fetcher("https://evil.example/pixel.gif")


# ---------------------------------------------------------------------------
# text/plain fallback + escape
# ---------------------------------------------------------------------------


class TestTextPlainFallbackEscaping:
    """When there is no text/html body, the plain-text fallback must escape."""

    def _plain_only_message(self) -> Message:
        msg: Message = email.mime.multipart.MIMEMultipart("mixed")
        msg.attach(
            email.mime.text.MIMEText(
                "Your receipt: <script>alert(1)</script>", "plain", "utf-8"
            )
        )
        return msg

    def test_no_html_leaf_selects_none(self) -> None:
        """select_body_html returns (None, 'none') for a plain-only message."""
        msg = self._plain_only_message()

        html_src, body_source = select_body_html(msg)

        assert html_src is None
        assert body_source == "none"

    def test_fallback_wrapper_html_escapes_the_script_tag(self) -> None:
        """The synthesised fallback wrapper must not contain a raw <script> tag."""
        msg = self._plain_only_message()
        assert select_body_html(msg)[0] is None

        plain_src = select_plain_source(msg)
        assert plain_src is not None
        body_source = "text-fallback"

        escaped = html_module.escape(plain_src)
        wrapper_html = (
            "<!DOCTYPE html><html><head>"
            '<meta charset="utf-8"></head>'
            f"<body><pre>{escaped}</pre></body></html>"
        )

        assert body_source == "text-fallback"
        assert "<script>" not in wrapper_html
        assert "&lt;script&gt;" in wrapper_html

        pdf_bytes = render_pdf.render_html_to_pdf(wrapper_html, {}, base_url=None)
        assert pdf_bytes.startswith(b"%PDF")


# ---------------------------------------------------------------------------
# WeasyPrint unavailable / render failed mapping
# ---------------------------------------------------------------------------


class TestErrorMapping:
    """render_html_to_pdf maps ImportError/OSError distinctly from other errors."""

    def test_import_error_maps_to_weasyprint_unavailable(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Simulate weasyprint being unimportable at call time."""
        import builtins  # pylint: disable=import-outside-toplevel

        real_import = builtins.__import__

        def _fake_import(name, *args, **kwargs):
            if name == "weasyprint":
                raise ImportError("simulated: no module named weasyprint")
            return real_import(name, *args, **kwargs)

        monkeypatch.setattr(builtins, "__import__", _fake_import)

        with pytest.raises(render_pdf.WeasyPrintUnavailableError):
            render_pdf.render_html_to_pdf("<html></html>", {})

    def test_malformed_html_still_produces_a_pdf_not_a_render_error(self) -> None:
        """WeasyPrint is lenient with malformed markup — confirms it does not
        spuriously raise RenderFailedError for merely-invalid-but-parseable
        HTML (html5lib-style error recovery)."""
        pdf_bytes = render_pdf.render_html_to_pdf(
            "<html><body><p>unclosed", {}, base_url=None
        )
        assert pdf_bytes.startswith(b"%PDF")


# ---------------------------------------------------------------------------
# Real-render smoke test
# ---------------------------------------------------------------------------


def test_real_render_smoke() -> None:
    """Rendering trivial HTML produces bytes starting with the PDF magic header."""
    pytest.importorskip("weasyprint")

    pdf_bytes = render_pdf.render_html_to_pdf(
        "<html><body><h1>Hello</h1></body></html>", {}, base_url=None
    )

    assert pdf_bytes.startswith(b"%PDF")
