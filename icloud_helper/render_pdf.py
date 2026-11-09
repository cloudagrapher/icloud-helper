"""In-process HTML-to-PDF rendering for flagged-message receipts.

Renders a message's ORIGINAL HTML to a PDF using WeasyPrint — a pure-Python
renderer with no JavaScript engine, so no script or tracking-pixel code
ever executes. Every external resource load (images, stylesheets, fonts)
funnels through a single ``url_fetcher`` callable, which is the SOLE egress
gate for this feature.

Egress-block design (default-deny, fail-closed)
------------------------------------------------
``make_no_egress_fetcher`` builds a scheme allowlist:

- ``cid:<id>`` — resolved against a Content-ID map built from the SAME
  message being rendered (see ``flagged.build_cid_map``). Unknown ids raise.
- ``data:...`` — delegated to ``weasyprint.default_url_fetcher``, which
  decodes the payload locally. No network I/O is involved.
- Anything else (``http:``, ``https:``, ``file:``, protocol-relative
  ``//host/...``, ``ftp:``, empty/unknown scheme) raises a PLAIN
  ``ValueError``.

The plain-exception choice is deliberate and load-bearing: WeasyPrint
catches a plain exception raised by ``url_fetcher``, drops just that one
resource (rendering a broken-image placeholder), and continues rendering
the rest of the document. Raising
``weasyprint.urls.FatalURLFetchingError`` instead would abort the ENTIRE
render on the first blocked resource, which is not the desired behaviour
here — receipts commonly reference a handful of remote tracking pixels or
CDN-hosted images that we want dropped, not treated as fatal.

Callers MUST also pass ``base_url=None`` to ``weasyprint.HTML(...)`` so
relative URLs in the message HTML cannot resolve to ``file://`` paths on
this machine. The fetcher's scheme allowlist is a backstop against ``file:``
regardless.

This module is the ONLY place that imports weasyprint. The import is
deferred to inside ``render_html_to_pdf`` (mirroring the pypdf
deferred-import pattern in ``attachments.py``) so this module — and any
module that imports it — loads cleanly, and pylint stays clean, even when
the native WeasyPrint/Pango library is not installed on the host.
"""
from __future__ import annotations

import logging
import urllib.parse
from typing import Callable, Dict, List, Optional, Tuple

log = logging.getLogger(__name__)


class RenderError(Exception):
    """Base class for save_message_pdf rendering errors."""


class WeasyPrintUnavailableError(RenderError):
    """Raised when weasyprint (or a native dependency, e.g. Pango) is missing.

    Surfaced by the MCP tool as the ``weasyprint_unavailable`` error.
    """


class RenderFailedError(RenderError):
    """Raised when WeasyPrint itself fails while rendering valid input.

    Surfaced by the MCP tool as the ``render_failed`` error.
    """


def _strip_cid(url: str) -> str:
    """Normalise a ``cid:`` URL to its bare content-id.

    Strips the ``cid:`` scheme prefix, percent-decodes it, and removes any
    surrounding angle brackets (``<...>``) that some senders include in
    the raw ``Content-ID`` header (and therefore in ``cid:`` references to
    it).

    Args:
        url: Raw ``cid:...`` URL as passed to ``url_fetcher`` by WeasyPrint.

    Returns:
        The bare content-id, in the same normalised form as the keys
        produced by ``flagged.build_cid_map``.
    """
    raw = url[len("cid:"):]
    decoded = urllib.parse.unquote(raw)
    return decoded.strip().lstrip("<").rstrip(">")


def make_no_egress_fetcher(
    cid_map: Dict[str, Tuple[bytes, str]],
    dropped_urls: Optional[List[str]] = None,
) -> Callable[[str], dict]:
    """Build a WeasyPrint ``url_fetcher`` that blocks ALL network egress.

    See the module docstring for the full allowlist rationale.

    Args:
        cid_map: Mapping of bracket-stripped Content-ID -> (bytes,
            mime_type), as built by ``flagged.build_cid_map()`` for the
            exact message being rendered. ``cid:`` references are resolved
            ONLY against this map — never across message boundaries.
        dropped_urls: Optional list that this fetcher appends to whenever
            it refuses a remote reference (any scheme other than ``cid:``
            or ``data:``). Callers can inspect ``len(dropped_urls)`` after
            rendering to report how many remote references were dropped.
            Unknown ``cid:`` misses are NOT counted here (they are not
            remote references).

    Returns:
        A callable suitable for ``weasyprint.HTML(url_fetcher=...)``.
    """

    def _fetch(url: str) -> dict:
        parsed = urllib.parse.urlsplit(url)
        scheme = parsed.scheme.lower()

        if scheme == "cid":
            cid = _strip_cid(url)
            if cid not in cid_map:
                raise ValueError(f"blocked: unknown cid reference {cid!r}")
            data, mime_type = cid_map[cid]
            return {"string": data, "mime_type": mime_type}

        if scheme == "data":
            # Decoded entirely locally by weasyprint — no network I/O.
            import weasyprint  # pylint: disable=import-outside-toplevel

            return weasyprint.default_url_fetcher(url)

        # Default-deny: http, https, file, ftp, protocol-relative
        # (//host/...), empty scheme, and anything else not explicitly
        # allowed above. A PLAIN exception (not FatalURLFetchingError) so
        # WeasyPrint drops only this resource and keeps rendering.
        if dropped_urls is not None:
            dropped_urls.append(url)
        raise ValueError(
            f"blocked: egress via {scheme or '(relative)'!r} scheme is "
            "not permitted"
        )

    return _fetch


def render_html_to_pdf(
    html_str: str,
    cid_map: Dict[str, Tuple[bytes, str]],
    base_url: Optional[str] = None,
    dropped_urls: Optional[List[str]] = None,
) -> bytes:
    """Render *html_str* to PDF bytes with all network egress blocked.

    Args:
        html_str: The message's original HTML body (or a synthesised
            text-fallback wrapper built by the caller).
        cid_map: Content-ID -> (bytes, mime_type) map for THIS message,
            built by ``flagged.build_cid_map()``.
        base_url: Passed through to ``weasyprint.HTML``. Callers should
            pass ``None`` (the default) so relative URLs in the message
            cannot resolve to ``file://`` paths; the url_fetcher refuses
            ``file:`` as a backstop regardless.
        dropped_urls: Optional list that collects remote reference URLs
            dropped during rendering (see ``make_no_egress_fetcher``).

    Returns:
        Rendered PDF bytes (always starts with ``b"%PDF"``).

    Raises:
        WeasyPrintUnavailableError: weasyprint, or a native dependency it
            requires (e.g. Pango via cffi), could not be loaded.
        RenderFailedError: WeasyPrint raised while rendering otherwise
            well-formed input.
    """
    try:
        from weasyprint import HTML  # pylint: disable=import-outside-toplevel
    except (ImportError, OSError) as exc:
        # OSError covers cffi/dlopen failures when the native Pango/GObject
        # libraries are missing — practically indistinguishable from "not
        # installed" for our purposes.
        raise WeasyPrintUnavailableError(str(exc)) from exc

    fetcher = make_no_egress_fetcher(cid_map, dropped_urls=dropped_urls)
    try:
        document = HTML(string=html_str, base_url=base_url, url_fetcher=fetcher)
        return document.write_pdf()
    except Exception as exc:  # pylint: disable=broad-except
        raise RenderFailedError(str(exc)) from exc
