"""Body-link unsubscribe candidate extraction and landing-page classification.

Phase 1 (read-only, ADR-016): scans a message's MIME leaf parts for anchors
and bare URLs that look like unsubscribe/preferences links, scoring them by
confidence.  Nothing in this phase issues a network request.

Phase 1.5 (gated GET probe, ADR-016): classifies the HTML of a fetched
landing page into a small enum so a caller can decide whether the page is
already a terminal confirmation, a single-click confirm, a multi-field form,
a login wall, a CAPTCHA, an inconclusive JS-rendered shell, or a dead end —
WITHOUT auto-submitting anything. Auto-submission of discovered forms is
explicitly out of scope for this module; see
``mcp_server.probe_unsubscribe_link`` for the read-only GET path this module
supports.

Imports only stdlib and icloud_helper.flagged (for iter_leaf_parts) so this
module stays free of the ``mcp`` dependency, matching flagged.py's
Python-3.9-safe import discipline.
"""
# pylint: disable=too-many-lines
from __future__ import annotations

import dataclasses
import hashlib
import re
import urllib.parse
from email.message import Message
from enum import Enum
from html.parser import HTMLParser
from typing import Dict, List, Optional

from icloud_helper.flagged import iter_leaf_parts

# ---------------------------------------------------------------------------
# Phase 1 — candidate extraction
# ---------------------------------------------------------------------------

# Maximum number of candidates returned by extract_unsubscribe_candidates.
_MAX_CANDIDATES = 10

# Anchor/title/aria-label text signals (case-insensitive).
_TEXT_SIGNAL_RE = re.compile(
    r"unsubscribe"
    r"|opt[\s\-]?out"
    r"|email preferences"
    r"|manage (your )?(subscription|preferences)"
    r"|notification settings"
    r"|stop receiving"
    r"|remove me",
    re.IGNORECASE,
)

# URL host/path/query signals (case-insensitive).  Unbounded substring
# matches on bare "unsub"/"remove" false-positive heavily on unrelated
# URLs (e.g. "remove-background.png", "removed_user_id=5",
# "unsubstantiated-claim", "cart/remove-item") — see ADR-016 code review.
# "unsub" is therefore anchored to a path/query token boundary so it only
# matches when it stands alone as a segment/param name (e.g. "/unsub",
# "unsub_id=", "unsub-token"), not as a substring of an unrelated word.
_URL_SIGNAL_RE = re.compile(
    r"unsubscribe"
    r"|(?<![a-z0-9])unsub(?![a-z0-9])"
    r"|optout"
    r"|opt-out"
    r"|email-preferences"
    r"|manage-prefs"
    r"|list-unsubscribe",
    re.IGNORECASE,
)

# "remove" is only a genuine unsubscribe signal when it co-occurs with
# subscription-ish context (me/email/subscription/newsletter/list) within
# a short window — bare "remove" alone matches too many unrelated URLs
# (image filenames, e-commerce "remove item" links, etc.) to be reliable
# on its own.
_URL_REMOVE_CONTEXT_RE = re.compile(
    r"(?<![a-z0-9])remove(?![a-z0-9])[^a-z0-9]{0,20}"
    r"(?<![a-z0-9])(me|email|subscription|newsletter|list)(?![a-z0-9])"
    r"|(?<![a-z0-9])(me|email|subscription|newsletter|list)(?![a-z0-9])"
    r"[^a-z0-9]{0,20}(?<![a-z0-9])remove(?![a-z0-9])",
    re.IGNORECASE,
)

# mailto subject signal.
_MAILTO_SUBJECT_RE = re.compile(r"unsubscribe", re.IGNORECASE)

# Bare-URL scan for text/plain parts.
_BARE_URL_RE = re.compile(r"https?://[^\s<>\"']+", re.IGNORECASE)

# Window of surrounding characters captured around a bare text/plain URL,
# used only to evaluate the text signal (not returned to callers).
_PLAIN_TEXT_WINDOW = 60


@dataclasses.dataclass
class LinkCandidate:  # pylint: disable=too-many-instance-attributes
    """A single candidate unsubscribe/preferences link found in a message body.

    Attributes:
        url: The raw URL (or mailto: URI) as found in the message.
        scheme: One of "https", "http", or "mailto".
        anchor_text: Visible anchor text (HTML) or surrounding-text window
            (text/plain).  Empty string when unavailable.
        matched_on: Ordered list of signal names that fired, e.g.
            ["anchor_text", "url_path"] or ["mailto_subject"].
        confidence: One of "high", "medium", "low".
        host: Hostname parsed from the URL.  Empty for a mailto: URI with
            no host component.
        url_sha256: SHA-256 hex digest of the full URL/URI string, for
            token-free audit logging (mirrors unsubscribe._safe_target_str).
    """

    url: str
    scheme: str
    anchor_text: str
    matched_on: List[str] = dataclasses.field(default_factory=list)
    confidence: str = "low"
    host: str = ""
    url_sha256: str = ""


def _url_sha256(url: str) -> str:
    """Return the SHA-256 hex digest of a URL string.

    Args:
        url: Full URL or URI string.

    Returns:
        Lowercase hex digest string.
    """
    return hashlib.sha256(url.encode("utf-8", errors="replace")).hexdigest()


def _normalize_url(url: str) -> str:
    """Return a normalized form of a URL for dedupe comparison.

    Lowercases the scheme and host, strips a trailing slash from an
    otherwise-empty path, and leaves the query string untouched (query
    strings routinely carry per-recipient tokens that are NOT safe to drop
    when comparing whether two links are "the same" link).

    Args:
        url: Raw URL or URI string.

    Returns:
        Normalized string suitable as a dedupe key.
    """
    parsed = urllib.parse.urlsplit(url)
    scheme = parsed.scheme.lower()
    netloc = parsed.netloc.lower()
    path = parsed.path or ""
    return urllib.parse.urlunsplit(
        (scheme, netloc, path, parsed.query, "")
    )


def _classify_scheme(url: str) -> Optional[str]:
    """Return "https", "http", or "mailto" for a URL, or None if unsupported.

    Args:
        url: Candidate URL or URI string.

    Returns:
        Scheme label, or None when the scheme is not one we surface.
    """
    scheme = urllib.parse.urlsplit(url).scheme.lower()
    if scheme in ("https", "http", "mailto"):
        return scheme
    return None


def _score_text_signals(*texts: str) -> bool:
    """Return True if any of the given texts match the unsubscribe phrase set.

    Args:
        *texts: Candidate text strings (anchor text, title, aria-label).

    Returns:
        True when at least one non-empty text matches _TEXT_SIGNAL_RE.
    """
    return any(t and _TEXT_SIGNAL_RE.search(t) for t in texts)


def _score_url_signal(url: str) -> bool:
    """Return True if the URL's host/path/query matches the unsubscribe pattern.

    "remove" alone is deliberately excluded from _URL_SIGNAL_RE (too many
    unrelated false positives — see module comment above
    _URL_REMOVE_CONTEXT_RE); it only counts as a signal when it co-occurs
    with subscription-ish context in the same haystack.

    Args:
        url: Candidate URL string.

    Returns:
        True when host, path, or query matches _URL_SIGNAL_RE, or matches
        the contextual "remove ... subscription-ish-word" pattern.
    """
    parsed = urllib.parse.urlsplit(url)
    haystack = f"{parsed.netloc}{parsed.path}?{parsed.query}"
    return bool(
        _URL_SIGNAL_RE.search(haystack)
        or _URL_REMOVE_CONTEXT_RE.search(haystack)
    )


def _confidence_for(matched_on: List[str]) -> str:
    """Compute a confidence label from the set of matched signal names.

    high: an explicit anchor/title/aria-label text match AND a corroborating
    URL-pattern match.
    medium: exactly one strong signal (text OR url).
    low: only a weak/incidental signal (e.g. mailto_subject alone).

    Args:
        matched_on: List of signal names that fired for this candidate.

    Returns:
        "high", "medium", or "low".
    """
    has_text = "anchor_text" in matched_on
    has_url = "url_path" in matched_on
    has_mailto_subject = "mailto_subject" in matched_on

    if has_text and has_url:
        return "high"
    if has_text or has_url:
        return "medium"
    if has_mailto_subject:
        return "low"
    return "low"


class _AnchorCollector(HTMLParser):
    """Collect ``<a>`` tag href/text/title/aria-label from HTML.

    Anchors do not legally nest in HTML, but real-world (malformed)
    marketing email HTML sometimes opens a new ``<a>`` before closing the
    previous one, or never closes the last ``<a>`` on the page at all. A
    stack is used (rather than a single pending-anchor slot) so an outer
    anchor is never silently overwritten/dropped when this happens; any
    anchors still open at end-of-document are flushed in ``close()``.

    Attributes:
        anchors: List of dicts with keys href, text, title, aria_label,
            in document order (nested/unclosed anchors are flushed in the
            order they were opened).
    """

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.anchors: List[Dict[str, str]] = []
        self._stack: List[Dict[str, str]] = []

    def handle_starttag(self, tag: str, attrs: list) -> None:
        """Open a new anchor record on ``<a href=...>``.

        Args:
            tag: HTML tag name (lowercased by HTMLParser).
            attrs: List of (name, value) attribute pairs.
        """
        if tag.lower() != "a":
            return
        attr_map = {k.lower(): (v or "") for k, v in attrs}
        href = attr_map.get("href", "")
        if not href:
            return
        self._stack.append(
            {
                "href": href,
                "text": "",
                "title": attr_map.get("title", ""),
                "aria_label": attr_map.get("aria-label", ""),
            }
        )

    def handle_data(self, data: str) -> None:
        """Accumulate visible text inside every currently-open anchor.

        Args:
            data: Text node content.
        """
        for anchor in self._stack:
            anchor["text"] += data

    def handle_endtag(self, tag: str) -> None:
        """Close the innermost still-open anchor on ``</a>``.

        Args:
            tag: HTML tag name (lowercased by HTMLParser).
        """
        if tag.lower() != "a" or not self._stack:
            return
        self._flush_one(self._stack.pop())

    def _flush_one(self, anchor: Dict[str, str]) -> None:
        """Normalize whitespace and append one anchor to ``self.anchors``.

        Args:
            anchor: The anchor record being closed/flushed.
        """
        anchor["text"] = re.sub(r"\s+", " ", anchor["text"]).strip()
        self.anchors.append(anchor)

    def close(self) -> None:
        """Flush any anchors still open at end-of-document, then close.

        A trailing unclosed ``<a>`` (no matching ``</a>``) must not be
        silently dropped — this is common in malformed marketing HTML.
        """
        while self._stack:
            self._flush_one(self._stack.pop(0))
        super().close()

    def error(self, message: str) -> None:
        """Silently absorb HTML parse errors (matches _HTMLTextExtractor).

        Args:
            message: Error description from the parser.
        """


def _candidate_from_href(
    href: str,
    anchor_text: str,
    title: str,
    aria_label: str,
) -> Optional[LinkCandidate]:
    """Build a LinkCandidate from an anchor's href + text signals, if eligible.

    Args:
        href: Raw href attribute value.
        anchor_text: Visible text inside the anchor.
        title: title="" attribute value.
        aria_label: aria-label="" attribute value.

    Returns:
        A LinkCandidate, or None when the href's scheme is not supported.
    """
    scheme = _classify_scheme(href)
    if scheme is None:
        return None

    matched_on: List[str] = []
    if _score_text_signals(anchor_text, title, aria_label):
        matched_on.append("anchor_text")
    if _score_url_signal(href):
        matched_on.append("url_path")
    if scheme == "mailto":
        query = urllib.parse.urlsplit(href).query
        params = urllib.parse.parse_qs(query)
        subject_values = params.get("subject", [])
        if any(_MAILTO_SUBJECT_RE.search(v) for v in subject_values):
            matched_on.append("mailto_subject")

    if not matched_on:
        return None

    parsed = urllib.parse.urlsplit(href)
    display_text = anchor_text or title or aria_label
    return LinkCandidate(
        url=href,
        scheme=scheme,
        anchor_text=display_text,
        matched_on=matched_on,
        confidence=_confidence_for(matched_on),
        host=parsed.hostname or "",
        url_sha256=_url_sha256(href),
    )


def _candidates_from_html_part(part: Message) -> List[LinkCandidate]:
    """Extract LinkCandidates from a single text/html leaf part.

    Args:
        part: A text/html MIME leaf part.

    Returns:
        List of LinkCandidate objects found in this part, in document order.
    """
    raw = part.get_payload(decode=True) or b""
    charset = part.get_content_charset() or "utf-8"
    try:
        html_source = raw.decode(charset, errors="replace")
    except LookupError:
        html_source = raw.decode("utf-8", errors="replace")

    collector = _AnchorCollector()
    collector.feed(html_source)
    collector.close()

    results: List[LinkCandidate] = []
    for anchor in collector.anchors:
        candidate = _candidate_from_href(
            anchor["href"],
            anchor["text"],
            anchor["title"],
            anchor["aria_label"],
        )
        if candidate is not None:
            results.append(candidate)
    return results


def _candidates_from_plain_part(part: Message) -> List[LinkCandidate]:
    """Extract LinkCandidates from bare URLs in a single text/plain leaf part.

    Args:
        part: A text/plain MIME leaf part.

    Returns:
        List of LinkCandidate objects found in this part, in document order.
    """
    raw = part.get_payload(decode=True) or b""
    charset = part.get_content_charset() or "utf-8"
    try:
        text = raw.decode(charset, errors="replace")
    except LookupError:
        text = raw.decode("utf-8", errors="replace")

    results: List[LinkCandidate] = []
    for match in _BARE_URL_RE.finditer(text):
        url = match.group(0).rstrip(").,;'\"")
        scheme = _classify_scheme(url)
        if scheme is None:
            continue

        start = max(0, match.start() - _PLAIN_TEXT_WINDOW)
        end = min(len(text), match.end() + _PLAIN_TEXT_WINDOW)
        window = re.sub(r"\s+", " ", text[start:end]).strip()

        matched_on: List[str] = []
        if _score_text_signals(window):
            matched_on.append("anchor_text")
        if _score_url_signal(url):
            matched_on.append("url_path")
        if not matched_on:
            continue

        parsed = urllib.parse.urlsplit(url)
        results.append(
            LinkCandidate(
                url=url,
                scheme=scheme,
                anchor_text=window,
                matched_on=matched_on,
                confidence=_confidence_for(matched_on),
                host=parsed.hostname or "",
                url_sha256=_url_sha256(url),
            )
        )
    return results


_CONFIDENCE_RANK = {"high": 0, "medium": 1, "low": 2}


def extract_unsubscribe_candidates(msg: Message) -> List[LinkCandidate]:
    """Scan a parsed message for unsubscribe/preferences link candidates.

    Walks every leaf part in document order (``iter_leaf_parts``).  HTML
    parts are scanned for ``<a>`` tags via ``_AnchorCollector``; text/plain
    parts are scanned for bare URLs with a small surrounding-text window
    used only to evaluate the text signal.  Candidates are deduplicated on
    a normalized URL (scheme+host+path+query, fragment stripped) and capped
    at the top 10, sorted by confidence (high, medium, low) then by
    document order.

    This function performs NO network I/O.

    Args:
        msg: Parsed email.message.Message object.

    Returns:
        List of LinkCandidate, sorted by confidence then document order,
        capped at 10 entries.
    """
    all_candidates: List[LinkCandidate] = []
    for part in iter_leaf_parts(msg):
        content_type = part.get_content_type()
        disposition = (part.get_content_disposition() or "").lower()
        if disposition == "attachment":
            continue
        if content_type == "text/html":
            all_candidates.extend(_candidates_from_html_part(part))
        elif content_type == "text/plain":
            all_candidates.extend(_candidates_from_plain_part(part))

    seen: Dict[str, int] = {}
    deduped: List[LinkCandidate] = []
    for candidate in all_candidates:
        key = _normalize_url(candidate.url)
        if key in seen:
            continue
        seen[key] = len(deduped)
        deduped.append(candidate)

    ranked = sorted(
        enumerate(deduped),
        key=lambda pair: (_CONFIDENCE_RANK.get(pair[1].confidence, 3), pair[0]),
    )
    return [candidate for _, candidate in ranked[:_MAX_CANDIDATES]]


# ---------------------------------------------------------------------------
# Phase 1.5 — landing-page classification
# ---------------------------------------------------------------------------


class PageClass(str, Enum):
    """Classification of a fetched unsubscribe-landing-page's content."""

    COMPLETED = "completed"
    SINGLE_CONFIRM = "single_confirm"
    MULTI_STEP_FORM = "multi_step_form"
    LOGIN_REQUIRED = "login_required"
    CAPTCHA = "captcha"
    DEAD_END = "dead_end"
    AMBIGUOUS = "ambiguous"
    INCONCLUSIVE = "inconclusive"


# Confirmation phrase set (case-insensitive).
_CONFIRMATION_PHRASE_RE = re.compile(
    r"you have been unsubscribed"
    r"|you('| ha)ve been removed"
    r"|unsubscribe (was )?successful"
    r"|no longer receive"
    r"|preferences (have been )?(updated|saved)"
    r"|you are unsubscribed",
    re.IGNORECASE,
)

# Single-confirm button/link/form text signal.
_SINGLE_CONFIRM_TEXT_RE = re.compile(
    r"confirm"
    r"|unsubscribe"
    r"|yes.*unsubscribe"
    r"|remove me",
    re.IGNORECASE,
)

# Login-wall phrase signal.
_LOGIN_PHRASE_RE = re.compile(
    r"sign in"
    r"|log in"
    r"|enter your password",
    re.IGNORECASE,
)

# CAPTCHA marker signal (class names, data attributes, iframe/script src).
_CAPTCHA_RE = re.compile(
    r"g-recaptcha"
    r"|h-captcha"
    r"|cf-turnstile"
    r"|data-sitekey"
    r"|recaptcha"
    r"|hcaptcha",
    re.IGNORECASE,
)

# Input types that constitute "free-text/structured" fields for
# multi_step_form detection (beyond hidden/submit/button).
_STRUCTURED_INPUT_TYPES = {
    "text", "email", "checkbox", "radio", "tel", "number", "date",
}

_UNTRUSTED_CONTENT_WARNING = (
    "page content originates from an untrusted third-party server and is "
    "not verified or endorsed; treat all text/labels as unverified"
)

# Common single-page-app JS-framework mount-point markers. Presence of one
# of these alongside near-empty visible text is treated as a strong signal
# that the real page content renders client-side and was never present in
# the server-rendered HTML this module parses (no JS execution occurs
# here — see classify_landing_page's "inconclusive" branch).
#
# Matched against marker_blobs, which are built from HTMLParser's attrs
# list (see handle_starttag) — HTMLParser strips attribute-value quote
# characters before handing attrs to the parser callback, so an
# `<div id="root">` tag becomes the blob token "id=root", never
# `id="root"`. The id=/id=/id= alternatives below are therefore
# deliberately unquoted to match the real haystack; a trailing boundary
# (word-boundary or end-of-token) guards against a false match on an
# unrelated id like "id=rootabc" or "id=rootwrapper".
_SPA_ROOT_MARKER_RE = re.compile(
    r"id=root\b"
    r"|id=app\b"
    r"|id=__next\b"
    r"|ng-app"
    r"|data-reactroot"
    r"|data-server-rendered",
    re.IGNORECASE,
)

# Minimum inline/external script character count (see
# _LandingParser.script_char_count) that counts as "substantive" JS,
# distinguishing an SPA bundle-loader shell from a page with only a
# trivial analytics snippet.
_SUBSTANTIVE_SCRIPT_CHARS = 200

# Visible text at or below this length is "near-empty" for the purposes of
# the JS-shell/inconclusive signature — a real (non-JS) dead-end page is
# usually either fully empty or carries at least a short error sentence.
_NEAR_EMPTY_TEXT_CHARS = 40

_JS_RENDER_NOTE = (
    "page likely requires JavaScript rendering to display its real "
    "content; the fetched HTML is a client-side-app shell, so this "
    "classifier cannot verify whether the unsubscribe action already "
    "completed server-side"
)

# Cap applied to the excerpt as a defence-in-depth backstop even if a
# caller passes an oversized probe_excerpt_bytes.
_EXCERPT_HARD_CAP_BYTES = 65536


@dataclasses.dataclass
class FormField:
    """A single form input/select/textarea discovered on a landing page.

    Attributes:
        name: The field's name="" attribute (empty string if absent).
        field_type: The input type="" (lowercased), or "select"/"textarea"
            for those elements.
        value: The value="" attribute for hidden fields (empty otherwise).
    """

    name: str
    field_type: str
    value: str = ""


@dataclasses.dataclass
class NextActionEgress:
    """Egress-policy verdict for a NextAction's action_url.

    Surfaced explicitly (rather than silently checked-and-discarded) so a
    future caller (e.g. a Phase 2 submit step) can see up front whether
    action_url would pass egress, instead of having to re-derive it or
    risk acting on a URL that was never actually cleared.

    Attributes:
        allowed: Whether egress_check_fn permitted this URL.
        block_class: Taxonomy tag when blocked/deferred (e.g.
            "pending_review", "hard_block"), None when allowed.
        detail: Human-readable reason string from the egress verdict.
    """

    allowed: bool
    block_class: Optional[str] = None
    detail: str = ""


@dataclasses.dataclass
class NextAction:
    """A proposed (but NOT auto-submitted) next step for a landing page.

    Attributes:
        type: Always "form_submit" for now.
        action_url: Absolute URL the form would submit to (urljoin'd against
            final_url). See action_url_egress for whether it would pass
            egress — this field itself is not a safety guarantee.
        method: HTTP method the form declares ("get" or "post", lowercased).
        required_fields: Names of non-hidden fields the form declares.
        hidden_fields: Names of hidden fields the form declares.
        submit_label: Visible text of the submit control, if any.
        action_url_egress: Egress verdict for action_url, or None when no
            egress_check_fn was supplied to the classifier.
    """

    type: str
    action_url: str
    method: str
    required_fields: List[str] = dataclasses.field(default_factory=list)
    hidden_fields: List[str] = dataclasses.field(default_factory=list)
    submit_label: str = ""
    action_url_egress: Optional[NextActionEgress] = None


@dataclasses.dataclass
class LandingClassification:  # pylint: disable=too-many-instance-attributes
    """Result of classifying a fetched unsubscribe-landing page.

    Attributes:
        page_class: One of the PageClass enum values.
        final_url_host: Hostname of the final (post-redirect) URL.
        http_status: HTTP status code of the final response.
        confirmation_phrases_found: List of confirmation phrases matched.
        next_action: Optional[NextAction] — present only for single_confirm
            and multi_step_form when a form was found; otherwise None.
        page_text_excerpt: Script/style/comment-stripped visible text,
            capped at the configured excerpt size.
        warnings: List of caller-facing warnings; always includes an
            untrusted-content notice.
    """

    page_class: str
    final_url_host: str
    http_status: Optional[int]
    confirmation_phrases_found: List[str] = dataclasses.field(
        default_factory=list
    )
    next_action: Optional[NextAction] = None
    page_text_excerpt: str = ""
    warnings: List[str] = dataclasses.field(default_factory=list)


class _LandingParser(HTMLParser):  # pylint: disable=too-many-instance-attributes
    """Collect forms, inputs, buttons, selects, iframes/scripts, and text.

    ``<form>`` tags do not legally nest, but malformed-but-common marketing
    HTML sometimes opens a new ``<form>`` before closing the previous one
    (or never closes the last form on the page). A stack of pending forms
    is used — rather than a single pending-form slot — so an outer form's
    hidden token fields are never silently overwritten/dropped; any forms
    still open at end-of-document are flushed in ``close()``. The same
    applies to standalone (non-form) ``<a>``/``<button>`` elements, tracked
    separately so single_confirm classification (see classify_landing_page)
    can anchor a phrase match to an actual actionable element rather than
    to arbitrary page prose.

    Attributes:
        forms: List of dicts with keys action, method, fields (list of
            FormField), submit_label.
        standalone_actionables: List of visible-text strings from
            top-level (non-form) ``<a>`` and ``<button>`` elements — the
            only elements whose own text is eligible for single_confirm
            phrase matching.
        iframe_srcs: List of iframe src="" values.
        script_srcs: List of script src="" values.
        marker_blobs: List of raw attribute-value strings from every tag,
            used for the CAPTCHA class/data-attribute scan.
        text_parts: List of visible text fragments (script/style/comment
            content excluded).
        script_char_count: Total character count of inline ``<script>``
            body content, used only to distinguish a JS-SPA bundle-loader
            shell from a page with a trivial analytics snippet (see
            classify_landing_page's "inconclusive" branch).
        saw_spa_root_marker: True if any tag's attributes matched a known
            SPA framework mount-point signature (e.g. ``id="root"``,
            ``data-reactroot``).
    """

    _VOID_SKIP_TAGS = ("script", "style")

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.forms: List[Dict] = []
        self.standalone_actionables: List[str] = []
        self.iframe_srcs: List[str] = []
        self.script_srcs: List[str] = []
        self.marker_blobs: List[str] = []
        self.text_parts: List[str] = []
        self.script_char_count = 0
        self.saw_spa_root_marker = False
        self._form_stack: List[Dict] = []
        self._button_capture_stack: List[List[str]] = []
        self._standalone_anchor_capture: Optional[List[str]] = None
        self._skip_depth = 0
        self._in_script_depth = 0

    @property
    def _current_form(self) -> Optional[Dict]:
        """Return the innermost still-open form, or None."""
        if not self._form_stack:
            return None
        return self._form_stack[-1]

    def _start_form(self, attr_map: Dict[str, str]) -> None:
        """Open a new form record on ``<form action method>``.

        Args:
            attr_map: Lowercased attribute-name to value mapping.
        """
        self._form_stack.append(
            {
                "action": attr_map.get("action", ""),
                "method": (attr_map.get("method", "get") or "get").lower(),
                "fields": [],
                "submit_label": "",
            }
        )

    def _add_input_field(self, attr_map: Dict[str, str]) -> None:
        """Append an ``<input>`` field to the innermost open form.

        Args:
            attr_map: Lowercased attribute-name to value mapping.
        """
        form = self._current_form
        if form is None:
            return
        field_type = (attr_map.get("type", "text") or "text").lower()
        form["fields"].append(
            FormField(
                name=attr_map.get("name", ""),
                field_type=field_type,
                value=attr_map.get("value", ""),
            )
        )
        if field_type in ("submit", "button"):
            label = attr_map.get("value", "")
            if label:
                form["submit_label"] = label

    def _add_select_field(self, attr_map: Dict[str, str]) -> None:
        """Append a ``<select>`` field to the innermost open form.

        Args:
            attr_map: Lowercased attribute-name to value mapping.
        """
        form = self._current_form
        if form is None:
            return
        form["fields"].append(
            FormField(name=attr_map.get("name", ""), field_type="select")
        )

    def _add_textarea_field(self, attr_map: Dict[str, str]) -> None:
        """Append a ``<textarea>`` field to the innermost open form.

        Args:
            attr_map: Lowercased attribute-name to value mapping.
        """
        form = self._current_form
        if form is None:
            return
        form["fields"].append(
            FormField(name=attr_map.get("name", ""), field_type="textarea")
        )

    def _start_button_capture(self, attr_map: Dict[str, str]) -> None:
        """Begin capturing visible text inside a ``<button>``.

        Tracked whether or not a form is open: a button inside a form
        contributes to that form's submit_label; a standalone button (no
        open form) is recorded as a standalone actionable element.

        Args:
            attr_map: Lowercased attribute-name to value mapping (unused;
                present for handler-signature symmetry).
        """
        del attr_map
        self._button_capture_stack.append([])

    def _start_anchor_capture(self, attr_map: Dict[str, str]) -> None:
        """Begin capturing visible text inside a top-level ``<a>``.

        Only anchors outside any form are tracked here — form-embedded
        anchors are rare and not relevant to single_confirm classification.

        Args:
            attr_map: Lowercased attribute-name to value mapping (unused;
                present for handler-signature symmetry).
        """
        del attr_map
        if self._current_form is None:
            self._standalone_anchor_capture = []

    def _record_iframe_src(self, attr_map: Dict[str, str]) -> None:
        """Record an ``<iframe src>`` for the CAPTCHA/embed marker scan.

        Args:
            attr_map: Lowercased attribute-name to value mapping.
        """
        src = attr_map.get("src", "")
        if src:
            self.iframe_srcs.append(src)

    def _record_script_src(self, attr_map: Dict[str, str]) -> None:
        """Record a ``<script src>`` for the CAPTCHA/embed marker scan.

        Args:
            attr_map: Lowercased attribute-name to value mapping.
        """
        src = attr_map.get("src", "")
        if src:
            self.script_srcs.append(src)

    def handle_starttag(self, tag: str, attrs: list) -> None:
        """Track form/input/button/select/iframe/script structure.

        Args:
            tag: HTML tag name (lowercased by HTMLParser).
            attrs: List of (name, value) attribute pairs.
        """
        tag = tag.lower()
        attr_map = {k.lower(): (v or "") for k, v in attrs}
        blob = " ".join(f"{k}={v}" for k, v in attr_map.items())
        self.marker_blobs.append(blob)
        if not self.saw_spa_root_marker and _SPA_ROOT_MARKER_RE.search(blob):
            self.saw_spa_root_marker = True

        if tag in self._VOID_SKIP_TAGS:
            self._skip_depth += 1
            if tag == "script":
                self._in_script_depth += 1
            return

        handlers = {
            "form": self._start_form,
            "input": self._add_input_field,
            "select": self._add_select_field,
            "textarea": self._add_textarea_field,
            "button": self._start_button_capture,
            "a": self._start_anchor_capture,
            "iframe": self._record_iframe_src,
            "script": self._record_script_src,
        }
        handler = handlers.get(tag)
        if handler is not None:
            handler(attr_map)

    def _end_button(self) -> None:
        """Close the innermost open ``<button>`` capture on ``</button>``."""
        if not self._button_capture_stack:
            return
        label = "".join(self._button_capture_stack.pop()).strip()
        if not label:
            return
        form = self._current_form
        if form is not None:
            form["submit_label"] = label
        else:
            self.standalone_actionables.append(label)

    def _end_anchor(self) -> None:
        """Close a top-level ``<a>`` capture on ``</a>``."""
        if self._standalone_anchor_capture is None:
            return
        label = "".join(self._standalone_anchor_capture).strip()
        if label:
            self.standalone_actionables.append(label)
        self._standalone_anchor_capture = None

    def _end_form(self) -> None:
        """Flush the innermost still-open form on ``</form>``."""
        if not self._form_stack:
            return
        self.forms.append(self._form_stack.pop())

    def handle_endtag(self, tag: str) -> None:
        """Close form/button/anchor tracking and script/style skip regions.

        Args:
            tag: HTML tag name (lowercased by HTMLParser).
        """
        tag = tag.lower()
        if tag in self._VOID_SKIP_TAGS:
            self._skip_depth = max(0, self._skip_depth - 1)
            if tag == "script":
                self._in_script_depth = max(0, self._in_script_depth - 1)
            return

        end_handlers = {
            "button": self._end_button,
            "a": self._end_anchor,
            "form": self._end_form,
        }
        handler = end_handlers.get(tag)
        if handler is not None:
            handler()

    def handle_data(self, data: str) -> None:
        """Collect visible text, dropping script/style content.

        Args:
            data: Text node content.
        """
        if self._in_script_depth > 0:
            self.script_char_count += len(data)
        if self._button_capture_stack:
            self._button_capture_stack[-1].append(data)
        if self._standalone_anchor_capture is not None:
            self._standalone_anchor_capture.append(data)
        if self._skip_depth == 0:
            self.text_parts.append(data)

    def handle_comment(self, data: str) -> None:
        """Ignore HTML comments entirely (excerpt exclusion).

        Args:
            data: Comment text (unused — comments are stripped).
        """

    def error(self, message: str) -> None:
        """Silently absorb HTML parse errors.

        Args:
            message: Error description from the parser.
        """

    def close(self) -> None:
        """Flush any forms/anchors/buttons still open at end-of-document.

        Malformed-but-common marketing HTML sometimes never closes its
        last ``<form>``/``<a>``/``<button>`` — without this, that trailing
        element (which may be the real unsubscribe form) would be silently
        dropped rather than surfaced to the caller.
        """
        super().close()
        while self._form_stack:
            self._end_form()
        self._end_anchor()
        while self._button_capture_stack:
            self._end_button()
        super().close()

    def get_text(self) -> str:
        """Return visible text with collapsed whitespace.

        Returns:
            Plain text string, script/style/comment content excluded.
        """
        raw = "".join(self.text_parts)
        return re.sub(r"\s+", " ", raw).strip()


def _find_confirmation_phrases(text: str) -> List[str]:
    """Return the distinct confirmation phrases found in text.

    Args:
        text: Visible page text.

    Returns:
        List of matched phrase substrings (as they appear in text), in
        order of first occurrence, deduplicated.
    """
    seen: List[str] = []
    for match in _CONFIRMATION_PHRASE_RE.finditer(text):
        value = match.group(0)
        if value not in seen:
            seen.append(value)
    return seen


def _form_has_structured_input(form: Dict) -> bool:
    """Return True if a form has any free-text/email/checkbox/radio/select field.

    Args:
        form: Form dict as produced by _LandingParser (fields: List[FormField]).

    Returns:
        True when at least one field is a "structured" input type or a
        select/textarea element.
    """
    for field in form["fields"]:
        if field.field_type in _STRUCTURED_INPUT_TYPES:
            return True
        if field.field_type in ("select", "textarea"):
            return True
    return False


def _form_matches_unsubscribe_phrase(form: Dict) -> bool:
    """Return True if a form's own submit_label looks unsubscribe-shaped.

    Deliberately checked against the form's OWN submit_label only — never
    against the whole page's visible text — so an unrelated form (e.g. a
    newsletter-signup or site-search box that happens to sit on the same
    page) is never misidentified just because the surrounding page prose
    mentions "unsubscribe" elsewhere.

    Args:
        form: Form dict as produced by _LandingParser.

    Returns:
        True when the form's submit_label matches the confirm/unsubscribe/
        remove-me phrase set.
    """
    return bool(_SINGLE_CONFIRM_TEXT_RE.search(form["submit_label"]))


def _select_unsubscribe_form(forms: List[Dict]) -> Optional[Dict]:
    """Pick the single form among candidates that is the unsubscribe form.

    A landing page can carry multiple forms with a structured (text/email/
    checkbox/etc.) field — a search box, a newsletter re-subscribe widget,
    a feedback form — any of which would be silently (and wrongly) treated
    as the unsubscribe form by naively picking forms[0]. This instead:

    1. If there is exactly one candidate form, it is unambiguous — use it.
    2. If there are multiple, prefer whichever ones have a submit_label
       matching the unsubscribe phrase set. If exactly one such form
       exists, use it.
    3. Otherwise (zero or multiple phrase-matching forms among multiple
       candidates) the choice is genuinely ambiguous — return None so the
       caller can classify the page as ambiguous instead of guessing.

    Args:
        forms: Candidate form dicts (already filtered by the caller to
            whatever population is relevant, e.g. structured_forms).

    Returns:
        The single unambiguous form, or None when no safe choice exists.
    """
    if len(forms) == 1:
        return forms[0]
    if not forms:
        return None
    phrase_matches = [f for f in forms if _form_matches_unsubscribe_phrase(f)]
    if len(phrase_matches) == 1:
        return phrase_matches[0]
    return None


def _looks_like_js_render_shell(parser: "_LandingParser", visible_text: str) -> bool:
    """Return True if the page looks like an unrendered JS-SPA shell.

    A conservative, narrow signature requiring TWO co-occurring signals so
    an ordinary short dead-end page that merely happens to load an
    analytics snippet is never misclassified:

    1. Near-empty visible text — a JS app shell renders nothing server-side
       beyond, at most, a page title/loading spinner.
    2. A recognized SPA framework mount-point marker (React/Next.js/
       Angular-style root div, ``data-reactroot``, etc.) OR a substantive
       inline ``<script>`` payload (a bundle-loader's inline boot code, as
       opposed to a trivial analytics/tag-manager snippet). An external
       ``<script src>`` alone does NOT count — plenty of genuinely dead/
       error pages load a tracking pixel script and nothing else.

    Args:
        parser: The ``_LandingParser`` that already fed the page's HTML.
        visible_text: The parser's collapsed visible-text output.

    Returns:
        True only on a clear JS-shell signature; otherwise False so the
        caller falls back to the existing dead_end/ambiguous logic.
    """
    if len(visible_text) > _NEAR_EMPTY_TEXT_CHARS:
        return False
    has_substantive_script = parser.script_char_count >= _SUBSTANTIVE_SCRIPT_CHARS
    return parser.saw_spa_root_marker or has_substantive_script


def _build_next_action(
    form: Dict, final_url: str, egress_check_fn
) -> Optional[NextAction]:
    """Build a NextAction for a form, validating action_url via egress_check.

    Args:
        form: Form dict as produced by _LandingParser.
        final_url: The final (post-redirect) URL of the landing page, used
            as the base for resolving a relative form action.
        egress_check_fn: Callable(url) -> object with ``allowed`` (bool),
            ``block_class``, and ``detail`` attributes (an EgressVerdict).
            The verdict is threaded into the returned NextAction's
            action_url_egress rather than only checked for its side
            effect, so the caller does not have to blindly trust
            action_url or re-run the check itself.

    Returns:
        NextAction, or None when the form has no usable action URL.
    """
    action_raw = form["action"] or final_url
    action_url = urllib.parse.urljoin(final_url, action_raw)

    action_url_egress = None
    if egress_check_fn is not None:
        verdict = egress_check_fn(action_url)
        if verdict is not None:
            action_url_egress = NextActionEgress(
                allowed=bool(getattr(verdict, "allowed", False)),
                block_class=getattr(verdict, "block_class", None),
                detail=getattr(verdict, "detail", ""),
            )

    required = [
        f.name
        for f in form["fields"]
        if f.field_type not in ("hidden",) and f.name
    ]
    hidden = [
        f.name for f in form["fields"] if f.field_type == "hidden" and f.name
    ]
    return NextAction(
        type="form_submit",
        action_url=action_url,
        method=form["method"],
        required_fields=required,
        hidden_fields=hidden,
        submit_label=form["submit_label"],
        action_url_egress=action_url_egress,
    )


def classify_landing_page(  # pylint: disable=too-many-locals,too-many-branches,too-many-return-statements
    final_url: str,
    status: Optional[int],
    html: str,
    excerpt_bytes: int = 4096,
    egress_check_fn=None,
) -> LandingClassification:
    """Classify a fetched unsubscribe-landing page into a PageClass.

    Never auto-submits any discovered form; ``next_action`` is informational
    only, for a caller/model to review and (in a future phase) act on
    explicitly.

    Signal precedence (first match wins, evaluated in this order so a page
    exhibiting multiple signals resolves predictably):
      1. captcha        — any CAPTCHA marker present.
      2. login_required — a password input or login phrase present.
      3. multi_step_form — a form with a structured (text/email/checkbox/
         radio/select/textarea) field.
      4. completed      — 2xx + confirmation phrase + no actionable form.
      5. single_confirm — exactly one form/button/link matching the
         confirm/unsubscribe/remove phrase set, no structured fields.
      6. inconclusive   — 2xx with no other signal, but a clear JS-SPA
         shell signature (near-empty visible text plus an SPA mount-point
         marker or a substantive inline script) — the real content likely
         renders client-side and was never in the fetched HTML.
      7. dead_end       — 4xx/5xx, or empty/no signal at all.
      8. ambiguous      — none of the above resolve cleanly (e.g. a 2xx page
         with a confirmation phrase AND a leftover actionable form).

    Args:
        final_url: The final (post-redirect) URL of the fetched page.
        status: HTTP status code of the final response, or None.
        html: Raw HTML body of the final response (already bounded by the
            caller's max_capture_bytes).
        excerpt_bytes: Maximum size in bytes of page_text_excerpt.
        egress_check_fn: Optional callable(url) -> EgressVerdict-like
            object (allowed/block_class/detail), invoked on any form
            action_url before it is surfaced in next_action. The verdict
            is threaded into next_action.action_url_egress so the caller
            can see whether action_url would pass egress without having
            to re-run the check itself.

    Returns:
        LandingClassification with page_class, final_url_host, http_status,
        confirmation_phrases_found, next_action, page_text_excerpt, and
        warnings (always including an untrusted-content notice).
    """
    parsed_final = urllib.parse.urlsplit(final_url)
    final_url_host = parsed_final.hostname or ""

    warnings = [_UNTRUSTED_CONTENT_WARNING]

    parser = _LandingParser()
    parser.feed(html or "")
    parser.close()
    visible_text = parser.get_text()

    cap = min(max(excerpt_bytes, 0), _EXCERPT_HARD_CAP_BYTES)
    excerpt_bytes_encoded = visible_text.encode("utf-8", errors="replace")[:cap]
    page_text_excerpt = excerpt_bytes_encoded.decode("utf-8", errors="ignore")

    confirmation_phrases = _find_confirmation_phrases(visible_text)

    marker_haystack = " ".join(parser.marker_blobs) + " " + " ".join(
        parser.iframe_srcs + parser.script_srcs
    )
    has_captcha = bool(_CAPTCHA_RE.search(marker_haystack))

    has_password_input = any(
        f.field_type == "password"
        for form in parser.forms
        for f in form["fields"]
    )
    has_login_phrase = bool(_LOGIN_PHRASE_RE.search(visible_text))

    structured_forms = [f for f in parser.forms if _form_has_structured_input(f)]
    # A form's own submit_label is the only text that anchors it to the
    # single_confirm phrase set — matching against the whole page's
    # visible_text here would let unrelated prose ("please confirm your
    # email" elsewhere on the page) turn an unrelated form into a false
    # single_confirm candidate (see ADR-016 code review, bug 2).
    single_confirm_forms = [
        f
        for f in parser.forms
        if not _form_has_structured_input(f)
        and _SINGLE_CONFIRM_TEXT_RE.search(f["submit_label"])
    ]

    is_error_status = status is not None and (status >= 400)
    is_empty = not html or not html.strip()

    # 1. captcha
    if has_captcha:
        next_action = None
        chosen_form = _select_unsubscribe_form(structured_forms)
        if chosen_form is not None:
            next_action = _build_next_action(
                chosen_form, final_url, egress_check_fn
            )
        return LandingClassification(
            page_class=PageClass.CAPTCHA.value,
            final_url_host=final_url_host,
            http_status=status,
            confirmation_phrases_found=confirmation_phrases,
            next_action=next_action,
            page_text_excerpt=page_text_excerpt,
            warnings=warnings,
        )

    # 2. login_required
    if has_password_input or has_login_phrase:
        return LandingClassification(
            page_class=PageClass.LOGIN_REQUIRED.value,
            final_url_host=final_url_host,
            http_status=status,
            confirmation_phrases_found=confirmation_phrases,
            next_action=None,
            page_text_excerpt=page_text_excerpt,
            warnings=warnings,
        )

    # 3. multi_step_form
    if structured_forms:
        chosen_form = _select_unsubscribe_form(structured_forms)
        if chosen_form is None:
            # Multiple structured-input forms with no way to safely tell
            # which one is the unsubscribe form (e.g. a search box or
            # newsletter-signup widget sharing the page with the real
            # form) — surfacing a next_action here would risk pointing the
            # caller at the wrong endpoint, so this is ambiguous instead.
            page_class = PageClass.AMBIGUOUS.value
            next_action = None
        else:
            next_action = _build_next_action(
                chosen_form, final_url, egress_check_fn
            )
            page_class = PageClass.MULTI_STEP_FORM.value
            if confirmation_phrases and status is not None and status < 300:
                # Conflicting signals: a confirmation phrase alongside a
                # form that still requires structured input.
                page_class = PageClass.AMBIGUOUS.value
        return LandingClassification(
            page_class=page_class,
            final_url_host=final_url_host,
            http_status=status,
            confirmation_phrases_found=confirmation_phrases,
            next_action=next_action,
            page_text_excerpt=page_text_excerpt,
            warnings=warnings,
        )

    # 4. completed
    #
    # status=None (no HTTP status available to the caller) is treated the
    # same as a 2xx here rather than falling through to ambiguous: a clear
    # confirmation phrase with no actionable form left is unambiguous
    # regardless of whether an HTTP status was captured alongside it. Only
    # a *known* error status (>=400, handled by is_error_status below)
    # should override a confirmation phrase.
    no_actionable_form = not parser.forms
    status_not_error = status is None or status < 300
    if status_not_error and confirmation_phrases and no_actionable_form:
        return LandingClassification(
            page_class=PageClass.COMPLETED.value,
            final_url_host=final_url_host,
            http_status=status,
            confirmation_phrases_found=confirmation_phrases,
            next_action=None,
            page_text_excerpt=page_text_excerpt,
            warnings=warnings,
        )

    # 5. single_confirm — exactly one qualifying form/button/link, no
    #    structured fields beyond hidden.
    #
    # Matched against standalone_actionables (the text owned by an actual
    # <a>/<button> element outside any form) rather than the whole page's
    # visible_text — matching the whole page's prose would fire on ordinary
    # sentences ("please confirm your email", "remove me from your cart")
    # that are not attached to any real actionable element (see ADR-016
    # code review, bug 2).
    matching_standalone_links = [
        label
        for label in parser.standalone_actionables
        if _SINGLE_CONFIRM_TEXT_RE.search(label)
    ]
    single_confirm_links = (
        bool(matching_standalone_links)
        and not parser.forms
        and not confirmation_phrases
    )

    total_single_confirm_candidates = len(single_confirm_forms) + (
        1 if single_confirm_links else 0
    )
    if (
        total_single_confirm_candidates == 1
        and not is_error_status
        and not is_empty
    ):
        next_action = None
        if single_confirm_forms:
            next_action = _build_next_action(
                single_confirm_forms[0], final_url, egress_check_fn
            )
        return LandingClassification(
            page_class=PageClass.SINGLE_CONFIRM.value,
            final_url_host=final_url_host,
            http_status=status,
            confirmation_phrases_found=confirmation_phrases,
            next_action=next_action,
            page_text_excerpt=page_text_excerpt,
            warnings=warnings,
        )

    # 6. inconclusive — fetched OK, but no signal because the real content
    #    renders client-side and this classifier never executes JS. This
    #    must be distinguished from a genuine dead_end: a GET against a
    #    JS-SPA unsubscribe endpoint may well have already completed the
    #    unsubscribe server-side (many SPAs perform the mutation on GET and
    #    then render a client-side confirmation) — reporting "dead_end"
    #    here would misleadingly conflate "nothing here" with "we simply
    #    can't see what happened without a browser." Deliberately narrow
    #    and evaluated only when every other signal has already come up
    #    empty, so a page with any real signal (form/phrase/actionable
    #    link) is never reclassified out from under those branches.
    no_signal_at_all = (
        not confirmation_phrases
        and not parser.forms
        and not single_confirm_links
    )
    # Deliberately stricter than the "completed" branch above: completed
    # treats status=None the same as a 2xx (status_not_error), because a
    # clear confirmation phrase is unambiguous on its own. Here there is NO
    # positive content signal at all — status is the ONLY evidence this was
    # a normal fetch rather than a caller that never captured a status, so
    # status=None is intentionally excluded (falls through to dead_end/
    # ambiguous instead) rather than assumed to be a successful 2xx.
    is_success_status = status is not None and 200 <= status < 300
    if (
        is_success_status
        and no_signal_at_all
        and not is_empty
        and _looks_like_js_render_shell(parser, visible_text)
    ):
        return LandingClassification(
            page_class=PageClass.INCONCLUSIVE.value,
            final_url_host=final_url_host,
            http_status=status,
            confirmation_phrases_found=confirmation_phrases,
            next_action=None,
            page_text_excerpt=page_text_excerpt,
            warnings=warnings + [_JS_RENDER_NOTE],
        )

    # 7. dead_end — error status, or no content, or no signal at all.
    if is_error_status or is_empty or no_signal_at_all:
        return LandingClassification(
            page_class=PageClass.DEAD_END.value,
            final_url_host=final_url_host,
            http_status=status,
            confirmation_phrases_found=confirmation_phrases,
            next_action=None,
            page_text_excerpt=page_text_excerpt,
            warnings=warnings,
        )

    # 8. ambiguous — conflicting or otherwise unresolved signals.
    return LandingClassification(
        page_class=PageClass.AMBIGUOUS.value,
        final_url_host=final_url_host,
        http_status=status,
        confirmation_phrases_found=confirmation_phrases,
        next_action=None,
        page_text_excerpt=page_text_excerpt,
        warnings=warnings,
    )
