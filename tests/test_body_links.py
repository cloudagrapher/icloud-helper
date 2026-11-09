"""Tests for icloud_helper.body_links Phase 1 candidate extraction and
Phase 1.5 landing-page classification.
"""
from __future__ import annotations

import unittest
from email import message_from_bytes

from icloud_helper.body_links import (
    LandingClassification,
    LinkCandidate,
    NextAction,
    PageClass,
    classify_landing_page,
    extract_unsubscribe_candidates,
)


def _msg_html(html_body: str, charset: str = "utf-8") -> object:
    """Build a single-part text/html email.message.Message for testing."""
    raw = (
        b"From: sender@example.com\r\n"
        b"To: me@example.com\r\n"
        b"Subject: test\r\n"
        b"MIME-Version: 1.0\r\n"
        b"Content-Type: text/html; charset=" + charset.encode() + b"\r\n"
        b"\r\n" + html_body.encode(charset)
    )
    return message_from_bytes(raw)


def _msg_plain(text_body: str) -> object:
    """Build a single-part text/plain email.message.Message for testing."""
    raw = (
        b"From: sender@example.com\r\n"
        b"To: me@example.com\r\n"
        b"Subject: test\r\n"
        b"MIME-Version: 1.0\r\n"
        b"Content-Type: text/plain; charset=utf-8\r\n"
        b"\r\n" + text_body.encode("utf-8")
    )
    return message_from_bytes(raw)


def _msg_multipart(html_body: str, plain_body: str) -> object:
    """Build a multipart/alternative message with html + plain parts."""
    boundary = "BOUNDARY123"
    raw = (
        f"From: sender@example.com\r\n"
        f"To: me@example.com\r\n"
        f"Subject: test\r\n"
        f"MIME-Version: 1.0\r\n"
        f'Content-Type: multipart/alternative; boundary="{boundary}"\r\n'
        f"\r\n"
        f"--{boundary}\r\n"
        f"Content-Type: text/plain; charset=utf-8\r\n"
        f"\r\n"
        f"{plain_body}\r\n"
        f"--{boundary}\r\n"
        f"Content-Type: text/html; charset=utf-8\r\n"
        f"\r\n"
        f"{html_body}\r\n"
        f"--{boundary}--\r\n"
    ).encode("utf-8")
    return message_from_bytes(raw)


class TestExtractUnsubscribeCandidatesHtml(unittest.TestCase):
    """HTML anchor-based candidate extraction."""

    def test_explicit_anchor_text_is_high_confidence(self) -> None:
        """An <a>Unsubscribe</a> whose href also matches is high confidence."""
        msg = _msg_html(
            '<html><body><a href="https://x.com/unsubscribe?id=1">'
            "Unsubscribe</a></body></html>"
        )
        candidates = extract_unsubscribe_candidates(msg)
        self.assertEqual(len(candidates), 1)
        candidate = candidates[0]
        self.assertIsInstance(candidate, LinkCandidate)
        self.assertEqual(candidate.confidence, "high")
        self.assertIn("anchor_text", candidate.matched_on)
        self.assertIn("url_path", candidate.matched_on)
        self.assertEqual(candidate.scheme, "https")
        self.assertEqual(candidate.host, "x.com")
        self.assertTrue(candidate.url_sha256)

    def test_manage_preferences_text_only_is_medium_or_low(self) -> None:
        """Weaker anchor text with a non-matching URL is medium confidence."""
        msg = _msg_html(
            '<html><body><a href="https://x.com/prefs?id=1">'
            "manage preferences</a></body></html>"
        )
        candidates = extract_unsubscribe_candidates(msg)
        self.assertEqual(len(candidates), 1)
        self.assertIn(candidates[0].confidence, ("medium", "low"))
        self.assertIn("anchor_text", candidates[0].matched_on)

    def test_mailto_with_unsubscribe_subject(self) -> None:
        """A mailto: href with subject=unsubscribe is a mailto candidate."""
        msg = _msg_html(
            '<html><body><a href="mailto:x@y.com?subject=unsubscribe">'
            "Contact us</a></body></html>"
        )
        candidates = extract_unsubscribe_candidates(msg)
        self.assertEqual(len(candidates), 1)
        self.assertEqual(candidates[0].scheme, "mailto")
        self.assertIn("mailto_subject", candidates[0].matched_on)

    def test_no_candidates_when_no_signal(self) -> None:
        """A message with only unrelated links yields no candidates."""
        msg = _msg_html(
            '<html><body><a href="https://x.com/about">About us</a>'
            '<a href="https://x.com/contact">Contact</a></body></html>'
        )
        candidates = extract_unsubscribe_candidates(msg)
        self.assertEqual(candidates, [])

    def test_ranking_order_high_before_medium(self) -> None:
        """High-confidence candidates sort before medium/low ones."""
        msg = _msg_html(
            "<html><body>"
            '<a href="https://x.com/prefs">manage preferences</a>'
            '<a href="https://x.com/unsubscribe">Unsubscribe</a>'
            "</body></html>"
        )
        candidates = extract_unsubscribe_candidates(msg)
        self.assertEqual(len(candidates), 2)
        self.assertEqual(candidates[0].confidence, "high")
        self.assertIn(candidates[1].confidence, ("medium", "low"))


class TestExtractUnsubscribeCandidatesPlain(unittest.TestCase):
    """Bare-URL scanning in text/plain parts."""

    def test_bare_unsubscribe_url_in_plain_text(self) -> None:
        """A bare https URL with unsubscribe in the path is surfaced."""
        msg = _msg_plain(
            "Hi there,\n\n"
            "To stop receiving these emails, visit "
            "https://x.com/unsubscribe?token=abc123 and confirm.\n"
        )
        candidates = extract_unsubscribe_candidates(msg)
        self.assertEqual(len(candidates), 1)
        self.assertEqual(candidates[0].scheme, "https")
        self.assertIn("unsubscribe", candidates[0].url)

    def test_plain_text_no_signal_yields_no_candidates(self) -> None:
        """A bare URL with no unsubscribe signal is not surfaced."""
        msg = _msg_plain("Check out https://x.com/products for our catalog.\n")
        candidates = extract_unsubscribe_candidates(msg)
        self.assertEqual(candidates, [])


class TestExtractUnsubscribeCandidatesMultipart(unittest.TestCase):
    """Multipart dedupe behaviour."""

    def test_same_link_in_html_and_plain_is_deduped(self) -> None:
        """The same unsubscribe URL in both parts yields one candidate."""
        url = "https://x.com/unsubscribe?id=42"
        msg = _msg_multipart(
            html_body=f'<html><body><a href="{url}">Unsubscribe</a></body></html>',
            plain_body=f"Unsubscribe here: {url}",
        )
        candidates = extract_unsubscribe_candidates(msg)
        self.assertEqual(len(candidates), 1)

    def test_cap_at_ten_candidates(self) -> None:
        """More than 10 distinct candidates are capped at 10."""
        links = "".join(
            f'<a href="https://x.com/unsubscribe?id={i}">Unsubscribe {i}</a>'
            for i in range(15)
        )
        msg = _msg_html(f"<html><body>{links}</body></html>")
        candidates = extract_unsubscribe_candidates(msg)
        self.assertEqual(len(candidates), 10)


class TestClassifyLandingPageCompleted(unittest.TestCase):
    """PageClass.COMPLETED signal rules."""

    def test_confirmation_phrase_2xx_no_form(self) -> None:
        """2xx + confirmation phrase + no form yields completed."""
        html = "<html><body><p>You have been unsubscribed successfully.</p></body></html>"
        result = classify_landing_page("https://x.com/done", 200, html)
        self.assertIsInstance(result, LandingClassification)
        self.assertEqual(result.page_class, PageClass.COMPLETED.value)
        self.assertTrue(result.confirmation_phrases_found)
        self.assertIsNone(result.next_action)


class TestClassifyLandingPageSingleConfirm(unittest.TestCase):
    """PageClass.SINGLE_CONFIRM signal rules."""

    def test_single_confirm_button_no_structured_fields(self) -> None:
        """A form with only a hidden field + confirm button is single_confirm."""
        html = (
            "<html><body>"
            '<form action="/confirm" method="post">'
            '<input type="hidden" name="token" value="abc">'
            "<button>Confirm Unsubscribe</button>"
            "</form></body></html>"
        )
        result = classify_landing_page("https://x.com/step1", 200, html)
        self.assertEqual(result.page_class, PageClass.SINGLE_CONFIRM.value)
        self.assertIsInstance(result.next_action, NextAction)
        self.assertEqual(result.next_action.method, "post")
        self.assertEqual(result.next_action.hidden_fields, ["token"])
        self.assertEqual(result.next_action.required_fields, [])


class TestClassifyLandingPageMultiStepForm(unittest.TestCase):
    """PageClass.MULTI_STEP_FORM signal rules."""

    def test_form_with_email_and_checkbox(self) -> None:
        """A form with email/checkbox inputs is multi_step_form."""
        html = (
            "<html><body>"
            '<form action="/save" method="post">'
            '<input type="email" name="email">'
            '<input type="checkbox" name="promo">'
            "<button>Save preferences</button>"
            "</form></body></html>"
        )
        result = classify_landing_page("https://x.com/prefs", 200, html)
        self.assertEqual(result.page_class, PageClass.MULTI_STEP_FORM.value)
        self.assertIsInstance(result.next_action, NextAction)
        self.assertIn("email", result.next_action.required_fields)
        self.assertIn("promo", result.next_action.required_fields)


class TestClassifyLandingPageLoginRequired(unittest.TestCase):
    """PageClass.LOGIN_REQUIRED signal rules."""

    def test_password_input_triggers_login_required(self) -> None:
        """A password input on the page triggers login_required."""
        html = (
            "<html><body><form>"
            '<input type="password" name="pw">'
            "</form></body></html>"
        )
        result = classify_landing_page("https://x.com/login", 200, html)
        self.assertEqual(result.page_class, PageClass.LOGIN_REQUIRED.value)
        self.assertIsNone(result.next_action)

    def test_login_phrase_without_password_field(self) -> None:
        """A 'sign in' phrase alone also triggers login_required."""
        html = "<html><body><p>Please sign in to manage your account.</p></body></html>"
        result = classify_landing_page("https://x.com/login2", 200, html)
        self.assertEqual(result.page_class, PageClass.LOGIN_REQUIRED.value)


class TestClassifyLandingPageCaptcha(unittest.TestCase):
    """PageClass.CAPTCHA signal rules."""

    def test_recaptcha_marker(self) -> None:
        """A g-recaptcha div triggers captcha classification."""
        html = (
            '<html><body><div class="g-recaptcha" data-sitekey="xyz">'
            "</div></body></html>"
        )
        result = classify_landing_page("https://x.com/captcha", 200, html)
        self.assertEqual(result.page_class, PageClass.CAPTCHA.value)


class TestClassifyLandingPageDeadEnd(unittest.TestCase):
    """PageClass.DEAD_END signal rules."""

    def test_404_status(self) -> None:
        """A 404 response is a dead end."""
        result = classify_landing_page(
            "https://x.com/missing", 404, "<html><body>Not found</body></html>"
        )
        self.assertEqual(result.page_class, PageClass.DEAD_END.value)

    def test_500_status(self) -> None:
        """A 500 response is a dead end."""
        result = classify_landing_page(
            "https://x.com/error", 500, "<html><body>Server error</body></html>"
        )
        self.assertEqual(result.page_class, PageClass.DEAD_END.value)

    def test_empty_body(self) -> None:
        """An empty body with a 2xx status is a dead end."""
        result = classify_landing_page("https://x.com/empty", 200, "")
        self.assertEqual(result.page_class, PageClass.DEAD_END.value)

    def test_no_signal_at_all(self) -> None:
        """A page with unrelated content and no forms is a dead end."""
        html = "<html><body><p>Welcome to our homepage.</p></body></html>"
        result = classify_landing_page("https://x.com/home", 200, html)
        self.assertEqual(result.page_class, PageClass.DEAD_END.value)


class TestClassifyLandingPageAmbiguous(unittest.TestCase):
    """PageClass.AMBIGUOUS signal rules."""

    def test_confirmation_phrase_with_leftover_structured_form(self) -> None:
        """Conflicting signals (confirmation text AND a real form) are ambiguous."""
        html = (
            "<html><body>"
            "<p>Your preferences have been updated.</p>"
            '<form action="/more" method="post">'
            '<input type="email" name="email">'
            "</form></body></html>"
        )
        result = classify_landing_page("https://x.com/mixed", 200, html)
        self.assertEqual(result.page_class, PageClass.AMBIGUOUS.value)


class TestClassifyLandingPageExcerptAndWarnings(unittest.TestCase):
    """Excerpt sizing and untrusted-content warning behaviour."""

    def test_script_and_style_stripped_from_excerpt(self) -> None:
        """<script> and <style> content never appears in page_text_excerpt."""
        html = (
            "<html><head><style>.x{color:red}</style>"
            "<script>alert('should not appear');</script></head>"
            "<body><p>You have been removed from this list.</p></body></html>"
        )
        result = classify_landing_page("https://x.com/done", 200, html)
        self.assertNotIn("alert", result.page_text_excerpt)
        self.assertNotIn("color:red", result.page_text_excerpt)

    def test_excerpt_respects_excerpt_bytes_cap(self) -> None:
        """page_text_excerpt is capped at the requested excerpt_bytes."""
        long_text = "A" * 10000
        html = f"<html><body><p>{long_text}</p></body></html>"
        result = classify_landing_page(
            "https://x.com/long", 200, html, excerpt_bytes=100
        )
        self.assertLessEqual(len(result.page_text_excerpt.encode("utf-8")), 100)

    def test_untrusted_content_warning_always_present(self) -> None:
        """warnings always includes an untrusted-content notice."""
        result = classify_landing_page("https://x.com/any", 200, "<html></html>")
        self.assertTrue(
            any("untrusted" in w.lower() for w in result.warnings)
        )


class TestFormSelectionAmbiguity(unittest.TestCase):
    """ADR-016 code review bug 1: don't blindly pick structured_forms[0].

    A page with multiple structured-input forms (e.g. a search box AND the
    real unsubscribe/preferences form) must not silently point next_action
    at whichever form happened to appear first in the HTML.
    """

    def test_unrelated_search_form_before_real_form_is_still_selected(self) -> None:
        """The unsubscribe-labelled form is chosen even when it isn't first."""
        html = (
            "<html><body>"
            '<form action="/search" method="get">'
            '<input type="text" name="q">'
            "<button>Search</button>"
            "</form>"
            '<form action="/prefs" method="post">'
            '<input type="email" name="email">'
            '<input type="checkbox" name="promo">'
            "<button>Unsubscribe from this list</button>"
            "</form>"
            "</body></html>"
        )
        result = classify_landing_page("https://x.com/mixed-forms", 200, html)
        self.assertEqual(result.page_class, PageClass.MULTI_STEP_FORM.value)
        self.assertIsInstance(result.next_action, NextAction)
        self.assertEqual(result.next_action.action_url, "https://x.com/prefs")

    def test_two_unrelated_structured_forms_no_phrase_match_is_ambiguous(self) -> None:
        """Two candidate forms, neither unsubscribe-labelled, is ambiguous."""
        html = (
            "<html><body>"
            '<form action="/search" method="get">'
            '<input type="text" name="q">'
            "<button>Search</button>"
            "</form>"
            '<form action="/newsletter" method="post">'
            '<input type="email" name="email">'
            "<button>Sign up</button>"
            "</form>"
            "</body></html>"
        )
        result = classify_landing_page("https://x.com/two-forms", 200, html)
        self.assertEqual(result.page_class, PageClass.AMBIGUOUS.value)
        self.assertIsNone(result.next_action)

    def test_single_structured_form_is_unambiguous(self) -> None:
        """Exactly one structured-input form is still selected without a
        phrase match requirement (unchanged single-form behaviour)."""
        html = (
            "<html><body>"
            '<form action="/save" method="post">'
            '<input type="email" name="email">'
            "<button>Save</button>"
            "</form>"
            "</body></html>"
        )
        result = classify_landing_page("https://x.com/one-form", 200, html)
        self.assertEqual(result.page_class, PageClass.MULTI_STEP_FORM.value)
        self.assertIsInstance(result.next_action, NextAction)
        self.assertEqual(result.next_action.action_url, "https://x.com/save")


class TestSingleConfirmAnchoredToRealElement(unittest.TestCase):
    """ADR-016 code review bug 2: single_confirm must not fire on bare prose."""

    def test_confirm_phrase_in_prose_with_no_actionable_element_is_dead_end(self) -> None:
        """Ordinary prose mentioning 'confirm'/'remove me' with no form,
        link, or button is not single_confirm."""
        html = (
            "<html><body>"
            "<p>Please confirm your email address by checking your inbox. "
            "If you would like us to remove me from your cart, contact "
            "support.</p>"
            "</body></html>"
        )
        result = classify_landing_page("https://x.com/prose-only", 200, html)
        self.assertNotEqual(result.page_class, PageClass.SINGLE_CONFIRM.value)
        self.assertIsNone(result.next_action)

    def test_confirm_phrase_on_real_anchor_is_single_confirm(self) -> None:
        """A confirm-phrase-labelled <a> (no form) is still single_confirm."""
        html = (
            "<html><body>"
            "<p>We received your request.</p>"
            '<a href="/confirm-unsub?id=1">Confirm unsubscribe</a>'
            "</body></html>"
        )
        result = classify_landing_page("https://x.com/real-anchor", 200, html)
        self.assertEqual(result.page_class, PageClass.SINGLE_CONFIRM.value)

    def test_confirm_phrase_only_in_page_prose_near_unrelated_anchor(self) -> None:
        """A confirm phrase in page prose does not attach to an unrelated
        anchor's own (non-matching) text."""
        html = (
            "<html><body>"
            "<p>Please confirm your email to continue receiving updates.</p>"
            '<a href="/about">About us</a>'
            "</body></html>"
        )
        result = classify_landing_page("https://x.com/unrelated-anchor", 200, html)
        self.assertNotEqual(result.page_class, PageClass.SINGLE_CONFIRM.value)


class TestMalformedHtmlNestedAndUnclosedTags(unittest.TestCase):
    """ADR-016 code review bug 3: nested/unclosed <a>/<form> must not drop
    the outer element."""

    def test_nested_anchor_outer_href_not_dropped(self) -> None:
        """An <a> opened before the previous one closes still surfaces the
        outer anchor's href/text via extract_unsubscribe_candidates."""
        msg = _msg_html(
            '<html><body><a href="https://x.com/unsubscribe?id=1">'
            "Unsubscribe "
            '<a href="https://x.com/other">here</a>'
            "</a></body></html>"
        )
        candidates = extract_unsubscribe_candidates(msg)
        urls = [c.url for c in candidates]
        self.assertIn("https://x.com/unsubscribe?id=1", urls)

    def test_unclosed_trailing_anchor_not_dropped(self) -> None:
        """A trailing <a> with no closing tag is still surfaced at EOF."""
        msg = _msg_html(
            '<html><body><a href="https://x.com/unsubscribe?id=9">'
            "Unsubscribe now"
        )
        candidates = extract_unsubscribe_candidates(msg)
        urls = [c.url for c in candidates]
        self.assertIn("https://x.com/unsubscribe?id=9", urls)

    def test_nested_form_outer_fields_not_dropped(self) -> None:
        """A <form> opened before the previous one closes still surfaces the
        outer form's hidden token field in next_action."""
        html = (
            "<html><body>"
            '<form action="/confirm" method="post">'
            '<input type="hidden" name="token" value="outer-token">'
            '<form action="/inner" method="post">'
            '<input type="hidden" name="inner_token" value="x">'
            "</form>"
            "<button>Confirm Unsubscribe</button>"
            "</form>"
            "</body></html>"
        )
        result = classify_landing_page("https://x.com/nested-form", 200, html)
        self.assertIsInstance(result.next_action, NextAction)
        self.assertIn("token", result.next_action.hidden_fields)

    def test_unclosed_trailing_form_not_dropped(self) -> None:
        """A trailing <form> with no closing tag is still flushed at EOF."""
        html = (
            "<html><body>"
            '<form action="/confirm" method="post">'
            '<input type="hidden" name="token" value="abc">'
            "<button>Confirm Unsubscribe</button>"
        )
        result = classify_landing_page("https://x.com/unclosed-form", 200, html)
        self.assertIsInstance(result.next_action, NextAction)
        self.assertEqual(result.next_action.hidden_fields, ["token"])


class TestUrlSignalFalsePositives(unittest.TestCase):
    """ADR-016 code review bug 4: bare remove/unsub substrings must not
    false-positive on unrelated URLs."""

    def test_remove_background_image_is_not_a_candidate(self) -> None:
        """A cart/UI image path containing 'remove' is not surfaced."""
        msg = _msg_html(
            '<html><body><a href="https://cdn.x.com/remove-background.png">'
            "icon</a></body></html>"
        )
        candidates = extract_unsubscribe_candidates(msg)
        self.assertEqual(candidates, [])

    def test_removed_user_id_query_param_is_not_a_candidate(self) -> None:
        """A query param literally named removed_user_id is not surfaced."""
        msg = _msg_html(
            '<html><body><a href="https://x.com/profile?removed_user_id=5">'
            "View profile</a></body></html>"
        )
        candidates = extract_unsubscribe_candidates(msg)
        self.assertEqual(candidates, [])

    def test_cart_remove_item_link_is_not_a_candidate(self) -> None:
        """An e-commerce 'remove item from cart' link is not surfaced."""
        msg = _msg_html(
            '<html><body><a href="https://shop.x.com/cart/remove-item?id=42">'
            "Remove</a></body></html>"
        )
        candidates = extract_unsubscribe_candidates(msg)
        self.assertEqual(candidates, [])

    def test_remove_me_from_list_url_is_still_a_candidate(self) -> None:
        """'remove' co-occurring with subscription-ish context still counts."""
        msg = _msg_html(
            '<html><body><a href="https://x.com/list?action=remove_me">'
            "Leave this list</a></body></html>"
        )
        candidates = extract_unsubscribe_candidates(msg)
        urls = [c.url for c in candidates]
        self.assertIn("https://x.com/list?action=remove_me", urls)

    def test_unsubstantiated_word_is_not_a_candidate(self) -> None:
        """A URL containing 'unsub' only as part of an unrelated word is
        not surfaced (word-boundary check on bare 'unsub')."""
        msg = _msg_html(
            '<html><body><a href="https://x.com/articles/unsubstantiated-claim">'
            "Read more</a></body></html>"
        )
        candidates = extract_unsubscribe_candidates(msg)
        self.assertEqual(candidates, [])

    def test_real_unsubscribe_url_still_matches(self) -> None:
        """A genuine /unsubscribe URL is unaffected by the tightened regex."""
        msg = _msg_html(
            '<html><body><a href="https://x.com/unsubscribe?id=1">'
            "Unsubscribe</a></body></html>"
        )
        candidates = extract_unsubscribe_candidates(msg)
        urls = [c.url for c in candidates]
        self.assertIn("https://x.com/unsubscribe?id=1", urls)

    def test_bare_unsub_path_segment_still_matches(self) -> None:
        """A bare '/unsub' path segment (not a substring of another word)
        still counts as a signal."""
        msg = _msg_html(
            '<html><body><a href="https://x.com/unsub?id=1">Stop mail</a>'
            "</body></html>"
        )
        candidates = extract_unsubscribe_candidates(msg)
        urls = [c.url for c in candidates]
        self.assertIn("https://x.com/unsub?id=1", urls)


class TestCompletedStatusNoneEdgeCase(unittest.TestCase):
    """ADR-016 code review bug 5: status=None should not force ambiguous."""

    def test_status_none_with_confirmation_phrase_and_no_form_is_completed(
        self,
    ) -> None:
        """A clear confirmation phrase, no HTTP status, no leftover form is
        completed rather than ambiguous."""
        html = (
            "<html><body><p>You have been unsubscribed successfully.</p>"
            "</body></html>"
        )
        result = classify_landing_page("https://x.com/done", None, html)
        self.assertEqual(result.page_class, PageClass.COMPLETED.value)

    def test_status_none_with_error_like_content_is_not_forced_completed(
        self,
    ) -> None:
        """status=None with no confirmation phrase at all still falls
        through normally (not classified completed just because status is
        None)."""
        html = "<html><body><p>Welcome to our homepage.</p></body></html>"
        result = classify_landing_page("https://x.com/home", None, html)
        self.assertNotEqual(result.page_class, PageClass.COMPLETED.value)


if __name__ == "__main__":
    unittest.main()
