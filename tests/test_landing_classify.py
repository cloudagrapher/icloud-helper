"""Dedicated fixture-per-PageClass tests for classify_landing_page.

Complements the broader assertions in test_body_links.py with one explicit
fixture per PageClass enum value, next_action field extraction detail, and
excerpt-sizing edge cases.
"""
from __future__ import annotations

import unittest

from icloud_helper.body_links import (
    NextActionEgress,
    PageClass,
    classify_landing_page,
)


class TestOneFixturePerPageClass(unittest.TestCase):
    """Exactly one canonical fixture per PageClass value."""

    def test_completed(self) -> None:
        """RFC-shaped confirmation page with no form is completed."""
        html = (
            "<html><body><h1>Success</h1>"
            "<p>You are unsubscribed. You will no longer receive "
            "emails from us.</p></body></html>"
        )
        result = classify_landing_page("https://esp.example.com/ok", 200, html)
        self.assertEqual(result.page_class, PageClass.COMPLETED.value)

    def test_single_confirm(self) -> None:
        """A bare confirm link with no form is single_confirm."""
        html = (
            "<html><body><p>Click below to unsubscribe.</p>"
            '<a href="/do-confirm">Yes, unsubscribe me</a>'
            "</body></html>"
        )
        result = classify_landing_page(
            "https://esp.example.com/confirm-link", 200, html
        )
        self.assertEqual(result.page_class, PageClass.SINGLE_CONFIRM.value)

    def test_multi_step_form(self) -> None:
        """A form requesting a reason (select) + email is multi_step_form."""
        html = (
            "<html><body><form action=\"/unsub\" method=\"post\">"
            '<input type="email" name="email" placeholder="confirm your email">'
            "<select name=\"reason\"><option>too many emails</option></select>"
            "<button>Submit</button>"
            "</form></body></html>"
        )
        result = classify_landing_page(
            "https://esp.example.com/multi", 200, html
        )
        self.assertEqual(result.page_class, PageClass.MULTI_STEP_FORM.value)

    def test_login_required(self) -> None:
        """An account-portal login wall is login_required."""
        html = (
            "<html><body><h2>Log in to manage your subscriptions</h2>"
            '<form><input type="text" name="user">'
            '<input type="password" name="pw"></form></body></html>'
        )
        result = classify_landing_page(
            "https://portal.example.com/login", 200, html
        )
        self.assertEqual(result.page_class, PageClass.LOGIN_REQUIRED.value)

    def test_captcha(self) -> None:
        """An hCaptcha widget on the page is captcha."""
        html = (
            '<html><body><div class="h-captcha" data-sitekey="abc">'
            "</div></body></html>"
        )
        result = classify_landing_page(
            "https://esp.example.com/verify", 200, html
        )
        self.assertEqual(result.page_class, PageClass.CAPTCHA.value)

    def test_dead_end(self) -> None:
        """A 410 Gone with no body is dead_end."""
        result = classify_landing_page("https://esp.example.com/gone", 410, "")
        self.assertEqual(result.page_class, PageClass.DEAD_END.value)

    def test_inconclusive_js_spa_empty_shell(self) -> None:
        """A 200 React-style empty shell (no server-rendered content) is
        inconclusive, not dead_end — Nextdoor's unsubscribe page is a real
        example: HTTP 200, page_text_excerpt is just "Nextdoor", no forms,
        no confirmation phrases, because the real content renders
        client-side via JS this classifier never executes.
        """
        html = (
            '<html><body><div id="root"></div>'
            "<script>"
            + ("window.__BOOTSTRAP__=" + "{'a':1};" * 40)
            + "</script>"
            "</body></html>"
        )
        result = classify_landing_page(
            "https://nextdoor.example.com/unsubscribe", 200, html
        )
        self.assertEqual(result.page_class, PageClass.INCONCLUSIVE.value)
        self.assertTrue(
            any("javascript" in w.lower() for w in result.warnings)
        )

    def test_ambiguous(self) -> None:
        """A confirmation phrase alongside a still-actionable form is ambiguous."""
        html = (
            "<html><body><p>Preferences updated.</p>"
            '<form action="/more" method="post">'
            '<input type="text" name="reason"></form></body></html>'
        )
        result = classify_landing_page(
            "https://esp.example.com/weird", 200, html
        )
        self.assertEqual(result.page_class, PageClass.AMBIGUOUS.value)


class TestInconclusiveVsDeadEnd(unittest.TestCase):
    """Disambiguate the new inconclusive (JS-shell) class from dead_end."""

    def test_blank_body_with_no_js_signal_is_still_dead_end(self) -> None:
        """A genuinely empty 200 body (no script, no SPA marker) is dead_end.

        Guards against over-broadening the new inconclusive branch: a page
        with no content and no JS-shell signature at all must still be
        reported as dead_end, not inconclusive.
        """
        html = "<html><body></body></html>"
        result = classify_landing_page(
            "https://esp.example.com/blank", 200, html
        )
        self.assertEqual(result.page_class, PageClass.DEAD_END.value)

    def test_short_text_with_trivial_script_is_still_dead_end(self) -> None:
        """Near-empty text plus a trivial (non-substantive) inline script,
        with no SPA root marker, is not enough to trigger inconclusive.
        """
        html = (
            "<html><body><p>Gone.</p>"
            "<script>ga('send','pageview');</script>"
            "</body></html>"
        )
        result = classify_landing_page(
            "https://esp.example.com/trivial-script", 200, html
        )
        self.assertEqual(result.page_class, PageClass.DEAD_END.value)

    def test_404_with_spa_shell_markup_is_still_dead_end(self) -> None:
        """An error status always wins over the JS-shell heuristic."""
        html = (
            '<html><body><div id="root"></div>'
            "<script>"
            + ("window.__BOOTSTRAP__=" + "{'a':1};" * 40)
            + "</script>"
            "</body></html>"
        )
        result = classify_landing_page(
            "https://esp.example.com/missing", 404, html
        )
        self.assertEqual(result.page_class, PageClass.DEAD_END.value)

    def test_data_reactroot_marker_alone_triggers_inconclusive(self) -> None:
        """A data-reactroot mount point, with only an EXTERNAL script (no
        substantive inline script), is recognized as a JS-shell purely on
        the marker signal — isolates the marker path from the script-length
        path.
        """
        html = (
            '<html><body><div data-reactroot="">'
            + ("x" * 10)
            + "</div>"
            + '<script src="/static/bundle.js"></script>'
            "</body></html>"
        )
        result = classify_landing_page(
            "https://esp.example.com/react", 200, html
        )
        self.assertEqual(result.page_class, PageClass.INCONCLUSIVE.value)

    def test_id_root_marker_alone_triggers_inconclusive(self) -> None:
        """Regression test (code-reviewer finding): id="root" is the
        motivating real-world case (Nextdoor's unsubscribe page uses this
        exact mount point). HTMLParser strips attribute-value quotes before
        _LandingParser ever sees them, so marker_blobs contains the literal
        text "id=root", never `id="root"` with quote characters — a regex
        that requires the quote characters can never match and this
        fixture would previously (incorrectly) classify as dead_end.

        Isolates the marker path: only an EXTERNAL script tag is present
        (no substantive inline script), so this exercises the SPA marker
        signal alone, not the script-length signal.
        """
        html = (
            '<html><body><div id="root"></div>'
            '<script src="/static/bundle.js"></script>'
            "</body></html>"
        )
        result = classify_landing_page(
            "https://nextdoor.example.com/unsubscribe", 200, html
        )
        self.assertEqual(result.page_class, PageClass.INCONCLUSIVE.value)

    def test_id_app_marker_alone_triggers_inconclusive(self) -> None:
        """Regression test (code-reviewer finding): id="app" (Vue's common
        mount point) in isolation, external script only.
        """
        html = (
            '<html><body><div id="app"></div>'
            '<script src="/static/app.js"></script>'
            "</body></html>"
        )
        result = classify_landing_page(
            "https://esp.example.com/vue-shell", 200, html
        )
        self.assertEqual(result.page_class, PageClass.INCONCLUSIVE.value)

    def test_id_next_marker_alone_triggers_inconclusive(self) -> None:
        """Regression test (code-reviewer finding): id="__next" (Next.js's
        mount point) in isolation, external script only.
        """
        html = (
            '<html><body><div id="__next"></div>'
            '<script src="/_next/static/chunk.js"></script>'
            "</body></html>"
        )
        result = classify_landing_page(
            "https://esp.example.com/next-shell", 200, html
        )
        self.assertEqual(result.page_class, PageClass.INCONCLUSIVE.value)

    def test_id_root_substring_does_not_false_match(self) -> None:
        """A boundary check: an unrelated id like "rootwrapper" must not
        false-match the id=root marker pattern (guards the trailing \\b in
        _SPA_ROOT_MARKER_RE).
        """
        html = (
            '<html><body><div id="rootwrapper"></div>'
            '<script src="/static/bundle.js"></script>'
            "</body></html>"
        )
        result = classify_landing_page(
            "https://esp.example.com/not-a-root", 200, html
        )
        self.assertEqual(result.page_class, PageClass.DEAD_END.value)

    def test_near_empty_text_boundary_40_chars_is_inconclusive(self) -> None:
        """Exactly _NEAR_EMPTY_TEXT_CHARS (40) visible characters, with a
        marker present, still qualifies as near-empty (inclusive boundary).
        """
        text = "x" * 40
        html = (
            f'<html><body><div id="root">{text}</div>'
            '<script src="/static/bundle.js"></script>'
            "</body></html>"
        )
        result = classify_landing_page(
            "https://esp.example.com/boundary-40", 200, html
        )
        self.assertEqual(result.page_class, PageClass.INCONCLUSIVE.value)

    def test_visible_text_boundary_41_chars_is_not_inconclusive(self) -> None:
        """41 visible characters (one over the near-empty threshold) no
        longer qualifies, even with a marker present — falls through to
        dead_end (no other signal on this fixture).
        """
        text = "x" * 41
        html = (
            f'<html><body><div id="root">{text}</div>'
            '<script src="/static/bundle.js"></script>'
            "</body></html>"
        )
        result = classify_landing_page(
            "https://esp.example.com/boundary-41", 200, html
        )
        self.assertEqual(result.page_class, PageClass.DEAD_END.value)

    def test_script_char_boundary_200_chars_is_inconclusive(self) -> None:
        """Exactly _SUBSTANTIVE_SCRIPT_CHARS (200) inline script characters,
        with no SPA marker, still qualifies as substantive (inclusive
        boundary) — isolates the script-length path from the marker path.
        """
        script_body = "a" * 200
        html = f"<html><body><script>{script_body}</script></body></html>"
        result = classify_landing_page(
            "https://esp.example.com/script-boundary-200", 200, html
        )
        self.assertEqual(result.page_class, PageClass.INCONCLUSIVE.value)

    def test_script_char_boundary_199_chars_is_not_inconclusive(self) -> None:
        """199 inline script characters (one under the substantive
        threshold), with no SPA marker, does not qualify — falls through to
        dead_end (no other signal on this fixture).
        """
        script_body = "a" * 199
        html = f"<html><body><script>{script_body}</script></body></html>"
        result = classify_landing_page(
            "https://esp.example.com/script-boundary-199", 200, html
        )
        self.assertEqual(result.page_class, PageClass.DEAD_END.value)

    def test_existing_fixtures_unaffected_by_inconclusive_branch(self) -> None:
        """completed/single_confirm/multi_step_form fixtures are unchanged
        by the new inconclusive branch (it only fires when every other
        signal is already absent).
        """
        completed_html = (
            "<html><body><h1>Success</h1>"
            "<p>You are unsubscribed. You will no longer receive "
            "emails from us.</p></body></html>"
        )
        completed = classify_landing_page(
            "https://esp.example.com/ok", 200, completed_html
        )
        self.assertEqual(completed.page_class, PageClass.COMPLETED.value)

        single_confirm_html = (
            "<html><body><p>Click below to unsubscribe.</p>"
            '<a href="/do-confirm">Yes, unsubscribe me</a>'
            "</body></html>"
        )
        single_confirm = classify_landing_page(
            "https://esp.example.com/confirm-link", 200, single_confirm_html
        )
        self.assertEqual(
            single_confirm.page_class, PageClass.SINGLE_CONFIRM.value
        )

        multi_step_html = (
            "<html><body><form action=\"/unsub\" method=\"post\">"
            '<input type="email" name="email" placeholder="confirm your email">'
            "<select name=\"reason\"><option>too many emails</option></select>"
            "<button>Submit</button>"
            "</form></body></html>"
        )
        multi_step = classify_landing_page(
            "https://esp.example.com/multi", 200, multi_step_html
        )
        self.assertEqual(multi_step.page_class, PageClass.MULTI_STEP_FORM.value)


class TestNextActionExtraction(unittest.TestCase):
    """Detailed next_action field extraction."""

    def test_relative_action_url_is_resolved_via_urljoin(self) -> None:
        """A relative form action is resolved against final_url."""
        html = (
            '<html><body><form action="confirm.php" method="POST">'
            '<input type="hidden" name="csrf" value="xyz">'
            "<button>Confirm Unsubscribe</button>"
            "</form></body></html>"
        )
        result = classify_landing_page(
            "https://esp.example.com/step/page.html", 200, html
        )
        self.assertIsNotNone(result.next_action)
        self.assertEqual(
            result.next_action.action_url,
            "https://esp.example.com/step/confirm.php",
        )
        self.assertEqual(result.next_action.method, "post")

    def test_hidden_and_required_fields_separated(self) -> None:
        """Hidden fields are reported separately from non-hidden fields."""
        html = (
            '<html><body><form action="/save" method="post">'
            '<input type="hidden" name="csrf" value="tok">'
            '<input type="hidden" name="list_id" value="42">'
            '<input type="email" name="email">'
            '<input type="checkbox" name="marketing">'
            "<button>Save</button></form></body></html>"
        )
        result = classify_landing_page("https://esp.example.com/f", 200, html)
        self.assertIsNotNone(result.next_action)
        self.assertEqual(
            sorted(result.next_action.hidden_fields), ["csrf", "list_id"]
        )
        self.assertEqual(
            sorted(result.next_action.required_fields),
            ["email", "marketing"],
        )

    def test_submit_label_captured_from_button_text(self) -> None:
        """The visible <button> text is captured as submit_label."""
        html = (
            '<html><body><form action="/go" method="post">'
            '<input type="hidden" name="t" value="1">'
            "<button>  Yes, Unsubscribe Me  </button>"
            "</form></body></html>"
        )
        result = classify_landing_page("https://esp.example.com/g", 200, html)
        self.assertIsNotNone(result.next_action)
        self.assertEqual(result.next_action.submit_label, "Yes, Unsubscribe Me")

    def test_egress_check_fn_invoked_on_action_url(self) -> None:
        """The optional egress_check_fn callback is invoked with the resolved URL."""
        calls = []

        def fake_egress_check(url: str) -> NextActionEgress:
            calls.append(url)
            return NextActionEgress(allowed=True)

        html = (
            '<html><body><form action="/submit" method="post">'
            '<input type="hidden" name="t" value="1">'
            "<button>Confirm</button></form></body></html>"
        )
        classify_landing_page(
            "https://esp.example.com/base/",
            200,
            html,
            egress_check_fn=fake_egress_check,
        )
        self.assertEqual(calls, ["https://esp.example.com/submit"])

    def test_egress_verdict_threaded_into_next_action(self) -> None:
        """The EgressVerdict returned by egress_check_fn is not discarded.

        Regression test for ADR-016 code review bug 6: next_action must
        expose whether action_url would pass egress, not just invoke the
        check for its side effect.
        """

        def fake_egress_check(url: str) -> NextActionEgress:
            del url
            return NextActionEgress(
                allowed=False,
                block_class="pending_review",
                detail="host not yet allowlisted",
            )

        html = (
            '<html><body><form action="/submit" method="post">'
            '<input type="hidden" name="t" value="1">'
            "<button>Confirm</button></form></body></html>"
        )
        result = classify_landing_page(
            "https://esp.example.com/base/",
            200,
            html,
            egress_check_fn=fake_egress_check,
        )
        self.assertIsNotNone(result.next_action)
        egress = result.next_action.action_url_egress
        self.assertIsNotNone(egress)
        self.assertFalse(egress.allowed)
        self.assertEqual(egress.block_class, "pending_review")
        self.assertEqual(egress.detail, "host not yet allowlisted")

    def test_next_action_egress_none_when_no_egress_check_fn(self) -> None:
        """action_url_egress stays None when no egress_check_fn is supplied."""
        html = (
            '<html><body><form action="/submit" method="post">'
            '<input type="hidden" name="t" value="1">'
            "<button>Confirm</button></form></body></html>"
        )
        result = classify_landing_page(
            "https://esp.example.com/base/", 200, html
        )
        self.assertIsNotNone(result.next_action)
        self.assertIsNone(result.next_action.action_url_egress)


class TestExcerptStrippingAndSizing(unittest.TestCase):
    """Excerpt content and size guarantees."""

    def test_comments_stripped_from_excerpt(self) -> None:
        """HTML comments never appear in page_text_excerpt."""
        html = (
            "<html><body><!-- internal tracking id 12345 -->"
            "<p>You have been unsubscribed.</p></body></html>"
        )
        result = classify_landing_page("https://esp.example.com/c", 200, html)
        self.assertNotIn("tracking id", result.page_text_excerpt)

    def test_default_excerpt_bytes_respected(self) -> None:
        """The default excerpt_bytes=4096 caps the excerpt length."""
        long_text = "B" * 20000
        html = f"<html><body><p>{long_text}</p></body></html>"
        result = classify_landing_page("https://esp.example.com/long", 200, html)
        self.assertLessEqual(len(result.page_text_excerpt.encode("utf-8")), 4096)

    def test_zero_excerpt_bytes_yields_empty_excerpt(self) -> None:
        """excerpt_bytes=0 yields an empty excerpt string."""
        html = "<html><body><p>Some text here.</p></body></html>"
        result = classify_landing_page(
            "https://esp.example.com/z", 200, html, excerpt_bytes=0
        )
        self.assertEqual(result.page_text_excerpt, "")


if __name__ == "__main__":
    unittest.main()
