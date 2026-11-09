"""Tests for icloud_helper.headers."""

from __future__ import annotations

import pytest

from icloud_helper.headers import (
    SenderRecord,
    classify_sender,
    content_pattern_facts,
    decode_header_value,
    determine_unsubscribe_method,
    display_name_has_email,
    extract_urls_from_list_unsubscribe,
    is_bulk,
    local_part_looks_like_email,
    parse_from_header,
    triage_messages,
)


# ---------------------------------------------------------------------------
# decode_header_value
# ---------------------------------------------------------------------------

class TestDecodeHeaderValue:
    def test_none_returns_empty_string(self):
        assert decode_header_value(None) == ""

    def test_plain_ascii(self):
        assert decode_header_value("Hello World") == "Hello World"

    def test_strips_leading_trailing_whitespace(self):
        assert decode_header_value("  hello  ") == "hello"

    def test_rfc2047_utf8_encoded(self):
        # =?utf-8?q?Acme_Corp?=
        encoded = "=?utf-8?q?Acme_Corp?="
        result = decode_header_value(encoded)
        assert result == "Acme Corp"

    def test_rfc2047_base64_encoded(self):
        # "Test" base64-encoded in latin-1
        encoded = "=?latin-1?b?VGVzdA==?="
        result = decode_header_value(encoded)
        assert result == "Test"

    def test_mixed_encoded_and_plain(self):
        encoded = "=?utf-8?q?Hello?= World"
        result = decode_header_value(encoded)
        assert "Hello" in result
        assert "World" in result


# ---------------------------------------------------------------------------
# parse_from_header
# ---------------------------------------------------------------------------

class TestParseFromHeader:
    def test_angle_bracket_format(self):
        name, addr = parse_from_header("Alice <alice@example.com>")
        assert name == "Alice"
        assert addr == "alice@example.com"

    def test_bare_address(self):
        name, addr = parse_from_header("alice@example.com")
        assert addr == "alice@example.com"

    def test_normalises_to_lowercase(self):
        _, addr = parse_from_header("Alice <ALICE@EXAMPLE.COM>")
        assert addr == "alice@example.com"

    def test_empty_string(self):
        name, addr = parse_from_header("")
        assert name == ""
        assert addr == ""

    def test_strips_display_name_whitespace(self):
        name, _ = parse_from_header("  Bob  <bob@example.com>")
        assert name == "Bob"

    def test_quoted_display_name(self):
        name, addr = parse_from_header('"Newsletter Team" <news@corp.com>')
        assert name == "Newsletter Team"
        assert addr == "news@corp.com"


# ---------------------------------------------------------------------------
# extract_urls_from_list_unsubscribe
# ---------------------------------------------------------------------------

class TestExtractUrlsFromListUnsubscribe:
    def test_http_url(self):
        http, mailto = extract_urls_from_list_unsubscribe(
            "<https://example.com/unsub>"
        )
        assert http == ["https://example.com/unsub"]
        assert mailto == []

    def test_mailto_url(self):
        http, mailto = extract_urls_from_list_unsubscribe(
            "<mailto:unsub@example.com>"
        )
        assert http == []
        assert mailto == ["mailto:unsub@example.com"]

    def test_mixed_http_and_mailto(self):
        header = (
            "<https://example.com/unsub>, <mailto:unsub@example.com>"
        )
        http, mailto = extract_urls_from_list_unsubscribe(header)
        assert len(http) == 1
        assert len(mailto) == 1

    def test_no_angle_brackets_skipped(self):
        http, mailto = extract_urls_from_list_unsubscribe(
            "https://example.com/unsub"
        )
        assert http == []
        assert mailto == []

    def test_empty_string(self):
        http, mailto = extract_urls_from_list_unsubscribe("")
        assert http == []
        assert mailto == []

    def test_http_not_https(self):
        http, _ = extract_urls_from_list_unsubscribe(
            "<http://example.com/unsub>"
        )
        assert http == ["http://example.com/unsub"]


# ---------------------------------------------------------------------------
# determine_unsubscribe_method
# ---------------------------------------------------------------------------

class TestDetermineUnsubscribeMethod:
    def test_one_click(self):
        result = determine_unsubscribe_method(
            "<https://example.com/unsub>",
            "List-Unsubscribe=One-Click",
        )
        assert result == "one-click"

    def test_mailto_when_no_post_header(self):
        result = determine_unsubscribe_method(
            "<mailto:unsub@example.com>",
            "",
        )
        assert result == "mailto"

    def test_http_only(self):
        result = determine_unsubscribe_method(
            "<https://example.com/unsub>",
            "",
        )
        assert result == "http-only"

    def test_none_when_empty(self):
        result = determine_unsubscribe_method("", "")
        assert result == "none"

    def test_mailto_preferred_over_nothing(self):
        result = determine_unsubscribe_method(
            "<mailto:x@y.com>",
            "some-other-value",
        )
        assert result == "mailto"

    def test_one_click_requires_https(self):
        # http (not https) with one-click post header should NOT be one-click
        result = determine_unsubscribe_method(
            "<http://example.com/unsub>",
            "List-Unsubscribe=One-Click",
        )
        assert result != "one-click"


# ---------------------------------------------------------------------------
# is_bulk
# ---------------------------------------------------------------------------

class TestIsBulk:
    def test_list_unsubscribe_signal(self):
        assert is_bulk({"list-unsubscribe": "<https://x.com/unsub>"})

    def test_list_id_signal(self):
        assert is_bulk({"list-id": "<list.example.com>"})

    def test_precedence_bulk_signal(self):
        assert is_bulk({"precedence": "bulk"})

    def test_precedence_bulk_case_insensitive(self):
        assert is_bulk({"precedence": "BULK"})

    def test_no_bulk_signal(self):
        assert not is_bulk({"from": "user@example.com", "subject": "Hello"})

    def test_empty_dict(self):
        assert not is_bulk({})


# ---------------------------------------------------------------------------
# classify_sender
# ---------------------------------------------------------------------------

class TestClassifySender:
    def _make_record(
        self,
        email_address: str = "news@newsletter.com",
        display_name: str = "Newsletter",
        unsub_header: str = "<https://newsletter.com/unsub/>",
        unsub_method: str = "http-only",
    ) -> SenderRecord:
        rec = SenderRecord(email_address, display_name)
        rec.sample_unsubscribe_header = unsub_header
        rec.unsubscribe_method = unsub_method
        return rec

    def test_newsletter_classification(self):
        rec = self._make_record(
            email_address="news@mailchimp.com",
            unsub_header="<https://mailchimp.com/unsub/>",
            unsub_method="one-click",
        )
        result = classify_sender(
            rec,
            has_list_unsub=True,
            has_list_id=True,
            has_precedence_bulk=False,
        )
        assert result == "newsletter"

    def test_spam_no_list_unsubscribe(self):
        rec = self._make_record()
        result = classify_sender(
            rec,
            has_list_unsub=False,
            has_list_id=True,
            has_precedence_bulk=True,
        )
        assert result == "spam"

    def test_spam_malformed_unsubscribe_url(self):
        rec = self._make_record(
            unsub_header="<https://not-a-url>",
            unsub_method="http-only",
        )
        result = classify_sender(
            rec,
            has_list_unsub=True,
            has_list_id=True,
            has_precedence_bulk=False,
        )
        assert result == "spam"

    def test_spam_generated_local_part_no_vowels(self):
        rec = self._make_record(
            email_address="xbctdfgh@example.com",
            unsub_header="<https://example.com/unsub/>",
            unsub_method="http-only",
        )
        result = classify_sender(
            rec,
            has_list_unsub=True,
            has_list_id=True,
            has_precedence_bulk=False,
        )
        assert result == "spam"

    def test_spam_uuid_local_part(self):
        rec = self._make_record(
            email_address=(
                "550e8400-e29b-41d4-a716-446655440000@example.com"
            ),
            unsub_header="<https://example.com/unsub/>",
            unsub_method="http-only",
        )
        result = classify_sender(
            rec,
            has_list_unsub=True,
            has_list_id=False,
            has_precedence_bulk=False,
        )
        assert result == "spam"

    def test_unknown_when_no_secondary_signal(self):
        rec = self._make_record(
            email_address="updates@newsletter.com",
            unsub_header="<https://newsletter.com/unsub/>",
            unsub_method="http-only",
        )
        result = classify_sender(
            rec,
            has_list_unsub=True,
            has_list_id=False,
            has_precedence_bulk=False,
        )
        assert result == "unknown"


# ---------------------------------------------------------------------------
# triage_messages (integration-style)
# ---------------------------------------------------------------------------

class TestTriageMessages:
    def _make_headers(
        self,
        from_addr: str,
        list_unsub: str = "",
        list_id: str = "",
        precedence: str = "",
    ) -> dict:
        return {
            "from": from_addr,
            "list-unsubscribe": list_unsub,
            "list-unsubscribe-post": "",
            "list-id": list_id,
            "precedence": precedence,
        }

    def test_non_bulk_messages_excluded(self):
        headers = [self._make_headers("alice@personal.com")]
        result = triage_messages(headers)
        assert result == {}

    def test_bulk_message_included(self):
        headers = [
            self._make_headers(
                "news@newsletter.com",
                list_unsub="<https://newsletter.com/unsub/>",
                list_id="<list.newsletter.com>",
            )
        ]
        result = triage_messages(headers)
        assert "news@newsletter.com" in result

    def test_message_count_accumulates(self):
        h = self._make_headers(
            "news@newsletter.com",
            list_unsub="<https://newsletter.com/unsub/>",
        )
        result = triage_messages([h, h, h])
        assert result["news@newsletter.com"].message_count == 3

    def test_missing_from_maps_to_unknown(self):
        headers = [
            {
                "from": "",
                "list-unsubscribe": "<https://x.com/unsub/>",
                "list-id": "<x.com>",
                "list-unsubscribe-post": "",
                "precedence": "",
            }
        ]
        result = triage_messages(headers)
        assert "unknown@unknown" in result

    def test_classification_assigned(self):
        h = self._make_headers(
            "news@mailchimp.com",
            list_unsub="<https://mailchimp.com/unsub/>",
            list_id="<list.mailchimp.com>",
        )
        result = triage_messages([h])
        rec = result["news@mailchimp.com"]
        assert rec.classification in ("newsletter", "spam", "unknown")


# ---------------------------------------------------------------------------
# Tranche 3 new helpers
# ---------------------------------------------------------------------------


class TestLocalPartLooksLikeEmail:
    """Tests for local_part_looks_like_email helper."""

    def test_realtor_gmail_spoof(self):
        """Embedded .gmail.com in local-part → True."""
        addr = "leanneallenrealestate.gmail.com@tafv5o.ff02.fdske.com"
        assert local_part_looks_like_email(addr) is True

    def test_plain_address_false(self):
        """Normal local-part → False."""
        assert local_part_looks_like_email("alice@example.com") is False

    def test_local_part_with_tld_suffix(self):
        """Local-part ending in .net → True."""
        assert local_part_looks_like_email("something.net@relay.example.com") is True

    def test_no_at_sign(self):
        """String with no @ → False."""
        assert local_part_looks_like_email("notanemail") is False

    def test_yahoo_brand_in_local_part(self):
        """Known mail-brand 'yahoo' in local-part → True."""
        assert local_part_looks_like_email("user.yahoo@relay.com") is True

    # --- false-negative cases (must NOT fire on normal human addresses) ---

    def test_dotted_human_name_false(self):
        """john.doe local-part does not end in a known TLD → False."""
        assert local_part_looks_like_email("john.doe@example.com") is False

    def test_newsletter_subdomain_style_false(self):
        """news.weekly local-part has no TLD suffix → False."""
        assert local_part_looks_like_email("news.weekly@realbrand.com") is False

    def test_initial_dot_surname_false(self):
        """j.smith does not end in a known TLD → False."""
        assert local_part_looks_like_email("j.smith@corp.com") is False

    def test_three_part_human_name_false(self):
        """mary.jane.watson ends in .watson, not a known TLD → False."""
        assert local_part_looks_like_email("mary.jane.watson@corp.com") is False

    def test_brand_arm_still_fires(self):
        """support.gmail in local-part triggers _MAIL_BRAND_RE → True."""
        assert local_part_looks_like_email("support.gmail@evil.com") is True


class TestDisplayNameHasEmail:
    """Tests for display_name_has_email helper."""

    def test_display_name_with_at(self):
        """Display name containing @ → True."""
        assert display_name_has_email("alice@legit.com") is True

    def test_display_name_without_at(self):
        """Plain display name → False."""
        assert display_name_has_email("Alice Smith") is False

    def test_empty_string(self):
        """Empty display name → False."""
        assert display_name_has_email("") is False


class TestContentPatternFacts:
    """Tests for content_pattern_facts helper."""

    def test_otp_phrase_and_digit(self):
        """OTP phrase + digit cluster → has_otp_pattern=True."""
        facts = content_pattern_facts(
            "Your verification code",
            "Your verification code is 482910. Do not share.",
        )
        assert facts["has_otp_pattern"] is True

    def test_otp_phrase_no_digit_false(self):
        """OTP phrase without a digit cluster → has_otp_pattern=False."""
        facts = content_pattern_facts(
            "verification code",
            "Your verification code will be sent shortly.",
        )
        assert facts["has_otp_pattern"] is False

    def test_receipt_pattern_detected(self):
        """Receipt language → has_receipt_pattern=True."""
        facts = content_pattern_facts(
            "Your Receipt",
            "Thank you for your order #ORD-1234.",
        )
        assert facts["has_receipt_pattern"] is True

    def test_currency_total_detected(self):
        """Currency figure → currency_total_present=True."""
        facts = content_pattern_facts(
            "Invoice",
            "Total: $99.99",
        )
        assert facts["currency_total_present"] is True

    def test_marketing_cta_density(self):
        """Multiple CTAs → marketing_cta_density > 0."""
        body = "Shop now! Buy now! Save 50%! Limited time offer. " * 5
        facts = content_pattern_facts("Deals", body)
        assert facts["marketing_cta_density"] > 0.0

    def test_empty_body_zero_density(self):
        """Empty body → marketing_cta_density=0.0, content facts False."""
        facts = content_pattern_facts("Hello", "")
        assert facts["marketing_cta_density"] == 0.0
        assert facts["has_otp_pattern"] is False
        assert facts["has_receipt_pattern"] is False
        assert facts["currency_total_present"] is False

    def test_subject_only_contributes(self):
        """OTP phrase in subject only (empty body) → has_otp_pattern=True."""
        facts = content_pattern_facts("Your OTP is 9921", "")
        assert facts["has_otp_pattern"] is True


class TestCronPathUnchanged:
    """Regression: cron-path functions still return spam/newsletter/unknown."""

    def test_classify_sender_still_returns_spam(self):
        """classify_sender returns 'spam' for bulk without List-Unsubscribe."""
        rec = SenderRecord("bulk@example.com", "Bulk")
        rec.sample_unsubscribe_header = ""
        rec.unsubscribe_method = "none"
        result = classify_sender(
            rec,
            has_list_unsub=False,
            has_list_id=True,
            has_precedence_bulk=True,
        )
        assert result == "spam"

    def test_classify_sender_still_returns_newsletter(self):
        """classify_sender returns 'newsletter' for well-formed bulk sender."""
        rec = SenderRecord("news@mailchimp.com", "MailChimp")
        rec.sample_unsubscribe_header = "<https://mailchimp.com/unsub/>"
        rec.unsubscribe_method = "http-only"
        result = classify_sender(
            rec,
            has_list_unsub=True,
            has_list_id=True,
            has_precedence_bulk=False,
        )
        assert result == "newsletter"

    def test_triage_messages_returns_spam_newsletter_unknown(self):
        """triage_messages still classifies senders as spam/newsletter/unknown."""
        headers_newsletter = {
            "from": "news@mailchimp.com",
            "list-unsubscribe": "<https://mailchimp.com/unsub/>",
            "list-unsubscribe-post": "",
            "list-id": "<list.mailchimp.com>",
            "precedence": "",
        }
        headers_spam = {
            "from": "bad@spammy.xyz",
            "list-unsubscribe": "",
            "list-unsubscribe-post": "",
            "list-id": "<spammy.xyz>",
            "precedence": "bulk",
        }
        result = triage_messages([headers_newsletter, headers_spam])
        assert result["news@mailchimp.com"].classification in (
            "newsletter", "spam", "unknown"
        )
        assert result["bad@spammy.xyz"].classification == "spam"
