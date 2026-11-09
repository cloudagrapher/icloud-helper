"""Tests for icloud_helper.policy."""

from __future__ import annotations

import logging

import pytest

from icloud_helper.policy import (
    GlobalConfig,
    RateLimitConfig,
    SenderPolicy,
    get_actionable_senders,
    load_config,
    load_policy,
)


# ---------------------------------------------------------------------------
# load_config
# ---------------------------------------------------------------------------

class TestLoadConfig:
    def test_defaults_when_file_missing(self, tmp_path):
        result = load_config(tmp_path / "config.toml")
        assert isinstance(result, GlobalConfig)
        assert result.dry_run is True
        assert result.allow_delete is False
        assert result.folders == ["INBOX"]

    def test_missing_file_logs_warning(self, tmp_path, caplog):
        with caplog.at_level(logging.WARNING, logger="icloud_helper.policy"):
            load_config(tmp_path / "config.toml")
        assert any("not found" in r.message for r in caplog.records)

    def test_valid_config(self, tmp_path):
        toml_content = """
folders = ["INBOX", "Junk"]
dry_run = false
allow_delete = false
disposition = "archive"
protected_domains = ["bank.com", "gov.uk"]
allow_mcp_policy_writes = true

[rate_limits]
max_unsubscribes_per_run = 10
request_sleep_seconds = 3.5
"""
        config_file = tmp_path / "config.toml"
        config_file.write_text(toml_content, encoding="utf-8")
        result = load_config(config_file)
        assert result.folders == ["INBOX", "Junk"]
        assert result.dry_run is False
        assert result.disposition == "archive"
        assert result.protected_domains == ["bank.com", "gov.uk"]
        assert result.allow_mcp_policy_writes is True
        assert result.rate_limits.max_unsubscribes_per_run == 10
        assert result.rate_limits.request_sleep_seconds == 3.5

    def test_discord_webhook_not_in_config(self, tmp_path):
        """discord_webhook_url must not be loaded from config (M1: use secrets)."""
        toml_content = 'discord_webhook_url = "https://hooks.discord.com/abc"\n'
        config_file = tmp_path / "config.toml"
        config_file.write_text(toml_content, encoding="utf-8")
        result = load_config(config_file)
        assert not hasattr(result, "discord_webhook_url"), (
            "discord_webhook_url must not be a GlobalConfig attribute; "
            "use secrets/discord_webhook_url instead."
        )

    def test_malformed_toml_returns_defaults(self, tmp_path):
        bad_file = tmp_path / "config.toml"
        bad_file.write_text("this is [not valid toml {{", encoding="utf-8")
        result = load_config(bad_file)
        assert isinstance(result, GlobalConfig)
        assert result.dry_run is True

    def test_malformed_toml_logs_error(self, tmp_path, caplog):
        bad_file = tmp_path / "config.toml"
        bad_file.write_text("x = [unclosed", encoding="utf-8")
        with caplog.at_level(logging.ERROR, logger="icloud_helper.policy"):
            load_config(bad_file)
        assert any("Malformed" in r.message for r in caplog.records)

    def test_partial_config_uses_defaults_for_missing(self, tmp_path):
        config_file = tmp_path / "config.toml"
        config_file.write_text('dry_run = false\n', encoding="utf-8")
        result = load_config(config_file)
        assert result.dry_run is False
        assert result.folders == ["INBOX"]  # default preserved

    def test_protected_domains_normalised_lowercase(self, tmp_path):
        config_file = tmp_path / "config.toml"
        config_file.write_text(
            'protected_domains = ["Bank.Com", "GOV.UK"]\n',
            encoding="utf-8",
        )
        result = load_config(config_file)
        assert "bank.com" in result.protected_domains
        assert "gov.uk" in result.protected_domains

    def test_probe_max_capture_bytes_default_under_ceiling(self, tmp_path):
        """The default probe_max_capture_bytes (512 KiB) is well under the
        4 MiB hard ceiling and passes through unclamped."""
        result = load_config(tmp_path / "config.toml")
        assert result.probe_max_capture_bytes == 524288

    def test_probe_max_capture_bytes_oversized_value_is_clamped(self, tmp_path):
        """Security hardening (LOW-2): an operator misconfig requesting an
        arbitrarily large probe_max_capture_bytes is clamped to a 4 MiB
        hard ceiling, not honoured as-is."""
        config_file = tmp_path / "config.toml"
        config_file.write_text(
            "probe_max_capture_bytes = 999999999999\n",
            encoding="utf-8",
        )
        result = load_config(config_file)
        assert result.probe_max_capture_bytes == 4 * 1024 * 1024

    def test_probe_max_capture_bytes_negative_value_clamped_to_zero(
        self, tmp_path
    ):
        """A negative configured value is clamped to zero, not passed
        through as a negative read() length."""
        config_file = tmp_path / "config.toml"
        config_file.write_text(
            "probe_max_capture_bytes = -5\n",
            encoding="utf-8",
        )
        result = load_config(config_file)
        assert result.probe_max_capture_bytes == 0

    def test_probe_max_capture_bytes_within_ceiling_unchanged(self, tmp_path):
        """A reasonable, sub-ceiling configured value passes through as-is."""
        config_file = tmp_path / "config.toml"
        config_file.write_text(
            "probe_max_capture_bytes = 1048576\n",
            encoding="utf-8",
        )
        result = load_config(config_file)
        assert result.probe_max_capture_bytes == 1048576


# ---------------------------------------------------------------------------
# load_policy
# ---------------------------------------------------------------------------

class TestLoadPolicy:
    def test_missing_file_returns_empty(self, tmp_path):
        result = load_policy(tmp_path / "policy.toml")
        assert result == {}

    def test_missing_file_logs_info(self, tmp_path, caplog):
        with caplog.at_level(logging.INFO, logger="icloud_helper.policy"):
            load_policy(tmp_path / "policy.toml")
        assert any("no actionable" in r.message for r in caplog.records)

    def test_valid_unsubscribe_entry(self, tmp_path):
        policy_file = tmp_path / "policy.toml"
        policy_file.write_text(
            '["news@example.com"]\naction = "unsubscribe"\n',
            encoding="utf-8",
        )
        result = load_policy(policy_file)
        assert "news@example.com" in result
        assert result["news@example.com"].action == "unsubscribe"

    def test_valid_keep_entry(self, tmp_path):
        policy_file = tmp_path / "policy.toml"
        policy_file.write_text(
            '["trusted@example.com"]\naction = "keep"\n',
            encoding="utf-8",
        )
        result = load_policy(policy_file)
        assert result["trusted@example.com"].action == "keep"

    def test_sender_keys_normalised_lowercase(self, tmp_path):
        policy_file = tmp_path / "policy.toml"
        policy_file.write_text(
            '["NEWS@EXAMPLE.COM"]\naction = "unsubscribe"\n',
            encoding="utf-8",
        )
        result = load_policy(policy_file)
        assert "news@example.com" in result

    def test_malformed_toml_returns_empty(self, tmp_path):
        bad_file = tmp_path / "policy.toml"
        bad_file.write_text("[[not valid toml", encoding="utf-8")
        result = load_policy(bad_file)
        assert result == {}

    def test_malformed_toml_logs_error(self, tmp_path, caplog):
        bad_file = tmp_path / "policy.toml"
        bad_file.write_text("[[broken", encoding="utf-8")
        with caplog.at_level(logging.ERROR, logger="icloud_helper.policy"):
            load_policy(bad_file)
        assert any("Malformed" in r.message for r in caplog.records)

    def test_invalid_action_skipped_with_error_log(self, tmp_path, caplog):
        policy_file = tmp_path / "policy.toml"
        policy_file.write_text(
            '["spam@x.com"]\naction = "delete"\n',
            encoding="utf-8",
        )
        with caplog.at_level(logging.ERROR, logger="icloud_helper.policy"):
            result = load_policy(policy_file)
        assert "spam@x.com" not in result
        assert any("invalid action" in r.message for r in caplog.records)

    def test_optional_disposition_field(self, tmp_path):
        policy_file = tmp_path / "policy.toml"
        policy_file.write_text(
            '["news@example.com"]\naction = "unsubscribe"\n'
            'disposition = "archive"\n',
            encoding="utf-8",
        )
        result = load_policy(policy_file)
        assert result["news@example.com"].disposition == "archive"

    def test_disposition_none_when_absent(self, tmp_path):
        policy_file = tmp_path / "policy.toml"
        policy_file.write_text(
            '["news@example.com"]\naction = "unsubscribe"\n',
            encoding="utf-8",
        )
        result = load_policy(policy_file)
        assert result["news@example.com"].disposition is None

    def test_multiple_entries(self, tmp_path):
        policy_file = tmp_path / "policy.toml"
        policy_file.write_text(
            '["a@example.com"]\naction = "unsubscribe"\n\n'
            '["b@example.com"]\naction = "keep"\n',
            encoding="utf-8",
        )
        result = load_policy(policy_file)
        assert len(result) == 2


# ---------------------------------------------------------------------------
# get_actionable_senders
# ---------------------------------------------------------------------------

class TestGetActionableSenders:
    def _make_policy(self, entries: dict) -> dict:
        return {
            email: SenderPolicy(**kwargs)
            for email, kwargs in entries.items()
        }

    def test_keep_entries_excluded(self):
        policy = self._make_policy({
            "a@example.com": {"action": "unsubscribe"},
            "b@example.com": {"action": "keep"},
        })
        result = get_actionable_senders(policy, [])
        assert "a@example.com" in result
        assert "b@example.com" not in result

    def test_protected_domain_excluded(self):
        policy = self._make_policy({
            "news@bank.com": {"action": "unsubscribe"},
        })
        result = get_actionable_senders(policy, ["bank.com"])
        assert "news@bank.com" not in result

    def test_non_protected_domain_included(self):
        policy = self._make_policy({
            "news@newsletter.com": {"action": "unsubscribe"},
        })
        result = get_actionable_senders(policy, ["bank.com"])
        assert "news@newsletter.com" in result

    def test_empty_policy_returns_empty(self):
        result = get_actionable_senders({}, ["bank.com"])
        assert result == {}

    def test_protected_domain_logs_warning(self, caplog):
        policy = self._make_policy({
            "x@protected.com": {"action": "unsubscribe"},
        })
        with caplog.at_level(logging.WARNING, logger="icloud_helper.policy"):
            get_actionable_senders(policy, ["protected.com"])
        assert any("protected_domains" in r.message for r in caplog.records)
