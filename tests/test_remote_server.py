"""Tests for the remote (Streamable HTTP + GitHub OAuth) entrypoint.

No network calls: the OAuth provider is built with dummy credentials and
the GitHub token check is stubbed.
"""
from __future__ import annotations

import ast
import asyncio
import inspect
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

pytest.importorskip("fastmcp", reason="remote server needs the fastmcp package")

# pylint: disable=wrong-import-position
from fastmcp.server.auth import AccessToken  # noqa: E402
from fastmcp.server.auth.providers.github import GitHubProvider  # noqa: E402

from icloud_helper import readonly_guard  # noqa: E402
from icloud_helper import remote_server as rs  # noqa: E402
from icloud_helper import unsubscribe  # noqa: E402
from icloud_helper.imap_client import select_folder_readwrite  # noqa: E402

# Every tool that can change the mailbox, reach the network on the user's
# behalf, write local files or dump config.  None may appear remotely.
_FORBIDDEN_TOOLS = {
    "unsubscribe_sender",
    "run_cleanup",
    "trigger_triage",
    "approve_sender",
    "move_messages",
    "trash_messages",
    "unsubscribe_message",
    "probe_unsubscribe_link",
    "unsubscribe_with_fallback",
    "save_message_pdf",
    "get_config",
}


def _env(tmp_path: Path, **overrides: str) -> dict:
    secret = tmp_path / "github_client_secret"
    secret.write_text("s" * 40, encoding="utf-8")
    env = {
        "ICLOUD_HELPER_PUBLIC_URL": "https://mcp.example.com",
        "ICLOUD_HELPER_GITHUB_CLIENT_ID": "Ov23testclient",
        "ICLOUD_HELPER_GITHUB_CLIENT_SECRET_FILE": str(secret),
        "ICLOUD_HELPER_ALLOWED_GITHUB_LOGIN": "OwnerLogin",
    }
    env.update(overrides)
    return env


@pytest.fixture(name="auth")
def _auth(tmp_path, monkeypatch):
    monkeypatch.setenv("FASTMCP_HOME", str(tmp_path / "fastmcp"))
    settings = rs.RemoteSettings.from_env(
        _env(tmp_path, ICLOUD_HELPER_ALLOWED_GITHUB_ID="12345")
    )
    return rs.build_auth(settings)


@pytest.fixture(autouse=True)
def _reset_guard():
    readonly_guard.disable()
    yield
    readonly_guard.disable()


def _tool_names(server) -> set:
    return {t.name for t in asyncio.run(server.list_tools())}


# ---------------------------------------------------------------------------
# Tool surface
# ---------------------------------------------------------------------------


def test_only_read_tools_are_registered():
    names = _tool_names(rs.build_server())
    assert names == set(rs.REMOTE_TOOL_NAMES)
    assert not names & _FORBIDDEN_TOOLS


def test_remote_get_attachment_has_no_save_to():
    server = rs.build_server()
    tools = {t.name: t for t in asyncio.run(server.list_tools())}
    props = tools["get_attachment"].parameters["properties"]
    assert "save_to" not in props
    assert {"uid", "index", "folder", "uidvalidity"} <= set(props)


def test_remote_get_attachment_forces_empty_save_to():
    core = MagicMock(return_value={"ok": True})
    wrapper = rs._no_save_get_attachment(core)  # pylint: disable=protected-access
    assert "save_to" not in inspect.signature(wrapper).parameters
    wrapper(uid="7", index=0)
    assert core.call_args.kwargs["save_to"] == ""


# ---------------------------------------------------------------------------
# Settings
# ---------------------------------------------------------------------------


def test_settings_defaults(tmp_path):
    settings = rs.RemoteSettings.from_env(_env(tmp_path))
    assert settings.host == "0.0.0.0"
    assert settings.port == 8765
    assert settings.path == "/mcp"
    assert settings.allowed_id is None
    assert settings.allowed_redirect_uris() == [rs.CLAUDE_AI_REDIRECT_URI]


@pytest.mark.parametrize(
    "missing",
    [
        "ICLOUD_HELPER_PUBLIC_URL",
        "ICLOUD_HELPER_GITHUB_CLIENT_ID",
        "ICLOUD_HELPER_GITHUB_CLIENT_SECRET_FILE",
        "ICLOUD_HELPER_ALLOWED_GITHUB_LOGIN",
    ],
)
def test_settings_require_each_variable(tmp_path, missing):
    env = _env(tmp_path)
    env[missing] = "  "
    with pytest.raises(rs.ConfigError, match=missing):
        rs.RemoteSettings.from_env(env)


def test_settings_reject_plain_http(tmp_path):
    with pytest.raises(rs.ConfigError, match="https"):
        rs.RemoteSettings.from_env(
            _env(tmp_path, ICLOUD_HELPER_PUBLIC_URL="http://mcp.example.com")
        )


def test_settings_reject_non_numeric_id(tmp_path):
    with pytest.raises(rs.ConfigError, match="numeric"):
        rs.RemoteSettings.from_env(
            _env(tmp_path, ICLOUD_HELPER_ALLOWED_GITHUB_ID="owner")
        )


def test_claude_code_redirects_are_opt_in(tmp_path):
    settings = rs.RemoteSettings.from_env(
        _env(tmp_path, ICLOUD_HELPER_ALLOW_CLAUDE_CODE="1")
    )
    uris = settings.allowed_redirect_uris()
    assert uris[0] == rs.CLAUDE_AI_REDIRECT_URI
    assert "http://localhost:*" in uris


# ---------------------------------------------------------------------------
# Single-user gate
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("claims", "allowed_id", "expected"),
    [
        ({"login": "OwnerLogin", "sub": "12345"}, "12345", True),
        ({"login": "ownerlogin", "sub": "12345"}, "12345", True),
        ({"login": "OwnerLogin", "sub": "99999"}, "12345", False),
        ({"login": "someone-else", "sub": "12345"}, "12345", False),
        ({"login": "OwnerLogin"}, None, True),
        ({"login": ""}, None, False),
        ({}, None, False),
        ({"login": None, "sub": "12345"}, "12345", False),
    ],
)
def test_is_allowed_identity(claims, allowed_id, expected):
    assert rs.is_allowed_identity(claims, "OwnerLogin", allowed_id) is expected


def _token(claims: dict) -> AccessToken:
    return AccessToken(token="t", client_id="c", scopes=["read:user"], claims=claims)


def test_provider_rejects_other_accounts(auth):
    other = _token({"login": "someone-else", "sub": "777"})
    with patch.object(GitHubProvider, "load_access_token", return_value=other):
        assert asyncio.run(auth.load_access_token("jwt")) is None
        assert asyncio.run(auth.verify_token("jwt")) is None


def test_provider_accepts_owner(auth):
    owner = _token({"login": "OwnerLogin", "sub": "12345"})
    with patch.object(GitHubProvider, "load_access_token", return_value=owner):
        assert asyncio.run(auth.load_access_token("jwt")) is owner


def test_provider_passes_through_invalid_tokens(auth):
    with patch.object(GitHubProvider, "load_access_token", return_value=None):
        assert asyncio.run(auth.load_access_token("jwt")) is None


def test_provider_uses_minimal_scope_and_claude_redirect(auth):
    assert auth.required_scopes == rs.GITHUB_SCOPES == ["read:user"]


def test_unauthenticated_mcp_request_gets_401_with_resource_metadata(auth):
    from starlette.testclient import TestClient  # pylint: disable=import-outside-toplevel

    app = rs.build_server(auth=auth).http_app(path="/mcp")
    with TestClient(app) as client:
        resp = client.post(
            "/mcp",
            json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
            headers={"Accept": "application/json, text/event-stream"},
        )
        assert resp.status_code == 401
        assert "resource_metadata=" in resp.headers.get("www-authenticate", "")

        meta = client.get("/.well-known/oauth-protected-resource/mcp")
        assert meta.status_code == 200
        assert meta.json()["authorization_servers"][0].startswith(
            "https://mcp.example.com"
        )


# ---------------------------------------------------------------------------
# Read-only guard
# ---------------------------------------------------------------------------


def test_guard_off_by_default(monkeypatch):
    monkeypatch.delenv(readonly_guard.ENV_VAR, raising=False)
    assert readonly_guard.is_read_only() is False
    readonly_guard.assert_writes_allowed("anything")


def test_guard_env_var(monkeypatch):
    monkeypatch.setenv(readonly_guard.ENV_VAR, "1")
    with pytest.raises(readonly_guard.ReadOnlyModeError):
        readonly_guard.assert_writes_allowed("anything")


def test_guard_blocks_readwrite_select():
    readonly_guard.enable()
    imap = MagicMock()
    with pytest.raises(readonly_guard.ReadOnlyModeError):
        select_folder_readwrite(imap, "INBOX")
    imap.select.assert_not_called()


def test_guard_blocks_one_click_egress():
    readonly_guard.enable()
    with pytest.raises(readonly_guard.ReadOnlyModeError):
        unsubscribe.unsubscribe_one_click(
            sender="a@example.com", url="https://example.com/u", dry_run=False
        )


def test_mailto_guard_runs_before_smtp_connect():
    """The SMTP send path checks the guard before opening a connection."""
    source = inspect.getsource(unsubscribe.unsubscribe_mailto)
    tree = ast.parse(source.lstrip())
    calls = [
        node for node in ast.walk(tree)
        if isinstance(node, ast.Call)
    ]

    def lineno_of(predicate):
        return min(n.lineno for n in calls if predicate(n))

    guard = lineno_of(
        lambda n: isinstance(n.func, ast.Name)
        and n.func.id == "assert_writes_allowed"
    )
    smtp = lineno_of(
        lambda n: isinstance(n.func, ast.Attribute) and n.func.attr == "SMTP"
    )
    assert guard < smtp
