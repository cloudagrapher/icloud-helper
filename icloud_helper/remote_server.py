"""Remote (Streamable HTTP) MCP entrypoint for claude.ai custom connectors.

This is a second, separate entrypoint next to the local stdio server in
``mcp_server.py``.  It reuses the same tool functions but:

- registers only the read tools in ``READ_TOOLS`` (no move, trash,
  unsubscribe, probe, policy writes, local file writes or config dump);
- turns on process-wide read-only mode (``readonly_guard``) before serving,
  so IMAP read-write SELECT, unsubscribe HTTP egress and SMTP sends refuse
  to run even if a tool were exposed by mistake;
- requires OAuth: FastMCP's GitHub OAuth proxy presents Dynamic Client
  Registration / CIMD to Claude and signs users in with one pre-registered
  GitHub OAuth app; and
- accepts exactly one GitHub account (by login, optionally pinned to the
  numeric user id, which survives a username change).

Configuration is environment variables plus secret files (never secret
values in env):

  ICLOUD_HELPER_PUBLIC_URL          https://mcp.example.com (required)
  ICLOUD_HELPER_GITHUB_CLIENT_ID    GitHub OAuth app client id (required)
  ICLOUD_HELPER_GITHUB_CLIENT_SECRET_FILE
                                    file holding the client secret (required)
  ICLOUD_HELPER_ALLOWED_GITHUB_LOGIN
                                    the one GitHub login allowed (required)
  ICLOUD_HELPER_ALLOWED_GITHUB_ID   numeric GitHub user id (optional, recommended)
  ICLOUD_HELPER_JWT_KEY_FILE        file holding the token signing key
                                    (optional; derived from the client
                                    secret when absent)
  ICLOUD_HELPER_ALLOW_CLAUDE_CODE   "1" also allows Claude Code's loopback
                                    redirect (optional)
  ICLOUD_HELPER_HOST / _PORT / _PATH
                                    bind address, default 0.0.0.0:8765/mcp
  FASTMCP_HOME                      where the encrypted OAuth state lives;
                                    mount it on a persistent volume

Run:  python -m icloud_helper.remote_server
"""
from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from typing import Any, Callable, Mapping, Optional

from fastmcp import FastMCP as RemoteFastMCP  # pylint: disable=import-error
from fastmcp.server.auth import AccessToken  # pylint: disable=import-error
from fastmcp.server.auth.providers.github import (  # pylint: disable=import-error
    GitHubProvider,
)

from icloud_helper import readonly_guard
from icloud_helper.secrets import read_secret

logger = logging.getLogger(__name__)

CLAUDE_AI_REDIRECT_URI = "https://claude.ai/api/mcp/auth_callback"
CLAUDE_CODE_REDIRECT_URIS = ("http://localhost:*", "http://127.0.0.1:*")

# Upstream GitHub scope: read-only profile access is all the gate needs.
GITHUB_SCOPES = ["read:user"]

# The only tools exposed remotely.  Everything here opens IMAP through
# flagged.open_readonly_session (EXAMINE + BODY.PEEK) and writes nothing.
READ_TOOLS = (
    "list_messages",
    "get_message_body",
    "list_flagged_messages",
    "find_unsubscribe_links",
)
# get_attachment is exposed through the no-save wrapper below, not directly.
REMOTE_TOOL_NAMES = READ_TOOLS + ("get_attachment",)


class ConfigError(ValueError):
    """Raised when the remote server's environment is incomplete."""


@dataclass(frozen=True)
class RemoteSettings:  # pylint: disable=too-many-instance-attributes
    """Validated settings for the remote server."""

    public_url: str
    github_client_id: str
    github_client_secret_file: str
    allowed_login: str
    allowed_id: Optional[str]
    jwt_key_file: Optional[str]
    allow_claude_code: bool
    host: str
    port: int
    path: str

    @classmethod
    def from_env(cls, env: Mapping[str, str]) -> "RemoteSettings":
        """Build settings from environment variables.

        Args:
            env: Mapping of environment variables (normally os.environ).

        Returns:
            Validated RemoteSettings.

        Raises:
            ConfigError: If a required variable is missing or invalid.
        """
        def required(name: str) -> str:
            value = env.get(name, "").strip()
            if not value:
                raise ConfigError(f"{name} is required")
            return value

        public_url = required("ICLOUD_HELPER_PUBLIC_URL").rstrip("/")
        if not public_url.startswith("https://"):
            raise ConfigError("ICLOUD_HELPER_PUBLIC_URL must start with https://")

        allowed_id = env.get("ICLOUD_HELPER_ALLOWED_GITHUB_ID", "").strip() or None
        if allowed_id is not None and not allowed_id.isdigit():
            raise ConfigError("ICLOUD_HELPER_ALLOWED_GITHUB_ID must be numeric")

        path = env.get("ICLOUD_HELPER_PATH", "/mcp").strip() or "/mcp"
        if not path.startswith("/"):
            raise ConfigError("ICLOUD_HELPER_PATH must start with /")

        try:
            port = int(env.get("ICLOUD_HELPER_PORT", "8765"))
        except ValueError as exc:
            raise ConfigError("ICLOUD_HELPER_PORT must be an integer") from exc

        return cls(
            public_url=public_url,
            github_client_id=required("ICLOUD_HELPER_GITHUB_CLIENT_ID"),
            github_client_secret_file=required(
                "ICLOUD_HELPER_GITHUB_CLIENT_SECRET_FILE"
            ),
            allowed_login=required("ICLOUD_HELPER_ALLOWED_GITHUB_LOGIN"),
            allowed_id=allowed_id,
            jwt_key_file=env.get("ICLOUD_HELPER_JWT_KEY_FILE", "").strip() or None,
            allow_claude_code=env.get("ICLOUD_HELPER_ALLOW_CLAUDE_CODE", "") == "1",
            host=env.get("ICLOUD_HELPER_HOST", "0.0.0.0").strip() or "0.0.0.0",
            port=port,
            path=path,
        )

    def allowed_redirect_uris(self) -> list[str]:
        """Return the MCP-client redirect URIs the proxy will accept.

        Returns:
            claude.ai's callback, plus loopback patterns for Claude Code
            when enabled.
        """
        uris = [CLAUDE_AI_REDIRECT_URI]
        if self.allow_claude_code:
            uris.extend(CLAUDE_CODE_REDIRECT_URIS)
        return uris


def is_allowed_identity(
    claims: Mapping[str, Any], allowed_login: str, allowed_id: Optional[str]
) -> bool:
    """Return True only for the one configured GitHub account.

    Login comparison is case-insensitive (GitHub logins are).  When
    ``allowed_id`` is set, the numeric ``sub`` must match too, so a renamed
    or re-registered username can't take over the gate.

    Args:
        claims: AccessToken claims from the GitHub token verifier.
        allowed_login: The permitted GitHub login.
        allowed_id: The permitted numeric GitHub user id, or None.

    Returns:
        True if the claims identify the permitted account.
    """
    login = claims.get("login")
    if not isinstance(login, str) or not login:
        return False
    if login.casefold() != allowed_login.casefold():
        return False
    if allowed_id is not None and str(claims.get("sub", "")) != allowed_id:
        return False
    return True


class SingleUserGitHubProvider(GitHubProvider):  # pylint: disable=too-many-ancestors
    """GitHub OAuth proxy that rejects every account but one.

    The check runs on every request's bearer token (``verify_token``
    delegates to ``load_access_token``), so a token issued to any other
    GitHub account gets a 401 on every MCP call.
    """

    def __init__(
        self, *, allowed_login: str, allowed_id: Optional[str] = None, **kwargs: Any
    ) -> None:
        if not allowed_login:
            raise ConfigError("allowed_login is required")
        super().__init__(**kwargs)
        self._allowed_login = allowed_login
        self._allowed_id = allowed_id

    async def load_access_token(self, token: str) -> AccessToken | None:  # type: ignore[override]
        result = await super().load_access_token(token)
        if result is None:
            return None
        if not is_allowed_identity(result.claims, self._allowed_login, self._allowed_id):
            logger.warning(
                "Rejected token for GitHub login %r (not the allowed account)",
                result.claims.get("login"),
            )
            return None
        return result


def build_auth(settings: RemoteSettings) -> SingleUserGitHubProvider:
    """Create the OAuth provider from settings and secret files.

    Args:
        settings: Validated RemoteSettings.

    Returns:
        A SingleUserGitHubProvider ready to pass to FastMCP.
    """
    jwt_key = read_secret(settings.jwt_key_file) if settings.jwt_key_file else None
    return SingleUserGitHubProvider(
        allowed_login=settings.allowed_login,
        allowed_id=settings.allowed_id,
        client_id=settings.github_client_id,
        client_secret=read_secret(settings.github_client_secret_file),
        base_url=settings.public_url,
        required_scopes=GITHUB_SCOPES,
        allowed_client_redirect_uris=settings.allowed_redirect_uris(),
        jwt_signing_key=jwt_key,
        require_authorization_consent=True,
    )


def _no_save_get_attachment(core_get_attachment: Callable[..., dict]) -> Callable[..., dict]:
    """Wrap get_attachment so the remote caller can't write files.

    Args:
        core_get_attachment: mcp_server.get_attachment.

    Returns:
        A tool function with the same read parameters and no ``save_to``.
    """

    def get_attachment(  # pylint: disable=too-many-arguments,too-many-positional-arguments
        uid: str,
        index: int,
        folder: str = "INBOX",
        uidvalidity: int = 0,
        offset: int = 0,
        length: int = 0,
        extract_text: bool = False,
        include_base64: bool = True,
    ) -> dict:
        """Fetch one attachment from a message by UID and index (read-only).

        The index comes from the attachment manifest returned by
        list_flagged_messages.  Pass that call's uidvalidity to detect
        folder changes.  Folders: INBOX, Junk, Archive.

        Args:
            uid: Message UID as a string.
            index: Zero-based attachment index from the manifest.
            folder: IMAP folder. Default: INBOX.
            uidvalidity: UIDVALIDITY from list_flagged_messages, or 0.
            offset: Byte offset for ranged reads. Default 0.
            length: Bytes to return; 0 means to end. Default 0.
            extract_text: Extract plain text (text/* and PDF). Default False.
            include_base64: Include base64 data in the response. Default True.

        Returns:
            Attachment metadata and content, or an error object.
        """
        return core_get_attachment(
            uid=uid,
            index=index,
            folder=folder,
            uidvalidity=uidvalidity,
            save_to="",
            offset=offset,
            length=length,
            extract_text=extract_text,
            include_base64=include_base64,
        )

    return get_attachment


def build_server(auth: Any = None) -> RemoteFastMCP:
    """Create the remote FastMCP server with the read-only tool subset.

    Importing ``mcp_server`` loads config.toml, policy.toml and the state DB
    exactly as the stdio server does; nothing there is registered here
    except ``READ_TOOLS`` and the no-save ``get_attachment`` wrapper.

    Args:
        auth: OAuth provider, or None (tests only).

    Returns:
        The configured server.
    """
    from icloud_helper import mcp_server as core  # pylint: disable=import-outside-toplevel

    server = RemoteFastMCP("icloud-helper", auth=auth)
    for name in READ_TOOLS:
        server.tool(getattr(core, name))
    server.tool(_no_save_get_attachment(core.get_attachment))
    return server


def main() -> None:
    """Validate settings, turn on read-only mode and serve over HTTP."""
    logging.basicConfig(
        level=os.environ.get("ICLOUD_HELPER_LOG_LEVEL", "INFO"),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    settings = RemoteSettings.from_env(os.environ)
    readonly_guard.enable()
    server = build_server(auth=build_auth(settings))
    logger.info(
        "icloud-helper remote: read-only, %d tools, allowed GitHub login %s%s",
        len(REMOTE_TOOL_NAMES),
        settings.allowed_login,
        f" (id {settings.allowed_id})" if settings.allowed_id else "",
    )
    server.run(
        transport="http", host=settings.host, port=settings.port, path=settings.path
    )


if __name__ == "__main__":
    main()
