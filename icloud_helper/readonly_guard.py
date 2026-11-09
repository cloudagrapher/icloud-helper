"""Process-wide read-only switch for the remote (HTTP) deployment.

The remote entrypoint (``remote_server.py``) registers only read tools, so
no write path is reachable through MCP.  This module is the second layer:
when read-only mode is on, every code path that can change the mailbox or
reach the network on the user's behalf refuses to run, even if a future
change accidentally exposes it.

Guarded paths:
- ``imap_client.select_folder_readwrite`` (IMAP MOVE/STORE need a rw SELECT)
- ``unsubscribe.unsubscribe_one_click`` (HTTPS POST/GET egress)
- ``unsubscribe.unsubscribe_mailto`` (SMTP send via iCloud)

Read-only mode is on when ``enable()`` has been called in this process or
the environment variable ``ICLOUD_HELPER_READ_ONLY`` is ``"1"``.  The local
stdio server never sets either, so its behaviour is unchanged.
"""
from __future__ import annotations

import os

ENV_VAR = "ICLOUD_HELPER_READ_ONLY"

_ENABLED = False  # pylint: disable=invalid-name


class ReadOnlyModeError(RuntimeError):
    """Raised when a write or egress path runs while read-only mode is on."""


def enable() -> None:
    """Turn read-only mode on for the rest of this process."""
    global _ENABLED  # pylint: disable=global-statement
    _ENABLED = True


def disable() -> None:
    """Turn the in-process flag off (tests only; the env var still applies)."""
    global _ENABLED  # pylint: disable=global-statement
    _ENABLED = False


def is_read_only() -> bool:
    """Return True when read-only mode is on.

    Returns:
        True if ``enable()`` was called or ``ICLOUD_HELPER_READ_ONLY=1``.
    """
    return _ENABLED or os.environ.get(ENV_VAR, "") == "1"


def assert_writes_allowed(operation: str) -> None:
    """Refuse ``operation`` when read-only mode is on.

    Args:
        operation: Short description used in the error message.

    Raises:
        ReadOnlyModeError: If read-only mode is on.
    """
    if is_read_only():
        raise ReadOnlyModeError(
            f"{operation} refused: icloud-helper is running in read-only mode"
        )
