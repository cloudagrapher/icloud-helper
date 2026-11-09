"""Secret file reader for mail-cleaner."""

from __future__ import annotations

import logging
import sys
from pathlib import Path

log = logging.getLogger(__name__)


def read_secret(path: str) -> str:
    """Read a secret from a file, stripping trailing whitespace.

    Args:
        path: Filesystem path to the secret file.

    Returns:
        File contents with trailing whitespace removed.
    """
    try:
        return Path(path).read_text(encoding="utf-8").strip()
    except OSError as exc:
        log.error("Cannot read secret file %s: %s", path, exc)
        sys.exit(1)
