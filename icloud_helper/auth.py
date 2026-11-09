"""Sender authentication helpers for mail-cleaner (H1 gate).

Provides ``check_sender_auth``, which evaluates iCloud-stamped
Authentication-Results headers and returns a tuple of
``(passed: bool, authenticated_from_domain: Optional[str])``.

``authenticated_from_domain`` is the ``header.from=`` value extracted from
the SAME trusted iCloud AR header that asserted ``dmarc=pass``.  Callers
must use this domain — not the raw ``From:`` header — when authorising
fork-C mailto targets (C1 fix).

Also provides the read-only ``extract_auth_signals`` helper, which returns
a rich factual dict of per-verifier results for use by the read surface.
It shares the same trusted-authserv iteration logic as ``check_sender_auth``
but never changes that function's behaviour.
"""
from __future__ import annotations

import logging
import re
from typing import Dict, List, Optional, Tuple

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Trusted authserv-id
# ---------------------------------------------------------------------------

# Empirically confirmed by fetching raw AR headers from real iCloud INBOX
# messages: iCloud stamps one Authentication-Results header per verifier,
# each using a subdomain of icloud.com as its authserv-id.
# Examples observed:
#   dmarc.icloud.com        — DMARC verdict
#   dkim-verifier.icloud.com — DKIM verdict
#   spf.icloud.com           — SPF verdict
#   arc.icloud.com           — ARC verdict
#   bimi.icloud.com          — BIMI verdict
#
# We trust ONLY AR headers whose authserv-id is exactly "icloud.com" or is
# a subdomain of "icloud.com".  All other authserv-ids are ignored, so an
# attacker-controlled header such as "attacker.example; dmarc=pass" has no
# effect on the gate.
_TRUSTED_AUTHSERV_SUFFIX = "icloud.com"

# ---------------------------------------------------------------------------
# Compiled regexes — gate
# ---------------------------------------------------------------------------

# dmarc=pass must be a delimited token.  \b prevents "dmarc=passfail" from
# satisfying the check (bypass 2 fix).
_DMARC_PASS_RE = re.compile(r"\bdmarc\s*=\s*pass\b", re.IGNORECASE)

# Presence detector for any dkim= token.  If dkim is present in a trusted AR
# header, it must also be dkim=pass.
_DKIM_ANY_RE = re.compile(r"\bdkim\s*=\s*\S+", re.IGNORECASE)
_DKIM_PASS_RE = re.compile(r"\bdkim\s*=\s*pass\b", re.IGNORECASE)

# Extract the header.from= value from an AR body.  The value runs until the
# next whitespace or end of string.
_HEADER_FROM_RE = re.compile(
    r"\bheader\.from\s*=\s*([^\s;,]+)", re.IGNORECASE
)

# ---------------------------------------------------------------------------
# Compiled regexes — extract_auth_signals (read-only, additive)
# ---------------------------------------------------------------------------

# SPF verdict: spf=<result> as a delimited token.
_SPF_RE = re.compile(
    r"\bspf\s*=\s*(pass|fail|softfail|neutral|none|temperror|permerror)\b",
    re.IGNORECASE,
)

# DKIM verdict: dkim=<result> as a delimited token.
_DKIM_VERDICT_RE = re.compile(
    r"\bdkim\s*=\s*(pass|fail|none)\b",
    re.IGNORECASE,
)

# DMARC verdict: dmarc=<result> as a delimited token.
_DMARC_VERDICT_RE = re.compile(
    r"\bdmarc\s*=\s*(pass|fail|none)\b",
    re.IGNORECASE,
)

# header.d= (DKIM signing domain).
_HEADER_D_RE = re.compile(
    r"\bheader\.d\s*=\s*([^\s;,]+)", re.IGNORECASE
)

# smtp.mailfrom= (envelope From domain or full address).
_SMTP_MAILFROM_RE = re.compile(
    r"\bsmtp\.mailfrom\s*=\s*([^\s;,]+)", re.IGNORECASE
)

# ---------------------------------------------------------------------------
# Public helpers
# ---------------------------------------------------------------------------


def authserv_id_is_trusted(authserv_raw: str) -> bool:
    """Return True if the raw authserv-id token belongs to iCloud.

    Strips any optional version tag (RFC 7601 §2.2: the authserv-id may be
    followed by a slash and version number, e.g. ``dmarc.icloud.com/1``).

    Args:
        authserv_raw: Text before the first semicolon in an AR header,
            stripped of leading/trailing whitespace.

    Returns:
        True when the authserv-id is exactly ``icloud.com`` or a subdomain
        of ``icloud.com``.
    """
    # Strip optional version tag: "host/version" → "host"
    token = authserv_raw.split("/", 1)[0].strip().lower()
    return (
        token == _TRUSTED_AUTHSERV_SUFFIX
        or token.endswith("." + _TRUSTED_AUTHSERV_SUFFIX)
    )


def check_sender_auth(
    headers: Dict[str, str],
) -> Tuple[bool, Optional[str]]:
    """Check iCloud-authserv sender authentication for a single message.

    Processes Authentication-Results headers individually (never as a joined
    blob) and trusts ONLY those whose authserv-id is under ``icloud.com``.
    This closes three bypass vectors:

    1. **Foreign authserv-id**: headers stamped by a non-iCloud verifier
       (e.g. ``attacker.example; dmarc=pass``) are ignored entirely.
    2. **Substring match**: ``dmarc=pass`` is matched as a delimited token
       (``\\bdmarc=pass\\b``) so ``dmarc=passfail`` does not satisfy the gate.
    3. **Per-UID check**: callers must pass the headers for the specific UID
       being evaluated, not a shared first-message snapshot.

    Conservative contract: no trusted AR header present → fail closed
    (route message to pending, do not action).

    Args:
        headers: Lowercase-keyed header dict as returned by
            ``actor._uid_fetch_headers`` for a single UID.  When multiple
            Authentication-Results headers are present, the dict contains
            both ``authentication-results`` (joined) and
            ``authentication-results-list`` (NUL-delimited individual
            values).

    Returns:
        A tuple of ``(passed, authenticated_from_domain)`` where:

        - ``passed`` is ``True`` when a trusted iCloud AR header asserts
          ``dmarc=pass`` (and ``dkim=pass`` if a ``dkim=`` token is present
          in that same header).
        - ``authenticated_from_domain`` is the ``header.from=`` value
          extracted from the passing trusted AR header (lowercased, trailing
          dot stripped), or ``None`` if the header did not carry a
          ``header.from=`` token.  Callers must use this domain for fork-C
          mailto authorization — the raw ``From:`` header must not be used.
    """
    # Prefer the NUL-delimited list when there are multiple AR headers; fall
    # back to the joined string for backward compatibility.
    raw_list_str = headers.get("authentication-results-list", "")
    if raw_list_str:
        ar_values: List[str] = raw_list_str.split("\x00")
    else:
        joined = headers.get("authentication-results", "")
        if not joined:
            log.debug(
                "authentication-results header absent — failing auth check"
            )
            return False, None
        # Single header (or already-joined legacy value): wrap in list.
        ar_values = [joined]

    for ar_hdr in ar_values:
        # An AR header value must contain a semicolon separating the
        # authserv-id from the result list.
        if ";" not in ar_hdr:
            continue
        authserv_raw, body = ar_hdr.split(";", 1)
        authserv_raw = authserv_raw.strip()

        if not authserv_id_is_trusted(authserv_raw):
            log.debug(
                "Ignoring AR header from untrusted authserv-id %r",
                authserv_raw,
            )
            continue

        # Within a trusted header, require dmarc=pass as a delimited token.
        if not _DMARC_PASS_RE.search(body):
            log.debug(
                "Trusted AR header (%r) does not assert dmarc=pass",
                authserv_raw,
            )
            continue

        # If a dkim= token is present in this same trusted header, require
        # dkim=pass.
        if _DKIM_ANY_RE.search(body) and not _DKIM_PASS_RE.search(body):
            log.debug(
                "Trusted AR header (%r) has dkim= but not dkim=pass",
                authserv_raw,
            )
            continue

        # Auth passed.  Extract header.from= from this same trusted header.
        authenticated_from_domain: Optional[str] = None
        m = _HEADER_FROM_RE.search(body)
        if m:
            authenticated_from_domain = (
                m.group(1).lower().rstrip(".")
            )
        return True, authenticated_from_domain

    log.debug(
        "No trusted iCloud AR header asserting dmarc=pass — "
        "failing auth check"
    )
    return False, None


def _last_two_labels(domain: str) -> str:
    """Return the last two dot-separated labels of a domain.

    Used for relaxed alignment comparison.  This is a heuristic only —
    it is NOT a public-suffix-aware organisational-domain comparison.
    The strict ``"aligned"`` axis (exact match) is the reliable signal.

    Args:
        domain: Fully-qualified or partial domain string.

    Returns:
        Last two labels joined by ``"."``, or the original string when
        fewer than two labels are present.
    """
    parts = domain.rstrip(".").split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else domain


def _compute_from_alignment(
    authenticated_from_domain: Optional[str],
    from_header_domain: Optional[str],
    dmarc_aligned: bool,
) -> str:
    """Compute From-domain alignment relative to the DMARC-authenticated domain.

    Args:
        authenticated_from_domain: header.from= from the DMARC-passing AR header,
            or None when no trusted DMARC was found.
        from_header_domain: Domain parsed from the raw ``From:`` header, or None.
        dmarc_aligned: True when dmarc=pass from a trusted iCloud authserv.

    Returns:
        One of: ``"aligned"``, ``"relaxed"``, ``"misaligned"``, ``"unknown"``.
    """
    if authenticated_from_domain is None or from_header_domain is None:
        return "unknown"
    if from_header_domain == authenticated_from_domain:
        return "aligned"
    if _last_two_labels(from_header_domain) == _last_two_labels(
        authenticated_from_domain
    ):
        return "relaxed"
    # DMARC passed but domains share no registrable domain — spoof signal.
    if dmarc_aligned:
        return "misaligned"
    return "unknown"


def _scan_trusted_ar_bodies(  # pylint: disable=too-many-branches
    ar_values: List[str],
) -> Tuple[str, str, str, bool, Optional[str], Optional[str], Optional[str], bool]:
    """Iterate trusted iCloud AR header bodies and extract per-verifier verdicts.

    Returns a tuple of:
    (spf, dkim, dmarc, dmarc_aligned, authenticated_from_domain,
     dkim_d_domain, envelope_from_domain, trusted_results_present)

    Args:
        ar_values: List of individual AR header body strings (already split on NUL).

    Returns:
        Eight-tuple of extracted values (see above).
    """
    spf: str = "unknown"
    dkim: str = "unknown"
    dmarc: str = "unknown"
    dmarc_aligned: bool = False
    authenticated_from_domain: Optional[str] = None
    dkim_d_domain: Optional[str] = None
    envelope_from_domain: Optional[str] = None
    trusted_results_present: bool = False

    for ar_hdr in ar_values:
        if ";" not in ar_hdr:
            continue
        authserv_raw, body = ar_hdr.split(";", 1)
        if not authserv_id_is_trusted(authserv_raw.strip()):
            continue
        trusted_results_present = True

        if spf == "unknown":
            m = _SPF_RE.search(body)
            if m:
                spf = m.group(1).lower()

        if dkim == "unknown":
            m = _DKIM_VERDICT_RE.search(body)
            if m:
                dkim = m.group(1).lower()

        if dkim_d_domain is None:
            m = _HEADER_D_RE.search(body)
            if m:
                dkim_d_domain = m.group(1).lower().rstrip(".")

        if envelope_from_domain is None:
            m = _SMTP_MAILFROM_RE.search(body)
            if m:
                raw_mf = m.group(1).lower().rstrip(".")
                envelope_from_domain = (
                    raw_mf.split("@", 1)[-1] if "@" in raw_mf else raw_mf
                )

        if dmarc == "unknown":
            m = _DMARC_VERDICT_RE.search(body)
            if m:
                dmarc = m.group(1).lower()
                if dmarc == "pass":
                    dmarc_aligned = True
                    hf_m = _HEADER_FROM_RE.search(body)
                    if hf_m:
                        authenticated_from_domain = (
                            hf_m.group(1).lower().rstrip(".")
                        )

    return (
        spf, dkim, dmarc, dmarc_aligned,
        authenticated_from_domain, dkim_d_domain,
        envelope_from_domain, trusted_results_present,
    )


def _build_ar_values(headers: Dict[str, str]) -> List[str]:
    """Return the list of individual AR header bodies from a header dict.

    Prefers the NUL-delimited ``authentication-results-list`` key preserved
    by ``parse_message_headers``; falls back to the joined
    ``authentication-results`` value for backward compatibility.

    Args:
        headers: Lowercase-keyed header dict.

    Returns:
        List of individual AR header strings (not yet split on ``";"``)
        ready for trusted-authserv iteration.
    """
    raw_list_str = headers.get("authentication-results-list", "")
    if raw_list_str:
        return raw_list_str.split("\x00")
    joined = headers.get("authentication-results", "")
    return [joined] if joined else []


def _parse_from_domain(raw_from: str, eu_module: object) -> Optional[str]:
    """Extract the domain from a raw ``From:`` header value.

    Args:
        raw_from: Raw From header string (may be empty or display-name form).
        eu_module: The ``email.utils`` module (passed in to avoid a repeated
            import inside the hot path).

    Returns:
        Lowercased domain string, or ``None`` when no ``@``-address is found.
    """
    if not raw_from:
        return None
    _, addr = eu_module.parseaddr(raw_from)  # type: ignore[union-attr]
    if addr and "@" in addr:
        return addr.split("@", 1)[-1].lower().strip(".")
    return None


def extract_auth_signals(headers: Dict[str, str]) -> Dict:
    """Extract factual per-verifier authentication signals from AR headers.

    Read-only and purely additive — does NOT change ``check_sender_auth``'s
    behaviour or the security gate contract.  Iterates the same trusted
    authserv-id list as ``check_sender_auth`` and returns raw verdicts as
    FACTS for the model to interpret; it never renders a composite verdict.

    When multiple trusted AR headers are present (iCloud stamps one per
    verifier), each is inspected independently.  The *first* match for each
    protocol wins (iCloud emits at most one SPF, one DKIM, one DMARC header).

    ``from_alignment`` uses a two-level heuristic — see ``_compute_from_alignment``.

    Args:
        headers: Lowercase-keyed header dict as returned by
            ``imap_client.parse_message_headers``.  Must contain
            ``authentication-results-list`` (NUL-delimited) when multiple
            AR headers are present; falls back to ``authentication-results``
            for backward compatibility.

    Returns:
        Dict with keys:
        - ``spf``: str — one of pass/fail/softfail/neutral/none/
          temperror/permerror/unknown.
        - ``dkim``: str — one of pass/fail/none/unknown.
        - ``dmarc``: str — one of pass/fail/none/unknown.
        - ``dmarc_aligned``: bool — True when dmarc=pass from a trusted
          iCloud authserv was found (mirrors the gate condition, without
          requiring dkim=pass in the same header).
        - ``authenticated_from_domain``: Optional[str] — header.from= value
          from the DMARC-passing trusted AR header, lowercased.
        - ``dkim_d_domain``: Optional[str] — header.d= from a trusted
          DKIM AR header.
        - ``envelope_from_domain``: Optional[str] — smtp.mailfrom= domain
          extracted from a trusted AR header.
        - ``from_header_domain``: Optional[str] — domain parsed from the
          raw ``From:`` header (lowercased).
        - ``from_alignment``: str — aligned/relaxed/misaligned/unknown.
        - ``trusted_results_present``: bool — at least one trusted iCloud
          AR header was found.
    """
    import email.utils as _eu  # pylint: disable=import-outside-toplevel

    # Build AR values list and scan (same logic as check_sender_auth).
    ar_values = _build_ar_values(headers)
    (
        spf, dkim, dmarc, dmarc_aligned,
        authenticated_from_domain, dkim_d_domain,
        envelope_from_domain, trusted_results_present,
    ) = _scan_trusted_ar_bodies(ar_values)

    # Parse From: header domain for alignment.
    from_header_domain = _parse_from_domain(headers.get("from", ""), _eu)
    from_alignment = _compute_from_alignment(
        authenticated_from_domain, from_header_domain, dmarc_aligned
    )

    return {
        "spf": spf,
        "dkim": dkim,
        "dmarc": dmarc,
        "dmarc_aligned": dmarc_aligned,
        "authenticated_from_domain": authenticated_from_domain,
        "dkim_d_domain": dkim_d_domain,
        "envelope_from_domain": envelope_from_domain,
        "from_header_domain": from_header_domain,
        "from_alignment": from_alignment,
        "trusted_results_present": trusted_results_present,
    }
