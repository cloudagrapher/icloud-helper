"""RFC 8058 one-click unsubscribe execution and mailto fallback.

Tranche 3 Pass B: denylist-primary SSRF control with per-hop IP pinning.
"""
# pylint: disable=too-many-lines
from __future__ import annotations

import dataclasses
import email.message
import email.utils
import hashlib
import http.client
import ipaddress
import logging
import smtplib
import socket
import ssl
import urllib.error
import urllib.parse
import urllib.request
from enum import Enum
from typing import List, Optional, Tuple

from icloud_helper.headers import (
    determine_unsubscribe_method,
    extract_urls_from_list_unsubscribe,
)
from icloud_helper.policy import GlobalConfig
from icloud_helper.readonly_guard import assert_writes_allowed

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# B.2 — IP denylist (table-driven; primary SSRF control)
# ---------------------------------------------------------------------------

# Each entry is documented so the security-reviewer can audit coverage.
# The stdlib is_private/is_reserved/is_loopback/is_link_local/is_multicast/
# is_unspecified flags serve as a BACKSTOP but the explicit CIDR table is the
# documented first-line control.

_DENIED_NETWORKS: List[ipaddress.IPv4Network | ipaddress.IPv6Network] = [
    # ---- IPv4 ----
    ipaddress.ip_network("10.0.0.0/8"),         # RFC1918 private
    ipaddress.ip_network("172.16.0.0/12"),       # RFC1918 private
    ipaddress.ip_network("192.168.0.0/16"),      # RFC1918 private
    ipaddress.ip_network("127.0.0.0/8"),         # Loopback
    ipaddress.ip_network("169.254.0.0/16"),      # Link-local / metadata (169.254.169.254)
    ipaddress.ip_network("100.64.0.0/10"),       # CGNAT / Tailscale
    ipaddress.ip_network("0.0.0.0/8"),           # "This" network
    ipaddress.ip_network("224.0.0.0/4"),         # Multicast
    ipaddress.ip_network("240.0.0.0/4"),         # Reserved (Class E)
    # ---- IPv6 ----
    ipaddress.ip_network("::1/128"),             # Loopback
    ipaddress.ip_network("fc00::/7"),            # ULA (fc00::/7 covers fd00::/8)
    ipaddress.ip_network("fe80::/10"),           # Link-local
    # ::ffff:0:0/96 is defence-in-depth only: the IPv4-mapped unwrap branch
    # above intercepts all ::ffff: addresses before the CIDR table, so this
    # entry never matches at runtime.  It is kept so that if the unwrap
    # branch is ever removed, the table still catches the range explicitly.
    ipaddress.ip_network("::ffff:0:0/96"),
    ipaddress.ip_network("2001:db8::/32"),       # Documentation
]


def _ip_is_denied(addr: str) -> bool:
    """Return True when the IP address must not be contacted.

    Checks membership in ``_DENIED_NETWORKS`` (primary control) AND the
    stdlib ``is_*`` predicates (backstop).  IPv4-mapped IPv6 addresses
    (``::ffff:A.B.C.D``) are unwrapped to their embedded IPv4 address and
    re-checked against the full denylist so that 169.254.169.254 embedded
    in an IPv6 address is still caught.  Unparseable addresses are denied.

    Args:
        addr: Dotted-decimal IPv4 or colon-separated IPv6 string.

    Returns:
        True when the address is denied (private, reserved, loopback, etc.).
    """
    try:
        ip = ipaddress.ip_address(addr)
    except ValueError:
        logger.warning("_ip_is_denied: unparseable address %r — denying", addr)
        return True

    # Unwrap IPv4-mapped IPv6 (::ffff:A.B.C.D) and re-check the embedded v4.
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        embedded = str(ip.ipv4_mapped)
        return _ip_is_denied(embedded)

    # Primary: explicit CIDR table check.
    for net in _DENIED_NETWORKS:
        if ip in net:
            return True

    # Backstop: stdlib flags catch anything the table misses.
    return (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_reserved
        or ip.is_multicast
        or ip.is_unspecified
    )


# ---------------------------------------------------------------------------
# B.1 — EgressVerdict + egress_check
# ---------------------------------------------------------------------------


class _EgressOutcome(str, Enum):
    """Disposition of an egress_check call."""

    ALLOW = "allow"
    HARD_BLOCK = "hard_block"   # non-https or IP denylist hit
    DEFERRED = "deferred"       # review domain (pending_review)


@dataclasses.dataclass
class EgressVerdict:
    """Result of egress_check for a single URL.

    Attributes:
        outcome: ALLOW, HARD_BLOCK, or DEFERRED.
        hostname: Parsed hostname from the URL.
        resolved_ips: All IPs the hostname resolved to.
        block_class: Taxonomy tag if blocked or deferred.
        detail: Human-readable reason string.
    """

    outcome: _EgressOutcome
    hostname: str = ""
    resolved_ips: List[str] = dataclasses.field(default_factory=list)
    block_class: Optional[str] = None
    detail: str = ""

    @property
    def allowed(self) -> bool:
        """Return True when egress is permitted."""
        return self.outcome == _EgressOutcome.ALLOW


def egress_check(  # pylint: disable=too-many-return-statements,too-many-locals
    url: str, config: "GlobalConfig"
) -> EgressVerdict:
    """Validate a URL against the denylist-primary SSRF policy.

    Steps:
    1. Scheme must be https.
    2. Hostname must be non-empty.
    3. Resolve hostname via getaddrinfo.
    4. If ANY resolved IP is denied → hard block (DNS-rebinding defence:
       a host resolving to BOTH public and denied IPs is also hard-blocked).
    5. If hostname is in ``unsubscribe_denied_domains`` → hard block.
    6. If hostname is in ``unsubscribe_review_domains`` AND NOT in
       ``unsubscribe_allowed_domains`` → deferred (pending_review).
    7. All-public + not denied-domain → allow.

    Args:
        url: Candidate URL to validate.
        config: GlobalConfig with denylist/review domain lists.

    Returns:
        EgressVerdict with outcome, resolved IPs, block_class and detail.
    """
    parsed = urllib.parse.urlparse(url)

    if parsed.scheme != "https":
        return EgressVerdict(
            outcome=_EgressOutcome.HARD_BLOCK,
            hostname=parsed.hostname or "",
            block_class="hard_policy",
            detail="scheme must be https (SSRF/egress policy)",
        )

    hostname = parsed.hostname or ""
    if not hostname:
        return EgressVerdict(
            outcome=_EgressOutcome.HARD_BLOCK,
            hostname="",
            block_class="hard_policy",
            detail="URL has no hostname",
        )

    # Named-domain denylist check (before DNS — avoids resolution of blocked names).
    denied_domains: List[str] = getattr(
        config, "unsubscribe_denied_domains", []
    ) or []
    if _host_in_list(hostname, denied_domains):
        return EgressVerdict(
            outcome=_EgressOutcome.HARD_BLOCK,
            hostname=hostname,
            block_class="hard_policy",
            detail=f"host {hostname} is in unsubscribe_denied_domains",
        )

    # DNS resolution + IP denylist.
    try:
        results = socket.getaddrinfo(hostname, None)
    except (socket.gaierror, OSError) as exc:
        logger.warning("egress_check: DNS resolution failed for %s: %s", hostname, exc)
        return EgressVerdict(
            outcome=_EgressOutcome.HARD_BLOCK,
            hostname=hostname,
            block_class="hard_policy",
            detail=f"DNS resolution failed: {exc}",
        )

    resolved_ips: List[str] = []
    denied_found = False
    public_found = False

    for _family, _type, _proto, _canonname, sockaddr in results:
        raw_addr = sockaddr[0]
        # Strip IPv4-mapped prefix for the resolved_ips list; _ip_is_denied
        # handles the unwrap internally.
        addr = raw_addr
        if addr.startswith("::ffff:"):
            addr = addr[7:]
        if addr not in resolved_ips:
            resolved_ips.append(addr)
        if _ip_is_denied(raw_addr):
            denied_found = True
            logger.warning(
                "egress_check: %s resolves to denied IP %s",
                hostname,
                addr,
            )
        else:
            public_found = True

    if denied_found:
        # DNS-rebinding defence: hard block even if public IPs also present.
        detail = (
            f"host {hostname} resolves to denied IP(s) {resolved_ips} "
            "(possible DNS-rebinding)"
            if public_found
            else f"host {hostname} resolves to denied IP(s) {resolved_ips}"
        )
        return EgressVerdict(
            outcome=_EgressOutcome.HARD_BLOCK,
            hostname=hostname,
            resolved_ips=resolved_ips,
            block_class="hard_policy",
            detail=detail,
        )

    # Review-domain check (runs AFTER IP check — IP denylist is primary).
    review_domains: List[str] = getattr(
        config, "unsubscribe_review_domains", []
    ) or []
    allowed_domains: List[str] = getattr(
        config, "unsubscribe_allowed_domains", []
    ) or []
    if _host_in_list(hostname, review_domains) and not _host_in_list(
        hostname, allowed_domains
    ):
        return EgressVerdict(
            outcome=_EgressOutcome.DEFERRED,
            hostname=hostname,
            resolved_ips=resolved_ips,
            block_class="pending_review",
            detail=(
                f"host {hostname} is in unsubscribe_review_domains; "
                "approve host in unsubscribe_allowed_domains to proceed"
            ),
        )

    return EgressVerdict(
        outcome=_EgressOutcome.ALLOW,
        hostname=hostname,
        resolved_ips=resolved_ips,
    )


# ---------------------------------------------------------------------------
# B.3 — IP-pinned HTTPS opener
# ---------------------------------------------------------------------------


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    """HTTPS connection that connects to a pre-validated IP.

    Resolves the rebinding/TOCTOU window: the IP we validated in egress_check
    is the IP we actually connect to.  The original ``Host:`` header and TLS
    SNI/cert-verification hostname remain the original domain name so
    certificate validation still checks the correct name.

    Args:
        host: Original hostname (used for TLS SNI and Host header).
        validated_ip: Pre-validated IP address to connect to.
        port: TCP port.
        timeout: Socket timeout in seconds.
        context: TLS context (must have check_hostname=True).
    """

    def __init__(  # pylint: disable=too-many-arguments,too-many-positional-arguments
        self,
        host: str,
        validated_ip: str,
        port: int,
        timeout: float,
        context: ssl.SSLContext,
    ) -> None:
        super().__init__(
            validated_ip,       # connect to the pinned IP, not the hostname
            port=port,
            timeout=timeout,
            context=context,
        )
        # _server_hostname_override holds the original domain name (not the
        # pinned IP).  Passed as server_hostname to wrap_socket so that both
        # SNI and TLS certificate hostname verification use the real domain
        # while the TCP connection targets the pre-validated IP.
        # NOTE: _original_host is intentionally absent — Host: header
        # routing uses self._server_hostname_override directly.
        self._server_hostname_override = host

    def connect(self) -> None:
        """Open a TCP+TLS connection to the validated IP.

        self.host is the pinned IP (set by super().__init__ with validated_ip).
        server_hostname=self._server_hostname_override passes the original
        domain to wrap_socket so that both SNI and TLS certificate hostname
        verification use the real domain name, not the raw IP.  check_hostname
        is never toggled: the SSLContext must have check_hostname=True for the
        entire duration of the handshake.
        """
        self.sock = socket.create_connection(
            (self.host, self.port), self.timeout
        )
        self.sock = self._context.wrap_socket(
            self.sock,
            server_hostname=self._server_hostname_override,
        )


class _PinnedHTTPSHandler(urllib.request.HTTPSHandler):
    """urllib handler that uses a pinned IP for the HTTPS connection."""

    def __init__(
        self,
        validated_ip: str,
        timeout: float,
        context: ssl.SSLContext,
    ) -> None:
        super().__init__(context=context)
        self._validated_ip = validated_ip
        self._timeout = timeout
        self._context = context

    def https_open(
        self, req: urllib.request.Request
    ) -> http.client.HTTPResponse:
        """Open an HTTPS connection pinned to the validated IP."""
        host = req.host
        port = 443
        if ":" in host:
            host, port_str = host.rsplit(":", 1)
            try:
                port = int(port_str)
            except ValueError:
                port = 443
        conn = _PinnedHTTPSConnection(
            host=host,
            validated_ip=self._validated_ip,
            port=port,
            timeout=self._timeout,
            context=self._context,
        )
        return self.do_open(  # type: ignore[return-value]
            lambda h, **kw: conn,  # type: ignore[arg-type]
            req,
        )


# ---------------------------------------------------------------------------
# Helper: domain list suffix matching
# ---------------------------------------------------------------------------


def _host_in_list(hostname: str, domain_list: List[str]) -> bool:
    """Return True if hostname suffix-matches any entry in domain_list.

    Suffix match on the registered-domain level, e.g. 'foo.benchurl.com'
    matches 'benchurl.com', and 'benchurl.com' matches 'benchurl.com'.

    Args:
        hostname: DNS hostname to check.
        domain_list: List of domain suffixes to match against.

    Returns:
        True when hostname is in the list.
    """
    hostname = hostname.lower().rstrip(".")
    for domain in domain_list:
        domain = domain.lower().rstrip(".")
        if hostname == domain or hostname.endswith("." + domain):
            return True
    return False


# Keep the old name for callers outside this module (mcp_server uses it indirectly
# via effective_unsubscribe_domains which is fine; the name is not exported in __all__).
_host_in_allowlist = _host_in_list


# ---------------------------------------------------------------------------
# Legacy allowlist helpers (kept as trust hints, no longer primary gates)
# ---------------------------------------------------------------------------

# These are historical reference lists. They are NO LONGER the primary SSRF
# control (the IP denylist is). They remain as:
#   - Trust hints: a host on unsubscribe_allowed_domains skips pending_review.
#   - Config fallback: effective_unsubscribe_domains / effective_mailto_domains
#     still surface them to callers (e.g. get_config in mcp_server.py).
_ALLOWED_UNSUBSCRIBE_DOMAINS: List[str] = [
    "res-marriott.com",
    "trk.notify.carsandstays.delta.com",
    "notify.carsandstays.delta.com",
    "linkedin.com",
    "thankyou.citi.com",
    "unsub.r.groupon.com",
    "groupon.com",
    "06.emailinboundprocessing.com",
    "benchurl.com",
    "l.info6.citi.com",
    "info6.citi.com",
    "manage.kmail-lists.com",
    "postmaster.uber.com",
    "dice.com",
    "unsub.apple.com",
    "campaign-preferences.com",
    "sqspmail.com",
]

# iCloud delivers mailto through smtp.mail.me.com; the SSRF surface for
# mailto is near-zero. These domains are kept as confidence hints only.
_ALLOWED_MAILTO_DOMAINS: List[str] = [
    "res-marriott.com",
    "thankyou.citi.com",
    "unsub.r.groupon.com",
    "notify.carsandstays.delta.com",
]

# Fixed subject used for all mailto unsubscribes; never trust header-supplied.
_MAILTO_SUBJECT = "Unsubscribe"


def effective_unsubscribe_domains(config: "GlobalConfig") -> List[str]:
    """Return the effective one-click unsubscribe domain allowlist (trust hints).

    When ``config.unsubscribe_allowed_domains`` is non-empty that list is
    returned as-is.  When it is empty the module-level
    ``_ALLOWED_UNSUBSCRIBE_DOMAINS`` list is returned so callers always see
    the real applied list.  Note: these are now TRUST HINTS for skipping
    pending_review, not primary egress gates.

    Args:
        config: Loaded GlobalConfig instance.

    Returns:
        Non-empty list of domain strings.
    """
    domains = getattr(config, "unsubscribe_allowed_domains", None)
    if domains:
        return list(domains)
    return list(_ALLOWED_UNSUBSCRIBE_DOMAINS)


def _effective_mailto_domains(config: "GlobalConfig") -> List[str]:
    """Return the effective mailto domain allowlist (private).

    Args:
        config: Loaded GlobalConfig instance.

    Returns:
        List of allowed mailto domain strings.
    """
    domains = getattr(config, "mailto_allowed_domains", None)
    if domains:
        return list(domains)
    return list(_ALLOWED_MAILTO_DOMAINS)


def effective_mailto_domains(config: "GlobalConfig") -> List[str]:
    """Return the effective mailto fallback domain allowlist (trust hints).

    Args:
        config: Loaded GlobalConfig instance.

    Returns:
        Non-empty list of allowed mailto domain strings.
    """
    return _effective_mailto_domains(config)


# ---------------------------------------------------------------------------
# B.4 — Revised mailto domain authorization
# ---------------------------------------------------------------------------


def _mailto_domain_authorized(  # pylint: disable=too-many-locals
    to_host: str,
    verified_sender_domain: str,
    config: "GlobalConfig",
    dry_run: bool = False,
) -> Tuple[bool, Optional[str]]:
    """Return (authorized, block_class) for a mailto target domain.

    Authorization is granted when ALL of these hold:
    1. The sender passed the DKIM/DMARC gate (enforced upstream; this
       function does not re-verify it).
    2. The target host is NOT in ``mailto_denied_domains``.
    3. The target host resolves to only public IPs (defence-in-depth;
       delivery is via iCloud SMTP but we still refuse private-IP targets).

    The old requirement that the target host match the sender domain OR appear
    in ``mailto_allowed_domains`` is demoted to a confidence note (logged) —
    it no longer gates authorization.  This unblocks cross-domain mailto
    targets like AWS Customer Council → na2.alida.com.

    Args:
        to_host: The domain part of the mailto To address.
        verified_sender_domain: DKIM/DMARC-verified From-domain.
        config: Loaded GlobalConfig instance.
        dry_run: When True, skip live DNS resolution.

    Returns:
        Tuple of (authorized: bool, block_class: Optional[str]).
        block_class is None when authorized, otherwise a taxonomy tag.
    """
    normalized_host = to_host.lower().rstrip(".") if to_host else ""

    # Gate 1: mailto_denied_domains hard-blocks the target host.
    mailto_denied: List[str] = getattr(
        config, "mailto_denied_domains", []
    ) or []
    if _host_in_list(normalized_host, mailto_denied):
        logger.warning(
            "_mailto_domain_authorized: host %s is in mailto_denied_domains",
            normalized_host,
        )
        return False, "hard_policy"

    # Confidence note: log whether target domain matches sender domain or
    # is in the legacy allowlist (informational only, not a gate).
    effective_mailto = _effective_mailto_domains(config)
    is_sender_match = (
        normalized_host and normalized_host == verified_sender_domain
    )
    is_in_legacy_list = _host_in_list(normalized_host, effective_mailto)
    if not is_sender_match and not is_in_legacy_list:
        logger.info(
            "_mailto_domain_authorized: host %s is cross-domain (sender=%s) "
            "and not in legacy allowlist — permitted (delivery via iCloud SMTP)",
            normalized_host,
            verified_sender_domain,
        )

    # Gate 2 (defence-in-depth): resolve the target host and reject if any
    # resolved IP is denied.  Delivery is via iCloud SMTP, so the connection
    # is to iCloud, not this host — but we still refuse private-IP targets
    # to avoid leaking information about reachable hosts.
    if not dry_run and normalized_host:
        try:
            results = socket.getaddrinfo(normalized_host, None)
        except (socket.gaierror, OSError) as exc:
            logger.warning(
                "_mailto_domain_authorized: DNS resolution failed for %s: %s "
                "— denying (fail-closed)",
                normalized_host,
                exc,
            )
            return False, "hard_policy"

        for _family, _type, _proto, _canonname, sockaddr in results:
            raw_addr = sockaddr[0]
            if _ip_is_denied(raw_addr):
                logger.warning(
                    "_mailto_domain_authorized: host %s resolves to denied IP %s "
                    "— blocking (defence-in-depth)",
                    normalized_host,
                    raw_addr,
                )
                return False, "hard_policy"

    return True, None


# ---------------------------------------------------------------------------
# B.5 — UnsubscribeResult with block_class taxonomy
# ---------------------------------------------------------------------------


@dataclasses.dataclass
class UnsubscribeResult:  # pylint: disable=too-many-instance-attributes
    """Result of an unsubscribe attempt.

    Attributes:
        sender: The sender email address.
        method: The unsubscribe method used.
        target: The URL or mailto address targeted.
        http_status: HTTP status code if applicable.
        result: Outcome of the attempt.
        dry_run: Whether this was a dry run.
        detail: Additional detail about the outcome.
        methods_attempted: Ordered list of methods tried.
        method_used: The method that produced a non-deferred result, if any.
        fallback_reason: Why a fallback was attempted, if applicable.
        block_class: Taxonomy tag for the block type, if any.
            Values: "retryable", "pending_review", "hard_policy",
            "no_mechanism", "auth_failed".
        remediation: Human-readable guidance for the block_class.
        final_url: The final (post-redirect) URL actually reached, when
            ``capture_body`` was requested on a live one-click call.
            None for calls that did not request body capture.
        body_capture: Up to ``max_capture_bytes`` of the response body,
            decoded best-effort as text, when ``capture_body=True`` was
            passed to ``unsubscribe_one_click``. None otherwise (including
            the default header-only path, which never reads the body).
    """

    sender: str
    method: str  # "one-click" | "mailto" | "deferred" | "none"
    target: str
    http_status: Optional[int]
    result: str  # "success" | "failed" | "deferred" | "success-simulated"
    dry_run: bool
    detail: str = ""
    methods_attempted: List[str] = dataclasses.field(default_factory=list)
    method_used: Optional[str] = None
    fallback_reason: Optional[str] = None
    block_class: Optional[str] = None
    remediation: Optional[str] = None
    final_url: Optional[str] = None
    body_capture: Optional[str] = None


# Remediation strings keyed by block_class.
_REMEDIATION: dict = {
    "retryable": "retry later; transient transport or server error",
    "pending_review": "approve target host in unsubscribe_allowed_domains in config",
    "hard_policy": (
        "blocked by SSRF/egress policy; not retryable — "
        "check unsubscribe_denied_domains or IP denylist"
    ),
    "no_mechanism": "no List-Unsubscribe header found",
    "auth_failed": "sender failed DKIM/DMARC authentication",
}


def _make_block_result(  # pylint: disable=too-many-arguments,too-many-positional-arguments
    sender: str,
    method: str,
    target: str,
    dry_run: bool,
    block_class: str,
    detail: str,
    http_status: Optional[int] = None,
) -> "UnsubscribeResult":
    """Construct a deferred/failed UnsubscribeResult with block_class wiring.

    Args:
        sender: Sender email address.
        method: Method string (e.g. "one-click").
        target: Safe target string.
        dry_run: Whether in dry-run mode.
        block_class: Taxonomy tag.
        detail: Human-readable reason.
        http_status: HTTP status code if applicable.

    Returns:
        UnsubscribeResult with result, block_class, and remediation populated.
    """
    result_str = "deferred"
    return UnsubscribeResult(
        sender=sender,
        method=method,
        target=target,
        http_status=http_status,
        result=result_str,
        dry_run=dry_run,
        detail=detail,
        block_class=block_class,
        remediation=_REMEDIATION.get(block_class),
    )


def _safe_target_str(url: str) -> str:
    """Return a token-scrubbed target string for audit storage.

    Stores host + sha256 hex of the full URL so the record is traceable
    without exposing tokenized query strings.

    Args:
        url: Full URL string.

    Returns:
        'host:<hostname> sha256:<hex>' string.
    """
    parsed = urllib.parse.urlparse(url)
    host = parsed.hostname or ""
    digest = hashlib.sha256(url.encode("utf-8", errors="replace")).hexdigest()
    return f"host:{host} sha256:{digest}"


# ---------------------------------------------------------------------------
# B.3 — Redirect-following one-click with per-hop egress_check + IP pinning
# ---------------------------------------------------------------------------

# Hard ceiling on how much of a probed/one-click response body is ever read
# into memory, regardless of what a caller or an operator misconfig (e.g.
# GlobalConfig.probe_max_capture_bytes) requests. This is a backstop of last
# resort — GlobalConfig.load_config already clamps probe_max_capture_bytes at
# load time — enforced again here so no code path (present or future) can
# balloon memory by reading an oversized response body. Mirrors the spirit of
# body_links._EXCERPT_HARD_CAP_BYTES.
_CAPTURE_HARD_CAP_BYTES = 4 * 1024 * 1024  # 4 MiB


def unsubscribe_one_click(  # pylint: disable=too-many-return-statements,too-many-branches,too-many-statements,too-many-locals,too-many-arguments,too-many-positional-arguments
    sender: str,
    url: str,
    dry_run: bool,
    timeout: int = 30,
    config: Optional["GlobalConfig"] = None,
    allowed_domains: Optional[List[str]] = None,
    http_method: str = "POST",
    capture_body: bool = False,
    max_capture_bytes: int = 65536,
) -> "UnsubscribeResult":
    """Execute an RFC 8058 one-click unsubscribe via HTTPS POST (or GET probe).

    The URL is validated by ``egress_check`` before any I/O.  Redirects are
    followed up to ``config.egress.max_redirects`` hops; each hop's target
    URL is independently validated and its resolved IP is pinned before
    connecting so the IP we validate is the IP we connect to (B2+B3).

    Args:
        sender: The sender email address being unsubscribed.
        url: The one-click unsubscribe URL. Must be HTTPS.
        dry_run: If True, simulate without any network I/O.
        timeout: Socket timeout in seconds (overridden by config.egress
            when config is provided).
        config: GlobalConfig for egress policy. When None a minimal
            pass-through config is created.
        allowed_domains: Legacy parameter kept for backward compatibility;
            when provided the list is used only as a trust hint (same as
            config.unsubscribe_allowed_domains).
        http_method: "POST" (default) sends the RFC 8058
            ``List-Unsubscribe=One-Click`` body exactly as before. "GET"
            sends no request body at all (used by the Phase 1.5 landing
            page probe, which must not trigger a one-click action solely
            by fetching the page).
        capture_body: When True, read up to ``max_capture_bytes`` of the
            final response body and attach it to
            ``UnsubscribeResult.body_capture``. The default header-only
            path (capture_body=False) never calls ``response.read()``, so
            existing callers are unaffected.
        max_capture_bytes: Upper bound in bytes on the captured response
            body when ``capture_body=True``. Ignored otherwise. Clamped to
            _CAPTURE_HARD_CAP_BYTES regardless of the value requested.

    Returns:
        UnsubscribeResult describing the outcome.
    """
    assert_writes_allowed("one-click unsubscribe egress")
    # Build a minimal config stand-in when none is provided (backward compat).
    if config is None:
        config = _FallbackConfig(
            allowed_domains=allowed_domains or _ALLOWED_UNSUBSCRIBE_DOMAINS
        )
    elif allowed_domains is not None:
        # Merge caller-provided allowed_domains as trust hints into config.
        config = _FallbackConfig(
            allowed_domains=allowed_domains,
            _base=config,
        )

    effective_timeout = int(
        getattr(getattr(config, "egress", None), "http_timeout_seconds", timeout)
    )
    max_redirects = int(
        getattr(getattr(config, "egress", None), "max_redirects", 3)
    )

    safe_target = _safe_target_str(url)

    verdict = egress_check(url, config)
    if not verdict.allowed:
        logger.warning(
            "egress_check: %s for %s (host=%s)",
            verdict.detail,
            sender,
            verdict.hostname,
        )
        return _make_block_result(
            sender=sender,
            method="one-click",
            target=safe_target,
            dry_run=dry_run,
            block_class=verdict.block_class or "hard_policy",
            detail=verdict.detail,
        )

    if dry_run:
        logger.info(
            "DRY RUN: would %s one-click unsubscribe for %s to host=%s",
            http_method,
            sender,
            verdict.hostname,
        )
        return UnsubscribeResult(
            sender=sender,
            method="one-click",
            target=safe_target,
            http_status=None,
            result="success-simulated",
            dry_run=True,
        )

    # Live path: IP-pinned connection with redirect follow + per-hop re-check.
    current_url = url
    hops_remaining = max_redirects

    while True:
        # Fresh TLS context per hop: nothing mutates it, but a new context
        # per hop ensures that per-session state (tickets, resumption) from
        # one hop cannot influence the next, and removes any risk of a
        # misbehaving server fingerprinting us across hops.
        tls_ctx = ssl.create_default_context()

        hop_parsed = urllib.parse.urlparse(current_url)
        hop_hostname = hop_parsed.hostname or ""

        # Pin the validated IP: re-resolve per hop (no cached IPs).
        # The double DNS resolution (egress_check + here) is intentional:
        # using the freshest resolution as the pin closes the TOCTOU window
        # between the initial check and the actual connection.
        try:
            hop_results = socket.getaddrinfo(hop_hostname, None)
        except (socket.gaierror, OSError) as exc:
            logger.warning(
                "Hop DNS failed for %s (sender=%s): %s",
                hop_hostname, sender, exc,
            )
            return _make_block_result(
                sender=sender,
                method="one-click",
                target=safe_target,
                dry_run=False,
                block_class="hard_policy",
                detail=f"DNS resolution failed at hop: {exc}",
            )

        # Use the first non-denied address as the pinned IP.
        pinned_ip: Optional[str] = None
        for _fam, _typ, _proto, _cn, sockaddr in hop_results:
            candidate = sockaddr[0]
            if not _ip_is_denied(candidate):
                pinned_ip = candidate
                break

        if pinned_ip is None:
            return _make_block_result(
                sender=sender,
                method="one-click",
                target=safe_target,
                dry_run=False,
                block_class="hard_policy",
                detail=(
                    f"all resolved IPs for {hop_hostname} are denied "
                    "(IP-pin validation failed)"
                ),
            )

        if http_method == "GET":
            req = urllib.request.Request(
                current_url,
                data=None,
                method="GET",
                headers={
                    "User-Agent": "mail-cleaner/1.0",
                    "Host": hop_hostname,
                },
            )
        else:
            req = urllib.request.Request(
                current_url,
                data=b"List-Unsubscribe=One-Click",
                method="POST",
                headers={
                    "Content-Type": "application/x-www-form-urlencoded",
                    "User-Agent": "mail-cleaner/1.0",
                    "Host": hop_hostname,
                },
            )

        pinned_handler = _PinnedHTTPSHandler(
            validated_ip=pinned_ip,
            timeout=effective_timeout,
            context=tls_ctx,
        )
        # Disable the default redirect handler so we control redirect following.
        opener = urllib.request.build_opener(
            pinned_handler,
            _NoRedirectHandler(),
        )

        try:
            with opener.open(req, timeout=effective_timeout) as response:
                status = response.status
                logger.info(
                    "One-click unsubscribe for %s returned HTTP %d (host=%s)",
                    sender,
                    status,
                    hop_hostname,
                )
                body_capture: Optional[str] = None
                if capture_body:
                    read_limit = min(
                        max(max_capture_bytes, 0), _CAPTURE_HARD_CAP_BYTES
                    )
                    raw_body = response.read(read_limit)
                    body_capture = raw_body.decode("utf-8", errors="replace")
                return UnsubscribeResult(
                    sender=sender,
                    method="one-click",
                    target=safe_target,
                    http_status=status,
                    result="success",
                    dry_run=False,
                    final_url=current_url if capture_body else None,
                    body_capture=body_capture,
                )

        except urllib.error.HTTPError as exc:
            if 300 <= exc.code < 400:
                if hops_remaining <= 0:
                    logger.warning(
                        "max_redirects exceeded for %s (host=%s)",
                        sender,
                        hop_hostname,
                    )
                    return _make_block_result(
                        sender=sender,
                        method="one-click",
                        target=safe_target,
                        dry_run=False,
                        block_class="retryable",
                        detail=(
                            f"max_redirects ({max_redirects}) exceeded; "
                            "redirect chain too long"
                        ),
                        http_status=exc.code,
                    )

                location = exc.headers.get("Location", "")
                if not location:
                    return _make_block_result(
                        sender=sender,
                        method="one-click",
                        target=safe_target,
                        dry_run=False,
                        block_class="retryable",
                        detail=f"redirect {exc.code} with no Location header",
                        http_status=exc.code,
                    )

                # Resolve relative redirects.
                next_url = urllib.parse.urljoin(current_url, location)

                # Per-hop egress_check on the redirect target.
                hop_verdict = egress_check(next_url, config)
                if not hop_verdict.allowed:
                    logger.warning(
                        "Redirect target blocked by egress_check for %s: %s",
                        sender,
                        hop_verdict.detail,
                    )
                    return _make_block_result(
                        sender=sender,
                        method="one-click",
                        target=safe_target,
                        dry_run=False,
                        block_class=hop_verdict.block_class or "hard_policy",
                        detail=(
                            f"redirect target blocked: {hop_verdict.detail}"
                        ),
                        http_status=exc.code,
                    )

                current_url = next_url
                hops_remaining -= 1
                continue

            # Non-redirect HTTP error.
            is_retryable = exc.code >= 500
            logger.warning(
                "HTTP error during one-click unsubscribe for %s (host=%s): %s",
                sender,
                hop_hostname,
                exc,
            )
            return UnsubscribeResult(
                sender=sender,
                method="one-click",
                target=safe_target,
                http_status=exc.code,
                result="failed",
                dry_run=False,
                detail=str(exc),
                block_class="retryable" if is_retryable else None,
                remediation=(
                    _REMEDIATION["retryable"] if is_retryable else None
                ),
            )

        except urllib.error.URLError as exc:
            logger.warning(
                "URL error during one-click unsubscribe for %s (host=%s): %s",
                sender,
                hop_hostname,
                exc,
            )
            return UnsubscribeResult(
                sender=sender,
                method="one-click",
                target=safe_target,
                http_status=None,
                result="failed",
                dry_run=False,
                detail=str(exc),
                block_class="retryable",
                remediation=_REMEDIATION["retryable"],
            )

        except http.client.HTTPException as exc:
            logger.warning(
                "HTTP client error during one-click unsubscribe for %s "
                "(host=%s): %s",
                sender,
                hop_hostname,
                exc,
            )
            return UnsubscribeResult(
                sender=sender,
                method="one-click",
                target=safe_target,
                http_status=None,
                result="failed",
                dry_run=False,
                detail=str(exc),
                block_class="retryable",
                remediation=_REMEDIATION["retryable"],
            )

        except socket.timeout as exc:
            logger.warning(
                "Timeout during one-click unsubscribe for %s (host=%s): %s",
                sender,
                hop_hostname,
                exc,
            )
            return UnsubscribeResult(
                sender=sender,
                method="one-click",
                target=safe_target,
                http_status=None,
                result="failed",
                dry_run=False,
                detail="connection timed out",
                block_class="retryable",
                remediation=_REMEDIATION["retryable"],
            )

        except OSError as exc:
            logger.warning(
                "OS error during one-click unsubscribe for %s (host=%s): %s",
                sender,
                hop_hostname,
                exc,
            )
            return UnsubscribeResult(
                sender=sender,
                method="one-click",
                target=safe_target,
                http_status=None,
                result="failed",
                dry_run=False,
                detail=str(exc),
                block_class="retryable",
                remediation=_REMEDIATION["retryable"],
            )


class _NoRedirectHandler(urllib.request.HTTPErrorProcessor):
    """Raise HTTPError for 3xx redirects instead of following them.

    This gives the redirect-follow loop in unsubscribe_one_click explicit
    control over each hop so egress_check can validate each target.
    """

    def http_response(
        self,
        request: urllib.request.Request,
        response: http.client.HTTPResponse,
    ) -> http.client.HTTPResponse:
        """Raise HTTPError for redirects, pass through other responses."""
        if 300 <= response.status < 400:
            raise urllib.error.HTTPError(
                request.full_url,
                response.status,
                "Redirect intercepted",
                response.headers,
                response,
            )
        return super().http_response(request, response)

    https_response = http_response


# Keep the old class name alive for any callers that reference it by name.
NoRedirectHandler = _NoRedirectHandler


# ---------------------------------------------------------------------------
# B.4 — mailto unsubscribe with SMTP timeout
# ---------------------------------------------------------------------------


def unsubscribe_mailto(  # pylint: disable=too-many-arguments,too-many-positional-arguments,too-many-return-statements,too-many-locals,too-many-branches,too-many-statements
    sender: str,
    mailto_uri: str,
    smtp_host: str,
    smtp_port: int,
    username: str,
    password: str,
    dry_run: bool,
    config: Optional["GlobalConfig"] = None,
    verified_sender_domain: str = "",
) -> "UnsubscribeResult":
    """Send an unsubscribe request via a mailto URI.

    Validates the to_address is a single well-formed RFC 5322 address.  The
    target host is authorized by ``_mailto_domain_authorized`` (not by the
    legacy domain-match allowlist gate — see B.4 rationale).  Uses a fixed
    subject line (_MAILTO_SUBJECT) to ignore any attacker-controlled subject.
    Connects to the SMTP server with STARTTLS; refuses plaintext.  SMTP
    timeout is controlled by config.egress.smtp_timeout_seconds.

    Args:
        sender: The sender email address being unsubscribed.
        mailto_uri: The mailto: URI from List-Unsubscribe.
        smtp_host: SMTP server hostname.
        smtp_port: SMTP server port (typically 587 for STARTTLS).
        username: SMTP authentication username.
        password: SMTP authentication password. Never logged.
        dry_run: If True, simulate without any network I/O.
        config: GlobalConfig for policy. When None, uses liberal defaults.
        verified_sender_domain: DKIM/DMARC-verified From-domain.

    Returns:
        UnsubscribeResult describing the outcome.
    """
    smtp_timeout = 30
    if config is not None:
        smtp_timeout = int(
            getattr(
                getattr(config, "egress", None),
                "smtp_timeout_seconds",
                30,
            )
        )

    parsed = urllib.parse.urlparse(mailto_uri)
    to_address = parsed.path.strip()

    parsed_addrs = email.utils.getaddresses([to_address])
    if len(parsed_addrs) != 1 or not parsed_addrs[0][1]:
        logger.warning(
            "mailto unsubscribe for %s has invalid to_address %r — skipped",
            sender,
            to_address,
        )
        return _make_block_result(
            sender=sender,
            method="mailto",
            target="invalid-to-address",
            dry_run=dry_run,
            block_class="hard_policy",
            detail="mailto to_address is not a single valid address",
        )

    _, to_addr_clean = parsed_addrs[0]
    if "@" not in to_addr_clean:
        logger.warning(
            "mailto unsubscribe for %s has no '@' in address %r — skipped",
            sender,
            to_addr_clean,
        )
        return _make_block_result(
            sender=sender,
            method="mailto",
            target="invalid-to-address",
            dry_run=dry_run,
            block_class="hard_policy",
            detail="mailto to_address has no '@' — not a valid email address",
        )
    to_host = to_addr_clean.split("@", 1)[-1]

    # B.4: authorization via _mailto_domain_authorized (not legacy allowlist gate).
    cfg_for_auth = config if config is not None else _FallbackConfig()
    authorized, auth_block_class = _mailto_domain_authorized(
        to_host,
        verified_sender_domain,
        cfg_for_auth,
        dry_run=dry_run,
    )
    if not authorized:
        logger.warning(
            "mailto target host %s for %s refused: block_class=%s",
            to_host,
            sender,
            auth_block_class,
        )
        return _make_block_result(
            sender=sender,
            method="mailto",
            target=f"host:{to_host}",
            dry_run=dry_run,
            block_class=auth_block_class or "hard_policy",
            detail=f"mailto host {to_host} blocked by egress policy",
        )

    subject = _MAILTO_SUBJECT

    if dry_run:
        logger.info(
            "DRY RUN: would send mailto unsubscribe for %s to host=%s",
            sender,
            to_host,
        )
        return UnsubscribeResult(
            sender=sender,
            method="mailto",
            target=f"host:{to_host}",
            http_status=None,
            result="success-simulated",
            dry_run=True,
        )

    msg = email.message.EmailMessage()
    msg["From"] = username
    msg["To"] = to_addr_clean
    msg["Subject"] = subject
    msg.set_content("Unsubscribe")

    assert_writes_allowed("mailto unsubscribe SMTP send")
    smtp: Optional[smtplib.SMTP] = None
    try:
        smtp = smtplib.SMTP(smtp_host, smtp_port, timeout=smtp_timeout)
        smtp.ehlo()

        tls_ctx = ssl.create_default_context()
        try:
            smtp.starttls(context=tls_ctx)
        except smtplib.SMTPException as exc:
            logger.error(
                "STARTTLS failed for mailto unsubscribe %s: %s — "
                "refusing plaintext transmission",
                sender,
                exc,
            )
            return UnsubscribeResult(
                sender=sender,
                method="mailto",
                target=f"host:{to_host}",
                http_status=None,
                result="failed",
                dry_run=False,
                detail="STARTTLS failed; plaintext refused",
                block_class="retryable",
                remediation=_REMEDIATION["retryable"],
            )

        smtp.ehlo()
        smtp.login(username, password)
        smtp.send_message(msg)
        logger.info(
            "Mailto unsubscribe sent for %s to host=%s", sender, to_host
        )
        return UnsubscribeResult(
            sender=sender,
            method="mailto",
            target=f"host:{to_host}",
            http_status=None,
            result="success",
            dry_run=False,
        )

    except smtplib.SMTPException as exc:
        logger.warning(
            "SMTP error during mailto unsubscribe for %s: %s", sender, exc,
        )
        return UnsubscribeResult(
            sender=sender,
            method="mailto",
            target=f"host:{to_host}",
            http_status=None,
            result="failed",
            dry_run=False,
            detail=str(exc),
            block_class="retryable",
            remediation=_REMEDIATION["retryable"],
        )

    except ssl.SSLError as exc:
        logger.warning(
            "SSL error during mailto unsubscribe for %s: %s", sender, exc,
        )
        return UnsubscribeResult(
            sender=sender,
            method="mailto",
            target=f"host:{to_host}",
            http_status=None,
            result="failed",
            dry_run=False,
            detail=str(exc),
            block_class="retryable",
            remediation=_REMEDIATION["retryable"],
        )

    except OSError as exc:
        logger.warning(
            "OS error during mailto unsubscribe for %s: %s", sender, exc,
        )
        return UnsubscribeResult(
            sender=sender,
            method="mailto",
            target=f"host:{to_host}",
            http_status=None,
            result="failed",
            dry_run=False,
            detail=str(exc),
            block_class="retryable",
            remediation=_REMEDIATION["retryable"],
        )

    finally:
        if smtp is not None:
            try:
                smtp.quit()
            except smtplib.SMTPException:
                pass


# ---------------------------------------------------------------------------
# Minimal fallback config stand-in (internal only)
# ---------------------------------------------------------------------------


class _FallbackConfig:  # pylint: disable=too-few-public-methods
    """Minimal GlobalConfig stand-in for backward-compat callers.

    Only used when no config is provided to unsubscribe_one_click or
    unsubscribe_mailto.  Not exposed publicly.
    """

    def __init__(
        self,
        allowed_domains: Optional[List[str]] = None,
        denied_domains: Optional[List[str]] = None,
        _base: Optional["GlobalConfig"] = None,
    ) -> None:
        self.dry_run = getattr(_base, "dry_run", False)
        self.unsubscribe_allowed_domains = (
            allowed_domains
            if allowed_domains is not None
            else getattr(_base, "unsubscribe_allowed_domains", [])
        )
        self.unsubscribe_denied_domains = (
            denied_domains
            if denied_domains is not None
            else getattr(_base, "unsubscribe_denied_domains", [])
        )
        self.unsubscribe_review_domains = getattr(
            _base, "unsubscribe_review_domains", []
        )
        self.mailto_allowed_domains = getattr(
            _base, "mailto_allowed_domains", []
        )
        self.mailto_denied_domains = getattr(
            _base, "mailto_denied_domains", []
        )
        self.egress = getattr(_base, "egress", None)


# ---------------------------------------------------------------------------
# perform_unsubscribe — orchestration with prefer_mailto (B4)
# ---------------------------------------------------------------------------


def perform_unsubscribe(  # pylint: disable=too-many-arguments,too-many-positional-arguments,too-many-locals,too-many-branches,too-many-statements,too-many-return-statements
    sender: str,
    unsubscribe_header: str,
    unsubscribe_post_header: str,
    global_config: "GlobalConfig",
    smtp_username: str,
    smtp_password: str,
    allowed_domains: Optional[List[str]] = None,
    verified_sender_domain: Optional[str] = None,
) -> "UnsubscribeResult":
    """Determine and execute the best available unsubscribe method.

    B4 routing logic:
    - When ``prefer_mailto`` is True (config default) AND a mailto URI is
      present AND the sender passed DKIM/DMARC (verified_sender_domain set),
      mailto is tried FIRST.
    - If mailto is unavailable or the sender is not authenticated, falls back
      to one-click (with full egress_check).
    - When one-click is deferred for a pending_review reason and a mailto URI
      is available, mailto is attempted as a fallback.

    DKIM/DMARC is fail-closed upstream; this function trusts the caller to
    only pass a non-empty verified_sender_domain when auth has passed.

    Args:
        sender: The sender email address.
        unsubscribe_header: Value of the List-Unsubscribe header.
        unsubscribe_post_header: Value of the List-Unsubscribe-Post header.
        global_config: Global policy configuration including dry_run flag.
        smtp_username: SMTP login username for mailto fallback.
        smtp_password: SMTP login password. Never logged.
        allowed_domains: Override the one-click domain allowlist (trust hint).
        verified_sender_domain: DKIM/DMARC-verified sender domain.  Non-empty
            signals that sender auth passed.

    Returns:
        UnsubscribeResult describing which method was used and its outcome.
    """
    dry_run = global_config.dry_run
    vsd = verified_sender_domain or ""

    # Merge caller-provided allowed_domains as a trust hint.
    effective_config = global_config
    if allowed_domains is not None:
        effective_config = _FallbackConfig(
            allowed_domains=allowed_domains,
            _base=global_config,
        )

    prefer_mailto: bool = getattr(
        getattr(global_config, "egress", None), "prefer_mailto", True
    )

    method = determine_unsubscribe_method(
        unsubscribe_header, unsubscribe_post_header
    )

    if method in ("one-click", "mailto"):
        https_urls, mailto_uris = extract_urls_from_list_unsubscribe(
            unsubscribe_header
        )
    else:
        https_urls, mailto_uris = [], []

    # B4: prefer mailto when present, sender authed, and prefer_mailto=True.
    sender_authed = bool(vsd)
    mailto_first = (
        prefer_mailto
        and sender_authed
        and bool(mailto_uris)
        and method in ("one-click", "mailto")
    )

    if mailto_first:
        mailto_result = unsubscribe_mailto(
            sender=sender,
            mailto_uri=mailto_uris[0],
            smtp_host="smtp.mail.me.com",
            smtp_port=587,
            username=smtp_username,
            password=smtp_password,
            dry_run=dry_run,
            config=global_config,
            verified_sender_domain=vsd,
        )
        mailto_result.methods_attempted = ["mailto"]
        mailto_result.method_used = (
            "mailto"
            if mailto_result.result not in ("deferred", "failed")
            else None
        )
        if mailto_result.result in ("success", "success-simulated"):
            logger.info(
                "prefer_mailto: mailto succeeded for %s (method_used=mailto)",
                sender,
            )
            return mailto_result

        # Mailto failed/deferred — fall through to one-click if available.
        logger.info(
            "prefer_mailto: mailto failed for %s (%s), "
            "trying one-click fallback",
            sender,
            mailto_result.detail,
        )
        if not https_urls:
            mailto_result.methods_attempted = ["mailto"]
            return mailto_result

        one_click_result = unsubscribe_one_click(
            sender=sender,
            url=https_urls[0],
            dry_run=dry_run,
            config=effective_config,
        )
        one_click_result.methods_attempted = ["mailto", "one-click"]
        one_click_result.method_used = (
            "one-click"
            if one_click_result.result not in ("deferred", "failed")
            else None
        )
        one_click_result.fallback_reason = (
            f"mailto failed: {mailto_result.detail}"
        )
        return one_click_result

    # Standard routing: one-click first, mailto as fallback.
    if method == "one-click":
        if not https_urls:
            logger.warning(
                "one-click method determined but no HTTPS URL found for %s",
                sender,
            )
            return _make_block_result(
                sender=sender,
                method="one-click",
                target="",
                dry_run=dry_run,
                block_class="no_mechanism",
                detail="no HTTPS URL found for one-click",
            )

        one_click_result = unsubscribe_one_click(
            sender=sender,
            url=https_urls[0],
            dry_run=dry_run,
            config=effective_config,
        )
        one_click_result.methods_attempted = ["one-click"]
        one_click_result.method_used = (
            "one-click"
            if one_click_result.result not in ("deferred", "failed")
            else None
        )

        # Mailto fallback: fire when one-click is pending_review deferred
        # and a mailto URI is available.
        _is_pending_review = (
            one_click_result.result == "deferred"
            and one_click_result.block_class == "pending_review"
            and bool(mailto_uris)
        )
        if _is_pending_review:
            fallback_reason = (
                f"one-click pending_review: {one_click_result.detail}"
            )
            logger.info(
                "Attempting mailto fallback for %s (one-click pending_review)",
                sender,
            )
            mailto_result = unsubscribe_mailto(
                sender=sender,
                mailto_uri=mailto_uris[0],
                smtp_host="smtp.mail.me.com",
                smtp_port=587,
                username=smtp_username,
                password=smtp_password,
                dry_run=dry_run,
                config=global_config,
                verified_sender_domain=vsd,
            )
            mailto_result.methods_attempted = ["one-click", "mailto"]
            mailto_result.method_used = (
                "mailto"
                if mailto_result.result not in ("deferred", "failed")
                else None
            )
            mailto_result.fallback_reason = fallback_reason
            logger.info(
                "mailto fallback for %s: result=%s block_class=%s",
                sender,
                mailto_result.result,
                mailto_result.block_class,
            )
            return mailto_result

        # Legacy: also fire fallback when detail contains the old phrase
        # "not in unsubscribe_allowed_domains" (handles tests/callers that
        # still inject old-style deferred results without block_class).
        _is_legacy_allowlist_block = (
            one_click_result.result == "deferred"
            and bool(mailto_uris)
            and "not in unsubscribe_allowed_domains" in one_click_result.detail
            and "SSRF" not in one_click_result.detail
        )
        if _is_legacy_allowlist_block:
            fallback_reason = (
                f"one-click blocked: {one_click_result.detail}"
            )
            logger.info(
                "Attempting mailto fallback for %s (legacy allowlist block)",
                sender,
            )
            # Extract to_host for authorization check.
            parsed_mailto = urllib.parse.urlparse(mailto_uris[0])
            to_addr_raw = parsed_mailto.path.strip()
            parsed_addrs = email.utils.getaddresses([to_addr_raw])
            to_host_fb = ""
            if parsed_addrs and parsed_addrs[0][1]:
                _, to_addr_clean = parsed_addrs[0]
                to_host_fb = (
                    to_addr_clean.split("@", 1)[-1]
                    if "@" in to_addr_clean
                    else ""
                )

            authorized_fb, _ = _mailto_domain_authorized(
                to_host_fb, vsd, global_config, dry_run=dry_run
            )
            if not authorized_fb:
                logger.warning(
                    "mailto fallback for %s refused: host %s not authorized",
                    sender,
                    to_host_fb,
                )
                one_click_result.methods_attempted = [
                    "one-click",
                    "mailto-refused",
                ]
                one_click_result.fallback_reason = fallback_reason
                return one_click_result

            mailto_result = unsubscribe_mailto(
                sender=sender,
                mailto_uri=mailto_uris[0],
                smtp_host="smtp.mail.me.com",
                smtp_port=587,
                username=smtp_username,
                password=smtp_password,
                dry_run=dry_run,
                config=global_config,
                verified_sender_domain=vsd,
            )
            mailto_result.methods_attempted = ["one-click", "mailto"]
            mailto_result.method_used = (
                "mailto"
                if mailto_result.result not in ("deferred", "failed")
                else None
            )
            mailto_result.fallback_reason = fallback_reason
            logger.info(
                "mailto fallback for %s: result=%s",
                sender,
                mailto_result.result,
            )
            return mailto_result

        return one_click_result

    if method == "mailto":
        if not mailto_uris:
            logger.warning(
                "mailto method determined but no mailto URI found for %s",
                sender,
            )
            return _make_block_result(
                sender=sender,
                method="mailto",
                target="",
                dry_run=dry_run,
                block_class="no_mechanism",
                detail="no mailto URI found",
            )
        result = unsubscribe_mailto(
            sender=sender,
            mailto_uri=mailto_uris[0],
            smtp_host="smtp.mail.me.com",
            smtp_port=587,
            username=smtp_username,
            password=smtp_password,
            dry_run=dry_run,
            config=global_config,
            verified_sender_domain=vsd,
        )
        result.methods_attempted = ["mailto"]
        result.method_used = (
            "mailto" if result.result not in ("deferred", "failed") else None
        )
        return result

    if method == "http-only":
        logger.info(
            "Deferring unsubscribe for %s: http-only links not followed",
            sender,
        )
        return _make_block_result(
            sender=sender,
            method="deferred",
            target="",
            dry_run=dry_run,
            block_class="hard_policy",
            detail="http-only links not followed (SSRF risk)",
        )

    logger.info("No unsubscribe mechanism found for %s", sender)
    result = _make_block_result(
        sender=sender,
        method="none",
        target="",
        dry_run=dry_run,
        block_class="no_mechanism",
        detail="no unsubscribe mechanism found",
    )
    result.methods_attempted = ["none"]
    return result
