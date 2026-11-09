# Architectural Decisions

ADRs for icloud-helper. Newest considerations appended; keep all entries.

### ADR-001: Deterministic core does irreversible actions; the model orchestrates (2026-06-12)

**Context:**
- A small local model (openclaw/gemma) should not make unattended, irreversible mail decisions.

**Decision:**
- All irreversible actions live in deterministic, audited Python (allowlist-gated, dry-run default, SQLite audit). The model only orchestrates and proposes.

**Consequences:**
- ✅ Safety/auditability independent of model quality.
- ✅ Later extended (ADR-009) so the model does judgment but the core still gates execution.

### ADR-002: Allowlist-only policy (2026-06-12)

**Decision:**
- The autonomous actor only acts on senders explicitly in `policy.toml` (`action=unsubscribe|keep`). Unknown senders go to a pending queue + notification, never auto-actioned.

**Consequences:**
- ✅ No surprise actions on new senders. ❌ New senders need manual approval (acceptable).

### ADR-003: Soft-delete only — never EXPUNGE (2026-06-12, reaffirmed 2026-06-29)

**Decision:**
- "Delete" = IMAP MOVE to the iCloud trash (`"Deleted Messages"`). The project NEVER issues EXPUNGE. COPY+`\Deleted` fallback leaves a recoverable struck-through copy if MOVE is unsupported. Gated by `allow_delete`.

**Consequences:**
- ✅ Fully reversible. ✅ Enforced by an AST-checked "no expunge" test.

### ADR-004: Dry-run is the default; only the cron goes live (2026-06-12)

**Decision:**
- `config.dry_run=true`. Manual/MCP runs simulate. Only the nightly cron passes `--no-dry-run`. (See ADR-010 for the model-judgment live path, which uses a separate switch.)

### ADR-005: DKIM/DMARC sender-auth gate (2026-06-12)

**Decision:**
- Before any destructive action triggered by sender identity, require `Authentication-Results` with `dmarc=pass` from a trusted `authserv-id` (only `icloud.com`/subdomains). `From` is forgeable. Implemented in `auth.py`, enforced per-UID.

### ADR-006: SSRF guards on unsubscribe (2026-06-12)

**Decision:**
- One-click unsubscribe (RFC 8058 POST) only over HTTPS, to an allowlisted domain, after resolving the host and rejecting private/loopback IPs, with NO redirect following. mailto fallback uses a fixed subject over verified STARTTLS.

### ADR-007: Two Python venvs (2026-06-12) — SUPERSEDED by ADR-011

**Decision (original):**
- `.venv` (py3.9) for the actor; `.venv-mcp` (py3.13) because the `mcp`/FastMCP SDK needs ≥3.10.

**Update:** the 3.9 split was a Mac system-python artifact, not a real constraint. The Unraid container (ADR-011) standardizes on a single Python 3.13 image and drops the dual-venv.

### ADR-008: Rename mail-cleaner → icloud-helper (2026-06-29)

**Context:** scope grew beyond unsubscribe cleanup (now also flagged-receipt extraction + general mailbox judgment).

**Decision:** package `icloud_helper`, project `~/icloud-helper`, the FastMCP serverInfo name, openclaw + Claude Desktop registrations, and the cron all renamed. State DB filename kept as `mailcleaner.db` for continuity.

### ADR-009: Model-judgment rearchitecture (2026-06-29)

**Context:** the header heuristics (`is_bulk`/`classify_sender`) were the final word; the user wanted Claude (in Cowork) to judge newsletter/spam/unnecessary from actual content.

**Decision:** demote the header classifier to an advisory SIGNAL the model may override. Add `read_surface.py` exposing message content (snippets + on-demand full body + `header_signals`) across an INBOX+Junk+Archive allowlist. The Python core becomes executor/guardrail.

**Consequences:**
- ✅ Better classification (model reads real content). ❌ More mailbox content reaches the model/cloud — bounded by the folder allowlist + snippet caps; required a security review.

### ADR-010: Confirmed-action gate; do NOT repurpose dry_run (2026-06-29)

**Context:** "propose → you approve → execute live" needed a live path without weakening the cron's dry-run safety.

**Decision:** a live action requires `allow_confirmed_actions==true` (persistent config toggle, default false) AND per-call `confirm==true` AND a live-validated NON-ZERO uidvalidity. Otherwise it SIMULATES. `dry_run` stays a separate switch governing legacy/cron tools.

**Alternatives:** arm-with-timeout window, env-var-per-launch → user chose the persistent toggle for simplicity.

**Consequences:**
- ✅ Cron safety unchanged. ❌ Known/accepted trust gap: the server can't verify a human (vs the model) set `confirm` — if the toggle is left ON the model could self-confirm. Mitigated by a startup warning + a `warning` field in every live-action response. Arm only during a watched session; disarm after.

### ADR-011: Migrate off the Mac to an Unraid container (2026-06-30, SHELVED — superseded by ADR-013)

**Context:** a Mac juggling two logged-in accounts is the wrong home (see bugs 2026-06-30). Need an always-on, GUI-login-free host.

**Decision:** run icloud-helper as a Docker **Compose** project on Unraid (`tower`), with a **networked HTTP MCP server** (FastMCP HTTP transport) and **Tailscale attached to the container** (its own tailnet identity). Secrets + state on mounted appdata volumes; nightly actor via Unraid User Scripts `docker exec`. openclaw + its gemma model stay on howl-m2 and connect to the remote MCP by URL. Keep howl-m2 as rollback until verified.

**Alternatives:** stdio over `ssh root@tower docker exec` (simpler, rejected for the cleaner networked endpoint the user wanted).

### ADR-012: Shared IMAP primitives (2026-06-29)

**Decision:** `uid_search(imap, criterion)` and `parse_message_headers(raw)` live in `imap_client.py` and are reused by actor, triage, and flagged paths — removes duplicate-code and keeps classification identical across callers.

### ADR-013: Run locally as a stdio MCP server for Cowork; drop openclaw + the Unraid plan (2026-06-30)

**Context:**
- The Unraid/HTTP/Tailscale plan (ADR-011) existed mostly to serve a REMOTE openclaw on howl-m2. The user decided openclaw no longer needs the tool, and that the service "should just run locally from where it is used" — i.e. on the Mac where Claude Cowork/Desktop runs.

**Decision:**
- Deploy icloud-helper as a plain **local stdio MCP server** at `~/Projects/icloud-helper`, spawned directly by Claude Desktop (`command` = the local `.venv/bin/python`, `args` = `-m icloud_helper.mcp_server`, `cwd` = the repo). No SSH, no Tailscale endpoint, no HTTP transport, no `mcp-remote` bridge.
- Single Python 3.13 venv (drops the dual-venv, ADR-007).
- openclaw dropped as a consumer for now (its howl-m2 registration is obsolete). The Unraid migration (ADR-011) is shelved — revisit only if a remote/always-on consumer returns.

**Consequences:**
- ✅ Simplest possible: no network surface, no tunnel, no bridge, no auth endpoint to secure.
- ✅ Reliable for a Cowork-only tool (Desktop owns the subprocess lifecycle).
- ❌ Only runs while the Mac is on / Desktop is running. The autonomous nightly cron is NOT carried over by this decision — if always-on autonomous cleanup is wanted again, that needs a separate host (revisit ADR-011).

### ADR-014: Arm confirmed actions for local Cowork use (2026-06-30)

**Context:** the goal is to let Cowork actually execute moves/trashes/unsubscribes, not just simulate.

**Decision:** set `allow_confirmed_actions = true` and `allow_delete = true` in the local `config.toml`. `dry_run` stays `true` (it governs the separate legacy/cron path, NOT the confirmed-action gate). Live execution still requires per-call `confirm=true` + a valid non-zero uidvalidity.

**Consequences:**
- ✅ Cowork can execute live (approval happens in the Cowork chat).
- ❌ Accepted trust gap (ADR-010): the server can't verify a human (vs the model) set `confirm` — acceptable here because it's the user's own local machine, single-user, supervised, and every action is reversible (trash → "Deleted Messages", move reversible, unsubscribe low-harm). The server logs a WARNING at startup while armed.

### ADR-015: Disable the sender-level unsubscribe allowlist — default-allow (2026-07-01)

**Context:**
- ADR-002 made the allowlist default-DENY: `_apply_action_guards` (`mcp_server.py`) refused any sender absent from `policy.toml` with `action="unsubscribe"`. With the model-judgment architecture (ADR-009) and Cowork now doing per-sender judgment interactively, that default-deny gate is redundant friction — every new sender needs a manual `policy.toml` edit before Cowork can act on it.

**Decision:**
- Flip Guard 1 in `_apply_action_guards` to default-ALLOW: a sender with no policy entry is now permitted. Explicit `action="keep"` entries still hard-refuse (new error `sender_marked_keep`, distinct from the removed `sender_not_in_allowlist`). Guard 2 (`protected_domains`) is untouched — protected domains still hard-refuse regardless of policy state. This supersedes the allowlist-only clause of ADR-002; the "unknown senders never auto-actioned" property no longer holds at the sender-identity layer.

**Consequences:**
- ✅ Cowork can act on any sender without a manual `policy.toml` allowlist edit first — removes the main friction ADR-002 introduced.
- ✅ `keep`-marked senders remain protected, as does the protected-domains list.
- ❌ Loses the "no surprise actions on new senders" guarantee from ADR-002 at the sender-identity layer. Mitigated by the other unchanged guardrails: DKIM/DMARC sender-auth gate (ADR-005), SSRF/IP denylist (ADR-006/Pass B), `dry_run` default (ADR-004), and the confirmed-action gate (ADR-010) — a live mutation still requires `allow_confirmed_actions` + per-call `confirm` on the user's own supervised machine.

### ADR-016: Body-link unsubscribe — surface, probe/classify, and (deferred) act (2026-07-01)

**Context:**
- Unsubscribe was header-only: `perform_unsubscribe` routed off `determine_unsubscribe_method` reading `List-Unsubscribe`/`List-Unsubscribe-Post`. Senders with no such header (staffing-firm recruiter blasts; marketing arriving via Apple Hide My Email / Firefox / iCloud relays) return `no_mechanism` and could not be actioned, even when a visible "Unsubscribe" link exists in the HTML body. Stefan wanted the assistant to surface those body links and, where safe, act on them — with the emphasis on surfacing candidates to the model rather than blind auto-following.

**Decision (phased):**
- **Phase 1 — surface (read-only), BUILT.** New module `body_links.py` (`extract_unsubscribe_candidates`, `LinkCandidate`, `_AnchorCollector`) parses HTML `<a href>` anchors and text URLs, scoring against unsubscribe heuristics (anchor text, URL path/query, `mailto?subject=`, title/aria) into `high`/`medium`/`low` confidence. New read-only MCP tool `find_unsubscribe_links(folder, uid, uidvalidity)` returns ranked candidates plus `extract_auth_signals` (so the relayed-mail picture is visible) and a per-candidate `egress_preview` (a pure `egress_check`, DNS-resolve only, no request). Never issues a request; BODY.PEEK, no Seen flag.
- **Phase 1.5 — probe + classify (gated GET), BUILT.** New MCP tool `probe_unsubscribe_link(folder, uid, uidvalidity, url, confirm=False)` fetches the landing page via a real GET through the existing egress layer and classifies it (`body_links.classify_landing_page`, `_LandingParser`) into `completed` / `single_confirm` / `multi_step_form` / `login_required` / `captcha` / `dead_end` / `ambiguous`, returning the extracted next action (form `action_url`+method+required/hidden fields, itself egress-checked via the `NextActionEgress` field) and a bounded, script-stripped page excerpt. This is a "read-only-ish" probe: it may itself complete a GET-style one-click unsubscribe, so it runs the full gate chain and `confirm=false` simulates (returns the `egress_check` preview, no fetch).
- **Phase 2 — act on a chosen next-step, and form auto-submit: EXPLICITLY DEFERRED / OUT OF SCOPE.** Programmatically submitting a reconstructed form (model-selected field values) to an `action_url` derived from untrusted HTML is a materially larger SSRF/CSRF/injection surface. It is not built; reviving it requires its own switch and its own ADR. The `completed` case needs no follow-up; for `single_confirm`/`multi_step_form` the probe returns the next action and the assistant reports it to the user.

**Security model:**
- **Egress reuse (no new egress code).** The probe GET goes through `unsubscribe_one_click(http_method="GET", capture_body=True)` — the same Pass-B path: HTTPS-only, `egress_check` pre-flight, IP denylist (resolution-based, DNS-rebinding defeated), IP-pinned connection with TLS hostname verification intact, per-hop redirect re-validation, `max_redirects`, timeouts. The header one-click path is unchanged (never sets `capture_body`).
- **URL provenance.** Before any fetch, the probed `url` must be byte-identical to a candidate re-extracted from the live message (`url_not_in_message` otherwise). The model cannot invent or mutate a target URL; a prompt-injected body cannot steer egress to an arbitrary host beyond a link the message genuinely contains (and that link is still egress-gated).
- **Untrusted landing-page handling.** Response body is size-bounded at read (`probe_max_capture_bytes`, default 512 KiB, clamped to a 4 MiB ceiling in `load_config` plus an independent read-site backstop); parsed with scripts/style/comments stripped; reduced to structured signals + a capped text excerpt (`probe_excerpt_bytes`, default 4 KiB); no sub-resources (images/iframes/scripts) are ever fetched. Every probe response carries an always-present warning that the page content is untrusted third-party data, not instructions.
- **Relayed-mail authorization stance.** DKIM/DMARC (`check_sender_auth`, fail-closed) still gates the ACTION — it proves iCloud accepted the message as authenticated in transit. Sender↔link-host domain alignment is explicitly NOT required (structurally impossible for Hide My Email / ESP relays); host authorization is delegated entirely to the egress policy (IP denylist + `unsubscribe_denied_domains` + `unsubscribe_review_domains`). Misalignment (`from_alignment`) is surfaced to the model as a signal, never a hard block.
- **Audit hygiene.** Targets are logged as `host:<host> sha256:<hex>`; raw tokenized URLs are never stored.

**Config switches + secure defaults:**
- `allow_body_link_unsubscribe` (default **false**) — master switch for the whole body-link path; distinct from `allow_confirmed_actions`, so the higher-risk body-link egress stays off even when confirmed actions are armed. Both `find_unsubscribe_links` (read-only) and `probe_unsubscribe_link` respect it; probe simulates when off.
- `probe_excerpt_bytes` (4096) and `probe_max_capture_bytes` (524288, clamped to a 4 MiB ceiling). Arming the feature = flipping `allow_body_link_unsubscribe` to true.

**Gate order (normative, as implemented):** parse/extract → **URL-provenance** → **DKIM/DMARC (fail-closed)** → protected-domain → `allow_body_link_unsubscribe` master switch → confirmed-action gate → fetch. This puts the pure in-memory provenance check ahead of DKIM/DMARC, a deliberate deviation from the original design spec (which listed DKIM/DMARC first). Recorded as normative: provenance has no side effects, and all four security gates (auth, protected-domain, master switch, confirm) still precede any network I/O — order among the pre-fetch checks does not change what is or isn't blocked.

**Relationship to prior ADRs:** consistent with ADR-005 (DKIM/DMARC, preserved and interpreted for relays), ADR-006/Pass B (SSRF egress layer, reused verbatim — the earlier "no redirect following" clause was already amended by Pass B's per-hop re-validation), and ADR-010/014 (confirmed-action gate). No conflict; this extends the unsubscribe surface beyond headers.

**Consequences:**
- ✅ Automation now reaches body-link-only senders (recruiter blasts, relayed marketing) that header-only unsubscribe could not touch.
- ✅ First tool to pull arbitrary external page content into the model's context, done behind a dedicated switch, provenance gating, untrusted-content framing, and the full SSRF layer; security-reviewer cleared to arm (no Critical/High).
- ❌ Residual accepted risk: the model may choose a link and a human may confirm a probe/action — same trust boundary as ADR-010, bounded by egress reachability (public hosts only), reversibility (unsubscribe is low-harm), and the default-off master switch.
- ❌ Multi-step completion (form submit) is a known gap deferred by design; the assistant reports the next action for the user to complete manually until a future phase revisits it.

### ADR-017: In-process HTML→PDF via WeasyPrint with a fail-closed egress fetcher (2026-07-08)

**Context:**
- Email-only receipts (Delta, Uber, meals) have no PDF/JPEG attachment. The prior workaround produced typed plain-text transcriptions, which Geco (Reply's expense system) rejects — Stefan needs the real receipt look, i.e. the message rendered as authored.
- Wanted an in-process "print to PDF" of the original text/html body with zero risk of network egress (no tracking-pixel callbacks, no remote CSS/font fetches revealing the mailbox).

**Decision:**
- Render the message's ORIGINAL text/html in-process with WeasyPrint (`render_pdf.py`) — a pure-Python renderer with NO JavaScript engine, so no script or tracking code ever executes.
- Single egress gate: a `url_fetcher` scheme allowlist (`make_no_egress_fetcher`). Only `cid:` (resolved against `flagged.build_cid_map()` of the SAME message) and `data:` (decoded locally by `weasyprint.default_url_fetcher`, no I/O) are served. Everything else — `http:`, `https:`, `file:`, protocol-relative `//host`, empty/unknown scheme — raises a PLAIN `ValueError`, so WeasyPrint drops just that resource (broken-image placeholder) and keeps rendering, rather than aborting on `FatalURLFetchingError`. Remote references are dropped-not-fetched; the count is surfaced as `dropped_remote_refs`.
- `base_url=None` passed to `weasyprint.HTML(...)` so relative URLs cannot resolve to local `file://` paths; the scheme allowlist is a backstop regardless.
- No text/html leaf → fall back to the first text/plain leaf, `html.escape`'d and wrapped in a minimal `<pre>` document (`body_source="text-fallback"`).
- `save_to` is a REQUIRED bare filename, validated BEFORE any IMAP session opens; PDF written atomically (mode 600) inside `downloads_dir` (mode 700) via `attachments.atomic_write_attachment`. `flagged.max_attachment_bytes` is enforced against the RENDERED PDF before any write (DoS guard).

**Gating:**
- Matches `get_attachment`: NO arm flag, NO confirmed-action gate. Justified because the tool performs ZERO egress, is read-only over IMAP (BODY.PEEK via the read-only session, no Seen flag, no EXPUNGE), and produces only a local, path-contained write. It never mutates the mailbox and never reaches the network.

**Alternatives rejected:**
- Headless Chromium (`--headless --print-to-pdf`): executes JavaScript (tracking/egress surface) and is Homebrew-deprecated/Gatekeeper-disabled 2026-09-01. Rejected.
- LibreOffice (`soffice --convert-to pdf`): poor HTML-email fidelity and no per-resource egress hook to enforce fail-closed loading. Rejected.

**Consequences:**
- ✅ Produces a real print-to-PDF of the receipt as authored, accepted by Geco.
- ✅ Egress is structurally impossible during render (default-deny allowlist + `base_url=None`); security-reviewer gate was skipped for velocity (Stefan's call) with the architect confirming the egress-block property sound.
- ❌ New native dependency: WeasyPrint needs Pango, installed via `brew install weasyprint` (or `brew install pango`) alongside the `.venv` pin `weasyprint==69.0`.
- ❌ WeasyPrint 69.0 DEPRECATES the dict-based `url_fetcher`/`default_url_fetcher` API in favour of a new `URLFetcher`/`URLFetcherResponse` class. Works today (harmless DeprecationWarnings); a future WeasyPrint bump will require migrating `render_pdf.py` to the class-based API.

**Relationship to prior ADRs:** preserves ADR-003 (no EXPUNGE — read-only session only). Runs in the local `.venv` per ADR-013. Needs no egress master switch (contrast ADR-016's `allow_body_link_unsubscribe`) precisely because it performs no egress — there is nothing to gate at the network layer.

### ADR-018: Remote read-only HTTP entrypoint on Unraid, next to local stdio (2026-11-09)

**Context:**
- Stefan wants claude.ai (not only the local Mac client) to read his iCloud mail as a custom connector. That needs a public HTTPS endpoint with OAuth, which ADR-013's local stdio server can't provide.
- ADR-011's Unraid container plan was shelved because no remote consumer existed. One exists now.

**Decision:**
- Add a SECOND entrypoint, `icloud_helper/remote_server.py`, served over Streamable HTTP. It revives the Unraid host from ADR-011 for this one purpose; ADR-013 stays in force for the local stdio server, which keeps all 21 tools.
- Tools come from an allowlist: `list_messages`, `get_message_body`, `list_flagged_messages`, `find_unsubscribe_links`, and `get_attachment` through a wrapper with no `save_to` (forced to `""`). No action, policy-write, PDF-write or config tool is registered.
- Second layer: `readonly_guard`. `main()` calls `enable()` and the Dockerfile sets `ICLOUD_HELPER_READ_ONLY=1`. With it on, `select_folder_readwrite`, `unsubscribe_one_click` and `unsubscribe_mailto` (before SMTP connect) raise `ReadOnlyModeError`.
- Auth: FastMCP's `GitHubProvider` (an OAuth proxy presenting DCR/CIMD to Claude) with `read:user` scope and consent on. `SingleUserGitHubProvider` rejects any token whose GitHub login (case-insensitive) or, when set, numeric id doesn't match. Redirects: claude.ai's callback only; Claude Code loopback is opt-in.
- Network: Tailscale sidecar (`tag:mcp`) on Unraid, no published ports; Caddy on the VPS (`tag:edge`) restricts server-to-server paths to Anthropic's egress ranges. Files in `deploy/`.

**Library pin:** `fastmcp==3.4.11` in `requirements-remote.txt`. fastmcp 4.x requires `mcp` 2.x, which removes `mcp.server.fastmcp` and would break the stdio server; 3.4.11 coexists with `mcp==1.27.2`.

**Alternatives rejected:**
- Tailscale Funnel: no auth or IP allowlist of its own, ts.net hostnames only, beta.
- Cloudflare Access managed OAuth: beta and unverified against Claude's connector flow.
- Exposing the stdio server through a bridge: would expose every action tool.

**Consequences:**
- ✅ claude.ai can read mail with no write or egress path reachable, even by mistake.
- ✅ Kill switch at five independent layers (connector, Caddy, ACL, JWT key, app password).
- ❌ A second deployment to keep in step with `mcp_server` changes; `test_remote_server.py` pins the tool surface so additions are deliberate.
- ❌ Follow-up: egress details (e.g. `find_unsubscribe_links`' `egress_preview`) can include resolved IP strings. Harmless locally; review before relying on the remote server for anything shared.
