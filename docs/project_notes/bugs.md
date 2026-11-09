# Bug Log

Chronological log of bugs and their fixes. Keep entries brief. Newest at top.

### 2026-07-01 - `classify_landing_page` mislabeled JS-SPA/bot-hostile unsubscribe pages as `dead_end` (FIXED)
- **Issue**: live testing of `probe_unsubscribe_link` (ADR-016) against real senders found landing pages that fetch fine (HTTP 200) but render their real content client-side via JS. Example: Nextdoor's unsubscribe page returned `page_text_excerpt` of just `"Nextdoor"` — no forms, no confirmation phrases — because the server HTML is an empty React-style shell. This was classified `dead_end`, which is misleading: the page isn't dead, we just can't see its content without executing JS. Related: some bot-hostile endpoints (e.g. Golfshot's tracker) refuse non-browser requests outright, which surfaces as a fetch failure rather than a classification issue.
- **Root Cause**: `classify_landing_page` and `probe_unsubscribe_link` only ever see server-rendered HTML (`html.parser`, stdlib-only, no JS execution by design — see ADR-016). A JS-SPA page's server response is a near-empty bundle-loader shell, which fell through every existing signal check straight to the `dead_end` fallback, conflating "genuinely nothing here / error" with "fetched OK but unrenderable without a browser." A GET against such an endpoint may well have already completed the unsubscribe server-side; the classifier just can't verify it from the HTML.
- **Solution**: added a new `PageClass.INCONCLUSIVE` value in `icloud_helper/body_links.py`. Before falling through to `dead_end`, a narrow, conservative heuristic (`_looks_like_js_render_shell`) checks for near-empty visible text (≤40 chars) co-occurring with either a known SPA mount-point marker (`id="root"`/`id="app"`/`id="__next"`/`data-reactroot`/`ng-app`/etc.) or a substantive inline `<script>` payload (≥200 chars) — an external `<script src>` alone does not qualify, to avoid misclassifying ordinary dead pages that merely load an analytics snippet. Only fires on a 2xx status with zero other signal (no form/phrase/actionable link); error statuses and genuinely empty/no-signal pages with no JS-shell signature still report `dead_end`. `warnings` gains a `_JS_RENDER_NOTE` explaining the limitation. Backward compatible — `PageClass` is a superset, no existing branch behavior changed. Tests in `tests/test_landing_classify.py` cover the shell fixture, a still-dead_end blank body, a still-dead_end trivial-script body, and a still-dead_end 404 with shell markup.
- **Prevention**: `probe_unsubscribe_link` is server-rendered-HTML-only by design (no headless browser, no JS execution — ADR-016 explicitly scoped this out for the security/egress-control story). This is a durable limitation, not a bug to eventually "fully fix" without adding a JS runtime: any JS-SPA unsubscribe page, and any bot-hostile endpoint that refuses non-browser requests, will remain either `inconclusive` or a fetch failure. Deferred option (not implemented, not planned): an out-of-band sandboxed headless-browser render step, kept fully outside the egress/security-gated GET path, if this ever becomes a high-value target for automation.

### 2026-06-30 - heuristic_classification labels nearly all mail "spam" incl. OTPs/receipts (FIXING — T3 classifier)
- **Issue**: live, 18 of 20 INBOX messages came back `heuristic_classification:"spam"` — including an OTP login code, payment receipts (Uber/Hyatt/Delta/Chick-fil-A/City of Smyrna), CPA tax docs, hotel reservations, a personal email, a business invoice. All things to KEEP.
- **Root Cause**: `read_surface.header_signals` calls `headers.classify_sender` on EVERY message, but `classify_sender` sub-classifies BULK senders only — its first rule is `if not has_list_unsub: return "spam"`. Transactional/personal mail has no List-Unsubscribe header → all stamped "spam". Right function, wrong population.
- **Impact**: dangerous as an action trigger; the only saving grace is nothing auto-acts on the label (`run_cleanup` keys off `policy.toml`). Label is currently useless/misleading.
- **Fix (T3)**: gate `classify_sender` to `is_bulk`-only (non-bulk → a safe label, never "spam"); add structured spf/dkim/dmarc+alignment signals, a transactional/OTP detector (DMARC-aligned + receipt/OTP patterns → "transactional", never auto-actioned), and a numeric confidence.
- **Prevention**: never apply a bulk sub-classifier to non-bulk mail; require a transactional detector + confidence before any tool keys off a classification.

### 2026-06-30 - trash_messages hangs 4 min and kills the server (REGRESSION from the quoting fix — FIXED, live-confirmed)
- **Issue**: after the BAD-Parse-Error fix, a live trash call HANGS ~4 min and wedges the stdio MCP server (worse than the old fast error). Found in Cowork live testing.
- **Root Cause**: the IMAP connection sets NO socket `timeout` (`imaplib.IMAP4_SSL(host, port, ssl_context=...)`), so a stalled read-write op blocks at TCP level for minutes. Likely trigger: the trash flow opens a read-only precheck session AND a separate read-write session; iCloud throttles concurrent connections per account, so the 2nd login/select waits for a slot. Secondary bug: `resolve_special_use_mailbox` calls `imap.list('(SPECIAL-USE)', '""', '"*"')` (3-arg, imaplib rejects) so special-use resolution silently always falls back (harmless for trash — fallback is "Deleted Messages" — but the feature is dead).
- **Fix (planned)**: add a socket `timeout` to `IMAP4_SSL` (bounds every op → fast error not hang); close the read-only precheck session before opening the read-write one; fix the special-use LIST call. Sequenced AFTER the in-flight T2 polish (same-file collision avoidance).
- **Prevention**: always set an IMAP socket timeout; never hold overlapping sessions against a connection-limited server; live-test mutating paths (simulate can't reveal a hang).

### 2026-06-30 - trash_messages/move_messages: IMAP `BAD Parse Error` on space-named mailbox (FIXED)
- **Issue**: live `trash_messages` to `Deleted Messages` failed deterministically with `UID command error: BAD [b'Parse Error']`. Invisible in simulate mode (no IMAP command issued).
- **Root Cause**: the move/copy destination mailbox is passed UNQUOTED; `Deleted Messages` has a space, so the server parses `Deleted` as the mailbox. Same surface affects `move_messages` to `Archive`/trash. The cron's `Unsubscribed` (no space) never tripped it.
- **Solution**: quote + modified-UTF-7-encode mailbox names in all IMAP commands (one `_encode_mailbox` helper); resolve special-use `\Trash`/`\Archive` via `LIST (SPECIAL-USE)` with config fallback; quote the COPY+`\Deleted` fallback too. Test asserts the MOVE/COPY command quotes a space-named mailbox.
- **Prevention**: never pass mailbox names to imaplib unquoted; live-test mutating tools against space-named mailboxes (simulate can't catch IMAP-command bugs).

### 2026-06-30 - Claude Desktop MCP launch: ModuleNotFoundError (cwd not applied)
- **Issue**: the local stdio server failed under Claude Desktop with `ModuleNotFoundError: No module named 'icloud_helper'`, even though the identical command ran fine from a shell.
- **Root Cause**: Claude Desktop does NOT honor the config's `cwd` field, so `python -m icloud_helper.mcp_server` launched from a directory where the repo root isn't on `sys.path`.
- **Solution**: added `icloud_helper.pth` (containing the repo root) to the venv's `site-packages` so the package imports regardless of launch directory. Verified launching from `/tmp`.
- **Prevention**: don't rely on `cwd` for Desktop MCP servers. ⚠️ A venv rebuild drops the `.pth` — re-add it, or better, add a `pyproject.toml` + `pip install -e .` so it survives.

### 2026-06-30 - `tomli_w` missing from requirements.txt
- **Issue**: A clean venv built from `requirements.txt` failed 2 policy-write tests with `ModuleNotFoundError: No module named 'tomli_w'`.
- **Root Cause**: `mcp_server.py` imports `tomli_w` (policy writes), but it was only ever installed ad-hoc on howl-m2's `.venv-mcp` and never added to the manifest (which still had stale dual-venv comments).
- **Solution**: Added `tomli_w==1.2.0` to `requirements.txt`; rewrote it for the single py3.13 venv. Suite back to green (292 passed).
- **Prevention**: Manifest must list every imported third-party module; build a clean venv from it periodically to catch drift.

### 2026-06-30 - Tailscale dropped the host (two macOS accounts)
- **Issue**: icloud-helper "disconnected"; host `howl-m2` showed offline on the tailnet (last seen ~13m), a ghost node `howl-m2-1` appeared.
- **Root Cause**: Two macOS accounts logged in via fast user switching, both running the Tailscale GUI. They contend over the node identity; the second account re-registered the machine, knocking the original node offline. Not a reboot — uptime was 29 days.
- **Solution**: Run Tailscale in ONE account only (`ollama`); sign it out in the other. `tailscaled` is a system LaunchDaemon (boot-scoped), so the connection is machine-wide and the GUI in a second account is unnecessary.
- **Prevention**: This fragility is the main reason for the Unraid migration (see decisions ADR-011). Remove the `howl-m2-1` ghost node in the Tailscale admin console.

### 2026-06-29 - Confirmed-action SystemExit crashes the shared MCP server
- **Issue**: A transient credential/IMAP failure during a confirmed action killed the stdio MCP server for ALL clients (openclaw + Cowork).
- **Root Cause**: `read_secret`/`connect_and_login`/`select_folder_readwrite` call `sys.exit(1)` → `SystemExit`, which is a `BaseException` and is NOT caught by `except Exception`.
- **Solution**: `actions.open_readwrite_session` wraps those calls in `except SystemExit` and re-raises `ActionsError` (mirroring `flagged.open_readonly_session`); the action tools catch `(ActionsError, SystemExit)`. 5 regression tests lock it.
- **Prevention**: In any long-lived shared stdio server, convert `sys.exit()`/`SystemExit` from helpers into a catchable Exception at the tool boundary. Never rely on `except Exception` to contain it.

### 2026-06-29 - Triage dead after rename; stale hardcoded paths
- **Issue**: `triage.py` crashed at import (`ImportError: fetch_all_message_ids`), leaving the triage snapshot stuck on an old date.
- **Root Cause**: `triage.py` imported `fetch_all_message_ids`/`fetch_headers_batch` that never existed in `imap_client.py` (the actor had private equivalents). Separately, runtime path constants still pointed at the retired `~/mail-cleaner` tree: `actor._DEFAULT_CONFIG`/`_DEFAULT_POLICY`, `triage` secrets + `--output` default, `state._DEFAULT_DB_PATH`.
- **Solution**: Added `fetch_all_message_ids`/`fetch_headers_batch` to `imap_client.py` (mirroring the actor's lowercase-key, multi-valued-`Authentication-Results` parsing); made all path constants `Path(__file__).resolve().parent`-relative.
- **Prevention**: A directory/package rename must grep ALL `.py` for `Path.home()/"<oldname>"` and absolute-path string literals — runtime path constants are the silent breakers, not just imports/docstrings.

### 2026-06-29 - Duplicate test files double-collected
- **Issue**: pytest counts inflated (~283 vs ~223); risk of editing the wrong copy.
- **Root Cause**: Stale duplicate test files existed alongside the canonical `tests/` dir with no `testpaths` config, so a bare `pytest` from root collected both.
- **Solution**: Moved the duplicate copies into `.removed-duplicate-tests-YYYYMMDD/`. Always run `pytest tests/` explicitly.
- **Prevention**: Keep tests only under `tests/`; consider a `testpaths` setting.

### 2026-06-13 - State corruption from dry-run re-attempts
- **Issue**: Three real unsubscribe successes were downgraded success→deferred in the SQLite state.
- **Root Cause**: Re-attempt logic interacted badly with prior dry-run writes.
- **Solution**: Repaired from the `audit_log` (dry_run=0 truth); backed up DB first.
- **Prevention**: Verify agent "done" claims against the real data path, not the agent's word.

### 2026-06-12 - Header-key casing made actor find 0 senders
- **Issue**: Actor reported 0 bulk senders on a non-empty inbox.
- **Root Cause**: Fetch stored mixed-case header keys; consumers (`is_bulk`, `triage_messages`) expect lowercase.
- **Solution**: Normalize all header names to lowercase at parse time (`parse_message_headers`).
- **Prevention**: One canonical header-dict contract (lowercase) shared by all consumers.

### 2026-06-12 - Dry-run poisoned state so live run would no-op
- **Issue**: A later live run would skip everything.
- **Root Cause**: Actor wrote `mark_processed`/`sender_state` even in dry-run.
- **Solution**: Guarded all state writes with `if not dry_run`.

### 2026-06-12 - Disposition STORE-fail returned success (data loss)
- **Issue**: Mail could be stranded (copied but not removed, reported as success).
- **Root Cause**: COPY+`\Deleted` fallback returned `success=True` even when the STORE failed; actor also discarded the disposition result.
- **Solution**: Return `success=False` on STORE failure; actor only marks success when disposition succeeded. Never EXPUNGE.

### 2026-06-12 - Unsubscribe SSRF
- **Issue**: Unsubscribe POST fetched arbitrary URLs without validation.
- **Solution**: Resolve host, reject private/loopback IPs, enforce a domain allowlist, no redirects (no per-hop revalidation).

### 2026-06-12 - Forgeable DKIM gate
- **Issue**: Sender-auth check used a joined-blob substring match (3 bypasses).
- **Solution**: Per-header `authserv-id` trust (only `icloud.com`/subdomains), `\bdmarc\s*=\s*pass\b` token-boundary match, evaluated per-UID. See `auth.py`.

### 2026-06-12 - IMAP/SMTP TLS unverified on Python 3.9
- **Issue**: `IMAP4_SSL`/SMTP used an unverified context (CERT_NONE) on the 3.9 stdlib.
- **Solution**: Pass `ssl.create_default_context()` (CERT_REQUIRED + hostname check) to IMAP and SMTP STARTTLS.
