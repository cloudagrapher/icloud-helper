# Work Log

Brief log of work completed. No external ticket system — dates + summaries. Newest at top.

### Week of 2026-07-06

**Completed:**
- 2026-07-08: **Replaced typed transcriptions with real print-to-PDF renders
  (`save_message_pdf`, ADR-017).** Re-listed flagged INBOX (uidvalidity
  1221852132, unchanged), matched sources by sender/subject/date, rendered 19
  email-only receipts to PDF (all `body_source: "html"`, egress-blocked) and
  moved them over the old transcriptions: June (chicago-6:20-26) — Delta HTWFOV,
  Uber Eats, Chick-fil-A, 6 Lyft, + both flagged Uber Jun 26 twins ($81.98
  charge summary / $94.27 final, left in `flagged/`, still OUT of total); April
  (chicago-4:22-24) — Delta G9GDK8 BOTH legs (added `delta-flight-G9GDK8-return.pdf`
  for the rebooked 24APR leg, uid 80312), Courtyard Kokomo reservation,
  ParkChicago, 4 Lyft. Archived all 19 source emails INBOX→Archive
  (`move_messages` confirm=true, all `done`). Totals unchanged. Dropped the
  "transcribed" wording from the June + April report notes. **Elmira
  `ATL-SYR-DTW-ATL.pdf`:** the handoff listed it as a text-render to replace, but
  it was already a real 9-page receipt in `processed/` (16MAR26, conf. HNTRY5,
  ticket 0062411309409) — already uploaded to Geco, nothing to re-render; fixed
  the report row to point at `processed/` and corrected the note. dtw-7:09-11
  future trip (81814, 81859) left untouched per handoff. Status: done.
- 2026-07-08: **Lyft/Uber processing, re-added receipts, and Elmira city-split.**
  (1) City-split: `elm-3:16-19` reduced to NY-only ($2,501.99); moved the Detroit
  leg (Mar 19–20) — Marriott $164.50 + Budget $65.32 — into new `dtw-3:19-20/`
  ($229.82); round-trip airfare kept once in Elmira; identified `hotel-initial.pdf`
  as the Courtyard Elmira reservation confirmation (dupe of the folio, not claimed).
  (2) Processed 10 flagged Lyft rides via `get_message_body` → LibreOffice text
  PDFs: 6 → June (+$220.96), 4 → April (+$132.53), all Apple Pay (Lyft omits card
  last-4). (3) Filed 4 re-added root PDFs: AMOCO gas $61.43 (resolves the April
  missing-gas flag) → April; ATL parking $140.00, Hyatt McCormick Rockstar $7.82
  (new card …3022), McCormick food court $25.15 → June. (4) Uber Jun 26 twins
  proven to be ONE ride ($81.98 pre-tip charge summary vs $94.27 final incl.
  $12.29 tip); rendered both into `chicago-6:20-26/flagged/` and left OUT of the
  total pending confirmation. New totals: **April $1,465.96**, **June $3,270.35**
  (→ $3,364.62 if the flagged $94.27 Uber is re-added). Status: done.
- 2026-07-08: **Filed loose Expenses-root receipts into trips + updated reports.** Split `various-receipts.pdf` (4 pages) into labeled single-page PDFs — Metra rail $3.75 → June; Cracker Barrel $40.13, Dandy gas $64.42, Speedway gas $8.01 → Elmira. Renamed/moved 8 Starbucks screenshots (5 → June $47.15, 3 → Elmira $64.47) and filed Gino's East ($56.51, flagged: handwritten tip/total don't reconcile) + Arc Bar ($23.00) + two pre-staged June meals (Hyatt Market Red Bull $6.15, Sixes & Eights lunch $30.33). New totals: **Elmira $2,731.81**, **June $2,970.69**. Gotcha: 4 root files (`gas-4:23`/`food-6:22`/`lunch-6:22`/`airport-parking-6:26`.pdf) are byte-identical copies of the June Arc Bar tab — flagged the missing April gas receipt in that report; left the dupes in root (not mine to delete). macOS Unicode-normalization bit `mv` on the screenshot names (NFD on disk vs typed NFC → "No such file or directory"); moved them via Python `os.listdir`/`shutil.move` matching on the timestamp token. Status: done.
- 2026-07-08: **Built expense reports from flagged mail for 4 trips** — `elm-3:16-19` ($2,554.78), `chicago-4:22-24` ($1,272.00), `chicago-6:20-26` ($2,803.80), `dtw-7:09-11` ($1,072.12, preliminary — trip not yet taken). Extracted hotel folios / rental statements via `get_attachment` (`extract_text`), flight + meal totals via `get_message_body`; drafted `report.md` + placed receipt PDFs/JPEGs at each trip root. Model-judgment catches: Elmira had the wrong rental filed (Hertz booking $316.04 vs the actual Enterprise invoice $421.20), Budget was prepaid on card ($65.32, not comped), April airfare was rebooked (net $794.80 via eCredit), a duplicate June Uber receipt, and Kokomo/SpringHill are reservation-only estimates. Workflow documented in key_facts (Geco / `processed/` convention). Status: done.
- 2026-07-08: Reinstalled the `chromium` Homebrew cask (was a dangling symlink — app removed by Gatekeeper). Renders after `xattr -dr com.apple.quarantine /Applications/Chromium.app`, but the cask is deprecated (disabled 2026-09-01); LibreOffice `soffice` is the durable HTML→PDF renderer. Status: done.

### Week of 2026-07-01

**Completed:**
- 2026-07-01: **Body-link unsubscribe Phase 1 + 1.5 shipped (ADR-016).** `find_unsubscribe_links` (read-only surface + ranked candidates + egress_preview + auth_signals) and `probe_unsubscribe_link` (gated GET + `classify_landing_page`); Phase 2/form auto-submit deferred out-of-scope. Full chain: architect → engineer → code-review (6 logic/quality bugs fixed) → security-review (CLEARED to arm, no Critical/High; 2 Low fixed: probe cap ceiling, bounded CSS pass). Egress reuse + URL-provenance + untrusted-page handling + relay DKIM/DMARC stance verified. 625 passed / 1 skipped, pylint 10.00 per production file. Disabled by default (`allow_body_link_unsubscribe=false`). Architect final approval given. Status: done.
- 2026-07-01: Disabled the per-sender unsubscribe allowlist (ADR-015) — `_apply_action_guards` is now default-allow; only explicit `action="keep"` and protected domains refuse. Added guard unit tests + regression tests; 527 passed / 1 skipped, pylint 10.00 on `mcp_server.py`. Status: done.

### Week of 2026-06-29

**Completed:**
- 2026-06-30: **Pivoted to local deployment (ADR-013/014).** Dropped openclaw + shelved the Unraid migration (which existed mainly to serve remote openclaw). icloud-helper now runs as a local stdio MCP server from `~/Projects/icloud-helper`; built a single py3.13 `.venv`; fixed missing `tomli_w` in requirements; full suite 292 passed locally; repointed Claude Desktop to the local server; **armed** `allow_confirmed_actions` + `allow_delete` so Cowork can execute live. Verified the local command starts (16 tools, armed warning).
- 2026-06-30: Set up `docs/project_notes/` project-memory system (this).
- 2026-06-30: Diagnosed the Tailscale dual-account drop (see bugs).
- 2026-06-30: Designed (then shelved) the Unraid container migration — architect plan captured in history if revived.
- 2026-06-29: **Model-judgment rearchitecture** — `read_surface.py` (content + `header_signals`), `actions.py` (read-write IMAP), 5 new MCP tools (`list_messages`, `get_message_body`, `move_messages`, `trash_messages`, `unsubscribe_message`), confirmed-action gate. Full chain: architect → engineer → code-review → security-review (1 HIGH SystemExit blocker, fixed + regression-tested) → architect approval. Deployed (16 tools live), defaults OFF.
- 2026-06-29: Fixed triage import bug + stale `~/mail-cleaner` path constants (would have broken the cron); consolidated shared IMAP primitives (`uid_search`, `parse_message_headers`).
- 2026-06-29: Renamed `mail-cleaner` → `icloud-helper` end-to-end (package, paths, openclaw + Desktop registrations, cron). Removed 26 duplicate tests.
- 2026-06-29: Shipped flagged-message retrieval tools (`list_flagged_messages`, `get_attachment`) for expense-receipt extraction; full review chain; security-cleared.

### Week of 2026-06-12

**Completed:**
- 2026-06-13: First supervised live runs (7 of 9 senders unsubscribed + filed); registered + validated the nightly cron; upgraded openclaw model e4b → gemma4:26b; repaired corrupted state.
- 2026-06-12: Built the iCloud newsletter auto-unsubscribe system — deterministic core, MCP server, actor, `policy.toml`, SSRF + DKIM + TLS hardening. ~176 tests, pylint 10. Architect approved go-live.

## Open / backlog

### Cowork live-test feedback (2026-06-30) — prioritized
P0 (DONE): trash/move IMAP mailbox quoting (`BAD Parse Error`) — fixed + live-verified, see bugs.md.
**Tranches 1+2 approved (architect plan 2026-06-30). Fork decisions:** A=all tools return `dict` (drop json.dumps; validated no `{"result":...}` wrapper in mcp 1.27.2) · B=envelope has `gates_evaluated[]`+`blocked_by` · C=mailto fallback authorized by DKIM/DMARC-verified sender domain OR new `mailto_allowed_domains` config · D=`get_attachment` `save_to` writes under **~/Claude/icloud-helper-attachments/** (Cowork file area) · E=`pypdf` for extract_text · F=default snippet 1.5KB (8KB ceiling stays) · G=hand-rolled magic-byte sniffing (no new dep). Build = 2 separate engineer passes (T1 then T2); security-review required for T1 mailto fallback + T2 save_to. **T1 DONE 2026-06-30** (engineer→code-review→security-review found 2 blockers C1/H1 [mailto auth used raw From not DMARC identity; unsubscribe_sender had no DKIM gate] → fixed → security re-review SAFE → architect APPROVED; 355 tests pass, T1 files pylint 10). User must restart Desktop to load T1. **T2 DONE 2026-06-30** (get_attachment save_to[→~/Claude/icloud-helper-attachments]/extract_text[pypdf]/chunking, view projection, HTML→text clean, detected_mime; code-review fixes incl. QP-decode-URL-corruption guard; security-cleared + architect APPROVED 2026-06-30). Live-verified by Cowork: structured JSON, accurate body_source, clean snippets confirmed. **Trash-hang regression FIXED + architect APPROVED + live-confirmed** (batch multi-UID trash succeeded, status:done). Deferred follow-ups (non-blocking): extract_attachment decodes pre-size-check (bounded by message size); IMAP 30s timeout doesn't cover unsubscribe HTTP/SMTP egress → folded into Pass B. **A0 hotfix DONE 2026-06-30**: gated `classify_sender` to `is_bulk`-only in `header_signals`; non-bulk → `"not_bulk"`, never `"spam"` (closed the OTP/receipt-mislabeled-spam exposure). 433 tests pass, pylint 10.
**KEY DESIGN STEER (Stefan, 2026-06-30):** the deterministic code should NOT render a classification verdict on mail it's never seen — that overreach caused the spam bug and contradicts the model-judges architecture (ADR-001/009). Pass A is being rebuilt **facts-only**: emit factual signals (SPF/DKIM/DMARC+alignment, has-List-Unsubscribe, OTP/receipt/marketing-CTA patterns as booleans/counts, spoof indicators) + the single honest label `bulk`/`not_bulk`. NO category verdict, NO confidence score. Cowork judges from the facts + body. Facts inform; the user/model decide; only the safety guardrails (allowlist/DKIM/SSRF/confirm) ever block.
**Pass A DONE + architect APPROVED 2026-06-30** (facts-only classifier: auth signals via `extract_auth_signals` [AR-collapse fixed], spoof facts [local_part_looks_like_email tightened to real-TLD suffixes], content-pattern booleans, `bulk`/`not_bulk` only — no verdict/confidence; cron path untouched; `check_sender_auth` unchanged). 222 Pass-A-adjacent tests pass. Restart Desktop to load.
**TRANCHE 3 COMPLETE 2026-06-30** (Pass A facts-only classifier + Pass B egress redesign both architect-APPROVED). User restarts Desktop to load both; re-run AWS Customer Council unsubscribe (now goes through via mailto/iCloud-SMTP).
**Pass B DONE + architect APPROVED 2026-06-30** (egress allowlist→denylist + per-hop-re-checked redirect following + `_PinnedHTTPSConnection` IP-pinning + mailto reconcile [unblocks AWS via iCloud-SMTP delivery] + block_class taxonomy incl. auth_failed + HTTP/SMTP timeouts). Code-review caught + fixed a TLS MITM BLOCKER (check_hostname was toggled OFF during the handshake in the IP-pinning connect — now passes server_hostname with check_hostname=True). 522 tests pass, pylint 10. Security verdict: no critical/high; IP denylist complete (+stdlib backstop for 6to4/Teredo/NAT64), rebinding/TOCTOU closed, test-coverage integrity intact. LOW follow-ups (non-blocking, backlogged): (1) actor.py cron doesn't thread verified_sender_domain → cron prefer_mailto won't engage (functional only; auth still enforced per-UID; MCP paths thread it correctly); (2) internal resolved-IP strings appear in egress detail/MCP reason (harmless for local caller; scrub if MCP ever exposed beyond local).
**LESSON (corrected): tests are NOT isolation-clean.** Pass A approval first reported "8 egress failures + a test_mcp_server hang"; the architect reconciled — running those test FILES STANDALONE fails because `test_security_hardening.py`/`test_confirmed_actions.py`/`test_mcp_server.py` depend on session-scoped fixture state (DNS mocks, config, allowlist seeding) seeded by earlier modules in full-suite collection order. Full suite in one process = 479 passed/1 skipped, 0 failed. So it was NOT Pass B contamination and NOT a regression. **Backlog FU-A: make those test modules self-seeding (mock DNS/config in setUp, add --timeout to the MCP suite) so `pytest tests/<file>` works alone.** Also: a 40-min suite needs the actual pytest summary line attached to any "it's green" claim, not a paraphrase. (relaxed-alignment PSL caveat already documented.)
**T3 PLANNING** (architect): (1) classifier upgrade — gate classify_sender to bulk-only + structured auth signals + transactional/OTP detector + confidence (see bugs.md spam-over-flagging); (2) unsubscribe egress allowlist→denylist + post-DNS/redirect SSRF checks (unblocks ESP-domain unsubscribes like AWS Customer Council's mailto to na2.alida.com; security-review required). AWS Customer Council unsubscribe still blocked pending the egress redesign — re-run after.
Tranche 1 (quick wins, high value):
- Return structured JSON, not a `{"result":"<escaped json string>"}` wrapper (every tool, double-encoded).
- Standardize all mutating-tool responses to one envelope; replace `success:true` on simulations with `status:"simulated"`; add `blocked_by` (master_switch|allow_delete|domain_allowlist|dkim_dmarc) + `remediation`.
- `get_config`/capabilities tool: read folders, archive/trash names, the two master flags, size caps, unsubscribe/protected domain lists.
- `unsubscribe_message`: fall back to `mailto:` when the HTTPS one-click host is blocked/fails; report `method_attempted`/`method_used`/`fallback_reason`.
Tranche 2 (read ergonomics):
- `get_attachment`: add `save_to` (write to an allowlisted dir, return path+sha256+size+detected_mime), `offset`/`length` chunking, and `extract_text` (server-side pdftotext) — base64-inline is the biggest functional blocker for the expense task.
- `view=metadata|snippet|full` projection + smaller default snippet (1–2 KB) + `max_total_bytes`/`truncated`.
- HTML→text: decode quoted-printable (`=3D`,`=C2=A0`) + entities, strip `<style>`/`<script>`, normalize whitespace before truncating.
- `detected_mime` via magic-byte sniffing; fix `body_source` mislabeling (HTML reported as plain).
Tranche 3 (deeper):
- Server-side IMAP SEARCH for `unread_only`/`bulk_only`/date/sender/subject so filters apply to the WHOLE folder (today they filter only the newest-N window — Archive has 11k msgs, only newest ~40 seen). Add real cursor pagination + `total_matching` vs `total_in_folder`.
- Classifier: expose structured signals (spf/dkim/dmarc + alignment, local-part-looks-like-email, ESP identity, `is_first_party`), a transactional-vs-marketing detector (DMARC-aligned + receipt/confirmation patterns → never auto-unsub/archive), and a numeric `confidence`. Live misses: Proton notice flagged spam (false pos); spoofed realtor throwaway-domain only `unknown`; Marriott/Delta/Cigna transactional == promo label.
- Security (needs security-reviewer): shift unsubscribe egress from allowlist-as-primary to denylist + post-DNS egress checks (block RFC1918/loopback/link-local/169.254.169.254, re-check after redirects); keep DKIM/DMARC fail-closed; prefer mailto. Allowlist becomes a thin review queue with clear retryable-vs-hard-blocked status.
- Optional: opaque message token encoding folder+uid+uidvalidity (fewer foot-guns than 3 positional args).
- Docs: document the triage workflow (trigger_triage → list_bulk_senders/get_triage_report → unsubscribe_sender/unsubscribe_message); `list_bulk_senders` confirmed as the right sender-grouped triage entrypoint.
Suggested tests from the handoff: gate matrix (every mutating tool × confirm × allow_confirmed_actions × allow_delete); shared response-schema contract test; content-sniffing; save_to + chunked-read sha256; pagination coverage; HTML→text; uidvalidity mismatch; **live mutation against a space-named mailbox** (would have caught P0).

### Other
- Defense-in-depth (low, from T1 security review): add explicit RFC-5322 format/quote validation on `sender` in `_fetch_live_sender_headers` before building `FROM "<sender>"` — non-exploitable today (policy.toml allowlist gates it), but hardens against future callers.
- Housekeeping (from T1 architect approval): repo-wide pylint is 9.99 due to a pre-existing `R0801` duplicate-code on IMAP session-teardown boilerplate shared across actions.py/triage.py/flagged.py. Extract a shared teardown helper or baseline R0801 — otherwise CI gating on repo-wide pylint==10 trips on unrelated files. (T1/T2 files are 10.00 in isolation.)
- FU-A (test hygiene, low): make `test_security_hardening.py`/`test_confirmed_actions.py`/`test_mcp_server.py` isolation-clean — they only pass in full-suite collection order (session-scoped fixtures). Self-seed DNS/config mocks in setUp + add a pytest `--timeout` so single-file runs work.
- Discord webhook 403 — needs a fresh URL (see key_facts).
- Bound large-message memory in the read tools (fetch is capped on return, not on fetch).
- `git init` this repo (gitignore secrets/state/.venv); add `pyproject.toml` + `pip install -e .` so the venv import survives rebuilds (replaces the `.pth`).
