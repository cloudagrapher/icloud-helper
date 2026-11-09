# Key Facts

Non-sensitive project configuration and constants. **No secret values here** — secrets live in `secrets/` (mode 600), referenced by location only.

## Deployment

- **Primary deployment (since 2026-06-30, ADR-013):** runs LOCALLY on the Mac as a stdio MCP server from `~/Projects/icloud-helper`. Claude Desktop spawns it directly: `command` = `~/Projects/icloud-helper/.venv/bin/python`, `args` = `-m icloud_helper.mcp_server`, `cwd` = the repo. Single Python 3.13 venv at `.venv`. No SSH/Tailscale/HTTP. THIS repo is now the runtime, not just a working copy. ⚠️ Desktop ignores the config `cwd`, so the venv has an `icloud_helper.pth` (→ repo root) in site-packages to make the package importable from any launch dir; a venv rebuild must re-add it (or add a pyproject + `pip install -e .`). Still NOT git-tracked — consider `git init` (gitignore `secrets/`, `state/`, `.venv*`, `__pycache__`).
- **howl-m2 (old host, retired as primary):** SSH `ollama@howl-m2.kamori-tuna.ts.net`, `~/icloud-helper`. Kept as rollback/history; openclaw registration there is obsolete (openclaw dropped as a consumer).
- **Unraid "tower" (SHELVED, ADR-011):** `root@100.67.51.65` / `tower.kamori-tuna.ts.net`, Unraid 7.3.0. The container/HTTP/Tailscale plan is parked — revisit only if an always-on / remote consumer returns.

## iCloud account / mail servers

- Address: `stefan@bekker.cloud` (iCloud+ custom domain).
- IMAP: `imap.mail.me.com:993` (SSL, cert-verified).
- SMTP: `smtp.mail.me.com:587` (STARTTLS, cert-verified).
- Auth: app-specific password — value in `secrets/icloud_app_password` (NOT here).
- Real IMAP folder names: `INBOX`, `Junk`, `Archive`, `Deleted Messages` (the iCloud trash; carries the `\Trash` flag). Read allowlist = `INBOX`, `Junk`, `Archive`.

## Secrets (locations only — never values)

- `secrets/icloud_email`, `secrets/icloud_app_password`, `secrets/discord_webhook_url` — all mode 600.
- ⚠️ Discord webhook currently returns **HTTP 403 (revoked/expired)** — notifications fail (cron is best-effort-deliver so the job still succeeds). Needs a fresh webhook URL.

## Config flags + defaults (`config.toml`)

- `dry_run = true` (governs legacy/cron path only), `allow_mcp_policy_writes = false`.
- **ARMED (2026-06-30, ADR-014):** `allow_confirmed_actions = true` + `allow_delete = true` — Cowork can execute live moves/trashes/unsubscribes (per-call `confirm=true` + valid uidvalidity still required). Server logs a WARNING at startup while armed. To disarm, set both back to `false` and relaunch.
- `disposition = "move_to_unsubscribed"`, `max_unsubscribes_per_run = 5`.
- `[actions]` `max_moves_per_run = 50`, `max_trashes_per_run = 50`, `archive_folder = "Archive"`, `trash_folder = "Deleted Messages"`.
- `[read]` `folders = ["INBOX","Junk","Archive"]`, `max_snippet_bytes = 8192`.
- `[flagged]` `max_attachment_bytes = 10485760` (10 MiB), `default_limit = 25`, `max_limit = 100`, `max_body_bytes = 262144` (256 KiB).

## MCP server (FastMCP) — 21 tools

- **Read:** `list_bulk_senders`, `get_triage_report`, `show_pending_senders`, `get_audit_log`, `get_sender_status`, `list_flagged_messages`, `get_attachment`, `save_message_pdf`, `list_messages`, `get_message_body`, `find_unsubscribe_links`, `get_config`.
- **Actions (gated):** `unsubscribe_sender`, `run_cleanup`, `trigger_triage`, `approve_sender`, `move_messages`, `trash_messages`, `unsubscribe_message`, `probe_unsubscribe_link`, `unsubscribe_with_fallback`.
- `save_message_pdf` (added 2026-07-08, ADR-017): renders a flagged message's original text/html to PDF in-process via WeasyPrint (no JS engine, fail-closed egress fetcher — cid:+data: only). Gated like `get_attachment` (no arm flag, no confirmed-action gate) because it performs zero egress and only a local write. Reuses `attachments.downloads_dir` + `flagged.max_attachment_bytes` — NO new config key. Requires WeasyPrint in `.venv` (`weasyprint==69.0`) plus Pango via `brew install weasyprint`. ⚠️ WeasyPrint 69.0 deprecates the dict `url_fetcher` API (class-based `URLFetcher` on a future bump).
- Transport: stdio, local (ADR-013).

## Automation

- Nightly actor: `04:00 actor.py --no-dry-run --folder INBOX`. Currently an openclaw cron on howl-m2 (id `7487ecb0-d13e-4aa1-870a-c646b092c9e2`). Migrating to Unraid User Scripts `docker exec`.
- The actor needs no model — it's a plain Python invocation.

## Clients

- **openclaw** (howl-m2): gateway `ai.openclaw.gateway` (launchd LaunchAgent, login-scoped — no auto-login), model `ollama/gemma4:26b` (fallback `gemma4:e4b`). Reached at `https://openclaw.kamori-tuna.ts.net` (Tailscale service `svc:openclaw`).
- **Claude Desktop / Cowork** (local Mac map-9000): MCP entry `icloud-helper` in `~/Library/Application Support/Claude/claude_desktop_config.json`. NOTE: the running Desktop app rewrites that file from memory — fully quit Desktop before editing it.

## Tailnet

- Tailnet: `kamori-tuna.ts.net`. Nodes: `howl-m2` (Mac Studio), `tower` (Unraid), `map-9000` (local Mac). Ghost node `howl-m2-1` should be removed in the admin console.

## Tests / quality bar

- Run `pytest tests/` explicitly (not bare `pytest`). pylint bar is 10.00/10.
- "No EXPUNGE" is enforced by an AST-checking test — keep it green.

## Expense receipts → Geco (added 2026-07-08)

- Stefan files travel expenses in **Geco** (Reply's internal expense system).
- One folder per trip in `~/Desktop/Expenses/`, named `<dest>-<M:DD-DD>` (e.g. `elm-3:16-19`, `chicago-6:20-26`). The date range in the name scopes which receipts belong to it; completed trips move to `z-archived/`.
- Workflow: pull matching **flagged** iCloud messages (`list_flagged_messages` → `get_attachment` / `get_message_body`), draft a `report.md` at the folder root, drop receipt files (PDF/JPEG) at the folder **root**.
- `processed/` subfolder = receipts Stefan has ALREADY uploaded to Geco (his tracker). **Do NOT stage new receipts there** — leave it alone.
- Stefan's rules: include EVERYTHING charged to a hotel room (don't strip incidentals/gift-shop); a "prepaid" line paid on his own card is a real expense, not a comp; prefer final folios/statements over booking estimates and flag reservation-only items.
- `get_attachment save_to=` writes to `downloads_dir` = `~/Claude/icloud-helper-attachments` (bare filename only); move from there into the trip folder.
- Email-only receipts (Delta flights, Uber, meals) have no attachment → use the `save_message_pdf` MCP tool (added 2026-07-08, ADR-017), which does an in-process print-to-PDF of the message's original HTML via WeasyPrint (Geco rejects typed transcriptions; this gives the real receipt look). Writes to `downloads_dir` = `~/Claude/icloud-helper-attachments`; move into the trip folder. Requires Pango (`brew install weasyprint`). The old external renderers (LibreOffice `soffice --convert-to pdf`; chromium `--headless --print-to-pdf`, Homebrew-deprecated/Gatekeeper-disabled 2026-09-01) are superseded for email HTML receipts.
