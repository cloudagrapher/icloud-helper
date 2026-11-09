# icloud-helper runbook

Operational procedures for the icloud-helper service on howl-m2.

## Editing policy.toml

`policy.toml` is an allowlist: only senders explicitly listed are acted on.
Absent senders are logged to `pending_senders` and can trigger Discord alerts.

Add a new sender for unsubscription:

```toml
["newsletter@example.com"]
action = "unsubscribe"
```

Silence alerts for a sender you want to keep:

```toml
["receipts@service.com"]
action = "keep"
```

Valid action values: `"unsubscribe"`, `"keep"`. No other values are accepted
by the policy loader.

Add an optional per-sender disposition override:

```toml
["newsletter@example.com"]
action = "unsubscribe"
disposition = "archive"   # overrides global disposition for this sender only
```

Valid disposition values: `"move_to_unsubscribed"`, `"archive"`, `"delete"`.
`"delete"` also requires `allow_delete = true` in `config.toml`.

Changes take effect on the next `actor.py` run — no restart or reload needed.

To remove a sender, delete its block from the file. Existing audit log
entries for that sender are not affected.

## Flipping dry-run to live

**Do not set `dry_run = false` without completing all checks below.**

Pre-flight checklist:

1. Confirm secrets are present and non-empty:

```bash
cat ~/icloud-helper/secrets/icloud_email
cat ~/icloud-helper/secrets/icloud_app_password
```

2. Review the last dry-run output:

```bash
tail -100 ~/icloud-helper/logs/actor.log
```

Confirm the senders listed match what you expect from `policy.toml`.

3. Review the audit log for recent dry-run entries:

```bash
sqlite3 ~/icloud-helper/state/mailcleaner.db \
  "SELECT ts, sender, method, result, detail
   FROM audit_log
   ORDER BY id DESC
   LIMIT 20;"
```

4. Confirm `policy.toml` looks correct and `protected_domains` in
   `config.toml` includes any domains you must never touch.

When satisfied, set `dry_run = false` in `~/icloud-helper/config.toml`:

```toml
dry_run = false
```

Run live:

```bash
cd ~/icloud-helper
.venv/bin/python actor.py
```

To revert immediately without editing the config:

```bash
.venv/bin/python actor.py --dry-run
```

To revert permanently, set `dry_run = true` in `config.toml`.

## Reading the SQLite audit log

The state database is at `~/icloud-helper/state/mailcleaner.db` (mode 0600).

Open it:

```bash
sqlite3 ~/icloud-helper/state/mailcleaner.db
```

List the 50 most recent actions:

```sql
SELECT ts, sender, method, result, detail
FROM audit_log
ORDER BY id DESC
LIMIT 50;
```

Count actions by result type:

```sql
SELECT result, COUNT(*) AS n
FROM audit_log
GROUP BY result
ORDER BY n DESC;
```

Find all actions for a specific sender:

```sql
SELECT ts, method, target, dry_run, http_status, result, detail
FROM audit_log
WHERE sender = 'newsletter@example.com'
ORDER BY id DESC;
```

Check pending senders awaiting a policy decision:

```sql
SELECT sender, classification, unsub_method, message_count, first_seen
FROM pending_senders
WHERE notified_at IS NULL
ORDER BY message_count DESC;
```

Look up the current state of a sender:

```sql
SELECT * FROM sender_state WHERE sender = 'newsletter@example.com';
```

Exit sqlite3: `.quit`

## Scheduling via openclaw

Run `actor.py` daily at 8 AM:

```bash
openclaw cron add \
  --command '.venv/bin/python actor.py' \
  --command-cwd ~/icloud-helper \
  --cron '0 8 * * *'
```

Common cron expressions:

| Schedule | Expression |
|----------|-----------|
| Daily at 8 AM | `0 8 * * *` |
| Every 6 hours | `0 */6 * * *` |
| Weekdays at 7 AM | `0 7 * * 1-5` |

List active jobs:

```bash
openclaw cron list
```

## MCP registration

The MCP server exposes read and action tools to Claude via openclaw. It runs
as a stdio server using the `.venv-mcp` Python 3.13 venv.

Register (run once):

```bash
openclaw mcp add icloud-helper \
  --command /Users/ollama/icloud-helper/.venv-mcp/bin/python3.13 \
  --arg -m --arg icloud_helper.mcp_server \
  --cwd /Users/ollama/icloud-helper
```

Available tools after registration:

| Tool | What it does |
|------|-------------|
| `list_bulk_senders` | Senders from the latest triage report, optional classification filter |
| `get_triage_report` | Full contents of `reports/triage-latest.json` |
| `show_pending_senders` | Senders in `pending_senders` awaiting a policy decision |
| `get_audit_log` | Recent audit log entries |
| `get_sender_status` | State for a specific sender |
| `unsubscribe_sender` | Trigger unsubscribe for a sender already in the allowlist |
| `approve_sender` | Add or update a sender in `policy.toml` (human-authorised path) |
| `run_cleanup` | Shell out to `actor.py` for a full cleanup pass |
| `trigger_triage` | Shell out to `triage.py` to refresh the triage report |

The server reads `dry_run` from `config.toml` at startup and never overrides
it. Action tools enforce the same allowlist and protected-domain guards as
`actor.py`.

## launchd fallback

If you prefer launchd over openclaw cron, create a plist at
`~/Library/LaunchAgents/com.local.icloud-helper.plist`:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
    "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.local.icloud-helper</string>

    <key>ProgramArguments</key>
    <array>
        <string>/Users/ollama/icloud-helper/.venv/bin/python</string>
        <string>/Users/ollama/icloud-helper/actor.py</string>
    </array>

    <key>WorkingDirectory</key>
    <string>/Users/ollama/icloud-helper</string>

    <key>StartCalendarInterval</key>
    <dict>
        <key>Hour</key>
        <integer>8</integer>
        <key>Minute</key>
        <integer>0</integer>
    </dict>

    <key>StandardOutPath</key>
    <string>/Users/ollama/icloud-helper/logs/launchd-stdout.log</string>

    <key>StandardErrorPath</key>
    <string>/Users/ollama/icloud-helper/logs/launchd-stderr.log</string>
</dict>
</plist>
```

Load the agent:

```bash
launchctl load ~/Library/LaunchAgents/com.local.icloud-helper.plist
```

Unload it:

```bash
launchctl unload ~/Library/LaunchAgents/com.local.icloud-helper.plist
```

Adjust `Hour` and `Minute` to change the schedule. Logs land in
`~/icloud-helper/logs/` alongside `actor.log`. `dry_run` is still controlled
by `config.toml`; the plist does not set it.
