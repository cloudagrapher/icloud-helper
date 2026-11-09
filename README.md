# icloud-helper

Automated iCloud IMAP cleanup. Scans configured mailboxes for bulk senders,
triages them against a per-sender policy, and optionally unsubscribes,
archives, or moves their messages. All actions default to dry-run; no
mutations occur until you explicitly disable it.

## How it works

Two scripts run in sequence:

1. `triage.py` — read-only scan. Connects to iCloud IMAP via SSL, fetches
   message headers without marking anything as read, and classifies bulk
   senders as `newsletter`, `spam`, or `unknown`. Writes
   `reports/triage-latest.json`.

2. `actor.py` — applies policy. Loads the triage output, matches senders
   against `policy.toml`, and acts: unsubscribing via one-click HTTP or
   mailto, moving messages, or archiving. Records every action to
   `state/mailcleaner.db`.

## Directory structure

```
icloud-helper/
├── actor.py              # Cleanup orchestrator
├── triage.py             # Read-only IMAP scanner and classifier
├── config.toml           # Global settings (dry_run, folders, rate limits)
├── policy.toml           # Per-sender allowlist
├── policy.example.toml   # Template — copy to policy.toml and edit
├── logs/
│   └── actor.log         # actor.py run log (appended each run)
├── reports/
│   └── triage-latest.json  # Latest triage output, read by actor.py
├── secrets/
│   ├── icloud_email        # iCloud email address (mode 0600)
│   └── icloud_app_password # App-specific password (mode 0600)
├── state/
│   └── mailcleaner.db    # SQLite audit log and sender state
├── icloud_helper/
│   ├── disposition.py    # IMAP move, archive, and soft-delete actions
│   ├── headers.py        # Header parsing and bulk-mail classification
│   ├── imap_client.py    # IMAP connection and batch-fetch helpers
│   ├── mcp_server.py     # FastMCP stdio server (read + action tools)
│   ├── notify.py         # Discord webhook for pending-sender alerts
│   ├── policy.py         # Config and policy loaders and dataclasses
│   ├── secrets.py        # Secret file reader
│   ├── state.py          # SQLite DAO for audit log, sender state, pending queue
│   └── unsubscribe.py    # One-click HTTP and mailto unsubscribe handlers
├── .venv/                # Python 3.9 venv for triage.py and actor.py
└── .venv-mcp/            # Python 3.13 venv for the MCP server
```

## Setup

Prerequisites:
- Python 3.9 installed (`python3.9 --version`)
- Python 3.13 installed (`python3.13 --version`) — MCP server only
- iCloud IMAP enabled (iCloud.com > Settings > Mail > check that IMAP access is on)
- App-specific password from [appleid.apple.com](https://appleid.apple.com) under
  Security > App-Specific Passwords

Create the main venv (used by `triage.py` and `actor.py`):

```bash
cd ~/icloud-helper
python3.9 -m venv .venv
.venv/bin/pip install tomli tomlkit
```

Verify:

```bash
.venv/bin/python -c "import tomli, tomlkit; print('main venv ok')"
```

Create the MCP venv (only needed if you use the MCP server):

```bash
python3.13 -m venv .venv-mcp
.venv-mcp/bin/pip install 'mcp[cli]'
```

## Secrets

Credentials are stored as plain text files in `secrets/`, each at mode 0600.
`read_secret()` exits with an error if a file is missing, so both must be
present before running either script.

| File | Content |
|------|---------|
| `secrets/icloud_email` | Full iCloud email address |
| `secrets/icloud_app_password` | App-specific password — 16-character format (`xxxx-xxxx-xxxx-xxxx`), not your Apple ID password |

Create them:

```bash
echo -n 'you@icloud.com' > ~/icloud-helper/secrets/icloud_email
echo -n 'abcd-efgh-ijkl-mnop' > ~/icloud-helper/secrets/icloud_app_password
chmod 600 ~/icloud-helper/secrets/icloud_email \
          ~/icloud-helper/secrets/icloud_app_password
```

`secrets/discord_webhook_url` exists in the directory but is not currently
read by the code — the webhook URL is set in `config.toml` for now. A future
refactor will move it here.

## config.toml

| Key | Default | Description |
|-----|---------|-------------|
| `folders` | `["INBOX", "Junk"]` | Folders to scan each run |
| `dry_run` | `true` | Master safety switch. No HTTP requests or IMAP mutations when true |
| `allow_delete` | `false` | Enables permanent deletion. Requires `dry_run = false` and `disposition = "delete"` |
| `disposition` | `"move_to_unsubscribed"` | Default action for unsubscribed senders. Options: `"move_to_unsubscribed"`, `"archive"`, `"delete"` |
| `protected_domains` | `[]` | Domains never acted on regardless of policy (banks, employers, etc.) |
| `discord_webhook_url` | `""` | Discord incoming webhook URL for new-sender notifications. Empty disables it |
| `rate_limits.max_unsubscribes_per_run` | `5` | Safety cap on unsubscribe actions per run |
| `rate_limits.request_sleep_seconds` | `2.0` | Wait time between outbound unsubscribe requests |

## policy.toml

Each entry is a TOML table keyed by the lowercase sender email address. Only
senders explicitly listed here are acted on.

Valid actions:

- `"unsubscribe"` — send an unsubscribe request and apply the configured
  disposition to their existing messages
- `"keep"` — silence new-sender alerts; never act on this sender

```toml
["newsletter@example.com"]
action = "unsubscribe"

["receipts@bank.com"]
action = "keep"
```

An optional `disposition` key overrides the global default for a specific sender:

```toml
["newsletter@example.com"]
action = "unsubscribe"
disposition = "archive"
```

Senders absent from `policy.toml` are logged to `pending_senders` in the state
DB and trigger a Discord notification if a webhook URL is configured.

## Running triage.py

`triage.py` is read-only and safe to run at any time. It never modifies
messages or sets the IMAP Seen flag.

```bash
cd ~/icloud-helper
.venv/bin/python triage.py --folder INBOX
```

Limit the scan to the first 200 messages (useful when testing against a large mailbox):

```bash
.venv/bin/python triage.py --folder INBOX --limit 200
```

Output: a summary table to stdout and `reports/triage-latest.json` with full
sender data. `actor.py` reads this JSON on its next run.

## Running actor.py

`actor.py` reads `dry_run` from `config.toml` by default. The `--dry-run`
and `--no-dry-run` flags override it for a single run.

Dry-run pass (safe at any time — no network calls or IMAP changes):

```bash
cd ~/icloud-helper
.venv/bin/python actor.py --dry-run
```

Expected output:

```
==============================...
DRY-RUN MODE: no network I/O or IMAP mutations will occur
==============================...
INFO actor: Would unsubscribe: newsletter@example.com (method=one-click)
INFO actor: Dry-run complete.
```

Restrict to one folder:

```bash
.venv/bin/python actor.py --dry-run --folder INBOX
```

Limit messages processed per folder:

```bash
.venv/bin/python actor.py --dry-run --folder INBOX --limit 500
```

Run output goes to stdout and is appended to `logs/actor.log`. Review the log
after each dry run before flipping to live mode.
# icloud-helper
