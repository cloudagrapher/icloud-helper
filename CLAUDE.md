# icloud-helper

iCloud mail assistant for `stefan@bekker.cloud`: deterministic Python core (allowlist-gated, dry-run default, SQLite-audited) that auto-unsubscribes bulk mail, retrieves flagged-receipt content, and exposes a FastMCP server so Claude (openclaw / Cowork) can judge and propose actions. The model decides WHAT; the core enforces HOW (no EXPUNGE, DKIM/SSRF guards, confirmed-action gate). See `docs/project_notes/` for history.

## Project Memory System

This project maintains institutional knowledge in `docs/project_notes/` for consistency across sessions.

### Memory Files

- **bugs.md** - Bug log with dates, solutions, and prevention notes
- **decisions.md** - Architectural Decision Records (ADRs) with context and trade-offs
- **key_facts.md** - Project configuration, hosts, ports, folder names, important URLs
- **issues.md** - Work log with dates, descriptions, and status

### Memory-Aware Protocols

**Before proposing architectural changes:**
- Check `docs/project_notes/decisions.md` for existing decisions
- Verify the proposed approach doesn't conflict with past choices
- If it does conflict, acknowledge the existing decision and explain why a change is warranted

**When encountering errors or bugs:**
- Search `docs/project_notes/bugs.md` for similar issues
- Apply known solutions if found
- Document new bugs and solutions when resolved

**When looking up project configuration:**
- Check `docs/project_notes/key_facts.md` for hosts, ports, folder names, config flags
- Prefer documented facts over assumptions

**When completing work:**
- Log completed work in `docs/project_notes/issues.md` with date, brief description, and status

**When the user requests memory updates:**
- Update the appropriate memory file and follow the established format

### Style Guidelines for Memory Files

- Prefer bullet lists over tables
- Keep entries concise (1-3 lines for descriptions)
- Always include dates for temporal context
- **Never store secret values** in these files (app passwords, webhook URLs, tokens) — reference their location in `secrets/` instead
- Manual cleanup of old entries is expected (not automated)
