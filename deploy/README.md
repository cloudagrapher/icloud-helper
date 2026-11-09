# Remote read-only deployment (Unraid + Tailscale + Caddy)

This runs `icloud_helper.remote_server` so claude.ai can use icloud-helper as a
custom connector.  The local stdio server (`icloud_helper.mcp_server`, ADR-013)
is unchanged and keeps every tool.  The remote one exposes five read tools
only: `list_messages`, `get_message_body`, `list_flagged_messages`,
`find_unsubscribe_links` and `get_attachment` (no `save_to`).  See ADR-018.

```
claude.ai ──https──> Caddy on the VPS (tag:edge) ──tailnet──> icloud-helper on Unraid (tag:mcp)
                     /mcp, /token, /register, /.well-known/*: Anthropic IPs only
                     /authorize, /auth/callback, /consent: open (your browser)
```

Every `<placeholder>` below is yours to fill.  Never commit a filled-in copy.

## 1. GitHub OAuth app

Create an OAuth app under your GitHub account (Settings > Developer settings >
OAuth Apps):

- Homepage URL: `https://<mcp.your-domain.example>`
- Authorization callback URL: `https://<mcp.your-domain.example>/auth/callback`

Note the client id.  Generate a client secret and put it straight into the
secret file in step 2.  Find your numeric user id with
`gh api user --jq .id` (pinning it survives a username change).

## 2. Files on Unraid

Under `/mnt/user/appdata/icloud-helper` (or set `APPDATA`):

```
config.toml              remote copy, with allow_confirmed_actions = false
                         and allow_delete = false (defence in depth)
policy.toml              copy of the local one
secrets/                 icloud_email, icloud_app_password  (mode 600)
secrets-runtime/         ts_authkey, github_client_secret, jwt_signing_key
state/                   empty; the container creates mailcleaner.db
fastmcp/                 empty; encrypted OAuth client and token state
tailscale/               empty; Tailscale node state
```

- `jwt_signing_key`: `openssl rand -base64 48 > secrets-runtime/jwt_signing_key`
- `ts_authkey`: a tagged (`tag:mcp`), pre-approved, single-use auth key.
- Make `secrets/`, `state/` and `fastmcp/` owned by uid 10001 (the container
  user): `chown -R 10001:10001 secrets state fastmcp && chmod 600 secrets/*`.
- Use a separate iCloud app-specific password for this host, so revoking it
  doesn't touch the Mac.

## 3. Start it

```
cd deploy/unraid
docker compose up -d --build
docker compose logs -f icloud-helper
```

The log line should read `icloud-helper remote: read-only, 5 tools, allowed
GitHub login <you>`.

## 4. Tailscale ACL

Allow only the edge to reach the app, on one port:

```json
{"action": "accept", "src": ["tag:edge"], "dst": ["tag:mcp:8765"]}
```

## 5. Caddy on the VPS

Copy `deploy/vps/Caddyfile` into the VPS's Caddy config, fill the
placeholders and reload.  If the DERP relay already holds 443 on that VPS,
move one of them first (a second IP, or a second small VPS).

## 6. Add the connector

claude.ai > Settings > Connectors > Add custom connector, URL
`https://<mcp.your-domain.example>/mcp`.  Sign in with GitHub and approve the
consent page.  Any other GitHub account gets a 401 on every call.

## Kill switch (fastest first)

1. Remove the connector in claude.ai.
2. Disable the Caddy site and reload Caddy.
3. Remove the `tag:edge -> tag:mcp` ACL grant.
4. Replace `jwt_signing_key` and restart, which invalidates every issued token.
5. Revoke the host's iCloud app-specific password at account.apple.com.

## Not verified yet

- The Docker image has not been built here (no Docker daemon in the build
  environment).  WeasyPrint's Pango libraries are installed because
  `mcp_server` imports it.
- No live GitHub sign-in has been run against a real OAuth app.
- The Caddyfile was not checked with `caddy validate`.
- `TS_AUTHKEY: file:...` relies on the Tailscale image reading a key from a
  file; if your image version doesn't, pass the key once via `TS_AUTHKEY` and
  remove it after the node registers.
