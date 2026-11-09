# icloud-helper remote MCP server (read-only, Streamable HTTP, GitHub OAuth).
# Build:  docker build -t icloud-helper-remote .
# Run it with deploy/unraid/compose.yaml, which adds the Tailscale sidecar,
# volumes and secrets.  Nothing in this image holds a credential.
FROM python:3.13-slim

# WeasyPrint (imported by mcp_server via render_pdf) needs Pango at import time.
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      libpango-1.0-0 libpangoft2-1.0-0 libharfbuzz-subset0 fonts-dejavu-core \
 && rm -rf /var/lib/apt/lists/*

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    ICLOUD_HELPER_READ_ONLY=1 \
    FASTMCP_HOME=/data/fastmcp

WORKDIR /app
COPY requirements.txt requirements-remote.txt ./
RUN pip install --no-cache-dir -r requirements-remote.txt

COPY icloud_helper ./icloud_helper

# Runtime mounts (see compose.yaml): config.toml, policy.toml (ro),
# secrets/ (ro), state/ (rw), /data/fastmcp (rw).
RUN useradd --system --uid 10001 --home-dir /app --shell /usr/sbin/nologin icloud \
 && mkdir -p /app/state /app/secrets /data/fastmcp \
 && chown -R icloud:icloud /app/state /data/fastmcp
USER icloud

EXPOSE 8765
CMD ["python", "-m", "icloud_helper.remote_server"]
