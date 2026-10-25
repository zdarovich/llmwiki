# LLM Wiki local image: Next.js standalone + FastAPI + SQLite in one container.
# Build from the repo root:  docker build -f docker/local/Dockerfile -t llmwiki .
# Run:                       docker run -p 3000:3000 -v ~/my-wiki:/workspace llmwiki

FROM node:22-bookworm-slim AS web-build
WORKDIR /build/web
COPY web/package.json web/package-lock.json ./
RUN npm ci
COPY web/ ./
COPY tests/fixtures/parity/ /build/tests/fixtures/parity/
ENV NEXT_PUBLIC_MODE=local \
    NEXT_PUBLIC_API_URL=/api \
    NEXT_TELEMETRY_DISABLED=1
RUN npm run build

FROM python:3.11-slim-bookworm
WORKDIR /app
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    MODE=local \
    WORKSPACE_PATH=/workspace \
    API_URL=http://localhost:3000/api

# opendataloader-pdf (the default local PDF parser) shells out to java.
RUN apt-get update && apt-get install -y --no-install-recommends default-jre-headless \
    && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir uv

COPY api/requirements.lock ./api/requirements.lock
RUN uv pip install --system --require-hashes -r api/requirements.lock

# The MCP server pins its own dependency set — isolate it in a venv.
COPY mcp/requirements.lock ./mcp/requirements.lock
RUN uv venv /opt/mcp && uv pip install --python /opt/mcp/bin/python --require-hashes -r mcp/requirements.lock

COPY --from=node:22-bookworm-slim /usr/local/bin/node /usr/local/bin/node

COPY api/ ./api/
COPY mcp/ ./mcp/
COPY shared/ ./shared/
COPY llmwiki ./llmwiki
COPY --from=web-build /build/web/.next/standalone /app/web
COPY --from=web-build /build/web/.next/static /app/web/.next/static
COPY --from=web-build /build/web/public /app/web/public
COPY docker/local/entrypoint.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

VOLUME /workspace
EXPOSE 3000
HEALTHCHECK --interval=30s --timeout=5s --start-period=30s \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:3000/api/health', timeout=3)" || exit 1

ENTRYPOINT ["/app/entrypoint.sh"]
