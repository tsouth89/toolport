# Headless Toolport gateway image (OpenAPI + MCP streamable-HTTP).
# Build from the repo root:
#   docker build -t toolport-gateway .
# Published to ghcr.io/tsouth89/toolport-gateway on push to main (see
# .github/workflows/docker-publish.yml).

FROM rust:1-slim-bookworm AS build
WORKDIR /src
RUN apt-get update && apt-get install -y --no-install-recommends \
        pkg-config libssl-dev libdbus-1-dev libglib2.0-dev libgtk-3-dev libwebkit2gtk-4.1-dev libjavascriptcoregtk-4.1-dev \
    && rm -rf /var/lib/apt/lists/*

# Cache dependency compilation: copy manifests + icons (tauri-build needs them),
# stub the sources, build once, then rebuild with the real tree.
COPY src-tauri/Cargo.toml src-tauri/Cargo.lock src-tauri/build.rs src-tauri/tauri.conf.json ./src-tauri/
COPY src-tauri/icons ./src-tauri/icons
COPY src-tauri/capabilities ./src-tauri/capabilities
WORKDIR /src/src-tauri
RUN mkdir -p src/bin && \
    printf '%s\n' \
      '#[cfg(test)] mod tests {}' \
      'pub fn _docker_dep_stub() {}' > src/lib.rs && \
    printf 'fn main() {}\n' > src/main.rs && \
    printf 'fn main() {}\n' > src/bin/toolport-gateway.rs && \
    printf 'fn main() {}\n' > src/bin/mock-mcp-server.rs && \
    cargo build --release --bin toolport-gateway

COPY src-tauri/src ./src
RUN touch src/lib.rs src/main.rs src/bin/toolport-gateway.rs src/bin/mock-mcp-server.rs && \
    cargo build --release --bin toolport-gateway

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates libssl3 libdbus-1-3 curl \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /data
COPY --from=build /src/src-tauri/target/release/toolport-gateway /usr/local/bin/toolport-gateway
RUN useradd --system --uid 10001 --home-dir /data toolport \
    && chown toolport:toolport /data

USER toolport
ENV CONDUIT_HTTP=8765
ENV CONDUIT_HTTP_HOST=0.0.0.0
ENV CONDUIT_REGISTRY=/data/registry.json
EXPOSE 8765
VOLUME ["/data"]

# CONDUIT_HTTP_TOKEN is required for non-loopback binds (enforced by the binary).
ENTRYPOINT ["toolport-gateway", "--http", "8765"]
