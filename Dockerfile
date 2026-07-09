# Runtime-only headless Toolport gateway image.
# CI builds `toolport-gateway` with cached Rust (see docker-publish.yml) and
# copies the binary in as `toolport-gateway-bin` before `docker build`.
# For a from-source local build, use: docker build -f Dockerfile.source .

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates libssl3 libdbus-1-3 curl \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /data
COPY toolport-gateway-bin /usr/local/bin/toolport-gateway
RUN chmod 755 /usr/local/bin/toolport-gateway \
    && useradd --system --uid 10001 --home-dir /data toolport \
    && chown toolport:toolport /data

USER toolport
ENV CONDUIT_HTTP=8765
ENV CONDUIT_HTTP_HOST=0.0.0.0
ENV CONDUIT_REGISTRY=/data/registry.json
EXPOSE 8765
VOLUME ["/data"]

ENTRYPOINT ["toolport-gateway", "--http", "8765"]
