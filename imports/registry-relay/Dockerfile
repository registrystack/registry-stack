# syntax=docker/dockerfile:1.7

FROM rust:1-bookworm AS builder
WORKDIR /workspace

COPY Cargo.toml Cargo.lock ./
COPY benches ./benches
COPY resources ./resources
COPY src ./src

RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/workspace/target \
    cargo build --release --locked && \
    cp /workspace/target/release/registry-relay /usr/local/bin/registry-relay

FROM debian:bookworm-slim AS runtime

RUN groupadd --system --gid 10001 registry_relay && \
    useradd --system --uid 10001 --gid registry_relay --home-dir /var/lib/registry-relay --shell /usr/sbin/nologin registry_relay && \
    mkdir -p /etc/registry-relay /var/lib/registry-relay/cache /var/lib/registry-relay/data /var/log/registry-relay && \
    chown -R registry_relay:registry_relay /var/lib/registry-relay /var/log/registry-relay && \
    apt-get update && \
    apt-get install -y --no-install-recommends ca-certificates && \
    rm -rf /var/lib/apt/lists/*

COPY --from=builder /usr/local/bin/registry-relay /usr/local/bin/registry-relay
COPY LICENSE /licenses/registry-relay/LICENSE

USER registry_relay:registry_relay
WORKDIR /var/lib/registry-relay

ENV REGISTRY_RELAY_CONFIG=/etc/registry-relay/config.yaml
EXPOSE 8080

ENTRYPOINT ["/usr/local/bin/registry-relay"]
CMD ["--config", "/etc/registry-relay/config.yaml"]
