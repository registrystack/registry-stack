# syntax=docker/dockerfile:1.7

# Keep the tag for humans and the digest for reproducible pulls.
FROM rust:1.97-trixie@sha256:1bcff4befb740599103a2c7cb51058e14479b2e35e3a34a3f0dc4ede09927488 AS builder
WORKDIR /workspace/registry_relay

COPY Cargo.toml Cargo.lock ./
COPY --from=registry-platform /Cargo.toml /Cargo.lock /workspace/registry-platform/
COPY --from=registry-platform /crates /workspace/registry-platform/crates
COPY --from=registry-manifest /Cargo.toml /README.md /workspace/registry-manifest/
COPY --from=registry-manifest /crates /workspace/registry-manifest/crates
COPY --from=crosswalk /Cargo.toml /Cargo.lock /workspace/crosswalk/
COPY --from=crosswalk /crates /workspace/crosswalk/crates
COPY benches ./benches
COPY resources ./resources
COPY src ./src

ARG REGISTRY_RELAY_FEATURES=""
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/workspace/registry_relay/target \
    find src benches resources -type f -exec touch {} + && \
    if [ -n "$REGISTRY_RELAY_FEATURES" ]; then \
        cargo build --release --locked --features "$REGISTRY_RELAY_FEATURES"; \
    else \
        cargo build --release --locked; \
    fi && \
    cp /workspace/registry_relay/target/release/registry-relay /usr/local/bin/registry-relay && \
    cp /workspace/registry_relay/target/release/registry-relay-rhai-worker /usr/local/bin/registry-relay-rhai-worker && \
    mkdir -p \
        /workspace/runtime-root/etc/registry-relay \
        /workspace/runtime-root/var/lib/registry-relay/cache \
        /workspace/runtime-root/var/lib/registry-relay/data \
        /workspace/runtime-root/var/log/registry-relay && \
    chown -R 65532:65532 /workspace/runtime-root

# Distroless cc keeps glibc and CA certificates while dropping shell/package tools.
FROM gcr.io/distroless/cc-debian13:nonroot@sha256:d97bc0a941b8d4be647dc0ee75b264ddbb772f1ac5ba690a4309c00723b23775 AS runtime

COPY --from=builder --chown=65532:65532 /workspace/runtime-root/ /
COPY --from=builder /usr/local/bin/registry-relay /usr/local/bin/registry-relay
COPY --from=builder /usr/local/bin/registry-relay-rhai-worker /usr/local/bin/registry-relay-rhai-worker
COPY LICENSE /licenses/registry-relay/LICENSE

WORKDIR /var/lib/registry-relay

ENV REGISTRY_RELAY_CONFIG=/etc/registry-relay/config.yaml
EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 CMD ["/usr/local/bin/registry-relay", "healthcheck"]

ENTRYPOINT ["/usr/local/bin/registry-relay"]
CMD ["--config", "/etc/registry-relay/config.yaml"]
