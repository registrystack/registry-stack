# SPDX-License-Identifier: Apache-2.0

# syntax=docker/dockerfile:1.7

# Keep the tag for humans and the digest for reproducible pulls.
FROM rust:1.97-trixie@sha256:1bcff4befb740599103a2c7cb51058e14479b2e35e3a34a3f0dc4ede09927488 AS builder

WORKDIR /workspace/registry-notary
COPY --from=registry-platform Cargo.toml README.md LICENSE /workspace/registry-platform/
COPY --from=registry-platform crates /workspace/registry-platform/crates
COPY --from=crosswalk Cargo.toml /workspace/crosswalk/
COPY --from=crosswalk crates /workspace/crosswalk/crates
COPY . .

ARG REGISTRY_NOTARY_FEATURES="registry-notary-cel,pkcs11"
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/workspace/target \
    if [ -n "$REGISTRY_NOTARY_FEATURES" ]; then \
        CARGO_TARGET_DIR=/workspace/target cargo build --release --locked -p registry-notary --features "$REGISTRY_NOTARY_FEATURES"; \
    else \
        CARGO_TARGET_DIR=/workspace/target cargo build --release --locked -p registry-notary; \
    fi \
    && mkdir -p /workspace/out \
    && cp /workspace/target/release/registry-notary /workspace/out/registry-notary \
    && case ",$REGISTRY_NOTARY_FEATURES," in \
        *,registry-notary-cel,*) \
            CARGO_TARGET_DIR=/workspace/target cargo build --release --locked -p registry-notary-server --bin registry-notary-cel-worker --features "$REGISTRY_NOTARY_FEATURES" \
            && cp /workspace/target/release/registry-notary-cel-worker /workspace/out/registry-notary-cel-worker ;; \
        *) true ;; \
    esac \
    && mkdir -p \
        /workspace/runtime-root/etc/registry-notary \
        /workspace/runtime-root/var/lib/registry-notary \
        /workspace/runtime-root/var/log/registry-notary \
    && chown -R 65532:65532 /workspace/runtime-root

# Runtime policy: the main Notary image is a distroless Rust service image.
# Keep the runtime shell-free, non-root, and compatible with binary healthchecks
# and JSON-array entrypoints. CI enforces this policy.
FROM gcr.io/distroless/cc-debian13:nonroot@sha256:d97bc0a941b8d4be647dc0ee75b264ddbb772f1ac5ba690a4309c00723b23775 AS runtime

COPY --from=builder --chown=65532:65532 /workspace/runtime-root/ /
COPY --from=builder /workspace/out/ /usr/local/bin/

ENV REGISTRY_NOTARY_BIND=0.0.0.0:8080
EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 CMD ["/usr/local/bin/registry-notary", "healthcheck"]

WORKDIR /var/lib/registry-notary
ENTRYPOINT ["/usr/local/bin/registry-notary"]
CMD ["--config", "/etc/registry-notary/config.yaml"]
