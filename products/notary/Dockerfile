# SPDX-License-Identifier: Apache-2.0

# syntax=docker/dockerfile:1.7

# Keep the tag for humans and the digest for reproducible pulls.
FROM rust:1-bookworm@sha256:5e2214abe154fe26e39f64488952e5c991eeed1d6d6da7cc8381ae83927f0cfc AS builder

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
    esac

# Runtime policy: the main Notary image is a distroless Rust service image.
# Keep the runtime shell-free, non-root, and compatible with binary healthchecks
# and JSON-array entrypoints. CI enforces this policy.
FROM gcr.io/distroless/cc-debian12:nonroot@sha256:b0ae8e989418b458e0f25489bc3be523718938a2b70864cc0f6a00af1ddbd985 AS runtime

COPY --from=builder /workspace/out/ /usr/local/bin/

ENV REGISTRY_NOTARY_BIND=0.0.0.0:8080
EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 CMD ["/usr/local/bin/registry-notary", "healthcheck"]

WORKDIR /var/lib/registry-notary
ENTRYPOINT ["/usr/local/bin/registry-notary"]
CMD ["--config", "/etc/registry-notary/config.yaml"]
