# SPDX-License-Identifier: Apache-2.0

# syntax=docker/dockerfile:1.7

# Keep the tag for humans and the digest for reproducible pulls.
FROM rust:1-bookworm@sha256:8fa55b2f3ddf97471ab6a767bfa3f37e6bad0986ba823e75fea57e2a2a5c3073 AS builder

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
FROM gcr.io/distroless/cc-debian12:nonroot@sha256:66aa873a4a14fb164aa01296058efd8253744606d72715e45acface073359faa AS runtime

COPY --from=builder /workspace/out/ /usr/local/bin/

ENV REGISTRY_NOTARY_BIND=0.0.0.0:8080
EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 CMD ["/usr/local/bin/registry-notary", "healthcheck"]

WORKDIR /var/lib/registry-notary
ENTRYPOINT ["/usr/local/bin/registry-notary"]
CMD ["--config", "/etc/registry-notary/config.yaml"]
