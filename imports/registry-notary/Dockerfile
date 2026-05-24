# SPDX-License-Identifier: Apache-2.0

# syntax=docker/dockerfile:1.7

# Keep the tag for humans and the digest for reproducible pulls.
FROM rust:1-bookworm@sha256:6258907abe69656e41cd992e0b705cdcfabcbbe3db374f92ed2d47121282d4a1 AS builder

WORKDIR /workspace/registry-witness
COPY --from=registry-platform Cargo.toml README.md LICENSE /workspace/registry-platform/
COPY --from=registry-platform crates /workspace/registry-platform/crates
COPY . .

RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/workspace/target \
    CARGO_TARGET_DIR=/workspace/target cargo build --release --locked -p registry-witness-bin \
    && cp /workspace/target/release/registry-witness /usr/local/bin/registry-witness

# Distroless cc keeps glibc and CA certificates while dropping shell/package tools.
FROM gcr.io/distroless/cc-debian12:nonroot@sha256:bd2899c12b335c827750ccf2359879eab09c09b206023dcebea408947d54127c AS runtime

COPY --from=builder /usr/local/bin/registry-witness /usr/local/bin/registry-witness

EXPOSE 8080

ENTRYPOINT ["/usr/local/bin/registry-witness"]
