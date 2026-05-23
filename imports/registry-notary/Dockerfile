# SPDX-License-Identifier: Apache-2.0

# syntax=docker/dockerfile:1.7

FROM rust:1-bookworm AS builder

WORKDIR /workspace
COPY . .

RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/workspace/target \
    cargo build --release --locked -p evidence-server-bin \
    && cp /workspace/target/release/evidence-server /usr/local/bin/evidence-server

FROM debian:bookworm-slim AS runtime

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /usr/local/bin/evidence-server /usr/local/bin/evidence-server

USER nobody:nogroup
EXPOSE 8080

ENTRYPOINT ["evidence-server"]
