# syntax=docker/dockerfile:1.7

FROM rust:1-bookworm AS builder
WORKDIR /workspace

COPY Cargo.toml Cargo.lock ./
COPY src ./src

RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/workspace/target \
    cargo build --release --locked && \
    cp /workspace/target/release/data_gate /usr/local/bin/data_gate

FROM debian:bookworm-slim AS runtime

RUN groupadd --system --gid 10001 data_gate && \
    useradd --system --uid 10001 --gid data_gate --home-dir /var/lib/data_gate --shell /usr/sbin/nologin data_gate && \
    mkdir -p /etc/data_gate /var/lib/data_gate/cache /var/lib/data_gate/data /var/log/data_gate && \
    chown -R data_gate:data_gate /var/lib/data_gate /var/log/data_gate && \
    apt-get update && \
    apt-get install -y --no-install-recommends ca-certificates && \
    rm -rf /var/lib/apt/lists/*

COPY --from=builder /usr/local/bin/data_gate /usr/local/bin/data_gate
COPY LICENSE /licenses/data_gate/LICENSE

USER data_gate:data_gate
WORKDIR /var/lib/data_gate

ENV DATAGATE_CONFIG=/etc/data_gate/config.yaml
EXPOSE 8080

ENTRYPOINT ["/usr/local/bin/data_gate"]
CMD ["--config", "/etc/data_gate/config.yaml"]
