# syntax=docker/dockerfile:1.7@sha256:a57df69d0ea827fb7266491f2813635de6f17269be881f696fbfdf2d83dda33e

# SPDX-License-Identifier: Apache-2.0

# Adopter and development images for the `mint` and `evidence` services.
#
# These are not release evidence. Release images are assembled from
# release/docker with binaries produced outside Docker by
# release/scripts/build-release-binaries.sh under the pinned builder image.
#
# Build from the repository root:
#
#   docker build -f docker/Dockerfile --target mint -t registry-mint .
#   docker build -f docker/Dockerfile --target evidence -t registry-evidence .
#
# cargo-chef turns dependency compilation into an ordinary image layer keyed
# on the manifests and lockfile alone, so registry and CI layer caches
# survive source-only changes. Each binary gets its own recipe, filtered to
# its transitive dependency closure, so a manifest change in an unrelated
# workspace member invalidates neither image.

# Keep the tag for humans and the digest for reproducible pulls.
FROM rust:1.95-trixie@sha256:f49565f188ee00bc2a18dd418183f2c5f23ef7d6e691890517ed341a598f67c3 AS chef
RUN cargo install cargo-chef --locked --version 0.1.77
WORKDIR /workspace

# The planner reruns on any source change, but that is cheap: the recipes it
# emits depend only on the manifests and lockfile, so unchanged recipes keep
# the cook layers below cached.
FROM chef AS planner
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
COPY products ./products
RUN cargo chef prepare --recipe-path recipe-mint.json --bin mint \
    && cargo chef prepare --recipe-path recipe-evidence.json --bin evidence

FROM chef AS mint-builder
COPY --from=planner /workspace/recipe-mint.json recipe.json
# No --locked here: the bin-filtered recipe carries a lockfile trimmed to the
# closure, which cargo would refuse to reconcile. The final build is --locked.
RUN cargo chef cook --release --recipe-path recipe.json --bin mint
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
COPY products ./products
RUN cargo build --release --locked -p registry-mint --bin mint \
    && mkdir -p /workspace/runtime-root/etc/registry-mint \
    && chown -R 65532:65532 /workspace/runtime-root

# Distroless cc keeps glibc and CA certificates while dropping shell/package tools.
FROM gcr.io/distroless/cc-debian13:nonroot@sha256:c31ff9abcb1910f3ab25c7957bdaf0bfe12a01eb546e8df2282f1c8f682b606c AS mint

COPY --from=mint-builder /workspace/runtime-root/ /
COPY --from=mint-builder /workspace/target/release/mint /usr/local/bin/mint
COPY LICENSE /licenses/registry-mint/LICENSE

# The configuration is a startup-only deployment artifact; mount it read-only
# at /etc/registry-mint. Key material and the client registry live beside it
# at whatever paths the configuration names.
ENV MINT_CONFIG=/etc/registry-mint/config.yaml
EXPOSE 8081

# No HEALTHCHECK: distroless has no shell or curl and the binary has no
# healthcheck subcommand. The service serves GET /health for HTTP probes.
ENTRYPOINT ["/usr/local/bin/mint"]
CMD ["serve"]

FROM chef AS evidence-builder
COPY --from=planner /workspace/recipe-evidence.json recipe.json
# No --locked here: the bin-filtered recipe carries a lockfile trimmed to the
# closure, which cargo would refuse to reconcile. The final build is --locked.
RUN cargo chef cook --release --recipe-path recipe.json --bin evidence
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
COPY products ./products
RUN cargo build --release --locked -p registry-evidence --bin evidence \
    && mkdir -p \
        /workspace/runtime-root/etc/registry-evidence \
        /workspace/runtime-root/var/lib/registry-evidence/audit \
    && chown -R 65532:65532 /workspace/runtime-root

FROM gcr.io/distroless/cc-debian13:nonroot@sha256:c31ff9abcb1910f3ab25c7957bdaf0bfe12a01eb546e8df2282f1c8f682b606c AS evidence

COPY --from=evidence-builder /workspace/runtime-root/ /
COPY --from=evidence-builder /workspace/target/release/evidence /usr/local/bin/evidence
COPY LICENSE /licenses/registry-evidence/LICENSE

WORKDIR /var/lib/registry-evidence

# The runtime file, governed bundle, and secret root are startup-only
# deployment artifacts; mount them read-only under /etc/registry-evidence.
# Point the runtime's audit destination under /var/lib/registry-evidence,
# which is writable by the nonroot user.
ENV REGISTRY_EVIDENCE_RUNTIME=/etc/registry-evidence/runtime.yaml
EXPOSE 8080

# No HEALTHCHECK: distroless has no shell or curl and the binary has no
# healthcheck subcommand. The service serves GET /health for HTTP probes.
ENTRYPOINT ["/usr/local/bin/evidence"]
CMD ["serve"]
