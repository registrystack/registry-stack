# syntax=docker/dockerfile:1.7@sha256:a57df69d0ea827fb7266491f2813635de6f17269be881f696fbfdf2d83dda33e

# SPDX-License-Identifier: Apache-2.0

# Adopter and development images for the `evidence` and `casework` services.
#
# These are not release evidence. Release images are assembled from
# release/docker with binaries produced outside Docker by
# release/scripts/build-release-binaries.sh under the pinned builder image.
#
# Build from the repository root:
#
#   docker build -f docker/Dockerfile --target evidence -t registry-evidence .
#   docker build -f docker/Dockerfile --target casework -t registry-casework .
#
# cargo-chef turns dependency compilation into an ordinary image layer keyed
# on the manifests and lockfile alone, so registry and CI layer caches
# survive source-only changes. Each binary gets its own recipe, filtered to
# its transitive dependency closure, so a manifest change in an unrelated
# workspace member invalidates none of these images.

ARG SOURCE_DATE_EPOCH=0

# Keep the tag for humans and the digest for reproducible pulls.
FROM rust:1.98-trixie@sha256:a8a5f0a1e5fe7dfe1d352591e4a1c7dd2c08fd70475cae872cf3458ba0df0546 AS chef
RUN cargo install cargo-chef --locked --version 0.1.77
WORKDIR /workspace

# The planner reruns on any source change, but that is cheap: the recipes it
# emits depend only on the manifests and lockfile, so unchanged recipes keep
# the cook layers below cached.
FROM chef AS planner
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
COPY products ./products
RUN cargo chef prepare --recipe-path recipe-evidence.json --bin evidence \
    && cargo chef prepare --recipe-path recipe-casework.json --bin casework

FROM chef AS evidence-builder
ARG SOURCE_DATE_EPOCH
COPY --from=planner /workspace/recipe-evidence.json recipe.json
# No --locked here: the bin-filtered recipe carries a lockfile trimmed to the
# closure, which cargo would refuse to reconcile. The final build is --locked.
RUN cargo chef cook --release --recipe-path recipe.json --bin evidence
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
COPY products ./products
ADD --checksum=sha256:967aa62605721081c3eb2a17650611a792aa802d76a6511d1840242623d204c9 https://snapshot.debian.org/archive/debian/20260913T000000Z/pool/main/g/glibc/libc6_2.41-12+deb13u4_amd64.deb /workspace/runtime-packages/libc6_2.41-12+deb13u4_amd64.deb
ADD --checksum=sha256:8784eda966b189c777a384dac5ce009e8fc9b52d006926c5a013e7fa8aa688cc https://snapshot.debian.org/archive/debian/20260913T000000Z/pool/main/g/glibc/libc6_2.41-12+deb13u4_arm64.deb /workspace/runtime-packages/libc6_2.41-12+deb13u4_arm64.deb
RUN --mount=type=bind,source=release/scripts/install-runtime-libc6.sh,target=/workspace/install-runtime-libc6.sh,readonly \
    cargo build --release --locked -p registry-evidence --bin evidence \
    && mkdir -p \
        /workspace/runtime-root/etc/registry-evidence \
        /workspace/runtime-root/var/lib/registry-evidence/audit \
    && /workspace/install-runtime-libc6.sh /workspace/runtime-root /workspace/runtime-packages \
    && chown -R 65532:65532 /workspace/runtime-root/var/lib/registry-evidence \
    && chmod 0700 /workspace/runtime-root/var/lib/registry-evidence/audit \
    && find /workspace/runtime-root -exec touch -h --date="@${SOURCE_DATE_EPOCH}" {} +

FROM gcr.io/distroless/cc-debian13:nonroot@sha256:54df941ed0d06a1bd95ef5e0ce391fd8d9f94b64782dc9a60062727849ee3f97 AS evidence

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

FROM chef AS casework-builder
ARG SOURCE_DATE_EPOCH
COPY --from=planner /workspace/recipe-casework.json recipe.json
RUN cargo chef cook --release --recipe-path recipe.json --bin casework
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
COPY products ./products
ADD --checksum=sha256:967aa62605721081c3eb2a17650611a792aa802d76a6511d1840242623d204c9 https://snapshot.debian.org/archive/debian/20260913T000000Z/pool/main/g/glibc/libc6_2.41-12+deb13u4_amd64.deb /workspace/runtime-packages/libc6_2.41-12+deb13u4_amd64.deb
ADD --checksum=sha256:8784eda966b189c777a384dac5ce009e8fc9b52d006926c5a013e7fa8aa688cc https://snapshot.debian.org/archive/debian/20260913T000000Z/pool/main/g/glibc/libc6_2.41-12+deb13u4_arm64.deb /workspace/runtime-packages/libc6_2.41-12+deb13u4_arm64.deb
RUN --mount=type=bind,source=release/scripts/install-runtime-libc6.sh,target=/workspace/install-runtime-libc6.sh,readonly \
    cargo build --release --locked -p registry-casework --bin casework \
    && mkdir -p \
        /workspace/runtime-root/etc/registry-casework \
        /workspace/runtime-root/var/lib/registry-casework/audit \
    && /workspace/install-runtime-libc6.sh /workspace/runtime-root /workspace/runtime-packages \
    && chown -R 65532:65532 /workspace/runtime-root/var/lib/registry-casework \
    && chmod 0700 /workspace/runtime-root/var/lib/registry-casework/audit \
    && find /workspace/runtime-root -exec touch -h --date="@${SOURCE_DATE_EPOCH}" {} +

FROM gcr.io/distroless/cc-debian13:nonroot@sha256:54df941ed0d06a1bd95ef5e0ce391fd8d9f94b64782dc9a60062727849ee3f97 AS casework

COPY --from=casework-builder /workspace/runtime-root/ /
COPY --from=casework-builder /workspace/target/release/casework /usr/local/bin/casework
COPY LICENSE /licenses/registry-casework/LICENSE

WORKDIR /var/lib/registry-casework
EXPOSE 8100

ENTRYPOINT ["/usr/local/bin/casework"]
CMD ["--runtime-config", "/etc/registry-casework/runtime.yaml", "serve"]
