# syntax=docker/dockerfile:1.7@sha256:a57df69d0ea827fb7266491f2813635de6f17269be881f696fbfdf2d83dda33e

FROM rust:1.95-trixie@sha256:f49565f188ee00bc2a18dd418183f2c5f23ef7d6e691890517ed341a598f67c3 AS builder

# pg_query 6.1.1 always invokes bindgen and regenerates its Rust protobuf types
# when Cargo exposes a protoc command. Freeze the archive and both packages so
# BReg's canonical build does not consult Debian's mutable package indexes.
RUN rm -f /etc/apt/sources.list.d/debian.sources \
    && printf '%s\n' \
        'deb [check-valid-until=no] https://snapshot.debian.org/archive/debian/20250810T000000Z trixie main' \
        >/etc/apt/sources.list \
    && apt-get update -qq \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        libclang-19-dev=1:19.1.7-3+b1 \
        protobuf-compiler=3.21.12-11 \
    && rm -rf /var/lib/apt/lists/*
