# syntax=docker/dockerfile:1.7@sha256:a57df69d0ea827fb7266491f2813635de6f17269be881f696fbfdf2d83dda33e

FROM rust:1.98-trixie@sha256:bf5a9aa29062a6cb03c49bd59a46eb55e3cc770caf598a221a7866e500be3082 AS builder

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
        python3-pip=25.1.1+dfsg-1 \
    && rm -rf /var/lib/apt/lists/*

# The release binaries are compiled and linked with Zig so each one binds only
# the glibc symbols of the floor in release/glibc-floor.env. Without it the
# builder's own much newer glibc decides the floor by accident, and a binary
# that starts here refuses to start on a supported distribution. Zig arrives
# from the Python index against recorded file hashes, so a file substituted
# there later is rejected rather than installed.
COPY release/requirements/ziglang-0.12.1.txt /tmp/ziglang-requirements.txt
RUN python3 -m pip install --no-cache-dir --break-system-packages --require-hashes \
        --requirement /tmp/ziglang-requirements.txt \
    && rm -f /tmp/ziglang-requirements.txt \
    && test "$(python3 -m ziglang version)" = 0.12.1
