# Mirrors the pinned suite's development server image while fixing its base.
FROM eclipse-temurin:21@sha256:da9d3a4f7650db39b918fc5a2c3da76556fb8cc8e5f3767cdea0bb409286951a

RUN apt-get update \
    && apt-get install -y --no-install-recommends redir=3.3-1build1 \
    && rm -rf /var/lib/apt/lists/*
