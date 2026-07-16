# Mirrors the pinned suite's development server image while fixing its base.
FROM eclipse-temurin:25@sha256:201fbb8886b2d273218aa3a192f0afbf7b5ff65ee8cc6ef47f5dce2171f013ea

RUN apt-get update \
    && apt-get install -y --no-install-recommends redir=3.3-1build1 \
    && rm -rf /var/lib/apt/lists/*
