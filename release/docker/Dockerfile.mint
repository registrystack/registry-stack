# syntax=docker/dockerfile:1.7@sha256:a57df69d0ea827fb7266491f2813635de6f17269be881f696fbfdf2d83dda33e

ARG SOURCE_DATE_EPOCH=0

FROM debian:trixie-slim@sha256:3a39a0592364683e6bab97937b72cad5a8fa6dcbbee90edb3bb48c7f8e94f258 AS runtime-root
ARG SOURCE_DATE_EPOCH

RUN --mount=type=bind,source=dist/image-bin,target=/workspace/image-bin \
    --mount=type=bind,source=LICENSE,target=/workspace/LICENSE \
    mkdir -p \
        /workspace/runtime-root/etc/registry-mint \
        /workspace/runtime-root/licenses/mint \
        /workspace/runtime-root/usr/local/bin \
        /workspace/runtime-root/var/lib/registry-mint/audit \
    && install -m 0755 /workspace/image-bin/mint /workspace/runtime-root/usr/local/bin/mint \
    && install -m 0644 /workspace/LICENSE /workspace/runtime-root/licenses/mint/LICENSE \
    && chown -R 65532:65532 /workspace/runtime-root/var/lib/registry-mint \
    && chmod 0700 /workspace/runtime-root/var/lib/registry-mint/audit \
    && find /workspace/runtime-root -exec touch -h --date="@${SOURCE_DATE_EPOCH}" {} +

FROM gcr.io/distroless/cc-debian13:nonroot@sha256:a77defd6fedbb3392b175ba8ea3d1c22be963c1597c248c3ba987ddd80bfb512 AS runtime

LABEL org.registrystack.runtime.uid="65532" \
      org.registrystack.runtime.gid="65532"

COPY --from=runtime-root /workspace/runtime-root/ /

WORKDIR /var/lib/registry-mint

ENV MINT_CONFIG=/etc/registry-mint/config.yaml

EXPOSE 8081

# Mint serves GET /health for the platform's HTTP probe. The Distroless image
# has no shell or HTTP client, and Mint has no healthcheck subcommand.
ENTRYPOINT ["/usr/local/bin/mint"]
CMD ["serve"]
