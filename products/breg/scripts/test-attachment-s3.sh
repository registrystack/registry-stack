#!/usr/bin/env bash
set -euo pipefail

: "${BREG_TEST_DATABASE_URL:?Set BREG_TEST_DATABASE_URL to a disposable PostgreSQL server}"

# This test owns only the container it starts. Credentials are synthetic and
# the published port is loopback-only; no operator storage is used.
export BREG_TEST_S3_ACCESS_KEY=breg960test
export BREG_TEST_S3_SECRET_KEY=breg960-test-only-secret
export BREG_TEST_S3_BUCKET=breg-http-attachments
# SeaweedFS takes its static S3 credentials from a mounted identities file
# rather than environment variables; write one scoped to this run only.
config_dir=$(mktemp -d)
container=
trap 'if [[ -n "$container" ]]; then docker rm --force "$container" >/dev/null; fi; rm -rf "$config_dir"' EXIT
cat >"$config_dir/s3.json" <<EOF
{
  "identities": [
    {
      "name": "breg-test",
      "credentials": [
        {"accessKey": "$BREG_TEST_S3_ACCESS_KEY", "secretKey": "$BREG_TEST_S3_SECRET_KEY"}
      ],
      "actions": ["Admin", "Read", "Write", "List", "Tagging"]
    }
  ]
}
EOF
# The image drops to its own unprivileged user, so the file must be readable
# to it; the credentials are the synthetic ones already written above.
chmod 755 "$config_dir"
chmod 644 "$config_dir/s3.json"
container=$(docker run -d -p 127.0.0.1::8333 \
  -v "$config_dir:/config:ro" \
  chrislusf/seaweedfs@sha256:ce9e796f1fe6f06968f4c04bdaf8f678dad9c8acdfef3d244133d71bfa6bf882 \
  server -s3 -s3.config=/config/s3.json -dir=/data)
port=$(docker port "$container" 8333/tcp)
export BREG_TEST_S3_ENDPOINT="http://$port"
ready=false
for ((attempt=0; attempt<30; attempt++)); do
  if curl --fail --silent "$BREG_TEST_S3_ENDPOINT/healthz" >/dev/null; then
    ready=true
    break
  fi
  sleep 1
done
if [[ "$ready" != true ]]; then
  echo 'Disposable S3 server did not become ready.' >&2
  docker logs --tail 50 "$container" >&2
  exit 1
fi
# Bucket creation goes straight through the S3 API with the host's own curl
# rather than a CLI baked into the image, so the choice of server image never
# adds a tooling dependency here.
curl --fail --silent --show-error --aws-sigv4 "aws:amz:us-east-1:s3" \
  --user "$BREG_TEST_S3_ACCESS_KEY:$BREG_TEST_S3_SECRET_KEY" \
  -X PUT "$BREG_TEST_S3_ENDPOINT/$BREG_TEST_S3_BUCKET" >/dev/null

export CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0
export RUSTC_WRAPPER="${RUSTC_WRAPPER-}"
# The two feature sets match test-postgres.sh, so running after it reuses
# its registry-breg builds.
cargo test --locked -p registry-breg --features runtime,tooling,schema --lib \
  attachment_storage -- --include-ignored
cargo test --locked -p registry-breg --features postgres-test,tooling,schema \
  --test postgres_change_requests \
  real_s3_http_attachments_preserve_proposals_and_complete_operator_erasure -- --ignored --exact
