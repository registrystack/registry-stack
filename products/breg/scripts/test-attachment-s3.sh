#!/usr/bin/env bash
set -euo pipefail

: "${BREG_TEST_DATABASE_URL:?Set BREG_TEST_DATABASE_URL to a disposable PostgreSQL server}"

# This test owns only the container it starts. Credentials are synthetic and
# the published port is loopback-only; no operator storage is used.
export BREG_TEST_S3_ACCESS_KEY=breg960test
export BREG_TEST_S3_SECRET_KEY=breg960-test-only-secret
export BREG_TEST_S3_BUCKET=breg-http-attachments
container=$(docker run --rm -d -p 127.0.0.1::9000 \
  -e MINIO_ROOT_USER="$BREG_TEST_S3_ACCESS_KEY" \
  -e MINIO_ROOT_PASSWORD="$BREG_TEST_S3_SECRET_KEY" \
  quay.io/minio/minio@sha256:14cea493d9a34af32f524e538b8346cf79f3321eff8e708c1e2960462bd8936e \
  server /data)
trap 'docker stop "$container" >/dev/null' EXIT
port=$(docker port "$container" 9000/tcp)
export BREG_TEST_S3_ENDPOINT="http://$port"
ready=false
for ((attempt=0; attempt<30; attempt++)); do
  if curl --fail --silent "$BREG_TEST_S3_ENDPOINT/minio/health/ready" >/dev/null; then
    ready=true
    break
  fi
  sleep 1
done
[[ "$ready" == true ]] || { echo 'Disposable S3 server did not become ready.' >&2; exit 1; }
docker exec "$container" /usr/bin/mc alias set acceptance http://127.0.0.1:9000 \
  "$BREG_TEST_S3_ACCESS_KEY" "$BREG_TEST_S3_SECRET_KEY" >/dev/null
docker exec "$container" /usr/bin/mc mb "acceptance/$BREG_TEST_S3_BUCKET" >/dev/null

export CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0
export RUSTC_WRAPPER="${RUSTC_WRAPPER-}"
cargo test --locked -p registry-breg --features runtime,schema --lib \
  attachment_storage -- --include-ignored
cargo test --locked -p registry-breg --features postgres-test,tooling \
  --test postgres_change_requests \
  real_s3_http_attachments_preserve_proposals_and_complete_operator_erasure -- --ignored --exact
