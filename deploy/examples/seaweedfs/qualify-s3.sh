#!/usr/bin/env bash
set -euo pipefail

command -v grep >/dev/null 2>&1 || {
	printf '%s\n' 'grep is required.' >&2
	exit 1
}

image='chrislusf/seaweedfs@sha256:ccad23e18639c8b98cee17e7100b95830a06077b56d8e5b006d6dcf8ec5e94a0'
bucket='registry-breg-attachments'
other_bucket='registry-breg-other'
app_access='breg-qualification-app'
app_secret='breg-qualification-app-secret'
bootstrap_access='breg-qualification-bootstrap'
bootstrap_secret='breg-qualification-bootstrap-secret'
scratch=$(mktemp -d "${TMPDIR:-/tmp}/registry-seaweedfs-qualification.XXXXXX")
container="registry-seaweedfs-qualification-$$"

cleanup() {
	docker rm --force "$container" >/dev/null 2>&1 || true
	rm -f "$scratch/s3.json" "$scratch/app.curl" "$scratch/bootstrap.curl" \
		"$scratch/proof.curl" "$scratch/payload" "$scratch/download" \
		"$scratch/versioning"
	rmdir "$scratch" 2>/dev/null || true
}
trap cleanup EXIT

printf '%s\n' "qualification attachment" >"$scratch/payload"
printf 'user = "%s:%s"\n' "$app_access" "$app_secret" >"$scratch/app.curl"
printf 'user = "%s:%s"\n' "$bootstrap_access" "$bootstrap_secret" \
	>"$scratch/bootstrap.curl"
printf 'user = "%s:%s"\n' 'breg960test' 'breg960-test-only-secret' \
	>"$scratch/proof.curl"
chmod 600 "$scratch/app.curl" "$scratch/bootstrap.curl" "$scratch/proof.curl"

cat >"$scratch/s3.json" <<EOF
{
  "identities": [
    {
      "name": "bootstrap",
      "credentials": [
        {"accessKey": "$bootstrap_access", "secretKey": "$bootstrap_secret"}
      ],
      "actions": ["Admin:registry-breg-attachments"]
    },
    {
      "name": "registry-breg",
      "credentials": [
        {"accessKey": "$app_access", "secretKey": "$app_secret"}
      ],
      "actions": [
        "Read:registry-breg-attachments",
        "Write:registry-breg-attachments"
      ]
    },
    {
      "name": "maintained-breg-proof",
      "credentials": [
        {"accessKey": "breg960test", "secretKey": "breg960-test-only-secret"}
      ],
      "actions": ["Admin", "Read", "Write", "List", "Tagging"]
    }
  ]
}
EOF
chmod 755 "$scratch"
chmod 644 "$scratch/s3.json"

docker run --detach --name "$container" --publish 127.0.0.1::8333 \
	--volume "$scratch:/config:ro" "$image" \
	server -s3 -s3.config=/config/s3.json -dir=/data >/dev/null

endpoint="http://$(docker port "$container" 8333/tcp)"
ready=false
for ((attempt = 0; attempt < 45; attempt++)); do
	if curl --fail --silent "$endpoint/healthz" >/dev/null; then
		ready=true
		break
	fi
	sleep 1
done
if [[ "$ready" != true ]]; then
	printf '%s\n' 'Disposable SeaweedFS server did not become ready.' >&2
	docker logs --tail 50 "$container" >&2
	exit 1
fi

curl --fail --silent --show-error --config "$scratch/bootstrap.curl" \
	--aws-sigv4 "aws:amz:us-east-1:s3" -X PUT "$endpoint/$bucket" >/dev/null

# This is the same no-versioning startup probe BReg performs before accepting
# an attachment store. Any Enabled or Suspended status would be refused.
curl --fail --silent --show-error --config "$scratch/app.curl" \
	--aws-sigv4 "aws:amz:us-east-1:s3" \
	"$endpoint/$bucket?versioning" >"$scratch/versioning"
versioning_status=0
grep -E -q '<Status>(Enabled|Suspended)</Status>' "$scratch/versioning" || versioning_status=$?
if [[ "$versioning_status" -eq 0 ]]; then
	printf '%s\n' 'Disposable bucket unexpectedly has versioning configured.' >&2
	exit 1
elif [[ "$versioning_status" -ne 1 ]]; then
	printf 'Could not check the versioning response (grep exited %s).\n' "$versioning_status" >&2
	exit 1
fi

curl --fail --silent --show-error --config "$scratch/app.curl" \
	--aws-sigv4 "aws:amz:us-east-1:s3" --data-binary @"$scratch/payload" \
	-X PUT "$endpoint/$bucket/breg/qualification/object" >/dev/null
curl --fail --silent --show-error --config "$scratch/app.curl" \
	--aws-sigv4 "aws:amz:us-east-1:s3" \
	"$endpoint/$bucket/breg/qualification/object" >"$scratch/download"
cmp "$scratch/payload" "$scratch/download"
curl --fail --silent --show-error --config "$scratch/app.curl" \
	--aws-sigv4 "aws:amz:us-east-1:s3" -X DELETE \
	"$endpoint/$bucket/breg/qualification/object" >/dev/null

if curl --fail --silent --config "$scratch/app.curl" \
	--aws-sigv4 "aws:amz:us-east-1:s3" -X PUT \
	"$endpoint/$other_bucket" >/dev/null 2>&1; then
	printf '%s\n' 'expected the bucket-scoped identity to refuse another bucket' >&2
	exit 1
fi

if [[ "${RUN_BREG_S3_TESTS:-0}" == 1 ]]; then
	curl --fail --silent --show-error --config "$scratch/proof.curl" \
		--aws-sigv4 "aws:amz:us-east-1:s3" -X PUT \
		"$endpoint/breg-http-attachments" >/dev/null
	export BREG_TEST_S3_ACCESS_KEY='breg960test'
	export BREG_TEST_S3_SECRET_KEY='breg960-test-only-secret'
	export BREG_TEST_S3_BUCKET='breg-http-attachments'
	export BREG_TEST_S3_ENDPOINT="$endpoint"
	export OBJECTSTORE_TEST_S3_URL="$endpoint"
	export CARGO_INCREMENTAL=0
	export CARGO_PROFILE_DEV_DEBUG=0
	export CARGO_PROFILE_TEST_DEBUG=0
	cargo test --locked -p registry-platform-objectstore --lib s3 -- --include-ignored
	cargo test --locked -p registry-breg --features runtime,tooling,schema --lib \
		attachment_storage -- --include-ignored
fi

printf '%s\n' 'SeaweedFS S3 qualification passed.'
