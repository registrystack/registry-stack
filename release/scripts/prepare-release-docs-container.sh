#!/usr/bin/env bash
# Canonical preparation environment, shared by the maintained prepare-docs command.
set -euo pipefail
cp -R /input/. /workspace
apt-get update -qq
# The steps below need git, Python with PyYAML, and the tools that fetch Node.
# None compiles Rust: the CLI reference renders the committed command catalog.
apt-get install -y -qq ca-certificates curl git python3 python3-yaml xz-utils
cd /tmp
curl -fsSLO https://nodejs.org/dist/v22.12.0/node-v22.12.0-linux-x64.tar.xz
curl -fsSLO https://nodejs.org/dist/v22.12.0/SHASUMS256.txt
grep '  node-v22.12.0-linux-x64.tar.xz$' SHASUMS256.txt | sha256sum -c -
tar -xJf node-v22.12.0-linux-x64.tar.xz
export PATH="/tmp/node-v22.12.0-linux-x64/bin:${PATH}"
cd /workspace/docs/site
npm ci
node scripts/prepare-release-docs-metadata.mjs \
  --version "${DOCS_VERSION}" --release-id "${DOCS_RELEASE_ID}" \
  --date "${DOCS_DATE}" --json > /output/metadata.json
# Archive source generation exports HEAD. Make metadata visible in this scratch
# history only; the returned patch is always relative to the original source.
git add src/data/docsets.yaml src/data/repo-docs.yaml
if ! git diff --cached --quiet; then
  git -c user.name='Registry documentation preparation' \
    -c user.email='docs-preparation@localhost' -c commit.gpgsign=false \
    -c core.hooksPath=/dev/null commit -m 'Stage candidate documentation metadata'
fi
npm test
npm run check:draft-links
npm run check:evidence-anchors
export DOCS_DOCSET="v${DOCS_VERSION}"
npm run build:archive
lock_mode="$(node --input-type=module -e '
  import fs from "node:fs"; import YAML from "yaml";
  const lock = YAML.parse(fs.readFileSync("src/data/archive-lock.yaml", "utf8"));
  console.log(Object.hasOwn(lock.archives, process.env.DOCS_DOCSET) ? "--verify-lock" : "--write-lock");
')"
npm run archive:snapshot -- "${DOCS_DOCSET}" --output "/output/${DOCS_DOCSET}.tar.gz" "${lock_mode}"
npm run archive:snapshot -- "${DOCS_DOCSET}" --verify-lock
# These checks require the new lock; never create placeholder digests to run them early.
unset DOCS_DOCSET
npm run check
npm run check:archive-lock -- --base-ref "${DOCS_SOURCE_SHA}"
cd /workspace
git diff --binary "${DOCS_SOURCE_SHA}" -- \
  docs/site/src/data/docsets.yaml docs/site/src/data/repo-docs.yaml \
  docs/site/src/data/archive-lock.yaml > /output/documentation.patch
git diff --name-only -z "${DOCS_SOURCE_SHA}" -- \
  docs/site/src/data/docsets.yaml docs/site/src/data/repo-docs.yaml \
  docs/site/src/data/archive-lock.yaml | python3 -c \
  'import json,sys; print(json.dumps([p for p in sys.stdin.read().split("\0") if p]))' \
  > /output/changed-paths.json
