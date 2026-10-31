#!/usr/bin/env bash
# One-shot generator for the governed-ingestion bad-corpus members and the
# job control directory. Run directly; it writes only under
# products/adapter/fixtures/corpus/. Pins are recomputed from the written
# bytes with shasum, exactly as the corpus README requires.
set -euo pipefail

repo_root=$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../../../.." && pwd)
corpus="$repo_root/products/adapter/fixtures/corpus"
bad="$corpus/bad"

profile_body() {
  cat <<'EOF'
# yaml-language-server: $schema=https://id.registrystack.org/schemas/adapter/profile/profile.v1alpha1.schema.json
#
# Bad-corpus member @@CODE@@: this artifact set must be refused with
# exactly @@CODE@@. Clean baseline profile.
#
# Refuse with:
#   target/debug/adapterctl check products/adapter/fixtures/corpus/bad/@@CODE@@/project.yaml
apiVersion: id.registrystack.org/formats/adapter/profile/v1alpha1
kind: AdapterProfile
id: case-api
version: "1"
operations:
  - id: cases-get
    method: GET
    path: /v2/cases/{type}/{case_id}
    pathParameters:
      - type
      - case_id
    recordTypeParameter: type
    recordIdParameter: case_id
    responseEnvelope: '{"case": {{record}}, "fetchedAt": "{{requestId}}"}'
problems:
  - code: cases.upstream
    status: 502
    title: the source could not be reached
    classes: [upstream, breaker.open, throttle.rejected, loop.maximum-iterations-reached]
  - code: cases.mapping
    status: 422
    title: the request or its mapping was refused
    classes: [validation, conversion.unmapped, aggregation.duplicate]
  - code: cases.exhausted
    status: 502
    title: the run exhausted a budget
    classes: [script, budget.exhausted]
  - code: cases.boundary
    status: 500
    title: the facade refused the call
    classes: [disclosure.violation, egress.refused, credential.rejected, outcome, facade]
problemEnvelope: '{"family": "{{problemCode}}"}'
EOF
}

project_body() {
  cat <<'EOF'
# yaml-language-server: $schema=https://id.registrystack.org/schemas/adapter/project/project.v1alpha1.schema.json
#
# Bad-corpus member @@CODE@@: this artifact set must be refused with
# exactly @@CODE@@. @@PROJECT_DEFECT@@
#
# Refuse with:
#   target/debug/adapterctl check products/adapter/fixtures/corpus/bad/@@CODE@@/project.yaml
apiVersion: id.registrystack.org/formats/adapter/project/v1alpha1
kind: AdapterProject
project:
  id: case-api-example
  version: "1"
profile:
  id: case-api
  version: "1"
  digest: @@PROFILE_DIGEST@@
pack:
  id: case-api-pack
  version: "1"
  digest: @@PACK_DIGEST@@
recordTypes:
  - name: case
    fields:
      - name: case_type
        type: string
        required: true
templatedRoutes:
  - routeTemplate: find-cases
    routeId: case-find
bindings:
  - id: case-get
    operation: cases-get
    recordType: case
    route: @@BINDING_ROUTE@@
    maximumUpstreamCalls: 4
accessProfiles:
  - id: case-reader
    scopes:
      - cases.read
    operations:
      - cases-get
    recordTypes:
      - case
EOF
}

# finish_member <code> <project defect> [<binding route>]
finish_member() {
  local code="$1" project_defect="$2" binding_route="${3:-case-find}"
  local dir="$bad/$code"
  local profile_digest pack_digest
  profile_digest=$(shasum -a 256 "$dir/profile.yaml" | awk '{print "sha256:" $1}')
  pack_digest=$(shasum -a 256 "$dir/pack.yaml" | awk '{print "sha256:" $1}')
  project_body \
    | sed "s/@@CODE@@/$code/g" \
    | sed "s|@@PROJECT_DEFECT@@|$project_defect|" \
    | sed "s/@@PROFILE_DIGEST@@/$profile_digest/" \
    | sed "s/@@PACK_DIGEST@@/$pack_digest/" \
    | sed "s/@@BINDING_ROUTE@@/$binding_route/" > "$dir/project.yaml"
}

# begin_member <code> <pack defect sentence>
begin_member() {
  local code="$1" pack_defect="$2"
  local dir="$bad/$code"
  mkdir -p "$dir"
  profile_body | sed "s/@@CODE@@/$code/g" > "$dir/profile.yaml"
  {
    cat <<EOF
# yaml-language-server: \$schema=https://id.registrystack.org/schemas/adapter/pack/pack.v1alpha1.schema.json
#
# Bad-corpus member $code: this artifact set must be refused with
# exactly $code. $pack_defect
#
# Refuse with:
#   target/debug/adapterctl check products/adapter/fixtures/corpus/bad/$code/project.yaml
apiVersion: id.registrystack.org/formats/adapter/pack/v1alpha1
kind: AdapterPack
id: case-api-pack
version: "1"
testedVersions:
  - "1.0"
endpoints:
EOF
  } > "$dir/pack.yaml"
}

facade_endpoint() {
  cat <<'EOF'
  - id: cases
    component: http
    authentication:
      type: basic
    attemptTimeoutMilliseconds: 10000
    maximumResponseBytes: 1048576
EOF
}

job_endpoint_file() {
  cat <<'EOF'
  - id: submissions
    component: file
    authentication:
      type: none
    attemptTimeoutMilliseconds: 10000
    maximumResponseBytes: 1048576
EOF
}

postgres_endpoint() {
  cat <<'EOF'
  - id: ledger
    component: postgres
    authentication:
      type: none
    attemptTimeoutMilliseconds: 10000
    maximumResponseBytes: 1048576
    queryFile: queries/ledger.sql
EOF
}

ledger_query_file() {
  cat <<'EOF'
queryFiles:
  - path: queries/ledger.sql
    digest: sha256:1111111111111111111111111111111111111111111111111111111111111111
EOF
}

facade_template() {
  cat <<'EOF'
routeTemplates:
  - id: find-cases
    parameters:
      - name: type
        type: string
        required: false
      - name: case_id
        type: string
        required: false
    steps:
      - to:
          uri: http:cases
          parameters:
            httpMethod: GET
            path: /v2/cases/{{type}}/{{case_id}}
            pathParameters:
              type:
                constant: welfare
              case_id:
                header: recordId
            query:
              _format:
                constant: json
EOF
}

unpinned_postgres_endpoint() {
  cat <<'EOF'
  - id: ledger
    component: postgres
    authentication:
      type: none
    attemptTimeoutMilliseconds: 10000
    maximumResponseBytes: 1048576
EOF
}

capline() {
  printf 'capabilities: {}\n'
}

# ---------------------------------------------------------------------------
# adapter.job.component-facade-refused
# ---------------------------------------------------------------------------
begin_member "adapter.job.component-facade-refused" \
  "The bound find-cases template sends to the postgres job component, so the facade path reaches a job-only send."
{
  postgres_endpoint
  ledger_query_file
  cat <<'EOF'
routeTemplates:
  - id: find-cases
    parameters:
      - name: type
        type: string
        required: false
      - name: case_id
        type: string
        required: false
    steps:
      - to:
          uri: postgres:ledger
EOF
  capline
} >> "$bad/adapter.job.component-facade-refused/pack.yaml"
finish_member "adapter.job.component-facade-refused" \
  "Clean baseline project; the defect sits in the pack."

# ---------------------------------------------------------------------------
# adapter.job.poll-facade-refused
# ---------------------------------------------------------------------------
begin_member "adapter.job.poll-facade-refused" \
  "The bound find-cases template carries a pollEnrich step, which the facade path must never poll through."
{
  facade_endpoint
  job_endpoint_file
  cat <<'EOF'
routeTemplates:
  - id: find-cases
    parameters:
      - name: type
        type: string
        required: false
      - name: case_id
        type: string
        required: false
    steps:
      - pollEnrich:
          uri: file:submissions
          timeoutMilliseconds: 5000
      - to:
          uri: http:cases
          parameters:
            httpMethod: GET
            path: /v2/cases/{{type}}/{{case_id}}
            pathParameters:
              type:
                constant: welfare
              case_id:
                header: recordId
            query:
              _format:
                constant: json
EOF
  capline
} >> "$bad/adapter.job.poll-facade-refused/pack.yaml"
finish_member "adapter.job.poll-facade-refused" \
  "Clean baseline project; the defect sits in the pack."

# ---------------------------------------------------------------------------
# adapter.job.send-component-refused
# ---------------------------------------------------------------------------
begin_member "adapter.job.send-component-refused" \
  "The bound find-cases template sends to file:submissions; a job source is read through pollEnrich, never sent to."
{
  facade_endpoint
  job_endpoint_file
  facade_template
  cat <<'EOF'
      - to:
          uri: file:submissions
      - to:
          uri: http:cases
          parameters:
            httpMethod: GET
            path: /v2/cases/{{type}}/{{case_id}}
            pathParameters:
              type:
                constant: welfare
              case_id:
                header: recordId
            query:
              _format:
                constant: json
EOF
  capline
} >> "$bad/adapter.job.send-component-refused/pack.yaml"
finish_member "adapter.job.send-component-refused" \
  "Clean baseline project; the defect sits in the pack."

# ---------------------------------------------------------------------------
# adapter.job.source-scan-required
# ---------------------------------------------------------------------------
begin_member "adapter.job.source-scan-required" \
  "The source route declares nextRecovery but no scan, so the item contract is undeclared."
{
  facade_endpoint
  facade_template
  cat <<'EOF'
sourceRoutes:
  - id: kobo-submissions
    nextRecovery: key-deduplicated
    steps: []
EOF
  capline
} >> "$bad/adapter.job.source-scan-required/pack.yaml"
finish_member "adapter.job.source-scan-required" \
  "Clean baseline project; the defect sits in the pack."

# ---------------------------------------------------------------------------
# adapter.job.source-recovery-required
# ---------------------------------------------------------------------------
begin_member "adapter.job.source-recovery-required" \
  "The source route declares scan but no recovery semantics for next."
{
  facade_endpoint
  facade_template
  cat <<'EOF'
sourceRoutes:
  - id: kobo-submissions
    scan: ongoing
    steps: []
EOF
  capline
} >> "$bad/adapter.job.source-recovery-required/pack.yaml"
finish_member "adapter.job.source-recovery-required" \
  "Clean baseline project; the defect sits in the pack."

# ---------------------------------------------------------------------------
# adapter.job.source-id-collision
# ---------------------------------------------------------------------------
begin_member "adapter.job.source-id-collision" \
  "The source route id find-cases collides with the find-cases route template id."
{
  facade_endpoint
  facade_template
  cat <<'EOF'
sourceRoutes:
  - id: find-cases
    scan: ongoing
    nextRecovery: exact-replay
    steps: []
EOF
  capline
} >> "$bad/adapter.job.source-id-collision/pack.yaml"
finish_member "adapter.job.source-id-collision" \
  "Clean baseline project; the defect sits in the pack."

# ---------------------------------------------------------------------------
# adapter.job.source-bound-refused
# ---------------------------------------------------------------------------
begin_member "adapter.job.source-bound-refused" \
  "The pack is clean; the project binds a facade operation to the source route id, which is a job entry point only."
{
  facade_endpoint
  facade_template
  cat <<'EOF'
sourceRoutes:
  - id: kobo-submissions
    scan: ongoing
    nextRecovery: key-deduplicated
    steps: []
EOF
  capline
} >> "$bad/adapter.job.source-bound-refused/pack.yaml"
finish_member "adapter.job.source-bound-refused" \
  "The binding names the source route id kobo-submissions (it co-fires adapter.project.unknown-route, whose condition is the strict superset here)." \
  "kobo-submissions"

# ---------------------------------------------------------------------------
# adapter.job.source-called-refused
# ---------------------------------------------------------------------------
begin_member "adapter.job.source-called-refused" \
  "The bound find-cases template sends to direct:kobo-submissions; acquisition never enters the facade path, so a source route is not a subroutine."
{
  facade_endpoint
  facade_template
  cat <<'EOF'
      - to:
          uri: direct:kobo-submissions
sourceRoutes:
  - id: kobo-submissions
    scan: ongoing
    nextRecovery: key-deduplicated
    steps: []
EOF
  capline
} >> "$bad/adapter.job.source-called-refused/pack.yaml"
finish_member "adapter.job.source-called-refused" \
  "Clean baseline project; the defect sits in the pack."

# ---------------------------------------------------------------------------
# adapter.job.poll-endpoint-unknown
# ---------------------------------------------------------------------------
begin_member "adapter.job.poll-endpoint-unknown" \
  "The source route polls file:nope, which no declared endpoint answers."
{
  facade_endpoint
  facade_template
  cat <<'EOF'
sourceRoutes:
  - id: kobo-submissions
    scan: ongoing
    nextRecovery: exact-replay
    steps:
      - pollEnrich:
          uri: file:nope
          timeoutMilliseconds: 5000
EOF
  capline
} >> "$bad/adapter.job.poll-endpoint-unknown/pack.yaml"
finish_member "adapter.job.poll-endpoint-unknown" \
  "Clean baseline project; the defect sits in the pack."

# ---------------------------------------------------------------------------
# adapter.job.poll-endpoint-kind
# ---------------------------------------------------------------------------
begin_member "adapter.job.poll-endpoint-kind" \
  "The source route polls file:dropbox, but dropbox is an sftp endpoint, so the scheme and the component disagree."
{
  facade_endpoint
  cat <<'EOF'
  - id: dropbox
    component: sftp
    authentication:
      type: none
    attemptTimeoutMilliseconds: 10000
    maximumResponseBytes: 1048576
EOF
  facade_template
  cat <<'EOF'
sourceRoutes:
  - id: kobo-submissions
    scan: ongoing
    nextRecovery: exact-replay
    steps:
      - pollEnrich:
          uri: file:dropbox
          timeoutMilliseconds: 5000
EOF
  capline
} >> "$bad/adapter.job.poll-endpoint-kind/pack.yaml"
finish_member "adapter.job.poll-endpoint-kind" \
  "Clean baseline project; the defect sits in the pack."

# ---------------------------------------------------------------------------
# adapter.job.poll-timeout
# ---------------------------------------------------------------------------
begin_member "adapter.job.poll-timeout" \
  "The source route's pollEnrich declares no timeoutMilliseconds, so one read is unbounded."
{
  facade_endpoint
  job_endpoint_file
  facade_template
  cat <<'EOF'
sourceRoutes:
  - id: kobo-submissions
    scan: ongoing
    nextRecovery: exact-replay
    steps:
      - pollEnrich:
          uri: file:submissions
EOF
  capline
} >> "$bad/adapter.job.poll-timeout/pack.yaml"
finish_member "adapter.job.poll-timeout" \
  "Clean baseline project; the defect sits in the pack."

# ---------------------------------------------------------------------------
# adapter.job.decoder-unknown
# ---------------------------------------------------------------------------
begin_member "adapter.job.decoder-unknown" \
  "The source route's pollEnrich names decoder parquet, outside the closed csv, jsonl, and raw set."
{
  facade_endpoint
  job_endpoint_file
  facade_template
  cat <<'EOF'
sourceRoutes:
  - id: kobo-submissions
    scan: ongoing
    nextRecovery: exact-replay
    steps:
      - pollEnrich:
          uri: file:submissions
          timeoutMilliseconds: 5000
          decoder: parquet
EOF
  capline
} >> "$bad/adapter.job.decoder-unknown/pack.yaml"
finish_member "adapter.job.decoder-unknown" \
  "Clean baseline project; the defect sits in the pack."

# ---------------------------------------------------------------------------
# adapter.job.postgres-query-unpinned
# ---------------------------------------------------------------------------
begin_member "adapter.job.postgres-query-unpinned" \
  "The postgres endpoint names no queryFile, so its SQL is unpinned."
{
  facade_endpoint
  unpinned_postgres_endpoint
  facade_template
  capline
} >> "$bad/adapter.job.postgres-query-unpinned/pack.yaml"
finish_member "adapter.job.postgres-query-unpinned" \
  "Clean baseline project; the defect sits in the pack."

# ---------------------------------------------------------------------------
# adapter.job.postgres-parameters-unbounded
# ---------------------------------------------------------------------------
begin_member "adapter.job.postgres-parameters-unbounded" \
  "The source route's postgres send carries seventeen named parameters, one past the bound of sixteen."
{
  facade_endpoint
  postgres_endpoint
  ledger_query_file
  facade_template
  cat <<'EOF'
sourceRoutes:
  - id: kobo-submissions
    scan: ongoing
    nextRecovery: exact-replay
    steps:
      - to:
          uri: postgres:ledger
          parameters:
            queryParameters:
              p00: {constant: 0}
              p01: {constant: 1}
              p02: {constant: 2}
              p03: {constant: 3}
              p04: {constant: 4}
              p05: {constant: 5}
              p06: {constant: 6}
              p07: {constant: 7}
              p08: {constant: 8}
              p09: {constant: 9}
              p10: {constant: 10}
              p11: {constant: 11}
              p12: {constant: 12}
              p13: {constant: 13}
              p14: {constant: 14}
              p15: {constant: 15}
              p16: {constant: 16}
EOF
  capline
} >> "$bad/adapter.job.postgres-parameters-unbounded/pack.yaml"
finish_member "adapter.job.postgres-parameters-unbounded" \
  "Clean baseline project; the defect sits in the pack."

# ---------------------------------------------------------------------------
# adapter.job.endpoint-response-bound
# ---------------------------------------------------------------------------
begin_member "adapter.job.endpoint-response-bound" \
  "The bound facade template's cases endpoint declares a response bound above the facade ceiling; only a source-route-only endpoint may declare up to the platform cap."
{
  facade_endpoint | sed 's/maximumResponseBytes: 1048576/maximumResponseBytes: 2097152/'
  facade_template
  capline
} >> "$bad/adapter.job.endpoint-response-bound/pack.yaml"
finish_member "adapter.job.endpoint-response-bound" \
  "Clean baseline project; the defect sits in the pack."

# ---------------------------------------------------------------------------
# The four job-definition members: a clean workspace plus a job.yaml whose
# defect the job compiler's check_job refuses.
# ---------------------------------------------------------------------------

begin_job_member() {
  # $1 code, $2 job defect, $3 job route, $4 response bytes, $5 page bytes,
  # $6 page deadline (optional, default 300000)
  local code="$1" job_defect="$2" job_route="$3" response_bytes="$4" page_bytes="$5"
  local deadline="${6:-300000}"
  local dir="$bad/$code"
  mkdir -p "$dir"
  profile_body | sed "s/@@CODE@@/$code/g" > "$dir/profile.yaml"
  {
    cat <<EOF
# yaml-language-server: \$schema=https://id.registrystack.org/schemas/adapter/pack/pack.v1alpha1.schema.json
#
# Bad-corpus member $code: this artifact set must be refused with
# exactly $code. Clean baseline pack; the job definition beside it carries
# the defect.
#
# Refuse with:
#   target/debug/adapterctl check products/adapter/fixtures/corpus/bad/$code/project.yaml
apiVersion: id.registrystack.org/formats/adapter/pack/v1alpha1
kind: AdapterPack
id: case-api-pack
version: "1"
testedVersions:
  - "1.0"
endpoints:
EOF
    facade_endpoint
    job_endpoint_file
    postgres_endpoint
    ledger_query_file
    facade_template
    cat <<'EOF'
sourceRoutes:
  - id: kobo-submissions
    scan: ongoing
    nextRecovery: key-deduplicated
    steps:
      - pollEnrich:
          uri: file:submissions
          timeoutMilliseconds: 5000
          decoder: csv
      - to:
          uri: postgres:ledger
          parameters:
            queryParameters:
              since:
                exchangeProperty: AdapterJobCursor
EOF
    capline
  } > "$dir/pack.yaml"
  local profile_digest pack_digest
  profile_digest=$(shasum -a 256 "$dir/profile.yaml" | awk '{print "sha256:" $1}')
  pack_digest=$(shasum -a 256 "$dir/pack.yaml" | awk '{print "sha256:" $1}')
  project_body \
    | sed "s/@@CODE@@/$code/g" \
    | sed "s|@@PROJECT_DEFECT@@|Clean baseline project; the defect sits in the job definition.|" \
    | sed "s/@@PROFILE_DIGEST@@/$profile_digest/" \
    | sed "s/@@PACK_DIGEST@@/$pack_digest/" \
    | sed "s/@@BINDING_ROUTE@@/case-find/" > "$dir/project.yaml"
  {
    cat <<EOF
# yaml-language-server: \$schema=https://id.registrystack.org/schemas/adapter/job/job.v1alpha1.schema.json
#
# Bad-corpus member $code: this artifact set must be refused with
# exactly $code. $job_defect
#
# The job definition is refused by the job compiler's check_job over the
# pinned pack beside this file (the workspace itself stays clean):
#   job check products/adapter/fixtures/corpus/bad/$code/job.yaml
#     --pack products/adapter/fixtures/corpus/bad/$code/pack.yaml
apiVersion: id.registrystack.org/formats/adapter/job/v1alpha1
kind: AdapterJob
job:
  id: kobo-daily
  version: "1"
source:
  pack:
    id: case-api-pack
    version: "1"
    digest: $pack_digest
  route: $job_route
profile:
  pageDeadlineMilliseconds: $deadline
  maximumResponseBytes: $response_bytes
  maximumPageItems: 500
  maximumPageBytes: $page_bytes
  read:
    maximumFileBytes: 1073741824
    maximumRowBytes: 1048576
    maximumFieldBytes: 65536
    maximumRowsPerPage: 500
EOF
  } > "$dir/job.yaml"
}

begin_job_member "adapter.job.route-unknown" \
  "The job names source route nope, which the pinned pack's sourceRoutes do not declare." \
  "nope" 16777216 1048576

begin_job_member "adapter.job.profile-bound" \
  "The profile's pageDeadlineMilliseconds lies above its 600000 bound." \
  "kobo-submissions" 16777216 1048576 600001

begin_job_member "adapter.job.profile-inconsistent" \
  "The profile's maximumPageBytes exceeds its own maximumResponseBytes." \
  "kobo-submissions" 1048576 2097152

begin_job_member "adapter.job.profile-endpoint-bound" \
  "The profile's maximumResponseBytes is tighter than the ledger endpoint's declared bound, which the source route reaches." \
  "kobo-submissions" 1048575 1048575

# ---------------------------------------------------------------------------
# The clean job-mode control: a pack with sourceRoutes, a pollEnrich route,
# and a postgres endpoint, beside a matching job artifact.
# ---------------------------------------------------------------------------
control="$corpus/base-job"
mkdir -p "$control"
{
  cat <<'EOF'
# yaml-language-server: $schema=https://id.registrystack.org/schemas/adapter/profile/profile.v1alpha1.schema.json
#
# The clean job-mode control: profile.
#
# Check with:
#   target/debug/adapterctl check products/adapter/fixtures/corpus/base-job/project.yaml
apiVersion: id.registrystack.org/formats/adapter/profile/v1alpha1
kind: AdapterProfile
id: case-api
version: "1"
operations:
  - id: cases-get
    method: GET
    path: /v2/cases/{type}/{case_id}
    pathParameters:
      - type
      - case_id
    recordTypeParameter: type
    recordIdParameter: case_id
    responseEnvelope: '{"case": {{record}}, "fetchedAt": "{{requestId}}"}'
problems:
  - code: cases.upstream
    status: 502
    title: the source could not be reached
    classes: [upstream, breaker.open, throttle.rejected, loop.maximum-iterations-reached]
  - code: cases.mapping
    status: 422
    title: the request or its mapping was refused
    classes: [validation, conversion.unmapped, aggregation.duplicate]
  - code: cases.exhausted
    status: 502
    title: the run exhausted a budget
    classes: [script, budget.exhausted]
  - code: cases.boundary
    status: 500
    title: the facade refused the call
    classes: [disclosure.violation, egress.refused, credential.rejected, outcome, facade]
problemEnvelope: '{"family": "{{problemCode}}"}'
EOF
} > "$control/profile.yaml"
{
  cat <<'EOF'
# yaml-language-server: $schema=https://id.registrystack.org/schemas/adapter/pack/pack.v1alpha1.schema.json
#
# The clean job-mode control: a pack with a source route, a pollEnrich
# read, and a digest-pinned postgres endpoint.
#
# Check with:
#   target/debug/adapterctl check products/adapter/fixtures/corpus/base-job/project.yaml
apiVersion: id.registrystack.org/formats/adapter/pack/v1alpha1
kind: AdapterPack
id: case-api-pack
version: "1"
testedVersions:
  - "1.0"
endpoints:
EOF
  facade_endpoint
  sed 's/maximumResponseBytes: 1048576/maximumResponseBytes: 16777216/' <<<"$(job_endpoint_file)"
  postgres_endpoint
  ledger_query_file
  facade_template
  cat <<'EOF'
sourceRoutes:
  - id: kobo-submissions
    scan: ongoing
    nextRecovery: key-deduplicated
    steps:
      - pollEnrich:
          uri: file:submissions
          timeoutMilliseconds: 5000
          decoder: csv
      - to:
          uri: postgres:ledger
          parameters:
            queryParameters:
              since:
                exchangeProperty: AdapterJobCursor
EOF
  capline
} > "$control/pack.yaml"
profile_digest=$(shasum -a 256 "$control/profile.yaml" | awk '{print "sha256:" $1}')
pack_digest=$(shasum -a 256 "$control/pack.yaml" | awk '{print "sha256:" $1}')
{
  cat <<EOF
# yaml-language-server: \$schema=https://id.registrystack.org/schemas/adapter/project/project.v1alpha1.schema.json
#
# The clean job-mode control: this workspace and the job artifact beside
# it must pass with zero findings.
#
# Check with:
#   target/debug/adapterctl check products/adapter/fixtures/corpus/base-job/project.yaml
apiVersion: id.registrystack.org/formats/adapter/project/v1alpha1
kind: AdapterProject
project:
  id: case-api-example
  version: "1"
profile:
  id: case-api
  version: "1"
  digest: $profile_digest
pack:
  id: case-api-pack
  version: "1"
  digest: $pack_digest
recordTypes:
  - name: case
    fields:
      - name: case_type
        type: string
        required: true
templatedRoutes:
  - routeTemplate: find-cases
    routeId: case-find
bindings:
  - id: case-get
    operation: cases-get
    recordType: case
    route: case-find
    maximumUpstreamCalls: 4
accessProfiles:
  - id: case-reader
    scopes:
      - cases.read
    operations:
      - cases-get
    recordTypes:
      - case
EOF
} > "$control/project.yaml"
pack_digest=$(shasum -a 256 "$control/pack.yaml" | awk '{print "sha256:" $1}')
{
  cat <<EOF
# yaml-language-server: \$schema=https://id.registrystack.org/schemas/adapter/job/job.v1alpha1.schema.json
#
# The clean job-mode control: a job over the pack's source route, bounded
# by its profile. The job compiler's check_job passes it with zero
# findings.
apiVersion: id.registrystack.org/formats/adapter/job/v1alpha1
kind: AdapterJob
job:
  id: kobo-daily
  version: "1"
source:
  pack:
    id: case-api-pack
    version: "1"
    digest: $pack_digest
  route: kobo-submissions
profile:
  pageDeadlineMilliseconds: 300000
  maximumResponseBytes: 16777216
  maximumPageItems: 500
  maximumPageBytes: 1048576
  read:
    maximumFileBytes: 1073741824
    maximumRowBytes: 1048576
    maximumFieldBytes: 65536
    maximumRowsPerPage: 500
EOF
} > "$control/job.yaml"

printf 'corpus members and the base-job control are written\n'
