# OpenID conformance suite

This directory owns Registry Stack's wrapper for the OpenID Foundation
conformance suite. It stays with the release surface so conformance work does
not depend on a mutable hosted environment or on the separately maintained
[Solmara Lab](https://github.com/registrystack/solmara-lab).

The wrapper pins the upstream suite checkout to `release-v5.2.0`
(`dee9a25160e789f0f80517674693ef7989ab9fa1`) and overlays the upstream Compose
files with digest-pinned MongoDB, Maven, Nginx, and Java images. The suite JAR
cache is bound to the checked-out commit, and the suite's Python helpers install
from the checked-in fully hashed lock only when its upstream requirements still
match the reviewed input. A different suite ref can be supplied for
investigation, but results from an override are not evidence for the checked-in
mapping until the image, Python, and JAR pins are reviewed with it.

## Evidence boundary

The checked-in runner, plan map, and non-secret configuration template make
the suite invocation repeatable. They are not external conformance evidence by
themselves:

- The supported Registry Notary topology must use a frozen release-candidate
  image pinned by digest and checked-in non-secret configuration.
- The owner-only `submit-offer` adapter can send the real issuer-initiated
  pre-authorized offer to the suite's `/credential_offer` callback without
  exposing it in process arguments or command output.
- The upstream full-plan shape currently selects DPoP. Registry Notary 1.0 does
  not support or claim DPoP, wallet attestation, PAR, EUDI, HAIP, an
  authorization-code wallet grant, or ES256 holder proof.
- Registry Relay uses the separate
  [candidate-neutral Relay and Zitadel smoke](../relay-oidc/README.md) with
  `auth.mode: oidc`. The OIDF suite has no generic resource-server plan for
  that surface.

Development and historical demo runs are not release evidence. A reviewed
result becomes evidence only when it records the candidate image digest, suite
commit, exact plan variants, configuration digest, start and completion times,
and unmodified result status without retaining secrets.

`promote-evidence` provides that source-side boundary for the metadata-only
slice. It authenticates the referenced published candidate through the same
signed image lock, release capsule, provenance, checksums, local tag target, and
manifest binding used by the other conformance tooling. Candidate fields are
derived, not supplied individually. The OIDF export cannot prove that the
tested endpoint ran that candidate image, so the summary marks that association
as operator-attested and pending review. The command creates a new, closed JSON
summary for separate maintainer review. It does not make the summary
certification evidence by itself.

## Plan mapping

[`plan-map.json`](plan-map.json) is the machine-readable mapping.

- `notary-oid4vci-issuer-metadata` is a candidate-only slice for Registry
  Notary's registry-backed OID4VCI issuer. It runs
  `oid4vci-1_0-issuer-test-plan` with only
  `oid4vci-1_0-issuer-metadata-test`.
- `notary-oid4vci-issuer-full` is mapped but blocked until the suite path
  matches the supported Registry Notary profile. The offer adapter closes only
  the callback transport gap; it does not add DPoP, attestation, batch,
  notification, or other unsupported product behavior.

The suite's `sender_constrain=dpop` selector is required by the upstream plan
shape. The metadata-only module does not exercise DPoP, and the selector must
not be reported as product support.

The map also records why Relay OIDC bearer validation and third-party OpenID
Providers are outside the available OIDF plan set. That exclusion is not a
substitute for exercising Relay's OIDC path. The release-owned Relay smoke is
directly runnable against a published image digest, but its output remains
unreviewed until a maintainer binds it to the release candidate.

## Prerequisites

- Python 3.11 or later
- Git
- Docker with Docker Compose
- A Registry Notary issuer whose image is pinned by digest and whose issuer URL
  is reachable from the conformance-suite container

## Run the candidate metadata slice

List the mapped scenarios, prepare the pinned suite, and start it:

```bash
release/scripts/openid-conformance-runner.py list
release/scripts/openid-conformance-runner.py prepare
release/scripts/openid-conformance-runner.py up
```

Start the frozen Registry Notary candidate topology separately. Its configured credential
issuer URL must exactly match its metadata and be reachable from the suite
container. Then run:

```bash
REGISTRY_OPENID_CONFORMANCE_ISSUER_URL="https://issuer.example.test" \
  release/scripts/openid-conformance-runner.py run \
  notary-oid4vci-issuer-metadata
```

Candidate-only scenarios are directly runnable. `--allow-blocked` is reserved
for deliberate investigation of scenarios whose status is explicitly blocked;
it does not turn their output into release evidence.

For an issuer-initiated suite module, store the exact
`openid-credential-offer` URI rendered after Notary completes its authenticated
`/oid4vci/offer/callback` in an owner-only file. After `up`, export the exact
self-signed certificate generated for the suite's Nginx service from
`/etc/ssl/certs/nginx-selfsigned.crt`, then submit the offer:

```bash
release/scripts/openid-conformance-runner.py export-suite-ca \
  --output target/openid-conformance/conformance-suite-ca.pem

chmod 600 /private/path/notary-offer.txt
release/scripts/openid-conformance-runner.py submit-offer \
  --offer-file /private/path/notary-offer.txt \
  --issuer-url https://issuer.example.test \
  --suite-offer-endpoint 'https://localhost.emobix.co.uk:8443/<module>/credential_offer' \
  --suite-ca-certificate target/openid-conformance/conformance-suite-ca.pem
```

The adapter accepts only an inline Notary offer with the pre-authorized-code
grant, sends it once to the pinned suite origin without proxies or redirects,
and prints no offer content. TLS uses normal hostname and certificate
validation. The checked-in certificate recipe covers
`localhost.emobix.co.uk`, `localhost`, `127.0.0.1`, and `::1`. The optional CA
file is read once without following symlinks and adds only that explicitly
captured local trust anchor. The export command refuses to overwrite an
existing output. A fabricated offer is not candidate evidence.

Set `REGISTRY_OPENID_CONFORMANCE_AUTHORIZATION_SERVER` when the authorization
server differs from the issuer. Set
`REGISTRY_OPENID_CONFORMANCE_CREDENTIAL_CONFIGURATION_ID` when the topology
does not use the default `person_is_alive_sd_jwt` identifier.

Use `--dry-run` to render configuration and inspect the exact suite command
without starting a test plan:

```bash
REGISTRY_OPENID_CONFORMANCE_ISSUER_URL="https://issuer.example.test" \
  release/scripts/openid-conformance-runner.py run \
  notary-oid4vci-issuer-metadata --dry-run
```

Stop the suite when finished:

```bash
release/scripts/openid-conformance-runner.py down
```

The checkout, Python environment, Maven cache, rendered configuration, and
exported suite artifacts live under `target/openid-conformance/`, which Git
ignores.

## Promote a result for review

Keep the raw plan export outside the repository and make it owner-only. Download
the candidate's `registryctl-<tag>-image-lock.json`, its `.sig` and `.pem`, the
release capsule and its `.sig` and `.pem`, release provenance, and
`SHA256SUMS` into one private directory. Fetch the immutable release tag and
install `cosign` and `slsa-verifier`.

While the same suite instance used for the run is still running, capture its
generated CA and `/jwks` signing-key response through the runner's authenticated
HTTPS path:

```bash
release/scripts/openid-conformance-runner.py export-suite-ca \
  --output /private/oidf/suite-ca.pem

release/scripts/openid-conformance-runner.py export-suite-jwks \
  --conformance-server https://localhost.emobix.co.uk:8443 \
  --suite-ca-certificate /private/oidf/suite-ca.pem \
  --output /private/oidf/suite-jwks.json
```

The JWKS command disables proxies and redirects, validates a closed RSA signing
key shape, and refuses to overwrite its owner-only output. Do not restart or
replace the suite after this capture. Run the metadata slice with an explicit
private output directory:

```bash
mkdir -m 700 /private/oidf/metadata-run

REGISTRY_OPENID_CONFORMANCE_ISSUER_URL="https://issuer.example.test" \
  release/scripts/openid-conformance-runner.py run \
  notary-oid4vci-issuer-metadata \
  --output-dir /private/oidf/metadata-run
```

The wrapper passes that directory to the pinned upstream runner as
`--export-dir`. The completed directory contains the rendered configuration
and exactly one plan-export ZIP for this one-module slice. There is no separate
UI download step. Keep the same suite instance running until the command
finishes, then identify the ZIP and make it owner-only:

```bash
find /private/oidf/metadata-run -maxdepth 1 -type f -name '*.zip' -print
chmod 600 /private/oidf/metadata-run/<plan-export>.zip

release/scripts/openid-conformance-runner.py promote-evidence \
  --suite-export /private/oidf/metadata-run/<plan-export>.zip \
  --suite-jwks /private/oidf/suite-jwks.json \
  --release-manifest release/manifests/registry-stack-<release-id>.yaml \
  --image-lock /private/release/registryctl-<tag>-image-lock.json \
  --output /private/review/openid-metadata-evidence.json
```

The command refuses to overwrite the output. It accepts only the single
`oid4vci-1_0-issuer-metadata-test` JSON export and its matching signature,
rejects unsafe or unexpected ZIP entries, and verifies the Base64URL
SHA256withRSA signature over the exact JSON bytes against exactly one captured
suite key. The filename run identifier must match `testInfo._id`,
`testInfo.testId`, and every considered log entry.

The authoritative module status must be `FINISHED`. Its `PASSED`, `FAILED`,
`WARNING`, `REVIEW`, `SKIPPED`, or `UNKNOWN` result is copied unchanged. The
archive does not contain a plan verdict or runner exit status. Completion time
comes from the matching terminal log event. Condition identifiers and messages
are not copied. The summary retains only aggregate informational, successful,
review, warning, and failure counts.

The summary records:

- the authenticated release tag target, manifest source ref, signed capsule,
  image-lock hashes, exact Registry Notary image digest, and the explicit
  operator-attested endpoint association;
- the pinned 40-character suite commit, release tag, signed export's matching
  reported version and origin, exact scenario, plan, module, variants, and the
  explicit operator-attested commit association;
- the canonical SHA-256 digest of the captured suite JWKS and successful
  exact-byte export signature verification;
- SHA-256 digests of the checked-in plan map and configuration template;
- a digest of the effective runtime configuration after replacing only
  `vci.static_tx_code` with the fixed `<redacted>` marker; and
- the suite start time, terminal-log completion time, terminal status,
  unmodified result, and condition outcome counts.

The transaction code is not copied or hashed because a digest of a
low-entropy code would be brute-forceable. The public summary includes no raw
export hash, plan or module instance id, free-form message, request, response,
token, proof, credential, civil identifier, or suite log. Its committed shape
is [`evidence-summary.schema.json`](evidence-summary.schema.json), which the
command validates before writing output. Review the candidate deployment
evidence, suite checkout and runtime, and summary separately before committing
it as release evidence.

When advancing the suite ref, compare its `scripts/requirements.txt` with
`python-requirements.in`. After review, regenerate the hashed lock with the
command recorded at the top of `python-requirements.txt`. Dependabot scans that
pip-compile lock weekly, while the runner keeps its direct input byte-bound to
the pinned suite. Review the four image tags and refresh their immutable digests
through the matching Dependabot Dockerfile and Docker Compose updates.
`prepare` reuses the suite JAR only while its recorded source ref, builder
override digest, and artifact digest still match.

## Sensitive result handling

Do not commit a raw result export. Full-flow output may include bearer tokens,
proof JWTs, issued credentials, transaction codes, or seeded civil identifiers.
The promotion command reads the private export only to validate the selected
module, terminal record, safe runtime-configuration shape, and condition
counts. It constructs the public summary
from an explicit allowlist and checks that sensitive raw values did not cross
that boundary. A failed, warned, skipped, review, or unknown result remains
visible and is never upgraded to a pass.

A promoted summary is still unreviewed candidate output until a maintainer
checks the authenticated candidate assets, operator-attested endpoint
association, and result. The full issuer scenario remains explicitly
unsupported because the upstream profile requires behavior outside Registry
Notary 1.0. The offer adapter is no longer a blocker; it closes only the
callback transport gap.

The first metadata-only run and its known failures are recorded in
[`initial-report.md`](initial-report.md). It is historical context only. It is
not evidence for the current candidate, any wallet, any verifier, or the full
issuer profile.

The Rust SD-JWT verifier is a caller-invoked library, not an OID4VP endpoint.
Its library and fixture tests therefore do not support an OID4VP verifier
conformance claim.
