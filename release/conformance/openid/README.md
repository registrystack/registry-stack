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
`/oid4vci/offer/callback` in an owner-only file, then submit it:

```bash
chmod 600 /private/path/notary-offer.txt
release/scripts/openid-conformance-runner.py submit-offer \
  --offer-file /private/path/notary-offer.txt \
  --issuer-url https://issuer.example.test \
  --suite-offer-endpoint 'https://localhost.emobix.co.uk:8443/<module>/credential_offer' \
  --suite-ca-certificate /private/path/conformance-suite-ca.pem
```

The adapter accepts only an inline Notary offer with the pre-authorized-code
grant, sends it once to the pinned suite origin without proxies or redirects,
and prints no offer content. TLS uses normal hostname and certificate
validation. The optional CA file adds only an explicitly supplied local trust
anchor for the suite's self-signed development certificate. A fabricated offer
is not candidate evidence.

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
Review and redact an export before turning it into release evidence. A failed
or warned result must remain visible in the reviewed summary.

The current runner keeps raw exports private but does not yet generate the
candidate-bound allowlisted summary or review promotion required for release
evidence. Until that source-side gate and a real frozen-candidate exercise
exist, its output remains candidate-exercise material rather than a completed
conformance claim.

The first metadata-only run and its known failures are recorded in
[`initial-report.md`](initial-report.md). It is historical context only. It is
not evidence for the current candidate, any wallet, any verifier, or the full
issuer profile.

The Rust SD-JWT verifier is a caller-invoked library, not an OID4VP endpoint.
Its library and fixture tests therefore do not support an OID4VP verifier
conformance claim.
