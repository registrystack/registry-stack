# OpenID conformance suite

This directory owns Registry Stack's wrapper for the OpenID Foundation
conformance suite. It stays with the release surface so conformance work does
not depend on a mutable hosted environment or on the separately maintained
[Solmara Lab](https://github.com/registrystack/solmara-lab).

The wrapper pins the upstream suite checkout to `release-v5.2.0`
(`dee9a25160e789f0f80517674693ef7989ab9fa1`) and overlays the upstream Compose
file with a digest-pinned MongoDB image. A different suite ref can be supplied
for investigation, but results from an override are not evidence for the
checked-in mapping.

## Evidence boundary

The checked-in runner, plan map, and non-secret configuration template make
the suite invocation repeatable. They do not yet complete issue #205:

- The supported Registry Notary topology must use published release images
  pinned by digest and checked-in non-secret configuration.
- The full OID4VCI issuer plan needs an adapter that sends the issuer-initiated
  credential offer to the suite's `/credential_offer` callback.
- Registry Relay needs a separate pinned-topology smoke with `auth.mode: oidc`.
  The OIDF suite has no generic resource-server plan for that surface.

Solmara Lab may provide the running topology during development, but release
gating and reproduction of the suite invocation must not require it.

## Plan mapping

[`plan-map.json`](plan-map.json) is the machine-readable mapping.

- `notary-oid4vci-issuer-metadata` is the applicable initial slice for Registry
  Notary's citizen OID4VCI issuer. It runs
  `oid4vci-1_0-issuer-test-plan` with only
  `oid4vci-1_0-issuer-metadata-test`.
- `notary-oid4vci-issuer-full` is mapped but blocked until a topology adapter
  bridges a Notary credential offer into the suite callback.

The map also records why Relay OIDC bearer validation and third-party OpenID
Providers are outside the available OIDF plan set. That exclusion is not a
substitute for exercising Relay's OIDC path.

## Prerequisites

- Python 3.11 or later
- Git
- Docker with Docker Compose
- A Registry Notary issuer whose image is pinned by digest and whose issuer URL
  is reachable from the conformance-suite container

## Run the metadata slice

List the mapped scenarios, prepare the pinned suite, and start it:

```bash
release/scripts/openid-conformance-runner.py list
release/scripts/openid-conformance-runner.py prepare
release/scripts/openid-conformance-runner.py up
```

Start the pinned Registry Notary topology separately. Its configured credential
issuer URL must exactly match its metadata and be reachable from the suite
container. Then run:

```bash
REGISTRY_OPENID_CONFORMANCE_ISSUER_URL="https://issuer.example.test" \
  release/scripts/openid-conformance-runner.py run \
  notary-oid4vci-issuer-metadata
```

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

## Sensitive result handling

Do not commit a raw result export. Full-flow output may include bearer tokens,
proof JWTs, issued credentials, transaction codes, or seeded civil identifiers.
Review and redact an export before turning it into release evidence. A failed
or warned result must remain visible in the reviewed summary.

The first metadata-only run and its known failures are recorded in
[`initial-report.md`](initial-report.md). It is historical evidence from the
retired hosted lab, not proof of the still-open pinned release topology.
