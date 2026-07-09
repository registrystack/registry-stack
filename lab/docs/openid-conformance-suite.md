# OpenID conformance suite

The lab carries a repeatable wrapper for the OpenID Foundation conformance
suite so standards evidence can be produced without depending on hosted lab
state. The wrapper pins the upstream suite checkout to `release-v5.2.0`
(`dee9a25160e789f0f80517674693ef7989ab9fa1`) and overlays the upstream Compose
file with a digest-pinned MongoDB image.

## Plan mapping

The mapping lives in
[`config/openid-conformance/plan-map.json`](../config/openid-conformance/plan-map.json).

- `notary-oid4vci-issuer-metadata`: applicable initial slice for Registry
  Notary's citizen OID4VCI issuer. It runs the OIDF
  `oid4vci-1_0-issuer-test-plan` with only
  `oid4vci-1_0-issuer-metadata-test`.
- `notary-oid4vci-issuer-full`: mapped but blocked until the lab has a bridge
  from Notary credential offers into the suite's exposed
  `/credential_offer` callback.

Registry Relay's OIDC bearer-token validation is not mapped to an OIDF suite
plan because the suite does not publish a generic resource-server plan for a
Relay-style protected API. Keep using `just relay-zitadel` and
`just oidc-relay` for that surface.

## Running the suite

Prepare and start the suite. `prepare` clones or refreshes the pinned checkout
and uses the suite's Docker-based Maven builder to create
`target/fapi-test-suite.jar` when it is missing:

```bash
just openid-conformance-prepare
just openid-conformance-up
```

Start the citizen OID4VCI Notary with a credential issuer URL that the suite
container can reach and that exactly matches the issuer metadata, for example a
stable HTTPS tunnel or a Docker host name:

```bash
CITIZEN_OID4VCI_CREDENTIAL_ISSUER="https://your-tunnel.example" \
just citizen-oid4vci-code
```

Then run the metadata slice:

```bash
REGISTRY_LAB_OPENID_CONFORMANCE_ISSUER_URL="https://your-tunnel.example" \
just openid-conformance-run -- notary-oid4vci-issuer-metadata
```

The runner writes rendered config and exported suite artifacts under
`output/openid-conformance/`. Do not commit those files; they can contain local
debug artifacts.

Use `--dry-run` to inspect the exact suite command without starting a run:

```bash
REGISTRY_LAB_OPENID_CONFORMANCE_ISSUER_URL="https://your-tunnel.example" \
just openid-conformance-run -- notary-oid4vci-issuer-metadata --dry-run
```

Stop the suite when finished:

```bash
just openid-conformance-down
```

## Current status

The existing `just citizen-oid4vci-*` probe pulls the Notary credential offer
directly. The full OIDF issuer plan expects the issuer to send a credential
offer into a suite-owned callback URL exposed at run time. The lab needs a
small adapter or config mode for that callback before the full issuer plan can
run end to end. Until then, only the metadata slice is repeatable.

The initial metadata-slice run against
`https://citizen-notary.lab.registrystack.org` executed and exported results,
then failed on OID4VCI credential issuer metadata validation and authorization
server metadata discovery. See
[`openid-conformance-initial-report.md`](openid-conformance-initial-report.md)
for the recorded result.
