# OpenID conformance initial report

Date: 2026-07-09

Issue: [#205](https://github.com/registrystack/registry-stack/issues/205)

## Evidence boundary

This report preserves the first Registry Stack mapping and execution against
the OpenID Foundation conformance suite. The run targeted the mutable hosted
lab that existed at the time. It records useful initial failures, but it does
not satisfy issue #205's requirement for a topology built from pinned release
images and checked-in configuration.

- Suite: `https://gitlab.com/openid/conformance-suite.git`
- Pinned suite ref: `dee9a25160e789f0f80517674693ef7989ab9fa1`
  (`release-v5.2.0`)
- Initial scenario: `notary-oid4vci-issuer-metadata`
- OIDF plan: `oid4vci-1_0-issuer-test-plan`
- OIDF module: `oid4vci-1_0-issuer-metadata-test`

## Result

Status: executed, with initial conformance failures recorded.

The historical runner invocation used the retired lab wrapper and its
environment name:

```bash
REGISTRY_LAB_OPENID_CONFORMANCE_ISSUER_URL="https://citizen-notary.lab.registrystack.org" \
  just openid-conformance-run -- notary-oid4vci-issuer-metadata \
  --suite-dir /tmp/openid-conformance-suite-205 \
  --no-prepare
```

Result summary:

- Suite plan id: `NalPrjqHehUMZ`
- Suite module id: `TkIp0Z5WO6ywlpo`
- Conditions: 21 successes, 2 failures, 1 warning
- Runner exit status: nonzero because the suite reported unexpected failures
  and an unexpected warning

Failure details:

- `VCICredentialIssuerMetadataValidation` failed against
  `OID4VCI-1FINAL-12.2.3`: the suite schema requires `uri` in the credential
  display `logo` and `background_image` objects, while the hosted metadata used
  `url` in those nested objects.
- `VCIFetchOAuthorizationServerMetadata` failed against
  `OID4VCI-1FINAL-12.2.3` and `RFC8414-3.1`: the suite derived an OAuth
  authorization-server metadata URL from the issuer's
  `authorization_servers` value and received `404 Not Found`.

Warning details:

- `CheckForUnexpectedParametersInCredentialIssuerMetadata` warned on metadata
  members that the pinned suite did not accept for this schema, including
  `token_endpoint`, `scope`, `proof_types_supported`, `display`,
  `cryptographic_binding_methods_supported`, and nested `url` and `alt_text`
  display fields.

The raw suite export is not committed because future full-flow runs may contain
bearer tokens, proof JWTs, issued credentials, transaction codes, or seeded
civil identifiers.

## Current reproduction path

The release-owned runner, mapping, configuration template, and pinned Compose
override are documented in [`README.md`](README.md). A current metadata run
uses `REGISTRY_OPENID_CONFORMANCE_ISSUER_URL` and writes ignored artifacts under
`target/openid-conformance/`.

The next reviewed run must use a pinned release topology. The full OIDF issuer
plan also remains blocked by a flow mismatch: the OIDF issuer tests wait for an
issuer-initiated credential offer callback into the suite, while the available
Registry Notary smoke flow pulls the offer endpoint directly.
