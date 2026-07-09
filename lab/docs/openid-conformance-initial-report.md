# OpenID conformance initial report

Date: 2026-07-09

Issue: `#205`

## Scope

This report records the first Registry Lab mapping for the OpenID Foundation
conformance suite.

- Suite: `https://gitlab.com/openid/conformance-suite.git`
- Pinned suite ref: `dee9a25160e789f0f80517674693ef7989ab9fa1`
  (`release-v5.2.0`)
- Initial scenario: `notary-oid4vci-issuer-metadata`
- OIDF plan: `oid4vci-1_0-issuer-test-plan`
- OIDF module: `oid4vci-1_0-issuer-metadata-test`

## Result

Status: executed, with initial conformance failures recorded.

Run command:

```bash
REGISTRY_LAB_OPENID_CONFORMANCE_ISSUER_URL="https://citizen-notary.lab.registrystack.org" \
just openid-conformance-run -- notary-oid4vci-issuer-metadata \
  --suite-dir /tmp/openid-conformance-suite-205 \
  --no-prepare
```

Result summary:

- Suite plan id: `NalPrjqHehUMZ`
- Suite module id: `TkIp0Z5WO6ywlpo`
- Local output directory:
  `output/openid-conformance/notary-oid4vci-issuer-metadata-20260709T084150Z/`
- Conditions: 21 successes, 2 failures, 1 warning
- Runner exit status: nonzero because the suite reported unexpected failures
  and an unexpected warning

Failure details:

- `VCICredentialIssuerMetadataValidation` failed against
  `OID4VCI-1FINAL-12.2.3`: the suite schema requires `uri` in the
  credential display `logo` and `background_image` objects, but the hosted lab
  metadata uses `url` in those nested objects.
- `VCIFetchOAuthorizationServerMetadata` failed against
  `OID4VCI-1FINAL-12.2.3` and `RFC8414-3.1`: the suite derived
  `https://esignet.lab.registrystack.org/.well-known/oauth-authorization-server/v1/esignet`
  from the issuer's `authorization_servers` value and received `404 Not Found`.

Warning details:

- `CheckForUnexpectedParametersInCredentialIssuerMetadata` warned on metadata
  members that the pinned suite does not accept for this schema, including
  `token_endpoint`, `scope`, `proof_types_supported`, `display`,
  `cryptographic_binding_methods_supported`, and nested `url`/`alt_text`
  display fields.

The exported suite ZIP is not committed because future full-flow runs may
contain bearer tokens, proof JWTs, issued credentials, or seeded civil
identifiers.

## Evidence Added

- Repeatable runner: `scripts/openid-conformance-runner.py`
- Plan map: `config/openid-conformance/plan-map.json`
- Config template: `config/openid-conformance/registry-notary-oid4vci-issuer.template.json`
- Pinned Mongo override: `config/openid-conformance/docker-compose.override.yaml`
- Operator guide: `docs/openid-conformance-suite.md`

## Next Run Criteria

The metadata slice is runnable. To reproduce it against a locally started
Notary, start Notary with a suite-reachable issuer URL:

```bash
CITIZEN_OID4VCI_CREDENTIAL_ISSUER="https://your-tunnel.example" \
just citizen-oid4vci-code

REGISTRY_LAB_OPENID_CONFORMANCE_ISSUER_URL="https://your-tunnel.example" \
just openid-conformance-run -- notary-oid4vci-issuer-metadata
```

Do not publish `output/openid-conformance/` artifacts without redacting tokens,
proof JWTs, issued credentials, and seeded civil identifiers.

The full OIDF issuer plan remains blocked by a flow mismatch: the OIDF issuer
tests wait for an issuer-initiated credential offer callback into the suite,
while the current lab probe pulls the Notary offer endpoint directly.
