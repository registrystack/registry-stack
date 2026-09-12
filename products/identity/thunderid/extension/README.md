# Native citizen federation

Institutional RFC 8693 exchange uses the pinned upstream issuer. Citizen delegation additionally requires the source patch in this directory and the rebuilt native Gate frontend. The patch adds outbound private-key JWT authentication, S256 PKCE, essential claims, strict signed OIDC response validation, and consent-bound citizen authorization codes inside ThunderID. It does not add another issuer service or a custom delegation grant.

## Build and verify

Run from the Registry Stack root with Docker, Go and the upstream-pinned pnpm version available:

```sh
python3 products/identity/thunderid/extension/build.py --output /absolute/fresh/build --image
```

Use `--archive /path/to/cached.tar.gz` to reuse a download. The builder verifies the archive against `crates/registry-thunderid-tooling/thunderid-version.json`, applies a captured patch, builds the native server and Gate, and creates a new local candidate image. It refuses existing output directories. `build.json` records the upstream commit, archive and patch checksums, binary and Gate asset checksums, frontend lockfile checksum, tool versions, base image digest and candidate image ID. No service is started. Use that immutable image ID in the owning session's `container::Session.image`.

The patch carries focused native Go tests with real local authorization, token, JWKS and signed UserInfo endpoints. In the prepared `upstream/backend` directory, run:

```sh
go test -mod=readonly ./internal/authn/oauth ./internal/authn/oidc ./internal/authn/consent ./internal/connection ./internal/idp ./internal/flow/executor ./internal/oauth/oauth2/granthandlers ./internal/oauth/oauth2/authz ./internal/oauth/oauth2/token ./pkg/thunderidengine/providers
```

In `upstream/frontend/packages/design`, run:

```sh
pnpm exec vitest run src/components/flow/adapters/__tests__/ConsentAdapter.test.tsx src/components/flow/__tests__/FlowComponentRenderer.test.tsx
```

Run the institutional regression against the candidate using `products/identity/scripts/test-contextual-exchange.py --image sha256:LOCAL_IMAGE_ID`. Its candidate mode also bootstraps the native citizen connection, user type, flow and code-only client. This establishes configuration acceptance and institutional interoperability; a deployment must separately verify its real identity provider and destination journey.

## Governed configuration

`registry_thunderid_tooling::citizen::render` appends a closed native citizen registration to a fresh session after `render::render` and before `local::start`. Supply the provider's exact issuer, authorization/token/UserInfo/JWKS endpoints, registered outbound client ID and redirect URI, expected signed response algorithms, and the agent's own public JWKS and exact callback URI. The helper emits a separate human type and a federation, JIT provisioning, consent and assertion flow. Provider identity is bound to the verified issuer and pairwise `sub`; account linking by mutable claims is disabled on this path.

The provider must supply a governed opaque `person_reference` in signed UserInfo. It remains distinct from OIDC `sub`. Only the consent-approved verified value can become `registry_subject_person_reference`. Optional `require_active_identity` emits the governed constant `registry_identity_status=active`. It never reads this constant from citizen input. Scope-to-field descriptions, purpose and the exact destination resource come from the owning product's authorization policy. Copy a development resource from that session's client export; do not derive it from a project name.

The native policy shape is:

```yaml
loginConsent:
  validityPeriod: 300
  delegation:
    purpose: citizen-self-service
    resource: urn:destination:exact-registration
    scopeFields:
      registry:population:self-service: [person-reference, status]
    subjectAttribute: person_reference
    identityStatus: active
```

Citizen agents admit only `authorization_code`, exact redirects, PKCE and at most 300-second access tokens. Every authorization requires fresh consent. Tokens carry the citizen subject, authenticated OAuth `client_id`, native registered agent entity ID in `act.sub`, `registry_actor_kind=agent`, and governed purpose. They cannot carry institutional grant attributes. Code redemption checks the exact current consent authorization record and unchanged resource, scopes, field/purpose policy and duration. Missing cache, unavailable consent, withdrawal, expiry or replacement approval denies old codes.

## Citizen control and provider keys

The agent's normal authorization link opens the native Gate flow. After authenticating with the configured identity provider, the citizen sees the agent, destination, purpose, requested fields and duration. **Decline this request** denies this issuance and preserves earlier consent. **Withdraw this agent’s access** withdraws that authenticated citizen's current consent for this agent and invalidates outstanding codes. Reapproving later does not revive old codes. Already issued access tokens may remain usable until their expiry, at most five minutes. Withdrawal is available in the native human flow without requiring the agent to return a bearer token.

Outbound `private_key_jwt` reuses the injected issuer signing service, with RS256, the registered signing `kid`, exact token-endpoint audience, fresh `jti`, and 60-second assertions. Register its public key with the identity provider. Rotating that issuer key also requires updating the provider's outbound client registration. Endpoint origins must match the exact configured issuer; redirects are refused. HTTPS is required except explicitly authored local HTTP fixtures. ID Tokens and UserInfo must be signed JWS with the configured algorithms, matching issuer, audience, key and subject; ID Token nonce and both authorization transactions' state/PKCE bindings are verified. Encrypted UserInfo is not enabled by this profile.
