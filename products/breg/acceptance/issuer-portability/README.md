# Identity-provider portability journey

This opt-in local journey obtains actual tokens from Registry Mint and a
digest-pinned Keycloak 26.7.3 container, then passes them through BReg's real
authenticator and HTTP router. It uses generated credentials and synthetic
identities only. Docker, Cargo, and `uv` are required.

```sh
cargo build --locked -p registry-mint --bin mint
uv run products/breg/scripts/test-issuer-portability.py
```

`CARGO_TARGET_DIR` is respected; `--mint /absolute/path/to/mint` selects an
already-built matching binary. The runner owns a unique disposable container,
dynamic loopback ports, and an owner-only temporary directory. It cleans up
services and credentials when finished. It does not contact an existing realm.

To also continue a persisted approval across the issuer change, set
`BREG_TEST_DATABASE_URL` to an explicitly disposable PostgreSQL database, as
for the product's PostgreSQL tests, and opt in:

```sh
uv run products/breg/scripts/test-issuer-portability.py --with-postgres
```

This additional case records the first approval using a real Mint token,
reconstructs BReg with Keycloak trust against the same database, refuses the
old Mint token and the same service principal's attempt to approve another
stage, then accepts the independent human's Keycloak token. The runner never
creates or resets the supplied database. Builds finish before token issuance.
It also continues the original principal's pagination cursor and replays a
committed approval receipt after cutover. Another principal cannot reuse the cursor.

The default registry project requires the `registry_principal` direct claim,
`registry.read` permission, `registry-administration` purpose, and `districts`
assignment. It authorizes GET only, for assigned districts. The proof covers:

- Mint client credentials and Keycloak service-account client credentials.
- Keycloak's interactive authorization endpoint, real login form and session,
  authorization-code redirect, state validation, and PKCE code exchange.
  Direct password grants are disabled.
- Explicit stable principal, purpose and district extraction from signed tokens.
  The service principal remains identical across issuers. The human has a
  separate institutional principal, even with the same task permissions.
- Requests reaching the recording backend with the expected district boundary.
- Missing scope and ungranted operation refusal before record I/O.
- New issuer acceptance after explicit trust replacement, old issuer refusal,
  and wrong-resource refusal.

Mint issues its registered scopes and configured audience. It does not offer
request-time scope downscoping or resource selection. Keycloak uses an optional
`registry.read` client scope and a BReg audience mapper. Both therefore issue
the same BReg permission and resource contract through different provisioning
mechanisms. No production authentication dependency on either issuer is added.

The default router test uses a recording backend. The optional PostgreSQL
case adds persisted approval continuity. Broader database enforcement, hosted
login UX, revocation operations, and production TLS are separate verification
surfaces. The approval fixture also consumes the same `tenant_claim` assignment
from both issuers.
Issuer JWKS are fetched from each live provider and then passed to BReg's
existing static-key-source interface. This journey does not prove remote-JWKS
refresh or key rotation. Local HTTP is restricted to this disposable exercise.
The scripted login client preserves secure cookies for the exact loopback
issuer, matching browsers' treatment of trustworthy localhost origins.

Keycloak references: [container startup](https://www.keycloak.org/server/containers),
[realm import](https://www.keycloak.org/server/importExport), and
[26.7.3 release](https://www.keycloak.org/2026/08/keycloak-2673-released).
