# Identity-provider portability journey

This opt-in local journey obtains actual tokens from the pinned stock ThunderID issuer and a
digest-pinned Keycloak 26.7.3 container, then passes them through BReg's real
authenticator and HTTP router. It uses generated credentials and synthetic
identities only. Docker, Cargo, and `uv` are required.

```sh
cargo build --locked -p registry-bregctl -p registry-breg --bin bregctl --bin breg
uv run products/breg/scripts/test-issuer-portability.py
```

`CARGO_TARGET_DIR` is respected; `--bregctl` and `--breg` select already-built matching
binaries. The runner owns a unique disposable container,
dynamic loopback ports, and an owner-only temporary directory. It cleans up
services and credentials when finished. It does not contact an existing realm.

With an explicitly disposable PostgreSQL service, the opt-in native case also
proves that issuer replacement cannot transfer old Proposal ownership or receipt
authority to the same textual principal. A reconstructed runtime with the same
issuer can still recover its exact committed receipt:

```sh
uv run products/breg/scripts/test-issuer-portability.py --with-postgres
```

Set `BREG_TEST_DATABASE_URL` as for the other PostgreSQL tests. This case uses
the same native database with distinct issuer-bound mutation coordinators.
It does not migrate retired Request approvals across issuers.

The default registry project requires the `registry_principal` direct claim,
`registry:read` permission, `registry-administration` purpose, and `districts`
assignment. It authorizes GET only, for assigned districts. The proof covers:

- Stock ThunderID and Keycloak service-account client credentials.
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

The stock issuer receives the exact resource, scopes, and authority from the retained development
client registration. Keycloak uses an optional
`registry:read` client scope and a BReg audience mapper. Both therefore issue
the same BReg permission and resource contract through different provisioning
mechanisms. No production authentication dependency on either issuer is added.

The default router test uses a recording backend; the opt-in PostgreSQL case
proves native Proposal issuer isolation and same-issuer receipt recovery.
Broader database enforcement, hosted login UX, revocation operations, and
production TLS are separate verification surfaces.
Issuer JWKS are fetched from each live provider and then passed to BReg's
existing static-key-source interface. This journey does not prove remote-JWKS
refresh or key rotation. Local HTTP is restricted to this disposable exercise.
The scripted login client preserves secure cookies for the exact loopback
issuer, matching browsers' treatment of trustworthy localhost origins.

Keycloak references: [container startup](https://www.keycloak.org/server/containers),
[realm import](https://www.keycloak.org/server/importExport), and
[26.7.3 release](https://www.keycloak.org/2026/08/keycloak-2673-released).
