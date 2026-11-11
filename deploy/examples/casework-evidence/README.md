# Casework and Evidence qualification fixtures

These fixtures support an isolated, private qualification of the Registry Stack
Casework and Evidence Helm modules. They are not a deployment stack and are not
production identity, source, or signing services.

## Private HTTPS fixture

`qualification_server.py` serves:

- one fixed OIDC JWKS document at `/.well-known/jwks.json`;
- one health response at `/healthz`;
- the bounded synthetic records used by the released Evidence standalone
  example.

The server requires TLS and a static source token. It disables access logging
because source paths can contain selectors. Keep the issuer private key outside
Kubernetes and issue only short-lived synthetic tokens for qualification.

Casework has two independently governed issuer bindings. The runtime OIDC issuer
authenticates access tokens, while each `trustedProducers` entry in the immutable
package authorizes review submissions. A live create test therefore requires a
fresh reviewed package whose trusted producer issuer and subject exactly match
the synthetic HTTPS issuer and token subject. Changing only the runtime OIDC
configuration is expected to leave review creation denied.

Evidence production profiles reject private source destinations unless the
runtime connection explicitly lists the exact private service address or narrow
network in `allowedPrivateCidrs`. Do not admit a whole cluster or node network
when one service address is sufficient.

## Development Transit proxy

`qualification_transit_proxy.py` is a workload-local, Unix-socket proxy for one
synthetic Vault Transit key named `evidence-signing`. It forwards only:

- `GET /v1/transit/keys/evidence-signing`;
- `POST /v1/transit/sign/evidence-signing/sha2-256`.

The scoped synthetic Vault policy must match those exact upstream paths:

```hcl
path "transit/keys/evidence-signing" {
  capabilities = ["read"]
}

path "transit/sign/evidence-signing/sha2-256" {
  capabilities = ["update"]
}
```

The proxy token belongs only in the proxy container. Evidence receives the
Unix socket. This fixture proves the v0.46 Transit protocol and sign-and-verify
startup check with a disposable synthetic key. Qualify key custody, unseal,
backup, rotation, and recovery with the institution's signer.

## Focused checks

Run the pure proxy contract test directly:

```sh
python3 deploy/examples/casework-evidence/tests/test_qualification_transit_proxy.py
```

The HTTPS fixture test binds an ephemeral loopback port:

```sh
python3 deploy/examples/casework-evidence/tests/test_qualification_server.py
```

Live acceptance should retain only synthetic artifacts and establish, at
minimum:

- Casework `plan`, `apply`, and post-apply `plan` under separate runtime and
  migration database roles over TLS;
- Casework `/health` and `/ready`, authorized review creation, wrong-scope
  denial, authenticated readback, and owner-only persistent audit readback after
  a Pod restart;
- Evidence authority activation, history, and post-activation check;
- Evidence `/health` and `/ready`, authorized assertion issuance, authority
  denial, signature verification against the governed public key, and
  owner-only persistent audit readback after a Pod restart.

Render and create operation Jobs explicitly. The chart does not run these
operations as Helm hooks. Render success alone is not a live composition,
database restore, or signer-custody proof.
