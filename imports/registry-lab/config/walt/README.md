# walt.id wallet config (hosted holder wallet)

These files configure the self-hosted walt.id **holder** wallet deployed by
`compose.walt-hosted.yaml` so the citizen Notary can issue credentials into a
real third-party wallet. Only the wallet-api (holder side) is deployed; walt's
issuer-api / verifier-api / portal are not used because the Registry Notary is
the issuer.

## Provenance

The `*.conf` files are vendored from
`walt-id/waltid-identity` at `docker-compose/wallet-api/config/` (release
`0.20.2`). They are copied verbatim except for the three deltas below. The
config-loader service in the compose file clones this directory into a named
volume and mounts it at `/waltid-wallet-api/config` (Coolify does not seed
compose bind mounts from the repo; see the runbook). `Caddyfile` and this
`README.md` are excluded from that mount.

## Deltas from stock walt

1. **`registration-defaults.conf`** — `defaultKeyConfig.keyType` is `Ed25519`
   (stock: `secp256r1`). The citizen Notary OID4VCI contract only accepts holder
   proofs signed with `EdDSA` bound via `did:jwk`. Ed25519 + `did:jwk` is exactly
   that.
2. **`auth.conf`** — the login-session `encryptionKey` / `signKey` / `tokenKey`
   are read from the environment (`WALT_AUTH_*`) instead of walt's public sample
   values, and fail-closed if unset.
3. **`dev-mode.conf`** — `enableDidWebResolverHttps=true` (stock: `false`) so the
   wallet resolves the Notary's `did:web` issuer over HTTPS.

## Ingress

`Caddyfile` keeps only walt's demo-wallet site block: it serves the web wallet
on `:7101` and proxies `/wallet-api/*` to `wallet-api:7001` on the same origin.
Coolify routes `wallet.lab.registrystack.org` to this Caddy.
