# Deployment Hardening Runbook

This runbook is for teams moving Registry Notary from a demo into a shared test,
pilot, or production-like environment. It focuses on implemented operational
controls and deployment choices. Route names may still evolve while the REST API
design is being finalized.

## Baseline Assumptions

Registry Notary may handle personal-data lookups, credential issuance, holder
proofs, OIDC tokens, and audit evidence. Treat it as a security-sensitive
service even when the issued credentials are short lived.

The hardened posture is:

- TLS terminates before public traffic reaches Notary.
- Callers authenticate on every protected route.
- Source tokens, signing keys, Redis URLs, and audit secrets stay outside YAML.
- External source reads happen only after auth, scope, subject-binding, and
  policy checks pass.
- Replay and status data are shared when more than one process can serve the
  same traffic.
- Audit logs are redacted and retained outside the Notary host.

## Network Boundary

Put Registry Notary behind a platform ingress, reverse proxy, or service mesh
that provides TLS, request-size controls, access logs, and rate limits. The
server already applies conservative application checks, but the deployment
boundary should absorb internet-facing load and malformed traffic.

Recommended controls:

- Serve public traffic only over HTTPS.
- Set `evidence.api_base_url`, `credential_status.base_url`, and OID4VCI public
  URLs to the externally reachable HTTPS issuer origin.
- Keep `/metrics` and admin actions behind normal network controls and require
  `registry_notary:admin`.
- Use proxy limits for body size, header size, connection count, idle timeout,
  and request rate.
- Do not expose demo source services, sidecar worker endpoints, local Redis, or
  HSM management ports to the public network.

For source connections, leave these false outside demos unless the risk is
explicitly accepted:

```yaml
allow_insecure_localhost: false
allow_insecure_private_network: false
```

The private-network escape hatch is useful for Docker Compose or lab
topologies, but production source fetches should use HTTPS and a reviewed
network path.

## Authentication And Authorization

Choose one caller-auth mode per deployment:

- `api_key` for backend services and operator integrations.
- `oidc` for citizen self-attestation and wallet flows.

Do not mix static API keys with OIDC in the same config. OIDC mode rejects
static `api_keys` and `bearer_tokens`.

Hardening checklist:

- Hash static API keys and bearer tokens with `registry-notary hash-api-key`;
  never store raw caller secrets in YAML.
- Give each caller a distinct `id` and the smallest useful scope set.
- Reserve `registry_notary:admin` for operators, status mutation, metrics
  scraping, and reload-like actions.
- For OIDC, use HTTPS `jwks_uri`, explicit `audiences`, and a small
  `allowed_clients` list when your identity provider supports it.
- Map external scopes with `auth.oidc.scope_map` instead of accepting broad
  identity-provider scopes directly.
- Keep clock leeway small. Self-attestation requires
  `auth.oidc.leeway_seconds` to stay within the self-attestation clock-leeway
  ceiling.

## Secret Inventory

Every deployable environment should document where these are stored and how
they rotate:

| Secret | Why it matters | Rotation note |
| --- | --- | --- |
| Caller API key or bearer token | Authenticates backend callers | Rotate by adding a new hash, deploying callers, then removing the old hash |
| Source static token | Authorizes upstream registry reads | Coordinate with source owner and watch source-auth failures |
| Source OAuth client secret | Obtains upstream access tokens | Rotate at identity provider, then deployment secret store |
| Issuer signing key or HSM PIN | Signs credentials | Follow key-status rotation in `signing-key-provider.md` |
| Audit HMAC secret | Hashes identifiers in audit records | Keep stable for the retention window, rotate with an audit-correlation plan |
| Redis URL and credentials | Protects replay and status stores | Rotate with readiness monitoring |

Do not print full environment dumps in diagnostics or incident notes. `doctor`
and `explain-config` are designed to avoid secret output, but shell history,
process managers, and support tickets still need care.

## Replay Store

Replay protection applies to:

- Static-peer federation request JWT ids.
- OID4VCI nonces.
- Holder proof JWT ids.

Use `in_memory` only when one process handles all relevant traffic and losing
replay state on restart is acceptable:

```yaml
replay:
  storage: in_memory
```

Use Redis for active-active, rolling deploys that overlap traffic, public wallet
flows, or federation:

```yaml
replay:
  storage: redis
  redis:
    url_env: REGISTRY_NOTARY_REPLAY_REDIS_URL
    key_prefix: registry-notary
    connect_timeout_ms: 1000
    operation_timeout_ms: 500
```

Operational expectations:

- The service should fail readiness when Redis is unavailable.
- Redis keys are scoped and hashed, but the Redis database is still operational
  security material.
- Use a deployment-specific `key_prefix` when multiple environments share a
  Redis cluster.
- Alert on Redis connection failures and increased replay denials.

## Credential Status Store

If status is disabled, verifiers rely on credential expiry and issuer trust.
That is the default beta posture.

If status is enabled, prefer Redis outside lab deployments:

```yaml
credential_status:
  enabled: true
  base_url: https://notary.example.gov
  storage: redis
  retention_seconds: 86400
  redis:
    url_env: REGISTRY_NOTARY_STATUS_REDIS_URL
    key_prefix: registry-notary
```

Hardening expectations:

- `base_url` must be the public HTTPS issuer origin verifiers can reach.
- Keep retention at least as long as the longest credential validity plus
  verifier tolerance.
- Treat status mutation as an admin operation. Require `registry_notary:admin`.
- Monitor status-store readiness and status update failures.
- Keep status records free of subject ids, holder keys, claim values, source
  rows, and SD-JWT disclosures.

See [`credential-lifecycle-status.md`](credential-lifecycle-status.md) for
semantics.

## Audit

Audit is how operators explain what Notary did without logging raw personal
data. Configure a sink and stable HMAC secret:

```yaml
audit:
  sink: stdout
  hash_secret_env: REGISTRY_NOTARY_AUDIT_HASH_SECRET
```

Use one of these patterns:

| Sink | Use when | Requirement |
| --- | --- | --- |
| `stdout` | Container runtime or platform log agent owns collection | Ship logs off-host and retain them immutably enough for your assurance level |
| `file` or `jsonl` | A host process owns local JSONL files | Configure file permissions, rotation, backups, and external anchoring |
| `syslog` | Local syslog or journald pipeline is standard | Confirm socket path and downstream retention |

Audit records include `prev_hash` and `record_hash`. File sinks can resume from
the retained tail hash, but any local-only chain can still be rewritten by a
host-level attacker. For pilots that rely on tamper evidence, ship records
off-host or periodically anchor the tail hash in independently controlled
storage.

## Metrics

`/metrics` is intended for Prometheus scraping and uses low-cardinality labels.
It still requires an admin credential.

```yaml
scrape_configs:
  - job_name: registry-notary
    metrics_path: /metrics
    authorization:
      type: Bearer
      credentials_file: /run/secrets/registry-notary-metrics-token
    static_configs:
      - targets: ["registry-notary:4325"]
```

Do not add labels containing subject ids, principal ids, holder material,
tokens, request ids, source rows, SD-JWT disclosures, or raw errors.

Useful alerts:

- Readiness failures.
- Source read failures or elevated 5xx from source connectors.
- Auth denials above normal baseline.
- Replay denials above normal baseline.
- Credential issuance errors.
- Credential status store failures when status is enabled.

## Source Connections

Source registries are often the highest-risk integration point because Notary
uses them to make real eligibility or identity assertions.

Deployment checks:

- Use HTTPS source URLs unless this is a controlled local or private-network
  demo.
- Configure exactly one of `token_env` or `source_auth`.
- Prefer OAuth2 client credentials when the upstream supports it.
- Keep `max_in_flight` low enough that Notary cannot overload the source.
- Leave `retry_on_5xx: true` for idempotent read APIs. Disable it for
  synchronous sidecars whose worker executions must not repeat.
- Enable `bulk_mode` only after source contract tests prove the upstream
  response shape and cardinality.
- Keep `field_paths` and claim `fields` to the minimum data needed.

When using OpenFn sidecars, isolate worker execution, pin adaptor versions, and
avoid retrying non-idempotent jobs.

## Signing Keys

Use local JWK environment keys for development, tests, and simple mounted-secret
deployments. Use PKCS#11 where the deployment requires HSM-backed signing.

Operational rules:

- `status: active` keys may sign and publish.
- `status: publish_only` keys publish public material but cannot sign.
- `status: disabled` keys do neither.
- Keep `kid` stable for a key version and unique among published keys.
- Do not configure a private JWK for `publish_only`.
- For PKCS#11, keep `module_path` absolute and store the PIN through `pin_env`.

Use [`signing-key-provider.md`](signing-key-provider.md) for key generation,
PKCS#11 setup, and rotation examples.

## Self-Attestation And Wallet Flows

Public citizen and wallet flows need identity-provider, gateway, and Notary
controls to line up.

Checklist:

- Use `auth.mode: oidc`.
- Require exact subject binding from a reviewed token claim.
- Keep `allowed_claims`, `allowed_purposes`, `allowed_formats`,
  `allowed_disclosures`, and `credential_profiles` narrow.
- Keep `allowed_wallet_origins` to exact HTTPS origins. No wildcards.
- Keep `allowed_operations.batch_evaluate: false`.
- Configure `token_policy` ceilings for auth age, access-token lifetime,
  evaluation age, credential validity, and clock leeway.
- Use gateway or identity-provider rate limits in addition to Notary's
  in-process rate limits.
- Use Redis replay storage when multiple processes can serve OID4VCI traffic.
- Enable OID4VCI nonces for wallets that support them.

See [`oid4vci-wallet-interop.md`](oid4vci-wallet-interop.md) for wallet-facing
behavior.

## Readiness And Rollout

Before first shared deployment:

```sh
registry-notary explain-config --config registry-notary.yaml
registry-notary doctor --config registry-notary.yaml
registry-notary doctor --config registry-notary.yaml --live --subject-id <test-subject>
```

During rollout:

- Deploy with one claim and one source first.
- Confirm `/ready` passes after startup.
- Confirm Prometheus can scrape `/metrics` with an admin credential.
- Run one controlled evaluation and, if enabled, one controlled credential
  issuance.
- Confirm audit records arrive in the off-host sink.
- Confirm source owners see expected low-volume requests.
- Confirm Redis readiness for replay and status stores.

Rollback plan:

- Keep previous config and secrets available until the new deployment has passed
  live checks.
- If signing keys changed, keep old public keys published until old credentials
  have expired and verifier caches have refreshed.
- If credential status was enabled, do not disable it until issued credentials
  that reference status URLs have expired or verifiers have been told to stop
  expecting live status.

## Incident Notes

For an auth or token incident:

- Revoke or rotate the affected caller credential or OIDC client.
- Keep audit HMAC secret stable so investigators can correlate records.
- Search audit by hashed principal, caller id, claim id, credential profile,
  source id, and outcome, not by raw personal data.

For a signing-key incident:

- Mark the compromised key `disabled`.
- Promote or create a new `active` key.
- Keep unaffected old keys `publish_only` when verifiers still need their public
  keys.
- Decide whether status-enabled credentials need suspension or revocation.

For a source-data incident:

- Disable affected claims or remove the source connection.
- Rotate source credentials if they may have leaked.
- Reissue credentials only after source owners confirm data quality.
