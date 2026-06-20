# Deployment Hardening Runbook

> **Page type:** Runbook · **Product:** Registry Notary · **Layer:** operations · **Audience:** operator

This runbook is for teams moving Registry Notary from a demo into a shared test,
pilot, or production-like environment. It focuses on implemented operational
controls and deployment choices.

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
- Use `server.admin_listener.mode: dedicated` for governed or production
  deployments. In dedicated mode `/metrics` and `/admin/v1/*` are served on the
  admin listener, not the public listener. `/metrics` and admin write actions
  still require `registry_notary:admin`; `/admin/v1/posture` requires the
  dedicated read-only `registry_notary:ops_read` scope.
- Use `server.admin_listener.mode: shared_with_public` only for simple local
  deployments without `config_trust`, and keep it behind local network controls.
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
- Reserve `registry_notary:admin` for operators, status mutation, and governed
  apply actions. Use `registry_notary:metrics_read` for Prometheus scraping and
  `registry_notary:ops_read` for posture and admin capability discovery.
- For OIDC, use HTTPS `jwks_url`, explicit `audiences`, and a small
  `allowed_clients` list when your identity provider supports it.
- Map external scopes with `auth.oidc.scope_map` instead of accepting broad
  identity-provider scopes directly.
- Keep clock leeway small. Self-attestation requires
  `auth.oidc.leeway` to stay within the self-attestation clock-leeway
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

For `replay` config options (`in_memory` vs. `redis`, URL env, key prefix,
and timeout fields), see the
[Replay Store section of the configuration reference](operator-config-reference.md#replay-store).

Operational gates:

- In-memory replay makes `/ready` return HTTP 503 with `status: degraded`.
- Under a declared deployment profile, in-memory replay combined with a
  high-risk mode (federation, OID4VCI pre-authorized code, holder proof,
  wallet-facing traffic, or declared multi-instance) is gated by
  `notary.replay.in_memory_high_risk`. See
  [Deployment Profile and Gates](operator-config-reference.md#deployment-profile-and-gates).
- The service fails readiness when Redis is unavailable.
- Redis keys are scoped and hashed, but the Redis database is still operational
  security material.
- Use a deployment-specific `key_prefix` when multiple environments share a
  Redis cluster.
- Alert on Redis connection failures and increased replay denials.

## Credential Status Store

If status is disabled, verifiers rely on credential expiry and issuer trust.
That is the default posture.

If status is enabled, prefer Redis outside lab deployments. For the full
`credential_status` config block (storage options, `base_url`, `retention_seconds`,
and Redis fields), see the
[Credential Status section of the configuration reference](operator-config-reference.md#credential-status).

Operational gates:

- `base_url` must be the public HTTPS issuer origin verifiers can reach.
- Keep retention at least as long as the longest credential validity plus
  verifier tolerance.
- Treat status mutation as an admin operation. Require `registry_notary:admin`.
- Monitor status-store readiness and status update failures.
- Keep status records free of subject ids, holder keys, claim values, source
  rows, and SD-JWT disclosures.

See [`credential-lifecycle-status.md`](credential-lifecycle-status.md) for
status semantics, the privacy boundary, and the rollout checklist.

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
It requires a dedicated `registry_notary:metrics_read` credential.

```yaml
scrape_configs:
  - job_name: registry-notary
    metrics_path: /metrics
    authorization:
      type: Bearer
      credentials_file: /run/secrets/registry-notary-metrics-token
    static_configs:
      - targets: ["registry-notary:8081"]
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

When using source adapter sidecars, keep target credentials in the sidecar,
configure target rate and concurrency limits, and avoid retrying
non-idempotent adapter execution. For OpenFn sources, isolate worker execution
and pin adaptor versions. The sidecar must be reachable only from Notary over
localhost or a private pod network. Do not expose it publicly, put it behind an
internet-facing ingress, or allow callers to invoke adapter execution directly.

For deployments with OpenFn sources, **network-layer egress controls on the
sidecar pod are required**. The Node.js OpenFn engine path is not covered by
the in-process SSRF defenses that protect the `http_json`, `http_flow`, and
`fhir` paths. Apply a Kubernetes NetworkPolicy (with an enforcing CNI such as
Calico or Cilium) or an enforced allow-listing egress proxy to block the cloud
metadata IP (`169.254.169.254`, `fd00:ec2::254`) and RFC 1918 ranges from the
worker pod. Do not rely on proxy environment variables alone for the OpenFn
worker path; the proxy must be enforced at the network layer. See
[`openfn-sidecar-egress-hardening.md`](openfn-sidecar-egress-hardening.md)
for a ready-to-apply policy and verification checklist.

Runbook gates for source adapter sidecar source connections:

- Set `retry_on_5xx: false`. Notary does not retry sidecar adapter execution
  failures.
- In governed deployments, set `expected_sidecar` on the source connection to
  fail closed on runtime identity or config-hash mismatch.

For full sidecar config fields and examples, see the
[Source Adapter Sidecar Source Connections section of the configuration reference](operator-config-reference.md#source-adapter-sidecar-source-connections).

## Signing Keys

Use local JWK environment keys for development, tests, and simple mounted-secret
deployments. Use PKCS#11 where the deployment requires HSM-backed signing.

Operational gates:

- Before rollout, run `registry-notary build-info` and confirm
  `capabilities.signing_providers.pkcs11` is `true` when using PKCS#11.
- Before routing production traffic, run `registry-notary doctor --config <path>`
  with the same PKCS#11 module, token label, key lookup, public JWK, and PIN
  environment used by the service.

See [`signing-key-provider.md`](signing-key-provider.md) for key status values,
rotation procedure, PKCS#11 setup, and worked examples.

## Self-Attestation And Wallet Flows

Public citizen and wallet flows need identity-provider, gateway, and Notary
controls to line up. See [`self-attestation-operator-guide.md`](self-attestation-operator-guide.md)
for the full configuration reference, subject-binding rules, and rollout
checklist for self-attestation. See [`oid4vci-wallet-interop.md`](oid4vci-wallet-interop.md)
for wallet-facing behavior.

Deployment hardening checklist:

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

## Readiness And Rollout

Before first shared deployment:

```sh
registry-notary explain-config --config registry-notary.yaml
registry-notary doctor --config registry-notary.yaml
registry-notary doctor --config registry-notary.yaml --live --target-id <test-target>
```

During rollout:

- Deploy with one claim and one source first.
- Confirm `/ready` passes after startup.
- Confirm Prometheus can scrape `/metrics` with a `registry_notary:metrics_read`
  credential.
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

### Auth or Token Incident

**Symptom:** Unauthorized requests succeed, an API key or bearer token is
suspected compromised, or an OIDC client secret is known or believed leaked.
Auth denials may spike as the attacker probes, or may be absent if the
credential is valid and in active misuse.

**Steps:**

1. Identify the affected caller id or OIDC client by searching audit records
   using hashed principal, caller id, and outcome fields. Do not use raw
   personal data in your search.
2. Revoke or rotate the affected credential: remove the old hash from
   `auth.api_keys` or `auth.bearer_tokens` (for static keys), or rotate the
   OIDC client secret at the identity provider.
3. Deploy the updated config or rotate the secret in the deployment secret
   store, depending on how secrets are injected.
4. Keep the audit HMAC secret stable throughout. Rotating it breaks
   correlation of records issued before the rotation.
5. If the incident involves an OIDC client, confirm with the identity provider
   that the old client secret is invalidated and that no other clients share
   the compromised material.

**Verification:**

- Confirm `/ready` passes after the config change.
- Confirm that new requests using the revoked credential are denied (auth
  denial in metrics and audit).
- Confirm that legitimate callers using their current credentials still
  succeed.

---

### Signing-Key Incident

**Symptom:** A signing key private material is known or suspected leaked, a
PKCS#11 PIN is compromised, or an HSM slot is suspected tampered. Credentials
signed with the affected key may have been issued or could be issued by an
attacker with a copy of the key.

**Steps:**

1. Mark the compromised key `status: disabled` in config. A disabled key
   cannot sign and its public material is no longer published.
2. Deploy the updated config so the change takes effect.
3. Promote an existing key to `status: active`, or generate and configure a
   new active key. See [`signing-key-provider.md`](signing-key-provider.md)
   for key generation and PKCS#11 setup.
4. For keys that were `active` before the incident, set them to `publish_only`
   (not `disabled`) only if verifiers still hold credentials that reference
   their key id and need the public key to verify signatures on already-issued
   material. Set `publish_until_unix_seconds` to the end of that verification
   window, or once all such credentials have expired and verifier caches have
   refreshed, set them to `disabled`.
5. Decide whether status-enabled credentials signed by the compromised key
   need suspension or revocation. If so, use the status mutation endpoint
   (requires `registry_notary:admin`) to update each affected credential's
   status. Confirm that the status store reflects the changes.

**Verification:**

- Confirm `/ready` passes after the config change.
- Confirm new credential issuances use the new active key (check `kid` in a
  test-issued credential).
- Confirm the disabled key's public material is no longer served.
- If credentials were suspended or revoked, confirm their status URLs return
  the updated state.

---

### Source-Data Incident

**Symptom:** A source registry returns incorrect, stale, or corrupted data;
a source credential (token or OAuth client secret) is suspected leaked; or
source data quality is called into question by a downstream report or audit.
Credentials already issued may contain incorrect claims.

**Steps:**

1. Disable the affected claims or remove the source connection from config to
   stop new issuances that rely on the suspect data.
2. Deploy the updated config so no further reads go to the affected source.
3. If source credentials may have leaked, rotate them: remove the old secret
   from the deployment secret store and update `token_env` or the OAuth client
   secret at the source identity provider. Coordinate the rotation with the
   source owner.
4. Work with the source owner to confirm data quality is restored and that
   the root cause is understood.
5. Assess which credentials issued during the affected window contain incorrect
   claims. If status is enabled, suspend or revoke those credentials via the
   status mutation endpoint (requires `registry_notary:admin`). If status is
   not enabled, notify relying parties and coordinate re-issuance.
6. Re-enable the source connection or claims only after the source owner
   confirms data quality.
7. Reissue credentials for affected subjects after re-enabling.

**Verification:**

- Confirm `/ready` passes after config changes.
- Confirm source reads succeed with the new credentials (check source read
  metrics and audit records for the source id).
- Confirm no evaluation or issuance errors related to the affected source.
- If credentials were suspended, confirm their status URLs return the updated
  state before communicating recovery to relying parties.
