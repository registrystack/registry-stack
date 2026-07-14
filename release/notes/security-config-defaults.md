# Security-Relevant Configuration Defaults Inventory

> **Status: Historical beta-11 inventory.** The paths and example counts below
> describe the pre-convergence v0.9.0 tree. Direct Notary source connectors,
> source-adapter sidecars, and their Lab and demo configurations were removed
> before 1.0. Do not use this snapshot as the current runtime or deployment
> inventory.

Issue: [#204](https://github.com/registrystack/registry-stack/issues/204)

This inventory records security-relevant code defaults and the values shipped in
example, demo, performance, and lab configs. It does not mark the secure-by-default
review complete; each row still needs a maintainer decision.

Example-value counts were gathered from tracked Relay and Notary runtime-service
YAML under `crates/registry-relay/config`, `crates/registry-relay/demo/config`,
`crates/registry-relay/demo/decentralized/config/relay`,
`crates/registry-relay/demo/decentralized/config/evidence`,
`crates/registry-relay/perf/config`, `lab/config/relay`,
`lab/config/coolify/relay`, `lab/config/notary`, `lab/config/coolify/notary`,
`products/notary/demo/config`, and `products/notary/perf/config`.
Metadata manifests, compose files, sidecar configs, and mapping-only YAML were
excluded.

| Product | Setting | Code default | Value in shipped examples | Security relevance | Decision still needed |
| --- | --- | --- | --- | --- | --- |
| Relay | `server.openapi_requires_auth` | `true` in `default_openapi_requires_auth()` ([config](../../crates/registry-relay/src/config/mod.rs)) | 12 Relay configs set `false`; 15 Relay configs omit the field and inherit `true`. Lab and decentralized demo Relay configs set `false`; product example configs omit it. | Unauthenticated `/openapi.json` includes the configured API surface. Docs say `false` is only for local testing or controlled tooling. | Decide whether lab/demo `false` remains acceptable because those configs declare `deployment.profile: local`, or whether copied examples need a safer value or stronger warning. |
| Notary | `server.openapi_requires_auth` | `true` in `default_openapi_requires_auth()` ([config](../../crates/registry-notary-core/src/config.rs)) | 18 Notary configs set `false`; 9 Notary configs omit the field and inherit `true`. Lab, Coolify, and decentralized evidence configs set `false`; product demo configs generally omit it. | Unauthenticated `/openapi.json` exposes the configured Notary API surface; capability discovery remains authenticated. Docs say `false` is only for local testing or controlled tooling. | Decide whether lab/demo `false` remains acceptable because those configs declare `deployment.profile: local`, or whether copied examples need a safer value or stronger warning. |
| Relay | `server.admin_bind` | Omitted by default (`Option<SocketAddr>` is `None`) ([config](../../crates/registry-relay/src/config/mod.rs)) | 2 Relay lab configs set `0.0.0.0:8081`; 25 Relay configs omit it. | Admin listener carries metrics, posture, capabilities, and reload. Ops docs require private exposure when configured. | Decide whether the two lab binds need replacement with loopback/private-only examples or an explicit lab-network rationale. |
| Notary | `server.admin_listener` | Disabled by default; default dedicated bind value is `127.0.0.1:8082` if the config block is enabled without overriding `bind` ([config](../../crates/registry-notary-core/src/config.rs)) | 15 Notary lab/Coolify configs set `mode: dedicated` with `bind: 0.0.0.0:8081`; 12 Notary configs omit the block and keep the admin surface disabled. | Admin listener exposes operational/admin routes; governed config requires `mode: dedicated` and rejects reusing the public bind. | Decide whether lab/Coolify `0.0.0.0:8081` needs replacement with a private-only bind or an explicit deployment-network rationale. |
| Relay | `config_trust` | Omitted by default; post-[#314](https://github.com/registrystack/registry-stack/issues/314) shape is `trust_anchor_path`, `bundle_path`, `antirollback_state_path`, and optional `break_glass_override_path` ([config](../../crates/registry-relay/src/config/mod.rs)) | All 27 Relay configs in the scanned example set omit `config_trust`. | Without `config_trust`, startup uses local YAML rather than a signed local bundle. `evidence_grade` treats unsigned config as a startup-fail gate. Post-#314 config trust is boot-time only: no admin config apply route and no hot apply. | Decide whether release examples should keep local YAML only, add signed-bundle examples, or explicitly fence the current examples as non-evidence-grade. |
| Notary | `config_trust` | Omitted by default; post-[#314](https://github.com/registrystack/registry-stack/issues/314) shape is `trust_anchor_path`, `bundle_path`, `antirollback_state_path`, and optional `break_glass_override_path` ([config](../../crates/registry-notary-core/src/config.rs)) | All 27 Notary configs in the scanned example set omit `config_trust`. | Without `config_trust`, startup uses local YAML rather than a signed local bundle. `evidence_grade` treats unsigned config as a startup-fail gate. Post-#314 config trust is boot-time only: no admin config apply route and no hot apply. | Decide whether release examples should keep local YAML only, add signed-bundle examples, or explicitly fence the current examples as non-evidence-grade. |
| Relay | `auth.failure_throttle` | Disabled by default; when enabled, defaults are `max_failures: 20` and `window_seconds: 60` ([config](../../crates/registry-relay/src/config/mod.rs)) | All 27 Relay configs in the scanned example set omit `auth.failure_throttle`, so the local backstop is disabled. | The throttle is a process-local backstop for repeated auth failures from one resolved client address. It does not replace ingress rate limiting and can collapse all clients behind one proxy bucket unless `server.trust_proxy` is configured correctly. | Decide whether shipped examples should enable the throttle, leave it disabled with ingress-rate-limit evidence, or document the DoS posture deferral in section 7. |
| Relay | `deployment.evidence.audit_offhost_shipping` | `false` by `DeploymentEvidenceConfig::default()` ([config](../../crates/registry-relay/src/config/mod.rs)) | All 27 Relay configs in the scanned example set omit the evidence flag, so it remains `false`. | When the audit sink is a local rotating file and off-host shipping is not declared, `relay.audit.retention_local_only` fires under production and evidence-grade profiles. | Decide whether examples should keep local-only audit retention as a local-profile demo constraint or add off-host audit evidence in deployable examples. |
| Notary | `deployment.evidence.audit_offhost_shipping` | `false` by `DeploymentConfig` evidence defaults ([operator reference](../../products/notary/docs/operator-config-reference.md)) | All 27 Notary configs in the scanned example set omit the evidence flag, so it remains `false`. | When the audit sink is local file/JSONL and off-host shipping is not declared, `notary.audit.retention_local_only` fires under production and evidence-grade profiles. | Decide whether examples should keep local-only audit retention as a local-profile demo constraint or add off-host audit evidence in deployable examples. |

Every scanned Relay and Notary runtime-service config declares
`deployment.profile: local`. That explains why many example values are acceptable
for local demonstrations, but it does not by itself settle whether those files
are safe starting points for adopters who copy them into production.
