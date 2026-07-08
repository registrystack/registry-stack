# Configuration trust and integrity

> **Page type:** Explanation · **Product:** Registry Notary · **Layer:** all · **Audience:** operator, integrator, security reviewer

This page explains what Registry Notary and its source adapter sidecar guarantee
about the configuration they run, what you are responsible for, and what is
deliberately out of scope. It is written for operators deciding how to deploy,
integrators connecting a source, and security reviewers evaluating the trust
model. For the exact configuration fields and commands, follow the links in
[Where to go next](#where-to-go-next).

The short version: production configuration can be delivered as a
cryptographically signed local bundle and verified before startup, the
components fail closed when verification fails, and secrets are never part of
the signed configuration.
The strength of these guarantees rests on how you protect your signing keys.

## What you can rely on

- Signed before it runs: In production the source adapter sidecar can start
  from a signed local configuration bundle and verify it before it serves any
  traffic. A bundle that is not signed by a key you authorized, has been
  tampered with, or is older than what is already accepted is refused.
- Fail closed, not degraded: If the signature, signer authorization, file
  closure, identity binding, anti-rollback, runtime configuration validation and
  compile, or startup readiness checks fail, the sidecar refuses to serve. It
  does not start in a partial or best-effort state.
- **No silent rollback.** A previously valid but superseded bundle cannot be
  replayed to move you back to an older configuration.
- **Notary can pin the sidecar it trusts.** Registry Notary can record the exact
  sidecar configuration it expects and refuse to read from a sidecar that does
  not match, so a drifted or misconfigured sidecar is caught at the source
  boundary rather than silently used.
- **Secrets stay out of the configuration.** The signed bundle names the
  credentials a source uses; it never contains their values. Credential values
  are never sent to Notary, and never appear in logs, metrics, audit records, or
  the assurance endpoint.

## What you are responsible for

These guarantees are only as strong as the operational practices behind them.

- Key custody: You hold the signing keys and the trust anchor. Anyone who can
  sign with an authorized key can change what runs. Protect signing keys with the
  same care as your most sensitive production secrets, and prefer hardware-backed
  or HSM custody for production. This is the single most important control.
- Trust-anchor distribution and pinning: You distribute the trust anchor to
  each deployment and configure which signer keys are accepted.
- **Credential injection.** You supply credential values at deploy time through
  the environment variables the bundle names. The platform does not distribute
  secret values; your deployment tooling (a secret manager, sealed secrets, or
  equivalent) does.
- **Pinning the expected sidecar.** When you want Notary to enforce that it is
  talking to a known-good sidecar, pin the expected configuration hash in the
  source connection.
- **Network boundary.** The sidecar is a private component. Keep it on localhost
  or a private pod network and never expose it publicly. Constrain its outbound
  access with deployment networking.
- **Image provenance.** Pin container images by digest. See
  [Security assurance](security-assurance.md) for the current image-signing
  status and release evidence.

## How configuration integrity works

A configuration bundle is a local directory containing `manifest.json`,
`manifest.sig.json`, and `config/...`. The manifest binds runtime material
(limits, source definitions, mapping expressions or scripts, and runtime policy)
to a specific product, instance, environment, and stream, gives it a sequence
number, records the whole-config content hash, and lists the exact files allowed
inside the bundle.

Before a bundle takes effect, the component checks, in order and failing closed
on the first failure:

1. the manifest signatures verify against the trust anchor you configured;
2. the bundle is bound to this exact product, instance, environment, and stream;
3. the signers are enabled in the trust anchor;
4. the file closure and hashes match the manifest;
5. the sequence is not older than what was last accepted (anti-rollback);
6. the runtime material deserializes and compiles or validates successfully,
   including configured CEL expressions and scripts;
7. startup readiness, including smoke lookups against configured sources,
   succeeds.

Only after all readiness-critical checks pass is the bundle recorded as accepted
and the listener started. The accepted configuration is summarized by a stable
`config_hash` that Notary and operators can pin.

### Built on local signed bundles

Configuration integrity uses Registry Config Bundle v1, not an HTTP admin apply
surface. Operators build and sign a local bundle directory, place that directory
on the node, and restart the service. The node CLI can verify a bundle before
promotion with `config verify-bundle`; there is no `apply-bundle` command, no
admin config verify, dry-run, or apply route, and no hot apply.

## How secrets are handled

There are two distinct secrets in a Notary-to-sidecar deployment, and neither
lives in the signed configuration.

**The Notary-to-sidecar token** authenticates the connection. Notary holds the
real token. The sidecar holds only a hash (fingerprint) of it and verifies
presented tokens against that fingerprint, so the plaintext token never sits on
the sidecar.

**The target-service credential** is what the sidecar source uses to read the
upstream registry. Its value lives in an environment variable on the sidecar
host. The signed bundle records only the variable's name and the base URLs that
credential is allowed to target, never the value. At startup the sidecar loads
the credential, checks its base URL against the allow-list, and holds it in
memory.

For source-adapter sources, the credential reaches a workflow only through the
per-request input passed to the worker over a private channel, scoped to that
single execution. The worker process runs with a cleared environment, so it does
not inherit the sidecar host's secrets, and configured credential and token
environment variable names are explicitly blocked from being passed into the
worker. The credential is never returned to Notary, never logged, and never
included in the assurance output.

Because the binding (which environment variable, which allowed base URLs) is
part of the signed bundle, someone who can edit local files cannot repoint a
source at a different credential or widen its allowed destinations without a
re-signed, re-authorized bundle. Rotating the credential value itself is a
deploy-time operation and does not require re-signing the bundle; the
`config_hash` describes the binding and policy, not the secret value.

## What this does not protect against

A security control is only useful if its limits are clear. The following are
deliberately out of scope, and you should compensate for them with deployment
controls.

- **The assurance check is self-attested.** When Notary pins an expected sidecar
  and reads its `/v1/assurance`, it is trusting a report the sidecar produces
  about itself. This detects configuration drift, a sidecar running something
  other than what you pinned, but it does not defend against a malicious or
  impersonating component on the private network that forges its responses. Treat
  the sidecar as a trusted component behind a private boundary, and rely on
  network controls and the bearer token for that boundary.
- **Configuration integrity is not runtime-code integrity.** The signature
  proves the governed runtime bundle is authentic. The whole-config
  `config_hash` covers the inline governed content, including CEL expressions,
  Rhai scripts, and runtime policy. The sidecar does not maintain a separate
  per-file expression hash ledger, and the assurance booleans do not attest to
  installed runtime or adapter package versions. Manage the sidecar binary and
  dependencies with your image build and supply-chain controls.
- **The base-URL allow-list is not an egress sandbox.** `allowed_base_urls`
  validates the configured credential targets at startup. It is not a general
  JavaScript egress firewall for workflow code. Constrain outbound traffic with
  deployment networking, for example a Kubernetes network policy or an internal
  network.
- Verification is at startup, not continuous: The sidecar verifies its
  bundle at startup; Notary refreshes the sidecar's assurance on readiness
  checks and caches it for a short interval. Trust-anchor or bundle changes are
  recognized on the next verification, which requires a restart.
- **Release images are not signed.** Pin images by digest and review the root
  release capsule, SBOM, and vulnerability scan artifacts.

## Development mode

Local development can run from unsigned local config using an explicit opt-in
flag. Emergency `accept_unsigned` is also local: it pins an absolute config path
and hash for boot recovery, not an HTTP admin break-glass flow. These modes
disable the signature guarantees above and must never be used as normal
production operation. For rehearsing the signed flow locally, release tooling
can build and verify a signed bundle against a local trust anchor.

## Where to go next

- [Model sources and claims](source-claim-modeling-guide.md): configure the
  source adapter sidecar connector and the claim boundary.
- [Operator configuration reference](operator-config-reference.md): the exact
  configuration blocks, including the source connection and expected-sidecar
  pinning.
- [Source adapter sidecar reference](../../../crates/registry-notary-source-adapter-sidecar/README.md):
  the sidecar runtime details for source-adapter deployments.
- [Signing key providers](signing-key-provider.md): credential (SD-JWT VC)
  signing keys. Note these are the keys Notary uses to sign issued credentials,
  which are separate from the keys that sign configuration bundles.
- [Deployment hardening runbook](deployment-hardening-runbook.md): network
  boundaries, secrets, audit, and rollback readiness.
- [Security assurance](security-assurance.md): release, image, and CI security
  evidence.
