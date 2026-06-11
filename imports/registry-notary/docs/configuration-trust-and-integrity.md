# Configuration Trust And Integrity

> **Page type:** Explanation · **Product:** Registry Notary · **Layer:** all · **Audience:** operator, integrator, security reviewer

This page explains what Registry Notary and its OpenFn sidecar guarantee about
the configuration they run, what you are responsible for, and what is
deliberately out of scope. It is written for operators deciding how to deploy,
integrators connecting a source, and security reviewers evaluating the trust
model. For the exact configuration fields and commands, follow the links in
[Where to go next](#where-to-go-next).

The short version: production configuration is delivered as a cryptographically
signed bundle and verified before it takes effect, the components fail closed
when verification fails, and secrets are never part of the signed configuration.
The strength of these guarantees rests on how you protect your signing keys.

## What you can rely on

- **Signed before it runs.** In production the OpenFn sidecar starts from a
  signed configuration bundle and verifies it before it serves any traffic. A
  bundle that is not signed by a key you authorized, has been tampered with, has
  expired, or is older than what is already accepted is refused.
- **Fail closed, not degraded.** If the signature, signer authorization, file
  hashes, pinned runtime versions, or startup readiness checks fail, the sidecar
  refuses to serve. It does not start in a partial or best-effort state.
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

- **Key custody.** You hold the signing keys and the trust root. Anyone who can
  sign with an authorized key can change what runs. Protect signing keys with the
  same care as your most sensitive production secrets, and prefer hardware-backed
  or HSM custody for production. This is the single most important control.
- **Trust-root distribution and pinning.** You distribute the trust root to each
  deployment and configure which roots, signer keys, roles, thresholds, and
  change classes are accepted. Require multiple signatures (a threshold) for
  high-risk changes such as workflow or source-binding bundles.
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

A configuration bundle is the runtime material (limits, pinned runtime and
adaptor versions, worker definition, and source workflows) plus signed metadata
that binds it to a specific product, instance, environment, and stream, gives it
a sequence number, and records its content hash.

Before a bundle takes effect, the component checks, in order and failing closed
on the first failure:

1. the signatures verify against the trust root you configured;
2. the bundle is bound to this exact product, instance, environment, and stream;
3. the signers are authorized for the change classes in the bundle, meeting the
   required signature threshold;
4. the sequence is not older than what was last accepted (anti-rollback);
5. the runtime material matches the recorded content hash, and every workflow
   expression file matches its recorded SHA-256 hash;
6. the pinned OpenFn runtime and adaptor versions match what is installed;
7. startup readiness (including a smoke lookup against the source) succeeds.

Only after all readiness-critical checks pass is the bundle recorded as accepted
and the listener started. The accepted configuration is summarized by a stable
`config_hash` that Notary and operators can pin.

### Built on TUF

Configuration integrity is not homegrown cryptography. It uses
[The Update Framework (TUF)](https://theupdateframework.io/) through a standard,
maintained client implementation. TUF provides signed metadata with separate
roles, threshold signatures, signed key rotation, freshness (expiration)
enforcement, and protection against rollback and mix-and-match attacks. The
change-class authorization model (which keys may approve which kinds of change,
and how many signatures each requires) is a Registry-specific policy layered on
top of TUF's verified output. In short: TUF establishes that a bundle is
authentic and current; the Registry layer decides whether the signers were
allowed to make that particular change.

## How secrets are handled

There are two distinct secrets in a Notary-to-sidecar deployment, and neither
lives in the signed configuration.

**The Notary-to-sidecar token** authenticates the connection. Notary holds the
real token. The sidecar holds only a hash (fingerprint) of it and verifies
presented tokens against that fingerprint, so the plaintext token never sits on
the sidecar.

**The target-service credential** is what the OpenFn workflow uses to read the
upstream registry. Its value lives in an environment variable on the sidecar
host. The signed bundle records only the variable's name and the base URLs that
credential is allowed to target, never the value. At startup the sidecar loads
the credential, checks its base URL against the allow-list, and holds it in
memory.

The credential reaches a workflow only through the per-request input passed to
the worker over a private channel, scoped to that single execution. The worker
process runs with a cleared environment, so it does not inherit the sidecar
host's secrets, and configured credential and token environment variable names
are explicitly blocked from being passed into the worker. The credential is
never returned to Notary, never logged, and never included in the assurance
output.

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
  proves the configuration bundle is authentic, including the workflow
  expression files, which are content-hashed. The OpenFn worker runtime and its
  adaptors are pinned by version and verified against the installed versions, but
  their contents are not hashed by the configuration signature. A compromised
  dependency published at a pinned version is outside what the config signature
  covers; manage that with your image build and supply-chain controls.
- **The base-URL allow-list is not an egress sandbox.** `allowed_base_urls`
  validates the configured credential targets at startup. It is not a general
  JavaScript egress firewall for workflow code. Constrain outbound traffic with
  deployment networking, for example a Kubernetes network policy or an internal
  network.
- **Verification is at apply time, not continuous.** The sidecar verifies its
  bundle at startup; Notary refreshes the sidecar's assurance on readiness checks
  and caches it for a short interval. Revoked keys or newly expired metadata are
  recognized on the next verification (a restart or the next readiness refresh),
  not instantaneously.
- **Container images are signed by the release workflow.** Pin images by
  digest and verify the `cosign` signature for release tags. See
  [Security assurance](security-assurance.md).

## Development mode

Local development can run from an unsigned manifest using an explicit opt-in
flag. This mode exists only for local iteration and demos; it disables the
guarantees above and must never be used in production. Production startup
requires a configured trust anchor and refuses unsigned configuration. For
rehearsing the signed flow locally, the release tooling can build and verify a
signed bundle against a local trust root, which exercises the real verification
path without production key custody.

## Where to go next

- [Model sources and claims](source-claim-modeling-guide.md): configure the
  OpenFn sidecar source connector and the claim boundary.
- [Operator configuration reference](operator-config-reference.md): the exact
  configuration blocks, including the source connection and expected-sidecar
  pinning.
- [OpenFn sidecar reference](../crates/registry-notary-openfn-sidecar/README.md):
  the governed bundle layout and the commands that render, sign, and verify a
  bundle.
- [Signing key providers](signing-key-provider.md): credential (SD-JWT VC)
  signing keys. Note these are the keys Notary uses to sign issued credentials,
  which are separate from the keys that sign configuration bundles.
- [Deployment hardening runbook](deployment-hardening-runbook.md): network
  boundaries, secrets, audit, and rollback readiness.
- [Security assurance](security-assurance.md): release, image, and CI security
  evidence.
