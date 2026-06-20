# Sidecar Trust And Secret Handling

> **Page type:** Explanation · **Product:** Registry Notary · **Layer:** evaluation · **Audience:** operator, integrator, security reviewer

Registry Notary reads source facts through the source adapter sidecar when a
target system needs governed HTTP JSON mapping, a short dependent HTTP JSON
flow, OpenFn adaptor execution, or normalization outside Notary. This page
covers what is specific to that source path: how the sidecar verifies the
configuration it runs, how Notary confirms it is talking to the sidecar you
expect, and how secrets are handled along the way.

The general governed-configuration model (signed bundles, TUF verification, trust
roots, signer thresholds, and anti-rollback) is a shared Registry Platform
capability used by Registry Relay and Registry Notary alike. This page does not
restate it. See
[Governed configuration](../../registry-platform/docs/governed-configuration.md)
for the shared model and how verification, authorization, and rollback protection
work. Configuration integrity there is built on TUF (The Update Framework)
through a standard, maintained client, not homegrown cryptography. What follows
is the Notary- and sidecar-specific layer on top of that model.

## What you can rely on

- **The sidecar fails closed at startup.** In production the sidecar starts only
  from a signed configuration bundle. If the signature, signer authorization,
  content and per-file expression hashes, pinned runtime and adaptor versions, or
  the startup smoke lookup fail, it refuses to serve. It does not start in a
  partial or best-effort state.
- **Notary can pin the sidecar it trusts.** A source connection can record the
  exact sidecar identity and configuration hash it expects. Notary refuses to
  read from a sidecar whose reported assurance does not match, so a drifted or
  misconfigured sidecar is caught at the source boundary rather than silently
  used.
- **Secrets stay out of the configuration.** The signed bundle names the
  credentials a source uses; it never contains their values. Credential values
  are never sent to Notary, and never appear in logs, metrics, audit records, or
  the assurance endpoint.

## What you are responsible for

Key custody and trust-root distribution are part of the
[shared governed-configuration model](../../registry-platform/docs/governed-configuration.md#trust-roots-roles-and-change-classes)
and matter just as much here: the guarantees above are only as strong as your
protection of the signing keys. Specific to the sidecar path:

- **Credential injection.** Supply credential values at deploy time through the
  environment variables the bundle names. The platform distributes the binding,
  not the secret value; your secret manager does.
- **Pinning the expected sidecar.** To have Notary enforce that it is talking to
  a known-good sidecar, pin the expected configuration hash and the verification
  requirements in the source connection.
- **Network boundary.** The sidecar is a private component. Keep it on localhost
  or a private pod network, never expose it publicly, and constrain its outbound
  access with deployment networking.
- **Image provenance.** Pin container images by digest. See
  [Security assurance](security-assurance.md).

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

For OpenFn sources, the credential reaches a workflow only through the
per-request input passed to the worker over a private channel, scoped to that
single execution. The worker process runs with a cleared environment, so it does
not inherit the sidecar host's secrets, and configured credential and token
environment variable names are explicitly blocked from being passed into the
worker. The credential is never returned to Notary, never logged, and never
included in the assurance output.

Because the binding (which environment variable, which allowed base URLs) is part
of the signed bundle, someone who can edit local files cannot repoint a source at
a different credential or widen its allowed destinations without a re-signed,
re-authorized bundle. Rotating the credential value itself is a deploy-time
operation and does not require re-signing the bundle; the configuration hash
describes the binding and policy, not the secret value.

## What this does not protect against

A security control is only useful if its limits are clear. The following are
deliberately out of scope for the sidecar source path, and you should compensate
for them with deployment controls.

- **The assurance check is self-attested.** When Notary pins an expected sidecar
  and reads its assurance, it is trusting a report the sidecar produces about
  itself. This detects configuration drift, a sidecar running something other
  than what you pinned, but it does not defend against a malicious or
  impersonating component on the private network that forges its responses. Treat
  the sidecar as a trusted component behind a private boundary, and rely on
  network controls and the bearer token for that boundary.
- **Configuration integrity is not runtime-code integrity.** The signature proves
  the configuration bundle is authentic, including OpenFn workflow expression
  files when they are used. Those files are content-hashed. The OpenFn worker
  runtime and its adaptors are pinned by version and verified against the
  installed versions, but their contents are not hashed by the configuration
  signature. A compromised dependency published at a pinned version is outside
  what the config signature covers; manage that with your image build and
  supply-chain controls.
- **The base-URL allow-list is not an egress sandbox.** `allowed_base_urls`
  validates the configured credential targets at startup. It is not a general
  JavaScript egress firewall for workflow code. The `http_json`, `http_flow`,
  and `fhir` engine paths enforce in-process SSRF defenses; the Node.js OpenFn
  engine path does not. Constrain outbound traffic with deployment networking.
  For OpenFn sources, network-layer egress controls are required, not optional —
  see [OpenFn sidecar egress hardening](openfn-sidecar-egress-hardening.md)
  for a ready-to-apply Kubernetes NetworkPolicy and egress-proxy alternative.
- **Notary's assurance view is periodic, not per-read.** Notary refreshes the
  sidecar's assurance on readiness checks and caches it for a short interval, so a
  sidecar that changes underneath a running Notary is recognized on the next
  refresh, not instantaneously.
- **Container images are signed by the release workflow.** Pin images by
  digest and verify the `cosign` signature for release tags. See
  [Security assurance](security-assurance.md).

## Development mode

Local development can run the sidecar from an unsigned manifest using an explicit
opt-in flag. This mode exists only for local iteration and demos; it disables the
guarantees above and must never be used in production. Production startup requires
a configured trust anchor and refuses unsigned configuration. For rehearsing the
signed flow locally, the sidecar's release tooling can build and verify a signed
bundle against a local trust root, which exercises the real verification path
without production key custody.

## Where to go next

- [Governed configuration](../../registry-platform/docs/governed-configuration.md):
  the shared platform model behind signed configuration, trust roots, signer
  thresholds, and anti-rollback. Read this first for the trust model itself.
- [Model sources and claims](source-claim-modeling-guide.md): configure the
  source adapter sidecar connector and the claim boundary.
- [Operator configuration reference](operator-config-reference.md): the exact
  configuration blocks, including the source connection and expected-sidecar
  pinning.
- [Source adapter sidecar reference](../crates/registry-notary-source-adapter-sidecar/README.md):
  the governed bundle layout and the commands that render, sign, and verify a
  bundle.
- [Signing key providers](signing-key-provider.md): credential (SD-JWT VC)
  signing keys. Note these are the keys Notary uses to sign issued credentials,
  which are separate from the keys that sign configuration bundles.
- [Deployment hardening runbook](deployment-hardening-runbook.md): network
  boundaries, secrets, audit, and rollback readiness.
