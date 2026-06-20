# Security

Report vulnerabilities privately through GitHub Security Advisories:

`https://github.com/jeremi/registry-notary/security/advisories/new`

If GitHub advisories are unavailable, contact Jeremi through an existing private
project channel before opening a public issue or pull request. Do not open
public issues for suspected credential disclosure, auth bypass, audit redaction
failure, source connector data leakage, or signing key handling bugs.

Include the affected commit, config shape, reproduction steps, and impact. Do
not include live credentials, bearer tokens, API keys, private keys, or raw
registry records in the report.

We aim to acknowledge private reports within 5 business days.

In scope for this policy: authentication bypass, credential disclosure, audit
redaction failure, audit integrity failure, signing-key handling bugs, source
connector data leakage, and privacy regressions that expose raw subject
identifiers.

Known pilot limitations such as no revocation service, no
`/.well-known/jwt-vc-issuer` endpoint, and no built-in data-subject erasure
workflow should be reported as product gaps unless they create an exploitable
security or privacy issue beyond the documented limitation.

The source adapter sidecar's `http_json`, `http_flow`, and `fhir` engine paths
enforce in-process SSRF defenses (base-URL allow-list, DNS-resolved IP checks,
cloud-metadata-IP block, redirect handling). The Node.js OpenFn engine path does
not go through those checks. Deployments running OpenFn sources **must** enforce
network-layer egress controls on the sidecar pod: a Kubernetes NetworkPolicy
with an enforcing CNI (Calico, Cilium) or an enforced allow-listing egress proxy
to block the cloud metadata IP (`169.254.169.254`, `fd00:ec2::254`) and RFC 1918
ranges from the worker. This is a deployment requirement, not an optional
hardening step. See
[`docs/openfn-sidecar-egress-hardening.md`](docs/openfn-sidecar-egress-hardening.md)
for a ready-to-apply NetworkPolicy, an enforced egress-proxy alternative, and a
verification checklist. See also
`crates/registry-notary-source-adapter-sidecar/README.md`.
