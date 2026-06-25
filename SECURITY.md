# Security

Report vulnerabilities privately through GitHub Security Advisories:

`https://github.com/registrystack/registry-stack/security/advisories/new`

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
security or privacy issue beyond the documented limitation. The source adapter
sidecar also relies on deployment-network egress controls for outbound source
traffic; see `crates/registry-notary-source-adapter-sidecar/README.md`.

## Verifying release signatures

Registry Stack release assets are signed by the release workflow with keyless
Sigstore cosign. Keyless signing does not use a long-lived project private key
or a project-hosted public key file. The signing certificate is issued from the
GitHub Actions OIDC identity for
`registrystack/registry-stack/.github/workflows/release.yml`, and the public
verification material is the `.pem` certificate, `.sig` signature, Fulcio root,
and Rekor transparency-log entry used by cosign.

For each signed release asset, download three files from the GitHub Release:

- The asset, for example `registryctl-v0.8.2-linux-amd64`
- The matching signature, for example `registryctl-v0.8.2-linux-amd64.sig`
- The matching certificate, for example `registryctl-v0.8.2-linux-amd64.pem`

Then verify the asset:

```bash
asset=registryctl-v0.8.2-linux-amd64

cosign verify-blob \
  --certificate "${asset}.pem" \
  --signature "${asset}.sig" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-identity-regexp '^https://github.com/registrystack/registry-stack/.github/workflows/release.yml@refs/tags/v[0-9]+[.][0-9]+[.][0-9]+.*$' \
  "${asset}"
```

If a release asset does not have matching `.sig` and `.pem` files, treat that
asset as unsigned. The `v0.8.0` prerelease was published before release-asset
signing was added and does not currently include cosign signature assets.

Important Git version tags are not yet cryptographically signed with GPG, SSH,
or Sigstore. The current signed-release control covers GitHub Release assets
that include matching cosign `.sig` and `.pem` files; signed Git tags remain a
separate hardening item.
