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
security or privacy issue beyond the documented limitation. Registry Relay
owns source connectivity and transformation; deployments must enforce its
documented outbound-network and credential boundaries.

## Verifying release signatures and provenance

Current Beta releases use an attested candidate and one signed checksum chain.
The candidate workflow attests the exact candidate manifest and bundle. The
publication workflow verifies those attestations and the source binding before
promotion, then keyless-signs `SHA256SUMS`. Every public payload listed in that
file is authenticated by the checksum signature.

Keyless signing does not use a long-lived project private key. The signing
certificate comes from the GitHub Actions OIDC identity for the publication
workflow on protected `main`.

After downloading a release, verify the checksum bundle and then the covered
payloads:

```bash
tag=v0.16.3
bundle="registry-stack-${tag}-SHA256SUMS.sigstore.json"

cosign verify-blob SHA256SUMS \
  --bundle "${bundle}" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-identity \
    "https://github.com/registrystack/registry-stack/.github/workflows/release.yml@refs/heads/main"

sha256sum --check --strict SHA256SUMS
```

Ordinary Beta releases do not publish a second generic SLSA provenance asset.
Earlier releases may instead use per-file `.sig` and `.pem` pairs or a generic
SLSA provenance file. Follow the `release/VERIFY.md` committed at the release's
tag rather than applying the current asset contract to historical releases.

Important Git version tags are annotated but are not yet cryptographically
signed with GPG, SSH, or Sigstore. The publication workflow checks the exact tag
and candidate binding; the signed public control covers `SHA256SUMS` and every
payload it lists. See [`release/VERIFY.md`](release/VERIFY.md) for the complete
verification procedure.
