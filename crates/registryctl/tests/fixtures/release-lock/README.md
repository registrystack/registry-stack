# Release-lock Sigstore fixtures

`cosign-3.0.4-checksums.txt` and its `.sigstore.json` bundle are the exact
`v3.0.4` release assets published by the Sigstore Cosign project:

- <https://github.com/sigstore/cosign/releases/tag/v3.0.4>
- artifact SHA-256:
  `c772bf545b26d4c666bc9254084c8ec74cdaa061cbbd553bb3766fdb7b1a4e09`
- bundle SHA-256:
  `6b3182a6bdf006d54b138cbf8a99787669e16c18738ed243774e4d9f49a710ce`
- certificate identity:
  `keyless@projectsigstore.iam.gserviceaccount.com`
- certificate issuer: `https://accounts.google.com`

The smaller `cosign-v3-blob` pair comes from the Apache-2.0
`sigstore-verify` 0.11.0 interoperability suite and exercises envelope
assembly without duplicating the release-size artifact in Python tests.
