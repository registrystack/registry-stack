# Opt-in wallet verifier compatibility harnesses

These harnesses are future-readiness checks, not wallet integrations and not
interoperability claims. They pin one upstream source tag and commit, then
require an operator-supplied adapter built from that exact upstream revision to
verify a stored Evidence SD-JWT VC against a pinned Evidence JWKS.

The adapter protocol is intentionally small:

```text
<adapter> --registry-stack-version
<adapter> verify --credential <file> --jwks <file>
```

The first command prints the exact expected version line shown by a failing
harness. The verify command exits zero only after the named third-party library
has parsed the complete credential, selected the supplied JWK by `kid`, and
verified the ES256 issuer signature and SD-JWT disclosures. It must not replace
that result with Registry Stack's own verifier.

Each harness verifies the original, mutates the issuer signature, and requires
the same adapter to reject the mutation. A missing adapter, an upstream tag that
does not resolve to the pinned commit, acceptance of the mutated signature, or
any third-party limitation is a failure. This is why CI does not run these
networked checks by default and why the repository makes no compatibility
claim merely because the harness exists.

Run after producing a credential and trusted JWKS with the local demo:

```sh
EVIDENCE_WALLET_COMPAT=1 \
WALTID_SD_JWT_VERIFY=/absolute/path/to/pinned-waltid-adapter \
products/evidence/scripts/compat/waltid-sd-jwt-vc.sh \
  products/evidence/.sd-jwt-vc-demo/credential.txt \
  products/evidence/.sd-jwt-vc-demo/trusted.jwks.json

EVIDENCE_WALLET_COMPAT=1 \
INJI_SD_JWT_VERIFY=/absolute/path/to/pinned-inji-adapter \
products/evidence/scripts/compat/inji-sd-jwt-vc.sh \
  products/evidence/.sd-jwt-vc-demo/credential.txt \
  products/evidence/.sd-jwt-vc-demo/trusted.jwks.json
```

The current pins are:

- walt.id identity `v0.23.0`, commit
  `ba72e32fb5aea2affc1315dfa8471c4ea0384ef6`
- MOSIP Inji VC verifier `v1.9.0`, commit
  `cd5a1d79aa511922a787c7def797e50b2fb13c30`

Pin updates are reviewed compatibility-profile changes. Do not float a branch,
tag, Maven version, container tag, or dependency range inside an adapter.
