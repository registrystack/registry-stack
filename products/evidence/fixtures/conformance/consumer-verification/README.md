# Consumer verification vector

A synthetic signed Registry Evidence response that a relying party's own test
suite can verify, with every input a verifier needs and the outcomes it must
reach. All values are synthetic.

| File | Contents |
|---|---|
| `../golden/adult-request.json` | The request the relying party sent and retained, including its `requestNonce` |
| `response.json` | The `application/jose+json` response body: a flattened JWS over the exact bytes of `../golden/adult-evidence.json` |
| `jwks.json` | The public key set the relying party pinned for this provider |
| `policy.json` | The relying party's expectations, in the verification policy format (`contracts/verification-policy.schema.yaml`) |
| `cases.json` | Verification instants and changes, each with the result a verifier must reach |

A case may change members of `policy.json` (`policyChanges`) or the response
(`responseChange`). `replace-first-payload-character` replaces the first
character of `payload` with `A`, or with `B` when it already is `A`.
`verifierKind` is the refusal class the reference verifier reports; your
verifier only has to refuse.

`crates/registry-evidence-verifier/tests/consumer_verification.rs` runs every
case against the reference verifier. ECDSA signatures are randomised, so the
response is signed once and kept; it is not regenerated on each run.
