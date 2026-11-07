# Registry Evidence Presentation

`registry-evidence-presentation` verifies a credential that a holder presented from a wallet, for the Evidence holder-presented credential source (`products/evidence/CONCEPT.md` section 15.10). It performs no I/O and reads no clock: the caller supplies the presentation, the session context, the configured issuer trust, and the evaluation time.

```rust
verify_sd_jwt_vc(presentation, &ctx, &trust, &policy, now)
    -> Result<VerifiedCredential, PresentationRefusal>
```

## Configuration types

All are plain data with serde `Deserialize`, `deny_unknown_fields`, camelCase keys (`products/platform/CONFIG-CONVENTIONS.md`). The caller reads files; this crate gets text and bytes.

- `IssuerTrust`: a list of entries, each with an `id`, the exact `issuer` (`iss`) it vouches for, the `vct` values that issuer may issue, and one key source: `x5c` (trust anchors as PEM text, `maxPathLength`, `leafKeyTypes`) or `jwks` (pinned public Ed25519 or P-256 keys, each with a `kid`). Construction refuses an empty list, a repeated `id` or `issuer`, an empty `vct` list, and an empty or unusable key source.
- `IssuerDenyList` (read from `IssuerDenyListConfig`): issuer identifiers (`issuers`) and SHA-256 fingerprints of certificate DER (`certificateSha256`, 64 hex digits). Both members are required, so an empty deny-list is stated rather than defaulted. `IssuerTrust::with_deny_list` attaches it; without one, nothing is denied.
- `ChannelPolicy`: accepted `vct` values; `keyBindingRequired` (always stated, never inferred from whether a key-binding JWT arrived); `kbIatWindowSeconds`; `clockSkewSeconds`; `issuerAlgorithms` (`ES256`, `EdDSA`).
- `SessionContext`: the session `nonce`, the full prefixed `client_id` (for example `x509_san_dns:verifier.example`), and `received_at`.

## What it checks

In this order, stopping at the first failure:

1. Size and shape of the presentation, disclosure count and size.
2. Issuer JWT header: `typ` is exactly `dc+sd-jwt`; `alg` is on the policy list (never `none`); `crit`, `b64`, `jku`, `jwk` and `x5u` are refused.
3. The deny-list: the unverified `iss`, and every certificate in a presented `x5c` header (leaf or intermediate) by fingerprint, are checked before the allow-list lookup and before any key lookup or signature check. A hit is `IssuerDenied`.
4. `iss` is present and equals the `issuer` of exactly one trust entry.
5. The issuer key. For an `x5c` entry, the header chain is verified to that entry's anchors (an anchor is never taken from the header) and `iss` must be bound to the leaf certificate. For a `jwks` entry, the header `kid` selects a pinned key; a missing or unknown `kid` is refused, and an `x5c` header is refused.
6. The issuer signature.
7. `vct` is present and exactly in both the policy list and the entry list.
8. Disclosures resolve (nested, recursive, array elements, decoys; duplicate digests, unreferenced and malformed disclosures are refused), and none of `iss`, `nbf`, `exp`, `cnf`, `vct`, `status` was supplied or reached by a disclosure.
9. Times at the injected `now`, with skew: `exp` not passed, `nbf` reached, `iat` required and not in the future.
10. The holder key: `cnf.jwk`, or `cnf.kid` when it is a `did:jwk` decoded locally (Ed25519 keys, the platform's `did:jwk` support). `cnf` must hold exactly that one member.
11. Key binding. When policy requires it the key-binding JWT must be present. When one is present it is always validated, required or not: `typ` `kb+jwt`, ES256 or EdDSA, `aud` equal to the full prefixed `client_id`, `nonce` equal to the session nonce (constant time), `iat` within the window around `received_at`, `sd_hash` over the presented SD-JWT. Unknown KB-JWT claims are ignored.

### Binding `iss` to the issuer certificate

SD-JWT VC draft-13 section 3.5 makes the subject of the end-entity certificate the issuer and defines no comparison with `iss`. Draft-25 section 2.5 says the `x5c` mechanism does not authenticate `iss`, and a recipient may treat `iss` as identifying the issuer only when its policy binds it to the end-entity certificate, for example through a subjectAltName (RFC 5280 section 4.2.1.6). The stricter reading is implemented: the binding is required, and holds when a `uniformResourceIdentifier` SAN equals `iss` exactly, or when `iss` is an `https` URL and a `dNSName` SAN equals its host (ASCII case-insensitive, no wildcard matching). The certificate subject name is not used.

## Accept matrix

| Item | Rule |
|---|---|
| Credential `typ` | `dc+sd-jwt` only |
| Issuer algorithms | policy list, ES256 and EdDSA |
| `vct` | exact match in the policy and in the trust entry; no type metadata, no `vct#integrity` |
| Issuer key | `x5c` chain to configured anchors, or a pinned JWKS selected by `kid` |
| Key binding | required by policy, never by presence |
| Holder key | `cnf.jwk`, or `cnf.kid` as `did:jwk` |
| Status | the presence of a `status` claim is reported; status is not checked |

P-256 JWKs without `alg` (as wallets and issuers publish them) are read as ES256.

## What it never does

No fetch of any kind (no issuer metadata, no JWKS, no status list, no type metadata), no DID resolution beyond decoding a `did:jwk` locally, no clock, no filesystem, no async runtime, no replay store: a nonce is compared, never consumed.

## Refusals

`PresentationRefusal` is a closed, `#[non_exhaustive]` enum of fixed-message categories. Its `Display` and `Debug` never carry presented bytes, claim names or values, keys, or the nonce. `Debug` of `SessionContext` redacts the nonce and `Debug` of `VerifiedCredential` redacts the claims.

## Test vectors

`tests/vectors/generate.py` produces presentations with the OpenWallet Foundation `sd-jwt` Python reference (`uv run --script generate.py`). The committed JSON files record the fixed keys, times, nonce and client identifier; `tests/vectors.rs` verifies them. Salts and ECDSA signatures are random, so a rerun yields different bytes with the same meaning.
