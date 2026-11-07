# Registry Platform X.509

`registry-platform-x509` validates X.509 certificate chains carried in a JOSE `x5c` header against operator-configured trust anchors, outside TLS. It never takes a trust anchor from the chain it validates, takes the verification time from the caller, and performs no I/O.

## API

- `X5cChain::parse` reads an `x5c` value (standard base64 DER, leaf first); `X5cChain::from_pem` reads a PEM bundle. At most 8 certificates of at most 16 KiB each; an empty chain is refused.
- `TrustAnchors::from_der_certificates` and `TrustAnchors::from_pem` take bytes the caller loaded (at most 64 anchors, 1 MiB of PEM). `digest()` is an order-independent base64url SHA-256 over the set, for logging which anchors were used.
- `ChainPolicy` sets the maximum number of intermediate CA certificates on the verified path (a configured anchor the chain also ships does not count) and the allowed leaf key types. The leaf must always carry a KeyUsage extension with digitalSignature.
- `verify_chain(&chain, &anchors, &policy, now)` returns a `VerifiedLeaf`: the leaf `PublicJwk` (P-256 or Ed25519; other key types are refused), SAN DNS names and URIs, a printable subject for logs, and the `x509_hash`. Path building, validity periods, and CA/path-length constraints come from `rustls-webpki`; KeyUsage and key extraction come from `x509-cert`. Extended key usage is not constrained.
- `x509_hash(leaf_der)` is base64url (no padding) of SHA-256 over the leaf DER, the OpenID4VP 1.0 `x509_hash` client identifier.
- `CertifiedSigner` binds a `registry_platform_crypto::SigningProvider` to its chain. It refuses a chain whose leaf key differs from the signer key, and exposes the `x5c` header value and `x509_hash`. It does not validate the chain; relying parties do.

This crate does not check revocation; status is handled elsewhere, later. `CertifiedSigner` does not validate its own chain, so a caller that needs that calls `verify_chain` at startup.

`X509Error` is a closed enum. No variant, Display, or Debug output carries certificate bytes.

## Test data

`tests/data/hash-vector-leaf.der.b64` is a P-256 self-signed certificate made with OpenSSL; `hash-vector-leaf.x509_hash` was computed independently of this crate with:

```sh
openssl x509 -in c.pem -outform der | openssl dgst -sha256 -binary | openssl base64 -A | tr '+/' '-_' | tr -d '='
```
