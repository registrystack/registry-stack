# /// script
# requires-python = ">=3.10"
# dependencies = [
#     "sd-jwt==0.10.4",
#     "cryptography",
# ]
# ///
"""Generate SD-JWT VC presentation vectors with an independent implementation.

The issuer and holder sides come from the OpenWallet Foundation `sd-jwt`
Python reference (https://github.com/openwallet-foundation-labs/sd-jwt-python),
not from this repository. Run with:

    uv run --script generate.py

Keys, times, nonce and client_id are fixed below and recorded in each output
file. Salts and ECDSA signatures are random, so a rerun produces different
bytes with the same meaning; the committed files are the vectors the Rust
tests verify (tests/vectors.rs). The keys are test keys and protect nothing.
"""

import base64
import datetime
import json
import pathlib
import sys

import sd_jwt.holder
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.x509.oid import NameOID
from jwcrypto.jwk import JWK
from sd_jwt.holder import SDJWTHolder
from sd_jwt.issuer import SDJWTIssuer
from sd_jwt.common import SDObj

OUT = pathlib.Path(__file__).resolve().parent

# Fixed instants (Unix seconds).
NOW = 1_800_000_000
ISSUED_AT = NOW - 1000
EXPIRES_AT = NOW + 30 * 86400

NONCE = "vector-nonce-5e1c9b"
CLIENT_ID = "x509_san_dns:verifier.example"

ISSUER = "https://vectors.example/issuer"
VCT = "https://vectors.example/vct/person"

ISSUER_ES256 = {"crv": "P-256", "d": "ItLhY3aIrWDXjAtL2BTfsQ9ZvaJqcZDimWragFM_BKI", "kty": "EC", "x": "Gp8VE_E5ua2HpBppIbZMlHHTWvnuhf1wZW594tOMU08", "y": "MntKFbL-hZ1dmkjylsFfpBaluftN0MGBRqbxnIPU4hU"}
HOLDER_ES256 = {"crv": "P-256", "d": "KU1uQZBCHIlpPSnFIvni7WQ-1eeVkiOLEbj7348NsH0", "kty": "EC", "x": "ZItgB0ciFdV4IQwawN0ZPcg6D-v6EPoc0MtpOilmgjY", "y": "ppY8DiBNfI2irqn1uKkzOw0E2RiHarv8qnSJRWEiCxI"}
ISSUER_ED = {"crv": "Ed25519", "d": "jzFeLJy6LMCMLU0-BaF1WX7I3PhulDCUBG1-2g0CwGw", "kty": "OKP", "x": "F3WRR3YPqkaaHiMQNBYGzI7rXx_-fXrwLIzj6t4n1rU"}
HOLDER_ED = {"crv": "Ed25519", "d": "9PDgcoaK6ECJuZN9XbIwc9I2uwk8p4cLwCfwF6v9mdI", "kty": "OKP", "x": "9kVbcObcHBj4q97xNp3cSP3g8xHcl18DPdvKc51veMY"}
ROOT_ES256 = {"crv": "P-256", "d": "FzhpHsNOXH-QK9YBbeJd442BfCrBapzpQ2UrJsawv1c", "kty": "EC", "x": "d9Yd46hPN3QI-ThFFTNUoD2OYslalXhKYxIfMKw8iGI", "y": "LGCZeEsA2R1GGOU-oKh0KXFCgU14QeRUwBUWqvMUJ88"}


def b64url_int(value: str) -> int:
    return int.from_bytes(base64.urlsafe_b64decode(value + "=" * (-len(value) % 4)), "big")


def public_of(jwk: dict) -> dict:
    return {k: v for k, v in jwk.items() if k != "d"}


def ec_private(jwk: dict):
    return ec.derive_private_key(b64url_int(jwk["d"]), ec.SECP256R1())


def ed_private(jwk: dict):
    seed = base64.urlsafe_b64decode(jwk["d"] + "=" * (-len(jwk["d"]) % 4))
    return Ed25519PrivateKey.from_private_bytes(seed)


def certificates():
    """A fixed-validity root (P-256) and an Ed25519 leaf issued directly by it."""
    not_before = datetime.datetime(2026, 1, 1, tzinfo=datetime.timezone.utc)
    not_after = datetime.datetime(2036, 1, 1, tzinfo=datetime.timezone.utc)
    root_key = ec_private(ROOT_ES256)
    root_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Vectors Root")])
    root = (
        x509.CertificateBuilder()
        .subject_name(root_name)
        .issuer_name(root_name)
        .public_key(root_key.public_key())
        .serial_number(1)
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=False, content_commitment=False, key_encipherment=False,
                data_encipherment=False, key_agreement=False, key_cert_sign=True,
                crl_sign=False, encipher_only=False, decipher_only=False,
            ),
            critical=True,
        )
        .sign(root_key, hashes.SHA256())
    )
    leaf_key = ed_private(ISSUER_ED)
    leaf = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Vectors Issuer")]))
        .issuer_name(root_name)
        .public_key(leaf_key.public_key())
        .serial_number(2)
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True, content_commitment=False, key_encipherment=False,
                data_encipherment=False, key_agreement=False, key_cert_sign=False,
                crl_sign=False, encipher_only=False, decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("vectors.example")]), critical=False)
        .sign(root_key, hashes.SHA256())
    )
    return root, leaf


def claims(sd_wrapped: bool) -> dict:
    """Registered claims in the clear, personal claims selectively disclosable."""
    base = {
        "iss": ISSUER,
        "vct": VCT,
        "iat": ISSUED_AT,
        "nbf": ISSUED_AT,
        "exp": EXPIRES_AT,
    }
    if not sd_wrapped:
        return base
    return {
        **base,
        SDObj("given_name"): "Aroha",
        SDObj("family_name"): "Tane",
        "address": {SDObj("street"): "1 Lambton Quay", "city": "Wellington"},
        "nationalities": [SDObj("NZ"), "FR"],
    }


def present(issuer_jwk, holder_jwk, alg, extra_header, disclose, with_kb):
    issuer_key = JWK(**issuer_jwk)
    holder_key = JWK(**holder_jwk)
    issuer = SDJWTIssuer(
        claims(True),
        issuer_key,
        holder_key,
        sign_alg=alg,
        add_decoy_claims=True,
        extra_header_parameters={"typ": "dc+sd-jwt", **extra_header},
    )
    holder = SDJWTHolder(issuer.sd_jwt_issuance)
    if with_kb:
        # The reference reads time.time() for the key-binding `iat`; pin it.
        sd_jwt.holder.time = lambda: NOW
        holder.create_presentation(disclose, NONCE, CLIENT_ID, holder_key, alg)
    else:
        holder.create_presentation(disclose)
    return holder.sd_jwt_presentation


def write(name, document):
    path = OUT / f"{name}.json"
    path.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n")
    print(f"wrote {path}", file=sys.stderr)


def main():
    common = {
        "now": NOW,
        "receivedAt": NOW,
        "nonce": NONCE,
        "clientId": CLIENT_ID,
        "issuer": ISSUER,
        "vct": VCT,
        "issuedAt": ISSUED_AT,
        "expiresAt": EXPIRES_AT,
        "generator": "sd-jwt (OpenWallet Foundation) 0.10.4 via generate.py",
    }

    # Vector 1: ES256 issuer with a pinned key, ES256 holder, key binding,
    # nested and array Disclosures, decoy digests. The holder withholds
    # `family_name` and shows `given_name`, the street, and the first
    # nationality.
    disclose = {"given_name": True, "address": {"street": True}, "nationalities": [True]}
    write(
        "es256-pinned-key",
        {
            **common,
            "presentation": present(
                ISSUER_ES256, HOLDER_ES256, "ES256", {"kid": "vector-issuer-es256"}, disclose, True
            ),
            "keyBindingRequired": True,
            "issuerKey": {**public_of(ISSUER_ES256), "kid": "vector-issuer-es256", "alg": "ES256"},
            "expectedClaims": {
                "given_name": "Aroha",
                "address": {"street": "1 Lambton Quay", "city": "Wellington"},
                "nationalities": ["NZ", "FR"],
            },
            "withheldClaims": ["family_name"],
        },
    )

    # Vector 2: Ed25519 issuer whose certificate chains to a P-256 root, carried
    # in `x5c`; Ed25519 holder; the issuer is bound to the leaf through the
    # dNSName SAN equal to the host of `iss`. No key-binding JWT is sent.
    root, leaf = certificates()
    leaf_der = leaf.public_bytes(serialization.Encoding.DER)
    write(
        "eddsa-x5c-no-key-binding",
        {
            **common,
            "issuer": "https://vectors.example/issuer",
            "presentation": present(
                ISSUER_ED,
                HOLDER_ED,
                "EdDSA",
                {"x5c": [base64.b64encode(leaf_der).decode()]},
                {"family_name": True, "nationalities": []},
                False,
            ),
            "keyBindingRequired": False,
            "anchorPem": root.public_bytes(serialization.Encoding.PEM).decode(),
            "expectedClaims": {
                "family_name": "Tane",
                "address": {"city": "Wellington"},
                "nationalities": ["FR"],
            },
            "withheldClaims": ["given_name"],
        },
    )


if __name__ == "__main__":
    main()
