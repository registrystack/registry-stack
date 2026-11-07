# /// script
# requires-python = ">=3.10"
# dependencies = ["jwcrypto"]
# ///
"""Generate compact JWE vectors with jwcrypto, an implementation independent of this crate.

Usage (from any directory):

    uv run tests/fixtures/gen_jwe_vectors.py tests/fixtures/jwe-vectors.json

Every run generates a fresh recipient key, so regenerating replaces the whole
file. The tests in tests/jwe.rs read these members of the output:

  recipient_private_jwk  EC P-256 recipient key; the tests give it kid "enc-1",
                         which the "-kid" cases carry in their protected header
  cases                  eight valid vectors (A128GCM and A256GCM, each plain,
                         with apu/apv, with kid, and with a 20000 byte payload)
  wrong_alg, wrong_enc   well formed JWEs with a refused alg or enc
  other_curve            epk on P-384
  other_recipient        valid JWE addressed to a different P-256 key

The vectors contain only a throwaway test key and synthetic payloads.
"""
import json, sys
from jwcrypto import jwk, jwe
from jwcrypto.common import base64url_encode

def enc(pub, payload, header):
    j = jwe.JWE(payload, json.dumps(header))
    j.add_recipient(pub)
    return j.serialize(compact=True)

out = {"cases": []}
key = jwk.JWK.generate(kty="EC", crv="P-256")
out["recipient_private_jwk"] = json.loads(key.export_private())
pub = jwk.JWK(**json.loads(key.export_public()))
payload = json.dumps({"vp_token": {"cred": ["eyJ.abc.def"]}, "state": "s1"}).encode()
big = b"x" * 20000
for e in ("A128GCM", "A256GCM"):
    for label, extra in (("plain", {}), ("apu_apv", {"apu": base64url_encode(b"Alice"), "apv": base64url_encode(b"nonce-123")}),
                         ("kid", {"kid": "enc-1"})):
        h = {"alg": "ECDH-ES", "enc": e, **extra}
        c = enc(pub, payload, h)
        # round trip with jwcrypto itself to prove the vector is valid
        d = jwe.JWE(); d.deserialize(c); d.decrypt(key); assert d.payload == payload
        out["cases"].append({"name": f"{e}-{label}", "compact": c, "plaintext": payload.decode()})
    c = enc(pub, big, {"alg": "ECDH-ES", "enc": e})
    out["cases"].append({"name": f"{e}-20k", "compact": c, "plaintext": big.decode()})
# negatives produced by jwcrypto
out["wrong_alg"] = enc(pub, payload, {"alg": "ECDH-ES+A128KW", "enc": "A128GCM"})
out["wrong_enc"] = enc(pub, payload, {"alg": "ECDH-ES", "enc": "A128CBC-HS256"})
p384 = jwk.JWK.generate(kty="EC", crv="P-384")
out["other_curve"] = enc(jwk.JWK(**json.loads(p384.export_public())), payload, {"alg": "ECDH-ES", "enc": "A128GCM"})
out["other_recipient"] = enc(jwk.JWK(**json.loads(jwk.JWK.generate(kty="EC", crv="P-256").export_public())), payload, {"alg": "ECDH-ES", "enc": "A128GCM"})
json.dump(out, open(sys.argv[1], "w"), indent=1)
print("cases", len(out["cases"]))
