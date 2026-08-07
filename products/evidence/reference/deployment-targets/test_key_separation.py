#!/usr/bin/env python3
"""Focused regression tests for deployment-target client-key parsing."""

from __future__ import annotations

import base64
import pathlib
import sys
import tempfile
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

from key_separation import CheckError, check_client_file


ED25519_X = "k61ZMTVQ46byu1FIuIPwG5kqnOl4NLZPPD9dB1zuov0"
P256_X = "3zUWEuqSgzHbjwNbXbhqJrTd75dHZPNseIbIS4eM5Ks"
P256_Y = "XSfKJQ1wizjUKFf-WewDor4sPNt7XBQlnpWeiAPLM34"
RSA_N = (
    base64.urlsafe_b64encode(((1 << 1023) + 643).to_bytes(128, "big"))
    .rstrip(b"=")
    .decode()
)


class ClientKeySeparationTests(unittest.TestCase):
    def write(self, root: pathlib.Path, name: str, body: str) -> pathlib.Path:
        path = root / name
        path.write_text(body, encoding="utf-8")
        return path

    def test_multiline_ed25519_es256_and_rs256_keys_are_structurally_parsed(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            registration = self.write(
                root,
                "client.yaml",
                f"""clientId: example
keys:
  - kty: OKP
    crv: Ed25519
    alg: EdDSA
    kid: ed-key
    x: {ED25519_X}
  - kty: EC
    crv: P-256
    alg: ES256
    kid: ec-key
    x: {P256_X}
    y: {P256_Y}
  - kty: RSA
    alg: RS256
    kid: rsa-key
    n: {RSA_N}
    e: AQAB
""",
            )
            seen: dict[str, pathlib.Path] = {}
            check_client_file(registration, seen)
            self.assertEqual(len(seen), 3)

    def test_malformed_yaml_and_public_material_are_rejected(self) -> None:
        cases = {
            "yaml.yaml": "keys: [\n",
            "coordinate.yaml": """keys:
  - kty: EC
    crv: P-256
    alg: ES256
    kid: broken
    x: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
    y: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
""",
            "duplicate-member.yaml": f"""keys:
  - kty: OKP
    crv: Ed25519
    kid: one
    kid: two
    x: {ED25519_X}
""",
        }
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            for name, body in cases.items():
                with self.subTest(name=name):
                    with self.assertRaises(CheckError):
                        check_client_file(self.write(root, name, body), {})

    def test_private_members_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = self.write(
                pathlib.Path(directory),
                "private.yaml",
                f"""keys:
  - kty: OKP
    crv: Ed25519
    alg: EdDSA
    kid: private
    x: {ED25519_X}
    d: {ED25519_X}
""",
            )
            with self.assertRaisesRegex(CheckError, "private key material"):
                check_client_file(path, {})

    def test_reused_material_is_rejected_across_files_and_within_one_file(self) -> None:
        key = f"""kty: OKP
    crv: Ed25519
    alg: EdDSA
    x: {ED25519_X}"""
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            first = self.write(
                root, "first.yaml", f"keys:\n  - {key}\n    kid: first\n"
            )
            second = self.write(
                root, "second.yaml", f"keys:\n  - {key}\n    kid: second\n"
            )
            seen: dict[str, pathlib.Path] = {}
            check_client_file(first, seen)
            with self.assertRaisesRegex(CheckError, "public key material reused"):
                check_client_file(second, seen)

            within = self.write(
                root,
                "within.yaml",
                f"keys:\n  - {key}\n    kid: one\n  - {key}\n    kid: two\n",
            )
            with self.assertRaisesRegex(CheckError, "public key material reused"):
                check_client_file(within, {})


if __name__ == "__main__":
    unittest.main()
