#!/usr/bin/env python3
"""Focused tests for credential commitment tooling."""

from __future__ import annotations

import os
import subprocess
import sys
import unittest
from pathlib import Path

SCRIPT_PATH = Path(__file__).with_name("credential-commitment.py")


class CredentialCommitmentTest(unittest.TestCase):
    def run_script(
        self,
        *args: str,
        env: dict[str, str] | None = None,
    ) -> subprocess.CompletedProcess[str]:
        command_env = os.environ.copy()
        if env is not None:
            command_env.update(env)
        return subprocess.run(
            [sys.executable, str(SCRIPT_PATH), *args],
            check=False,
            env=command_env,
            text=True,
            capture_output=True,
        )

    def test_notary_api_key_fixed_vector(self) -> None:
        raw = "notary-api-key-fixture"
        fingerprint = (
            "sha256:"
            "768a5e740400fbab0ea42d185b3013b7ff4139db77f02112b7e8023b6840e71e"
        )
        commitment = (
            "sha256:"
            "e07fecaa013f1e460b183f7d941c4e2a380110fa08b5eb9a4261f7fd6d84949b"
        )

        fp_result = self.run_script(
            "fingerprint",
            "--raw-env",
            "RAW_NOTARY_API_KEY",
            env={"RAW_NOTARY_API_KEY": raw},
        )
        self.assertEqual(fp_result.returncode, 0, fp_result.stderr)
        self.assertEqual(fp_result.stdout, f"{fingerprint}\n")

        commitment_result = self.run_script(
            "commitment",
            "--product",
            "registry-notary",
            "--credential-type",
            "api_key",
            "--credential-id",
            "dhis2_evidence_client",
            "--fingerprint",
            fingerprint,
        )
        self.assertEqual(commitment_result.returncode, 0, commitment_result.stderr)
        self.assertEqual(commitment_result.stdout, f"{commitment}\n")

        pair_result = self.run_script(
            "env-pair",
            "--product",
            "registry-notary",
            "--credential-type",
            "api_key",
            "--credential-id",
            "dhis2_evidence_client",
            "--raw-env",
            "RAW_NOTARY_API_KEY",
            env={"RAW_NOTARY_API_KEY": raw},
        )
        self.assertEqual(pair_result.returncode, 0, pair_result.stderr)
        self.assertEqual(
            pair_result.stdout,
            "\n".join(
                [
                    f"RAW_NOTARY_API_KEY_HASH={fingerprint}",
                    f"RAW_NOTARY_API_KEY_COMMITMENT={commitment}",
                    "",
                ]
            ),
        )

    def test_notary_bearer_token_fixed_vector(self) -> None:
        result = self.run_script(
            "env-pair",
            "--product",
            "registry-notary",
            "--credential-type",
            "bearer_token",
            "--credential-id",
            "dhis2_evidence_client",
            "--raw-env",
            "RAW_NOTARY_BEARER_TOKEN",
            env={"RAW_NOTARY_BEARER_TOKEN": "notary-bearer-token-fixture"},
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            result.stdout,
            "\n".join(
                [
                    "RAW_NOTARY_BEARER_TOKEN_HASH="
                    "sha256:8a56007ccf5e455a408af4634b38f24272cd3eeb7d149a900935a136891149e3",
                    "RAW_NOTARY_BEARER_TOKEN_COMMITMENT="
                    "sha256:2fc0e5fbd41675ae920bf0874a1686187135f73abad88448dd264818f0a56803",
                    "",
                ]
            ),
        )

    def test_relay_api_key_fixed_vector(self) -> None:
        result = self.run_script(
            "env-pair",
            "--product",
            "registry-relay",
            "--credential-type",
            "api_key",
            "--credential-id",
            "health_metadata_client",
            "--raw-env",
            "RAW_RELAY_API_KEY",
            env={"RAW_RELAY_API_KEY": "relay-api-key-fixture"},
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            result.stdout,
            "\n".join(
                [
                    "RAW_RELAY_API_KEY_HASH="
                    "sha256:3234da03c4bc49ebab2a458c9a5e55036a1e5b6d9f58621d152499242276e76f",
                    "RAW_RELAY_API_KEY_COMMITMENT="
                    "sha256:486f4de7246e413e9f51e70e4ea7851ffbd3d507d55cb5f1976c22def3dd77e3",
                    "",
                ]
            ),
        )

    def test_invalid_inputs_fail_without_stdout(self) -> None:
        cases = [
            (
                "commitment",
                "--product",
                "registry-unknown",
                "--credential-type",
                "api_key",
                "--credential-id",
                "dhis2_evidence_client",
                "--fingerprint",
                "sha256:" + "0" * 64,
            ),
            (
                "commitment",
                "--product",
                "registry-relay",
                "--credential-type",
                "bearer_token",
                "--credential-id",
                "health_metadata_client",
                "--fingerprint",
                "sha256:" + "0" * 64,
            ),
            (
                "commitment",
                "--product",
                "registry-notary",
                "--credential-type",
                "api_key",
                "--credential-id",
                "dhis2_evidence_client",
                "--fingerprint",
                "sha256:" + "g" * 64,
            ),
            ("fingerprint", "--raw-env", "1_BAD_ENV_NAME"),
            ("fingerprint", "--raw-env", "MISSING_RAW_SECRET"),
        ]
        for args in cases:
            with self.subTest(args=args):
                result = self.run_script(*args)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(result.stdout, "")

    def test_env_pair_does_not_emit_raw_secret(self) -> None:
        raw_secret = "raw-secret-that-must-not-appear"
        result = self.run_script(
            "env-pair",
            "--product",
            "registry-notary",
            "--credential-type",
            "api_key",
            "--credential-id",
            "dhis2_evidence_client",
            "--raw-env",
            "RAW_SECRET",
            env={"RAW_SECRET": raw_secret},
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        combined_output = result.stdout + result.stderr
        self.assertNotIn(raw_secret, combined_output)
        self.assertIn("RAW_SECRET_HASH=sha256:", result.stdout)
        self.assertIn("RAW_SECRET_COMMITMENT=sha256:", result.stdout)

        invalid_result = self.run_script(
            "env-pair",
            "--product",
            "registry-unknown",
            "--credential-type",
            "api_key",
            "--credential-id",
            "dhis2_evidence_client",
            "--raw-env",
            "RAW_SECRET",
            env={"RAW_SECRET": raw_secret},
        )
        self.assertNotEqual(invalid_result.returncode, 0)
        self.assertNotIn(raw_secret, invalid_result.stdout + invalid_result.stderr)


if __name__ == "__main__":
    unittest.main()
