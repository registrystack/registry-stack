#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0

"""Tests for the pure pieces of the Scheduling demo support module.

Run from the repository root:

    python3 -m unittest products/scheduling/demo/support/test_demo.py -v
"""

import base64
import json
import subprocess
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import demo  # noqa: E402


class B64UrlTest(unittest.TestCase):
    def test_encoding_drops_padding_and_keeps_url_safety(self):
        self.assertEqual(demo.b64url(b"\xff"), "_w")
        self.assertEqual(demo.b64url(b"ab"), "YWI")
        self.assertEqual(demo.b64url(b"abc"), "YWJj")


class RsaJwkTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.key = demo_key_path()
        subprocess.run(
            ["openssl", "genpkey", "-algorithm", "RSA",
             "-pkeyopt", "rsa_keygen_bits:2048", "-out", str(cls.key)],
            check=True, capture_output=True,
        )
        cls.public_der = subprocess.run(
            ["openssl", "rsa", "-in", str(cls.key), "-pubout", "-outform", "DER"],
            check=True, capture_output=True,
        ).stdout

    @classmethod
    def tearDownClass(cls):
        cls.key.unlink(missing_ok=True)

    def test_the_public_key_becomes_an_rs256_jwk(self):
        jwk = demo.rsa_public_jwk(self.public_der)
        self.assertEqual(jwk["kty"], "RSA")
        self.assertEqual(jwk["alg"], "RS256")
        self.assertEqual(jwk["use"], "sig")
        # A 2048-bit modulus is 256 bytes before encoding; e is the usual
        # 65537, which base64url-encodes to the well-known AQAB.
        modulus = base64.urlsafe_b64decode(jwk["n"] + "===")
        self.assertEqual(len(modulus), 256)
        self.assertEqual(jwk["e"], "AQAB")

    def test_a_non_sequence_document_is_refused(self):
        with self.assertRaises(ValueError):
            demo.rsa_public_jwk(b"\x02\x01\x00")


def demo_key_path() -> Path:
    import tempfile
    return Path(tempfile.gettempdir()) / "scheduling-demo-test-key.pem"


class MintTokenTest(unittest.TestCase):
    def test_the_header_is_an_rfc9068_access_token(self):
        def signer(data):
            self.assertEqual(data.count(b"."), 1)
            return b"signature"

        token = demo.mint_token(signer, {"iss": "https://issuer.test", "sub": "s"})
        header, payload, signature = token.split(".")
        decoded_header = json.loads(base64.urlsafe_b64decode(header + "==="))
        decoded_payload = json.loads(base64.urlsafe_b64decode(payload + "==="))
        self.assertEqual(decoded_header, {"alg": "RS256", "typ": "at+jwt", "kid": demo.DEMO_KEY_ID})
        self.assertEqual(signature, demo.b64url(b"signature"))
        self.assertEqual(decoded_payload["iss"], "https://issuer.test")
        self.assertEqual(decoded_payload["sub"], "s")


class CallerClaimsTest(unittest.TestCase):
    def test_a_reader_carries_scopes_and_no_grant(self):
        claims = demo.caller_claims("demo-reader", "reader-subject", scopes=["scheduling-read"])
        self.assertEqual(claims["registry_scopes"], ["scheduling-read"])
        self.assertEqual(claims["registry_actor_kind"], "service")
        self.assertNotIn("registry_grant_bounds", claims)

    def test_a_booker_carries_a_complete_scheduling_grant(self):
        claims = demo.caller_claims("demo-booker-a", "booker-subject", grant=True, now=1_000_000)
        self.assertEqual(claims["registry_grant_client"], "demo-booker-a")
        self.assertEqual(claims["registry_grant_resource"], demo.DEMO_AUDIENCE)
        self.assertEqual(claims["registry_grant_exp"], 1_000_000 + 3600)
        self.assertEqual(claims["registry_purpose"], "registry-update")
        self.assertEqual(claims["registry_approver"], "demo-approver")
        bounds = claims["registry_grant_bounds"]
        self.assertEqual(bounds["type"], "scheduling")
        locations = {permission["location"] for permission in bounds["permissions"]}
        self.assertEqual(locations, {"bangkok-counter", "new-york-hall"})


class AdmissionBodyTest(unittest.TestCase):
    def test_the_body_names_its_caller_as_the_duplicate_key(self):
        body = demo.admission_body(demo.BANGKOK_OFFERING, demo.BANGKOK_HOLD_START, 7, "demo-hold")
        self.assertEqual(body["offering"], demo.BANGKOK_OFFERING)
        self.assertEqual(body["start"], demo.BANGKOK_HOLD_START)
        self.assertEqual(body["duplicateKey"], "demo-hold")
        self.assertEqual(body["policyRevision"], 7)
        self.assertEqual(body["party"], {"recipients": 1, "attendees": 1})
        self.assertEqual(body["capabilities"], [])
        self.assertEqual(body["prerequisites"], [])


class HoldTtlTest(unittest.TestCase):
    def test_the_demo_policy_ttl_is_shortened_exactly_once(self):
        policy = "holdPolicy:\n  ttlMinutes: 5\n  maxPerCaller: 3\n"
        self.assertEqual(demo.shorten_hold_ttl(policy),
                         "holdPolicy:\n  ttlMinutes: 1\n  maxPerCaller: 3\n")

    def test_an_unexpected_template_is_refused_rather_than_silently_kept(self):
        with self.assertRaises(ValueError):
            demo.shorten_hold_ttl("holdPolicy:\n  ttlMinutes: 9\n")


class DemoRecordsTest(unittest.TestCase):
    def test_the_records_document_carries_one_station_per_pool(self):
        import re
        members = re.findall(r"resourceId: (\S+)", demo.DEMO_RECORDS)
        self.assertEqual(members, ["station-1", "hall-station-1"])
        # The fold-day closure the AT-19 grid assertions depend on.
        self.assertIn('date: "2026-11-01"', demo.DEMO_RECORDS)
        self.assertIn("kind: closure", demo.DEMO_RECORDS)


class RuntimeConfigTest(unittest.TestCase):
    def test_the_runtime_config_pins_every_required_block(self):
        config = demo.runtime_config(
            Path("/run/project"), Path("/run/secrets"), Path("/run/audit"), 8105, None
        )
        for required in (
            "apiVersion: registry.registrystack.org/scheduling-runtime/v1alpha1",
            "kind: SchedulingRuntimeConfig",
            "root: /run/project",
            "bind: 127.0.0.1:8105",
            "tlsTermination: development-loopback",
            "root: /run/secrets",
            "runtimeUrlRef: secret:file/db-url",
            "migrationUrlRef: secret:file/db-url",
            f"issuer: {demo.DEMO_ISSUER}",
            f"audience: {demo.DEMO_AUDIENCE}",
            "kind: static",
            "documentRef: secret:file/jwks",
            "path: /run/audit",
            "hashKeyRef: secret:file/audit-key",
        ):
            self.assertIn(required, config)
        self.assertNotIn("trustedRootCertificateRef", config)

    def test_the_database_trust_root_is_named_when_present(self):
        config = demo.runtime_config(
            Path("/run/project"), Path("/run/secrets"), Path("/run/audit"), 8105,
            Path("/run/secrets/db-root-ca"),
        )
        self.assertIn(
            "trustedRootCertificateRef: secret:file/db-root-ca",
            config,
        )

    def test_the_audit_path_names_the_journal_file(self):
        config = demo.runtime_config(
            Path("/run/project"), Path("/run/secrets"), Path("/run/audit/audit.jsonl"), 8105, None
        )
        self.assertIn("path: /run/audit/audit.jsonl", config)


class BangkokSpacingTest(unittest.TestCase):
    def test_the_committed_bangkok_bookings_clear_each_others_buffers(self):
        starts = [
            demo.parse_instant(demo.BANGKOK_RACE_START),
            demo.parse_instant(demo.BANGKOK_HOLD_START),
            demo.parse_instant(demo.BANGKOK_REPLAY_START),
        ]
        for earlier, later in zip(sorted(starts), sorted(starts)[1:]):
            # The offering buffers five minutes each side of a 30-minute
            # booking, so two committed bookings need more than a slot's
            # width between their starts to leave the station free.
            self.assertGreaterEqual((later - earlier).total_seconds(), 3600)
        for value in starts:
            self.assertEqual(value.minute % 30, 0)


class FoldDayExpectationsTest(unittest.TestCase):
    def test_the_pinned_grid_is_thirty_minutes_from_the_moved_anchor(self):
        starts = [demo.parse_instant(value) for value in demo.FOLD_SERVED_SLOTS]
        self.assertEqual(starts[0], demo.parse_instant(demo.FOLD_FIRST_SLOT))
        for earlier, later in zip(starts, starts[1:]):
            self.assertEqual((later - earlier).total_seconds(), 1800)
        # The wall-clock match the scenario refuses is not on the grid.
        refused = demo.parse_instant(demo.FOLD_UNSERVED_START)
        self.assertNotIn(refused, starts)


if __name__ == "__main__":
    unittest.main()
