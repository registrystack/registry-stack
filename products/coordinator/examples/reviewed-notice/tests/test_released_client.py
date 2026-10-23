import hashlib
import importlib.util
from pathlib import Path
import unittest

source = Path(__file__).resolve().parents[1] / "released_client.py"
spec = importlib.util.spec_from_file_location("released_client", source)
client = importlib.util.module_from_spec(spec)
spec.loader.exec_module(client)


class InputTests(unittest.TestCase):
    def test_projection_matches_the_existing_rust_helper_contract(self):
        fields = {
            "applicantName": "Amina Example",
            "benefitProgram": "Permit renewal",
            "requestedAmount": 1200,
            "email": "excluded@example.org",
        }
        prepared = client.input_from_record(
            {
                "meta": {"entityTypeIdentifier": "application"},
                "data": {
                    "recordIdentifier": "00000000-0000-4000-8000-000000000001",
                    "revisionIdentifier": "r1",
                    "domainData": fields,
                },
            },
            "00000000-0000-4000-8000-000000000001",
        )
        canonical = b'{"applicantName":"Amina Example","benefitProgram":"Permit renewal","requestedAmount":1200}'
        self.assertEqual(
            prepared["applicationDigest"],
            "sha256:" + hashlib.sha256(canonical).hexdigest(),
        )
        self.assertNotIn("email", str(prepared))

    def test_identity_and_projection_refusals_are_value_free(self):
        value = {
            "meta": {"entityTypeIdentifier": "application"},
            "data": {
                "recordIdentifier": "one",
                "revisionIdentifier": "r1",
                "domainData": {
                    "applicantName": "canary-name",
                    "benefitProgram": "Permit",
                    "requestedAmount": 1,
                },
            },
        }
        with self.assertRaisesRegex(ValueError, "identity"):
            client.input_from_record(value, "other")
        value["data"]["recordIdentifier"] = "other"
        value["data"]["domainData"]["requestedAmount"] = True
        with self.assertRaises(ValueError) as error:
            client.input_from_record(value, "other")
        self.assertNotIn("canary-name", str(error.exception))
