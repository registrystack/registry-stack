import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from prepare_local import PrepareError, database_password, postgres_manifest, unchanged


class LocalInputsTest(unittest.TestCase):
    def test_database_credentials_only_name_the_local_role_and_database(self):
        expected = "registry-postgres.directory.svc.cluster.local"
        url = f"postgresql://registry_runtime:safe%2Bexample@{expected}:5432/registry_breg"
        self.assertEqual(database_password(url, "registry_runtime", "directory"), "safe+example")
        for malformed in (
            url.replace(expected, "another-db.example.org"),
            url.replace("registry_runtime", "postgres"),
            url.replace("registry_breg", "another_database"),
            url + "?sslmode=disable",
            url.replace("safe%2Bexample", "encoded%0Anewline"),
        ):
            with self.subTest(malformed=malformed), self.assertRaises(PrepareError):
                database_password(malformed, "registry_runtime", "directory")

    def test_input_replay_requires_the_same_immutable_object_data(self):
        desired = {"kind": "Secret", "type": "Opaque", "immutable": True, "data": {"key": "Yg=="}}
        self.assertTrue(unchanged({**desired, "metadata": {"resourceVersion": "8"}}, desired))
        self.assertFalse(unchanged({**desired, "immutable": False}, desired))
        self.assertFalse(unchanged({**desired, "data": {"key": "YQ=="}}, desired))

    def test_postgres_tls_renewal_changes_only_the_named_secret(self):
        original = postgres_manifest("registry-postgres-tls")
        renewed = postgres_manifest("registry-postgres-tls-v2")
        self.assertEqual(renewed.replace("registry-postgres-tls-v2", "registry-postgres-tls"), original)
        self.assertIn("secretName: registry-postgres-tls-v2", renewed)
