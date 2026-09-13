import importlib.util
import json
import subprocess
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("demo", HERE / "demo.py")
DEMO = importlib.util.module_from_spec(SPEC)
assert SPEC.loader
SPEC.loader.exec_module(DEMO)
REPO = HERE.parents[3]

class DevPreparationTests(unittest.TestCase):
    def prepare(self, fixture: str):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        root.mkdir(mode=0o700, exist_ok=True)
        sources = {"household":"publicschema-household", "asset-site":"asset-site-placement", "asset-change-request":"asset-site-placement-change-requests"}
        DEMO.prepare_dev(root, REPO / "products/breg/acceptance" / sources.get(fixture, fixture), fixture)
        return root, json.loads((root / "project/dev-clients.yaml").read_text())

    def test_business_clients_use_private_key_dev_contract(self):
        root, document = self.prepare("business-establishments")
        self.assertEqual([c["id"] for c in document["clients"]], ["business-demo", "business-demo-no-purpose", "business-demo-viewer"])
        viewer = document["clients"][2]
        self.assertEqual(viewer["claims"]["business_code"], "BUSINESS-DEMO-001")
        registry = (root / "project/registry.yaml").read_text()
        self.assertIn("field: business-code\n            claim: business_code", registry)
        self.assertIn("operator-without-purpose-is-concealed", (root / "project/tests/journeys.yaml").read_text())
        self.assertEqual(document["clients"][1]["testBindings"][0]["stepId"], "operator-without-purpose-is-concealed")

    def test_each_fixture_has_one_explicit_client_per_persona_profile(self):
        expected = {"household": 3, "asset-site": 3, "asset-change-request": 6, "facility": 2, "inspection": 2}
        for fixture, count in expected.items():
            with self.subTest(fixture=fixture):
                _, document = self.prepare(fixture)
                self.assertEqual(len(document["clients"]), count)
                profiles = [c["accessProfiles"][0] for c in document["clients"]]
                variants = [c for c in document["clients"] if c.get("testBindings")]
                self.assertEqual(len(variants), len(profiles) - len(set(profiles)))
                self.assertTrue(all(c["scopes"] and c["claims"] for c in document["clients"]))

    def test_prepare_refuses_existing_output(self):
        root, _ = self.prepare("business-establishments")
        with self.assertRaises(FileExistsError):
            DEMO.prepare_dev(root, REPO / "products/breg/acceptance/business-establishments", "business-establishments")

    def test_launcher_refuses_existing_state_without_touching_it(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        state = Path(temporary.name) / "existing"
        state.mkdir()
        sentinel = state / "sentinel"
        sentinel.write_text("keep")
        result = subprocess.run(
            [str(REPO / "products/breg/demo/run.sh"), "--state-dir", str(state), "--smoke"],
            text=True,
            capture_output=True,
        )
        self.assertEqual(result.returncode, 2)
        self.assertEqual(sentinel.read_text(), "keep")
        self.assertIn("state path already exists", result.stderr)

if __name__ == "__main__":
    unittest.main()
