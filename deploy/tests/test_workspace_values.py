import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from workspace_values import WorkspaceError, render_workspace


class WorkspaceValuesTest(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.addCleanup(self.folder.cleanup)
        self.root = Path(self.folder.name)
        (self.root / "workspace").mkdir()
        self.project = self.root / "registry.yaml"
        self.project.write_text("kind: BRegProject\n")
        self.file = self.root / "workspace/generated.json"
        self.index = {
            "apiVersion": "id.registrystack.org/formats/platform/workspace-generated/v1alpha1",
            "kind": "WorkspaceGenerated",
            "sourceVersion": "saved-1",
            "sourceHash": "a" * 64,
            "files": [{
                "path": self.project.name,
                "sha256": hashlib.sha256(self.project.read_bytes()).hexdigest(),
                "source": {"type": "product", "product": "breg", "items": ["records:contact"]},
            }],
        }
        self.file.write_text(json.dumps(self.index))
        self.bindings = {
            "workspaceSourceHash": self.index["sourceHash"],
            "breg": {"package": {"existingClaim": "approved-package"}},
        }

    def test_enables_the_saved_workspace_product_using_operator_bindings(self):
        result, extensions = render_workspace(self.root, self.bindings)
        self.assertIsNone(extensions)
        self.assertTrue(result["breg"]["enabled"])
        self.assertTrue(result["breg"]["serve"])
        self.assertEqual(result["breg"]["package"], {"existingClaim": "approved-package"})
        self.assertNotIn("workspaceSourceHash", result)
        self.assertNotIn("enabled", self.bindings["breg"])

    def test_refuses_changed_generated_bytes(self):
        self.project.write_text("changed\n")
        with self.assertRaisesRegex(WorkspaceError, "hash differs"):
            render_workspace(self.root, self.bindings)

    def test_refuses_bindings_for_another_saved_workspace(self):
        self.bindings["workspaceSourceHash"] = "b" * 64
        with self.assertRaisesRegex(WorkspaceError, "saved workspace"):
            render_workspace(self.root, self.bindings)

    def test_refuses_paths_outside_the_generated_files(self):
        self.index["files"][0]["path"] = "../outside"
        self.file.write_text(json.dumps(self.index))
        with self.assertRaisesRegex(WorkspaceError, "unsafe"):
            render_workspace(self.root, self.bindings)

    def test_refuses_enabling_an_unpublished_product(self):
        with self.assertRaisesRegex(WorkspaceError, "absent from"):
            render_workspace(self.root, self.bindings, ["casework"])

    def publish(self, relative, product, content):
        target = self.root / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content)
        self.index["files"].append({
            "path": relative,
            "sha256": hashlib.sha256(target.read_bytes()).hexdigest(),
            "source": {"type": "product", "product": product, "items": []},
        })
        self.file.write_text(json.dumps(self.index))

    def test_ignores_rstack_development_manifest(self):
        self.publish("dev.yaml", "rstack", "kind: RStackDev\n")
        result, _ = render_workspace(self.root, self.bindings)
        self.assertTrue(result["breg"]["enabled"])

    def test_compiles_a_separate_helm_release_from_indexed_endpoint_intent(self):
        self.publish("deployment/endpoints.json", "deployment", json.dumps({
            "extensions": {"endpoints": {"intake": {"path": "/extensions/intake"}}},
        }))
        self.bindings["extensions"] = {
            "namespace": "workspace-extensions",
            "publicHost": "service.example.test",
            "ingressClassName": "traefik",
            "ingressNamespace": "kube-system",
            "ingressPodLabels": {"app.kubernetes.io/name": "traefik"},
            "tlsSecretName": "service-tls",
            "imagePullSecrets": [{"name": "extension-images"}],
            "endpoints": {"intake": {"image": "ghcr.io/example/intake@sha256:" + "a" * 64, "port": 8080}},
        }
        products, extension = render_workspace(self.root, self.bindings)
        self.assertTrue(products["breg"]["serve"])
        self.assertNotIn("extensions", products)
        self.assertEqual(extension["global"]["imagePullSecrets"], [{"name": "extension-images"}])
        self.assertNotIn("imagePullSecrets", extension["extensions"])
        self.assertEqual(extension["extensions"]["namespace"], "workspace-extensions")
        self.assertEqual(extension["extensions"]["endpoints"]["intake"]["path"], "/extensions/intake")
        self.bindings["breg"]["ingress"] = {"enabled": True, "host": "service.example.test"}
        with self.assertRaisesRegex(WorkspaceError, "separate HTTPS hostname"):
            render_workspace(self.root, self.bindings)
        (self.root / "deployment/endpoints.json").write_text("{}\n")
        with self.assertRaisesRegex(WorkspaceError, "hash differs"):
            render_workspace(self.root, self.bindings)

    def test_refuses_unindexed_extensions(self):
        (self.root / "deployment").mkdir()
        (self.root / "deployment/endpoints.json").write_text("{}\n")
        with self.assertRaisesRegex(WorkspaceError, "generated file index"):
            render_workspace(self.root, self.bindings)


if __name__ == "__main__":
    unittest.main()
