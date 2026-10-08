#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0

import importlib.util
import json
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("registry_editor_configure", ROOT / "editors/configure.py")
configure = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(configure)


class ConfigureTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.workspace = Path(self.temp.name)

    def project(self, name, marker, source=None):
        path = self.workspace / name
        path.mkdir()
        if source is None:
            (path / marker).write_text("schemaVersion: test\n")
        else:
            shutil.copyfile(ROOT / source, path / marker)
        return path

    def test_editor_versions_match_the_hosted_server(self):
        expected = configure.workspace_version()
        vscode = json.loads((ROOT / "editors/vscode/package.json").read_text())
        self.assertEqual(vscode["version"], expected)
        for relative in ("editors/zed/Cargo.toml", "editors/zed/extension.toml"):
            with self.subTest(manifest=relative):
                version = re.search(r'^version\s*=\s*"([^"]+)"', (ROOT / relative).read_text(), re.MULTILINE)
                self.assertIsNotNone(version)
                self.assertEqual(version.group(1), expected)

    def test_breg_schema_snapshots_tasks_and_idempotent_merge(self):
        project = self.project(
            "breg",
            "registry.yaml",
            "products/breg/fixtures/organization-membership-access/registry.yaml",
        )
        settings_path = self.workspace / ".vscode/settings.json"
        settings_path.parent.mkdir()
        settings_path.write_text('{"editor.tabSize": 4}\n')
        configure.configure("breg", project, self.workspace, None)
        settings = json.loads(settings_path.read_text())
        self.assertEqual(settings["editor.tabSize"], 4)
        schemas = settings["yaml.schemas"]
        self.assertEqual(len(schemas), 3)
        project_schema = (project / ".registry-stack-editor/schemas/registry-project.schema.json").as_uri()
        self.assertEqual(schemas[project_schema], [str(project / "registry.yaml")])
        zed = json.loads((self.workspace / ".zed/settings.json").read_text())
        self.assertEqual(zed["lsp"]["yaml-language-server"]["settings"]["yaml"]["schemas"], schemas)
        vscode_tasks = json.loads((self.workspace / ".vscode/tasks.json").read_text())["tasks"]
        zed_tasks = json.loads((self.workspace / ".zed/tasks.json").read_text())
        self.assertEqual(vscode_tasks[0]["args"], ["check", str(project)])
        self.assertEqual(zed_tasks[0]["args"], ["check", str(project)])
        self.assertEqual(vscode_tasks[0]["type"], "process")
        snapshots = {
            path: path.read_bytes()
            for path in (
                settings_path,
                self.workspace / ".zed/settings.json",
                self.workspace / ".vscode/tasks.json",
                self.workspace / ".zed/tasks.json",
                project / ".registry-stack-editor/state.json",
            )
        }
        configure.configure("breg", project, self.workspace, None)
        self.assertEqual({path: path.read_bytes() for path in snapshots}, snapshots)

    def test_refuses_jsonc_before_writing_anything(self):
        project = self.project("casework", "casework.yaml")
        settings_path = self.workspace / ".vscode/settings.json"
        settings_path.parent.mkdir()
        settings_path.write_text('{"editor.tabSize": 4, // keep this comment\n}\n')
        with self.assertRaisesRegex(configure.SetupError, "not strict JSON"):
            configure.configure("casework", project, self.workspace, None)
        self.assertEqual(
            settings_path.read_text(), '{"editor.tabSize": 4, // keep this comment\n}\n'
        )
        self.assertFalse((project / ".registry-stack-editor").exists())
        self.assertFalse((self.workspace / ".zed").exists())

    def test_manifest_and_oid_markers_require_safe_existing_yaml(self):
        project = self.project("manifest", "metadata.yaml")
        for document in ("../outside.yaml", "/absolute.yaml", "nested\\file.yaml", "absent.yaml"):
            with self.subTest(document=document):
                with self.assertRaises(configure.SetupError):
                    configure.configure("manifest", project, self.workspace, document)
        configure.configure("manifest", project, self.workspace, "metadata.yaml")
        marker = json.loads((project / ".registry-stack-editor/project.json").read_text())
        self.assertEqual(marker, {"product": "manifest", "document": "metadata.yaml"})
        task = json.loads((self.workspace / ".zed/tasks.json").read_text())[0]
        self.assertEqual(task["args"], ["validate", str(project / "metadata.yaml")])

        oid = self.project("oid", "issuer.yaml")
        with self.assertRaisesRegex(configure.SetupError, "requires --document"):
            configure.configure("evidence-oid4vci", oid, self.workspace, None)
        configure.configure("evidence-oid4vci", oid, self.workspace, "issuer.yaml")
        marker = json.loads((oid / ".registry-stack-editor/project.json").read_text())
        self.assertEqual(marker, {"product": "evidence-oid4vci", "document": "issuer.yaml"})
        self.assertEqual(len(json.loads((self.workspace / ".zed/tasks.json").read_text())), 1)

    def test_marker_only_setup_preserves_unrelated_jsonc(self):
        project = self.project("wallet", "issuer.yaml")
        originals = {}
        for editor in ("vscode", "zed"):
            for name in ("settings.json", "tasks.json"):
                path = self.workspace / f".{editor}" / name
                path.parent.mkdir(exist_ok=True)
                content = '{ // preserved workspace comment\n}\n'
                path.write_text(content)
                originals[path] = content
        configure.configure("evidence-oid4vci", project, self.workspace, "issuer.yaml")
        self.assertEqual({path: path.read_text() for path in originals}, originals)
        marker = json.loads((project / ".registry-stack-editor/project.json").read_text())
        self.assertEqual(marker, {"product": "evidence-oid4vci", "document": "issuer.yaml"})

    def test_task_only_setup_preserves_unrelated_settings_jsonc(self):
        project = self.project("manifest", "metadata.yaml")
        settings = self.workspace / ".vscode/settings.json"
        settings.parent.mkdir()
        content = '{ // preserved workspace comment\n}\n'
        settings.write_text(content)
        with patch.dict(configure.SCHEMAS, {"manifest": ()}):
            configure.configure("manifest", project, self.workspace, "metadata.yaml")
        self.assertEqual(settings.read_text(), content)
        tasks = json.loads((self.workspace / ".vscode/tasks.json").read_text())["tasks"]
        self.assertEqual(tasks[0]["command"], "registry-manifest")

    def test_refuses_modified_managed_schema_and_task(self):
        project = self.project("messaging", "messaging.yaml")
        configure.configure("messaging", project, self.workspace, None)
        schema = project / ".registry-stack-editor/schemas/runtime.schema.json"
        schema.write_text("{}\n")
        with self.assertRaisesRegex(configure.SetupError, "managed schema was edited"):
            configure.configure("messaging", project, self.workspace, None)
        schema.write_bytes((ROOT / "products/messaging/generated/runtime/runtime.schema.json").read_bytes())
        tasks_path = self.workspace / ".zed/tasks.json"
        tasks = json.loads(tasks_path.read_text())
        tasks[0]["args"] = ["wrong"]
        tasks_path.write_text(json.dumps(tasks))
        with self.assertRaisesRegex(configure.SetupError, "managed task was edited"):
            configure.configure("messaging", project, self.workspace, None)

    def test_refuses_symlinked_editor_directory_and_workspace_change(self):
        project = self.project("casework", "casework.yaml")
        external = self.workspace / "external"
        external.mkdir()
        (self.workspace / ".vscode").symlink_to(external, target_is_directory=True)
        with self.assertRaisesRegex(configure.SetupError, "symbolic link"):
            configure.configure("casework", project, self.workspace, None)
        self.assertEqual(list(external.iterdir()), [])
        (self.workspace / ".vscode").unlink()

        configure.configure("casework", project, self.workspace, None)
        with self.assertRaisesRegex(configure.SetupError, "state does not match"):
            configure.configure("casework", project, project, None)

    def test_two_products_share_workspace_without_schema_or_task_collision(self):
        breg = self.project("breg", "registry.yaml")
        casework = self.project("casework", "casework.yaml")
        settings_path = self.workspace / ".vscode/settings.json"
        settings_path.parent.mkdir()
        unrelated_uri = (self.workspace / "unrelated/.editor/schemas/registry.schema.json").as_uri()
        settings_path.write_text(
            json.dumps({"yaml.schemas": {unrelated_uri: [str(self.workspace / "unrelated/registry.yaml")]}})
        )
        configure.configure("breg", breg, self.workspace, None)
        configure.configure("casework", casework, self.workspace, None)
        configure.configure("breg", breg, self.workspace, None)
        settings = json.loads(settings_path.read_text())
        self.assertEqual(len(settings["yaml.schemas"]), 5)
        self.assertEqual(settings["yaml.schemas"][unrelated_uri], [str(self.workspace / "unrelated/registry.yaml")])
        tasks = json.loads((self.workspace / ".vscode/tasks.json").read_text())["tasks"]
        self.assertEqual(len(tasks), 2)
        self.assertEqual({task["command"] for task in tasks}, {"bregctl", "caseworkctl"})

    def test_render_bundle_maps_its_manifest_label_tables_and_runtime(self):
        bundle = self.project("render", "manifest.yaml", "products/render/bundles/receipt/manifest.yaml")
        configure.configure("render", bundle, self.workspace, None)
        schemas = json.loads((self.workspace / ".vscode/settings.json").read_text())["yaml.schemas"]
        managed = bundle / ".registry-stack-editor/schemas"
        self.assertEqual(
            schemas,
            {
                (managed / "bundle.schema.json").as_uri(): [str(bundle / "manifest.yaml")],
                (managed / "labels.schema.json").as_uri(): [str(bundle / "labels/*.yaml")],
                (managed / "runtime.schema.json").as_uri(): [str(bundle / "runtime.yaml")],
            },
        )
        self.assertEqual(
            (managed / "labels.schema.json").read_bytes(),
            (ROOT / "products/render/schemas/labels.schema.json").read_bytes(),
        )

    def test_manifest_maps_its_document_and_profile_descriptors(self):
        project = self.project(
            "manifest",
            "catalog.metadata.yaml",
            "products/manifest/profiles/example-benefits-sync/fixtures/metadata.yaml",
        )
        configure.configure("manifest", project, self.workspace, "catalog.metadata.yaml")
        schemas = json.loads((self.workspace / ".vscode/settings.json").read_text())["yaml.schemas"]
        managed = project / ".registry-stack-editor/schemas"
        self.assertEqual(
            schemas,
            {
                (managed / "metadata.schema.json").as_uri(): [str(project / "catalog.metadata.yaml")],
                (managed / "profile.schema.json").as_uri(): [str(project / "**/profile.yaml")],
            },
        )
        self.assertEqual(
            (managed / "profile.schema.json").read_bytes(),
            (ROOT / "products/manifest/schemas/profile.schema.json").read_bytes(),
        )

    def test_platform_maps_its_task_connection_file(self):
        project = self.project(
            "platform", "task-connection.yaml", "products/platform/examples/task-connection.yaml"
        )
        configure.configure("platform", project, self.workspace, None)
        schemas = json.loads((self.workspace / ".vscode/settings.json").read_text())["yaml.schemas"]
        managed = project / ".registry-stack-editor/schemas"
        self.assertEqual(
            schemas,
            {(managed / "task-connection.schema.json").as_uri(): [str(project / "task-connection.yaml")]},
        )
        self.assertEqual(
            (managed / "task-connection.schema.json").read_bytes(),
            (ROOT / "products/platform/schemas/task-connection.schema.json").read_bytes(),
        )
        task = json.loads((self.workspace / ".vscode/tasks.json").read_text())["tasks"][0]
        self.assertEqual(task["command"], "evidencectl")
        self.assertEqual(task["options"]["cwd"], str(project))

    def test_breg_services_map_their_runtime_schemas_beside_each_other(self):
        services = {
            "breg-mcp": ("gateway", "products/breg/generated/mcp-runtime/mcp-runtime.schema.json"),
            "breg-review": ("review", "products/breg/generated/review-runtime/review-runtime.schema.json"),
        }
        projects = {}
        for product, (name, _) in services.items():
            example = f"products/breg/examples/{product.removeprefix('breg-')}-runtime/runtime.yaml"
            projects[product] = self.project(name, "runtime.yaml", example)
            configure.configure(product, projects[product], self.workspace, None)
        settings = json.loads((self.workspace / ".vscode/settings.json").read_text())
        tasks = json.loads((self.workspace / ".vscode/tasks.json").read_text())["tasks"]
        self.assertEqual(len(settings["yaml.schemas"]), 2)
        self.assertEqual({task["command"] for task in tasks}, set(services))
        for product, (_, source) in services.items():
            with self.subTest(product=product):
                project = projects[product]
                schema = project / ".registry-stack-editor/schemas" / Path(source).name
                self.assertEqual(schema.read_bytes(), (ROOT / source).read_bytes())
                self.assertEqual(settings["yaml.schemas"][schema.as_uri()], [str(project / "runtime.yaml")])
        with self.assertRaisesRegex(configure.SetupError, "breg-mcp project needs runtime.yaml"):
            configure.configure("breg-mcp", self.project("empty", "other.yaml"), self.workspace, None)

    def test_check_task_uses_product_cli_shape(self):
        project = self.workspace / "sample"
        document = project / "metadata.yaml"
        expected = {
            "breg": ["check", str(project)],
            "breg-mcp": ["--runtime-config", str(project / "runtime.yaml"), "check"],
            "breg-review": ["--runtime-config", str(project / "runtime.yaml"), "check"],
            "casework": ["check", str(project)],
            "scheduling": ["check", str(project)],
            "messaging": ["check", "--project", str(project)],
            "discovery": ["check", "--project", str(project)],
            "manifest": ["validate", str(document)],
            "render": ["check", "--bundle", str(project)],
            "evidence": ["check", str(project)],
            "platform": ["dev", "check", "task-connection.yaml"],
        }
        for product, args in expected.items():
            with self.subTest(product=product):
                vscode, zed = configure.task_for(product, project, document)
                self.assertEqual(vscode["args"], args)
                self.assertEqual(zed["args"], args)
                self.assertEqual(zed["cwd"], str(project))
        self.assertIsNone(configure.task_for("evidence-oid4vci", project, document))

    def test_hosting_cli_must_match_current_source_version(self):
        version = configure.workspace_version()
        with patch.object(configure.shutil, "which", return_value="/bin/evidencectl"):
            with patch.object(
                configure.subprocess,
                "run",
                return_value=subprocess.CompletedProcess([], 0, f"evidencectl {version}-dev\n", ""),
            ):
                self.assertEqual(configure.matching_cli("evidencectl"), "/bin/evidencectl")
            with patch.object(
                configure.subprocess,
                "run",
                return_value=subprocess.CompletedProcess([], 0, "evidencectl 0.2.0\n", ""),
            ):
                with self.assertRaisesRegex(configure.SetupError, "must report Registry Stack"):
                    configure.matching_cli("evidencectl")

    def test_evidence_forwards_workspace(self):
        evidence = self.project("evidence", "evidence-project.yaml")
        with patch.object(configure, "matching_cli", return_value="/bin/evidencectl"):
            with patch.object(configure.subprocess, "run", return_value=subprocess.CompletedProcess([], 0)) as run:
                configure.configure("evidence", evidence, self.workspace, None)
        run.assert_called_once_with(
            [
                "/bin/evidencectl",
                "tooling",
                "editor",
                str(evidence),
                "--workspace",
                str(self.workspace),
            ],
            check=False,
        )

    def test_command_line_configures_real_scheduling_example_in_shared_workspace(self):
        source = ROOT / "products/scheduling/examples/standalone-exact-time"
        project = self.workspace / "Scheduling project"
        shutil.copytree(source, project)
        result = subprocess.run(
            [
                sys.executable,
                str(ROOT / "editors/configure.py"),
                "scheduling",
                str(project),
                "--workspace",
                str(self.workspace),
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Configured Registry Stack scheduling", result.stdout)
        task = json.loads((self.workspace / ".zed/tasks.json").read_text())[0]
        self.assertEqual(task["args"], ["check", str(project)])
        settings = json.loads((self.workspace / ".vscode/settings.json").read_text())
        self.assertEqual(
            settings["yaml.schemas"][
                (project / ".registry-stack-editor/schemas/runtime.schema.json").as_uri()
            ],
            [str(project / "runtime.yaml"), str(project / "runtime.example.yaml")],
        )


if __name__ == "__main__":
    unittest.main()
