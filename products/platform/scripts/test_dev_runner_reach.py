import tempfile
import unittest
from pathlib import Path

from check_dev_runner_reach import dependency_violations, source_violations


def metadata(package, dependency, kind=None):
    return {
        "workspace_members": ["host"],
        "packages": [
            {"id": "host", "name": package, "dependencies": [
                {"name": dependency, "kind": kind, "optional": True},
            ]},
        ],
    }


class DevRunnerReachTests(unittest.TestCase):
    def test_approved_hosts(self):
        for package, dependency in (
            ("registry-discoveryctl", "registry-rstack-dev"),
            ("registry-adapter-connectors", "registry-platform-testing"),
            ("registry-rstack", "registry-thunderid-tooling"),
        ):
            with self.subTest(package=package):
                self.assertEqual(dependency_violations(metadata(package, dependency)), [])

    def test_optional_normal_dependencies_are_checked(self):
        for dependency in (
            "registry-rstack-dev", "registry-platform-testing", "registry-thunderid-tooling"
        ):
            with self.subTest(dependency=dependency):
                failures = dependency_violations(metadata("registry-unapproved", dependency))
                self.assertEqual(len(failures), 1)
                self.assertIn(dependency, failures[0])
                self.assertIn("registry-unapproved", failures[0])

    def test_dev_and_build_dependencies_are_outside_the_gate(self):
        for kind in ("dev", "build"):
            self.assertEqual(
                dependency_violations(metadata("registry-unapproved", "registry-rstack-dev", kind)),
                [],
            )

    def test_runtime_references_are_limited_to_named_files(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for crate, approved in (
                ("registry-render", "bundle.rs"),
                ("registry-coordinator", "project_check.rs"),
            ):
                source = root / "crates" / crate / "src"
                source.mkdir(parents=True)
                (source / approved).write_text("registry_rstack_dev::some_function();\n")
                (source / "serve.rs").write_text("registry_rstack_dev::some_function();\n")
            failures = source_violations(root)
            self.assertEqual(len(failures), 2)
            self.assertTrue(all("serve.rs:1" in failure for failure in failures))
