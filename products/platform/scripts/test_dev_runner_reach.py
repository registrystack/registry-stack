import tempfile
import unittest
from pathlib import Path

from check_dev_runner_reach import (
    ALLOWLIST,
    DEV_RUNNER,
    DEV_RUNNER_HOSTS,
    dependency_violations,
    source_violations,
)


def metadata(package, dependency, kind=None):
    return {
        "workspace_members": ["host"],
        "resolve": {"nodes": [{"id": "host", "deps": []}]},
        "packages": [
            {"id": "host", "name": package, "dependencies": [
                {"name": dependency, "kind": kind, "optional": True},
            ]},
        ],
    }


class DevRunnerReachTests(unittest.TestCase):
    def test_missing_resolution_graph_fails(self):
        graph = metadata("registry-adapter-job", "registry-platform-testing")
        del graph["resolve"]
        self.assertEqual(dependency_violations(graph), ["Cargo metadata has no dependency resolution graph."])

    def test_test_support_is_refused_in_the_default_closure(self):
        graph = metadata("registry-adapter-job", "registry-platform-testing")
        graph["packages"].append({
            "id": "testing", "name": "registry-platform-testing", "dependencies": [],
        })
        graph["resolve"]["nodes"][0]["deps"] = [
            {"pkg": "testing", "dep_kinds": [{"kind": None}]},
        ]
        graph["resolve"]["nodes"].append({"id": "testing", "deps": []})
        self.assertEqual(dependency_violations(graph), [])
        self.assertEqual(dependency_violations(graph, default_features=True), [
            "Test-support dependency enabled by default: registry-adapter-job -> registry-platform-testing",
        ])

    def test_approved_hosts(self):
        for package, dependency in (
            ("registry-discoveryctl", "registry-rstack-dev"),
            ("registry-adapter-connectors", "registry-platform-testing"),
            ("registry-rstack", "registry-thunderid-tooling"),
        ):
            with self.subTest(package=package):
                self.assertEqual(dependency_violations(metadata(package, dependency)), [])

    def test_hosts_are_the_runner_dependents_that_host_runs(self):
        self.assertIn("registry-cli-docs", ALLOWLIST[DEV_RUNNER])
        self.assertNotIn("registry-cli-docs", DEV_RUNNER_HOSTS)
        self.assertIn("registry-bregctl", DEV_RUNNER_HOSTS)
        self.assertLessEqual(DEV_RUNNER_HOSTS, set(ALLOWLIST[DEV_RUNNER]))

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

    def test_unapproved_crate_reaches_runner_through_approved_host(self):
        graph = metadata("registry-discoveryctl", "registry-rstack-dev")
        graph["workspace_members"].append("caller")
        graph["packages"].extend([
            {"id": "caller", "name": "registry-unapproved", "dependencies": []},
            {"id": "runner", "name": "registry-rstack-dev", "dependencies": []},
        ])
        graph["resolve"] = {"nodes": [
            {"id": "caller", "deps": [{"pkg": "host", "dep_kinds": [{"kind": None}]}]},
            {"id": "host", "deps": [{"pkg": "runner", "dep_kinds": [{"kind": None}]}]},
            {"id": "runner", "deps": []},
        ]}
        failures = dependency_violations(graph)
        self.assertEqual(len(failures), 1)
        self.assertIn("registry-unapproved -> registry-discoveryctl -> registry-rstack-dev", failures[0])

    def test_import_alias_and_extern_crate_are_runner_references(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "crates/registry-render/src"
            source.mkdir(parents=True)
            (source / "serve.rs").write_text(
                "use registry_rstack_dev as runner;\n"
                "extern crate registry_rstack_dev as dev;\n"
            )
            self.assertEqual(len(source_violations(root)), 2)


if __name__ == "__main__":
    unittest.main()
