#!/usr/bin/env python3
"""Exercise CI event routing against real, isolated Git histories."""

from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import tempfile
import textwrap
import unittest

from ci_changes import SHARDS, Workspace, classify
from ci_event_routing import select_event


ROOT = Path(__file__).resolve().parents[2]


class EventRoutingTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.metadata = subprocess.run(
            ["cargo", "metadata", "--locked", "--no-deps", "--format-version", "1"],
            cwd=ROOT, check=True, capture_output=True, text=True,
        ).stdout
        cls.workspace = Workspace(json.loads(cls.metadata))

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.repo = Path(self.temporary.name)
        self.git("init", "-q", "-b", "main")
        self.git("config", "user.email", "ci-test@example.invalid")
        self.git("config", "user.name", "CI routing test")
        self.git("config", "commit.gpgsign", "false")
        self.base = self.commit("README.md")
        self.git("update-ref", "refs/remotes/origin/main", self.base)

    def git(self, *args: str) -> str:
        return subprocess.run(
            ["git", *args], cwd=self.repo, check=True, capture_output=True, text=True,
        ).stdout.strip()

    def commit(self, path: str, text: str = "fixture\n") -> str:
        target = self.repo / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text, encoding="utf-8")
        self.git("add", "--", path)
        self.git("commit", "-qm", "Add fixture")
        return self.git("rev-parse", "HEAD")

    def test_multi_commit_push_keeps_every_owner(self) -> None:
        paths = ("crates/registry-breg/src/lib.rs", "crates/registry-evidence/src/lib.rs")
        self.commit(paths[0])
        head = self.commit(paths[1])
        selection = select_event(self.repo, "push", {"before": self.base}, head)
        self.assertFalse(selection.full_sweep)
        self.assertEqual(set(selection.paths), set(paths))
        selected = classify(self.workspace, selection.paths)
        self.assertTrue(selected["breg_contracts"])
        self.assertTrue(selected["evidence_contracts"])
        self.assertEqual(selection.archive_base_ref, self.base)

    def test_merge_group_diff_uses_supplied_base_and_combined_head(self) -> None:
        paths = ("crates/registry-breg/src/lib.rs", "crates/registry-discovery/src/lib.rs")
        self.git("checkout", "-qb", "candidate")
        self.commit(paths[0])
        self.git("checkout", "-q", "main")
        self.commit(paths[1])
        self.git("merge", "--no-ff", "-qm", "Queue candidates", "candidate")
        head = self.git("rev-parse", "HEAD")
        selection = select_event(
            self.repo, "merge_group", {"merge_group": {"base_sha": self.base, "head_sha": head}},
            self.base,  # Event payload, not a stale fallback SHA, owns this head.
        )
        self.assertFalse(selection.full_sweep)
        self.assertEqual(set(selection.paths), set(paths))
        selected = classify(self.workspace, selection.paths)
        self.assertTrue(selected["breg_contracts"])
        self.assertTrue(selected["discovery_contracts"])

    def test_rename_and_delete_include_old_owners(self) -> None:
        old = "crates/registry-breg/src/moved.rs"
        deleted = "crates/registry-evidence/src/deleted.rs"
        self.commit(old)
        base = self.commit(deleted)
        destination = "crates/registry-discovery/src/moved.rs"
        (self.repo / destination).parent.mkdir(parents=True)
        self.git("mv", old, destination)
        self.git("rm", deleted)
        self.git("commit", "-qm", "Move and remove fixtures")
        selection = select_event(self.repo, "push", {"before": base}, self.git("rev-parse", "HEAD"))
        self.assertEqual(set(selection.paths), {old, deleted, destination})

    def test_missing_or_zero_base_and_missing_head_request_full_sweep(self) -> None:
        for base, head in (("0" * 40, self.base), ("f" * 40, self.base), (self.base, "f" * 40)):
            with self.subTest(base=base, head=head):
                selection = select_event(self.repo, "push", {"before": base}, head)
                self.assertTrue(selection.full_sweep)
                self.assertTrue(selection.archive_comparison_required)
                self.assertEqual(selection.archive_base_ref, self.base if base == self.base else "")
                outputs = classify(self.workspace, selection.paths, full_sweep=selection.full_sweep)
                self.assertTrue(outputs["docs_archives"])
                self.assertTrue(outputs["release_linux_node_clients"])

    def test_empty_diff_selects_no_product_work(self) -> None:
        selection = select_event(self.repo, "push", {"before": self.base}, self.base)
        self.assertFalse(selection.full_sweep)
        self.assertEqual(selection.paths, ())
        self.assertFalse(classify(self.workspace, selection.paths)["rust"])

    def test_divergent_valid_endpoints_use_net_changes(self) -> None:
        self.git("checkout", "-qb", "other")
        old = self.commit("crates/registry-breg/src/lib.rs")
        self.git("checkout", "-q", "main")
        head = self.commit("crates/registry-evidence/src/lib.rs")
        selection = select_event(self.repo, "push", {"before": old}, head)
        self.assertFalse(selection.full_sweep)
        self.assertEqual(len(selection.paths), 2)

    def test_pr_keeps_event_two_endpoint_comparison(self) -> None:
        head = self.commit("crates/registry-breg/src/lib.rs")
        selection = select_event(self.repo, "pull_request", {
            "pull_request": {"base": {"sha": self.base}, "head": {"sha": head}},
        }, self.base)
        self.assertEqual(selection.paths, ("crates/registry-breg/src/lib.rs",))

    def test_schedule_has_no_historical_comparison_and_selects_every_gate(self) -> None:
        selection = select_event(self.repo, "schedule", {}, self.base)
        self.assertTrue(selection.full_sweep)
        self.assertFalse(selection.archive_comparison_required)
        self.assertEqual(selection.archive_base_ref, "")
        outputs = classify(self.workspace, (), full_sweep=True)
        self.assertTrue(all(value for value in outputs.values() if isinstance(value, bool)))
        self.assertEqual(len(outputs["rust_matrix"]["include"]), len(SHARDS))

    def test_manual_defaults_full_and_can_explicitly_select_branch_diff(self) -> None:
        head = self.commit("crates/registry-breg/src/lib.rs")
        for inputs in ({}, {"full": True}, {"full": "true"}):
            selection = select_event(self.repo, "workflow_dispatch", {"inputs": inputs}, head)
            self.assertTrue(selection.full_sweep)
            self.assertEqual(selection.archive_base_ref, self.base)
        for value in (False, "false"):
            selection = select_event(self.repo, "workflow_dispatch", {"inputs": {"full": value}}, head)
            self.assertFalse(selection.full_sweep)
            self.assertEqual(selection.paths, ("crates/registry-breg/src/lib.rs",))

    def test_actual_entrypoint_publishes_selection_and_archive_policy(self) -> None:
        event_path = self.repo / "event.json"
        event_path.write_text("{}", encoding="utf-8")
        metadata_path = self.repo / "metadata.json"
        metadata_path.write_text(self.metadata, encoding="utf-8")
        output = self.repo / "output"
        subprocess.run([
            "python3", str(ROOT / ".github/scripts/ci_event_routing.py"),
            "--metadata", str(metadata_path), "--github-output", str(output),
        ], cwd=self.repo, env={**os.environ, "GITHUB_EVENT_NAME": "schedule",
                              "GITHUB_EVENT_PATH": str(event_path), "GITHUB_SHA": self.base},
           check=True, capture_output=True, text=True)
        values = dict(line.split("=", 1) for line in output.read_text().splitlines())
        self.assertEqual(values["archive_comparison_required"], "false")
        self.assertEqual(values["docs_archives"], "true")
        self.assertEqual(values["release_linux_node_clients"], "true")

    def test_full_sweep_cli_and_workflow_triggers(self) -> None:
        metadata_path = self.repo / "metadata.json"
        metadata_path.write_text(self.metadata, encoding="utf-8")
        output = self.repo / "full-output"
        subprocess.run([
            "python3", str(ROOT / ".github/scripts/ci_changes.py"), "--full-sweep",
            "--metadata", str(metadata_path), "--github-output", str(output),
        ], cwd=self.repo, check=True, capture_output=True, text=True)
        values = dict(line.split("=", 1) for line in output.read_text().splitlines())
        self.assertEqual(values["docs_archives"], "true")
        self.assertEqual(values["release_linux_node_clients"], "true")
        workflow = (ROOT / ".github/workflows/ci.yml").read_text()
        self.assertIn('    - cron: "37 22 * * *"', workflow)
        self.assertIn("        type: boolean\n        default: true", workflow)
        self.assertIn("run: python3 .github/scripts/test_ci_event_routing.py", workflow)
        # Periodic/manual execution must not broaden the trusted upload surface.
        guard = "if: github.event_name == 'push' && github.ref == 'refs/heads/main'"
        self.assertEqual(workflow.count(guard), 2)
        for name in ("Changed paths", "Rust workspace", "Release tooling", "Release source proof", "Docs"):
            self.assertIn(f"    name: {name}\n", workflow)

    def test_archive_workflow_executes_comparison_policy(self) -> None:
        workflow = (ROOT / ".github/workflows/ci.yml").read_text()
        step = workflow.split("      - name: Validate archive lock and compare event baseline\n", 1)[1]
        script = textwrap.dedent(step.split("        run: |\n", 1)[1].split("\n      - name:", 1)[0])
        # Record npm arguments; test the actual owning shell without installing docs.
        npm = self.repo / "npm"
        npm.write_text('#!/bin/sh\nprintf "%s\\n" "$@" > "$ARG_LOG"\n')
        npm.chmod(0o755)
        log = self.repo / "args"
        for required, base, success, args in (
            ("true", self.base, True, ["run", "check:archive-lock", "--", "--base-ref", self.base]),
            ("false", "", True, ["run", "check:archive-lock"]),
            ("true", "", False, []),
            ("", "", False, []),
        ):
            with self.subTest(required=required, base=base):
                log.unlink(missing_ok=True)
                result = subprocess.run(["bash", "-c", script], cwd=self.repo,
                    env={**os.environ, "PATH": f"{self.repo}{os.pathsep}{os.environ['PATH']}",
                         "ARG_LOG": str(log), "ARCHIVE_COMPARISON_REQUIRED": required,
                         "ARCHIVE_LOCK_BASE_REF": base}, capture_output=True, text=True)
                self.assertEqual(result.returncode == 0, success)
                self.assertEqual(log.read_text().splitlines() if log.exists() else [], args)


if __name__ == "__main__":
    unittest.main()
