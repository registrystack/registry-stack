from __future__ import annotations

import importlib.util
import json
import subprocess
import tempfile
from pathlib import Path
from unittest import TestCase, main, mock


SPEC = importlib.util.spec_from_file_location(
    "prepare_release_docs", Path(__file__).with_name("prepare_release_docs.py")
)
prep = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(prep)
REAL_RUN = subprocess.run


class PreparationTest(TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.repo = self.root / "release source"
        self.repo.mkdir()
        prep.git(self.repo, "init", "-b", "main")
        prep.git(self.repo, "config", "user.name", "Test")
        prep.git(self.repo, "config", "user.email", "test@example.invalid")
        (self.repo / "Cargo.toml").write_text('[workspace.package]\nversion = "0.29.0"\n')
        path = self.repo / "release/manifests/registry-stack-beta-41.yaml"
        path.parent.mkdir(parents=True)
        path.write_text('stack: {version: 0.29.0, release: beta-41}\nartifacts: {registry-docs: 0.29.0}\n')
        path = self.repo / "release/notes/v0.29.0.md"
        path.parent.mkdir(parents=True)
        path.write_text("# Release notes\n")
        for name in prep.DOCS_INPUTS:
            path = self.repo / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("historical: preserved\n")
        (self.repo / "docs/site/src/data/cli-reference.yaml").write_text("status: current\n")
        self.commit()
        prep.git(self.repo, "remote", "add", "origin", "https://github.com/registrystack/registry-stack.git")
        prep.git(self.repo, "update-ref", "refs/remotes/origin/main", "HEAD")

    def commit(self):
        prep.git(self.repo, "add", ".")
        prep.git(self.repo, "-c", "commit.gpgsign=false", "-c", "core.hooksPath=/dev/null", "commit", "-m", "Fixture")

    def fake_docker(self, args, **kwargs):
        if args[0] != "docker":
            return REAL_RUN(args, **kwargs)
        mounts = [args[i + 1] for i, arg in enumerate(args) if arg == "--mount"]
        source = Path(mounts[0].split("src=", 1)[1].split(",dst=", 1)[0])
        artifacts = Path(mounts[1].split("src=", 1)[1].split(",dst=", 1)[0])
        path = source / prep.DOCS_INPUTS[0]
        if "candidate:" not in path.read_text():
            path.write_text(path.read_text() + "candidate: v0.29.0\n")
        (artifacts / "documentation.patch").write_text(
            REAL_RUN(["git", "-C", str(source), "diff", "HEAD"], check=True, capture_output=True, text=True).stdout
        )
        (artifacts / "changed-paths.json").write_text(json.dumps([prep.DOCS_INPUTS[0]]))
        (artifacts / "v0.29.0.tar.gz").write_bytes(b"fixture archive")
        return subprocess.CompletedProcess(args, 0)

    def prepare(self, **kwargs):
        return prep.prepare_docs(self.repo, "0.29.0", "beta-41", "2026-09-10", **kwargs)

    def test_preview_builds_from_exact_source_without_changing_branch(self):
        head = prep.git(self.repo, "rev-parse", "HEAD")
        output = self.root / "review output"
        with mock.patch.object(prep.subprocess, "run", side_effect=self.fake_docker):
            report = self.prepare(output_dir=output)
        self.assertEqual(report["status"], "ready")
        self.assertFalse(report["applied"])
        self.assertIn("candidate: v0.29.0", Path(report["patch"]).read_text())
        self.assertEqual(prep.git(self.repo, "rev-parse", "HEAD"), head)
        self.assertEqual(prep.git(self.repo, "status", "--porcelain"), "")
        self.assertEqual(json.loads((output / "report.json").read_text())["source_sha"], head)

    def test_apply_preserves_untracked_work_and_rerun_is_noop(self):
        user_file = self.repo / "user-notes.txt"
        user_file.write_text("keep me")
        with mock.patch.object(prep.subprocess, "run", side_effect=self.fake_docker):
            self.assertTrue(self.prepare(output_dir=self.root / "first", apply=True)["applied"])
        self.assertEqual(user_file.read_text(), "keep me")
        prep.git(self.repo, "add", prep.DOCS_INPUTS[0])
        prep.git(self.repo, "-c", "commit.gpgsign=false", "commit", "-m", "Prepare docs")
        with mock.patch.object(prep.subprocess, "run", side_effect=self.fake_docker):
            report = self.prepare(output_dir=self.root / "second", apply=True)
        self.assertEqual(Path(report["patch"]).read_bytes(), b"")
        self.assertEqual(user_file.read_text(), "keep me")
        for name in prep.DOCS_INPUTS:
            self.assertIn("historical: preserved", (self.repo / name).read_text())

    def test_failed_build_keeps_source_unchanged_and_reports_recovery(self):
        def fail(args, **kwargs):
            if args[0] == "docker":
                raise subprocess.CalledProcessError(1, args)
            return REAL_RUN(args, **kwargs)
        output = self.root / "failure"
        with mock.patch.object(prep.subprocess, "run", side_effect=fail):
            with self.assertRaisesRegex(prep.PreparationError, "cli-reference:digest"):
                self.prepare(output_dir=output, apply=True)
        self.assertEqual(prep.git(self.repo, "status", "--porcelain"), "")
        self.assertEqual(json.loads((output / "report.json").read_text())["status"], "failed")

    def test_concurrent_input_edit_prevents_apply(self):
        def mutate(args, **kwargs):
            result = self.fake_docker(args, **kwargs)
            if args[0] == "docker":
                (self.repo / prep.DOCS_INPUTS[1]).write_text("concurrent: keep\n")
            return result
        with mock.patch.object(prep.subprocess, "run", side_effect=mutate):
            with self.assertRaises(prep.PreparationError):
                self.prepare(output_dir=self.root / "concurrent", apply=True)
        self.assertEqual((self.repo / prep.DOCS_INPUTS[1]).read_text(), "concurrent: keep\n")
        self.assertNotIn("candidate:", (self.repo / prep.DOCS_INPUTS[0]).read_text())

    def test_uncommitted_inputs_and_wrong_identity_fail_before_build(self):
        with self.assertRaisesRegex(prep.PreparationError, "tracked input"):
            prep.validate_inputs(self.repo, "0.30.0", "beta-41", "2026-09-10")
        (self.repo / prep.DOCS_INPUTS[0]).write_text("work: in progress\n")
        with self.assertRaisesRegex(prep.PreparationError, "commit"):
            self.prepare(output_dir=self.root / "not-created")
        self.assertFalse((self.root / "not-created").exists())

    def test_staged_edit_with_restored_worktree_still_prevents_apply(self):
        head = prep.git(self.repo, "rev-parse", "HEAD")
        path = self.repo / prep.DOCS_INPUTS[0]
        original = path.read_text()
        path.write_text("staged: keep\n")
        prep.git(self.repo, "add", prep.DOCS_INPUTS[0])
        path.write_text(original)
        patch = self.root / "empty.patch"
        patch.write_text("")
        with self.assertRaisesRegex(prep.PreparationError, "inputs changed"):
            prep.apply_patch(self.repo, head, patch)
        self.assertEqual(prep.git(self.repo, "show", f":{prep.DOCS_INPUTS[0]}"), "staged: keep")
        self.assertEqual(path.read_text(), original)

    def test_untracked_manifest_is_rejected_before_clone(self):
        name = "release/manifests/registry-stack-beta-41.yaml"
        prep.git(self.repo, "rm", "--cached", name)
        prep.git(self.repo, "-c", "commit.gpgsign=false", "commit", "-m", "Untrack manifest")
        with self.assertRaises(subprocess.CalledProcessError):
            self.prepare(output_dir=self.root / "not-created")
        self.assertFalse((self.root / "not-created").exists())

    def test_existing_output_is_never_overwritten(self):
        output = self.root / "existing"
        output.mkdir()
        (output / "report.json").write_text("previous evidence")
        with self.assertRaises(FileExistsError):
            self.prepare(output_dir=output)
        self.assertEqual((output / "report.json").read_text(), "previous evidence")


if __name__ == "__main__":
    main()
