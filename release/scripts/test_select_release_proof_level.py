#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import json
import subprocess
import tempfile
import unittest
from pathlib import Path


SCRIPT = Path(__file__).with_name("select-release-proof-level.py")


def load_module():
    spec = importlib.util.spec_from_file_location("select_release_proof_level", SCRIPT)
    if spec is None or spec.loader is None:
        raise ImportError(f"could not load module spec from {SCRIPT}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def run_git(repo: Path, *arguments: str) -> str:
    return subprocess.run(
        ["git", "-C", str(repo), *arguments],
        check=True,
        stdout=subprocess.PIPE,
        text=True,
    ).stdout.strip()


class SelectReleaseProofLevelTest(unittest.TestCase):
    def setUp(self) -> None:
        self.module = load_module()
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.repo = Path(self.temporary.name)
        run_git(self.repo, "init", "-q")
        run_git(self.repo, "config", "user.name", "Release Test")
        run_git(self.repo, "config", "user.email", "release@example.test")
        (self.repo / "README.md").write_text("base\n", encoding="utf-8")
        run_git(self.repo, "add", "README.md")
        run_git(self.repo, "commit", "-qm", "base")
        self.base = run_git(self.repo, "rev-parse", "HEAD")
        run_git(self.repo, "tag", "-a", "v0.12.2", "-m", "v0.12.2")

    def select(self, **overrides):
        arguments = {
            "repo": self.repo,
            "requested": "auto",
            "version": "0.13.1",
            "source_ref": "HEAD",
            "previous_receipt": None,
            "previous_tag": "v0.12.2",
            "current_builders": None,
            "milestone": "beta",
            "candidate_evidence": "complete",
        }
        arguments.update(overrides)
        return self.module.select(**arguments)

    def commit(self, path: str, contents: str = "changed\n") -> None:
        target = self.repo / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(contents, encoding="utf-8")
        run_git(self.repo, "add", path)
        run_git(self.repo, "commit", "-qm", f"change {path}")

    def builders(self, *, image_buildx_version: str = "v0.33.0") -> dict:
        return {
            "binary_image": "rust@example",
            "binary_fingerprint": "1" * 64,
            "binary_recipe_fingerprint": "2" * 64,
            "image_buildkit_image": "buildkit@example",
            "image_buildx_version": image_buildx_version,
            "image_recipe_fingerprint": "3" * 64,
        }

    def builders_file(self, **overrides) -> Path:
        path = self.repo / "current-builders.json"
        path.write_text(
            json.dumps(self.builders(**overrides)),
            encoding="utf-8",
        )
        return path

    def receipt(self, source_sha: str, **builder_overrides) -> Path:
        path = self.repo / "previous-receipt.json"
        path.write_text(
            json.dumps(
                {
                    "schema_version": "registry-stack.release-candidate-receipt.v1",
                    "repository": "registrystack/registry-stack",
                    "workflow": {
                        "path": ".github/workflows/release-candidate.yml",
                        "ref": "refs/heads/main",
                        "event": "repository_dispatch",
                    },
                    "release": {
                        "version": "0.12.2",
                        "tag": "v0.12.2",
                        "source_sha": source_sha,
                    },
                    "builders": self.builders(**builder_overrides),
                }
            ),
            encoding="utf-8",
        )
        return path

    def test_ordinary_beta_change_selects_standard(self) -> None:
        self.commit("crates/example/src/lib.rs")
        result = self.select()
        self.assertEqual("standard", result.proof_level)
        self.assertEqual(self.base, result.comparison_base)
        self.assertEqual([], result.sensitive_paths)

    def test_release_script_change_forces_extended(self) -> None:
        self.commit("release/scripts/example.py")
        result = self.select()
        self.assertEqual("extended", result.proof_level)
        self.assertEqual(["release/scripts/example.py"], result.sensitive_paths)

    def test_trust_anchor_change_forces_extended(self) -> None:
        self.commit("Cargo.lock")
        self.assertEqual("extended", self.select().proof_level)

    def test_explicit_extended_has_no_standard_bypass(self) -> None:
        self.commit("crates/example/src/lib.rs")
        result = self.select(requested="extended")
        self.assertEqual("extended", result.proof_level)
        with self.assertRaisesRegex(self.module.SelectionError, "auto or extended"):
            self.select(requested="standard")

    def test_stable_audit_and_one_dot_zero_force_extended(self) -> None:
        self.commit("crates/example/src/lib.rs")
        for overrides in (
            {"milestone": "stable"},
            {"milestone": "audit"},
            {"version": "1.0.0"},
        ):
            with self.subTest(overrides=overrides):
                self.assertEqual("extended", self.select(**overrides).proof_level)

    def test_incomplete_or_disagreeing_evidence_forces_extended(self) -> None:
        self.commit("crates/example/src/lib.rs")
        for state in ("incomplete", "disagree"):
            with self.subTest(state=state):
                self.assertEqual(
                    "extended",
                    self.select(candidate_evidence=state).proof_level,
                )

    def test_receipt_is_preferred_as_authoritative_base(self) -> None:
        self.commit("crates/example/src/lib.rs")
        result = self.select(
            previous_receipt=self.receipt(self.base),
            previous_tag=None,
            current_builders=self.builders_file(),
        )
        self.assertEqual("standard", result.proof_level)
        self.assertEqual("promoted_receipt", result.comparison_base_kind)

    def test_conflicting_receipt_and_tag_force_extended(self) -> None:
        self.commit("crates/example/src/lib.rs")
        newer = run_git(self.repo, "rev-parse", "HEAD")
        result = self.select(
            previous_receipt=self.receipt(newer),
            current_builders=self.builders_file(),
        )
        self.assertEqual("extended", result.proof_level)
        self.assertTrue(any("different commits" in reason for reason in result.reasons))

    def test_untrusted_receipt_identity_forces_extended(self) -> None:
        self.commit("crates/example/src/lib.rs")
        receipt = self.receipt(self.base)
        value = json.loads(receipt.read_text(encoding="utf-8"))
        value["workflow"]["ref"] = "refs/heads/untrusted"
        receipt.write_text(json.dumps(value), encoding="utf-8")
        result = self.select(
            previous_receipt=receipt,
            previous_tag=None,
            current_builders=self.builders_file(),
        )
        self.assertEqual("extended", result.proof_level)
        self.assertTrue(any("not authoritative" in reason for reason in result.reasons))

    def test_receipt_trust_anchor_change_forces_extended_without_path_change(
        self,
    ) -> None:
        self.commit("crates/example/src/lib.rs")
        result = self.select(
            previous_receipt=self.receipt(self.base),
            current_builders=self.builders_file(image_buildx_version="v0.34.0"),
        )
        self.assertEqual("extended", result.proof_level)
        self.assertIn("<receipt-trust-anchor-mismatch>", result.sensitive_paths)
        self.assertTrue(
            any("image_buildx_version" in reason for reason in result.reasons)
        )

    def test_missing_current_fingerprints_with_receipt_is_ambiguous(self) -> None:
        self.commit("crates/example/src/lib.rs")
        result = self.select(previous_receipt=self.receipt(self.base))
        self.assertEqual("extended", result.proof_level)
        self.assertTrue(
            any("fingerprints are missing" in reason for reason in result.reasons)
        )

    def test_missing_or_unrelated_history_forces_extended(self) -> None:
        self.commit("crates/example/src/lib.rs")
        self.assertEqual(
            "extended",
            self.select(previous_tag=None).proof_level,
        )
        run_git(self.repo, "checkout", "--orphan", "unrelated")
        run_git(self.repo, "rm", "-qrf", ".")
        (self.repo / "other").write_text("other\n", encoding="utf-8")
        run_git(self.repo, "add", "other")
        run_git(self.repo, "commit", "-qm", "unrelated")
        self.assertEqual("extended", self.select().proof_level)


if __name__ == "__main__":
    unittest.main()
