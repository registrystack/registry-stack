#!/usr/bin/env python3
"""Exercise note drafting through the supported CLI with Git and offline GitHub data."""

from __future__ import annotations

import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path


TOOL = Path(__file__).resolve().parent / "registry-release"
REPOSITORY = "registrystack/registry-stack"


class DraftNotesTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.repo = self.root / "repo"
        self.repo.mkdir()
        self.git("init", "-b", "main")
        self.git("config", "user.email", "release-test@example.invalid")
        self.git("config", "user.name", "Release Test")
        self.git("remote", "add", "origin", f"https://github.com/{REPOSITORY}.git")
        self.baseline = self.change("products/breg/old.md", "baseline")
        self.git("tag", "v0.28.0")
        self.bin = self.root / "bin"
        self.bin.mkdir()
        fake = self.bin / "gh"
        fake.write_text(
            "#!/usr/bin/env python3\n"
            "import json, os, pathlib, sys\n"
            "args = sys.argv[1:]\n"
            "assert args[:4] == ['api', '--paginate', '--slurp', args[3]]\n"
            "assert len(args) == 4 and args[3].endswith('/pulls?per_page=100')\n"
            "with open(os.environ['NOTES_CALLS'], 'a') as log:\n"
            "    log.write(json.dumps(args) + '\\n')\n"
            "if os.environ.get('NOTES_FAIL'):\n"
            "    sys.stderr.write('fixture GitHub failure\\n')\n"
            "    sys.exit(1)\n"
            "data = json.loads(pathlib.Path(os.environ['NOTES_FIXTURE']).read_text())\n"
            "sha = args[3].split('/')[4]\n"
            "print(json.dumps(data.get(sha, [[]])))\n",
            encoding="utf-8",
        )
        fake.chmod(0o755)
        self.fixture = self.root / "prs.json"
        self.fixture.write_text("{}", encoding="utf-8")
        self.calls = self.root / "calls.jsonl"
        self.environment = dict(os.environ, PATH=f"{self.bin}{os.pathsep}{os.environ['PATH']}")
        self.environment.update(NOTES_FIXTURE=str(self.fixture), NOTES_CALLS=str(self.calls))

    def git(self, *args: str) -> str:
        return subprocess.run(
            ["git", *args], cwd=self.repo, text=True, capture_output=True, check=True,
        ).stdout.strip()

    def change(self, path: str, title: str) -> str:
        destination = self.repo / path
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(title + "\n", encoding="utf-8")
        self.git("add", path)
        self.git("commit", "-m", title)
        return self.git("rev-parse", "HEAD")

    def pr(self, number: int, sha: str, title: str = "Merged work") -> dict:
        return {
            "number": number, "title": title, "merged_at": "2026-09-09T00:00:00Z",
            "merge_commit_sha": sha, "base": {"repo": {"full_name": REPOSITORY}},
        }

    def draft(self, *args: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [str(TOOL), "draft-notes", "--repo", str(self.repo), "--version", "0.29.0",
             "--release-id", "beta-41", "--from-tag", "v0.28.0", *args],
            text=True, capture_output=True, env=self.environment, check=False,
        )

    def test_exact_range_collects_prs_direct_commits_and_net_components(self) -> None:
        first = self.change("crates/registry-breg/lib.rs", "Squashed work")
        second = self.change("docs/readme.md", "Follow-up")
        direct = self.change("products/breg/new.md", "Direct [link](bad) <script> *title*")
        self.git("rm", "products/breg/old.md")
        self.git("commit", "-m", "Remove obsolete file")
        source = self.git("rev-parse", "HEAD")
        self.change("products/evidence/later.md", "Outside range")
        merged = self.pr(41, second, "Use [field](bad) <b> & *syntax*")
        unmerged = self.pr(42, first)
        unmerged["merged_at"] = None
        foreign = self.pr(43, first)
        foreign["base"]["repo"]["full_name"] = "elsewhere/other"
        outside = self.pr(44, "a" * 40)
        self.fixture.write_text(json.dumps({
            first: [[unmerged, foreign, outside], [merged]], second: [[merged]],
        }), encoding="utf-8")
        result = self.draft("--source-ref", source)
        self.assertEqual(result.returncode, 0, result.stderr)
        body = result.stdout
        self.assertEqual(body.count(f"https://github.com/{REPOSITORY}/pull/41"), 1)
        self.assertNotIn("/pull/42", body)
        self.assertNotIn("/pull/43", body)
        self.assertNotIn("/pull/44", body)
        self.assertIn("Use \\[field\\]\\(bad\\) &lt;b&gt; &amp; \\*syntax\\*", body)
        self.assertIn(f"/commit/{direct}", body)
        self.assertIn(f"/compare/{self.baseline}...{source}", body)
        self.assertIn("products/breg: 2 changed files", body)
        self.assertIn("crates/registry-breg: 1 changed file", body)
        self.assertNotIn("products/evidence", body)
        self.assertNotIn("Outside range", body)
        self.assertIn("TODO (release author)", body)
        self.assertEqual(body, self.draft("--source-ref", source).stdout)

    def test_merge_commit_represents_branch_work_once(self) -> None:
        self.git("switch", "-c", "feature")
        branch_commit = self.change("products/relay-v2/feature.md", "Feature implementation")
        self.git("switch", "main")
        self.git("merge", "--no-ff", "feature", "-m", "Merge feature")
        merged = self.git("rev-parse", "HEAD")
        self.fixture.write_text(json.dumps({merged: [[self.pr(50, merged)]]}), encoding="utf-8")
        result = self.draft()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("/pull/50", result.stdout)
        self.assertNotIn(branch_commit, result.stdout)
        self.assertEqual(len(self.calls.read_text().splitlines()), 1)

    def test_new_output_and_existing_file_or_symlink_refusal(self) -> None:
        self.change("docs/a.md", "Documentation")
        output = self.root / "draft.md"
        result = self.draft("--output", str(output))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "")
        authored = "Human-authored upgrade guidance\n"
        output.write_text(authored, encoding="utf-8")
        link = self.root / "link.md"
        link.symlink_to(output)
        dangling = self.root / "dangling.md"
        dangling.symlink_to(self.root / "absent.md")
        for path in (output, link, dangling):
            with self.subTest(path=path):
                refused = self.draft("--output", str(path))
                self.assertNotEqual(refused.returncode, 0)
                self.assertIn("already exists", refused.stderr)
                self.assertEqual(output.read_text(), authored)
        self.assertFalse((self.root / "absent.md").exists())

    def test_missing_and_nonancestor_baselines_fail_without_github_queries(self) -> None:
        source = self.change("docs/a.md", "Current source")
        self.git("switch", "-c", "other", self.baseline)
        self.change("docs/other.md", "Other line")
        self.git("tag", "v0.28.1")
        for baseline in ("v9.9.9", "v0.28.1"):
            with self.subTest(baseline=baseline):
                result = self.draft("--from-tag", baseline, "--source-ref", source)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(result.stdout, "")
        self.assertFalse(self.calls.exists())

    def test_github_failure_or_malformed_pages_never_creates_partial_draft(self) -> None:
        sha = self.change("docs/a.md", "Documentation")
        output = self.root / "draft.md"
        self.environment["NOTES_FAIL"] = "1"
        failed = self.draft("--output", str(output))
        self.assertNotEqual(failed.returncode, 0)
        self.assertIn("fixture GitHub failure", failed.stderr)
        self.assertFalse(output.exists())
        del self.environment["NOTES_FAIL"]
        self.fixture.write_text(json.dumps({sha: {"unexpected": "shape"}}), encoding="utf-8")
        malformed = self.draft("--output", str(output))
        self.assertNotEqual(malformed.returncode, 0)
        self.assertIn("malformed pull-request pages", malformed.stderr)
        self.assertFalse(output.exists())

    def test_one_point_zero_draft_does_not_infer_beta_status(self) -> None:
        result = self.draft("--version", "1.0.0", "--release-id", "release-1")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(result.stdout.startswith("# Registry Stack v1.0.0\n"))
        self.assertIn("TODO (release author)", result.stdout)
        self.assertNotIn("pre-1.0", result.stdout)
        self.assertNotIn("Beta", result.stdout)

    def test_wrong_origin_and_invalid_release_identity_fail_before_queries(self) -> None:
        self.change("docs/a.md", "Documentation")
        for args in (("--version", "v0.29.0"), ("--release-id", "invalid/id")):
            result = self.draft(*args)
            self.assertNotEqual(result.returncode, 0)
        self.git("remote", "set-url", "origin", "https://github.com/elsewhere/other.git")
        result = self.draft()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("origin remote", result.stderr)
        self.assertFalse(self.calls.exists())


if __name__ == "__main__":
    unittest.main()
