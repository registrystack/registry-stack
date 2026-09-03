#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import hashlib
import io
import json
import os
import stat
import subprocess
import sys
import tempfile
from contextlib import redirect_stderr, redirect_stdout
from importlib.machinery import SourceFileLoader
from pathlib import Path
from unittest import SkipTest, TestCase, main, mock

import yaml


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "release/scripts/registry-release"
IMAGE_DIGEST = "sha256:" + "a" * 64
IMAGE_DIGEST_REF = f"ghcr.io/registrystack/relay@{IMAGE_DIGEST}"


def load_debian13_image_check():
    path = ROOT / "release/scripts/check-debian13-images.py"
    spec = importlib.util.spec_from_file_location("check_debian13_images", path)
    if spec is None or spec.loader is None:
        raise ImportError(f"could not load module spec from {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module




def load_registry_release():
    module_name = "registry_release_module"
    loader = SourceFileLoader(module_name, str(TOOL))
    spec = importlib.util.spec_from_loader(module_name, loader)
    if spec is None:
        raise ImportError(f"could not load module spec from {TOOL}")
    module = importlib.util.module_from_spec(spec)
    sys.path.insert(0, str(TOOL.parent))
    try:
        loader.exec_module(module)
    finally:
        sys.path.pop(0)
    return module


class RegistryReleaseTest(TestCase):
    def test_candidate_request_requires_current_source_workflow_revision(
        self,
    ) -> None:
        registry_release = load_registry_release()
        source = "a" * 40
        context = {
            "repo": ROOT,
            "selected": {"data": {"stack": {}}},
        }
        with (
            mock.patch.object(
                registry_release,
                "prepare_release_context",
                return_value=context,
            ),
            mock.patch.object(
                registry_release,
                "refresh_protected_main",
                return_value=source,
            ),
            mock.patch.object(
                registry_release,
                "resolve_commit",
                return_value=source,
            ),
            mock.patch.object(registry_release, "run_checked") as dispatch,
            mock.patch.object(
                registry_release,
                "wait_for_dispatched_run",
                return_value={
                    "id": 42,
                    "html_url": "https://github.com/registrystack/registry-stack/actions/runs/42",
                },
            ),
            redirect_stdout(io.StringIO()) as output,
        ):
            accepted = registry_release.request_release_candidate(
                ROOT,
                "1.2.3",
                "beta-20",
                source,
                "origin/main",
                "registrystack/registry-stack",
                print_request=False,
            )

        self.assertEqual(0, accepted)
        dispatch.assert_called_once()
        self.assertIn("run 42", output.getvalue())
        request = dispatch.call_args.args[0]
        self.assertTrue(
            any(part.startswith("client_payload[request_id]=") for part in request)
        )

        stale_source = "b" * 40

        def resolve(_repo: Path, revision: str, _description: str) -> str:
            return stale_source if revision == stale_source else source

        with (
            mock.patch.object(
                registry_release,
                "prepare_release_context",
                return_value=context,
            ),
            mock.patch.object(
                registry_release,
                "refresh_protected_main",
                return_value=source,
            ),
            mock.patch.object(
                registry_release,
                "resolve_commit",
                side_effect=resolve,
            ),
            mock.patch.object(registry_release, "run_checked") as no_dispatch,
            mock.patch.object(
                registry_release,
                "wait_for_dispatched_run",
            ) as no_run_lookup,
        ):
            rejected = registry_release.request_release_candidate(
                ROOT,
                "1.2.3",
                "beta-20",
                stale_source,
                "origin/main",
                "registrystack/registry-stack",
                print_request=False,
            )

        self.assertEqual(1, rejected)
        no_dispatch.assert_not_called()
        no_run_lookup.assert_not_called()

    def test_candidate_run_lookup_uses_unique_display_title(self) -> None:
        registry_release = load_registry_release()
        source = "a" * 40
        expected = {
            "id": 123,
            "html_url": "https://github.com/registrystack/registry-stack/actions/runs/123",
            "event": "repository_dispatch",
            "head_sha": source,
            "display_title": "Release candidate beta-20 v1.2.3 (request)",
        }
        with mock.patch.object(
            registry_release,
            "workflow_runs",
            return_value=[
                {
                    **expected,
                    "id": 122,
                    "display_title": "Release candidate beta-19 v1.2.2 (other)",
                },
                expected,
            ],
        ):
            observed = registry_release.wait_for_dispatched_run(
                "registrystack/registry-stack",
                source_sha=source,
                display_title=expected["display_title"],
                request_id="request",
            )

        self.assertEqual(expected, observed)

    def test_candidate_request_aborts_if_main_advances_while_waiting_for_ci(
        self,
    ) -> None:
        registry_release = load_registry_release()
        source = "a" * 40
        advanced = "b" * 40
        context = {
            "repo": ROOT,
            "selected": {"data": {"stack": {}}},
        }

        def resolve(_repo: Path, revision: str, _description: str) -> str:
            if revision == "origin/main" and refresh.call_count > 1:
                return advanced
            return source

        with (
            mock.patch.object(
                registry_release,
                "prepare_release_context",
                return_value=context,
            ),
            mock.patch.object(
                registry_release,
                "refresh_protected_main",
                side_effect=[source, advanced],
            ) as refresh,
            mock.patch.object(
                registry_release,
                "resolve_commit",
                side_effect=resolve,
            ),
            mock.patch.object(
                registry_release,
                "wait_for_exact_protected_ci",
                return_value={
                    "id": 77,
                    "html_url": "https://github.com/registrystack/registry-stack/actions/runs/77",
                },
            ),
            mock.patch.object(registry_release, "run_checked") as no_dispatch,
            mock.patch.object(
                registry_release,
                "wait_for_dispatched_run",
            ) as no_run_lookup,
            redirect_stderr(io.StringIO()) as errors,
        ):
            result = registry_release.request_release_candidate(
                ROOT,
                "1.2.3",
                "beta-20",
                source,
                "origin/main",
                "registrystack/registry-stack",
                print_request=False,
                wait_for_ci=True,
            )

        self.assertEqual(1, result)
        self.assertEqual(2, refresh.call_count)
        no_dispatch.assert_not_called()
        no_run_lookup.assert_not_called()
        self.assertIn("protected default branch advanced", errors.getvalue())

    def test_wait_for_ci_watches_only_the_exact_source_run(self) -> None:
        registry_release = load_registry_release()
        source = "a" * 40
        active = {
            "id": 77,
            "html_url": "https://github.com/registrystack/registry-stack/actions/runs/77",
            "event": "push",
            "head_sha": source,
            "status": "in_progress",
            "conclusion": None,
        }
        passed = {**active, "status": "completed", "conclusion": "success"}
        with (
            mock.patch.object(
                registry_release,
                "workflow_runs",
                side_effect=[[active], [passed]],
            ),
            mock.patch.object(registry_release, "watch_workflow_run") as watch,
        ):
            observed = registry_release.wait_for_exact_protected_ci(
                "registrystack/registry-stack",
                source,
            )

        self.assertEqual(passed, observed)
        watch.assert_called_once_with(
            "registrystack/registry-stack",
            77,
            "protected-main CI",
            verbose=False,
        )

    def test_compact_wait_finds_approval_while_run_is_in_progress(self) -> None:
        registry_release = load_registry_release()
        url = "https://github.com/registrystack/registry-stack/actions/runs/77"
        queued = {"id": 77, "html_url": url, "status": "queued", "conclusion": None}
        in_progress = {**queued, "status": "in_progress"}
        passed = {**queued, "status": "completed", "conclusion": "success"}
        with (
            mock.patch.object(
                registry_release,
                "workflow_run",
                side_effect=[queued, queued, in_progress, passed],
            ),
            mock.patch.object(
                registry_release,
                "pending_deployments",
                side_effect=[[], [], [{"environment": {"name": "npm"}}]],
            ),
            mock.patch.object(registry_release.time, "sleep"),
            redirect_stdout(io.StringIO()) as output,
        ):
            registry_release.watch_workflow_run(
                "registrystack/registry-stack",
                77,
                "release",
            )

        text = output.getvalue()
        self.assertEqual(1, text.count("release run 77: queued"))
        self.assertEqual(1, text.count(url))
        self.assertIn("release run 77: in_progress", text)
        self.assertIn("pending protected-environment approval for npm", text)
        self.assertIn("authorized reviewer", text)
        self.assertIn("pending_deployments", text)
        self.assertIn("release run 77: completed/success", text)

    def test_verbose_wait_uses_raw_gh_watcher(self) -> None:
        registry_release = load_registry_release()
        with (
            mock.patch.object(
                registry_release.subprocess,
                "run",
                return_value=subprocess.CompletedProcess([], 0),
            ) as run,
            mock.patch.object(registry_release, "workflow_run") as compact,
        ):
            registry_release.watch_workflow_run(
                "registrystack/registry-stack",
                77,
                "release",
                verbose=True,
            )

        compact.assert_not_called()
        self.assertEqual(
            [
                "gh",
                "run",
                "watch",
                "77",
                "--repo",
                "registrystack/registry-stack",
                "--exit-status",
            ],
            run.call_args.args[0],
        )

    def test_recovery_draft_must_keep_the_candidate_binding(self) -> None:
        registry_release = load_registry_release()
        manifest_sha = "b" * 64
        marker = f"registry-stack-release-candidate-v2 manifest_sha256:{manifest_sha}"
        release = {
            "tag_name": "v1.2.3",
            "name": "RegistryStack v1.2.3",
            "prerelease": False,
            "draft": True,
            "published_at": None,
            "body": marker,
        }
        self.assertEqual(
            "draft",
            registry_release.validate_recovery_release(
                release,
                tag="v1.2.3",
                manifest_sha256=manifest_sha,
            ),
        )

        release["body"] = "different candidate"
        with self.assertRaisesRegex(
            registry_release.ReleasePlanError,
            "not bound to this candidate",
        ):
            registry_release.validate_recovery_release(
                release,
                tag="v1.2.3",
                manifest_sha256=manifest_sha,
            )

    def test_recovery_requires_the_local_tag_to_match_origin(self) -> None:
        registry_release = load_registry_release()
        reference = "refs/tags/v1.2.3"
        local_object = "a" * 40
        remote_object = "b" * 40
        source = "c" * 40

        def checked(command, **_kwargs):
            if command == ["git", "cat-file", "-t", reference]:
                return "tag\n"
            if command == ["git", "rev-parse", reference]:
                return f"{local_object}\n"
            if command[:3] == ["git", "ls-remote", "--tags"]:
                return (
                    f"{remote_object}\t{reference}\n"
                    f"{source}\t{reference}^{{}}\n"
                )
            raise AssertionError(command)

        with self.assertRaisesRegex(
            registry_release.ReleasePlanError,
            "does not exactly match origin",
        ):
            with (
                mock.patch.object(registry_release, "run_checked", side_effect=checked),
                mock.patch.object(
                    registry_release,
                    "resolve_commit",
                    return_value=source,
                ),
            ):
                registry_release.tagged_candidate_binding(ROOT, "v1.2.3")

    def test_recovery_verification_emits_exact_retry_command(self) -> None:
        registry_release = load_registry_release()
        manifest_sha = "b" * 64
        source_sha = "a" * 40
        workflow_revision = "c" * 40
        protected_main = "d" * 40
        binding = registry_release.release_candidate.render_tag_binding(
            77,
            1,
            manifest_sha,
        )
        with (
            mock.patch.object(registry_release, "verify_origin_repository"),
            mock.patch.object(
                registry_release,
                "tagged_candidate_binding",
                return_value=(
                    source_sha,
                    registry_release.release_candidate.parse_tag_binding(binding),
                ),
            ),
            mock.patch.object(registry_release, "release_for_tag", return_value=None),
            mock.patch.object(
                registry_release,
                "verify_candidate_run",
                return_value=(
                    {
                        "release": {"version": "0.22.0"},
                        "workflow": {"revision": workflow_revision},
                    },
                    binding,
                ),
            ),
            mock.patch.object(
                registry_release,
                "refresh_protected_main",
                return_value=protected_main,
            ),
            mock.patch.object(
                registry_release,
                "resolve_commit",
                return_value=workflow_revision,
            ),
            mock.patch.object(
                registry_release,
                "validate_candidate_ancestry",
            ) as validate_ancestry,
            redirect_stdout(io.StringIO()) as output,
            redirect_stderr(io.StringIO()) as errors,
        ):
            result = registry_release.verify_release_recovery(
                ROOT,
                tag="v0.22.0",
                repository="registrystack/registry-stack",
            )

        self.assertEqual(0, result)
        expected = (
            "gh workflow run release.yml --repo registrystack/registry-stack "
            "--ref main -f tag=v0.22.0"
        )
        self.assertIn(expected, output.getvalue())
        self.assertIn(expected, errors.getvalue())
        validate_ancestry.assert_called_once_with(
            ROOT,
            source_sha=source_sha,
            workflow_revision=workflow_revision,
            protected_main_sha=protected_main,
        )

    def test_recovery_verification_rejects_unreachable_candidate_source(self) -> None:
        registry_release = load_registry_release()
        source_sha = "a" * 40
        workflow_revision = "c" * 40
        protected_main = "d" * 40
        manifest_sha = "b" * 64
        binding = registry_release.release_candidate.render_tag_binding(
            77,
            1,
            manifest_sha,
        )
        with (
            mock.patch.object(registry_release, "verify_origin_repository"),
            mock.patch.object(registry_release, "release_for_tag", return_value=None),
            mock.patch.object(
                registry_release,
                "tagged_candidate_binding",
                return_value=(
                    source_sha,
                    registry_release.release_candidate.parse_tag_binding(binding),
                ),
            ),
            mock.patch.object(
                registry_release,
                "verify_candidate_run",
                return_value=(
                    {
                        "release": {"version": "0.22.0"},
                        "workflow": {"revision": workflow_revision},
                    },
                    binding,
                ),
            ),
            mock.patch.object(
                registry_release,
                "refresh_protected_main",
                return_value=protected_main,
            ),
            mock.patch.object(
                registry_release,
                "resolve_commit",
                return_value=workflow_revision,
            ),
            mock.patch.object(
                registry_release,
                "validate_candidate_ancestry",
                side_effect=registry_release.ReleasePlanError(
                    f"candidate source {source_sha} is not reachable from protected main"
                ),
            ),
            redirect_stdout(io.StringIO()) as output,
            redirect_stderr(io.StringIO()) as errors,
        ):
            result = registry_release.verify_release_recovery(
                ROOT,
                tag="v0.22.0",
                repository="registrystack/registry-stack",
            )

        self.assertEqual(1, result)
        self.assertNotIn("workflow run", output.getvalue())
        self.assertIn("not reachable from protected main", errors.getvalue())

    def test_recovery_verification_rejects_tags_publication_cannot_dispatch(
        self,
    ) -> None:
        registry_release = load_registry_release()
        for tag, expected_error in (
            ("v1.2.3", "Beta publication accepts only v0.x.y release tags"),
            ("v0.18.0", "pre-v0.19 releases are immutable historical evidence"),
        ):
            with self.subTest(tag=tag):
                with (
                    mock.patch.object(registry_release, "verify_origin_repository"),
                    mock.patch.object(
                        registry_release,
                        "release_for_tag",
                        return_value=None,
                    ),
                    mock.patch.object(
                        registry_release,
                        "tagged_candidate_binding",
                    ) as candidate,
                    redirect_stdout(io.StringIO()),
                    redirect_stderr(io.StringIO()) as errors,
                ):
                    result = registry_release.verify_release_recovery(
                        ROOT,
                        tag=tag,
                        repository="registrystack/registry-stack",
                    )

                self.assertEqual(1, result)
                candidate.assert_not_called()
                self.assertIn(expected_error, errors.getvalue())

    def test_published_recovery_routes_to_public_verification_without_retry(self) -> None:
        registry_release = load_registry_release()
        public = {"tag": "v1.2.3", "status": "verified"}
        with (
            mock.patch.object(registry_release, "verify_origin_repository"),
            mock.patch.object(
                registry_release,
                "release_for_tag",
                return_value={"draft": False},
            ),
            mock.patch.object(
                registry_release.verify_public_release,
                "verify",
                return_value=public,
            ) as verify_public,
            mock.patch.object(registry_release, "verify_candidate_run") as candidate,
            redirect_stdout(io.StringIO()) as output,
            redirect_stderr(io.StringIO()) as errors,
        ):
            result = registry_release.verify_release_recovery(
                ROOT,
                tag="v1.2.3",
                repository="registrystack/registry-stack",
            )

        self.assertEqual(0, result)
        verify_public.assert_called_once()
        candidate.assert_not_called()
        self.assertIn('"status": "complete"', output.getvalue())
        self.assertNotIn("workflow run", output.getvalue())
        self.assertIn("do not retry", errors.getvalue())

    def test_candidate_ancestry_accepts_main_advancement_and_rejects_unreachable_source(
        self,
    ) -> None:
        registry_release = load_registry_release()
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            subprocess.run(["git", "init", "-b", "main"], cwd=repo, check=True)
            subprocess.run(
                ["git", "config", "user.email", "test@example.invalid"],
                cwd=repo,
                check=True,
            )
            subprocess.run(
                ["git", "config", "user.name", "Test"],
                cwd=repo,
                check=True,
            )
            (repo / "source").write_text("source\n", encoding="utf-8")
            subprocess.run(["git", "add", "source"], cwd=repo, check=True)
            subprocess.run(["git", "commit", "-m", "source"], cwd=repo, check=True)
            source = subprocess.check_output(
                ["git", "rev-parse", "HEAD"], cwd=repo, text=True
            ).strip()
            (repo / "advance").write_text("advance\n", encoding="utf-8")
            subprocess.run(["git", "add", "advance"], cwd=repo, check=True)
            subprocess.run(["git", "commit", "-m", "advance"], cwd=repo, check=True)
            advanced_main = subprocess.check_output(
                ["git", "rev-parse", "HEAD"], cwd=repo, text=True
            ).strip()

            registry_release.validate_candidate_ancestry(
                repo,
                source_sha=source,
                workflow_revision=source,
                protected_main_sha=advanced_main,
            )

            tree = subprocess.check_output(
                ["git", "rev-parse", f"{source}^{{tree}}"], cwd=repo, text=True
            ).strip()
            unrelated = subprocess.check_output(
                ["git", "commit-tree", tree, "-m", "unrelated"],
                cwd=repo,
                text=True,
            ).strip()
            with self.assertRaisesRegex(
                registry_release.ReleasePlanError,
                "not reachable from protected main",
            ):
                registry_release.validate_candidate_ancestry(
                    repo,
                    source_sha=unrelated,
                    workflow_revision=source,
                    protected_main_sha=advanced_main,
                )

    def test_candidate_artifact_download_removes_transport_archive(self) -> None:
        registry_release = load_registry_release()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            destination = root / "candidate" / "payload"
            archive = destination.parent / "artifact-42.zip"

            def download(_endpoint: str, path: Path) -> None:
                self.assertTrue(path.parent.is_dir())
                path.write_bytes(b"archive")

            def extract(
                path: Path,
                output: Path,
                *,
                expected_sha256: str,
            ) -> None:
                self.assertEqual(archive, path)
                self.assertEqual("a" * 64, expected_sha256)
                output.mkdir()
                (output / "payload.txt").write_text("verified\n", encoding="utf-8")

            with (
                mock.patch.object(
                    registry_release,
                    "download_gh_api_bytes",
                    side_effect=download,
                ),
                mock.patch.object(
                    registry_release.release_candidate,
                    "extract_artifact_archive",
                    side_effect=extract,
                ),
            ):
                registry_release.download_candidate_artifact(
                    "registrystack/registry-stack",
                    42,
                    destination,
                    expected_archive_sha256="a" * 64,
                )

            self.assertFalse(archive.exists())
            self.assertEqual(
                "verified\n",
                (destination / "payload.txt").read_text(encoding="utf-8"),
            )

    def test_candidate_artifact_download_removes_archive_after_rejection(self) -> None:
        registry_release = load_registry_release()
        with tempfile.TemporaryDirectory() as tmp:
            destination = Path(tmp) / "candidate" / "payload"
            archive = destination.parent / "artifact-42.zip"

            def download(_endpoint: str, path: Path) -> None:
                path.write_bytes(b"archive")

            with (
                mock.patch.object(
                    registry_release,
                    "download_gh_api_bytes",
                    side_effect=download,
                ),
                mock.patch.object(
                    registry_release.release_candidate,
                    "extract_artifact_archive",
                    side_effect=registry_release.release_candidate.CandidateError(
                        "digest mismatch"
                    ),
                ),
                self.assertRaisesRegex(
                    registry_release.ReleasePlanError,
                    "cannot verify candidate artifact 42: digest mismatch",
                ),
            ):
                registry_release.download_candidate_artifact(
                    "registrystack/registry-stack",
                    42,
                    destination,
                    expected_archive_sha256="a" * 64,
                )

            self.assertFalse(archive.exists())




    def test_required_ci_contexts_wrap_path_gated_jobs(self) -> None:
        workflow = yaml.safe_load(
            (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
        )
        jobs = workflow["jobs"]
        required_contexts = {
            "release-tool": (
                "release-tool-required",
                "Release tooling",
                "release_tool",
            ),
            "release-source-proof": (
                "release-source-proof-required",
                "Release source proof",
                "release_source_proof",
            ),
            "docs": (
                "docs-required",
                "Docs",
                "docs",
            ),
        }

        for check_job_id, (
            required_job_id,
            context_name,
            path_output,
        ) in required_contexts.items():
            with self.subTest(context=context_name):
                check_job = jobs[check_job_id]
                self.assertEqual(f"{context_name} checks", check_job["name"])
                self.assertEqual(
                    f"needs.changes.outputs.{path_output} == 'true'",
                    check_job["if"],
                )

                required_job = jobs[required_job_id]
                self.assertEqual(context_name, required_job["name"])
                expected_needs = {"changes", check_job_id}
                if check_job_id == "docs":
                    expected_needs.add("docs-archives")
                self.assertEqual(expected_needs, set(required_job["needs"]))
                self.assertEqual("${{ always() }}", required_job["if"])
                self.assertEqual(1, len(required_job["steps"]))
                step = required_job["steps"][0]
                self.assertEqual(
                    "${{ needs.changes.result }}",
                    step["env"]["CHANGES_RESULT"],
                )
                self.assertEqual(
                    f"${{{{ needs.changes.outputs.{path_output} }}}}",
                    step["env"]["REQUIRED"],
                )
                self.assertEqual(
                    f"${{{{ needs.{check_job_id}.result }}}}",
                    step["env"]["RESULT"],
                )
                self.assertIn(
                    "success:true:success|success:false:skipped",
                    step["run"],
                )

    def test_required_rust_context_aggregates_path_gated_shards(self) -> None:
        workflow = yaml.safe_load(
            (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
        )
        jobs = workflow["jobs"]
        rust_result = jobs["rust-result"]

        self.assertEqual("Rust workspace", rust_result["name"])
        self.assertEqual("always()", rust_result["if"])
        self.assertEqual(
            {
                "changes",
                "rust-policy",
                "rust-quality",
                "rust-tests",
                "discovery-contracts",
                "evidence-contracts",
                "identifiers",
                "breg-contracts",
                "relay-client-contracts",
                "relay-v2-contracts",
            },
            set(rust_result["needs"]),
        )
        self.assertEqual(
            "${{ toJSON(needs) }}",
            rust_result["env"]["RUST_JOB_RESULTS"],
        )
        self.assertEqual(1, len(rust_result["steps"]))
        self.assertIn(
            'details["result"] not in {"success", "skipped"}',
            rust_result["steps"][0]["run"],
        )




    def test_debian13_contract_binds_builder_to_candidate_workflow(self) -> None:
        module = load_debian13_image_check()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for relative in module.MAINTAINED_TEXT_PATHS:
                destination = root / relative
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.write_text(
                    (ROOT / relative).read_text(encoding="utf-8"),
                    encoding="utf-8",
                )

            candidate_path = root / ".github/workflows/release-candidate.yml"
            candidate = candidate_path.read_text(encoding="utf-8").replace(
                f"  RELEASE_BUILDER_IMAGE: {module.RUST_BUILDER}\n",
                "",
                1,
            )
            candidate_path.write_text(candidate, encoding="utf-8")

            release_path = root / ".github/workflows/release.yml"
            release = release_path.read_text(encoding="utf-8").replace(
                "env:\n",
                f"env:\n  RELEASE_BUILDER_IMAGE: {module.RUST_BUILDER}\n",
                1,
            )
            release_path.write_text(release, encoding="utf-8")

            failures = module.check_repository(root)
            self.assertTrue(
                any(
                    ".github/workflows/release-candidate.yml: missing pinned "
                    "Debian 13 release builder" in failure
                    for failure in failures
                )
            )
            self.assertTrue(
                any(
                    "promotion workflow must not rebuild candidate artifacts"
                    in failure
                    for failure in failures
                )
            )

    def test_contributing_documents_major_functionality_test_policy(self) -> None:
        text = (ROOT / "CONTRIBUTING.md").read_text(encoding="utf-8")

        self.assertIn("major new functionality MUST add", text)
        self.assertIn("automated test suite", text)
        self.assertIn("change proposal or pull request", text)

    def test_contributing_documents_proportional_repeatability_policy(self) -> None:
        text = (ROOT / "CONTRIBUTING.md").read_text(encoding="utf-8")

        self.assertIn("Repeatable Builds And Generated Outputs", text)
        self.assertIn("built once from an exact protected-main commit", text)
        self.assertIn(".github/workflows/release-candidate.yml", text)
        self.assertIn("not a\nduplicate build in every ordinary Beta", text)


    def test_release_image_packaging_uses_release_dockerfiles(self) -> None:
        workflow = (ROOT / ".github/workflows/release-candidate.yml").read_text(
            encoding="utf-8"
        )
        recipe = (ROOT / "release/scripts/build-release-image.sh").read_text(
            encoding="utf-8"
        )
        release_dockerfiles = [
            "release/docker/Dockerfile.discovery",
            "release/docker/Dockerfile.evidence",
            "release/docker/Dockerfile.mint",
            "release/docker/Dockerfile.breg",
            "release/docker/Dockerfile.relay",
        ]

        for dockerfile in release_dockerfiles:
            self.assertIn("release/docker/Dockerfile.${name}", recipe)
            text = (ROOT / dockerfile).read_text(encoding="utf-8")
            self.assertIn("dist/image-bin", text)
        self.assertFalse((ROOT / "release/docker/Dockerfile.registry-relay").exists())
        self.assertIn("release/scripts/build-release-image.sh", workflow)

    def test_candidate_checks_current_image_labels_before_credentials_and_scanning(
        self,
    ) -> None:
        workflow = (ROOT / ".github/workflows/release-candidate.yml").read_text(
            encoding="utf-8"
        )
        checker = "python3 release/scripts/check-release-image-oci-labels.py"
        self.assertEqual(2, workflow.count(checker))
        first_check = workflow.index(checker)
        second_check = workflow.index(checker, first_check + 1)
        for start in (first_check, second_check):
            invocation = workflow[start : start + 500]
            self.assertIn('--source "https://github.com/${GITHUB_REPOSITORY}"', invocation)
            self.assertIn('--revision "${{ needs.validate.outputs.source_sha }}"', invocation)
            self.assertIn('--version "${{ needs.validate.outputs.version }}"', invocation)
        self.assertNotIn("--expected-label", workflow)

        local_check = workflow.index(
            "Verify local image layouts before package credentials are used"
        )
        registry_login = workflow.index("oras login", local_check)
        self.assertLess(first_check, registry_login)

        candidate_check = second_check
        scan = workflow.index('scan_image \\\n              "${candidate_ref}"', candidate_check)
        self.assertLess(candidate_check, scan)

    def test_release_builds_and_packages_evidence_oid4vci_on_every_platform(self) -> None:
        workflow = (ROOT / ".github/workflows/release-candidate.yml").read_text(
            encoding="utf-8"
        )
        platform_job = workflow[
            workflow.index("\n  build-platforms:") : workflow.index("\n  clients:")
        ]
        linux_recipe = (ROOT / "release/scripts/build-release-binaries.sh").read_text(
            encoding="utf-8"
        )
        installer = (ROOT / "crates/registry-evidencectl/install.sh").read_text(
            encoding="utf-8"
        )

        self.assertIn("-p registry-evidence-oid4vci", platform_job)
        self.assertIn(
            "for evidence_binary in evidence evidencectl mint evidence-oid4vci",
            platform_job,
        )
        self.assertIn("-p registry-evidence-oid4vci", linux_recipe)
        self.assertIn(
            '"evidence-oid4vci-${tag}-linux-amd64"',
            linux_recipe,
        )
        self.assertIn(
            "binaries=(evidence evidencectl mint evidence-oid4vci)", installer
        )
        self.assertIn(
            'EVIDENCECTL_INSTALL_DIR="${evidence_install_dir}"', workflow
        )
        self.assertIn(
            "for binary in evidence evidencectl mint evidence-oid4vci",
            workflow,
        )

    def test_release_builds_installs_and_smokes_breg_from_v0_26(self) -> None:
        workflow = (ROOT / ".github/workflows/release-candidate.yml").read_text(
            encoding="utf-8"
        )
        platform_job = workflow[
            workflow.index("\n  build-platforms:") : workflow.index("\n  clients:")
        ]
        assemble = workflow.split("\n  assemble:", 1)[1].split("\n  attest:", 1)[0]
        installer = ROOT / "crates/registry-breg/install.sh"
        installer_text = installer.read_text(encoding="utf-8")

        self.assertIn("release_minor >= 26", platform_job)
        self.assertIn("-p registry-breg --bin breg --features runtime", platform_job)
        self.assertIn("-p registry-bregctl", platform_job)
        self.assertIn(
            "for breg_binary in breg bregctl",
            platform_job,
        )
        self.assertIn(
            'breg_installer="breg-${{ needs.validate.outputs.tag }}-install.sh"',
            assemble,
        )
        self.assertIn("crates/registry-breg/install.sh", assemble)
        self.assertIn("BREG_ASSET_DIR", assemble)
        self.assertIn("BREG_INSTALL_DIR", assemble)
        self.assertIn('init "${breg_project}"', assemble)
        self.assertIn('check "${breg_project}"', assemble)
        self.assertIn(
            "binaries=(breg bregctl)", installer_text
        )

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            assets = root / "assets"
            destination = root / "bin"
            assets.mkdir()
            os_name = subprocess.run(
                ["uname", "-s"], check=True, capture_output=True, text=True
            ).stdout.strip()
            architecture = subprocess.run(
                ["uname", "-m"], check=True, capture_output=True, text=True
            ).stdout.strip()
            if os_name == "Darwin" and architecture in {"arm64", "aarch64"}:
                platform_name = "macos-arm64"
            elif os_name == "Linux" and architecture in {"x86_64", "amd64"}:
                platform_name = "linux-amd64"
            elif os_name == "Linux" and architecture in {"arm64", "aarch64"}:
                platform_name = "linux-arm64"
            else:
                raise SkipTest(f"installer has no release asset for {os_name}/{architecture}")
            checksums = []
            for binary in ("breg", "bregctl"):
                name = f"{binary}-v0.26.0-{platform_name}"
                body = f"{binary} fixture\n".encode()
                (assets / name).write_bytes(body)
                checksums.append(f"{hashlib.sha256(body).hexdigest()}  {name}\n")
            (assets / "SHA256SUMS").write_text("".join(checksums), encoding="utf-8")
            environment = os.environ.copy()
            environment.update(
                {
                    "BREG_VERSION": "v0.26.0",
                    "BREG_ASSET_DIR": str(assets),
                    "BREG_INSTALL_DIR": str(destination),
                }
            )
            result = subprocess.run(
                ["bash", str(installer)],
                env=environment,
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(0, result.returncode, result.stderr)
            for binary in ("breg", "bregctl"):
                installed = destination / binary
                self.assertEqual(f"{binary} fixture\n", installed.read_text())
                self.assertTrue(installed.stat().st_mode & stat.S_IXUSR)







    def test_release_image_scans_are_policy_enforced_and_preserved(self) -> None:
        workflow = (ROOT / ".github/workflows/release-candidate.yml").read_text(
            encoding="utf-8"
        )
        assemble = workflow.split("\n  assemble:", 1)[1].split("\n  attest:", 1)[0]
        scan_step = assemble.index("Verify and scan exact candidate images")
        package_step = assemble.index(
            "Assemble public payload and validate version-appropriate install inputs"
        )
        self.assertLess(scan_step, package_step)
        scan_body = assemble[scan_step:package_step]
        self.assertIn("scan_image() {", scan_body)
        self.assertIn('grype "${image_ref}" -o json > "${report}"', scan_body)
        self.assertIn("set +e", scan_body)
        self.assertIn('status=$?', scan_body)
        status_guard = scan_body.index("if (( status != 0 )); then")
        failure = scan_body.index(
            'echo "Grype failed (exit ${status}); refusing candidate scan" >&2',
            status_guard,
        )
        failure_exit = scan_body.index("exit 1", failure)
        report_validation = scan_body.index("if ! jq -e '", failure_exit)
        self.assertLess(status_guard, failure)
        self.assertLess(failure, failure_exit)
        self.assertLess(failure_exit, report_validation)
        self.assertIn('(.matches | type == "array")', scan_body)
        self.assertIn('(.source.type == "image")', scan_body)
        self.assertIn(
            ".descriptor.db.built // .descriptor.db.status.built",
            scan_body,
        )
        self.assertIn(
            'test("checksum=sha256%3A[0-9a-fA-F]{64}")',
            scan_body,
        )
        self.assertIn(
            "Grype did not emit a complete scan report",
            scan_body,
        )
        self.assertNotIn("::warning::Grype exited", scan_body)
        self.assertIn("now_epoch - db_built_epoch > 259200", scan_body)
        self.assertIn("for name in ${RELEASE_IMAGE_NAMES}; do", scan_body)
        self.assertIn(
            "candidate/security/image-sbom/${name}.spdx.json",
            scan_body,
        )
        self.assertIn("candidate/security/syft/${name}.syft.json", scan_body)
        self.assertIn("candidate/security/grype/${name}.grype.json", scan_body)
        self.assertIn("SYFT_FILE_METADATA_SELECTION=all", scan_body)
        self.assertIn("SYFT_FILE_METADATA_DIGESTS=sha256", scan_body)
        self.assertIn('crane export "${candidate_ref}" -', scan_body)
        self.assertIn(
            'candidate/security/oci-config/${name}.json',
            scan_body,
        )
        self.assertIn('crane config "${candidate_ref}"', scan_body)
        self.assertIn(
            '.architecture == "amd64"',
            scan_body,
        )
        self.assertIn('.os == "linux"', scan_body)
        self.assertIn('(.config | type == "object")', scan_body)
        self.assertIn('(.rootfs.type == "layers")', scan_body)
        self.assertIn('((.rootfs.diff_ids | type) == "array")', scan_body)
        self.assertIn('(.rootfs.diff_ids | length > 0)', scan_body)
        self.assertIn(
            '--directory="candidate/security/rootfs/${name}"', scan_body
        )
        self.assertIn("contains a forbidden special file", scan_body)
        self.assertIn(
            "python3 release/scripts/check-advisory-baselines.py",
            scan_body,
        )
        self.assertIn(
            "baseline=products/relay-v2/security/advisory-baseline.json",
            scan_body,
        )
        self.assertIn(
            '--syft-report "candidate/security/syft/${name}.syft.json"',
            scan_body,
        )
        self.assertIn(
            '--rootfs "candidate/security/rootfs/${name}"',
            scan_body,
        )
        self.assertIn(
            '--candidate-image-digest "${digest}"',
            scan_body,
        )
        self.assertIn(
            '--source-revision "${{ needs.validate.outputs.source_sha }}"',
            scan_body,
        )
        self.assertIn(
            '--oci-config "candidate/security/oci-config/${name}.json"',
            scan_body,
        )
        self.assertIn(
            'baseline="release/security/${name}-advisory-baseline.json"',
            scan_body,
        )
        self.assertIn('--subject "${name}-image"', scan_body)
        self.assertIn("for name in ${RELEASE_IMAGE_NAMES}; do", scan_body)
        self.assertIn("printf '%s-image\\n' \"${name}\"", scan_body)
        self.assertIn('--argjson subjects "${advisory_subjects}"', scan_body)
        self.assertIn("docker run --rm", scan_body)
        self.assertIn("--network none", scan_body)
        self.assertIn("--read-only", scan_body)
        self.assertIn("--cap-drop ALL", scan_body)
        self.assertIn("--security-opt no-new-privileges", scan_body)
        self.assertIn("rm -rf candidate/security/rootfs", scan_body)
        self.assertNotIn("postgresql", scan_body.lower())
        self.assertNotIn("registry-relay", scan_body)
        package_body = assemble[package_step:]
        self.assertIn(
            "image-sbom syft grype advisory-verdict.json",
            package_body,
        )
        self.assertNotIn(
            "cp candidate/security/grype/*.grype.json",
            package_body,
        )

    def test_candidate_workflow_uses_only_the_current_release_roster(self) -> None:
        workflow = (ROOT / ".github/workflows/release-candidate.yml").read_text(
            encoding="utf-8"
        )
        canonical = workflow.split("\n  build-canonical:", 1)[1].split(
            "\n  build-platforms:", 1
        )[0]
        binary_recipe = (ROOT / "release/scripts/build-release-binaries.sh").read_text(
            encoding="utf-8"
        )

        for current in (
            "relay-${{ needs.validate.outputs.tag }}-linux-amd64",
            "relayctl-${{ needs.validate.outputs.tag }}-linux-amd64",
            "release_candidate.py image-names",
            "RELEASE_IMAGE_NAMES: ${{ needs.validate.outputs.image_names }}",
            "echo \"image_names=${release_image_names}\"",
            "-p registry-relayctl",
        ):
            self.assertIn(current, workflow)
        self.assertIn("registry-manifest-${RELEASE_TAG}-linux-amd64", binary_recipe)
        for retired in (
            "-p registryctl ",
            "for name in registry-relay; do",
            "registry-relay-rhai-worker",
            "registryctl-${{ needs.validate.outputs.tag }}-install.sh",
            "registryctl-postgresql-image.ref",
            "render-registryctl-image-lock",
            "*-image-lock.json",
            "check-registryctl-tutorials.sh",
            "import-map-2026-06-24.yaml",
        ):
            self.assertNotIn(retired, workflow)
        cache_key = next(
            line.strip() for line in canonical.splitlines() if line.strip().startswith("key:")
        )
        self.assertIn("Cargo.lock", cache_key)
        self.assertIn("--locked", workflow)
        self.assertIn(
            "GHCR package ${package} must be provisioned before release",
            workflow,
        )
        self.assertIn('candidate_package="${package}-candidate"', workflow)
        self.assertIn('elif [[ "${candidate_package_status}" != 404 ]]', workflow)
        self.assertIn('elif [[ "${package_status}" != 404 ]]', workflow)
        self.assertLess(
            workflow.index('elif [[ "${package_status}" != 404 ]]'),
            workflow.index("oras cp --from-oci-layout"),
        )
        self.assertIn("require-package-visibility", workflow)

    def test_publication_omits_legacy_image_lock_from_v0_19(self) -> None:
        workflow = (ROOT / ".github/workflows/release.yml").read_text(
            encoding="utf-8"
        )

        self.assertNotIn("registryctl", workflow)
        self.assertNotIn("image-lock", workflow)
        self.assertNotIn("if ((minor < 19)); then", workflow)
        promotion = workflow.split("\n  promote-images:", 1)[1].split(
            "\n  finalize-assets:", 1
        )[0]
        self.assertIn("require-package-visibility", promotion)
        self.assertIn("--visibility public", promotion)
        self.assertNotIn("if ((minor >= 19)); then", workflow)
        self.assertNotIn("if ((minor < 19)); then", workflow)
        major, minor, _patch = (int(part) for part in "1.0.0".split("."))
        self.assertTrue(major > 0 or minor >= 19)

    def test_release_canary_exercises_the_current_image_contract(self) -> None:
        workflow = (ROOT / ".github/workflows/release-canary.yml").read_text(
            encoding="utf-8"
        )

        for current in (
            "_relay_v2_payload_inventory",
            "payloads: $payloads[0]",
            "image_names=(relay evidence mint discovery breg)",
            "images: $images[0]",
            "scans: $scans[0]",
            '"discovery-image"',
            '"evidence-image"',
            '"mint-image"',
            '"breg-image"',
            '"relay-image"',
        ):
            self.assertIn(current, workflow)
        for retired in (
            "registry-relay",
            "registryctl-",
            "postgresql",
        ):
            self.assertNotIn(retired, workflow)

    def test_relay_scan_workflow_contract_detects_structural_mutations(
        self,
    ) -> None:
        workflow = (ROOT / ".github/workflows/release-candidate.yml").read_text(
            encoding="utf-8"
        )
        assemble = workflow.split("\n  assemble:", 1)[1].split("\n  attest:", 1)[0]

        def assert_contract(text: str) -> None:
            for fragment in (
                'grype "${image_ref}" -o json > "${report}"',
                'if (( status != 0 )); then\n'
                '              echo "Grype failed (exit ${status}); refusing candidate scan" >&2\n'
                "              exit 1\n"
                "            fi",
                "Grype did not emit a complete scan report",
                "now_epoch - db_built_epoch > 259200",
                "products/relay-v2/security/advisory-baseline.json",
                'release/security/${name}-advisory-baseline.json',
                "printf '%s-image\\n' \"${name}\"",
                '--argjson subjects "${advisory_subjects}"',
                "image-sbom syft grype advisory-verdict.json",
            ):
                self.assertIn(fragment, text)

        assert_contract(assemble)
        for fragment in (
            'grype "${image_ref}" -o json > "${report}"',
            'if (( status != 0 )); then\n'
            '              echo "Grype failed (exit ${status}); refusing candidate scan" >&2\n'
            "              exit 1\n"
            "            fi",
            "Grype did not emit a complete scan report",
            "now_epoch - db_built_epoch > 259200",
            "products/relay-v2/security/advisory-baseline.json",
            'release/security/${name}-advisory-baseline.json',
            "printf '%s-image\\n' \"${name}\"",
            '--argjson subjects "${advisory_subjects}"',
            "image-sbom syft grype advisory-verdict.json",
        ):
            with self.subTest(fragment=fragment):
                with self.assertRaises(AssertionError):
                    assert_contract(assemble.replace(fragment, "", 1))



    def test_release_packaging_uses_relay_v2_artifact_identities(self) -> None:
        binary_recipe = (ROOT / "release/scripts/build-release-binaries.sh").read_text(
            encoding="utf-8"
        )
        image_recipe = (ROOT / "release/scripts/build-release-image.sh").read_text(
            encoding="utf-8"
        )
        release_dockerfiles = {
            name: (ROOT / f"release/docker/Dockerfile.{name}").read_text(
                encoding="utf-8"
            )
            for name in (
                "discovery",
                "evidence",
                "mint",
                "breg",
                "relay",
            )
        }

        self.assertIn("-p registry-manifest-cli", binary_recipe)
        self.assertIn("-p registry-relay-v2", binary_recipe)
        self.assertIn("--bin relay", binary_recipe)
        self.assertIn("--no-default-features", binary_recipe)
        self.assertIn("-p registry-relayctl", binary_recipe)
        self.assertIn("-p registry-discovery", binary_recipe)
        self.assertIn("--bin discovery", binary_recipe)
        for artifact in ("discovery", "registry-manifest", "relay", "relayctl"):
            self.assertIn(
                f'"dist/bin/{artifact}-${{RELEASE_TAG}}-linux-amd64"',
                binary_recipe,
            )
        self.assertNotIn("-p registryctl ", binary_recipe)
        self.assertNotIn("-p registry-relay ", binary_recipe)
        self.assertNotIn("registry-relay-rhai-worker", binary_recipe)
        for name in (
            "discovery",
            "evidence",
            "mint",
            "breg",
            "relay",
        ):
            self.assertIn(
                f"cp target/release/{name} dist/image-bin/{name}",
                binary_recipe,
            )
            self.assertIn(
                f"install -m 0755 /workspace/image-bin/{name} "
                f"/workspace/runtime-root/usr/local/bin/{name}",
                release_dockerfiles[name],
            )
        self.assertIn("discovery|evidence|mint|breg|relay)", image_recipe)
        self.assertNotIn("registry-relay)", image_recipe)

    def test_breg_release_image_keeps_deployment_inputs_external(self) -> None:
        dockerfile = (
            ROOT / "release/docker/Dockerfile.breg"
        ).read_text(encoding="utf-8")
        bind_mounts = [
            line.strip()
            for line in dockerfile.splitlines()
            if "--mount=type=bind,source=" in line
        ]
        copy_instructions = [
            line.strip()
            for line in dockerfile.splitlines()
            if line.lstrip().startswith(("COPY ", "ADD "))
        ]

        self.assertEqual(
            [
                "RUN --mount=type=bind,source=dist/image-bin,target=/workspace/image-bin \\",
                "--mount=type=bind,source=LICENSE,target=/workspace/LICENSE \\",
            ],
            bind_mounts,
        )
        self.assertEqual(
            ["COPY --from=runtime-root /workspace/runtime-root/ /"],
            copy_instructions,
        )
        self.assertNotIn("bregctl", dockerfile)

    def test_discovery_runtime_artifact_joins_the_inventory_at_v0_24(self) -> None:
        module = load_registry_release()
        without_discovery = {
            name: "0.24.0"
            for name in (
                *module.RELAY_V2_ARTIFACT_INVENTORY,
                "relay-installer",
                "registry-docs",
                "relay-client-node",
                "relay-client-python",
                "discovery-client-node",
                "discovery-client-python",
            )
        }

        self.assertNotEqual(
            [], module.artifact_inventory_errors("0.24.0", without_discovery)
        )
        self.assertEqual(
            [],
            module.artifact_inventory_errors(
                "0.24.0", without_discovery | {"discovery": "0.24.0"}
            ),
        )
        self.assertEqual(
            [],
            module.artifact_inventory_errors(
                "0.23.0", {name: "0.23.0" for name in without_discovery}
            ),
        )
        self.assertNotEqual(
            [],
            module.artifact_inventory_errors(
                "0.23.0",
                {name: "0.23.0" for name in without_discovery}
                | {"discovery": "0.23.0"},
            ),
        )

    def test_binary_recipe_stages_discovery_only_from_its_first_release(self) -> None:
        # The recipe runs for every supported version, including a rebuilt
        # candidate for a version whose recorded inventory predates Discovery.
        # Run the recipe's own gate rather than a copy of it.
        recipe = (ROOT / "release/scripts/build-release-binaries.sh").read_text(
            encoding="utf-8"
        )
        start = recipe.index("IFS=. read -r version_major")
        end = recipe.index("fi\n", recipe.index("include_discovery=1")) + len("fi\n")
        gate = recipe[start:end]

        def include_discovery(version: str) -> str:
            completed = subprocess.run(
                [
                    "bash",
                    "-c",
                    "set -euo pipefail\n"
                    'version="$1"\n'
                    f"{gate}"
                    'printf "%s" "${include_discovery}"',
                    "build-release-binaries",
                    version,
                ],
                capture_output=True,
                text=True,
                check=True,
            )
            return completed.stdout

        for version in ("0.19.0", "0.21.0", "0.23.0", "0.23.9"):
            with self.subTest(version=version):
                self.assertEqual("0", include_discovery(version))
        for version in ("0.24.0", "0.24.1", "0.25.0", "1.0.0"):
            with self.subTest(version=version):
                self.assertEqual("1", include_discovery(version))

        # The staged asset lists follow the same gate, so an earlier candidate
        # neither checksums nor chmods an asset the recipe did not build.
        self.assertIn(
            'bin_assets+=("discovery-${tag}-linux-amd64")',
            recipe,
        )
        self.assertIn("image_bin_binaries+=(discovery)", recipe)

    def test_breg_release_surface_begins_at_v0_26(self) -> None:
        module = load_registry_release()
        current = {
            name: "0.26.0"
            for name in (
                *module.RELAY_V2_ARTIFACT_INVENTORY,
                "relay-installer",
                "registry-docs",
                "relay-client-node",
                "relay-client-python",
                "discovery-client-node",
                "discovery-client-python",
                "discovery",
            )
        }
        breg = {
            "breg": "0.26.0",
            "bregctl": "0.26.0",
            "breg-installer": "0.26.0",
        }

        self.assertNotEqual(
            [], module.artifact_inventory_errors("0.26.0", current)
        )
        self.assertEqual(
            [],
            module.artifact_inventory_errors(
                "0.26.0", current | breg
            ),
        )
        self.assertEqual(
            [],
            module.artifact_inventory_errors(
                "0.25.0", {name: "0.25.0" for name in current}
            ),
        )

        recipe = (ROOT / "release/scripts/build-release-binaries.sh").read_text(
            encoding="utf-8"
        )
        self.assertIn("RELEASE_INCLUDE_BREG", recipe)
        self.assertIn("-p registry-breg", recipe)
        self.assertIn("--features runtime", recipe)
        self.assertIn("-p registry-bregctl", recipe)
        self.assertIn(
            '"breg-${tag}-linux-amd64"', recipe
        )
        self.assertIn(
            '"bregctl-${tag}-linux-amd64"', recipe
        )
        self.assertIn("image_bin_binaries+=(breg)", recipe)
        builder = (ROOT / "release/docker/Dockerfile.builder").read_text(
            encoding="utf-8"
        )
        self.assertIn("release/docker/Dockerfile.builder", recipe)
        self.assertIn("20250810T000000Z", builder)
        self.assertIn("libclang-19-dev=1:19.1.7-3+b1", builder)
        self.assertIn("protobuf-compiler=3.21.12-11", builder)
        self.assertIn("snapshot.debian.org/archive/debian/", builder)
        self.assertIn("RELEASE_BUILDER_READY=1", recipe)
        self.assertIn(
            "RELEASE_BUILDER_READY is internal to the canonical builder container",
            recipe,
        )
        self.assertIn('${repo_root}" != "/workspace"', recipe)
        self.assertIn('--user "$(id -u):$(id -g)"', recipe)

    def test_release_packaging_excludes_retired_notary(self) -> None:
        binary_recipe = (ROOT / "release/scripts/build-release-binaries.sh").read_text(
            encoding="utf-8"
        )
        image_recipe = (ROOT / "release/scripts/build-release-image.sh").read_text(
            encoding="utf-8"
        )
        self.assertNotIn("registry-notary", binary_recipe)
        self.assertNotIn("registry-notary", image_recipe)
        self.assertFalse(
            (ROOT / "release/docker/Dockerfile.registry-notary").exists()
        )

    def test_release_product_images_preown_managed_audit_and_state_directories(
        self,
    ) -> None:
        contracts = {
            "evidence": "/workspace/runtime-root/var/lib/registry-evidence/audit",
            "mint": "/workspace/runtime-root/var/lib/registry-mint/audit",
            "relay": "/workspace/runtime-root/var/lib/relay/audit",
        }
        for name, audit_path in contracts.items():
            with self.subTest(name=name):
                dockerfile = (
                    ROOT / f"release/docker/Dockerfile.{name}"
                ).read_text(encoding="utf-8")
                self.assertIn(audit_path, dockerfile)
                self.assertIn(f"chmod 0700 {audit_path}", dockerfile)

    def test_nightly_security_scans_the_exact_release_dockerfile_roster(self) -> None:
        workflow = (ROOT / ".github/workflows/nightly-security.yml").read_text(
            encoding="utf-8"
        )
        for name in (
            "discovery",
            "evidence",
            "mint",
            "breg",
            "relay",
        ):
            self.assertIn(
                f'Path("release/docker/Dockerfile.{name}")',
                workflow,
            )
        self.assertNotIn('glob("Dockerfile.registry-*")', workflow)










    def test_validate_docsets_matches_release_manifests(self) -> None:
        result = run_tool("validate-docsets")

        self.assertEqual(0, result.returncode, result.stderr)
        self.assertRegex(
            result.stdout,
            r"validated [1-9][0-9]* versioned docsets against release manifests",
        )

    def test_validate_docsets_rejects_external_ref_drift(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            manifest_dir, docsets = write_docset_fixture(root)
            data = yaml.safe_load(docsets.read_text(encoding="utf-8"))
            data["docsets"][0]["products"]["crosswalk"]["ref"] = "b" * 40
            docsets.write_text(yaml.safe_dump(data), encoding="utf-8")

            result = run_tool(
                "validate-docsets",
                "--manifest-dir",
                str(manifest_dir),
                "--docsets",
                str(docsets),
            )

        self.assertNotEqual(0, result.returncode)
        self.assertIn("external crosswalk ref", result.stderr)

    def test_validate_docsets_rejects_monorepo_ref_drift(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            manifest_dir, docsets = write_docset_fixture(root)
            data = yaml.safe_load(docsets.read_text(encoding="utf-8"))
            data["docsets"][0]["products"]["registry-stack"]["ref"] = "b" * 40
            docsets.write_text(yaml.safe_dump(data), encoding="utf-8")

            result = run_tool(
                "validate-docsets",
                "--manifest-dir",
                str(manifest_dir),
                "--docsets",
                str(docsets),
            )

        self.assertNotEqual(0, result.returncode)
        self.assertIn("product registry-stack ref", result.stderr)

    def test_validate_docsets_accepts_active_candidate_tag_refs(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            manifest_dir, docsets = write_docset_fixture(root)
            manifest_path = manifest_dir / "registry-stack-beta-6.yaml"
            manifest = yaml.safe_load(manifest_path.read_text(encoding="utf-8"))
            del manifest["stack"]["source_ref"]
            del manifest["stack"]["status"]
            manifest_path.write_text(
                yaml.safe_dump(manifest, sort_keys=False),
                encoding="utf-8",
            )
            data = yaml.safe_load(docsets.read_text(encoding="utf-8"))
            data["docsets"][0]["availability"] = "candidate"
            data["docsets"][0]["products"]["registry-stack"]["ref"] = "v0.8.0"
            docsets.write_text(
                yaml.safe_dump(data, sort_keys=False),
                encoding="utf-8",
            )

            result = run_tool(
                "validate-docsets",
                "--manifest-dir",
                str(manifest_dir),
                "--docsets",
                str(docsets),
            )

        self.assertEqual(0, result.returncode, result.stderr)

    def test_validate_docsets_rejects_active_candidate_tag_drift(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            manifest_dir, docsets = write_docset_fixture(root)
            manifest_path = manifest_dir / "registry-stack-beta-6.yaml"
            manifest = yaml.safe_load(manifest_path.read_text(encoding="utf-8"))
            del manifest["stack"]["source_ref"]
            del manifest["stack"]["status"]
            manifest_path.write_text(
                yaml.safe_dump(manifest, sort_keys=False),
                encoding="utf-8",
            )
            data = yaml.safe_load(docsets.read_text(encoding="utf-8"))
            data["docsets"][0]["availability"] = "candidate"
            data["docsets"][0]["products"]["registry-stack"]["ref"] = "v0.8.1"
            docsets.write_text(
                yaml.safe_dump(data, sort_keys=False),
                encoding="utf-8",
            )

            result = run_tool(
                "validate-docsets",
                "--manifest-dir",
                str(manifest_dir),
                "--docsets",
                str(docsets),
            )

        self.assertNotEqual(0, result.returncode)
        self.assertIn("product registry-stack ref", result.stderr)

    def test_validate_docsets_rejects_source_marker_drift(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            manifest_dir, docsets = write_docset_fixture(root)
            data = yaml.safe_load(docsets.read_text(encoding="utf-8"))
            data["docsets"][0]["source"] = "manual-docset"
            docsets.write_text(yaml.safe_dump(data), encoding="utf-8")

            result = run_tool(
                "validate-docsets",
                "--manifest-dir",
                str(manifest_dir),
                "--docsets",
                str(docsets),
            )

        self.assertNotEqual(0, result.returncode)
        self.assertIn("source 'manual-docset'", result.stderr)

    def test_validate_docsets_rejects_candidate_docs_for_released_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            manifest_dir, docsets = write_docset_fixture(root)
            manifest_path = manifest_dir / "registry-stack-beta-6.yaml"
            manifest = yaml.safe_load(manifest_path.read_text(encoding="utf-8"))
            manifest["stack"]["status"] = "released"
            manifest_path.write_text(
                yaml.safe_dump(manifest, sort_keys=False),
                encoding="utf-8",
            )
            data = yaml.safe_load(docsets.read_text(encoding="utf-8"))
            data["released"] = "v0.8.0"
            data["docsets"][0]["availability"] = "candidate"
            docsets.write_text(
                yaml.safe_dump(data, sort_keys=False),
                encoding="utf-8",
            )

            result = run_tool(
                "validate-docsets",
                "--manifest-dir",
                str(manifest_dir),
                "--docsets",
                str(docsets),
            )

        self.assertNotEqual(0, result.returncode)
        self.assertIn(
            "docset v0.8.0 availability must be 'released' because its "
            "release manifest status is 'released'",
            result.stderr,
        )

    def test_validate_docsets_rejects_stale_released_selector(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            manifest_dir, docsets = write_docset_fixture(root)
            manifest_path = manifest_dir / "registry-stack-beta-6.yaml"
            manifest = yaml.safe_load(manifest_path.read_text(encoding="utf-8"))
            manifest["stack"]["status"] = "released"
            manifest_path.write_text(
                yaml.safe_dump(manifest, sort_keys=False),
                encoding="utf-8",
            )
            data = yaml.safe_load(docsets.read_text(encoding="utf-8"))
            data["released"] = "v0.7.0"
            data["docsets"][0]["availability"] = "released"
            docsets.write_text(
                yaml.safe_dump(data, sort_keys=False),
                encoding="utf-8",
            )

            result = run_tool(
                "validate-docsets",
                "--manifest-dir",
                str(manifest_dir),
                "--docsets",
                str(docsets),
            )

        self.assertNotEqual(0, result.returncode)
        self.assertIn(
            "docsets.yaml released selector must be 'v0.8.0', the newest "
            "released manifest, not 'v0.7.0'",
            result.stderr,
        )

    def test_validate_docsets_rejects_missing_release_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _, docsets = write_docset_fixture(root)
            empty_manifest_dir = root / "empty-manifests"
            empty_manifest_dir.mkdir()

            result = run_tool(
                "validate-docsets",
                "--manifest-dir",
                str(empty_manifest_dir),
                "--docsets",
                str(docsets),
            )

        self.assertNotEqual(0, result.returncode)
        self.assertIn("has no release manifest", result.stderr)

    def test_validate_docsets_rejects_missing_archive_lock_entry(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            manifest_dir, docsets = write_docset_fixture(root)
            archive_lock = root / "archive-lock.yaml"
            archive_lock.write_text(
                yaml.safe_dump(
                    {
                        "schema_version": "registry-docs.archive-lock.v1",
                        "archives": {},
                    }
                ),
                encoding="utf-8",
            )

            result = run_tool(
                "validate-docsets",
                "--manifest-dir",
                str(manifest_dir),
                "--docsets",
                str(docsets),
                "--archive-lock",
                str(archive_lock),
            )

        self.assertNotEqual(0, result.returncode)
        self.assertIn("missing lock-backed docset v0.8.0", result.stderr)

    def test_validate_docsets_accepts_historical_and_dual_tree_archive_locks(
        self,
    ) -> None:
        shapes = (
            {
                "bundle_sha256": "a" * 64,
                "tree_sha256": "b" * 64,
            },
            {
                "bundle_sha256": "a" * 64,
                "root_tree_sha256": "b" * 64,
                "version_tree_sha256": "c" * 64,
            },
        )
        for entry in shapes:
            with self.subTest(fields=sorted(entry)), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                manifest_dir, docsets = write_docset_fixture(root)
                archive_lock = root / "archive-lock.yaml"
                archive_lock.write_text(
                    yaml.safe_dump(
                        {
                            "schema_version": "registry-docs.archive-lock.v1",
                            "archives": {"v0.8.0": entry},
                        },
                        sort_keys=False,
                    ),
                    encoding="utf-8",
                )

                result = run_tool(
                    "validate-docsets",
                    "--manifest-dir",
                    str(manifest_dir),
                    "--docsets",
                    str(docsets),
                    "--archive-lock",
                    str(archive_lock),
                )

            self.assertEqual(0, result.returncode, result.stderr)

    def test_validate_docsets_rejects_mixed_partial_and_open_archive_locks(
        self,
    ) -> None:
        invalid_entries = (
            (
                {
                    "bundle_sha256": "a" * 64,
                    "root_tree_sha256": "b" * 64,
                },
                "must contain exactly",
            ),
            (
                {
                    "bundle_sha256": "a" * 64,
                    "tree_sha256": "b" * 64,
                    "root_tree_sha256": "c" * 64,
                    "version_tree_sha256": "d" * 64,
                },
                "must contain exactly",
            ),
            (
                {
                    "bundle_sha256": "a" * 64,
                    "tree_sha256": "b" * 64,
                    "telemetry": "not promotion data",
                },
                "unknown field telemetry",
            ),
            (
                {
                    "bundle_sha256": "a" * 64,
                    "root_tree_sha256": "b" * 64,
                    "version_tree_sha256": "INVALID",
                },
                "version_tree_sha256 must be 64 lowercase hex characters",
            ),
        )
        for entry, expected in invalid_entries:
            with self.subTest(fields=sorted(entry)), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                manifest_dir, docsets = write_docset_fixture(root)
                archive_lock = root / "archive-lock.yaml"
                archive_lock.write_text(
                    yaml.safe_dump(
                        {
                            "schema_version": "registry-docs.archive-lock.v1",
                            "archives": {"v0.8.0": entry},
                        },
                        sort_keys=False,
                    ),
                    encoding="utf-8",
                )

                result = run_tool(
                    "validate-docsets",
                    "--manifest-dir",
                    str(manifest_dir),
                    "--docsets",
                    str(docsets),
                    "--archive-lock",
                    str(archive_lock),
                )

            self.assertNotEqual(0, result.returncode)
            self.assertIn(expected, result.stderr)

    def test_audit_import_map(self) -> None:
        result = run_tool("audit", "release/manifests/import-map-2026-06-24.yaml")
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertIn("audited 7 imports", result.stdout)

    def test_removed_stub_commands_are_not_registered(self) -> None:
        for command in ("classify-warning", "generate-docset", "collect-artifacts"):
            with self.subTest(command=command):
                result = run_tool(command)
                self.assertEqual(2, result.returncode)
                self.assertIn("invalid choice", result.stderr)

    def test_validate_rejects_mismatched_source_tag(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            manifest = write_manifest(Path(tmp), source_tag="v9.9.9")
            result = run_tool("validate", str(manifest))
        self.assertNotEqual(0, result.returncode)
        self.assertIn("stack.source_tag must be v0.19.0", result.stderr)

    def test_validate_rejects_head_for_non_draft_release(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            manifest = write_manifest(
                Path(tmp), source_ref="HEAD", status="release-candidate"
            )
            result = run_tool("validate", str(manifest))
        self.assertNotEqual(0, result.returncode)
        self.assertIn("stack.source_ref may be HEAD only", result.stderr)

    def test_validate_accepts_active_manifest_without_future_source_or_status(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            manifest = write_manifest(Path(tmp), version="0.19.0")
            data = yaml.safe_load(manifest.read_text(encoding="utf-8"))
            data["stack"].pop("source_ref")
            data["stack"].pop("status")
            manifest.write_text(
                yaml.safe_dump(data, sort_keys=False),
                encoding="utf-8",
            )

            result = run_tool("validate", str(manifest))

        self.assertEqual(0, result.returncode, result.stderr)
        self.assertIn("validated", result.stdout)

    def test_validate_current_selects_highest_semver_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            manifest_dir = Path(tmp) / "manifests"
            manifest_dir.mkdir()
            source_ref = git(ROOT, "rev-parse", "HEAD")
            for version, release_id in (
                ("0.91.0", "beta-29"),
                ("0.92.0", "beta-30"),
            ):
                manifest = write_manifest(
                    manifest_dir,
                    version=version,
                    source_ref=source_ref,
                )
                data = yaml.safe_load(manifest.read_text(encoding="utf-8"))
                data["stack"]["release"] = release_id
                data["stack"].pop("source_ref")
                data["stack"].pop("status")
                manifest.write_text(
                    yaml.safe_dump(data, sort_keys=False), encoding="utf-8"
                )
                manifest.rename(manifest_dir / f"registry-stack-{release_id}.yaml")

            result = run_tool(
                "validate-current",
                "--manifest-dir",
                str(manifest_dir),
            )

        self.assertEqual(0, result.returncode, result.stderr)
        self.assertIn("beta-30 0.92.0", result.stdout)
        self.assertNotIn("beta-29", result.stdout)

    def test_validate_current_requires_a_release_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            result = run_tool(
                "validate-current",
                "--manifest-dir",
                tmp,
            )

        self.assertNotEqual(0, result.returncode)
        self.assertIn("no Registry Stack release manifests found", result.stderr)

    def test_validate_current_rejects_mismatched_release_identity(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            manifest_dir = Path(tmp) / "manifests"
            manifest_dir.mkdir()
            manifest = write_manifest(manifest_dir)
            manifest.rename(manifest_dir / "registry-stack-beta-29.yaml")

            result = run_tool(
                "validate-current",
                "--manifest-dir",
                str(manifest_dir),
            )

        self.assertNotEqual(0, result.returncode)
        self.assertIn(
            "filename registry-stack-beta-29.yaml does not match stack.release 'beta-6'",
            result.stderr,
        )

    def test_validate_current_rejects_invalid_release_id(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            manifest_dir = Path(tmp) / "manifests"
            manifest_dir.mkdir()
            manifest = write_manifest(manifest_dir)
            data = yaml.safe_load(manifest.read_text(encoding="utf-8"))
            data["stack"]["release"] = "invalid release"
            manifest = manifest_dir / "registry-stack-invalid-release.yaml"
            manifest.write_text(
                yaml.safe_dump(data, sort_keys=False), encoding="utf-8"
            )

            result = run_tool(
                "validate-current",
                "--manifest-dir",
                str(manifest_dir),
            )

        self.assertNotEqual(0, result.returncode)
        self.assertIn("release ID must start with", result.stderr)

    def test_validate_rejects_partially_removed_legacy_source_state(self) -> None:
        for removed in ("source_ref", "status"):
            with self.subTest(removed=removed), tempfile.TemporaryDirectory() as tmp:
                manifest = write_manifest(Path(tmp))
                data = yaml.safe_load(manifest.read_text(encoding="utf-8"))
                data["stack"].pop(removed)
                manifest.write_text(
                    yaml.safe_dump(data, sort_keys=False),
                    encoding="utf-8",
                )

                result = run_tool("validate", str(manifest))

            self.assertNotEqual(0, result.returncode)
            self.assertIn(
                "must both be present for a historical manifest or both omitted",
                result.stderr,
            )









    def test_validate_requires_exact_v0_19_adopter_inventory(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            manifest = write_manifest(Path(tmp), version="0.19.0")
            accepted = run_tool("validate", str(manifest))

            data = yaml.safe_load(manifest.read_text(encoding="utf-8"))
            del data["artifacts"]["relayctl"]
            data["artifacts"]["registryctl"] = "0.19.0"
            data["artifacts"]["registryctl-installer"] = "0.19.0"
            manifest.write_text(
                yaml.safe_dump(data, sort_keys=False), encoding="utf-8"
            )
            rejected = run_tool("validate", str(manifest))

        self.assertEqual(0, accepted.returncode, accepted.stderr)
        self.assertNotEqual(0, rejected.returncode)
        self.assertIn("missing relayctl", rejected.stderr)
        self.assertIn("unexpected registryctl", rejected.stderr)
        self.assertIn("registryctl-installer", rejected.stderr)

    def test_validate_v0_19_does_not_require_registryctl_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            manifest = write_manifest(Path(tmp), version="0.19.0")
            data = yaml.safe_load(manifest.read_text(encoding="utf-8"))

            result = run_tool("validate", str(manifest))

        self.assertEqual(0, result.returncode, result.stderr)
        self.assertNotIn("registryctl-image-lock", data["artifacts"])
        self.assertNotIn("registryctl-installer", data["artifacts"])
        self.assertNotIn("registry-docs", data["artifacts"])

    def test_validate_requires_exact_identifier_catalog_after_v0_19_0(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            catalog_source_ref = git(ROOT, "rev-parse", "HEAD")
            manifest = write_manifest(
                root,
                version="0.19.1",
                source_ref=catalog_source_ref,
            )
            accepted = run_tool("validate", str(manifest))

            data = yaml.safe_load(manifest.read_text(encoding="utf-8"))
            data["identifier_catalog"]["sha256"] = "0" * 64
            manifest.write_text(
                yaml.safe_dump(data, sort_keys=False), encoding="utf-8"
            )
            mismatched = run_tool("validate", str(manifest))

            missing = write_manifest(
                root,
                version="0.19.1",
                source_ref=catalog_source_ref,
            )
            data = yaml.safe_load(missing.read_text(encoding="utf-8"))
            del data["identifier_catalog"]
            missing.write_text(
                yaml.safe_dump(data, sort_keys=False), encoding="utf-8"
            )
            absent = run_tool("validate", str(missing))

        self.assertEqual(0, accepted.returncode, accepted.stderr)
        self.assertNotEqual(0, mismatched.returncode)
        self.assertIn("does not match the committed catalog bytes", mismatched.stderr)
        self.assertNotEqual(0, absent.returncode)
        self.assertIn("identifier_catalog is required", absent.stderr)

    def test_validate_uses_identifier_catalog_from_recorded_source_ref(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = init_repo(Path(tmp))
            catalog_path = (
                root / "products/identifiers/generated/catalog.v1.json"
            )
            catalog_path.parent.mkdir(parents=True)
            source_catalog = (
                ROOT / "products/identifiers/generated/catalog.v1.json"
            ).read_bytes()
            catalog_path.write_bytes(source_catalog)
            git(root, "add", str(catalog_path.relative_to(root)))
            git(root, "commit", "-m", "record release catalog")
            source_ref = git(root, "rev-parse", "HEAD")
            manifest = write_manifest(
                root,
                version="0.19.1",
                source_ref=source_ref,
                status="released",
            )

            catalog_path.write_text(
                json.dumps({"version": 1, "entries": [{"status": "active"}]})
                + "\n",
                encoding="utf-8",
            )
            accepted = run_tool("validate", str(manifest))

            data = yaml.safe_load(manifest.read_text(encoding="utf-8"))
            data["identifier_catalog"]["sha256"] = hashlib.sha256(
                catalog_path.read_bytes()
            ).hexdigest()
            manifest.write_text(
                yaml.safe_dump(data, sort_keys=False), encoding="utf-8"
            )
            mismatched = run_tool("validate", str(manifest))

        self.assertEqual(0, accepted.returncode, accepted.stderr)
        self.assertNotEqual(0, mismatched.returncode)
        self.assertIn("does not match the committed catalog bytes", mismatched.stderr)

    def test_validate_uses_identifier_catalog_from_existing_source_tag(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = init_repo(Path(tmp))
            catalog_path = root / "products/identifiers/generated/catalog.v1.json"
            catalog_path.parent.mkdir(parents=True)
            catalog_path.write_text(
                json.dumps({"version": 1, "entries": [{"status": "active"}]})
                + "\n",
                encoding="utf-8",
            )
            git(root, "add", str(catalog_path.relative_to(root)))
            git(root, "commit", "-m", "record tagged catalog")
            tagged_source = git(root, "rev-parse", "HEAD")
            git(root, "tag", "v0.19.1")
            manifest = write_manifest(
                root,
                version="0.19.1",
                source_ref=tagged_source,
            )
            data = yaml.safe_load(manifest.read_text(encoding="utf-8"))
            del data["stack"]["source_ref"]
            del data["stack"]["status"]
            manifest.write_text(
                yaml.safe_dump(data, sort_keys=False), encoding="utf-8"
            )

            catalog_path.write_text(
                json.dumps(
                    {
                        "version": 1,
                        "entries": [
                            {"status": "active"},
                            {"status": "active"},
                        ],
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            git(root, "add", str(catalog_path.relative_to(root)))
            git(root, "commit", "-m", "advance current catalog")
            accepted = run_tool("validate", str(manifest))

            data = yaml.safe_load(manifest.read_text(encoding="utf-8"))
            data["identifier_catalog"]["sha256"] = hashlib.sha256(
                catalog_path.read_bytes()
            ).hexdigest()
            data["identifier_catalog"]["entry_count"] = 2
            manifest.write_text(
                yaml.safe_dump(data, sort_keys=False), encoding="utf-8"
            )
            mismatched = run_tool("validate", str(manifest))

        self.assertEqual(0, accepted.returncode, accepted.stderr)
        self.assertNotEqual(0, mismatched.returncode)
        self.assertIn("does not match the committed catalog bytes", mismatched.stderr)

    def test_validate_copied_manifest_uses_tool_repository_source_tag(self) -> None:
        source = ROOT / "release/manifests/registry-stack-beta-32.yaml"
        with tempfile.TemporaryDirectory() as tmp:
            copied = Path(tmp) / source.name
            copied.write_bytes(source.read_bytes())
            result = run_tool("validate", str(copied))

        self.assertEqual(0, result.returncode, result.stderr)
        self.assertIn("validated", result.stdout)

    def test_relay_installer_joins_the_exact_inventory_after_v0_19_0(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            historical = write_manifest(root, version="0.19.0")
            historical_result = run_tool("validate", str(historical))
            historical_data = yaml.safe_load(
                historical.read_text(encoding="utf-8")
            )

            current = write_manifest(
                root,
                version="0.19.1",
                source_ref=git(ROOT, "rev-parse", "HEAD"),
            )
            current_result = run_tool("validate", str(current))
            data = yaml.safe_load(current.read_text(encoding="utf-8"))
            self.assertNotIn("relay-client-node", historical_data["artifacts"])
            self.assertEqual("0.19.1", data["artifacts"]["relay-client-node"])
            self.assertEqual("0.19.1", data["artifacts"]["relay-client-python"])
            del data["artifacts"]["relay-installer"]
            current.write_text(
                yaml.safe_dump(data, sort_keys=False), encoding="utf-8"
            )
            missing_result = run_tool("validate", str(current))

            current = write_manifest(
                root,
                version="0.19.1",
                source_ref=git(ROOT, "rev-parse", "HEAD"),
            )
            data = yaml.safe_load(current.read_text(encoding="utf-8"))
            del data["artifacts"]["registry-docs"]
            current.write_text(
                yaml.safe_dump(data, sort_keys=False), encoding="utf-8"
            )
            missing_docs_result = run_tool("validate", str(current))

        self.assertEqual(0, historical_result.returncode, historical_result.stderr)
        self.assertEqual(0, current_result.returncode, current_result.stderr)
        self.assertNotEqual(0, missing_result.returncode)
        self.assertIn("missing relay-installer", missing_result.stderr)
        self.assertNotEqual(0, missing_docs_result.returncode)
        self.assertIn("missing registry-docs", missing_docs_result.stderr)


    def test_validate_still_rejects_unknown_artifacts_beside_the_evidence_toolset(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            manifest = write_manifest(
                Path(tmp),
                version="0.19.0",
            )
            contents = manifest.read_text(encoding="utf-8")
            contents = contents.replace(
                "evidencectl-installer:", "registry-lab: '0.19.0'\n  evidencectl-installer:"
            )
            manifest.write_text(contents, encoding="utf-8")
            rejected = run_tool("validate", str(manifest))

        self.assertNotEqual(0, rejected.returncode)
        self.assertIn("unexpected registry-lab", rejected.stderr)













    def test_validate_source_accepts_ancestor_source_ref(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = init_repo(Path(tmp))
            source_ref = commit_file(repo, "source.txt", "source\n")
            commit_file(repo, "release.txt", "release\n")
            git(repo, "tag", "v0.19.0")
            manifest = write_manifest(repo, source_ref=source_ref)

            result = run_tool(
                "validate-source",
                str(manifest),
                "--tag",
                "v0.19.0",
                "--repo",
                str(repo),
                "--default-branch",
                "main",
            )

        self.assertEqual(0, result.returncode, result.stderr)
        self.assertIn("validated source lineage", result.stdout)

    def test_validate_source_rejects_mismatched_source_tag(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = init_repo(Path(tmp))
            source_ref = commit_file(repo, "source.txt", "source\n")
            git(repo, "tag", "v0.19.0")
            manifest = write_manifest(repo, source_ref=source_ref, source_tag="v9.9.9")

            result = run_tool(
                "validate-source",
                str(manifest),
                "--tag",
                "v0.19.0",
                "--repo",
                str(repo),
                "--default-branch",
                "main",
            )

        self.assertNotEqual(0, result.returncode)
        self.assertIn("does not match checked-out release tag", result.stderr)

    def test_validate_source_rejects_non_ancestor_source_ref(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = init_repo(Path(tmp))
            commit_file(repo, "main.txt", "main\n")
            git(repo, "checkout", "-b", "side")
            side_ref = commit_file(repo, "side.txt", "side\n")
            git(repo, "checkout", "main")
            commit_file(repo, "release.txt", "release\n")
            git(repo, "tag", "v0.19.0")
            manifest = write_manifest(repo, source_ref=side_ref)

            result = run_tool(
                "validate-source",
                str(manifest),
                "--tag",
                "v0.19.0",
                "--repo",
                str(repo),
                "--default-branch",
                "main",
            )

        self.assertNotEqual(0, result.returncode)
        self.assertIn("is not an ancestor of release tag target", result.stderr)

    def test_validate_source_allows_draft_not_reachable_from_default_branch(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = init_repo(Path(tmp))
            commit_file(repo, "main.txt", "main\n")
            git(repo, "checkout", "--orphan", "draft")
            commit_file(repo, "draft.txt", "draft\n")
            git(repo, "tag", "v0.19.0")
            manifest = write_manifest(repo, source_ref="HEAD", status="draft")

            result = run_tool(
                "validate-source",
                str(manifest),
                "--tag",
                "v0.19.0",
                "--repo",
                str(repo),
                "--default-branch",
                "main",
            )

        self.assertEqual(0, result.returncode, result.stderr)
































    def test_bind_spdx_subject_adds_digest_bound_described_package(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            spdx = root / "registry-notary.spdx.json"
            spdx.write_text(
                json.dumps(
                    {
                        "spdxVersion": "SPDX-2.3",
                        "name": "syft-registry-notary-output",
                        "documentDescribes": ["SPDXRef-DocumentRoot"],
                        "packages": [
                            {
                                "SPDXID": "SPDXRef-DocumentRoot",
                                "name": "registry-notary",
                                "downloadLocation": "NOASSERTION",
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )

            result = run_tool(
                "bind-spdx-subject",
                str(spdx),
                "--image-name",
                "registry-notary",
                "--digest-ref",
                IMAGE_DIGEST_REF,
            )

            data = json.loads(spdx.read_text(encoding="utf-8"))

        self.assertEqual(0, result.returncode, result.stderr)
        described = set(data["documentDescribes"])
        subject_packages = [
            package for package in data["packages"] if package["SPDXID"] in described
        ]
        self.assertTrue(
            any(package["name"] == IMAGE_DIGEST_REF for package in subject_packages)
        )
        self.assertTrue(
            any(IMAGE_DIGEST in json.dumps(package) for package in subject_packages)
        )

    def test_bind_spdx_file_subject_adds_sha256_bound_described_package(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            spdx = root / "relayctl.spdx.json"
            digest = "a" * 64
            spdx.write_text(
                json.dumps(
                    {
                        "spdxVersion": "SPDX-2.3",
                        "name": "syft-relayctl-output",
                        "documentDescribes": ["SPDXRef-DocumentRoot"],
                        "packages": [
                            {
                                "SPDXID": "SPDXRef-DocumentRoot",
                                "name": "relayctl",
                                "downloadLocation": "NOASSERTION",
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )

            result = run_tool(
                "bind-spdx-file-subject",
                str(spdx),
                "--file-name",
                "relayctl-v0.19.0-linux-amd64",
                "--sha256",
                digest,
            )

            data = json.loads(spdx.read_text(encoding="utf-8"))

        self.assertEqual(0, result.returncode, result.stderr)
        described = set(data["documentDescribes"])
        subject_packages = [
            package for package in data["packages"] if package["SPDXID"] in described
        ]
        self.assertTrue(
            any(
                package["name"] == "relayctl-v0.19.0-linux-amd64"
                and package["checksums"][0]["checksumValue"] == digest
                for package in subject_packages
            )
        )


def run_tool(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(TOOL), *args],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )


def git(repo: Path, *args: str) -> str:
    return subprocess.check_output(["git", *args], cwd=repo, text=True).strip()


def init_repo(repo: Path) -> Path:
    git(repo, "init", "-b", "main")
    git(repo, "config", "user.email", "release-test@example.invalid")
    git(repo, "config", "user.name", "Release Test")
    return repo




def commit_file(repo: Path, name: str, body: str) -> str:
    path = repo / name
    path.write_text(body, encoding="utf-8")
    git(repo, "add", name)
    git(repo, "commit", "-m", f"add {name}")
    return git(repo, "rev-parse", "HEAD")


def write_manifest(
    directory: Path,
    *,
    source_ref: str = "f30a541df539c2e16de09733c5944c744a60493c",
    source_tag: str | None = None,
    status: str = "release-candidate",
    version: str = "0.19.0",
) -> Path:
    if source_tag is None:
        source_tag = f"v{version}"
    version_tuple = tuple(int(part) for part in version.split("."))
    artifacts = {
        name: version
        for name in (
            "registry-manifest",
            "relay",
            "relayctl",
            "evidence",
            "evidencectl",
            "mint",
            "evidence-oid4vci",
            "evidencectl-installer",
            "evidence-client-node",
            "evidence-client-python",
        )
    }
    if version_tuple >= (0, 19, 1):
        artifacts["relay-installer"] = version
        artifacts["registry-docs"] = version
        artifacts["relay-client-node"] = version
        artifacts["relay-client-python"] = version
    if version_tuple >= (0, 23, 0):
        artifacts["discovery-client-node"] = version
        artifacts["discovery-client-python"] = version
    if version_tuple >= (0, 24, 0):
        artifacts["discovery"] = version
    if version_tuple >= (0, 26, 0):
        artifacts["breg"] = version
        artifacts["bregctl"] = version
        artifacts["breg-installer"] = version
    manifest = {
        "stack": {
            "release": "beta-6",
            "version": version,
            "source_repo": "registrystack/registry-stack",
            "source_ref": source_ref,
            "source_tag": source_tag,
            "status": status,
        },
        "artifacts": artifacts,
        "external": {
            "crosswalk": {
                "repo": "PublicSchema/crosswalk",
                "ref": "1d44ec735fdc8a7c719264b339574371e8330337",
                "status": "tested external input",
            },
        },
    }
    if version_tuple >= (0, 19, 1):
        catalog_relative_path = "products/identifiers/generated/catalog.v1.json"
        repository = directory
        repository_result = subprocess.run(
            ["git", "-C", str(directory), "rev-parse", "--show-toplevel"],
            check=False,
            capture_output=True,
            text=True,
        )
        if repository_result.returncode == 0:
            repository = Path(repository_result.stdout.strip())
        else:
            repository = ROOT
        catalog_result = subprocess.run(
            ["git", "-C", str(repository), "show", f"{source_ref}:{catalog_relative_path}"],
            check=True,
            capture_output=True,
        )
        catalog_bytes = catalog_result.stdout
        catalog = json.loads(catalog_bytes)
        manifest["identifier_catalog"] = {
            "path": catalog_relative_path,
            "sha256": hashlib.sha256(catalog_bytes).hexdigest(),
            "entry_count": len(catalog["entries"]),
        }
    path = directory / "release-manifest.yaml"
    path.write_text(yaml.safe_dump(manifest, sort_keys=False), encoding="utf-8")
    return path


def write_docset_fixture(root: Path) -> tuple[Path, Path]:
    manifest_dir = root / "manifests"
    manifest_dir.mkdir()
    manifest = write_manifest(manifest_dir, version="0.8.0")
    manifest.rename(manifest_dir / "registry-stack-beta-6.yaml")
    docsets = root / "docsets.yaml"
    docsets.write_text(
        yaml.safe_dump(
            {
                "current": "latest",
                "docsets": [
                    {
                        "id": "v0.8.0",
                        "status": "archived",
                        "source": "registry-stack-v0.8.0",
                        "products": {
                            "registry-stack": {
                                "version": "v0.8.0",
                                "ref": "f30a541df539c2e16de09733c5944c744a60493c",
                            },
                            "crosswalk": {
                                "version": "crosswalk-core-v0.2.0",
                                "ref": "1d44ec735fdc8a7c719264b339574371e8330337",
                            },
                        },
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    (root / "archive-lock.yaml").write_text(
        yaml.safe_dump(
            {
                "schema_version": "registry-docs.archive-lock.v1",
                "archives": {
                    "v0.8.0": {
                        "bundle_sha256": "a" * 64,
                        "tree_sha256": "b" * 64,
                    }
                },
            }
        ),
        encoding="utf-8",
    )
    return manifest_dir, docsets
















if __name__ == "__main__":
    main()
