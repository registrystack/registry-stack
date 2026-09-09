from __future__ import annotations

import io
import json
from contextlib import redirect_stderr
from unittest import TestCase, main, mock

from release.scripts.test_registry_release import load_registry_release


class ProtectedCiWaitTest(TestCase):
    def setUp(self):
        self.tool = load_registry_release()
        self.sha = "a" * 40
        self.run = {
            "id": 123,
            "html_url": "https://github.com/registrystack/registry-stack/actions/runs/123",
            "event": "push",
            "head_sha": self.sha,
            "head_branch": "main",
            "status": "completed",
            "conclusion": "success",
        }

    def test_rejects_failed_main_even_when_other_runs_succeed(self):
        runs = [
            {**self.run, "head_sha": "b" * 40},
            {**self.run, "event": "pull_request"},
            {**self.run, "head_branch": "feature"},
            {**self.run, "conclusion": "failure"},
        ]
        with mock.patch.object(self.tool, "run_checked", return_value=json.dumps({"workflow_runs": runs})):
            with self.assertRaisesRegex(self.tool.ReleasePlanError, "concluded 'failure'"):
                self.tool.wait_for_exact_protected_ci("registrystack/registry-stack", self.sha)

    def test_pending_main_must_finish_successfully(self):
        pending = {**self.run, "status": "in_progress", "conclusion": None}
        for conclusion in ("success", "failure", "cancelled", "timed_out"):
            with self.subTest(conclusion=conclusion):
                completed = {**self.run, "conclusion": conclusion}
                with (
                    mock.patch.object(self.tool, "workflow_runs", side_effect=[[pending], [completed]]),
                    mock.patch.object(self.tool, "watch_workflow_run") as watch,
                ):
                    if conclusion == "success":
                        self.assertEqual(self.tool.wait_for_exact_protected_ci("registrystack/registry-stack", self.sha), completed)
                    else:
                        with self.assertRaisesRegex(self.tool.ReleasePlanError, "did not succeed"):
                            self.tool.wait_for_exact_protected_ci("registrystack/registry-stack", self.sha)
                    self.assertEqual(watch.call_args.args[1], 123)

    def test_recheck_cannot_substitute_another_branch_success(self):
        pending = {**self.run, "status": "queued", "conclusion": None}
        with (
            mock.patch.object(self.tool, "workflow_runs", side_effect=[[pending], [{**self.run, "head_branch": "feature"}]]),
            mock.patch.object(self.tool, "watch_workflow_run"),
        ):
            with self.assertRaisesRegex(self.tool.ReleasePlanError, "did not succeed"):
                self.tool.wait_for_exact_protected_ci("registrystack/registry-stack", self.sha)

    def test_missing_ci_fails_after_bounded_discovery(self):
        with (
            mock.patch.object(self.tool, "workflow_runs", return_value=[]),
            mock.patch.object(self.tool.time, "monotonic", side_effect=[0, 121]),
        ):
            with self.assertRaisesRegex(self.tool.ReleasePlanError, "no protected-main CI run appeared"):
                self.tool.wait_for_exact_protected_ci("registrystack/registry-stack", self.sha)

    def test_command_rejects_nonexact_source_before_network(self):
        with mock.patch.object(self.tool, "wait_for_exact_protected_ci") as wait, redirect_stderr(io.StringIO()):
            self.assertEqual(self.tool.wait_for_protected_ci_command("registrystack/registry-stack", "main"), 1)
        wait.assert_not_called()


if __name__ == "__main__":
    main()
