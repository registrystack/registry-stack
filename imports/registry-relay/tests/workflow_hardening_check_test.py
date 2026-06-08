# SPDX-License-Identifier: Apache-2.0
import importlib.util
import unittest
from pathlib import Path


def load_module():
    path = Path(__file__).resolve().parents[1] / "scripts" / "check_workflow_hardening.py"
    spec = importlib.util.spec_from_file_location("check_workflow_hardening", path)
    if spec is None or spec.loader is None:
        raise ImportError(f"could not load module spec from {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class WorkflowHardeningCheckTest(unittest.TestCase):
    def setUp(self):
        self.module = load_module()

    def flagged(self, text: str) -> bool:
        path = self.module.WORKFLOWS / "ci.yml"
        failures: list[str] = []
        for pattern, detail in self.module.NEXTEST_FORBIDDEN_PATTERNS:
            failures.extend(self.module.forbid(text, pattern, path, detail))
        return bool(failures)

    def test_flags_get_nexte_st_installer(self):
        self.assertTrue(self.flagged("run: curl -LsSf https://get.nexte.st/latest/linux | tar xzf -"))

    def test_flags_curl_piped_to_tar(self):
        self.assertTrue(self.flagged("run: curl -L https://example.test/nextest.tar.gz | tar xzf -"))

    def test_flags_wget_piped_to_tar(self):
        self.assertTrue(self.flagged("run: wget -qO- https://example.test/nextest.tar.gz | tar xzf -"))

    def test_flags_split_curl_download_then_tar(self):
        text = (
            "run: |\n"
            "  curl -L -o nextest.tar.gz https://example.test/nextest.tar.gz\n"
            "  tar xzf nextest.tar.gz\n"
        )
        self.assertTrue(self.flagged(text))

    def test_flags_split_wget_download_then_tar(self):
        text = (
            "run: |\n"
            "  wget -O nextest.tar.gz https://example.test/nextest.tar.gz\n"
            "  tar xzf nextest.tar.gz\n"
        )
        self.assertTrue(self.flagged(text))

    def test_does_not_flag_pinned_install_action(self):
        text = (
            "uses: taiki-e/install-action@25435dc8dd3baed7417e0c96d3fe89013a5b2e09 # v2.81.3\n"
            "with:\n"
            "  tool: nextest@0.9.136\n"
            "  fallback: none\n"
        )
        self.assertFalse(self.flagged(text))

    def test_does_not_flag_tar_of_local_artifact(self):
        text = (
            "run: |\n"
            "  cargo build --release\n"
            "  tar czf dist/bundle.tar.gz target/release/registry-relay\n"
        )
        self.assertFalse(self.flagged(text))

    def test_real_workflows_pass(self):
        self.assertEqual(self.module.main(), 0)


if __name__ == "__main__":
    unittest.main()
