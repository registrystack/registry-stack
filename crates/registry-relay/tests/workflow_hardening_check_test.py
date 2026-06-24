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

    def binary_release_failures(self, text: str) -> list[str]:
        path = self.module.WORKFLOWS / "binary-release.yml"
        return self.module.require_binary_release_powershell_hardening(text, path)

    def coverage_failures(self, text: str) -> list[str]:
        path = self.module.WORKFLOWS / "ci.yml"
        return self.module.require_coverage_contract(text, path)

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

    def test_flags_tag_interpolation_inside_release_powershell(self):
        text = (
            '[[ ! "$GITHUB_REF_NAME" =~ ^v[0-9]+\\.[0-9]+\\.[0-9]+$ ]]\n'
            'PACKAGE_DIR="$package_dir" PACKAGE_ZIP="target/dist/${package}.zip" \\\n'
            '  pwsh -NoProfile -Command "Compress-Archive -Path target/dist/${{ github.ref_name }} -DestinationPath target/dist/out.zip -Force"\n'
        )

        failures = self.binary_release_failures(text)

        self.assertTrue(any("GitHub tag interpolation in PowerShell" in failure for failure in failures))

    def test_flags_package_path_interpolation_inside_release_powershell(self):
        text = (
            '[[ ! "$GITHUB_REF_NAME" =~ ^v[0-9]+\\.[0-9]+\\.[0-9]+$ ]]\n'
            'PACKAGE_DIR="$package_dir" PACKAGE_ZIP="target/dist/${package}.zip" \\\n'
            '  pwsh -NoProfile -Command "Compress-Archive -Path \'$package_dir/*\' -DestinationPath \'target/dist/$package.zip\' -Force"\n'
        )

        failures = self.binary_release_failures(text)

        self.assertTrue(any("tag-derived package path interpolation in PowerShell" in failure for failure in failures))

    def test_flags_multiline_tag_interpolation_inside_release_powershell(self):
        text = (
            '[[ ! "$GITHUB_REF_NAME" =~ ^v[0-9]+\\.[0-9]+\\.[0-9]+$ ]]\n'
            'PACKAGE_DIR="$package_dir" PACKAGE_ZIP="target/dist/${package}.zip" \\\n'
            "  pwsh -NoProfile -Command \"Compress-Archive -Path (Join-Path \\$env:PACKAGE_DIR '*') -DestinationPath \\$env:PACKAGE_ZIP -Force\"\n"
            "  pwsh -NoProfile -Command @'\n"
            "    Compress-Archive \\\n"
            "      -Path target/dist/${{ github.ref_name }}/* \\\n"
            "      -DestinationPath target/dist/out.zip \\\n"
            "      -Force\n"
            "'@\n"
        )

        failures = self.binary_release_failures(text)

        self.assertTrue(any("GitHub tag interpolation in PowerShell" in failure for failure in failures))

    def test_accepts_env_only_release_powershell_paths(self):
        text = (
            '[[ ! "$GITHUB_REF_NAME" =~ ^v[0-9]+\\.[0-9]+\\.[0-9]+$ ]]\n'
            'PACKAGE_DIR="$package_dir" PACKAGE_ZIP="target/dist/${package}.zip" \\\n'
            "  pwsh -NoProfile -Command \"Compress-Archive -Path (Join-Path \\$env:PACKAGE_DIR '*') -DestinationPath \\$env:PACKAGE_ZIP -Force\"\n"
        )

        self.assertEqual(self.binary_release_failures(text), [])

    def test_coverage_contract_requires_threshold(self):
        text = (
            'CARGO_LLVM_COV_VERSION: "0.8.7"\n'
            "components: llvm-tools-preview\n"
            "tool: cargo-llvm-cov@${{ env.CARGO_LLVM_COV_VERSION }}\n"
            "cargo llvm-cov clean --workspace\n"
            "cargo llvm-cov nextest --no-report --build-jobs 2\n"
            "cargo llvm-cov nextest --all-features --no-report --build-jobs 2\n"
            "cargo llvm-cov report | tee target/coverage/summary.txt\n"
            "target/coverage/summary.txt\n"
            "target/coverage/lcov.info\n"
            "target/coverage/summary.json\n"
            "target/coverage/dashboard.json\n"
            "Upload coverage artifacts\n"
            "Enforce coverage threshold\n"
            'dashboard["status"] != "pass"\n'
            "uses: actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02 # v4.6.2\n"
        )

        failures = self.coverage_failures(text)

        self.assertTrue(any("baseline coverage threshold" in failure for failure in failures))

    def test_coverage_contract_requires_pinned_llvm_cov_install(self):
        text = (
            'CARGO_LLVM_COV_VERSION: "0.8.7"\n'
            'REGISTRY_RELAY_COVERAGE_THRESHOLD: "85"\n'
            "components: llvm-tools-preview\n"
            "cargo llvm-cov clean --workspace\n"
            "cargo llvm-cov nextest --no-report --build-jobs 2\n"
            "cargo llvm-cov nextest --all-features --no-report --build-jobs 2\n"
            "cargo llvm-cov report | tee target/coverage/summary.txt\n"
            "target/coverage/summary.txt\n"
            "target/coverage/lcov.info\n"
            "target/coverage/summary.json\n"
            "target/coverage/dashboard.json\n"
            "Upload coverage artifacts\n"
            "Enforce coverage threshold\n"
            'dashboard["status"] != "pass"\n'
            "uses: actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02 # v4.6.2\n"
        )

        failures = self.coverage_failures(text)

        self.assertTrue(any("pinned cargo-llvm-cov install" in failure for failure in failures))

    def test_coverage_contract_requires_llvm_tools_component(self):
        text = (
            'CARGO_LLVM_COV_VERSION: "0.8.7"\n'
            'REGISTRY_RELAY_COVERAGE_THRESHOLD: "85"\n'
            "tool: cargo-llvm-cov@${{ env.CARGO_LLVM_COV_VERSION }}\n"
            "cargo llvm-cov clean --workspace\n"
            "cargo llvm-cov nextest --no-report --build-jobs 2\n"
            "cargo llvm-cov nextest --all-features --no-report --build-jobs 2\n"
            "cargo llvm-cov report | tee target/coverage/summary.txt\n"
            "target/coverage/summary.txt\n"
            "target/coverage/lcov.info\n"
            "target/coverage/summary.json\n"
            "target/coverage/dashboard.json\n"
            "Upload coverage artifacts\n"
            "Enforce coverage threshold\n"
            'dashboard["status"] != "pass"\n'
            "uses: actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02 # v4.6.2\n"
        )

        failures = self.coverage_failures(text)

        self.assertTrue(any("LLVM tools Rust component" in failure for failure in failures))

    def test_coverage_contract_rejects_direct_fail_under_before_upload(self):
        text = Path(self.module.ROOT / ".github" / "workflows" / "ci.yml").read_text(
            encoding="utf-8"
        )
        text += "\ncargo llvm-cov report --fail-under-lines 85\n"

        failures = self.coverage_failures(text)

        self.assertTrue(any("direct fail-under coverage gate" in failure for failure in failures))

    def test_coverage_contract_requires_upload_before_threshold_enforcement(self):
        text = Path(self.module.ROOT / ".github" / "workflows" / "ci.yml").read_text(
            encoding="utf-8"
        )
        text = text.replace("Upload coverage artifacts", "Upload coverage artifacts removed")
        text = text.replace("Enforce coverage threshold", "Upload coverage artifacts")
        text = text.replace("Upload coverage artifacts removed", "Enforce coverage threshold")

        failures = self.coverage_failures(text)

        self.assertTrue(any("upload before threshold enforcement" in failure for failure in failures))

    def test_real_workflows_pass(self):
        self.assertEqual(self.module.main(), 0)


if __name__ == "__main__":
    unittest.main()
