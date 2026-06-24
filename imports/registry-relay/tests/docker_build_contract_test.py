# SPDX-License-Identifier: Apache-2.0
import importlib.util
import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def load_module():
    path = ROOT / "scripts" / "check_docker_build_contract.py"
    spec = importlib.util.spec_from_file_location("check_docker_build_contract", path)
    if spec is None or spec.loader is None:
        raise ImportError(f"could not load module spec from {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class DockerBuildContractTest(unittest.TestCase):
    def setUp(self):
        self.module = load_module()

    def test_local_manifest_context_requires_immutable_clean_checkout(self):
        script = (ROOT / "scripts" / "build-image.sh").read_text()

        match = re.search(r'REGISTRY_MANIFEST_REF:-([0-9a-f]{40})', script)
        self.assertIsNotNone(match)
        self.assertIn('expr "$expected_ref" : \'[0-9a-f][0-9a-f]*$\'', script)
        self.assertIn('git -C "$dir" rev-parse HEAD', script)
        self.assertIn('git -C "$dir" status --porcelain', script)
        self.assertIn('REGISTRY_RELAY_ALLOW_UNPINNED_LOCAL_CONTEXTS', script)
        self.assertIn(
            'verify_pinned_git_context "REGISTRY_MANIFEST" "$manifest_dir" "$manifest_ref"',
            script,
        )

    def test_flags_documented_direct_local_manifest_builds(self):
        module = self.module
        path = ROOT / "README.md"
        module._CONTENT_CACHE[path] = (
            "```sh\n"
            "docker buildx build --load \\\n"
            "  --build-context registry-manifest=../registry-manifest \\\n"
            "  -t registry-relay:local .\n"
            "```\n"
        )
        self.assertTrue(module.forbid_documented_unpinned_build_context(path))

    def test_real_docker_build_contract_passes(self):
        self.assertEqual(self.module.main(), 0)


if __name__ == "__main__":
    unittest.main()
