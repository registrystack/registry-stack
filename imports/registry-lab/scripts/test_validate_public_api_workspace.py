#!/usr/bin/env python3
"""Focused tests for the public Bruno API workspace contract."""

from __future__ import annotations

import importlib.util
import shutil
import sys
import tempfile
import unittest
from pathlib import Path


SCRIPT_DIR = Path(__file__).resolve().parent
VALIDATOR_PATH = SCRIPT_DIR / "validate-public-api-workspace.py"
REPO_ROOT = SCRIPT_DIR.parent


def load_validator():
    spec = importlib.util.spec_from_file_location("validate_public_api_workspace", VALIDATOR_PATH)
    if not spec or not spec.loader:
        raise RuntimeError(f"could not load {VALIDATOR_PATH}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class PublicApiWorkspaceValidationTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.validator = load_validator()

    def test_current_workspace_contract_passes(self) -> None:
        issues = self.validator.validate_workspace(REPO_ROOT)
        self.assertEqual([], issues, [str(issue) for issue in issues])

    def test_rejects_hosted_token_drift(self) -> None:
        with self._workspace_fixture() as root:
            hosted = root / "requests" / "registry-lab" / "environments" / "Hosted Lab.bru"
            hosted.write_text(
                hosted.read_text(encoding="utf-8").replace(
                    "CIVIL_METADATA_CLIENT_RAW: public-civil-metadata",
                    "CIVIL_METADATA_CLIENT_RAW: stale-token",
                ),
                encoding="utf-8",
            )

            issues = self.validator.validate_workspace(root)

        self.assertIssue(issues, "hosted-token-mismatch")

    def test_rejects_forbidden_secret_names(self) -> None:
        with self._workspace_fixture() as root:
            request = root / "requests" / "registry-lab" / "00 - Start Here" / "Leaky request.bru"
            request.write_text(
                """
meta {
  name: Leaky request
  type: http
  seq: 99
}

headers {
  Authorization: Bearer {{OPENFN_SIDECAR_TOKEN_RAW}}
}

script:post-response {
  test("status is 200", function () {
    expect(res.getStatus()).to.equal(200);
  });
  test("has body", function () {
    expect(res.getBody()).to.exist;
  });
}
""",
                encoding="utf-8",
            )

            issues = self.validator.validate_workspace(root)

        self.assertIssue(issues, "forbidden-bruno-secret-name")

    def test_rejects_request_without_behavior_assertion(self) -> None:
        with self._workspace_fixture() as root:
            request = root / "requests" / "registry-lab" / "10 - Relay Metadata" / "Civil datasets.bru"
            request.write_text(
                """
meta {
  name: Civil datasets
  type: http
  seq: 1
}

get {
  url: {{civil_relay_url}}/v1/datasets
  body: none
  auth: none
}

script:post-response {
  test("status is 200", function () {
    expect(res.getStatus()).to.equal(200);
  });
}
""",
                encoding="utf-8",
            )

            issues = self.validator.validate_workspace(root)

        self.assertIssue(issues, "missing-behavior-test")

    def assertIssue(self, issues, code: str) -> None:
        codes = [issue.code for issue in issues]
        self.assertIn(code, codes, [str(issue) for issue in issues])

    @staticmethod
    def _workspace_fixture():
        temp = tempfile.TemporaryDirectory()
        root = Path(temp.name)
        shutil.copytree(REPO_ROOT / "docs", root / "docs")
        config_dir = root / "config" / "lab-homepage"
        config_dir.mkdir(parents=True)
        (config_dir / "public-demo-credentials.env").write_text(
            """
CIVIL_METADATA_CLIENT_RAW=public-civil-metadata
SOCIAL_METADATA_CLIENT_RAW=public-social-metadata
""".lstrip(),
            encoding="utf-8",
        )
        collection = root / "requests" / "registry-lab"
        env_dir = collection / "environments"
        env_dir.mkdir(parents=True)
        (collection / "bruno.json").write_text(
            '{"version":"1","name":"Registry Lab","type":"collection"}\n',
            encoding="utf-8",
        )
        (collection / "collection.bru").write_text(
            "meta {\n  name: Registry Lab\n}\n\nauth {\n  mode: none\n}\n",
            encoding="utf-8",
        )
        (collection / "README.md").write_text(
            "Hosted Lab uses public demo credentials from config/lab-homepage/public-demo-credentials.env.\n"
            "Run the hosted slice with Bruno, then run the Local Compose slice after just generate.\n",
            encoding="utf-8",
        )
        (env_dir / "Hosted Lab.bru").write_text(
            """
vars {
  lab_homepage_url: https://lab.registrystack.org
  civil_relay_url: https://civil-relay.lab.registrystack.org
  CIVIL_METADATA_CLIENT_RAW: public-civil-metadata
  SOCIAL_METADATA_CLIENT_RAW: public-social-metadata
}
""".lstrip(),
            encoding="utf-8",
        )
        (env_dir / "Local Compose.bru").write_text(
            """
vars {
  civil_relay_url: http://127.0.0.1:4311
  CIVIL_METADATA_CLIENT_RAW:
  SOCIAL_METADATA_CLIENT_RAW:
}
""".lstrip(),
            encoding="utf-8",
        )
        for folder in (
            "00 - Start Here",
            "10 - Relay Metadata",
            "20 - Relay Access Boundaries",
            "30 - Notary Evaluation",
        ):
            path = collection / folder
            path.mkdir()
            (path / f"{folder}.bru").write_text(
                """
meta {
  name: fixture request
  type: http
  seq: 1
}

get {
  url: {{civil_relay_url}}/healthz
  body: none
  auth: none
}

script:post-response {
  test("status is 200", function () {
    expect(res.getStatus()).to.equal(200);
  });
  test("response has expected fixture marker", function () {
    expect(res.getBody()).to.exist;
  });
}
""".lstrip(),
                encoding="utf-8",
            )

        class Fixture:
            def __enter__(self):
                return root

            def __exit__(self, *args):
                temp.cleanup()

        return Fixture()


if __name__ == "__main__":
    unittest.main()
