#!/usr/bin/env python3
"""Focused tests for retained hosted deployment safety checks."""

from __future__ import annotations

import copy
import importlib.util
import sys
import unittest
from pathlib import Path


SCRIPT = Path(__file__).with_name("validate-hosted-deploy.py")
SPEC = importlib.util.spec_from_file_location("validate_hosted_deploy", SCRIPT)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("could not load hosted deployment validator")
validator = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = validator
SPEC.loader.exec_module(validator)


class HostedDeployValidationTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.root = Path(__file__).resolve().parents[1]
        cls.artifacts = {}
        cls.roots = {}
        cls.texts = {}
        for name, filename in {
            "registry-lab": "compose.coolify.yaml",
            "esignet": "compose.esignet-hosted.yaml",
            "social": "compose.social-hosted.yaml",
            "agri": "compose.agri-hosted.yaml",
            "walt": "compose.walt-hosted.yaml",
        }.items():
            path = cls.root / filename
            cls.artifacts[name] = validator.load_compose(path)
            cls.roots[name] = cls.root
            cls.texts[name] = path.read_text(encoding="utf-8")

    def validate(self, artifacts=None):
        return validator.validate_artifacts(
            artifacts or self.artifacts,
            self.roots,
            self.texts,
            check_metadata_digest_pins=False,
        )

    def test_repository_hosted_artifacts_pass_retained_checks(self) -> None:
        self.assertEqual(self.validate(), [])

    def test_rejects_missing_required_service(self) -> None:
        artifacts = copy.deepcopy(self.artifacts)
        del artifacts["registry-lab"]["services"]["self-attested-notary"]
        codes = {issue.code for issue in self.validate(artifacts)}
        self.assertIn("missing-service", codes)

    def test_rejects_host_port_publication(self) -> None:
        artifacts = copy.deepcopy(self.artifacts)
        artifacts["social"]["services"]["social-protection-registry-relay"]["ports"] = ["4312:8080"]
        codes = {issue.code for issue in self.validate(artifacts)}
        self.assertIn("host-ports", codes)

    def test_active_artifacts_exclude_retired_notary_source_paths(self) -> None:
        forbidden = (
            "source_connections",
            "source_bindings",
            "transitional_direct",
            "registry_data_api",
            "source_adapter_sidecar",
        )
        paths = [
            self.root / "compose.coolify.yaml",
            self.root / "compose.social-hosted.yaml",
            self.root / "compose.agri-hosted.yaml",
            self.root / "config/notary/self-attested-notary.yaml",
        ]
        text = "\n".join(path.read_text(encoding="utf-8") for path in paths)
        for value in forbidden:
            with self.subTest(value=value):
                self.assertNotIn(value, text)


if __name__ == "__main__":
    unittest.main()
