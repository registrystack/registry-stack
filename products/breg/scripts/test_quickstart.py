#!/usr/bin/env python3

from __future__ import annotations

import contextlib
import importlib.util
import io
import json
import subprocess
import tempfile
import unittest
import unittest.mock as mock
from pathlib import Path


PRODUCT_ROOT = Path(__file__).resolve().parents[1]
QUICKSTART = PRODUCT_ROOT / "quickstart"
SPATIAL_FIXTURE = PRODUCT_ROOT / "acceptance/spatial-service-sites"


def load_helper():
    spec = importlib.util.spec_from_file_location("quickstart_support", QUICKSTART / "support/quickstart.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def prepare_request_root(root: Path) -> None:
    root.chmod(0o700)
    (root / "headers").mkdir(mode=0o700)
    (root / "breg-origin").write_text("http://127.0.0.1:1\n", encoding="ascii")
    token_path = root / "headers/operator.header"
    token_path.write_text("Authorization: Bearer header.payload.signature\n", encoding="ascii")
    token_path.chmod(0o600)
    map_token_path = root / "headers/installation-map-reader.header"
    map_token_path.write_text("Authorization: Bearer header.payload.signature\n", encoding="ascii")
    map_token_path.chmod(0o600)


class _FakeHttpResponse:
    def __init__(self, status: int, body: bytes) -> None:
        self.status = status
        self._body = body

    def read(self) -> bytes:
        return self._body

    def __enter__(self) -> "_FakeHttpResponse":
        return self

    def __exit__(self, exc_type: object, exc: object, tb: object) -> bool:
        return False


class BRegQuickstartTests(unittest.TestCase):
    def test_offline_self_test_passes_without_network(self) -> None:
        result = subprocess.run(
            [str(QUICKSTART / "self-test.sh")],
            cwd=PRODUCT_ROOT.parents[1],
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
        self.assertIn("self-test passed", result.stdout)

    def test_readme_keeps_local_and_production_paths_separate(self) -> None:
        readme = (QUICKSTART / "README.md").read_text(encoding="utf-8")
        unwrapped = " ".join(readme.split())
        self.assertIn("bregctl dev", readme)
        self.assertIn("pinned stock ThunderID issuer", readme)
        self.assertIn("private-key JWT clients", readme)
        self.assertIn(".run/headers/operator.header", readme)
        self.assertIn("does not put the bearer token on the command line", unwrapped)
        self.assertIn("Production deployments require", readme)


    def test_spatial_project_uses_explicit_private_key_clients(self) -> None:
        helper = load_helper()
        with tempfile.TemporaryDirectory() as spatial_dir:
            spatial_root = Path(spatial_dir)
            helper.prepare_spatial(SPATIAL_FIXTURE, spatial_root / "project")
            spatial_registry = (spatial_root / "project/registry.yaml").read_text(encoding="utf-8")
            clients = (spatial_root / "project/dev-clients.yaml").read_text(encoding="utf-8")
            self.assertIn("environment: local", spatial_registry)
            self.assertIn("instanceId: generic-quickstart-local", spatial_registry)
            self.assertIn("manifestProjection:", spatial_registry)
            self.assertIn("id: operator", clients)
            self.assertIn("id: installation-map-reader", clients)
            self.assertIn("service_zones: central", clients)
            self.assertNotIn("clientAuthentication:", clients)

    def test_create_record_reads_record_identifier_from_registry_record_envelope(self) -> None:
        helper = load_helper()
        with tempfile.TemporaryDirectory() as root_dir:
            root = Path(root_dir)
            prepare_request_root(root)
            envelope = json.dumps(
                {
                    "data": {
                        "recordIdentifier": "11111111-1111-1111-1111-111111111111",
                        "revisionIdentifier": "1",
                        "domainData": {"code": "QS-001", "label": "Quickstart example record"},
                    },
                    "meta": {
                        "registryIdentifier": "generic-registry-local-db",
                        "datasetIdentifier": "records",
                        "entityTypeIdentifier": "record",
                    },
                }
            ).encode()

            def fake_urlopen(request: object, timeout: float = 10) -> _FakeHttpResponse:
                return _FakeHttpResponse(201, envelope)

            captured = io.StringIO()
            with mock.patch("urllib.request.urlopen", fake_urlopen):
                with contextlib.redirect_stdout(captured):
                    helper.generic(root, "create", "QS-001", "Quickstart example record", None)
            self.assertEqual(captured.getvalue().strip(), "11111111-1111-1111-1111-111111111111")

    def test_spatial_smoke_reads_rows_from_items_and_rejects_legacy_records_key(self) -> None:
        helper = load_helper()
        with tempfile.TemporaryDirectory() as root_dir:
            root = Path(root_dir)
            prepare_request_root(root)
            seed = root / "seed.jsonl"
            seed.write_text(
                "\n".join(json.dumps({"operation": "create", "data": {"code": f"S-{index}"}}) for index in range(200)) + "\n",
                encoding="utf-8",
            )
            created = {
                "data": {"recordIdentifier": "x", "revisionIdentifier": "1", "domainData": {}},
                "meta": {"registryIdentifier": "r", "datasetIdentifier": "d", "entityTypeIdentifier": "e"},
            }
            geojson = {"type": "FeatureCollection", "features": [{}]}

            def fake_request_with_legacy_records_key(root_arg, method, path, body=None, expected=200, client="operator", idem=None, accept="application/json"):
                if method == "POST":
                    return created
                if accept == "application/geo+json":
                    return geojson
                return {"records": [{}]}

            with mock.patch.object(helper, "request", fake_request_with_legacy_records_key):
                with self.assertRaises(helper.QuickstartError):
                    helper.spatial_smoke(root, seed)

            def fake_request_with_items_key(root_arg, method, path, body=None, expected=200, client="operator", idem=None, accept="application/json"):
                if method == "POST":
                    return created
                if accept == "application/geo+json":
                    return geojson
                return {"items": [{}], "pageInfo": {"nextCursor": None}, "meta": {}}

            with mock.patch.object(helper, "request", fake_request_with_items_key):
                helper.spatial_smoke(root, seed)

    def test_spatial_launcher_preserves_generic_default_and_switches_only_on_flag(self) -> None:
        run_source = (QUICKSTART / "run.sh").read_text(encoding="utf-8")
        self.assertIn("spatial=false", run_source)
        self.assertIn("--spatial", run_source)
        self.assertIn("prepare-spatial-project", run_source)
        self.assertIn("dev token installation-map-reader", run_source)
        self.assertIn("spatial-smoke", run_source)
        self.assertIn("Base Registry Engine quickstart is ready", run_source)

    def test_spatial_helper_keeps_secret_file_private_and_runtime_clients_explicit(self) -> None:
        helper_source = (QUICKSTART / "support/quickstart.py").read_text(encoding="utf-8")
        self.assertIn("id: installation-map-reader", helper_source)
        self.assertIn("accessProfiles: [installation-map-reader]", helper_source)
        self.assertIn("service-sites:map:read", helper_source)
        self.assertIn("synthetic-qgis-installation", helper_source)
        self.assertIn("service_zones: central", helper_source)
        self.assertNotIn("clientAuthentication:", helper_source)


if __name__ == "__main__":
    unittest.main()
