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

import yaml


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
    token_path = root / "headers/editor.header"
    token_path.write_text("Authorization: Bearer header.payload.signature\n", encoding="ascii")
    token_path.chmod(0o600)
    for client in ("foreign-editor", "operator"):
        token = root / "headers" / f"{client}.header"
        token.write_text(f"Authorization: Bearer {client}.payload.signature\n", encoding="ascii")
        token.chmod(0o600)
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

    def test_spatial_project_has_a_package_and_clients_for_its_journeys(self) -> None:
        helper = load_helper()
        with tempfile.TemporaryDirectory() as spatial_dir:
            project = Path(spatial_dir) / "project"
            helper.prepare_spatial(SPATIAL_FIXTURE, project)
            registry = yaml.safe_load((project / "registry.yaml").read_text())
            journeys = yaml.safe_load((project / "tests/journeys.yaml").read_text())
            clients = yaml.safe_load((project / "dev-clients.yaml").read_text())["clients"]
        self.assertTrue(registry["package"]["sourceRevision"])
        self.assertNotIn("instanceId", registry["package"])
        profiles = {step["accessProfile"] for journey in journeys["journeys"] for step in journey["steps"]}
        self.assertIn("map-reader", profiles)
        self.assertIn("directory-reader", profiles)
        for profile in profiles:
            self.assertEqual(sum(profile in client["accessProfiles"] for client in clients), 1, profile)
        map_client = next(client for client in clients if client["id"] == "installation-map-reader")
        self.assertEqual(map_client["claims"]["service_zones"], "central")
        self.assertEqual(map_client["scopes"], ["service-sites:map:read"])

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
                        "domainData": {"name": "Example contact", "email": "contact@example.test", "jurisdiction": "zone-a"},
                    },
                    "meta": {
                        "registryIdentifier": "local-directory-db",
                        "datasetIdentifier": "directory",
                        "recordTypeIdentifier": "contact",
                    },
                }
            ).encode()

            def fake_urlopen(request, timeout: float = 10) -> _FakeHttpResponse:
                self.assertEqual(request.method, "POST")
                self.assertEqual(request.full_url, "http://127.0.0.1:1/v1/records/contacts?accessProfile=directory-editor")
                self.assertEqual(json.loads(request.data), {"data": {
                    "name": "Example contact", "email": "contact@example.test", "jurisdiction": "zone-a"
                }})
                self.assertTrue(request.get_header("Idempotency-key").startswith("quickstart-"))
                return _FakeHttpResponse(201, envelope)

            captured = io.StringIO()
            with mock.patch("urllib.request.urlopen", fake_urlopen):
                with contextlib.redirect_stdout(captured):
                    helper.directory(root, "create", "Example contact", "contact@example.test", None)
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
                "meta": {"registryIdentifier": "r", "datasetIdentifier": "d", "recordTypeIdentifier": "e"},
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

    def test_spatial_preparation_preserves_the_authored_project_without_rewriting_it(self) -> None:
        helper = load_helper()
        with tempfile.TemporaryDirectory() as root_dir:
            project = Path(root_dir) / "project"
            helper.prepare_spatial(SPATIAL_FIXTURE, project)
            expected = {p.relative_to(SPATIAL_FIXTURE): p.read_bytes() for p in SPATIAL_FIXTURE.rglob("*") if p.is_file()}
            actual = {p.relative_to(project): p.read_bytes() for p in project.rglob("*") if p.is_file()}
            self.assertEqual(actual, expected)

    def test_directory_refusal_uses_the_foreign_client_and_requires_concealment(self) -> None:
        helper = load_helper()
        with tempfile.TemporaryDirectory() as root_dir:
            root = Path(root_dir)
            prepare_request_root(root)
            def reply(status, document):
                def fake_urlopen(request, timeout=30):
                    self.assertEqual(request.method, "GET")
                    self.assertEqual(request.get_header("Authorization"), "Bearer foreign-editor.payload.signature")
                    self.assertIn("/contacts/contact-id?accessProfile=directory-editor", request.full_url)
                    return _FakeHttpResponse(status, json.dumps(document).encode())
                return fake_urlopen
            with mock.patch("urllib.request.urlopen", reply(404, {"code": "resource.not_found"})):
                helper.directory(root, "refusal", record_id="contact-id")
            for status, body in ((200, {"data": {}}), (404, {"code": "wrong"}), (404, {"code": "resource.not_found", "data": {}})):
                with mock.patch("urllib.request.urlopen", reply(status, body)):
                    with self.assertRaises(helper.QuickstartError):
                        helper.directory(root, "refusal", record_id="contact-id")


if __name__ == "__main__":
    unittest.main()
