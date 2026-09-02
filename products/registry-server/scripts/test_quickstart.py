#!/usr/bin/env python3

from __future__ import annotations

import contextlib
import importlib.util
import io
import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock


PRODUCT_ROOT = Path(__file__).resolve().parents[1]
QUICKSTART = PRODUCT_ROOT / "quickstart"
SPATIAL_FIXTURE = PRODUCT_ROOT / "acceptance/spatial-service-sites"


def load_helper():
    spec = importlib.util.spec_from_file_location("quickstart_support", QUICKSTART / "support/quickstart.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def prepare_root(root: Path) -> None:
    (root / "project/tests").mkdir(parents=True)
    (root / "secrets").mkdir()
    (root / "keys").mkdir()
    (root / "project/registry.yaml").write_text("apiVersion: registry.registrystack.org/v1alpha1\nkind: RegistryProject\n", encoding="utf-8")
    (root / "project/tests/journeys.yaml").write_text(
        "journeys:\n"
        "  - id: generic-smoke\n"
        "    steps:\n"
        "      - id: create-record\n"
        "      - id: get-record\n"
        "      - id: list-records\n",
        encoding="utf-8",
    )
    (root / "secrets/database-password").write_text("abcdef0123456789", encoding="ascii")
    (root / "keys/mint-public.jwk.json").write_text('{"kid":"mint-key","kty":"EC"}', encoding="utf-8")
    (root / "keys/operator-public.jwk.json").write_text('{"kid":"operator-key","kty":"EC"}', encoding="utf-8")


def prepare_request_root(root: Path) -> None:
    root.chmod(0o700)
    (root / "secrets").mkdir(mode=0o700)
    (root / "server-origin").write_text("http://127.0.0.1:1\n", encoding="ascii")
    token_path = root / "secrets/operator-token"
    token_path.write_text("header.payload.signature", encoding="ascii")
    token_path.chmod(0o600)
    map_token_path = root / "secrets/map-token"
    map_token_path.write_text("header.payload.signature", encoding="ascii")
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


class RegistryServerQuickstartTests(unittest.TestCase):
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
        self.assertIn("registry-serverctl init", readme)
        self.assertIn("adds only local package identity", readme)
        self.assertIn("quickstart/.run/secrets/operator-token", readme)
        self.assertIn("does not put the token on the command line", readme)
        self.assertIn("unsigned", readme)
        self.assertIn("local package", readme)
        self.assertIn("Production pilots still require", readme)


    def test_prepare_outputs_keep_generic_absent_and_spatial_explicit(self) -> None:
        helper = load_helper()
        with tempfile.TemporaryDirectory() as generic_dir, tempfile.TemporaryDirectory() as spatial_dir:
            generic_root = Path(generic_dir)
            prepare_root(generic_root)
            helper.prepare(generic_root, 15432, 18080, 18081)
            generic_runtime = (generic_root / "runtime-test.yaml").read_text(encoding="utf-8")
            generic_bootstrap = (generic_root / "database/bootstrap.sql").read_text(encoding="utf-8")
            generic_initialize = (generic_root / "database/initialize.sql").read_text(encoding="utf-8")
            self.assertIn("allowedClients: [generic-quickstart]", generic_runtime)
            self.assertNotIn("publicOrigin", generic_runtime)
            self.assertNotIn("qgis-installation-central", generic_runtime)
            self.assertNotIn("registry_spatial_ext", generic_initialize)
            self.assertNotIn("registry_quickstart_runtime__spatial_bbox", generic_bootstrap)
            self.assertNotIn("registry_quickstart_runtime__spatial_bbox", generic_initialize)

            spatial_root = Path(spatial_dir)
            (spatial_root / "secrets").mkdir()
            (spatial_root / "keys").mkdir()
            helper.prepare_spatial_project(SPATIAL_FIXTURE, spatial_root / "project")
            (spatial_root / "secrets/database-password").write_text("abcdef0123456789", encoding="ascii")
            (spatial_root / "keys/mint-public.jwk.json").write_text('{"kid":"mint-key","kty":"EC"}', encoding="utf-8")
            (spatial_root / "keys/operator-public.jwk.json").write_text('{"kid":"operator-key","kty":"EC"}', encoding="utf-8")
            helper.prepare(spatial_root, 15432, 18080, 18081, True, "sha256:testfingerprint")
            spatial_registry = (spatial_root / "project/registry.yaml").read_text(encoding="utf-8")
            spatial_runtime = (spatial_root / "runtime-test.yaml").read_text(encoding="utf-8")
            spatial_bootstrap = (spatial_root / "database/bootstrap.sql").read_text(encoding="utf-8")
            spatial_initialize = (spatial_root / "database/initialize.sql").read_text(encoding="utf-8")
            spatial_initialize_runtime = (spatial_root / "database/initialize-runtime.sql").read_text(encoding="utf-8")
            qgis_client = (spatial_root / "mint/clients/qgis-installation-central.yaml").read_text(encoding="utf-8")
            credentials = (spatial_root / "schema-test-credentials.yaml").read_text(encoding="utf-8")
            self.assertIn("environment: local", spatial_registry)
            self.assertIn("instanceId: generic_registry_local", spatial_registry)
            self.assertIn("manifestProjection:", spatial_registry)
            self.assertIn("publicOrigin: http://127.0.0.1:18081", spatial_runtime)
            self.assertIn("qgis-installation-central", spatial_runtime)
            self.assertIn("registry_spatial_ext", spatial_initialize)
            self.assertIn("registry_spatial_ext", spatial_initialize_runtime)
            self.assertIn("CREATE ROLE registry_quickstart_runtime__spatial_bbox NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS;", spatial_bootstrap)
            self.assertIn("GRANT registry_quickstart_runtime__spatial_bbox TO registry_quickstart_migration WITH INHERIT FALSE, SET TRUE, ADMIN FALSE;", spatial_bootstrap)
            self.assertIn("GRANT USAGE ON SCHEMA registry_spatial_ext TO registry_quickstart_migration, registry_quickstart_runtime, registry_quickstart_runtime__spatial_bbox;", spatial_initialize)
            self.assertIn("GRANT USAGE ON SCHEMA registry_spatial_ext TO registry_quickstart_migration, registry_quickstart_runtime, registry_quickstart_runtime__spatial_bbox;", spatial_initialize_runtime)
            self.assertNotIn("registry_quickstart_runtime__spatial_bbox TO registry_quickstart_runtime", spatial_bootstrap)
            self.assertNotIn("registry_quickstart_runtime__spatial_bbox LOGIN", spatial_bootstrap)
            self.assertNotIn("AUTHORIZATION registry_quickstart_runtime__spatial_bbox", spatial_initialize)
            self.assertNotIn("CREATE SCHEMA registry_spatial_ext AUTHORIZATION registry_quickstart_runtime__spatial_bbox", spatial_initialize)
            self.assertIn("clientAuthentication:", qgis_client)
            self.assertIn('secretFingerprints: ["sha256:testfingerprint"]', qgis_client)
            admin_client = (spatial_root / "mint/clients/generic-quickstart.yaml").read_text(encoding="utf-8")
            self.assertIn("synthetic-service-site-admin", admin_client)
            self.assertIn("service_zones: central", qgis_client)
            self.assertIn("create-central-service-site", credentials)
            self.assertIn("installation-client-sees-own-central-row", credentials)
            self.assertIn("public-map-reader-bbox-finds-central-site", credentials)
            self.assertIn("directory-reader-bbox-is-refused", credentials)
            self.assertIn("credential: {type: anonymous}", credentials)

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
                    helper.request(root, "create", "QS-001", "Quickstart example record", None)
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

            def fake_request_with_legacy_records_key(
                root_arg: Path,
                method: str,
                path: str,
                body: dict | None,
                idempotency_key: str | None = None,
                expected: int = 200,
                token_name: str = "operator-token",
                accept: str = "application/json",
            ) -> dict:
                if method == "POST":
                    return created
                if accept == "application/geo+json":
                    return geojson
                return {"records": [{}]}

            with mock.patch.object(helper, "_request", fake_request_with_legacy_records_key):
                with self.assertRaises(helper.QuickstartError):
                    helper.spatial_smoke(root, seed)

            def fake_request_with_items_key(
                root_arg: Path,
                method: str,
                path: str,
                body: dict | None,
                idempotency_key: str | None = None,
                expected: int = 200,
                token_name: str = "operator-token",
                accept: str = "application/json",
            ) -> dict:
                if method == "POST":
                    return created
                if accept == "application/geo+json":
                    return geojson
                return {"items": [{}], "pageInfo": {"nextCursor": None}, "meta": {}}

            with mock.patch.object(helper, "_request", fake_request_with_items_key):
                helper.spatial_smoke(root, seed)

    def test_spatial_launcher_preserves_generic_default_and_switches_only_on_flag(self) -> None:
        run_source = (QUICKSTART / "run.sh").read_text(encoding="utf-8")
        self.assertIn("spatial=false", run_source)
        self.assertIn('postgres_image="$ordinary_postgres_image"', run_source)
        self.assertIn("--spatial", run_source)
        self.assertIn("postgres_platform=(--platform linux/amd64)", run_source)
        self.assertIn("prepare-spatial-project", run_source)
        self.assertIn("mint-client-secret-token", run_source)
        self.assertIn("spatial-smoke", run_source)
        self.assertIn("service-site.installation-map-reader", run_source)
        self.assertIn("Registry Server generic quickstart smoke passed", run_source)
        self.assertIn("Registry Server spatial quickstart smoke passed", run_source)

    def test_spatial_helper_keeps_secret_file_private_and_runtime_clients_explicit(self) -> None:
        helper_source = (QUICKSTART / "support/quickstart.py").read_text(encoding="utf-8")
        self.assertIn('QGIS_CLIENT_ID = "qgis-installation-central"', helper_source)
        self.assertIn("clientAuthentication:", helper_source)
        self.assertIn("secretFingerprints:", helper_source)
        self.assertIn('_require_owner_only_regular(secret_path, "QGIS client secret")', helper_source)
        self.assertIn("registry_spatial_ext", helper_source)
        self.assertIn('SPATIAL_BBOX_ROLE = "registry_quickstart_runtime__spatial_bbox"', helper_source)
        self.assertIn("WITH INHERIT FALSE, SET TRUE, ADMIN FALSE", helper_source)
        self.assertIn("publicOrigin: http://127.0.0.1", helper_source)
        self.assertIn("service-sites:map.read", helper_source)
        self.assertIn("synthetic-qgis-installation", helper_source)
        self.assertIn("service_zones: central", helper_source)
        self.assertNotIn("print(secret", helper_source)


if __name__ == "__main__":
    unittest.main()
