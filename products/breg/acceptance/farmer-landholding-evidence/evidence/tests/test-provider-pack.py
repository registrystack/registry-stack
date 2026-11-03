#!/usr/bin/env python3
"""Pin the farmer provider's two governed pack acquisition routes."""

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest import mock

import yaml


ROOT = Path(__file__).resolve().parents[1]
PROJECT = ROOT / "provider"
RUN_PROVIDER_PATH = ROOT / "run-provider.py"
RUN_PROVIDER_SPEC = importlib.util.spec_from_file_location(
    "farmer_provider_runner", RUN_PROVIDER_PATH
)
assert RUN_PROVIDER_SPEC is not None and RUN_PROVIDER_SPEC.loader is not None
RUN_PROVIDER = importlib.util.module_from_spec(RUN_PROVIDER_SPEC)
RUN_PROVIDER_SPEC.loader.exec_module(RUN_PROVIDER)


class ProviderPackTest(unittest.TestCase):
    def test_output_root_accepts_fresh_or_empty_owner_only_directory(self):
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            fresh = parent / "fresh"
            self.assertEqual(RUN_PROVIDER.prepare_output_root(fresh), fresh.resolve())
            self.assertTrue(fresh.is_dir())
            self.assertEqual(stat.S_IMODE(fresh.stat().st_mode), 0o700)

            empty = parent / "empty"
            empty.mkdir(mode=0o700)
            self.assertEqual(RUN_PROVIDER.prepare_output_root(empty), empty.resolve())
            self.assertEqual(list(empty.iterdir()), [])

    def test_output_root_rejects_existing_data_symlink_and_wrong_owner(self):
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            nonempty = parent / "nonempty"
            nonempty.mkdir(mode=0o700)
            sentinel = nonempty / "keep"
            sentinel.write_bytes(b"do not touch")
            with self.assertRaisesRegex(RuntimeError, "empty"):
                RUN_PROVIDER.prepare_output_root(nonempty)
            self.assertEqual(sentinel.read_bytes(), b"do not touch")

            target = parent / "target"
            target.mkdir(mode=0o700)
            link = parent / "link"
            link.symlink_to(target, target_is_directory=True)
            with self.assertRaisesRegex(RuntimeError, "symbolic link"):
                RUN_PROVIDER.prepare_output_root(link)
            self.assertTrue(link.is_symlink())
            self.assertEqual(list(target.iterdir()), [])

            public = parent / "public"
            public.mkdir(mode=0o755)
            self.assertEqual(RUN_PROVIDER.prepare_output_root(public), public.resolve())
            self.assertEqual(stat.S_IMODE(public.stat().st_mode), 0o700)

            wrong_owner = parent / "wrong-owner"
            wrong_owner.mkdir(mode=0o700)
            with mock.patch.object(
                RUN_PROVIDER.os, "geteuid", return_value=os.geteuid() + 1
            ):
                with self.assertRaisesRegex(RuntimeError, "current user"):
                    RUN_PROVIDER.prepare_output_root(wrong_owner)
            self.assertEqual(stat.S_IMODE(wrong_owner.stat().st_mode), 0o700)

    def test_package_compiler_is_bound_to_the_supplied_evidence_runtime(self):
        evidence = Path("/verified/evidence")
        evidencectl = Path("/verified/evidencectl")
        with mock.patch.dict(os.environ, {"EVIDENCE_BIN": "/poison/evidence"}):
            with mock.patch.object(RUN_PROVIDER, "command") as command:
                RUN_PROVIDER.compile_package(
                    evidencectl,
                    evidence,
                    Path("/project"),
                    Path("/project/provider-target.yaml"),
                    Path("/candidate"),
                )
            self.assertEqual(os.environ["EVIDENCE_BIN"], "/poison/evidence")

        command.assert_called_once()
        args, kwargs = command.call_args
        self.assertEqual(args[0], str(evidencectl))
        self.assertEqual(kwargs["env"]["EVIDENCE_BIN"], str(evidence))

    def test_project_binds_both_sources_only_to_reviewed_pack_routes(self):
        project = yaml.safe_load((PROJECT / "evidence.yaml").read_text())
        self.assertEqual(project["kind"], "EvidenceProject")
        sources = project["sources"]
        self.assertEqual(set(sources), {"source-status", "source-category"})
        self.assertEqual(
            sources["source-status"],
            {
                "pack": {"id": "farmer-facts", "version": "1"},
                "route": "status",
                "connection": "farmer-facts",
                "acquisitionPosture": "field-projected",
                "inputs": {
                    "reference": {
                        "selector": {
                            "role": "farmer",
                            "profile": "farmer-number-v1",
                            "field": "farmer-number",
                        }
                    }
                },
            },
        )
        expected_category = dict(sources["source-status"])
        expected_category["route"] = "category"
        self.assertEqual(sources["source-category"], expected_category)
        for source in sources.values():
            self.assertNotIn("type", source)
            self.assertNotIn("request", source)
            self.assertNotIn("baseUrl", source)

    def test_pack_routes_preserve_distinct_minimum_provider_requests(self):
        pack = json.loads(
            (PROJECT / "adapter-packs/farmer-facts/pack.yaml").read_text()
        )
        self.assertEqual(pack["id"], "farmer-facts")
        self.assertEqual(pack["version"], "1")
        routes = {route["id"]: route for route in pack["sourceRoutes"]}
        self.assertEqual(set(routes), {"status", "category"})
        for route_id, fact in (("status", "active"), ("category", "category")):
            route = routes[route_id]
            self.assertEqual(route["evidence"]["acquisitionPosture"], "field-projected")
            send = next(step["to"] for step in route["steps"] if "to" in step)
            self.assertEqual(send["uri"], "http:provider")
            self.assertEqual(send["parameters"]["httpMethod"], "POST")
            self.assertEqual(send["parameters"]["path"], "/v1/facts")
            self.assertEqual(send["parameters"]["operation"], "lookup")
            request = send["parameters"]["body"]["rhai"]
            self.assertEqual(request["entrypoint"], f"request_{route_id}")
            self.assertEqual(route["evidence"]["factsSchema"]["path"], f"schemas/{fact}-facts.json")

    def test_pack_digests_and_target_connection_are_closed(self):
        pack = json.loads(
            (PROJECT / "adapter-packs/farmer-facts/pack.yaml").read_text()
        )
        artifacts = list(pack["scripts"])
        for route in pack["sourceRoutes"]:
            artifacts.extend(
                (
                    route["evidence"]["inputsSchema"],
                    route["evidence"]["factsSchema"],
                )
            )
            for step in route["steps"]:
                if "validateSchema" in step:
                    artifacts.append(step["validateSchema"])
        for artifact in artifacts:
            actual = hashlib.sha256(
                (PROJECT / "adapter-packs/farmer-facts" / artifact["path"]).read_bytes()
            ).hexdigest()
            self.assertEqual(artifact["digest"], "sha256:" + actual, artifact["path"])

        schemas = PROJECT / "adapter-packs/farmer-facts/schemas"
        inputs = json.loads((schemas / "inputs.json").read_text())
        self.assertEqual(inputs["properties"]["reference"]["minLength"], 3)
        for response_name in ("status-provider.json", "category-provider.json"):
            response = json.loads((schemas / response_name).read_text())
            self.assertEqual(response["properties"]["total"]["maximum"], 1000)
            self.assertEqual(response["properties"]["reference"]["minLength"], 1)

        target = yaml.safe_load((PROJECT / "provider-target.yaml").read_text())
        self.assertEqual(
            target["connections"]["farmer-facts"],
            {
                "endpoints": {
                    "provider": {
                        "origin": "http://127.0.0.1:9",
                        "authentication": {
                            "type": "static-authorization",
                            "tokenRef": "secret:file/source-a-token",
                        },
                    }
                },
            },
        )


if __name__ == "__main__":
    unittest.main()
