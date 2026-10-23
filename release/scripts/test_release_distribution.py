#!/usr/bin/env python3
from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import os
import stat
import tempfile
from pathlib import Path
from unittest import TestCase, main, mock


SCRIPT = Path(__file__).with_name("release_distribution.py")


def load_module():
    spec = importlib.util.spec_from_file_location("release_distribution", SCRIPT)
    if spec is None or spec.loader is None:
        raise ImportError(f"could not load module spec from {SCRIPT}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class ReleaseDistributionTest(TestCase):
    def setUp(self) -> None:
        self.module = load_module()
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.repo = Path(self.temp.name)

    def write_selection(self, document: object, version: str = "0.45.0") -> Path:
        path = self.repo / "release" / "distributions" / f"v{version}.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(document), encoding="utf-8")
        return path

    def test_load_components_is_optional_and_closed(self) -> None:
        self.assertEqual([], self.module.load_components(self.repo, "0.45.0"))
        document = {
            "schema_version": "registry-stack.distribution-selection.v1",
            "stack_version": "0.45.0",
            "components": [
                {
                    "unit": "discovery",
                    "version": "1.2.3",
                    "policy": "exact",
                }
            ],
        }
        self.write_selection(document)
        self.assertEqual(document["components"], self.module.load_components(self.repo, "0.45.0"))

        changed = copy.deepcopy(document)
        changed["unknown"] = True
        self.write_selection(changed)
        with self.assertRaisesRegex(self.module.DistributionError, "exactly"):
            self.module.load_components(self.repo, "0.45.0")

    def test_selection_policy_admits_only_the_exact_committed_version(self) -> None:
        exact = {"unit": "discovery", "version": "2.0.0", "policy": "exact"}
        self.module.validate_selected_version(exact, "2.0.0")
        for selected in ("2.0.1", "1.9.9", "2.1.0"):
            with self.subTest(selected=selected):
                with self.assertRaisesRegex(self.module.DistributionError, "exact version"):
                    self.module.validate_selected_version(exact, selected)
        compatible = {"unit": "discovery", "version": "2.0.0", "policy": "compatible-patch"}
        with self.assertRaisesRegex(self.module.DistributionError, "policy must be exact"):
            self.module.validate_selected_version(compatible, "2.0.0")

    def test_authenticated_manifest_becomes_an_exact_component_lock(self) -> None:
        payload = {
            "name": "discovery-v1.2.4-linux-amd64",
            "kind": "binary",
            "size": 7,
            "sha256": "b" * 64,
        }
        manifest = {
            "schema_version": "registry-stack.release-candidate.v3",
            "repository": "registrystack/registry-stack",
            "release": {
                "unit": "discovery",
                "version": "1.2.4",
                "release_id": "discovery-beta-2",
                "tag": "discovery/v1.2.4",
                "source_sha": "a" * 40,
            },
            "validity": {"created_at": "2026-10-23T00:00:00Z"},
            "payloads": [payload],
            "images": [
                {
                    "name": "discovery",
                    "candidate_ref": "ghcr.io/registrystack/discovery-candidate@sha256:" + "c" * 64,
                    "final_ref": "ghcr.io/registrystack/discovery:v1.2.4",
                    "digest": "sha256:" + "c" * 64,
                }
            ],
        }
        body = (json.dumps(manifest, sort_keys=True) + "\n").encode()
        manifest_name = "registry-discovery-v1.2.4-release-manifest.json"
        checksums = {payload["name"]: payload["sha256"], manifest_name: hashlib.sha256(body).hexdigest()}
        selection = {"unit": "discovery", "version": "1.2.4", "policy": "exact"}
        with (
            mock.patch.object(
                self.module.release_candidate,
                "validate_candidate_manifest",
                return_value=manifest,
            ) as validate,
            mock.patch.object(
                self.module.release_candidate,
                "validate_release_components",
                side_effect=lambda components: components,
            ),
        ):
            component = self.module.component_from_authenticated_release(
                manifest_bytes=body,
                manifest_sha256=hashlib.sha256(body).hexdigest(),
                checksums=checksums,
                selection=selection,
            )
        self.assertEqual("discovery/v1.2.4", component["release_tag"])
        self.assertEqual("a" * 40, component["source_sha"])
        self.assertEqual(
            {"name": manifest_name, "sha256": hashlib.sha256(body).hexdigest()},
            component["manifest"],
        )
        self.assertEqual(
            [{"name": "discovery", "final_ref": "ghcr.io/registrystack/discovery:v1.2.4", "digest": "sha256:" + "c" * 64}],
            component["images"],
        )
        self.assertEqual("discovery", validate.call_args.kwargs["expected_unit"])

        rebound = copy.deepcopy(manifest)
        rebound["release"]["tag"] = "discovery/v1.2.3"
        rebound_body = (json.dumps(rebound, sort_keys=True) + "\n").encode()
        with (
            mock.patch.object(self.module.release_candidate, "validate_candidate_manifest", return_value=rebound),
            mock.patch.object(
                self.module.release_candidate,
                "validate_release_components",
                side_effect=lambda components: components,
            ),
            self.assertRaisesRegex(self.module.DistributionError, "release identity"),
        ):
            self.module.component_from_authenticated_release(
                manifest_bytes=rebound_body,
                manifest_sha256=hashlib.sha256(rebound_body).hexdigest(),
                checksums={
                    payload["name"]: payload["sha256"],
                    manifest_name: hashlib.sha256(rebound_body).hexdigest(),
                },
                selection=selection,
            )

    def test_distribution_lock_is_canonical_and_checksum_ready(self) -> None:
        component = {
            "unit": "discovery",
            "version": "1.2.3",
            "release_tag": "discovery/v1.2.3",
            "source_sha": "a" * 40,
            "manifest": {"name": "registry-discovery-v1.2.3-release-manifest.json", "sha256": "d" * 64},
            "payloads": [],
            "images": [],
        }
        with mock.patch.object(
            self.module.release_candidate,
            "validate_release_components",
            return_value=[component],
        ):
            body = self.module.render_distribution_lock("0.45.0", [component])
        self.assertTrue(body.endswith(b"\n"))
        self.assertEqual(
            "registry-stack-v0.45.0-distribution.json",
            self.module.distribution_lock_name("0.45.0"),
        )
        self.assertEqual([component], json.loads(body)["components"])

    def test_resolver_uses_only_the_committed_version(self) -> None:
        exact = {"unit": "discovery", "version": "2.0.0", "policy": "exact"}
        self.assertEqual("discovery/v2.0.0", self.module.select_release_tag(exact))

    def test_resolve_components_uses_complete_public_verifier(self) -> None:
        selection = {
            "unit": "discovery",
            "version": "1.2.3",
            "policy": "exact",
        }
        closure = {
            "manifest_bytes": b"{}\n",
            "manifest_sha256": "a" * 64,
            "checksums": {"manifest": "a" * 64},
        }
        component = {"unit": "discovery", "version": "1.2.4"}
        with (
            mock.patch.object(self.module, "load_components", return_value=[selection]),
            mock.patch.object(
                self.module.verify_public_release,
                "verify_component_closure",
                return_value=closure,
            ) as verify,
            mock.patch.object(
                self.module,
                "component_from_authenticated_release",
                return_value=component,
            ) as lock,
        ):
            self.assertEqual(
                [component],
                self.module.resolve_components(
                    self.repo,
                    "0.45.0",
                    repository="registrystack/registry-stack",
                ),
            )
        self.assertEqual("discovery/v1.2.3", verify.call_args.kwargs["tag"])
        self.assertEqual(closure["manifest_bytes"], lock.call_args.kwargs["manifest_bytes"])


class DistributionInstallTest(TestCase):
    def setUp(self) -> None:
        self.module = load_module()
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.assets = self.root / "release-assets"
        self.assets.mkdir()
        self.install_dir = self.root / "install" / "bin"
        self.fake_bin = self.root / "fake-bin"
        self.fake_bin.mkdir()
        self.log = self.root / "gh-requests.jsonl"
        self._write_fake_gh()
        self._write_fake_uname()
        self.component = self._write_component_assets()
        self.lock = self.root / "registry-stack-v0.45.0-distribution.json"
        self.lock.write_bytes(
            self.module.render_distribution_lock("0.45.0", [self.component])
        )

    def _write_component_assets(self) -> dict:
        version = "1.2.3"
        inventory = self.module.release_units.payload_inventory("discovery", version)
        source_installer = (
            SCRIPT.parents[2] / "crates" / "registry-discovery" / "install.sh"
        ).read_text(encoding="utf-8")
        installer = source_installer.replace(
            'default_version=""', 'default_version="v1.2.3"', 1
        ).encode()
        payloads = []
        for index, (name, kind) in enumerate(sorted(inventory.items())):
            if name in {
                "discovery-v1.2.3-linux-amd64",
                "discoveryctl-v1.2.3-linux-amd64",
            }:
                binary = name.split("-v", 1)[0]
                body = (
                    "#!/bin/sh\n"
                    'if [ "${1:-}" = "--version" ]; then\n'
                    f"  printf '{binary} 1.2.3\\n'\n"
                    "  exit 0\n"
                    "fi\n"
                    "exit 2\n"
                ).encode()
            elif kind == "installer":
                body = installer
            else:
                body = f"fixture {index}: {name}\n".encode()
            path = self.assets / name
            path.write_bytes(body)
            if kind in {"binary", "installer"}:
                path.chmod(0o755)
            payloads.append(
                {
                    "name": name,
                    "kind": kind,
                    "size": len(body),
                    "sha256": hashlib.sha256(body).hexdigest(),
                }
            )
        return {
            "unit": "discovery",
            "version": version,
            "release_tag": "discovery/v1.2.3",
            "source_sha": "a" * 40,
            "manifest": {
                "name": "registry-discovery-v1.2.3-release-manifest.json",
                "sha256": "b" * 64,
            },
            "payloads": payloads,
            "images": [
                {
                    "name": "discovery",
                    "final_ref": "ghcr.io/registrystack/discovery:v1.2.3",
                    "digest": "sha256:" + "c" * 64,
                }
            ],
        }

    def _write_fake_gh(self) -> None:
        path = self.fake_bin / "gh"
        path.write_text(
            "#!/usr/bin/env python3\n"
            "import json, os, shutil, sys\n"
            "args = sys.argv[1:]\n"
            "with open(os.environ['FAKE_GH_LOG'], 'a', encoding='utf-8') as log:\n"
            "    log.write(json.dumps(args) + '\\n')\n"
            "if args[:2] != ['release', 'download']:\n"
            "    raise SystemExit(2)\n"
            "destination = args[args.index('--dir') + 1]\n"
            "patterns = [args[i + 1] for i, value in enumerate(args) if value == '--pattern']\n"
            "for name in patterns:\n"
            "    shutil.copy2(os.path.join(os.environ['FAKE_RELEASE_DIR'], name), destination)\n",
            encoding="utf-8",
        )
        path.chmod(path.stat().st_mode | stat.S_IXUSR)

    def _write_fake_uname(self) -> None:
        path = self.fake_bin / "uname"
        path.write_text(
            "#!/bin/sh\n"
            "case \"${1:-}\" in\n"
            "  -s) printf 'Linux\\n' ;;\n"
            "  -m) printf 'x86_64\\n' ;;\n"
            "  *) exit 2 ;;\n"
            "esac\n",
            encoding="utf-8",
        )
        path.chmod(path.stat().st_mode | stat.S_IXUSR)

    def install(self) -> dict:
        environment = {
            "PATH": f"{self.fake_bin}:{os.environ['PATH']}",
            "FAKE_GH_LOG": str(self.log),
            "FAKE_RELEASE_DIR": str(self.assets),
        }
        with mock.patch.dict(os.environ, environment, clear=False):
            return self.module.install_from_distribution_lock(
                self.lock,
                self.install_dir,
            )

    def test_installs_original_authenticated_pair_with_original_installer(self) -> None:
        result = self.install()
        self.assertEqual(
            {"discovery": "discovery 1.2.3", "discoveryctl": "discoveryctl 1.2.3"},
            result["versions"],
        )
        self.assertEqual("discovery/v1.2.3", result["release_tag"])
        requests = [json.loads(line) for line in self.log.read_text().splitlines()]
        self.assertEqual(1, len(requests))
        request = requests[0]
        self.assertEqual(["release", "download", "discovery/v1.2.3"], request[:3])
        self.assertEqual(
            "github.com/registrystack/registry-stack",
            request[request.index("--repo") + 1],
        )
        self.assertEqual(
            {
                "discovery-v1.2.3-linux-amd64",
                "discoveryctl-v1.2.3-linux-amd64",
                "discovery-v1.2.3-install.sh",
            },
            {
                request[index + 1]
                for index, value in enumerate(request)
                if value == "--pattern"
            },
        )

    def test_tampered_download_refuses_before_install(self) -> None:
        path = self.assets / "discoveryctl-v1.2.3-linux-amd64"
        tampered = bytearray(path.read_bytes())
        tampered[-1] = ord("\n") if tampered[-1] != ord("\n") else ord(" ")
        path.write_bytes(tampered)
        with self.assertRaisesRegex(self.module.DistributionError, "digest"):
            self.install()
        self.assertFalse(self.install_dir.exists())

    def test_truncated_download_refuses_recorded_size(self) -> None:
        (self.assets / "discovery-v1.2.3-linux-amd64").write_bytes(b"short")
        with self.assertRaisesRegex(self.module.DistributionError, "size"):
            self.install()
        self.assertFalse(self.install_dir.exists())

    def test_lock_must_be_closed_and_cannot_rebind_source_release(self) -> None:
        document = json.loads(self.lock.read_text())
        document["components"][0]["release_tag"] = "discovery/v1.2.4"
        self.lock.write_text(json.dumps(document))
        with self.assertRaisesRegex(self.module.DistributionError, "lock is invalid"):
            self.install()
        self.assertFalse(self.log.exists())


if __name__ == "__main__":
    main()
