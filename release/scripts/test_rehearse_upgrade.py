#!/usr/bin/env python3
from __future__ import annotations

import base64
import contextlib
import hashlib
import importlib.util
import io
import json
import socket
import tarfile
import tempfile
import unittest
import unittest.mock
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "release/scripts/rehearse-upgrade.py"
SPEC = importlib.util.spec_from_file_location("rehearse_upgrade", SCRIPT)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)

WORKFLOW = ROOT / ".github/workflows/release-upgrade-rehearsal.yml"
API_STABILITY = ROOT / "docs/site/src/content/docs/reference/api-stability.mdx"
Error = MODULE.RehearsalError


def write_tar(path: Path, members: dict[str, bytes]) -> None:
    with tarfile.open(path, "w:gz") as archive:
        for name, data in members.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            info.mode = 0o755
            archive.addfile(info, io.BytesIO(data))


class ReleaseSelectionTest(unittest.TestCase):
    def test_selects_the_release_this_source_succeeds_before_and_after_the_bump(self) -> None:
        published = ["v0.31.0", "v0.32.0", "v0.33.0", "v0.34.0-rc.1", "nightly"]
        self.assertEqual(MODULE.select_from_tag(published, "0.33.0"), "v0.33.0")
        self.assertEqual(MODULE.select_from_tag(published, "0.34.0"), "v0.33.0")
        self.assertEqual(MODULE.select_from_tag([*published, "v0.34.0"], "0.34.0"), "v0.34.0")

    def test_compares_versions_numerically(self) -> None:
        self.assertEqual(MODULE.select_from_tag(["v0.9.0", "v0.10.0"], "0.10.1"), "v0.10.0")

    def test_refuses_when_no_release_precedes_the_source(self) -> None:
        with self.assertRaisesRegex(Error, "no published release"):
            MODULE.select_from_tag(["v0.34.0"], "0.33.0")

    def test_refuses_the_v032_to_v033_exception_explicitly(self) -> None:
        for tag in ("v0.32.0", "v0.31.4", "v0.1.0"):
            with self.subTest(tag=tag), self.assertRaisesRegex(Error, "v0.32 to v0.33"):
                MODULE.check_forward_path(tag, "0.34.0")
        MODULE.check_forward_path("v0.33.0", "0.33.0")
        MODULE.check_forward_path("v0.33.0", "0.34.0")

    def test_refuses_to_move_state_backward(self) -> None:
        with self.assertRaisesRegex(Error, "only moves state forward"):
            MODULE.check_forward_path("v0.34.0", "0.33.0")

    def test_refuses_malformed_tags_and_versions(self) -> None:
        for tag in ("0.33.0", "v0.33", "v0.33.0-rc.1", "v01.2.3"):
            with self.subTest(tag=tag), self.assertRaises(Error):
                MODULE.parse_tag(tag)
        with self.assertRaises(Error):
            MODULE.parse_version("0.33.0-dev")

    def test_reads_the_workspace_version(self) -> None:
        MODULE.parse_version(MODULE.workspace_version(ROOT))

    def test_main_refuses_the_exception_before_any_download_or_container(self) -> None:
        stderr = io.StringIO()
        with tempfile.TemporaryDirectory() as temporary, contextlib.redirect_stderr(stderr):
            work = Path(temporary) / "work"
            status = MODULE.main([
                "--from-tag", "v0.32.0", "--platform", "linux-amd64",
                "--to-bin-dir", temporary, "--work-dir", str(work),
            ])
            self.assertFalse(work.exists())
        self.assertEqual(status, 1)
        self.assertIn("no forward state path", stderr.getvalue())

    def test_fetch_only_needs_no_binaries_under_test(self) -> None:
        args = MODULE.parse_args(["--fetch-only", "--platform", "linux-amd64",
                                  "--work-dir", "/work"])
        self.assertTrue(args.fetch_only)
        self.assertIsNone(args.to_bin_dir)
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            MODULE.parse_args(["--platform", "linux-amd64", "--work-dir", "/work"])
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            MODULE.parse_args(["--fetch-only", "--from-bin-dir", "/bin", "--platform",
                               "linux-amd64", "--work-dir", "/work"])

    def test_fetch_only_authenticates_the_release_and_starts_nothing(self) -> None:
        def fetch(tag, platform, download, bin_dir, binaries):
            bin_dir.mkdir(mode=0o700)
            for binary in binaries:
                script = bin_dir / binary
                script.write_text(f"#!/bin/sh\necho '{binary} 0.33.0'\n", encoding="utf-8")
                script.chmod(0o755)

        with tempfile.TemporaryDirectory() as temporary, \
                contextlib.redirect_stdout(io.StringIO()), \
                unittest.mock.patch.object(MODULE, "fetch_release", side_effect=fetch) as fetched, \
                unittest.mock.patch.object(MODULE, "Postgres", side_effect=AssertionError("started")), \
                unittest.mock.patch.object(MODULE, "workspace_version", return_value="0.34.0"):
            work = Path(temporary) / "work"
            report = Path(temporary) / "report.json"
            status = MODULE.main(["--fetch-only", "--from-tag", "v0.33.0", "--platform",
                                  "linux-amd64", "--product", "breg", "--work-dir", str(work),
                                  "--report", str(report)])
            self.assertEqual(status, 0)
            self.assertEqual(fetched.call_args.args[4], ("breg", "bregctl"))
            self.assertTrue((work / "from-bin" / "bregctl").is_file())
            document = json.loads(report.read_text(encoding="utf-8"))
        self.assertEqual(document["fromProvenance"], "cosign and SHA256SUMS verified")
        self.assertEqual(document["fromBinDir"], str(work.resolve() / "from-bin"))
        self.assertNotIn("breg", document)


class AssetAuthenticationTest(unittest.TestCase):
    def test_names_one_asset_per_rehearsed_binary(self) -> None:
        linux = MODULE.asset_names("v0.33.0", "linux-amd64")
        self.assertEqual(sorted(linux), sorted(MODULE.BINARIES))
        self.assertEqual(linux["bregctl"], "bregctl-v0.33.0-linux-amd64")
        macos = MODULE.asset_names("v0.33.0", "macos-arm64")
        self.assertEqual(macos["evidence"], "evidence-v0.33.0-macos-arm64.tar.gz")
        with self.assertRaises(Error):
            MODULE.asset_names("v0.33.0", "windows-amd64")

    def test_parses_sha256sums_strictly(self) -> None:
        digest = "a" * 64
        self.assertEqual(MODULE.parse_sha256sums(f"{digest}  breg\n"), {"breg": digest})
        for text in (
            f"{digest} breg\n",
            f"{digest}  ../breg\n",
            f"{'A' * 64}  breg\n",
            f"{digest}  breg\n{digest}  breg\n",
        ):
            with self.subTest(text=text), self.assertRaises(Error):
                MODULE.parse_sha256sums(text)

    def test_verifies_each_asset_by_name(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            (directory / "breg").write_bytes(b"breg")
            (directory / "other").write_bytes(b"breg")
            digests = {"breg": hashlib.sha256(b"breg").hexdigest()}
            MODULE.verify_assets_by_name(directory, ["breg"], digests)
            with self.assertRaisesRegex(Error, "does not cover other"):
                MODULE.verify_assets_by_name(directory, ["other"], digests)
            (directory / "breg").write_bytes(b"tampered")
            with self.assertRaisesRegex(Error, "does not match"):
                MODULE.verify_assets_by_name(directory, ["breg"], digests)
            with self.assertRaisesRegex(Error, "was not downloaded"):
                MODULE.verify_assets_by_name(directory, ["absent"], {"absent": "0" * 64})

    def test_installs_a_linux_asset_as_the_plain_binary_name(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            asset = directory / "breg-v0.33.0-linux-amd64"
            asset.write_bytes(b"binary")
            destination = directory / "bin"
            destination.mkdir()
            MODULE.install_asset(asset, "breg", destination)
            self.assertEqual((destination / "breg").read_bytes(), b"binary")
            self.assertTrue((destination / "breg").stat().st_mode & 0o100)

    def test_installs_only_a_closed_macos_bundle(self) -> None:
        stem = "breg-v0.33.0-macos-arm64"
        library = "libaws_lc_fips_0_14_2_crypto.dylib"
        closed = {stem: b"binary", "THIRD_PARTY_NOTICES": b"notices", library: b"fips"}
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            destination = directory / "bin"
            destination.mkdir()
            asset = directory / f"{stem}.tar.gz"
            write_tar(asset, closed)
            MODULE.install_asset(asset, "breg", destination)
            self.assertEqual((destination / "breg").read_bytes(), b"binary")
            self.assertEqual((destination / library).read_bytes(), b"fips")
            self.assertFalse((destination / "THIRD_PARTY_NOTICES").exists())

            refused = {
                "extra member": {**closed, "install.sh": b"#!/bin/sh"},
                "missing notices": {stem: b"binary", library: b"fips"},
                "missing library": {stem: b"binary", "THIRD_PARTY_NOTICES": b"notices"},
                "other executable": {"bregctl": b"binary", "THIRD_PARTY_NOTICES": b"n",
                                     library: b"fips"},
                "path traversal": {stem: b"binary", "THIRD_PARTY_NOTICES": b"n",
                                   f"../{library}": b"fips"},
            }
            for label, members in refused.items():
                with self.subTest(label=label):
                    write_tar(asset, members)
                    with self.assertRaisesRegex(Error, "closed macOS native bundle"):
                        MODULE.install_asset(asset, "breg", destination)

            write_tar(asset, {**closed, library: b"different"})
            with self.assertRaisesRegex(Error, "conflicting"):
                MODULE.install_asset(asset, "breg", destination)


class SideTest(unittest.TestCase):
    def test_delegating_tools_find_this_side_s_runtime_not_an_ambient_one(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            bin_dir = Path(temp) / "bin"
            side = MODULE.Side("from", bin_dir, Path(temp) / "ca.pem")
            ambient = {"EVIDENCE_BIN": "/elsewhere/evidence", "PATH": "/usr/bin"}
            with unittest.mock.patch.dict(MODULE.os.environ, ambient):
                env = side.env()
            self.assertEqual(env["EVIDENCE_BIN"], str(bin_dir / "evidence"))
            self.assertEqual(env["PATH"].split(MODULE.os.pathsep)[0], str(bin_dir))

    def test_a_focused_run_needs_only_the_named_products_binaries(self) -> None:
        self.assertEqual(MODULE.product_binaries(["evidence"]), ("evidence", "evidencectl"))
        self.assertEqual(MODULE.product_binaries(list(MODULE.PRODUCTS)), MODULE.BINARIES)
        assets = MODULE.asset_names("v0.33.0", "linux-amd64", ("evidence", "evidencectl"))
        self.assertEqual(sorted(assets), ["evidence", "evidencectl"])
        with tempfile.TemporaryDirectory() as temp:
            bin_dir = Path(temp)
            for binary in ("evidence", "evidencectl"):
                script = bin_dir / binary
                script.write_text(f"#!/bin/sh\necho '{binary} 0.33.0'\n", encoding="utf-8")
                script.chmod(0o755)
            side = MODULE.Side("from", bin_dir, bin_dir / "ca.pem")
            versions = MODULE.check_binaries(side, "0.33.0", ("evidence", "evidencectl"))
            self.assertEqual(sorted(versions), ["evidence", "evidencectl"])
            with self.assertRaisesRegex(Error, "lack breg"):
                MODULE.check_binaries(side, "0.33.0", MODULE.BINARIES)


def load_json(path: Path) -> object:
    return json.loads(path.read_text(encoding="utf-8"))


def dump_json(path: Path, document: object) -> None:
    path.write_text(json.dumps(document), encoding="utf-8")


# JSON is YAML, so the runtime document round-trips without PyYAML, which the
# release-tool CI step does not install.
@unittest.mock.patch.object(MODULE, "dump_yaml", dump_json)
@unittest.mock.patch.object(MODULE, "load_yaml", load_json)
class CaseworkPackageTest(unittest.TestCase):
    def casework(self, root: Path) -> object:
        casework = MODULE.Casework.__new__(MODULE.Casework)
        casework.work = root
        casework.project = root / "project"
        casework.package = root / "package"
        casework.runtime = root / "runtime.yaml"
        casework.package.mkdir()
        dump_json(casework.runtime, {"package": {"root": str(casework.package)}})
        return casework

    def test_a_package_from_before_the_shared_format_is_rebuilt_by_the_new_side(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            casework = self.casework(Path(directory))
            (casework.package / "casework.package.json").write_text("{}")
            side = unittest.mock.Mock()
            self.assertTrue(casework.repackage(side))
            rebuilt = Path(directory) / "package-rebuilt"
            side.run.assert_called_once_with("caseworkctl", "package", str(casework.project),
                                             "--output", str(rebuilt))
            self.assertEqual(casework.package, rebuilt)
            self.assertEqual(load_json(casework.runtime)["package"]["root"], str(rebuilt))

    def test_a_shared_format_package_is_kept(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            casework = self.casework(Path(directory))
            (casework.package / "SHA256SUMS").write_text("")
            side = unittest.mock.Mock()
            self.assertFalse(casework.repackage(side))
            side.run.assert_not_called()
            self.assertEqual(load_json(casework.runtime)["package"]["root"],
                             str(casework.package))


class EvidenceGrammarTest(unittest.TestCase):
    OLD_GOVERNANCE = {
        "version": 1,
        "authentication": {
            "kind": "oidc-access-token",
            "issuer": "http://127.0.0.1:9000",
            "audiences": ["urn:example:evidence"],
            "jwksUri": "http://127.0.0.1:9000/oauth2/jwks",
            "requiredScopes": ["evidence"],
        },
        "audit": {"format": "keyed-jsonl", "hashSecretRef": "secret:file/audit",
                  "hashKeyVersion": 1, "failClosed": True},
    }
    OLD_RUNTIME = {
        "version": 1,
        "bundleDirectory": "/srv/candidate/bundle",
        "listener": {"bindHost": "127.0.0.1", "port": 8080, "tlsTermination": "x"},
        "metricsListener": {"bindHost": "::1", "port": 9090},
        "secretProviders": {"file": {"root": "/srv/secrets"}},
        "auditStorage": {"path": "/audit/evidence.jsonl", "maximumFileBytes": 1048576},
    }

    def test_an_earlier_governance_moves_to_the_oidc_block_and_the_current_audit_key(self) -> None:
        migrated = MODULE.migrate_evidence_governance(self.OLD_GOVERNANCE)
        self.assertEqual(migrated["authentication"], {"oidc": {
            "issuer": "http://127.0.0.1:9000",
            "audience": "urn:example:evidence",
            "jwksSource": {"kind": "uri", "uri": "http://127.0.0.1:9000/oauth2/jwks"},
            "requiredScopes": ["evidence"],
        }})
        self.assertEqual(migrated["audit"], {"hashKeyRef": "secret:file/audit",
                                             "hashKeyVersion": 1})
        self.assertEqual(self.OLD_GOVERNANCE["authentication"]["kind"], "oidc-access-token")
        self.assertEqual(MODULE.migrate_evidence_governance(migrated), migrated)

    def test_an_earlier_governance_with_several_audiences_is_refused(self) -> None:
        governance = {"authentication": {**self.OLD_GOVERNANCE["authentication"],
                                         "audiences": ["a", "b"]}}
        with self.assertRaisesRegex(Error, "one audience"):
            MODULE.migrate_evidence_governance(governance)

    def test_an_earlier_runtime_gains_the_envelope_package_bind_addresses_and_audit_block(self) -> None:
        migrated = MODULE.migrate_evidence_runtime(self.OLD_RUNTIME)
        self.assertEqual(migrated, {
            "apiVersion": "registry.registrystack.org/evidence-runtime/v1alpha1",
            "kind": "EvidenceRuntimeConfig",
            "package": {"root": "/srv/candidate/bundle"},
            "listener": {"bind": "127.0.0.1:8080", "tlsTermination": "x"},
            "metricsListener": {"bind": "[::1]:9090"},
            "secretProviders": {"file": {"root": "/srv/secrets"}},
            "audit": {"path": "/audit/evidence.jsonl", "rotateBytes": 1048576},
        })
        self.assertEqual(MODULE.migrate_evidence_runtime(migrated), migrated)

    def test_the_runtime_file_is_named_the_way_each_side_reads_it(self) -> None:
        runtime = Path("/srv/runtime.yaml")
        self.assertEqual(MODULE.evidence_arguments(True, runtime, "check"),
                         ["check", "--runtime-config", "/srv/runtime.yaml"])
        self.assertEqual(MODULE.evidence_arguments(False, runtime, "check"),
                         ["--runtime", "/srv/runtime.yaml", "check"])
        self.assertEqual(MODULE.breg_arguments(True, runtime),
                         ["--runtime-config", "/srv/runtime.yaml"])
        self.assertEqual(MODULE.breg_arguments(False, runtime),
                         ["--config", "/srv/runtime.yaml"])

    def test_a_local_target_becomes_a_production_target_in_either_grammar(self) -> None:
        local = {
            "assuranceProfile": "local",
            "service": {"providerId": "urn:registrystack:evidence:local:provider",
                        "publicOrigin": "http://127.0.0.1:8080"},
            "publication": {"endpointUrl": "http://127.0.0.1:8080"},
            "responseFormats": [],
            "signing": {"activePublicJwkFile": "public-keys/local.jwk.json"},
            "authorityProfiles": {"local-caller": {"grants": [], "kind": "explicit-request"}},
        }
        for authentication, issuer_key, jwks in (
            (self.OLD_GOVERNANCE["authentication"], ("issuer",), ("jwksUri",)),
            ({"oidc": {"issuer": "http://127.0.0.1:8081"}}, ("oidc", "issuer"),
             ("oidc", "jwksSource", "uri")),
        ):
            production = MODULE.evidence_production_governance(
                {**local, "authentication": authentication}, "https://127.0.0.1:9443",
                "public-keys/transit.jwk.json")
            self.assertEqual(production["assuranceProfile"], "production")
            self.assertEqual(production["service"], {
                "providerId": "urn:example:upgrade-rehearsal:provider",
                "publicOrigin": "https://evidence.example.test"})
            self.assertEqual(production["publication"],
                             {"endpointUrl": "https://evidence.example.test"})
            self.assertEqual(production["responseFormats"], ["signed-jws"])
            self.assertEqual(production["authorityProfiles"]["local-caller"]["grants"], [{
                "requirement": MODULE.EVIDENCE_REQUIREMENT,
                "purpose": MODULE.EVIDENCE_PURPOSE,
                "audienceFrom": "authenticated-requester",
                "responseFormats": ["signed-jws"],
                "subjects": [{"role": "subject", "selectorProfile": "record-reference-v1",
                              "valueOrigin": "request"}]}])
            self.assertEqual(production["signing"],
                             {"activePublicJwkFile": "public-keys/transit.jwk.json"})
            value: Any = production["authentication"]
            for key in issuer_key:
                value = value[key]
            self.assertEqual(value, "https://127.0.0.1:9443")
            value = production["authentication"]
            for key in jwks:
                value = value[key]
            self.assertEqual(value, "https://127.0.0.1:9443/oauth2/jwks")
        self.assertEqual(local["assuranceProfile"], "local")


class TransitStubTest(unittest.TestCase):
    def test_a_der_signature_becomes_the_fixed_width_jws_form(self) -> None:
        der = bytes([0x30, 0x45, 0x02, 0x21, 0x00]) + b"\x81" * 32 + bytes([0x02, 0x20]) + b"\x02" * 32
        self.assertEqual(MODULE.ecdsa_der_to_raw(der), b"\x81" * 32 + b"\x02" * 32)
        short = bytes([0x30, 0x24, 0x02, 0x1f]) + b"\x03" * 31 + bytes([0x02, 0x01, 0x04])
        self.assertEqual(MODULE.ecdsa_der_to_raw(short),
                         b"\x00" + b"\x03" * 31 + b"\x00" * 31 + b"\x04")
        with self.assertRaises(Error):
            MODULE.ecdsa_der_to_raw(b"\x31\x00")

    def test_the_stub_signs_a_prehashed_digest_the_public_key_verifies(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            key = Path(directory) / "transit.pem"
            MODULE.run(["openssl", "ecparam", "-name", "prime256v1", "-genkey", "-noout",
                        "-out", str(key)])
            jwk = MODULE.ec_public_jwk(key)
            self.assertEqual(sorted(jwk), ["alg", "crv", "kid", "kty", "x", "y"])
            transit = MODULE.TransitServer(key)
            try:
                metadata = transit_call(transit.socket_path, "GET",
                                        "/v1/transit/keys/evidence-signing", None)
                self.assertEqual(metadata["data"]["latest_version"], 1)
                public_pem = metadata["data"]["keys"]["1"]["public_key"]
                digest = hashlib.sha256(b"rehearsal").digest()
                signed = transit_call(transit.socket_path, "POST",
                                      "/v1/transit/sign/evidence-signing/sha2-256",
                                      {"input": base64.b64encode(digest).decode(),
                                       "key_version": 1, "prehashed": True,
                                       "marshaling_algorithm": "jws"})
                refused = transit_call(transit.socket_path, "POST",
                                       "/v1/transit/sign/evidence-signing/sha2-256",
                                       {"input": base64.b64encode(digest).decode(),
                                        "key_version": 1, "prehashed": False,
                                        "marshaling_algorithm": "jws"})
            finally:
                transit.stop()
            self.assertIn("errors", refused)
            self.assertFalse(transit.socket_path.exists())
            prefix, raw = signed["data"]["signature"].rsplit(":", 1)
            self.assertEqual(prefix, "vault:v1")
            raw_bytes = base64.urlsafe_b64decode(raw + "=" * (-len(raw) % 4))
            self.assertEqual(len(raw_bytes), 64)
            public = Path(directory) / "public.pem"
            public.write_text(public_pem)
            signature = Path(directory) / "signature.der"
            signature.write_bytes(raw_to_der(raw_bytes))
            message = Path(directory) / "digest"
            message.write_bytes(digest)
            MODULE.run(["openssl", "pkeyutl", "-verify", "-pubin", "-inkey", str(public),
                        "-in", str(message), "-sigfile", str(signature)])


def transit_call(socket_path: Path, method: str, path: str, body: Any) -> Any:
    data = json.dumps(body).encode() if body is not None else b""
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
        client.connect(str(socket_path))
        client.sendall(f"{method} {path} HTTP/1.1\r\nHost: transit\r\n"
                       f"Content-Length: {len(data)}\r\nConnection: close\r\n\r\n".encode()
                       + data)
        response = b""
        while chunk := client.recv(65536):
            response += chunk
    return json.loads(response.split(b"\r\n\r\n", 1)[1])


def raw_to_der(raw: bytes) -> bytes:
    def integer(value: bytes) -> bytes:
        value = value.lstrip(b"\0") or b"\0"
        if value[0] & 0x80:
            value = b"\0" + value
        return bytes([0x02, len(value)]) + value
    body = integer(raw[:32]) + integer(raw[32:])
    return bytes([0x30, len(body)]) + body


class StateComparisonTest(unittest.TestCase):
    def test_a_table_that_lost_rows_or_vanished_is_a_loss(self) -> None:
        before = {"public.a": 3, "public.b": 2, "public.c": 0}
        after = {"public.a": 3, "public.b": 1, "public.d": 5}
        self.assertEqual(MODULE.row_count_losses(before, after), [
            "public.b dropped from 2 to 1 rows",
            "public.c disappeared (held 0 rows)",
        ])

    def test_only_retired_audit_tables_can_be_replaced_by_an_archive(self) -> None:
        self.assertTrue(MODULE.row_count_losses({"public.records": 3}, {}, {"public.records": 3}))

    def test_successor_preserves_record_state_while_etags_change(self) -> None:
        before = {"records/1": {"etag": "old-package", "domainData": {"code": "a"}, "revision": "r1"}}
        after = {"records/1": {"etag": "new-package", "domainData": {"code": "a"}, "revision": "r1"}}
        self.assertEqual(MODULE.breg_view_differences(before, after), [])
        after["records/1"]["domainData"] = {"code": "lost"}
        self.assertTrue(MODULE.breg_view_differences(before, after))

    def test_growth_and_new_tables_are_not_losses(self) -> None:
        self.assertEqual(MODULE.row_count_losses({"a": 1}, {"a": 4, "b": 0}), [])

    def test_names_every_view_served_differently(self) -> None:
        before = {"records/1": {"etag": "1"}, "records/2": {"etag": "2"}}
        after = {"records/1": {"etag": "changed"}, "records/3": {"etag": "3"}}
        self.assertEqual(MODULE.view_differences(before, after), [
            "records/1 changed across the upgrade",
            "records/2 is no longer served",
            "records/3 was not captured before the upgrade",
        ])
        self.assertEqual(MODULE.view_differences(before, dict(before)), [])


class AuditUpgradeTest(unittest.TestCase):
    def test_archives_every_old_segment_before_a_fresh_stream(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            audit = root / "audit"
            audit.mkdir()
            for name in ("evidence.jsonl", "evidence.jsonl.00000001"):
                (audit / name).write_text('{"old":true}\n')
            (audit / "other.jsonl").write_text("keep")
            archive = root / "archive"
            self.assertEqual(MODULE.archive_audit_files(audit, "evidence.jsonl", archive), 2)
            self.assertEqual(MODULE.audit_record_count(archive, "evidence.jsonl"), 2)
            self.assertEqual(sorted(path.name for path in audit.iterdir()), ["other.jsonl"])

    def test_fresh_stream_requires_valid_response_envelopes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            path = root / "evidence.jsonl"
            schema = "registry.evidence.audit/v2"
            for value in ({"old": True}, {"schema": schema, "phase": "response"}):
                path.write_text(json.dumps(value) + "\n")
                with self.assertRaises(Error):
                    MODULE.audit_record_count(root, "evidence.jsonl", schema=schema)
            path.write_text(json.dumps({"schema": schema, "phase": "response",
                "eventId": "event-1", "time": "2026-09-25T00:00:00Z",
                "correlation": "operation-1", "record": {}}) + "\n")
            self.assertEqual(MODULE.audit_record_count(root, "evidence.jsonl", schema=schema), 1)

    def test_retired_audit_tables_are_preserved_before_exclusion(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            postgres = unittest.mock.Mock()
            postgres.sql.return_value = '{"record":1}\n{"record":2}\n'
            table = "registry_internal.registry_audit"
            before = {table: 2, "registry_internal.registry_state": 1}
            archive = MODULE.archive_audit_tables(postgres, "registry", before, Path(temporary))
            self.assertEqual(archive, {table: 2})
            self.assertEqual(MODULE.row_count_losses(before,
                {"registry_internal.registry_state": 1}, archive), [])
            self.assertTrue(MODULE.row_count_losses(before, {}, archive))
            self.assertTrue(MODULE.row_count_losses(before, {}, {table: 1}))
            postgres.sql.return_value = '{"record":1}\n'
            with self.assertRaisesRegex(Error, "archive"):
                MODULE.archive_audit_tables(postgres, "registry", before, Path(temporary) / "bad")

    def test_outbox_drain_waits_and_refuses_a_timeout(self) -> None:
        postgres = unittest.mock.Mock()
        postgres.sql.side_effect = ["t", "2", "0"]
        with unittest.mock.patch.object(MODULE.time, "sleep"):
            MODULE.wait_for_casework_audit(postgres)
        postgres.sql.side_effect = None
        postgres.sql.return_value = "t"
        with unittest.mock.patch.object(MODULE.time, "monotonic", side_effect=[0, 91]):
            with self.assertRaisesRegex(Error, "drain"):
                MODULE.wait_for_casework_audit(postgres)


class GateWiringTest(unittest.TestCase):
    def test_workflow_rehearses_from_verified_release_assets(self) -> None:
        workflow = WORKFLOW.read_text(encoding="utf-8")
        for required in ("workflow_dispatch:", "pull_request:", "release/manifests/**",
                         "release/scripts/rehearse-upgrade.py",
                         "sigstore/cosign-installer@", "--platform linux-amd64",
                         "--features registry-breg/runtime"):
            self.assertTrue(required in workflow, f"workflow lacks {required!r}")
        for refused in ("--from-bin-dir", "contents: write", "id-token: write"):
            self.assertFalse(refused in workflow, f"workflow carries {refused!r}")

    def test_api_stability_states_the_same_exception(self) -> None:
        page = API_STABILITY.read_text(encoding="utf-8")
        floor = "v{}.{}.{}".format(*MODULE.FORWARD_PATH_FLOOR)
        for required in (floor, "v0.32", "rehearse-upgrade.py"):
            self.assertTrue(required in page, f"api-stability page lacks {required!r}")


if __name__ == "__main__":
    unittest.main()
