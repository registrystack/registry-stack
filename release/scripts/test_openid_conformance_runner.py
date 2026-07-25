#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import importlib.util
import json
import re
import shlex
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest import TestCase, main
from unittest.mock import MagicMock, patch


SCRIPT_DIR = Path(__file__).resolve().parent
RUNNER_PATH = SCRIPT_DIR / "openid-conformance-runner.py"
NGINX_DOCKERFILE = SCRIPT_DIR.parent / "conformance" / "openid" / "nginx.Dockerfile"


def load_runner():
    spec = importlib.util.spec_from_file_location(
        "openid_conformance_runner", RUNNER_PATH
    )
    if not spec or not spec.loader:
        raise RuntimeError(f"could not load {RUNNER_PATH}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def nginx_certificate_command(certificate: Path, private_key: Path) -> list[str]:
    dockerfile = NGINX_DOCKERFILE.read_text(encoding="utf-8")
    recipe = dockerfile.split("RUN ", 1)[1].split("\nCOPY ", 1)[0]
    command = shlex.split(recipe.replace("\\\n", " "))
    command[command.index("-out") + 1] = str(certificate)
    command[command.index("-keyout") + 1] = str(private_key)
    return command


class EmptyHttpsHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        self.send_response(204)
        self.end_headers()

    def log_message(self, _format: str, *_args) -> None:
        return


class OpenIdConformanceRunnerTest(TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.runner = load_runner()
        cls.plan_map = cls.runner.load_plan_map()

    def offer_uri(
        self, issuer: str = "https://issuer.example.test"
    ) -> tuple[str, str]:
        grant = "urn:ietf:params:oauth:grant-type:pre-authorized_code"
        inline = json.dumps(
            {
                "credential_issuer": issuer,
                "credential_configuration_ids": ["person_is_alive_sd_jwt"],
                "grants": {grant: {"pre-authorized_code": "owner-only-code"}},
            }
        )
        return inline, "openid-credential-offer://?" + urllib.parse.urlencode(
            {"credential_offer": inline}
        )

    def test_plan_map_has_unique_scenarios_and_pinned_suite_ref(self) -> None:
        scenarios = self.plan_map["scenarios"]
        self.assertEqual(len(scenarios), len({scenario["id"] for scenario in scenarios}))
        suite = self.plan_map["suite"]
        self.assertEqual(40, len(suite["ref"]))
        self.assertEqual(
            "https://gitlab.com/openid/conformance-suite.git", suite["repo"]
        )
        self.assertEqual(
            "registry.release.openid_conformance_plan_map.v1",
            self.plan_map["schema_version"],
        )

    def test_release_defaults_do_not_reference_retired_lab_paths(self) -> None:
        self.assertEqual(
            self.runner.REPO_ROOT / "release" / "conformance" / "openid",
            self.runner.CONFIG_DIR,
        )
        self.assertTrue(
            self.runner.DEFAULT_OUTPUT_ROOT.is_relative_to(
                self.runner.REPO_ROOT / "target"
            )
        )
        serialized = json.dumps(self.plan_map)
        self.assertNotIn("REGISTRY_LAB_", serialized)
        self.assertNotIn("blocked-by-lab", serialized)

    def test_notary_mapping_is_candidate_only_and_matches_the_1_0_profile(self) -> None:
        metadata = self.runner.find_scenario(
            self.plan_map, "notary-oid4vci-issuer-metadata"
        )
        full = self.runner.find_scenario(
            self.plan_map, "notary-oid4vci-issuer-full"
        )

        self.assertEqual("candidate-only", metadata["status"])
        self.assertEqual(
            "pre_authorization_code", metadata["variants"]["vci_grant_type"]
        )
        self.assertIn("registry-backed", metadata["surface"])
        metadata_notes = " ".join(metadata["notes"])
        self.assertIn("does not support or claim DPoP", metadata_notes)
        self.assertIn("frozen candidate artifact", metadata_notes)

        self.assertEqual("blocked-by-suite-profile", full["status"])
        self.assertEqual(
            "pre_authorization_code", full["variants"]["vci_grant_type"]
        )
        full_contract = " ".join(full["requires"] + full["notes"])
        self.assertIn("pre-authorized offer", full_contract)
        self.assertIn("is not a wallet grant", full_contract)
        self.assertNotIn(
            "policy decision on whether the first full run targets",
            full_contract,
        )
        verifier = next(
            item
            for item in self.plan_map["non_oidf_surfaces"]
            if item["surface"] == "Registry Notary Rust SD-JWT verifier"
        )
        self.assertIn("not an OID4VP endpoint", verifier["reason"])

    def test_submit_offer_forwards_only_the_real_notary_preauthorized_offer(
        self,
    ) -> None:
        issuer = "https://issuer.example.test"
        inline, offer_uri = self.offer_uri(issuer)
        with tempfile.TemporaryDirectory() as tmp:
            offer_file = Path(tmp) / "offer.txt"
            offer_file.write_text(offer_uri, encoding="utf-8")
            offer_file.chmod(0o600)
            args = self.runner.parse_args(
                [
                    "submit-offer",
                    "--offer-file",
                    str(offer_file),
                    "--issuer-url",
                    issuer,
                    "--suite-offer-endpoint",
                    "https://suite.example.test/run/credential_offer",
                    "--conformance-server",
                    "https://suite.example.test",
                ]
            )
            response = MagicMock()
            response.__enter__.return_value.status = 204
            opener = MagicMock()
            opener.open.return_value = response
            tls_context = MagicMock()
            with patch.object(
                self.runner.ssl,
                "create_default_context",
                return_value=tls_context,
            ) as create_context:
                with patch.object(
                    self.runner.ssl,
                    "_create_unverified_context",
                    side_effect=AssertionError("unverified TLS must not be used"),
                ):
                    with patch.object(
                        self.runner.urllib.request,
                        "build_opener",
                        return_value=opener,
                    ) as build_opener:
                        with patch("builtins.print") as printed:
                            self.assertEqual(0, self.runner.cmd_submit_offer(args))

            submitted = urllib.parse.urlsplit(opener.open.call_args.args[0])
            self.assertEqual(
                [inline],
                urllib.parse.parse_qs(submitted.query)["credential_offer"],
            )
            create_context.assert_called_once_with()
            https_handler = next(
                handler
                for handler in build_opener.call_args.args
                if isinstance(handler, self.runner.urllib.request.HTTPSHandler)
            )
            self.assertIs(tls_context, https_handler._context)
            printed.assert_called_once_with("credential offer submitted")

            opener.open.side_effect = self.runner.urllib.error.URLError(inline)
            with patch.object(
                self.runner.urllib.request, "build_opener", return_value=opener
            ):
                with self.assertRaisesRegex(
                    self.runner.RunnerError, "submission failed"
                ) as caught:
                    self.runner.cmd_submit_offer(args)
            self.assertNotIn("owner-only-code", str(caught.exception))

    def test_submit_offer_rejects_untrusted_remote_tls(self) -> None:
        issuer = "https://issuer.example.test"
        inline, offer_uri = self.offer_uri(issuer)
        with tempfile.TemporaryDirectory() as tmp:
            offer_file = Path(tmp) / "offer.txt"
            offer_file.write_text(offer_uri, encoding="utf-8")
            offer_file.chmod(0o600)
            args = self.runner.parse_args(
                [
                    "submit-offer",
                    "--offer-file",
                    str(offer_file),
                    "--issuer-url",
                    issuer,
                    "--suite-offer-endpoint",
                    "https://suite.example.test/run/credential_offer",
                    "--conformance-server",
                    "https://suite.example.test",
                ]
            )
            opener = MagicMock()
            opener.open.side_effect = self.runner.urllib.error.URLError(
                self.runner.ssl.SSLCertVerificationError(
                    1, "self-signed certificate"
                )
            )
            with patch.object(
                self.runner.urllib.request, "build_opener", return_value=opener
            ):
                with self.assertRaisesRegex(
                    self.runner.RunnerError, "submission failed"
                ) as caught:
                    self.runner.cmd_submit_offer(args)

            self.assertNotIn(inline, str(caught.exception))

    def test_submit_offer_accepts_an_explicit_local_suite_ca(self) -> None:
        issuer = "https://issuer.example.test"
        _, offer_uri = self.offer_uri(issuer)
        with tempfile.TemporaryDirectory() as tmp:
            offer_file = Path(tmp) / "offer.txt"
            offer_file.write_text(offer_uri, encoding="utf-8")
            offer_file.chmod(0o600)
            suite_ca = Path(tmp) / "suite-ca.pem"
            suite_ca.write_text("local test CA", encoding="utf-8")
            args = self.runner.parse_args(
                [
                    "submit-offer",
                    "--offer-file",
                    str(offer_file),
                    "--issuer-url",
                    issuer,
                    "--suite-offer-endpoint",
                    "https://localhost.emobix.co.uk:8443/run/credential_offer",
                    "--conformance-server",
                    "https://localhost.emobix.co.uk:8443",
                    "--suite-ca-certificate",
                    str(suite_ca),
                ]
            )
            response = MagicMock()
            response.__enter__.return_value.status = 204
            opener = MagicMock()
            opener.open.return_value = response
            tls_context = MagicMock()
            with patch.object(
                self.runner.ssl,
                "SSLContext",
                return_value=tls_context,
            ) as create_context:
                with patch.object(
                    self.runner.urllib.request,
                    "build_opener",
                    return_value=opener,
                ):
                    with patch("builtins.print"):
                        self.assertEqual(0, self.runner.cmd_submit_offer(args))

            create_context.assert_called_once_with(
                self.runner.ssl.PROTOCOL_TLS_CLIENT
            )
            tls_context.load_verify_locations.assert_called_once_with(
                cadata=b"local test CA"
            )

    def test_suite_ca_read_holds_one_descriptor_across_path_replacement(
        self,
    ) -> None:
        original = (
            b"-----BEGIN CERTIFICATE-----\n"
            b"captured-original\n"
            b"-----END CERTIFICATE-----\n"
        )
        replacement = (
            b"-----BEGIN CERTIFICATE-----\n"
            b"replacement\n"
            b"-----END CERTIFICATE-----\n"
        )
        with tempfile.TemporaryDirectory() as tmp:
            ca_path = Path(tmp) / "suite-ca.pem"
            replacement_path = Path(tmp) / "replacement.pem"
            ca_path.write_bytes(original)
            replacement_path.write_bytes(replacement)
            real_open = self.runner.os.open

            def open_then_replace(path, flags):
                descriptor = real_open(path, flags)
                self.runner.os.replace(replacement_path, ca_path)
                return descriptor

            tls_context = MagicMock()
            with patch.object(
                self.runner.os, "open", side_effect=open_then_replace
            ) as secure_open:
                with patch.object(
                    self.runner.ssl,
                    "SSLContext",
                    return_value=tls_context,
                ):
                    self.runner.suite_tls_context(ca_path)

            self.assertEqual(replacement, ca_path.read_bytes())
            secure_open.assert_called_once()
            flags = secure_open.call_args.args[1]
            for required_flag in ("O_NOFOLLOW", "O_CLOEXEC"):
                value = getattr(self.runner.os, required_flag, 0)
                if value:
                    self.assertEqual(value, flags & value)
            tls_context.load_verify_locations.assert_called_once_with(
                cadata=original.decode("ascii")
            )

    def test_suite_ca_loader_preserves_der_bytes(self) -> None:
        tls_context = MagicMock()
        certificate = b"\x30\x82\x01\x00\xff"

        self.runner.add_suite_ca(tls_context, certificate)

        tls_context.load_verify_locations.assert_called_once_with(
            cadata=certificate
        )

    def test_suite_ca_read_rejects_symlink(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "suite-ca.pem"
            target.write_text("certificate", encoding="utf-8")
            link = Path(tmp) / "suite-ca-link.pem"
            link.symlink_to(target)

            with self.assertRaisesRegex(
                self.runner.RunnerError, "opened securely"
            ):
                self.runner.read_suite_ca_certificate(link)

    def test_exported_certificate_recipe_authenticates_documented_suite_host(
        self,
    ) -> None:
        openssl = shutil.which("openssl")
        if not openssl:
            self.skipTest("openssl is required for the checked-in certificate recipe")
        issuer = "https://issuer.example.test"
        _, offer_uri = self.offer_uri(issuer)
        with tempfile.TemporaryDirectory() as tmp:
            work = Path(tmp)
            certificate = work / "recipe.crt"
            private_key = work / "recipe.key"
            command = nginx_certificate_command(certificate, private_key)
            self.assertEqual(openssl, shutil.which(command[0]))
            self.assertIn(
                (
                    "subjectAltName=DNS:localhost.emobix.co.uk,DNS:localhost,"
                    "IP:127.0.0.1,IP:::1"
                ),
                command,
            )
            subprocess.run(
                command,
                check=True,
                capture_output=True,
                text=True,
            )

            suite_dir = work / "suite"
            suite_dir.mkdir()
            exported = work / "conformance-suite-ca.pem"
            export_args = self.runner.parse_args(
                [
                    "export-suite-ca",
                    "--suite-dir",
                    str(suite_dir),
                    "--output",
                    str(exported),
                ]
            )
            compose_commands: list[list[str]] = []

            def copy_container_certificate(
                compose_command: list[str], **_kwargs
            ) -> None:
                compose_commands.append(compose_command)
                Path(compose_command[-1]).write_bytes(certificate.read_bytes())

            with patch.object(
                self.runner,
                "run_checked",
                side_effect=copy_container_certificate,
            ):
                with patch("builtins.print"):
                    self.assertEqual(0, self.runner.cmd_export_suite_ca(export_args))

            self.assertEqual(certificate.read_bytes(), exported.read_bytes())
            self.assertEqual(0o600, exported.stat().st_mode & 0o777)
            self.assertEqual(
                f"nginx:{self.runner.SUITE_CA_CONTAINER_PATH}",
                compose_commands[0][-2],
            )

            offer_file = work / "offer.txt"
            offer_file.write_text(offer_uri, encoding="utf-8")
            offer_file.chmod(0o600)
            server = ThreadingHTTPServer(("127.0.0.1", 0), EmptyHttpsHandler)
            server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            server_context.minimum_version = ssl.TLSVersion.TLSv1_2
            server_context.load_cert_chain(certificate, private_key)
            server.socket = server_context.wrap_socket(
                server.socket, server_side=True
            )
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            host = "localhost.emobix.co.uk"
            port = server.server_port
            submit_args = self.runner.parse_args(
                [
                    "submit-offer",
                    "--offer-file",
                    str(offer_file),
                    "--issuer-url",
                    issuer,
                    "--suite-offer-endpoint",
                    f"https://{host}:{port}/run/credential_offer",
                    "--conformance-server",
                    f"https://{host}:{port}",
                    "--suite-ca-certificate",
                    str(exported),
                ]
            )
            real_getaddrinfo = socket.getaddrinfo

            def loopback_suite(hostname, *args, **kwargs):
                if hostname == host:
                    hostname = "127.0.0.1"
                return real_getaddrinfo(hostname, *args, **kwargs)

            try:
                with patch.object(
                    socket, "getaddrinfo", side_effect=loopback_suite
                ):
                    with patch("builtins.print"):
                        self.assertEqual(
                            0, self.runner.cmd_submit_offer(submit_args)
                        )
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=2)

    def test_submit_offer_rejects_cleartext_suite_endpoint(self) -> None:
        issuer = "https://issuer.example.test"
        _, offer_uri = self.offer_uri(issuer)
        with tempfile.TemporaryDirectory() as tmp:
            offer_file = Path(tmp) / "offer.txt"
            offer_file.write_text(offer_uri, encoding="utf-8")
            offer_file.chmod(0o600)
            args = self.runner.parse_args(
                [
                    "submit-offer",
                    "--offer-file",
                    str(offer_file),
                    "--issuer-url",
                    issuer,
                    "--suite-offer-endpoint",
                    "http://suite.example.test/run/credential_offer",
                    "--conformance-server",
                    "http://suite.example.test",
                ]
            )
            with patch.object(
                self.runner.urllib.request, "build_opener"
            ) as build_opener:
                with self.assertRaisesRegex(self.runner.RunnerError, "HTTPS"):
                    self.runner.cmd_submit_offer(args)

            build_opener.assert_not_called()

    def test_read_offer_uses_one_no_follow_descriptor(self) -> None:
        issuer = "https://issuer.example.test"
        inline, offer_uri = self.offer_uri(issuer)
        with tempfile.TemporaryDirectory() as tmp:
            offer_file = Path(tmp) / "offer.txt"
            offer_file.write_text(offer_uri, encoding="utf-8")
            offer_file.chmod(0o600)
            real_open = self.runner.os.open
            with patch.object(Path, "read_text", side_effect=AssertionError):
                with patch.object(
                    self.runner.os, "open", wraps=real_open
                ) as secure_open:
                    self.assertEqual(
                        inline, self.runner.read_offer(offer_file, issuer)
                    )

        secure_open.assert_called_once_with(
            offer_file,
            self.runner.os.O_RDONLY
            | self.runner.os.O_CLOEXEC
            | self.runner.os.O_NOFOLLOW,
        )

    def test_read_offer_rejects_symlink(self) -> None:
        issuer = "https://issuer.example.test"
        _, offer_uri = self.offer_uri(issuer)
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "offer.txt"
            target.write_text(offer_uri, encoding="utf-8")
            target.chmod(0o600)
            link = Path(tmp) / "offer-link.txt"
            link.symlink_to(target)
            with self.assertRaisesRegex(
                self.runner.RunnerError, "could not be opened securely"
            ):
                self.runner.read_offer(link, issuer)

    def test_builder_override_pins_maven_image_by_digest(self) -> None:
        override = self.runner.BUILDER_COMPOSE_OVERRIDE_PATH.read_text(
            encoding="utf-8"
        )
        self.assertIn("maven:3-eclipse-temurin-21@sha256:", override)
        self.assertIn(
            str(self.runner.BUILDER_COMPOSE_OVERRIDE_PATH),
            self.runner.builder_command(Path("/suite"), "run", "builder"),
        )

    def test_dependency_inputs_are_dependabot_discoverable(self) -> None:
        compose_filename = re.compile(
            r"(docker-)?compose(-[\w]+)?(?:\.[\w-]+)?\.ya?ml",
            re.IGNORECASE,
        )
        self.assertIsNotNone(
            compose_filename.fullmatch(
                self.runner.BUILDER_COMPOSE_OVERRIDE_PATH.name
            )
        )
        self.assertEqual(".txt", self.runner.SUITE_REQUIREMENTS_LOCK_PATH.suffix)
        dependabot_path = self.runner.REPO_ROOT / ".github" / "dependabot.yml"
        dependabot = dependabot_path.read_text(encoding="utf-8")
        self.assertIn("package-ecosystem: docker-compose", dependabot)
        self.assertIn("package-ecosystem: pip", dependabot)

    def test_runtime_override_pins_built_image_bases(self) -> None:
        override = self.runner.COMPOSE_OVERRIDE_PATH.read_text(encoding="utf-8")
        nginx = (self.runner.CONFIG_DIR / "nginx.Dockerfile").read_text(
            encoding="utf-8"
        )
        server = (self.runner.CONFIG_DIR / "server-dev.Dockerfile").read_text(
            encoding="utf-8"
        )
        self.assertIn("REGISTRY_OPENID_CONFORMANCE_CONFIG_DIR", override)
        self.assertIn("nginx:1.27.3@sha256:", nginx)
        self.assertIn("eclipse-temurin:21@sha256:", server)

    def test_metadata_scenario_cli_selects_single_oid4vci_module(self) -> None:
        scenario = self.runner.find_scenario(
            self.plan_map, "notary-oid4vci-issuer-metadata"
        )
        plan_arg = self.runner.scenario_plan_arg(scenario)
        self.assertTrue(plan_arg.startswith("oid4vci-1_0-issuer-test-plan["))
        self.assertIn("[client_auth_type=private_key_jwt]", plan_arg)
        self.assertIn("[sender_constrain=dpop]", plan_arg)
        self.assertIn("[fapi_profile=vci]", plan_arg)
        self.assertIn("[fapi_request_method=unsigned]", plan_arg)
        self.assertIn("[authorization_request_type=simple]", plan_arg)
        self.assertIn("[credential_format=sd_jwt_vc]", plan_arg)
        self.assertIn("[vci_credential_encryption=plain]", plan_arg)
        self.assertTrue(plan_arg.endswith(":oid4vci-1_0-issuer-metadata-test"))

    def test_rendered_config_is_valid_json_and_uses_supplied_issuer(self) -> None:
        scenario = self.runner.find_scenario(
            self.plan_map, "notary-oid4vci-issuer-metadata"
        )
        rendered = self.runner.render_config(
            scenario,
            {
                "issuer_url": "https://issuer.example.test",
                "authorization_server": "https://issuer.example.test/auth",
                "credential_configuration_id": "person_is_alive_sd_jwt",
                "static_tx_code": "1234",
                "client_id": "client-a",
                "client2_id": "client-b",
            },
        )
        config = json.loads(rendered)
        self.assertEqual(
            "registry-stack-notary-oid4vci-issuer", config["alias"]
        )
        self.assertEqual(
            "https://issuer.example.test", config["vci"]["credential_issuer_url"]
        )
        self.assertEqual(
            "person_is_alive_sd_jwt",
            config["vci"]["credential_configuration_id"],
        )
        self.assertEqual("client-a", config["client"]["client_id"])
        self.assertNotIn("${", rendered)

    def test_build_run_uses_export_dir_and_conformance_environment(self) -> None:
        scenario = self.runner.find_scenario(
            self.plan_map, "notary-oid4vci-issuer-metadata"
        )
        with tempfile.TemporaryDirectory() as tmp:
            args = self.runner.parse_args(
                [
                    "run",
                    "notary-oid4vci-issuer-metadata",
                    "--issuer-url",
                    "https://issuer.example.test",
                    "--output-dir",
                    tmp,
                    "--suite-dir",
                    str(Path(tmp) / "suite"),
                    "--no-prepare",
                    "--dry-run",
                ]
            )
            output_dir, env, command = self.runner.build_run(
                self.plan_map, scenario, args
            )
            self.assertEqual(Path(tmp).resolve(), output_dir)
            self.assertEqual(
                self.plan_map["suite"]["base_url"], env["CONFORMANCE_SERVER"]
            )
            self.assertEqual("1", env["CONFORMANCE_DEV_MODE"])
            self.assertIn("--export-dir", command)
            self.assertIn(str(output_dir), command)
            self.assertIn("oid4vci-1_0-issuer-metadata-test", " ".join(command))
            self.assertTrue(
                (output_dir / "notary-oid4vci-issuer-metadata.config.json").exists()
            )

    def test_suite_artifact_build_uses_docker_builder_and_maven_cache(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            checkout = Path(tmp) / "suite"
            jar = checkout / self.runner.SUITE_JAR
            jar.parent.mkdir(parents=True)
            args = self.runner.parse_args(
                [
                    "prepare",
                    "--suite-dir",
                    str(checkout),
                    "--maven-cache-dir",
                    str(Path(tmp) / "maven"),
                ]
            )
            calls = []

            def fake_run_checked(command, cwd=None, env=None):
                calls.append((command, cwd, env))
                jar.write_text("jar", encoding="utf-8")

            with patch.object(shutil, "which", return_value="/usr/bin/docker"):
                with patch.object(self.runner, "suite_checkout_ref", return_value="a" * 40):
                    with patch.object(
                        self.runner, "run_checked", side_effect=fake_run_checked
                    ):
                        self.runner.ensure_suite_artifact(checkout, args)

            self.assertEqual(
                self.runner.builder_command(checkout, "run", "--rm", "builder"),
                calls[0][0],
            )
            self.assertEqual(checkout, calls[0][1])
            self.assertEqual(
                str((Path(tmp) / "maven").resolve()), calls[0][2]["MAVEN_CACHE"]
            )
            stamp = json.loads(
                (checkout / self.runner.SUITE_JAR_STAMP).read_text(encoding="utf-8")
            )
            self.assertEqual("a" * 40, stamp["source_ref"])
            self.assertEqual(
                self.runner.file_sha256(jar), stamp["jar_sha256"]
            )
            self.assertEqual(
                self.runner.file_sha256(
                    self.runner.BUILDER_COMPOSE_OVERRIDE_PATH
                ),
                stamp["builder_override_sha256"],
            )

    def test_existing_suite_artifact_skips_build_by_default(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            checkout = Path(tmp) / "suite"
            jar = checkout / self.runner.SUITE_JAR
            jar.parent.mkdir(parents=True)
            jar.write_text("jar", encoding="utf-8")
            stamp = checkout / self.runner.SUITE_JAR_STAMP
            with patch.object(self.runner, "suite_checkout_ref", return_value="a" * 40):
                stamp.write_text(
                    json.dumps(
                        self.runner.expected_suite_artifact_stamp(checkout, jar),
                        sort_keys=True,
                    )
                    + "\n",
                    encoding="utf-8",
                )
            args = self.runner.parse_args(["prepare", "--suite-dir", str(checkout)])

            with patch.object(self.runner, "suite_checkout_ref", return_value="a" * 40):
                with patch.object(self.runner, "run_checked") as run_checked:
                    self.runner.ensure_suite_artifact(checkout, args)

            run_checked.assert_not_called()

    def test_suite_artifact_rebuilds_when_checkout_ref_changes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            checkout = Path(tmp) / "suite"
            jar = checkout / self.runner.SUITE_JAR
            jar.parent.mkdir(parents=True)
            jar.write_text("old", encoding="utf-8")
            stamp = checkout / self.runner.SUITE_JAR_STAMP
            with patch.object(self.runner, "suite_checkout_ref", return_value="a" * 40):
                stamp.write_text(
                    json.dumps(
                        self.runner.expected_suite_artifact_stamp(checkout, jar),
                        sort_keys=True,
                    )
                    + "\n",
                    encoding="utf-8",
                )
            args = self.runner.parse_args(["prepare", "--suite-dir", str(checkout)])

            def fake_run_checked(command, cwd=None, env=None):
                jar.write_text("new", encoding="utf-8")

            with patch.object(shutil, "which", return_value="/usr/bin/docker"):
                with patch.object(
                    self.runner, "suite_checkout_ref", return_value="b" * 40
                ):
                    with patch.object(
                        self.runner, "run_checked", side_effect=fake_run_checked
                    ) as run_checked:
                        self.runner.ensure_suite_artifact(checkout, args)

            run_checked.assert_called_once()
            self.assertEqual("new", jar.read_text(encoding="utf-8"))
            self.assertEqual(
                "b" * 40,
                json.loads(stamp.read_text(encoding="utf-8"))["source_ref"],
            )

    def test_suite_python_venv_installs_requirements_and_records_digest(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            checkout = Path(tmp) / "suite"
            requirements = checkout / "scripts" / "requirements.txt"
            requirements.parent.mkdir(parents=True)
            requirements.write_bytes(
                self.runner.SUITE_REQUIREMENTS_INPUT_PATH.read_bytes()
            )
            venv_dir = Path(tmp) / "venv"
            args = self.runner.parse_args(
                [
                    "prepare",
                    "--suite-dir",
                    str(checkout),
                    "--python-venv-dir",
                    str(venv_dir),
                ]
            )

            calls = []

            def fake_run_checked(command, cwd=None, env=None):
                calls.append(command)
                if command[1:3] == ["-m", "venv"]:
                    Path(command[-1]).mkdir(parents=True)

            with patch.object(
                self.runner, "run_checked", side_effect=fake_run_checked
            ):
                python = self.runner.ensure_suite_python(checkout, args)

            self.assertEqual(venv_dir.resolve(), python.parents[2])
            self.assertTrue(python.parent.parent.name.startswith("py"))
            self.assertEqual(
                [sys.executable, "-m", "venv", str(python.parents[1])], calls[0]
            )
            self.assertEqual(str(python), calls[1][0])
            self.assertIn("--require-hashes", calls[1])
            self.assertIn("--only-binary=:all:", calls[1])
            self.assertEqual("-r", calls[1][-2])
            self.assertEqual(
                str(self.runner.SUITE_REQUIREMENTS_LOCK_PATH), calls[1][-1]
            )
            self.assertEqual(
                self.runner.requirements_digest(
                    self.runner.SUITE_REQUIREMENTS_INPUT_PATH,
                    self.runner.SUITE_REQUIREMENTS_LOCK_PATH,
                ),
                (python.parents[1] / ".requirements.sha256")
                .read_text(encoding="utf-8")
                .strip(),
            )

    def test_suite_python_cache_key_changes_with_lock_digest(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            args = self.runner.parse_args(
                ["prepare", "--python-venv-dir", str(Path(tmp) / "venvs")]
            )
            first = self.runner.suite_python(args)
            with patch.object(
                self.runner, "requirements_digest", return_value="b" * 64
            ):
                second = self.runner.suite_python(args)
            self.assertNotEqual(first, second)

    def test_suite_python_recreates_incomplete_digest_cache(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            checkout = Path(tmp) / "suite"
            requirements = checkout / "scripts" / "requirements.txt"
            requirements.parent.mkdir(parents=True)
            requirements.write_bytes(
                self.runner.SUITE_REQUIREMENTS_INPUT_PATH.read_bytes()
            )
            args = self.runner.parse_args(
                [
                    "prepare",
                    "--suite-dir",
                    str(checkout),
                    "--python-venv-dir",
                    str(Path(tmp) / "venvs"),
                ]
            )
            python = self.runner.suite_python(args)
            python.parent.mkdir(parents=True)
            python.touch()
            stale = python.parents[1] / "stale-package"
            stale.touch()

            def fake_run_checked(command, cwd=None, env=None):
                if command[1:3] == ["-m", "venv"]:
                    Path(command[-1]).mkdir(parents=True)

            with patch.object(
                self.runner, "run_checked", side_effect=fake_run_checked
            ):
                self.runner.ensure_suite_python(checkout, args)

            self.assertFalse(stale.exists())
            self.assertTrue(
                (python.parents[1] / ".requirements.sha256").is_file()
            )

    def test_suite_python_rejects_changed_upstream_requirements(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            checkout = Path(tmp) / "suite"
            requirements = checkout / "scripts" / "requirements.txt"
            requirements.parent.mkdir(parents=True)
            requirements.write_text("httpx\npyparsing\nunreviewed\n", encoding="utf-8")
            args = self.runner.parse_args(
                ["prepare", "--suite-dir", str(checkout)]
            )

            with self.assertRaisesRegex(
                self.runner.RunnerError, "differ from the checked-in locked input"
            ):
                self.runner.ensure_suite_python(checkout, args)

    def test_blocked_full_scenario_requires_explicit_override(self) -> None:
        args = self.runner.parse_args(
            [
                "run",
                "notary-oid4vci-issuer-full",
                "--issuer-url",
                "https://issuer.example.test",
                "--no-prepare",
                "--dry-run",
            ]
        )
        with self.assertRaisesRegex(
            self.runner.RunnerError, "blocked-by-suite-profile"
        ):
            self.runner.cmd_run(args)

    def test_candidate_only_metadata_scenario_runs_without_blocked_override(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            args = self.runner.parse_args(
                [
                    "run",
                    "notary-oid4vci-issuer-metadata",
                    "--issuer-url",
                    "https://issuer.example.test",
                    "--output-dir",
                    tmp,
                    "--suite-dir",
                    str(Path(tmp) / "suite"),
                    "--no-prepare",
                    "--dry-run",
                ]
            )
            with patch("builtins.print") as printed:
                self.assertEqual(0, self.runner.cmd_run(args))
            invocation = json.loads(printed.call_args.args[0])
            self.assertIn(
                "oid4vci-1_0-issuer-metadata-test", " ".join(invocation["command"])
            )


if __name__ == "__main__":
    main()
