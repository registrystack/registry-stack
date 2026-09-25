from __future__ import annotations

import argparse
import base64
import importlib.util
import json
import shutil
import subprocess
import tempfile
import threading
import time
import unittest
import unittest.mock
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


MODULE_PATH = Path(__file__).with_name("loadenv.py")
LOADTEST = MODULE_PATH.parent.parent
REPOSITORY = MODULE_PATH.parents[4]
SPEC = importlib.util.spec_from_file_location("loadtest_evidence", REPOSITORY / "scripts/loadtest/evidence.py")
assert SPEC and SPEC.loader
evidence = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(evidence)
LOADENV_SPEC = importlib.util.spec_from_file_location("loadtest_environment", MODULE_PATH)
assert LOADENV_SPEC and LOADENV_SPEC.loader
loadenv = importlib.util.module_from_spec(LOADENV_SPEC)
LOADENV_SPEC.loader.exec_module(loadenv)


def _b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _token(expires_in: float, marker: str = "client") -> str:
    header = _b64url(json.dumps({"alg": "RS256", "typ": "JWT"}).encode())
    claims = _b64url(json.dumps({"sub": f"synthetic-{marker}", "exp": int(time.time() + expires_in)}).encode())
    return f"{header}.{claims}.{_b64url(b'synthetic-signature-' + marker.encode())}"


def _owned_root(repository: Path, build_profile: str = "release") -> tuple[Path, Path]:
    root = repository / "products/evidence/loadtest/.run"
    (root / "project").mkdir(parents=True)
    (root / ".launcher-owned").write_text(f"{loadenv.MARKER}\n", encoding="ascii")
    evidencectl = repository / "target" / build_profile / "evidencectl"
    evidencectl.parent.mkdir(parents=True, exist_ok=True)
    return root, evidencectl


def _write_environment(root: Path, executable: Path, **overrides: object) -> dict[str, object]:
    environment: dict[str, object] = {
        "evidence_url": "http://127.0.0.1:1234",
        "evidencectl": str(executable),
        "build_profile": "release",
        "project": str(root / "project"),
        "clients": 3,
        "runtime_library_path": "",
        "mock": {"pid": 4242, "port": 4711},
    }
    environment.update(overrides)
    (root / "env.json").write_text(json.dumps(environment), encoding="utf-8")
    return environment


class EvidenceStub:
    """A loopback stand-in for Evidence that records only what the tests assert on."""

    def __init__(self, limit_after: int | None = None) -> None:
        self.requests: list[dict[str, object]] = []
        self.lock = threading.Lock()
        stub = self

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self) -> None:  # noqa: N802 - stdlib handler API
                length = int(self.headers.get("Content-Length", "0"))
                body = json.loads(self.rfile.read(length))
                with stub.lock:
                    stub.requests.append(
                        {"authorization": self.headers.get("Authorization"), "accept": self.headers.get("Accept"), "body": body}
                    )
                    count = len(stub.requests)
                subject = body["subjects"][0]["selector"]["values"]["person_id"]
                if limit_after is not None and count > limit_after:
                    self._reply(429, "application/problem+json", {"code": "rate_limited"})
                elif subject.startswith("lt-absent-"):
                    self._reply(503, "application/problem+json", {"code": "source.unavailable"})
                else:
                    self._reply(
                        200,
                        "application/jose+json",
                        {
                            "protected": _b64url(b'{"alg":"ES256","typ":"evidence+jws"}'),
                            "payload": _b64url(json.dumps({"requirement": body["requirement"]}).encode()),
                            "signature": _b64url(b"synthetic-signature"),
                        },
                    )

            def _reply(self, status: int, content_type: str, value: object) -> None:
                payload = json.dumps(value).encode()
                self.send_response(status)
                self.send_header("Content-Type", content_type)
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

            def log_message(self, _format: str, *args: object) -> None:
                _ = args

        try:
            self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        except PermissionError as error:
            raise unittest.SkipTest("loopback sockets are unavailable in this sandbox") from error
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    def __enter__(self) -> "EvidenceStub":
        self.thread.start()
        return self

    def __exit__(self, *_: object) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)

    @property
    def origin(self) -> str:
        return f"http://127.0.0.1:{self.server.server_port}"


class EvidenceHarnessTests(unittest.TestCase):
    def test_profiles_pin_arrival_rates_recovery_and_expected_refusals(self) -> None:
        workload = (LOADTEST / "lib/workload.js").read_text(encoding="utf-8")
        steady = (LOADTEST / "profiles/steady.js").read_text(encoding="utf-8")
        burst = (LOADTEST / "profiles/burst.js").read_text(encoding="utf-8")
        limiter = (LOADTEST / "profiles/limiter.js").read_text(encoding="utf-8")
        runner = (LOADTEST / "run.sh").read_text(encoding="utf-8")
        self.assertIn("exec.scenario.iterationInTest % authorizations.length", workload)
        self.assertIn("new Uint8Array(32)", workload)
        self.assertIn("http.expectedStatuses(...expected)", workload)
        self.assertIn("'evidence_absent', [503]", workload)
        self.assertIn("problemCode(r) === 'source.unavailable'", workload)
        self.assertIn("executor: 'constant-arrival-rate'", steady)
        self.assertIn("http_req_failed: ['rate==0']", steady)
        self.assertIn("dropped_iterations: ['count==0']", steady)
        self.assertIn("'http_reqs{status:429}': ['count==0']", steady)
        self.assertIn("recovery:", burst)
        self.assertIn("'http_req_failed{scenario:recovery}'", burst)
        self.assertIn("checks: ['rate>0.99']", burst)
        self.assertIn("'checks{scenario:recovery}': ['rate==1']", burst)
        self.assertIn("'http_reqs{status:429}': ['count>0']", limiter)
        self.assertIn("--http-debug | --http-debug=* | --system-tags | --system-tags=*", runner)
        self.assertIn("K6_HTTP_DEBUG", runner)
        self.assertIn("<= 240", runner)
        self.assertIn("0.9*int(sys.argv[2])", runner)
        for profile in ("smoke", "steady", "burst", "limiter"):
            source = (LOADTEST / f"profiles/{profile}.js").read_text(encoding="utf-8")
            self.assertIn("'../../../../scripts/loadtest/k6/config.js'", source)
            self.assertIn("systemTags: SAFE_SYSTEM_TAGS", source)
            self.assertNotIn("sleep(", source)

    def _run_profile(self, profile: str, origin: str, root: Path, clients: int = 3) -> tuple[Path, list[Path]]:
        artifacts = root / "artifacts"
        artifacts.mkdir()
        subjects = root / "subjects.txt"
        absent = root / "absent.txt"
        subjects.write_text("".join(f"{loadenv.subject_id(i)}\n" for i in range(1, 6)), encoding="utf-8")
        absent.write_text("".join(f"{loadenv.absent_id(i)}\n" for i in range(1, 3)), encoding="utf-8")
        headers = []
        for index in range(clients):
            header = root / f"loadtest-{index:03d}.header"
            header.write_text(f"Authorization: Bearer {_token(300, f'client{index}')}\n", encoding="ascii")
            header.chmod(0o600)
            headers.append(header)
        listing = root / "header-files.txt"
        listing.write_text("".join(f"{path}\n" for path in headers), encoding="utf-8")
        samples = artifacts / "k6-samples.json"
        command = ["k6", "run", "--quiet", "--out", f"json={samples}"]
        for name, value in {
            "EVIDENCE_URL": origin,
            "HEADER_FILES_LIST": listing,
            "SUBJECTS_FILE": subjects,
            "ABSENT_FILE": absent,
            "REQUIREMENT": loadenv.REQUIREMENT,
            "SELECTOR_PROFILE": loadenv.SELECTOR_PROFILE,
            "PURPOSE": loadenv.PURPOSE,
            "K6_SUMMARY_PATH": artifacts / "k6-summary.json",
        }.items():
            command.extend(["-e", f"{name}={value}"])
        command.append(str(LOADTEST / f"profiles/{profile}.js"))
        result = subprocess.run(command, capture_output=True, text=True, timeout=60)
        self.assertEqual(result.returncode, 0, result.stderr or result.stdout)
        safety = artifacts / "safety.json"
        evidence.assert_safe(
            argparse.Namespace(
                artifact_dir=artifacts,
                samples=samples,
                secret_file=headers,
                seed_pool=[subjects, absent],
                out=safety,
            )
        )
        self.assertTrue(json.loads(safety.read_text(encoding="utf-8"))["safe"])
        self.assertIsNone(evidence._sample_summary(samples)["tagViolation"])
        return artifacts, headers

    @unittest.skipUnless(shutil.which("k6"), "k6 is not installed")
    def test_smoke_rotates_clients_with_fresh_nonces_and_leaves_no_identifiers(self) -> None:
        with EvidenceStub() as stub, tempfile.TemporaryDirectory() as directory:
            artifacts, headers = self._run_profile("smoke", stub.origin, Path(directory))
            samples = (artifacts / "k6-samples.json").read_text(encoding="utf-8")
            expected_authorizations = {path.read_text(encoding="ascii").strip()[len("Authorization: ") :] for path in headers}
        self.assertEqual(len(stub.requests), 12)
        self.assertEqual({request["authorization"] for request in stub.requests}, expected_authorizations)
        self.assertEqual({request["accept"] for request in stub.requests}, {"application/jose+json"})
        nonces = [request["body"]["requestNonce"] for request in stub.requests]  # type: ignore[index]
        self.assertEqual(len(set(nonces)), len(nonces))
        for nonce in nonces:
            self.assertEqual(len(nonce), 43)
            self.assertEqual(len(base64.urlsafe_b64decode(nonce + "=")), 32)
        bodies = [request["body"] for request in stub.requests]
        self.assertEqual({body["requirement"] for body in bodies}, {loadenv.REQUIREMENT})  # type: ignore[index]
        absent = [body for body in bodies if body["subjects"][0]["selector"]["values"]["person_id"].startswith("lt-absent-")]  # type: ignore[index]
        self.assertEqual(len(absent), 2)
        for identifier in ("lt-subject-", "lt-absent-", "requestNonce", "Bearer"):
            self.assertNotIn(identifier, samples)

    @unittest.skipUnless(shutil.which("k6"), "k6 is not installed")
    def test_limiter_requires_a_rate_limited_response(self) -> None:
        with EvidenceStub(limit_after=10) as stub, tempfile.TemporaryDirectory() as directory:
            self._run_profile("limiter", stub.origin, Path(directory))
        self.assertEqual(len(stub.requests), 20)
        self.assertEqual(len({request["authorization"] for request in stub.requests}), 1)

    @unittest.skipUnless(shutil.which("k6"), "k6 is not installed")
    def test_smoke_fails_when_an_unknown_subject_is_answered(self) -> None:
        # A stub that never refuses must fail the absent-subject check.
        with EvidenceStub() as stub, tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(AssertionError):
                with unittest.mock.patch.object(loadenv, "absent_id", loadenv.subject_id):
                    self._run_profile("smoke", stub.origin, Path(directory))

    def test_local_project_adds_a_bounded_synthetic_source_and_refuses_reuse(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            project = root / "project"
            project.mkdir()
            (project / "evidence-project.yaml").write_text("version: 1\n", encoding="utf-8")
            pool = root / "pool"
            loadenv.local_project(LOADTEST / "project", project, pool)
            plan = (project / "mocks/source.yaml").read_text(encoding="utf-8")
            self.assertEqual(plan.count("      - name: lt-subject-"), loadenv.SUBJECTS)
            self.assertLessEqual(loadenv.SUBJECTS, 256, "evidencectl source mock allows 256 cases per operation")
            self.assertEqual(len(list((project / "mocks/cases").glob("*.json"))), loadenv.SUBJECTS)
            case = json.loads((project / "mocks/cases/lt-subject-0005.json").read_text(encoding="utf-8"))
            self.assertEqual(case["person_id"], "lt-subject-0005")
            self.assertTrue(case["date_of_birth"].startswith("201"))
            facts = json.loads((pool / "pool-facts.json").read_text(encoding="utf-8"))
            self.assertEqual(facts, {"subjects": 200, "adultSubjects": 160, "minorSubjects": 40, "absentSubjects": 50})
            subjects = (pool / "subjects.txt").read_text(encoding="utf-8").split()
            absent = (pool / "absent.txt").read_text(encoding="utf-8").split()
            self.assertEqual(len(subjects), 200)
            self.assertFalse(set(subjects) & set(absent))
            self.assertEqual(
                (project / "questions/adult-status.yaml").read_text(encoding="utf-8"),
                (LOADTEST / "project/questions/adult-status.yaml").read_text(encoding="utf-8"),
            )
            with self.assertRaises(loadenv.LoadtestError):
                loadenv.local_project(LOADTEST / "project", project, root / "second-pool")
            with self.assertRaises(loadenv.LoadtestError):
                loadenv.local_project(LOADTEST / "project", root / "uninitialised", root / "third-pool")

    def test_birth_dates_are_deterministic_and_minors_stay_minors_for_years(self) -> None:
        for index in range(1, loadenv.SUBJECTS + 1):
            year = int(loadenv.date_of_birth(index)[:4])
            if index % loadenv.MINOR_EVERY == 0:
                self.assertGreaterEqual(year, 2012)
            else:
                self.assertLessEqual(year, 1999)
        self.assertEqual(loadenv.date_of_birth(7), loadenv.date_of_birth(7))

    def test_openapi_template_names_the_mock_origin_once(self) -> None:
        template = LOADTEST / "project/source.openapi.yaml"
        self.assertEqual(template.read_text(encoding="utf-8").count(loadenv.OPENAPI_PLACEHOLDER), 1)
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "source.openapi.yaml"
            loadenv.render_openapi(template, 4711, output)
            rendered = output.read_text(encoding="utf-8")
            self.assertIn("url: http://127.0.0.1:4711\n", rendered)
            self.assertNotIn("MOCK_PORT", rendered)
            with self.assertRaises(loadenv.LoadtestError):
                loadenv.render_openapi(output, 4711, Path(directory) / "again.yaml")

    def test_bundle_rate_limits_read_exactly_one_value_per_key(self) -> None:
        bundle = "rateLimits:\n  requestsPerPrincipalPerMinute: 60\n  burstPerPrincipal: 10\n  failedSelectorAttemptsPerPrincipalAuthorityPerMinute: 10\n"
        self.assertEqual(
            loadenv.bundle_rate_limits(bundle),
            {
                "requestsPerPrincipalPerMinute": 60,
                "burstPerPrincipal": 10,
                "failedSelectorAttemptsPerPrincipalAuthorityPerMinute": 10,
            },
        )
        self.assertEqual(loadenv.bundle_rate_limits(json.dumps({"rateLimits": loadenv.bundle_rate_limits(bundle)}))["burstPerPrincipal"], 10)
        with self.assertRaises(loadenv.LoadtestError):
            loadenv.bundle_rate_limits(bundle.replace("  burstPerPrincipal: 10\n", ""))

    def test_client_count_is_bounded(self) -> None:
        self.assertEqual(loadenv.client_ids(2), ["loadtest-001", "loadtest-002"])
        for count in (0, loadenv.MAXIMUM_CLIENTS + 1):
            with self.assertRaises(loadenv.LoadtestError):
                loadenv.client_ids(count)

    def test_dev_header_must_be_the_owned_private_session_file(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            project = Path(directory) / "project"
            header = project / ".evidence/dev/generated/keys/loadtest-001.header"
            header.parent.mkdir(parents=True)
            header.write_text("Authorization: Bearer header.payload.signature\n", encoding="ascii")
            header.chmod(0o600)
            fake = Path(directory) / "evidencectl"
            fake.write_text(
                f"#!/bin/sh\nprintf '%s\\n' '{{\"status\":\"ready\",\"headerFile\":\"{header}\"}}'\n", encoding="utf-8"
            )
            fake.chmod(0o700)
            self.assertEqual(loadenv.fresh_header(fake, project, "loadtest-001"), header.resolve())
            with self.assertRaises(loadenv.LoadtestError):
                loadenv.fresh_header(fake, project, "loadtest-002")
            header.chmod(0o644)
            with self.assertRaises(loadenv.LoadtestError):
                loadenv.fresh_header(fake, project, "loadtest-001")

    def _fake_token_evidencectl(self, evidencectl: Path, expires_in: int) -> None:
        # Writes one owner-only header per requested client, then reports it.
        evidencectl.write_text(
            "#!/usr/bin/env python3\n"
            "import base64, json, os, sys, time\n"
            "client, project = sys.argv[5], sys.argv[6]\n"
            "b = lambda v: base64.urlsafe_b64encode(v).rstrip(b'=').decode()\n"
            f"claims = b(json.dumps({{'exp': int(time.time()) + {expires_in}}}).encode())\n"
            "path = os.path.join(project, '.evidence/dev/generated/keys', client + '.header')\n"
            "os.makedirs(os.path.dirname(path), exist_ok=True)\n"
            "fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)\n"
            "os.write(fd, ('Authorization: Bearer ' + b(b'{}') + '.' + claims + '.' + b(client.encode()) + '\\n').encode())\n"
            "os.close(fd)\n"
            "print(json.dumps({'operation': 'dev-token', 'status': 'ready', 'headerFile': path}))\n",
            encoding="utf-8",
        )
        evidencectl.chmod(0o700)

    def test_fresh_headers_fetch_every_client_and_refuse_short_lived_tokens(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repository = Path(directory).resolve()
            root, evidencectl = _owned_root(repository)
            _write_environment(root, evidencectl)
            self._fake_token_evidencectl(evidencectl, 300)
            listing = loadenv.fresh_headers(root, repository)
            paths = listing.read_text(encoding="utf-8").split()
            self.assertEqual([Path(path).name for path in paths], [f"loadtest-00{i}.header" for i in (1, 2, 3)])
            self.assertEqual(listing.stat().st_mode & 0o077, 0)
            self.assertNotIn("Bearer", listing.read_text(encoding="utf-8"))
            self._fake_token_evidencectl(evidencectl, 120)
            with self.assertRaises(loadenv.LoadtestError):
                loadenv.fresh_headers(root, repository)

    def test_describe_accepts_only_the_recorded_build_of_this_checkout(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repository = Path(directory).resolve()
            root, evidencectl = _owned_root(repository)
            evidencectl.write_text("", encoding="utf-8")
            library = repository / "fips"
            library.mkdir()
            environment = _write_environment(root, evidencectl, runtime_library_path=str(library))
            self.assertEqual(
                loadenv.describe(root, repository),
                ("http://127.0.0.1:1234", str(evidencectl), str(root / "project"), "3", str(library)),
            )
            for override in ({"build_profile": "debug"}, {"clients": 0}, {"evidence_url": "http://192.0.2.1:1234"}):
                _write_environment(root, evidencectl, **{**environment, **override})
                with self.assertRaises(loadenv.LoadtestError):
                    loadenv.describe(root, repository)
            (root / ".launcher-owned").write_text("registry-stack-breg-loadtest-v2\n", encoding="ascii")
            _write_environment(root, evidencectl, **environment)
            with self.assertRaises(loadenv.LoadtestError):
                loadenv.describe(root, repository)

    def test_mock_pid_is_returned_only_for_the_exact_launched_command(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repository = Path(directory).resolve()
            root, evidencectl = _owned_root(repository)
            _write_environment(root, evidencectl)
            project = str((root / "project").resolve())
            expected = loadenv.mock_command(evidencectl, 4711)
            self.assertEqual(
                expected, f"{evidencectl} source mock serve --config mocks/source.yaml --http-addr 127.0.0.1:4711"
            )
            with (
                unittest.mock.patch.object(loadenv, "_process_command", return_value=expected),
                unittest.mock.patch.object(loadenv, "_process_cwd", return_value=project),
            ):
                self.assertEqual(loadenv.owned_mock_pid(root), 4242)
            with (
                unittest.mock.patch.object(loadenv, "_process_command", return_value=expected),
                unittest.mock.patch.object(loadenv, "_process_cwd", return_value="/tmp/another-project"),
            ):
                self.assertIsNone(loadenv.owned_mock_pid(root))
            with (
                unittest.mock.patch.object(loadenv, "_process_command", return_value="/usr/bin/unrelated"),
                unittest.mock.patch.object(loadenv, "_process_cwd", return_value=project),
            ):
                self.assertIsNone(loadenv.owned_mock_pid(root))
            with (
                unittest.mock.patch.object(loadenv, "_process_command", return_value=""),
                unittest.mock.patch.object(loadenv, "_process_cwd", return_value=""),
            ):
                self.assertIsNone(loadenv.owned_mock_pid(root))

    def test_process_cwd_reads_a_live_process_directory(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            child = subprocess.Popen(["sleep", "30"], cwd=directory)
            try:
                self.assertEqual(loadenv._process_cwd(child.pid), str(Path(directory).resolve()))
            finally:
                child.kill()
                child.wait()
            self.assertEqual(loadenv._process_cwd(child.pid), "")

    def test_process_cwd_reads_proc_on_linux_without_lsof(self) -> None:
        with (
            unittest.mock.patch.object(loadenv.sys, "platform", "linux"),
            unittest.mock.patch.object(loadenv.os, "readlink", return_value="/tmp/project") as readlink,
            unittest.mock.patch.object(loadenv.subprocess, "run") as run,
        ):
            self.assertEqual(loadenv._process_cwd(4242), "/tmp/project")
        readlink.assert_called_once_with("/proc/4242/cwd")
        run.assert_not_called()
        with (
            unittest.mock.patch.object(loadenv.sys, "platform", "linux"),
            unittest.mock.patch.object(loadenv.os, "readlink", side_effect=FileNotFoundError()),
        ):
            self.assertEqual(loadenv._process_cwd(4242), "")

    def test_process_cwd_names_lsof_when_it_is_missing_elsewhere(self) -> None:
        with (
            unittest.mock.patch.object(loadenv.sys, "platform", "darwin"),
            unittest.mock.patch.object(loadenv.subprocess, "run", side_effect=FileNotFoundError(2, "missing", "lsof")),
        ):
            with self.assertRaisesRegex(loadenv.LoadtestError, "lsof is required"):
                loadenv._process_cwd(4242)

    def test_environment_records_only_non_secret_facts_and_integer_pool_summary(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repository = Path(directory).resolve()
            root, evidencectl = _owned_root(repository)
            evidencectl.write_text("", encoding="utf-8")
            project = root / "project"
            bundle = project / ".evidence/dev/bundle/evidence.yaml"
            bundle.parent.mkdir(parents=True)
            bundle.write_text(
                f"requirement: {loadenv.REQUIREMENT}\nprofile: {loadenv.SELECTOR_PROFILE}\n"
                "rateLimits:\n  requestsPerPrincipalPerMinute: 60\n  burstPerPrincipal: 10\n"
                "  failedSelectorAttemptsPerPrincipalAuthorityPerMinute: 10\n",
                encoding="utf-8",
            )
            (root / "pool").mkdir()
            (root / "pool/pool-facts.json").write_text(json.dumps({"subjects": 200}), encoding="utf-8")
            report = root / "dev-report.json"
            report.write_text(
                json.dumps({"status": "ready", "project": str(project), "evidenceOrigin": "http://127.0.0.1:5555"}),
                encoding="utf-8",
            )
            expected = loadenv.mock_command(evidencectl, 4711)
            with (
                unittest.mock.patch.object(loadenv, "_process_command", return_value=expected),
                unittest.mock.patch.object(loadenv, "_process_cwd", return_value=str(project.resolve())),
            ):
                loadenv.write_environment(root, report, evidencectl, "release", "", 4242, 4711, 3)
            environment = json.loads((root / "env.json").read_text(encoding="utf-8"))
            self.assertEqual(environment["evidence_url"], "http://127.0.0.1:5555")
            self.assertEqual(environment["mock"], {"pid": 4242, "port": 4711})
            self.assertEqual(environment["clients"], 3)
            summary = json.loads((root / "pool/pool-summary.json").read_text(encoding="utf-8"))
            self.assertEqual(summary["loadClients"], 3)
            self.assertEqual(summary["requestsPerPrincipalPerMinute"], 60)
            self.assertEqual(evidence._seed_counts(root / "pool/pool-summary.json"), summary)
            with unittest.mock.patch.object(loadenv, "_process_command", return_value="/usr/bin/unrelated"):
                (root / "env.json").unlink()
                with self.assertRaises(loadenv.LoadtestError):
                    loadenv.write_environment(root, report, evidencectl, "release", "", 4242, 4711, 3)

    def test_shell_entrypoints_parse_and_keep_their_safety_contracts(self) -> None:
        for script in ("up.sh", "down.sh", "run.sh"):
            subprocess.run(["bash", "-n", str(LOADTEST / script)], check=True)
        up = (LOADTEST / "up.sh").read_text(encoding="utf-8")
        run = (LOADTEST / "run.sh").read_text(encoding="utf-8")
        down = (LOADTEST / "down.sh").read_text(encoding="utf-8")
        self.assertIn("trap cleanup_failed_start EXIT", up)
        self.assertIn("cargo-runtime-library-path.sh", up)
        self.assertIn("registry_cargo_build", up)
        self.assertIn("--runtime-library-path", up)
        self.assertIn('evidencectl" --format json dev start', up)
        self.assertIn("DYLD_FALLBACK_LIBRARY_PATH", run)
        self.assertIn("DYLD_FALLBACK_LIBRARY_PATH", down)
        self.assertIn("--secret-file", run)
        self.assertIn("--seed-pool", run)
        self.assertIn("dev stop", down)
        self.assertIn("dev clean", down)
        self.assertIn("mock-pid", down)
        for source in (up, run, down):
            self.assertNotIn("rm -rf", source)


if __name__ == "__main__":
    unittest.main()
