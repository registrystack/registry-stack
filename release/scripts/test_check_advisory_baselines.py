# SPDX-License-Identifier: Apache-2.0
import copy
import contextlib
import hashlib
import importlib.util
import io
import json
import os
import re
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
CHECKER = Path(__file__).with_name("check-advisory-baselines.py")
LIVE_BASELINES = (
    ROOT / "products/relay-v2/security/advisory-baseline.json",
    ROOT / "release/security/breg-advisory-baseline.json",
    ROOT / "release/security/discovery-advisory-baseline.json",
    ROOT / "release/security/evidence-advisory-baseline.json",
    ROOT / "release/security/mint-advisory-baseline.json",
)
LIVE_REFERENCE_IMAGE_DIGESTS = {
    "relay": "sha256:ff8e8d84143d3af01930d0ddc65c8b894f367b31b66f0b5d163854cd7d28dea8",
    "breg": "sha256:ff6faa69c81b62029578f50d47499165e3942a01cd2987b70984a920d5619239",
    "discovery": "sha256:68b298259c0871c161a4f3f7c1ef4f0bb0a78e42051f833aa1d64a922ad75587",
    "evidence": "sha256:3b2acf91f2095d565d06529175fc231414c0dd508844c2d09ad4522d7be03908",
    "mint": "sha256:532598e7581716ce679cb83e10aa7d6c1ff9c134f0fcfc7ec9578818644db800",
}
LIVE_REFERENCE_SOURCE_REVISION = "3e655214558e4479a72a2049ebf72bf5721a303e"
# The date the live exceptions below were reviewed against, stated here rather
# than derived from the baselines: deriving it from their own reviewed_at values
# would make the checker's future-dated guard unreachable for the newest
# exception. Move it forward by hand when the baselines are renewed.
LIVE_REVIEW_EVALUATION_DATE = "2026-09-04"
LIVE_REFERENCE_PROVENANCE = {
    "relay": "official_candidate",
    "breg": "official_candidate",
    "discovery": "official_candidate",
    "evidence": "official_candidate",
    "mint": "official_candidate",
}
LIVE_EXECUTABLES = {
    "relay": "/usr/local/bin/relay",
    "breg": "/usr/local/bin/breg",
    "discovery": "/usr/local/bin/discovery",
    "evidence": "/usr/local/bin/evidence",
    "mint": "/usr/local/bin/mint",
}


def load_module():
    spec = importlib.util.spec_from_file_location("check_advisory_baselines", CHECKER)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class AdvisoryBaselineCheckTest(unittest.TestCase):
    IMAGE_DIGEST = "sha256:" + "a" * 64
    BASE_LAYER_1 = "sha256:" + "1" * 64
    BASE_LAYER_2 = "sha256:" + "2" * 64
    APP_LAYER = "sha256:" + "3" * 64
    REVIEWED_REVISION = "b" * 40
    SUBJECT = "test-image"
    RUNTIME_CONFIG = {
        "user": "65532",
        "entrypoint": ["/app/service"],
        "command": ["serve"],
        "working_dir": "/app",
        "environment": [
            "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
        ],
        "healthcheck": None,
        "args_escaped": False,
        "exposed_ports": ["8080/tcp"],
        "stop_signal": "",
    }

    def setUp(self):
        self.module = load_module()
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.rootfs = self.root / "rootfs"
        self.rootfs.mkdir()
        self.baseline_path = self.root / "baseline.json"
        self.write_elf("/app/service")

    def tearDown(self):
        self.tmp.cleanup()

    def write_elf(
        self,
        image_path,
        undefined=(),
        needed=(),
        *,
        machine=62,
        rpaths=None,
        runpaths=None,
        interpreter=None,
        loader_tags=(),
    ):
        path = self.rootfs / image_path.lstrip("/")
        path.parent.mkdir(parents=True, exist_ok=True)
        strings = bytearray(b"\0")

        def add_string(value):
            offset = len(strings)
            strings.extend(value.encode() + b"\0")
            return offset

        symbol_offsets = [add_string(symbol) for symbol in undefined]
        needed_offsets = [add_string(library) for library in needed]
        rpath_offset = add_string(":".join(rpaths)) if rpaths is not None else None
        runpath_offset = (
            add_string(":".join(runpaths)) if runpaths is not None else None
        )
        symbols = bytearray(b"\0" * 24)
        for offset in symbol_offsets:
            symbols.extend(struct.pack("<IBBHQQ", offset, 0x12, 0, 0, 0, 0))
        dynamic = bytearray()
        for offset in needed_offsets:
            dynamic.extend(struct.pack("<qQ", 1, offset))
        if rpath_offset is not None:
            dynamic.extend(struct.pack("<qQ", 15, rpath_offset))
        if runpath_offset is not None:
            dynamic.extend(struct.pack("<qQ", 29, runpath_offset))
        for tag in loader_tags:
            dynamic.extend(struct.pack("<qQ", tag, 0))
        dynamic.extend(struct.pack("<qQ", 0, 0))

        header_size = 64
        program_header_size = 56 if interpreter is not None else 0
        program_offset = header_size if interpreter is not None else 0
        encoded_interpreter = (
            interpreter.encode() + b"\0" if interpreter is not None else b""
        )
        interpreter_offset = header_size + program_header_size
        string_offset = (
            interpreter_offset + len(encoded_interpreter) + 7
        ) & ~7
        symbol_offset = (string_offset + len(strings) + 7) & ~7
        dynamic_offset = (symbol_offset + len(symbols) + 7) & ~7
        section_offset = (dynamic_offset + len(dynamic) + 7) & ~7
        ident = b"\x7fELF" + bytes([2, 1, 1, 0]) + b"\0" * 8
        header = struct.pack(
            "<16sHHIQQQIHHHHHH",
            ident,
            3,
            machine,
            1,
            0,
            program_offset,
            section_offset,
            0,
            header_size,
            program_header_size,
            int(interpreter is not None),
            64,
            4,
            0,
        )
        data = bytearray(header)
        if interpreter is not None:
            data.extend(
                struct.pack(
                    "<IIQQQQQQ",
                    3,
                    4,
                    interpreter_offset,
                    0,
                    0,
                    len(encoded_interpreter),
                    len(encoded_interpreter),
                    1,
                )
            )
            data.extend(encoded_interpreter)
        data.extend(b"\0" * (string_offset - len(data)))
        data.extend(strings)
        data.extend(b"\0" * (symbol_offset - len(data)))
        data.extend(symbols)
        data.extend(b"\0" * (dynamic_offset - len(data)))
        data.extend(dynamic)
        data.extend(b"\0" * (section_offset - len(data)))
        section_header = "<IIQQQQIIQQ"
        data.extend(struct.pack(section_header, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0))
        data.extend(
            struct.pack(
                section_header,
                0,
                3,
                0,
                0,
                string_offset,
                len(strings),
                0,
                0,
                1,
                0,
            )
        )
        data.extend(
            struct.pack(
                section_header,
                0,
                11,
                0,
                0,
                symbol_offset,
                len(symbols),
                1,
                0,
                8,
                24,
            )
        )
        data.extend(
            struct.pack(
                section_header,
                0,
                6,
                0,
                0,
                dynamic_offset,
                len(dynamic),
                1,
                0,
                8,
                16,
            )
        )
        path.write_bytes(data)
        return path

    def digest(self, image_path):
        path = self.rootfs / image_path.lstrip("/")
        return hashlib.sha256(path.read_bytes()).hexdigest()

    def file_entry(self, image_path):
        return {
            "id": "file-" + image_path.replace("/", "-"),
            "location": {"path": image_path, "layerID": self.APP_LAYER},
            "metadata": {"type": "RegularFile"},
            "digests": [{"algorithm": "sha256", "value": self.digest(image_path)}],
        }

    def image_target(self, layers=None, image_digest=None):
        layers = layers or [self.BASE_LAYER_1, self.BASE_LAYER_2, self.APP_LAYER]
        image_ref = f"registry.example/test@{image_digest or self.IMAGE_DIGEST}"
        return {
            "userInput": image_ref,
            "repoDigests": [image_ref],
            "architecture": "amd64",
            "os": "linux",
            "layers": [{"digest": layer} for layer in layers],
        }

    def reports(
        self,
        *,
        files=("/app/service",),
        layers=None,
        image_digest=None,
        component_layer=None,
        severity="High",
    ):
        component_layer = component_layer or self.BASE_LAYER_1
        artifact = {
            "id": "artifact-1",
            "name": "openssl",
            "version": "3.0.0",
            "type": "deb",
            "locations": [
                {
                    "path": "/var/lib/dpkg/status.d/openssl",
                    "layerID": component_layer,
                }
            ],
        }
        target = self.image_target(layers, image_digest)
        grype = {
            "descriptor": {"name": "grype", "version": "0.104.0"},
            "source": {"type": "image", "target": copy.deepcopy(target)},
            "matches": [
                {
                    "vulnerability": {
                        "id": "CVE-2026-0001",
                        "severity": severity,
                        "fix": {"versions": [], "state": "not-fixed"},
                    },
                    "artifact": copy.deepcopy(artifact),
                }
            ],
        }
        syft = {
            "descriptor": {"name": "syft", "version": "1.45.1"},
            "schema": {"version": "16.1.3"},
            "source": {"type": "image", "metadata": copy.deepcopy(target)},
            "artifacts": [copy.deepcopy(artifact)],
            "files": [self.file_entry(path) for path in files],
        }
        return grype, syft

    def finding(self, **kwargs):
        grype, syft = self.reports(**kwargs)
        return self.module.normalize_grype(grype, self.SUBJECT, syft).findings[0]

    def test_syft_root_directory_is_valid_file_evidence(self):
        grype, syft = self.reports()
        syft["files"].append(
            {
                "id": "file-root",
                "location": {"path": "/", "layerID": self.BASE_LAYER_1},
                "metadata": {"type": "Directory"},
            }
        )

        normalized = self.module.normalize_grype(grype, self.SUBJECT, syft)

        self.assertIn("/", normalized.findings[0].syft_file_paths)

    def test_reviewed_assertion_path_cannot_target_root(self):
        with self.assertRaises(SystemExit):
            self.module.validate_image_path("/", "reviewed assertion path")

    def test_syft_file_paths_reject_unsafe_or_unnormalized_values(self):
        for path in (
            "app/service",
            "/app//service",
            "/app/service/",
            "/app/./service",
            "/app/../service",
            "/app/\x00service",
        ):
            with self.subTest(path=repr(path)):
                with self.assertRaises(SystemExit):
                    self.module.syft_files({"files": [{"location": {"path": path}}]})

    def test_syft_file_paths_reject_duplicates_including_root(self):
        root_entry = {"location": {"path": "/"}}
        with self.assertRaises(SystemExit):
            self.module.syft_files({"files": [root_entry, copy.deepcopy(root_entry)]})

    def with_digest(self, definition):
        definition["definition_digest"] = self.module.definition_digest(definition)
        return definition

    def dynamic_assertion(self, symbols=("ungetwc",)):
        return self.with_digest(
            {
                "kind": "dynamic_symbol_absent",
                "reference_image_digest": self.IMAGE_DIGEST,
                "reference_source_revision": self.REVIEWED_REVISION,
                "reference_provenance": "official_candidate",
                "executables": ["/app/service"],
                "symbols": list(symbols),
            }
        )

    def closure_assertion(self, files=("/app/service",), executable="/app/service"):
        return self.with_digest(
            {
                "kind": "executable_closure_equals",
                "reference_image_digest": self.IMAGE_DIGEST,
                "reference_source_revision": self.REVIEWED_REVISION,
                "reference_provenance": "official_candidate",
                "executables": [executable],
                "files": [
                    {
                        "path": path,
                        "sha256": f"sha256:{self.digest(path)}",
                    }
                    for path in files
                ],
            }
        )

    def whole_image_assertion(self, files=("/app/service",)):
        return self.with_digest(
            {
                "kind": "whole_image_fingerprint_equals",
                "reference_image_digest": self.IMAGE_DIGEST,
                "reference_source_revision": self.REVIEWED_REVISION,
                "reference_provenance": "official_candidate",
                "runtime_definition_digest": self.runtime()["definition_digest"],
                "files": [
                    {
                        "path": path,
                        "sha256": f"sha256:{self.digest(path)}",
                    }
                    for path in files
                ],
            }
        )

    def package_assertion(self):
        return self.with_digest(
            {
                "kind": "package_absent_from_executable_closure",
                "reference_image_digest": self.IMAGE_DIGEST,
                "reference_source_revision": self.REVIEWED_REVISION,
                "reference_provenance": "official_candidate",
                "executables": ["/app/service"],
                "package": "libblocked",
            }
        )

    def runtime(self):
        return self.with_digest(
            {
                "image": "gcr.io/example/base@sha256:" + "9" * 64,
                "layer_ids": [self.BASE_LAYER_1, self.BASE_LAYER_2],
                "application_layer_ids": [self.APP_LAYER],
                "config": copy.deepcopy(self.RUNTIME_CONFIG),
            }
        )

    def raw_oci_config(
        self,
        *,
        revision=None,
        environment=None,
        healthcheck=None,
        args_escaped=False,
    ):
        config = {
            "User": self.RUNTIME_CONFIG["user"],
            "Entrypoint": copy.deepcopy(self.RUNTIME_CONFIG["entrypoint"]),
            "Cmd": copy.deepcopy(self.RUNTIME_CONFIG["command"]),
            "WorkingDir": self.RUNTIME_CONFIG["working_dir"],
            "Env": copy.deepcopy(environment or self.RUNTIME_CONFIG["environment"]),
            "ArgsEscaped": args_escaped,
            "ExposedPorts": {port: {} for port in self.RUNTIME_CONFIG["exposed_ports"]},
            "Labels": {
                "org.opencontainers.image.source": (
                    "https://github.com/registrystack/registry-stack"
                ),
                "org.opencontainers.image.revision": (
                    revision or self.REVIEWED_REVISION
                ),
                "org.opencontainers.image.version": "0.0.0-test",
                "org.registrystack.runtime.uid": "65532",
                "org.registrystack.runtime.gid": "65532",
            },
        }
        if healthcheck is not None:
            config["Healthcheck"] = copy.deepcopy(healthcheck)
        return config

    def oci_image_config(self, *, layers=None, **config_kwargs):
        return {
            "architecture": "amd64",
            "os": "linux",
            "rootfs": {
                "type": "layers",
                "diff_ids": list(
                    layers
                    or [self.BASE_LAYER_1, self.BASE_LAYER_2, self.APP_LAYER]
                ),
            },
            "config": self.raw_oci_config(**config_kwargs),
            "history": [],
        }

    def exception(self, finding, assertion=None):
        runtime = self.runtime()
        return {
            "vulnerability_id": finding.rule_id,
            "package": finding.package,
            "installed_version": finding.installed_version,
            "severity": finding.severity,
            "status": "accepted_risk",
            "owner": "@maintainers",
            "rationale": "Reviewed exact candidate exposure with machine evidence.",
            "reviewed_at": "2026-08-01",
            "expires_at": "2026-09-01",
            "invalidation_triggers": sorted(
                self.module.REQUIRED_INVALIDATION_TRIGGERS
            ),
            "runtime_definition_digest": runtime["definition_digest"],
            "component_layer_id": finding.component_layer_id,
            "exposure_assertion": assertion or self.dynamic_assertion(),
        }

    def baseline(self, finding, assertion=None):
        return {
            "version": 4,
            "service": "test-service",
            "runtime": self.runtime(),
            "policies": [
                {
                    "tool": "zizmor",
                    "minimum_severity": "high",
                    "action": "block_unreviewed",
                },
                {
                    "tool": "grype",
                    "minimum_severity": "high",
                    "action": "block_unreviewed",
                    "block_fixable": True,
                },
            ],
            "exceptions": [self.exception(finding, assertion)],
        }

    def load_baseline(self, data):
        self.baseline_path.write_text(json.dumps(data), encoding="utf-8")
        return self.module.load_baseline(self.baseline_path)

    def check(
        self,
        finding,
        baseline,
        rootfs=True,
        candidate_image_digest=None,
        runtime_config=None,
    ):
        return self.module.check_grype_findings(
            [finding],
            self.module.ImageEvidence(finding.image_digest, finding.layer_ids),
            baseline,
            self.module.parse_date("2026-08-13", "today"),
            self.rootfs if rootfs else None,
            candidate_image_digest or finding.image_digest,
            runtime_config or copy.deepcopy(self.RUNTIME_CONFIG),
            finding.layer_ids,
        )

    def install_host_elf_closure(self, host_executable, build_root, image_path):
        installed = {image_path}
        destination = self.rootfs / image_path.lstrip("/")
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(host_executable, destination)
        result = subprocess.run(
            ["ldd", str(host_executable)],
            check=True,
            capture_output=True,
            text=True,
        )
        for line in result.stdout.splitlines():
            match = re.search(r"=>\s+(/\S+)\s+\(", line)
            if match is None:
                match = re.match(r"\s*(/\S+)\s+\(", line)
            if match is None:
                continue
            source = Path(match.group(1))
            try:
                relative = Path(os.path.normpath(source)).relative_to(build_root)
                dependency_path = "/" + relative.as_posix()
            except ValueError:
                dependency_path = source.as_posix()
            target = self.rootfs / dependency_path.lstrip("/")
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source.resolve(), target)
            installed.add(dependency_path)
        return tuple(sorted(installed))

    def syft_digests_for_rootfs(self, files):
        return tuple(
            sorted(
                (
                    image_path,
                    f"sha256:{self.digest(image_path)}",
                )
                for image_path in files
            )
        )

    def test_new_forbidden_symbol_invalidates_exception(self):
        reviewed = self.finding()
        baseline = self.load_baseline(self.baseline(reviewed))
        self.assertEqual(0, self.check(reviewed, baseline))

        self.write_elf("/app/service", undefined=("ungetwc",))
        changed = self.finding()
        self.assertEqual(1, self.check(changed, baseline))

    def test_whole_image_fingerprint_blocks_new_forbidden_symbol(self):
        reviewed = self.finding()
        baseline = self.load_baseline(
            self.baseline(reviewed, self.whole_image_assertion())
        )
        self.write_elf("/app/service", undefined=("ungetwc",))
        changed = self.finding(
            layers=[self.BASE_LAYER_1, self.BASE_LAYER_2, "sha256:" + "4" * 64]
        )
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr):
            self.assertEqual(1, self.check(changed, baseline))
        output = stderr.getvalue()
        self.assertIn("ordered OCI rootfs.diff_ids changed", output)
        self.assertIn("runtime.layer_ids/application_layer_ids", output)
        self.assertNotIn("reviewed runtime change", output)

    def test_future_dated_exception_is_invalid(self):
        reviewed = self.finding()
        data = self.baseline(reviewed)
        data["exceptions"][0]["reviewed_at"] = "2026-08-14"
        baseline = self.load_baseline(data)
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr):
            self.assertEqual(1, self.check(reviewed, baseline))
        self.assertIn("future-dated exception:", stderr.getvalue())

    def test_dynamic_lookup_makes_symbol_absence_unevaluable(self):
        for api in ("dlopen", "dlmopen", "dlsym", "dlvsym"):
            with self.subTest(api=api):
                self.write_elf("/app/service", undefined=(api,))
                finding = self.finding()
                baseline = self.load_baseline(self.baseline(finding))
                stderr = io.StringIO()
                with contextlib.redirect_stderr(stderr):
                    self.assertEqual(1, self.check(finding, baseline))
                self.assertIn(
                    f"imports dynamic loading API(s) ['{api}']; "
                    "executable closure is open",
                    stderr.getvalue(),
                )

    def test_dynamic_loading_makes_exact_closure_unevaluable(self):
        for api in ("dlopen", "dlmopen", "dlsym", "dlvsym"):
            with self.subTest(api=api):
                self.write_elf("/app/service", undefined=(api,))
                finding = self.finding()
                baseline = self.load_baseline(
                    self.baseline(finding, self.closure_assertion())
                )
                stderr = io.StringIO()
                with contextlib.redirect_stderr(stderr):
                    self.assertEqual(1, self.check(finding, baseline))
                self.assertIn(
                    f"imports dynamic loading API(s) ['{api}']; "
                    "executable closure is open",
                    stderr.getvalue(),
                )

    @unittest.skipUnless(
        sys.platform.startswith("linux")
        and shutil.which("cc") is not None
        and shutil.which("ldd") is not None,
        "requires a Linux glibc toolchain",
    )
    def test_real_glibc_definition_passes_but_importing_dependency_fails(self):
        build_root = self.root / "linux-fixture"
        binary_dir = build_root / "app/bin"
        library_dir = build_root / "app/lib"
        binary_dir.mkdir(parents=True)
        library_dir.mkdir(parents=True)
        main_source = build_root / "main.c"
        wrapper_source = build_root / "wrapper.c"
        executable = binary_dir / "service"
        wrapper = library_dir / "libwrapper.so"
        main_source.write_text("int main(void) { return 0; }\n", encoding="utf-8")
        subprocess.run(["cc", str(main_source), "-o", str(executable)], check=True)
        base_files = self.install_host_elf_closure(
            executable, build_root, "/app/bin/service"
        )
        base_finding = self.finding(files=base_files)
        baseline = self.load_baseline(
            self.baseline(base_finding, self.with_digest({
                "kind": "dynamic_symbol_absent",
                "reference_image_digest": self.IMAGE_DIGEST,
                "reference_source_revision": self.REVIEWED_REVISION,
                "reference_provenance": "official_candidate",
                "executables": ["/app/bin/service"],
                "symbols": ["ungetwc"],
            }))
        )
        libc_path = next(path for path in base_files if path.endswith("/libc.so.6"))
        libc = self.rootfs / libc_path.lstrip("/")
        self.assertIn(b"ungetwc", libc.read_bytes())
        self.assertNotIn("ungetwc", self.module.parse_elf(libc).undefined_dynamic_symbols)
        self.assertEqual(0, self.check(base_finding, baseline))

        wrapper_source.write_text(
            "#include <stdio.h>\n"
            "#include <wchar.h>\n"
            "wint_t invoke_ungetwc(FILE *stream) { return ungetwc(L'x', stream); }\n",
            encoding="utf-8",
        )
        subprocess.run(
            ["cc", "-shared", "-fPIC", str(wrapper_source), "-o", str(wrapper)],
            check=True,
        )
        subprocess.run(
            [
                "cc",
                str(main_source),
                "-L",
                str(library_dir),
                "-Wl,--no-as-needed",
                "-lwrapper",
                "-Wl,-rpath,$ORIGIN/../lib",
                "-o",
                str(executable),
            ],
            check=True,
        )
        exposed_files = self.install_host_elf_closure(
            executable, build_root, "/app/bin/service"
        )
        self.assertIn("/app/lib/libwrapper.so", exposed_files)
        imported = self.module.parse_elf(self.rootfs / "app/lib/libwrapper.so")
        self.assertIn("ungetwc", imported.undefined_dynamic_symbols)
        exposed_finding = self.finding(files=exposed_files)
        self.assertEqual(1, self.check(exposed_finding, baseline))

        exposed_assertion = self.with_digest(
            {
                "kind": "dynamic_symbol_absent",
                "reference_image_digest": self.IMAGE_DIGEST,
                "reference_source_revision": self.REVIEWED_REVISION,
                "reference_provenance": "official_candidate",
                "executables": ["/app/bin/service"],
                "symbols": ["ungetwc"],
            }
        )
        exposed_result = self.module.evaluate_exposure_assertion(
            exposed_assertion,
            self.runtime(),
            exposed_finding.layer_ids,
            copy.deepcopy(self.RUNTIME_CONFIG),
            self.rootfs,
            frozenset(exposed_files),
            self.syft_digests_for_rootfs(exposed_files),
        )
        self.assertTrue(exposed_result.evaluable)
        self.assertFalse(exposed_result.passed)
        self.assertIn("/app/lib/libwrapper.so", exposed_result.detail)

    def test_new_package_reachability_invalidates_exception(self):
        self.write_elf("/lib/libsafe.so")
        self.write_elf("/lib/libblocked.so")
        metadata = self.rootfs / "var/lib/dpkg/status.d/libblocked.md5sums"
        metadata.parent.mkdir(parents=True)
        metadata.write_text(
            f"{'0' * 32}  lib/libblocked.so\n",
            encoding="utf-8",
        )
        files = (
            "/app/service",
            "/lib/libsafe.so",
            "/lib/libblocked.so",
            "/var/lib/dpkg/status.d/libblocked.md5sums",
        )
        self.write_elf("/app/service", needed=("libsafe.so",))
        reviewed = self.finding(files=files)
        baseline = self.load_baseline(
            self.baseline(reviewed, self.package_assertion())
        )
        self.assertEqual(0, self.check(reviewed, baseline))

        self.write_elf("/app/service", needed=("libblocked.so",))
        reachable = self.finding(files=files)
        self.assertEqual(1, self.check(reachable, baseline))

    def test_dynamic_loading_makes_package_absence_unevaluable(self):
        metadata = self.rootfs / "var/lib/dpkg/status.d/libblocked.md5sums"
        metadata.parent.mkdir(parents=True)
        metadata.write_text(
            f"{'0' * 32}  lib/libblocked.so\n",
            encoding="utf-8",
        )
        self.write_elf("/lib/libblocked.so")
        files = (
            "/app/service",
            "/lib/libblocked.so",
            "/var/lib/dpkg/status.d/libblocked.md5sums",
        )
        for api in ("dlopen", "dlmopen", "dlsym", "dlvsym"):
            with self.subTest(api=api):
                self.write_elf("/app/service", undefined=(api,))
                finding = self.finding(files=files)
                baseline = self.load_baseline(
                    self.baseline(finding, self.package_assertion())
                )
                stderr = io.StringIO()
                with contextlib.redirect_stderr(stderr):
                    self.assertEqual(1, self.check(finding, baseline))
                self.assertIn(
                    f"imports dynamic loading API(s) ['{api}']; "
                    "executable closure is open",
                    stderr.getvalue(),
                )

    def test_whole_image_fingerprint_blocks_new_reachable_dependency(self):
        reviewed = self.finding()
        baseline = self.load_baseline(
            self.baseline(reviewed, self.whole_image_assertion())
        )
        self.write_elf("/lib/libwrapper.so", undefined=("ungetwc",))
        self.write_elf("/app/service", needed=("libwrapper.so",))
        changed = self.finding(
            files=("/app/service", "/lib/libwrapper.so"),
            layers=[self.BASE_LAYER_1, self.BASE_LAYER_2, "sha256:" + "4" * 64],
        )
        self.assertEqual(1, self.check(changed, baseline))

    def test_new_dependency_invalidates_reviewed_closure(self):
        reviewed = self.finding()
        baseline = self.load_baseline(
            self.baseline(reviewed, self.closure_assertion())
        )
        self.assertEqual(0, self.check(reviewed, baseline))

        self.write_elf("/lib/libwrapper.so")
        self.write_elf("/app/service", needed=("libwrapper.so",))
        files = ("/app/service", "/lib/libwrapper.so")
        reachable = self.finding(files=files)
        self.assertEqual(1, self.check(reachable, baseline))

    def test_pt_interp_is_part_of_reviewed_closure(self):
        interpreter = "/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2"
        self.write_elf(interpreter)
        alias = self.rootfs / "lib64/ld-linux-x86-64.so.2"
        alias.parent.mkdir(parents=True)
        alias.symlink_to("../usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2")
        self.write_elf(
            "/app/service",
            interpreter="/lib64/ld-linux-x86-64.so.2",
        )
        files = ("/app/service", interpreter)
        finding = self.finding(files=files)
        baseline = self.load_baseline(
            self.baseline(finding, self.closure_assertion(files))
        )
        self.assertEqual(0, self.check(finding, baseline))

        missing_interpreter = self.load_baseline(
            self.baseline(finding, self.closure_assertion())
        )
        self.assertEqual(1, self.check(finding, missing_interpreter))

    def test_unsupported_dynamic_tags_fail_closed(self):
        for tag, name in (
            (0x6FFFFEFB, "DT_DEPAUDIT"),
            (0x6FFFFEFC, "DT_AUDIT"),
            (0x7FFFFFFF, "DT_FILTER"),
            (0x7FFFFFFD, "DT_AUXILIARY"),
        ):
            with self.subTest(tag=name):
                self.write_elf("/app/service", loader_tags=(tag,))
                finding = self.finding()
                baseline = self.load_baseline(
                    self.baseline(finding, self.closure_assertion())
                )
                stderr = io.StringIO()
                with contextlib.redirect_stderr(stderr):
                    self.assertEqual(1, self.check(finding, baseline))
                self.assertIn(name, stderr.getvalue())

    def test_mismatched_dependency_rootfs_fails_closed(self):
        self.write_elf("/lib/libwrapper.so")
        self.write_elf("/app/service", needed=("libwrapper.so",))
        files = ("/app/service", "/lib/libwrapper.so")
        finding = self.finding(files=files)
        baseline = self.load_baseline(
            self.baseline(finding, self.closure_assertion(files))
        )
        (self.rootfs / "lib/libwrapper.so").write_bytes(b"substituted dependency")
        self.assertEqual(1, self.check(finding, baseline))

    def test_constructed_scanf_format_change_invalidates_reviewed_closure(self):
        reviewed = self.finding()
        baseline = self.load_baseline(
            self.baseline(reviewed, self.closure_assertion())
        )
        self.assertEqual(0, self.check(reviewed, baseline))

        with (self.rootfs / "app/service").open("ab") as executable:
            executable.write(b"caller-supplied scanf format path\0")
        exposed = self.finding()
        self.assertEqual(1, self.check(exposed, baseline))

    def test_default_loader_path_wins_over_same_directory_decoy(self):
        self.write_elf("/app/service", needed=("libsafe.so",))
        self.write_elf("/app/libsafe.so")
        self.write_elf("/lib/libsafe.so")
        files = ("/app/service", "/app/libsafe.so", "/lib/libsafe.so")
        finding = self.finding(files=files)
        dependency, error = self.module.resolve_needed(
            self.rootfs,
            self.rootfs / "app/service",
            "libsafe.so",
            self.module.parse_elf(self.rootfs / "app/service"),
            finding.syft_file_digests,
        )
        self.assertEqual("", error)
        self.assertEqual(
            "/lib/libsafe.so",
            self.module.image_path_for(self.rootfs, dependency),
        )

    def test_runpath_shadow_invalidates_reviewed_closure(self):
        self.write_elf(
            "/app/service",
            needed=("libsafe.so",),
            runpaths=("/decoy",),
        )
        self.write_elf("/lib/libsafe.so")
        self.write_elf("/decoy/libsafe.so")
        files = ("/app/service", "/lib/libsafe.so", "/decoy/libsafe.so")
        finding = self.finding(files=files)
        baseline = self.load_baseline(
            self.baseline(
                finding,
                self.closure_assertion(("/app/service", "/lib/libsafe.so")),
            )
        )
        self.assertEqual(1, self.check(finding, baseline))

    def test_relative_runpath_fails_closed(self):
        self.write_elf(
            "/app/service",
            needed=("libsafe.so",),
            runpaths=("lib",),
        )
        self.write_elf("/lib/libsafe.so")
        files = ("/app/service", "/lib/libsafe.so")
        finding = self.finding(files=files)
        baseline = self.load_baseline(
            self.baseline(finding, self.closure_assertion(files))
        )
        self.assertEqual(1, self.check(finding, baseline))

    def test_rpath_fails_closed(self):
        self.write_elf(
            "/app/service",
            needed=("libsafe.so",),
            rpaths=("/lib",),
        )
        self.write_elf("/lib/libsafe.so")
        files = ("/app/service", "/lib/libsafe.so")
        finding = self.finding(files=files)
        baseline = self.load_baseline(
            self.baseline(finding, self.closure_assertion(files))
        )
        self.assertEqual(1, self.check(finding, baseline))

    def test_unsupported_runpath_token_fails_closed(self):
        self.write_elf(
            "/app/service",
            needed=("libsafe.so",),
            runpaths=("$LIB",),
        )
        self.write_elf("/lib/libsafe.so")
        files = ("/app/service", "/lib/libsafe.so")
        finding = self.finding(files=files)
        baseline = self.load_baseline(
            self.baseline(finding, self.closure_assertion(files))
        )
        self.assertEqual(1, self.check(finding, baseline))

    def test_machine_specific_default_ignores_cross_arch_decoy(self):
        self.write_elf("/app/service", needed=("libsafe.so",), machine=183)
        self.write_elf("/lib/aarch64-linux-gnu/libsafe.so", machine=183)
        self.write_elf("/lib/x86_64-linux-gnu/libsafe.so", machine=62)
        files = (
            "/app/service",
            "/lib/aarch64-linux-gnu/libsafe.so",
            "/lib/x86_64-linux-gnu/libsafe.so",
        )
        finding = self.finding(files=files)
        dependency, error = self.module.resolve_needed(
            self.rootfs,
            self.rootfs / "app/service",
            "libsafe.so",
            self.module.parse_elf(self.rootfs / "app/service"),
            finding.syft_file_digests,
        )
        self.assertEqual("", error)
        self.assertEqual(
            "/lib/aarch64-linux-gnu/libsafe.so",
            self.module.image_path_for(self.rootfs, dependency),
        )
        baseline = self.load_baseline(
            self.baseline(
                finding,
                self.closure_assertion(
                    ("/app/service", "/lib/aarch64-linux-gnu/libsafe.so")
                ),
            )
        )
        self.assertEqual(0, self.check(finding, baseline))

    def test_global_loader_inputs_fail_closed(self):
        for image_path in self.module.UNSUPPORTED_GLOBAL_LOADER_INPUTS:
            with self.subTest(image_path=image_path):
                path = self.rootfs / image_path.lstrip("/")
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("/lib/libevil.so\n", encoding="utf-8")
                finding = self.finding(files=("/app/service", image_path))
                baseline = self.load_baseline(
                    self.baseline(finding, self.closure_assertion())
                )
                self.assertEqual(1, self.check(finding, baseline))
                path.unlink()

    def test_missing_rootfs_fails_closed(self):
        finding = self.finding()
        baseline = self.load_baseline(self.baseline(finding))
        self.assertEqual(1, self.check(finding, baseline, rootfs=False))

    def test_mismatched_rootfs_fails_closed(self):
        finding = self.finding()
        baseline = self.load_baseline(self.baseline(finding))
        (self.rootfs / "app/service").write_bytes(b"substituted rootfs")
        self.assertEqual(1, self.check(finding, baseline))

    def test_assertion_definition_drift_requires_rereview(self):
        finding = self.finding()
        baseline = self.baseline(finding, self.closure_assertion())
        baseline["exceptions"][0]["exposure_assertion"]["files"][0][
            "sha256"
        ] = "sha256:" + "f" * 64
        with self.assertRaises(SystemExit):
            self.load_baseline(baseline)

    def test_runtime_and_component_changes_invalidate_exception(self):
        finding = self.finding()
        baseline = self.load_baseline(self.baseline(finding))
        changed_runtime = self.finding(
            layers=[self.BASE_LAYER_1, "sha256:" + "4" * 64, self.APP_LAYER]
        )
        changed_component = self.finding(component_layer=self.BASE_LAYER_2)
        self.assertEqual(1, self.check(changed_runtime, baseline))
        self.assertEqual(1, self.check(changed_component, baseline))

    def test_added_candidate_layer_blocks_unreviewed_loader_input(self):
        finding = self.finding()
        baseline = self.load_baseline(self.baseline(finding))
        self.write_elf("/opt/preload.so")
        changed = self.finding(
            files=("/app/service", "/opt/preload.so"),
            layers=[
                self.BASE_LAYER_1,
                self.BASE_LAYER_2,
                self.APP_LAYER,
                "sha256:" + "4" * 64,
            ],
            image_digest="sha256:" + "c" * 64,
        )
        self.assertEqual(1, self.check(changed, baseline))

    def test_independent_candidate_digest_mismatch_fails_closed(self):
        finding = self.finding()
        baseline = self.load_baseline(self.baseline(finding))
        self.assertEqual(
            1,
            self.check(
                finding,
                baseline,
                candidate_image_digest="sha256:" + "c" * 64,
            ),
        )

    def test_empty_report_still_binds_candidate_image_identity(self):
        finding = self.finding()
        baseline_data = self.baseline(finding)
        baseline_data["exceptions"] = []
        baseline = self.load_baseline(baseline_data)
        grype, syft = self.reports()
        grype["matches"] = []
        normalized = self.module.normalize_grype(grype, self.SUBJECT, syft)
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr):
            result = self.module.check_grype_findings(
                list(normalized.findings),
                normalized.image,
                baseline,
                self.module.parse_date("2026-08-13", "today"),
                self.rootfs,
                "sha256:" + "c" * 64,
                copy.deepcopy(self.RUNTIME_CONFIG),
                normalized.image.layer_ids,
            )
        self.assertEqual(1, result)
        self.assertIn("candidate image identity mismatch", stderr.getvalue())

    def test_empty_report_still_binds_oci_rootfs_diff_ids(self):
        finding = self.finding()
        baseline_data = self.baseline(finding)
        baseline_data["exceptions"] = []
        baseline = self.load_baseline(baseline_data)
        grype, syft = self.reports()
        grype["matches"] = []
        normalized = self.module.normalize_grype(grype, self.SUBJECT, syft)
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr):
            result = self.module.check_grype_findings(
                list(normalized.findings),
                normalized.image,
                baseline,
                self.module.parse_date("2026-08-13", "today"),
                self.rootfs,
                normalized.image.digest,
                copy.deepcopy(self.RUNTIME_CONFIG),
                (self.BASE_LAYER_1, self.BASE_LAYER_2, "sha256:" + "4" * 64),
            )
        self.assertEqual(1, result)
        self.assertIn("candidate rootfs evidence mismatch", stderr.getvalue())

    def test_candidate_source_revision_label_mismatch_fails_closed(self):
        with self.assertRaises(SystemExit):
            self.module.normalize_oci_image_config(
                self.oci_image_config(revision="c" * 40),
                self.REVIEWED_REVISION,
            )

    def test_full_crane_config_binds_authoritative_rootfs_diff_ids(self):
        evidence = self.module.normalize_oci_image_config(
            self.oci_image_config(), self.REVIEWED_REVISION
        )
        self.assertEqual(
            (self.BASE_LAYER_1, self.BASE_LAYER_2, self.APP_LAYER),
            evidence.layer_ids,
        )
        self.assertEqual(self.RUNTIME_CONFIG, evidence.runtime_config)

    def test_oci_rootfs_diff_id_mismatch_fails_closed(self):
        finding = self.finding()
        baseline = self.load_baseline(self.baseline(finding))
        self.assertEqual(
            1,
            self.module.check_grype_findings(
                [finding],
                self.module.ImageEvidence(finding.image_digest, finding.layer_ids),
                baseline,
                self.module.parse_date("2026-08-13", "today"),
                self.rootfs,
                finding.image_digest,
                copy.deepcopy(self.RUNTIME_CONFIG),
                (self.BASE_LAYER_1, self.BASE_LAYER_2, "sha256:" + "4" * 64),
            ),
        )

    def test_candidate_layer_change_invalidates_exception(self):
        finding = self.finding()
        baseline = self.load_baseline(self.baseline(finding))
        changed = self.finding(
            layers=[
                self.BASE_LAYER_1,
                self.BASE_LAYER_2,
                "sha256:" + "4" * 64,
            ]
        )
        self.assertEqual(1, self.check(changed, baseline))

    def test_loader_environment_change_invalidates_exception(self):
        finding = self.finding()
        baseline = self.load_baseline(self.baseline(finding))
        changed_config = copy.deepcopy(self.RUNTIME_CONFIG)
        changed_config["environment"].append("LD_PRELOAD=/opt/libevil.so")
        self.assertEqual(
            1,
            self.check(finding, baseline, runtime_config=changed_config),
        )

    def test_loader_environment_is_rejected_from_oci_config(self):
        environment = copy.deepcopy(self.RUNTIME_CONFIG["environment"])
        environment.append("LD_PRELOAD=/opt/libevil.so")
        with self.assertRaises(SystemExit):
            self.module.normalize_runtime_config(
                self.raw_oci_config(environment=environment),
                self.REVIEWED_REVISION,
            )

    def test_exec_healthcheck_is_part_of_normalized_oci_config(self):
        healthcheck = {
            "Test": ["CMD", "/app/service", "healthcheck"],
            "Interval": 30_000_000_000,
            "Timeout": 5_000_000_000,
            "StartPeriod": 10_000_000_000,
            "Retries": 3,
        }
        raw = self.raw_oci_config(healthcheck=healthcheck, args_escaped=True)
        normalized = self.module.normalize_runtime_config(
            raw, self.REVIEWED_REVISION
        )
        self.assertEqual(
            {
                "test": ["CMD", "/app/service", "healthcheck"],
                "interval": 30_000_000_000,
                "timeout": 5_000_000_000,
                "start_period": 10_000_000_000,
                "start_interval": 0,
                "retries": 3,
            },
            normalized["healthcheck"],
        )
        self.assertTrue(normalized["args_escaped"])

    def test_runtime_ports_and_stop_signal_are_normalized(self):
        raw = self.raw_oci_config()
        raw["StopSignal"] = "SIGTERM"
        normalized = self.module.normalize_runtime_config(
            raw, self.REVIEWED_REVISION
        )
        self.assertEqual(["8080/tcp"], normalized["exposed_ports"])
        self.assertEqual("SIGTERM", normalized["stop_signal"])

    def test_unknown_oci_runtime_fields_fail_closed(self):
        for field, value in (
            ("NetworkDisabled", True),
            ("StopTimeout", 10),
            ("Tty", True),
            ("FutureRuntimeHook", {"enabled": True}),
        ):
            with self.subTest(field=field):
                raw = self.raw_oci_config()
                raw[field] = value
                with self.assertRaises(SystemExit):
                    self.module.normalize_runtime_config(raw, self.REVIEWED_REVISION)

    def test_oci_runtime_types_and_identity_sets_fail_closed(self):
        cases = []
        typed_user = self.raw_oci_config()
        typed_user["User"] = 65532
        cases.append(typed_user)
        duplicate_env = self.raw_oci_config()
        duplicate_env["Env"].append("PATH=/decoy")
        cases.append(duplicate_env)
        extra_label = self.raw_oci_config()
        extra_label["Labels"]["routing.example/enabled"] = "true"
        cases.append(extra_label)
        wrong_runtime_uid = self.raw_oci_config()
        wrong_runtime_uid["Labels"]["org.registrystack.runtime.uid"] = "0"
        cases.append(wrong_runtime_uid)
        wrong_runtime_gid = self.raw_oci_config()
        wrong_runtime_gid["Labels"]["org.registrystack.runtime.gid"] = "0"
        cases.append(wrong_runtime_gid)
        extra_healthcheck = self.raw_oci_config(
            healthcheck={
                "Test": ["CMD", "/app/service", "healthcheck"],
                "FutureField": 1,
            }
        )
        cases.append(extra_healthcheck)
        for raw in cases:
            with self.subTest(raw=raw):
                with self.assertRaises(SystemExit):
                    self.module.normalize_runtime_config(raw, self.REVIEWED_REVISION)

    def test_shell_form_runtime_inputs_fail_closed(self):
        for field, value in (
            ("Shell", ["/bin/sh", "-c"]),
            ("OnBuild", ["RUN echo unsafe"]),
            ("Volumes", {"/host": {}}),
        ):
            with self.subTest(field=field):
                raw = self.raw_oci_config()
                raw[field] = value
                with self.assertRaises(SystemExit):
                    self.module.normalize_runtime_config(raw, self.REVIEWED_REVISION)

    def test_v3_baseline_is_rejected(self):
        finding = self.finding()
        baseline = self.baseline(finding)
        baseline["version"] = 3
        with self.assertRaises(SystemExit):
            self.load_baseline(baseline)

    def test_all_live_baselines_use_evaluable_whole_image_fingerprints(self):
        for path in LIVE_BASELINES:
            with self.subTest(path=path):
                baseline = self.module.load_baseline(path)
                service = baseline["service"]
                live_assertion = baseline["exceptions"][0]["exposure_assertion"]
                self.assertTrue(
                    all(
                        exception["exposure_assertion"] == live_assertion
                        for exception in baseline["exceptions"]
                    )
                )
                self.assertEqual(
                    "whole_image_fingerprint_equals", live_assertion["kind"]
                )
                self.assertEqual(
                    LIVE_REFERENCE_IMAGE_DIGESTS[service],
                    live_assertion["reference_image_digest"],
                )
                self.assertEqual(
                    LIVE_REFERENCE_SOURCE_REVISION,
                    live_assertion["reference_source_revision"],
                )
                self.assertEqual(
                    LIVE_REFERENCE_PROVENANCE[service],
                    live_assertion["reference_provenance"],
                )
                self.assertEqual(
                    baseline["runtime"]["definition_digest"],
                    live_assertion["runtime_definition_digest"],
                )
                executable = LIVE_EXECUTABLES[service]
                paths = {entry["path"] for entry in live_assertion["files"]}
                self.assertEqual(
                    {
                        executable,
                        "/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2",
                        "/usr/lib/x86_64-linux-gnu/libc.so.6",
                        "/usr/lib/x86_64-linux-gnu/libgcc_s.so.1",
                        "/usr/lib/x86_64-linux-gnu/libm.so.6",
                    },
                    paths,
                )
                self.write_elf("/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2")
                interpreter_alias = self.rootfs / "lib64/ld-linux-x86-64.so.2"
                interpreter_alias.parent.mkdir(parents=True, exist_ok=True)
                if not interpreter_alias.is_symlink():
                    interpreter_alias.symlink_to(
                        "../usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2"
                    )
                self.write_elf(
                    "/usr/lib/x86_64-linux-gnu/libc.so.6",
                    needed=("ld-linux-x86-64.so.2",),
                )
                self.write_elf("/usr/lib/x86_64-linux-gnu/libgcc_s.so.1")
                self.write_elf("/usr/lib/x86_64-linux-gnu/libm.so.6")
                self.write_elf(
                    executable,
                    needed=("libc.so.6", "libgcc_s.so.1", "libm.so.6"),
                    interpreter="/lib64/ld-linux-x86-64.so.2",
                )
                assertion = copy.deepcopy(live_assertion)
                assertion["files"] = [
                    {
                        "path": image_path,
                        "sha256": f"sha256:{self.digest(image_path)}",
                    }
                    for image_path in sorted(paths)
                ]
                assertion["definition_digest"] = self.module.definition_digest(assertion)
                synthetic_baseline = copy.deepcopy(baseline)
                for exception in synthetic_baseline["exceptions"]:
                    exception["exposure_assertion"] = copy.deepcopy(assertion)
                runtime_layers = list(baseline["runtime"]["layer_ids"])
                application_layers = baseline["runtime"]["application_layer_ids"]
                target = self.image_target(
                    runtime_layers + application_layers,
                    live_assertion["reference_image_digest"],
                )
                artifacts = {}
                for exception in baseline["exceptions"]:
                    package = exception["package"]
                    artifacts.setdefault(
                        package,
                        {
                            "id": f"{package}-artifact",
                            "name": package,
                            "version": exception["installed_version"],
                            "type": "deb",
                            "locations": [
                                {
                                    "path": f"/var/lib/dpkg/status.d/{package}",
                                    "layerID": exception["component_layer_id"],
                                }
                            ],
                        },
                    )
                grype = {
                    "descriptor": {"name": "grype", "version": "0.104.0"},
                    "source": {"type": "image", "target": copy.deepcopy(target)},
                    "matches": [
                        {
                            "vulnerability": {
                                "id": exception["vulnerability_id"],
                                "severity": exception["severity"],
                                "fix": {"versions": [], "state": "not-fixed"},
                            },
                            "artifact": copy.deepcopy(artifacts[exception["package"]]),
                        }
                        for exception in baseline["exceptions"]
                    ],
                }
                syft = {
                    "descriptor": {"name": "syft", "version": "1.45.1"},
                    "schema": {"version": "16.1.3"},
                    "source": {"type": "image", "metadata": copy.deepcopy(target)},
                    "artifacts": [
                        copy.deepcopy(artifact) for artifact in artifacts.values()
                    ],
                    "files": [self.file_entry(image_path) for image_path in sorted(paths)],
                }
                normalized = self.module.normalize_grype(
                    grype, f"{service}-image", syft
                )
                self.assertEqual(
                    0,
                    self.module.check_grype_findings(
                        list(normalized.findings),
                        normalized.image,
                        synthetic_baseline,
                        self.module.parse_date(
                            LIVE_REVIEW_EVALUATION_DATE, "today"
                        ),
                        self.rootfs,
                        live_assertion["reference_image_digest"],
                        copy.deepcopy(baseline["runtime"]["config"]),
                        tuple(runtime_layers + application_layers),
                    ),
                )


if __name__ == "__main__":
    unittest.main()
