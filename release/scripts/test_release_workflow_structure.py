#!/usr/bin/env python3
from __future__ import annotations

import json
import importlib.util
import subprocess
import tempfile
import unittest
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[2]
WORKFLOWS = ROOT / ".github" / "workflows"
LATEST_RELEASE_HELPER = ROOT / "release/scripts/verify_latest_published_release.py"
LINUX_NODE_BUILD_HELPER = ROOT / "release/scripts/build-linux-node-client"


def workflow(name: str) -> tuple[str, dict]:
    text = (WORKFLOWS / name).read_text(encoding="utf-8")
    return text, yaml.safe_load(text)


def step_run(document: dict, job: str, name: str) -> str:
    return next(
        step["run"]
        for step in document["jobs"][job]["steps"]
        if step.get("name") == name
    )


def verify_latest_release_fixture(
    metadata: list[dict],
    expected_tag: str,
    expected_sha256: str,
) -> subprocess.CompletedProcess[str]:
    with tempfile.TemporaryDirectory() as temporary_directory:
        metadata_path = Path(temporary_directory) / "release.json"
        metadata_path.write_text(json.dumps(metadata), encoding="utf-8")
        return subprocess.run(
            [
                "python3",
                str(LATEST_RELEASE_HELPER),
                "--metadata",
                str(metadata_path),
                "--expected-tag",
                expected_tag,
                "--expected-sha256",
                expected_sha256,
            ],
            capture_output=True,
            text=True,
            check=False,
        )


class EvidenceDevelopmentWorkflowStructureTest(unittest.TestCase):
    def test_is_manual_main_only_with_one_narrow_publication_job(self) -> None:
        text, document = workflow("evidence-dev.yml")
        trigger = text.split("permissions:", 1)[0]
        self.assertIn("workflow_dispatch:", trigger)
        self.assertNotIn("push:", trigger)
        self.assertNotIn("pull_request:", trigger)
        self.assertNotIn("schedule:", trigger)
        self.assertEqual(
            list(document["jobs"]),
            ["validate", "build", "clients", "assemble", "publish"],
        )
        self.assertEqual(
            document["jobs"]["validate"]["permissions"],
            {"actions": "read", "contents": "read"},
        )
        self.assertEqual(
            document["jobs"]["clients"]["permissions"],
            {"contents": "read"},
        )
        self.assertEqual(
            document["jobs"]["assemble"]["permissions"],
            {"actions": "read", "contents": "read"},
        )
        self.assertEqual(
            document["jobs"]["publish"]["permissions"],
            {"actions": "read", "contents": "write"},
        )
        self.assertEqual(text.count("contents: write"), 1)
        publish_uses = {
            step.get("uses", "") for step in document["jobs"]["publish"]["steps"]
        }
        self.assertFalse(
            any(action.startswith("actions/checkout@") for action in publish_uses)
        )

    def test_binds_a_unique_dev_tag_to_successful_protected_main(self) -> None:
        _, document = workflow("evidence-dev.yml")
        validation = step_run(
            document,
            "validate",
            "Validate manual source and successful CI",
        )
        self.assertIn('"${GITHUB_REF}" != refs/heads/main', validation)
        self.assertIn(
            '"$(git rev-parse refs/remotes/origin/main)" != "${GITHUB_SHA}"',
            validation,
        )
        self.assertIn("actions/workflows/ci.yml/runs?head_sha=${GITHUB_SHA}", validation)
        self.assertIn('.event == "push"', validation)
        self.assertIn(
            'tag="v${version}-dev.${GITHUB_RUN_ID}.${GITHUB_RUN_ATTEMPT}"',
            validation,
        )
        self.assertIn("Cannot prove development tag ${tag} is absent", validation)
        for job_name in ("build", "assemble"):
            checkout = next(
                step
                for step in document["jobs"][job_name]["steps"]
                if step.get("uses", "").startswith("actions/checkout@")
            )
            self.assertEqual(
                checkout["with"]["ref"],
                "${{ needs.validate.outputs.source_sha }}",
            )
            self.assertFalse(checkout["with"]["persist-credentials"])

    def test_builds_and_smokes_the_released_toolset_shape(self) -> None:
        _, document = workflow("evidence-dev.yml")
        matrix = document["jobs"]["build"]["strategy"]["matrix"]["include"]
        self.assertEqual(
            {(entry["target"], entry["asset"]) for entry in matrix},
            {
                ("x86_64-unknown-linux-gnu", "linux-amd64"),
                ("aarch64-unknown-linux-gnu", "linux-arm64"),
                ("aarch64-apple-darwin", "macos-arm64"),
            },
        )
        build = step_run(
            document,
            "build",
            "Build native Evidence development binaries",
        )
        for package in (
            "registry-evidence",
            "registry-evidencectl",
            "registry-mint",
            "registry-evidence-oid4vci",
        ):
            self.assertIn(f"-p {package}", build)
        self.assertIn("cargo build --release --locked", build)
        self.assertIn(
            "for binary in evidence evidencectl mint evidence-oid4vci", build
        )

        assemble = step_run(
            document,
            "assemble",
            "Assemble development assets and checksums",
        )
        smoke = step_run(
            document,
            "assemble",
            "Smoke the development installer before publication",
        )
        self.assertIn('$0 == "default_version=\\\"\\\""', assemble)
        self.assertIn("registry.evidence-development-build/v1", assemble)
        self.assertIn("sha256sum --", assemble)
        self.assertIn("EVIDENCECTL_ASSET_DIR", smoke)
        self.assertIn("bash development-assets/evidencectl-install.sh", smoke)

    def test_development_binaries_report_a_development_version(self) -> None:
        _, document = workflow("evidence-dev.yml")
        build = step_run(
            document,
            "build",
            "Build native Evidence development binaries",
        )
        smoke = step_run(
            document,
            "assemble",
            "Smoke the development installer before publication",
        )
        expected = (
            'test "${observed}" = '
            '"${binary} ${{ needs.validate.outputs.version }}-dev"'
        )
        self.assertIn(expected, build)
        self.assertIn(expected, smoke)
        # These assets are development builds, so the build must stay unmarked:
        # the suffix above is the proof a tester cannot mistake one for the
        # eventual release of the same version.
        self.assertNotIn("REGISTRY_RELEASE_TAG", build)

    def test_builds_and_smokes_the_relying_party_client_packages(self) -> None:
        _, document = workflow("evidence-dev.yml")
        clients = document["jobs"]["clients"]
        matrix = clients["strategy"]["matrix"]["include"]
        self.assertEqual(
            {
                (entry["asset"], entry["wheel_tag"], entry["napi_platform"])
                for entry in matrix
            },
            {
                ("linux-amd64", "cp310-abi3-linux_x86_64", "linux-x64-gnu"),
                ("linux-arm64", "cp310-abi3-linux_aarch64", "linux-arm64-gnu"),
                ("macos-arm64", "cp310-abi3-macosx_11_0_arm64", "darwin-arm64"),
            },
        )
        self.assertEqual(clients["env"]["RUSTUP_TOOLCHAIN"], "1.95.0")

        wheel = step_run(document, "clients", "Build the Python client wheel")
        # The published wheel name has to be predictable from the source, since
        # the roster below names it exactly: hence a stated Linux platform tag
        # instead of maturin's symbol-derived manylinux audit, and exactly one
        # wheel per platform rather than one per interpreter version.
        self.assertIn("--compatibility linux", wheel)
        self.assertIn("expected exactly one wheel", wheel)
        node = step_run(document, "clients", "Build the Node client package")
        self.assertIn(
            "package/evidence-client.${{ matrix.napi_platform }}.node",
            node,
        )

        # Both smokes load a prebuilt native artifact and exercise it offline.
        # Neither may carry a credential, and each addresses a reserved host
        # that cannot resolve, so a request would fail rather than leave.
        for name in ("Smoke the Python client wheel", "Smoke the Node client package"):
            smoke = step_run(document, "clients", name)
            self.assertIn("placeholder-not-a-credential", smoke)
            self.assertIn("https://evidence.invalid", smoke)
            self.assertIn("P-256", smoke)
            self.assertIn("ES256", smoke)
            self.assertNotIn("Ed25519", smoke)
            self.assertNotIn("EdDSA", smoke)

        python_smoke = step_run(document, "clients", "Smoke the Python client wheel")
        self.assertIn('JWKS, [], "placeholder-not-a-credential"', python_smoke)
        self.assertIn('"response_format": "signed-jws"', python_smoke)
        node_smoke = step_run(document, "clients", "Smoke the Node client package")
        self.assertIn("revokedKeyIds: []", node_smoke)
        self.assertIn("responseFormat: 'signed-jws'", node_smoke)

        roster = step_run(
            document,
            "publish",
            "Reverify the closed development asset roster",
        )
        self.assertIn('echo "evidence-client-node-${tag}-${platform}.tgz"', roster)
        self.assertIn(
            'echo "registry_evidence_client-${python_version}-cp310-abi3-${wheel_platform}.whl"',
            roster,
        )
        self.assertIn(
            "for wheel_platform in linux_x86_64 linux_aarch64 macosx_11_0_arm64",
            roster,
        )

    def test_publishes_one_unique_prerelease_and_prints_its_curl_command(self) -> None:
        text, document = workflow("evidence-dev.yml")
        verify = step_run(
            document,
            "publish",
            "Reverify the closed development asset roster",
        )
        publish = step_run(
            document,
            "publish",
            "Publish unique development prerelease",
        )
        self.assertIn("diff -u", verify)
        self.assertIn("sha256sum --check --strict SHA256SUMS", verify)
        self.assertIn("gh release create", publish)
        self.assertIn('--target "${source_sha}"', publish)
        self.assertIn("--prerelease", publish)
        self.assertIn("--latest=false", publish)
        self.assertIn(
            'download_url="https://github.com/${GITHUB_REPOSITORY}/releases/download/${tag}"',
            publish,
        )
        self.assertIn('install_url="${download_url}/evidencectl-install.sh"', publish)
        for forbidden in (
            "gh release upload",
            "gh release delete",
            "--clobber",
            "git push",
            "git update-ref",
        ):
            self.assertNotIn(forbidden, text)


class CandidateWorkflowStructureTest(unittest.TestCase):
    def test_current_release_pipeline_has_no_pre_v0_19_surface(self) -> None:
        paths = (
            WORKFLOWS / "release-candidate.yml",
            WORKFLOWS / "release.yml",
            WORKFLOWS / "release-canary.yml",
            ROOT / "release/scripts/build-release-binaries.sh",
            ROOT / "release/scripts/build-release-image.sh",
        )
        for path in paths:
            with self.subTest(path=path.relative_to(ROOT)):
                self.assertNotIn(
                    "registry-notary",
                    path.read_text(encoding="utf-8").lower(),
                )
                self.assertNotIn(
                    "registryctl",
                    path.read_text(encoding="utf-8").lower(),
                )
        self.assertFalse((ROOT / "release/docker/Dockerfile.registry-notary").exists())

        repeatability = (WORKFLOWS / "release-repeatability.yml").read_text(
            encoding="utf-8"
        )
        self.assertIn(
            ".images[] | [.name,.final_ref,.digest] | @tsv",
            repeatability,
        )
        self.assertNotIn("image_lock", repeatability)
        self.assertNotIn("minor < 19", repeatability)

        module_path = ROOT / "release/scripts/release_candidate.py"
        spec = importlib.util.spec_from_file_location("release_candidate", module_path)
        self.assertIsNotNone(spec)
        self.assertIsNotNone(spec.loader)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        self.assertEqual(
            {"relay"}, module._candidate_image_names("0.20.1")
        )
        self.assertEqual(
            {"evidence", "mint", "relay"},
            module._candidate_image_names("0.21.0"),
        )
        self.assertFalse(
            any("registry-notary" in name for name in module.SECURITY_EVIDENCE_REQUIRED_FILES)
        )

    def test_pre_v0_19_requests_fail_before_release_discovery(self) -> None:
        _, candidate_document = workflow("release-candidate.yml")
        candidate = step_run(
            candidate_document,
            "validate",
            "Validate request, source, CI, and destinations",
        )
        self.assertIn(
            "pre-v0.19 releases are immutable historical evidence",
            candidate,
        )
        self.assertIn("Git tag and archived assets", candidate)
        for discovery in ("git fetch", "git ls-remote", "gh api"):
            self.assertLess(
                candidate.index("pre-v0.19 releases"),
                candidate.index(discovery),
            )

        _, publication_document = workflow("release.yml")
        publication = step_run(
            publication_document,
            "verify",
            "Resolve exact tag identity",
        )
        self.assertIn(
            "pre-v0.19 releases are immutable historical evidence",
            publication,
        )
        self.assertIn("Git tag and archived assets", publication)
        self.assertLess(
            publication.index("pre-v0.19 releases"),
            publication.index("git fetch"),
        )

    def test_keeps_one_candidate_pipeline_with_narrow_permissions(self) -> None:
        _, document = workflow("release-candidate.yml")
        self.assertEqual(
            list(document["jobs"]),
            [
                "validate",
                "build-canonical",
                "build-platforms",
                "clients",
                "assemble",
                "attest",
            ],
        )
        for job in ("build-canonical", "build-platforms", "clients"):
            permissions = document["jobs"][job]["permissions"]
            self.assertNotEqual(permissions.get("packages"), "write")
            self.assertNotEqual(permissions.get("id-token"), "write")
        self.assertEqual(
            document["jobs"]["assemble"]["permissions"]["packages"], "write"
        )
        self.assertEqual(document["jobs"]["attest"]["permissions"]["id-token"], "write")

    def test_validates_exact_main_source_ci_and_unused_destinations(self) -> None:
        text, document = workflow("release-candidate.yml")
        validation = step_run(
            document,
            "validate",
            "Validate request, source, CI, and destinations",
        )
        self.assertIn('[[ "${REQUEST_SOURCE_SHA}" != "${workflow_revision}" ]]', validation)
        self.assertIn("github.event.client_payload.request_id", text)
        self.assertIn('[[ ! "${REQUEST_ID}" =~ ^[0-9a-f]{32}$ ]]', validation)
        self.assertIn("refs/remotes/origin/main", validation)
        self.assertIn("actions/workflows/ci.yml/runs", validation)
        self.assertIn("git ls-remote --exit-code --tags", validation)
        self.assertIn("require-image-tag-absent", validation)
        self.assertNotIn("select-canary", validation)
        self.assertNotIn("canary", validation.lower())
        self.assertIn(
            '--source-sha "${{ needs.validate.outputs.source_sha }}"',
            text,
        )

    def test_builds_once_scans_exact_images_and_attests_the_candidate(self) -> None:
        text, _ = workflow("release-candidate.yml")
        self.assertIn("Build canonical Linux payload once", text)
        self.assertIn("Build private candidate image layouts once", text)
        self.assertIn("Verify and scan exact candidate images", text)
        self.assertIn("release-candidate-manifest.json", text)
        self.assertIn("Seal compact candidate manifest and bundle", text)
        self.assertIn("Reverify all bytes before requesting OIDC", text)
        self.assertIn("Attest manifest and bundle after re-verification", text)

    def test_current_candidate_builds_and_seals_registry_docs(self) -> None:
        text, _ = workflow("release-candidate.yml")
        self.assertIn("registry-docs-", text)
        self.assertIn("kind=docs", text)
        self.assertIn("docs_name", text)
        self.assertIn("validate-docsets", text)
        self.assertIn("npm run build:archive", text)
        self.assertIn("--verify-lock", text)

    def test_every_published_binary_is_built_as_a_release_build(self) -> None:
        _, document = workflow("release-candidate.yml")
        native = next(
            step
            for step in document["jobs"]["build-platforms"]["steps"]
            if step.get("name") == "Build native platform payload once"
        )
        self.assertEqual(
            native.get("env"),
            {"REGISTRY_RELEASE_TAG": "${{ needs.validate.outputs.tag }}"},
        )
        # The canonical Linux payload carries the same marker through
        # build-release-binaries.sh rather than a step-level environment.
        canonical = step_run(
            document, "build-canonical", "Build canonical Linux payload once"
        )
        self.assertIn("release/scripts/build-release-binaries.sh", canonical)

    def test_release_embeds_evidencectl_tag_and_publishes_latest_alias(self) -> None:
        _, document = workflow("release-candidate.yml")
        assemble = step_run(
            document,
            "assemble",
            "Assemble public payload and validate version-appropriate install inputs",
        )
        self.assertIn('$0 == "default_version=\\\"\\\""', assemble)
        self.assertIn('version="${{ needs.validate.outputs.tag }}"', assemble)
        self.assertIn(
            'cp "candidate/bundle-root/${evidencectl_installer}" \\\n'
            "  candidate/bundle-root/evidencectl-install.sh",
            assemble,
        )
        self.assertIn(
            "chmod 0755 candidate/bundle-root/evidencectl-install.sh",
            assemble,
        )

    def test_next_release_embeds_and_smokes_relay_installer_aliases(self) -> None:
        _, document = workflow("release-candidate.yml")
        assemble = step_run(
            document,
            "assemble",
            "Assemble public payload and validate version-appropriate install inputs",
        )
        self.assertIn(
            'relay_installer="relay-${{ needs.validate.outputs.tag }}-install.sh"',
            assemble,
        )
        self.assertIn("crates/registry-relay-v2/install.sh", assemble)
        self.assertIn(
            'cp "candidate/bundle-root/${relay_installer}" \\\n'
            "    candidate/bundle-root/relay-install.sh",
            assemble,
        )
        self.assertIn(
            'RELAY_ASSET_DIR="${GITHUB_WORKSPACE}/candidate/bundle-root"',
            assemble,
        )
        self.assertIn('RELAY_INSTALL_DIR="${relay_install_dir}"', assemble)
        self.assertIn('"${relay_install_dir}/relay" --version', assemble)
        self.assertIn('"${relay_install_dir}/relayctl" --version', assemble)
        self.assertIn(
            '"relayctl-${{ needs.validate.outputs.tag }}-linux-amd64"',
            assemble,
        )
        self.assertIn("relay_patch >= 1", assemble)

    def test_builds_and_smokes_stable_native_client_packages(self) -> None:
        text, document = workflow("release-candidate.yml")
        clients = document["jobs"]["clients"]
        matrix = clients["strategy"]["matrix"]["include"]
        self.assertEqual(
            {
                (
                    entry["asset"],
                    entry["target"],
                    entry["wheel_tag"],
                    entry["registry_wheel_tag"],
                    entry["napi_platform"],
                )
                for entry in matrix
            },
            {
                (
                    "linux-amd64-glibc",
                    "x86_64-unknown-linux-gnu",
                    "cp310-abi3-linux_x86_64",
                    "cp310-abi3-manylinux_2_17_x86_64.manylinux2014_x86_64",
                    "linux-x64-gnu",
                ),
                (
                    "linux-arm64-glibc",
                    "aarch64-unknown-linux-gnu",
                    "cp310-abi3-linux_aarch64",
                    "cp310-abi3-manylinux_2_17_aarch64.manylinux2014_aarch64",
                    "linux-arm64-gnu",
                ),
                (
                    "macos-arm64",
                    "aarch64-apple-darwin",
                    "cp310-abi3-macosx_11_0_arm64",
                    "cp310-abi3-macosx_11_0_arm64",
                    "darwin-arm64",
                ),
            },
        )
        self.assertEqual(
            clients["env"]["CLIENT_VERSION"],
            "${{ needs.validate.outputs.version }}",
        )
        setup_node = next(
            step for step in clients["steps"] if step.get("name") == "Setup Node"
        )
        self.assertEqual(setup_node["with"]["node-version"], "22.20.0")
        cargo_cache = next(
            step
            for step in clients["steps"]
            if step.get("name") == "Restore native client Cargo cache"
        )
        cache_key = cargo_cache["with"]["key"]
        self.assertIn("zig-0.12.1-glibc-2.17", cache_key)
        self.assertIn("release/requirements/maturin-1.9.6.txt", cache_key)
        self.assertIn("release/scripts/zig-glibc-compiler", cache_key)
        self.assertIn("release/scripts/build-linux-node-client", cache_key)
        self.assertIn("crates/registry-evidence-client-node/package-lock.json", cache_key)
        self.assertIn("crates/registry-relay-client-node/package-lock.json", cache_key)
        wheel = step_run(document, "clients", "Build Python client wheels")
        self.assertIn("--compatibility linux", wheel)
        self.assertIn("--compatibility manylinux_2_17 --zig", wheel)
        self.assertIn("matrix.registry_wheel_tag", wheel)
        self.assertIn("registry_${client}_client", wheel)
        self.assertIn("expected_wheels=2", wheel)
        self.assertIn("--require-hashes --only-binary=:all:", wheel)
        self.assertIn("release/requirements/maturin-1.9.6.txt", wheel)
        node = step_run(document, "clients", "Build Node client packages")
        self.assertNotIn("--use-napi-cross", node)
        self.assertIn(
            "release/scripts/build-linux-node-client \\\n"
            '      --client "${client}" \\\n'
            '      --target "${{ matrix.target }}" \\\n'
            '      --napi-platform "${{ matrix.napi_platform }}" \\\n'
            '      --zig-python "${RUNNER_TEMP}/maturin/bin/python"',
            node,
        )
        helper_call = "release/scripts/build-linux-node-client"
        self.assertLess(
            node.index('(cd "${client_dir}" && npm ci)'), node.index(helper_call)
        )
        self.assertLess(
            node.index(helper_call), node.index('(cd "${client_dir}" && npm pack')
        )
        self.assertIn(
            '(cd "${client_dir}" && ./node_modules/.bin/napi build \\\n'
            '      --platform --release --target "${{ matrix.target }}")',
            node,
        )

        helper = LINUX_NODE_BUILD_HELPER.read_text(encoding="utf-8")
        self.assertIn('zig_version="$("${zig_python}" -m ziglang version)"', helper)
        self.assertIn('if [[ "${zig_version}" != 0.12.1 ]]', helper)
        for routed_variable in (
            "HOST_CC",
            "HOST_CXX",
            "TARGET_CC",
            "TARGET_CXX",
        ):
            self.assertIn(f"export {routed_variable}=", helper)
        for routed_variable in (
            'CC_${target_env}',
            'CXX_${target_env}',
            'CARGO_TARGET_${cargo_target_env}_LINKER',
        ):
            self.assertIn(f'export "{routed_variable}=', helper)
        napi_build = "./node_modules/.bin/napi build"
        self.assertIn('--platform --release --target "${rust_target}"', helper)
        self.assertNotIn("--use-napi-cross", helper)
        self.assertLess(helper.index('export HOST_CC='), helper.index(napi_build))
        self.assertLess(helper.index('export HOST_CXX='), helper.index(napi_build))
        self.assertIn(
            'unversioned_imports="$(\n'
            '  readelf --wide --dyn-syms "${addon}" \\\n'
            "    | awk '$7 == \"UND\" && $5 != \"WEAK\" && "
            "$8 !~ /@/ && $8 !~ /^(napi_|node_api_)/ { print $8 }' \\\n"
            "    | sort -u\n"
            ")\"",
            helper,
        )
        self.assertIn(
            'if [[ -n "${unversioned_imports}" ]]; then\n'
            "  printf 'native addon has strong unversioned imports:"
            "\\n%s\\n' \\\n"
            '    "${unversioned_imports}" >&2\n'
            "  exit 1",
            helper,
        )
        guard_start = helper.index('unversioned_imports="$(')
        self.assertLess(helper.index(napi_build), guard_start)
        self.assertLess(
            guard_start,
            helper.index('readelf --version-info "${addon}"'),
        )
        predicate_marker = "| awk '"
        predicate_start = helper.index(predicate_marker, guard_start) + len(
            predicate_marker
        )
        predicate_end = helper.index("' \\", predicate_start)
        predicate = helper[predicate_start:predicate_end]
        dynsym_fixtures = {
            "observed ISO C23 import": (
                "  1: 0000000000000000 0 FUNC GLOBAL DEFAULT UND "
                "__isoc23_sscanf\n",
                ["__isoc23_sscanf"],
            ),
            "generic strong unversioned import": (
                "  2: 0000000000000000 0 FUNC GLOBAL DEFAULT UND malloc\n",
                ["malloc"],
            ),
            "intentional Node-API imports": (
                "  3: 0000000000000000 0 FUNC GLOBAL DEFAULT UND "
                "napi_create_function\n"
                "  4: 0000000000000000 0 FUNC GLOBAL DEFAULT UND "
                "node_api_get_module_file_name\n",
                [],
            ),
            "versioned import": (
                "  5: 0000000000000000 0 FUNC GLOBAL DEFAULT UND "
                "malloc@GLIBC_2.2.5\n",
                [],
            ),
            "weak import": (
                "  6: 0000000000000000 0 FUNC WEAK DEFAULT UND getrandom\n",
                [],
            ),
        }
        for fixture_name, (dynsym, expected) in dynsym_fixtures.items():
            with self.subTest(fixture=fixture_name):
                guard = subprocess.run(
                    ["awk", predicate],
                    input=dynsym,
                    capture_output=True,
                    text=True,
                    check=True,
                )
                self.assertEqual(guard.stdout.splitlines(), expected)
        self.assertIn("readelf --version-info", helper)
        self.assertIn("GLIBC_2.17", helper)
        self.assertIn(
            "package/${client}-client.${{ matrix.napi_platform }}.node",
            node,
        )
        self.assertIn('"./npm/${{ matrix.napi_platform }}"', node)
        self.assertIn("registry-${client}-client-node", node)
        for name in ("Smoke Python client wheels", "Smoke Node client packages"):
            smoke = step_run(document, "clients", name)
            self.assertIn("smoke-${client}-client-package", smoke)
            self.assertIn("for client in discovery evidence relay", smoke)
        node_smoke = step_run(document, "clients", "Smoke Node client packages")
        self.assertIn("node-root-${client}", node_smoke)
        self.assertIn("root_package", node_smoke)
        self.assertIn("platform_package", node_smoke)
        self.assertIn('packages=("${root_package}" "${platform_package}")', node_smoke)
        self.assertIn("docker run --rm --network none", node_smoke)
        self.assertIn('"${NODE_GLIBC_BASELINE_IMAGE}"', node_smoke)
        baseline = clients["env"]["NODE_GLIBC_BASELINE_IMAGE"]
        self.assertRegex(baseline, r"^node:22\.12\.0-bullseye-slim@sha256:[0-9a-f]{64}$")
        self.assertIn("-maxdepth 1 -name '*.node'", node_smoke)
        self.assertIn("node_modules/@registrystack/${client}-client-", node_smoke)
        self.assertIn(
            "crates/registry-discovery-client-node/package-lock.json",
            str(clients),
        )
        self.assertIn(
            "crates/registry-evidence-client-node/package-lock.json",
            str(clients),
        )
        self.assertIn(
            "crates/registry-relay-client-node/package-lock.json",
            str(clients),
        )
        assemble = step_run(
            document,
            "assemble",
            "Assemble public payload and validate version-appropriate install inputs",
        )
        self.assertIn("candidate-clients-${platform}", assemble)
        self.assertIn('"${client_root}"/* candidate/bundle-root/', assemble)
        self.assertIn("expected-client-assets", assemble)
        self.assertIn("actual-client-assets", assemble)
        self.assertIn("diff -u", assemble)
        self.assertIn("include_relay_clients=1", assemble)
        self.assertIn("expected_client_assets=4", assemble)
        self.assertIn("expected_client_assets=6", assemble)
        self.assertIn("expected_client_assets=9", assemble)
        self.assertIn("relay-client-node-", assemble)
        self.assertIn("discovery-client-node-", assemble)
        self.assertIn("registrystack-${client}-client-${version}.tgz", assemble)
        self.assertIn("for client in discovery evidence relay", assemble)
        self.assertIn("client_registry.py validate-dist", assemble)
        self.assertIn("registry_relay_client-", assemble)
        self.assertIn("registry_discovery_client-", assemble)
        self.assertIn("kind=client-package", text)
        self.assertIn("discovery-client-node-*.tgz", text)
        self.assertIn("registrystack-discovery-client-*.tgz", text)
        self.assertIn("registry_discovery_client-*.whl", text)
        self.assertIn("registrystack-evidence-client-*.tgz", text)
        self.assertIn("registrystack-relay-client-*.tgz", text)
        for forbidden in ("npm publish", "maturin publish", "twine upload"):
            self.assertNotIn(forbidden, text)

    def test_reuses_cache_with_seven_day_validity_and_storage_margin(self) -> None:
        text, document = workflow("release-candidate.yml")
        cache = next(
            step
            for step in document["jobs"]["build-canonical"]["steps"]
            if step.get("name") == "Restore reusable Cargo cache"
        )
        self.assertEqual(
            cache["with"]["key"],
            "registry-stack-release-${{ runner.os }}-"
            "${{ hashFiles('rust-toolchain.toml', 'Cargo.lock', "
            "'release/scripts/build-release-binaries.sh') }}",
        )
        self.assertIn("registry-stack-release-${{ runner.os }}-", cache["with"]["restore-keys"])
        self.assertIn('created_at} + 7 days', text)
        final_upload = next(
            step
            for step in document["jobs"]["assemble"]["steps"]
            if step.get("name") == "Upload one candidate manifest and bundle"
        )
        self.assertEqual(final_upload["with"]["retention-days"], 8)
        self.assertNotIn("Rehearse forced 1.x release-lock runtime contract", text)

    def test_only_pre_oidc_reverification_accepts_the_current_run(self) -> None:
        text, document = workflow("release-candidate.yml")
        reverify = step_run(
            document,
            "attest",
            "Reverify all bytes before requesting OIDC",
        )
        self.assertEqual(text.count("--allow-current-run-in-progress"), 1)
        self.assertIn("--allow-current-run-in-progress", reverify)

    def test_runs_each_candidate_image_before_it_scans_it(self) -> None:
        _, document = workflow("release-candidate.yml")
        scan = step_run(
            document,
            "assemble",
            "Verify and scan exact candidate images",
        )
        # Syft and Grype fill an image target's architecture and os only from
        # a daemon-backed provider, and check-advisory-baselines.py rejects
        # evidence that leaves them empty. Running the image is what puts it
        # in the daemon, so moving either scan ahead of it fails the gate with
        # a linux/amd64 message on an image that is amd64.
        run_image = scan.index('"${candidate_ref}" --version')
        self.assertIn("docker run --rm", scan[:run_image])
        self.assertLess(run_image, scan.index('syft "${candidate_ref}"'))
        self.assertLess(run_image, scan.index("scan_image \\"))


class PublicationWorkflowStructureTest(unittest.TestCase):
    def test_is_a_manual_main_workflow_with_recoverable_jobs(self) -> None:
        text, document = workflow("release.yml")
        self.assertIn("workflow_dispatch:", text.split("permissions:", 1)[0])
        self.assertNotIn("push:", text.split("permissions:", 1)[0])
        self.assertIn("${{ inputs.tag }}", text)
        self.assertIn('"${GITHUB_REF}" != refs/heads/main', text)
        self.assertEqual(
            list(document["jobs"]),
            [
                "verify",
                "stage-draft",
                "promote-images",
                "finalize-assets",
                "publish",
                "closeout-published",
                "publish_client_npm",
                "publish_client_pypi",
                "dispatch-docs",
            ],
        )
        self.assertEqual(
            document["jobs"]["promote-images"]["permissions"],
            {"actions": "read", "contents": "write", "packages": "write"},
        )

    def test_image_promotion_can_reread_the_bound_draft(self) -> None:
        _, document = workflow("release.yml")
        promote = document["jobs"]["promote-images"]
        self.assertEqual("write", promote["permissions"]["contents"])
        reconcile = step_run(
            document,
            "promote-images",
            "Reconcile exact staged draft before first public image write",
        )
        self.assertIn(
            'gh api "repos/${GITHUB_REPOSITORY}/releases/${release_id}"',
            reconcile,
        )

    def test_binds_an_annotated_tag_to_exact_candidate_and_main_revisions(self) -> None:
        text, document = workflow("release.yml")
        identity = next(
            step
            for step in document["jobs"]["verify"]["steps"]
            if step.get("name") == "Resolve exact tag identity"
        )
        self.assertEqual(identity["env"]["RELEASE_TAG"], "${{ inputs.tag }}")
        self.assertNotIn("${{ inputs.tag }}", identity["run"])
        self.assertIn('"${tag%%.*}" != v0', identity["run"])
        self.assertIn('git cat-file -t "refs/tags/${tag}"', text)
        self.assertIn("git merge-base --is-ancestor", text)
        self.assertIn("promotion_revision", text)
        self.assertIn("verify-tag-binding", text)
        self.assertIn("--trusted-run-metadata promotion/trusted-run.json", text)
        self.assertNotIn("select-canary", text)

    def test_client_registry_publication_begins_with_v0_21_1(self) -> None:
        _, document = workflow("release.yml")
        verify = step_run(
            document,
            "verify",
            "Verify binding, candidate, and attestations",
        )
        self.assertIn(
            "from release_candidate import CLIENT_REGISTRY_PACKAGE_MINIMUM_VERSION",
            verify,
        )
        self.assertIn(
            "version >= CLIENT_REGISTRY_PACKAGE_MINIMUM_VERSION",
            verify,
        )

    def test_checks_out_the_protected_workflow_before_running_repo_scripts(self) -> None:
        _, document = workflow("release.yml")
        for job_name, job in document["jobs"].items():
            script_indexes = [
                index
                for index, step in enumerate(job.get("steps", []))
                if "release/scripts/" in step.get("run", "")
            ]
            if not script_indexes:
                continue
            checkout_indexes = [
                index
                for index, step in enumerate(job["steps"])
                if step.get("uses", "").startswith("actions/checkout@")
            ]
            self.assertTrue(checkout_indexes, job_name)
            self.assertLess(min(checkout_indexes), min(script_indexes), job_name)

    def test_reconciles_only_absent_or_exact_public_image_tags(self) -> None:
        _, document = workflow("release.yml")
        promotion = step_run(
            document,
            "promote-images",
            "Reconcile exact image digests",
        )
        self.assertIn("reconcile-image-tag", promotion)
        self.assertIn('--expected-digest "${digest}"', promotion)
        self.assertIn('if [[ "${state}" == absent ]]', promotion)
        self.assertIn('crane copy "${candidate_ref}" "${final_ref}"', promotion)
        self.assertIn('test "$(crane digest "${final_ref}")" = "${digest}"', promotion)
        self.assertNotIn("require-image-tag-absent", promotion)

    def test_preserves_exact_draft_binding_without_overwriting_assets(self) -> None:
        text, document = workflow("release.yml")
        self.assertIn("Reconcile bound draft and upload exact staged inventory", text)
        self.assertIn("registry-stack-release-candidate-v2 manifest_sha256:", text)
        self.assertIn(".draft == true", text)
        self.assertIn(".prerelease == false", text)
        self.assertNotIn("--prerelease", text)
        self.assertNotIn("--clobber", text)
        tagged_checkout = next(
            step
            for step in document["jobs"]["stage-draft"]["steps"]
            if step.get("name") == "Checkout exact tagged product source"
        )
        self.assertEqual(
            tagged_checkout["with"]["ref"],
            "${{ needs.verify.outputs.source_sha }}",
        )
        stage = step_run(
            document,
            "stage-draft",
            "Reconcile bound draft and upload exact staged inventory",
        )
        self.assertIn(
            'cp "product-source/release/notes/${tag}.md"',
            stage,
        )

    def test_fresh_retry_closes_out_only_an_exact_published_release(self) -> None:
        _, document = workflow("release.yml")
        classify = step_run(
            document,
            "verify",
            "Classify absent, draft, or exact published release destination",
        )
        self.assertIn(".prerelease == false", classify)
        self.assertIn(".tag_name == $tag", classify)
        self.assertIn(".name == $title", classify)
        self.assertIn("contains($marker)", classify)
        self.assertIn(".draft == true and .published_at == null", classify)
        self.assertIn(".draft == false", classify)
        self.assertIn('state="$(jq -r', classify)
        self.assertEqual(
            document["jobs"]["stage-draft"]["if"],
            "needs.verify.outputs.destination_state != 'published'",
        )
        closeout = document["jobs"]["closeout-published"]
        self.assertEqual(
            closeout["if"],
            "needs.verify.outputs.destination_state == 'published'",
        )
        public_verify = step_run(
            document,
            "closeout-published",
            "Verify the minimum immutable public contract",
        )
        self.assertIn("registry-release verify-public", public_verify)
        self.assertIn(
            "needs.closeout-published.result == 'success'",
            document["jobs"]["dispatch-docs"]["if"],
        )

    def test_recovers_only_the_closed_final_asset_roster(self) -> None:
        _, document = workflow("release.yml")
        stage = step_run(
            document,
            "stage-draft",
            "Reconcile bound draft and upload exact staged inventory",
        )
        promote = step_run(
            document,
            "promote-images",
            "Reconcile exact staged draft before first public image write",
        )
        finalize = step_run(
            document,
            "finalize-assets",
            "Clean retryable final additions and reverify exact staged assets",
        )
        current_retryable_names = (
            "SHA256SUMS",
            '"registry-stack-${tag}-SHA256SUMS.sigstore.json"',
        )
        retryable_roster = stage[
            stage.index("printf '%s\\n'") : stage.index(
                "> contract/retryable-final-assets"
            )
        ]
        for name in current_retryable_names:
            self.assertIn(name, retryable_roster)
        self.assertNotIn("registryctl", retryable_roster)
        self.assertNotIn("minor < 19", retryable_roster)
        for name in current_retryable_names:
            self.assertNotIn(name, finalize)
        self.assertLess(
            stage.index('"${RUNNER_TEMP}/staged-draft.json" >/dev/null'),
            stage.index("> contract/retryable-final-assets"),
        )
        self.assertIn("cat contract/expected-staged-assets", stage)
        self.assertIn("cat contract/retryable-final-assets", stage)
        self.assertIn("contract/allowed-staged-assets", stage)
        self.assertIn("[[ -s contract/unexpected-staged-assets ]]", stage)
        self.assertLess(
            promote.index("contract/draft-release.json >/dev/null"),
            promote.index("comm -23"),
        )
        self.assertIn("contract/observed-assets", promote)
        self.assertIn("contract/retryable-final-assets", promote)
        self.assertIn("diff -u contract/expected-assets contract/actual-assets", promote)
        self.assertLess(
            finalize.index("require_bound_draft\n"),
            finalize.index("cat contract/retryable-final-assets"),
        )
        self.assertLess(
            finalize.index("require_bound_draft\n"),
            finalize.index("gh api --method DELETE"),
        )

    def test_rechecks_candidate_immediately_before_public_image_access(self) -> None:
        text, document = workflow("release.yml")
        expiry = text.index(
            "Recheck candidate expiry immediately before registry login"
        )
        login = text.index("Log in for exact candidate promotion", expiry)
        copy = text.index('crane copy "${candidate_ref}" "${final_ref}"', login)
        self.assertLess(expiry, login)
        self.assertLess(login, copy)
        expiry_run = step_run(
            document,
            "promote-images",
            "Recheck candidate expiry immediately before registry login",
        )
        self.assertIn(".validity.expires_at", expiry_run)
        self.assertNotIn("verify-candidate", expiry_run)

    def test_downloads_the_exact_promotion_artifact_to_its_consumed_path(self) -> None:
        _, document = workflow("release.yml")
        for job_name, step_name in (
            ("promote-images", "Download verified candidate and draft contract"),
            ("finalize-assets", "Download exact candidate and staged draft contract"),
        ):
            download = next(
                step
                for step in document["jobs"][job_name]["steps"]
                if step.get("name") == step_name
            )
            self.assertEqual(
                download["with"]["name"],
                "release-promotion-input-${{ github.run_id }}",
            )
            self.assertEqual(download["with"]["path"], "promotion")
            self.assertNotIn("pattern", download["with"])
        expiry = step_run(
            document,
            "promote-images",
            "Recheck candidate expiry immediately before registry login",
        )
        promote = step_run(
            document,
            "promote-images",
            "Reconcile exact image digests",
        )
        for run in (expiry, promote):
            self.assertIn(
                "manifest=promotion/release-candidate-manifest.json",
                run,
            )
            self.assertNotIn("inputs/release-promotion-input", run)

    def test_signs_one_checksum_closure_without_beta_only_ceremony(self) -> None:
        text, _ = workflow("release.yml")
        self.assertIn("SHA256SUMS.sigstore.json", text)
        self.assertIn("cosign sign-blob --yes", text)
        self.assertIn(
            ".github/workflows/release.yml@refs/heads/main",
            text,
        )
        self.assertNotIn("release-provenance", text)
        self.assertNotIn("slsa-framework/slsa-github-generator", text)
        self.assertNotIn("Generate signed 1.x lock", text)
        self.assertNotIn("registry-release-lock.v1.json", text)

    def test_dispatches_docs_for_current_release_candidates(self) -> None:
        text, document = workflow("release.yml")
        self.assertIn("Recheck complete signed release and exact public images", text)
        self.assertIn("Publish immutable release", text)
        self.assertIn("-F draft=false", text)
        self.assertIn("-F prerelease=false", text)
        self.assertNotIn("registry-docs-", text)
        verify = step_run(
            document,
            "verify",
            "Verify binding, candidate, and attestations",
        )
        self.assertNotIn("minor >= 16", verify)
        self.assertNotIn("minor < 19", verify)
        self.assertIn("major > 0", verify)
        self.assertIn("(minor == 19 && patch >= 1)", verify)
        self.assertIn(".docs.sha256", verify)
        self.assertIn("docs_sha256=${docs_sha256}", verify)
        self.assertEqual(
            document["jobs"]["verify"]["outputs"]["docs_sha256"],
            "${{ steps.candidate.outputs.docs_sha256 }}",
        )
        dispatch = document["jobs"]["dispatch-docs"]
        self.assertIn("needs.verify.outputs.docs_sha256 != ''", dispatch["if"])
        self.assertIn("needs.publish.result == 'success'", dispatch["if"])
        self.assertIn(
            "needs.closeout-published.result == 'success'", dispatch["if"]
        )
        self.assertEqual(
            dispatch["needs"], ["verify", "publish", "closeout-published"]
        )
        dispatch_run = step_run(
            document,
            "dispatch-docs",
            "Dispatch authenticated docs promotion",
        )
        self.assertIn('released_tag=${{ needs.verify.outputs.tag }}', dispatch_run)
        self.assertIn(
            'docs_sha256=${{ needs.verify.outputs.docs_sha256 }}',
            dispatch_run,
        )

    def test_promotes_exact_client_packages_with_oidc_and_retry_safety(self) -> None:
        text, document = workflow("release.yml")
        npm = document["jobs"]["publish_client_npm"]
        pypi = document["jobs"]["publish_client_pypi"]
        for job, environment in ((npm, "npm"),):
            self.assertEqual(job["environment"], environment)
            self.assertEqual(
                job["permissions"],
                {"actions": "read", "contents": "read", "id-token": "write"},
            )
            self.assertIn(
                "needs.verify.outputs.client_registries == 'true'", job["if"]
            )
            self.assertIn(
                "needs.verify.outputs.destination_state != 'published'", job["if"]
            )
            self.assertEqual(
                job["strategy"]["matrix"],
                "${{ fromJSON(needs.verify.outputs.client_registry_matrix) }}",
            )
        self.assertEqual(pypi["environment"], "${{ matrix.environment }}")
        self.assertEqual(
            pypi["strategy"]["matrix"],
            "${{ fromJSON(needs.verify.outputs.client_registry_pypi_matrix) }}",
        )
        self.assertEqual(
            pypi["permissions"],
            {"actions": "read", "contents": "read", "id-token": "write"},
        )
        self.assertIn(
            "needs.verify.outputs.client_registries == 'true'", pypi["if"]
        )
        self.assertIn(
            "needs.verify.outputs.destination_state != 'published'", pypi["if"]
        )
        candidate = step_run(
            document,
            "verify",
            "Verify binding, candidate, and attestations",
        )
        self.assertIn("DISCOVERY_CLIENT_PACKAGE_MINIMUM_VERSION", candidate)
        self.assertIn("client_registry_matrix=", candidate)
        self.assertIn("client_registry_pypi_matrix=", candidate)
        self.assertEqual(npm["needs"], ["verify", "finalize-assets"])
        self.assertEqual(pypi["needs"], ["verify", "finalize-assets"])
        publish = document["jobs"]["publish"]
        self.assertIn("publish_client_npm", publish["needs"])
        self.assertIn("publish_client_pypi", publish["needs"])
        self.assertIn("needs.publish_client_npm.result == 'success'", publish["if"])
        self.assertIn("needs.publish_client_pypi.result == 'success'", publish["if"])
        npm_publish = step_run(
            document,
            "publish_client_npm",
            "Reconcile platform packages, then publish the root package",
        )
        self.assertIn("client_registry.py npm-state", npm_publish)
        self.assertIn('npm publish "./${tarball}"', npm_publish)
        self.assertNotIn('npm publish "${tarball}"', npm_publish)
        self.assertIn("require_unexpired_candidate", npm_publish)
        self.assertLess(
            npm_publish.rindex("require_unexpired_candidate"),
            npm_publish.index("npm publish"),
        )
        self.assertLess(
            npm_publish.index("registrystack-${client}-client-linux-x64-gnu"),
            npm_publish.index('"registrystack-${client}-client-${version}.tgz"'),
        )
        pypi_publish = next(
            step
            for step in pypi["steps"]
            if step.get("uses", "").startswith("pypa/gh-action-pypi-publish@")
        )
        self.assertEqual(pypi_publish["with"]["packages-dir"], "dist")
        self.assertTrue(pypi_publish["with"]["skip-existing"])
        pypi_expiry_index = next(
            index
            for index, step in enumerate(pypi["steps"])
            if step.get("name")
            == "Recheck candidate expiry immediately before PyPI publication"
        )
        pypi_publish_index = pypi["steps"].index(pypi_publish)
        self.assertEqual(pypi_expiry_index + 1, pypi_publish_index)
        immediate_pypi_expiry = pypi["steps"][pypi_expiry_index]["run"]
        self.assertIn(".validity.expires_at", immediate_pypi_expiry)
        self.assertIn("now_epoch >= expires_epoch", immediate_pypi_expiry)
        for job_name in ("publish_client_npm", "publish_client_pypi"):
            expiry = step_run(
                document,
                job_name,
                "Recheck candidate expiry after environment approval",
            )
            self.assertIn(".validity.expires_at", expiry)
            self.assertIn("now_epoch >= expires_epoch", expiry)
        self.assertNotIn("NODE_AUTH_TOKEN", text)
        self.assertNotIn("PYPI_TOKEN", text)


class SupportingWorkflowStructureTest(unittest.TestCase):
    def test_operator_docs_match_the_latest_non_prerelease_contract(self) -> None:
        operations = (ROOT / "release/OPERATIONS.md").read_text(encoding="utf-8")
        verify = (ROOT / "release/VERIFY.md").read_text(encoding="utf-8")
        self.assertIn("public, non-prerelease", operations)
        self.assertIn("GitHub Release", operations)
        self.assertNotIn("marked as a prerelease", operations)
        self.assertIn(".isPrerelease == false", verify)
        self.assertNotIn(".isPrerelease == true", verify)

    def test_advisory_renewal_pulls_the_candidate_before_scanning_it(self) -> None:
        operations = (ROOT / "release/OPERATIONS.md").read_text(encoding="utf-8")
        renewal = next(
            block
            for block in operations.split("```")
            if 'syft "${candidate_ref}"' in block
        )
        # The renewal commands are run by hand, so they carry the daemon-backed
        # pull the candidate workflow gets incidentally from running the image.
        # Without it Syft and Grype leave the target's architecture and os
        # empty and check-advisory-baselines.py rejects the evidence as not
        # linux/amd64.
        pull = renewal.index('docker pull --platform linux/amd64 "${candidate_ref}"')
        self.assertLess(pull, renewal.index('syft "${candidate_ref}"'))
        self.assertLess(pull, renewal.index('grype "${candidate_ref}"'))

    def test_docs_deploys_main_and_rechecks_latest_docs_release(self) -> None:
        text, document = workflow("docs-pages.yml")
        releases_endpoint = '"repos/${GITHUB_REPOSITORY}/releases?per_page=100"'
        helper = "release/scripts/verify_latest_published_release.py"
        self.assertEqual(text.count(releases_endpoint), 2)
        self.assertEqual(text.count(f"python3 {helper}"), 2)
        trigger = text.split("permissions:", 1)[0]
        self.assertIn("push:", trigger)
        self.assertIn("- main", trigger)
        self.assertIn("required: false", trigger)
        self.assertIn("ref: ${{ github.sha }}", text)
        self.assertIn(".prerelease==false", text)
        self.assertIn(
            ".github/workflows/release.yml@refs/heads/main",
            text,
        )
        cosign = next(
            step
            for step in document["jobs"]["build"]["steps"]
            if step.get("name") == "Install cosign"
        )
        self.assertEqual(cosign["with"]["cosign-release"], "v3.0.6")
        deploy_steps = document["jobs"]["deploy"]["steps"]
        recheck = next(
            index
            for index, step in enumerate(deploy_steps)
            if step.get("name")
            == "Recheck latest published docs release immediately before deployment"
        )
        deployment = next(
            index
            for index, step in enumerate(deploy_steps)
            if step.get("name") == "Deploy to GitHub Pages"
        )
        self.assertEqual(recheck + 1, deployment)
        self.assertEqual(deploy_steps[deployment]["with"]["timeout"], 600_000)

    def test_latest_docs_release_fixture_rejects_stale_or_nonpublished_dispatches(
        self,
    ) -> None:
        digest = "a" * 64
        release = {
            "tag_name": "v1.4.0",
            "draft": False,
            "prerelease": False,
            "published_at": "2026-07-29T10:00:00Z",
            "assets": [
                {
                    "name": "registry-docs-v1.4.0.tar.gz",
                    "digest": f"sha256:{digest}",
                },
                {"name": "SHA256SUMS"},
                {"name": "registry-stack-v1.4.0-SHA256SUMS.sigstore.json"},
            ],
        }
        self.assertEqual(
            verify_latest_release_fixture([release], "v1.4.0", digest).returncode,
            0,
        )
        no_docs = {
            **release,
            "tag_name": "v1.5.0",
            "assets": [],
        }
        self.assertEqual(
            verify_latest_release_fixture(
                [release, no_docs], "v1.4.0", digest
            ).returncode,
            0,
        )
        stale = verify_latest_release_fixture([release], "v1.3.0", digest)
        self.assertNotEqual(stale.returncode, 0)
        self.assertIn("is stale", stale.stderr)
        mismatched_digest = verify_latest_release_fixture(
            [release], "v1.4.0", "b" * 64
        )
        self.assertNotEqual(mismatched_digest.returncode, 0)
        self.assertIn("does not match", mismatched_digest.stderr)
        incomplete = {
            **release,
            "assets": release["assets"][:-1],
        }
        missing_signature = verify_latest_release_fixture(
            [incomplete], "v1.4.0", digest
        )
        self.assertNotEqual(missing_signature.returncode, 0)
        self.assertIn("must carry exactly one", missing_signature.stderr)
        duplicated = {
            **release,
            "assets": [*release["assets"], release["assets"][0]],
        }
        duplicate_docs = verify_latest_release_fixture(
            [duplicated], "v1.4.0", digest
        )
        self.assertNotEqual(duplicate_docs.returncode, 0)
        self.assertIn("must carry exactly one", duplicate_docs.stderr)
        for field in ("draft", "prerelease"):
            with self.subTest(field=field):
                invalid = dict(release)
                invalid[field] = True
                result = verify_latest_release_fixture(
                    [invalid], "v1.4.0", digest
                )
                self.assertNotEqual(result.returncode, 0)

    def test_canary_is_async_and_has_no_public_write_permission(self) -> None:
        text, document = workflow("release-canary.yml")
        trigger = text.split("permissions:", 1)[0]
        self.assertIn("schedule:", trigger)
        self.assertIn("workflow_dispatch:", trigger)
        for job in document["jobs"].values():
            permissions = job.get("permissions", {})
            self.assertNotEqual(permissions.get("contents"), "write")
            self.assertNotEqual(permissions.get("packages"), "write")
        self.assertIn("registry-docs-", text)
        self.assertIn("docs: {", text)
        self.assertNotIn("docs-dispatch", text)

    def test_scorecard_is_schedule_or_manual_only(self) -> None:
        text, _ = workflow("scorecard.yml")
        trigger = text.split("permissions:", 1)[0]
        self.assertIn("schedule:", trigger)
        self.assertIn("workflow_dispatch:", trigger)
        self.assertNotIn("push:", trigger)
        self.assertNotIn("pull_request:", trigger)


if __name__ == "__main__":
    unittest.main()
