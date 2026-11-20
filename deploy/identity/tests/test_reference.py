#!/usr/bin/env python3
"""Contract tests for the ThunderID K3s reference integration."""

from __future__ import annotations

import json
import os
import pathlib
import shutil
import subprocess
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]


class ReferenceIdentityContract(unittest.TestCase):
    def test_release_pin_matches_the_chart_lock(self) -> None:
        lock = json.loads((ROOT / "chart-lock.json").read_text())
        self.assertEqual(lock["chart"]["version"], "1.0.1")
        self.assertEqual(
            lock["chart"]["digest"],
            "sha256:f54599dc3715fe054576c4a8351b7346f153205d17f6b553f82fab11c4536218",
        )
        self.assertEqual(
            lock["image"]["digest"],
            "sha256:d3c0613ff447a551fd440768a15bdfb6668948e80809cbb50f82d6752f22ab3e",
        )
        self.assertEqual(
            lock["source"]["commit"], "12f517c4384004e360e26eb7eb1ab0501b678bb2"
        )

    def test_reference_values_use_existing_secrets_and_durable_state(self) -> None:
        values = (ROOT / "values.reference.yaml").read_text()
        self.assertIn("digest: sha256:d3c0613f", values)
        self.assertIn("sslmode: verify-full", values)
        self.assertEqual(values.count("name: registry-identity-postgres"), 4)
        self.assertNotIn("password: ", values)
        self.assertIn("name: registry-identity-admin", values)
        self.assertIn("secretName: registry-identity-fixture-credentials", values)
        self.assertIn("size: 16Mi", values)
        self.assertIn("storageClass: local-path", values)

    def test_database_tls_verifies_the_postgres_identity(self) -> None:
        values = (ROOT / "values.reference.yaml").read_text()
        self.assertEqual(values.count("sslmode: verify-full"), 4)
        self.assertIn("name: PGSSLROOTCERT", values)
        self.assertIn("/opt/thunderid/config/resources/postgres-ca.pem", values)
        self.assertIn("name: registry-identity-material", values)
        self.assertNotIn("sslmode: require", values)
        self.assertNotIn("sslmode: disable", values)

    def test_runbook_requires_a_ca_signed_end_entity_issuer_certificate(self) -> None:
        runbook = (ROOT / "README.md").read_text()
        self.assertIn("CA:FALSE", runbook)
        self.assertIn("serverAuth", runbook)
        self.assertIn("pure CA certificate", runbook)
        self.assertIn("qualification-root-ca.pem", runbook)

    def test_runbook_rejects_line_terminated_secret_files(self) -> None:
        runbook = (ROOT / "README.md").read_text()
        self.assertIn("must not contain a trailing newline", runbook)
        self.assertIn("HTML password input", runbook)

    def test_browser_fixture_is_exact_and_synthetic(self) -> None:
        deployment = (ROOT / "identity-deployment.yaml").read_text()
        self.assertIn("id: app-kit", deployment)
        self.assertIn(
            "https://app.registry-qualification.test/auth/callback", deployment
        )
        self.assertIn("secret:env/APP_KIT_CLIENT_SECRET", deployment)
        self.assertIn("id: qualification-officer", deployment)
        self.assertIn("secret:env/QUALIFICATION_OFFICER_PASSWORD", deployment)
        self.assertIn("accessProfiles: [directory-editor]", deployment)
        self.assertIn("registry_purpose: directory-administration", deployment)
        self.assertIn("jurisdiction: zone-a", deployment)
        for attribute in (
            "registry_principal",
            "registry_purpose",
            "registry_actor_kind",
            "jurisdiction",
        ):
            self.assertIn(f"- {attribute}", deployment)
        self.assertNotIn("password:", deployment)

        augmentation = (ROOT / "augment-app-kit-resources.mjs").read_text()
        self.assertIn("registry_role", augmentation)
        self.assertIn("contact-editor", augmentation)
        self.assertIn("registry_scopes", augmentation)
        self.assertIn("registry:directory:write", augmentation)
        self.assertIn("expected exactly", augmentation)

    def test_browser_driver_pins_private_tls_and_checks_access_boundary(self) -> None:
        driver = (ROOT / "browser-login.mjs").read_text()
        self.assertIn("APPKIT_EXPECTED_ISSUER", driver)
        self.assertIn("APPKIT_TLS_SPKI", driver)
        self.assertIn("--ignore-certificate-errors-spki-list=", driver)
        self.assertIn("APPKIT_PROXY_SERVER", driver)
        self.assertIn("APPKIT_HOST_RESOLVER_RULES", driver)
        self.assertIn('fetch("/api/model")', driver)
        self.assertIn("anonymousModelStatus !== 401", driver)
        self.assertIn("authenticatedModelStatus !== 200", driver)
        self.assertIn("session.authenticated !== true", driver)
        self.assertIn("session.role !== expectedRole", driver)
        self.assertNotIn("App Kit session has no display name", driver)
        self.assertIn("OIDC sign-in did not complete the App Kit callback", driver)
        self.assertNotIn("page.url()", driver)
        self.assertNotIn('locator("body")', driver)
        self.assertNotIn("{ cause: error }", driver)

    def test_browser_driver_can_prove_restored_records_and_row_boundary(self) -> None:
        driver = (ROOT / "browser-login.mjs").read_text()
        self.assertIn("APPKIT_RETAINED_RECORD_IDS", driver)
        self.assertIn("/api/entities/contact/records/", driver)
        self.assertIn('fetch("/api/entities/contact/records")', driver)
        self.assertIn('fetch("/api/tasks"', driver)
        self.assertIn('send("zone-a"', driver)
        self.assertIn('send("zone-b"', driver)
        self.assertIn("journey.deniedStatus !== 403", driver)
        self.assertIn("cross-jurisdiction write denied with 403", driver)
        self.assertNotIn("response.text()", driver)

    def test_default_bootstrap_precedes_declarative_resources(self) -> None:
        values = (ROOT / "values.bootstrap-defaults.yaml").read_text()
        self.assertIn("enabled: false", values)
        self.assertIn("application: mutable", values)
        self.assertIn("resource: mutable", values)
        self.assertIn("name: registry-identity-postgres-ca", values)
        runbook = (ROOT / "README.md").read_text()
        install = runbook[runbook.index("helm install thunderid") :]
        self.assertIn(
            "--values deploy/identity/values.bootstrap-defaults.yaml", install
        )

    def test_restored_state_never_reruns_setup(self) -> None:
        create = (ROOT / "values.restore-create.yaml").read_text()
        serving = (ROOT / "values.restored-state.yaml").read_text()
        self.assertIn("replicaCount: 0", create)
        self.assertIn("enabled: false", create)
        self.assertIn("enabled: false", serving)
        self.assertIn("restoreExistingState: true", create)
        self.assertIn("restoreExistingState: true", serving)
        self.assertNotIn("replicaCount", serving)
        runbook = (ROOT / "README.md").read_text()
        self.assertIn("Keep `setup.sh` and the fresh schema Job disabled", runbook)
        self.assertIn("against restored state", runbook)
        self.assertIn("prepare-restored-state-chart.sh", runbook)
        self.assertIn("values.restore-create.yaml", runbook)
        self.assertIn("values.restored-state.yaml", runbook)

    def test_restored_state_chart_mounts_claims_without_setup_job(self) -> None:
        preparer = (ROOT / "prepare-restored-state-chart.sh").read_text()
        self.assertIn("set -euo pipefail", preparer)
        self.assertIn("restoreExistingState", preparer)
        self.assertIn("expected exactly three setup-gated state mounts", preparer)
        self.assertIn("setup Job condition changed unexpectedly", preparer)
        self.assertNotIn("rm ", preparer)

    def test_material_preparation_uses_augmented_app_kit_resources(self) -> None:
        preparer = (ROOT / "prepare-material.sh").read_text()
        self.assertIn("resources.app-kit.yaml", preparer)
        self.assertIn('--from-file="resources=', preparer)
        self.assertNotIn("rg ", preparer)

    def test_runbook_names_external_postgres_schema_prerequisite(self) -> None:
        runbook = (ROOT / "README.md").read_text()
        for database in (
            "configdb",
            "runtime_transient",
            "entitydb",
            "runtime_persistent",
        ):
            self.assertIn(f"backend/dbscripts/{database}/postgres.sql", runbook)
        self.assertIn("12f517c4384004e360e26eb7eb1ab0501b678bb2", runbook)

    def test_schema_one_shot_uses_upstream_setup_bundle_while_non_serving(self) -> None:
        job = (ROOT / "schema-bootstrap-job.yaml").read_text()
        self.assertIn('registry.stack/bootstrap-requires-serving-replicas: "0"', job)
        self.assertIn("@sha256:d3c0613f", job)
        self.assertIn('command: ["./setup.sh"]', job)
        self.assertIn("initContainers:", job)
        self.assertIn("wait-for-postgres", job)
        self.assertIn("/dev/tcp/registry-postgres.directory.svc.cluster.local/5432", job)
        self.assertIn("/opt/thunderid/bootstrap/70-registry-agent-type.yaml", job)
        self.assertIn("/opt/thunderid/bootstrap/80-registry-agent.yaml", job)
        self.assertIn("subPath: agent.yaml", job)
        self.assertNotRegex(job, r"subPath: [0-9a-f]{8}-[0-9a-f-]{27}")
        self.assertNotIn("bootstrap --defaults", job)
        self.assertIn("secretKeyRef:", job)
        self.assertNotIn("value: registry-identity", job)

    def test_chart_preparer_verifies_upstream_before_narrow_patch(self) -> None:
        preparer = (ROOT / "prepare-restricted-chart.sh").read_text()
        self.assertIn("set -euo pipefail", preparer)
        self.assertIn("f6fd424047932405d3d8f50d6ef69798f10626563828c1d1bed186efba99dc4d", preparer)
        self.assertIn("expected exactly two lowercase capability entries", preparer)
        self.assertIn("- ALL", preparer)
        self.assertNotIn("rm ", preparer)
        self.assertNotIn("rg ", preparer)

    def test_qualification_script_never_prints_bearer_or_password(self) -> None:
        script = (ROOT / "qualify-oidc.sh").read_text()
        driver = (ROOT / "qualify-oidc.mjs").read_text()
        self.assertIn("set -euo pipefail", script)
        self.assertIn("oauth2/token", driver)
        self.assertIn(".well-known/openid-configuration", driver)
        self.assertIn("IDENTITY_CONNECT_ADDRESS", driver)
        self.assertIn("IDENTITY_CONNECT_PORT", driver)
        self.assertIn("options.lookup", driver)
        self.assertIn('createHash("sha256")', driver)
        self.assertIn("signing JWK thumbprint=", driver)
        self.assertNotIn("set -x", script)
        self.assertNotIn("echo $", script)
        self.assertNotIn("console.log(accessToken", driver)

    def test_public_files_name_no_lab_infrastructure(self) -> None:
        banned = ("registry-k3s-proof", "beta-58", "OrbStack", "private lab", "App Kit v0.44")
        for path in ROOT.iterdir():
            if path.is_file():
                text = path.read_text()
                for name in banned:
                    self.assertNotIn(name, text, f"{name} appears in {path.name}")

    def test_runbook_uses_the_main_guide_commands(self) -> None:
        runbook = (ROOT / "README.md").read_text()
        self.assertIn("sudo k3s kubectl", runbook)
        self.assertIn("/usr/local/lib/registry-stack/helm", runbook)
        self.assertIn("KUBECONFIG=/etc/rancher/k3s/k3s.yaml", runbook)
        for line in runbook.splitlines():
            self.assertFalse(line.startswith("helm "), line)
            self.assertFalse(line.startswith("sudo -n k3s"), line)

    def test_runbook_says_what_to_remove_before_a_pilot(self) -> None:
        runbook = (ROOT / "README.md").read_text()
        self.assertIn("Before a pilot", runbook)
        self.assertIn("qualification-officer", runbook[runbook.index("Before a pilot") :])
        self.assertIn("QUALIFICATION_OFFICER_PASSWORD", runbook[runbook.index("Before a pilot") :])

    def test_network_policy_admits_only_the_ingress_controller(self) -> None:
        # Registry Stack Pods reach ThunderID through its HTTPS origin at the
        # ingress, and the chart does not label Pods with part-of, so a rule
        # for them would match nothing.
        policy = (ROOT / "network-policy.yaml").read_text()
        self.assertIn("kind: NetworkPolicy", policy)
        self.assertIn("namespace: registry-identity-qualification", policy)
        self.assertIn("policyTypes:\n    - Ingress", policy)
        self.assertIn("kubernetes.io/metadata.name: kube-system", policy)
        self.assertIn("app.kubernetes.io/name: traefik", policy)
        self.assertEqual(policy.count("namespaceSelector:"), 1)
        self.assertEqual(policy.count("podSelector:"), 2)
        self.assertNotIn("part-of", policy)
        self.assertEqual(policy.count("port: 8090"), 1)
        self.assertNotIn("ipBlock", policy)
        runbook = (ROOT / "README.md").read_text()
        self.assertIn("deploy/identity/network-policy.yaml", runbook)
        self.assertNotIn("Registry Stack Pods in\nthe `directory` namespace", runbook)

    def test_postgres_network_policy_admits_only_the_identity_namespace(self) -> None:
        policy = (ROOT / "postgres-network-policy.yaml").read_text()
        self.assertIn("kind: NetworkPolicy", policy)
        self.assertIn("namespace: directory", policy)
        self.assertIn("app.kubernetes.io/name: registry-postgres", policy)
        self.assertIn("policyTypes:\n    - Ingress", policy)
        self.assertIn("kubernetes.io/metadata.name: registry-identity-qualification", policy)
        self.assertEqual(policy.count("port: 5432"), 1)
        self.assertNotIn("ipBlock", policy)
        runbook = (ROOT / "README.md").read_text()
        self.assertEqual(runbook.count("deploy/identity/postgres-network-policy.yaml"), 2)

    def test_dead_post_renderer_is_not_referenced(self) -> None:
        for path in ROOT.iterdir():
            if path.is_file() and path.suffix in {".md", ".py", ".sh", ".yaml"}:
                self.assertNotIn("post-render-restricted", path.read_text())


class PreparerScripts(unittest.TestCase):
    def setUp(self) -> None:
        self.scratch = pathlib.Path(tempfile.mkdtemp(prefix="identity-prep-"))
        self.addCleanup(shutil.rmtree, self.scratch, ignore_errors=True)
        self.bin = self.scratch / "bin"
        self.bin.mkdir()
        self.log = self.scratch / "kubectl.log"
        fake = self.bin / "kubectl"
        fake.write_text(
            '#!/usr/bin/env bash\nprintf \'%s\\n\' "$*" >>"$FAKE_KUBECTL_LOG"\n'
            "printf 'kind: Fake\\n'\n"
        )
        fake.chmod(0o755)

    def run_script(self, name, *args, path=None):
        env = {
            "PATH": path or f"{self.bin}:/usr/bin:/bin",
            "FAKE_KUBECTL_LOG": str(self.log),
        }
        return subprocess.run(
            [shutil.which("bash"), str(ROOT / name), *map(str, args)],
            env=env,
            capture_output=True,
            text=True,
        )

    def generated(self, agents=1):
        root = self.scratch / "generated"
        (root / "resources").mkdir(parents=True)
        (root / "registry-schema" / "agents").mkdir(parents=True)
        (root / "identity-receipt.json").write_text("{}")
        (root / "resources" / "resources.app-kit.yaml").write_text("a: b\n")
        (root / "registry-schema" / "agent-type.yaml").write_text("a: b\n")
        for number in range(agents):
            (root / "registry-schema" / "agents" / f"0000000{number}-agent.yaml").write_text("a: b\n")
        ca = self.scratch / "ca.pem"
        ca.write_text("ca")
        return root, ca

    def test_material_is_prepared_with_fixed_agent_key_and_ca_configmap(self) -> None:
        root, ca = self.generated()
        out = self.scratch / "out"
        result = self.run_script("prepare-material.sh", root, ca, out)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            sorted(p.name for p in out.iterdir()),
            ["agent-type.yaml", "agents.yaml", "material.yaml", "postgres-ca.yaml"],
        )
        calls = self.log.read_text()
        self.assertIn("create configmap registry-identity-postgres-ca", calls)
        self.assertIn("--from-file=agent.yaml=", calls)
        self.assertEqual([p.name for p in self.scratch.glob("out.partial.*")], [])

    def test_material_failure_leaves_no_output_that_blocks_a_rerun(self) -> None:
        root, ca = self.generated(agents=2)
        out = self.scratch / "out"
        result = self.run_script("prepare-material.sh", root, ca, out)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("exactly one agent", result.stderr)
        self.assertFalse(out.exists())
        (root / "registry-schema" / "agents" / "00000001-agent.yaml").unlink()
        rerun = self.run_script("prepare-material.sh", root, ca, out)
        self.assertEqual(rerun.returncode, 0, rerun.stderr)
        self.assertTrue(out.is_dir())

    def fake_chart(self, gates=3):
        chart = self.scratch / "chart"
        (chart / "templates").mkdir(parents=True, exist_ok=True)
        (chart / "Chart.yaml").write_text("name: thunderid\n")
        gate = "{{- if .Values.setup.enabled }}\n"
        (chart / "templates" / "thunderid-deployment.yaml").write_text(gate * 2)
        (chart / "templates" / "pvc.yaml").write_text(gate * (gates - 2))
        (chart / "templates" / "setup-job.yaml").write_text(gate)
        return chart

    def test_restored_state_chart_is_moved_into_place_only_on_success(self) -> None:
        chart = self.fake_chart(gates=2)
        out = self.scratch / "restored"
        failed = self.run_script("prepare-restored-state-chart.sh", chart, out)
        self.assertNotEqual(failed.returncode, 0)
        self.assertIn("expected exactly three", failed.stderr)
        self.assertFalse(out.exists())
        chart = self.fake_chart(gates=3)
        ok = self.run_script("prepare-restored-state-chart.sh", chart, out)
        self.assertEqual(ok.returncode, 0, ok.stderr)
        self.assertIn(
            "restoreExistingState",
            (out / "templates" / "pvc.yaml").read_text(),
        )

    def test_missing_grep_is_reported_as_a_missing_tool(self) -> None:
        chart = self.fake_chart()
        tools = self.scratch / "tools"
        tools.mkdir()
        for tool in ("mktemp", "cp", "mv", "perl", "wc", "tr", "dirname", "chmod"):
            (tools / tool).symlink_to(shutil.which(tool))
        result = self.run_script(
            "prepare-restored-state-chart.sh", chart, self.scratch / "x", path=str(tools)
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("grep is required", result.stderr)

    def test_grep_failure_while_checking_the_setup_job_stops_the_preparer(self) -> None:
        chart = self.fake_chart()
        grep = self.bin / "grep"
        grep.write_text(
            "#!/usr/bin/env bash\n"
            'if [[ "$1" == "-c" && "${*: -1}" == *setup-job.yaml ]]; then exit 2; fi\n'
            f'exec {shutil.which("grep")} "$@"\n'
        )
        grep.chmod(0o755)
        out = self.scratch / "restored"
        result = self.run_script("prepare-restored-state-chart.sh", chart, out)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("grep failed on", result.stderr)
        self.assertFalse(out.exists())


if __name__ == "__main__":
    unittest.main()
