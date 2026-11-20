"""Structured contract tests for the Registry Stack Helm chart.

Each test renders the chart with Helm, converts the manifests to JSON with
mikefarah yq v4, and asserts on individual workloads. Run through
chart-contract.sh, which passes HELM_BIN and checks that both tools exist.
"""

import json
import os
import shutil
import subprocess
import unittest
from pathlib import Path

CHART = Path(__file__).resolve().parent.parent
FIXTURE = CHART / "tests" / "fixtures" / "complete.yaml"
EXTENSIONS = CHART / "tests" / "fixtures" / "extensions.yaml"
NAMESPACE = "registry-pilot"
RELEASE = "pilot"

DIGEST_A = "sha256:" + "a" * 64
NO_SERVE = [
    "--set", "breg.serve=false",
    "--set", "appKit.serve=false",
    "--set", "casework.serve=false",
    "--set", "evidence.serve=false",
]
BREG_JOB = "templates/breg-operation-job.yaml"
CASEWORK_JOB = "templates/casework-operation-job.yaml"
EVIDENCE_JOB = "templates/evidence-operation-job.yaml"

HELM = ""
YQ = ""


def setUpModule():
    """Fail loudly when a required tool is missing."""
    global HELM, YQ
    helm = os.environ.get("HELM_BIN", "helm")
    yq = os.environ.get("YQ_BIN", "yq")
    resolved_helm = shutil.which(helm)
    resolved_yq = shutil.which(yq)
    if resolved_helm is None:
        raise RuntimeError(f"helm not found ({helm}). Set HELM_BIN to a Helm 4 binary.")
    if resolved_yq is None:
        raise RuntimeError(f"yq not found ({yq}). Install mikefarah yq v4.")
    version = subprocess.run(
        [resolved_yq, "--version"], capture_output=True, text=True, check=True
    ).stdout
    if "mikefarah" not in version:
        raise RuntimeError(f"{resolved_yq} is not mikefarah yq v4: {version.strip()}")
    HELM, YQ = resolved_helm, resolved_yq


def run(command, **kwargs):
    return subprocess.run(command, capture_output=True, text=True, **kwargs)


def helm_template(args, show_only=None, values=(FIXTURE,), release=RELEASE, namespace=NAMESPACE):
    command = [HELM, "template", release, str(CHART), "--namespace", namespace]
    for path in values:
        command += ["--values", str(path)]
    command += list(args)
    if show_only:
        command += ["--show-only", show_only]
    return run(command)


def render(args=(), show_only=None, **kwargs):
    """Render the chart and return its manifests as a list of dicts."""
    result = helm_template(args, show_only, **kwargs)
    if result.returncode != 0:
        raise AssertionError(f"helm template failed:\n{result.stderr}")
    converted = run([YQ, "-o=json", "-I=0", "."], input=result.stdout)
    if converted.returncode != 0:
        raise AssertionError(f"yq failed:\n{converted.stderr}")
    docs = [json.loads(line) for line in converted.stdout.splitlines() if line.strip()]
    return [doc for doc in docs if doc is not None]


def operation(product, name, kind, *extra):
    return [
        "--set", f"{product}.operation.enabled=true",
        "--set-string", f"{product}.operation.name={name}",
        "--set-string", f"{product}.operation.kind={kind}",
        *extra,
    ]


def render_operation(show_only, product, name, kind, *extra):
    return render(NO_SERVE + operation(product, name, kind, *extra), show_only)


def of_kind(docs, kind):
    return [doc for doc in docs if doc["kind"] == kind]


def named(docs, kind, name):
    matches = [doc for doc in of_kind(docs, kind) if doc["metadata"]["name"] == name]
    if len(matches) != 1:
        raise AssertionError(f"expected one {kind} named {name}, found {len(matches)}")
    return matches[0]


def pod_spec(workload):
    return workload["spec"]["template"]["spec"]


def pod_labels(workload):
    return workload["spec"]["template"]["metadata"]["labels"]


def containers(workload):
    return pod_spec(workload)["containers"]


def init_containers(workload):
    return pod_spec(workload).get("initContainers", [])


def container(workload, name):
    matches = [c for c in containers(workload) if c["name"] == name]
    if len(matches) != 1:
        raise AssertionError(f"expected one container {name}")
    return matches[0]


def volumes(workload):
    return {v["name"]: v for v in pod_spec(workload)["volumes"]}


def mounts(c):
    return {m["name"]: m for m in c.get("volumeMounts", [])}


def writable(c):
    return {m["name"] for m in c.get("volumeMounts", []) if not m.get("readOnly", False)}


def env(c):
    return {e["name"]: e.get("value") for e in c.get("env", [])}


def claims(workload):
    return {
        v["name"]: v["persistentVolumeClaim"]["claimName"]
        for v in pod_spec(workload)["volumes"]
        if "persistentVolumeClaim" in v
    }


def secret_names(workload):
    return {
        v["secret"]["secretName"] for v in pod_spec(workload)["volumes"] if "secret" in v
    }


def find_keys(value, key):
    """Yield every value stored under `key` anywhere in a JSON structure."""
    if isinstance(value, dict):
        for k, v in value.items():
            if k == key:
                yield v
            yield from find_keys(v, key)
    elif isinstance(value, list):
        for item in value:
            yield from find_keys(item, key)


def workloads(docs):
    return of_kind(docs, "Deployment") + of_kind(docs, "Job")


# yq reads the rendered octal literal 0444 as the decimal number 444.
class Invariants:
    """Per-workload security assertions shared by every render."""

    # Writable mounts a workload may declare, by volume name.
    STAGING = {
        "runtime-private", "secret-private", "config-private",
        "compiled-authority-private", "proxy-config-private", "proxy-secret-private",
    }
    READ_ONLY_CLAIMS = {"package", "candidate", "bundle", "runtime-inputs"}

    def check(self, test, docs, label):
        for workload in workloads(docs):
            name = f"{label}: {workload['metadata']['name']}"
            self.pod(test, workload, name)
            self.volumes(test, workload, name)
            self.writes(test, workload, name)
        for policy in of_kind(docs, "NetworkPolicy"):
            self.policy(test, policy, docs, f"{label}: {policy['metadata']['name']}")
        for kind in ("Secret", "PersistentVolumeClaim", "ServiceAccount"):
            test.assertEqual(of_kind(docs, kind), [], f"{label}: chart must not render {kind}")
        test.assertEqual([], list(find_keys(docs, "fsGroup")), f"{label}: fsGroup is set")
        for annotations in find_keys(docs, "annotations"):
            test.assertFalse(
                [k for k in annotations if k.startswith("helm.sh/hook")],
                f"{label}: helm hook annotation",
            )

    def pod(self, test, workload, name):
        spec = pod_spec(workload)
        test.assertIs(spec.get("automountServiceAccountToken"), False, f"{name}: service-account token")
        for flag in ("hostNetwork", "hostPID", "hostIPC"):
            test.assertFalse(spec.get(flag), f"{name}: {flag}")
        context = spec.get("securityContext", {})
        test.assertIs(context.get("runAsNonRoot"), True, f"{name}: pod runAsNonRoot")
        if "runAsUser" in context:
            test.assertGreaterEqual(context["runAsUser"], 1, f"{name}: pod runAsUser")
        test.assertEqual(
            context.get("seccompProfile"), {"type": "RuntimeDefault"}, f"{name}: seccomp"
        )
        for c in containers(workload) + init_containers(workload):
            cname = f"{name}/{c['name']}"
            sc = c.get("securityContext", {})
            test.assertIs(sc.get("allowPrivilegeEscalation"), False, f"{cname}: privilege escalation")
            test.assertEqual(sc.get("capabilities", {}).get("drop"), ["ALL"], f"{cname}: capabilities")
            test.assertIs(sc.get("readOnlyRootFilesystem"), True, f"{cname}: read-only root")
            test.assertIs(sc.get("runAsNonRoot"), True, f"{cname}: runAsNonRoot")
            test.assertGreaterEqual(sc.get("runAsUser", 0), 1, f"{cname}: runAsUser")
            test.assertNotIn("privileged", sc, f"{cname}: privileged")
            test.assertRegex(c["image"], r"@sha256:[0-9a-f]{64}$", f"{cname}: image digest")

    def volumes(self, test, workload, name):
        spec = pod_spec(workload)
        for vol in spec["volumes"]:
            vname = f"{name}/{vol['name']}"
            test.assertNotIn("hostPath", vol, f"{vname}: hostPath")
            if "emptyDir" in vol:
                test.assertEqual(vol["emptyDir"].get("medium"), "Memory", f"{vname}: emptyDir medium")
            if "secret" in vol:
                test.assertEqual(vol["secret"].get("defaultMode"), 444, f"{vname}: secret mode")
            if "configMap" in vol:
                test.assertEqual(vol["configMap"].get("defaultMode"), 444, f"{vname}: configMap mode")
            if "persistentVolumeClaim" in vol and vol["name"] in self.READ_ONLY_CLAIMS:
                test.assertIs(vol["persistentVolumeClaim"].get("readOnly"), True, f"{vname}: claim read-only")
        # Secret and ConfigMap projections are staged by init containers only.
        projected = {v["name"] for v in spec["volumes"] if "secret" in v or "configMap" in v}
        for c in containers(workload):
            test.assertEqual(
                projected & set(mounts(c)), set(),
                f"{name}/{c['name']}: mounts a projected volume directly",
            )
        for c in init_containers(workload):
            for mount in c.get("volumeMounts", []):
                if mount["name"] in projected:
                    test.assertIs(mount.get("readOnly"), True, f"{name}/{c['name']}: source mount")

    def writes(self, test, workload, name):
        activating = workload["metadata"]["labels"].get("registry.stack/operation") == "authority-activate"
        sizes = {v["name"]: v for v in pod_spec(workload)["volumes"]}
        for c in init_containers(workload):
            test.assertTrue(
                writable(c) <= self.STAGING, f"{name}/{c['name']}: unexpected writable {writable(c)}"
            )
        for c in containers(workload):
            allowed = {"audit", "tmp"} | ({"authority"} if activating else set())
            if c["name"] == "transit-proxy":
                allowed = {"transit-socket"}
            test.assertTrue(
                writable(c) <= allowed, f"{name}/{c['name']}: unexpected writable {writable(c)}"
            )
            for volume in writable(c) & {"tmp"}:
                test.assertIn("sizeLimit", sizes[volume]["emptyDir"], f"{name}: tmp needs a size limit")

    def policy(self, test, policy, docs, name):
        spec = policy["spec"]
        test.assertEqual(spec["policyTypes"], ["Ingress", "Egress"], f"{name}: policyTypes")
        selector = spec["podSelector"]["matchLabels"]
        test.assertTrue(selector, f"{name}: empty pod selector")
        selected = [w for w in workloads(docs) if selector.items() <= pod_labels(w).items()]
        test.assertTrue(selected, f"{name}: selects no workload in this render")
        operation_policy = "registrystack.org/operation-id" in selector
        if operation_policy:
            test.assertEqual(spec["ingress"], [], f"{name}: operation ingress must be empty")
        for rule in spec["ingress"]:
            test.assertEqual(len(rule["ports"]), 1, f"{name}: ingress ports")
            test.assertEqual(rule["ports"][0]["protocol"], "TCP", f"{name}: ingress protocol")
            test.assertTrue(rule["from"], f"{name}: ingress peers")
            for peer in rule["from"]:
                test.assertTrue(peer, f"{name}: empty ingress peer admits everything")
        for rule in spec["egress"]:
            test.assertTrue(rule.get("to"), f"{name}: egress rule without peers")
            test.assertTrue(rule.get("ports"), f"{name}: egress rule without ports")
            for peer in rule["to"]:
                test.assertTrue(peer, f"{name}: empty egress peer")


INVARIANTS = Invariants()


class ChartTest(unittest.TestCase):
    def assert_invariants(self, docs, label):
        INVARIANTS.check(self, docs, label)

    def assert_refused(self, args, *fragments, values=(FIXTURE,), namespace=NAMESPACE):
        """The render must fail with every fragment in Helm's error output."""
        result = helm_template(args, values=values, namespace=namespace)
        self.assertNotEqual(result.returncode, 0, f"render succeeded for {args}")
        self.assertTrue(result.stderr.strip(), "failure printed nothing")
        for fragment in fragments:
            self.assertIn(fragment, result.stderr, f"{args}: wrong error")


class LintTest(ChartTest):
    def test_lint_passes_with_the_fixture(self):
        result = run([HELM, "lint", str(CHART), "--values", str(FIXTURE)])
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


class ServingTest(ChartTest):
    @classmethod
    def setUpClass(cls):
        cls.docs = render()

    def test_shared_invariants(self):
        self.assert_invariants(self.docs, "serving")

    def test_resource_inventory(self):
        self.assertEqual(
            sorted((d["kind"], d["metadata"]["name"]) for d in self.docs),
            sorted(
                (kind, f"pilot-registry-stack-{part}")
                for kind in ("Deployment", "Service", "Ingress", "NetworkPolicy")
                for part in ("breg", "app-kit", "casework", "evidence")
            ),
        )
        for doc in self.docs:
            self.assertEqual(doc["metadata"]["namespace"], NAMESPACE)

    def test_deployments_run_one_recreated_replica(self):
        for deployment in of_kind(self.docs, "Deployment"):
            self.assertEqual(deployment["spec"]["replicas"], 1)
            self.assertEqual(deployment["spec"]["strategy"], {"type": "Recreate"})

    def test_images_are_pinned_per_container(self):
        expected = {
            "breg": {"breg": "ghcr.io/registrystack/breg@sha256:" + "a" * 64},
            "app-kit": {"app-kit": "registry.example/app-kit@sha256:" + "b" * 64},
            "casework": {"casework": "ghcr.io/registrystack/casework@sha256:" + "e" * 64},
            "evidence": {
                "evidence": "ghcr.io/registrystack/evidence@sha256:" + "1" * 64,
                "transit-proxy": "hashicorp/vault@sha256:" + "3" * 64,
            },
        }
        for part, images in expected.items():
            deployment = named(self.docs, "Deployment", f"pilot-registry-stack-{part}")
            self.assertEqual({c["name"]: c["image"] for c in containers(deployment)}, images)
            for init in init_containers(deployment):
                self.assertTrue(init["image"].startswith("docker.io/library/busybox@sha256:"))

    def test_probes(self):
        expected = {
            "breg": ("/ready", "/healthz"),
            "casework": ("/ready", "/health"),
            "evidence": ("/ready", "/health"),
        }
        for part, (ready, live) in expected.items():
            c = container(named(self.docs, "Deployment", f"pilot-registry-stack-{part}"), part)
            self.assertEqual(c["readinessProbe"]["httpGet"]["path"], ready)
            self.assertEqual(c["livenessProbe"]["httpGet"]["path"], live)
        kit = container(named(self.docs, "Deployment", "pilot-registry-stack-app-kit"), "app-kit")
        self.assertEqual(kit["readinessProbe"]["httpGet"]["path"], "/health")
        self.assertEqual(
            kit["readinessProbe"]["httpGet"]["httpHeaders"],
            [{"name": "Host", "value": "registry.example"}],
        )
        self.assertNotIn("livenessProbe", kit)

    def test_no_private_ca_variables_by_default(self):
        for deployment in of_kind(self.docs, "Deployment"):
            for c in containers(deployment):
                self.assertFalse({"SSL_CERT_FILE", "NODE_EXTRA_CA_CERTS"} & set(env(c)))

    def test_breg_storage_and_inputs(self):
        breg = named(self.docs, "Deployment", "pilot-registry-stack-breg")
        self.assertEqual(claims(breg), {"package": "breg-package", "audit": "breg-audit"})
        self.assertEqual(
            {k: v["mountPath"] for k, v in mounts(container(breg, "breg")).items()},
            {
                "runtime-private": "/etc/breg-runtime",
                "secret-private": "/etc/breg-secrets",
                "package": "/var/lib/breg/package",
                "audit": "/var/log/breg",
            },
        )
        self.assertEqual(secret_names(breg), {"breg-runtime-inputs"})
        self.assertEqual(breg["spec"]["template"]["metadata"]["annotations"],
                         {"registrystack.org/package-digest": "sha256:" + "d" * 64})
        self.assertEqual(
            pod_spec(breg)["hostAliases"],
            [{"ip": "192.0.2.11", "hostnames": ["issuer.test", "source.test"]}],
        )

    def test_casework_storage_and_inputs(self):
        casework = named(self.docs, "Deployment", "pilot-registry-stack-casework")
        self.assertEqual(claims(casework), {"package": "casework-package", "audit": "casework-audit"})
        self.assertEqual(secret_names(casework), {"casework-runtime-inputs"})

    def test_app_kit_staging_and_scratch_space(self):
        kit = named(self.docs, "Deployment", "pilot-registry-stack-app-kit")
        context = pod_spec(kit)["securityContext"]
        self.assertEqual((context["runAsUser"], context["runAsGroup"]), (1000, 1000))
        self.assertEqual(secret_names(kit), {"app-kit-secrets"})
        main = container(kit, "app-kit")
        self.assertEqual(env(main), {"APPKIT_HOST_CONFIG": "/etc/registry-app-kit/config/host.json"})
        self.assertEqual(
            {k: v["mountPath"] for k, v in mounts(main).items() if k != "tmp"},
            {"config-private": "/etc/registry-app-kit/config", "secret-private": "/etc/registry-app-kit/secrets"},
        )
        self.assertEqual(mounts(main)["tmp"]["mountPath"], "/tmp")
        self.assertEqual(volumes(kit)["tmp"]["emptyDir"], {"medium": "Memory", "sizeLimit": "64Mi"})
        staging = init_containers(kit)[0]
        self.assertIn("chmod 0400", staging["args"][0])
        self.assertIn('target="/work/secrets/private/', staging["args"][0])
        self.assertEqual(
            pod_spec(kit)["hostAliases"], [{"ip": "192.0.2.12", "hostnames": ["api.test"]}]
        )

    def test_evidence_runs_the_transit_proxy_with_scoped_inputs(self):
        evidence = named(self.docs, "Deployment", "pilot-registry-stack-evidence")
        self.assertEqual(
            claims(evidence),
            {
                "bundle": "evidence-bundle",
                "runtime-inputs": "evidence-runtime-files",
                "audit": "evidence-audit",
                "authority": "evidence-authority",
            },
        )
        self.assertEqual(
            secret_names(evidence), {"evidence-runtime-inputs", "evidence-transit-proxy-inputs"}
        )
        self.assertEqual(
            evidence["spec"]["template"]["metadata"]["annotations"],
            {"registrystack.org/package-digest": "sha256:" + "2" * 64},
        )
        main = mounts(container(evidence, "evidence"))
        self.assertIn("transit-socket", main)
        self.assertTrue(main["authority"]["readOnly"])
        self.assertTrue(main["transit-socket"]["readOnly"])
        self.assertFalse({"proxy-secret-private", "proxy-secret-source", "proxy-config-private"} & set(main))
        proxy = mounts(container(evidence, "transit-proxy"))
        self.assertEqual(set(proxy), {"proxy-config-private", "proxy-secret-private", "transit-socket"})
        self.assertEqual(proxy["proxy-secret-private"]["mountPath"], "/run/secrets/registry-evidence-transit-proxy")

    def test_only_breg_pods_carry_the_database_client_label(self):
        label = "registrystack.org/database-client"
        for deployment in of_kind(self.docs, "Deployment"):
            has = label in pod_labels(deployment)
            self.assertEqual(has, deployment["metadata"]["name"].endswith("-breg"), deployment["metadata"]["name"])

    def test_services_are_cluster_ip(self):
        for service in of_kind(self.docs, "Service"):
            self.assertEqual(service["spec"]["type"], "ClusterIP", service["metadata"]["name"])

    def test_ingress_hosts_and_tls(self):
        expected = {
            "breg": ("api.registry.example", "breg-api-tls"),
            "app-kit": ("registry.example", "app-kit-tls"),
            "casework": ("casework.registry.example", "casework-api-tls"),
            "evidence": ("evidence.registry.example", "evidence-api-tls"),
        }
        for part, (host, secret) in expected.items():
            ingress = named(self.docs, "Ingress", f"pilot-registry-stack-{part}")
            self.assertEqual(ingress["spec"]["tls"], [{"hosts": [host], "secretName": secret}])
            self.assertEqual([r["host"] for r in ingress["spec"]["rules"]], [host])

    def test_serving_network_policies(self):
        ingress_system = {"namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": "ingress-system"}}}
        breg = named(self.docs, "NetworkPolicy", "pilot-registry-stack-breg")["spec"]
        self.assertEqual(
            breg["ingress"],
            [{
                "from": [
                    ingress_system,
                    {
                        "namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": "trusted-extension"}},
                        "podSelector": {"matchLabels": {"app.kubernetes.io/part-of": "registry-extension"}},
                    },
                ],
                "ports": [{"protocol": "TCP", "port": 8080}],
            }],
        )
        dns = {
            "to": [{
                "namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": "kube-system"}},
                "podSelector": {"matchLabels": {"k8s-app": "kube-dns"}},
            }],
            "ports": [{"protocol": "UDP", "port": 53}, {"protocol": "TCP", "port": 53}],
        }
        self.assertEqual(
            breg["egress"],
            [dns, {"to": [{"ipBlock": {"cidr": "192.0.2.0/24"}}], "ports": [{"port": 5432, "protocol": "TCP"}]}],
        )
        for part, port in (("app-kit", 3100), ("casework", 8100), ("evidence", 8080)):
            spec = named(self.docs, "NetworkPolicy", f"pilot-registry-stack-{part}")["spec"]
            self.assertEqual(
                spec["ingress"], [{"from": [ingress_system], "ports": [{"protocol": "TCP", "port": port}]}]
            )
            self.assertEqual(spec["egress"][0], dns)

    def test_private_ca_keys_reach_serving_containers(self):
        docs = render(["--set-string", "casework.caBundleKey=private-ca.pem",
                       "--set-string", "breg.caBundleKey=private-ca.pem",
                       "--set-string", "appKit.caBundleKey=private-ca.pem"])
        expected = {
            ("breg", "breg"): ("SSL_CERT_FILE", "/etc/breg-secrets/private-ca.pem"),
            ("casework", "casework"): ("SSL_CERT_FILE", "/etc/registry-casework/secrets/private-ca.pem"),
            ("app-kit", "app-kit"): ("NODE_EXTRA_CA_CERTS", "/etc/registry-app-kit/secrets/private-ca.pem"),
        }
        for (part, name), (variable, path) in expected.items():
            c = container(named(docs, "Deployment", f"pilot-registry-stack-{part}"), name)
            self.assertEqual(env(c)[variable], path)

    def test_app_kit_liveness_and_private_host(self):
        docs = render(["--set-string", "appKit.probes.livenessPath=/live"],
                      "templates/app-kit-deployment.yaml")
        kit = container(named(docs, "Deployment", "pilot-registry-stack-app-kit"), "app-kit")
        self.assertEqual(kit["livenessProbe"]["httpGet"]["path"], "/live")
        docs = render(["--set", "appKit.ingress.enabled=false",
                       "--set-string", "appKit.probes.host=private.staff.example:4430"],
                      "templates/app-kit-deployment.yaml")
        kit = container(named(docs, "Deployment", "pilot-registry-stack-app-kit"), "app-kit")
        self.assertEqual(
            kit["readinessProbe"]["httpGet"]["httpHeaders"],
            [{"name": "Host", "value": "private.staff.example:4430"}],
        )


class InactiveTest(ChartTest):
    def test_inactive_release_renders_nothing(self):
        result = helm_template(NO_SERVE + ["--set", "appKit.enabled=false"])
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), "")


class BregOperationTest(ChartTest):
    def render(self, kind, *extra, name=None):
        docs = render(
            NO_SERVE + ["--set", "appKit.enabled=false"]
            + operation("breg", name or f"{kind}-001", kind, *extra),
            BREG_JOB,
        )
        self.assert_invariants(docs, f"breg {kind}")
        return docs

    ARGS = {
        "verify": ["verify", "--runtime-config", "/etc/breg-runtime/runtime.yaml"],
        "doctor": ["doctor", "--runtime-config", "/etc/breg-runtime/runtime.yaml"],
        "status": ["status", "--runtime-config", "/etc/breg-runtime/runtime.yaml"],
        "plan": ["plan", "--runtime-config", "/etc/breg-runtime/runtime.yaml",
                 "--package", "/var/lib/breg/package", "--expected-digest", "sha256:" + "d" * 64],
        "apply-initial": ["apply", "--initial", "--runtime-config", "/etc/breg-runtime/runtime.yaml",
                          "--package", "/var/lib/breg/package", "--expected-digest", "sha256:" + "d" * 64],
        "claim-status": ["instance-claim", "status", "--runtime-config", "/etc/breg-runtime/runtime.yaml"],
        "claim-adopt": ["instance-claim", "adopt", "--acknowledge-original-retired",
                        "--runtime-config", "/etc/breg-runtime/runtime.yaml"],
        "reconcile": ["migration", "reconcile", "--runtime-config", "/etc/breg-runtime/runtime.yaml",
                      "--package", "/var/lib/breg/package",
                      "--operator-reference", "helm-read-only-inspection"],
    }

    def test_every_kind_runs_the_exact_command(self):
        for kind, args in self.ARGS.items():
            with self.subTest(kind=kind):
                job = named(self.render(kind), "Job", f"pilot-registry-stack-breg-{kind}-001")
                c = container(job, "bregctl")
                self.assertEqual(c["command"], ["/usr/local/bin/bregctl"])
                self.assertEqual(c["args"], ["--format", "json", *args])
                self.assertEqual(env(c)["REGISTRY_STACK_OPERATION_KIND"], kind)
                labels = job["metadata"]["labels"]
                self.assertEqual(labels["registry.stack/operation"], kind)
                self.assertEqual(labels["registrystack.org/operation-id"], f"{kind}-001")
                self.assertEqual(
                    job["metadata"]["annotations"]["registrystack.org/package-digest"],
                    "sha256:" + "d" * 64,
                )
                self.assertEqual(claims(job), {"package": "breg-package", "audit": "breg-audit"})
                self.assertEqual(
                    secret_names(job), {"breg-runtime-inputs", "breg-migration-inputs"}
                )
                self.assertEqual(
                    pod_spec(job)["hostAliases"],
                    [{"ip": "192.0.2.11", "hostnames": ["issuer.test", "source.test"]}],
                )

    def test_operation_policy_selects_only_its_job(self):
        docs = self.render("apply-initial", name="activate-001")
        policy = named(docs, "NetworkPolicy", "pilot-registry-stack-breg-activate-001")
        self.assertEqual(
            policy["spec"]["podSelector"]["matchLabels"]["registrystack.org/operation-id"],
            "activate-001",
        )
        self.assertIn(
            {"to": [{"ipBlock": {"cidr": "192.0.2.0/24"}}], "ports": [{"port": 5432, "protocol": "TCP"}]},
            policy["spec"]["egress"],
        )

    def test_job_pod_carries_the_database_client_label(self):
        job = named(self.render("verify"), "Job", "pilot-registry-stack-breg-verify-001")
        self.assertEqual(pod_labels(job)["registrystack.org/database-client"], "true")

    def test_claim_adopt_alone_acknowledges_retirement(self):
        for kind, args in self.ARGS.items():
            self.assertEqual("--acknowledge-original-retired" in args, kind == "claim-adopt", kind)

    def test_private_ca_reaches_the_operation(self):
        job = named(
            self.render("verify", "--set-string", "breg.caBundleKey=private-ca.pem"),
            "Job", "pilot-registry-stack-breg-verify-001",
        )
        self.assertEqual(env(container(job, "bregctl"))["SSL_CERT_FILE"], "/etc/breg-secrets/private-ca.pem")

    def test_successor_apply_binds_the_candidate(self):
        docs = self.render(
            "apply-successor",
            "--set-string", "breg.operation.candidate.existingClaim=successor-package",
            "--set-string", f"breg.operation.candidate.expectedDigest={DIGEST_A}",
        )
        job = named(docs, "Job", "pilot-registry-stack-breg-apply-successor-001")
        c = container(job, "bregctl")
        self.assertEqual(
            c["args"],
            ["--format", "json", "apply", "--runtime-config", "/etc/breg-runtime/runtime.yaml",
             "--package", "/var/lib/breg/candidate", "--expected-digest", DIGEST_A],
        )
        self.assertEqual(
            claims(job),
            {"package": "breg-package", "candidate": "successor-package", "audit": "breg-audit"},
        )
        self.assertEqual(mounts(c)["candidate"]["mountPath"], "/var/lib/breg/candidate")
        self.assertEqual(
            job["metadata"]["annotations"]["registrystack.org/package-digest"], DIGEST_A
        )

    def test_successor_apply_needs_a_candidate(self):
        self.assert_refused(
            NO_SERVE + operation("breg", "missing-candidate", "apply-successor"),
            "A successor apply needs the candidate package claim and digest",
        )

    def test_operator_reference_reaches_apply_only(self):
        for kind in ("apply-initial", "apply-successor"):
            with self.subTest(kind=kind):
                extra = ["--set-string", "breg.operation.operatorReference=CHANGE-9012"]
                if kind == "apply-successor":
                    extra += [
                        "--set-string", "breg.operation.candidate.existingClaim=successor-package",
                        "--set-string", f"breg.operation.candidate.expectedDigest={DIGEST_A}",
                    ]
                args = container(
                    named(self.render(kind, *extra), "Job", f"pilot-registry-stack-breg-{kind}-001"),
                    "bregctl",
                )["args"]
                position = args.index("--operator-reference")
                self.assertEqual(args[position + 1], "CHANGE-9012")
        for kind in ("verify", "doctor", "status", "plan", "claim-status", "claim-adopt"):
            with self.subTest(kind=kind):
                args = container(
                    named(
                        self.render(kind, "--set-string", "breg.operation.operatorReference=CHANGE-9012"),
                        "Job", f"pilot-registry-stack-breg-{kind}-001",
                    ),
                    "bregctl",
                )["args"]
                self.assertNotIn("--operator-reference", args)
        # Reconcile keeps its fixed read-only reference whatever the value says.
        args = container(
            named(
                self.render("reconcile", "--set-string", "breg.operation.operatorReference=CHANGE-9012"),
                "Job", "pilot-registry-stack-breg-reconcile-001",
            ),
            "bregctl",
        )["args"]
        self.assertEqual(args[args.index("--operator-reference") + 1], "helm-read-only-inspection")

    def test_no_operator_reference_by_default(self):
        args = container(
            named(self.render("apply-initial"), "Job", "pilot-registry-stack-breg-apply-initial-001"),
            "bregctl",
        )["args"]
        self.assertNotIn("--operator-reference", args)


class CaseworkOperationTest(ChartTest):
    def render(self, kind, *extra):
        docs = render_operation(CASEWORK_JOB, "casework", f"{kind}-001", kind, *extra)
        self.assert_invariants(docs, f"casework {kind}")
        return named(docs, "Job", f"pilot-registry-stack-casework-{kind}-001")

    def test_plan(self):
        job = self.render("plan")
        c = container(job, "caseworkctl")
        self.assertEqual(c["command"], ["/usr/local/bin/caseworkctl"])
        self.assertEqual(c["args"], ["--format", "json", "plan", "--runtime-config", "/etc/registry-casework/runtime.yaml"])
        self.assertEqual(job["metadata"]["labels"]["registry.stack/operation"], "plan")
        self.assertEqual(job["metadata"]["labels"]["registrystack.org/operation-id"], "plan-001")
        self.assertTrue(
            job["metadata"]["annotations"]["registrystack.org/package-digest"].startswith("sha256:")
        )
        self.assertEqual(secret_names(job), {"casework-runtime-inputs"})
        runtime = mounts(c)["runtime-private"]
        self.assertEqual(
            (runtime["mountPath"], runtime["subPath"]),
            ("/etc/registry-casework/runtime.yaml", "private/runtime.yaml"),
        )

    def test_apply_receives_the_migration_secret_and_references(self):
        job = self.render(
            "apply",
            "--set-string", "casework.operation.operatorReference=CHANGE-1234",
            "--set-json", 'casework.operation.backupReferences=["backup-before-activation"]',
        )
        args = container(job, "caseworkctl")["args"]
        self.assertEqual(args[2], "apply")
        self.assertEqual(args[args.index("--operator-reference") + 1], "CHANGE-1234")
        self.assertEqual(args[args.index("--backup-reference") + 1], "backup-before-activation")
        self.assertEqual(secret_names(job), {"casework-runtime-inputs", "casework-migration-inputs"})

    def test_doctor_uses_the_private_ca(self):
        job = self.render("doctor", "--set-string", "casework.caBundleKey=private-ca.pem")
        c = container(job, "caseworkctl")
        self.assertEqual(c["args"][2], "doctor")
        self.assertEqual(env(c)["SSL_CERT_FILE"], "/etc/registry-casework/secrets/private-ca.pem")
        self.assertEqual(secret_names(job), {"casework-runtime-inputs"})


class EvidenceOperationTest(ChartTest):
    def render(self, kind, *extra):
        docs = render_operation(EVIDENCE_JOB, "evidence", f"{kind}-001", kind, *extra)
        self.assert_invariants(docs, f"evidence {kind}")
        return named(docs, "Job", f"pilot-registry-stack-evidence-{kind}-001")

    def test_check(self):
        job = self.render("check")
        c = container(job, "evidence")
        self.assertEqual(c["command"], ["/usr/local/bin/evidence"])
        self.assertEqual(c["args"], ["check", "--runtime-config", "/etc/registry-evidence/runtime.yaml", "--format", "json"])
        self.assertEqual(job["metadata"]["labels"]["registrystack.org/operation-id"], "check-001")
        self.assertEqual(
            job["metadata"]["annotations"]["registrystack.org/package-digest"], "sha256:" + "2" * 64
        )
        self.assertEqual(secret_names(job), set())
        self.assertEqual(claims(job), {"bundle": "evidence-bundle", "runtime-inputs": "evidence-runtime-files", "authority": "evidence-authority"})
        self.assertEqual(writable(c), set())

    def test_authority_activate(self):
        job = self.render(
            "authority-activate", "--set-string", "evidence.operation.operatorReference=CHANGE-5678"
        )
        c = container(job, "evidence")
        self.assertEqual(
            c["args"],
            ["authority", "activate", "--runtime-config", "/etc/registry-evidence/runtime.yaml",
             "--document", "/etc/registry-evidence/compiled-authority.yaml",
             "--operator-reference", "CHANGE-5678"],
        )
        self.assertEqual(secret_names(job), {"evidence-activation-inputs"})
        self.assertEqual(claims(job), {"bundle": "evidence-bundle", "audit": "evidence-audit", "authority": "evidence-authority"})
        self.assertEqual(writable(c), {"audit", "authority"})

    def test_authority_history(self):
        job = self.render("authority-history")
        c = container(job, "evidence")
        self.assertEqual(c["args"], ["authority", "history", "--runtime-config", "/etc/registry-evidence/runtime.yaml"])
        self.assertEqual(claims(job), {"authority": "evidence-authority"})
        self.assertEqual(secret_names(job), set())
        self.assertEqual(writable(c), set())
        self.assertTrue(volumes(job)["authority"]["persistentVolumeClaim"]["readOnly"])


class ExtensionTest(ChartTest):
    @classmethod
    def setUpClass(cls):
        cls.docs = render(values=(EXTENSIONS,), namespace="pilot-extensions")

    def test_inventory_and_hardening(self):
        self.assertEqual(
            sorted(d["kind"] for d in self.docs),
            ["Deployment", "Ingress", "NetworkPolicy", "Service"],
        )
        deployment = named(self.docs, "Deployment", "extension-intake")
        pod = pod_spec(deployment)
        self.assertIs(pod["automountServiceAccountToken"], False)
        for c in pod["containers"]:
            self.assertIs(c["securityContext"]["readOnlyRootFilesystem"], True)
            self.assertIs(c["securityContext"]["allowPrivilegeEscalation"], False)
            self.assertEqual(c["securityContext"]["capabilities"]["drop"], ["ALL"])
            self.assertIn("PUBLIC_PATH", env(c))
            self.assertNotIn("5432", json.dumps(c))
        self.assertEqual(volumes(deployment)["temp"]["emptyDir"]["sizeLimit"], "32Mi")
        self.assertEqual(secret_names(deployment), {"intake-client"})
        for doc in self.docs:
            self.assertEqual(doc["metadata"]["namespace"], "pilot-extensions")
        self.assertEqual(named(self.docs, "Service", "extension-intake")["spec"]["type"], "ClusterIP")

    def test_ingress_path_is_exact(self):
        ingress = named(self.docs, "Ingress", "extension-intake")
        paths = ingress["spec"]["rules"][0]["http"]["paths"]
        self.assertEqual([(p["path"], p["pathType"]) for p in paths], [("/extensions/intake", "Exact")])

    def test_policy_has_no_egress_without_configuration(self):
        policy = named(self.docs, "NetworkPolicy", "extension-intake")
        self.assertEqual(policy["spec"]["egress"], [])
        self.assertEqual(policy["spec"]["policyTypes"], ["Ingress", "Egress"])

    def test_namespace_must_match(self):
        self.assert_refused([], values=(EXTENSIONS,), namespace=NAMESPACE)

    def test_core_modules_are_refused(self):
        self.assert_refused([], values=(EXTENSIONS, FIXTURE), namespace="pilot-extensions")

    def test_unbounded_pod_selector_is_refused(self):
        self.assert_refused(
            ["--set-json", 'extensions.endpoints.intake.egress=[{"to":{"podSelector":{}},"ports":[{"port":443}]}]'],
            "/extensions/endpoints/intake/egress/0/to",
            values=(EXTENSIONS,), namespace="pilot-extensions",
        )

    def test_all_address_blocks_are_refused(self):
        for cidrs in (["0.0.0.0/0"], ["::/0"], ["0.0.0.0/1", "128.0.0.0/1"], ["0.0.0.0/00"]):
            with self.subTest(cidrs=cidrs):
                egress = [{"to": {"ipBlock": {"cidr": c}}, "ports": [{"port": 443}]} for c in cidrs]
                self.assert_refused(
                    ["--set-json", "extensions.endpoints.intake.egress=" + json.dumps(egress)],
                    "/extensions/endpoints/intake/egress",
                    values=(EXTENSIONS,), namespace="pilot-extensions",
                )

    def test_bounded_blocks_are_accepted(self):
        for cidr in ("198.51.100.0/24", "203.0.113.7/32", "10.0.0.0/8", "2001:db8::/32", "0.0.0.0/8"):
            with self.subTest(cidr=cidr):
                egress = [{"to": {"ipBlock": {"cidr": cidr}}, "ports": [{"port": 443}]}]
                result = helm_template(
                    ["--set-json", "extensions.endpoints.intake.egress=" + json.dumps(egress)],
                    values=(EXTENSIONS,), namespace="pilot-extensions",
                )
                self.assertEqual(result.returncode, 0, result.stderr)


class SchemaRefusalTest(ChartTest):
    """Each refusal names the values path and the rule that failed."""

    def test_digests_must_be_sha256(self):
        self.assert_refused(["--set-string", "breg.image.digest=latest"], "at '/breg/image/digest'", "does not match pattern")
        self.assert_refused(["--set-string", "casework.image.digest=latest"], "at '/casework/image/digest'")
        self.assert_refused(["--set-string", "evidence.image.digest=latest"], "at '/evidence/image/digest'")
        self.assert_refused(
            ["--set-string", "breg.package.expectedDigest=sha256:ABC"], "at '/breg/package/expectedDigest'"
        )

    def test_image_repository_refuses_tags(self):
        for product in ("breg", "appKit", "casework", "evidence"):
            self.assert_refused(
                ["--set-string", f"{product}.image.repository=ghcr.io/registrystack/{product}:v0.46.0"],
                f"at '/{product}/image/repository'", "does not match pattern",
            )
        self.assert_refused(
            ["--set-string", "staging.image.repository=busybox:1.37"], "at '/staging/image/repository'"
        )
        self.assert_refused(
            ["--set-string", "breg.image.repository=localhost:5000/team/breg:1"],
            "at '/breg/image/repository'",
        )

    def test_image_repository_accepts_registries_with_ports(self):
        for repository in ("localhost:5000/breg", "registry.example:5443/team/breg", "ghcr.io/registrystack/breg", "busybox"):
            with self.subTest(repository=repository):
                result = helm_template(["--set-string", f"breg.image.repository={repository}"])
                self.assertEqual(result.returncode, 0, result.stderr)

    def test_unknown_operations_are_refused(self):
        for product in ("breg", "casework", "evidence"):
            self.assert_refused(
                ["--set-string", f"{product}.operation.kind=arbitrary-command"],
                f"at '/{product}/operation/kind'", "value must be one of",
            )

    def test_serving_needs_the_component_enabled(self):
        for product in ("breg", "casework", "evidence", "appKit"):
            self.assert_refused(
                ["--set", f"{product}.enabled=false", "--set", f"{product}.serve=true"],
                f"at '/{product}/enabled'", "value must be true",
            )

    def test_operations_refuse_a_serving_workload(self):
        cases = {
            "breg": "verify",
            "casework": "plan",
            "evidence": "check",
        }
        for product, kind in cases.items():
            with self.subTest(product=product):
                self.assert_refused(
                    operation(product, "beside-serving", kind),
                    f"at '/{product}/serve'", "value must be false",
                )

    def test_services_are_cluster_ip_only(self):
        for product in ("breg", "appKit", "casework", "evidence"):
            for service_type in ("NodePort", "LoadBalancer"):
                with self.subTest(product=product, type=service_type):
                    self.assert_refused(
                        ["--set-string", f"{product}.service.type={service_type}"],
                        f"at '/{product}/service/type'", "value must be 'ClusterIP'",
                    )

    def test_casework_apply_needs_its_migration_secret(self):
        self.assert_refused(
            NO_SERVE + operation("casework", "apply-no-migration", "apply")
            + ["--set-string", "casework.migrationSecrets.secretName="],
            "at '/casework/migrationSecrets/secretName'",
        )

    def test_app_kit_refuses_root(self):
        self.assert_refused(
            ["--set", "appKit.securityContext.runAsUser=0"],
            "at '/appKit/securityContext/runAsUser'", "minimum",
        )

    def test_evidence_serving_needs_the_transit_proxy(self):
        self.assert_refused(
            ["--set", "evidence.transitProxy.enabled=false"],
            "Evidence cannot serve without the Transit proxy",
            "evidence.transitProxy.enabled=true",
        )

    def test_evidence_activation_needs_its_secret(self):
        self.assert_refused(
            NO_SERVE + operation("evidence", "activate-no-secret", "authority-activate")
            + ["--set-string", "evidence.activationSecrets.secretName="],
            "at '/evidence/activationSecrets/secretName'",
        )

    def test_host_aliases_need_hostnames(self):
        self.assert_refused(
            ["--set-json", 'breg.hostAliases=[{"ip":"192.0.2.11","hostnames":[]}]'],
            "at '/breg/hostAliases/0/hostnames'", "minItems",
        )

    def test_operator_reference_is_bounded(self):
        for product in ("breg", "casework", "evidence"):
            self.assert_refused(
                ["--set-string", f"{product}.operation.operatorReference={'x' * 257}"],
                f"at '/{product}/operation/operatorReference'", "maxLength",
            )


if __name__ == "__main__":
    unittest.main(verbosity=2)
