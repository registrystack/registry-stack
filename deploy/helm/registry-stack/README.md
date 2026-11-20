# Registry Stack Helm chart

This chart is a public reference. It is not a supported product, is not
published with Registry Stack releases, and has not been qualified for
production.

## Supported releases

The chart was tested against the v0.46.0 Registry Stack images and is not part
of any release artifact. Adopters pin every image by digest from the release
manifest of the version they run. The chart `appVersion` stays 0.46.0 until a
later release is tested, so it does not follow newer releases automatically.

This chart deploys four independently controlled workloads:

- Base Registry Engine (BReg) from a Registry Stack release image.
- Registry Casework from the same Registry Stack release.
- Registry Evidence from the same Registry Stack release.
- One prebuilt Registry App Kit image supplied by the adopter.

All workloads are off by default. Set both `enabled: true` and `serve: true`
for a component before the chart renders its Deployment, Service, Ingress, and
NetworkPolicy. Keeping `serve: false` makes an inactive staging release render
no serving workload. BReg, Casework, and Evidence operation Jobs are separate,
explicit render paths.

Use the [deployment guide](../../README.md) for Ubuntu K3s and existing
Kubernetes. Prepare the named inputs and qualify the selected release,
dependencies and recovery procedure on the target infrastructure.

## Ownership boundary

The operator owns the namespace, Secrets, ConfigMaps, claims, database,
identity provider, certificates and backups. The chart references those
inputs so their lifecycle follows the installation's retention policy.
Supply credential references by name.

The [extension endpoint profile](../../examples/intake-status/README.md) uses
the same chart as a separate release in its own namespace. Its reviewed
images get their own Services, HTTPS routes and NetworkPolicies.

The default full name is `<release>-registry-stack`. Serving resources append
`-breg`, `-app-kit`, `-casework`, or `-evidence`. Operation resources append
the component and explicit operation name.
`fullnameOverride` replaces the full-name prefix. The chart emits resources
into the Helm release namespace and never hard-codes one.

## Images and workload security

Every image is `repository@sha256:<digest>`. Tags are not accepted. Supply:

- `breg.image.repository` and `breg.image.digest` from the Registry Stack
  release manifest.
- `casework.image.repository` and `casework.image.digest` from that manifest.
- `evidence.image.repository` and `evidence.image.digest` from that manifest.
- `evidence.transitProxy.image.repository` and `.digest` for the reviewed
  workload-local Vault/OpenBao proxy image.
- `appKit.image.repository` and `appKit.image.digest` for the compatible,
  prebuilt application.
- `staging.image.repository` and `staging.image.digest` for a small image with
  `/bin/sh`, `cp`, `chmod`, and `mkdir`. The test fixture uses the verified
  multi-platform BusyBox 1.37.0 index digest.

BReg, Casework, and Evidence run as UID and GID 65532. App Kit defaults to its image
contract of UID and GID 1000. Change `appKit.securityContext.runAsUser` and
`.runAsGroup` together only when the prebuilt image uses different non-root
IDs. Its staging init container uses those same IDs, so the serving process
owns the copied files. Every container drops all capabilities, uses the runtime
default seccomp profile, refuses privilege escalation, has a read-only root
filesystem, and disables the service-account token. Serving Deployments use
one replica and `Recreate`, so Helm does not perform a mixed-package rolling
update.

No BReg, Casework, or Evidence Pod sets `fsGroup`. Kubelet can otherwise
recursively change an existing owner-only audit or authority volume root.

## BReg input contract

Set these references when `breg.enabled` is true:

| Value | Existing input | Pod path |
| --- | --- | --- |
| `breg.runtimeConfig.configMapName` and `.key` | `BRegRuntimeConfig` file | `/etc/breg-runtime/runtime.yaml` |
| `breg.runtimeSecrets.secretName` | Runtime-only secret files | `/etc/breg-secrets/*` |
| `breg.migrationSecrets.secretName` | Migration-only secret files, operation Jobs only | `/etc/breg-secrets/*` |
| `breg.package.existingClaim` | Preloaded immutable package PVC | `/var/lib/breg/package` read-only |
| `breg.audit.existingClaim` | Retained audit PVC | `/var/log/breg` read-write |

The runtime ConfigMap must bind exactly these container paths:

- `listener.bind: 0.0.0.0:8080`
- `secretProviders.file.root: /etc/breg-secrets`
- `package.root: /var/lib/breg/package`
- `package.expectedDigest` equal to `breg.package.expectedDigest`
- `audit.path: /var/log/breg/audit.jsonl`

Use the closed `package/` directory produced by `bregctl package` as the PVC
root. Preload it out of band and
keep the volume read-only to the chart. `breg.package.expectedDigest` is also
placed on the Deployment, Pod, and operation Job as
`registrystack.org/package-digest`. BReg enforces the digest through
the runtime file and `bregctl --expected-digest`.

Provision the audit PVC root as a real directory owned by UID/GID 65532 with
mode `0700`. Do not use a symlink or a storage setup that changes its group or
mode. The chart deliberately does not run a privileged ownership-fixing
container.

Kubernetes ConfigMap and Secret projections are symlinks, which BReg refuses.
The non-root staging init container reads projections with mode `0444`, copies
them into memory-backed, UID-owned `0700` subdirectories as real `0400` files,
and the BReg container mounts only those final subdirectories read-only. The
serving Pod never projects or mounts `breg.migrationSecrets`.

The runtime Secret should contain only values the serving process needs, such
as the runtime database URL, audit key, cursor key, and optional private CA.
Keep the migration database URL only in the separate migration Secret. Key
names must match the `secret:file/<name>` references in `runtime.yaml`. A key
collision between the two Secrets makes an operation init container fail
visibly instead of silently replacing a value.

For an OIDC issuer or another native HTTPS dependency whose certificate uses a
private authority, put the PEM roots in the runtime Secret and set
`breg.caBundleKey` to that key. Serving and operation containers then receive
only `SSL_CERT_FILE=/etc/breg-secrets/<key>`. The value is empty by default, so
public Web PKI remains the native client's default. Keep the database-specific
`trustedRootCertificateRef` in `runtime.yaml` for the BReg database TLS binding.

Use BReg's production split-role mode. `database.roles.runtime` names the role
in the runtime URL, and `database.roles.migration` names the different role in
the migration URL. The serving Pod receives no migration URL. Keep
`identity.databaseId`, `identity.instanceId`, and the role names stable across
the serving Deployment and every operation Job. One replica plus `Recreate`
prevents simultaneous chart-managed BReg versions, but it does not authorise
an instance-claim adoption: select `claim-adopt` only after every other copy of
the Registry has stopped and is permanently retired.

## App Kit input contract

`appKit.config.configMapName` and `appKit.secrets.secretName` reference the
prebuilt application's existing inputs. Keep the image's `host.json` in the
ConfigMap at `appKit.config.mountPath`. The staging init container copies all
projected keys to memory-backed, owner-only regular files, and the serving
container mounts only those staged subdirectories read-only at:

- `appKit.config.mountPath`, default `/etc/registry-app-kit/config`
- `appKit.secrets.mountPath`, default `/etc/registry-app-kit/secrets`

Put `host.json` in the ConfigMap. The chart sets `APPKIT_HOST_CONFIG` to
`<appKit.config.mountPath>/host.json`. Build the App Kit host and its assets
into the pinned image before installing.
When the Node.js HTTPS client needs private roots, place the PEM bundle in the
App Kit Secret and set `appKit.caBundleKey`. The container then receives only
`NODE_EXTRA_CA_CERTS=<appKit.secrets.mountPath>/<key>`.
Readiness defaults to `/health`. Liveness is omitted by default because the
current host health includes database reachability. A database outage should
drain traffic without restarting an otherwise healthy process. Set
`appKit.probes.livenessPath` only when the selected image exposes a
process-only liveness endpoint.
Probes send the configured public Host header. Set `appKit.probes.host`
when the application origin has a port or when ingress is provided outside
the chart.
Use an App Kit image built and tested against the exact Registry Stack release
you deploy.

Treat referenced ConfigMaps and Secrets as immutable. Changing an existing
object with the same name does not recreate a Pod, and the serving container
does not mount the original projection. Create a versioned replacement and
update the reference through Helm so the Deployment recreates its Pod.

## Casework input contract

Set these references when `casework.enabled` is true:

| Value | Existing input | Pod path |
| --- | --- | --- |
| `casework.runtimeConfig.configMapName` and `.key` | `CaseworkRuntimeConfig` file | `/etc/registry-casework/runtime.yaml` |
| `casework.runtimeSecrets.secretName` | Runtime database and application secret files | `/etc/registry-casework/secrets/*` |
| `casework.migrationSecrets.secretName` | Migration database secret files, apply Job only | `/etc/registry-casework/secrets/*` |
| `casework.package.existingClaim` | Preloaded immutable package PVC | `/var/lib/registry-casework/package` read-only |
| `casework.audit.existingClaim` | Retained audit PVC | `/var/lib/registry-casework/audit` read-write |

The runtime ConfigMap must bind the container contract, including:

- `identity.databaseId` stable for this Casework database.
- `listener.bind: 0.0.0.0:8100`,
  `listener.tlsTermination: operator-controlled-upstream`, and
  `listener.networkExposure: container-private` when ingress owns HTTPS.
- `secretProviders.file.root: /etc/registry-casework/secrets`.
- `package.root: /var/lib/registry-casework/package`.
- `package.expectedDigest` equal to `casework.package.expectedDigest`.
- `audit.path: /var/lib/registry-casework/audit/casework.ndjson`.

Preload the closed, immutable package into its retained PVC out of band. The
chart places `casework.package.expectedDigest` on the Deployment, Pod, and
operation Job as `registrystack.org/package-digest`. The runtime configuration
remains the enforcement binding. Provision the audit PVC root as a real
directory owned by UID/GID 65532 with mode `0700`. Do not use symlinks or rely
on a privileged ownership-fixing container.

As with BReg, Casework rejects unsafe projected inputs. The staging init
container copies the ConfigMap and Secret projections into memory-backed,
UID-owned `0700` subdirectories as real `0400` files. The serving container
mounts only those final subdirectories read-only and never receives
`casework.migrationSecrets`.

Use separate PostgreSQL runtime and migration roles. Serving, `plan`, and
`doctor` receive only the runtime Secret. Only the explicit `apply` Job also
receives the migration Secret. Keep the migration database URL out of the
runtime Secret. If a private CA is needed for a native HTTPS dependency, set
`casework.caBundleKey` to its key in the runtime Secret. Serving and operation
containers then receive `SSL_CERT_FILE=/etc/registry-casework/secrets/<key>`.

## Evidence input and Transit contract

Evidence serving uses one replica because one process owns the audit file and
captures one activated authority snapshot. Set these existing inputs:

| Value | Existing input | Pod path |
| --- | --- | --- |
| `evidence.runtimeConfig.configMapName` and `.key` | Target-specific `EvidenceRuntimeConfig` | `/etc/registry-evidence/runtime.yaml` |
| `evidence.runtimeSecrets.secretName` | Serving audit, subject-binding, and source credential files | `/run/secrets/registry-evidence/*` |
| `evidence.activationSecrets.secretName` | Activation audit key only | `/run/secrets/registry-evidence/*` in the activation Job |
| `evidence.bundle.existingClaim` | Reviewed immutable `bundle/` | `/etc/registry-evidence/bundle` read-only |
| `evidence.runtimeInputs.existingClaim` | Optional immutable CA bundles and source extracts | `/etc/registry-evidence/inputs` read-only |
| `evidence.compiledAuthority.configMapName` and `.key` | Reviewed `compiled-authority.yaml` | `/etc/registry-evidence/compiled-authority.yaml` in the activation Job |
| `evidence.audit.existingClaim` | Retained audit storage | `/var/lib/registry-evidence/audit` read-write |
| `evidence.authority.existingClaim` | Retained authority history | `/var/lib/registry-evidence/authority`, read-only while serving and writable only for activation |

The runtime file must use the chart paths and bind the approved digest:

- `package.root: /etc/registry-evidence/bundle` and
  `package.expectedDigest` equal to `evidence.bundle.expectedDigest`.
- `authority.root: /var/lib/registry-evidence/authority`.
- `listener.bind: 0.0.0.0:8080`,
  `listener.networkExposure: container-private`,
  `listener.tlsTermination: operator-controlled-upstream`, and
  `listener.trustProxyIdentityHeaders: false`.
- `secretProviders.file.root: /run/secrets/registry-evidence`.
- `audit.path: /var/lib/registry-evidence/audit/evidence.jsonl`.
- `signer.unixSocketPath: /run/registry-evidence/transit-proxy.sock` with the
  reviewed Transit mount, key name, pinned nonzero key version, and timeout.
- Private CA and extract paths, when used, under
  `/etc/registry-evidence/inputs`.

Preload the package and optional runtime inputs out of band. Keep them
immutable and read-only. The chart stages the runtime file and Secret
projections into memory-backed owner-only regular files before Evidence sees
them. Provision the audit and authority PVC roots as real directories owned by
UID/GID 65532 with mode `0700`. The package digest annotation is an operator-visible
binding, while Evidence enforces the digest from `runtime.yaml`.

Evidence cannot serve without the Transit proxy. The chart refuses to render
`evidence.serve: true` while `evidence.transitProxy.enabled` is false, and the
error says so. Set `evidence.transitProxy.enabled: true` and fill in
`evidence.transitProxy`, or keep `evidence.serve: false`.

Production and evidence-grade signing uses the configurable pinned
`evidence.transitProxy.image`. Its command reads the staged proxy configuration
at `/etc/registry-evidence/transit-proxy/proxy.hcl`, its scoped credentials are
available only at `/run/secrets/registry-evidence-transit-proxy`, and it creates
the shared socket under `/run/registry-evidence`. Evidence receives the socket,
not the proxy Secret. Set the proxy UID/GID to the reviewed image contract and
configure the socket group so UID/GID 65532 can connect.

Every Pod disables service-account token mounting. Therefore the reference
Vault Agent configuration that reads a Kubernetes service-account token is not
supported by this chart. Use a proxy authentication method whose credential is
provided by `evidence.transitProxy.secrets`, with a narrowly scoped provider
policy that permits only metadata read and signing for the pinned key version.
No token, AppRole secret, or provider credential belongs in values, the proxy
ConfigMap, or the Evidence Secret.

The proxy and Evidence share one Pod network namespace. Kubernetes
NetworkPolicy cannot distinguish their egress, so
`evidence.networkPolicy.transitEgress` documents and admits the provider path
at Pod scope, while `dependencyEgress` admits Evidence issuer and source paths.
Secret separation, the Unix socket, provider policy, and Evidence's fixed
source bindings remain the authorisation boundaries.

## Ingress and network policy

Each enabled Ingress requires a host and an existing TLS Secret. Set the
cluster's `className`, annotations, host, and path independently for BReg, App
Kit, Casework, and Evidence. BReg's configured `listener.publicOrigin` must match its
externally visible HTTPS origin. Configure rate limiting in the ingress
controller. Every Service is ClusterIP only, and the schema refuses other
types. Expose a component through its Ingress.

NetworkPolicy is enabled by default. An empty ingress peer list admits no
other Pod, so list the ingress controller explicitly. On K3s, traffic that
originates on the Pod's own node is still accepted before policy is applied,
so host processes and `hostNetwork` Pods on that node can reach the plaintext
service ports even with an empty list. Treat access to the node as access to
those ports. Each item under
`networkPolicy.ingress` is a standard `NetworkPolicyPeer`, for example a
namespace selector alone or a namespace and Pod selector together.

`dependencyEgress` lists exact standard peers and ports for PostgreSQL, OIDC,
and other required services. DNS egress is separately restricted to the
configured DNS namespace and Pod selectors. Use suitable CIDRs or in-cluster
selectors for dependencies, and account for provider address changes.
The chosen CNI must enforce NetworkPolicy.

Casework additionally exposes `casework.networkPolicy.bregContextEgress` for
the BReg API and token endpoint needed by current-source context providers.
Configure the scoped BReg client and access profile. Casework readiness checks
its database and audit sink. Qualify each configured provider separately.

Deploy partner endpoints as a separate release of this chart with their own
namespace and HTTPS hostname. The extension values define an exact public path,
a digest-pinned image, and any required egress. An endpoint that uses BReg
calls the HTTPS API with a scoped OAuth client. BReg enforces the token, client,
scope, access profile, and row boundaries.
[Extension endpoint guide](../../examples/intake-status/README.md)

Extension egress rejects an `ipBlock` that opens every address, such as
`0.0.0.0/0`, `::/0` or any prefix shorter than `/8`. This is a guard against
mistakes and not a security boundary, because several broader-than-intended
blocks can still be combined. Review extension egress as you would any
NetworkPolicy. The core workloads' own egress is not subject to this guard.

The database manifests in `deploy/postgres` admit connections only from Pods
labelled `registrystack.org/database-client: "true"`, which the chart sets on
BReg, Casework and App Kit serving Pods and on BReg and Casework operation Pods.
Evidence and extension Pods do not carry it.

For a bounded test environment whose real TLS names are not available through
cluster DNS, `breg.hostAliases` applies standard Pod host aliases to BReg
serving and operation Pods, and `appKit.hostAliases` applies them to App Kit.
Each entry has `ip` and a non-empty `hostnames` list. Both default empty. Use
normal DNS for production endpoint changes.

## Render one BReg operation

No Job is rendered by a normal release. Render one named operation with the
same deployment values and apply it only after operator review:

```bash
helm template operation ./deploy/helm/registry-stack \
  --namespace directory \
  --values deployment-values.yaml \
  --set breg.serve=false \
  --set appKit.serve=false \
  --set casework.serve=false \
  --set breg.operation.enabled=true \
  --set-string breg.operation.name=activate-001 \
  --set-string breg.operation.kind=apply-initial \
  --show-only templates/breg-operation-job.yaml
```

The selected template emits the Job and its deny-ingress, bounded-egress
NetworkPolicy. It has no Helm hook annotation. Every command uses the matching
image's `/usr/local/bin/bregctl --format json` and the staged runtime file.
Both resources carry and select the unique
`registrystack.org/operation-id: <breg.operation.name>` label, so a retained
policy for another operation name does not admit this Job's egress.

| `breg.operation.kind` | Command behaviour |
| --- | --- |
| `verify` | Verifies the package without opening the database. |
| `doctor` | Checks startup dependencies without binding a listener. |
| `status` | Reads the activation ledger. |
| `plan` | Checks the candidate package with `--expected-digest`. |
| `apply-initial` | Explicitly passes `apply --initial` and `--expected-digest`. |
| `apply-successor` | Applies the separately mounted candidate with its exact digest. |
| `claim-status` | Reads the connected database instance claim. |
| `claim-adopt` | Explicitly selects adoption and passes `--acknowledge-original-retired`. |
| `reconcile` | Runs the read-only migration reconcile assessment. |

Set `breg.operation.operatorReference` to record an operator reference with
`apply-initial` and `apply-successor`. It is empty by default and the flag is
then omitted. `reconcile` always passes the fixed read-only reference
`helm-read-only-inspection` that its command requires. The other kinds do not
accept the flag.

An operation Job is refused while the same component has `serve: true`. Set
`serve: false` for BReg, Casework or Evidence before rendering its operation.

For a successor plan or apply, keep `breg.runtimeConfig` and `breg.package`
bound to the active configuration and package. Bind the target claim and
digest separately with `breg.operation.candidate.existingClaim` and
`breg.operation.candidate.expectedDigest`. The operator does this using
the deployed Helm values and the reviewed successor. Use the product's
operator procedure for changes that require a BReg `--backup` binding. The
chart has no path that passes `--backup`, so a destructive BReg migration on
Kubernetes cannot be run through it.

## Keep an operation report

An operation Job is removed after `ttlSecondsAfterFinished` (24 hours by
default), and its Pod logs go with it. Save the report before then, for
example with `kubectl logs job/<job-name> --namespace <namespace> >
<operation-name>-report.json`. BReg, Casework and `evidence check` write JSON.
Evidence authority commands write text. Store the file with the change record.
Raise `ttlSecondsAfterFinished` only when you cannot collect it in time.

## Render one Casework operation

Normal releases render no Casework Job. First stop the release with the
operator's `stop` command (see "Back up a consistent installation" in
[`deploy/OPERATIONS.md`](../../OPERATIONS.md)). It applies `serve: false` through
Helm and waits until no Pod of the release is running. Confirm that with
`sudo k3s kubectl -n directory get pods -l app.kubernetes.io/instance=directory`.
Then render one named operation, review both the Job and its unique-operation
NetworkPolicy, and create them using the product-owned operator procedure:

```bash
helm template casework-operation ./deploy/helm/registry-stack \
  --namespace directory \
  --values deployment-values.yaml \
  --set breg.serve=false \
  --set appKit.serve=false \
  --set casework.serve=false \
  --set casework.operation.enabled=true \
  --set-string casework.operation.name=apply-001 \
  --set-string casework.operation.kind=apply \
  --set-string casework.operation.operatorReference=CHANGE-1234 \
  --set-json 'casework.operation.backupReferences=["backup-before-activation"]' \
  --show-only templates/casework-operation-job.yaml
```

Every command uses `/usr/local/bin/caseworkctl --format json` from the pinned
Casework image and `/etc/registry-casework/runtime.yaml`:

| `casework.operation.kind` | Command behaviour |
| --- | --- |
| `plan` | Reads runtime state and reports the package activation plan. |
| `doctor` | Checks the documented startup dependencies without serving. |
| `apply` | Applies the plan using the separate migration role and optional operator and backup references. |

Operation names are part of the Job and NetworkPolicy selector through
`registrystack.org/operation-id`. Use a unique name for each attempt.
Operator and backup references are retained in audit records. Do not place
credentials or personal data in them. Run `stop` before `apply`, as above, and
do not set `casework.serve: true` until the operation succeeds and its report
has been reviewed.

Rendering proves manifest shape only. It does not prove database migration,
backup validity, restore, BReg context access, ingress routing, or a composed
Casework journey. `doctor` also does not exercise every issuer, provider, or
source integration.

## Render one Evidence operation

Normal releases render no Evidence Job. Install the reviewed bundle and
runtime inputs, then stop the release with the operator's `stop` command and
confirm that no Pod of the release is running, as for Casework above. Activate
the separately reviewed authority, inspect its result or history, then permit
serving:

```bash
helm template evidence-operation ./deploy/helm/registry-stack \
  --namespace directory \
  --values deployment-values.yaml \
  --set breg.serve=false \
  --set appKit.serve=false \
  --set casework.serve=false \
  --set evidence.serve=false \
  --set evidence.operation.enabled=true \
  --set-string evidence.operation.name=activate-001 \
  --set-string evidence.operation.kind=authority-activate \
  --set-string evidence.operation.operatorReference=CHANGE-5678 \
  --show-only templates/evidence-operation-job.yaml
```

| `evidence.operation.kind` | Exact product command and scope |
| --- | --- |
| `check` | `evidence check --runtime-config /etc/registry-evidence/runtime.yaml --format json` validates the bundle and runtime inputs offline. |
| `authority-activate` | `evidence authority activate --runtime-config ... --document /etc/registry-evidence/compiled-authority.yaml` writes retained authority state and activation audit. |
| `authority-history` | `evidence authority history --runtime-config ...` reads committed history after an uncertain or completed activation. |

Only `check` has the released `--format json` option. The v0.46.0 authority
commands have no output-format flag, so the chart preserves their native text
reports and exit status instead of claiming JSON output.

Activation receives only `evidence.activationSecrets`, the compiled authority,
and writable audit and authority PVCs. It does not receive source credentials
or Transit proxy credentials. History receives the authority PVC read-only.
The check Job receives neither Secret nor writable storage. Each Job and its
deny-all NetworkPolicy carry the unique
`registrystack.org/operation-id: <evidence.operation.name>` selector and have no
Helm hook annotation.

The Casework operations have no status kind, and BReg exposes no metrics
port, so neither is wired here.

The v0.46.0 `evidence` binary has no `authority check` subcommand, and the
released Evidence image contains no `evidencectl`, so the chart does not invent
either operation. The check Job deliberately omits
`--require-runtime-dependencies` and `--require-audit-under`: a production dependency check needs the
long-running workload-local Transit proxy, which would prevent a standard Job
sidecar from completing on every Kubernetes version supported by this chart.
The serving process performs the actual package, authority, secret, signer,
audit, and source-credential startup checks, and `/ready` rechecks the signer,
audit writer, subject-binding key, and source credentials. Route traffic only
after readiness succeeds. A rendered Job is not a live signer, source,
authority, audit durability, or assertion proof.

## Checks

The chart schema rejects tags, malformed digests, unknown top-level values,
and missing required references for enabled workloads. Run the contract suite
with the pinned Helm binary:

```bash
HELM_BIN=/path/to/helm bash deploy/helm/registry-stack/tests/chart-contract.sh
```

The suite lints the chart, renders serving and inactive releases, renders each
sensitive operation shape, checks security and persistence invariants, and
proves malformed digests are refused. It does not start Kubernetes, BReg,
Casework, Evidence, PostgreSQL, a Transit provider, an ingress controller, or
App Kit.
