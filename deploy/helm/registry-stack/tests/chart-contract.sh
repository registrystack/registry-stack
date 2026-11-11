#!/usr/bin/env bash
set -euo pipefail

chart_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)
helm_bin=${HELM_BIN:-helm}
fixture="$chart_dir/tests/fixtures/complete.yaml"
rendered=$(mktemp)
operation=$(mktemp)
inactive=$(mktemp)
casework_operation=$(mktemp)
app_kit=$(mktemp)
app_kit_container=$(mktemp)
evidence_operation=$(mktemp)
evidence_deployment=$(mktemp)
evidence_container=$(mktemp)
extension=$(mktemp)
trap 'rm -f "$rendered" "$operation" "$inactive" "$casework_operation" "$app_kit" "$app_kit_container" "$evidence_operation" "$evidence_deployment" "$evidence_container" "$extension"' EXIT

fail() {
	printf 'chart contract failed: %s\n' "$1" >&2
	exit 1
}

contains() {
	local file=$1
	local text=$2
	rg -F --quiet -- "$text" "$file" || fail "expected '$text' in $file"
}

absent() {
	local file=$1
	local text=$2
	if rg -F --quiet -- "$text" "$file"; then
		fail "did not expect '$text' in $file"
	fi
}

"$helm_bin" lint "$chart_dir" --values "$fixture"
"$helm_bin" template pilot "$chart_dir" \
	--namespace registry-pilot \
	--values "$fixture" >"$rendered"

contains "$rendered" 'name: pilot-registry-stack-breg'
contains "$rendered" 'name: pilot-registry-stack-app-kit'
contains "$rendered" 'name: pilot-registry-stack-casework'
contains "$rendered" 'name: pilot-registry-stack-evidence'
contains "$rendered" 'name: APPKIT_HOST_CONFIG'
contains "$rendered" 'value: "/etc/registry-app-kit/config/host.json"'
contains "$rendered" 'namespace: registry-pilot'
contains "$rendered" 'image: "ghcr.io/registrystack/breg@sha256:'
contains "$rendered" 'image: "registry.example/app-kit@sha256:'
contains "$rendered" 'image: "ghcr.io/registrystack/casework@sha256:'
contains "$rendered" 'image: "ghcr.io/registrystack/evidence@sha256:'
contains "$rendered" 'image: "hashicorp/vault@sha256:'
contains "$rendered" 'image: "docker.io/library/busybox@sha256:'
contains "$rendered" 'type: Recreate'
contains "$rendered" 'automountServiceAccountToken: false'
contains "$rendered" 'runAsUser: 65532'
contains "$rendered" 'runAsNonRoot: true'
contains "$rendered" 'readOnlyRootFilesystem: true'
contains "$rendered" 'allowPrivilegeEscalation: false'
contains "$rendered" 'defaultMode: 0444'
contains "$rendered" 'seccompProfile:'
contains "$rendered" 'type: RuntimeDefault'
contains "$rendered" 'claimName: breg-audit'
contains "$rendered" 'claimName: breg-package'
contains "$rendered" 'claimName: casework-audit'
contains "$rendered" 'claimName: casework-package'
contains "$rendered" 'claimName: evidence-bundle'
contains "$rendered" 'claimName: evidence-runtime-files'
contains "$rendered" 'claimName: evidence-audit'
contains "$rendered" 'claimName: evidence-authority'
contains "$rendered" 'mountPath: /var/lib/breg/package'
contains "$rendered" 'mountPath: /var/log/breg'
contains "$rendered" 'path: /healthz'
contains "$rendered" 'path: /ready'
contains "$rendered" 'secretName: breg-api-tls'
contains "$rendered" 'secretName: app-kit-tls'
contains "$rendered" 'secretName: casework-api-tls'
contains "$rendered" 'secretName: evidence-api-tls'
contains "$rendered" 'kubernetes.io/metadata.name: trusted-extension'
contains "$rendered" 'kubernetes.io/metadata.name: ingress-system'
contains "$rendered" 'cidr: 192.0.2.0/24'
contains "$rendered" 'protocol: TCP'
contains "$rendered" 'port: 5432'
contains "$rendered" 'ip: 192.0.2.11'
contains "$rendered" '- issuer.test'
contains "$rendered" 'ip: 192.0.2.12'
contains "$rendered" '- api.test'
absent "$rendered" 'kind: Secret'
absent "$rendered" 'kind: PersistentVolumeClaim'
absent "$rendered" 'kind: ServiceAccount'
absent "$rendered" 'secretName: breg-migration-inputs'
absent "$rendered" 'secretName: casework-migration-inputs'
absent "$rendered" 'secretName: evidence-activation-inputs'
absent "$rendered" 'name: evidence-compiled-authority'
absent "$rendered" 'fsGroup:'
absent "$rendered" 'SSL_CERT_FILE'
absent "$rendered" 'NODE_EXTRA_CA_CERTS'
absent "$rendered" 'helm.sh/hook'
absent "$rendered" 'kind: Job'

"$helm_bin" template evidence-serving "$chart_dir" \
	--namespace registry-pilot \
	--values "$fixture" \
	--show-only templates/evidence-deployment.yaml >"$evidence_deployment"
contains "$evidence_deployment" 'registrystack.org/package-digest: "sha256:2222'
contains "$evidence_deployment" 'mountPath: /etc/registry-evidence/bundle'
contains "$evidence_deployment" 'mountPath: /etc/registry-evidence/runtime.yaml'
contains "$evidence_deployment" 'mountPath: /run/secrets/registry-evidence'
contains "$evidence_deployment" 'mountPath: /var/lib/registry-evidence/audit'
contains "$evidence_deployment" 'mountPath: /var/lib/registry-evidence/authority'
contains "$evidence_deployment" 'mountPath: /run/registry-evidence'
contains "$evidence_deployment" 'path: /health'
contains "$evidence_deployment" 'path: /ready'
contains "$evidence_deployment" 'secretName: evidence-runtime-inputs'
contains "$evidence_deployment" 'secretName: evidence-transit-proxy-inputs'
contains "$evidence_deployment" 'automountServiceAccountToken: false'
contains "$evidence_deployment" 'readOnly: true'
sed -n '/        - name: evidence$/,/        - name: transit-proxy$/p' "$evidence_deployment" >"$evidence_container"
contains "$evidence_container" 'name: transit-socket'
absent "$evidence_container" 'name: proxy-secret-private'
absent "$evidence_container" 'name: proxy-secret-source'
absent "$evidence_container" 'secretName: evidence-transit-proxy-inputs'

"$helm_bin" template evidence-operation "$chart_dir" \
	--namespace registry-pilot \
	--values "$fixture" \
	--set breg.serve=false \
	--set appKit.serve=false \
	--set casework.serve=false \
	--set evidence.serve=false \
	--set evidence.operation.enabled=true \
	--set-string evidence.operation.name=check-001 \
	--set-string evidence.operation.kind=check \
	--show-only templates/evidence-operation-job.yaml >"$evidence_operation"
contains "$evidence_operation" 'kind: Job'
contains "$evidence_operation" 'name: evidence-operation-registry-stack-evidence-check-001'
contains "$evidence_operation" 'registrystack.org/operation-id: "check-001"'
contains "$evidence_operation" 'registrystack.org/package-digest: "sha256:2222'
contains "$evidence_operation" '- check'
contains "$evidence_operation" '- --runtime-config'
contains "$evidence_operation" '- --format'
contains "$evidence_operation" '- json'
contains "$evidence_operation" 'claimName: evidence-authority'
contains "$evidence_operation" 'mountPath: /var/lib/registry-evidence/authority'
absent "$evidence_operation" 'secretName: evidence-runtime-inputs'
absent "$evidence_operation" 'secretName: evidence-transit-proxy-inputs'
absent "$evidence_operation" 'claimName: evidence-audit'

"$helm_bin" template evidence-operation "$chart_dir" \
	--namespace registry-pilot \
	--values "$fixture" \
	--set breg.serve=false \
	--set appKit.serve=false \
	--set casework.serve=false \
	--set evidence.serve=false \
	--set evidence.operation.enabled=true \
	--set-string evidence.operation.name=activate-001 \
	--set-string evidence.operation.kind=authority-activate \
	--set-string evidence.operation.operatorReference=CHANGE-5678 \
	--show-only templates/evidence-operation-job.yaml >"$evidence_operation"
contains "$evidence_operation" '- authority'
contains "$evidence_operation" '- activate'
contains "$evidence_operation" '- --document'
contains "$evidence_operation" '/etc/registry-evidence/compiled-authority.yaml'
contains "$evidence_operation" '- --operator-reference'
contains "$evidence_operation" '- "CHANGE-5678"'
contains "$evidence_operation" 'secretName: evidence-activation-inputs'
absent "$evidence_operation" 'secretName: evidence-runtime-inputs'
contains "$evidence_operation" 'claimName: evidence-audit'
contains "$evidence_operation" 'claimName: evidence-authority'
absent "$evidence_operation" 'secretName: evidence-transit-proxy-inputs'
absent "$evidence_operation" 'secretName: evidence-runtime-inputs'

"$helm_bin" template evidence-operation "$chart_dir" \
	--namespace registry-pilot \
	--values "$fixture" \
	--set breg.serve=false \
	--set appKit.serve=false \
	--set casework.serve=false \
	--set evidence.serve=false \
	--set evidence.operation.enabled=true \
	--set-string evidence.operation.name=history-001 \
	--set-string evidence.operation.kind=authority-history \
	--show-only templates/evidence-operation-job.yaml >"$evidence_operation"
contains "$evidence_operation" '- authority'
contains "$evidence_operation" '- history'
contains "$evidence_operation" 'claimName: evidence-authority'
absent "$evidence_operation" 'claimName: evidence-bundle'
absent "$evidence_operation" 'secretName: evidence-runtime-inputs'
absent "$evidence_operation" 'claimName: evidence-audit'
absent "$evidence_operation" 'secretName: evidence-transit-proxy-inputs'
absent "$evidence_operation" 'helm.sh/hook'

"$helm_bin" template app-kit-staging "$chart_dir" \
	--namespace registry-pilot \
	--values "$fixture" \
	--show-only templates/app-kit-deployment.yaml >"$app_kit"
contains "$app_kit" 'runAsUser: 1000'
contains "$app_kit" 'runAsGroup: 1000'
contains "$app_kit" 'mountPath: /staging/secrets'
contains "$app_kit" 'target="/work/secrets/private/'
contains "$app_kit" 'chmod 0400'
contains "$app_kit" 'mountPath: /etc/registry-app-kit/config'
contains "$app_kit" 'mountPath: /etc/registry-app-kit/secrets'
sed -n '/^      containers:/,/^      volumes:/p' "$app_kit" >"$app_kit_container"
contains "$app_kit_container" 'name: secret-private'
absent "$app_kit_container" 'name: secret-source'
contains "$app_kit" 'readinessProbe:'
contains "$app_kit" 'path: /health'
contains "$app_kit" 'name: Host'
contains "$app_kit" 'value: "registry.example"'
absent "$app_kit" 'livenessProbe:'
contains "$app_kit" 'ip: 192.0.2.12'
contains "$app_kit" '- api.test'

"$helm_bin" template app-kit-liveness "$chart_dir" \
	--namespace registry-pilot \
	--values "$fixture" \
	--set-string appKit.probes.livenessPath=/live \
	--show-only templates/app-kit-deployment.yaml >"$app_kit"
contains "$app_kit" 'livenessProbe:'
contains "$app_kit" 'path: /live'

"$helm_bin" template app-kit-private "$chart_dir" \
	--namespace registry-pilot --values "$fixture" --set appKit.ingress.enabled=false \
	--set-string appKit.probes.host=private.staff.example:4430 \
	--show-only templates/app-kit-deployment.yaml >"$app_kit"
contains "$app_kit" 'value: "private.staff.example:4430"'

"$helm_bin" template casework-operation "$chart_dir" \
	--namespace registry-pilot \
	--values "$fixture" \
	--set breg.serve=false \
	--set appKit.serve=false \
	--set casework.serve=false \
	--set casework.operation.enabled=true \
	--set-string casework.operation.name=plan-001 \
	--set-string casework.operation.kind=plan \
	--show-only templates/casework-operation-job.yaml >"$casework_operation"
contains "$casework_operation" 'kind: Job'
contains "$casework_operation" 'name: casework-operation-registry-stack-casework-plan-001'
contains "$casework_operation" 'registrystack.org/operation-id: "plan-001"'
contains "$casework_operation" 'registry.stack/operation: "plan"'
contains "$casework_operation" 'registrystack.org/package-digest: "sha256:'
contains "$casework_operation" '/usr/local/bin/caseworkctl'
contains "$casework_operation" '- --format'
contains "$casework_operation" '- json'
contains "$casework_operation" '- plan'
contains "$casework_operation" '/etc/registry-casework/runtime.yaml'
contains "$casework_operation" 'mountPath: /etc/registry-casework/runtime.yaml'
contains "$casework_operation" 'subPath: private/runtime.yaml'
contains "$casework_operation" 'secretName: casework-runtime-inputs'
absent "$casework_operation" 'secretName: casework-migration-inputs'
absent "$casework_operation" 'helm.sh/hook'

"$helm_bin" template casework-operation "$chart_dir" \
	--namespace registry-pilot \
	--values "$fixture" \
	--set breg.serve=false \
	--set appKit.serve=false \
	--set casework.serve=false \
	--set casework.operation.enabled=true \
	--set-string casework.operation.name=apply-001 \
	--set-string casework.operation.kind=apply \
	--set-string casework.operation.operatorReference=CHANGE-1234 \
	--set-json 'casework.operation.backupReferences=["backup-before-activation"]' \
	--show-only templates/casework-operation-job.yaml >"$casework_operation"
contains "$casework_operation" '- apply'
contains "$casework_operation" '- --operator-reference'
contains "$casework_operation" '- "CHANGE-1234"'
contains "$casework_operation" '- --backup-reference'
contains "$casework_operation" '- "backup-before-activation"'
contains "$casework_operation" 'secretName: casework-runtime-inputs'
contains "$casework_operation" 'secretName: casework-migration-inputs'

"$helm_bin" template casework-operation "$chart_dir" \
	--namespace registry-pilot \
	--values "$fixture" \
	--set breg.serve=false \
	--set appKit.serve=false \
	--set casework.serve=false \
	--set casework.operation.enabled=true \
	--set-string casework.operation.name=doctor-001 \
	--set-string casework.operation.kind=doctor \
	--set-string casework.caBundleKey=private-ca.pem \
	--show-only templates/casework-operation-job.yaml >"$casework_operation"
contains "$casework_operation" '- doctor'
contains "$casework_operation" 'value: "/etc/registry-casework/secrets/private-ca.pem"'
absent "$casework_operation" 'secretName: casework-migration-inputs'

"$helm_bin" template casework-ca "$chart_dir" \
	--namespace registry-pilot \
	--values "$fixture" \
	--set-string casework.caBundleKey=private-ca.pem >"$rendered"
contains "$rendered" 'value: "/etc/registry-casework/secrets/private-ca.pem"'

"$helm_bin" template private-ca "$chart_dir" \
	--namespace registry-pilot \
	--values "$fixture" \
	--set-string breg.caBundleKey=private-ca.pem \
	--set-string appKit.caBundleKey=private-ca.pem >"$rendered"
contains "$rendered" 'name: SSL_CERT_FILE'
contains "$rendered" 'value: "/etc/breg-secrets/private-ca.pem"'
contains "$rendered" 'name: NODE_EXTRA_CA_CERTS'
contains "$rendered" 'value: "/etc/registry-app-kit/secrets/private-ca.pem"'

"$helm_bin" template operation "$chart_dir" \
	--namespace registry-pilot \
	--values "$fixture" \
	--set breg.serve=false \
	--set appKit.enabled=false \
	--set appKit.serve=false \
	--set breg.operation.enabled=true \
	--set-string breg.operation.name=activate-001 \
	--set-string breg.operation.kind=apply-initial \
	--show-only templates/breg-operation-job.yaml >"$operation"

contains "$operation" 'kind: Job'
contains "$operation" 'name: operation-registry-stack-breg-activate-001'
contains "$operation" 'registry.stack/operation: "apply-initial"'
contains "$operation" 'registrystack.org/operation-id: "activate-001"'
contains "$operation" 'value: "apply-initial"'
contains "$operation" 'registrystack.org/package-digest: "sha256:'
contains "$operation" 'secretName: breg-migration-inputs'
contains "$operation" 'secretName: breg-runtime-inputs'
contains "$operation" '/usr/local/bin/bregctl'
contains "$operation" '- --format'
contains "$operation" '- json'
contains "$operation" '--initial'
contains "$operation" '--expected-digest'
contains "$operation" 'ip: 192.0.2.11'
contains "$operation" '- issuer.test'
absent "$operation" 'helm.sh/hook'

"$helm_bin" template operation "$chart_dir" \
	--namespace registry-pilot \
	--values "$fixture" \
	--set breg.serve=false \
	--set appKit.enabled=false \
	--set appKit.serve=false \
	--set breg.operation.enabled=true \
	--set-string breg.operation.name=verify-ca-001 \
	--set-string breg.operation.kind=verify \
	--set-string breg.caBundleKey=private-ca.pem \
	--show-only templates/breg-operation-job.yaml >"$operation"
contains "$operation" 'name: SSL_CERT_FILE'
contains "$operation" 'value: "/etc/breg-secrets/private-ca.pem"'

for kind in verify doctor status plan claim-status claim-adopt reconcile; do
	"$helm_bin" template operation "$chart_dir" \
		--namespace registry-pilot \
		--values "$fixture" \
		--set breg.serve=false \
		--set appKit.enabled=false \
		--set appKit.serve=false \
		--set breg.operation.enabled=true \
		--set-string breg.operation.name="$kind-001" \
		--set-string breg.operation.kind="$kind" \
		--show-only templates/breg-operation-job.yaml >"$operation"
	contains "$operation" "value: \"$kind\""
	contains "$operation" '- --format'
	contains "$operation" '- json'
done

contains "$operation" '- migration'
contains "$operation" '- reconcile'
contains "$operation" '- helm-read-only-inspection'
absent "$operation" '--execute'

"$helm_bin" template operation "$chart_dir" \
	--namespace registry-pilot \
	--values "$fixture" \
	--set breg.serve=false \
	--set appKit.enabled=false \
	--set appKit.serve=false \
	--set breg.operation.enabled=true \
	--set-string breg.operation.name=claim-status-002 \
	--set-string breg.operation.kind=claim-status \
	--show-only templates/breg-operation-job.yaml >"$operation"
absent "$operation" '--acknowledge-original-retired'

"$helm_bin" template operation "$chart_dir" \
	--namespace registry-pilot \
	--values "$fixture" \
	--set breg.serve=false \
	--set appKit.enabled=false \
	--set appKit.serve=false \
	--set breg.operation.enabled=true \
	--set-string breg.operation.name=claim-adopt-002 \
	--set-string breg.operation.kind=claim-adopt \
	--show-only templates/breg-operation-job.yaml >"$operation"
contains "$operation" '--acknowledge-original-retired'

"$helm_bin" template operation "$chart_dir" \
	--namespace registry-pilot \
	--values "$fixture" \
	--set breg.serve=false \
	--set appKit.enabled=false \
	--set appKit.serve=false \
	--set breg.operation.enabled=true \
	--set-string breg.operation.name=apply-successor-002 \
	--set-string breg.operation.kind=apply-successor \
	--set-string breg.operation.candidate.existingClaim=successor-package \
	--set-string breg.operation.candidate.expectedDigest=sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa \
	--show-only templates/breg-operation-job.yaml >"$operation"
contains "$operation" '- apply'
contains "$operation" '--expected-digest'
contains "$operation" 'claimName: breg-package'
contains "$operation" 'claimName: successor-package'
contains "$operation" 'mountPath: /var/lib/breg/candidate'
contains "$operation" '- /var/lib/breg/candidate'
contains "$operation" 'registrystack.org/package-digest: "sha256:aaaa'
absent "$operation" '--initial'

if "$helm_bin" template operation "$chart_dir" --namespace registry-pilot --values "$fixture" \
	--set breg.serve=false --set breg.operation.enabled=true --set-string breg.operation.name=missing-candidate \
	--set-string breg.operation.kind=apply-successor >/dev/null 2>&1; then
	fail 'a successor apply must bind the candidate claim and digest separately'
fi

"$helm_bin" template inactive "$chart_dir" \
	--namespace registry-pilot \
	--values "$fixture" \
	--set breg.serve=false \
	--set appKit.enabled=false \
	--set appKit.serve=false \
	--set casework.serve=false \
	--set evidence.serve=false >"$inactive"

absent "$inactive" 'kind: Deployment'
absent "$inactive" 'kind: Service'
absent "$inactive" 'kind: Ingress'
absent "$inactive" 'kind: Job'

if "$helm_bin" lint "$chart_dir" --values "$fixture" \
	--set-string breg.image.digest=latest >/dev/null 2>&1; then
	fail 'schema accepted a non-digest BReg image reference'
fi

if "$helm_bin" lint "$chart_dir" --values "$fixture" \
	--set-string breg.package.expectedDigest=sha256:ABC >/dev/null 2>&1; then
	fail 'schema accepted an invalid package digest'
fi

if "$helm_bin" lint "$chart_dir" --values "$fixture" \
	--set-string breg.operation.kind=arbitrary-command >/dev/null 2>&1; then
	fail 'schema accepted an arbitrary BReg operation'
fi

if "$helm_bin" lint "$chart_dir" --values "$fixture" \
	--set breg.enabled=false --set breg.serve=true >/dev/null 2>&1; then
	fail 'schema allowed BReg to serve while disabled'
fi

if "$helm_bin" lint "$chart_dir" --values "$fixture" \
	--set-string casework.image.digest=latest >/dev/null 2>&1; then
	fail 'schema accepted a non-digest Casework image reference'
fi

if "$helm_bin" lint "$chart_dir" --values "$fixture" \
	--set-string casework.operation.kind=arbitrary-command >/dev/null 2>&1; then
	fail 'schema accepted an arbitrary Casework operation'
fi

if "$helm_bin" lint "$chart_dir" --values "$fixture" \
	--set casework.enabled=false --set casework.serve=true >/dev/null 2>&1; then
	fail 'schema allowed Casework to serve while disabled'
fi

if "$helm_bin" lint "$chart_dir" --values "$fixture" \
	--set-string casework.service.type=NodePort >/dev/null 2>&1; then
	fail 'schema allowed a non-ClusterIP Casework Service'
fi

if "$helm_bin" lint "$chart_dir" --values "$fixture" \
	--set casework.serve=false \
	--set casework.operation.enabled=true \
	--set-string casework.operation.name=apply-no-migration \
	--set-string casework.operation.kind=apply \
	--set-string casework.migrationSecrets.secretName= >/dev/null 2>&1; then
	fail 'schema allowed Casework apply without a migration Secret'
fi

if "$helm_bin" lint "$chart_dir" --values "$fixture" \
	--set appKit.securityContext.runAsUser=0 >/dev/null 2>&1; then
	fail 'schema accepted a root App Kit UID'
fi

if "$helm_bin" lint "$chart_dir" --values "$fixture" \
	--set-string evidence.image.digest=latest >/dev/null 2>&1; then
	fail 'schema accepted a non-digest Evidence image reference'
fi

if "$helm_bin" lint "$chart_dir" --values "$fixture" \
	--set-string evidence.operation.kind=arbitrary-command >/dev/null 2>&1; then
	fail 'schema accepted an arbitrary Evidence operation'
fi

if "$helm_bin" lint "$chart_dir" --values "$fixture" \
	--set evidence.enabled=false --set evidence.serve=true >/dev/null 2>&1; then
	fail 'schema allowed Evidence to serve while disabled'
fi

if "$helm_bin" lint "$chart_dir" --values "$fixture" \
	--set evidence.transitProxy.enabled=false >/dev/null 2>&1; then
	fail 'schema allowed Evidence serving without the Transit proxy'
fi

if "$helm_bin" lint "$chart_dir" --values "$fixture" \
	--set evidence.serve=false \
	--set evidence.operation.enabled=true \
	--set-string evidence.operation.name=activate-no-secret \
	--set-string evidence.operation.kind=authority-activate \
	--set-string evidence.activationSecrets.secretName= >/dev/null 2>&1; then
	fail 'schema allowed Evidence authority activation without its scoped Secret'
fi

if "$helm_bin" lint "$chart_dir" --values "$fixture" \
	--set-json 'breg.hostAliases=[{"ip":"192.0.2.11","hostnames":[]}]' >/dev/null 2>&1; then
	fail 'schema accepted a host alias without hostnames'
fi

extensions="$chart_dir/tests/fixtures/extensions.yaml"
"$helm_bin" template extensions "$chart_dir" --namespace pilot-extensions --values "$extensions" >"$extension"
contains "$extension" 'name: extension-intake'
contains "$extension" 'kind: NetworkPolicy'
contains "$extension" 'kind: Deployment'
contains "$extension" 'kind: Service'
contains "$extension" 'kind: Ingress'
contains "$extension" 'automountServiceAccountToken: false'
contains "$extension" 'readOnlyRootFilesystem: true'
contains "$extension" 'name: PUBLIC_PATH'
contains "$extension" 'pathType: Exact'
contains "$extension" 'path: "/extensions/intake"'
contains "$extension" 'secretName: intake-client'
contains "$extension" 'secretName: service-tls'
contains "$extension" 'egress: []'
absent "$extension" 'kind: Secret'
absent "$extension" 'port: 5432'
absent "$extension" 'kind: PersistentVolumeClaim'
absent "$extension" 'kind: ServiceAccount'
absent "$extension" 'NodePort'

if "$helm_bin" template extensions "$chart_dir" --namespace registry-pilot \
	--values "$extensions" >/dev/null 2>&1; then
	fail 'extension release rendered in an unbound namespace'
fi
if "$helm_bin" template extensions "$chart_dir" --namespace pilot-extensions \
	--values "$extensions" --values "$fixture" >/dev/null 2>&1; then
	fail 'extension release accepted core modules'
fi
if "$helm_bin" template extensions "$chart_dir" --namespace pilot-extensions \
	--values "$extensions" --set-json 'extensions.endpoints.intake.egress=[{"to":{"podSelector":{}},"ports":[{"port":443}]}]' >/dev/null 2>&1; then
	fail 'extension accepted an unbounded Pod selector'
fi

printf 'chart contract passed\n'
