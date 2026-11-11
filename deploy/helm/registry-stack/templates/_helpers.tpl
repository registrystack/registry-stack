{{- define "registry-stack.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "registry-stack.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name (include "registry-stack.name" .) | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}

{{- define "registry-stack.bregName" -}}
{{- printf "%s-breg" (include "registry-stack.fullname" . | trunc 58 | trimSuffix "-") }}
{{- end }}

{{- define "registry-stack.appKitName" -}}
{{- printf "%s-app-kit" (include "registry-stack.fullname" . | trunc 55 | trimSuffix "-") }}
{{- end }}

{{- define "registry-stack.operationName" -}}
{{- printf "%s-breg-%s" (include "registry-stack.fullname" . | trunc 26 | trimSuffix "-") .Values.breg.operation.name }}
{{- end }}

{{- define "registry-stack.caseworkName" -}}
{{- printf "%s-casework" (include "registry-stack.fullname" . | trunc 54 | trimSuffix "-") }}
{{- end }}

{{- define "registry-stack.caseworkOperationName" -}}
{{- printf "%s-casework-%s" (include "registry-stack.fullname" .) .Values.casework.operation.name | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "registry-stack.evidenceName" -}}
{{- printf "%s-evidence" (include "registry-stack.fullname" . | trunc 54 | trimSuffix "-") }}
{{- end }}

{{- define "registry-stack.evidenceOperationName" -}}
{{- printf "%s-evidence-%s" (include "registry-stack.fullname" .) .Values.evidence.operation.name | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "registry-stack.labels" -}}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | quote }}
app.kubernetes.io/name: {{ include "registry-stack.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/part-of: registry-stack
{{- end }}

{{- define "registry-stack.selectorLabels" -}}
app.kubernetes.io/name: {{ include "registry-stack.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/component: {{ .component }}
{{- end }}

{{- define "registry-stack.image" -}}
{{- printf "%s@%s" .repository .digest -}}
{{- end }}

{{- define "registry-stack.podSecurityContext" -}}
runAsNonRoot: true
runAsUser: 65532
runAsGroup: 65532
seccompProfile:
  type: RuntimeDefault
{{- end }}

{{- define "registry-stack.containerSecurityContext" -}}
allowPrivilegeEscalation: false
capabilities:
  drop:
    - ALL
readOnlyRootFilesystem: true
runAsNonRoot: true
runAsUser: 65532
runAsGroup: 65532
{{- end }}

{{- define "registry-stack.appKitPodSecurityContext" -}}
runAsNonRoot: true
runAsUser: {{ .Values.appKit.securityContext.runAsUser }}
runAsGroup: {{ .Values.appKit.securityContext.runAsGroup }}
seccompProfile:
  type: RuntimeDefault
{{- end }}

{{- define "registry-stack.appKitContainerSecurityContext" -}}
allowPrivilegeEscalation: false
capabilities:
  drop:
    - ALL
readOnlyRootFilesystem: true
runAsNonRoot: true
runAsUser: {{ .Values.appKit.securityContext.runAsUser }}
runAsGroup: {{ .Values.appKit.securityContext.runAsGroup }}
{{- end }}

{{- define "registry-stack.imagePullSecrets" -}}
{{- with .Values.global.imagePullSecrets }}
imagePullSecrets:
{{- range . }}
  - name: {{ .name }}
{{- end }}
{{- end }}
{{- end }}
