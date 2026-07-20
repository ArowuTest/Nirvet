{{- define "nirvet.name" -}}nirvet{{- end -}}
{{- define "nirvet.fullname" -}}{{ .Release.Name }}-nirvet{{- end -}}

{{- define "nirvet.labels" -}}
app.kubernetes.io/name: {{ include "nirvet.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: nirvet-{{ .Chart.Version }}
{{- end -}}

{{- define "nirvet.selectorLabels" -}}
app.kubernetes.io/name: {{ include "nirvet.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{/* Pod-level securityContext — non-root, seccomp RuntimeDefault. */}}
{{- define "nirvet.podSecurityContext" -}}
runAsNonRoot: true
runAsUser: 65532
runAsGroup: 65532
fsGroup: 65532
seccompProfile:
  type: RuntimeDefault
{{- end -}}

{{/* Container-level securityContext — read-only rootfs, no privilege escalation, ALL caps dropped. */}}
{{- define "nirvet.containerSecurityContext" -}}
runAsNonRoot: true
readOnlyRootFilesystem: true
allowPrivilegeEscalation: false
privileged: false
capabilities:
  drop: ["ALL"]
{{- end -}}

{{/* The digest-pinned image reference (never a floating tag). */}}
{{- define "nirvet.image" -}}
{{- .Values.image.repository }}@{{ .Values.image.digest }}
{{- end -}}

{{/* envFrom: the non-secret ConfigMap + the operator-supplied Secret (required — no working default). */}}
{{- define "nirvet.envFrom" -}}
- configMapRef:
    name: {{ include "nirvet.fullname" . }}-config
- secretRef:
    name: {{ required "existingSecretName is REQUIRED — supply a Secret with the DB/JWT/master-key/Vault-token env; the chart never templates secret values" .Values.existingSecretName }}
{{- end -}}
