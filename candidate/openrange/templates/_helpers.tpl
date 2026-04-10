{{/*
Namespace name for a zone.
Usage: include "openrange.ns" (dict "zone" $zoneName "global" $.Values.global)
*/}}
{{- define "openrange.ns" -}}
{{ .global.namePrefix }}-{{ .zone }}
{{- end -}}

{{/*
Common labels applied to all resources.
*/}}
{{- define "openrange.labels" -}}
app.kubernetes.io/part-of: openrange
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/managed-by: helm
openrange/snapshot: {{ .Values.global.snapshotId | default "generated" }}
{{- end -}}
