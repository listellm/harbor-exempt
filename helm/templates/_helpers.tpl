{{/*
Expand the name of the chart.
*/}}
{{- define "harbor-exempt.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Override AppVersion
*/}}
{{- define "harbor-exempt.appVersion" -}}
{{- coalesce .Values.image.tag .Chart.AppVersion }}
{{- end }}

{{/*
Create a default fully qualified app name.
*/}}
{{- define "harbor-exempt.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{/*
Create chart name and version as used by the chart label.
*/}}
{{- define "harbor-exempt.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "harbor-exempt.labels" -}}
helm.sh/chart: {{ include "harbor-exempt.chart" . }}
{{ include "harbor-exempt.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ include "harbor-exempt.appVersion" . | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels
*/}}
{{- define "harbor-exempt.selectorLabels" -}}
app.kubernetes.io/name: {{ include "harbor-exempt.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Create the name of the service account to use
*/}}
{{- define "harbor-exempt.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "harbor-exempt.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
PostgreSQL selector labels
*/}}
{{- define "harbor-exempt.postgresql.selectorLabels" -}}
app.kubernetes.io/name: {{ include "harbor-exempt.name" . }}-postgresql
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
PostgreSQL labels
*/}}
{{- define "harbor-exempt.postgresql.labels" -}}
helm.sh/chart: {{ include "harbor-exempt.chart" . }}
{{ include "harbor-exempt.postgresql.selectorLabels" . }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{- /*
  Compute a checksum based on the rendered content of specific ConfigMaps.
*/ -}}
{{- define "harbor-exempt.configsChecksum" -}}
{{- $files := list
  "configmap.yaml"
  "configmap-seed.yaml"
-}}
{{- $checksum := "" -}}
{{- range $files -}}
  {{- $content := include (print $.Template.BasePath (printf "/%s" .)) $ -}}
  {{- $checksum = printf "%s%s" $checksum $content | sha256sum -}}
{{- end -}}
{{- $checksum | sha256sum -}}
{{- end -}}
