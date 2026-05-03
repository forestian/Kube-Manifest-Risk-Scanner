# kube-manifest-risk-scanner

`kube-risk-scan` is a local static analysis CLI for Kubernetes YAML and JSON manifests. It scans raw manifests before deployment and reports operational, reliability, and security risks with explanations and remediation suggestions.

It is built for DevOps, SRE, DevSecOps, Kubernetes, Cloud MSP, and platform engineering workflows where small manifest mistakes can become production incidents.

## Why Scan Manifests?

Many Kubernetes incidents start with simple configuration problems: missing resource requests, missing health probes, privileged containers, floating image tags, hostPath mounts, unsafe service exposure, missing replica counts, and workloads running as root.

`kube-risk-scan` catches these issues locally before manifests are applied to a cluster. It does not require cluster access and does not call Kubernetes APIs.

## Security Note

Secret values are never printed. If a Secret manifest contains `data` or `stringData`, the report only states that those fields exist.

## Build

```sh
go build -o kube-risk-scan .
```

Run from source:

```sh
go run . version
```

## Install from GitHub Releases

Download a prebuilt binary from the GitHub Releases page.

Linux/macOS:

```sh
tar -xzf <archive>.tar.gz
chmod +x kube-risk-scan
./kube-risk-scan version
```

Windows:

Download the Windows archive, extract it, and run:

```powershell
kube-risk-scan.exe version
```

## Commands

Create a demo project:

```sh
kube-risk-scan init --output ./kube-risk-demo
```

Scan one file:

```sh
kube-risk-scan scan --file examples/risky-deployment.yaml
```

Scan a directory recursively:

```sh
kube-risk-scan scan --dir ./manifests
```

Use the production profile:

```sh
kube-risk-scan scan --dir ./manifests --profile production
```

Write a markdown report:

```sh
kube-risk-scan scan --dir ./manifests --format markdown --output report.md
```

Fail a pipeline when high risk findings exist:

```sh
kube-risk-scan scan --dir ./manifests --fail-on-risk high
```

Ignore selected rules:

```sh
kube-risk-scan scan --dir ./manifests --ignore missing-liveness-probe,missing-resource-limits
```

Include info-level findings:

```sh
kube-risk-scan scan --dir ./manifests --profile production --include-info
```

## Scan Flags

- `--file string`: scan one manifest file.
- `--dir string`: scan a directory recursively.
- `--format string`: `text`, `json`, or `markdown`. Default: `text`.
- `--output string`: write report to a file.
- `--profile string`: `default`, `production`, or `dev`. Default: `default`.
- `--fail-on-risk string`: `none`, `low`, `medium`, or `high`. Default: `none`.
- `--include-info`: include info-level findings.
- `--ignore string`: comma-separated rule IDs to suppress.
- `--config string`: optional YAML config file for simple future-friendly defaults.

Exactly one scan source is required: `--file` or `--dir`.

## Init Flags

- `--output string`: output directory. Default: `./kube-risk-demo`.
- `--force`: overwrite the output directory.

## Supported Inputs

- `.yaml`
- `.yml`
- `.json`

YAML multi-document files are supported. Directories are walked recursively. Non-YAML and non-JSON files are ignored.

## Supported Resources

- Pod
- Deployment
- StatefulSet
- DaemonSet
- ReplicaSet
- Job
- CronJob
- Service
- Ingress
- Namespace
- ServiceAccount
- ConfigMap
- Secret

Workload templates are analyzed for Deployment, StatefulSet, DaemonSet, ReplicaSet, Job, and CronJob.

## Rules

| Rule ID | Risk | Summary |
|---|---|---|
| `missing-resource-requests` | medium | CPU or memory requests are missing. |
| `missing-resource-limits` | low, medium in production | CPU or memory limits are missing. |
| `missing-readiness-probe` | medium | A long-running container has no readiness probe. |
| `missing-liveness-probe` | low, medium in production | A long-running container has no liveness probe. |
| `latest-image-tag` | high | Image uses `:latest` or has no explicit tag or digest. |
| `privileged-container` | high | Container runs privileged. |
| `allow-privilege-escalation` | high | Container allows privilege escalation. |
| `run-as-root` | medium | Container may run as root. |
| `hostpath-volume` | high | Pod uses a hostPath volume. |
| `host-network` | high | Pod uses the host network namespace. |
| `host-pid` | high | Pod uses the host PID namespace. |
| `host-ipc` | high | Pod uses the host IPC namespace. |
| `dangerous-capability` | high | Container adds high-risk Linux capabilities. |
| `capabilities-not-dropped` | low, medium in production | Container does not drop all Linux capabilities. |
| `missing-seccomp-profile` | low, medium in production | No RuntimeDefault or explicit seccomp profile is set. |
| `automount-service-account-token` | medium | Service account token is mounted or not disabled in production. |
| `default-service-account` | medium | Workload uses the default service account or omits one in production. |
| `service-loadbalancer` | medium | Service type is LoadBalancer. |
| `service-nodeport` | medium | Service type is NodePort. |
| `ingress-without-tls` | medium | Ingress has rules but no TLS section. |
| `namespace-missing` | low, medium in production | Namespaced resource has no namespace. |
| `default-namespace` | low, medium in production | Resource uses the default namespace. |
| `replicas-one-production` | medium | Deployment or StatefulSet has one replica in production. |
| `replicas-missing-production` | medium | Deployment or StatefulSet omits replicas in production. |
| `cronjob-no-concurrency-policy` | low | CronJob concurrencyPolicy is missing. |
| `cronjob-no-deadline` | low | CronJob startingDeadlineSeconds is missing. |
| `secret-plain-manifest` | medium | Secret contains data or stringData. |
| `configmap-large-inline-config` | low | ConfigMap contains very large inline values. |
| `image-pull-policy-always` | info | Always pulls a mutable image. |
| `no-pod-disruption-budget-note` | info | Production workload has multiple replicas but no PDB was scanned. |

## Profiles

`default` provides balanced scanning without emphasizing production-only hardening.

`dev` keeps high-risk security findings high while leaving production-hardening checks at lower severity.

`production` raises the severity of availability and hardening checks such as missing limits, missing liveness probes, missing namespace, default namespace, missing replicas, missing seccomp, and missing service account configuration. It also emits PodDisruptionBudget notes when `--include-info` is set.

## Fail-on-risk

`--fail-on-risk` controls the CLI exit code after the report is printed or written.

- `none`: never fail due to findings.
- `low`: fail on low, medium, or high findings.
- `medium`: fail on medium or high findings.
- `high`: fail on high findings.

Info findings never trigger fail-on-risk.

## Ignore Rules

Suppress rules with a comma-separated list:

```sh
kube-risk-scan scan --dir ./manifests --ignore missing-liveness-probe,missing-resource-limits
```

Ignored rules do not appear in findings or summary counts.

## Output Examples

Text output:

```text
Kube Manifest Risk Scanner

Profile: production
Scanned files: 8
Scanned resources: 21

Summary:
- High risk: 3
- Medium risk: 7
- Low risk: 4
- Info: 2
```

JSON output includes the full `ScanReport` structure:

```sh
kube-risk-scan scan --dir ./manifests --format json
```

Markdown output is suitable for GitHub PR comments:

```markdown
# Kube Manifest Risk Scanner

## Summary

| Risk | Count |
|---|---:|
| High | 3 |
| Medium | 7 |
| Low | 4 |
| Info | 2 |
```

## Config File

`--config` supports simple YAML defaults for:

```yaml
format: markdown
profile: production
fail_on_risk: high
include_info: true
ignore:
  - missing-liveness-probe
```

Explicit CLI flags override config values.

## Limitations

- Static file analysis only.
- No Kubernetes API calls.
- No kubectl, Helm, or Kustomize execution.
- No admission controller or policy server.
- No cloud provider integration.
- No schema validation.
- No AI-generated remediation.
- Line numbers are reserved for future parser enhancements.

## Roadmap

- GitHub Action.
- GitHub PR comment integration.
- SARIF output.
- OPA/Rego and Kyverno export paths.
- Optional Helm and Kustomize rendering as separate local-only workflows.
- Kubernetes API scanning mode.
- Admission controller mode.
