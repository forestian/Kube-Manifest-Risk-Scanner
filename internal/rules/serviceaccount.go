package rules

import "kube-manifest-risk-scanner/internal/model"

func analyzeServiceAccount(ctx podContext, opts Options) []model.Finding {
	var findings []model.Finding
	if value, ok := boolAt(ctx.podSpec, "automountServiceAccountToken"); ok {
		if value {
			findings = append(findings, newFinding(ctx.resource, "medium", "automount-service-account-token", "Service account token automounted",
				ctx.podSpecPath+".automountServiceAccountToken", "automountServiceAccountToken=true",
				"Mounted service account tokens can be abused if a pod is compromised.",
				"Set automountServiceAccountToken false unless the workload needs Kubernetes API access.", ""))
		}
	} else if opts.Profile == "production" {
		findings = append(findings, newFinding(ctx.resource, "medium", "automount-service-account-token", "Service account token automount not disabled",
			ctx.podSpecPath+".automountServiceAccountToken", "automountServiceAccountToken omitted",
			"Mounted service account tokens can be abused if a pod is compromised.",
			"Set automountServiceAccountToken false unless the workload needs Kubernetes API access.", ""))
	}

	serviceAccountName, hasSAN := stringAt(ctx.podSpec, "serviceAccountName")
	if !hasSAN {
		serviceAccountName, hasSAN = stringAt(ctx.podSpec, "serviceAccount")
	}
	if hasSAN && serviceAccountName == "default" {
		findings = append(findings, newFinding(ctx.resource, "medium", "default-service-account", "Default service account used",
			ctx.podSpecPath+".serviceAccountName", "serviceAccountName=default",
			"Using the default service account can make permissions unclear.",
			"Create a dedicated service account with least privilege.", ""))
	} else if !hasSAN && opts.Profile == "production" {
		findings = append(findings, newFinding(ctx.resource, "medium", "default-service-account", "Service account missing in production",
			ctx.podSpecPath+".serviceAccountName", "serviceAccountName omitted",
			"Using the default service account can make permissions unclear.",
			"Create a dedicated service account with least privilege.", ""))
	}
	return findings
}
