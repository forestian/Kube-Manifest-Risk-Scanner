package rules

import "kube-manifest-risk-scanner/internal/model"

func analyzeReplicas(resource model.Resource, opts Options) []model.Finding {
	if opts.Profile != "production" {
		return nil
	}
	replicas, ok := intAt(resource.Object, "spec", "replicas")
	if !ok {
		return []model.Finding{newFinding(resource, "medium", "replicas-missing-production", "Replicas missing in production",
			"spec.replicas", "",
			"Omitted replicas defaults may be unclear and can result in insufficient redundancy.",
			"Set replicas explicitly for production workloads.", "")}
	}
	if replicas == 1 {
		return []model.Finding{newFinding(resource, "medium", "replicas-one-production", "Single replica in production",
			"spec.replicas", "replicas=1",
			"A single replica can reduce availability during node failure or rollout.",
			"Use at least 2 replicas for production services where possible.", "")}
	}
	return nil
}

func analyzePDBNotes(resources []model.Resource) []model.Finding {
	var findings []model.Finding
	for _, resource := range resources {
		if resource.Kind != "Deployment" && resource.Kind != "StatefulSet" {
			continue
		}
		replicas, ok := intAt(resource.Object, "spec", "replicas")
		if !ok || replicas <= 1 {
			continue
		}
		findings = append(findings, newFinding(resource, "info", "no-pod-disruption-budget-note", "Consider a PodDisruptionBudget",
			"", "replicas>1 and no PodDisruptionBudget found in scanned files",
			"PodDisruptionBudget can help protect availability during voluntary disruptions.",
			"Consider adding a PDB for production workloads.", ""))
	}
	return findings
}
