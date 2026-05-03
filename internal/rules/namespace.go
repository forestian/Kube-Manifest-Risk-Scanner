package rules

import "kube-manifest-risk-scanner/internal/model"

var namespacedKinds = map[string]bool{
	"Pod":            true,
	"Deployment":     true,
	"StatefulSet":    true,
	"DaemonSet":      true,
	"ReplicaSet":     true,
	"Job":            true,
	"CronJob":        true,
	"Service":        true,
	"Ingress":        true,
	"ServiceAccount": true,
	"ConfigMap":      true,
	"Secret":         true,
}

func analyzeNamespace(resource model.Resource, opts Options) []model.Finding {
	if !namespacedKinds[resource.Kind] {
		return nil
	}
	namespace := resource.Namespace
	if namespace == "" {
		return []model.Finding{newFinding(resource, profileRisk(opts, "low", "medium"), "namespace-missing", "Missing namespace",
			"metadata.namespace", "",
			"Missing namespace may deploy resources into the default namespace accidentally.",
			"Set explicit namespace in manifests.", "")}
	}
	if namespace == "default" {
		return []model.Finding{newFinding(resource, profileRisk(opts, "low", "medium"), "default-namespace", "Default namespace used",
			"metadata.namespace", "namespace=default",
			"Using the default namespace can make ownership and isolation unclear.",
			"Use application or team-specific namespaces.", "")}
	}
	return nil
}
