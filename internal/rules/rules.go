package rules

import "kube-manifest-risk-scanner/internal/model"

type Options struct {
	Profile string
}

func AnalyzeResources(resources []model.Resource, opts Options) []model.Finding {
	var findings []model.Finding
	hasPDB := false
	for _, resource := range resources {
		if resource.Kind == "PodDisruptionBudget" {
			hasPDB = true
		}
	}

	for _, resource := range resources {
		findings = append(findings, analyzeNamespace(resource, opts)...)

		switch resource.Kind {
		case "Service":
			findings = append(findings, analyzeService(resource)...)
		case "Ingress":
			findings = append(findings, analyzeIngress(resource)...)
		case "Secret":
			findings = append(findings, analyzeSecret(resource)...)
		case "ConfigMap":
			findings = append(findings, analyzeConfigMap(resource)...)
		case "CronJob":
			findings = append(findings, analyzeCronJob(resource)...)
		case "Deployment", "StatefulSet":
			findings = append(findings, analyzeReplicas(resource, opts)...)
		}

		for _, podContext := range podSpecContexts(resource) {
			findings = append(findings, analyzePodSpec(podContext, opts)...)
		}
	}

	if opts.Profile == "production" && !hasPDB {
		findings = append(findings, analyzePDBNotes(resources)...)
	}

	return findings
}
