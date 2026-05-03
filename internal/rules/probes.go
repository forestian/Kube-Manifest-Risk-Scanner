package rules

import "kube-manifest-risk-scanner/internal/model"

func analyzeProbes(ctx podContext, container containerContext, opts Options) []model.Finding {
	var findings []model.Finding
	if _, ok := mapAt(container.spec, "readinessProbe"); !ok {
		findings = append(findings, newFinding(ctx.resource, "medium", "missing-readiness-probe", "Missing readiness probe",
			container.path+".readinessProbe", "",
			"Without a readiness probe, Kubernetes may route traffic to an application before it is ready.",
			"Add a readinessProbe that checks actual service readiness.", container.name))
	}
	if _, ok := mapAt(container.spec, "livenessProbe"); !ok {
		findings = append(findings, newFinding(ctx.resource, profileRisk(opts, "low", "medium"), "missing-liveness-probe", "Missing liveness probe",
			container.path+".livenessProbe", "",
			"Without a liveness probe, Kubernetes may not restart stuck applications.",
			"Add a livenessProbe carefully to avoid restart loops.", container.name))
	}
	return findings
}
