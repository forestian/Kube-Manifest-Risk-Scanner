package rules

import "kube-manifest-risk-scanner/internal/model"

func analyzeCronJob(resource model.Resource) []model.Finding {
	var findings []model.Finding
	if _, ok := stringAt(resource.Object, "spec", "concurrencyPolicy"); !ok {
		findings = append(findings, newFinding(resource, "low", "cronjob-no-concurrency-policy", "CronJob concurrency policy missing",
			"spec.concurrencyPolicy", "",
			"Missing concurrency policy may allow overlapping job runs.",
			"Set concurrencyPolicy to Forbid or Replace if overlapping runs are unsafe.", ""))
	}
	if _, ok := intAt(resource.Object, "spec", "startingDeadlineSeconds"); !ok {
		findings = append(findings, newFinding(resource, "low", "cronjob-no-deadline", "CronJob starting deadline missing",
			"spec.startingDeadlineSeconds", "",
			"Missing starting deadline can make delayed job behavior less predictable.",
			"Set startingDeadlineSeconds if missed schedule behavior matters.", ""))
	}
	return findings
}
