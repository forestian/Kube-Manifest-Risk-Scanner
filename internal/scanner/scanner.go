package scanner

import (
	"sort"

	"kube-manifest-risk-scanner/internal/model"
	"kube-manifest-risk-scanner/internal/risk"
	"kube-manifest-risk-scanner/internal/rules"
)

type Options struct {
	Profile     string
	IncludeInfo bool
	Ignore      map[string]bool
}

func Scan(resources []model.Resource, scannedFiles int, opts Options) model.ScanReport {
	if opts.Profile == "" {
		opts.Profile = "default"
	}

	rawFindings := rules.AnalyzeResources(resources, rules.Options{Profile: opts.Profile})
	findings := make([]model.Finding, 0, len(rawFindings))
	summary := model.Summary{}
	for _, finding := range rawFindings {
		if opts.Ignore != nil && opts.Ignore[finding.RuleID] {
			continue
		}
		if finding.Risk == string(model.RiskInfo) && !opts.IncludeInfo {
			continue
		}
		findings = append(findings, finding)
		summary.Add(finding.Risk)
	}

	sort.SliceStable(findings, func(i, j int) bool {
		left := findings[i]
		right := findings[j]
		if risk.Weight(left.Risk) != risk.Weight(right.Risk) {
			return risk.Weight(left.Risk) > risk.Weight(right.Risk)
		}
		if left.File != right.File {
			return left.File < right.File
		}
		if left.ResourceKind != right.ResourceKind {
			return left.ResourceKind < right.ResourceKind
		}
		if left.ResourceName != right.ResourceName {
			return left.ResourceName < right.ResourceName
		}
		if left.RuleID != right.RuleID {
			return left.RuleID < right.RuleID
		}
		if left.ContainerName != right.ContainerName {
			return left.ContainerName < right.ContainerName
		}
		return left.Path < right.Path
	})

	return model.ScanReport{
		Profile:          opts.Profile,
		ScannedFiles:     scannedFiles,
		ScannedResources: len(resources),
		Summary:          summary,
		Findings:         findings,
	}
}
