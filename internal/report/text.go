package report

import (
	"fmt"
	"strings"

	"kube-manifest-risk-scanner/internal/model"
)

func Text(scanReport model.ScanReport) string {
	var b strings.Builder
	b.WriteString("Kube Manifest Risk Scanner\n\n")
	fmt.Fprintf(&b, "Profile: %s\n", scanReport.Profile)
	fmt.Fprintf(&b, "Scanned files: %d\n", scanReport.ScannedFiles)
	fmt.Fprintf(&b, "Scanned resources: %d\n\n", scanReport.ScannedResources)
	b.WriteString("Summary:\n")
	fmt.Fprintf(&b, "- High risk: %d\n", scanReport.Summary.High)
	fmt.Fprintf(&b, "- Medium risk: %d\n", scanReport.Summary.Medium)
	fmt.Fprintf(&b, "- Low risk: %d\n", scanReport.Summary.Low)
	fmt.Fprintf(&b, "- Info: %d\n\n", scanReport.Summary.Info)
	b.WriteString("Findings:\n\n")
	if len(scanReport.Findings) == 0 {
		b.WriteString("No findings.\n")
		return b.String()
	}
	for i, finding := range scanReport.Findings {
		if i > 0 {
			b.WriteString("\n")
		}
		fmt.Fprintf(&b, "[%s] %s\n", strings.ToUpper(finding.Risk), finding.RuleID)
		fmt.Fprintf(&b, "File: %s\n", finding.File)
		fmt.Fprintf(&b, "Resource: %s/%s\n", finding.ResourceKind, finding.ResourceName)
		if finding.Namespace != "" {
			fmt.Fprintf(&b, "Namespace: %s\n", finding.Namespace)
		}
		if finding.ContainerName != "" {
			fmt.Fprintf(&b, "Container: %s\n", finding.ContainerName)
		}
		if finding.Path != "" {
			fmt.Fprintf(&b, "Path: %s\n", finding.Path)
		}
		if finding.Evidence != "" {
			fmt.Fprintf(&b, "Evidence: %s\n", finding.Evidence)
		}
		b.WriteString("\nExplanation:\n")
		fmt.Fprintf(&b, "%s\n\n", finding.Explanation)
		b.WriteString("Suggestion:\n")
		fmt.Fprintf(&b, "%s\n", finding.Suggestion)
	}
	return b.String()
}
