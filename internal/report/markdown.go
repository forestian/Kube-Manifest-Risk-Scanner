package report

import (
	"fmt"
	"strings"

	"kube-manifest-risk-scanner/internal/model"
)

func Markdown(scanReport model.ScanReport) string {
	var b strings.Builder
	b.WriteString("# Kube Manifest Risk Scanner\n\n")
	fmt.Fprintf(&b, "Profile: `%s`  \n", scanReport.Profile)
	fmt.Fprintf(&b, "Scanned files: `%d`  \n", scanReport.ScannedFiles)
	fmt.Fprintf(&b, "Scanned resources: `%d`\n\n", scanReport.ScannedResources)
	b.WriteString("## Summary\n\n")
	b.WriteString("| Risk | Count |\n")
	b.WriteString("|---|---:|\n")
	fmt.Fprintf(&b, "| High | %d |\n", scanReport.Summary.High)
	fmt.Fprintf(&b, "| Medium | %d |\n", scanReport.Summary.Medium)
	fmt.Fprintf(&b, "| Low | %d |\n", scanReport.Summary.Low)
	fmt.Fprintf(&b, "| Info | %d |\n\n", scanReport.Summary.Info)
	b.WriteString("## Findings\n\n")
	if len(scanReport.Findings) == 0 {
		b.WriteString("No findings.\n")
		return b.String()
	}
	for _, finding := range scanReport.Findings {
		fmt.Fprintf(&b, "### %s / %s\n\n", strings.ToUpper(finding.Risk), escapeMarkdown(finding.RuleID))
		fmt.Fprintf(&b, "File: `%s`  \n", escapeMarkdown(finding.File))
		fmt.Fprintf(&b, "Resource: `%s/%s`  \n", escapeMarkdown(finding.ResourceKind), escapeMarkdown(finding.ResourceName))
		if finding.Namespace != "" {
			fmt.Fprintf(&b, "Namespace: `%s`  \n", escapeMarkdown(finding.Namespace))
		}
		if finding.ContainerName != "" {
			fmt.Fprintf(&b, "Container: `%s`  \n", escapeMarkdown(finding.ContainerName))
		}
		if finding.Path != "" {
			fmt.Fprintf(&b, "Path: `%s`  \n", escapeMarkdown(finding.Path))
		}
		if finding.Evidence != "" {
			fmt.Fprintf(&b, "Evidence: `%s`  \n", escapeMarkdown(finding.Evidence))
		}
		b.WriteString("\n")
		fmt.Fprintf(&b, "%s\n\n", finding.Explanation)
		fmt.Fprintf(&b, "Suggestion: %s\n\n", finding.Suggestion)
	}
	return b.String()
}

func escapeMarkdown(value string) string {
	value = strings.ReplaceAll(value, "`", "'")
	value = strings.ReplaceAll(value, "|", "\\|")
	return value
}
