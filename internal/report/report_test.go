package report

import (
	"encoding/json"
	"strings"
	"testing"

	"kube-manifest-risk-scanner/internal/model"
)

func TestJSONReportGeneration(t *testing.T) {
	scanReport := sampleReport()
	rendered, err := JSON(scanReport)
	if err != nil {
		t.Fatalf("JSON returned error: %v", err)
	}
	var decoded model.ScanReport
	if err := json.Unmarshal([]byte(rendered), &decoded); err != nil {
		t.Fatalf("invalid JSON report: %v", err)
	}
	if decoded.Findings[0].RuleID != "latest-image-tag" {
		t.Fatalf("unexpected decoded report: %+v", decoded)
	}
}

func TestMarkdownReportGeneration(t *testing.T) {
	rendered := Markdown(sampleReport())
	for _, want := range []string{"# Kube Manifest Risk Scanner", "| High | 1 |", "### HIGH / latest-image-tag"} {
		if !strings.Contains(rendered, want) {
			t.Fatalf("markdown report missing %q:\n%s", want, rendered)
		}
	}
}

func sampleReport() model.ScanReport {
	return model.ScanReport{
		Profile:          "production",
		ScannedFiles:     1,
		ScannedResources: 1,
		Summary:          model.Summary{High: 1},
		Findings: []model.Finding{
			{
				File:         "manifest.yaml",
				Risk:         "high",
				RuleID:       "latest-image-tag",
				Title:        "Latest image tag",
				ResourceKind: "Deployment",
				ResourceName: "api",
				Explanation:  "Floating image tags make deployments non-deterministic and difficult to roll back.",
				Suggestion:   "Use immutable version tags or image digests.",
			},
		},
	}
}
