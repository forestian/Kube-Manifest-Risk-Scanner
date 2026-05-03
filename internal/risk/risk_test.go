package risk

import (
	"testing"

	"kube-manifest-risk-scanner/internal/model"
)

func TestFailOnRiskBehavior(t *testing.T) {
	summary := model.Summary{Low: 1, Medium: 1, High: 1}
	if ShouldFail(summary, "none") {
		t.Fatalf("none threshold should not fail")
	}
	if !ShouldFail(summary, "low") {
		t.Fatalf("low threshold should fail")
	}
	if !ShouldFail(summary, "medium") {
		t.Fatalf("medium threshold should fail")
	}
	if !ShouldFail(summary, "high") {
		t.Fatalf("high threshold should fail")
	}
	if ShouldFail(model.Summary{Info: 3}, "low") {
		t.Fatalf("info findings should not fail")
	}
}
