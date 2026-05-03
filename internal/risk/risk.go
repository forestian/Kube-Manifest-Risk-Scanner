package risk

import "kube-manifest-risk-scanner/internal/model"

func ShouldFail(summary model.Summary, threshold string) bool {
	switch threshold {
	case "low":
		return summary.Low+summary.Medium+summary.High > 0
	case "medium":
		return summary.Medium+summary.High > 0
	case "high":
		return summary.High > 0
	default:
		return false
	}
}

func Weight(level string) int {
	switch level {
	case string(model.RiskHigh):
		return 4
	case string(model.RiskMedium):
		return 3
	case string(model.RiskLow):
		return 2
	case string(model.RiskInfo):
		return 1
	default:
		return 0
	}
}
