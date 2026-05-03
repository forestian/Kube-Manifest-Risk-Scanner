package report

import (
	"encoding/json"

	"kube-manifest-risk-scanner/internal/model"
)

func JSON(scanReport model.ScanReport) (string, error) {
	data, err := json.MarshalIndent(scanReport, "", "  ")
	if err != nil {
		return "", err
	}
	return string(data) + "\n", nil
}
