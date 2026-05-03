package report

import (
	"fmt"

	"kube-manifest-risk-scanner/internal/model"
)

func Render(scanReport model.ScanReport, format string) (string, error) {
	switch format {
	case "text":
		return Text(scanReport), nil
	case "json":
		return JSON(scanReport)
	case "markdown":
		return Markdown(scanReport), nil
	default:
		return "", fmt.Errorf("unsupported report format: %s", format)
	}
}
