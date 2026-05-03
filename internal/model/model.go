package model

type RiskLevel string

const (
	RiskInfo   RiskLevel = "info"
	RiskLow    RiskLevel = "low"
	RiskMedium RiskLevel = "medium"
	RiskHigh   RiskLevel = "high"
)

type Finding struct {
	File          string `json:"file"`
	Line          int    `json:"line,omitempty"`
	Risk          string `json:"risk"`
	RuleID        string `json:"rule_id"`
	Title         string `json:"title"`
	ResourceKind  string `json:"resource_kind"`
	ResourceName  string `json:"resource_name"`
	Namespace     string `json:"namespace,omitempty"`
	ContainerName string `json:"container_name,omitempty"`
	Path          string `json:"path,omitempty"`
	Evidence      string `json:"evidence,omitempty"`
	Explanation   string `json:"explanation"`
	Suggestion    string `json:"suggestion"`
}

type ScanReport struct {
	Profile          string    `json:"profile"`
	ScannedFiles     int       `json:"scanned_files"`
	ScannedResources int       `json:"scanned_resources"`
	Summary          Summary   `json:"summary"`
	Findings         []Finding `json:"findings"`
}

type Summary struct {
	Info   int `json:"info"`
	Low    int `json:"low"`
	Medium int `json:"medium"`
	High   int `json:"high"`
}

type Resource struct {
	File       string
	APIVersion string
	Kind       string
	Name       string
	Namespace  string
	Object     map[string]any
}

func (s *Summary) Add(risk string) {
	switch risk {
	case string(RiskInfo):
		s.Info++
	case string(RiskLow):
		s.Low++
	case string(RiskMedium):
		s.Medium++
	case string(RiskHigh):
		s.High++
	}
}
