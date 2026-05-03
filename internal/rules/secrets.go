package rules

import (
	"fmt"

	"kube-manifest-risk-scanner/internal/model"
)

const largeConfigValueBytes = 32 * 1024

func analyzeSecret(resource model.Resource) []model.Finding {
	data, hasData := mapAt(resource.Object, "data")
	stringData, hasStringData := mapAt(resource.Object, "stringData")
	if (!hasData || len(data) == 0) && (!hasStringData || len(stringData) == 0) {
		return nil
	}
	evidence := "data or stringData field present"
	switch {
	case hasData && len(data) > 0 && hasStringData && len(stringData) > 0:
		evidence = "data and stringData fields present"
	case hasData && len(data) > 0:
		evidence = "data field present"
	case hasStringData && len(stringData) > 0:
		evidence = "stringData field present"
	}
	return []model.Finding{newFinding(resource, "medium", "secret-plain-manifest", "Secret data in manifest",
		"data", evidence,
		"Committing raw Secret manifests can expose sensitive data if stored in Git.",
		"Use External Secrets, SealedSecrets, SOPS, or another secret management approach.", "")}
}

func analyzeConfigMap(resource model.Resource) []model.Finding {
	data, ok := mapAt(resource.Object, "data")
	if !ok {
		return nil
	}
	var findings []model.Finding
	for key, value := range data {
		text, ok := value.(string)
		if !ok {
			continue
		}
		if len(text) > largeConfigValueBytes {
			findings = append(findings, newFinding(resource, "low", "configmap-large-inline-config", "Large inline ConfigMap value",
				"data."+key, fmt.Sprintf("key %q is %d bytes", key, len(text)),
				"Large ConfigMaps can be hard to review and may hit Kubernetes object limits.",
				"Keep ConfigMaps focused and consider external configuration management.", ""))
		}
	}
	return findings
}
