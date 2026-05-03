package rules

import (
	"strings"

	"kube-manifest-risk-scanner/internal/model"
)

func analyzeImages(ctx podContext, container containerContext) []model.Finding {
	image, ok := stringAt(container.spec, "image")
	if !ok || image == "" {
		return nil
	}
	var findings []model.Finding
	if isFloatingImage(image) {
		findings = append(findings, newFinding(ctx.resource, "high", "latest-image-tag", "Latest or missing image tag",
			container.path+".image", image,
			"Floating image tags make deployments non-deterministic and difficult to roll back.",
			"Use immutable version tags or image digests.", container.name))
	}
	if pullPolicy, ok := stringAt(container.spec, "imagePullPolicy"); ok && pullPolicy == "Always" && isFloatingImage(image) {
		findings = append(findings, newFinding(ctx.resource, "info", "image-pull-policy-always", "Image pull policy Always with mutable image",
			container.path+".imagePullPolicy", "imagePullPolicy=Always image="+image,
			"Always pulling mutable images can make deployments less predictable.",
			"Use immutable tags or digests.", container.name))
	}
	return findings
}

func isFloatingImage(image string) bool {
	if strings.Contains(image, "@sha256:") {
		return false
	}
	lastSlash := strings.LastIndex(image, "/")
	lastColon := strings.LastIndex(image, ":")
	if lastColon <= lastSlash {
		return true
	}
	return image[lastColon+1:] == "latest"
}
