package rules

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"kube-manifest-risk-scanner/internal/model"
)

type podContext struct {
	resource    model.Resource
	podSpec     map[string]any
	podSpecPath string
	jobLike     bool
}

type containerContext struct {
	name  string
	index int
	init  bool
	spec  map[string]any
	path  string
}

func analyzePodSpec(ctx podContext, opts Options) []model.Finding {
	var findings []model.Finding
	findings = append(findings, analyzeHostNamespaces(ctx)...)
	findings = append(findings, analyzeHostPathVolumes(ctx)...)
	findings = append(findings, analyzeServiceAccount(ctx, opts)...)

	for _, container := range containers(ctx) {
		findings = append(findings, analyzeResourceRequests(ctx, container)...)
		findings = append(findings, analyzeResourceLimits(ctx, container, opts)...)
		findings = append(findings, analyzeImages(ctx, container)...)
		findings = append(findings, analyzeSecurity(ctx, container, opts)...)
		if !container.init && !ctx.jobLike {
			findings = append(findings, analyzeProbes(ctx, container, opts)...)
		}
	}
	return findings
}

func podSpecContexts(resource model.Resource) []podContext {
	switch resource.Kind {
	case "Pod":
		spec, ok := mapAt(resource.Object, "spec")
		if !ok {
			return nil
		}
		return []podContext{{resource: resource, podSpec: spec, podSpecPath: "spec"}}
	case "Deployment", "StatefulSet", "DaemonSet", "ReplicaSet":
		spec, ok := mapAt(resource.Object, "spec", "template", "spec")
		if !ok {
			return nil
		}
		return []podContext{{resource: resource, podSpec: spec, podSpecPath: "spec.template.spec"}}
	case "Job":
		spec, ok := mapAt(resource.Object, "spec", "template", "spec")
		if !ok {
			return nil
		}
		return []podContext{{resource: resource, podSpec: spec, podSpecPath: "spec.template.spec", jobLike: true}}
	case "CronJob":
		spec, ok := mapAt(resource.Object, "spec", "jobTemplate", "spec", "template", "spec")
		if !ok {
			return nil
		}
		return []podContext{{resource: resource, podSpec: spec, podSpecPath: "spec.jobTemplate.spec.template.spec", jobLike: true}}
	default:
		return nil
	}
}

func containers(ctx podContext) []containerContext {
	var result []containerContext
	addContainers := func(key string, init bool) {
		items, ok := sliceAt(ctx.podSpec, key)
		if !ok {
			return
		}
		for i, item := range items {
			spec, ok := item.(map[string]any)
			if !ok {
				continue
			}
			name, _ := stringAt(spec, "name")
			result = append(result, containerContext{
				name:  name,
				index: i,
				init:  init,
				spec:  spec,
				path:  fmt.Sprintf("%s.%s[%d]", ctx.podSpecPath, key, i),
			})
		}
	}
	addContainers("containers", false)
	addContainers("initContainers", true)
	return result
}

func analyzeResourceRequests(ctx podContext, container containerContext) []model.Finding {
	resources, _ := mapAt(container.spec, "resources")
	requests, _ := mapAt(resources, "requests")
	missing := missingKeys(requests, "cpu", "memory")
	if len(missing) == 0 {
		return nil
	}
	return []model.Finding{newFinding(ctx.resource, "medium", "missing-resource-requests", "Missing resource requests",
		container.path+".resources.requests", "missing "+strings.Join(missing, " and ")+" request(s)",
		"Containers without resource requests may be scheduled unpredictably and can cause noisy-neighbor problems.",
		"Set CPU and memory requests based on observed usage.", container.name)}
}

func analyzeResourceLimits(ctx podContext, container containerContext, opts Options) []model.Finding {
	resources, _ := mapAt(container.spec, "resources")
	limits, _ := mapAt(resources, "limits")
	missing := missingKeys(limits, "cpu", "memory")
	if len(missing) == 0 {
		return nil
	}
	risk := profileRisk(opts, "low", "medium")
	return []model.Finding{newFinding(ctx.resource, risk, "missing-resource-limits", "Missing resource limits",
		container.path+".resources.limits", "missing "+strings.Join(missing, " and ")+" limit(s)",
		"Containers without limits can consume more resources than expected.",
		"Set limits where appropriate, especially for shared clusters.", container.name)}
}

func missingKeys(values map[string]any, keys ...string) []string {
	missing := make([]string, 0, len(keys))
	for _, key := range keys {
		if values == nil {
			missing = append(missing, key)
			continue
		}
		if _, ok := values[key]; !ok {
			missing = append(missing, key)
		}
	}
	return missing
}

func newFinding(resource model.Resource, riskValue, ruleID, title, path, evidence, explanation, suggestion, containerName string) model.Finding {
	return model.Finding{
		File:          resource.File,
		Risk:          riskValue,
		RuleID:        ruleID,
		Title:         title,
		ResourceKind:  resource.Kind,
		ResourceName:  resource.Name,
		Namespace:     resource.Namespace,
		ContainerName: containerName,
		Path:          path,
		Evidence:      evidence,
		Explanation:   explanation,
		Suggestion:    suggestion,
	}
}

func profileRisk(opts Options, defaultRisk, productionRisk string) string {
	if opts.Profile == "production" {
		return productionRisk
	}
	return defaultRisk
}

func mapAt(root map[string]any, path ...string) (map[string]any, bool) {
	if root == nil {
		return nil, false
	}
	current := any(root)
	for _, key := range path {
		currentMap, ok := current.(map[string]any)
		if !ok {
			return nil, false
		}
		current, ok = currentMap[key]
		if !ok {
			return nil, false
		}
	}
	result, ok := current.(map[string]any)
	return result, ok
}

func sliceAt(root map[string]any, path ...string) ([]any, bool) {
	if root == nil {
		return nil, false
	}
	current := any(root)
	for _, key := range path {
		currentMap, ok := current.(map[string]any)
		if !ok {
			return nil, false
		}
		current, ok = currentMap[key]
		if !ok {
			return nil, false
		}
	}
	result, ok := current.([]any)
	return result, ok
}

func stringAt(root map[string]any, path ...string) (string, bool) {
	value, ok := valueAt(root, path...)
	if !ok {
		return "", false
	}
	text, ok := value.(string)
	return text, ok
}

func boolAt(root map[string]any, path ...string) (bool, bool) {
	value, ok := valueAt(root, path...)
	if !ok {
		return false, false
	}
	result, ok := value.(bool)
	return result, ok
}

func intAt(root map[string]any, path ...string) (int, bool) {
	value, ok := valueAt(root, path...)
	if !ok {
		return 0, false
	}
	switch typed := value.(type) {
	case int:
		return typed, true
	case int64:
		return int(typed), true
	case int32:
		return int(typed), true
	case float64:
		return int(typed), true
	case json.Number:
		number, err := strconv.Atoi(typed.String())
		return number, err == nil
	default:
		return 0, false
	}
}

func valueAt(root map[string]any, path ...string) (any, bool) {
	if root == nil {
		return nil, false
	}
	current := any(root)
	for _, key := range path {
		currentMap, ok := current.(map[string]any)
		if !ok {
			return nil, false
		}
		current, ok = currentMap[key]
		if !ok {
			return nil, false
		}
	}
	return current, true
}

func stringSliceAt(root map[string]any, path ...string) ([]string, bool) {
	items, ok := sliceAt(root, path...)
	if !ok {
		return nil, false
	}
	result := make([]string, 0, len(items))
	for _, item := range items {
		if text, ok := item.(string); ok {
			result = append(result, text)
		}
	}
	return result, true
}

func containsFold(values []string, target string) bool {
	for _, value := range values {
		if strings.EqualFold(value, target) {
			return true
		}
	}
	return false
}
