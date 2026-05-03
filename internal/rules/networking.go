package rules

import (
	"fmt"

	"kube-manifest-risk-scanner/internal/model"
)

func analyzeHostNamespaces(ctx podContext) []model.Finding {
	var findings []model.Finding
	if value, ok := boolAt(ctx.podSpec, "hostNetwork"); ok && value {
		findings = append(findings, newFinding(ctx.resource, "high", "host-network", "Host network enabled",
			ctx.podSpecPath+".hostNetwork", "hostNetwork=true",
			"hostNetwork gives pods access to the node network namespace and can increase blast radius.",
			"Avoid hostNetwork unless required.", ""))
	}
	if value, ok := boolAt(ctx.podSpec, "hostPID"); ok && value {
		findings = append(findings, newFinding(ctx.resource, "high", "host-pid", "Host PID namespace enabled",
			ctx.podSpecPath+".hostPID", "hostPID=true",
			"hostPID exposes host process namespace to pods.",
			"Avoid hostPID unless required.", ""))
	}
	if value, ok := boolAt(ctx.podSpec, "hostIPC"); ok && value {
		findings = append(findings, newFinding(ctx.resource, "high", "host-ipc", "Host IPC namespace enabled",
			ctx.podSpecPath+".hostIPC", "hostIPC=true",
			"hostIPC exposes host IPC namespace to pods.",
			"Avoid hostIPC unless required.", ""))
	}
	return findings
}

func analyzeHostPathVolumes(ctx podContext) []model.Finding {
	volumes, ok := sliceAt(ctx.podSpec, "volumes")
	if !ok {
		return nil
	}
	var findings []model.Finding
	for i, item := range volumes {
		volume, ok := item.(map[string]any)
		if !ok {
			continue
		}
		hostPath, ok := mapAt(volume, "hostPath")
		if !ok {
			continue
		}
		name, _ := stringAt(volume, "name")
		path, _ := stringAt(hostPath, "path")
		evidence := "hostPath volume"
		if path != "" {
			evidence = fmt.Sprintf("volume %q uses hostPath %q", name, path)
		}
		findings = append(findings, newFinding(ctx.resource, "high", "hostpath-volume", "hostPath volume",
			fmt.Sprintf("%s.volumes[%d].hostPath", ctx.podSpecPath, i), evidence,
			"hostPath can expose host filesystem paths to containers.",
			"Avoid hostPath; use PVCs, ConfigMaps, Secrets, or CSI volumes where possible.", ""))
	}
	return findings
}

func analyzeService(resource model.Resource) []model.Finding {
	serviceType, _ := stringAt(resource.Object, "spec", "type")
	switch serviceType {
	case "LoadBalancer":
		return []model.Finding{newFinding(resource, "medium", "service-loadbalancer", "Service type LoadBalancer",
			"spec.type", "type=LoadBalancer",
			"LoadBalancer services may expose workloads externally and introduce cloud costs.",
			"Confirm exposure, firewall rules, and cost implications.", "")}
	case "NodePort":
		return []model.Finding{newFinding(resource, "medium", "service-nodeport", "Service type NodePort",
			"spec.type", "type=NodePort",
			"NodePort exposes a port on every node and may increase attack surface.",
			"Confirm network exposure and restrict access.", "")}
	default:
		return nil
	}
}

func analyzeIngress(resource model.Resource) []model.Finding {
	rules, rulesOK := sliceAt(resource.Object, "spec", "rules")
	tls, tlsOK := sliceAt(resource.Object, "spec", "tls")
	if !rulesOK || len(rules) == 0 || (tlsOK && len(tls) > 0) {
		return nil
	}
	return []model.Finding{newFinding(resource, "medium", "ingress-without-tls", "Ingress without TLS",
		"spec.tls", "",
		"Ingress without TLS may expose traffic without encryption.",
		"Configure TLS for production ingress.", "")}
}
