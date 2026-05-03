package rules

import (
	"fmt"
	"strings"

	"kube-manifest-risk-scanner/internal/model"
)

var dangerousCapabilities = map[string]bool{
	"ALL":          true,
	"SYS_ADMIN":    true,
	"NET_ADMIN":    true,
	"SYS_PTRACE":   true,
	"DAC_OVERRIDE": true,
	"SYS_MODULE":   true,
	"SYS_RAWIO":    true,
	"NET_RAW":      true,
}

func analyzeSecurity(ctx podContext, container containerContext, opts Options) []model.Finding {
	var findings []model.Finding
	containerSC, _ := mapAt(container.spec, "securityContext")
	podSC, _ := mapAt(ctx.podSpec, "securityContext")

	if privileged, ok := boolAt(containerSC, "privileged"); ok && privileged {
		findings = append(findings, newFinding(ctx.resource, "high", "privileged-container", "Privileged container",
			container.path+".securityContext.privileged", "privileged=true",
			"Privileged containers have broad host access and increase compromise impact.",
			"Avoid privileged mode unless absolutely required and documented.", container.name))
	}
	if allow, ok := boolAt(containerSC, "allowPrivilegeEscalation"); ok && allow {
		findings = append(findings, newFinding(ctx.resource, "high", "allow-privilege-escalation", "Privilege escalation allowed",
			container.path+".securityContext.allowPrivilegeEscalation", "allowPrivilegeEscalation=true",
			"Privilege escalation can allow processes to gain more privileges than intended.",
			"Set allowPrivilegeEscalation to false where possible.", container.name))
	}

	findings = append(findings, analyzeRunAsRoot(ctx, container, podSC, containerSC, opts)...)
	findings = append(findings, analyzeCapabilities(ctx, container, containerSC, opts)...)
	findings = append(findings, analyzeSeccomp(ctx, container, podSC, containerSC, opts)...)
	return findings
}

func analyzeRunAsRoot(ctx podContext, container containerContext, podSC, containerSC map[string]any, opts Options) []model.Finding {
	if value, ok := boolAt(containerSC, "runAsNonRoot"); ok && !value {
		return []model.Finding{newFinding(ctx.resource, "medium", "run-as-root", "Container may run as root",
			container.path+".securityContext.runAsNonRoot", "runAsNonRoot=false",
			"Running containers as root increases impact if the container is compromised.",
			"Set runAsNonRoot true and use a non-zero runAsUser.", container.name)}
	}
	if value, ok := boolAt(podSC, "runAsNonRoot"); ok && !value {
		return []model.Finding{newFinding(ctx.resource, "medium", "run-as-root", "Pod may run as root",
			ctx.podSpecPath+".securityContext.runAsNonRoot", "runAsNonRoot=false",
			"Running containers as root increases impact if the container is compromised.",
			"Set runAsNonRoot true and use a non-zero runAsUser.", container.name)}
	}
	if value, ok := intAt(containerSC, "runAsUser"); ok && value == 0 {
		return []model.Finding{newFinding(ctx.resource, "medium", "run-as-root", "Container runs as root",
			container.path+".securityContext.runAsUser", "runAsUser=0",
			"Running containers as root increases impact if the container is compromised.",
			"Set runAsNonRoot true and use a non-zero runAsUser.", container.name)}
	}
	if value, ok := intAt(podSC, "runAsUser"); ok && value == 0 {
		return []model.Finding{newFinding(ctx.resource, "medium", "run-as-root", "Pod runs as root",
			ctx.podSpecPath+".securityContext.runAsUser", "runAsUser=0",
			"Running containers as root increases impact if the container is compromised.",
			"Set runAsNonRoot true and use a non-zero runAsUser.", container.name)}
	}
	if opts.Profile != "production" {
		return nil
	}
	if hasNonRootSetting(containerSC) || hasNonRootSetting(podSC) {
		return nil
	}
	return []model.Finding{newFinding(ctx.resource, "medium", "run-as-root", "No non-root security context",
		container.path+".securityContext", "no runAsNonRoot or non-zero runAsUser setting",
		"Running containers as root increases impact if the container is compromised.",
		"Set runAsNonRoot true and use a non-zero runAsUser.", container.name)}
}

func hasNonRootSetting(securityContext map[string]any) bool {
	if value, ok := boolAt(securityContext, "runAsNonRoot"); ok && value {
		return true
	}
	if value, ok := intAt(securityContext, "runAsUser"); ok && value != 0 {
		return true
	}
	return false
}

func analyzeCapabilities(ctx podContext, container containerContext, containerSC map[string]any, opts Options) []model.Finding {
	var findings []model.Finding
	added, _ := stringSliceAt(containerSC, "capabilities", "add")
	for _, capability := range added {
		if dangerousCapabilities[strings.ToUpper(capability)] {
			findings = append(findings, newFinding(ctx.resource, "high", "dangerous-capability", "Dangerous Linux capability",
				container.path+".securityContext.capabilities.add", capability,
				"Added Linux capabilities can significantly expand container privileges.",
				"Drop unnecessary capabilities and avoid adding high-risk capabilities.", container.name))
		}
	}

	dropped, _ := stringSliceAt(containerSC, "capabilities", "drop")
	if !containsFold(dropped, "ALL") {
		findings = append(findings, newFinding(ctx.resource, profileRisk(opts, "low", "medium"), "capabilities-not-dropped", "Capabilities are not dropped by default",
			container.path+".securityContext.capabilities.drop", fmt.Sprintf("drop=%v", dropped),
			"Dropping all capabilities by default reduces container privilege.",
			"Set capabilities.drop to ALL and add back only required capabilities.", container.name))
	}
	return findings
}

func analyzeSeccomp(ctx podContext, container containerContext, podSC, containerSC map[string]any, opts Options) []model.Finding {
	if _, ok := mapAt(containerSC, "seccompProfile"); ok {
		return nil
	}
	if _, ok := mapAt(podSC, "seccompProfile"); ok {
		return nil
	}
	return []model.Finding{newFinding(ctx.resource, profileRisk(opts, "low", "medium"), "missing-seccomp-profile", "Missing seccomp profile",
		container.path+".securityContext.seccompProfile", "",
		"Seccomp reduces kernel attack surface.",
		"Use RuntimeDefault seccomp profile where possible.", container.name)}
}
