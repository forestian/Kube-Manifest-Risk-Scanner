package scanner_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"kube-manifest-risk-scanner/internal/model"
	"kube-manifest-risk-scanner/internal/parser"
	"kube-manifest-risk-scanner/internal/report"
	"kube-manifest-risk-scanner/internal/scanner"
)

func TestWorkloadContainerRules(t *testing.T) {
	scanReport := scanYAML(t, `apiVersion: apps/v1
kind: Deployment
metadata:
  name: risky
  namespace: default
spec:
  replicas: 1
  selector:
    matchLabels:
      app: risky
  template:
    metadata:
      labels:
        app: risky
    spec:
      serviceAccountName: default
      automountServiceAccountToken: true
      hostNetwork: true
      volumes:
        - name: host-root
          hostPath:
            path: /
      containers:
        - name: api
          image: nginx:latest
          imagePullPolicy: Always
          securityContext:
            privileged: true
            allowPrivilegeEscalation: true
            runAsUser: 0
            capabilities:
              add: ["SYS_ADMIN"]
`, "production", true, nil)

	for _, ruleID := range []string{
		"missing-resource-requests",
		"missing-resource-limits",
		"missing-readiness-probe",
		"missing-liveness-probe",
		"latest-image-tag",
		"image-pull-policy-always",
		"privileged-container",
		"allow-privilege-escalation",
		"run-as-root",
		"hostpath-volume",
		"host-network",
		"dangerous-capability",
		"default-namespace",
		"replicas-one-production",
	} {
		if !hasRule(scanReport, ruleID) {
			t.Fatalf("expected rule %s in findings", ruleID)
		}
	}
}

func TestImageWithoutTagDetection(t *testing.T) {
	scanReport := scanYAML(t, goodDeploymentWithImage("nginx"), "default", false, nil)
	if !hasRule(scanReport, "latest-image-tag") {
		t.Fatalf("expected image without tag to trigger latest-image-tag")
	}
}

func TestMissingResourceRequestsAndLimitsDetection(t *testing.T) {
	scanReport := scanYAML(t, `apiVersion: v1
kind: Pod
metadata:
  name: api
  namespace: apps
spec:
  containers:
    - name: api
      image: nginx:1.27
      resources:
        requests:
          cpu: 100m
`, "production", false, nil)
	if !hasRule(scanReport, "missing-resource-requests") {
		t.Fatalf("expected missing-resource-requests")
	}
	if !hasRule(scanReport, "missing-resource-limits") {
		t.Fatalf("expected missing-resource-limits")
	}
}

func TestMissingProbeDetection(t *testing.T) {
	scanReport := scanYAML(t, goodDeploymentWithImage("nginx:1.27"), "production", false, nil)
	if !hasRule(scanReport, "missing-readiness-probe") {
		t.Fatalf("expected missing-readiness-probe")
	}
	if !hasRule(scanReport, "missing-liveness-probe") {
		t.Fatalf("expected missing-liveness-probe")
	}
}

func TestNetworkingNamespaceServiceIngressCronJobRules(t *testing.T) {
	scanReport := scanYAML(t, `apiVersion: v1
kind: Service
metadata:
  name: public
spec:
  type: LoadBalancer
---
apiVersion: v1
kind: Service
metadata:
  name: node
  namespace: default
spec:
  type: NodePort
---
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: web
  namespace: apps
spec:
  rules:
    - host: example.com
---
apiVersion: batch/v1
kind: CronJob
metadata:
  name: cleanup
spec:
  schedule: "*/5 * * * *"
  jobTemplate:
    spec:
      template:
        spec:
          restartPolicy: OnFailure
          hostPID: true
          containers:
            - name: cleanup
              image: busybox:1.36
`, "production", false, nil)

	for _, ruleID := range []string{
		"service-loadbalancer",
		"service-nodeport",
		"ingress-without-tls",
		"namespace-missing",
		"default-namespace",
		"cronjob-no-concurrency-policy",
		"host-pid",
	} {
		if !hasRule(scanReport, ruleID) {
			t.Fatalf("expected rule %s in findings", ruleID)
		}
	}
}

func TestSecretFindingDoesNotPrintValues(t *testing.T) {
	scanReport := scanYAML(t, `apiVersion: v1
kind: Secret
metadata:
  name: db
  namespace: apps
stringData:
  password: placeholder-value
`, "default", false, nil)
	if !hasRule(scanReport, "secret-plain-manifest") {
		t.Fatalf("expected secret-plain-manifest")
	}
	text := report.Text(scanReport)
	if strings.Contains(text, "placeholder-value") {
		t.Fatalf("secret value leaked in report: %s", text)
	}
}

func TestIncludeInfoBehavior(t *testing.T) {
	manifest := goodDeploymentWithImagePullPolicy("nginx:latest", "Always")
	withoutInfo := scanYAML(t, manifest, "default", false, nil)
	if hasRule(withoutInfo, "image-pull-policy-always") {
		t.Fatalf("did not expect info finding without include-info")
	}
	withInfo := scanYAML(t, manifest, "default", true, nil)
	if !hasRule(withInfo, "image-pull-policy-always") {
		t.Fatalf("expected info finding with include-info")
	}
}

func TestIgnoreRuleBehavior(t *testing.T) {
	scanReport := scanYAML(t, goodDeploymentWithImage("nginx:latest"), "default", false, map[string]bool{
		"latest-image-tag": true,
	})
	if hasRule(scanReport, "latest-image-tag") {
		t.Fatalf("ignored rule appeared in findings")
	}
	if scanReport.Summary.High != 0 {
		t.Fatalf("ignored high finding should not be counted, got %+v", scanReport.Summary)
	}
}

func scanYAML(t *testing.T, manifest, profile string, includeInfo bool, ignore map[string]bool) model.ScanReport {
	t.Helper()
	path := filepath.Join(t.TempDir(), "manifest.yaml")
	if err := os.WriteFile(path, []byte(manifest), 0644); err != nil {
		t.Fatal(err)
	}
	resources, err := parser.ParseFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return scanner.Scan(resources, 1, scanner.Options{
		Profile:     profile,
		IncludeInfo: includeInfo,
		Ignore:      ignore,
	})
}

func hasRule(scanReport model.ScanReport, ruleID string) bool {
	for _, finding := range scanReport.Findings {
		if finding.RuleID == ruleID {
			return true
		}
	}
	return false
}

func goodDeploymentWithImage(image string) string {
	return goodDeploymentWithImagePullPolicy(image, "IfNotPresent")
}

func goodDeploymentWithImagePullPolicy(image, pullPolicy string) string {
	return `apiVersion: apps/v1
kind: Deployment
metadata:
  name: api
  namespace: apps
spec:
  replicas: 2
  selector:
    matchLabels:
      app: api
  template:
    metadata:
      labels:
        app: api
    spec:
      automountServiceAccountToken: false
      serviceAccountName: api
      securityContext:
        runAsNonRoot: true
        runAsUser: 1000
        seccompProfile:
          type: RuntimeDefault
      containers:
        - name: api
          image: ` + image + `
          imagePullPolicy: ` + pullPolicy + `
          resources:
            requests:
              cpu: 100m
              memory: 128Mi
            limits:
              cpu: 500m
              memory: 256Mi
          securityContext:
            allowPrivilegeEscalation: false
            capabilities:
              drop: ["ALL"]
`
}
