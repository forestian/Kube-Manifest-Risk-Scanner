package initdemo

import (
	"os"
	"path/filepath"
	"testing"
)

func TestInitOutputStructure(t *testing.T) {
	output := filepath.Join(t.TempDir(), "demo")
	if err := Create(output, false); err != nil {
		t.Fatalf("Create returned error: %v", err)
	}
	for _, path := range []string{
		"README.md",
		filepath.Join("manifests", "good-deployment.yaml"),
		filepath.Join("manifests", "risky-deployment.yaml"),
		filepath.Join("manifests", "risky-service.yaml"),
		filepath.Join("manifests", "risky-cronjob.yaml"),
		"report.md",
	} {
		if _, err := os.Stat(filepath.Join(output, path)); err != nil {
			t.Fatalf("expected %s to exist: %v", path, err)
		}
	}
}

func TestInitOverwriteProtection(t *testing.T) {
	output := filepath.Join(t.TempDir(), "demo")
	if err := os.MkdirAll(output, 0755); err != nil {
		t.Fatal(err)
	}
	if err := Create(output, false); err == nil {
		t.Fatalf("expected overwrite protection error")
	}
	if err := Create(output, true); err != nil {
		t.Fatalf("expected --force overwrite to succeed: %v", err)
	}
}
