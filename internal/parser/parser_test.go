package parser

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseSingleYAMLManifest(t *testing.T) {
	path := writeTestFile(t, "deployment.yaml", `apiVersion: apps/v1
kind: Deployment
metadata:
  name: api
`)
	resources, err := ParseFile(path)
	if err != nil {
		t.Fatalf("ParseFile returned error: %v", err)
	}
	if len(resources) != 1 {
		t.Fatalf("expected 1 resource, got %d", len(resources))
	}
	if resources[0].Kind != "Deployment" || resources[0].Name != "api" {
		t.Fatalf("unexpected resource: %+v", resources[0])
	}
}

func TestParseMultiDocumentYAMLManifest(t *testing.T) {
	path := writeTestFile(t, "multi.yaml", `apiVersion: v1
kind: Service
metadata:
  name: api
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: api-config
`)
	resources, err := ParseFile(path)
	if err != nil {
		t.Fatalf("ParseFile returned error: %v", err)
	}
	if len(resources) != 2 {
		t.Fatalf("expected 2 resources, got %d", len(resources))
	}
}

func TestParseJSONManifest(t *testing.T) {
	path := writeTestFile(t, "pod.json", `{"apiVersion":"v1","kind":"Pod","metadata":{"name":"api","namespace":"apps"},"spec":{"containers":[{"name":"api","image":"nginx:1.27"}]}}`)
	resources, err := ParseFile(path)
	if err != nil {
		t.Fatalf("ParseFile returned error: %v", err)
	}
	if len(resources) != 1 {
		t.Fatalf("expected 1 resource, got %d", len(resources))
	}
	if resources[0].Kind != "Pod" || resources[0].Namespace != "apps" {
		t.Fatalf("unexpected resource: %+v", resources[0])
	}
}

func TestParseDirRecursivelyIgnoresUnsupportedFiles(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "nested"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "deployment.yaml"), []byte(`apiVersion: apps/v1
kind: Deployment
metadata:
  name: api
`), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "nested", "service.yml"), []byte(`apiVersion: v1
kind: Service
metadata:
  name: api
`), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "notes.txt"), []byte("ignore me"), 0644); err != nil {
		t.Fatal(err)
	}

	resources, scannedFiles, err := ParseDir(root)
	if err != nil {
		t.Fatalf("ParseDir returned error: %v", err)
	}
	if scannedFiles != 2 {
		t.Fatalf("expected 2 scanned files, got %d", scannedFiles)
	}
	if len(resources) != 2 {
		t.Fatalf("expected 2 resources, got %d", len(resources))
	}
}

func writeTestFile(t *testing.T, name, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	return path
}
