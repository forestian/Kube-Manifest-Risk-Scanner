package parser

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

func ParseFile(path string) ([]Resource, error) {
	ext := strings.ToLower(filepath.Ext(path))
	if !isSupportedExt(ext) {
		return nil, fmt.Errorf("unsupported manifest file type: %s", path)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read manifest %s: %w", path, err)
	}
	switch ext {
	case ".json":
		return parseJSON(path, data)
	default:
		return parseYAML(path, data)
	}
}

func ParseDir(root string) ([]Resource, int, error) {
	var resources []Resource
	scannedFiles := 0
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			return nil
		}
		if !IsSupportedFile(path) {
			return nil
		}
		scannedFiles++
		fileResources, err := ParseFile(path)
		if err != nil {
			return err
		}
		resources = append(resources, fileResources...)
		return nil
	})
	if err != nil {
		return nil, scannedFiles, err
	}
	return resources, scannedFiles, nil
}

func IsSupportedFile(path string) bool {
	return isSupportedExt(strings.ToLower(filepath.Ext(path)))
}

func isSupportedExt(ext string) bool {
	return ext == ".yaml" || ext == ".yml" || ext == ".json"
}

func parseYAML(path string, data []byte) ([]Resource, error) {
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	var resources []Resource
	for {
		var doc any
		err := decoder.Decode(&doc)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("parse YAML %s: %w", path, err)
		}
		normalized := normalize(doc)
		if normalized == nil {
			continue
		}
		resources = append(resources, resourcesFromDocument(path, normalized)...)
	}
	return resources, nil
}

func parseJSON(path string, data []byte) ([]Resource, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	var doc any
	if err := decoder.Decode(&doc); err != nil {
		return nil, fmt.Errorf("parse JSON %s: %w", path, err)
	}
	return resourcesFromDocument(path, normalize(doc)), nil
}

func resourcesFromDocument(path string, doc any) []Resource {
	obj, ok := doc.(map[string]any)
	if !ok || len(obj) == 0 {
		return nil
	}
	if kind, _ := obj["kind"].(string); kind == "List" {
		items, _ := obj["items"].([]any)
		resources := make([]Resource, 0, len(items))
		for _, item := range items {
			if itemObj, ok := item.(map[string]any); ok {
				resources = append(resources, newResource(path, itemObj))
			}
		}
		return resources
	}
	return []Resource{newResource(path, obj)}
}

func newResource(path string, obj map[string]any) Resource {
	metadata, _ := obj["metadata"].(map[string]any)
	name, _ := metadata["name"].(string)
	namespace, _ := metadata["namespace"].(string)
	kind, _ := obj["kind"].(string)
	apiVersion, _ := obj["apiVersion"].(string)
	return Resource{
		File:       filepath.ToSlash(filepath.Clean(path)),
		APIVersion: apiVersion,
		Kind:       kind,
		Name:       name,
		Namespace:  namespace,
		Object:     obj,
	}
}

func normalize(value any) any {
	switch typed := value.(type) {
	case map[string]any:
		result := make(map[string]any, len(typed))
		for key, item := range typed {
			result[key] = normalize(item)
		}
		return result
	case map[any]any:
		result := make(map[string]any, len(typed))
		for key, item := range typed {
			result[fmt.Sprint(key)] = normalize(item)
		}
		return result
	case []any:
		result := make([]any, 0, len(typed))
		for _, item := range typed {
			result = append(result, normalize(item))
		}
		return result
	default:
		return typed
	}
}
