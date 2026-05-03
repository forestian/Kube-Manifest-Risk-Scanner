package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"kube-manifest-risk-scanner/internal/parser"
	"kube-manifest-risk-scanner/internal/report"
	"kube-manifest-risk-scanner/internal/risk"
	"kube-manifest-risk-scanner/internal/scanner"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

type scanFlags struct {
	file        string
	dir         string
	format      string
	output      string
	profile     string
	failOnRisk  string
	includeInfo bool
	ignore      string
	config      string
}

func newScanCommand() *cobra.Command {
	flags := scanFlags{
		format:     "text",
		profile:    "default",
		failOnRisk: "none",
	}

	cmd := &cobra.Command{
		Use:   "scan",
		Short: "Scan Kubernetes YAML or JSON manifests",
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := applyScanConfig(cmd, &flags); err != nil {
				return err
			}
			if err := validateScanFlags(flags); err != nil {
				return err
			}

			var (
				resources    []parser.Resource
				scannedFiles int
				err          error
			)
			if flags.file != "" {
				resources, err = parser.ParseFile(flags.file)
				scannedFiles = 1
			} else {
				resources, scannedFiles, err = parser.ParseDir(flags.dir)
			}
			if err != nil {
				return err
			}

			scanReport := scanner.Scan(resources, scannedFiles, scanner.Options{
				Profile:     flags.profile,
				IncludeInfo: flags.includeInfo,
				Ignore:      parseIgnoreList(flags.ignore),
			})

			rendered, err := report.Render(scanReport, flags.format)
			if err != nil {
				return err
			}
			if flags.output != "" {
				if err := os.WriteFile(flags.output, []byte(rendered), 0644); err != nil {
					return fmt.Errorf("write report %s: %w", flags.output, err)
				}
			} else {
				if _, err := fmt.Fprint(cmd.OutOrStdout(), rendered); err != nil {
					return err
				}
			}

			if risk.ShouldFail(scanReport.Summary, flags.failOnRisk) {
				return fmt.Errorf("risk threshold %q exceeded", flags.failOnRisk)
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&flags.file, "file", "", "Kubernetes manifest file to scan")
	cmd.Flags().StringVar(&flags.dir, "dir", "", "Directory of Kubernetes manifests to scan recursively")
	cmd.Flags().StringVar(&flags.format, "format", "text", "report format: text, json, or markdown")
	cmd.Flags().StringVar(&flags.output, "output", "", "write report to a file instead of stdout")
	cmd.Flags().StringVar(&flags.profile, "profile", "default", "scan profile: default, production, or dev")
	cmd.Flags().StringVar(&flags.failOnRisk, "fail-on-risk", "none", "exit non-zero at threshold: none, low, medium, or high")
	cmd.Flags().BoolVar(&flags.includeInfo, "include-info", false, "include info-level findings")
	cmd.Flags().StringVar(&flags.ignore, "ignore", "", "comma-separated rule IDs to suppress")
	cmd.Flags().StringVar(&flags.config, "config", "", "optional YAML config file")

	return cmd
}

func validateScanFlags(flags scanFlags) error {
	if (flags.file == "") == (flags.dir == "") {
		return fmt.Errorf("exactly one scan source is required: --file or --dir")
	}
	if flags.file != "" {
		info, err := os.Stat(flags.file)
		if err != nil {
			return fmt.Errorf("--file must exist: %s", flags.file)
		}
		if info.IsDir() {
			return fmt.Errorf("--file must be a file: %s", flags.file)
		}
	}
	if flags.dir != "" {
		info, err := os.Stat(flags.dir)
		if err != nil {
			return fmt.Errorf("--dir must exist: %s", flags.dir)
		}
		if !info.IsDir() {
			return fmt.Errorf("--dir must be a directory: %s", flags.dir)
		}
	}
	if !oneOf(flags.format, "text", "json", "markdown") {
		return fmt.Errorf("--format must be text, json, or markdown")
	}
	if !oneOf(flags.profile, "default", "production", "dev") {
		return fmt.Errorf("--profile must be default, production, or dev")
	}
	if !oneOf(flags.failOnRisk, "none", "low", "medium", "high") {
		return fmt.Errorf("--fail-on-risk must be none, low, medium, or high")
	}
	return nil
}

func applyScanConfig(cmd *cobra.Command, flags *scanFlags) error {
	if flags.config == "" {
		return nil
	}
	data, err := os.ReadFile(flags.config)
	if err != nil {
		return fmt.Errorf("read config %s: %w", flags.config, err)
	}
	var raw map[string]any
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return fmt.Errorf("parse config %s: %w", flags.config, err)
	}
	if !cmd.Flags().Changed("format") {
		if value, ok := raw["format"].(string); ok {
			flags.format = value
		}
	}
	if !cmd.Flags().Changed("profile") {
		if value, ok := raw["profile"].(string); ok {
			flags.profile = value
		}
	}
	if !cmd.Flags().Changed("fail-on-risk") {
		if value, ok := raw["fail_on_risk"].(string); ok {
			flags.failOnRisk = value
		}
	}
	if !cmd.Flags().Changed("include-info") {
		if value, ok := raw["include_info"].(bool); ok {
			flags.includeInfo = value
		}
	}
	if !cmd.Flags().Changed("ignore") {
		flags.ignore = ignoreFromConfig(raw["ignore"])
	}
	return nil
}

func ignoreFromConfig(value any) string {
	switch typed := value.(type) {
	case string:
		return typed
	case []any:
		parts := make([]string, 0, len(typed))
		for _, item := range typed {
			if text, ok := item.(string); ok {
				parts = append(parts, text)
			}
		}
		return strings.Join(parts, ",")
	default:
		return ""
	}
}

func parseIgnoreList(value string) map[string]bool {
	ignored := map[string]bool{}
	for _, part := range strings.Split(value, ",") {
		ruleID := strings.TrimSpace(part)
		if ruleID != "" {
			ignored[ruleID] = true
		}
	}
	return ignored
}

func oneOf(value string, allowed ...string) bool {
	for _, item := range allowed {
		if value == item {
			return true
		}
	}
	return false
}

func cleanOutputPath(path string) string {
	return filepath.Clean(path)
}
