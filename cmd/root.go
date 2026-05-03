package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

const binaryName = "kube-risk-scan"

var rootCmd = &cobra.Command{
	Use:           binaryName,
	Short:         "Scan Kubernetes manifests for operational, reliability, and security risks",
	SilenceUsage:  true,
	SilenceErrors: true,
}

func init() {
	rootCmd.AddCommand(newScanCommand())
	rootCmd.AddCommand(newInitCommand())
	rootCmd.AddCommand(newVersionCommand())
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
