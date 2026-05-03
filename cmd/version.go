package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

const version = "0.1.0"

func newVersionCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print the kube-risk-scan version",
		RunE: func(cmd *cobra.Command, args []string) error {
			_, err := fmt.Fprintf(cmd.OutOrStdout(), "%s %s\n", binaryName, version)
			return err
		},
	}
}
