package cmd

import (
	"fmt"

	"kube-manifest-risk-scanner/internal/initdemo"

	"github.com/spf13/cobra"
)

func newInitCommand() *cobra.Command {
	var output string
	var force bool

	cmd := &cobra.Command{
		Use:   "init",
		Short: "Create an example manifest scanning project",
		RunE: func(cmd *cobra.Command, args []string) error {
			if output == "" {
				return fmt.Errorf("--output is required")
			}
			if err := initdemo.Create(output, force); err != nil {
				return err
			}
			_, err := fmt.Fprintf(cmd.OutOrStdout(), "Created demo project at %s\n", output)
			return err
		},
	}

	cmd.Flags().StringVar(&output, "output", "./kube-risk-demo", "demo output directory")
	cmd.Flags().BoolVar(&force, "force", false, "overwrite the output directory if it already exists")

	return cmd
}
