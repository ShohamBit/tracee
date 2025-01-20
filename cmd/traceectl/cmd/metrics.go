package cmd

import (
	"os"

	cmdCobra "github.com/aquasecurity/tracee/cmd/traceectl/pkg/cmd/cobra"

	"github.com/aquasecurity/tracee/cmd/traceectl/pkg/client"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var metricsCmd = &cobra.Command{
	Use:   "metrics",
	Short: "Display Tracee metrics",
	Long:  "Retrieves metrics about Tracee's performance and resource usage.",
	Run: func(cmd *cobra.Command, args []string) {
		displayMetrics(cmd, args)
	},
}

func init() {
	rootCmd.AddCommand(metricsCmd)

	metricsCmd.Flags().String(flags.ServerFlag, client.DefaultSocket, "Specify the server unix socket.")
	if err := viper.BindPFlag(flags.ServerFlag, metricsCmd.Flags().Lookup(flags.ServerFlag)); err != nil {
		panic(err)
	}
}
