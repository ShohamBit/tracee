package cmd

import (
	"github.com/aquasecurity/tracee/cmd/traceectl/pkg/client"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Display the version of tracee",
	Long:  "This is the version of the tracee application you connected to",
	Run: func(cmd *cobra.Command, args []string) {
		displayVersion(cmd, args)
	},
}

func inti() {
	rootCmd.AddCommand(versionCmd)

	versionCmd.Flags().String(flags.ServerFlag, client.DefaultSocket, "Specify the server unix socket.")
	if err := viper.BindPFlag(flags.ServerFlag, versionCmd.Flags().Lookup(flags.ServerFlag)); err != nil {
		panic(err)
	}
}
