package cmd

import (
	"os"

	"github.com/aquasecurity/tracee/cmd/traceectl/pkg/cmd/flags"

	"github.com/aquasecurity/tracee/cmd/traceectl/pkg/client"
	cmdCobra "github.com/aquasecurity/tracee/cmd/traceectl/pkg/cmd/cobra"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Display the version of tracee",
	Long:  "This is the version of the tracee application you connected to",
	Run: func(cmd *cobra.Command, args []string) {
		runner, err := cmdCobra.GetVersion(cmd)
		if err != nil {
			cmd.PrintErrf("error creating runner: %s\n", err)
			os.Exit(1)
		}
		if err := runner.Run(); err != nil {
			cmd.PrintErrf("error running: %s\n", err)
			os.Exit(1)
		}
		runner.Server.Close()
	},
}

func init() {
	rootCmd.AddCommand(versionCmd)
	versionCmd.Flags().String(flags.ServerFlag, client.DefaultSocket, "Specify the server unix socket (default: /var/run/tracee.sock).")
	if err := viper.BindPFlag(flags.ServerFlag, versionCmd.Flags().Lookup(flags.ServerFlag)); err != nil {
		panic(err)
	}
}
