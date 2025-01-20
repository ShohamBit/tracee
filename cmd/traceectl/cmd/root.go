package cmd

import (
	"os"

	"github.com/spf13/cobra"

	"github.com/aquasecurity/tracee/cmd/traceectl/pkg/client"
	"github.com/aquasecurity/tracee/cmd/traceectl/pkg/cmd/flags"
)

var (
	formatFlag string
	outputFlag string
	server     client.ServerInfo = client.ServerInfo{
		ConnectionType: client.Protocol_UNIX,
		Addr:           client.Socket,
	}
)

var (
	rootCmd = &cobra.Command{
		Use:   "traceectl [flags] [command]",
		Short: "traceectl is a CLI tool for tracee",
		Long: `traceectl is a CLI tool for tracee:
This tool allows you to manage events, stream events directly from tracee, and get info about tracee.
`,
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			var err error
			if err = flags.PrepareOutput(cmd, outputFlag); err != nil {
				return err
			}
			if server, err = flags.PrepareServer(cmd, server); err != nil {
				return err
			}
			return nil
		},
		Run: func(cmd *cobra.Command, args []string) {
			cmd.Help()
		},
	}
)

func init() {
	rootCmd.AddCommand(streamCmd)
	rootCmd.AddCommand(eventCmd)

	rootCmd.PersistentFlags().StringVar(&server.Addr, "server", client.Socket, `Server connection path or address.
	for unix socket <socket_path> (default: /tmp/tracee.sock)
	for tcp <IP:Port>`)
	rootCmd.PersistentFlags().StringVarP(&outputFlag, "output", "o", "", "Specify the output format")
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
