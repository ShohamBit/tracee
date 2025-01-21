package cobra

import (
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/aquasecurity/tracee/cmd/traceectl/pkg/client"
	"github.com/aquasecurity/tracee/cmd/traceectl/pkg/cmd"
	"github.com/aquasecurity/tracee/cmd/traceectl/pkg/cmd/flags"
	"github.com/aquasecurity/tracee/cmd/traceectl/pkg/cmd/printer"
)

func GetStream(cmdCobra *cobra.Command) (cmd.Stream, error) {
	var stream cmd.Stream

	server, err := flags.PrepareServer(viper.GetString(client.ServerFlag))
	if err != nil {
		return stream, err
	}

	outputFlag, err := cmdCobra.Flags().GetString("output")
	if err != nil {
		return stream, err
	}
	if err := flags.PrepareOutput(cmdCobra, outputFlag); err != nil {
		return stream, err
	}

	formatFlag, err := cmdCobra.Flags().GetString("format")
	if err != nil {
		return stream, err
	}
	format, err := flags.PrepareFormat(formatFlag)
	if err != nil {
		return stream, err
	}

	p, err := printer.New(cmdCobra, format)
	if err != nil {
		return stream, err
	}
	stream.Printer = p
	stream.Server = server
	return stream, nil
}

func GetVersion(cmdCobra *cobra.Command) (cmd.Version, error) {
	var version cmd.Version

	server, err := flags.PrepareServer(viper.GetString(client.ServerFlag))
	if err != nil {
		return version, err
	}

	version.Server = server
	version.CMD = cmdCobra
	return version, nil
}
