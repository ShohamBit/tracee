package cobra

import (
	"github.com/spf13/cobra"

	"github.com/aquasecurity/tracee/pkg/cmd"
)

func GetTraceeRunner(c *cobra.Command, version string) (cmd.Runner, error) {
	var runner cmd.Runner
	//TODO:
	// 1. from now on tracee will not run at all
	// 2. in order to make tracee run complete thenest steps
	// 3. set up all flags in root
	// 4. set up config file
	// 5. set up config file and cli flags
	// 6. compleat this document according to viper flags

	// runner.HTTPServer = httpServer
	// runner.GRPCServer = grpcServer
	// runner.TraceeConfig = cfg
	// runner.Printer = p
	// runner.InstallPath = traceeInstallPath

	// runner.TraceeConfig.EngineConfig = engine.Config{
	// 	Enabled:          true,
	// 	SigNameToEventID: sigNameToEventId,
	// 	Signatures:       signatures,
	// 	SignatureBufferSize: 1000,
	// 	DataSources:         dataSources,
	// }

	return runner, nil
}
