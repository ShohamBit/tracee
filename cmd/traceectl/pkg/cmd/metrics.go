package cmd

import (
	"context"
	"fmt"

	pb "github.com/aquasecurity/tracee/api/v1beta1"
	"github.com/aquasecurity/tracee/cmd/traceectl/pkg/client"
	"github.com/aquasecurity/tracee/cmd/traceectl/pkg/config"
	"github.com/spf13/cobra"
)

type Metrics struct {
	Config  config.Config
	Server  *client.Server
	Printer *cobra.Command
}

func (m Metrics) Run() error {
	if err := m.Server.Connect(); err != nil {
		return fmt.Errorf("error running version: %s", err)
	}
	defer m.Server.Close()

	response, err := m.Server.GetMetrics(context.Background(), &pb.GetMetricsRequest{})
	if err != nil {
		return fmt.Errorf("error getting metrics: %s", err)
	}
	if metricsJson, err := response.MarshalJSON(); err != nil {
		panic(err)
	} else {
		m.Printer.Printf("\n%s\n", metricsJson)
		return nil
	}
}
