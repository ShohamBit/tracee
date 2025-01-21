package printer

import (
	"fmt"
	"strconv"
	"strings"

	pb "github.com/aquasecurity/tracee/api/v1beta1"
	"github.com/spf13/cobra"
)

type EventPrinter interface {
	// Init serves as the initializer method for every event Printer type
	Init() error
	// Preamble prints something before event printing begins (one time)
	Preamble()
	// Epilogue prints something after event printing ends (one time)
	Epilogue(metrics *pb.GetMetricsResponse)
	// Print prints a single event
	Print(event *pb.Event)
	// dispose of resources
	Close()
}

func New(cmd *cobra.Command, kind string) (EventPrinter, error) {
	var res EventPrinter
	switch kind {
	case "table":
		res = &tableEventPrinter{
			cmd: cmd,
		}
	case "json":
		res = &jsonEventPrinter{
			cmd: cmd,
		}
	default:
		return res, fmt.Errorf("unsupported output type: %s", kind)
	}
	err := res.Init()
	if err != nil {
		return nil, err
	}
	return res, nil
}

type tableEventPrinter struct {
	cmd *cobra.Command
}

func (p tableEventPrinter) Init() error { return nil }

func (p tableEventPrinter) Preamble() {
	p.cmd.Printf("%-15s %-10s %-20s %-15s %s\n",
		"TIME",
		"EVENT NAME",
		"POLICIES",
		"PID",
		"DATA",
	)
}

func (p tableEventPrinter) Epilogue(metrics *pb.GetMetricsResponse) {
	p.cmd.Printf("%s\n", metrics.String())
}

func (p tableEventPrinter) Print(event *pb.Event) {
	p.cmd.Printf("%-15s %-10s %-20s %-15s %s\n",
		event.Timestamp.AsTime().Format("15:04:05.000"),
		event.Name,
		strings.Join(event.Policies.Matched, ","),
		strconv.Itoa(int(event.Context.Process.Pid.Value)),
		event.GetData(),
	)
}

func (p tableEventPrinter) Close() {}

type jsonEventPrinter struct {
	cmd *cobra.Command
}

func (p jsonEventPrinter) Init() error { return nil }

func (p jsonEventPrinter) Preamble() {}

func (p jsonEventPrinter) Epilogue(metrics *pb.GetMetricsResponse) {
	p.cmd.Printf("%s\n", metrics.String())
}

func (p jsonEventPrinter) Print(event *pb.Event) {
	eBytes, err := event.MarshalJSON()
	if err != nil {
		p.cmd.PrintErrf("Error marshaling event to json: %s\n", err)
	}
	p.cmd.Printf("%s\n", string(eBytes))
}

func (p jsonEventPrinter) Close() {}
