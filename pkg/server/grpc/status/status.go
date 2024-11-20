package status

import (
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"

	pb "github.com/aquasecurity/tracee/api/v1beta1"
	"github.com/aquasecurity/tracee/pkg/version"
	"google.golang.org/protobuf/types/known/durationpb"
)

const (
	CLK_TCK = 100
)

var (
	startTime time.Time
)

func Init() {
	startTime = time.Now()
}
func GetStatusInfo() *pb.StatusInfo {
	return &pb.StatusInfo{
		Pid:     getPid(),
		Uptime:  durationpb.New(getUptime()),
		Version: version.GetVersion(),
	}
}

func getUptime() time.Duration {
	return time.Since(startTime)
}

func getPid() int64 {
	return int64(os.Getpid())
}

func GetPerformanceSummary() *pb.PerformanceSummary {
	return &pb.PerformanceSummary{
		MemoryUsage: getMemoryUsage(),
		CpuUsage:    getCpuUsage(),
	}
}

func getMemoryUsage() int64 {
	var mem runtime.MemStats
	runtime.ReadMemStats(&mem)
	return int64(mem.Sys / (1024 * 1024))
}

func getCpuUsage() float32 {
	readCPUStat := func() (float64, error) {
		data, err := os.ReadFile("/proc/self/stat")
		if err != nil {
			return 0, err
		}
		fields := strings.Fields(string(data))
		// Fields[13] (utime) and Fields[14] (stime) are process CPU times in clock ticks
		utime, err := strconv.ParseFloat(fields[13], 64)
		if err != nil {
			return 0, err
		}
		stime, err := strconv.ParseFloat(fields[14], 64)
		if err != nil {
			return 0, err
		}
		return utime + stime, nil
	}
	startCPU, _ := readCPUStat()
	startTime := time.Now()
	interval := 1 * time.Second
	time.Sleep(interval)

	endCPU, _ := readCPUStat()
	endTime := time.Now()

	// Calculate CPU usage percentage
	//cpu usage = (cpu time used / total time) / ticks
	cpuTimeUsed := endCPU - startCPU
	totalTime := endTime.Sub(startTime).Seconds()
	cpuUsage := (cpuTimeUsed / totalTime) / CLK_TCK * 100 //convert to percentages

	return float32(cpuUsage)
}

// GetEventStats returns event statistics
func GetEventStats() *pb.EventStats {
	return &pb.EventStats{
		TotalEventsCaptured: 15384, // Replace with actual data
		EventsProcessed:     14212,
		EventsDropped:       1172,
	}
}

// GetPolicySummary returns policy summary information
func GetPolicySummary() *pb.PolicySummary {
	return &pb.PolicySummary{
		NumberOfPolicies: 2, // Replace with actual policy count
	}
}

// GetArtifactCaptureStatus returns artifact capture details
func GetArtifactCaptureStatus() *pb.ArtifactCaptureStatus {
	return &pb.ArtifactCaptureStatus{
		Enabled:           true, // Replace with actual logic
		CapturedArtifacts: "3 network packets, 1 file write",
		StorageLocation:   "/tmp/tracee/artifacts",
	}
}

// GetProbeStatus returns the status of eBPF probes
func GetProbeStatus() *pb.ProbeStatus {
	return &pb.ProbeStatus{
		LoadedProbes: []string{"open", "openat", "execve"}, // Replace with actual probe names
		FailedProbes: []*pb.ProbeStatus_FailedProbe{
			{
				Name:   "mmap",
				Reason: "permission denied",
			},
		},
	}
}

// GetStreamSummary returns active stream details
func GetStreamSummary() *pb.StreamSummary {
	return &pb.StreamSummary{
		ActiveStreams: 5, // Replace with actual active stream count
	}
}
