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

var (
	startTime time.Time
)

func Init() {
	startTime = time.Now()
}

// GetStatusInfo returns the current status information
func GetStatusInfo() *pb.StatusInfo {
	return &pb.StatusInfo{
		Pid:     getPid(),
		Uptime:  durationpb.New(getUptime()),
		Version: version.GetVersion(),
	}
}

// Get uptime as a time.Duration
func getUptime() time.Duration {
	return time.Since(startTime)
}

// Get the PID of the process
func getPid() int64 {
	return int64(os.Getpid()) // Ensure compatibility with int32
}

// GetPerformanceSummary returns performance-related data
func GetPerformanceSummary() *pb.PerformanceSummary {
	return &pb.PerformanceSummary{
		MemoryUsage: getMemoryUsage(),
		CpuUsage:    getCpuUsage(),
	}
}

// Mocked functions for performance metrics
func getMemoryUsage() int64 {
	var mem runtime.MemStats
	runtime.ReadMemStats(&mem)
	return int64(mem.Alloc/2 ^ 20)
}

func getCpuUsage() float32 {
	// Read CPU times from /proc/self/stat
	readCPUStat := func() (float64, error) {
		data, err := os.ReadFile("/proc/self/stat")
		if err != nil {
			return 0, err
		}

		// Parse the fields from /proc/self/stat
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

		// Total CPU time used by the process
		return utime + stime, nil
	}

	// Get initial CPU time and wall clock time
	startCPU, _ := readCPUStat()
	startTime := time.Now()

	// Wait for an interval
	interval := 1 * time.Second
	time.Sleep(interval)

	// Get CPU time and wall clock time again
	endCPU, _ := readCPUStat()
	endTime := time.Now()

	// Calculate CPU usage percentage
	cpuTimeUsed := endCPU - startCPU
	totalTime := endTime.Sub(startTime).Seconds()
	cpuUsage := (cpuTimeUsed / totalTime) * 100

	return float32(cpuUsage)
}

func getNetworkLatency() int64 {
	// Placeholder: Replace with actual latency logic
	return 10 // Example: 10 ms
}

func getAverageEventProcessingTime() int32 {
	// Placeholder: Replace with actual event processing time logic
	return 15 // Example: 15 ms
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
