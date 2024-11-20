// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.34.2
// 	protoc        v5.28.1
// source: api/v1beta1/status.proto

package v1beta1

import (
	duration "github.com/golang/protobuf/ptypes/duration"
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	reflect "reflect"
	sync "sync"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

type Status struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// Main fields
	StatusInfo            *StatusInfo            `protobuf:"bytes,1,opt,name=status_info,json=statusInfo,proto3" json:"status_info,omitempty"`
	PerformanceSummary    *PerformanceSummary    `protobuf:"bytes,2,opt,name=performance_summary,json=performanceSummary,proto3" json:"performance_summary,omitempty"`
	EventStats            *EventStats            `protobuf:"bytes,3,opt,name=event_stats,json=eventStats,proto3" json:"event_stats,omitempty"`
	PolicySummary         *PolicySummary         `protobuf:"bytes,4,opt,name=policy_summary,json=policySummary,proto3" json:"policy_summary,omitempty"`
	ArtifactCaptureStatus *ArtifactCaptureStatus `protobuf:"bytes,5,opt,name=artifact_capture_status,json=artifactCaptureStatus,proto3" json:"artifact_capture_status,omitempty"`
	ProbeStatus           *ProbeStatus           `protobuf:"bytes,6,opt,name=probe_status,json=probeStatus,proto3" json:"probe_status,omitempty"`
	StreamSummary         *StreamSummary         `protobuf:"bytes,7,opt,name=stream_summary,json=streamSummary,proto3" json:"stream_summary,omitempty"` // Optional additional section
}

func (x *Status) Reset() {
	*x = Status{}
	if protoimpl.UnsafeEnabled {
		mi := &file_api_v1beta1_status_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Status) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Status) ProtoMessage() {}

func (x *Status) ProtoReflect() protoreflect.Message {
	mi := &file_api_v1beta1_status_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Status.ProtoReflect.Descriptor instead.
func (*Status) Descriptor() ([]byte, []int) {
	return file_api_v1beta1_status_proto_rawDescGZIP(), []int{0}
}

func (x *Status) GetStatusInfo() *StatusInfo {
	if x != nil {
		return x.StatusInfo
	}
	return nil
}

func (x *Status) GetPerformanceSummary() *PerformanceSummary {
	if x != nil {
		return x.PerformanceSummary
	}
	return nil
}

func (x *Status) GetEventStats() *EventStats {
	if x != nil {
		return x.EventStats
	}
	return nil
}

func (x *Status) GetPolicySummary() *PolicySummary {
	if x != nil {
		return x.PolicySummary
	}
	return nil
}

func (x *Status) GetArtifactCaptureStatus() *ArtifactCaptureStatus {
	if x != nil {
		return x.ArtifactCaptureStatus
	}
	return nil
}

func (x *Status) GetProbeStatus() *ProbeStatus {
	if x != nil {
		return x.ProbeStatus
	}
	return nil
}

func (x *Status) GetStreamSummary() *StreamSummary {
	if x != nil {
		return x.StreamSummary
	}
	return nil
}

// General status information
type StatusInfo struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Uptime  *duration.Duration `protobuf:"bytes,1,opt,name=uptime,proto3" json:"uptime,omitempty"`   // Service uptime
	Version string             `protobuf:"bytes,2,opt,name=version,proto3" json:"version,omitempty"` // Service version
	Pid     int64              `protobuf:"varint,3,opt,name=pid,proto3" json:"pid,omitempty"`        // Process ID
}

func (x *StatusInfo) Reset() {
	*x = StatusInfo{}
	if protoimpl.UnsafeEnabled {
		mi := &file_api_v1beta1_status_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *StatusInfo) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*StatusInfo) ProtoMessage() {}

func (x *StatusInfo) ProtoReflect() protoreflect.Message {
	mi := &file_api_v1beta1_status_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use StatusInfo.ProtoReflect.Descriptor instead.
func (*StatusInfo) Descriptor() ([]byte, []int) {
	return file_api_v1beta1_status_proto_rawDescGZIP(), []int{1}
}

func (x *StatusInfo) GetUptime() *duration.Duration {
	if x != nil {
		return x.Uptime
	}
	return nil
}

func (x *StatusInfo) GetVersion() string {
	if x != nil {
		return x.Version
	}
	return ""
}

func (x *StatusInfo) GetPid() int64 {
	if x != nil {
		return x.Pid
	}
	return 0
}

// Performance summary
type PerformanceSummary struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	MemoryUsage int64   `protobuf:"varint,1,opt,name=memory_usage,json=memoryUsage,proto3" json:"memory_usage,omitempty"` // Memory usage in MB
	CpuUsage    float32 `protobuf:"fixed32,2,opt,name=cpu_usage,json=cpuUsage,proto3" json:"cpu_usage,omitempty"`         // CPU usage percentage
}

func (x *PerformanceSummary) Reset() {
	*x = PerformanceSummary{}
	if protoimpl.UnsafeEnabled {
		mi := &file_api_v1beta1_status_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *PerformanceSummary) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*PerformanceSummary) ProtoMessage() {}

func (x *PerformanceSummary) ProtoReflect() protoreflect.Message {
	mi := &file_api_v1beta1_status_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use PerformanceSummary.ProtoReflect.Descriptor instead.
func (*PerformanceSummary) Descriptor() ([]byte, []int) {
	return file_api_v1beta1_status_proto_rawDescGZIP(), []int{2}
}

func (x *PerformanceSummary) GetMemoryUsage() int64 {
	if x != nil {
		return x.MemoryUsage
	}
	return 0
}

func (x *PerformanceSummary) GetCpuUsage() float32 {
	if x != nil {
		return x.CpuUsage
	}
	return 0
}

// Event statistics
type EventStats struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	TotalEventsCaptured int64 `protobuf:"varint,1,opt,name=total_events_captured,json=totalEventsCaptured,proto3" json:"total_events_captured,omitempty"` // Total events captured
	EventsProcessed     int64 `protobuf:"varint,2,opt,name=events_processed,json=eventsProcessed,proto3" json:"events_processed,omitempty"`               // Successfully processed events
	EventsDropped       int64 `protobuf:"varint,3,opt,name=events_dropped,json=eventsDropped,proto3" json:"events_dropped,omitempty"`                     // Events dropped
}

func (x *EventStats) Reset() {
	*x = EventStats{}
	if protoimpl.UnsafeEnabled {
		mi := &file_api_v1beta1_status_proto_msgTypes[3]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *EventStats) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*EventStats) ProtoMessage() {}

func (x *EventStats) ProtoReflect() protoreflect.Message {
	mi := &file_api_v1beta1_status_proto_msgTypes[3]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use EventStats.ProtoReflect.Descriptor instead.
func (*EventStats) Descriptor() ([]byte, []int) {
	return file_api_v1beta1_status_proto_rawDescGZIP(), []int{3}
}

func (x *EventStats) GetTotalEventsCaptured() int64 {
	if x != nil {
		return x.TotalEventsCaptured
	}
	return 0
}

func (x *EventStats) GetEventsProcessed() int64 {
	if x != nil {
		return x.EventsProcessed
	}
	return 0
}

func (x *EventStats) GetEventsDropped() int64 {
	if x != nil {
		return x.EventsDropped
	}
	return 0
}

// Policy summary
type PolicySummary struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	NumberOfPolicies int64 `protobuf:"varint,1,opt,name=number_of_policies,json=numberOfPolicies,proto3" json:"number_of_policies,omitempty"` // Total number of policies
}

func (x *PolicySummary) Reset() {
	*x = PolicySummary{}
	if protoimpl.UnsafeEnabled {
		mi := &file_api_v1beta1_status_proto_msgTypes[4]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *PolicySummary) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*PolicySummary) ProtoMessage() {}

func (x *PolicySummary) ProtoReflect() protoreflect.Message {
	mi := &file_api_v1beta1_status_proto_msgTypes[4]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use PolicySummary.ProtoReflect.Descriptor instead.
func (*PolicySummary) Descriptor() ([]byte, []int) {
	return file_api_v1beta1_status_proto_rawDescGZIP(), []int{4}
}

func (x *PolicySummary) GetNumberOfPolicies() int64 {
	if x != nil {
		return x.NumberOfPolicies
	}
	return 0
}

// Stream summary
type StreamSummary struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	ActiveStreams int64 `protobuf:"varint,1,opt,name=active_streams,json=activeStreams,proto3" json:"active_streams,omitempty"` // Number of active streams
}

func (x *StreamSummary) Reset() {
	*x = StreamSummary{}
	if protoimpl.UnsafeEnabled {
		mi := &file_api_v1beta1_status_proto_msgTypes[5]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *StreamSummary) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*StreamSummary) ProtoMessage() {}

func (x *StreamSummary) ProtoReflect() protoreflect.Message {
	mi := &file_api_v1beta1_status_proto_msgTypes[5]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use StreamSummary.ProtoReflect.Descriptor instead.
func (*StreamSummary) Descriptor() ([]byte, []int) {
	return file_api_v1beta1_status_proto_rawDescGZIP(), []int{5}
}

func (x *StreamSummary) GetActiveStreams() int64 {
	if x != nil {
		return x.ActiveStreams
	}
	return 0
}

// Artifact capture status
type ArtifactCaptureStatus struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Enabled           bool   `protobuf:"varint,1,opt,name=enabled,proto3" json:"enabled,omitempty"`                                             // Whether artifact capture is enabled
	CapturedArtifacts string `protobuf:"bytes,2,opt,name=captured_artifacts,json=capturedArtifacts,proto3" json:"captured_artifacts,omitempty"` //TODO:
	StorageLocation   string `protobuf:"bytes,3,opt,name=storage_location,json=storageLocation,proto3" json:"storage_location,omitempty"`       // work on how the artifect ill look
}

func (x *ArtifactCaptureStatus) Reset() {
	*x = ArtifactCaptureStatus{}
	if protoimpl.UnsafeEnabled {
		mi := &file_api_v1beta1_status_proto_msgTypes[6]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ArtifactCaptureStatus) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ArtifactCaptureStatus) ProtoMessage() {}

func (x *ArtifactCaptureStatus) ProtoReflect() protoreflect.Message {
	mi := &file_api_v1beta1_status_proto_msgTypes[6]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ArtifactCaptureStatus.ProtoReflect.Descriptor instead.
func (*ArtifactCaptureStatus) Descriptor() ([]byte, []int) {
	return file_api_v1beta1_status_proto_rawDescGZIP(), []int{6}
}

func (x *ArtifactCaptureStatus) GetEnabled() bool {
	if x != nil {
		return x.Enabled
	}
	return false
}

func (x *ArtifactCaptureStatus) GetCapturedArtifacts() string {
	if x != nil {
		return x.CapturedArtifacts
	}
	return ""
}

func (x *ArtifactCaptureStatus) GetStorageLocation() string {
	if x != nil {
		return x.StorageLocation
	}
	return ""
}

// eBPF probe status
type ProbeStatus struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	LoadedProbes []string                   `protobuf:"bytes,1,rep,name=loaded_probes,json=loadedProbes,proto3" json:"loaded_probes,omitempty"` // List of successfully loaded probes
	FailedProbes []*ProbeStatus_FailedProbe `protobuf:"bytes,2,rep,name=failed_probes,json=failedProbes,proto3" json:"failed_probes,omitempty"` // List of failed probes with reasons
}

func (x *ProbeStatus) Reset() {
	*x = ProbeStatus{}
	if protoimpl.UnsafeEnabled {
		mi := &file_api_v1beta1_status_proto_msgTypes[7]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ProbeStatus) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ProbeStatus) ProtoMessage() {}

func (x *ProbeStatus) ProtoReflect() protoreflect.Message {
	mi := &file_api_v1beta1_status_proto_msgTypes[7]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ProbeStatus.ProtoReflect.Descriptor instead.
func (*ProbeStatus) Descriptor() ([]byte, []int) {
	return file_api_v1beta1_status_proto_rawDescGZIP(), []int{7}
}

func (x *ProbeStatus) GetLoadedProbes() []string {
	if x != nil {
		return x.LoadedProbes
	}
	return nil
}

func (x *ProbeStatus) GetFailedProbes() []*ProbeStatus_FailedProbe {
	if x != nil {
		return x.FailedProbes
	}
	return nil
}

type ProbeStatus_FailedProbe struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Name   string `protobuf:"bytes,1,opt,name=name,proto3" json:"name,omitempty"`     // Name of the failed probe
	Reason string `protobuf:"bytes,2,opt,name=reason,proto3" json:"reason,omitempty"` // Reason for failure
}

func (x *ProbeStatus_FailedProbe) Reset() {
	*x = ProbeStatus_FailedProbe{}
	if protoimpl.UnsafeEnabled {
		mi := &file_api_v1beta1_status_proto_msgTypes[8]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ProbeStatus_FailedProbe) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ProbeStatus_FailedProbe) ProtoMessage() {}

func (x *ProbeStatus_FailedProbe) ProtoReflect() protoreflect.Message {
	mi := &file_api_v1beta1_status_proto_msgTypes[8]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ProbeStatus_FailedProbe.ProtoReflect.Descriptor instead.
func (*ProbeStatus_FailedProbe) Descriptor() ([]byte, []int) {
	return file_api_v1beta1_status_proto_rawDescGZIP(), []int{7, 0}
}

func (x *ProbeStatus_FailedProbe) GetName() string {
	if x != nil {
		return x.Name
	}
	return ""
}

func (x *ProbeStatus_FailedProbe) GetReason() string {
	if x != nil {
		return x.Reason
	}
	return ""
}

var File_api_v1beta1_status_proto protoreflect.FileDescriptor

var file_api_v1beta1_status_proto_rawDesc = []byte{
	0x0a, 0x18, 0x61, 0x70, 0x69, 0x2f, 0x76, 0x31, 0x62, 0x65, 0x74, 0x61, 0x31, 0x2f, 0x73, 0x74,
	0x61, 0x74, 0x75, 0x73, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x0e, 0x74, 0x72, 0x61, 0x63,
	0x65, 0x65, 0x2e, 0x76, 0x31, 0x62, 0x65, 0x74, 0x61, 0x31, 0x1a, 0x1e, 0x67, 0x6f, 0x6f, 0x67,
	0x6c, 0x65, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2f, 0x64, 0x75, 0x72, 0x61,
	0x74, 0x69, 0x6f, 0x6e, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0x82, 0x04, 0x0a, 0x06, 0x53,
	0x74, 0x61, 0x74, 0x75, 0x73, 0x12, 0x3b, 0x0a, 0x0b, 0x73, 0x74, 0x61, 0x74, 0x75, 0x73, 0x5f,
	0x69, 0x6e, 0x66, 0x6f, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x1a, 0x2e, 0x74, 0x72, 0x61,
	0x63, 0x65, 0x65, 0x2e, 0x76, 0x31, 0x62, 0x65, 0x74, 0x61, 0x31, 0x2e, 0x53, 0x74, 0x61, 0x74,
	0x75, 0x73, 0x49, 0x6e, 0x66, 0x6f, 0x52, 0x0a, 0x73, 0x74, 0x61, 0x74, 0x75, 0x73, 0x49, 0x6e,
	0x66, 0x6f, 0x12, 0x53, 0x0a, 0x13, 0x70, 0x65, 0x72, 0x66, 0x6f, 0x72, 0x6d, 0x61, 0x6e, 0x63,
	0x65, 0x5f, 0x73, 0x75, 0x6d, 0x6d, 0x61, 0x72, 0x79, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0b, 0x32,
	0x22, 0x2e, 0x74, 0x72, 0x61, 0x63, 0x65, 0x65, 0x2e, 0x76, 0x31, 0x62, 0x65, 0x74, 0x61, 0x31,
	0x2e, 0x50, 0x65, 0x72, 0x66, 0x6f, 0x72, 0x6d, 0x61, 0x6e, 0x63, 0x65, 0x53, 0x75, 0x6d, 0x6d,
	0x61, 0x72, 0x79, 0x52, 0x12, 0x70, 0x65, 0x72, 0x66, 0x6f, 0x72, 0x6d, 0x61, 0x6e, 0x63, 0x65,
	0x53, 0x75, 0x6d, 0x6d, 0x61, 0x72, 0x79, 0x12, 0x3b, 0x0a, 0x0b, 0x65, 0x76, 0x65, 0x6e, 0x74,
	0x5f, 0x73, 0x74, 0x61, 0x74, 0x73, 0x18, 0x03, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x1a, 0x2e, 0x74,
	0x72, 0x61, 0x63, 0x65, 0x65, 0x2e, 0x76, 0x31, 0x62, 0x65, 0x74, 0x61, 0x31, 0x2e, 0x45, 0x76,
	0x65, 0x6e, 0x74, 0x53, 0x74, 0x61, 0x74, 0x73, 0x52, 0x0a, 0x65, 0x76, 0x65, 0x6e, 0x74, 0x53,
	0x74, 0x61, 0x74, 0x73, 0x12, 0x44, 0x0a, 0x0e, 0x70, 0x6f, 0x6c, 0x69, 0x63, 0x79, 0x5f, 0x73,
	0x75, 0x6d, 0x6d, 0x61, 0x72, 0x79, 0x18, 0x04, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x1d, 0x2e, 0x74,
	0x72, 0x61, 0x63, 0x65, 0x65, 0x2e, 0x76, 0x31, 0x62, 0x65, 0x74, 0x61, 0x31, 0x2e, 0x50, 0x6f,
	0x6c, 0x69, 0x63, 0x79, 0x53, 0x75, 0x6d, 0x6d, 0x61, 0x72, 0x79, 0x52, 0x0d, 0x70, 0x6f, 0x6c,
	0x69, 0x63, 0x79, 0x53, 0x75, 0x6d, 0x6d, 0x61, 0x72, 0x79, 0x12, 0x5d, 0x0a, 0x17, 0x61, 0x72,
	0x74, 0x69, 0x66, 0x61, 0x63, 0x74, 0x5f, 0x63, 0x61, 0x70, 0x74, 0x75, 0x72, 0x65, 0x5f, 0x73,
	0x74, 0x61, 0x74, 0x75, 0x73, 0x18, 0x05, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x25, 0x2e, 0x74, 0x72,
	0x61, 0x63, 0x65, 0x65, 0x2e, 0x76, 0x31, 0x62, 0x65, 0x74, 0x61, 0x31, 0x2e, 0x41, 0x72, 0x74,
	0x69, 0x66, 0x61, 0x63, 0x74, 0x43, 0x61, 0x70, 0x74, 0x75, 0x72, 0x65, 0x53, 0x74, 0x61, 0x74,
	0x75, 0x73, 0x52, 0x15, 0x61, 0x72, 0x74, 0x69, 0x66, 0x61, 0x63, 0x74, 0x43, 0x61, 0x70, 0x74,
	0x75, 0x72, 0x65, 0x53, 0x74, 0x61, 0x74, 0x75, 0x73, 0x12, 0x3e, 0x0a, 0x0c, 0x70, 0x72, 0x6f,
	0x62, 0x65, 0x5f, 0x73, 0x74, 0x61, 0x74, 0x75, 0x73, 0x18, 0x06, 0x20, 0x01, 0x28, 0x0b, 0x32,
	0x1b, 0x2e, 0x74, 0x72, 0x61, 0x63, 0x65, 0x65, 0x2e, 0x76, 0x31, 0x62, 0x65, 0x74, 0x61, 0x31,
	0x2e, 0x50, 0x72, 0x6f, 0x62, 0x65, 0x53, 0x74, 0x61, 0x74, 0x75, 0x73, 0x52, 0x0b, 0x70, 0x72,
	0x6f, 0x62, 0x65, 0x53, 0x74, 0x61, 0x74, 0x75, 0x73, 0x12, 0x44, 0x0a, 0x0e, 0x73, 0x74, 0x72,
	0x65, 0x61, 0x6d, 0x5f, 0x73, 0x75, 0x6d, 0x6d, 0x61, 0x72, 0x79, 0x18, 0x07, 0x20, 0x01, 0x28,
	0x0b, 0x32, 0x1d, 0x2e, 0x74, 0x72, 0x61, 0x63, 0x65, 0x65, 0x2e, 0x76, 0x31, 0x62, 0x65, 0x74,
	0x61, 0x31, 0x2e, 0x53, 0x74, 0x72, 0x65, 0x61, 0x6d, 0x53, 0x75, 0x6d, 0x6d, 0x61, 0x72, 0x79,
	0x52, 0x0d, 0x73, 0x74, 0x72, 0x65, 0x61, 0x6d, 0x53, 0x75, 0x6d, 0x6d, 0x61, 0x72, 0x79, 0x22,
	0x6b, 0x0a, 0x0a, 0x53, 0x74, 0x61, 0x74, 0x75, 0x73, 0x49, 0x6e, 0x66, 0x6f, 0x12, 0x31, 0x0a,
	0x06, 0x75, 0x70, 0x74, 0x69, 0x6d, 0x65, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x19, 0x2e,
	0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e,
	0x44, 0x75, 0x72, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x52, 0x06, 0x75, 0x70, 0x74, 0x69, 0x6d, 0x65,
	0x12, 0x18, 0x0a, 0x07, 0x76, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x18, 0x02, 0x20, 0x01, 0x28,
	0x09, 0x52, 0x07, 0x76, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x12, 0x10, 0x0a, 0x03, 0x70, 0x69,
	0x64, 0x18, 0x03, 0x20, 0x01, 0x28, 0x03, 0x52, 0x03, 0x70, 0x69, 0x64, 0x22, 0x54, 0x0a, 0x12,
	0x50, 0x65, 0x72, 0x66, 0x6f, 0x72, 0x6d, 0x61, 0x6e, 0x63, 0x65, 0x53, 0x75, 0x6d, 0x6d, 0x61,
	0x72, 0x79, 0x12, 0x21, 0x0a, 0x0c, 0x6d, 0x65, 0x6d, 0x6f, 0x72, 0x79, 0x5f, 0x75, 0x73, 0x61,
	0x67, 0x65, 0x18, 0x01, 0x20, 0x01, 0x28, 0x03, 0x52, 0x0b, 0x6d, 0x65, 0x6d, 0x6f, 0x72, 0x79,
	0x55, 0x73, 0x61, 0x67, 0x65, 0x12, 0x1b, 0x0a, 0x09, 0x63, 0x70, 0x75, 0x5f, 0x75, 0x73, 0x61,
	0x67, 0x65, 0x18, 0x02, 0x20, 0x01, 0x28, 0x02, 0x52, 0x08, 0x63, 0x70, 0x75, 0x55, 0x73, 0x61,
	0x67, 0x65, 0x22, 0x92, 0x01, 0x0a, 0x0a, 0x45, 0x76, 0x65, 0x6e, 0x74, 0x53, 0x74, 0x61, 0x74,
	0x73, 0x12, 0x32, 0x0a, 0x15, 0x74, 0x6f, 0x74, 0x61, 0x6c, 0x5f, 0x65, 0x76, 0x65, 0x6e, 0x74,
	0x73, 0x5f, 0x63, 0x61, 0x70, 0x74, 0x75, 0x72, 0x65, 0x64, 0x18, 0x01, 0x20, 0x01, 0x28, 0x03,
	0x52, 0x13, 0x74, 0x6f, 0x74, 0x61, 0x6c, 0x45, 0x76, 0x65, 0x6e, 0x74, 0x73, 0x43, 0x61, 0x70,
	0x74, 0x75, 0x72, 0x65, 0x64, 0x12, 0x29, 0x0a, 0x10, 0x65, 0x76, 0x65, 0x6e, 0x74, 0x73, 0x5f,
	0x70, 0x72, 0x6f, 0x63, 0x65, 0x73, 0x73, 0x65, 0x64, 0x18, 0x02, 0x20, 0x01, 0x28, 0x03, 0x52,
	0x0f, 0x65, 0x76, 0x65, 0x6e, 0x74, 0x73, 0x50, 0x72, 0x6f, 0x63, 0x65, 0x73, 0x73, 0x65, 0x64,
	0x12, 0x25, 0x0a, 0x0e, 0x65, 0x76, 0x65, 0x6e, 0x74, 0x73, 0x5f, 0x64, 0x72, 0x6f, 0x70, 0x70,
	0x65, 0x64, 0x18, 0x03, 0x20, 0x01, 0x28, 0x03, 0x52, 0x0d, 0x65, 0x76, 0x65, 0x6e, 0x74, 0x73,
	0x44, 0x72, 0x6f, 0x70, 0x70, 0x65, 0x64, 0x22, 0x3d, 0x0a, 0x0d, 0x50, 0x6f, 0x6c, 0x69, 0x63,
	0x79, 0x53, 0x75, 0x6d, 0x6d, 0x61, 0x72, 0x79, 0x12, 0x2c, 0x0a, 0x12, 0x6e, 0x75, 0x6d, 0x62,
	0x65, 0x72, 0x5f, 0x6f, 0x66, 0x5f, 0x70, 0x6f, 0x6c, 0x69, 0x63, 0x69, 0x65, 0x73, 0x18, 0x01,
	0x20, 0x01, 0x28, 0x03, 0x52, 0x10, 0x6e, 0x75, 0x6d, 0x62, 0x65, 0x72, 0x4f, 0x66, 0x50, 0x6f,
	0x6c, 0x69, 0x63, 0x69, 0x65, 0x73, 0x22, 0x36, 0x0a, 0x0d, 0x53, 0x74, 0x72, 0x65, 0x61, 0x6d,
	0x53, 0x75, 0x6d, 0x6d, 0x61, 0x72, 0x79, 0x12, 0x25, 0x0a, 0x0e, 0x61, 0x63, 0x74, 0x69, 0x76,
	0x65, 0x5f, 0x73, 0x74, 0x72, 0x65, 0x61, 0x6d, 0x73, 0x18, 0x01, 0x20, 0x01, 0x28, 0x03, 0x52,
	0x0d, 0x61, 0x63, 0x74, 0x69, 0x76, 0x65, 0x53, 0x74, 0x72, 0x65, 0x61, 0x6d, 0x73, 0x22, 0x8b,
	0x01, 0x0a, 0x15, 0x41, 0x72, 0x74, 0x69, 0x66, 0x61, 0x63, 0x74, 0x43, 0x61, 0x70, 0x74, 0x75,
	0x72, 0x65, 0x53, 0x74, 0x61, 0x74, 0x75, 0x73, 0x12, 0x18, 0x0a, 0x07, 0x65, 0x6e, 0x61, 0x62,
	0x6c, 0x65, 0x64, 0x18, 0x01, 0x20, 0x01, 0x28, 0x08, 0x52, 0x07, 0x65, 0x6e, 0x61, 0x62, 0x6c,
	0x65, 0x64, 0x12, 0x2d, 0x0a, 0x12, 0x63, 0x61, 0x70, 0x74, 0x75, 0x72, 0x65, 0x64, 0x5f, 0x61,
	0x72, 0x74, 0x69, 0x66, 0x61, 0x63, 0x74, 0x73, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x11,
	0x63, 0x61, 0x70, 0x74, 0x75, 0x72, 0x65, 0x64, 0x41, 0x72, 0x74, 0x69, 0x66, 0x61, 0x63, 0x74,
	0x73, 0x12, 0x29, 0x0a, 0x10, 0x73, 0x74, 0x6f, 0x72, 0x61, 0x67, 0x65, 0x5f, 0x6c, 0x6f, 0x63,
	0x61, 0x74, 0x69, 0x6f, 0x6e, 0x18, 0x03, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0f, 0x73, 0x74, 0x6f,
	0x72, 0x61, 0x67, 0x65, 0x4c, 0x6f, 0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x22, 0xbb, 0x01, 0x0a,
	0x0b, 0x50, 0x72, 0x6f, 0x62, 0x65, 0x53, 0x74, 0x61, 0x74, 0x75, 0x73, 0x12, 0x23, 0x0a, 0x0d,
	0x6c, 0x6f, 0x61, 0x64, 0x65, 0x64, 0x5f, 0x70, 0x72, 0x6f, 0x62, 0x65, 0x73, 0x18, 0x01, 0x20,
	0x03, 0x28, 0x09, 0x52, 0x0c, 0x6c, 0x6f, 0x61, 0x64, 0x65, 0x64, 0x50, 0x72, 0x6f, 0x62, 0x65,
	0x73, 0x12, 0x4c, 0x0a, 0x0d, 0x66, 0x61, 0x69, 0x6c, 0x65, 0x64, 0x5f, 0x70, 0x72, 0x6f, 0x62,
	0x65, 0x73, 0x18, 0x02, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x27, 0x2e, 0x74, 0x72, 0x61, 0x63, 0x65,
	0x65, 0x2e, 0x76, 0x31, 0x62, 0x65, 0x74, 0x61, 0x31, 0x2e, 0x50, 0x72, 0x6f, 0x62, 0x65, 0x53,
	0x74, 0x61, 0x74, 0x75, 0x73, 0x2e, 0x46, 0x61, 0x69, 0x6c, 0x65, 0x64, 0x50, 0x72, 0x6f, 0x62,
	0x65, 0x52, 0x0c, 0x66, 0x61, 0x69, 0x6c, 0x65, 0x64, 0x50, 0x72, 0x6f, 0x62, 0x65, 0x73, 0x1a,
	0x39, 0x0a, 0x0b, 0x46, 0x61, 0x69, 0x6c, 0x65, 0x64, 0x50, 0x72, 0x6f, 0x62, 0x65, 0x12, 0x12,
	0x0a, 0x04, 0x6e, 0x61, 0x6d, 0x65, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x04, 0x6e, 0x61,
	0x6d, 0x65, 0x12, 0x16, 0x0a, 0x06, 0x72, 0x65, 0x61, 0x73, 0x6f, 0x6e, 0x18, 0x02, 0x20, 0x01,
	0x28, 0x09, 0x52, 0x06, 0x72, 0x65, 0x61, 0x73, 0x6f, 0x6e, 0x42, 0x2b, 0x5a, 0x29, 0x67, 0x69,
	0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x2f, 0x61, 0x71, 0x75, 0x61, 0x73, 0x65, 0x63, 0x75,
	0x72, 0x69, 0x74, 0x79, 0x2f, 0x74, 0x72, 0x61, 0x63, 0x65, 0x65, 0x2f, 0x61, 0x70, 0x69, 0x2f,
	0x76, 0x31, 0x62, 0x65, 0x74, 0x61, 0x31, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_api_v1beta1_status_proto_rawDescOnce sync.Once
	file_api_v1beta1_status_proto_rawDescData = file_api_v1beta1_status_proto_rawDesc
)

func file_api_v1beta1_status_proto_rawDescGZIP() []byte {
	file_api_v1beta1_status_proto_rawDescOnce.Do(func() {
		file_api_v1beta1_status_proto_rawDescData = protoimpl.X.CompressGZIP(file_api_v1beta1_status_proto_rawDescData)
	})
	return file_api_v1beta1_status_proto_rawDescData
}

var file_api_v1beta1_status_proto_msgTypes = make([]protoimpl.MessageInfo, 9)
var file_api_v1beta1_status_proto_goTypes = []any{
	(*Status)(nil),                  // 0: tracee.v1beta1.Status
	(*StatusInfo)(nil),              // 1: tracee.v1beta1.StatusInfo
	(*PerformanceSummary)(nil),      // 2: tracee.v1beta1.PerformanceSummary
	(*EventStats)(nil),              // 3: tracee.v1beta1.EventStats
	(*PolicySummary)(nil),           // 4: tracee.v1beta1.PolicySummary
	(*StreamSummary)(nil),           // 5: tracee.v1beta1.StreamSummary
	(*ArtifactCaptureStatus)(nil),   // 6: tracee.v1beta1.ArtifactCaptureStatus
	(*ProbeStatus)(nil),             // 7: tracee.v1beta1.ProbeStatus
	(*ProbeStatus_FailedProbe)(nil), // 8: tracee.v1beta1.ProbeStatus.FailedProbe
	(*duration.Duration)(nil),       // 9: google.protobuf.Duration
}
var file_api_v1beta1_status_proto_depIdxs = []int32{
	1, // 0: tracee.v1beta1.Status.status_info:type_name -> tracee.v1beta1.StatusInfo
	2, // 1: tracee.v1beta1.Status.performance_summary:type_name -> tracee.v1beta1.PerformanceSummary
	3, // 2: tracee.v1beta1.Status.event_stats:type_name -> tracee.v1beta1.EventStats
	4, // 3: tracee.v1beta1.Status.policy_summary:type_name -> tracee.v1beta1.PolicySummary
	6, // 4: tracee.v1beta1.Status.artifact_capture_status:type_name -> tracee.v1beta1.ArtifactCaptureStatus
	7, // 5: tracee.v1beta1.Status.probe_status:type_name -> tracee.v1beta1.ProbeStatus
	5, // 6: tracee.v1beta1.Status.stream_summary:type_name -> tracee.v1beta1.StreamSummary
	9, // 7: tracee.v1beta1.StatusInfo.uptime:type_name -> google.protobuf.Duration
	8, // 8: tracee.v1beta1.ProbeStatus.failed_probes:type_name -> tracee.v1beta1.ProbeStatus.FailedProbe
	9, // [9:9] is the sub-list for method output_type
	9, // [9:9] is the sub-list for method input_type
	9, // [9:9] is the sub-list for extension type_name
	9, // [9:9] is the sub-list for extension extendee
	0, // [0:9] is the sub-list for field type_name
}

func init() { file_api_v1beta1_status_proto_init() }
func file_api_v1beta1_status_proto_init() {
	if File_api_v1beta1_status_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_api_v1beta1_status_proto_msgTypes[0].Exporter = func(v any, i int) any {
			switch v := v.(*Status); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_api_v1beta1_status_proto_msgTypes[1].Exporter = func(v any, i int) any {
			switch v := v.(*StatusInfo); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_api_v1beta1_status_proto_msgTypes[2].Exporter = func(v any, i int) any {
			switch v := v.(*PerformanceSummary); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_api_v1beta1_status_proto_msgTypes[3].Exporter = func(v any, i int) any {
			switch v := v.(*EventStats); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_api_v1beta1_status_proto_msgTypes[4].Exporter = func(v any, i int) any {
			switch v := v.(*PolicySummary); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_api_v1beta1_status_proto_msgTypes[5].Exporter = func(v any, i int) any {
			switch v := v.(*StreamSummary); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_api_v1beta1_status_proto_msgTypes[6].Exporter = func(v any, i int) any {
			switch v := v.(*ArtifactCaptureStatus); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_api_v1beta1_status_proto_msgTypes[7].Exporter = func(v any, i int) any {
			switch v := v.(*ProbeStatus); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_api_v1beta1_status_proto_msgTypes[8].Exporter = func(v any, i int) any {
			switch v := v.(*ProbeStatus_FailedProbe); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_api_v1beta1_status_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   9,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_api_v1beta1_status_proto_goTypes,
		DependencyIndexes: file_api_v1beta1_status_proto_depIdxs,
		MessageInfos:      file_api_v1beta1_status_proto_msgTypes,
	}.Build()
	File_api_v1beta1_status_proto = out.File
	file_api_v1beta1_status_proto_rawDesc = nil
	file_api_v1beta1_status_proto_goTypes = nil
	file_api_v1beta1_status_proto_depIdxs = nil
}
