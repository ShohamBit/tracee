// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.34.2
// 	protoc        v5.28.1
// source: api/v1beta1/tracee.proto

package v1beta1

import (
	field_mask "google.golang.org/genproto/protobuf/field_mask"
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

type GetVersionRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields
}

func (x *GetVersionRequest) Reset() {
	*x = GetVersionRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_api_v1beta1_tracee_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *GetVersionRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*GetVersionRequest) ProtoMessage() {}

func (x *GetVersionRequest) ProtoReflect() protoreflect.Message {
	mi := &file_api_v1beta1_tracee_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use GetVersionRequest.ProtoReflect.Descriptor instead.
func (*GetVersionRequest) Descriptor() ([]byte, []int) {
	return file_api_v1beta1_tracee_proto_rawDescGZIP(), []int{0}
}

type GetVersionResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Version string `protobuf:"bytes,1,opt,name=version,proto3" json:"version,omitempty"`
}

func (x *GetVersionResponse) Reset() {
	*x = GetVersionResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_api_v1beta1_tracee_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *GetVersionResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*GetVersionResponse) ProtoMessage() {}

func (x *GetVersionResponse) ProtoReflect() protoreflect.Message {
	mi := &file_api_v1beta1_tracee_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use GetVersionResponse.ProtoReflect.Descriptor instead.
func (*GetVersionResponse) Descriptor() ([]byte, []int) {
	return file_api_v1beta1_tracee_proto_rawDescGZIP(), []int{1}
}

func (x *GetVersionResponse) GetVersion() string {
	if x != nil {
		return x.Version
	}
	return ""
}

type GetEventDefinitionsRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	EventNames []string `protobuf:"bytes,1,rep,name=event_names,json=eventNames,proto3" json:"event_names,omitempty"` // TODO: tags
}

func (x *GetEventDefinitionsRequest) Reset() {
	*x = GetEventDefinitionsRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_api_v1beta1_tracee_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *GetEventDefinitionsRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*GetEventDefinitionsRequest) ProtoMessage() {}

func (x *GetEventDefinitionsRequest) ProtoReflect() protoreflect.Message {
	mi := &file_api_v1beta1_tracee_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use GetEventDefinitionsRequest.ProtoReflect.Descriptor instead.
func (*GetEventDefinitionsRequest) Descriptor() ([]byte, []int) {
	return file_api_v1beta1_tracee_proto_rawDescGZIP(), []int{2}
}

func (x *GetEventDefinitionsRequest) GetEventNames() []string {
	if x != nil {
		return x.EventNames
	}
	return nil
}

type GetEventDefinitionsResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Definitions []*EventDefinition `protobuf:"bytes,1,rep,name=definitions,proto3" json:"definitions,omitempty"`
}

func (x *GetEventDefinitionsResponse) Reset() {
	*x = GetEventDefinitionsResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_api_v1beta1_tracee_proto_msgTypes[3]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *GetEventDefinitionsResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*GetEventDefinitionsResponse) ProtoMessage() {}

func (x *GetEventDefinitionsResponse) ProtoReflect() protoreflect.Message {
	mi := &file_api_v1beta1_tracee_proto_msgTypes[3]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use GetEventDefinitionsResponse.ProtoReflect.Descriptor instead.
func (*GetEventDefinitionsResponse) Descriptor() ([]byte, []int) {
	return file_api_v1beta1_tracee_proto_rawDescGZIP(), []int{3}
}

func (x *GetEventDefinitionsResponse) GetDefinitions() []*EventDefinition {
	if x != nil {
		return x.Definitions
	}
	return nil
}

type EnableEventRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Name string `protobuf:"bytes,1,opt,name=name,proto3" json:"name,omitempty"`
}

func (x *EnableEventRequest) Reset() {
	*x = EnableEventRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_api_v1beta1_tracee_proto_msgTypes[4]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *EnableEventRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*EnableEventRequest) ProtoMessage() {}

func (x *EnableEventRequest) ProtoReflect() protoreflect.Message {
	mi := &file_api_v1beta1_tracee_proto_msgTypes[4]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use EnableEventRequest.ProtoReflect.Descriptor instead.
func (*EnableEventRequest) Descriptor() ([]byte, []int) {
	return file_api_v1beta1_tracee_proto_rawDescGZIP(), []int{4}
}

func (x *EnableEventRequest) GetName() string {
	if x != nil {
		return x.Name
	}
	return ""
}

type EnableEventResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields
}

func (x *EnableEventResponse) Reset() {
	*x = EnableEventResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_api_v1beta1_tracee_proto_msgTypes[5]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *EnableEventResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*EnableEventResponse) ProtoMessage() {}

func (x *EnableEventResponse) ProtoReflect() protoreflect.Message {
	mi := &file_api_v1beta1_tracee_proto_msgTypes[5]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use EnableEventResponse.ProtoReflect.Descriptor instead.
func (*EnableEventResponse) Descriptor() ([]byte, []int) {
	return file_api_v1beta1_tracee_proto_rawDescGZIP(), []int{5}
}

type DisableEventRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Name string `protobuf:"bytes,1,opt,name=name,proto3" json:"name,omitempty"`
}

func (x *DisableEventRequest) Reset() {
	*x = DisableEventRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_api_v1beta1_tracee_proto_msgTypes[6]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *DisableEventRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*DisableEventRequest) ProtoMessage() {}

func (x *DisableEventRequest) ProtoReflect() protoreflect.Message {
	mi := &file_api_v1beta1_tracee_proto_msgTypes[6]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use DisableEventRequest.ProtoReflect.Descriptor instead.
func (*DisableEventRequest) Descriptor() ([]byte, []int) {
	return file_api_v1beta1_tracee_proto_rawDescGZIP(), []int{6}
}

func (x *DisableEventRequest) GetName() string {
	if x != nil {
		return x.Name
	}
	return ""
}

type DisableEventResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields
}

func (x *DisableEventResponse) Reset() {
	*x = DisableEventResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_api_v1beta1_tracee_proto_msgTypes[7]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *DisableEventResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*DisableEventResponse) ProtoMessage() {}

func (x *DisableEventResponse) ProtoReflect() protoreflect.Message {
	mi := &file_api_v1beta1_tracee_proto_msgTypes[7]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use DisableEventResponse.ProtoReflect.Descriptor instead.
func (*DisableEventResponse) Descriptor() ([]byte, []int) {
	return file_api_v1beta1_tracee_proto_rawDescGZIP(), []int{7}
}

type StreamEventsRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Policies []string              `protobuf:"bytes,1,rep,name=policies,proto3" json:"policies,omitempty"`
	Mask     *field_mask.FieldMask `protobuf:"bytes,2,opt,name=mask,proto3" json:"mask,omitempty"`
}

func (x *StreamEventsRequest) Reset() {
	*x = StreamEventsRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_api_v1beta1_tracee_proto_msgTypes[8]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *StreamEventsRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*StreamEventsRequest) ProtoMessage() {}

func (x *StreamEventsRequest) ProtoReflect() protoreflect.Message {
	mi := &file_api_v1beta1_tracee_proto_msgTypes[8]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use StreamEventsRequest.ProtoReflect.Descriptor instead.
func (*StreamEventsRequest) Descriptor() ([]byte, []int) {
	return file_api_v1beta1_tracee_proto_rawDescGZIP(), []int{8}
}

func (x *StreamEventsRequest) GetPolicies() []string {
	if x != nil {
		return x.Policies
	}
	return nil
}

func (x *StreamEventsRequest) GetMask() *field_mask.FieldMask {
	if x != nil {
		return x.Mask
	}
	return nil
}

type StreamEventsResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Event *Event `protobuf:"bytes,1,opt,name=event,proto3" json:"event,omitempty"`
}

func (x *StreamEventsResponse) Reset() {
	*x = StreamEventsResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_api_v1beta1_tracee_proto_msgTypes[9]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *StreamEventsResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*StreamEventsResponse) ProtoMessage() {}

func (x *StreamEventsResponse) ProtoReflect() protoreflect.Message {
	mi := &file_api_v1beta1_tracee_proto_msgTypes[9]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use StreamEventsResponse.ProtoReflect.Descriptor instead.
func (*StreamEventsResponse) Descriptor() ([]byte, []int) {
	return file_api_v1beta1_tracee_proto_rawDescGZIP(), []int{9}
}

func (x *StreamEventsResponse) GetEvent() *Event {
	if x != nil {
		return x.Event
	}
	return nil
}

type GetStatusRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields
}

func (x *GetStatusRequest) Reset() {
	*x = GetStatusRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_api_v1beta1_tracee_proto_msgTypes[10]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *GetStatusRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*GetStatusRequest) ProtoMessage() {}

func (x *GetStatusRequest) ProtoReflect() protoreflect.Message {
	mi := &file_api_v1beta1_tracee_proto_msgTypes[10]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use GetStatusRequest.ProtoReflect.Descriptor instead.
func (*GetStatusRequest) Descriptor() ([]byte, []int) {
	return file_api_v1beta1_tracee_proto_rawDescGZIP(), []int{10}
}

type GetStatusResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Status *Status `protobuf:"bytes,1,opt,name=status,proto3" json:"status,omitempty"`
}

func (x *GetStatusResponse) Reset() {
	*x = GetStatusResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_api_v1beta1_tracee_proto_msgTypes[11]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *GetStatusResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*GetStatusResponse) ProtoMessage() {}

func (x *GetStatusResponse) ProtoReflect() protoreflect.Message {
	mi := &file_api_v1beta1_tracee_proto_msgTypes[11]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use GetStatusResponse.ProtoReflect.Descriptor instead.
func (*GetStatusResponse) Descriptor() ([]byte, []int) {
	return file_api_v1beta1_tracee_proto_rawDescGZIP(), []int{11}
}

func (x *GetStatusResponse) GetStatus() *Status {
	if x != nil {
		return x.Status
	}
	return nil
}

var File_api_v1beta1_tracee_proto protoreflect.FileDescriptor

var file_api_v1beta1_tracee_proto_rawDesc = []byte{
	0x0a, 0x18, 0x61, 0x70, 0x69, 0x2f, 0x76, 0x31, 0x62, 0x65, 0x74, 0x61, 0x31, 0x2f, 0x74, 0x72,
	0x61, 0x63, 0x65, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x0e, 0x74, 0x72, 0x61, 0x63,
	0x65, 0x65, 0x2e, 0x76, 0x31, 0x62, 0x65, 0x74, 0x61, 0x31, 0x1a, 0x20, 0x67, 0x6f, 0x6f, 0x67,
	0x6c, 0x65, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2f, 0x66, 0x69, 0x65, 0x6c,
	0x64, 0x5f, 0x6d, 0x61, 0x73, 0x6b, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x17, 0x61, 0x70,
	0x69, 0x2f, 0x76, 0x31, 0x62, 0x65, 0x74, 0x61, 0x31, 0x2f, 0x65, 0x76, 0x65, 0x6e, 0x74, 0x2e,
	0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x18, 0x61, 0x70, 0x69, 0x2f, 0x76, 0x31, 0x62, 0x65, 0x74,
	0x61, 0x31, 0x2f, 0x73, 0x74, 0x61, 0x74, 0x75, 0x73, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a,
	0x1c, 0x61, 0x70, 0x69, 0x2f, 0x76, 0x31, 0x62, 0x65, 0x74, 0x61, 0x31, 0x2f, 0x64, 0x65, 0x66,
	0x69, 0x6e, 0x69, 0x74, 0x69, 0x6f, 0x6e, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0x13, 0x0a,
	0x11, 0x47, 0x65, 0x74, 0x56, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x52, 0x65, 0x71, 0x75, 0x65,
	0x73, 0x74, 0x22, 0x2e, 0x0a, 0x12, 0x47, 0x65, 0x74, 0x56, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e,
	0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12, 0x18, 0x0a, 0x07, 0x76, 0x65, 0x72, 0x73,
	0x69, 0x6f, 0x6e, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x07, 0x76, 0x65, 0x72, 0x73, 0x69,
	0x6f, 0x6e, 0x22, 0x3d, 0x0a, 0x1a, 0x47, 0x65, 0x74, 0x45, 0x76, 0x65, 0x6e, 0x74, 0x44, 0x65,
	0x66, 0x69, 0x6e, 0x69, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74,
	0x12, 0x1f, 0x0a, 0x0b, 0x65, 0x76, 0x65, 0x6e, 0x74, 0x5f, 0x6e, 0x61, 0x6d, 0x65, 0x73, 0x18,
	0x01, 0x20, 0x03, 0x28, 0x09, 0x52, 0x0a, 0x65, 0x76, 0x65, 0x6e, 0x74, 0x4e, 0x61, 0x6d, 0x65,
	0x73, 0x22, 0x60, 0x0a, 0x1b, 0x47, 0x65, 0x74, 0x45, 0x76, 0x65, 0x6e, 0x74, 0x44, 0x65, 0x66,
	0x69, 0x6e, 0x69, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65,
	0x12, 0x41, 0x0a, 0x0b, 0x64, 0x65, 0x66, 0x69, 0x6e, 0x69, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x18,
	0x01, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x1f, 0x2e, 0x74, 0x72, 0x61, 0x63, 0x65, 0x65, 0x2e, 0x76,
	0x31, 0x62, 0x65, 0x74, 0x61, 0x31, 0x2e, 0x45, 0x76, 0x65, 0x6e, 0x74, 0x44, 0x65, 0x66, 0x69,
	0x6e, 0x69, 0x74, 0x69, 0x6f, 0x6e, 0x52, 0x0b, 0x64, 0x65, 0x66, 0x69, 0x6e, 0x69, 0x74, 0x69,
	0x6f, 0x6e, 0x73, 0x22, 0x28, 0x0a, 0x12, 0x45, 0x6e, 0x61, 0x62, 0x6c, 0x65, 0x45, 0x76, 0x65,
	0x6e, 0x74, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x12, 0x12, 0x0a, 0x04, 0x6e, 0x61, 0x6d,
	0x65, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x04, 0x6e, 0x61, 0x6d, 0x65, 0x22, 0x15, 0x0a,
	0x13, 0x45, 0x6e, 0x61, 0x62, 0x6c, 0x65, 0x45, 0x76, 0x65, 0x6e, 0x74, 0x52, 0x65, 0x73, 0x70,
	0x6f, 0x6e, 0x73, 0x65, 0x22, 0x29, 0x0a, 0x13, 0x44, 0x69, 0x73, 0x61, 0x62, 0x6c, 0x65, 0x45,
	0x76, 0x65, 0x6e, 0x74, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x12, 0x12, 0x0a, 0x04, 0x6e,
	0x61, 0x6d, 0x65, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x04, 0x6e, 0x61, 0x6d, 0x65, 0x22,
	0x16, 0x0a, 0x14, 0x44, 0x69, 0x73, 0x61, 0x62, 0x6c, 0x65, 0x45, 0x76, 0x65, 0x6e, 0x74, 0x52,
	0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x22, 0x61, 0x0a, 0x13, 0x53, 0x74, 0x72, 0x65, 0x61,
	0x6d, 0x45, 0x76, 0x65, 0x6e, 0x74, 0x73, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x12, 0x1a,
	0x0a, 0x08, 0x70, 0x6f, 0x6c, 0x69, 0x63, 0x69, 0x65, 0x73, 0x18, 0x01, 0x20, 0x03, 0x28, 0x09,
	0x52, 0x08, 0x70, 0x6f, 0x6c, 0x69, 0x63, 0x69, 0x65, 0x73, 0x12, 0x2e, 0x0a, 0x04, 0x6d, 0x61,
	0x73, 0x6b, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x1a, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c,
	0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e, 0x46, 0x69, 0x65, 0x6c, 0x64,
	0x4d, 0x61, 0x73, 0x6b, 0x52, 0x04, 0x6d, 0x61, 0x73, 0x6b, 0x22, 0x43, 0x0a, 0x14, 0x53, 0x74,
	0x72, 0x65, 0x61, 0x6d, 0x45, 0x76, 0x65, 0x6e, 0x74, 0x73, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e,
	0x73, 0x65, 0x12, 0x2b, 0x0a, 0x05, 0x65, 0x76, 0x65, 0x6e, 0x74, 0x18, 0x01, 0x20, 0x01, 0x28,
	0x0b, 0x32, 0x15, 0x2e, 0x74, 0x72, 0x61, 0x63, 0x65, 0x65, 0x2e, 0x76, 0x31, 0x62, 0x65, 0x74,
	0x61, 0x31, 0x2e, 0x45, 0x76, 0x65, 0x6e, 0x74, 0x52, 0x05, 0x65, 0x76, 0x65, 0x6e, 0x74, 0x22,
	0x12, 0x0a, 0x10, 0x47, 0x65, 0x74, 0x53, 0x74, 0x61, 0x74, 0x75, 0x73, 0x52, 0x65, 0x71, 0x75,
	0x65, 0x73, 0x74, 0x22, 0x43, 0x0a, 0x11, 0x47, 0x65, 0x74, 0x53, 0x74, 0x61, 0x74, 0x75, 0x73,
	0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12, 0x2e, 0x0a, 0x06, 0x73, 0x74, 0x61, 0x74,
	0x75, 0x73, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x16, 0x2e, 0x74, 0x72, 0x61, 0x63, 0x65,
	0x65, 0x2e, 0x76, 0x31, 0x62, 0x65, 0x74, 0x61, 0x31, 0x2e, 0x53, 0x74, 0x61, 0x74, 0x75, 0x73,
	0x52, 0x06, 0x73, 0x74, 0x61, 0x74, 0x75, 0x73, 0x32, 0xb6, 0x04, 0x0a, 0x0d, 0x54, 0x72, 0x61,
	0x63, 0x65, 0x65, 0x53, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x12, 0x6e, 0x0a, 0x13, 0x47, 0x65,
	0x74, 0x45, 0x76, 0x65, 0x6e, 0x74, 0x44, 0x65, 0x66, 0x69, 0x6e, 0x69, 0x74, 0x69, 0x6f, 0x6e,
	0x73, 0x12, 0x2a, 0x2e, 0x74, 0x72, 0x61, 0x63, 0x65, 0x65, 0x2e, 0x76, 0x31, 0x62, 0x65, 0x74,
	0x61, 0x31, 0x2e, 0x47, 0x65, 0x74, 0x45, 0x76, 0x65, 0x6e, 0x74, 0x44, 0x65, 0x66, 0x69, 0x6e,
	0x69, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x1a, 0x2b, 0x2e,
	0x74, 0x72, 0x61, 0x63, 0x65, 0x65, 0x2e, 0x76, 0x31, 0x62, 0x65, 0x74, 0x61, 0x31, 0x2e, 0x47,
	0x65, 0x74, 0x45, 0x76, 0x65, 0x6e, 0x74, 0x44, 0x65, 0x66, 0x69, 0x6e, 0x69, 0x74, 0x69, 0x6f,
	0x6e, 0x73, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12, 0x5b, 0x0a, 0x0c, 0x53, 0x74,
	0x72, 0x65, 0x61, 0x6d, 0x45, 0x76, 0x65, 0x6e, 0x74, 0x73, 0x12, 0x23, 0x2e, 0x74, 0x72, 0x61,
	0x63, 0x65, 0x65, 0x2e, 0x76, 0x31, 0x62, 0x65, 0x74, 0x61, 0x31, 0x2e, 0x53, 0x74, 0x72, 0x65,
	0x61, 0x6d, 0x45, 0x76, 0x65, 0x6e, 0x74, 0x73, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x1a,
	0x24, 0x2e, 0x74, 0x72, 0x61, 0x63, 0x65, 0x65, 0x2e, 0x76, 0x31, 0x62, 0x65, 0x74, 0x61, 0x31,
	0x2e, 0x53, 0x74, 0x72, 0x65, 0x61, 0x6d, 0x45, 0x76, 0x65, 0x6e, 0x74, 0x73, 0x52, 0x65, 0x73,
	0x70, 0x6f, 0x6e, 0x73, 0x65, 0x30, 0x01, 0x12, 0x56, 0x0a, 0x0b, 0x45, 0x6e, 0x61, 0x62, 0x6c,
	0x65, 0x45, 0x76, 0x65, 0x6e, 0x74, 0x12, 0x22, 0x2e, 0x74, 0x72, 0x61, 0x63, 0x65, 0x65, 0x2e,
	0x76, 0x31, 0x62, 0x65, 0x74, 0x61, 0x31, 0x2e, 0x45, 0x6e, 0x61, 0x62, 0x6c, 0x65, 0x45, 0x76,
	0x65, 0x6e, 0x74, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x1a, 0x23, 0x2e, 0x74, 0x72, 0x61,
	0x63, 0x65, 0x65, 0x2e, 0x76, 0x31, 0x62, 0x65, 0x74, 0x61, 0x31, 0x2e, 0x45, 0x6e, 0x61, 0x62,
	0x6c, 0x65, 0x45, 0x76, 0x65, 0x6e, 0x74, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12,
	0x59, 0x0a, 0x0c, 0x44, 0x69, 0x73, 0x61, 0x62, 0x6c, 0x65, 0x45, 0x76, 0x65, 0x6e, 0x74, 0x12,
	0x23, 0x2e, 0x74, 0x72, 0x61, 0x63, 0x65, 0x65, 0x2e, 0x76, 0x31, 0x62, 0x65, 0x74, 0x61, 0x31,
	0x2e, 0x44, 0x69, 0x73, 0x61, 0x62, 0x6c, 0x65, 0x45, 0x76, 0x65, 0x6e, 0x74, 0x52, 0x65, 0x71,
	0x75, 0x65, 0x73, 0x74, 0x1a, 0x24, 0x2e, 0x74, 0x72, 0x61, 0x63, 0x65, 0x65, 0x2e, 0x76, 0x31,
	0x62, 0x65, 0x74, 0x61, 0x31, 0x2e, 0x44, 0x69, 0x73, 0x61, 0x62, 0x6c, 0x65, 0x45, 0x76, 0x65,
	0x6e, 0x74, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12, 0x53, 0x0a, 0x0a, 0x47, 0x65,
	0x74, 0x56, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x12, 0x21, 0x2e, 0x74, 0x72, 0x61, 0x63, 0x65,
	0x65, 0x2e, 0x76, 0x31, 0x62, 0x65, 0x74, 0x61, 0x31, 0x2e, 0x47, 0x65, 0x74, 0x56, 0x65, 0x72,
	0x73, 0x69, 0x6f, 0x6e, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x1a, 0x22, 0x2e, 0x74, 0x72,
	0x61, 0x63, 0x65, 0x65, 0x2e, 0x76, 0x31, 0x62, 0x65, 0x74, 0x61, 0x31, 0x2e, 0x47, 0x65, 0x74,
	0x56, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12,
	0x50, 0x0a, 0x09, 0x47, 0x65, 0x74, 0x53, 0x74, 0x61, 0x74, 0x75, 0x73, 0x12, 0x20, 0x2e, 0x74,
	0x72, 0x61, 0x63, 0x65, 0x65, 0x2e, 0x76, 0x31, 0x62, 0x65, 0x74, 0x61, 0x31, 0x2e, 0x47, 0x65,
	0x74, 0x53, 0x74, 0x61, 0x74, 0x75, 0x73, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x1a, 0x21,
	0x2e, 0x74, 0x72, 0x61, 0x63, 0x65, 0x65, 0x2e, 0x76, 0x31, 0x62, 0x65, 0x74, 0x61, 0x31, 0x2e,
	0x47, 0x65, 0x74, 0x53, 0x74, 0x61, 0x74, 0x75, 0x73, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73,
	0x65, 0x42, 0x2b, 0x5a, 0x29, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x2f, 0x61,
	0x71, 0x75, 0x61, 0x73, 0x65, 0x63, 0x75, 0x72, 0x69, 0x74, 0x79, 0x2f, 0x74, 0x72, 0x61, 0x63,
	0x65, 0x65, 0x2f, 0x61, 0x70, 0x69, 0x2f, 0x76, 0x31, 0x62, 0x65, 0x74, 0x61, 0x31, 0x62, 0x06,
	0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_api_v1beta1_tracee_proto_rawDescOnce sync.Once
	file_api_v1beta1_tracee_proto_rawDescData = file_api_v1beta1_tracee_proto_rawDesc
)

func file_api_v1beta1_tracee_proto_rawDescGZIP() []byte {
	file_api_v1beta1_tracee_proto_rawDescOnce.Do(func() {
		file_api_v1beta1_tracee_proto_rawDescData = protoimpl.X.CompressGZIP(file_api_v1beta1_tracee_proto_rawDescData)
	})
	return file_api_v1beta1_tracee_proto_rawDescData
}

var file_api_v1beta1_tracee_proto_msgTypes = make([]protoimpl.MessageInfo, 12)
var file_api_v1beta1_tracee_proto_goTypes = []any{
	(*GetVersionRequest)(nil),           // 0: tracee.v1beta1.GetVersionRequest
	(*GetVersionResponse)(nil),          // 1: tracee.v1beta1.GetVersionResponse
	(*GetEventDefinitionsRequest)(nil),  // 2: tracee.v1beta1.GetEventDefinitionsRequest
	(*GetEventDefinitionsResponse)(nil), // 3: tracee.v1beta1.GetEventDefinitionsResponse
	(*EnableEventRequest)(nil),          // 4: tracee.v1beta1.EnableEventRequest
	(*EnableEventResponse)(nil),         // 5: tracee.v1beta1.EnableEventResponse
	(*DisableEventRequest)(nil),         // 6: tracee.v1beta1.DisableEventRequest
	(*DisableEventResponse)(nil),        // 7: tracee.v1beta1.DisableEventResponse
	(*StreamEventsRequest)(nil),         // 8: tracee.v1beta1.StreamEventsRequest
	(*StreamEventsResponse)(nil),        // 9: tracee.v1beta1.StreamEventsResponse
	(*GetStatusRequest)(nil),            // 10: tracee.v1beta1.GetStatusRequest
	(*GetStatusResponse)(nil),           // 11: tracee.v1beta1.GetStatusResponse
	(*EventDefinition)(nil),             // 12: tracee.v1beta1.EventDefinition
	(*field_mask.FieldMask)(nil),        // 13: google.protobuf.FieldMask
	(*Event)(nil),                       // 14: tracee.v1beta1.Event
	(*Status)(nil),                      // 15: tracee.v1beta1.Status
}
var file_api_v1beta1_tracee_proto_depIdxs = []int32{
	12, // 0: tracee.v1beta1.GetEventDefinitionsResponse.definitions:type_name -> tracee.v1beta1.EventDefinition
	13, // 1: tracee.v1beta1.StreamEventsRequest.mask:type_name -> google.protobuf.FieldMask
	14, // 2: tracee.v1beta1.StreamEventsResponse.event:type_name -> tracee.v1beta1.Event
	15, // 3: tracee.v1beta1.GetStatusResponse.status:type_name -> tracee.v1beta1.Status
	2,  // 4: tracee.v1beta1.TraceeService.GetEventDefinitions:input_type -> tracee.v1beta1.GetEventDefinitionsRequest
	8,  // 5: tracee.v1beta1.TraceeService.StreamEvents:input_type -> tracee.v1beta1.StreamEventsRequest
	4,  // 6: tracee.v1beta1.TraceeService.EnableEvent:input_type -> tracee.v1beta1.EnableEventRequest
	6,  // 7: tracee.v1beta1.TraceeService.DisableEvent:input_type -> tracee.v1beta1.DisableEventRequest
	0,  // 8: tracee.v1beta1.TraceeService.GetVersion:input_type -> tracee.v1beta1.GetVersionRequest
	10, // 9: tracee.v1beta1.TraceeService.GetStatus:input_type -> tracee.v1beta1.GetStatusRequest
	3,  // 10: tracee.v1beta1.TraceeService.GetEventDefinitions:output_type -> tracee.v1beta1.GetEventDefinitionsResponse
	9,  // 11: tracee.v1beta1.TraceeService.StreamEvents:output_type -> tracee.v1beta1.StreamEventsResponse
	5,  // 12: tracee.v1beta1.TraceeService.EnableEvent:output_type -> tracee.v1beta1.EnableEventResponse
	7,  // 13: tracee.v1beta1.TraceeService.DisableEvent:output_type -> tracee.v1beta1.DisableEventResponse
	1,  // 14: tracee.v1beta1.TraceeService.GetVersion:output_type -> tracee.v1beta1.GetVersionResponse
	11, // 15: tracee.v1beta1.TraceeService.GetStatus:output_type -> tracee.v1beta1.GetStatusResponse
	10, // [10:16] is the sub-list for method output_type
	4,  // [4:10] is the sub-list for method input_type
	4,  // [4:4] is the sub-list for extension type_name
	4,  // [4:4] is the sub-list for extension extendee
	0,  // [0:4] is the sub-list for field type_name
}

func init() { file_api_v1beta1_tracee_proto_init() }
func file_api_v1beta1_tracee_proto_init() {
	if File_api_v1beta1_tracee_proto != nil {
		return
	}
	file_api_v1beta1_event_proto_init()
	file_api_v1beta1_status_proto_init()
	file_api_v1beta1_definition_proto_init()
	if !protoimpl.UnsafeEnabled {
		file_api_v1beta1_tracee_proto_msgTypes[0].Exporter = func(v any, i int) any {
			switch v := v.(*GetVersionRequest); i {
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
		file_api_v1beta1_tracee_proto_msgTypes[1].Exporter = func(v any, i int) any {
			switch v := v.(*GetVersionResponse); i {
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
		file_api_v1beta1_tracee_proto_msgTypes[2].Exporter = func(v any, i int) any {
			switch v := v.(*GetEventDefinitionsRequest); i {
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
		file_api_v1beta1_tracee_proto_msgTypes[3].Exporter = func(v any, i int) any {
			switch v := v.(*GetEventDefinitionsResponse); i {
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
		file_api_v1beta1_tracee_proto_msgTypes[4].Exporter = func(v any, i int) any {
			switch v := v.(*EnableEventRequest); i {
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
		file_api_v1beta1_tracee_proto_msgTypes[5].Exporter = func(v any, i int) any {
			switch v := v.(*EnableEventResponse); i {
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
		file_api_v1beta1_tracee_proto_msgTypes[6].Exporter = func(v any, i int) any {
			switch v := v.(*DisableEventRequest); i {
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
		file_api_v1beta1_tracee_proto_msgTypes[7].Exporter = func(v any, i int) any {
			switch v := v.(*DisableEventResponse); i {
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
		file_api_v1beta1_tracee_proto_msgTypes[8].Exporter = func(v any, i int) any {
			switch v := v.(*StreamEventsRequest); i {
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
		file_api_v1beta1_tracee_proto_msgTypes[9].Exporter = func(v any, i int) any {
			switch v := v.(*StreamEventsResponse); i {
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
		file_api_v1beta1_tracee_proto_msgTypes[10].Exporter = func(v any, i int) any {
			switch v := v.(*GetStatusRequest); i {
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
		file_api_v1beta1_tracee_proto_msgTypes[11].Exporter = func(v any, i int) any {
			switch v := v.(*GetStatusResponse); i {
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
			RawDescriptor: file_api_v1beta1_tracee_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   12,
			NumExtensions: 0,
			NumServices:   1,
		},
		GoTypes:           file_api_v1beta1_tracee_proto_goTypes,
		DependencyIndexes: file_api_v1beta1_tracee_proto_depIdxs,
		MessageInfos:      file_api_v1beta1_tracee_proto_msgTypes,
	}.Build()
	File_api_v1beta1_tracee_proto = out.File
	file_api_v1beta1_tracee_proto_rawDesc = nil
	file_api_v1beta1_tracee_proto_goTypes = nil
	file_api_v1beta1_tracee_proto_depIdxs = nil
}
