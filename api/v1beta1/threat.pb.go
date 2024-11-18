// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.34.2
// 	protoc        v5.28.1
// source: api/v1beta1/threat.proto

package v1beta1

import (
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

type Severity int32

const (
	Severity_INFO     Severity = 0
	Severity_LOW      Severity = 1
	Severity_MEDIUM   Severity = 2
	Severity_HIGH     Severity = 3
	Severity_CRITICAL Severity = 4
)

// Enum value maps for Severity.
var (
	Severity_name = map[int32]string{
		0: "INFO",
		1: "LOW",
		2: "MEDIUM",
		3: "HIGH",
		4: "CRITICAL",
	}
	Severity_value = map[string]int32{
		"INFO":     0,
		"LOW":      1,
		"MEDIUM":   2,
		"HIGH":     3,
		"CRITICAL": 4,
	}
)

func (x Severity) Enum() *Severity {
	p := new(Severity)
	*p = x
	return p
}

func (x Severity) String() string {
	return protoimpl.X.EnumStringOf(x.Descriptor(), protoreflect.EnumNumber(x))
}

func (Severity) Descriptor() protoreflect.EnumDescriptor {
	return file_api_v1beta1_threat_proto_enumTypes[0].Descriptor()
}

func (Severity) Type() protoreflect.EnumType {
	return &file_api_v1beta1_threat_proto_enumTypes[0]
}

func (x Severity) Number() protoreflect.EnumNumber {
	return protoreflect.EnumNumber(x)
}

// Deprecated: Use Severity.Descriptor instead.
func (Severity) EnumDescriptor() ([]byte, []int) {
	return file_api_v1beta1_threat_proto_rawDescGZIP(), []int{0}
}

type Threat struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Description string            `protobuf:"bytes,1,opt,name=description,proto3" json:"description,omitempty"`
	Mitre       *Mitre            `protobuf:"bytes,2,opt,name=mitre,proto3" json:"mitre,omitempty"`
	Severity    Severity          `protobuf:"varint,3,opt,name=severity,proto3,enum=tracee.v1beta1.Severity" json:"severity,omitempty"`
	Name        string            `protobuf:"bytes,4,opt,name=name,proto3" json:"name,omitempty"`
	Properties  map[string]string `protobuf:"bytes,5,rep,name=properties,proto3" json:"properties,omitempty" protobuf_key:"bytes,1,opt,name=key,proto3" protobuf_val:"bytes,2,opt,name=value,proto3"`
}

func (x *Threat) Reset() {
	*x = Threat{}
	if protoimpl.UnsafeEnabled {
		mi := &file_api_v1beta1_threat_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Threat) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Threat) ProtoMessage() {}

func (x *Threat) ProtoReflect() protoreflect.Message {
	mi := &file_api_v1beta1_threat_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Threat.ProtoReflect.Descriptor instead.
func (*Threat) Descriptor() ([]byte, []int) {
	return file_api_v1beta1_threat_proto_rawDescGZIP(), []int{0}
}

func (x *Threat) GetDescription() string {
	if x != nil {
		return x.Description
	}
	return ""
}

func (x *Threat) GetMitre() *Mitre {
	if x != nil {
		return x.Mitre
	}
	return nil
}

func (x *Threat) GetSeverity() Severity {
	if x != nil {
		return x.Severity
	}
	return Severity_INFO
}

func (x *Threat) GetName() string {
	if x != nil {
		return x.Name
	}
	return ""
}

func (x *Threat) GetProperties() map[string]string {
	if x != nil {
		return x.Properties
	}
	return nil
}

type Mitre struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Tactic    *MitreTactic    `protobuf:"bytes,1,opt,name=tactic,proto3" json:"tactic,omitempty"`
	Technique *MitreTechnique `protobuf:"bytes,2,opt,name=technique,proto3" json:"technique,omitempty"`
}

func (x *Mitre) Reset() {
	*x = Mitre{}
	if protoimpl.UnsafeEnabled {
		mi := &file_api_v1beta1_threat_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Mitre) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Mitre) ProtoMessage() {}

func (x *Mitre) ProtoReflect() protoreflect.Message {
	mi := &file_api_v1beta1_threat_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Mitre.ProtoReflect.Descriptor instead.
func (*Mitre) Descriptor() ([]byte, []int) {
	return file_api_v1beta1_threat_proto_rawDescGZIP(), []int{1}
}

func (x *Mitre) GetTactic() *MitreTactic {
	if x != nil {
		return x.Tactic
	}
	return nil
}

func (x *Mitre) GetTechnique() *MitreTechnique {
	if x != nil {
		return x.Technique
	}
	return nil
}

type MitreTactic struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Name string `protobuf:"bytes,1,opt,name=name,proto3" json:"name,omitempty"`
}

func (x *MitreTactic) Reset() {
	*x = MitreTactic{}
	if protoimpl.UnsafeEnabled {
		mi := &file_api_v1beta1_threat_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *MitreTactic) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*MitreTactic) ProtoMessage() {}

func (x *MitreTactic) ProtoReflect() protoreflect.Message {
	mi := &file_api_v1beta1_threat_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use MitreTactic.ProtoReflect.Descriptor instead.
func (*MitreTactic) Descriptor() ([]byte, []int) {
	return file_api_v1beta1_threat_proto_rawDescGZIP(), []int{2}
}

func (x *MitreTactic) GetName() string {
	if x != nil {
		return x.Name
	}
	return ""
}

type MitreTechnique struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Id   string `protobuf:"bytes,1,opt,name=id,proto3" json:"id,omitempty"`
	Name string `protobuf:"bytes,2,opt,name=name,proto3" json:"name,omitempty"`
}

func (x *MitreTechnique) Reset() {
	*x = MitreTechnique{}
	if protoimpl.UnsafeEnabled {
		mi := &file_api_v1beta1_threat_proto_msgTypes[3]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *MitreTechnique) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*MitreTechnique) ProtoMessage() {}

func (x *MitreTechnique) ProtoReflect() protoreflect.Message {
	mi := &file_api_v1beta1_threat_proto_msgTypes[3]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use MitreTechnique.ProtoReflect.Descriptor instead.
func (*MitreTechnique) Descriptor() ([]byte, []int) {
	return file_api_v1beta1_threat_proto_rawDescGZIP(), []int{3}
}

func (x *MitreTechnique) GetId() string {
	if x != nil {
		return x.Id
	}
	return ""
}

func (x *MitreTechnique) GetName() string {
	if x != nil {
		return x.Name
	}
	return ""
}

var File_api_v1beta1_threat_proto protoreflect.FileDescriptor

var file_api_v1beta1_threat_proto_rawDesc = []byte{
	0x0a, 0x18, 0x61, 0x70, 0x69, 0x2f, 0x76, 0x31, 0x62, 0x65, 0x74, 0x61, 0x31, 0x2f, 0x74, 0x68,
	0x72, 0x65, 0x61, 0x74, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x0e, 0x74, 0x72, 0x61, 0x63,
	0x65, 0x65, 0x2e, 0x76, 0x31, 0x62, 0x65, 0x74, 0x61, 0x31, 0x22, 0xa8, 0x02, 0x0a, 0x06, 0x54,
	0x68, 0x72, 0x65, 0x61, 0x74, 0x12, 0x20, 0x0a, 0x0b, 0x64, 0x65, 0x73, 0x63, 0x72, 0x69, 0x70,
	0x74, 0x69, 0x6f, 0x6e, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0b, 0x64, 0x65, 0x73, 0x63,
	0x72, 0x69, 0x70, 0x74, 0x69, 0x6f, 0x6e, 0x12, 0x2b, 0x0a, 0x05, 0x6d, 0x69, 0x74, 0x72, 0x65,
	0x18, 0x02, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x15, 0x2e, 0x74, 0x72, 0x61, 0x63, 0x65, 0x65, 0x2e,
	0x76, 0x31, 0x62, 0x65, 0x74, 0x61, 0x31, 0x2e, 0x4d, 0x69, 0x74, 0x72, 0x65, 0x52, 0x05, 0x6d,
	0x69, 0x74, 0x72, 0x65, 0x12, 0x34, 0x0a, 0x08, 0x73, 0x65, 0x76, 0x65, 0x72, 0x69, 0x74, 0x79,
	0x18, 0x03, 0x20, 0x01, 0x28, 0x0e, 0x32, 0x18, 0x2e, 0x74, 0x72, 0x61, 0x63, 0x65, 0x65, 0x2e,
	0x76, 0x31, 0x62, 0x65, 0x74, 0x61, 0x31, 0x2e, 0x53, 0x65, 0x76, 0x65, 0x72, 0x69, 0x74, 0x79,
	0x52, 0x08, 0x73, 0x65, 0x76, 0x65, 0x72, 0x69, 0x74, 0x79, 0x12, 0x12, 0x0a, 0x04, 0x6e, 0x61,
	0x6d, 0x65, 0x18, 0x04, 0x20, 0x01, 0x28, 0x09, 0x52, 0x04, 0x6e, 0x61, 0x6d, 0x65, 0x12, 0x46,
	0x0a, 0x0a, 0x70, 0x72, 0x6f, 0x70, 0x65, 0x72, 0x74, 0x69, 0x65, 0x73, 0x18, 0x05, 0x20, 0x03,
	0x28, 0x0b, 0x32, 0x26, 0x2e, 0x74, 0x72, 0x61, 0x63, 0x65, 0x65, 0x2e, 0x76, 0x31, 0x62, 0x65,
	0x74, 0x61, 0x31, 0x2e, 0x54, 0x68, 0x72, 0x65, 0x61, 0x74, 0x2e, 0x50, 0x72, 0x6f, 0x70, 0x65,
	0x72, 0x74, 0x69, 0x65, 0x73, 0x45, 0x6e, 0x74, 0x72, 0x79, 0x52, 0x0a, 0x70, 0x72, 0x6f, 0x70,
	0x65, 0x72, 0x74, 0x69, 0x65, 0x73, 0x1a, 0x3d, 0x0a, 0x0f, 0x50, 0x72, 0x6f, 0x70, 0x65, 0x72,
	0x74, 0x69, 0x65, 0x73, 0x45, 0x6e, 0x74, 0x72, 0x79, 0x12, 0x10, 0x0a, 0x03, 0x6b, 0x65, 0x79,
	0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x03, 0x6b, 0x65, 0x79, 0x12, 0x14, 0x0a, 0x05, 0x76,
	0x61, 0x6c, 0x75, 0x65, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x05, 0x76, 0x61, 0x6c, 0x75,
	0x65, 0x3a, 0x02, 0x38, 0x01, 0x22, 0x7a, 0x0a, 0x05, 0x4d, 0x69, 0x74, 0x72, 0x65, 0x12, 0x33,
	0x0a, 0x06, 0x74, 0x61, 0x63, 0x74, 0x69, 0x63, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x1b,
	0x2e, 0x74, 0x72, 0x61, 0x63, 0x65, 0x65, 0x2e, 0x76, 0x31, 0x62, 0x65, 0x74, 0x61, 0x31, 0x2e,
	0x4d, 0x69, 0x74, 0x72, 0x65, 0x54, 0x61, 0x63, 0x74, 0x69, 0x63, 0x52, 0x06, 0x74, 0x61, 0x63,
	0x74, 0x69, 0x63, 0x12, 0x3c, 0x0a, 0x09, 0x74, 0x65, 0x63, 0x68, 0x6e, 0x69, 0x71, 0x75, 0x65,
	0x18, 0x02, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x1e, 0x2e, 0x74, 0x72, 0x61, 0x63, 0x65, 0x65, 0x2e,
	0x76, 0x31, 0x62, 0x65, 0x74, 0x61, 0x31, 0x2e, 0x4d, 0x69, 0x74, 0x72, 0x65, 0x54, 0x65, 0x63,
	0x68, 0x6e, 0x69, 0x71, 0x75, 0x65, 0x52, 0x09, 0x74, 0x65, 0x63, 0x68, 0x6e, 0x69, 0x71, 0x75,
	0x65, 0x22, 0x21, 0x0a, 0x0b, 0x4d, 0x69, 0x74, 0x72, 0x65, 0x54, 0x61, 0x63, 0x74, 0x69, 0x63,
	0x12, 0x12, 0x0a, 0x04, 0x6e, 0x61, 0x6d, 0x65, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x04,
	0x6e, 0x61, 0x6d, 0x65, 0x22, 0x34, 0x0a, 0x0e, 0x4d, 0x69, 0x74, 0x72, 0x65, 0x54, 0x65, 0x63,
	0x68, 0x6e, 0x69, 0x71, 0x75, 0x65, 0x12, 0x0e, 0x0a, 0x02, 0x69, 0x64, 0x18, 0x01, 0x20, 0x01,
	0x28, 0x09, 0x52, 0x02, 0x69, 0x64, 0x12, 0x12, 0x0a, 0x04, 0x6e, 0x61, 0x6d, 0x65, 0x18, 0x02,
	0x20, 0x01, 0x28, 0x09, 0x52, 0x04, 0x6e, 0x61, 0x6d, 0x65, 0x2a, 0x41, 0x0a, 0x08, 0x53, 0x65,
	0x76, 0x65, 0x72, 0x69, 0x74, 0x79, 0x12, 0x08, 0x0a, 0x04, 0x49, 0x4e, 0x46, 0x4f, 0x10, 0x00,
	0x12, 0x07, 0x0a, 0x03, 0x4c, 0x4f, 0x57, 0x10, 0x01, 0x12, 0x0a, 0x0a, 0x06, 0x4d, 0x45, 0x44,
	0x49, 0x55, 0x4d, 0x10, 0x02, 0x12, 0x08, 0x0a, 0x04, 0x48, 0x49, 0x47, 0x48, 0x10, 0x03, 0x12,
	0x0c, 0x0a, 0x08, 0x43, 0x52, 0x49, 0x54, 0x49, 0x43, 0x41, 0x4c, 0x10, 0x04, 0x42, 0x2b, 0x5a,
	0x29, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x2f, 0x61, 0x71, 0x75, 0x61, 0x73,
	0x65, 0x63, 0x75, 0x72, 0x69, 0x74, 0x79, 0x2f, 0x74, 0x72, 0x61, 0x63, 0x65, 0x65, 0x2f, 0x61,
	0x70, 0x69, 0x2f, 0x76, 0x31, 0x62, 0x65, 0x74, 0x61, 0x31, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74,
	0x6f, 0x33,
}

var (
	file_api_v1beta1_threat_proto_rawDescOnce sync.Once
	file_api_v1beta1_threat_proto_rawDescData = file_api_v1beta1_threat_proto_rawDesc
)

func file_api_v1beta1_threat_proto_rawDescGZIP() []byte {
	file_api_v1beta1_threat_proto_rawDescOnce.Do(func() {
		file_api_v1beta1_threat_proto_rawDescData = protoimpl.X.CompressGZIP(file_api_v1beta1_threat_proto_rawDescData)
	})
	return file_api_v1beta1_threat_proto_rawDescData
}

var file_api_v1beta1_threat_proto_enumTypes = make([]protoimpl.EnumInfo, 1)
var file_api_v1beta1_threat_proto_msgTypes = make([]protoimpl.MessageInfo, 5)
var file_api_v1beta1_threat_proto_goTypes = []any{
	(Severity)(0),          // 0: tracee.v1beta1.Severity
	(*Threat)(nil),         // 1: tracee.v1beta1.Threat
	(*Mitre)(nil),          // 2: tracee.v1beta1.Mitre
	(*MitreTactic)(nil),    // 3: tracee.v1beta1.MitreTactic
	(*MitreTechnique)(nil), // 4: tracee.v1beta1.MitreTechnique
	nil,                    // 5: tracee.v1beta1.Threat.PropertiesEntry
}
var file_api_v1beta1_threat_proto_depIdxs = []int32{
	2, // 0: tracee.v1beta1.Threat.mitre:type_name -> tracee.v1beta1.Mitre
	0, // 1: tracee.v1beta1.Threat.severity:type_name -> tracee.v1beta1.Severity
	5, // 2: tracee.v1beta1.Threat.properties:type_name -> tracee.v1beta1.Threat.PropertiesEntry
	3, // 3: tracee.v1beta1.Mitre.tactic:type_name -> tracee.v1beta1.MitreTactic
	4, // 4: tracee.v1beta1.Mitre.technique:type_name -> tracee.v1beta1.MitreTechnique
	5, // [5:5] is the sub-list for method output_type
	5, // [5:5] is the sub-list for method input_type
	5, // [5:5] is the sub-list for extension type_name
	5, // [5:5] is the sub-list for extension extendee
	0, // [0:5] is the sub-list for field type_name
}

func init() { file_api_v1beta1_threat_proto_init() }
func file_api_v1beta1_threat_proto_init() {
	if File_api_v1beta1_threat_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_api_v1beta1_threat_proto_msgTypes[0].Exporter = func(v any, i int) any {
			switch v := v.(*Threat); i {
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
		file_api_v1beta1_threat_proto_msgTypes[1].Exporter = func(v any, i int) any {
			switch v := v.(*Mitre); i {
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
		file_api_v1beta1_threat_proto_msgTypes[2].Exporter = func(v any, i int) any {
			switch v := v.(*MitreTactic); i {
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
		file_api_v1beta1_threat_proto_msgTypes[3].Exporter = func(v any, i int) any {
			switch v := v.(*MitreTechnique); i {
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
			RawDescriptor: file_api_v1beta1_threat_proto_rawDesc,
			NumEnums:      1,
			NumMessages:   5,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_api_v1beta1_threat_proto_goTypes,
		DependencyIndexes: file_api_v1beta1_threat_proto_depIdxs,
		EnumInfos:         file_api_v1beta1_threat_proto_enumTypes,
		MessageInfos:      file_api_v1beta1_threat_proto_msgTypes,
	}.Build()
	File_api_v1beta1_threat_proto = out.File
	file_api_v1beta1_threat_proto_rawDesc = nil
	file_api_v1beta1_threat_proto_goTypes = nil
	file_api_v1beta1_threat_proto_depIdxs = nil
}
