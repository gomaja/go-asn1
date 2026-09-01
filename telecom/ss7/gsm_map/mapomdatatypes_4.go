// Code generated from ASN.1 module "MAP-OM-DataTypes". DO NOT EDIT.

package gsm_map

import (
	"fmt"

	"github.com/gomaja/go-asn1/runtime"
	"github.com/gomaja/go-asn1/runtime/ber"
	"github.com/gomaja/go-asn1/runtime/tag"
)

// Ensure imports are used.
var (
	_ runtime.BitString
	_ = ber.EncodeTLV
	_ = tag.ClassUniversal
)

// ActivateTraceModeArg4 represents the ASN.1 type ActivateTraceModeArg4 (SEQUENCE).
type ActivateTraceModeArg4 struct {
	Imsi                  *IMSI4               `asn1:"tag:0,context,implicit,optional" json:"Imsi,omitempty"`
	TraceReference        TraceReference4      `asn1:"tag:1,context,implicit"`
	TraceType             TraceType4           `asn1:"tag:2,context,implicit"`
	OmcId                 *AddressString4      `asn1:"tag:3,context,implicit,optional" json:"OmcId,omitempty"`
	ExtensionContainer    *ExtensionContainer4 `asn1:"tag:4,context,implicit,optional" json:"ExtensionContainer,omitempty"`
	TraceReference2       *TraceReference24    `asn1:"tag:5,context,implicit,optional" json:"TraceReference2,omitempty"`
	TraceDepthList        *TraceDepthList4     `asn1:"tag:6,context,implicit,optional" json:"TraceDepthList,omitempty"`
	TraceNETypeList       *TraceNETypeList4    `asn1:"tag:7,context,implicit,optional" json:"TraceNETypeList,omitempty"`
	TraceInterfaceList    *TraceInterfaceList4 `asn1:"tag:8,context,implicit,optional" json:"TraceInterfaceList,omitempty"`
	TraceEventList        *TraceEventList4     `asn1:"tag:9,context,implicit,optional" json:"TraceEventList,omitempty"`
	TraceCollectionEntity *GSNAddress4         `asn1:"tag:10,context,implicit,optional" json:"TraceCollectionEntity,omitempty"`
	MdtConfiguration      *MDTConfiguration3   `asn1:"tag:11,context,implicit,optional" json:"MdtConfiguration,omitempty"`
	ExtCount_             int64                `asn1:"-" json:"-"`
	ExtPresent_           []bool               `asn1:"-" json:"-"`
	ExtData_              [][]byte             `asn1:"-" json:"-"`
}

// MDTConfiguration3 represents the ASN.1 type MDTConfiguration3 (SEQUENCE).
type MDTConfiguration3 struct {
	JobType            JobType3             `asn1:""`
	AreaScope          *AreaScope3          `asn1:",optional" json:"AreaScope,omitempty"`
	ListOfMeasurements *ListOfMeasurements3 `asn1:",optional" json:"ListOfMeasurements,omitempty"`
	ReportingTrigger   *ReportingTrigger3   `asn1:"tag:0,context,implicit,optional" json:"ReportingTrigger,omitempty"`
	ReportInterval     *ReportInterval3     `asn1:",optional" json:"ReportInterval,omitempty"`
	ReportAmount       *ReportAmount3       `asn1:"tag:1,context,implicit,optional" json:"ReportAmount,omitempty"`
	EventThresholdRSRP *EventThresholdRSRP3 `asn1:",optional" json:"EventThresholdRSRP,omitempty"`
	EventThresholdRSRQ *EventThresholdRSRQ3 `asn1:"tag:2,context,implicit,optional" json:"EventThresholdRSRQ,omitempty"`
	LoggingInterval    *LoggingInterval3    `asn1:"tag:3,context,implicit,optional" json:"LoggingInterval,omitempty"`
	LoggingDuration    *LoggingDuration3    `asn1:"tag:4,context,implicit,optional" json:"LoggingDuration,omitempty"`
	ExtensionContainer *ExtensionContainer4 `asn1:"tag:5,context,implicit,optional" json:"ExtensionContainer,omitempty"`
	ExtCount_          int64                `asn1:"-" json:"-"`
	ExtPresent_        []bool               `asn1:"-" json:"-"`
	ExtData_           [][]byte             `asn1:"-" json:"-"`
}

// JobType3 represents the ASN.1 ENUMERATED type JobType3.
type JobType3 int64

const (
	JobType3ImmediateMDTOnly     JobType3 = 0
	JobType3LoggedMDTOnly        JobType3 = 1
	JobType3TraceOnly            JobType3 = 2
	JobType3ImmediateMDTAndTrace JobType3 = 3
)

func (v JobType3) String() string {
	switch v {
	case JobType3ImmediateMDTOnly:
		return "immediate-MDT-only"
	case JobType3LoggedMDTOnly:
		return "logged-MDT-only"
	case JobType3TraceOnly:
		return "trace-only"
	case JobType3ImmediateMDTAndTrace:
		return "immediate-MDT-and-trace"
	default:
		return "unknown"
	}
}

// AreaScope3 represents the ASN.1 type AreaScope3 (SEQUENCE).
type AreaScope3 struct {
	CgiList                  CGIList3             `asn1:"tag:0,context,implicit,optional" json:"CgiList,omitempty"`
	CgiListIndef_            bool                 `asn1:"-" json:"-"`
	EUtranCgiList            EUTRANCGIList3       `asn1:"tag:1,context,implicit,optional" json:"EUtranCgiList,omitempty"`
	EUtranCgiListIndef_      bool                 `asn1:"-" json:"-"`
	RoutingAreaIdList        RoutingAreaIdList3   `asn1:"tag:2,context,implicit,optional" json:"RoutingAreaIdList,omitempty"`
	RoutingAreaIdListIndef_  bool                 `asn1:"-" json:"-"`
	LocationAreaIdList       LocationAreaIdList3  `asn1:"tag:3,context,implicit,optional" json:"LocationAreaIdList,omitempty"`
	LocationAreaIdListIndef_ bool                 `asn1:"-" json:"-"`
	TrackingAreaIdList       TrackingAreaIdList3  `asn1:"tag:4,context,implicit,optional" json:"TrackingAreaIdList,omitempty"`
	TrackingAreaIdListIndef_ bool                 `asn1:"-" json:"-"`
	ExtensionContainer       *ExtensionContainer4 `asn1:"tag:5,context,implicit,optional" json:"ExtensionContainer,omitempty"`
	ExtCount_                int64                `asn1:"-" json:"-"`
	ExtPresent_              []bool               `asn1:"-" json:"-"`
	ExtData_                 [][]byte             `asn1:"-" json:"-"`
}

// CGIList3 represents the ASN.1 type CGIList3 (SEQUENCE_OF).
type CGIList3 = []GlobalCellId4

// EUTRANCGIList3 represents the ASN.1 type EUTRANCGIList3 (SEQUENCE_OF).
type EUTRANCGIList3 = []EUTRANCGI3

// RoutingAreaIdList3 represents the ASN.1 type RoutingAreaIdList3 (SEQUENCE_OF).
type RoutingAreaIdList3 = []RAIdentity4

// LocationAreaIdList3 represents the ASN.1 type LocationAreaIdList3 (SEQUENCE_OF).
type LocationAreaIdList3 = []LAIFixedLength4

// TrackingAreaIdList3 represents the ASN.1 type TrackingAreaIdList3 (SEQUENCE_OF).
type TrackingAreaIdList3 = []TAId3

// ListOfMeasurements3 represents the ASN.1 type ListOfMeasurements3 (OCTET_STRING).
type ListOfMeasurements3 = []byte

// ReportingTrigger3 represents the ASN.1 type ReportingTrigger3 (OCTET_STRING).
type ReportingTrigger3 = []byte

// ReportInterval3 represents the ASN.1 ENUMERATED type ReportInterval3.
type ReportInterval3 int64

const (
	ReportInterval3Umts250ms   ReportInterval3 = 0
	ReportInterval3Umts500ms   ReportInterval3 = 1
	ReportInterval3Umts1000ms  ReportInterval3 = 2
	ReportInterval3Umts2000ms  ReportInterval3 = 3
	ReportInterval3Umts3000ms  ReportInterval3 = 4
	ReportInterval3Umts4000ms  ReportInterval3 = 5
	ReportInterval3Umts6000ms  ReportInterval3 = 6
	ReportInterval3Umts8000ms  ReportInterval3 = 7
	ReportInterval3Umts12000ms ReportInterval3 = 8
	ReportInterval3Umts16000ms ReportInterval3 = 9
	ReportInterval3Umts20000ms ReportInterval3 = 10
	ReportInterval3Umts24000ms ReportInterval3 = 11
	ReportInterval3Umts28000ms ReportInterval3 = 12
	ReportInterval3Umts32000ms ReportInterval3 = 13
	ReportInterval3Umts64000ms ReportInterval3 = 14
	ReportInterval3Lte120ms    ReportInterval3 = 15
	ReportInterval3Lte240ms    ReportInterval3 = 16
	ReportInterval3Lte480ms    ReportInterval3 = 17
	ReportInterval3Lte640ms    ReportInterval3 = 18
	ReportInterval3Lte1024ms   ReportInterval3 = 19
	ReportInterval3Lte2048ms   ReportInterval3 = 20
	ReportInterval3Lte5120ms   ReportInterval3 = 21
	ReportInterval3Lte10240ms  ReportInterval3 = 22
	ReportInterval3Lte1min     ReportInterval3 = 23
	ReportInterval3Lte6min     ReportInterval3 = 24
	ReportInterval3Lte12min    ReportInterval3 = 25
	ReportInterval3Lte30min    ReportInterval3 = 26
	ReportInterval3Lte60min    ReportInterval3 = 27
)

func (v ReportInterval3) String() string {
	switch v {
	case ReportInterval3Umts250ms:
		return "umts250ms"
	case ReportInterval3Umts500ms:
		return "umts500ms"
	case ReportInterval3Umts1000ms:
		return "umts1000ms"
	case ReportInterval3Umts2000ms:
		return "umts2000ms"
	case ReportInterval3Umts3000ms:
		return "umts3000ms"
	case ReportInterval3Umts4000ms:
		return "umts4000ms"
	case ReportInterval3Umts6000ms:
		return "umts6000ms"
	case ReportInterval3Umts8000ms:
		return "umts8000ms"
	case ReportInterval3Umts12000ms:
		return "umts12000ms"
	case ReportInterval3Umts16000ms:
		return "umts16000ms"
	case ReportInterval3Umts20000ms:
		return "umts20000ms"
	case ReportInterval3Umts24000ms:
		return "umts24000ms"
	case ReportInterval3Umts28000ms:
		return "umts28000ms"
	case ReportInterval3Umts32000ms:
		return "umts32000ms"
	case ReportInterval3Umts64000ms:
		return "umts64000ms"
	case ReportInterval3Lte120ms:
		return "lte120ms"
	case ReportInterval3Lte240ms:
		return "lte240ms"
	case ReportInterval3Lte480ms:
		return "lte480ms"
	case ReportInterval3Lte640ms:
		return "lte640ms"
	case ReportInterval3Lte1024ms:
		return "lte1024ms"
	case ReportInterval3Lte2048ms:
		return "lte2048ms"
	case ReportInterval3Lte5120ms:
		return "lte5120ms"
	case ReportInterval3Lte10240ms:
		return "lte10240ms"
	case ReportInterval3Lte1min:
		return "lte1min"
	case ReportInterval3Lte6min:
		return "lte6min"
	case ReportInterval3Lte12min:
		return "lte12min"
	case ReportInterval3Lte30min:
		return "lte30min"
	case ReportInterval3Lte60min:
		return "lte60min"
	default:
		return "unknown"
	}
}

// ReportAmount3 represents the ASN.1 ENUMERATED type ReportAmount3.
type ReportAmount3 int64

const (
	ReportAmount3D1       ReportAmount3 = 0
	ReportAmount3D2       ReportAmount3 = 1
	ReportAmount3D4       ReportAmount3 = 2
	ReportAmount3D8       ReportAmount3 = 3
	ReportAmount3D16      ReportAmount3 = 4
	ReportAmount3D32      ReportAmount3 = 5
	ReportAmount3D64      ReportAmount3 = 6
	ReportAmount3Infinity ReportAmount3 = 7
)

func (v ReportAmount3) String() string {
	switch v {
	case ReportAmount3D1:
		return "d1"
	case ReportAmount3D2:
		return "d2"
	case ReportAmount3D4:
		return "d4"
	case ReportAmount3D8:
		return "d8"
	case ReportAmount3D16:
		return "d16"
	case ReportAmount3D32:
		return "d32"
	case ReportAmount3D64:
		return "d64"
	case ReportAmount3Infinity:
		return "infinity"
	default:
		return "unknown"
	}
}

// EventThresholdRSRP3 represents the ASN.1 type EventThresholdRSRP3 (INTEGER).
type EventThresholdRSRP3 = int64

// EventThresholdRSRQ3 represents the ASN.1 type EventThresholdRSRQ3 (INTEGER).
type EventThresholdRSRQ3 = int64

// LoggingInterval3 represents the ASN.1 ENUMERATED type LoggingInterval3.
type LoggingInterval3 int64

const (
	LoggingInterval3D1dot28  LoggingInterval3 = 0
	LoggingInterval3D2dot56  LoggingInterval3 = 1
	LoggingInterval3D5dot12  LoggingInterval3 = 2
	LoggingInterval3D10dot24 LoggingInterval3 = 3
	LoggingInterval3D20dot48 LoggingInterval3 = 4
	LoggingInterval3D30dot72 LoggingInterval3 = 5
	LoggingInterval3D40dot96 LoggingInterval3 = 6
	LoggingInterval3D61dot44 LoggingInterval3 = 7
)

func (v LoggingInterval3) String() string {
	switch v {
	case LoggingInterval3D1dot28:
		return "d1dot28"
	case LoggingInterval3D2dot56:
		return "d2dot56"
	case LoggingInterval3D5dot12:
		return "d5dot12"
	case LoggingInterval3D10dot24:
		return "d10dot24"
	case LoggingInterval3D20dot48:
		return "d20dot48"
	case LoggingInterval3D30dot72:
		return "d30dot72"
	case LoggingInterval3D40dot96:
		return "d40dot96"
	case LoggingInterval3D61dot44:
		return "d61dot44"
	default:
		return "unknown"
	}
}

// LoggingDuration3 represents the ASN.1 ENUMERATED type LoggingDuration3.
type LoggingDuration3 int64

const (
	LoggingDuration3D600sec  LoggingDuration3 = 0
	LoggingDuration3D1200sec LoggingDuration3 = 1
	LoggingDuration3D2400sec LoggingDuration3 = 2
	LoggingDuration3D3600sec LoggingDuration3 = 3
	LoggingDuration3D5400sec LoggingDuration3 = 4
	LoggingDuration3D7200sec LoggingDuration3 = 5
)

func (v LoggingDuration3) String() string {
	switch v {
	case LoggingDuration3D600sec:
		return "d600sec"
	case LoggingDuration3D1200sec:
		return "d1200sec"
	case LoggingDuration3D2400sec:
		return "d2400sec"
	case LoggingDuration3D3600sec:
		return "d3600sec"
	case LoggingDuration3D5400sec:
		return "d5400sec"
	case LoggingDuration3D7200sec:
		return "d7200sec"
	default:
		return "unknown"
	}
}

// TraceReference4 represents the ASN.1 type TraceReference4 (OCTET_STRING).
type TraceReference4 = []byte

// TraceReference24 represents the ASN.1 type TraceReference24 (OCTET_STRING).
type TraceReference24 = []byte

// TraceRecordingSessionReference4 represents the ASN.1 type TraceRecordingSessionReference4 (OCTET_STRING).
type TraceRecordingSessionReference4 = []byte

// TraceType4 represents the ASN.1 type TraceType4 (INTEGER).
type TraceType4 = int64

// TraceDepthList4 represents the ASN.1 type TraceDepthList4 (SEQUENCE).
type TraceDepthList4 struct {
	MscSTraceDepth *TraceDepth4 `asn1:"tag:0,context,implicit,optional" json:"MscSTraceDepth,omitempty"`
	MgwTraceDepth  *TraceDepth4 `asn1:"tag:1,context,implicit,optional" json:"MgwTraceDepth,omitempty"`
	SgsnTraceDepth *TraceDepth4 `asn1:"tag:2,context,implicit,optional" json:"SgsnTraceDepth,omitempty"`
	GgsnTraceDepth *TraceDepth4 `asn1:"tag:3,context,implicit,optional" json:"GgsnTraceDepth,omitempty"`
	RncTraceDepth  *TraceDepth4 `asn1:"tag:4,context,implicit,optional" json:"RncTraceDepth,omitempty"`
	BmscTraceDepth *TraceDepth4 `asn1:"tag:5,context,implicit,optional" json:"BmscTraceDepth,omitempty"`
	MmeTraceDepth  *TraceDepth4 `asn1:"tag:6,context,implicit,optional" json:"MmeTraceDepth,omitempty"`
	SgwTraceDepth  *TraceDepth4 `asn1:"tag:7,context,implicit,optional" json:"SgwTraceDepth,omitempty"`
	PgwTraceDepth  *TraceDepth4 `asn1:"tag:8,context,implicit,optional" json:"PgwTraceDepth,omitempty"`
	ENBTraceDepth  *TraceDepth4 `asn1:"tag:9,context,implicit,optional" json:"ENBTraceDepth,omitempty"`
	ExtCount_      int64        `asn1:"-" json:"-"`
	ExtPresent_    []bool       `asn1:"-" json:"-"`
	ExtData_       [][]byte     `asn1:"-" json:"-"`
}

// TraceDepth4 represents the ASN.1 ENUMERATED type TraceDepth4.
type TraceDepth4 int64

const (
	TraceDepth4Minimum TraceDepth4 = 0
	TraceDepth4Medium  TraceDepth4 = 1
	TraceDepth4Maximum TraceDepth4 = 2
)

func (v TraceDepth4) String() string {
	switch v {
	case TraceDepth4Minimum:
		return "minimum"
	case TraceDepth4Medium:
		return "medium"
	case TraceDepth4Maximum:
		return "maximum"
	default:
		return "unknown"
	}
}

// TraceNETypeList4 represents the ASN.1 type TraceNETypeList4 (BIT_STRING).
type TraceNETypeList4 = runtime.BitString

// TraceInterfaceList4 represents the ASN.1 type TraceInterfaceList4 (SEQUENCE).
type TraceInterfaceList4 struct {
	MscSList    *MSCSInterfaceList4 `asn1:"tag:0,context,implicit,optional" json:"MscSList,omitempty"`
	MgwList     *MGWInterfaceList4  `asn1:"tag:1,context,implicit,optional" json:"MgwList,omitempty"`
	SgsnList    *SGSNInterfaceList4 `asn1:"tag:2,context,implicit,optional" json:"SgsnList,omitempty"`
	GgsnList    *GGSNInterfaceList4 `asn1:"tag:3,context,implicit,optional" json:"GgsnList,omitempty"`
	RncList     *RNCInterfaceList4  `asn1:"tag:4,context,implicit,optional" json:"RncList,omitempty"`
	BmscList    *BMSCInterfaceList4 `asn1:"tag:5,context,implicit,optional" json:"BmscList,omitempty"`
	MmeList     *MMEInterfaceList3  `asn1:"tag:6,context,implicit,optional" json:"MmeList,omitempty"`
	SgwList     *SGWInterfaceList3  `asn1:"tag:7,context,implicit,optional" json:"SgwList,omitempty"`
	PgwList     *PGWInterfaceList3  `asn1:"tag:8,context,implicit,optional" json:"PgwList,omitempty"`
	ENBList     *ENBInterfaceList3  `asn1:"tag:9,context,implicit,optional" json:"ENBList,omitempty"`
	ExtCount_   int64               `asn1:"-" json:"-"`
	ExtPresent_ []bool              `asn1:"-" json:"-"`
	ExtData_    [][]byte            `asn1:"-" json:"-"`
}

// MSCSInterfaceList4 represents the ASN.1 type MSCSInterfaceList4 (BIT_STRING).
type MSCSInterfaceList4 = runtime.BitString

// MGWInterfaceList4 represents the ASN.1 type MGWInterfaceList4 (BIT_STRING).
type MGWInterfaceList4 = runtime.BitString

// SGSNInterfaceList4 represents the ASN.1 type SGSNInterfaceList4 (BIT_STRING).
type SGSNInterfaceList4 = runtime.BitString

// GGSNInterfaceList4 represents the ASN.1 type GGSNInterfaceList4 (BIT_STRING).
type GGSNInterfaceList4 = runtime.BitString

// RNCInterfaceList4 represents the ASN.1 type RNCInterfaceList4 (BIT_STRING).
type RNCInterfaceList4 = runtime.BitString

// BMSCInterfaceList4 represents the ASN.1 type BMSCInterfaceList4 (BIT_STRING).
type BMSCInterfaceList4 = runtime.BitString

// MMEInterfaceList3 represents the ASN.1 type MMEInterfaceList3 (BIT_STRING).
type MMEInterfaceList3 = runtime.BitString

// SGWInterfaceList3 represents the ASN.1 type SGWInterfaceList3 (BIT_STRING).
type SGWInterfaceList3 = runtime.BitString

// PGWInterfaceList3 represents the ASN.1 type PGWInterfaceList3 (BIT_STRING).
type PGWInterfaceList3 = runtime.BitString

// ENBInterfaceList3 represents the ASN.1 type ENBInterfaceList3 (BIT_STRING).
type ENBInterfaceList3 = runtime.BitString

// TraceEventList4 represents the ASN.1 type TraceEventList4 (SEQUENCE).
type TraceEventList4 struct {
	MscSList    *MSCSEventList4 `asn1:"tag:0,context,implicit,optional" json:"MscSList,omitempty"`
	MgwList     *MGWEventList4  `asn1:"tag:1,context,implicit,optional" json:"MgwList,omitempty"`
	SgsnList    *SGSNEventList4 `asn1:"tag:2,context,implicit,optional" json:"SgsnList,omitempty"`
	GgsnList    *GGSNEventList4 `asn1:"tag:3,context,implicit,optional" json:"GgsnList,omitempty"`
	BmscList    *BMSCEventList4 `asn1:"tag:4,context,implicit,optional" json:"BmscList,omitempty"`
	MmeList     *MMEEventList3  `asn1:"tag:5,context,implicit,optional" json:"MmeList,omitempty"`
	SgwList     *SGWEventList3  `asn1:"tag:6,context,implicit,optional" json:"SgwList,omitempty"`
	PgwList     *PGWEventList3  `asn1:"tag:7,context,implicit,optional" json:"PgwList,omitempty"`
	ExtCount_   int64           `asn1:"-" json:"-"`
	ExtPresent_ []bool          `asn1:"-" json:"-"`
	ExtData_    [][]byte        `asn1:"-" json:"-"`
}

// MSCSEventList4 represents the ASN.1 type MSCSEventList4 (BIT_STRING).
type MSCSEventList4 = runtime.BitString

// MGWEventList4 represents the ASN.1 type MGWEventList4 (BIT_STRING).
type MGWEventList4 = runtime.BitString

// SGSNEventList4 represents the ASN.1 type SGSNEventList4 (BIT_STRING).
type SGSNEventList4 = runtime.BitString

// GGSNEventList4 represents the ASN.1 type GGSNEventList4 (BIT_STRING).
type GGSNEventList4 = runtime.BitString

// BMSCEventList4 represents the ASN.1 type BMSCEventList4 (BIT_STRING).
type BMSCEventList4 = runtime.BitString

// MMEEventList3 represents the ASN.1 type MMEEventList3 (BIT_STRING).
type MMEEventList3 = runtime.BitString

// SGWEventList3 represents the ASN.1 type SGWEventList3 (BIT_STRING).
type SGWEventList3 = runtime.BitString

// PGWEventList3 represents the ASN.1 type PGWEventList3 (BIT_STRING).
type PGWEventList3 = runtime.BitString

// TracePropagationList4 represents the ASN.1 type TracePropagationList4 (SEQUENCE).
type TracePropagationList4 struct {
	TraceReference                 *TraceReference4                 `asn1:"tag:0,context,implicit,optional" json:"TraceReference,omitempty"`
	TraceType                      *TraceType4                      `asn1:"tag:1,context,implicit,optional" json:"TraceType,omitempty"`
	TraceReference2                *TraceReference24                `asn1:"tag:2,context,implicit,optional" json:"TraceReference2,omitempty"`
	TraceRecordingSessionReference *TraceRecordingSessionReference4 `asn1:"tag:3,context,implicit,optional" json:"TraceRecordingSessionReference,omitempty"`
	RncTraceDepth                  *TraceDepth4                     `asn1:"tag:4,context,implicit,optional" json:"RncTraceDepth,omitempty"`
	RncInterfaceList               *RNCInterfaceList4               `asn1:"tag:5,context,implicit,optional" json:"RncInterfaceList,omitempty"`
	MscSTraceDepth                 *TraceDepth4                     `asn1:"tag:6,context,implicit,optional" json:"MscSTraceDepth,omitempty"`
	MscSInterfaceList              *MSCSInterfaceList4              `asn1:"tag:7,context,implicit,optional" json:"MscSInterfaceList,omitempty"`
	MscSEventList                  *MSCSEventList4                  `asn1:"tag:8,context,implicit,optional" json:"MscSEventList,omitempty"`
	MgwTraceDepth                  *TraceDepth4                     `asn1:"tag:9,context,implicit,optional" json:"MgwTraceDepth,omitempty"`
	MgwInterfaceList               *MGWInterfaceList4               `asn1:"tag:10,context,implicit,optional" json:"MgwInterfaceList,omitempty"`
	MgwEventList                   *MGWEventList4                   `asn1:"tag:11,context,implicit,optional" json:"MgwEventList,omitempty"`
	ExtCount_                      int64                            `asn1:"-" json:"-"`
	ExtPresent_                    []bool                           `asn1:"-" json:"-"`
	ExtData_                       [][]byte                         `asn1:"-" json:"-"`
}

// ActivateTraceModeRes4 represents the ASN.1 type ActivateTraceModeRes4 (SEQUENCE).
type ActivateTraceModeRes4 struct {
	ExtensionContainer    *ExtensionContainer4 `asn1:"tag:0,context,implicit,optional" json:"ExtensionContainer,omitempty"`
	TraceSupportIndicator *struct{}            `asn1:"tag:1,context,implicit,optional" json:"TraceSupportIndicator,omitempty"`
	ExtCount_             int64                `asn1:"-" json:"-"`
	ExtPresent_           []bool               `asn1:"-" json:"-"`
	ExtData_              [][]byte             `asn1:"-" json:"-"`
}

// DeactivateTraceModeArg4 represents the ASN.1 type DeactivateTraceModeArg4 (SEQUENCE).
type DeactivateTraceModeArg4 struct {
	Imsi               *IMSI4               `asn1:"tag:0,context,implicit,optional" json:"Imsi,omitempty"`
	TraceReference     TraceReference4      `asn1:"tag:1,context,implicit"`
	ExtensionContainer *ExtensionContainer4 `asn1:"tag:2,context,implicit,optional" json:"ExtensionContainer,omitempty"`
	TraceReference2    *TraceReference24    `asn1:"tag:3,context,implicit,optional" json:"TraceReference2,omitempty"`
	ExtCount_          int64                `asn1:"-" json:"-"`
	ExtPresent_        []bool               `asn1:"-" json:"-"`
	ExtData_           [][]byte             `asn1:"-" json:"-"`
}

// DeactivateTraceModeRes4 represents the ASN.1 type DeactivateTraceModeRes4 (SEQUENCE).
type DeactivateTraceModeRes4 struct {
	ExtensionContainer *ExtensionContainer4 `asn1:"tag:0,context,implicit,optional" json:"ExtensionContainer,omitempty"`
	ExtCount_          int64                `asn1:"-" json:"-"`
	ExtPresent_        []bool               `asn1:"-" json:"-"`
	ExtData_           [][]byte             `asn1:"-" json:"-"`
}

// MarshalBER encodes ActivateTraceModeArg4 to BER format.
func (v *ActivateTraceModeArg4) MarshalBER() ([]byte, error) {
	var children []byte
	if v.Imsi != nil {
		enc_imsi := ber.EncodeOctetString([]byte(*v.Imsi))
		enc_imsi = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, false, enc_imsi)
		children = append(children, enc_imsi...)
	}
	enc_tracereference := ber.EncodeOctetString([]byte(v.TraceReference))
	enc_tracereference = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, false, enc_tracereference)
	children = append(children, enc_tracereference...)
	enc_tracetype := ber.EncodeInteger(int64(v.TraceType))
	enc_tracetype = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, false, enc_tracetype)
	children = append(children, enc_tracetype...)
	if v.OmcId != nil {
		enc_omcid := ber.EncodeOctetString([]byte(*v.OmcId))
		enc_omcid = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, false, enc_omcid)
		children = append(children, enc_omcid...)
	}
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding extensionContainer: %w", err)
		}
		enc_extensioncontainer = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, true, enc_extensioncontainer)
		children = append(children, enc_extensioncontainer...)
	}
	if v.TraceReference2 != nil {
		enc_tracereference2 := ber.EncodeOctetString([]byte(*v.TraceReference2))
		enc_tracereference2 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 5, false, enc_tracereference2)
		children = append(children, enc_tracereference2...)
	}
	if v.TraceDepthList != nil {
		enc_tracedepthlist, err := v.TraceDepthList.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding traceDepthList: %w", err)
		}
		enc_tracedepthlist = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 6, true, enc_tracedepthlist)
		children = append(children, enc_tracedepthlist...)
	}
	if v.TraceNETypeList != nil {
		enc_tracenetypelist := ber.EncodeBitString(v.TraceNETypeList.Bytes, (8-(v.TraceNETypeList.BitLength%8))%8)
		enc_tracenetypelist = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 7, false, enc_tracenetypelist)
		children = append(children, enc_tracenetypelist...)
	}
	if v.TraceInterfaceList != nil {
		enc_traceinterfacelist, err := v.TraceInterfaceList.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding traceInterfaceList: %w", err)
		}
		enc_traceinterfacelist = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 8, true, enc_traceinterfacelist)
		children = append(children, enc_traceinterfacelist...)
	}
	if v.TraceEventList != nil {
		enc_traceeventlist, err := v.TraceEventList.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding traceEventList: %w", err)
		}
		enc_traceeventlist = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 9, true, enc_traceeventlist)
		children = append(children, enc_traceeventlist...)
	}
	if v.TraceCollectionEntity != nil {
		enc_tracecollectionentity := ber.EncodeOctetString([]byte(*v.TraceCollectionEntity))
		enc_tracecollectionentity = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 10, false, enc_tracecollectionentity)
		children = append(children, enc_tracecollectionentity...)
	}
	if v.MdtConfiguration != nil {
		enc_mdtconfiguration, err := v.MdtConfiguration.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding mdt-Configuration: %w", err)
		}
		enc_mdtconfiguration = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 11, true, enc_mdtconfiguration)
		children = append(children, enc_mdtconfiguration...)
	}
	for i, ext := range v.ExtData_ {
		_, n, _, extErr := ber.DecodeTLV(ext)
		if extErr != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, extErr)
		}
		if n != len(ext) {
			return nil, fmt.Errorf("encoding extension %d: %w", i, ber.ErrExtraData)
		}
		children = append(children, ext...)
	}
	return ber.EncodeSequence(children), nil
}

// MarshalDER encodes ActivateTraceModeArg4 to DER format.
func (v *ActivateTraceModeArg4) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes ActivateTraceModeArg4 from BER/DER format.
func (v *ActivateTraceModeArg4) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding ActivateTraceModeArg4 SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "ActivateTraceModeArg4", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode imsi
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
				_, n_imsi, rawVal_imsi, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding imsi: %w", err)
				}
				tmp_imsi := IMSI4(rawVal_imsi)
				v.Imsi = &tmp_imsi
				offset += n_imsi
			}
		}
	}
	// Decode traceReference
	if offset >= len(content) {
		return fmt.Errorf("missing required field traceReference")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 1 {
			return fmt.Errorf("expected tag [%s %d] for traceReference, got %s", "CONTEXT", 1, reqTag_)
		}
	}
	_, n_tracereference, rawVal_tracereference, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding traceReference: %w", err)
	}
	v.TraceReference = TraceReference4(rawVal_tracereference)
	offset += n_tracereference
	// Decode traceType
	if offset >= len(content) {
		return fmt.Errorf("missing required field traceType")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 2 {
			return fmt.Errorf("expected tag [%s %d] for traceType, got %s", "CONTEXT", 2, reqTag_)
		}
	}
	_, n_tracetype, rawVal_tracetype, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding traceType: %w", err)
	}
	decVal_tracetype, intErr := ber.DecodeIntegerValue(rawVal_tracetype)
	if intErr != nil {
		return fmt.Errorf("decoding traceType: %w", intErr)
	}
	v.TraceType = TraceType4(decVal_tracetype)
	offset += n_tracetype
	// Decode omc-Id
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3 {
				_, n_omcid, rawVal_omcid, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding omc-Id: %w", err)
				}
				tmp_omcid := AddressString4(rawVal_omcid)
				v.OmcId = &tmp_omcid
				offset += n_omcid
			}
		}
	}
	// Decode extensionContainer
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4 {
				_, n_extensioncontainer, rawVal_extensioncontainer, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding extensionContainer: %w", err)
				}
				reconstructed_extensioncontainer := ber.EncodeSequence(rawVal_extensioncontainer)
				var dec_extensioncontainer ExtensionContainer4
				if unmErr := dec_extensioncontainer.UnmarshalBER(reconstructed_extensioncontainer); unmErr != nil {
					return fmt.Errorf("decoding extensionContainer: %w", unmErr)
				}
				v.ExtensionContainer = &dec_extensioncontainer
				offset += n_extensioncontainer
			}
		}
	}
	// Decode traceReference2
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 5 {
				_, n_tracereference2, rawVal_tracereference2, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding traceReference2: %w", err)
				}
				tmp_tracereference2 := TraceReference24(rawVal_tracereference2)
				v.TraceReference2 = &tmp_tracereference2
				offset += n_tracereference2
			}
		}
	}
	// Decode traceDepthList
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 6 {
				_, n_tracedepthlist, rawVal_tracedepthlist, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding traceDepthList: %w", err)
				}
				reconstructed_tracedepthlist := ber.EncodeSequence(rawVal_tracedepthlist)
				var dec_tracedepthlist TraceDepthList4
				if unmErr := dec_tracedepthlist.UnmarshalBER(reconstructed_tracedepthlist); unmErr != nil {
					return fmt.Errorf("decoding traceDepthList: %w", unmErr)
				}
				v.TraceDepthList = &dec_tracedepthlist
				offset += n_tracedepthlist
			}
		}
	}
	// Decode traceNE-TypeList
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 7 {
				_, n_tracenetypelist, rawVal_tracenetypelist, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding traceNE-TypeList: %w", err)
				}
				bsBytes_tracenetypelist, bsUnused_tracenetypelist, bsErr := ber.DecodeBitStringValue(rawVal_tracenetypelist)
				if bsErr != nil {
					return fmt.Errorf("decoding traceNE-TypeList: %w", bsErr)
				}
				tmp_tracenetypelist := runtime.BitString{Bytes: bsBytes_tracenetypelist, BitLength: len(bsBytes_tracenetypelist)*8 - bsUnused_tracenetypelist}
				v.TraceNETypeList = &tmp_tracenetypelist
				offset += n_tracenetypelist
			}
		}
	}
	// Decode traceInterfaceList
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 8 {
				_, n_traceinterfacelist, rawVal_traceinterfacelist, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding traceInterfaceList: %w", err)
				}
				reconstructed_traceinterfacelist := ber.EncodeSequence(rawVal_traceinterfacelist)
				var dec_traceinterfacelist TraceInterfaceList4
				if unmErr := dec_traceinterfacelist.UnmarshalBER(reconstructed_traceinterfacelist); unmErr != nil {
					return fmt.Errorf("decoding traceInterfaceList: %w", unmErr)
				}
				v.TraceInterfaceList = &dec_traceinterfacelist
				offset += n_traceinterfacelist
			}
		}
	}
	// Decode traceEventList
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 9 {
				_, n_traceeventlist, rawVal_traceeventlist, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding traceEventList: %w", err)
				}
				reconstructed_traceeventlist := ber.EncodeSequence(rawVal_traceeventlist)
				var dec_traceeventlist TraceEventList4
				if unmErr := dec_traceeventlist.UnmarshalBER(reconstructed_traceeventlist); unmErr != nil {
					return fmt.Errorf("decoding traceEventList: %w", unmErr)
				}
				v.TraceEventList = &dec_traceeventlist
				offset += n_traceeventlist
			}
		}
	}
	// Decode traceCollectionEntity
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 10 {
				_, n_tracecollectionentity, rawVal_tracecollectionentity, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding traceCollectionEntity: %w", err)
				}
				tmp_tracecollectionentity := GSNAddress4(rawVal_tracecollectionentity)
				v.TraceCollectionEntity = &tmp_tracecollectionentity
				offset += n_tracecollectionentity
			}
		}
	}
	// Decode mdt-Configuration
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 11 {
				_, n_mdtconfiguration, rawVal_mdtconfiguration, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding mdt-Configuration: %w", err)
				}
				reconstructed_mdtconfiguration := ber.EncodeSequence(rawVal_mdtconfiguration)
				var dec_mdtconfiguration MDTConfiguration3
				if unmErr := dec_mdtconfiguration.UnmarshalBER(reconstructed_mdtconfiguration); unmErr != nil {
					return fmt.Errorf("decoding mdt-Configuration: %w", unmErr)
				}
				v.MdtConfiguration = &dec_mdtconfiguration
				offset += n_mdtconfiguration
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "ActivateTraceModeArg4", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes MDTConfiguration3 to BER format.
func (v *MDTConfiguration3) MarshalBER() ([]byte, error) {
	var children []byte
	enc_jobtype := ber.EncodeEnumerated(int64(v.JobType))
	children = append(children, enc_jobtype...)
	if v.AreaScope != nil {
		enc_areascope, err := v.AreaScope.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding areaScope: %w", err)
		}
		children = append(children, enc_areascope...)
	}
	if v.ListOfMeasurements != nil {
		enc_listofmeasurements := ber.EncodeOctetString([]byte(*v.ListOfMeasurements))
		children = append(children, enc_listofmeasurements...)
	}
	if v.ReportingTrigger != nil {
		enc_reportingtrigger := ber.EncodeOctetString([]byte(*v.ReportingTrigger))
		enc_reportingtrigger = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, false, enc_reportingtrigger)
		children = append(children, enc_reportingtrigger...)
	}
	if v.ReportInterval != nil {
		enc_reportinterval := ber.EncodeEnumerated(int64(*v.ReportInterval))
		children = append(children, enc_reportinterval...)
	}
	if v.ReportAmount != nil {
		enc_reportamount := ber.EncodeEnumerated(int64(*v.ReportAmount))
		enc_reportamount = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, false, enc_reportamount)
		children = append(children, enc_reportamount...)
	}
	if v.EventThresholdRSRP != nil {
		enc_eventthresholdrsrp := ber.EncodeInteger(int64(*v.EventThresholdRSRP))
		children = append(children, enc_eventthresholdrsrp...)
	}
	if v.EventThresholdRSRQ != nil {
		enc_eventthresholdrsrq := ber.EncodeInteger(int64(*v.EventThresholdRSRQ))
		enc_eventthresholdrsrq = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, false, enc_eventthresholdrsrq)
		children = append(children, enc_eventthresholdrsrq...)
	}
	if v.LoggingInterval != nil {
		enc_logginginterval := ber.EncodeEnumerated(int64(*v.LoggingInterval))
		enc_logginginterval = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, false, enc_logginginterval)
		children = append(children, enc_logginginterval...)
	}
	if v.LoggingDuration != nil {
		enc_loggingduration := ber.EncodeEnumerated(int64(*v.LoggingDuration))
		enc_loggingduration = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, false, enc_loggingduration)
		children = append(children, enc_loggingduration...)
	}
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding extensionContainer: %w", err)
		}
		enc_extensioncontainer = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 5, true, enc_extensioncontainer)
		children = append(children, enc_extensioncontainer...)
	}
	for i, ext := range v.ExtData_ {
		_, n, _, extErr := ber.DecodeTLV(ext)
		if extErr != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, extErr)
		}
		if n != len(ext) {
			return nil, fmt.Errorf("encoding extension %d: %w", i, ber.ErrExtraData)
		}
		children = append(children, ext...)
	}
	return ber.EncodeSequence(children), nil
}

// MarshalDER encodes MDTConfiguration3 to DER format.
func (v *MDTConfiguration3) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes MDTConfiguration3 from BER/DER format.
func (v *MDTConfiguration3) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding MDTConfiguration3 SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "MDTConfiguration3", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode jobType
	if offset >= len(content) {
		return fmt.Errorf("missing required field jobType")
	}
	val_jobtype, n, err := ber.DecodeInteger(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding jobType: %w", err)
	}
	v.JobType = JobType3(val_jobtype)
	offset += n
	// Decode areaScope
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassUniversal && peekTag.Number == 16 {
				// Decode nested SEQUENCE (AreaScope3)
				_, n_areascope, _, tlvErr_areascope := ber.DecodeTLV(content[offset:])
				if tlvErr_areascope != nil {
					return fmt.Errorf("decoding areaScope: %w", tlvErr_areascope)
				}
				var dec_areascope AreaScope3
				if unmErr := dec_areascope.UnmarshalBER(content[offset : offset+n_areascope]); unmErr != nil {
					return fmt.Errorf("decoding areaScope: %w", unmErr)
				}
				v.AreaScope = &dec_areascope
				offset += n_areascope
			}
		}
	}
	// Decode listOfMeasurements
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassUniversal && peekTag.Number == 4 {
				val_listofmeasurements, n, err := ber.DecodeOctetString(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding listOfMeasurements: %w", err)
				}
				tmp_listofmeasurements := ListOfMeasurements3(val_listofmeasurements)
				v.ListOfMeasurements = &tmp_listofmeasurements
				offset += n
			}
		}
	}
	// Decode reportingTrigger
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
				_, n_reportingtrigger, rawVal_reportingtrigger, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding reportingTrigger: %w", err)
				}
				tmp_reportingtrigger := ReportingTrigger3(rawVal_reportingtrigger)
				v.ReportingTrigger = &tmp_reportingtrigger
				offset += n_reportingtrigger
			}
		}
	}
	// Decode reportInterval
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassUniversal && peekTag.Number == 10 {
				val_reportinterval, n, err := ber.DecodeInteger(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding reportInterval: %w", err)
				}
				tmp_reportinterval := ReportInterval3(val_reportinterval)
				v.ReportInterval = &tmp_reportinterval
				offset += n
			}
		}
	}
	// Decode reportAmount
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
				_, n_reportamount, rawVal_reportamount, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding reportAmount: %w", err)
				}
				decVal_reportamount, intErr := ber.DecodeIntegerValue(rawVal_reportamount)
				if intErr != nil {
					return fmt.Errorf("decoding reportAmount: %w", intErr)
				}
				tmp_reportamount := ReportAmount3(decVal_reportamount)
				v.ReportAmount = &tmp_reportamount
				offset += n_reportamount
			}
		}
	}
	// Decode eventThresholdRSRP
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassUniversal && peekTag.Number == 2 {
				val_eventthresholdrsrp, n, err := ber.DecodeInteger(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding eventThresholdRSRP: %w", err)
				}
				tmp_eventthresholdrsrp := EventThresholdRSRP3(val_eventthresholdrsrp)
				v.EventThresholdRSRP = &tmp_eventthresholdrsrp
				offset += n
			}
		}
	}
	// Decode eventThresholdRSRQ
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2 {
				_, n_eventthresholdrsrq, rawVal_eventthresholdrsrq, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding eventThresholdRSRQ: %w", err)
				}
				decVal_eventthresholdrsrq, intErr := ber.DecodeIntegerValue(rawVal_eventthresholdrsrq)
				if intErr != nil {
					return fmt.Errorf("decoding eventThresholdRSRQ: %w", intErr)
				}
				tmp_eventthresholdrsrq := EventThresholdRSRQ3(decVal_eventthresholdrsrq)
				v.EventThresholdRSRQ = &tmp_eventthresholdrsrq
				offset += n_eventthresholdrsrq
			}
		}
	}
	// Decode loggingInterval
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3 {
				_, n_logginginterval, rawVal_logginginterval, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding loggingInterval: %w", err)
				}
				decVal_logginginterval, intErr := ber.DecodeIntegerValue(rawVal_logginginterval)
				if intErr != nil {
					return fmt.Errorf("decoding loggingInterval: %w", intErr)
				}
				tmp_logginginterval := LoggingInterval3(decVal_logginginterval)
				v.LoggingInterval = &tmp_logginginterval
				offset += n_logginginterval
			}
		}
	}
	// Decode loggingDuration
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4 {
				_, n_loggingduration, rawVal_loggingduration, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding loggingDuration: %w", err)
				}
				decVal_loggingduration, intErr := ber.DecodeIntegerValue(rawVal_loggingduration)
				if intErr != nil {
					return fmt.Errorf("decoding loggingDuration: %w", intErr)
				}
				tmp_loggingduration := LoggingDuration3(decVal_loggingduration)
				v.LoggingDuration = &tmp_loggingduration
				offset += n_loggingduration
			}
		}
	}
	// Decode extensionContainer
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 5 {
				_, n_extensioncontainer, rawVal_extensioncontainer, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding extensionContainer: %w", err)
				}
				reconstructed_extensioncontainer := ber.EncodeSequence(rawVal_extensioncontainer)
				var dec_extensioncontainer ExtensionContainer4
				if unmErr := dec_extensioncontainer.UnmarshalBER(reconstructed_extensioncontainer); unmErr != nil {
					return fmt.Errorf("decoding extensionContainer: %w", unmErr)
				}
				v.ExtensionContainer = &dec_extensioncontainer
				offset += n_extensioncontainer
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "MDTConfiguration3", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes AreaScope3 to BER format.
func (v *AreaScope3) MarshalBER() ([]byte, error) {
	var children []byte
	if v.CgiList != nil {
		enc_cgilist, err := MarshalBERCGIList3(v.CgiList)
		if err != nil {
			return nil, fmt.Errorf("encoding cgi-List: %w", err)
		}
		if v.CgiListIndef_ {
			// Strip the outer SEQUENCE tag from marshalBER output to get raw children.
			_, _, seqContent_, tlvErr_ := ber.DecodeTLV(enc_cgilist)
			if tlvErr_ != nil {
				return nil, tlvErr_
			}
			enc_cgilist = ber.EncodeConstructedIndefinite(tag.Tag{Class: tag.ClassContextSpecific, Number: 0}, seqContent_)
		} else {
			enc_cgilist = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, true, enc_cgilist)
		}
		children = append(children, enc_cgilist...)
	}
	if v.EUtranCgiList != nil {
		enc_eutrancgilist, err := MarshalBEREUTRANCGIList3(v.EUtranCgiList)
		if err != nil {
			return nil, fmt.Errorf("encoding e-utran-cgi-List: %w", err)
		}
		if v.EUtranCgiListIndef_ {
			// Strip the outer SEQUENCE tag from marshalBER output to get raw children.
			_, _, seqContent_, tlvErr_ := ber.DecodeTLV(enc_eutrancgilist)
			if tlvErr_ != nil {
				return nil, tlvErr_
			}
			enc_eutrancgilist = ber.EncodeConstructedIndefinite(tag.Tag{Class: tag.ClassContextSpecific, Number: 1}, seqContent_)
		} else {
			enc_eutrancgilist = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, true, enc_eutrancgilist)
		}
		children = append(children, enc_eutrancgilist...)
	}
	if v.RoutingAreaIdList != nil {
		enc_routingareaidlist, err := MarshalBERRoutingAreaIdList3(v.RoutingAreaIdList)
		if err != nil {
			return nil, fmt.Errorf("encoding routingAreaId-List: %w", err)
		}
		if v.RoutingAreaIdListIndef_ {
			// Strip the outer SEQUENCE tag from marshalBER output to get raw children.
			_, _, seqContent_, tlvErr_ := ber.DecodeTLV(enc_routingareaidlist)
			if tlvErr_ != nil {
				return nil, tlvErr_
			}
			enc_routingareaidlist = ber.EncodeConstructedIndefinite(tag.Tag{Class: tag.ClassContextSpecific, Number: 2}, seqContent_)
		} else {
			enc_routingareaidlist = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, true, enc_routingareaidlist)
		}
		children = append(children, enc_routingareaidlist...)
	}
	if v.LocationAreaIdList != nil {
		enc_locationareaidlist, err := MarshalBERLocationAreaIdList3(v.LocationAreaIdList)
		if err != nil {
			return nil, fmt.Errorf("encoding locationAreaId-List: %w", err)
		}
		if v.LocationAreaIdListIndef_ {
			// Strip the outer SEQUENCE tag from marshalBER output to get raw children.
			_, _, seqContent_, tlvErr_ := ber.DecodeTLV(enc_locationareaidlist)
			if tlvErr_ != nil {
				return nil, tlvErr_
			}
			enc_locationareaidlist = ber.EncodeConstructedIndefinite(tag.Tag{Class: tag.ClassContextSpecific, Number: 3}, seqContent_)
		} else {
			enc_locationareaidlist = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, true, enc_locationareaidlist)
		}
		children = append(children, enc_locationareaidlist...)
	}
	if v.TrackingAreaIdList != nil {
		enc_trackingareaidlist, err := MarshalBERTrackingAreaIdList3(v.TrackingAreaIdList)
		if err != nil {
			return nil, fmt.Errorf("encoding trackingAreaId-List: %w", err)
		}
		if v.TrackingAreaIdListIndef_ {
			// Strip the outer SEQUENCE tag from marshalBER output to get raw children.
			_, _, seqContent_, tlvErr_ := ber.DecodeTLV(enc_trackingareaidlist)
			if tlvErr_ != nil {
				return nil, tlvErr_
			}
			enc_trackingareaidlist = ber.EncodeConstructedIndefinite(tag.Tag{Class: tag.ClassContextSpecific, Number: 4}, seqContent_)
		} else {
			enc_trackingareaidlist = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, true, enc_trackingareaidlist)
		}
		children = append(children, enc_trackingareaidlist...)
	}
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding extensionContainer: %w", err)
		}
		enc_extensioncontainer = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 5, true, enc_extensioncontainer)
		children = append(children, enc_extensioncontainer...)
	}
	for i, ext := range v.ExtData_ {
		_, n, _, extErr := ber.DecodeTLV(ext)
		if extErr != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, extErr)
		}
		if n != len(ext) {
			return nil, fmt.Errorf("encoding extension %d: %w", i, ber.ErrExtraData)
		}
		children = append(children, ext...)
	}
	return ber.EncodeSequence(children), nil
}

// MarshalDER encodes AreaScope3 to DER format.
func (v *AreaScope3) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// ITU-T X.690 (02/2021) Section 10.1 requires DER length forms to be definite.
	derValue := *v
	derValue.CgiListIndef_ = false
	derValue.EUtranCgiListIndef_ = false
	derValue.RoutingAreaIdListIndef_ = false
	derValue.LocationAreaIdListIndef_ = false
	derValue.TrackingAreaIdListIndef_ = false
	v = &derValue
	return v.MarshalBER()
}

// UnmarshalBER decodes AreaScope3 from BER/DER format.
func (v *AreaScope3) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding AreaScope3 SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "AreaScope3", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode cgi-List
	v.CgiListIndef_ = false
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
				_, n_cgilist, rawVal_cgilist, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding cgi-List: %w", err)
				}
				reconstructed_cgilist := ber.EncodeSequence(rawVal_cgilist)
				dec_cgilist, unmErr := UnmarshalBERCGIList3(reconstructed_cgilist)
				if unmErr != nil {
					return fmt.Errorf("decoding cgi-List: %w", unmErr)
				}
				v.CgiList = dec_cgilist
				{
					_, tagSz_, _ := ber.DecodeTag(content[offset:])
					if offset+tagSz_ < len(content) && content[offset+tagSz_] == 0x80 {
						v.CgiListIndef_ = true
					}
				}
				offset += n_cgilist
			}
		}
	}
	// Decode e-utran-cgi-List
	v.EUtranCgiListIndef_ = false
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
				_, n_eutrancgilist, rawVal_eutrancgilist, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding e-utran-cgi-List: %w", err)
				}
				reconstructed_eutrancgilist := ber.EncodeSequence(rawVal_eutrancgilist)
				dec_eutrancgilist, unmErr := UnmarshalBEREUTRANCGIList3(reconstructed_eutrancgilist)
				if unmErr != nil {
					return fmt.Errorf("decoding e-utran-cgi-List: %w", unmErr)
				}
				v.EUtranCgiList = dec_eutrancgilist
				{
					_, tagSz_, _ := ber.DecodeTag(content[offset:])
					if offset+tagSz_ < len(content) && content[offset+tagSz_] == 0x80 {
						v.EUtranCgiListIndef_ = true
					}
				}
				offset += n_eutrancgilist
			}
		}
	}
	// Decode routingAreaId-List
	v.RoutingAreaIdListIndef_ = false
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2 {
				_, n_routingareaidlist, rawVal_routingareaidlist, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding routingAreaId-List: %w", err)
				}
				reconstructed_routingareaidlist := ber.EncodeSequence(rawVal_routingareaidlist)
				dec_routingareaidlist, unmErr := UnmarshalBERRoutingAreaIdList3(reconstructed_routingareaidlist)
				if unmErr != nil {
					return fmt.Errorf("decoding routingAreaId-List: %w", unmErr)
				}
				v.RoutingAreaIdList = dec_routingareaidlist
				{
					_, tagSz_, _ := ber.DecodeTag(content[offset:])
					if offset+tagSz_ < len(content) && content[offset+tagSz_] == 0x80 {
						v.RoutingAreaIdListIndef_ = true
					}
				}
				offset += n_routingareaidlist
			}
		}
	}
	// Decode locationAreaId-List
	v.LocationAreaIdListIndef_ = false
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3 {
				_, n_locationareaidlist, rawVal_locationareaidlist, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding locationAreaId-List: %w", err)
				}
				reconstructed_locationareaidlist := ber.EncodeSequence(rawVal_locationareaidlist)
				dec_locationareaidlist, unmErr := UnmarshalBERLocationAreaIdList3(reconstructed_locationareaidlist)
				if unmErr != nil {
					return fmt.Errorf("decoding locationAreaId-List: %w", unmErr)
				}
				v.LocationAreaIdList = dec_locationareaidlist
				{
					_, tagSz_, _ := ber.DecodeTag(content[offset:])
					if offset+tagSz_ < len(content) && content[offset+tagSz_] == 0x80 {
						v.LocationAreaIdListIndef_ = true
					}
				}
				offset += n_locationareaidlist
			}
		}
	}
	// Decode trackingAreaId-List
	v.TrackingAreaIdListIndef_ = false
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4 {
				_, n_trackingareaidlist, rawVal_trackingareaidlist, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding trackingAreaId-List: %w", err)
				}
				reconstructed_trackingareaidlist := ber.EncodeSequence(rawVal_trackingareaidlist)
				dec_trackingareaidlist, unmErr := UnmarshalBERTrackingAreaIdList3(reconstructed_trackingareaidlist)
				if unmErr != nil {
					return fmt.Errorf("decoding trackingAreaId-List: %w", unmErr)
				}
				v.TrackingAreaIdList = dec_trackingareaidlist
				{
					_, tagSz_, _ := ber.DecodeTag(content[offset:])
					if offset+tagSz_ < len(content) && content[offset+tagSz_] == 0x80 {
						v.TrackingAreaIdListIndef_ = true
					}
				}
				offset += n_trackingareaidlist
			}
		}
	}
	// Decode extensionContainer
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 5 {
				_, n_extensioncontainer, rawVal_extensioncontainer, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding extensionContainer: %w", err)
				}
				reconstructed_extensioncontainer := ber.EncodeSequence(rawVal_extensioncontainer)
				var dec_extensioncontainer ExtensionContainer4
				if unmErr := dec_extensioncontainer.UnmarshalBER(reconstructed_extensioncontainer); unmErr != nil {
					return fmt.Errorf("decoding extensionContainer: %w", unmErr)
				}
				v.ExtensionContainer = &dec_extensioncontainer
				offset += n_extensioncontainer
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "AreaScope3", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBERCGIList3 encodes a CGIList3 list to BER.
func MarshalBERCGIList3(list CGIList3) ([]byte, error) {
	var children []byte
	for _, elem := range list {
		children = append(children, ber.EncodeOctetString([]byte(elem))...)
	}
	return ber.EncodeSequence(children), nil
}

// UnmarshalBERCGIList3 decodes a CGIList3 list from BER.
func UnmarshalBERCGIList3(data []byte) (CGIList3, error) {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return nil, fmt.Errorf("decoding CGIList3: %w", err)
	}
	if total != len(data) {
		return nil, &ber.DecodeError{Offset: total, TypeName: "CGIList3", Cause: ber.ErrExtraData}
	}
	var result CGIList3
	offset := 0
	for offset < len(content) {
		val, n, osErr := ber.DecodeOctetString(content[offset:])
		if osErr != nil {
			return nil, fmt.Errorf("decoding element: %w", osErr)
		}
		result = append(result, GlobalCellId4(val))
		offset += n
	}
	return result, nil
}

// MarshalBEREUTRANCGIList3 encodes a EUTRANCGIList3 list to BER.
func MarshalBEREUTRANCGIList3(list EUTRANCGIList3) ([]byte, error) {
	var children []byte
	for _, elem := range list {
		children = append(children, ber.EncodeOctetString([]byte(elem))...)
	}
	return ber.EncodeSequence(children), nil
}

// UnmarshalBEREUTRANCGIList3 decodes a EUTRANCGIList3 list from BER.
func UnmarshalBEREUTRANCGIList3(data []byte) (EUTRANCGIList3, error) {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return nil, fmt.Errorf("decoding EUTRANCGIList3: %w", err)
	}
	if total != len(data) {
		return nil, &ber.DecodeError{Offset: total, TypeName: "EUTRANCGIList3", Cause: ber.ErrExtraData}
	}
	var result EUTRANCGIList3
	offset := 0
	for offset < len(content) {
		val, n, osErr := ber.DecodeOctetString(content[offset:])
		if osErr != nil {
			return nil, fmt.Errorf("decoding element: %w", osErr)
		}
		result = append(result, EUTRANCGI3(val))
		offset += n
	}
	return result, nil
}

// MarshalBERRoutingAreaIdList3 encodes a RoutingAreaIdList3 list to BER.
func MarshalBERRoutingAreaIdList3(list RoutingAreaIdList3) ([]byte, error) {
	var children []byte
	for _, elem := range list {
		children = append(children, ber.EncodeOctetString([]byte(elem))...)
	}
	return ber.EncodeSequence(children), nil
}

// UnmarshalBERRoutingAreaIdList3 decodes a RoutingAreaIdList3 list from BER.
func UnmarshalBERRoutingAreaIdList3(data []byte) (RoutingAreaIdList3, error) {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return nil, fmt.Errorf("decoding RoutingAreaIdList3: %w", err)
	}
	if total != len(data) {
		return nil, &ber.DecodeError{Offset: total, TypeName: "RoutingAreaIdList3", Cause: ber.ErrExtraData}
	}
	var result RoutingAreaIdList3
	offset := 0
	for offset < len(content) {
		val, n, osErr := ber.DecodeOctetString(content[offset:])
		if osErr != nil {
			return nil, fmt.Errorf("decoding element: %w", osErr)
		}
		result = append(result, RAIdentity4(val))
		offset += n
	}
	return result, nil
}

// MarshalBERLocationAreaIdList3 encodes a LocationAreaIdList3 list to BER.
func MarshalBERLocationAreaIdList3(list LocationAreaIdList3) ([]byte, error) {
	var children []byte
	for _, elem := range list {
		children = append(children, ber.EncodeOctetString([]byte(elem))...)
	}
	return ber.EncodeSequence(children), nil
}

// UnmarshalBERLocationAreaIdList3 decodes a LocationAreaIdList3 list from BER.
func UnmarshalBERLocationAreaIdList3(data []byte) (LocationAreaIdList3, error) {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return nil, fmt.Errorf("decoding LocationAreaIdList3: %w", err)
	}
	if total != len(data) {
		return nil, &ber.DecodeError{Offset: total, TypeName: "LocationAreaIdList3", Cause: ber.ErrExtraData}
	}
	var result LocationAreaIdList3
	offset := 0
	for offset < len(content) {
		val, n, osErr := ber.DecodeOctetString(content[offset:])
		if osErr != nil {
			return nil, fmt.Errorf("decoding element: %w", osErr)
		}
		result = append(result, LAIFixedLength4(val))
		offset += n
	}
	return result, nil
}

// MarshalBERTrackingAreaIdList3 encodes a TrackingAreaIdList3 list to BER.
func MarshalBERTrackingAreaIdList3(list TrackingAreaIdList3) ([]byte, error) {
	var children []byte
	for _, elem := range list {
		children = append(children, ber.EncodeOctetString([]byte(elem))...)
	}
	return ber.EncodeSequence(children), nil
}

// UnmarshalBERTrackingAreaIdList3 decodes a TrackingAreaIdList3 list from BER.
func UnmarshalBERTrackingAreaIdList3(data []byte) (TrackingAreaIdList3, error) {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return nil, fmt.Errorf("decoding TrackingAreaIdList3: %w", err)
	}
	if total != len(data) {
		return nil, &ber.DecodeError{Offset: total, TypeName: "TrackingAreaIdList3", Cause: ber.ErrExtraData}
	}
	var result TrackingAreaIdList3
	offset := 0
	for offset < len(content) {
		val, n, osErr := ber.DecodeOctetString(content[offset:])
		if osErr != nil {
			return nil, fmt.Errorf("decoding element: %w", osErr)
		}
		result = append(result, TAId3(val))
		offset += n
	}
	return result, nil
}

// MarshalBER encodes TraceDepthList4 to BER format.
func (v *TraceDepthList4) MarshalBER() ([]byte, error) {
	var children []byte
	if v.MscSTraceDepth != nil {
		enc_mscstracedepth := ber.EncodeEnumerated(int64(*v.MscSTraceDepth))
		enc_mscstracedepth = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, false, enc_mscstracedepth)
		children = append(children, enc_mscstracedepth...)
	}
	if v.MgwTraceDepth != nil {
		enc_mgwtracedepth := ber.EncodeEnumerated(int64(*v.MgwTraceDepth))
		enc_mgwtracedepth = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, false, enc_mgwtracedepth)
		children = append(children, enc_mgwtracedepth...)
	}
	if v.SgsnTraceDepth != nil {
		enc_sgsntracedepth := ber.EncodeEnumerated(int64(*v.SgsnTraceDepth))
		enc_sgsntracedepth = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, false, enc_sgsntracedepth)
		children = append(children, enc_sgsntracedepth...)
	}
	if v.GgsnTraceDepth != nil {
		enc_ggsntracedepth := ber.EncodeEnumerated(int64(*v.GgsnTraceDepth))
		enc_ggsntracedepth = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, false, enc_ggsntracedepth)
		children = append(children, enc_ggsntracedepth...)
	}
	if v.RncTraceDepth != nil {
		enc_rnctracedepth := ber.EncodeEnumerated(int64(*v.RncTraceDepth))
		enc_rnctracedepth = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, false, enc_rnctracedepth)
		children = append(children, enc_rnctracedepth...)
	}
	if v.BmscTraceDepth != nil {
		enc_bmsctracedepth := ber.EncodeEnumerated(int64(*v.BmscTraceDepth))
		enc_bmsctracedepth = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 5, false, enc_bmsctracedepth)
		children = append(children, enc_bmsctracedepth...)
	}
	if v.MmeTraceDepth != nil {
		enc_mmetracedepth := ber.EncodeEnumerated(int64(*v.MmeTraceDepth))
		enc_mmetracedepth = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 6, false, enc_mmetracedepth)
		children = append(children, enc_mmetracedepth...)
	}
	if v.SgwTraceDepth != nil {
		enc_sgwtracedepth := ber.EncodeEnumerated(int64(*v.SgwTraceDepth))
		enc_sgwtracedepth = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 7, false, enc_sgwtracedepth)
		children = append(children, enc_sgwtracedepth...)
	}
	if v.PgwTraceDepth != nil {
		enc_pgwtracedepth := ber.EncodeEnumerated(int64(*v.PgwTraceDepth))
		enc_pgwtracedepth = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 8, false, enc_pgwtracedepth)
		children = append(children, enc_pgwtracedepth...)
	}
	if v.ENBTraceDepth != nil {
		enc_enbtracedepth := ber.EncodeEnumerated(int64(*v.ENBTraceDepth))
		enc_enbtracedepth = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 9, false, enc_enbtracedepth)
		children = append(children, enc_enbtracedepth...)
	}
	for i, ext := range v.ExtData_ {
		_, n, _, extErr := ber.DecodeTLV(ext)
		if extErr != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, extErr)
		}
		if n != len(ext) {
			return nil, fmt.Errorf("encoding extension %d: %w", i, ber.ErrExtraData)
		}
		children = append(children, ext...)
	}
	return ber.EncodeSequence(children), nil
}

// MarshalDER encodes TraceDepthList4 to DER format.
func (v *TraceDepthList4) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes TraceDepthList4 from BER/DER format.
func (v *TraceDepthList4) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding TraceDepthList4 SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "TraceDepthList4", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode msc-s-TraceDepth
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
				_, n_mscstracedepth, rawVal_mscstracedepth, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding msc-s-TraceDepth: %w", err)
				}
				decVal_mscstracedepth, intErr := ber.DecodeIntegerValue(rawVal_mscstracedepth)
				if intErr != nil {
					return fmt.Errorf("decoding msc-s-TraceDepth: %w", intErr)
				}
				tmp_mscstracedepth := TraceDepth4(decVal_mscstracedepth)
				v.MscSTraceDepth = &tmp_mscstracedepth
				offset += n_mscstracedepth
			}
		}
	}
	// Decode mgw-TraceDepth
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
				_, n_mgwtracedepth, rawVal_mgwtracedepth, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding mgw-TraceDepth: %w", err)
				}
				decVal_mgwtracedepth, intErr := ber.DecodeIntegerValue(rawVal_mgwtracedepth)
				if intErr != nil {
					return fmt.Errorf("decoding mgw-TraceDepth: %w", intErr)
				}
				tmp_mgwtracedepth := TraceDepth4(decVal_mgwtracedepth)
				v.MgwTraceDepth = &tmp_mgwtracedepth
				offset += n_mgwtracedepth
			}
		}
	}
	// Decode sgsn-TraceDepth
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2 {
				_, n_sgsntracedepth, rawVal_sgsntracedepth, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding sgsn-TraceDepth: %w", err)
				}
				decVal_sgsntracedepth, intErr := ber.DecodeIntegerValue(rawVal_sgsntracedepth)
				if intErr != nil {
					return fmt.Errorf("decoding sgsn-TraceDepth: %w", intErr)
				}
				tmp_sgsntracedepth := TraceDepth4(decVal_sgsntracedepth)
				v.SgsnTraceDepth = &tmp_sgsntracedepth
				offset += n_sgsntracedepth
			}
		}
	}
	// Decode ggsn-TraceDepth
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3 {
				_, n_ggsntracedepth, rawVal_ggsntracedepth, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding ggsn-TraceDepth: %w", err)
				}
				decVal_ggsntracedepth, intErr := ber.DecodeIntegerValue(rawVal_ggsntracedepth)
				if intErr != nil {
					return fmt.Errorf("decoding ggsn-TraceDepth: %w", intErr)
				}
				tmp_ggsntracedepth := TraceDepth4(decVal_ggsntracedepth)
				v.GgsnTraceDepth = &tmp_ggsntracedepth
				offset += n_ggsntracedepth
			}
		}
	}
	// Decode rnc-TraceDepth
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4 {
				_, n_rnctracedepth, rawVal_rnctracedepth, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding rnc-TraceDepth: %w", err)
				}
				decVal_rnctracedepth, intErr := ber.DecodeIntegerValue(rawVal_rnctracedepth)
				if intErr != nil {
					return fmt.Errorf("decoding rnc-TraceDepth: %w", intErr)
				}
				tmp_rnctracedepth := TraceDepth4(decVal_rnctracedepth)
				v.RncTraceDepth = &tmp_rnctracedepth
				offset += n_rnctracedepth
			}
		}
	}
	// Decode bmsc-TraceDepth
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 5 {
				_, n_bmsctracedepth, rawVal_bmsctracedepth, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding bmsc-TraceDepth: %w", err)
				}
				decVal_bmsctracedepth, intErr := ber.DecodeIntegerValue(rawVal_bmsctracedepth)
				if intErr != nil {
					return fmt.Errorf("decoding bmsc-TraceDepth: %w", intErr)
				}
				tmp_bmsctracedepth := TraceDepth4(decVal_bmsctracedepth)
				v.BmscTraceDepth = &tmp_bmsctracedepth
				offset += n_bmsctracedepth
			}
		}
	}
	// Decode mme-TraceDepth
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 6 {
				_, n_mmetracedepth, rawVal_mmetracedepth, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding mme-TraceDepth: %w", err)
				}
				decVal_mmetracedepth, intErr := ber.DecodeIntegerValue(rawVal_mmetracedepth)
				if intErr != nil {
					return fmt.Errorf("decoding mme-TraceDepth: %w", intErr)
				}
				tmp_mmetracedepth := TraceDepth4(decVal_mmetracedepth)
				v.MmeTraceDepth = &tmp_mmetracedepth
				offset += n_mmetracedepth
			}
		}
	}
	// Decode sgw-TraceDepth
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 7 {
				_, n_sgwtracedepth, rawVal_sgwtracedepth, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding sgw-TraceDepth: %w", err)
				}
				decVal_sgwtracedepth, intErr := ber.DecodeIntegerValue(rawVal_sgwtracedepth)
				if intErr != nil {
					return fmt.Errorf("decoding sgw-TraceDepth: %w", intErr)
				}
				tmp_sgwtracedepth := TraceDepth4(decVal_sgwtracedepth)
				v.SgwTraceDepth = &tmp_sgwtracedepth
				offset += n_sgwtracedepth
			}
		}
	}
	// Decode pgw-TraceDepth
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 8 {
				_, n_pgwtracedepth, rawVal_pgwtracedepth, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding pgw-TraceDepth: %w", err)
				}
				decVal_pgwtracedepth, intErr := ber.DecodeIntegerValue(rawVal_pgwtracedepth)
				if intErr != nil {
					return fmt.Errorf("decoding pgw-TraceDepth: %w", intErr)
				}
				tmp_pgwtracedepth := TraceDepth4(decVal_pgwtracedepth)
				v.PgwTraceDepth = &tmp_pgwtracedepth
				offset += n_pgwtracedepth
			}
		}
	}
	// Decode eNB-TraceDepth
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 9 {
				_, n_enbtracedepth, rawVal_enbtracedepth, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding eNB-TraceDepth: %w", err)
				}
				decVal_enbtracedepth, intErr := ber.DecodeIntegerValue(rawVal_enbtracedepth)
				if intErr != nil {
					return fmt.Errorf("decoding eNB-TraceDepth: %w", intErr)
				}
				tmp_enbtracedepth := TraceDepth4(decVal_enbtracedepth)
				v.ENBTraceDepth = &tmp_enbtracedepth
				offset += n_enbtracedepth
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "TraceDepthList4", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes TraceInterfaceList4 to BER format.
func (v *TraceInterfaceList4) MarshalBER() ([]byte, error) {
	var children []byte
	if v.MscSList != nil {
		enc_mscslist := ber.EncodeBitString(v.MscSList.Bytes, (8-(v.MscSList.BitLength%8))%8)
		enc_mscslist = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, false, enc_mscslist)
		children = append(children, enc_mscslist...)
	}
	if v.MgwList != nil {
		enc_mgwlist := ber.EncodeBitString(v.MgwList.Bytes, (8-(v.MgwList.BitLength%8))%8)
		enc_mgwlist = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, false, enc_mgwlist)
		children = append(children, enc_mgwlist...)
	}
	if v.SgsnList != nil {
		enc_sgsnlist := ber.EncodeBitString(v.SgsnList.Bytes, (8-(v.SgsnList.BitLength%8))%8)
		enc_sgsnlist = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, false, enc_sgsnlist)
		children = append(children, enc_sgsnlist...)
	}
	if v.GgsnList != nil {
		enc_ggsnlist := ber.EncodeBitString(v.GgsnList.Bytes, (8-(v.GgsnList.BitLength%8))%8)
		enc_ggsnlist = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, false, enc_ggsnlist)
		children = append(children, enc_ggsnlist...)
	}
	if v.RncList != nil {
		enc_rnclist := ber.EncodeBitString(v.RncList.Bytes, (8-(v.RncList.BitLength%8))%8)
		enc_rnclist = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, false, enc_rnclist)
		children = append(children, enc_rnclist...)
	}
	if v.BmscList != nil {
		enc_bmsclist := ber.EncodeBitString(v.BmscList.Bytes, (8-(v.BmscList.BitLength%8))%8)
		enc_bmsclist = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 5, false, enc_bmsclist)
		children = append(children, enc_bmsclist...)
	}
	if v.MmeList != nil {
		enc_mmelist := ber.EncodeBitString(v.MmeList.Bytes, (8-(v.MmeList.BitLength%8))%8)
		enc_mmelist = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 6, false, enc_mmelist)
		children = append(children, enc_mmelist...)
	}
	if v.SgwList != nil {
		enc_sgwlist := ber.EncodeBitString(v.SgwList.Bytes, (8-(v.SgwList.BitLength%8))%8)
		enc_sgwlist = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 7, false, enc_sgwlist)
		children = append(children, enc_sgwlist...)
	}
	if v.PgwList != nil {
		enc_pgwlist := ber.EncodeBitString(v.PgwList.Bytes, (8-(v.PgwList.BitLength%8))%8)
		enc_pgwlist = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 8, false, enc_pgwlist)
		children = append(children, enc_pgwlist...)
	}
	if v.ENBList != nil {
		enc_enblist := ber.EncodeBitString(v.ENBList.Bytes, (8-(v.ENBList.BitLength%8))%8)
		enc_enblist = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 9, false, enc_enblist)
		children = append(children, enc_enblist...)
	}
	for i, ext := range v.ExtData_ {
		_, n, _, extErr := ber.DecodeTLV(ext)
		if extErr != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, extErr)
		}
		if n != len(ext) {
			return nil, fmt.Errorf("encoding extension %d: %w", i, ber.ErrExtraData)
		}
		children = append(children, ext...)
	}
	return ber.EncodeSequence(children), nil
}

// MarshalDER encodes TraceInterfaceList4 to DER format.
func (v *TraceInterfaceList4) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes TraceInterfaceList4 from BER/DER format.
func (v *TraceInterfaceList4) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding TraceInterfaceList4 SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "TraceInterfaceList4", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode msc-s-List
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
				_, n_mscslist, rawVal_mscslist, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding msc-s-List: %w", err)
				}
				bsBytes_mscslist, bsUnused_mscslist, bsErr := ber.DecodeBitStringValue(rawVal_mscslist)
				if bsErr != nil {
					return fmt.Errorf("decoding msc-s-List: %w", bsErr)
				}
				tmp_mscslist := runtime.BitString{Bytes: bsBytes_mscslist, BitLength: len(bsBytes_mscslist)*8 - bsUnused_mscslist}
				v.MscSList = &tmp_mscslist
				offset += n_mscslist
			}
		}
	}
	// Decode mgw-List
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
				_, n_mgwlist, rawVal_mgwlist, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding mgw-List: %w", err)
				}
				bsBytes_mgwlist, bsUnused_mgwlist, bsErr := ber.DecodeBitStringValue(rawVal_mgwlist)
				if bsErr != nil {
					return fmt.Errorf("decoding mgw-List: %w", bsErr)
				}
				tmp_mgwlist := runtime.BitString{Bytes: bsBytes_mgwlist, BitLength: len(bsBytes_mgwlist)*8 - bsUnused_mgwlist}
				v.MgwList = &tmp_mgwlist
				offset += n_mgwlist
			}
		}
	}
	// Decode sgsn-List
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2 {
				_, n_sgsnlist, rawVal_sgsnlist, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding sgsn-List: %w", err)
				}
				bsBytes_sgsnlist, bsUnused_sgsnlist, bsErr := ber.DecodeBitStringValue(rawVal_sgsnlist)
				if bsErr != nil {
					return fmt.Errorf("decoding sgsn-List: %w", bsErr)
				}
				tmp_sgsnlist := runtime.BitString{Bytes: bsBytes_sgsnlist, BitLength: len(bsBytes_sgsnlist)*8 - bsUnused_sgsnlist}
				v.SgsnList = &tmp_sgsnlist
				offset += n_sgsnlist
			}
		}
	}
	// Decode ggsn-List
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3 {
				_, n_ggsnlist, rawVal_ggsnlist, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding ggsn-List: %w", err)
				}
				bsBytes_ggsnlist, bsUnused_ggsnlist, bsErr := ber.DecodeBitStringValue(rawVal_ggsnlist)
				if bsErr != nil {
					return fmt.Errorf("decoding ggsn-List: %w", bsErr)
				}
				tmp_ggsnlist := runtime.BitString{Bytes: bsBytes_ggsnlist, BitLength: len(bsBytes_ggsnlist)*8 - bsUnused_ggsnlist}
				v.GgsnList = &tmp_ggsnlist
				offset += n_ggsnlist
			}
		}
	}
	// Decode rnc-List
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4 {
				_, n_rnclist, rawVal_rnclist, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding rnc-List: %w", err)
				}
				bsBytes_rnclist, bsUnused_rnclist, bsErr := ber.DecodeBitStringValue(rawVal_rnclist)
				if bsErr != nil {
					return fmt.Errorf("decoding rnc-List: %w", bsErr)
				}
				tmp_rnclist := runtime.BitString{Bytes: bsBytes_rnclist, BitLength: len(bsBytes_rnclist)*8 - bsUnused_rnclist}
				v.RncList = &tmp_rnclist
				offset += n_rnclist
			}
		}
	}
	// Decode bmsc-List
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 5 {
				_, n_bmsclist, rawVal_bmsclist, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding bmsc-List: %w", err)
				}
				bsBytes_bmsclist, bsUnused_bmsclist, bsErr := ber.DecodeBitStringValue(rawVal_bmsclist)
				if bsErr != nil {
					return fmt.Errorf("decoding bmsc-List: %w", bsErr)
				}
				tmp_bmsclist := runtime.BitString{Bytes: bsBytes_bmsclist, BitLength: len(bsBytes_bmsclist)*8 - bsUnused_bmsclist}
				v.BmscList = &tmp_bmsclist
				offset += n_bmsclist
			}
		}
	}
	// Decode mme-List
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 6 {
				_, n_mmelist, rawVal_mmelist, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding mme-List: %w", err)
				}
				bsBytes_mmelist, bsUnused_mmelist, bsErr := ber.DecodeBitStringValue(rawVal_mmelist)
				if bsErr != nil {
					return fmt.Errorf("decoding mme-List: %w", bsErr)
				}
				tmp_mmelist := runtime.BitString{Bytes: bsBytes_mmelist, BitLength: len(bsBytes_mmelist)*8 - bsUnused_mmelist}
				v.MmeList = &tmp_mmelist
				offset += n_mmelist
			}
		}
	}
	// Decode sgw-List
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 7 {
				_, n_sgwlist, rawVal_sgwlist, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding sgw-List: %w", err)
				}
				bsBytes_sgwlist, bsUnused_sgwlist, bsErr := ber.DecodeBitStringValue(rawVal_sgwlist)
				if bsErr != nil {
					return fmt.Errorf("decoding sgw-List: %w", bsErr)
				}
				tmp_sgwlist := runtime.BitString{Bytes: bsBytes_sgwlist, BitLength: len(bsBytes_sgwlist)*8 - bsUnused_sgwlist}
				v.SgwList = &tmp_sgwlist
				offset += n_sgwlist
			}
		}
	}
	// Decode pgw-List
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 8 {
				_, n_pgwlist, rawVal_pgwlist, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding pgw-List: %w", err)
				}
				bsBytes_pgwlist, bsUnused_pgwlist, bsErr := ber.DecodeBitStringValue(rawVal_pgwlist)
				if bsErr != nil {
					return fmt.Errorf("decoding pgw-List: %w", bsErr)
				}
				tmp_pgwlist := runtime.BitString{Bytes: bsBytes_pgwlist, BitLength: len(bsBytes_pgwlist)*8 - bsUnused_pgwlist}
				v.PgwList = &tmp_pgwlist
				offset += n_pgwlist
			}
		}
	}
	// Decode eNB-List
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 9 {
				_, n_enblist, rawVal_enblist, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding eNB-List: %w", err)
				}
				bsBytes_enblist, bsUnused_enblist, bsErr := ber.DecodeBitStringValue(rawVal_enblist)
				if bsErr != nil {
					return fmt.Errorf("decoding eNB-List: %w", bsErr)
				}
				tmp_enblist := runtime.BitString{Bytes: bsBytes_enblist, BitLength: len(bsBytes_enblist)*8 - bsUnused_enblist}
				v.ENBList = &tmp_enblist
				offset += n_enblist
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "TraceInterfaceList4", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes TraceEventList4 to BER format.
func (v *TraceEventList4) MarshalBER() ([]byte, error) {
	var children []byte
	if v.MscSList != nil {
		enc_mscslist := ber.EncodeBitString(v.MscSList.Bytes, (8-(v.MscSList.BitLength%8))%8)
		enc_mscslist = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, false, enc_mscslist)
		children = append(children, enc_mscslist...)
	}
	if v.MgwList != nil {
		enc_mgwlist := ber.EncodeBitString(v.MgwList.Bytes, (8-(v.MgwList.BitLength%8))%8)
		enc_mgwlist = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, false, enc_mgwlist)
		children = append(children, enc_mgwlist...)
	}
	if v.SgsnList != nil {
		enc_sgsnlist := ber.EncodeBitString(v.SgsnList.Bytes, (8-(v.SgsnList.BitLength%8))%8)
		enc_sgsnlist = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, false, enc_sgsnlist)
		children = append(children, enc_sgsnlist...)
	}
	if v.GgsnList != nil {
		enc_ggsnlist := ber.EncodeBitString(v.GgsnList.Bytes, (8-(v.GgsnList.BitLength%8))%8)
		enc_ggsnlist = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, false, enc_ggsnlist)
		children = append(children, enc_ggsnlist...)
	}
	if v.BmscList != nil {
		enc_bmsclist := ber.EncodeBitString(v.BmscList.Bytes, (8-(v.BmscList.BitLength%8))%8)
		enc_bmsclist = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, false, enc_bmsclist)
		children = append(children, enc_bmsclist...)
	}
	if v.MmeList != nil {
		enc_mmelist := ber.EncodeBitString(v.MmeList.Bytes, (8-(v.MmeList.BitLength%8))%8)
		enc_mmelist = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 5, false, enc_mmelist)
		children = append(children, enc_mmelist...)
	}
	if v.SgwList != nil {
		enc_sgwlist := ber.EncodeBitString(v.SgwList.Bytes, (8-(v.SgwList.BitLength%8))%8)
		enc_sgwlist = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 6, false, enc_sgwlist)
		children = append(children, enc_sgwlist...)
	}
	if v.PgwList != nil {
		enc_pgwlist := ber.EncodeBitString(v.PgwList.Bytes, (8-(v.PgwList.BitLength%8))%8)
		enc_pgwlist = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 7, false, enc_pgwlist)
		children = append(children, enc_pgwlist...)
	}
	for i, ext := range v.ExtData_ {
		_, n, _, extErr := ber.DecodeTLV(ext)
		if extErr != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, extErr)
		}
		if n != len(ext) {
			return nil, fmt.Errorf("encoding extension %d: %w", i, ber.ErrExtraData)
		}
		children = append(children, ext...)
	}
	return ber.EncodeSequence(children), nil
}

// MarshalDER encodes TraceEventList4 to DER format.
func (v *TraceEventList4) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes TraceEventList4 from BER/DER format.
func (v *TraceEventList4) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding TraceEventList4 SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "TraceEventList4", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode msc-s-List
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
				_, n_mscslist, rawVal_mscslist, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding msc-s-List: %w", err)
				}
				bsBytes_mscslist, bsUnused_mscslist, bsErr := ber.DecodeBitStringValue(rawVal_mscslist)
				if bsErr != nil {
					return fmt.Errorf("decoding msc-s-List: %w", bsErr)
				}
				tmp_mscslist := runtime.BitString{Bytes: bsBytes_mscslist, BitLength: len(bsBytes_mscslist)*8 - bsUnused_mscslist}
				v.MscSList = &tmp_mscslist
				offset += n_mscslist
			}
		}
	}
	// Decode mgw-List
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
				_, n_mgwlist, rawVal_mgwlist, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding mgw-List: %w", err)
				}
				bsBytes_mgwlist, bsUnused_mgwlist, bsErr := ber.DecodeBitStringValue(rawVal_mgwlist)
				if bsErr != nil {
					return fmt.Errorf("decoding mgw-List: %w", bsErr)
				}
				tmp_mgwlist := runtime.BitString{Bytes: bsBytes_mgwlist, BitLength: len(bsBytes_mgwlist)*8 - bsUnused_mgwlist}
				v.MgwList = &tmp_mgwlist
				offset += n_mgwlist
			}
		}
	}
	// Decode sgsn-List
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2 {
				_, n_sgsnlist, rawVal_sgsnlist, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding sgsn-List: %w", err)
				}
				bsBytes_sgsnlist, bsUnused_sgsnlist, bsErr := ber.DecodeBitStringValue(rawVal_sgsnlist)
				if bsErr != nil {
					return fmt.Errorf("decoding sgsn-List: %w", bsErr)
				}
				tmp_sgsnlist := runtime.BitString{Bytes: bsBytes_sgsnlist, BitLength: len(bsBytes_sgsnlist)*8 - bsUnused_sgsnlist}
				v.SgsnList = &tmp_sgsnlist
				offset += n_sgsnlist
			}
		}
	}
	// Decode ggsn-List
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3 {
				_, n_ggsnlist, rawVal_ggsnlist, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding ggsn-List: %w", err)
				}
				bsBytes_ggsnlist, bsUnused_ggsnlist, bsErr := ber.DecodeBitStringValue(rawVal_ggsnlist)
				if bsErr != nil {
					return fmt.Errorf("decoding ggsn-List: %w", bsErr)
				}
				tmp_ggsnlist := runtime.BitString{Bytes: bsBytes_ggsnlist, BitLength: len(bsBytes_ggsnlist)*8 - bsUnused_ggsnlist}
				v.GgsnList = &tmp_ggsnlist
				offset += n_ggsnlist
			}
		}
	}
	// Decode bmsc-List
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4 {
				_, n_bmsclist, rawVal_bmsclist, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding bmsc-List: %w", err)
				}
				bsBytes_bmsclist, bsUnused_bmsclist, bsErr := ber.DecodeBitStringValue(rawVal_bmsclist)
				if bsErr != nil {
					return fmt.Errorf("decoding bmsc-List: %w", bsErr)
				}
				tmp_bmsclist := runtime.BitString{Bytes: bsBytes_bmsclist, BitLength: len(bsBytes_bmsclist)*8 - bsUnused_bmsclist}
				v.BmscList = &tmp_bmsclist
				offset += n_bmsclist
			}
		}
	}
	// Decode mme-List
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 5 {
				_, n_mmelist, rawVal_mmelist, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding mme-List: %w", err)
				}
				bsBytes_mmelist, bsUnused_mmelist, bsErr := ber.DecodeBitStringValue(rawVal_mmelist)
				if bsErr != nil {
					return fmt.Errorf("decoding mme-List: %w", bsErr)
				}
				tmp_mmelist := runtime.BitString{Bytes: bsBytes_mmelist, BitLength: len(bsBytes_mmelist)*8 - bsUnused_mmelist}
				v.MmeList = &tmp_mmelist
				offset += n_mmelist
			}
		}
	}
	// Decode sgw-List
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 6 {
				_, n_sgwlist, rawVal_sgwlist, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding sgw-List: %w", err)
				}
				bsBytes_sgwlist, bsUnused_sgwlist, bsErr := ber.DecodeBitStringValue(rawVal_sgwlist)
				if bsErr != nil {
					return fmt.Errorf("decoding sgw-List: %w", bsErr)
				}
				tmp_sgwlist := runtime.BitString{Bytes: bsBytes_sgwlist, BitLength: len(bsBytes_sgwlist)*8 - bsUnused_sgwlist}
				v.SgwList = &tmp_sgwlist
				offset += n_sgwlist
			}
		}
	}
	// Decode pgw-List
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 7 {
				_, n_pgwlist, rawVal_pgwlist, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding pgw-List: %w", err)
				}
				bsBytes_pgwlist, bsUnused_pgwlist, bsErr := ber.DecodeBitStringValue(rawVal_pgwlist)
				if bsErr != nil {
					return fmt.Errorf("decoding pgw-List: %w", bsErr)
				}
				tmp_pgwlist := runtime.BitString{Bytes: bsBytes_pgwlist, BitLength: len(bsBytes_pgwlist)*8 - bsUnused_pgwlist}
				v.PgwList = &tmp_pgwlist
				offset += n_pgwlist
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "TraceEventList4", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes TracePropagationList4 to BER format.
func (v *TracePropagationList4) MarshalBER() ([]byte, error) {
	var children []byte
	if v.TraceReference != nil {
		enc_tracereference := ber.EncodeOctetString([]byte(*v.TraceReference))
		enc_tracereference = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, false, enc_tracereference)
		children = append(children, enc_tracereference...)
	}
	if v.TraceType != nil {
		enc_tracetype := ber.EncodeInteger(int64(*v.TraceType))
		enc_tracetype = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, false, enc_tracetype)
		children = append(children, enc_tracetype...)
	}
	if v.TraceReference2 != nil {
		enc_tracereference2 := ber.EncodeOctetString([]byte(*v.TraceReference2))
		enc_tracereference2 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, false, enc_tracereference2)
		children = append(children, enc_tracereference2...)
	}
	if v.TraceRecordingSessionReference != nil {
		enc_tracerecordingsessionreference := ber.EncodeOctetString([]byte(*v.TraceRecordingSessionReference))
		enc_tracerecordingsessionreference = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, false, enc_tracerecordingsessionreference)
		children = append(children, enc_tracerecordingsessionreference...)
	}
	if v.RncTraceDepth != nil {
		enc_rnctracedepth := ber.EncodeEnumerated(int64(*v.RncTraceDepth))
		enc_rnctracedepth = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, false, enc_rnctracedepth)
		children = append(children, enc_rnctracedepth...)
	}
	if v.RncInterfaceList != nil {
		enc_rncinterfacelist := ber.EncodeBitString(v.RncInterfaceList.Bytes, (8-(v.RncInterfaceList.BitLength%8))%8)
		enc_rncinterfacelist = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 5, false, enc_rncinterfacelist)
		children = append(children, enc_rncinterfacelist...)
	}
	if v.MscSTraceDepth != nil {
		enc_mscstracedepth := ber.EncodeEnumerated(int64(*v.MscSTraceDepth))
		enc_mscstracedepth = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 6, false, enc_mscstracedepth)
		children = append(children, enc_mscstracedepth...)
	}
	if v.MscSInterfaceList != nil {
		enc_mscsinterfacelist := ber.EncodeBitString(v.MscSInterfaceList.Bytes, (8-(v.MscSInterfaceList.BitLength%8))%8)
		enc_mscsinterfacelist = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 7, false, enc_mscsinterfacelist)
		children = append(children, enc_mscsinterfacelist...)
	}
	if v.MscSEventList != nil {
		enc_mscseventlist := ber.EncodeBitString(v.MscSEventList.Bytes, (8-(v.MscSEventList.BitLength%8))%8)
		enc_mscseventlist = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 8, false, enc_mscseventlist)
		children = append(children, enc_mscseventlist...)
	}
	if v.MgwTraceDepth != nil {
		enc_mgwtracedepth := ber.EncodeEnumerated(int64(*v.MgwTraceDepth))
		enc_mgwtracedepth = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 9, false, enc_mgwtracedepth)
		children = append(children, enc_mgwtracedepth...)
	}
	if v.MgwInterfaceList != nil {
		enc_mgwinterfacelist := ber.EncodeBitString(v.MgwInterfaceList.Bytes, (8-(v.MgwInterfaceList.BitLength%8))%8)
		enc_mgwinterfacelist = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 10, false, enc_mgwinterfacelist)
		children = append(children, enc_mgwinterfacelist...)
	}
	if v.MgwEventList != nil {
		enc_mgweventlist := ber.EncodeBitString(v.MgwEventList.Bytes, (8-(v.MgwEventList.BitLength%8))%8)
		enc_mgweventlist = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 11, false, enc_mgweventlist)
		children = append(children, enc_mgweventlist...)
	}
	for i, ext := range v.ExtData_ {
		_, n, _, extErr := ber.DecodeTLV(ext)
		if extErr != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, extErr)
		}
		if n != len(ext) {
			return nil, fmt.Errorf("encoding extension %d: %w", i, ber.ErrExtraData)
		}
		children = append(children, ext...)
	}
	return ber.EncodeSequence(children), nil
}

// MarshalDER encodes TracePropagationList4 to DER format.
func (v *TracePropagationList4) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes TracePropagationList4 from BER/DER format.
func (v *TracePropagationList4) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding TracePropagationList4 SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "TracePropagationList4", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode traceReference
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
				_, n_tracereference, rawVal_tracereference, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding traceReference: %w", err)
				}
				tmp_tracereference := TraceReference4(rawVal_tracereference)
				v.TraceReference = &tmp_tracereference
				offset += n_tracereference
			}
		}
	}
	// Decode traceType
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
				_, n_tracetype, rawVal_tracetype, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding traceType: %w", err)
				}
				decVal_tracetype, intErr := ber.DecodeIntegerValue(rawVal_tracetype)
				if intErr != nil {
					return fmt.Errorf("decoding traceType: %w", intErr)
				}
				tmp_tracetype := TraceType4(decVal_tracetype)
				v.TraceType = &tmp_tracetype
				offset += n_tracetype
			}
		}
	}
	// Decode traceReference2
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2 {
				_, n_tracereference2, rawVal_tracereference2, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding traceReference2: %w", err)
				}
				tmp_tracereference2 := TraceReference24(rawVal_tracereference2)
				v.TraceReference2 = &tmp_tracereference2
				offset += n_tracereference2
			}
		}
	}
	// Decode traceRecordingSessionReference
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3 {
				_, n_tracerecordingsessionreference, rawVal_tracerecordingsessionreference, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding traceRecordingSessionReference: %w", err)
				}
				tmp_tracerecordingsessionreference := TraceRecordingSessionReference4(rawVal_tracerecordingsessionreference)
				v.TraceRecordingSessionReference = &tmp_tracerecordingsessionreference
				offset += n_tracerecordingsessionreference
			}
		}
	}
	// Decode rnc-TraceDepth
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4 {
				_, n_rnctracedepth, rawVal_rnctracedepth, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding rnc-TraceDepth: %w", err)
				}
				decVal_rnctracedepth, intErr := ber.DecodeIntegerValue(rawVal_rnctracedepth)
				if intErr != nil {
					return fmt.Errorf("decoding rnc-TraceDepth: %w", intErr)
				}
				tmp_rnctracedepth := TraceDepth4(decVal_rnctracedepth)
				v.RncTraceDepth = &tmp_rnctracedepth
				offset += n_rnctracedepth
			}
		}
	}
	// Decode rnc-InterfaceList
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 5 {
				_, n_rncinterfacelist, rawVal_rncinterfacelist, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding rnc-InterfaceList: %w", err)
				}
				bsBytes_rncinterfacelist, bsUnused_rncinterfacelist, bsErr := ber.DecodeBitStringValue(rawVal_rncinterfacelist)
				if bsErr != nil {
					return fmt.Errorf("decoding rnc-InterfaceList: %w", bsErr)
				}
				tmp_rncinterfacelist := runtime.BitString{Bytes: bsBytes_rncinterfacelist, BitLength: len(bsBytes_rncinterfacelist)*8 - bsUnused_rncinterfacelist}
				v.RncInterfaceList = &tmp_rncinterfacelist
				offset += n_rncinterfacelist
			}
		}
	}
	// Decode msc-s-TraceDepth
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 6 {
				_, n_mscstracedepth, rawVal_mscstracedepth, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding msc-s-TraceDepth: %w", err)
				}
				decVal_mscstracedepth, intErr := ber.DecodeIntegerValue(rawVal_mscstracedepth)
				if intErr != nil {
					return fmt.Errorf("decoding msc-s-TraceDepth: %w", intErr)
				}
				tmp_mscstracedepth := TraceDepth4(decVal_mscstracedepth)
				v.MscSTraceDepth = &tmp_mscstracedepth
				offset += n_mscstracedepth
			}
		}
	}
	// Decode msc-s-InterfaceList
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 7 {
				_, n_mscsinterfacelist, rawVal_mscsinterfacelist, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding msc-s-InterfaceList: %w", err)
				}
				bsBytes_mscsinterfacelist, bsUnused_mscsinterfacelist, bsErr := ber.DecodeBitStringValue(rawVal_mscsinterfacelist)
				if bsErr != nil {
					return fmt.Errorf("decoding msc-s-InterfaceList: %w", bsErr)
				}
				tmp_mscsinterfacelist := runtime.BitString{Bytes: bsBytes_mscsinterfacelist, BitLength: len(bsBytes_mscsinterfacelist)*8 - bsUnused_mscsinterfacelist}
				v.MscSInterfaceList = &tmp_mscsinterfacelist
				offset += n_mscsinterfacelist
			}
		}
	}
	// Decode msc-s-EventList
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 8 {
				_, n_mscseventlist, rawVal_mscseventlist, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding msc-s-EventList: %w", err)
				}
				bsBytes_mscseventlist, bsUnused_mscseventlist, bsErr := ber.DecodeBitStringValue(rawVal_mscseventlist)
				if bsErr != nil {
					return fmt.Errorf("decoding msc-s-EventList: %w", bsErr)
				}
				tmp_mscseventlist := runtime.BitString{Bytes: bsBytes_mscseventlist, BitLength: len(bsBytes_mscseventlist)*8 - bsUnused_mscseventlist}
				v.MscSEventList = &tmp_mscseventlist
				offset += n_mscseventlist
			}
		}
	}
	// Decode mgw-TraceDepth
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 9 {
				_, n_mgwtracedepth, rawVal_mgwtracedepth, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding mgw-TraceDepth: %w", err)
				}
				decVal_mgwtracedepth, intErr := ber.DecodeIntegerValue(rawVal_mgwtracedepth)
				if intErr != nil {
					return fmt.Errorf("decoding mgw-TraceDepth: %w", intErr)
				}
				tmp_mgwtracedepth := TraceDepth4(decVal_mgwtracedepth)
				v.MgwTraceDepth = &tmp_mgwtracedepth
				offset += n_mgwtracedepth
			}
		}
	}
	// Decode mgw-InterfaceList
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 10 {
				_, n_mgwinterfacelist, rawVal_mgwinterfacelist, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding mgw-InterfaceList: %w", err)
				}
				bsBytes_mgwinterfacelist, bsUnused_mgwinterfacelist, bsErr := ber.DecodeBitStringValue(rawVal_mgwinterfacelist)
				if bsErr != nil {
					return fmt.Errorf("decoding mgw-InterfaceList: %w", bsErr)
				}
				tmp_mgwinterfacelist := runtime.BitString{Bytes: bsBytes_mgwinterfacelist, BitLength: len(bsBytes_mgwinterfacelist)*8 - bsUnused_mgwinterfacelist}
				v.MgwInterfaceList = &tmp_mgwinterfacelist
				offset += n_mgwinterfacelist
			}
		}
	}
	// Decode mgw-EventList
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 11 {
				_, n_mgweventlist, rawVal_mgweventlist, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding mgw-EventList: %w", err)
				}
				bsBytes_mgweventlist, bsUnused_mgweventlist, bsErr := ber.DecodeBitStringValue(rawVal_mgweventlist)
				if bsErr != nil {
					return fmt.Errorf("decoding mgw-EventList: %w", bsErr)
				}
				tmp_mgweventlist := runtime.BitString{Bytes: bsBytes_mgweventlist, BitLength: len(bsBytes_mgweventlist)*8 - bsUnused_mgweventlist}
				v.MgwEventList = &tmp_mgweventlist
				offset += n_mgweventlist
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "TracePropagationList4", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes ActivateTraceModeRes4 to BER format.
func (v *ActivateTraceModeRes4) MarshalBER() ([]byte, error) {
	var children []byte
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding extensionContainer: %w", err)
		}
		enc_extensioncontainer = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, true, enc_extensioncontainer)
		children = append(children, enc_extensioncontainer...)
	}
	if v.TraceSupportIndicator != nil {
		enc_tracesupportindicator := ber.EncodeNull()
		enc_tracesupportindicator = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, false, enc_tracesupportindicator)
		children = append(children, enc_tracesupportindicator...)
	}
	for i, ext := range v.ExtData_ {
		_, n, _, extErr := ber.DecodeTLV(ext)
		if extErr != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, extErr)
		}
		if n != len(ext) {
			return nil, fmt.Errorf("encoding extension %d: %w", i, ber.ErrExtraData)
		}
		children = append(children, ext...)
	}
	return ber.EncodeSequence(children), nil
}

// MarshalDER encodes ActivateTraceModeRes4 to DER format.
func (v *ActivateTraceModeRes4) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes ActivateTraceModeRes4 from BER/DER format.
func (v *ActivateTraceModeRes4) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding ActivateTraceModeRes4 SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "ActivateTraceModeRes4", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode extensionContainer
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
				_, n_extensioncontainer, rawVal_extensioncontainer, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding extensionContainer: %w", err)
				}
				reconstructed_extensioncontainer := ber.EncodeSequence(rawVal_extensioncontainer)
				var dec_extensioncontainer ExtensionContainer4
				if unmErr := dec_extensioncontainer.UnmarshalBER(reconstructed_extensioncontainer); unmErr != nil {
					return fmt.Errorf("decoding extensionContainer: %w", unmErr)
				}
				v.ExtensionContainer = &dec_extensioncontainer
				offset += n_extensioncontainer
			}
		}
	}
	// Decode traceSupportIndicator
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
				_, n_tracesupportindicator, rawVal_tracesupportindicator, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding traceSupportIndicator: %w", err)
				}
				_ = rawVal_tracesupportindicator
				v.TraceSupportIndicator = &struct{}{}
				offset += n_tracesupportindicator
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "ActivateTraceModeRes4", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes DeactivateTraceModeArg4 to BER format.
func (v *DeactivateTraceModeArg4) MarshalBER() ([]byte, error) {
	var children []byte
	if v.Imsi != nil {
		enc_imsi := ber.EncodeOctetString([]byte(*v.Imsi))
		enc_imsi = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, false, enc_imsi)
		children = append(children, enc_imsi...)
	}
	enc_tracereference := ber.EncodeOctetString([]byte(v.TraceReference))
	enc_tracereference = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, false, enc_tracereference)
	children = append(children, enc_tracereference...)
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding extensionContainer: %w", err)
		}
		enc_extensioncontainer = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, true, enc_extensioncontainer)
		children = append(children, enc_extensioncontainer...)
	}
	if v.TraceReference2 != nil {
		enc_tracereference2 := ber.EncodeOctetString([]byte(*v.TraceReference2))
		enc_tracereference2 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, false, enc_tracereference2)
		children = append(children, enc_tracereference2...)
	}
	for i, ext := range v.ExtData_ {
		_, n, _, extErr := ber.DecodeTLV(ext)
		if extErr != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, extErr)
		}
		if n != len(ext) {
			return nil, fmt.Errorf("encoding extension %d: %w", i, ber.ErrExtraData)
		}
		children = append(children, ext...)
	}
	return ber.EncodeSequence(children), nil
}

// MarshalDER encodes DeactivateTraceModeArg4 to DER format.
func (v *DeactivateTraceModeArg4) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes DeactivateTraceModeArg4 from BER/DER format.
func (v *DeactivateTraceModeArg4) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding DeactivateTraceModeArg4 SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "DeactivateTraceModeArg4", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode imsi
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
				_, n_imsi, rawVal_imsi, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding imsi: %w", err)
				}
				tmp_imsi := IMSI4(rawVal_imsi)
				v.Imsi = &tmp_imsi
				offset += n_imsi
			}
		}
	}
	// Decode traceReference
	if offset >= len(content) {
		return fmt.Errorf("missing required field traceReference")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 1 {
			return fmt.Errorf("expected tag [%s %d] for traceReference, got %s", "CONTEXT", 1, reqTag_)
		}
	}
	_, n_tracereference, rawVal_tracereference, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding traceReference: %w", err)
	}
	v.TraceReference = TraceReference4(rawVal_tracereference)
	offset += n_tracereference
	// Decode extensionContainer
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2 {
				_, n_extensioncontainer, rawVal_extensioncontainer, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding extensionContainer: %w", err)
				}
				reconstructed_extensioncontainer := ber.EncodeSequence(rawVal_extensioncontainer)
				var dec_extensioncontainer ExtensionContainer4
				if unmErr := dec_extensioncontainer.UnmarshalBER(reconstructed_extensioncontainer); unmErr != nil {
					return fmt.Errorf("decoding extensionContainer: %w", unmErr)
				}
				v.ExtensionContainer = &dec_extensioncontainer
				offset += n_extensioncontainer
			}
		}
	}
	// Decode traceReference2
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3 {
				_, n_tracereference2, rawVal_tracereference2, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding traceReference2: %w", err)
				}
				tmp_tracereference2 := TraceReference24(rawVal_tracereference2)
				v.TraceReference2 = &tmp_tracereference2
				offset += n_tracereference2
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "DeactivateTraceModeArg4", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes DeactivateTraceModeRes4 to BER format.
func (v *DeactivateTraceModeRes4) MarshalBER() ([]byte, error) {
	var children []byte
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding extensionContainer: %w", err)
		}
		enc_extensioncontainer = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, true, enc_extensioncontainer)
		children = append(children, enc_extensioncontainer...)
	}
	for i, ext := range v.ExtData_ {
		_, n, _, extErr := ber.DecodeTLV(ext)
		if extErr != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, extErr)
		}
		if n != len(ext) {
			return nil, fmt.Errorf("encoding extension %d: %w", i, ber.ErrExtraData)
		}
		children = append(children, ext...)
	}
	return ber.EncodeSequence(children), nil
}

// MarshalDER encodes DeactivateTraceModeRes4 to DER format.
func (v *DeactivateTraceModeRes4) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes DeactivateTraceModeRes4 from BER/DER format.
func (v *DeactivateTraceModeRes4) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding DeactivateTraceModeRes4 SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "DeactivateTraceModeRes4", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode extensionContainer
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
				_, n_extensioncontainer, rawVal_extensioncontainer, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding extensionContainer: %w", err)
				}
				reconstructed_extensioncontainer := ber.EncodeSequence(rawVal_extensioncontainer)
				var dec_extensioncontainer ExtensionContainer4
				if unmErr := dec_extensioncontainer.UnmarshalBER(reconstructed_extensioncontainer); unmErr != nil {
					return fmt.Errorf("decoding extensionContainer: %w", unmErr)
				}
				v.ExtensionContainer = &dec_extensioncontainer
				offset += n_extensioncontainer
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "DeactivateTraceModeRes4", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}
