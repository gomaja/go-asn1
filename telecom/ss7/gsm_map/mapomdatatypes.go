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

// ActivateTraceModeArg represents the ASN.1 type ActivateTraceModeArg (SEQUENCE).
type ActivateTraceModeArg struct {
	Imsi                  *IMSI               `asn1:"tag:0,context,implicit,optional" json:"Imsi,omitempty"`
	TraceReference        TraceReference      `asn1:"tag:1,context,implicit"`
	TraceType             TraceType           `asn1:"tag:2,context,implicit"`
	OmcId                 *AddressString      `asn1:"tag:3,context,implicit,optional" json:"OmcId,omitempty"`
	ExtensionContainer    *ExtensionContainer `asn1:"tag:4,context,implicit,optional" json:"ExtensionContainer,omitempty"`
	TraceReference2       *TraceReference2    `asn1:"tag:5,context,implicit,optional" json:"TraceReference2,omitempty"`
	TraceDepthList        *TraceDepthList     `asn1:"tag:6,context,implicit,optional" json:"TraceDepthList,omitempty"`
	TraceNETypeList       *TraceNETypeList    `asn1:"tag:7,context,implicit,optional" json:"TraceNETypeList,omitempty"`
	TraceInterfaceList    *TraceInterfaceList `asn1:"tag:8,context,implicit,optional" json:"TraceInterfaceList,omitempty"`
	TraceEventList        *TraceEventList     `asn1:"tag:9,context,implicit,optional" json:"TraceEventList,omitempty"`
	TraceCollectionEntity *GSNAddress         `asn1:"tag:10,context,implicit,optional" json:"TraceCollectionEntity,omitempty"`
	MdtConfiguration      *MDTConfiguration   `asn1:"tag:11,context,implicit,optional" json:"MdtConfiguration,omitempty"`
	ExtCount_             int64               `asn1:"-" json:"-"`
	ExtPresent_           []bool              `asn1:"-" json:"-"`
	ExtData_              [][]byte            `asn1:"-" json:"-"`
	berOriginal_          []byte              `asn1:"-" json:"-"`
	berSnapshot_          []byte              `asn1:"-" json:"-"`
}

// MDTConfiguration represents the ASN.1 type MDT-Configuration (SEQUENCE).
type MDTConfiguration struct {
	JobType                  JobType               `asn1:""`
	AreaScope                *AreaScope            `asn1:",optional" json:"AreaScope,omitempty"`
	ListOfMeasurements       *ListOfMeasurements   `asn1:",optional" json:"ListOfMeasurements,omitempty"`
	ReportingTrigger         *ReportingTrigger     `asn1:"tag:0,context,implicit,optional" json:"ReportingTrigger,omitempty"`
	ReportInterval           *ReportInterval       `asn1:",optional" json:"ReportInterval,omitempty"`
	ReportAmount             *ReportAmount         `asn1:"tag:1,context,implicit,optional" json:"ReportAmount,omitempty"`
	EventThresholdRSRP       *EventThresholdRSRP   `asn1:",optional" json:"EventThresholdRSRP,omitempty"`
	EventThresholdRSRQ       *EventThresholdRSRQ   `asn1:"tag:2,context,implicit,optional" json:"EventThresholdRSRQ,omitempty"`
	LoggingInterval          *LoggingInterval      `asn1:"tag:3,context,implicit,optional" json:"LoggingInterval,omitempty"`
	LoggingDuration          *LoggingDuration      `asn1:"tag:4,context,implicit,optional" json:"LoggingDuration,omitempty"`
	ExtensionContainer       *ExtensionContainer   `asn1:"tag:5,context,implicit,optional" json:"ExtensionContainer,omitempty"`
	MeasurementPeriodUMTS    *PeriodUMTS           `asn1:"tag:6,context,implicit,optional" json:"MeasurementPeriodUMTS,omitempty"`
	MeasurementPeriodLTE     *PeriodLTE            `asn1:"tag:7,context,implicit,optional" json:"MeasurementPeriodLTE,omitempty"`
	CollectionPeriodRRMUMTS  *PeriodUMTS           `asn1:"tag:8,context,implicit,optional" json:"CollectionPeriodRRMUMTS,omitempty"`
	CollectionPeriodRRMLTE   *PeriodLTE            `asn1:"tag:9,context,implicit,optional" json:"CollectionPeriodRRMLTE,omitempty"`
	PositioningMethod        *PositioningMethod    `asn1:"tag:10,context,implicit,optional" json:"PositioningMethod,omitempty"`
	MeasurementQuantity      *MeasurementQuantity  `asn1:"tag:11,context,implicit,optional" json:"MeasurementQuantity,omitempty"`
	EventThreshold1F         *EventThreshold1F     `asn1:"tag:12,context,implicit,optional" json:"EventThreshold1F,omitempty"`
	EventThreshold1I         *EventThreshold1I     `asn1:"tag:13,context,implicit,optional" json:"EventThreshold1I,omitempty"`
	MdtAllowedPLMNList       *MDTAllowedPLMNIdList `asn1:"tag:14,context,implicit,optional" json:"MdtAllowedPLMNList,omitempty"`
	MdtAllowedPLMNListIndef_ bool                  `asn1:"-" json:"-"`
	ExtCount_                int64                 `asn1:"-" json:"-"`
	ExtPresent_              []bool                `asn1:"-" json:"-"`
	ExtData_                 [][]byte              `asn1:"-" json:"-"`
	berOriginal_             []byte                `asn1:"-" json:"-"`
	berSnapshot_             []byte                `asn1:"-" json:"-"`
}

// MDTAllowedPLMNIdList represents the ASN.1 type MDT-Allowed-PLMNId-List (SEQUENCE_OF).
type MDTAllowedPLMNIdList struct {
	Values       []PLMNId `json:"Values"`
	berOriginal_ []byte   `json:"-"`
	berSnapshot_ []byte   `json:"-"`
}

// PeriodUMTS represents the ASN.1 ENUMERATED type PeriodUMTS.
type PeriodUMTS int64

const (
	PeriodUMTSD250ms   PeriodUMTS = 0
	PeriodUMTSD500ms   PeriodUMTS = 1
	PeriodUMTSD1000ms  PeriodUMTS = 2
	PeriodUMTSD2000ms  PeriodUMTS = 3
	PeriodUMTSD3000ms  PeriodUMTS = 4
	PeriodUMTSD4000ms  PeriodUMTS = 5
	PeriodUMTSD6000ms  PeriodUMTS = 6
	PeriodUMTSD8000ms  PeriodUMTS = 7
	PeriodUMTSD12000ms PeriodUMTS = 8
	PeriodUMTSD16000ms PeriodUMTS = 9
	PeriodUMTSD20000ms PeriodUMTS = 10
	PeriodUMTSD24000ms PeriodUMTS = 11
	PeriodUMTSD28000ms PeriodUMTS = 12
	PeriodUMTSD32000ms PeriodUMTS = 13
	PeriodUMTSD64000ms PeriodUMTS = 14
)

func (v PeriodUMTS) String() string {
	switch v {
	case PeriodUMTSD250ms:
		return "d250ms"
	case PeriodUMTSD500ms:
		return "d500ms"
	case PeriodUMTSD1000ms:
		return "d1000ms"
	case PeriodUMTSD2000ms:
		return "d2000ms"
	case PeriodUMTSD3000ms:
		return "d3000ms"
	case PeriodUMTSD4000ms:
		return "d4000ms"
	case PeriodUMTSD6000ms:
		return "d6000ms"
	case PeriodUMTSD8000ms:
		return "d8000ms"
	case PeriodUMTSD12000ms:
		return "d12000ms"
	case PeriodUMTSD16000ms:
		return "d16000ms"
	case PeriodUMTSD20000ms:
		return "d20000ms"
	case PeriodUMTSD24000ms:
		return "d24000ms"
	case PeriodUMTSD28000ms:
		return "d28000ms"
	case PeriodUMTSD32000ms:
		return "d32000ms"
	case PeriodUMTSD64000ms:
		return "d64000ms"
	default:
		return "unknown"
	}
}

// PeriodLTE represents the ASN.1 ENUMERATED type PeriodLTE.
type PeriodLTE int64

const (
	PeriodLTED1024ms  PeriodLTE = 0
	PeriodLTED1280ms  PeriodLTE = 1
	PeriodLTED2048ms  PeriodLTE = 2
	PeriodLTED2560ms  PeriodLTE = 3
	PeriodLTED5120ms  PeriodLTE = 4
	PeriodLTED10240ms PeriodLTE = 5
	PeriodLTED1min    PeriodLTE = 6
)

func (v PeriodLTE) String() string {
	switch v {
	case PeriodLTED1024ms:
		return "d1024ms"
	case PeriodLTED1280ms:
		return "d1280ms"
	case PeriodLTED2048ms:
		return "d2048ms"
	case PeriodLTED2560ms:
		return "d2560ms"
	case PeriodLTED5120ms:
		return "d5120ms"
	case PeriodLTED10240ms:
		return "d10240ms"
	case PeriodLTED1min:
		return "d1min"
	default:
		return "unknown"
	}
}

// PositioningMethod represents the ASN.1 type PositioningMethod (OCTET_STRING).
type PositioningMethod = []byte

// MeasurementQuantity represents the ASN.1 type MeasurementQuantity (OCTET_STRING).
type MeasurementQuantity = []byte

// EventThreshold1F represents the ASN.1 type EventThreshold1F (INTEGER).
type EventThreshold1F = int64

// EventThreshold1I represents the ASN.1 type EventThreshold1I (INTEGER).
type EventThreshold1I = int64

// JobType represents the ASN.1 ENUMERATED type JobType.
type JobType int64

const (
	JobTypeImmediateMDTOnly     JobType = 0
	JobTypeLoggedMDTOnly        JobType = 1
	JobTypeTraceOnly            JobType = 2
	JobTypeImmediateMDTAndTrace JobType = 3
)

func (v JobType) String() string {
	switch v {
	case JobTypeImmediateMDTOnly:
		return "immediate-MDT-only"
	case JobTypeLoggedMDTOnly:
		return "logged-MDT-only"
	case JobTypeTraceOnly:
		return "trace-only"
	case JobTypeImmediateMDTAndTrace:
		return "immediate-MDT-and-trace"
	default:
		return "unknown"
	}
}

// AreaScope represents the ASN.1 type AreaScope (SEQUENCE).
type AreaScope struct {
	CgiList                  *CGIList            `asn1:"tag:0,context,implicit,optional" json:"CgiList,omitempty"`
	CgiListIndef_            bool                `asn1:"-" json:"-"`
	EUtranCgiList            *EUTRANCGIList      `asn1:"tag:1,context,implicit,optional" json:"EUtranCgiList,omitempty"`
	EUtranCgiListIndef_      bool                `asn1:"-" json:"-"`
	RoutingAreaIdList        *RoutingAreaIdList  `asn1:"tag:2,context,implicit,optional" json:"RoutingAreaIdList,omitempty"`
	RoutingAreaIdListIndef_  bool                `asn1:"-" json:"-"`
	LocationAreaIdList       *LocationAreaIdList `asn1:"tag:3,context,implicit,optional" json:"LocationAreaIdList,omitempty"`
	LocationAreaIdListIndef_ bool                `asn1:"-" json:"-"`
	TrackingAreaIdList       *TrackingAreaIdList `asn1:"tag:4,context,implicit,optional" json:"TrackingAreaIdList,omitempty"`
	TrackingAreaIdListIndef_ bool                `asn1:"-" json:"-"`
	ExtensionContainer       *ExtensionContainer `asn1:"tag:5,context,implicit,optional" json:"ExtensionContainer,omitempty"`
	ExtCount_                int64               `asn1:"-" json:"-"`
	ExtPresent_              []bool              `asn1:"-" json:"-"`
	ExtData_                 [][]byte            `asn1:"-" json:"-"`
	berOriginal_             []byte              `asn1:"-" json:"-"`
	berSnapshot_             []byte              `asn1:"-" json:"-"`
}

// CGIList represents the ASN.1 type CGI-List (SEQUENCE_OF).
type CGIList struct {
	Values       []GlobalCellId `json:"Values"`
	berOriginal_ []byte         `json:"-"`
	berSnapshot_ []byte         `json:"-"`
}

// EUTRANCGIList represents the ASN.1 type E-UTRAN-CGI-List (SEQUENCE_OF).
type EUTRANCGIList struct {
	Values       []EUTRANCGI `json:"Values"`
	berOriginal_ []byte      `json:"-"`
	berSnapshot_ []byte      `json:"-"`
}

// RoutingAreaIdList represents the ASN.1 type RoutingAreaId-List (SEQUENCE_OF).
type RoutingAreaIdList struct {
	Values       []RAIdentity `json:"Values"`
	berOriginal_ []byte       `json:"-"`
	berSnapshot_ []byte       `json:"-"`
}

// LocationAreaIdList represents the ASN.1 type LocationAreaId-List (SEQUENCE_OF).
type LocationAreaIdList struct {
	Values       []LAIFixedLength `json:"Values"`
	berOriginal_ []byte           `json:"-"`
	berSnapshot_ []byte           `json:"-"`
}

// TrackingAreaIdList represents the ASN.1 type TrackingAreaId-List (SEQUENCE_OF).
type TrackingAreaIdList struct {
	Values       []TAId `json:"Values"`
	berOriginal_ []byte `json:"-"`
	berSnapshot_ []byte `json:"-"`
}

// ListOfMeasurements represents the ASN.1 type ListOfMeasurements (OCTET_STRING).
type ListOfMeasurements = []byte

// ReportingTrigger represents the ASN.1 type ReportingTrigger (OCTET_STRING).
type ReportingTrigger = []byte

// ReportInterval represents the ASN.1 ENUMERATED type ReportInterval.
type ReportInterval int64

const (
	ReportIntervalUmts250ms   ReportInterval = 0
	ReportIntervalUmts500ms   ReportInterval = 1
	ReportIntervalUmts1000ms  ReportInterval = 2
	ReportIntervalUmts2000ms  ReportInterval = 3
	ReportIntervalUmts3000ms  ReportInterval = 4
	ReportIntervalUmts4000ms  ReportInterval = 5
	ReportIntervalUmts6000ms  ReportInterval = 6
	ReportIntervalUmts8000ms  ReportInterval = 7
	ReportIntervalUmts12000ms ReportInterval = 8
	ReportIntervalUmts16000ms ReportInterval = 9
	ReportIntervalUmts20000ms ReportInterval = 10
	ReportIntervalUmts24000ms ReportInterval = 11
	ReportIntervalUmts28000ms ReportInterval = 12
	ReportIntervalUmts32000ms ReportInterval = 13
	ReportIntervalUmts64000ms ReportInterval = 14
	ReportIntervalLte120ms    ReportInterval = 15
	ReportIntervalLte240ms    ReportInterval = 16
	ReportIntervalLte480ms    ReportInterval = 17
	ReportIntervalLte640ms    ReportInterval = 18
	ReportIntervalLte1024ms   ReportInterval = 19
	ReportIntervalLte2048ms   ReportInterval = 20
	ReportIntervalLte5120ms   ReportInterval = 21
	ReportIntervalLte10240ms  ReportInterval = 22
	ReportIntervalLte1min     ReportInterval = 23
	ReportIntervalLte6min     ReportInterval = 24
	ReportIntervalLte12min    ReportInterval = 25
	ReportIntervalLte30min    ReportInterval = 26
	ReportIntervalLte60min    ReportInterval = 27
)

func (v ReportInterval) String() string {
	switch v {
	case ReportIntervalUmts250ms:
		return "umts250ms"
	case ReportIntervalUmts500ms:
		return "umts500ms"
	case ReportIntervalUmts1000ms:
		return "umts1000ms"
	case ReportIntervalUmts2000ms:
		return "umts2000ms"
	case ReportIntervalUmts3000ms:
		return "umts3000ms"
	case ReportIntervalUmts4000ms:
		return "umts4000ms"
	case ReportIntervalUmts6000ms:
		return "umts6000ms"
	case ReportIntervalUmts8000ms:
		return "umts8000ms"
	case ReportIntervalUmts12000ms:
		return "umts12000ms"
	case ReportIntervalUmts16000ms:
		return "umts16000ms"
	case ReportIntervalUmts20000ms:
		return "umts20000ms"
	case ReportIntervalUmts24000ms:
		return "umts24000ms"
	case ReportIntervalUmts28000ms:
		return "umts28000ms"
	case ReportIntervalUmts32000ms:
		return "umts32000ms"
	case ReportIntervalUmts64000ms:
		return "umts64000ms"
	case ReportIntervalLte120ms:
		return "lte120ms"
	case ReportIntervalLte240ms:
		return "lte240ms"
	case ReportIntervalLte480ms:
		return "lte480ms"
	case ReportIntervalLte640ms:
		return "lte640ms"
	case ReportIntervalLte1024ms:
		return "lte1024ms"
	case ReportIntervalLte2048ms:
		return "lte2048ms"
	case ReportIntervalLte5120ms:
		return "lte5120ms"
	case ReportIntervalLte10240ms:
		return "lte10240ms"
	case ReportIntervalLte1min:
		return "lte1min"
	case ReportIntervalLte6min:
		return "lte6min"
	case ReportIntervalLte12min:
		return "lte12min"
	case ReportIntervalLte30min:
		return "lte30min"
	case ReportIntervalLte60min:
		return "lte60min"
	default:
		return "unknown"
	}
}

// ReportAmount represents the ASN.1 ENUMERATED type ReportAmount.
type ReportAmount int64

const (
	ReportAmountD1       ReportAmount = 0
	ReportAmountD2       ReportAmount = 1
	ReportAmountD4       ReportAmount = 2
	ReportAmountD8       ReportAmount = 3
	ReportAmountD16      ReportAmount = 4
	ReportAmountD32      ReportAmount = 5
	ReportAmountD64      ReportAmount = 6
	ReportAmountInfinity ReportAmount = 7
)

func (v ReportAmount) String() string {
	switch v {
	case ReportAmountD1:
		return "d1"
	case ReportAmountD2:
		return "d2"
	case ReportAmountD4:
		return "d4"
	case ReportAmountD8:
		return "d8"
	case ReportAmountD16:
		return "d16"
	case ReportAmountD32:
		return "d32"
	case ReportAmountD64:
		return "d64"
	case ReportAmountInfinity:
		return "infinity"
	default:
		return "unknown"
	}
}

// EventThresholdRSRP represents the ASN.1 type EventThresholdRSRP (INTEGER).
type EventThresholdRSRP = int64

// EventThresholdRSRQ represents the ASN.1 type EventThresholdRSRQ (INTEGER).
type EventThresholdRSRQ = int64

// LoggingInterval represents the ASN.1 ENUMERATED type LoggingInterval.
type LoggingInterval int64

const (
	LoggingIntervalD1dot28  LoggingInterval = 0
	LoggingIntervalD2dot56  LoggingInterval = 1
	LoggingIntervalD5dot12  LoggingInterval = 2
	LoggingIntervalD10dot24 LoggingInterval = 3
	LoggingIntervalD20dot48 LoggingInterval = 4
	LoggingIntervalD30dot72 LoggingInterval = 5
	LoggingIntervalD40dot96 LoggingInterval = 6
	LoggingIntervalD61dot44 LoggingInterval = 7
)

func (v LoggingInterval) String() string {
	switch v {
	case LoggingIntervalD1dot28:
		return "d1dot28"
	case LoggingIntervalD2dot56:
		return "d2dot56"
	case LoggingIntervalD5dot12:
		return "d5dot12"
	case LoggingIntervalD10dot24:
		return "d10dot24"
	case LoggingIntervalD20dot48:
		return "d20dot48"
	case LoggingIntervalD30dot72:
		return "d30dot72"
	case LoggingIntervalD40dot96:
		return "d40dot96"
	case LoggingIntervalD61dot44:
		return "d61dot44"
	default:
		return "unknown"
	}
}

// LoggingDuration represents the ASN.1 ENUMERATED type LoggingDuration.
type LoggingDuration int64

const (
	LoggingDurationD600sec  LoggingDuration = 0
	LoggingDurationD1200sec LoggingDuration = 1
	LoggingDurationD2400sec LoggingDuration = 2
	LoggingDurationD3600sec LoggingDuration = 3
	LoggingDurationD5400sec LoggingDuration = 4
	LoggingDurationD7200sec LoggingDuration = 5
)

func (v LoggingDuration) String() string {
	switch v {
	case LoggingDurationD600sec:
		return "d600sec"
	case LoggingDurationD1200sec:
		return "d1200sec"
	case LoggingDurationD2400sec:
		return "d2400sec"
	case LoggingDurationD3600sec:
		return "d3600sec"
	case LoggingDurationD5400sec:
		return "d5400sec"
	case LoggingDurationD7200sec:
		return "d7200sec"
	default:
		return "unknown"
	}
}

// TraceReference represents the ASN.1 type TraceReference (OCTET_STRING).
type TraceReference = []byte

// TraceReference2 represents the ASN.1 type TraceReference2 (OCTET_STRING).
type TraceReference2 = []byte

// TraceRecordingSessionReference represents the ASN.1 type TraceRecordingSessionReference (OCTET_STRING).
type TraceRecordingSessionReference = []byte

// TraceType represents the ASN.1 type TraceType (INTEGER).
type TraceType = int64

// TraceDepthList represents the ASN.1 type TraceDepthList (SEQUENCE).
type TraceDepthList struct {
	MscSTraceDepth          *TraceDepth          `asn1:"tag:0,context,implicit,optional" json:"MscSTraceDepth,omitempty"`
	MgwTraceDepth           *TraceDepth          `asn1:"tag:1,context,implicit,optional" json:"MgwTraceDepth,omitempty"`
	SgsnTraceDepth          *TraceDepth          `asn1:"tag:2,context,implicit,optional" json:"SgsnTraceDepth,omitempty"`
	GgsnTraceDepth          *TraceDepth          `asn1:"tag:3,context,implicit,optional" json:"GgsnTraceDepth,omitempty"`
	RncTraceDepth           *TraceDepth          `asn1:"tag:4,context,implicit,optional" json:"RncTraceDepth,omitempty"`
	BmscTraceDepth          *TraceDepth          `asn1:"tag:5,context,implicit,optional" json:"BmscTraceDepth,omitempty"`
	MmeTraceDepth           *TraceDepth          `asn1:"tag:6,context,implicit,optional" json:"MmeTraceDepth,omitempty"`
	SgwTraceDepth           *TraceDepth          `asn1:"tag:7,context,implicit,optional" json:"SgwTraceDepth,omitempty"`
	PgwTraceDepth           *TraceDepth          `asn1:"tag:8,context,implicit,optional" json:"PgwTraceDepth,omitempty"`
	ENBTraceDepth           *TraceDepth          `asn1:"tag:9,context,implicit,optional" json:"ENBTraceDepth,omitempty"`
	MscSTraceDepthExtension *TraceDepthExtension `asn1:"tag:10,context,implicit,optional" json:"MscSTraceDepthExtension,omitempty"`
	MgwTraceDepthExtension  *TraceDepthExtension `asn1:"tag:11,context,implicit,optional" json:"MgwTraceDepthExtension,omitempty"`
	SgsnTraceDepthExtension *TraceDepthExtension `asn1:"tag:12,context,implicit,optional" json:"SgsnTraceDepthExtension,omitempty"`
	GgsnTraceDepthExtension *TraceDepthExtension `asn1:"tag:13,context,implicit,optional" json:"GgsnTraceDepthExtension,omitempty"`
	RncTraceDepthExtension  *TraceDepthExtension `asn1:"tag:14,context,implicit,optional" json:"RncTraceDepthExtension,omitempty"`
	BmscTraceDepthExtension *TraceDepthExtension `asn1:"tag:15,context,implicit,optional" json:"BmscTraceDepthExtension,omitempty"`
	MmeTraceDepthExtension  *TraceDepthExtension `asn1:"tag:16,context,implicit,optional" json:"MmeTraceDepthExtension,omitempty"`
	SgwTraceDepthExtension  *TraceDepthExtension `asn1:"tag:17,context,implicit,optional" json:"SgwTraceDepthExtension,omitempty"`
	PgwTraceDepthExtension  *TraceDepthExtension `asn1:"tag:18,context,implicit,optional" json:"PgwTraceDepthExtension,omitempty"`
	ENBTraceDepthExtension  *TraceDepthExtension `asn1:"tag:19,context,implicit,optional" json:"ENBTraceDepthExtension,omitempty"`
	ExtCount_               int64                `asn1:"-" json:"-"`
	ExtPresent_             []bool               `asn1:"-" json:"-"`
	ExtData_                [][]byte             `asn1:"-" json:"-"`
	berOriginal_            []byte               `asn1:"-" json:"-"`
	berSnapshot_            []byte               `asn1:"-" json:"-"`
}

// TraceDepth represents the ASN.1 ENUMERATED type TraceDepth.
type TraceDepth int64

const (
	TraceDepthMinimum TraceDepth = 0
	TraceDepthMedium  TraceDepth = 1
	TraceDepthMaximum TraceDepth = 2
)

func (v TraceDepth) String() string {
	switch v {
	case TraceDepthMinimum:
		return "minimum"
	case TraceDepthMedium:
		return "medium"
	case TraceDepthMaximum:
		return "maximum"
	default:
		return "unknown"
	}
}

// TraceDepthExtension represents the ASN.1 ENUMERATED type TraceDepthExtension.
type TraceDepthExtension int64

const (
	TraceDepthExtensionMinimumWithoutVendorSpecificExtension TraceDepthExtension = 0
	TraceDepthExtensionMediumWithoutVendorSpecificExtension  TraceDepthExtension = 1
	TraceDepthExtensionMaximumWithoutVendorSpecificExtension TraceDepthExtension = 2
)

func (v TraceDepthExtension) String() string {
	switch v {
	case TraceDepthExtensionMinimumWithoutVendorSpecificExtension:
		return "minimumWithoutVendorSpecificExtension"
	case TraceDepthExtensionMediumWithoutVendorSpecificExtension:
		return "mediumWithoutVendorSpecificExtension"
	case TraceDepthExtensionMaximumWithoutVendorSpecificExtension:
		return "maximumWithoutVendorSpecificExtension"
	default:
		return "unknown"
	}
}

// TraceNETypeList represents the ASN.1 type TraceNE-TypeList (BIT_STRING).
type TraceNETypeList = runtime.BitString

// TraceInterfaceList represents the ASN.1 type TraceInterfaceList (SEQUENCE).
type TraceInterfaceList struct {
	MscSList     *MSCSInterfaceList `asn1:"tag:0,context,implicit,optional" json:"MscSList,omitempty"`
	MgwList      *MGWInterfaceList  `asn1:"tag:1,context,implicit,optional" json:"MgwList,omitempty"`
	SgsnList     *SGSNInterfaceList `asn1:"tag:2,context,implicit,optional" json:"SgsnList,omitempty"`
	GgsnList     *GGSNInterfaceList `asn1:"tag:3,context,implicit,optional" json:"GgsnList,omitempty"`
	RncList      *RNCInterfaceList  `asn1:"tag:4,context,implicit,optional" json:"RncList,omitempty"`
	BmscList     *BMSCInterfaceList `asn1:"tag:5,context,implicit,optional" json:"BmscList,omitempty"`
	MmeList      *MMEInterfaceList  `asn1:"tag:6,context,implicit,optional" json:"MmeList,omitempty"`
	SgwList      *SGWInterfaceList  `asn1:"tag:7,context,implicit,optional" json:"SgwList,omitempty"`
	PgwList      *PGWInterfaceList  `asn1:"tag:8,context,implicit,optional" json:"PgwList,omitempty"`
	ENBList      *ENBInterfaceList  `asn1:"tag:9,context,implicit,optional" json:"ENBList,omitempty"`
	ExtCount_    int64              `asn1:"-" json:"-"`
	ExtPresent_  []bool             `asn1:"-" json:"-"`
	ExtData_     [][]byte           `asn1:"-" json:"-"`
	berOriginal_ []byte             `asn1:"-" json:"-"`
	berSnapshot_ []byte             `asn1:"-" json:"-"`
}

// MSCSInterfaceList represents the ASN.1 type MSC-S-InterfaceList (BIT_STRING).
type MSCSInterfaceList = runtime.BitString

// MGWInterfaceList represents the ASN.1 type MGW-InterfaceList (BIT_STRING).
type MGWInterfaceList = runtime.BitString

// SGSNInterfaceList represents the ASN.1 type SGSN-InterfaceList (BIT_STRING).
type SGSNInterfaceList = runtime.BitString

// GGSNInterfaceList represents the ASN.1 type GGSN-InterfaceList (BIT_STRING).
type GGSNInterfaceList = runtime.BitString

// RNCInterfaceList represents the ASN.1 type RNC-InterfaceList (BIT_STRING).
type RNCInterfaceList = runtime.BitString

// BMSCInterfaceList represents the ASN.1 type BMSC-InterfaceList (BIT_STRING).
type BMSCInterfaceList = runtime.BitString

// MMEInterfaceList represents the ASN.1 type MME-InterfaceList (BIT_STRING).
type MMEInterfaceList = runtime.BitString

// SGWInterfaceList represents the ASN.1 type SGW-InterfaceList (BIT_STRING).
type SGWInterfaceList = runtime.BitString

// PGWInterfaceList represents the ASN.1 type PGW-InterfaceList (BIT_STRING).
type PGWInterfaceList = runtime.BitString

// ENBInterfaceList represents the ASN.1 type ENB-InterfaceList (BIT_STRING).
type ENBInterfaceList = runtime.BitString

// TraceEventList represents the ASN.1 type TraceEventList (SEQUENCE).
type TraceEventList struct {
	MscSList     *MSCSEventList `asn1:"tag:0,context,implicit,optional" json:"MscSList,omitempty"`
	MgwList      *MGWEventList  `asn1:"tag:1,context,implicit,optional" json:"MgwList,omitempty"`
	SgsnList     *SGSNEventList `asn1:"tag:2,context,implicit,optional" json:"SgsnList,omitempty"`
	GgsnList     *GGSNEventList `asn1:"tag:3,context,implicit,optional" json:"GgsnList,omitempty"`
	BmscList     *BMSCEventList `asn1:"tag:4,context,implicit,optional" json:"BmscList,omitempty"`
	MmeList      *MMEEventList  `asn1:"tag:5,context,implicit,optional" json:"MmeList,omitempty"`
	SgwList      *SGWEventList  `asn1:"tag:6,context,implicit,optional" json:"SgwList,omitempty"`
	PgwList      *PGWEventList  `asn1:"tag:7,context,implicit,optional" json:"PgwList,omitempty"`
	ExtCount_    int64          `asn1:"-" json:"-"`
	ExtPresent_  []bool         `asn1:"-" json:"-"`
	ExtData_     [][]byte       `asn1:"-" json:"-"`
	berOriginal_ []byte         `asn1:"-" json:"-"`
	berSnapshot_ []byte         `asn1:"-" json:"-"`
}

// MSCSEventList represents the ASN.1 type MSC-S-EventList (BIT_STRING).
type MSCSEventList = runtime.BitString

// MGWEventList represents the ASN.1 type MGW-EventList (BIT_STRING).
type MGWEventList = runtime.BitString

// SGSNEventList represents the ASN.1 type SGSN-EventList (BIT_STRING).
type SGSNEventList = runtime.BitString

// GGSNEventList represents the ASN.1 type GGSN-EventList (BIT_STRING).
type GGSNEventList = runtime.BitString

// BMSCEventList represents the ASN.1 type BMSC-EventList (BIT_STRING).
type BMSCEventList = runtime.BitString

// MMEEventList represents the ASN.1 type MME-EventList (BIT_STRING).
type MMEEventList = runtime.BitString

// SGWEventList represents the ASN.1 type SGW-EventList (BIT_STRING).
type SGWEventList = runtime.BitString

// PGWEventList represents the ASN.1 type PGW-EventList (BIT_STRING).
type PGWEventList = runtime.BitString

// TracePropagationList represents the ASN.1 type TracePropagationList (SEQUENCE).
type TracePropagationList struct {
	TraceReference                 *TraceReference                 `asn1:"tag:0,context,implicit,optional" json:"TraceReference,omitempty"`
	TraceType                      *TraceType                      `asn1:"tag:1,context,implicit,optional" json:"TraceType,omitempty"`
	TraceReference2                *TraceReference2                `asn1:"tag:2,context,implicit,optional" json:"TraceReference2,omitempty"`
	TraceRecordingSessionReference *TraceRecordingSessionReference `asn1:"tag:3,context,implicit,optional" json:"TraceRecordingSessionReference,omitempty"`
	RncTraceDepth                  *TraceDepth                     `asn1:"tag:4,context,implicit,optional" json:"RncTraceDepth,omitempty"`
	RncInterfaceList               *RNCInterfaceList               `asn1:"tag:5,context,implicit,optional" json:"RncInterfaceList,omitempty"`
	MscSTraceDepth                 *TraceDepth                     `asn1:"tag:6,context,implicit,optional" json:"MscSTraceDepth,omitempty"`
	MscSInterfaceList              *MSCSInterfaceList              `asn1:"tag:7,context,implicit,optional" json:"MscSInterfaceList,omitempty"`
	MscSEventList                  *MSCSEventList                  `asn1:"tag:8,context,implicit,optional" json:"MscSEventList,omitempty"`
	MgwTraceDepth                  *TraceDepth                     `asn1:"tag:9,context,implicit,optional" json:"MgwTraceDepth,omitempty"`
	MgwInterfaceList               *MGWInterfaceList               `asn1:"tag:10,context,implicit,optional" json:"MgwInterfaceList,omitempty"`
	MgwEventList                   *MGWEventList                   `asn1:"tag:11,context,implicit,optional" json:"MgwEventList,omitempty"`
	RncTraceDepthExtension         *TraceDepthExtension            `asn1:"tag:12,context,implicit,optional" json:"RncTraceDepthExtension,omitempty"`
	MscSTraceDepthExtension        *TraceDepthExtension            `asn1:"tag:13,context,implicit,optional" json:"MscSTraceDepthExtension,omitempty"`
	MgwTraceDepthExtension         *TraceDepthExtension            `asn1:"tag:14,context,implicit,optional" json:"MgwTraceDepthExtension,omitempty"`
	ExtCount_                      int64                           `asn1:"-" json:"-"`
	ExtPresent_                    []bool                          `asn1:"-" json:"-"`
	ExtData_                       [][]byte                        `asn1:"-" json:"-"`
	berOriginal_                   []byte                          `asn1:"-" json:"-"`
	berSnapshot_                   []byte                          `asn1:"-" json:"-"`
}

// ActivateTraceModeRes represents the ASN.1 type ActivateTraceModeRes (SEQUENCE).
type ActivateTraceModeRes struct {
	ExtensionContainer    *ExtensionContainer `asn1:"tag:0,context,implicit,optional" json:"ExtensionContainer,omitempty"`
	TraceSupportIndicator *struct{}           `asn1:"tag:1,context,implicit,optional" json:"TraceSupportIndicator,omitempty"`
	ExtCount_             int64               `asn1:"-" json:"-"`
	ExtPresent_           []bool              `asn1:"-" json:"-"`
	ExtData_              [][]byte            `asn1:"-" json:"-"`
	berOriginal_          []byte              `asn1:"-" json:"-"`
	berSnapshot_          []byte              `asn1:"-" json:"-"`
}

// DeactivateTraceModeArg represents the ASN.1 type DeactivateTraceModeArg (SEQUENCE).
type DeactivateTraceModeArg struct {
	Imsi               *IMSI               `asn1:"tag:0,context,implicit,optional" json:"Imsi,omitempty"`
	TraceReference     TraceReference      `asn1:"tag:1,context,implicit"`
	ExtensionContainer *ExtensionContainer `asn1:"tag:2,context,implicit,optional" json:"ExtensionContainer,omitempty"`
	TraceReference2    *TraceReference2    `asn1:"tag:3,context,implicit,optional" json:"TraceReference2,omitempty"`
	ExtCount_          int64               `asn1:"-" json:"-"`
	ExtPresent_        []bool              `asn1:"-" json:"-"`
	ExtData_           [][]byte            `asn1:"-" json:"-"`
	berOriginal_       []byte              `asn1:"-" json:"-"`
	berSnapshot_       []byte              `asn1:"-" json:"-"`
}

// DeactivateTraceModeRes represents the ASN.1 type DeactivateTraceModeRes (SEQUENCE).
type DeactivateTraceModeRes struct {
	ExtensionContainer *ExtensionContainer `asn1:"tag:0,context,implicit,optional" json:"ExtensionContainer,omitempty"`
	ExtCount_          int64               `asn1:"-" json:"-"`
	ExtPresent_        []bool              `asn1:"-" json:"-"`
	ExtData_           [][]byte            `asn1:"-" json:"-"`
	berOriginal_       []byte              `asn1:"-" json:"-"`
	berSnapshot_       []byte              `asn1:"-" json:"-"`
}

// MarshalBER encodes ActivateTraceModeArg to BER format.
func (v *ActivateTraceModeArg) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: ActivateTraceModeArg receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *ActivateTraceModeArg) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if v.Imsi != nil {
		if len(*v.Imsi) < 3 || len(*v.Imsi) > 8 {
			if constraintErr := ber.CheckEncodedLength(opts, "imsi", "SIZE (3..8)", len(*v.Imsi)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_imsi, encodeErr_enc_imsi := ber.EncodeOctetString([]byte(*v.Imsi))
		if encodeErr_enc_imsi != nil {
			return nil, fmt.Errorf("encoding imsi: %w", encodeErr_enc_imsi)
		}
		retagged_enc_imsi, tagErr_enc_imsi := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_imsi)
		if tagErr_enc_imsi != nil {
			return nil, fmt.Errorf("encoding imsi: %w", tagErr_enc_imsi)
		}
		enc_imsi = retagged_enc_imsi
		children = append(children, enc_imsi...)
	}
	if len(v.TraceReference) < 1 || len(v.TraceReference) > 2 {
		if constraintErr := ber.CheckEncodedLength(opts, "traceReference", "SIZE (1..2)", len(v.TraceReference)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_tracereference, encodeErr_enc_tracereference := ber.EncodeOctetString([]byte(v.TraceReference))
	if encodeErr_enc_tracereference != nil {
		return nil, fmt.Errorf("encoding traceReference: %w", encodeErr_enc_tracereference)
	}
	retagged_enc_tracereference, tagErr_enc_tracereference := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_tracereference)
	if tagErr_enc_tracereference != nil {
		return nil, fmt.Errorf("encoding traceReference: %w", tagErr_enc_tracereference)
	}
	enc_tracereference = retagged_enc_tracereference
	children = append(children, enc_tracereference...)
	if !(int64(v.TraceType) >= 0 && int64(v.TraceType) <= 255) {
		if constraintErr := ber.CheckEncodedValue(opts, "traceType", "(0..255)", fmt.Sprint(int64(v.TraceType))); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_tracetype := ber.EncodeInteger(int64(v.TraceType))
	retagged_enc_tracetype, tagErr_enc_tracetype := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_tracetype)
	if tagErr_enc_tracetype != nil {
		return nil, fmt.Errorf("encoding traceType: %w", tagErr_enc_tracetype)
	}
	enc_tracetype = retagged_enc_tracetype
	children = append(children, enc_tracetype...)
	if v.OmcId != nil {
		if len(*v.OmcId) < 1 || len(*v.OmcId) > 20 {
			if constraintErr := ber.CheckEncodedLength(opts, "omc-Id", "SIZE (1..20)", len(*v.OmcId)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_omcid, encodeErr_enc_omcid := ber.EncodeOctetString([]byte(*v.OmcId))
		if encodeErr_enc_omcid != nil {
			return nil, fmt.Errorf("encoding omc-Id: %w", encodeErr_enc_omcid)
		}
		retagged_enc_omcid, tagErr_enc_omcid := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, enc_omcid)
		if tagErr_enc_omcid != nil {
			return nil, fmt.Errorf("encoding omc-Id: %w", tagErr_enc_omcid)
		}
		enc_omcid = retagged_enc_omcid
		children = append(children, enc_omcid...)
	}
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalBER(ber.ChildEncodeOptions(opts, "extensionContainer")...)
		if err != nil {
			return nil, fmt.Errorf("encoding extensionContainer: %w", err)
		}
		retagged_enc_extensioncontainer, tagErr_enc_extensioncontainer := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, enc_extensioncontainer)
		if tagErr_enc_extensioncontainer != nil {
			return nil, fmt.Errorf("encoding extensionContainer: %w", tagErr_enc_extensioncontainer)
		}
		enc_extensioncontainer = retagged_enc_extensioncontainer
		children = append(children, enc_extensioncontainer...)
	}
	if v.TraceReference2 != nil {
		if len(*v.TraceReference2) < 3 || len(*v.TraceReference2) > 3 {
			if constraintErr := ber.CheckEncodedLength(opts, "traceReference2", "SIZE (3)", len(*v.TraceReference2)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_tracereference2, encodeErr_enc_tracereference2 := ber.EncodeOctetString([]byte(*v.TraceReference2))
		if encodeErr_enc_tracereference2 != nil {
			return nil, fmt.Errorf("encoding traceReference2: %w", encodeErr_enc_tracereference2)
		}
		retagged_enc_tracereference2, tagErr_enc_tracereference2 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 5, enc_tracereference2)
		if tagErr_enc_tracereference2 != nil {
			return nil, fmt.Errorf("encoding traceReference2: %w", tagErr_enc_tracereference2)
		}
		enc_tracereference2 = retagged_enc_tracereference2
		children = append(children, enc_tracereference2...)
	}
	if v.TraceDepthList != nil {
		enc_tracedepthlist, err := v.TraceDepthList.MarshalBER(ber.ChildEncodeOptions(opts, "traceDepthList")...)
		if err != nil {
			return nil, fmt.Errorf("encoding traceDepthList: %w", err)
		}
		retagged_enc_tracedepthlist, tagErr_enc_tracedepthlist := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 6, enc_tracedepthlist)
		if tagErr_enc_tracedepthlist != nil {
			return nil, fmt.Errorf("encoding traceDepthList: %w", tagErr_enc_tracedepthlist)
		}
		enc_tracedepthlist = retagged_enc_tracedepthlist
		children = append(children, enc_tracedepthlist...)
	}
	if v.TraceNETypeList != nil {
		if (*v.TraceNETypeList).BitLength < 6 || (*v.TraceNETypeList).BitLength > 16 {
			if constraintErr := ber.CheckEncodedLength(opts, "traceNE-TypeList", "SIZE (6..16)", (*v.TraceNETypeList).BitLength); constraintErr != nil {
				return nil, constraintErr
			}
		}
		if bitStringErr := ber.ValidateBitStringLength(v.TraceNETypeList.Bytes, v.TraceNETypeList.BitLength); bitStringErr != nil {
			return nil, fmt.Errorf("encoding %s: %w", "traceNE-TypeList", bitStringErr)
		}
		// arithmetic pattern BER_BITSTRING_FIELD: 0 <= bit length before modulo and subtraction; gen/codegen.go:526
		if v.TraceNETypeList.BitLength < 0 {
			return nil, fmt.Errorf("negative bit string length")
		}
		enc_tracenetypelist, encodeErr_enc_tracenetypelist := ber.EncodeBitString(v.TraceNETypeList.Bytes, (8-(v.TraceNETypeList.BitLength%8))%8)
		if encodeErr_enc_tracenetypelist != nil {
			return nil, fmt.Errorf("encoding traceNE-TypeList: %w", encodeErr_enc_tracenetypelist)
		}
		retagged_enc_tracenetypelist, tagErr_enc_tracenetypelist := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 7, enc_tracenetypelist)
		if tagErr_enc_tracenetypelist != nil {
			return nil, fmt.Errorf("encoding traceNE-TypeList: %w", tagErr_enc_tracenetypelist)
		}
		enc_tracenetypelist = retagged_enc_tracenetypelist
		children = append(children, enc_tracenetypelist...)
	}
	if v.TraceInterfaceList != nil {
		enc_traceinterfacelist, err := v.TraceInterfaceList.MarshalBER(ber.ChildEncodeOptions(opts, "traceInterfaceList")...)
		if err != nil {
			return nil, fmt.Errorf("encoding traceInterfaceList: %w", err)
		}
		retagged_enc_traceinterfacelist, tagErr_enc_traceinterfacelist := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 8, enc_traceinterfacelist)
		if tagErr_enc_traceinterfacelist != nil {
			return nil, fmt.Errorf("encoding traceInterfaceList: %w", tagErr_enc_traceinterfacelist)
		}
		enc_traceinterfacelist = retagged_enc_traceinterfacelist
		children = append(children, enc_traceinterfacelist...)
	}
	if v.TraceEventList != nil {
		enc_traceeventlist, err := v.TraceEventList.MarshalBER(ber.ChildEncodeOptions(opts, "traceEventList")...)
		if err != nil {
			return nil, fmt.Errorf("encoding traceEventList: %w", err)
		}
		retagged_enc_traceeventlist, tagErr_enc_traceeventlist := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 9, enc_traceeventlist)
		if tagErr_enc_traceeventlist != nil {
			return nil, fmt.Errorf("encoding traceEventList: %w", tagErr_enc_traceeventlist)
		}
		enc_traceeventlist = retagged_enc_traceeventlist
		children = append(children, enc_traceeventlist...)
	}
	if v.TraceCollectionEntity != nil {
		if len(*v.TraceCollectionEntity) < 5 || len(*v.TraceCollectionEntity) > 17 {
			if constraintErr := ber.CheckEncodedLength(opts, "traceCollectionEntity", "SIZE (5..17)", len(*v.TraceCollectionEntity)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_tracecollectionentity, encodeErr_enc_tracecollectionentity := ber.EncodeOctetString([]byte(*v.TraceCollectionEntity))
		if encodeErr_enc_tracecollectionentity != nil {
			return nil, fmt.Errorf("encoding traceCollectionEntity: %w", encodeErr_enc_tracecollectionentity)
		}
		retagged_enc_tracecollectionentity, tagErr_enc_tracecollectionentity := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 10, enc_tracecollectionentity)
		if tagErr_enc_tracecollectionentity != nil {
			return nil, fmt.Errorf("encoding traceCollectionEntity: %w", tagErr_enc_tracecollectionentity)
		}
		enc_tracecollectionentity = retagged_enc_tracecollectionentity
		children = append(children, enc_tracecollectionentity...)
	}
	if v.MdtConfiguration != nil {
		enc_mdtconfiguration, err := v.MdtConfiguration.MarshalBER(ber.ChildEncodeOptions(opts, "mdt-Configuration")...)
		if err != nil {
			return nil, fmt.Errorf("encoding mdt-Configuration: %w", err)
		}
		retagged_enc_mdtconfiguration, tagErr_enc_mdtconfiguration := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 11, enc_mdtconfiguration)
		if tagErr_enc_mdtconfiguration != nil {
			return nil, fmt.Errorf("encoding mdt-Configuration: %w", tagErr_enc_mdtconfiguration)
		}
		enc_mdtconfiguration = retagged_enc_mdtconfiguration
		children = append(children, enc_mdtconfiguration...)
	}
	for i, ext := range v.ExtData_ {
		_, n, _, extErr := ber.DecodeEncodedTLV(ext)
		if extErr != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, extErr)
		}
		if n != len(ext) {
			return nil, fmt.Errorf("encoding extension %d: %w", i, ber.ErrExtraData)
		}
		children = append(children, ext...)
	}
	return ber.EncodeSequence(children)
}

// MarshalDER encodes ActivateTraceModeArg to DER format.
func (v *ActivateTraceModeArg) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: ActivateTraceModeArg receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if v.Imsi != nil {
		if len(*v.Imsi) < 3 || len(*v.Imsi) > 8 {
			if constraintErr := ber.CheckEncodedLength(nil, "imsi", "SIZE (3..8)", len(*v.Imsi)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_imsi, encodeErr_enc_imsi := ber.EncodeOctetString([]byte(*v.Imsi))
		if encodeErr_enc_imsi != nil {
			return nil, fmt.Errorf("encoding imsi: %w", encodeErr_enc_imsi)
		}
		retagged_enc_imsi, tagErr_enc_imsi := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_imsi)
		if tagErr_enc_imsi != nil {
			return nil, fmt.Errorf("encoding imsi: %w", tagErr_enc_imsi)
		}
		enc_imsi = retagged_enc_imsi
		children = append(children, enc_imsi...)
	}
	if len(v.TraceReference) < 1 || len(v.TraceReference) > 2 {
		if constraintErr := ber.CheckEncodedLength(nil, "traceReference", "SIZE (1..2)", len(v.TraceReference)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_tracereference, encodeErr_enc_tracereference := ber.EncodeOctetString([]byte(v.TraceReference))
	if encodeErr_enc_tracereference != nil {
		return nil, fmt.Errorf("encoding traceReference: %w", encodeErr_enc_tracereference)
	}
	retagged_enc_tracereference, tagErr_enc_tracereference := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_tracereference)
	if tagErr_enc_tracereference != nil {
		return nil, fmt.Errorf("encoding traceReference: %w", tagErr_enc_tracereference)
	}
	enc_tracereference = retagged_enc_tracereference
	children = append(children, enc_tracereference...)
	if !(int64(v.TraceType) >= 0 && int64(v.TraceType) <= 255) {
		if constraintErr := ber.CheckEncodedValue(nil, "traceType", "(0..255)", fmt.Sprint(int64(v.TraceType))); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_tracetype := ber.EncodeInteger(int64(v.TraceType))
	retagged_enc_tracetype, tagErr_enc_tracetype := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_tracetype)
	if tagErr_enc_tracetype != nil {
		return nil, fmt.Errorf("encoding traceType: %w", tagErr_enc_tracetype)
	}
	enc_tracetype = retagged_enc_tracetype
	children = append(children, enc_tracetype...)
	if v.OmcId != nil {
		if len(*v.OmcId) < 1 || len(*v.OmcId) > 20 {
			if constraintErr := ber.CheckEncodedLength(nil, "omc-Id", "SIZE (1..20)", len(*v.OmcId)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_omcid, encodeErr_enc_omcid := ber.EncodeOctetString([]byte(*v.OmcId))
		if encodeErr_enc_omcid != nil {
			return nil, fmt.Errorf("encoding omc-Id: %w", encodeErr_enc_omcid)
		}
		retagged_enc_omcid, tagErr_enc_omcid := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, enc_omcid)
		if tagErr_enc_omcid != nil {
			return nil, fmt.Errorf("encoding omc-Id: %w", tagErr_enc_omcid)
		}
		enc_omcid = retagged_enc_omcid
		children = append(children, enc_omcid...)
	}
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding extensionContainer: %w", err)
		}
		retagged_enc_extensioncontainer, tagErr_enc_extensioncontainer := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, enc_extensioncontainer)
		if tagErr_enc_extensioncontainer != nil {
			return nil, fmt.Errorf("encoding extensionContainer: %w", tagErr_enc_extensioncontainer)
		}
		enc_extensioncontainer = retagged_enc_extensioncontainer
		children = append(children, enc_extensioncontainer...)
	}
	if v.TraceReference2 != nil {
		if len(*v.TraceReference2) < 3 || len(*v.TraceReference2) > 3 {
			if constraintErr := ber.CheckEncodedLength(nil, "traceReference2", "SIZE (3)", len(*v.TraceReference2)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_tracereference2, encodeErr_enc_tracereference2 := ber.EncodeOctetString([]byte(*v.TraceReference2))
		if encodeErr_enc_tracereference2 != nil {
			return nil, fmt.Errorf("encoding traceReference2: %w", encodeErr_enc_tracereference2)
		}
		retagged_enc_tracereference2, tagErr_enc_tracereference2 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 5, enc_tracereference2)
		if tagErr_enc_tracereference2 != nil {
			return nil, fmt.Errorf("encoding traceReference2: %w", tagErr_enc_tracereference2)
		}
		enc_tracereference2 = retagged_enc_tracereference2
		children = append(children, enc_tracereference2...)
	}
	if v.TraceDepthList != nil {
		enc_tracedepthlist, err := v.TraceDepthList.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding traceDepthList: %w", err)
		}
		retagged_enc_tracedepthlist, tagErr_enc_tracedepthlist := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 6, enc_tracedepthlist)
		if tagErr_enc_tracedepthlist != nil {
			return nil, fmt.Errorf("encoding traceDepthList: %w", tagErr_enc_tracedepthlist)
		}
		enc_tracedepthlist = retagged_enc_tracedepthlist
		children = append(children, enc_tracedepthlist...)
	}
	if v.TraceNETypeList != nil {
		if (*v.TraceNETypeList).BitLength < 6 || (*v.TraceNETypeList).BitLength > 16 {
			if constraintErr := ber.CheckEncodedLength(nil, "traceNE-TypeList", "SIZE (6..16)", (*v.TraceNETypeList).BitLength); constraintErr != nil {
				return nil, constraintErr
			}
		}
		if bitStringErr := ber.ValidateBitStringLength(v.TraceNETypeList.Bytes, v.TraceNETypeList.BitLength); bitStringErr != nil {
			return nil, fmt.Errorf("encoding %s: %w", "traceNE-TypeList", bitStringErr)
		}
		if bitStringErr := ber.ValidateDERBitString(v.TraceNETypeList.Bytes, v.TraceNETypeList.BitLength); bitStringErr != nil {
			return nil, fmt.Errorf("encoding %s: %w", "traceNE-TypeList", bitStringErr)
		}
		// arithmetic pattern BER_BITSTRING_FIELD: 0 <= bit length before modulo and subtraction; gen/codegen.go:526
		if v.TraceNETypeList.BitLength < 0 {
			return nil, fmt.Errorf("negative bit string length")
		}
		enc_tracenetypelist, encodeErr_enc_tracenetypelist := ber.EncodeDERNamedBitString(v.TraceNETypeList.Bytes, v.TraceNETypeList.BitLength)
		if encodeErr_enc_tracenetypelist != nil {
			return nil, fmt.Errorf("encoding traceNE-TypeList: %w", encodeErr_enc_tracenetypelist)
		}
		retagged_enc_tracenetypelist, tagErr_enc_tracenetypelist := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 7, enc_tracenetypelist)
		if tagErr_enc_tracenetypelist != nil {
			return nil, fmt.Errorf("encoding traceNE-TypeList: %w", tagErr_enc_tracenetypelist)
		}
		enc_tracenetypelist = retagged_enc_tracenetypelist
		children = append(children, enc_tracenetypelist...)
	}
	if v.TraceInterfaceList != nil {
		enc_traceinterfacelist, err := v.TraceInterfaceList.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding traceInterfaceList: %w", err)
		}
		retagged_enc_traceinterfacelist, tagErr_enc_traceinterfacelist := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 8, enc_traceinterfacelist)
		if tagErr_enc_traceinterfacelist != nil {
			return nil, fmt.Errorf("encoding traceInterfaceList: %w", tagErr_enc_traceinterfacelist)
		}
		enc_traceinterfacelist = retagged_enc_traceinterfacelist
		children = append(children, enc_traceinterfacelist...)
	}
	if v.TraceEventList != nil {
		enc_traceeventlist, err := v.TraceEventList.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding traceEventList: %w", err)
		}
		retagged_enc_traceeventlist, tagErr_enc_traceeventlist := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 9, enc_traceeventlist)
		if tagErr_enc_traceeventlist != nil {
			return nil, fmt.Errorf("encoding traceEventList: %w", tagErr_enc_traceeventlist)
		}
		enc_traceeventlist = retagged_enc_traceeventlist
		children = append(children, enc_traceeventlist...)
	}
	if v.TraceCollectionEntity != nil {
		if len(*v.TraceCollectionEntity) < 5 || len(*v.TraceCollectionEntity) > 17 {
			if constraintErr := ber.CheckEncodedLength(nil, "traceCollectionEntity", "SIZE (5..17)", len(*v.TraceCollectionEntity)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_tracecollectionentity, encodeErr_enc_tracecollectionentity := ber.EncodeOctetString([]byte(*v.TraceCollectionEntity))
		if encodeErr_enc_tracecollectionentity != nil {
			return nil, fmt.Errorf("encoding traceCollectionEntity: %w", encodeErr_enc_tracecollectionentity)
		}
		retagged_enc_tracecollectionentity, tagErr_enc_tracecollectionentity := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 10, enc_tracecollectionentity)
		if tagErr_enc_tracecollectionentity != nil {
			return nil, fmt.Errorf("encoding traceCollectionEntity: %w", tagErr_enc_tracecollectionentity)
		}
		enc_tracecollectionentity = retagged_enc_tracecollectionentity
		children = append(children, enc_tracecollectionentity...)
	}
	if v.MdtConfiguration != nil {
		enc_mdtconfiguration, err := v.MdtConfiguration.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding mdt-Configuration: %w", err)
		}
		retagged_enc_mdtconfiguration, tagErr_enc_mdtconfiguration := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 11, enc_mdtconfiguration)
		if tagErr_enc_mdtconfiguration != nil {
			return nil, fmt.Errorf("encoding mdt-Configuration: %w", tagErr_enc_mdtconfiguration)
		}
		enc_mdtconfiguration = retagged_enc_mdtconfiguration
		children = append(children, enc_mdtconfiguration...)
	}
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDEREncodedElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
		children = append(children, ext...)
	}
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding ActivateTraceModeArg as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes ActivateTraceModeArg from BER/DER format.
func (v *ActivateTraceModeArg) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: ActivateTraceModeArg destination is nil", ber.ErrInvalidValue)
	}
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = ActivateTraceModeArg{}
	defer func() {
		if returnErr != nil || !ber.BERNeedsPreservation(opts) {
			return
		}
		var snapshotReports ber.ViolationLog
		snapshot, snapshotErr := v.marshalBER(ber.WithConstraintTolerance(&snapshotReports))
		if snapshotErr != nil {
			returnErr = snapshotErr
			return
		}
		v.berOriginal_ = append([]byte(nil), data...)
		v.berSnapshot_ = snapshot
	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("decoding ActivateTraceModeArg SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "ActivateTraceModeArg", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode imsi
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
				decodedTag_imsi, n_imsi, rawVal_imsi, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding imsi: %w", err)
				}
				if decodedTag_imsi.Class != tag.ClassContextSpecific || decodedTag_imsi.Number != 0 {
					return fmt.Errorf("decoding imsi: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_imsi)
				}
				decVal_imsi, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_imsi.Constructed, rawVal_imsi, opts...)
				if octetErr != nil {
					return fmt.Errorf("decoding imsi: %w", octetErr)
				}
				tmp_imsi := IMSI(decVal_imsi)
				v.Imsi = &tmp_imsi
				if offset > len(content) || n_imsi < 0 || n_imsi > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_imsi
				if len(*v.Imsi) < 3 || len(*v.Imsi) > 8 {
					if constraintErr := ber.CheckDecodedLength(opts, "imsi", "SIZE (3..8)", len(*v.Imsi)); constraintErr != nil {
						return constraintErr
					}
				}
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
	decodedTag_tracereference, n_tracereference, rawVal_tracereference, err := ber.DecodeTLV(content[offset:], opts...)
	if err != nil {
		return fmt.Errorf("decoding traceReference: %w", err)
	}
	if decodedTag_tracereference.Class != tag.ClassContextSpecific || decodedTag_tracereference.Number != 1 {
		return fmt.Errorf("decoding traceReference: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_tracereference)
	}
	decVal_tracereference, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_tracereference.Constructed, rawVal_tracereference, opts...)
	if octetErr != nil {
		return fmt.Errorf("decoding traceReference: %w", octetErr)
	}
	v.TraceReference = TraceReference(decVal_tracereference)
	if offset < 0 || offset >
		len(content) || n_tracereference < 0 || n_tracereference > len(content[offset:]) {
		return fmt.Errorf("invalid BER content window")
	}

	offset += n_tracereference
	if len(v.TraceReference) < 1 || len(v.TraceReference) > 2 {
		if constraintErr := ber.CheckDecodedLength(opts, "traceReference", "SIZE (1..2)", len(v.TraceReference)); constraintErr != nil {
			return constraintErr
		}
	}
	// Decode traceType
	if offset >= len(content) {
		return fmt.Errorf("missing required field traceType")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 2 {
			return fmt.Errorf("expected tag [%s %d] for traceType, got %s", "CONTEXT", 2, reqTag_)
		}
	}
	decodedTag_tracetype, n_tracetype, rawVal_tracetype, err := ber.DecodeTLV(content[offset:], opts...)
	if err != nil {
		return fmt.Errorf("decoding traceType: %w", err)
	}
	if decodedTag_tracetype.Class != tag.ClassContextSpecific || decodedTag_tracetype.Number != 2 || decodedTag_tracetype.Constructed != false {
		return fmt.Errorf("decoding traceType: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_tracetype)
	}
	decVal_tracetype, intErr := ber.DecodeIntegerValue(rawVal_tracetype)
	if intErr != nil {
		return fmt.Errorf("decoding traceType: %w", intErr)
	}
	v.TraceType = TraceType(decVal_tracetype)
	if offset < 0 || offset >
		len(content) || n_tracetype < 0 || n_tracetype > len(content[offset:]) {
		return fmt.Errorf("invalid BER content window")
	}

	offset += n_tracetype
	if !(int64(v.TraceType) >= 0 && int64(v.TraceType) <= 255) {
		if constraintErr := ber.CheckDecodedValue(opts, "traceType", "(0..255)", fmt.Sprint(int64(v.TraceType))); constraintErr != nil {
			return constraintErr
		}
	}
	// Decode omc-Id
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3 {
				decodedTag_omcid, n_omcid, rawVal_omcid, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding omc-Id: %w", err)
				}
				if decodedTag_omcid.Class != tag.ClassContextSpecific || decodedTag_omcid.Number != 3 {
					return fmt.Errorf("decoding omc-Id: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_omcid)
				}
				decVal_omcid, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_omcid.Constructed, rawVal_omcid, opts...)
				if octetErr != nil {
					return fmt.Errorf("decoding omc-Id: %w", octetErr)
				}
				tmp_omcid := AddressString(decVal_omcid)
				v.OmcId = &tmp_omcid
				if offset < 0 || offset >
					len(content) || n_omcid < 0 || n_omcid > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_omcid
				if len(*v.OmcId) < 1 || len(*v.OmcId) > 20 {
					if constraintErr := ber.CheckDecodedLength(opts, "omc-Id", "SIZE (1..20)", len(*v.OmcId)); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode extensionContainer
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4 {
				decodedTag_extensioncontainer, n_extensioncontainer, rawVal_extensioncontainer, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding extensionContainer: %w", err)
				}
				if decodedTag_extensioncontainer.Class != tag.ClassContextSpecific || decodedTag_extensioncontainer.Number != 4 || decodedTag_extensioncontainer.Constructed != true {
					return fmt.Errorf("decoding extensionContainer: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_extensioncontainer)
				}
				reconstructed_extensioncontainer, reconstructionErr_extensioncontainer := ber.EncodeSequence(rawVal_extensioncontainer)
				if reconstructionErr_extensioncontainer != nil {
					return fmt.Errorf("decoding extensionContainer: %w", reconstructionErr_extensioncontainer)
				}
				var dec_extensioncontainer ExtensionContainer
				if unmErr := dec_extensioncontainer.UnmarshalBER(reconstructed_extensioncontainer, ber.ChildDecodeOptions(opts, "extensionContainer")...); unmErr != nil {
					return fmt.Errorf("decoding extensionContainer: %w", unmErr)
				}
				v.ExtensionContainer = &dec_extensioncontainer
				if offset < 0 || offset >
					len(content) || n_extensioncontainer < 0 || n_extensioncontainer >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_extensioncontainer
			}
		}
	}
	// Decode traceReference2
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 5 {
				decodedTag_tracereference2, n_tracereference2, rawVal_tracereference2, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding traceReference2: %w", err)
				}
				if decodedTag_tracereference2.Class != tag.ClassContextSpecific || decodedTag_tracereference2.Number != 5 {
					return fmt.Errorf("decoding traceReference2: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_tracereference2)
				}
				decVal_tracereference2, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_tracereference2.Constructed, rawVal_tracereference2, opts...)
				if octetErr != nil {
					return fmt.Errorf("decoding traceReference2: %w", octetErr)
				}
				tmp_tracereference2 := TraceReference2(decVal_tracereference2)
				v.TraceReference2 = &tmp_tracereference2
				if offset < 0 || offset >
					len(content) || n_tracereference2 < 0 || n_tracereference2 >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_tracereference2
				if len(*v.TraceReference2) < 3 || len(*v.TraceReference2) > 3 {
					if constraintErr := ber.CheckDecodedLength(opts, "traceReference2", "SIZE (3)", len(*v.TraceReference2)); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode traceDepthList
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 6 {
				decodedTag_tracedepthlist, n_tracedepthlist, rawVal_tracedepthlist, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding traceDepthList: %w", err)
				}
				if decodedTag_tracedepthlist.Class != tag.ClassContextSpecific || decodedTag_tracedepthlist.Number != 6 || decodedTag_tracedepthlist.Constructed != true {
					return fmt.Errorf("decoding traceDepthList: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_tracedepthlist)
				}
				reconstructed_tracedepthlist, reconstructionErr_tracedepthlist := ber.EncodeSequence(rawVal_tracedepthlist)
				if reconstructionErr_tracedepthlist != nil {
					return fmt.Errorf("decoding traceDepthList: %w", reconstructionErr_tracedepthlist)
				}
				var dec_tracedepthlist TraceDepthList
				if unmErr := dec_tracedepthlist.UnmarshalBER(reconstructed_tracedepthlist, ber.ChildDecodeOptions(opts, "traceDepthList")...); unmErr != nil {
					return fmt.Errorf("decoding traceDepthList: %w", unmErr)
				}
				v.TraceDepthList = &dec_tracedepthlist
				if offset < 0 || offset >
					len(content) || n_tracedepthlist < 0 || n_tracedepthlist > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_tracedepthlist
			}
		}
	}
	// Decode traceNE-TypeList
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 7 {
				decodedTag_tracenetypelist, n_tracenetypelist, rawVal_tracenetypelist, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding traceNE-TypeList: %w", err)
				}
				if decodedTag_tracenetypelist.Class != tag.ClassContextSpecific || decodedTag_tracenetypelist.Number != 7 {
					return fmt.Errorf("decoding traceNE-TypeList: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_tracenetypelist)
				}
				bsBytes_tracenetypelist, bsUnused_tracenetypelist, bsErr := ber.DecodeImplicitBitStringValue(decodedTag_tracenetypelist.Constructed, rawVal_tracenetypelist, opts...)
				if bsErr != nil {
					return fmt.Errorf("decoding traceNE-TypeList: %w", bsErr)
				}
				bsBitLength_tracenetypelist, bsLenErr_tracenetypelist := ber.BitStringBitLength(len(bsBytes_tracenetypelist), bsUnused_tracenetypelist)
				if bsLenErr_tracenetypelist != nil {
					return fmt.Errorf("decoding traceNE-TypeList: %w", bsLenErr_tracenetypelist)
				}
				tmp_tracenetypelist := runtime.BitString{Bytes: bsBytes_tracenetypelist, BitLength: bsBitLength_tracenetypelist}
				v.TraceNETypeList = &tmp_tracenetypelist
				if offset < 0 || offset >
					len(content) || n_tracenetypelist < 0 || n_tracenetypelist >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_tracenetypelist
				*v.TraceNETypeList = ber.NormalizeNamedBitStringSize(*v.TraceNETypeList, []ber.NamedBitSizeSet{{{Min: 6, Max: 16}}}, opts...)
				if (*v.TraceNETypeList).BitLength < 6 || (*v.TraceNETypeList).BitLength > 16 {
					if constraintErr := ber.CheckDecodedLength(opts, "traceNE-TypeList", "SIZE (6..16)", (*v.TraceNETypeList).BitLength); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode traceInterfaceList
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 8 {
				decodedTag_traceinterfacelist, n_traceinterfacelist, rawVal_traceinterfacelist, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding traceInterfaceList: %w", err)
				}
				if decodedTag_traceinterfacelist.Class != tag.ClassContextSpecific || decodedTag_traceinterfacelist.Number != 8 || decodedTag_traceinterfacelist.Constructed != true {
					return fmt.Errorf("decoding traceInterfaceList: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_traceinterfacelist)
				}
				reconstructed_traceinterfacelist, reconstructionErr_traceinterfacelist := ber.EncodeSequence(rawVal_traceinterfacelist)
				if reconstructionErr_traceinterfacelist != nil {
					return fmt.Errorf("decoding traceInterfaceList: %w", reconstructionErr_traceinterfacelist)
				}
				var dec_traceinterfacelist TraceInterfaceList
				if unmErr := dec_traceinterfacelist.UnmarshalBER(reconstructed_traceinterfacelist, ber.ChildDecodeOptions(opts, "traceInterfaceList")...); unmErr != nil {
					return fmt.Errorf("decoding traceInterfaceList: %w", unmErr)
				}
				v.TraceInterfaceList = &dec_traceinterfacelist
				if offset < 0 || offset >
					len(content) || n_traceinterfacelist < 0 || n_traceinterfacelist >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_traceinterfacelist
			}
		}
	}
	// Decode traceEventList
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 9 {
				decodedTag_traceeventlist, n_traceeventlist, rawVal_traceeventlist, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding traceEventList: %w", err)
				}
				if decodedTag_traceeventlist.Class != tag.ClassContextSpecific || decodedTag_traceeventlist.Number != 9 || decodedTag_traceeventlist.Constructed != true {
					return fmt.Errorf("decoding traceEventList: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_traceeventlist)
				}
				reconstructed_traceeventlist, reconstructionErr_traceeventlist := ber.EncodeSequence(rawVal_traceeventlist)
				if reconstructionErr_traceeventlist != nil {
					return fmt.Errorf("decoding traceEventList: %w", reconstructionErr_traceeventlist)
				}
				var dec_traceeventlist TraceEventList
				if unmErr := dec_traceeventlist.UnmarshalBER(reconstructed_traceeventlist, ber.ChildDecodeOptions(opts, "traceEventList")...); unmErr != nil {
					return fmt.Errorf("decoding traceEventList: %w", unmErr)
				}
				v.TraceEventList = &dec_traceeventlist
				if offset < 0 || offset >
					len(content) || n_traceeventlist < 0 || n_traceeventlist > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_traceeventlist
			}
		}
	}
	// Decode traceCollectionEntity
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 10 {
				decodedTag_tracecollectionentity, n_tracecollectionentity, rawVal_tracecollectionentity, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding traceCollectionEntity: %w", err)
				}
				if decodedTag_tracecollectionentity.Class != tag.ClassContextSpecific || decodedTag_tracecollectionentity.Number != 10 {
					return fmt.Errorf("decoding traceCollectionEntity: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_tracecollectionentity)
				}
				decVal_tracecollectionentity, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_tracecollectionentity.Constructed, rawVal_tracecollectionentity, opts...)
				if octetErr != nil {
					return fmt.Errorf("decoding traceCollectionEntity: %w", octetErr)
				}
				tmp_tracecollectionentity := GSNAddress(decVal_tracecollectionentity)
				v.TraceCollectionEntity = &tmp_tracecollectionentity
				if offset < 0 || offset >
					len(content) || n_tracecollectionentity < 0 || n_tracecollectionentity >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_tracecollectionentity
				if len(*v.TraceCollectionEntity) < 5 || len(*v.TraceCollectionEntity) > 17 {
					if constraintErr := ber.CheckDecodedLength(opts, "traceCollectionEntity", "SIZE (5..17)", len(*v.TraceCollectionEntity)); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode mdt-Configuration
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 11 {
				decodedTag_mdtconfiguration, n_mdtconfiguration, rawVal_mdtconfiguration, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding mdt-Configuration: %w", err)
				}
				if decodedTag_mdtconfiguration.Class != tag.ClassContextSpecific || decodedTag_mdtconfiguration.Number != 11 || decodedTag_mdtconfiguration.Constructed != true {
					return fmt.Errorf("decoding mdt-Configuration: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_mdtconfiguration)
				}
				reconstructed_mdtconfiguration, reconstructionErr_mdtconfiguration := ber.EncodeSequence(rawVal_mdtconfiguration)
				if reconstructionErr_mdtconfiguration != nil {
					return fmt.Errorf("decoding mdt-Configuration: %w", reconstructionErr_mdtconfiguration)
				}
				var dec_mdtconfiguration MDTConfiguration
				if unmErr := dec_mdtconfiguration.UnmarshalBER(reconstructed_mdtconfiguration, ber.ChildDecodeOptions(opts, "mdt-Configuration")...); unmErr != nil {
					return fmt.Errorf("decoding mdt-Configuration: %w", unmErr)
				}
				v.MdtConfiguration = &dec_mdtconfiguration
				if offset < 0 || offset >
					len(content) || n_mdtconfiguration < 0 || n_mdtconfiguration >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_mdtconfiguration
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:], opts...)
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "ActivateTraceModeArg", Cause: extErr_}
		}
		if offset < 0 || offset >
			len(content) || nExt_ < 0 || nExt_ > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		if offset < 0 || offset >
			len(content) || nExt_ < 0 || nExt_ > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes MDTConfiguration to BER format.
func (v *MDTConfiguration) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: MDTConfiguration receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *MDTConfiguration) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if int64(v.JobType) != 0 && int64(v.JobType) != 1 && int64(v.JobType) != 2 && int64(v.JobType) != 3 {
		if constraintErr := ber.CheckEncodedValue(opts, "jobType", "ENUMERATED {0, 1, 2, 3}", fmt.Sprint(int64(v.JobType))); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_jobtype := ber.EncodeEnumerated(int64(v.JobType))
	children = append(children, enc_jobtype...)
	if v.AreaScope != nil {
		enc_areascope, err := v.AreaScope.MarshalBER(ber.ChildEncodeOptions(opts, "areaScope")...)
		if err != nil {
			return nil, fmt.Errorf("encoding areaScope: %w", err)
		}
		children = append(children, enc_areascope...)
	}
	if v.ListOfMeasurements != nil {
		if len(*v.ListOfMeasurements) < 4 || len(*v.ListOfMeasurements) > 4 {
			if constraintErr := ber.CheckEncodedLength(opts, "listOfMeasurements", "SIZE (4)", len(*v.ListOfMeasurements)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_listofmeasurements, encodeErr_enc_listofmeasurements := ber.EncodeOctetString([]byte(*v.ListOfMeasurements))
		if encodeErr_enc_listofmeasurements != nil {
			return nil, fmt.Errorf("encoding listOfMeasurements: %w", encodeErr_enc_listofmeasurements)
		}
		children = append(children, enc_listofmeasurements...)
	}
	if v.ReportingTrigger != nil {
		if len(*v.ReportingTrigger) < 1 || len(*v.ReportingTrigger) > 1 {
			if constraintErr := ber.CheckEncodedLength(opts, "reportingTrigger", "SIZE (1)", len(*v.ReportingTrigger)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_reportingtrigger, encodeErr_enc_reportingtrigger := ber.EncodeOctetString([]byte(*v.ReportingTrigger))
		if encodeErr_enc_reportingtrigger != nil {
			return nil, fmt.Errorf("encoding reportingTrigger: %w", encodeErr_enc_reportingtrigger)
		}
		retagged_enc_reportingtrigger, tagErr_enc_reportingtrigger := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_reportingtrigger)
		if tagErr_enc_reportingtrigger != nil {
			return nil, fmt.Errorf("encoding reportingTrigger: %w", tagErr_enc_reportingtrigger)
		}
		enc_reportingtrigger = retagged_enc_reportingtrigger
		children = append(children, enc_reportingtrigger...)
	}
	if v.ReportInterval != nil {
		if int64(*v.ReportInterval) != 0 && int64(*v.ReportInterval) != 1 && int64(*v.ReportInterval) != 2 && int64(*v.ReportInterval) != 3 && int64(*v.ReportInterval) != 4 && int64(*v.ReportInterval) != 5 && int64(*v.ReportInterval) != 6 && int64(*v.ReportInterval) != 7 && int64(*v.ReportInterval) != 8 && int64(*v.ReportInterval) != 9 && int64(*v.ReportInterval) != 10 && int64(*v.ReportInterval) != 11 && int64(*v.ReportInterval) != 12 && int64(*v.ReportInterval) != 13 && int64(*v.ReportInterval) != 14 && int64(*v.ReportInterval) != 15 && int64(*v.ReportInterval) != 16 && int64(*v.ReportInterval) != 17 && int64(*v.ReportInterval) != 18 && int64(*v.ReportInterval) != 19 && int64(*v.ReportInterval) != 20 && int64(*v.ReportInterval) != 21 && int64(*v.ReportInterval) != 22 && int64(*v.ReportInterval) != 23 && int64(*v.ReportInterval) != 24 && int64(*v.ReportInterval) != 25 && int64(*v.ReportInterval) != 26 && int64(*v.ReportInterval) != 27 {
			if constraintErr := ber.CheckEncodedValue(opts, "reportInterval", "ENUMERATED {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27}", fmt.Sprint(int64(*v.ReportInterval))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_reportinterval := ber.EncodeEnumerated(int64(*v.ReportInterval))
		children = append(children, enc_reportinterval...)
	}
	if v.ReportAmount != nil {
		if int64(*v.ReportAmount) != 0 && int64(*v.ReportAmount) != 1 && int64(*v.ReportAmount) != 2 && int64(*v.ReportAmount) != 3 && int64(*v.ReportAmount) != 4 && int64(*v.ReportAmount) != 5 && int64(*v.ReportAmount) != 6 && int64(*v.ReportAmount) != 7 {
			if constraintErr := ber.CheckEncodedValue(opts, "reportAmount", "ENUMERATED {0, 1, 2, 3, 4, 5, 6, 7}", fmt.Sprint(int64(*v.ReportAmount))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_reportamount := ber.EncodeEnumerated(int64(*v.ReportAmount))
		retagged_enc_reportamount, tagErr_enc_reportamount := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_reportamount)
		if tagErr_enc_reportamount != nil {
			return nil, fmt.Errorf("encoding reportAmount: %w", tagErr_enc_reportamount)
		}
		enc_reportamount = retagged_enc_reportamount
		children = append(children, enc_reportamount...)
	}
	if v.EventThresholdRSRP != nil {
		if !(int64(*v.EventThresholdRSRP) >= 0 && int64(*v.EventThresholdRSRP) <= 97) {
			if constraintErr := ber.CheckEncodedValue(opts, "eventThresholdRSRP", "(0..97)", fmt.Sprint(int64(*v.EventThresholdRSRP))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_eventthresholdrsrp := ber.EncodeInteger(int64(*v.EventThresholdRSRP))
		children = append(children, enc_eventthresholdrsrp...)
	}
	if v.EventThresholdRSRQ != nil {
		if !(int64(*v.EventThresholdRSRQ) >= 0 && int64(*v.EventThresholdRSRQ) <= 34) {
			if constraintErr := ber.CheckEncodedValue(opts, "eventThresholdRSRQ", "(0..34)", fmt.Sprint(int64(*v.EventThresholdRSRQ))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_eventthresholdrsrq := ber.EncodeInteger(int64(*v.EventThresholdRSRQ))
		retagged_enc_eventthresholdrsrq, tagErr_enc_eventthresholdrsrq := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_eventthresholdrsrq)
		if tagErr_enc_eventthresholdrsrq != nil {
			return nil, fmt.Errorf("encoding eventThresholdRSRQ: %w", tagErr_enc_eventthresholdrsrq)
		}
		enc_eventthresholdrsrq = retagged_enc_eventthresholdrsrq
		children = append(children, enc_eventthresholdrsrq...)
	}
	if v.LoggingInterval != nil {
		if int64(*v.LoggingInterval) != 0 && int64(*v.LoggingInterval) != 1 && int64(*v.LoggingInterval) != 2 && int64(*v.LoggingInterval) != 3 && int64(*v.LoggingInterval) != 4 && int64(*v.LoggingInterval) != 5 && int64(*v.LoggingInterval) != 6 && int64(*v.LoggingInterval) != 7 {
			if constraintErr := ber.CheckEncodedValue(opts, "loggingInterval", "ENUMERATED {0, 1, 2, 3, 4, 5, 6, 7}", fmt.Sprint(int64(*v.LoggingInterval))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_logginginterval := ber.EncodeEnumerated(int64(*v.LoggingInterval))
		retagged_enc_logginginterval, tagErr_enc_logginginterval := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, enc_logginginterval)
		if tagErr_enc_logginginterval != nil {
			return nil, fmt.Errorf("encoding loggingInterval: %w", tagErr_enc_logginginterval)
		}
		enc_logginginterval = retagged_enc_logginginterval
		children = append(children, enc_logginginterval...)
	}
	if v.LoggingDuration != nil {
		if int64(*v.LoggingDuration) != 0 && int64(*v.LoggingDuration) != 1 && int64(*v.LoggingDuration) != 2 && int64(*v.LoggingDuration) != 3 && int64(*v.LoggingDuration) != 4 && int64(*v.LoggingDuration) != 5 {
			if constraintErr := ber.CheckEncodedValue(opts, "loggingDuration", "ENUMERATED {0, 1, 2, 3, 4, 5}", fmt.Sprint(int64(*v.LoggingDuration))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_loggingduration := ber.EncodeEnumerated(int64(*v.LoggingDuration))
		retagged_enc_loggingduration, tagErr_enc_loggingduration := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, enc_loggingduration)
		if tagErr_enc_loggingduration != nil {
			return nil, fmt.Errorf("encoding loggingDuration: %w", tagErr_enc_loggingduration)
		}
		enc_loggingduration = retagged_enc_loggingduration
		children = append(children, enc_loggingduration...)
	}
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalBER(ber.ChildEncodeOptions(opts, "extensionContainer")...)
		if err != nil {
			return nil, fmt.Errorf("encoding extensionContainer: %w", err)
		}
		retagged_enc_extensioncontainer, tagErr_enc_extensioncontainer := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 5, enc_extensioncontainer)
		if tagErr_enc_extensioncontainer != nil {
			return nil, fmt.Errorf("encoding extensionContainer: %w", tagErr_enc_extensioncontainer)
		}
		enc_extensioncontainer = retagged_enc_extensioncontainer
		children = append(children, enc_extensioncontainer...)
	}
	if v.MeasurementPeriodUMTS != nil {
		if int64(*v.MeasurementPeriodUMTS) != 0 && int64(*v.MeasurementPeriodUMTS) != 1 && int64(*v.MeasurementPeriodUMTS) != 2 && int64(*v.MeasurementPeriodUMTS) != 3 && int64(*v.MeasurementPeriodUMTS) != 4 && int64(*v.MeasurementPeriodUMTS) != 5 && int64(*v.MeasurementPeriodUMTS) != 6 && int64(*v.MeasurementPeriodUMTS) != 7 && int64(*v.MeasurementPeriodUMTS) != 8 && int64(*v.MeasurementPeriodUMTS) != 9 && int64(*v.MeasurementPeriodUMTS) != 10 && int64(*v.MeasurementPeriodUMTS) != 11 && int64(*v.MeasurementPeriodUMTS) != 12 && int64(*v.MeasurementPeriodUMTS) != 13 && int64(*v.MeasurementPeriodUMTS) != 14 {
			if constraintErr := ber.CheckEncodedValue(opts, "measurementPeriodUMTS", "ENUMERATED {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14}", fmt.Sprint(int64(*v.MeasurementPeriodUMTS))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_measurementperiodumts := ber.EncodeEnumerated(int64(*v.MeasurementPeriodUMTS))
		retagged_enc_measurementperiodumts, tagErr_enc_measurementperiodumts := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 6, enc_measurementperiodumts)
		if tagErr_enc_measurementperiodumts != nil {
			return nil, fmt.Errorf("encoding measurementPeriodUMTS: %w", tagErr_enc_measurementperiodumts)
		}
		enc_measurementperiodumts = retagged_enc_measurementperiodumts
		children = append(children, enc_measurementperiodumts...)
	}
	if v.MeasurementPeriodLTE != nil {
		if int64(*v.MeasurementPeriodLTE) != 0 && int64(*v.MeasurementPeriodLTE) != 1 && int64(*v.MeasurementPeriodLTE) != 2 && int64(*v.MeasurementPeriodLTE) != 3 && int64(*v.MeasurementPeriodLTE) != 4 && int64(*v.MeasurementPeriodLTE) != 5 && int64(*v.MeasurementPeriodLTE) != 6 {
			if constraintErr := ber.CheckEncodedValue(opts, "measurementPeriodLTE", "ENUMERATED {0, 1, 2, 3, 4, 5, 6}", fmt.Sprint(int64(*v.MeasurementPeriodLTE))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_measurementperiodlte := ber.EncodeEnumerated(int64(*v.MeasurementPeriodLTE))
		retagged_enc_measurementperiodlte, tagErr_enc_measurementperiodlte := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 7, enc_measurementperiodlte)
		if tagErr_enc_measurementperiodlte != nil {
			return nil, fmt.Errorf("encoding measurementPeriodLTE: %w", tagErr_enc_measurementperiodlte)
		}
		enc_measurementperiodlte = retagged_enc_measurementperiodlte
		children = append(children, enc_measurementperiodlte...)
	}
	if v.CollectionPeriodRRMUMTS != nil {
		if int64(*v.CollectionPeriodRRMUMTS) != 0 && int64(*v.CollectionPeriodRRMUMTS) != 1 && int64(*v.CollectionPeriodRRMUMTS) != 2 && int64(*v.CollectionPeriodRRMUMTS) != 3 && int64(*v.CollectionPeriodRRMUMTS) != 4 && int64(*v.CollectionPeriodRRMUMTS) != 5 && int64(*v.CollectionPeriodRRMUMTS) != 6 && int64(*v.CollectionPeriodRRMUMTS) != 7 && int64(*v.CollectionPeriodRRMUMTS) != 8 && int64(*v.CollectionPeriodRRMUMTS) != 9 && int64(*v.CollectionPeriodRRMUMTS) != 10 && int64(*v.CollectionPeriodRRMUMTS) != 11 && int64(*v.CollectionPeriodRRMUMTS) != 12 && int64(*v.CollectionPeriodRRMUMTS) != 13 && int64(*v.CollectionPeriodRRMUMTS) != 14 {
			if constraintErr := ber.CheckEncodedValue(opts, "collectionPeriodRRM-UMTS", "ENUMERATED {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14}", fmt.Sprint(int64(*v.CollectionPeriodRRMUMTS))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_collectionperiodrrmumts := ber.EncodeEnumerated(int64(*v.CollectionPeriodRRMUMTS))
		retagged_enc_collectionperiodrrmumts, tagErr_enc_collectionperiodrrmumts := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 8, enc_collectionperiodrrmumts)
		if tagErr_enc_collectionperiodrrmumts != nil {
			return nil, fmt.Errorf("encoding collectionPeriodRRM-UMTS: %w", tagErr_enc_collectionperiodrrmumts)
		}
		enc_collectionperiodrrmumts = retagged_enc_collectionperiodrrmumts
		children = append(children, enc_collectionperiodrrmumts...)
	}
	if v.CollectionPeriodRRMLTE != nil {
		if int64(*v.CollectionPeriodRRMLTE) != 0 && int64(*v.CollectionPeriodRRMLTE) != 1 && int64(*v.CollectionPeriodRRMLTE) != 2 && int64(*v.CollectionPeriodRRMLTE) != 3 && int64(*v.CollectionPeriodRRMLTE) != 4 && int64(*v.CollectionPeriodRRMLTE) != 5 && int64(*v.CollectionPeriodRRMLTE) != 6 {
			if constraintErr := ber.CheckEncodedValue(opts, "collectionPeriodRRM-LTE", "ENUMERATED {0, 1, 2, 3, 4, 5, 6}", fmt.Sprint(int64(*v.CollectionPeriodRRMLTE))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_collectionperiodrrmlte := ber.EncodeEnumerated(int64(*v.CollectionPeriodRRMLTE))
		retagged_enc_collectionperiodrrmlte, tagErr_enc_collectionperiodrrmlte := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 9, enc_collectionperiodrrmlte)
		if tagErr_enc_collectionperiodrrmlte != nil {
			return nil, fmt.Errorf("encoding collectionPeriodRRM-LTE: %w", tagErr_enc_collectionperiodrrmlte)
		}
		enc_collectionperiodrrmlte = retagged_enc_collectionperiodrrmlte
		children = append(children, enc_collectionperiodrrmlte...)
	}
	if v.PositioningMethod != nil {
		if len(*v.PositioningMethod) < 1 || len(*v.PositioningMethod) > 1 {
			if constraintErr := ber.CheckEncodedLength(opts, "positioningMethod", "SIZE (1)", len(*v.PositioningMethod)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_positioningmethod, encodeErr_enc_positioningmethod := ber.EncodeOctetString([]byte(*v.PositioningMethod))
		if encodeErr_enc_positioningmethod != nil {
			return nil, fmt.Errorf("encoding positioningMethod: %w", encodeErr_enc_positioningmethod)
		}
		retagged_enc_positioningmethod, tagErr_enc_positioningmethod := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 10, enc_positioningmethod)
		if tagErr_enc_positioningmethod != nil {
			return nil, fmt.Errorf("encoding positioningMethod: %w", tagErr_enc_positioningmethod)
		}
		enc_positioningmethod = retagged_enc_positioningmethod
		children = append(children, enc_positioningmethod...)
	}
	if v.MeasurementQuantity != nil {
		if len(*v.MeasurementQuantity) < 1 || len(*v.MeasurementQuantity) > 1 {
			if constraintErr := ber.CheckEncodedLength(opts, "measurementQuantity", "SIZE (1)", len(*v.MeasurementQuantity)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_measurementquantity, encodeErr_enc_measurementquantity := ber.EncodeOctetString([]byte(*v.MeasurementQuantity))
		if encodeErr_enc_measurementquantity != nil {
			return nil, fmt.Errorf("encoding measurementQuantity: %w", encodeErr_enc_measurementquantity)
		}
		retagged_enc_measurementquantity, tagErr_enc_measurementquantity := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 11, enc_measurementquantity)
		if tagErr_enc_measurementquantity != nil {
			return nil, fmt.Errorf("encoding measurementQuantity: %w", tagErr_enc_measurementquantity)
		}
		enc_measurementquantity = retagged_enc_measurementquantity
		children = append(children, enc_measurementquantity...)
	}
	if v.EventThreshold1F != nil {
		if !(int64(*v.EventThreshold1F) >= -120 && int64(*v.EventThreshold1F) <= 165) {
			if constraintErr := ber.CheckEncodedValue(opts, "eventThreshold1F", "(-120..165)", fmt.Sprint(int64(*v.EventThreshold1F))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_eventthreshold1f := ber.EncodeInteger(int64(*v.EventThreshold1F))
		retagged_enc_eventthreshold1f, tagErr_enc_eventthreshold1f := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 12, enc_eventthreshold1f)
		if tagErr_enc_eventthreshold1f != nil {
			return nil, fmt.Errorf("encoding eventThreshold1F: %w", tagErr_enc_eventthreshold1f)
		}
		enc_eventthreshold1f = retagged_enc_eventthreshold1f
		children = append(children, enc_eventthreshold1f...)
	}
	if v.EventThreshold1I != nil {
		if !(int64(*v.EventThreshold1I) >= -120 && int64(*v.EventThreshold1I) <= -25) {
			if constraintErr := ber.CheckEncodedValue(opts, "eventThreshold1I", "(-120..-25)", fmt.Sprint(int64(*v.EventThreshold1I))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_eventthreshold1i := ber.EncodeInteger(int64(*v.EventThreshold1I))
		retagged_enc_eventthreshold1i, tagErr_enc_eventthreshold1i := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 13, enc_eventthreshold1i)
		if tagErr_enc_eventthreshold1i != nil {
			return nil, fmt.Errorf("encoding eventThreshold1I: %w", tagErr_enc_eventthreshold1i)
		}
		enc_eventthreshold1i = retagged_enc_eventthreshold1i
		children = append(children, enc_eventthreshold1i...)
	}
	if v.MdtAllowedPLMNList != nil {
		if len((v.MdtAllowedPLMNList).Values) < 1 || len((v.MdtAllowedPLMNList).Values) > 16 {
			if constraintErr := ber.CheckEncodedLength(opts, "mdt-Allowed-PLMN-List", "SIZE (1..16)", len((v.MdtAllowedPLMNList).Values)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_mdtallowedplmnlist, err := MarshalBERMDTAllowedPLMNIdList(v.MdtAllowedPLMNList, ber.ChildEncodeOptions(opts, "mdt-Allowed-PLMN-List")...)
		if err != nil {
			return nil, fmt.Errorf("encoding mdt-Allowed-PLMN-List: %w", err)
		}
		if v.MdtAllowedPLMNListIndef_ {
			// Strip the outer SEQUENCE tag from marshalBER output to get raw children.
			_, _, seqContent_, tlvErr_ := ber.DecodeEncodedTLV(enc_mdtallowedplmnlist)
			if tlvErr_ != nil {
				return nil, tlvErr_
			}
			{
				var encodeErr error
				enc_mdtallowedplmnlist, encodeErr = ber.EncodeConstructedIndefinite(tag.Tag{Class: tag.ClassContextSpecific, Number: 14}, seqContent_)
				if encodeErr != nil {
					return nil, fmt.Errorf("encoding mdt-Allowed-PLMN-List: %w", encodeErr)
				}
			}
		} else {
			retagged_enc_mdtallowedplmnlist, tagErr_enc_mdtallowedplmnlist := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 14, enc_mdtallowedplmnlist)
			if tagErr_enc_mdtallowedplmnlist != nil {
				return nil, fmt.Errorf("encoding mdt-Allowed-PLMN-List: %w", tagErr_enc_mdtallowedplmnlist)
			}
			enc_mdtallowedplmnlist = retagged_enc_mdtallowedplmnlist
		}
		children = append(children, enc_mdtallowedplmnlist...)
	}
	for i, ext := range v.ExtData_ {
		_, n, _, extErr := ber.DecodeEncodedTLV(ext)
		if extErr != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, extErr)
		}
		if n != len(ext) {
			return nil, fmt.Errorf("encoding extension %d: %w", i, ber.ErrExtraData)
		}
		children = append(children, ext...)
	}
	return ber.EncodeSequence(children)
}

// MarshalDER encodes MDTConfiguration to DER format.
func (v *MDTConfiguration) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: MDTConfiguration receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if int64(v.JobType) != 0 && int64(v.JobType) != 1 && int64(v.JobType) != 2 && int64(v.JobType) != 3 {
		if constraintErr := ber.CheckEncodedValue(nil, "jobType", "ENUMERATED {0, 1, 2, 3}", fmt.Sprint(int64(v.JobType))); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_jobtype := ber.EncodeEnumerated(int64(v.JobType))
	children = append(children, enc_jobtype...)
	if v.AreaScope != nil {
		enc_areascope, err := v.AreaScope.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding areaScope: %w", err)
		}
		children = append(children, enc_areascope...)
	}
	if v.ListOfMeasurements != nil {
		if len(*v.ListOfMeasurements) < 4 || len(*v.ListOfMeasurements) > 4 {
			if constraintErr := ber.CheckEncodedLength(nil, "listOfMeasurements", "SIZE (4)", len(*v.ListOfMeasurements)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_listofmeasurements, encodeErr_enc_listofmeasurements := ber.EncodeOctetString([]byte(*v.ListOfMeasurements))
		if encodeErr_enc_listofmeasurements != nil {
			return nil, fmt.Errorf("encoding listOfMeasurements: %w", encodeErr_enc_listofmeasurements)
		}
		children = append(children, enc_listofmeasurements...)
	}
	if v.ReportingTrigger != nil {
		if len(*v.ReportingTrigger) < 1 || len(*v.ReportingTrigger) > 1 {
			if constraintErr := ber.CheckEncodedLength(nil, "reportingTrigger", "SIZE (1)", len(*v.ReportingTrigger)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_reportingtrigger, encodeErr_enc_reportingtrigger := ber.EncodeOctetString([]byte(*v.ReportingTrigger))
		if encodeErr_enc_reportingtrigger != nil {
			return nil, fmt.Errorf("encoding reportingTrigger: %w", encodeErr_enc_reportingtrigger)
		}
		retagged_enc_reportingtrigger, tagErr_enc_reportingtrigger := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_reportingtrigger)
		if tagErr_enc_reportingtrigger != nil {
			return nil, fmt.Errorf("encoding reportingTrigger: %w", tagErr_enc_reportingtrigger)
		}
		enc_reportingtrigger = retagged_enc_reportingtrigger
		children = append(children, enc_reportingtrigger...)
	}
	if v.ReportInterval != nil {
		if int64(*v.ReportInterval) != 0 && int64(*v.ReportInterval) != 1 && int64(*v.ReportInterval) != 2 && int64(*v.ReportInterval) != 3 && int64(*v.ReportInterval) != 4 && int64(*v.ReportInterval) != 5 && int64(*v.ReportInterval) != 6 && int64(*v.ReportInterval) != 7 && int64(*v.ReportInterval) != 8 && int64(*v.ReportInterval) != 9 && int64(*v.ReportInterval) != 10 && int64(*v.ReportInterval) != 11 && int64(*v.ReportInterval) != 12 && int64(*v.ReportInterval) != 13 && int64(*v.ReportInterval) != 14 && int64(*v.ReportInterval) != 15 && int64(*v.ReportInterval) != 16 && int64(*v.ReportInterval) != 17 && int64(*v.ReportInterval) != 18 && int64(*v.ReportInterval) != 19 && int64(*v.ReportInterval) != 20 && int64(*v.ReportInterval) != 21 && int64(*v.ReportInterval) != 22 && int64(*v.ReportInterval) != 23 && int64(*v.ReportInterval) != 24 && int64(*v.ReportInterval) != 25 && int64(*v.ReportInterval) != 26 && int64(*v.ReportInterval) != 27 {
			if constraintErr := ber.CheckEncodedValue(nil, "reportInterval", "ENUMERATED {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27}", fmt.Sprint(int64(*v.ReportInterval))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_reportinterval := ber.EncodeEnumerated(int64(*v.ReportInterval))
		children = append(children, enc_reportinterval...)
	}
	if v.ReportAmount != nil {
		if int64(*v.ReportAmount) != 0 && int64(*v.ReportAmount) != 1 && int64(*v.ReportAmount) != 2 && int64(*v.ReportAmount) != 3 && int64(*v.ReportAmount) != 4 && int64(*v.ReportAmount) != 5 && int64(*v.ReportAmount) != 6 && int64(*v.ReportAmount) != 7 {
			if constraintErr := ber.CheckEncodedValue(nil, "reportAmount", "ENUMERATED {0, 1, 2, 3, 4, 5, 6, 7}", fmt.Sprint(int64(*v.ReportAmount))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_reportamount := ber.EncodeEnumerated(int64(*v.ReportAmount))
		retagged_enc_reportamount, tagErr_enc_reportamount := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_reportamount)
		if tagErr_enc_reportamount != nil {
			return nil, fmt.Errorf("encoding reportAmount: %w", tagErr_enc_reportamount)
		}
		enc_reportamount = retagged_enc_reportamount
		children = append(children, enc_reportamount...)
	}
	if v.EventThresholdRSRP != nil {
		if !(int64(*v.EventThresholdRSRP) >= 0 && int64(*v.EventThresholdRSRP) <= 97) {
			if constraintErr := ber.CheckEncodedValue(nil, "eventThresholdRSRP", "(0..97)", fmt.Sprint(int64(*v.EventThresholdRSRP))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_eventthresholdrsrp := ber.EncodeInteger(int64(*v.EventThresholdRSRP))
		children = append(children, enc_eventthresholdrsrp...)
	}
	if v.EventThresholdRSRQ != nil {
		if !(int64(*v.EventThresholdRSRQ) >= 0 && int64(*v.EventThresholdRSRQ) <= 34) {
			if constraintErr := ber.CheckEncodedValue(nil, "eventThresholdRSRQ", "(0..34)", fmt.Sprint(int64(*v.EventThresholdRSRQ))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_eventthresholdrsrq := ber.EncodeInteger(int64(*v.EventThresholdRSRQ))
		retagged_enc_eventthresholdrsrq, tagErr_enc_eventthresholdrsrq := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_eventthresholdrsrq)
		if tagErr_enc_eventthresholdrsrq != nil {
			return nil, fmt.Errorf("encoding eventThresholdRSRQ: %w", tagErr_enc_eventthresholdrsrq)
		}
		enc_eventthresholdrsrq = retagged_enc_eventthresholdrsrq
		children = append(children, enc_eventthresholdrsrq...)
	}
	if v.LoggingInterval != nil {
		if int64(*v.LoggingInterval) != 0 && int64(*v.LoggingInterval) != 1 && int64(*v.LoggingInterval) != 2 && int64(*v.LoggingInterval) != 3 && int64(*v.LoggingInterval) != 4 && int64(*v.LoggingInterval) != 5 && int64(*v.LoggingInterval) != 6 && int64(*v.LoggingInterval) != 7 {
			if constraintErr := ber.CheckEncodedValue(nil, "loggingInterval", "ENUMERATED {0, 1, 2, 3, 4, 5, 6, 7}", fmt.Sprint(int64(*v.LoggingInterval))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_logginginterval := ber.EncodeEnumerated(int64(*v.LoggingInterval))
		retagged_enc_logginginterval, tagErr_enc_logginginterval := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, enc_logginginterval)
		if tagErr_enc_logginginterval != nil {
			return nil, fmt.Errorf("encoding loggingInterval: %w", tagErr_enc_logginginterval)
		}
		enc_logginginterval = retagged_enc_logginginterval
		children = append(children, enc_logginginterval...)
	}
	if v.LoggingDuration != nil {
		if int64(*v.LoggingDuration) != 0 && int64(*v.LoggingDuration) != 1 && int64(*v.LoggingDuration) != 2 && int64(*v.LoggingDuration) != 3 && int64(*v.LoggingDuration) != 4 && int64(*v.LoggingDuration) != 5 {
			if constraintErr := ber.CheckEncodedValue(nil, "loggingDuration", "ENUMERATED {0, 1, 2, 3, 4, 5}", fmt.Sprint(int64(*v.LoggingDuration))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_loggingduration := ber.EncodeEnumerated(int64(*v.LoggingDuration))
		retagged_enc_loggingduration, tagErr_enc_loggingduration := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, enc_loggingduration)
		if tagErr_enc_loggingduration != nil {
			return nil, fmt.Errorf("encoding loggingDuration: %w", tagErr_enc_loggingduration)
		}
		enc_loggingduration = retagged_enc_loggingduration
		children = append(children, enc_loggingduration...)
	}
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding extensionContainer: %w", err)
		}
		retagged_enc_extensioncontainer, tagErr_enc_extensioncontainer := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 5, enc_extensioncontainer)
		if tagErr_enc_extensioncontainer != nil {
			return nil, fmt.Errorf("encoding extensionContainer: %w", tagErr_enc_extensioncontainer)
		}
		enc_extensioncontainer = retagged_enc_extensioncontainer
		children = append(children, enc_extensioncontainer...)
	}
	if v.MeasurementPeriodUMTS != nil {
		if int64(*v.MeasurementPeriodUMTS) != 0 && int64(*v.MeasurementPeriodUMTS) != 1 && int64(*v.MeasurementPeriodUMTS) != 2 && int64(*v.MeasurementPeriodUMTS) != 3 && int64(*v.MeasurementPeriodUMTS) != 4 && int64(*v.MeasurementPeriodUMTS) != 5 && int64(*v.MeasurementPeriodUMTS) != 6 && int64(*v.MeasurementPeriodUMTS) != 7 && int64(*v.MeasurementPeriodUMTS) != 8 && int64(*v.MeasurementPeriodUMTS) != 9 && int64(*v.MeasurementPeriodUMTS) != 10 && int64(*v.MeasurementPeriodUMTS) != 11 && int64(*v.MeasurementPeriodUMTS) != 12 && int64(*v.MeasurementPeriodUMTS) != 13 && int64(*v.MeasurementPeriodUMTS) != 14 {
			if constraintErr := ber.CheckEncodedValue(nil, "measurementPeriodUMTS", "ENUMERATED {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14}", fmt.Sprint(int64(*v.MeasurementPeriodUMTS))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_measurementperiodumts := ber.EncodeEnumerated(int64(*v.MeasurementPeriodUMTS))
		retagged_enc_measurementperiodumts, tagErr_enc_measurementperiodumts := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 6, enc_measurementperiodumts)
		if tagErr_enc_measurementperiodumts != nil {
			return nil, fmt.Errorf("encoding measurementPeriodUMTS: %w", tagErr_enc_measurementperiodumts)
		}
		enc_measurementperiodumts = retagged_enc_measurementperiodumts
		children = append(children, enc_measurementperiodumts...)
	}
	if v.MeasurementPeriodLTE != nil {
		if int64(*v.MeasurementPeriodLTE) != 0 && int64(*v.MeasurementPeriodLTE) != 1 && int64(*v.MeasurementPeriodLTE) != 2 && int64(*v.MeasurementPeriodLTE) != 3 && int64(*v.MeasurementPeriodLTE) != 4 && int64(*v.MeasurementPeriodLTE) != 5 && int64(*v.MeasurementPeriodLTE) != 6 {
			if constraintErr := ber.CheckEncodedValue(nil, "measurementPeriodLTE", "ENUMERATED {0, 1, 2, 3, 4, 5, 6}", fmt.Sprint(int64(*v.MeasurementPeriodLTE))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_measurementperiodlte := ber.EncodeEnumerated(int64(*v.MeasurementPeriodLTE))
		retagged_enc_measurementperiodlte, tagErr_enc_measurementperiodlte := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 7, enc_measurementperiodlte)
		if tagErr_enc_measurementperiodlte != nil {
			return nil, fmt.Errorf("encoding measurementPeriodLTE: %w", tagErr_enc_measurementperiodlte)
		}
		enc_measurementperiodlte = retagged_enc_measurementperiodlte
		children = append(children, enc_measurementperiodlte...)
	}
	if v.CollectionPeriodRRMUMTS != nil {
		if int64(*v.CollectionPeriodRRMUMTS) != 0 && int64(*v.CollectionPeriodRRMUMTS) != 1 && int64(*v.CollectionPeriodRRMUMTS) != 2 && int64(*v.CollectionPeriodRRMUMTS) != 3 && int64(*v.CollectionPeriodRRMUMTS) != 4 && int64(*v.CollectionPeriodRRMUMTS) != 5 && int64(*v.CollectionPeriodRRMUMTS) != 6 && int64(*v.CollectionPeriodRRMUMTS) != 7 && int64(*v.CollectionPeriodRRMUMTS) != 8 && int64(*v.CollectionPeriodRRMUMTS) != 9 && int64(*v.CollectionPeriodRRMUMTS) != 10 && int64(*v.CollectionPeriodRRMUMTS) != 11 && int64(*v.CollectionPeriodRRMUMTS) != 12 && int64(*v.CollectionPeriodRRMUMTS) != 13 && int64(*v.CollectionPeriodRRMUMTS) != 14 {
			if constraintErr := ber.CheckEncodedValue(nil, "collectionPeriodRRM-UMTS", "ENUMERATED {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14}", fmt.Sprint(int64(*v.CollectionPeriodRRMUMTS))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_collectionperiodrrmumts := ber.EncodeEnumerated(int64(*v.CollectionPeriodRRMUMTS))
		retagged_enc_collectionperiodrrmumts, tagErr_enc_collectionperiodrrmumts := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 8, enc_collectionperiodrrmumts)
		if tagErr_enc_collectionperiodrrmumts != nil {
			return nil, fmt.Errorf("encoding collectionPeriodRRM-UMTS: %w", tagErr_enc_collectionperiodrrmumts)
		}
		enc_collectionperiodrrmumts = retagged_enc_collectionperiodrrmumts
		children = append(children, enc_collectionperiodrrmumts...)
	}
	if v.CollectionPeriodRRMLTE != nil {
		if int64(*v.CollectionPeriodRRMLTE) != 0 && int64(*v.CollectionPeriodRRMLTE) != 1 && int64(*v.CollectionPeriodRRMLTE) != 2 && int64(*v.CollectionPeriodRRMLTE) != 3 && int64(*v.CollectionPeriodRRMLTE) != 4 && int64(*v.CollectionPeriodRRMLTE) != 5 && int64(*v.CollectionPeriodRRMLTE) != 6 {
			if constraintErr := ber.CheckEncodedValue(nil, "collectionPeriodRRM-LTE", "ENUMERATED {0, 1, 2, 3, 4, 5, 6}", fmt.Sprint(int64(*v.CollectionPeriodRRMLTE))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_collectionperiodrrmlte := ber.EncodeEnumerated(int64(*v.CollectionPeriodRRMLTE))
		retagged_enc_collectionperiodrrmlte, tagErr_enc_collectionperiodrrmlte := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 9, enc_collectionperiodrrmlte)
		if tagErr_enc_collectionperiodrrmlte != nil {
			return nil, fmt.Errorf("encoding collectionPeriodRRM-LTE: %w", tagErr_enc_collectionperiodrrmlte)
		}
		enc_collectionperiodrrmlte = retagged_enc_collectionperiodrrmlte
		children = append(children, enc_collectionperiodrrmlte...)
	}
	if v.PositioningMethod != nil {
		if len(*v.PositioningMethod) < 1 || len(*v.PositioningMethod) > 1 {
			if constraintErr := ber.CheckEncodedLength(nil, "positioningMethod", "SIZE (1)", len(*v.PositioningMethod)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_positioningmethod, encodeErr_enc_positioningmethod := ber.EncodeOctetString([]byte(*v.PositioningMethod))
		if encodeErr_enc_positioningmethod != nil {
			return nil, fmt.Errorf("encoding positioningMethod: %w", encodeErr_enc_positioningmethod)
		}
		retagged_enc_positioningmethod, tagErr_enc_positioningmethod := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 10, enc_positioningmethod)
		if tagErr_enc_positioningmethod != nil {
			return nil, fmt.Errorf("encoding positioningMethod: %w", tagErr_enc_positioningmethod)
		}
		enc_positioningmethod = retagged_enc_positioningmethod
		children = append(children, enc_positioningmethod...)
	}
	if v.MeasurementQuantity != nil {
		if len(*v.MeasurementQuantity) < 1 || len(*v.MeasurementQuantity) > 1 {
			if constraintErr := ber.CheckEncodedLength(nil, "measurementQuantity", "SIZE (1)", len(*v.MeasurementQuantity)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_measurementquantity, encodeErr_enc_measurementquantity := ber.EncodeOctetString([]byte(*v.MeasurementQuantity))
		if encodeErr_enc_measurementquantity != nil {
			return nil, fmt.Errorf("encoding measurementQuantity: %w", encodeErr_enc_measurementquantity)
		}
		retagged_enc_measurementquantity, tagErr_enc_measurementquantity := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 11, enc_measurementquantity)
		if tagErr_enc_measurementquantity != nil {
			return nil, fmt.Errorf("encoding measurementQuantity: %w", tagErr_enc_measurementquantity)
		}
		enc_measurementquantity = retagged_enc_measurementquantity
		children = append(children, enc_measurementquantity...)
	}
	if v.EventThreshold1F != nil {
		if !(int64(*v.EventThreshold1F) >= -120 && int64(*v.EventThreshold1F) <= 165) {
			if constraintErr := ber.CheckEncodedValue(nil, "eventThreshold1F", "(-120..165)", fmt.Sprint(int64(*v.EventThreshold1F))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_eventthreshold1f := ber.EncodeInteger(int64(*v.EventThreshold1F))
		retagged_enc_eventthreshold1f, tagErr_enc_eventthreshold1f := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 12, enc_eventthreshold1f)
		if tagErr_enc_eventthreshold1f != nil {
			return nil, fmt.Errorf("encoding eventThreshold1F: %w", tagErr_enc_eventthreshold1f)
		}
		enc_eventthreshold1f = retagged_enc_eventthreshold1f
		children = append(children, enc_eventthreshold1f...)
	}
	if v.EventThreshold1I != nil {
		if !(int64(*v.EventThreshold1I) >= -120 && int64(*v.EventThreshold1I) <= -25) {
			if constraintErr := ber.CheckEncodedValue(nil, "eventThreshold1I", "(-120..-25)", fmt.Sprint(int64(*v.EventThreshold1I))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_eventthreshold1i := ber.EncodeInteger(int64(*v.EventThreshold1I))
		retagged_enc_eventthreshold1i, tagErr_enc_eventthreshold1i := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 13, enc_eventthreshold1i)
		if tagErr_enc_eventthreshold1i != nil {
			return nil, fmt.Errorf("encoding eventThreshold1I: %w", tagErr_enc_eventthreshold1i)
		}
		enc_eventthreshold1i = retagged_enc_eventthreshold1i
		children = append(children, enc_eventthreshold1i...)
	}
	if v.MdtAllowedPLMNList != nil {
		if len((v.MdtAllowedPLMNList).Values) < 1 || len((v.MdtAllowedPLMNList).Values) > 16 {
			if constraintErr := ber.CheckEncodedLength(nil, "mdt-Allowed-PLMN-List", "SIZE (1..16)", len((v.MdtAllowedPLMNList).Values)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_mdtallowedplmnlist, err := MarshalDERMDTAllowedPLMNIdList(v.MdtAllowedPLMNList)
		if err != nil {
			return nil, fmt.Errorf("encoding mdt-Allowed-PLMN-List: %w", err)
		}
		retagged_enc_mdtallowedplmnlist, tagErr_enc_mdtallowedplmnlist := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 14, enc_mdtallowedplmnlist)
		if tagErr_enc_mdtallowedplmnlist != nil {
			return nil, fmt.Errorf("encoding mdt-Allowed-PLMN-List: %w", tagErr_enc_mdtallowedplmnlist)
		}
		enc_mdtallowedplmnlist = retagged_enc_mdtallowedplmnlist
		children = append(children, enc_mdtallowedplmnlist...)
	}
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDEREncodedElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
		children = append(children, ext...)
	}
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding MDTConfiguration as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes MDTConfiguration from BER/DER format.
func (v *MDTConfiguration) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: MDTConfiguration destination is nil", ber.ErrInvalidValue)
	}
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = MDTConfiguration{}
	defer func() {
		if returnErr != nil || !ber.BERNeedsPreservation(opts) {
			return
		}
		var snapshotReports ber.ViolationLog
		snapshot, snapshotErr := v.marshalBER(ber.WithConstraintTolerance(&snapshotReports))
		if snapshotErr != nil {
			returnErr = snapshotErr
			return
		}
		v.berOriginal_ = append([]byte(nil), data...)
		v.berSnapshot_ = snapshot
	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("decoding MDTConfiguration SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "MDTConfiguration", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode jobType
	if offset >= len(content) {
		return fmt.Errorf("missing required field jobType")
	}
	val_jobtype, n, err := ber.DecodeEnumerated(content[offset:], opts...)
	if err != nil {
		return fmt.Errorf("decoding jobType: %w", err)
	}
	v.JobType = JobType(val_jobtype)
	if offset > len(content) || n < 0 || n > len(content[offset:]) {
		return fmt.Errorf("invalid BER content window")
	}

	offset += n
	if int64(v.JobType) != 0 && int64(v.JobType) != 1 && int64(v.JobType) != 2 && int64(v.JobType) != 3 {
		if constraintErr := ber.CheckDecodedValue(opts, "jobType", "ENUMERATED {0, 1, 2, 3}", fmt.Sprint(int64(v.JobType))); constraintErr != nil {
			return constraintErr
		}
	}
	// Decode areaScope
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassUniversal && peekTag.Number == 16 {
				// Decode nested SEQUENCE (AreaScope)
				_, n_areascope, _, tlvErr_areascope := ber.DecodeTLV(content[offset:], opts...)
				if tlvErr_areascope != nil {
					return fmt.Errorf("decoding areaScope: %w", tlvErr_areascope)
				}
				var dec_areascope AreaScope
				if offset < 0 || offset >
					len(content) || n_areascope < 0 || n_areascope > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				if unmErr := dec_areascope.UnmarshalBER(content[offset:offset+n_areascope], ber.ChildDecodeOptions(opts, "areaScope")...); unmErr != nil {
					return fmt.Errorf("decoding areaScope: %w", unmErr)
				}
				v.AreaScope = &dec_areascope
				if offset < 0 || offset >
					len(content) || n_areascope < 0 || n_areascope > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_areascope
			}
		}
	}
	// Decode listOfMeasurements
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassUniversal && peekTag.Number == 4 {
				val_listofmeasurements, n, err := ber.DecodeOctetString(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding listOfMeasurements: %w", err)
				}
				tmp_listofmeasurements := ListOfMeasurements(val_listofmeasurements)
				v.ListOfMeasurements = &tmp_listofmeasurements
				if offset < 0 || offset >
					len(content) || n < 0 || n > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n
				if len(*v.ListOfMeasurements) < 4 || len(*v.ListOfMeasurements) > 4 {
					if constraintErr := ber.CheckDecodedLength(opts, "listOfMeasurements", "SIZE (4)", len(*v.ListOfMeasurements)); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode reportingTrigger
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
				decodedTag_reportingtrigger, n_reportingtrigger, rawVal_reportingtrigger, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding reportingTrigger: %w", err)
				}
				if decodedTag_reportingtrigger.Class != tag.ClassContextSpecific || decodedTag_reportingtrigger.Number != 0 {
					return fmt.Errorf("decoding reportingTrigger: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_reportingtrigger)
				}
				decVal_reportingtrigger, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_reportingtrigger.Constructed, rawVal_reportingtrigger, opts...)
				if octetErr != nil {
					return fmt.Errorf("decoding reportingTrigger: %w", octetErr)
				}
				tmp_reportingtrigger := ReportingTrigger(decVal_reportingtrigger)
				v.ReportingTrigger = &tmp_reportingtrigger
				if offset < 0 || offset >
					len(content) || n_reportingtrigger < 0 || n_reportingtrigger >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_reportingtrigger
				if len(*v.ReportingTrigger) < 1 || len(*v.ReportingTrigger) > 1 {
					if constraintErr := ber.CheckDecodedLength(opts, "reportingTrigger", "SIZE (1)", len(*v.ReportingTrigger)); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode reportInterval
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassUniversal && peekTag.Number == 10 {
				val_reportinterval, n, err := ber.DecodeEnumerated(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding reportInterval: %w", err)
				}
				tmp_reportinterval := ReportInterval(val_reportinterval)
				v.ReportInterval = &tmp_reportinterval
				if offset < 0 || offset >
					len(content) || n < 0 || n > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n
				if int64(*v.ReportInterval) != 0 && int64(*v.ReportInterval) != 1 && int64(*v.ReportInterval) != 2 && int64(*v.ReportInterval) != 3 && int64(*v.ReportInterval) != 4 && int64(*v.ReportInterval) != 5 && int64(*v.ReportInterval) != 6 && int64(*v.ReportInterval) != 7 && int64(*v.ReportInterval) != 8 && int64(*v.ReportInterval) != 9 && int64(*v.ReportInterval) != 10 && int64(*v.ReportInterval) != 11 && int64(*v.ReportInterval) != 12 && int64(*v.ReportInterval) != 13 && int64(*v.ReportInterval) != 14 && int64(*v.ReportInterval) != 15 && int64(*v.ReportInterval) != 16 && int64(*v.ReportInterval) != 17 && int64(*v.ReportInterval) != 18 && int64(*v.ReportInterval) != 19 && int64(*v.ReportInterval) != 20 && int64(*v.ReportInterval) != 21 && int64(*v.ReportInterval) != 22 && int64(*v.ReportInterval) != 23 && int64(*v.ReportInterval) != 24 && int64(*v.ReportInterval) != 25 && int64(*v.ReportInterval) != 26 && int64(*v.ReportInterval) != 27 {
					if constraintErr := ber.CheckDecodedValue(opts, "reportInterval", "ENUMERATED {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27}", fmt.Sprint(int64(*v.ReportInterval))); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode reportAmount
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
				decodedTag_reportamount, n_reportamount, rawVal_reportamount, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding reportAmount: %w", err)
				}
				if decodedTag_reportamount.Class != tag.ClassContextSpecific || decodedTag_reportamount.Number != 1 || decodedTag_reportamount.Constructed != false {
					return fmt.Errorf("decoding reportAmount: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_reportamount)
				}
				decVal_reportamount, intErr := ber.DecodeEnumeratedValue(rawVal_reportamount)
				if intErr != nil {
					return fmt.Errorf("decoding reportAmount: %w", intErr)
				}
				tmp_reportamount := ReportAmount(decVal_reportamount)
				v.ReportAmount = &tmp_reportamount
				if offset < 0 || offset >
					len(content) || n_reportamount < 0 || n_reportamount > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_reportamount
				if int64(*v.ReportAmount) != 0 && int64(*v.ReportAmount) != 1 && int64(*v.ReportAmount) != 2 && int64(*v.ReportAmount) != 3 && int64(*v.ReportAmount) != 4 && int64(*v.ReportAmount) != 5 && int64(*v.ReportAmount) != 6 && int64(*v.ReportAmount) != 7 {
					if constraintErr := ber.CheckDecodedValue(opts, "reportAmount", "ENUMERATED {0, 1, 2, 3, 4, 5, 6, 7}", fmt.Sprint(int64(*v.ReportAmount))); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode eventThresholdRSRP
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassUniversal && peekTag.Number == 2 {
				val_eventthresholdrsrp, n, err := ber.DecodeInteger(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding eventThresholdRSRP: %w", err)
				}
				tmp_eventthresholdrsrp := EventThresholdRSRP(val_eventthresholdrsrp)
				v.EventThresholdRSRP = &tmp_eventthresholdrsrp
				if offset < 0 || offset >
					len(content) || n < 0 || n > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n
				if !(int64(*v.EventThresholdRSRP) >= 0 && int64(*v.EventThresholdRSRP) <= 97) {
					if constraintErr := ber.CheckDecodedValue(opts, "eventThresholdRSRP", "(0..97)", fmt.Sprint(int64(*v.EventThresholdRSRP))); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode eventThresholdRSRQ
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2 {
				decodedTag_eventthresholdrsrq, n_eventthresholdrsrq, rawVal_eventthresholdrsrq, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding eventThresholdRSRQ: %w", err)
				}
				if decodedTag_eventthresholdrsrq.Class != tag.ClassContextSpecific || decodedTag_eventthresholdrsrq.Number != 2 || decodedTag_eventthresholdrsrq.Constructed != false {
					return fmt.Errorf("decoding eventThresholdRSRQ: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_eventthresholdrsrq)
				}
				decVal_eventthresholdrsrq, intErr := ber.DecodeIntegerValue(rawVal_eventthresholdrsrq)
				if intErr != nil {
					return fmt.Errorf("decoding eventThresholdRSRQ: %w", intErr)
				}
				tmp_eventthresholdrsrq := EventThresholdRSRQ(decVal_eventthresholdrsrq)
				v.EventThresholdRSRQ = &tmp_eventthresholdrsrq
				if offset < 0 || offset >
					len(content) || n_eventthresholdrsrq < 0 || n_eventthresholdrsrq >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_eventthresholdrsrq
				if !(int64(*v.EventThresholdRSRQ) >= 0 && int64(*v.EventThresholdRSRQ) <= 34) {
					if constraintErr := ber.CheckDecodedValue(opts, "eventThresholdRSRQ", "(0..34)", fmt.Sprint(int64(*v.EventThresholdRSRQ))); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode loggingInterval
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3 {
				decodedTag_logginginterval, n_logginginterval, rawVal_logginginterval, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding loggingInterval: %w", err)
				}
				if decodedTag_logginginterval.Class != tag.ClassContextSpecific || decodedTag_logginginterval.Number != 3 || decodedTag_logginginterval.Constructed != false {
					return fmt.Errorf("decoding loggingInterval: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_logginginterval)
				}
				decVal_logginginterval, intErr := ber.DecodeEnumeratedValue(rawVal_logginginterval)
				if intErr != nil {
					return fmt.Errorf("decoding loggingInterval: %w", intErr)
				}
				tmp_logginginterval := LoggingInterval(decVal_logginginterval)
				v.LoggingInterval = &tmp_logginginterval
				if offset < 0 || offset >
					len(content) || n_logginginterval < 0 || n_logginginterval >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_logginginterval
				if int64(*v.LoggingInterval) != 0 && int64(*v.LoggingInterval) != 1 && int64(*v.LoggingInterval) != 2 && int64(*v.LoggingInterval) != 3 && int64(*v.LoggingInterval) != 4 && int64(*v.LoggingInterval) != 5 && int64(*v.LoggingInterval) != 6 && int64(*v.LoggingInterval) != 7 {
					if constraintErr := ber.CheckDecodedValue(opts, "loggingInterval", "ENUMERATED {0, 1, 2, 3, 4, 5, 6, 7}", fmt.Sprint(int64(*v.LoggingInterval))); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode loggingDuration
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4 {
				decodedTag_loggingduration, n_loggingduration, rawVal_loggingduration, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding loggingDuration: %w", err)
				}
				if decodedTag_loggingduration.Class != tag.ClassContextSpecific || decodedTag_loggingduration.Number != 4 || decodedTag_loggingduration.Constructed != false {
					return fmt.Errorf("decoding loggingDuration: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_loggingduration)
				}
				decVal_loggingduration, intErr := ber.DecodeEnumeratedValue(rawVal_loggingduration)
				if intErr != nil {
					return fmt.Errorf("decoding loggingDuration: %w", intErr)
				}
				tmp_loggingduration := LoggingDuration(decVal_loggingduration)
				v.LoggingDuration = &tmp_loggingduration
				if offset < 0 || offset >
					len(content) || n_loggingduration < 0 || n_loggingduration >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_loggingduration
				if int64(*v.LoggingDuration) != 0 && int64(*v.LoggingDuration) != 1 && int64(*v.LoggingDuration) != 2 && int64(*v.LoggingDuration) != 3 && int64(*v.LoggingDuration) != 4 && int64(*v.LoggingDuration) != 5 {
					if constraintErr := ber.CheckDecodedValue(opts, "loggingDuration", "ENUMERATED {0, 1, 2, 3, 4, 5}", fmt.Sprint(int64(*v.LoggingDuration))); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode extensionContainer
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 5 {
				decodedTag_extensioncontainer, n_extensioncontainer, rawVal_extensioncontainer, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding extensionContainer: %w", err)
				}
				if decodedTag_extensioncontainer.Class != tag.ClassContextSpecific || decodedTag_extensioncontainer.Number != 5 || decodedTag_extensioncontainer.Constructed != true {
					return fmt.Errorf("decoding extensionContainer: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_extensioncontainer)
				}
				reconstructed_extensioncontainer, reconstructionErr_extensioncontainer := ber.EncodeSequence(rawVal_extensioncontainer)
				if reconstructionErr_extensioncontainer != nil {
					return fmt.Errorf("decoding extensionContainer: %w", reconstructionErr_extensioncontainer)
				}
				var dec_extensioncontainer ExtensionContainer
				if unmErr := dec_extensioncontainer.UnmarshalBER(reconstructed_extensioncontainer, ber.ChildDecodeOptions(opts, "extensionContainer")...); unmErr != nil {
					return fmt.Errorf("decoding extensionContainer: %w", unmErr)
				}
				v.ExtensionContainer = &dec_extensioncontainer
				if offset < 0 || offset >
					len(content) || n_extensioncontainer < 0 || n_extensioncontainer >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_extensioncontainer
			}
		}
	}
	// Decode measurementPeriodUMTS
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 6 {
				decodedTag_measurementperiodumts, n_measurementperiodumts, rawVal_measurementperiodumts, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding measurementPeriodUMTS: %w", err)
				}
				if decodedTag_measurementperiodumts.Class != tag.ClassContextSpecific || decodedTag_measurementperiodumts.Number != 6 || decodedTag_measurementperiodumts.Constructed != false {
					return fmt.Errorf("decoding measurementPeriodUMTS: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_measurementperiodumts)
				}
				decVal_measurementperiodumts, intErr := ber.DecodeEnumeratedValue(rawVal_measurementperiodumts)
				if intErr != nil {
					return fmt.Errorf("decoding measurementPeriodUMTS: %w", intErr)
				}
				tmp_measurementperiodumts := PeriodUMTS(decVal_measurementperiodumts)
				v.MeasurementPeriodUMTS = &tmp_measurementperiodumts
				if offset < 0 || offset >
					len(content) || n_measurementperiodumts < 0 || n_measurementperiodumts >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_measurementperiodumts
				if int64(*v.MeasurementPeriodUMTS) != 0 && int64(*v.MeasurementPeriodUMTS) != 1 && int64(*v.MeasurementPeriodUMTS) != 2 && int64(*v.MeasurementPeriodUMTS) != 3 && int64(*v.MeasurementPeriodUMTS) != 4 && int64(*v.MeasurementPeriodUMTS) != 5 && int64(*v.MeasurementPeriodUMTS) != 6 && int64(*v.MeasurementPeriodUMTS) != 7 && int64(*v.MeasurementPeriodUMTS) != 8 && int64(*v.MeasurementPeriodUMTS) != 9 && int64(*v.MeasurementPeriodUMTS) != 10 && int64(*v.MeasurementPeriodUMTS) != 11 && int64(*v.MeasurementPeriodUMTS) != 12 && int64(*v.MeasurementPeriodUMTS) != 13 && int64(*v.MeasurementPeriodUMTS) != 14 {
					if constraintErr := ber.CheckDecodedValue(opts, "measurementPeriodUMTS", "ENUMERATED {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14}", fmt.Sprint(int64(*v.MeasurementPeriodUMTS))); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode measurementPeriodLTE
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 7 {
				decodedTag_measurementperiodlte, n_measurementperiodlte, rawVal_measurementperiodlte, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding measurementPeriodLTE: %w", err)
				}
				if decodedTag_measurementperiodlte.Class != tag.ClassContextSpecific || decodedTag_measurementperiodlte.Number != 7 || decodedTag_measurementperiodlte.Constructed != false {
					return fmt.Errorf("decoding measurementPeriodLTE: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_measurementperiodlte)
				}
				decVal_measurementperiodlte, intErr := ber.DecodeEnumeratedValue(rawVal_measurementperiodlte)
				if intErr != nil {
					return fmt.Errorf("decoding measurementPeriodLTE: %w", intErr)
				}
				tmp_measurementperiodlte := PeriodLTE(decVal_measurementperiodlte)
				v.MeasurementPeriodLTE = &tmp_measurementperiodlte
				if offset < 0 || offset >
					len(content) || n_measurementperiodlte < 0 || n_measurementperiodlte >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_measurementperiodlte
				if int64(*v.MeasurementPeriodLTE) != 0 && int64(*v.MeasurementPeriodLTE) != 1 && int64(*v.MeasurementPeriodLTE) != 2 && int64(*v.MeasurementPeriodLTE) != 3 && int64(*v.MeasurementPeriodLTE) != 4 && int64(*v.MeasurementPeriodLTE) != 5 && int64(*v.MeasurementPeriodLTE) != 6 {
					if constraintErr := ber.CheckDecodedValue(opts, "measurementPeriodLTE", "ENUMERATED {0, 1, 2, 3, 4, 5, 6}", fmt.Sprint(int64(*v.MeasurementPeriodLTE))); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode collectionPeriodRRM-UMTS
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 8 {
				decodedTag_collectionperiodrrmumts, n_collectionperiodrrmumts, rawVal_collectionperiodrrmumts, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding collectionPeriodRRM-UMTS: %w", err)
				}
				if decodedTag_collectionperiodrrmumts.Class != tag.ClassContextSpecific || decodedTag_collectionperiodrrmumts.Number != 8 || decodedTag_collectionperiodrrmumts.Constructed != false {
					return fmt.Errorf("decoding collectionPeriodRRM-UMTS: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_collectionperiodrrmumts)
				}
				decVal_collectionperiodrrmumts, intErr := ber.DecodeEnumeratedValue(rawVal_collectionperiodrrmumts)
				if intErr != nil {
					return fmt.Errorf("decoding collectionPeriodRRM-UMTS: %w", intErr)
				}
				tmp_collectionperiodrrmumts := PeriodUMTS(decVal_collectionperiodrrmumts)
				v.CollectionPeriodRRMUMTS = &tmp_collectionperiodrrmumts
				if offset < 0 || offset >
					len(content) || n_collectionperiodrrmumts < 0 || n_collectionperiodrrmumts >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_collectionperiodrrmumts
				if int64(*v.CollectionPeriodRRMUMTS) != 0 && int64(*v.CollectionPeriodRRMUMTS) != 1 && int64(*v.CollectionPeriodRRMUMTS) != 2 && int64(*v.CollectionPeriodRRMUMTS) != 3 && int64(*v.CollectionPeriodRRMUMTS) != 4 && int64(*v.CollectionPeriodRRMUMTS) != 5 && int64(*v.CollectionPeriodRRMUMTS) != 6 && int64(*v.CollectionPeriodRRMUMTS) != 7 && int64(*v.CollectionPeriodRRMUMTS) != 8 && int64(*v.CollectionPeriodRRMUMTS) != 9 && int64(*v.CollectionPeriodRRMUMTS) != 10 && int64(*v.CollectionPeriodRRMUMTS) != 11 && int64(*v.CollectionPeriodRRMUMTS) != 12 && int64(*v.CollectionPeriodRRMUMTS) != 13 && int64(*v.CollectionPeriodRRMUMTS) != 14 {
					if constraintErr := ber.CheckDecodedValue(opts, "collectionPeriodRRM-UMTS", "ENUMERATED {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14}", fmt.Sprint(int64(*v.CollectionPeriodRRMUMTS))); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode collectionPeriodRRM-LTE
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 9 {
				decodedTag_collectionperiodrrmlte, n_collectionperiodrrmlte, rawVal_collectionperiodrrmlte, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding collectionPeriodRRM-LTE: %w", err)
				}
				if decodedTag_collectionperiodrrmlte.Class != tag.ClassContextSpecific || decodedTag_collectionperiodrrmlte.Number != 9 || decodedTag_collectionperiodrrmlte.Constructed != false {
					return fmt.Errorf("decoding collectionPeriodRRM-LTE: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_collectionperiodrrmlte)
				}
				decVal_collectionperiodrrmlte, intErr := ber.DecodeEnumeratedValue(rawVal_collectionperiodrrmlte)
				if intErr != nil {
					return fmt.Errorf("decoding collectionPeriodRRM-LTE: %w", intErr)
				}
				tmp_collectionperiodrrmlte := PeriodLTE(decVal_collectionperiodrrmlte)
				v.CollectionPeriodRRMLTE = &tmp_collectionperiodrrmlte
				if offset < 0 || offset >
					len(content) || n_collectionperiodrrmlte < 0 || n_collectionperiodrrmlte >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_collectionperiodrrmlte
				if int64(*v.CollectionPeriodRRMLTE) != 0 && int64(*v.CollectionPeriodRRMLTE) != 1 && int64(*v.CollectionPeriodRRMLTE) != 2 && int64(*v.CollectionPeriodRRMLTE) != 3 && int64(*v.CollectionPeriodRRMLTE) != 4 && int64(*v.CollectionPeriodRRMLTE) != 5 && int64(*v.CollectionPeriodRRMLTE) != 6 {
					if constraintErr := ber.CheckDecodedValue(opts, "collectionPeriodRRM-LTE", "ENUMERATED {0, 1, 2, 3, 4, 5, 6}", fmt.Sprint(int64(*v.CollectionPeriodRRMLTE))); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode positioningMethod
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 10 {
				decodedTag_positioningmethod, n_positioningmethod, rawVal_positioningmethod, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding positioningMethod: %w", err)
				}
				if decodedTag_positioningmethod.Class != tag.ClassContextSpecific || decodedTag_positioningmethod.Number != 10 {
					return fmt.Errorf("decoding positioningMethod: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_positioningmethod)
				}
				decVal_positioningmethod, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_positioningmethod.Constructed, rawVal_positioningmethod, opts...)
				if octetErr != nil {
					return fmt.Errorf("decoding positioningMethod: %w", octetErr)
				}
				tmp_positioningmethod := PositioningMethod(decVal_positioningmethod)
				v.PositioningMethod = &tmp_positioningmethod
				if offset < 0 || offset >
					len(content) || n_positioningmethod < 0 || n_positioningmethod >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_positioningmethod
				if len(*v.PositioningMethod) < 1 || len(*v.PositioningMethod) > 1 {
					if constraintErr := ber.CheckDecodedLength(opts, "positioningMethod", "SIZE (1)", len(*v.PositioningMethod)); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode measurementQuantity
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 11 {
				decodedTag_measurementquantity, n_measurementquantity, rawVal_measurementquantity, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding measurementQuantity: %w", err)
				}
				if decodedTag_measurementquantity.Class != tag.ClassContextSpecific || decodedTag_measurementquantity.Number != 11 {
					return fmt.Errorf("decoding measurementQuantity: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_measurementquantity)
				}
				decVal_measurementquantity, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_measurementquantity.Constructed, rawVal_measurementquantity, opts...)
				if octetErr != nil {
					return fmt.Errorf("decoding measurementQuantity: %w", octetErr)
				}
				tmp_measurementquantity := MeasurementQuantity(decVal_measurementquantity)
				v.MeasurementQuantity = &tmp_measurementquantity
				if offset < 0 || offset >
					len(content) || n_measurementquantity < 0 || n_measurementquantity >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_measurementquantity
				if len(*v.MeasurementQuantity) < 1 || len(*v.MeasurementQuantity) > 1 {
					if constraintErr := ber.CheckDecodedLength(opts, "measurementQuantity", "SIZE (1)", len(*v.MeasurementQuantity)); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode eventThreshold1F
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 12 {
				decodedTag_eventthreshold1f, n_eventthreshold1f, rawVal_eventthreshold1f, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding eventThreshold1F: %w", err)
				}
				if decodedTag_eventthreshold1f.Class != tag.ClassContextSpecific || decodedTag_eventthreshold1f.Number != 12 || decodedTag_eventthreshold1f.Constructed != false {
					return fmt.Errorf("decoding eventThreshold1F: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_eventthreshold1f)
				}
				decVal_eventthreshold1f, intErr := ber.DecodeIntegerValue(rawVal_eventthreshold1f)
				if intErr != nil {
					return fmt.Errorf("decoding eventThreshold1F: %w", intErr)
				}
				tmp_eventthreshold1f := EventThreshold1F(decVal_eventthreshold1f)
				v.EventThreshold1F = &tmp_eventthreshold1f
				if offset < 0 || offset >
					len(content) || n_eventthreshold1f < 0 || n_eventthreshold1f >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_eventthreshold1f
				if !(int64(*v.EventThreshold1F) >= -120 && int64(*v.EventThreshold1F) <= 165) {
					if constraintErr := ber.CheckDecodedValue(opts, "eventThreshold1F", "(-120..165)", fmt.Sprint(int64(*v.EventThreshold1F))); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode eventThreshold1I
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 13 {
				decodedTag_eventthreshold1i, n_eventthreshold1i, rawVal_eventthreshold1i, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding eventThreshold1I: %w", err)
				}
				if decodedTag_eventthreshold1i.Class != tag.ClassContextSpecific || decodedTag_eventthreshold1i.Number != 13 || decodedTag_eventthreshold1i.Constructed != false {
					return fmt.Errorf("decoding eventThreshold1I: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_eventthreshold1i)
				}
				decVal_eventthreshold1i, intErr := ber.DecodeIntegerValue(rawVal_eventthreshold1i)
				if intErr != nil {
					return fmt.Errorf("decoding eventThreshold1I: %w", intErr)
				}
				tmp_eventthreshold1i := EventThreshold1I(decVal_eventthreshold1i)
				v.EventThreshold1I = &tmp_eventthreshold1i
				if offset < 0 || offset >
					len(content) || n_eventthreshold1i < 0 || n_eventthreshold1i >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_eventthreshold1i
				if !(int64(*v.EventThreshold1I) >= -120 && int64(*v.EventThreshold1I) <= -25) {
					if constraintErr := ber.CheckDecodedValue(opts, "eventThreshold1I", "(-120..-25)", fmt.Sprint(int64(*v.EventThreshold1I))); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode mdt-Allowed-PLMN-List
	v.MdtAllowedPLMNListIndef_ = false
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 14 {
				decodedTag_mdtallowedplmnlist, n_mdtallowedplmnlist, rawVal_mdtallowedplmnlist, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding mdt-Allowed-PLMN-List: %w", err)
				}
				if decodedTag_mdtallowedplmnlist.Class != tag.ClassContextSpecific || decodedTag_mdtallowedplmnlist.Number != 14 || decodedTag_mdtallowedplmnlist.Constructed != true {
					return fmt.Errorf("decoding mdt-Allowed-PLMN-List: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_mdtallowedplmnlist)
				}
				reconstructed_mdtallowedplmnlist, reconstructionErr_mdtallowedplmnlist := ber.EncodeSequence(rawVal_mdtallowedplmnlist)
				if reconstructionErr_mdtallowedplmnlist != nil {
					return fmt.Errorf("decoding mdt-Allowed-PLMN-List: %w", reconstructionErr_mdtallowedplmnlist)
				}
				dec_mdtallowedplmnlist, unmErr := UnmarshalBERMDTAllowedPLMNIdList(reconstructed_mdtallowedplmnlist, ber.ChildDecodeOptions(opts, "mdt-Allowed-PLMN-List")...)
				if unmErr != nil {
					return fmt.Errorf("decoding mdt-Allowed-PLMN-List: %w", unmErr)
				}
				v.MdtAllowedPLMNList = dec_mdtallowedplmnlist
				{
					_, tagSz_, _ := ber.DecodeTag(content[offset:])
					if offset < 0 || offset >
						len(content) || tagSz_ < 0 || tagSz_ > len(content[offset:]) {
						return fmt.Errorf("invalid BER content window")
					}

					if offset+tagSz_ < len(content) && content[offset+tagSz_] == 0x80 {
						v.MdtAllowedPLMNListIndef_ = true
					}
				}
				if offset < 0 || offset >
					len(content) || n_mdtallowedplmnlist < 0 || n_mdtallowedplmnlist >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_mdtallowedplmnlist
				if len((v.MdtAllowedPLMNList).Values) < 1 || len((v.MdtAllowedPLMNList).Values) > 16 {
					if constraintErr := ber.CheckDecodedLength(opts, "mdt-Allowed-PLMN-List", "SIZE (1..16)", len((v.MdtAllowedPLMNList).Values)); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:], opts...)
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "MDTConfiguration", Cause: extErr_}
		}
		if offset < 0 || offset >
			len(content) || nExt_ < 0 || nExt_ > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		if offset < 0 || offset >
			len(content) || nExt_ < 0 || nExt_ > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBERMDTAllowedPLMNIdList encodes a MDTAllowedPLMNIdList list to BER.
func MarshalBERMDTAllowedPLMNIdList(collection *MDTAllowedPLMNIdList, opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	if collection == nil {
		return nil, fmt.Errorf("%w: required collection is nil", ber.ErrInvalidValue)
	}
	encoded, err := marshalBERMDTAllowedPLMNIdList(collection, opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, collection.berOriginal_, collection.berSnapshot_, opts), nil
}
func marshalBERMDTAllowedPLMNIdList(collection *MDTAllowedPLMNIdList, opts ...ber.EncodeOption) ([]byte, error) {
	list := collection.Values
	if len(list) < 1 || len(list) > 16 {
		if constraintErr := ber.CheckEncodedLength(opts, "MDTAllowedPLMNIdList", "SIZE (1..16)", len(list)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	var children []byte
	for elemIndex, elem := range list {
		if len(elem) < 3 || len(elem) > 3 {
			if constraintErr := ber.CheckEncodedLength(opts, fmt.Sprintf("element[%d]", elemIndex), "SIZE (3)", len(elem)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		encodedElem, encodeErr_encodedElem := ber.EncodeOctetString([]byte(elem))
		if encodeErr_encodedElem != nil {
			return nil, fmt.Errorf("encoding element: %w", encodeErr_encodedElem)
		}
		children = append(children, encodedElem...)
	}
	return ber.EncodeSequence(children)
}

// MarshalDERMDTAllowedPLMNIdList encodes a MDTAllowedPLMNIdList list to DER.
func MarshalDERMDTAllowedPLMNIdList(collection *MDTAllowedPLMNIdList) ([]byte, error) {
	if collection == nil {
		return nil, fmt.Errorf("%w: required collection is nil", ber.ErrInvalidValue)
	}
	list := collection.Values
	if len(list) < 1 || len(list) > 16 {
		if constraintErr := ber.CheckEncodedLength(nil, "MDTAllowedPLMNIdList", "SIZE (1..16)", len(list)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	var children []byte
	for elemIndex, elem := range list {
		if len(elem) < 3 || len(elem) > 3 {
			if constraintErr := ber.CheckEncodedLength(nil, fmt.Sprintf("element[%d]", elemIndex), "SIZE (3)", len(elem)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		encodedElem, encodeErr_encodedElem := ber.EncodeOctetString([]byte(elem))
		if encodeErr_encodedElem != nil {
			return nil, fmt.Errorf("encoding element: %w", encodeErr_encodedElem)
		}
		children = append(children, encodedElem...)
	}
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding MDTAllowedPLMNIdList as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBERMDTAllowedPLMNIdList decodes a MDTAllowedPLMNIdList list from BER.
func UnmarshalBERMDTAllowedPLMNIdList(data []byte, opts ...ber.DecodeOption) (returnValue *MDTAllowedPLMNIdList, returnErr error) {
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return nil, err
	}
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return nil, fmt.Errorf("decoding MDTAllowedPLMNIdList: %w", err)
	}
	if total != len(data) {
		return nil, &ber.DecodeError{Offset: total, TypeName: "MDTAllowedPLMNIdList", Cause: ber.ErrExtraData}
	}
	var result []PLMNId
	offset := 0
	for offset < len(content) {
		elementData := content[offset:]
		val, n, osErr := ber.DecodeOctetString(elementData, opts...)
		if osErr != nil {
			return nil, fmt.Errorf("decoding element: %w", osErr)
		}
		if len(val) < 3 || len(val) > 3 {
			if constraintErr := ber.CheckDecodedLength(opts, fmt.Sprintf("element[%d]", len(result)), "SIZE (3)", len(val)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		result = append(result, PLMNId(val))
		if offset < 0 || offset >
			len(content) || n < 0 || n > len(content[offset:]) {
			return nil, fmt.Errorf("invalid BER content window")
		}

		offset += n
	}
	if len(result) < 1 || len(result) > 16 {
		if constraintErr := ber.CheckDecodedLength(opts, "MDTAllowedPLMNIdList", "SIZE (1..16)", len(result)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	decoded := &MDTAllowedPLMNIdList{Values: result}
	if ber.BERNeedsPreservation(opts) {
		var snapshotReports ber.ViolationLog
		snapshot, snapshotErr := MarshalBERMDTAllowedPLMNIdList(decoded, ber.WithConstraintTolerance(&snapshotReports))
		if snapshotErr != nil {
			return nil, snapshotErr
		}
		decoded.berOriginal_ = append([]byte(nil), data...)
		decoded.berSnapshot_ = snapshot
	}
	return decoded, nil
}

// MarshalBER encodes AreaScope to BER format.
func (v *AreaScope) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: AreaScope receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *AreaScope) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if v.CgiList != nil {
		if len((v.CgiList).Values) < 1 || len((v.CgiList).Values) > 32 {
			if constraintErr := ber.CheckEncodedLength(opts, "cgi-List", "SIZE (1..32)", len((v.CgiList).Values)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_cgilist, err := MarshalBERCGIList(v.CgiList, ber.ChildEncodeOptions(opts, "cgi-List")...)
		if err != nil {
			return nil, fmt.Errorf("encoding cgi-List: %w", err)
		}
		if v.CgiListIndef_ {
			// Strip the outer SEQUENCE tag from marshalBER output to get raw children.
			_, _, seqContent_, tlvErr_ := ber.DecodeEncodedTLV(enc_cgilist)
			if tlvErr_ != nil {
				return nil, tlvErr_
			}
			{
				var encodeErr error
				enc_cgilist, encodeErr = ber.EncodeConstructedIndefinite(tag.Tag{Class: tag.ClassContextSpecific, Number: 0}, seqContent_)
				if encodeErr != nil {
					return nil, fmt.Errorf("encoding cgi-List: %w", encodeErr)
				}
			}
		} else {
			retagged_enc_cgilist, tagErr_enc_cgilist := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_cgilist)
			if tagErr_enc_cgilist != nil {
				return nil, fmt.Errorf("encoding cgi-List: %w", tagErr_enc_cgilist)
			}
			enc_cgilist = retagged_enc_cgilist
		}
		children = append(children, enc_cgilist...)
	}
	if v.EUtranCgiList != nil {
		if len((v.EUtranCgiList).Values) < 1 || len((v.EUtranCgiList).Values) > 32 {
			if constraintErr := ber.CheckEncodedLength(opts, "e-utran-cgi-List", "SIZE (1..32)", len((v.EUtranCgiList).Values)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_eutrancgilist, err := MarshalBEREUTRANCGIList(v.EUtranCgiList, ber.ChildEncodeOptions(opts, "e-utran-cgi-List")...)
		if err != nil {
			return nil, fmt.Errorf("encoding e-utran-cgi-List: %w", err)
		}
		if v.EUtranCgiListIndef_ {
			// Strip the outer SEQUENCE tag from marshalBER output to get raw children.
			_, _, seqContent_, tlvErr_ := ber.DecodeEncodedTLV(enc_eutrancgilist)
			if tlvErr_ != nil {
				return nil, tlvErr_
			}
			{
				var encodeErr error
				enc_eutrancgilist, encodeErr = ber.EncodeConstructedIndefinite(tag.Tag{Class: tag.ClassContextSpecific, Number: 1}, seqContent_)
				if encodeErr != nil {
					return nil, fmt.Errorf("encoding e-utran-cgi-List: %w", encodeErr)
				}
			}
		} else {
			retagged_enc_eutrancgilist, tagErr_enc_eutrancgilist := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_eutrancgilist)
			if tagErr_enc_eutrancgilist != nil {
				return nil, fmt.Errorf("encoding e-utran-cgi-List: %w", tagErr_enc_eutrancgilist)
			}
			enc_eutrancgilist = retagged_enc_eutrancgilist
		}
		children = append(children, enc_eutrancgilist...)
	}
	if v.RoutingAreaIdList != nil {
		if len((v.RoutingAreaIdList).Values) < 1 || len((v.RoutingAreaIdList).Values) > 8 {
			if constraintErr := ber.CheckEncodedLength(opts, "routingAreaId-List", "SIZE (1..8)", len((v.RoutingAreaIdList).Values)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_routingareaidlist, err := MarshalBERRoutingAreaIdList(v.RoutingAreaIdList, ber.ChildEncodeOptions(opts, "routingAreaId-List")...)
		if err != nil {
			return nil, fmt.Errorf("encoding routingAreaId-List: %w", err)
		}
		if v.RoutingAreaIdListIndef_ {
			// Strip the outer SEQUENCE tag from marshalBER output to get raw children.
			_, _, seqContent_, tlvErr_ := ber.DecodeEncodedTLV(enc_routingareaidlist)
			if tlvErr_ != nil {
				return nil, tlvErr_
			}
			{
				var encodeErr error
				enc_routingareaidlist, encodeErr = ber.EncodeConstructedIndefinite(tag.Tag{Class: tag.ClassContextSpecific, Number: 2}, seqContent_)
				if encodeErr != nil {
					return nil, fmt.Errorf("encoding routingAreaId-List: %w", encodeErr)
				}
			}
		} else {
			retagged_enc_routingareaidlist, tagErr_enc_routingareaidlist := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_routingareaidlist)
			if tagErr_enc_routingareaidlist != nil {
				return nil, fmt.Errorf("encoding routingAreaId-List: %w", tagErr_enc_routingareaidlist)
			}
			enc_routingareaidlist = retagged_enc_routingareaidlist
		}
		children = append(children, enc_routingareaidlist...)
	}
	if v.LocationAreaIdList != nil {
		if len((v.LocationAreaIdList).Values) < 1 || len((v.LocationAreaIdList).Values) > 8 {
			if constraintErr := ber.CheckEncodedLength(opts, "locationAreaId-List", "SIZE (1..8)", len((v.LocationAreaIdList).Values)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_locationareaidlist, err := MarshalBERLocationAreaIdList(v.LocationAreaIdList, ber.ChildEncodeOptions(opts, "locationAreaId-List")...)
		if err != nil {
			return nil, fmt.Errorf("encoding locationAreaId-List: %w", err)
		}
		if v.LocationAreaIdListIndef_ {
			// Strip the outer SEQUENCE tag from marshalBER output to get raw children.
			_, _, seqContent_, tlvErr_ := ber.DecodeEncodedTLV(enc_locationareaidlist)
			if tlvErr_ != nil {
				return nil, tlvErr_
			}
			{
				var encodeErr error
				enc_locationareaidlist, encodeErr = ber.EncodeConstructedIndefinite(tag.Tag{Class: tag.ClassContextSpecific, Number: 3}, seqContent_)
				if encodeErr != nil {
					return nil, fmt.Errorf("encoding locationAreaId-List: %w", encodeErr)
				}
			}
		} else {
			retagged_enc_locationareaidlist, tagErr_enc_locationareaidlist := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, enc_locationareaidlist)
			if tagErr_enc_locationareaidlist != nil {
				return nil, fmt.Errorf("encoding locationAreaId-List: %w", tagErr_enc_locationareaidlist)
			}
			enc_locationareaidlist = retagged_enc_locationareaidlist
		}
		children = append(children, enc_locationareaidlist...)
	}
	if v.TrackingAreaIdList != nil {
		if len((v.TrackingAreaIdList).Values) < 1 || len((v.TrackingAreaIdList).Values) > 8 {
			if constraintErr := ber.CheckEncodedLength(opts, "trackingAreaId-List", "SIZE (1..8)", len((v.TrackingAreaIdList).Values)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_trackingareaidlist, err := MarshalBERTrackingAreaIdList(v.TrackingAreaIdList, ber.ChildEncodeOptions(opts, "trackingAreaId-List")...)
		if err != nil {
			return nil, fmt.Errorf("encoding trackingAreaId-List: %w", err)
		}
		if v.TrackingAreaIdListIndef_ {
			// Strip the outer SEQUENCE tag from marshalBER output to get raw children.
			_, _, seqContent_, tlvErr_ := ber.DecodeEncodedTLV(enc_trackingareaidlist)
			if tlvErr_ != nil {
				return nil, tlvErr_
			}
			{
				var encodeErr error
				enc_trackingareaidlist, encodeErr = ber.EncodeConstructedIndefinite(tag.Tag{Class: tag.ClassContextSpecific, Number: 4}, seqContent_)
				if encodeErr != nil {
					return nil, fmt.Errorf("encoding trackingAreaId-List: %w", encodeErr)
				}
			}
		} else {
			retagged_enc_trackingareaidlist, tagErr_enc_trackingareaidlist := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, enc_trackingareaidlist)
			if tagErr_enc_trackingareaidlist != nil {
				return nil, fmt.Errorf("encoding trackingAreaId-List: %w", tagErr_enc_trackingareaidlist)
			}
			enc_trackingareaidlist = retagged_enc_trackingareaidlist
		}
		children = append(children, enc_trackingareaidlist...)
	}
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalBER(ber.ChildEncodeOptions(opts, "extensionContainer")...)
		if err != nil {
			return nil, fmt.Errorf("encoding extensionContainer: %w", err)
		}
		retagged_enc_extensioncontainer, tagErr_enc_extensioncontainer := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 5, enc_extensioncontainer)
		if tagErr_enc_extensioncontainer != nil {
			return nil, fmt.Errorf("encoding extensionContainer: %w", tagErr_enc_extensioncontainer)
		}
		enc_extensioncontainer = retagged_enc_extensioncontainer
		children = append(children, enc_extensioncontainer...)
	}
	for i, ext := range v.ExtData_ {
		_, n, _, extErr := ber.DecodeEncodedTLV(ext)
		if extErr != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, extErr)
		}
		if n != len(ext) {
			return nil, fmt.Errorf("encoding extension %d: %w", i, ber.ErrExtraData)
		}
		children = append(children, ext...)
	}
	return ber.EncodeSequence(children)
}

// MarshalDER encodes AreaScope to DER format.
func (v *AreaScope) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: AreaScope receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if v.CgiList != nil {
		if len((v.CgiList).Values) < 1 || len((v.CgiList).Values) > 32 {
			if constraintErr := ber.CheckEncodedLength(nil, "cgi-List", "SIZE (1..32)", len((v.CgiList).Values)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_cgilist, err := MarshalDERCGIList(v.CgiList)
		if err != nil {
			return nil, fmt.Errorf("encoding cgi-List: %w", err)
		}
		retagged_enc_cgilist, tagErr_enc_cgilist := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_cgilist)
		if tagErr_enc_cgilist != nil {
			return nil, fmt.Errorf("encoding cgi-List: %w", tagErr_enc_cgilist)
		}
		enc_cgilist = retagged_enc_cgilist
		children = append(children, enc_cgilist...)
	}
	if v.EUtranCgiList != nil {
		if len((v.EUtranCgiList).Values) < 1 || len((v.EUtranCgiList).Values) > 32 {
			if constraintErr := ber.CheckEncodedLength(nil, "e-utran-cgi-List", "SIZE (1..32)", len((v.EUtranCgiList).Values)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_eutrancgilist, err := MarshalDEREUTRANCGIList(v.EUtranCgiList)
		if err != nil {
			return nil, fmt.Errorf("encoding e-utran-cgi-List: %w", err)
		}
		retagged_enc_eutrancgilist, tagErr_enc_eutrancgilist := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_eutrancgilist)
		if tagErr_enc_eutrancgilist != nil {
			return nil, fmt.Errorf("encoding e-utran-cgi-List: %w", tagErr_enc_eutrancgilist)
		}
		enc_eutrancgilist = retagged_enc_eutrancgilist
		children = append(children, enc_eutrancgilist...)
	}
	if v.RoutingAreaIdList != nil {
		if len((v.RoutingAreaIdList).Values) < 1 || len((v.RoutingAreaIdList).Values) > 8 {
			if constraintErr := ber.CheckEncodedLength(nil, "routingAreaId-List", "SIZE (1..8)", len((v.RoutingAreaIdList).Values)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_routingareaidlist, err := MarshalDERRoutingAreaIdList(v.RoutingAreaIdList)
		if err != nil {
			return nil, fmt.Errorf("encoding routingAreaId-List: %w", err)
		}
		retagged_enc_routingareaidlist, tagErr_enc_routingareaidlist := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_routingareaidlist)
		if tagErr_enc_routingareaidlist != nil {
			return nil, fmt.Errorf("encoding routingAreaId-List: %w", tagErr_enc_routingareaidlist)
		}
		enc_routingareaidlist = retagged_enc_routingareaidlist
		children = append(children, enc_routingareaidlist...)
	}
	if v.LocationAreaIdList != nil {
		if len((v.LocationAreaIdList).Values) < 1 || len((v.LocationAreaIdList).Values) > 8 {
			if constraintErr := ber.CheckEncodedLength(nil, "locationAreaId-List", "SIZE (1..8)", len((v.LocationAreaIdList).Values)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_locationareaidlist, err := MarshalDERLocationAreaIdList(v.LocationAreaIdList)
		if err != nil {
			return nil, fmt.Errorf("encoding locationAreaId-List: %w", err)
		}
		retagged_enc_locationareaidlist, tagErr_enc_locationareaidlist := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, enc_locationareaidlist)
		if tagErr_enc_locationareaidlist != nil {
			return nil, fmt.Errorf("encoding locationAreaId-List: %w", tagErr_enc_locationareaidlist)
		}
		enc_locationareaidlist = retagged_enc_locationareaidlist
		children = append(children, enc_locationareaidlist...)
	}
	if v.TrackingAreaIdList != nil {
		if len((v.TrackingAreaIdList).Values) < 1 || len((v.TrackingAreaIdList).Values) > 8 {
			if constraintErr := ber.CheckEncodedLength(nil, "trackingAreaId-List", "SIZE (1..8)", len((v.TrackingAreaIdList).Values)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_trackingareaidlist, err := MarshalDERTrackingAreaIdList(v.TrackingAreaIdList)
		if err != nil {
			return nil, fmt.Errorf("encoding trackingAreaId-List: %w", err)
		}
		retagged_enc_trackingareaidlist, tagErr_enc_trackingareaidlist := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, enc_trackingareaidlist)
		if tagErr_enc_trackingareaidlist != nil {
			return nil, fmt.Errorf("encoding trackingAreaId-List: %w", tagErr_enc_trackingareaidlist)
		}
		enc_trackingareaidlist = retagged_enc_trackingareaidlist
		children = append(children, enc_trackingareaidlist...)
	}
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding extensionContainer: %w", err)
		}
		retagged_enc_extensioncontainer, tagErr_enc_extensioncontainer := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 5, enc_extensioncontainer)
		if tagErr_enc_extensioncontainer != nil {
			return nil, fmt.Errorf("encoding extensionContainer: %w", tagErr_enc_extensioncontainer)
		}
		enc_extensioncontainer = retagged_enc_extensioncontainer
		children = append(children, enc_extensioncontainer...)
	}
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDEREncodedElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
		children = append(children, ext...)
	}
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding AreaScope as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes AreaScope from BER/DER format.
func (v *AreaScope) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: AreaScope destination is nil", ber.ErrInvalidValue)
	}
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = AreaScope{}
	defer func() {
		if returnErr != nil || !ber.BERNeedsPreservation(opts) {
			return
		}
		var snapshotReports ber.ViolationLog
		snapshot, snapshotErr := v.marshalBER(ber.WithConstraintTolerance(&snapshotReports))
		if snapshotErr != nil {
			returnErr = snapshotErr
			return
		}
		v.berOriginal_ = append([]byte(nil), data...)
		v.berSnapshot_ = snapshot
	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("decoding AreaScope SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "AreaScope", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode cgi-List
	v.CgiListIndef_ = false
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
				decodedTag_cgilist, n_cgilist, rawVal_cgilist, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding cgi-List: %w", err)
				}
				if decodedTag_cgilist.Class != tag.ClassContextSpecific || decodedTag_cgilist.Number != 0 || decodedTag_cgilist.Constructed != true {
					return fmt.Errorf("decoding cgi-List: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_cgilist)
				}
				reconstructed_cgilist, reconstructionErr_cgilist := ber.EncodeSequence(rawVal_cgilist)
				if reconstructionErr_cgilist != nil {
					return fmt.Errorf("decoding cgi-List: %w", reconstructionErr_cgilist)
				}
				dec_cgilist, unmErr := UnmarshalBERCGIList(reconstructed_cgilist, ber.ChildDecodeOptions(opts, "cgi-List")...)
				if unmErr != nil {
					return fmt.Errorf("decoding cgi-List: %w", unmErr)
				}
				v.CgiList = dec_cgilist
				{
					_, tagSz_, _ := ber.DecodeTag(content[offset:])
					if offset > len(content) || tagSz_ < 0 || tagSz_ > len(content[offset:]) {
						return fmt.Errorf("invalid BER content window")
					}

					if offset+tagSz_ < len(content) && content[offset+tagSz_] == 0x80 {
						v.CgiListIndef_ = true
					}
				}
				if offset > len(content) || n_cgilist < 0 || n_cgilist > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_cgilist
				if len((v.CgiList).Values) < 1 || len((v.CgiList).Values) > 32 {
					if constraintErr := ber.CheckDecodedLength(opts, "cgi-List", "SIZE (1..32)", len((v.CgiList).Values)); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode e-utran-cgi-List
	v.EUtranCgiListIndef_ = false
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
				decodedTag_eutrancgilist, n_eutrancgilist, rawVal_eutrancgilist, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding e-utran-cgi-List: %w", err)
				}
				if decodedTag_eutrancgilist.Class != tag.ClassContextSpecific || decodedTag_eutrancgilist.Number != 1 || decodedTag_eutrancgilist.Constructed != true {
					return fmt.Errorf("decoding e-utran-cgi-List: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_eutrancgilist)
				}
				reconstructed_eutrancgilist, reconstructionErr_eutrancgilist := ber.EncodeSequence(rawVal_eutrancgilist)
				if reconstructionErr_eutrancgilist != nil {
					return fmt.Errorf("decoding e-utran-cgi-List: %w", reconstructionErr_eutrancgilist)
				}
				dec_eutrancgilist, unmErr := UnmarshalBEREUTRANCGIList(reconstructed_eutrancgilist, ber.ChildDecodeOptions(opts, "e-utran-cgi-List")...)
				if unmErr != nil {
					return fmt.Errorf("decoding e-utran-cgi-List: %w", unmErr)
				}
				v.EUtranCgiList = dec_eutrancgilist
				{
					_, tagSz_, _ := ber.DecodeTag(content[offset:])
					if offset < 0 || offset >
						len(content) || tagSz_ < 0 || tagSz_ > len(content[offset:]) {
						return fmt.Errorf("invalid BER content window")
					}

					if offset+tagSz_ < len(content) && content[offset+tagSz_] == 0x80 {
						v.EUtranCgiListIndef_ = true
					}
				}
				if offset < 0 || offset >
					len(content) || n_eutrancgilist < 0 || n_eutrancgilist >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_eutrancgilist
				if len((v.EUtranCgiList).Values) < 1 || len((v.EUtranCgiList).Values) > 32 {
					if constraintErr := ber.CheckDecodedLength(opts, "e-utran-cgi-List", "SIZE (1..32)", len((v.EUtranCgiList).Values)); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode routingAreaId-List
	v.RoutingAreaIdListIndef_ = false
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2 {
				decodedTag_routingareaidlist, n_routingareaidlist, rawVal_routingareaidlist, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding routingAreaId-List: %w", err)
				}
				if decodedTag_routingareaidlist.Class != tag.ClassContextSpecific || decodedTag_routingareaidlist.Number != 2 || decodedTag_routingareaidlist.Constructed != true {
					return fmt.Errorf("decoding routingAreaId-List: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_routingareaidlist)
				}
				reconstructed_routingareaidlist, reconstructionErr_routingareaidlist := ber.EncodeSequence(rawVal_routingareaidlist)
				if reconstructionErr_routingareaidlist != nil {
					return fmt.Errorf("decoding routingAreaId-List: %w", reconstructionErr_routingareaidlist)
				}
				dec_routingareaidlist, unmErr := UnmarshalBERRoutingAreaIdList(reconstructed_routingareaidlist, ber.ChildDecodeOptions(opts, "routingAreaId-List")...)
				if unmErr != nil {
					return fmt.Errorf("decoding routingAreaId-List: %w", unmErr)
				}
				v.RoutingAreaIdList = dec_routingareaidlist
				{
					_, tagSz_, _ := ber.DecodeTag(content[offset:])
					if offset < 0 || offset >
						len(content) || tagSz_ < 0 || tagSz_ > len(content[offset:]) {
						return fmt.Errorf("invalid BER content window")
					}

					if offset+tagSz_ < len(content) && content[offset+tagSz_] == 0x80 {
						v.RoutingAreaIdListIndef_ = true
					}
				}
				if offset < 0 || offset >
					len(content) || n_routingareaidlist < 0 || n_routingareaidlist >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_routingareaidlist
				if len((v.RoutingAreaIdList).Values) < 1 || len((v.RoutingAreaIdList).Values) > 8 {
					if constraintErr := ber.CheckDecodedLength(opts, "routingAreaId-List", "SIZE (1..8)", len((v.RoutingAreaIdList).Values)); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode locationAreaId-List
	v.LocationAreaIdListIndef_ = false
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3 {
				decodedTag_locationareaidlist, n_locationareaidlist, rawVal_locationareaidlist, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding locationAreaId-List: %w", err)
				}
				if decodedTag_locationareaidlist.Class != tag.ClassContextSpecific || decodedTag_locationareaidlist.Number != 3 || decodedTag_locationareaidlist.Constructed != true {
					return fmt.Errorf("decoding locationAreaId-List: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_locationareaidlist)
				}
				reconstructed_locationareaidlist, reconstructionErr_locationareaidlist := ber.EncodeSequence(rawVal_locationareaidlist)
				if reconstructionErr_locationareaidlist != nil {
					return fmt.Errorf("decoding locationAreaId-List: %w", reconstructionErr_locationareaidlist)
				}
				dec_locationareaidlist, unmErr := UnmarshalBERLocationAreaIdList(reconstructed_locationareaidlist, ber.ChildDecodeOptions(opts, "locationAreaId-List")...)
				if unmErr != nil {
					return fmt.Errorf("decoding locationAreaId-List: %w", unmErr)
				}
				v.LocationAreaIdList = dec_locationareaidlist
				{
					_, tagSz_, _ := ber.DecodeTag(content[offset:])
					if offset < 0 || offset >
						len(content) || tagSz_ < 0 || tagSz_ > len(content[offset:]) {
						return fmt.Errorf("invalid BER content window")
					}

					if offset+tagSz_ < len(content) && content[offset+tagSz_] == 0x80 {
						v.LocationAreaIdListIndef_ = true
					}
				}
				if offset < 0 || offset >
					len(content) || n_locationareaidlist < 0 || n_locationareaidlist >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_locationareaidlist
				if len((v.LocationAreaIdList).Values) < 1 || len((v.LocationAreaIdList).Values) > 8 {
					if constraintErr := ber.CheckDecodedLength(opts, "locationAreaId-List", "SIZE (1..8)", len((v.LocationAreaIdList).Values)); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode trackingAreaId-List
	v.TrackingAreaIdListIndef_ = false
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4 {
				decodedTag_trackingareaidlist, n_trackingareaidlist, rawVal_trackingareaidlist, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding trackingAreaId-List: %w", err)
				}
				if decodedTag_trackingareaidlist.Class != tag.ClassContextSpecific || decodedTag_trackingareaidlist.Number != 4 || decodedTag_trackingareaidlist.Constructed != true {
					return fmt.Errorf("decoding trackingAreaId-List: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_trackingareaidlist)
				}
				reconstructed_trackingareaidlist, reconstructionErr_trackingareaidlist := ber.EncodeSequence(rawVal_trackingareaidlist)
				if reconstructionErr_trackingareaidlist != nil {
					return fmt.Errorf("decoding trackingAreaId-List: %w", reconstructionErr_trackingareaidlist)
				}
				dec_trackingareaidlist, unmErr := UnmarshalBERTrackingAreaIdList(reconstructed_trackingareaidlist, ber.ChildDecodeOptions(opts, "trackingAreaId-List")...)
				if unmErr != nil {
					return fmt.Errorf("decoding trackingAreaId-List: %w", unmErr)
				}
				v.TrackingAreaIdList = dec_trackingareaidlist
				{
					_, tagSz_, _ := ber.DecodeTag(content[offset:])
					if offset < 0 || offset >
						len(content) || tagSz_ < 0 || tagSz_ > len(content[offset:]) {
						return fmt.Errorf("invalid BER content window")
					}

					if offset+tagSz_ < len(content) && content[offset+tagSz_] == 0x80 {
						v.TrackingAreaIdListIndef_ = true
					}
				}
				if offset < 0 || offset >
					len(content) || n_trackingareaidlist < 0 || n_trackingareaidlist >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_trackingareaidlist
				if len((v.TrackingAreaIdList).Values) < 1 || len((v.TrackingAreaIdList).Values) > 8 {
					if constraintErr := ber.CheckDecodedLength(opts, "trackingAreaId-List", "SIZE (1..8)", len((v.TrackingAreaIdList).Values)); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode extensionContainer
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 5 {
				decodedTag_extensioncontainer, n_extensioncontainer, rawVal_extensioncontainer, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding extensionContainer: %w", err)
				}
				if decodedTag_extensioncontainer.Class != tag.ClassContextSpecific || decodedTag_extensioncontainer.Number != 5 || decodedTag_extensioncontainer.Constructed != true {
					return fmt.Errorf("decoding extensionContainer: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_extensioncontainer)
				}
				reconstructed_extensioncontainer, reconstructionErr_extensioncontainer := ber.EncodeSequence(rawVal_extensioncontainer)
				if reconstructionErr_extensioncontainer != nil {
					return fmt.Errorf("decoding extensionContainer: %w", reconstructionErr_extensioncontainer)
				}
				var dec_extensioncontainer ExtensionContainer
				if unmErr := dec_extensioncontainer.UnmarshalBER(reconstructed_extensioncontainer, ber.ChildDecodeOptions(opts, "extensionContainer")...); unmErr != nil {
					return fmt.Errorf("decoding extensionContainer: %w", unmErr)
				}
				v.ExtensionContainer = &dec_extensioncontainer
				if offset < 0 || offset >
					len(content) || n_extensioncontainer < 0 || n_extensioncontainer >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_extensioncontainer
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:], opts...)
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "AreaScope", Cause: extErr_}
		}
		if offset < 0 || offset >
			len(content) || nExt_ < 0 || nExt_ > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		if offset < 0 || offset >
			len(content) || nExt_ < 0 || nExt_ > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBERCGIList encodes a CGIList list to BER.
func MarshalBERCGIList(collection *CGIList, opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	if collection == nil {
		return nil, fmt.Errorf("%w: required collection is nil", ber.ErrInvalidValue)
	}
	encoded, err := marshalBERCGIList(collection, opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, collection.berOriginal_, collection.berSnapshot_, opts), nil
}
func marshalBERCGIList(collection *CGIList, opts ...ber.EncodeOption) ([]byte, error) {
	list := collection.Values
	if len(list) < 1 || len(list) > 32 {
		if constraintErr := ber.CheckEncodedLength(opts, "CGIList", "SIZE (1..32)", len(list)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	var children []byte
	for elemIndex, elem := range list {
		if len(elem) < 5 || len(elem) > 7 {
			if constraintErr := ber.CheckEncodedLength(opts, fmt.Sprintf("element[%d]", elemIndex), "SIZE (5..7)", len(elem)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		encodedElem, encodeErr_encodedElem := ber.EncodeOctetString([]byte(elem))
		if encodeErr_encodedElem != nil {
			return nil, fmt.Errorf("encoding element: %w", encodeErr_encodedElem)
		}
		children = append(children, encodedElem...)
	}
	return ber.EncodeSequence(children)
}

// MarshalDERCGIList encodes a CGIList list to DER.
func MarshalDERCGIList(collection *CGIList) ([]byte, error) {
	if collection == nil {
		return nil, fmt.Errorf("%w: required collection is nil", ber.ErrInvalidValue)
	}
	list := collection.Values
	if len(list) < 1 || len(list) > 32 {
		if constraintErr := ber.CheckEncodedLength(nil, "CGIList", "SIZE (1..32)", len(list)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	var children []byte
	for elemIndex, elem := range list {
		if len(elem) < 5 || len(elem) > 7 {
			if constraintErr := ber.CheckEncodedLength(nil, fmt.Sprintf("element[%d]", elemIndex), "SIZE (5..7)", len(elem)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		encodedElem, encodeErr_encodedElem := ber.EncodeOctetString([]byte(elem))
		if encodeErr_encodedElem != nil {
			return nil, fmt.Errorf("encoding element: %w", encodeErr_encodedElem)
		}
		children = append(children, encodedElem...)
	}
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding CGIList as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBERCGIList decodes a CGIList list from BER.
func UnmarshalBERCGIList(data []byte, opts ...ber.DecodeOption) (returnValue *CGIList, returnErr error) {
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return nil, err
	}
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return nil, fmt.Errorf("decoding CGIList: %w", err)
	}
	if total != len(data) {
		return nil, &ber.DecodeError{Offset: total, TypeName: "CGIList", Cause: ber.ErrExtraData}
	}
	var result []GlobalCellId
	offset := 0
	for offset < len(content) {
		elementData := content[offset:]
		val, n, osErr := ber.DecodeOctetString(elementData, opts...)
		if osErr != nil {
			return nil, fmt.Errorf("decoding element: %w", osErr)
		}
		if len(val) < 5 || len(val) > 7 {
			if constraintErr := ber.CheckDecodedLength(opts, fmt.Sprintf("element[%d]", len(result)), "SIZE (5..7)", len(val)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		result = append(result, GlobalCellId(val))
		if offset < 0 || offset >
			len(content) || n < 0 || n > len(content[offset:]) {
			return nil, fmt.Errorf("invalid BER content window")
		}

		offset += n
	}
	if len(result) < 1 || len(result) > 32 {
		if constraintErr := ber.CheckDecodedLength(opts, "CGIList", "SIZE (1..32)", len(result)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	decoded := &CGIList{Values: result}
	if ber.BERNeedsPreservation(opts) {
		var snapshotReports ber.ViolationLog
		snapshot, snapshotErr := MarshalBERCGIList(decoded, ber.WithConstraintTolerance(&snapshotReports))
		if snapshotErr != nil {
			return nil, snapshotErr
		}
		decoded.berOriginal_ = append([]byte(nil), data...)
		decoded.berSnapshot_ = snapshot
	}
	return decoded, nil
}

// MarshalBEREUTRANCGIList encodes a EUTRANCGIList list to BER.
func MarshalBEREUTRANCGIList(collection *EUTRANCGIList, opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	if collection == nil {
		return nil, fmt.Errorf("%w: required collection is nil", ber.ErrInvalidValue)
	}
	encoded, err := marshalBEREUTRANCGIList(collection, opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, collection.berOriginal_, collection.berSnapshot_, opts), nil
}
func marshalBEREUTRANCGIList(collection *EUTRANCGIList, opts ...ber.EncodeOption) ([]byte, error) {
	list := collection.Values
	if len(list) < 1 || len(list) > 32 {
		if constraintErr := ber.CheckEncodedLength(opts, "EUTRANCGIList", "SIZE (1..32)", len(list)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	var children []byte
	for elemIndex, elem := range list {
		if len(elem) < 7 || len(elem) > 7 {
			if constraintErr := ber.CheckEncodedLength(opts, fmt.Sprintf("element[%d]", elemIndex), "SIZE (7)", len(elem)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		encodedElem, encodeErr_encodedElem := ber.EncodeOctetString([]byte(elem))
		if encodeErr_encodedElem != nil {
			return nil, fmt.Errorf("encoding element: %w", encodeErr_encodedElem)
		}
		children = append(children, encodedElem...)
	}
	return ber.EncodeSequence(children)
}

// MarshalDEREUTRANCGIList encodes a EUTRANCGIList list to DER.
func MarshalDEREUTRANCGIList(collection *EUTRANCGIList) ([]byte, error) {
	if collection == nil {
		return nil, fmt.Errorf("%w: required collection is nil", ber.ErrInvalidValue)
	}
	list := collection.Values
	if len(list) < 1 || len(list) > 32 {
		if constraintErr := ber.CheckEncodedLength(nil, "EUTRANCGIList", "SIZE (1..32)", len(list)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	var children []byte
	for elemIndex, elem := range list {
		if len(elem) < 7 || len(elem) > 7 {
			if constraintErr := ber.CheckEncodedLength(nil, fmt.Sprintf("element[%d]", elemIndex), "SIZE (7)", len(elem)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		encodedElem, encodeErr_encodedElem := ber.EncodeOctetString([]byte(elem))
		if encodeErr_encodedElem != nil {
			return nil, fmt.Errorf("encoding element: %w", encodeErr_encodedElem)
		}
		children = append(children, encodedElem...)
	}
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding EUTRANCGIList as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBEREUTRANCGIList decodes a EUTRANCGIList list from BER.
func UnmarshalBEREUTRANCGIList(data []byte, opts ...ber.DecodeOption) (returnValue *EUTRANCGIList, returnErr error) {
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return nil, err
	}
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return nil, fmt.Errorf("decoding EUTRANCGIList: %w", err)
	}
	if total != len(data) {
		return nil, &ber.DecodeError{Offset: total, TypeName: "EUTRANCGIList", Cause: ber.ErrExtraData}
	}
	var result []EUTRANCGI
	offset := 0
	for offset < len(content) {
		elementData := content[offset:]
		val, n, osErr := ber.DecodeOctetString(elementData, opts...)
		if osErr != nil {
			return nil, fmt.Errorf("decoding element: %w", osErr)
		}
		if len(val) < 7 || len(val) > 7 {
			if constraintErr := ber.CheckDecodedLength(opts, fmt.Sprintf("element[%d]", len(result)), "SIZE (7)", len(val)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		result = append(result, EUTRANCGI(val))
		if offset < 0 || offset >
			len(content) || n < 0 || n > len(content[offset:]) {
			return nil, fmt.Errorf("invalid BER content window")
		}

		offset += n
	}
	if len(result) < 1 || len(result) > 32 {
		if constraintErr := ber.CheckDecodedLength(opts, "EUTRANCGIList", "SIZE (1..32)", len(result)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	decoded := &EUTRANCGIList{Values: result}
	if ber.BERNeedsPreservation(opts) {
		var snapshotReports ber.ViolationLog
		snapshot, snapshotErr := MarshalBEREUTRANCGIList(decoded, ber.WithConstraintTolerance(&snapshotReports))
		if snapshotErr != nil {
			return nil, snapshotErr
		}
		decoded.berOriginal_ = append([]byte(nil), data...)
		decoded.berSnapshot_ = snapshot
	}
	return decoded, nil
}

// MarshalBERRoutingAreaIdList encodes a RoutingAreaIdList list to BER.
func MarshalBERRoutingAreaIdList(collection *RoutingAreaIdList, opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	if collection == nil {
		return nil, fmt.Errorf("%w: required collection is nil", ber.ErrInvalidValue)
	}
	encoded, err := marshalBERRoutingAreaIdList(collection, opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, collection.berOriginal_, collection.berSnapshot_, opts), nil
}
func marshalBERRoutingAreaIdList(collection *RoutingAreaIdList, opts ...ber.EncodeOption) ([]byte, error) {
	list := collection.Values
	if len(list) < 1 || len(list) > 8 {
		if constraintErr := ber.CheckEncodedLength(opts, "RoutingAreaIdList", "SIZE (1..8)", len(list)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	var children []byte
	for elemIndex, elem := range list {
		if len(elem) < 6 || len(elem) > 6 {
			if constraintErr := ber.CheckEncodedLength(opts, fmt.Sprintf("element[%d]", elemIndex), "SIZE (6)", len(elem)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		encodedElem, encodeErr_encodedElem := ber.EncodeOctetString([]byte(elem))
		if encodeErr_encodedElem != nil {
			return nil, fmt.Errorf("encoding element: %w", encodeErr_encodedElem)
		}
		children = append(children, encodedElem...)
	}
	return ber.EncodeSequence(children)
}

// MarshalDERRoutingAreaIdList encodes a RoutingAreaIdList list to DER.
func MarshalDERRoutingAreaIdList(collection *RoutingAreaIdList) ([]byte, error) {
	if collection == nil {
		return nil, fmt.Errorf("%w: required collection is nil", ber.ErrInvalidValue)
	}
	list := collection.Values
	if len(list) < 1 || len(list) > 8 {
		if constraintErr := ber.CheckEncodedLength(nil, "RoutingAreaIdList", "SIZE (1..8)", len(list)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	var children []byte
	for elemIndex, elem := range list {
		if len(elem) < 6 || len(elem) > 6 {
			if constraintErr := ber.CheckEncodedLength(nil, fmt.Sprintf("element[%d]", elemIndex), "SIZE (6)", len(elem)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		encodedElem, encodeErr_encodedElem := ber.EncodeOctetString([]byte(elem))
		if encodeErr_encodedElem != nil {
			return nil, fmt.Errorf("encoding element: %w", encodeErr_encodedElem)
		}
		children = append(children, encodedElem...)
	}
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding RoutingAreaIdList as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBERRoutingAreaIdList decodes a RoutingAreaIdList list from BER.
func UnmarshalBERRoutingAreaIdList(data []byte, opts ...ber.DecodeOption) (returnValue *RoutingAreaIdList, returnErr error) {
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return nil, err
	}
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return nil, fmt.Errorf("decoding RoutingAreaIdList: %w", err)
	}
	if total != len(data) {
		return nil, &ber.DecodeError{Offset: total, TypeName: "RoutingAreaIdList", Cause: ber.ErrExtraData}
	}
	var result []RAIdentity
	offset := 0
	for offset < len(content) {
		elementData := content[offset:]
		val, n, osErr := ber.DecodeOctetString(elementData, opts...)
		if osErr != nil {
			return nil, fmt.Errorf("decoding element: %w", osErr)
		}
		if len(val) < 6 || len(val) > 6 {
			if constraintErr := ber.CheckDecodedLength(opts, fmt.Sprintf("element[%d]", len(result)), "SIZE (6)", len(val)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		result = append(result, RAIdentity(val))
		if offset < 0 || offset >
			len(content) || n < 0 || n > len(content[offset:]) {
			return nil, fmt.Errorf("invalid BER content window")
		}

		offset += n
	}
	if len(result) < 1 || len(result) > 8 {
		if constraintErr := ber.CheckDecodedLength(opts, "RoutingAreaIdList", "SIZE (1..8)", len(result)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	decoded := &RoutingAreaIdList{Values: result}
	if ber.BERNeedsPreservation(opts) {
		var snapshotReports ber.ViolationLog
		snapshot, snapshotErr := MarshalBERRoutingAreaIdList(decoded, ber.WithConstraintTolerance(&snapshotReports))
		if snapshotErr != nil {
			return nil, snapshotErr
		}
		decoded.berOriginal_ = append([]byte(nil), data...)
		decoded.berSnapshot_ = snapshot
	}
	return decoded, nil
}

// MarshalBERLocationAreaIdList encodes a LocationAreaIdList list to BER.
func MarshalBERLocationAreaIdList(collection *LocationAreaIdList, opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	if collection == nil {
		return nil, fmt.Errorf("%w: required collection is nil", ber.ErrInvalidValue)
	}
	encoded, err := marshalBERLocationAreaIdList(collection, opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, collection.berOriginal_, collection.berSnapshot_, opts), nil
}
func marshalBERLocationAreaIdList(collection *LocationAreaIdList, opts ...ber.EncodeOption) ([]byte, error) {
	list := collection.Values
	if len(list) < 1 || len(list) > 8 {
		if constraintErr := ber.CheckEncodedLength(opts, "LocationAreaIdList", "SIZE (1..8)", len(list)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	var children []byte
	for elemIndex, elem := range list {
		if len(elem) < 5 || len(elem) > 5 {
			if constraintErr := ber.CheckEncodedLength(opts, fmt.Sprintf("element[%d]", elemIndex), "SIZE (5)", len(elem)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		encodedElem, encodeErr_encodedElem := ber.EncodeOctetString([]byte(elem))
		if encodeErr_encodedElem != nil {
			return nil, fmt.Errorf("encoding element: %w", encodeErr_encodedElem)
		}
		children = append(children, encodedElem...)
	}
	return ber.EncodeSequence(children)
}

// MarshalDERLocationAreaIdList encodes a LocationAreaIdList list to DER.
func MarshalDERLocationAreaIdList(collection *LocationAreaIdList) ([]byte, error) {
	if collection == nil {
		return nil, fmt.Errorf("%w: required collection is nil", ber.ErrInvalidValue)
	}
	list := collection.Values
	if len(list) < 1 || len(list) > 8 {
		if constraintErr := ber.CheckEncodedLength(nil, "LocationAreaIdList", "SIZE (1..8)", len(list)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	var children []byte
	for elemIndex, elem := range list {
		if len(elem) < 5 || len(elem) > 5 {
			if constraintErr := ber.CheckEncodedLength(nil, fmt.Sprintf("element[%d]", elemIndex), "SIZE (5)", len(elem)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		encodedElem, encodeErr_encodedElem := ber.EncodeOctetString([]byte(elem))
		if encodeErr_encodedElem != nil {
			return nil, fmt.Errorf("encoding element: %w", encodeErr_encodedElem)
		}
		children = append(children, encodedElem...)
	}
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding LocationAreaIdList as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBERLocationAreaIdList decodes a LocationAreaIdList list from BER.
func UnmarshalBERLocationAreaIdList(data []byte, opts ...ber.DecodeOption) (returnValue *LocationAreaIdList, returnErr error) {
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return nil, err
	}
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return nil, fmt.Errorf("decoding LocationAreaIdList: %w", err)
	}
	if total != len(data) {
		return nil, &ber.DecodeError{Offset: total, TypeName: "LocationAreaIdList", Cause: ber.ErrExtraData}
	}
	var result []LAIFixedLength
	offset := 0
	for offset < len(content) {
		elementData := content[offset:]
		val, n, osErr := ber.DecodeOctetString(elementData, opts...)
		if osErr != nil {
			return nil, fmt.Errorf("decoding element: %w", osErr)
		}
		if len(val) < 5 || len(val) > 5 {
			if constraintErr := ber.CheckDecodedLength(opts, fmt.Sprintf("element[%d]", len(result)), "SIZE (5)", len(val)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		result = append(result, LAIFixedLength(val))
		if offset < 0 || offset >
			len(content) || n < 0 || n > len(content[offset:]) {
			return nil, fmt.Errorf("invalid BER content window")
		}

		offset += n
	}
	if len(result) < 1 || len(result) > 8 {
		if constraintErr := ber.CheckDecodedLength(opts, "LocationAreaIdList", "SIZE (1..8)", len(result)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	decoded := &LocationAreaIdList{Values: result}
	if ber.BERNeedsPreservation(opts) {
		var snapshotReports ber.ViolationLog
		snapshot, snapshotErr := MarshalBERLocationAreaIdList(decoded, ber.WithConstraintTolerance(&snapshotReports))
		if snapshotErr != nil {
			return nil, snapshotErr
		}
		decoded.berOriginal_ = append([]byte(nil), data...)
		decoded.berSnapshot_ = snapshot
	}
	return decoded, nil
}

// MarshalBERTrackingAreaIdList encodes a TrackingAreaIdList list to BER.
func MarshalBERTrackingAreaIdList(collection *TrackingAreaIdList, opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	if collection == nil {
		return nil, fmt.Errorf("%w: required collection is nil", ber.ErrInvalidValue)
	}
	encoded, err := marshalBERTrackingAreaIdList(collection, opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, collection.berOriginal_, collection.berSnapshot_, opts), nil
}
func marshalBERTrackingAreaIdList(collection *TrackingAreaIdList, opts ...ber.EncodeOption) ([]byte, error) {
	list := collection.Values
	if len(list) < 1 || len(list) > 8 {
		if constraintErr := ber.CheckEncodedLength(opts, "TrackingAreaIdList", "SIZE (1..8)", len(list)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	var children []byte
	for elemIndex, elem := range list {
		if len(elem) < 5 || len(elem) > 5 {
			if constraintErr := ber.CheckEncodedLength(opts, fmt.Sprintf("element[%d]", elemIndex), "SIZE (5)", len(elem)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		encodedElem, encodeErr_encodedElem := ber.EncodeOctetString([]byte(elem))
		if encodeErr_encodedElem != nil {
			return nil, fmt.Errorf("encoding element: %w", encodeErr_encodedElem)
		}
		children = append(children, encodedElem...)
	}
	return ber.EncodeSequence(children)
}

// MarshalDERTrackingAreaIdList encodes a TrackingAreaIdList list to DER.
func MarshalDERTrackingAreaIdList(collection *TrackingAreaIdList) ([]byte, error) {
	if collection == nil {
		return nil, fmt.Errorf("%w: required collection is nil", ber.ErrInvalidValue)
	}
	list := collection.Values
	if len(list) < 1 || len(list) > 8 {
		if constraintErr := ber.CheckEncodedLength(nil, "TrackingAreaIdList", "SIZE (1..8)", len(list)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	var children []byte
	for elemIndex, elem := range list {
		if len(elem) < 5 || len(elem) > 5 {
			if constraintErr := ber.CheckEncodedLength(nil, fmt.Sprintf("element[%d]", elemIndex), "SIZE (5)", len(elem)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		encodedElem, encodeErr_encodedElem := ber.EncodeOctetString([]byte(elem))
		if encodeErr_encodedElem != nil {
			return nil, fmt.Errorf("encoding element: %w", encodeErr_encodedElem)
		}
		children = append(children, encodedElem...)
	}
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding TrackingAreaIdList as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBERTrackingAreaIdList decodes a TrackingAreaIdList list from BER.
func UnmarshalBERTrackingAreaIdList(data []byte, opts ...ber.DecodeOption) (returnValue *TrackingAreaIdList, returnErr error) {
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return nil, err
	}
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return nil, fmt.Errorf("decoding TrackingAreaIdList: %w", err)
	}
	if total != len(data) {
		return nil, &ber.DecodeError{Offset: total, TypeName: "TrackingAreaIdList", Cause: ber.ErrExtraData}
	}
	var result []TAId
	offset := 0
	for offset < len(content) {
		elementData := content[offset:]
		val, n, osErr := ber.DecodeOctetString(elementData, opts...)
		if osErr != nil {
			return nil, fmt.Errorf("decoding element: %w", osErr)
		}
		if len(val) < 5 || len(val) > 5 {
			if constraintErr := ber.CheckDecodedLength(opts, fmt.Sprintf("element[%d]", len(result)), "SIZE (5)", len(val)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		result = append(result, TAId(val))
		if offset < 0 || offset >
			len(content) || n < 0 || n > len(content[offset:]) {
			return nil, fmt.Errorf("invalid BER content window")
		}

		offset += n
	}
	if len(result) < 1 || len(result) > 8 {
		if constraintErr := ber.CheckDecodedLength(opts, "TrackingAreaIdList", "SIZE (1..8)", len(result)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	decoded := &TrackingAreaIdList{Values: result}
	if ber.BERNeedsPreservation(opts) {
		var snapshotReports ber.ViolationLog
		snapshot, snapshotErr := MarshalBERTrackingAreaIdList(decoded, ber.WithConstraintTolerance(&snapshotReports))
		if snapshotErr != nil {
			return nil, snapshotErr
		}
		decoded.berOriginal_ = append([]byte(nil), data...)
		decoded.berSnapshot_ = snapshot
	}
	return decoded, nil
}

// MarshalBER encodes TraceDepthList to BER format.
func (v *TraceDepthList) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: TraceDepthList receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *TraceDepthList) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if v.MscSTraceDepth != nil {
		enc_mscstracedepth := ber.EncodeEnumerated(int64(*v.MscSTraceDepth))
		retagged_enc_mscstracedepth, tagErr_enc_mscstracedepth := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_mscstracedepth)
		if tagErr_enc_mscstracedepth != nil {
			return nil, fmt.Errorf("encoding msc-s-TraceDepth: %w", tagErr_enc_mscstracedepth)
		}
		enc_mscstracedepth = retagged_enc_mscstracedepth
		children = append(children, enc_mscstracedepth...)
	}
	if v.MgwTraceDepth != nil {
		enc_mgwtracedepth := ber.EncodeEnumerated(int64(*v.MgwTraceDepth))
		retagged_enc_mgwtracedepth, tagErr_enc_mgwtracedepth := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_mgwtracedepth)
		if tagErr_enc_mgwtracedepth != nil {
			return nil, fmt.Errorf("encoding mgw-TraceDepth: %w", tagErr_enc_mgwtracedepth)
		}
		enc_mgwtracedepth = retagged_enc_mgwtracedepth
		children = append(children, enc_mgwtracedepth...)
	}
	if v.SgsnTraceDepth != nil {
		enc_sgsntracedepth := ber.EncodeEnumerated(int64(*v.SgsnTraceDepth))
		retagged_enc_sgsntracedepth, tagErr_enc_sgsntracedepth := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_sgsntracedepth)
		if tagErr_enc_sgsntracedepth != nil {
			return nil, fmt.Errorf("encoding sgsn-TraceDepth: %w", tagErr_enc_sgsntracedepth)
		}
		enc_sgsntracedepth = retagged_enc_sgsntracedepth
		children = append(children, enc_sgsntracedepth...)
	}
	if v.GgsnTraceDepth != nil {
		enc_ggsntracedepth := ber.EncodeEnumerated(int64(*v.GgsnTraceDepth))
		retagged_enc_ggsntracedepth, tagErr_enc_ggsntracedepth := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, enc_ggsntracedepth)
		if tagErr_enc_ggsntracedepth != nil {
			return nil, fmt.Errorf("encoding ggsn-TraceDepth: %w", tagErr_enc_ggsntracedepth)
		}
		enc_ggsntracedepth = retagged_enc_ggsntracedepth
		children = append(children, enc_ggsntracedepth...)
	}
	if v.RncTraceDepth != nil {
		enc_rnctracedepth := ber.EncodeEnumerated(int64(*v.RncTraceDepth))
		retagged_enc_rnctracedepth, tagErr_enc_rnctracedepth := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, enc_rnctracedepth)
		if tagErr_enc_rnctracedepth != nil {
			return nil, fmt.Errorf("encoding rnc-TraceDepth: %w", tagErr_enc_rnctracedepth)
		}
		enc_rnctracedepth = retagged_enc_rnctracedepth
		children = append(children, enc_rnctracedepth...)
	}
	if v.BmscTraceDepth != nil {
		enc_bmsctracedepth := ber.EncodeEnumerated(int64(*v.BmscTraceDepth))
		retagged_enc_bmsctracedepth, tagErr_enc_bmsctracedepth := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 5, enc_bmsctracedepth)
		if tagErr_enc_bmsctracedepth != nil {
			return nil, fmt.Errorf("encoding bmsc-TraceDepth: %w", tagErr_enc_bmsctracedepth)
		}
		enc_bmsctracedepth = retagged_enc_bmsctracedepth
		children = append(children, enc_bmsctracedepth...)
	}
	if v.MmeTraceDepth != nil {
		enc_mmetracedepth := ber.EncodeEnumerated(int64(*v.MmeTraceDepth))
		retagged_enc_mmetracedepth, tagErr_enc_mmetracedepth := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 6, enc_mmetracedepth)
		if tagErr_enc_mmetracedepth != nil {
			return nil, fmt.Errorf("encoding mme-TraceDepth: %w", tagErr_enc_mmetracedepth)
		}
		enc_mmetracedepth = retagged_enc_mmetracedepth
		children = append(children, enc_mmetracedepth...)
	}
	if v.SgwTraceDepth != nil {
		enc_sgwtracedepth := ber.EncodeEnumerated(int64(*v.SgwTraceDepth))
		retagged_enc_sgwtracedepth, tagErr_enc_sgwtracedepth := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 7, enc_sgwtracedepth)
		if tagErr_enc_sgwtracedepth != nil {
			return nil, fmt.Errorf("encoding sgw-TraceDepth: %w", tagErr_enc_sgwtracedepth)
		}
		enc_sgwtracedepth = retagged_enc_sgwtracedepth
		children = append(children, enc_sgwtracedepth...)
	}
	if v.PgwTraceDepth != nil {
		enc_pgwtracedepth := ber.EncodeEnumerated(int64(*v.PgwTraceDepth))
		retagged_enc_pgwtracedepth, tagErr_enc_pgwtracedepth := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 8, enc_pgwtracedepth)
		if tagErr_enc_pgwtracedepth != nil {
			return nil, fmt.Errorf("encoding pgw-TraceDepth: %w", tagErr_enc_pgwtracedepth)
		}
		enc_pgwtracedepth = retagged_enc_pgwtracedepth
		children = append(children, enc_pgwtracedepth...)
	}
	if v.ENBTraceDepth != nil {
		enc_enbtracedepth := ber.EncodeEnumerated(int64(*v.ENBTraceDepth))
		retagged_enc_enbtracedepth, tagErr_enc_enbtracedepth := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 9, enc_enbtracedepth)
		if tagErr_enc_enbtracedepth != nil {
			return nil, fmt.Errorf("encoding eNB-TraceDepth: %w", tagErr_enc_enbtracedepth)
		}
		enc_enbtracedepth = retagged_enc_enbtracedepth
		children = append(children, enc_enbtracedepth...)
	}
	if v.MscSTraceDepthExtension != nil {
		enc_mscstracedepthextension := ber.EncodeEnumerated(int64(*v.MscSTraceDepthExtension))
		retagged_enc_mscstracedepthextension, tagErr_enc_mscstracedepthextension := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 10, enc_mscstracedepthextension)
		if tagErr_enc_mscstracedepthextension != nil {
			return nil, fmt.Errorf("encoding msc-s-TraceDepthExtension: %w", tagErr_enc_mscstracedepthextension)
		}
		enc_mscstracedepthextension = retagged_enc_mscstracedepthextension
		children = append(children, enc_mscstracedepthextension...)
	}
	if v.MgwTraceDepthExtension != nil {
		enc_mgwtracedepthextension := ber.EncodeEnumerated(int64(*v.MgwTraceDepthExtension))
		retagged_enc_mgwtracedepthextension, tagErr_enc_mgwtracedepthextension := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 11, enc_mgwtracedepthextension)
		if tagErr_enc_mgwtracedepthextension != nil {
			return nil, fmt.Errorf("encoding mgw-TraceDepthExtension: %w", tagErr_enc_mgwtracedepthextension)
		}
		enc_mgwtracedepthextension = retagged_enc_mgwtracedepthextension
		children = append(children, enc_mgwtracedepthextension...)
	}
	if v.SgsnTraceDepthExtension != nil {
		enc_sgsntracedepthextension := ber.EncodeEnumerated(int64(*v.SgsnTraceDepthExtension))
		retagged_enc_sgsntracedepthextension, tagErr_enc_sgsntracedepthextension := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 12, enc_sgsntracedepthextension)
		if tagErr_enc_sgsntracedepthextension != nil {
			return nil, fmt.Errorf("encoding sgsn-TraceDepthExtension: %w", tagErr_enc_sgsntracedepthextension)
		}
		enc_sgsntracedepthextension = retagged_enc_sgsntracedepthextension
		children = append(children, enc_sgsntracedepthextension...)
	}
	if v.GgsnTraceDepthExtension != nil {
		enc_ggsntracedepthextension := ber.EncodeEnumerated(int64(*v.GgsnTraceDepthExtension))
		retagged_enc_ggsntracedepthextension, tagErr_enc_ggsntracedepthextension := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 13, enc_ggsntracedepthextension)
		if tagErr_enc_ggsntracedepthextension != nil {
			return nil, fmt.Errorf("encoding ggsn-TraceDepthExtension: %w", tagErr_enc_ggsntracedepthextension)
		}
		enc_ggsntracedepthextension = retagged_enc_ggsntracedepthextension
		children = append(children, enc_ggsntracedepthextension...)
	}
	if v.RncTraceDepthExtension != nil {
		enc_rnctracedepthextension := ber.EncodeEnumerated(int64(*v.RncTraceDepthExtension))
		retagged_enc_rnctracedepthextension, tagErr_enc_rnctracedepthextension := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 14, enc_rnctracedepthextension)
		if tagErr_enc_rnctracedepthextension != nil {
			return nil, fmt.Errorf("encoding rnc-TraceDepthExtension: %w", tagErr_enc_rnctracedepthextension)
		}
		enc_rnctracedepthextension = retagged_enc_rnctracedepthextension
		children = append(children, enc_rnctracedepthextension...)
	}
	if v.BmscTraceDepthExtension != nil {
		enc_bmsctracedepthextension := ber.EncodeEnumerated(int64(*v.BmscTraceDepthExtension))
		retagged_enc_bmsctracedepthextension, tagErr_enc_bmsctracedepthextension := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 15, enc_bmsctracedepthextension)
		if tagErr_enc_bmsctracedepthextension != nil {
			return nil, fmt.Errorf("encoding bmsc-TraceDepthExtension: %w", tagErr_enc_bmsctracedepthextension)
		}
		enc_bmsctracedepthextension = retagged_enc_bmsctracedepthextension
		children = append(children, enc_bmsctracedepthextension...)
	}
	if v.MmeTraceDepthExtension != nil {
		enc_mmetracedepthextension := ber.EncodeEnumerated(int64(*v.MmeTraceDepthExtension))
		retagged_enc_mmetracedepthextension, tagErr_enc_mmetracedepthextension := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 16, enc_mmetracedepthextension)
		if tagErr_enc_mmetracedepthextension != nil {
			return nil, fmt.Errorf("encoding mme-TraceDepthExtension: %w", tagErr_enc_mmetracedepthextension)
		}
		enc_mmetracedepthextension = retagged_enc_mmetracedepthextension
		children = append(children, enc_mmetracedepthextension...)
	}
	if v.SgwTraceDepthExtension != nil {
		enc_sgwtracedepthextension := ber.EncodeEnumerated(int64(*v.SgwTraceDepthExtension))
		retagged_enc_sgwtracedepthextension, tagErr_enc_sgwtracedepthextension := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 17, enc_sgwtracedepthextension)
		if tagErr_enc_sgwtracedepthextension != nil {
			return nil, fmt.Errorf("encoding sgw-TraceDepthExtension: %w", tagErr_enc_sgwtracedepthextension)
		}
		enc_sgwtracedepthextension = retagged_enc_sgwtracedepthextension
		children = append(children, enc_sgwtracedepthextension...)
	}
	if v.PgwTraceDepthExtension != nil {
		enc_pgwtracedepthextension := ber.EncodeEnumerated(int64(*v.PgwTraceDepthExtension))
		retagged_enc_pgwtracedepthextension, tagErr_enc_pgwtracedepthextension := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 18, enc_pgwtracedepthextension)
		if tagErr_enc_pgwtracedepthextension != nil {
			return nil, fmt.Errorf("encoding pgw-TraceDepthExtension: %w", tagErr_enc_pgwtracedepthextension)
		}
		enc_pgwtracedepthextension = retagged_enc_pgwtracedepthextension
		children = append(children, enc_pgwtracedepthextension...)
	}
	if v.ENBTraceDepthExtension != nil {
		enc_enbtracedepthextension := ber.EncodeEnumerated(int64(*v.ENBTraceDepthExtension))
		retagged_enc_enbtracedepthextension, tagErr_enc_enbtracedepthextension := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 19, enc_enbtracedepthextension)
		if tagErr_enc_enbtracedepthextension != nil {
			return nil, fmt.Errorf("encoding eNB-TraceDepthExtension: %w", tagErr_enc_enbtracedepthextension)
		}
		enc_enbtracedepthextension = retagged_enc_enbtracedepthextension
		children = append(children, enc_enbtracedepthextension...)
	}
	for i, ext := range v.ExtData_ {
		_, n, _, extErr := ber.DecodeEncodedTLV(ext)
		if extErr != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, extErr)
		}
		if n != len(ext) {
			return nil, fmt.Errorf("encoding extension %d: %w", i, ber.ErrExtraData)
		}
		children = append(children, ext...)
	}
	return ber.EncodeSequence(children)
}

// MarshalDER encodes TraceDepthList to DER format.
func (v *TraceDepthList) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: TraceDepthList receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if v.MscSTraceDepth != nil {
		enc_mscstracedepth := ber.EncodeEnumerated(int64(*v.MscSTraceDepth))
		retagged_enc_mscstracedepth, tagErr_enc_mscstracedepth := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_mscstracedepth)
		if tagErr_enc_mscstracedepth != nil {
			return nil, fmt.Errorf("encoding msc-s-TraceDepth: %w", tagErr_enc_mscstracedepth)
		}
		enc_mscstracedepth = retagged_enc_mscstracedepth
		children = append(children, enc_mscstracedepth...)
	}
	if v.MgwTraceDepth != nil {
		enc_mgwtracedepth := ber.EncodeEnumerated(int64(*v.MgwTraceDepth))
		retagged_enc_mgwtracedepth, tagErr_enc_mgwtracedepth := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_mgwtracedepth)
		if tagErr_enc_mgwtracedepth != nil {
			return nil, fmt.Errorf("encoding mgw-TraceDepth: %w", tagErr_enc_mgwtracedepth)
		}
		enc_mgwtracedepth = retagged_enc_mgwtracedepth
		children = append(children, enc_mgwtracedepth...)
	}
	if v.SgsnTraceDepth != nil {
		enc_sgsntracedepth := ber.EncodeEnumerated(int64(*v.SgsnTraceDepth))
		retagged_enc_sgsntracedepth, tagErr_enc_sgsntracedepth := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_sgsntracedepth)
		if tagErr_enc_sgsntracedepth != nil {
			return nil, fmt.Errorf("encoding sgsn-TraceDepth: %w", tagErr_enc_sgsntracedepth)
		}
		enc_sgsntracedepth = retagged_enc_sgsntracedepth
		children = append(children, enc_sgsntracedepth...)
	}
	if v.GgsnTraceDepth != nil {
		enc_ggsntracedepth := ber.EncodeEnumerated(int64(*v.GgsnTraceDepth))
		retagged_enc_ggsntracedepth, tagErr_enc_ggsntracedepth := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, enc_ggsntracedepth)
		if tagErr_enc_ggsntracedepth != nil {
			return nil, fmt.Errorf("encoding ggsn-TraceDepth: %w", tagErr_enc_ggsntracedepth)
		}
		enc_ggsntracedepth = retagged_enc_ggsntracedepth
		children = append(children, enc_ggsntracedepth...)
	}
	if v.RncTraceDepth != nil {
		enc_rnctracedepth := ber.EncodeEnumerated(int64(*v.RncTraceDepth))
		retagged_enc_rnctracedepth, tagErr_enc_rnctracedepth := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, enc_rnctracedepth)
		if tagErr_enc_rnctracedepth != nil {
			return nil, fmt.Errorf("encoding rnc-TraceDepth: %w", tagErr_enc_rnctracedepth)
		}
		enc_rnctracedepth = retagged_enc_rnctracedepth
		children = append(children, enc_rnctracedepth...)
	}
	if v.BmscTraceDepth != nil {
		enc_bmsctracedepth := ber.EncodeEnumerated(int64(*v.BmscTraceDepth))
		retagged_enc_bmsctracedepth, tagErr_enc_bmsctracedepth := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 5, enc_bmsctracedepth)
		if tagErr_enc_bmsctracedepth != nil {
			return nil, fmt.Errorf("encoding bmsc-TraceDepth: %w", tagErr_enc_bmsctracedepth)
		}
		enc_bmsctracedepth = retagged_enc_bmsctracedepth
		children = append(children, enc_bmsctracedepth...)
	}
	if v.MmeTraceDepth != nil {
		enc_mmetracedepth := ber.EncodeEnumerated(int64(*v.MmeTraceDepth))
		retagged_enc_mmetracedepth, tagErr_enc_mmetracedepth := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 6, enc_mmetracedepth)
		if tagErr_enc_mmetracedepth != nil {
			return nil, fmt.Errorf("encoding mme-TraceDepth: %w", tagErr_enc_mmetracedepth)
		}
		enc_mmetracedepth = retagged_enc_mmetracedepth
		children = append(children, enc_mmetracedepth...)
	}
	if v.SgwTraceDepth != nil {
		enc_sgwtracedepth := ber.EncodeEnumerated(int64(*v.SgwTraceDepth))
		retagged_enc_sgwtracedepth, tagErr_enc_sgwtracedepth := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 7, enc_sgwtracedepth)
		if tagErr_enc_sgwtracedepth != nil {
			return nil, fmt.Errorf("encoding sgw-TraceDepth: %w", tagErr_enc_sgwtracedepth)
		}
		enc_sgwtracedepth = retagged_enc_sgwtracedepth
		children = append(children, enc_sgwtracedepth...)
	}
	if v.PgwTraceDepth != nil {
		enc_pgwtracedepth := ber.EncodeEnumerated(int64(*v.PgwTraceDepth))
		retagged_enc_pgwtracedepth, tagErr_enc_pgwtracedepth := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 8, enc_pgwtracedepth)
		if tagErr_enc_pgwtracedepth != nil {
			return nil, fmt.Errorf("encoding pgw-TraceDepth: %w", tagErr_enc_pgwtracedepth)
		}
		enc_pgwtracedepth = retagged_enc_pgwtracedepth
		children = append(children, enc_pgwtracedepth...)
	}
	if v.ENBTraceDepth != nil {
		enc_enbtracedepth := ber.EncodeEnumerated(int64(*v.ENBTraceDepth))
		retagged_enc_enbtracedepth, tagErr_enc_enbtracedepth := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 9, enc_enbtracedepth)
		if tagErr_enc_enbtracedepth != nil {
			return nil, fmt.Errorf("encoding eNB-TraceDepth: %w", tagErr_enc_enbtracedepth)
		}
		enc_enbtracedepth = retagged_enc_enbtracedepth
		children = append(children, enc_enbtracedepth...)
	}
	if v.MscSTraceDepthExtension != nil {
		enc_mscstracedepthextension := ber.EncodeEnumerated(int64(*v.MscSTraceDepthExtension))
		retagged_enc_mscstracedepthextension, tagErr_enc_mscstracedepthextension := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 10, enc_mscstracedepthextension)
		if tagErr_enc_mscstracedepthextension != nil {
			return nil, fmt.Errorf("encoding msc-s-TraceDepthExtension: %w", tagErr_enc_mscstracedepthextension)
		}
		enc_mscstracedepthextension = retagged_enc_mscstracedepthextension
		children = append(children, enc_mscstracedepthextension...)
	}
	if v.MgwTraceDepthExtension != nil {
		enc_mgwtracedepthextension := ber.EncodeEnumerated(int64(*v.MgwTraceDepthExtension))
		retagged_enc_mgwtracedepthextension, tagErr_enc_mgwtracedepthextension := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 11, enc_mgwtracedepthextension)
		if tagErr_enc_mgwtracedepthextension != nil {
			return nil, fmt.Errorf("encoding mgw-TraceDepthExtension: %w", tagErr_enc_mgwtracedepthextension)
		}
		enc_mgwtracedepthextension = retagged_enc_mgwtracedepthextension
		children = append(children, enc_mgwtracedepthextension...)
	}
	if v.SgsnTraceDepthExtension != nil {
		enc_sgsntracedepthextension := ber.EncodeEnumerated(int64(*v.SgsnTraceDepthExtension))
		retagged_enc_sgsntracedepthextension, tagErr_enc_sgsntracedepthextension := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 12, enc_sgsntracedepthextension)
		if tagErr_enc_sgsntracedepthextension != nil {
			return nil, fmt.Errorf("encoding sgsn-TraceDepthExtension: %w", tagErr_enc_sgsntracedepthextension)
		}
		enc_sgsntracedepthextension = retagged_enc_sgsntracedepthextension
		children = append(children, enc_sgsntracedepthextension...)
	}
	if v.GgsnTraceDepthExtension != nil {
		enc_ggsntracedepthextension := ber.EncodeEnumerated(int64(*v.GgsnTraceDepthExtension))
		retagged_enc_ggsntracedepthextension, tagErr_enc_ggsntracedepthextension := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 13, enc_ggsntracedepthextension)
		if tagErr_enc_ggsntracedepthextension != nil {
			return nil, fmt.Errorf("encoding ggsn-TraceDepthExtension: %w", tagErr_enc_ggsntracedepthextension)
		}
		enc_ggsntracedepthextension = retagged_enc_ggsntracedepthextension
		children = append(children, enc_ggsntracedepthextension...)
	}
	if v.RncTraceDepthExtension != nil {
		enc_rnctracedepthextension := ber.EncodeEnumerated(int64(*v.RncTraceDepthExtension))
		retagged_enc_rnctracedepthextension, tagErr_enc_rnctracedepthextension := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 14, enc_rnctracedepthextension)
		if tagErr_enc_rnctracedepthextension != nil {
			return nil, fmt.Errorf("encoding rnc-TraceDepthExtension: %w", tagErr_enc_rnctracedepthextension)
		}
		enc_rnctracedepthextension = retagged_enc_rnctracedepthextension
		children = append(children, enc_rnctracedepthextension...)
	}
	if v.BmscTraceDepthExtension != nil {
		enc_bmsctracedepthextension := ber.EncodeEnumerated(int64(*v.BmscTraceDepthExtension))
		retagged_enc_bmsctracedepthextension, tagErr_enc_bmsctracedepthextension := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 15, enc_bmsctracedepthextension)
		if tagErr_enc_bmsctracedepthextension != nil {
			return nil, fmt.Errorf("encoding bmsc-TraceDepthExtension: %w", tagErr_enc_bmsctracedepthextension)
		}
		enc_bmsctracedepthextension = retagged_enc_bmsctracedepthextension
		children = append(children, enc_bmsctracedepthextension...)
	}
	if v.MmeTraceDepthExtension != nil {
		enc_mmetracedepthextension := ber.EncodeEnumerated(int64(*v.MmeTraceDepthExtension))
		retagged_enc_mmetracedepthextension, tagErr_enc_mmetracedepthextension := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 16, enc_mmetracedepthextension)
		if tagErr_enc_mmetracedepthextension != nil {
			return nil, fmt.Errorf("encoding mme-TraceDepthExtension: %w", tagErr_enc_mmetracedepthextension)
		}
		enc_mmetracedepthextension = retagged_enc_mmetracedepthextension
		children = append(children, enc_mmetracedepthextension...)
	}
	if v.SgwTraceDepthExtension != nil {
		enc_sgwtracedepthextension := ber.EncodeEnumerated(int64(*v.SgwTraceDepthExtension))
		retagged_enc_sgwtracedepthextension, tagErr_enc_sgwtracedepthextension := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 17, enc_sgwtracedepthextension)
		if tagErr_enc_sgwtracedepthextension != nil {
			return nil, fmt.Errorf("encoding sgw-TraceDepthExtension: %w", tagErr_enc_sgwtracedepthextension)
		}
		enc_sgwtracedepthextension = retagged_enc_sgwtracedepthextension
		children = append(children, enc_sgwtracedepthextension...)
	}
	if v.PgwTraceDepthExtension != nil {
		enc_pgwtracedepthextension := ber.EncodeEnumerated(int64(*v.PgwTraceDepthExtension))
		retagged_enc_pgwtracedepthextension, tagErr_enc_pgwtracedepthextension := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 18, enc_pgwtracedepthextension)
		if tagErr_enc_pgwtracedepthextension != nil {
			return nil, fmt.Errorf("encoding pgw-TraceDepthExtension: %w", tagErr_enc_pgwtracedepthextension)
		}
		enc_pgwtracedepthextension = retagged_enc_pgwtracedepthextension
		children = append(children, enc_pgwtracedepthextension...)
	}
	if v.ENBTraceDepthExtension != nil {
		enc_enbtracedepthextension := ber.EncodeEnumerated(int64(*v.ENBTraceDepthExtension))
		retagged_enc_enbtracedepthextension, tagErr_enc_enbtracedepthextension := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 19, enc_enbtracedepthextension)
		if tagErr_enc_enbtracedepthextension != nil {
			return nil, fmt.Errorf("encoding eNB-TraceDepthExtension: %w", tagErr_enc_enbtracedepthextension)
		}
		enc_enbtracedepthextension = retagged_enc_enbtracedepthextension
		children = append(children, enc_enbtracedepthextension...)
	}
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDEREncodedElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
		children = append(children, ext...)
	}
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding TraceDepthList as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes TraceDepthList from BER/DER format.
func (v *TraceDepthList) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: TraceDepthList destination is nil", ber.ErrInvalidValue)
	}
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = TraceDepthList{}
	defer func() {
		if returnErr != nil || !ber.BERNeedsPreservation(opts) {
			return
		}
		var snapshotReports ber.ViolationLog
		snapshot, snapshotErr := v.marshalBER(ber.WithConstraintTolerance(&snapshotReports))
		if snapshotErr != nil {
			returnErr = snapshotErr
			return
		}
		v.berOriginal_ = append([]byte(nil), data...)
		v.berSnapshot_ = snapshot
	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("decoding TraceDepthList SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "TraceDepthList", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode msc-s-TraceDepth
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
				decodedTag_mscstracedepth, n_mscstracedepth, rawVal_mscstracedepth, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding msc-s-TraceDepth: %w", err)
				}
				if decodedTag_mscstracedepth.Class != tag.ClassContextSpecific || decodedTag_mscstracedepth.Number != 0 || decodedTag_mscstracedepth.Constructed != false {
					return fmt.Errorf("decoding msc-s-TraceDepth: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_mscstracedepth)
				}
				decVal_mscstracedepth, intErr := ber.DecodeEnumeratedValue(rawVal_mscstracedepth)
				if intErr != nil {
					return fmt.Errorf("decoding msc-s-TraceDepth: %w", intErr)
				}
				tmp_mscstracedepth := TraceDepth(decVal_mscstracedepth)
				v.MscSTraceDepth = &tmp_mscstracedepth
				if offset > len(content) || n_mscstracedepth < 0 || n_mscstracedepth > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_mscstracedepth
			}
		}
	}
	// Decode mgw-TraceDepth
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
				decodedTag_mgwtracedepth, n_mgwtracedepth, rawVal_mgwtracedepth, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding mgw-TraceDepth: %w", err)
				}
				if decodedTag_mgwtracedepth.Class != tag.ClassContextSpecific || decodedTag_mgwtracedepth.Number != 1 || decodedTag_mgwtracedepth.Constructed != false {
					return fmt.Errorf("decoding mgw-TraceDepth: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_mgwtracedepth)
				}
				decVal_mgwtracedepth, intErr := ber.DecodeEnumeratedValue(rawVal_mgwtracedepth)
				if intErr != nil {
					return fmt.Errorf("decoding mgw-TraceDepth: %w", intErr)
				}
				tmp_mgwtracedepth := TraceDepth(decVal_mgwtracedepth)
				v.MgwTraceDepth = &tmp_mgwtracedepth
				if offset < 0 || offset >
					len(content) || n_mgwtracedepth < 0 || n_mgwtracedepth >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_mgwtracedepth
			}
		}
	}
	// Decode sgsn-TraceDepth
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2 {
				decodedTag_sgsntracedepth, n_sgsntracedepth, rawVal_sgsntracedepth, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding sgsn-TraceDepth: %w", err)
				}
				if decodedTag_sgsntracedepth.Class != tag.ClassContextSpecific || decodedTag_sgsntracedepth.Number != 2 || decodedTag_sgsntracedepth.Constructed != false {
					return fmt.Errorf("decoding sgsn-TraceDepth: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_sgsntracedepth)
				}
				decVal_sgsntracedepth, intErr := ber.DecodeEnumeratedValue(rawVal_sgsntracedepth)
				if intErr != nil {
					return fmt.Errorf("decoding sgsn-TraceDepth: %w", intErr)
				}
				tmp_sgsntracedepth := TraceDepth(decVal_sgsntracedepth)
				v.SgsnTraceDepth = &tmp_sgsntracedepth
				if offset < 0 || offset >
					len(content) || n_sgsntracedepth < 0 || n_sgsntracedepth >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_sgsntracedepth
			}
		}
	}
	// Decode ggsn-TraceDepth
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3 {
				decodedTag_ggsntracedepth, n_ggsntracedepth, rawVal_ggsntracedepth, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding ggsn-TraceDepth: %w", err)
				}
				if decodedTag_ggsntracedepth.Class != tag.ClassContextSpecific || decodedTag_ggsntracedepth.Number != 3 || decodedTag_ggsntracedepth.Constructed != false {
					return fmt.Errorf("decoding ggsn-TraceDepth: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_ggsntracedepth)
				}
				decVal_ggsntracedepth, intErr := ber.DecodeEnumeratedValue(rawVal_ggsntracedepth)
				if intErr != nil {
					return fmt.Errorf("decoding ggsn-TraceDepth: %w", intErr)
				}
				tmp_ggsntracedepth := TraceDepth(decVal_ggsntracedepth)
				v.GgsnTraceDepth = &tmp_ggsntracedepth
				if offset < 0 || offset >
					len(content) || n_ggsntracedepth < 0 || n_ggsntracedepth >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_ggsntracedepth
			}
		}
	}
	// Decode rnc-TraceDepth
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4 {
				decodedTag_rnctracedepth, n_rnctracedepth, rawVal_rnctracedepth, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding rnc-TraceDepth: %w", err)
				}
				if decodedTag_rnctracedepth.Class != tag.ClassContextSpecific || decodedTag_rnctracedepth.Number != 4 || decodedTag_rnctracedepth.Constructed != false {
					return fmt.Errorf("decoding rnc-TraceDepth: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_rnctracedepth)
				}
				decVal_rnctracedepth, intErr := ber.DecodeEnumeratedValue(rawVal_rnctracedepth)
				if intErr != nil {
					return fmt.Errorf("decoding rnc-TraceDepth: %w", intErr)
				}
				tmp_rnctracedepth := TraceDepth(decVal_rnctracedepth)
				v.RncTraceDepth = &tmp_rnctracedepth
				if offset < 0 || offset >
					len(content) || n_rnctracedepth < 0 || n_rnctracedepth >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_rnctracedepth
			}
		}
	}
	// Decode bmsc-TraceDepth
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 5 {
				decodedTag_bmsctracedepth, n_bmsctracedepth, rawVal_bmsctracedepth, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding bmsc-TraceDepth: %w", err)
				}
				if decodedTag_bmsctracedepth.Class != tag.ClassContextSpecific || decodedTag_bmsctracedepth.Number != 5 || decodedTag_bmsctracedepth.Constructed != false {
					return fmt.Errorf("decoding bmsc-TraceDepth: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_bmsctracedepth)
				}
				decVal_bmsctracedepth, intErr := ber.DecodeEnumeratedValue(rawVal_bmsctracedepth)
				if intErr != nil {
					return fmt.Errorf("decoding bmsc-TraceDepth: %w", intErr)
				}
				tmp_bmsctracedepth := TraceDepth(decVal_bmsctracedepth)
				v.BmscTraceDepth = &tmp_bmsctracedepth
				if offset < 0 || offset >
					len(content) || n_bmsctracedepth < 0 || n_bmsctracedepth >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_bmsctracedepth
			}
		}
	}
	// Decode mme-TraceDepth
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 6 {
				decodedTag_mmetracedepth, n_mmetracedepth, rawVal_mmetracedepth, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding mme-TraceDepth: %w", err)
				}
				if decodedTag_mmetracedepth.Class != tag.ClassContextSpecific || decodedTag_mmetracedepth.Number != 6 || decodedTag_mmetracedepth.Constructed != false {
					return fmt.Errorf("decoding mme-TraceDepth: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_mmetracedepth)
				}
				decVal_mmetracedepth, intErr := ber.DecodeEnumeratedValue(rawVal_mmetracedepth)
				if intErr != nil {
					return fmt.Errorf("decoding mme-TraceDepth: %w", intErr)
				}
				tmp_mmetracedepth := TraceDepth(decVal_mmetracedepth)
				v.MmeTraceDepth = &tmp_mmetracedepth
				if offset < 0 || offset >
					len(content) || n_mmetracedepth < 0 || n_mmetracedepth >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_mmetracedepth
			}
		}
	}
	// Decode sgw-TraceDepth
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 7 {
				decodedTag_sgwtracedepth, n_sgwtracedepth, rawVal_sgwtracedepth, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding sgw-TraceDepth: %w", err)
				}
				if decodedTag_sgwtracedepth.Class != tag.ClassContextSpecific || decodedTag_sgwtracedepth.Number != 7 || decodedTag_sgwtracedepth.Constructed != false {
					return fmt.Errorf("decoding sgw-TraceDepth: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_sgwtracedepth)
				}
				decVal_sgwtracedepth, intErr := ber.DecodeEnumeratedValue(rawVal_sgwtracedepth)
				if intErr != nil {
					return fmt.Errorf("decoding sgw-TraceDepth: %w", intErr)
				}
				tmp_sgwtracedepth := TraceDepth(decVal_sgwtracedepth)
				v.SgwTraceDepth = &tmp_sgwtracedepth
				if offset < 0 || offset >
					len(content) || n_sgwtracedepth < 0 || n_sgwtracedepth >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_sgwtracedepth
			}
		}
	}
	// Decode pgw-TraceDepth
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 8 {
				decodedTag_pgwtracedepth, n_pgwtracedepth, rawVal_pgwtracedepth, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding pgw-TraceDepth: %w", err)
				}
				if decodedTag_pgwtracedepth.Class != tag.ClassContextSpecific || decodedTag_pgwtracedepth.Number != 8 || decodedTag_pgwtracedepth.Constructed != false {
					return fmt.Errorf("decoding pgw-TraceDepth: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_pgwtracedepth)
				}
				decVal_pgwtracedepth, intErr := ber.DecodeEnumeratedValue(rawVal_pgwtracedepth)
				if intErr != nil {
					return fmt.Errorf("decoding pgw-TraceDepth: %w", intErr)
				}
				tmp_pgwtracedepth := TraceDepth(decVal_pgwtracedepth)
				v.PgwTraceDepth = &tmp_pgwtracedepth
				if offset < 0 || offset >
					len(content) || n_pgwtracedepth < 0 || n_pgwtracedepth >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_pgwtracedepth
			}
		}
	}
	// Decode eNB-TraceDepth
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 9 {
				decodedTag_enbtracedepth, n_enbtracedepth, rawVal_enbtracedepth, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding eNB-TraceDepth: %w", err)
				}
				if decodedTag_enbtracedepth.Class != tag.ClassContextSpecific || decodedTag_enbtracedepth.Number != 9 || decodedTag_enbtracedepth.Constructed != false {
					return fmt.Errorf("decoding eNB-TraceDepth: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_enbtracedepth)
				}
				decVal_enbtracedepth, intErr := ber.DecodeEnumeratedValue(rawVal_enbtracedepth)
				if intErr != nil {
					return fmt.Errorf("decoding eNB-TraceDepth: %w", intErr)
				}
				tmp_enbtracedepth := TraceDepth(decVal_enbtracedepth)
				v.ENBTraceDepth = &tmp_enbtracedepth
				if offset < 0 || offset >
					len(content) || n_enbtracedepth < 0 || n_enbtracedepth >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_enbtracedepth
			}
		}
	}
	// Decode msc-s-TraceDepthExtension
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 10 {
				decodedTag_mscstracedepthextension, n_mscstracedepthextension, rawVal_mscstracedepthextension, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding msc-s-TraceDepthExtension: %w", err)
				}
				if decodedTag_mscstracedepthextension.Class != tag.ClassContextSpecific || decodedTag_mscstracedepthextension.Number != 10 || decodedTag_mscstracedepthextension.Constructed != false {
					return fmt.Errorf("decoding msc-s-TraceDepthExtension: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_mscstracedepthextension)
				}
				decVal_mscstracedepthextension, intErr := ber.DecodeEnumeratedValue(rawVal_mscstracedepthextension)
				if intErr != nil {
					return fmt.Errorf("decoding msc-s-TraceDepthExtension: %w", intErr)
				}
				tmp_mscstracedepthextension := TraceDepthExtension(decVal_mscstracedepthextension)
				v.MscSTraceDepthExtension = &tmp_mscstracedepthextension
				if offset < 0 || offset >
					len(content) || n_mscstracedepthextension < 0 || n_mscstracedepthextension >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_mscstracedepthextension
			}
		}
	}
	// Decode mgw-TraceDepthExtension
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 11 {
				decodedTag_mgwtracedepthextension, n_mgwtracedepthextension, rawVal_mgwtracedepthextension, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding mgw-TraceDepthExtension: %w", err)
				}
				if decodedTag_mgwtracedepthextension.Class != tag.ClassContextSpecific || decodedTag_mgwtracedepthextension.Number != 11 || decodedTag_mgwtracedepthextension.Constructed != false {
					return fmt.Errorf("decoding mgw-TraceDepthExtension: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_mgwtracedepthextension)
				}
				decVal_mgwtracedepthextension, intErr := ber.DecodeEnumeratedValue(rawVal_mgwtracedepthextension)
				if intErr != nil {
					return fmt.Errorf("decoding mgw-TraceDepthExtension: %w", intErr)
				}
				tmp_mgwtracedepthextension := TraceDepthExtension(decVal_mgwtracedepthextension)
				v.MgwTraceDepthExtension = &tmp_mgwtracedepthextension
				if offset < 0 || offset >
					len(content) || n_mgwtracedepthextension < 0 || n_mgwtracedepthextension >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_mgwtracedepthextension
			}
		}
	}
	// Decode sgsn-TraceDepthExtension
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 12 {
				decodedTag_sgsntracedepthextension, n_sgsntracedepthextension, rawVal_sgsntracedepthextension, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding sgsn-TraceDepthExtension: %w", err)
				}
				if decodedTag_sgsntracedepthextension.Class != tag.ClassContextSpecific || decodedTag_sgsntracedepthextension.Number != 12 || decodedTag_sgsntracedepthextension.Constructed != false {
					return fmt.Errorf("decoding sgsn-TraceDepthExtension: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_sgsntracedepthextension)
				}
				decVal_sgsntracedepthextension, intErr := ber.DecodeEnumeratedValue(rawVal_sgsntracedepthextension)
				if intErr != nil {
					return fmt.Errorf("decoding sgsn-TraceDepthExtension: %w", intErr)
				}
				tmp_sgsntracedepthextension := TraceDepthExtension(decVal_sgsntracedepthextension)
				v.SgsnTraceDepthExtension = &tmp_sgsntracedepthextension
				if offset < 0 || offset >
					len(content) || n_sgsntracedepthextension < 0 || n_sgsntracedepthextension >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_sgsntracedepthextension
			}
		}
	}
	// Decode ggsn-TraceDepthExtension
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 13 {
				decodedTag_ggsntracedepthextension, n_ggsntracedepthextension, rawVal_ggsntracedepthextension, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding ggsn-TraceDepthExtension: %w", err)
				}
				if decodedTag_ggsntracedepthextension.Class != tag.ClassContextSpecific || decodedTag_ggsntracedepthextension.Number != 13 || decodedTag_ggsntracedepthextension.Constructed != false {
					return fmt.Errorf("decoding ggsn-TraceDepthExtension: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_ggsntracedepthextension)
				}
				decVal_ggsntracedepthextension, intErr := ber.DecodeEnumeratedValue(rawVal_ggsntracedepthextension)
				if intErr != nil {
					return fmt.Errorf("decoding ggsn-TraceDepthExtension: %w", intErr)
				}
				tmp_ggsntracedepthextension := TraceDepthExtension(decVal_ggsntracedepthextension)
				v.GgsnTraceDepthExtension = &tmp_ggsntracedepthextension
				if offset < 0 || offset >
					len(content) || n_ggsntracedepthextension < 0 || n_ggsntracedepthextension >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_ggsntracedepthextension
			}
		}
	}
	// Decode rnc-TraceDepthExtension
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 14 {
				decodedTag_rnctracedepthextension, n_rnctracedepthextension, rawVal_rnctracedepthextension, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding rnc-TraceDepthExtension: %w", err)
				}
				if decodedTag_rnctracedepthextension.Class != tag.ClassContextSpecific || decodedTag_rnctracedepthextension.Number != 14 || decodedTag_rnctracedepthextension.Constructed != false {
					return fmt.Errorf("decoding rnc-TraceDepthExtension: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_rnctracedepthextension)
				}
				decVal_rnctracedepthextension, intErr := ber.DecodeEnumeratedValue(rawVal_rnctracedepthextension)
				if intErr != nil {
					return fmt.Errorf("decoding rnc-TraceDepthExtension: %w", intErr)
				}
				tmp_rnctracedepthextension := TraceDepthExtension(decVal_rnctracedepthextension)
				v.RncTraceDepthExtension = &tmp_rnctracedepthextension
				if offset < 0 || offset >
					len(content) || n_rnctracedepthextension < 0 || n_rnctracedepthextension >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_rnctracedepthextension
			}
		}
	}
	// Decode bmsc-TraceDepthExtension
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 15 {
				decodedTag_bmsctracedepthextension, n_bmsctracedepthextension, rawVal_bmsctracedepthextension, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding bmsc-TraceDepthExtension: %w", err)
				}
				if decodedTag_bmsctracedepthextension.Class != tag.ClassContextSpecific || decodedTag_bmsctracedepthextension.Number != 15 || decodedTag_bmsctracedepthextension.Constructed != false {
					return fmt.Errorf("decoding bmsc-TraceDepthExtension: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_bmsctracedepthextension)
				}
				decVal_bmsctracedepthextension, intErr := ber.DecodeEnumeratedValue(rawVal_bmsctracedepthextension)
				if intErr != nil {
					return fmt.Errorf("decoding bmsc-TraceDepthExtension: %w", intErr)
				}
				tmp_bmsctracedepthextension := TraceDepthExtension(decVal_bmsctracedepthextension)
				v.BmscTraceDepthExtension = &tmp_bmsctracedepthextension
				if offset < 0 || offset >
					len(content) || n_bmsctracedepthextension < 0 || n_bmsctracedepthextension >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_bmsctracedepthextension
			}
		}
	}
	// Decode mme-TraceDepthExtension
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 16 {
				decodedTag_mmetracedepthextension, n_mmetracedepthextension, rawVal_mmetracedepthextension, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding mme-TraceDepthExtension: %w", err)
				}
				if decodedTag_mmetracedepthextension.Class != tag.ClassContextSpecific || decodedTag_mmetracedepthextension.Number != 16 || decodedTag_mmetracedepthextension.Constructed != false {
					return fmt.Errorf("decoding mme-TraceDepthExtension: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_mmetracedepthextension)
				}
				decVal_mmetracedepthextension, intErr := ber.DecodeEnumeratedValue(rawVal_mmetracedepthextension)
				if intErr != nil {
					return fmt.Errorf("decoding mme-TraceDepthExtension: %w", intErr)
				}
				tmp_mmetracedepthextension := TraceDepthExtension(decVal_mmetracedepthextension)
				v.MmeTraceDepthExtension = &tmp_mmetracedepthextension
				if offset < 0 || offset >
					len(content) || n_mmetracedepthextension < 0 || n_mmetracedepthextension >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_mmetracedepthextension
			}
		}
	}
	// Decode sgw-TraceDepthExtension
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 17 {
				decodedTag_sgwtracedepthextension, n_sgwtracedepthextension, rawVal_sgwtracedepthextension, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding sgw-TraceDepthExtension: %w", err)
				}
				if decodedTag_sgwtracedepthextension.Class != tag.ClassContextSpecific || decodedTag_sgwtracedepthextension.Number != 17 || decodedTag_sgwtracedepthextension.Constructed != false {
					return fmt.Errorf("decoding sgw-TraceDepthExtension: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_sgwtracedepthextension)
				}
				decVal_sgwtracedepthextension, intErr := ber.DecodeEnumeratedValue(rawVal_sgwtracedepthextension)
				if intErr != nil {
					return fmt.Errorf("decoding sgw-TraceDepthExtension: %w", intErr)
				}
				tmp_sgwtracedepthextension := TraceDepthExtension(decVal_sgwtracedepthextension)
				v.SgwTraceDepthExtension = &tmp_sgwtracedepthextension
				if offset < 0 || offset >
					len(content) || n_sgwtracedepthextension < 0 || n_sgwtracedepthextension >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_sgwtracedepthextension
			}
		}
	}
	// Decode pgw-TraceDepthExtension
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 18 {
				decodedTag_pgwtracedepthextension, n_pgwtracedepthextension, rawVal_pgwtracedepthextension, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding pgw-TraceDepthExtension: %w", err)
				}
				if decodedTag_pgwtracedepthextension.Class != tag.ClassContextSpecific || decodedTag_pgwtracedepthextension.Number != 18 || decodedTag_pgwtracedepthextension.Constructed != false {
					return fmt.Errorf("decoding pgw-TraceDepthExtension: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_pgwtracedepthextension)
				}
				decVal_pgwtracedepthextension, intErr := ber.DecodeEnumeratedValue(rawVal_pgwtracedepthextension)
				if intErr != nil {
					return fmt.Errorf("decoding pgw-TraceDepthExtension: %w", intErr)
				}
				tmp_pgwtracedepthextension := TraceDepthExtension(decVal_pgwtracedepthextension)
				v.PgwTraceDepthExtension = &tmp_pgwtracedepthextension
				if offset < 0 || offset >
					len(content) || n_pgwtracedepthextension < 0 || n_pgwtracedepthextension >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_pgwtracedepthextension
			}
		}
	}
	// Decode eNB-TraceDepthExtension
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 19 {
				decodedTag_enbtracedepthextension, n_enbtracedepthextension, rawVal_enbtracedepthextension, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding eNB-TraceDepthExtension: %w", err)
				}
				if decodedTag_enbtracedepthextension.Class != tag.ClassContextSpecific || decodedTag_enbtracedepthextension.Number != 19 || decodedTag_enbtracedepthextension.Constructed != false {
					return fmt.Errorf("decoding eNB-TraceDepthExtension: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_enbtracedepthextension)
				}
				decVal_enbtracedepthextension, intErr := ber.DecodeEnumeratedValue(rawVal_enbtracedepthextension)
				if intErr != nil {
					return fmt.Errorf("decoding eNB-TraceDepthExtension: %w", intErr)
				}
				tmp_enbtracedepthextension := TraceDepthExtension(decVal_enbtracedepthextension)
				v.ENBTraceDepthExtension = &tmp_enbtracedepthextension
				if offset < 0 || offset >
					len(content) || n_enbtracedepthextension < 0 || n_enbtracedepthextension >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_enbtracedepthextension
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:], opts...)
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "TraceDepthList", Cause: extErr_}
		}
		if offset < 0 || offset >
			len(content) || nExt_ < 0 || nExt_ > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		if offset < 0 || offset >
			len(content) || nExt_ < 0 || nExt_ > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes TraceInterfaceList to BER format.
func (v *TraceInterfaceList) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: TraceInterfaceList receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *TraceInterfaceList) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if v.MscSList != nil {
		if (*v.MscSList).BitLength < 10 || (*v.MscSList).BitLength > 16 {
			if constraintErr := ber.CheckEncodedLength(opts, "msc-s-List", "SIZE (10..16)", (*v.MscSList).BitLength); constraintErr != nil {
				return nil, constraintErr
			}
		}
		if bitStringErr := ber.ValidateBitStringLength(v.MscSList.Bytes, v.MscSList.BitLength); bitStringErr != nil {
			return nil, fmt.Errorf("encoding %s: %w", "msc-s-List", bitStringErr)
		}
		// arithmetic pattern BER_BITSTRING_FIELD: 0 <= bit length before modulo and subtraction; gen/codegen.go:526
		if v.MscSList.BitLength < 0 {
			return nil, fmt.Errorf("negative bit string length")
		}
		enc_mscslist, encodeErr_enc_mscslist := ber.EncodeBitString(v.MscSList.Bytes, (8-(v.MscSList.BitLength%8))%8)
		if encodeErr_enc_mscslist != nil {
			return nil, fmt.Errorf("encoding msc-s-List: %w", encodeErr_enc_mscslist)
		}
		retagged_enc_mscslist, tagErr_enc_mscslist := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_mscslist)
		if tagErr_enc_mscslist != nil {
			return nil, fmt.Errorf("encoding msc-s-List: %w", tagErr_enc_mscslist)
		}
		enc_mscslist = retagged_enc_mscslist
		children = append(children, enc_mscslist...)
	}
	if v.MgwList != nil {
		if (*v.MgwList).BitLength < 3 || (*v.MgwList).BitLength > 8 {
			if constraintErr := ber.CheckEncodedLength(opts, "mgw-List", "SIZE (3..8)", (*v.MgwList).BitLength); constraintErr != nil {
				return nil, constraintErr
			}
		}
		if bitStringErr := ber.ValidateBitStringLength(v.MgwList.Bytes, v.MgwList.BitLength); bitStringErr != nil {
			return nil, fmt.Errorf("encoding %s: %w", "mgw-List", bitStringErr)
		}
		// arithmetic pattern BER_BITSTRING_FIELD: 0 <= bit length before modulo and subtraction; gen/codegen.go:526
		if v.MgwList.BitLength < 0 {
			return nil, fmt.Errorf("negative bit string length")
		}
		enc_mgwlist, encodeErr_enc_mgwlist := ber.EncodeBitString(v.MgwList.Bytes, (8-(v.MgwList.BitLength%8))%8)
		if encodeErr_enc_mgwlist != nil {
			return nil, fmt.Errorf("encoding mgw-List: %w", encodeErr_enc_mgwlist)
		}
		retagged_enc_mgwlist, tagErr_enc_mgwlist := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_mgwlist)
		if tagErr_enc_mgwlist != nil {
			return nil, fmt.Errorf("encoding mgw-List: %w", tagErr_enc_mgwlist)
		}
		enc_mgwlist = retagged_enc_mgwlist
		children = append(children, enc_mgwlist...)
	}
	if v.SgsnList != nil {
		if (*v.SgsnList).BitLength < 8 || (*v.SgsnList).BitLength > 16 {
			if constraintErr := ber.CheckEncodedLength(opts, "sgsn-List", "SIZE (8..16)", (*v.SgsnList).BitLength); constraintErr != nil {
				return nil, constraintErr
			}
		}
		if bitStringErr := ber.ValidateBitStringLength(v.SgsnList.Bytes, v.SgsnList.BitLength); bitStringErr != nil {
			return nil, fmt.Errorf("encoding %s: %w", "sgsn-List", bitStringErr)
		}
		// arithmetic pattern BER_BITSTRING_FIELD: 0 <= bit length before modulo and subtraction; gen/codegen.go:526
		if v.SgsnList.BitLength < 0 {
			return nil, fmt.Errorf("negative bit string length")
		}
		enc_sgsnlist, encodeErr_enc_sgsnlist := ber.EncodeBitString(v.SgsnList.Bytes, (8-(v.SgsnList.BitLength%8))%8)
		if encodeErr_enc_sgsnlist != nil {
			return nil, fmt.Errorf("encoding sgsn-List: %w", encodeErr_enc_sgsnlist)
		}
		retagged_enc_sgsnlist, tagErr_enc_sgsnlist := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_sgsnlist)
		if tagErr_enc_sgsnlist != nil {
			return nil, fmt.Errorf("encoding sgsn-List: %w", tagErr_enc_sgsnlist)
		}
		enc_sgsnlist = retagged_enc_sgsnlist
		children = append(children, enc_sgsnlist...)
	}
	if v.GgsnList != nil {
		if (*v.GgsnList).BitLength < 3 || (*v.GgsnList).BitLength > 8 {
			if constraintErr := ber.CheckEncodedLength(opts, "ggsn-List", "SIZE (3..8)", (*v.GgsnList).BitLength); constraintErr != nil {
				return nil, constraintErr
			}
		}
		if bitStringErr := ber.ValidateBitStringLength(v.GgsnList.Bytes, v.GgsnList.BitLength); bitStringErr != nil {
			return nil, fmt.Errorf("encoding %s: %w", "ggsn-List", bitStringErr)
		}
		// arithmetic pattern BER_BITSTRING_FIELD: 0 <= bit length before modulo and subtraction; gen/codegen.go:526
		if v.GgsnList.BitLength < 0 {
			return nil, fmt.Errorf("negative bit string length")
		}
		enc_ggsnlist, encodeErr_enc_ggsnlist := ber.EncodeBitString(v.GgsnList.Bytes, (8-(v.GgsnList.BitLength%8))%8)
		if encodeErr_enc_ggsnlist != nil {
			return nil, fmt.Errorf("encoding ggsn-List: %w", encodeErr_enc_ggsnlist)
		}
		retagged_enc_ggsnlist, tagErr_enc_ggsnlist := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, enc_ggsnlist)
		if tagErr_enc_ggsnlist != nil {
			return nil, fmt.Errorf("encoding ggsn-List: %w", tagErr_enc_ggsnlist)
		}
		enc_ggsnlist = retagged_enc_ggsnlist
		children = append(children, enc_ggsnlist...)
	}
	if v.RncList != nil {
		if (*v.RncList).BitLength < 4 || (*v.RncList).BitLength > 8 {
			if constraintErr := ber.CheckEncodedLength(opts, "rnc-List", "SIZE (4..8)", (*v.RncList).BitLength); constraintErr != nil {
				return nil, constraintErr
			}
		}
		if bitStringErr := ber.ValidateBitStringLength(v.RncList.Bytes, v.RncList.BitLength); bitStringErr != nil {
			return nil, fmt.Errorf("encoding %s: %w", "rnc-List", bitStringErr)
		}
		// arithmetic pattern BER_BITSTRING_FIELD: 0 <= bit length before modulo and subtraction; gen/codegen.go:526
		if v.RncList.BitLength < 0 {
			return nil, fmt.Errorf("negative bit string length")
		}
		enc_rnclist, encodeErr_enc_rnclist := ber.EncodeBitString(v.RncList.Bytes, (8-(v.RncList.BitLength%8))%8)
		if encodeErr_enc_rnclist != nil {
			return nil, fmt.Errorf("encoding rnc-List: %w", encodeErr_enc_rnclist)
		}
		retagged_enc_rnclist, tagErr_enc_rnclist := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, enc_rnclist)
		if tagErr_enc_rnclist != nil {
			return nil, fmt.Errorf("encoding rnc-List: %w", tagErr_enc_rnclist)
		}
		enc_rnclist = retagged_enc_rnclist
		children = append(children, enc_rnclist...)
	}
	if v.BmscList != nil {
		if (*v.BmscList).BitLength < 1 || (*v.BmscList).BitLength > 8 {
			if constraintErr := ber.CheckEncodedLength(opts, "bmsc-List", "SIZE (1..8)", (*v.BmscList).BitLength); constraintErr != nil {
				return nil, constraintErr
			}
		}
		if bitStringErr := ber.ValidateBitStringLength(v.BmscList.Bytes, v.BmscList.BitLength); bitStringErr != nil {
			return nil, fmt.Errorf("encoding %s: %w", "bmsc-List", bitStringErr)
		}
		// arithmetic pattern BER_BITSTRING_FIELD: 0 <= bit length before modulo and subtraction; gen/codegen.go:526
		if v.BmscList.BitLength < 0 {
			return nil, fmt.Errorf("negative bit string length")
		}
		enc_bmsclist, encodeErr_enc_bmsclist := ber.EncodeBitString(v.BmscList.Bytes, (8-(v.BmscList.BitLength%8))%8)
		if encodeErr_enc_bmsclist != nil {
			return nil, fmt.Errorf("encoding bmsc-List: %w", encodeErr_enc_bmsclist)
		}
		retagged_enc_bmsclist, tagErr_enc_bmsclist := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 5, enc_bmsclist)
		if tagErr_enc_bmsclist != nil {
			return nil, fmt.Errorf("encoding bmsc-List: %w", tagErr_enc_bmsclist)
		}
		enc_bmsclist = retagged_enc_bmsclist
		children = append(children, enc_bmsclist...)
	}
	if v.MmeList != nil {
		if (*v.MmeList).BitLength < 5 || (*v.MmeList).BitLength > 8 {
			if constraintErr := ber.CheckEncodedLength(opts, "mme-List", "SIZE (5..8)", (*v.MmeList).BitLength); constraintErr != nil {
				return nil, constraintErr
			}
		}
		if bitStringErr := ber.ValidateBitStringLength(v.MmeList.Bytes, v.MmeList.BitLength); bitStringErr != nil {
			return nil, fmt.Errorf("encoding %s: %w", "mme-List", bitStringErr)
		}
		// arithmetic pattern BER_BITSTRING_FIELD: 0 <= bit length before modulo and subtraction; gen/codegen.go:526
		if v.MmeList.BitLength < 0 {
			return nil, fmt.Errorf("negative bit string length")
		}
		enc_mmelist, encodeErr_enc_mmelist := ber.EncodeBitString(v.MmeList.Bytes, (8-(v.MmeList.BitLength%8))%8)
		if encodeErr_enc_mmelist != nil {
			return nil, fmt.Errorf("encoding mme-List: %w", encodeErr_enc_mmelist)
		}
		retagged_enc_mmelist, tagErr_enc_mmelist := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 6, enc_mmelist)
		if tagErr_enc_mmelist != nil {
			return nil, fmt.Errorf("encoding mme-List: %w", tagErr_enc_mmelist)
		}
		enc_mmelist = retagged_enc_mmelist
		children = append(children, enc_mmelist...)
	}
	if v.SgwList != nil {
		if (*v.SgwList).BitLength < 5 || (*v.SgwList).BitLength > 8 {
			if constraintErr := ber.CheckEncodedLength(opts, "sgw-List", "SIZE (5..8)", (*v.SgwList).BitLength); constraintErr != nil {
				return nil, constraintErr
			}
		}
		if bitStringErr := ber.ValidateBitStringLength(v.SgwList.Bytes, v.SgwList.BitLength); bitStringErr != nil {
			return nil, fmt.Errorf("encoding %s: %w", "sgw-List", bitStringErr)
		}
		// arithmetic pattern BER_BITSTRING_FIELD: 0 <= bit length before modulo and subtraction; gen/codegen.go:526
		if v.SgwList.BitLength < 0 {
			return nil, fmt.Errorf("negative bit string length")
		}
		enc_sgwlist, encodeErr_enc_sgwlist := ber.EncodeBitString(v.SgwList.Bytes, (8-(v.SgwList.BitLength%8))%8)
		if encodeErr_enc_sgwlist != nil {
			return nil, fmt.Errorf("encoding sgw-List: %w", encodeErr_enc_sgwlist)
		}
		retagged_enc_sgwlist, tagErr_enc_sgwlist := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 7, enc_sgwlist)
		if tagErr_enc_sgwlist != nil {
			return nil, fmt.Errorf("encoding sgw-List: %w", tagErr_enc_sgwlist)
		}
		enc_sgwlist = retagged_enc_sgwlist
		children = append(children, enc_sgwlist...)
	}
	if v.PgwList != nil {
		if (*v.PgwList).BitLength < 8 || (*v.PgwList).BitLength > 16 {
			if constraintErr := ber.CheckEncodedLength(opts, "pgw-List", "SIZE (8..16)", (*v.PgwList).BitLength); constraintErr != nil {
				return nil, constraintErr
			}
		}
		if bitStringErr := ber.ValidateBitStringLength(v.PgwList.Bytes, v.PgwList.BitLength); bitStringErr != nil {
			return nil, fmt.Errorf("encoding %s: %w", "pgw-List", bitStringErr)
		}
		// arithmetic pattern BER_BITSTRING_FIELD: 0 <= bit length before modulo and subtraction; gen/codegen.go:526
		if v.PgwList.BitLength < 0 {
			return nil, fmt.Errorf("negative bit string length")
		}
		enc_pgwlist, encodeErr_enc_pgwlist := ber.EncodeBitString(v.PgwList.Bytes, (8-(v.PgwList.BitLength%8))%8)
		if encodeErr_enc_pgwlist != nil {
			return nil, fmt.Errorf("encoding pgw-List: %w", encodeErr_enc_pgwlist)
		}
		retagged_enc_pgwlist, tagErr_enc_pgwlist := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 8, enc_pgwlist)
		if tagErr_enc_pgwlist != nil {
			return nil, fmt.Errorf("encoding pgw-List: %w", tagErr_enc_pgwlist)
		}
		enc_pgwlist = retagged_enc_pgwlist
		children = append(children, enc_pgwlist...)
	}
	if v.ENBList != nil {
		if (*v.ENBList).BitLength < 3 || (*v.ENBList).BitLength > 8 {
			if constraintErr := ber.CheckEncodedLength(opts, "eNB-List", "SIZE (3..8)", (*v.ENBList).BitLength); constraintErr != nil {
				return nil, constraintErr
			}
		}
		if bitStringErr := ber.ValidateBitStringLength(v.ENBList.Bytes, v.ENBList.BitLength); bitStringErr != nil {
			return nil, fmt.Errorf("encoding %s: %w", "eNB-List", bitStringErr)
		}
		// arithmetic pattern BER_BITSTRING_FIELD: 0 <= bit length before modulo and subtraction; gen/codegen.go:526
		if v.ENBList.BitLength < 0 {
			return nil, fmt.Errorf("negative bit string length")
		}
		enc_enblist, encodeErr_enc_enblist := ber.EncodeBitString(v.ENBList.Bytes, (8-(v.ENBList.BitLength%8))%8)
		if encodeErr_enc_enblist != nil {
			return nil, fmt.Errorf("encoding eNB-List: %w", encodeErr_enc_enblist)
		}
		retagged_enc_enblist, tagErr_enc_enblist := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 9, enc_enblist)
		if tagErr_enc_enblist != nil {
			return nil, fmt.Errorf("encoding eNB-List: %w", tagErr_enc_enblist)
		}
		enc_enblist = retagged_enc_enblist
		children = append(children, enc_enblist...)
	}
	for i, ext := range v.ExtData_ {
		_, n, _, extErr := ber.DecodeEncodedTLV(ext)
		if extErr != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, extErr)
		}
		if n != len(ext) {
			return nil, fmt.Errorf("encoding extension %d: %w", i, ber.ErrExtraData)
		}
		children = append(children, ext...)
	}
	return ber.EncodeSequence(children)
}

// MarshalDER encodes TraceInterfaceList to DER format.
func (v *TraceInterfaceList) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: TraceInterfaceList receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if v.MscSList != nil {
		if (*v.MscSList).BitLength < 10 || (*v.MscSList).BitLength > 16 {
			if constraintErr := ber.CheckEncodedLength(nil, "msc-s-List", "SIZE (10..16)", (*v.MscSList).BitLength); constraintErr != nil {
				return nil, constraintErr
			}
		}
		if bitStringErr := ber.ValidateBitStringLength(v.MscSList.Bytes, v.MscSList.BitLength); bitStringErr != nil {
			return nil, fmt.Errorf("encoding %s: %w", "msc-s-List", bitStringErr)
		}
		if bitStringErr := ber.ValidateDERBitString(v.MscSList.Bytes, v.MscSList.BitLength); bitStringErr != nil {
			return nil, fmt.Errorf("encoding %s: %w", "msc-s-List", bitStringErr)
		}
		// arithmetic pattern BER_BITSTRING_FIELD: 0 <= bit length before modulo and subtraction; gen/codegen.go:526
		if v.MscSList.BitLength < 0 {
			return nil, fmt.Errorf("negative bit string length")
		}
		enc_mscslist, encodeErr_enc_mscslist := ber.EncodeDERNamedBitString(v.MscSList.Bytes, v.MscSList.BitLength)
		if encodeErr_enc_mscslist != nil {
			return nil, fmt.Errorf("encoding msc-s-List: %w", encodeErr_enc_mscslist)
		}
		retagged_enc_mscslist, tagErr_enc_mscslist := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_mscslist)
		if tagErr_enc_mscslist != nil {
			return nil, fmt.Errorf("encoding msc-s-List: %w", tagErr_enc_mscslist)
		}
		enc_mscslist = retagged_enc_mscslist
		children = append(children, enc_mscslist...)
	}
	if v.MgwList != nil {
		if (*v.MgwList).BitLength < 3 || (*v.MgwList).BitLength > 8 {
			if constraintErr := ber.CheckEncodedLength(nil, "mgw-List", "SIZE (3..8)", (*v.MgwList).BitLength); constraintErr != nil {
				return nil, constraintErr
			}
		}
		if bitStringErr := ber.ValidateBitStringLength(v.MgwList.Bytes, v.MgwList.BitLength); bitStringErr != nil {
			return nil, fmt.Errorf("encoding %s: %w", "mgw-List", bitStringErr)
		}
		if bitStringErr := ber.ValidateDERBitString(v.MgwList.Bytes, v.MgwList.BitLength); bitStringErr != nil {
			return nil, fmt.Errorf("encoding %s: %w", "mgw-List", bitStringErr)
		}
		// arithmetic pattern BER_BITSTRING_FIELD: 0 <= bit length before modulo and subtraction; gen/codegen.go:526
		if v.MgwList.BitLength < 0 {
			return nil, fmt.Errorf("negative bit string length")
		}
		enc_mgwlist, encodeErr_enc_mgwlist := ber.EncodeDERNamedBitString(v.MgwList.Bytes, v.MgwList.BitLength)
		if encodeErr_enc_mgwlist != nil {
			return nil, fmt.Errorf("encoding mgw-List: %w", encodeErr_enc_mgwlist)
		}
		retagged_enc_mgwlist, tagErr_enc_mgwlist := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_mgwlist)
		if tagErr_enc_mgwlist != nil {
			return nil, fmt.Errorf("encoding mgw-List: %w", tagErr_enc_mgwlist)
		}
		enc_mgwlist = retagged_enc_mgwlist
		children = append(children, enc_mgwlist...)
	}
	if v.SgsnList != nil {
		if (*v.SgsnList).BitLength < 8 || (*v.SgsnList).BitLength > 16 {
			if constraintErr := ber.CheckEncodedLength(nil, "sgsn-List", "SIZE (8..16)", (*v.SgsnList).BitLength); constraintErr != nil {
				return nil, constraintErr
			}
		}
		if bitStringErr := ber.ValidateBitStringLength(v.SgsnList.Bytes, v.SgsnList.BitLength); bitStringErr != nil {
			return nil, fmt.Errorf("encoding %s: %w", "sgsn-List", bitStringErr)
		}
		if bitStringErr := ber.ValidateDERBitString(v.SgsnList.Bytes, v.SgsnList.BitLength); bitStringErr != nil {
			return nil, fmt.Errorf("encoding %s: %w", "sgsn-List", bitStringErr)
		}
		// arithmetic pattern BER_BITSTRING_FIELD: 0 <= bit length before modulo and subtraction; gen/codegen.go:526
		if v.SgsnList.BitLength < 0 {
			return nil, fmt.Errorf("negative bit string length")
		}
		enc_sgsnlist, encodeErr_enc_sgsnlist := ber.EncodeDERNamedBitString(v.SgsnList.Bytes, v.SgsnList.BitLength)
		if encodeErr_enc_sgsnlist != nil {
			return nil, fmt.Errorf("encoding sgsn-List: %w", encodeErr_enc_sgsnlist)
		}
		retagged_enc_sgsnlist, tagErr_enc_sgsnlist := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_sgsnlist)
		if tagErr_enc_sgsnlist != nil {
			return nil, fmt.Errorf("encoding sgsn-List: %w", tagErr_enc_sgsnlist)
		}
		enc_sgsnlist = retagged_enc_sgsnlist
		children = append(children, enc_sgsnlist...)
	}
	if v.GgsnList != nil {
		if (*v.GgsnList).BitLength < 3 || (*v.GgsnList).BitLength > 8 {
			if constraintErr := ber.CheckEncodedLength(nil, "ggsn-List", "SIZE (3..8)", (*v.GgsnList).BitLength); constraintErr != nil {
				return nil, constraintErr
			}
		}
		if bitStringErr := ber.ValidateBitStringLength(v.GgsnList.Bytes, v.GgsnList.BitLength); bitStringErr != nil {
			return nil, fmt.Errorf("encoding %s: %w", "ggsn-List", bitStringErr)
		}
		if bitStringErr := ber.ValidateDERBitString(v.GgsnList.Bytes, v.GgsnList.BitLength); bitStringErr != nil {
			return nil, fmt.Errorf("encoding %s: %w", "ggsn-List", bitStringErr)
		}
		// arithmetic pattern BER_BITSTRING_FIELD: 0 <= bit length before modulo and subtraction; gen/codegen.go:526
		if v.GgsnList.BitLength < 0 {
			return nil, fmt.Errorf("negative bit string length")
		}
		enc_ggsnlist, encodeErr_enc_ggsnlist := ber.EncodeDERNamedBitString(v.GgsnList.Bytes, v.GgsnList.BitLength)
		if encodeErr_enc_ggsnlist != nil {
			return nil, fmt.Errorf("encoding ggsn-List: %w", encodeErr_enc_ggsnlist)
		}
		retagged_enc_ggsnlist, tagErr_enc_ggsnlist := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, enc_ggsnlist)
		if tagErr_enc_ggsnlist != nil {
			return nil, fmt.Errorf("encoding ggsn-List: %w", tagErr_enc_ggsnlist)
		}
		enc_ggsnlist = retagged_enc_ggsnlist
		children = append(children, enc_ggsnlist...)
	}
	if v.RncList != nil {
		if (*v.RncList).BitLength < 4 || (*v.RncList).BitLength > 8 {
			if constraintErr := ber.CheckEncodedLength(nil, "rnc-List", "SIZE (4..8)", (*v.RncList).BitLength); constraintErr != nil {
				return nil, constraintErr
			}
		}
		if bitStringErr := ber.ValidateBitStringLength(v.RncList.Bytes, v.RncList.BitLength); bitStringErr != nil {
			return nil, fmt.Errorf("encoding %s: %w", "rnc-List", bitStringErr)
		}
		if bitStringErr := ber.ValidateDERBitString(v.RncList.Bytes, v.RncList.BitLength); bitStringErr != nil {
			return nil, fmt.Errorf("encoding %s: %w", "rnc-List", bitStringErr)
		}
		// arithmetic pattern BER_BITSTRING_FIELD: 0 <= bit length before modulo and subtraction; gen/codegen.go:526
		if v.RncList.BitLength < 0 {
			return nil, fmt.Errorf("negative bit string length")
		}
		enc_rnclist, encodeErr_enc_rnclist := ber.EncodeDERNamedBitString(v.RncList.Bytes, v.RncList.BitLength)
		if encodeErr_enc_rnclist != nil {
			return nil, fmt.Errorf("encoding rnc-List: %w", encodeErr_enc_rnclist)
		}
		retagged_enc_rnclist, tagErr_enc_rnclist := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, enc_rnclist)
		if tagErr_enc_rnclist != nil {
			return nil, fmt.Errorf("encoding rnc-List: %w", tagErr_enc_rnclist)
		}
		enc_rnclist = retagged_enc_rnclist
		children = append(children, enc_rnclist...)
	}
	if v.BmscList != nil {
		if (*v.BmscList).BitLength < 1 || (*v.BmscList).BitLength > 8 {
			if constraintErr := ber.CheckEncodedLength(nil, "bmsc-List", "SIZE (1..8)", (*v.BmscList).BitLength); constraintErr != nil {
				return nil, constraintErr
			}
		}
		if bitStringErr := ber.ValidateBitStringLength(v.BmscList.Bytes, v.BmscList.BitLength); bitStringErr != nil {
			return nil, fmt.Errorf("encoding %s: %w", "bmsc-List", bitStringErr)
		}
		if bitStringErr := ber.ValidateDERBitString(v.BmscList.Bytes, v.BmscList.BitLength); bitStringErr != nil {
			return nil, fmt.Errorf("encoding %s: %w", "bmsc-List", bitStringErr)
		}
		// arithmetic pattern BER_BITSTRING_FIELD: 0 <= bit length before modulo and subtraction; gen/codegen.go:526
		if v.BmscList.BitLength < 0 {
			return nil, fmt.Errorf("negative bit string length")
		}
		enc_bmsclist, encodeErr_enc_bmsclist := ber.EncodeDERNamedBitString(v.BmscList.Bytes, v.BmscList.BitLength)
		if encodeErr_enc_bmsclist != nil {
			return nil, fmt.Errorf("encoding bmsc-List: %w", encodeErr_enc_bmsclist)
		}
		retagged_enc_bmsclist, tagErr_enc_bmsclist := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 5, enc_bmsclist)
		if tagErr_enc_bmsclist != nil {
			return nil, fmt.Errorf("encoding bmsc-List: %w", tagErr_enc_bmsclist)
		}
		enc_bmsclist = retagged_enc_bmsclist
		children = append(children, enc_bmsclist...)
	}
	if v.MmeList != nil {
		if (*v.MmeList).BitLength < 5 || (*v.MmeList).BitLength > 8 {
			if constraintErr := ber.CheckEncodedLength(nil, "mme-List", "SIZE (5..8)", (*v.MmeList).BitLength); constraintErr != nil {
				return nil, constraintErr
			}
		}
		if bitStringErr := ber.ValidateBitStringLength(v.MmeList.Bytes, v.MmeList.BitLength); bitStringErr != nil {
			return nil, fmt.Errorf("encoding %s: %w", "mme-List", bitStringErr)
		}
		if bitStringErr := ber.ValidateDERBitString(v.MmeList.Bytes, v.MmeList.BitLength); bitStringErr != nil {
			return nil, fmt.Errorf("encoding %s: %w", "mme-List", bitStringErr)
		}
		// arithmetic pattern BER_BITSTRING_FIELD: 0 <= bit length before modulo and subtraction; gen/codegen.go:526
		if v.MmeList.BitLength < 0 {
			return nil, fmt.Errorf("negative bit string length")
		}
		enc_mmelist, encodeErr_enc_mmelist := ber.EncodeDERNamedBitString(v.MmeList.Bytes, v.MmeList.BitLength)
		if encodeErr_enc_mmelist != nil {
			return nil, fmt.Errorf("encoding mme-List: %w", encodeErr_enc_mmelist)
		}
		retagged_enc_mmelist, tagErr_enc_mmelist := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 6, enc_mmelist)
		if tagErr_enc_mmelist != nil {
			return nil, fmt.Errorf("encoding mme-List: %w", tagErr_enc_mmelist)
		}
		enc_mmelist = retagged_enc_mmelist
		children = append(children, enc_mmelist...)
	}
	if v.SgwList != nil {
		if (*v.SgwList).BitLength < 5 || (*v.SgwList).BitLength > 8 {
			if constraintErr := ber.CheckEncodedLength(nil, "sgw-List", "SIZE (5..8)", (*v.SgwList).BitLength); constraintErr != nil {
				return nil, constraintErr
			}
		}
		if bitStringErr := ber.ValidateBitStringLength(v.SgwList.Bytes, v.SgwList.BitLength); bitStringErr != nil {
			return nil, fmt.Errorf("encoding %s: %w", "sgw-List", bitStringErr)
		}
		if bitStringErr := ber.ValidateDERBitString(v.SgwList.Bytes, v.SgwList.BitLength); bitStringErr != nil {
			return nil, fmt.Errorf("encoding %s: %w", "sgw-List", bitStringErr)
		}
		// arithmetic pattern BER_BITSTRING_FIELD: 0 <= bit length before modulo and subtraction; gen/codegen.go:526
		if v.SgwList.BitLength < 0 {
			return nil, fmt.Errorf("negative bit string length")
		}
		enc_sgwlist, encodeErr_enc_sgwlist := ber.EncodeDERNamedBitString(v.SgwList.Bytes, v.SgwList.BitLength)
		if encodeErr_enc_sgwlist != nil {
			return nil, fmt.Errorf("encoding sgw-List: %w", encodeErr_enc_sgwlist)
		}
		retagged_enc_sgwlist, tagErr_enc_sgwlist := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 7, enc_sgwlist)
		if tagErr_enc_sgwlist != nil {
			return nil, fmt.Errorf("encoding sgw-List: %w", tagErr_enc_sgwlist)
		}
		enc_sgwlist = retagged_enc_sgwlist
		children = append(children, enc_sgwlist...)
	}
	if v.PgwList != nil {
		if (*v.PgwList).BitLength < 8 || (*v.PgwList).BitLength > 16 {
			if constraintErr := ber.CheckEncodedLength(nil, "pgw-List", "SIZE (8..16)", (*v.PgwList).BitLength); constraintErr != nil {
				return nil, constraintErr
			}
		}
		if bitStringErr := ber.ValidateBitStringLength(v.PgwList.Bytes, v.PgwList.BitLength); bitStringErr != nil {
			return nil, fmt.Errorf("encoding %s: %w", "pgw-List", bitStringErr)
		}
		if bitStringErr := ber.ValidateDERBitString(v.PgwList.Bytes, v.PgwList.BitLength); bitStringErr != nil {
			return nil, fmt.Errorf("encoding %s: %w", "pgw-List", bitStringErr)
		}
		// arithmetic pattern BER_BITSTRING_FIELD: 0 <= bit length before modulo and subtraction; gen/codegen.go:526
		if v.PgwList.BitLength < 0 {
			return nil, fmt.Errorf("negative bit string length")
		}
		enc_pgwlist, encodeErr_enc_pgwlist := ber.EncodeDERNamedBitString(v.PgwList.Bytes, v.PgwList.BitLength)
		if encodeErr_enc_pgwlist != nil {
			return nil, fmt.Errorf("encoding pgw-List: %w", encodeErr_enc_pgwlist)
		}
		retagged_enc_pgwlist, tagErr_enc_pgwlist := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 8, enc_pgwlist)
		if tagErr_enc_pgwlist != nil {
			return nil, fmt.Errorf("encoding pgw-List: %w", tagErr_enc_pgwlist)
		}
		enc_pgwlist = retagged_enc_pgwlist
		children = append(children, enc_pgwlist...)
	}
	if v.ENBList != nil {
		if (*v.ENBList).BitLength < 3 || (*v.ENBList).BitLength > 8 {
			if constraintErr := ber.CheckEncodedLength(nil, "eNB-List", "SIZE (3..8)", (*v.ENBList).BitLength); constraintErr != nil {
				return nil, constraintErr
			}
		}
		if bitStringErr := ber.ValidateBitStringLength(v.ENBList.Bytes, v.ENBList.BitLength); bitStringErr != nil {
			return nil, fmt.Errorf("encoding %s: %w", "eNB-List", bitStringErr)
		}
		if bitStringErr := ber.ValidateDERBitString(v.ENBList.Bytes, v.ENBList.BitLength); bitStringErr != nil {
			return nil, fmt.Errorf("encoding %s: %w", "eNB-List", bitStringErr)
		}
		// arithmetic pattern BER_BITSTRING_FIELD: 0 <= bit length before modulo and subtraction; gen/codegen.go:526
		if v.ENBList.BitLength < 0 {
			return nil, fmt.Errorf("negative bit string length")
		}
		enc_enblist, encodeErr_enc_enblist := ber.EncodeDERNamedBitString(v.ENBList.Bytes, v.ENBList.BitLength)
		if encodeErr_enc_enblist != nil {
			return nil, fmt.Errorf("encoding eNB-List: %w", encodeErr_enc_enblist)
		}
		retagged_enc_enblist, tagErr_enc_enblist := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 9, enc_enblist)
		if tagErr_enc_enblist != nil {
			return nil, fmt.Errorf("encoding eNB-List: %w", tagErr_enc_enblist)
		}
		enc_enblist = retagged_enc_enblist
		children = append(children, enc_enblist...)
	}
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDEREncodedElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
		children = append(children, ext...)
	}
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding TraceInterfaceList as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes TraceInterfaceList from BER/DER format.
func (v *TraceInterfaceList) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: TraceInterfaceList destination is nil", ber.ErrInvalidValue)
	}
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = TraceInterfaceList{}
	defer func() {
		if returnErr != nil || !ber.BERNeedsPreservation(opts) {
			return
		}
		var snapshotReports ber.ViolationLog
		snapshot, snapshotErr := v.marshalBER(ber.WithConstraintTolerance(&snapshotReports))
		if snapshotErr != nil {
			returnErr = snapshotErr
			return
		}
		v.berOriginal_ = append([]byte(nil), data...)
		v.berSnapshot_ = snapshot
	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("decoding TraceInterfaceList SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "TraceInterfaceList", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode msc-s-List
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
				decodedTag_mscslist, n_mscslist, rawVal_mscslist, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding msc-s-List: %w", err)
				}
				if decodedTag_mscslist.Class != tag.ClassContextSpecific || decodedTag_mscslist.Number != 0 {
					return fmt.Errorf("decoding msc-s-List: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_mscslist)
				}
				bsBytes_mscslist, bsUnused_mscslist, bsErr := ber.DecodeImplicitBitStringValue(decodedTag_mscslist.Constructed, rawVal_mscslist, opts...)
				if bsErr != nil {
					return fmt.Errorf("decoding msc-s-List: %w", bsErr)
				}
				bsBitLength_mscslist, bsLenErr_mscslist := ber.BitStringBitLength(len(bsBytes_mscslist), bsUnused_mscslist)
				if bsLenErr_mscslist != nil {
					return fmt.Errorf("decoding msc-s-List: %w", bsLenErr_mscslist)
				}
				tmp_mscslist := runtime.BitString{Bytes: bsBytes_mscslist, BitLength: bsBitLength_mscslist}
				v.MscSList = &tmp_mscslist
				if offset > len(content) || n_mscslist < 0 || n_mscslist > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_mscslist
				*v.MscSList = ber.NormalizeNamedBitStringSize(*v.MscSList, []ber.NamedBitSizeSet{{{Min: 10, Max: 16}}}, opts...)
				if (*v.MscSList).BitLength < 10 || (*v.MscSList).BitLength > 16 {
					if constraintErr := ber.CheckDecodedLength(opts, "msc-s-List", "SIZE (10..16)", (*v.MscSList).BitLength); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode mgw-List
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
				decodedTag_mgwlist, n_mgwlist, rawVal_mgwlist, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding mgw-List: %w", err)
				}
				if decodedTag_mgwlist.Class != tag.ClassContextSpecific || decodedTag_mgwlist.Number != 1 {
					return fmt.Errorf("decoding mgw-List: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_mgwlist)
				}
				bsBytes_mgwlist, bsUnused_mgwlist, bsErr := ber.DecodeImplicitBitStringValue(decodedTag_mgwlist.Constructed, rawVal_mgwlist, opts...)
				if bsErr != nil {
					return fmt.Errorf("decoding mgw-List: %w", bsErr)
				}
				bsBitLength_mgwlist, bsLenErr_mgwlist := ber.BitStringBitLength(len(bsBytes_mgwlist), bsUnused_mgwlist)
				if bsLenErr_mgwlist != nil {
					return fmt.Errorf("decoding mgw-List: %w", bsLenErr_mgwlist)
				}
				tmp_mgwlist := runtime.BitString{Bytes: bsBytes_mgwlist, BitLength: bsBitLength_mgwlist}
				v.MgwList = &tmp_mgwlist
				if offset < 0 || offset >
					len(content) || n_mgwlist < 0 || n_mgwlist > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_mgwlist
				*v.MgwList = ber.NormalizeNamedBitStringSize(*v.MgwList, []ber.NamedBitSizeSet{{{Min: 3, Max: 8}}}, opts...)
				if (*v.MgwList).BitLength < 3 || (*v.MgwList).BitLength > 8 {
					if constraintErr := ber.CheckDecodedLength(opts, "mgw-List", "SIZE (3..8)", (*v.MgwList).BitLength); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode sgsn-List
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2 {
				decodedTag_sgsnlist, n_sgsnlist, rawVal_sgsnlist, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding sgsn-List: %w", err)
				}
				if decodedTag_sgsnlist.Class != tag.ClassContextSpecific || decodedTag_sgsnlist.Number != 2 {
					return fmt.Errorf("decoding sgsn-List: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_sgsnlist)
				}
				bsBytes_sgsnlist, bsUnused_sgsnlist, bsErr := ber.DecodeImplicitBitStringValue(decodedTag_sgsnlist.Constructed, rawVal_sgsnlist, opts...)
				if bsErr != nil {
					return fmt.Errorf("decoding sgsn-List: %w", bsErr)
				}
				bsBitLength_sgsnlist, bsLenErr_sgsnlist := ber.BitStringBitLength(len(bsBytes_sgsnlist), bsUnused_sgsnlist)
				if bsLenErr_sgsnlist != nil {
					return fmt.Errorf("decoding sgsn-List: %w", bsLenErr_sgsnlist)
				}
				tmp_sgsnlist := runtime.BitString{Bytes: bsBytes_sgsnlist, BitLength: bsBitLength_sgsnlist}
				v.SgsnList = &tmp_sgsnlist
				if offset < 0 || offset >
					len(content) || n_sgsnlist < 0 || n_sgsnlist > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_sgsnlist
				*v.SgsnList = ber.NormalizeNamedBitStringSize(*v.SgsnList, []ber.NamedBitSizeSet{{{Min: 8, Max: 16}}}, opts...)
				if (*v.SgsnList).BitLength < 8 || (*v.SgsnList).BitLength > 16 {
					if constraintErr := ber.CheckDecodedLength(opts, "sgsn-List", "SIZE (8..16)", (*v.SgsnList).BitLength); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode ggsn-List
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3 {
				decodedTag_ggsnlist, n_ggsnlist, rawVal_ggsnlist, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding ggsn-List: %w", err)
				}
				if decodedTag_ggsnlist.Class != tag.ClassContextSpecific || decodedTag_ggsnlist.Number != 3 {
					return fmt.Errorf("decoding ggsn-List: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_ggsnlist)
				}
				bsBytes_ggsnlist, bsUnused_ggsnlist, bsErr := ber.DecodeImplicitBitStringValue(decodedTag_ggsnlist.Constructed, rawVal_ggsnlist, opts...)
				if bsErr != nil {
					return fmt.Errorf("decoding ggsn-List: %w", bsErr)
				}
				bsBitLength_ggsnlist, bsLenErr_ggsnlist := ber.BitStringBitLength(len(bsBytes_ggsnlist), bsUnused_ggsnlist)
				if bsLenErr_ggsnlist != nil {
					return fmt.Errorf("decoding ggsn-List: %w", bsLenErr_ggsnlist)
				}
				tmp_ggsnlist := runtime.BitString{Bytes: bsBytes_ggsnlist, BitLength: bsBitLength_ggsnlist}
				v.GgsnList = &tmp_ggsnlist
				if offset < 0 || offset >
					len(content) || n_ggsnlist < 0 || n_ggsnlist > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_ggsnlist
				*v.GgsnList = ber.NormalizeNamedBitStringSize(*v.GgsnList, []ber.NamedBitSizeSet{{{Min: 3, Max: 8}}}, opts...)
				if (*v.GgsnList).BitLength < 3 || (*v.GgsnList).BitLength > 8 {
					if constraintErr := ber.CheckDecodedLength(opts, "ggsn-List", "SIZE (3..8)", (*v.GgsnList).BitLength); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode rnc-List
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4 {
				decodedTag_rnclist, n_rnclist, rawVal_rnclist, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding rnc-List: %w", err)
				}
				if decodedTag_rnclist.Class != tag.ClassContextSpecific || decodedTag_rnclist.Number != 4 {
					return fmt.Errorf("decoding rnc-List: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_rnclist)
				}
				bsBytes_rnclist, bsUnused_rnclist, bsErr := ber.DecodeImplicitBitStringValue(decodedTag_rnclist.Constructed, rawVal_rnclist, opts...)
				if bsErr != nil {
					return fmt.Errorf("decoding rnc-List: %w", bsErr)
				}
				bsBitLength_rnclist, bsLenErr_rnclist := ber.BitStringBitLength(len(bsBytes_rnclist), bsUnused_rnclist)
				if bsLenErr_rnclist != nil {
					return fmt.Errorf("decoding rnc-List: %w", bsLenErr_rnclist)
				}
				tmp_rnclist := runtime.BitString{Bytes: bsBytes_rnclist, BitLength: bsBitLength_rnclist}
				v.RncList = &tmp_rnclist
				if offset < 0 || offset >
					len(content) || n_rnclist < 0 || n_rnclist > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_rnclist
				*v.RncList = ber.NormalizeNamedBitStringSize(*v.RncList, []ber.NamedBitSizeSet{{{Min: 4, Max: 8}}}, opts...)
				if (*v.RncList).BitLength < 4 || (*v.RncList).BitLength > 8 {
					if constraintErr := ber.CheckDecodedLength(opts, "rnc-List", "SIZE (4..8)", (*v.RncList).BitLength); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode bmsc-List
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 5 {
				decodedTag_bmsclist, n_bmsclist, rawVal_bmsclist, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding bmsc-List: %w", err)
				}
				if decodedTag_bmsclist.Class != tag.ClassContextSpecific || decodedTag_bmsclist.Number != 5 {
					return fmt.Errorf("decoding bmsc-List: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_bmsclist)
				}
				bsBytes_bmsclist, bsUnused_bmsclist, bsErr := ber.DecodeImplicitBitStringValue(decodedTag_bmsclist.Constructed, rawVal_bmsclist, opts...)
				if bsErr != nil {
					return fmt.Errorf("decoding bmsc-List: %w", bsErr)
				}
				bsBitLength_bmsclist, bsLenErr_bmsclist := ber.BitStringBitLength(len(bsBytes_bmsclist), bsUnused_bmsclist)
				if bsLenErr_bmsclist != nil {
					return fmt.Errorf("decoding bmsc-List: %w", bsLenErr_bmsclist)
				}
				tmp_bmsclist := runtime.BitString{Bytes: bsBytes_bmsclist, BitLength: bsBitLength_bmsclist}
				v.BmscList = &tmp_bmsclist
				if offset < 0 || offset >
					len(content) || n_bmsclist < 0 || n_bmsclist > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_bmsclist
				*v.BmscList = ber.NormalizeNamedBitStringSize(*v.BmscList, []ber.NamedBitSizeSet{{{Min: 1, Max: 8}}}, opts...)
				if (*v.BmscList).BitLength < 1 || (*v.BmscList).BitLength > 8 {
					if constraintErr := ber.CheckDecodedLength(opts, "bmsc-List", "SIZE (1..8)", (*v.BmscList).BitLength); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode mme-List
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 6 {
				decodedTag_mmelist, n_mmelist, rawVal_mmelist, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding mme-List: %w", err)
				}
				if decodedTag_mmelist.Class != tag.ClassContextSpecific || decodedTag_mmelist.Number != 6 {
					return fmt.Errorf("decoding mme-List: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_mmelist)
				}
				bsBytes_mmelist, bsUnused_mmelist, bsErr := ber.DecodeImplicitBitStringValue(decodedTag_mmelist.Constructed, rawVal_mmelist, opts...)
				if bsErr != nil {
					return fmt.Errorf("decoding mme-List: %w", bsErr)
				}
				bsBitLength_mmelist, bsLenErr_mmelist := ber.BitStringBitLength(len(bsBytes_mmelist), bsUnused_mmelist)
				if bsLenErr_mmelist != nil {
					return fmt.Errorf("decoding mme-List: %w", bsLenErr_mmelist)
				}
				tmp_mmelist := runtime.BitString{Bytes: bsBytes_mmelist, BitLength: bsBitLength_mmelist}
				v.MmeList = &tmp_mmelist
				if offset < 0 || offset >
					len(content) || n_mmelist < 0 || n_mmelist > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_mmelist
				*v.MmeList = ber.NormalizeNamedBitStringSize(*v.MmeList, []ber.NamedBitSizeSet{{{Min: 5, Max: 8}}}, opts...)
				if (*v.MmeList).BitLength < 5 || (*v.MmeList).BitLength > 8 {
					if constraintErr := ber.CheckDecodedLength(opts, "mme-List", "SIZE (5..8)", (*v.MmeList).BitLength); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode sgw-List
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 7 {
				decodedTag_sgwlist, n_sgwlist, rawVal_sgwlist, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding sgw-List: %w", err)
				}
				if decodedTag_sgwlist.Class != tag.ClassContextSpecific || decodedTag_sgwlist.Number != 7 {
					return fmt.Errorf("decoding sgw-List: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_sgwlist)
				}
				bsBytes_sgwlist, bsUnused_sgwlist, bsErr := ber.DecodeImplicitBitStringValue(decodedTag_sgwlist.Constructed, rawVal_sgwlist, opts...)
				if bsErr != nil {
					return fmt.Errorf("decoding sgw-List: %w", bsErr)
				}
				bsBitLength_sgwlist, bsLenErr_sgwlist := ber.BitStringBitLength(len(bsBytes_sgwlist), bsUnused_sgwlist)
				if bsLenErr_sgwlist != nil {
					return fmt.Errorf("decoding sgw-List: %w", bsLenErr_sgwlist)
				}
				tmp_sgwlist := runtime.BitString{Bytes: bsBytes_sgwlist, BitLength: bsBitLength_sgwlist}
				v.SgwList = &tmp_sgwlist
				if offset < 0 || offset >
					len(content) || n_sgwlist < 0 || n_sgwlist > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_sgwlist
				*v.SgwList = ber.NormalizeNamedBitStringSize(*v.SgwList, []ber.NamedBitSizeSet{{{Min: 5, Max: 8}}}, opts...)
				if (*v.SgwList).BitLength < 5 || (*v.SgwList).BitLength > 8 {
					if constraintErr := ber.CheckDecodedLength(opts, "sgw-List", "SIZE (5..8)", (*v.SgwList).BitLength); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode pgw-List
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 8 {
				decodedTag_pgwlist, n_pgwlist, rawVal_pgwlist, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding pgw-List: %w", err)
				}
				if decodedTag_pgwlist.Class != tag.ClassContextSpecific || decodedTag_pgwlist.Number != 8 {
					return fmt.Errorf("decoding pgw-List: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_pgwlist)
				}
				bsBytes_pgwlist, bsUnused_pgwlist, bsErr := ber.DecodeImplicitBitStringValue(decodedTag_pgwlist.Constructed, rawVal_pgwlist, opts...)
				if bsErr != nil {
					return fmt.Errorf("decoding pgw-List: %w", bsErr)
				}
				bsBitLength_pgwlist, bsLenErr_pgwlist := ber.BitStringBitLength(len(bsBytes_pgwlist), bsUnused_pgwlist)
				if bsLenErr_pgwlist != nil {
					return fmt.Errorf("decoding pgw-List: %w", bsLenErr_pgwlist)
				}
				tmp_pgwlist := runtime.BitString{Bytes: bsBytes_pgwlist, BitLength: bsBitLength_pgwlist}
				v.PgwList = &tmp_pgwlist
				if offset < 0 || offset >
					len(content) || n_pgwlist < 0 || n_pgwlist > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_pgwlist
				*v.PgwList = ber.NormalizeNamedBitStringSize(*v.PgwList, []ber.NamedBitSizeSet{{{Min: 8, Max: 16}}}, opts...)
				if (*v.PgwList).BitLength < 8 || (*v.PgwList).BitLength > 16 {
					if constraintErr := ber.CheckDecodedLength(opts, "pgw-List", "SIZE (8..16)", (*v.PgwList).BitLength); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode eNB-List
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 9 {
				decodedTag_enblist, n_enblist, rawVal_enblist, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding eNB-List: %w", err)
				}
				if decodedTag_enblist.Class != tag.ClassContextSpecific || decodedTag_enblist.Number != 9 {
					return fmt.Errorf("decoding eNB-List: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_enblist)
				}
				bsBytes_enblist, bsUnused_enblist, bsErr := ber.DecodeImplicitBitStringValue(decodedTag_enblist.Constructed, rawVal_enblist, opts...)
				if bsErr != nil {
					return fmt.Errorf("decoding eNB-List: %w", bsErr)
				}
				bsBitLength_enblist, bsLenErr_enblist := ber.BitStringBitLength(len(bsBytes_enblist), bsUnused_enblist)
				if bsLenErr_enblist != nil {
					return fmt.Errorf("decoding eNB-List: %w", bsLenErr_enblist)
				}
				tmp_enblist := runtime.BitString{Bytes: bsBytes_enblist, BitLength: bsBitLength_enblist}
				v.ENBList = &tmp_enblist
				if offset < 0 || offset >
					len(content) || n_enblist < 0 || n_enblist > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_enblist
				*v.ENBList = ber.NormalizeNamedBitStringSize(*v.ENBList, []ber.NamedBitSizeSet{{{Min: 3, Max: 8}}}, opts...)
				if (*v.ENBList).BitLength < 3 || (*v.ENBList).BitLength > 8 {
					if constraintErr := ber.CheckDecodedLength(opts, "eNB-List", "SIZE (3..8)", (*v.ENBList).BitLength); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:], opts...)
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "TraceInterfaceList", Cause: extErr_}
		}
		if offset < 0 || offset >
			len(content) || nExt_ < 0 || nExt_ > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		if offset < 0 || offset >
			len(content) || nExt_ < 0 || nExt_ > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes TraceEventList to BER format.
func (v *TraceEventList) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: TraceEventList receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *TraceEventList) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if v.MscSList != nil {
		if (*v.MscSList).BitLength < 5 || (*v.MscSList).BitLength > 16 {
			if constraintErr := ber.CheckEncodedLength(opts, "msc-s-List", "SIZE (5..16)", (*v.MscSList).BitLength); constraintErr != nil {
				return nil, constraintErr
			}
		}
		if bitStringErr := ber.ValidateBitStringLength(v.MscSList.Bytes, v.MscSList.BitLength); bitStringErr != nil {
			return nil, fmt.Errorf("encoding %s: %w", "msc-s-List", bitStringErr)
		}
		// arithmetic pattern BER_BITSTRING_FIELD: 0 <= bit length before modulo and subtraction; gen/codegen.go:526
		if v.MscSList.BitLength < 0 {
			return nil, fmt.Errorf("negative bit string length")
		}
		enc_mscslist, encodeErr_enc_mscslist := ber.EncodeBitString(v.MscSList.Bytes, (8-(v.MscSList.BitLength%8))%8)
		if encodeErr_enc_mscslist != nil {
			return nil, fmt.Errorf("encoding msc-s-List: %w", encodeErr_enc_mscslist)
		}
		retagged_enc_mscslist, tagErr_enc_mscslist := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_mscslist)
		if tagErr_enc_mscslist != nil {
			return nil, fmt.Errorf("encoding msc-s-List: %w", tagErr_enc_mscslist)
		}
		enc_mscslist = retagged_enc_mscslist
		children = append(children, enc_mscslist...)
	}
	if v.MgwList != nil {
		if (*v.MgwList).BitLength < 1 || (*v.MgwList).BitLength > 8 {
			if constraintErr := ber.CheckEncodedLength(opts, "mgw-List", "SIZE (1..8)", (*v.MgwList).BitLength); constraintErr != nil {
				return nil, constraintErr
			}
		}
		if bitStringErr := ber.ValidateBitStringLength(v.MgwList.Bytes, v.MgwList.BitLength); bitStringErr != nil {
			return nil, fmt.Errorf("encoding %s: %w", "mgw-List", bitStringErr)
		}
		// arithmetic pattern BER_BITSTRING_FIELD: 0 <= bit length before modulo and subtraction; gen/codegen.go:526
		if v.MgwList.BitLength < 0 {
			return nil, fmt.Errorf("negative bit string length")
		}
		enc_mgwlist, encodeErr_enc_mgwlist := ber.EncodeBitString(v.MgwList.Bytes, (8-(v.MgwList.BitLength%8))%8)
		if encodeErr_enc_mgwlist != nil {
			return nil, fmt.Errorf("encoding mgw-List: %w", encodeErr_enc_mgwlist)
		}
		retagged_enc_mgwlist, tagErr_enc_mgwlist := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_mgwlist)
		if tagErr_enc_mgwlist != nil {
			return nil, fmt.Errorf("encoding mgw-List: %w", tagErr_enc_mgwlist)
		}
		enc_mgwlist = retagged_enc_mgwlist
		children = append(children, enc_mgwlist...)
	}
	if v.SgsnList != nil {
		if (*v.SgsnList).BitLength < 4 || (*v.SgsnList).BitLength > 16 {
			if constraintErr := ber.CheckEncodedLength(opts, "sgsn-List", "SIZE (4..16)", (*v.SgsnList).BitLength); constraintErr != nil {
				return nil, constraintErr
			}
		}
		if bitStringErr := ber.ValidateBitStringLength(v.SgsnList.Bytes, v.SgsnList.BitLength); bitStringErr != nil {
			return nil, fmt.Errorf("encoding %s: %w", "sgsn-List", bitStringErr)
		}
		// arithmetic pattern BER_BITSTRING_FIELD: 0 <= bit length before modulo and subtraction; gen/codegen.go:526
		if v.SgsnList.BitLength < 0 {
			return nil, fmt.Errorf("negative bit string length")
		}
		enc_sgsnlist, encodeErr_enc_sgsnlist := ber.EncodeBitString(v.SgsnList.Bytes, (8-(v.SgsnList.BitLength%8))%8)
		if encodeErr_enc_sgsnlist != nil {
			return nil, fmt.Errorf("encoding sgsn-List: %w", encodeErr_enc_sgsnlist)
		}
		retagged_enc_sgsnlist, tagErr_enc_sgsnlist := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_sgsnlist)
		if tagErr_enc_sgsnlist != nil {
			return nil, fmt.Errorf("encoding sgsn-List: %w", tagErr_enc_sgsnlist)
		}
		enc_sgsnlist = retagged_enc_sgsnlist
		children = append(children, enc_sgsnlist...)
	}
	if v.GgsnList != nil {
		if (*v.GgsnList).BitLength < 2 || (*v.GgsnList).BitLength > 8 {
			if constraintErr := ber.CheckEncodedLength(opts, "ggsn-List", "SIZE (2..8)", (*v.GgsnList).BitLength); constraintErr != nil {
				return nil, constraintErr
			}
		}
		if bitStringErr := ber.ValidateBitStringLength(v.GgsnList.Bytes, v.GgsnList.BitLength); bitStringErr != nil {
			return nil, fmt.Errorf("encoding %s: %w", "ggsn-List", bitStringErr)
		}
		// arithmetic pattern BER_BITSTRING_FIELD: 0 <= bit length before modulo and subtraction; gen/codegen.go:526
		if v.GgsnList.BitLength < 0 {
			return nil, fmt.Errorf("negative bit string length")
		}
		enc_ggsnlist, encodeErr_enc_ggsnlist := ber.EncodeBitString(v.GgsnList.Bytes, (8-(v.GgsnList.BitLength%8))%8)
		if encodeErr_enc_ggsnlist != nil {
			return nil, fmt.Errorf("encoding ggsn-List: %w", encodeErr_enc_ggsnlist)
		}
		retagged_enc_ggsnlist, tagErr_enc_ggsnlist := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, enc_ggsnlist)
		if tagErr_enc_ggsnlist != nil {
			return nil, fmt.Errorf("encoding ggsn-List: %w", tagErr_enc_ggsnlist)
		}
		enc_ggsnlist = retagged_enc_ggsnlist
		children = append(children, enc_ggsnlist...)
	}
	if v.BmscList != nil {
		if (*v.BmscList).BitLength < 1 || (*v.BmscList).BitLength > 8 {
			if constraintErr := ber.CheckEncodedLength(opts, "bmsc-List", "SIZE (1..8)", (*v.BmscList).BitLength); constraintErr != nil {
				return nil, constraintErr
			}
		}
		if bitStringErr := ber.ValidateBitStringLength(v.BmscList.Bytes, v.BmscList.BitLength); bitStringErr != nil {
			return nil, fmt.Errorf("encoding %s: %w", "bmsc-List", bitStringErr)
		}
		// arithmetic pattern BER_BITSTRING_FIELD: 0 <= bit length before modulo and subtraction; gen/codegen.go:526
		if v.BmscList.BitLength < 0 {
			return nil, fmt.Errorf("negative bit string length")
		}
		enc_bmsclist, encodeErr_enc_bmsclist := ber.EncodeBitString(v.BmscList.Bytes, (8-(v.BmscList.BitLength%8))%8)
		if encodeErr_enc_bmsclist != nil {
			return nil, fmt.Errorf("encoding bmsc-List: %w", encodeErr_enc_bmsclist)
		}
		retagged_enc_bmsclist, tagErr_enc_bmsclist := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, enc_bmsclist)
		if tagErr_enc_bmsclist != nil {
			return nil, fmt.Errorf("encoding bmsc-List: %w", tagErr_enc_bmsclist)
		}
		enc_bmsclist = retagged_enc_bmsclist
		children = append(children, enc_bmsclist...)
	}
	if v.MmeList != nil {
		if (*v.MmeList).BitLength < 6 || (*v.MmeList).BitLength > 8 {
			if constraintErr := ber.CheckEncodedLength(opts, "mme-List", "SIZE (6..8)", (*v.MmeList).BitLength); constraintErr != nil {
				return nil, constraintErr
			}
		}
		if bitStringErr := ber.ValidateBitStringLength(v.MmeList.Bytes, v.MmeList.BitLength); bitStringErr != nil {
			return nil, fmt.Errorf("encoding %s: %w", "mme-List", bitStringErr)
		}
		// arithmetic pattern BER_BITSTRING_FIELD: 0 <= bit length before modulo and subtraction; gen/codegen.go:526
		if v.MmeList.BitLength < 0 {
			return nil, fmt.Errorf("negative bit string length")
		}
		enc_mmelist, encodeErr_enc_mmelist := ber.EncodeBitString(v.MmeList.Bytes, (8-(v.MmeList.BitLength%8))%8)
		if encodeErr_enc_mmelist != nil {
			return nil, fmt.Errorf("encoding mme-List: %w", encodeErr_enc_mmelist)
		}
		retagged_enc_mmelist, tagErr_enc_mmelist := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 5, enc_mmelist)
		if tagErr_enc_mmelist != nil {
			return nil, fmt.Errorf("encoding mme-List: %w", tagErr_enc_mmelist)
		}
		enc_mmelist = retagged_enc_mmelist
		children = append(children, enc_mmelist...)
	}
	if v.SgwList != nil {
		if (*v.SgwList).BitLength < 3 || (*v.SgwList).BitLength > 8 {
			if constraintErr := ber.CheckEncodedLength(opts, "sgw-List", "SIZE (3..8)", (*v.SgwList).BitLength); constraintErr != nil {
				return nil, constraintErr
			}
		}
		if bitStringErr := ber.ValidateBitStringLength(v.SgwList.Bytes, v.SgwList.BitLength); bitStringErr != nil {
			return nil, fmt.Errorf("encoding %s: %w", "sgw-List", bitStringErr)
		}
		// arithmetic pattern BER_BITSTRING_FIELD: 0 <= bit length before modulo and subtraction; gen/codegen.go:526
		if v.SgwList.BitLength < 0 {
			return nil, fmt.Errorf("negative bit string length")
		}
		enc_sgwlist, encodeErr_enc_sgwlist := ber.EncodeBitString(v.SgwList.Bytes, (8-(v.SgwList.BitLength%8))%8)
		if encodeErr_enc_sgwlist != nil {
			return nil, fmt.Errorf("encoding sgw-List: %w", encodeErr_enc_sgwlist)
		}
		retagged_enc_sgwlist, tagErr_enc_sgwlist := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 6, enc_sgwlist)
		if tagErr_enc_sgwlist != nil {
			return nil, fmt.Errorf("encoding sgw-List: %w", tagErr_enc_sgwlist)
		}
		enc_sgwlist = retagged_enc_sgwlist
		children = append(children, enc_sgwlist...)
	}
	if v.PgwList != nil {
		if (*v.PgwList).BitLength < 3 || (*v.PgwList).BitLength > 8 {
			if constraintErr := ber.CheckEncodedLength(opts, "pgw-List", "SIZE (3..8)", (*v.PgwList).BitLength); constraintErr != nil {
				return nil, constraintErr
			}
		}
		if bitStringErr := ber.ValidateBitStringLength(v.PgwList.Bytes, v.PgwList.BitLength); bitStringErr != nil {
			return nil, fmt.Errorf("encoding %s: %w", "pgw-List", bitStringErr)
		}
		// arithmetic pattern BER_BITSTRING_FIELD: 0 <= bit length before modulo and subtraction; gen/codegen.go:526
		if v.PgwList.BitLength < 0 {
			return nil, fmt.Errorf("negative bit string length")
		}
		enc_pgwlist, encodeErr_enc_pgwlist := ber.EncodeBitString(v.PgwList.Bytes, (8-(v.PgwList.BitLength%8))%8)
		if encodeErr_enc_pgwlist != nil {
			return nil, fmt.Errorf("encoding pgw-List: %w", encodeErr_enc_pgwlist)
		}
		retagged_enc_pgwlist, tagErr_enc_pgwlist := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 7, enc_pgwlist)
		if tagErr_enc_pgwlist != nil {
			return nil, fmt.Errorf("encoding pgw-List: %w", tagErr_enc_pgwlist)
		}
		enc_pgwlist = retagged_enc_pgwlist
		children = append(children, enc_pgwlist...)
	}
	for i, ext := range v.ExtData_ {
		_, n, _, extErr := ber.DecodeEncodedTLV(ext)
		if extErr != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, extErr)
		}
		if n != len(ext) {
			return nil, fmt.Errorf("encoding extension %d: %w", i, ber.ErrExtraData)
		}
		children = append(children, ext...)
	}
	return ber.EncodeSequence(children)
}

// MarshalDER encodes TraceEventList to DER format.
func (v *TraceEventList) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: TraceEventList receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if v.MscSList != nil {
		if (*v.MscSList).BitLength < 5 || (*v.MscSList).BitLength > 16 {
			if constraintErr := ber.CheckEncodedLength(nil, "msc-s-List", "SIZE (5..16)", (*v.MscSList).BitLength); constraintErr != nil {
				return nil, constraintErr
			}
		}
		if bitStringErr := ber.ValidateBitStringLength(v.MscSList.Bytes, v.MscSList.BitLength); bitStringErr != nil {
			return nil, fmt.Errorf("encoding %s: %w", "msc-s-List", bitStringErr)
		}
		if bitStringErr := ber.ValidateDERBitString(v.MscSList.Bytes, v.MscSList.BitLength); bitStringErr != nil {
			return nil, fmt.Errorf("encoding %s: %w", "msc-s-List", bitStringErr)
		}
		// arithmetic pattern BER_BITSTRING_FIELD: 0 <= bit length before modulo and subtraction; gen/codegen.go:526
		if v.MscSList.BitLength < 0 {
			return nil, fmt.Errorf("negative bit string length")
		}
		enc_mscslist, encodeErr_enc_mscslist := ber.EncodeDERNamedBitString(v.MscSList.Bytes, v.MscSList.BitLength)
		if encodeErr_enc_mscslist != nil {
			return nil, fmt.Errorf("encoding msc-s-List: %w", encodeErr_enc_mscslist)
		}
		retagged_enc_mscslist, tagErr_enc_mscslist := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_mscslist)
		if tagErr_enc_mscslist != nil {
			return nil, fmt.Errorf("encoding msc-s-List: %w", tagErr_enc_mscslist)
		}
		enc_mscslist = retagged_enc_mscslist
		children = append(children, enc_mscslist...)
	}
	if v.MgwList != nil {
		if (*v.MgwList).BitLength < 1 || (*v.MgwList).BitLength > 8 {
			if constraintErr := ber.CheckEncodedLength(nil, "mgw-List", "SIZE (1..8)", (*v.MgwList).BitLength); constraintErr != nil {
				return nil, constraintErr
			}
		}
		if bitStringErr := ber.ValidateBitStringLength(v.MgwList.Bytes, v.MgwList.BitLength); bitStringErr != nil {
			return nil, fmt.Errorf("encoding %s: %w", "mgw-List", bitStringErr)
		}
		if bitStringErr := ber.ValidateDERBitString(v.MgwList.Bytes, v.MgwList.BitLength); bitStringErr != nil {
			return nil, fmt.Errorf("encoding %s: %w", "mgw-List", bitStringErr)
		}
		// arithmetic pattern BER_BITSTRING_FIELD: 0 <= bit length before modulo and subtraction; gen/codegen.go:526
		if v.MgwList.BitLength < 0 {
			return nil, fmt.Errorf("negative bit string length")
		}
		enc_mgwlist, encodeErr_enc_mgwlist := ber.EncodeDERNamedBitString(v.MgwList.Bytes, v.MgwList.BitLength)
		if encodeErr_enc_mgwlist != nil {
			return nil, fmt.Errorf("encoding mgw-List: %w", encodeErr_enc_mgwlist)
		}
		retagged_enc_mgwlist, tagErr_enc_mgwlist := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_mgwlist)
		if tagErr_enc_mgwlist != nil {
			return nil, fmt.Errorf("encoding mgw-List: %w", tagErr_enc_mgwlist)
		}
		enc_mgwlist = retagged_enc_mgwlist
		children = append(children, enc_mgwlist...)
	}
	if v.SgsnList != nil {
		if (*v.SgsnList).BitLength < 4 || (*v.SgsnList).BitLength > 16 {
			if constraintErr := ber.CheckEncodedLength(nil, "sgsn-List", "SIZE (4..16)", (*v.SgsnList).BitLength); constraintErr != nil {
				return nil, constraintErr
			}
		}
		if bitStringErr := ber.ValidateBitStringLength(v.SgsnList.Bytes, v.SgsnList.BitLength); bitStringErr != nil {
			return nil, fmt.Errorf("encoding %s: %w", "sgsn-List", bitStringErr)
		}
		if bitStringErr := ber.ValidateDERBitString(v.SgsnList.Bytes, v.SgsnList.BitLength); bitStringErr != nil {
			return nil, fmt.Errorf("encoding %s: %w", "sgsn-List", bitStringErr)
		}
		// arithmetic pattern BER_BITSTRING_FIELD: 0 <= bit length before modulo and subtraction; gen/codegen.go:526
		if v.SgsnList.BitLength < 0 {
			return nil, fmt.Errorf("negative bit string length")
		}
		enc_sgsnlist, encodeErr_enc_sgsnlist := ber.EncodeDERNamedBitString(v.SgsnList.Bytes, v.SgsnList.BitLength)
		if encodeErr_enc_sgsnlist != nil {
			return nil, fmt.Errorf("encoding sgsn-List: %w", encodeErr_enc_sgsnlist)
		}
		retagged_enc_sgsnlist, tagErr_enc_sgsnlist := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_sgsnlist)
		if tagErr_enc_sgsnlist != nil {
			return nil, fmt.Errorf("encoding sgsn-List: %w", tagErr_enc_sgsnlist)
		}
		enc_sgsnlist = retagged_enc_sgsnlist
		children = append(children, enc_sgsnlist...)
	}
	if v.GgsnList != nil {
		if (*v.GgsnList).BitLength < 2 || (*v.GgsnList).BitLength > 8 {
			if constraintErr := ber.CheckEncodedLength(nil, "ggsn-List", "SIZE (2..8)", (*v.GgsnList).BitLength); constraintErr != nil {
				return nil, constraintErr
			}
		}
		if bitStringErr := ber.ValidateBitStringLength(v.GgsnList.Bytes, v.GgsnList.BitLength); bitStringErr != nil {
			return nil, fmt.Errorf("encoding %s: %w", "ggsn-List", bitStringErr)
		}
		if bitStringErr := ber.ValidateDERBitString(v.GgsnList.Bytes, v.GgsnList.BitLength); bitStringErr != nil {
			return nil, fmt.Errorf("encoding %s: %w", "ggsn-List", bitStringErr)
		}
		// arithmetic pattern BER_BITSTRING_FIELD: 0 <= bit length before modulo and subtraction; gen/codegen.go:526
		if v.GgsnList.BitLength < 0 {
			return nil, fmt.Errorf("negative bit string length")
		}
		enc_ggsnlist, encodeErr_enc_ggsnlist := ber.EncodeDERNamedBitString(v.GgsnList.Bytes, v.GgsnList.BitLength)
		if encodeErr_enc_ggsnlist != nil {
			return nil, fmt.Errorf("encoding ggsn-List: %w", encodeErr_enc_ggsnlist)
		}
		retagged_enc_ggsnlist, tagErr_enc_ggsnlist := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, enc_ggsnlist)
		if tagErr_enc_ggsnlist != nil {
			return nil, fmt.Errorf("encoding ggsn-List: %w", tagErr_enc_ggsnlist)
		}
		enc_ggsnlist = retagged_enc_ggsnlist
		children = append(children, enc_ggsnlist...)
	}
	if v.BmscList != nil {
		if (*v.BmscList).BitLength < 1 || (*v.BmscList).BitLength > 8 {
			if constraintErr := ber.CheckEncodedLength(nil, "bmsc-List", "SIZE (1..8)", (*v.BmscList).BitLength); constraintErr != nil {
				return nil, constraintErr
			}
		}
		if bitStringErr := ber.ValidateBitStringLength(v.BmscList.Bytes, v.BmscList.BitLength); bitStringErr != nil {
			return nil, fmt.Errorf("encoding %s: %w", "bmsc-List", bitStringErr)
		}
		if bitStringErr := ber.ValidateDERBitString(v.BmscList.Bytes, v.BmscList.BitLength); bitStringErr != nil {
			return nil, fmt.Errorf("encoding %s: %w", "bmsc-List", bitStringErr)
		}
		// arithmetic pattern BER_BITSTRING_FIELD: 0 <= bit length before modulo and subtraction; gen/codegen.go:526
		if v.BmscList.BitLength < 0 {
			return nil, fmt.Errorf("negative bit string length")
		}
		enc_bmsclist, encodeErr_enc_bmsclist := ber.EncodeDERNamedBitString(v.BmscList.Bytes, v.BmscList.BitLength)
		if encodeErr_enc_bmsclist != nil {
			return nil, fmt.Errorf("encoding bmsc-List: %w", encodeErr_enc_bmsclist)
		}
		retagged_enc_bmsclist, tagErr_enc_bmsclist := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, enc_bmsclist)
		if tagErr_enc_bmsclist != nil {
			return nil, fmt.Errorf("encoding bmsc-List: %w", tagErr_enc_bmsclist)
		}
		enc_bmsclist = retagged_enc_bmsclist
		children = append(children, enc_bmsclist...)
	}
	if v.MmeList != nil {
		if (*v.MmeList).BitLength < 6 || (*v.MmeList).BitLength > 8 {
			if constraintErr := ber.CheckEncodedLength(nil, "mme-List", "SIZE (6..8)", (*v.MmeList).BitLength); constraintErr != nil {
				return nil, constraintErr
			}
		}
		if bitStringErr := ber.ValidateBitStringLength(v.MmeList.Bytes, v.MmeList.BitLength); bitStringErr != nil {
			return nil, fmt.Errorf("encoding %s: %w", "mme-List", bitStringErr)
		}
		if bitStringErr := ber.ValidateDERBitString(v.MmeList.Bytes, v.MmeList.BitLength); bitStringErr != nil {
			return nil, fmt.Errorf("encoding %s: %w", "mme-List", bitStringErr)
		}
		// arithmetic pattern BER_BITSTRING_FIELD: 0 <= bit length before modulo and subtraction; gen/codegen.go:526
		if v.MmeList.BitLength < 0 {
			return nil, fmt.Errorf("negative bit string length")
		}
		enc_mmelist, encodeErr_enc_mmelist := ber.EncodeDERNamedBitString(v.MmeList.Bytes, v.MmeList.BitLength)
		if encodeErr_enc_mmelist != nil {
			return nil, fmt.Errorf("encoding mme-List: %w", encodeErr_enc_mmelist)
		}
		retagged_enc_mmelist, tagErr_enc_mmelist := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 5, enc_mmelist)
		if tagErr_enc_mmelist != nil {
			return nil, fmt.Errorf("encoding mme-List: %w", tagErr_enc_mmelist)
		}
		enc_mmelist = retagged_enc_mmelist
		children = append(children, enc_mmelist...)
	}
	if v.SgwList != nil {
		if (*v.SgwList).BitLength < 3 || (*v.SgwList).BitLength > 8 {
			if constraintErr := ber.CheckEncodedLength(nil, "sgw-List", "SIZE (3..8)", (*v.SgwList).BitLength); constraintErr != nil {
				return nil, constraintErr
			}
		}
		if bitStringErr := ber.ValidateBitStringLength(v.SgwList.Bytes, v.SgwList.BitLength); bitStringErr != nil {
			return nil, fmt.Errorf("encoding %s: %w", "sgw-List", bitStringErr)
		}
		if bitStringErr := ber.ValidateDERBitString(v.SgwList.Bytes, v.SgwList.BitLength); bitStringErr != nil {
			return nil, fmt.Errorf("encoding %s: %w", "sgw-List", bitStringErr)
		}
		// arithmetic pattern BER_BITSTRING_FIELD: 0 <= bit length before modulo and subtraction; gen/codegen.go:526
		if v.SgwList.BitLength < 0 {
			return nil, fmt.Errorf("negative bit string length")
		}
		enc_sgwlist, encodeErr_enc_sgwlist := ber.EncodeDERNamedBitString(v.SgwList.Bytes, v.SgwList.BitLength)
		if encodeErr_enc_sgwlist != nil {
			return nil, fmt.Errorf("encoding sgw-List: %w", encodeErr_enc_sgwlist)
		}
		retagged_enc_sgwlist, tagErr_enc_sgwlist := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 6, enc_sgwlist)
		if tagErr_enc_sgwlist != nil {
			return nil, fmt.Errorf("encoding sgw-List: %w", tagErr_enc_sgwlist)
		}
		enc_sgwlist = retagged_enc_sgwlist
		children = append(children, enc_sgwlist...)
	}
	if v.PgwList != nil {
		if (*v.PgwList).BitLength < 3 || (*v.PgwList).BitLength > 8 {
			if constraintErr := ber.CheckEncodedLength(nil, "pgw-List", "SIZE (3..8)", (*v.PgwList).BitLength); constraintErr != nil {
				return nil, constraintErr
			}
		}
		if bitStringErr := ber.ValidateBitStringLength(v.PgwList.Bytes, v.PgwList.BitLength); bitStringErr != nil {
			return nil, fmt.Errorf("encoding %s: %w", "pgw-List", bitStringErr)
		}
		if bitStringErr := ber.ValidateDERBitString(v.PgwList.Bytes, v.PgwList.BitLength); bitStringErr != nil {
			return nil, fmt.Errorf("encoding %s: %w", "pgw-List", bitStringErr)
		}
		// arithmetic pattern BER_BITSTRING_FIELD: 0 <= bit length before modulo and subtraction; gen/codegen.go:526
		if v.PgwList.BitLength < 0 {
			return nil, fmt.Errorf("negative bit string length")
		}
		enc_pgwlist, encodeErr_enc_pgwlist := ber.EncodeDERNamedBitString(v.PgwList.Bytes, v.PgwList.BitLength)
		if encodeErr_enc_pgwlist != nil {
			return nil, fmt.Errorf("encoding pgw-List: %w", encodeErr_enc_pgwlist)
		}
		retagged_enc_pgwlist, tagErr_enc_pgwlist := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 7, enc_pgwlist)
		if tagErr_enc_pgwlist != nil {
			return nil, fmt.Errorf("encoding pgw-List: %w", tagErr_enc_pgwlist)
		}
		enc_pgwlist = retagged_enc_pgwlist
		children = append(children, enc_pgwlist...)
	}
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDEREncodedElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
		children = append(children, ext...)
	}
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding TraceEventList as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes TraceEventList from BER/DER format.
func (v *TraceEventList) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: TraceEventList destination is nil", ber.ErrInvalidValue)
	}
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = TraceEventList{}
	defer func() {
		if returnErr != nil || !ber.BERNeedsPreservation(opts) {
			return
		}
		var snapshotReports ber.ViolationLog
		snapshot, snapshotErr := v.marshalBER(ber.WithConstraintTolerance(&snapshotReports))
		if snapshotErr != nil {
			returnErr = snapshotErr
			return
		}
		v.berOriginal_ = append([]byte(nil), data...)
		v.berSnapshot_ = snapshot
	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("decoding TraceEventList SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "TraceEventList", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode msc-s-List
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
				decodedTag_mscslist, n_mscslist, rawVal_mscslist, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding msc-s-List: %w", err)
				}
				if decodedTag_mscslist.Class != tag.ClassContextSpecific || decodedTag_mscslist.Number != 0 {
					return fmt.Errorf("decoding msc-s-List: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_mscslist)
				}
				bsBytes_mscslist, bsUnused_mscslist, bsErr := ber.DecodeImplicitBitStringValue(decodedTag_mscslist.Constructed, rawVal_mscslist, opts...)
				if bsErr != nil {
					return fmt.Errorf("decoding msc-s-List: %w", bsErr)
				}
				bsBitLength_mscslist, bsLenErr_mscslist := ber.BitStringBitLength(len(bsBytes_mscslist), bsUnused_mscslist)
				if bsLenErr_mscslist != nil {
					return fmt.Errorf("decoding msc-s-List: %w", bsLenErr_mscslist)
				}
				tmp_mscslist := runtime.BitString{Bytes: bsBytes_mscslist, BitLength: bsBitLength_mscslist}
				v.MscSList = &tmp_mscslist
				if offset > len(content) || n_mscslist < 0 || n_mscslist > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_mscslist
				*v.MscSList = ber.NormalizeNamedBitStringSize(*v.MscSList, []ber.NamedBitSizeSet{{{Min: 5, Max: 16}}}, opts...)
				if (*v.MscSList).BitLength < 5 || (*v.MscSList).BitLength > 16 {
					if constraintErr := ber.CheckDecodedLength(opts, "msc-s-List", "SIZE (5..16)", (*v.MscSList).BitLength); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode mgw-List
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
				decodedTag_mgwlist, n_mgwlist, rawVal_mgwlist, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding mgw-List: %w", err)
				}
				if decodedTag_mgwlist.Class != tag.ClassContextSpecific || decodedTag_mgwlist.Number != 1 {
					return fmt.Errorf("decoding mgw-List: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_mgwlist)
				}
				bsBytes_mgwlist, bsUnused_mgwlist, bsErr := ber.DecodeImplicitBitStringValue(decodedTag_mgwlist.Constructed, rawVal_mgwlist, opts...)
				if bsErr != nil {
					return fmt.Errorf("decoding mgw-List: %w", bsErr)
				}
				bsBitLength_mgwlist, bsLenErr_mgwlist := ber.BitStringBitLength(len(bsBytes_mgwlist), bsUnused_mgwlist)
				if bsLenErr_mgwlist != nil {
					return fmt.Errorf("decoding mgw-List: %w", bsLenErr_mgwlist)
				}
				tmp_mgwlist := runtime.BitString{Bytes: bsBytes_mgwlist, BitLength: bsBitLength_mgwlist}
				v.MgwList = &tmp_mgwlist
				if offset < 0 || offset >
					len(content) || n_mgwlist < 0 || n_mgwlist > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_mgwlist
				*v.MgwList = ber.NormalizeNamedBitStringSize(*v.MgwList, []ber.NamedBitSizeSet{{{Min: 1, Max: 8}}}, opts...)
				if (*v.MgwList).BitLength < 1 || (*v.MgwList).BitLength > 8 {
					if constraintErr := ber.CheckDecodedLength(opts, "mgw-List", "SIZE (1..8)", (*v.MgwList).BitLength); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode sgsn-List
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2 {
				decodedTag_sgsnlist, n_sgsnlist, rawVal_sgsnlist, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding sgsn-List: %w", err)
				}
				if decodedTag_sgsnlist.Class != tag.ClassContextSpecific || decodedTag_sgsnlist.Number != 2 {
					return fmt.Errorf("decoding sgsn-List: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_sgsnlist)
				}
				bsBytes_sgsnlist, bsUnused_sgsnlist, bsErr := ber.DecodeImplicitBitStringValue(decodedTag_sgsnlist.Constructed, rawVal_sgsnlist, opts...)
				if bsErr != nil {
					return fmt.Errorf("decoding sgsn-List: %w", bsErr)
				}
				bsBitLength_sgsnlist, bsLenErr_sgsnlist := ber.BitStringBitLength(len(bsBytes_sgsnlist), bsUnused_sgsnlist)
				if bsLenErr_sgsnlist != nil {
					return fmt.Errorf("decoding sgsn-List: %w", bsLenErr_sgsnlist)
				}
				tmp_sgsnlist := runtime.BitString{Bytes: bsBytes_sgsnlist, BitLength: bsBitLength_sgsnlist}
				v.SgsnList = &tmp_sgsnlist
				if offset < 0 || offset >
					len(content) || n_sgsnlist < 0 || n_sgsnlist > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_sgsnlist
				*v.SgsnList = ber.NormalizeNamedBitStringSize(*v.SgsnList, []ber.NamedBitSizeSet{{{Min: 4, Max: 16}}}, opts...)
				if (*v.SgsnList).BitLength < 4 || (*v.SgsnList).BitLength > 16 {
					if constraintErr := ber.CheckDecodedLength(opts, "sgsn-List", "SIZE (4..16)", (*v.SgsnList).BitLength); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode ggsn-List
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3 {
				decodedTag_ggsnlist, n_ggsnlist, rawVal_ggsnlist, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding ggsn-List: %w", err)
				}
				if decodedTag_ggsnlist.Class != tag.ClassContextSpecific || decodedTag_ggsnlist.Number != 3 {
					return fmt.Errorf("decoding ggsn-List: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_ggsnlist)
				}
				bsBytes_ggsnlist, bsUnused_ggsnlist, bsErr := ber.DecodeImplicitBitStringValue(decodedTag_ggsnlist.Constructed, rawVal_ggsnlist, opts...)
				if bsErr != nil {
					return fmt.Errorf("decoding ggsn-List: %w", bsErr)
				}
				bsBitLength_ggsnlist, bsLenErr_ggsnlist := ber.BitStringBitLength(len(bsBytes_ggsnlist), bsUnused_ggsnlist)
				if bsLenErr_ggsnlist != nil {
					return fmt.Errorf("decoding ggsn-List: %w", bsLenErr_ggsnlist)
				}
				tmp_ggsnlist := runtime.BitString{Bytes: bsBytes_ggsnlist, BitLength: bsBitLength_ggsnlist}
				v.GgsnList = &tmp_ggsnlist
				if offset < 0 || offset >
					len(content) || n_ggsnlist < 0 || n_ggsnlist > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_ggsnlist
				*v.GgsnList = ber.NormalizeNamedBitStringSize(*v.GgsnList, []ber.NamedBitSizeSet{{{Min: 2, Max: 8}}}, opts...)
				if (*v.GgsnList).BitLength < 2 || (*v.GgsnList).BitLength > 8 {
					if constraintErr := ber.CheckDecodedLength(opts, "ggsn-List", "SIZE (2..8)", (*v.GgsnList).BitLength); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode bmsc-List
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4 {
				decodedTag_bmsclist, n_bmsclist, rawVal_bmsclist, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding bmsc-List: %w", err)
				}
				if decodedTag_bmsclist.Class != tag.ClassContextSpecific || decodedTag_bmsclist.Number != 4 {
					return fmt.Errorf("decoding bmsc-List: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_bmsclist)
				}
				bsBytes_bmsclist, bsUnused_bmsclist, bsErr := ber.DecodeImplicitBitStringValue(decodedTag_bmsclist.Constructed, rawVal_bmsclist, opts...)
				if bsErr != nil {
					return fmt.Errorf("decoding bmsc-List: %w", bsErr)
				}
				bsBitLength_bmsclist, bsLenErr_bmsclist := ber.BitStringBitLength(len(bsBytes_bmsclist), bsUnused_bmsclist)
				if bsLenErr_bmsclist != nil {
					return fmt.Errorf("decoding bmsc-List: %w", bsLenErr_bmsclist)
				}
				tmp_bmsclist := runtime.BitString{Bytes: bsBytes_bmsclist, BitLength: bsBitLength_bmsclist}
				v.BmscList = &tmp_bmsclist
				if offset < 0 || offset >
					len(content) || n_bmsclist < 0 || n_bmsclist > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_bmsclist
				*v.BmscList = ber.NormalizeNamedBitStringSize(*v.BmscList, []ber.NamedBitSizeSet{{{Min: 1, Max: 8}}}, opts...)
				if (*v.BmscList).BitLength < 1 || (*v.BmscList).BitLength > 8 {
					if constraintErr := ber.CheckDecodedLength(opts, "bmsc-List", "SIZE (1..8)", (*v.BmscList).BitLength); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode mme-List
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 5 {
				decodedTag_mmelist, n_mmelist, rawVal_mmelist, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding mme-List: %w", err)
				}
				if decodedTag_mmelist.Class != tag.ClassContextSpecific || decodedTag_mmelist.Number != 5 {
					return fmt.Errorf("decoding mme-List: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_mmelist)
				}
				bsBytes_mmelist, bsUnused_mmelist, bsErr := ber.DecodeImplicitBitStringValue(decodedTag_mmelist.Constructed, rawVal_mmelist, opts...)
				if bsErr != nil {
					return fmt.Errorf("decoding mme-List: %w", bsErr)
				}
				bsBitLength_mmelist, bsLenErr_mmelist := ber.BitStringBitLength(len(bsBytes_mmelist), bsUnused_mmelist)
				if bsLenErr_mmelist != nil {
					return fmt.Errorf("decoding mme-List: %w", bsLenErr_mmelist)
				}
				tmp_mmelist := runtime.BitString{Bytes: bsBytes_mmelist, BitLength: bsBitLength_mmelist}
				v.MmeList = &tmp_mmelist
				if offset < 0 || offset >
					len(content) || n_mmelist < 0 || n_mmelist > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_mmelist
				*v.MmeList = ber.NormalizeNamedBitStringSize(*v.MmeList, []ber.NamedBitSizeSet{{{Min: 6, Max: 8}}}, opts...)
				if (*v.MmeList).BitLength < 6 || (*v.MmeList).BitLength > 8 {
					if constraintErr := ber.CheckDecodedLength(opts, "mme-List", "SIZE (6..8)", (*v.MmeList).BitLength); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode sgw-List
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 6 {
				decodedTag_sgwlist, n_sgwlist, rawVal_sgwlist, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding sgw-List: %w", err)
				}
				if decodedTag_sgwlist.Class != tag.ClassContextSpecific || decodedTag_sgwlist.Number != 6 {
					return fmt.Errorf("decoding sgw-List: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_sgwlist)
				}
				bsBytes_sgwlist, bsUnused_sgwlist, bsErr := ber.DecodeImplicitBitStringValue(decodedTag_sgwlist.Constructed, rawVal_sgwlist, opts...)
				if bsErr != nil {
					return fmt.Errorf("decoding sgw-List: %w", bsErr)
				}
				bsBitLength_sgwlist, bsLenErr_sgwlist := ber.BitStringBitLength(len(bsBytes_sgwlist), bsUnused_sgwlist)
				if bsLenErr_sgwlist != nil {
					return fmt.Errorf("decoding sgw-List: %w", bsLenErr_sgwlist)
				}
				tmp_sgwlist := runtime.BitString{Bytes: bsBytes_sgwlist, BitLength: bsBitLength_sgwlist}
				v.SgwList = &tmp_sgwlist
				if offset < 0 || offset >
					len(content) || n_sgwlist < 0 || n_sgwlist > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_sgwlist
				*v.SgwList = ber.NormalizeNamedBitStringSize(*v.SgwList, []ber.NamedBitSizeSet{{{Min: 3, Max: 8}}}, opts...)
				if (*v.SgwList).BitLength < 3 || (*v.SgwList).BitLength > 8 {
					if constraintErr := ber.CheckDecodedLength(opts, "sgw-List", "SIZE (3..8)", (*v.SgwList).BitLength); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode pgw-List
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 7 {
				decodedTag_pgwlist, n_pgwlist, rawVal_pgwlist, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding pgw-List: %w", err)
				}
				if decodedTag_pgwlist.Class != tag.ClassContextSpecific || decodedTag_pgwlist.Number != 7 {
					return fmt.Errorf("decoding pgw-List: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_pgwlist)
				}
				bsBytes_pgwlist, bsUnused_pgwlist, bsErr := ber.DecodeImplicitBitStringValue(decodedTag_pgwlist.Constructed, rawVal_pgwlist, opts...)
				if bsErr != nil {
					return fmt.Errorf("decoding pgw-List: %w", bsErr)
				}
				bsBitLength_pgwlist, bsLenErr_pgwlist := ber.BitStringBitLength(len(bsBytes_pgwlist), bsUnused_pgwlist)
				if bsLenErr_pgwlist != nil {
					return fmt.Errorf("decoding pgw-List: %w", bsLenErr_pgwlist)
				}
				tmp_pgwlist := runtime.BitString{Bytes: bsBytes_pgwlist, BitLength: bsBitLength_pgwlist}
				v.PgwList = &tmp_pgwlist
				if offset < 0 || offset >
					len(content) || n_pgwlist < 0 || n_pgwlist > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_pgwlist
				*v.PgwList = ber.NormalizeNamedBitStringSize(*v.PgwList, []ber.NamedBitSizeSet{{{Min: 3, Max: 8}}}, opts...)
				if (*v.PgwList).BitLength < 3 || (*v.PgwList).BitLength > 8 {
					if constraintErr := ber.CheckDecodedLength(opts, "pgw-List", "SIZE (3..8)", (*v.PgwList).BitLength); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:], opts...)
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "TraceEventList", Cause: extErr_}
		}
		if offset < 0 || offset >
			len(content) || nExt_ < 0 || nExt_ > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		if offset < 0 || offset >
			len(content) || nExt_ < 0 || nExt_ > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes TracePropagationList to BER format.
func (v *TracePropagationList) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: TracePropagationList receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *TracePropagationList) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if v.TraceReference != nil {
		if len(*v.TraceReference) < 1 || len(*v.TraceReference) > 2 {
			if constraintErr := ber.CheckEncodedLength(opts, "traceReference", "SIZE (1..2)", len(*v.TraceReference)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_tracereference, encodeErr_enc_tracereference := ber.EncodeOctetString([]byte(*v.TraceReference))
		if encodeErr_enc_tracereference != nil {
			return nil, fmt.Errorf("encoding traceReference: %w", encodeErr_enc_tracereference)
		}
		retagged_enc_tracereference, tagErr_enc_tracereference := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_tracereference)
		if tagErr_enc_tracereference != nil {
			return nil, fmt.Errorf("encoding traceReference: %w", tagErr_enc_tracereference)
		}
		enc_tracereference = retagged_enc_tracereference
		children = append(children, enc_tracereference...)
	}
	if v.TraceType != nil {
		if !(int64(*v.TraceType) >= 0 && int64(*v.TraceType) <= 255) {
			if constraintErr := ber.CheckEncodedValue(opts, "traceType", "(0..255)", fmt.Sprint(int64(*v.TraceType))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_tracetype := ber.EncodeInteger(int64(*v.TraceType))
		retagged_enc_tracetype, tagErr_enc_tracetype := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_tracetype)
		if tagErr_enc_tracetype != nil {
			return nil, fmt.Errorf("encoding traceType: %w", tagErr_enc_tracetype)
		}
		enc_tracetype = retagged_enc_tracetype
		children = append(children, enc_tracetype...)
	}
	if v.TraceReference2 != nil {
		if len(*v.TraceReference2) < 3 || len(*v.TraceReference2) > 3 {
			if constraintErr := ber.CheckEncodedLength(opts, "traceReference2", "SIZE (3)", len(*v.TraceReference2)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_tracereference2, encodeErr_enc_tracereference2 := ber.EncodeOctetString([]byte(*v.TraceReference2))
		if encodeErr_enc_tracereference2 != nil {
			return nil, fmt.Errorf("encoding traceReference2: %w", encodeErr_enc_tracereference2)
		}
		retagged_enc_tracereference2, tagErr_enc_tracereference2 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_tracereference2)
		if tagErr_enc_tracereference2 != nil {
			return nil, fmt.Errorf("encoding traceReference2: %w", tagErr_enc_tracereference2)
		}
		enc_tracereference2 = retagged_enc_tracereference2
		children = append(children, enc_tracereference2...)
	}
	if v.TraceRecordingSessionReference != nil {
		if len(*v.TraceRecordingSessionReference) < 2 || len(*v.TraceRecordingSessionReference) > 2 {
			if constraintErr := ber.CheckEncodedLength(opts, "traceRecordingSessionReference", "SIZE (2)", len(*v.TraceRecordingSessionReference)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_tracerecordingsessionreference, encodeErr_enc_tracerecordingsessionreference := ber.EncodeOctetString([]byte(*v.TraceRecordingSessionReference))
		if encodeErr_enc_tracerecordingsessionreference != nil {
			return nil, fmt.Errorf("encoding traceRecordingSessionReference: %w", encodeErr_enc_tracerecordingsessionreference)
		}
		retagged_enc_tracerecordingsessionreference, tagErr_enc_tracerecordingsessionreference := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, enc_tracerecordingsessionreference)
		if tagErr_enc_tracerecordingsessionreference != nil {
			return nil, fmt.Errorf("encoding traceRecordingSessionReference: %w", tagErr_enc_tracerecordingsessionreference)
		}
		enc_tracerecordingsessionreference = retagged_enc_tracerecordingsessionreference
		children = append(children, enc_tracerecordingsessionreference...)
	}
	if v.RncTraceDepth != nil {
		enc_rnctracedepth := ber.EncodeEnumerated(int64(*v.RncTraceDepth))
		retagged_enc_rnctracedepth, tagErr_enc_rnctracedepth := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, enc_rnctracedepth)
		if tagErr_enc_rnctracedepth != nil {
			return nil, fmt.Errorf("encoding rnc-TraceDepth: %w", tagErr_enc_rnctracedepth)
		}
		enc_rnctracedepth = retagged_enc_rnctracedepth
		children = append(children, enc_rnctracedepth...)
	}
	if v.RncInterfaceList != nil {
		if (*v.RncInterfaceList).BitLength < 4 || (*v.RncInterfaceList).BitLength > 8 {
			if constraintErr := ber.CheckEncodedLength(opts, "rnc-InterfaceList", "SIZE (4..8)", (*v.RncInterfaceList).BitLength); constraintErr != nil {
				return nil, constraintErr
			}
		}
		if bitStringErr := ber.ValidateBitStringLength(v.RncInterfaceList.Bytes, v.RncInterfaceList.BitLength); bitStringErr != nil {
			return nil, fmt.Errorf("encoding %s: %w", "rnc-InterfaceList", bitStringErr)
		}
		// arithmetic pattern BER_BITSTRING_FIELD: 0 <= bit length before modulo and subtraction; gen/codegen.go:526
		if v.RncInterfaceList.BitLength < 0 {
			return nil, fmt.Errorf("negative bit string length")
		}
		enc_rncinterfacelist, encodeErr_enc_rncinterfacelist := ber.EncodeBitString(v.RncInterfaceList.Bytes, (8-(v.RncInterfaceList.BitLength%8))%8)
		if encodeErr_enc_rncinterfacelist != nil {
			return nil, fmt.Errorf("encoding rnc-InterfaceList: %w", encodeErr_enc_rncinterfacelist)
		}
		retagged_enc_rncinterfacelist, tagErr_enc_rncinterfacelist := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 5, enc_rncinterfacelist)
		if tagErr_enc_rncinterfacelist != nil {
			return nil, fmt.Errorf("encoding rnc-InterfaceList: %w", tagErr_enc_rncinterfacelist)
		}
		enc_rncinterfacelist = retagged_enc_rncinterfacelist
		children = append(children, enc_rncinterfacelist...)
	}
	if v.MscSTraceDepth != nil {
		enc_mscstracedepth := ber.EncodeEnumerated(int64(*v.MscSTraceDepth))
		retagged_enc_mscstracedepth, tagErr_enc_mscstracedepth := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 6, enc_mscstracedepth)
		if tagErr_enc_mscstracedepth != nil {
			return nil, fmt.Errorf("encoding msc-s-TraceDepth: %w", tagErr_enc_mscstracedepth)
		}
		enc_mscstracedepth = retagged_enc_mscstracedepth
		children = append(children, enc_mscstracedepth...)
	}
	if v.MscSInterfaceList != nil {
		if (*v.MscSInterfaceList).BitLength < 10 || (*v.MscSInterfaceList).BitLength > 16 {
			if constraintErr := ber.CheckEncodedLength(opts, "msc-s-InterfaceList", "SIZE (10..16)", (*v.MscSInterfaceList).BitLength); constraintErr != nil {
				return nil, constraintErr
			}
		}
		if bitStringErr := ber.ValidateBitStringLength(v.MscSInterfaceList.Bytes, v.MscSInterfaceList.BitLength); bitStringErr != nil {
			return nil, fmt.Errorf("encoding %s: %w", "msc-s-InterfaceList", bitStringErr)
		}
		// arithmetic pattern BER_BITSTRING_FIELD: 0 <= bit length before modulo and subtraction; gen/codegen.go:526
		if v.MscSInterfaceList.BitLength < 0 {
			return nil, fmt.Errorf("negative bit string length")
		}
		enc_mscsinterfacelist, encodeErr_enc_mscsinterfacelist := ber.EncodeBitString(v.MscSInterfaceList.Bytes, (8-(v.MscSInterfaceList.BitLength%8))%8)
		if encodeErr_enc_mscsinterfacelist != nil {
			return nil, fmt.Errorf("encoding msc-s-InterfaceList: %w", encodeErr_enc_mscsinterfacelist)
		}
		retagged_enc_mscsinterfacelist, tagErr_enc_mscsinterfacelist := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 7, enc_mscsinterfacelist)
		if tagErr_enc_mscsinterfacelist != nil {
			return nil, fmt.Errorf("encoding msc-s-InterfaceList: %w", tagErr_enc_mscsinterfacelist)
		}
		enc_mscsinterfacelist = retagged_enc_mscsinterfacelist
		children = append(children, enc_mscsinterfacelist...)
	}
	if v.MscSEventList != nil {
		if (*v.MscSEventList).BitLength < 5 || (*v.MscSEventList).BitLength > 16 {
			if constraintErr := ber.CheckEncodedLength(opts, "msc-s-EventList", "SIZE (5..16)", (*v.MscSEventList).BitLength); constraintErr != nil {
				return nil, constraintErr
			}
		}
		if bitStringErr := ber.ValidateBitStringLength(v.MscSEventList.Bytes, v.MscSEventList.BitLength); bitStringErr != nil {
			return nil, fmt.Errorf("encoding %s: %w", "msc-s-EventList", bitStringErr)
		}
		// arithmetic pattern BER_BITSTRING_FIELD: 0 <= bit length before modulo and subtraction; gen/codegen.go:526
		if v.MscSEventList.BitLength < 0 {
			return nil, fmt.Errorf("negative bit string length")
		}
		enc_mscseventlist, encodeErr_enc_mscseventlist := ber.EncodeBitString(v.MscSEventList.Bytes, (8-(v.MscSEventList.BitLength%8))%8)
		if encodeErr_enc_mscseventlist != nil {
			return nil, fmt.Errorf("encoding msc-s-EventList: %w", encodeErr_enc_mscseventlist)
		}
		retagged_enc_mscseventlist, tagErr_enc_mscseventlist := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 8, enc_mscseventlist)
		if tagErr_enc_mscseventlist != nil {
			return nil, fmt.Errorf("encoding msc-s-EventList: %w", tagErr_enc_mscseventlist)
		}
		enc_mscseventlist = retagged_enc_mscseventlist
		children = append(children, enc_mscseventlist...)
	}
	if v.MgwTraceDepth != nil {
		enc_mgwtracedepth := ber.EncodeEnumerated(int64(*v.MgwTraceDepth))
		retagged_enc_mgwtracedepth, tagErr_enc_mgwtracedepth := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 9, enc_mgwtracedepth)
		if tagErr_enc_mgwtracedepth != nil {
			return nil, fmt.Errorf("encoding mgw-TraceDepth: %w", tagErr_enc_mgwtracedepth)
		}
		enc_mgwtracedepth = retagged_enc_mgwtracedepth
		children = append(children, enc_mgwtracedepth...)
	}
	if v.MgwInterfaceList != nil {
		if (*v.MgwInterfaceList).BitLength < 3 || (*v.MgwInterfaceList).BitLength > 8 {
			if constraintErr := ber.CheckEncodedLength(opts, "mgw-InterfaceList", "SIZE (3..8)", (*v.MgwInterfaceList).BitLength); constraintErr != nil {
				return nil, constraintErr
			}
		}
		if bitStringErr := ber.ValidateBitStringLength(v.MgwInterfaceList.Bytes, v.MgwInterfaceList.BitLength); bitStringErr != nil {
			return nil, fmt.Errorf("encoding %s: %w", "mgw-InterfaceList", bitStringErr)
		}
		// arithmetic pattern BER_BITSTRING_FIELD: 0 <= bit length before modulo and subtraction; gen/codegen.go:526
		if v.MgwInterfaceList.BitLength < 0 {
			return nil, fmt.Errorf("negative bit string length")
		}
		enc_mgwinterfacelist, encodeErr_enc_mgwinterfacelist := ber.EncodeBitString(v.MgwInterfaceList.Bytes, (8-(v.MgwInterfaceList.BitLength%8))%8)
		if encodeErr_enc_mgwinterfacelist != nil {
			return nil, fmt.Errorf("encoding mgw-InterfaceList: %w", encodeErr_enc_mgwinterfacelist)
		}
		retagged_enc_mgwinterfacelist, tagErr_enc_mgwinterfacelist := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 10, enc_mgwinterfacelist)
		if tagErr_enc_mgwinterfacelist != nil {
			return nil, fmt.Errorf("encoding mgw-InterfaceList: %w", tagErr_enc_mgwinterfacelist)
		}
		enc_mgwinterfacelist = retagged_enc_mgwinterfacelist
		children = append(children, enc_mgwinterfacelist...)
	}
	if v.MgwEventList != nil {
		if (*v.MgwEventList).BitLength < 1 || (*v.MgwEventList).BitLength > 8 {
			if constraintErr := ber.CheckEncodedLength(opts, "mgw-EventList", "SIZE (1..8)", (*v.MgwEventList).BitLength); constraintErr != nil {
				return nil, constraintErr
			}
		}
		if bitStringErr := ber.ValidateBitStringLength(v.MgwEventList.Bytes, v.MgwEventList.BitLength); bitStringErr != nil {
			return nil, fmt.Errorf("encoding %s: %w", "mgw-EventList", bitStringErr)
		}
		// arithmetic pattern BER_BITSTRING_FIELD: 0 <= bit length before modulo and subtraction; gen/codegen.go:526
		if v.MgwEventList.BitLength < 0 {
			return nil, fmt.Errorf("negative bit string length")
		}
		enc_mgweventlist, encodeErr_enc_mgweventlist := ber.EncodeBitString(v.MgwEventList.Bytes, (8-(v.MgwEventList.BitLength%8))%8)
		if encodeErr_enc_mgweventlist != nil {
			return nil, fmt.Errorf("encoding mgw-EventList: %w", encodeErr_enc_mgweventlist)
		}
		retagged_enc_mgweventlist, tagErr_enc_mgweventlist := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 11, enc_mgweventlist)
		if tagErr_enc_mgweventlist != nil {
			return nil, fmt.Errorf("encoding mgw-EventList: %w", tagErr_enc_mgweventlist)
		}
		enc_mgweventlist = retagged_enc_mgweventlist
		children = append(children, enc_mgweventlist...)
	}
	if v.RncTraceDepthExtension != nil {
		enc_rnctracedepthextension := ber.EncodeEnumerated(int64(*v.RncTraceDepthExtension))
		retagged_enc_rnctracedepthextension, tagErr_enc_rnctracedepthextension := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 12, enc_rnctracedepthextension)
		if tagErr_enc_rnctracedepthextension != nil {
			return nil, fmt.Errorf("encoding rnc-TraceDepthExtension: %w", tagErr_enc_rnctracedepthextension)
		}
		enc_rnctracedepthextension = retagged_enc_rnctracedepthextension
		children = append(children, enc_rnctracedepthextension...)
	}
	if v.MscSTraceDepthExtension != nil {
		enc_mscstracedepthextension := ber.EncodeEnumerated(int64(*v.MscSTraceDepthExtension))
		retagged_enc_mscstracedepthextension, tagErr_enc_mscstracedepthextension := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 13, enc_mscstracedepthextension)
		if tagErr_enc_mscstracedepthextension != nil {
			return nil, fmt.Errorf("encoding msc-s-TraceDepthExtension: %w", tagErr_enc_mscstracedepthextension)
		}
		enc_mscstracedepthextension = retagged_enc_mscstracedepthextension
		children = append(children, enc_mscstracedepthextension...)
	}
	if v.MgwTraceDepthExtension != nil {
		enc_mgwtracedepthextension := ber.EncodeEnumerated(int64(*v.MgwTraceDepthExtension))
		retagged_enc_mgwtracedepthextension, tagErr_enc_mgwtracedepthextension := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 14, enc_mgwtracedepthextension)
		if tagErr_enc_mgwtracedepthextension != nil {
			return nil, fmt.Errorf("encoding mgw-TraceDepthExtension: %w", tagErr_enc_mgwtracedepthextension)
		}
		enc_mgwtracedepthextension = retagged_enc_mgwtracedepthextension
		children = append(children, enc_mgwtracedepthextension...)
	}
	for i, ext := range v.ExtData_ {
		_, n, _, extErr := ber.DecodeEncodedTLV(ext)
		if extErr != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, extErr)
		}
		if n != len(ext) {
			return nil, fmt.Errorf("encoding extension %d: %w", i, ber.ErrExtraData)
		}
		children = append(children, ext...)
	}
	return ber.EncodeSequence(children)
}

// MarshalDER encodes TracePropagationList to DER format.
func (v *TracePropagationList) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: TracePropagationList receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if v.TraceReference != nil {
		if len(*v.TraceReference) < 1 || len(*v.TraceReference) > 2 {
			if constraintErr := ber.CheckEncodedLength(nil, "traceReference", "SIZE (1..2)", len(*v.TraceReference)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_tracereference, encodeErr_enc_tracereference := ber.EncodeOctetString([]byte(*v.TraceReference))
		if encodeErr_enc_tracereference != nil {
			return nil, fmt.Errorf("encoding traceReference: %w", encodeErr_enc_tracereference)
		}
		retagged_enc_tracereference, tagErr_enc_tracereference := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_tracereference)
		if tagErr_enc_tracereference != nil {
			return nil, fmt.Errorf("encoding traceReference: %w", tagErr_enc_tracereference)
		}
		enc_tracereference = retagged_enc_tracereference
		children = append(children, enc_tracereference...)
	}
	if v.TraceType != nil {
		if !(int64(*v.TraceType) >= 0 && int64(*v.TraceType) <= 255) {
			if constraintErr := ber.CheckEncodedValue(nil, "traceType", "(0..255)", fmt.Sprint(int64(*v.TraceType))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_tracetype := ber.EncodeInteger(int64(*v.TraceType))
		retagged_enc_tracetype, tagErr_enc_tracetype := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_tracetype)
		if tagErr_enc_tracetype != nil {
			return nil, fmt.Errorf("encoding traceType: %w", tagErr_enc_tracetype)
		}
		enc_tracetype = retagged_enc_tracetype
		children = append(children, enc_tracetype...)
	}
	if v.TraceReference2 != nil {
		if len(*v.TraceReference2) < 3 || len(*v.TraceReference2) > 3 {
			if constraintErr := ber.CheckEncodedLength(nil, "traceReference2", "SIZE (3)", len(*v.TraceReference2)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_tracereference2, encodeErr_enc_tracereference2 := ber.EncodeOctetString([]byte(*v.TraceReference2))
		if encodeErr_enc_tracereference2 != nil {
			return nil, fmt.Errorf("encoding traceReference2: %w", encodeErr_enc_tracereference2)
		}
		retagged_enc_tracereference2, tagErr_enc_tracereference2 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_tracereference2)
		if tagErr_enc_tracereference2 != nil {
			return nil, fmt.Errorf("encoding traceReference2: %w", tagErr_enc_tracereference2)
		}
		enc_tracereference2 = retagged_enc_tracereference2
		children = append(children, enc_tracereference2...)
	}
	if v.TraceRecordingSessionReference != nil {
		if len(*v.TraceRecordingSessionReference) < 2 || len(*v.TraceRecordingSessionReference) > 2 {
			if constraintErr := ber.CheckEncodedLength(nil, "traceRecordingSessionReference", "SIZE (2)", len(*v.TraceRecordingSessionReference)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_tracerecordingsessionreference, encodeErr_enc_tracerecordingsessionreference := ber.EncodeOctetString([]byte(*v.TraceRecordingSessionReference))
		if encodeErr_enc_tracerecordingsessionreference != nil {
			return nil, fmt.Errorf("encoding traceRecordingSessionReference: %w", encodeErr_enc_tracerecordingsessionreference)
		}
		retagged_enc_tracerecordingsessionreference, tagErr_enc_tracerecordingsessionreference := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, enc_tracerecordingsessionreference)
		if tagErr_enc_tracerecordingsessionreference != nil {
			return nil, fmt.Errorf("encoding traceRecordingSessionReference: %w", tagErr_enc_tracerecordingsessionreference)
		}
		enc_tracerecordingsessionreference = retagged_enc_tracerecordingsessionreference
		children = append(children, enc_tracerecordingsessionreference...)
	}
	if v.RncTraceDepth != nil {
		enc_rnctracedepth := ber.EncodeEnumerated(int64(*v.RncTraceDepth))
		retagged_enc_rnctracedepth, tagErr_enc_rnctracedepth := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, enc_rnctracedepth)
		if tagErr_enc_rnctracedepth != nil {
			return nil, fmt.Errorf("encoding rnc-TraceDepth: %w", tagErr_enc_rnctracedepth)
		}
		enc_rnctracedepth = retagged_enc_rnctracedepth
		children = append(children, enc_rnctracedepth...)
	}
	if v.RncInterfaceList != nil {
		if (*v.RncInterfaceList).BitLength < 4 || (*v.RncInterfaceList).BitLength > 8 {
			if constraintErr := ber.CheckEncodedLength(nil, "rnc-InterfaceList", "SIZE (4..8)", (*v.RncInterfaceList).BitLength); constraintErr != nil {
				return nil, constraintErr
			}
		}
		if bitStringErr := ber.ValidateBitStringLength(v.RncInterfaceList.Bytes, v.RncInterfaceList.BitLength); bitStringErr != nil {
			return nil, fmt.Errorf("encoding %s: %w", "rnc-InterfaceList", bitStringErr)
		}
		if bitStringErr := ber.ValidateDERBitString(v.RncInterfaceList.Bytes, v.RncInterfaceList.BitLength); bitStringErr != nil {
			return nil, fmt.Errorf("encoding %s: %w", "rnc-InterfaceList", bitStringErr)
		}
		// arithmetic pattern BER_BITSTRING_FIELD: 0 <= bit length before modulo and subtraction; gen/codegen.go:526
		if v.RncInterfaceList.BitLength < 0 {
			return nil, fmt.Errorf("negative bit string length")
		}
		enc_rncinterfacelist, encodeErr_enc_rncinterfacelist := ber.EncodeDERNamedBitString(v.RncInterfaceList.Bytes, v.RncInterfaceList.BitLength)
		if encodeErr_enc_rncinterfacelist != nil {
			return nil, fmt.Errorf("encoding rnc-InterfaceList: %w", encodeErr_enc_rncinterfacelist)
		}
		retagged_enc_rncinterfacelist, tagErr_enc_rncinterfacelist := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 5, enc_rncinterfacelist)
		if tagErr_enc_rncinterfacelist != nil {
			return nil, fmt.Errorf("encoding rnc-InterfaceList: %w", tagErr_enc_rncinterfacelist)
		}
		enc_rncinterfacelist = retagged_enc_rncinterfacelist
		children = append(children, enc_rncinterfacelist...)
	}
	if v.MscSTraceDepth != nil {
		enc_mscstracedepth := ber.EncodeEnumerated(int64(*v.MscSTraceDepth))
		retagged_enc_mscstracedepth, tagErr_enc_mscstracedepth := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 6, enc_mscstracedepth)
		if tagErr_enc_mscstracedepth != nil {
			return nil, fmt.Errorf("encoding msc-s-TraceDepth: %w", tagErr_enc_mscstracedepth)
		}
		enc_mscstracedepth = retagged_enc_mscstracedepth
		children = append(children, enc_mscstracedepth...)
	}
	if v.MscSInterfaceList != nil {
		if (*v.MscSInterfaceList).BitLength < 10 || (*v.MscSInterfaceList).BitLength > 16 {
			if constraintErr := ber.CheckEncodedLength(nil, "msc-s-InterfaceList", "SIZE (10..16)", (*v.MscSInterfaceList).BitLength); constraintErr != nil {
				return nil, constraintErr
			}
		}
		if bitStringErr := ber.ValidateBitStringLength(v.MscSInterfaceList.Bytes, v.MscSInterfaceList.BitLength); bitStringErr != nil {
			return nil, fmt.Errorf("encoding %s: %w", "msc-s-InterfaceList", bitStringErr)
		}
		if bitStringErr := ber.ValidateDERBitString(v.MscSInterfaceList.Bytes, v.MscSInterfaceList.BitLength); bitStringErr != nil {
			return nil, fmt.Errorf("encoding %s: %w", "msc-s-InterfaceList", bitStringErr)
		}
		// arithmetic pattern BER_BITSTRING_FIELD: 0 <= bit length before modulo and subtraction; gen/codegen.go:526
		if v.MscSInterfaceList.BitLength < 0 {
			return nil, fmt.Errorf("negative bit string length")
		}
		enc_mscsinterfacelist, encodeErr_enc_mscsinterfacelist := ber.EncodeDERNamedBitString(v.MscSInterfaceList.Bytes, v.MscSInterfaceList.BitLength)
		if encodeErr_enc_mscsinterfacelist != nil {
			return nil, fmt.Errorf("encoding msc-s-InterfaceList: %w", encodeErr_enc_mscsinterfacelist)
		}
		retagged_enc_mscsinterfacelist, tagErr_enc_mscsinterfacelist := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 7, enc_mscsinterfacelist)
		if tagErr_enc_mscsinterfacelist != nil {
			return nil, fmt.Errorf("encoding msc-s-InterfaceList: %w", tagErr_enc_mscsinterfacelist)
		}
		enc_mscsinterfacelist = retagged_enc_mscsinterfacelist
		children = append(children, enc_mscsinterfacelist...)
	}
	if v.MscSEventList != nil {
		if (*v.MscSEventList).BitLength < 5 || (*v.MscSEventList).BitLength > 16 {
			if constraintErr := ber.CheckEncodedLength(nil, "msc-s-EventList", "SIZE (5..16)", (*v.MscSEventList).BitLength); constraintErr != nil {
				return nil, constraintErr
			}
		}
		if bitStringErr := ber.ValidateBitStringLength(v.MscSEventList.Bytes, v.MscSEventList.BitLength); bitStringErr != nil {
			return nil, fmt.Errorf("encoding %s: %w", "msc-s-EventList", bitStringErr)
		}
		if bitStringErr := ber.ValidateDERBitString(v.MscSEventList.Bytes, v.MscSEventList.BitLength); bitStringErr != nil {
			return nil, fmt.Errorf("encoding %s: %w", "msc-s-EventList", bitStringErr)
		}
		// arithmetic pattern BER_BITSTRING_FIELD: 0 <= bit length before modulo and subtraction; gen/codegen.go:526
		if v.MscSEventList.BitLength < 0 {
			return nil, fmt.Errorf("negative bit string length")
		}
		enc_mscseventlist, encodeErr_enc_mscseventlist := ber.EncodeDERNamedBitString(v.MscSEventList.Bytes, v.MscSEventList.BitLength)
		if encodeErr_enc_mscseventlist != nil {
			return nil, fmt.Errorf("encoding msc-s-EventList: %w", encodeErr_enc_mscseventlist)
		}
		retagged_enc_mscseventlist, tagErr_enc_mscseventlist := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 8, enc_mscseventlist)
		if tagErr_enc_mscseventlist != nil {
			return nil, fmt.Errorf("encoding msc-s-EventList: %w", tagErr_enc_mscseventlist)
		}
		enc_mscseventlist = retagged_enc_mscseventlist
		children = append(children, enc_mscseventlist...)
	}
	if v.MgwTraceDepth != nil {
		enc_mgwtracedepth := ber.EncodeEnumerated(int64(*v.MgwTraceDepth))
		retagged_enc_mgwtracedepth, tagErr_enc_mgwtracedepth := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 9, enc_mgwtracedepth)
		if tagErr_enc_mgwtracedepth != nil {
			return nil, fmt.Errorf("encoding mgw-TraceDepth: %w", tagErr_enc_mgwtracedepth)
		}
		enc_mgwtracedepth = retagged_enc_mgwtracedepth
		children = append(children, enc_mgwtracedepth...)
	}
	if v.MgwInterfaceList != nil {
		if (*v.MgwInterfaceList).BitLength < 3 || (*v.MgwInterfaceList).BitLength > 8 {
			if constraintErr := ber.CheckEncodedLength(nil, "mgw-InterfaceList", "SIZE (3..8)", (*v.MgwInterfaceList).BitLength); constraintErr != nil {
				return nil, constraintErr
			}
		}
		if bitStringErr := ber.ValidateBitStringLength(v.MgwInterfaceList.Bytes, v.MgwInterfaceList.BitLength); bitStringErr != nil {
			return nil, fmt.Errorf("encoding %s: %w", "mgw-InterfaceList", bitStringErr)
		}
		if bitStringErr := ber.ValidateDERBitString(v.MgwInterfaceList.Bytes, v.MgwInterfaceList.BitLength); bitStringErr != nil {
			return nil, fmt.Errorf("encoding %s: %w", "mgw-InterfaceList", bitStringErr)
		}
		// arithmetic pattern BER_BITSTRING_FIELD: 0 <= bit length before modulo and subtraction; gen/codegen.go:526
		if v.MgwInterfaceList.BitLength < 0 {
			return nil, fmt.Errorf("negative bit string length")
		}
		enc_mgwinterfacelist, encodeErr_enc_mgwinterfacelist := ber.EncodeDERNamedBitString(v.MgwInterfaceList.Bytes, v.MgwInterfaceList.BitLength)
		if encodeErr_enc_mgwinterfacelist != nil {
			return nil, fmt.Errorf("encoding mgw-InterfaceList: %w", encodeErr_enc_mgwinterfacelist)
		}
		retagged_enc_mgwinterfacelist, tagErr_enc_mgwinterfacelist := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 10, enc_mgwinterfacelist)
		if tagErr_enc_mgwinterfacelist != nil {
			return nil, fmt.Errorf("encoding mgw-InterfaceList: %w", tagErr_enc_mgwinterfacelist)
		}
		enc_mgwinterfacelist = retagged_enc_mgwinterfacelist
		children = append(children, enc_mgwinterfacelist...)
	}
	if v.MgwEventList != nil {
		if (*v.MgwEventList).BitLength < 1 || (*v.MgwEventList).BitLength > 8 {
			if constraintErr := ber.CheckEncodedLength(nil, "mgw-EventList", "SIZE (1..8)", (*v.MgwEventList).BitLength); constraintErr != nil {
				return nil, constraintErr
			}
		}
		if bitStringErr := ber.ValidateBitStringLength(v.MgwEventList.Bytes, v.MgwEventList.BitLength); bitStringErr != nil {
			return nil, fmt.Errorf("encoding %s: %w", "mgw-EventList", bitStringErr)
		}
		if bitStringErr := ber.ValidateDERBitString(v.MgwEventList.Bytes, v.MgwEventList.BitLength); bitStringErr != nil {
			return nil, fmt.Errorf("encoding %s: %w", "mgw-EventList", bitStringErr)
		}
		// arithmetic pattern BER_BITSTRING_FIELD: 0 <= bit length before modulo and subtraction; gen/codegen.go:526
		if v.MgwEventList.BitLength < 0 {
			return nil, fmt.Errorf("negative bit string length")
		}
		enc_mgweventlist, encodeErr_enc_mgweventlist := ber.EncodeDERNamedBitString(v.MgwEventList.Bytes, v.MgwEventList.BitLength)
		if encodeErr_enc_mgweventlist != nil {
			return nil, fmt.Errorf("encoding mgw-EventList: %w", encodeErr_enc_mgweventlist)
		}
		retagged_enc_mgweventlist, tagErr_enc_mgweventlist := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 11, enc_mgweventlist)
		if tagErr_enc_mgweventlist != nil {
			return nil, fmt.Errorf("encoding mgw-EventList: %w", tagErr_enc_mgweventlist)
		}
		enc_mgweventlist = retagged_enc_mgweventlist
		children = append(children, enc_mgweventlist...)
	}
	if v.RncTraceDepthExtension != nil {
		enc_rnctracedepthextension := ber.EncodeEnumerated(int64(*v.RncTraceDepthExtension))
		retagged_enc_rnctracedepthextension, tagErr_enc_rnctracedepthextension := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 12, enc_rnctracedepthextension)
		if tagErr_enc_rnctracedepthextension != nil {
			return nil, fmt.Errorf("encoding rnc-TraceDepthExtension: %w", tagErr_enc_rnctracedepthextension)
		}
		enc_rnctracedepthextension = retagged_enc_rnctracedepthextension
		children = append(children, enc_rnctracedepthextension...)
	}
	if v.MscSTraceDepthExtension != nil {
		enc_mscstracedepthextension := ber.EncodeEnumerated(int64(*v.MscSTraceDepthExtension))
		retagged_enc_mscstracedepthextension, tagErr_enc_mscstracedepthextension := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 13, enc_mscstracedepthextension)
		if tagErr_enc_mscstracedepthextension != nil {
			return nil, fmt.Errorf("encoding msc-s-TraceDepthExtension: %w", tagErr_enc_mscstracedepthextension)
		}
		enc_mscstracedepthextension = retagged_enc_mscstracedepthextension
		children = append(children, enc_mscstracedepthextension...)
	}
	if v.MgwTraceDepthExtension != nil {
		enc_mgwtracedepthextension := ber.EncodeEnumerated(int64(*v.MgwTraceDepthExtension))
		retagged_enc_mgwtracedepthextension, tagErr_enc_mgwtracedepthextension := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 14, enc_mgwtracedepthextension)
		if tagErr_enc_mgwtracedepthextension != nil {
			return nil, fmt.Errorf("encoding mgw-TraceDepthExtension: %w", tagErr_enc_mgwtracedepthextension)
		}
		enc_mgwtracedepthextension = retagged_enc_mgwtracedepthextension
		children = append(children, enc_mgwtracedepthextension...)
	}
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDEREncodedElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
		children = append(children, ext...)
	}
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding TracePropagationList as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes TracePropagationList from BER/DER format.
func (v *TracePropagationList) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: TracePropagationList destination is nil", ber.ErrInvalidValue)
	}
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = TracePropagationList{}
	defer func() {
		if returnErr != nil || !ber.BERNeedsPreservation(opts) {
			return
		}
		var snapshotReports ber.ViolationLog
		snapshot, snapshotErr := v.marshalBER(ber.WithConstraintTolerance(&snapshotReports))
		if snapshotErr != nil {
			returnErr = snapshotErr
			return
		}
		v.berOriginal_ = append([]byte(nil), data...)
		v.berSnapshot_ = snapshot
	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("decoding TracePropagationList SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "TracePropagationList", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode traceReference
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
				decodedTag_tracereference, n_tracereference, rawVal_tracereference, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding traceReference: %w", err)
				}
				if decodedTag_tracereference.Class != tag.ClassContextSpecific || decodedTag_tracereference.Number != 0 {
					return fmt.Errorf("decoding traceReference: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_tracereference)
				}
				decVal_tracereference, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_tracereference.Constructed, rawVal_tracereference, opts...)
				if octetErr != nil {
					return fmt.Errorf("decoding traceReference: %w", octetErr)
				}
				tmp_tracereference := TraceReference(decVal_tracereference)
				v.TraceReference = &tmp_tracereference
				if offset > len(content) || n_tracereference < 0 || n_tracereference > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_tracereference
				if len(*v.TraceReference) < 1 || len(*v.TraceReference) > 2 {
					if constraintErr := ber.CheckDecodedLength(opts, "traceReference", "SIZE (1..2)", len(*v.TraceReference)); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode traceType
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
				decodedTag_tracetype, n_tracetype, rawVal_tracetype, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding traceType: %w", err)
				}
				if decodedTag_tracetype.Class != tag.ClassContextSpecific || decodedTag_tracetype.Number != 1 || decodedTag_tracetype.Constructed != false {
					return fmt.Errorf("decoding traceType: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_tracetype)
				}
				decVal_tracetype, intErr := ber.DecodeIntegerValue(rawVal_tracetype)
				if intErr != nil {
					return fmt.Errorf("decoding traceType: %w", intErr)
				}
				tmp_tracetype := TraceType(decVal_tracetype)
				v.TraceType = &tmp_tracetype
				if offset < 0 || offset >
					len(content) || n_tracetype < 0 || n_tracetype > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_tracetype
				if !(int64(*v.TraceType) >= 0 && int64(*v.TraceType) <= 255) {
					if constraintErr := ber.CheckDecodedValue(opts, "traceType", "(0..255)", fmt.Sprint(int64(*v.TraceType))); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode traceReference2
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2 {
				decodedTag_tracereference2, n_tracereference2, rawVal_tracereference2, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding traceReference2: %w", err)
				}
				if decodedTag_tracereference2.Class != tag.ClassContextSpecific || decodedTag_tracereference2.Number != 2 {
					return fmt.Errorf("decoding traceReference2: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_tracereference2)
				}
				decVal_tracereference2, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_tracereference2.Constructed, rawVal_tracereference2, opts...)
				if octetErr != nil {
					return fmt.Errorf("decoding traceReference2: %w", octetErr)
				}
				tmp_tracereference2 := TraceReference2(decVal_tracereference2)
				v.TraceReference2 = &tmp_tracereference2
				if offset < 0 || offset >
					len(content) || n_tracereference2 < 0 || n_tracereference2 >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_tracereference2
				if len(*v.TraceReference2) < 3 || len(*v.TraceReference2) > 3 {
					if constraintErr := ber.CheckDecodedLength(opts, "traceReference2", "SIZE (3)", len(*v.TraceReference2)); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode traceRecordingSessionReference
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3 {
				decodedTag_tracerecordingsessionreference, n_tracerecordingsessionreference, rawVal_tracerecordingsessionreference, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding traceRecordingSessionReference: %w", err)
				}
				if decodedTag_tracerecordingsessionreference.Class != tag.ClassContextSpecific || decodedTag_tracerecordingsessionreference.Number != 3 {
					return fmt.Errorf("decoding traceRecordingSessionReference: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_tracerecordingsessionreference)
				}
				decVal_tracerecordingsessionreference, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_tracerecordingsessionreference.Constructed, rawVal_tracerecordingsessionreference, opts...)
				if octetErr != nil {
					return fmt.Errorf("decoding traceRecordingSessionReference: %w", octetErr)
				}
				tmp_tracerecordingsessionreference := TraceRecordingSessionReference(decVal_tracerecordingsessionreference)
				v.TraceRecordingSessionReference = &tmp_tracerecordingsessionreference
				if offset < 0 || offset >
					len(content) || n_tracerecordingsessionreference < 0 || n_tracerecordingsessionreference >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_tracerecordingsessionreference
				if len(*v.TraceRecordingSessionReference) < 2 || len(*v.TraceRecordingSessionReference) > 2 {
					if constraintErr := ber.CheckDecodedLength(opts, "traceRecordingSessionReference", "SIZE (2)", len(*v.TraceRecordingSessionReference)); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode rnc-TraceDepth
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4 {
				decodedTag_rnctracedepth, n_rnctracedepth, rawVal_rnctracedepth, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding rnc-TraceDepth: %w", err)
				}
				if decodedTag_rnctracedepth.Class != tag.ClassContextSpecific || decodedTag_rnctracedepth.Number != 4 || decodedTag_rnctracedepth.Constructed != false {
					return fmt.Errorf("decoding rnc-TraceDepth: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_rnctracedepth)
				}
				decVal_rnctracedepth, intErr := ber.DecodeEnumeratedValue(rawVal_rnctracedepth)
				if intErr != nil {
					return fmt.Errorf("decoding rnc-TraceDepth: %w", intErr)
				}
				tmp_rnctracedepth := TraceDepth(decVal_rnctracedepth)
				v.RncTraceDepth = &tmp_rnctracedepth
				if offset < 0 || offset >
					len(content) || n_rnctracedepth < 0 || n_rnctracedepth > len(
					content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_rnctracedepth
			}
		}
	}
	// Decode rnc-InterfaceList
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 5 {
				decodedTag_rncinterfacelist, n_rncinterfacelist, rawVal_rncinterfacelist, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding rnc-InterfaceList: %w", err)
				}
				if decodedTag_rncinterfacelist.Class != tag.ClassContextSpecific || decodedTag_rncinterfacelist.Number != 5 {
					return fmt.Errorf("decoding rnc-InterfaceList: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_rncinterfacelist)
				}
				bsBytes_rncinterfacelist, bsUnused_rncinterfacelist, bsErr := ber.DecodeImplicitBitStringValue(decodedTag_rncinterfacelist.Constructed, rawVal_rncinterfacelist, opts...)
				if bsErr != nil {
					return fmt.Errorf("decoding rnc-InterfaceList: %w", bsErr)
				}
				bsBitLength_rncinterfacelist, bsLenErr_rncinterfacelist := ber.BitStringBitLength(len(bsBytes_rncinterfacelist), bsUnused_rncinterfacelist)
				if bsLenErr_rncinterfacelist != nil {
					return fmt.Errorf("decoding rnc-InterfaceList: %w", bsLenErr_rncinterfacelist)
				}
				tmp_rncinterfacelist := runtime.BitString{Bytes: bsBytes_rncinterfacelist, BitLength: bsBitLength_rncinterfacelist}
				v.RncInterfaceList = &tmp_rncinterfacelist
				if offset < 0 || offset >
					len(content) || n_rncinterfacelist < 0 || n_rncinterfacelist >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_rncinterfacelist
				*v.RncInterfaceList = ber.NormalizeNamedBitStringSize(*v.RncInterfaceList, []ber.NamedBitSizeSet{{{Min: 4, Max: 8}}}, opts...)
				if (*v.RncInterfaceList).BitLength < 4 || (*v.RncInterfaceList).BitLength > 8 {
					if constraintErr := ber.CheckDecodedLength(opts, "rnc-InterfaceList", "SIZE (4..8)", (*v.RncInterfaceList).BitLength); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode msc-s-TraceDepth
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 6 {
				decodedTag_mscstracedepth, n_mscstracedepth, rawVal_mscstracedepth, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding msc-s-TraceDepth: %w", err)
				}
				if decodedTag_mscstracedepth.Class != tag.ClassContextSpecific || decodedTag_mscstracedepth.Number != 6 || decodedTag_mscstracedepth.Constructed != false {
					return fmt.Errorf("decoding msc-s-TraceDepth: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_mscstracedepth)
				}
				decVal_mscstracedepth, intErr := ber.DecodeEnumeratedValue(rawVal_mscstracedepth)
				if intErr != nil {
					return fmt.Errorf("decoding msc-s-TraceDepth: %w", intErr)
				}
				tmp_mscstracedepth := TraceDepth(decVal_mscstracedepth)
				v.MscSTraceDepth = &tmp_mscstracedepth
				if offset < 0 || offset >
					len(content) || n_mscstracedepth < 0 || n_mscstracedepth > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_mscstracedepth
			}
		}
	}
	// Decode msc-s-InterfaceList
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 7 {
				decodedTag_mscsinterfacelist, n_mscsinterfacelist, rawVal_mscsinterfacelist, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding msc-s-InterfaceList: %w", err)
				}
				if decodedTag_mscsinterfacelist.Class != tag.ClassContextSpecific || decodedTag_mscsinterfacelist.Number != 7 {
					return fmt.Errorf("decoding msc-s-InterfaceList: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_mscsinterfacelist)
				}
				bsBytes_mscsinterfacelist, bsUnused_mscsinterfacelist, bsErr := ber.DecodeImplicitBitStringValue(decodedTag_mscsinterfacelist.Constructed, rawVal_mscsinterfacelist, opts...)
				if bsErr != nil {
					return fmt.Errorf("decoding msc-s-InterfaceList: %w", bsErr)
				}
				bsBitLength_mscsinterfacelist, bsLenErr_mscsinterfacelist := ber.BitStringBitLength(len(bsBytes_mscsinterfacelist), bsUnused_mscsinterfacelist)
				if bsLenErr_mscsinterfacelist != nil {
					return fmt.Errorf("decoding msc-s-InterfaceList: %w", bsLenErr_mscsinterfacelist)
				}
				tmp_mscsinterfacelist := runtime.BitString{Bytes: bsBytes_mscsinterfacelist, BitLength: bsBitLength_mscsinterfacelist}
				v.MscSInterfaceList = &tmp_mscsinterfacelist
				if offset < 0 || offset >
					len(content) || n_mscsinterfacelist < 0 || n_mscsinterfacelist >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_mscsinterfacelist
				*v.MscSInterfaceList = ber.NormalizeNamedBitStringSize(*v.MscSInterfaceList, []ber.NamedBitSizeSet{{{Min: 10, Max: 16}}}, opts...)
				if (*v.MscSInterfaceList).BitLength < 10 || (*v.MscSInterfaceList).BitLength > 16 {
					if constraintErr := ber.CheckDecodedLength(opts, "msc-s-InterfaceList", "SIZE (10..16)", (*v.MscSInterfaceList).BitLength); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode msc-s-EventList
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 8 {
				decodedTag_mscseventlist, n_mscseventlist, rawVal_mscseventlist, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding msc-s-EventList: %w", err)
				}
				if decodedTag_mscseventlist.Class != tag.ClassContextSpecific || decodedTag_mscseventlist.Number != 8 {
					return fmt.Errorf("decoding msc-s-EventList: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_mscseventlist)
				}
				bsBytes_mscseventlist, bsUnused_mscseventlist, bsErr := ber.DecodeImplicitBitStringValue(decodedTag_mscseventlist.Constructed, rawVal_mscseventlist, opts...)
				if bsErr != nil {
					return fmt.Errorf("decoding msc-s-EventList: %w", bsErr)
				}
				bsBitLength_mscseventlist, bsLenErr_mscseventlist := ber.BitStringBitLength(len(bsBytes_mscseventlist), bsUnused_mscseventlist)
				if bsLenErr_mscseventlist != nil {
					return fmt.Errorf("decoding msc-s-EventList: %w", bsLenErr_mscseventlist)
				}
				tmp_mscseventlist := runtime.BitString{Bytes: bsBytes_mscseventlist, BitLength: bsBitLength_mscseventlist}
				v.MscSEventList = &tmp_mscseventlist
				if offset < 0 || offset >
					len(content) || n_mscseventlist < 0 || n_mscseventlist > len(
					content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_mscseventlist
				*v.MscSEventList = ber.NormalizeNamedBitStringSize(*v.MscSEventList, []ber.NamedBitSizeSet{{{Min: 5, Max: 16}}}, opts...)
				if (*v.MscSEventList).BitLength < 5 || (*v.MscSEventList).BitLength > 16 {
					if constraintErr := ber.CheckDecodedLength(opts, "msc-s-EventList", "SIZE (5..16)", (*v.MscSEventList).BitLength); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode mgw-TraceDepth
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 9 {
				decodedTag_mgwtracedepth, n_mgwtracedepth, rawVal_mgwtracedepth, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding mgw-TraceDepth: %w", err)
				}
				if decodedTag_mgwtracedepth.Class != tag.ClassContextSpecific || decodedTag_mgwtracedepth.Number != 9 || decodedTag_mgwtracedepth.Constructed != false {
					return fmt.Errorf("decoding mgw-TraceDepth: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_mgwtracedepth)
				}
				decVal_mgwtracedepth, intErr := ber.DecodeEnumeratedValue(rawVal_mgwtracedepth)
				if intErr != nil {
					return fmt.Errorf("decoding mgw-TraceDepth: %w", intErr)
				}
				tmp_mgwtracedepth := TraceDepth(decVal_mgwtracedepth)
				v.MgwTraceDepth = &tmp_mgwtracedepth
				if offset < 0 || offset >
					len(content) || n_mgwtracedepth < 0 || n_mgwtracedepth > len(
					content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_mgwtracedepth
			}
		}
	}
	// Decode mgw-InterfaceList
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 10 {
				decodedTag_mgwinterfacelist, n_mgwinterfacelist, rawVal_mgwinterfacelist, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding mgw-InterfaceList: %w", err)
				}
				if decodedTag_mgwinterfacelist.Class != tag.ClassContextSpecific || decodedTag_mgwinterfacelist.Number != 10 {
					return fmt.Errorf("decoding mgw-InterfaceList: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_mgwinterfacelist)
				}
				bsBytes_mgwinterfacelist, bsUnused_mgwinterfacelist, bsErr := ber.DecodeImplicitBitStringValue(decodedTag_mgwinterfacelist.Constructed, rawVal_mgwinterfacelist, opts...)
				if bsErr != nil {
					return fmt.Errorf("decoding mgw-InterfaceList: %w", bsErr)
				}
				bsBitLength_mgwinterfacelist, bsLenErr_mgwinterfacelist := ber.BitStringBitLength(len(bsBytes_mgwinterfacelist), bsUnused_mgwinterfacelist)
				if bsLenErr_mgwinterfacelist != nil {
					return fmt.Errorf("decoding mgw-InterfaceList: %w", bsLenErr_mgwinterfacelist)
				}
				tmp_mgwinterfacelist := runtime.BitString{Bytes: bsBytes_mgwinterfacelist, BitLength: bsBitLength_mgwinterfacelist}
				v.MgwInterfaceList = &tmp_mgwinterfacelist
				if offset < 0 || offset >
					len(content) || n_mgwinterfacelist < 0 || n_mgwinterfacelist >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_mgwinterfacelist
				*v.MgwInterfaceList = ber.NormalizeNamedBitStringSize(*v.MgwInterfaceList, []ber.NamedBitSizeSet{{{Min: 3, Max: 8}}}, opts...)
				if (*v.MgwInterfaceList).BitLength < 3 || (*v.MgwInterfaceList).BitLength > 8 {
					if constraintErr := ber.CheckDecodedLength(opts, "mgw-InterfaceList", "SIZE (3..8)", (*v.MgwInterfaceList).BitLength); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode mgw-EventList
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 11 {
				decodedTag_mgweventlist, n_mgweventlist, rawVal_mgweventlist, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding mgw-EventList: %w", err)
				}
				if decodedTag_mgweventlist.Class != tag.ClassContextSpecific || decodedTag_mgweventlist.Number != 11 {
					return fmt.Errorf("decoding mgw-EventList: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_mgweventlist)
				}
				bsBytes_mgweventlist, bsUnused_mgweventlist, bsErr := ber.DecodeImplicitBitStringValue(decodedTag_mgweventlist.Constructed, rawVal_mgweventlist, opts...)
				if bsErr != nil {
					return fmt.Errorf("decoding mgw-EventList: %w", bsErr)
				}
				bsBitLength_mgweventlist, bsLenErr_mgweventlist := ber.BitStringBitLength(len(bsBytes_mgweventlist), bsUnused_mgweventlist)
				if bsLenErr_mgweventlist != nil {
					return fmt.Errorf("decoding mgw-EventList: %w", bsLenErr_mgweventlist)
				}
				tmp_mgweventlist := runtime.BitString{Bytes: bsBytes_mgweventlist, BitLength: bsBitLength_mgweventlist}
				v.MgwEventList = &tmp_mgweventlist
				if offset < 0 || offset >
					len(content) || n_mgweventlist < 0 || n_mgweventlist > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_mgweventlist
				*v.MgwEventList = ber.NormalizeNamedBitStringSize(*v.MgwEventList, []ber.NamedBitSizeSet{{{Min: 1, Max: 8}}}, opts...)
				if (*v.MgwEventList).BitLength < 1 || (*v.MgwEventList).BitLength > 8 {
					if constraintErr := ber.CheckDecodedLength(opts, "mgw-EventList", "SIZE (1..8)", (*v.MgwEventList).BitLength); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode rnc-TraceDepthExtension
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 12 {
				decodedTag_rnctracedepthextension, n_rnctracedepthextension, rawVal_rnctracedepthextension, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding rnc-TraceDepthExtension: %w", err)
				}
				if decodedTag_rnctracedepthextension.Class != tag.ClassContextSpecific || decodedTag_rnctracedepthextension.Number != 12 || decodedTag_rnctracedepthextension.Constructed != false {
					return fmt.Errorf("decoding rnc-TraceDepthExtension: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_rnctracedepthextension)
				}
				decVal_rnctracedepthextension, intErr := ber.DecodeEnumeratedValue(rawVal_rnctracedepthextension)
				if intErr != nil {
					return fmt.Errorf("decoding rnc-TraceDepthExtension: %w", intErr)
				}
				tmp_rnctracedepthextension := TraceDepthExtension(decVal_rnctracedepthextension)
				v.RncTraceDepthExtension = &tmp_rnctracedepthextension
				if offset < 0 || offset >
					len(content) || n_rnctracedepthextension < 0 || n_rnctracedepthextension >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_rnctracedepthextension
			}
		}
	}
	// Decode msc-s-TraceDepthExtension
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 13 {
				decodedTag_mscstracedepthextension, n_mscstracedepthextension, rawVal_mscstracedepthextension, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding msc-s-TraceDepthExtension: %w", err)
				}
				if decodedTag_mscstracedepthextension.Class != tag.ClassContextSpecific || decodedTag_mscstracedepthextension.Number != 13 || decodedTag_mscstracedepthextension.Constructed != false {
					return fmt.Errorf("decoding msc-s-TraceDepthExtension: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_mscstracedepthextension)
				}
				decVal_mscstracedepthextension, intErr := ber.DecodeEnumeratedValue(rawVal_mscstracedepthextension)
				if intErr != nil {
					return fmt.Errorf("decoding msc-s-TraceDepthExtension: %w", intErr)
				}
				tmp_mscstracedepthextension := TraceDepthExtension(decVal_mscstracedepthextension)
				v.MscSTraceDepthExtension = &tmp_mscstracedepthextension
				if offset < 0 || offset >
					len(content) || n_mscstracedepthextension < 0 || n_mscstracedepthextension >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_mscstracedepthextension
			}
		}
	}
	// Decode mgw-TraceDepthExtension
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 14 {
				decodedTag_mgwtracedepthextension, n_mgwtracedepthextension, rawVal_mgwtracedepthextension, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding mgw-TraceDepthExtension: %w", err)
				}
				if decodedTag_mgwtracedepthextension.Class != tag.ClassContextSpecific || decodedTag_mgwtracedepthextension.Number != 14 || decodedTag_mgwtracedepthextension.Constructed != false {
					return fmt.Errorf("decoding mgw-TraceDepthExtension: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_mgwtracedepthextension)
				}
				decVal_mgwtracedepthextension, intErr := ber.DecodeEnumeratedValue(rawVal_mgwtracedepthextension)
				if intErr != nil {
					return fmt.Errorf("decoding mgw-TraceDepthExtension: %w", intErr)
				}
				tmp_mgwtracedepthextension := TraceDepthExtension(decVal_mgwtracedepthextension)
				v.MgwTraceDepthExtension = &tmp_mgwtracedepthextension
				if offset < 0 || offset >
					len(content) || n_mgwtracedepthextension < 0 || n_mgwtracedepthextension >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_mgwtracedepthextension
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:], opts...)
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "TracePropagationList", Cause: extErr_}
		}
		if offset < 0 || offset >
			len(content) || nExt_ < 0 || nExt_ > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		if offset < 0 || offset >
			len(content) || nExt_ < 0 || nExt_ > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes ActivateTraceModeRes to BER format.
func (v *ActivateTraceModeRes) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: ActivateTraceModeRes receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *ActivateTraceModeRes) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalBER(ber.ChildEncodeOptions(opts, "extensionContainer")...)
		if err != nil {
			return nil, fmt.Errorf("encoding extensionContainer: %w", err)
		}
		retagged_enc_extensioncontainer, tagErr_enc_extensioncontainer := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_extensioncontainer)
		if tagErr_enc_extensioncontainer != nil {
			return nil, fmt.Errorf("encoding extensionContainer: %w", tagErr_enc_extensioncontainer)
		}
		enc_extensioncontainer = retagged_enc_extensioncontainer
		children = append(children, enc_extensioncontainer...)
	}
	if v.TraceSupportIndicator != nil {
		enc_tracesupportindicator := ber.EncodeNull()
		retagged_enc_tracesupportindicator, tagErr_enc_tracesupportindicator := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_tracesupportindicator)
		if tagErr_enc_tracesupportindicator != nil {
			return nil, fmt.Errorf("encoding traceSupportIndicator: %w", tagErr_enc_tracesupportindicator)
		}
		enc_tracesupportindicator = retagged_enc_tracesupportindicator
		children = append(children, enc_tracesupportindicator...)
	}
	for i, ext := range v.ExtData_ {
		_, n, _, extErr := ber.DecodeEncodedTLV(ext)
		if extErr != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, extErr)
		}
		if n != len(ext) {
			return nil, fmt.Errorf("encoding extension %d: %w", i, ber.ErrExtraData)
		}
		children = append(children, ext...)
	}
	return ber.EncodeSequence(children)
}

// MarshalDER encodes ActivateTraceModeRes to DER format.
func (v *ActivateTraceModeRes) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: ActivateTraceModeRes receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding extensionContainer: %w", err)
		}
		retagged_enc_extensioncontainer, tagErr_enc_extensioncontainer := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_extensioncontainer)
		if tagErr_enc_extensioncontainer != nil {
			return nil, fmt.Errorf("encoding extensionContainer: %w", tagErr_enc_extensioncontainer)
		}
		enc_extensioncontainer = retagged_enc_extensioncontainer
		children = append(children, enc_extensioncontainer...)
	}
	if v.TraceSupportIndicator != nil {
		enc_tracesupportindicator := ber.EncodeNull()
		retagged_enc_tracesupportindicator, tagErr_enc_tracesupportindicator := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_tracesupportindicator)
		if tagErr_enc_tracesupportindicator != nil {
			return nil, fmt.Errorf("encoding traceSupportIndicator: %w", tagErr_enc_tracesupportindicator)
		}
		enc_tracesupportindicator = retagged_enc_tracesupportindicator
		children = append(children, enc_tracesupportindicator...)
	}
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDEREncodedElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
		children = append(children, ext...)
	}
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding ActivateTraceModeRes as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes ActivateTraceModeRes from BER/DER format.
func (v *ActivateTraceModeRes) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: ActivateTraceModeRes destination is nil", ber.ErrInvalidValue)
	}
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = ActivateTraceModeRes{}
	defer func() {
		if returnErr != nil || !ber.BERNeedsPreservation(opts) {
			return
		}
		var snapshotReports ber.ViolationLog
		snapshot, snapshotErr := v.marshalBER(ber.WithConstraintTolerance(&snapshotReports))
		if snapshotErr != nil {
			returnErr = snapshotErr
			return
		}
		v.berOriginal_ = append([]byte(nil), data...)
		v.berSnapshot_ = snapshot
	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("decoding ActivateTraceModeRes SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "ActivateTraceModeRes", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode extensionContainer
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
				decodedTag_extensioncontainer, n_extensioncontainer, rawVal_extensioncontainer, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding extensionContainer: %w", err)
				}
				if decodedTag_extensioncontainer.Class != tag.ClassContextSpecific || decodedTag_extensioncontainer.Number != 0 || decodedTag_extensioncontainer.Constructed != true {
					return fmt.Errorf("decoding extensionContainer: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_extensioncontainer)
				}
				reconstructed_extensioncontainer, reconstructionErr_extensioncontainer := ber.EncodeSequence(rawVal_extensioncontainer)
				if reconstructionErr_extensioncontainer != nil {
					return fmt.Errorf("decoding extensionContainer: %w", reconstructionErr_extensioncontainer)
				}
				var dec_extensioncontainer ExtensionContainer
				if unmErr := dec_extensioncontainer.UnmarshalBER(reconstructed_extensioncontainer, ber.ChildDecodeOptions(opts, "extensionContainer")...); unmErr != nil {
					return fmt.Errorf("decoding extensionContainer: %w", unmErr)
				}
				v.ExtensionContainer = &dec_extensioncontainer
				if offset > len(content) || n_extensioncontainer < 0 || n_extensioncontainer > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_extensioncontainer
			}
		}
	}
	// Decode traceSupportIndicator
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
				decodedTag_tracesupportindicator, n_tracesupportindicator, rawVal_tracesupportindicator, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding traceSupportIndicator: %w", err)
				}
				if decodedTag_tracesupportindicator.Class != tag.ClassContextSpecific || decodedTag_tracesupportindicator.Number != 1 || decodedTag_tracesupportindicator.Constructed != false {
					return fmt.Errorf("decoding traceSupportIndicator: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_tracesupportindicator)
				}
				if len(rawVal_tracesupportindicator) != 0 {
					return fmt.Errorf("decoding traceSupportIndicator: %w: NULL content length %d", ber.ErrInvalidValue, len(rawVal_tracesupportindicator))
				}
				v.TraceSupportIndicator = &struct{}{}
				if offset < 0 || offset >
					len(content) || n_tracesupportindicator < 0 || n_tracesupportindicator >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_tracesupportindicator
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:], opts...)
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "ActivateTraceModeRes", Cause: extErr_}
		}
		if offset < 0 || offset >
			len(content) || nExt_ < 0 || nExt_ > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		if offset < 0 || offset >
			len(content) || nExt_ < 0 || nExt_ > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes DeactivateTraceModeArg to BER format.
func (v *DeactivateTraceModeArg) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: DeactivateTraceModeArg receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *DeactivateTraceModeArg) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if v.Imsi != nil {
		if len(*v.Imsi) < 3 || len(*v.Imsi) > 8 {
			if constraintErr := ber.CheckEncodedLength(opts, "imsi", "SIZE (3..8)", len(*v.Imsi)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_imsi, encodeErr_enc_imsi := ber.EncodeOctetString([]byte(*v.Imsi))
		if encodeErr_enc_imsi != nil {
			return nil, fmt.Errorf("encoding imsi: %w", encodeErr_enc_imsi)
		}
		retagged_enc_imsi, tagErr_enc_imsi := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_imsi)
		if tagErr_enc_imsi != nil {
			return nil, fmt.Errorf("encoding imsi: %w", tagErr_enc_imsi)
		}
		enc_imsi = retagged_enc_imsi
		children = append(children, enc_imsi...)
	}
	if len(v.TraceReference) < 1 || len(v.TraceReference) > 2 {
		if constraintErr := ber.CheckEncodedLength(opts, "traceReference", "SIZE (1..2)", len(v.TraceReference)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_tracereference, encodeErr_enc_tracereference := ber.EncodeOctetString([]byte(v.TraceReference))
	if encodeErr_enc_tracereference != nil {
		return nil, fmt.Errorf("encoding traceReference: %w", encodeErr_enc_tracereference)
	}
	retagged_enc_tracereference, tagErr_enc_tracereference := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_tracereference)
	if tagErr_enc_tracereference != nil {
		return nil, fmt.Errorf("encoding traceReference: %w", tagErr_enc_tracereference)
	}
	enc_tracereference = retagged_enc_tracereference
	children = append(children, enc_tracereference...)
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalBER(ber.ChildEncodeOptions(opts, "extensionContainer")...)
		if err != nil {
			return nil, fmt.Errorf("encoding extensionContainer: %w", err)
		}
		retagged_enc_extensioncontainer, tagErr_enc_extensioncontainer := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_extensioncontainer)
		if tagErr_enc_extensioncontainer != nil {
			return nil, fmt.Errorf("encoding extensionContainer: %w", tagErr_enc_extensioncontainer)
		}
		enc_extensioncontainer = retagged_enc_extensioncontainer
		children = append(children, enc_extensioncontainer...)
	}
	if v.TraceReference2 != nil {
		if len(*v.TraceReference2) < 3 || len(*v.TraceReference2) > 3 {
			if constraintErr := ber.CheckEncodedLength(opts, "traceReference2", "SIZE (3)", len(*v.TraceReference2)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_tracereference2, encodeErr_enc_tracereference2 := ber.EncodeOctetString([]byte(*v.TraceReference2))
		if encodeErr_enc_tracereference2 != nil {
			return nil, fmt.Errorf("encoding traceReference2: %w", encodeErr_enc_tracereference2)
		}
		retagged_enc_tracereference2, tagErr_enc_tracereference2 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, enc_tracereference2)
		if tagErr_enc_tracereference2 != nil {
			return nil, fmt.Errorf("encoding traceReference2: %w", tagErr_enc_tracereference2)
		}
		enc_tracereference2 = retagged_enc_tracereference2
		children = append(children, enc_tracereference2...)
	}
	for i, ext := range v.ExtData_ {
		_, n, _, extErr := ber.DecodeEncodedTLV(ext)
		if extErr != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, extErr)
		}
		if n != len(ext) {
			return nil, fmt.Errorf("encoding extension %d: %w", i, ber.ErrExtraData)
		}
		children = append(children, ext...)
	}
	return ber.EncodeSequence(children)
}

// MarshalDER encodes DeactivateTraceModeArg to DER format.
func (v *DeactivateTraceModeArg) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: DeactivateTraceModeArg receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if v.Imsi != nil {
		if len(*v.Imsi) < 3 || len(*v.Imsi) > 8 {
			if constraintErr := ber.CheckEncodedLength(nil, "imsi", "SIZE (3..8)", len(*v.Imsi)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_imsi, encodeErr_enc_imsi := ber.EncodeOctetString([]byte(*v.Imsi))
		if encodeErr_enc_imsi != nil {
			return nil, fmt.Errorf("encoding imsi: %w", encodeErr_enc_imsi)
		}
		retagged_enc_imsi, tagErr_enc_imsi := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_imsi)
		if tagErr_enc_imsi != nil {
			return nil, fmt.Errorf("encoding imsi: %w", tagErr_enc_imsi)
		}
		enc_imsi = retagged_enc_imsi
		children = append(children, enc_imsi...)
	}
	if len(v.TraceReference) < 1 || len(v.TraceReference) > 2 {
		if constraintErr := ber.CheckEncodedLength(nil, "traceReference", "SIZE (1..2)", len(v.TraceReference)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_tracereference, encodeErr_enc_tracereference := ber.EncodeOctetString([]byte(v.TraceReference))
	if encodeErr_enc_tracereference != nil {
		return nil, fmt.Errorf("encoding traceReference: %w", encodeErr_enc_tracereference)
	}
	retagged_enc_tracereference, tagErr_enc_tracereference := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_tracereference)
	if tagErr_enc_tracereference != nil {
		return nil, fmt.Errorf("encoding traceReference: %w", tagErr_enc_tracereference)
	}
	enc_tracereference = retagged_enc_tracereference
	children = append(children, enc_tracereference...)
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding extensionContainer: %w", err)
		}
		retagged_enc_extensioncontainer, tagErr_enc_extensioncontainer := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_extensioncontainer)
		if tagErr_enc_extensioncontainer != nil {
			return nil, fmt.Errorf("encoding extensionContainer: %w", tagErr_enc_extensioncontainer)
		}
		enc_extensioncontainer = retagged_enc_extensioncontainer
		children = append(children, enc_extensioncontainer...)
	}
	if v.TraceReference2 != nil {
		if len(*v.TraceReference2) < 3 || len(*v.TraceReference2) > 3 {
			if constraintErr := ber.CheckEncodedLength(nil, "traceReference2", "SIZE (3)", len(*v.TraceReference2)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_tracereference2, encodeErr_enc_tracereference2 := ber.EncodeOctetString([]byte(*v.TraceReference2))
		if encodeErr_enc_tracereference2 != nil {
			return nil, fmt.Errorf("encoding traceReference2: %w", encodeErr_enc_tracereference2)
		}
		retagged_enc_tracereference2, tagErr_enc_tracereference2 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, enc_tracereference2)
		if tagErr_enc_tracereference2 != nil {
			return nil, fmt.Errorf("encoding traceReference2: %w", tagErr_enc_tracereference2)
		}
		enc_tracereference2 = retagged_enc_tracereference2
		children = append(children, enc_tracereference2...)
	}
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDEREncodedElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
		children = append(children, ext...)
	}
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding DeactivateTraceModeArg as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes DeactivateTraceModeArg from BER/DER format.
func (v *DeactivateTraceModeArg) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: DeactivateTraceModeArg destination is nil", ber.ErrInvalidValue)
	}
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = DeactivateTraceModeArg{}
	defer func() {
		if returnErr != nil || !ber.BERNeedsPreservation(opts) {
			return
		}
		var snapshotReports ber.ViolationLog
		snapshot, snapshotErr := v.marshalBER(ber.WithConstraintTolerance(&snapshotReports))
		if snapshotErr != nil {
			returnErr = snapshotErr
			return
		}
		v.berOriginal_ = append([]byte(nil), data...)
		v.berSnapshot_ = snapshot
	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("decoding DeactivateTraceModeArg SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "DeactivateTraceModeArg", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode imsi
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
				decodedTag_imsi, n_imsi, rawVal_imsi, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding imsi: %w", err)
				}
				if decodedTag_imsi.Class != tag.ClassContextSpecific || decodedTag_imsi.Number != 0 {
					return fmt.Errorf("decoding imsi: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_imsi)
				}
				decVal_imsi, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_imsi.Constructed, rawVal_imsi, opts...)
				if octetErr != nil {
					return fmt.Errorf("decoding imsi: %w", octetErr)
				}
				tmp_imsi := IMSI(decVal_imsi)
				v.Imsi = &tmp_imsi
				if offset > len(content) || n_imsi < 0 || n_imsi > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_imsi
				if len(*v.Imsi) < 3 || len(*v.Imsi) > 8 {
					if constraintErr := ber.CheckDecodedLength(opts, "imsi", "SIZE (3..8)", len(*v.Imsi)); constraintErr != nil {
						return constraintErr
					}
				}
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
	decodedTag_tracereference, n_tracereference, rawVal_tracereference, err := ber.DecodeTLV(content[offset:], opts...)
	if err != nil {
		return fmt.Errorf("decoding traceReference: %w", err)
	}
	if decodedTag_tracereference.Class != tag.ClassContextSpecific || decodedTag_tracereference.Number != 1 {
		return fmt.Errorf("decoding traceReference: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_tracereference)
	}
	decVal_tracereference, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_tracereference.Constructed, rawVal_tracereference, opts...)
	if octetErr != nil {
		return fmt.Errorf("decoding traceReference: %w", octetErr)
	}
	v.TraceReference = TraceReference(decVal_tracereference)
	if offset < 0 || offset >
		len(content) || n_tracereference < 0 || n_tracereference > len(
		content[offset:]) {
		return fmt.Errorf("invalid BER content window")
	}

	offset += n_tracereference
	if len(v.TraceReference) < 1 || len(v.TraceReference) > 2 {
		if constraintErr := ber.CheckDecodedLength(opts, "traceReference", "SIZE (1..2)", len(v.TraceReference)); constraintErr != nil {
			return constraintErr
		}
	}
	// Decode extensionContainer
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2 {
				decodedTag_extensioncontainer, n_extensioncontainer, rawVal_extensioncontainer, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding extensionContainer: %w", err)
				}
				if decodedTag_extensioncontainer.Class != tag.ClassContextSpecific || decodedTag_extensioncontainer.Number != 2 || decodedTag_extensioncontainer.Constructed != true {
					return fmt.Errorf("decoding extensionContainer: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_extensioncontainer)
				}
				reconstructed_extensioncontainer, reconstructionErr_extensioncontainer := ber.EncodeSequence(rawVal_extensioncontainer)
				if reconstructionErr_extensioncontainer != nil {
					return fmt.Errorf("decoding extensionContainer: %w", reconstructionErr_extensioncontainer)
				}
				var dec_extensioncontainer ExtensionContainer
				if unmErr := dec_extensioncontainer.UnmarshalBER(reconstructed_extensioncontainer, ber.ChildDecodeOptions(opts, "extensionContainer")...); unmErr != nil {
					return fmt.Errorf("decoding extensionContainer: %w", unmErr)
				}
				v.ExtensionContainer = &dec_extensioncontainer
				if offset < 0 || offset >
					len(content) || n_extensioncontainer < 0 || n_extensioncontainer >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_extensioncontainer
			}
		}
	}
	// Decode traceReference2
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3 {
				decodedTag_tracereference2, n_tracereference2, rawVal_tracereference2, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding traceReference2: %w", err)
				}
				if decodedTag_tracereference2.Class != tag.ClassContextSpecific || decodedTag_tracereference2.Number != 3 {
					return fmt.Errorf("decoding traceReference2: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_tracereference2)
				}
				decVal_tracereference2, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_tracereference2.Constructed, rawVal_tracereference2, opts...)
				if octetErr != nil {
					return fmt.Errorf("decoding traceReference2: %w", octetErr)
				}
				tmp_tracereference2 := TraceReference2(decVal_tracereference2)
				v.TraceReference2 = &tmp_tracereference2
				if offset < 0 || offset >
					len(content) || n_tracereference2 < 0 || n_tracereference2 > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_tracereference2
				if len(*v.TraceReference2) < 3 || len(*v.TraceReference2) > 3 {
					if constraintErr := ber.CheckDecodedLength(opts, "traceReference2", "SIZE (3)", len(*v.TraceReference2)); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:], opts...)
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "DeactivateTraceModeArg", Cause: extErr_}
		}
		if offset < 0 || offset >
			len(content) || nExt_ < 0 || nExt_ > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		if offset < 0 || offset >
			len(content) || nExt_ < 0 || nExt_ > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes DeactivateTraceModeRes to BER format.
func (v *DeactivateTraceModeRes) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: DeactivateTraceModeRes receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *DeactivateTraceModeRes) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalBER(ber.ChildEncodeOptions(opts, "extensionContainer")...)
		if err != nil {
			return nil, fmt.Errorf("encoding extensionContainer: %w", err)
		}
		retagged_enc_extensioncontainer, tagErr_enc_extensioncontainer := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_extensioncontainer)
		if tagErr_enc_extensioncontainer != nil {
			return nil, fmt.Errorf("encoding extensionContainer: %w", tagErr_enc_extensioncontainer)
		}
		enc_extensioncontainer = retagged_enc_extensioncontainer
		children = append(children, enc_extensioncontainer...)
	}
	for i, ext := range v.ExtData_ {
		_, n, _, extErr := ber.DecodeEncodedTLV(ext)
		if extErr != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, extErr)
		}
		if n != len(ext) {
			return nil, fmt.Errorf("encoding extension %d: %w", i, ber.ErrExtraData)
		}
		children = append(children, ext...)
	}
	return ber.EncodeSequence(children)
}

// MarshalDER encodes DeactivateTraceModeRes to DER format.
func (v *DeactivateTraceModeRes) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: DeactivateTraceModeRes receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding extensionContainer: %w", err)
		}
		retagged_enc_extensioncontainer, tagErr_enc_extensioncontainer := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_extensioncontainer)
		if tagErr_enc_extensioncontainer != nil {
			return nil, fmt.Errorf("encoding extensionContainer: %w", tagErr_enc_extensioncontainer)
		}
		enc_extensioncontainer = retagged_enc_extensioncontainer
		children = append(children, enc_extensioncontainer...)
	}
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDEREncodedElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
		children = append(children, ext...)
	}
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding DeactivateTraceModeRes as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes DeactivateTraceModeRes from BER/DER format.
func (v *DeactivateTraceModeRes) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: DeactivateTraceModeRes destination is nil", ber.ErrInvalidValue)
	}
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = DeactivateTraceModeRes{}
	defer func() {
		if returnErr != nil || !ber.BERNeedsPreservation(opts) {
			return
		}
		var snapshotReports ber.ViolationLog
		snapshot, snapshotErr := v.marshalBER(ber.WithConstraintTolerance(&snapshotReports))
		if snapshotErr != nil {
			returnErr = snapshotErr
			return
		}
		v.berOriginal_ = append([]byte(nil), data...)
		v.berSnapshot_ = snapshot
	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("decoding DeactivateTraceModeRes SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "DeactivateTraceModeRes", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode extensionContainer
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
				decodedTag_extensioncontainer, n_extensioncontainer, rawVal_extensioncontainer, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding extensionContainer: %w", err)
				}
				if decodedTag_extensioncontainer.Class != tag.ClassContextSpecific || decodedTag_extensioncontainer.Number != 0 || decodedTag_extensioncontainer.Constructed != true {
					return fmt.Errorf("decoding extensionContainer: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_extensioncontainer)
				}
				reconstructed_extensioncontainer, reconstructionErr_extensioncontainer := ber.EncodeSequence(rawVal_extensioncontainer)
				if reconstructionErr_extensioncontainer != nil {
					return fmt.Errorf("decoding extensionContainer: %w", reconstructionErr_extensioncontainer)
				}
				var dec_extensioncontainer ExtensionContainer
				if unmErr := dec_extensioncontainer.UnmarshalBER(reconstructed_extensioncontainer, ber.ChildDecodeOptions(opts, "extensionContainer")...); unmErr != nil {
					return fmt.Errorf("decoding extensionContainer: %w", unmErr)
				}
				v.ExtensionContainer = &dec_extensioncontainer
				if offset > len(content) || n_extensioncontainer < 0 || n_extensioncontainer > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_extensioncontainer
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:], opts...)
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "DeactivateTraceModeRes", Cause: extErr_}
		}
		if offset < 0 || offset >
			len(content) || nExt_ < 0 || nExt_ > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		if offset < 0 || offset >
			len(content) || nExt_ < 0 || nExt_ > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}
