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

// ActivateTraceModeArg3 represents the ASN.1 type ActivateTraceModeArg3 (SEQUENCE).
type ActivateTraceModeArg3 struct {
	Imsi                  *IMSI3                     `asn1:"tag:0,context,implicit,optional" json:"Imsi,omitempty"`
	TraceReference        TraceReference3            `asn1:"tag:1,context,implicit"`
	TraceType             TraceType3                 `asn1:"tag:2,context,implicit"`
	OmcId                 *AddressString3            `asn1:"tag:3,context,implicit,optional" json:"OmcId,omitempty"`
	ExtensionContainer    *ExtensionContainer3       `asn1:"tag:4,context,implicit,optional" json:"ExtensionContainer,omitempty"`
	TraceReference2       *TraceReference23          `asn1:"tag:5,context,implicit,optional" json:"TraceReference2,omitempty"`
	TraceDepthList        *TraceDepthList3           `asn1:"tag:6,context,implicit,optional" json:"TraceDepthList,omitempty"`
	TraceNETypeList       *TraceNETypeList3          `asn1:"tag:7,context,implicit,optional" json:"TraceNETypeList,omitempty"`
	TraceInterfaceList    *TraceInterfaceList3       `asn1:"tag:8,context,implicit,optional" json:"TraceInterfaceList,omitempty"`
	TraceEventList        *TraceEventList3           `asn1:"tag:9,context,implicit,optional" json:"TraceEventList,omitempty"`
	TraceCollectionEntity *CommonDataTypesGSNAddress `asn1:"tag:10,context,implicit,optional" json:"TraceCollectionEntity,omitempty"`
	MdtConfiguration      *OMMDTConfiguration        `asn1:"tag:11,context,implicit,optional" json:"MdtConfiguration,omitempty"`
	ExtCount_             int64                      `asn1:"-" json:"-"`
	ExtPresent_           []bool                     `asn1:"-" json:"-"`
	ExtData_              [][]byte                   `asn1:"-" json:"-"`
}

// OMMDTConfiguration represents the ASN.1 type OMMDTConfiguration (SEQUENCE).
type OMMDTConfiguration struct {
	JobType                 OMJobType              `asn1:""`
	AreaScope               *OMAreaScope           `asn1:",optional" json:"AreaScope,omitempty"`
	ListOfMeasurements      *OMListOfMeasurements  `asn1:",optional" json:"ListOfMeasurements,omitempty"`
	ReportingTrigger        *OMReportingTrigger    `asn1:"tag:0,context,implicit,optional" json:"ReportingTrigger,omitempty"`
	ReportInterval          *OMReportInterval      `asn1:",optional" json:"ReportInterval,omitempty"`
	ReportAmount            *OMReportAmount        `asn1:"tag:1,context,implicit,optional" json:"ReportAmount,omitempty"`
	EventThresholdRSRP      *OMEventThresholdRSRP  `asn1:",optional" json:"EventThresholdRSRP,omitempty"`
	EventThresholdRSRQ      *OMEventThresholdRSRQ  `asn1:"tag:2,context,implicit,optional" json:"EventThresholdRSRQ,omitempty"`
	LoggingInterval         *OMLoggingInterval     `asn1:"tag:3,context,implicit,optional" json:"LoggingInterval,omitempty"`
	LoggingDuration         *OMLoggingDuration     `asn1:"tag:4,context,implicit,optional" json:"LoggingDuration,omitempty"`
	ExtensionContainer      *ExtensionContainer3   `asn1:"tag:5,context,implicit,optional" json:"ExtensionContainer,omitempty"`
	MeasurementPeriodUMTS   *OMPeriodUMTS          `asn1:"tag:6,context,implicit,optional" json:"MeasurementPeriodUMTS,omitempty"`
	MeasurementPeriodLTE    *OMPeriodLTE           `asn1:"tag:7,context,implicit,optional" json:"MeasurementPeriodLTE,omitempty"`
	CollectionPeriodRRMUMTS *OMPeriodUMTS          `asn1:"tag:8,context,implicit,optional" json:"CollectionPeriodRRMUMTS,omitempty"`
	CollectionPeriodRRMLTE  *OMPeriodLTE           `asn1:"tag:9,context,implicit,optional" json:"CollectionPeriodRRMLTE,omitempty"`
	PositioningMethod       *OMPositioningMethod   `asn1:"tag:10,context,implicit,optional" json:"PositioningMethod,omitempty"`
	MeasurementQuantity     *OMMeasurementQuantity `asn1:"tag:11,context,implicit,optional" json:"MeasurementQuantity,omitempty"`
	EventThreshold1F        *OMEventThreshold1F    `asn1:"tag:12,context,implicit,optional" json:"EventThreshold1F,omitempty"`
	EventThreshold1I        *OMEventThreshold1I    `asn1:"tag:13,context,implicit,optional" json:"EventThreshold1I,omitempty"`
	ExtCount_               int64                  `asn1:"-" json:"-"`
	ExtPresent_             []bool                 `asn1:"-" json:"-"`
	ExtData_                [][]byte               `asn1:"-" json:"-"`
}

// OMPeriodUMTS represents the ASN.1 ENUMERATED type OMPeriodUMTS.
type OMPeriodUMTS int64

const (
	OMPeriodUMTSD250ms   OMPeriodUMTS = 0
	OMPeriodUMTSD500ms   OMPeriodUMTS = 1
	OMPeriodUMTSD1000ms  OMPeriodUMTS = 2
	OMPeriodUMTSD2000ms  OMPeriodUMTS = 3
	OMPeriodUMTSD3000ms  OMPeriodUMTS = 4
	OMPeriodUMTSD4000ms  OMPeriodUMTS = 5
	OMPeriodUMTSD6000ms  OMPeriodUMTS = 6
	OMPeriodUMTSD8000ms  OMPeriodUMTS = 7
	OMPeriodUMTSD12000ms OMPeriodUMTS = 8
	OMPeriodUMTSD16000ms OMPeriodUMTS = 9
	OMPeriodUMTSD20000ms OMPeriodUMTS = 10
	OMPeriodUMTSD24000ms OMPeriodUMTS = 11
	OMPeriodUMTSD28000ms OMPeriodUMTS = 12
	OMPeriodUMTSD32000ms OMPeriodUMTS = 13
	OMPeriodUMTSD64000ms OMPeriodUMTS = 14
)

func (v OMPeriodUMTS) String() string {
	switch v {
	case OMPeriodUMTSD250ms:
		return "d250ms"
	case OMPeriodUMTSD500ms:
		return "d500ms"
	case OMPeriodUMTSD1000ms:
		return "d1000ms"
	case OMPeriodUMTSD2000ms:
		return "d2000ms"
	case OMPeriodUMTSD3000ms:
		return "d3000ms"
	case OMPeriodUMTSD4000ms:
		return "d4000ms"
	case OMPeriodUMTSD6000ms:
		return "d6000ms"
	case OMPeriodUMTSD8000ms:
		return "d8000ms"
	case OMPeriodUMTSD12000ms:
		return "d12000ms"
	case OMPeriodUMTSD16000ms:
		return "d16000ms"
	case OMPeriodUMTSD20000ms:
		return "d20000ms"
	case OMPeriodUMTSD24000ms:
		return "d24000ms"
	case OMPeriodUMTSD28000ms:
		return "d28000ms"
	case OMPeriodUMTSD32000ms:
		return "d32000ms"
	case OMPeriodUMTSD64000ms:
		return "d64000ms"
	default:
		return "unknown"
	}
}

// OMPeriodLTE represents the ASN.1 ENUMERATED type OMPeriodLTE.
type OMPeriodLTE int64

const (
	OMPeriodLTED1024ms  OMPeriodLTE = 0
	OMPeriodLTED1280ms  OMPeriodLTE = 1
	OMPeriodLTED2048ms  OMPeriodLTE = 2
	OMPeriodLTED2560ms  OMPeriodLTE = 3
	OMPeriodLTED5120ms  OMPeriodLTE = 4
	OMPeriodLTED10240ms OMPeriodLTE = 5
	OMPeriodLTED1min    OMPeriodLTE = 6
)

func (v OMPeriodLTE) String() string {
	switch v {
	case OMPeriodLTED1024ms:
		return "d1024ms"
	case OMPeriodLTED1280ms:
		return "d1280ms"
	case OMPeriodLTED2048ms:
		return "d2048ms"
	case OMPeriodLTED2560ms:
		return "d2560ms"
	case OMPeriodLTED5120ms:
		return "d5120ms"
	case OMPeriodLTED10240ms:
		return "d10240ms"
	case OMPeriodLTED1min:
		return "d1min"
	default:
		return "unknown"
	}
}

// OMPositioningMethod represents the ASN.1 type OMPositioningMethod (OCTET_STRING).
type OMPositioningMethod = []byte

// OMMeasurementQuantity represents the ASN.1 type OMMeasurementQuantity (OCTET_STRING).
type OMMeasurementQuantity = []byte

// OMEventThreshold1F represents the ASN.1 type OMEventThreshold1F (INTEGER).
type OMEventThreshold1F = int64

// OMEventThreshold1I represents the ASN.1 type OMEventThreshold1I (INTEGER).
type OMEventThreshold1I = int64

// OMJobType represents the ASN.1 ENUMERATED type OMJobType.
type OMJobType int64

const (
	OMJobTypeImmediateMDTOnly     OMJobType = 0
	OMJobTypeLoggedMDTOnly        OMJobType = 1
	OMJobTypeTraceOnly            OMJobType = 2
	OMJobTypeImmediateMDTAndTrace OMJobType = 3
)

func (v OMJobType) String() string {
	switch v {
	case OMJobTypeImmediateMDTOnly:
		return "immediate-MDT-only"
	case OMJobTypeLoggedMDTOnly:
		return "logged-MDT-only"
	case OMJobTypeTraceOnly:
		return "trace-only"
	case OMJobTypeImmediateMDTAndTrace:
		return "immediate-MDT-and-trace"
	default:
		return "unknown"
	}
}

// OMAreaScope represents the ASN.1 type OMAreaScope (SEQUENCE).
type OMAreaScope struct {
	CgiList                  OMCGIList            `asn1:"tag:0,context,implicit,optional" json:"CgiList,omitempty"`
	CgiListIndef_            bool                 `asn1:"-" json:"-"`
	EUtranCgiList            OMEUTRANCGIList      `asn1:"tag:1,context,implicit,optional" json:"EUtranCgiList,omitempty"`
	EUtranCgiListIndef_      bool                 `asn1:"-" json:"-"`
	RoutingAreaIdList        OMRoutingAreaIdList  `asn1:"tag:2,context,implicit,optional" json:"RoutingAreaIdList,omitempty"`
	RoutingAreaIdListIndef_  bool                 `asn1:"-" json:"-"`
	LocationAreaIdList       OMLocationAreaIdList `asn1:"tag:3,context,implicit,optional" json:"LocationAreaIdList,omitempty"`
	LocationAreaIdListIndef_ bool                 `asn1:"-" json:"-"`
	TrackingAreaIdList       OMTrackingAreaIdList `asn1:"tag:4,context,implicit,optional" json:"TrackingAreaIdList,omitempty"`
	TrackingAreaIdListIndef_ bool                 `asn1:"-" json:"-"`
	ExtensionContainer       *ExtensionContainer3 `asn1:"tag:5,context,implicit,optional" json:"ExtensionContainer,omitempty"`
	ExtCount_                int64                `asn1:"-" json:"-"`
	ExtPresent_              []bool               `asn1:"-" json:"-"`
	ExtData_                 [][]byte             `asn1:"-" json:"-"`
}

// OMCGIList represents the ASN.1 type OMCGIList (SEQUENCE_OF).
type OMCGIList = []GlobalCellId3

// OMEUTRANCGIList represents the ASN.1 type OMEUTRANCGIList (SEQUENCE_OF).
type OMEUTRANCGIList = []CommonDataTypesEUTRANCGI

// OMRoutingAreaIdList represents the ASN.1 type OMRoutingAreaIdList (SEQUENCE_OF).
type OMRoutingAreaIdList = []CommonDataTypesRAIdentity

// OMLocationAreaIdList represents the ASN.1 type OMLocationAreaIdList (SEQUENCE_OF).
type OMLocationAreaIdList = []LAIFixedLength3

// OMTrackingAreaIdList represents the ASN.1 type OMTrackingAreaIdList (SEQUENCE_OF).
type OMTrackingAreaIdList = []CommonDataTypesTAId

// OMListOfMeasurements represents the ASN.1 type OMListOfMeasurements (OCTET_STRING).
type OMListOfMeasurements = []byte

// OMReportingTrigger represents the ASN.1 type OMReportingTrigger (OCTET_STRING).
type OMReportingTrigger = []byte

// OMReportInterval represents the ASN.1 ENUMERATED type OMReportInterval.
type OMReportInterval int64

const (
	OMReportIntervalUmts250ms   OMReportInterval = 0
	OMReportIntervalUmts500ms   OMReportInterval = 1
	OMReportIntervalUmts1000ms  OMReportInterval = 2
	OMReportIntervalUmts2000ms  OMReportInterval = 3
	OMReportIntervalUmts3000ms  OMReportInterval = 4
	OMReportIntervalUmts4000ms  OMReportInterval = 5
	OMReportIntervalUmts6000ms  OMReportInterval = 6
	OMReportIntervalUmts8000ms  OMReportInterval = 7
	OMReportIntervalUmts12000ms OMReportInterval = 8
	OMReportIntervalUmts16000ms OMReportInterval = 9
	OMReportIntervalUmts20000ms OMReportInterval = 10
	OMReportIntervalUmts24000ms OMReportInterval = 11
	OMReportIntervalUmts28000ms OMReportInterval = 12
	OMReportIntervalUmts32000ms OMReportInterval = 13
	OMReportIntervalUmts64000ms OMReportInterval = 14
	OMReportIntervalLte120ms    OMReportInterval = 15
	OMReportIntervalLte240ms    OMReportInterval = 16
	OMReportIntervalLte480ms    OMReportInterval = 17
	OMReportIntervalLte640ms    OMReportInterval = 18
	OMReportIntervalLte1024ms   OMReportInterval = 19
	OMReportIntervalLte2048ms   OMReportInterval = 20
	OMReportIntervalLte5120ms   OMReportInterval = 21
	OMReportIntervalLte10240ms  OMReportInterval = 22
	OMReportIntervalLte1min     OMReportInterval = 23
	OMReportIntervalLte6min     OMReportInterval = 24
	OMReportIntervalLte12min    OMReportInterval = 25
	OMReportIntervalLte30min    OMReportInterval = 26
	OMReportIntervalLte60min    OMReportInterval = 27
)

func (v OMReportInterval) String() string {
	switch v {
	case OMReportIntervalUmts250ms:
		return "umts250ms"
	case OMReportIntervalUmts500ms:
		return "umts500ms"
	case OMReportIntervalUmts1000ms:
		return "umts1000ms"
	case OMReportIntervalUmts2000ms:
		return "umts2000ms"
	case OMReportIntervalUmts3000ms:
		return "umts3000ms"
	case OMReportIntervalUmts4000ms:
		return "umts4000ms"
	case OMReportIntervalUmts6000ms:
		return "umts6000ms"
	case OMReportIntervalUmts8000ms:
		return "umts8000ms"
	case OMReportIntervalUmts12000ms:
		return "umts12000ms"
	case OMReportIntervalUmts16000ms:
		return "umts16000ms"
	case OMReportIntervalUmts20000ms:
		return "umts20000ms"
	case OMReportIntervalUmts24000ms:
		return "umts24000ms"
	case OMReportIntervalUmts28000ms:
		return "umts28000ms"
	case OMReportIntervalUmts32000ms:
		return "umts32000ms"
	case OMReportIntervalUmts64000ms:
		return "umts64000ms"
	case OMReportIntervalLte120ms:
		return "lte120ms"
	case OMReportIntervalLte240ms:
		return "lte240ms"
	case OMReportIntervalLte480ms:
		return "lte480ms"
	case OMReportIntervalLte640ms:
		return "lte640ms"
	case OMReportIntervalLte1024ms:
		return "lte1024ms"
	case OMReportIntervalLte2048ms:
		return "lte2048ms"
	case OMReportIntervalLte5120ms:
		return "lte5120ms"
	case OMReportIntervalLte10240ms:
		return "lte10240ms"
	case OMReportIntervalLte1min:
		return "lte1min"
	case OMReportIntervalLte6min:
		return "lte6min"
	case OMReportIntervalLte12min:
		return "lte12min"
	case OMReportIntervalLte30min:
		return "lte30min"
	case OMReportIntervalLte60min:
		return "lte60min"
	default:
		return "unknown"
	}
}

// OMReportAmount represents the ASN.1 ENUMERATED type OMReportAmount.
type OMReportAmount int64

const (
	OMReportAmountD1       OMReportAmount = 0
	OMReportAmountD2       OMReportAmount = 1
	OMReportAmountD4       OMReportAmount = 2
	OMReportAmountD8       OMReportAmount = 3
	OMReportAmountD16      OMReportAmount = 4
	OMReportAmountD32      OMReportAmount = 5
	OMReportAmountD64      OMReportAmount = 6
	OMReportAmountInfinity OMReportAmount = 7
)

func (v OMReportAmount) String() string {
	switch v {
	case OMReportAmountD1:
		return "d1"
	case OMReportAmountD2:
		return "d2"
	case OMReportAmountD4:
		return "d4"
	case OMReportAmountD8:
		return "d8"
	case OMReportAmountD16:
		return "d16"
	case OMReportAmountD32:
		return "d32"
	case OMReportAmountD64:
		return "d64"
	case OMReportAmountInfinity:
		return "infinity"
	default:
		return "unknown"
	}
}

// OMEventThresholdRSRP represents the ASN.1 type OMEventThresholdRSRP (INTEGER).
type OMEventThresholdRSRP = int64

// OMEventThresholdRSRQ represents the ASN.1 type OMEventThresholdRSRQ (INTEGER).
type OMEventThresholdRSRQ = int64

// OMLoggingInterval represents the ASN.1 ENUMERATED type OMLoggingInterval.
type OMLoggingInterval int64

const (
	OMLoggingIntervalD1dot28  OMLoggingInterval = 0
	OMLoggingIntervalD2dot56  OMLoggingInterval = 1
	OMLoggingIntervalD5dot12  OMLoggingInterval = 2
	OMLoggingIntervalD10dot24 OMLoggingInterval = 3
	OMLoggingIntervalD20dot48 OMLoggingInterval = 4
	OMLoggingIntervalD30dot72 OMLoggingInterval = 5
	OMLoggingIntervalD40dot96 OMLoggingInterval = 6
	OMLoggingIntervalD61dot44 OMLoggingInterval = 7
)

func (v OMLoggingInterval) String() string {
	switch v {
	case OMLoggingIntervalD1dot28:
		return "d1dot28"
	case OMLoggingIntervalD2dot56:
		return "d2dot56"
	case OMLoggingIntervalD5dot12:
		return "d5dot12"
	case OMLoggingIntervalD10dot24:
		return "d10dot24"
	case OMLoggingIntervalD20dot48:
		return "d20dot48"
	case OMLoggingIntervalD30dot72:
		return "d30dot72"
	case OMLoggingIntervalD40dot96:
		return "d40dot96"
	case OMLoggingIntervalD61dot44:
		return "d61dot44"
	default:
		return "unknown"
	}
}

// OMLoggingDuration represents the ASN.1 ENUMERATED type OMLoggingDuration.
type OMLoggingDuration int64

const (
	OMLoggingDurationD600sec  OMLoggingDuration = 0
	OMLoggingDurationD1200sec OMLoggingDuration = 1
	OMLoggingDurationD2400sec OMLoggingDuration = 2
	OMLoggingDurationD3600sec OMLoggingDuration = 3
	OMLoggingDurationD5400sec OMLoggingDuration = 4
	OMLoggingDurationD7200sec OMLoggingDuration = 5
)

func (v OMLoggingDuration) String() string {
	switch v {
	case OMLoggingDurationD600sec:
		return "d600sec"
	case OMLoggingDurationD1200sec:
		return "d1200sec"
	case OMLoggingDurationD2400sec:
		return "d2400sec"
	case OMLoggingDurationD3600sec:
		return "d3600sec"
	case OMLoggingDurationD5400sec:
		return "d5400sec"
	case OMLoggingDurationD7200sec:
		return "d7200sec"
	default:
		return "unknown"
	}
}

// TraceReference3 represents the ASN.1 type TraceReference3 (OCTET_STRING).
type TraceReference3 = []byte

// TraceReference23 represents the ASN.1 type TraceReference23 (OCTET_STRING).
type TraceReference23 = []byte

// TraceRecordingSessionReference3 represents the ASN.1 type TraceRecordingSessionReference3 (OCTET_STRING).
type TraceRecordingSessionReference3 = []byte

// TraceType3 represents the ASN.1 type TraceType3 (INTEGER).
type TraceType3 = int64

// TraceDepthList3 represents the ASN.1 type TraceDepthList3 (SEQUENCE).
type TraceDepthList3 struct {
	MscSTraceDepth          *TraceDepth3           `asn1:"tag:0,context,implicit,optional" json:"MscSTraceDepth,omitempty"`
	MgwTraceDepth           *TraceDepth3           `asn1:"tag:1,context,implicit,optional" json:"MgwTraceDepth,omitempty"`
	SgsnTraceDepth          *TraceDepth3           `asn1:"tag:2,context,implicit,optional" json:"SgsnTraceDepth,omitempty"`
	GgsnTraceDepth          *TraceDepth3           `asn1:"tag:3,context,implicit,optional" json:"GgsnTraceDepth,omitempty"`
	RncTraceDepth           *TraceDepth3           `asn1:"tag:4,context,implicit,optional" json:"RncTraceDepth,omitempty"`
	BmscTraceDepth          *TraceDepth3           `asn1:"tag:5,context,implicit,optional" json:"BmscTraceDepth,omitempty"`
	MmeTraceDepth           *TraceDepth3           `asn1:"tag:6,context,implicit,optional" json:"MmeTraceDepth,omitempty"`
	SgwTraceDepth           *TraceDepth3           `asn1:"tag:7,context,implicit,optional" json:"SgwTraceDepth,omitempty"`
	PgwTraceDepth           *TraceDepth3           `asn1:"tag:8,context,implicit,optional" json:"PgwTraceDepth,omitempty"`
	ENBTraceDepth           *TraceDepth3           `asn1:"tag:9,context,implicit,optional" json:"ENBTraceDepth,omitempty"`
	MscSTraceDepthExtension *OMTraceDepthExtension `asn1:"tag:10,context,implicit,optional" json:"MscSTraceDepthExtension,omitempty"`
	MgwTraceDepthExtension  *OMTraceDepthExtension `asn1:"tag:11,context,implicit,optional" json:"MgwTraceDepthExtension,omitempty"`
	SgsnTraceDepthExtension *OMTraceDepthExtension `asn1:"tag:12,context,implicit,optional" json:"SgsnTraceDepthExtension,omitempty"`
	GgsnTraceDepthExtension *OMTraceDepthExtension `asn1:"tag:13,context,implicit,optional" json:"GgsnTraceDepthExtension,omitempty"`
	RncTraceDepthExtension  *OMTraceDepthExtension `asn1:"tag:14,context,implicit,optional" json:"RncTraceDepthExtension,omitempty"`
	BmscTraceDepthExtension *OMTraceDepthExtension `asn1:"tag:15,context,implicit,optional" json:"BmscTraceDepthExtension,omitempty"`
	MmeTraceDepthExtension  *OMTraceDepthExtension `asn1:"tag:16,context,implicit,optional" json:"MmeTraceDepthExtension,omitempty"`
	SgwTraceDepthExtension  *OMTraceDepthExtension `asn1:"tag:17,context,implicit,optional" json:"SgwTraceDepthExtension,omitempty"`
	PgwTraceDepthExtension  *OMTraceDepthExtension `asn1:"tag:18,context,implicit,optional" json:"PgwTraceDepthExtension,omitempty"`
	ENBTraceDepthExtension  *OMTraceDepthExtension `asn1:"tag:19,context,implicit,optional" json:"ENBTraceDepthExtension,omitempty"`
	ExtCount_               int64                  `asn1:"-" json:"-"`
	ExtPresent_             []bool                 `asn1:"-" json:"-"`
	ExtData_                [][]byte               `asn1:"-" json:"-"`
}

// TraceDepth3 represents the ASN.1 ENUMERATED type TraceDepth3.
type TraceDepth3 int64

const (
	TraceDepth3Minimum TraceDepth3 = 0
	TraceDepth3Medium  TraceDepth3 = 1
	TraceDepth3Maximum TraceDepth3 = 2
)

func (v TraceDepth3) String() string {
	switch v {
	case TraceDepth3Minimum:
		return "minimum"
	case TraceDepth3Medium:
		return "medium"
	case TraceDepth3Maximum:
		return "maximum"
	default:
		return "unknown"
	}
}

// OMTraceDepthExtension represents the ASN.1 ENUMERATED type OMTraceDepthExtension.
type OMTraceDepthExtension int64

const (
	OMTraceDepthExtensionMinimumWithoutVendorSpecificExtension OMTraceDepthExtension = 0
	OMTraceDepthExtensionMediumWithoutVendorSpecificExtension  OMTraceDepthExtension = 1
	OMTraceDepthExtensionMaximumWithoutVendorSpecificExtension OMTraceDepthExtension = 2
)

func (v OMTraceDepthExtension) String() string {
	switch v {
	case OMTraceDepthExtensionMinimumWithoutVendorSpecificExtension:
		return "minimumWithoutVendorSpecificExtension"
	case OMTraceDepthExtensionMediumWithoutVendorSpecificExtension:
		return "mediumWithoutVendorSpecificExtension"
	case OMTraceDepthExtensionMaximumWithoutVendorSpecificExtension:
		return "maximumWithoutVendorSpecificExtension"
	default:
		return "unknown"
	}
}

// TraceNETypeList3 represents the ASN.1 type TraceNETypeList3 (BIT_STRING).
type TraceNETypeList3 = runtime.BitString

// TraceInterfaceList3 represents the ASN.1 type TraceInterfaceList3 (SEQUENCE).
type TraceInterfaceList3 struct {
	MscSList    *MSCSInterfaceList3 `asn1:"tag:0,context,implicit,optional" json:"MscSList,omitempty"`
	MgwList     *MGWInterfaceList3  `asn1:"tag:1,context,implicit,optional" json:"MgwList,omitempty"`
	SgsnList    *SGSNInterfaceList3 `asn1:"tag:2,context,implicit,optional" json:"SgsnList,omitempty"`
	GgsnList    *GGSNInterfaceList3 `asn1:"tag:3,context,implicit,optional" json:"GgsnList,omitempty"`
	RncList     *RNCInterfaceList3  `asn1:"tag:4,context,implicit,optional" json:"RncList,omitempty"`
	BmscList    *BMSCInterfaceList3 `asn1:"tag:5,context,implicit,optional" json:"BmscList,omitempty"`
	MmeList     *OMMMEInterfaceList `asn1:"tag:6,context,implicit,optional" json:"MmeList,omitempty"`
	SgwList     *OMSGWInterfaceList `asn1:"tag:7,context,implicit,optional" json:"SgwList,omitempty"`
	PgwList     *OMPGWInterfaceList `asn1:"tag:8,context,implicit,optional" json:"PgwList,omitempty"`
	ENBList     *OMENBInterfaceList `asn1:"tag:9,context,implicit,optional" json:"ENBList,omitempty"`
	ExtCount_   int64               `asn1:"-" json:"-"`
	ExtPresent_ []bool              `asn1:"-" json:"-"`
	ExtData_    [][]byte            `asn1:"-" json:"-"`
}

// MSCSInterfaceList3 represents the ASN.1 type MSCSInterfaceList3 (BIT_STRING).
type MSCSInterfaceList3 = runtime.BitString

// MGWInterfaceList3 represents the ASN.1 type MGWInterfaceList3 (BIT_STRING).
type MGWInterfaceList3 = runtime.BitString

// SGSNInterfaceList3 represents the ASN.1 type SGSNInterfaceList3 (BIT_STRING).
type SGSNInterfaceList3 = runtime.BitString

// GGSNInterfaceList3 represents the ASN.1 type GGSNInterfaceList3 (BIT_STRING).
type GGSNInterfaceList3 = runtime.BitString

// RNCInterfaceList3 represents the ASN.1 type RNCInterfaceList3 (BIT_STRING).
type RNCInterfaceList3 = runtime.BitString

// BMSCInterfaceList3 represents the ASN.1 type BMSCInterfaceList3 (BIT_STRING).
type BMSCInterfaceList3 = runtime.BitString

// OMMMEInterfaceList represents the ASN.1 type OMMMEInterfaceList (BIT_STRING).
type OMMMEInterfaceList = runtime.BitString

// OMSGWInterfaceList represents the ASN.1 type OMSGWInterfaceList (BIT_STRING).
type OMSGWInterfaceList = runtime.BitString

// OMPGWInterfaceList represents the ASN.1 type OMPGWInterfaceList (BIT_STRING).
type OMPGWInterfaceList = runtime.BitString

// OMENBInterfaceList represents the ASN.1 type OMENBInterfaceList (BIT_STRING).
type OMENBInterfaceList = runtime.BitString

// TraceEventList3 represents the ASN.1 type TraceEventList3 (SEQUENCE).
type TraceEventList3 struct {
	MscSList    *MSCSEventList3 `asn1:"tag:0,context,implicit,optional" json:"MscSList,omitempty"`
	MgwList     *MGWEventList3  `asn1:"tag:1,context,implicit,optional" json:"MgwList,omitempty"`
	SgsnList    *SGSNEventList3 `asn1:"tag:2,context,implicit,optional" json:"SgsnList,omitempty"`
	GgsnList    *GGSNEventList3 `asn1:"tag:3,context,implicit,optional" json:"GgsnList,omitempty"`
	BmscList    *BMSCEventList3 `asn1:"tag:4,context,implicit,optional" json:"BmscList,omitempty"`
	MmeList     *OMMMEEventList `asn1:"tag:5,context,implicit,optional" json:"MmeList,omitempty"`
	SgwList     *OMSGWEventList `asn1:"tag:6,context,implicit,optional" json:"SgwList,omitempty"`
	PgwList     *OMPGWEventList `asn1:"tag:7,context,implicit,optional" json:"PgwList,omitempty"`
	ExtCount_   int64           `asn1:"-" json:"-"`
	ExtPresent_ []bool          `asn1:"-" json:"-"`
	ExtData_    [][]byte        `asn1:"-" json:"-"`
}

// MSCSEventList3 represents the ASN.1 type MSCSEventList3 (BIT_STRING).
type MSCSEventList3 = runtime.BitString

// MGWEventList3 represents the ASN.1 type MGWEventList3 (BIT_STRING).
type MGWEventList3 = runtime.BitString

// SGSNEventList3 represents the ASN.1 type SGSNEventList3 (BIT_STRING).
type SGSNEventList3 = runtime.BitString

// GGSNEventList3 represents the ASN.1 type GGSNEventList3 (BIT_STRING).
type GGSNEventList3 = runtime.BitString

// BMSCEventList3 represents the ASN.1 type BMSCEventList3 (BIT_STRING).
type BMSCEventList3 = runtime.BitString

// OMMMEEventList represents the ASN.1 type OMMMEEventList (BIT_STRING).
type OMMMEEventList = runtime.BitString

// OMSGWEventList represents the ASN.1 type OMSGWEventList (BIT_STRING).
type OMSGWEventList = runtime.BitString

// OMPGWEventList represents the ASN.1 type OMPGWEventList (BIT_STRING).
type OMPGWEventList = runtime.BitString

// TracePropagationList3 represents the ASN.1 type TracePropagationList3 (SEQUENCE).
type TracePropagationList3 struct {
	TraceReference                 *TraceReference3                 `asn1:"tag:0,context,implicit,optional" json:"TraceReference,omitempty"`
	TraceType                      *TraceType3                      `asn1:"tag:1,context,implicit,optional" json:"TraceType,omitempty"`
	TraceReference2                *TraceReference23                `asn1:"tag:2,context,implicit,optional" json:"TraceReference2,omitempty"`
	TraceRecordingSessionReference *TraceRecordingSessionReference3 `asn1:"tag:3,context,implicit,optional" json:"TraceRecordingSessionReference,omitempty"`
	RncTraceDepth                  *TraceDepth3                     `asn1:"tag:4,context,implicit,optional" json:"RncTraceDepth,omitempty"`
	RncInterfaceList               *RNCInterfaceList3               `asn1:"tag:5,context,implicit,optional" json:"RncInterfaceList,omitempty"`
	MscSTraceDepth                 *TraceDepth3                     `asn1:"tag:6,context,implicit,optional" json:"MscSTraceDepth,omitempty"`
	MscSInterfaceList              *MSCSInterfaceList3              `asn1:"tag:7,context,implicit,optional" json:"MscSInterfaceList,omitempty"`
	MscSEventList                  *MSCSEventList3                  `asn1:"tag:8,context,implicit,optional" json:"MscSEventList,omitempty"`
	MgwTraceDepth                  *TraceDepth3                     `asn1:"tag:9,context,implicit,optional" json:"MgwTraceDepth,omitempty"`
	MgwInterfaceList               *MGWInterfaceList3               `asn1:"tag:10,context,implicit,optional" json:"MgwInterfaceList,omitempty"`
	MgwEventList                   *MGWEventList3                   `asn1:"tag:11,context,implicit,optional" json:"MgwEventList,omitempty"`
	RncTraceDepthExtension         *OMTraceDepthExtension           `asn1:"tag:12,context,implicit,optional" json:"RncTraceDepthExtension,omitempty"`
	MscSTraceDepthExtension        *OMTraceDepthExtension           `asn1:"tag:13,context,implicit,optional" json:"MscSTraceDepthExtension,omitempty"`
	MgwTraceDepthExtension         *OMTraceDepthExtension           `asn1:"tag:14,context,implicit,optional" json:"MgwTraceDepthExtension,omitempty"`
	ExtCount_                      int64                            `asn1:"-" json:"-"`
	ExtPresent_                    []bool                           `asn1:"-" json:"-"`
	ExtData_                       [][]byte                         `asn1:"-" json:"-"`
}

// ActivateTraceModeRes3 represents the ASN.1 type ActivateTraceModeRes3 (SEQUENCE).
type ActivateTraceModeRes3 struct {
	ExtensionContainer    *ExtensionContainer3 `asn1:"tag:0,context,implicit,optional" json:"ExtensionContainer,omitempty"`
	TraceSupportIndicator *struct{}            `asn1:"tag:1,context,implicit,optional" json:"TraceSupportIndicator,omitempty"`
	ExtCount_             int64                `asn1:"-" json:"-"`
	ExtPresent_           []bool               `asn1:"-" json:"-"`
	ExtData_              [][]byte             `asn1:"-" json:"-"`
}

// DeactivateTraceModeArg3 represents the ASN.1 type DeactivateTraceModeArg3 (SEQUENCE).
type DeactivateTraceModeArg3 struct {
	Imsi               *IMSI3               `asn1:"tag:0,context,implicit,optional" json:"Imsi,omitempty"`
	TraceReference     TraceReference3      `asn1:"tag:1,context,implicit"`
	ExtensionContainer *ExtensionContainer3 `asn1:"tag:2,context,implicit,optional" json:"ExtensionContainer,omitempty"`
	TraceReference2    *TraceReference23    `asn1:"tag:3,context,implicit,optional" json:"TraceReference2,omitempty"`
	ExtCount_          int64                `asn1:"-" json:"-"`
	ExtPresent_        []bool               `asn1:"-" json:"-"`
	ExtData_           [][]byte             `asn1:"-" json:"-"`
}

// DeactivateTraceModeRes3 represents the ASN.1 type DeactivateTraceModeRes3 (SEQUENCE).
type DeactivateTraceModeRes3 struct {
	ExtensionContainer *ExtensionContainer3 `asn1:"tag:0,context,implicit,optional" json:"ExtensionContainer,omitempty"`
	ExtCount_          int64                `asn1:"-" json:"-"`
	ExtPresent_        []bool               `asn1:"-" json:"-"`
	ExtData_           [][]byte             `asn1:"-" json:"-"`
}

// MarshalBER encodes ActivateTraceModeArg3 to BER format.
func (v *ActivateTraceModeArg3) MarshalBER() ([]byte, error) {
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

// MarshalDER encodes ActivateTraceModeArg3 to DER format.
func (v *ActivateTraceModeArg3) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes ActivateTraceModeArg3 from BER/DER format.
func (v *ActivateTraceModeArg3) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding ActivateTraceModeArg3 SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "ActivateTraceModeArg3", Cause: ber.ErrExtraData}
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
				tmp_imsi := IMSI3(rawVal_imsi)
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
	v.TraceReference = TraceReference3(rawVal_tracereference)
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
	v.TraceType = TraceType3(decVal_tracetype)
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
				tmp_omcid := AddressString3(rawVal_omcid)
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
				var dec_extensioncontainer ExtensionContainer3
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
				tmp_tracereference2 := TraceReference23(rawVal_tracereference2)
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
				var dec_tracedepthlist TraceDepthList3
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
				var dec_traceinterfacelist TraceInterfaceList3
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
				var dec_traceeventlist TraceEventList3
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
				tmp_tracecollectionentity := CommonDataTypesGSNAddress(rawVal_tracecollectionentity)
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
				var dec_mdtconfiguration OMMDTConfiguration
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
			return &ber.DecodeError{Offset: offset, TypeName: "ActivateTraceModeArg3", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes OMMDTConfiguration to BER format.
func (v *OMMDTConfiguration) MarshalBER() ([]byte, error) {
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
	if v.MeasurementPeriodUMTS != nil {
		enc_measurementperiodumts := ber.EncodeEnumerated(int64(*v.MeasurementPeriodUMTS))
		enc_measurementperiodumts = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 6, false, enc_measurementperiodumts)
		children = append(children, enc_measurementperiodumts...)
	}
	if v.MeasurementPeriodLTE != nil {
		enc_measurementperiodlte := ber.EncodeEnumerated(int64(*v.MeasurementPeriodLTE))
		enc_measurementperiodlte = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 7, false, enc_measurementperiodlte)
		children = append(children, enc_measurementperiodlte...)
	}
	if v.CollectionPeriodRRMUMTS != nil {
		enc_collectionperiodrrmumts := ber.EncodeEnumerated(int64(*v.CollectionPeriodRRMUMTS))
		enc_collectionperiodrrmumts = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 8, false, enc_collectionperiodrrmumts)
		children = append(children, enc_collectionperiodrrmumts...)
	}
	if v.CollectionPeriodRRMLTE != nil {
		enc_collectionperiodrrmlte := ber.EncodeEnumerated(int64(*v.CollectionPeriodRRMLTE))
		enc_collectionperiodrrmlte = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 9, false, enc_collectionperiodrrmlte)
		children = append(children, enc_collectionperiodrrmlte...)
	}
	if v.PositioningMethod != nil {
		enc_positioningmethod := ber.EncodeOctetString([]byte(*v.PositioningMethod))
		enc_positioningmethod = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 10, false, enc_positioningmethod)
		children = append(children, enc_positioningmethod...)
	}
	if v.MeasurementQuantity != nil {
		enc_measurementquantity := ber.EncodeOctetString([]byte(*v.MeasurementQuantity))
		enc_measurementquantity = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 11, false, enc_measurementquantity)
		children = append(children, enc_measurementquantity...)
	}
	if v.EventThreshold1F != nil {
		enc_eventthreshold1f := ber.EncodeInteger(int64(*v.EventThreshold1F))
		enc_eventthreshold1f = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 12, false, enc_eventthreshold1f)
		children = append(children, enc_eventthreshold1f...)
	}
	if v.EventThreshold1I != nil {
		enc_eventthreshold1i := ber.EncodeInteger(int64(*v.EventThreshold1I))
		enc_eventthreshold1i = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 13, false, enc_eventthreshold1i)
		children = append(children, enc_eventthreshold1i...)
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

// MarshalDER encodes OMMDTConfiguration to DER format.
func (v *OMMDTConfiguration) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes OMMDTConfiguration from BER/DER format.
func (v *OMMDTConfiguration) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding OMMDTConfiguration SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "OMMDTConfiguration", Cause: ber.ErrExtraData}
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
	v.JobType = OMJobType(val_jobtype)
	offset += n
	// Decode areaScope
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassUniversal && peekTag.Number == 16 {
				// Decode nested SEQUENCE (OMAreaScope)
				_, n_areascope, _, tlvErr_areascope := ber.DecodeTLV(content[offset:])
				if tlvErr_areascope != nil {
					return fmt.Errorf("decoding areaScope: %w", tlvErr_areascope)
				}
				var dec_areascope OMAreaScope
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
				tmp_listofmeasurements := OMListOfMeasurements(val_listofmeasurements)
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
				tmp_reportingtrigger := OMReportingTrigger(rawVal_reportingtrigger)
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
				tmp_reportinterval := OMReportInterval(val_reportinterval)
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
				tmp_reportamount := OMReportAmount(decVal_reportamount)
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
				tmp_eventthresholdrsrp := OMEventThresholdRSRP(val_eventthresholdrsrp)
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
				tmp_eventthresholdrsrq := OMEventThresholdRSRQ(decVal_eventthresholdrsrq)
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
				tmp_logginginterval := OMLoggingInterval(decVal_logginginterval)
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
				tmp_loggingduration := OMLoggingDuration(decVal_loggingduration)
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
				var dec_extensioncontainer ExtensionContainer3
				if unmErr := dec_extensioncontainer.UnmarshalBER(reconstructed_extensioncontainer); unmErr != nil {
					return fmt.Errorf("decoding extensionContainer: %w", unmErr)
				}
				v.ExtensionContainer = &dec_extensioncontainer
				offset += n_extensioncontainer
			}
		}
	}
	// Decode measurementPeriodUMTS
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 6 {
				_, n_measurementperiodumts, rawVal_measurementperiodumts, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding measurementPeriodUMTS: %w", err)
				}
				decVal_measurementperiodumts, intErr := ber.DecodeIntegerValue(rawVal_measurementperiodumts)
				if intErr != nil {
					return fmt.Errorf("decoding measurementPeriodUMTS: %w", intErr)
				}
				tmp_measurementperiodumts := OMPeriodUMTS(decVal_measurementperiodumts)
				v.MeasurementPeriodUMTS = &tmp_measurementperiodumts
				offset += n_measurementperiodumts
			}
		}
	}
	// Decode measurementPeriodLTE
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 7 {
				_, n_measurementperiodlte, rawVal_measurementperiodlte, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding measurementPeriodLTE: %w", err)
				}
				decVal_measurementperiodlte, intErr := ber.DecodeIntegerValue(rawVal_measurementperiodlte)
				if intErr != nil {
					return fmt.Errorf("decoding measurementPeriodLTE: %w", intErr)
				}
				tmp_measurementperiodlte := OMPeriodLTE(decVal_measurementperiodlte)
				v.MeasurementPeriodLTE = &tmp_measurementperiodlte
				offset += n_measurementperiodlte
			}
		}
	}
	// Decode collectionPeriodRRM-UMTS
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 8 {
				_, n_collectionperiodrrmumts, rawVal_collectionperiodrrmumts, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding collectionPeriodRRM-UMTS: %w", err)
				}
				decVal_collectionperiodrrmumts, intErr := ber.DecodeIntegerValue(rawVal_collectionperiodrrmumts)
				if intErr != nil {
					return fmt.Errorf("decoding collectionPeriodRRM-UMTS: %w", intErr)
				}
				tmp_collectionperiodrrmumts := OMPeriodUMTS(decVal_collectionperiodrrmumts)
				v.CollectionPeriodRRMUMTS = &tmp_collectionperiodrrmumts
				offset += n_collectionperiodrrmumts
			}
		}
	}
	// Decode collectionPeriodRRM-LTE
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 9 {
				_, n_collectionperiodrrmlte, rawVal_collectionperiodrrmlte, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding collectionPeriodRRM-LTE: %w", err)
				}
				decVal_collectionperiodrrmlte, intErr := ber.DecodeIntegerValue(rawVal_collectionperiodrrmlte)
				if intErr != nil {
					return fmt.Errorf("decoding collectionPeriodRRM-LTE: %w", intErr)
				}
				tmp_collectionperiodrrmlte := OMPeriodLTE(decVal_collectionperiodrrmlte)
				v.CollectionPeriodRRMLTE = &tmp_collectionperiodrrmlte
				offset += n_collectionperiodrrmlte
			}
		}
	}
	// Decode positioningMethod
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 10 {
				_, n_positioningmethod, rawVal_positioningmethod, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding positioningMethod: %w", err)
				}
				tmp_positioningmethod := OMPositioningMethod(rawVal_positioningmethod)
				v.PositioningMethod = &tmp_positioningmethod
				offset += n_positioningmethod
			}
		}
	}
	// Decode measurementQuantity
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 11 {
				_, n_measurementquantity, rawVal_measurementquantity, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding measurementQuantity: %w", err)
				}
				tmp_measurementquantity := OMMeasurementQuantity(rawVal_measurementquantity)
				v.MeasurementQuantity = &tmp_measurementquantity
				offset += n_measurementquantity
			}
		}
	}
	// Decode eventThreshold1F
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 12 {
				_, n_eventthreshold1f, rawVal_eventthreshold1f, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding eventThreshold1F: %w", err)
				}
				decVal_eventthreshold1f, intErr := ber.DecodeIntegerValue(rawVal_eventthreshold1f)
				if intErr != nil {
					return fmt.Errorf("decoding eventThreshold1F: %w", intErr)
				}
				tmp_eventthreshold1f := OMEventThreshold1F(decVal_eventthreshold1f)
				v.EventThreshold1F = &tmp_eventthreshold1f
				offset += n_eventthreshold1f
			}
		}
	}
	// Decode eventThreshold1I
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 13 {
				_, n_eventthreshold1i, rawVal_eventthreshold1i, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding eventThreshold1I: %w", err)
				}
				decVal_eventthreshold1i, intErr := ber.DecodeIntegerValue(rawVal_eventthreshold1i)
				if intErr != nil {
					return fmt.Errorf("decoding eventThreshold1I: %w", intErr)
				}
				tmp_eventthreshold1i := OMEventThreshold1I(decVal_eventthreshold1i)
				v.EventThreshold1I = &tmp_eventthreshold1i
				offset += n_eventthreshold1i
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "OMMDTConfiguration", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes OMAreaScope to BER format.
func (v *OMAreaScope) MarshalBER() ([]byte, error) {
	var children []byte
	if v.CgiList != nil {
		enc_cgilist, err := MarshalBEROMCGIList(v.CgiList)
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
		enc_eutrancgilist, err := MarshalBEROMEUTRANCGIList(v.EUtranCgiList)
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
		enc_routingareaidlist, err := MarshalBEROMRoutingAreaIdList(v.RoutingAreaIdList)
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
		enc_locationareaidlist, err := MarshalBEROMLocationAreaIdList(v.LocationAreaIdList)
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
		enc_trackingareaidlist, err := MarshalBEROMTrackingAreaIdList(v.TrackingAreaIdList)
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

// MarshalDER encodes OMAreaScope to DER format.
func (v *OMAreaScope) MarshalDER() ([]byte, error) {
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

// UnmarshalBER decodes OMAreaScope from BER/DER format.
func (v *OMAreaScope) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding OMAreaScope SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "OMAreaScope", Cause: ber.ErrExtraData}
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
				dec_cgilist, unmErr := UnmarshalBEROMCGIList(reconstructed_cgilist)
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
				dec_eutrancgilist, unmErr := UnmarshalBEROMEUTRANCGIList(reconstructed_eutrancgilist)
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
				dec_routingareaidlist, unmErr := UnmarshalBEROMRoutingAreaIdList(reconstructed_routingareaidlist)
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
				dec_locationareaidlist, unmErr := UnmarshalBEROMLocationAreaIdList(reconstructed_locationareaidlist)
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
				dec_trackingareaidlist, unmErr := UnmarshalBEROMTrackingAreaIdList(reconstructed_trackingareaidlist)
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
				var dec_extensioncontainer ExtensionContainer3
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
			return &ber.DecodeError{Offset: offset, TypeName: "OMAreaScope", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBEROMCGIList encodes a OMCGIList list to BER.
func MarshalBEROMCGIList(list OMCGIList) ([]byte, error) {
	var children []byte
	for _, elem := range list {
		children = append(children, ber.EncodeOctetString([]byte(elem))...)
	}
	return ber.EncodeSequence(children), nil
}

// UnmarshalBEROMCGIList decodes a OMCGIList list from BER.
func UnmarshalBEROMCGIList(data []byte) (OMCGIList, error) {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return nil, fmt.Errorf("decoding OMCGIList: %w", err)
	}
	if total != len(data) {
		return nil, &ber.DecodeError{Offset: total, TypeName: "OMCGIList", Cause: ber.ErrExtraData}
	}
	var result OMCGIList
	offset := 0
	for offset < len(content) {
		val, n, osErr := ber.DecodeOctetString(content[offset:])
		if osErr != nil {
			return nil, fmt.Errorf("decoding element: %w", osErr)
		}
		result = append(result, GlobalCellId3(val))
		offset += n
	}
	return result, nil
}

// MarshalBEROMEUTRANCGIList encodes a OMEUTRANCGIList list to BER.
func MarshalBEROMEUTRANCGIList(list OMEUTRANCGIList) ([]byte, error) {
	var children []byte
	for _, elem := range list {
		children = append(children, ber.EncodeOctetString([]byte(elem))...)
	}
	return ber.EncodeSequence(children), nil
}

// UnmarshalBEROMEUTRANCGIList decodes a OMEUTRANCGIList list from BER.
func UnmarshalBEROMEUTRANCGIList(data []byte) (OMEUTRANCGIList, error) {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return nil, fmt.Errorf("decoding OMEUTRANCGIList: %w", err)
	}
	if total != len(data) {
		return nil, &ber.DecodeError{Offset: total, TypeName: "OMEUTRANCGIList", Cause: ber.ErrExtraData}
	}
	var result OMEUTRANCGIList
	offset := 0
	for offset < len(content) {
		val, n, osErr := ber.DecodeOctetString(content[offset:])
		if osErr != nil {
			return nil, fmt.Errorf("decoding element: %w", osErr)
		}
		result = append(result, CommonDataTypesEUTRANCGI(val))
		offset += n
	}
	return result, nil
}

// MarshalBEROMRoutingAreaIdList encodes a OMRoutingAreaIdList list to BER.
func MarshalBEROMRoutingAreaIdList(list OMRoutingAreaIdList) ([]byte, error) {
	var children []byte
	for _, elem := range list {
		children = append(children, ber.EncodeOctetString([]byte(elem))...)
	}
	return ber.EncodeSequence(children), nil
}

// UnmarshalBEROMRoutingAreaIdList decodes a OMRoutingAreaIdList list from BER.
func UnmarshalBEROMRoutingAreaIdList(data []byte) (OMRoutingAreaIdList, error) {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return nil, fmt.Errorf("decoding OMRoutingAreaIdList: %w", err)
	}
	if total != len(data) {
		return nil, &ber.DecodeError{Offset: total, TypeName: "OMRoutingAreaIdList", Cause: ber.ErrExtraData}
	}
	var result OMRoutingAreaIdList
	offset := 0
	for offset < len(content) {
		val, n, osErr := ber.DecodeOctetString(content[offset:])
		if osErr != nil {
			return nil, fmt.Errorf("decoding element: %w", osErr)
		}
		result = append(result, CommonDataTypesRAIdentity(val))
		offset += n
	}
	return result, nil
}

// MarshalBEROMLocationAreaIdList encodes a OMLocationAreaIdList list to BER.
func MarshalBEROMLocationAreaIdList(list OMLocationAreaIdList) ([]byte, error) {
	var children []byte
	for _, elem := range list {
		children = append(children, ber.EncodeOctetString([]byte(elem))...)
	}
	return ber.EncodeSequence(children), nil
}

// UnmarshalBEROMLocationAreaIdList decodes a OMLocationAreaIdList list from BER.
func UnmarshalBEROMLocationAreaIdList(data []byte) (OMLocationAreaIdList, error) {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return nil, fmt.Errorf("decoding OMLocationAreaIdList: %w", err)
	}
	if total != len(data) {
		return nil, &ber.DecodeError{Offset: total, TypeName: "OMLocationAreaIdList", Cause: ber.ErrExtraData}
	}
	var result OMLocationAreaIdList
	offset := 0
	for offset < len(content) {
		val, n, osErr := ber.DecodeOctetString(content[offset:])
		if osErr != nil {
			return nil, fmt.Errorf("decoding element: %w", osErr)
		}
		result = append(result, LAIFixedLength3(val))
		offset += n
	}
	return result, nil
}

// MarshalBEROMTrackingAreaIdList encodes a OMTrackingAreaIdList list to BER.
func MarshalBEROMTrackingAreaIdList(list OMTrackingAreaIdList) ([]byte, error) {
	var children []byte
	for _, elem := range list {
		children = append(children, ber.EncodeOctetString([]byte(elem))...)
	}
	return ber.EncodeSequence(children), nil
}

// UnmarshalBEROMTrackingAreaIdList decodes a OMTrackingAreaIdList list from BER.
func UnmarshalBEROMTrackingAreaIdList(data []byte) (OMTrackingAreaIdList, error) {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return nil, fmt.Errorf("decoding OMTrackingAreaIdList: %w", err)
	}
	if total != len(data) {
		return nil, &ber.DecodeError{Offset: total, TypeName: "OMTrackingAreaIdList", Cause: ber.ErrExtraData}
	}
	var result OMTrackingAreaIdList
	offset := 0
	for offset < len(content) {
		val, n, osErr := ber.DecodeOctetString(content[offset:])
		if osErr != nil {
			return nil, fmt.Errorf("decoding element: %w", osErr)
		}
		result = append(result, CommonDataTypesTAId(val))
		offset += n
	}
	return result, nil
}

// MarshalBER encodes TraceDepthList3 to BER format.
func (v *TraceDepthList3) MarshalBER() ([]byte, error) {
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
	if v.MscSTraceDepthExtension != nil {
		enc_mscstracedepthextension := ber.EncodeEnumerated(int64(*v.MscSTraceDepthExtension))
		enc_mscstracedepthextension = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 10, false, enc_mscstracedepthextension)
		children = append(children, enc_mscstracedepthextension...)
	}
	if v.MgwTraceDepthExtension != nil {
		enc_mgwtracedepthextension := ber.EncodeEnumerated(int64(*v.MgwTraceDepthExtension))
		enc_mgwtracedepthextension = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 11, false, enc_mgwtracedepthextension)
		children = append(children, enc_mgwtracedepthextension...)
	}
	if v.SgsnTraceDepthExtension != nil {
		enc_sgsntracedepthextension := ber.EncodeEnumerated(int64(*v.SgsnTraceDepthExtension))
		enc_sgsntracedepthextension = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 12, false, enc_sgsntracedepthextension)
		children = append(children, enc_sgsntracedepthextension...)
	}
	if v.GgsnTraceDepthExtension != nil {
		enc_ggsntracedepthextension := ber.EncodeEnumerated(int64(*v.GgsnTraceDepthExtension))
		enc_ggsntracedepthextension = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 13, false, enc_ggsntracedepthextension)
		children = append(children, enc_ggsntracedepthextension...)
	}
	if v.RncTraceDepthExtension != nil {
		enc_rnctracedepthextension := ber.EncodeEnumerated(int64(*v.RncTraceDepthExtension))
		enc_rnctracedepthextension = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 14, false, enc_rnctracedepthextension)
		children = append(children, enc_rnctracedepthextension...)
	}
	if v.BmscTraceDepthExtension != nil {
		enc_bmsctracedepthextension := ber.EncodeEnumerated(int64(*v.BmscTraceDepthExtension))
		enc_bmsctracedepthextension = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 15, false, enc_bmsctracedepthextension)
		children = append(children, enc_bmsctracedepthextension...)
	}
	if v.MmeTraceDepthExtension != nil {
		enc_mmetracedepthextension := ber.EncodeEnumerated(int64(*v.MmeTraceDepthExtension))
		enc_mmetracedepthextension = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 16, false, enc_mmetracedepthextension)
		children = append(children, enc_mmetracedepthextension...)
	}
	if v.SgwTraceDepthExtension != nil {
		enc_sgwtracedepthextension := ber.EncodeEnumerated(int64(*v.SgwTraceDepthExtension))
		enc_sgwtracedepthextension = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 17, false, enc_sgwtracedepthextension)
		children = append(children, enc_sgwtracedepthextension...)
	}
	if v.PgwTraceDepthExtension != nil {
		enc_pgwtracedepthextension := ber.EncodeEnumerated(int64(*v.PgwTraceDepthExtension))
		enc_pgwtracedepthextension = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 18, false, enc_pgwtracedepthextension)
		children = append(children, enc_pgwtracedepthextension...)
	}
	if v.ENBTraceDepthExtension != nil {
		enc_enbtracedepthextension := ber.EncodeEnumerated(int64(*v.ENBTraceDepthExtension))
		enc_enbtracedepthextension = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 19, false, enc_enbtracedepthextension)
		children = append(children, enc_enbtracedepthextension...)
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

// MarshalDER encodes TraceDepthList3 to DER format.
func (v *TraceDepthList3) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes TraceDepthList3 from BER/DER format.
func (v *TraceDepthList3) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding TraceDepthList3 SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "TraceDepthList3", Cause: ber.ErrExtraData}
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
				tmp_mscstracedepth := TraceDepth3(decVal_mscstracedepth)
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
				tmp_mgwtracedepth := TraceDepth3(decVal_mgwtracedepth)
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
				tmp_sgsntracedepth := TraceDepth3(decVal_sgsntracedepth)
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
				tmp_ggsntracedepth := TraceDepth3(decVal_ggsntracedepth)
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
				tmp_rnctracedepth := TraceDepth3(decVal_rnctracedepth)
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
				tmp_bmsctracedepth := TraceDepth3(decVal_bmsctracedepth)
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
				tmp_mmetracedepth := TraceDepth3(decVal_mmetracedepth)
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
				tmp_sgwtracedepth := TraceDepth3(decVal_sgwtracedepth)
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
				tmp_pgwtracedepth := TraceDepth3(decVal_pgwtracedepth)
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
				tmp_enbtracedepth := TraceDepth3(decVal_enbtracedepth)
				v.ENBTraceDepth = &tmp_enbtracedepth
				offset += n_enbtracedepth
			}
		}
	}
	// Decode msc-s-TraceDepthExtension
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 10 {
				_, n_mscstracedepthextension, rawVal_mscstracedepthextension, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding msc-s-TraceDepthExtension: %w", err)
				}
				decVal_mscstracedepthextension, intErr := ber.DecodeIntegerValue(rawVal_mscstracedepthextension)
				if intErr != nil {
					return fmt.Errorf("decoding msc-s-TraceDepthExtension: %w", intErr)
				}
				tmp_mscstracedepthextension := OMTraceDepthExtension(decVal_mscstracedepthextension)
				v.MscSTraceDepthExtension = &tmp_mscstracedepthextension
				offset += n_mscstracedepthextension
			}
		}
	}
	// Decode mgw-TraceDepthExtension
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 11 {
				_, n_mgwtracedepthextension, rawVal_mgwtracedepthextension, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding mgw-TraceDepthExtension: %w", err)
				}
				decVal_mgwtracedepthextension, intErr := ber.DecodeIntegerValue(rawVal_mgwtracedepthextension)
				if intErr != nil {
					return fmt.Errorf("decoding mgw-TraceDepthExtension: %w", intErr)
				}
				tmp_mgwtracedepthextension := OMTraceDepthExtension(decVal_mgwtracedepthextension)
				v.MgwTraceDepthExtension = &tmp_mgwtracedepthextension
				offset += n_mgwtracedepthextension
			}
		}
	}
	// Decode sgsn-TraceDepthExtension
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 12 {
				_, n_sgsntracedepthextension, rawVal_sgsntracedepthextension, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding sgsn-TraceDepthExtension: %w", err)
				}
				decVal_sgsntracedepthextension, intErr := ber.DecodeIntegerValue(rawVal_sgsntracedepthextension)
				if intErr != nil {
					return fmt.Errorf("decoding sgsn-TraceDepthExtension: %w", intErr)
				}
				tmp_sgsntracedepthextension := OMTraceDepthExtension(decVal_sgsntracedepthextension)
				v.SgsnTraceDepthExtension = &tmp_sgsntracedepthextension
				offset += n_sgsntracedepthextension
			}
		}
	}
	// Decode ggsn-TraceDepthExtension
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 13 {
				_, n_ggsntracedepthextension, rawVal_ggsntracedepthextension, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding ggsn-TraceDepthExtension: %w", err)
				}
				decVal_ggsntracedepthextension, intErr := ber.DecodeIntegerValue(rawVal_ggsntracedepthextension)
				if intErr != nil {
					return fmt.Errorf("decoding ggsn-TraceDepthExtension: %w", intErr)
				}
				tmp_ggsntracedepthextension := OMTraceDepthExtension(decVal_ggsntracedepthextension)
				v.GgsnTraceDepthExtension = &tmp_ggsntracedepthextension
				offset += n_ggsntracedepthextension
			}
		}
	}
	// Decode rnc-TraceDepthExtension
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 14 {
				_, n_rnctracedepthextension, rawVal_rnctracedepthextension, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding rnc-TraceDepthExtension: %w", err)
				}
				decVal_rnctracedepthextension, intErr := ber.DecodeIntegerValue(rawVal_rnctracedepthextension)
				if intErr != nil {
					return fmt.Errorf("decoding rnc-TraceDepthExtension: %w", intErr)
				}
				tmp_rnctracedepthextension := OMTraceDepthExtension(decVal_rnctracedepthextension)
				v.RncTraceDepthExtension = &tmp_rnctracedepthextension
				offset += n_rnctracedepthextension
			}
		}
	}
	// Decode bmsc-TraceDepthExtension
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 15 {
				_, n_bmsctracedepthextension, rawVal_bmsctracedepthextension, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding bmsc-TraceDepthExtension: %w", err)
				}
				decVal_bmsctracedepthextension, intErr := ber.DecodeIntegerValue(rawVal_bmsctracedepthextension)
				if intErr != nil {
					return fmt.Errorf("decoding bmsc-TraceDepthExtension: %w", intErr)
				}
				tmp_bmsctracedepthextension := OMTraceDepthExtension(decVal_bmsctracedepthextension)
				v.BmscTraceDepthExtension = &tmp_bmsctracedepthextension
				offset += n_bmsctracedepthextension
			}
		}
	}
	// Decode mme-TraceDepthExtension
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 16 {
				_, n_mmetracedepthextension, rawVal_mmetracedepthextension, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding mme-TraceDepthExtension: %w", err)
				}
				decVal_mmetracedepthextension, intErr := ber.DecodeIntegerValue(rawVal_mmetracedepthextension)
				if intErr != nil {
					return fmt.Errorf("decoding mme-TraceDepthExtension: %w", intErr)
				}
				tmp_mmetracedepthextension := OMTraceDepthExtension(decVal_mmetracedepthextension)
				v.MmeTraceDepthExtension = &tmp_mmetracedepthextension
				offset += n_mmetracedepthextension
			}
		}
	}
	// Decode sgw-TraceDepthExtension
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 17 {
				_, n_sgwtracedepthextension, rawVal_sgwtracedepthextension, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding sgw-TraceDepthExtension: %w", err)
				}
				decVal_sgwtracedepthextension, intErr := ber.DecodeIntegerValue(rawVal_sgwtracedepthextension)
				if intErr != nil {
					return fmt.Errorf("decoding sgw-TraceDepthExtension: %w", intErr)
				}
				tmp_sgwtracedepthextension := OMTraceDepthExtension(decVal_sgwtracedepthextension)
				v.SgwTraceDepthExtension = &tmp_sgwtracedepthextension
				offset += n_sgwtracedepthextension
			}
		}
	}
	// Decode pgw-TraceDepthExtension
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 18 {
				_, n_pgwtracedepthextension, rawVal_pgwtracedepthextension, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding pgw-TraceDepthExtension: %w", err)
				}
				decVal_pgwtracedepthextension, intErr := ber.DecodeIntegerValue(rawVal_pgwtracedepthextension)
				if intErr != nil {
					return fmt.Errorf("decoding pgw-TraceDepthExtension: %w", intErr)
				}
				tmp_pgwtracedepthextension := OMTraceDepthExtension(decVal_pgwtracedepthextension)
				v.PgwTraceDepthExtension = &tmp_pgwtracedepthextension
				offset += n_pgwtracedepthextension
			}
		}
	}
	// Decode eNB-TraceDepthExtension
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 19 {
				_, n_enbtracedepthextension, rawVal_enbtracedepthextension, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding eNB-TraceDepthExtension: %w", err)
				}
				decVal_enbtracedepthextension, intErr := ber.DecodeIntegerValue(rawVal_enbtracedepthextension)
				if intErr != nil {
					return fmt.Errorf("decoding eNB-TraceDepthExtension: %w", intErr)
				}
				tmp_enbtracedepthextension := OMTraceDepthExtension(decVal_enbtracedepthextension)
				v.ENBTraceDepthExtension = &tmp_enbtracedepthextension
				offset += n_enbtracedepthextension
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "TraceDepthList3", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes TraceInterfaceList3 to BER format.
func (v *TraceInterfaceList3) MarshalBER() ([]byte, error) {
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

// MarshalDER encodes TraceInterfaceList3 to DER format.
func (v *TraceInterfaceList3) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes TraceInterfaceList3 from BER/DER format.
func (v *TraceInterfaceList3) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding TraceInterfaceList3 SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "TraceInterfaceList3", Cause: ber.ErrExtraData}
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
			return &ber.DecodeError{Offset: offset, TypeName: "TraceInterfaceList3", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes TraceEventList3 to BER format.
func (v *TraceEventList3) MarshalBER() ([]byte, error) {
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

// MarshalDER encodes TraceEventList3 to DER format.
func (v *TraceEventList3) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes TraceEventList3 from BER/DER format.
func (v *TraceEventList3) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding TraceEventList3 SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "TraceEventList3", Cause: ber.ErrExtraData}
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
			return &ber.DecodeError{Offset: offset, TypeName: "TraceEventList3", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes TracePropagationList3 to BER format.
func (v *TracePropagationList3) MarshalBER() ([]byte, error) {
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
	if v.RncTraceDepthExtension != nil {
		enc_rnctracedepthextension := ber.EncodeEnumerated(int64(*v.RncTraceDepthExtension))
		enc_rnctracedepthextension = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 12, false, enc_rnctracedepthextension)
		children = append(children, enc_rnctracedepthextension...)
	}
	if v.MscSTraceDepthExtension != nil {
		enc_mscstracedepthextension := ber.EncodeEnumerated(int64(*v.MscSTraceDepthExtension))
		enc_mscstracedepthextension = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 13, false, enc_mscstracedepthextension)
		children = append(children, enc_mscstracedepthextension...)
	}
	if v.MgwTraceDepthExtension != nil {
		enc_mgwtracedepthextension := ber.EncodeEnumerated(int64(*v.MgwTraceDepthExtension))
		enc_mgwtracedepthextension = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 14, false, enc_mgwtracedepthextension)
		children = append(children, enc_mgwtracedepthextension...)
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

// MarshalDER encodes TracePropagationList3 to DER format.
func (v *TracePropagationList3) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes TracePropagationList3 from BER/DER format.
func (v *TracePropagationList3) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding TracePropagationList3 SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "TracePropagationList3", Cause: ber.ErrExtraData}
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
				tmp_tracereference := TraceReference3(rawVal_tracereference)
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
				tmp_tracetype := TraceType3(decVal_tracetype)
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
				tmp_tracereference2 := TraceReference23(rawVal_tracereference2)
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
				tmp_tracerecordingsessionreference := TraceRecordingSessionReference3(rawVal_tracerecordingsessionreference)
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
				tmp_rnctracedepth := TraceDepth3(decVal_rnctracedepth)
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
				tmp_mscstracedepth := TraceDepth3(decVal_mscstracedepth)
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
				tmp_mgwtracedepth := TraceDepth3(decVal_mgwtracedepth)
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
	// Decode rnc-TraceDepthExtension
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 12 {
				_, n_rnctracedepthextension, rawVal_rnctracedepthextension, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding rnc-TraceDepthExtension: %w", err)
				}
				decVal_rnctracedepthextension, intErr := ber.DecodeIntegerValue(rawVal_rnctracedepthextension)
				if intErr != nil {
					return fmt.Errorf("decoding rnc-TraceDepthExtension: %w", intErr)
				}
				tmp_rnctracedepthextension := OMTraceDepthExtension(decVal_rnctracedepthextension)
				v.RncTraceDepthExtension = &tmp_rnctracedepthextension
				offset += n_rnctracedepthextension
			}
		}
	}
	// Decode msc-s-TraceDepthExtension
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 13 {
				_, n_mscstracedepthextension, rawVal_mscstracedepthextension, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding msc-s-TraceDepthExtension: %w", err)
				}
				decVal_mscstracedepthextension, intErr := ber.DecodeIntegerValue(rawVal_mscstracedepthextension)
				if intErr != nil {
					return fmt.Errorf("decoding msc-s-TraceDepthExtension: %w", intErr)
				}
				tmp_mscstracedepthextension := OMTraceDepthExtension(decVal_mscstracedepthextension)
				v.MscSTraceDepthExtension = &tmp_mscstracedepthextension
				offset += n_mscstracedepthextension
			}
		}
	}
	// Decode mgw-TraceDepthExtension
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 14 {
				_, n_mgwtracedepthextension, rawVal_mgwtracedepthextension, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding mgw-TraceDepthExtension: %w", err)
				}
				decVal_mgwtracedepthextension, intErr := ber.DecodeIntegerValue(rawVal_mgwtracedepthextension)
				if intErr != nil {
					return fmt.Errorf("decoding mgw-TraceDepthExtension: %w", intErr)
				}
				tmp_mgwtracedepthextension := OMTraceDepthExtension(decVal_mgwtracedepthextension)
				v.MgwTraceDepthExtension = &tmp_mgwtracedepthextension
				offset += n_mgwtracedepthextension
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "TracePropagationList3", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes ActivateTraceModeRes3 to BER format.
func (v *ActivateTraceModeRes3) MarshalBER() ([]byte, error) {
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

// MarshalDER encodes ActivateTraceModeRes3 to DER format.
func (v *ActivateTraceModeRes3) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes ActivateTraceModeRes3 from BER/DER format.
func (v *ActivateTraceModeRes3) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding ActivateTraceModeRes3 SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "ActivateTraceModeRes3", Cause: ber.ErrExtraData}
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
				var dec_extensioncontainer ExtensionContainer3
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
			return &ber.DecodeError{Offset: offset, TypeName: "ActivateTraceModeRes3", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes DeactivateTraceModeArg3 to BER format.
func (v *DeactivateTraceModeArg3) MarshalBER() ([]byte, error) {
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

// MarshalDER encodes DeactivateTraceModeArg3 to DER format.
func (v *DeactivateTraceModeArg3) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes DeactivateTraceModeArg3 from BER/DER format.
func (v *DeactivateTraceModeArg3) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding DeactivateTraceModeArg3 SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "DeactivateTraceModeArg3", Cause: ber.ErrExtraData}
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
				tmp_imsi := IMSI3(rawVal_imsi)
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
	v.TraceReference = TraceReference3(rawVal_tracereference)
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
				var dec_extensioncontainer ExtensionContainer3
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
				tmp_tracereference2 := TraceReference23(rawVal_tracereference2)
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
			return &ber.DecodeError{Offset: offset, TypeName: "DeactivateTraceModeArg3", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes DeactivateTraceModeRes3 to BER format.
func (v *DeactivateTraceModeRes3) MarshalBER() ([]byte, error) {
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

// MarshalDER encodes DeactivateTraceModeRes3 to DER format.
func (v *DeactivateTraceModeRes3) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes DeactivateTraceModeRes3 from BER/DER format.
func (v *DeactivateTraceModeRes3) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding DeactivateTraceModeRes3 SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "DeactivateTraceModeRes3", Cause: ber.ErrExtraData}
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
				var dec_extensioncontainer ExtensionContainer3
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
			return &ber.DecodeError{Offset: offset, TypeName: "DeactivateTraceModeRes3", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}
