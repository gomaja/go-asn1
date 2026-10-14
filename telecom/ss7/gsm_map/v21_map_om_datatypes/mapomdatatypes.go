// Code generated from ASN.1 module "MAP-OM-DataTypes". DO NOT EDIT.

package v21_map_om_datatypes

import (
	"fmt"

	"github.com/gomaja/go-asn1/runtime"
	"github.com/gomaja/go-asn1/runtime/ber"
	"github.com/gomaja/go-asn1/runtime/tag"
	"github.com/gomaja/go-asn1/telecom/ss7/gsm_map/v21_map_commondatatypes"
	"github.com/gomaja/go-asn1/telecom/ss7/gsm_map/v21_map_extensiondatatypes"
)

// Ensure imports are used.
var (
	_ runtime.BitString
	_ = ber.EncodeTLV
	_ = tag.ClassUniversal
)

// OMActivateTraceModeArg represents the ASN.1 type ActivateTraceModeArg (SEQUENCE).
type OMActivateTraceModeArg struct {
	Imsi                  *v21_map_commondatatypes.CommonDataTypesIMSI                     `asn1:"tag:0,context,implicit,optional" json:"Imsi,omitempty"`
	TraceReference        OMTraceReference                                                 `asn1:"tag:1,context,implicit"`
	TraceType             OMTraceType                                                      `asn1:"tag:2,context,implicit"`
	OmcId                 *v21_map_commondatatypes.CommonDataTypesAddressString            `asn1:"tag:3,context,implicit,optional" json:"OmcId,omitempty"`
	ExtensionContainer    *v21_map_extensiondatatypes.ExtensionDataTypesExtensionContainer `asn1:"tag:4,context,implicit,optional" json:"ExtensionContainer,omitempty"`
	TraceReference2       *OMTraceReference2                                               `asn1:"tag:5,context,implicit,optional" json:"TraceReference2,omitempty"`
	TraceDepthList        *OMTraceDepthList                                                `asn1:"tag:6,context,implicit,optional" json:"TraceDepthList,omitempty"`
	TraceNETypeList       *OMTraceNETypeList                                               `asn1:"tag:7,context,implicit,optional" json:"TraceNETypeList,omitempty"`
	TraceInterfaceList    *OMTraceInterfaceList                                            `asn1:"tag:8,context,implicit,optional" json:"TraceInterfaceList,omitempty"`
	TraceEventList        *OMTraceEventList                                                `asn1:"tag:9,context,implicit,optional" json:"TraceEventList,omitempty"`
	TraceCollectionEntity *v21_map_commondatatypes.CommonDataTypesGSNAddress               `asn1:"tag:10,context,implicit,optional" json:"TraceCollectionEntity,omitempty"`
	MdtConfiguration      *OMMDTConfiguration                                              `asn1:"tag:11,context,implicit,optional" json:"MdtConfiguration,omitempty"`
	ExtCount_             int64                                                            `asn1:"-" json:"-"`
	ExtPresent_           []bool                                                           `asn1:"-" json:"-"`
	ExtData_              [][]byte                                                         `asn1:"-" json:"-"`
	berOriginal_          []byte                                                           `asn1:"-" json:"-"`
	berSnapshot_          []byte                                                           `asn1:"-" json:"-"`
}

// OMMDTConfiguration represents the ASN.1 type MDT-Configuration (SEQUENCE).
type OMMDTConfiguration struct {
	JobType                  OMJobType                                                        `asn1:""`
	AreaScope                *OMAreaScope                                                     `asn1:",optional" json:"AreaScope,omitempty"`
	ListOfMeasurements       *OMListOfMeasurements                                            `asn1:",optional" json:"ListOfMeasurements,omitempty"`
	ReportingTrigger         *OMReportingTrigger                                              `asn1:"tag:0,context,implicit,optional" json:"ReportingTrigger,omitempty"`
	ReportInterval           *OMReportInterval                                                `asn1:",optional" json:"ReportInterval,omitempty"`
	ReportAmount             *OMReportAmount                                                  `asn1:"tag:1,context,implicit,optional" json:"ReportAmount,omitempty"`
	EventThresholdRSRP       *OMEventThresholdRSRP                                            `asn1:",optional" json:"EventThresholdRSRP,omitempty"`
	EventThresholdRSRQ       *OMEventThresholdRSRQ                                            `asn1:"tag:2,context,implicit,optional" json:"EventThresholdRSRQ,omitempty"`
	LoggingInterval          *OMLoggingInterval                                               `asn1:"tag:3,context,implicit,optional" json:"LoggingInterval,omitempty"`
	LoggingDuration          *OMLoggingDuration                                               `asn1:"tag:4,context,implicit,optional" json:"LoggingDuration,omitempty"`
	ExtensionContainer       *v21_map_extensiondatatypes.ExtensionDataTypesExtensionContainer `asn1:"tag:5,context,implicit,optional" json:"ExtensionContainer,omitempty"`
	MeasurementPeriodUMTS    *OMPeriodUMTS                                                    `asn1:"tag:6,context,implicit,optional" json:"MeasurementPeriodUMTS,omitempty"`
	MeasurementPeriodLTE     *OMPeriodLTE                                                     `asn1:"tag:7,context,implicit,optional" json:"MeasurementPeriodLTE,omitempty"`
	CollectionPeriodRRMUMTS  *OMPeriodUMTS                                                    `asn1:"tag:8,context,implicit,optional" json:"CollectionPeriodRRMUMTS,omitempty"`
	CollectionPeriodRRMLTE   *OMPeriodLTE                                                     `asn1:"tag:9,context,implicit,optional" json:"CollectionPeriodRRMLTE,omitempty"`
	PositioningMethod        *OMPositioningMethod                                             `asn1:"tag:10,context,implicit,optional" json:"PositioningMethod,omitempty"`
	MeasurementQuantity      *OMMeasurementQuantity                                           `asn1:"tag:11,context,implicit,optional" json:"MeasurementQuantity,omitempty"`
	EventThreshold1F         *OMEventThreshold1F                                              `asn1:"tag:12,context,implicit,optional" json:"EventThreshold1F,omitempty"`
	EventThreshold1I         *OMEventThreshold1I                                              `asn1:"tag:13,context,implicit,optional" json:"EventThreshold1I,omitempty"`
	MdtAllowedPLMNList       *OMMDTAllowedPLMNIdList                                          `asn1:"tag:14,context,implicit,optional" json:"MdtAllowedPLMNList,omitempty"`
	MdtAllowedPLMNListIndef_ bool                                                             `asn1:"-" json:"-"`
	ExtCount_                int64                                                            `asn1:"-" json:"-"`
	ExtPresent_              []bool                                                           `asn1:"-" json:"-"`
	ExtData_                 [][]byte                                                         `asn1:"-" json:"-"`
	berOriginal_             []byte                                                           `asn1:"-" json:"-"`
	berSnapshot_             []byte                                                           `asn1:"-" json:"-"`
}

// OMMDTAllowedPLMNIdList represents the ASN.1 type MDT-Allowed-PLMNId-List (SEQUENCE_OF).
type OMMDTAllowedPLMNIdList struct {
	Values       []v21_map_commondatatypes.CommonDataTypesPLMNId `json:"Values"`
	berOriginal_ []byte                                          `json:"-"`
	berSnapshot_ []byte                                          `json:"-"`
}

// OMPeriodUMTS represents the ASN.1 ENUMERATED type PeriodUMTS.
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

// OMPeriodLTE represents the ASN.1 ENUMERATED type PeriodLTE.
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

// OMPositioningMethod represents the ASN.1 type PositioningMethod (OCTET_STRING).
type OMPositioningMethod = []byte

// OMMeasurementQuantity represents the ASN.1 type MeasurementQuantity (OCTET_STRING).
type OMMeasurementQuantity = []byte

// OMEventThreshold1F represents the ASN.1 type EventThreshold1F (INTEGER).
type OMEventThreshold1F = int64

// OMEventThreshold1I represents the ASN.1 type EventThreshold1I (INTEGER).
type OMEventThreshold1I = int64

// OMJobType represents the ASN.1 ENUMERATED type JobType.
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

// OMAreaScope represents the ASN.1 type AreaScope (SEQUENCE).
type OMAreaScope struct {
	CgiList                  *OMCGIList                                                       `asn1:"tag:0,context,implicit,optional" json:"CgiList,omitempty"`
	CgiListIndef_            bool                                                             `asn1:"-" json:"-"`
	EUtranCgiList            *OMEUTRANCGIList                                                 `asn1:"tag:1,context,implicit,optional" json:"EUtranCgiList,omitempty"`
	EUtranCgiListIndef_      bool                                                             `asn1:"-" json:"-"`
	RoutingAreaIdList        *OMRoutingAreaIdList                                             `asn1:"tag:2,context,implicit,optional" json:"RoutingAreaIdList,omitempty"`
	RoutingAreaIdListIndef_  bool                                                             `asn1:"-" json:"-"`
	LocationAreaIdList       *OMLocationAreaIdList                                            `asn1:"tag:3,context,implicit,optional" json:"LocationAreaIdList,omitempty"`
	LocationAreaIdListIndef_ bool                                                             `asn1:"-" json:"-"`
	TrackingAreaIdList       *OMTrackingAreaIdList                                            `asn1:"tag:4,context,implicit,optional" json:"TrackingAreaIdList,omitempty"`
	TrackingAreaIdListIndef_ bool                                                             `asn1:"-" json:"-"`
	ExtensionContainer       *v21_map_extensiondatatypes.ExtensionDataTypesExtensionContainer `asn1:"tag:5,context,implicit,optional" json:"ExtensionContainer,omitempty"`
	ExtCount_                int64                                                            `asn1:"-" json:"-"`
	ExtPresent_              []bool                                                           `asn1:"-" json:"-"`
	ExtData_                 [][]byte                                                         `asn1:"-" json:"-"`
	berOriginal_             []byte                                                           `asn1:"-" json:"-"`
	berSnapshot_             []byte                                                           `asn1:"-" json:"-"`
}

// OMCGIList represents the ASN.1 type CGI-List (SEQUENCE_OF).
type OMCGIList struct {
	Values       []v21_map_commondatatypes.CommonDataTypesGlobalCellId `json:"Values"`
	berOriginal_ []byte                                                `json:"-"`
	berSnapshot_ []byte                                                `json:"-"`
}

// OMEUTRANCGIList represents the ASN.1 type E-UTRAN-CGI-List (SEQUENCE_OF).
type OMEUTRANCGIList struct {
	Values       []v21_map_commondatatypes.CommonDataTypesEUTRANCGI `json:"Values"`
	berOriginal_ []byte                                             `json:"-"`
	berSnapshot_ []byte                                             `json:"-"`
}

// OMRoutingAreaIdList represents the ASN.1 type RoutingAreaId-List (SEQUENCE_OF).
type OMRoutingAreaIdList struct {
	Values       []v21_map_commondatatypes.CommonDataTypesRAIdentity `json:"Values"`
	berOriginal_ []byte                                              `json:"-"`
	berSnapshot_ []byte                                              `json:"-"`
}

// OMLocationAreaIdList represents the ASN.1 type LocationAreaId-List (SEQUENCE_OF).
type OMLocationAreaIdList struct {
	Values       []v21_map_commondatatypes.CommonDataTypesLAIFixedLength `json:"Values"`
	berOriginal_ []byte                                                  `json:"-"`
	berSnapshot_ []byte                                                  `json:"-"`
}

// OMTrackingAreaIdList represents the ASN.1 type TrackingAreaId-List (SEQUENCE_OF).
type OMTrackingAreaIdList struct {
	Values       []v21_map_commondatatypes.CommonDataTypesTAId `json:"Values"`
	berOriginal_ []byte                                        `json:"-"`
	berSnapshot_ []byte                                        `json:"-"`
}

// OMListOfMeasurements represents the ASN.1 type ListOfMeasurements (OCTET_STRING).
type OMListOfMeasurements = []byte

// OMReportingTrigger represents the ASN.1 type ReportingTrigger (OCTET_STRING).
type OMReportingTrigger = []byte

// OMReportInterval represents the ASN.1 ENUMERATED type ReportInterval.
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

// OMReportAmount represents the ASN.1 ENUMERATED type ReportAmount.
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

// OMEventThresholdRSRP represents the ASN.1 type EventThresholdRSRP (INTEGER).
type OMEventThresholdRSRP = int64

// OMEventThresholdRSRQ represents the ASN.1 type EventThresholdRSRQ (INTEGER).
type OMEventThresholdRSRQ = int64

// OMLoggingInterval represents the ASN.1 ENUMERATED type LoggingInterval.
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

// OMLoggingDuration represents the ASN.1 ENUMERATED type LoggingDuration.
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

// OMTraceReference represents the ASN.1 type TraceReference (OCTET_STRING).
type OMTraceReference = []byte

// OMTraceReference2 represents the ASN.1 type TraceReference2 (OCTET_STRING).
type OMTraceReference2 = []byte

// OMTraceRecordingSessionReference represents the ASN.1 type TraceRecordingSessionReference (OCTET_STRING).
type OMTraceRecordingSessionReference = []byte

// OMTraceType represents the ASN.1 type TraceType (INTEGER).
type OMTraceType = int64

// OMTraceDepthList represents the ASN.1 type TraceDepthList (SEQUENCE).
type OMTraceDepthList struct {
	MscSTraceDepth          *OMTraceDepth          `asn1:"tag:0,context,implicit,optional" json:"MscSTraceDepth,omitempty"`
	MgwTraceDepth           *OMTraceDepth          `asn1:"tag:1,context,implicit,optional" json:"MgwTraceDepth,omitempty"`
	SgsnTraceDepth          *OMTraceDepth          `asn1:"tag:2,context,implicit,optional" json:"SgsnTraceDepth,omitempty"`
	GgsnTraceDepth          *OMTraceDepth          `asn1:"tag:3,context,implicit,optional" json:"GgsnTraceDepth,omitempty"`
	RncTraceDepth           *OMTraceDepth          `asn1:"tag:4,context,implicit,optional" json:"RncTraceDepth,omitempty"`
	BmscTraceDepth          *OMTraceDepth          `asn1:"tag:5,context,implicit,optional" json:"BmscTraceDepth,omitempty"`
	MmeTraceDepth           *OMTraceDepth          `asn1:"tag:6,context,implicit,optional" json:"MmeTraceDepth,omitempty"`
	SgwTraceDepth           *OMTraceDepth          `asn1:"tag:7,context,implicit,optional" json:"SgwTraceDepth,omitempty"`
	PgwTraceDepth           *OMTraceDepth          `asn1:"tag:8,context,implicit,optional" json:"PgwTraceDepth,omitempty"`
	ENBTraceDepth           *OMTraceDepth          `asn1:"tag:9,context,implicit,optional" json:"ENBTraceDepth,omitempty"`
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
	berOriginal_            []byte                 `asn1:"-" json:"-"`
	berSnapshot_            []byte                 `asn1:"-" json:"-"`
}

// OMTraceDepth represents the ASN.1 ENUMERATED type TraceDepth.
type OMTraceDepth int64

const (
	OMTraceDepthMinimum OMTraceDepth = 0
	OMTraceDepthMedium  OMTraceDepth = 1
	OMTraceDepthMaximum OMTraceDepth = 2
)

func (v OMTraceDepth) String() string {
	switch v {
	case OMTraceDepthMinimum:
		return "minimum"
	case OMTraceDepthMedium:
		return "medium"
	case OMTraceDepthMaximum:
		return "maximum"
	default:
		return "unknown"
	}
}

// OMTraceDepthExtension represents the ASN.1 ENUMERATED type TraceDepthExtension.
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

// OMTraceNETypeList represents the ASN.1 type TraceNE-TypeList (BIT_STRING).
type OMTraceNETypeList = runtime.BitString

// OMTraceInterfaceList represents the ASN.1 type TraceInterfaceList (SEQUENCE).
type OMTraceInterfaceList struct {
	MscSList     *OMMSCSInterfaceList `asn1:"tag:0,context,implicit,optional" json:"MscSList,omitempty"`
	MgwList      *OMMGWInterfaceList  `asn1:"tag:1,context,implicit,optional" json:"MgwList,omitempty"`
	SgsnList     *OMSGSNInterfaceList `asn1:"tag:2,context,implicit,optional" json:"SgsnList,omitempty"`
	GgsnList     *OMGGSNInterfaceList `asn1:"tag:3,context,implicit,optional" json:"GgsnList,omitempty"`
	RncList      *OMRNCInterfaceList  `asn1:"tag:4,context,implicit,optional" json:"RncList,omitempty"`
	BmscList     *OMBMSCInterfaceList `asn1:"tag:5,context,implicit,optional" json:"BmscList,omitempty"`
	MmeList      *OMMMEInterfaceList  `asn1:"tag:6,context,implicit,optional" json:"MmeList,omitempty"`
	SgwList      *OMSGWInterfaceList  `asn1:"tag:7,context,implicit,optional" json:"SgwList,omitempty"`
	PgwList      *OMPGWInterfaceList  `asn1:"tag:8,context,implicit,optional" json:"PgwList,omitempty"`
	ENBList      *OMENBInterfaceList  `asn1:"tag:9,context,implicit,optional" json:"ENBList,omitempty"`
	ExtCount_    int64                `asn1:"-" json:"-"`
	ExtPresent_  []bool               `asn1:"-" json:"-"`
	ExtData_     [][]byte             `asn1:"-" json:"-"`
	berOriginal_ []byte               `asn1:"-" json:"-"`
	berSnapshot_ []byte               `asn1:"-" json:"-"`
}

// OMMSCSInterfaceList represents the ASN.1 type MSC-S-InterfaceList (BIT_STRING).
type OMMSCSInterfaceList = runtime.BitString

// OMMGWInterfaceList represents the ASN.1 type MGW-InterfaceList (BIT_STRING).
type OMMGWInterfaceList = runtime.BitString

// OMSGSNInterfaceList represents the ASN.1 type SGSN-InterfaceList (BIT_STRING).
type OMSGSNInterfaceList = runtime.BitString

// OMGGSNInterfaceList represents the ASN.1 type GGSN-InterfaceList (BIT_STRING).
type OMGGSNInterfaceList = runtime.BitString

// OMRNCInterfaceList represents the ASN.1 type RNC-InterfaceList (BIT_STRING).
type OMRNCInterfaceList = runtime.BitString

// OMBMSCInterfaceList represents the ASN.1 type BMSC-InterfaceList (BIT_STRING).
type OMBMSCInterfaceList = runtime.BitString

// OMMMEInterfaceList represents the ASN.1 type MME-InterfaceList (BIT_STRING).
type OMMMEInterfaceList = runtime.BitString

// OMSGWInterfaceList represents the ASN.1 type SGW-InterfaceList (BIT_STRING).
type OMSGWInterfaceList = runtime.BitString

// OMPGWInterfaceList represents the ASN.1 type PGW-InterfaceList (BIT_STRING).
type OMPGWInterfaceList = runtime.BitString

// OMENBInterfaceList represents the ASN.1 type ENB-InterfaceList (BIT_STRING).
type OMENBInterfaceList = runtime.BitString

// OMTraceEventList represents the ASN.1 type TraceEventList (SEQUENCE).
type OMTraceEventList struct {
	MscSList     *OMMSCSEventList `asn1:"tag:0,context,implicit,optional" json:"MscSList,omitempty"`
	MgwList      *OMMGWEventList  `asn1:"tag:1,context,implicit,optional" json:"MgwList,omitempty"`
	SgsnList     *OMSGSNEventList `asn1:"tag:2,context,implicit,optional" json:"SgsnList,omitempty"`
	GgsnList     *OMGGSNEventList `asn1:"tag:3,context,implicit,optional" json:"GgsnList,omitempty"`
	BmscList     *OMBMSCEventList `asn1:"tag:4,context,implicit,optional" json:"BmscList,omitempty"`
	MmeList      *OMMMEEventList  `asn1:"tag:5,context,implicit,optional" json:"MmeList,omitempty"`
	SgwList      *OMSGWEventList  `asn1:"tag:6,context,implicit,optional" json:"SgwList,omitempty"`
	PgwList      *OMPGWEventList  `asn1:"tag:7,context,implicit,optional" json:"PgwList,omitempty"`
	ExtCount_    int64            `asn1:"-" json:"-"`
	ExtPresent_  []bool           `asn1:"-" json:"-"`
	ExtData_     [][]byte         `asn1:"-" json:"-"`
	berOriginal_ []byte           `asn1:"-" json:"-"`
	berSnapshot_ []byte           `asn1:"-" json:"-"`
}

// OMMSCSEventList represents the ASN.1 type MSC-S-EventList (BIT_STRING).
type OMMSCSEventList = runtime.BitString

// OMMGWEventList represents the ASN.1 type MGW-EventList (BIT_STRING).
type OMMGWEventList = runtime.BitString

// OMSGSNEventList represents the ASN.1 type SGSN-EventList (BIT_STRING).
type OMSGSNEventList = runtime.BitString

// OMGGSNEventList represents the ASN.1 type GGSN-EventList (BIT_STRING).
type OMGGSNEventList = runtime.BitString

// OMBMSCEventList represents the ASN.1 type BMSC-EventList (BIT_STRING).
type OMBMSCEventList = runtime.BitString

// OMMMEEventList represents the ASN.1 type MME-EventList (BIT_STRING).
type OMMMEEventList = runtime.BitString

// OMSGWEventList represents the ASN.1 type SGW-EventList (BIT_STRING).
type OMSGWEventList = runtime.BitString

// OMPGWEventList represents the ASN.1 type PGW-EventList (BIT_STRING).
type OMPGWEventList = runtime.BitString

// OMTracePropagationList represents the ASN.1 type TracePropagationList (SEQUENCE).
type OMTracePropagationList struct {
	TraceReference                 *OMTraceReference                 `asn1:"tag:0,context,implicit,optional" json:"TraceReference,omitempty"`
	TraceType                      *OMTraceType                      `asn1:"tag:1,context,implicit,optional" json:"TraceType,omitempty"`
	TraceReference2                *OMTraceReference2                `asn1:"tag:2,context,implicit,optional" json:"TraceReference2,omitempty"`
	TraceRecordingSessionReference *OMTraceRecordingSessionReference `asn1:"tag:3,context,implicit,optional" json:"TraceRecordingSessionReference,omitempty"`
	RncTraceDepth                  *OMTraceDepth                     `asn1:"tag:4,context,implicit,optional" json:"RncTraceDepth,omitempty"`
	RncInterfaceList               *OMRNCInterfaceList               `asn1:"tag:5,context,implicit,optional" json:"RncInterfaceList,omitempty"`
	MscSTraceDepth                 *OMTraceDepth                     `asn1:"tag:6,context,implicit,optional" json:"MscSTraceDepth,omitempty"`
	MscSInterfaceList              *OMMSCSInterfaceList              `asn1:"tag:7,context,implicit,optional" json:"MscSInterfaceList,omitempty"`
	MscSEventList                  *OMMSCSEventList                  `asn1:"tag:8,context,implicit,optional" json:"MscSEventList,omitempty"`
	MgwTraceDepth                  *OMTraceDepth                     `asn1:"tag:9,context,implicit,optional" json:"MgwTraceDepth,omitempty"`
	MgwInterfaceList               *OMMGWInterfaceList               `asn1:"tag:10,context,implicit,optional" json:"MgwInterfaceList,omitempty"`
	MgwEventList                   *OMMGWEventList                   `asn1:"tag:11,context,implicit,optional" json:"MgwEventList,omitempty"`
	RncTraceDepthExtension         *OMTraceDepthExtension            `asn1:"tag:12,context,implicit,optional" json:"RncTraceDepthExtension,omitempty"`
	MscSTraceDepthExtension        *OMTraceDepthExtension            `asn1:"tag:13,context,implicit,optional" json:"MscSTraceDepthExtension,omitempty"`
	MgwTraceDepthExtension         *OMTraceDepthExtension            `asn1:"tag:14,context,implicit,optional" json:"MgwTraceDepthExtension,omitempty"`
	ExtCount_                      int64                             `asn1:"-" json:"-"`
	ExtPresent_                    []bool                            `asn1:"-" json:"-"`
	ExtData_                       [][]byte                          `asn1:"-" json:"-"`
	berOriginal_                   []byte                            `asn1:"-" json:"-"`
	berSnapshot_                   []byte                            `asn1:"-" json:"-"`
}

// OMActivateTraceModeRes represents the ASN.1 type ActivateTraceModeRes (SEQUENCE).
type OMActivateTraceModeRes struct {
	ExtensionContainer    *v21_map_extensiondatatypes.ExtensionDataTypesExtensionContainer `asn1:"tag:0,context,implicit,optional" json:"ExtensionContainer,omitempty"`
	TraceSupportIndicator *struct{}                                                        `asn1:"tag:1,context,implicit,optional" json:"TraceSupportIndicator,omitempty"`
	ExtCount_             int64                                                            `asn1:"-" json:"-"`
	ExtPresent_           []bool                                                           `asn1:"-" json:"-"`
	ExtData_              [][]byte                                                         `asn1:"-" json:"-"`
	berOriginal_          []byte                                                           `asn1:"-" json:"-"`
	berSnapshot_          []byte                                                           `asn1:"-" json:"-"`
}

// OMDeactivateTraceModeArg represents the ASN.1 type DeactivateTraceModeArg (SEQUENCE).
type OMDeactivateTraceModeArg struct {
	Imsi               *v21_map_commondatatypes.CommonDataTypesIMSI                     `asn1:"tag:0,context,implicit,optional" json:"Imsi,omitempty"`
	TraceReference     OMTraceReference                                                 `asn1:"tag:1,context,implicit"`
	ExtensionContainer *v21_map_extensiondatatypes.ExtensionDataTypesExtensionContainer `asn1:"tag:2,context,implicit,optional" json:"ExtensionContainer,omitempty"`
	TraceReference2    *OMTraceReference2                                               `asn1:"tag:3,context,implicit,optional" json:"TraceReference2,omitempty"`
	ExtCount_          int64                                                            `asn1:"-" json:"-"`
	ExtPresent_        []bool                                                           `asn1:"-" json:"-"`
	ExtData_           [][]byte                                                         `asn1:"-" json:"-"`
	berOriginal_       []byte                                                           `asn1:"-" json:"-"`
	berSnapshot_       []byte                                                           `asn1:"-" json:"-"`
}

// OMDeactivateTraceModeRes represents the ASN.1 type DeactivateTraceModeRes (SEQUENCE).
type OMDeactivateTraceModeRes struct {
	ExtensionContainer *v21_map_extensiondatatypes.ExtensionDataTypesExtensionContainer `asn1:"tag:0,context,implicit,optional" json:"ExtensionContainer,omitempty"`
	ExtCount_          int64                                                            `asn1:"-" json:"-"`
	ExtPresent_        []bool                                                           `asn1:"-" json:"-"`
	ExtData_           [][]byte                                                         `asn1:"-" json:"-"`
	berOriginal_       []byte                                                           `asn1:"-" json:"-"`
	berSnapshot_       []byte                                                           `asn1:"-" json:"-"`
}

// MarshalBER encodes OMActivateTraceModeArg to BER format.
func (v *OMActivateTraceModeArg) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: OMActivateTraceModeArg receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *OMActivateTraceModeArg) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
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
			return nil, qualifyBERError(encodeErr_enc_imsi, "imsi", "encoding", false)
		}
		retagged_enc_imsi, tagErr_enc_imsi := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_imsi)
		if tagErr_enc_imsi != nil {
			return nil, qualifyBERError(tagErr_enc_imsi, "imsi", "encoding", false)
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
		return nil, qualifyBERError(encodeErr_enc_tracereference, "traceReference", "encoding", false)
	}
	retagged_enc_tracereference, tagErr_enc_tracereference := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_tracereference)
	if tagErr_enc_tracereference != nil {
		return nil, qualifyBERError(tagErr_enc_tracereference, "traceReference", "encoding", false)
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
		return nil, qualifyBERError(tagErr_enc_tracetype, "traceType", "encoding", false)
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
			return nil, qualifyBERError(encodeErr_enc_omcid, "omc-Id", "encoding", false)
		}
		retagged_enc_omcid, tagErr_enc_omcid := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, enc_omcid)
		if tagErr_enc_omcid != nil {
			return nil, qualifyBERError(tagErr_enc_omcid, "omc-Id", "encoding", false)
		}
		enc_omcid = retagged_enc_omcid
		children = append(children, enc_omcid...)
	}
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalBER(ber.ChildEncodeOptions(opts, "extensionContainer")...)
		if err != nil {
			return nil, qualifyBERError(err, "extensionContainer", "encoding", false)
		}
		retagged_enc_extensioncontainer, tagErr_enc_extensioncontainer := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, enc_extensioncontainer)
		if tagErr_enc_extensioncontainer != nil {
			return nil, qualifyBERError(tagErr_enc_extensioncontainer, "extensionContainer", "encoding", false)
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
			return nil, qualifyBERError(encodeErr_enc_tracereference2, "traceReference2", "encoding", false)
		}
		retagged_enc_tracereference2, tagErr_enc_tracereference2 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 5, enc_tracereference2)
		if tagErr_enc_tracereference2 != nil {
			return nil, qualifyBERError(tagErr_enc_tracereference2, "traceReference2", "encoding", false)
		}
		enc_tracereference2 = retagged_enc_tracereference2
		children = append(children, enc_tracereference2...)
	}
	if v.TraceDepthList != nil {
		enc_tracedepthlist, err := v.TraceDepthList.MarshalBER(ber.ChildEncodeOptions(opts, "traceDepthList")...)
		if err != nil {
			return nil, qualifyBERError(err, "traceDepthList", "encoding", false)
		}
		retagged_enc_tracedepthlist, tagErr_enc_tracedepthlist := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 6, enc_tracedepthlist)
		if tagErr_enc_tracedepthlist != nil {
			return nil, qualifyBERError(tagErr_enc_tracedepthlist, "traceDepthList", "encoding", false)
		}
		enc_tracedepthlist = retagged_enc_tracedepthlist
		children = append(children, enc_tracedepthlist...)
	}
	if v.TraceNETypeList != nil {
		if bitStringErr := ber.ValidateBitStringLength(v.TraceNETypeList.Bytes, v.TraceNETypeList.BitLength); bitStringErr != nil {
			return nil, qualifyBERError(bitStringErr, "traceNE-TypeList", "encoding", false)
		}
		// arithmetic pattern BER_BITSTRING_FIELD: 0 <= bit length before modulo and subtraction; gen/codegen.go:644
		if v.TraceNETypeList.BitLength < 0 {
			return nil, fmt.Errorf("negative bit string length")
		}
		if (*v.TraceNETypeList).BitLength < 6 || (*v.TraceNETypeList).BitLength > 16 {
			if constraintErr := ber.CheckEncodedLength(opts, "traceNE-TypeList", "SIZE (6..16)", (*v.TraceNETypeList).BitLength); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_tracenetypelist, encodeErr_enc_tracenetypelist := ber.EncodeBitString(v.TraceNETypeList.Bytes, ber.UnusedBitCount(v.TraceNETypeList.BitLength))
		if encodeErr_enc_tracenetypelist != nil {
			return nil, qualifyBERError(encodeErr_enc_tracenetypelist, "traceNE-TypeList", "encoding", false)
		}
		retagged_enc_tracenetypelist, tagErr_enc_tracenetypelist := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 7, enc_tracenetypelist)
		if tagErr_enc_tracenetypelist != nil {
			return nil, qualifyBERError(tagErr_enc_tracenetypelist, "traceNE-TypeList", "encoding", false)
		}
		enc_tracenetypelist = retagged_enc_tracenetypelist
		children = append(children, enc_tracenetypelist...)
	}
	if v.TraceInterfaceList != nil {
		enc_traceinterfacelist, err := v.TraceInterfaceList.MarshalBER(ber.ChildEncodeOptions(opts, "traceInterfaceList")...)
		if err != nil {
			return nil, qualifyBERError(err, "traceInterfaceList", "encoding", false)
		}
		retagged_enc_traceinterfacelist, tagErr_enc_traceinterfacelist := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 8, enc_traceinterfacelist)
		if tagErr_enc_traceinterfacelist != nil {
			return nil, qualifyBERError(tagErr_enc_traceinterfacelist, "traceInterfaceList", "encoding", false)
		}
		enc_traceinterfacelist = retagged_enc_traceinterfacelist
		children = append(children, enc_traceinterfacelist...)
	}
	if v.TraceEventList != nil {
		enc_traceeventlist, err := v.TraceEventList.MarshalBER(ber.ChildEncodeOptions(opts, "traceEventList")...)
		if err != nil {
			return nil, qualifyBERError(err, "traceEventList", "encoding", false)
		}
		retagged_enc_traceeventlist, tagErr_enc_traceeventlist := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 9, enc_traceeventlist)
		if tagErr_enc_traceeventlist != nil {
			return nil, qualifyBERError(tagErr_enc_traceeventlist, "traceEventList", "encoding", false)
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
			return nil, qualifyBERError(encodeErr_enc_tracecollectionentity, "traceCollectionEntity", "encoding", false)
		}
		retagged_enc_tracecollectionentity, tagErr_enc_tracecollectionentity := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 10, enc_tracecollectionentity)
		if tagErr_enc_tracecollectionentity != nil {
			return nil, qualifyBERError(tagErr_enc_tracecollectionentity, "traceCollectionEntity", "encoding", false)
		}
		enc_tracecollectionentity = retagged_enc_tracecollectionentity
		children = append(children, enc_tracecollectionentity...)
	}
	if v.MdtConfiguration != nil {
		enc_mdtconfiguration, err := v.MdtConfiguration.MarshalBER(ber.ChildEncodeOptions(opts, "mdt-Configuration")...)
		if err != nil {
			return nil, qualifyBERError(err, "mdt-Configuration", "encoding", false)
		}
		retagged_enc_mdtconfiguration, tagErr_enc_mdtconfiguration := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 11, enc_mdtconfiguration)
		if tagErr_enc_mdtconfiguration != nil {
			return nil, qualifyBERError(tagErr_enc_mdtconfiguration, "mdt-Configuration", "encoding", false)
		}
		enc_mdtconfiguration = retagged_enc_mdtconfiguration
		children = append(children, enc_mdtconfiguration...)
	}
	for i, ext := range v.ExtData_ {
		if err := ber.CheckBEROpaqueReplay(opts...); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
		peekTag, n, _, extErr := ber.DecodeEncodedTLV(ext)
		if extErr != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, extErr)
		}
		if n != len(ext) {
			return nil, fmt.Errorf("encoding extension %d: %w", i, ber.ErrExtraData)
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: only the first addition is restricted.
		if i == 0 && ((peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 11) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 10) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 9) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 8) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 7) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 6) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 5) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3)) {
			if constraintErr := ber.CheckEncodedValue(opts, "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
				return nil, constraintErr
			}
		}
		children = append(children, ext...)
	}
	return ber.EncodeSequence(children)
}

// MarshalDER encodes OMActivateTraceModeArg to DER format.
func (v *OMActivateTraceModeArg) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: OMActivateTraceModeArg receiver is nil", ber.ErrInvalidValue)
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
			return nil, qualifyBERError(encodeErr_enc_imsi, "imsi", "encoding", true)
		}
		retagged_enc_imsi, tagErr_enc_imsi := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_imsi)
		if tagErr_enc_imsi != nil {
			return nil, qualifyBERError(tagErr_enc_imsi, "imsi", "encoding", true)
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
		return nil, qualifyBERError(encodeErr_enc_tracereference, "traceReference", "encoding", true)
	}
	retagged_enc_tracereference, tagErr_enc_tracereference := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_tracereference)
	if tagErr_enc_tracereference != nil {
		return nil, qualifyBERError(tagErr_enc_tracereference, "traceReference", "encoding", true)
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
		return nil, qualifyBERError(tagErr_enc_tracetype, "traceType", "encoding", true)
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
			return nil, qualifyBERError(encodeErr_enc_omcid, "omc-Id", "encoding", true)
		}
		retagged_enc_omcid, tagErr_enc_omcid := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, enc_omcid)
		if tagErr_enc_omcid != nil {
			return nil, qualifyBERError(tagErr_enc_omcid, "omc-Id", "encoding", true)
		}
		enc_omcid = retagged_enc_omcid
		children = append(children, enc_omcid...)
	}
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalDER()
		if err != nil {
			return nil, qualifyBERError(err, "extensionContainer", "encoding", true)
		}
		retagged_enc_extensioncontainer, tagErr_enc_extensioncontainer := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, enc_extensioncontainer)
		if tagErr_enc_extensioncontainer != nil {
			return nil, qualifyBERError(tagErr_enc_extensioncontainer, "extensionContainer", "encoding", true)
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
			return nil, qualifyBERError(encodeErr_enc_tracereference2, "traceReference2", "encoding", true)
		}
		retagged_enc_tracereference2, tagErr_enc_tracereference2 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 5, enc_tracereference2)
		if tagErr_enc_tracereference2 != nil {
			return nil, qualifyBERError(tagErr_enc_tracereference2, "traceReference2", "encoding", true)
		}
		enc_tracereference2 = retagged_enc_tracereference2
		children = append(children, enc_tracereference2...)
	}
	if v.TraceDepthList != nil {
		enc_tracedepthlist, err := v.TraceDepthList.MarshalDER()
		if err != nil {
			return nil, qualifyBERError(err, "traceDepthList", "encoding", true)
		}
		retagged_enc_tracedepthlist, tagErr_enc_tracedepthlist := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 6, enc_tracedepthlist)
		if tagErr_enc_tracedepthlist != nil {
			return nil, qualifyBERError(tagErr_enc_tracedepthlist, "traceDepthList", "encoding", true)
		}
		enc_tracedepthlist = retagged_enc_tracedepthlist
		children = append(children, enc_tracedepthlist...)
	}
	if v.TraceNETypeList != nil {
		if bitStringErr := ber.ValidateBitStringLength(v.TraceNETypeList.Bytes, v.TraceNETypeList.BitLength); bitStringErr != nil {
			return nil, qualifyBERError(bitStringErr, "traceNE-TypeList", "encoding", true)
		}
		if bitStringErr := ber.ValidateDERBitString(v.TraceNETypeList.Bytes, v.TraceNETypeList.BitLength); bitStringErr != nil {
			return nil, qualifyBERError(bitStringErr, "traceNE-TypeList", "encoding", true)
		}
		// arithmetic pattern BER_BITSTRING_FIELD: 0 <= bit length before modulo and subtraction; gen/codegen.go:644
		if v.TraceNETypeList.BitLength < 0 {
			return nil, fmt.Errorf("negative bit string length")
		}
		if (*v.TraceNETypeList).BitLength < 6 || (*v.TraceNETypeList).BitLength > 16 {
			if constraintErr := ber.CheckEncodedLength(nil, "traceNE-TypeList", "SIZE (6..16)", (*v.TraceNETypeList).BitLength); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_tracenetypelist, encodeErr_enc_tracenetypelist := ber.EncodeDERNamedBitString(v.TraceNETypeList.Bytes, v.TraceNETypeList.BitLength)
		if encodeErr_enc_tracenetypelist != nil {
			return nil, qualifyBERError(encodeErr_enc_tracenetypelist, "traceNE-TypeList", "encoding", true)
		}
		retagged_enc_tracenetypelist, tagErr_enc_tracenetypelist := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 7, enc_tracenetypelist)
		if tagErr_enc_tracenetypelist != nil {
			return nil, qualifyBERError(tagErr_enc_tracenetypelist, "traceNE-TypeList", "encoding", true)
		}
		enc_tracenetypelist = retagged_enc_tracenetypelist
		children = append(children, enc_tracenetypelist...)
	}
	if v.TraceInterfaceList != nil {
		enc_traceinterfacelist, err := v.TraceInterfaceList.MarshalDER()
		if err != nil {
			return nil, qualifyBERError(err, "traceInterfaceList", "encoding", true)
		}
		retagged_enc_traceinterfacelist, tagErr_enc_traceinterfacelist := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 8, enc_traceinterfacelist)
		if tagErr_enc_traceinterfacelist != nil {
			return nil, qualifyBERError(tagErr_enc_traceinterfacelist, "traceInterfaceList", "encoding", true)
		}
		enc_traceinterfacelist = retagged_enc_traceinterfacelist
		children = append(children, enc_traceinterfacelist...)
	}
	if v.TraceEventList != nil {
		enc_traceeventlist, err := v.TraceEventList.MarshalDER()
		if err != nil {
			return nil, qualifyBERError(err, "traceEventList", "encoding", true)
		}
		retagged_enc_traceeventlist, tagErr_enc_traceeventlist := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 9, enc_traceeventlist)
		if tagErr_enc_traceeventlist != nil {
			return nil, qualifyBERError(tagErr_enc_traceeventlist, "traceEventList", "encoding", true)
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
			return nil, qualifyBERError(encodeErr_enc_tracecollectionentity, "traceCollectionEntity", "encoding", true)
		}
		retagged_enc_tracecollectionentity, tagErr_enc_tracecollectionentity := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 10, enc_tracecollectionentity)
		if tagErr_enc_tracecollectionentity != nil {
			return nil, qualifyBERError(tagErr_enc_tracecollectionentity, "traceCollectionEntity", "encoding", true)
		}
		enc_tracecollectionentity = retagged_enc_tracecollectionentity
		children = append(children, enc_tracecollectionentity...)
	}
	if v.MdtConfiguration != nil {
		enc_mdtconfiguration, err := v.MdtConfiguration.MarshalDER()
		if err != nil {
			return nil, qualifyBERError(err, "mdt-Configuration", "encoding", true)
		}
		retagged_enc_mdtconfiguration, tagErr_enc_mdtconfiguration := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 11, enc_mdtconfiguration)
		if tagErr_enc_mdtconfiguration != nil {
			return nil, qualifyBERError(tagErr_enc_mdtconfiguration, "mdt-Configuration", "encoding", true)
		}
		enc_mdtconfiguration = retagged_enc_mdtconfiguration
		children = append(children, enc_mdtconfiguration...)
	}
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDEREncodedElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
		peekTag, _, _, extErr := ber.DecodeEncodedTLV(ext)
		if extErr != nil {
			return nil, extErr
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: only the first addition is restricted.
		if i == 0 && ((peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 11) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 10) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 9) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 8) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 7) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 6) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 5) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3)) {
			if constraintErr := ber.CheckEncodedValue(nil, "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
				return nil, constraintErr
			}
		}
		children = append(children, ext...)
	}
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("%s: %w", "encoding OMActivateTraceModeArg as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}

// UnmarshalBER decodes OMActivateTraceModeArg from BER/DER format.
func (v *OMActivateTraceModeArg) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: OMActivateTraceModeArg destination is nil", ber.ErrInvalidValue)
	}
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return ber.DiagnosePreflight(err, data, opts, "child", func(probeOpts []ber.DecodeOption) error {
			var probe OMActivateTraceModeArg
			return probe.UnmarshalBER(data, probeOpts...)
		})
	}
	*v = OMActivateTraceModeArg{}
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
		return fmt.Errorf("%s: %w", "decoding OMActivateTraceModeArg SEQUENCE", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "OMActivateTraceModeArg", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode imsi
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
				ber.MarkPreflightTarget(opts, "imsi", content[offset:])
				decodedTag_imsi, n_imsi, rawVal_imsi, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "imsi", "decoding", false)
				}
				if decodedTag_imsi.Class != tag.ClassContextSpecific || decodedTag_imsi.Number != 0 {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_imsi), "imsi", "decoding", false)
				}
				decVal_imsi, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_imsi.Constructed, rawVal_imsi, opts...)
				if octetErr != nil {
					return qualifyBERError(octetErr, "imsi", "decoding", false)
				}
				tmp_imsi := v21_map_commondatatypes.CommonDataTypesIMSI(decVal_imsi)
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
	{
		ber.MarkPreflightTarget(opts, "traceReference", content[offset:])
		decodedTag_tracereference, n_tracereference, rawVal_tracereference, err := ber.DecodeTLV(content[offset:], opts...)
		if err != nil {
			return qualifyBERError(err, "traceReference", "decoding", false)
		}
		if decodedTag_tracereference.Class != tag.ClassContextSpecific || decodedTag_tracereference.Number != 1 {
			return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_tracereference), "traceReference", "decoding", false)
		}
		decVal_tracereference, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_tracereference.Constructed, rawVal_tracereference, opts...)
		if octetErr != nil {
			return qualifyBERError(octetErr, "traceReference", "decoding", false)
		}
		v.TraceReference = OMTraceReference(decVal_tracereference)
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
	{
		ber.MarkPreflightTarget(opts, "traceType", content[offset:])
		decodedTag_tracetype, n_tracetype, rawVal_tracetype, err := ber.DecodeTLV(content[offset:], opts...)
		if err != nil {
			return qualifyBERError(err, "traceType", "decoding", false)
		}
		if decodedTag_tracetype.Class != tag.ClassContextSpecific || decodedTag_tracetype.Number != 2 || decodedTag_tracetype.Constructed != false {
			return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_tracetype), "traceType", "decoding", false)
		}
		decVal_tracetype, intErr := ber.DecodeIntegerValue(rawVal_tracetype)
		if intErr != nil {
			return qualifyBERError(intErr, "traceType", "decoding", false)
		}
		v.TraceType = OMTraceType(decVal_tracetype)
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
	}
	// Decode omc-Id
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3 {
				ber.MarkPreflightTarget(opts, "omc-Id", content[offset:])
				decodedTag_omcid, n_omcid, rawVal_omcid, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "omc-Id", "decoding", false)
				}
				if decodedTag_omcid.Class != tag.ClassContextSpecific || decodedTag_omcid.Number != 3 {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_omcid), "omc-Id", "decoding", false)
				}
				decVal_omcid, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_omcid.Constructed, rawVal_omcid, opts...)
				if octetErr != nil {
					return qualifyBERError(octetErr, "omc-Id", "decoding", false)
				}
				tmp_omcid := v21_map_commondatatypes.CommonDataTypesAddressString(decVal_omcid)
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
				ber.MarkPreflightTarget(opts, "extensionContainer", content[offset:])
				decodedTag_extensioncontainer, n_extensioncontainer, rawVal_extensioncontainer, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "extensionContainer", "decoding", false)
				}
				if decodedTag_extensioncontainer.Class != tag.ClassContextSpecific || decodedTag_extensioncontainer.Number != 4 || decodedTag_extensioncontainer.Constructed != true {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_extensioncontainer), "extensionContainer", "decoding", false)
				}
				reconstructed_extensioncontainer, reconstructionErr_extensioncontainer := ber.EncodeSequence(rawVal_extensioncontainer)
				if reconstructionErr_extensioncontainer != nil {
					return qualifyBERError(reconstructionErr_extensioncontainer, "extensionContainer", "decoding", false)
				}
				var dec_extensioncontainer v21_map_extensiondatatypes.ExtensionDataTypesExtensionContainer
				if unmErr := dec_extensioncontainer.UnmarshalBER(reconstructed_extensioncontainer, ber.ChildDecodeOptions(opts, "extensionContainer")...); unmErr != nil {
					return qualifyBERError(unmErr, "extensionContainer", "decoding", false)
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
				ber.MarkPreflightTarget(opts, "traceReference2", content[offset:])
				decodedTag_tracereference2, n_tracereference2, rawVal_tracereference2, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "traceReference2", "decoding", false)
				}
				if decodedTag_tracereference2.Class != tag.ClassContextSpecific || decodedTag_tracereference2.Number != 5 {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_tracereference2), "traceReference2", "decoding", false)
				}
				decVal_tracereference2, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_tracereference2.Constructed, rawVal_tracereference2, opts...)
				if octetErr != nil {
					return qualifyBERError(octetErr, "traceReference2", "decoding", false)
				}
				tmp_tracereference2 := OMTraceReference2(decVal_tracereference2)
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
	// Decode traceDepthList
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 6 {
				ber.MarkPreflightTarget(opts, "traceDepthList", content[offset:])
				decodedTag_tracedepthlist, n_tracedepthlist, rawVal_tracedepthlist, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "traceDepthList", "decoding", false)
				}
				if decodedTag_tracedepthlist.Class != tag.ClassContextSpecific || decodedTag_tracedepthlist.Number != 6 || decodedTag_tracedepthlist.Constructed != true {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_tracedepthlist), "traceDepthList", "decoding", false)
				}
				reconstructed_tracedepthlist, reconstructionErr_tracedepthlist := ber.EncodeSequence(rawVal_tracedepthlist)
				if reconstructionErr_tracedepthlist != nil {
					return qualifyBERError(reconstructionErr_tracedepthlist, "traceDepthList", "decoding", false)
				}
				var dec_tracedepthlist OMTraceDepthList
				if unmErr := dec_tracedepthlist.UnmarshalBER(reconstructed_tracedepthlist, ber.ChildDecodeOptions(opts, "traceDepthList")...); unmErr != nil {
					return qualifyBERError(unmErr, "traceDepthList", "decoding", false)
				}
				v.TraceDepthList = &dec_tracedepthlist
				if offset < 0 || offset >
					len(content) || n_tracedepthlist < 0 || n_tracedepthlist > len(
					content[offset:]) {
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
				ber.MarkPreflightTarget(opts, "traceNE-TypeList", content[offset:])
				decodedTag_tracenetypelist, n_tracenetypelist, rawVal_tracenetypelist, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "traceNE-TypeList", "decoding", false)
				}
				if decodedTag_tracenetypelist.Class != tag.ClassContextSpecific || decodedTag_tracenetypelist.Number != 7 {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_tracenetypelist), "traceNE-TypeList", "decoding", false)
				}
				bsBytes_tracenetypelist, bsUnused_tracenetypelist, bsErr := ber.DecodeImplicitBitStringValue(decodedTag_tracenetypelist.Constructed, rawVal_tracenetypelist, opts...)
				if bsErr != nil {
					return qualifyBERError(bsErr, "traceNE-TypeList", "decoding", false)
				}
				bsBitLength_tracenetypelist, bsLenErr_tracenetypelist := ber.BitStringBitLength(len(bsBytes_tracenetypelist), bsUnused_tracenetypelist)
				if bsLenErr_tracenetypelist != nil {
					return qualifyBERError(bsLenErr_tracenetypelist, "traceNE-TypeList", "decoding", false)
				}
				tmp_tracenetypelist := runtime.BitString{Bytes: bsBytes_tracenetypelist, BitLength: bsBitLength_tracenetypelist}
				v.TraceNETypeList = &tmp_tracenetypelist
				if offset < 0 || offset >
					len(content) || n_tracenetypelist < 0 || n_tracenetypelist > len(content[offset:]) {
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
				ber.MarkPreflightTarget(opts, "traceInterfaceList", content[offset:])
				decodedTag_traceinterfacelist, n_traceinterfacelist, rawVal_traceinterfacelist, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "traceInterfaceList", "decoding", false)
				}
				if decodedTag_traceinterfacelist.Class != tag.ClassContextSpecific || decodedTag_traceinterfacelist.Number != 8 || decodedTag_traceinterfacelist.Constructed != true {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_traceinterfacelist), "traceInterfaceList", "decoding", false)
				}
				reconstructed_traceinterfacelist, reconstructionErr_traceinterfacelist := ber.EncodeSequence(rawVal_traceinterfacelist)
				if reconstructionErr_traceinterfacelist != nil {
					return qualifyBERError(reconstructionErr_traceinterfacelist, "traceInterfaceList", "decoding", false)
				}
				var dec_traceinterfacelist OMTraceInterfaceList
				if unmErr := dec_traceinterfacelist.UnmarshalBER(reconstructed_traceinterfacelist, ber.ChildDecodeOptions(opts, "traceInterfaceList")...); unmErr != nil {
					return qualifyBERError(unmErr, "traceInterfaceList", "decoding", false)
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
				ber.MarkPreflightTarget(opts, "traceEventList", content[offset:])
				decodedTag_traceeventlist, n_traceeventlist, rawVal_traceeventlist, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "traceEventList", "decoding", false)
				}
				if decodedTag_traceeventlist.Class != tag.ClassContextSpecific || decodedTag_traceeventlist.Number != 9 || decodedTag_traceeventlist.Constructed != true {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_traceeventlist), "traceEventList", "decoding", false)
				}
				reconstructed_traceeventlist, reconstructionErr_traceeventlist := ber.EncodeSequence(rawVal_traceeventlist)
				if reconstructionErr_traceeventlist != nil {
					return qualifyBERError(reconstructionErr_traceeventlist, "traceEventList", "decoding", false)
				}
				var dec_traceeventlist OMTraceEventList
				if unmErr := dec_traceeventlist.UnmarshalBER(reconstructed_traceeventlist, ber.ChildDecodeOptions(opts, "traceEventList")...); unmErr != nil {
					return qualifyBERError(unmErr, "traceEventList", "decoding", false)
				}
				v.TraceEventList = &dec_traceeventlist
				if offset < 0 || offset >
					len(content) || n_traceeventlist < 0 || n_traceeventlist > len(
					content[offset:]) {
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
				ber.MarkPreflightTarget(opts, "traceCollectionEntity", content[offset:])
				decodedTag_tracecollectionentity, n_tracecollectionentity, rawVal_tracecollectionentity, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "traceCollectionEntity", "decoding", false)
				}
				if decodedTag_tracecollectionentity.Class != tag.ClassContextSpecific || decodedTag_tracecollectionentity.Number != 10 {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_tracecollectionentity), "traceCollectionEntity", "decoding", false)
				}
				decVal_tracecollectionentity, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_tracecollectionentity.Constructed, rawVal_tracecollectionentity, opts...)
				if octetErr != nil {
					return qualifyBERError(octetErr, "traceCollectionEntity", "decoding", false)
				}
				tmp_tracecollectionentity := v21_map_commondatatypes.CommonDataTypesGSNAddress(decVal_tracecollectionentity)
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
				ber.MarkPreflightTarget(opts, "mdt-Configuration", content[offset:])
				decodedTag_mdtconfiguration, n_mdtconfiguration, rawVal_mdtconfiguration, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "mdt-Configuration", "decoding", false)
				}
				if decodedTag_mdtconfiguration.Class != tag.ClassContextSpecific || decodedTag_mdtconfiguration.Number != 11 || decodedTag_mdtconfiguration.Constructed != true {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_mdtconfiguration), "mdt-Configuration", "decoding", false)
				}
				reconstructed_mdtconfiguration, reconstructionErr_mdtconfiguration := ber.EncodeSequence(rawVal_mdtconfiguration)
				if reconstructionErr_mdtconfiguration != nil {
					return qualifyBERError(reconstructionErr_mdtconfiguration, "mdt-Configuration", "decoding", false)
				}
				var dec_mdtconfiguration OMMDTConfiguration
				if unmErr := dec_mdtconfiguration.UnmarshalBER(reconstructed_mdtconfiguration, ber.ChildDecodeOptions(opts, "mdt-Configuration")...); unmErr != nil {
					return qualifyBERError(unmErr, "mdt-Configuration", "decoding", false)
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
		peekTag, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:], opts...)
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "OMActivateTraceModeArg", Cause: extErr_}
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: the first unknown addition must differ from trailing OPTIONAL/DEFAULT tags.
		if len(v.ExtData_) == 0 && ((peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 11) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 10) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 9) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 8) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 7) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 6) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 5) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3)) {
			if !ber.ConstraintToleranceEnabled(opts) {
				return &ber.DecodeError{Offset: offset, TypeName: "OMActivateTraceModeArg", Cause: fmt.Errorf("%w: repeated or out-of-order SEQUENCE component tag %s", ber.ErrInvalidTag, peekTag)}
			}
			if orderErr_ := ber.CheckDecodedValue(opts, fmt.Sprintf("ExtData_[%d]", len(v.ExtData_)), "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); orderErr_ != nil {
				return orderErr_
			}
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

// MarshalBER encodes OMMDTConfiguration to BER format.
func (v *OMMDTConfiguration) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: OMMDTConfiguration receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *OMMDTConfiguration) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
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
			return nil, qualifyBERError(err, "areaScope", "encoding", false)
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
			return nil, qualifyBERError(encodeErr_enc_listofmeasurements, "listOfMeasurements", "encoding", false)
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
			return nil, qualifyBERError(encodeErr_enc_reportingtrigger, "reportingTrigger", "encoding", false)
		}
		retagged_enc_reportingtrigger, tagErr_enc_reportingtrigger := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_reportingtrigger)
		if tagErr_enc_reportingtrigger != nil {
			return nil, qualifyBERError(tagErr_enc_reportingtrigger, "reportingTrigger", "encoding", false)
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
			return nil, qualifyBERError(tagErr_enc_reportamount, "reportAmount", "encoding", false)
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
			return nil, qualifyBERError(tagErr_enc_eventthresholdrsrq, "eventThresholdRSRQ", "encoding", false)
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
			return nil, qualifyBERError(tagErr_enc_logginginterval, "loggingInterval", "encoding", false)
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
			return nil, qualifyBERError(tagErr_enc_loggingduration, "loggingDuration", "encoding", false)
		}
		enc_loggingduration = retagged_enc_loggingduration
		children = append(children, enc_loggingduration...)
	}
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalBER(ber.ChildEncodeOptions(opts, "extensionContainer")...)
		if err != nil {
			return nil, qualifyBERError(err, "extensionContainer", "encoding", false)
		}
		retagged_enc_extensioncontainer, tagErr_enc_extensioncontainer := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 5, enc_extensioncontainer)
		if tagErr_enc_extensioncontainer != nil {
			return nil, qualifyBERError(tagErr_enc_extensioncontainer, "extensionContainer", "encoding", false)
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
			return nil, qualifyBERError(tagErr_enc_measurementperiodumts, "measurementPeriodUMTS", "encoding", false)
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
			return nil, qualifyBERError(tagErr_enc_measurementperiodlte, "measurementPeriodLTE", "encoding", false)
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
			return nil, qualifyBERError(tagErr_enc_collectionperiodrrmumts, "collectionPeriodRRM-UMTS", "encoding", false)
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
			return nil, qualifyBERError(tagErr_enc_collectionperiodrrmlte, "collectionPeriodRRM-LTE", "encoding", false)
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
			return nil, qualifyBERError(encodeErr_enc_positioningmethod, "positioningMethod", "encoding", false)
		}
		retagged_enc_positioningmethod, tagErr_enc_positioningmethod := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 10, enc_positioningmethod)
		if tagErr_enc_positioningmethod != nil {
			return nil, qualifyBERError(tagErr_enc_positioningmethod, "positioningMethod", "encoding", false)
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
			return nil, qualifyBERError(encodeErr_enc_measurementquantity, "measurementQuantity", "encoding", false)
		}
		retagged_enc_measurementquantity, tagErr_enc_measurementquantity := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 11, enc_measurementquantity)
		if tagErr_enc_measurementquantity != nil {
			return nil, qualifyBERError(tagErr_enc_measurementquantity, "measurementQuantity", "encoding", false)
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
			return nil, qualifyBERError(tagErr_enc_eventthreshold1f, "eventThreshold1F", "encoding", false)
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
			return nil, qualifyBERError(tagErr_enc_eventthreshold1i, "eventThreshold1I", "encoding", false)
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
		enc_mdtallowedplmnlist, err := MarshalBEROMMDTAllowedPLMNIdList(v.MdtAllowedPLMNList, ber.ParentCollectionSizeEncodeOptions(ber.ChildEncodeOptions(opts, "mdt-Allowed-PLMN-List"))...)
		if err != nil {
			return nil, qualifyBERError(err, "mdt-Allowed-PLMN-List", "encoding", false)
		}
		if ber.BERReplayEnabled(opts) && v.MdtAllowedPLMNListIndef_ {
			// Strip the outer SEQUENCE tag from marshalBER output to get raw children.
			_, _, seqContent_, tlvErr_ := ber.DecodeEncodedTLV(enc_mdtallowedplmnlist)
			if tlvErr_ != nil {
				return nil, tlvErr_
			}
			{
				var encodeErr error
				enc_mdtallowedplmnlist, encodeErr = ber.EncodeConstructedIndefinite(tag.Tag{Class: tag.ClassContextSpecific, Number: 14}, seqContent_)
				if encodeErr != nil {
					return nil, qualifyBERError(encodeErr, "mdt-Allowed-PLMN-List", "encoding", false)
				}
			}
		} else {
			retagged_enc_mdtallowedplmnlist, tagErr_enc_mdtallowedplmnlist := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 14, enc_mdtallowedplmnlist)
			if tagErr_enc_mdtallowedplmnlist != nil {
				return nil, qualifyBERError(tagErr_enc_mdtallowedplmnlist, "mdt-Allowed-PLMN-List", "encoding", false)
			}
			enc_mdtallowedplmnlist = retagged_enc_mdtallowedplmnlist
		}
		children = append(children, enc_mdtallowedplmnlist...)
	}
	for i, ext := range v.ExtData_ {
		if err := ber.CheckBEROpaqueReplay(opts...); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
		peekTag, n, _, extErr := ber.DecodeEncodedTLV(ext)
		if extErr != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, extErr)
		}
		if n != len(ext) {
			return nil, fmt.Errorf("encoding extension %d: %w", i, ber.ErrExtraData)
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: only the first addition is restricted.
		if i == 0 && ((peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 14) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 13) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 12) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 11) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 10) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 9) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 8) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 7) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 6) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 5) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2) || (peekTag.Class == tag.ClassUniversal && peekTag.Number == 2) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1) || (peekTag.Class == tag.ClassUniversal && peekTag.Number == 10) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0) || (peekTag.Class == tag.ClassUniversal && peekTag.Number == 4) || (peekTag.Class == tag.ClassUniversal && peekTag.Number == 16)) {
			if constraintErr := ber.CheckEncodedValue(opts, "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
				return nil, constraintErr
			}
		}
		children = append(children, ext...)
	}
	return ber.EncodeSequence(children)
}

// MarshalDER encodes OMMDTConfiguration to DER format.
func (v *OMMDTConfiguration) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: OMMDTConfiguration receiver is nil", ber.ErrInvalidValue)
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
			return nil, qualifyBERError(err, "areaScope", "encoding", true)
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
			return nil, qualifyBERError(encodeErr_enc_listofmeasurements, "listOfMeasurements", "encoding", true)
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
			return nil, qualifyBERError(encodeErr_enc_reportingtrigger, "reportingTrigger", "encoding", true)
		}
		retagged_enc_reportingtrigger, tagErr_enc_reportingtrigger := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_reportingtrigger)
		if tagErr_enc_reportingtrigger != nil {
			return nil, qualifyBERError(tagErr_enc_reportingtrigger, "reportingTrigger", "encoding", true)
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
			return nil, qualifyBERError(tagErr_enc_reportamount, "reportAmount", "encoding", true)
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
			return nil, qualifyBERError(tagErr_enc_eventthresholdrsrq, "eventThresholdRSRQ", "encoding", true)
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
			return nil, qualifyBERError(tagErr_enc_logginginterval, "loggingInterval", "encoding", true)
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
			return nil, qualifyBERError(tagErr_enc_loggingduration, "loggingDuration", "encoding", true)
		}
		enc_loggingduration = retagged_enc_loggingduration
		children = append(children, enc_loggingduration...)
	}
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalDER()
		if err != nil {
			return nil, qualifyBERError(err, "extensionContainer", "encoding", true)
		}
		retagged_enc_extensioncontainer, tagErr_enc_extensioncontainer := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 5, enc_extensioncontainer)
		if tagErr_enc_extensioncontainer != nil {
			return nil, qualifyBERError(tagErr_enc_extensioncontainer, "extensionContainer", "encoding", true)
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
			return nil, qualifyBERError(tagErr_enc_measurementperiodumts, "measurementPeriodUMTS", "encoding", true)
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
			return nil, qualifyBERError(tagErr_enc_measurementperiodlte, "measurementPeriodLTE", "encoding", true)
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
			return nil, qualifyBERError(tagErr_enc_collectionperiodrrmumts, "collectionPeriodRRM-UMTS", "encoding", true)
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
			return nil, qualifyBERError(tagErr_enc_collectionperiodrrmlte, "collectionPeriodRRM-LTE", "encoding", true)
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
			return nil, qualifyBERError(encodeErr_enc_positioningmethod, "positioningMethod", "encoding", true)
		}
		retagged_enc_positioningmethod, tagErr_enc_positioningmethod := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 10, enc_positioningmethod)
		if tagErr_enc_positioningmethod != nil {
			return nil, qualifyBERError(tagErr_enc_positioningmethod, "positioningMethod", "encoding", true)
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
			return nil, qualifyBERError(encodeErr_enc_measurementquantity, "measurementQuantity", "encoding", true)
		}
		retagged_enc_measurementquantity, tagErr_enc_measurementquantity := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 11, enc_measurementquantity)
		if tagErr_enc_measurementquantity != nil {
			return nil, qualifyBERError(tagErr_enc_measurementquantity, "measurementQuantity", "encoding", true)
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
			return nil, qualifyBERError(tagErr_enc_eventthreshold1f, "eventThreshold1F", "encoding", true)
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
			return nil, qualifyBERError(tagErr_enc_eventthreshold1i, "eventThreshold1I", "encoding", true)
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
		enc_mdtallowedplmnlist, err := MarshalDEROMMDTAllowedPLMNIdList(v.MdtAllowedPLMNList)
		if err != nil {
			return nil, qualifyBERError(err, "mdt-Allowed-PLMN-List", "encoding", true)
		}
		retagged_enc_mdtallowedplmnlist, tagErr_enc_mdtallowedplmnlist := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 14, enc_mdtallowedplmnlist)
		if tagErr_enc_mdtallowedplmnlist != nil {
			return nil, qualifyBERError(tagErr_enc_mdtallowedplmnlist, "mdt-Allowed-PLMN-List", "encoding", true)
		}
		enc_mdtallowedplmnlist = retagged_enc_mdtallowedplmnlist
		children = append(children, enc_mdtallowedplmnlist...)
	}
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDEREncodedElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
		peekTag, _, _, extErr := ber.DecodeEncodedTLV(ext)
		if extErr != nil {
			return nil, extErr
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: only the first addition is restricted.
		if i == 0 && ((peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 14) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 13) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 12) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 11) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 10) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 9) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 8) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 7) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 6) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 5) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2) || (peekTag.Class == tag.ClassUniversal && peekTag.Number == 2) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1) || (peekTag.Class == tag.ClassUniversal && peekTag.Number == 10) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0) || (peekTag.Class == tag.ClassUniversal && peekTag.Number == 4) || (peekTag.Class == tag.ClassUniversal && peekTag.Number == 16)) {
			if constraintErr := ber.CheckEncodedValue(nil, "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
				return nil, constraintErr
			}
		}
		children = append(children, ext...)
	}
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("%s: %w", "encoding OMMDTConfiguration as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}

// UnmarshalBER decodes OMMDTConfiguration from BER/DER format.
func (v *OMMDTConfiguration) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: OMMDTConfiguration destination is nil", ber.ErrInvalidValue)
	}
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return ber.DiagnosePreflight(err, data, opts, "child", func(probeOpts []ber.DecodeOption) error {
			var probe OMMDTConfiguration
			return probe.UnmarshalBER(data, probeOpts...)
		})
	}
	*v = OMMDTConfiguration{}
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
		return fmt.Errorf("%s: %w", "decoding OMMDTConfiguration SEQUENCE", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "OMMDTConfiguration", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode jobType
	if offset >= len(content) {
		return fmt.Errorf("missing required field jobType")
	}
	{
		ber.MarkPreflightTarget(opts, "jobType", content[offset:])
		val_jobtype, n, err := ber.DecodeEnumerated(content[offset:], opts...)
		if err != nil {
			return qualifyBERError(err, "jobType", "decoding", false)
		}
		v.JobType = OMJobType(val_jobtype)
		if offset > len(content) || n < 0 || n > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n
		if int64(v.JobType) != 0 && int64(v.JobType) != 1 && int64(v.JobType) != 2 && int64(v.JobType) != 3 {
			if constraintErr := ber.CheckDecodedValue(opts, "jobType", "ENUMERATED {0, 1, 2, 3}", fmt.Sprint(int64(v.JobType))); constraintErr != nil {
				return constraintErr
			}
		}
	}
	// Decode areaScope
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassUniversal && peekTag.Number == 16 {
				ber.MarkPreflightTarget(opts, "areaScope", content[offset:])
				// Decode nested SEQUENCE (OMAreaScope)
				_, n_areascope, _, tlvErr_areascope := ber.DecodeTLV(content[offset:], opts...)
				if tlvErr_areascope != nil {
					return qualifyBERError(tlvErr_areascope, "areaScope", "decoding", false)
				}
				var dec_areascope OMAreaScope
				if offset < 0 || offset >
					len(content) || n_areascope < 0 || n_areascope > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				if unmErr := dec_areascope.UnmarshalBER(content[offset:offset+n_areascope], ber.ChildDecodeOptions(opts, "areaScope")...); unmErr != nil {
					return qualifyBERError(unmErr, "areaScope", "decoding", false)
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
				ber.MarkPreflightTarget(opts, "listOfMeasurements", content[offset:])
				val_listofmeasurements, n, err := ber.DecodeOctetString(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "listOfMeasurements", "decoding", false)
				}
				tmp_listofmeasurements := OMListOfMeasurements(val_listofmeasurements)
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
				ber.MarkPreflightTarget(opts, "reportingTrigger", content[offset:])
				decodedTag_reportingtrigger, n_reportingtrigger, rawVal_reportingtrigger, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "reportingTrigger", "decoding", false)
				}
				if decodedTag_reportingtrigger.Class != tag.ClassContextSpecific || decodedTag_reportingtrigger.Number != 0 {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_reportingtrigger), "reportingTrigger", "decoding", false)
				}
				decVal_reportingtrigger, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_reportingtrigger.Constructed, rawVal_reportingtrigger, opts...)
				if octetErr != nil {
					return qualifyBERError(octetErr, "reportingTrigger", "decoding", false)
				}
				tmp_reportingtrigger := OMReportingTrigger(decVal_reportingtrigger)
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
				ber.MarkPreflightTarget(opts, "reportInterval", content[offset:])
				val_reportinterval, n, err := ber.DecodeEnumerated(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "reportInterval", "decoding", false)
				}
				tmp_reportinterval := OMReportInterval(val_reportinterval)
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
				ber.MarkPreflightTarget(opts, "reportAmount", content[offset:])
				decodedTag_reportamount, n_reportamount, rawVal_reportamount, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "reportAmount", "decoding", false)
				}
				if decodedTag_reportamount.Class != tag.ClassContextSpecific || decodedTag_reportamount.Number != 1 || decodedTag_reportamount.Constructed != false {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_reportamount), "reportAmount", "decoding", false)
				}
				decVal_reportamount, intErr := ber.DecodeEnumeratedValue(rawVal_reportamount)
				if intErr != nil {
					return qualifyBERError(intErr, "reportAmount", "decoding", false)
				}
				tmp_reportamount := OMReportAmount(decVal_reportamount)
				v.ReportAmount = &tmp_reportamount
				if offset < 0 || offset >
					len(content) || n_reportamount < 0 || n_reportamount > len(
					content[offset:]) {
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
				ber.MarkPreflightTarget(opts, "eventThresholdRSRP", content[offset:])
				val_eventthresholdrsrp, n, err := ber.DecodeInteger(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "eventThresholdRSRP", "decoding", false)
				}
				tmp_eventthresholdrsrp := OMEventThresholdRSRP(val_eventthresholdrsrp)
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
				ber.MarkPreflightTarget(opts, "eventThresholdRSRQ", content[offset:])
				decodedTag_eventthresholdrsrq, n_eventthresholdrsrq, rawVal_eventthresholdrsrq, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "eventThresholdRSRQ", "decoding", false)
				}
				if decodedTag_eventthresholdrsrq.Class != tag.ClassContextSpecific || decodedTag_eventthresholdrsrq.Number != 2 || decodedTag_eventthresholdrsrq.Constructed != false {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_eventthresholdrsrq), "eventThresholdRSRQ", "decoding", false)
				}
				decVal_eventthresholdrsrq, intErr := ber.DecodeIntegerValue(rawVal_eventthresholdrsrq)
				if intErr != nil {
					return qualifyBERError(intErr, "eventThresholdRSRQ", "decoding", false)
				}
				tmp_eventthresholdrsrq := OMEventThresholdRSRQ(decVal_eventthresholdrsrq)
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
				ber.MarkPreflightTarget(opts, "loggingInterval", content[offset:])
				decodedTag_logginginterval, n_logginginterval, rawVal_logginginterval, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "loggingInterval", "decoding", false)
				}
				if decodedTag_logginginterval.Class != tag.ClassContextSpecific || decodedTag_logginginterval.Number != 3 || decodedTag_logginginterval.Constructed != false {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_logginginterval), "loggingInterval", "decoding", false)
				}
				decVal_logginginterval, intErr := ber.DecodeEnumeratedValue(rawVal_logginginterval)
				if intErr != nil {
					return qualifyBERError(intErr, "loggingInterval", "decoding", false)
				}
				tmp_logginginterval := OMLoggingInterval(decVal_logginginterval)
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
				ber.MarkPreflightTarget(opts, "loggingDuration", content[offset:])
				decodedTag_loggingduration, n_loggingduration, rawVal_loggingduration, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "loggingDuration", "decoding", false)
				}
				if decodedTag_loggingduration.Class != tag.ClassContextSpecific || decodedTag_loggingduration.Number != 4 || decodedTag_loggingduration.Constructed != false {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_loggingduration), "loggingDuration", "decoding", false)
				}
				decVal_loggingduration, intErr := ber.DecodeEnumeratedValue(rawVal_loggingduration)
				if intErr != nil {
					return qualifyBERError(intErr, "loggingDuration", "decoding", false)
				}
				tmp_loggingduration := OMLoggingDuration(decVal_loggingduration)
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
				ber.MarkPreflightTarget(opts, "extensionContainer", content[offset:])
				decodedTag_extensioncontainer, n_extensioncontainer, rawVal_extensioncontainer, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "extensionContainer", "decoding", false)
				}
				if decodedTag_extensioncontainer.Class != tag.ClassContextSpecific || decodedTag_extensioncontainer.Number != 5 || decodedTag_extensioncontainer.Constructed != true {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_extensioncontainer), "extensionContainer", "decoding", false)
				}
				reconstructed_extensioncontainer, reconstructionErr_extensioncontainer := ber.EncodeSequence(rawVal_extensioncontainer)
				if reconstructionErr_extensioncontainer != nil {
					return qualifyBERError(reconstructionErr_extensioncontainer, "extensionContainer", "decoding", false)
				}
				var dec_extensioncontainer v21_map_extensiondatatypes.ExtensionDataTypesExtensionContainer
				if unmErr := dec_extensioncontainer.UnmarshalBER(reconstructed_extensioncontainer, ber.ChildDecodeOptions(opts, "extensionContainer")...); unmErr != nil {
					return qualifyBERError(unmErr, "extensionContainer", "decoding", false)
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
				ber.MarkPreflightTarget(opts, "measurementPeriodUMTS", content[offset:])
				decodedTag_measurementperiodumts, n_measurementperiodumts, rawVal_measurementperiodumts, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "measurementPeriodUMTS", "decoding", false)
				}
				if decodedTag_measurementperiodumts.Class != tag.ClassContextSpecific || decodedTag_measurementperiodumts.Number != 6 || decodedTag_measurementperiodumts.Constructed != false {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_measurementperiodumts), "measurementPeriodUMTS", "decoding", false)
				}
				decVal_measurementperiodumts, intErr := ber.DecodeEnumeratedValue(rawVal_measurementperiodumts)
				if intErr != nil {
					return qualifyBERError(intErr, "measurementPeriodUMTS", "decoding", false)
				}
				tmp_measurementperiodumts := OMPeriodUMTS(decVal_measurementperiodumts)
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
				ber.MarkPreflightTarget(opts, "measurementPeriodLTE", content[offset:])
				decodedTag_measurementperiodlte, n_measurementperiodlte, rawVal_measurementperiodlte, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "measurementPeriodLTE", "decoding", false)
				}
				if decodedTag_measurementperiodlte.Class != tag.ClassContextSpecific || decodedTag_measurementperiodlte.Number != 7 || decodedTag_measurementperiodlte.Constructed != false {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_measurementperiodlte), "measurementPeriodLTE", "decoding", false)
				}
				decVal_measurementperiodlte, intErr := ber.DecodeEnumeratedValue(rawVal_measurementperiodlte)
				if intErr != nil {
					return qualifyBERError(intErr, "measurementPeriodLTE", "decoding", false)
				}
				tmp_measurementperiodlte := OMPeriodLTE(decVal_measurementperiodlte)
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
				ber.MarkPreflightTarget(opts, "collectionPeriodRRM-UMTS", content[offset:])
				decodedTag_collectionperiodrrmumts, n_collectionperiodrrmumts, rawVal_collectionperiodrrmumts, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "collectionPeriodRRM-UMTS", "decoding", false)
				}
				if decodedTag_collectionperiodrrmumts.Class != tag.ClassContextSpecific || decodedTag_collectionperiodrrmumts.Number != 8 || decodedTag_collectionperiodrrmumts.Constructed != false {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_collectionperiodrrmumts), "collectionPeriodRRM-UMTS", "decoding", false)
				}
				decVal_collectionperiodrrmumts, intErr := ber.DecodeEnumeratedValue(rawVal_collectionperiodrrmumts)
				if intErr != nil {
					return qualifyBERError(intErr, "collectionPeriodRRM-UMTS", "decoding", false)
				}
				tmp_collectionperiodrrmumts := OMPeriodUMTS(decVal_collectionperiodrrmumts)
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
				ber.MarkPreflightTarget(opts, "collectionPeriodRRM-LTE", content[offset:])
				decodedTag_collectionperiodrrmlte, n_collectionperiodrrmlte, rawVal_collectionperiodrrmlte, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "collectionPeriodRRM-LTE", "decoding", false)
				}
				if decodedTag_collectionperiodrrmlte.Class != tag.ClassContextSpecific || decodedTag_collectionperiodrrmlte.Number != 9 || decodedTag_collectionperiodrrmlte.Constructed != false {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_collectionperiodrrmlte), "collectionPeriodRRM-LTE", "decoding", false)
				}
				decVal_collectionperiodrrmlte, intErr := ber.DecodeEnumeratedValue(rawVal_collectionperiodrrmlte)
				if intErr != nil {
					return qualifyBERError(intErr, "collectionPeriodRRM-LTE", "decoding", false)
				}
				tmp_collectionperiodrrmlte := OMPeriodLTE(decVal_collectionperiodrrmlte)
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
				ber.MarkPreflightTarget(opts, "positioningMethod", content[offset:])
				decodedTag_positioningmethod, n_positioningmethod, rawVal_positioningmethod, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "positioningMethod", "decoding", false)
				}
				if decodedTag_positioningmethod.Class != tag.ClassContextSpecific || decodedTag_positioningmethod.Number != 10 {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_positioningmethod), "positioningMethod", "decoding", false)
				}
				decVal_positioningmethod, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_positioningmethod.Constructed, rawVal_positioningmethod, opts...)
				if octetErr != nil {
					return qualifyBERError(octetErr, "positioningMethod", "decoding", false)
				}
				tmp_positioningmethod := OMPositioningMethod(decVal_positioningmethod)
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
				ber.MarkPreflightTarget(opts, "measurementQuantity", content[offset:])
				decodedTag_measurementquantity, n_measurementquantity, rawVal_measurementquantity, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "measurementQuantity", "decoding", false)
				}
				if decodedTag_measurementquantity.Class != tag.ClassContextSpecific || decodedTag_measurementquantity.Number != 11 {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_measurementquantity), "measurementQuantity", "decoding", false)
				}
				decVal_measurementquantity, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_measurementquantity.Constructed, rawVal_measurementquantity, opts...)
				if octetErr != nil {
					return qualifyBERError(octetErr, "measurementQuantity", "decoding", false)
				}
				tmp_measurementquantity := OMMeasurementQuantity(decVal_measurementquantity)
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
				ber.MarkPreflightTarget(opts, "eventThreshold1F", content[offset:])
				decodedTag_eventthreshold1f, n_eventthreshold1f, rawVal_eventthreshold1f, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "eventThreshold1F", "decoding", false)
				}
				if decodedTag_eventthreshold1f.Class != tag.ClassContextSpecific || decodedTag_eventthreshold1f.Number != 12 || decodedTag_eventthreshold1f.Constructed != false {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_eventthreshold1f), "eventThreshold1F", "decoding", false)
				}
				decVal_eventthreshold1f, intErr := ber.DecodeIntegerValue(rawVal_eventthreshold1f)
				if intErr != nil {
					return qualifyBERError(intErr, "eventThreshold1F", "decoding", false)
				}
				tmp_eventthreshold1f := OMEventThreshold1F(decVal_eventthreshold1f)
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
				ber.MarkPreflightTarget(opts, "eventThreshold1I", content[offset:])
				decodedTag_eventthreshold1i, n_eventthreshold1i, rawVal_eventthreshold1i, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "eventThreshold1I", "decoding", false)
				}
				if decodedTag_eventthreshold1i.Class != tag.ClassContextSpecific || decodedTag_eventthreshold1i.Number != 13 || decodedTag_eventthreshold1i.Constructed != false {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_eventthreshold1i), "eventThreshold1I", "decoding", false)
				}
				decVal_eventthreshold1i, intErr := ber.DecodeIntegerValue(rawVal_eventthreshold1i)
				if intErr != nil {
					return qualifyBERError(intErr, "eventThreshold1I", "decoding", false)
				}
				tmp_eventthreshold1i := OMEventThreshold1I(decVal_eventthreshold1i)
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
				ber.MarkPreflightTarget(opts, "mdt-Allowed-PLMN-List", content[offset:])
				decodedTag_mdtallowedplmnlist, n_mdtallowedplmnlist, rawVal_mdtallowedplmnlist, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "mdt-Allowed-PLMN-List", "decoding", false)
				}
				if decodedTag_mdtallowedplmnlist.Class != tag.ClassContextSpecific || decodedTag_mdtallowedplmnlist.Number != 14 || decodedTag_mdtallowedplmnlist.Constructed != true {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_mdtallowedplmnlist), "mdt-Allowed-PLMN-List", "decoding", false)
				}
				reconstructed_mdtallowedplmnlist, reconstructionErr_mdtallowedplmnlist := ber.EncodeSequence(rawVal_mdtallowedplmnlist)
				if reconstructionErr_mdtallowedplmnlist != nil {
					return qualifyBERError(reconstructionErr_mdtallowedplmnlist, "mdt-Allowed-PLMN-List", "decoding", false)
				}
				dec_mdtallowedplmnlist, unmErr := UnmarshalBEROMMDTAllowedPLMNIdList(reconstructed_mdtallowedplmnlist, ber.ParentCollectionSizeDecodeOptions(ber.ChildDecodeOptions(opts, "mdt-Allowed-PLMN-List"))...)
				if unmErr != nil {
					return qualifyBERError(unmErr, "mdt-Allowed-PLMN-List", "decoding", false)
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
		peekTag, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:], opts...)
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "OMMDTConfiguration", Cause: extErr_}
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: the first unknown addition must differ from trailing OPTIONAL/DEFAULT tags.
		if len(v.ExtData_) == 0 && ((peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 14) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 13) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 12) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 11) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 10) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 9) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 8) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 7) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 6) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 5) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2) || (peekTag.Class == tag.ClassUniversal && peekTag.Number == 2) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1) || (peekTag.Class == tag.ClassUniversal && peekTag.Number == 10) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0) || (peekTag.Class == tag.ClassUniversal && peekTag.Number == 4) || (peekTag.Class == tag.ClassUniversal && peekTag.Number == 16)) {
			if !ber.ConstraintToleranceEnabled(opts) {
				return &ber.DecodeError{Offset: offset, TypeName: "OMMDTConfiguration", Cause: fmt.Errorf("%w: repeated or out-of-order SEQUENCE component tag %s", ber.ErrInvalidTag, peekTag)}
			}
			if orderErr_ := ber.CheckDecodedValue(opts, fmt.Sprintf("ExtData_[%d]", len(v.ExtData_)), "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); orderErr_ != nil {
				return orderErr_
			}
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

// MarshalBEROMMDTAllowedPLMNIdList encodes a OMMDTAllowedPLMNIdList list to BER.
func MarshalBEROMMDTAllowedPLMNIdList(collection *OMMDTAllowedPLMNIdList, opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	if collection == nil {
		return nil, fmt.Errorf("%w: required collection is nil", ber.ErrInvalidValue)
	}
	encoded, err := marshalBEROMMDTAllowedPLMNIdList(collection, opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, collection.berOriginal_, collection.berSnapshot_, opts), nil
}
func marshalBEROMMDTAllowedPLMNIdList(collection *OMMDTAllowedPLMNIdList, opts ...ber.EncodeOption) ([]byte, error) {
	list := collection.Values
	if len(list) < 1 || len(list) > 16 {
		if constraintErr := ber.CheckEncodedCollectionLength(opts, "MDT-Allowed-PLMNId-List", "SIZE (1..16)", len(list)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	var children []byte
	for elemIndex, elem := range list {
		_ = elemIndex
		if len(elem) < 3 || len(elem) > 3 {
			if constraintErr := ber.CheckEncodedLength(opts, fmt.Sprintf("element[%d]", elemIndex), "SIZE (3)", len(elem)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		encodedElem, encodeErr_encodedElem := ber.EncodeOctetString([]byte(elem))
		if encodeErr_encodedElem != nil {
			return nil, qualifyBERError(encodeErr_encodedElem, fmt.Sprintf("element[%d]",
				elemIndex),

				"encoding", false)
		}
		children = append(children, encodedElem...)
	}
	return ber.EncodeSequence(children)
}

// MarshalDEROMMDTAllowedPLMNIdList encodes a OMMDTAllowedPLMNIdList list to DER.
func MarshalDEROMMDTAllowedPLMNIdList(collection *OMMDTAllowedPLMNIdList) ([]byte, error) {
	if collection == nil {
		return nil, fmt.Errorf("%w: required collection is nil", ber.ErrInvalidValue)
	}
	list := collection.Values
	if len(list) < 1 || len(list) > 16 {
		if constraintErr := ber.CheckEncodedCollectionLength(nil, "MDT-Allowed-PLMNId-List", "SIZE (1..16)", len(list)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	var children []byte
	for elemIndex, elem := range list {
		_ = elemIndex
		if len(elem) < 3 || len(elem) > 3 {
			if constraintErr := ber.CheckEncodedLength(nil, fmt.Sprintf("element[%d]", elemIndex), "SIZE (3)", len(elem)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		encodedElem, encodeErr_encodedElem := ber.EncodeOctetString([]byte(elem))
		if encodeErr_encodedElem != nil {
			return nil, qualifyBERError(encodeErr_encodedElem, fmt.Sprintf("element[%d]",
				elemIndex),

				"encoding", true)
		}
		children = append(children, encodedElem...)
	}
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("%s: %w", "encoding OMMDTAllowedPLMNIdList as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}

// UnmarshalBEROMMDTAllowedPLMNIdList decodes a OMMDTAllowedPLMNIdList list from BER.
func UnmarshalBEROMMDTAllowedPLMNIdList(data []byte, opts ...ber.DecodeOption) (returnValue *OMMDTAllowedPLMNIdList, returnErr error) {
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return nil, ber.DiagnosePreflight(err, data, opts, "element", func(probeOpts []ber.DecodeOption) error {
			_, probeErr := UnmarshalBEROMMDTAllowedPLMNIdList(data, probeOpts...)
			return probeErr
		})
	}
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", "decoding OMMDTAllowedPLMNIdList", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return nil, &ber.DecodeError{Offset: total, TypeName: "OMMDTAllowedPLMNIdList", Cause: ber.ErrExtraData}
	}
	var result []v21_map_commondatatypes.CommonDataTypesPLMNId
	offset := 0
	for offset < len(content) {
		elementIndex := len(result)
		_ = elementIndex
		elementData := content[offset:]
		ber.MarkPreflightElement(opts, elementIndex, elementData)
		val, n, osErr := ber.DecodeOctetString(elementData, opts...)
		if osErr != nil {
			return nil, qualifyBERError(osErr, fmt.Sprintf("element[%d]",
				elementIndex),

				"decoding", false)
		}
		if len(val) < 3 || len(val) > 3 {
			if constraintErr := ber.CheckDecodedLength(opts, fmt.Sprintf("element[%d]", len(result)), "SIZE (3)", len(val)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		result = append(result, v21_map_commondatatypes.CommonDataTypesPLMNId(val))
		if offset < 0 || offset >
			len(content) || n < 0 || n > len(content[offset:]) {
			return nil, fmt.Errorf("invalid BER content window")
		}

		offset += n
	}
	if len(result) < 1 || len(result) > 16 {
		if constraintErr := ber.CheckDecodedCollectionLength(opts, "MDT-Allowed-PLMNId-List", "SIZE (1..16)", len(result)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	decoded := &OMMDTAllowedPLMNIdList{Values: result}
	if ber.BERNeedsPreservation(opts) {
		var snapshotReports ber.ViolationLog
		snapshot, snapshotErr := MarshalBEROMMDTAllowedPLMNIdList(decoded, ber.WithConstraintTolerance(&snapshotReports))
		if snapshotErr != nil {
			return nil, snapshotErr
		}
		decoded.berOriginal_ = append([]byte(nil), data...)
		decoded.berSnapshot_ = snapshot
	}
	return decoded, nil
}

// MarshalBER encodes OMAreaScope to BER format.
func (v *OMAreaScope) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: OMAreaScope receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *OMAreaScope) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
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
		enc_cgilist, err := MarshalBEROMCGIList(v.CgiList, ber.ParentCollectionSizeEncodeOptions(ber.ChildEncodeOptions(opts, "cgi-List"))...)
		if err != nil {
			return nil, qualifyBERError(err, "cgi-List", "encoding", false)
		}
		if ber.BERReplayEnabled(opts) && v.CgiListIndef_ {
			// Strip the outer SEQUENCE tag from marshalBER output to get raw children.
			_, _, seqContent_, tlvErr_ := ber.DecodeEncodedTLV(enc_cgilist)
			if tlvErr_ != nil {
				return nil, tlvErr_
			}
			{
				var encodeErr error
				enc_cgilist, encodeErr = ber.EncodeConstructedIndefinite(tag.Tag{Class: tag.ClassContextSpecific, Number: 0}, seqContent_)
				if encodeErr != nil {
					return nil, qualifyBERError(encodeErr, "cgi-List", "encoding", false)
				}
			}
		} else {
			retagged_enc_cgilist, tagErr_enc_cgilist := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_cgilist)
			if tagErr_enc_cgilist != nil {
				return nil, qualifyBERError(tagErr_enc_cgilist, "cgi-List", "encoding", false)
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
		enc_eutrancgilist, err := MarshalBEROMEUTRANCGIList(v.EUtranCgiList, ber.ParentCollectionSizeEncodeOptions(ber.ChildEncodeOptions(opts, "e-utran-cgi-List"))...)
		if err != nil {
			return nil, qualifyBERError(err, "e-utran-cgi-List", "encoding", false)
		}
		if ber.BERReplayEnabled(opts) && v.EUtranCgiListIndef_ {
			// Strip the outer SEQUENCE tag from marshalBER output to get raw children.
			_, _, seqContent_, tlvErr_ := ber.DecodeEncodedTLV(enc_eutrancgilist)
			if tlvErr_ != nil {
				return nil, tlvErr_
			}
			{
				var encodeErr error
				enc_eutrancgilist, encodeErr = ber.EncodeConstructedIndefinite(tag.Tag{Class: tag.ClassContextSpecific, Number: 1}, seqContent_)
				if encodeErr != nil {
					return nil, qualifyBERError(encodeErr, "e-utran-cgi-List", "encoding", false)
				}
			}
		} else {
			retagged_enc_eutrancgilist, tagErr_enc_eutrancgilist := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_eutrancgilist)
			if tagErr_enc_eutrancgilist != nil {
				return nil, qualifyBERError(tagErr_enc_eutrancgilist, "e-utran-cgi-List", "encoding", false)
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
		enc_routingareaidlist, err := MarshalBEROMRoutingAreaIdList(v.RoutingAreaIdList, ber.ParentCollectionSizeEncodeOptions(ber.ChildEncodeOptions(opts, "routingAreaId-List"))...)
		if err != nil {
			return nil, qualifyBERError(err, "routingAreaId-List", "encoding", false)
		}
		if ber.BERReplayEnabled(opts) && v.RoutingAreaIdListIndef_ {
			// Strip the outer SEQUENCE tag from marshalBER output to get raw children.
			_, _, seqContent_, tlvErr_ := ber.DecodeEncodedTLV(enc_routingareaidlist)
			if tlvErr_ != nil {
				return nil, tlvErr_
			}
			{
				var encodeErr error
				enc_routingareaidlist, encodeErr = ber.EncodeConstructedIndefinite(tag.Tag{Class: tag.ClassContextSpecific, Number: 2}, seqContent_)
				if encodeErr != nil {
					return nil, qualifyBERError(encodeErr, "routingAreaId-List", "encoding", false)
				}
			}
		} else {
			retagged_enc_routingareaidlist, tagErr_enc_routingareaidlist := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_routingareaidlist)
			if tagErr_enc_routingareaidlist != nil {
				return nil, qualifyBERError(tagErr_enc_routingareaidlist, "routingAreaId-List", "encoding", false)
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
		enc_locationareaidlist, err := MarshalBEROMLocationAreaIdList(v.LocationAreaIdList, ber.ParentCollectionSizeEncodeOptions(ber.ChildEncodeOptions(opts, "locationAreaId-List"))...)
		if err != nil {
			return nil, qualifyBERError(err, "locationAreaId-List", "encoding", false)
		}
		if ber.BERReplayEnabled(opts) && v.LocationAreaIdListIndef_ {
			// Strip the outer SEQUENCE tag from marshalBER output to get raw children.
			_, _, seqContent_, tlvErr_ := ber.DecodeEncodedTLV(enc_locationareaidlist)
			if tlvErr_ != nil {
				return nil, tlvErr_
			}
			{
				var encodeErr error
				enc_locationareaidlist, encodeErr = ber.EncodeConstructedIndefinite(tag.Tag{Class: tag.ClassContextSpecific, Number: 3}, seqContent_)
				if encodeErr != nil {
					return nil, qualifyBERError(encodeErr, "locationAreaId-List", "encoding", false)
				}
			}
		} else {
			retagged_enc_locationareaidlist, tagErr_enc_locationareaidlist := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, enc_locationareaidlist)
			if tagErr_enc_locationareaidlist != nil {
				return nil, qualifyBERError(tagErr_enc_locationareaidlist, "locationAreaId-List", "encoding", false)
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
		enc_trackingareaidlist, err := MarshalBEROMTrackingAreaIdList(v.TrackingAreaIdList, ber.ParentCollectionSizeEncodeOptions(ber.ChildEncodeOptions(opts, "trackingAreaId-List"))...)
		if err != nil {
			return nil, qualifyBERError(err, "trackingAreaId-List", "encoding", false)
		}
		if ber.BERReplayEnabled(opts) && v.TrackingAreaIdListIndef_ {
			// Strip the outer SEQUENCE tag from marshalBER output to get raw children.
			_, _, seqContent_, tlvErr_ := ber.DecodeEncodedTLV(enc_trackingareaidlist)
			if tlvErr_ != nil {
				return nil, tlvErr_
			}
			{
				var encodeErr error
				enc_trackingareaidlist, encodeErr = ber.EncodeConstructedIndefinite(tag.Tag{Class: tag.ClassContextSpecific, Number: 4}, seqContent_)
				if encodeErr != nil {
					return nil, qualifyBERError(encodeErr, "trackingAreaId-List", "encoding", false)
				}
			}
		} else {
			retagged_enc_trackingareaidlist, tagErr_enc_trackingareaidlist := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, enc_trackingareaidlist)
			if tagErr_enc_trackingareaidlist != nil {
				return nil, qualifyBERError(tagErr_enc_trackingareaidlist, "trackingAreaId-List", "encoding", false)
			}
			enc_trackingareaidlist = retagged_enc_trackingareaidlist
		}
		children = append(children, enc_trackingareaidlist...)
	}
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalBER(ber.ChildEncodeOptions(opts, "extensionContainer")...)
		if err != nil {
			return nil, qualifyBERError(err, "extensionContainer", "encoding", false)
		}
		retagged_enc_extensioncontainer, tagErr_enc_extensioncontainer := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 5, enc_extensioncontainer)
		if tagErr_enc_extensioncontainer != nil {
			return nil, qualifyBERError(tagErr_enc_extensioncontainer, "extensionContainer", "encoding", false)
		}
		enc_extensioncontainer = retagged_enc_extensioncontainer
		children = append(children, enc_extensioncontainer...)
	}
	for i, ext := range v.ExtData_ {
		if err := ber.CheckBEROpaqueReplay(opts...); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
		peekTag, n, _, extErr := ber.DecodeEncodedTLV(ext)
		if extErr != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, extErr)
		}
		if n != len(ext) {
			return nil, fmt.Errorf("encoding extension %d: %w", i, ber.ErrExtraData)
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: only the first addition is restricted.
		if i == 0 && ((peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 5) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0)) {
			if constraintErr := ber.CheckEncodedValue(opts, "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
				return nil, constraintErr
			}
		}
		children = append(children, ext...)
	}
	return ber.EncodeSequence(children)
}

// MarshalDER encodes OMAreaScope to DER format.
func (v *OMAreaScope) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: OMAreaScope receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if v.CgiList != nil {
		if len((v.CgiList).Values) < 1 || len((v.CgiList).Values) > 32 {
			if constraintErr := ber.CheckEncodedLength(nil, "cgi-List", "SIZE (1..32)", len((v.CgiList).Values)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_cgilist, err := MarshalDEROMCGIList(v.CgiList)
		if err != nil {
			return nil, qualifyBERError(err, "cgi-List", "encoding", true)
		}
		retagged_enc_cgilist, tagErr_enc_cgilist := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_cgilist)
		if tagErr_enc_cgilist != nil {
			return nil, qualifyBERError(tagErr_enc_cgilist, "cgi-List", "encoding", true)
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
		enc_eutrancgilist, err := MarshalDEROMEUTRANCGIList(v.EUtranCgiList)
		if err != nil {
			return nil, qualifyBERError(err, "e-utran-cgi-List", "encoding", true)
		}
		retagged_enc_eutrancgilist, tagErr_enc_eutrancgilist := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_eutrancgilist)
		if tagErr_enc_eutrancgilist != nil {
			return nil, qualifyBERError(tagErr_enc_eutrancgilist, "e-utran-cgi-List", "encoding", true)
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
		enc_routingareaidlist, err := MarshalDEROMRoutingAreaIdList(v.RoutingAreaIdList)
		if err != nil {
			return nil, qualifyBERError(err, "routingAreaId-List", "encoding", true)
		}
		retagged_enc_routingareaidlist, tagErr_enc_routingareaidlist := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_routingareaidlist)
		if tagErr_enc_routingareaidlist != nil {
			return nil, qualifyBERError(tagErr_enc_routingareaidlist, "routingAreaId-List", "encoding", true)
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
		enc_locationareaidlist, err := MarshalDEROMLocationAreaIdList(v.LocationAreaIdList)
		if err != nil {
			return nil, qualifyBERError(err, "locationAreaId-List", "encoding", true)
		}
		retagged_enc_locationareaidlist, tagErr_enc_locationareaidlist := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, enc_locationareaidlist)
		if tagErr_enc_locationareaidlist != nil {
			return nil, qualifyBERError(tagErr_enc_locationareaidlist, "locationAreaId-List", "encoding", true)
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
		enc_trackingareaidlist, err := MarshalDEROMTrackingAreaIdList(v.TrackingAreaIdList)
		if err != nil {
			return nil, qualifyBERError(err, "trackingAreaId-List", "encoding", true)
		}
		retagged_enc_trackingareaidlist, tagErr_enc_trackingareaidlist := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, enc_trackingareaidlist)
		if tagErr_enc_trackingareaidlist != nil {
			return nil, qualifyBERError(tagErr_enc_trackingareaidlist, "trackingAreaId-List", "encoding", true)
		}
		enc_trackingareaidlist = retagged_enc_trackingareaidlist
		children = append(children, enc_trackingareaidlist...)
	}
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalDER()
		if err != nil {
			return nil, qualifyBERError(err, "extensionContainer", "encoding", true)
		}
		retagged_enc_extensioncontainer, tagErr_enc_extensioncontainer := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 5, enc_extensioncontainer)
		if tagErr_enc_extensioncontainer != nil {
			return nil, qualifyBERError(tagErr_enc_extensioncontainer, "extensionContainer", "encoding", true)
		}
		enc_extensioncontainer = retagged_enc_extensioncontainer
		children = append(children, enc_extensioncontainer...)
	}
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDEREncodedElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
		peekTag, _, _, extErr := ber.DecodeEncodedTLV(ext)
		if extErr != nil {
			return nil, extErr
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: only the first addition is restricted.
		if i == 0 && ((peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 5) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0)) {
			if constraintErr := ber.CheckEncodedValue(nil, "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
				return nil, constraintErr
			}
		}
		children = append(children, ext...)
	}
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("%s: %w", "encoding OMAreaScope as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}

// UnmarshalBER decodes OMAreaScope from BER/DER format.
func (v *OMAreaScope) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: OMAreaScope destination is nil", ber.ErrInvalidValue)
	}
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return ber.DiagnosePreflight(err, data, opts, "child", func(probeOpts []ber.DecodeOption) error {
			var probe OMAreaScope
			return probe.UnmarshalBER(data, probeOpts...)
		})
	}
	*v = OMAreaScope{}
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
		return fmt.Errorf("%s: %w", "decoding OMAreaScope SEQUENCE", qualifyBERError(err, "", "decoding", false))
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
				ber.MarkPreflightTarget(opts, "cgi-List", content[offset:])
				decodedTag_cgilist, n_cgilist, rawVal_cgilist, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "cgi-List", "decoding", false)
				}
				if decodedTag_cgilist.Class != tag.ClassContextSpecific || decodedTag_cgilist.Number != 0 || decodedTag_cgilist.Constructed != true {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_cgilist), "cgi-List", "decoding", false)
				}
				reconstructed_cgilist, reconstructionErr_cgilist := ber.EncodeSequence(rawVal_cgilist)
				if reconstructionErr_cgilist != nil {
					return qualifyBERError(reconstructionErr_cgilist, "cgi-List", "decoding", false)
				}
				dec_cgilist, unmErr := UnmarshalBEROMCGIList(reconstructed_cgilist, ber.ParentCollectionSizeDecodeOptions(ber.ChildDecodeOptions(opts, "cgi-List"))...)
				if unmErr != nil {
					return qualifyBERError(unmErr, "cgi-List", "decoding", false)
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
				ber.MarkPreflightTarget(opts, "e-utran-cgi-List", content[offset:])
				decodedTag_eutrancgilist, n_eutrancgilist, rawVal_eutrancgilist, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "e-utran-cgi-List", "decoding", false)
				}
				if decodedTag_eutrancgilist.Class != tag.ClassContextSpecific || decodedTag_eutrancgilist.Number != 1 || decodedTag_eutrancgilist.Constructed != true {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_eutrancgilist), "e-utran-cgi-List", "decoding", false)
				}
				reconstructed_eutrancgilist, reconstructionErr_eutrancgilist := ber.EncodeSequence(rawVal_eutrancgilist)
				if reconstructionErr_eutrancgilist != nil {
					return qualifyBERError(reconstructionErr_eutrancgilist, "e-utran-cgi-List", "decoding", false)
				}
				dec_eutrancgilist, unmErr := UnmarshalBEROMEUTRANCGIList(reconstructed_eutrancgilist, ber.ParentCollectionSizeDecodeOptions(ber.ChildDecodeOptions(opts, "e-utran-cgi-List"))...)
				if unmErr != nil {
					return qualifyBERError(unmErr, "e-utran-cgi-List", "decoding", false)
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
				ber.MarkPreflightTarget(opts, "routingAreaId-List", content[offset:])
				decodedTag_routingareaidlist, n_routingareaidlist, rawVal_routingareaidlist, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "routingAreaId-List", "decoding", false)
				}
				if decodedTag_routingareaidlist.Class != tag.ClassContextSpecific || decodedTag_routingareaidlist.Number != 2 || decodedTag_routingareaidlist.Constructed != true {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_routingareaidlist), "routingAreaId-List", "decoding", false)
				}
				reconstructed_routingareaidlist, reconstructionErr_routingareaidlist := ber.EncodeSequence(rawVal_routingareaidlist)
				if reconstructionErr_routingareaidlist != nil {
					return qualifyBERError(reconstructionErr_routingareaidlist, "routingAreaId-List", "decoding", false)
				}
				dec_routingareaidlist, unmErr := UnmarshalBEROMRoutingAreaIdList(reconstructed_routingareaidlist, ber.ParentCollectionSizeDecodeOptions(ber.ChildDecodeOptions(opts, "routingAreaId-List"))...)
				if unmErr != nil {
					return qualifyBERError(unmErr, "routingAreaId-List", "decoding", false)
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
				ber.MarkPreflightTarget(opts, "locationAreaId-List", content[offset:])
				decodedTag_locationareaidlist, n_locationareaidlist, rawVal_locationareaidlist, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "locationAreaId-List", "decoding", false)
				}
				if decodedTag_locationareaidlist.Class != tag.ClassContextSpecific || decodedTag_locationareaidlist.Number != 3 || decodedTag_locationareaidlist.Constructed != true {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_locationareaidlist), "locationAreaId-List", "decoding", false)
				}
				reconstructed_locationareaidlist, reconstructionErr_locationareaidlist := ber.EncodeSequence(rawVal_locationareaidlist)
				if reconstructionErr_locationareaidlist != nil {
					return qualifyBERError(reconstructionErr_locationareaidlist, "locationAreaId-List", "decoding", false)
				}
				dec_locationareaidlist, unmErr := UnmarshalBEROMLocationAreaIdList(reconstructed_locationareaidlist, ber.ParentCollectionSizeDecodeOptions(ber.ChildDecodeOptions(opts, "locationAreaId-List"))...)
				if unmErr != nil {
					return qualifyBERError(unmErr, "locationAreaId-List", "decoding", false)
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
				ber.MarkPreflightTarget(opts, "trackingAreaId-List", content[offset:])
				decodedTag_trackingareaidlist, n_trackingareaidlist, rawVal_trackingareaidlist, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "trackingAreaId-List", "decoding", false)
				}
				if decodedTag_trackingareaidlist.Class != tag.ClassContextSpecific || decodedTag_trackingareaidlist.Number != 4 || decodedTag_trackingareaidlist.Constructed != true {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_trackingareaidlist), "trackingAreaId-List", "decoding", false)
				}
				reconstructed_trackingareaidlist, reconstructionErr_trackingareaidlist := ber.EncodeSequence(rawVal_trackingareaidlist)
				if reconstructionErr_trackingareaidlist != nil {
					return qualifyBERError(reconstructionErr_trackingareaidlist, "trackingAreaId-List", "decoding", false)
				}
				dec_trackingareaidlist, unmErr := UnmarshalBEROMTrackingAreaIdList(reconstructed_trackingareaidlist, ber.ParentCollectionSizeDecodeOptions(ber.ChildDecodeOptions(opts, "trackingAreaId-List"))...)
				if unmErr != nil {
					return qualifyBERError(unmErr, "trackingAreaId-List", "decoding", false)
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
				ber.MarkPreflightTarget(opts, "extensionContainer", content[offset:])
				decodedTag_extensioncontainer, n_extensioncontainer, rawVal_extensioncontainer, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "extensionContainer", "decoding", false)
				}
				if decodedTag_extensioncontainer.Class != tag.ClassContextSpecific || decodedTag_extensioncontainer.Number != 5 || decodedTag_extensioncontainer.Constructed != true {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_extensioncontainer), "extensionContainer", "decoding", false)
				}
				reconstructed_extensioncontainer, reconstructionErr_extensioncontainer := ber.EncodeSequence(rawVal_extensioncontainer)
				if reconstructionErr_extensioncontainer != nil {
					return qualifyBERError(reconstructionErr_extensioncontainer, "extensionContainer", "decoding", false)
				}
				var dec_extensioncontainer v21_map_extensiondatatypes.ExtensionDataTypesExtensionContainer
				if unmErr := dec_extensioncontainer.UnmarshalBER(reconstructed_extensioncontainer, ber.ChildDecodeOptions(opts, "extensionContainer")...); unmErr != nil {
					return qualifyBERError(unmErr, "extensionContainer", "decoding", false)
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
		peekTag, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:], opts...)
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "OMAreaScope", Cause: extErr_}
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: the first unknown addition must differ from trailing OPTIONAL/DEFAULT tags.
		if len(v.ExtData_) == 0 && ((peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 5) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0)) {
			if !ber.ConstraintToleranceEnabled(opts) {
				return &ber.DecodeError{Offset: offset, TypeName: "OMAreaScope", Cause: fmt.Errorf("%w: repeated or out-of-order SEQUENCE component tag %s", ber.ErrInvalidTag, peekTag)}
			}
			if orderErr_ := ber.CheckDecodedValue(opts, fmt.Sprintf("ExtData_[%d]", len(v.ExtData_)), "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); orderErr_ != nil {
				return orderErr_
			}
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

// MarshalBEROMCGIList encodes a OMCGIList list to BER.
func MarshalBEROMCGIList(collection *OMCGIList, opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	if collection == nil {
		return nil, fmt.Errorf("%w: required collection is nil", ber.ErrInvalidValue)
	}
	encoded, err := marshalBEROMCGIList(collection, opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, collection.berOriginal_, collection.berSnapshot_, opts), nil
}
func marshalBEROMCGIList(collection *OMCGIList, opts ...ber.EncodeOption) ([]byte, error) {
	list := collection.Values
	if len(list) < 1 || len(list) > 32 {
		if constraintErr := ber.CheckEncodedCollectionLength(opts, "CGI-List", "SIZE (1..32)", len(list)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	var children []byte
	for elemIndex, elem := range list {
		_ = elemIndex
		if len(elem) < 5 || len(elem) > 7 {
			if constraintErr := ber.CheckEncodedLength(opts, fmt.Sprintf("element[%d]", elemIndex), "SIZE (5..7)", len(elem)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		encodedElem, encodeErr_encodedElem := ber.EncodeOctetString([]byte(elem))
		if encodeErr_encodedElem != nil {
			return nil, qualifyBERError(encodeErr_encodedElem, fmt.Sprintf("element[%d]",
				elemIndex),

				"encoding", false)
		}
		children = append(children, encodedElem...)
	}
	return ber.EncodeSequence(children)
}

// MarshalDEROMCGIList encodes a OMCGIList list to DER.
func MarshalDEROMCGIList(collection *OMCGIList) ([]byte, error) {
	if collection == nil {
		return nil, fmt.Errorf("%w: required collection is nil", ber.ErrInvalidValue)
	}
	list := collection.Values
	if len(list) < 1 || len(list) > 32 {
		if constraintErr := ber.CheckEncodedCollectionLength(nil, "CGI-List", "SIZE (1..32)", len(list)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	var children []byte
	for elemIndex, elem := range list {
		_ = elemIndex
		if len(elem) < 5 || len(elem) > 7 {
			if constraintErr := ber.CheckEncodedLength(nil, fmt.Sprintf("element[%d]", elemIndex), "SIZE (5..7)", len(elem)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		encodedElem, encodeErr_encodedElem := ber.EncodeOctetString([]byte(elem))
		if encodeErr_encodedElem != nil {
			return nil, qualifyBERError(encodeErr_encodedElem, fmt.Sprintf("element[%d]",
				elemIndex),

				"encoding", true)
		}
		children = append(children, encodedElem...)
	}
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("%s: %w", "encoding OMCGIList as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}

// UnmarshalBEROMCGIList decodes a OMCGIList list from BER.
func UnmarshalBEROMCGIList(data []byte, opts ...ber.DecodeOption) (returnValue *OMCGIList, returnErr error) {
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return nil, ber.DiagnosePreflight(err, data, opts, "element", func(probeOpts []ber.DecodeOption) error {
			_, probeErr := UnmarshalBEROMCGIList(data, probeOpts...)
			return probeErr
		})
	}
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", "decoding OMCGIList", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return nil, &ber.DecodeError{Offset: total, TypeName: "OMCGIList", Cause: ber.ErrExtraData}
	}
	var result []v21_map_commondatatypes.CommonDataTypesGlobalCellId
	offset := 0
	for offset < len(content) {
		elementIndex := len(result)
		_ = elementIndex
		elementData := content[offset:]
		ber.MarkPreflightElement(opts, elementIndex, elementData)
		val, n, osErr := ber.DecodeOctetString(elementData, opts...)
		if osErr != nil {
			return nil, qualifyBERError(osErr, fmt.Sprintf("element[%d]",
				elementIndex),

				"decoding", false)
		}
		if len(val) < 5 || len(val) > 7 {
			if constraintErr := ber.CheckDecodedLength(opts, fmt.Sprintf("element[%d]", len(result)), "SIZE (5..7)", len(val)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		result = append(result, v21_map_commondatatypes.CommonDataTypesGlobalCellId(val))
		if offset < 0 || offset >
			len(content) || n < 0 || n > len(content[offset:]) {
			return nil, fmt.Errorf("invalid BER content window")
		}

		offset += n
	}
	if len(result) < 1 || len(result) > 32 {
		if constraintErr := ber.CheckDecodedCollectionLength(opts, "CGI-List", "SIZE (1..32)", len(result)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	decoded := &OMCGIList{Values: result}
	if ber.BERNeedsPreservation(opts) {
		var snapshotReports ber.ViolationLog
		snapshot, snapshotErr := MarshalBEROMCGIList(decoded, ber.WithConstraintTolerance(&snapshotReports))
		if snapshotErr != nil {
			return nil, snapshotErr
		}
		decoded.berOriginal_ = append([]byte(nil), data...)
		decoded.berSnapshot_ = snapshot
	}
	return decoded, nil
}

// MarshalBEROMEUTRANCGIList encodes a OMEUTRANCGIList list to BER.
func MarshalBEROMEUTRANCGIList(collection *OMEUTRANCGIList, opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	if collection == nil {
		return nil, fmt.Errorf("%w: required collection is nil", ber.ErrInvalidValue)
	}
	encoded, err := marshalBEROMEUTRANCGIList(collection, opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, collection.berOriginal_, collection.berSnapshot_, opts), nil
}
func marshalBEROMEUTRANCGIList(collection *OMEUTRANCGIList, opts ...ber.EncodeOption) ([]byte, error) {
	list := collection.Values
	if len(list) < 1 || len(list) > 32 {
		if constraintErr := ber.CheckEncodedCollectionLength(opts, "E-UTRAN-CGI-List", "SIZE (1..32)", len(list)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	var children []byte
	for elemIndex, elem := range list {
		_ = elemIndex
		if len(elem) < 7 || len(elem) > 7 {
			if constraintErr := ber.CheckEncodedLength(opts, fmt.Sprintf("element[%d]", elemIndex), "SIZE (7)", len(elem)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		encodedElem, encodeErr_encodedElem := ber.EncodeOctetString([]byte(elem))
		if encodeErr_encodedElem != nil {
			return nil, qualifyBERError(encodeErr_encodedElem, fmt.Sprintf("element[%d]",
				elemIndex),

				"encoding", false)
		}
		children = append(children, encodedElem...)
	}
	return ber.EncodeSequence(children)
}

// MarshalDEROMEUTRANCGIList encodes a OMEUTRANCGIList list to DER.
func MarshalDEROMEUTRANCGIList(collection *OMEUTRANCGIList) ([]byte, error) {
	if collection == nil {
		return nil, fmt.Errorf("%w: required collection is nil", ber.ErrInvalidValue)
	}
	list := collection.Values
	if len(list) < 1 || len(list) > 32 {
		if constraintErr := ber.CheckEncodedCollectionLength(nil, "E-UTRAN-CGI-List", "SIZE (1..32)", len(list)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	var children []byte
	for elemIndex, elem := range list {
		_ = elemIndex
		if len(elem) < 7 || len(elem) > 7 {
			if constraintErr := ber.CheckEncodedLength(nil, fmt.Sprintf("element[%d]", elemIndex), "SIZE (7)", len(elem)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		encodedElem, encodeErr_encodedElem := ber.EncodeOctetString([]byte(elem))
		if encodeErr_encodedElem != nil {
			return nil, qualifyBERError(encodeErr_encodedElem, fmt.Sprintf("element[%d]",
				elemIndex),

				"encoding", true)
		}
		children = append(children, encodedElem...)
	}
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("%s: %w", "encoding OMEUTRANCGIList as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}

// UnmarshalBEROMEUTRANCGIList decodes a OMEUTRANCGIList list from BER.
func UnmarshalBEROMEUTRANCGIList(data []byte, opts ...ber.DecodeOption) (returnValue *OMEUTRANCGIList, returnErr error) {
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return nil, ber.DiagnosePreflight(err, data, opts, "element", func(probeOpts []ber.DecodeOption) error {
			_, probeErr := UnmarshalBEROMEUTRANCGIList(data, probeOpts...)
			return probeErr
		})
	}
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", "decoding OMEUTRANCGIList", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return nil, &ber.DecodeError{Offset: total, TypeName: "OMEUTRANCGIList", Cause: ber.ErrExtraData}
	}
	var result []v21_map_commondatatypes.CommonDataTypesEUTRANCGI
	offset := 0
	for offset < len(content) {
		elementIndex := len(result)
		_ = elementIndex
		elementData := content[offset:]
		ber.MarkPreflightElement(opts, elementIndex, elementData)
		val, n, osErr := ber.DecodeOctetString(elementData, opts...)
		if osErr != nil {
			return nil, qualifyBERError(osErr, fmt.Sprintf("element[%d]",
				elementIndex),

				"decoding", false)
		}
		if len(val) < 7 || len(val) > 7 {
			if constraintErr := ber.CheckDecodedLength(opts, fmt.Sprintf("element[%d]", len(result)), "SIZE (7)", len(val)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		result = append(result, v21_map_commondatatypes.CommonDataTypesEUTRANCGI(val))
		if offset < 0 || offset >
			len(content) || n < 0 || n > len(content[offset:]) {
			return nil, fmt.Errorf("invalid BER content window")
		}

		offset += n
	}
	if len(result) < 1 || len(result) > 32 {
		if constraintErr := ber.CheckDecodedCollectionLength(opts, "E-UTRAN-CGI-List", "SIZE (1..32)", len(result)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	decoded := &OMEUTRANCGIList{Values: result}
	if ber.BERNeedsPreservation(opts) {
		var snapshotReports ber.ViolationLog
		snapshot, snapshotErr := MarshalBEROMEUTRANCGIList(decoded, ber.WithConstraintTolerance(&snapshotReports))
		if snapshotErr != nil {
			return nil, snapshotErr
		}
		decoded.berOriginal_ = append([]byte(nil), data...)
		decoded.berSnapshot_ = snapshot
	}
	return decoded, nil
}

// MarshalBEROMRoutingAreaIdList encodes a OMRoutingAreaIdList list to BER.
func MarshalBEROMRoutingAreaIdList(collection *OMRoutingAreaIdList, opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	if collection == nil {
		return nil, fmt.Errorf("%w: required collection is nil", ber.ErrInvalidValue)
	}
	encoded, err := marshalBEROMRoutingAreaIdList(collection, opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, collection.berOriginal_, collection.berSnapshot_, opts), nil
}
func marshalBEROMRoutingAreaIdList(collection *OMRoutingAreaIdList, opts ...ber.EncodeOption) ([]byte, error) {
	list := collection.Values
	if len(list) < 1 || len(list) > 8 {
		if constraintErr := ber.CheckEncodedCollectionLength(opts, "RoutingAreaId-List", "SIZE (1..8)", len(list)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	var children []byte
	for elemIndex, elem := range list {
		_ = elemIndex
		if len(elem) < 6 || len(elem) > 6 {
			if constraintErr := ber.CheckEncodedLength(opts, fmt.Sprintf("element[%d]", elemIndex), "SIZE (6)", len(elem)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		encodedElem, encodeErr_encodedElem := ber.EncodeOctetString([]byte(elem))
		if encodeErr_encodedElem != nil {
			return nil, qualifyBERError(encodeErr_encodedElem, fmt.Sprintf("element[%d]",
				elemIndex),

				"encoding", false)
		}
		children = append(children, encodedElem...)
	}
	return ber.EncodeSequence(children)
}

// MarshalDEROMRoutingAreaIdList encodes a OMRoutingAreaIdList list to DER.
func MarshalDEROMRoutingAreaIdList(collection *OMRoutingAreaIdList) ([]byte, error) {
	if collection == nil {
		return nil, fmt.Errorf("%w: required collection is nil", ber.ErrInvalidValue)
	}
	list := collection.Values
	if len(list) < 1 || len(list) > 8 {
		if constraintErr := ber.CheckEncodedCollectionLength(nil, "RoutingAreaId-List", "SIZE (1..8)", len(list)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	var children []byte
	for elemIndex, elem := range list {
		_ = elemIndex
		if len(elem) < 6 || len(elem) > 6 {
			if constraintErr := ber.CheckEncodedLength(nil, fmt.Sprintf("element[%d]", elemIndex), "SIZE (6)", len(elem)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		encodedElem, encodeErr_encodedElem := ber.EncodeOctetString([]byte(elem))
		if encodeErr_encodedElem != nil {
			return nil, qualifyBERError(encodeErr_encodedElem, fmt.Sprintf("element[%d]",
				elemIndex),

				"encoding", true)
		}
		children = append(children, encodedElem...)
	}
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("%s: %w", "encoding OMRoutingAreaIdList as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}

// UnmarshalBEROMRoutingAreaIdList decodes a OMRoutingAreaIdList list from BER.
func UnmarshalBEROMRoutingAreaIdList(data []byte, opts ...ber.DecodeOption) (returnValue *OMRoutingAreaIdList, returnErr error) {
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return nil, ber.DiagnosePreflight(err, data, opts, "element", func(probeOpts []ber.DecodeOption) error {
			_, probeErr := UnmarshalBEROMRoutingAreaIdList(data, probeOpts...)
			return probeErr
		})
	}
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", "decoding OMRoutingAreaIdList", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return nil, &ber.DecodeError{Offset: total, TypeName: "OMRoutingAreaIdList", Cause: ber.ErrExtraData}
	}
	var result []v21_map_commondatatypes.CommonDataTypesRAIdentity
	offset := 0
	for offset < len(content) {
		elementIndex := len(result)
		_ = elementIndex
		elementData := content[offset:]
		ber.MarkPreflightElement(opts, elementIndex, elementData)
		val, n, osErr := ber.DecodeOctetString(elementData, opts...)
		if osErr != nil {
			return nil, qualifyBERError(osErr, fmt.Sprintf("element[%d]",
				elementIndex),

				"decoding", false)
		}
		if len(val) < 6 || len(val) > 6 {
			if constraintErr := ber.CheckDecodedLength(opts, fmt.Sprintf("element[%d]", len(result)), "SIZE (6)", len(val)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		result = append(result, v21_map_commondatatypes.CommonDataTypesRAIdentity(val))
		if offset < 0 || offset >
			len(content) || n < 0 || n > len(content[offset:]) {
			return nil, fmt.Errorf("invalid BER content window")
		}

		offset += n
	}
	if len(result) < 1 || len(result) > 8 {
		if constraintErr := ber.CheckDecodedCollectionLength(opts, "RoutingAreaId-List", "SIZE (1..8)", len(result)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	decoded := &OMRoutingAreaIdList{Values: result}
	if ber.BERNeedsPreservation(opts) {
		var snapshotReports ber.ViolationLog
		snapshot, snapshotErr := MarshalBEROMRoutingAreaIdList(decoded, ber.WithConstraintTolerance(&snapshotReports))
		if snapshotErr != nil {
			return nil, snapshotErr
		}
		decoded.berOriginal_ = append([]byte(nil), data...)
		decoded.berSnapshot_ = snapshot
	}
	return decoded, nil
}

// MarshalBEROMLocationAreaIdList encodes a OMLocationAreaIdList list to BER.
func MarshalBEROMLocationAreaIdList(collection *OMLocationAreaIdList, opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	if collection == nil {
		return nil, fmt.Errorf("%w: required collection is nil", ber.ErrInvalidValue)
	}
	encoded, err := marshalBEROMLocationAreaIdList(collection, opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, collection.berOriginal_, collection.berSnapshot_, opts), nil
}
func marshalBEROMLocationAreaIdList(collection *OMLocationAreaIdList, opts ...ber.EncodeOption) ([]byte, error) {
	list := collection.Values
	if len(list) < 1 || len(list) > 8 {
		if constraintErr := ber.CheckEncodedCollectionLength(opts, "LocationAreaId-List", "SIZE (1..8)", len(list)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	var children []byte
	for elemIndex, elem := range list {
		_ = elemIndex
		if len(elem) < 5 || len(elem) > 5 {
			if constraintErr := ber.CheckEncodedLength(opts, fmt.Sprintf("element[%d]", elemIndex), "SIZE (5)", len(elem)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		encodedElem, encodeErr_encodedElem := ber.EncodeOctetString([]byte(elem))
		if encodeErr_encodedElem != nil {
			return nil, qualifyBERError(encodeErr_encodedElem, fmt.Sprintf("element[%d]",
				elemIndex),

				"encoding", false)
		}
		children = append(children, encodedElem...)
	}
	return ber.EncodeSequence(children)
}

// MarshalDEROMLocationAreaIdList encodes a OMLocationAreaIdList list to DER.
func MarshalDEROMLocationAreaIdList(collection *OMLocationAreaIdList) ([]byte, error) {
	if collection == nil {
		return nil, fmt.Errorf("%w: required collection is nil", ber.ErrInvalidValue)
	}
	list := collection.Values
	if len(list) < 1 || len(list) > 8 {
		if constraintErr := ber.CheckEncodedCollectionLength(nil, "LocationAreaId-List", "SIZE (1..8)", len(list)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	var children []byte
	for elemIndex, elem := range list {
		_ = elemIndex
		if len(elem) < 5 || len(elem) > 5 {
			if constraintErr := ber.CheckEncodedLength(nil, fmt.Sprintf("element[%d]", elemIndex), "SIZE (5)", len(elem)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		encodedElem, encodeErr_encodedElem := ber.EncodeOctetString([]byte(elem))
		if encodeErr_encodedElem != nil {
			return nil, qualifyBERError(encodeErr_encodedElem, fmt.Sprintf("element[%d]",
				elemIndex),

				"encoding", true)
		}
		children = append(children, encodedElem...)
	}
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("%s: %w", "encoding OMLocationAreaIdList as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}

// UnmarshalBEROMLocationAreaIdList decodes a OMLocationAreaIdList list from BER.
func UnmarshalBEROMLocationAreaIdList(data []byte, opts ...ber.DecodeOption) (returnValue *OMLocationAreaIdList, returnErr error) {
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return nil, ber.DiagnosePreflight(err, data, opts, "element", func(probeOpts []ber.DecodeOption) error {
			_, probeErr := UnmarshalBEROMLocationAreaIdList(data, probeOpts...)
			return probeErr
		})
	}
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", "decoding OMLocationAreaIdList", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return nil, &ber.DecodeError{Offset: total, TypeName: "OMLocationAreaIdList", Cause: ber.ErrExtraData}
	}
	var result []v21_map_commondatatypes.CommonDataTypesLAIFixedLength
	offset := 0
	for offset < len(content) {
		elementIndex := len(result)
		_ = elementIndex
		elementData := content[offset:]
		ber.MarkPreflightElement(opts, elementIndex, elementData)
		val, n, osErr := ber.DecodeOctetString(elementData, opts...)
		if osErr != nil {
			return nil, qualifyBERError(osErr, fmt.Sprintf("element[%d]",
				elementIndex),

				"decoding", false)
		}
		if len(val) < 5 || len(val) > 5 {
			if constraintErr := ber.CheckDecodedLength(opts, fmt.Sprintf("element[%d]", len(result)), "SIZE (5)", len(val)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		result = append(result, v21_map_commondatatypes.CommonDataTypesLAIFixedLength(val))
		if offset < 0 || offset >
			len(content) || n < 0 || n > len(content[offset:]) {
			return nil, fmt.Errorf("invalid BER content window")
		}

		offset += n
	}
	if len(result) < 1 || len(result) > 8 {
		if constraintErr := ber.CheckDecodedCollectionLength(opts, "LocationAreaId-List", "SIZE (1..8)", len(result)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	decoded := &OMLocationAreaIdList{Values: result}
	if ber.BERNeedsPreservation(opts) {
		var snapshotReports ber.ViolationLog
		snapshot, snapshotErr := MarshalBEROMLocationAreaIdList(decoded, ber.WithConstraintTolerance(&snapshotReports))
		if snapshotErr != nil {
			return nil, snapshotErr
		}
		decoded.berOriginal_ = append([]byte(nil), data...)
		decoded.berSnapshot_ = snapshot
	}
	return decoded, nil
}

// MarshalBEROMTrackingAreaIdList encodes a OMTrackingAreaIdList list to BER.
func MarshalBEROMTrackingAreaIdList(collection *OMTrackingAreaIdList, opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	if collection == nil {
		return nil, fmt.Errorf("%w: required collection is nil", ber.ErrInvalidValue)
	}
	encoded, err := marshalBEROMTrackingAreaIdList(collection, opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, collection.berOriginal_, collection.berSnapshot_, opts), nil
}
func marshalBEROMTrackingAreaIdList(collection *OMTrackingAreaIdList, opts ...ber.EncodeOption) ([]byte, error) {
	list := collection.Values
	if len(list) < 1 || len(list) > 8 {
		if constraintErr := ber.CheckEncodedCollectionLength(opts, "TrackingAreaId-List", "SIZE (1..8)", len(list)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	var children []byte
	for elemIndex, elem := range list {
		_ = elemIndex
		if len(elem) < 5 || len(elem) > 5 {
			if constraintErr := ber.CheckEncodedLength(opts, fmt.Sprintf("element[%d]", elemIndex), "SIZE (5)", len(elem)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		encodedElem, encodeErr_encodedElem := ber.EncodeOctetString([]byte(elem))
		if encodeErr_encodedElem != nil {
			return nil, qualifyBERError(encodeErr_encodedElem, fmt.Sprintf("element[%d]",
				elemIndex),

				"encoding", false)
		}
		children = append(children, encodedElem...)
	}
	return ber.EncodeSequence(children)
}

// MarshalDEROMTrackingAreaIdList encodes a OMTrackingAreaIdList list to DER.
func MarshalDEROMTrackingAreaIdList(collection *OMTrackingAreaIdList) ([]byte, error) {
	if collection == nil {
		return nil, fmt.Errorf("%w: required collection is nil", ber.ErrInvalidValue)
	}
	list := collection.Values
	if len(list) < 1 || len(list) > 8 {
		if constraintErr := ber.CheckEncodedCollectionLength(nil, "TrackingAreaId-List", "SIZE (1..8)", len(list)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	var children []byte
	for elemIndex, elem := range list {
		_ = elemIndex
		if len(elem) < 5 || len(elem) > 5 {
			if constraintErr := ber.CheckEncodedLength(nil, fmt.Sprintf("element[%d]", elemIndex), "SIZE (5)", len(elem)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		encodedElem, encodeErr_encodedElem := ber.EncodeOctetString([]byte(elem))
		if encodeErr_encodedElem != nil {
			return nil, qualifyBERError(encodeErr_encodedElem, fmt.Sprintf("element[%d]",
				elemIndex),

				"encoding", true)
		}
		children = append(children, encodedElem...)
	}
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("%s: %w", "encoding OMTrackingAreaIdList as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}

// UnmarshalBEROMTrackingAreaIdList decodes a OMTrackingAreaIdList list from BER.
func UnmarshalBEROMTrackingAreaIdList(data []byte, opts ...ber.DecodeOption) (returnValue *OMTrackingAreaIdList, returnErr error) {
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return nil, ber.DiagnosePreflight(err, data, opts, "element", func(probeOpts []ber.DecodeOption) error {
			_, probeErr := UnmarshalBEROMTrackingAreaIdList(data, probeOpts...)
			return probeErr
		})
	}
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", "decoding OMTrackingAreaIdList", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return nil, &ber.DecodeError{Offset: total, TypeName: "OMTrackingAreaIdList", Cause: ber.ErrExtraData}
	}
	var result []v21_map_commondatatypes.CommonDataTypesTAId
	offset := 0
	for offset < len(content) {
		elementIndex := len(result)
		_ = elementIndex
		elementData := content[offset:]
		ber.MarkPreflightElement(opts, elementIndex, elementData)
		val, n, osErr := ber.DecodeOctetString(elementData, opts...)
		if osErr != nil {
			return nil, qualifyBERError(osErr, fmt.Sprintf("element[%d]",
				elementIndex),

				"decoding", false)
		}
		if len(val) < 5 || len(val) > 5 {
			if constraintErr := ber.CheckDecodedLength(opts, fmt.Sprintf("element[%d]", len(result)), "SIZE (5)", len(val)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		result = append(result, v21_map_commondatatypes.CommonDataTypesTAId(val))
		if offset < 0 || offset >
			len(content) || n < 0 || n > len(content[offset:]) {
			return nil, fmt.Errorf("invalid BER content window")
		}

		offset += n
	}
	if len(result) < 1 || len(result) > 8 {
		if constraintErr := ber.CheckDecodedCollectionLength(opts, "TrackingAreaId-List", "SIZE (1..8)", len(result)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	decoded := &OMTrackingAreaIdList{Values: result}
	if ber.BERNeedsPreservation(opts) {
		var snapshotReports ber.ViolationLog
		snapshot, snapshotErr := MarshalBEROMTrackingAreaIdList(decoded, ber.WithConstraintTolerance(&snapshotReports))
		if snapshotErr != nil {
			return nil, snapshotErr
		}
		decoded.berOriginal_ = append([]byte(nil), data...)
		decoded.berSnapshot_ = snapshot
	}
	return decoded, nil
}

// MarshalBER encodes OMTraceDepthList to BER format.
func (v *OMTraceDepthList) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: OMTraceDepthList receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *OMTraceDepthList) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if v.MscSTraceDepth != nil {
		enc_mscstracedepth := ber.EncodeEnumerated(int64(*v.MscSTraceDepth))
		retagged_enc_mscstracedepth, tagErr_enc_mscstracedepth := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_mscstracedepth)
		if tagErr_enc_mscstracedepth != nil {
			return nil, qualifyBERError(tagErr_enc_mscstracedepth, "msc-s-TraceDepth", "encoding", false)
		}
		enc_mscstracedepth = retagged_enc_mscstracedepth
		children = append(children, enc_mscstracedepth...)
	}
	if v.MgwTraceDepth != nil {
		enc_mgwtracedepth := ber.EncodeEnumerated(int64(*v.MgwTraceDepth))
		retagged_enc_mgwtracedepth, tagErr_enc_mgwtracedepth := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_mgwtracedepth)
		if tagErr_enc_mgwtracedepth != nil {
			return nil, qualifyBERError(tagErr_enc_mgwtracedepth, "mgw-TraceDepth", "encoding", false)
		}
		enc_mgwtracedepth = retagged_enc_mgwtracedepth
		children = append(children, enc_mgwtracedepth...)
	}
	if v.SgsnTraceDepth != nil {
		enc_sgsntracedepth := ber.EncodeEnumerated(int64(*v.SgsnTraceDepth))
		retagged_enc_sgsntracedepth, tagErr_enc_sgsntracedepth := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_sgsntracedepth)
		if tagErr_enc_sgsntracedepth != nil {
			return nil, qualifyBERError(tagErr_enc_sgsntracedepth, "sgsn-TraceDepth", "encoding", false)
		}
		enc_sgsntracedepth = retagged_enc_sgsntracedepth
		children = append(children, enc_sgsntracedepth...)
	}
	if v.GgsnTraceDepth != nil {
		enc_ggsntracedepth := ber.EncodeEnumerated(int64(*v.GgsnTraceDepth))
		retagged_enc_ggsntracedepth, tagErr_enc_ggsntracedepth := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, enc_ggsntracedepth)
		if tagErr_enc_ggsntracedepth != nil {
			return nil, qualifyBERError(tagErr_enc_ggsntracedepth, "ggsn-TraceDepth", "encoding", false)
		}
		enc_ggsntracedepth = retagged_enc_ggsntracedepth
		children = append(children, enc_ggsntracedepth...)
	}
	if v.RncTraceDepth != nil {
		enc_rnctracedepth := ber.EncodeEnumerated(int64(*v.RncTraceDepth))
		retagged_enc_rnctracedepth, tagErr_enc_rnctracedepth := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, enc_rnctracedepth)
		if tagErr_enc_rnctracedepth != nil {
			return nil, qualifyBERError(tagErr_enc_rnctracedepth, "rnc-TraceDepth", "encoding", false)
		}
		enc_rnctracedepth = retagged_enc_rnctracedepth
		children = append(children, enc_rnctracedepth...)
	}
	if v.BmscTraceDepth != nil {
		enc_bmsctracedepth := ber.EncodeEnumerated(int64(*v.BmscTraceDepth))
		retagged_enc_bmsctracedepth, tagErr_enc_bmsctracedepth := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 5, enc_bmsctracedepth)
		if tagErr_enc_bmsctracedepth != nil {
			return nil, qualifyBERError(tagErr_enc_bmsctracedepth, "bmsc-TraceDepth", "encoding", false)
		}
		enc_bmsctracedepth = retagged_enc_bmsctracedepth
		children = append(children, enc_bmsctracedepth...)
	}
	if v.MmeTraceDepth != nil {
		enc_mmetracedepth := ber.EncodeEnumerated(int64(*v.MmeTraceDepth))
		retagged_enc_mmetracedepth, tagErr_enc_mmetracedepth := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 6, enc_mmetracedepth)
		if tagErr_enc_mmetracedepth != nil {
			return nil, qualifyBERError(tagErr_enc_mmetracedepth, "mme-TraceDepth", "encoding", false)
		}
		enc_mmetracedepth = retagged_enc_mmetracedepth
		children = append(children, enc_mmetracedepth...)
	}
	if v.SgwTraceDepth != nil {
		enc_sgwtracedepth := ber.EncodeEnumerated(int64(*v.SgwTraceDepth))
		retagged_enc_sgwtracedepth, tagErr_enc_sgwtracedepth := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 7, enc_sgwtracedepth)
		if tagErr_enc_sgwtracedepth != nil {
			return nil, qualifyBERError(tagErr_enc_sgwtracedepth, "sgw-TraceDepth", "encoding", false)
		}
		enc_sgwtracedepth = retagged_enc_sgwtracedepth
		children = append(children, enc_sgwtracedepth...)
	}
	if v.PgwTraceDepth != nil {
		enc_pgwtracedepth := ber.EncodeEnumerated(int64(*v.PgwTraceDepth))
		retagged_enc_pgwtracedepth, tagErr_enc_pgwtracedepth := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 8, enc_pgwtracedepth)
		if tagErr_enc_pgwtracedepth != nil {
			return nil, qualifyBERError(tagErr_enc_pgwtracedepth, "pgw-TraceDepth", "encoding", false)
		}
		enc_pgwtracedepth = retagged_enc_pgwtracedepth
		children = append(children, enc_pgwtracedepth...)
	}
	if v.ENBTraceDepth != nil {
		enc_enbtracedepth := ber.EncodeEnumerated(int64(*v.ENBTraceDepth))
		retagged_enc_enbtracedepth, tagErr_enc_enbtracedepth := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 9, enc_enbtracedepth)
		if tagErr_enc_enbtracedepth != nil {
			return nil, qualifyBERError(tagErr_enc_enbtracedepth, "eNB-TraceDepth", "encoding", false)
		}
		enc_enbtracedepth = retagged_enc_enbtracedepth
		children = append(children, enc_enbtracedepth...)
	}
	if v.MscSTraceDepthExtension != nil {
		enc_mscstracedepthextension := ber.EncodeEnumerated(int64(*v.MscSTraceDepthExtension))
		retagged_enc_mscstracedepthextension, tagErr_enc_mscstracedepthextension := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 10, enc_mscstracedepthextension)
		if tagErr_enc_mscstracedepthextension != nil {
			return nil, qualifyBERError(tagErr_enc_mscstracedepthextension, "msc-s-TraceDepthExtension", "encoding", false)
		}
		enc_mscstracedepthextension = retagged_enc_mscstracedepthextension
		children = append(children, enc_mscstracedepthextension...)
	}
	if v.MgwTraceDepthExtension != nil {
		enc_mgwtracedepthextension := ber.EncodeEnumerated(int64(*v.MgwTraceDepthExtension))
		retagged_enc_mgwtracedepthextension, tagErr_enc_mgwtracedepthextension := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 11, enc_mgwtracedepthextension)
		if tagErr_enc_mgwtracedepthextension != nil {
			return nil, qualifyBERError(tagErr_enc_mgwtracedepthextension, "mgw-TraceDepthExtension", "encoding", false)
		}
		enc_mgwtracedepthextension = retagged_enc_mgwtracedepthextension
		children = append(children, enc_mgwtracedepthextension...)
	}
	if v.SgsnTraceDepthExtension != nil {
		enc_sgsntracedepthextension := ber.EncodeEnumerated(int64(*v.SgsnTraceDepthExtension))
		retagged_enc_sgsntracedepthextension, tagErr_enc_sgsntracedepthextension := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 12, enc_sgsntracedepthextension)
		if tagErr_enc_sgsntracedepthextension != nil {
			return nil, qualifyBERError(tagErr_enc_sgsntracedepthextension, "sgsn-TraceDepthExtension", "encoding", false)
		}
		enc_sgsntracedepthextension = retagged_enc_sgsntracedepthextension
		children = append(children, enc_sgsntracedepthextension...)
	}
	if v.GgsnTraceDepthExtension != nil {
		enc_ggsntracedepthextension := ber.EncodeEnumerated(int64(*v.GgsnTraceDepthExtension))
		retagged_enc_ggsntracedepthextension, tagErr_enc_ggsntracedepthextension := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 13, enc_ggsntracedepthextension)
		if tagErr_enc_ggsntracedepthextension != nil {
			return nil, qualifyBERError(tagErr_enc_ggsntracedepthextension, "ggsn-TraceDepthExtension", "encoding", false)
		}
		enc_ggsntracedepthextension = retagged_enc_ggsntracedepthextension
		children = append(children, enc_ggsntracedepthextension...)
	}
	if v.RncTraceDepthExtension != nil {
		enc_rnctracedepthextension := ber.EncodeEnumerated(int64(*v.RncTraceDepthExtension))
		retagged_enc_rnctracedepthextension, tagErr_enc_rnctracedepthextension := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 14, enc_rnctracedepthextension)
		if tagErr_enc_rnctracedepthextension != nil {
			return nil, qualifyBERError(tagErr_enc_rnctracedepthextension, "rnc-TraceDepthExtension", "encoding", false)
		}
		enc_rnctracedepthextension = retagged_enc_rnctracedepthextension
		children = append(children, enc_rnctracedepthextension...)
	}
	if v.BmscTraceDepthExtension != nil {
		enc_bmsctracedepthextension := ber.EncodeEnumerated(int64(*v.BmscTraceDepthExtension))
		retagged_enc_bmsctracedepthextension, tagErr_enc_bmsctracedepthextension := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 15, enc_bmsctracedepthextension)
		if tagErr_enc_bmsctracedepthextension != nil {
			return nil, qualifyBERError(tagErr_enc_bmsctracedepthextension, "bmsc-TraceDepthExtension", "encoding", false)
		}
		enc_bmsctracedepthextension = retagged_enc_bmsctracedepthextension
		children = append(children, enc_bmsctracedepthextension...)
	}
	if v.MmeTraceDepthExtension != nil {
		enc_mmetracedepthextension := ber.EncodeEnumerated(int64(*v.MmeTraceDepthExtension))
		retagged_enc_mmetracedepthextension, tagErr_enc_mmetracedepthextension := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 16, enc_mmetracedepthextension)
		if tagErr_enc_mmetracedepthextension != nil {
			return nil, qualifyBERError(tagErr_enc_mmetracedepthextension, "mme-TraceDepthExtension", "encoding", false)
		}
		enc_mmetracedepthextension = retagged_enc_mmetracedepthextension
		children = append(children, enc_mmetracedepthextension...)
	}
	if v.SgwTraceDepthExtension != nil {
		enc_sgwtracedepthextension := ber.EncodeEnumerated(int64(*v.SgwTraceDepthExtension))
		retagged_enc_sgwtracedepthextension, tagErr_enc_sgwtracedepthextension := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 17, enc_sgwtracedepthextension)
		if tagErr_enc_sgwtracedepthextension != nil {
			return nil, qualifyBERError(tagErr_enc_sgwtracedepthextension, "sgw-TraceDepthExtension", "encoding", false)
		}
		enc_sgwtracedepthextension = retagged_enc_sgwtracedepthextension
		children = append(children, enc_sgwtracedepthextension...)
	}
	if v.PgwTraceDepthExtension != nil {
		enc_pgwtracedepthextension := ber.EncodeEnumerated(int64(*v.PgwTraceDepthExtension))
		retagged_enc_pgwtracedepthextension, tagErr_enc_pgwtracedepthextension := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 18, enc_pgwtracedepthextension)
		if tagErr_enc_pgwtracedepthextension != nil {
			return nil, qualifyBERError(tagErr_enc_pgwtracedepthextension, "pgw-TraceDepthExtension", "encoding", false)
		}
		enc_pgwtracedepthextension = retagged_enc_pgwtracedepthextension
		children = append(children, enc_pgwtracedepthextension...)
	}
	if v.ENBTraceDepthExtension != nil {
		enc_enbtracedepthextension := ber.EncodeEnumerated(int64(*v.ENBTraceDepthExtension))
		retagged_enc_enbtracedepthextension, tagErr_enc_enbtracedepthextension := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 19, enc_enbtracedepthextension)
		if tagErr_enc_enbtracedepthextension != nil {
			return nil, qualifyBERError(tagErr_enc_enbtracedepthextension, "eNB-TraceDepthExtension", "encoding", false)
		}
		enc_enbtracedepthextension = retagged_enc_enbtracedepthextension
		children = append(children, enc_enbtracedepthextension...)
	}
	for i, ext := range v.ExtData_ {
		if err := ber.CheckBEROpaqueReplay(opts...); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
		peekTag, n, _, extErr := ber.DecodeEncodedTLV(ext)
		if extErr != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, extErr)
		}
		if n != len(ext) {
			return nil, fmt.Errorf("encoding extension %d: %w", i, ber.ErrExtraData)
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: only the first addition is restricted.
		if i == 0 && ((peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 19) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 18) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 17) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 16) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 15) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 14) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 13) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 12) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 11) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 10) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 9) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 8) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 7) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 6) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 5) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0)) {
			if constraintErr := ber.CheckEncodedValue(opts, "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
				return nil, constraintErr
			}
		}
		children = append(children, ext...)
	}
	return ber.EncodeSequence(children)
}

// MarshalDER encodes OMTraceDepthList to DER format.
func (v *OMTraceDepthList) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: OMTraceDepthList receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if v.MscSTraceDepth != nil {
		enc_mscstracedepth := ber.EncodeEnumerated(int64(*v.MscSTraceDepth))
		retagged_enc_mscstracedepth, tagErr_enc_mscstracedepth := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_mscstracedepth)
		if tagErr_enc_mscstracedepth != nil {
			return nil, qualifyBERError(tagErr_enc_mscstracedepth, "msc-s-TraceDepth", "encoding", true)
		}
		enc_mscstracedepth = retagged_enc_mscstracedepth
		children = append(children, enc_mscstracedepth...)
	}
	if v.MgwTraceDepth != nil {
		enc_mgwtracedepth := ber.EncodeEnumerated(int64(*v.MgwTraceDepth))
		retagged_enc_mgwtracedepth, tagErr_enc_mgwtracedepth := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_mgwtracedepth)
		if tagErr_enc_mgwtracedepth != nil {
			return nil, qualifyBERError(tagErr_enc_mgwtracedepth, "mgw-TraceDepth", "encoding", true)
		}
		enc_mgwtracedepth = retagged_enc_mgwtracedepth
		children = append(children, enc_mgwtracedepth...)
	}
	if v.SgsnTraceDepth != nil {
		enc_sgsntracedepth := ber.EncodeEnumerated(int64(*v.SgsnTraceDepth))
		retagged_enc_sgsntracedepth, tagErr_enc_sgsntracedepth := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_sgsntracedepth)
		if tagErr_enc_sgsntracedepth != nil {
			return nil, qualifyBERError(tagErr_enc_sgsntracedepth, "sgsn-TraceDepth", "encoding", true)
		}
		enc_sgsntracedepth = retagged_enc_sgsntracedepth
		children = append(children, enc_sgsntracedepth...)
	}
	if v.GgsnTraceDepth != nil {
		enc_ggsntracedepth := ber.EncodeEnumerated(int64(*v.GgsnTraceDepth))
		retagged_enc_ggsntracedepth, tagErr_enc_ggsntracedepth := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, enc_ggsntracedepth)
		if tagErr_enc_ggsntracedepth != nil {
			return nil, qualifyBERError(tagErr_enc_ggsntracedepth, "ggsn-TraceDepth", "encoding", true)
		}
		enc_ggsntracedepth = retagged_enc_ggsntracedepth
		children = append(children, enc_ggsntracedepth...)
	}
	if v.RncTraceDepth != nil {
		enc_rnctracedepth := ber.EncodeEnumerated(int64(*v.RncTraceDepth))
		retagged_enc_rnctracedepth, tagErr_enc_rnctracedepth := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, enc_rnctracedepth)
		if tagErr_enc_rnctracedepth != nil {
			return nil, qualifyBERError(tagErr_enc_rnctracedepth, "rnc-TraceDepth", "encoding", true)
		}
		enc_rnctracedepth = retagged_enc_rnctracedepth
		children = append(children, enc_rnctracedepth...)
	}
	if v.BmscTraceDepth != nil {
		enc_bmsctracedepth := ber.EncodeEnumerated(int64(*v.BmscTraceDepth))
		retagged_enc_bmsctracedepth, tagErr_enc_bmsctracedepth := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 5, enc_bmsctracedepth)
		if tagErr_enc_bmsctracedepth != nil {
			return nil, qualifyBERError(tagErr_enc_bmsctracedepth, "bmsc-TraceDepth", "encoding", true)
		}
		enc_bmsctracedepth = retagged_enc_bmsctracedepth
		children = append(children, enc_bmsctracedepth...)
	}
	if v.MmeTraceDepth != nil {
		enc_mmetracedepth := ber.EncodeEnumerated(int64(*v.MmeTraceDepth))
		retagged_enc_mmetracedepth, tagErr_enc_mmetracedepth := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 6, enc_mmetracedepth)
		if tagErr_enc_mmetracedepth != nil {
			return nil, qualifyBERError(tagErr_enc_mmetracedepth, "mme-TraceDepth", "encoding", true)
		}
		enc_mmetracedepth = retagged_enc_mmetracedepth
		children = append(children, enc_mmetracedepth...)
	}
	if v.SgwTraceDepth != nil {
		enc_sgwtracedepth := ber.EncodeEnumerated(int64(*v.SgwTraceDepth))
		retagged_enc_sgwtracedepth, tagErr_enc_sgwtracedepth := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 7, enc_sgwtracedepth)
		if tagErr_enc_sgwtracedepth != nil {
			return nil, qualifyBERError(tagErr_enc_sgwtracedepth, "sgw-TraceDepth", "encoding", true)
		}
		enc_sgwtracedepth = retagged_enc_sgwtracedepth
		children = append(children, enc_sgwtracedepth...)
	}
	if v.PgwTraceDepth != nil {
		enc_pgwtracedepth := ber.EncodeEnumerated(int64(*v.PgwTraceDepth))
		retagged_enc_pgwtracedepth, tagErr_enc_pgwtracedepth := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 8, enc_pgwtracedepth)
		if tagErr_enc_pgwtracedepth != nil {
			return nil, qualifyBERError(tagErr_enc_pgwtracedepth, "pgw-TraceDepth", "encoding", true)
		}
		enc_pgwtracedepth = retagged_enc_pgwtracedepth
		children = append(children, enc_pgwtracedepth...)
	}
	if v.ENBTraceDepth != nil {
		enc_enbtracedepth := ber.EncodeEnumerated(int64(*v.ENBTraceDepth))
		retagged_enc_enbtracedepth, tagErr_enc_enbtracedepth := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 9, enc_enbtracedepth)
		if tagErr_enc_enbtracedepth != nil {
			return nil, qualifyBERError(tagErr_enc_enbtracedepth, "eNB-TraceDepth", "encoding", true)
		}
		enc_enbtracedepth = retagged_enc_enbtracedepth
		children = append(children, enc_enbtracedepth...)
	}
	if v.MscSTraceDepthExtension != nil {
		enc_mscstracedepthextension := ber.EncodeEnumerated(int64(*v.MscSTraceDepthExtension))
		retagged_enc_mscstracedepthextension, tagErr_enc_mscstracedepthextension := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 10, enc_mscstracedepthextension)
		if tagErr_enc_mscstracedepthextension != nil {
			return nil, qualifyBERError(tagErr_enc_mscstracedepthextension, "msc-s-TraceDepthExtension", "encoding", true)
		}
		enc_mscstracedepthextension = retagged_enc_mscstracedepthextension
		children = append(children, enc_mscstracedepthextension...)
	}
	if v.MgwTraceDepthExtension != nil {
		enc_mgwtracedepthextension := ber.EncodeEnumerated(int64(*v.MgwTraceDepthExtension))
		retagged_enc_mgwtracedepthextension, tagErr_enc_mgwtracedepthextension := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 11, enc_mgwtracedepthextension)
		if tagErr_enc_mgwtracedepthextension != nil {
			return nil, qualifyBERError(tagErr_enc_mgwtracedepthextension, "mgw-TraceDepthExtension", "encoding", true)
		}
		enc_mgwtracedepthextension = retagged_enc_mgwtracedepthextension
		children = append(children, enc_mgwtracedepthextension...)
	}
	if v.SgsnTraceDepthExtension != nil {
		enc_sgsntracedepthextension := ber.EncodeEnumerated(int64(*v.SgsnTraceDepthExtension))
		retagged_enc_sgsntracedepthextension, tagErr_enc_sgsntracedepthextension := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 12, enc_sgsntracedepthextension)
		if tagErr_enc_sgsntracedepthextension != nil {
			return nil, qualifyBERError(tagErr_enc_sgsntracedepthextension, "sgsn-TraceDepthExtension", "encoding", true)
		}
		enc_sgsntracedepthextension = retagged_enc_sgsntracedepthextension
		children = append(children, enc_sgsntracedepthextension...)
	}
	if v.GgsnTraceDepthExtension != nil {
		enc_ggsntracedepthextension := ber.EncodeEnumerated(int64(*v.GgsnTraceDepthExtension))
		retagged_enc_ggsntracedepthextension, tagErr_enc_ggsntracedepthextension := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 13, enc_ggsntracedepthextension)
		if tagErr_enc_ggsntracedepthextension != nil {
			return nil, qualifyBERError(tagErr_enc_ggsntracedepthextension, "ggsn-TraceDepthExtension", "encoding", true)
		}
		enc_ggsntracedepthextension = retagged_enc_ggsntracedepthextension
		children = append(children, enc_ggsntracedepthextension...)
	}
	if v.RncTraceDepthExtension != nil {
		enc_rnctracedepthextension := ber.EncodeEnumerated(int64(*v.RncTraceDepthExtension))
		retagged_enc_rnctracedepthextension, tagErr_enc_rnctracedepthextension := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 14, enc_rnctracedepthextension)
		if tagErr_enc_rnctracedepthextension != nil {
			return nil, qualifyBERError(tagErr_enc_rnctracedepthextension, "rnc-TraceDepthExtension", "encoding", true)
		}
		enc_rnctracedepthextension = retagged_enc_rnctracedepthextension
		children = append(children, enc_rnctracedepthextension...)
	}
	if v.BmscTraceDepthExtension != nil {
		enc_bmsctracedepthextension := ber.EncodeEnumerated(int64(*v.BmscTraceDepthExtension))
		retagged_enc_bmsctracedepthextension, tagErr_enc_bmsctracedepthextension := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 15, enc_bmsctracedepthextension)
		if tagErr_enc_bmsctracedepthextension != nil {
			return nil, qualifyBERError(tagErr_enc_bmsctracedepthextension, "bmsc-TraceDepthExtension", "encoding", true)
		}
		enc_bmsctracedepthextension = retagged_enc_bmsctracedepthextension
		children = append(children, enc_bmsctracedepthextension...)
	}
	if v.MmeTraceDepthExtension != nil {
		enc_mmetracedepthextension := ber.EncodeEnumerated(int64(*v.MmeTraceDepthExtension))
		retagged_enc_mmetracedepthextension, tagErr_enc_mmetracedepthextension := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 16, enc_mmetracedepthextension)
		if tagErr_enc_mmetracedepthextension != nil {
			return nil, qualifyBERError(tagErr_enc_mmetracedepthextension, "mme-TraceDepthExtension", "encoding", true)
		}
		enc_mmetracedepthextension = retagged_enc_mmetracedepthextension
		children = append(children, enc_mmetracedepthextension...)
	}
	if v.SgwTraceDepthExtension != nil {
		enc_sgwtracedepthextension := ber.EncodeEnumerated(int64(*v.SgwTraceDepthExtension))
		retagged_enc_sgwtracedepthextension, tagErr_enc_sgwtracedepthextension := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 17, enc_sgwtracedepthextension)
		if tagErr_enc_sgwtracedepthextension != nil {
			return nil, qualifyBERError(tagErr_enc_sgwtracedepthextension, "sgw-TraceDepthExtension", "encoding", true)
		}
		enc_sgwtracedepthextension = retagged_enc_sgwtracedepthextension
		children = append(children, enc_sgwtracedepthextension...)
	}
	if v.PgwTraceDepthExtension != nil {
		enc_pgwtracedepthextension := ber.EncodeEnumerated(int64(*v.PgwTraceDepthExtension))
		retagged_enc_pgwtracedepthextension, tagErr_enc_pgwtracedepthextension := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 18, enc_pgwtracedepthextension)
		if tagErr_enc_pgwtracedepthextension != nil {
			return nil, qualifyBERError(tagErr_enc_pgwtracedepthextension, "pgw-TraceDepthExtension", "encoding", true)
		}
		enc_pgwtracedepthextension = retagged_enc_pgwtracedepthextension
		children = append(children, enc_pgwtracedepthextension...)
	}
	if v.ENBTraceDepthExtension != nil {
		enc_enbtracedepthextension := ber.EncodeEnumerated(int64(*v.ENBTraceDepthExtension))
		retagged_enc_enbtracedepthextension, tagErr_enc_enbtracedepthextension := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 19, enc_enbtracedepthextension)
		if tagErr_enc_enbtracedepthextension != nil {
			return nil, qualifyBERError(tagErr_enc_enbtracedepthextension, "eNB-TraceDepthExtension", "encoding", true)
		}
		enc_enbtracedepthextension = retagged_enc_enbtracedepthextension
		children = append(children, enc_enbtracedepthextension...)
	}
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDEREncodedElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
		peekTag, _, _, extErr := ber.DecodeEncodedTLV(ext)
		if extErr != nil {
			return nil, extErr
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: only the first addition is restricted.
		if i == 0 && ((peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 19) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 18) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 17) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 16) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 15) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 14) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 13) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 12) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 11) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 10) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 9) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 8) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 7) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 6) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 5) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0)) {
			if constraintErr := ber.CheckEncodedValue(nil, "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
				return nil, constraintErr
			}
		}
		children = append(children, ext...)
	}
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("%s: %w", "encoding OMTraceDepthList as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}

// UnmarshalBER decodes OMTraceDepthList from BER/DER format.
func (v *OMTraceDepthList) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: OMTraceDepthList destination is nil", ber.ErrInvalidValue)
	}
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return ber.DiagnosePreflight(err, data, opts, "child", func(probeOpts []ber.DecodeOption) error {
			var probe OMTraceDepthList
			return probe.UnmarshalBER(data, probeOpts...)
		})
	}
	*v = OMTraceDepthList{}
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
		return fmt.Errorf("%s: %w", "decoding OMTraceDepthList SEQUENCE", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "OMTraceDepthList", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode msc-s-TraceDepth
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
				ber.MarkPreflightTarget(opts, "msc-s-TraceDepth", content[offset:])
				decodedTag_mscstracedepth, n_mscstracedepth, rawVal_mscstracedepth, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "msc-s-TraceDepth", "decoding", false)
				}
				if decodedTag_mscstracedepth.Class != tag.ClassContextSpecific || decodedTag_mscstracedepth.Number != 0 || decodedTag_mscstracedepth.Constructed != false {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_mscstracedepth), "msc-s-TraceDepth", "decoding", false)
				}
				decVal_mscstracedepth, intErr := ber.DecodeEnumeratedValue(rawVal_mscstracedepth)
				if intErr != nil {
					return qualifyBERError(intErr, "msc-s-TraceDepth", "decoding", false)
				}
				tmp_mscstracedepth := OMTraceDepth(decVal_mscstracedepth)
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
				ber.MarkPreflightTarget(opts, "mgw-TraceDepth", content[offset:])
				decodedTag_mgwtracedepth, n_mgwtracedepth, rawVal_mgwtracedepth, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "mgw-TraceDepth", "decoding", false)
				}
				if decodedTag_mgwtracedepth.Class != tag.ClassContextSpecific || decodedTag_mgwtracedepth.Number != 1 || decodedTag_mgwtracedepth.Constructed != false {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_mgwtracedepth), "mgw-TraceDepth", "decoding", false)
				}
				decVal_mgwtracedepth, intErr := ber.DecodeEnumeratedValue(rawVal_mgwtracedepth)
				if intErr != nil {
					return qualifyBERError(intErr, "mgw-TraceDepth", "decoding", false)
				}
				tmp_mgwtracedepth := OMTraceDepth(decVal_mgwtracedepth)
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
				ber.MarkPreflightTarget(opts, "sgsn-TraceDepth", content[offset:])
				decodedTag_sgsntracedepth, n_sgsntracedepth, rawVal_sgsntracedepth, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "sgsn-TraceDepth", "decoding", false)
				}
				if decodedTag_sgsntracedepth.Class != tag.ClassContextSpecific || decodedTag_sgsntracedepth.Number != 2 || decodedTag_sgsntracedepth.Constructed != false {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_sgsntracedepth), "sgsn-TraceDepth", "decoding", false)
				}
				decVal_sgsntracedepth, intErr := ber.DecodeEnumeratedValue(rawVal_sgsntracedepth)
				if intErr != nil {
					return qualifyBERError(intErr, "sgsn-TraceDepth", "decoding", false)
				}
				tmp_sgsntracedepth := OMTraceDepth(decVal_sgsntracedepth)
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
				ber.MarkPreflightTarget(opts, "ggsn-TraceDepth", content[offset:])
				decodedTag_ggsntracedepth, n_ggsntracedepth, rawVal_ggsntracedepth, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "ggsn-TraceDepth", "decoding", false)
				}
				if decodedTag_ggsntracedepth.Class != tag.ClassContextSpecific || decodedTag_ggsntracedepth.Number != 3 || decodedTag_ggsntracedepth.Constructed != false {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_ggsntracedepth), "ggsn-TraceDepth", "decoding", false)
				}
				decVal_ggsntracedepth, intErr := ber.DecodeEnumeratedValue(rawVal_ggsntracedepth)
				if intErr != nil {
					return qualifyBERError(intErr, "ggsn-TraceDepth", "decoding", false)
				}
				tmp_ggsntracedepth := OMTraceDepth(decVal_ggsntracedepth)
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
				ber.MarkPreflightTarget(opts, "rnc-TraceDepth", content[offset:])
				decodedTag_rnctracedepth, n_rnctracedepth, rawVal_rnctracedepth, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "rnc-TraceDepth", "decoding", false)
				}
				if decodedTag_rnctracedepth.Class != tag.ClassContextSpecific || decodedTag_rnctracedepth.Number != 4 || decodedTag_rnctracedepth.Constructed != false {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_rnctracedepth), "rnc-TraceDepth", "decoding", false)
				}
				decVal_rnctracedepth, intErr := ber.DecodeEnumeratedValue(rawVal_rnctracedepth)
				if intErr != nil {
					return qualifyBERError(intErr, "rnc-TraceDepth", "decoding", false)
				}
				tmp_rnctracedepth := OMTraceDepth(decVal_rnctracedepth)
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
				ber.MarkPreflightTarget(opts, "bmsc-TraceDepth", content[offset:])
				decodedTag_bmsctracedepth, n_bmsctracedepth, rawVal_bmsctracedepth, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "bmsc-TraceDepth", "decoding", false)
				}
				if decodedTag_bmsctracedepth.Class != tag.ClassContextSpecific || decodedTag_bmsctracedepth.Number != 5 || decodedTag_bmsctracedepth.Constructed != false {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_bmsctracedepth), "bmsc-TraceDepth", "decoding", false)
				}
				decVal_bmsctracedepth, intErr := ber.DecodeEnumeratedValue(rawVal_bmsctracedepth)
				if intErr != nil {
					return qualifyBERError(intErr, "bmsc-TraceDepth", "decoding", false)
				}
				tmp_bmsctracedepth := OMTraceDepth(decVal_bmsctracedepth)
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
				ber.MarkPreflightTarget(opts, "mme-TraceDepth", content[offset:])
				decodedTag_mmetracedepth, n_mmetracedepth, rawVal_mmetracedepth, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "mme-TraceDepth", "decoding", false)
				}
				if decodedTag_mmetracedepth.Class != tag.ClassContextSpecific || decodedTag_mmetracedepth.Number != 6 || decodedTag_mmetracedepth.Constructed != false {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_mmetracedepth), "mme-TraceDepth", "decoding", false)
				}
				decVal_mmetracedepth, intErr := ber.DecodeEnumeratedValue(rawVal_mmetracedepth)
				if intErr != nil {
					return qualifyBERError(intErr, "mme-TraceDepth", "decoding", false)
				}
				tmp_mmetracedepth := OMTraceDepth(decVal_mmetracedepth)
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
				ber.MarkPreflightTarget(opts, "sgw-TraceDepth", content[offset:])
				decodedTag_sgwtracedepth, n_sgwtracedepth, rawVal_sgwtracedepth, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "sgw-TraceDepth", "decoding", false)
				}
				if decodedTag_sgwtracedepth.Class != tag.ClassContextSpecific || decodedTag_sgwtracedepth.Number != 7 || decodedTag_sgwtracedepth.Constructed != false {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_sgwtracedepth), "sgw-TraceDepth", "decoding", false)
				}
				decVal_sgwtracedepth, intErr := ber.DecodeEnumeratedValue(rawVal_sgwtracedepth)
				if intErr != nil {
					return qualifyBERError(intErr, "sgw-TraceDepth", "decoding", false)
				}
				tmp_sgwtracedepth := OMTraceDepth(decVal_sgwtracedepth)
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
				ber.MarkPreflightTarget(opts, "pgw-TraceDepth", content[offset:])
				decodedTag_pgwtracedepth, n_pgwtracedepth, rawVal_pgwtracedepth, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "pgw-TraceDepth", "decoding", false)
				}
				if decodedTag_pgwtracedepth.Class != tag.ClassContextSpecific || decodedTag_pgwtracedepth.Number != 8 || decodedTag_pgwtracedepth.Constructed != false {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_pgwtracedepth), "pgw-TraceDepth", "decoding", false)
				}
				decVal_pgwtracedepth, intErr := ber.DecodeEnumeratedValue(rawVal_pgwtracedepth)
				if intErr != nil {
					return qualifyBERError(intErr, "pgw-TraceDepth", "decoding", false)
				}
				tmp_pgwtracedepth := OMTraceDepth(decVal_pgwtracedepth)
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
				ber.MarkPreflightTarget(opts, "eNB-TraceDepth", content[offset:])
				decodedTag_enbtracedepth, n_enbtracedepth, rawVal_enbtracedepth, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "eNB-TraceDepth", "decoding", false)
				}
				if decodedTag_enbtracedepth.Class != tag.ClassContextSpecific || decodedTag_enbtracedepth.Number != 9 || decodedTag_enbtracedepth.Constructed != false {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_enbtracedepth), "eNB-TraceDepth", "decoding", false)
				}
				decVal_enbtracedepth, intErr := ber.DecodeEnumeratedValue(rawVal_enbtracedepth)
				if intErr != nil {
					return qualifyBERError(intErr, "eNB-TraceDepth", "decoding", false)
				}
				tmp_enbtracedepth := OMTraceDepth(decVal_enbtracedepth)
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
				ber.MarkPreflightTarget(opts, "msc-s-TraceDepthExtension", content[offset:])
				decodedTag_mscstracedepthextension, n_mscstracedepthextension, rawVal_mscstracedepthextension, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "msc-s-TraceDepthExtension", "decoding", false)
				}
				if decodedTag_mscstracedepthextension.Class != tag.ClassContextSpecific || decodedTag_mscstracedepthextension.Number != 10 || decodedTag_mscstracedepthextension.Constructed != false {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_mscstracedepthextension), "msc-s-TraceDepthExtension", "decoding", false)
				}
				decVal_mscstracedepthextension, intErr := ber.DecodeEnumeratedValue(rawVal_mscstracedepthextension)
				if intErr != nil {
					return qualifyBERError(intErr, "msc-s-TraceDepthExtension", "decoding", false)
				}
				tmp_mscstracedepthextension := OMTraceDepthExtension(decVal_mscstracedepthextension)
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
				ber.MarkPreflightTarget(opts, "mgw-TraceDepthExtension", content[offset:])
				decodedTag_mgwtracedepthextension, n_mgwtracedepthextension, rawVal_mgwtracedepthextension, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "mgw-TraceDepthExtension", "decoding", false)
				}
				if decodedTag_mgwtracedepthextension.Class != tag.ClassContextSpecific || decodedTag_mgwtracedepthextension.Number != 11 || decodedTag_mgwtracedepthextension.Constructed != false {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_mgwtracedepthextension), "mgw-TraceDepthExtension", "decoding", false)
				}
				decVal_mgwtracedepthextension, intErr := ber.DecodeEnumeratedValue(rawVal_mgwtracedepthextension)
				if intErr != nil {
					return qualifyBERError(intErr, "mgw-TraceDepthExtension", "decoding", false)
				}
				tmp_mgwtracedepthextension := OMTraceDepthExtension(decVal_mgwtracedepthextension)
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
				ber.MarkPreflightTarget(opts, "sgsn-TraceDepthExtension", content[offset:])
				decodedTag_sgsntracedepthextension, n_sgsntracedepthextension, rawVal_sgsntracedepthextension, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "sgsn-TraceDepthExtension", "decoding", false)
				}
				if decodedTag_sgsntracedepthextension.Class != tag.ClassContextSpecific || decodedTag_sgsntracedepthextension.Number != 12 || decodedTag_sgsntracedepthextension.Constructed != false {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_sgsntracedepthextension), "sgsn-TraceDepthExtension", "decoding", false)
				}
				decVal_sgsntracedepthextension, intErr := ber.DecodeEnumeratedValue(rawVal_sgsntracedepthextension)
				if intErr != nil {
					return qualifyBERError(intErr, "sgsn-TraceDepthExtension", "decoding", false)
				}
				tmp_sgsntracedepthextension := OMTraceDepthExtension(decVal_sgsntracedepthextension)
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
				ber.MarkPreflightTarget(opts, "ggsn-TraceDepthExtension", content[offset:])
				decodedTag_ggsntracedepthextension, n_ggsntracedepthextension, rawVal_ggsntracedepthextension, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "ggsn-TraceDepthExtension", "decoding", false)
				}
				if decodedTag_ggsntracedepthextension.Class != tag.ClassContextSpecific || decodedTag_ggsntracedepthextension.Number != 13 || decodedTag_ggsntracedepthextension.Constructed != false {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_ggsntracedepthextension), "ggsn-TraceDepthExtension", "decoding", false)
				}
				decVal_ggsntracedepthextension, intErr := ber.DecodeEnumeratedValue(rawVal_ggsntracedepthextension)
				if intErr != nil {
					return qualifyBERError(intErr, "ggsn-TraceDepthExtension", "decoding", false)
				}
				tmp_ggsntracedepthextension := OMTraceDepthExtension(decVal_ggsntracedepthextension)
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
				ber.MarkPreflightTarget(opts, "rnc-TraceDepthExtension", content[offset:])
				decodedTag_rnctracedepthextension, n_rnctracedepthextension, rawVal_rnctracedepthextension, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "rnc-TraceDepthExtension", "decoding", false)
				}
				if decodedTag_rnctracedepthextension.Class != tag.ClassContextSpecific || decodedTag_rnctracedepthextension.Number != 14 || decodedTag_rnctracedepthextension.Constructed != false {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_rnctracedepthextension), "rnc-TraceDepthExtension", "decoding", false)
				}
				decVal_rnctracedepthextension, intErr := ber.DecodeEnumeratedValue(rawVal_rnctracedepthextension)
				if intErr != nil {
					return qualifyBERError(intErr, "rnc-TraceDepthExtension", "decoding", false)
				}
				tmp_rnctracedepthextension := OMTraceDepthExtension(decVal_rnctracedepthextension)
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
				ber.MarkPreflightTarget(opts, "bmsc-TraceDepthExtension", content[offset:])
				decodedTag_bmsctracedepthextension, n_bmsctracedepthextension, rawVal_bmsctracedepthextension, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "bmsc-TraceDepthExtension", "decoding", false)
				}
				if decodedTag_bmsctracedepthextension.Class != tag.ClassContextSpecific || decodedTag_bmsctracedepthextension.Number != 15 || decodedTag_bmsctracedepthextension.Constructed != false {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_bmsctracedepthextension), "bmsc-TraceDepthExtension", "decoding", false)
				}
				decVal_bmsctracedepthextension, intErr := ber.DecodeEnumeratedValue(rawVal_bmsctracedepthextension)
				if intErr != nil {
					return qualifyBERError(intErr, "bmsc-TraceDepthExtension", "decoding", false)
				}
				tmp_bmsctracedepthextension := OMTraceDepthExtension(decVal_bmsctracedepthextension)
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
				ber.MarkPreflightTarget(opts, "mme-TraceDepthExtension", content[offset:])
				decodedTag_mmetracedepthextension, n_mmetracedepthextension, rawVal_mmetracedepthextension, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "mme-TraceDepthExtension", "decoding", false)
				}
				if decodedTag_mmetracedepthextension.Class != tag.ClassContextSpecific || decodedTag_mmetracedepthextension.Number != 16 || decodedTag_mmetracedepthextension.Constructed != false {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_mmetracedepthextension), "mme-TraceDepthExtension", "decoding", false)
				}
				decVal_mmetracedepthextension, intErr := ber.DecodeEnumeratedValue(rawVal_mmetracedepthextension)
				if intErr != nil {
					return qualifyBERError(intErr, "mme-TraceDepthExtension", "decoding", false)
				}
				tmp_mmetracedepthextension := OMTraceDepthExtension(decVal_mmetracedepthextension)
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
				ber.MarkPreflightTarget(opts, "sgw-TraceDepthExtension", content[offset:])
				decodedTag_sgwtracedepthextension, n_sgwtracedepthextension, rawVal_sgwtracedepthextension, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "sgw-TraceDepthExtension", "decoding", false)
				}
				if decodedTag_sgwtracedepthextension.Class != tag.ClassContextSpecific || decodedTag_sgwtracedepthextension.Number != 17 || decodedTag_sgwtracedepthextension.Constructed != false {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_sgwtracedepthextension), "sgw-TraceDepthExtension", "decoding", false)
				}
				decVal_sgwtracedepthextension, intErr := ber.DecodeEnumeratedValue(rawVal_sgwtracedepthextension)
				if intErr != nil {
					return qualifyBERError(intErr, "sgw-TraceDepthExtension", "decoding", false)
				}
				tmp_sgwtracedepthextension := OMTraceDepthExtension(decVal_sgwtracedepthextension)
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
				ber.MarkPreflightTarget(opts, "pgw-TraceDepthExtension", content[offset:])
				decodedTag_pgwtracedepthextension, n_pgwtracedepthextension, rawVal_pgwtracedepthextension, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "pgw-TraceDepthExtension", "decoding", false)
				}
				if decodedTag_pgwtracedepthextension.Class != tag.ClassContextSpecific || decodedTag_pgwtracedepthextension.Number != 18 || decodedTag_pgwtracedepthextension.Constructed != false {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_pgwtracedepthextension), "pgw-TraceDepthExtension", "decoding", false)
				}
				decVal_pgwtracedepthextension, intErr := ber.DecodeEnumeratedValue(rawVal_pgwtracedepthextension)
				if intErr != nil {
					return qualifyBERError(intErr, "pgw-TraceDepthExtension", "decoding", false)
				}
				tmp_pgwtracedepthextension := OMTraceDepthExtension(decVal_pgwtracedepthextension)
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
				ber.MarkPreflightTarget(opts, "eNB-TraceDepthExtension", content[offset:])
				decodedTag_enbtracedepthextension, n_enbtracedepthextension, rawVal_enbtracedepthextension, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "eNB-TraceDepthExtension", "decoding", false)
				}
				if decodedTag_enbtracedepthextension.Class != tag.ClassContextSpecific || decodedTag_enbtracedepthextension.Number != 19 || decodedTag_enbtracedepthextension.Constructed != false {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_enbtracedepthextension), "eNB-TraceDepthExtension", "decoding", false)
				}
				decVal_enbtracedepthextension, intErr := ber.DecodeEnumeratedValue(rawVal_enbtracedepthextension)
				if intErr != nil {
					return qualifyBERError(intErr, "eNB-TraceDepthExtension", "decoding", false)
				}
				tmp_enbtracedepthextension := OMTraceDepthExtension(decVal_enbtracedepthextension)
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
		peekTag, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:], opts...)
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "OMTraceDepthList", Cause: extErr_}
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: the first unknown addition must differ from trailing OPTIONAL/DEFAULT tags.
		if len(v.ExtData_) == 0 && ((peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 19) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 18) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 17) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 16) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 15) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 14) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 13) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 12) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 11) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 10) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 9) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 8) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 7) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 6) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 5) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0)) {
			if !ber.ConstraintToleranceEnabled(opts) {
				return &ber.DecodeError{Offset: offset, TypeName: "OMTraceDepthList", Cause: fmt.Errorf("%w: repeated or out-of-order SEQUENCE component tag %s", ber.ErrInvalidTag, peekTag)}
			}
			if orderErr_ := ber.CheckDecodedValue(opts, fmt.Sprintf("ExtData_[%d]", len(v.ExtData_)), "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); orderErr_ != nil {
				return orderErr_
			}
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

// MarshalBER encodes OMTraceInterfaceList to BER format.
func (v *OMTraceInterfaceList) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: OMTraceInterfaceList receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *OMTraceInterfaceList) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if v.MscSList != nil {
		if bitStringErr := ber.ValidateBitStringLength(v.MscSList.Bytes, v.MscSList.BitLength); bitStringErr != nil {
			return nil, qualifyBERError(bitStringErr, "msc-s-List", "encoding", false)
		}
		// arithmetic pattern BER_BITSTRING_FIELD: 0 <= bit length before modulo and subtraction; gen/codegen.go:644
		if v.MscSList.BitLength < 0 {
			return nil, fmt.Errorf("negative bit string length")
		}
		if (*v.MscSList).BitLength < 10 || (*v.MscSList).BitLength > 16 {
			if constraintErr := ber.CheckEncodedLength(opts, "msc-s-List", "SIZE (10..16)", (*v.MscSList).BitLength); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_mscslist, encodeErr_enc_mscslist := ber.EncodeBitString(v.MscSList.Bytes, ber.UnusedBitCount(v.MscSList.BitLength))
		if encodeErr_enc_mscslist != nil {
			return nil, qualifyBERError(encodeErr_enc_mscslist, "msc-s-List", "encoding", false)
		}
		retagged_enc_mscslist, tagErr_enc_mscslist := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_mscslist)
		if tagErr_enc_mscslist != nil {
			return nil, qualifyBERError(tagErr_enc_mscslist, "msc-s-List", "encoding", false)
		}
		enc_mscslist = retagged_enc_mscslist
		children = append(children, enc_mscslist...)
	}
	if v.MgwList != nil {
		if bitStringErr := ber.ValidateBitStringLength(v.MgwList.Bytes, v.MgwList.BitLength); bitStringErr != nil {
			return nil, qualifyBERError(bitStringErr, "mgw-List", "encoding", false)
		}
		// arithmetic pattern BER_BITSTRING_FIELD: 0 <= bit length before modulo and subtraction; gen/codegen.go:644
		if v.MgwList.BitLength < 0 {
			return nil, fmt.Errorf("negative bit string length")
		}
		if (*v.MgwList).BitLength < 3 || (*v.MgwList).BitLength > 8 {
			if constraintErr := ber.CheckEncodedLength(opts, "mgw-List", "SIZE (3..8)", (*v.MgwList).BitLength); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_mgwlist, encodeErr_enc_mgwlist := ber.EncodeBitString(v.MgwList.Bytes, ber.UnusedBitCount(v.MgwList.BitLength))
		if encodeErr_enc_mgwlist != nil {
			return nil, qualifyBERError(encodeErr_enc_mgwlist, "mgw-List", "encoding", false)
		}
		retagged_enc_mgwlist, tagErr_enc_mgwlist := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_mgwlist)
		if tagErr_enc_mgwlist != nil {
			return nil, qualifyBERError(tagErr_enc_mgwlist, "mgw-List", "encoding", false)
		}
		enc_mgwlist = retagged_enc_mgwlist
		children = append(children, enc_mgwlist...)
	}
	if v.SgsnList != nil {
		if bitStringErr := ber.ValidateBitStringLength(v.SgsnList.Bytes, v.SgsnList.BitLength); bitStringErr != nil {
			return nil, qualifyBERError(bitStringErr, "sgsn-List", "encoding", false)
		}
		// arithmetic pattern BER_BITSTRING_FIELD: 0 <= bit length before modulo and subtraction; gen/codegen.go:644
		if v.SgsnList.BitLength < 0 {
			return nil, fmt.Errorf("negative bit string length")
		}
		if (*v.SgsnList).BitLength < 8 || (*v.SgsnList).BitLength > 16 {
			if constraintErr := ber.CheckEncodedLength(opts, "sgsn-List", "SIZE (8..16)", (*v.SgsnList).BitLength); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_sgsnlist, encodeErr_enc_sgsnlist := ber.EncodeBitString(v.SgsnList.Bytes, ber.UnusedBitCount(v.SgsnList.BitLength))
		if encodeErr_enc_sgsnlist != nil {
			return nil, qualifyBERError(encodeErr_enc_sgsnlist, "sgsn-List", "encoding", false)
		}
		retagged_enc_sgsnlist, tagErr_enc_sgsnlist := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_sgsnlist)
		if tagErr_enc_sgsnlist != nil {
			return nil, qualifyBERError(tagErr_enc_sgsnlist, "sgsn-List", "encoding", false)
		}
		enc_sgsnlist = retagged_enc_sgsnlist
		children = append(children, enc_sgsnlist...)
	}
	if v.GgsnList != nil {
		if bitStringErr := ber.ValidateBitStringLength(v.GgsnList.Bytes, v.GgsnList.BitLength); bitStringErr != nil {
			return nil, qualifyBERError(bitStringErr, "ggsn-List", "encoding", false)
		}
		// arithmetic pattern BER_BITSTRING_FIELD: 0 <= bit length before modulo and subtraction; gen/codegen.go:644
		if v.GgsnList.BitLength < 0 {
			return nil, fmt.Errorf("negative bit string length")
		}
		if (*v.GgsnList).BitLength < 3 || (*v.GgsnList).BitLength > 8 {
			if constraintErr := ber.CheckEncodedLength(opts, "ggsn-List", "SIZE (3..8)", (*v.GgsnList).BitLength); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_ggsnlist, encodeErr_enc_ggsnlist := ber.EncodeBitString(v.GgsnList.Bytes, ber.UnusedBitCount(v.GgsnList.BitLength))
		if encodeErr_enc_ggsnlist != nil {
			return nil, qualifyBERError(encodeErr_enc_ggsnlist, "ggsn-List", "encoding", false)
		}
		retagged_enc_ggsnlist, tagErr_enc_ggsnlist := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, enc_ggsnlist)
		if tagErr_enc_ggsnlist != nil {
			return nil, qualifyBERError(tagErr_enc_ggsnlist, "ggsn-List", "encoding", false)
		}
		enc_ggsnlist = retagged_enc_ggsnlist
		children = append(children, enc_ggsnlist...)
	}
	if v.RncList != nil {
		if bitStringErr := ber.ValidateBitStringLength(v.RncList.Bytes, v.RncList.BitLength); bitStringErr != nil {
			return nil, qualifyBERError(bitStringErr, "rnc-List", "encoding", false)
		}
		// arithmetic pattern BER_BITSTRING_FIELD: 0 <= bit length before modulo and subtraction; gen/codegen.go:644
		if v.RncList.BitLength < 0 {
			return nil, fmt.Errorf("negative bit string length")
		}
		if (*v.RncList).BitLength < 4 || (*v.RncList).BitLength > 8 {
			if constraintErr := ber.CheckEncodedLength(opts, "rnc-List", "SIZE (4..8)", (*v.RncList).BitLength); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_rnclist, encodeErr_enc_rnclist := ber.EncodeBitString(v.RncList.Bytes, ber.UnusedBitCount(v.RncList.BitLength))
		if encodeErr_enc_rnclist != nil {
			return nil, qualifyBERError(encodeErr_enc_rnclist, "rnc-List", "encoding", false)
		}
		retagged_enc_rnclist, tagErr_enc_rnclist := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, enc_rnclist)
		if tagErr_enc_rnclist != nil {
			return nil, qualifyBERError(tagErr_enc_rnclist, "rnc-List", "encoding", false)
		}
		enc_rnclist = retagged_enc_rnclist
		children = append(children, enc_rnclist...)
	}
	if v.BmscList != nil {
		if bitStringErr := ber.ValidateBitStringLength(v.BmscList.Bytes, v.BmscList.BitLength); bitStringErr != nil {
			return nil, qualifyBERError(bitStringErr, "bmsc-List", "encoding", false)
		}
		// arithmetic pattern BER_BITSTRING_FIELD: 0 <= bit length before modulo and subtraction; gen/codegen.go:644
		if v.BmscList.BitLength < 0 {
			return nil, fmt.Errorf("negative bit string length")
		}
		if (*v.BmscList).BitLength < 1 || (*v.BmscList).BitLength > 8 {
			if constraintErr := ber.CheckEncodedLength(opts, "bmsc-List", "SIZE (1..8)", (*v.BmscList).BitLength); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_bmsclist, encodeErr_enc_bmsclist := ber.EncodeBitString(v.BmscList.Bytes, ber.UnusedBitCount(v.BmscList.BitLength))
		if encodeErr_enc_bmsclist != nil {
			return nil, qualifyBERError(encodeErr_enc_bmsclist, "bmsc-List", "encoding", false)
		}
		retagged_enc_bmsclist, tagErr_enc_bmsclist := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 5, enc_bmsclist)
		if tagErr_enc_bmsclist != nil {
			return nil, qualifyBERError(tagErr_enc_bmsclist, "bmsc-List", "encoding", false)
		}
		enc_bmsclist = retagged_enc_bmsclist
		children = append(children, enc_bmsclist...)
	}
	if v.MmeList != nil {
		if bitStringErr := ber.ValidateBitStringLength(v.MmeList.Bytes, v.MmeList.BitLength); bitStringErr != nil {
			return nil, qualifyBERError(bitStringErr, "mme-List", "encoding", false)
		}
		// arithmetic pattern BER_BITSTRING_FIELD: 0 <= bit length before modulo and subtraction; gen/codegen.go:644
		if v.MmeList.BitLength < 0 {
			return nil, fmt.Errorf("negative bit string length")
		}
		if (*v.MmeList).BitLength < 5 || (*v.MmeList).BitLength > 8 {
			if constraintErr := ber.CheckEncodedLength(opts, "mme-List", "SIZE (5..8)", (*v.MmeList).BitLength); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_mmelist, encodeErr_enc_mmelist := ber.EncodeBitString(v.MmeList.Bytes, ber.UnusedBitCount(v.MmeList.BitLength))
		if encodeErr_enc_mmelist != nil {
			return nil, qualifyBERError(encodeErr_enc_mmelist, "mme-List", "encoding", false)
		}
		retagged_enc_mmelist, tagErr_enc_mmelist := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 6, enc_mmelist)
		if tagErr_enc_mmelist != nil {
			return nil, qualifyBERError(tagErr_enc_mmelist, "mme-List", "encoding", false)
		}
		enc_mmelist = retagged_enc_mmelist
		children = append(children, enc_mmelist...)
	}
	if v.SgwList != nil {
		if bitStringErr := ber.ValidateBitStringLength(v.SgwList.Bytes, v.SgwList.BitLength); bitStringErr != nil {
			return nil, qualifyBERError(bitStringErr, "sgw-List", "encoding", false)
		}
		// arithmetic pattern BER_BITSTRING_FIELD: 0 <= bit length before modulo and subtraction; gen/codegen.go:644
		if v.SgwList.BitLength < 0 {
			return nil, fmt.Errorf("negative bit string length")
		}
		if (*v.SgwList).BitLength < 5 || (*v.SgwList).BitLength > 8 {
			if constraintErr := ber.CheckEncodedLength(opts, "sgw-List", "SIZE (5..8)", (*v.SgwList).BitLength); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_sgwlist, encodeErr_enc_sgwlist := ber.EncodeBitString(v.SgwList.Bytes, ber.UnusedBitCount(v.SgwList.BitLength))
		if encodeErr_enc_sgwlist != nil {
			return nil, qualifyBERError(encodeErr_enc_sgwlist, "sgw-List", "encoding", false)
		}
		retagged_enc_sgwlist, tagErr_enc_sgwlist := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 7, enc_sgwlist)
		if tagErr_enc_sgwlist != nil {
			return nil, qualifyBERError(tagErr_enc_sgwlist, "sgw-List", "encoding", false)
		}
		enc_sgwlist = retagged_enc_sgwlist
		children = append(children, enc_sgwlist...)
	}
	if v.PgwList != nil {
		if bitStringErr := ber.ValidateBitStringLength(v.PgwList.Bytes, v.PgwList.BitLength); bitStringErr != nil {
			return nil, qualifyBERError(bitStringErr, "pgw-List", "encoding", false)
		}
		// arithmetic pattern BER_BITSTRING_FIELD: 0 <= bit length before modulo and subtraction; gen/codegen.go:644
		if v.PgwList.BitLength < 0 {
			return nil, fmt.Errorf("negative bit string length")
		}
		if (*v.PgwList).BitLength < 8 || (*v.PgwList).BitLength > 16 {
			if constraintErr := ber.CheckEncodedLength(opts, "pgw-List", "SIZE (8..16)", (*v.PgwList).BitLength); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_pgwlist, encodeErr_enc_pgwlist := ber.EncodeBitString(v.PgwList.Bytes, ber.UnusedBitCount(v.PgwList.BitLength))
		if encodeErr_enc_pgwlist != nil {
			return nil, qualifyBERError(encodeErr_enc_pgwlist, "pgw-List", "encoding", false)
		}
		retagged_enc_pgwlist, tagErr_enc_pgwlist := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 8, enc_pgwlist)
		if tagErr_enc_pgwlist != nil {
			return nil, qualifyBERError(tagErr_enc_pgwlist, "pgw-List", "encoding", false)
		}
		enc_pgwlist = retagged_enc_pgwlist
		children = append(children, enc_pgwlist...)
	}
	if v.ENBList != nil {
		if bitStringErr := ber.ValidateBitStringLength(v.ENBList.Bytes, v.ENBList.BitLength); bitStringErr != nil {
			return nil, qualifyBERError(bitStringErr, "eNB-List", "encoding", false)
		}
		// arithmetic pattern BER_BITSTRING_FIELD: 0 <= bit length before modulo and subtraction; gen/codegen.go:644
		if v.ENBList.BitLength < 0 {
			return nil, fmt.Errorf("negative bit string length")
		}
		if (*v.ENBList).BitLength < 3 || (*v.ENBList).BitLength > 8 {
			if constraintErr := ber.CheckEncodedLength(opts, "eNB-List", "SIZE (3..8)", (*v.ENBList).BitLength); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_enblist, encodeErr_enc_enblist := ber.EncodeBitString(v.ENBList.Bytes, ber.UnusedBitCount(v.ENBList.BitLength))
		if encodeErr_enc_enblist != nil {
			return nil, qualifyBERError(encodeErr_enc_enblist, "eNB-List", "encoding", false)
		}
		retagged_enc_enblist, tagErr_enc_enblist := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 9, enc_enblist)
		if tagErr_enc_enblist != nil {
			return nil, qualifyBERError(tagErr_enc_enblist, "eNB-List", "encoding", false)
		}
		enc_enblist = retagged_enc_enblist
		children = append(children, enc_enblist...)
	}
	for i, ext := range v.ExtData_ {
		if err := ber.CheckBEROpaqueReplay(opts...); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
		peekTag, n, _, extErr := ber.DecodeEncodedTLV(ext)
		if extErr != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, extErr)
		}
		if n != len(ext) {
			return nil, fmt.Errorf("encoding extension %d: %w", i, ber.ErrExtraData)
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: only the first addition is restricted.
		if i == 0 && ((peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 9) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 8) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 7) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 6) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 5) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0)) {
			if constraintErr := ber.CheckEncodedValue(opts, "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
				return nil, constraintErr
			}
		}
		children = append(children, ext...)
	}
	return ber.EncodeSequence(children)
}

// MarshalDER encodes OMTraceInterfaceList to DER format.
func (v *OMTraceInterfaceList) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: OMTraceInterfaceList receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if v.MscSList != nil {
		if bitStringErr := ber.ValidateBitStringLength(v.MscSList.Bytes, v.MscSList.BitLength); bitStringErr != nil {
			return nil, qualifyBERError(bitStringErr, "msc-s-List", "encoding", true)
		}
		if bitStringErr := ber.ValidateDERBitString(v.MscSList.Bytes, v.MscSList.BitLength); bitStringErr != nil {
			return nil, qualifyBERError(bitStringErr, "msc-s-List", "encoding", true)
		}
		// arithmetic pattern BER_BITSTRING_FIELD: 0 <= bit length before modulo and subtraction; gen/codegen.go:644
		if v.MscSList.BitLength < 0 {
			return nil, fmt.Errorf("negative bit string length")
		}
		if (*v.MscSList).BitLength < 10 || (*v.MscSList).BitLength > 16 {
			if constraintErr := ber.CheckEncodedLength(nil, "msc-s-List", "SIZE (10..16)", (*v.MscSList).BitLength); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_mscslist, encodeErr_enc_mscslist := ber.EncodeDERNamedBitString(v.MscSList.Bytes, v.MscSList.BitLength)
		if encodeErr_enc_mscslist != nil {
			return nil, qualifyBERError(encodeErr_enc_mscslist, "msc-s-List", "encoding", true)
		}
		retagged_enc_mscslist, tagErr_enc_mscslist := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_mscslist)
		if tagErr_enc_mscslist != nil {
			return nil, qualifyBERError(tagErr_enc_mscslist, "msc-s-List", "encoding", true)
		}
		enc_mscslist = retagged_enc_mscslist
		children = append(children, enc_mscslist...)
	}
	if v.MgwList != nil {
		if bitStringErr := ber.ValidateBitStringLength(v.MgwList.Bytes, v.MgwList.BitLength); bitStringErr != nil {
			return nil, qualifyBERError(bitStringErr, "mgw-List", "encoding", true)
		}
		if bitStringErr := ber.ValidateDERBitString(v.MgwList.Bytes, v.MgwList.BitLength); bitStringErr != nil {
			return nil, qualifyBERError(bitStringErr, "mgw-List", "encoding", true)
		}
		// arithmetic pattern BER_BITSTRING_FIELD: 0 <= bit length before modulo and subtraction; gen/codegen.go:644
		if v.MgwList.BitLength < 0 {
			return nil, fmt.Errorf("negative bit string length")
		}
		if (*v.MgwList).BitLength < 3 || (*v.MgwList).BitLength > 8 {
			if constraintErr := ber.CheckEncodedLength(nil, "mgw-List", "SIZE (3..8)", (*v.MgwList).BitLength); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_mgwlist, encodeErr_enc_mgwlist := ber.EncodeDERNamedBitString(v.MgwList.Bytes, v.MgwList.BitLength)
		if encodeErr_enc_mgwlist != nil {
			return nil, qualifyBERError(encodeErr_enc_mgwlist, "mgw-List", "encoding", true)
		}
		retagged_enc_mgwlist, tagErr_enc_mgwlist := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_mgwlist)
		if tagErr_enc_mgwlist != nil {
			return nil, qualifyBERError(tagErr_enc_mgwlist, "mgw-List", "encoding", true)
		}
		enc_mgwlist = retagged_enc_mgwlist
		children = append(children, enc_mgwlist...)
	}
	if v.SgsnList != nil {
		if bitStringErr := ber.ValidateBitStringLength(v.SgsnList.Bytes, v.SgsnList.BitLength); bitStringErr != nil {
			return nil, qualifyBERError(bitStringErr, "sgsn-List", "encoding", true)
		}
		if bitStringErr := ber.ValidateDERBitString(v.SgsnList.Bytes, v.SgsnList.BitLength); bitStringErr != nil {
			return nil, qualifyBERError(bitStringErr, "sgsn-List", "encoding", true)
		}
		// arithmetic pattern BER_BITSTRING_FIELD: 0 <= bit length before modulo and subtraction; gen/codegen.go:644
		if v.SgsnList.BitLength < 0 {
			return nil, fmt.Errorf("negative bit string length")
		}
		if (*v.SgsnList).BitLength < 8 || (*v.SgsnList).BitLength > 16 {
			if constraintErr := ber.CheckEncodedLength(nil, "sgsn-List", "SIZE (8..16)", (*v.SgsnList).BitLength); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_sgsnlist, encodeErr_enc_sgsnlist := ber.EncodeDERNamedBitString(v.SgsnList.Bytes, v.SgsnList.BitLength)
		if encodeErr_enc_sgsnlist != nil {
			return nil, qualifyBERError(encodeErr_enc_sgsnlist, "sgsn-List", "encoding", true)
		}
		retagged_enc_sgsnlist, tagErr_enc_sgsnlist := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_sgsnlist)
		if tagErr_enc_sgsnlist != nil {
			return nil, qualifyBERError(tagErr_enc_sgsnlist, "sgsn-List", "encoding", true)
		}
		enc_sgsnlist = retagged_enc_sgsnlist
		children = append(children, enc_sgsnlist...)
	}
	if v.GgsnList != nil {
		if bitStringErr := ber.ValidateBitStringLength(v.GgsnList.Bytes, v.GgsnList.BitLength); bitStringErr != nil {
			return nil, qualifyBERError(bitStringErr, "ggsn-List", "encoding", true)
		}
		if bitStringErr := ber.ValidateDERBitString(v.GgsnList.Bytes, v.GgsnList.BitLength); bitStringErr != nil {
			return nil, qualifyBERError(bitStringErr, "ggsn-List", "encoding", true)
		}
		// arithmetic pattern BER_BITSTRING_FIELD: 0 <= bit length before modulo and subtraction; gen/codegen.go:644
		if v.GgsnList.BitLength < 0 {
			return nil, fmt.Errorf("negative bit string length")
		}
		if (*v.GgsnList).BitLength < 3 || (*v.GgsnList).BitLength > 8 {
			if constraintErr := ber.CheckEncodedLength(nil, "ggsn-List", "SIZE (3..8)", (*v.GgsnList).BitLength); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_ggsnlist, encodeErr_enc_ggsnlist := ber.EncodeDERNamedBitString(v.GgsnList.Bytes, v.GgsnList.BitLength)
		if encodeErr_enc_ggsnlist != nil {
			return nil, qualifyBERError(encodeErr_enc_ggsnlist, "ggsn-List", "encoding", true)
		}
		retagged_enc_ggsnlist, tagErr_enc_ggsnlist := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, enc_ggsnlist)
		if tagErr_enc_ggsnlist != nil {
			return nil, qualifyBERError(tagErr_enc_ggsnlist, "ggsn-List", "encoding", true)
		}
		enc_ggsnlist = retagged_enc_ggsnlist
		children = append(children, enc_ggsnlist...)
	}
	if v.RncList != nil {
		if bitStringErr := ber.ValidateBitStringLength(v.RncList.Bytes, v.RncList.BitLength); bitStringErr != nil {
			return nil, qualifyBERError(bitStringErr, "rnc-List", "encoding", true)
		}
		if bitStringErr := ber.ValidateDERBitString(v.RncList.Bytes, v.RncList.BitLength); bitStringErr != nil {
			return nil, qualifyBERError(bitStringErr, "rnc-List", "encoding", true)
		}
		// arithmetic pattern BER_BITSTRING_FIELD: 0 <= bit length before modulo and subtraction; gen/codegen.go:644
		if v.RncList.BitLength < 0 {
			return nil, fmt.Errorf("negative bit string length")
		}
		if (*v.RncList).BitLength < 4 || (*v.RncList).BitLength > 8 {
			if constraintErr := ber.CheckEncodedLength(nil, "rnc-List", "SIZE (4..8)", (*v.RncList).BitLength); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_rnclist, encodeErr_enc_rnclist := ber.EncodeDERNamedBitString(v.RncList.Bytes, v.RncList.BitLength)
		if encodeErr_enc_rnclist != nil {
			return nil, qualifyBERError(encodeErr_enc_rnclist, "rnc-List", "encoding", true)
		}
		retagged_enc_rnclist, tagErr_enc_rnclist := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, enc_rnclist)
		if tagErr_enc_rnclist != nil {
			return nil, qualifyBERError(tagErr_enc_rnclist, "rnc-List", "encoding", true)
		}
		enc_rnclist = retagged_enc_rnclist
		children = append(children, enc_rnclist...)
	}
	if v.BmscList != nil {
		if bitStringErr := ber.ValidateBitStringLength(v.BmscList.Bytes, v.BmscList.BitLength); bitStringErr != nil {
			return nil, qualifyBERError(bitStringErr, "bmsc-List", "encoding", true)
		}
		if bitStringErr := ber.ValidateDERBitString(v.BmscList.Bytes, v.BmscList.BitLength); bitStringErr != nil {
			return nil, qualifyBERError(bitStringErr, "bmsc-List", "encoding", true)
		}
		// arithmetic pattern BER_BITSTRING_FIELD: 0 <= bit length before modulo and subtraction; gen/codegen.go:644
		if v.BmscList.BitLength < 0 {
			return nil, fmt.Errorf("negative bit string length")
		}
		if (*v.BmscList).BitLength < 1 || (*v.BmscList).BitLength > 8 {
			if constraintErr := ber.CheckEncodedLength(nil, "bmsc-List", "SIZE (1..8)", (*v.BmscList).BitLength); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_bmsclist, encodeErr_enc_bmsclist := ber.EncodeDERNamedBitString(v.BmscList.Bytes, v.BmscList.BitLength)
		if encodeErr_enc_bmsclist != nil {
			return nil, qualifyBERError(encodeErr_enc_bmsclist, "bmsc-List", "encoding", true)
		}
		retagged_enc_bmsclist, tagErr_enc_bmsclist := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 5, enc_bmsclist)
		if tagErr_enc_bmsclist != nil {
			return nil, qualifyBERError(tagErr_enc_bmsclist, "bmsc-List", "encoding", true)
		}
		enc_bmsclist = retagged_enc_bmsclist
		children = append(children, enc_bmsclist...)
	}
	if v.MmeList != nil {
		if bitStringErr := ber.ValidateBitStringLength(v.MmeList.Bytes, v.MmeList.BitLength); bitStringErr != nil {
			return nil, qualifyBERError(bitStringErr, "mme-List", "encoding", true)
		}
		if bitStringErr := ber.ValidateDERBitString(v.MmeList.Bytes, v.MmeList.BitLength); bitStringErr != nil {
			return nil, qualifyBERError(bitStringErr, "mme-List", "encoding", true)
		}
		// arithmetic pattern BER_BITSTRING_FIELD: 0 <= bit length before modulo and subtraction; gen/codegen.go:644
		if v.MmeList.BitLength < 0 {
			return nil, fmt.Errorf("negative bit string length")
		}
		if (*v.MmeList).BitLength < 5 || (*v.MmeList).BitLength > 8 {
			if constraintErr := ber.CheckEncodedLength(nil, "mme-List", "SIZE (5..8)", (*v.MmeList).BitLength); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_mmelist, encodeErr_enc_mmelist := ber.EncodeDERNamedBitString(v.MmeList.Bytes, v.MmeList.BitLength)
		if encodeErr_enc_mmelist != nil {
			return nil, qualifyBERError(encodeErr_enc_mmelist, "mme-List", "encoding", true)
		}
		retagged_enc_mmelist, tagErr_enc_mmelist := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 6, enc_mmelist)
		if tagErr_enc_mmelist != nil {
			return nil, qualifyBERError(tagErr_enc_mmelist, "mme-List", "encoding", true)
		}
		enc_mmelist = retagged_enc_mmelist
		children = append(children, enc_mmelist...)
	}
	if v.SgwList != nil {
		if bitStringErr := ber.ValidateBitStringLength(v.SgwList.Bytes, v.SgwList.BitLength); bitStringErr != nil {
			return nil, qualifyBERError(bitStringErr, "sgw-List", "encoding", true)
		}
		if bitStringErr := ber.ValidateDERBitString(v.SgwList.Bytes, v.SgwList.BitLength); bitStringErr != nil {
			return nil, qualifyBERError(bitStringErr, "sgw-List", "encoding", true)
		}
		// arithmetic pattern BER_BITSTRING_FIELD: 0 <= bit length before modulo and subtraction; gen/codegen.go:644
		if v.SgwList.BitLength < 0 {
			return nil, fmt.Errorf("negative bit string length")
		}
		if (*v.SgwList).BitLength < 5 || (*v.SgwList).BitLength > 8 {
			if constraintErr := ber.CheckEncodedLength(nil, "sgw-List", "SIZE (5..8)", (*v.SgwList).BitLength); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_sgwlist, encodeErr_enc_sgwlist := ber.EncodeDERNamedBitString(v.SgwList.Bytes, v.SgwList.BitLength)
		if encodeErr_enc_sgwlist != nil {
			return nil, qualifyBERError(encodeErr_enc_sgwlist, "sgw-List", "encoding", true)
		}
		retagged_enc_sgwlist, tagErr_enc_sgwlist := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 7, enc_sgwlist)
		if tagErr_enc_sgwlist != nil {
			return nil, qualifyBERError(tagErr_enc_sgwlist, "sgw-List", "encoding", true)
		}
		enc_sgwlist = retagged_enc_sgwlist
		children = append(children, enc_sgwlist...)
	}
	if v.PgwList != nil {
		if bitStringErr := ber.ValidateBitStringLength(v.PgwList.Bytes, v.PgwList.BitLength); bitStringErr != nil {
			return nil, qualifyBERError(bitStringErr, "pgw-List", "encoding", true)
		}
		if bitStringErr := ber.ValidateDERBitString(v.PgwList.Bytes, v.PgwList.BitLength); bitStringErr != nil {
			return nil, qualifyBERError(bitStringErr, "pgw-List", "encoding", true)
		}
		// arithmetic pattern BER_BITSTRING_FIELD: 0 <= bit length before modulo and subtraction; gen/codegen.go:644
		if v.PgwList.BitLength < 0 {
			return nil, fmt.Errorf("negative bit string length")
		}
		if (*v.PgwList).BitLength < 8 || (*v.PgwList).BitLength > 16 {
			if constraintErr := ber.CheckEncodedLength(nil, "pgw-List", "SIZE (8..16)", (*v.PgwList).BitLength); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_pgwlist, encodeErr_enc_pgwlist := ber.EncodeDERNamedBitString(v.PgwList.Bytes, v.PgwList.BitLength)
		if encodeErr_enc_pgwlist != nil {
			return nil, qualifyBERError(encodeErr_enc_pgwlist, "pgw-List", "encoding", true)
		}
		retagged_enc_pgwlist, tagErr_enc_pgwlist := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 8, enc_pgwlist)
		if tagErr_enc_pgwlist != nil {
			return nil, qualifyBERError(tagErr_enc_pgwlist, "pgw-List", "encoding", true)
		}
		enc_pgwlist = retagged_enc_pgwlist
		children = append(children, enc_pgwlist...)
	}
	if v.ENBList != nil {
		if bitStringErr := ber.ValidateBitStringLength(v.ENBList.Bytes, v.ENBList.BitLength); bitStringErr != nil {
			return nil, qualifyBERError(bitStringErr, "eNB-List", "encoding", true)
		}
		if bitStringErr := ber.ValidateDERBitString(v.ENBList.Bytes, v.ENBList.BitLength); bitStringErr != nil {
			return nil, qualifyBERError(bitStringErr, "eNB-List", "encoding", true)
		}
		// arithmetic pattern BER_BITSTRING_FIELD: 0 <= bit length before modulo and subtraction; gen/codegen.go:644
		if v.ENBList.BitLength < 0 {
			return nil, fmt.Errorf("negative bit string length")
		}
		if (*v.ENBList).BitLength < 3 || (*v.ENBList).BitLength > 8 {
			if constraintErr := ber.CheckEncodedLength(nil, "eNB-List", "SIZE (3..8)", (*v.ENBList).BitLength); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_enblist, encodeErr_enc_enblist := ber.EncodeDERNamedBitString(v.ENBList.Bytes, v.ENBList.BitLength)
		if encodeErr_enc_enblist != nil {
			return nil, qualifyBERError(encodeErr_enc_enblist, "eNB-List", "encoding", true)
		}
		retagged_enc_enblist, tagErr_enc_enblist := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 9, enc_enblist)
		if tagErr_enc_enblist != nil {
			return nil, qualifyBERError(tagErr_enc_enblist, "eNB-List", "encoding", true)
		}
		enc_enblist = retagged_enc_enblist
		children = append(children, enc_enblist...)
	}
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDEREncodedElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
		peekTag, _, _, extErr := ber.DecodeEncodedTLV(ext)
		if extErr != nil {
			return nil, extErr
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: only the first addition is restricted.
		if i == 0 && ((peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 9) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 8) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 7) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 6) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 5) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0)) {
			if constraintErr := ber.CheckEncodedValue(nil, "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
				return nil, constraintErr
			}
		}
		children = append(children, ext...)
	}
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("%s: %w", "encoding OMTraceInterfaceList as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}

// UnmarshalBER decodes OMTraceInterfaceList from BER/DER format.
func (v *OMTraceInterfaceList) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: OMTraceInterfaceList destination is nil", ber.ErrInvalidValue)
	}
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return ber.DiagnosePreflight(err, data, opts, "child", func(probeOpts []ber.DecodeOption) error {
			var probe OMTraceInterfaceList
			return probe.UnmarshalBER(data, probeOpts...)
		})
	}
	*v = OMTraceInterfaceList{}
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
		return fmt.Errorf("%s: %w", "decoding OMTraceInterfaceList SEQUENCE", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "OMTraceInterfaceList", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode msc-s-List
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
				ber.MarkPreflightTarget(opts, "msc-s-List", content[offset:])
				decodedTag_mscslist, n_mscslist, rawVal_mscslist, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "msc-s-List", "decoding", false)
				}
				if decodedTag_mscslist.Class != tag.ClassContextSpecific || decodedTag_mscslist.Number != 0 {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_mscslist), "msc-s-List", "decoding", false)
				}
				bsBytes_mscslist, bsUnused_mscslist, bsErr := ber.DecodeImplicitBitStringValue(decodedTag_mscslist.Constructed, rawVal_mscslist, opts...)
				if bsErr != nil {
					return qualifyBERError(bsErr, "msc-s-List", "decoding", false)
				}
				bsBitLength_mscslist, bsLenErr_mscslist := ber.BitStringBitLength(len(bsBytes_mscslist), bsUnused_mscslist)
				if bsLenErr_mscslist != nil {
					return qualifyBERError(bsLenErr_mscslist, "msc-s-List", "decoding", false)
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
				ber.MarkPreflightTarget(opts, "mgw-List", content[offset:])
				decodedTag_mgwlist, n_mgwlist, rawVal_mgwlist, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "mgw-List", "decoding", false)
				}
				if decodedTag_mgwlist.Class != tag.ClassContextSpecific || decodedTag_mgwlist.Number != 1 {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_mgwlist), "mgw-List", "decoding", false)
				}
				bsBytes_mgwlist, bsUnused_mgwlist, bsErr := ber.DecodeImplicitBitStringValue(decodedTag_mgwlist.Constructed, rawVal_mgwlist, opts...)
				if bsErr != nil {
					return qualifyBERError(bsErr, "mgw-List", "decoding", false)
				}
				bsBitLength_mgwlist, bsLenErr_mgwlist := ber.BitStringBitLength(len(bsBytes_mgwlist), bsUnused_mgwlist)
				if bsLenErr_mgwlist != nil {
					return qualifyBERError(bsLenErr_mgwlist, "mgw-List", "decoding", false)
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
				ber.MarkPreflightTarget(opts, "sgsn-List", content[offset:])
				decodedTag_sgsnlist, n_sgsnlist, rawVal_sgsnlist, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "sgsn-List", "decoding", false)
				}
				if decodedTag_sgsnlist.Class != tag.ClassContextSpecific || decodedTag_sgsnlist.Number != 2 {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_sgsnlist), "sgsn-List", "decoding", false)
				}
				bsBytes_sgsnlist, bsUnused_sgsnlist, bsErr := ber.DecodeImplicitBitStringValue(decodedTag_sgsnlist.Constructed, rawVal_sgsnlist, opts...)
				if bsErr != nil {
					return qualifyBERError(bsErr, "sgsn-List", "decoding", false)
				}
				bsBitLength_sgsnlist, bsLenErr_sgsnlist := ber.BitStringBitLength(len(bsBytes_sgsnlist), bsUnused_sgsnlist)
				if bsLenErr_sgsnlist != nil {
					return qualifyBERError(bsLenErr_sgsnlist, "sgsn-List", "decoding", false)
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
				ber.MarkPreflightTarget(opts, "ggsn-List", content[offset:])
				decodedTag_ggsnlist, n_ggsnlist, rawVal_ggsnlist, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "ggsn-List", "decoding", false)
				}
				if decodedTag_ggsnlist.Class != tag.ClassContextSpecific || decodedTag_ggsnlist.Number != 3 {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_ggsnlist), "ggsn-List", "decoding", false)
				}
				bsBytes_ggsnlist, bsUnused_ggsnlist, bsErr := ber.DecodeImplicitBitStringValue(decodedTag_ggsnlist.Constructed, rawVal_ggsnlist, opts...)
				if bsErr != nil {
					return qualifyBERError(bsErr, "ggsn-List", "decoding", false)
				}
				bsBitLength_ggsnlist, bsLenErr_ggsnlist := ber.BitStringBitLength(len(bsBytes_ggsnlist), bsUnused_ggsnlist)
				if bsLenErr_ggsnlist != nil {
					return qualifyBERError(bsLenErr_ggsnlist, "ggsn-List", "decoding", false)
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
				ber.MarkPreflightTarget(opts, "rnc-List", content[offset:])
				decodedTag_rnclist, n_rnclist, rawVal_rnclist, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "rnc-List", "decoding", false)
				}
				if decodedTag_rnclist.Class != tag.ClassContextSpecific || decodedTag_rnclist.Number != 4 {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_rnclist), "rnc-List", "decoding", false)
				}
				bsBytes_rnclist, bsUnused_rnclist, bsErr := ber.DecodeImplicitBitStringValue(decodedTag_rnclist.Constructed, rawVal_rnclist, opts...)
				if bsErr != nil {
					return qualifyBERError(bsErr, "rnc-List", "decoding", false)
				}
				bsBitLength_rnclist, bsLenErr_rnclist := ber.BitStringBitLength(len(bsBytes_rnclist), bsUnused_rnclist)
				if bsLenErr_rnclist != nil {
					return qualifyBERError(bsLenErr_rnclist, "rnc-List", "decoding", false)
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
				ber.MarkPreflightTarget(opts, "bmsc-List", content[offset:])
				decodedTag_bmsclist, n_bmsclist, rawVal_bmsclist, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "bmsc-List", "decoding", false)
				}
				if decodedTag_bmsclist.Class != tag.ClassContextSpecific || decodedTag_bmsclist.Number != 5 {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_bmsclist), "bmsc-List", "decoding", false)
				}
				bsBytes_bmsclist, bsUnused_bmsclist, bsErr := ber.DecodeImplicitBitStringValue(decodedTag_bmsclist.Constructed, rawVal_bmsclist, opts...)
				if bsErr != nil {
					return qualifyBERError(bsErr, "bmsc-List", "decoding", false)
				}
				bsBitLength_bmsclist, bsLenErr_bmsclist := ber.BitStringBitLength(len(bsBytes_bmsclist), bsUnused_bmsclist)
				if bsLenErr_bmsclist != nil {
					return qualifyBERError(bsLenErr_bmsclist, "bmsc-List", "decoding", false)
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
				ber.MarkPreflightTarget(opts, "mme-List", content[offset:])
				decodedTag_mmelist, n_mmelist, rawVal_mmelist, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "mme-List", "decoding", false)
				}
				if decodedTag_mmelist.Class != tag.ClassContextSpecific || decodedTag_mmelist.Number != 6 {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_mmelist), "mme-List", "decoding", false)
				}
				bsBytes_mmelist, bsUnused_mmelist, bsErr := ber.DecodeImplicitBitStringValue(decodedTag_mmelist.Constructed, rawVal_mmelist, opts...)
				if bsErr != nil {
					return qualifyBERError(bsErr, "mme-List", "decoding", false)
				}
				bsBitLength_mmelist, bsLenErr_mmelist := ber.BitStringBitLength(len(bsBytes_mmelist), bsUnused_mmelist)
				if bsLenErr_mmelist != nil {
					return qualifyBERError(bsLenErr_mmelist, "mme-List", "decoding", false)
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
				ber.MarkPreflightTarget(opts, "sgw-List", content[offset:])
				decodedTag_sgwlist, n_sgwlist, rawVal_sgwlist, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "sgw-List", "decoding", false)
				}
				if decodedTag_sgwlist.Class != tag.ClassContextSpecific || decodedTag_sgwlist.Number != 7 {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_sgwlist), "sgw-List", "decoding", false)
				}
				bsBytes_sgwlist, bsUnused_sgwlist, bsErr := ber.DecodeImplicitBitStringValue(decodedTag_sgwlist.Constructed, rawVal_sgwlist, opts...)
				if bsErr != nil {
					return qualifyBERError(bsErr, "sgw-List", "decoding", false)
				}
				bsBitLength_sgwlist, bsLenErr_sgwlist := ber.BitStringBitLength(len(bsBytes_sgwlist), bsUnused_sgwlist)
				if bsLenErr_sgwlist != nil {
					return qualifyBERError(bsLenErr_sgwlist, "sgw-List", "decoding", false)
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
				ber.MarkPreflightTarget(opts, "pgw-List", content[offset:])
				decodedTag_pgwlist, n_pgwlist, rawVal_pgwlist, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "pgw-List", "decoding", false)
				}
				if decodedTag_pgwlist.Class != tag.ClassContextSpecific || decodedTag_pgwlist.Number != 8 {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_pgwlist), "pgw-List", "decoding", false)
				}
				bsBytes_pgwlist, bsUnused_pgwlist, bsErr := ber.DecodeImplicitBitStringValue(decodedTag_pgwlist.Constructed, rawVal_pgwlist, opts...)
				if bsErr != nil {
					return qualifyBERError(bsErr, "pgw-List", "decoding", false)
				}
				bsBitLength_pgwlist, bsLenErr_pgwlist := ber.BitStringBitLength(len(bsBytes_pgwlist), bsUnused_pgwlist)
				if bsLenErr_pgwlist != nil {
					return qualifyBERError(bsLenErr_pgwlist, "pgw-List", "decoding", false)
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
				ber.MarkPreflightTarget(opts, "eNB-List", content[offset:])
				decodedTag_enblist, n_enblist, rawVal_enblist, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "eNB-List", "decoding", false)
				}
				if decodedTag_enblist.Class != tag.ClassContextSpecific || decodedTag_enblist.Number != 9 {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_enblist), "eNB-List", "decoding", false)
				}
				bsBytes_enblist, bsUnused_enblist, bsErr := ber.DecodeImplicitBitStringValue(decodedTag_enblist.Constructed, rawVal_enblist, opts...)
				if bsErr != nil {
					return qualifyBERError(bsErr, "eNB-List", "decoding", false)
				}
				bsBitLength_enblist, bsLenErr_enblist := ber.BitStringBitLength(len(bsBytes_enblist), bsUnused_enblist)
				if bsLenErr_enblist != nil {
					return qualifyBERError(bsLenErr_enblist, "eNB-List", "decoding", false)
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
		peekTag, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:], opts...)
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "OMTraceInterfaceList", Cause: extErr_}
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: the first unknown addition must differ from trailing OPTIONAL/DEFAULT tags.
		if len(v.ExtData_) == 0 && ((peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 9) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 8) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 7) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 6) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 5) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0)) {
			if !ber.ConstraintToleranceEnabled(opts) {
				return &ber.DecodeError{Offset: offset, TypeName: "OMTraceInterfaceList", Cause: fmt.Errorf("%w: repeated or out-of-order SEQUENCE component tag %s", ber.ErrInvalidTag, peekTag)}
			}
			if orderErr_ := ber.CheckDecodedValue(opts, fmt.Sprintf("ExtData_[%d]", len(v.ExtData_)), "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); orderErr_ != nil {
				return orderErr_
			}
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

// MarshalBER encodes OMTraceEventList to BER format.
func (v *OMTraceEventList) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: OMTraceEventList receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *OMTraceEventList) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if v.MscSList != nil {
		if bitStringErr := ber.ValidateBitStringLength(v.MscSList.Bytes, v.MscSList.BitLength); bitStringErr != nil {
			return nil, qualifyBERError(bitStringErr, "msc-s-List", "encoding", false)
		}
		// arithmetic pattern BER_BITSTRING_FIELD: 0 <= bit length before modulo and subtraction; gen/codegen.go:644
		if v.MscSList.BitLength < 0 {
			return nil, fmt.Errorf("negative bit string length")
		}
		if (*v.MscSList).BitLength < 5 || (*v.MscSList).BitLength > 16 {
			if constraintErr := ber.CheckEncodedLength(opts, "msc-s-List", "SIZE (5..16)", (*v.MscSList).BitLength); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_mscslist, encodeErr_enc_mscslist := ber.EncodeBitString(v.MscSList.Bytes, ber.UnusedBitCount(v.MscSList.BitLength))
		if encodeErr_enc_mscslist != nil {
			return nil, qualifyBERError(encodeErr_enc_mscslist, "msc-s-List", "encoding", false)
		}
		retagged_enc_mscslist, tagErr_enc_mscslist := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_mscslist)
		if tagErr_enc_mscslist != nil {
			return nil, qualifyBERError(tagErr_enc_mscslist, "msc-s-List", "encoding", false)
		}
		enc_mscslist = retagged_enc_mscslist
		children = append(children, enc_mscslist...)
	}
	if v.MgwList != nil {
		if bitStringErr := ber.ValidateBitStringLength(v.MgwList.Bytes, v.MgwList.BitLength); bitStringErr != nil {
			return nil, qualifyBERError(bitStringErr, "mgw-List", "encoding", false)
		}
		// arithmetic pattern BER_BITSTRING_FIELD: 0 <= bit length before modulo and subtraction; gen/codegen.go:644
		if v.MgwList.BitLength < 0 {
			return nil, fmt.Errorf("negative bit string length")
		}
		if (*v.MgwList).BitLength < 1 || (*v.MgwList).BitLength > 8 {
			if constraintErr := ber.CheckEncodedLength(opts, "mgw-List", "SIZE (1..8)", (*v.MgwList).BitLength); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_mgwlist, encodeErr_enc_mgwlist := ber.EncodeBitString(v.MgwList.Bytes, ber.UnusedBitCount(v.MgwList.BitLength))
		if encodeErr_enc_mgwlist != nil {
			return nil, qualifyBERError(encodeErr_enc_mgwlist, "mgw-List", "encoding", false)
		}
		retagged_enc_mgwlist, tagErr_enc_mgwlist := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_mgwlist)
		if tagErr_enc_mgwlist != nil {
			return nil, qualifyBERError(tagErr_enc_mgwlist, "mgw-List", "encoding", false)
		}
		enc_mgwlist = retagged_enc_mgwlist
		children = append(children, enc_mgwlist...)
	}
	if v.SgsnList != nil {
		if bitStringErr := ber.ValidateBitStringLength(v.SgsnList.Bytes, v.SgsnList.BitLength); bitStringErr != nil {
			return nil, qualifyBERError(bitStringErr, "sgsn-List", "encoding", false)
		}
		// arithmetic pattern BER_BITSTRING_FIELD: 0 <= bit length before modulo and subtraction; gen/codegen.go:644
		if v.SgsnList.BitLength < 0 {
			return nil, fmt.Errorf("negative bit string length")
		}
		if (*v.SgsnList).BitLength < 4 || (*v.SgsnList).BitLength > 16 {
			if constraintErr := ber.CheckEncodedLength(opts, "sgsn-List", "SIZE (4..16)", (*v.SgsnList).BitLength); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_sgsnlist, encodeErr_enc_sgsnlist := ber.EncodeBitString(v.SgsnList.Bytes, ber.UnusedBitCount(v.SgsnList.BitLength))
		if encodeErr_enc_sgsnlist != nil {
			return nil, qualifyBERError(encodeErr_enc_sgsnlist, "sgsn-List", "encoding", false)
		}
		retagged_enc_sgsnlist, tagErr_enc_sgsnlist := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_sgsnlist)
		if tagErr_enc_sgsnlist != nil {
			return nil, qualifyBERError(tagErr_enc_sgsnlist, "sgsn-List", "encoding", false)
		}
		enc_sgsnlist = retagged_enc_sgsnlist
		children = append(children, enc_sgsnlist...)
	}
	if v.GgsnList != nil {
		if bitStringErr := ber.ValidateBitStringLength(v.GgsnList.Bytes, v.GgsnList.BitLength); bitStringErr != nil {
			return nil, qualifyBERError(bitStringErr, "ggsn-List", "encoding", false)
		}
		// arithmetic pattern BER_BITSTRING_FIELD: 0 <= bit length before modulo and subtraction; gen/codegen.go:644
		if v.GgsnList.BitLength < 0 {
			return nil, fmt.Errorf("negative bit string length")
		}
		if (*v.GgsnList).BitLength < 2 || (*v.GgsnList).BitLength > 8 {
			if constraintErr := ber.CheckEncodedLength(opts, "ggsn-List", "SIZE (2..8)", (*v.GgsnList).BitLength); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_ggsnlist, encodeErr_enc_ggsnlist := ber.EncodeBitString(v.GgsnList.Bytes, ber.UnusedBitCount(v.GgsnList.BitLength))
		if encodeErr_enc_ggsnlist != nil {
			return nil, qualifyBERError(encodeErr_enc_ggsnlist, "ggsn-List", "encoding", false)
		}
		retagged_enc_ggsnlist, tagErr_enc_ggsnlist := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, enc_ggsnlist)
		if tagErr_enc_ggsnlist != nil {
			return nil, qualifyBERError(tagErr_enc_ggsnlist, "ggsn-List", "encoding", false)
		}
		enc_ggsnlist = retagged_enc_ggsnlist
		children = append(children, enc_ggsnlist...)
	}
	if v.BmscList != nil {
		if bitStringErr := ber.ValidateBitStringLength(v.BmscList.Bytes, v.BmscList.BitLength); bitStringErr != nil {
			return nil, qualifyBERError(bitStringErr, "bmsc-List", "encoding", false)
		}
		// arithmetic pattern BER_BITSTRING_FIELD: 0 <= bit length before modulo and subtraction; gen/codegen.go:644
		if v.BmscList.BitLength < 0 {
			return nil, fmt.Errorf("negative bit string length")
		}
		if (*v.BmscList).BitLength < 1 || (*v.BmscList).BitLength > 8 {
			if constraintErr := ber.CheckEncodedLength(opts, "bmsc-List", "SIZE (1..8)", (*v.BmscList).BitLength); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_bmsclist, encodeErr_enc_bmsclist := ber.EncodeBitString(v.BmscList.Bytes, ber.UnusedBitCount(v.BmscList.BitLength))
		if encodeErr_enc_bmsclist != nil {
			return nil, qualifyBERError(encodeErr_enc_bmsclist, "bmsc-List", "encoding", false)
		}
		retagged_enc_bmsclist, tagErr_enc_bmsclist := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, enc_bmsclist)
		if tagErr_enc_bmsclist != nil {
			return nil, qualifyBERError(tagErr_enc_bmsclist, "bmsc-List", "encoding", false)
		}
		enc_bmsclist = retagged_enc_bmsclist
		children = append(children, enc_bmsclist...)
	}
	if v.MmeList != nil {
		if bitStringErr := ber.ValidateBitStringLength(v.MmeList.Bytes, v.MmeList.BitLength); bitStringErr != nil {
			return nil, qualifyBERError(bitStringErr, "mme-List", "encoding", false)
		}
		// arithmetic pattern BER_BITSTRING_FIELD: 0 <= bit length before modulo and subtraction; gen/codegen.go:644
		if v.MmeList.BitLength < 0 {
			return nil, fmt.Errorf("negative bit string length")
		}
		if (*v.MmeList).BitLength < 6 || (*v.MmeList).BitLength > 8 {
			if constraintErr := ber.CheckEncodedLength(opts, "mme-List", "SIZE (6..8)", (*v.MmeList).BitLength); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_mmelist, encodeErr_enc_mmelist := ber.EncodeBitString(v.MmeList.Bytes, ber.UnusedBitCount(v.MmeList.BitLength))
		if encodeErr_enc_mmelist != nil {
			return nil, qualifyBERError(encodeErr_enc_mmelist, "mme-List", "encoding", false)
		}
		retagged_enc_mmelist, tagErr_enc_mmelist := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 5, enc_mmelist)
		if tagErr_enc_mmelist != nil {
			return nil, qualifyBERError(tagErr_enc_mmelist, "mme-List", "encoding", false)
		}
		enc_mmelist = retagged_enc_mmelist
		children = append(children, enc_mmelist...)
	}
	if v.SgwList != nil {
		if bitStringErr := ber.ValidateBitStringLength(v.SgwList.Bytes, v.SgwList.BitLength); bitStringErr != nil {
			return nil, qualifyBERError(bitStringErr, "sgw-List", "encoding", false)
		}
		// arithmetic pattern BER_BITSTRING_FIELD: 0 <= bit length before modulo and subtraction; gen/codegen.go:644
		if v.SgwList.BitLength < 0 {
			return nil, fmt.Errorf("negative bit string length")
		}
		if (*v.SgwList).BitLength < 3 || (*v.SgwList).BitLength > 8 {
			if constraintErr := ber.CheckEncodedLength(opts, "sgw-List", "SIZE (3..8)", (*v.SgwList).BitLength); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_sgwlist, encodeErr_enc_sgwlist := ber.EncodeBitString(v.SgwList.Bytes, ber.UnusedBitCount(v.SgwList.BitLength))
		if encodeErr_enc_sgwlist != nil {
			return nil, qualifyBERError(encodeErr_enc_sgwlist, "sgw-List", "encoding", false)
		}
		retagged_enc_sgwlist, tagErr_enc_sgwlist := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 6, enc_sgwlist)
		if tagErr_enc_sgwlist != nil {
			return nil, qualifyBERError(tagErr_enc_sgwlist, "sgw-List", "encoding", false)
		}
		enc_sgwlist = retagged_enc_sgwlist
		children = append(children, enc_sgwlist...)
	}
	if v.PgwList != nil {
		if bitStringErr := ber.ValidateBitStringLength(v.PgwList.Bytes, v.PgwList.BitLength); bitStringErr != nil {
			return nil, qualifyBERError(bitStringErr, "pgw-List", "encoding", false)
		}
		// arithmetic pattern BER_BITSTRING_FIELD: 0 <= bit length before modulo and subtraction; gen/codegen.go:644
		if v.PgwList.BitLength < 0 {
			return nil, fmt.Errorf("negative bit string length")
		}
		if (*v.PgwList).BitLength < 3 || (*v.PgwList).BitLength > 8 {
			if constraintErr := ber.CheckEncodedLength(opts, "pgw-List", "SIZE (3..8)", (*v.PgwList).BitLength); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_pgwlist, encodeErr_enc_pgwlist := ber.EncodeBitString(v.PgwList.Bytes, ber.UnusedBitCount(v.PgwList.BitLength))
		if encodeErr_enc_pgwlist != nil {
			return nil, qualifyBERError(encodeErr_enc_pgwlist, "pgw-List", "encoding", false)
		}
		retagged_enc_pgwlist, tagErr_enc_pgwlist := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 7, enc_pgwlist)
		if tagErr_enc_pgwlist != nil {
			return nil, qualifyBERError(tagErr_enc_pgwlist, "pgw-List", "encoding", false)
		}
		enc_pgwlist = retagged_enc_pgwlist
		children = append(children, enc_pgwlist...)
	}
	for i, ext := range v.ExtData_ {
		if err := ber.CheckBEROpaqueReplay(opts...); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
		peekTag, n, _, extErr := ber.DecodeEncodedTLV(ext)
		if extErr != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, extErr)
		}
		if n != len(ext) {
			return nil, fmt.Errorf("encoding extension %d: %w", i, ber.ErrExtraData)
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: only the first addition is restricted.
		if i == 0 && ((peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 7) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 6) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 5) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0)) {
			if constraintErr := ber.CheckEncodedValue(opts, "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
				return nil, constraintErr
			}
		}
		children = append(children, ext...)
	}
	return ber.EncodeSequence(children)
}

// MarshalDER encodes OMTraceEventList to DER format.
func (v *OMTraceEventList) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: OMTraceEventList receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if v.MscSList != nil {
		if bitStringErr := ber.ValidateBitStringLength(v.MscSList.Bytes, v.MscSList.BitLength); bitStringErr != nil {
			return nil, qualifyBERError(bitStringErr, "msc-s-List", "encoding", true)
		}
		if bitStringErr := ber.ValidateDERBitString(v.MscSList.Bytes, v.MscSList.BitLength); bitStringErr != nil {
			return nil, qualifyBERError(bitStringErr, "msc-s-List", "encoding", true)
		}
		// arithmetic pattern BER_BITSTRING_FIELD: 0 <= bit length before modulo and subtraction; gen/codegen.go:644
		if v.MscSList.BitLength < 0 {
			return nil, fmt.Errorf("negative bit string length")
		}
		if (*v.MscSList).BitLength < 5 || (*v.MscSList).BitLength > 16 {
			if constraintErr := ber.CheckEncodedLength(nil, "msc-s-List", "SIZE (5..16)", (*v.MscSList).BitLength); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_mscslist, encodeErr_enc_mscslist := ber.EncodeDERNamedBitString(v.MscSList.Bytes, v.MscSList.BitLength)
		if encodeErr_enc_mscslist != nil {
			return nil, qualifyBERError(encodeErr_enc_mscslist, "msc-s-List", "encoding", true)
		}
		retagged_enc_mscslist, tagErr_enc_mscslist := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_mscslist)
		if tagErr_enc_mscslist != nil {
			return nil, qualifyBERError(tagErr_enc_mscslist, "msc-s-List", "encoding", true)
		}
		enc_mscslist = retagged_enc_mscslist
		children = append(children, enc_mscslist...)
	}
	if v.MgwList != nil {
		if bitStringErr := ber.ValidateBitStringLength(v.MgwList.Bytes, v.MgwList.BitLength); bitStringErr != nil {
			return nil, qualifyBERError(bitStringErr, "mgw-List", "encoding", true)
		}
		if bitStringErr := ber.ValidateDERBitString(v.MgwList.Bytes, v.MgwList.BitLength); bitStringErr != nil {
			return nil, qualifyBERError(bitStringErr, "mgw-List", "encoding", true)
		}
		// arithmetic pattern BER_BITSTRING_FIELD: 0 <= bit length before modulo and subtraction; gen/codegen.go:644
		if v.MgwList.BitLength < 0 {
			return nil, fmt.Errorf("negative bit string length")
		}
		if (*v.MgwList).BitLength < 1 || (*v.MgwList).BitLength > 8 {
			if constraintErr := ber.CheckEncodedLength(nil, "mgw-List", "SIZE (1..8)", (*v.MgwList).BitLength); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_mgwlist, encodeErr_enc_mgwlist := ber.EncodeDERNamedBitString(v.MgwList.Bytes, v.MgwList.BitLength)
		if encodeErr_enc_mgwlist != nil {
			return nil, qualifyBERError(encodeErr_enc_mgwlist, "mgw-List", "encoding", true)
		}
		retagged_enc_mgwlist, tagErr_enc_mgwlist := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_mgwlist)
		if tagErr_enc_mgwlist != nil {
			return nil, qualifyBERError(tagErr_enc_mgwlist, "mgw-List", "encoding", true)
		}
		enc_mgwlist = retagged_enc_mgwlist
		children = append(children, enc_mgwlist...)
	}
	if v.SgsnList != nil {
		if bitStringErr := ber.ValidateBitStringLength(v.SgsnList.Bytes, v.SgsnList.BitLength); bitStringErr != nil {
			return nil, qualifyBERError(bitStringErr, "sgsn-List", "encoding", true)
		}
		if bitStringErr := ber.ValidateDERBitString(v.SgsnList.Bytes, v.SgsnList.BitLength); bitStringErr != nil {
			return nil, qualifyBERError(bitStringErr, "sgsn-List", "encoding", true)
		}
		// arithmetic pattern BER_BITSTRING_FIELD: 0 <= bit length before modulo and subtraction; gen/codegen.go:644
		if v.SgsnList.BitLength < 0 {
			return nil, fmt.Errorf("negative bit string length")
		}
		if (*v.SgsnList).BitLength < 4 || (*v.SgsnList).BitLength > 16 {
			if constraintErr := ber.CheckEncodedLength(nil, "sgsn-List", "SIZE (4..16)", (*v.SgsnList).BitLength); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_sgsnlist, encodeErr_enc_sgsnlist := ber.EncodeDERNamedBitString(v.SgsnList.Bytes, v.SgsnList.BitLength)
		if encodeErr_enc_sgsnlist != nil {
			return nil, qualifyBERError(encodeErr_enc_sgsnlist, "sgsn-List", "encoding", true)
		}
		retagged_enc_sgsnlist, tagErr_enc_sgsnlist := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_sgsnlist)
		if tagErr_enc_sgsnlist != nil {
			return nil, qualifyBERError(tagErr_enc_sgsnlist, "sgsn-List", "encoding", true)
		}
		enc_sgsnlist = retagged_enc_sgsnlist
		children = append(children, enc_sgsnlist...)
	}
	if v.GgsnList != nil {
		if bitStringErr := ber.ValidateBitStringLength(v.GgsnList.Bytes, v.GgsnList.BitLength); bitStringErr != nil {
			return nil, qualifyBERError(bitStringErr, "ggsn-List", "encoding", true)
		}
		if bitStringErr := ber.ValidateDERBitString(v.GgsnList.Bytes, v.GgsnList.BitLength); bitStringErr != nil {
			return nil, qualifyBERError(bitStringErr, "ggsn-List", "encoding", true)
		}
		// arithmetic pattern BER_BITSTRING_FIELD: 0 <= bit length before modulo and subtraction; gen/codegen.go:644
		if v.GgsnList.BitLength < 0 {
			return nil, fmt.Errorf("negative bit string length")
		}
		if (*v.GgsnList).BitLength < 2 || (*v.GgsnList).BitLength > 8 {
			if constraintErr := ber.CheckEncodedLength(nil, "ggsn-List", "SIZE (2..8)", (*v.GgsnList).BitLength); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_ggsnlist, encodeErr_enc_ggsnlist := ber.EncodeDERNamedBitString(v.GgsnList.Bytes, v.GgsnList.BitLength)
		if encodeErr_enc_ggsnlist != nil {
			return nil, qualifyBERError(encodeErr_enc_ggsnlist, "ggsn-List", "encoding", true)
		}
		retagged_enc_ggsnlist, tagErr_enc_ggsnlist := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, enc_ggsnlist)
		if tagErr_enc_ggsnlist != nil {
			return nil, qualifyBERError(tagErr_enc_ggsnlist, "ggsn-List", "encoding", true)
		}
		enc_ggsnlist = retagged_enc_ggsnlist
		children = append(children, enc_ggsnlist...)
	}
	if v.BmscList != nil {
		if bitStringErr := ber.ValidateBitStringLength(v.BmscList.Bytes, v.BmscList.BitLength); bitStringErr != nil {
			return nil, qualifyBERError(bitStringErr, "bmsc-List", "encoding", true)
		}
		if bitStringErr := ber.ValidateDERBitString(v.BmscList.Bytes, v.BmscList.BitLength); bitStringErr != nil {
			return nil, qualifyBERError(bitStringErr, "bmsc-List", "encoding", true)
		}
		// arithmetic pattern BER_BITSTRING_FIELD: 0 <= bit length before modulo and subtraction; gen/codegen.go:644
		if v.BmscList.BitLength < 0 {
			return nil, fmt.Errorf("negative bit string length")
		}
		if (*v.BmscList).BitLength < 1 || (*v.BmscList).BitLength > 8 {
			if constraintErr := ber.CheckEncodedLength(nil, "bmsc-List", "SIZE (1..8)", (*v.BmscList).BitLength); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_bmsclist, encodeErr_enc_bmsclist := ber.EncodeDERNamedBitString(v.BmscList.Bytes, v.BmscList.BitLength)
		if encodeErr_enc_bmsclist != nil {
			return nil, qualifyBERError(encodeErr_enc_bmsclist, "bmsc-List", "encoding", true)
		}
		retagged_enc_bmsclist, tagErr_enc_bmsclist := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, enc_bmsclist)
		if tagErr_enc_bmsclist != nil {
			return nil, qualifyBERError(tagErr_enc_bmsclist, "bmsc-List", "encoding", true)
		}
		enc_bmsclist = retagged_enc_bmsclist
		children = append(children, enc_bmsclist...)
	}
	if v.MmeList != nil {
		if bitStringErr := ber.ValidateBitStringLength(v.MmeList.Bytes, v.MmeList.BitLength); bitStringErr != nil {
			return nil, qualifyBERError(bitStringErr, "mme-List", "encoding", true)
		}
		if bitStringErr := ber.ValidateDERBitString(v.MmeList.Bytes, v.MmeList.BitLength); bitStringErr != nil {
			return nil, qualifyBERError(bitStringErr, "mme-List", "encoding", true)
		}
		// arithmetic pattern BER_BITSTRING_FIELD: 0 <= bit length before modulo and subtraction; gen/codegen.go:644
		if v.MmeList.BitLength < 0 {
			return nil, fmt.Errorf("negative bit string length")
		}
		if (*v.MmeList).BitLength < 6 || (*v.MmeList).BitLength > 8 {
			if constraintErr := ber.CheckEncodedLength(nil, "mme-List", "SIZE (6..8)", (*v.MmeList).BitLength); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_mmelist, encodeErr_enc_mmelist := ber.EncodeDERNamedBitString(v.MmeList.Bytes, v.MmeList.BitLength)
		if encodeErr_enc_mmelist != nil {
			return nil, qualifyBERError(encodeErr_enc_mmelist, "mme-List", "encoding", true)
		}
		retagged_enc_mmelist, tagErr_enc_mmelist := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 5, enc_mmelist)
		if tagErr_enc_mmelist != nil {
			return nil, qualifyBERError(tagErr_enc_mmelist, "mme-List", "encoding", true)
		}
		enc_mmelist = retagged_enc_mmelist
		children = append(children, enc_mmelist...)
	}
	if v.SgwList != nil {
		if bitStringErr := ber.ValidateBitStringLength(v.SgwList.Bytes, v.SgwList.BitLength); bitStringErr != nil {
			return nil, qualifyBERError(bitStringErr, "sgw-List", "encoding", true)
		}
		if bitStringErr := ber.ValidateDERBitString(v.SgwList.Bytes, v.SgwList.BitLength); bitStringErr != nil {
			return nil, qualifyBERError(bitStringErr, "sgw-List", "encoding", true)
		}
		// arithmetic pattern BER_BITSTRING_FIELD: 0 <= bit length before modulo and subtraction; gen/codegen.go:644
		if v.SgwList.BitLength < 0 {
			return nil, fmt.Errorf("negative bit string length")
		}
		if (*v.SgwList).BitLength < 3 || (*v.SgwList).BitLength > 8 {
			if constraintErr := ber.CheckEncodedLength(nil, "sgw-List", "SIZE (3..8)", (*v.SgwList).BitLength); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_sgwlist, encodeErr_enc_sgwlist := ber.EncodeDERNamedBitString(v.SgwList.Bytes, v.SgwList.BitLength)
		if encodeErr_enc_sgwlist != nil {
			return nil, qualifyBERError(encodeErr_enc_sgwlist, "sgw-List", "encoding", true)
		}
		retagged_enc_sgwlist, tagErr_enc_sgwlist := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 6, enc_sgwlist)
		if tagErr_enc_sgwlist != nil {
			return nil, qualifyBERError(tagErr_enc_sgwlist, "sgw-List", "encoding", true)
		}
		enc_sgwlist = retagged_enc_sgwlist
		children = append(children, enc_sgwlist...)
	}
	if v.PgwList != nil {
		if bitStringErr := ber.ValidateBitStringLength(v.PgwList.Bytes, v.PgwList.BitLength); bitStringErr != nil {
			return nil, qualifyBERError(bitStringErr, "pgw-List", "encoding", true)
		}
		if bitStringErr := ber.ValidateDERBitString(v.PgwList.Bytes, v.PgwList.BitLength); bitStringErr != nil {
			return nil, qualifyBERError(bitStringErr, "pgw-List", "encoding", true)
		}
		// arithmetic pattern BER_BITSTRING_FIELD: 0 <= bit length before modulo and subtraction; gen/codegen.go:644
		if v.PgwList.BitLength < 0 {
			return nil, fmt.Errorf("negative bit string length")
		}
		if (*v.PgwList).BitLength < 3 || (*v.PgwList).BitLength > 8 {
			if constraintErr := ber.CheckEncodedLength(nil, "pgw-List", "SIZE (3..8)", (*v.PgwList).BitLength); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_pgwlist, encodeErr_enc_pgwlist := ber.EncodeDERNamedBitString(v.PgwList.Bytes, v.PgwList.BitLength)
		if encodeErr_enc_pgwlist != nil {
			return nil, qualifyBERError(encodeErr_enc_pgwlist, "pgw-List", "encoding", true)
		}
		retagged_enc_pgwlist, tagErr_enc_pgwlist := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 7, enc_pgwlist)
		if tagErr_enc_pgwlist != nil {
			return nil, qualifyBERError(tagErr_enc_pgwlist, "pgw-List", "encoding", true)
		}
		enc_pgwlist = retagged_enc_pgwlist
		children = append(children, enc_pgwlist...)
	}
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDEREncodedElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
		peekTag, _, _, extErr := ber.DecodeEncodedTLV(ext)
		if extErr != nil {
			return nil, extErr
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: only the first addition is restricted.
		if i == 0 && ((peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 7) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 6) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 5) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0)) {
			if constraintErr := ber.CheckEncodedValue(nil, "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
				return nil, constraintErr
			}
		}
		children = append(children, ext...)
	}
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("%s: %w", "encoding OMTraceEventList as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}

// UnmarshalBER decodes OMTraceEventList from BER/DER format.
func (v *OMTraceEventList) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: OMTraceEventList destination is nil", ber.ErrInvalidValue)
	}
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return ber.DiagnosePreflight(err, data, opts, "child", func(probeOpts []ber.DecodeOption) error {
			var probe OMTraceEventList
			return probe.UnmarshalBER(data, probeOpts...)
		})
	}
	*v = OMTraceEventList{}
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
		return fmt.Errorf("%s: %w", "decoding OMTraceEventList SEQUENCE", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "OMTraceEventList", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode msc-s-List
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
				ber.MarkPreflightTarget(opts, "msc-s-List", content[offset:])
				decodedTag_mscslist, n_mscslist, rawVal_mscslist, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "msc-s-List", "decoding", false)
				}
				if decodedTag_mscslist.Class != tag.ClassContextSpecific || decodedTag_mscslist.Number != 0 {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_mscslist), "msc-s-List", "decoding", false)
				}
				bsBytes_mscslist, bsUnused_mscslist, bsErr := ber.DecodeImplicitBitStringValue(decodedTag_mscslist.Constructed, rawVal_mscslist, opts...)
				if bsErr != nil {
					return qualifyBERError(bsErr, "msc-s-List", "decoding", false)
				}
				bsBitLength_mscslist, bsLenErr_mscslist := ber.BitStringBitLength(len(bsBytes_mscslist), bsUnused_mscslist)
				if bsLenErr_mscslist != nil {
					return qualifyBERError(bsLenErr_mscslist, "msc-s-List", "decoding", false)
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
				ber.MarkPreflightTarget(opts, "mgw-List", content[offset:])
				decodedTag_mgwlist, n_mgwlist, rawVal_mgwlist, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "mgw-List", "decoding", false)
				}
				if decodedTag_mgwlist.Class != tag.ClassContextSpecific || decodedTag_mgwlist.Number != 1 {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_mgwlist), "mgw-List", "decoding", false)
				}
				bsBytes_mgwlist, bsUnused_mgwlist, bsErr := ber.DecodeImplicitBitStringValue(decodedTag_mgwlist.Constructed, rawVal_mgwlist, opts...)
				if bsErr != nil {
					return qualifyBERError(bsErr, "mgw-List", "decoding", false)
				}
				bsBitLength_mgwlist, bsLenErr_mgwlist := ber.BitStringBitLength(len(bsBytes_mgwlist), bsUnused_mgwlist)
				if bsLenErr_mgwlist != nil {
					return qualifyBERError(bsLenErr_mgwlist, "mgw-List", "decoding", false)
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
				ber.MarkPreflightTarget(opts, "sgsn-List", content[offset:])
				decodedTag_sgsnlist, n_sgsnlist, rawVal_sgsnlist, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "sgsn-List", "decoding", false)
				}
				if decodedTag_sgsnlist.Class != tag.ClassContextSpecific || decodedTag_sgsnlist.Number != 2 {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_sgsnlist), "sgsn-List", "decoding", false)
				}
				bsBytes_sgsnlist, bsUnused_sgsnlist, bsErr := ber.DecodeImplicitBitStringValue(decodedTag_sgsnlist.Constructed, rawVal_sgsnlist, opts...)
				if bsErr != nil {
					return qualifyBERError(bsErr, "sgsn-List", "decoding", false)
				}
				bsBitLength_sgsnlist, bsLenErr_sgsnlist := ber.BitStringBitLength(len(bsBytes_sgsnlist), bsUnused_sgsnlist)
				if bsLenErr_sgsnlist != nil {
					return qualifyBERError(bsLenErr_sgsnlist, "sgsn-List", "decoding", false)
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
				ber.MarkPreflightTarget(opts, "ggsn-List", content[offset:])
				decodedTag_ggsnlist, n_ggsnlist, rawVal_ggsnlist, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "ggsn-List", "decoding", false)
				}
				if decodedTag_ggsnlist.Class != tag.ClassContextSpecific || decodedTag_ggsnlist.Number != 3 {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_ggsnlist), "ggsn-List", "decoding", false)
				}
				bsBytes_ggsnlist, bsUnused_ggsnlist, bsErr := ber.DecodeImplicitBitStringValue(decodedTag_ggsnlist.Constructed, rawVal_ggsnlist, opts...)
				if bsErr != nil {
					return qualifyBERError(bsErr, "ggsn-List", "decoding", false)
				}
				bsBitLength_ggsnlist, bsLenErr_ggsnlist := ber.BitStringBitLength(len(bsBytes_ggsnlist), bsUnused_ggsnlist)
				if bsLenErr_ggsnlist != nil {
					return qualifyBERError(bsLenErr_ggsnlist, "ggsn-List", "decoding", false)
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
				ber.MarkPreflightTarget(opts, "bmsc-List", content[offset:])
				decodedTag_bmsclist, n_bmsclist, rawVal_bmsclist, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "bmsc-List", "decoding", false)
				}
				if decodedTag_bmsclist.Class != tag.ClassContextSpecific || decodedTag_bmsclist.Number != 4 {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_bmsclist), "bmsc-List", "decoding", false)
				}
				bsBytes_bmsclist, bsUnused_bmsclist, bsErr := ber.DecodeImplicitBitStringValue(decodedTag_bmsclist.Constructed, rawVal_bmsclist, opts...)
				if bsErr != nil {
					return qualifyBERError(bsErr, "bmsc-List", "decoding", false)
				}
				bsBitLength_bmsclist, bsLenErr_bmsclist := ber.BitStringBitLength(len(bsBytes_bmsclist), bsUnused_bmsclist)
				if bsLenErr_bmsclist != nil {
					return qualifyBERError(bsLenErr_bmsclist, "bmsc-List", "decoding", false)
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
				ber.MarkPreflightTarget(opts, "mme-List", content[offset:])
				decodedTag_mmelist, n_mmelist, rawVal_mmelist, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "mme-List", "decoding", false)
				}
				if decodedTag_mmelist.Class != tag.ClassContextSpecific || decodedTag_mmelist.Number != 5 {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_mmelist), "mme-List", "decoding", false)
				}
				bsBytes_mmelist, bsUnused_mmelist, bsErr := ber.DecodeImplicitBitStringValue(decodedTag_mmelist.Constructed, rawVal_mmelist, opts...)
				if bsErr != nil {
					return qualifyBERError(bsErr, "mme-List", "decoding", false)
				}
				bsBitLength_mmelist, bsLenErr_mmelist := ber.BitStringBitLength(len(bsBytes_mmelist), bsUnused_mmelist)
				if bsLenErr_mmelist != nil {
					return qualifyBERError(bsLenErr_mmelist, "mme-List", "decoding", false)
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
				ber.MarkPreflightTarget(opts, "sgw-List", content[offset:])
				decodedTag_sgwlist, n_sgwlist, rawVal_sgwlist, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "sgw-List", "decoding", false)
				}
				if decodedTag_sgwlist.Class != tag.ClassContextSpecific || decodedTag_sgwlist.Number != 6 {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_sgwlist), "sgw-List", "decoding", false)
				}
				bsBytes_sgwlist, bsUnused_sgwlist, bsErr := ber.DecodeImplicitBitStringValue(decodedTag_sgwlist.Constructed, rawVal_sgwlist, opts...)
				if bsErr != nil {
					return qualifyBERError(bsErr, "sgw-List", "decoding", false)
				}
				bsBitLength_sgwlist, bsLenErr_sgwlist := ber.BitStringBitLength(len(bsBytes_sgwlist), bsUnused_sgwlist)
				if bsLenErr_sgwlist != nil {
					return qualifyBERError(bsLenErr_sgwlist, "sgw-List", "decoding", false)
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
				ber.MarkPreflightTarget(opts, "pgw-List", content[offset:])
				decodedTag_pgwlist, n_pgwlist, rawVal_pgwlist, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "pgw-List", "decoding", false)
				}
				if decodedTag_pgwlist.Class != tag.ClassContextSpecific || decodedTag_pgwlist.Number != 7 {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_pgwlist), "pgw-List", "decoding", false)
				}
				bsBytes_pgwlist, bsUnused_pgwlist, bsErr := ber.DecodeImplicitBitStringValue(decodedTag_pgwlist.Constructed, rawVal_pgwlist, opts...)
				if bsErr != nil {
					return qualifyBERError(bsErr, "pgw-List", "decoding", false)
				}
				bsBitLength_pgwlist, bsLenErr_pgwlist := ber.BitStringBitLength(len(bsBytes_pgwlist), bsUnused_pgwlist)
				if bsLenErr_pgwlist != nil {
					return qualifyBERError(bsLenErr_pgwlist, "pgw-List", "decoding", false)
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
		peekTag, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:], opts...)
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "OMTraceEventList", Cause: extErr_}
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: the first unknown addition must differ from trailing OPTIONAL/DEFAULT tags.
		if len(v.ExtData_) == 0 && ((peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 7) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 6) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 5) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0)) {
			if !ber.ConstraintToleranceEnabled(opts) {
				return &ber.DecodeError{Offset: offset, TypeName: "OMTraceEventList", Cause: fmt.Errorf("%w: repeated or out-of-order SEQUENCE component tag %s", ber.ErrInvalidTag, peekTag)}
			}
			if orderErr_ := ber.CheckDecodedValue(opts, fmt.Sprintf("ExtData_[%d]", len(v.ExtData_)), "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); orderErr_ != nil {
				return orderErr_
			}
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

// MarshalBER encodes OMTracePropagationList to BER format.
func (v *OMTracePropagationList) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: OMTracePropagationList receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *OMTracePropagationList) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
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
			return nil, qualifyBERError(encodeErr_enc_tracereference, "traceReference", "encoding", false)
		}
		retagged_enc_tracereference, tagErr_enc_tracereference := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_tracereference)
		if tagErr_enc_tracereference != nil {
			return nil, qualifyBERError(tagErr_enc_tracereference, "traceReference", "encoding", false)
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
			return nil, qualifyBERError(tagErr_enc_tracetype, "traceType", "encoding", false)
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
			return nil, qualifyBERError(encodeErr_enc_tracereference2, "traceReference2", "encoding", false)
		}
		retagged_enc_tracereference2, tagErr_enc_tracereference2 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_tracereference2)
		if tagErr_enc_tracereference2 != nil {
			return nil, qualifyBERError(tagErr_enc_tracereference2, "traceReference2", "encoding", false)
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
			return nil, qualifyBERError(encodeErr_enc_tracerecordingsessionreference, "traceRecordingSessionReference", "encoding", false)
		}
		retagged_enc_tracerecordingsessionreference, tagErr_enc_tracerecordingsessionreference := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, enc_tracerecordingsessionreference)
		if tagErr_enc_tracerecordingsessionreference != nil {
			return nil, qualifyBERError(tagErr_enc_tracerecordingsessionreference, "traceRecordingSessionReference", "encoding", false)
		}
		enc_tracerecordingsessionreference = retagged_enc_tracerecordingsessionreference
		children = append(children, enc_tracerecordingsessionreference...)
	}
	if v.RncTraceDepth != nil {
		enc_rnctracedepth := ber.EncodeEnumerated(int64(*v.RncTraceDepth))
		retagged_enc_rnctracedepth, tagErr_enc_rnctracedepth := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, enc_rnctracedepth)
		if tagErr_enc_rnctracedepth != nil {
			return nil, qualifyBERError(tagErr_enc_rnctracedepth, "rnc-TraceDepth", "encoding", false)
		}
		enc_rnctracedepth = retagged_enc_rnctracedepth
		children = append(children, enc_rnctracedepth...)
	}
	if v.RncInterfaceList != nil {
		if bitStringErr := ber.ValidateBitStringLength(v.RncInterfaceList.Bytes, v.RncInterfaceList.BitLength); bitStringErr != nil {
			return nil, qualifyBERError(bitStringErr, "rnc-InterfaceList", "encoding", false)
		}
		// arithmetic pattern BER_BITSTRING_FIELD: 0 <= bit length before modulo and subtraction; gen/codegen.go:644
		if v.RncInterfaceList.BitLength < 0 {
			return nil, fmt.Errorf("negative bit string length")
		}
		if (*v.RncInterfaceList).BitLength < 4 || (*v.RncInterfaceList).BitLength > 8 {
			if constraintErr := ber.CheckEncodedLength(opts, "rnc-InterfaceList", "SIZE (4..8)", (*v.RncInterfaceList).BitLength); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_rncinterfacelist, encodeErr_enc_rncinterfacelist := ber.EncodeBitString(v.RncInterfaceList.Bytes, ber.UnusedBitCount(v.RncInterfaceList.BitLength))
		if encodeErr_enc_rncinterfacelist != nil {
			return nil, qualifyBERError(encodeErr_enc_rncinterfacelist, "rnc-InterfaceList", "encoding", false)
		}
		retagged_enc_rncinterfacelist, tagErr_enc_rncinterfacelist := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 5, enc_rncinterfacelist)
		if tagErr_enc_rncinterfacelist != nil {
			return nil, qualifyBERError(tagErr_enc_rncinterfacelist, "rnc-InterfaceList", "encoding", false)
		}
		enc_rncinterfacelist = retagged_enc_rncinterfacelist
		children = append(children, enc_rncinterfacelist...)
	}
	if v.MscSTraceDepth != nil {
		enc_mscstracedepth := ber.EncodeEnumerated(int64(*v.MscSTraceDepth))
		retagged_enc_mscstracedepth, tagErr_enc_mscstracedepth := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 6, enc_mscstracedepth)
		if tagErr_enc_mscstracedepth != nil {
			return nil, qualifyBERError(tagErr_enc_mscstracedepth, "msc-s-TraceDepth", "encoding", false)
		}
		enc_mscstracedepth = retagged_enc_mscstracedepth
		children = append(children, enc_mscstracedepth...)
	}
	if v.MscSInterfaceList != nil {
		if bitStringErr := ber.ValidateBitStringLength(v.MscSInterfaceList.Bytes, v.MscSInterfaceList.BitLength); bitStringErr != nil {
			return nil, qualifyBERError(bitStringErr, "msc-s-InterfaceList", "encoding", false)
		}
		// arithmetic pattern BER_BITSTRING_FIELD: 0 <= bit length before modulo and subtraction; gen/codegen.go:644
		if v.MscSInterfaceList.BitLength < 0 {
			return nil, fmt.Errorf("negative bit string length")
		}
		if (*v.MscSInterfaceList).BitLength < 10 || (*v.MscSInterfaceList).BitLength > 16 {
			if constraintErr := ber.CheckEncodedLength(opts, "msc-s-InterfaceList", "SIZE (10..16)", (*v.MscSInterfaceList).BitLength); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_mscsinterfacelist, encodeErr_enc_mscsinterfacelist := ber.EncodeBitString(v.MscSInterfaceList.Bytes, ber.UnusedBitCount(v.MscSInterfaceList.BitLength))
		if encodeErr_enc_mscsinterfacelist != nil {
			return nil, qualifyBERError(encodeErr_enc_mscsinterfacelist, "msc-s-InterfaceList", "encoding", false)
		}
		retagged_enc_mscsinterfacelist, tagErr_enc_mscsinterfacelist := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 7, enc_mscsinterfacelist)
		if tagErr_enc_mscsinterfacelist != nil {
			return nil, qualifyBERError(tagErr_enc_mscsinterfacelist, "msc-s-InterfaceList", "encoding", false)
		}
		enc_mscsinterfacelist = retagged_enc_mscsinterfacelist
		children = append(children, enc_mscsinterfacelist...)
	}
	if v.MscSEventList != nil {
		if bitStringErr := ber.ValidateBitStringLength(v.MscSEventList.Bytes, v.MscSEventList.BitLength); bitStringErr != nil {
			return nil, qualifyBERError(bitStringErr, "msc-s-EventList", "encoding", false)
		}
		// arithmetic pattern BER_BITSTRING_FIELD: 0 <= bit length before modulo and subtraction; gen/codegen.go:644
		if v.MscSEventList.BitLength < 0 {
			return nil, fmt.Errorf("negative bit string length")
		}
		if (*v.MscSEventList).BitLength < 5 || (*v.MscSEventList).BitLength > 16 {
			if constraintErr := ber.CheckEncodedLength(opts, "msc-s-EventList", "SIZE (5..16)", (*v.MscSEventList).BitLength); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_mscseventlist, encodeErr_enc_mscseventlist := ber.EncodeBitString(v.MscSEventList.Bytes, ber.UnusedBitCount(v.MscSEventList.BitLength))
		if encodeErr_enc_mscseventlist != nil {
			return nil, qualifyBERError(encodeErr_enc_mscseventlist, "msc-s-EventList", "encoding", false)
		}
		retagged_enc_mscseventlist, tagErr_enc_mscseventlist := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 8, enc_mscseventlist)
		if tagErr_enc_mscseventlist != nil {
			return nil, qualifyBERError(tagErr_enc_mscseventlist, "msc-s-EventList", "encoding", false)
		}
		enc_mscseventlist = retagged_enc_mscseventlist
		children = append(children, enc_mscseventlist...)
	}
	if v.MgwTraceDepth != nil {
		enc_mgwtracedepth := ber.EncodeEnumerated(int64(*v.MgwTraceDepth))
		retagged_enc_mgwtracedepth, tagErr_enc_mgwtracedepth := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 9, enc_mgwtracedepth)
		if tagErr_enc_mgwtracedepth != nil {
			return nil, qualifyBERError(tagErr_enc_mgwtracedepth, "mgw-TraceDepth", "encoding", false)
		}
		enc_mgwtracedepth = retagged_enc_mgwtracedepth
		children = append(children, enc_mgwtracedepth...)
	}
	if v.MgwInterfaceList != nil {
		if bitStringErr := ber.ValidateBitStringLength(v.MgwInterfaceList.Bytes, v.MgwInterfaceList.BitLength); bitStringErr != nil {
			return nil, qualifyBERError(bitStringErr, "mgw-InterfaceList", "encoding", false)
		}
		// arithmetic pattern BER_BITSTRING_FIELD: 0 <= bit length before modulo and subtraction; gen/codegen.go:644
		if v.MgwInterfaceList.BitLength < 0 {
			return nil, fmt.Errorf("negative bit string length")
		}
		if (*v.MgwInterfaceList).BitLength < 3 || (*v.MgwInterfaceList).BitLength > 8 {
			if constraintErr := ber.CheckEncodedLength(opts, "mgw-InterfaceList", "SIZE (3..8)", (*v.MgwInterfaceList).BitLength); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_mgwinterfacelist, encodeErr_enc_mgwinterfacelist := ber.EncodeBitString(v.MgwInterfaceList.Bytes, ber.UnusedBitCount(v.MgwInterfaceList.BitLength))
		if encodeErr_enc_mgwinterfacelist != nil {
			return nil, qualifyBERError(encodeErr_enc_mgwinterfacelist, "mgw-InterfaceList", "encoding", false)
		}
		retagged_enc_mgwinterfacelist, tagErr_enc_mgwinterfacelist := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 10, enc_mgwinterfacelist)
		if tagErr_enc_mgwinterfacelist != nil {
			return nil, qualifyBERError(tagErr_enc_mgwinterfacelist, "mgw-InterfaceList", "encoding", false)
		}
		enc_mgwinterfacelist = retagged_enc_mgwinterfacelist
		children = append(children, enc_mgwinterfacelist...)
	}
	if v.MgwEventList != nil {
		if bitStringErr := ber.ValidateBitStringLength(v.MgwEventList.Bytes, v.MgwEventList.BitLength); bitStringErr != nil {
			return nil, qualifyBERError(bitStringErr, "mgw-EventList", "encoding", false)
		}
		// arithmetic pattern BER_BITSTRING_FIELD: 0 <= bit length before modulo and subtraction; gen/codegen.go:644
		if v.MgwEventList.BitLength < 0 {
			return nil, fmt.Errorf("negative bit string length")
		}
		if (*v.MgwEventList).BitLength < 1 || (*v.MgwEventList).BitLength > 8 {
			if constraintErr := ber.CheckEncodedLength(opts, "mgw-EventList", "SIZE (1..8)", (*v.MgwEventList).BitLength); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_mgweventlist, encodeErr_enc_mgweventlist := ber.EncodeBitString(v.MgwEventList.Bytes, ber.UnusedBitCount(v.MgwEventList.BitLength))
		if encodeErr_enc_mgweventlist != nil {
			return nil, qualifyBERError(encodeErr_enc_mgweventlist, "mgw-EventList", "encoding", false)
		}
		retagged_enc_mgweventlist, tagErr_enc_mgweventlist := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 11, enc_mgweventlist)
		if tagErr_enc_mgweventlist != nil {
			return nil, qualifyBERError(tagErr_enc_mgweventlist, "mgw-EventList", "encoding", false)
		}
		enc_mgweventlist = retagged_enc_mgweventlist
		children = append(children, enc_mgweventlist...)
	}
	if v.RncTraceDepthExtension != nil {
		enc_rnctracedepthextension := ber.EncodeEnumerated(int64(*v.RncTraceDepthExtension))
		retagged_enc_rnctracedepthextension, tagErr_enc_rnctracedepthextension := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 12, enc_rnctracedepthextension)
		if tagErr_enc_rnctracedepthextension != nil {
			return nil, qualifyBERError(tagErr_enc_rnctracedepthextension, "rnc-TraceDepthExtension", "encoding", false)
		}
		enc_rnctracedepthextension = retagged_enc_rnctracedepthextension
		children = append(children, enc_rnctracedepthextension...)
	}
	if v.MscSTraceDepthExtension != nil {
		enc_mscstracedepthextension := ber.EncodeEnumerated(int64(*v.MscSTraceDepthExtension))
		retagged_enc_mscstracedepthextension, tagErr_enc_mscstracedepthextension := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 13, enc_mscstracedepthextension)
		if tagErr_enc_mscstracedepthextension != nil {
			return nil, qualifyBERError(tagErr_enc_mscstracedepthextension, "msc-s-TraceDepthExtension", "encoding", false)
		}
		enc_mscstracedepthextension = retagged_enc_mscstracedepthextension
		children = append(children, enc_mscstracedepthextension...)
	}
	if v.MgwTraceDepthExtension != nil {
		enc_mgwtracedepthextension := ber.EncodeEnumerated(int64(*v.MgwTraceDepthExtension))
		retagged_enc_mgwtracedepthextension, tagErr_enc_mgwtracedepthextension := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 14, enc_mgwtracedepthextension)
		if tagErr_enc_mgwtracedepthextension != nil {
			return nil, qualifyBERError(tagErr_enc_mgwtracedepthextension, "mgw-TraceDepthExtension", "encoding", false)
		}
		enc_mgwtracedepthextension = retagged_enc_mgwtracedepthextension
		children = append(children, enc_mgwtracedepthextension...)
	}
	for i, ext := range v.ExtData_ {
		if err := ber.CheckBEROpaqueReplay(opts...); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
		peekTag, n, _, extErr := ber.DecodeEncodedTLV(ext)
		if extErr != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, extErr)
		}
		if n != len(ext) {
			return nil, fmt.Errorf("encoding extension %d: %w", i, ber.ErrExtraData)
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: only the first addition is restricted.
		if i == 0 && ((peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 14) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 13) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 12) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 11) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 10) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 9) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 8) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 7) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 6) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 5) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0)) {
			if constraintErr := ber.CheckEncodedValue(opts, "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
				return nil, constraintErr
			}
		}
		children = append(children, ext...)
	}
	return ber.EncodeSequence(children)
}

// MarshalDER encodes OMTracePropagationList to DER format.
func (v *OMTracePropagationList) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: OMTracePropagationList receiver is nil", ber.ErrInvalidValue)
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
			return nil, qualifyBERError(encodeErr_enc_tracereference, "traceReference", "encoding", true)
		}
		retagged_enc_tracereference, tagErr_enc_tracereference := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_tracereference)
		if tagErr_enc_tracereference != nil {
			return nil, qualifyBERError(tagErr_enc_tracereference, "traceReference", "encoding", true)
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
			return nil, qualifyBERError(tagErr_enc_tracetype, "traceType", "encoding", true)
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
			return nil, qualifyBERError(encodeErr_enc_tracereference2, "traceReference2", "encoding", true)
		}
		retagged_enc_tracereference2, tagErr_enc_tracereference2 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_tracereference2)
		if tagErr_enc_tracereference2 != nil {
			return nil, qualifyBERError(tagErr_enc_tracereference2, "traceReference2", "encoding", true)
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
			return nil, qualifyBERError(encodeErr_enc_tracerecordingsessionreference, "traceRecordingSessionReference", "encoding", true)
		}
		retagged_enc_tracerecordingsessionreference, tagErr_enc_tracerecordingsessionreference := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, enc_tracerecordingsessionreference)
		if tagErr_enc_tracerecordingsessionreference != nil {
			return nil, qualifyBERError(tagErr_enc_tracerecordingsessionreference, "traceRecordingSessionReference", "encoding", true)
		}
		enc_tracerecordingsessionreference = retagged_enc_tracerecordingsessionreference
		children = append(children, enc_tracerecordingsessionreference...)
	}
	if v.RncTraceDepth != nil {
		enc_rnctracedepth := ber.EncodeEnumerated(int64(*v.RncTraceDepth))
		retagged_enc_rnctracedepth, tagErr_enc_rnctracedepth := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, enc_rnctracedepth)
		if tagErr_enc_rnctracedepth != nil {
			return nil, qualifyBERError(tagErr_enc_rnctracedepth, "rnc-TraceDepth", "encoding", true)
		}
		enc_rnctracedepth = retagged_enc_rnctracedepth
		children = append(children, enc_rnctracedepth...)
	}
	if v.RncInterfaceList != nil {
		if bitStringErr := ber.ValidateBitStringLength(v.RncInterfaceList.Bytes, v.RncInterfaceList.BitLength); bitStringErr != nil {
			return nil, qualifyBERError(bitStringErr, "rnc-InterfaceList", "encoding", true)
		}
		if bitStringErr := ber.ValidateDERBitString(v.RncInterfaceList.Bytes, v.RncInterfaceList.BitLength); bitStringErr != nil {
			return nil, qualifyBERError(bitStringErr, "rnc-InterfaceList", "encoding", true)
		}
		// arithmetic pattern BER_BITSTRING_FIELD: 0 <= bit length before modulo and subtraction; gen/codegen.go:644
		if v.RncInterfaceList.BitLength < 0 {
			return nil, fmt.Errorf("negative bit string length")
		}
		if (*v.RncInterfaceList).BitLength < 4 || (*v.RncInterfaceList).BitLength > 8 {
			if constraintErr := ber.CheckEncodedLength(nil, "rnc-InterfaceList", "SIZE (4..8)", (*v.RncInterfaceList).BitLength); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_rncinterfacelist, encodeErr_enc_rncinterfacelist := ber.EncodeDERNamedBitString(v.RncInterfaceList.Bytes, v.RncInterfaceList.BitLength)
		if encodeErr_enc_rncinterfacelist != nil {
			return nil, qualifyBERError(encodeErr_enc_rncinterfacelist, "rnc-InterfaceList", "encoding", true)
		}
		retagged_enc_rncinterfacelist, tagErr_enc_rncinterfacelist := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 5, enc_rncinterfacelist)
		if tagErr_enc_rncinterfacelist != nil {
			return nil, qualifyBERError(tagErr_enc_rncinterfacelist, "rnc-InterfaceList", "encoding", true)
		}
		enc_rncinterfacelist = retagged_enc_rncinterfacelist
		children = append(children, enc_rncinterfacelist...)
	}
	if v.MscSTraceDepth != nil {
		enc_mscstracedepth := ber.EncodeEnumerated(int64(*v.MscSTraceDepth))
		retagged_enc_mscstracedepth, tagErr_enc_mscstracedepth := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 6, enc_mscstracedepth)
		if tagErr_enc_mscstracedepth != nil {
			return nil, qualifyBERError(tagErr_enc_mscstracedepth, "msc-s-TraceDepth", "encoding", true)
		}
		enc_mscstracedepth = retagged_enc_mscstracedepth
		children = append(children, enc_mscstracedepth...)
	}
	if v.MscSInterfaceList != nil {
		if bitStringErr := ber.ValidateBitStringLength(v.MscSInterfaceList.Bytes, v.MscSInterfaceList.BitLength); bitStringErr != nil {
			return nil, qualifyBERError(bitStringErr, "msc-s-InterfaceList", "encoding", true)
		}
		if bitStringErr := ber.ValidateDERBitString(v.MscSInterfaceList.Bytes, v.MscSInterfaceList.BitLength); bitStringErr != nil {
			return nil, qualifyBERError(bitStringErr, "msc-s-InterfaceList", "encoding", true)
		}
		// arithmetic pattern BER_BITSTRING_FIELD: 0 <= bit length before modulo and subtraction; gen/codegen.go:644
		if v.MscSInterfaceList.BitLength < 0 {
			return nil, fmt.Errorf("negative bit string length")
		}
		if (*v.MscSInterfaceList).BitLength < 10 || (*v.MscSInterfaceList).BitLength > 16 {
			if constraintErr := ber.CheckEncodedLength(nil, "msc-s-InterfaceList", "SIZE (10..16)", (*v.MscSInterfaceList).BitLength); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_mscsinterfacelist, encodeErr_enc_mscsinterfacelist := ber.EncodeDERNamedBitString(v.MscSInterfaceList.Bytes, v.MscSInterfaceList.BitLength)
		if encodeErr_enc_mscsinterfacelist != nil {
			return nil, qualifyBERError(encodeErr_enc_mscsinterfacelist, "msc-s-InterfaceList", "encoding", true)
		}
		retagged_enc_mscsinterfacelist, tagErr_enc_mscsinterfacelist := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 7, enc_mscsinterfacelist)
		if tagErr_enc_mscsinterfacelist != nil {
			return nil, qualifyBERError(tagErr_enc_mscsinterfacelist, "msc-s-InterfaceList", "encoding", true)
		}
		enc_mscsinterfacelist = retagged_enc_mscsinterfacelist
		children = append(children, enc_mscsinterfacelist...)
	}
	if v.MscSEventList != nil {
		if bitStringErr := ber.ValidateBitStringLength(v.MscSEventList.Bytes, v.MscSEventList.BitLength); bitStringErr != nil {
			return nil, qualifyBERError(bitStringErr, "msc-s-EventList", "encoding", true)
		}
		if bitStringErr := ber.ValidateDERBitString(v.MscSEventList.Bytes, v.MscSEventList.BitLength); bitStringErr != nil {
			return nil, qualifyBERError(bitStringErr, "msc-s-EventList", "encoding", true)
		}
		// arithmetic pattern BER_BITSTRING_FIELD: 0 <= bit length before modulo and subtraction; gen/codegen.go:644
		if v.MscSEventList.BitLength < 0 {
			return nil, fmt.Errorf("negative bit string length")
		}
		if (*v.MscSEventList).BitLength < 5 || (*v.MscSEventList).BitLength > 16 {
			if constraintErr := ber.CheckEncodedLength(nil, "msc-s-EventList", "SIZE (5..16)", (*v.MscSEventList).BitLength); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_mscseventlist, encodeErr_enc_mscseventlist := ber.EncodeDERNamedBitString(v.MscSEventList.Bytes, v.MscSEventList.BitLength)
		if encodeErr_enc_mscseventlist != nil {
			return nil, qualifyBERError(encodeErr_enc_mscseventlist, "msc-s-EventList", "encoding", true)
		}
		retagged_enc_mscseventlist, tagErr_enc_mscseventlist := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 8, enc_mscseventlist)
		if tagErr_enc_mscseventlist != nil {
			return nil, qualifyBERError(tagErr_enc_mscseventlist, "msc-s-EventList", "encoding", true)
		}
		enc_mscseventlist = retagged_enc_mscseventlist
		children = append(children, enc_mscseventlist...)
	}
	if v.MgwTraceDepth != nil {
		enc_mgwtracedepth := ber.EncodeEnumerated(int64(*v.MgwTraceDepth))
		retagged_enc_mgwtracedepth, tagErr_enc_mgwtracedepth := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 9, enc_mgwtracedepth)
		if tagErr_enc_mgwtracedepth != nil {
			return nil, qualifyBERError(tagErr_enc_mgwtracedepth, "mgw-TraceDepth", "encoding", true)
		}
		enc_mgwtracedepth = retagged_enc_mgwtracedepth
		children = append(children, enc_mgwtracedepth...)
	}
	if v.MgwInterfaceList != nil {
		if bitStringErr := ber.ValidateBitStringLength(v.MgwInterfaceList.Bytes, v.MgwInterfaceList.BitLength); bitStringErr != nil {
			return nil, qualifyBERError(bitStringErr, "mgw-InterfaceList", "encoding", true)
		}
		if bitStringErr := ber.ValidateDERBitString(v.MgwInterfaceList.Bytes, v.MgwInterfaceList.BitLength); bitStringErr != nil {
			return nil, qualifyBERError(bitStringErr, "mgw-InterfaceList", "encoding", true)
		}
		// arithmetic pattern BER_BITSTRING_FIELD: 0 <= bit length before modulo and subtraction; gen/codegen.go:644
		if v.MgwInterfaceList.BitLength < 0 {
			return nil, fmt.Errorf("negative bit string length")
		}
		if (*v.MgwInterfaceList).BitLength < 3 || (*v.MgwInterfaceList).BitLength > 8 {
			if constraintErr := ber.CheckEncodedLength(nil, "mgw-InterfaceList", "SIZE (3..8)", (*v.MgwInterfaceList).BitLength); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_mgwinterfacelist, encodeErr_enc_mgwinterfacelist := ber.EncodeDERNamedBitString(v.MgwInterfaceList.Bytes, v.MgwInterfaceList.BitLength)
		if encodeErr_enc_mgwinterfacelist != nil {
			return nil, qualifyBERError(encodeErr_enc_mgwinterfacelist, "mgw-InterfaceList", "encoding", true)
		}
		retagged_enc_mgwinterfacelist, tagErr_enc_mgwinterfacelist := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 10, enc_mgwinterfacelist)
		if tagErr_enc_mgwinterfacelist != nil {
			return nil, qualifyBERError(tagErr_enc_mgwinterfacelist, "mgw-InterfaceList", "encoding", true)
		}
		enc_mgwinterfacelist = retagged_enc_mgwinterfacelist
		children = append(children, enc_mgwinterfacelist...)
	}
	if v.MgwEventList != nil {
		if bitStringErr := ber.ValidateBitStringLength(v.MgwEventList.Bytes, v.MgwEventList.BitLength); bitStringErr != nil {
			return nil, qualifyBERError(bitStringErr, "mgw-EventList", "encoding", true)
		}
		if bitStringErr := ber.ValidateDERBitString(v.MgwEventList.Bytes, v.MgwEventList.BitLength); bitStringErr != nil {
			return nil, qualifyBERError(bitStringErr, "mgw-EventList", "encoding", true)
		}
		// arithmetic pattern BER_BITSTRING_FIELD: 0 <= bit length before modulo and subtraction; gen/codegen.go:644
		if v.MgwEventList.BitLength < 0 {
			return nil, fmt.Errorf("negative bit string length")
		}
		if (*v.MgwEventList).BitLength < 1 || (*v.MgwEventList).BitLength > 8 {
			if constraintErr := ber.CheckEncodedLength(nil, "mgw-EventList", "SIZE (1..8)", (*v.MgwEventList).BitLength); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_mgweventlist, encodeErr_enc_mgweventlist := ber.EncodeDERNamedBitString(v.MgwEventList.Bytes, v.MgwEventList.BitLength)
		if encodeErr_enc_mgweventlist != nil {
			return nil, qualifyBERError(encodeErr_enc_mgweventlist, "mgw-EventList", "encoding", true)
		}
		retagged_enc_mgweventlist, tagErr_enc_mgweventlist := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 11, enc_mgweventlist)
		if tagErr_enc_mgweventlist != nil {
			return nil, qualifyBERError(tagErr_enc_mgweventlist, "mgw-EventList", "encoding", true)
		}
		enc_mgweventlist = retagged_enc_mgweventlist
		children = append(children, enc_mgweventlist...)
	}
	if v.RncTraceDepthExtension != nil {
		enc_rnctracedepthextension := ber.EncodeEnumerated(int64(*v.RncTraceDepthExtension))
		retagged_enc_rnctracedepthextension, tagErr_enc_rnctracedepthextension := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 12, enc_rnctracedepthextension)
		if tagErr_enc_rnctracedepthextension != nil {
			return nil, qualifyBERError(tagErr_enc_rnctracedepthextension, "rnc-TraceDepthExtension", "encoding", true)
		}
		enc_rnctracedepthextension = retagged_enc_rnctracedepthextension
		children = append(children, enc_rnctracedepthextension...)
	}
	if v.MscSTraceDepthExtension != nil {
		enc_mscstracedepthextension := ber.EncodeEnumerated(int64(*v.MscSTraceDepthExtension))
		retagged_enc_mscstracedepthextension, tagErr_enc_mscstracedepthextension := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 13, enc_mscstracedepthextension)
		if tagErr_enc_mscstracedepthextension != nil {
			return nil, qualifyBERError(tagErr_enc_mscstracedepthextension, "msc-s-TraceDepthExtension", "encoding", true)
		}
		enc_mscstracedepthextension = retagged_enc_mscstracedepthextension
		children = append(children, enc_mscstracedepthextension...)
	}
	if v.MgwTraceDepthExtension != nil {
		enc_mgwtracedepthextension := ber.EncodeEnumerated(int64(*v.MgwTraceDepthExtension))
		retagged_enc_mgwtracedepthextension, tagErr_enc_mgwtracedepthextension := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 14, enc_mgwtracedepthextension)
		if tagErr_enc_mgwtracedepthextension != nil {
			return nil, qualifyBERError(tagErr_enc_mgwtracedepthextension, "mgw-TraceDepthExtension", "encoding", true)
		}
		enc_mgwtracedepthextension = retagged_enc_mgwtracedepthextension
		children = append(children, enc_mgwtracedepthextension...)
	}
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDEREncodedElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
		peekTag, _, _, extErr := ber.DecodeEncodedTLV(ext)
		if extErr != nil {
			return nil, extErr
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: only the first addition is restricted.
		if i == 0 && ((peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 14) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 13) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 12) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 11) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 10) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 9) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 8) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 7) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 6) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 5) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0)) {
			if constraintErr := ber.CheckEncodedValue(nil, "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
				return nil, constraintErr
			}
		}
		children = append(children, ext...)
	}
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("%s: %w", "encoding OMTracePropagationList as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}

// UnmarshalBER decodes OMTracePropagationList from BER/DER format.
func (v *OMTracePropagationList) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: OMTracePropagationList destination is nil", ber.ErrInvalidValue)
	}
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return ber.DiagnosePreflight(err, data, opts, "child", func(probeOpts []ber.DecodeOption) error {
			var probe OMTracePropagationList
			return probe.UnmarshalBER(data, probeOpts...)
		})
	}
	*v = OMTracePropagationList{}
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
		return fmt.Errorf("%s: %w", "decoding OMTracePropagationList SEQUENCE", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "OMTracePropagationList", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode traceReference
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
				ber.MarkPreflightTarget(opts, "traceReference", content[offset:])
				decodedTag_tracereference, n_tracereference, rawVal_tracereference, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "traceReference", "decoding", false)
				}
				if decodedTag_tracereference.Class != tag.ClassContextSpecific || decodedTag_tracereference.Number != 0 {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_tracereference), "traceReference", "decoding", false)
				}
				decVal_tracereference, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_tracereference.Constructed, rawVal_tracereference, opts...)
				if octetErr != nil {
					return qualifyBERError(octetErr, "traceReference", "decoding", false)
				}
				tmp_tracereference := OMTraceReference(decVal_tracereference)
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
				ber.MarkPreflightTarget(opts, "traceType", content[offset:])
				decodedTag_tracetype, n_tracetype, rawVal_tracetype, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "traceType", "decoding", false)
				}
				if decodedTag_tracetype.Class != tag.ClassContextSpecific || decodedTag_tracetype.Number != 1 || decodedTag_tracetype.Constructed != false {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_tracetype), "traceType", "decoding", false)
				}
				decVal_tracetype, intErr := ber.DecodeIntegerValue(rawVal_tracetype)
				if intErr != nil {
					return qualifyBERError(intErr, "traceType", "decoding", false)
				}
				tmp_tracetype := OMTraceType(decVal_tracetype)
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
				ber.MarkPreflightTarget(opts, "traceReference2", content[offset:])
				decodedTag_tracereference2, n_tracereference2, rawVal_tracereference2, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "traceReference2", "decoding", false)
				}
				if decodedTag_tracereference2.Class != tag.ClassContextSpecific || decodedTag_tracereference2.Number != 2 {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_tracereference2), "traceReference2", "decoding", false)
				}
				decVal_tracereference2, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_tracereference2.Constructed, rawVal_tracereference2, opts...)
				if octetErr != nil {
					return qualifyBERError(octetErr, "traceReference2", "decoding", false)
				}
				tmp_tracereference2 := OMTraceReference2(decVal_tracereference2)
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
	// Decode traceRecordingSessionReference
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3 {
				ber.MarkPreflightTarget(opts, "traceRecordingSessionReference", content[offset:])
				decodedTag_tracerecordingsessionreference, n_tracerecordingsessionreference, rawVal_tracerecordingsessionreference, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "traceRecordingSessionReference", "decoding", false)
				}
				if decodedTag_tracerecordingsessionreference.Class != tag.ClassContextSpecific || decodedTag_tracerecordingsessionreference.Number != 3 {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_tracerecordingsessionreference), "traceRecordingSessionReference", "decoding", false)
				}
				decVal_tracerecordingsessionreference, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_tracerecordingsessionreference.Constructed, rawVal_tracerecordingsessionreference, opts...)
				if octetErr != nil {
					return qualifyBERError(octetErr, "traceRecordingSessionReference", "decoding", false)
				}
				tmp_tracerecordingsessionreference := OMTraceRecordingSessionReference(decVal_tracerecordingsessionreference)
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
				ber.MarkPreflightTarget(opts, "rnc-TraceDepth", content[offset:])
				decodedTag_rnctracedepth, n_rnctracedepth, rawVal_rnctracedepth, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "rnc-TraceDepth", "decoding", false)
				}
				if decodedTag_rnctracedepth.Class != tag.ClassContextSpecific || decodedTag_rnctracedepth.Number != 4 || decodedTag_rnctracedepth.Constructed != false {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_rnctracedepth), "rnc-TraceDepth", "decoding", false)
				}
				decVal_rnctracedepth, intErr := ber.DecodeEnumeratedValue(rawVal_rnctracedepth)
				if intErr != nil {
					return qualifyBERError(intErr, "rnc-TraceDepth", "decoding", false)
				}
				tmp_rnctracedepth := OMTraceDepth(decVal_rnctracedepth)
				v.RncTraceDepth = &tmp_rnctracedepth
				if offset < 0 || offset >
					len(content) || n_rnctracedepth < 0 || n_rnctracedepth > len(content[offset:]) {
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
				ber.MarkPreflightTarget(opts, "rnc-InterfaceList", content[offset:])
				decodedTag_rncinterfacelist, n_rncinterfacelist, rawVal_rncinterfacelist, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "rnc-InterfaceList", "decoding", false)
				}
				if decodedTag_rncinterfacelist.Class != tag.ClassContextSpecific || decodedTag_rncinterfacelist.Number != 5 {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_rncinterfacelist), "rnc-InterfaceList", "decoding", false)
				}
				bsBytes_rncinterfacelist, bsUnused_rncinterfacelist, bsErr := ber.DecodeImplicitBitStringValue(decodedTag_rncinterfacelist.Constructed, rawVal_rncinterfacelist, opts...)
				if bsErr != nil {
					return qualifyBERError(bsErr, "rnc-InterfaceList", "decoding", false)
				}
				bsBitLength_rncinterfacelist, bsLenErr_rncinterfacelist := ber.BitStringBitLength(len(bsBytes_rncinterfacelist), bsUnused_rncinterfacelist)
				if bsLenErr_rncinterfacelist != nil {
					return qualifyBERError(bsLenErr_rncinterfacelist, "rnc-InterfaceList", "decoding", false)
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
				ber.MarkPreflightTarget(opts, "msc-s-TraceDepth", content[offset:])
				decodedTag_mscstracedepth, n_mscstracedepth, rawVal_mscstracedepth, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "msc-s-TraceDepth", "decoding", false)
				}
				if decodedTag_mscstracedepth.Class != tag.ClassContextSpecific || decodedTag_mscstracedepth.Number != 6 || decodedTag_mscstracedepth.Constructed != false {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_mscstracedepth), "msc-s-TraceDepth", "decoding", false)
				}
				decVal_mscstracedepth, intErr := ber.DecodeEnumeratedValue(rawVal_mscstracedepth)
				if intErr != nil {
					return qualifyBERError(intErr, "msc-s-TraceDepth", "decoding", false)
				}
				tmp_mscstracedepth := OMTraceDepth(decVal_mscstracedepth)
				v.MscSTraceDepth = &tmp_mscstracedepth
				if offset < 0 || offset >
					len(content) || n_mscstracedepth < 0 || n_mscstracedepth > len(
					content[offset:]) {
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
				ber.MarkPreflightTarget(opts, "msc-s-InterfaceList", content[offset:])
				decodedTag_mscsinterfacelist, n_mscsinterfacelist, rawVal_mscsinterfacelist, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "msc-s-InterfaceList", "decoding", false)
				}
				if decodedTag_mscsinterfacelist.Class != tag.ClassContextSpecific || decodedTag_mscsinterfacelist.Number != 7 {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_mscsinterfacelist), "msc-s-InterfaceList", "decoding", false)
				}
				bsBytes_mscsinterfacelist, bsUnused_mscsinterfacelist, bsErr := ber.DecodeImplicitBitStringValue(decodedTag_mscsinterfacelist.Constructed, rawVal_mscsinterfacelist, opts...)
				if bsErr != nil {
					return qualifyBERError(bsErr, "msc-s-InterfaceList", "decoding", false)
				}
				bsBitLength_mscsinterfacelist, bsLenErr_mscsinterfacelist := ber.BitStringBitLength(len(bsBytes_mscsinterfacelist), bsUnused_mscsinterfacelist)
				if bsLenErr_mscsinterfacelist != nil {
					return qualifyBERError(bsLenErr_mscsinterfacelist, "msc-s-InterfaceList", "decoding", false)
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
				ber.MarkPreflightTarget(opts, "msc-s-EventList", content[offset:])
				decodedTag_mscseventlist, n_mscseventlist, rawVal_mscseventlist, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "msc-s-EventList", "decoding", false)
				}
				if decodedTag_mscseventlist.Class != tag.ClassContextSpecific || decodedTag_mscseventlist.Number != 8 {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_mscseventlist), "msc-s-EventList", "decoding", false)
				}
				bsBytes_mscseventlist, bsUnused_mscseventlist, bsErr := ber.DecodeImplicitBitStringValue(decodedTag_mscseventlist.Constructed, rawVal_mscseventlist, opts...)
				if bsErr != nil {
					return qualifyBERError(bsErr, "msc-s-EventList", "decoding", false)
				}
				bsBitLength_mscseventlist, bsLenErr_mscseventlist := ber.BitStringBitLength(len(bsBytes_mscseventlist), bsUnused_mscseventlist)
				if bsLenErr_mscseventlist != nil {
					return qualifyBERError(bsLenErr_mscseventlist, "msc-s-EventList", "decoding", false)
				}
				tmp_mscseventlist := runtime.BitString{Bytes: bsBytes_mscseventlist, BitLength: bsBitLength_mscseventlist}
				v.MscSEventList = &tmp_mscseventlist
				if offset < 0 || offset >
					len(content) || n_mscseventlist < 0 || n_mscseventlist > len(content[offset:]) {
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
				ber.MarkPreflightTarget(opts, "mgw-TraceDepth", content[offset:])
				decodedTag_mgwtracedepth, n_mgwtracedepth, rawVal_mgwtracedepth, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "mgw-TraceDepth", "decoding", false)
				}
				if decodedTag_mgwtracedepth.Class != tag.ClassContextSpecific || decodedTag_mgwtracedepth.Number != 9 || decodedTag_mgwtracedepth.Constructed != false {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_mgwtracedepth), "mgw-TraceDepth", "decoding", false)
				}
				decVal_mgwtracedepth, intErr := ber.DecodeEnumeratedValue(rawVal_mgwtracedepth)
				if intErr != nil {
					return qualifyBERError(intErr, "mgw-TraceDepth", "decoding", false)
				}
				tmp_mgwtracedepth := OMTraceDepth(decVal_mgwtracedepth)
				v.MgwTraceDepth = &tmp_mgwtracedepth
				if offset < 0 || offset >
					len(content) || n_mgwtracedepth < 0 || n_mgwtracedepth > len(content[offset:]) {
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
				ber.MarkPreflightTarget(opts, "mgw-InterfaceList", content[offset:])
				decodedTag_mgwinterfacelist, n_mgwinterfacelist, rawVal_mgwinterfacelist, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "mgw-InterfaceList", "decoding", false)
				}
				if decodedTag_mgwinterfacelist.Class != tag.ClassContextSpecific || decodedTag_mgwinterfacelist.Number != 10 {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_mgwinterfacelist), "mgw-InterfaceList", "decoding", false)
				}
				bsBytes_mgwinterfacelist, bsUnused_mgwinterfacelist, bsErr := ber.DecodeImplicitBitStringValue(decodedTag_mgwinterfacelist.Constructed, rawVal_mgwinterfacelist, opts...)
				if bsErr != nil {
					return qualifyBERError(bsErr, "mgw-InterfaceList", "decoding", false)
				}
				bsBitLength_mgwinterfacelist, bsLenErr_mgwinterfacelist := ber.BitStringBitLength(len(bsBytes_mgwinterfacelist), bsUnused_mgwinterfacelist)
				if bsLenErr_mgwinterfacelist != nil {
					return qualifyBERError(bsLenErr_mgwinterfacelist, "mgw-InterfaceList", "decoding", false)
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
				ber.MarkPreflightTarget(opts, "mgw-EventList", content[offset:])
				decodedTag_mgweventlist, n_mgweventlist, rawVal_mgweventlist, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "mgw-EventList", "decoding", false)
				}
				if decodedTag_mgweventlist.Class != tag.ClassContextSpecific || decodedTag_mgweventlist.Number != 11 {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_mgweventlist), "mgw-EventList", "decoding", false)
				}
				bsBytes_mgweventlist, bsUnused_mgweventlist, bsErr := ber.DecodeImplicitBitStringValue(decodedTag_mgweventlist.Constructed, rawVal_mgweventlist, opts...)
				if bsErr != nil {
					return qualifyBERError(bsErr, "mgw-EventList", "decoding", false)
				}
				bsBitLength_mgweventlist, bsLenErr_mgweventlist := ber.BitStringBitLength(len(bsBytes_mgweventlist), bsUnused_mgweventlist)
				if bsLenErr_mgweventlist != nil {
					return qualifyBERError(bsLenErr_mgweventlist, "mgw-EventList", "decoding", false)
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
				ber.MarkPreflightTarget(opts, "rnc-TraceDepthExtension", content[offset:])
				decodedTag_rnctracedepthextension, n_rnctracedepthextension, rawVal_rnctracedepthextension, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "rnc-TraceDepthExtension", "decoding", false)
				}
				if decodedTag_rnctracedepthextension.Class != tag.ClassContextSpecific || decodedTag_rnctracedepthextension.Number != 12 || decodedTag_rnctracedepthextension.Constructed != false {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_rnctracedepthextension), "rnc-TraceDepthExtension", "decoding", false)
				}
				decVal_rnctracedepthextension, intErr := ber.DecodeEnumeratedValue(rawVal_rnctracedepthextension)
				if intErr != nil {
					return qualifyBERError(intErr, "rnc-TraceDepthExtension", "decoding", false)
				}
				tmp_rnctracedepthextension := OMTraceDepthExtension(decVal_rnctracedepthextension)
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
				ber.MarkPreflightTarget(opts, "msc-s-TraceDepthExtension", content[offset:])
				decodedTag_mscstracedepthextension, n_mscstracedepthextension, rawVal_mscstracedepthextension, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "msc-s-TraceDepthExtension", "decoding", false)
				}
				if decodedTag_mscstracedepthextension.Class != tag.ClassContextSpecific || decodedTag_mscstracedepthextension.Number != 13 || decodedTag_mscstracedepthextension.Constructed != false {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_mscstracedepthextension), "msc-s-TraceDepthExtension", "decoding", false)
				}
				decVal_mscstracedepthextension, intErr := ber.DecodeEnumeratedValue(rawVal_mscstracedepthextension)
				if intErr != nil {
					return qualifyBERError(intErr, "msc-s-TraceDepthExtension", "decoding", false)
				}
				tmp_mscstracedepthextension := OMTraceDepthExtension(decVal_mscstracedepthextension)
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
				ber.MarkPreflightTarget(opts, "mgw-TraceDepthExtension", content[offset:])
				decodedTag_mgwtracedepthextension, n_mgwtracedepthextension, rawVal_mgwtracedepthextension, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "mgw-TraceDepthExtension", "decoding", false)
				}
				if decodedTag_mgwtracedepthextension.Class != tag.ClassContextSpecific || decodedTag_mgwtracedepthextension.Number != 14 || decodedTag_mgwtracedepthextension.Constructed != false {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_mgwtracedepthextension), "mgw-TraceDepthExtension", "decoding", false)
				}
				decVal_mgwtracedepthextension, intErr := ber.DecodeEnumeratedValue(rawVal_mgwtracedepthextension)
				if intErr != nil {
					return qualifyBERError(intErr, "mgw-TraceDepthExtension", "decoding", false)
				}
				tmp_mgwtracedepthextension := OMTraceDepthExtension(decVal_mgwtracedepthextension)
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
		peekTag, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:], opts...)
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "OMTracePropagationList", Cause: extErr_}
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: the first unknown addition must differ from trailing OPTIONAL/DEFAULT tags.
		if len(v.ExtData_) == 0 && ((peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 14) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 13) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 12) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 11) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 10) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 9) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 8) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 7) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 6) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 5) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0)) {
			if !ber.ConstraintToleranceEnabled(opts) {
				return &ber.DecodeError{Offset: offset, TypeName: "OMTracePropagationList", Cause: fmt.Errorf("%w: repeated or out-of-order SEQUENCE component tag %s", ber.ErrInvalidTag, peekTag)}
			}
			if orderErr_ := ber.CheckDecodedValue(opts, fmt.Sprintf("ExtData_[%d]", len(v.ExtData_)), "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); orderErr_ != nil {
				return orderErr_
			}
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

// MarshalBER encodes OMActivateTraceModeRes to BER format.
func (v *OMActivateTraceModeRes) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: OMActivateTraceModeRes receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *OMActivateTraceModeRes) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalBER(ber.ChildEncodeOptions(opts, "extensionContainer")...)
		if err != nil {
			return nil, qualifyBERError(err, "extensionContainer", "encoding", false)
		}
		retagged_enc_extensioncontainer, tagErr_enc_extensioncontainer := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_extensioncontainer)
		if tagErr_enc_extensioncontainer != nil {
			return nil, qualifyBERError(tagErr_enc_extensioncontainer, "extensionContainer", "encoding", false)
		}
		enc_extensioncontainer = retagged_enc_extensioncontainer
		children = append(children, enc_extensioncontainer...)
	}
	if v.TraceSupportIndicator != nil {
		enc_tracesupportindicator := ber.EncodeNull()
		retagged_enc_tracesupportindicator, tagErr_enc_tracesupportindicator := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_tracesupportindicator)
		if tagErr_enc_tracesupportindicator != nil {
			return nil, qualifyBERError(tagErr_enc_tracesupportindicator, "traceSupportIndicator", "encoding", false)
		}
		enc_tracesupportindicator = retagged_enc_tracesupportindicator
		children = append(children, enc_tracesupportindicator...)
	}
	for i, ext := range v.ExtData_ {
		if err := ber.CheckBEROpaqueReplay(opts...); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
		peekTag, n, _, extErr := ber.DecodeEncodedTLV(ext)
		if extErr != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, extErr)
		}
		if n != len(ext) {
			return nil, fmt.Errorf("encoding extension %d: %w", i, ber.ErrExtraData)
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: only the first addition is restricted.
		if i == 0 && ((peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0)) {
			if constraintErr := ber.CheckEncodedValue(opts, "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
				return nil, constraintErr
			}
		}
		children = append(children, ext...)
	}
	return ber.EncodeSequence(children)
}

// MarshalDER encodes OMActivateTraceModeRes to DER format.
func (v *OMActivateTraceModeRes) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: OMActivateTraceModeRes receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalDER()
		if err != nil {
			return nil, qualifyBERError(err, "extensionContainer", "encoding", true)
		}
		retagged_enc_extensioncontainer, tagErr_enc_extensioncontainer := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_extensioncontainer)
		if tagErr_enc_extensioncontainer != nil {
			return nil, qualifyBERError(tagErr_enc_extensioncontainer, "extensionContainer", "encoding", true)
		}
		enc_extensioncontainer = retagged_enc_extensioncontainer
		children = append(children, enc_extensioncontainer...)
	}
	if v.TraceSupportIndicator != nil {
		enc_tracesupportindicator := ber.EncodeNull()
		retagged_enc_tracesupportindicator, tagErr_enc_tracesupportindicator := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_tracesupportindicator)
		if tagErr_enc_tracesupportindicator != nil {
			return nil, qualifyBERError(tagErr_enc_tracesupportindicator, "traceSupportIndicator", "encoding", true)
		}
		enc_tracesupportindicator = retagged_enc_tracesupportindicator
		children = append(children, enc_tracesupportindicator...)
	}
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDEREncodedElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
		peekTag, _, _, extErr := ber.DecodeEncodedTLV(ext)
		if extErr != nil {
			return nil, extErr
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: only the first addition is restricted.
		if i == 0 && ((peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0)) {
			if constraintErr := ber.CheckEncodedValue(nil, "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
				return nil, constraintErr
			}
		}
		children = append(children, ext...)
	}
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("%s: %w", "encoding OMActivateTraceModeRes as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}

// UnmarshalBER decodes OMActivateTraceModeRes from BER/DER format.
func (v *OMActivateTraceModeRes) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: OMActivateTraceModeRes destination is nil", ber.ErrInvalidValue)
	}
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return ber.DiagnosePreflight(err, data, opts, "child", func(probeOpts []ber.DecodeOption) error {
			var probe OMActivateTraceModeRes
			return probe.UnmarshalBER(data, probeOpts...)
		})
	}
	*v = OMActivateTraceModeRes{}
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
		return fmt.Errorf("%s: %w", "decoding OMActivateTraceModeRes SEQUENCE", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "OMActivateTraceModeRes", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode extensionContainer
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
				ber.MarkPreflightTarget(opts, "extensionContainer", content[offset:])
				decodedTag_extensioncontainer, n_extensioncontainer, rawVal_extensioncontainer, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "extensionContainer", "decoding", false)
				}
				if decodedTag_extensioncontainer.Class != tag.ClassContextSpecific || decodedTag_extensioncontainer.Number != 0 || decodedTag_extensioncontainer.Constructed != true {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_extensioncontainer), "extensionContainer", "decoding", false)
				}
				reconstructed_extensioncontainer, reconstructionErr_extensioncontainer := ber.EncodeSequence(rawVal_extensioncontainer)
				if reconstructionErr_extensioncontainer != nil {
					return qualifyBERError(reconstructionErr_extensioncontainer, "extensionContainer", "decoding", false)
				}
				var dec_extensioncontainer v21_map_extensiondatatypes.ExtensionDataTypesExtensionContainer
				if unmErr := dec_extensioncontainer.UnmarshalBER(reconstructed_extensioncontainer, ber.ChildDecodeOptions(opts, "extensionContainer")...); unmErr != nil {
					return qualifyBERError(unmErr, "extensionContainer", "decoding", false)
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
				ber.MarkPreflightTarget(opts, "traceSupportIndicator", content[offset:])
				decodedTag_tracesupportindicator, n_tracesupportindicator, rawVal_tracesupportindicator, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "traceSupportIndicator", "decoding", false)
				}
				if decodedTag_tracesupportindicator.Class != tag.ClassContextSpecific || decodedTag_tracesupportindicator.Number != 1 || decodedTag_tracesupportindicator.Constructed != false {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_tracesupportindicator), "traceSupportIndicator", "decoding", false)
				}
				if len(rawVal_tracesupportindicator) != 0 {
					return qualifyBERError(fmt.Errorf("%w: NULL content length %d", ber.ErrInvalidValue, len(rawVal_tracesupportindicator)), "traceSupportIndicator", "decoding", false)
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
		peekTag, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:], opts...)
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "OMActivateTraceModeRes", Cause: extErr_}
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: the first unknown addition must differ from trailing OPTIONAL/DEFAULT tags.
		if len(v.ExtData_) == 0 && ((peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0)) {
			if !ber.ConstraintToleranceEnabled(opts) {
				return &ber.DecodeError{Offset: offset, TypeName: "OMActivateTraceModeRes", Cause: fmt.Errorf("%w: repeated or out-of-order SEQUENCE component tag %s", ber.ErrInvalidTag, peekTag)}
			}
			if orderErr_ := ber.CheckDecodedValue(opts, fmt.Sprintf("ExtData_[%d]", len(v.ExtData_)), "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); orderErr_ != nil {
				return orderErr_
			}
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

// MarshalBER encodes OMDeactivateTraceModeArg to BER format.
func (v *OMDeactivateTraceModeArg) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: OMDeactivateTraceModeArg receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *OMDeactivateTraceModeArg) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
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
			return nil, qualifyBERError(encodeErr_enc_imsi, "imsi", "encoding", false)
		}
		retagged_enc_imsi, tagErr_enc_imsi := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_imsi)
		if tagErr_enc_imsi != nil {
			return nil, qualifyBERError(tagErr_enc_imsi, "imsi", "encoding", false)
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
		return nil, qualifyBERError(encodeErr_enc_tracereference, "traceReference", "encoding", false)
	}
	retagged_enc_tracereference, tagErr_enc_tracereference := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_tracereference)
	if tagErr_enc_tracereference != nil {
		return nil, qualifyBERError(tagErr_enc_tracereference, "traceReference", "encoding", false)
	}
	enc_tracereference = retagged_enc_tracereference
	children = append(children, enc_tracereference...)
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalBER(ber.ChildEncodeOptions(opts, "extensionContainer")...)
		if err != nil {
			return nil, qualifyBERError(err, "extensionContainer", "encoding", false)
		}
		retagged_enc_extensioncontainer, tagErr_enc_extensioncontainer := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_extensioncontainer)
		if tagErr_enc_extensioncontainer != nil {
			return nil, qualifyBERError(tagErr_enc_extensioncontainer, "extensionContainer", "encoding", false)
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
			return nil, qualifyBERError(encodeErr_enc_tracereference2, "traceReference2", "encoding", false)
		}
		retagged_enc_tracereference2, tagErr_enc_tracereference2 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, enc_tracereference2)
		if tagErr_enc_tracereference2 != nil {
			return nil, qualifyBERError(tagErr_enc_tracereference2, "traceReference2", "encoding", false)
		}
		enc_tracereference2 = retagged_enc_tracereference2
		children = append(children, enc_tracereference2...)
	}
	for i, ext := range v.ExtData_ {
		if err := ber.CheckBEROpaqueReplay(opts...); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
		peekTag, n, _, extErr := ber.DecodeEncodedTLV(ext)
		if extErr != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, extErr)
		}
		if n != len(ext) {
			return nil, fmt.Errorf("encoding extension %d: %w", i, ber.ErrExtraData)
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: only the first addition is restricted.
		if i == 0 && ((peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2)) {
			if constraintErr := ber.CheckEncodedValue(opts, "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
				return nil, constraintErr
			}
		}
		children = append(children, ext...)
	}
	return ber.EncodeSequence(children)
}

// MarshalDER encodes OMDeactivateTraceModeArg to DER format.
func (v *OMDeactivateTraceModeArg) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: OMDeactivateTraceModeArg receiver is nil", ber.ErrInvalidValue)
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
			return nil, qualifyBERError(encodeErr_enc_imsi, "imsi", "encoding", true)
		}
		retagged_enc_imsi, tagErr_enc_imsi := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_imsi)
		if tagErr_enc_imsi != nil {
			return nil, qualifyBERError(tagErr_enc_imsi, "imsi", "encoding", true)
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
		return nil, qualifyBERError(encodeErr_enc_tracereference, "traceReference", "encoding", true)
	}
	retagged_enc_tracereference, tagErr_enc_tracereference := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_tracereference)
	if tagErr_enc_tracereference != nil {
		return nil, qualifyBERError(tagErr_enc_tracereference, "traceReference", "encoding", true)
	}
	enc_tracereference = retagged_enc_tracereference
	children = append(children, enc_tracereference...)
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalDER()
		if err != nil {
			return nil, qualifyBERError(err, "extensionContainer", "encoding", true)
		}
		retagged_enc_extensioncontainer, tagErr_enc_extensioncontainer := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_extensioncontainer)
		if tagErr_enc_extensioncontainer != nil {
			return nil, qualifyBERError(tagErr_enc_extensioncontainer, "extensionContainer", "encoding", true)
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
			return nil, qualifyBERError(encodeErr_enc_tracereference2, "traceReference2", "encoding", true)
		}
		retagged_enc_tracereference2, tagErr_enc_tracereference2 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, enc_tracereference2)
		if tagErr_enc_tracereference2 != nil {
			return nil, qualifyBERError(tagErr_enc_tracereference2, "traceReference2", "encoding", true)
		}
		enc_tracereference2 = retagged_enc_tracereference2
		children = append(children, enc_tracereference2...)
	}
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDEREncodedElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
		peekTag, _, _, extErr := ber.DecodeEncodedTLV(ext)
		if extErr != nil {
			return nil, extErr
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: only the first addition is restricted.
		if i == 0 && ((peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2)) {
			if constraintErr := ber.CheckEncodedValue(nil, "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
				return nil, constraintErr
			}
		}
		children = append(children, ext...)
	}
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("%s: %w", "encoding OMDeactivateTraceModeArg as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}

// UnmarshalBER decodes OMDeactivateTraceModeArg from BER/DER format.
func (v *OMDeactivateTraceModeArg) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: OMDeactivateTraceModeArg destination is nil", ber.ErrInvalidValue)
	}
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return ber.DiagnosePreflight(err, data, opts, "child", func(probeOpts []ber.DecodeOption) error {
			var probe OMDeactivateTraceModeArg
			return probe.UnmarshalBER(data, probeOpts...)
		})
	}
	*v = OMDeactivateTraceModeArg{}
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
		return fmt.Errorf("%s: %w", "decoding OMDeactivateTraceModeArg SEQUENCE", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "OMDeactivateTraceModeArg", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode imsi
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
				ber.MarkPreflightTarget(opts, "imsi", content[offset:])
				decodedTag_imsi, n_imsi, rawVal_imsi, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "imsi", "decoding", false)
				}
				if decodedTag_imsi.Class != tag.ClassContextSpecific || decodedTag_imsi.Number != 0 {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_imsi), "imsi", "decoding", false)
				}
				decVal_imsi, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_imsi.Constructed, rawVal_imsi, opts...)
				if octetErr != nil {
					return qualifyBERError(octetErr, "imsi", "decoding", false)
				}
				tmp_imsi := v21_map_commondatatypes.CommonDataTypesIMSI(decVal_imsi)
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
	{
		ber.MarkPreflightTarget(opts, "traceReference", content[offset:])
		decodedTag_tracereference, n_tracereference, rawVal_tracereference, err := ber.DecodeTLV(content[offset:], opts...)
		if err != nil {
			return qualifyBERError(err, "traceReference", "decoding", false)
		}
		if decodedTag_tracereference.Class != tag.ClassContextSpecific || decodedTag_tracereference.Number != 1 {
			return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_tracereference), "traceReference", "decoding", false)
		}
		decVal_tracereference, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_tracereference.Constructed, rawVal_tracereference, opts...)
		if octetErr != nil {
			return qualifyBERError(octetErr, "traceReference", "decoding", false)
		}
		v.TraceReference = OMTraceReference(decVal_tracereference)
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
	}
	// Decode extensionContainer
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2 {
				ber.MarkPreflightTarget(opts, "extensionContainer", content[offset:])
				decodedTag_extensioncontainer, n_extensioncontainer, rawVal_extensioncontainer, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "extensionContainer", "decoding", false)
				}
				if decodedTag_extensioncontainer.Class != tag.ClassContextSpecific || decodedTag_extensioncontainer.Number != 2 || decodedTag_extensioncontainer.Constructed != true {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_extensioncontainer), "extensionContainer", "decoding", false)
				}
				reconstructed_extensioncontainer, reconstructionErr_extensioncontainer := ber.EncodeSequence(rawVal_extensioncontainer)
				if reconstructionErr_extensioncontainer != nil {
					return qualifyBERError(reconstructionErr_extensioncontainer, "extensionContainer", "decoding", false)
				}
				var dec_extensioncontainer v21_map_extensiondatatypes.ExtensionDataTypesExtensionContainer
				if unmErr := dec_extensioncontainer.UnmarshalBER(reconstructed_extensioncontainer, ber.ChildDecodeOptions(opts, "extensionContainer")...); unmErr != nil {
					return qualifyBERError(unmErr, "extensionContainer", "decoding", false)
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
				ber.MarkPreflightTarget(opts, "traceReference2", content[offset:])
				decodedTag_tracereference2, n_tracereference2, rawVal_tracereference2, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "traceReference2", "decoding", false)
				}
				if decodedTag_tracereference2.Class != tag.ClassContextSpecific || decodedTag_tracereference2.Number != 3 {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_tracereference2), "traceReference2", "decoding", false)
				}
				decVal_tracereference2, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_tracereference2.Constructed, rawVal_tracereference2, opts...)
				if octetErr != nil {
					return qualifyBERError(octetErr, "traceReference2", "decoding", false)
				}
				tmp_tracereference2 := OMTraceReference2(decVal_tracereference2)
				v.TraceReference2 = &tmp_tracereference2
				if offset < 0 || offset >
					len(content) || n_tracereference2 < 0 || n_tracereference2 > len(
					content[offset:]) {
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
		peekTag, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:], opts...)
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "OMDeactivateTraceModeArg", Cause: extErr_}
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: the first unknown addition must differ from trailing OPTIONAL/DEFAULT tags.
		if len(v.ExtData_) == 0 && ((peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2)) {
			if !ber.ConstraintToleranceEnabled(opts) {
				return &ber.DecodeError{Offset: offset, TypeName: "OMDeactivateTraceModeArg", Cause: fmt.Errorf("%w: repeated or out-of-order SEQUENCE component tag %s", ber.ErrInvalidTag, peekTag)}
			}
			if orderErr_ := ber.CheckDecodedValue(opts, fmt.Sprintf("ExtData_[%d]", len(v.ExtData_)), "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); orderErr_ != nil {
				return orderErr_
			}
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

// MarshalBER encodes OMDeactivateTraceModeRes to BER format.
func (v *OMDeactivateTraceModeRes) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: OMDeactivateTraceModeRes receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *OMDeactivateTraceModeRes) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalBER(ber.ChildEncodeOptions(opts, "extensionContainer")...)
		if err != nil {
			return nil, qualifyBERError(err, "extensionContainer", "encoding", false)
		}
		retagged_enc_extensioncontainer, tagErr_enc_extensioncontainer := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_extensioncontainer)
		if tagErr_enc_extensioncontainer != nil {
			return nil, qualifyBERError(tagErr_enc_extensioncontainer, "extensionContainer", "encoding", false)
		}
		enc_extensioncontainer = retagged_enc_extensioncontainer
		children = append(children, enc_extensioncontainer...)
	}
	for i, ext := range v.ExtData_ {
		if err := ber.CheckBEROpaqueReplay(opts...); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
		peekTag, n, _, extErr := ber.DecodeEncodedTLV(ext)
		if extErr != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, extErr)
		}
		if n != len(ext) {
			return nil, fmt.Errorf("encoding extension %d: %w", i, ber.ErrExtraData)
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: only the first addition is restricted.
		if i == 0 && (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0) {
			if constraintErr := ber.CheckEncodedValue(opts, "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
				return nil, constraintErr
			}
		}
		children = append(children, ext...)
	}
	return ber.EncodeSequence(children)
}

// MarshalDER encodes OMDeactivateTraceModeRes to DER format.
func (v *OMDeactivateTraceModeRes) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: OMDeactivateTraceModeRes receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalDER()
		if err != nil {
			return nil, qualifyBERError(err, "extensionContainer", "encoding", true)
		}
		retagged_enc_extensioncontainer, tagErr_enc_extensioncontainer := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_extensioncontainer)
		if tagErr_enc_extensioncontainer != nil {
			return nil, qualifyBERError(tagErr_enc_extensioncontainer, "extensionContainer", "encoding", true)
		}
		enc_extensioncontainer = retagged_enc_extensioncontainer
		children = append(children, enc_extensioncontainer...)
	}
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDEREncodedElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
		peekTag, _, _, extErr := ber.DecodeEncodedTLV(ext)
		if extErr != nil {
			return nil, extErr
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: only the first addition is restricted.
		if i == 0 && (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0) {
			if constraintErr := ber.CheckEncodedValue(nil, "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
				return nil, constraintErr
			}
		}
		children = append(children, ext...)
	}
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("%s: %w", "encoding OMDeactivateTraceModeRes as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}

// UnmarshalBER decodes OMDeactivateTraceModeRes from BER/DER format.
func (v *OMDeactivateTraceModeRes) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: OMDeactivateTraceModeRes destination is nil", ber.ErrInvalidValue)
	}
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return ber.DiagnosePreflight(err, data, opts, "child", func(probeOpts []ber.DecodeOption) error {
			var probe OMDeactivateTraceModeRes
			return probe.UnmarshalBER(data, probeOpts...)
		})
	}
	*v = OMDeactivateTraceModeRes{}
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
		return fmt.Errorf("%s: %w", "decoding OMDeactivateTraceModeRes SEQUENCE", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "OMDeactivateTraceModeRes", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode extensionContainer
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
				ber.MarkPreflightTarget(opts, "extensionContainer", content[offset:])
				decodedTag_extensioncontainer, n_extensioncontainer, rawVal_extensioncontainer, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "extensionContainer", "decoding", false)
				}
				if decodedTag_extensioncontainer.Class != tag.ClassContextSpecific || decodedTag_extensioncontainer.Number != 0 || decodedTag_extensioncontainer.Constructed != true {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_extensioncontainer), "extensionContainer", "decoding", false)
				}
				reconstructed_extensioncontainer, reconstructionErr_extensioncontainer := ber.EncodeSequence(rawVal_extensioncontainer)
				if reconstructionErr_extensioncontainer != nil {
					return qualifyBERError(reconstructionErr_extensioncontainer, "extensionContainer", "decoding", false)
				}
				var dec_extensioncontainer v21_map_extensiondatatypes.ExtensionDataTypesExtensionContainer
				if unmErr := dec_extensioncontainer.UnmarshalBER(reconstructed_extensioncontainer, ber.ChildDecodeOptions(opts, "extensionContainer")...); unmErr != nil {
					return qualifyBERError(unmErr, "extensionContainer", "decoding", false)
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
		peekTag, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:], opts...)
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "OMDeactivateTraceModeRes", Cause: extErr_}
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: the first unknown addition must differ from trailing OPTIONAL/DEFAULT tags.
		if len(v.ExtData_) == 0 && (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0) {
			if !ber.ConstraintToleranceEnabled(opts) {
				return &ber.DecodeError{Offset: offset, TypeName: "OMDeactivateTraceModeRes", Cause: fmt.Errorf("%w: repeated or out-of-order SEQUENCE component tag %s", ber.ErrInvalidTag, peekTag)}
			}
			if orderErr_ := ber.CheckDecodedValue(opts, fmt.Sprintf("ExtData_[%d]", len(v.ExtData_)), "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); orderErr_ != nil {
				return orderErr_
			}
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
