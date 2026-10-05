// Code generated from ASN.1 module "NokiaMAP-Extensions". DO NOT EDIT.

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

const (

	// MaxNumOfActiveSS is the integer constant for maxNumOfActiveSS.
	MaxNumOfActiveSS int64 = 30

	// MaxNumOfCA is the integer constant for maxNumOfCA.
	MaxNumOfCA int64 = 3

	// PicLock is the octet string constant for picLock.
	PicLock = "\x01"

	// PrefCarrierId is the octet string constant for prefCarrierId.
	PrefCarrierId = "\x02"

	// MKeyValue is the octet string constant for mKey.
	MKeyValue = "\x03"

	// SmsKey is the octet string constant for smsKey.
	SmsKey = "\x04"

	// FraudDataValue is the octet string constant for fraud-Data.
	FraudDataValue = "\x05"

	// CellUpdate is the octet string constant for cell-update.
	CellUpdate = "\x06"

	// MaxnumOfMAPservices is the integer constant for maxnumOfMAPservices.
	MaxnumOfMAPservices int64 = 256

	// MaxNumOfLEAs is the integer constant for maxNumOfLEAs.
	MaxNumOfLEAs int64 = 7

	// MaxNumOfServicesWithInfo is the integer constant for maxNumOfServicesWithInfo.
	MaxNumOfServicesWithInfo int64 = 20

	// MaxNumOfCodec is the integer constant for maxNumOfCodec.
	MaxNumOfCodec int64 = 8

	// MaxNumberOfCOSFeatures is the integer constant for maxNumberOfCOSFeatures.
	MaxNumberOfCOSFeatures int64 = 13
)

// RoutingCategory represents the ASN.1 type RoutingCategory (OCTET_STRING).
type RoutingCategory = []byte

// ActiveSSList represents the ASN.1 type ActiveSS-List (OCTET_STRING).
type ActiveSSList = []byte

// ExtRoutingCategory represents the ASN.1 type ExtRoutingCategory (INTEGER).
type ExtRoutingCategory = int64

// IsdArgExt represents the ASN.1 type IsdArgExt (SEQUENCE).
type IsdArgExt struct {
	AlsLineIndicator   *struct{}            `asn1:"tag:0,context,implicit,optional" json:"AlsLineIndicator,omitempty"`
	RoutingCategory    *RoutingCategory     `asn1:"tag:1,context,implicit,optional" json:"RoutingCategory,omitempty"`
	ServiceList        *MAPserviceList      `asn1:"tag:2,context,implicit,optional" json:"ServiceList,omitempty"`
	ServInfoList       *ServiceListWithInfo `asn1:"tag:3,context,implicit,optional" json:"ServInfoList,omitempty"`
	ServInfoListIndef_ bool                 `asn1:"-" json:"-"`
	ExtRoutingCategory *ExtRoutingCategory  `asn1:"tag:5,context,implicit,optional" json:"ExtRoutingCategory,omitempty"`
	OwnMSISDN          *ISDNAddressString5  `asn1:"tag:6,context,implicit,optional" json:"OwnMSISDN,omitempty"`
	ExtCount_          int64                `asn1:"-" json:"-"`
	ExtPresent_        []bool               `asn1:"-" json:"-"`
	ExtData_           [][]byte             `asn1:"-" json:"-"`
	berOriginal_       []byte               `asn1:"-" json:"-"`
	berSnapshot_       []byte               `asn1:"-" json:"-"`
}

// DsdArgExt represents the ASN.1 type DsdArgExt (SEQUENCE).
type DsdArgExt struct {
	AlsLineIndicator *struct{}       `asn1:"tag:0,context,implicit,optional" json:"AlsLineIndicator,omitempty"`
	ServiceList      *MAPserviceList `asn1:"tag:1,context,implicit,optional" json:"ServiceList,omitempty"`
	ExtCount_        int64           `asn1:"-" json:"-"`
	ExtPresent_      []bool          `asn1:"-" json:"-"`
	ExtData_         [][]byte        `asn1:"-" json:"-"`
	berOriginal_     []byte          `asn1:"-" json:"-"`
	berSnapshot_     []byte          `asn1:"-" json:"-"`
}

// UlResExt represents the ASN.1 type UlResExt (SEQUENCE).
type UlResExt struct {
	MwdSet       *struct{} `asn1:"tag:0,context,implicit,optional" json:"MwdSet,omitempty"`
	ExtCount_    int64     `asn1:"-" json:"-"`
	ExtPresent_  []bool    `asn1:"-" json:"-"`
	ExtData_     [][]byte  `asn1:"-" json:"-"`
	berOriginal_ []byte    `asn1:"-" json:"-"`
	berSnapshot_ []byte    `asn1:"-" json:"-"`
}

// EmoInCategoryKey represents the ASN.1 type EmoInCategoryKey (OCTET_STRING).
type EmoInCategoryKey = TBCDSTRING5

// SSDataEmoInExt represents the ASN.1 type SS-DataEmoInExt (SEQUENCE).
type SSDataEmoInExt struct {
	EmoInCategoryKey *EmoInCategoryKey `asn1:"tag:2,private,implicit,optional" json:"EmoInCategoryKey,omitempty"`
	ExtCount_        int64             `asn1:"-" json:"-"`
	ExtPresent_      []bool            `asn1:"-" json:"-"`
	ExtData_         [][]byte          `asn1:"-" json:"-"`
	berOriginal_     []byte            `asn1:"-" json:"-"`
	berSnapshot_     []byte            `asn1:"-" json:"-"`
}

// InTriggerKey represents the ASN.1 type InTriggerKey (INTEGER).
type InTriggerKey = int64

// PnpIndex represents the ASN.1 type PnpIndex (OCTET_STRING).
type PnpIndex = []byte

// CallRedirectionIndex represents the ASN.1 type CallRedirectionIndex (INTEGER).
type CallRedirectionIndex = int64

// ChargingArea represents the ASN.1 type ChargingArea (INTEGER).
type ChargingArea = int64

// ChargingAreaList represents the ASN.1 type ChargingAreaList (SEQUENCE_OF).
type ChargingAreaList struct {
	Values       []ChargingArea `json:"Values"`
	berOriginal_ []byte         `json:"-"`
	berSnapshot_ []byte         `json:"-"`
}

// RegionalChargingData represents the ASN.1 type RegionalChargingData (SEQUENCE).
type RegionalChargingData struct {
	ChargingAreaList       *ChargingAreaList `asn1:"tag:0,context,implicit,optional" json:"ChargingAreaList,omitempty"`
	ChargingAreaListIndef_ bool              `asn1:"-" json:"-"`
	ExtCount_              int64             `asn1:"-" json:"-"`
	ExtPresent_            []bool            `asn1:"-" json:"-"`
	ExtData_               [][]byte          `asn1:"-" json:"-"`
	berOriginal_           []byte            `asn1:"-" json:"-"`
	berSnapshot_           []byte            `asn1:"-" json:"-"`
}

// SSDataExtension represents the ASN.1 type SS-DataExtension (SEQUENCE).
type SSDataExtension struct {
	InTriggerKey         *InTriggerKey         `asn1:"tag:0,context,implicit,optional" json:"InTriggerKey,omitempty"`
	PnpIndex             *PnpIndex             `asn1:"tag:1,context,implicit,optional" json:"PnpIndex,omitempty"`
	CallRedirectionIndex *CallRedirectionIndex `asn1:"tag:2,context,implicit,optional" json:"CallRedirectionIndex,omitempty"`
	RegionalChargingData *RegionalChargingData `asn1:"tag:3,context,implicit,optional" json:"RegionalChargingData,omitempty"`
	ExtCount_            int64                 `asn1:"-" json:"-"`
	ExtPresent_          []bool                `asn1:"-" json:"-"`
	ExtData_             [][]byte              `asn1:"-" json:"-"`
	berOriginal_         []byte                `asn1:"-" json:"-"`
	berSnapshot_         []byte                `asn1:"-" json:"-"`
}

// SriExtension represents the ASN.1 type SriExtension (SEQUENCE).
type SriExtension struct {
	CallForwardingOverride   *struct{}                 `asn1:"tag:0,context,implicit,optional" json:"CallForwardingOverride,omitempty"`
	InCapability             *struct{}                 `asn1:"tag:1,context,implicit,optional" json:"InCapability,omitempty"`
	CallingCategory          *CallingCategory          `asn1:"tag:2,context,implicit,optional" json:"CallingCategory,omitempty"`
	InternalServiceIndicator *InternalServiceIndicator `asn1:"tag:3,context,implicit,optional" json:"InternalServiceIndicator,omitempty"`
	SrbtSupportIndicator     *struct{}                 `asn1:"tag:4,context,implicit,optional" json:"SrbtSupportIndicator,omitempty"`
	GmscSupportIndicator     *struct{}                 `asn1:"tag:5,context,implicit,optional" json:"GmscSupportIndicator,omitempty"`
	ExtCount_                int64                     `asn1:"-" json:"-"`
	ExtPresent_              []bool                    `asn1:"-" json:"-"`
	ExtData_                 [][]byte                  `asn1:"-" json:"-"`
	berOriginal_             []byte                    `asn1:"-" json:"-"`
	berSnapshot_             []byte                    `asn1:"-" json:"-"`
}

// CallingCategory represents the ASN.1 type CallingCategory (OCTET_STRING).
type CallingCategory = []byte

// InternalServiceIndicator represents the ASN.1 type InternalServiceIndicator (OCTET_STRING).
type InternalServiceIndicator = []byte

// ExtensionsExtraProtocolId represents the ASN.1 INTEGER type ExtraProtocolId with named numbers.
type ExtensionsExtraProtocolId int64

const (
	ExtensionsExtraProtocolIdQ763 ExtensionsExtraProtocolId = 1
)

func (v ExtensionsExtraProtocolId) String() string {
	switch v {
	case ExtensionsExtraProtocolIdQ763:
		return "q763"
	default:
		return "unknown"
	}
}

// ExtensionsExtraSignalInfo represents the ASN.1 type ExtraSignalInfo (SEQUENCE).
type ExtensionsExtraSignalInfo struct {
	ProtocolId   ExtensionsExtraProtocolId `asn1:""`
	SignalInfo   SignalInfo5               `asn1:""`
	berOriginal_ []byte                    `asn1:"-" json:"-"`
	berSnapshot_ []byte                    `asn1:"-" json:"-"`
}

// CUGCallInfo represents the ASN.1 type CUG-CallInfo (OCTET_STRING).
type CUGCallInfo = []byte

// NokiaCUGData represents the ASN.1 type Nokia-CUG-Data (SEQUENCE).
type NokiaCUGData struct {
	CugInterlock          *CUGInterlock5 `asn1:"tag:0,context,implicit,optional" json:"CugInterlock,omitempty"`
	CugOutgoingAccess     *bool          `asn1:"tag:1,context,implicit,optional" json:"CugOutgoingAccess,omitempty"`
	CugOutgoingAccessRaw_ byte           `asn1:"-" json:"-"`
	CugCallInfo           *CUGCallInfo   `asn1:"tag:2,context,implicit,optional" json:"CugCallInfo,omitempty"`
	ExtCount_             int64          `asn1:"-" json:"-"`
	ExtPresent_           []bool         `asn1:"-" json:"-"`
	ExtData_              [][]byte       `asn1:"-" json:"-"`
	berOriginal_          []byte         `asn1:"-" json:"-"`
	berSnapshot_          []byte         `asn1:"-" json:"-"`
}

// SriResExtension represents the ASN.1 type SriResExtension (SEQUENCE).
type SriResExtension struct {
	InTriggerKey        *InTriggerKey       `asn1:"tag:0,context,implicit,optional" json:"InTriggerKey,omitempty"`
	VlrNumber           *ISDNAddressString5 `asn1:"tag:1,context,implicit,optional" json:"VlrNumber,omitempty"`
	ActiveSs            *ActiveSSList       `asn1:"tag:2,context,implicit,optional" json:"ActiveSs,omitempty"`
	TraceReference      *TraceReference5    `asn1:"tag:3,context,implicit,optional" json:"TraceReference,omitempty"`
	TraceType           *TraceType5         `asn1:"tag:4,context,implicit,optional" json:"TraceType,omitempty"`
	OmcId               *AddressString5     `asn1:"tag:5,context,implicit,optional" json:"OmcId,omitempty"`
	HotBilling          *bool               `asn1:"tag:6,context,implicit,optional" json:"HotBilling,omitempty"`
	HotBillingRaw_      byte                `asn1:"-" json:"-"`
	CfoIsDone           *bool               `asn1:"tag:7,context,implicit,optional" json:"CfoIsDone,omitempty"`
	CfoIsDoneRaw_       byte                `asn1:"-" json:"-"`
	CfInCug             *bool               `asn1:"tag:8,context,implicit,optional" json:"CfInCug,omitempty"`
	CfInCugRaw_         byte                `asn1:"-" json:"-"`
	BasicService        *BasicServiceCode5  `asn1:"tag:9,context,explicit,optional" json:"BasicService,omitempty"`
	Category            *Category6          `asn1:"tag:10,context,implicit,optional" json:"Category,omitempty"`
	RoutingCategory     *RoutingCategory    `asn1:"tag:11,context,implicit,optional" json:"RoutingCategory,omitempty"`
	PnpIndex            *PnpIndex           `asn1:"tag:12,context,implicit,optional" json:"PnpIndex,omitempty"`
	NokiaCUG            *NokiaCUGData       `asn1:"tag:13,context,implicit,optional" json:"NokiaCUG,omitempty"`
	NoBarrings          *struct{}           `asn1:"tag:14,context,implicit,optional" json:"NoBarrings,omitempty"`
	OdbData             *ODBData5           `asn1:"tag:15,context,implicit,optional" json:"OdbData,omitempty"`
	FraudData           *FraudData          `asn1:"tag:16,context,implicit,optional" json:"FraudData,omitempty"`
	ExtRoutingCategory  *ExtRoutingCategory `asn1:"tag:17,context,implicit,optional" json:"ExtRoutingCategory,omitempty"`
	LeaId               *LeaId              `asn1:"tag:18,context,implicit,optional" json:"LeaId,omitempty"`
	OlcmInfoTable       *OlcmInfoTable      `asn1:"tag:19,context,implicit,optional" json:"OlcmInfoTable,omitempty"`
	OlcmInfoTableIndef_ bool                `asn1:"-" json:"-"`
	CallingCategory     *CallingCategory    `asn1:"tag:20,context,implicit,optional" json:"CallingCategory,omitempty"`
	CommonMSISDN        *ISDNAddressString5 `asn1:"tag:21,context,implicit,optional" json:"CommonMSISDN,omitempty"`
	RgData              *RgData             `asn1:"tag:22,context,implicit,optional" json:"RgData,omitempty"`
	OlcmTraceReference  *OlcmTraceReference `asn1:"tag:23,context,implicit,optional" json:"OlcmTraceReference,omitempty"`
	ExtCount_           int64               `asn1:"-" json:"-"`
	ExtPresent_         []bool              `asn1:"-" json:"-"`
	ExtData_            [][]byte            `asn1:"-" json:"-"`
	berOriginal_        []byte              `asn1:"-" json:"-"`
	berSnapshot_        []byte              `asn1:"-" json:"-"`
}

// RgData represents the ASN.1 type RgData (SEQUENCE).
type RgData struct {
	NoAnswerTimer       *NoAnswerTimer      `asn1:"tag:0,context,implicit,optional" json:"NoAnswerTimer,omitempty"`
	MemberList          *MemberList         `asn1:"tag:1,context,implicit,optional" json:"MemberList,omitempty"`
	MemberListIndef_    bool                `asn1:"-" json:"-"`
	AlertingMethod      *AlertingMethod     `asn1:"tag:2,context,implicit,optional" json:"AlertingMethod,omitempty"`
	UserType            *UserType           `asn1:"tag:3,context,implicit,optional" json:"UserType,omitempty"`
	DivertedToNbr       *ISDNAddressString5 `asn1:"tag:4,context,implicit,optional" json:"DivertedToNbr,omitempty"`
	MemberOfSuppression *struct{}           `asn1:"tag:5,context,implicit,optional" json:"MemberOfSuppression,omitempty"`
	Ringbacktone        *struct{}           `asn1:"tag:6,context,implicit,optional" json:"Ringbacktone,omitempty"`
	ExtCount_           int64               `asn1:"-" json:"-"`
	ExtPresent_         []bool              `asn1:"-" json:"-"`
	ExtData_            [][]byte            `asn1:"-" json:"-"`
	berOriginal_        []byte              `asn1:"-" json:"-"`
	berSnapshot_        []byte              `asn1:"-" json:"-"`
}

// NoAnswerTimer represents the ASN.1 type NoAnswerTimer (OCTET_STRING).
type NoAnswerTimer = []byte

// MemberList represents the ASN.1 type MemberList (SEQUENCE_OF).
type MemberList struct {
	Values       []ISDNAddressString5 `json:"Values"`
	berOriginal_ []byte               `json:"-"`
	berSnapshot_ []byte               `json:"-"`
}

// AlertingMethod represents the ASN.1 type AlertingMethod (OCTET_STRING).
type AlertingMethod = []byte

// UserType represents the ASN.1 type UserType (OCTET_STRING).
type UserType = []byte

// MAPserviceCode represents the ASN.1 type MAPserviceCode (OCTET_STRING).
type MAPserviceCode = []byte

// MAPserviceList represents the ASN.1 type MAPserviceList (OCTET_STRING).
type MAPserviceList = []byte

// CarrierIdCode represents the ASN.1 type CarrierIdCode (OCTET_STRING).
type CarrierIdCode = []byte

// PrefCarrierIdList represents the ASN.1 type PrefCarrierIdList (SEQUENCE).
type PrefCarrierIdList struct {
	PrefCarrierIdCode1 CarrierIdCode `asn1:"tag:0,context,implicit"`
	ExtCount_          int64         `asn1:"-" json:"-"`
	ExtPresent_        []bool        `asn1:"-" json:"-"`
	ExtData_           [][]byte      `asn1:"-" json:"-"`
	berOriginal_       []byte        `asn1:"-" json:"-"`
	berSnapshot_       []byte        `asn1:"-" json:"-"`
}

// ANSIIsdArgExt represents the ASN.1 type ANSIIsdArgExt (SEQUENCE).
type ANSIIsdArgExt struct {
	PrefCarrierIdList *PrefCarrierIdList `asn1:"tag:0,context,implicit,optional" json:"PrefCarrierIdList,omitempty"`
	ExtCount_         int64              `asn1:"-" json:"-"`
	ExtPresent_       []bool             `asn1:"-" json:"-"`
	ExtData_          [][]byte           `asn1:"-" json:"-"`
	berOriginal_      []byte             `asn1:"-" json:"-"`
	berSnapshot_      []byte             `asn1:"-" json:"-"`
}

// ANSISriResExt represents the ASN.1 type ANSISriResExt (SEQUENCE).
type ANSISriResExt struct {
	PrefCarrierIdList *PrefCarrierIdList `asn1:"tag:0,context,implicit,optional" json:"PrefCarrierIdList,omitempty"`
	ExtCount_         int64              `asn1:"-" json:"-"`
	ExtPresent_       []bool             `asn1:"-" json:"-"`
	ExtData_          [][]byte           `asn1:"-" json:"-"`
	berOriginal_      []byte             `asn1:"-" json:"-"`
	berSnapshot_      []byte             `asn1:"-" json:"-"`
}

// CanLocArgExt represents the ASN.1 type CanLocArgExt (SEQUENCE).
type CanLocArgExt struct {
	Termination  []byte   `asn1:"tag:0,context,implicit,optional" json:"Termination,omitzero"`
	ExtCount_    int64    `asn1:"-" json:"-"`
	ExtPresent_  []bool   `asn1:"-" json:"-"`
	ExtData_     [][]byte `asn1:"-" json:"-"`
	berOriginal_ []byte   `asn1:"-" json:"-"`
	berSnapshot_ []byte   `asn1:"-" json:"-"`
}

// ATMargExt represents the ASN.1 type ATMargExt (SEQUENCE).
type ATMargExt struct {
	TraceReference      *TraceReference5    `asn1:"tag:0,context,implicit,optional" json:"TraceReference,omitempty"`
	TraceType           *TraceType5         `asn1:"tag:1,context,implicit,optional" json:"TraceType,omitempty"`
	LeaId               *LeaId              `asn1:"tag:2,context,implicit,optional" json:"LeaId,omitempty"`
	OlcmInfoTable       *OlcmInfoTable      `asn1:"tag:3,context,implicit,optional" json:"OlcmInfoTable,omitempty"`
	OlcmInfoTableIndef_ bool                `asn1:"-" json:"-"`
	OlcmTraceReference  *OlcmTraceReference `asn1:"tag:4,context,implicit,optional" json:"OlcmTraceReference,omitempty"`
	ExtCount_           int64               `asn1:"-" json:"-"`
	ExtPresent_         []bool              `asn1:"-" json:"-"`
	ExtData_            [][]byte            `asn1:"-" json:"-"`
	berOriginal_        []byte              `asn1:"-" json:"-"`
	berSnapshot_        []byte              `asn1:"-" json:"-"`
}

// LeaId represents the ASN.1 type LeaId (INTEGER).
type LeaId = int64

// OlcmInfoTable represents the ASN.1 type OlcmInfoTable (SEQUENCE_OF).
type OlcmInfoTable struct {
	Values       []OlcmInfo `json:"Values"`
	berOriginal_ []byte     `json:"-"`
	berSnapshot_ []byte     `json:"-"`
}

// OlcmInfo represents the ASN.1 type OlcmInfo (SEQUENCE).
type OlcmInfo struct {
	TraceReference     TraceReference5     `asn1:"tag:0,context,implicit"`
	TraceType          TraceType5          `asn1:"tag:1,context,implicit"`
	LeaId              *LeaId              `asn1:"tag:2,context,implicit,optional" json:"LeaId,omitempty"`
	OlcmTraceReference *OlcmTraceReference `asn1:"tag:3,context,implicit,optional" json:"OlcmTraceReference,omitempty"`
	ExtCount_          int64               `asn1:"-" json:"-"`
	ExtPresent_        []bool              `asn1:"-" json:"-"`
	ExtData_           [][]byte            `asn1:"-" json:"-"`
	berOriginal_       []byte              `asn1:"-" json:"-"`
	berSnapshot_       []byte              `asn1:"-" json:"-"`
}

// OlcmTraceReference represents the ASN.1 type OlcmTraceReference (OCTET_STRING).
type OlcmTraceReference = []byte

// ATMresExt represents the ASN.1 type ATMresExt (SEQUENCE).
type ATMresExt struct {
	OlcmActive   *struct{} `asn1:"tag:0,context,implicit,optional" json:"OlcmActive,omitempty"`
	ExtCount_    int64     `asn1:"-" json:"-"`
	ExtPresent_  []bool    `asn1:"-" json:"-"`
	ExtData_     [][]byte  `asn1:"-" json:"-"`
	berOriginal_ []byte    `asn1:"-" json:"-"`
	berSnapshot_ []byte    `asn1:"-" json:"-"`
}

// DTMargExt represents the ASN.1 type DTMargExt (SEQUENCE).
type DTMargExt struct {
	TraceType          *TraceType5         `asn1:"tag:0,context,implicit,optional" json:"TraceType,omitempty"`
	LeaId              *LeaId              `asn1:"tag:1,context,implicit,optional" json:"LeaId,omitempty"`
	OlcmTraceReference *OlcmTraceReference `asn1:"tag:2,context,implicit,optional" json:"OlcmTraceReference,omitempty"`
	ExtCount_          int64               `asn1:"-" json:"-"`
	ExtPresent_        []bool              `asn1:"-" json:"-"`
	ExtData_           [][]byte            `asn1:"-" json:"-"`
	berOriginal_       []byte              `asn1:"-" json:"-"`
	berSnapshot_       []byte              `asn1:"-" json:"-"`
}

// VersionInfo represents the ASN.1 type VersionInfo (OCTET_STRING).
type VersionInfo = []byte

// FraudInfo represents the ASN.1 type FraudInfo (SEQUENCE).
type FraudInfo struct {
	Moc          *FraudData `asn1:"tag:0,context,implicit,optional" json:"Moc,omitempty"`
	Cf           *FraudData `asn1:"tag:1,context,implicit,optional" json:"Cf,omitempty"`
	Ct           *FraudData `asn1:"tag:2,context,implicit,optional" json:"Ct,omitempty"`
	ExtCount_    int64      `asn1:"-" json:"-"`
	ExtPresent_  []bool     `asn1:"-" json:"-"`
	ExtData_     [][]byte   `asn1:"-" json:"-"`
	berOriginal_ []byte     `asn1:"-" json:"-"`
	berSnapshot_ []byte     `asn1:"-" json:"-"`
}

// FraudData represents the ASN.1 type FraudData (SEQUENCE).
type FraudData struct {
	Time           *TimeLimit     `asn1:"tag:0,context,implicit,optional" json:"Time,omitempty"`
	TimeAction     *ActionType    `asn1:"tag:1,context,implicit,optional" json:"TimeAction,omitempty"`
	MaxCount       *FraudMaxCount `asn1:"tag:2,context,implicit,optional" json:"MaxCount,omitempty"`
	MaxCountAction *ActionType    `asn1:"tag:3,context,implicit,optional" json:"MaxCountAction,omitempty"`
	ExtCount_      int64          `asn1:"-" json:"-"`
	ExtPresent_    []bool         `asn1:"-" json:"-"`
	ExtData_       [][]byte       `asn1:"-" json:"-"`
	berOriginal_   []byte         `asn1:"-" json:"-"`
	berSnapshot_   []byte         `asn1:"-" json:"-"`
}

// TimeLimit represents the ASN.1 type TimeLimit (INTEGER).
type TimeLimit = int64

// ActionType represents the ASN.1 type ActionType (OCTET_STRING).
type ActionType = []byte

// FraudMaxCount represents the ASN.1 type FraudMaxCount (INTEGER).
type FraudMaxCount = int64

// ServiceWithInfo represents the ASN.1 type ServiceWithInfo (SEQUENCE).
type ServiceWithInfo struct {
	ServiceCode  *MAPserviceCode `asn1:"tag:0,context,implicit,optional" json:"ServiceCode,omitempty"`
	VersionInfo  *VersionInfo    `asn1:"tag:1,context,implicit,optional" json:"VersionInfo,omitempty"`
	InKey        *INKey          `asn1:",optional" json:"InKey,omitempty"`
	FraudInfo    *FraudInfo      `asn1:",optional" json:"FraudInfo,omitempty"`
	ExtCount_    int64           `asn1:"-" json:"-"`
	ExtPresent_  []bool          `asn1:"-" json:"-"`
	ExtData_     [][]byte        `asn1:"-" json:"-"`
	berOriginal_ []byte          `asn1:"-" json:"-"`
	berSnapshot_ []byte          `asn1:"-" json:"-"`
}

// ServiceListWithInfo represents the ASN.1 type ServiceListWithInfo (SEQUENCE_OF).
type ServiceListWithInfo struct {
	Values       []ServiceWithInfo `json:"Values"`
	berOriginal_ []byte            `json:"-"`
	berSnapshot_ []byte            `json:"-"`
}

// INKey choice constants.
const (
	INKeyChoiceMobileINKey = 1
	INKeyChoiceSmsINKey    = 2
)

// INKey represents the ASN.1 CHOICE type INKey.
type INKey struct {
	Choice       int
	berOriginal_ []byte  `json:"-"`
	berSnapshot_ []byte  `json:"-"`
	MobileINKey  *MKey   `json:"MobileINKey,omitempty"`
	SmsINKey     *SMSKey `json:"SmsINKey,omitempty"`
}

// NewINKeyMobileINKey creates a INKey with the mobile-IN-key alternative.
func NewINKeyMobileINKey(v MKey) INKey {
	return INKey{
		Choice:      INKeyChoiceMobileINKey,
		MobileINKey: &v,
	}
}

// NewINKeySmsINKey creates a INKey with the sms-IN-key alternative.
func NewINKeySmsINKey(v SMSKey) INKey {
	return INKey{
		Choice:   INKeyChoiceSmsINKey,
		SmsINKey: &v,
	}
}

// MmTdpName represents the ASN.1 type MmTdpName (OCTET_STRING).
type MmTdpName = []byte

// ExtensionsServiceKey represents the ASN.1 type ServiceKey (INTEGER).
type ExtensionsServiceKey = int64

// MKeyVer represents the ASN.1 type MKeyVer (OCTET_STRING).
type MKeyVer = []byte

// LocupType represents the ASN.1 type LocupType (OCTET_STRING).
type LocupType = []byte

// MKey represents the ASN.1 type MKey (SEQUENCE).
type MKey struct {
	MKeyVer      *MKeyVer              `asn1:"tag:0,context,implicit,optional" json:"MKeyVer,omitempty"`
	MmScfAddress *ISDNAddressString5   `asn1:"tag:1,context,implicit,optional" json:"MmScfAddress,omitempty"`
	MmTdpName    *MmTdpName            `asn1:"tag:2,context,implicit,optional" json:"MmTdpName,omitempty"`
	ServiceKey   *ExtensionsServiceKey `asn1:"tag:3,context,implicit,optional" json:"ServiceKey,omitempty"`
	LocupType    *LocupType            `asn1:"tag:4,context,implicit,optional" json:"LocupType,omitempty"`
	ExtCount_    int64                 `asn1:"-" json:"-"`
	ExtPresent_  []bool                `asn1:"-" json:"-"`
	ExtData_     [][]byte              `asn1:"-" json:"-"`
	berOriginal_ []byte                `asn1:"-" json:"-"`
	berSnapshot_ []byte                `asn1:"-" json:"-"`
}

// SmsTdpName represents the ASN.1 type SmsTdpName (OCTET_STRING).
type SmsTdpName = []byte

// SMSKey represents the ASN.1 type SMSKey (SEQUENCE).
type SMSKey struct {
	MmSCPAddress *ISDNAddressString5   `asn1:"tag:0,context,implicit,optional" json:"MmSCPAddress,omitempty"`
	SmsTdpName   *SmsTdpName           `asn1:"tag:1,context,implicit,optional" json:"SmsTdpName,omitempty"`
	ServiceKey   *ExtensionsServiceKey `asn1:"tag:2,context,implicit,optional" json:"ServiceKey,omitempty"`
	MmsFlag      *struct{}             `asn1:"tag:3,context,implicit,optional" json:"MmsFlag,omitempty"`
	ExtCount_    int64                 `asn1:"-" json:"-"`
	ExtPresent_  []bool                `asn1:"-" json:"-"`
	ExtData_     [][]byte              `asn1:"-" json:"-"`
	berOriginal_ []byte                `asn1:"-" json:"-"`
	berSnapshot_ []byte                `asn1:"-" json:"-"`
}

// NumberPorted represents the ASN.1 ENUMERATED type NumberPorted.
type NumberPorted int64

const (
	NumberPortedNotPorted NumberPorted = 0
	NumberPortedPorted    NumberPorted = 1
)

func (v NumberPorted) String() string {
	switch v {
	case NumberPortedNotPorted:
		return "notPorted"
	case NumberPortedPorted:
		return "ported"
	default:
		return "unknown"
	}
}

// USSDExtension represents the ASN.1 type USSD-Extension (SEQUENCE).
type USSDExtension struct {
	RoutingCategory *RoutingCategory                         `asn1:"tag:0,context,implicit,optional" json:"RoutingCategory,omitempty"`
	CellId          *CellGlobalIdOrServiceAreaIdFixedLength5 `asn1:"tag:1,context,implicit,optional" json:"CellId,omitempty"`
	SaiPresent      *struct{}                                `asn1:"tag:2,context,implicit,optional" json:"SaiPresent,omitempty"`
	ExtCount_       int64                                    `asn1:"-" json:"-"`
	ExtPresent_     []bool                                   `asn1:"-" json:"-"`
	ExtData_        [][]byte                                 `asn1:"-" json:"-"`
	berOriginal_    []byte                                   `asn1:"-" json:"-"`
	berSnapshot_    []byte                                   `asn1:"-" json:"-"`
}

// HOExt represents the ASN.1 type HO-Ext (SEQUENCE).
type HOExt struct {
	MapOpt          *MapOptFields  `asn1:"tag:0,context,implicit,optional" json:"MapOpt,omitempty"`
	CodecList       *CodecListExt  `asn1:"tag:1,context,implicit,optional" json:"CodecList,omitempty"`
	CodecListIndef_ bool           `asn1:"-" json:"-"`
	SelectedCodec   *SelectedCodec `asn1:"tag:2,context,implicit,optional" json:"SelectedCodec,omitempty"`
	UmaAccess       *struct{}      `asn1:"tag:3,context,implicit,optional" json:"UmaAccess,omitempty"`
	UmaIpAddress    []byte         `asn1:"tag:4,context,implicit,optional" json:"UmaIpAddress,omitzero"`
	UmaIpPortNb     *IPPortNb      `asn1:"tag:5,context,implicit,optional" json:"UmaIpPortNb,omitempty"`
	ExtCount_       int64          `asn1:"-" json:"-"`
	ExtPresent_     []bool         `asn1:"-" json:"-"`
	ExtData_        [][]byte       `asn1:"-" json:"-"`
	berOriginal_    []byte         `asn1:"-" json:"-"`
	berSnapshot_    []byte         `asn1:"-" json:"-"`
}

// MapOptFields represents the ASN.1 type MapOptFields (OCTET_STRING).
type MapOptFields = []byte

// CodecListExt represents the ASN.1 type CodecListExt (SEQUENCE_OF).
type CodecListExt struct {
	Values       []CodecExt `json:"Values"`
	berOriginal_ []byte     `json:"-"`
	berSnapshot_ []byte     `json:"-"`
}

// CodecExt represents the ASN.1 type CodecExt (OCTET_STRING).
type CodecExt = []byte

// SelectedCodec represents the ASN.1 type SelectedCodec (SEQUENCE).
type SelectedCodec struct {
	Codec        CodecExt `asn1:"tag:0,context,implicit"`
	Modes        Modes    `asn1:"tag:1,context,implicit"`
	ExtCount_    int64    `asn1:"-" json:"-"`
	ExtPresent_  []bool   `asn1:"-" json:"-"`
	ExtData_     [][]byte `asn1:"-" json:"-"`
	berOriginal_ []byte   `asn1:"-" json:"-"`
	berSnapshot_ []byte   `asn1:"-" json:"-"`
}

// Modes represents the ASN.1 type Modes (OCTET_STRING).
type Modes = []byte

// IPPortNb represents the ASN.1 type IPPortNb (INTEGER).
type IPPortNb = int64

// AbsentSubscriberExt represents the ASN.1 type AbsentSubscriberExt (SEQUENCE).
type AbsentSubscriberExt struct {
	OlcmInfoTable       *OlcmInfoTable `asn1:"tag:0,context,implicit,optional" json:"OlcmInfoTable,omitempty"`
	OlcmInfoTableIndef_ bool           `asn1:"-" json:"-"`
	Imsi                *IMSI5         `asn1:"tag:1,context,implicit,optional" json:"Imsi,omitempty"`
	ExtCount_           int64          `asn1:"-" json:"-"`
	ExtPresent_         []bool         `asn1:"-" json:"-"`
	ExtData_            [][]byte       `asn1:"-" json:"-"`
	berOriginal_        []byte         `asn1:"-" json:"-"`
	berSnapshot_        []byte         `asn1:"-" json:"-"`
}

// ErrOlcmInfoTableExt represents the ASN.1 type ErrOlcmInfoTableExt (SEQUENCE).
type ErrOlcmInfoTableExt struct {
	OlcmInfoTable       *OlcmInfoTable `asn1:"tag:0,context,implicit,optional" json:"OlcmInfoTable,omitempty"`
	OlcmInfoTableIndef_ bool           `asn1:"-" json:"-"`
	Imsi                *IMSI5         `asn1:"tag:1,context,implicit,optional" json:"Imsi,omitempty"`
	ExtCount_           int64          `asn1:"-" json:"-"`
	ExtPresent_         []bool         `asn1:"-" json:"-"`
	ExtData_            [][]byte       `asn1:"-" json:"-"`
	berOriginal_        []byte         `asn1:"-" json:"-"`
	berSnapshot_        []byte         `asn1:"-" json:"-"`
}

// RoutingCategoryExt represents the ASN.1 type RoutingCategoryExt (SEQUENCE).
type RoutingCategoryExt struct {
	RoutingCategory    *RoutingCategory    `asn1:"tag:0,context,implicit,optional" json:"RoutingCategory,omitempty"`
	ExtRoutingCategory *ExtRoutingCategory `asn1:"tag:1,context,implicit,optional" json:"ExtRoutingCategory,omitempty"`
	ExtCount_          int64               `asn1:"-" json:"-"`
	ExtPresent_        []bool              `asn1:"-" json:"-"`
	ExtData_           [][]byte            `asn1:"-" json:"-"`
	berOriginal_       []byte              `asn1:"-" json:"-"`
	berSnapshot_       []byte              `asn1:"-" json:"-"`
}

// SriForSMArgExt represents the ASN.1 type SriForSMArgExt (SEQUENCE).
type SriForSMArgExt struct {
	CfuSMSCounter     *CfuSMSCounter `asn1:"tag:0,context,implicit,optional" json:"CfuSMSCounter,omitempty"`
	Cfusmcfo          *struct{}      `asn1:"tag:2,context,implicit,optional" json:"Cfusmcfo,omitempty"`
	MemberInterrogate *struct{}      `asn1:"tag:3,context,implicit,optional" json:"MemberInterrogate,omitempty"`
	ExtCount_         int64          `asn1:"-" json:"-"`
	ExtPresent_       []bool         `asn1:"-" json:"-"`
	ExtData_          [][]byte       `asn1:"-" json:"-"`
	berOriginal_      []byte         `asn1:"-" json:"-"`
	berSnapshot_      []byte         `asn1:"-" json:"-"`
}

// ReportSMDelStatArgExt represents the ASN.1 type ReportSMDelStatArgExt (SEQUENCE).
type ReportSMDelStatArgExt struct {
	CfuSMSCounter *CfuSMSCounter `asn1:"tag:0,context,implicit,optional" json:"CfuSMSCounter,omitempty"`
	Cfusmcfo      *struct{}      `asn1:"tag:2,context,implicit,optional" json:"Cfusmcfo,omitempty"`
	ExtCount_     int64          `asn1:"-" json:"-"`
	ExtPresent_   []bool         `asn1:"-" json:"-"`
	ExtData_      [][]byte       `asn1:"-" json:"-"`
	berOriginal_  []byte         `asn1:"-" json:"-"`
	berSnapshot_  []byte         `asn1:"-" json:"-"`
}

// CfuSMSCounter represents the ASN.1 type CfuSMSCounter (OCTET_STRING).
type CfuSMSCounter = []byte

// MOForwardSMArgExt represents the ASN.1 type MO-ForwardSM-ArgExt (SEQUENCE).
type MOForwardSMArgExt struct {
	LocationAreaCode *LocationAreaCode                        `asn1:"tag:0,context,implicit,optional" json:"LocationAreaCode,omitempty"`
	CellId           *CellGlobalIdOrServiceAreaIdFixedLength5 `asn1:"tag:1,context,implicit,optional" json:"CellId,omitempty"`
	ExtCount_        int64                                    `asn1:"-" json:"-"`
	ExtPresent_      []bool                                   `asn1:"-" json:"-"`
	ExtData_         [][]byte                                 `asn1:"-" json:"-"`
	berOriginal_     []byte                                   `asn1:"-" json:"-"`
	berSnapshot_     []byte                                   `asn1:"-" json:"-"`
}

// LocationAreaCode represents the ASN.1 type LocationAreaCode (OCTET_STRING).
type LocationAreaCode = []byte

// UdlArgExt represents the ASN.1 type UdlArgExt (SEQUENCE).
type UdlArgExt struct {
	Lai          *LAIFixedLength5 `asn1:"tag:0,context,implicit,optional" json:"Lai,omitempty"`
	SendImmResp  *struct{}        `asn1:"tag:1,context,implicit,optional" json:"SendImmResp,omitempty"`
	ExtCount_    int64            `asn1:"-" json:"-"`
	ExtPresent_  []bool           `asn1:"-" json:"-"`
	ExtData_     [][]byte         `asn1:"-" json:"-"`
	berOriginal_ []byte           `asn1:"-" json:"-"`
	berSnapshot_ []byte           `asn1:"-" json:"-"`
}

// RoamNotAllowedExt represents the ASN.1 type RoamNotAllowedExt (SEQUENCE).
type RoamNotAllowedExt struct {
	RejectCause  []byte   `asn1:"tag:0,context,implicit,optional" json:"RejectCause,omitzero"`
	ExtCount_    int64    `asn1:"-" json:"-"`
	ExtPresent_  []bool   `asn1:"-" json:"-"`
	ExtData_     [][]byte `asn1:"-" json:"-"`
	berOriginal_ []byte   `asn1:"-" json:"-"`
	berSnapshot_ []byte   `asn1:"-" json:"-"`
}

// AnyTimeModArgExt represents the ASN.1 type AnyTimeModArgExt (SEQUENCE).
type AnyTimeModArgExt struct {
	SenderMSISDN *ISDNAddressString5 `asn1:"tag:0,context,implicit,optional" json:"SenderMSISDN,omitempty"`
	ExtCount_    int64               `asn1:"-" json:"-"`
	ExtPresent_  []bool              `asn1:"-" json:"-"`
	ExtData_     [][]byte            `asn1:"-" json:"-"`
	berOriginal_ []byte              `asn1:"-" json:"-"`
	berSnapshot_ []byte              `asn1:"-" json:"-"`
}

// CosInfo represents the ASN.1 type CosInfo (SEQUENCE).
type CosInfo struct {
	SsCode               *SSCode6        `asn1:",optional" json:"SsCode,omitempty"`
	CosFeatureList       *COSFeatureList `asn1:""`
	CosFeatureListIndef_ bool            `asn1:"-" json:"-"`
	berOriginal_         []byte          `asn1:"-" json:"-"`
	berSnapshot_         []byte          `asn1:"-" json:"-"`
}

// COSFeatureList represents the ASN.1 type COS-FeatureList (SEQUENCE_OF).
type COSFeatureList struct {
	Values       []COSFeature `json:"Values"`
	berOriginal_ []byte       `json:"-"`
	berSnapshot_ []byte       `json:"-"`
}

// COSFeature represents the ASN.1 type COS-Feature (SEQUENCE).
type COSFeature struct {
	BasicServiceCode *BasicServiceCode5 `asn1:",optional" json:"BasicServiceCode,omitempty"`
	SsStatus         SSStatus6          `asn1:"tag:4,context,implicit"`
	CustomerGroupID  *CustomerGroupID   `asn1:"tag:5,context,implicit,optional" json:"CustomerGroupID,omitempty"`
	SubGroupID       *SubGroupID        `asn1:"tag:6,context,implicit,optional" json:"SubGroupID,omitempty"`
	ClassOfServiceID *ClassOfServiceID  `asn1:"tag:7,context,implicit,optional" json:"ClassOfServiceID,omitempty"`
	berOriginal_     []byte             `asn1:"-" json:"-"`
	berSnapshot_     []byte             `asn1:"-" json:"-"`
}

// CustomerGroupID represents the ASN.1 type CustomerGroupID (BIT_STRING).
type CustomerGroupID = runtime.BitString

// SubGroupID represents the ASN.1 type SubGroupID (BIT_STRING).
type SubGroupID = runtime.BitString

// ClassOfServiceID represents the ASN.1 type ClassOfServiceID (BIT_STRING).
type ClassOfServiceID = runtime.BitString

// AccessTypeExt represents the ASN.1 type AccessTypeExt (SEQUENCE).
type AccessTypeExt struct {
	Access       Access   `asn1:""`
	Version      Version  `asn1:""`
	ExtCount_    int64    `asn1:"-" json:"-"`
	ExtPresent_  []bool   `asn1:"-" json:"-"`
	ExtData_     [][]byte `asn1:"-" json:"-"`
	berOriginal_ []byte   `asn1:"-" json:"-"`
	berSnapshot_ []byte   `asn1:"-" json:"-"`
}

// Access represents the ASN.1 ENUMERATED type Access.
type Access int64

const (
	AccessGsm   Access = 1
	AccessGeran Access = 2
	AccessUtran Access = 3
)

func (v Access) String() string {
	switch v {
	case AccessGsm:
		return "gsm"
	case AccessGeran:
		return "geran"
	case AccessUtran:
		return "utran"
	default:
		return "unknown"
	}
}

// Version represents the ASN.1 type Version (INTEGER).
type Version = int64

// AccessSubscriptionListExt represents the ASN.1 type AccessSubscriptionListExt (SEQUENCE_OF).
type AccessSubscriptionListExt struct {
	Values       []Access `json:"Values"`
	berOriginal_ []byte   `json:"-"`
	berSnapshot_ []byte   `json:"-"`
}

// AllowedServiceData represents the ASN.1 type AllowedServiceData (BIT_STRING).
type AllowedServiceData = runtime.BitString

// AnyTimePOBarringArg represents the ASN.1 type AnyTimePO-BarringArg (SEQUENCE).
type AnyTimePOBarringArg struct {
	SubscriberIdentity SubscriberIdentity5 `asn1:"tag:0,context,explicit"`
	GsmSCFAddress      ISDNAddressString5  `asn1:"tag:3,context,implicit"`
	GprsBarring        GprsBarring         `asn1:""`
	ExtCount_          int64               `asn1:"-" json:"-"`
	ExtPresent_        []bool              `asn1:"-" json:"-"`
	ExtData_           [][]byte            `asn1:"-" json:"-"`
	berOriginal_       []byte              `asn1:"-" json:"-"`
	berSnapshot_       []byte              `asn1:"-" json:"-"`
}

// AnyTimePOBarringRes represents the ASN.1 type AnyTimePO-BarringRes (SEQUENCE).
type AnyTimePOBarringRes struct {
	ExtCount_    int64    `asn1:"-" json:"-"`
	ExtPresent_  []bool   `asn1:"-" json:"-"`
	ExtData_     [][]byte `asn1:"-" json:"-"`
	berOriginal_ []byte   `asn1:"-" json:"-"`
	berSnapshot_ []byte   `asn1:"-" json:"-"`
}

// GprsBarring represents the ASN.1 ENUMERATED type GprsBarring.
type GprsBarring int64

const (
	GprsBarringGprsServiceBarring GprsBarring = 0
	GprsBarringGrantGPRSService   GprsBarring = 1
)

func (v GprsBarring) String() string {
	switch v {
	case GprsBarringGprsServiceBarring:
		return "gprsServiceBarring"
	case GprsBarringGrantGPRSService:
		return "grantGPRS-Service"
	default:
		return "unknown"
	}
}

// MarshalBER encodes IsdArgExt to BER format.
func (v *IsdArgExt) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: IsdArgExt receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *IsdArgExt) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if v.AlsLineIndicator != nil {
		enc_alslineindicator := ber.EncodeNull()
		retagged_enc_alslineindicator, tagErr_enc_alslineindicator := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_alslineindicator)
		if tagErr_enc_alslineindicator != nil {
			return nil, fmt.Errorf("encoding alsLineIndicator: %w", tagErr_enc_alslineindicator)
		}
		enc_alslineindicator = retagged_enc_alslineindicator
		children = append(children, enc_alslineindicator...)
	}
	if v.RoutingCategory != nil {
		if len(*v.RoutingCategory) < 1 || len(*v.RoutingCategory) > 1 {
			if constraintErr := ber.CheckEncodedLength(opts, "routingCategory", "SIZE (1)", len(*v.RoutingCategory)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_routingcategory, encodeErr_enc_routingcategory := ber.EncodeOctetString([]byte(*v.RoutingCategory))
		if encodeErr_enc_routingcategory != nil {
			return nil, fmt.Errorf("encoding routingCategory: %w", encodeErr_enc_routingcategory)
		}
		retagged_enc_routingcategory, tagErr_enc_routingcategory := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_routingcategory)
		if tagErr_enc_routingcategory != nil {
			return nil, fmt.Errorf("encoding routingCategory: %w", tagErr_enc_routingcategory)
		}
		enc_routingcategory = retagged_enc_routingcategory
		children = append(children, enc_routingcategory...)
	}
	if v.ServiceList != nil {
		if len(*v.ServiceList) > 256 {
			if constraintErr := ber.CheckEncodedLength(opts, "serviceList", "SIZE (0..256)", len(*v.ServiceList)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_servicelist, encodeErr_enc_servicelist := ber.EncodeOctetString([]byte(*v.ServiceList))
		if encodeErr_enc_servicelist != nil {
			return nil, fmt.Errorf("encoding serviceList: %w", encodeErr_enc_servicelist)
		}
		retagged_enc_servicelist, tagErr_enc_servicelist := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_servicelist)
		if tagErr_enc_servicelist != nil {
			return nil, fmt.Errorf("encoding serviceList: %w", tagErr_enc_servicelist)
		}
		enc_servicelist = retagged_enc_servicelist
		children = append(children, enc_servicelist...)
	}
	if v.ServInfoList != nil {
		if len((v.ServInfoList).Values) < 1 || len((v.ServInfoList).Values) > 20 {
			if constraintErr := ber.CheckEncodedLength(opts, "serv-info-list", "SIZE (1..20)", len((v.ServInfoList).Values)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_servinfolist, err := MarshalBERServiceListWithInfo(v.ServInfoList, ber.ChildEncodeOptions(opts, "serv-info-list")...)
		if err != nil {
			return nil, fmt.Errorf("encoding serv-info-list: %w", err)
		}
		if v.ServInfoListIndef_ {
			// Strip the outer SEQUENCE tag from marshalBER output to get raw children.
			_, _, seqContent_, tlvErr_ := ber.DecodeEncodedTLV(enc_servinfolist)
			if tlvErr_ != nil {
				return nil, tlvErr_
			}
			{
				var encodeErr error
				enc_servinfolist, encodeErr = ber.EncodeConstructedIndefinite(tag.Tag{Class: tag.ClassContextSpecific, Number: 3}, seqContent_)
				if encodeErr != nil {
					return nil, fmt.Errorf("encoding serv-info-list: %w", encodeErr)
				}
			}
		} else {
			retagged_enc_servinfolist, tagErr_enc_servinfolist := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, enc_servinfolist)
			if tagErr_enc_servinfolist != nil {
				return nil, fmt.Errorf("encoding serv-info-list: %w", tagErr_enc_servinfolist)
			}
			enc_servinfolist = retagged_enc_servinfolist
		}
		children = append(children, enc_servinfolist...)
	}
	if v.ExtRoutingCategory != nil {
		if !(int64(*v.ExtRoutingCategory) >= 0 && int64(*v.ExtRoutingCategory) <= 2147483647) {
			if constraintErr := ber.CheckEncodedValue(opts, "extRoutingCategory", "(0..2147483647)", fmt.Sprint(int64(*v.ExtRoutingCategory))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_extroutingcategory := ber.EncodeInteger(int64(*v.ExtRoutingCategory))
		retagged_enc_extroutingcategory, tagErr_enc_extroutingcategory := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 5, enc_extroutingcategory)
		if tagErr_enc_extroutingcategory != nil {
			return nil, fmt.Errorf("encoding extRoutingCategory: %w", tagErr_enc_extroutingcategory)
		}
		enc_extroutingcategory = retagged_enc_extroutingcategory
		children = append(children, enc_extroutingcategory...)
	}
	if v.OwnMSISDN != nil {
		if len(*v.OwnMSISDN) < 1 || len(*v.OwnMSISDN) > 9 {
			if constraintErr := ber.CheckEncodedLength(opts, "ownMSISDN", "SIZE (1..9)", len(*v.OwnMSISDN)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		if len(*v.OwnMSISDN) < 1 || len(*v.OwnMSISDN) > 20 {
			if constraintErr := ber.CheckEncodedLength(opts, "ownMSISDN", "SIZE (1..20)", len(*v.OwnMSISDN)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_ownmsisdn, encodeErr_enc_ownmsisdn := ber.EncodeOctetString([]byte(*v.OwnMSISDN))
		if encodeErr_enc_ownmsisdn != nil {
			return nil, fmt.Errorf("encoding ownMSISDN: %w", encodeErr_enc_ownmsisdn)
		}
		retagged_enc_ownmsisdn, tagErr_enc_ownmsisdn := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 6, enc_ownmsisdn)
		if tagErr_enc_ownmsisdn != nil {
			return nil, fmt.Errorf("encoding ownMSISDN: %w", tagErr_enc_ownmsisdn)
		}
		enc_ownmsisdn = retagged_enc_ownmsisdn
		children = append(children, enc_ownmsisdn...)
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
	return ber.EncodeConstructed(tag.Tag{Class: tag.ClassPrivate, Number: 0, Constructed: true}, children)
}

// MarshalDER encodes IsdArgExt to DER format.
func (v *IsdArgExt) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: IsdArgExt receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if v.AlsLineIndicator != nil {
		enc_alslineindicator := ber.EncodeNull()
		retagged_enc_alslineindicator, tagErr_enc_alslineindicator := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_alslineindicator)
		if tagErr_enc_alslineindicator != nil {
			return nil, fmt.Errorf("encoding alsLineIndicator: %w", tagErr_enc_alslineindicator)
		}
		enc_alslineindicator = retagged_enc_alslineindicator
		children = append(children, enc_alslineindicator...)
	}
	if v.RoutingCategory != nil {
		if len(*v.RoutingCategory) < 1 || len(*v.RoutingCategory) > 1 {
			if constraintErr := ber.CheckEncodedLength(nil, "routingCategory", "SIZE (1)", len(*v.RoutingCategory)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_routingcategory, encodeErr_enc_routingcategory := ber.EncodeOctetString([]byte(*v.RoutingCategory))
		if encodeErr_enc_routingcategory != nil {
			return nil, fmt.Errorf("encoding routingCategory: %w", encodeErr_enc_routingcategory)
		}
		retagged_enc_routingcategory, tagErr_enc_routingcategory := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_routingcategory)
		if tagErr_enc_routingcategory != nil {
			return nil, fmt.Errorf("encoding routingCategory: %w", tagErr_enc_routingcategory)
		}
		enc_routingcategory = retagged_enc_routingcategory
		children = append(children, enc_routingcategory...)
	}
	if v.ServiceList != nil {
		if len(*v.ServiceList) > 256 {
			if constraintErr := ber.CheckEncodedLength(nil, "serviceList", "SIZE (0..256)", len(*v.ServiceList)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_servicelist, encodeErr_enc_servicelist := ber.EncodeOctetString([]byte(*v.ServiceList))
		if encodeErr_enc_servicelist != nil {
			return nil, fmt.Errorf("encoding serviceList: %w", encodeErr_enc_servicelist)
		}
		retagged_enc_servicelist, tagErr_enc_servicelist := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_servicelist)
		if tagErr_enc_servicelist != nil {
			return nil, fmt.Errorf("encoding serviceList: %w", tagErr_enc_servicelist)
		}
		enc_servicelist = retagged_enc_servicelist
		children = append(children, enc_servicelist...)
	}
	if v.ServInfoList != nil {
		if len((v.ServInfoList).Values) < 1 || len((v.ServInfoList).Values) > 20 {
			if constraintErr := ber.CheckEncodedLength(nil, "serv-info-list", "SIZE (1..20)", len((v.ServInfoList).Values)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_servinfolist, err := MarshalDERServiceListWithInfo(v.ServInfoList)
		if err != nil {
			return nil, fmt.Errorf("encoding serv-info-list: %w", err)
		}
		retagged_enc_servinfolist, tagErr_enc_servinfolist := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, enc_servinfolist)
		if tagErr_enc_servinfolist != nil {
			return nil, fmt.Errorf("encoding serv-info-list: %w", tagErr_enc_servinfolist)
		}
		enc_servinfolist = retagged_enc_servinfolist
		children = append(children, enc_servinfolist...)
	}
	if v.ExtRoutingCategory != nil {
		if !(int64(*v.ExtRoutingCategory) >= 0 && int64(*v.ExtRoutingCategory) <= 2147483647) {
			if constraintErr := ber.CheckEncodedValue(nil, "extRoutingCategory", "(0..2147483647)", fmt.Sprint(int64(*v.ExtRoutingCategory))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_extroutingcategory := ber.EncodeInteger(int64(*v.ExtRoutingCategory))
		retagged_enc_extroutingcategory, tagErr_enc_extroutingcategory := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 5, enc_extroutingcategory)
		if tagErr_enc_extroutingcategory != nil {
			return nil, fmt.Errorf("encoding extRoutingCategory: %w", tagErr_enc_extroutingcategory)
		}
		enc_extroutingcategory = retagged_enc_extroutingcategory
		children = append(children, enc_extroutingcategory...)
	}
	if v.OwnMSISDN != nil {
		if len(*v.OwnMSISDN) < 1 || len(*v.OwnMSISDN) > 9 {
			if constraintErr := ber.CheckEncodedLength(nil, "ownMSISDN", "SIZE (1..9)", len(*v.OwnMSISDN)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		if len(*v.OwnMSISDN) < 1 || len(*v.OwnMSISDN) > 20 {
			if constraintErr := ber.CheckEncodedLength(nil, "ownMSISDN", "SIZE (1..20)", len(*v.OwnMSISDN)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_ownmsisdn, encodeErr_enc_ownmsisdn := ber.EncodeOctetString([]byte(*v.OwnMSISDN))
		if encodeErr_enc_ownmsisdn != nil {
			return nil, fmt.Errorf("encoding ownMSISDN: %w", encodeErr_enc_ownmsisdn)
		}
		retagged_enc_ownmsisdn, tagErr_enc_ownmsisdn := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 6, enc_ownmsisdn)
		if tagErr_enc_ownmsisdn != nil {
			return nil, fmt.Errorf("encoding ownMSISDN: %w", tagErr_enc_ownmsisdn)
		}
		enc_ownmsisdn = retagged_enc_ownmsisdn
		children = append(children, enc_ownmsisdn...)
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
	retagged_encoded, tagErr_encoded := ber.EncodeImplicitTagWithClass(tag.ClassPrivate, 0, encoded)
	if tagErr_encoded != nil {
		return nil, fmt.Errorf("encoding IsdArgExt: %w", tagErr_encoded)
	}
	encoded = retagged_encoded
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding IsdArgExt as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes IsdArgExt from BER/DER format.
func (v *IsdArgExt) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: IsdArgExt destination is nil", ber.ErrInvalidValue)
	}
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = IsdArgExt{}
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
	decodedTag, content, total, err := ber.DecodeConstructedContent(data, opts...)
	if err != nil {
		return fmt.Errorf("decoding IsdArgExt: %w", err)
	}
	if decodedTag.Class != tag.ClassPrivate || decodedTag.Number != 0 || !decodedTag.Constructed {
		return fmt.Errorf("decoding IsdArgExt: %w: expected tag [PRIVATE 0], got %s", ber.ErrInvalidTag, decodedTag)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "IsdArgExt", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode alsLineIndicator
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
				decodedTag_alslineindicator, n_alslineindicator, rawVal_alslineindicator, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding alsLineIndicator: %w", err)
				}
				if decodedTag_alslineindicator.Class != tag.ClassContextSpecific || decodedTag_alslineindicator.Number != 0 || decodedTag_alslineindicator.Constructed != false {
					return fmt.Errorf("decoding alsLineIndicator: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_alslineindicator)
				}
				if len(rawVal_alslineindicator) != 0 {
					return fmt.Errorf("decoding alsLineIndicator: %w: NULL content length %d", ber.ErrInvalidValue, len(rawVal_alslineindicator))
				}
				v.AlsLineIndicator = &struct{}{}
				if offset < 0 || offset >
					len(content) || n_alslineindicator < 0 || n_alslineindicator >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_alslineindicator
			}
		}
	}
	// Decode routingCategory
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
				decodedTag_routingcategory, n_routingcategory, rawVal_routingcategory, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding routingCategory: %w", err)
				}
				if decodedTag_routingcategory.Class != tag.ClassContextSpecific || decodedTag_routingcategory.Number != 1 {
					return fmt.Errorf("decoding routingCategory: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_routingcategory)
				}
				decVal_routingcategory, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_routingcategory.Constructed, rawVal_routingcategory, opts...)
				if octetErr != nil {
					return fmt.Errorf("decoding routingCategory: %w", octetErr)
				}
				tmp_routingcategory := RoutingCategory(decVal_routingcategory)
				v.RoutingCategory = &tmp_routingcategory
				if offset < 0 || offset >
					len(content) || n_routingcategory < 0 || n_routingcategory >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_routingcategory
				if len(*v.RoutingCategory) < 1 || len(*v.RoutingCategory) > 1 {
					if constraintErr := ber.CheckDecodedLength(opts, "routingCategory", "SIZE (1)", len(*v.RoutingCategory)); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode serviceList
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2 {
				decodedTag_servicelist, n_servicelist, rawVal_servicelist, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding serviceList: %w", err)
				}
				if decodedTag_servicelist.Class != tag.ClassContextSpecific || decodedTag_servicelist.Number != 2 {
					return fmt.Errorf("decoding serviceList: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_servicelist)
				}
				decVal_servicelist, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_servicelist.Constructed, rawVal_servicelist, opts...)
				if octetErr != nil {
					return fmt.Errorf("decoding serviceList: %w", octetErr)
				}
				tmp_servicelist := MAPserviceList(decVal_servicelist)
				v.ServiceList = &tmp_servicelist
				if offset < 0 || offset >
					len(content) || n_servicelist < 0 || n_servicelist >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_servicelist
				if len(*v.ServiceList) > 256 {
					if constraintErr := ber.CheckDecodedLength(opts, "serviceList", "SIZE (0..256)", len(*v.ServiceList)); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode serv-info-list
	v.ServInfoListIndef_ = false
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3 {
				decodedTag_servinfolist, n_servinfolist, rawVal_servinfolist, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding serv-info-list: %w", err)
				}
				if decodedTag_servinfolist.Class != tag.ClassContextSpecific || decodedTag_servinfolist.Number != 3 || decodedTag_servinfolist.Constructed != true {
					return fmt.Errorf("decoding serv-info-list: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_servinfolist)
				}
				reconstructed_servinfolist, reconstructionErr_servinfolist := ber.EncodeSequence(rawVal_servinfolist)
				if reconstructionErr_servinfolist != nil {
					return fmt.Errorf("decoding serv-info-list: %w", reconstructionErr_servinfolist)
				}
				dec_servinfolist, unmErr := UnmarshalBERServiceListWithInfo(reconstructed_servinfolist, ber.ChildDecodeOptions(opts, "serv-info-list")...)
				if unmErr != nil {
					return fmt.Errorf("decoding serv-info-list: %w", unmErr)
				}
				v.ServInfoList = dec_servinfolist
				{
					_, tagSz_, _ := ber.DecodeTag(content[offset:])
					if offset < 0 || offset >
						len(content) || tagSz_ < 0 || tagSz_ > len(content[offset:]) {
						return fmt.Errorf("invalid BER content window")
					}

					if offset+tagSz_ < len(content) && content[offset+tagSz_] == 0x80 {
						v.ServInfoListIndef_ = true
					}
				}
				if offset < 0 || offset >
					len(content) || n_servinfolist < 0 || n_servinfolist >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_servinfolist
				if len((v.ServInfoList).Values) < 1 || len((v.ServInfoList).Values) > 20 {
					if constraintErr := ber.CheckDecodedLength(opts, "serv-info-list", "SIZE (1..20)", len((v.ServInfoList).Values)); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode extRoutingCategory
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 5 {
				decodedTag_extroutingcategory, n_extroutingcategory, rawVal_extroutingcategory, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding extRoutingCategory: %w", err)
				}
				if decodedTag_extroutingcategory.Class != tag.ClassContextSpecific || decodedTag_extroutingcategory.Number != 5 || decodedTag_extroutingcategory.Constructed != false {
					return fmt.Errorf("decoding extRoutingCategory: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_extroutingcategory)
				}
				decVal_extroutingcategory, intErr := ber.DecodeIntegerValue(rawVal_extroutingcategory)
				if intErr != nil {
					return fmt.Errorf("decoding extRoutingCategory: %w", intErr)
				}
				tmp_extroutingcategory := ExtRoutingCategory(decVal_extroutingcategory)
				v.ExtRoutingCategory = &tmp_extroutingcategory
				if offset < 0 || offset >
					len(content) || n_extroutingcategory < 0 || n_extroutingcategory >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_extroutingcategory
				if !(int64(*v.ExtRoutingCategory) >= 0 && int64(*v.ExtRoutingCategory) <= 2147483647) {
					if constraintErr := ber.CheckDecodedValue(opts, "extRoutingCategory", "(0..2147483647)", fmt.Sprint(int64(*v.ExtRoutingCategory))); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode ownMSISDN
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 6 {
				decodedTag_ownmsisdn, n_ownmsisdn, rawVal_ownmsisdn, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding ownMSISDN: %w", err)
				}
				if decodedTag_ownmsisdn.Class != tag.ClassContextSpecific || decodedTag_ownmsisdn.Number != 6 {
					return fmt.Errorf("decoding ownMSISDN: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_ownmsisdn)
				}
				decVal_ownmsisdn, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_ownmsisdn.Constructed, rawVal_ownmsisdn, opts...)
				if octetErr != nil {
					return fmt.Errorf("decoding ownMSISDN: %w", octetErr)
				}
				tmp_ownmsisdn := ISDNAddressString5(decVal_ownmsisdn)
				v.OwnMSISDN = &tmp_ownmsisdn
				if offset < 0 || offset >
					len(content) || n_ownmsisdn < 0 || n_ownmsisdn > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_ownmsisdn
				if len(*v.OwnMSISDN) < 1 || len(*v.OwnMSISDN) > 9 {
					if constraintErr := ber.CheckDecodedLength(opts, "ownMSISDN", "SIZE (1..9)", len(*v.OwnMSISDN)); constraintErr != nil {
						return constraintErr
					}
				}
				if len(*v.OwnMSISDN) < 1 || len(*v.OwnMSISDN) > 20 {
					if constraintErr := ber.CheckDecodedLength(opts, "ownMSISDN", "SIZE (1..20)", len(*v.OwnMSISDN)); constraintErr != nil {
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
			return &ber.DecodeError{Offset: offset, TypeName: "IsdArgExt", Cause: extErr_}
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

// MarshalBER encodes DsdArgExt to BER format.
func (v *DsdArgExt) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: DsdArgExt receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *DsdArgExt) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if v.AlsLineIndicator != nil {
		enc_alslineindicator := ber.EncodeNull()
		retagged_enc_alslineindicator, tagErr_enc_alslineindicator := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_alslineindicator)
		if tagErr_enc_alslineindicator != nil {
			return nil, fmt.Errorf("encoding alsLineIndicator: %w", tagErr_enc_alslineindicator)
		}
		enc_alslineindicator = retagged_enc_alslineindicator
		children = append(children, enc_alslineindicator...)
	}
	if v.ServiceList != nil {
		if len(*v.ServiceList) > 256 {
			if constraintErr := ber.CheckEncodedLength(opts, "serviceList", "SIZE (0..256)", len(*v.ServiceList)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_servicelist, encodeErr_enc_servicelist := ber.EncodeOctetString([]byte(*v.ServiceList))
		if encodeErr_enc_servicelist != nil {
			return nil, fmt.Errorf("encoding serviceList: %w", encodeErr_enc_servicelist)
		}
		retagged_enc_servicelist, tagErr_enc_servicelist := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_servicelist)
		if tagErr_enc_servicelist != nil {
			return nil, fmt.Errorf("encoding serviceList: %w", tagErr_enc_servicelist)
		}
		enc_servicelist = retagged_enc_servicelist
		children = append(children, enc_servicelist...)
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
	return ber.EncodeConstructed(tag.Tag{Class: tag.ClassPrivate, Number: 0, Constructed: true}, children)
}

// MarshalDER encodes DsdArgExt to DER format.
func (v *DsdArgExt) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: DsdArgExt receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if v.AlsLineIndicator != nil {
		enc_alslineindicator := ber.EncodeNull()
		retagged_enc_alslineindicator, tagErr_enc_alslineindicator := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_alslineindicator)
		if tagErr_enc_alslineindicator != nil {
			return nil, fmt.Errorf("encoding alsLineIndicator: %w", tagErr_enc_alslineindicator)
		}
		enc_alslineindicator = retagged_enc_alslineindicator
		children = append(children, enc_alslineindicator...)
	}
	if v.ServiceList != nil {
		if len(*v.ServiceList) > 256 {
			if constraintErr := ber.CheckEncodedLength(nil, "serviceList", "SIZE (0..256)", len(*v.ServiceList)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_servicelist, encodeErr_enc_servicelist := ber.EncodeOctetString([]byte(*v.ServiceList))
		if encodeErr_enc_servicelist != nil {
			return nil, fmt.Errorf("encoding serviceList: %w", encodeErr_enc_servicelist)
		}
		retagged_enc_servicelist, tagErr_enc_servicelist := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_servicelist)
		if tagErr_enc_servicelist != nil {
			return nil, fmt.Errorf("encoding serviceList: %w", tagErr_enc_servicelist)
		}
		enc_servicelist = retagged_enc_servicelist
		children = append(children, enc_servicelist...)
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
	retagged_encoded, tagErr_encoded := ber.EncodeImplicitTagWithClass(tag.ClassPrivate, 0, encoded)
	if tagErr_encoded != nil {
		return nil, fmt.Errorf("encoding DsdArgExt: %w", tagErr_encoded)
	}
	encoded = retagged_encoded
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding DsdArgExt as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes DsdArgExt from BER/DER format.
func (v *DsdArgExt) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: DsdArgExt destination is nil", ber.ErrInvalidValue)
	}
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = DsdArgExt{}
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
	decodedTag, content, total, err := ber.DecodeConstructedContent(data, opts...)
	if err != nil {
		return fmt.Errorf("decoding DsdArgExt: %w", err)
	}
	if decodedTag.Class != tag.ClassPrivate || decodedTag.Number != 0 || !decodedTag.Constructed {
		return fmt.Errorf("decoding DsdArgExt: %w: expected tag [PRIVATE 0], got %s", ber.ErrInvalidTag, decodedTag)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "DsdArgExt", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode alsLineIndicator
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
				decodedTag_alslineindicator, n_alslineindicator, rawVal_alslineindicator, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding alsLineIndicator: %w", err)
				}
				if decodedTag_alslineindicator.Class != tag.ClassContextSpecific || decodedTag_alslineindicator.Number != 0 || decodedTag_alslineindicator.Constructed != false {
					return fmt.Errorf("decoding alsLineIndicator: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_alslineindicator)
				}
				if len(rawVal_alslineindicator) != 0 {
					return fmt.Errorf("decoding alsLineIndicator: %w: NULL content length %d", ber.ErrInvalidValue, len(rawVal_alslineindicator))
				}
				v.AlsLineIndicator = &struct{}{}
				if offset < 0 || offset >
					len(content) || n_alslineindicator < 0 || n_alslineindicator >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_alslineindicator
			}
		}
	}
	// Decode serviceList
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
				decodedTag_servicelist, n_servicelist, rawVal_servicelist, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding serviceList: %w", err)
				}
				if decodedTag_servicelist.Class != tag.ClassContextSpecific || decodedTag_servicelist.Number != 1 {
					return fmt.Errorf("decoding serviceList: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_servicelist)
				}
				decVal_servicelist, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_servicelist.Constructed, rawVal_servicelist, opts...)
				if octetErr != nil {
					return fmt.Errorf("decoding serviceList: %w", octetErr)
				}
				tmp_servicelist := MAPserviceList(decVal_servicelist)
				v.ServiceList = &tmp_servicelist
				if offset < 0 || offset >
					len(content) || n_servicelist < 0 || n_servicelist >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_servicelist
				if len(*v.ServiceList) > 256 {
					if constraintErr := ber.CheckDecodedLength(opts, "serviceList", "SIZE (0..256)", len(*v.ServiceList)); constraintErr != nil {
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
			return &ber.DecodeError{Offset: offset, TypeName: "DsdArgExt", Cause: extErr_}
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

// MarshalBER encodes UlResExt to BER format.
func (v *UlResExt) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: UlResExt receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *UlResExt) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if v.MwdSet != nil {
		enc_mwdset := ber.EncodeNull()
		retagged_enc_mwdset, tagErr_enc_mwdset := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_mwdset)
		if tagErr_enc_mwdset != nil {
			return nil, fmt.Errorf("encoding mwd-Set: %w", tagErr_enc_mwdset)
		}
		enc_mwdset = retagged_enc_mwdset
		children = append(children, enc_mwdset...)
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
	return ber.EncodeConstructed(tag.Tag{Class: tag.ClassPrivate, Number: 0, Constructed: true}, children)
}

// MarshalDER encodes UlResExt to DER format.
func (v *UlResExt) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: UlResExt receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if v.MwdSet != nil {
		enc_mwdset := ber.EncodeNull()
		retagged_enc_mwdset, tagErr_enc_mwdset := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_mwdset)
		if tagErr_enc_mwdset != nil {
			return nil, fmt.Errorf("encoding mwd-Set: %w", tagErr_enc_mwdset)
		}
		enc_mwdset = retagged_enc_mwdset
		children = append(children, enc_mwdset...)
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
	retagged_encoded, tagErr_encoded := ber.EncodeImplicitTagWithClass(tag.ClassPrivate, 0, encoded)
	if tagErr_encoded != nil {
		return nil, fmt.Errorf("encoding UlResExt: %w", tagErr_encoded)
	}
	encoded = retagged_encoded
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding UlResExt as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes UlResExt from BER/DER format.
func (v *UlResExt) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: UlResExt destination is nil", ber.ErrInvalidValue)
	}
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = UlResExt{}
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
	decodedTag, content, total, err := ber.DecodeConstructedContent(data, opts...)
	if err != nil {
		return fmt.Errorf("decoding UlResExt: %w", err)
	}
	if decodedTag.Class != tag.ClassPrivate || decodedTag.Number != 0 || !decodedTag.Constructed {
		return fmt.Errorf("decoding UlResExt: %w: expected tag [PRIVATE 0], got %s", ber.ErrInvalidTag, decodedTag)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "UlResExt", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode mwd-Set
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
				decodedTag_mwdset, n_mwdset, rawVal_mwdset, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding mwd-Set: %w", err)
				}
				if decodedTag_mwdset.Class != tag.ClassContextSpecific || decodedTag_mwdset.Number != 0 || decodedTag_mwdset.Constructed != false {
					return fmt.Errorf("decoding mwd-Set: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_mwdset)
				}
				if len(rawVal_mwdset) != 0 {
					return fmt.Errorf("decoding mwd-Set: %w: NULL content length %d", ber.ErrInvalidValue, len(rawVal_mwdset))
				}
				v.MwdSet = &struct{}{}
				if offset < 0 || offset >
					len(content) || n_mwdset < 0 || n_mwdset > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_mwdset
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:], opts...)
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "UlResExt", Cause: extErr_}
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

// MarshalBER encodes SSDataEmoInExt to BER format.
func (v *SSDataEmoInExt) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: SSDataEmoInExt receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *SSDataEmoInExt) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if v.EmoInCategoryKey != nil {
		if len(*v.EmoInCategoryKey) < 1 || len(*v.EmoInCategoryKey) > 3 {
			if constraintErr := ber.CheckEncodedLength(opts, "emoInCategoryKey", "SIZE (1..3)", len(*v.EmoInCategoryKey)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_emoincategorykey, encodeErr_enc_emoincategorykey := ber.EncodeOctetString([]byte(*v.EmoInCategoryKey))
		if encodeErr_enc_emoincategorykey != nil {
			return nil, fmt.Errorf("encoding emoInCategoryKey: %w", encodeErr_enc_emoincategorykey)
		}
		retagged_enc_emoincategorykey, tagErr_enc_emoincategorykey := ber.EncodeImplicitTagWithClass(tag.ClassPrivate, 2, enc_emoincategorykey)
		if tagErr_enc_emoincategorykey != nil {
			return nil, fmt.Errorf("encoding emoInCategoryKey: %w", tagErr_enc_emoincategorykey)
		}
		enc_emoincategorykey = retagged_enc_emoincategorykey
		children = append(children, enc_emoincategorykey...)
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
	return ber.EncodeConstructed(tag.Tag{Class: tag.ClassPrivate, Number: 1, Constructed: true}, children)
}

// MarshalDER encodes SSDataEmoInExt to DER format.
func (v *SSDataEmoInExt) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: SSDataEmoInExt receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if v.EmoInCategoryKey != nil {
		if len(*v.EmoInCategoryKey) < 1 || len(*v.EmoInCategoryKey) > 3 {
			if constraintErr := ber.CheckEncodedLength(nil, "emoInCategoryKey", "SIZE (1..3)", len(*v.EmoInCategoryKey)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_emoincategorykey, encodeErr_enc_emoincategorykey := ber.EncodeOctetString([]byte(*v.EmoInCategoryKey))
		if encodeErr_enc_emoincategorykey != nil {
			return nil, fmt.Errorf("encoding emoInCategoryKey: %w", encodeErr_enc_emoincategorykey)
		}
		retagged_enc_emoincategorykey, tagErr_enc_emoincategorykey := ber.EncodeImplicitTagWithClass(tag.ClassPrivate, 2, enc_emoincategorykey)
		if tagErr_enc_emoincategorykey != nil {
			return nil, fmt.Errorf("encoding emoInCategoryKey: %w", tagErr_enc_emoincategorykey)
		}
		enc_emoincategorykey = retagged_enc_emoincategorykey
		children = append(children, enc_emoincategorykey...)
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
	retagged_encoded, tagErr_encoded := ber.EncodeImplicitTagWithClass(tag.ClassPrivate, 1, encoded)
	if tagErr_encoded != nil {
		return nil, fmt.Errorf("encoding SSDataEmoInExt: %w", tagErr_encoded)
	}
	encoded = retagged_encoded
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding SSDataEmoInExt as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes SSDataEmoInExt from BER/DER format.
func (v *SSDataEmoInExt) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: SSDataEmoInExt destination is nil", ber.ErrInvalidValue)
	}
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = SSDataEmoInExt{}
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
	decodedTag, content, total, err := ber.DecodeConstructedContent(data, opts...)
	if err != nil {
		return fmt.Errorf("decoding SSDataEmoInExt: %w", err)
	}
	if decodedTag.Class != tag.ClassPrivate || decodedTag.Number != 1 || !decodedTag.Constructed {
		return fmt.Errorf("decoding SSDataEmoInExt: %w: expected tag [PRIVATE 1], got %s", ber.ErrInvalidTag, decodedTag)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "SSDataEmoInExt", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode emoInCategoryKey
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassPrivate && peekTag.Number == 2 {
				decodedTag_emoincategorykey, n_emoincategorykey, rawVal_emoincategorykey, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding emoInCategoryKey: %w", err)
				}
				if decodedTag_emoincategorykey.Class != tag.ClassPrivate || decodedTag_emoincategorykey.Number != 2 {
					return fmt.Errorf("decoding emoInCategoryKey: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_emoincategorykey)
				}
				decVal_emoincategorykey, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_emoincategorykey.Constructed, rawVal_emoincategorykey, opts...)
				if octetErr != nil {
					return fmt.Errorf("decoding emoInCategoryKey: %w", octetErr)
				}
				tmp_emoincategorykey := EmoInCategoryKey(decVal_emoincategorykey)
				v.EmoInCategoryKey = &tmp_emoincategorykey
				if offset < 0 || offset >
					len(content) || n_emoincategorykey < 0 || n_emoincategorykey >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_emoincategorykey
				if len(*v.EmoInCategoryKey) < 1 || len(*v.EmoInCategoryKey) > 3 {
					if constraintErr := ber.CheckDecodedLength(opts, "emoInCategoryKey", "SIZE (1..3)", len(*v.EmoInCategoryKey)); constraintErr != nil {
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
			return &ber.DecodeError{Offset: offset, TypeName: "SSDataEmoInExt", Cause: extErr_}
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

// MarshalBERChargingAreaList encodes a ChargingAreaList list to BER.
func MarshalBERChargingAreaList(collection *ChargingAreaList, opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	if collection == nil {
		return nil, fmt.Errorf("%w: required collection is nil", ber.ErrInvalidValue)
	}
	encoded, err := marshalBERChargingAreaList(collection, opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, collection.berOriginal_, collection.berSnapshot_, opts), nil
}
func marshalBERChargingAreaList(collection *ChargingAreaList, opts ...ber.EncodeOption) ([]byte, error) {
	list := collection.Values
	if len(list) < 1 || len(list) > 3 {
		if constraintErr := ber.CheckEncodedLength(opts, "ChargingAreaList", "SIZE (1..3)", len(list)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	var children []byte
	for elemIndex, elem := range list {
		if !(elem >= 1 && elem <= 9999) {
			if constraintErr := ber.CheckEncodedValue(opts, fmt.Sprintf("element[%d]", elemIndex), "(1..9999)", fmt.Sprint(elem)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		children = append(children, ber.EncodeInteger(int64(elem))...)
	}
	return ber.EncodeSequence(children)
}

// MarshalDERChargingAreaList encodes a ChargingAreaList list to DER.
func MarshalDERChargingAreaList(collection *ChargingAreaList) ([]byte, error) {
	if collection == nil {
		return nil, fmt.Errorf("%w: required collection is nil", ber.ErrInvalidValue)
	}
	list := collection.Values
	if len(list) < 1 || len(list) > 3 {
		if constraintErr := ber.CheckEncodedLength(nil, "ChargingAreaList", "SIZE (1..3)", len(list)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	var children []byte
	for elemIndex, elem := range list {
		if !(elem >= 1 && elem <= 9999) {
			if constraintErr := ber.CheckEncodedValue(nil, fmt.Sprintf("element[%d]", elemIndex), "(1..9999)", fmt.Sprint(elem)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		children = append(children, ber.EncodeInteger(int64(elem))...)
	}
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding ChargingAreaList as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBERChargingAreaList decodes a ChargingAreaList list from BER.
func UnmarshalBERChargingAreaList(data []byte, opts ...ber.DecodeOption) (returnValue *ChargingAreaList, returnErr error) {
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return nil, err
	}
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return nil, fmt.Errorf("decoding ChargingAreaList: %w", err)
	}
	if total != len(data) {
		return nil, &ber.DecodeError{Offset: total, TypeName: "ChargingAreaList", Cause: ber.ErrExtraData}
	}
	var result []ChargingArea
	offset := 0
	for offset < len(content) {
		elementData := content[offset:]
		val, n, intErr := ber.DecodeInteger(elementData, opts...)
		if intErr != nil {
			return nil, fmt.Errorf("decoding element: %w", intErr)
		}
		if !(val >= 1 && val <= 9999) {
			if constraintErr := ber.CheckDecodedValue(opts, fmt.Sprintf("element[%d]", len(result)), "(1..9999)", fmt.Sprint(val)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		result = append(result, ChargingArea(val))
		if offset < 0 || offset >
			len(content) || n < 0 || n > len(content[offset:]) {
			return nil, fmt.Errorf("invalid BER content window")
		}

		offset += n
	}
	if len(result) < 1 || len(result) > 3 {
		if constraintErr := ber.CheckDecodedLength(opts, "ChargingAreaList", "SIZE (1..3)", len(result)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	decoded := &ChargingAreaList{Values: result}
	if ber.BERNeedsPreservation(opts) {
		var snapshotReports ber.ViolationLog
		snapshot, snapshotErr := MarshalBERChargingAreaList(decoded, ber.WithConstraintTolerance(&snapshotReports))
		if snapshotErr != nil {
			return nil, snapshotErr
		}
		decoded.berOriginal_ = append([]byte(nil), data...)
		decoded.berSnapshot_ = snapshot
	}
	return decoded, nil
}

// MarshalBER encodes RegionalChargingData to BER format.
func (v *RegionalChargingData) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: RegionalChargingData receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *RegionalChargingData) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if v.ChargingAreaList != nil {
		if len((v.ChargingAreaList).Values) < 1 || len((v.ChargingAreaList).Values) > 3 {
			if constraintErr := ber.CheckEncodedLength(opts, "chargingAreaList", "SIZE (1..3)", len((v.ChargingAreaList).Values)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_chargingarealist, err := MarshalBERChargingAreaList(v.ChargingAreaList, ber.ChildEncodeOptions(opts, "chargingAreaList")...)
		if err != nil {
			return nil, fmt.Errorf("encoding chargingAreaList: %w", err)
		}
		if v.ChargingAreaListIndef_ {
			// Strip the outer SEQUENCE tag from marshalBER output to get raw children.
			_, _, seqContent_, tlvErr_ := ber.DecodeEncodedTLV(enc_chargingarealist)
			if tlvErr_ != nil {
				return nil, tlvErr_
			}
			{
				var encodeErr error
				enc_chargingarealist, encodeErr = ber.EncodeConstructedIndefinite(tag.Tag{Class: tag.ClassContextSpecific, Number: 0}, seqContent_)
				if encodeErr != nil {
					return nil, fmt.Errorf("encoding chargingAreaList: %w", encodeErr)
				}
			}
		} else {
			retagged_enc_chargingarealist, tagErr_enc_chargingarealist := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_chargingarealist)
			if tagErr_enc_chargingarealist != nil {
				return nil, fmt.Errorf("encoding chargingAreaList: %w", tagErr_enc_chargingarealist)
			}
			enc_chargingarealist = retagged_enc_chargingarealist
		}
		children = append(children, enc_chargingarealist...)
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

// MarshalDER encodes RegionalChargingData to DER format.
func (v *RegionalChargingData) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: RegionalChargingData receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if v.ChargingAreaList != nil {
		if len((v.ChargingAreaList).Values) < 1 || len((v.ChargingAreaList).Values) > 3 {
			if constraintErr := ber.CheckEncodedLength(nil, "chargingAreaList", "SIZE (1..3)", len((v.ChargingAreaList).Values)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_chargingarealist, err := MarshalDERChargingAreaList(v.ChargingAreaList)
		if err != nil {
			return nil, fmt.Errorf("encoding chargingAreaList: %w", err)
		}
		retagged_enc_chargingarealist, tagErr_enc_chargingarealist := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_chargingarealist)
		if tagErr_enc_chargingarealist != nil {
			return nil, fmt.Errorf("encoding chargingAreaList: %w", tagErr_enc_chargingarealist)
		}
		enc_chargingarealist = retagged_enc_chargingarealist
		children = append(children, enc_chargingarealist...)
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
		return nil, fmt.Errorf("encoding RegionalChargingData as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes RegionalChargingData from BER/DER format.
func (v *RegionalChargingData) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: RegionalChargingData destination is nil", ber.ErrInvalidValue)
	}
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = RegionalChargingData{}
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
		return fmt.Errorf("decoding RegionalChargingData SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "RegionalChargingData", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode chargingAreaList
	v.ChargingAreaListIndef_ = false
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
				decodedTag_chargingarealist, n_chargingarealist, rawVal_chargingarealist, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding chargingAreaList: %w", err)
				}
				if decodedTag_chargingarealist.Class != tag.ClassContextSpecific || decodedTag_chargingarealist.Number != 0 || decodedTag_chargingarealist.Constructed != true {
					return fmt.Errorf("decoding chargingAreaList: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_chargingarealist)
				}
				reconstructed_chargingarealist, reconstructionErr_chargingarealist := ber.EncodeSequence(rawVal_chargingarealist)
				if reconstructionErr_chargingarealist != nil {
					return fmt.Errorf("decoding chargingAreaList: %w", reconstructionErr_chargingarealist)
				}
				dec_chargingarealist, unmErr := UnmarshalBERChargingAreaList(reconstructed_chargingarealist, ber.ChildDecodeOptions(opts, "chargingAreaList")...)
				if unmErr != nil {
					return fmt.Errorf("decoding chargingAreaList: %w", unmErr)
				}
				v.ChargingAreaList = dec_chargingarealist
				{
					_, tagSz_, _ := ber.DecodeTag(content[offset:])
					if offset < 0 || offset >
						len(content) || tagSz_ < 0 || tagSz_ > len(content[offset:]) {
						return fmt.Errorf("invalid BER content window")
					}

					if offset+tagSz_ < len(content) && content[offset+tagSz_] == 0x80 {
						v.ChargingAreaListIndef_ = true
					}
				}
				if offset < 0 || offset >
					len(content) || n_chargingarealist < 0 || n_chargingarealist >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_chargingarealist
				if len((v.ChargingAreaList).Values) < 1 || len((v.ChargingAreaList).Values) > 3 {
					if constraintErr := ber.CheckDecodedLength(opts, "chargingAreaList", "SIZE (1..3)", len((v.ChargingAreaList).Values)); constraintErr != nil {
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
			return &ber.DecodeError{Offset: offset, TypeName: "RegionalChargingData", Cause: extErr_}
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

// MarshalBER encodes SSDataExtension to BER format.
func (v *SSDataExtension) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: SSDataExtension receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *SSDataExtension) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if v.InTriggerKey != nil {
		if !(int64(*v.InTriggerKey) >= 1 && int64(*v.InTriggerKey) <= 65535) {
			if constraintErr := ber.CheckEncodedValue(opts, "inTriggerKey", "(1..65535)", fmt.Sprint(int64(*v.InTriggerKey))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_intriggerkey := ber.EncodeInteger(int64(*v.InTriggerKey))
		retagged_enc_intriggerkey, tagErr_enc_intriggerkey := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_intriggerkey)
		if tagErr_enc_intriggerkey != nil {
			return nil, fmt.Errorf("encoding inTriggerKey: %w", tagErr_enc_intriggerkey)
		}
		enc_intriggerkey = retagged_enc_intriggerkey
		children = append(children, enc_intriggerkey...)
	}
	if v.PnpIndex != nil {
		if len(*v.PnpIndex) < 3 || len(*v.PnpIndex) > 3 {
			if constraintErr := ber.CheckEncodedLength(opts, "pnpIndex", "SIZE (3)", len(*v.PnpIndex)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_pnpindex, encodeErr_enc_pnpindex := ber.EncodeOctetString([]byte(*v.PnpIndex))
		if encodeErr_enc_pnpindex != nil {
			return nil, fmt.Errorf("encoding pnpIndex: %w", encodeErr_enc_pnpindex)
		}
		retagged_enc_pnpindex, tagErr_enc_pnpindex := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_pnpindex)
		if tagErr_enc_pnpindex != nil {
			return nil, fmt.Errorf("encoding pnpIndex: %w", tagErr_enc_pnpindex)
		}
		enc_pnpindex = retagged_enc_pnpindex
		children = append(children, enc_pnpindex...)
	}
	if v.CallRedirectionIndex != nil {
		if !(int64(*v.CallRedirectionIndex) >= 0 && int64(*v.CallRedirectionIndex) <= 255) {
			if constraintErr := ber.CheckEncodedValue(opts, "callRedirectionIndex", "(0..255)", fmt.Sprint(int64(*v.CallRedirectionIndex))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_callredirectionindex := ber.EncodeInteger(int64(*v.CallRedirectionIndex))
		retagged_enc_callredirectionindex, tagErr_enc_callredirectionindex := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_callredirectionindex)
		if tagErr_enc_callredirectionindex != nil {
			return nil, fmt.Errorf("encoding callRedirectionIndex: %w", tagErr_enc_callredirectionindex)
		}
		enc_callredirectionindex = retagged_enc_callredirectionindex
		children = append(children, enc_callredirectionindex...)
	}
	if v.RegionalChargingData != nil {
		enc_regionalchargingdata, err := v.RegionalChargingData.MarshalBER(ber.ChildEncodeOptions(opts, "regionalChargingData")...)
		if err != nil {
			return nil, fmt.Errorf("encoding regionalChargingData: %w", err)
		}
		retagged_enc_regionalchargingdata, tagErr_enc_regionalchargingdata := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, enc_regionalchargingdata)
		if tagErr_enc_regionalchargingdata != nil {
			return nil, fmt.Errorf("encoding regionalChargingData: %w", tagErr_enc_regionalchargingdata)
		}
		enc_regionalchargingdata = retagged_enc_regionalchargingdata
		children = append(children, enc_regionalchargingdata...)
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
	return ber.EncodeConstructed(tag.Tag{Class: tag.ClassPrivate, Number: 0, Constructed: true}, children)
}

// MarshalDER encodes SSDataExtension to DER format.
func (v *SSDataExtension) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: SSDataExtension receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if v.InTriggerKey != nil {
		if !(int64(*v.InTriggerKey) >= 1 && int64(*v.InTriggerKey) <= 65535) {
			if constraintErr := ber.CheckEncodedValue(nil, "inTriggerKey", "(1..65535)", fmt.Sprint(int64(*v.InTriggerKey))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_intriggerkey := ber.EncodeInteger(int64(*v.InTriggerKey))
		retagged_enc_intriggerkey, tagErr_enc_intriggerkey := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_intriggerkey)
		if tagErr_enc_intriggerkey != nil {
			return nil, fmt.Errorf("encoding inTriggerKey: %w", tagErr_enc_intriggerkey)
		}
		enc_intriggerkey = retagged_enc_intriggerkey
		children = append(children, enc_intriggerkey...)
	}
	if v.PnpIndex != nil {
		if len(*v.PnpIndex) < 3 || len(*v.PnpIndex) > 3 {
			if constraintErr := ber.CheckEncodedLength(nil, "pnpIndex", "SIZE (3)", len(*v.PnpIndex)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_pnpindex, encodeErr_enc_pnpindex := ber.EncodeOctetString([]byte(*v.PnpIndex))
		if encodeErr_enc_pnpindex != nil {
			return nil, fmt.Errorf("encoding pnpIndex: %w", encodeErr_enc_pnpindex)
		}
		retagged_enc_pnpindex, tagErr_enc_pnpindex := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_pnpindex)
		if tagErr_enc_pnpindex != nil {
			return nil, fmt.Errorf("encoding pnpIndex: %w", tagErr_enc_pnpindex)
		}
		enc_pnpindex = retagged_enc_pnpindex
		children = append(children, enc_pnpindex...)
	}
	if v.CallRedirectionIndex != nil {
		if !(int64(*v.CallRedirectionIndex) >= 0 && int64(*v.CallRedirectionIndex) <= 255) {
			if constraintErr := ber.CheckEncodedValue(nil, "callRedirectionIndex", "(0..255)", fmt.Sprint(int64(*v.CallRedirectionIndex))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_callredirectionindex := ber.EncodeInteger(int64(*v.CallRedirectionIndex))
		retagged_enc_callredirectionindex, tagErr_enc_callredirectionindex := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_callredirectionindex)
		if tagErr_enc_callredirectionindex != nil {
			return nil, fmt.Errorf("encoding callRedirectionIndex: %w", tagErr_enc_callredirectionindex)
		}
		enc_callredirectionindex = retagged_enc_callredirectionindex
		children = append(children, enc_callredirectionindex...)
	}
	if v.RegionalChargingData != nil {
		enc_regionalchargingdata, err := v.RegionalChargingData.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding regionalChargingData: %w", err)
		}
		retagged_enc_regionalchargingdata, tagErr_enc_regionalchargingdata := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, enc_regionalchargingdata)
		if tagErr_enc_regionalchargingdata != nil {
			return nil, fmt.Errorf("encoding regionalChargingData: %w", tagErr_enc_regionalchargingdata)
		}
		enc_regionalchargingdata = retagged_enc_regionalchargingdata
		children = append(children, enc_regionalchargingdata...)
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
	retagged_encoded, tagErr_encoded := ber.EncodeImplicitTagWithClass(tag.ClassPrivate, 0, encoded)
	if tagErr_encoded != nil {
		return nil, fmt.Errorf("encoding SSDataExtension: %w", tagErr_encoded)
	}
	encoded = retagged_encoded
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding SSDataExtension as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes SSDataExtension from BER/DER format.
func (v *SSDataExtension) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: SSDataExtension destination is nil", ber.ErrInvalidValue)
	}
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = SSDataExtension{}
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
	decodedTag, content, total, err := ber.DecodeConstructedContent(data, opts...)
	if err != nil {
		return fmt.Errorf("decoding SSDataExtension: %w", err)
	}
	if decodedTag.Class != tag.ClassPrivate || decodedTag.Number != 0 || !decodedTag.Constructed {
		return fmt.Errorf("decoding SSDataExtension: %w: expected tag [PRIVATE 0], got %s", ber.ErrInvalidTag, decodedTag)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "SSDataExtension", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode inTriggerKey
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
				decodedTag_intriggerkey, n_intriggerkey, rawVal_intriggerkey, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding inTriggerKey: %w", err)
				}
				if decodedTag_intriggerkey.Class != tag.ClassContextSpecific || decodedTag_intriggerkey.Number != 0 || decodedTag_intriggerkey.Constructed != false {
					return fmt.Errorf("decoding inTriggerKey: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_intriggerkey)
				}
				decVal_intriggerkey, intErr := ber.DecodeIntegerValue(rawVal_intriggerkey)
				if intErr != nil {
					return fmt.Errorf("decoding inTriggerKey: %w", intErr)
				}
				tmp_intriggerkey := InTriggerKey(decVal_intriggerkey)
				v.InTriggerKey = &tmp_intriggerkey
				if offset < 0 || offset >
					len(content) || n_intriggerkey < 0 || n_intriggerkey > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_intriggerkey
				if !(int64(*v.InTriggerKey) >= 1 && int64(*v.InTriggerKey) <= 65535) {
					if constraintErr := ber.CheckDecodedValue(opts, "inTriggerKey", "(1..65535)", fmt.Sprint(int64(*v.InTriggerKey))); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode pnpIndex
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
				decodedTag_pnpindex, n_pnpindex, rawVal_pnpindex, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding pnpIndex: %w", err)
				}
				if decodedTag_pnpindex.Class != tag.ClassContextSpecific || decodedTag_pnpindex.Number != 1 {
					return fmt.Errorf("decoding pnpIndex: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_pnpindex)
				}
				decVal_pnpindex, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_pnpindex.Constructed, rawVal_pnpindex, opts...)
				if octetErr != nil {
					return fmt.Errorf("decoding pnpIndex: %w", octetErr)
				}
				tmp_pnpindex := PnpIndex(decVal_pnpindex)
				v.PnpIndex = &tmp_pnpindex
				if offset < 0 || offset >
					len(content) || n_pnpindex < 0 || n_pnpindex > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_pnpindex
				if len(*v.PnpIndex) < 3 || len(*v.PnpIndex) > 3 {
					if constraintErr := ber.CheckDecodedLength(opts, "pnpIndex", "SIZE (3)", len(*v.PnpIndex)); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode callRedirectionIndex
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2 {
				decodedTag_callredirectionindex, n_callredirectionindex, rawVal_callredirectionindex, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding callRedirectionIndex: %w", err)
				}
				if decodedTag_callredirectionindex.Class != tag.ClassContextSpecific || decodedTag_callredirectionindex.Number != 2 || decodedTag_callredirectionindex.Constructed != false {
					return fmt.Errorf("decoding callRedirectionIndex: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_callredirectionindex)
				}
				decVal_callredirectionindex, intErr := ber.DecodeIntegerValue(rawVal_callredirectionindex)
				if intErr != nil {
					return fmt.Errorf("decoding callRedirectionIndex: %w", intErr)
				}
				tmp_callredirectionindex := CallRedirectionIndex(decVal_callredirectionindex)
				v.CallRedirectionIndex = &tmp_callredirectionindex
				if offset < 0 || offset >
					len(content) || n_callredirectionindex < 0 || n_callredirectionindex >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_callredirectionindex
				if !(int64(*v.CallRedirectionIndex) >= 0 && int64(*v.CallRedirectionIndex) <= 255) {
					if constraintErr := ber.CheckDecodedValue(opts, "callRedirectionIndex", "(0..255)", fmt.Sprint(int64(*v.CallRedirectionIndex))); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode regionalChargingData
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3 {
				decodedTag_regionalchargingdata, n_regionalchargingdata, rawVal_regionalchargingdata, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding regionalChargingData: %w", err)
				}
				if decodedTag_regionalchargingdata.Class != tag.ClassContextSpecific || decodedTag_regionalchargingdata.Number != 3 || decodedTag_regionalchargingdata.Constructed != true {
					return fmt.Errorf("decoding regionalChargingData: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_regionalchargingdata)
				}
				reconstructed_regionalchargingdata, reconstructionErr_regionalchargingdata := ber.EncodeSequence(rawVal_regionalchargingdata)
				if reconstructionErr_regionalchargingdata != nil {
					return fmt.Errorf("decoding regionalChargingData: %w", reconstructionErr_regionalchargingdata)
				}
				var dec_regionalchargingdata RegionalChargingData
				if unmErr := dec_regionalchargingdata.UnmarshalBER(reconstructed_regionalchargingdata, ber.ChildDecodeOptions(opts, "regionalChargingData")...); unmErr != nil {
					return fmt.Errorf("decoding regionalChargingData: %w", unmErr)
				}
				v.RegionalChargingData = &dec_regionalchargingdata
				if offset < 0 || offset >
					len(content) || n_regionalchargingdata < 0 || n_regionalchargingdata >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_regionalchargingdata
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:], opts...)
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "SSDataExtension", Cause: extErr_}
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

// MarshalBER encodes SriExtension to BER format.
func (v *SriExtension) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: SriExtension receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *SriExtension) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if v.CallForwardingOverride != nil {
		enc_callforwardingoverride := ber.EncodeNull()
		retagged_enc_callforwardingoverride, tagErr_enc_callforwardingoverride := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_callforwardingoverride)
		if tagErr_enc_callforwardingoverride != nil {
			return nil, fmt.Errorf("encoding callForwardingOverride: %w", tagErr_enc_callforwardingoverride)
		}
		enc_callforwardingoverride = retagged_enc_callforwardingoverride
		children = append(children, enc_callforwardingoverride...)
	}
	if v.InCapability != nil {
		enc_incapability := ber.EncodeNull()
		retagged_enc_incapability, tagErr_enc_incapability := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_incapability)
		if tagErr_enc_incapability != nil {
			return nil, fmt.Errorf("encoding in-Capability: %w", tagErr_enc_incapability)
		}
		enc_incapability = retagged_enc_incapability
		children = append(children, enc_incapability...)
	}
	if v.CallingCategory != nil {
		if len(*v.CallingCategory) < 1 || len(*v.CallingCategory) > 1 {
			if constraintErr := ber.CheckEncodedLength(opts, "callingCategory", "SIZE (1)", len(*v.CallingCategory)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_callingcategory, encodeErr_enc_callingcategory := ber.EncodeOctetString([]byte(*v.CallingCategory))
		if encodeErr_enc_callingcategory != nil {
			return nil, fmt.Errorf("encoding callingCategory: %w", encodeErr_enc_callingcategory)
		}
		retagged_enc_callingcategory, tagErr_enc_callingcategory := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_callingcategory)
		if tagErr_enc_callingcategory != nil {
			return nil, fmt.Errorf("encoding callingCategory: %w", tagErr_enc_callingcategory)
		}
		enc_callingcategory = retagged_enc_callingcategory
		children = append(children, enc_callingcategory...)
	}
	if v.InternalServiceIndicator != nil {
		if len(*v.InternalServiceIndicator) < 1 || len(*v.InternalServiceIndicator) > 1 {
			if constraintErr := ber.CheckEncodedLength(opts, "internalServiceIndicator", "SIZE (1)", len(*v.InternalServiceIndicator)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_internalserviceindicator, encodeErr_enc_internalserviceindicator := ber.EncodeOctetString([]byte(*v.InternalServiceIndicator))
		if encodeErr_enc_internalserviceindicator != nil {
			return nil, fmt.Errorf("encoding internalServiceIndicator: %w", encodeErr_enc_internalserviceindicator)
		}
		retagged_enc_internalserviceindicator, tagErr_enc_internalserviceindicator := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, enc_internalserviceindicator)
		if tagErr_enc_internalserviceindicator != nil {
			return nil, fmt.Errorf("encoding internalServiceIndicator: %w", tagErr_enc_internalserviceindicator)
		}
		enc_internalserviceindicator = retagged_enc_internalserviceindicator
		children = append(children, enc_internalserviceindicator...)
	}
	if v.SrbtSupportIndicator != nil {
		enc_srbtsupportindicator := ber.EncodeNull()
		retagged_enc_srbtsupportindicator, tagErr_enc_srbtsupportindicator := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, enc_srbtsupportindicator)
		if tagErr_enc_srbtsupportindicator != nil {
			return nil, fmt.Errorf("encoding srbtSupportIndicator: %w", tagErr_enc_srbtsupportindicator)
		}
		enc_srbtsupportindicator = retagged_enc_srbtsupportindicator
		children = append(children, enc_srbtsupportindicator...)
	}
	if v.GmscSupportIndicator != nil {
		enc_gmscsupportindicator := ber.EncodeNull()
		retagged_enc_gmscsupportindicator, tagErr_enc_gmscsupportindicator := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 5, enc_gmscsupportindicator)
		if tagErr_enc_gmscsupportindicator != nil {
			return nil, fmt.Errorf("encoding gmscSupportIndicator: %w", tagErr_enc_gmscsupportindicator)
		}
		enc_gmscsupportindicator = retagged_enc_gmscsupportindicator
		children = append(children, enc_gmscsupportindicator...)
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
	return ber.EncodeConstructed(tag.Tag{Class: tag.ClassPrivate, Number: 0, Constructed: true}, children)
}

// MarshalDER encodes SriExtension to DER format.
func (v *SriExtension) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: SriExtension receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if v.CallForwardingOverride != nil {
		enc_callforwardingoverride := ber.EncodeNull()
		retagged_enc_callforwardingoverride, tagErr_enc_callforwardingoverride := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_callforwardingoverride)
		if tagErr_enc_callforwardingoverride != nil {
			return nil, fmt.Errorf("encoding callForwardingOverride: %w", tagErr_enc_callforwardingoverride)
		}
		enc_callforwardingoverride = retagged_enc_callforwardingoverride
		children = append(children, enc_callforwardingoverride...)
	}
	if v.InCapability != nil {
		enc_incapability := ber.EncodeNull()
		retagged_enc_incapability, tagErr_enc_incapability := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_incapability)
		if tagErr_enc_incapability != nil {
			return nil, fmt.Errorf("encoding in-Capability: %w", tagErr_enc_incapability)
		}
		enc_incapability = retagged_enc_incapability
		children = append(children, enc_incapability...)
	}
	if v.CallingCategory != nil {
		if len(*v.CallingCategory) < 1 || len(*v.CallingCategory) > 1 {
			if constraintErr := ber.CheckEncodedLength(nil, "callingCategory", "SIZE (1)", len(*v.CallingCategory)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_callingcategory, encodeErr_enc_callingcategory := ber.EncodeOctetString([]byte(*v.CallingCategory))
		if encodeErr_enc_callingcategory != nil {
			return nil, fmt.Errorf("encoding callingCategory: %w", encodeErr_enc_callingcategory)
		}
		retagged_enc_callingcategory, tagErr_enc_callingcategory := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_callingcategory)
		if tagErr_enc_callingcategory != nil {
			return nil, fmt.Errorf("encoding callingCategory: %w", tagErr_enc_callingcategory)
		}
		enc_callingcategory = retagged_enc_callingcategory
		children = append(children, enc_callingcategory...)
	}
	if v.InternalServiceIndicator != nil {
		if len(*v.InternalServiceIndicator) < 1 || len(*v.InternalServiceIndicator) > 1 {
			if constraintErr := ber.CheckEncodedLength(nil, "internalServiceIndicator", "SIZE (1)", len(*v.InternalServiceIndicator)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_internalserviceindicator, encodeErr_enc_internalserviceindicator := ber.EncodeOctetString([]byte(*v.InternalServiceIndicator))
		if encodeErr_enc_internalserviceindicator != nil {
			return nil, fmt.Errorf("encoding internalServiceIndicator: %w", encodeErr_enc_internalserviceindicator)
		}
		retagged_enc_internalserviceindicator, tagErr_enc_internalserviceindicator := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, enc_internalserviceindicator)
		if tagErr_enc_internalserviceindicator != nil {
			return nil, fmt.Errorf("encoding internalServiceIndicator: %w", tagErr_enc_internalserviceindicator)
		}
		enc_internalserviceindicator = retagged_enc_internalserviceindicator
		children = append(children, enc_internalserviceindicator...)
	}
	if v.SrbtSupportIndicator != nil {
		enc_srbtsupportindicator := ber.EncodeNull()
		retagged_enc_srbtsupportindicator, tagErr_enc_srbtsupportindicator := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, enc_srbtsupportindicator)
		if tagErr_enc_srbtsupportindicator != nil {
			return nil, fmt.Errorf("encoding srbtSupportIndicator: %w", tagErr_enc_srbtsupportindicator)
		}
		enc_srbtsupportindicator = retagged_enc_srbtsupportindicator
		children = append(children, enc_srbtsupportindicator...)
	}
	if v.GmscSupportIndicator != nil {
		enc_gmscsupportindicator := ber.EncodeNull()
		retagged_enc_gmscsupportindicator, tagErr_enc_gmscsupportindicator := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 5, enc_gmscsupportindicator)
		if tagErr_enc_gmscsupportindicator != nil {
			return nil, fmt.Errorf("encoding gmscSupportIndicator: %w", tagErr_enc_gmscsupportindicator)
		}
		enc_gmscsupportindicator = retagged_enc_gmscsupportindicator
		children = append(children, enc_gmscsupportindicator...)
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
	retagged_encoded, tagErr_encoded := ber.EncodeImplicitTagWithClass(tag.ClassPrivate, 0, encoded)
	if tagErr_encoded != nil {
		return nil, fmt.Errorf("encoding SriExtension: %w", tagErr_encoded)
	}
	encoded = retagged_encoded
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding SriExtension as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes SriExtension from BER/DER format.
func (v *SriExtension) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: SriExtension destination is nil", ber.ErrInvalidValue)
	}
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = SriExtension{}
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
	decodedTag, content, total, err := ber.DecodeConstructedContent(data, opts...)
	if err != nil {
		return fmt.Errorf("decoding SriExtension: %w", err)
	}
	if decodedTag.Class != tag.ClassPrivate || decodedTag.Number != 0 || !decodedTag.Constructed {
		return fmt.Errorf("decoding SriExtension: %w: expected tag [PRIVATE 0], got %s", ber.ErrInvalidTag, decodedTag)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "SriExtension", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode callForwardingOverride
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
				decodedTag_callforwardingoverride, n_callforwardingoverride, rawVal_callforwardingoverride, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding callForwardingOverride: %w", err)
				}
				if decodedTag_callforwardingoverride.Class != tag.ClassContextSpecific || decodedTag_callforwardingoverride.Number != 0 || decodedTag_callforwardingoverride.Constructed != false {
					return fmt.Errorf("decoding callForwardingOverride: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_callforwardingoverride)
				}
				if len(rawVal_callforwardingoverride) != 0 {
					return fmt.Errorf("decoding callForwardingOverride: %w: NULL content length %d", ber.ErrInvalidValue, len(rawVal_callforwardingoverride))
				}
				v.CallForwardingOverride = &struct{}{}
				if offset < 0 || offset >
					len(content) || n_callforwardingoverride < 0 || n_callforwardingoverride >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_callforwardingoverride
			}
		}
	}
	// Decode in-Capability
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
				decodedTag_incapability, n_incapability, rawVal_incapability, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding in-Capability: %w", err)
				}
				if decodedTag_incapability.Class != tag.ClassContextSpecific || decodedTag_incapability.Number != 1 || decodedTag_incapability.Constructed != false {
					return fmt.Errorf("decoding in-Capability: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_incapability)
				}
				if len(rawVal_incapability) != 0 {
					return fmt.Errorf("decoding in-Capability: %w: NULL content length %d", ber.ErrInvalidValue, len(rawVal_incapability))
				}
				v.InCapability = &struct{}{}
				if offset < 0 || offset >
					len(content) || n_incapability < 0 || n_incapability >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_incapability
			}
		}
	}
	// Decode callingCategory
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2 {
				decodedTag_callingcategory, n_callingcategory, rawVal_callingcategory, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding callingCategory: %w", err)
				}
				if decodedTag_callingcategory.Class != tag.ClassContextSpecific || decodedTag_callingcategory.Number != 2 {
					return fmt.Errorf("decoding callingCategory: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_callingcategory)
				}
				decVal_callingcategory, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_callingcategory.Constructed, rawVal_callingcategory, opts...)
				if octetErr != nil {
					return fmt.Errorf("decoding callingCategory: %w", octetErr)
				}
				tmp_callingcategory := CallingCategory(decVal_callingcategory)
				v.CallingCategory = &tmp_callingcategory
				if offset < 0 || offset >
					len(content) || n_callingcategory < 0 || n_callingcategory >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_callingcategory
				if len(*v.CallingCategory) < 1 || len(*v.CallingCategory) > 1 {
					if constraintErr := ber.CheckDecodedLength(opts, "callingCategory", "SIZE (1)", len(*v.CallingCategory)); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode internalServiceIndicator
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3 {
				decodedTag_internalserviceindicator, n_internalserviceindicator, rawVal_internalserviceindicator, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding internalServiceIndicator: %w", err)
				}
				if decodedTag_internalserviceindicator.Class != tag.ClassContextSpecific || decodedTag_internalserviceindicator.Number != 3 {
					return fmt.Errorf("decoding internalServiceIndicator: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_internalserviceindicator)
				}
				decVal_internalserviceindicator, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_internalserviceindicator.Constructed, rawVal_internalserviceindicator, opts...)
				if octetErr != nil {
					return fmt.Errorf("decoding internalServiceIndicator: %w", octetErr)
				}
				tmp_internalserviceindicator := InternalServiceIndicator(decVal_internalserviceindicator)
				v.InternalServiceIndicator = &tmp_internalserviceindicator
				if offset < 0 || offset >
					len(content) || n_internalserviceindicator < 0 || n_internalserviceindicator >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_internalserviceindicator
				if len(*v.InternalServiceIndicator) < 1 || len(*v.InternalServiceIndicator) > 1 {
					if constraintErr := ber.CheckDecodedLength(opts, "internalServiceIndicator", "SIZE (1)", len(*v.InternalServiceIndicator)); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode srbtSupportIndicator
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4 {
				decodedTag_srbtsupportindicator, n_srbtsupportindicator, rawVal_srbtsupportindicator, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding srbtSupportIndicator: %w", err)
				}
				if decodedTag_srbtsupportindicator.Class != tag.ClassContextSpecific || decodedTag_srbtsupportindicator.Number != 4 || decodedTag_srbtsupportindicator.Constructed != false {
					return fmt.Errorf("decoding srbtSupportIndicator: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_srbtsupportindicator)
				}
				if len(rawVal_srbtsupportindicator) != 0 {
					return fmt.Errorf("decoding srbtSupportIndicator: %w: NULL content length %d", ber.ErrInvalidValue, len(rawVal_srbtsupportindicator))
				}
				v.SrbtSupportIndicator = &struct{}{}
				if offset < 0 || offset >
					len(content) || n_srbtsupportindicator < 0 || n_srbtsupportindicator >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_srbtsupportindicator
			}
		}
	}
	// Decode gmscSupportIndicator
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 5 {
				decodedTag_gmscsupportindicator, n_gmscsupportindicator, rawVal_gmscsupportindicator, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding gmscSupportIndicator: %w", err)
				}
				if decodedTag_gmscsupportindicator.Class != tag.ClassContextSpecific || decodedTag_gmscsupportindicator.Number != 5 || decodedTag_gmscsupportindicator.Constructed != false {
					return fmt.Errorf("decoding gmscSupportIndicator: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_gmscsupportindicator)
				}
				if len(rawVal_gmscsupportindicator) != 0 {
					return fmt.Errorf("decoding gmscSupportIndicator: %w: NULL content length %d", ber.ErrInvalidValue, len(rawVal_gmscsupportindicator))
				}
				v.GmscSupportIndicator = &struct{}{}
				if offset < 0 || offset >
					len(content) || n_gmscsupportindicator < 0 || n_gmscsupportindicator >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_gmscsupportindicator
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:], opts...)
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "SriExtension", Cause: extErr_}
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

// MarshalBER encodes ExtensionsExtraSignalInfo to BER format.
func (v *ExtensionsExtraSignalInfo) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: ExtensionsExtraSignalInfo receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *ExtensionsExtraSignalInfo) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if !(int64(v.ProtocolId) >= 1 && int64(v.ProtocolId) <= 20) {
		if constraintErr := ber.CheckEncodedValue(opts, "protocolId", "(1..20)", fmt.Sprint(int64(v.ProtocolId))); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_protocolid := ber.EncodeInteger(int64(v.ProtocolId))
	children = append(children, enc_protocolid...)
	if len(v.SignalInfo) < 1 || len(v.SignalInfo) > 200 {
		if constraintErr := ber.CheckEncodedLength(opts, "signalInfo", "SIZE (1..200)", len(v.SignalInfo)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_signalinfo, encodeErr_enc_signalinfo := ber.EncodeOctetString([]byte(v.SignalInfo))
	if encodeErr_enc_signalinfo != nil {
		return nil, fmt.Errorf("encoding signalInfo: %w", encodeErr_enc_signalinfo)
	}
	children = append(children, enc_signalinfo...)
	return ber.EncodeConstructed(tag.Tag{Class: tag.ClassPrivate, Number: 1, Constructed: true}, children)
}

// MarshalDER encodes ExtensionsExtraSignalInfo to DER format.
func (v *ExtensionsExtraSignalInfo) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: ExtensionsExtraSignalInfo receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if !(int64(v.ProtocolId) >= 1 && int64(v.ProtocolId) <= 20) {
		if constraintErr := ber.CheckEncodedValue(nil, "protocolId", "(1..20)", fmt.Sprint(int64(v.ProtocolId))); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_protocolid := ber.EncodeInteger(int64(v.ProtocolId))
	children = append(children, enc_protocolid...)
	if len(v.SignalInfo) < 1 || len(v.SignalInfo) > 200 {
		if constraintErr := ber.CheckEncodedLength(nil, "signalInfo", "SIZE (1..200)", len(v.SignalInfo)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_signalinfo, encodeErr_enc_signalinfo := ber.EncodeOctetString([]byte(v.SignalInfo))
	if encodeErr_enc_signalinfo != nil {
		return nil, fmt.Errorf("encoding signalInfo: %w", encodeErr_enc_signalinfo)
	}
	children = append(children, enc_signalinfo...)
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	retagged_encoded, tagErr_encoded := ber.EncodeImplicitTagWithClass(tag.ClassPrivate, 1, encoded)
	if tagErr_encoded != nil {
		return nil, fmt.Errorf("encoding ExtensionsExtraSignalInfo: %w", tagErr_encoded)
	}
	encoded = retagged_encoded
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding ExtensionsExtraSignalInfo as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes ExtensionsExtraSignalInfo from BER/DER format.
func (v *ExtensionsExtraSignalInfo) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: ExtensionsExtraSignalInfo destination is nil", ber.ErrInvalidValue)
	}
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = ExtensionsExtraSignalInfo{}
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
	decodedTag, content, total, err := ber.DecodeConstructedContent(data, opts...)
	if err != nil {
		return fmt.Errorf("decoding ExtensionsExtraSignalInfo: %w", err)
	}
	if decodedTag.Class != tag.ClassPrivate || decodedTag.Number != 1 || !decodedTag.Constructed {
		return fmt.Errorf("decoding ExtensionsExtraSignalInfo: %w: expected tag [PRIVATE 1], got %s", ber.ErrInvalidTag, decodedTag)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "ExtensionsExtraSignalInfo", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode protocolId
	if offset >= len(content) {
		return fmt.Errorf("missing required field protocolId")
	}
	val_protocolid, n, err := ber.DecodeInteger(content[offset:], opts...)
	if err != nil {
		return fmt.Errorf("decoding protocolId: %w", err)
	}
	v.ProtocolId = ExtensionsExtraProtocolId(val_protocolid)
	if offset < 0 || offset >
		len(content) || n < 0 || n > len(content[offset:]) {
		return fmt.Errorf("invalid BER content window")
	}

	offset += n
	if !(int64(v.ProtocolId) >= 1 && int64(v.ProtocolId) <= 20) {
		if constraintErr := ber.CheckDecodedValue(opts, "protocolId", "(1..20)", fmt.Sprint(int64(v.ProtocolId))); constraintErr != nil {
			return constraintErr
		}
	}
	// Decode signalInfo
	if offset >= len(content) {
		return fmt.Errorf("missing required field signalInfo")
	}
	val_signalinfo, n, err := ber.DecodeOctetString(content[offset:], opts...)
	if err != nil {
		return fmt.Errorf("decoding signalInfo: %w", err)
	}
	v.SignalInfo = SignalInfo5(val_signalinfo)
	if offset < 0 || offset >
		len(content) || n < 0 || n > len(content[offset:]) {
		return fmt.Errorf("invalid BER content window")
	}

	offset += n
	if len(v.SignalInfo) < 1 || len(v.SignalInfo) > 200 {
		if constraintErr := ber.CheckDecodedLength(opts, "signalInfo", "SIZE (1..200)", len(v.SignalInfo)); constraintErr != nil {
			return constraintErr
		}
	}
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "ExtensionsExtraSignalInfo", Cause: ber.ErrExtraData}
	}
	return nil
}

// MarshalBER encodes NokiaCUGData to BER format.
func (v *NokiaCUGData) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: NokiaCUGData receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *NokiaCUGData) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if v.CugInterlock != nil {
		if len(*v.CugInterlock) < 4 || len(*v.CugInterlock) > 4 {
			if constraintErr := ber.CheckEncodedLength(opts, "cug-Interlock", "SIZE (4)", len(*v.CugInterlock)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_cuginterlock, encodeErr_enc_cuginterlock := ber.EncodeOctetString([]byte(*v.CugInterlock))
		if encodeErr_enc_cuginterlock != nil {
			return nil, fmt.Errorf("encoding cug-Interlock: %w", encodeErr_enc_cuginterlock)
		}
		retagged_enc_cuginterlock, tagErr_enc_cuginterlock := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_cuginterlock)
		if tagErr_enc_cuginterlock != nil {
			return nil, fmt.Errorf("encoding cug-Interlock: %w", tagErr_enc_cuginterlock)
		}
		enc_cuginterlock = retagged_enc_cuginterlock
		children = append(children, enc_cuginterlock...)
	}
	if v.CugOutgoingAccess != nil {
		var enc_cugoutgoingaccess []byte
		if v.CugOutgoingAccessRaw_ != 0 {
			enc_cugoutgoingaccess = ber.EncodeBooleanRaw(v.CugOutgoingAccessRaw_)
		} else {
			enc_cugoutgoingaccess = ber.EncodeBoolean(*v.CugOutgoingAccess)
		}
		retagged_enc_cugoutgoingaccess, tagErr_enc_cugoutgoingaccess := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_cugoutgoingaccess)
		if tagErr_enc_cugoutgoingaccess != nil {
			return nil, fmt.Errorf("encoding cug-OutgoingAccess: %w", tagErr_enc_cugoutgoingaccess)
		}
		enc_cugoutgoingaccess = retagged_enc_cugoutgoingaccess
		children = append(children, enc_cugoutgoingaccess...)
	}
	if v.CugCallInfo != nil {
		if len(*v.CugCallInfo) < 1 || len(*v.CugCallInfo) > 4 {
			if constraintErr := ber.CheckEncodedLength(opts, "cug-CallInfo", "SIZE (1..4)", len(*v.CugCallInfo)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_cugcallinfo, encodeErr_enc_cugcallinfo := ber.EncodeOctetString([]byte(*v.CugCallInfo))
		if encodeErr_enc_cugcallinfo != nil {
			return nil, fmt.Errorf("encoding cug-CallInfo: %w", encodeErr_enc_cugcallinfo)
		}
		retagged_enc_cugcallinfo, tagErr_enc_cugcallinfo := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_cugcallinfo)
		if tagErr_enc_cugcallinfo != nil {
			return nil, fmt.Errorf("encoding cug-CallInfo: %w", tagErr_enc_cugcallinfo)
		}
		enc_cugcallinfo = retagged_enc_cugcallinfo
		children = append(children, enc_cugcallinfo...)
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

// MarshalDER encodes NokiaCUGData to DER format.
func (v *NokiaCUGData) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: NokiaCUGData receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if v.CugInterlock != nil {
		if len(*v.CugInterlock) < 4 || len(*v.CugInterlock) > 4 {
			if constraintErr := ber.CheckEncodedLength(nil, "cug-Interlock", "SIZE (4)", len(*v.CugInterlock)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_cuginterlock, encodeErr_enc_cuginterlock := ber.EncodeOctetString([]byte(*v.CugInterlock))
		if encodeErr_enc_cuginterlock != nil {
			return nil, fmt.Errorf("encoding cug-Interlock: %w", encodeErr_enc_cuginterlock)
		}
		retagged_enc_cuginterlock, tagErr_enc_cuginterlock := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_cuginterlock)
		if tagErr_enc_cuginterlock != nil {
			return nil, fmt.Errorf("encoding cug-Interlock: %w", tagErr_enc_cuginterlock)
		}
		enc_cuginterlock = retagged_enc_cuginterlock
		children = append(children, enc_cuginterlock...)
	}
	if v.CugOutgoingAccess != nil {
		enc_cugoutgoingaccess := ber.EncodeBoolean(*v.CugOutgoingAccess)
		retagged_enc_cugoutgoingaccess, tagErr_enc_cugoutgoingaccess := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_cugoutgoingaccess)
		if tagErr_enc_cugoutgoingaccess != nil {
			return nil, fmt.Errorf("encoding cug-OutgoingAccess: %w", tagErr_enc_cugoutgoingaccess)
		}
		enc_cugoutgoingaccess = retagged_enc_cugoutgoingaccess
		children = append(children, enc_cugoutgoingaccess...)
	}
	if v.CugCallInfo != nil {
		if len(*v.CugCallInfo) < 1 || len(*v.CugCallInfo) > 4 {
			if constraintErr := ber.CheckEncodedLength(nil, "cug-CallInfo", "SIZE (1..4)", len(*v.CugCallInfo)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_cugcallinfo, encodeErr_enc_cugcallinfo := ber.EncodeOctetString([]byte(*v.CugCallInfo))
		if encodeErr_enc_cugcallinfo != nil {
			return nil, fmt.Errorf("encoding cug-CallInfo: %w", encodeErr_enc_cugcallinfo)
		}
		retagged_enc_cugcallinfo, tagErr_enc_cugcallinfo := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_cugcallinfo)
		if tagErr_enc_cugcallinfo != nil {
			return nil, fmt.Errorf("encoding cug-CallInfo: %w", tagErr_enc_cugcallinfo)
		}
		enc_cugcallinfo = retagged_enc_cugcallinfo
		children = append(children, enc_cugcallinfo...)
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
		return nil, fmt.Errorf("encoding NokiaCUGData as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes NokiaCUGData from BER/DER format.
func (v *NokiaCUGData) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: NokiaCUGData destination is nil", ber.ErrInvalidValue)
	}
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = NokiaCUGData{}
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
		return fmt.Errorf("decoding NokiaCUGData SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "NokiaCUGData", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode cug-Interlock
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
				decodedTag_cuginterlock, n_cuginterlock, rawVal_cuginterlock, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding cug-Interlock: %w", err)
				}
				if decodedTag_cuginterlock.Class != tag.ClassContextSpecific || decodedTag_cuginterlock.Number != 0 {
					return fmt.Errorf("decoding cug-Interlock: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_cuginterlock)
				}
				decVal_cuginterlock, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_cuginterlock.Constructed, rawVal_cuginterlock, opts...)
				if octetErr != nil {
					return fmt.Errorf("decoding cug-Interlock: %w", octetErr)
				}
				tmp_cuginterlock := CUGInterlock5(decVal_cuginterlock)
				v.CugInterlock = &tmp_cuginterlock
				if offset < 0 || offset >
					len(content) || n_cuginterlock < 0 || n_cuginterlock >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_cuginterlock
				if len(*v.CugInterlock) < 4 || len(*v.CugInterlock) > 4 {
					if constraintErr := ber.CheckDecodedLength(opts, "cug-Interlock", "SIZE (4)", len(*v.CugInterlock)); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode cug-OutgoingAccess
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
				decodedTag_cugoutgoingaccess, n_cugoutgoingaccess, rawVal_cugoutgoingaccess, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding cug-OutgoingAccess: %w", err)
				}
				if decodedTag_cugoutgoingaccess.Class != tag.ClassContextSpecific || decodedTag_cugoutgoingaccess.Number != 1 || decodedTag_cugoutgoingaccess.Constructed != false {
					return fmt.Errorf("decoding cug-OutgoingAccess: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_cugoutgoingaccess)
				}
				decVal_cugoutgoingaccess, boolErr := ber.DecodeBooleanValue(rawVal_cugoutgoingaccess)
				if boolErr != nil {
					return fmt.Errorf("decoding cug-OutgoingAccess: %w", boolErr)
				}
				if len(rawVal_cugoutgoingaccess) == 1 && rawVal_cugoutgoingaccess[0] != 0 && rawVal_cugoutgoingaccess[0] != 0xff {
					ber.MarkBERNonCanonical(opts)
				}
				if len(rawVal_cugoutgoingaccess) == 1 {
					v.CugOutgoingAccessRaw_ = rawVal_cugoutgoingaccess[0]
				}
				v.CugOutgoingAccess = &decVal_cugoutgoingaccess
				if offset < 0 || offset >
					len(content) || n_cugoutgoingaccess < 0 || n_cugoutgoingaccess >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_cugoutgoingaccess
			}
		}
	}
	// Decode cug-CallInfo
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2 {
				decodedTag_cugcallinfo, n_cugcallinfo, rawVal_cugcallinfo, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding cug-CallInfo: %w", err)
				}
				if decodedTag_cugcallinfo.Class != tag.ClassContextSpecific || decodedTag_cugcallinfo.Number != 2 {
					return fmt.Errorf("decoding cug-CallInfo: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_cugcallinfo)
				}
				decVal_cugcallinfo, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_cugcallinfo.Constructed, rawVal_cugcallinfo, opts...)
				if octetErr != nil {
					return fmt.Errorf("decoding cug-CallInfo: %w", octetErr)
				}
				tmp_cugcallinfo := CUGCallInfo(decVal_cugcallinfo)
				v.CugCallInfo = &tmp_cugcallinfo
				if offset < 0 || offset >
					len(content) || n_cugcallinfo < 0 || n_cugcallinfo >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_cugcallinfo
				if len(*v.CugCallInfo) < 1 || len(*v.CugCallInfo) > 4 {
					if constraintErr := ber.CheckDecodedLength(opts, "cug-CallInfo", "SIZE (1..4)", len(*v.CugCallInfo)); constraintErr != nil {
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
			return &ber.DecodeError{Offset: offset, TypeName: "NokiaCUGData", Cause: extErr_}
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

// MarshalBER encodes SriResExtension to BER format.
func (v *SriResExtension) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: SriResExtension receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *SriResExtension) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if v.InTriggerKey != nil {
		if !(int64(*v.InTriggerKey) >= 1 && int64(*v.InTriggerKey) <= 65535) {
			if constraintErr := ber.CheckEncodedValue(opts, "inTriggerKey", "(1..65535)", fmt.Sprint(int64(*v.InTriggerKey))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_intriggerkey := ber.EncodeInteger(int64(*v.InTriggerKey))
		retagged_enc_intriggerkey, tagErr_enc_intriggerkey := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_intriggerkey)
		if tagErr_enc_intriggerkey != nil {
			return nil, fmt.Errorf("encoding inTriggerKey: %w", tagErr_enc_intriggerkey)
		}
		enc_intriggerkey = retagged_enc_intriggerkey
		children = append(children, enc_intriggerkey...)
	}
	if v.VlrNumber != nil {
		if len(*v.VlrNumber) < 1 || len(*v.VlrNumber) > 9 {
			if constraintErr := ber.CheckEncodedLength(opts, "vlrNumber", "SIZE (1..9)", len(*v.VlrNumber)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		if len(*v.VlrNumber) < 1 || len(*v.VlrNumber) > 20 {
			if constraintErr := ber.CheckEncodedLength(opts, "vlrNumber", "SIZE (1..20)", len(*v.VlrNumber)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_vlrnumber, encodeErr_enc_vlrnumber := ber.EncodeOctetString([]byte(*v.VlrNumber))
		if encodeErr_enc_vlrnumber != nil {
			return nil, fmt.Errorf("encoding vlrNumber: %w", encodeErr_enc_vlrnumber)
		}
		retagged_enc_vlrnumber, tagErr_enc_vlrnumber := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_vlrnumber)
		if tagErr_enc_vlrnumber != nil {
			return nil, fmt.Errorf("encoding vlrNumber: %w", tagErr_enc_vlrnumber)
		}
		enc_vlrnumber = retagged_enc_vlrnumber
		children = append(children, enc_vlrnumber...)
	}
	if v.ActiveSs != nil {
		if len(*v.ActiveSs) < 1 || len(*v.ActiveSs) > 30 {
			if constraintErr := ber.CheckEncodedLength(opts, "activeSs", "SIZE (1..30)", len(*v.ActiveSs)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_activess, encodeErr_enc_activess := ber.EncodeOctetString([]byte(*v.ActiveSs))
		if encodeErr_enc_activess != nil {
			return nil, fmt.Errorf("encoding activeSs: %w", encodeErr_enc_activess)
		}
		retagged_enc_activess, tagErr_enc_activess := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_activess)
		if tagErr_enc_activess != nil {
			return nil, fmt.Errorf("encoding activeSs: %w", tagErr_enc_activess)
		}
		enc_activess = retagged_enc_activess
		children = append(children, enc_activess...)
	}
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
		retagged_enc_tracereference, tagErr_enc_tracereference := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, enc_tracereference)
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
		retagged_enc_tracetype, tagErr_enc_tracetype := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, enc_tracetype)
		if tagErr_enc_tracetype != nil {
			return nil, fmt.Errorf("encoding traceType: %w", tagErr_enc_tracetype)
		}
		enc_tracetype = retagged_enc_tracetype
		children = append(children, enc_tracetype...)
	}
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
		retagged_enc_omcid, tagErr_enc_omcid := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 5, enc_omcid)
		if tagErr_enc_omcid != nil {
			return nil, fmt.Errorf("encoding omc-Id: %w", tagErr_enc_omcid)
		}
		enc_omcid = retagged_enc_omcid
		children = append(children, enc_omcid...)
	}
	if v.HotBilling != nil {
		var enc_hotbilling []byte
		if v.HotBillingRaw_ != 0 {
			enc_hotbilling = ber.EncodeBooleanRaw(v.HotBillingRaw_)
		} else {
			enc_hotbilling = ber.EncodeBoolean(*v.HotBilling)
		}
		retagged_enc_hotbilling, tagErr_enc_hotbilling := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 6, enc_hotbilling)
		if tagErr_enc_hotbilling != nil {
			return nil, fmt.Errorf("encoding hotBilling: %w", tagErr_enc_hotbilling)
		}
		enc_hotbilling = retagged_enc_hotbilling
		children = append(children, enc_hotbilling...)
	}
	if v.CfoIsDone != nil {
		var enc_cfoisdone []byte
		if v.CfoIsDoneRaw_ != 0 {
			enc_cfoisdone = ber.EncodeBooleanRaw(v.CfoIsDoneRaw_)
		} else {
			enc_cfoisdone = ber.EncodeBoolean(*v.CfoIsDone)
		}
		retagged_enc_cfoisdone, tagErr_enc_cfoisdone := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 7, enc_cfoisdone)
		if tagErr_enc_cfoisdone != nil {
			return nil, fmt.Errorf("encoding cfoIsDone: %w", tagErr_enc_cfoisdone)
		}
		enc_cfoisdone = retagged_enc_cfoisdone
		children = append(children, enc_cfoisdone...)
	}
	if v.CfInCug != nil {
		var enc_cfincug []byte
		if v.CfInCugRaw_ != 0 {
			enc_cfincug = ber.EncodeBooleanRaw(v.CfInCugRaw_)
		} else {
			enc_cfincug = ber.EncodeBoolean(*v.CfInCug)
		}
		retagged_enc_cfincug, tagErr_enc_cfincug := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 8, enc_cfincug)
		if tagErr_enc_cfincug != nil {
			return nil, fmt.Errorf("encoding cfInCug: %w", tagErr_enc_cfincug)
		}
		enc_cfincug = retagged_enc_cfincug
		children = append(children, enc_cfincug...)
	}
	if v.BasicService != nil {
		enc_basicservice, err := v.BasicService.MarshalBER(ber.ChildEncodeOptions(opts, "basicService")...)
		if err != nil {
			return nil, fmt.Errorf("encoding basicService: %w", err)
		}
		{
			var encodeErr error
			enc_basicservice, encodeErr = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 9, enc_basicservice)
			if encodeErr != nil {
				return nil, fmt.Errorf("encoding basicService: %w", encodeErr)
			}
		}
		children = append(children, enc_basicservice...)
	}
	if v.Category != nil {
		if len(*v.Category) < 1 || len(*v.Category) > 1 {
			if constraintErr := ber.CheckEncodedLength(opts, "category", "SIZE (1)", len(*v.Category)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_category, encodeErr_enc_category := ber.EncodeOctetString([]byte(*v.Category))
		if encodeErr_enc_category != nil {
			return nil, fmt.Errorf("encoding category: %w", encodeErr_enc_category)
		}
		retagged_enc_category, tagErr_enc_category := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 10, enc_category)
		if tagErr_enc_category != nil {
			return nil, fmt.Errorf("encoding category: %w", tagErr_enc_category)
		}
		enc_category = retagged_enc_category
		children = append(children, enc_category...)
	}
	if v.RoutingCategory != nil {
		if len(*v.RoutingCategory) < 1 || len(*v.RoutingCategory) > 1 {
			if constraintErr := ber.CheckEncodedLength(opts, "routingCategory", "SIZE (1)", len(*v.RoutingCategory)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_routingcategory, encodeErr_enc_routingcategory := ber.EncodeOctetString([]byte(*v.RoutingCategory))
		if encodeErr_enc_routingcategory != nil {
			return nil, fmt.Errorf("encoding routingCategory: %w", encodeErr_enc_routingcategory)
		}
		retagged_enc_routingcategory, tagErr_enc_routingcategory := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 11, enc_routingcategory)
		if tagErr_enc_routingcategory != nil {
			return nil, fmt.Errorf("encoding routingCategory: %w", tagErr_enc_routingcategory)
		}
		enc_routingcategory = retagged_enc_routingcategory
		children = append(children, enc_routingcategory...)
	}
	if v.PnpIndex != nil {
		if len(*v.PnpIndex) < 3 || len(*v.PnpIndex) > 3 {
			if constraintErr := ber.CheckEncodedLength(opts, "pnpIndex", "SIZE (3)", len(*v.PnpIndex)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_pnpindex, encodeErr_enc_pnpindex := ber.EncodeOctetString([]byte(*v.PnpIndex))
		if encodeErr_enc_pnpindex != nil {
			return nil, fmt.Errorf("encoding pnpIndex: %w", encodeErr_enc_pnpindex)
		}
		retagged_enc_pnpindex, tagErr_enc_pnpindex := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 12, enc_pnpindex)
		if tagErr_enc_pnpindex != nil {
			return nil, fmt.Errorf("encoding pnpIndex: %w", tagErr_enc_pnpindex)
		}
		enc_pnpindex = retagged_enc_pnpindex
		children = append(children, enc_pnpindex...)
	}
	if v.NokiaCUG != nil {
		enc_nokiacug, err := v.NokiaCUG.MarshalBER(ber.ChildEncodeOptions(opts, "nokia-CUG")...)
		if err != nil {
			return nil, fmt.Errorf("encoding nokia-CUG: %w", err)
		}
		retagged_enc_nokiacug, tagErr_enc_nokiacug := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 13, enc_nokiacug)
		if tagErr_enc_nokiacug != nil {
			return nil, fmt.Errorf("encoding nokia-CUG: %w", tagErr_enc_nokiacug)
		}
		enc_nokiacug = retagged_enc_nokiacug
		children = append(children, enc_nokiacug...)
	}
	if v.NoBarrings != nil {
		enc_nobarrings := ber.EncodeNull()
		retagged_enc_nobarrings, tagErr_enc_nobarrings := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 14, enc_nobarrings)
		if tagErr_enc_nobarrings != nil {
			return nil, fmt.Errorf("encoding noBarrings: %w", tagErr_enc_nobarrings)
		}
		enc_nobarrings = retagged_enc_nobarrings
		children = append(children, enc_nobarrings...)
	}
	if v.OdbData != nil {
		enc_odbdata, err := v.OdbData.MarshalBER(ber.ChildEncodeOptions(opts, "odb-Data")...)
		if err != nil {
			return nil, fmt.Errorf("encoding odb-Data: %w", err)
		}
		retagged_enc_odbdata, tagErr_enc_odbdata := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 15, enc_odbdata)
		if tagErr_enc_odbdata != nil {
			return nil, fmt.Errorf("encoding odb-Data: %w", tagErr_enc_odbdata)
		}
		enc_odbdata = retagged_enc_odbdata
		children = append(children, enc_odbdata...)
	}
	if v.FraudData != nil {
		enc_frauddata, err := v.FraudData.MarshalBER(ber.ChildEncodeOptions(opts, "fraudData")...)
		if err != nil {
			return nil, fmt.Errorf("encoding fraudData: %w", err)
		}
		retagged_enc_frauddata, tagErr_enc_frauddata := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 16, enc_frauddata)
		if tagErr_enc_frauddata != nil {
			return nil, fmt.Errorf("encoding fraudData: %w", tagErr_enc_frauddata)
		}
		enc_frauddata = retagged_enc_frauddata
		children = append(children, enc_frauddata...)
	}
	if v.ExtRoutingCategory != nil {
		if !(int64(*v.ExtRoutingCategory) >= 0 && int64(*v.ExtRoutingCategory) <= 2147483647) {
			if constraintErr := ber.CheckEncodedValue(opts, "extRoutingCategory", "(0..2147483647)", fmt.Sprint(int64(*v.ExtRoutingCategory))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_extroutingcategory := ber.EncodeInteger(int64(*v.ExtRoutingCategory))
		retagged_enc_extroutingcategory, tagErr_enc_extroutingcategory := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 17, enc_extroutingcategory)
		if tagErr_enc_extroutingcategory != nil {
			return nil, fmt.Errorf("encoding extRoutingCategory: %w", tagErr_enc_extroutingcategory)
		}
		enc_extroutingcategory = retagged_enc_extroutingcategory
		children = append(children, enc_extroutingcategory...)
	}
	if v.LeaId != nil {
		if !(int64(*v.LeaId) >= 0 && int64(*v.LeaId) <= 65535) {
			if constraintErr := ber.CheckEncodedValue(opts, "leaId", "(0..65535)", fmt.Sprint(int64(*v.LeaId))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_leaid := ber.EncodeInteger(int64(*v.LeaId))
		retagged_enc_leaid, tagErr_enc_leaid := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 18, enc_leaid)
		if tagErr_enc_leaid != nil {
			return nil, fmt.Errorf("encoding leaId: %w", tagErr_enc_leaid)
		}
		enc_leaid = retagged_enc_leaid
		children = append(children, enc_leaid...)
	}
	if v.OlcmInfoTable != nil {
		if len((v.OlcmInfoTable).Values) < 1 || len((v.OlcmInfoTable).Values) > 7 {
			if constraintErr := ber.CheckEncodedLength(opts, "olcmInfoTable", "SIZE (1..7)", len((v.OlcmInfoTable).Values)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_olcminfotable, err := MarshalBEROlcmInfoTable(v.OlcmInfoTable, ber.ChildEncodeOptions(opts, "olcmInfoTable")...)
		if err != nil {
			return nil, fmt.Errorf("encoding olcmInfoTable: %w", err)
		}
		if v.OlcmInfoTableIndef_ {
			// Strip the outer SEQUENCE tag from marshalBER output to get raw children.
			_, _, seqContent_, tlvErr_ := ber.DecodeEncodedTLV(enc_olcminfotable)
			if tlvErr_ != nil {
				return nil, tlvErr_
			}
			{
				var encodeErr error
				enc_olcminfotable, encodeErr = ber.EncodeConstructedIndefinite(tag.Tag{Class: tag.ClassContextSpecific, Number: 19}, seqContent_)
				if encodeErr != nil {
					return nil, fmt.Errorf("encoding olcmInfoTable: %w", encodeErr)
				}
			}
		} else {
			retagged_enc_olcminfotable, tagErr_enc_olcminfotable := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 19, enc_olcminfotable)
			if tagErr_enc_olcminfotable != nil {
				return nil, fmt.Errorf("encoding olcmInfoTable: %w", tagErr_enc_olcminfotable)
			}
			enc_olcminfotable = retagged_enc_olcminfotable
		}
		children = append(children, enc_olcminfotable...)
	}
	if v.CallingCategory != nil {
		if len(*v.CallingCategory) < 1 || len(*v.CallingCategory) > 1 {
			if constraintErr := ber.CheckEncodedLength(opts, "callingCategory", "SIZE (1)", len(*v.CallingCategory)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_callingcategory, encodeErr_enc_callingcategory := ber.EncodeOctetString([]byte(*v.CallingCategory))
		if encodeErr_enc_callingcategory != nil {
			return nil, fmt.Errorf("encoding callingCategory: %w", encodeErr_enc_callingcategory)
		}
		retagged_enc_callingcategory, tagErr_enc_callingcategory := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 20, enc_callingcategory)
		if tagErr_enc_callingcategory != nil {
			return nil, fmt.Errorf("encoding callingCategory: %w", tagErr_enc_callingcategory)
		}
		enc_callingcategory = retagged_enc_callingcategory
		children = append(children, enc_callingcategory...)
	}
	if v.CommonMSISDN != nil {
		if len(*v.CommonMSISDN) < 1 || len(*v.CommonMSISDN) > 9 {
			if constraintErr := ber.CheckEncodedLength(opts, "commonMSISDN", "SIZE (1..9)", len(*v.CommonMSISDN)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		if len(*v.CommonMSISDN) < 1 || len(*v.CommonMSISDN) > 20 {
			if constraintErr := ber.CheckEncodedLength(opts, "commonMSISDN", "SIZE (1..20)", len(*v.CommonMSISDN)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_commonmsisdn, encodeErr_enc_commonmsisdn := ber.EncodeOctetString([]byte(*v.CommonMSISDN))
		if encodeErr_enc_commonmsisdn != nil {
			return nil, fmt.Errorf("encoding commonMSISDN: %w", encodeErr_enc_commonmsisdn)
		}
		retagged_enc_commonmsisdn, tagErr_enc_commonmsisdn := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 21, enc_commonmsisdn)
		if tagErr_enc_commonmsisdn != nil {
			return nil, fmt.Errorf("encoding commonMSISDN: %w", tagErr_enc_commonmsisdn)
		}
		enc_commonmsisdn = retagged_enc_commonmsisdn
		children = append(children, enc_commonmsisdn...)
	}
	if v.RgData != nil {
		enc_rgdata, err := v.RgData.MarshalBER(ber.ChildEncodeOptions(opts, "rgData")...)
		if err != nil {
			return nil, fmt.Errorf("encoding rgData: %w", err)
		}
		retagged_enc_rgdata, tagErr_enc_rgdata := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 22, enc_rgdata)
		if tagErr_enc_rgdata != nil {
			return nil, fmt.Errorf("encoding rgData: %w", tagErr_enc_rgdata)
		}
		enc_rgdata = retagged_enc_rgdata
		children = append(children, enc_rgdata...)
	}
	if v.OlcmTraceReference != nil {
		if len(*v.OlcmTraceReference) < 1 || len(*v.OlcmTraceReference) > 4 {
			if constraintErr := ber.CheckEncodedLength(opts, "olcmTraceReference", "SIZE (1..4)", len(*v.OlcmTraceReference)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_olcmtracereference, encodeErr_enc_olcmtracereference := ber.EncodeOctetString([]byte(*v.OlcmTraceReference))
		if encodeErr_enc_olcmtracereference != nil {
			return nil, fmt.Errorf("encoding olcmTraceReference: %w", encodeErr_enc_olcmtracereference)
		}
		retagged_enc_olcmtracereference, tagErr_enc_olcmtracereference := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 23, enc_olcmtracereference)
		if tagErr_enc_olcmtracereference != nil {
			return nil, fmt.Errorf("encoding olcmTraceReference: %w", tagErr_enc_olcmtracereference)
		}
		enc_olcmtracereference = retagged_enc_olcmtracereference
		children = append(children, enc_olcmtracereference...)
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
	return ber.EncodeConstructed(tag.Tag{Class: tag.ClassPrivate, Number: 0, Constructed: true}, children)
}

// MarshalDER encodes SriResExtension to DER format.
func (v *SriResExtension) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: SriResExtension receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if v.InTriggerKey != nil {
		if !(int64(*v.InTriggerKey) >= 1 && int64(*v.InTriggerKey) <= 65535) {
			if constraintErr := ber.CheckEncodedValue(nil, "inTriggerKey", "(1..65535)", fmt.Sprint(int64(*v.InTriggerKey))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_intriggerkey := ber.EncodeInteger(int64(*v.InTriggerKey))
		retagged_enc_intriggerkey, tagErr_enc_intriggerkey := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_intriggerkey)
		if tagErr_enc_intriggerkey != nil {
			return nil, fmt.Errorf("encoding inTriggerKey: %w", tagErr_enc_intriggerkey)
		}
		enc_intriggerkey = retagged_enc_intriggerkey
		children = append(children, enc_intriggerkey...)
	}
	if v.VlrNumber != nil {
		if len(*v.VlrNumber) < 1 || len(*v.VlrNumber) > 9 {
			if constraintErr := ber.CheckEncodedLength(nil, "vlrNumber", "SIZE (1..9)", len(*v.VlrNumber)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		if len(*v.VlrNumber) < 1 || len(*v.VlrNumber) > 20 {
			if constraintErr := ber.CheckEncodedLength(nil, "vlrNumber", "SIZE (1..20)", len(*v.VlrNumber)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_vlrnumber, encodeErr_enc_vlrnumber := ber.EncodeOctetString([]byte(*v.VlrNumber))
		if encodeErr_enc_vlrnumber != nil {
			return nil, fmt.Errorf("encoding vlrNumber: %w", encodeErr_enc_vlrnumber)
		}
		retagged_enc_vlrnumber, tagErr_enc_vlrnumber := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_vlrnumber)
		if tagErr_enc_vlrnumber != nil {
			return nil, fmt.Errorf("encoding vlrNumber: %w", tagErr_enc_vlrnumber)
		}
		enc_vlrnumber = retagged_enc_vlrnumber
		children = append(children, enc_vlrnumber...)
	}
	if v.ActiveSs != nil {
		if len(*v.ActiveSs) < 1 || len(*v.ActiveSs) > 30 {
			if constraintErr := ber.CheckEncodedLength(nil, "activeSs", "SIZE (1..30)", len(*v.ActiveSs)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_activess, encodeErr_enc_activess := ber.EncodeOctetString([]byte(*v.ActiveSs))
		if encodeErr_enc_activess != nil {
			return nil, fmt.Errorf("encoding activeSs: %w", encodeErr_enc_activess)
		}
		retagged_enc_activess, tagErr_enc_activess := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_activess)
		if tagErr_enc_activess != nil {
			return nil, fmt.Errorf("encoding activeSs: %w", tagErr_enc_activess)
		}
		enc_activess = retagged_enc_activess
		children = append(children, enc_activess...)
	}
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
		retagged_enc_tracereference, tagErr_enc_tracereference := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, enc_tracereference)
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
		retagged_enc_tracetype, tagErr_enc_tracetype := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, enc_tracetype)
		if tagErr_enc_tracetype != nil {
			return nil, fmt.Errorf("encoding traceType: %w", tagErr_enc_tracetype)
		}
		enc_tracetype = retagged_enc_tracetype
		children = append(children, enc_tracetype...)
	}
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
		retagged_enc_omcid, tagErr_enc_omcid := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 5, enc_omcid)
		if tagErr_enc_omcid != nil {
			return nil, fmt.Errorf("encoding omc-Id: %w", tagErr_enc_omcid)
		}
		enc_omcid = retagged_enc_omcid
		children = append(children, enc_omcid...)
	}
	if v.HotBilling != nil {
		enc_hotbilling := ber.EncodeBoolean(*v.HotBilling)
		retagged_enc_hotbilling, tagErr_enc_hotbilling := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 6, enc_hotbilling)
		if tagErr_enc_hotbilling != nil {
			return nil, fmt.Errorf("encoding hotBilling: %w", tagErr_enc_hotbilling)
		}
		enc_hotbilling = retagged_enc_hotbilling
		children = append(children, enc_hotbilling...)
	}
	if v.CfoIsDone != nil {
		enc_cfoisdone := ber.EncodeBoolean(*v.CfoIsDone)
		retagged_enc_cfoisdone, tagErr_enc_cfoisdone := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 7, enc_cfoisdone)
		if tagErr_enc_cfoisdone != nil {
			return nil, fmt.Errorf("encoding cfoIsDone: %w", tagErr_enc_cfoisdone)
		}
		enc_cfoisdone = retagged_enc_cfoisdone
		children = append(children, enc_cfoisdone...)
	}
	if v.CfInCug != nil {
		enc_cfincug := ber.EncodeBoolean(*v.CfInCug)
		retagged_enc_cfincug, tagErr_enc_cfincug := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 8, enc_cfincug)
		if tagErr_enc_cfincug != nil {
			return nil, fmt.Errorf("encoding cfInCug: %w", tagErr_enc_cfincug)
		}
		enc_cfincug = retagged_enc_cfincug
		children = append(children, enc_cfincug...)
	}
	if v.BasicService != nil {
		enc_basicservice, err := v.BasicService.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding basicService: %w", err)
		}
		{
			var encodeErr error
			enc_basicservice, encodeErr = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 9, enc_basicservice)
			if encodeErr != nil {
				return nil, fmt.Errorf("encoding basicService: %w", encodeErr)
			}
		}
		children = append(children, enc_basicservice...)
	}
	if v.Category != nil {
		if len(*v.Category) < 1 || len(*v.Category) > 1 {
			if constraintErr := ber.CheckEncodedLength(nil, "category", "SIZE (1)", len(*v.Category)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_category, encodeErr_enc_category := ber.EncodeOctetString([]byte(*v.Category))
		if encodeErr_enc_category != nil {
			return nil, fmt.Errorf("encoding category: %w", encodeErr_enc_category)
		}
		retagged_enc_category, tagErr_enc_category := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 10, enc_category)
		if tagErr_enc_category != nil {
			return nil, fmt.Errorf("encoding category: %w", tagErr_enc_category)
		}
		enc_category = retagged_enc_category
		children = append(children, enc_category...)
	}
	if v.RoutingCategory != nil {
		if len(*v.RoutingCategory) < 1 || len(*v.RoutingCategory) > 1 {
			if constraintErr := ber.CheckEncodedLength(nil, "routingCategory", "SIZE (1)", len(*v.RoutingCategory)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_routingcategory, encodeErr_enc_routingcategory := ber.EncodeOctetString([]byte(*v.RoutingCategory))
		if encodeErr_enc_routingcategory != nil {
			return nil, fmt.Errorf("encoding routingCategory: %w", encodeErr_enc_routingcategory)
		}
		retagged_enc_routingcategory, tagErr_enc_routingcategory := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 11, enc_routingcategory)
		if tagErr_enc_routingcategory != nil {
			return nil, fmt.Errorf("encoding routingCategory: %w", tagErr_enc_routingcategory)
		}
		enc_routingcategory = retagged_enc_routingcategory
		children = append(children, enc_routingcategory...)
	}
	if v.PnpIndex != nil {
		if len(*v.PnpIndex) < 3 || len(*v.PnpIndex) > 3 {
			if constraintErr := ber.CheckEncodedLength(nil, "pnpIndex", "SIZE (3)", len(*v.PnpIndex)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_pnpindex, encodeErr_enc_pnpindex := ber.EncodeOctetString([]byte(*v.PnpIndex))
		if encodeErr_enc_pnpindex != nil {
			return nil, fmt.Errorf("encoding pnpIndex: %w", encodeErr_enc_pnpindex)
		}
		retagged_enc_pnpindex, tagErr_enc_pnpindex := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 12, enc_pnpindex)
		if tagErr_enc_pnpindex != nil {
			return nil, fmt.Errorf("encoding pnpIndex: %w", tagErr_enc_pnpindex)
		}
		enc_pnpindex = retagged_enc_pnpindex
		children = append(children, enc_pnpindex...)
	}
	if v.NokiaCUG != nil {
		enc_nokiacug, err := v.NokiaCUG.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding nokia-CUG: %w", err)
		}
		retagged_enc_nokiacug, tagErr_enc_nokiacug := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 13, enc_nokiacug)
		if tagErr_enc_nokiacug != nil {
			return nil, fmt.Errorf("encoding nokia-CUG: %w", tagErr_enc_nokiacug)
		}
		enc_nokiacug = retagged_enc_nokiacug
		children = append(children, enc_nokiacug...)
	}
	if v.NoBarrings != nil {
		enc_nobarrings := ber.EncodeNull()
		retagged_enc_nobarrings, tagErr_enc_nobarrings := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 14, enc_nobarrings)
		if tagErr_enc_nobarrings != nil {
			return nil, fmt.Errorf("encoding noBarrings: %w", tagErr_enc_nobarrings)
		}
		enc_nobarrings = retagged_enc_nobarrings
		children = append(children, enc_nobarrings...)
	}
	if v.OdbData != nil {
		enc_odbdata, err := v.OdbData.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding odb-Data: %w", err)
		}
		retagged_enc_odbdata, tagErr_enc_odbdata := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 15, enc_odbdata)
		if tagErr_enc_odbdata != nil {
			return nil, fmt.Errorf("encoding odb-Data: %w", tagErr_enc_odbdata)
		}
		enc_odbdata = retagged_enc_odbdata
		children = append(children, enc_odbdata...)
	}
	if v.FraudData != nil {
		enc_frauddata, err := v.FraudData.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding fraudData: %w", err)
		}
		retagged_enc_frauddata, tagErr_enc_frauddata := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 16, enc_frauddata)
		if tagErr_enc_frauddata != nil {
			return nil, fmt.Errorf("encoding fraudData: %w", tagErr_enc_frauddata)
		}
		enc_frauddata = retagged_enc_frauddata
		children = append(children, enc_frauddata...)
	}
	if v.ExtRoutingCategory != nil {
		if !(int64(*v.ExtRoutingCategory) >= 0 && int64(*v.ExtRoutingCategory) <= 2147483647) {
			if constraintErr := ber.CheckEncodedValue(nil, "extRoutingCategory", "(0..2147483647)", fmt.Sprint(int64(*v.ExtRoutingCategory))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_extroutingcategory := ber.EncodeInteger(int64(*v.ExtRoutingCategory))
		retagged_enc_extroutingcategory, tagErr_enc_extroutingcategory := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 17, enc_extroutingcategory)
		if tagErr_enc_extroutingcategory != nil {
			return nil, fmt.Errorf("encoding extRoutingCategory: %w", tagErr_enc_extroutingcategory)
		}
		enc_extroutingcategory = retagged_enc_extroutingcategory
		children = append(children, enc_extroutingcategory...)
	}
	if v.LeaId != nil {
		if !(int64(*v.LeaId) >= 0 && int64(*v.LeaId) <= 65535) {
			if constraintErr := ber.CheckEncodedValue(nil, "leaId", "(0..65535)", fmt.Sprint(int64(*v.LeaId))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_leaid := ber.EncodeInteger(int64(*v.LeaId))
		retagged_enc_leaid, tagErr_enc_leaid := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 18, enc_leaid)
		if tagErr_enc_leaid != nil {
			return nil, fmt.Errorf("encoding leaId: %w", tagErr_enc_leaid)
		}
		enc_leaid = retagged_enc_leaid
		children = append(children, enc_leaid...)
	}
	if v.OlcmInfoTable != nil {
		if len((v.OlcmInfoTable).Values) < 1 || len((v.OlcmInfoTable).Values) > 7 {
			if constraintErr := ber.CheckEncodedLength(nil, "olcmInfoTable", "SIZE (1..7)", len((v.OlcmInfoTable).Values)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_olcminfotable, err := MarshalDEROlcmInfoTable(v.OlcmInfoTable)
		if err != nil {
			return nil, fmt.Errorf("encoding olcmInfoTable: %w", err)
		}
		retagged_enc_olcminfotable, tagErr_enc_olcminfotable := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 19, enc_olcminfotable)
		if tagErr_enc_olcminfotable != nil {
			return nil, fmt.Errorf("encoding olcmInfoTable: %w", tagErr_enc_olcminfotable)
		}
		enc_olcminfotable = retagged_enc_olcminfotable
		children = append(children, enc_olcminfotable...)
	}
	if v.CallingCategory != nil {
		if len(*v.CallingCategory) < 1 || len(*v.CallingCategory) > 1 {
			if constraintErr := ber.CheckEncodedLength(nil, "callingCategory", "SIZE (1)", len(*v.CallingCategory)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_callingcategory, encodeErr_enc_callingcategory := ber.EncodeOctetString([]byte(*v.CallingCategory))
		if encodeErr_enc_callingcategory != nil {
			return nil, fmt.Errorf("encoding callingCategory: %w", encodeErr_enc_callingcategory)
		}
		retagged_enc_callingcategory, tagErr_enc_callingcategory := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 20, enc_callingcategory)
		if tagErr_enc_callingcategory != nil {
			return nil, fmt.Errorf("encoding callingCategory: %w", tagErr_enc_callingcategory)
		}
		enc_callingcategory = retagged_enc_callingcategory
		children = append(children, enc_callingcategory...)
	}
	if v.CommonMSISDN != nil {
		if len(*v.CommonMSISDN) < 1 || len(*v.CommonMSISDN) > 9 {
			if constraintErr := ber.CheckEncodedLength(nil, "commonMSISDN", "SIZE (1..9)", len(*v.CommonMSISDN)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		if len(*v.CommonMSISDN) < 1 || len(*v.CommonMSISDN) > 20 {
			if constraintErr := ber.CheckEncodedLength(nil, "commonMSISDN", "SIZE (1..20)", len(*v.CommonMSISDN)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_commonmsisdn, encodeErr_enc_commonmsisdn := ber.EncodeOctetString([]byte(*v.CommonMSISDN))
		if encodeErr_enc_commonmsisdn != nil {
			return nil, fmt.Errorf("encoding commonMSISDN: %w", encodeErr_enc_commonmsisdn)
		}
		retagged_enc_commonmsisdn, tagErr_enc_commonmsisdn := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 21, enc_commonmsisdn)
		if tagErr_enc_commonmsisdn != nil {
			return nil, fmt.Errorf("encoding commonMSISDN: %w", tagErr_enc_commonmsisdn)
		}
		enc_commonmsisdn = retagged_enc_commonmsisdn
		children = append(children, enc_commonmsisdn...)
	}
	if v.RgData != nil {
		enc_rgdata, err := v.RgData.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding rgData: %w", err)
		}
		retagged_enc_rgdata, tagErr_enc_rgdata := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 22, enc_rgdata)
		if tagErr_enc_rgdata != nil {
			return nil, fmt.Errorf("encoding rgData: %w", tagErr_enc_rgdata)
		}
		enc_rgdata = retagged_enc_rgdata
		children = append(children, enc_rgdata...)
	}
	if v.OlcmTraceReference != nil {
		if len(*v.OlcmTraceReference) < 1 || len(*v.OlcmTraceReference) > 4 {
			if constraintErr := ber.CheckEncodedLength(nil, "olcmTraceReference", "SIZE (1..4)", len(*v.OlcmTraceReference)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_olcmtracereference, encodeErr_enc_olcmtracereference := ber.EncodeOctetString([]byte(*v.OlcmTraceReference))
		if encodeErr_enc_olcmtracereference != nil {
			return nil, fmt.Errorf("encoding olcmTraceReference: %w", encodeErr_enc_olcmtracereference)
		}
		retagged_enc_olcmtracereference, tagErr_enc_olcmtracereference := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 23, enc_olcmtracereference)
		if tagErr_enc_olcmtracereference != nil {
			return nil, fmt.Errorf("encoding olcmTraceReference: %w", tagErr_enc_olcmtracereference)
		}
		enc_olcmtracereference = retagged_enc_olcmtracereference
		children = append(children, enc_olcmtracereference...)
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
	retagged_encoded, tagErr_encoded := ber.EncodeImplicitTagWithClass(tag.ClassPrivate, 0, encoded)
	if tagErr_encoded != nil {
		return nil, fmt.Errorf("encoding SriResExtension: %w", tagErr_encoded)
	}
	encoded = retagged_encoded
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding SriResExtension as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes SriResExtension from BER/DER format.
func (v *SriResExtension) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: SriResExtension destination is nil", ber.ErrInvalidValue)
	}
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = SriResExtension{}
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
	decodedTag, content, total, err := ber.DecodeConstructedContent(data, opts...)
	if err != nil {
		return fmt.Errorf("decoding SriResExtension: %w", err)
	}
	if decodedTag.Class != tag.ClassPrivate || decodedTag.Number != 0 || !decodedTag.Constructed {
		return fmt.Errorf("decoding SriResExtension: %w: expected tag [PRIVATE 0], got %s", ber.ErrInvalidTag, decodedTag)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "SriResExtension", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode inTriggerKey
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
				decodedTag_intriggerkey, n_intriggerkey, rawVal_intriggerkey, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding inTriggerKey: %w", err)
				}
				if decodedTag_intriggerkey.Class != tag.ClassContextSpecific || decodedTag_intriggerkey.Number != 0 || decodedTag_intriggerkey.Constructed != false {
					return fmt.Errorf("decoding inTriggerKey: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_intriggerkey)
				}
				decVal_intriggerkey, intErr := ber.DecodeIntegerValue(rawVal_intriggerkey)
				if intErr != nil {
					return fmt.Errorf("decoding inTriggerKey: %w", intErr)
				}
				tmp_intriggerkey := InTriggerKey(decVal_intriggerkey)
				v.InTriggerKey = &tmp_intriggerkey
				if offset < 0 || offset >
					len(content) || n_intriggerkey < 0 || n_intriggerkey > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_intriggerkey
				if !(int64(*v.InTriggerKey) >= 1 && int64(*v.InTriggerKey) <= 65535) {
					if constraintErr := ber.CheckDecodedValue(opts, "inTriggerKey", "(1..65535)", fmt.Sprint(int64(*v.InTriggerKey))); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode vlrNumber
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
				decodedTag_vlrnumber, n_vlrnumber, rawVal_vlrnumber, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding vlrNumber: %w", err)
				}
				if decodedTag_vlrnumber.Class != tag.ClassContextSpecific || decodedTag_vlrnumber.Number != 1 {
					return fmt.Errorf("decoding vlrNumber: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_vlrnumber)
				}
				decVal_vlrnumber, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_vlrnumber.Constructed, rawVal_vlrnumber, opts...)
				if octetErr != nil {
					return fmt.Errorf("decoding vlrNumber: %w", octetErr)
				}
				tmp_vlrnumber := ISDNAddressString5(decVal_vlrnumber)
				v.VlrNumber = &tmp_vlrnumber
				if offset < 0 || offset >
					len(content) || n_vlrnumber < 0 || n_vlrnumber > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_vlrnumber
				if len(*v.VlrNumber) < 1 || len(*v.VlrNumber) > 9 {
					if constraintErr := ber.CheckDecodedLength(opts, "vlrNumber", "SIZE (1..9)", len(*v.VlrNumber)); constraintErr != nil {
						return constraintErr
					}
				}
				if len(*v.VlrNumber) < 1 || len(*v.VlrNumber) > 20 {
					if constraintErr := ber.CheckDecodedLength(opts, "vlrNumber", "SIZE (1..20)", len(*v.VlrNumber)); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode activeSs
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2 {
				decodedTag_activess, n_activess, rawVal_activess, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding activeSs: %w", err)
				}
				if decodedTag_activess.Class != tag.ClassContextSpecific || decodedTag_activess.Number != 2 {
					return fmt.Errorf("decoding activeSs: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_activess)
				}
				decVal_activess, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_activess.Constructed, rawVal_activess, opts...)
				if octetErr != nil {
					return fmt.Errorf("decoding activeSs: %w", octetErr)
				}
				tmp_activess := ActiveSSList(decVal_activess)
				v.ActiveSs = &tmp_activess
				if offset < 0 || offset >
					len(content) || n_activess < 0 || n_activess > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_activess
				if len(*v.ActiveSs) < 1 || len(*v.ActiveSs) > 30 {
					if constraintErr := ber.CheckDecodedLength(opts, "activeSs", "SIZE (1..30)", len(*v.ActiveSs)); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode traceReference
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3 {
				decodedTag_tracereference, n_tracereference, rawVal_tracereference, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding traceReference: %w", err)
				}
				if decodedTag_tracereference.Class != tag.ClassContextSpecific || decodedTag_tracereference.Number != 3 {
					return fmt.Errorf("decoding traceReference: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_tracereference)
				}
				decVal_tracereference, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_tracereference.Constructed, rawVal_tracereference, opts...)
				if octetErr != nil {
					return fmt.Errorf("decoding traceReference: %w", octetErr)
				}
				tmp_tracereference := TraceReference5(decVal_tracereference)
				v.TraceReference = &tmp_tracereference
				if offset < 0 || offset >
					len(content) || n_tracereference < 0 || n_tracereference >
					len(content[offset:]) {
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
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4 {
				decodedTag_tracetype, n_tracetype, rawVal_tracetype, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding traceType: %w", err)
				}
				if decodedTag_tracetype.Class != tag.ClassContextSpecific || decodedTag_tracetype.Number != 4 || decodedTag_tracetype.Constructed != false {
					return fmt.Errorf("decoding traceType: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_tracetype)
				}
				decVal_tracetype, intErr := ber.DecodeIntegerValue(rawVal_tracetype)
				if intErr != nil {
					return fmt.Errorf("decoding traceType: %w", intErr)
				}
				tmp_tracetype := TraceType5(decVal_tracetype)
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
	// Decode omc-Id
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 5 {
				decodedTag_omcid, n_omcid, rawVal_omcid, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding omc-Id: %w", err)
				}
				if decodedTag_omcid.Class != tag.ClassContextSpecific || decodedTag_omcid.Number != 5 {
					return fmt.Errorf("decoding omc-Id: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_omcid)
				}
				decVal_omcid, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_omcid.Constructed, rawVal_omcid, opts...)
				if octetErr != nil {
					return fmt.Errorf("decoding omc-Id: %w", octetErr)
				}
				tmp_omcid := AddressString5(decVal_omcid)
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
	// Decode hotBilling
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 6 {
				decodedTag_hotbilling, n_hotbilling, rawVal_hotbilling, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding hotBilling: %w", err)
				}
				if decodedTag_hotbilling.Class != tag.ClassContextSpecific || decodedTag_hotbilling.Number != 6 || decodedTag_hotbilling.Constructed != false {
					return fmt.Errorf("decoding hotBilling: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_hotbilling)
				}
				decVal_hotbilling, boolErr := ber.DecodeBooleanValue(rawVal_hotbilling)
				if boolErr != nil {
					return fmt.Errorf("decoding hotBilling: %w", boolErr)
				}
				if len(rawVal_hotbilling) == 1 && rawVal_hotbilling[0] != 0 && rawVal_hotbilling[0] != 0xff {
					ber.MarkBERNonCanonical(opts)
				}
				if len(rawVal_hotbilling) == 1 {
					v.HotBillingRaw_ = rawVal_hotbilling[0]
				}
				v.HotBilling = &decVal_hotbilling
				if offset < 0 || offset >
					len(content) || n_hotbilling < 0 || n_hotbilling > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_hotbilling
			}
		}
	}
	// Decode cfoIsDone
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 7 {
				decodedTag_cfoisdone, n_cfoisdone, rawVal_cfoisdone, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding cfoIsDone: %w", err)
				}
				if decodedTag_cfoisdone.Class != tag.ClassContextSpecific || decodedTag_cfoisdone.Number != 7 || decodedTag_cfoisdone.Constructed != false {
					return fmt.Errorf("decoding cfoIsDone: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_cfoisdone)
				}
				decVal_cfoisdone, boolErr := ber.DecodeBooleanValue(rawVal_cfoisdone)
				if boolErr != nil {
					return fmt.Errorf("decoding cfoIsDone: %w", boolErr)
				}
				if len(rawVal_cfoisdone) == 1 && rawVal_cfoisdone[0] != 0 && rawVal_cfoisdone[0] != 0xff {
					ber.MarkBERNonCanonical(opts)
				}
				if len(rawVal_cfoisdone) == 1 {
					v.CfoIsDoneRaw_ = rawVal_cfoisdone[0]
				}
				v.CfoIsDone = &decVal_cfoisdone
				if offset < 0 || offset >
					len(content) || n_cfoisdone < 0 || n_cfoisdone > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_cfoisdone
			}
		}
	}
	// Decode cfInCug
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 8 {
				decodedTag_cfincug, n_cfincug, rawVal_cfincug, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding cfInCug: %w", err)
				}
				if decodedTag_cfincug.Class != tag.ClassContextSpecific || decodedTag_cfincug.Number != 8 || decodedTag_cfincug.Constructed != false {
					return fmt.Errorf("decoding cfInCug: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_cfincug)
				}
				decVal_cfincug, boolErr := ber.DecodeBooleanValue(rawVal_cfincug)
				if boolErr != nil {
					return fmt.Errorf("decoding cfInCug: %w", boolErr)
				}
				if len(rawVal_cfincug) == 1 && rawVal_cfincug[0] != 0 && rawVal_cfincug[0] != 0xff {
					ber.MarkBERNonCanonical(opts)
				}
				if len(rawVal_cfincug) == 1 {
					v.CfInCugRaw_ = rawVal_cfincug[0]
				}
				v.CfInCug = &decVal_cfincug
				if offset < 0 || offset >
					len(content) || n_cfincug < 0 || n_cfincug > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_cfincug
			}
		}
	}
	// Decode basicService
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 9 {
				decodedTag_basicservice, n_basicservice, innerData_basicservice, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding basicService: %w", err)
				}
				if decodedTag_basicservice.Class != tag.ClassContextSpecific || decodedTag_basicservice.Number != 9 || decodedTag_basicservice.Constructed != true {
					return fmt.Errorf("decoding basicService: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_basicservice)
				}
				// Decode inner value from explicit tag wrapper
				var dec_basicservice BasicServiceCode5
				if unmErr := dec_basicservice.UnmarshalBER(innerData_basicservice, ber.ChildDecodeOptions(opts, "basicService")...); unmErr != nil {
					return fmt.Errorf("decoding basicService: %w", unmErr)
				}
				v.BasicService = &dec_basicservice
				if offset < 0 || offset >
					len(content) || n_basicservice < 0 || n_basicservice > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_basicservice
			}
		}
	}
	// Decode category
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 10 {
				decodedTag_category, n_category, rawVal_category, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding category: %w", err)
				}
				if decodedTag_category.Class != tag.ClassContextSpecific || decodedTag_category.Number != 10 {
					return fmt.Errorf("decoding category: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_category)
				}
				decVal_category, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_category.Constructed, rawVal_category, opts...)
				if octetErr != nil {
					return fmt.Errorf("decoding category: %w", octetErr)
				}
				tmp_category := Category6(decVal_category)
				v.Category = &tmp_category
				if offset < 0 || offset >
					len(content) || n_category < 0 || n_category > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_category
				if len(*v.Category) < 1 || len(*v.Category) > 1 {
					if constraintErr := ber.CheckDecodedLength(opts, "category", "SIZE (1)", len(*v.Category)); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode routingCategory
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 11 {
				decodedTag_routingcategory, n_routingcategory, rawVal_routingcategory, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding routingCategory: %w", err)
				}
				if decodedTag_routingcategory.Class != tag.ClassContextSpecific || decodedTag_routingcategory.Number != 11 {
					return fmt.Errorf("decoding routingCategory: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_routingcategory)
				}
				decVal_routingcategory, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_routingcategory.Constructed, rawVal_routingcategory, opts...)
				if octetErr != nil {
					return fmt.Errorf("decoding routingCategory: %w", octetErr)
				}
				tmp_routingcategory := RoutingCategory(decVal_routingcategory)
				v.RoutingCategory = &tmp_routingcategory
				if offset < 0 || offset >
					len(content) || n_routingcategory < 0 || n_routingcategory >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_routingcategory
				if len(*v.RoutingCategory) < 1 || len(*v.RoutingCategory) > 1 {
					if constraintErr := ber.CheckDecodedLength(opts, "routingCategory", "SIZE (1)", len(*v.RoutingCategory)); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode pnpIndex
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 12 {
				decodedTag_pnpindex, n_pnpindex, rawVal_pnpindex, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding pnpIndex: %w", err)
				}
				if decodedTag_pnpindex.Class != tag.ClassContextSpecific || decodedTag_pnpindex.Number != 12 {
					return fmt.Errorf("decoding pnpIndex: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_pnpindex)
				}
				decVal_pnpindex, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_pnpindex.Constructed, rawVal_pnpindex, opts...)
				if octetErr != nil {
					return fmt.Errorf("decoding pnpIndex: %w", octetErr)
				}
				tmp_pnpindex := PnpIndex(decVal_pnpindex)
				v.PnpIndex = &tmp_pnpindex
				if offset < 0 || offset >
					len(content) || n_pnpindex < 0 || n_pnpindex > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_pnpindex
				if len(*v.PnpIndex) < 3 || len(*v.PnpIndex) > 3 {
					if constraintErr := ber.CheckDecodedLength(opts, "pnpIndex", "SIZE (3)", len(*v.PnpIndex)); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode nokia-CUG
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 13 {
				decodedTag_nokiacug, n_nokiacug, rawVal_nokiacug, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding nokia-CUG: %w", err)
				}
				if decodedTag_nokiacug.Class != tag.ClassContextSpecific || decodedTag_nokiacug.Number != 13 || decodedTag_nokiacug.Constructed != true {
					return fmt.Errorf("decoding nokia-CUG: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_nokiacug)
				}
				reconstructed_nokiacug, reconstructionErr_nokiacug := ber.EncodeSequence(rawVal_nokiacug)
				if reconstructionErr_nokiacug != nil {
					return fmt.Errorf("decoding nokia-CUG: %w", reconstructionErr_nokiacug)
				}
				var dec_nokiacug NokiaCUGData
				if unmErr := dec_nokiacug.UnmarshalBER(reconstructed_nokiacug, ber.ChildDecodeOptions(opts, "nokia-CUG")...); unmErr != nil {
					return fmt.Errorf("decoding nokia-CUG: %w", unmErr)
				}
				v.NokiaCUG = &dec_nokiacug
				if offset < 0 || offset >
					len(content) || n_nokiacug < 0 || n_nokiacug > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_nokiacug
			}
		}
	}
	// Decode noBarrings
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 14 {
				decodedTag_nobarrings, n_nobarrings, rawVal_nobarrings, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding noBarrings: %w", err)
				}
				if decodedTag_nobarrings.Class != tag.ClassContextSpecific || decodedTag_nobarrings.Number != 14 || decodedTag_nobarrings.Constructed != false {
					return fmt.Errorf("decoding noBarrings: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_nobarrings)
				}
				if len(rawVal_nobarrings) != 0 {
					return fmt.Errorf("decoding noBarrings: %w: NULL content length %d", ber.ErrInvalidValue, len(rawVal_nobarrings))
				}
				v.NoBarrings = &struct{}{}
				if offset < 0 || offset >
					len(content) || n_nobarrings < 0 || n_nobarrings > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_nobarrings
			}
		}
	}
	// Decode odb-Data
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 15 {
				decodedTag_odbdata, n_odbdata, rawVal_odbdata, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding odb-Data: %w", err)
				}
				if decodedTag_odbdata.Class != tag.ClassContextSpecific || decodedTag_odbdata.Number != 15 || decodedTag_odbdata.Constructed != true {
					return fmt.Errorf("decoding odb-Data: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_odbdata)
				}
				reconstructed_odbdata, reconstructionErr_odbdata := ber.EncodeSequence(rawVal_odbdata)
				if reconstructionErr_odbdata != nil {
					return fmt.Errorf("decoding odb-Data: %w", reconstructionErr_odbdata)
				}
				var dec_odbdata ODBData5
				if unmErr := dec_odbdata.UnmarshalBER(reconstructed_odbdata, ber.ChildDecodeOptions(opts, "odb-Data")...); unmErr != nil {
					return fmt.Errorf("decoding odb-Data: %w", unmErr)
				}
				v.OdbData = &dec_odbdata
				if offset < 0 || offset >
					len(content) || n_odbdata < 0 || n_odbdata > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_odbdata
			}
		}
	}
	// Decode fraudData
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 16 {
				decodedTag_frauddata, n_frauddata, rawVal_frauddata, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding fraudData: %w", err)
				}
				if decodedTag_frauddata.Class != tag.ClassContextSpecific || decodedTag_frauddata.Number != 16 || decodedTag_frauddata.Constructed != true {
					return fmt.Errorf("decoding fraudData: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_frauddata)
				}
				reconstructed_frauddata, reconstructionErr_frauddata := ber.EncodeSequence(rawVal_frauddata)
				if reconstructionErr_frauddata != nil {
					return fmt.Errorf("decoding fraudData: %w", reconstructionErr_frauddata)
				}
				var dec_frauddata FraudData
				if unmErr := dec_frauddata.UnmarshalBER(reconstructed_frauddata, ber.ChildDecodeOptions(opts, "fraudData")...); unmErr != nil {
					return fmt.Errorf("decoding fraudData: %w", unmErr)
				}
				v.FraudData = &dec_frauddata
				if offset < 0 || offset >
					len(content) || n_frauddata < 0 || n_frauddata > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_frauddata
			}
		}
	}
	// Decode extRoutingCategory
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 17 {
				decodedTag_extroutingcategory, n_extroutingcategory, rawVal_extroutingcategory, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding extRoutingCategory: %w", err)
				}
				if decodedTag_extroutingcategory.Class != tag.ClassContextSpecific || decodedTag_extroutingcategory.Number != 17 || decodedTag_extroutingcategory.Constructed != false {
					return fmt.Errorf("decoding extRoutingCategory: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_extroutingcategory)
				}
				decVal_extroutingcategory, intErr := ber.DecodeIntegerValue(rawVal_extroutingcategory)
				if intErr != nil {
					return fmt.Errorf("decoding extRoutingCategory: %w", intErr)
				}
				tmp_extroutingcategory := ExtRoutingCategory(decVal_extroutingcategory)
				v.ExtRoutingCategory = &tmp_extroutingcategory
				if offset < 0 || offset >
					len(content) || n_extroutingcategory < 0 || n_extroutingcategory >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_extroutingcategory
				if !(int64(*v.ExtRoutingCategory) >= 0 && int64(*v.ExtRoutingCategory) <= 2147483647) {
					if constraintErr := ber.CheckDecodedValue(opts, "extRoutingCategory", "(0..2147483647)", fmt.Sprint(int64(*v.ExtRoutingCategory))); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode leaId
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 18 {
				decodedTag_leaid, n_leaid, rawVal_leaid, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding leaId: %w", err)
				}
				if decodedTag_leaid.Class != tag.ClassContextSpecific || decodedTag_leaid.Number != 18 || decodedTag_leaid.Constructed != false {
					return fmt.Errorf("decoding leaId: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_leaid)
				}
				decVal_leaid, intErr := ber.DecodeIntegerValue(rawVal_leaid)
				if intErr != nil {
					return fmt.Errorf("decoding leaId: %w", intErr)
				}
				tmp_leaid := LeaId(decVal_leaid)
				v.LeaId = &tmp_leaid
				if offset < 0 || offset >
					len(content) || n_leaid < 0 || n_leaid > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_leaid
				if !(int64(*v.LeaId) >= 0 && int64(*v.LeaId) <= 65535) {
					if constraintErr := ber.CheckDecodedValue(opts, "leaId", "(0..65535)", fmt.Sprint(int64(*v.LeaId))); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode olcmInfoTable
	v.OlcmInfoTableIndef_ = false
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 19 {
				decodedTag_olcminfotable, n_olcminfotable, rawVal_olcminfotable, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding olcmInfoTable: %w", err)
				}
				if decodedTag_olcminfotable.Class != tag.ClassContextSpecific || decodedTag_olcminfotable.Number != 19 || decodedTag_olcminfotable.Constructed != true {
					return fmt.Errorf("decoding olcmInfoTable: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_olcminfotable)
				}
				reconstructed_olcminfotable, reconstructionErr_olcminfotable := ber.EncodeSequence(rawVal_olcminfotable)
				if reconstructionErr_olcminfotable != nil {
					return fmt.Errorf("decoding olcmInfoTable: %w", reconstructionErr_olcminfotable)
				}
				dec_olcminfotable, unmErr := UnmarshalBEROlcmInfoTable(reconstructed_olcminfotable, ber.ChildDecodeOptions(opts, "olcmInfoTable")...)
				if unmErr != nil {
					return fmt.Errorf("decoding olcmInfoTable: %w", unmErr)
				}
				v.OlcmInfoTable = dec_olcminfotable
				{
					_, tagSz_, _ := ber.DecodeTag(content[offset:])
					if offset < 0 || offset >
						len(content) || tagSz_ < 0 || tagSz_ > len(content[offset:]) {
						return fmt.Errorf("invalid BER content window")
					}

					if offset+tagSz_ < len(content) && content[offset+tagSz_] == 0x80 {
						v.OlcmInfoTableIndef_ = true
					}
				}
				if offset < 0 || offset >
					len(content) || n_olcminfotable < 0 || n_olcminfotable >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_olcminfotable
				if len((v.OlcmInfoTable).Values) < 1 || len((v.OlcmInfoTable).Values) > 7 {
					if constraintErr := ber.CheckDecodedLength(opts, "olcmInfoTable", "SIZE (1..7)", len((v.OlcmInfoTable).Values)); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode callingCategory
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 20 {
				decodedTag_callingcategory, n_callingcategory, rawVal_callingcategory, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding callingCategory: %w", err)
				}
				if decodedTag_callingcategory.Class != tag.ClassContextSpecific || decodedTag_callingcategory.Number != 20 {
					return fmt.Errorf("decoding callingCategory: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_callingcategory)
				}
				decVal_callingcategory, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_callingcategory.Constructed, rawVal_callingcategory, opts...)
				if octetErr != nil {
					return fmt.Errorf("decoding callingCategory: %w", octetErr)
				}
				tmp_callingcategory := CallingCategory(decVal_callingcategory)
				v.CallingCategory = &tmp_callingcategory
				if offset < 0 || offset >
					len(content) || n_callingcategory < 0 || n_callingcategory >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_callingcategory
				if len(*v.CallingCategory) < 1 || len(*v.CallingCategory) > 1 {
					if constraintErr := ber.CheckDecodedLength(opts, "callingCategory", "SIZE (1)", len(*v.CallingCategory)); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode commonMSISDN
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 21 {
				decodedTag_commonmsisdn, n_commonmsisdn, rawVal_commonmsisdn, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding commonMSISDN: %w", err)
				}
				if decodedTag_commonmsisdn.Class != tag.ClassContextSpecific || decodedTag_commonmsisdn.Number != 21 {
					return fmt.Errorf("decoding commonMSISDN: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_commonmsisdn)
				}
				decVal_commonmsisdn, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_commonmsisdn.Constructed, rawVal_commonmsisdn, opts...)
				if octetErr != nil {
					return fmt.Errorf("decoding commonMSISDN: %w", octetErr)
				}
				tmp_commonmsisdn := ISDNAddressString5(decVal_commonmsisdn)
				v.CommonMSISDN = &tmp_commonmsisdn
				if offset < 0 || offset >
					len(content) || n_commonmsisdn < 0 || n_commonmsisdn > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_commonmsisdn
				if len(*v.CommonMSISDN) < 1 || len(*v.CommonMSISDN) > 9 {
					if constraintErr := ber.CheckDecodedLength(opts, "commonMSISDN", "SIZE (1..9)", len(*v.CommonMSISDN)); constraintErr != nil {
						return constraintErr
					}
				}
				if len(*v.CommonMSISDN) < 1 || len(*v.CommonMSISDN) > 20 {
					if constraintErr := ber.CheckDecodedLength(opts, "commonMSISDN", "SIZE (1..20)", len(*v.CommonMSISDN)); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode rgData
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 22 {
				decodedTag_rgdata, n_rgdata, rawVal_rgdata, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding rgData: %w", err)
				}
				if decodedTag_rgdata.Class != tag.ClassContextSpecific || decodedTag_rgdata.Number != 22 || decodedTag_rgdata.Constructed != true {
					return fmt.Errorf("decoding rgData: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_rgdata)
				}
				reconstructed_rgdata, reconstructionErr_rgdata := ber.EncodeSequence(rawVal_rgdata)
				if reconstructionErr_rgdata != nil {
					return fmt.Errorf("decoding rgData: %w", reconstructionErr_rgdata)
				}
				var dec_rgdata RgData
				if unmErr := dec_rgdata.UnmarshalBER(reconstructed_rgdata, ber.ChildDecodeOptions(opts, "rgData")...); unmErr != nil {
					return fmt.Errorf("decoding rgData: %w", unmErr)
				}
				v.RgData = &dec_rgdata
				if offset < 0 || offset >
					len(content) || n_rgdata < 0 || n_rgdata > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_rgdata
			}
		}
	}
	// Decode olcmTraceReference
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 23 {
				decodedTag_olcmtracereference, n_olcmtracereference, rawVal_olcmtracereference, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding olcmTraceReference: %w", err)
				}
				if decodedTag_olcmtracereference.Class != tag.ClassContextSpecific || decodedTag_olcmtracereference.Number != 23 {
					return fmt.Errorf("decoding olcmTraceReference: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_olcmtracereference)
				}
				decVal_olcmtracereference, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_olcmtracereference.Constructed, rawVal_olcmtracereference, opts...)
				if octetErr != nil {
					return fmt.Errorf("decoding olcmTraceReference: %w", octetErr)
				}
				tmp_olcmtracereference := OlcmTraceReference(decVal_olcmtracereference)
				v.OlcmTraceReference = &tmp_olcmtracereference
				if offset < 0 || offset >
					len(content) || n_olcmtracereference < 0 || n_olcmtracereference >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_olcmtracereference
				if len(*v.OlcmTraceReference) < 1 || len(*v.OlcmTraceReference) > 4 {
					if constraintErr := ber.CheckDecodedLength(opts, "olcmTraceReference", "SIZE (1..4)", len(*v.OlcmTraceReference)); constraintErr != nil {
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
			return &ber.DecodeError{Offset: offset, TypeName: "SriResExtension", Cause: extErr_}
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

// MarshalBER encodes RgData to BER format.
func (v *RgData) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: RgData receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *RgData) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if v.NoAnswerTimer != nil {
		if len(*v.NoAnswerTimer) < 1 || len(*v.NoAnswerTimer) > 1 {
			if constraintErr := ber.CheckEncodedLength(opts, "noAnswerTimer", "SIZE (1)", len(*v.NoAnswerTimer)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_noanswertimer, encodeErr_enc_noanswertimer := ber.EncodeOctetString([]byte(*v.NoAnswerTimer))
		if encodeErr_enc_noanswertimer != nil {
			return nil, fmt.Errorf("encoding noAnswerTimer: %w", encodeErr_enc_noanswertimer)
		}
		retagged_enc_noanswertimer, tagErr_enc_noanswertimer := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_noanswertimer)
		if tagErr_enc_noanswertimer != nil {
			return nil, fmt.Errorf("encoding noAnswerTimer: %w", tagErr_enc_noanswertimer)
		}
		enc_noanswertimer = retagged_enc_noanswertimer
		children = append(children, enc_noanswertimer...)
	}
	if v.MemberList != nil {
		if len((v.MemberList).Values) < 1 || len((v.MemberList).Values) > 5 {
			if constraintErr := ber.CheckEncodedLength(opts, "memberList", "SIZE (1..5)", len((v.MemberList).Values)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_memberlist, err := MarshalBERMemberList(v.MemberList, ber.ChildEncodeOptions(opts, "memberList")...)
		if err != nil {
			return nil, fmt.Errorf("encoding memberList: %w", err)
		}
		if v.MemberListIndef_ {
			// Strip the outer SEQUENCE tag from marshalBER output to get raw children.
			_, _, seqContent_, tlvErr_ := ber.DecodeEncodedTLV(enc_memberlist)
			if tlvErr_ != nil {
				return nil, tlvErr_
			}
			{
				var encodeErr error
				enc_memberlist, encodeErr = ber.EncodeConstructedIndefinite(tag.Tag{Class: tag.ClassContextSpecific, Number: 1}, seqContent_)
				if encodeErr != nil {
					return nil, fmt.Errorf("encoding memberList: %w", encodeErr)
				}
			}
		} else {
			retagged_enc_memberlist, tagErr_enc_memberlist := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_memberlist)
			if tagErr_enc_memberlist != nil {
				return nil, fmt.Errorf("encoding memberList: %w", tagErr_enc_memberlist)
			}
			enc_memberlist = retagged_enc_memberlist
		}
		children = append(children, enc_memberlist...)
	}
	if v.AlertingMethod != nil {
		if len(*v.AlertingMethod) < 1 || len(*v.AlertingMethod) > 1 {
			if constraintErr := ber.CheckEncodedLength(opts, "alertingMethod", "SIZE (1)", len(*v.AlertingMethod)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_alertingmethod, encodeErr_enc_alertingmethod := ber.EncodeOctetString([]byte(*v.AlertingMethod))
		if encodeErr_enc_alertingmethod != nil {
			return nil, fmt.Errorf("encoding alertingMethod: %w", encodeErr_enc_alertingmethod)
		}
		retagged_enc_alertingmethod, tagErr_enc_alertingmethod := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_alertingmethod)
		if tagErr_enc_alertingmethod != nil {
			return nil, fmt.Errorf("encoding alertingMethod: %w", tagErr_enc_alertingmethod)
		}
		enc_alertingmethod = retagged_enc_alertingmethod
		children = append(children, enc_alertingmethod...)
	}
	if v.UserType != nil {
		if len(*v.UserType) < 1 || len(*v.UserType) > 1 {
			if constraintErr := ber.CheckEncodedLength(opts, "userType", "SIZE (1)", len(*v.UserType)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_usertype, encodeErr_enc_usertype := ber.EncodeOctetString([]byte(*v.UserType))
		if encodeErr_enc_usertype != nil {
			return nil, fmt.Errorf("encoding userType: %w", encodeErr_enc_usertype)
		}
		retagged_enc_usertype, tagErr_enc_usertype := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, enc_usertype)
		if tagErr_enc_usertype != nil {
			return nil, fmt.Errorf("encoding userType: %w", tagErr_enc_usertype)
		}
		enc_usertype = retagged_enc_usertype
		children = append(children, enc_usertype...)
	}
	if v.DivertedToNbr != nil {
		if len(*v.DivertedToNbr) < 1 || len(*v.DivertedToNbr) > 9 {
			if constraintErr := ber.CheckEncodedLength(opts, "divertedToNbr", "SIZE (1..9)", len(*v.DivertedToNbr)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		if len(*v.DivertedToNbr) < 1 || len(*v.DivertedToNbr) > 20 {
			if constraintErr := ber.CheckEncodedLength(opts, "divertedToNbr", "SIZE (1..20)", len(*v.DivertedToNbr)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_divertedtonbr, encodeErr_enc_divertedtonbr := ber.EncodeOctetString([]byte(*v.DivertedToNbr))
		if encodeErr_enc_divertedtonbr != nil {
			return nil, fmt.Errorf("encoding divertedToNbr: %w", encodeErr_enc_divertedtonbr)
		}
		retagged_enc_divertedtonbr, tagErr_enc_divertedtonbr := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, enc_divertedtonbr)
		if tagErr_enc_divertedtonbr != nil {
			return nil, fmt.Errorf("encoding divertedToNbr: %w", tagErr_enc_divertedtonbr)
		}
		enc_divertedtonbr = retagged_enc_divertedtonbr
		children = append(children, enc_divertedtonbr...)
	}
	if v.MemberOfSuppression != nil {
		enc_memberofsuppression := ber.EncodeNull()
		retagged_enc_memberofsuppression, tagErr_enc_memberofsuppression := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 5, enc_memberofsuppression)
		if tagErr_enc_memberofsuppression != nil {
			return nil, fmt.Errorf("encoding memberOfSuppression: %w", tagErr_enc_memberofsuppression)
		}
		enc_memberofsuppression = retagged_enc_memberofsuppression
		children = append(children, enc_memberofsuppression...)
	}
	if v.Ringbacktone != nil {
		enc_ringbacktone := ber.EncodeNull()
		retagged_enc_ringbacktone, tagErr_enc_ringbacktone := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 6, enc_ringbacktone)
		if tagErr_enc_ringbacktone != nil {
			return nil, fmt.Errorf("encoding ringbacktone: %w", tagErr_enc_ringbacktone)
		}
		enc_ringbacktone = retagged_enc_ringbacktone
		children = append(children, enc_ringbacktone...)
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

// MarshalDER encodes RgData to DER format.
func (v *RgData) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: RgData receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if v.NoAnswerTimer != nil {
		if len(*v.NoAnswerTimer) < 1 || len(*v.NoAnswerTimer) > 1 {
			if constraintErr := ber.CheckEncodedLength(nil, "noAnswerTimer", "SIZE (1)", len(*v.NoAnswerTimer)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_noanswertimer, encodeErr_enc_noanswertimer := ber.EncodeOctetString([]byte(*v.NoAnswerTimer))
		if encodeErr_enc_noanswertimer != nil {
			return nil, fmt.Errorf("encoding noAnswerTimer: %w", encodeErr_enc_noanswertimer)
		}
		retagged_enc_noanswertimer, tagErr_enc_noanswertimer := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_noanswertimer)
		if tagErr_enc_noanswertimer != nil {
			return nil, fmt.Errorf("encoding noAnswerTimer: %w", tagErr_enc_noanswertimer)
		}
		enc_noanswertimer = retagged_enc_noanswertimer
		children = append(children, enc_noanswertimer...)
	}
	if v.MemberList != nil {
		if len((v.MemberList).Values) < 1 || len((v.MemberList).Values) > 5 {
			if constraintErr := ber.CheckEncodedLength(nil, "memberList", "SIZE (1..5)", len((v.MemberList).Values)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_memberlist, err := MarshalDERMemberList(v.MemberList)
		if err != nil {
			return nil, fmt.Errorf("encoding memberList: %w", err)
		}
		retagged_enc_memberlist, tagErr_enc_memberlist := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_memberlist)
		if tagErr_enc_memberlist != nil {
			return nil, fmt.Errorf("encoding memberList: %w", tagErr_enc_memberlist)
		}
		enc_memberlist = retagged_enc_memberlist
		children = append(children, enc_memberlist...)
	}
	if v.AlertingMethod != nil {
		if len(*v.AlertingMethod) < 1 || len(*v.AlertingMethod) > 1 {
			if constraintErr := ber.CheckEncodedLength(nil, "alertingMethod", "SIZE (1)", len(*v.AlertingMethod)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_alertingmethod, encodeErr_enc_alertingmethod := ber.EncodeOctetString([]byte(*v.AlertingMethod))
		if encodeErr_enc_alertingmethod != nil {
			return nil, fmt.Errorf("encoding alertingMethod: %w", encodeErr_enc_alertingmethod)
		}
		retagged_enc_alertingmethod, tagErr_enc_alertingmethod := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_alertingmethod)
		if tagErr_enc_alertingmethod != nil {
			return nil, fmt.Errorf("encoding alertingMethod: %w", tagErr_enc_alertingmethod)
		}
		enc_alertingmethod = retagged_enc_alertingmethod
		children = append(children, enc_alertingmethod...)
	}
	if v.UserType != nil {
		if len(*v.UserType) < 1 || len(*v.UserType) > 1 {
			if constraintErr := ber.CheckEncodedLength(nil, "userType", "SIZE (1)", len(*v.UserType)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_usertype, encodeErr_enc_usertype := ber.EncodeOctetString([]byte(*v.UserType))
		if encodeErr_enc_usertype != nil {
			return nil, fmt.Errorf("encoding userType: %w", encodeErr_enc_usertype)
		}
		retagged_enc_usertype, tagErr_enc_usertype := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, enc_usertype)
		if tagErr_enc_usertype != nil {
			return nil, fmt.Errorf("encoding userType: %w", tagErr_enc_usertype)
		}
		enc_usertype = retagged_enc_usertype
		children = append(children, enc_usertype...)
	}
	if v.DivertedToNbr != nil {
		if len(*v.DivertedToNbr) < 1 || len(*v.DivertedToNbr) > 9 {
			if constraintErr := ber.CheckEncodedLength(nil, "divertedToNbr", "SIZE (1..9)", len(*v.DivertedToNbr)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		if len(*v.DivertedToNbr) < 1 || len(*v.DivertedToNbr) > 20 {
			if constraintErr := ber.CheckEncodedLength(nil, "divertedToNbr", "SIZE (1..20)", len(*v.DivertedToNbr)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_divertedtonbr, encodeErr_enc_divertedtonbr := ber.EncodeOctetString([]byte(*v.DivertedToNbr))
		if encodeErr_enc_divertedtonbr != nil {
			return nil, fmt.Errorf("encoding divertedToNbr: %w", encodeErr_enc_divertedtonbr)
		}
		retagged_enc_divertedtonbr, tagErr_enc_divertedtonbr := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, enc_divertedtonbr)
		if tagErr_enc_divertedtonbr != nil {
			return nil, fmt.Errorf("encoding divertedToNbr: %w", tagErr_enc_divertedtonbr)
		}
		enc_divertedtonbr = retagged_enc_divertedtonbr
		children = append(children, enc_divertedtonbr...)
	}
	if v.MemberOfSuppression != nil {
		enc_memberofsuppression := ber.EncodeNull()
		retagged_enc_memberofsuppression, tagErr_enc_memberofsuppression := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 5, enc_memberofsuppression)
		if tagErr_enc_memberofsuppression != nil {
			return nil, fmt.Errorf("encoding memberOfSuppression: %w", tagErr_enc_memberofsuppression)
		}
		enc_memberofsuppression = retagged_enc_memberofsuppression
		children = append(children, enc_memberofsuppression...)
	}
	if v.Ringbacktone != nil {
		enc_ringbacktone := ber.EncodeNull()
		retagged_enc_ringbacktone, tagErr_enc_ringbacktone := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 6, enc_ringbacktone)
		if tagErr_enc_ringbacktone != nil {
			return nil, fmt.Errorf("encoding ringbacktone: %w", tagErr_enc_ringbacktone)
		}
		enc_ringbacktone = retagged_enc_ringbacktone
		children = append(children, enc_ringbacktone...)
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
		return nil, fmt.Errorf("encoding RgData as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes RgData from BER/DER format.
func (v *RgData) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: RgData destination is nil", ber.ErrInvalidValue)
	}
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = RgData{}
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
		return fmt.Errorf("decoding RgData SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "RgData", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode noAnswerTimer
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
				decodedTag_noanswertimer, n_noanswertimer, rawVal_noanswertimer, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding noAnswerTimer: %w", err)
				}
				if decodedTag_noanswertimer.Class != tag.ClassContextSpecific || decodedTag_noanswertimer.Number != 0 {
					return fmt.Errorf("decoding noAnswerTimer: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_noanswertimer)
				}
				decVal_noanswertimer, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_noanswertimer.Constructed, rawVal_noanswertimer, opts...)
				if octetErr != nil {
					return fmt.Errorf("decoding noAnswerTimer: %w", octetErr)
				}
				tmp_noanswertimer := NoAnswerTimer(decVal_noanswertimer)
				v.NoAnswerTimer = &tmp_noanswertimer
				if offset < 0 || offset >
					len(content) || n_noanswertimer < 0 || n_noanswertimer >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_noanswertimer
				if len(*v.NoAnswerTimer) < 1 || len(*v.NoAnswerTimer) > 1 {
					if constraintErr := ber.CheckDecodedLength(opts, "noAnswerTimer", "SIZE (1)", len(*v.NoAnswerTimer)); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode memberList
	v.MemberListIndef_ = false
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
				decodedTag_memberlist, n_memberlist, rawVal_memberlist, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding memberList: %w", err)
				}
				if decodedTag_memberlist.Class != tag.ClassContextSpecific || decodedTag_memberlist.Number != 1 || decodedTag_memberlist.Constructed != true {
					return fmt.Errorf("decoding memberList: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_memberlist)
				}
				reconstructed_memberlist, reconstructionErr_memberlist := ber.EncodeSequence(rawVal_memberlist)
				if reconstructionErr_memberlist != nil {
					return fmt.Errorf("decoding memberList: %w", reconstructionErr_memberlist)
				}
				dec_memberlist, unmErr := UnmarshalBERMemberList(reconstructed_memberlist, ber.ChildDecodeOptions(opts, "memberList")...)
				if unmErr != nil {
					return fmt.Errorf("decoding memberList: %w", unmErr)
				}
				v.MemberList = dec_memberlist
				{
					_, tagSz_, _ := ber.DecodeTag(content[offset:])
					if offset < 0 || offset >
						len(content) || tagSz_ < 0 || tagSz_ > len(content[offset:]) {
						return fmt.Errorf("invalid BER content window")
					}

					if offset+tagSz_ < len(content) && content[offset+tagSz_] == 0x80 {
						v.MemberListIndef_ = true
					}
				}
				if offset < 0 || offset >
					len(content) || n_memberlist < 0 || n_memberlist >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_memberlist
				if len((v.MemberList).Values) < 1 || len((v.MemberList).Values) > 5 {
					if constraintErr := ber.CheckDecodedLength(opts, "memberList", "SIZE (1..5)", len((v.MemberList).Values)); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode alertingMethod
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2 {
				decodedTag_alertingmethod, n_alertingmethod, rawVal_alertingmethod, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding alertingMethod: %w", err)
				}
				if decodedTag_alertingmethod.Class != tag.ClassContextSpecific || decodedTag_alertingmethod.Number != 2 {
					return fmt.Errorf("decoding alertingMethod: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_alertingmethod)
				}
				decVal_alertingmethod, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_alertingmethod.Constructed, rawVal_alertingmethod, opts...)
				if octetErr != nil {
					return fmt.Errorf("decoding alertingMethod: %w", octetErr)
				}
				tmp_alertingmethod := AlertingMethod(decVal_alertingmethod)
				v.AlertingMethod = &tmp_alertingmethod
				if offset < 0 || offset >
					len(content) || n_alertingmethod < 0 || n_alertingmethod >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_alertingmethod
				if len(*v.AlertingMethod) < 1 || len(*v.AlertingMethod) > 1 {
					if constraintErr := ber.CheckDecodedLength(opts, "alertingMethod", "SIZE (1)", len(*v.AlertingMethod)); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode userType
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3 {
				decodedTag_usertype, n_usertype, rawVal_usertype, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding userType: %w", err)
				}
				if decodedTag_usertype.Class != tag.ClassContextSpecific || decodedTag_usertype.Number != 3 {
					return fmt.Errorf("decoding userType: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_usertype)
				}
				decVal_usertype, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_usertype.Constructed, rawVal_usertype, opts...)
				if octetErr != nil {
					return fmt.Errorf("decoding userType: %w", octetErr)
				}
				tmp_usertype := UserType(decVal_usertype)
				v.UserType = &tmp_usertype
				if offset < 0 || offset >
					len(content) || n_usertype < 0 || n_usertype >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_usertype
				if len(*v.UserType) < 1 || len(*v.UserType) > 1 {
					if constraintErr := ber.CheckDecodedLength(opts, "userType", "SIZE (1)", len(*v.UserType)); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode divertedToNbr
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4 {
				decodedTag_divertedtonbr, n_divertedtonbr, rawVal_divertedtonbr, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding divertedToNbr: %w", err)
				}
				if decodedTag_divertedtonbr.Class != tag.ClassContextSpecific || decodedTag_divertedtonbr.Number != 4 {
					return fmt.Errorf("decoding divertedToNbr: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_divertedtonbr)
				}
				decVal_divertedtonbr, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_divertedtonbr.Constructed, rawVal_divertedtonbr, opts...)
				if octetErr != nil {
					return fmt.Errorf("decoding divertedToNbr: %w", octetErr)
				}
				tmp_divertedtonbr := ISDNAddressString5(decVal_divertedtonbr)
				v.DivertedToNbr = &tmp_divertedtonbr
				if offset < 0 || offset >
					len(content) || n_divertedtonbr < 0 || n_divertedtonbr >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_divertedtonbr
				if len(*v.DivertedToNbr) < 1 || len(*v.DivertedToNbr) > 9 {
					if constraintErr := ber.CheckDecodedLength(opts, "divertedToNbr", "SIZE (1..9)", len(*v.DivertedToNbr)); constraintErr != nil {
						return constraintErr
					}
				}
				if len(*v.DivertedToNbr) < 1 || len(*v.DivertedToNbr) > 20 {
					if constraintErr := ber.CheckDecodedLength(opts, "divertedToNbr", "SIZE (1..20)", len(*v.DivertedToNbr)); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode memberOfSuppression
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 5 {
				decodedTag_memberofsuppression, n_memberofsuppression, rawVal_memberofsuppression, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding memberOfSuppression: %w", err)
				}
				if decodedTag_memberofsuppression.Class != tag.ClassContextSpecific || decodedTag_memberofsuppression.Number != 5 || decodedTag_memberofsuppression.Constructed != false {
					return fmt.Errorf("decoding memberOfSuppression: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_memberofsuppression)
				}
				if len(rawVal_memberofsuppression) != 0 {
					return fmt.Errorf("decoding memberOfSuppression: %w: NULL content length %d", ber.ErrInvalidValue, len(rawVal_memberofsuppression))
				}
				v.MemberOfSuppression = &struct{}{}
				if offset < 0 || offset >
					len(content) || n_memberofsuppression < 0 || n_memberofsuppression >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_memberofsuppression
			}
		}
	}
	// Decode ringbacktone
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 6 {
				decodedTag_ringbacktone, n_ringbacktone, rawVal_ringbacktone, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding ringbacktone: %w", err)
				}
				if decodedTag_ringbacktone.Class != tag.ClassContextSpecific || decodedTag_ringbacktone.Number != 6 || decodedTag_ringbacktone.Constructed != false {
					return fmt.Errorf("decoding ringbacktone: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_ringbacktone)
				}
				if len(rawVal_ringbacktone) != 0 {
					return fmt.Errorf("decoding ringbacktone: %w: NULL content length %d", ber.ErrInvalidValue, len(rawVal_ringbacktone))
				}
				v.Ringbacktone = &struct{}{}
				if offset < 0 || offset >
					len(content) || n_ringbacktone < 0 || n_ringbacktone >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_ringbacktone
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:], opts...)
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "RgData", Cause: extErr_}
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

// MarshalBERMemberList encodes a MemberList list to BER.
func MarshalBERMemberList(collection *MemberList, opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	if collection == nil {
		return nil, fmt.Errorf("%w: required collection is nil", ber.ErrInvalidValue)
	}
	encoded, err := marshalBERMemberList(collection, opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, collection.berOriginal_, collection.berSnapshot_, opts), nil
}
func marshalBERMemberList(collection *MemberList, opts ...ber.EncodeOption) ([]byte, error) {
	list := collection.Values
	if len(list) < 1 || len(list) > 5 {
		if constraintErr := ber.CheckEncodedLength(opts, "MemberList", "SIZE (1..5)", len(list)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	var children []byte
	for elemIndex, elem := range list {
		if len(elem) < 1 || len(elem) > 9 {
			if constraintErr := ber.CheckEncodedLength(opts, fmt.Sprintf("element[%d]", elemIndex), "SIZE (1..9)", len(elem)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		if len(elem) < 1 || len(elem) > 20 {
			if constraintErr := ber.CheckEncodedLength(opts, fmt.Sprintf("element[%d]", elemIndex), "SIZE (1..20)", len(elem)); constraintErr != nil {
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

// MarshalDERMemberList encodes a MemberList list to DER.
func MarshalDERMemberList(collection *MemberList) ([]byte, error) {
	if collection == nil {
		return nil, fmt.Errorf("%w: required collection is nil", ber.ErrInvalidValue)
	}
	list := collection.Values
	if len(list) < 1 || len(list) > 5 {
		if constraintErr := ber.CheckEncodedLength(nil, "MemberList", "SIZE (1..5)", len(list)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	var children []byte
	for elemIndex, elem := range list {
		if len(elem) < 1 || len(elem) > 9 {
			if constraintErr := ber.CheckEncodedLength(nil, fmt.Sprintf("element[%d]", elemIndex), "SIZE (1..9)", len(elem)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		if len(elem) < 1 || len(elem) > 20 {
			if constraintErr := ber.CheckEncodedLength(nil, fmt.Sprintf("element[%d]", elemIndex), "SIZE (1..20)", len(elem)); constraintErr != nil {
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
		return nil, fmt.Errorf("encoding MemberList as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBERMemberList decodes a MemberList list from BER.
func UnmarshalBERMemberList(data []byte, opts ...ber.DecodeOption) (returnValue *MemberList, returnErr error) {
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return nil, err
	}
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return nil, fmt.Errorf("decoding MemberList: %w", err)
	}
	if total != len(data) {
		return nil, &ber.DecodeError{Offset: total, TypeName: "MemberList", Cause: ber.ErrExtraData}
	}
	var result []ISDNAddressString5
	offset := 0
	for offset < len(content) {
		elementData := content[offset:]
		val, n, osErr := ber.DecodeOctetString(elementData, opts...)
		if osErr != nil {
			return nil, fmt.Errorf("decoding element: %w", osErr)
		}
		if len(val) < 1 || len(val) > 9 {
			if constraintErr := ber.CheckDecodedLength(opts, fmt.Sprintf("element[%d]", len(result)), "SIZE (1..9)", len(val)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		if len(val) < 1 || len(val) > 20 {
			if constraintErr := ber.CheckDecodedLength(opts, fmt.Sprintf("element[%d]", len(result)), "SIZE (1..20)", len(val)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		result = append(result, ISDNAddressString5(val))
		if offset < 0 || offset >
			len(content) || n < 0 || n > len(content[offset:]) {
			return nil, fmt.Errorf("invalid BER content window")
		}

		offset += n
	}
	if len(result) < 1 || len(result) > 5 {
		if constraintErr := ber.CheckDecodedLength(opts, "MemberList", "SIZE (1..5)", len(result)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	decoded := &MemberList{Values: result}
	if ber.BERNeedsPreservation(opts) {
		var snapshotReports ber.ViolationLog
		snapshot, snapshotErr := MarshalBERMemberList(decoded, ber.WithConstraintTolerance(&snapshotReports))
		if snapshotErr != nil {
			return nil, snapshotErr
		}
		decoded.berOriginal_ = append([]byte(nil), data...)
		decoded.berSnapshot_ = snapshot
	}
	return decoded, nil
}

// MarshalBER encodes PrefCarrierIdList to BER format.
func (v *PrefCarrierIdList) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: PrefCarrierIdList receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *PrefCarrierIdList) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if len(v.PrefCarrierIdCode1) < 3 || len(v.PrefCarrierIdCode1) > 3 {
		if constraintErr := ber.CheckEncodedLength(opts, "prefCarrierIdCode1", "SIZE (3)", len(v.PrefCarrierIdCode1)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_prefcarrieridcode1, encodeErr_enc_prefcarrieridcode1 := ber.EncodeOctetString([]byte(v.PrefCarrierIdCode1))
	if encodeErr_enc_prefcarrieridcode1 != nil {
		return nil, fmt.Errorf("encoding prefCarrierIdCode1: %w", encodeErr_enc_prefcarrieridcode1)
	}
	retagged_enc_prefcarrieridcode1, tagErr_enc_prefcarrieridcode1 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_prefcarrieridcode1)
	if tagErr_enc_prefcarrieridcode1 != nil {
		return nil, fmt.Errorf("encoding prefCarrierIdCode1: %w", tagErr_enc_prefcarrieridcode1)
	}
	enc_prefcarrieridcode1 = retagged_enc_prefcarrieridcode1
	children = append(children, enc_prefcarrieridcode1...)
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

// MarshalDER encodes PrefCarrierIdList to DER format.
func (v *PrefCarrierIdList) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: PrefCarrierIdList receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if len(v.PrefCarrierIdCode1) < 3 || len(v.PrefCarrierIdCode1) > 3 {
		if constraintErr := ber.CheckEncodedLength(nil, "prefCarrierIdCode1", "SIZE (3)", len(v.PrefCarrierIdCode1)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_prefcarrieridcode1, encodeErr_enc_prefcarrieridcode1 := ber.EncodeOctetString([]byte(v.PrefCarrierIdCode1))
	if encodeErr_enc_prefcarrieridcode1 != nil {
		return nil, fmt.Errorf("encoding prefCarrierIdCode1: %w", encodeErr_enc_prefcarrieridcode1)
	}
	retagged_enc_prefcarrieridcode1, tagErr_enc_prefcarrieridcode1 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_prefcarrieridcode1)
	if tagErr_enc_prefcarrieridcode1 != nil {
		return nil, fmt.Errorf("encoding prefCarrierIdCode1: %w", tagErr_enc_prefcarrieridcode1)
	}
	enc_prefcarrieridcode1 = retagged_enc_prefcarrieridcode1
	children = append(children, enc_prefcarrieridcode1...)
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
		return nil, fmt.Errorf("encoding PrefCarrierIdList as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes PrefCarrierIdList from BER/DER format.
func (v *PrefCarrierIdList) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: PrefCarrierIdList destination is nil", ber.ErrInvalidValue)
	}
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = PrefCarrierIdList{}
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
		return fmt.Errorf("decoding PrefCarrierIdList SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "PrefCarrierIdList", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode prefCarrierIdCode1
	if offset >= len(content) {
		return fmt.Errorf("missing required field prefCarrierIdCode1")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 0 {
			return fmt.Errorf("expected tag [%s %d] for prefCarrierIdCode1, got %s", "CONTEXT", 0, reqTag_)
		}
	}
	decodedTag_prefcarrieridcode1, n_prefcarrieridcode1, rawVal_prefcarrieridcode1, err := ber.DecodeTLV(content[offset:], opts...)
	if err != nil {
		return fmt.Errorf("decoding prefCarrierIdCode1: %w", err)
	}
	if decodedTag_prefcarrieridcode1.Class != tag.ClassContextSpecific || decodedTag_prefcarrieridcode1.Number != 0 {
		return fmt.Errorf("decoding prefCarrierIdCode1: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_prefcarrieridcode1)
	}
	decVal_prefcarrieridcode1, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_prefcarrieridcode1.Constructed, rawVal_prefcarrieridcode1, opts...)
	if octetErr != nil {
		return fmt.Errorf("decoding prefCarrierIdCode1: %w", octetErr)
	}
	v.PrefCarrierIdCode1 = CarrierIdCode(decVal_prefcarrieridcode1)
	if offset < 0 || offset >
		len(content) || n_prefcarrieridcode1 < 0 || n_prefcarrieridcode1 >
		len(content[offset:]) {
		return fmt.Errorf("invalid BER content window")
	}

	offset += n_prefcarrieridcode1
	if len(v.PrefCarrierIdCode1) < 3 || len(v.PrefCarrierIdCode1) > 3 {
		if constraintErr := ber.CheckDecodedLength(opts, "prefCarrierIdCode1", "SIZE (3)", len(v.PrefCarrierIdCode1)); constraintErr != nil {
			return constraintErr
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:], opts...)
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "PrefCarrierIdList", Cause: extErr_}
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

// MarshalBER encodes ANSIIsdArgExt to BER format.
func (v *ANSIIsdArgExt) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: ANSIIsdArgExt receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *ANSIIsdArgExt) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if v.PrefCarrierIdList != nil {
		enc_prefcarrieridlist, err := v.PrefCarrierIdList.MarshalBER(ber.ChildEncodeOptions(opts, "prefCarrierIdList")...)
		if err != nil {
			return nil, fmt.Errorf("encoding prefCarrierIdList: %w", err)
		}
		retagged_enc_prefcarrieridlist, tagErr_enc_prefcarrieridlist := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_prefcarrieridlist)
		if tagErr_enc_prefcarrieridlist != nil {
			return nil, fmt.Errorf("encoding prefCarrierIdList: %w", tagErr_enc_prefcarrieridlist)
		}
		enc_prefcarrieridlist = retagged_enc_prefcarrieridlist
		children = append(children, enc_prefcarrieridlist...)
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
	return ber.EncodeConstructed(tag.Tag{Class: tag.ClassPrivate, Number: 30, Constructed: true}, children)
}

// MarshalDER encodes ANSIIsdArgExt to DER format.
func (v *ANSIIsdArgExt) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: ANSIIsdArgExt receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if v.PrefCarrierIdList != nil {
		enc_prefcarrieridlist, err := v.PrefCarrierIdList.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding prefCarrierIdList: %w", err)
		}
		retagged_enc_prefcarrieridlist, tagErr_enc_prefcarrieridlist := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_prefcarrieridlist)
		if tagErr_enc_prefcarrieridlist != nil {
			return nil, fmt.Errorf("encoding prefCarrierIdList: %w", tagErr_enc_prefcarrieridlist)
		}
		enc_prefcarrieridlist = retagged_enc_prefcarrieridlist
		children = append(children, enc_prefcarrieridlist...)
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
	retagged_encoded, tagErr_encoded := ber.EncodeImplicitTagWithClass(tag.ClassPrivate, 30, encoded)
	if tagErr_encoded != nil {
		return nil, fmt.Errorf("encoding ANSIIsdArgExt: %w", tagErr_encoded)
	}
	encoded = retagged_encoded
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding ANSIIsdArgExt as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes ANSIIsdArgExt from BER/DER format.
func (v *ANSIIsdArgExt) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: ANSIIsdArgExt destination is nil", ber.ErrInvalidValue)
	}
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = ANSIIsdArgExt{}
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
	decodedTag, content, total, err := ber.DecodeConstructedContent(data, opts...)
	if err != nil {
		return fmt.Errorf("decoding ANSIIsdArgExt: %w", err)
	}
	if decodedTag.Class != tag.ClassPrivate || decodedTag.Number != 30 || !decodedTag.Constructed {
		return fmt.Errorf("decoding ANSIIsdArgExt: %w: expected tag [PRIVATE 30], got %s", ber.ErrInvalidTag, decodedTag)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "ANSIIsdArgExt", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode prefCarrierIdList
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
				decodedTag_prefcarrieridlist, n_prefcarrieridlist, rawVal_prefcarrieridlist, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding prefCarrierIdList: %w", err)
				}
				if decodedTag_prefcarrieridlist.Class != tag.ClassContextSpecific || decodedTag_prefcarrieridlist.Number != 0 || decodedTag_prefcarrieridlist.Constructed != true {
					return fmt.Errorf("decoding prefCarrierIdList: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_prefcarrieridlist)
				}
				reconstructed_prefcarrieridlist, reconstructionErr_prefcarrieridlist := ber.EncodeSequence(rawVal_prefcarrieridlist)
				if reconstructionErr_prefcarrieridlist != nil {
					return fmt.Errorf("decoding prefCarrierIdList: %w", reconstructionErr_prefcarrieridlist)
				}
				var dec_prefcarrieridlist PrefCarrierIdList
				if unmErr := dec_prefcarrieridlist.UnmarshalBER(reconstructed_prefcarrieridlist, ber.ChildDecodeOptions(opts, "prefCarrierIdList")...); unmErr != nil {
					return fmt.Errorf("decoding prefCarrierIdList: %w", unmErr)
				}
				v.PrefCarrierIdList = &dec_prefcarrieridlist
				if offset < 0 || offset >
					len(content) || n_prefcarrieridlist < 0 || n_prefcarrieridlist >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_prefcarrieridlist
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:], opts...)
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "ANSIIsdArgExt", Cause: extErr_}
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

// MarshalBER encodes ANSISriResExt to BER format.
func (v *ANSISriResExt) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: ANSISriResExt receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *ANSISriResExt) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if v.PrefCarrierIdList != nil {
		enc_prefcarrieridlist, err := v.PrefCarrierIdList.MarshalBER(ber.ChildEncodeOptions(opts, "prefCarrierIdList")...)
		if err != nil {
			return nil, fmt.Errorf("encoding prefCarrierIdList: %w", err)
		}
		retagged_enc_prefcarrieridlist, tagErr_enc_prefcarrieridlist := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_prefcarrieridlist)
		if tagErr_enc_prefcarrieridlist != nil {
			return nil, fmt.Errorf("encoding prefCarrierIdList: %w", tagErr_enc_prefcarrieridlist)
		}
		enc_prefcarrieridlist = retagged_enc_prefcarrieridlist
		children = append(children, enc_prefcarrieridlist...)
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
	return ber.EncodeConstructed(tag.Tag{Class: tag.ClassPrivate, Number: 30, Constructed: true}, children)
}

// MarshalDER encodes ANSISriResExt to DER format.
func (v *ANSISriResExt) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: ANSISriResExt receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if v.PrefCarrierIdList != nil {
		enc_prefcarrieridlist, err := v.PrefCarrierIdList.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding prefCarrierIdList: %w", err)
		}
		retagged_enc_prefcarrieridlist, tagErr_enc_prefcarrieridlist := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_prefcarrieridlist)
		if tagErr_enc_prefcarrieridlist != nil {
			return nil, fmt.Errorf("encoding prefCarrierIdList: %w", tagErr_enc_prefcarrieridlist)
		}
		enc_prefcarrieridlist = retagged_enc_prefcarrieridlist
		children = append(children, enc_prefcarrieridlist...)
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
	retagged_encoded, tagErr_encoded := ber.EncodeImplicitTagWithClass(tag.ClassPrivate, 30, encoded)
	if tagErr_encoded != nil {
		return nil, fmt.Errorf("encoding ANSISriResExt: %w", tagErr_encoded)
	}
	encoded = retagged_encoded
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding ANSISriResExt as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes ANSISriResExt from BER/DER format.
func (v *ANSISriResExt) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: ANSISriResExt destination is nil", ber.ErrInvalidValue)
	}
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = ANSISriResExt{}
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
	decodedTag, content, total, err := ber.DecodeConstructedContent(data, opts...)
	if err != nil {
		return fmt.Errorf("decoding ANSISriResExt: %w", err)
	}
	if decodedTag.Class != tag.ClassPrivate || decodedTag.Number != 30 || !decodedTag.Constructed {
		return fmt.Errorf("decoding ANSISriResExt: %w: expected tag [PRIVATE 30], got %s", ber.ErrInvalidTag, decodedTag)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "ANSISriResExt", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode prefCarrierIdList
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
				decodedTag_prefcarrieridlist, n_prefcarrieridlist, rawVal_prefcarrieridlist, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding prefCarrierIdList: %w", err)
				}
				if decodedTag_prefcarrieridlist.Class != tag.ClassContextSpecific || decodedTag_prefcarrieridlist.Number != 0 || decodedTag_prefcarrieridlist.Constructed != true {
					return fmt.Errorf("decoding prefCarrierIdList: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_prefcarrieridlist)
				}
				reconstructed_prefcarrieridlist, reconstructionErr_prefcarrieridlist := ber.EncodeSequence(rawVal_prefcarrieridlist)
				if reconstructionErr_prefcarrieridlist != nil {
					return fmt.Errorf("decoding prefCarrierIdList: %w", reconstructionErr_prefcarrieridlist)
				}
				var dec_prefcarrieridlist PrefCarrierIdList
				if unmErr := dec_prefcarrieridlist.UnmarshalBER(reconstructed_prefcarrieridlist, ber.ChildDecodeOptions(opts, "prefCarrierIdList")...); unmErr != nil {
					return fmt.Errorf("decoding prefCarrierIdList: %w", unmErr)
				}
				v.PrefCarrierIdList = &dec_prefcarrieridlist
				if offset < 0 || offset >
					len(content) || n_prefcarrieridlist < 0 || n_prefcarrieridlist >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_prefcarrieridlist
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:], opts...)
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "ANSISriResExt", Cause: extErr_}
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

// MarshalBER encodes CanLocArgExt to BER format.
func (v *CanLocArgExt) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: CanLocArgExt receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *CanLocArgExt) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if v.Termination != nil {
		if len(v.Termination) < 1 || len(v.Termination) > 1 {
			if constraintErr := ber.CheckEncodedLength(opts, "termination", "SIZE (1)", len(v.Termination)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_termination, encodeErr_enc_termination := ber.EncodeOctetString(v.Termination)
		if encodeErr_enc_termination != nil {
			return nil, fmt.Errorf("encoding termination: %w", encodeErr_enc_termination)
		}
		retagged_enc_termination, tagErr_enc_termination := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_termination)
		if tagErr_enc_termination != nil {
			return nil, fmt.Errorf("encoding termination: %w", tagErr_enc_termination)
		}
		enc_termination = retagged_enc_termination
		children = append(children, enc_termination...)
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
	return ber.EncodeConstructed(tag.Tag{Class: tag.ClassPrivate, Number: 0, Constructed: true}, children)
}

// MarshalDER encodes CanLocArgExt to DER format.
func (v *CanLocArgExt) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: CanLocArgExt receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if v.Termination != nil {
		if len(v.Termination) < 1 || len(v.Termination) > 1 {
			if constraintErr := ber.CheckEncodedLength(nil, "termination", "SIZE (1)", len(v.Termination)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_termination, encodeErr_enc_termination := ber.EncodeOctetString(v.Termination)
		if encodeErr_enc_termination != nil {
			return nil, fmt.Errorf("encoding termination: %w", encodeErr_enc_termination)
		}
		retagged_enc_termination, tagErr_enc_termination := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_termination)
		if tagErr_enc_termination != nil {
			return nil, fmt.Errorf("encoding termination: %w", tagErr_enc_termination)
		}
		enc_termination = retagged_enc_termination
		children = append(children, enc_termination...)
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
	retagged_encoded, tagErr_encoded := ber.EncodeImplicitTagWithClass(tag.ClassPrivate, 0, encoded)
	if tagErr_encoded != nil {
		return nil, fmt.Errorf("encoding CanLocArgExt: %w", tagErr_encoded)
	}
	encoded = retagged_encoded
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding CanLocArgExt as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes CanLocArgExt from BER/DER format.
func (v *CanLocArgExt) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: CanLocArgExt destination is nil", ber.ErrInvalidValue)
	}
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = CanLocArgExt{}
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
	decodedTag, content, total, err := ber.DecodeConstructedContent(data, opts...)
	if err != nil {
		return fmt.Errorf("decoding CanLocArgExt: %w", err)
	}
	if decodedTag.Class != tag.ClassPrivate || decodedTag.Number != 0 || !decodedTag.Constructed {
		return fmt.Errorf("decoding CanLocArgExt: %w: expected tag [PRIVATE 0], got %s", ber.ErrInvalidTag, decodedTag)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "CanLocArgExt", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode termination
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
				decodedTag_termination, n_termination, rawVal_termination, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding termination: %w", err)
				}
				if decodedTag_termination.Class != tag.ClassContextSpecific || decodedTag_termination.Number != 0 {
					return fmt.Errorf("decoding termination: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_termination)
				}
				decVal_termination, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_termination.Constructed, rawVal_termination, opts...)
				if octetErr != nil {
					return fmt.Errorf("decoding termination: %w", octetErr)
				}
				tmp_termination := decVal_termination
				v.Termination = tmp_termination
				if offset < 0 || offset >
					len(content) || n_termination < 0 || n_termination >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_termination
				if len(v.Termination) < 1 || len(v.Termination) > 1 {
					if constraintErr := ber.CheckDecodedLength(opts, "termination", "SIZE (1)", len(v.Termination)); constraintErr != nil {
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
			return &ber.DecodeError{Offset: offset, TypeName: "CanLocArgExt", Cause: extErr_}
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

// MarshalBER encodes ATMargExt to BER format.
func (v *ATMargExt) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: ATMargExt receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *ATMargExt) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
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
	if v.LeaId != nil {
		if !(int64(*v.LeaId) >= 0 && int64(*v.LeaId) <= 65535) {
			if constraintErr := ber.CheckEncodedValue(opts, "leaId", "(0..65535)", fmt.Sprint(int64(*v.LeaId))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_leaid := ber.EncodeInteger(int64(*v.LeaId))
		retagged_enc_leaid, tagErr_enc_leaid := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_leaid)
		if tagErr_enc_leaid != nil {
			return nil, fmt.Errorf("encoding leaId: %w", tagErr_enc_leaid)
		}
		enc_leaid = retagged_enc_leaid
		children = append(children, enc_leaid...)
	}
	if v.OlcmInfoTable != nil {
		if len((v.OlcmInfoTable).Values) < 1 || len((v.OlcmInfoTable).Values) > 7 {
			if constraintErr := ber.CheckEncodedLength(opts, "olcmInfoTable", "SIZE (1..7)", len((v.OlcmInfoTable).Values)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_olcminfotable, err := MarshalBEROlcmInfoTable(v.OlcmInfoTable, ber.ChildEncodeOptions(opts, "olcmInfoTable")...)
		if err != nil {
			return nil, fmt.Errorf("encoding olcmInfoTable: %w", err)
		}
		if v.OlcmInfoTableIndef_ {
			// Strip the outer SEQUENCE tag from marshalBER output to get raw children.
			_, _, seqContent_, tlvErr_ := ber.DecodeEncodedTLV(enc_olcminfotable)
			if tlvErr_ != nil {
				return nil, tlvErr_
			}
			{
				var encodeErr error
				enc_olcminfotable, encodeErr = ber.EncodeConstructedIndefinite(tag.Tag{Class: tag.ClassContextSpecific, Number: 3}, seqContent_)
				if encodeErr != nil {
					return nil, fmt.Errorf("encoding olcmInfoTable: %w", encodeErr)
				}
			}
		} else {
			retagged_enc_olcminfotable, tagErr_enc_olcminfotable := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, enc_olcminfotable)
			if tagErr_enc_olcminfotable != nil {
				return nil, fmt.Errorf("encoding olcmInfoTable: %w", tagErr_enc_olcminfotable)
			}
			enc_olcminfotable = retagged_enc_olcminfotable
		}
		children = append(children, enc_olcminfotable...)
	}
	if v.OlcmTraceReference != nil {
		if len(*v.OlcmTraceReference) < 1 || len(*v.OlcmTraceReference) > 4 {
			if constraintErr := ber.CheckEncodedLength(opts, "olcmTraceReference", "SIZE (1..4)", len(*v.OlcmTraceReference)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_olcmtracereference, encodeErr_enc_olcmtracereference := ber.EncodeOctetString([]byte(*v.OlcmTraceReference))
		if encodeErr_enc_olcmtracereference != nil {
			return nil, fmt.Errorf("encoding olcmTraceReference: %w", encodeErr_enc_olcmtracereference)
		}
		retagged_enc_olcmtracereference, tagErr_enc_olcmtracereference := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, enc_olcmtracereference)
		if tagErr_enc_olcmtracereference != nil {
			return nil, fmt.Errorf("encoding olcmTraceReference: %w", tagErr_enc_olcmtracereference)
		}
		enc_olcmtracereference = retagged_enc_olcmtracereference
		children = append(children, enc_olcmtracereference...)
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
	return ber.EncodeConstructed(tag.Tag{Class: tag.ClassPrivate, Number: 0, Constructed: true}, children)
}

// MarshalDER encodes ATMargExt to DER format.
func (v *ATMargExt) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: ATMargExt receiver is nil", ber.ErrInvalidValue)
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
	if v.LeaId != nil {
		if !(int64(*v.LeaId) >= 0 && int64(*v.LeaId) <= 65535) {
			if constraintErr := ber.CheckEncodedValue(nil, "leaId", "(0..65535)", fmt.Sprint(int64(*v.LeaId))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_leaid := ber.EncodeInteger(int64(*v.LeaId))
		retagged_enc_leaid, tagErr_enc_leaid := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_leaid)
		if tagErr_enc_leaid != nil {
			return nil, fmt.Errorf("encoding leaId: %w", tagErr_enc_leaid)
		}
		enc_leaid = retagged_enc_leaid
		children = append(children, enc_leaid...)
	}
	if v.OlcmInfoTable != nil {
		if len((v.OlcmInfoTable).Values) < 1 || len((v.OlcmInfoTable).Values) > 7 {
			if constraintErr := ber.CheckEncodedLength(nil, "olcmInfoTable", "SIZE (1..7)", len((v.OlcmInfoTable).Values)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_olcminfotable, err := MarshalDEROlcmInfoTable(v.OlcmInfoTable)
		if err != nil {
			return nil, fmt.Errorf("encoding olcmInfoTable: %w", err)
		}
		retagged_enc_olcminfotable, tagErr_enc_olcminfotable := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, enc_olcminfotable)
		if tagErr_enc_olcminfotable != nil {
			return nil, fmt.Errorf("encoding olcmInfoTable: %w", tagErr_enc_olcminfotable)
		}
		enc_olcminfotable = retagged_enc_olcminfotable
		children = append(children, enc_olcminfotable...)
	}
	if v.OlcmTraceReference != nil {
		if len(*v.OlcmTraceReference) < 1 || len(*v.OlcmTraceReference) > 4 {
			if constraintErr := ber.CheckEncodedLength(nil, "olcmTraceReference", "SIZE (1..4)", len(*v.OlcmTraceReference)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_olcmtracereference, encodeErr_enc_olcmtracereference := ber.EncodeOctetString([]byte(*v.OlcmTraceReference))
		if encodeErr_enc_olcmtracereference != nil {
			return nil, fmt.Errorf("encoding olcmTraceReference: %w", encodeErr_enc_olcmtracereference)
		}
		retagged_enc_olcmtracereference, tagErr_enc_olcmtracereference := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, enc_olcmtracereference)
		if tagErr_enc_olcmtracereference != nil {
			return nil, fmt.Errorf("encoding olcmTraceReference: %w", tagErr_enc_olcmtracereference)
		}
		enc_olcmtracereference = retagged_enc_olcmtracereference
		children = append(children, enc_olcmtracereference...)
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
	retagged_encoded, tagErr_encoded := ber.EncodeImplicitTagWithClass(tag.ClassPrivate, 0, encoded)
	if tagErr_encoded != nil {
		return nil, fmt.Errorf("encoding ATMargExt: %w", tagErr_encoded)
	}
	encoded = retagged_encoded
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding ATMargExt as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes ATMargExt from BER/DER format.
func (v *ATMargExt) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: ATMargExt destination is nil", ber.ErrInvalidValue)
	}
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = ATMargExt{}
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
	decodedTag, content, total, err := ber.DecodeConstructedContent(data, opts...)
	if err != nil {
		return fmt.Errorf("decoding ATMargExt: %w", err)
	}
	if decodedTag.Class != tag.ClassPrivate || decodedTag.Number != 0 || !decodedTag.Constructed {
		return fmt.Errorf("decoding ATMargExt: %w: expected tag [PRIVATE 0], got %s", ber.ErrInvalidTag, decodedTag)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "ATMargExt", Cause: ber.ErrExtraData}
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
				tmp_tracereference := TraceReference5(decVal_tracereference)
				v.TraceReference = &tmp_tracereference
				if offset < 0 || offset >
					len(content) || n_tracereference < 0 || n_tracereference >
					len(content[offset:]) {
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
				tmp_tracetype := TraceType5(decVal_tracetype)
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
	// Decode leaId
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2 {
				decodedTag_leaid, n_leaid, rawVal_leaid, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding leaId: %w", err)
				}
				if decodedTag_leaid.Class != tag.ClassContextSpecific || decodedTag_leaid.Number != 2 || decodedTag_leaid.Constructed != false {
					return fmt.Errorf("decoding leaId: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_leaid)
				}
				decVal_leaid, intErr := ber.DecodeIntegerValue(rawVal_leaid)
				if intErr != nil {
					return fmt.Errorf("decoding leaId: %w", intErr)
				}
				tmp_leaid := LeaId(decVal_leaid)
				v.LeaId = &tmp_leaid
				if offset < 0 || offset >
					len(content) || n_leaid < 0 || n_leaid > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_leaid
				if !(int64(*v.LeaId) >= 0 && int64(*v.LeaId) <= 65535) {
					if constraintErr := ber.CheckDecodedValue(opts, "leaId", "(0..65535)", fmt.Sprint(int64(*v.LeaId))); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode olcmInfoTable
	v.OlcmInfoTableIndef_ = false
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3 {
				decodedTag_olcminfotable, n_olcminfotable, rawVal_olcminfotable, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding olcmInfoTable: %w", err)
				}
				if decodedTag_olcminfotable.Class != tag.ClassContextSpecific || decodedTag_olcminfotable.Number != 3 || decodedTag_olcminfotable.Constructed != true {
					return fmt.Errorf("decoding olcmInfoTable: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_olcminfotable)
				}
				reconstructed_olcminfotable, reconstructionErr_olcminfotable := ber.EncodeSequence(rawVal_olcminfotable)
				if reconstructionErr_olcminfotable != nil {
					return fmt.Errorf("decoding olcmInfoTable: %w", reconstructionErr_olcminfotable)
				}
				dec_olcminfotable, unmErr := UnmarshalBEROlcmInfoTable(reconstructed_olcminfotable, ber.ChildDecodeOptions(opts, "olcmInfoTable")...)
				if unmErr != nil {
					return fmt.Errorf("decoding olcmInfoTable: %w", unmErr)
				}
				v.OlcmInfoTable = dec_olcminfotable
				{
					_, tagSz_, _ := ber.DecodeTag(content[offset:])
					if offset < 0 || offset >
						len(content) || tagSz_ < 0 || tagSz_ > len(content[offset:]) {
						return fmt.Errorf("invalid BER content window")
					}

					if offset+tagSz_ < len(content) && content[offset+tagSz_] == 0x80 {
						v.OlcmInfoTableIndef_ = true
					}
				}
				if offset < 0 || offset >
					len(content) || n_olcminfotable < 0 || n_olcminfotable >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_olcminfotable
				if len((v.OlcmInfoTable).Values) < 1 || len((v.OlcmInfoTable).Values) > 7 {
					if constraintErr := ber.CheckDecodedLength(opts, "olcmInfoTable", "SIZE (1..7)", len((v.OlcmInfoTable).Values)); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode olcmTraceReference
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4 {
				decodedTag_olcmtracereference, n_olcmtracereference, rawVal_olcmtracereference, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding olcmTraceReference: %w", err)
				}
				if decodedTag_olcmtracereference.Class != tag.ClassContextSpecific || decodedTag_olcmtracereference.Number != 4 {
					return fmt.Errorf("decoding olcmTraceReference: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_olcmtracereference)
				}
				decVal_olcmtracereference, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_olcmtracereference.Constructed, rawVal_olcmtracereference, opts...)
				if octetErr != nil {
					return fmt.Errorf("decoding olcmTraceReference: %w", octetErr)
				}
				tmp_olcmtracereference := OlcmTraceReference(decVal_olcmtracereference)
				v.OlcmTraceReference = &tmp_olcmtracereference
				if offset < 0 || offset >
					len(content) || n_olcmtracereference < 0 || n_olcmtracereference >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_olcmtracereference
				if len(*v.OlcmTraceReference) < 1 || len(*v.OlcmTraceReference) > 4 {
					if constraintErr := ber.CheckDecodedLength(opts, "olcmTraceReference", "SIZE (1..4)", len(*v.OlcmTraceReference)); constraintErr != nil {
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
			return &ber.DecodeError{Offset: offset, TypeName: "ATMargExt", Cause: extErr_}
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

// MarshalBEROlcmInfoTable encodes a OlcmInfoTable list to BER.
func MarshalBEROlcmInfoTable(collection *OlcmInfoTable, opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	if collection == nil {
		return nil, fmt.Errorf("%w: required collection is nil", ber.ErrInvalidValue)
	}
	encoded, err := marshalBEROlcmInfoTable(collection, opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, collection.berOriginal_, collection.berSnapshot_, opts), nil
}
func marshalBEROlcmInfoTable(collection *OlcmInfoTable, opts ...ber.EncodeOption) ([]byte, error) {
	list := collection.Values
	if len(list) < 1 || len(list) > 7 {
		if constraintErr := ber.CheckEncodedLength(opts, "OlcmInfoTable", "SIZE (1..7)", len(list)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	var children []byte
	for elemIndex, elem := range list {
		enc, err := elem.MarshalBER(ber.ChildEncodeOptions(opts, fmt.Sprintf("element[%d]", elemIndex))...)
		if err != nil {
			return nil, fmt.Errorf("encoding element: %w", err)
		}
		children = append(children, enc...)
	}
	return ber.EncodeSequence(children)
}

// MarshalDEROlcmInfoTable encodes a OlcmInfoTable list to DER.
func MarshalDEROlcmInfoTable(collection *OlcmInfoTable) ([]byte, error) {
	if collection == nil {
		return nil, fmt.Errorf("%w: required collection is nil", ber.ErrInvalidValue)
	}
	list := collection.Values
	if len(list) < 1 || len(list) > 7 {
		if constraintErr := ber.CheckEncodedLength(nil, "OlcmInfoTable", "SIZE (1..7)", len(list)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	var children []byte
	for _, elem := range list {
		enc, err := elem.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding element: %w", err)
		}
		children = append(children, enc...)
	}
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding OlcmInfoTable as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBEROlcmInfoTable decodes a OlcmInfoTable list from BER.
func UnmarshalBEROlcmInfoTable(data []byte, opts ...ber.DecodeOption) (returnValue *OlcmInfoTable, returnErr error) {
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return nil, err
	}
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return nil, fmt.Errorf("decoding OlcmInfoTable: %w", err)
	}
	if total != len(data) {
		return nil, &ber.DecodeError{Offset: total, TypeName: "OlcmInfoTable", Cause: ber.ErrExtraData}
	}
	var result []OlcmInfo
	offset := 0
	for offset < len(content) {
		elementData := content[offset:]
		var elem OlcmInfo
		_, n, _, tlvErr := ber.DecodeTLV(elementData, opts...)
		if tlvErr != nil {
			return nil, fmt.Errorf("decoding element TLV: %w", tlvErr)
		}
		if unmErr := elem.UnmarshalBER(elementData[:n], ber.ChildDecodeOptions(opts, fmt.Sprintf("element[%d]", len(result)))...); unmErr != nil {
			return nil, fmt.Errorf("decoding element: %w", unmErr)
		}
		result = append(result, elem)
		if offset < 0 || offset >
			len(content) || n < 0 || n > len(content[offset:]) {
			return nil, fmt.Errorf("invalid BER content window")
		}

		offset += n
	}
	if len(result) < 1 || len(result) > 7 {
		if constraintErr := ber.CheckDecodedLength(opts, "OlcmInfoTable", "SIZE (1..7)", len(result)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	decoded := &OlcmInfoTable{Values: result}
	if ber.BERNeedsPreservation(opts) {
		var snapshotReports ber.ViolationLog
		snapshot, snapshotErr := MarshalBEROlcmInfoTable(decoded, ber.WithConstraintTolerance(&snapshotReports))
		if snapshotErr != nil {
			return nil, snapshotErr
		}
		decoded.berOriginal_ = append([]byte(nil), data...)
		decoded.berSnapshot_ = snapshot
	}
	return decoded, nil
}

// MarshalBER encodes OlcmInfo to BER format.
func (v *OlcmInfo) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: OlcmInfo receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *OlcmInfo) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if len(v.TraceReference) < 1 || len(v.TraceReference) > 2 {
		if constraintErr := ber.CheckEncodedLength(opts, "traceReference", "SIZE (1..2)", len(v.TraceReference)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_tracereference, encodeErr_enc_tracereference := ber.EncodeOctetString([]byte(v.TraceReference))
	if encodeErr_enc_tracereference != nil {
		return nil, fmt.Errorf("encoding traceReference: %w", encodeErr_enc_tracereference)
	}
	retagged_enc_tracereference, tagErr_enc_tracereference := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_tracereference)
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
	retagged_enc_tracetype, tagErr_enc_tracetype := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_tracetype)
	if tagErr_enc_tracetype != nil {
		return nil, fmt.Errorf("encoding traceType: %w", tagErr_enc_tracetype)
	}
	enc_tracetype = retagged_enc_tracetype
	children = append(children, enc_tracetype...)
	if v.LeaId != nil {
		if !(int64(*v.LeaId) >= 0 && int64(*v.LeaId) <= 65535) {
			if constraintErr := ber.CheckEncodedValue(opts, "leaId", "(0..65535)", fmt.Sprint(int64(*v.LeaId))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_leaid := ber.EncodeInteger(int64(*v.LeaId))
		retagged_enc_leaid, tagErr_enc_leaid := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_leaid)
		if tagErr_enc_leaid != nil {
			return nil, fmt.Errorf("encoding leaId: %w", tagErr_enc_leaid)
		}
		enc_leaid = retagged_enc_leaid
		children = append(children, enc_leaid...)
	}
	if v.OlcmTraceReference != nil {
		if len(*v.OlcmTraceReference) < 1 || len(*v.OlcmTraceReference) > 4 {
			if constraintErr := ber.CheckEncodedLength(opts, "olcmTraceReference", "SIZE (1..4)", len(*v.OlcmTraceReference)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_olcmtracereference, encodeErr_enc_olcmtracereference := ber.EncodeOctetString([]byte(*v.OlcmTraceReference))
		if encodeErr_enc_olcmtracereference != nil {
			return nil, fmt.Errorf("encoding olcmTraceReference: %w", encodeErr_enc_olcmtracereference)
		}
		retagged_enc_olcmtracereference, tagErr_enc_olcmtracereference := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, enc_olcmtracereference)
		if tagErr_enc_olcmtracereference != nil {
			return nil, fmt.Errorf("encoding olcmTraceReference: %w", tagErr_enc_olcmtracereference)
		}
		enc_olcmtracereference = retagged_enc_olcmtracereference
		children = append(children, enc_olcmtracereference...)
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

// MarshalDER encodes OlcmInfo to DER format.
func (v *OlcmInfo) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: OlcmInfo receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if len(v.TraceReference) < 1 || len(v.TraceReference) > 2 {
		if constraintErr := ber.CheckEncodedLength(nil, "traceReference", "SIZE (1..2)", len(v.TraceReference)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_tracereference, encodeErr_enc_tracereference := ber.EncodeOctetString([]byte(v.TraceReference))
	if encodeErr_enc_tracereference != nil {
		return nil, fmt.Errorf("encoding traceReference: %w", encodeErr_enc_tracereference)
	}
	retagged_enc_tracereference, tagErr_enc_tracereference := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_tracereference)
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
	retagged_enc_tracetype, tagErr_enc_tracetype := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_tracetype)
	if tagErr_enc_tracetype != nil {
		return nil, fmt.Errorf("encoding traceType: %w", tagErr_enc_tracetype)
	}
	enc_tracetype = retagged_enc_tracetype
	children = append(children, enc_tracetype...)
	if v.LeaId != nil {
		if !(int64(*v.LeaId) >= 0 && int64(*v.LeaId) <= 65535) {
			if constraintErr := ber.CheckEncodedValue(nil, "leaId", "(0..65535)", fmt.Sprint(int64(*v.LeaId))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_leaid := ber.EncodeInteger(int64(*v.LeaId))
		retagged_enc_leaid, tagErr_enc_leaid := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_leaid)
		if tagErr_enc_leaid != nil {
			return nil, fmt.Errorf("encoding leaId: %w", tagErr_enc_leaid)
		}
		enc_leaid = retagged_enc_leaid
		children = append(children, enc_leaid...)
	}
	if v.OlcmTraceReference != nil {
		if len(*v.OlcmTraceReference) < 1 || len(*v.OlcmTraceReference) > 4 {
			if constraintErr := ber.CheckEncodedLength(nil, "olcmTraceReference", "SIZE (1..4)", len(*v.OlcmTraceReference)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_olcmtracereference, encodeErr_enc_olcmtracereference := ber.EncodeOctetString([]byte(*v.OlcmTraceReference))
		if encodeErr_enc_olcmtracereference != nil {
			return nil, fmt.Errorf("encoding olcmTraceReference: %w", encodeErr_enc_olcmtracereference)
		}
		retagged_enc_olcmtracereference, tagErr_enc_olcmtracereference := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, enc_olcmtracereference)
		if tagErr_enc_olcmtracereference != nil {
			return nil, fmt.Errorf("encoding olcmTraceReference: %w", tagErr_enc_olcmtracereference)
		}
		enc_olcmtracereference = retagged_enc_olcmtracereference
		children = append(children, enc_olcmtracereference...)
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
		return nil, fmt.Errorf("encoding OlcmInfo as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes OlcmInfo from BER/DER format.
func (v *OlcmInfo) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: OlcmInfo destination is nil", ber.ErrInvalidValue)
	}
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = OlcmInfo{}
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
		return fmt.Errorf("decoding OlcmInfo SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "OlcmInfo", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode traceReference
	if offset >= len(content) {
		return fmt.Errorf("missing required field traceReference")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 0 {
			return fmt.Errorf("expected tag [%s %d] for traceReference, got %s", "CONTEXT", 0, reqTag_)
		}
	}
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
	v.TraceReference = TraceReference5(decVal_tracereference)
	if offset < 0 || offset >
		len(content) || n_tracereference < 0 || n_tracereference >
		len(content[offset:]) {
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
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 1 {
			return fmt.Errorf("expected tag [%s %d] for traceType, got %s", "CONTEXT", 1, reqTag_)
		}
	}
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
	v.TraceType = TraceType5(decVal_tracetype)
	if offset < 0 || offset >
		len(content) || n_tracetype < 0 || n_tracetype >
		len(content[offset:]) {
		return fmt.Errorf("invalid BER content window")
	}

	offset += n_tracetype
	if !(int64(v.TraceType) >= 0 && int64(v.TraceType) <= 255) {
		if constraintErr := ber.CheckDecodedValue(opts, "traceType", "(0..255)", fmt.Sprint(int64(v.TraceType))); constraintErr != nil {
			return constraintErr
		}
	}
	// Decode leaId
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2 {
				decodedTag_leaid, n_leaid, rawVal_leaid, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding leaId: %w", err)
				}
				if decodedTag_leaid.Class != tag.ClassContextSpecific || decodedTag_leaid.Number != 2 || decodedTag_leaid.Constructed != false {
					return fmt.Errorf("decoding leaId: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_leaid)
				}
				decVal_leaid, intErr := ber.DecodeIntegerValue(rawVal_leaid)
				if intErr != nil {
					return fmt.Errorf("decoding leaId: %w", intErr)
				}
				tmp_leaid := LeaId(decVal_leaid)
				v.LeaId = &tmp_leaid
				if offset < 0 || offset >
					len(content) || n_leaid < 0 || n_leaid > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_leaid
				if !(int64(*v.LeaId) >= 0 && int64(*v.LeaId) <= 65535) {
					if constraintErr := ber.CheckDecodedValue(opts, "leaId", "(0..65535)", fmt.Sprint(int64(*v.LeaId))); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode olcmTraceReference
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3 {
				decodedTag_olcmtracereference, n_olcmtracereference, rawVal_olcmtracereference, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding olcmTraceReference: %w", err)
				}
				if decodedTag_olcmtracereference.Class != tag.ClassContextSpecific || decodedTag_olcmtracereference.Number != 3 {
					return fmt.Errorf("decoding olcmTraceReference: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_olcmtracereference)
				}
				decVal_olcmtracereference, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_olcmtracereference.Constructed, rawVal_olcmtracereference, opts...)
				if octetErr != nil {
					return fmt.Errorf("decoding olcmTraceReference: %w", octetErr)
				}
				tmp_olcmtracereference := OlcmTraceReference(decVal_olcmtracereference)
				v.OlcmTraceReference = &tmp_olcmtracereference
				if offset < 0 || offset >
					len(content) || n_olcmtracereference < 0 || n_olcmtracereference >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_olcmtracereference
				if len(*v.OlcmTraceReference) < 1 || len(*v.OlcmTraceReference) > 4 {
					if constraintErr := ber.CheckDecodedLength(opts, "olcmTraceReference", "SIZE (1..4)", len(*v.OlcmTraceReference)); constraintErr != nil {
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
			return &ber.DecodeError{Offset: offset, TypeName: "OlcmInfo", Cause: extErr_}
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

// MarshalBER encodes ATMresExt to BER format.
func (v *ATMresExt) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: ATMresExt receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *ATMresExt) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if v.OlcmActive != nil {
		enc_olcmactive := ber.EncodeNull()
		retagged_enc_olcmactive, tagErr_enc_olcmactive := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_olcmactive)
		if tagErr_enc_olcmactive != nil {
			return nil, fmt.Errorf("encoding olcmActive: %w", tagErr_enc_olcmactive)
		}
		enc_olcmactive = retagged_enc_olcmactive
		children = append(children, enc_olcmactive...)
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
	return ber.EncodeConstructed(tag.Tag{Class: tag.ClassPrivate, Number: 0, Constructed: true}, children)
}

// MarshalDER encodes ATMresExt to DER format.
func (v *ATMresExt) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: ATMresExt receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if v.OlcmActive != nil {
		enc_olcmactive := ber.EncodeNull()
		retagged_enc_olcmactive, tagErr_enc_olcmactive := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_olcmactive)
		if tagErr_enc_olcmactive != nil {
			return nil, fmt.Errorf("encoding olcmActive: %w", tagErr_enc_olcmactive)
		}
		enc_olcmactive = retagged_enc_olcmactive
		children = append(children, enc_olcmactive...)
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
	retagged_encoded, tagErr_encoded := ber.EncodeImplicitTagWithClass(tag.ClassPrivate, 0, encoded)
	if tagErr_encoded != nil {
		return nil, fmt.Errorf("encoding ATMresExt: %w", tagErr_encoded)
	}
	encoded = retagged_encoded
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding ATMresExt as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes ATMresExt from BER/DER format.
func (v *ATMresExt) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: ATMresExt destination is nil", ber.ErrInvalidValue)
	}
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = ATMresExt{}
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
	decodedTag, content, total, err := ber.DecodeConstructedContent(data, opts...)
	if err != nil {
		return fmt.Errorf("decoding ATMresExt: %w", err)
	}
	if decodedTag.Class != tag.ClassPrivate || decodedTag.Number != 0 || !decodedTag.Constructed {
		return fmt.Errorf("decoding ATMresExt: %w: expected tag [PRIVATE 0], got %s", ber.ErrInvalidTag, decodedTag)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "ATMresExt", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode olcmActive
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
				decodedTag_olcmactive, n_olcmactive, rawVal_olcmactive, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding olcmActive: %w", err)
				}
				if decodedTag_olcmactive.Class != tag.ClassContextSpecific || decodedTag_olcmactive.Number != 0 || decodedTag_olcmactive.Constructed != false {
					return fmt.Errorf("decoding olcmActive: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_olcmactive)
				}
				if len(rawVal_olcmactive) != 0 {
					return fmt.Errorf("decoding olcmActive: %w: NULL content length %d", ber.ErrInvalidValue, len(rawVal_olcmactive))
				}
				v.OlcmActive = &struct{}{}
				if offset < 0 || offset >
					len(content) || n_olcmactive < 0 || n_olcmactive >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_olcmactive
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:], opts...)
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "ATMresExt", Cause: extErr_}
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

// MarshalBER encodes DTMargExt to BER format.
func (v *DTMargExt) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: DTMargExt receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *DTMargExt) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if v.TraceType != nil {
		if !(int64(*v.TraceType) >= 0 && int64(*v.TraceType) <= 255) {
			if constraintErr := ber.CheckEncodedValue(opts, "traceType", "(0..255)", fmt.Sprint(int64(*v.TraceType))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_tracetype := ber.EncodeInteger(int64(*v.TraceType))
		retagged_enc_tracetype, tagErr_enc_tracetype := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_tracetype)
		if tagErr_enc_tracetype != nil {
			return nil, fmt.Errorf("encoding traceType: %w", tagErr_enc_tracetype)
		}
		enc_tracetype = retagged_enc_tracetype
		children = append(children, enc_tracetype...)
	}
	if v.LeaId != nil {
		if !(int64(*v.LeaId) >= 0 && int64(*v.LeaId) <= 65535) {
			if constraintErr := ber.CheckEncodedValue(opts, "leaId", "(0..65535)", fmt.Sprint(int64(*v.LeaId))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_leaid := ber.EncodeInteger(int64(*v.LeaId))
		retagged_enc_leaid, tagErr_enc_leaid := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_leaid)
		if tagErr_enc_leaid != nil {
			return nil, fmt.Errorf("encoding leaId: %w", tagErr_enc_leaid)
		}
		enc_leaid = retagged_enc_leaid
		children = append(children, enc_leaid...)
	}
	if v.OlcmTraceReference != nil {
		if len(*v.OlcmTraceReference) < 1 || len(*v.OlcmTraceReference) > 4 {
			if constraintErr := ber.CheckEncodedLength(opts, "olcmTraceReference", "SIZE (1..4)", len(*v.OlcmTraceReference)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_olcmtracereference, encodeErr_enc_olcmtracereference := ber.EncodeOctetString([]byte(*v.OlcmTraceReference))
		if encodeErr_enc_olcmtracereference != nil {
			return nil, fmt.Errorf("encoding olcmTraceReference: %w", encodeErr_enc_olcmtracereference)
		}
		retagged_enc_olcmtracereference, tagErr_enc_olcmtracereference := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_olcmtracereference)
		if tagErr_enc_olcmtracereference != nil {
			return nil, fmt.Errorf("encoding olcmTraceReference: %w", tagErr_enc_olcmtracereference)
		}
		enc_olcmtracereference = retagged_enc_olcmtracereference
		children = append(children, enc_olcmtracereference...)
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
	return ber.EncodeConstructed(tag.Tag{Class: tag.ClassPrivate, Number: 0, Constructed: true}, children)
}

// MarshalDER encodes DTMargExt to DER format.
func (v *DTMargExt) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: DTMargExt receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if v.TraceType != nil {
		if !(int64(*v.TraceType) >= 0 && int64(*v.TraceType) <= 255) {
			if constraintErr := ber.CheckEncodedValue(nil, "traceType", "(0..255)", fmt.Sprint(int64(*v.TraceType))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_tracetype := ber.EncodeInteger(int64(*v.TraceType))
		retagged_enc_tracetype, tagErr_enc_tracetype := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_tracetype)
		if tagErr_enc_tracetype != nil {
			return nil, fmt.Errorf("encoding traceType: %w", tagErr_enc_tracetype)
		}
		enc_tracetype = retagged_enc_tracetype
		children = append(children, enc_tracetype...)
	}
	if v.LeaId != nil {
		if !(int64(*v.LeaId) >= 0 && int64(*v.LeaId) <= 65535) {
			if constraintErr := ber.CheckEncodedValue(nil, "leaId", "(0..65535)", fmt.Sprint(int64(*v.LeaId))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_leaid := ber.EncodeInteger(int64(*v.LeaId))
		retagged_enc_leaid, tagErr_enc_leaid := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_leaid)
		if tagErr_enc_leaid != nil {
			return nil, fmt.Errorf("encoding leaId: %w", tagErr_enc_leaid)
		}
		enc_leaid = retagged_enc_leaid
		children = append(children, enc_leaid...)
	}
	if v.OlcmTraceReference != nil {
		if len(*v.OlcmTraceReference) < 1 || len(*v.OlcmTraceReference) > 4 {
			if constraintErr := ber.CheckEncodedLength(nil, "olcmTraceReference", "SIZE (1..4)", len(*v.OlcmTraceReference)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_olcmtracereference, encodeErr_enc_olcmtracereference := ber.EncodeOctetString([]byte(*v.OlcmTraceReference))
		if encodeErr_enc_olcmtracereference != nil {
			return nil, fmt.Errorf("encoding olcmTraceReference: %w", encodeErr_enc_olcmtracereference)
		}
		retagged_enc_olcmtracereference, tagErr_enc_olcmtracereference := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_olcmtracereference)
		if tagErr_enc_olcmtracereference != nil {
			return nil, fmt.Errorf("encoding olcmTraceReference: %w", tagErr_enc_olcmtracereference)
		}
		enc_olcmtracereference = retagged_enc_olcmtracereference
		children = append(children, enc_olcmtracereference...)
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
	retagged_encoded, tagErr_encoded := ber.EncodeImplicitTagWithClass(tag.ClassPrivate, 0, encoded)
	if tagErr_encoded != nil {
		return nil, fmt.Errorf("encoding DTMargExt: %w", tagErr_encoded)
	}
	encoded = retagged_encoded
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding DTMargExt as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes DTMargExt from BER/DER format.
func (v *DTMargExt) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: DTMargExt destination is nil", ber.ErrInvalidValue)
	}
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = DTMargExt{}
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
	decodedTag, content, total, err := ber.DecodeConstructedContent(data, opts...)
	if err != nil {
		return fmt.Errorf("decoding DTMargExt: %w", err)
	}
	if decodedTag.Class != tag.ClassPrivate || decodedTag.Number != 0 || !decodedTag.Constructed {
		return fmt.Errorf("decoding DTMargExt: %w: expected tag [PRIVATE 0], got %s", ber.ErrInvalidTag, decodedTag)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "DTMargExt", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode traceType
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
				decodedTag_tracetype, n_tracetype, rawVal_tracetype, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding traceType: %w", err)
				}
				if decodedTag_tracetype.Class != tag.ClassContextSpecific || decodedTag_tracetype.Number != 0 || decodedTag_tracetype.Constructed != false {
					return fmt.Errorf("decoding traceType: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_tracetype)
				}
				decVal_tracetype, intErr := ber.DecodeIntegerValue(rawVal_tracetype)
				if intErr != nil {
					return fmt.Errorf("decoding traceType: %w", intErr)
				}
				tmp_tracetype := TraceType5(decVal_tracetype)
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
	// Decode leaId
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
				decodedTag_leaid, n_leaid, rawVal_leaid, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding leaId: %w", err)
				}
				if decodedTag_leaid.Class != tag.ClassContextSpecific || decodedTag_leaid.Number != 1 || decodedTag_leaid.Constructed != false {
					return fmt.Errorf("decoding leaId: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_leaid)
				}
				decVal_leaid, intErr := ber.DecodeIntegerValue(rawVal_leaid)
				if intErr != nil {
					return fmt.Errorf("decoding leaId: %w", intErr)
				}
				tmp_leaid := LeaId(decVal_leaid)
				v.LeaId = &tmp_leaid
				if offset < 0 || offset >
					len(content) || n_leaid < 0 || n_leaid > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_leaid
				if !(int64(*v.LeaId) >= 0 && int64(*v.LeaId) <= 65535) {
					if constraintErr := ber.CheckDecodedValue(opts, "leaId", "(0..65535)", fmt.Sprint(int64(*v.LeaId))); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode olcmTraceReference
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2 {
				decodedTag_olcmtracereference, n_olcmtracereference, rawVal_olcmtracereference, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding olcmTraceReference: %w", err)
				}
				if decodedTag_olcmtracereference.Class != tag.ClassContextSpecific || decodedTag_olcmtracereference.Number != 2 {
					return fmt.Errorf("decoding olcmTraceReference: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_olcmtracereference)
				}
				decVal_olcmtracereference, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_olcmtracereference.Constructed, rawVal_olcmtracereference, opts...)
				if octetErr != nil {
					return fmt.Errorf("decoding olcmTraceReference: %w", octetErr)
				}
				tmp_olcmtracereference := OlcmTraceReference(decVal_olcmtracereference)
				v.OlcmTraceReference = &tmp_olcmtracereference
				if offset < 0 || offset >
					len(content) || n_olcmtracereference < 0 || n_olcmtracereference >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_olcmtracereference
				if len(*v.OlcmTraceReference) < 1 || len(*v.OlcmTraceReference) > 4 {
					if constraintErr := ber.CheckDecodedLength(opts, "olcmTraceReference", "SIZE (1..4)", len(*v.OlcmTraceReference)); constraintErr != nil {
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
			return &ber.DecodeError{Offset: offset, TypeName: "DTMargExt", Cause: extErr_}
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

// MarshalBER encodes FraudInfo to BER format.
func (v *FraudInfo) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: FraudInfo receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *FraudInfo) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if v.Moc != nil {
		enc_moc, err := v.Moc.MarshalBER(ber.ChildEncodeOptions(opts, "moc")...)
		if err != nil {
			return nil, fmt.Errorf("encoding moc: %w", err)
		}
		retagged_enc_moc, tagErr_enc_moc := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_moc)
		if tagErr_enc_moc != nil {
			return nil, fmt.Errorf("encoding moc: %w", tagErr_enc_moc)
		}
		enc_moc = retagged_enc_moc
		children = append(children, enc_moc...)
	}
	if v.Cf != nil {
		enc_cf, err := v.Cf.MarshalBER(ber.ChildEncodeOptions(opts, "cf")...)
		if err != nil {
			return nil, fmt.Errorf("encoding cf: %w", err)
		}
		retagged_enc_cf, tagErr_enc_cf := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_cf)
		if tagErr_enc_cf != nil {
			return nil, fmt.Errorf("encoding cf: %w", tagErr_enc_cf)
		}
		enc_cf = retagged_enc_cf
		children = append(children, enc_cf...)
	}
	if v.Ct != nil {
		enc_ct, err := v.Ct.MarshalBER(ber.ChildEncodeOptions(opts, "ct")...)
		if err != nil {
			return nil, fmt.Errorf("encoding ct: %w", err)
		}
		retagged_enc_ct, tagErr_enc_ct := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_ct)
		if tagErr_enc_ct != nil {
			return nil, fmt.Errorf("encoding ct: %w", tagErr_enc_ct)
		}
		enc_ct = retagged_enc_ct
		children = append(children, enc_ct...)
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

// MarshalDER encodes FraudInfo to DER format.
func (v *FraudInfo) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: FraudInfo receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if v.Moc != nil {
		enc_moc, err := v.Moc.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding moc: %w", err)
		}
		retagged_enc_moc, tagErr_enc_moc := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_moc)
		if tagErr_enc_moc != nil {
			return nil, fmt.Errorf("encoding moc: %w", tagErr_enc_moc)
		}
		enc_moc = retagged_enc_moc
		children = append(children, enc_moc...)
	}
	if v.Cf != nil {
		enc_cf, err := v.Cf.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding cf: %w", err)
		}
		retagged_enc_cf, tagErr_enc_cf := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_cf)
		if tagErr_enc_cf != nil {
			return nil, fmt.Errorf("encoding cf: %w", tagErr_enc_cf)
		}
		enc_cf = retagged_enc_cf
		children = append(children, enc_cf...)
	}
	if v.Ct != nil {
		enc_ct, err := v.Ct.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding ct: %w", err)
		}
		retagged_enc_ct, tagErr_enc_ct := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_ct)
		if tagErr_enc_ct != nil {
			return nil, fmt.Errorf("encoding ct: %w", tagErr_enc_ct)
		}
		enc_ct = retagged_enc_ct
		children = append(children, enc_ct...)
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
		return nil, fmt.Errorf("encoding FraudInfo as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes FraudInfo from BER/DER format.
func (v *FraudInfo) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: FraudInfo destination is nil", ber.ErrInvalidValue)
	}
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = FraudInfo{}
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
		return fmt.Errorf("decoding FraudInfo SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "FraudInfo", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode moc
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
				decodedTag_moc, n_moc, rawVal_moc, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding moc: %w", err)
				}
				if decodedTag_moc.Class != tag.ClassContextSpecific || decodedTag_moc.Number != 0 || decodedTag_moc.Constructed != true {
					return fmt.Errorf("decoding moc: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_moc)
				}
				reconstructed_moc, reconstructionErr_moc := ber.EncodeSequence(rawVal_moc)
				if reconstructionErr_moc != nil {
					return fmt.Errorf("decoding moc: %w", reconstructionErr_moc)
				}
				var dec_moc FraudData
				if unmErr := dec_moc.UnmarshalBER(reconstructed_moc, ber.ChildDecodeOptions(opts, "moc")...); unmErr != nil {
					return fmt.Errorf("decoding moc: %w", unmErr)
				}
				v.Moc = &dec_moc
				if offset < 0 || offset >
					len(content) || n_moc < 0 || n_moc > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_moc
			}
		}
	}
	// Decode cf
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
				decodedTag_cf, n_cf, rawVal_cf, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding cf: %w", err)
				}
				if decodedTag_cf.Class != tag.ClassContextSpecific || decodedTag_cf.Number != 1 || decodedTag_cf.Constructed != true {
					return fmt.Errorf("decoding cf: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_cf)
				}
				reconstructed_cf, reconstructionErr_cf := ber.EncodeSequence(rawVal_cf)
				if reconstructionErr_cf != nil {
					return fmt.Errorf("decoding cf: %w", reconstructionErr_cf)
				}
				var dec_cf FraudData
				if unmErr := dec_cf.UnmarshalBER(reconstructed_cf, ber.ChildDecodeOptions(opts, "cf")...); unmErr != nil {
					return fmt.Errorf("decoding cf: %w", unmErr)
				}
				v.Cf = &dec_cf
				if offset < 0 || offset >
					len(content) || n_cf < 0 || n_cf > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_cf
			}
		}
	}
	// Decode ct
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2 {
				decodedTag_ct, n_ct, rawVal_ct, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding ct: %w", err)
				}
				if decodedTag_ct.Class != tag.ClassContextSpecific || decodedTag_ct.Number != 2 || decodedTag_ct.Constructed != true {
					return fmt.Errorf("decoding ct: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_ct)
				}
				reconstructed_ct, reconstructionErr_ct := ber.EncodeSequence(rawVal_ct)
				if reconstructionErr_ct != nil {
					return fmt.Errorf("decoding ct: %w", reconstructionErr_ct)
				}
				var dec_ct FraudData
				if unmErr := dec_ct.UnmarshalBER(reconstructed_ct, ber.ChildDecodeOptions(opts, "ct")...); unmErr != nil {
					return fmt.Errorf("decoding ct: %w", unmErr)
				}
				v.Ct = &dec_ct
				if offset < 0 || offset >
					len(content) || n_ct < 0 || n_ct > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_ct
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:], opts...)
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "FraudInfo", Cause: extErr_}
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

// MarshalBER encodes FraudData to BER format.
func (v *FraudData) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: FraudData receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *FraudData) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if v.Time != nil {
		if !(int64(*v.Time) >= 0 && int64(*v.Time) <= 64800) {
			if constraintErr := ber.CheckEncodedValue(opts, "time", "(0..64800)", fmt.Sprint(int64(*v.Time))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_time := ber.EncodeInteger(int64(*v.Time))
		retagged_enc_time, tagErr_enc_time := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_time)
		if tagErr_enc_time != nil {
			return nil, fmt.Errorf("encoding time: %w", tagErr_enc_time)
		}
		enc_time = retagged_enc_time
		children = append(children, enc_time...)
	}
	if v.TimeAction != nil {
		if len(*v.TimeAction) < 1 || len(*v.TimeAction) > 10 {
			if constraintErr := ber.CheckEncodedLength(opts, "timeAction", "SIZE (1..10)", len(*v.TimeAction)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_timeaction, encodeErr_enc_timeaction := ber.EncodeOctetString([]byte(*v.TimeAction))
		if encodeErr_enc_timeaction != nil {
			return nil, fmt.Errorf("encoding timeAction: %w", encodeErr_enc_timeaction)
		}
		retagged_enc_timeaction, tagErr_enc_timeaction := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_timeaction)
		if tagErr_enc_timeaction != nil {
			return nil, fmt.Errorf("encoding timeAction: %w", tagErr_enc_timeaction)
		}
		enc_timeaction = retagged_enc_timeaction
		children = append(children, enc_timeaction...)
	}
	if v.MaxCount != nil {
		if !(int64(*v.MaxCount) >= 0 && int64(*v.MaxCount) <= 255) {
			if constraintErr := ber.CheckEncodedValue(opts, "maxCount", "(0..255)", fmt.Sprint(int64(*v.MaxCount))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_maxcount := ber.EncodeInteger(int64(*v.MaxCount))
		retagged_enc_maxcount, tagErr_enc_maxcount := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_maxcount)
		if tagErr_enc_maxcount != nil {
			return nil, fmt.Errorf("encoding maxCount: %w", tagErr_enc_maxcount)
		}
		enc_maxcount = retagged_enc_maxcount
		children = append(children, enc_maxcount...)
	}
	if v.MaxCountAction != nil {
		if len(*v.MaxCountAction) < 1 || len(*v.MaxCountAction) > 10 {
			if constraintErr := ber.CheckEncodedLength(opts, "maxCountAction", "SIZE (1..10)", len(*v.MaxCountAction)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_maxcountaction, encodeErr_enc_maxcountaction := ber.EncodeOctetString([]byte(*v.MaxCountAction))
		if encodeErr_enc_maxcountaction != nil {
			return nil, fmt.Errorf("encoding maxCountAction: %w", encodeErr_enc_maxcountaction)
		}
		retagged_enc_maxcountaction, tagErr_enc_maxcountaction := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, enc_maxcountaction)
		if tagErr_enc_maxcountaction != nil {
			return nil, fmt.Errorf("encoding maxCountAction: %w", tagErr_enc_maxcountaction)
		}
		enc_maxcountaction = retagged_enc_maxcountaction
		children = append(children, enc_maxcountaction...)
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

// MarshalDER encodes FraudData to DER format.
func (v *FraudData) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: FraudData receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if v.Time != nil {
		if !(int64(*v.Time) >= 0 && int64(*v.Time) <= 64800) {
			if constraintErr := ber.CheckEncodedValue(nil, "time", "(0..64800)", fmt.Sprint(int64(*v.Time))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_time := ber.EncodeInteger(int64(*v.Time))
		retagged_enc_time, tagErr_enc_time := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_time)
		if tagErr_enc_time != nil {
			return nil, fmt.Errorf("encoding time: %w", tagErr_enc_time)
		}
		enc_time = retagged_enc_time
		children = append(children, enc_time...)
	}
	if v.TimeAction != nil {
		if len(*v.TimeAction) < 1 || len(*v.TimeAction) > 10 {
			if constraintErr := ber.CheckEncodedLength(nil, "timeAction", "SIZE (1..10)", len(*v.TimeAction)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_timeaction, encodeErr_enc_timeaction := ber.EncodeOctetString([]byte(*v.TimeAction))
		if encodeErr_enc_timeaction != nil {
			return nil, fmt.Errorf("encoding timeAction: %w", encodeErr_enc_timeaction)
		}
		retagged_enc_timeaction, tagErr_enc_timeaction := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_timeaction)
		if tagErr_enc_timeaction != nil {
			return nil, fmt.Errorf("encoding timeAction: %w", tagErr_enc_timeaction)
		}
		enc_timeaction = retagged_enc_timeaction
		children = append(children, enc_timeaction...)
	}
	if v.MaxCount != nil {
		if !(int64(*v.MaxCount) >= 0 && int64(*v.MaxCount) <= 255) {
			if constraintErr := ber.CheckEncodedValue(nil, "maxCount", "(0..255)", fmt.Sprint(int64(*v.MaxCount))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_maxcount := ber.EncodeInteger(int64(*v.MaxCount))
		retagged_enc_maxcount, tagErr_enc_maxcount := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_maxcount)
		if tagErr_enc_maxcount != nil {
			return nil, fmt.Errorf("encoding maxCount: %w", tagErr_enc_maxcount)
		}
		enc_maxcount = retagged_enc_maxcount
		children = append(children, enc_maxcount...)
	}
	if v.MaxCountAction != nil {
		if len(*v.MaxCountAction) < 1 || len(*v.MaxCountAction) > 10 {
			if constraintErr := ber.CheckEncodedLength(nil, "maxCountAction", "SIZE (1..10)", len(*v.MaxCountAction)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_maxcountaction, encodeErr_enc_maxcountaction := ber.EncodeOctetString([]byte(*v.MaxCountAction))
		if encodeErr_enc_maxcountaction != nil {
			return nil, fmt.Errorf("encoding maxCountAction: %w", encodeErr_enc_maxcountaction)
		}
		retagged_enc_maxcountaction, tagErr_enc_maxcountaction := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, enc_maxcountaction)
		if tagErr_enc_maxcountaction != nil {
			return nil, fmt.Errorf("encoding maxCountAction: %w", tagErr_enc_maxcountaction)
		}
		enc_maxcountaction = retagged_enc_maxcountaction
		children = append(children, enc_maxcountaction...)
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
		return nil, fmt.Errorf("encoding FraudData as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes FraudData from BER/DER format.
func (v *FraudData) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: FraudData destination is nil", ber.ErrInvalidValue)
	}
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = FraudData{}
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
		return fmt.Errorf("decoding FraudData SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "FraudData", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode time
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
				decodedTag_time, n_time, rawVal_time, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding time: %w", err)
				}
				if decodedTag_time.Class != tag.ClassContextSpecific || decodedTag_time.Number != 0 || decodedTag_time.Constructed != false {
					return fmt.Errorf("decoding time: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_time)
				}
				decVal_time, intErr := ber.DecodeIntegerValue(rawVal_time)
				if intErr != nil {
					return fmt.Errorf("decoding time: %w", intErr)
				}
				tmp_time := TimeLimit(decVal_time)
				v.Time = &tmp_time
				if offset < 0 || offset >
					len(content) || n_time < 0 || n_time > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_time
				if !(int64(*v.Time) >= 0 && int64(*v.Time) <= 64800) {
					if constraintErr := ber.CheckDecodedValue(opts, "time", "(0..64800)", fmt.Sprint(int64(*v.Time))); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode timeAction
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
				decodedTag_timeaction, n_timeaction, rawVal_timeaction, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding timeAction: %w", err)
				}
				if decodedTag_timeaction.Class != tag.ClassContextSpecific || decodedTag_timeaction.Number != 1 {
					return fmt.Errorf("decoding timeAction: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_timeaction)
				}
				decVal_timeaction, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_timeaction.Constructed, rawVal_timeaction, opts...)
				if octetErr != nil {
					return fmt.Errorf("decoding timeAction: %w", octetErr)
				}
				tmp_timeaction := ActionType(decVal_timeaction)
				v.TimeAction = &tmp_timeaction
				if offset < 0 || offset >
					len(content) || n_timeaction < 0 || n_timeaction >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_timeaction
				if len(*v.TimeAction) < 1 || len(*v.TimeAction) > 10 {
					if constraintErr := ber.CheckDecodedLength(opts, "timeAction", "SIZE (1..10)", len(*v.TimeAction)); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode maxCount
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2 {
				decodedTag_maxcount, n_maxcount, rawVal_maxcount, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding maxCount: %w", err)
				}
				if decodedTag_maxcount.Class != tag.ClassContextSpecific || decodedTag_maxcount.Number != 2 || decodedTag_maxcount.Constructed != false {
					return fmt.Errorf("decoding maxCount: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_maxcount)
				}
				decVal_maxcount, intErr := ber.DecodeIntegerValue(rawVal_maxcount)
				if intErr != nil {
					return fmt.Errorf("decoding maxCount: %w", intErr)
				}
				tmp_maxcount := FraudMaxCount(decVal_maxcount)
				v.MaxCount = &tmp_maxcount
				if offset < 0 || offset >
					len(content) || n_maxcount < 0 || n_maxcount > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_maxcount
				if !(int64(*v.MaxCount) >= 0 && int64(*v.MaxCount) <= 255) {
					if constraintErr := ber.CheckDecodedValue(opts, "maxCount", "(0..255)", fmt.Sprint(int64(*v.MaxCount))); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode maxCountAction
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3 {
				decodedTag_maxcountaction, n_maxcountaction, rawVal_maxcountaction, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding maxCountAction: %w", err)
				}
				if decodedTag_maxcountaction.Class != tag.ClassContextSpecific || decodedTag_maxcountaction.Number != 3 {
					return fmt.Errorf("decoding maxCountAction: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_maxcountaction)
				}
				decVal_maxcountaction, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_maxcountaction.Constructed, rawVal_maxcountaction, opts...)
				if octetErr != nil {
					return fmt.Errorf("decoding maxCountAction: %w", octetErr)
				}
				tmp_maxcountaction := ActionType(decVal_maxcountaction)
				v.MaxCountAction = &tmp_maxcountaction
				if offset < 0 || offset >
					len(content) || n_maxcountaction < 0 || n_maxcountaction >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_maxcountaction
				if len(*v.MaxCountAction) < 1 || len(*v.MaxCountAction) > 10 {
					if constraintErr := ber.CheckDecodedLength(opts, "maxCountAction", "SIZE (1..10)", len(*v.MaxCountAction)); constraintErr != nil {
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
			return &ber.DecodeError{Offset: offset, TypeName: "FraudData", Cause: extErr_}
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

// MarshalBER encodes ServiceWithInfo to BER format.
func (v *ServiceWithInfo) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: ServiceWithInfo receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *ServiceWithInfo) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if v.ServiceCode != nil {
		if len(*v.ServiceCode) < 1 || len(*v.ServiceCode) > 1 {
			if constraintErr := ber.CheckEncodedLength(opts, "serviceCode", "SIZE (1)", len(*v.ServiceCode)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_servicecode, encodeErr_enc_servicecode := ber.EncodeOctetString([]byte(*v.ServiceCode))
		if encodeErr_enc_servicecode != nil {
			return nil, fmt.Errorf("encoding serviceCode: %w", encodeErr_enc_servicecode)
		}
		retagged_enc_servicecode, tagErr_enc_servicecode := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_servicecode)
		if tagErr_enc_servicecode != nil {
			return nil, fmt.Errorf("encoding serviceCode: %w", tagErr_enc_servicecode)
		}
		enc_servicecode = retagged_enc_servicecode
		children = append(children, enc_servicecode...)
	}
	if v.VersionInfo != nil {
		if len(*v.VersionInfo) < 1 || len(*v.VersionInfo) > 1 {
			if constraintErr := ber.CheckEncodedLength(opts, "versionInfo", "SIZE (1)", len(*v.VersionInfo)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_versioninfo, encodeErr_enc_versioninfo := ber.EncodeOctetString([]byte(*v.VersionInfo))
		if encodeErr_enc_versioninfo != nil {
			return nil, fmt.Errorf("encoding versionInfo: %w", encodeErr_enc_versioninfo)
		}
		retagged_enc_versioninfo, tagErr_enc_versioninfo := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_versioninfo)
		if tagErr_enc_versioninfo != nil {
			return nil, fmt.Errorf("encoding versionInfo: %w", tagErr_enc_versioninfo)
		}
		enc_versioninfo = retagged_enc_versioninfo
		children = append(children, enc_versioninfo...)
	}
	if v.InKey != nil {
		enc_inkey, err := v.InKey.MarshalBER(ber.ChildEncodeOptions(opts, "in-key")...)
		if err != nil {
			return nil, fmt.Errorf("encoding in-key: %w", err)
		}
		children = append(children, enc_inkey...)
	}
	if v.FraudInfo != nil {
		enc_fraudinfo, err := v.FraudInfo.MarshalBER(ber.ChildEncodeOptions(opts, "fraudInfo")...)
		if err != nil {
			return nil, fmt.Errorf("encoding fraudInfo: %w", err)
		}
		children = append(children, enc_fraudinfo...)
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

// MarshalDER encodes ServiceWithInfo to DER format.
func (v *ServiceWithInfo) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: ServiceWithInfo receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if v.ServiceCode != nil {
		if len(*v.ServiceCode) < 1 || len(*v.ServiceCode) > 1 {
			if constraintErr := ber.CheckEncodedLength(nil, "serviceCode", "SIZE (1)", len(*v.ServiceCode)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_servicecode, encodeErr_enc_servicecode := ber.EncodeOctetString([]byte(*v.ServiceCode))
		if encodeErr_enc_servicecode != nil {
			return nil, fmt.Errorf("encoding serviceCode: %w", encodeErr_enc_servicecode)
		}
		retagged_enc_servicecode, tagErr_enc_servicecode := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_servicecode)
		if tagErr_enc_servicecode != nil {
			return nil, fmt.Errorf("encoding serviceCode: %w", tagErr_enc_servicecode)
		}
		enc_servicecode = retagged_enc_servicecode
		children = append(children, enc_servicecode...)
	}
	if v.VersionInfo != nil {
		if len(*v.VersionInfo) < 1 || len(*v.VersionInfo) > 1 {
			if constraintErr := ber.CheckEncodedLength(nil, "versionInfo", "SIZE (1)", len(*v.VersionInfo)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_versioninfo, encodeErr_enc_versioninfo := ber.EncodeOctetString([]byte(*v.VersionInfo))
		if encodeErr_enc_versioninfo != nil {
			return nil, fmt.Errorf("encoding versionInfo: %w", encodeErr_enc_versioninfo)
		}
		if string(enc_versioninfo) != "\x04\x01\x80" {
			retagged_enc_versioninfo, tagErr_enc_versioninfo := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_versioninfo)
			if tagErr_enc_versioninfo != nil {
				return nil, fmt.Errorf("encoding versionInfo: %w", tagErr_enc_versioninfo)
			}
			enc_versioninfo = retagged_enc_versioninfo
			children = append(children, enc_versioninfo...)
		}
	}
	if v.InKey != nil {
		enc_inkey, err := v.InKey.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding in-key: %w", err)
		}
		children = append(children, enc_inkey...)
	}
	if v.FraudInfo != nil {
		enc_fraudinfo, err := v.FraudInfo.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding fraudInfo: %w", err)
		}
		children = append(children, enc_fraudinfo...)
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
		return nil, fmt.Errorf("encoding ServiceWithInfo as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes ServiceWithInfo from BER/DER format.
func (v *ServiceWithInfo) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: ServiceWithInfo destination is nil", ber.ErrInvalidValue)
	}
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = ServiceWithInfo{}
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
		return fmt.Errorf("decoding ServiceWithInfo SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "ServiceWithInfo", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode serviceCode
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
				decodedTag_servicecode, n_servicecode, rawVal_servicecode, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding serviceCode: %w", err)
				}
				if decodedTag_servicecode.Class != tag.ClassContextSpecific || decodedTag_servicecode.Number != 0 {
					return fmt.Errorf("decoding serviceCode: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_servicecode)
				}
				decVal_servicecode, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_servicecode.Constructed, rawVal_servicecode, opts...)
				if octetErr != nil {
					return fmt.Errorf("decoding serviceCode: %w", octetErr)
				}
				tmp_servicecode := MAPserviceCode(decVal_servicecode)
				v.ServiceCode = &tmp_servicecode
				if offset < 0 || offset >
					len(content) || n_servicecode < 0 || n_servicecode > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_servicecode
				if len(*v.ServiceCode) < 1 || len(*v.ServiceCode) > 1 {
					if constraintErr := ber.CheckDecodedLength(opts, "serviceCode", "SIZE (1)", len(*v.ServiceCode)); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode versionInfo
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
				decodedTag_versioninfo, n_versioninfo, rawVal_versioninfo, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding versionInfo: %w", err)
				}
				if decodedTag_versioninfo.Class != tag.ClassContextSpecific || decodedTag_versioninfo.Number != 1 {
					return fmt.Errorf("decoding versionInfo: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_versioninfo)
				}
				decVal_versioninfo, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_versioninfo.Constructed, rawVal_versioninfo, opts...)
				if octetErr != nil {
					return fmt.Errorf("decoding versionInfo: %w", octetErr)
				}
				tmp_versioninfo := VersionInfo(decVal_versioninfo)
				v.VersionInfo = &tmp_versioninfo
				if offset < 0 || offset >
					len(content) || n_versioninfo < 0 || n_versioninfo > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_versioninfo
				if len(*v.VersionInfo) < 1 || len(*v.VersionInfo) > 1 {
					if constraintErr := ber.CheckDecodedLength(opts, "versionInfo", "SIZE (1)", len(*v.VersionInfo)); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode in-key
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3) {
				// Decode nested CHOICE (INKey)
				_, n_inkey, _, tlvErr_inkey := ber.DecodeTLV(content[offset:], opts...)
				if tlvErr_inkey != nil {
					return fmt.Errorf("decoding in-key: %w", tlvErr_inkey)
				}
				var dec_inkey INKey
				if offset < 0 || offset >
					len(content) || n_inkey < 0 || n_inkey > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				if unmErr := dec_inkey.UnmarshalBER(content[offset:offset+n_inkey], ber.ChildDecodeOptions(opts, "in-key")...); unmErr != nil {
					return fmt.Errorf("decoding in-key: %w", unmErr)
				}
				v.InKey = &dec_inkey
				if offset < 0 || offset >
					len(content) || n_inkey < 0 || n_inkey > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_inkey
			}
		}
	}
	// Decode fraudInfo
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassUniversal && peekTag.Number == 16 {
				// Decode nested SEQUENCE (FraudInfo)
				_, n_fraudinfo, _, tlvErr_fraudinfo := ber.DecodeTLV(content[offset:], opts...)
				if tlvErr_fraudinfo != nil {
					return fmt.Errorf("decoding fraudInfo: %w", tlvErr_fraudinfo)
				}
				var dec_fraudinfo FraudInfo
				if offset < 0 || offset >
					len(content) || n_fraudinfo < 0 || n_fraudinfo > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				if unmErr := dec_fraudinfo.UnmarshalBER(content[offset:offset+n_fraudinfo], ber.ChildDecodeOptions(opts, "fraudInfo")...); unmErr != nil {
					return fmt.Errorf("decoding fraudInfo: %w", unmErr)
				}
				v.FraudInfo = &dec_fraudinfo
				if offset < 0 || offset >
					len(content) || n_fraudinfo < 0 || n_fraudinfo > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_fraudinfo
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:], opts...)
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "ServiceWithInfo", Cause: extErr_}
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

// MarshalBERServiceListWithInfo encodes a ServiceListWithInfo list to BER.
func MarshalBERServiceListWithInfo(collection *ServiceListWithInfo, opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	if collection == nil {
		return nil, fmt.Errorf("%w: required collection is nil", ber.ErrInvalidValue)
	}
	encoded, err := marshalBERServiceListWithInfo(collection, opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, collection.berOriginal_, collection.berSnapshot_, opts), nil
}
func marshalBERServiceListWithInfo(collection *ServiceListWithInfo, opts ...ber.EncodeOption) ([]byte, error) {
	list := collection.Values
	if len(list) < 1 || len(list) > 20 {
		if constraintErr := ber.CheckEncodedLength(opts, "ServiceListWithInfo", "SIZE (1..20)", len(list)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	var children []byte
	for elemIndex, elem := range list {
		enc, err := elem.MarshalBER(ber.ChildEncodeOptions(opts, fmt.Sprintf("element[%d]", elemIndex))...)
		if err != nil {
			return nil, fmt.Errorf("encoding element: %w", err)
		}
		children = append(children, enc...)
	}
	return ber.EncodeSequence(children)
}

// MarshalDERServiceListWithInfo encodes a ServiceListWithInfo list to DER.
func MarshalDERServiceListWithInfo(collection *ServiceListWithInfo) ([]byte, error) {
	if collection == nil {
		return nil, fmt.Errorf("%w: required collection is nil", ber.ErrInvalidValue)
	}
	list := collection.Values
	if len(list) < 1 || len(list) > 20 {
		if constraintErr := ber.CheckEncodedLength(nil, "ServiceListWithInfo", "SIZE (1..20)", len(list)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	var children []byte
	for _, elem := range list {
		enc, err := elem.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding element: %w", err)
		}
		children = append(children, enc...)
	}
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding ServiceListWithInfo as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBERServiceListWithInfo decodes a ServiceListWithInfo list from BER.
func UnmarshalBERServiceListWithInfo(data []byte, opts ...ber.DecodeOption) (returnValue *ServiceListWithInfo, returnErr error) {
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return nil, err
	}
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return nil, fmt.Errorf("decoding ServiceListWithInfo: %w", err)
	}
	if total != len(data) {
		return nil, &ber.DecodeError{Offset: total, TypeName: "ServiceListWithInfo", Cause: ber.ErrExtraData}
	}
	var result []ServiceWithInfo
	offset := 0
	for offset < len(content) {
		elementData := content[offset:]
		var elem ServiceWithInfo
		_, n, _, tlvErr := ber.DecodeTLV(elementData, opts...)
		if tlvErr != nil {
			return nil, fmt.Errorf("decoding element TLV: %w", tlvErr)
		}
		if unmErr := elem.UnmarshalBER(elementData[:n], ber.ChildDecodeOptions(opts, fmt.Sprintf("element[%d]", len(result)))...); unmErr != nil {
			return nil, fmt.Errorf("decoding element: %w", unmErr)
		}
		result = append(result, elem)
		if offset < 0 || offset >
			len(content) || n < 0 || n > len(content[offset:]) {
			return nil, fmt.Errorf("invalid BER content window")
		}

		offset += n
	}
	if len(result) < 1 || len(result) > 20 {
		if constraintErr := ber.CheckDecodedLength(opts, "ServiceListWithInfo", "SIZE (1..20)", len(result)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	decoded := &ServiceListWithInfo{Values: result}
	if ber.BERNeedsPreservation(opts) {
		var snapshotReports ber.ViolationLog
		snapshot, snapshotErr := MarshalBERServiceListWithInfo(decoded, ber.WithConstraintTolerance(&snapshotReports))
		if snapshotErr != nil {
			return nil, snapshotErr
		}
		decoded.berOriginal_ = append([]byte(nil), data...)
		decoded.berSnapshot_ = snapshot
	}
	return decoded, nil
}

// MarshalBER encodes INKey to BER format.
func (v *INKey) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: INKey receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *INKey) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	switch v.Choice {
	case INKeyChoiceMobileINKey:
		if v.MobileINKey == nil {
			return nil, fmt.Errorf("%w: choice INKey: mobile-IN-key is nil", ber.ErrInvalidValue)
		}
		enc_0, err := v.MobileINKey.MarshalBER(ber.ChildEncodeOptions(opts, "mobile-IN-key")...)
		if err != nil {
			return nil, fmt.Errorf("encoding mobile-IN-key: %w", err)
		}
		retagged_enc_0, tagErr_enc_0 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_0)
		if tagErr_enc_0 != nil {
			return nil, fmt.Errorf("encoding mobile-IN-key: %w", tagErr_enc_0)
		}
		enc_0 = retagged_enc_0
		return enc_0, nil
	case INKeyChoiceSmsINKey:
		if v.SmsINKey == nil {
			return nil, fmt.Errorf("%w: choice INKey: sms-IN-key is nil", ber.ErrInvalidValue)
		}
		enc_1, err := v.SmsINKey.MarshalBER(ber.ChildEncodeOptions(opts, "sms-IN-key")...)
		if err != nil {
			return nil, fmt.Errorf("encoding sms-IN-key: %w", err)
		}
		retagged_enc_1, tagErr_enc_1 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, enc_1)
		if tagErr_enc_1 != nil {
			return nil, fmt.Errorf("encoding sms-IN-key: %w", tagErr_enc_1)
		}
		enc_1 = retagged_enc_1
		return enc_1, nil
	default:
		return nil, fmt.Errorf("unknown choice %d for INKey", v.Choice)
	}
}

// MarshalDER encodes INKey to DER format.
func (v *INKey) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: INKey receiver is nil", ber.ErrInvalidValue)
	}
	switch v.Choice {
	case INKeyChoiceMobileINKey:
		if v.MobileINKey == nil {
			return nil, fmt.Errorf("%w: choice INKey: mobile-IN-key is nil", ber.ErrInvalidValue)
		}
		enc_der_0, err := v.MobileINKey.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding mobile-IN-key: %w", err)
		}
		retagged_enc_der_0, tagErr_enc_der_0 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_der_0)
		if tagErr_enc_der_0 != nil {
			return nil, fmt.Errorf("encoding mobile-IN-key: %w", tagErr_enc_der_0)
		}
		enc_der_0 = retagged_enc_der_0
		if derErr := ber.ValidateDEREncodedElement(enc_der_0); derErr != nil {
			return nil, fmt.Errorf("encoding mobile-IN-key as DER: %w", derErr)
		}
		return enc_der_0, nil
	case INKeyChoiceSmsINKey:
		if v.SmsINKey == nil {
			return nil, fmt.Errorf("%w: choice INKey: sms-IN-key is nil", ber.ErrInvalidValue)
		}
		enc_der_1, err := v.SmsINKey.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding sms-IN-key: %w", err)
		}
		retagged_enc_der_1, tagErr_enc_der_1 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, enc_der_1)
		if tagErr_enc_der_1 != nil {
			return nil, fmt.Errorf("encoding sms-IN-key: %w", tagErr_enc_der_1)
		}
		enc_der_1 = retagged_enc_der_1
		if derErr := ber.ValidateDEREncodedElement(enc_der_1); derErr != nil {
			return nil, fmt.Errorf("encoding sms-IN-key as DER: %w", derErr)
		}
		return enc_der_1, nil
	}
	encoded, err := v.marshalBER()
	if err != nil {
		return nil, err
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding INKey as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes INKey from BER/DER format.
func (v *INKey) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: INKey destination is nil", ber.ErrInvalidValue)
	}
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
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
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = INKey{}
	if len(data) == 0 {
		return fmt.Errorf("empty data for INKey CHOICE")
	}
	choiceData := data
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for INKey: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData, opts...)
	if tlvErr != nil {
		return fmt.Errorf("decoding INKey CHOICE: %w", tlvErr)
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "INKey", Cause: ber.ErrExtraData}
	}

	if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2 && peekTag.Constructed == true {
		v.Choice = INKeyChoiceMobileINKey
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData, opts...)
		if tlvErr != nil {
			return fmt.Errorf("decoding mobile-IN-key: %w", tlvErr)
		}
		reconstructed, reconstructionErr := ber.EncodeSequence(rawVal)
		if reconstructionErr != nil {
			return reconstructionErr
		}
		var dec MKey
		if unmErr := dec.UnmarshalBER(reconstructed, ber.ChildDecodeOptions(opts, "mobile-IN-key")...); unmErr != nil {
			return fmt.Errorf("decoding mobile-IN-key: %w", unmErr)
		}
		v.MobileINKey = &dec
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3 && peekTag.Constructed == true {
		v.Choice = INKeyChoiceSmsINKey
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData, opts...)
		if tlvErr != nil {
			return fmt.Errorf("decoding sms-IN-key: %w", tlvErr)
		}
		reconstructed, reconstructionErr := ber.EncodeSequence(rawVal)
		if reconstructionErr != nil {
			return reconstructionErr
		}
		var dec SMSKey
		if unmErr := dec.UnmarshalBER(reconstructed, ber.ChildDecodeOptions(opts, "sms-IN-key")...); unmErr != nil {
			return fmt.Errorf("decoding sms-IN-key: %w", unmErr)
		}
		v.SmsINKey = &dec
	} else {
		return fmt.Errorf("unknown tag %s for INKey CHOICE", peekTag)
	}
	return nil
}

// MarshalBER encodes MKey to BER format.
func (v *MKey) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: MKey receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *MKey) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if v.MKeyVer != nil {
		if len(*v.MKeyVer) < 1 || len(*v.MKeyVer) > 1 {
			if constraintErr := ber.CheckEncodedLength(opts, "mKeyVer", "SIZE (1)", len(*v.MKeyVer)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_mkeyver, encodeErr_enc_mkeyver := ber.EncodeOctetString([]byte(*v.MKeyVer))
		if encodeErr_enc_mkeyver != nil {
			return nil, fmt.Errorf("encoding mKeyVer: %w", encodeErr_enc_mkeyver)
		}
		retagged_enc_mkeyver, tagErr_enc_mkeyver := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_mkeyver)
		if tagErr_enc_mkeyver != nil {
			return nil, fmt.Errorf("encoding mKeyVer: %w", tagErr_enc_mkeyver)
		}
		enc_mkeyver = retagged_enc_mkeyver
		children = append(children, enc_mkeyver...)
	}
	if v.MmScfAddress != nil {
		if len(*v.MmScfAddress) < 1 || len(*v.MmScfAddress) > 9 {
			if constraintErr := ber.CheckEncodedLength(opts, "mmScfAddress", "SIZE (1..9)", len(*v.MmScfAddress)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		if len(*v.MmScfAddress) < 1 || len(*v.MmScfAddress) > 20 {
			if constraintErr := ber.CheckEncodedLength(opts, "mmScfAddress", "SIZE (1..20)", len(*v.MmScfAddress)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_mmscfaddress, encodeErr_enc_mmscfaddress := ber.EncodeOctetString([]byte(*v.MmScfAddress))
		if encodeErr_enc_mmscfaddress != nil {
			return nil, fmt.Errorf("encoding mmScfAddress: %w", encodeErr_enc_mmscfaddress)
		}
		retagged_enc_mmscfaddress, tagErr_enc_mmscfaddress := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_mmscfaddress)
		if tagErr_enc_mmscfaddress != nil {
			return nil, fmt.Errorf("encoding mmScfAddress: %w", tagErr_enc_mmscfaddress)
		}
		enc_mmscfaddress = retagged_enc_mmscfaddress
		children = append(children, enc_mmscfaddress...)
	}
	if v.MmTdpName != nil {
		if len(*v.MmTdpName) < 1 || len(*v.MmTdpName) > 8 {
			if constraintErr := ber.CheckEncodedLength(opts, "mmTdpName", "SIZE (1..8)", len(*v.MmTdpName)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_mmtdpname, encodeErr_enc_mmtdpname := ber.EncodeOctetString([]byte(*v.MmTdpName))
		if encodeErr_enc_mmtdpname != nil {
			return nil, fmt.Errorf("encoding mmTdpName: %w", encodeErr_enc_mmtdpname)
		}
		retagged_enc_mmtdpname, tagErr_enc_mmtdpname := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_mmtdpname)
		if tagErr_enc_mmtdpname != nil {
			return nil, fmt.Errorf("encoding mmTdpName: %w", tagErr_enc_mmtdpname)
		}
		enc_mmtdpname = retagged_enc_mmtdpname
		children = append(children, enc_mmtdpname...)
	}
	if v.ServiceKey != nil {
		if !(int64(*v.ServiceKey) >= 0 && int64(*v.ServiceKey) <= 2147483647) {
			if constraintErr := ber.CheckEncodedValue(opts, "serviceKey", "(0..2147483647)", fmt.Sprint(int64(*v.ServiceKey))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_servicekey := ber.EncodeInteger(int64(*v.ServiceKey))
		retagged_enc_servicekey, tagErr_enc_servicekey := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, enc_servicekey)
		if tagErr_enc_servicekey != nil {
			return nil, fmt.Errorf("encoding serviceKey: %w", tagErr_enc_servicekey)
		}
		enc_servicekey = retagged_enc_servicekey
		children = append(children, enc_servicekey...)
	}
	if v.LocupType != nil {
		if len(*v.LocupType) < 1 || len(*v.LocupType) > 8 {
			if constraintErr := ber.CheckEncodedLength(opts, "locupType", "SIZE (1..8)", len(*v.LocupType)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_locuptype, encodeErr_enc_locuptype := ber.EncodeOctetString([]byte(*v.LocupType))
		if encodeErr_enc_locuptype != nil {
			return nil, fmt.Errorf("encoding locupType: %w", encodeErr_enc_locuptype)
		}
		retagged_enc_locuptype, tagErr_enc_locuptype := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, enc_locuptype)
		if tagErr_enc_locuptype != nil {
			return nil, fmt.Errorf("encoding locupType: %w", tagErr_enc_locuptype)
		}
		enc_locuptype = retagged_enc_locuptype
		children = append(children, enc_locuptype...)
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

// MarshalDER encodes MKey to DER format.
func (v *MKey) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: MKey receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if v.MKeyVer != nil {
		if len(*v.MKeyVer) < 1 || len(*v.MKeyVer) > 1 {
			if constraintErr := ber.CheckEncodedLength(nil, "mKeyVer", "SIZE (1)", len(*v.MKeyVer)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_mkeyver, encodeErr_enc_mkeyver := ber.EncodeOctetString([]byte(*v.MKeyVer))
		if encodeErr_enc_mkeyver != nil {
			return nil, fmt.Errorf("encoding mKeyVer: %w", encodeErr_enc_mkeyver)
		}
		if string(enc_mkeyver) != "\x04\x01\x80" {
			retagged_enc_mkeyver, tagErr_enc_mkeyver := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_mkeyver)
			if tagErr_enc_mkeyver != nil {
				return nil, fmt.Errorf("encoding mKeyVer: %w", tagErr_enc_mkeyver)
			}
			enc_mkeyver = retagged_enc_mkeyver
			children = append(children, enc_mkeyver...)
		}
	}
	if v.MmScfAddress != nil {
		if len(*v.MmScfAddress) < 1 || len(*v.MmScfAddress) > 9 {
			if constraintErr := ber.CheckEncodedLength(nil, "mmScfAddress", "SIZE (1..9)", len(*v.MmScfAddress)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		if len(*v.MmScfAddress) < 1 || len(*v.MmScfAddress) > 20 {
			if constraintErr := ber.CheckEncodedLength(nil, "mmScfAddress", "SIZE (1..20)", len(*v.MmScfAddress)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_mmscfaddress, encodeErr_enc_mmscfaddress := ber.EncodeOctetString([]byte(*v.MmScfAddress))
		if encodeErr_enc_mmscfaddress != nil {
			return nil, fmt.Errorf("encoding mmScfAddress: %w", encodeErr_enc_mmscfaddress)
		}
		retagged_enc_mmscfaddress, tagErr_enc_mmscfaddress := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_mmscfaddress)
		if tagErr_enc_mmscfaddress != nil {
			return nil, fmt.Errorf("encoding mmScfAddress: %w", tagErr_enc_mmscfaddress)
		}
		enc_mmscfaddress = retagged_enc_mmscfaddress
		children = append(children, enc_mmscfaddress...)
	}
	if v.MmTdpName != nil {
		if len(*v.MmTdpName) < 1 || len(*v.MmTdpName) > 8 {
			if constraintErr := ber.CheckEncodedLength(nil, "mmTdpName", "SIZE (1..8)", len(*v.MmTdpName)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_mmtdpname, encodeErr_enc_mmtdpname := ber.EncodeOctetString([]byte(*v.MmTdpName))
		if encodeErr_enc_mmtdpname != nil {
			return nil, fmt.Errorf("encoding mmTdpName: %w", encodeErr_enc_mmtdpname)
		}
		retagged_enc_mmtdpname, tagErr_enc_mmtdpname := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_mmtdpname)
		if tagErr_enc_mmtdpname != nil {
			return nil, fmt.Errorf("encoding mmTdpName: %w", tagErr_enc_mmtdpname)
		}
		enc_mmtdpname = retagged_enc_mmtdpname
		children = append(children, enc_mmtdpname...)
	}
	if v.ServiceKey != nil {
		if !(int64(*v.ServiceKey) >= 0 && int64(*v.ServiceKey) <= 2147483647) {
			if constraintErr := ber.CheckEncodedValue(nil, "serviceKey", "(0..2147483647)", fmt.Sprint(int64(*v.ServiceKey))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_servicekey := ber.EncodeInteger(int64(*v.ServiceKey))
		retagged_enc_servicekey, tagErr_enc_servicekey := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, enc_servicekey)
		if tagErr_enc_servicekey != nil {
			return nil, fmt.Errorf("encoding serviceKey: %w", tagErr_enc_servicekey)
		}
		enc_servicekey = retagged_enc_servicekey
		children = append(children, enc_servicekey...)
	}
	if v.LocupType != nil {
		if len(*v.LocupType) < 1 || len(*v.LocupType) > 8 {
			if constraintErr := ber.CheckEncodedLength(nil, "locupType", "SIZE (1..8)", len(*v.LocupType)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_locuptype, encodeErr_enc_locuptype := ber.EncodeOctetString([]byte(*v.LocupType))
		if encodeErr_enc_locuptype != nil {
			return nil, fmt.Errorf("encoding locupType: %w", encodeErr_enc_locuptype)
		}
		retagged_enc_locuptype, tagErr_enc_locuptype := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, enc_locuptype)
		if tagErr_enc_locuptype != nil {
			return nil, fmt.Errorf("encoding locupType: %w", tagErr_enc_locuptype)
		}
		enc_locuptype = retagged_enc_locuptype
		children = append(children, enc_locuptype...)
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
		return nil, fmt.Errorf("encoding MKey as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes MKey from BER/DER format.
func (v *MKey) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: MKey destination is nil", ber.ErrInvalidValue)
	}
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = MKey{}
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
		return fmt.Errorf("decoding MKey SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "MKey", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode mKeyVer
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
				decodedTag_mkeyver, n_mkeyver, rawVal_mkeyver, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding mKeyVer: %w", err)
				}
				if decodedTag_mkeyver.Class != tag.ClassContextSpecific || decodedTag_mkeyver.Number != 0 {
					return fmt.Errorf("decoding mKeyVer: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_mkeyver)
				}
				decVal_mkeyver, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_mkeyver.Constructed, rawVal_mkeyver, opts...)
				if octetErr != nil {
					return fmt.Errorf("decoding mKeyVer: %w", octetErr)
				}
				tmp_mkeyver := MKeyVer(decVal_mkeyver)
				v.MKeyVer = &tmp_mkeyver
				if offset < 0 || offset >
					len(content) || n_mkeyver < 0 || n_mkeyver >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_mkeyver
				if len(*v.MKeyVer) < 1 || len(*v.MKeyVer) > 1 {
					if constraintErr := ber.CheckDecodedLength(opts, "mKeyVer", "SIZE (1)", len(*v.MKeyVer)); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode mmScfAddress
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
				decodedTag_mmscfaddress, n_mmscfaddress, rawVal_mmscfaddress, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding mmScfAddress: %w", err)
				}
				if decodedTag_mmscfaddress.Class != tag.ClassContextSpecific || decodedTag_mmscfaddress.Number != 1 {
					return fmt.Errorf("decoding mmScfAddress: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_mmscfaddress)
				}
				decVal_mmscfaddress, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_mmscfaddress.Constructed, rawVal_mmscfaddress, opts...)
				if octetErr != nil {
					return fmt.Errorf("decoding mmScfAddress: %w", octetErr)
				}
				tmp_mmscfaddress := ISDNAddressString5(decVal_mmscfaddress)
				v.MmScfAddress = &tmp_mmscfaddress
				if offset < 0 || offset >
					len(content) || n_mmscfaddress < 0 || n_mmscfaddress >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_mmscfaddress
				if len(*v.MmScfAddress) < 1 || len(*v.MmScfAddress) > 9 {
					if constraintErr := ber.CheckDecodedLength(opts, "mmScfAddress", "SIZE (1..9)", len(*v.MmScfAddress)); constraintErr != nil {
						return constraintErr
					}
				}
				if len(*v.MmScfAddress) < 1 || len(*v.MmScfAddress) > 20 {
					if constraintErr := ber.CheckDecodedLength(opts, "mmScfAddress", "SIZE (1..20)", len(*v.MmScfAddress)); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode mmTdpName
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2 {
				decodedTag_mmtdpname, n_mmtdpname, rawVal_mmtdpname, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding mmTdpName: %w", err)
				}
				if decodedTag_mmtdpname.Class != tag.ClassContextSpecific || decodedTag_mmtdpname.Number != 2 {
					return fmt.Errorf("decoding mmTdpName: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_mmtdpname)
				}
				decVal_mmtdpname, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_mmtdpname.Constructed, rawVal_mmtdpname, opts...)
				if octetErr != nil {
					return fmt.Errorf("decoding mmTdpName: %w", octetErr)
				}
				tmp_mmtdpname := MmTdpName(decVal_mmtdpname)
				v.MmTdpName = &tmp_mmtdpname
				if offset < 0 || offset >
					len(content) || n_mmtdpname < 0 || n_mmtdpname >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_mmtdpname
				if len(*v.MmTdpName) < 1 || len(*v.MmTdpName) > 8 {
					if constraintErr := ber.CheckDecodedLength(opts, "mmTdpName", "SIZE (1..8)", len(*v.MmTdpName)); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode serviceKey
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3 {
				decodedTag_servicekey, n_servicekey, rawVal_servicekey, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding serviceKey: %w", err)
				}
				if decodedTag_servicekey.Class != tag.ClassContextSpecific || decodedTag_servicekey.Number != 3 || decodedTag_servicekey.Constructed != false {
					return fmt.Errorf("decoding serviceKey: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_servicekey)
				}
				decVal_servicekey, intErr := ber.DecodeIntegerValue(rawVal_servicekey)
				if intErr != nil {
					return fmt.Errorf("decoding serviceKey: %w", intErr)
				}
				tmp_servicekey := ExtensionsServiceKey(decVal_servicekey)
				v.ServiceKey = &tmp_servicekey
				if offset < 0 || offset >
					len(content) || n_servicekey < 0 || n_servicekey >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_servicekey
				if !(int64(*v.ServiceKey) >= 0 && int64(*v.ServiceKey) <= 2147483647) {
					if constraintErr := ber.CheckDecodedValue(opts, "serviceKey", "(0..2147483647)", fmt.Sprint(int64(*v.ServiceKey))); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode locupType
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4 {
				decodedTag_locuptype, n_locuptype, rawVal_locuptype, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding locupType: %w", err)
				}
				if decodedTag_locuptype.Class != tag.ClassContextSpecific || decodedTag_locuptype.Number != 4 {
					return fmt.Errorf("decoding locupType: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_locuptype)
				}
				decVal_locuptype, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_locuptype.Constructed, rawVal_locuptype, opts...)
				if octetErr != nil {
					return fmt.Errorf("decoding locupType: %w", octetErr)
				}
				tmp_locuptype := LocupType(decVal_locuptype)
				v.LocupType = &tmp_locuptype
				if offset < 0 || offset >
					len(content) || n_locuptype < 0 || n_locuptype >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_locuptype
				if len(*v.LocupType) < 1 || len(*v.LocupType) > 8 {
					if constraintErr := ber.CheckDecodedLength(opts, "locupType", "SIZE (1..8)", len(*v.LocupType)); constraintErr != nil {
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
			return &ber.DecodeError{Offset: offset, TypeName: "MKey", Cause: extErr_}
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

// MarshalBER encodes SMSKey to BER format.
func (v *SMSKey) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: SMSKey receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *SMSKey) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if v.MmSCPAddress != nil {
		if len(*v.MmSCPAddress) < 1 || len(*v.MmSCPAddress) > 9 {
			if constraintErr := ber.CheckEncodedLength(opts, "mmSCPAddress", "SIZE (1..9)", len(*v.MmSCPAddress)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		if len(*v.MmSCPAddress) < 1 || len(*v.MmSCPAddress) > 20 {
			if constraintErr := ber.CheckEncodedLength(opts, "mmSCPAddress", "SIZE (1..20)", len(*v.MmSCPAddress)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_mmscpaddress, encodeErr_enc_mmscpaddress := ber.EncodeOctetString([]byte(*v.MmSCPAddress))
		if encodeErr_enc_mmscpaddress != nil {
			return nil, fmt.Errorf("encoding mmSCPAddress: %w", encodeErr_enc_mmscpaddress)
		}
		retagged_enc_mmscpaddress, tagErr_enc_mmscpaddress := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_mmscpaddress)
		if tagErr_enc_mmscpaddress != nil {
			return nil, fmt.Errorf("encoding mmSCPAddress: %w", tagErr_enc_mmscpaddress)
		}
		enc_mmscpaddress = retagged_enc_mmscpaddress
		children = append(children, enc_mmscpaddress...)
	}
	if v.SmsTdpName != nil {
		if len(*v.SmsTdpName) < 1 || len(*v.SmsTdpName) > 8 {
			if constraintErr := ber.CheckEncodedLength(opts, "smsTdpName", "SIZE (1..8)", len(*v.SmsTdpName)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_smstdpname, encodeErr_enc_smstdpname := ber.EncodeOctetString([]byte(*v.SmsTdpName))
		if encodeErr_enc_smstdpname != nil {
			return nil, fmt.Errorf("encoding smsTdpName: %w", encodeErr_enc_smstdpname)
		}
		retagged_enc_smstdpname, tagErr_enc_smstdpname := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_smstdpname)
		if tagErr_enc_smstdpname != nil {
			return nil, fmt.Errorf("encoding smsTdpName: %w", tagErr_enc_smstdpname)
		}
		enc_smstdpname = retagged_enc_smstdpname
		children = append(children, enc_smstdpname...)
	}
	if v.ServiceKey != nil {
		if !(int64(*v.ServiceKey) >= 0 && int64(*v.ServiceKey) <= 2147483647) {
			if constraintErr := ber.CheckEncodedValue(opts, "serviceKey", "(0..2147483647)", fmt.Sprint(int64(*v.ServiceKey))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_servicekey := ber.EncodeInteger(int64(*v.ServiceKey))
		retagged_enc_servicekey, tagErr_enc_servicekey := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_servicekey)
		if tagErr_enc_servicekey != nil {
			return nil, fmt.Errorf("encoding serviceKey: %w", tagErr_enc_servicekey)
		}
		enc_servicekey = retagged_enc_servicekey
		children = append(children, enc_servicekey...)
	}
	if v.MmsFlag != nil {
		enc_mmsflag := ber.EncodeNull()
		retagged_enc_mmsflag, tagErr_enc_mmsflag := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, enc_mmsflag)
		if tagErr_enc_mmsflag != nil {
			return nil, fmt.Errorf("encoding mmsFlag: %w", tagErr_enc_mmsflag)
		}
		enc_mmsflag = retagged_enc_mmsflag
		children = append(children, enc_mmsflag...)
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

// MarshalDER encodes SMSKey to DER format.
func (v *SMSKey) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: SMSKey receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if v.MmSCPAddress != nil {
		if len(*v.MmSCPAddress) < 1 || len(*v.MmSCPAddress) > 9 {
			if constraintErr := ber.CheckEncodedLength(nil, "mmSCPAddress", "SIZE (1..9)", len(*v.MmSCPAddress)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		if len(*v.MmSCPAddress) < 1 || len(*v.MmSCPAddress) > 20 {
			if constraintErr := ber.CheckEncodedLength(nil, "mmSCPAddress", "SIZE (1..20)", len(*v.MmSCPAddress)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_mmscpaddress, encodeErr_enc_mmscpaddress := ber.EncodeOctetString([]byte(*v.MmSCPAddress))
		if encodeErr_enc_mmscpaddress != nil {
			return nil, fmt.Errorf("encoding mmSCPAddress: %w", encodeErr_enc_mmscpaddress)
		}
		retagged_enc_mmscpaddress, tagErr_enc_mmscpaddress := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_mmscpaddress)
		if tagErr_enc_mmscpaddress != nil {
			return nil, fmt.Errorf("encoding mmSCPAddress: %w", tagErr_enc_mmscpaddress)
		}
		enc_mmscpaddress = retagged_enc_mmscpaddress
		children = append(children, enc_mmscpaddress...)
	}
	if v.SmsTdpName != nil {
		if len(*v.SmsTdpName) < 1 || len(*v.SmsTdpName) > 8 {
			if constraintErr := ber.CheckEncodedLength(nil, "smsTdpName", "SIZE (1..8)", len(*v.SmsTdpName)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_smstdpname, encodeErr_enc_smstdpname := ber.EncodeOctetString([]byte(*v.SmsTdpName))
		if encodeErr_enc_smstdpname != nil {
			return nil, fmt.Errorf("encoding smsTdpName: %w", encodeErr_enc_smstdpname)
		}
		retagged_enc_smstdpname, tagErr_enc_smstdpname := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_smstdpname)
		if tagErr_enc_smstdpname != nil {
			return nil, fmt.Errorf("encoding smsTdpName: %w", tagErr_enc_smstdpname)
		}
		enc_smstdpname = retagged_enc_smstdpname
		children = append(children, enc_smstdpname...)
	}
	if v.ServiceKey != nil {
		if !(int64(*v.ServiceKey) >= 0 && int64(*v.ServiceKey) <= 2147483647) {
			if constraintErr := ber.CheckEncodedValue(nil, "serviceKey", "(0..2147483647)", fmt.Sprint(int64(*v.ServiceKey))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_servicekey := ber.EncodeInteger(int64(*v.ServiceKey))
		retagged_enc_servicekey, tagErr_enc_servicekey := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_servicekey)
		if tagErr_enc_servicekey != nil {
			return nil, fmt.Errorf("encoding serviceKey: %w", tagErr_enc_servicekey)
		}
		enc_servicekey = retagged_enc_servicekey
		children = append(children, enc_servicekey...)
	}
	if v.MmsFlag != nil {
		enc_mmsflag := ber.EncodeNull()
		retagged_enc_mmsflag, tagErr_enc_mmsflag := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, enc_mmsflag)
		if tagErr_enc_mmsflag != nil {
			return nil, fmt.Errorf("encoding mmsFlag: %w", tagErr_enc_mmsflag)
		}
		enc_mmsflag = retagged_enc_mmsflag
		children = append(children, enc_mmsflag...)
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
		return nil, fmt.Errorf("encoding SMSKey as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes SMSKey from BER/DER format.
func (v *SMSKey) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: SMSKey destination is nil", ber.ErrInvalidValue)
	}
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = SMSKey{}
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
		return fmt.Errorf("decoding SMSKey SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "SMSKey", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode mmSCPAddress
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
				decodedTag_mmscpaddress, n_mmscpaddress, rawVal_mmscpaddress, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding mmSCPAddress: %w", err)
				}
				if decodedTag_mmscpaddress.Class != tag.ClassContextSpecific || decodedTag_mmscpaddress.Number != 0 {
					return fmt.Errorf("decoding mmSCPAddress: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_mmscpaddress)
				}
				decVal_mmscpaddress, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_mmscpaddress.Constructed, rawVal_mmscpaddress, opts...)
				if octetErr != nil {
					return fmt.Errorf("decoding mmSCPAddress: %w", octetErr)
				}
				tmp_mmscpaddress := ISDNAddressString5(decVal_mmscpaddress)
				v.MmSCPAddress = &tmp_mmscpaddress
				if offset < 0 || offset >
					len(content) || n_mmscpaddress < 0 || n_mmscpaddress >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_mmscpaddress
				if len(*v.MmSCPAddress) < 1 || len(*v.MmSCPAddress) > 9 {
					if constraintErr := ber.CheckDecodedLength(opts, "mmSCPAddress", "SIZE (1..9)", len(*v.MmSCPAddress)); constraintErr != nil {
						return constraintErr
					}
				}
				if len(*v.MmSCPAddress) < 1 || len(*v.MmSCPAddress) > 20 {
					if constraintErr := ber.CheckDecodedLength(opts, "mmSCPAddress", "SIZE (1..20)", len(*v.MmSCPAddress)); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode smsTdpName
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
				decodedTag_smstdpname, n_smstdpname, rawVal_smstdpname, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding smsTdpName: %w", err)
				}
				if decodedTag_smstdpname.Class != tag.ClassContextSpecific || decodedTag_smstdpname.Number != 1 {
					return fmt.Errorf("decoding smsTdpName: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_smstdpname)
				}
				decVal_smstdpname, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_smstdpname.Constructed, rawVal_smstdpname, opts...)
				if octetErr != nil {
					return fmt.Errorf("decoding smsTdpName: %w", octetErr)
				}
				tmp_smstdpname := SmsTdpName(decVal_smstdpname)
				v.SmsTdpName = &tmp_smstdpname
				if offset < 0 || offset >
					len(content) || n_smstdpname < 0 || n_smstdpname >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_smstdpname
				if len(*v.SmsTdpName) < 1 || len(*v.SmsTdpName) > 8 {
					if constraintErr := ber.CheckDecodedLength(opts, "smsTdpName", "SIZE (1..8)", len(*v.SmsTdpName)); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode serviceKey
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2 {
				decodedTag_servicekey, n_servicekey, rawVal_servicekey, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding serviceKey: %w", err)
				}
				if decodedTag_servicekey.Class != tag.ClassContextSpecific || decodedTag_servicekey.Number != 2 || decodedTag_servicekey.Constructed != false {
					return fmt.Errorf("decoding serviceKey: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_servicekey)
				}
				decVal_servicekey, intErr := ber.DecodeIntegerValue(rawVal_servicekey)
				if intErr != nil {
					return fmt.Errorf("decoding serviceKey: %w", intErr)
				}
				tmp_servicekey := ExtensionsServiceKey(decVal_servicekey)
				v.ServiceKey = &tmp_servicekey
				if offset < 0 || offset >
					len(content) || n_servicekey < 0 || n_servicekey >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_servicekey
				if !(int64(*v.ServiceKey) >= 0 && int64(*v.ServiceKey) <= 2147483647) {
					if constraintErr := ber.CheckDecodedValue(opts, "serviceKey", "(0..2147483647)", fmt.Sprint(int64(*v.ServiceKey))); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode mmsFlag
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3 {
				decodedTag_mmsflag, n_mmsflag, rawVal_mmsflag, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding mmsFlag: %w", err)
				}
				if decodedTag_mmsflag.Class != tag.ClassContextSpecific || decodedTag_mmsflag.Number != 3 || decodedTag_mmsflag.Constructed != false {
					return fmt.Errorf("decoding mmsFlag: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_mmsflag)
				}
				if len(rawVal_mmsflag) != 0 {
					return fmt.Errorf("decoding mmsFlag: %w: NULL content length %d", ber.ErrInvalidValue, len(rawVal_mmsflag))
				}
				v.MmsFlag = &struct{}{}
				if offset < 0 || offset >
					len(content) || n_mmsflag < 0 || n_mmsflag > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_mmsflag
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:], opts...)
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "SMSKey", Cause: extErr_}
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

// MarshalBER encodes USSDExtension to BER format.
func (v *USSDExtension) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: USSDExtension receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *USSDExtension) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if v.RoutingCategory != nil {
		if len(*v.RoutingCategory) < 1 || len(*v.RoutingCategory) > 1 {
			if constraintErr := ber.CheckEncodedLength(opts, "routingCategory", "SIZE (1)", len(*v.RoutingCategory)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_routingcategory, encodeErr_enc_routingcategory := ber.EncodeOctetString([]byte(*v.RoutingCategory))
		if encodeErr_enc_routingcategory != nil {
			return nil, fmt.Errorf("encoding routingCategory: %w", encodeErr_enc_routingcategory)
		}
		retagged_enc_routingcategory, tagErr_enc_routingcategory := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_routingcategory)
		if tagErr_enc_routingcategory != nil {
			return nil, fmt.Errorf("encoding routingCategory: %w", tagErr_enc_routingcategory)
		}
		enc_routingcategory = retagged_enc_routingcategory
		children = append(children, enc_routingcategory...)
	}
	if v.CellId != nil {
		if len(*v.CellId) < 7 || len(*v.CellId) > 7 {
			if constraintErr := ber.CheckEncodedLength(opts, "cellId", "SIZE (7)", len(*v.CellId)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_cellid, encodeErr_enc_cellid := ber.EncodeOctetString([]byte(*v.CellId))
		if encodeErr_enc_cellid != nil {
			return nil, fmt.Errorf("encoding cellId: %w", encodeErr_enc_cellid)
		}
		retagged_enc_cellid, tagErr_enc_cellid := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_cellid)
		if tagErr_enc_cellid != nil {
			return nil, fmt.Errorf("encoding cellId: %w", tagErr_enc_cellid)
		}
		enc_cellid = retagged_enc_cellid
		children = append(children, enc_cellid...)
	}
	if v.SaiPresent != nil {
		enc_saipresent := ber.EncodeNull()
		retagged_enc_saipresent, tagErr_enc_saipresent := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_saipresent)
		if tagErr_enc_saipresent != nil {
			return nil, fmt.Errorf("encoding sai-Present: %w", tagErr_enc_saipresent)
		}
		enc_saipresent = retagged_enc_saipresent
		children = append(children, enc_saipresent...)
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
	return ber.EncodeConstructed(tag.Tag{Class: tag.ClassPrivate, Number: 10, Constructed: true}, children)
}

// MarshalDER encodes USSDExtension to DER format.
func (v *USSDExtension) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: USSDExtension receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if v.RoutingCategory != nil {
		if len(*v.RoutingCategory) < 1 || len(*v.RoutingCategory) > 1 {
			if constraintErr := ber.CheckEncodedLength(nil, "routingCategory", "SIZE (1)", len(*v.RoutingCategory)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_routingcategory, encodeErr_enc_routingcategory := ber.EncodeOctetString([]byte(*v.RoutingCategory))
		if encodeErr_enc_routingcategory != nil {
			return nil, fmt.Errorf("encoding routingCategory: %w", encodeErr_enc_routingcategory)
		}
		retagged_enc_routingcategory, tagErr_enc_routingcategory := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_routingcategory)
		if tagErr_enc_routingcategory != nil {
			return nil, fmt.Errorf("encoding routingCategory: %w", tagErr_enc_routingcategory)
		}
		enc_routingcategory = retagged_enc_routingcategory
		children = append(children, enc_routingcategory...)
	}
	if v.CellId != nil {
		if len(*v.CellId) < 7 || len(*v.CellId) > 7 {
			if constraintErr := ber.CheckEncodedLength(nil, "cellId", "SIZE (7)", len(*v.CellId)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_cellid, encodeErr_enc_cellid := ber.EncodeOctetString([]byte(*v.CellId))
		if encodeErr_enc_cellid != nil {
			return nil, fmt.Errorf("encoding cellId: %w", encodeErr_enc_cellid)
		}
		retagged_enc_cellid, tagErr_enc_cellid := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_cellid)
		if tagErr_enc_cellid != nil {
			return nil, fmt.Errorf("encoding cellId: %w", tagErr_enc_cellid)
		}
		enc_cellid = retagged_enc_cellid
		children = append(children, enc_cellid...)
	}
	if v.SaiPresent != nil {
		enc_saipresent := ber.EncodeNull()
		retagged_enc_saipresent, tagErr_enc_saipresent := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_saipresent)
		if tagErr_enc_saipresent != nil {
			return nil, fmt.Errorf("encoding sai-Present: %w", tagErr_enc_saipresent)
		}
		enc_saipresent = retagged_enc_saipresent
		children = append(children, enc_saipresent...)
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
	retagged_encoded, tagErr_encoded := ber.EncodeImplicitTagWithClass(tag.ClassPrivate, 10, encoded)
	if tagErr_encoded != nil {
		return nil, fmt.Errorf("encoding USSDExtension: %w", tagErr_encoded)
	}
	encoded = retagged_encoded
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding USSDExtension as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes USSDExtension from BER/DER format.
func (v *USSDExtension) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: USSDExtension destination is nil", ber.ErrInvalidValue)
	}
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = USSDExtension{}
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
	decodedTag, content, total, err := ber.DecodeConstructedContent(data, opts...)
	if err != nil {
		return fmt.Errorf("decoding USSDExtension: %w", err)
	}
	if decodedTag.Class != tag.ClassPrivate || decodedTag.Number != 10 || !decodedTag.Constructed {
		return fmt.Errorf("decoding USSDExtension: %w: expected tag [PRIVATE 10], got %s", ber.ErrInvalidTag, decodedTag)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "USSDExtension", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode routingCategory
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
				decodedTag_routingcategory, n_routingcategory, rawVal_routingcategory, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding routingCategory: %w", err)
				}
				if decodedTag_routingcategory.Class != tag.ClassContextSpecific || decodedTag_routingcategory.Number != 0 {
					return fmt.Errorf("decoding routingCategory: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_routingcategory)
				}
				decVal_routingcategory, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_routingcategory.Constructed, rawVal_routingcategory, opts...)
				if octetErr != nil {
					return fmt.Errorf("decoding routingCategory: %w", octetErr)
				}
				tmp_routingcategory := RoutingCategory(decVal_routingcategory)
				v.RoutingCategory = &tmp_routingcategory
				if offset < 0 || offset >
					len(content) || n_routingcategory < 0 || n_routingcategory >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_routingcategory
				if len(*v.RoutingCategory) < 1 || len(*v.RoutingCategory) > 1 {
					if constraintErr := ber.CheckDecodedLength(opts, "routingCategory", "SIZE (1)", len(*v.RoutingCategory)); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode cellId
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
				decodedTag_cellid, n_cellid, rawVal_cellid, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding cellId: %w", err)
				}
				if decodedTag_cellid.Class != tag.ClassContextSpecific || decodedTag_cellid.Number != 1 {
					return fmt.Errorf("decoding cellId: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_cellid)
				}
				decVal_cellid, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_cellid.Constructed, rawVal_cellid, opts...)
				if octetErr != nil {
					return fmt.Errorf("decoding cellId: %w", octetErr)
				}
				tmp_cellid := CellGlobalIdOrServiceAreaIdFixedLength5(decVal_cellid)
				v.CellId = &tmp_cellid
				if offset < 0 || offset >
					len(content) || n_cellid < 0 || n_cellid > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_cellid
				if len(*v.CellId) < 7 || len(*v.CellId) > 7 {
					if constraintErr := ber.CheckDecodedLength(opts, "cellId", "SIZE (7)", len(*v.CellId)); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode sai-Present
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2 {
				decodedTag_saipresent, n_saipresent, rawVal_saipresent, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding sai-Present: %w", err)
				}
				if decodedTag_saipresent.Class != tag.ClassContextSpecific || decodedTag_saipresent.Number != 2 || decodedTag_saipresent.Constructed != false {
					return fmt.Errorf("decoding sai-Present: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_saipresent)
				}
				if len(rawVal_saipresent) != 0 {
					return fmt.Errorf("decoding sai-Present: %w: NULL content length %d", ber.ErrInvalidValue, len(rawVal_saipresent))
				}
				v.SaiPresent = &struct{}{}
				if offset < 0 || offset >
					len(content) || n_saipresent < 0 || n_saipresent > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_saipresent
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:], opts...)
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "USSDExtension", Cause: extErr_}
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

// MarshalBER encodes HOExt to BER format.
func (v *HOExt) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: HOExt receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *HOExt) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if v.MapOpt != nil {
		if len(*v.MapOpt) < 1 || len(*v.MapOpt) > 1 {
			if constraintErr := ber.CheckEncodedLength(opts, "map-Opt", "SIZE (1)", len(*v.MapOpt)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_mapopt, encodeErr_enc_mapopt := ber.EncodeOctetString([]byte(*v.MapOpt))
		if encodeErr_enc_mapopt != nil {
			return nil, fmt.Errorf("encoding map-Opt: %w", encodeErr_enc_mapopt)
		}
		retagged_enc_mapopt, tagErr_enc_mapopt := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_mapopt)
		if tagErr_enc_mapopt != nil {
			return nil, fmt.Errorf("encoding map-Opt: %w", tagErr_enc_mapopt)
		}
		enc_mapopt = retagged_enc_mapopt
		children = append(children, enc_mapopt...)
	}
	if v.CodecList != nil {
		if len((v.CodecList).Values) > 8 {
			if constraintErr := ber.CheckEncodedLength(opts, "codec-List", "SIZE (0..8)", len((v.CodecList).Values)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_codeclist, err := MarshalBERCodecListExt(v.CodecList, ber.ChildEncodeOptions(opts, "codec-List")...)
		if err != nil {
			return nil, fmt.Errorf("encoding codec-List: %w", err)
		}
		if v.CodecListIndef_ {
			// Strip the outer SEQUENCE tag from marshalBER output to get raw children.
			_, _, seqContent_, tlvErr_ := ber.DecodeEncodedTLV(enc_codeclist)
			if tlvErr_ != nil {
				return nil, tlvErr_
			}
			{
				var encodeErr error
				enc_codeclist, encodeErr = ber.EncodeConstructedIndefinite(tag.Tag{Class: tag.ClassContextSpecific, Number: 1}, seqContent_)
				if encodeErr != nil {
					return nil, fmt.Errorf("encoding codec-List: %w", encodeErr)
				}
			}
		} else {
			retagged_enc_codeclist, tagErr_enc_codeclist := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_codeclist)
			if tagErr_enc_codeclist != nil {
				return nil, fmt.Errorf("encoding codec-List: %w", tagErr_enc_codeclist)
			}
			enc_codeclist = retagged_enc_codeclist
		}
		children = append(children, enc_codeclist...)
	}
	if v.SelectedCodec != nil {
		enc_selectedcodec, err := v.SelectedCodec.MarshalBER(ber.ChildEncodeOptions(opts, "selected-Codec")...)
		if err != nil {
			return nil, fmt.Errorf("encoding selected-Codec: %w", err)
		}
		retagged_enc_selectedcodec, tagErr_enc_selectedcodec := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_selectedcodec)
		if tagErr_enc_selectedcodec != nil {
			return nil, fmt.Errorf("encoding selected-Codec: %w", tagErr_enc_selectedcodec)
		}
		enc_selectedcodec = retagged_enc_selectedcodec
		children = append(children, enc_selectedcodec...)
	}
	if v.UmaAccess != nil {
		enc_umaaccess := ber.EncodeNull()
		retagged_enc_umaaccess, tagErr_enc_umaaccess := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, enc_umaaccess)
		if tagErr_enc_umaaccess != nil {
			return nil, fmt.Errorf("encoding uma-access: %w", tagErr_enc_umaaccess)
		}
		enc_umaaccess = retagged_enc_umaaccess
		children = append(children, enc_umaaccess...)
	}
	if v.UmaIpAddress != nil {
		if len(v.UmaIpAddress) < 5 || len(v.UmaIpAddress) > 17 {
			if constraintErr := ber.CheckEncodedLength(opts, "uma-ip-address", "SIZE (5..17)", len(v.UmaIpAddress)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_umaipaddress, encodeErr_enc_umaipaddress := ber.EncodeOctetString(v.UmaIpAddress)
		if encodeErr_enc_umaipaddress != nil {
			return nil, fmt.Errorf("encoding uma-ip-address: %w", encodeErr_enc_umaipaddress)
		}
		retagged_enc_umaipaddress, tagErr_enc_umaipaddress := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, enc_umaipaddress)
		if tagErr_enc_umaipaddress != nil {
			return nil, fmt.Errorf("encoding uma-ip-address: %w", tagErr_enc_umaipaddress)
		}
		enc_umaipaddress = retagged_enc_umaipaddress
		children = append(children, enc_umaipaddress...)
	}
	if v.UmaIpPortNb != nil {
		if !(int64(*v.UmaIpPortNb) >= 0 && int64(*v.UmaIpPortNb) <= 65535) {
			if constraintErr := ber.CheckEncodedValue(opts, "uma-ip-port-nb", "(0..65535)", fmt.Sprint(int64(*v.UmaIpPortNb))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_umaipportnb := ber.EncodeInteger(int64(*v.UmaIpPortNb))
		retagged_enc_umaipportnb, tagErr_enc_umaipportnb := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 5, enc_umaipportnb)
		if tagErr_enc_umaipportnb != nil {
			return nil, fmt.Errorf("encoding uma-ip-port-nb: %w", tagErr_enc_umaipportnb)
		}
		enc_umaipportnb = retagged_enc_umaipportnb
		children = append(children, enc_umaipportnb...)
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
	return ber.EncodeConstructed(tag.Tag{Class: tag.ClassPrivate, Number: 0, Constructed: true}, children)
}

// MarshalDER encodes HOExt to DER format.
func (v *HOExt) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: HOExt receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if v.MapOpt != nil {
		if len(*v.MapOpt) < 1 || len(*v.MapOpt) > 1 {
			if constraintErr := ber.CheckEncodedLength(nil, "map-Opt", "SIZE (1)", len(*v.MapOpt)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_mapopt, encodeErr_enc_mapopt := ber.EncodeOctetString([]byte(*v.MapOpt))
		if encodeErr_enc_mapopt != nil {
			return nil, fmt.Errorf("encoding map-Opt: %w", encodeErr_enc_mapopt)
		}
		retagged_enc_mapopt, tagErr_enc_mapopt := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_mapopt)
		if tagErr_enc_mapopt != nil {
			return nil, fmt.Errorf("encoding map-Opt: %w", tagErr_enc_mapopt)
		}
		enc_mapopt = retagged_enc_mapopt
		children = append(children, enc_mapopt...)
	}
	if v.CodecList != nil {
		if len((v.CodecList).Values) > 8 {
			if constraintErr := ber.CheckEncodedLength(nil, "codec-List", "SIZE (0..8)", len((v.CodecList).Values)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_codeclist, err := MarshalDERCodecListExt(v.CodecList)
		if err != nil {
			return nil, fmt.Errorf("encoding codec-List: %w", err)
		}
		retagged_enc_codeclist, tagErr_enc_codeclist := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_codeclist)
		if tagErr_enc_codeclist != nil {
			return nil, fmt.Errorf("encoding codec-List: %w", tagErr_enc_codeclist)
		}
		enc_codeclist = retagged_enc_codeclist
		children = append(children, enc_codeclist...)
	}
	if v.SelectedCodec != nil {
		enc_selectedcodec, err := v.SelectedCodec.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding selected-Codec: %w", err)
		}
		retagged_enc_selectedcodec, tagErr_enc_selectedcodec := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_selectedcodec)
		if tagErr_enc_selectedcodec != nil {
			return nil, fmt.Errorf("encoding selected-Codec: %w", tagErr_enc_selectedcodec)
		}
		enc_selectedcodec = retagged_enc_selectedcodec
		children = append(children, enc_selectedcodec...)
	}
	if v.UmaAccess != nil {
		enc_umaaccess := ber.EncodeNull()
		retagged_enc_umaaccess, tagErr_enc_umaaccess := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, enc_umaaccess)
		if tagErr_enc_umaaccess != nil {
			return nil, fmt.Errorf("encoding uma-access: %w", tagErr_enc_umaaccess)
		}
		enc_umaaccess = retagged_enc_umaaccess
		children = append(children, enc_umaaccess...)
	}
	if v.UmaIpAddress != nil {
		if len(v.UmaIpAddress) < 5 || len(v.UmaIpAddress) > 17 {
			if constraintErr := ber.CheckEncodedLength(nil, "uma-ip-address", "SIZE (5..17)", len(v.UmaIpAddress)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_umaipaddress, encodeErr_enc_umaipaddress := ber.EncodeOctetString(v.UmaIpAddress)
		if encodeErr_enc_umaipaddress != nil {
			return nil, fmt.Errorf("encoding uma-ip-address: %w", encodeErr_enc_umaipaddress)
		}
		retagged_enc_umaipaddress, tagErr_enc_umaipaddress := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, enc_umaipaddress)
		if tagErr_enc_umaipaddress != nil {
			return nil, fmt.Errorf("encoding uma-ip-address: %w", tagErr_enc_umaipaddress)
		}
		enc_umaipaddress = retagged_enc_umaipaddress
		children = append(children, enc_umaipaddress...)
	}
	if v.UmaIpPortNb != nil {
		if !(int64(*v.UmaIpPortNb) >= 0 && int64(*v.UmaIpPortNb) <= 65535) {
			if constraintErr := ber.CheckEncodedValue(nil, "uma-ip-port-nb", "(0..65535)", fmt.Sprint(int64(*v.UmaIpPortNb))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_umaipportnb := ber.EncodeInteger(int64(*v.UmaIpPortNb))
		retagged_enc_umaipportnb, tagErr_enc_umaipportnb := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 5, enc_umaipportnb)
		if tagErr_enc_umaipportnb != nil {
			return nil, fmt.Errorf("encoding uma-ip-port-nb: %w", tagErr_enc_umaipportnb)
		}
		enc_umaipportnb = retagged_enc_umaipportnb
		children = append(children, enc_umaipportnb...)
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
	retagged_encoded, tagErr_encoded := ber.EncodeImplicitTagWithClass(tag.ClassPrivate, 0, encoded)
	if tagErr_encoded != nil {
		return nil, fmt.Errorf("encoding HOExt: %w", tagErr_encoded)
	}
	encoded = retagged_encoded
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding HOExt as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes HOExt from BER/DER format.
func (v *HOExt) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: HOExt destination is nil", ber.ErrInvalidValue)
	}
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = HOExt{}
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
	decodedTag, content, total, err := ber.DecodeConstructedContent(data, opts...)
	if err != nil {
		return fmt.Errorf("decoding HOExt: %w", err)
	}
	if decodedTag.Class != tag.ClassPrivate || decodedTag.Number != 0 || !decodedTag.Constructed {
		return fmt.Errorf("decoding HOExt: %w: expected tag [PRIVATE 0], got %s", ber.ErrInvalidTag, decodedTag)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "HOExt", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode map-Opt
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
				decodedTag_mapopt, n_mapopt, rawVal_mapopt, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding map-Opt: %w", err)
				}
				if decodedTag_mapopt.Class != tag.ClassContextSpecific || decodedTag_mapopt.Number != 0 {
					return fmt.Errorf("decoding map-Opt: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_mapopt)
				}
				decVal_mapopt, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_mapopt.Constructed, rawVal_mapopt, opts...)
				if octetErr != nil {
					return fmt.Errorf("decoding map-Opt: %w", octetErr)
				}
				tmp_mapopt := MapOptFields(decVal_mapopt)
				v.MapOpt = &tmp_mapopt
				if offset < 0 || offset >
					len(content) || n_mapopt < 0 || n_mapopt > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_mapopt
				if len(*v.MapOpt) < 1 || len(*v.MapOpt) > 1 {
					if constraintErr := ber.CheckDecodedLength(opts, "map-Opt", "SIZE (1)", len(*v.MapOpt)); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode codec-List
	v.CodecListIndef_ = false
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
				decodedTag_codeclist, n_codeclist, rawVal_codeclist, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding codec-List: %w", err)
				}
				if decodedTag_codeclist.Class != tag.ClassContextSpecific || decodedTag_codeclist.Number != 1 || decodedTag_codeclist.Constructed != true {
					return fmt.Errorf("decoding codec-List: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_codeclist)
				}
				reconstructed_codeclist, reconstructionErr_codeclist := ber.EncodeSequence(rawVal_codeclist)
				if reconstructionErr_codeclist != nil {
					return fmt.Errorf("decoding codec-List: %w", reconstructionErr_codeclist)
				}
				dec_codeclist, unmErr := UnmarshalBERCodecListExt(reconstructed_codeclist, ber.ChildDecodeOptions(opts, "codec-List")...)
				if unmErr != nil {
					return fmt.Errorf("decoding codec-List: %w", unmErr)
				}
				v.CodecList = dec_codeclist
				{
					_, tagSz_, _ := ber.DecodeTag(content[offset:])
					if offset < 0 || offset >
						len(content) || tagSz_ < 0 || tagSz_ > len(content[offset:]) {
						return fmt.Errorf("invalid BER content window")
					}

					if offset+tagSz_ < len(content) && content[offset+tagSz_] == 0x80 {
						v.CodecListIndef_ = true
					}
				}
				if offset < 0 || offset >
					len(content) || n_codeclist < 0 || n_codeclist >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_codeclist
				if len((v.CodecList).Values) > 8 {
					if constraintErr := ber.CheckDecodedLength(opts, "codec-List", "SIZE (0..8)", len((v.CodecList).Values)); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode selected-Codec
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2 {
				decodedTag_selectedcodec, n_selectedcodec, rawVal_selectedcodec, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding selected-Codec: %w", err)
				}
				if decodedTag_selectedcodec.Class != tag.ClassContextSpecific || decodedTag_selectedcodec.Number != 2 || decodedTag_selectedcodec.Constructed != true {
					return fmt.Errorf("decoding selected-Codec: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_selectedcodec)
				}
				reconstructed_selectedcodec, reconstructionErr_selectedcodec := ber.EncodeSequence(rawVal_selectedcodec)
				if reconstructionErr_selectedcodec != nil {
					return fmt.Errorf("decoding selected-Codec: %w", reconstructionErr_selectedcodec)
				}
				var dec_selectedcodec SelectedCodec
				if unmErr := dec_selectedcodec.UnmarshalBER(reconstructed_selectedcodec, ber.ChildDecodeOptions(opts, "selected-Codec")...); unmErr != nil {
					return fmt.Errorf("decoding selected-Codec: %w", unmErr)
				}
				v.SelectedCodec = &dec_selectedcodec
				if offset < 0 || offset >
					len(content) || n_selectedcodec < 0 || n_selectedcodec >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_selectedcodec
			}
		}
	}
	// Decode uma-access
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3 {
				decodedTag_umaaccess, n_umaaccess, rawVal_umaaccess, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding uma-access: %w", err)
				}
				if decodedTag_umaaccess.Class != tag.ClassContextSpecific || decodedTag_umaaccess.Number != 3 || decodedTag_umaaccess.Constructed != false {
					return fmt.Errorf("decoding uma-access: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_umaaccess)
				}
				if len(rawVal_umaaccess) != 0 {
					return fmt.Errorf("decoding uma-access: %w: NULL content length %d", ber.ErrInvalidValue, len(rawVal_umaaccess))
				}
				v.UmaAccess = &struct{}{}
				if offset < 0 || offset >
					len(content) || n_umaaccess < 0 || n_umaaccess >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_umaaccess
			}
		}
	}
	// Decode uma-ip-address
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4 {
				decodedTag_umaipaddress, n_umaipaddress, rawVal_umaipaddress, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding uma-ip-address: %w", err)
				}
				if decodedTag_umaipaddress.Class != tag.ClassContextSpecific || decodedTag_umaipaddress.Number != 4 {
					return fmt.Errorf("decoding uma-ip-address: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_umaipaddress)
				}
				decVal_umaipaddress, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_umaipaddress.Constructed, rawVal_umaipaddress, opts...)
				if octetErr != nil {
					return fmt.Errorf("decoding uma-ip-address: %w", octetErr)
				}
				tmp_umaipaddress := decVal_umaipaddress
				v.UmaIpAddress = tmp_umaipaddress
				if offset < 0 || offset >
					len(content) || n_umaipaddress < 0 || n_umaipaddress >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_umaipaddress
				if len(v.UmaIpAddress) < 5 || len(v.UmaIpAddress) > 17 {
					if constraintErr := ber.CheckDecodedLength(opts, "uma-ip-address", "SIZE (5..17)", len(v.UmaIpAddress)); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode uma-ip-port-nb
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 5 {
				decodedTag_umaipportnb, n_umaipportnb, rawVal_umaipportnb, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding uma-ip-port-nb: %w", err)
				}
				if decodedTag_umaipportnb.Class != tag.ClassContextSpecific || decodedTag_umaipportnb.Number != 5 || decodedTag_umaipportnb.Constructed != false {
					return fmt.Errorf("decoding uma-ip-port-nb: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_umaipportnb)
				}
				decVal_umaipportnb, intErr := ber.DecodeIntegerValue(rawVal_umaipportnb)
				if intErr != nil {
					return fmt.Errorf("decoding uma-ip-port-nb: %w", intErr)
				}
				tmp_umaipportnb := IPPortNb(decVal_umaipportnb)
				v.UmaIpPortNb = &tmp_umaipportnb
				if offset < 0 || offset >
					len(content) || n_umaipportnb < 0 || n_umaipportnb >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_umaipportnb
				if !(int64(*v.UmaIpPortNb) >= 0 && int64(*v.UmaIpPortNb) <= 65535) {
					if constraintErr := ber.CheckDecodedValue(opts, "uma-ip-port-nb", "(0..65535)", fmt.Sprint(int64(*v.UmaIpPortNb))); constraintErr != nil {
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
			return &ber.DecodeError{Offset: offset, TypeName: "HOExt", Cause: extErr_}
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

// MarshalBERCodecListExt encodes a CodecListExt list to BER.
func MarshalBERCodecListExt(collection *CodecListExt, opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	if collection == nil {
		return nil, fmt.Errorf("%w: required collection is nil", ber.ErrInvalidValue)
	}
	encoded, err := marshalBERCodecListExt(collection, opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, collection.berOriginal_, collection.berSnapshot_, opts), nil
}
func marshalBERCodecListExt(collection *CodecListExt, opts ...ber.EncodeOption) ([]byte, error) {
	list := collection.Values
	if len(list) > 8 {
		if constraintErr := ber.CheckEncodedLength(opts, "CodecListExt", "SIZE (0..8)", len(list)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	var children []byte
	for elemIndex, elem := range list {
		if len(elem) < 1 || len(elem) > 1 {
			if constraintErr := ber.CheckEncodedLength(opts, fmt.Sprintf("element[%d]", elemIndex), "SIZE (1)", len(elem)); constraintErr != nil {
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

// MarshalDERCodecListExt encodes a CodecListExt list to DER.
func MarshalDERCodecListExt(collection *CodecListExt) ([]byte, error) {
	if collection == nil {
		return nil, fmt.Errorf("%w: required collection is nil", ber.ErrInvalidValue)
	}
	list := collection.Values
	if len(list) > 8 {
		if constraintErr := ber.CheckEncodedLength(nil, "CodecListExt", "SIZE (0..8)", len(list)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	var children []byte
	for elemIndex, elem := range list {
		if len(elem) < 1 || len(elem) > 1 {
			if constraintErr := ber.CheckEncodedLength(nil, fmt.Sprintf("element[%d]", elemIndex), "SIZE (1)", len(elem)); constraintErr != nil {
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
		return nil, fmt.Errorf("encoding CodecListExt as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBERCodecListExt decodes a CodecListExt list from BER.
func UnmarshalBERCodecListExt(data []byte, opts ...ber.DecodeOption) (returnValue *CodecListExt, returnErr error) {
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return nil, err
	}
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return nil, fmt.Errorf("decoding CodecListExt: %w", err)
	}
	if total != len(data) {
		return nil, &ber.DecodeError{Offset: total, TypeName: "CodecListExt", Cause: ber.ErrExtraData}
	}
	var result []CodecExt
	offset := 0
	for offset < len(content) {
		elementData := content[offset:]
		val, n, osErr := ber.DecodeOctetString(elementData, opts...)
		if osErr != nil {
			return nil, fmt.Errorf("decoding element: %w", osErr)
		}
		if len(val) < 1 || len(val) > 1 {
			if constraintErr := ber.CheckDecodedLength(opts, fmt.Sprintf("element[%d]", len(result)), "SIZE (1)", len(val)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		result = append(result, CodecExt(val))
		if offset < 0 || offset >
			len(content) || n < 0 || n > len(content[offset:]) {
			return nil, fmt.Errorf("invalid BER content window")
		}

		offset += n
	}
	if len(result) > 8 {
		if constraintErr := ber.CheckDecodedLength(opts, "CodecListExt", "SIZE (0..8)", len(result)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	decoded := &CodecListExt{Values: result}
	if ber.BERNeedsPreservation(opts) {
		var snapshotReports ber.ViolationLog
		snapshot, snapshotErr := MarshalBERCodecListExt(decoded, ber.WithConstraintTolerance(&snapshotReports))
		if snapshotErr != nil {
			return nil, snapshotErr
		}
		decoded.berOriginal_ = append([]byte(nil), data...)
		decoded.berSnapshot_ = snapshot
	}
	return decoded, nil
}

// MarshalBER encodes SelectedCodec to BER format.
func (v *SelectedCodec) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: SelectedCodec receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *SelectedCodec) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if len(v.Codec) < 1 || len(v.Codec) > 1 {
		if constraintErr := ber.CheckEncodedLength(opts, "codec", "SIZE (1)", len(v.Codec)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_codec, encodeErr_enc_codec := ber.EncodeOctetString([]byte(v.Codec))
	if encodeErr_enc_codec != nil {
		return nil, fmt.Errorf("encoding codec: %w", encodeErr_enc_codec)
	}
	retagged_enc_codec, tagErr_enc_codec := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_codec)
	if tagErr_enc_codec != nil {
		return nil, fmt.Errorf("encoding codec: %w", tagErr_enc_codec)
	}
	enc_codec = retagged_enc_codec
	children = append(children, enc_codec...)
	if len(v.Modes) < 9 || len(v.Modes) > 9 {
		if constraintErr := ber.CheckEncodedLength(opts, "modes", "SIZE (9)", len(v.Modes)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_modes, encodeErr_enc_modes := ber.EncodeOctetString([]byte(v.Modes))
	if encodeErr_enc_modes != nil {
		return nil, fmt.Errorf("encoding modes: %w", encodeErr_enc_modes)
	}
	retagged_enc_modes, tagErr_enc_modes := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_modes)
	if tagErr_enc_modes != nil {
		return nil, fmt.Errorf("encoding modes: %w", tagErr_enc_modes)
	}
	enc_modes = retagged_enc_modes
	children = append(children, enc_modes...)
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

// MarshalDER encodes SelectedCodec to DER format.
func (v *SelectedCodec) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: SelectedCodec receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if len(v.Codec) < 1 || len(v.Codec) > 1 {
		if constraintErr := ber.CheckEncodedLength(nil, "codec", "SIZE (1)", len(v.Codec)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_codec, encodeErr_enc_codec := ber.EncodeOctetString([]byte(v.Codec))
	if encodeErr_enc_codec != nil {
		return nil, fmt.Errorf("encoding codec: %w", encodeErr_enc_codec)
	}
	retagged_enc_codec, tagErr_enc_codec := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_codec)
	if tagErr_enc_codec != nil {
		return nil, fmt.Errorf("encoding codec: %w", tagErr_enc_codec)
	}
	enc_codec = retagged_enc_codec
	children = append(children, enc_codec...)
	if len(v.Modes) < 9 || len(v.Modes) > 9 {
		if constraintErr := ber.CheckEncodedLength(nil, "modes", "SIZE (9)", len(v.Modes)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_modes, encodeErr_enc_modes := ber.EncodeOctetString([]byte(v.Modes))
	if encodeErr_enc_modes != nil {
		return nil, fmt.Errorf("encoding modes: %w", encodeErr_enc_modes)
	}
	retagged_enc_modes, tagErr_enc_modes := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_modes)
	if tagErr_enc_modes != nil {
		return nil, fmt.Errorf("encoding modes: %w", tagErr_enc_modes)
	}
	enc_modes = retagged_enc_modes
	children = append(children, enc_modes...)
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
		return nil, fmt.Errorf("encoding SelectedCodec as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes SelectedCodec from BER/DER format.
func (v *SelectedCodec) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: SelectedCodec destination is nil", ber.ErrInvalidValue)
	}
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = SelectedCodec{}
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
		return fmt.Errorf("decoding SelectedCodec SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "SelectedCodec", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode codec
	if offset >= len(content) {
		return fmt.Errorf("missing required field codec")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 0 {
			return fmt.Errorf("expected tag [%s %d] for codec, got %s", "CONTEXT", 0, reqTag_)
		}
	}
	decodedTag_codec, n_codec, rawVal_codec, err := ber.DecodeTLV(content[offset:], opts...)
	if err != nil {
		return fmt.Errorf("decoding codec: %w", err)
	}
	if decodedTag_codec.Class != tag.ClassContextSpecific || decodedTag_codec.Number != 0 {
		return fmt.Errorf("decoding codec: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_codec)
	}
	decVal_codec, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_codec.Constructed, rawVal_codec, opts...)
	if octetErr != nil {
		return fmt.Errorf("decoding codec: %w", octetErr)
	}
	v.Codec = CodecExt(decVal_codec)
	if offset < 0 || offset >
		len(content) || n_codec < 0 || n_codec > len(content[offset:]) {
		return fmt.Errorf("invalid BER content window")
	}

	offset += n_codec
	if len(v.Codec) < 1 || len(v.Codec) > 1 {
		if constraintErr := ber.CheckDecodedLength(opts, "codec", "SIZE (1)", len(v.Codec)); constraintErr != nil {
			return constraintErr
		}
	}
	// Decode modes
	if offset >= len(content) {
		return fmt.Errorf("missing required field modes")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 1 {
			return fmt.Errorf("expected tag [%s %d] for modes, got %s", "CONTEXT", 1, reqTag_)
		}
	}
	decodedTag_modes, n_modes, rawVal_modes, err := ber.DecodeTLV(content[offset:], opts...)
	if err != nil {
		return fmt.Errorf("decoding modes: %w", err)
	}
	if decodedTag_modes.Class != tag.ClassContextSpecific || decodedTag_modes.Number != 1 {
		return fmt.Errorf("decoding modes: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_modes)
	}
	decVal_modes, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_modes.Constructed, rawVal_modes, opts...)
	if octetErr != nil {
		return fmt.Errorf("decoding modes: %w", octetErr)
	}
	v.Modes = Modes(decVal_modes)
	if offset < 0 || offset >
		len(content) || n_modes < 0 || n_modes > len(content[offset:]) {
		return fmt.Errorf("invalid BER content window")
	}

	offset += n_modes
	if len(v.Modes) < 9 || len(v.Modes) > 9 {
		if constraintErr := ber.CheckDecodedLength(opts, "modes", "SIZE (9)", len(v.Modes)); constraintErr != nil {
			return constraintErr
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:], opts...)
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "SelectedCodec", Cause: extErr_}
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

// MarshalBER encodes AbsentSubscriberExt to BER format.
func (v *AbsentSubscriberExt) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: AbsentSubscriberExt receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *AbsentSubscriberExt) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if v.OlcmInfoTable != nil {
		if len((v.OlcmInfoTable).Values) < 1 || len((v.OlcmInfoTable).Values) > 7 {
			if constraintErr := ber.CheckEncodedLength(opts, "olcmInfoTable", "SIZE (1..7)", len((v.OlcmInfoTable).Values)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_olcminfotable, err := MarshalBEROlcmInfoTable(v.OlcmInfoTable, ber.ChildEncodeOptions(opts, "olcmInfoTable")...)
		if err != nil {
			return nil, fmt.Errorf("encoding olcmInfoTable: %w", err)
		}
		if v.OlcmInfoTableIndef_ {
			// Strip the outer SEQUENCE tag from marshalBER output to get raw children.
			_, _, seqContent_, tlvErr_ := ber.DecodeEncodedTLV(enc_olcminfotable)
			if tlvErr_ != nil {
				return nil, tlvErr_
			}
			{
				var encodeErr error
				enc_olcminfotable, encodeErr = ber.EncodeConstructedIndefinite(tag.Tag{Class: tag.ClassContextSpecific, Number: 0}, seqContent_)
				if encodeErr != nil {
					return nil, fmt.Errorf("encoding olcmInfoTable: %w", encodeErr)
				}
			}
		} else {
			retagged_enc_olcminfotable, tagErr_enc_olcminfotable := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_olcminfotable)
			if tagErr_enc_olcminfotable != nil {
				return nil, fmt.Errorf("encoding olcmInfoTable: %w", tagErr_enc_olcminfotable)
			}
			enc_olcminfotable = retagged_enc_olcminfotable
		}
		children = append(children, enc_olcminfotable...)
	}
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
		retagged_enc_imsi, tagErr_enc_imsi := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_imsi)
		if tagErr_enc_imsi != nil {
			return nil, fmt.Errorf("encoding imsi: %w", tagErr_enc_imsi)
		}
		enc_imsi = retagged_enc_imsi
		children = append(children, enc_imsi...)
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
	return ber.EncodeConstructed(tag.Tag{Class: tag.ClassPrivate, Number: 0, Constructed: true}, children)
}

// MarshalDER encodes AbsentSubscriberExt to DER format.
func (v *AbsentSubscriberExt) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: AbsentSubscriberExt receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if v.OlcmInfoTable != nil {
		if len((v.OlcmInfoTable).Values) < 1 || len((v.OlcmInfoTable).Values) > 7 {
			if constraintErr := ber.CheckEncodedLength(nil, "olcmInfoTable", "SIZE (1..7)", len((v.OlcmInfoTable).Values)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_olcminfotable, err := MarshalDEROlcmInfoTable(v.OlcmInfoTable)
		if err != nil {
			return nil, fmt.Errorf("encoding olcmInfoTable: %w", err)
		}
		retagged_enc_olcminfotable, tagErr_enc_olcminfotable := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_olcminfotable)
		if tagErr_enc_olcminfotable != nil {
			return nil, fmt.Errorf("encoding olcmInfoTable: %w", tagErr_enc_olcminfotable)
		}
		enc_olcminfotable = retagged_enc_olcminfotable
		children = append(children, enc_olcminfotable...)
	}
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
		retagged_enc_imsi, tagErr_enc_imsi := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_imsi)
		if tagErr_enc_imsi != nil {
			return nil, fmt.Errorf("encoding imsi: %w", tagErr_enc_imsi)
		}
		enc_imsi = retagged_enc_imsi
		children = append(children, enc_imsi...)
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
	retagged_encoded, tagErr_encoded := ber.EncodeImplicitTagWithClass(tag.ClassPrivate, 0, encoded)
	if tagErr_encoded != nil {
		return nil, fmt.Errorf("encoding AbsentSubscriberExt: %w", tagErr_encoded)
	}
	encoded = retagged_encoded
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding AbsentSubscriberExt as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes AbsentSubscriberExt from BER/DER format.
func (v *AbsentSubscriberExt) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: AbsentSubscriberExt destination is nil", ber.ErrInvalidValue)
	}
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = AbsentSubscriberExt{}
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
	decodedTag, content, total, err := ber.DecodeConstructedContent(data, opts...)
	if err != nil {
		return fmt.Errorf("decoding AbsentSubscriberExt: %w", err)
	}
	if decodedTag.Class != tag.ClassPrivate || decodedTag.Number != 0 || !decodedTag.Constructed {
		return fmt.Errorf("decoding AbsentSubscriberExt: %w: expected tag [PRIVATE 0], got %s", ber.ErrInvalidTag, decodedTag)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "AbsentSubscriberExt", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode olcmInfoTable
	v.OlcmInfoTableIndef_ = false
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
				decodedTag_olcminfotable, n_olcminfotable, rawVal_olcminfotable, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding olcmInfoTable: %w", err)
				}
				if decodedTag_olcminfotable.Class != tag.ClassContextSpecific || decodedTag_olcminfotable.Number != 0 || decodedTag_olcminfotable.Constructed != true {
					return fmt.Errorf("decoding olcmInfoTable: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_olcminfotable)
				}
				reconstructed_olcminfotable, reconstructionErr_olcminfotable := ber.EncodeSequence(rawVal_olcminfotable)
				if reconstructionErr_olcminfotable != nil {
					return fmt.Errorf("decoding olcmInfoTable: %w", reconstructionErr_olcminfotable)
				}
				dec_olcminfotable, unmErr := UnmarshalBEROlcmInfoTable(reconstructed_olcminfotable, ber.ChildDecodeOptions(opts, "olcmInfoTable")...)
				if unmErr != nil {
					return fmt.Errorf("decoding olcmInfoTable: %w", unmErr)
				}
				v.OlcmInfoTable = dec_olcminfotable
				{
					_, tagSz_, _ := ber.DecodeTag(content[offset:])
					if offset < 0 || offset >
						len(content) || tagSz_ < 0 || tagSz_ > len(content[offset:]) {
						return fmt.Errorf("invalid BER content window")
					}

					if offset+tagSz_ < len(content) && content[offset+tagSz_] == 0x80 {
						v.OlcmInfoTableIndef_ = true
					}
				}
				if offset < 0 || offset >
					len(content) || n_olcminfotable < 0 || n_olcminfotable > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_olcminfotable
				if len((v.OlcmInfoTable).Values) < 1 || len((v.OlcmInfoTable).Values) > 7 {
					if constraintErr := ber.CheckDecodedLength(opts, "olcmInfoTable", "SIZE (1..7)", len((v.OlcmInfoTable).Values)); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode imsi
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
				decodedTag_imsi, n_imsi, rawVal_imsi, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding imsi: %w", err)
				}
				if decodedTag_imsi.Class != tag.ClassContextSpecific || decodedTag_imsi.Number != 1 {
					return fmt.Errorf("decoding imsi: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_imsi)
				}
				decVal_imsi, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_imsi.Constructed, rawVal_imsi, opts...)
				if octetErr != nil {
					return fmt.Errorf("decoding imsi: %w", octetErr)
				}
				tmp_imsi := IMSI5(decVal_imsi)
				v.Imsi = &tmp_imsi
				if offset < 0 || offset >
					len(content) || n_imsi < 0 || n_imsi > len(content[offset:]) {
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
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:], opts...)
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "AbsentSubscriberExt", Cause: extErr_}
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

// MarshalBER encodes ErrOlcmInfoTableExt to BER format.
func (v *ErrOlcmInfoTableExt) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: ErrOlcmInfoTableExt receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *ErrOlcmInfoTableExt) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if v.OlcmInfoTable != nil {
		if len((v.OlcmInfoTable).Values) < 1 || len((v.OlcmInfoTable).Values) > 7 {
			if constraintErr := ber.CheckEncodedLength(opts, "olcmInfoTable", "SIZE (1..7)", len((v.OlcmInfoTable).Values)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_olcminfotable, err := MarshalBEROlcmInfoTable(v.OlcmInfoTable, ber.ChildEncodeOptions(opts, "olcmInfoTable")...)
		if err != nil {
			return nil, fmt.Errorf("encoding olcmInfoTable: %w", err)
		}
		if v.OlcmInfoTableIndef_ {
			// Strip the outer SEQUENCE tag from marshalBER output to get raw children.
			_, _, seqContent_, tlvErr_ := ber.DecodeEncodedTLV(enc_olcminfotable)
			if tlvErr_ != nil {
				return nil, tlvErr_
			}
			{
				var encodeErr error
				enc_olcminfotable, encodeErr = ber.EncodeConstructedIndefinite(tag.Tag{Class: tag.ClassContextSpecific, Number: 0}, seqContent_)
				if encodeErr != nil {
					return nil, fmt.Errorf("encoding olcmInfoTable: %w", encodeErr)
				}
			}
		} else {
			retagged_enc_olcminfotable, tagErr_enc_olcminfotable := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_olcminfotable)
			if tagErr_enc_olcminfotable != nil {
				return nil, fmt.Errorf("encoding olcmInfoTable: %w", tagErr_enc_olcminfotable)
			}
			enc_olcminfotable = retagged_enc_olcminfotable
		}
		children = append(children, enc_olcminfotable...)
	}
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
		retagged_enc_imsi, tagErr_enc_imsi := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_imsi)
		if tagErr_enc_imsi != nil {
			return nil, fmt.Errorf("encoding imsi: %w", tagErr_enc_imsi)
		}
		enc_imsi = retagged_enc_imsi
		children = append(children, enc_imsi...)
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
	return ber.EncodeConstructed(tag.Tag{Class: tag.ClassPrivate, Number: 0, Constructed: true}, children)
}

// MarshalDER encodes ErrOlcmInfoTableExt to DER format.
func (v *ErrOlcmInfoTableExt) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: ErrOlcmInfoTableExt receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if v.OlcmInfoTable != nil {
		if len((v.OlcmInfoTable).Values) < 1 || len((v.OlcmInfoTable).Values) > 7 {
			if constraintErr := ber.CheckEncodedLength(nil, "olcmInfoTable", "SIZE (1..7)", len((v.OlcmInfoTable).Values)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_olcminfotable, err := MarshalDEROlcmInfoTable(v.OlcmInfoTable)
		if err != nil {
			return nil, fmt.Errorf("encoding olcmInfoTable: %w", err)
		}
		retagged_enc_olcminfotable, tagErr_enc_olcminfotable := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_olcminfotable)
		if tagErr_enc_olcminfotable != nil {
			return nil, fmt.Errorf("encoding olcmInfoTable: %w", tagErr_enc_olcminfotable)
		}
		enc_olcminfotable = retagged_enc_olcminfotable
		children = append(children, enc_olcminfotable...)
	}
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
		retagged_enc_imsi, tagErr_enc_imsi := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_imsi)
		if tagErr_enc_imsi != nil {
			return nil, fmt.Errorf("encoding imsi: %w", tagErr_enc_imsi)
		}
		enc_imsi = retagged_enc_imsi
		children = append(children, enc_imsi...)
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
	retagged_encoded, tagErr_encoded := ber.EncodeImplicitTagWithClass(tag.ClassPrivate, 0, encoded)
	if tagErr_encoded != nil {
		return nil, fmt.Errorf("encoding ErrOlcmInfoTableExt: %w", tagErr_encoded)
	}
	encoded = retagged_encoded
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding ErrOlcmInfoTableExt as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes ErrOlcmInfoTableExt from BER/DER format.
func (v *ErrOlcmInfoTableExt) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: ErrOlcmInfoTableExt destination is nil", ber.ErrInvalidValue)
	}
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = ErrOlcmInfoTableExt{}
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
	decodedTag, content, total, err := ber.DecodeConstructedContent(data, opts...)
	if err != nil {
		return fmt.Errorf("decoding ErrOlcmInfoTableExt: %w", err)
	}
	if decodedTag.Class != tag.ClassPrivate || decodedTag.Number != 0 || !decodedTag.Constructed {
		return fmt.Errorf("decoding ErrOlcmInfoTableExt: %w: expected tag [PRIVATE 0], got %s", ber.ErrInvalidTag, decodedTag)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "ErrOlcmInfoTableExt", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode olcmInfoTable
	v.OlcmInfoTableIndef_ = false
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
				decodedTag_olcminfotable, n_olcminfotable, rawVal_olcminfotable, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding olcmInfoTable: %w", err)
				}
				if decodedTag_olcminfotable.Class != tag.ClassContextSpecific || decodedTag_olcminfotable.Number != 0 || decodedTag_olcminfotable.Constructed != true {
					return fmt.Errorf("decoding olcmInfoTable: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_olcminfotable)
				}
				reconstructed_olcminfotable, reconstructionErr_olcminfotable := ber.EncodeSequence(rawVal_olcminfotable)
				if reconstructionErr_olcminfotable != nil {
					return fmt.Errorf("decoding olcmInfoTable: %w", reconstructionErr_olcminfotable)
				}
				dec_olcminfotable, unmErr := UnmarshalBEROlcmInfoTable(reconstructed_olcminfotable, ber.ChildDecodeOptions(opts, "olcmInfoTable")...)
				if unmErr != nil {
					return fmt.Errorf("decoding olcmInfoTable: %w", unmErr)
				}
				v.OlcmInfoTable = dec_olcminfotable
				{
					_, tagSz_, _ := ber.DecodeTag(content[offset:])
					if offset < 0 || offset >
						len(content) || tagSz_ < 0 || tagSz_ > len(content[offset:]) {
						return fmt.Errorf("invalid BER content window")
					}

					if offset+tagSz_ < len(content) && content[offset+tagSz_] == 0x80 {
						v.OlcmInfoTableIndef_ = true
					}
				}
				if offset < 0 || offset >
					len(content) || n_olcminfotable < 0 || n_olcminfotable > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_olcminfotable
				if len((v.OlcmInfoTable).Values) < 1 || len((v.OlcmInfoTable).Values) > 7 {
					if constraintErr := ber.CheckDecodedLength(opts, "olcmInfoTable", "SIZE (1..7)", len((v.OlcmInfoTable).Values)); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode imsi
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
				decodedTag_imsi, n_imsi, rawVal_imsi, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding imsi: %w", err)
				}
				if decodedTag_imsi.Class != tag.ClassContextSpecific || decodedTag_imsi.Number != 1 {
					return fmt.Errorf("decoding imsi: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_imsi)
				}
				decVal_imsi, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_imsi.Constructed, rawVal_imsi, opts...)
				if octetErr != nil {
					return fmt.Errorf("decoding imsi: %w", octetErr)
				}
				tmp_imsi := IMSI5(decVal_imsi)
				v.Imsi = &tmp_imsi
				if offset < 0 || offset >
					len(content) || n_imsi < 0 || n_imsi > len(content[offset:]) {
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
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:], opts...)
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "ErrOlcmInfoTableExt", Cause: extErr_}
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

// MarshalBER encodes RoutingCategoryExt to BER format.
func (v *RoutingCategoryExt) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: RoutingCategoryExt receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *RoutingCategoryExt) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if v.RoutingCategory != nil {
		if len(*v.RoutingCategory) < 1 || len(*v.RoutingCategory) > 1 {
			if constraintErr := ber.CheckEncodedLength(opts, "routingCategory", "SIZE (1)", len(*v.RoutingCategory)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_routingcategory, encodeErr_enc_routingcategory := ber.EncodeOctetString([]byte(*v.RoutingCategory))
		if encodeErr_enc_routingcategory != nil {
			return nil, fmt.Errorf("encoding routingCategory: %w", encodeErr_enc_routingcategory)
		}
		retagged_enc_routingcategory, tagErr_enc_routingcategory := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_routingcategory)
		if tagErr_enc_routingcategory != nil {
			return nil, fmt.Errorf("encoding routingCategory: %w", tagErr_enc_routingcategory)
		}
		enc_routingcategory = retagged_enc_routingcategory
		children = append(children, enc_routingcategory...)
	}
	if v.ExtRoutingCategory != nil {
		if !(int64(*v.ExtRoutingCategory) >= 0 && int64(*v.ExtRoutingCategory) <= 2147483647) {
			if constraintErr := ber.CheckEncodedValue(opts, "extRoutingCategory", "(0..2147483647)", fmt.Sprint(int64(*v.ExtRoutingCategory))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_extroutingcategory := ber.EncodeInteger(int64(*v.ExtRoutingCategory))
		retagged_enc_extroutingcategory, tagErr_enc_extroutingcategory := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_extroutingcategory)
		if tagErr_enc_extroutingcategory != nil {
			return nil, fmt.Errorf("encoding extRoutingCategory: %w", tagErr_enc_extroutingcategory)
		}
		enc_extroutingcategory = retagged_enc_extroutingcategory
		children = append(children, enc_extroutingcategory...)
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
	return ber.EncodeConstructed(tag.Tag{Class: tag.ClassPrivate, Number: 0, Constructed: true}, children)
}

// MarshalDER encodes RoutingCategoryExt to DER format.
func (v *RoutingCategoryExt) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: RoutingCategoryExt receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if v.RoutingCategory != nil {
		if len(*v.RoutingCategory) < 1 || len(*v.RoutingCategory) > 1 {
			if constraintErr := ber.CheckEncodedLength(nil, "routingCategory", "SIZE (1)", len(*v.RoutingCategory)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_routingcategory, encodeErr_enc_routingcategory := ber.EncodeOctetString([]byte(*v.RoutingCategory))
		if encodeErr_enc_routingcategory != nil {
			return nil, fmt.Errorf("encoding routingCategory: %w", encodeErr_enc_routingcategory)
		}
		retagged_enc_routingcategory, tagErr_enc_routingcategory := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_routingcategory)
		if tagErr_enc_routingcategory != nil {
			return nil, fmt.Errorf("encoding routingCategory: %w", tagErr_enc_routingcategory)
		}
		enc_routingcategory = retagged_enc_routingcategory
		children = append(children, enc_routingcategory...)
	}
	if v.ExtRoutingCategory != nil {
		if !(int64(*v.ExtRoutingCategory) >= 0 && int64(*v.ExtRoutingCategory) <= 2147483647) {
			if constraintErr := ber.CheckEncodedValue(nil, "extRoutingCategory", "(0..2147483647)", fmt.Sprint(int64(*v.ExtRoutingCategory))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_extroutingcategory := ber.EncodeInteger(int64(*v.ExtRoutingCategory))
		retagged_enc_extroutingcategory, tagErr_enc_extroutingcategory := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_extroutingcategory)
		if tagErr_enc_extroutingcategory != nil {
			return nil, fmt.Errorf("encoding extRoutingCategory: %w", tagErr_enc_extroutingcategory)
		}
		enc_extroutingcategory = retagged_enc_extroutingcategory
		children = append(children, enc_extroutingcategory...)
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
	retagged_encoded, tagErr_encoded := ber.EncodeImplicitTagWithClass(tag.ClassPrivate, 0, encoded)
	if tagErr_encoded != nil {
		return nil, fmt.Errorf("encoding RoutingCategoryExt: %w", tagErr_encoded)
	}
	encoded = retagged_encoded
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding RoutingCategoryExt as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes RoutingCategoryExt from BER/DER format.
func (v *RoutingCategoryExt) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: RoutingCategoryExt destination is nil", ber.ErrInvalidValue)
	}
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = RoutingCategoryExt{}
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
	decodedTag, content, total, err := ber.DecodeConstructedContent(data, opts...)
	if err != nil {
		return fmt.Errorf("decoding RoutingCategoryExt: %w", err)
	}
	if decodedTag.Class != tag.ClassPrivate || decodedTag.Number != 0 || !decodedTag.Constructed {
		return fmt.Errorf("decoding RoutingCategoryExt: %w: expected tag [PRIVATE 0], got %s", ber.ErrInvalidTag, decodedTag)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "RoutingCategoryExt", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode routingCategory
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
				decodedTag_routingcategory, n_routingcategory, rawVal_routingcategory, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding routingCategory: %w", err)
				}
				if decodedTag_routingcategory.Class != tag.ClassContextSpecific || decodedTag_routingcategory.Number != 0 {
					return fmt.Errorf("decoding routingCategory: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_routingcategory)
				}
				decVal_routingcategory, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_routingcategory.Constructed, rawVal_routingcategory, opts...)
				if octetErr != nil {
					return fmt.Errorf("decoding routingCategory: %w", octetErr)
				}
				tmp_routingcategory := RoutingCategory(decVal_routingcategory)
				v.RoutingCategory = &tmp_routingcategory
				if offset < 0 || offset >
					len(content) || n_routingcategory < 0 || n_routingcategory >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_routingcategory
				if len(*v.RoutingCategory) < 1 || len(*v.RoutingCategory) > 1 {
					if constraintErr := ber.CheckDecodedLength(opts, "routingCategory", "SIZE (1)", len(*v.RoutingCategory)); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode extRoutingCategory
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
				decodedTag_extroutingcategory, n_extroutingcategory, rawVal_extroutingcategory, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding extRoutingCategory: %w", err)
				}
				if decodedTag_extroutingcategory.Class != tag.ClassContextSpecific || decodedTag_extroutingcategory.Number != 1 || decodedTag_extroutingcategory.Constructed != false {
					return fmt.Errorf("decoding extRoutingCategory: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_extroutingcategory)
				}
				decVal_extroutingcategory, intErr := ber.DecodeIntegerValue(rawVal_extroutingcategory)
				if intErr != nil {
					return fmt.Errorf("decoding extRoutingCategory: %w", intErr)
				}
				tmp_extroutingcategory := ExtRoutingCategory(decVal_extroutingcategory)
				v.ExtRoutingCategory = &tmp_extroutingcategory
				if offset < 0 || offset >
					len(content) || n_extroutingcategory < 0 || n_extroutingcategory >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_extroutingcategory
				if !(int64(*v.ExtRoutingCategory) >= 0 && int64(*v.ExtRoutingCategory) <= 2147483647) {
					if constraintErr := ber.CheckDecodedValue(opts, "extRoutingCategory", "(0..2147483647)", fmt.Sprint(int64(*v.ExtRoutingCategory))); constraintErr != nil {
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
			return &ber.DecodeError{Offset: offset, TypeName: "RoutingCategoryExt", Cause: extErr_}
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

// MarshalBER encodes SriForSMArgExt to BER format.
func (v *SriForSMArgExt) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: SriForSMArgExt receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *SriForSMArgExt) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if v.CfuSMSCounter != nil {
		if len(*v.CfuSMSCounter) < 1 || len(*v.CfuSMSCounter) > 1 {
			if constraintErr := ber.CheckEncodedLength(opts, "cfuSMSCounter", "SIZE (1)", len(*v.CfuSMSCounter)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_cfusmscounter, encodeErr_enc_cfusmscounter := ber.EncodeOctetString([]byte(*v.CfuSMSCounter))
		if encodeErr_enc_cfusmscounter != nil {
			return nil, fmt.Errorf("encoding cfuSMSCounter: %w", encodeErr_enc_cfusmscounter)
		}
		retagged_enc_cfusmscounter, tagErr_enc_cfusmscounter := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_cfusmscounter)
		if tagErr_enc_cfusmscounter != nil {
			return nil, fmt.Errorf("encoding cfuSMSCounter: %w", tagErr_enc_cfusmscounter)
		}
		enc_cfusmscounter = retagged_enc_cfusmscounter
		children = append(children, enc_cfusmscounter...)
	}
	if v.Cfusmcfo != nil {
		enc_cfusmcfo := ber.EncodeNull()
		retagged_enc_cfusmcfo, tagErr_enc_cfusmcfo := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_cfusmcfo)
		if tagErr_enc_cfusmcfo != nil {
			return nil, fmt.Errorf("encoding cfusmcfo: %w", tagErr_enc_cfusmcfo)
		}
		enc_cfusmcfo = retagged_enc_cfusmcfo
		children = append(children, enc_cfusmcfo...)
	}
	if v.MemberInterrogate != nil {
		enc_memberinterrogate := ber.EncodeNull()
		retagged_enc_memberinterrogate, tagErr_enc_memberinterrogate := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, enc_memberinterrogate)
		if tagErr_enc_memberinterrogate != nil {
			return nil, fmt.Errorf("encoding memberInterrogate: %w", tagErr_enc_memberinterrogate)
		}
		enc_memberinterrogate = retagged_enc_memberinterrogate
		children = append(children, enc_memberinterrogate...)
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
	return ber.EncodeConstructed(tag.Tag{Class: tag.ClassPrivate, Number: 0, Constructed: true}, children)
}

// MarshalDER encodes SriForSMArgExt to DER format.
func (v *SriForSMArgExt) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: SriForSMArgExt receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if v.CfuSMSCounter != nil {
		if len(*v.CfuSMSCounter) < 1 || len(*v.CfuSMSCounter) > 1 {
			if constraintErr := ber.CheckEncodedLength(nil, "cfuSMSCounter", "SIZE (1)", len(*v.CfuSMSCounter)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_cfusmscounter, encodeErr_enc_cfusmscounter := ber.EncodeOctetString([]byte(*v.CfuSMSCounter))
		if encodeErr_enc_cfusmscounter != nil {
			return nil, fmt.Errorf("encoding cfuSMSCounter: %w", encodeErr_enc_cfusmscounter)
		}
		retagged_enc_cfusmscounter, tagErr_enc_cfusmscounter := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_cfusmscounter)
		if tagErr_enc_cfusmscounter != nil {
			return nil, fmt.Errorf("encoding cfuSMSCounter: %w", tagErr_enc_cfusmscounter)
		}
		enc_cfusmscounter = retagged_enc_cfusmscounter
		children = append(children, enc_cfusmscounter...)
	}
	if v.Cfusmcfo != nil {
		enc_cfusmcfo := ber.EncodeNull()
		retagged_enc_cfusmcfo, tagErr_enc_cfusmcfo := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_cfusmcfo)
		if tagErr_enc_cfusmcfo != nil {
			return nil, fmt.Errorf("encoding cfusmcfo: %w", tagErr_enc_cfusmcfo)
		}
		enc_cfusmcfo = retagged_enc_cfusmcfo
		children = append(children, enc_cfusmcfo...)
	}
	if v.MemberInterrogate != nil {
		enc_memberinterrogate := ber.EncodeNull()
		retagged_enc_memberinterrogate, tagErr_enc_memberinterrogate := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, enc_memberinterrogate)
		if tagErr_enc_memberinterrogate != nil {
			return nil, fmt.Errorf("encoding memberInterrogate: %w", tagErr_enc_memberinterrogate)
		}
		enc_memberinterrogate = retagged_enc_memberinterrogate
		children = append(children, enc_memberinterrogate...)
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
	retagged_encoded, tagErr_encoded := ber.EncodeImplicitTagWithClass(tag.ClassPrivate, 0, encoded)
	if tagErr_encoded != nil {
		return nil, fmt.Errorf("encoding SriForSMArgExt: %w", tagErr_encoded)
	}
	encoded = retagged_encoded
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding SriForSMArgExt as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes SriForSMArgExt from BER/DER format.
func (v *SriForSMArgExt) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: SriForSMArgExt destination is nil", ber.ErrInvalidValue)
	}
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = SriForSMArgExt{}
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
	decodedTag, content, total, err := ber.DecodeConstructedContent(data, opts...)
	if err != nil {
		return fmt.Errorf("decoding SriForSMArgExt: %w", err)
	}
	if decodedTag.Class != tag.ClassPrivate || decodedTag.Number != 0 || !decodedTag.Constructed {
		return fmt.Errorf("decoding SriForSMArgExt: %w: expected tag [PRIVATE 0], got %s", ber.ErrInvalidTag, decodedTag)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "SriForSMArgExt", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode cfuSMSCounter
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
				decodedTag_cfusmscounter, n_cfusmscounter, rawVal_cfusmscounter, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding cfuSMSCounter: %w", err)
				}
				if decodedTag_cfusmscounter.Class != tag.ClassContextSpecific || decodedTag_cfusmscounter.Number != 0 {
					return fmt.Errorf("decoding cfuSMSCounter: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_cfusmscounter)
				}
				decVal_cfusmscounter, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_cfusmscounter.Constructed, rawVal_cfusmscounter, opts...)
				if octetErr != nil {
					return fmt.Errorf("decoding cfuSMSCounter: %w", octetErr)
				}
				tmp_cfusmscounter := CfuSMSCounter(decVal_cfusmscounter)
				v.CfuSMSCounter = &tmp_cfusmscounter
				if offset < 0 || offset >
					len(content) || n_cfusmscounter < 0 || n_cfusmscounter >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_cfusmscounter
				if len(*v.CfuSMSCounter) < 1 || len(*v.CfuSMSCounter) > 1 {
					if constraintErr := ber.CheckDecodedLength(opts, "cfuSMSCounter", "SIZE (1)", len(*v.CfuSMSCounter)); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode cfusmcfo
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2 {
				decodedTag_cfusmcfo, n_cfusmcfo, rawVal_cfusmcfo, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding cfusmcfo: %w", err)
				}
				if decodedTag_cfusmcfo.Class != tag.ClassContextSpecific || decodedTag_cfusmcfo.Number != 2 || decodedTag_cfusmcfo.Constructed != false {
					return fmt.Errorf("decoding cfusmcfo: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_cfusmcfo)
				}
				if len(rawVal_cfusmcfo) != 0 {
					return fmt.Errorf("decoding cfusmcfo: %w: NULL content length %d", ber.ErrInvalidValue, len(rawVal_cfusmcfo))
				}
				v.Cfusmcfo = &struct{}{}
				if offset < 0 || offset >
					len(content) || n_cfusmcfo < 0 || n_cfusmcfo > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_cfusmcfo
			}
		}
	}
	// Decode memberInterrogate
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3 {
				decodedTag_memberinterrogate, n_memberinterrogate, rawVal_memberinterrogate, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding memberInterrogate: %w", err)
				}
				if decodedTag_memberinterrogate.Class != tag.ClassContextSpecific || decodedTag_memberinterrogate.Number != 3 || decodedTag_memberinterrogate.Constructed != false {
					return fmt.Errorf("decoding memberInterrogate: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_memberinterrogate)
				}
				if len(rawVal_memberinterrogate) != 0 {
					return fmt.Errorf("decoding memberInterrogate: %w: NULL content length %d", ber.ErrInvalidValue, len(rawVal_memberinterrogate))
				}
				v.MemberInterrogate = &struct{}{}
				if offset < 0 || offset >
					len(content) || n_memberinterrogate < 0 || n_memberinterrogate >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_memberinterrogate
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:], opts...)
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "SriForSMArgExt", Cause: extErr_}
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

// MarshalBER encodes ReportSMDelStatArgExt to BER format.
func (v *ReportSMDelStatArgExt) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: ReportSMDelStatArgExt receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *ReportSMDelStatArgExt) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if v.CfuSMSCounter != nil {
		if len(*v.CfuSMSCounter) < 1 || len(*v.CfuSMSCounter) > 1 {
			if constraintErr := ber.CheckEncodedLength(opts, "cfuSMSCounter", "SIZE (1)", len(*v.CfuSMSCounter)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_cfusmscounter, encodeErr_enc_cfusmscounter := ber.EncodeOctetString([]byte(*v.CfuSMSCounter))
		if encodeErr_enc_cfusmscounter != nil {
			return nil, fmt.Errorf("encoding cfuSMSCounter: %w", encodeErr_enc_cfusmscounter)
		}
		retagged_enc_cfusmscounter, tagErr_enc_cfusmscounter := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_cfusmscounter)
		if tagErr_enc_cfusmscounter != nil {
			return nil, fmt.Errorf("encoding cfuSMSCounter: %w", tagErr_enc_cfusmscounter)
		}
		enc_cfusmscounter = retagged_enc_cfusmscounter
		children = append(children, enc_cfusmscounter...)
	}
	if v.Cfusmcfo != nil {
		enc_cfusmcfo := ber.EncodeNull()
		retagged_enc_cfusmcfo, tagErr_enc_cfusmcfo := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_cfusmcfo)
		if tagErr_enc_cfusmcfo != nil {
			return nil, fmt.Errorf("encoding cfusmcfo: %w", tagErr_enc_cfusmcfo)
		}
		enc_cfusmcfo = retagged_enc_cfusmcfo
		children = append(children, enc_cfusmcfo...)
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
	return ber.EncodeConstructed(tag.Tag{Class: tag.ClassPrivate, Number: 0, Constructed: true}, children)
}

// MarshalDER encodes ReportSMDelStatArgExt to DER format.
func (v *ReportSMDelStatArgExt) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: ReportSMDelStatArgExt receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if v.CfuSMSCounter != nil {
		if len(*v.CfuSMSCounter) < 1 || len(*v.CfuSMSCounter) > 1 {
			if constraintErr := ber.CheckEncodedLength(nil, "cfuSMSCounter", "SIZE (1)", len(*v.CfuSMSCounter)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_cfusmscounter, encodeErr_enc_cfusmscounter := ber.EncodeOctetString([]byte(*v.CfuSMSCounter))
		if encodeErr_enc_cfusmscounter != nil {
			return nil, fmt.Errorf("encoding cfuSMSCounter: %w", encodeErr_enc_cfusmscounter)
		}
		retagged_enc_cfusmscounter, tagErr_enc_cfusmscounter := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_cfusmscounter)
		if tagErr_enc_cfusmscounter != nil {
			return nil, fmt.Errorf("encoding cfuSMSCounter: %w", tagErr_enc_cfusmscounter)
		}
		enc_cfusmscounter = retagged_enc_cfusmscounter
		children = append(children, enc_cfusmscounter...)
	}
	if v.Cfusmcfo != nil {
		enc_cfusmcfo := ber.EncodeNull()
		retagged_enc_cfusmcfo, tagErr_enc_cfusmcfo := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_cfusmcfo)
		if tagErr_enc_cfusmcfo != nil {
			return nil, fmt.Errorf("encoding cfusmcfo: %w", tagErr_enc_cfusmcfo)
		}
		enc_cfusmcfo = retagged_enc_cfusmcfo
		children = append(children, enc_cfusmcfo...)
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
	retagged_encoded, tagErr_encoded := ber.EncodeImplicitTagWithClass(tag.ClassPrivate, 0, encoded)
	if tagErr_encoded != nil {
		return nil, fmt.Errorf("encoding ReportSMDelStatArgExt: %w", tagErr_encoded)
	}
	encoded = retagged_encoded
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding ReportSMDelStatArgExt as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes ReportSMDelStatArgExt from BER/DER format.
func (v *ReportSMDelStatArgExt) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: ReportSMDelStatArgExt destination is nil", ber.ErrInvalidValue)
	}
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = ReportSMDelStatArgExt{}
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
	decodedTag, content, total, err := ber.DecodeConstructedContent(data, opts...)
	if err != nil {
		return fmt.Errorf("decoding ReportSMDelStatArgExt: %w", err)
	}
	if decodedTag.Class != tag.ClassPrivate || decodedTag.Number != 0 || !decodedTag.Constructed {
		return fmt.Errorf("decoding ReportSMDelStatArgExt: %w: expected tag [PRIVATE 0], got %s", ber.ErrInvalidTag, decodedTag)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "ReportSMDelStatArgExt", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode cfuSMSCounter
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
				decodedTag_cfusmscounter, n_cfusmscounter, rawVal_cfusmscounter, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding cfuSMSCounter: %w", err)
				}
				if decodedTag_cfusmscounter.Class != tag.ClassContextSpecific || decodedTag_cfusmscounter.Number != 0 {
					return fmt.Errorf("decoding cfuSMSCounter: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_cfusmscounter)
				}
				decVal_cfusmscounter, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_cfusmscounter.Constructed, rawVal_cfusmscounter, opts...)
				if octetErr != nil {
					return fmt.Errorf("decoding cfuSMSCounter: %w", octetErr)
				}
				tmp_cfusmscounter := CfuSMSCounter(decVal_cfusmscounter)
				v.CfuSMSCounter = &tmp_cfusmscounter
				if offset < 0 || offset >
					len(content) || n_cfusmscounter < 0 || n_cfusmscounter > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_cfusmscounter
				if len(*v.CfuSMSCounter) < 1 || len(*v.CfuSMSCounter) > 1 {
					if constraintErr := ber.CheckDecodedLength(opts, "cfuSMSCounter", "SIZE (1)", len(*v.CfuSMSCounter)); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode cfusmcfo
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2 {
				decodedTag_cfusmcfo, n_cfusmcfo, rawVal_cfusmcfo, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding cfusmcfo: %w", err)
				}
				if decodedTag_cfusmcfo.Class != tag.ClassContextSpecific || decodedTag_cfusmcfo.Number != 2 || decodedTag_cfusmcfo.Constructed != false {
					return fmt.Errorf("decoding cfusmcfo: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_cfusmcfo)
				}
				if len(rawVal_cfusmcfo) != 0 {
					return fmt.Errorf("decoding cfusmcfo: %w: NULL content length %d", ber.ErrInvalidValue, len(rawVal_cfusmcfo))
				}
				v.Cfusmcfo = &struct{}{}
				if offset < 0 || offset >
					len(content) || n_cfusmcfo < 0 || n_cfusmcfo > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_cfusmcfo
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:], opts...)
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "ReportSMDelStatArgExt", Cause: extErr_}
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

// MarshalBER encodes MOForwardSMArgExt to BER format.
func (v *MOForwardSMArgExt) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: MOForwardSMArgExt receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *MOForwardSMArgExt) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if v.LocationAreaCode != nil {
		if len(*v.LocationAreaCode) < 2 || len(*v.LocationAreaCode) > 2 {
			if constraintErr := ber.CheckEncodedLength(opts, "locationAreaCode", "SIZE (2)", len(*v.LocationAreaCode)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_locationareacode, encodeErr_enc_locationareacode := ber.EncodeOctetString([]byte(*v.LocationAreaCode))
		if encodeErr_enc_locationareacode != nil {
			return nil, fmt.Errorf("encoding locationAreaCode: %w", encodeErr_enc_locationareacode)
		}
		retagged_enc_locationareacode, tagErr_enc_locationareacode := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_locationareacode)
		if tagErr_enc_locationareacode != nil {
			return nil, fmt.Errorf("encoding locationAreaCode: %w", tagErr_enc_locationareacode)
		}
		enc_locationareacode = retagged_enc_locationareacode
		children = append(children, enc_locationareacode...)
	}
	if v.CellId != nil {
		if len(*v.CellId) < 7 || len(*v.CellId) > 7 {
			if constraintErr := ber.CheckEncodedLength(opts, "cellId", "SIZE (7)", len(*v.CellId)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_cellid, encodeErr_enc_cellid := ber.EncodeOctetString([]byte(*v.CellId))
		if encodeErr_enc_cellid != nil {
			return nil, fmt.Errorf("encoding cellId: %w", encodeErr_enc_cellid)
		}
		retagged_enc_cellid, tagErr_enc_cellid := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_cellid)
		if tagErr_enc_cellid != nil {
			return nil, fmt.Errorf("encoding cellId: %w", tagErr_enc_cellid)
		}
		enc_cellid = retagged_enc_cellid
		children = append(children, enc_cellid...)
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
	return ber.EncodeConstructed(tag.Tag{Class: tag.ClassPrivate, Number: 0, Constructed: true}, children)
}

// MarshalDER encodes MOForwardSMArgExt to DER format.
func (v *MOForwardSMArgExt) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: MOForwardSMArgExt receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if v.LocationAreaCode != nil {
		if len(*v.LocationAreaCode) < 2 || len(*v.LocationAreaCode) > 2 {
			if constraintErr := ber.CheckEncodedLength(nil, "locationAreaCode", "SIZE (2)", len(*v.LocationAreaCode)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_locationareacode, encodeErr_enc_locationareacode := ber.EncodeOctetString([]byte(*v.LocationAreaCode))
		if encodeErr_enc_locationareacode != nil {
			return nil, fmt.Errorf("encoding locationAreaCode: %w", encodeErr_enc_locationareacode)
		}
		retagged_enc_locationareacode, tagErr_enc_locationareacode := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_locationareacode)
		if tagErr_enc_locationareacode != nil {
			return nil, fmt.Errorf("encoding locationAreaCode: %w", tagErr_enc_locationareacode)
		}
		enc_locationareacode = retagged_enc_locationareacode
		children = append(children, enc_locationareacode...)
	}
	if v.CellId != nil {
		if len(*v.CellId) < 7 || len(*v.CellId) > 7 {
			if constraintErr := ber.CheckEncodedLength(nil, "cellId", "SIZE (7)", len(*v.CellId)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_cellid, encodeErr_enc_cellid := ber.EncodeOctetString([]byte(*v.CellId))
		if encodeErr_enc_cellid != nil {
			return nil, fmt.Errorf("encoding cellId: %w", encodeErr_enc_cellid)
		}
		retagged_enc_cellid, tagErr_enc_cellid := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_cellid)
		if tagErr_enc_cellid != nil {
			return nil, fmt.Errorf("encoding cellId: %w", tagErr_enc_cellid)
		}
		enc_cellid = retagged_enc_cellid
		children = append(children, enc_cellid...)
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
	retagged_encoded, tagErr_encoded := ber.EncodeImplicitTagWithClass(tag.ClassPrivate, 0, encoded)
	if tagErr_encoded != nil {
		return nil, fmt.Errorf("encoding MOForwardSMArgExt: %w", tagErr_encoded)
	}
	encoded = retagged_encoded
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding MOForwardSMArgExt as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes MOForwardSMArgExt from BER/DER format.
func (v *MOForwardSMArgExt) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: MOForwardSMArgExt destination is nil", ber.ErrInvalidValue)
	}
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = MOForwardSMArgExt{}
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
	decodedTag, content, total, err := ber.DecodeConstructedContent(data, opts...)
	if err != nil {
		return fmt.Errorf("decoding MOForwardSMArgExt: %w", err)
	}
	if decodedTag.Class != tag.ClassPrivate || decodedTag.Number != 0 || !decodedTag.Constructed {
		return fmt.Errorf("decoding MOForwardSMArgExt: %w: expected tag [PRIVATE 0], got %s", ber.ErrInvalidTag, decodedTag)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "MOForwardSMArgExt", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode locationAreaCode
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
				decodedTag_locationareacode, n_locationareacode, rawVal_locationareacode, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding locationAreaCode: %w", err)
				}
				if decodedTag_locationareacode.Class != tag.ClassContextSpecific || decodedTag_locationareacode.Number != 0 {
					return fmt.Errorf("decoding locationAreaCode: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_locationareacode)
				}
				decVal_locationareacode, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_locationareacode.Constructed, rawVal_locationareacode, opts...)
				if octetErr != nil {
					return fmt.Errorf("decoding locationAreaCode: %w", octetErr)
				}
				tmp_locationareacode := LocationAreaCode(decVal_locationareacode)
				v.LocationAreaCode = &tmp_locationareacode
				if offset < 0 || offset >
					len(content) || n_locationareacode < 0 || n_locationareacode >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_locationareacode
				if len(*v.LocationAreaCode) < 2 || len(*v.LocationAreaCode) > 2 {
					if constraintErr := ber.CheckDecodedLength(opts, "locationAreaCode", "SIZE (2)", len(*v.LocationAreaCode)); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode cellId
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
				decodedTag_cellid, n_cellid, rawVal_cellid, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding cellId: %w", err)
				}
				if decodedTag_cellid.Class != tag.ClassContextSpecific || decodedTag_cellid.Number != 1 {
					return fmt.Errorf("decoding cellId: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_cellid)
				}
				decVal_cellid, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_cellid.Constructed, rawVal_cellid, opts...)
				if octetErr != nil {
					return fmt.Errorf("decoding cellId: %w", octetErr)
				}
				tmp_cellid := CellGlobalIdOrServiceAreaIdFixedLength5(decVal_cellid)
				v.CellId = &tmp_cellid
				if offset < 0 || offset >
					len(content) || n_cellid < 0 || n_cellid > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_cellid
				if len(*v.CellId) < 7 || len(*v.CellId) > 7 {
					if constraintErr := ber.CheckDecodedLength(opts, "cellId", "SIZE (7)", len(*v.CellId)); constraintErr != nil {
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
			return &ber.DecodeError{Offset: offset, TypeName: "MOForwardSMArgExt", Cause: extErr_}
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

// MarshalBER encodes UdlArgExt to BER format.
func (v *UdlArgExt) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: UdlArgExt receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *UdlArgExt) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if v.Lai != nil {
		if len(*v.Lai) < 5 || len(*v.Lai) > 5 {
			if constraintErr := ber.CheckEncodedLength(opts, "lai", "SIZE (5)", len(*v.Lai)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_lai, encodeErr_enc_lai := ber.EncodeOctetString([]byte(*v.Lai))
		if encodeErr_enc_lai != nil {
			return nil, fmt.Errorf("encoding lai: %w", encodeErr_enc_lai)
		}
		retagged_enc_lai, tagErr_enc_lai := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_lai)
		if tagErr_enc_lai != nil {
			return nil, fmt.Errorf("encoding lai: %w", tagErr_enc_lai)
		}
		enc_lai = retagged_enc_lai
		children = append(children, enc_lai...)
	}
	if v.SendImmResp != nil {
		enc_sendimmresp := ber.EncodeNull()
		retagged_enc_sendimmresp, tagErr_enc_sendimmresp := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_sendimmresp)
		if tagErr_enc_sendimmresp != nil {
			return nil, fmt.Errorf("encoding sendImmResp: %w", tagErr_enc_sendimmresp)
		}
		enc_sendimmresp = retagged_enc_sendimmresp
		children = append(children, enc_sendimmresp...)
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
	return ber.EncodeConstructed(tag.Tag{Class: tag.ClassPrivate, Number: 0, Constructed: true}, children)
}

// MarshalDER encodes UdlArgExt to DER format.
func (v *UdlArgExt) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: UdlArgExt receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if v.Lai != nil {
		if len(*v.Lai) < 5 || len(*v.Lai) > 5 {
			if constraintErr := ber.CheckEncodedLength(nil, "lai", "SIZE (5)", len(*v.Lai)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_lai, encodeErr_enc_lai := ber.EncodeOctetString([]byte(*v.Lai))
		if encodeErr_enc_lai != nil {
			return nil, fmt.Errorf("encoding lai: %w", encodeErr_enc_lai)
		}
		retagged_enc_lai, tagErr_enc_lai := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_lai)
		if tagErr_enc_lai != nil {
			return nil, fmt.Errorf("encoding lai: %w", tagErr_enc_lai)
		}
		enc_lai = retagged_enc_lai
		children = append(children, enc_lai...)
	}
	if v.SendImmResp != nil {
		enc_sendimmresp := ber.EncodeNull()
		retagged_enc_sendimmresp, tagErr_enc_sendimmresp := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_sendimmresp)
		if tagErr_enc_sendimmresp != nil {
			return nil, fmt.Errorf("encoding sendImmResp: %w", tagErr_enc_sendimmresp)
		}
		enc_sendimmresp = retagged_enc_sendimmresp
		children = append(children, enc_sendimmresp...)
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
	retagged_encoded, tagErr_encoded := ber.EncodeImplicitTagWithClass(tag.ClassPrivate, 0, encoded)
	if tagErr_encoded != nil {
		return nil, fmt.Errorf("encoding UdlArgExt: %w", tagErr_encoded)
	}
	encoded = retagged_encoded
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding UdlArgExt as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes UdlArgExt from BER/DER format.
func (v *UdlArgExt) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: UdlArgExt destination is nil", ber.ErrInvalidValue)
	}
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = UdlArgExt{}
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
	decodedTag, content, total, err := ber.DecodeConstructedContent(data, opts...)
	if err != nil {
		return fmt.Errorf("decoding UdlArgExt: %w", err)
	}
	if decodedTag.Class != tag.ClassPrivate || decodedTag.Number != 0 || !decodedTag.Constructed {
		return fmt.Errorf("decoding UdlArgExt: %w: expected tag [PRIVATE 0], got %s", ber.ErrInvalidTag, decodedTag)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "UdlArgExt", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode lai
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
				decodedTag_lai, n_lai, rawVal_lai, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding lai: %w", err)
				}
				if decodedTag_lai.Class != tag.ClassContextSpecific || decodedTag_lai.Number != 0 {
					return fmt.Errorf("decoding lai: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_lai)
				}
				decVal_lai, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_lai.Constructed, rawVal_lai, opts...)
				if octetErr != nil {
					return fmt.Errorf("decoding lai: %w", octetErr)
				}
				tmp_lai := LAIFixedLength5(decVal_lai)
				v.Lai = &tmp_lai
				if offset < 0 || offset >
					len(content) || n_lai < 0 || n_lai > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_lai
				if len(*v.Lai) < 5 || len(*v.Lai) > 5 {
					if constraintErr := ber.CheckDecodedLength(opts, "lai", "SIZE (5)", len(*v.Lai)); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode sendImmResp
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
				decodedTag_sendimmresp, n_sendimmresp, rawVal_sendimmresp, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding sendImmResp: %w", err)
				}
				if decodedTag_sendimmresp.Class != tag.ClassContextSpecific || decodedTag_sendimmresp.Number != 1 || decodedTag_sendimmresp.Constructed != false {
					return fmt.Errorf("decoding sendImmResp: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_sendimmresp)
				}
				if len(rawVal_sendimmresp) != 0 {
					return fmt.Errorf("decoding sendImmResp: %w: NULL content length %d", ber.ErrInvalidValue, len(rawVal_sendimmresp))
				}
				v.SendImmResp = &struct{}{}
				if offset < 0 || offset >
					len(content) || n_sendimmresp < 0 || n_sendimmresp >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_sendimmresp
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:], opts...)
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "UdlArgExt", Cause: extErr_}
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

// MarshalBER encodes RoamNotAllowedExt to BER format.
func (v *RoamNotAllowedExt) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: RoamNotAllowedExt receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *RoamNotAllowedExt) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if v.RejectCause != nil {
		if len(v.RejectCause) < 1 || len(v.RejectCause) > 1 {
			if constraintErr := ber.CheckEncodedLength(opts, "rejectCause", "SIZE (1)", len(v.RejectCause)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_rejectcause, encodeErr_enc_rejectcause := ber.EncodeOctetString(v.RejectCause)
		if encodeErr_enc_rejectcause != nil {
			return nil, fmt.Errorf("encoding rejectCause: %w", encodeErr_enc_rejectcause)
		}
		retagged_enc_rejectcause, tagErr_enc_rejectcause := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_rejectcause)
		if tagErr_enc_rejectcause != nil {
			return nil, fmt.Errorf("encoding rejectCause: %w", tagErr_enc_rejectcause)
		}
		enc_rejectcause = retagged_enc_rejectcause
		children = append(children, enc_rejectcause...)
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
	return ber.EncodeConstructed(tag.Tag{Class: tag.ClassPrivate, Number: 0, Constructed: true}, children)
}

// MarshalDER encodes RoamNotAllowedExt to DER format.
func (v *RoamNotAllowedExt) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: RoamNotAllowedExt receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if v.RejectCause != nil {
		if len(v.RejectCause) < 1 || len(v.RejectCause) > 1 {
			if constraintErr := ber.CheckEncodedLength(nil, "rejectCause", "SIZE (1)", len(v.RejectCause)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_rejectcause, encodeErr_enc_rejectcause := ber.EncodeOctetString(v.RejectCause)
		if encodeErr_enc_rejectcause != nil {
			return nil, fmt.Errorf("encoding rejectCause: %w", encodeErr_enc_rejectcause)
		}
		retagged_enc_rejectcause, tagErr_enc_rejectcause := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_rejectcause)
		if tagErr_enc_rejectcause != nil {
			return nil, fmt.Errorf("encoding rejectCause: %w", tagErr_enc_rejectcause)
		}
		enc_rejectcause = retagged_enc_rejectcause
		children = append(children, enc_rejectcause...)
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
	retagged_encoded, tagErr_encoded := ber.EncodeImplicitTagWithClass(tag.ClassPrivate, 0, encoded)
	if tagErr_encoded != nil {
		return nil, fmt.Errorf("encoding RoamNotAllowedExt: %w", tagErr_encoded)
	}
	encoded = retagged_encoded
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding RoamNotAllowedExt as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes RoamNotAllowedExt from BER/DER format.
func (v *RoamNotAllowedExt) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: RoamNotAllowedExt destination is nil", ber.ErrInvalidValue)
	}
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = RoamNotAllowedExt{}
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
	decodedTag, content, total, err := ber.DecodeConstructedContent(data, opts...)
	if err != nil {
		return fmt.Errorf("decoding RoamNotAllowedExt: %w", err)
	}
	if decodedTag.Class != tag.ClassPrivate || decodedTag.Number != 0 || !decodedTag.Constructed {
		return fmt.Errorf("decoding RoamNotAllowedExt: %w: expected tag [PRIVATE 0], got %s", ber.ErrInvalidTag, decodedTag)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "RoamNotAllowedExt", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode rejectCause
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
				decodedTag_rejectcause, n_rejectcause, rawVal_rejectcause, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding rejectCause: %w", err)
				}
				if decodedTag_rejectcause.Class != tag.ClassContextSpecific || decodedTag_rejectcause.Number != 0 {
					return fmt.Errorf("decoding rejectCause: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_rejectcause)
				}
				decVal_rejectcause, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_rejectcause.Constructed, rawVal_rejectcause, opts...)
				if octetErr != nil {
					return fmt.Errorf("decoding rejectCause: %w", octetErr)
				}
				tmp_rejectcause := decVal_rejectcause
				v.RejectCause = tmp_rejectcause
				if offset < 0 || offset >
					len(content) || n_rejectcause < 0 || n_rejectcause > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_rejectcause
				if len(v.RejectCause) < 1 || len(v.RejectCause) > 1 {
					if constraintErr := ber.CheckDecodedLength(opts, "rejectCause", "SIZE (1)", len(v.RejectCause)); constraintErr != nil {
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
			return &ber.DecodeError{Offset: offset, TypeName: "RoamNotAllowedExt", Cause: extErr_}
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

// MarshalBER encodes AnyTimeModArgExt to BER format.
func (v *AnyTimeModArgExt) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: AnyTimeModArgExt receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *AnyTimeModArgExt) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if v.SenderMSISDN != nil {
		if len(*v.SenderMSISDN) < 1 || len(*v.SenderMSISDN) > 9 {
			if constraintErr := ber.CheckEncodedLength(opts, "senderMSISDN", "SIZE (1..9)", len(*v.SenderMSISDN)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		if len(*v.SenderMSISDN) < 1 || len(*v.SenderMSISDN) > 20 {
			if constraintErr := ber.CheckEncodedLength(opts, "senderMSISDN", "SIZE (1..20)", len(*v.SenderMSISDN)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_sendermsisdn, encodeErr_enc_sendermsisdn := ber.EncodeOctetString([]byte(*v.SenderMSISDN))
		if encodeErr_enc_sendermsisdn != nil {
			return nil, fmt.Errorf("encoding senderMSISDN: %w", encodeErr_enc_sendermsisdn)
		}
		retagged_enc_sendermsisdn, tagErr_enc_sendermsisdn := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_sendermsisdn)
		if tagErr_enc_sendermsisdn != nil {
			return nil, fmt.Errorf("encoding senderMSISDN: %w", tagErr_enc_sendermsisdn)
		}
		enc_sendermsisdn = retagged_enc_sendermsisdn
		children = append(children, enc_sendermsisdn...)
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
	return ber.EncodeConstructed(tag.Tag{Class: tag.ClassPrivate, Number: 0, Constructed: true}, children)
}

// MarshalDER encodes AnyTimeModArgExt to DER format.
func (v *AnyTimeModArgExt) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: AnyTimeModArgExt receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if v.SenderMSISDN != nil {
		if len(*v.SenderMSISDN) < 1 || len(*v.SenderMSISDN) > 9 {
			if constraintErr := ber.CheckEncodedLength(nil, "senderMSISDN", "SIZE (1..9)", len(*v.SenderMSISDN)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		if len(*v.SenderMSISDN) < 1 || len(*v.SenderMSISDN) > 20 {
			if constraintErr := ber.CheckEncodedLength(nil, "senderMSISDN", "SIZE (1..20)", len(*v.SenderMSISDN)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_sendermsisdn, encodeErr_enc_sendermsisdn := ber.EncodeOctetString([]byte(*v.SenderMSISDN))
		if encodeErr_enc_sendermsisdn != nil {
			return nil, fmt.Errorf("encoding senderMSISDN: %w", encodeErr_enc_sendermsisdn)
		}
		retagged_enc_sendermsisdn, tagErr_enc_sendermsisdn := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_sendermsisdn)
		if tagErr_enc_sendermsisdn != nil {
			return nil, fmt.Errorf("encoding senderMSISDN: %w", tagErr_enc_sendermsisdn)
		}
		enc_sendermsisdn = retagged_enc_sendermsisdn
		children = append(children, enc_sendermsisdn...)
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
	retagged_encoded, tagErr_encoded := ber.EncodeImplicitTagWithClass(tag.ClassPrivate, 0, encoded)
	if tagErr_encoded != nil {
		return nil, fmt.Errorf("encoding AnyTimeModArgExt: %w", tagErr_encoded)
	}
	encoded = retagged_encoded
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding AnyTimeModArgExt as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes AnyTimeModArgExt from BER/DER format.
func (v *AnyTimeModArgExt) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: AnyTimeModArgExt destination is nil", ber.ErrInvalidValue)
	}
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = AnyTimeModArgExt{}
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
	decodedTag, content, total, err := ber.DecodeConstructedContent(data, opts...)
	if err != nil {
		return fmt.Errorf("decoding AnyTimeModArgExt: %w", err)
	}
	if decodedTag.Class != tag.ClassPrivate || decodedTag.Number != 0 || !decodedTag.Constructed {
		return fmt.Errorf("decoding AnyTimeModArgExt: %w: expected tag [PRIVATE 0], got %s", ber.ErrInvalidTag, decodedTag)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "AnyTimeModArgExt", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode senderMSISDN
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
				decodedTag_sendermsisdn, n_sendermsisdn, rawVal_sendermsisdn, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding senderMSISDN: %w", err)
				}
				if decodedTag_sendermsisdn.Class != tag.ClassContextSpecific || decodedTag_sendermsisdn.Number != 0 {
					return fmt.Errorf("decoding senderMSISDN: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_sendermsisdn)
				}
				decVal_sendermsisdn, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_sendermsisdn.Constructed, rawVal_sendermsisdn, opts...)
				if octetErr != nil {
					return fmt.Errorf("decoding senderMSISDN: %w", octetErr)
				}
				tmp_sendermsisdn := ISDNAddressString5(decVal_sendermsisdn)
				v.SenderMSISDN = &tmp_sendermsisdn
				if offset < 0 || offset >
					len(content) || n_sendermsisdn < 0 || n_sendermsisdn > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_sendermsisdn
				if len(*v.SenderMSISDN) < 1 || len(*v.SenderMSISDN) > 9 {
					if constraintErr := ber.CheckDecodedLength(opts, "senderMSISDN", "SIZE (1..9)", len(*v.SenderMSISDN)); constraintErr != nil {
						return constraintErr
					}
				}
				if len(*v.SenderMSISDN) < 1 || len(*v.SenderMSISDN) > 20 {
					if constraintErr := ber.CheckDecodedLength(opts, "senderMSISDN", "SIZE (1..20)", len(*v.SenderMSISDN)); constraintErr != nil {
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
			return &ber.DecodeError{Offset: offset, TypeName: "AnyTimeModArgExt", Cause: extErr_}
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

// MarshalBER encodes CosInfo to BER format.
func (v *CosInfo) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: CosInfo receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *CosInfo) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if v.SsCode != nil {
		if len(*v.SsCode) < 1 || len(*v.SsCode) > 1 {
			if constraintErr := ber.CheckEncodedLength(opts, "ss-Code", "SIZE (1)", len(*v.SsCode)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_sscode, encodeErr_enc_sscode := ber.EncodeOctetString([]byte(*v.SsCode))
		if encodeErr_enc_sscode != nil {
			return nil, fmt.Errorf("encoding ss-Code: %w", encodeErr_enc_sscode)
		}
		children = append(children, enc_sscode...)
	}
	if v.CosFeatureList == nil {
		return nil, fmt.Errorf("encoding cos-FeatureList: %w: required collection is nil", ber.ErrInvalidValue)
	}
	if len((v.CosFeatureList).Values) < 1 || len((v.CosFeatureList).Values) > 13 {
		if constraintErr := ber.CheckEncodedLength(opts, "cos-FeatureList", "SIZE (1..13)", len((v.CosFeatureList).Values)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_cosfeaturelist, err := MarshalBERCOSFeatureList(v.CosFeatureList, ber.ChildEncodeOptions(opts, "cos-FeatureList")...)
	if err != nil {
		return nil, fmt.Errorf("encoding cos-FeatureList: %w", err)
	}
	children = append(children, enc_cosfeaturelist...)
	return ber.EncodeSequence(children)
}

// MarshalDER encodes CosInfo to DER format.
func (v *CosInfo) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: CosInfo receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if v.SsCode != nil {
		if len(*v.SsCode) < 1 || len(*v.SsCode) > 1 {
			if constraintErr := ber.CheckEncodedLength(nil, "ss-Code", "SIZE (1)", len(*v.SsCode)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_sscode, encodeErr_enc_sscode := ber.EncodeOctetString([]byte(*v.SsCode))
		if encodeErr_enc_sscode != nil {
			return nil, fmt.Errorf("encoding ss-Code: %w", encodeErr_enc_sscode)
		}
		children = append(children, enc_sscode...)
	}
	if v.CosFeatureList == nil {
		return nil, fmt.Errorf("encoding cos-FeatureList: %w: required collection is nil", ber.ErrInvalidValue)
	}
	if len((v.CosFeatureList).Values) < 1 || len((v.CosFeatureList).Values) > 13 {
		if constraintErr := ber.CheckEncodedLength(nil, "cos-FeatureList", "SIZE (1..13)", len((v.CosFeatureList).Values)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_cosfeaturelist, err := MarshalDERCOSFeatureList(v.CosFeatureList)
	if err != nil {
		return nil, fmt.Errorf("encoding cos-FeatureList: %w", err)
	}
	children = append(children, enc_cosfeaturelist...)
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding CosInfo as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes CosInfo from BER/DER format.
func (v *CosInfo) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: CosInfo destination is nil", ber.ErrInvalidValue)
	}
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = CosInfo{}
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
		return fmt.Errorf("decoding CosInfo SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "CosInfo", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode ss-Code
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassUniversal && peekTag.Number == 4 {
				val_sscode, n, err := ber.DecodeOctetString(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding ss-Code: %w", err)
				}
				tmp_sscode := SSCode6(val_sscode)
				v.SsCode = &tmp_sscode
				if offset < 0 || offset >
					len(content) || n < 0 || n > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n
				if len(*v.SsCode) < 1 || len(*v.SsCode) > 1 {
					if constraintErr := ber.CheckDecodedLength(opts, "ss-Code", "SIZE (1)", len(*v.SsCode)); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode cos-FeatureList
	if offset >= len(content) {
		return fmt.Errorf("missing required field cos-FeatureList")
	}
	v.CosFeatureListIndef_ = false
	// Decode nested SEQUENCE_OF (COSFeatureList)
	_, n_cosfeaturelist, _, tlvErr_cosfeaturelist := ber.DecodeTLV(content[offset:], opts...)
	if tlvErr_cosfeaturelist != nil {
		return fmt.Errorf("decoding cos-FeatureList: %w", tlvErr_cosfeaturelist)
	}
	if offset < 0 || offset >
		len(content) || n_cosfeaturelist < 0 || n_cosfeaturelist >
		len(content[offset:]) {
		return fmt.Errorf("invalid BER content window")
	}

	tlv_cosfeaturelist := content[offset : offset+n_cosfeaturelist]
	{
		_, tagSz_, _ := ber.DecodeTag(tlv_cosfeaturelist)
		if tagSz_ < len(tlv_cosfeaturelist) && tlv_cosfeaturelist[tagSz_] == 0x80 {
			v.CosFeatureListIndef_ = true
		}
	}
	dec_cosfeaturelist, unmErr := UnmarshalBERCOSFeatureList(tlv_cosfeaturelist, ber.ChildDecodeOptions(opts, "cos-FeatureList")...)
	if unmErr != nil {
		return fmt.Errorf("decoding cos-FeatureList: %w", unmErr)
	}
	v.CosFeatureList = dec_cosfeaturelist
	if offset < 0 || offset >
		len(content) || n_cosfeaturelist < 0 || n_cosfeaturelist >
		len(content[offset:]) {
		return fmt.Errorf("invalid BER content window")
	}

	offset += n_cosfeaturelist
	if len((v.CosFeatureList).Values) < 1 || len((v.CosFeatureList).Values) > 13 {
		if constraintErr := ber.CheckDecodedLength(opts, "cos-FeatureList", "SIZE (1..13)", len((v.CosFeatureList).Values)); constraintErr != nil {
			return constraintErr
		}
	}
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "CosInfo", Cause: ber.ErrExtraData}
	}
	return nil
}

// MarshalBERCOSFeatureList encodes a COSFeatureList list to BER.
func MarshalBERCOSFeatureList(collection *COSFeatureList, opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	if collection == nil {
		return nil, fmt.Errorf("%w: required collection is nil", ber.ErrInvalidValue)
	}
	encoded, err := marshalBERCOSFeatureList(collection, opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, collection.berOriginal_, collection.berSnapshot_, opts), nil
}
func marshalBERCOSFeatureList(collection *COSFeatureList, opts ...ber.EncodeOption) ([]byte, error) {
	list := collection.Values
	if len(list) < 1 || len(list) > 13 {
		if constraintErr := ber.CheckEncodedLength(opts, "COSFeatureList", "SIZE (1..13)", len(list)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	var children []byte
	for elemIndex, elem := range list {
		enc, err := elem.MarshalBER(ber.ChildEncodeOptions(opts, fmt.Sprintf("element[%d]", elemIndex))...)
		if err != nil {
			return nil, fmt.Errorf("encoding element: %w", err)
		}
		children = append(children, enc...)
	}
	return ber.EncodeSequence(children)
}

// MarshalDERCOSFeatureList encodes a COSFeatureList list to DER.
func MarshalDERCOSFeatureList(collection *COSFeatureList) ([]byte, error) {
	if collection == nil {
		return nil, fmt.Errorf("%w: required collection is nil", ber.ErrInvalidValue)
	}
	list := collection.Values
	if len(list) < 1 || len(list) > 13 {
		if constraintErr := ber.CheckEncodedLength(nil, "COSFeatureList", "SIZE (1..13)", len(list)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	var children []byte
	for _, elem := range list {
		enc, err := elem.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding element: %w", err)
		}
		children = append(children, enc...)
	}
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding COSFeatureList as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBERCOSFeatureList decodes a COSFeatureList list from BER.
func UnmarshalBERCOSFeatureList(data []byte, opts ...ber.DecodeOption) (returnValue *COSFeatureList, returnErr error) {
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return nil, err
	}
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return nil, fmt.Errorf("decoding COSFeatureList: %w", err)
	}
	if total != len(data) {
		return nil, &ber.DecodeError{Offset: total, TypeName: "COSFeatureList", Cause: ber.ErrExtraData}
	}
	var result []COSFeature
	offset := 0
	for offset < len(content) {
		elementData := content[offset:]
		var elem COSFeature
		_, n, _, tlvErr := ber.DecodeTLV(elementData, opts...)
		if tlvErr != nil {
			return nil, fmt.Errorf("decoding element TLV: %w", tlvErr)
		}
		if unmErr := elem.UnmarshalBER(elementData[:n], ber.ChildDecodeOptions(opts, fmt.Sprintf("element[%d]", len(result)))...); unmErr != nil {
			return nil, fmt.Errorf("decoding element: %w", unmErr)
		}
		result = append(result, elem)
		if offset < 0 || offset >
			len(content) || n < 0 || n > len(content[offset:]) {
			return nil, fmt.Errorf("invalid BER content window")
		}

		offset += n
	}
	if len(result) < 1 || len(result) > 13 {
		if constraintErr := ber.CheckDecodedLength(opts, "COSFeatureList", "SIZE (1..13)", len(result)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	decoded := &COSFeatureList{Values: result}
	if ber.BERNeedsPreservation(opts) {
		var snapshotReports ber.ViolationLog
		snapshot, snapshotErr := MarshalBERCOSFeatureList(decoded, ber.WithConstraintTolerance(&snapshotReports))
		if snapshotErr != nil {
			return nil, snapshotErr
		}
		decoded.berOriginal_ = append([]byte(nil), data...)
		decoded.berSnapshot_ = snapshot
	}
	return decoded, nil
}

// MarshalBER encodes COSFeature to BER format.
func (v *COSFeature) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: COSFeature receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *COSFeature) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if v.BasicServiceCode != nil {
		enc_basicservicecode, err := v.BasicServiceCode.MarshalBER(ber.ChildEncodeOptions(opts, "basicServiceCode")...)
		if err != nil {
			return nil, fmt.Errorf("encoding basicServiceCode: %w", err)
		}
		children = append(children, enc_basicservicecode...)
	}
	if len(v.SsStatus) < 1 || len(v.SsStatus) > 1 {
		if constraintErr := ber.CheckEncodedLength(opts, "ss-Status", "SIZE (1)", len(v.SsStatus)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_ssstatus, encodeErr_enc_ssstatus := ber.EncodeOctetString([]byte(v.SsStatus))
	if encodeErr_enc_ssstatus != nil {
		return nil, fmt.Errorf("encoding ss-Status: %w", encodeErr_enc_ssstatus)
	}
	retagged_enc_ssstatus, tagErr_enc_ssstatus := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, enc_ssstatus)
	if tagErr_enc_ssstatus != nil {
		return nil, fmt.Errorf("encoding ss-Status: %w", tagErr_enc_ssstatus)
	}
	enc_ssstatus = retagged_enc_ssstatus
	children = append(children, enc_ssstatus...)
	if v.CustomerGroupID != nil {
		if (*v.CustomerGroupID).BitLength < 32 || (*v.CustomerGroupID).BitLength > 32 {
			if constraintErr := ber.CheckEncodedLength(opts, "customerGroupID", "SIZE (32)", (*v.CustomerGroupID).BitLength); constraintErr != nil {
				return nil, constraintErr
			}
		}
		if bitStringErr := ber.ValidateBitStringLength(v.CustomerGroupID.Bytes, v.CustomerGroupID.BitLength); bitStringErr != nil {
			return nil, fmt.Errorf("encoding %s: %w", "customerGroupID", bitStringErr)
		}
		// arithmetic pattern BER_BITSTRING_FIELD: 0 <= bit length before modulo and subtraction; gen/codegen.go:526
		if v.CustomerGroupID.BitLength < 0 {
			return nil, fmt.Errorf("negative bit string length")
		}
		enc_customergroupid, encodeErr_enc_customergroupid := ber.EncodeBitString(v.CustomerGroupID.Bytes, (8-(v.CustomerGroupID.BitLength%8))%8)
		if encodeErr_enc_customergroupid != nil {
			return nil, fmt.Errorf("encoding customerGroupID: %w", encodeErr_enc_customergroupid)
		}
		retagged_enc_customergroupid, tagErr_enc_customergroupid := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 5, enc_customergroupid)
		if tagErr_enc_customergroupid != nil {
			return nil, fmt.Errorf("encoding customerGroupID: %w", tagErr_enc_customergroupid)
		}
		enc_customergroupid = retagged_enc_customergroupid
		children = append(children, enc_customergroupid...)
	}
	if v.SubGroupID != nil {
		if (*v.SubGroupID).BitLength < 16 || (*v.SubGroupID).BitLength > 16 {
			if constraintErr := ber.CheckEncodedLength(opts, "subGroupID", "SIZE (16)", (*v.SubGroupID).BitLength); constraintErr != nil {
				return nil, constraintErr
			}
		}
		if bitStringErr := ber.ValidateBitStringLength(v.SubGroupID.Bytes, v.SubGroupID.BitLength); bitStringErr != nil {
			return nil, fmt.Errorf("encoding %s: %w", "subGroupID", bitStringErr)
		}
		// arithmetic pattern BER_BITSTRING_FIELD: 0 <= bit length before modulo and subtraction; gen/codegen.go:526
		if v.SubGroupID.BitLength < 0 {
			return nil, fmt.Errorf("negative bit string length")
		}
		enc_subgroupid, encodeErr_enc_subgroupid := ber.EncodeBitString(v.SubGroupID.Bytes, (8-(v.SubGroupID.BitLength%8))%8)
		if encodeErr_enc_subgroupid != nil {
			return nil, fmt.Errorf("encoding subGroupID: %w", encodeErr_enc_subgroupid)
		}
		retagged_enc_subgroupid, tagErr_enc_subgroupid := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 6, enc_subgroupid)
		if tagErr_enc_subgroupid != nil {
			return nil, fmt.Errorf("encoding subGroupID: %w", tagErr_enc_subgroupid)
		}
		enc_subgroupid = retagged_enc_subgroupid
		children = append(children, enc_subgroupid...)
	}
	if v.ClassOfServiceID != nil {
		if (*v.ClassOfServiceID).BitLength < 16 || (*v.ClassOfServiceID).BitLength > 16 {
			if constraintErr := ber.CheckEncodedLength(opts, "classOfServiceID", "SIZE (16)", (*v.ClassOfServiceID).BitLength); constraintErr != nil {
				return nil, constraintErr
			}
		}
		if bitStringErr := ber.ValidateBitStringLength(v.ClassOfServiceID.Bytes, v.ClassOfServiceID.BitLength); bitStringErr != nil {
			return nil, fmt.Errorf("encoding %s: %w", "classOfServiceID", bitStringErr)
		}
		// arithmetic pattern BER_BITSTRING_FIELD: 0 <= bit length before modulo and subtraction; gen/codegen.go:526
		if v.ClassOfServiceID.BitLength < 0 {
			return nil, fmt.Errorf("negative bit string length")
		}
		enc_classofserviceid, encodeErr_enc_classofserviceid := ber.EncodeBitString(v.ClassOfServiceID.Bytes, (8-(v.ClassOfServiceID.BitLength%8))%8)
		if encodeErr_enc_classofserviceid != nil {
			return nil, fmt.Errorf("encoding classOfServiceID: %w", encodeErr_enc_classofserviceid)
		}
		retagged_enc_classofserviceid, tagErr_enc_classofserviceid := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 7, enc_classofserviceid)
		if tagErr_enc_classofserviceid != nil {
			return nil, fmt.Errorf("encoding classOfServiceID: %w", tagErr_enc_classofserviceid)
		}
		enc_classofserviceid = retagged_enc_classofserviceid
		children = append(children, enc_classofserviceid...)
	}
	return ber.EncodeSequence(children)
}

// MarshalDER encodes COSFeature to DER format.
func (v *COSFeature) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: COSFeature receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if v.BasicServiceCode != nil {
		enc_basicservicecode, err := v.BasicServiceCode.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding basicServiceCode: %w", err)
		}
		children = append(children, enc_basicservicecode...)
	}
	if len(v.SsStatus) < 1 || len(v.SsStatus) > 1 {
		if constraintErr := ber.CheckEncodedLength(nil, "ss-Status", "SIZE (1)", len(v.SsStatus)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_ssstatus, encodeErr_enc_ssstatus := ber.EncodeOctetString([]byte(v.SsStatus))
	if encodeErr_enc_ssstatus != nil {
		return nil, fmt.Errorf("encoding ss-Status: %w", encodeErr_enc_ssstatus)
	}
	retagged_enc_ssstatus, tagErr_enc_ssstatus := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, enc_ssstatus)
	if tagErr_enc_ssstatus != nil {
		return nil, fmt.Errorf("encoding ss-Status: %w", tagErr_enc_ssstatus)
	}
	enc_ssstatus = retagged_enc_ssstatus
	children = append(children, enc_ssstatus...)
	if v.CustomerGroupID != nil {
		if (*v.CustomerGroupID).BitLength < 32 || (*v.CustomerGroupID).BitLength > 32 {
			if constraintErr := ber.CheckEncodedLength(nil, "customerGroupID", "SIZE (32)", (*v.CustomerGroupID).BitLength); constraintErr != nil {
				return nil, constraintErr
			}
		}
		if bitStringErr := ber.ValidateBitStringLength(v.CustomerGroupID.Bytes, v.CustomerGroupID.BitLength); bitStringErr != nil {
			return nil, fmt.Errorf("encoding %s: %w", "customerGroupID", bitStringErr)
		}
		if bitStringErr := ber.ValidateDERBitString(v.CustomerGroupID.Bytes, v.CustomerGroupID.BitLength); bitStringErr != nil {
			return nil, fmt.Errorf("encoding %s: %w", "customerGroupID", bitStringErr)
		}
		// arithmetic pattern BER_BITSTRING_FIELD: 0 <= bit length before modulo and subtraction; gen/codegen.go:526
		if v.CustomerGroupID.BitLength < 0 {
			return nil, fmt.Errorf("negative bit string length")
		}
		enc_customergroupid, encodeErr_enc_customergroupid := ber.EncodeDERNamedBitString(v.CustomerGroupID.Bytes, v.CustomerGroupID.BitLength)
		if encodeErr_enc_customergroupid != nil {
			return nil, fmt.Errorf("encoding customerGroupID: %w", encodeErr_enc_customergroupid)
		}
		retagged_enc_customergroupid, tagErr_enc_customergroupid := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 5, enc_customergroupid)
		if tagErr_enc_customergroupid != nil {
			return nil, fmt.Errorf("encoding customerGroupID: %w", tagErr_enc_customergroupid)
		}
		enc_customergroupid = retagged_enc_customergroupid
		children = append(children, enc_customergroupid...)
	}
	if v.SubGroupID != nil {
		if (*v.SubGroupID).BitLength < 16 || (*v.SubGroupID).BitLength > 16 {
			if constraintErr := ber.CheckEncodedLength(nil, "subGroupID", "SIZE (16)", (*v.SubGroupID).BitLength); constraintErr != nil {
				return nil, constraintErr
			}
		}
		if bitStringErr := ber.ValidateBitStringLength(v.SubGroupID.Bytes, v.SubGroupID.BitLength); bitStringErr != nil {
			return nil, fmt.Errorf("encoding %s: %w", "subGroupID", bitStringErr)
		}
		if bitStringErr := ber.ValidateDERBitString(v.SubGroupID.Bytes, v.SubGroupID.BitLength); bitStringErr != nil {
			return nil, fmt.Errorf("encoding %s: %w", "subGroupID", bitStringErr)
		}
		// arithmetic pattern BER_BITSTRING_FIELD: 0 <= bit length before modulo and subtraction; gen/codegen.go:526
		if v.SubGroupID.BitLength < 0 {
			return nil, fmt.Errorf("negative bit string length")
		}
		enc_subgroupid, encodeErr_enc_subgroupid := ber.EncodeBitString(v.SubGroupID.Bytes, (8-(v.SubGroupID.BitLength%8))%8)
		if encodeErr_enc_subgroupid != nil {
			return nil, fmt.Errorf("encoding subGroupID: %w", encodeErr_enc_subgroupid)
		}
		retagged_enc_subgroupid, tagErr_enc_subgroupid := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 6, enc_subgroupid)
		if tagErr_enc_subgroupid != nil {
			return nil, fmt.Errorf("encoding subGroupID: %w", tagErr_enc_subgroupid)
		}
		enc_subgroupid = retagged_enc_subgroupid
		children = append(children, enc_subgroupid...)
	}
	if v.ClassOfServiceID != nil {
		if (*v.ClassOfServiceID).BitLength < 16 || (*v.ClassOfServiceID).BitLength > 16 {
			if constraintErr := ber.CheckEncodedLength(nil, "classOfServiceID", "SIZE (16)", (*v.ClassOfServiceID).BitLength); constraintErr != nil {
				return nil, constraintErr
			}
		}
		if bitStringErr := ber.ValidateBitStringLength(v.ClassOfServiceID.Bytes, v.ClassOfServiceID.BitLength); bitStringErr != nil {
			return nil, fmt.Errorf("encoding %s: %w", "classOfServiceID", bitStringErr)
		}
		if bitStringErr := ber.ValidateDERBitString(v.ClassOfServiceID.Bytes, v.ClassOfServiceID.BitLength); bitStringErr != nil {
			return nil, fmt.Errorf("encoding %s: %w", "classOfServiceID", bitStringErr)
		}
		// arithmetic pattern BER_BITSTRING_FIELD: 0 <= bit length before modulo and subtraction; gen/codegen.go:526
		if v.ClassOfServiceID.BitLength < 0 {
			return nil, fmt.Errorf("negative bit string length")
		}
		enc_classofserviceid, encodeErr_enc_classofserviceid := ber.EncodeDERNamedBitString(v.ClassOfServiceID.Bytes, v.ClassOfServiceID.BitLength)
		if encodeErr_enc_classofserviceid != nil {
			return nil, fmt.Errorf("encoding classOfServiceID: %w", encodeErr_enc_classofserviceid)
		}
		retagged_enc_classofserviceid, tagErr_enc_classofserviceid := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 7, enc_classofserviceid)
		if tagErr_enc_classofserviceid != nil {
			return nil, fmt.Errorf("encoding classOfServiceID: %w", tagErr_enc_classofserviceid)
		}
		enc_classofserviceid = retagged_enc_classofserviceid
		children = append(children, enc_classofserviceid...)
	}
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding COSFeature as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes COSFeature from BER/DER format.
func (v *COSFeature) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: COSFeature destination is nil", ber.ErrInvalidValue)
	}
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = COSFeature{}
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
		return fmt.Errorf("decoding COSFeature SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "COSFeature", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode basicServiceCode
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3) {
				// Decode nested CHOICE (BasicServiceCode5)
				_, n_basicservicecode, _, tlvErr_basicservicecode := ber.DecodeTLV(content[offset:], opts...)
				if tlvErr_basicservicecode != nil {
					return fmt.Errorf("decoding basicServiceCode: %w", tlvErr_basicservicecode)
				}
				var dec_basicservicecode BasicServiceCode5
				if offset < 0 || offset >
					len(content) || n_basicservicecode < 0 || n_basicservicecode >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				if unmErr := dec_basicservicecode.UnmarshalBER(content[offset:offset+n_basicservicecode], ber.ChildDecodeOptions(opts, "basicServiceCode")...); unmErr != nil {
					return fmt.Errorf("decoding basicServiceCode: %w", unmErr)
				}
				v.BasicServiceCode = &dec_basicservicecode
				if offset < 0 || offset >
					len(content) || n_basicservicecode < 0 || n_basicservicecode >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_basicservicecode
			}
		}
	}
	// Decode ss-Status
	if offset >= len(content) {
		return fmt.Errorf("missing required field ss-Status")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 4 {
			return fmt.Errorf("expected tag [%s %d] for ss-Status, got %s", "CONTEXT", 4, reqTag_)
		}
	}
	decodedTag_ssstatus, n_ssstatus, rawVal_ssstatus, err := ber.DecodeTLV(content[offset:], opts...)
	if err != nil {
		return fmt.Errorf("decoding ss-Status: %w", err)
	}
	if decodedTag_ssstatus.Class != tag.ClassContextSpecific || decodedTag_ssstatus.Number != 4 {
		return fmt.Errorf("decoding ss-Status: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_ssstatus)
	}
	decVal_ssstatus, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_ssstatus.Constructed, rawVal_ssstatus, opts...)
	if octetErr != nil {
		return fmt.Errorf("decoding ss-Status: %w", octetErr)
	}
	v.SsStatus = SSStatus6(decVal_ssstatus)
	if offset < 0 || offset >
		len(content) || n_ssstatus < 0 || n_ssstatus > len(
		content[offset:]) {
		return fmt.Errorf("invalid BER content window")
	}

	offset += n_ssstatus
	if len(v.SsStatus) < 1 || len(v.SsStatus) > 1 {
		if constraintErr := ber.CheckDecodedLength(opts, "ss-Status", "SIZE (1)", len(v.SsStatus)); constraintErr != nil {
			return constraintErr
		}
	}
	// Decode customerGroupID
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 5 {
				decodedTag_customergroupid, n_customergroupid, rawVal_customergroupid, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding customerGroupID: %w", err)
				}
				if decodedTag_customergroupid.Class != tag.ClassContextSpecific || decodedTag_customergroupid.Number != 5 {
					return fmt.Errorf("decoding customerGroupID: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_customergroupid)
				}
				bsBytes_customergroupid, bsUnused_customergroupid, bsErr := ber.DecodeImplicitBitStringValue(decodedTag_customergroupid.Constructed, rawVal_customergroupid, opts...)
				if bsErr != nil {
					return fmt.Errorf("decoding customerGroupID: %w", bsErr)
				}
				bsBitLength_customergroupid, bsLenErr_customergroupid := ber.BitStringBitLength(len(bsBytes_customergroupid), bsUnused_customergroupid)
				if bsLenErr_customergroupid != nil {
					return fmt.Errorf("decoding customerGroupID: %w", bsLenErr_customergroupid)
				}
				tmp_customergroupid := runtime.BitString{Bytes: bsBytes_customergroupid, BitLength: bsBitLength_customergroupid}
				v.CustomerGroupID = &tmp_customergroupid
				if offset < 0 || offset >
					len(content) || n_customergroupid < 0 || n_customergroupid >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_customergroupid
				*v.CustomerGroupID = ber.NormalizeNamedBitStringSize(*v.CustomerGroupID, []ber.NamedBitSizeSet{{{Min: 32, Max: 32}}}, opts...)
				if (*v.CustomerGroupID).BitLength < 32 || (*v.CustomerGroupID).BitLength > 32 {
					if constraintErr := ber.CheckDecodedLength(opts, "customerGroupID", "SIZE (32)", (*v.CustomerGroupID).BitLength); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode subGroupID
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 6 {
				decodedTag_subgroupid, n_subgroupid, rawVal_subgroupid, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding subGroupID: %w", err)
				}
				if decodedTag_subgroupid.Class != tag.ClassContextSpecific || decodedTag_subgroupid.Number != 6 {
					return fmt.Errorf("decoding subGroupID: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_subgroupid)
				}
				bsBytes_subgroupid, bsUnused_subgroupid, bsErr := ber.DecodeImplicitBitStringValue(decodedTag_subgroupid.Constructed, rawVal_subgroupid, opts...)
				if bsErr != nil {
					return fmt.Errorf("decoding subGroupID: %w", bsErr)
				}
				bsBitLength_subgroupid, bsLenErr_subgroupid := ber.BitStringBitLength(len(bsBytes_subgroupid), bsUnused_subgroupid)
				if bsLenErr_subgroupid != nil {
					return fmt.Errorf("decoding subGroupID: %w", bsLenErr_subgroupid)
				}
				tmp_subgroupid := runtime.BitString{Bytes: bsBytes_subgroupid, BitLength: bsBitLength_subgroupid}
				v.SubGroupID = &tmp_subgroupid
				if offset < 0 || offset >
					len(content) || n_subgroupid < 0 || n_subgroupid >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_subgroupid
				if (*v.SubGroupID).BitLength < 16 || (*v.SubGroupID).BitLength > 16 {
					if constraintErr := ber.CheckDecodedLength(opts, "subGroupID", "SIZE (16)", (*v.SubGroupID).BitLength); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode classOfServiceID
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 7 {
				decodedTag_classofserviceid, n_classofserviceid, rawVal_classofserviceid, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding classOfServiceID: %w", err)
				}
				if decodedTag_classofserviceid.Class != tag.ClassContextSpecific || decodedTag_classofserviceid.Number != 7 {
					return fmt.Errorf("decoding classOfServiceID: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_classofserviceid)
				}
				bsBytes_classofserviceid, bsUnused_classofserviceid, bsErr := ber.DecodeImplicitBitStringValue(decodedTag_classofserviceid.Constructed, rawVal_classofserviceid, opts...)
				if bsErr != nil {
					return fmt.Errorf("decoding classOfServiceID: %w", bsErr)
				}
				bsBitLength_classofserviceid, bsLenErr_classofserviceid := ber.BitStringBitLength(len(bsBytes_classofserviceid), bsUnused_classofserviceid)
				if bsLenErr_classofserviceid != nil {
					return fmt.Errorf("decoding classOfServiceID: %w", bsLenErr_classofserviceid)
				}
				tmp_classofserviceid := runtime.BitString{Bytes: bsBytes_classofserviceid, BitLength: bsBitLength_classofserviceid}
				v.ClassOfServiceID = &tmp_classofserviceid
				if offset < 0 || offset >
					len(content) || n_classofserviceid < 0 || n_classofserviceid >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_classofserviceid
				*v.ClassOfServiceID = ber.NormalizeNamedBitStringSize(*v.ClassOfServiceID, []ber.NamedBitSizeSet{{{Min: 16, Max: 16}}}, opts...)
				if (*v.ClassOfServiceID).BitLength < 16 || (*v.ClassOfServiceID).BitLength > 16 {
					if constraintErr := ber.CheckDecodedLength(opts, "classOfServiceID", "SIZE (16)", (*v.ClassOfServiceID).BitLength); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "COSFeature", Cause: ber.ErrExtraData}
	}
	return nil
}

// MarshalBER encodes AccessTypeExt to BER format.
func (v *AccessTypeExt) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: AccessTypeExt receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *AccessTypeExt) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	enc_access := ber.EncodeEnumerated(int64(v.Access))
	children = append(children, enc_access...)
	if !(int64(v.Version) >= 1 && int64(v.Version) <= 20) {
		if constraintErr := ber.CheckEncodedValue(opts, "version", "(1..20)", fmt.Sprint(int64(v.Version))); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_version := ber.EncodeInteger(int64(v.Version))
	children = append(children, enc_version...)
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

// MarshalDER encodes AccessTypeExt to DER format.
func (v *AccessTypeExt) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: AccessTypeExt receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	enc_access := ber.EncodeEnumerated(int64(v.Access))
	children = append(children, enc_access...)
	if !(int64(v.Version) >= 1 && int64(v.Version) <= 20) {
		if constraintErr := ber.CheckEncodedValue(nil, "version", "(1..20)", fmt.Sprint(int64(v.Version))); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_version := ber.EncodeInteger(int64(v.Version))
	children = append(children, enc_version...)
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
		return nil, fmt.Errorf("encoding AccessTypeExt as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes AccessTypeExt from BER/DER format.
func (v *AccessTypeExt) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: AccessTypeExt destination is nil", ber.ErrInvalidValue)
	}
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = AccessTypeExt{}
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
		return fmt.Errorf("decoding AccessTypeExt SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "AccessTypeExt", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode access
	if offset >= len(content) {
		return fmt.Errorf("missing required field access")
	}
	val_access, n, err := ber.DecodeEnumerated(content[offset:], opts...)
	if err != nil {
		return fmt.Errorf("decoding access: %w", err)
	}
	v.Access = Access(val_access)
	if offset < 0 || offset >
		len(content) || n < 0 || n > len(content[offset:]) {
		return fmt.Errorf("invalid BER content window")
	}

	offset += n
	// Decode version
	if offset >= len(content) {
		return fmt.Errorf("missing required field version")
	}
	val_version, n, err := ber.DecodeInteger(content[offset:], opts...)
	if err != nil {
		return fmt.Errorf("decoding version: %w", err)
	}
	v.Version = Version(val_version)
	if offset < 0 || offset >
		len(content) || n < 0 || n > len(content[offset:]) {
		return fmt.Errorf("invalid BER content window")
	}

	offset += n
	if !(int64(v.Version) >= 1 && int64(v.Version) <= 20) {
		if constraintErr := ber.CheckDecodedValue(opts, "version", "(1..20)", fmt.Sprint(int64(v.Version))); constraintErr != nil {
			return constraintErr
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:], opts...)
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "AccessTypeExt", Cause: extErr_}
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

// MarshalBERAccessSubscriptionListExt encodes a AccessSubscriptionListExt list to BER.
func MarshalBERAccessSubscriptionListExt(collection *AccessSubscriptionListExt, opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	if collection == nil {
		return nil, fmt.Errorf("%w: required collection is nil", ber.ErrInvalidValue)
	}
	encoded, err := marshalBERAccessSubscriptionListExt(collection, opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, collection.berOriginal_, collection.berSnapshot_, opts), nil
}
func marshalBERAccessSubscriptionListExt(collection *AccessSubscriptionListExt, opts ...ber.EncodeOption) ([]byte, error) {
	list := collection.Values
	if len(list) < 1 || len(list) > 10 {
		if constraintErr := ber.CheckEncodedLength(opts, "AccessSubscriptionListExt", "SIZE (1..10)", len(list)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	var children []byte
	for _, elem := range list {
		children = append(children, ber.EncodeEnumerated(int64(elem))...)
	}
	return ber.EncodeSequence(children)
}

// MarshalDERAccessSubscriptionListExt encodes a AccessSubscriptionListExt list to DER.
func MarshalDERAccessSubscriptionListExt(collection *AccessSubscriptionListExt) ([]byte, error) {
	if collection == nil {
		return nil, fmt.Errorf("%w: required collection is nil", ber.ErrInvalidValue)
	}
	list := collection.Values
	if len(list) < 1 || len(list) > 10 {
		if constraintErr := ber.CheckEncodedLength(nil, "AccessSubscriptionListExt", "SIZE (1..10)", len(list)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	var children []byte
	for _, elem := range list {
		children = append(children, ber.EncodeEnumerated(int64(elem))...)
	}
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding AccessSubscriptionListExt as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBERAccessSubscriptionListExt decodes a AccessSubscriptionListExt list from BER.
func UnmarshalBERAccessSubscriptionListExt(data []byte, opts ...ber.DecodeOption) (returnValue *AccessSubscriptionListExt, returnErr error) {
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return nil, err
	}
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return nil, fmt.Errorf("decoding AccessSubscriptionListExt: %w", err)
	}
	if total != len(data) {
		return nil, &ber.DecodeError{Offset: total, TypeName: "AccessSubscriptionListExt", Cause: ber.ErrExtraData}
	}
	var result []Access
	offset := 0
	for offset < len(content) {
		elementData := content[offset:]
		val, n, intErr := ber.DecodeEnumerated(elementData, opts...)
		if intErr != nil {
			return nil, fmt.Errorf("decoding element: %w", intErr)
		}
		result = append(result, Access(val))
		if offset < 0 || offset >
			len(content) || n < 0 || n > len(content[offset:]) {
			return nil, fmt.Errorf("invalid BER content window")
		}

		offset += n
	}
	if len(result) < 1 || len(result) > 10 {
		if constraintErr := ber.CheckDecodedLength(opts, "AccessSubscriptionListExt", "SIZE (1..10)", len(result)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	decoded := &AccessSubscriptionListExt{Values: result}
	if ber.BERNeedsPreservation(opts) {
		var snapshotReports ber.ViolationLog
		snapshot, snapshotErr := MarshalBERAccessSubscriptionListExt(decoded, ber.WithConstraintTolerance(&snapshotReports))
		if snapshotErr != nil {
			return nil, snapshotErr
		}
		decoded.berOriginal_ = append([]byte(nil), data...)
		decoded.berSnapshot_ = snapshot
	}
	return decoded, nil
}

// MarshalBER encodes AnyTimePOBarringArg to BER format.
func (v *AnyTimePOBarringArg) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: AnyTimePOBarringArg receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *AnyTimePOBarringArg) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	enc_subscriberidentity, err := v.SubscriberIdentity.MarshalBER(ber.ChildEncodeOptions(opts, "subscriberIdentity")...)
	if err != nil {
		return nil, fmt.Errorf("encoding subscriberIdentity: %w", err)
	}
	{
		var encodeErr error
		enc_subscriberidentity, encodeErr = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 0, enc_subscriberidentity)
		if encodeErr != nil {
			return nil, fmt.Errorf("encoding subscriberIdentity: %w", encodeErr)
		}
	}
	children = append(children, enc_subscriberidentity...)
	if len(v.GsmSCFAddress) < 1 || len(v.GsmSCFAddress) > 9 {
		if constraintErr := ber.CheckEncodedLength(opts, "gsmSCF-Address", "SIZE (1..9)", len(v.GsmSCFAddress)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	if len(v.GsmSCFAddress) < 1 || len(v.GsmSCFAddress) > 20 {
		if constraintErr := ber.CheckEncodedLength(opts, "gsmSCF-Address", "SIZE (1..20)", len(v.GsmSCFAddress)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_gsmscfaddress, encodeErr_enc_gsmscfaddress := ber.EncodeOctetString([]byte(v.GsmSCFAddress))
	if encodeErr_enc_gsmscfaddress != nil {
		return nil, fmt.Errorf("encoding gsmSCF-Address: %w", encodeErr_enc_gsmscfaddress)
	}
	retagged_enc_gsmscfaddress, tagErr_enc_gsmscfaddress := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, enc_gsmscfaddress)
	if tagErr_enc_gsmscfaddress != nil {
		return nil, fmt.Errorf("encoding gsmSCF-Address: %w", tagErr_enc_gsmscfaddress)
	}
	enc_gsmscfaddress = retagged_enc_gsmscfaddress
	children = append(children, enc_gsmscfaddress...)
	enc_gprsbarring := ber.EncodeEnumerated(int64(v.GprsBarring))
	children = append(children, enc_gprsbarring...)
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

// MarshalDER encodes AnyTimePOBarringArg to DER format.
func (v *AnyTimePOBarringArg) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: AnyTimePOBarringArg receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	enc_subscriberidentity, err := v.SubscriberIdentity.MarshalDER()
	if err != nil {
		return nil, fmt.Errorf("encoding subscriberIdentity: %w", err)
	}
	{
		var encodeErr error
		enc_subscriberidentity, encodeErr = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 0, enc_subscriberidentity)
		if encodeErr != nil {
			return nil, fmt.Errorf("encoding subscriberIdentity: %w", encodeErr)
		}
	}
	children = append(children, enc_subscriberidentity...)
	if len(v.GsmSCFAddress) < 1 || len(v.GsmSCFAddress) > 9 {
		if constraintErr := ber.CheckEncodedLength(nil, "gsmSCF-Address", "SIZE (1..9)", len(v.GsmSCFAddress)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	if len(v.GsmSCFAddress) < 1 || len(v.GsmSCFAddress) > 20 {
		if constraintErr := ber.CheckEncodedLength(nil, "gsmSCF-Address", "SIZE (1..20)", len(v.GsmSCFAddress)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_gsmscfaddress, encodeErr_enc_gsmscfaddress := ber.EncodeOctetString([]byte(v.GsmSCFAddress))
	if encodeErr_enc_gsmscfaddress != nil {
		return nil, fmt.Errorf("encoding gsmSCF-Address: %w", encodeErr_enc_gsmscfaddress)
	}
	retagged_enc_gsmscfaddress, tagErr_enc_gsmscfaddress := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, enc_gsmscfaddress)
	if tagErr_enc_gsmscfaddress != nil {
		return nil, fmt.Errorf("encoding gsmSCF-Address: %w", tagErr_enc_gsmscfaddress)
	}
	enc_gsmscfaddress = retagged_enc_gsmscfaddress
	children = append(children, enc_gsmscfaddress...)
	enc_gprsbarring := ber.EncodeEnumerated(int64(v.GprsBarring))
	children = append(children, enc_gprsbarring...)
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
		return nil, fmt.Errorf("encoding AnyTimePOBarringArg as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes AnyTimePOBarringArg from BER/DER format.
func (v *AnyTimePOBarringArg) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: AnyTimePOBarringArg destination is nil", ber.ErrInvalidValue)
	}
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = AnyTimePOBarringArg{}
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
		return fmt.Errorf("decoding AnyTimePOBarringArg SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "AnyTimePOBarringArg", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode subscriberIdentity
	if offset >= len(content) {
		return fmt.Errorf("missing required field subscriberIdentity")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 0 {
			return fmt.Errorf("expected tag [%s %d] for subscriberIdentity, got %s", "CONTEXT", 0, reqTag_)
		}
	}
	decodedTag_subscriberidentity, n_subscriberidentity, innerData_subscriberidentity, err := ber.DecodeTLV(content[offset:], opts...)
	if err != nil {
		return fmt.Errorf("decoding subscriberIdentity: %w", err)
	}
	if decodedTag_subscriberidentity.Class != tag.ClassContextSpecific || decodedTag_subscriberidentity.Number != 0 || decodedTag_subscriberidentity.Constructed != true {
		return fmt.Errorf("decoding subscriberIdentity: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_subscriberidentity)
	}
	// Decode inner value from explicit tag wrapper
	if unmErr := v.SubscriberIdentity.UnmarshalBER(innerData_subscriberidentity, ber.ChildDecodeOptions(opts, "subscriberIdentity")...); unmErr != nil {
		return fmt.Errorf("decoding subscriberIdentity: %w", unmErr)
	}
	if offset < 0 || offset >
		len(content) || n_subscriberidentity < 0 || n_subscriberidentity >
		len(content[offset:]) {
		return fmt.Errorf("invalid BER content window")
	}

	offset += n_subscriberidentity
	// Decode gsmSCF-Address
	if offset >= len(content) {
		return fmt.Errorf("missing required field gsmSCF-Address")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 3 {
			return fmt.Errorf("expected tag [%s %d] for gsmSCF-Address, got %s", "CONTEXT", 3, reqTag_)
		}
	}
	decodedTag_gsmscfaddress, n_gsmscfaddress, rawVal_gsmscfaddress, err := ber.DecodeTLV(content[offset:], opts...)
	if err != nil {
		return fmt.Errorf("decoding gsmSCF-Address: %w", err)
	}
	if decodedTag_gsmscfaddress.Class != tag.ClassContextSpecific || decodedTag_gsmscfaddress.Number != 3 {
		return fmt.Errorf("decoding gsmSCF-Address: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_gsmscfaddress)
	}
	decVal_gsmscfaddress, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_gsmscfaddress.Constructed, rawVal_gsmscfaddress, opts...)
	if octetErr != nil {
		return fmt.Errorf("decoding gsmSCF-Address: %w", octetErr)
	}
	v.GsmSCFAddress = ISDNAddressString5(decVal_gsmscfaddress)
	if offset < 0 || offset >
		len(content) || n_gsmscfaddress < 0 || n_gsmscfaddress > len(content[offset:]) {
		return fmt.Errorf("invalid BER content window")
	}

	offset += n_gsmscfaddress
	if len(v.GsmSCFAddress) < 1 || len(v.GsmSCFAddress) > 9 {
		if constraintErr := ber.CheckDecodedLength(opts, "gsmSCF-Address", "SIZE (1..9)", len(v.GsmSCFAddress)); constraintErr != nil {
			return constraintErr
		}
	}
	if len(v.GsmSCFAddress) < 1 || len(v.GsmSCFAddress) > 20 {
		if constraintErr := ber.CheckDecodedLength(opts, "gsmSCF-Address", "SIZE (1..20)", len(v.GsmSCFAddress)); constraintErr != nil {
			return constraintErr
		}
	}
	// Decode gprs-Barring
	if offset >= len(content) {
		return fmt.Errorf("missing required field gprs-Barring")
	}
	val_gprsbarring, n, err := ber.DecodeEnumerated(content[offset:], opts...)
	if err != nil {
		return fmt.Errorf("decoding gprs-Barring: %w", err)
	}
	v.GprsBarring = GprsBarring(val_gprsbarring)
	if offset < 0 || offset >
		len(content) || n < 0 || n > len(content[offset:]) {
		return fmt.Errorf("invalid BER content window")
	}

	offset += n
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:], opts...)
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "AnyTimePOBarringArg", Cause: extErr_}
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

// MarshalBER encodes AnyTimePOBarringRes to BER format.
func (v *AnyTimePOBarringRes) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: AnyTimePOBarringRes receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *AnyTimePOBarringRes) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
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

// MarshalDER encodes AnyTimePOBarringRes to DER format.
func (v *AnyTimePOBarringRes) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: AnyTimePOBarringRes receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
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
		return nil, fmt.Errorf("encoding AnyTimePOBarringRes as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes AnyTimePOBarringRes from BER/DER format.
func (v *AnyTimePOBarringRes) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: AnyTimePOBarringRes destination is nil", ber.ErrInvalidValue)
	}
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = AnyTimePOBarringRes{}
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
		return fmt.Errorf("decoding AnyTimePOBarringRes SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "AnyTimePOBarringRes", Cause: ber.ErrExtraData}
	}
	offset := 0
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:], opts...)
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "AnyTimePOBarringRes", Cause: extErr_}
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
