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

	// MaxNumOfActiveSS is the integer constant for MaxNumOfActiveSS.
	MaxNumOfActiveSS int64 = 30

	// MaxNumOfCA is the integer constant for MaxNumOfCA.
	MaxNumOfCA int64 = 3

	// PicLock is the octet string constant for PicLock.
	PicLock = "\x01"

	// PrefCarrierId is the octet string constant for PrefCarrierId.
	PrefCarrierId = "\x02"

	// MKeyValue is the octet string constant for MKeyValue.
	MKeyValue = "\x03"

	// SmsKey is the octet string constant for SmsKey.
	SmsKey = "\x04"

	// FraudDataValue is the octet string constant for FraudDataValue.
	FraudDataValue = "\x05"

	// CellUpdate is the octet string constant for CellUpdate.
	CellUpdate = "\x06"

	// MaxnumOfMAPservices is the integer constant for MaxnumOfMAPservices.
	MaxnumOfMAPservices int64 = 256

	// MaxNumOfLEAs is the integer constant for MaxNumOfLEAs.
	MaxNumOfLEAs int64 = 7

	// MaxNumOfServicesWithInfo is the integer constant for MaxNumOfServicesWithInfo.
	MaxNumOfServicesWithInfo int64 = 20

	// MaxNumOfCodec is the integer constant for MaxNumOfCodec.
	MaxNumOfCodec int64 = 8

	// MaxNumberOfCOSFeatures is the integer constant for MaxNumberOfCOSFeatures.
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
	AlsLineIndicator   *struct{}           `asn1:"tag:0,context,implicit,optional" json:"AlsLineIndicator,omitempty"`
	RoutingCategory    *RoutingCategory    `asn1:"tag:1,context,implicit,optional" json:"RoutingCategory,omitempty"`
	ServiceList        *MAPserviceList     `asn1:"tag:2,context,implicit,optional" json:"ServiceList,omitempty"`
	ServInfoList       ServiceListWithInfo `asn1:"tag:3,context,implicit,optional" json:"ServInfoList,omitempty"`
	ServInfoListIndef_ bool                `asn1:"-" json:"-"`
	ExtRoutingCategory *ExtRoutingCategory `asn1:"tag:5,context,implicit,optional" json:"ExtRoutingCategory,omitempty"`
	OwnMSISDN          *ISDNAddressString4 `asn1:"tag:6,context,implicit,optional" json:"OwnMSISDN,omitempty"`
	ExtCount_          int64               `asn1:"-" json:"-"`
	ExtPresent_        []bool              `asn1:"-" json:"-"`
	ExtData_           [][]byte            `asn1:"-" json:"-"`
}

// DsdArgExt represents the ASN.1 type DsdArgExt (SEQUENCE).
type DsdArgExt struct {
	AlsLineIndicator *struct{}       `asn1:"tag:0,context,implicit,optional" json:"AlsLineIndicator,omitempty"`
	ServiceList      *MAPserviceList `asn1:"tag:1,context,implicit,optional" json:"ServiceList,omitempty"`
	ExtCount_        int64           `asn1:"-" json:"-"`
	ExtPresent_      []bool          `asn1:"-" json:"-"`
	ExtData_         [][]byte        `asn1:"-" json:"-"`
}

// UlResExt represents the ASN.1 type UlResExt (SEQUENCE).
type UlResExt struct {
	MwdSet      *struct{} `asn1:"tag:0,context,implicit,optional" json:"MwdSet,omitempty"`
	ExtCount_   int64     `asn1:"-" json:"-"`
	ExtPresent_ []bool    `asn1:"-" json:"-"`
	ExtData_    [][]byte  `asn1:"-" json:"-"`
}

// EmoInCategoryKey represents the ASN.1 type EmoInCategoryKey (OCTET_STRING).
type EmoInCategoryKey = TBCDSTRING4

// SSDataEmoInExt represents the ASN.1 type SS-DataEmoInExt (SEQUENCE).
type SSDataEmoInExt struct {
	EmoInCategoryKey *EmoInCategoryKey `asn1:"tag:2,private,implicit,optional" json:"EmoInCategoryKey,omitempty"`
	ExtCount_        int64             `asn1:"-" json:"-"`
	ExtPresent_      []bool            `asn1:"-" json:"-"`
	ExtData_         [][]byte          `asn1:"-" json:"-"`
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
type ChargingAreaList = []ChargingArea

// RegionalChargingData represents the ASN.1 type RegionalChargingData (SEQUENCE).
type RegionalChargingData struct {
	ChargingAreaList       ChargingAreaList `asn1:"tag:0,context,implicit,optional" json:"ChargingAreaList,omitempty"`
	ChargingAreaListIndef_ bool             `asn1:"-" json:"-"`
	ExtCount_              int64            `asn1:"-" json:"-"`
	ExtPresent_            []bool           `asn1:"-" json:"-"`
	ExtData_               [][]byte         `asn1:"-" json:"-"`
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
	ProtocolId ExtensionsExtraProtocolId `asn1:""`
	SignalInfo SignalInfo4               `asn1:""`
}

// CUGCallInfo represents the ASN.1 type CUG-CallInfo (OCTET_STRING).
type CUGCallInfo = []byte

// NokiaCUGData represents the ASN.1 type Nokia-CUG-Data (SEQUENCE).
type NokiaCUGData struct {
	CugInterlock          *CUGInterlock4 `asn1:"tag:0,context,implicit,optional" json:"CugInterlock,omitempty"`
	CugOutgoingAccess     *bool          `asn1:"tag:1,context,implicit,optional" json:"CugOutgoingAccess,omitempty"`
	CugOutgoingAccessRaw_ byte           `asn1:"-" json:"-"`
	CugCallInfo           *CUGCallInfo   `asn1:"tag:2,context,implicit,optional" json:"CugCallInfo,omitempty"`
	ExtCount_             int64          `asn1:"-" json:"-"`
	ExtPresent_           []bool         `asn1:"-" json:"-"`
	ExtData_              [][]byte       `asn1:"-" json:"-"`
}

// SriResExtension represents the ASN.1 type SriResExtension (SEQUENCE).
type SriResExtension struct {
	InTriggerKey        *InTriggerKey       `asn1:"tag:0,context,implicit,optional" json:"InTriggerKey,omitempty"`
	VlrNumber           *ISDNAddressString4 `asn1:"tag:1,context,implicit,optional" json:"VlrNumber,omitempty"`
	ActiveSs            *ActiveSSList       `asn1:"tag:2,context,implicit,optional" json:"ActiveSs,omitempty"`
	TraceReference      *TraceReference4    `asn1:"tag:3,context,implicit,optional" json:"TraceReference,omitempty"`
	TraceType           *TraceType4         `asn1:"tag:4,context,implicit,optional" json:"TraceType,omitempty"`
	OmcId               *AddressString4     `asn1:"tag:5,context,implicit,optional" json:"OmcId,omitempty"`
	HotBilling          *bool               `asn1:"tag:6,context,implicit,optional" json:"HotBilling,omitempty"`
	HotBillingRaw_      byte                `asn1:"-" json:"-"`
	CfoIsDone           *bool               `asn1:"tag:7,context,implicit,optional" json:"CfoIsDone,omitempty"`
	CfoIsDoneRaw_       byte                `asn1:"-" json:"-"`
	CfInCug             *bool               `asn1:"tag:8,context,implicit,optional" json:"CfInCug,omitempty"`
	CfInCugRaw_         byte                `asn1:"-" json:"-"`
	BasicService        *BasicServiceCode4  `asn1:"tag:9,context,explicit,optional" json:"BasicService,omitempty"`
	Category            *Category5          `asn1:"tag:10,context,implicit,optional" json:"Category,omitempty"`
	RoutingCategory     *RoutingCategory    `asn1:"tag:11,context,implicit,optional" json:"RoutingCategory,omitempty"`
	PnpIndex            *PnpIndex           `asn1:"tag:12,context,implicit,optional" json:"PnpIndex,omitempty"`
	NokiaCUG            *NokiaCUGData       `asn1:"tag:13,context,implicit,optional" json:"NokiaCUG,omitempty"`
	NoBarrings          *struct{}           `asn1:"tag:14,context,implicit,optional" json:"NoBarrings,omitempty"`
	OdbData             *ODBData4           `asn1:"tag:15,context,implicit,optional" json:"OdbData,omitempty"`
	FraudData           *FraudData          `asn1:"tag:16,context,implicit,optional" json:"FraudData,omitempty"`
	ExtRoutingCategory  *ExtRoutingCategory `asn1:"tag:17,context,implicit,optional" json:"ExtRoutingCategory,omitempty"`
	LeaId               *LeaId              `asn1:"tag:18,context,implicit,optional" json:"LeaId,omitempty"`
	OlcmInfoTable       OlcmInfoTable       `asn1:"tag:19,context,implicit,optional" json:"OlcmInfoTable,omitempty"`
	OlcmInfoTableIndef_ bool                `asn1:"-" json:"-"`
	CallingCategory     *CallingCategory    `asn1:"tag:20,context,implicit,optional" json:"CallingCategory,omitempty"`
	CommonMSISDN        *ISDNAddressString4 `asn1:"tag:21,context,implicit,optional" json:"CommonMSISDN,omitempty"`
	RgData              *RgData             `asn1:"tag:22,context,implicit,optional" json:"RgData,omitempty"`
	OlcmTraceReference  *OlcmTraceReference `asn1:"tag:23,context,implicit,optional" json:"OlcmTraceReference,omitempty"`
	ExtCount_           int64               `asn1:"-" json:"-"`
	ExtPresent_         []bool              `asn1:"-" json:"-"`
	ExtData_            [][]byte            `asn1:"-" json:"-"`
}

// RgData represents the ASN.1 type RgData (SEQUENCE).
type RgData struct {
	NoAnswerTimer       *NoAnswerTimer      `asn1:"tag:0,context,implicit,optional" json:"NoAnswerTimer,omitempty"`
	MemberList          MemberList          `asn1:"tag:1,context,implicit,optional" json:"MemberList,omitempty"`
	MemberListIndef_    bool                `asn1:"-" json:"-"`
	AlertingMethod      *AlertingMethod     `asn1:"tag:2,context,implicit,optional" json:"AlertingMethod,omitempty"`
	UserType            *UserType           `asn1:"tag:3,context,implicit,optional" json:"UserType,omitempty"`
	DivertedToNbr       *ISDNAddressString4 `asn1:"tag:4,context,implicit,optional" json:"DivertedToNbr,omitempty"`
	MemberOfSuppression *struct{}           `asn1:"tag:5,context,implicit,optional" json:"MemberOfSuppression,omitempty"`
	Ringbacktone        *struct{}           `asn1:"tag:6,context,implicit,optional" json:"Ringbacktone,omitempty"`
	ExtCount_           int64               `asn1:"-" json:"-"`
	ExtPresent_         []bool              `asn1:"-" json:"-"`
	ExtData_            [][]byte            `asn1:"-" json:"-"`
}

// NoAnswerTimer represents the ASN.1 type NoAnswerTimer (OCTET_STRING).
type NoAnswerTimer = []byte

// MemberList represents the ASN.1 type MemberList (SEQUENCE_OF).
type MemberList = []ISDNAddressString4

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
}

// ANSIIsdArgExt represents the ASN.1 type ANSIIsdArgExt (SEQUENCE).
type ANSIIsdArgExt struct {
	PrefCarrierIdList *PrefCarrierIdList `asn1:"tag:0,context,implicit,optional" json:"PrefCarrierIdList,omitempty"`
	ExtCount_         int64              `asn1:"-" json:"-"`
	ExtPresent_       []bool             `asn1:"-" json:"-"`
	ExtData_          [][]byte           `asn1:"-" json:"-"`
}

// ANSISriResExt represents the ASN.1 type ANSISriResExt (SEQUENCE).
type ANSISriResExt struct {
	PrefCarrierIdList *PrefCarrierIdList `asn1:"tag:0,context,implicit,optional" json:"PrefCarrierIdList,omitempty"`
	ExtCount_         int64              `asn1:"-" json:"-"`
	ExtPresent_       []bool             `asn1:"-" json:"-"`
	ExtData_          [][]byte           `asn1:"-" json:"-"`
}

// CanLocArgExt represents the ASN.1 type CanLocArgExt (SEQUENCE).
type CanLocArgExt struct {
	Termination []byte   `asn1:"tag:0,context,implicit,optional" json:"Termination,omitempty"`
	ExtCount_   int64    `asn1:"-" json:"-"`
	ExtPresent_ []bool   `asn1:"-" json:"-"`
	ExtData_    [][]byte `asn1:"-" json:"-"`
}

// ATMargExt represents the ASN.1 type ATMargExt (SEQUENCE).
type ATMargExt struct {
	TraceReference      *TraceReference4    `asn1:"tag:0,context,implicit,optional" json:"TraceReference,omitempty"`
	TraceType           *TraceType4         `asn1:"tag:1,context,implicit,optional" json:"TraceType,omitempty"`
	LeaId               *LeaId              `asn1:"tag:2,context,implicit,optional" json:"LeaId,omitempty"`
	OlcmInfoTable       OlcmInfoTable       `asn1:"tag:3,context,implicit,optional" json:"OlcmInfoTable,omitempty"`
	OlcmInfoTableIndef_ bool                `asn1:"-" json:"-"`
	OlcmTraceReference  *OlcmTraceReference `asn1:"tag:4,context,implicit,optional" json:"OlcmTraceReference,omitempty"`
	ExtCount_           int64               `asn1:"-" json:"-"`
	ExtPresent_         []bool              `asn1:"-" json:"-"`
	ExtData_            [][]byte            `asn1:"-" json:"-"`
}

// LeaId represents the ASN.1 type LeaId (INTEGER).
type LeaId = int64

// OlcmInfoTable represents the ASN.1 type OlcmInfoTable (SEQUENCE_OF).
type OlcmInfoTable = []OlcmInfo

// OlcmInfo represents the ASN.1 type OlcmInfo (SEQUENCE).
type OlcmInfo struct {
	TraceReference     TraceReference4     `asn1:"tag:0,context,implicit"`
	TraceType          TraceType4          `asn1:"tag:1,context,implicit"`
	LeaId              *LeaId              `asn1:"tag:2,context,implicit,optional" json:"LeaId,omitempty"`
	OlcmTraceReference *OlcmTraceReference `asn1:"tag:3,context,implicit,optional" json:"OlcmTraceReference,omitempty"`
	ExtCount_          int64               `asn1:"-" json:"-"`
	ExtPresent_        []bool              `asn1:"-" json:"-"`
	ExtData_           [][]byte            `asn1:"-" json:"-"`
}

// OlcmTraceReference represents the ASN.1 type OlcmTraceReference (OCTET_STRING).
type OlcmTraceReference = []byte

// ATMresExt represents the ASN.1 type ATMresExt (SEQUENCE).
type ATMresExt struct {
	OlcmActive  *struct{} `asn1:"tag:0,context,implicit,optional" json:"OlcmActive,omitempty"`
	ExtCount_   int64     `asn1:"-" json:"-"`
	ExtPresent_ []bool    `asn1:"-" json:"-"`
	ExtData_    [][]byte  `asn1:"-" json:"-"`
}

// DTMargExt represents the ASN.1 type DTMargExt (SEQUENCE).
type DTMargExt struct {
	TraceType          *TraceType4         `asn1:"tag:0,context,implicit,optional" json:"TraceType,omitempty"`
	LeaId              *LeaId              `asn1:"tag:1,context,implicit,optional" json:"LeaId,omitempty"`
	OlcmTraceReference *OlcmTraceReference `asn1:"tag:2,context,implicit,optional" json:"OlcmTraceReference,omitempty"`
	ExtCount_          int64               `asn1:"-" json:"-"`
	ExtPresent_        []bool              `asn1:"-" json:"-"`
	ExtData_           [][]byte            `asn1:"-" json:"-"`
}

// VersionInfo represents the ASN.1 type VersionInfo (OCTET_STRING).
type VersionInfo = []byte

// FraudInfo represents the ASN.1 type FraudInfo (SEQUENCE).
type FraudInfo struct {
	Moc         *FraudData `asn1:"tag:0,context,implicit,optional" json:"Moc,omitempty"`
	Cf          *FraudData `asn1:"tag:1,context,implicit,optional" json:"Cf,omitempty"`
	Ct          *FraudData `asn1:"tag:2,context,implicit,optional" json:"Ct,omitempty"`
	ExtCount_   int64      `asn1:"-" json:"-"`
	ExtPresent_ []bool     `asn1:"-" json:"-"`
	ExtData_    [][]byte   `asn1:"-" json:"-"`
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
}

// TimeLimit represents the ASN.1 type TimeLimit (INTEGER).
type TimeLimit = int64

// ActionType represents the ASN.1 type ActionType (OCTET_STRING).
type ActionType = []byte

// FraudMaxCount represents the ASN.1 type FraudMaxCount (INTEGER).
type FraudMaxCount = int64

// ServiceWithInfo represents the ASN.1 type ServiceWithInfo (SEQUENCE).
type ServiceWithInfo struct {
	ServiceCode *MAPserviceCode `asn1:"tag:0,context,implicit,optional" json:"ServiceCode,omitempty"`
	VersionInfo *VersionInfo    `asn1:"tag:1,context,implicit,optional" json:"VersionInfo,omitempty"`
	InKey       *INKey          `asn1:",optional" json:"InKey,omitempty"`
	FraudInfo   *FraudInfo      `asn1:",optional" json:"FraudInfo,omitempty"`
	ExtCount_   int64           `asn1:"-" json:"-"`
	ExtPresent_ []bool          `asn1:"-" json:"-"`
	ExtData_    [][]byte        `asn1:"-" json:"-"`
}

// ServiceListWithInfo represents the ASN.1 type ServiceListWithInfo (SEQUENCE_OF).
type ServiceListWithInfo = []ServiceWithInfo

// INKey choice constants.
const (
	INKeyChoiceMobileINKey = 1
	INKeyChoiceSmsINKey    = 2
)

// INKey represents the ASN.1 CHOICE type INKey.
type INKey struct {
	Choice      int
	MobileINKey *MKey   `json:"MobileINKey,omitempty"`
	SmsINKey    *SMSKey `json:"SmsINKey,omitempty"`
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
	MmScfAddress *ISDNAddressString4   `asn1:"tag:1,context,implicit,optional" json:"MmScfAddress,omitempty"`
	MmTdpName    *MmTdpName            `asn1:"tag:2,context,implicit,optional" json:"MmTdpName,omitempty"`
	ServiceKey   *ExtensionsServiceKey `asn1:"tag:3,context,implicit,optional" json:"ServiceKey,omitempty"`
	LocupType    *LocupType            `asn1:"tag:4,context,implicit,optional" json:"LocupType,omitempty"`
	ExtCount_    int64                 `asn1:"-" json:"-"`
	ExtPresent_  []bool                `asn1:"-" json:"-"`
	ExtData_     [][]byte              `asn1:"-" json:"-"`
}

// SmsTdpName represents the ASN.1 type SmsTdpName (OCTET_STRING).
type SmsTdpName = []byte

// SMSKey represents the ASN.1 type SMSKey (SEQUENCE).
type SMSKey struct {
	MmSCPAddress *ISDNAddressString4   `asn1:"tag:0,context,implicit,optional" json:"MmSCPAddress,omitempty"`
	SmsTdpName   *SmsTdpName           `asn1:"tag:1,context,implicit,optional" json:"SmsTdpName,omitempty"`
	ServiceKey   *ExtensionsServiceKey `asn1:"tag:2,context,implicit,optional" json:"ServiceKey,omitempty"`
	MmsFlag      *struct{}             `asn1:"tag:3,context,implicit,optional" json:"MmsFlag,omitempty"`
	ExtCount_    int64                 `asn1:"-" json:"-"`
	ExtPresent_  []bool                `asn1:"-" json:"-"`
	ExtData_     [][]byte              `asn1:"-" json:"-"`
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
	CellId          *CellGlobalIdOrServiceAreaIdFixedLength4 `asn1:"tag:1,context,implicit,optional" json:"CellId,omitempty"`
	SaiPresent      *struct{}                                `asn1:"tag:2,context,implicit,optional" json:"SaiPresent,omitempty"`
	ExtCount_       int64                                    `asn1:"-" json:"-"`
	ExtPresent_     []bool                                   `asn1:"-" json:"-"`
	ExtData_        [][]byte                                 `asn1:"-" json:"-"`
}

// HOExt represents the ASN.1 type HO-Ext (SEQUENCE).
type HOExt struct {
	MapOpt          *MapOptFields  `asn1:"tag:0,context,implicit,optional" json:"MapOpt,omitempty"`
	CodecList       CodecListExt   `asn1:"tag:1,context,implicit,optional" json:"CodecList,omitempty"`
	CodecListIndef_ bool           `asn1:"-" json:"-"`
	SelectedCodec   *SelectedCodec `asn1:"tag:2,context,implicit,optional" json:"SelectedCodec,omitempty"`
	UmaAccess       *struct{}      `asn1:"tag:3,context,implicit,optional" json:"UmaAccess,omitempty"`
	UmaIpAddress    []byte         `asn1:"tag:4,context,implicit,optional" json:"UmaIpAddress,omitempty"`
	UmaIpPortNb     *IPPortNb      `asn1:"tag:5,context,implicit,optional" json:"UmaIpPortNb,omitempty"`
	ExtCount_       int64          `asn1:"-" json:"-"`
	ExtPresent_     []bool         `asn1:"-" json:"-"`
	ExtData_        [][]byte       `asn1:"-" json:"-"`
}

// MapOptFields represents the ASN.1 type MapOptFields (OCTET_STRING).
type MapOptFields = []byte

// CodecListExt represents the ASN.1 type CodecListExt (SEQUENCE_OF).
type CodecListExt = []CodecExt

// CodecExt represents the ASN.1 type CodecExt (OCTET_STRING).
type CodecExt = []byte

// SelectedCodec represents the ASN.1 type SelectedCodec (SEQUENCE).
type SelectedCodec struct {
	Codec       CodecExt `asn1:"tag:0,context,implicit"`
	Modes       Modes    `asn1:"tag:1,context,implicit"`
	ExtCount_   int64    `asn1:"-" json:"-"`
	ExtPresent_ []bool   `asn1:"-" json:"-"`
	ExtData_    [][]byte `asn1:"-" json:"-"`
}

// Modes represents the ASN.1 type Modes (OCTET_STRING).
type Modes = []byte

// IPPortNb represents the ASN.1 type IPPortNb (INTEGER).
type IPPortNb = int64

// AbsentSubscriberExt represents the ASN.1 type AbsentSubscriberExt (SEQUENCE).
type AbsentSubscriberExt struct {
	OlcmInfoTable       OlcmInfoTable `asn1:"tag:0,context,implicit,optional" json:"OlcmInfoTable,omitempty"`
	OlcmInfoTableIndef_ bool          `asn1:"-" json:"-"`
	Imsi                *IMSI4        `asn1:"tag:1,context,implicit,optional" json:"Imsi,omitempty"`
	ExtCount_           int64         `asn1:"-" json:"-"`
	ExtPresent_         []bool        `asn1:"-" json:"-"`
	ExtData_            [][]byte      `asn1:"-" json:"-"`
}

// ErrOlcmInfoTableExt represents the ASN.1 type ErrOlcmInfoTableExt (SEQUENCE).
type ErrOlcmInfoTableExt struct {
	OlcmInfoTable       OlcmInfoTable `asn1:"tag:0,context,implicit,optional" json:"OlcmInfoTable,omitempty"`
	OlcmInfoTableIndef_ bool          `asn1:"-" json:"-"`
	Imsi                *IMSI4        `asn1:"tag:1,context,implicit,optional" json:"Imsi,omitempty"`
	ExtCount_           int64         `asn1:"-" json:"-"`
	ExtPresent_         []bool        `asn1:"-" json:"-"`
	ExtData_            [][]byte      `asn1:"-" json:"-"`
}

// RoutingCategoryExt represents the ASN.1 type RoutingCategoryExt (SEQUENCE).
type RoutingCategoryExt struct {
	RoutingCategory    *RoutingCategory    `asn1:"tag:0,context,implicit,optional" json:"RoutingCategory,omitempty"`
	ExtRoutingCategory *ExtRoutingCategory `asn1:"tag:1,context,implicit,optional" json:"ExtRoutingCategory,omitempty"`
	ExtCount_          int64               `asn1:"-" json:"-"`
	ExtPresent_        []bool              `asn1:"-" json:"-"`
	ExtData_           [][]byte            `asn1:"-" json:"-"`
}

// SriForSMArgExt represents the ASN.1 type SriForSMArgExt (SEQUENCE).
type SriForSMArgExt struct {
	CfuSMSCounter     *CfuSMSCounter `asn1:"tag:0,context,implicit,optional" json:"CfuSMSCounter,omitempty"`
	Cfusmcfo          *struct{}      `asn1:"tag:2,context,implicit,optional" json:"Cfusmcfo,omitempty"`
	MemberInterrogate *struct{}      `asn1:"tag:3,context,implicit,optional" json:"MemberInterrogate,omitempty"`
	ExtCount_         int64          `asn1:"-" json:"-"`
	ExtPresent_       []bool         `asn1:"-" json:"-"`
	ExtData_          [][]byte       `asn1:"-" json:"-"`
}

// ReportSMDelStatArgExt represents the ASN.1 type ReportSMDelStatArgExt (SEQUENCE).
type ReportSMDelStatArgExt struct {
	CfuSMSCounter *CfuSMSCounter `asn1:"tag:0,context,implicit,optional" json:"CfuSMSCounter,omitempty"`
	Cfusmcfo      *struct{}      `asn1:"tag:2,context,implicit,optional" json:"Cfusmcfo,omitempty"`
	ExtCount_     int64          `asn1:"-" json:"-"`
	ExtPresent_   []bool         `asn1:"-" json:"-"`
	ExtData_      [][]byte       `asn1:"-" json:"-"`
}

// CfuSMSCounter represents the ASN.1 type CfuSMSCounter (OCTET_STRING).
type CfuSMSCounter = []byte

// MOForwardSMArgExt represents the ASN.1 type MO-ForwardSM-ArgExt (SEQUENCE).
type MOForwardSMArgExt struct {
	LocationAreaCode *LocationAreaCode                        `asn1:"tag:0,context,implicit,optional" json:"LocationAreaCode,omitempty"`
	CellId           *CellGlobalIdOrServiceAreaIdFixedLength4 `asn1:"tag:1,context,implicit,optional" json:"CellId,omitempty"`
	ExtCount_        int64                                    `asn1:"-" json:"-"`
	ExtPresent_      []bool                                   `asn1:"-" json:"-"`
	ExtData_         [][]byte                                 `asn1:"-" json:"-"`
}

// LocationAreaCode represents the ASN.1 type LocationAreaCode (OCTET_STRING).
type LocationAreaCode = []byte

// UdlArgExt represents the ASN.1 type UdlArgExt (SEQUENCE).
type UdlArgExt struct {
	Lai         *LAIFixedLength4 `asn1:"tag:0,context,implicit,optional" json:"Lai,omitempty"`
	SendImmResp *struct{}        `asn1:"tag:1,context,implicit,optional" json:"SendImmResp,omitempty"`
	ExtCount_   int64            `asn1:"-" json:"-"`
	ExtPresent_ []bool           `asn1:"-" json:"-"`
	ExtData_    [][]byte         `asn1:"-" json:"-"`
}

// RoamNotAllowedExt represents the ASN.1 type RoamNotAllowedExt (SEQUENCE).
type RoamNotAllowedExt struct {
	RejectCause []byte   `asn1:"tag:0,context,implicit,optional" json:"RejectCause,omitempty"`
	ExtCount_   int64    `asn1:"-" json:"-"`
	ExtPresent_ []bool   `asn1:"-" json:"-"`
	ExtData_    [][]byte `asn1:"-" json:"-"`
}

// AnyTimeModArgExt represents the ASN.1 type AnyTimeModArgExt (SEQUENCE).
type AnyTimeModArgExt struct {
	SenderMSISDN *ISDNAddressString4 `asn1:"tag:0,context,implicit,optional" json:"SenderMSISDN,omitempty"`
	ExtCount_    int64               `asn1:"-" json:"-"`
	ExtPresent_  []bool              `asn1:"-" json:"-"`
	ExtData_     [][]byte            `asn1:"-" json:"-"`
}

// CosInfo represents the ASN.1 type CosInfo (SEQUENCE).
type CosInfo struct {
	SsCode               *SSCode5       `asn1:",optional" json:"SsCode,omitempty"`
	CosFeatureList       COSFeatureList `asn1:""`
	CosFeatureListIndef_ bool           `asn1:"-" json:"-"`
}

// COSFeatureList represents the ASN.1 type COS-FeatureList (SEQUENCE_OF).
type COSFeatureList = []COSFeature

// COSFeature represents the ASN.1 type COS-Feature (SEQUENCE).
type COSFeature struct {
	BasicServiceCode *BasicServiceCode4 `asn1:",optional" json:"BasicServiceCode,omitempty"`
	SsStatus         SSStatus5          `asn1:"tag:4,context,implicit"`
	CustomerGroupID  *CustomerGroupID   `asn1:"tag:5,context,implicit,optional" json:"CustomerGroupID,omitempty"`
	SubGroupID       *SubGroupID        `asn1:"tag:6,context,implicit,optional" json:"SubGroupID,omitempty"`
	ClassOfServiceID *ClassOfServiceID  `asn1:"tag:7,context,implicit,optional" json:"ClassOfServiceID,omitempty"`
}

// CustomerGroupID represents the ASN.1 type CustomerGroupID (BIT_STRING).
type CustomerGroupID = runtime.BitString

// SubGroupID represents the ASN.1 type SubGroupID (BIT_STRING).
type SubGroupID = runtime.BitString

// ClassOfServiceID represents the ASN.1 type ClassOfServiceID (BIT_STRING).
type ClassOfServiceID = runtime.BitString

// AccessTypeExt represents the ASN.1 type AccessTypeExt (SEQUENCE).
type AccessTypeExt struct {
	Access      Access   `asn1:""`
	Version     Version  `asn1:""`
	ExtCount_   int64    `asn1:"-" json:"-"`
	ExtPresent_ []bool   `asn1:"-" json:"-"`
	ExtData_    [][]byte `asn1:"-" json:"-"`
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
type AccessSubscriptionListExt = []Access

// AllowedServiceData represents the ASN.1 type AllowedServiceData (BIT_STRING).
type AllowedServiceData = runtime.BitString

// AnyTimePOBarringArg represents the ASN.1 type AnyTimePO-BarringArg (SEQUENCE).
type AnyTimePOBarringArg struct {
	SubscriberIdentity SubscriberIdentity4 `asn1:"tag:0,context,explicit"`
	GsmSCFAddress      ISDNAddressString4  `asn1:"tag:3,context,implicit"`
	GprsBarring        GprsBarring         `asn1:""`
	ExtCount_          int64               `asn1:"-" json:"-"`
	ExtPresent_        []bool              `asn1:"-" json:"-"`
	ExtData_           [][]byte            `asn1:"-" json:"-"`
}

// AnyTimePOBarringRes represents the ASN.1 type AnyTimePO-BarringRes (SEQUENCE).
type AnyTimePOBarringRes struct {
	ExtCount_   int64    `asn1:"-" json:"-"`
	ExtPresent_ []bool   `asn1:"-" json:"-"`
	ExtData_    [][]byte `asn1:"-" json:"-"`
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
func (v *IsdArgExt) MarshalBER() ([]byte, error) {
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
		enc_routingcategory := ber.EncodeOctetString([]byte(*v.RoutingCategory))
		retagged_enc_routingcategory, tagErr_enc_routingcategory := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_routingcategory)
		if tagErr_enc_routingcategory != nil {
			return nil, fmt.Errorf("encoding routingCategory: %w", tagErr_enc_routingcategory)
		}
		enc_routingcategory = retagged_enc_routingcategory
		children = append(children, enc_routingcategory...)
	}
	if v.ServiceList != nil {
		enc_servicelist := ber.EncodeOctetString([]byte(*v.ServiceList))
		retagged_enc_servicelist, tagErr_enc_servicelist := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_servicelist)
		if tagErr_enc_servicelist != nil {
			return nil, fmt.Errorf("encoding serviceList: %w", tagErr_enc_servicelist)
		}
		enc_servicelist = retagged_enc_servicelist
		children = append(children, enc_servicelist...)
	}
	if v.ServInfoList != nil {
		enc_servinfolist, err := MarshalBERServiceListWithInfo(v.ServInfoList)
		if err != nil {
			return nil, fmt.Errorf("encoding serv-info-list: %w", err)
		}
		if v.ServInfoListIndef_ {
			// Strip the outer SEQUENCE tag from marshalBER output to get raw children.
			_, _, seqContent_, tlvErr_ := ber.DecodeTLV(enc_servinfolist)
			if tlvErr_ != nil {
				return nil, tlvErr_
			}
			enc_servinfolist = ber.EncodeConstructedIndefinite(tag.Tag{Class: tag.ClassContextSpecific, Number: 3}, seqContent_)
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
		enc_extroutingcategory := ber.EncodeInteger(int64(*v.ExtRoutingCategory))
		retagged_enc_extroutingcategory, tagErr_enc_extroutingcategory := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 5, enc_extroutingcategory)
		if tagErr_enc_extroutingcategory != nil {
			return nil, fmt.Errorf("encoding extRoutingCategory: %w", tagErr_enc_extroutingcategory)
		}
		enc_extroutingcategory = retagged_enc_extroutingcategory
		children = append(children, enc_extroutingcategory...)
	}
	if v.OwnMSISDN != nil {
		enc_ownmsisdn := ber.EncodeOctetString([]byte(*v.OwnMSISDN))
		retagged_enc_ownmsisdn, tagErr_enc_ownmsisdn := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 6, enc_ownmsisdn)
		if tagErr_enc_ownmsisdn != nil {
			return nil, fmt.Errorf("encoding ownMSISDN: %w", tagErr_enc_ownmsisdn)
		}
		enc_ownmsisdn = retagged_enc_ownmsisdn
		children = append(children, enc_ownmsisdn...)
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
	return ber.EncodeConstructed(tag.Tag{Class: tag.ClassPrivate, Number: 0, Constructed: true}, children), nil
}

// MarshalDER encodes IsdArgExt to DER format.
func (v *IsdArgExt) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// ITU-T X.690 (02/2021) Section 10.1 requires DER length forms to be definite.
	derValue := *v
	derValue.ServInfoListIndef_ = false
	v = &derValue
	encoded, err := v.MarshalBER()
	if err != nil {
		return nil, err
	}
	if err := ber.ValidateDERElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding IsdArgExt as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes IsdArgExt from BER/DER format.
func (v *IsdArgExt) UnmarshalBER(data []byte) error {
	decodedTag, content, total, err := ber.DecodeConstructedContent(data)
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
				decodedTag_alslineindicator, n_alslineindicator, rawVal_alslineindicator, err := ber.DecodeTLV(content[offset:])
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
				offset += n_alslineindicator
			}
		}
	}
	// Decode routingCategory
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
				decodedTag_routingcategory, n_routingcategory, rawVal_routingcategory, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding routingCategory: %w", err)
				}
				if decodedTag_routingcategory.Class != tag.ClassContextSpecific || decodedTag_routingcategory.Number != 1 {
					return fmt.Errorf("decoding routingCategory: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_routingcategory)
				}
				tmp_routingcategory := RoutingCategory(rawVal_routingcategory)
				v.RoutingCategory = &tmp_routingcategory
				offset += n_routingcategory
			}
		}
	}
	// Decode serviceList
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2 {
				decodedTag_servicelist, n_servicelist, rawVal_servicelist, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding serviceList: %w", err)
				}
				if decodedTag_servicelist.Class != tag.ClassContextSpecific || decodedTag_servicelist.Number != 2 {
					return fmt.Errorf("decoding serviceList: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_servicelist)
				}
				tmp_servicelist := MAPserviceList(rawVal_servicelist)
				v.ServiceList = &tmp_servicelist
				offset += n_servicelist
			}
		}
	}
	// Decode serv-info-list
	v.ServInfoListIndef_ = false
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3 {
				decodedTag_servinfolist, n_servinfolist, rawVal_servinfolist, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding serv-info-list: %w", err)
				}
				if decodedTag_servinfolist.Class != tag.ClassContextSpecific || decodedTag_servinfolist.Number != 3 || decodedTag_servinfolist.Constructed != true {
					return fmt.Errorf("decoding serv-info-list: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_servinfolist)
				}
				reconstructed_servinfolist := ber.EncodeSequence(rawVal_servinfolist)
				dec_servinfolist, unmErr := UnmarshalBERServiceListWithInfo(reconstructed_servinfolist)
				if unmErr != nil {
					return fmt.Errorf("decoding serv-info-list: %w", unmErr)
				}
				v.ServInfoList = dec_servinfolist
				{
					_, tagSz_, _ := ber.DecodeTag(content[offset:])
					if offset+tagSz_ < len(content) && content[offset+tagSz_] == 0x80 {
						v.ServInfoListIndef_ = true
					}
				}
				offset += n_servinfolist
			}
		}
	}
	// Decode extRoutingCategory
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 5 {
				decodedTag_extroutingcategory, n_extroutingcategory, rawVal_extroutingcategory, err := ber.DecodeTLV(content[offset:])
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
				offset += n_extroutingcategory
			}
		}
	}
	// Decode ownMSISDN
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 6 {
				decodedTag_ownmsisdn, n_ownmsisdn, rawVal_ownmsisdn, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding ownMSISDN: %w", err)
				}
				if decodedTag_ownmsisdn.Class != tag.ClassContextSpecific || decodedTag_ownmsisdn.Number != 6 {
					return fmt.Errorf("decoding ownMSISDN: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_ownmsisdn)
				}
				tmp_ownmsisdn := ISDNAddressString4(rawVal_ownmsisdn)
				v.OwnMSISDN = &tmp_ownmsisdn
				offset += n_ownmsisdn
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "IsdArgExt", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes DsdArgExt to BER format.
func (v *DsdArgExt) MarshalBER() ([]byte, error) {
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
		enc_servicelist := ber.EncodeOctetString([]byte(*v.ServiceList))
		retagged_enc_servicelist, tagErr_enc_servicelist := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_servicelist)
		if tagErr_enc_servicelist != nil {
			return nil, fmt.Errorf("encoding serviceList: %w", tagErr_enc_servicelist)
		}
		enc_servicelist = retagged_enc_servicelist
		children = append(children, enc_servicelist...)
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
	return ber.EncodeConstructed(tag.Tag{Class: tag.ClassPrivate, Number: 0, Constructed: true}, children), nil
}

// MarshalDER encodes DsdArgExt to DER format.
func (v *DsdArgExt) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	encoded, err := v.MarshalBER()
	if err != nil {
		return nil, err
	}
	if err := ber.ValidateDERElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding DsdArgExt as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes DsdArgExt from BER/DER format.
func (v *DsdArgExt) UnmarshalBER(data []byte) error {
	decodedTag, content, total, err := ber.DecodeConstructedContent(data)
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
				decodedTag_alslineindicator, n_alslineindicator, rawVal_alslineindicator, err := ber.DecodeTLV(content[offset:])
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
				offset += n_alslineindicator
			}
		}
	}
	// Decode serviceList
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
				decodedTag_servicelist, n_servicelist, rawVal_servicelist, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding serviceList: %w", err)
				}
				if decodedTag_servicelist.Class != tag.ClassContextSpecific || decodedTag_servicelist.Number != 1 {
					return fmt.Errorf("decoding serviceList: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_servicelist)
				}
				tmp_servicelist := MAPserviceList(rawVal_servicelist)
				v.ServiceList = &tmp_servicelist
				offset += n_servicelist
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "DsdArgExt", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes UlResExt to BER format.
func (v *UlResExt) MarshalBER() ([]byte, error) {
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
		_, n, _, extErr := ber.DecodeTLV(ext)
		if extErr != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, extErr)
		}
		if n != len(ext) {
			return nil, fmt.Errorf("encoding extension %d: %w", i, ber.ErrExtraData)
		}
		children = append(children, ext...)
	}
	return ber.EncodeConstructed(tag.Tag{Class: tag.ClassPrivate, Number: 0, Constructed: true}, children), nil
}

// MarshalDER encodes UlResExt to DER format.
func (v *UlResExt) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	encoded, err := v.MarshalBER()
	if err != nil {
		return nil, err
	}
	if err := ber.ValidateDERElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding UlResExt as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes UlResExt from BER/DER format.
func (v *UlResExt) UnmarshalBER(data []byte) error {
	decodedTag, content, total, err := ber.DecodeConstructedContent(data)
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
				decodedTag_mwdset, n_mwdset, rawVal_mwdset, err := ber.DecodeTLV(content[offset:])
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
				offset += n_mwdset
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "UlResExt", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes SSDataEmoInExt to BER format.
func (v *SSDataEmoInExt) MarshalBER() ([]byte, error) {
	var children []byte
	if v.EmoInCategoryKey != nil {
		enc_emoincategorykey := ber.EncodeOctetString([]byte(*v.EmoInCategoryKey))
		retagged_enc_emoincategorykey, tagErr_enc_emoincategorykey := ber.EncodeImplicitTagWithClass(tag.ClassPrivate, 2, enc_emoincategorykey)
		if tagErr_enc_emoincategorykey != nil {
			return nil, fmt.Errorf("encoding emoInCategoryKey: %w", tagErr_enc_emoincategorykey)
		}
		enc_emoincategorykey = retagged_enc_emoincategorykey
		children = append(children, enc_emoincategorykey...)
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
	return ber.EncodeConstructed(tag.Tag{Class: tag.ClassPrivate, Number: 1, Constructed: true}, children), nil
}

// MarshalDER encodes SSDataEmoInExt to DER format.
func (v *SSDataEmoInExt) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	encoded, err := v.MarshalBER()
	if err != nil {
		return nil, err
	}
	if err := ber.ValidateDERElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding SSDataEmoInExt as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes SSDataEmoInExt from BER/DER format.
func (v *SSDataEmoInExt) UnmarshalBER(data []byte) error {
	decodedTag, content, total, err := ber.DecodeConstructedContent(data)
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
				decodedTag_emoincategorykey, n_emoincategorykey, rawVal_emoincategorykey, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding emoInCategoryKey: %w", err)
				}
				if decodedTag_emoincategorykey.Class != tag.ClassPrivate || decodedTag_emoincategorykey.Number != 2 {
					return fmt.Errorf("decoding emoInCategoryKey: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_emoincategorykey)
				}
				tmp_emoincategorykey := EmoInCategoryKey(rawVal_emoincategorykey)
				v.EmoInCategoryKey = &tmp_emoincategorykey
				offset += n_emoincategorykey
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "SSDataEmoInExt", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBERChargingAreaList encodes a ChargingAreaList list to BER.
func MarshalBERChargingAreaList(list ChargingAreaList) ([]byte, error) {
	var children []byte
	for _, elem := range list {
		children = append(children, ber.EncodeInteger(int64(elem))...)
	}
	return ber.EncodeSequence(children), nil
}

// UnmarshalBERChargingAreaList decodes a ChargingAreaList list from BER.
func UnmarshalBERChargingAreaList(data []byte) (ChargingAreaList, error) {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return nil, fmt.Errorf("decoding ChargingAreaList: %w", err)
	}
	if total != len(data) {
		return nil, &ber.DecodeError{Offset: total, TypeName: "ChargingAreaList", Cause: ber.ErrExtraData}
	}
	var result ChargingAreaList
	offset := 0
	for offset < len(content) {
		val, n, intErr := ber.DecodeInteger(content[offset:])
		if intErr != nil {
			return nil, fmt.Errorf("decoding element: %w", intErr)
		}
		result = append(result, ChargingArea(val))
		offset += n
	}
	return result, nil
}

// MarshalBER encodes RegionalChargingData to BER format.
func (v *RegionalChargingData) MarshalBER() ([]byte, error) {
	var children []byte
	if v.ChargingAreaList != nil {
		enc_chargingarealist, err := MarshalBERChargingAreaList(v.ChargingAreaList)
		if err != nil {
			return nil, fmt.Errorf("encoding chargingAreaList: %w", err)
		}
		if v.ChargingAreaListIndef_ {
			// Strip the outer SEQUENCE tag from marshalBER output to get raw children.
			_, _, seqContent_, tlvErr_ := ber.DecodeTLV(enc_chargingarealist)
			if tlvErr_ != nil {
				return nil, tlvErr_
			}
			enc_chargingarealist = ber.EncodeConstructedIndefinite(tag.Tag{Class: tag.ClassContextSpecific, Number: 0}, seqContent_)
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

// MarshalDER encodes RegionalChargingData to DER format.
func (v *RegionalChargingData) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// ITU-T X.690 (02/2021) Section 10.1 requires DER length forms to be definite.
	derValue := *v
	derValue.ChargingAreaListIndef_ = false
	v = &derValue
	encoded, err := v.MarshalBER()
	if err != nil {
		return nil, err
	}
	if err := ber.ValidateDERElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding RegionalChargingData as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes RegionalChargingData from BER/DER format.
func (v *RegionalChargingData) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
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
				decodedTag_chargingarealist, n_chargingarealist, rawVal_chargingarealist, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding chargingAreaList: %w", err)
				}
				if decodedTag_chargingarealist.Class != tag.ClassContextSpecific || decodedTag_chargingarealist.Number != 0 || decodedTag_chargingarealist.Constructed != true {
					return fmt.Errorf("decoding chargingAreaList: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_chargingarealist)
				}
				reconstructed_chargingarealist := ber.EncodeSequence(rawVal_chargingarealist)
				dec_chargingarealist, unmErr := UnmarshalBERChargingAreaList(reconstructed_chargingarealist)
				if unmErr != nil {
					return fmt.Errorf("decoding chargingAreaList: %w", unmErr)
				}
				v.ChargingAreaList = dec_chargingarealist
				{
					_, tagSz_, _ := ber.DecodeTag(content[offset:])
					if offset+tagSz_ < len(content) && content[offset+tagSz_] == 0x80 {
						v.ChargingAreaListIndef_ = true
					}
				}
				offset += n_chargingarealist
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "RegionalChargingData", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes SSDataExtension to BER format.
func (v *SSDataExtension) MarshalBER() ([]byte, error) {
	var children []byte
	if v.InTriggerKey != nil {
		enc_intriggerkey := ber.EncodeInteger(int64(*v.InTriggerKey))
		retagged_enc_intriggerkey, tagErr_enc_intriggerkey := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_intriggerkey)
		if tagErr_enc_intriggerkey != nil {
			return nil, fmt.Errorf("encoding inTriggerKey: %w", tagErr_enc_intriggerkey)
		}
		enc_intriggerkey = retagged_enc_intriggerkey
		children = append(children, enc_intriggerkey...)
	}
	if v.PnpIndex != nil {
		enc_pnpindex := ber.EncodeOctetString([]byte(*v.PnpIndex))
		retagged_enc_pnpindex, tagErr_enc_pnpindex := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_pnpindex)
		if tagErr_enc_pnpindex != nil {
			return nil, fmt.Errorf("encoding pnpIndex: %w", tagErr_enc_pnpindex)
		}
		enc_pnpindex = retagged_enc_pnpindex
		children = append(children, enc_pnpindex...)
	}
	if v.CallRedirectionIndex != nil {
		enc_callredirectionindex := ber.EncodeInteger(int64(*v.CallRedirectionIndex))
		retagged_enc_callredirectionindex, tagErr_enc_callredirectionindex := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_callredirectionindex)
		if tagErr_enc_callredirectionindex != nil {
			return nil, fmt.Errorf("encoding callRedirectionIndex: %w", tagErr_enc_callredirectionindex)
		}
		enc_callredirectionindex = retagged_enc_callredirectionindex
		children = append(children, enc_callredirectionindex...)
	}
	if v.RegionalChargingData != nil {
		enc_regionalchargingdata, err := v.RegionalChargingData.MarshalBER()
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
		_, n, _, extErr := ber.DecodeTLV(ext)
		if extErr != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, extErr)
		}
		if n != len(ext) {
			return nil, fmt.Errorf("encoding extension %d: %w", i, ber.ErrExtraData)
		}
		children = append(children, ext...)
	}
	return ber.EncodeConstructed(tag.Tag{Class: tag.ClassPrivate, Number: 0, Constructed: true}, children), nil
}

// MarshalDER encodes SSDataExtension to DER format.
func (v *SSDataExtension) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	encoded, err := v.MarshalBER()
	if err != nil {
		return nil, err
	}
	if err := ber.ValidateDERElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding SSDataExtension as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes SSDataExtension from BER/DER format.
func (v *SSDataExtension) UnmarshalBER(data []byte) error {
	decodedTag, content, total, err := ber.DecodeConstructedContent(data)
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
				decodedTag_intriggerkey, n_intriggerkey, rawVal_intriggerkey, err := ber.DecodeTLV(content[offset:])
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
				offset += n_intriggerkey
			}
		}
	}
	// Decode pnpIndex
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
				decodedTag_pnpindex, n_pnpindex, rawVal_pnpindex, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding pnpIndex: %w", err)
				}
				if decodedTag_pnpindex.Class != tag.ClassContextSpecific || decodedTag_pnpindex.Number != 1 {
					return fmt.Errorf("decoding pnpIndex: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_pnpindex)
				}
				tmp_pnpindex := PnpIndex(rawVal_pnpindex)
				v.PnpIndex = &tmp_pnpindex
				offset += n_pnpindex
			}
		}
	}
	// Decode callRedirectionIndex
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2 {
				decodedTag_callredirectionindex, n_callredirectionindex, rawVal_callredirectionindex, err := ber.DecodeTLV(content[offset:])
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
				offset += n_callredirectionindex
			}
		}
	}
	// Decode regionalChargingData
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3 {
				decodedTag_regionalchargingdata, n_regionalchargingdata, rawVal_regionalchargingdata, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding regionalChargingData: %w", err)
				}
				if decodedTag_regionalchargingdata.Class != tag.ClassContextSpecific || decodedTag_regionalchargingdata.Number != 3 || decodedTag_regionalchargingdata.Constructed != true {
					return fmt.Errorf("decoding regionalChargingData: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_regionalchargingdata)
				}
				reconstructed_regionalchargingdata := ber.EncodeSequence(rawVal_regionalchargingdata)
				var dec_regionalchargingdata RegionalChargingData
				if unmErr := dec_regionalchargingdata.UnmarshalBER(reconstructed_regionalchargingdata); unmErr != nil {
					return fmt.Errorf("decoding regionalChargingData: %w", unmErr)
				}
				v.RegionalChargingData = &dec_regionalchargingdata
				offset += n_regionalchargingdata
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "SSDataExtension", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes SriExtension to BER format.
func (v *SriExtension) MarshalBER() ([]byte, error) {
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
		enc_callingcategory := ber.EncodeOctetString([]byte(*v.CallingCategory))
		retagged_enc_callingcategory, tagErr_enc_callingcategory := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_callingcategory)
		if tagErr_enc_callingcategory != nil {
			return nil, fmt.Errorf("encoding callingCategory: %w", tagErr_enc_callingcategory)
		}
		enc_callingcategory = retagged_enc_callingcategory
		children = append(children, enc_callingcategory...)
	}
	if v.InternalServiceIndicator != nil {
		enc_internalserviceindicator := ber.EncodeOctetString([]byte(*v.InternalServiceIndicator))
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
		_, n, _, extErr := ber.DecodeTLV(ext)
		if extErr != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, extErr)
		}
		if n != len(ext) {
			return nil, fmt.Errorf("encoding extension %d: %w", i, ber.ErrExtraData)
		}
		children = append(children, ext...)
	}
	return ber.EncodeConstructed(tag.Tag{Class: tag.ClassPrivate, Number: 0, Constructed: true}, children), nil
}

// MarshalDER encodes SriExtension to DER format.
func (v *SriExtension) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	encoded, err := v.MarshalBER()
	if err != nil {
		return nil, err
	}
	if err := ber.ValidateDERElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding SriExtension as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes SriExtension from BER/DER format.
func (v *SriExtension) UnmarshalBER(data []byte) error {
	decodedTag, content, total, err := ber.DecodeConstructedContent(data)
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
				decodedTag_callforwardingoverride, n_callforwardingoverride, rawVal_callforwardingoverride, err := ber.DecodeTLV(content[offset:])
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
				offset += n_callforwardingoverride
			}
		}
	}
	// Decode in-Capability
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
				decodedTag_incapability, n_incapability, rawVal_incapability, err := ber.DecodeTLV(content[offset:])
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
				offset += n_incapability
			}
		}
	}
	// Decode callingCategory
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2 {
				decodedTag_callingcategory, n_callingcategory, rawVal_callingcategory, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding callingCategory: %w", err)
				}
				if decodedTag_callingcategory.Class != tag.ClassContextSpecific || decodedTag_callingcategory.Number != 2 {
					return fmt.Errorf("decoding callingCategory: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_callingcategory)
				}
				tmp_callingcategory := CallingCategory(rawVal_callingcategory)
				v.CallingCategory = &tmp_callingcategory
				offset += n_callingcategory
			}
		}
	}
	// Decode internalServiceIndicator
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3 {
				decodedTag_internalserviceindicator, n_internalserviceindicator, rawVal_internalserviceindicator, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding internalServiceIndicator: %w", err)
				}
				if decodedTag_internalserviceindicator.Class != tag.ClassContextSpecific || decodedTag_internalserviceindicator.Number != 3 {
					return fmt.Errorf("decoding internalServiceIndicator: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_internalserviceindicator)
				}
				tmp_internalserviceindicator := InternalServiceIndicator(rawVal_internalserviceindicator)
				v.InternalServiceIndicator = &tmp_internalserviceindicator
				offset += n_internalserviceindicator
			}
		}
	}
	// Decode srbtSupportIndicator
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4 {
				decodedTag_srbtsupportindicator, n_srbtsupportindicator, rawVal_srbtsupportindicator, err := ber.DecodeTLV(content[offset:])
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
				offset += n_srbtsupportindicator
			}
		}
	}
	// Decode gmscSupportIndicator
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 5 {
				decodedTag_gmscsupportindicator, n_gmscsupportindicator, rawVal_gmscsupportindicator, err := ber.DecodeTLV(content[offset:])
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
				offset += n_gmscsupportindicator
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "SriExtension", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes ExtensionsExtraSignalInfo to BER format.
func (v *ExtensionsExtraSignalInfo) MarshalBER() ([]byte, error) {
	var children []byte
	enc_protocolid := ber.EncodeInteger(int64(v.ProtocolId))
	children = append(children, enc_protocolid...)
	enc_signalinfo := ber.EncodeOctetString([]byte(v.SignalInfo))
	children = append(children, enc_signalinfo...)
	return ber.EncodeConstructed(tag.Tag{Class: tag.ClassPrivate, Number: 1, Constructed: true}, children), nil
}

// MarshalDER encodes ExtensionsExtraSignalInfo to DER format.
func (v *ExtensionsExtraSignalInfo) MarshalDER() ([]byte, error) {
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	encoded, err := v.MarshalBER()
	if err != nil {
		return nil, err
	}
	if err := ber.ValidateDERElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding ExtensionsExtraSignalInfo as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes ExtensionsExtraSignalInfo from BER/DER format.
func (v *ExtensionsExtraSignalInfo) UnmarshalBER(data []byte) error {
	decodedTag, content, total, err := ber.DecodeConstructedContent(data)
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
	val_protocolid, n, err := ber.DecodeInteger(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding protocolId: %w", err)
	}
	v.ProtocolId = ExtensionsExtraProtocolId(val_protocolid)
	offset += n
	// Decode signalInfo
	if offset >= len(content) {
		return fmt.Errorf("missing required field signalInfo")
	}
	val_signalinfo, n, err := ber.DecodeOctetString(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding signalInfo: %w", err)
	}
	v.SignalInfo = SignalInfo4(val_signalinfo)
	offset += n
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "ExtensionsExtraSignalInfo", Cause: ber.ErrExtraData}
	}
	return nil
}

// MarshalBER encodes NokiaCUGData to BER format.
func (v *NokiaCUGData) MarshalBER() ([]byte, error) {
	var children []byte
	if v.CugInterlock != nil {
		enc_cuginterlock := ber.EncodeOctetString([]byte(*v.CugInterlock))
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
		enc_cugcallinfo := ber.EncodeOctetString([]byte(*v.CugCallInfo))
		retagged_enc_cugcallinfo, tagErr_enc_cugcallinfo := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_cugcallinfo)
		if tagErr_enc_cugcallinfo != nil {
			return nil, fmt.Errorf("encoding cug-CallInfo: %w", tagErr_enc_cugcallinfo)
		}
		enc_cugcallinfo = retagged_enc_cugcallinfo
		children = append(children, enc_cugcallinfo...)
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

// MarshalDER encodes NokiaCUGData to DER format.
func (v *NokiaCUGData) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	encoded, err := v.MarshalBER()
	if err != nil {
		return nil, err
	}
	if err := ber.ValidateDERElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding NokiaCUGData as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes NokiaCUGData from BER/DER format.
func (v *NokiaCUGData) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
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
				decodedTag_cuginterlock, n_cuginterlock, rawVal_cuginterlock, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding cug-Interlock: %w", err)
				}
				if decodedTag_cuginterlock.Class != tag.ClassContextSpecific || decodedTag_cuginterlock.Number != 0 {
					return fmt.Errorf("decoding cug-Interlock: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_cuginterlock)
				}
				tmp_cuginterlock := CUGInterlock4(rawVal_cuginterlock)
				v.CugInterlock = &tmp_cuginterlock
				offset += n_cuginterlock
			}
		}
	}
	// Decode cug-OutgoingAccess
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
				decodedTag_cugoutgoingaccess, n_cugoutgoingaccess, rawVal_cugoutgoingaccess, err := ber.DecodeTLV(content[offset:])
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
				if len(rawVal_cugoutgoingaccess) == 1 {
					v.CugOutgoingAccessRaw_ = rawVal_cugoutgoingaccess[0]
				}
				v.CugOutgoingAccess = &decVal_cugoutgoingaccess
				offset += n_cugoutgoingaccess
			}
		}
	}
	// Decode cug-CallInfo
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2 {
				decodedTag_cugcallinfo, n_cugcallinfo, rawVal_cugcallinfo, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding cug-CallInfo: %w", err)
				}
				if decodedTag_cugcallinfo.Class != tag.ClassContextSpecific || decodedTag_cugcallinfo.Number != 2 {
					return fmt.Errorf("decoding cug-CallInfo: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_cugcallinfo)
				}
				tmp_cugcallinfo := CUGCallInfo(rawVal_cugcallinfo)
				v.CugCallInfo = &tmp_cugcallinfo
				offset += n_cugcallinfo
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "NokiaCUGData", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes SriResExtension to BER format.
func (v *SriResExtension) MarshalBER() ([]byte, error) {
	var children []byte
	if v.InTriggerKey != nil {
		enc_intriggerkey := ber.EncodeInteger(int64(*v.InTriggerKey))
		retagged_enc_intriggerkey, tagErr_enc_intriggerkey := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_intriggerkey)
		if tagErr_enc_intriggerkey != nil {
			return nil, fmt.Errorf("encoding inTriggerKey: %w", tagErr_enc_intriggerkey)
		}
		enc_intriggerkey = retagged_enc_intriggerkey
		children = append(children, enc_intriggerkey...)
	}
	if v.VlrNumber != nil {
		enc_vlrnumber := ber.EncodeOctetString([]byte(*v.VlrNumber))
		retagged_enc_vlrnumber, tagErr_enc_vlrnumber := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_vlrnumber)
		if tagErr_enc_vlrnumber != nil {
			return nil, fmt.Errorf("encoding vlrNumber: %w", tagErr_enc_vlrnumber)
		}
		enc_vlrnumber = retagged_enc_vlrnumber
		children = append(children, enc_vlrnumber...)
	}
	if v.ActiveSs != nil {
		enc_activess := ber.EncodeOctetString([]byte(*v.ActiveSs))
		retagged_enc_activess, tagErr_enc_activess := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_activess)
		if tagErr_enc_activess != nil {
			return nil, fmt.Errorf("encoding activeSs: %w", tagErr_enc_activess)
		}
		enc_activess = retagged_enc_activess
		children = append(children, enc_activess...)
	}
	if v.TraceReference != nil {
		enc_tracereference := ber.EncodeOctetString([]byte(*v.TraceReference))
		retagged_enc_tracereference, tagErr_enc_tracereference := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, enc_tracereference)
		if tagErr_enc_tracereference != nil {
			return nil, fmt.Errorf("encoding traceReference: %w", tagErr_enc_tracereference)
		}
		enc_tracereference = retagged_enc_tracereference
		children = append(children, enc_tracereference...)
	}
	if v.TraceType != nil {
		enc_tracetype := ber.EncodeInteger(int64(*v.TraceType))
		retagged_enc_tracetype, tagErr_enc_tracetype := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, enc_tracetype)
		if tagErr_enc_tracetype != nil {
			return nil, fmt.Errorf("encoding traceType: %w", tagErr_enc_tracetype)
		}
		enc_tracetype = retagged_enc_tracetype
		children = append(children, enc_tracetype...)
	}
	if v.OmcId != nil {
		enc_omcid := ber.EncodeOctetString([]byte(*v.OmcId))
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
		enc_basicservice, err := v.BasicService.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding basicService: %w", err)
		}
		enc_basicservice = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 9, enc_basicservice)
		children = append(children, enc_basicservice...)
	}
	if v.Category != nil {
		enc_category := ber.EncodeOctetString([]byte(*v.Category))
		retagged_enc_category, tagErr_enc_category := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 10, enc_category)
		if tagErr_enc_category != nil {
			return nil, fmt.Errorf("encoding category: %w", tagErr_enc_category)
		}
		enc_category = retagged_enc_category
		children = append(children, enc_category...)
	}
	if v.RoutingCategory != nil {
		enc_routingcategory := ber.EncodeOctetString([]byte(*v.RoutingCategory))
		retagged_enc_routingcategory, tagErr_enc_routingcategory := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 11, enc_routingcategory)
		if tagErr_enc_routingcategory != nil {
			return nil, fmt.Errorf("encoding routingCategory: %w", tagErr_enc_routingcategory)
		}
		enc_routingcategory = retagged_enc_routingcategory
		children = append(children, enc_routingcategory...)
	}
	if v.PnpIndex != nil {
		enc_pnpindex := ber.EncodeOctetString([]byte(*v.PnpIndex))
		retagged_enc_pnpindex, tagErr_enc_pnpindex := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 12, enc_pnpindex)
		if tagErr_enc_pnpindex != nil {
			return nil, fmt.Errorf("encoding pnpIndex: %w", tagErr_enc_pnpindex)
		}
		enc_pnpindex = retagged_enc_pnpindex
		children = append(children, enc_pnpindex...)
	}
	if v.NokiaCUG != nil {
		enc_nokiacug, err := v.NokiaCUG.MarshalBER()
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
		enc_odbdata, err := v.OdbData.MarshalBER()
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
		enc_frauddata, err := v.FraudData.MarshalBER()
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
		enc_extroutingcategory := ber.EncodeInteger(int64(*v.ExtRoutingCategory))
		retagged_enc_extroutingcategory, tagErr_enc_extroutingcategory := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 17, enc_extroutingcategory)
		if tagErr_enc_extroutingcategory != nil {
			return nil, fmt.Errorf("encoding extRoutingCategory: %w", tagErr_enc_extroutingcategory)
		}
		enc_extroutingcategory = retagged_enc_extroutingcategory
		children = append(children, enc_extroutingcategory...)
	}
	if v.LeaId != nil {
		enc_leaid := ber.EncodeInteger(int64(*v.LeaId))
		retagged_enc_leaid, tagErr_enc_leaid := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 18, enc_leaid)
		if tagErr_enc_leaid != nil {
			return nil, fmt.Errorf("encoding leaId: %w", tagErr_enc_leaid)
		}
		enc_leaid = retagged_enc_leaid
		children = append(children, enc_leaid...)
	}
	if v.OlcmInfoTable != nil {
		enc_olcminfotable, err := MarshalBEROlcmInfoTable(v.OlcmInfoTable)
		if err != nil {
			return nil, fmt.Errorf("encoding olcmInfoTable: %w", err)
		}
		if v.OlcmInfoTableIndef_ {
			// Strip the outer SEQUENCE tag from marshalBER output to get raw children.
			_, _, seqContent_, tlvErr_ := ber.DecodeTLV(enc_olcminfotable)
			if tlvErr_ != nil {
				return nil, tlvErr_
			}
			enc_olcminfotable = ber.EncodeConstructedIndefinite(tag.Tag{Class: tag.ClassContextSpecific, Number: 19}, seqContent_)
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
		enc_callingcategory := ber.EncodeOctetString([]byte(*v.CallingCategory))
		retagged_enc_callingcategory, tagErr_enc_callingcategory := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 20, enc_callingcategory)
		if tagErr_enc_callingcategory != nil {
			return nil, fmt.Errorf("encoding callingCategory: %w", tagErr_enc_callingcategory)
		}
		enc_callingcategory = retagged_enc_callingcategory
		children = append(children, enc_callingcategory...)
	}
	if v.CommonMSISDN != nil {
		enc_commonmsisdn := ber.EncodeOctetString([]byte(*v.CommonMSISDN))
		retagged_enc_commonmsisdn, tagErr_enc_commonmsisdn := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 21, enc_commonmsisdn)
		if tagErr_enc_commonmsisdn != nil {
			return nil, fmt.Errorf("encoding commonMSISDN: %w", tagErr_enc_commonmsisdn)
		}
		enc_commonmsisdn = retagged_enc_commonmsisdn
		children = append(children, enc_commonmsisdn...)
	}
	if v.RgData != nil {
		enc_rgdata, err := v.RgData.MarshalBER()
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
		enc_olcmtracereference := ber.EncodeOctetString([]byte(*v.OlcmTraceReference))
		retagged_enc_olcmtracereference, tagErr_enc_olcmtracereference := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 23, enc_olcmtracereference)
		if tagErr_enc_olcmtracereference != nil {
			return nil, fmt.Errorf("encoding olcmTraceReference: %w", tagErr_enc_olcmtracereference)
		}
		enc_olcmtracereference = retagged_enc_olcmtracereference
		children = append(children, enc_olcmtracereference...)
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
	return ber.EncodeConstructed(tag.Tag{Class: tag.ClassPrivate, Number: 0, Constructed: true}, children), nil
}

// MarshalDER encodes SriResExtension to DER format.
func (v *SriResExtension) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// ITU-T X.690 (02/2021) Section 10.1 requires DER length forms to be definite.
	derValue := *v
	derValue.OlcmInfoTableIndef_ = false
	v = &derValue
	encoded, err := v.MarshalBER()
	if err != nil {
		return nil, err
	}
	if err := ber.ValidateDERElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding SriResExtension as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes SriResExtension from BER/DER format.
func (v *SriResExtension) UnmarshalBER(data []byte) error {
	decodedTag, content, total, err := ber.DecodeConstructedContent(data)
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
				decodedTag_intriggerkey, n_intriggerkey, rawVal_intriggerkey, err := ber.DecodeTLV(content[offset:])
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
				offset += n_intriggerkey
			}
		}
	}
	// Decode vlrNumber
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
				decodedTag_vlrnumber, n_vlrnumber, rawVal_vlrnumber, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding vlrNumber: %w", err)
				}
				if decodedTag_vlrnumber.Class != tag.ClassContextSpecific || decodedTag_vlrnumber.Number != 1 {
					return fmt.Errorf("decoding vlrNumber: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_vlrnumber)
				}
				tmp_vlrnumber := ISDNAddressString4(rawVal_vlrnumber)
				v.VlrNumber = &tmp_vlrnumber
				offset += n_vlrnumber
			}
		}
	}
	// Decode activeSs
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2 {
				decodedTag_activess, n_activess, rawVal_activess, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding activeSs: %w", err)
				}
				if decodedTag_activess.Class != tag.ClassContextSpecific || decodedTag_activess.Number != 2 {
					return fmt.Errorf("decoding activeSs: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_activess)
				}
				tmp_activess := ActiveSSList(rawVal_activess)
				v.ActiveSs = &tmp_activess
				offset += n_activess
			}
		}
	}
	// Decode traceReference
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3 {
				decodedTag_tracereference, n_tracereference, rawVal_tracereference, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding traceReference: %w", err)
				}
				if decodedTag_tracereference.Class != tag.ClassContextSpecific || decodedTag_tracereference.Number != 3 {
					return fmt.Errorf("decoding traceReference: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_tracereference)
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
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4 {
				decodedTag_tracetype, n_tracetype, rawVal_tracetype, err := ber.DecodeTLV(content[offset:])
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
				tmp_tracetype := TraceType4(decVal_tracetype)
				v.TraceType = &tmp_tracetype
				offset += n_tracetype
			}
		}
	}
	// Decode omc-Id
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 5 {
				decodedTag_omcid, n_omcid, rawVal_omcid, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding omc-Id: %w", err)
				}
				if decodedTag_omcid.Class != tag.ClassContextSpecific || decodedTag_omcid.Number != 5 {
					return fmt.Errorf("decoding omc-Id: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_omcid)
				}
				tmp_omcid := AddressString4(rawVal_omcid)
				v.OmcId = &tmp_omcid
				offset += n_omcid
			}
		}
	}
	// Decode hotBilling
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 6 {
				decodedTag_hotbilling, n_hotbilling, rawVal_hotbilling, err := ber.DecodeTLV(content[offset:])
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
				if len(rawVal_hotbilling) == 1 {
					v.HotBillingRaw_ = rawVal_hotbilling[0]
				}
				v.HotBilling = &decVal_hotbilling
				offset += n_hotbilling
			}
		}
	}
	// Decode cfoIsDone
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 7 {
				decodedTag_cfoisdone, n_cfoisdone, rawVal_cfoisdone, err := ber.DecodeTLV(content[offset:])
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
				if len(rawVal_cfoisdone) == 1 {
					v.CfoIsDoneRaw_ = rawVal_cfoisdone[0]
				}
				v.CfoIsDone = &decVal_cfoisdone
				offset += n_cfoisdone
			}
		}
	}
	// Decode cfInCug
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 8 {
				decodedTag_cfincug, n_cfincug, rawVal_cfincug, err := ber.DecodeTLV(content[offset:])
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
				if len(rawVal_cfincug) == 1 {
					v.CfInCugRaw_ = rawVal_cfincug[0]
				}
				v.CfInCug = &decVal_cfincug
				offset += n_cfincug
			}
		}
	}
	// Decode basicService
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 9 {
				decodedTag_basicservice, n_basicservice, innerData_basicservice, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding basicService: %w", err)
				}
				if decodedTag_basicservice.Class != tag.ClassContextSpecific || decodedTag_basicservice.Number != 9 || decodedTag_basicservice.Constructed != true {
					return fmt.Errorf("decoding basicService: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_basicservice)
				}
				// Decode inner value from explicit tag wrapper
				var dec_basicservice BasicServiceCode4
				if unmErr := dec_basicservice.UnmarshalBER(innerData_basicservice); unmErr != nil {
					return fmt.Errorf("decoding basicService: %w", unmErr)
				}
				v.BasicService = &dec_basicservice
				offset += n_basicservice
			}
		}
	}
	// Decode category
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 10 {
				decodedTag_category, n_category, rawVal_category, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding category: %w", err)
				}
				if decodedTag_category.Class != tag.ClassContextSpecific || decodedTag_category.Number != 10 {
					return fmt.Errorf("decoding category: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_category)
				}
				tmp_category := Category5(rawVal_category)
				v.Category = &tmp_category
				offset += n_category
			}
		}
	}
	// Decode routingCategory
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 11 {
				decodedTag_routingcategory, n_routingcategory, rawVal_routingcategory, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding routingCategory: %w", err)
				}
				if decodedTag_routingcategory.Class != tag.ClassContextSpecific || decodedTag_routingcategory.Number != 11 {
					return fmt.Errorf("decoding routingCategory: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_routingcategory)
				}
				tmp_routingcategory := RoutingCategory(rawVal_routingcategory)
				v.RoutingCategory = &tmp_routingcategory
				offset += n_routingcategory
			}
		}
	}
	// Decode pnpIndex
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 12 {
				decodedTag_pnpindex, n_pnpindex, rawVal_pnpindex, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding pnpIndex: %w", err)
				}
				if decodedTag_pnpindex.Class != tag.ClassContextSpecific || decodedTag_pnpindex.Number != 12 {
					return fmt.Errorf("decoding pnpIndex: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_pnpindex)
				}
				tmp_pnpindex := PnpIndex(rawVal_pnpindex)
				v.PnpIndex = &tmp_pnpindex
				offset += n_pnpindex
			}
		}
	}
	// Decode nokia-CUG
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 13 {
				decodedTag_nokiacug, n_nokiacug, rawVal_nokiacug, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding nokia-CUG: %w", err)
				}
				if decodedTag_nokiacug.Class != tag.ClassContextSpecific || decodedTag_nokiacug.Number != 13 || decodedTag_nokiacug.Constructed != true {
					return fmt.Errorf("decoding nokia-CUG: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_nokiacug)
				}
				reconstructed_nokiacug := ber.EncodeSequence(rawVal_nokiacug)
				var dec_nokiacug NokiaCUGData
				if unmErr := dec_nokiacug.UnmarshalBER(reconstructed_nokiacug); unmErr != nil {
					return fmt.Errorf("decoding nokia-CUG: %w", unmErr)
				}
				v.NokiaCUG = &dec_nokiacug
				offset += n_nokiacug
			}
		}
	}
	// Decode noBarrings
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 14 {
				decodedTag_nobarrings, n_nobarrings, rawVal_nobarrings, err := ber.DecodeTLV(content[offset:])
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
				offset += n_nobarrings
			}
		}
	}
	// Decode odb-Data
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 15 {
				decodedTag_odbdata, n_odbdata, rawVal_odbdata, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding odb-Data: %w", err)
				}
				if decodedTag_odbdata.Class != tag.ClassContextSpecific || decodedTag_odbdata.Number != 15 || decodedTag_odbdata.Constructed != true {
					return fmt.Errorf("decoding odb-Data: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_odbdata)
				}
				reconstructed_odbdata := ber.EncodeSequence(rawVal_odbdata)
				var dec_odbdata ODBData4
				if unmErr := dec_odbdata.UnmarshalBER(reconstructed_odbdata); unmErr != nil {
					return fmt.Errorf("decoding odb-Data: %w", unmErr)
				}
				v.OdbData = &dec_odbdata
				offset += n_odbdata
			}
		}
	}
	// Decode fraudData
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 16 {
				decodedTag_frauddata, n_frauddata, rawVal_frauddata, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding fraudData: %w", err)
				}
				if decodedTag_frauddata.Class != tag.ClassContextSpecific || decodedTag_frauddata.Number != 16 || decodedTag_frauddata.Constructed != true {
					return fmt.Errorf("decoding fraudData: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_frauddata)
				}
				reconstructed_frauddata := ber.EncodeSequence(rawVal_frauddata)
				var dec_frauddata FraudData
				if unmErr := dec_frauddata.UnmarshalBER(reconstructed_frauddata); unmErr != nil {
					return fmt.Errorf("decoding fraudData: %w", unmErr)
				}
				v.FraudData = &dec_frauddata
				offset += n_frauddata
			}
		}
	}
	// Decode extRoutingCategory
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 17 {
				decodedTag_extroutingcategory, n_extroutingcategory, rawVal_extroutingcategory, err := ber.DecodeTLV(content[offset:])
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
				offset += n_extroutingcategory
			}
		}
	}
	// Decode leaId
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 18 {
				decodedTag_leaid, n_leaid, rawVal_leaid, err := ber.DecodeTLV(content[offset:])
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
				offset += n_leaid
			}
		}
	}
	// Decode olcmInfoTable
	v.OlcmInfoTableIndef_ = false
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 19 {
				decodedTag_olcminfotable, n_olcminfotable, rawVal_olcminfotable, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding olcmInfoTable: %w", err)
				}
				if decodedTag_olcminfotable.Class != tag.ClassContextSpecific || decodedTag_olcminfotable.Number != 19 || decodedTag_olcminfotable.Constructed != true {
					return fmt.Errorf("decoding olcmInfoTable: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_olcminfotable)
				}
				reconstructed_olcminfotable := ber.EncodeSequence(rawVal_olcminfotable)
				dec_olcminfotable, unmErr := UnmarshalBEROlcmInfoTable(reconstructed_olcminfotable)
				if unmErr != nil {
					return fmt.Errorf("decoding olcmInfoTable: %w", unmErr)
				}
				v.OlcmInfoTable = dec_olcminfotable
				{
					_, tagSz_, _ := ber.DecodeTag(content[offset:])
					if offset+tagSz_ < len(content) && content[offset+tagSz_] == 0x80 {
						v.OlcmInfoTableIndef_ = true
					}
				}
				offset += n_olcminfotable
			}
		}
	}
	// Decode callingCategory
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 20 {
				decodedTag_callingcategory, n_callingcategory, rawVal_callingcategory, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding callingCategory: %w", err)
				}
				if decodedTag_callingcategory.Class != tag.ClassContextSpecific || decodedTag_callingcategory.Number != 20 {
					return fmt.Errorf("decoding callingCategory: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_callingcategory)
				}
				tmp_callingcategory := CallingCategory(rawVal_callingcategory)
				v.CallingCategory = &tmp_callingcategory
				offset += n_callingcategory
			}
		}
	}
	// Decode commonMSISDN
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 21 {
				decodedTag_commonmsisdn, n_commonmsisdn, rawVal_commonmsisdn, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding commonMSISDN: %w", err)
				}
				if decodedTag_commonmsisdn.Class != tag.ClassContextSpecific || decodedTag_commonmsisdn.Number != 21 {
					return fmt.Errorf("decoding commonMSISDN: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_commonmsisdn)
				}
				tmp_commonmsisdn := ISDNAddressString4(rawVal_commonmsisdn)
				v.CommonMSISDN = &tmp_commonmsisdn
				offset += n_commonmsisdn
			}
		}
	}
	// Decode rgData
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 22 {
				decodedTag_rgdata, n_rgdata, rawVal_rgdata, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding rgData: %w", err)
				}
				if decodedTag_rgdata.Class != tag.ClassContextSpecific || decodedTag_rgdata.Number != 22 || decodedTag_rgdata.Constructed != true {
					return fmt.Errorf("decoding rgData: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_rgdata)
				}
				reconstructed_rgdata := ber.EncodeSequence(rawVal_rgdata)
				var dec_rgdata RgData
				if unmErr := dec_rgdata.UnmarshalBER(reconstructed_rgdata); unmErr != nil {
					return fmt.Errorf("decoding rgData: %w", unmErr)
				}
				v.RgData = &dec_rgdata
				offset += n_rgdata
			}
		}
	}
	// Decode olcmTraceReference
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 23 {
				decodedTag_olcmtracereference, n_olcmtracereference, rawVal_olcmtracereference, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding olcmTraceReference: %w", err)
				}
				if decodedTag_olcmtracereference.Class != tag.ClassContextSpecific || decodedTag_olcmtracereference.Number != 23 {
					return fmt.Errorf("decoding olcmTraceReference: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_olcmtracereference)
				}
				tmp_olcmtracereference := OlcmTraceReference(rawVal_olcmtracereference)
				v.OlcmTraceReference = &tmp_olcmtracereference
				offset += n_olcmtracereference
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "SriResExtension", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes RgData to BER format.
func (v *RgData) MarshalBER() ([]byte, error) {
	var children []byte
	if v.NoAnswerTimer != nil {
		enc_noanswertimer := ber.EncodeOctetString([]byte(*v.NoAnswerTimer))
		retagged_enc_noanswertimer, tagErr_enc_noanswertimer := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_noanswertimer)
		if tagErr_enc_noanswertimer != nil {
			return nil, fmt.Errorf("encoding noAnswerTimer: %w", tagErr_enc_noanswertimer)
		}
		enc_noanswertimer = retagged_enc_noanswertimer
		children = append(children, enc_noanswertimer...)
	}
	if v.MemberList != nil {
		enc_memberlist, err := MarshalBERMemberList(v.MemberList)
		if err != nil {
			return nil, fmt.Errorf("encoding memberList: %w", err)
		}
		if v.MemberListIndef_ {
			// Strip the outer SEQUENCE tag from marshalBER output to get raw children.
			_, _, seqContent_, tlvErr_ := ber.DecodeTLV(enc_memberlist)
			if tlvErr_ != nil {
				return nil, tlvErr_
			}
			enc_memberlist = ber.EncodeConstructedIndefinite(tag.Tag{Class: tag.ClassContextSpecific, Number: 1}, seqContent_)
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
		enc_alertingmethod := ber.EncodeOctetString([]byte(*v.AlertingMethod))
		retagged_enc_alertingmethod, tagErr_enc_alertingmethod := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_alertingmethod)
		if tagErr_enc_alertingmethod != nil {
			return nil, fmt.Errorf("encoding alertingMethod: %w", tagErr_enc_alertingmethod)
		}
		enc_alertingmethod = retagged_enc_alertingmethod
		children = append(children, enc_alertingmethod...)
	}
	if v.UserType != nil {
		enc_usertype := ber.EncodeOctetString([]byte(*v.UserType))
		retagged_enc_usertype, tagErr_enc_usertype := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, enc_usertype)
		if tagErr_enc_usertype != nil {
			return nil, fmt.Errorf("encoding userType: %w", tagErr_enc_usertype)
		}
		enc_usertype = retagged_enc_usertype
		children = append(children, enc_usertype...)
	}
	if v.DivertedToNbr != nil {
		enc_divertedtonbr := ber.EncodeOctetString([]byte(*v.DivertedToNbr))
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

// MarshalDER encodes RgData to DER format.
func (v *RgData) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// ITU-T X.690 (02/2021) Section 10.1 requires DER length forms to be definite.
	derValue := *v
	derValue.MemberListIndef_ = false
	v = &derValue
	encoded, err := v.MarshalBER()
	if err != nil {
		return nil, err
	}
	if err := ber.ValidateDERElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding RgData as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes RgData from BER/DER format.
func (v *RgData) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
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
				decodedTag_noanswertimer, n_noanswertimer, rawVal_noanswertimer, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding noAnswerTimer: %w", err)
				}
				if decodedTag_noanswertimer.Class != tag.ClassContextSpecific || decodedTag_noanswertimer.Number != 0 {
					return fmt.Errorf("decoding noAnswerTimer: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_noanswertimer)
				}
				tmp_noanswertimer := NoAnswerTimer(rawVal_noanswertimer)
				v.NoAnswerTimer = &tmp_noanswertimer
				offset += n_noanswertimer
			}
		}
	}
	// Decode memberList
	v.MemberListIndef_ = false
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
				decodedTag_memberlist, n_memberlist, rawVal_memberlist, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding memberList: %w", err)
				}
				if decodedTag_memberlist.Class != tag.ClassContextSpecific || decodedTag_memberlist.Number != 1 || decodedTag_memberlist.Constructed != true {
					return fmt.Errorf("decoding memberList: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_memberlist)
				}
				reconstructed_memberlist := ber.EncodeSequence(rawVal_memberlist)
				dec_memberlist, unmErr := UnmarshalBERMemberList(reconstructed_memberlist)
				if unmErr != nil {
					return fmt.Errorf("decoding memberList: %w", unmErr)
				}
				v.MemberList = dec_memberlist
				{
					_, tagSz_, _ := ber.DecodeTag(content[offset:])
					if offset+tagSz_ < len(content) && content[offset+tagSz_] == 0x80 {
						v.MemberListIndef_ = true
					}
				}
				offset += n_memberlist
			}
		}
	}
	// Decode alertingMethod
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2 {
				decodedTag_alertingmethod, n_alertingmethod, rawVal_alertingmethod, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding alertingMethod: %w", err)
				}
				if decodedTag_alertingmethod.Class != tag.ClassContextSpecific || decodedTag_alertingmethod.Number != 2 {
					return fmt.Errorf("decoding alertingMethod: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_alertingmethod)
				}
				tmp_alertingmethod := AlertingMethod(rawVal_alertingmethod)
				v.AlertingMethod = &tmp_alertingmethod
				offset += n_alertingmethod
			}
		}
	}
	// Decode userType
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3 {
				decodedTag_usertype, n_usertype, rawVal_usertype, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding userType: %w", err)
				}
				if decodedTag_usertype.Class != tag.ClassContextSpecific || decodedTag_usertype.Number != 3 {
					return fmt.Errorf("decoding userType: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_usertype)
				}
				tmp_usertype := UserType(rawVal_usertype)
				v.UserType = &tmp_usertype
				offset += n_usertype
			}
		}
	}
	// Decode divertedToNbr
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4 {
				decodedTag_divertedtonbr, n_divertedtonbr, rawVal_divertedtonbr, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding divertedToNbr: %w", err)
				}
				if decodedTag_divertedtonbr.Class != tag.ClassContextSpecific || decodedTag_divertedtonbr.Number != 4 {
					return fmt.Errorf("decoding divertedToNbr: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_divertedtonbr)
				}
				tmp_divertedtonbr := ISDNAddressString4(rawVal_divertedtonbr)
				v.DivertedToNbr = &tmp_divertedtonbr
				offset += n_divertedtonbr
			}
		}
	}
	// Decode memberOfSuppression
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 5 {
				decodedTag_memberofsuppression, n_memberofsuppression, rawVal_memberofsuppression, err := ber.DecodeTLV(content[offset:])
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
				offset += n_memberofsuppression
			}
		}
	}
	// Decode ringbacktone
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 6 {
				decodedTag_ringbacktone, n_ringbacktone, rawVal_ringbacktone, err := ber.DecodeTLV(content[offset:])
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
				offset += n_ringbacktone
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "RgData", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBERMemberList encodes a MemberList list to BER.
func MarshalBERMemberList(list MemberList) ([]byte, error) {
	var children []byte
	for _, elem := range list {
		children = append(children, ber.EncodeOctetString([]byte(elem))...)
	}
	return ber.EncodeSequence(children), nil
}

// UnmarshalBERMemberList decodes a MemberList list from BER.
func UnmarshalBERMemberList(data []byte) (MemberList, error) {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return nil, fmt.Errorf("decoding MemberList: %w", err)
	}
	if total != len(data) {
		return nil, &ber.DecodeError{Offset: total, TypeName: "MemberList", Cause: ber.ErrExtraData}
	}
	var result MemberList
	offset := 0
	for offset < len(content) {
		val, n, osErr := ber.DecodeOctetString(content[offset:])
		if osErr != nil {
			return nil, fmt.Errorf("decoding element: %w", osErr)
		}
		result = append(result, ISDNAddressString4(val))
		offset += n
	}
	return result, nil
}

// MarshalBER encodes PrefCarrierIdList to BER format.
func (v *PrefCarrierIdList) MarshalBER() ([]byte, error) {
	var children []byte
	enc_prefcarrieridcode1 := ber.EncodeOctetString([]byte(v.PrefCarrierIdCode1))
	retagged_enc_prefcarrieridcode1, tagErr_enc_prefcarrieridcode1 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_prefcarrieridcode1)
	if tagErr_enc_prefcarrieridcode1 != nil {
		return nil, fmt.Errorf("encoding prefCarrierIdCode1: %w", tagErr_enc_prefcarrieridcode1)
	}
	enc_prefcarrieridcode1 = retagged_enc_prefcarrieridcode1
	children = append(children, enc_prefcarrieridcode1...)
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

// MarshalDER encodes PrefCarrierIdList to DER format.
func (v *PrefCarrierIdList) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	encoded, err := v.MarshalBER()
	if err != nil {
		return nil, err
	}
	if err := ber.ValidateDERElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding PrefCarrierIdList as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes PrefCarrierIdList from BER/DER format.
func (v *PrefCarrierIdList) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
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
	decodedTag_prefcarrieridcode1, n_prefcarrieridcode1, rawVal_prefcarrieridcode1, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding prefCarrierIdCode1: %w", err)
	}
	if decodedTag_prefcarrieridcode1.Class != tag.ClassContextSpecific || decodedTag_prefcarrieridcode1.Number != 0 {
		return fmt.Errorf("decoding prefCarrierIdCode1: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_prefcarrieridcode1)
	}
	v.PrefCarrierIdCode1 = CarrierIdCode(rawVal_prefcarrieridcode1)
	offset += n_prefcarrieridcode1
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "PrefCarrierIdList", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes ANSIIsdArgExt to BER format.
func (v *ANSIIsdArgExt) MarshalBER() ([]byte, error) {
	var children []byte
	if v.PrefCarrierIdList != nil {
		enc_prefcarrieridlist, err := v.PrefCarrierIdList.MarshalBER()
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
		_, n, _, extErr := ber.DecodeTLV(ext)
		if extErr != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, extErr)
		}
		if n != len(ext) {
			return nil, fmt.Errorf("encoding extension %d: %w", i, ber.ErrExtraData)
		}
		children = append(children, ext...)
	}
	return ber.EncodeConstructed(tag.Tag{Class: tag.ClassPrivate, Number: 30, Constructed: true}, children), nil
}

// MarshalDER encodes ANSIIsdArgExt to DER format.
func (v *ANSIIsdArgExt) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	encoded, err := v.MarshalBER()
	if err != nil {
		return nil, err
	}
	if err := ber.ValidateDERElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding ANSIIsdArgExt as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes ANSIIsdArgExt from BER/DER format.
func (v *ANSIIsdArgExt) UnmarshalBER(data []byte) error {
	decodedTag, content, total, err := ber.DecodeConstructedContent(data)
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
				decodedTag_prefcarrieridlist, n_prefcarrieridlist, rawVal_prefcarrieridlist, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding prefCarrierIdList: %w", err)
				}
				if decodedTag_prefcarrieridlist.Class != tag.ClassContextSpecific || decodedTag_prefcarrieridlist.Number != 0 || decodedTag_prefcarrieridlist.Constructed != true {
					return fmt.Errorf("decoding prefCarrierIdList: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_prefcarrieridlist)
				}
				reconstructed_prefcarrieridlist := ber.EncodeSequence(rawVal_prefcarrieridlist)
				var dec_prefcarrieridlist PrefCarrierIdList
				if unmErr := dec_prefcarrieridlist.UnmarshalBER(reconstructed_prefcarrieridlist); unmErr != nil {
					return fmt.Errorf("decoding prefCarrierIdList: %w", unmErr)
				}
				v.PrefCarrierIdList = &dec_prefcarrieridlist
				offset += n_prefcarrieridlist
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "ANSIIsdArgExt", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes ANSISriResExt to BER format.
func (v *ANSISriResExt) MarshalBER() ([]byte, error) {
	var children []byte
	if v.PrefCarrierIdList != nil {
		enc_prefcarrieridlist, err := v.PrefCarrierIdList.MarshalBER()
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
		_, n, _, extErr := ber.DecodeTLV(ext)
		if extErr != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, extErr)
		}
		if n != len(ext) {
			return nil, fmt.Errorf("encoding extension %d: %w", i, ber.ErrExtraData)
		}
		children = append(children, ext...)
	}
	return ber.EncodeConstructed(tag.Tag{Class: tag.ClassPrivate, Number: 30, Constructed: true}, children), nil
}

// MarshalDER encodes ANSISriResExt to DER format.
func (v *ANSISriResExt) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	encoded, err := v.MarshalBER()
	if err != nil {
		return nil, err
	}
	if err := ber.ValidateDERElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding ANSISriResExt as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes ANSISriResExt from BER/DER format.
func (v *ANSISriResExt) UnmarshalBER(data []byte) error {
	decodedTag, content, total, err := ber.DecodeConstructedContent(data)
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
				decodedTag_prefcarrieridlist, n_prefcarrieridlist, rawVal_prefcarrieridlist, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding prefCarrierIdList: %w", err)
				}
				if decodedTag_prefcarrieridlist.Class != tag.ClassContextSpecific || decodedTag_prefcarrieridlist.Number != 0 || decodedTag_prefcarrieridlist.Constructed != true {
					return fmt.Errorf("decoding prefCarrierIdList: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_prefcarrieridlist)
				}
				reconstructed_prefcarrieridlist := ber.EncodeSequence(rawVal_prefcarrieridlist)
				var dec_prefcarrieridlist PrefCarrierIdList
				if unmErr := dec_prefcarrieridlist.UnmarshalBER(reconstructed_prefcarrieridlist); unmErr != nil {
					return fmt.Errorf("decoding prefCarrierIdList: %w", unmErr)
				}
				v.PrefCarrierIdList = &dec_prefcarrieridlist
				offset += n_prefcarrieridlist
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "ANSISriResExt", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes CanLocArgExt to BER format.
func (v *CanLocArgExt) MarshalBER() ([]byte, error) {
	var children []byte
	if v.Termination != nil {
		enc_termination := ber.EncodeOctetString(v.Termination)
		retagged_enc_termination, tagErr_enc_termination := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_termination)
		if tagErr_enc_termination != nil {
			return nil, fmt.Errorf("encoding termination: %w", tagErr_enc_termination)
		}
		enc_termination = retagged_enc_termination
		children = append(children, enc_termination...)
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
	return ber.EncodeConstructed(tag.Tag{Class: tag.ClassPrivate, Number: 0, Constructed: true}, children), nil
}

// MarshalDER encodes CanLocArgExt to DER format.
func (v *CanLocArgExt) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	encoded, err := v.MarshalBER()
	if err != nil {
		return nil, err
	}
	if err := ber.ValidateDERElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding CanLocArgExt as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes CanLocArgExt from BER/DER format.
func (v *CanLocArgExt) UnmarshalBER(data []byte) error {
	decodedTag, content, total, err := ber.DecodeConstructedContent(data)
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
				decodedTag_termination, n_termination, rawVal_termination, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding termination: %w", err)
				}
				if decodedTag_termination.Class != tag.ClassContextSpecific || decodedTag_termination.Number != 0 {
					return fmt.Errorf("decoding termination: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_termination)
				}
				tmp_termination := rawVal_termination
				v.Termination = tmp_termination
				offset += n_termination
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "CanLocArgExt", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes ATMargExt to BER format.
func (v *ATMargExt) MarshalBER() ([]byte, error) {
	var children []byte
	if v.TraceReference != nil {
		enc_tracereference := ber.EncodeOctetString([]byte(*v.TraceReference))
		retagged_enc_tracereference, tagErr_enc_tracereference := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_tracereference)
		if tagErr_enc_tracereference != nil {
			return nil, fmt.Errorf("encoding traceReference: %w", tagErr_enc_tracereference)
		}
		enc_tracereference = retagged_enc_tracereference
		children = append(children, enc_tracereference...)
	}
	if v.TraceType != nil {
		enc_tracetype := ber.EncodeInteger(int64(*v.TraceType))
		retagged_enc_tracetype, tagErr_enc_tracetype := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_tracetype)
		if tagErr_enc_tracetype != nil {
			return nil, fmt.Errorf("encoding traceType: %w", tagErr_enc_tracetype)
		}
		enc_tracetype = retagged_enc_tracetype
		children = append(children, enc_tracetype...)
	}
	if v.LeaId != nil {
		enc_leaid := ber.EncodeInteger(int64(*v.LeaId))
		retagged_enc_leaid, tagErr_enc_leaid := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_leaid)
		if tagErr_enc_leaid != nil {
			return nil, fmt.Errorf("encoding leaId: %w", tagErr_enc_leaid)
		}
		enc_leaid = retagged_enc_leaid
		children = append(children, enc_leaid...)
	}
	if v.OlcmInfoTable != nil {
		enc_olcminfotable, err := MarshalBEROlcmInfoTable(v.OlcmInfoTable)
		if err != nil {
			return nil, fmt.Errorf("encoding olcmInfoTable: %w", err)
		}
		if v.OlcmInfoTableIndef_ {
			// Strip the outer SEQUENCE tag from marshalBER output to get raw children.
			_, _, seqContent_, tlvErr_ := ber.DecodeTLV(enc_olcminfotable)
			if tlvErr_ != nil {
				return nil, tlvErr_
			}
			enc_olcminfotable = ber.EncodeConstructedIndefinite(tag.Tag{Class: tag.ClassContextSpecific, Number: 3}, seqContent_)
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
		enc_olcmtracereference := ber.EncodeOctetString([]byte(*v.OlcmTraceReference))
		retagged_enc_olcmtracereference, tagErr_enc_olcmtracereference := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, enc_olcmtracereference)
		if tagErr_enc_olcmtracereference != nil {
			return nil, fmt.Errorf("encoding olcmTraceReference: %w", tagErr_enc_olcmtracereference)
		}
		enc_olcmtracereference = retagged_enc_olcmtracereference
		children = append(children, enc_olcmtracereference...)
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
	return ber.EncodeConstructed(tag.Tag{Class: tag.ClassPrivate, Number: 0, Constructed: true}, children), nil
}

// MarshalDER encodes ATMargExt to DER format.
func (v *ATMargExt) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// ITU-T X.690 (02/2021) Section 10.1 requires DER length forms to be definite.
	derValue := *v
	derValue.OlcmInfoTableIndef_ = false
	v = &derValue
	encoded, err := v.MarshalBER()
	if err != nil {
		return nil, err
	}
	if err := ber.ValidateDERElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding ATMargExt as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes ATMargExt from BER/DER format.
func (v *ATMargExt) UnmarshalBER(data []byte) error {
	decodedTag, content, total, err := ber.DecodeConstructedContent(data)
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
				decodedTag_tracereference, n_tracereference, rawVal_tracereference, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding traceReference: %w", err)
				}
				if decodedTag_tracereference.Class != tag.ClassContextSpecific || decodedTag_tracereference.Number != 0 {
					return fmt.Errorf("decoding traceReference: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_tracereference)
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
				decodedTag_tracetype, n_tracetype, rawVal_tracetype, err := ber.DecodeTLV(content[offset:])
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
				tmp_tracetype := TraceType4(decVal_tracetype)
				v.TraceType = &tmp_tracetype
				offset += n_tracetype
			}
		}
	}
	// Decode leaId
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2 {
				decodedTag_leaid, n_leaid, rawVal_leaid, err := ber.DecodeTLV(content[offset:])
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
				offset += n_leaid
			}
		}
	}
	// Decode olcmInfoTable
	v.OlcmInfoTableIndef_ = false
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3 {
				decodedTag_olcminfotable, n_olcminfotable, rawVal_olcminfotable, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding olcmInfoTable: %w", err)
				}
				if decodedTag_olcminfotable.Class != tag.ClassContextSpecific || decodedTag_olcminfotable.Number != 3 || decodedTag_olcminfotable.Constructed != true {
					return fmt.Errorf("decoding olcmInfoTable: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_olcminfotable)
				}
				reconstructed_olcminfotable := ber.EncodeSequence(rawVal_olcminfotable)
				dec_olcminfotable, unmErr := UnmarshalBEROlcmInfoTable(reconstructed_olcminfotable)
				if unmErr != nil {
					return fmt.Errorf("decoding olcmInfoTable: %w", unmErr)
				}
				v.OlcmInfoTable = dec_olcminfotable
				{
					_, tagSz_, _ := ber.DecodeTag(content[offset:])
					if offset+tagSz_ < len(content) && content[offset+tagSz_] == 0x80 {
						v.OlcmInfoTableIndef_ = true
					}
				}
				offset += n_olcminfotable
			}
		}
	}
	// Decode olcmTraceReference
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4 {
				decodedTag_olcmtracereference, n_olcmtracereference, rawVal_olcmtracereference, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding olcmTraceReference: %w", err)
				}
				if decodedTag_olcmtracereference.Class != tag.ClassContextSpecific || decodedTag_olcmtracereference.Number != 4 {
					return fmt.Errorf("decoding olcmTraceReference: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_olcmtracereference)
				}
				tmp_olcmtracereference := OlcmTraceReference(rawVal_olcmtracereference)
				v.OlcmTraceReference = &tmp_olcmtracereference
				offset += n_olcmtracereference
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "ATMargExt", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBEROlcmInfoTable encodes a OlcmInfoTable list to BER.
func MarshalBEROlcmInfoTable(list OlcmInfoTable) ([]byte, error) {
	var children []byte
	for _, elem := range list {
		enc, err := elem.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding element: %w", err)
		}
		children = append(children, enc...)
	}
	return ber.EncodeSequence(children), nil
}

// UnmarshalBEROlcmInfoTable decodes a OlcmInfoTable list from BER.
func UnmarshalBEROlcmInfoTable(data []byte) (OlcmInfoTable, error) {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return nil, fmt.Errorf("decoding OlcmInfoTable: %w", err)
	}
	if total != len(data) {
		return nil, &ber.DecodeError{Offset: total, TypeName: "OlcmInfoTable", Cause: ber.ErrExtraData}
	}
	var result OlcmInfoTable
	offset := 0
	for offset < len(content) {
		var elem OlcmInfo
		_, n, _, tlvErr := ber.DecodeTLV(content[offset:])
		if tlvErr != nil {
			return nil, fmt.Errorf("decoding element TLV: %w", tlvErr)
		}
		if unmErr := elem.UnmarshalBER(content[offset : offset+n]); unmErr != nil {
			return nil, fmt.Errorf("decoding element: %w", unmErr)
		}
		result = append(result, elem)
		offset += n
	}
	return result, nil
}

// MarshalBER encodes OlcmInfo to BER format.
func (v *OlcmInfo) MarshalBER() ([]byte, error) {
	var children []byte
	enc_tracereference := ber.EncodeOctetString([]byte(v.TraceReference))
	retagged_enc_tracereference, tagErr_enc_tracereference := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_tracereference)
	if tagErr_enc_tracereference != nil {
		return nil, fmt.Errorf("encoding traceReference: %w", tagErr_enc_tracereference)
	}
	enc_tracereference = retagged_enc_tracereference
	children = append(children, enc_tracereference...)
	enc_tracetype := ber.EncodeInteger(int64(v.TraceType))
	retagged_enc_tracetype, tagErr_enc_tracetype := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_tracetype)
	if tagErr_enc_tracetype != nil {
		return nil, fmt.Errorf("encoding traceType: %w", tagErr_enc_tracetype)
	}
	enc_tracetype = retagged_enc_tracetype
	children = append(children, enc_tracetype...)
	if v.LeaId != nil {
		enc_leaid := ber.EncodeInteger(int64(*v.LeaId))
		retagged_enc_leaid, tagErr_enc_leaid := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_leaid)
		if tagErr_enc_leaid != nil {
			return nil, fmt.Errorf("encoding leaId: %w", tagErr_enc_leaid)
		}
		enc_leaid = retagged_enc_leaid
		children = append(children, enc_leaid...)
	}
	if v.OlcmTraceReference != nil {
		enc_olcmtracereference := ber.EncodeOctetString([]byte(*v.OlcmTraceReference))
		retagged_enc_olcmtracereference, tagErr_enc_olcmtracereference := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, enc_olcmtracereference)
		if tagErr_enc_olcmtracereference != nil {
			return nil, fmt.Errorf("encoding olcmTraceReference: %w", tagErr_enc_olcmtracereference)
		}
		enc_olcmtracereference = retagged_enc_olcmtracereference
		children = append(children, enc_olcmtracereference...)
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

// MarshalDER encodes OlcmInfo to DER format.
func (v *OlcmInfo) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	encoded, err := v.MarshalBER()
	if err != nil {
		return nil, err
	}
	if err := ber.ValidateDERElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding OlcmInfo as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes OlcmInfo from BER/DER format.
func (v *OlcmInfo) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
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
	decodedTag_tracereference, n_tracereference, rawVal_tracereference, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding traceReference: %w", err)
	}
	if decodedTag_tracereference.Class != tag.ClassContextSpecific || decodedTag_tracereference.Number != 0 {
		return fmt.Errorf("decoding traceReference: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_tracereference)
	}
	v.TraceReference = TraceReference4(rawVal_tracereference)
	offset += n_tracereference
	// Decode traceType
	if offset >= len(content) {
		return fmt.Errorf("missing required field traceType")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 1 {
			return fmt.Errorf("expected tag [%s %d] for traceType, got %s", "CONTEXT", 1, reqTag_)
		}
	}
	decodedTag_tracetype, n_tracetype, rawVal_tracetype, err := ber.DecodeTLV(content[offset:])
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
	v.TraceType = TraceType4(decVal_tracetype)
	offset += n_tracetype
	// Decode leaId
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2 {
				decodedTag_leaid, n_leaid, rawVal_leaid, err := ber.DecodeTLV(content[offset:])
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
				offset += n_leaid
			}
		}
	}
	// Decode olcmTraceReference
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3 {
				decodedTag_olcmtracereference, n_olcmtracereference, rawVal_olcmtracereference, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding olcmTraceReference: %w", err)
				}
				if decodedTag_olcmtracereference.Class != tag.ClassContextSpecific || decodedTag_olcmtracereference.Number != 3 {
					return fmt.Errorf("decoding olcmTraceReference: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_olcmtracereference)
				}
				tmp_olcmtracereference := OlcmTraceReference(rawVal_olcmtracereference)
				v.OlcmTraceReference = &tmp_olcmtracereference
				offset += n_olcmtracereference
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "OlcmInfo", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes ATMresExt to BER format.
func (v *ATMresExt) MarshalBER() ([]byte, error) {
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
		_, n, _, extErr := ber.DecodeTLV(ext)
		if extErr != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, extErr)
		}
		if n != len(ext) {
			return nil, fmt.Errorf("encoding extension %d: %w", i, ber.ErrExtraData)
		}
		children = append(children, ext...)
	}
	return ber.EncodeConstructed(tag.Tag{Class: tag.ClassPrivate, Number: 0, Constructed: true}, children), nil
}

// MarshalDER encodes ATMresExt to DER format.
func (v *ATMresExt) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	encoded, err := v.MarshalBER()
	if err != nil {
		return nil, err
	}
	if err := ber.ValidateDERElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding ATMresExt as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes ATMresExt from BER/DER format.
func (v *ATMresExt) UnmarshalBER(data []byte) error {
	decodedTag, content, total, err := ber.DecodeConstructedContent(data)
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
				decodedTag_olcmactive, n_olcmactive, rawVal_olcmactive, err := ber.DecodeTLV(content[offset:])
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
				offset += n_olcmactive
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "ATMresExt", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes DTMargExt to BER format.
func (v *DTMargExt) MarshalBER() ([]byte, error) {
	var children []byte
	if v.TraceType != nil {
		enc_tracetype := ber.EncodeInteger(int64(*v.TraceType))
		retagged_enc_tracetype, tagErr_enc_tracetype := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_tracetype)
		if tagErr_enc_tracetype != nil {
			return nil, fmt.Errorf("encoding traceType: %w", tagErr_enc_tracetype)
		}
		enc_tracetype = retagged_enc_tracetype
		children = append(children, enc_tracetype...)
	}
	if v.LeaId != nil {
		enc_leaid := ber.EncodeInteger(int64(*v.LeaId))
		retagged_enc_leaid, tagErr_enc_leaid := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_leaid)
		if tagErr_enc_leaid != nil {
			return nil, fmt.Errorf("encoding leaId: %w", tagErr_enc_leaid)
		}
		enc_leaid = retagged_enc_leaid
		children = append(children, enc_leaid...)
	}
	if v.OlcmTraceReference != nil {
		enc_olcmtracereference := ber.EncodeOctetString([]byte(*v.OlcmTraceReference))
		retagged_enc_olcmtracereference, tagErr_enc_olcmtracereference := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_olcmtracereference)
		if tagErr_enc_olcmtracereference != nil {
			return nil, fmt.Errorf("encoding olcmTraceReference: %w", tagErr_enc_olcmtracereference)
		}
		enc_olcmtracereference = retagged_enc_olcmtracereference
		children = append(children, enc_olcmtracereference...)
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
	return ber.EncodeConstructed(tag.Tag{Class: tag.ClassPrivate, Number: 0, Constructed: true}, children), nil
}

// MarshalDER encodes DTMargExt to DER format.
func (v *DTMargExt) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	encoded, err := v.MarshalBER()
	if err != nil {
		return nil, err
	}
	if err := ber.ValidateDERElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding DTMargExt as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes DTMargExt from BER/DER format.
func (v *DTMargExt) UnmarshalBER(data []byte) error {
	decodedTag, content, total, err := ber.DecodeConstructedContent(data)
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
				decodedTag_tracetype, n_tracetype, rawVal_tracetype, err := ber.DecodeTLV(content[offset:])
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
				tmp_tracetype := TraceType4(decVal_tracetype)
				v.TraceType = &tmp_tracetype
				offset += n_tracetype
			}
		}
	}
	// Decode leaId
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
				decodedTag_leaid, n_leaid, rawVal_leaid, err := ber.DecodeTLV(content[offset:])
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
				offset += n_leaid
			}
		}
	}
	// Decode olcmTraceReference
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2 {
				decodedTag_olcmtracereference, n_olcmtracereference, rawVal_olcmtracereference, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding olcmTraceReference: %w", err)
				}
				if decodedTag_olcmtracereference.Class != tag.ClassContextSpecific || decodedTag_olcmtracereference.Number != 2 {
					return fmt.Errorf("decoding olcmTraceReference: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_olcmtracereference)
				}
				tmp_olcmtracereference := OlcmTraceReference(rawVal_olcmtracereference)
				v.OlcmTraceReference = &tmp_olcmtracereference
				offset += n_olcmtracereference
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "DTMargExt", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes FraudInfo to BER format.
func (v *FraudInfo) MarshalBER() ([]byte, error) {
	var children []byte
	if v.Moc != nil {
		enc_moc, err := v.Moc.MarshalBER()
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
		enc_cf, err := v.Cf.MarshalBER()
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
		enc_ct, err := v.Ct.MarshalBER()
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

// MarshalDER encodes FraudInfo to DER format.
func (v *FraudInfo) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	encoded, err := v.MarshalBER()
	if err != nil {
		return nil, err
	}
	if err := ber.ValidateDERElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding FraudInfo as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes FraudInfo from BER/DER format.
func (v *FraudInfo) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
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
				decodedTag_moc, n_moc, rawVal_moc, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding moc: %w", err)
				}
				if decodedTag_moc.Class != tag.ClassContextSpecific || decodedTag_moc.Number != 0 || decodedTag_moc.Constructed != true {
					return fmt.Errorf("decoding moc: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_moc)
				}
				reconstructed_moc := ber.EncodeSequence(rawVal_moc)
				var dec_moc FraudData
				if unmErr := dec_moc.UnmarshalBER(reconstructed_moc); unmErr != nil {
					return fmt.Errorf("decoding moc: %w", unmErr)
				}
				v.Moc = &dec_moc
				offset += n_moc
			}
		}
	}
	// Decode cf
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
				decodedTag_cf, n_cf, rawVal_cf, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding cf: %w", err)
				}
				if decodedTag_cf.Class != tag.ClassContextSpecific || decodedTag_cf.Number != 1 || decodedTag_cf.Constructed != true {
					return fmt.Errorf("decoding cf: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_cf)
				}
				reconstructed_cf := ber.EncodeSequence(rawVal_cf)
				var dec_cf FraudData
				if unmErr := dec_cf.UnmarshalBER(reconstructed_cf); unmErr != nil {
					return fmt.Errorf("decoding cf: %w", unmErr)
				}
				v.Cf = &dec_cf
				offset += n_cf
			}
		}
	}
	// Decode ct
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2 {
				decodedTag_ct, n_ct, rawVal_ct, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding ct: %w", err)
				}
				if decodedTag_ct.Class != tag.ClassContextSpecific || decodedTag_ct.Number != 2 || decodedTag_ct.Constructed != true {
					return fmt.Errorf("decoding ct: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_ct)
				}
				reconstructed_ct := ber.EncodeSequence(rawVal_ct)
				var dec_ct FraudData
				if unmErr := dec_ct.UnmarshalBER(reconstructed_ct); unmErr != nil {
					return fmt.Errorf("decoding ct: %w", unmErr)
				}
				v.Ct = &dec_ct
				offset += n_ct
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "FraudInfo", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes FraudData to BER format.
func (v *FraudData) MarshalBER() ([]byte, error) {
	var children []byte
	if v.Time != nil {
		enc_time := ber.EncodeInteger(int64(*v.Time))
		retagged_enc_time, tagErr_enc_time := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_time)
		if tagErr_enc_time != nil {
			return nil, fmt.Errorf("encoding time: %w", tagErr_enc_time)
		}
		enc_time = retagged_enc_time
		children = append(children, enc_time...)
	}
	if v.TimeAction != nil {
		enc_timeaction := ber.EncodeOctetString([]byte(*v.TimeAction))
		retagged_enc_timeaction, tagErr_enc_timeaction := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_timeaction)
		if tagErr_enc_timeaction != nil {
			return nil, fmt.Errorf("encoding timeAction: %w", tagErr_enc_timeaction)
		}
		enc_timeaction = retagged_enc_timeaction
		children = append(children, enc_timeaction...)
	}
	if v.MaxCount != nil {
		enc_maxcount := ber.EncodeInteger(int64(*v.MaxCount))
		retagged_enc_maxcount, tagErr_enc_maxcount := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_maxcount)
		if tagErr_enc_maxcount != nil {
			return nil, fmt.Errorf("encoding maxCount: %w", tagErr_enc_maxcount)
		}
		enc_maxcount = retagged_enc_maxcount
		children = append(children, enc_maxcount...)
	}
	if v.MaxCountAction != nil {
		enc_maxcountaction := ber.EncodeOctetString([]byte(*v.MaxCountAction))
		retagged_enc_maxcountaction, tagErr_enc_maxcountaction := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, enc_maxcountaction)
		if tagErr_enc_maxcountaction != nil {
			return nil, fmt.Errorf("encoding maxCountAction: %w", tagErr_enc_maxcountaction)
		}
		enc_maxcountaction = retagged_enc_maxcountaction
		children = append(children, enc_maxcountaction...)
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

// MarshalDER encodes FraudData to DER format.
func (v *FraudData) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	encoded, err := v.MarshalBER()
	if err != nil {
		return nil, err
	}
	if err := ber.ValidateDERElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding FraudData as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes FraudData from BER/DER format.
func (v *FraudData) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
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
				decodedTag_time, n_time, rawVal_time, err := ber.DecodeTLV(content[offset:])
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
				offset += n_time
			}
		}
	}
	// Decode timeAction
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
				decodedTag_timeaction, n_timeaction, rawVal_timeaction, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding timeAction: %w", err)
				}
				if decodedTag_timeaction.Class != tag.ClassContextSpecific || decodedTag_timeaction.Number != 1 {
					return fmt.Errorf("decoding timeAction: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_timeaction)
				}
				tmp_timeaction := ActionType(rawVal_timeaction)
				v.TimeAction = &tmp_timeaction
				offset += n_timeaction
			}
		}
	}
	// Decode maxCount
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2 {
				decodedTag_maxcount, n_maxcount, rawVal_maxcount, err := ber.DecodeTLV(content[offset:])
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
				offset += n_maxcount
			}
		}
	}
	// Decode maxCountAction
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3 {
				decodedTag_maxcountaction, n_maxcountaction, rawVal_maxcountaction, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding maxCountAction: %w", err)
				}
				if decodedTag_maxcountaction.Class != tag.ClassContextSpecific || decodedTag_maxcountaction.Number != 3 {
					return fmt.Errorf("decoding maxCountAction: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_maxcountaction)
				}
				tmp_maxcountaction := ActionType(rawVal_maxcountaction)
				v.MaxCountAction = &tmp_maxcountaction
				offset += n_maxcountaction
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "FraudData", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes ServiceWithInfo to BER format.
func (v *ServiceWithInfo) MarshalBER() ([]byte, error) {
	var children []byte
	if v.ServiceCode != nil {
		enc_servicecode := ber.EncodeOctetString([]byte(*v.ServiceCode))
		retagged_enc_servicecode, tagErr_enc_servicecode := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_servicecode)
		if tagErr_enc_servicecode != nil {
			return nil, fmt.Errorf("encoding serviceCode: %w", tagErr_enc_servicecode)
		}
		enc_servicecode = retagged_enc_servicecode
		children = append(children, enc_servicecode...)
	}
	if v.VersionInfo != nil {
		enc_versioninfo := ber.EncodeOctetString([]byte(*v.VersionInfo))
		retagged_enc_versioninfo, tagErr_enc_versioninfo := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_versioninfo)
		if tagErr_enc_versioninfo != nil {
			return nil, fmt.Errorf("encoding versionInfo: %w", tagErr_enc_versioninfo)
		}
		enc_versioninfo = retagged_enc_versioninfo
		children = append(children, enc_versioninfo...)
	}
	if v.InKey != nil {
		enc_inkey, err := v.InKey.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding in-key: %w", err)
		}
		children = append(children, enc_inkey...)
	}
	if v.FraudInfo != nil {
		enc_fraudinfo, err := v.FraudInfo.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding fraudInfo: %w", err)
		}
		children = append(children, enc_fraudinfo...)
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

// MarshalDER encodes ServiceWithInfo to DER format.
func (v *ServiceWithInfo) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	encoded, err := v.MarshalBER()
	if err != nil {
		return nil, err
	}
	if err := ber.ValidateDERElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding ServiceWithInfo as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes ServiceWithInfo from BER/DER format.
func (v *ServiceWithInfo) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
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
				decodedTag_servicecode, n_servicecode, rawVal_servicecode, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding serviceCode: %w", err)
				}
				if decodedTag_servicecode.Class != tag.ClassContextSpecific || decodedTag_servicecode.Number != 0 {
					return fmt.Errorf("decoding serviceCode: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_servicecode)
				}
				tmp_servicecode := MAPserviceCode(rawVal_servicecode)
				v.ServiceCode = &tmp_servicecode
				offset += n_servicecode
			}
		}
	}
	// Decode versionInfo
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
				decodedTag_versioninfo, n_versioninfo, rawVal_versioninfo, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding versionInfo: %w", err)
				}
				if decodedTag_versioninfo.Class != tag.ClassContextSpecific || decodedTag_versioninfo.Number != 1 {
					return fmt.Errorf("decoding versionInfo: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_versioninfo)
				}
				tmp_versioninfo := VersionInfo(rawVal_versioninfo)
				v.VersionInfo = &tmp_versioninfo
				offset += n_versioninfo
			}
		}
	}
	// Decode in-key
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3) {
				// Decode nested CHOICE (INKey)
				_, n_inkey, _, tlvErr_inkey := ber.DecodeTLV(content[offset:])
				if tlvErr_inkey != nil {
					return fmt.Errorf("decoding in-key: %w", tlvErr_inkey)
				}
				var dec_inkey INKey
				if unmErr := dec_inkey.UnmarshalBER(content[offset : offset+n_inkey]); unmErr != nil {
					return fmt.Errorf("decoding in-key: %w", unmErr)
				}
				v.InKey = &dec_inkey
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
				_, n_fraudinfo, _, tlvErr_fraudinfo := ber.DecodeTLV(content[offset:])
				if tlvErr_fraudinfo != nil {
					return fmt.Errorf("decoding fraudInfo: %w", tlvErr_fraudinfo)
				}
				var dec_fraudinfo FraudInfo
				if unmErr := dec_fraudinfo.UnmarshalBER(content[offset : offset+n_fraudinfo]); unmErr != nil {
					return fmt.Errorf("decoding fraudInfo: %w", unmErr)
				}
				v.FraudInfo = &dec_fraudinfo
				offset += n_fraudinfo
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "ServiceWithInfo", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBERServiceListWithInfo encodes a ServiceListWithInfo list to BER.
func MarshalBERServiceListWithInfo(list ServiceListWithInfo) ([]byte, error) {
	var children []byte
	for _, elem := range list {
		enc, err := elem.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding element: %w", err)
		}
		children = append(children, enc...)
	}
	return ber.EncodeSequence(children), nil
}

// UnmarshalBERServiceListWithInfo decodes a ServiceListWithInfo list from BER.
func UnmarshalBERServiceListWithInfo(data []byte) (ServiceListWithInfo, error) {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return nil, fmt.Errorf("decoding ServiceListWithInfo: %w", err)
	}
	if total != len(data) {
		return nil, &ber.DecodeError{Offset: total, TypeName: "ServiceListWithInfo", Cause: ber.ErrExtraData}
	}
	var result ServiceListWithInfo
	offset := 0
	for offset < len(content) {
		var elem ServiceWithInfo
		_, n, _, tlvErr := ber.DecodeTLV(content[offset:])
		if tlvErr != nil {
			return nil, fmt.Errorf("decoding element TLV: %w", tlvErr)
		}
		if unmErr := elem.UnmarshalBER(content[offset : offset+n]); unmErr != nil {
			return nil, fmt.Errorf("decoding element: %w", unmErr)
		}
		result = append(result, elem)
		offset += n
	}
	return result, nil
}

// MarshalBER encodes INKey to BER format.
func (v *INKey) MarshalBER() ([]byte, error) {
	switch v.Choice {
	case INKeyChoiceMobileINKey:
		if v.MobileINKey == nil {
			return nil, fmt.Errorf("choice INKey: mobile-IN-key is nil")
		}
		enc_0, err := v.MobileINKey.MarshalBER()
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
			return nil, fmt.Errorf("choice INKey: sms-IN-key is nil")
		}
		enc_1, err := v.SmsINKey.MarshalBER()
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
	switch v.Choice {
	case INKeyChoiceMobileINKey:
		if v.MobileINKey == nil {
			return nil, fmt.Errorf("choice INKey: mobile-IN-key is nil")
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
		if derErr := ber.ValidateDERElement(enc_der_0); derErr != nil {
			return nil, fmt.Errorf("encoding mobile-IN-key as DER: %w", derErr)
		}
		return enc_der_0, nil
	case INKeyChoiceSmsINKey:
		if v.SmsINKey == nil {
			return nil, fmt.Errorf("choice INKey: sms-IN-key is nil")
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
		if derErr := ber.ValidateDERElement(enc_der_1); derErr != nil {
			return nil, fmt.Errorf("encoding sms-IN-key as DER: %w", derErr)
		}
		return enc_der_1, nil
	}
	encoded, err := v.MarshalBER()
	if err != nil {
		return nil, err
	}
	if err := ber.ValidateDERElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding INKey as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes INKey from BER/DER format.
func (v *INKey) UnmarshalBER(data []byte) error {
	if len(data) == 0 {
		return fmt.Errorf("empty data for INKey CHOICE")
	}
	choiceData := data
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for INKey: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData)
	if tlvErr != nil {
		return fmt.Errorf("decoding INKey CHOICE: %w", tlvErr)
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "INKey", Cause: ber.ErrExtraData}
	}

	if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2 && peekTag.Constructed == true {
		v.Choice = INKeyChoiceMobileINKey
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding mobile-IN-key: %w", tlvErr)
		}
		reconstructed := ber.EncodeSequence(rawVal)
		var dec MKey
		if unmErr := dec.UnmarshalBER(reconstructed); unmErr != nil {
			return fmt.Errorf("decoding mobile-IN-key: %w", unmErr)
		}
		v.MobileINKey = &dec
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3 && peekTag.Constructed == true {
		v.Choice = INKeyChoiceSmsINKey
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding sms-IN-key: %w", tlvErr)
		}
		reconstructed := ber.EncodeSequence(rawVal)
		var dec SMSKey
		if unmErr := dec.UnmarshalBER(reconstructed); unmErr != nil {
			return fmt.Errorf("decoding sms-IN-key: %w", unmErr)
		}
		v.SmsINKey = &dec
	} else {
		return fmt.Errorf("unknown tag %s for INKey CHOICE", peekTag)
	}
	return nil
}

// MarshalBER encodes MKey to BER format.
func (v *MKey) MarshalBER() ([]byte, error) {
	var children []byte
	if v.MKeyVer != nil {
		enc_mkeyver := ber.EncodeOctetString([]byte(*v.MKeyVer))
		retagged_enc_mkeyver, tagErr_enc_mkeyver := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_mkeyver)
		if tagErr_enc_mkeyver != nil {
			return nil, fmt.Errorf("encoding mKeyVer: %w", tagErr_enc_mkeyver)
		}
		enc_mkeyver = retagged_enc_mkeyver
		children = append(children, enc_mkeyver...)
	}
	if v.MmScfAddress != nil {
		enc_mmscfaddress := ber.EncodeOctetString([]byte(*v.MmScfAddress))
		retagged_enc_mmscfaddress, tagErr_enc_mmscfaddress := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_mmscfaddress)
		if tagErr_enc_mmscfaddress != nil {
			return nil, fmt.Errorf("encoding mmScfAddress: %w", tagErr_enc_mmscfaddress)
		}
		enc_mmscfaddress = retagged_enc_mmscfaddress
		children = append(children, enc_mmscfaddress...)
	}
	if v.MmTdpName != nil {
		enc_mmtdpname := ber.EncodeOctetString([]byte(*v.MmTdpName))
		retagged_enc_mmtdpname, tagErr_enc_mmtdpname := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_mmtdpname)
		if tagErr_enc_mmtdpname != nil {
			return nil, fmt.Errorf("encoding mmTdpName: %w", tagErr_enc_mmtdpname)
		}
		enc_mmtdpname = retagged_enc_mmtdpname
		children = append(children, enc_mmtdpname...)
	}
	if v.ServiceKey != nil {
		enc_servicekey := ber.EncodeInteger(int64(*v.ServiceKey))
		retagged_enc_servicekey, tagErr_enc_servicekey := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, enc_servicekey)
		if tagErr_enc_servicekey != nil {
			return nil, fmt.Errorf("encoding serviceKey: %w", tagErr_enc_servicekey)
		}
		enc_servicekey = retagged_enc_servicekey
		children = append(children, enc_servicekey...)
	}
	if v.LocupType != nil {
		enc_locuptype := ber.EncodeOctetString([]byte(*v.LocupType))
		retagged_enc_locuptype, tagErr_enc_locuptype := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, enc_locuptype)
		if tagErr_enc_locuptype != nil {
			return nil, fmt.Errorf("encoding locupType: %w", tagErr_enc_locuptype)
		}
		enc_locuptype = retagged_enc_locuptype
		children = append(children, enc_locuptype...)
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

// MarshalDER encodes MKey to DER format.
func (v *MKey) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	encoded, err := v.MarshalBER()
	if err != nil {
		return nil, err
	}
	if err := ber.ValidateDERElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding MKey as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes MKey from BER/DER format.
func (v *MKey) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
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
				decodedTag_mkeyver, n_mkeyver, rawVal_mkeyver, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding mKeyVer: %w", err)
				}
				if decodedTag_mkeyver.Class != tag.ClassContextSpecific || decodedTag_mkeyver.Number != 0 {
					return fmt.Errorf("decoding mKeyVer: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_mkeyver)
				}
				tmp_mkeyver := MKeyVer(rawVal_mkeyver)
				v.MKeyVer = &tmp_mkeyver
				offset += n_mkeyver
			}
		}
	}
	// Decode mmScfAddress
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
				decodedTag_mmscfaddress, n_mmscfaddress, rawVal_mmscfaddress, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding mmScfAddress: %w", err)
				}
				if decodedTag_mmscfaddress.Class != tag.ClassContextSpecific || decodedTag_mmscfaddress.Number != 1 {
					return fmt.Errorf("decoding mmScfAddress: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_mmscfaddress)
				}
				tmp_mmscfaddress := ISDNAddressString4(rawVal_mmscfaddress)
				v.MmScfAddress = &tmp_mmscfaddress
				offset += n_mmscfaddress
			}
		}
	}
	// Decode mmTdpName
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2 {
				decodedTag_mmtdpname, n_mmtdpname, rawVal_mmtdpname, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding mmTdpName: %w", err)
				}
				if decodedTag_mmtdpname.Class != tag.ClassContextSpecific || decodedTag_mmtdpname.Number != 2 {
					return fmt.Errorf("decoding mmTdpName: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_mmtdpname)
				}
				tmp_mmtdpname := MmTdpName(rawVal_mmtdpname)
				v.MmTdpName = &tmp_mmtdpname
				offset += n_mmtdpname
			}
		}
	}
	// Decode serviceKey
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3 {
				decodedTag_servicekey, n_servicekey, rawVal_servicekey, err := ber.DecodeTLV(content[offset:])
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
				offset += n_servicekey
			}
		}
	}
	// Decode locupType
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4 {
				decodedTag_locuptype, n_locuptype, rawVal_locuptype, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding locupType: %w", err)
				}
				if decodedTag_locuptype.Class != tag.ClassContextSpecific || decodedTag_locuptype.Number != 4 {
					return fmt.Errorf("decoding locupType: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_locuptype)
				}
				tmp_locuptype := LocupType(rawVal_locuptype)
				v.LocupType = &tmp_locuptype
				offset += n_locuptype
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "MKey", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes SMSKey to BER format.
func (v *SMSKey) MarshalBER() ([]byte, error) {
	var children []byte
	if v.MmSCPAddress != nil {
		enc_mmscpaddress := ber.EncodeOctetString([]byte(*v.MmSCPAddress))
		retagged_enc_mmscpaddress, tagErr_enc_mmscpaddress := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_mmscpaddress)
		if tagErr_enc_mmscpaddress != nil {
			return nil, fmt.Errorf("encoding mmSCPAddress: %w", tagErr_enc_mmscpaddress)
		}
		enc_mmscpaddress = retagged_enc_mmscpaddress
		children = append(children, enc_mmscpaddress...)
	}
	if v.SmsTdpName != nil {
		enc_smstdpname := ber.EncodeOctetString([]byte(*v.SmsTdpName))
		retagged_enc_smstdpname, tagErr_enc_smstdpname := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_smstdpname)
		if tagErr_enc_smstdpname != nil {
			return nil, fmt.Errorf("encoding smsTdpName: %w", tagErr_enc_smstdpname)
		}
		enc_smstdpname = retagged_enc_smstdpname
		children = append(children, enc_smstdpname...)
	}
	if v.ServiceKey != nil {
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

// MarshalDER encodes SMSKey to DER format.
func (v *SMSKey) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	encoded, err := v.MarshalBER()
	if err != nil {
		return nil, err
	}
	if err := ber.ValidateDERElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding SMSKey as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes SMSKey from BER/DER format.
func (v *SMSKey) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
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
				decodedTag_mmscpaddress, n_mmscpaddress, rawVal_mmscpaddress, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding mmSCPAddress: %w", err)
				}
				if decodedTag_mmscpaddress.Class != tag.ClassContextSpecific || decodedTag_mmscpaddress.Number != 0 {
					return fmt.Errorf("decoding mmSCPAddress: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_mmscpaddress)
				}
				tmp_mmscpaddress := ISDNAddressString4(rawVal_mmscpaddress)
				v.MmSCPAddress = &tmp_mmscpaddress
				offset += n_mmscpaddress
			}
		}
	}
	// Decode smsTdpName
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
				decodedTag_smstdpname, n_smstdpname, rawVal_smstdpname, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding smsTdpName: %w", err)
				}
				if decodedTag_smstdpname.Class != tag.ClassContextSpecific || decodedTag_smstdpname.Number != 1 {
					return fmt.Errorf("decoding smsTdpName: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_smstdpname)
				}
				tmp_smstdpname := SmsTdpName(rawVal_smstdpname)
				v.SmsTdpName = &tmp_smstdpname
				offset += n_smstdpname
			}
		}
	}
	// Decode serviceKey
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2 {
				decodedTag_servicekey, n_servicekey, rawVal_servicekey, err := ber.DecodeTLV(content[offset:])
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
				offset += n_servicekey
			}
		}
	}
	// Decode mmsFlag
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3 {
				decodedTag_mmsflag, n_mmsflag, rawVal_mmsflag, err := ber.DecodeTLV(content[offset:])
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
				offset += n_mmsflag
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "SMSKey", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes USSDExtension to BER format.
func (v *USSDExtension) MarshalBER() ([]byte, error) {
	var children []byte
	if v.RoutingCategory != nil {
		enc_routingcategory := ber.EncodeOctetString([]byte(*v.RoutingCategory))
		retagged_enc_routingcategory, tagErr_enc_routingcategory := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_routingcategory)
		if tagErr_enc_routingcategory != nil {
			return nil, fmt.Errorf("encoding routingCategory: %w", tagErr_enc_routingcategory)
		}
		enc_routingcategory = retagged_enc_routingcategory
		children = append(children, enc_routingcategory...)
	}
	if v.CellId != nil {
		enc_cellid := ber.EncodeOctetString([]byte(*v.CellId))
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
		_, n, _, extErr := ber.DecodeTLV(ext)
		if extErr != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, extErr)
		}
		if n != len(ext) {
			return nil, fmt.Errorf("encoding extension %d: %w", i, ber.ErrExtraData)
		}
		children = append(children, ext...)
	}
	return ber.EncodeConstructed(tag.Tag{Class: tag.ClassPrivate, Number: 10, Constructed: true}, children), nil
}

// MarshalDER encodes USSDExtension to DER format.
func (v *USSDExtension) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	encoded, err := v.MarshalBER()
	if err != nil {
		return nil, err
	}
	if err := ber.ValidateDERElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding USSDExtension as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes USSDExtension from BER/DER format.
func (v *USSDExtension) UnmarshalBER(data []byte) error {
	decodedTag, content, total, err := ber.DecodeConstructedContent(data)
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
				decodedTag_routingcategory, n_routingcategory, rawVal_routingcategory, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding routingCategory: %w", err)
				}
				if decodedTag_routingcategory.Class != tag.ClassContextSpecific || decodedTag_routingcategory.Number != 0 {
					return fmt.Errorf("decoding routingCategory: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_routingcategory)
				}
				tmp_routingcategory := RoutingCategory(rawVal_routingcategory)
				v.RoutingCategory = &tmp_routingcategory
				offset += n_routingcategory
			}
		}
	}
	// Decode cellId
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
				decodedTag_cellid, n_cellid, rawVal_cellid, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding cellId: %w", err)
				}
				if decodedTag_cellid.Class != tag.ClassContextSpecific || decodedTag_cellid.Number != 1 {
					return fmt.Errorf("decoding cellId: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_cellid)
				}
				tmp_cellid := CellGlobalIdOrServiceAreaIdFixedLength4(rawVal_cellid)
				v.CellId = &tmp_cellid
				offset += n_cellid
			}
		}
	}
	// Decode sai-Present
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2 {
				decodedTag_saipresent, n_saipresent, rawVal_saipresent, err := ber.DecodeTLV(content[offset:])
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
				offset += n_saipresent
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "USSDExtension", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes HOExt to BER format.
func (v *HOExt) MarshalBER() ([]byte, error) {
	var children []byte
	if v.MapOpt != nil {
		enc_mapopt := ber.EncodeOctetString([]byte(*v.MapOpt))
		retagged_enc_mapopt, tagErr_enc_mapopt := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_mapopt)
		if tagErr_enc_mapopt != nil {
			return nil, fmt.Errorf("encoding map-Opt: %w", tagErr_enc_mapopt)
		}
		enc_mapopt = retagged_enc_mapopt
		children = append(children, enc_mapopt...)
	}
	if v.CodecList != nil {
		enc_codeclist, err := MarshalBERCodecListExt(v.CodecList)
		if err != nil {
			return nil, fmt.Errorf("encoding codec-List: %w", err)
		}
		if v.CodecListIndef_ {
			// Strip the outer SEQUENCE tag from marshalBER output to get raw children.
			_, _, seqContent_, tlvErr_ := ber.DecodeTLV(enc_codeclist)
			if tlvErr_ != nil {
				return nil, tlvErr_
			}
			enc_codeclist = ber.EncodeConstructedIndefinite(tag.Tag{Class: tag.ClassContextSpecific, Number: 1}, seqContent_)
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
		enc_selectedcodec, err := v.SelectedCodec.MarshalBER()
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
		enc_umaipaddress := ber.EncodeOctetString(v.UmaIpAddress)
		retagged_enc_umaipaddress, tagErr_enc_umaipaddress := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, enc_umaipaddress)
		if tagErr_enc_umaipaddress != nil {
			return nil, fmt.Errorf("encoding uma-ip-address: %w", tagErr_enc_umaipaddress)
		}
		enc_umaipaddress = retagged_enc_umaipaddress
		children = append(children, enc_umaipaddress...)
	}
	if v.UmaIpPortNb != nil {
		enc_umaipportnb := ber.EncodeInteger(int64(*v.UmaIpPortNb))
		retagged_enc_umaipportnb, tagErr_enc_umaipportnb := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 5, enc_umaipportnb)
		if tagErr_enc_umaipportnb != nil {
			return nil, fmt.Errorf("encoding uma-ip-port-nb: %w", tagErr_enc_umaipportnb)
		}
		enc_umaipportnb = retagged_enc_umaipportnb
		children = append(children, enc_umaipportnb...)
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
	return ber.EncodeConstructed(tag.Tag{Class: tag.ClassPrivate, Number: 0, Constructed: true}, children), nil
}

// MarshalDER encodes HOExt to DER format.
func (v *HOExt) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// ITU-T X.690 (02/2021) Section 10.1 requires DER length forms to be definite.
	derValue := *v
	derValue.CodecListIndef_ = false
	v = &derValue
	encoded, err := v.MarshalBER()
	if err != nil {
		return nil, err
	}
	if err := ber.ValidateDERElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding HOExt as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes HOExt from BER/DER format.
func (v *HOExt) UnmarshalBER(data []byte) error {
	decodedTag, content, total, err := ber.DecodeConstructedContent(data)
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
				decodedTag_mapopt, n_mapopt, rawVal_mapopt, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding map-Opt: %w", err)
				}
				if decodedTag_mapopt.Class != tag.ClassContextSpecific || decodedTag_mapopt.Number != 0 {
					return fmt.Errorf("decoding map-Opt: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_mapopt)
				}
				tmp_mapopt := MapOptFields(rawVal_mapopt)
				v.MapOpt = &tmp_mapopt
				offset += n_mapopt
			}
		}
	}
	// Decode codec-List
	v.CodecListIndef_ = false
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
				decodedTag_codeclist, n_codeclist, rawVal_codeclist, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding codec-List: %w", err)
				}
				if decodedTag_codeclist.Class != tag.ClassContextSpecific || decodedTag_codeclist.Number != 1 || decodedTag_codeclist.Constructed != true {
					return fmt.Errorf("decoding codec-List: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_codeclist)
				}
				reconstructed_codeclist := ber.EncodeSequence(rawVal_codeclist)
				dec_codeclist, unmErr := UnmarshalBERCodecListExt(reconstructed_codeclist)
				if unmErr != nil {
					return fmt.Errorf("decoding codec-List: %w", unmErr)
				}
				v.CodecList = dec_codeclist
				{
					_, tagSz_, _ := ber.DecodeTag(content[offset:])
					if offset+tagSz_ < len(content) && content[offset+tagSz_] == 0x80 {
						v.CodecListIndef_ = true
					}
				}
				offset += n_codeclist
			}
		}
	}
	// Decode selected-Codec
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2 {
				decodedTag_selectedcodec, n_selectedcodec, rawVal_selectedcodec, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding selected-Codec: %w", err)
				}
				if decodedTag_selectedcodec.Class != tag.ClassContextSpecific || decodedTag_selectedcodec.Number != 2 || decodedTag_selectedcodec.Constructed != true {
					return fmt.Errorf("decoding selected-Codec: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_selectedcodec)
				}
				reconstructed_selectedcodec := ber.EncodeSequence(rawVal_selectedcodec)
				var dec_selectedcodec SelectedCodec
				if unmErr := dec_selectedcodec.UnmarshalBER(reconstructed_selectedcodec); unmErr != nil {
					return fmt.Errorf("decoding selected-Codec: %w", unmErr)
				}
				v.SelectedCodec = &dec_selectedcodec
				offset += n_selectedcodec
			}
		}
	}
	// Decode uma-access
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3 {
				decodedTag_umaaccess, n_umaaccess, rawVal_umaaccess, err := ber.DecodeTLV(content[offset:])
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
				offset += n_umaaccess
			}
		}
	}
	// Decode uma-ip-address
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4 {
				decodedTag_umaipaddress, n_umaipaddress, rawVal_umaipaddress, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding uma-ip-address: %w", err)
				}
				if decodedTag_umaipaddress.Class != tag.ClassContextSpecific || decodedTag_umaipaddress.Number != 4 {
					return fmt.Errorf("decoding uma-ip-address: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_umaipaddress)
				}
				tmp_umaipaddress := rawVal_umaipaddress
				v.UmaIpAddress = tmp_umaipaddress
				offset += n_umaipaddress
			}
		}
	}
	// Decode uma-ip-port-nb
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 5 {
				decodedTag_umaipportnb, n_umaipportnb, rawVal_umaipportnb, err := ber.DecodeTLV(content[offset:])
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
				offset += n_umaipportnb
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "HOExt", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBERCodecListExt encodes a CodecListExt list to BER.
func MarshalBERCodecListExt(list CodecListExt) ([]byte, error) {
	var children []byte
	for _, elem := range list {
		children = append(children, ber.EncodeOctetString([]byte(elem))...)
	}
	return ber.EncodeSequence(children), nil
}

// UnmarshalBERCodecListExt decodes a CodecListExt list from BER.
func UnmarshalBERCodecListExt(data []byte) (CodecListExt, error) {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return nil, fmt.Errorf("decoding CodecListExt: %w", err)
	}
	if total != len(data) {
		return nil, &ber.DecodeError{Offset: total, TypeName: "CodecListExt", Cause: ber.ErrExtraData}
	}
	var result CodecListExt
	offset := 0
	for offset < len(content) {
		val, n, osErr := ber.DecodeOctetString(content[offset:])
		if osErr != nil {
			return nil, fmt.Errorf("decoding element: %w", osErr)
		}
		result = append(result, CodecExt(val))
		offset += n
	}
	return result, nil
}

// MarshalBER encodes SelectedCodec to BER format.
func (v *SelectedCodec) MarshalBER() ([]byte, error) {
	var children []byte
	enc_codec := ber.EncodeOctetString([]byte(v.Codec))
	retagged_enc_codec, tagErr_enc_codec := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_codec)
	if tagErr_enc_codec != nil {
		return nil, fmt.Errorf("encoding codec: %w", tagErr_enc_codec)
	}
	enc_codec = retagged_enc_codec
	children = append(children, enc_codec...)
	enc_modes := ber.EncodeOctetString([]byte(v.Modes))
	retagged_enc_modes, tagErr_enc_modes := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_modes)
	if tagErr_enc_modes != nil {
		return nil, fmt.Errorf("encoding modes: %w", tagErr_enc_modes)
	}
	enc_modes = retagged_enc_modes
	children = append(children, enc_modes...)
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

// MarshalDER encodes SelectedCodec to DER format.
func (v *SelectedCodec) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	encoded, err := v.MarshalBER()
	if err != nil {
		return nil, err
	}
	if err := ber.ValidateDERElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding SelectedCodec as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes SelectedCodec from BER/DER format.
func (v *SelectedCodec) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
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
	decodedTag_codec, n_codec, rawVal_codec, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding codec: %w", err)
	}
	if decodedTag_codec.Class != tag.ClassContextSpecific || decodedTag_codec.Number != 0 {
		return fmt.Errorf("decoding codec: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_codec)
	}
	v.Codec = CodecExt(rawVal_codec)
	offset += n_codec
	// Decode modes
	if offset >= len(content) {
		return fmt.Errorf("missing required field modes")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 1 {
			return fmt.Errorf("expected tag [%s %d] for modes, got %s", "CONTEXT", 1, reqTag_)
		}
	}
	decodedTag_modes, n_modes, rawVal_modes, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding modes: %w", err)
	}
	if decodedTag_modes.Class != tag.ClassContextSpecific || decodedTag_modes.Number != 1 {
		return fmt.Errorf("decoding modes: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_modes)
	}
	v.Modes = Modes(rawVal_modes)
	offset += n_modes
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "SelectedCodec", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes AbsentSubscriberExt to BER format.
func (v *AbsentSubscriberExt) MarshalBER() ([]byte, error) {
	var children []byte
	if v.OlcmInfoTable != nil {
		enc_olcminfotable, err := MarshalBEROlcmInfoTable(v.OlcmInfoTable)
		if err != nil {
			return nil, fmt.Errorf("encoding olcmInfoTable: %w", err)
		}
		if v.OlcmInfoTableIndef_ {
			// Strip the outer SEQUENCE tag from marshalBER output to get raw children.
			_, _, seqContent_, tlvErr_ := ber.DecodeTLV(enc_olcminfotable)
			if tlvErr_ != nil {
				return nil, tlvErr_
			}
			enc_olcminfotable = ber.EncodeConstructedIndefinite(tag.Tag{Class: tag.ClassContextSpecific, Number: 0}, seqContent_)
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
		enc_imsi := ber.EncodeOctetString([]byte(*v.Imsi))
		retagged_enc_imsi, tagErr_enc_imsi := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_imsi)
		if tagErr_enc_imsi != nil {
			return nil, fmt.Errorf("encoding imsi: %w", tagErr_enc_imsi)
		}
		enc_imsi = retagged_enc_imsi
		children = append(children, enc_imsi...)
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
	return ber.EncodeConstructed(tag.Tag{Class: tag.ClassPrivate, Number: 0, Constructed: true}, children), nil
}

// MarshalDER encodes AbsentSubscriberExt to DER format.
func (v *AbsentSubscriberExt) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// ITU-T X.690 (02/2021) Section 10.1 requires DER length forms to be definite.
	derValue := *v
	derValue.OlcmInfoTableIndef_ = false
	v = &derValue
	encoded, err := v.MarshalBER()
	if err != nil {
		return nil, err
	}
	if err := ber.ValidateDERElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding AbsentSubscriberExt as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes AbsentSubscriberExt from BER/DER format.
func (v *AbsentSubscriberExt) UnmarshalBER(data []byte) error {
	decodedTag, content, total, err := ber.DecodeConstructedContent(data)
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
				decodedTag_olcminfotable, n_olcminfotable, rawVal_olcminfotable, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding olcmInfoTable: %w", err)
				}
				if decodedTag_olcminfotable.Class != tag.ClassContextSpecific || decodedTag_olcminfotable.Number != 0 || decodedTag_olcminfotable.Constructed != true {
					return fmt.Errorf("decoding olcmInfoTable: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_olcminfotable)
				}
				reconstructed_olcminfotable := ber.EncodeSequence(rawVal_olcminfotable)
				dec_olcminfotable, unmErr := UnmarshalBEROlcmInfoTable(reconstructed_olcminfotable)
				if unmErr != nil {
					return fmt.Errorf("decoding olcmInfoTable: %w", unmErr)
				}
				v.OlcmInfoTable = dec_olcminfotable
				{
					_, tagSz_, _ := ber.DecodeTag(content[offset:])
					if offset+tagSz_ < len(content) && content[offset+tagSz_] == 0x80 {
						v.OlcmInfoTableIndef_ = true
					}
				}
				offset += n_olcminfotable
			}
		}
	}
	// Decode imsi
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
				decodedTag_imsi, n_imsi, rawVal_imsi, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding imsi: %w", err)
				}
				if decodedTag_imsi.Class != tag.ClassContextSpecific || decodedTag_imsi.Number != 1 {
					return fmt.Errorf("decoding imsi: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_imsi)
				}
				tmp_imsi := IMSI4(rawVal_imsi)
				v.Imsi = &tmp_imsi
				offset += n_imsi
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "AbsentSubscriberExt", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes ErrOlcmInfoTableExt to BER format.
func (v *ErrOlcmInfoTableExt) MarshalBER() ([]byte, error) {
	var children []byte
	if v.OlcmInfoTable != nil {
		enc_olcminfotable, err := MarshalBEROlcmInfoTable(v.OlcmInfoTable)
		if err != nil {
			return nil, fmt.Errorf("encoding olcmInfoTable: %w", err)
		}
		if v.OlcmInfoTableIndef_ {
			// Strip the outer SEQUENCE tag from marshalBER output to get raw children.
			_, _, seqContent_, tlvErr_ := ber.DecodeTLV(enc_olcminfotable)
			if tlvErr_ != nil {
				return nil, tlvErr_
			}
			enc_olcminfotable = ber.EncodeConstructedIndefinite(tag.Tag{Class: tag.ClassContextSpecific, Number: 0}, seqContent_)
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
		enc_imsi := ber.EncodeOctetString([]byte(*v.Imsi))
		retagged_enc_imsi, tagErr_enc_imsi := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_imsi)
		if tagErr_enc_imsi != nil {
			return nil, fmt.Errorf("encoding imsi: %w", tagErr_enc_imsi)
		}
		enc_imsi = retagged_enc_imsi
		children = append(children, enc_imsi...)
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
	return ber.EncodeConstructed(tag.Tag{Class: tag.ClassPrivate, Number: 0, Constructed: true}, children), nil
}

// MarshalDER encodes ErrOlcmInfoTableExt to DER format.
func (v *ErrOlcmInfoTableExt) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// ITU-T X.690 (02/2021) Section 10.1 requires DER length forms to be definite.
	derValue := *v
	derValue.OlcmInfoTableIndef_ = false
	v = &derValue
	encoded, err := v.MarshalBER()
	if err != nil {
		return nil, err
	}
	if err := ber.ValidateDERElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding ErrOlcmInfoTableExt as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes ErrOlcmInfoTableExt from BER/DER format.
func (v *ErrOlcmInfoTableExt) UnmarshalBER(data []byte) error {
	decodedTag, content, total, err := ber.DecodeConstructedContent(data)
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
				decodedTag_olcminfotable, n_olcminfotable, rawVal_olcminfotable, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding olcmInfoTable: %w", err)
				}
				if decodedTag_olcminfotable.Class != tag.ClassContextSpecific || decodedTag_olcminfotable.Number != 0 || decodedTag_olcminfotable.Constructed != true {
					return fmt.Errorf("decoding olcmInfoTable: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_olcminfotable)
				}
				reconstructed_olcminfotable := ber.EncodeSequence(rawVal_olcminfotable)
				dec_olcminfotable, unmErr := UnmarshalBEROlcmInfoTable(reconstructed_olcminfotable)
				if unmErr != nil {
					return fmt.Errorf("decoding olcmInfoTable: %w", unmErr)
				}
				v.OlcmInfoTable = dec_olcminfotable
				{
					_, tagSz_, _ := ber.DecodeTag(content[offset:])
					if offset+tagSz_ < len(content) && content[offset+tagSz_] == 0x80 {
						v.OlcmInfoTableIndef_ = true
					}
				}
				offset += n_olcminfotable
			}
		}
	}
	// Decode imsi
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
				decodedTag_imsi, n_imsi, rawVal_imsi, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding imsi: %w", err)
				}
				if decodedTag_imsi.Class != tag.ClassContextSpecific || decodedTag_imsi.Number != 1 {
					return fmt.Errorf("decoding imsi: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_imsi)
				}
				tmp_imsi := IMSI4(rawVal_imsi)
				v.Imsi = &tmp_imsi
				offset += n_imsi
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "ErrOlcmInfoTableExt", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes RoutingCategoryExt to BER format.
func (v *RoutingCategoryExt) MarshalBER() ([]byte, error) {
	var children []byte
	if v.RoutingCategory != nil {
		enc_routingcategory := ber.EncodeOctetString([]byte(*v.RoutingCategory))
		retagged_enc_routingcategory, tagErr_enc_routingcategory := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_routingcategory)
		if tagErr_enc_routingcategory != nil {
			return nil, fmt.Errorf("encoding routingCategory: %w", tagErr_enc_routingcategory)
		}
		enc_routingcategory = retagged_enc_routingcategory
		children = append(children, enc_routingcategory...)
	}
	if v.ExtRoutingCategory != nil {
		enc_extroutingcategory := ber.EncodeInteger(int64(*v.ExtRoutingCategory))
		retagged_enc_extroutingcategory, tagErr_enc_extroutingcategory := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_extroutingcategory)
		if tagErr_enc_extroutingcategory != nil {
			return nil, fmt.Errorf("encoding extRoutingCategory: %w", tagErr_enc_extroutingcategory)
		}
		enc_extroutingcategory = retagged_enc_extroutingcategory
		children = append(children, enc_extroutingcategory...)
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
	return ber.EncodeConstructed(tag.Tag{Class: tag.ClassPrivate, Number: 0, Constructed: true}, children), nil
}

// MarshalDER encodes RoutingCategoryExt to DER format.
func (v *RoutingCategoryExt) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	encoded, err := v.MarshalBER()
	if err != nil {
		return nil, err
	}
	if err := ber.ValidateDERElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding RoutingCategoryExt as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes RoutingCategoryExt from BER/DER format.
func (v *RoutingCategoryExt) UnmarshalBER(data []byte) error {
	decodedTag, content, total, err := ber.DecodeConstructedContent(data)
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
				decodedTag_routingcategory, n_routingcategory, rawVal_routingcategory, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding routingCategory: %w", err)
				}
				if decodedTag_routingcategory.Class != tag.ClassContextSpecific || decodedTag_routingcategory.Number != 0 {
					return fmt.Errorf("decoding routingCategory: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_routingcategory)
				}
				tmp_routingcategory := RoutingCategory(rawVal_routingcategory)
				v.RoutingCategory = &tmp_routingcategory
				offset += n_routingcategory
			}
		}
	}
	// Decode extRoutingCategory
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
				decodedTag_extroutingcategory, n_extroutingcategory, rawVal_extroutingcategory, err := ber.DecodeTLV(content[offset:])
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
				offset += n_extroutingcategory
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "RoutingCategoryExt", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes SriForSMArgExt to BER format.
func (v *SriForSMArgExt) MarshalBER() ([]byte, error) {
	var children []byte
	if v.CfuSMSCounter != nil {
		enc_cfusmscounter := ber.EncodeOctetString([]byte(*v.CfuSMSCounter))
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
		_, n, _, extErr := ber.DecodeTLV(ext)
		if extErr != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, extErr)
		}
		if n != len(ext) {
			return nil, fmt.Errorf("encoding extension %d: %w", i, ber.ErrExtraData)
		}
		children = append(children, ext...)
	}
	return ber.EncodeConstructed(tag.Tag{Class: tag.ClassPrivate, Number: 0, Constructed: true}, children), nil
}

// MarshalDER encodes SriForSMArgExt to DER format.
func (v *SriForSMArgExt) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	encoded, err := v.MarshalBER()
	if err != nil {
		return nil, err
	}
	if err := ber.ValidateDERElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding SriForSMArgExt as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes SriForSMArgExt from BER/DER format.
func (v *SriForSMArgExt) UnmarshalBER(data []byte) error {
	decodedTag, content, total, err := ber.DecodeConstructedContent(data)
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
				decodedTag_cfusmscounter, n_cfusmscounter, rawVal_cfusmscounter, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding cfuSMSCounter: %w", err)
				}
				if decodedTag_cfusmscounter.Class != tag.ClassContextSpecific || decodedTag_cfusmscounter.Number != 0 {
					return fmt.Errorf("decoding cfuSMSCounter: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_cfusmscounter)
				}
				tmp_cfusmscounter := CfuSMSCounter(rawVal_cfusmscounter)
				v.CfuSMSCounter = &tmp_cfusmscounter
				offset += n_cfusmscounter
			}
		}
	}
	// Decode cfusmcfo
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2 {
				decodedTag_cfusmcfo, n_cfusmcfo, rawVal_cfusmcfo, err := ber.DecodeTLV(content[offset:])
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
				offset += n_cfusmcfo
			}
		}
	}
	// Decode memberInterrogate
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3 {
				decodedTag_memberinterrogate, n_memberinterrogate, rawVal_memberinterrogate, err := ber.DecodeTLV(content[offset:])
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
				offset += n_memberinterrogate
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "SriForSMArgExt", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes ReportSMDelStatArgExt to BER format.
func (v *ReportSMDelStatArgExt) MarshalBER() ([]byte, error) {
	var children []byte
	if v.CfuSMSCounter != nil {
		enc_cfusmscounter := ber.EncodeOctetString([]byte(*v.CfuSMSCounter))
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
		_, n, _, extErr := ber.DecodeTLV(ext)
		if extErr != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, extErr)
		}
		if n != len(ext) {
			return nil, fmt.Errorf("encoding extension %d: %w", i, ber.ErrExtraData)
		}
		children = append(children, ext...)
	}
	return ber.EncodeConstructed(tag.Tag{Class: tag.ClassPrivate, Number: 0, Constructed: true}, children), nil
}

// MarshalDER encodes ReportSMDelStatArgExt to DER format.
func (v *ReportSMDelStatArgExt) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	encoded, err := v.MarshalBER()
	if err != nil {
		return nil, err
	}
	if err := ber.ValidateDERElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding ReportSMDelStatArgExt as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes ReportSMDelStatArgExt from BER/DER format.
func (v *ReportSMDelStatArgExt) UnmarshalBER(data []byte) error {
	decodedTag, content, total, err := ber.DecodeConstructedContent(data)
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
				decodedTag_cfusmscounter, n_cfusmscounter, rawVal_cfusmscounter, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding cfuSMSCounter: %w", err)
				}
				if decodedTag_cfusmscounter.Class != tag.ClassContextSpecific || decodedTag_cfusmscounter.Number != 0 {
					return fmt.Errorf("decoding cfuSMSCounter: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_cfusmscounter)
				}
				tmp_cfusmscounter := CfuSMSCounter(rawVal_cfusmscounter)
				v.CfuSMSCounter = &tmp_cfusmscounter
				offset += n_cfusmscounter
			}
		}
	}
	// Decode cfusmcfo
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2 {
				decodedTag_cfusmcfo, n_cfusmcfo, rawVal_cfusmcfo, err := ber.DecodeTLV(content[offset:])
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
				offset += n_cfusmcfo
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "ReportSMDelStatArgExt", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes MOForwardSMArgExt to BER format.
func (v *MOForwardSMArgExt) MarshalBER() ([]byte, error) {
	var children []byte
	if v.LocationAreaCode != nil {
		enc_locationareacode := ber.EncodeOctetString([]byte(*v.LocationAreaCode))
		retagged_enc_locationareacode, tagErr_enc_locationareacode := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_locationareacode)
		if tagErr_enc_locationareacode != nil {
			return nil, fmt.Errorf("encoding locationAreaCode: %w", tagErr_enc_locationareacode)
		}
		enc_locationareacode = retagged_enc_locationareacode
		children = append(children, enc_locationareacode...)
	}
	if v.CellId != nil {
		enc_cellid := ber.EncodeOctetString([]byte(*v.CellId))
		retagged_enc_cellid, tagErr_enc_cellid := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_cellid)
		if tagErr_enc_cellid != nil {
			return nil, fmt.Errorf("encoding cellId: %w", tagErr_enc_cellid)
		}
		enc_cellid = retagged_enc_cellid
		children = append(children, enc_cellid...)
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
	return ber.EncodeConstructed(tag.Tag{Class: tag.ClassPrivate, Number: 0, Constructed: true}, children), nil
}

// MarshalDER encodes MOForwardSMArgExt to DER format.
func (v *MOForwardSMArgExt) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	encoded, err := v.MarshalBER()
	if err != nil {
		return nil, err
	}
	if err := ber.ValidateDERElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding MOForwardSMArgExt as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes MOForwardSMArgExt from BER/DER format.
func (v *MOForwardSMArgExt) UnmarshalBER(data []byte) error {
	decodedTag, content, total, err := ber.DecodeConstructedContent(data)
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
				decodedTag_locationareacode, n_locationareacode, rawVal_locationareacode, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding locationAreaCode: %w", err)
				}
				if decodedTag_locationareacode.Class != tag.ClassContextSpecific || decodedTag_locationareacode.Number != 0 {
					return fmt.Errorf("decoding locationAreaCode: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_locationareacode)
				}
				tmp_locationareacode := LocationAreaCode(rawVal_locationareacode)
				v.LocationAreaCode = &tmp_locationareacode
				offset += n_locationareacode
			}
		}
	}
	// Decode cellId
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
				decodedTag_cellid, n_cellid, rawVal_cellid, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding cellId: %w", err)
				}
				if decodedTag_cellid.Class != tag.ClassContextSpecific || decodedTag_cellid.Number != 1 {
					return fmt.Errorf("decoding cellId: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_cellid)
				}
				tmp_cellid := CellGlobalIdOrServiceAreaIdFixedLength4(rawVal_cellid)
				v.CellId = &tmp_cellid
				offset += n_cellid
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "MOForwardSMArgExt", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes UdlArgExt to BER format.
func (v *UdlArgExt) MarshalBER() ([]byte, error) {
	var children []byte
	if v.Lai != nil {
		enc_lai := ber.EncodeOctetString([]byte(*v.Lai))
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
		_, n, _, extErr := ber.DecodeTLV(ext)
		if extErr != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, extErr)
		}
		if n != len(ext) {
			return nil, fmt.Errorf("encoding extension %d: %w", i, ber.ErrExtraData)
		}
		children = append(children, ext...)
	}
	return ber.EncodeConstructed(tag.Tag{Class: tag.ClassPrivate, Number: 0, Constructed: true}, children), nil
}

// MarshalDER encodes UdlArgExt to DER format.
func (v *UdlArgExt) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	encoded, err := v.MarshalBER()
	if err != nil {
		return nil, err
	}
	if err := ber.ValidateDERElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding UdlArgExt as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes UdlArgExt from BER/DER format.
func (v *UdlArgExt) UnmarshalBER(data []byte) error {
	decodedTag, content, total, err := ber.DecodeConstructedContent(data)
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
				decodedTag_lai, n_lai, rawVal_lai, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding lai: %w", err)
				}
				if decodedTag_lai.Class != tag.ClassContextSpecific || decodedTag_lai.Number != 0 {
					return fmt.Errorf("decoding lai: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_lai)
				}
				tmp_lai := LAIFixedLength4(rawVal_lai)
				v.Lai = &tmp_lai
				offset += n_lai
			}
		}
	}
	// Decode sendImmResp
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
				decodedTag_sendimmresp, n_sendimmresp, rawVal_sendimmresp, err := ber.DecodeTLV(content[offset:])
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
				offset += n_sendimmresp
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "UdlArgExt", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes RoamNotAllowedExt to BER format.
func (v *RoamNotAllowedExt) MarshalBER() ([]byte, error) {
	var children []byte
	if v.RejectCause != nil {
		enc_rejectcause := ber.EncodeOctetString(v.RejectCause)
		retagged_enc_rejectcause, tagErr_enc_rejectcause := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_rejectcause)
		if tagErr_enc_rejectcause != nil {
			return nil, fmt.Errorf("encoding rejectCause: %w", tagErr_enc_rejectcause)
		}
		enc_rejectcause = retagged_enc_rejectcause
		children = append(children, enc_rejectcause...)
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
	return ber.EncodeConstructed(tag.Tag{Class: tag.ClassPrivate, Number: 0, Constructed: true}, children), nil
}

// MarshalDER encodes RoamNotAllowedExt to DER format.
func (v *RoamNotAllowedExt) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	encoded, err := v.MarshalBER()
	if err != nil {
		return nil, err
	}
	if err := ber.ValidateDERElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding RoamNotAllowedExt as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes RoamNotAllowedExt from BER/DER format.
func (v *RoamNotAllowedExt) UnmarshalBER(data []byte) error {
	decodedTag, content, total, err := ber.DecodeConstructedContent(data)
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
				decodedTag_rejectcause, n_rejectcause, rawVal_rejectcause, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding rejectCause: %w", err)
				}
				if decodedTag_rejectcause.Class != tag.ClassContextSpecific || decodedTag_rejectcause.Number != 0 {
					return fmt.Errorf("decoding rejectCause: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_rejectcause)
				}
				tmp_rejectcause := rawVal_rejectcause
				v.RejectCause = tmp_rejectcause
				offset += n_rejectcause
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "RoamNotAllowedExt", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes AnyTimeModArgExt to BER format.
func (v *AnyTimeModArgExt) MarshalBER() ([]byte, error) {
	var children []byte
	if v.SenderMSISDN != nil {
		enc_sendermsisdn := ber.EncodeOctetString([]byte(*v.SenderMSISDN))
		retagged_enc_sendermsisdn, tagErr_enc_sendermsisdn := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_sendermsisdn)
		if tagErr_enc_sendermsisdn != nil {
			return nil, fmt.Errorf("encoding senderMSISDN: %w", tagErr_enc_sendermsisdn)
		}
		enc_sendermsisdn = retagged_enc_sendermsisdn
		children = append(children, enc_sendermsisdn...)
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
	return ber.EncodeConstructed(tag.Tag{Class: tag.ClassPrivate, Number: 0, Constructed: true}, children), nil
}

// MarshalDER encodes AnyTimeModArgExt to DER format.
func (v *AnyTimeModArgExt) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	encoded, err := v.MarshalBER()
	if err != nil {
		return nil, err
	}
	if err := ber.ValidateDERElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding AnyTimeModArgExt as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes AnyTimeModArgExt from BER/DER format.
func (v *AnyTimeModArgExt) UnmarshalBER(data []byte) error {
	decodedTag, content, total, err := ber.DecodeConstructedContent(data)
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
				decodedTag_sendermsisdn, n_sendermsisdn, rawVal_sendermsisdn, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding senderMSISDN: %w", err)
				}
				if decodedTag_sendermsisdn.Class != tag.ClassContextSpecific || decodedTag_sendermsisdn.Number != 0 {
					return fmt.Errorf("decoding senderMSISDN: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_sendermsisdn)
				}
				tmp_sendermsisdn := ISDNAddressString4(rawVal_sendermsisdn)
				v.SenderMSISDN = &tmp_sendermsisdn
				offset += n_sendermsisdn
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "AnyTimeModArgExt", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes CosInfo to BER format.
func (v *CosInfo) MarshalBER() ([]byte, error) {
	var children []byte
	if v.SsCode != nil {
		enc_sscode := ber.EncodeOctetString([]byte(*v.SsCode))
		children = append(children, enc_sscode...)
	}
	enc_cosfeaturelist, err := MarshalBERCOSFeatureList(v.CosFeatureList)
	if err != nil {
		return nil, fmt.Errorf("encoding cos-FeatureList: %w", err)
	}
	children = append(children, enc_cosfeaturelist...)
	return ber.EncodeSequence(children), nil
}

// MarshalDER encodes CosInfo to DER format.
func (v *CosInfo) MarshalDER() ([]byte, error) {
	// ITU-T X.690 (02/2021) Section 10.1 requires DER length forms to be definite.
	derValue := *v
	derValue.CosFeatureListIndef_ = false
	v = &derValue
	encoded, err := v.MarshalBER()
	if err != nil {
		return nil, err
	}
	if err := ber.ValidateDERElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding CosInfo as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes CosInfo from BER/DER format.
func (v *CosInfo) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
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
				val_sscode, n, err := ber.DecodeOctetString(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding ss-Code: %w", err)
				}
				tmp_sscode := SSCode5(val_sscode)
				v.SsCode = &tmp_sscode
				offset += n
			}
		}
	}
	// Decode cos-FeatureList
	if offset >= len(content) {
		return fmt.Errorf("missing required field cos-FeatureList")
	}
	v.CosFeatureListIndef_ = false
	// Decode nested SEQUENCE_OF (COSFeatureList)
	_, n_cosfeaturelist, _, tlvErr_cosfeaturelist := ber.DecodeTLV(content[offset:])
	if tlvErr_cosfeaturelist != nil {
		return fmt.Errorf("decoding cos-FeatureList: %w", tlvErr_cosfeaturelist)
	}
	tlv_cosfeaturelist := content[offset : offset+n_cosfeaturelist]
	{
		_, tagSz_, _ := ber.DecodeTag(tlv_cosfeaturelist)
		if tagSz_ < len(tlv_cosfeaturelist) && tlv_cosfeaturelist[tagSz_] == 0x80 {
			v.CosFeatureListIndef_ = true
		}
	}
	dec_cosfeaturelist, unmErr := UnmarshalBERCOSFeatureList(tlv_cosfeaturelist)
	if unmErr != nil {
		return fmt.Errorf("decoding cos-FeatureList: %w", unmErr)
	}
	v.CosFeatureList = dec_cosfeaturelist
	offset += n_cosfeaturelist
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "CosInfo", Cause: ber.ErrExtraData}
	}
	return nil
}

// MarshalBERCOSFeatureList encodes a COSFeatureList list to BER.
func MarshalBERCOSFeatureList(list COSFeatureList) ([]byte, error) {
	var children []byte
	for _, elem := range list {
		enc, err := elem.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding element: %w", err)
		}
		children = append(children, enc...)
	}
	return ber.EncodeSequence(children), nil
}

// UnmarshalBERCOSFeatureList decodes a COSFeatureList list from BER.
func UnmarshalBERCOSFeatureList(data []byte) (COSFeatureList, error) {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return nil, fmt.Errorf("decoding COSFeatureList: %w", err)
	}
	if total != len(data) {
		return nil, &ber.DecodeError{Offset: total, TypeName: "COSFeatureList", Cause: ber.ErrExtraData}
	}
	var result COSFeatureList
	offset := 0
	for offset < len(content) {
		var elem COSFeature
		_, n, _, tlvErr := ber.DecodeTLV(content[offset:])
		if tlvErr != nil {
			return nil, fmt.Errorf("decoding element TLV: %w", tlvErr)
		}
		if unmErr := elem.UnmarshalBER(content[offset : offset+n]); unmErr != nil {
			return nil, fmt.Errorf("decoding element: %w", unmErr)
		}
		result = append(result, elem)
		offset += n
	}
	return result, nil
}

// MarshalBER encodes COSFeature to BER format.
func (v *COSFeature) MarshalBER() ([]byte, error) {
	var children []byte
	if v.BasicServiceCode != nil {
		enc_basicservicecode, err := v.BasicServiceCode.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding basicServiceCode: %w", err)
		}
		children = append(children, enc_basicservicecode...)
	}
	enc_ssstatus := ber.EncodeOctetString([]byte(v.SsStatus))
	retagged_enc_ssstatus, tagErr_enc_ssstatus := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, enc_ssstatus)
	if tagErr_enc_ssstatus != nil {
		return nil, fmt.Errorf("encoding ss-Status: %w", tagErr_enc_ssstatus)
	}
	enc_ssstatus = retagged_enc_ssstatus
	children = append(children, enc_ssstatus...)
	if v.CustomerGroupID != nil {
		enc_customergroupid := ber.EncodeBitString(v.CustomerGroupID.Bytes, (8-(v.CustomerGroupID.BitLength%8))%8)
		retagged_enc_customergroupid, tagErr_enc_customergroupid := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 5, enc_customergroupid)
		if tagErr_enc_customergroupid != nil {
			return nil, fmt.Errorf("encoding customerGroupID: %w", tagErr_enc_customergroupid)
		}
		enc_customergroupid = retagged_enc_customergroupid
		children = append(children, enc_customergroupid...)
	}
	if v.SubGroupID != nil {
		enc_subgroupid := ber.EncodeBitString(v.SubGroupID.Bytes, (8-(v.SubGroupID.BitLength%8))%8)
		retagged_enc_subgroupid, tagErr_enc_subgroupid := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 6, enc_subgroupid)
		if tagErr_enc_subgroupid != nil {
			return nil, fmt.Errorf("encoding subGroupID: %w", tagErr_enc_subgroupid)
		}
		enc_subgroupid = retagged_enc_subgroupid
		children = append(children, enc_subgroupid...)
	}
	if v.ClassOfServiceID != nil {
		enc_classofserviceid := ber.EncodeBitString(v.ClassOfServiceID.Bytes, (8-(v.ClassOfServiceID.BitLength%8))%8)
		retagged_enc_classofserviceid, tagErr_enc_classofserviceid := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 7, enc_classofserviceid)
		if tagErr_enc_classofserviceid != nil {
			return nil, fmt.Errorf("encoding classOfServiceID: %w", tagErr_enc_classofserviceid)
		}
		enc_classofserviceid = retagged_enc_classofserviceid
		children = append(children, enc_classofserviceid...)
	}
	return ber.EncodeSequence(children), nil
}

// MarshalDER encodes COSFeature to DER format.
func (v *COSFeature) MarshalDER() ([]byte, error) {
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	encoded, err := v.MarshalBER()
	if err != nil {
		return nil, err
	}
	if err := ber.ValidateDERElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding COSFeature as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes COSFeature from BER/DER format.
func (v *COSFeature) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
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
				// Decode nested CHOICE (BasicServiceCode4)
				_, n_basicservicecode, _, tlvErr_basicservicecode := ber.DecodeTLV(content[offset:])
				if tlvErr_basicservicecode != nil {
					return fmt.Errorf("decoding basicServiceCode: %w", tlvErr_basicservicecode)
				}
				var dec_basicservicecode BasicServiceCode4
				if unmErr := dec_basicservicecode.UnmarshalBER(content[offset : offset+n_basicservicecode]); unmErr != nil {
					return fmt.Errorf("decoding basicServiceCode: %w", unmErr)
				}
				v.BasicServiceCode = &dec_basicservicecode
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
	decodedTag_ssstatus, n_ssstatus, rawVal_ssstatus, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding ss-Status: %w", err)
	}
	if decodedTag_ssstatus.Class != tag.ClassContextSpecific || decodedTag_ssstatus.Number != 4 {
		return fmt.Errorf("decoding ss-Status: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_ssstatus)
	}
	v.SsStatus = SSStatus5(rawVal_ssstatus)
	offset += n_ssstatus
	// Decode customerGroupID
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 5 {
				decodedTag_customergroupid, n_customergroupid, rawVal_customergroupid, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding customerGroupID: %w", err)
				}
				if decodedTag_customergroupid.Class != tag.ClassContextSpecific || decodedTag_customergroupid.Number != 5 {
					return fmt.Errorf("decoding customerGroupID: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_customergroupid)
				}
				bsBytes_customergroupid, bsUnused_customergroupid, bsErr := ber.DecodeBitStringValue(rawVal_customergroupid)
				if bsErr != nil {
					return fmt.Errorf("decoding customerGroupID: %w", bsErr)
				}
				tmp_customergroupid := runtime.BitString{Bytes: bsBytes_customergroupid, BitLength: len(bsBytes_customergroupid)*8 - bsUnused_customergroupid}
				v.CustomerGroupID = &tmp_customergroupid
				offset += n_customergroupid
			}
		}
	}
	// Decode subGroupID
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 6 {
				decodedTag_subgroupid, n_subgroupid, rawVal_subgroupid, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding subGroupID: %w", err)
				}
				if decodedTag_subgroupid.Class != tag.ClassContextSpecific || decodedTag_subgroupid.Number != 6 {
					return fmt.Errorf("decoding subGroupID: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_subgroupid)
				}
				bsBytes_subgroupid, bsUnused_subgroupid, bsErr := ber.DecodeBitStringValue(rawVal_subgroupid)
				if bsErr != nil {
					return fmt.Errorf("decoding subGroupID: %w", bsErr)
				}
				tmp_subgroupid := runtime.BitString{Bytes: bsBytes_subgroupid, BitLength: len(bsBytes_subgroupid)*8 - bsUnused_subgroupid}
				v.SubGroupID = &tmp_subgroupid
				offset += n_subgroupid
			}
		}
	}
	// Decode classOfServiceID
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 7 {
				decodedTag_classofserviceid, n_classofserviceid, rawVal_classofserviceid, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding classOfServiceID: %w", err)
				}
				if decodedTag_classofserviceid.Class != tag.ClassContextSpecific || decodedTag_classofserviceid.Number != 7 {
					return fmt.Errorf("decoding classOfServiceID: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_classofserviceid)
				}
				bsBytes_classofserviceid, bsUnused_classofserviceid, bsErr := ber.DecodeBitStringValue(rawVal_classofserviceid)
				if bsErr != nil {
					return fmt.Errorf("decoding classOfServiceID: %w", bsErr)
				}
				tmp_classofserviceid := runtime.BitString{Bytes: bsBytes_classofserviceid, BitLength: len(bsBytes_classofserviceid)*8 - bsUnused_classofserviceid}
				v.ClassOfServiceID = &tmp_classofserviceid
				offset += n_classofserviceid
			}
		}
	}
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "COSFeature", Cause: ber.ErrExtraData}
	}
	return nil
}

// MarshalBER encodes AccessTypeExt to BER format.
func (v *AccessTypeExt) MarshalBER() ([]byte, error) {
	var children []byte
	enc_access := ber.EncodeEnumerated(int64(v.Access))
	children = append(children, enc_access...)
	enc_version := ber.EncodeInteger(int64(v.Version))
	children = append(children, enc_version...)
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

// MarshalDER encodes AccessTypeExt to DER format.
func (v *AccessTypeExt) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	encoded, err := v.MarshalBER()
	if err != nil {
		return nil, err
	}
	if err := ber.ValidateDERElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding AccessTypeExt as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes AccessTypeExt from BER/DER format.
func (v *AccessTypeExt) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
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
	val_access, n, err := ber.DecodeInteger(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding access: %w", err)
	}
	v.Access = Access(val_access)
	offset += n
	// Decode version
	if offset >= len(content) {
		return fmt.Errorf("missing required field version")
	}
	val_version, n, err := ber.DecodeInteger(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding version: %w", err)
	}
	v.Version = Version(val_version)
	offset += n
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "AccessTypeExt", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBERAccessSubscriptionListExt encodes a AccessSubscriptionListExt list to BER.
func MarshalBERAccessSubscriptionListExt(list AccessSubscriptionListExt) ([]byte, error) {
	var children []byte
	for _, elem := range list {
		children = append(children, ber.EncodeEnumerated(int64(elem))...)
	}
	return ber.EncodeSequence(children), nil
}

// UnmarshalBERAccessSubscriptionListExt decodes a AccessSubscriptionListExt list from BER.
func UnmarshalBERAccessSubscriptionListExt(data []byte) (AccessSubscriptionListExt, error) {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return nil, fmt.Errorf("decoding AccessSubscriptionListExt: %w", err)
	}
	if total != len(data) {
		return nil, &ber.DecodeError{Offset: total, TypeName: "AccessSubscriptionListExt", Cause: ber.ErrExtraData}
	}
	var result AccessSubscriptionListExt
	offset := 0
	for offset < len(content) {
		val, n, intErr := ber.DecodeInteger(content[offset:])
		if intErr != nil {
			return nil, fmt.Errorf("decoding element: %w", intErr)
		}
		result = append(result, Access(val))
		offset += n
	}
	return result, nil
}

// MarshalBER encodes AnyTimePOBarringArg to BER format.
func (v *AnyTimePOBarringArg) MarshalBER() ([]byte, error) {
	var children []byte
	enc_subscriberidentity, err := v.SubscriberIdentity.MarshalBER()
	if err != nil {
		return nil, fmt.Errorf("encoding subscriberIdentity: %w", err)
	}
	enc_subscriberidentity = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 0, enc_subscriberidentity)
	children = append(children, enc_subscriberidentity...)
	enc_gsmscfaddress := ber.EncodeOctetString([]byte(v.GsmSCFAddress))
	retagged_enc_gsmscfaddress, tagErr_enc_gsmscfaddress := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, enc_gsmscfaddress)
	if tagErr_enc_gsmscfaddress != nil {
		return nil, fmt.Errorf("encoding gsmSCF-Address: %w", tagErr_enc_gsmscfaddress)
	}
	enc_gsmscfaddress = retagged_enc_gsmscfaddress
	children = append(children, enc_gsmscfaddress...)
	enc_gprsbarring := ber.EncodeEnumerated(int64(v.GprsBarring))
	children = append(children, enc_gprsbarring...)
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

// MarshalDER encodes AnyTimePOBarringArg to DER format.
func (v *AnyTimePOBarringArg) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	encoded, err := v.MarshalBER()
	if err != nil {
		return nil, err
	}
	if err := ber.ValidateDERElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding AnyTimePOBarringArg as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes AnyTimePOBarringArg from BER/DER format.
func (v *AnyTimePOBarringArg) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
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
	decodedTag_subscriberidentity, n_subscriberidentity, innerData_subscriberidentity, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding subscriberIdentity: %w", err)
	}
	if decodedTag_subscriberidentity.Class != tag.ClassContextSpecific || decodedTag_subscriberidentity.Number != 0 || decodedTag_subscriberidentity.Constructed != true {
		return fmt.Errorf("decoding subscriberIdentity: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_subscriberidentity)
	}
	// Decode inner value from explicit tag wrapper
	if unmErr := v.SubscriberIdentity.UnmarshalBER(innerData_subscriberidentity); unmErr != nil {
		return fmt.Errorf("decoding subscriberIdentity: %w", unmErr)
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
	decodedTag_gsmscfaddress, n_gsmscfaddress, rawVal_gsmscfaddress, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding gsmSCF-Address: %w", err)
	}
	if decodedTag_gsmscfaddress.Class != tag.ClassContextSpecific || decodedTag_gsmscfaddress.Number != 3 {
		return fmt.Errorf("decoding gsmSCF-Address: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_gsmscfaddress)
	}
	v.GsmSCFAddress = ISDNAddressString4(rawVal_gsmscfaddress)
	offset += n_gsmscfaddress
	// Decode gprs-Barring
	if offset >= len(content) {
		return fmt.Errorf("missing required field gprs-Barring")
	}
	val_gprsbarring, n, err := ber.DecodeInteger(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding gprs-Barring: %w", err)
	}
	v.GprsBarring = GprsBarring(val_gprsbarring)
	offset += n
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "AnyTimePOBarringArg", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes AnyTimePOBarringRes to BER format.
func (v *AnyTimePOBarringRes) MarshalBER() ([]byte, error) {
	var children []byte
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

// MarshalDER encodes AnyTimePOBarringRes to DER format.
func (v *AnyTimePOBarringRes) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	encoded, err := v.MarshalBER()
	if err != nil {
		return nil, err
	}
	if err := ber.ValidateDERElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding AnyTimePOBarringRes as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes AnyTimePOBarringRes from BER/DER format.
func (v *AnyTimePOBarringRes) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
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
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "AnyTimePOBarringRes", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}
