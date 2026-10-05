// Code generated from ASN.1 module "MAP-LCS-DataTypes". DO NOT EDIT.

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

	// LCSMaxNameStringLength is the integer constant for maxNameStringLength.
	LCSMaxNameStringLength int64 = 63

	// LCSMaxRequestorIDStringLength is the integer constant for maxRequestorIDStringLength.
	LCSMaxRequestorIDStringLength int64 = 63

	// LCSMaxLCSCodewordStringLength is the integer constant for maxLCSCodewordStringLength.
	LCSMaxLCSCodewordStringLength int64 = 20

	// LCSMaxNumOfAreas is the integer constant for maxNumOfAreas.
	LCSMaxNumOfAreas int64 = 10

	// LCSMaxReportingAmount is the integer constant for maxReportingAmount.
	LCSMaxReportingAmount int64 = 8.639999e+06

	// LCSMaxReportingInterval is the integer constant for maxReportingInterval.
	LCSMaxReportingInterval int64 = 8.639999e+06

	// LCSMaxReportingAmountMilliseconds is the integer constant for maxReportingAmountMilliseconds.
	LCSMaxReportingAmountMilliseconds int64 = 8.639999e+09

	// LCSMaxReportingIntervalMilliseconds is the integer constant for maxReportingIntervalMilliseconds.
	LCSMaxReportingIntervalMilliseconds int64 = 999

	// LCSMaxNumOfReportingPLMN is the integer constant for maxNumOfReportingPLMN.
	LCSMaxNumOfReportingPLMN int64 = 20

	// LCSMaxExtGeographicalInformation is the integer constant for maxExt-GeographicalInformation.
	LCSMaxExtGeographicalInformation int64 = 20

	// LCSMaxPositioningDataInformation is the integer constant for maxPositioningDataInformation.
	LCSMaxPositioningDataInformation int64 = 10

	// LCSMaxUtranPositioningDataInfo is the integer constant for maxUtranPositioningDataInfo.
	LCSMaxUtranPositioningDataInfo int64 = 11

	// LCSMaxGeranGANSSpositioningData is the integer constant for maxGeranGANSSpositioningData.
	LCSMaxGeranGANSSpositioningData int64 = 10

	// LCSMaxUtranGANSSpositioningData is the integer constant for maxUtranGANSSpositioningData.
	LCSMaxUtranGANSSpositioningData int64 = 9

	// LCSMaxUtranAdditionalPositioningData is the integer constant for maxUtranAdditionalPositioningData.
	LCSMaxUtranAdditionalPositioningData int64 = 8

	// LCSMaxAddGeographicalInformation is the integer constant for maxAdd-GeographicalInformation.
	LCSMaxAddGeographicalInformation int64 = 91
)

// LCSRoutingInfoForLCSArg represents the ASN.1 type RoutingInfoForLCS-Arg (SEQUENCE).
type LCSRoutingInfoForLCSArg struct {
	MlcNumber          ISDNAddressString3   `asn1:"tag:0,context,implicit"`
	TargetMS           SubscriberIdentity3  `asn1:"tag:1,context,explicit"`
	ExtensionContainer *ExtensionContainer3 `asn1:"tag:2,context,implicit,optional" json:"ExtensionContainer,omitempty"`
	ExtCount_          int64                `asn1:"-" json:"-"`
	ExtPresent_        []bool               `asn1:"-" json:"-"`
	ExtData_           [][]byte             `asn1:"-" json:"-"`
	berOriginal_       []byte               `asn1:"-" json:"-"`
	berSnapshot_       []byte               `asn1:"-" json:"-"`
}

// LCSRoutingInfoForLCSRes represents the ASN.1 type RoutingInfoForLCS-Res (SEQUENCE).
type LCSRoutingInfoForLCSRes struct {
	TargetMS               SubscriberIdentity3        `asn1:"tag:0,context,explicit"`
	LcsLocationInfo        LCSLCSLocationInfo         `asn1:"tag:1,context,implicit"`
	ExtensionContainer     *ExtensionContainer3       `asn1:"tag:2,context,implicit,optional" json:"ExtensionContainer,omitempty"`
	VGmlcAddress           *CommonDataTypesGSNAddress `asn1:"tag:3,context,implicit,optional" json:"VGmlcAddress,omitempty"`
	HGmlcAddress           *CommonDataTypesGSNAddress `asn1:"tag:4,context,implicit,optional" json:"HGmlcAddress,omitempty"`
	PprAddress             *CommonDataTypesGSNAddress `asn1:"tag:5,context,implicit,optional" json:"PprAddress,omitempty"`
	AdditionalVGmlcAddress *CommonDataTypesGSNAddress `asn1:"tag:6,context,implicit,optional" json:"AdditionalVGmlcAddress,omitempty"`
	ExtCount_              int64                      `asn1:"-" json:"-"`
	ExtPresent_            []bool                     `asn1:"-" json:"-"`
	ExtData_               [][]byte                   `asn1:"-" json:"-"`
	berOriginal_           []byte                     `asn1:"-" json:"-"`
	berSnapshot_           []byte                     `asn1:"-" json:"-"`
}

// LCSLCSLocationInfo represents the ASN.1 type LCSLocationInfo (SEQUENCE).
type LCSLCSLocationInfo struct {
	NetworkNodeNumber           ISDNAddressString3               `asn1:""`
	Lmsi                        *LMSI3                           `asn1:"tag:0,context,implicit,optional" json:"Lmsi,omitempty"`
	ExtensionContainer          *ExtensionContainer3             `asn1:"tag:1,context,implicit,optional" json:"ExtensionContainer,omitempty"`
	GprsNodeIndicator           *struct{}                        `asn1:"tag:2,context,implicit,optional" json:"GprsNodeIndicator,omitempty"`
	AdditionalNumber            *AdditionalNumber3               `asn1:"tag:3,context,explicit,optional" json:"AdditionalNumber,omitempty"`
	SupportedLCSCapabilitySets  *SupportedLCSCapabilitySets4     `asn1:"tag:4,context,implicit,optional" json:"SupportedLCSCapabilitySets,omitempty"`
	AdditionalLCSCapabilitySets *SupportedLCSCapabilitySets4     `asn1:"tag:5,context,implicit,optional" json:"AdditionalLCSCapabilitySets,omitempty"`
	MmeName                     *CommonDataTypesDiameterIdentity `asn1:"tag:6,context,implicit,optional" json:"MmeName,omitempty"`
	AaaServerName               *CommonDataTypesDiameterIdentity `asn1:"tag:8,context,implicit,optional" json:"AaaServerName,omitempty"`
	SgsnName                    *CommonDataTypesDiameterIdentity `asn1:"tag:9,context,implicit,optional" json:"SgsnName,omitempty"`
	SgsnRealm                   *CommonDataTypesDiameterIdentity `asn1:"tag:10,context,implicit,optional" json:"SgsnRealm,omitempty"`
	ExtCount_                   int64                            `asn1:"-" json:"-"`
	ExtPresent_                 []bool                           `asn1:"-" json:"-"`
	ExtData_                    [][]byte                         `asn1:"-" json:"-"`
	berOriginal_                []byte                           `asn1:"-" json:"-"`
	berSnapshot_                []byte                           `asn1:"-" json:"-"`
}

// LCSProvideSubscriberLocationArg represents the ASN.1 type ProvideSubscriberLocation-Arg (SEQUENCE).
type LCSProvideSubscriberLocationArg struct {
	LocationType              LCSLocationType            `asn1:""`
	MlcNumber                 ISDNAddressString3         `asn1:""`
	LcsClientID               *LCSLCSClientID            `asn1:"tag:0,context,implicit,optional" json:"LcsClientID,omitempty"`
	PrivacyOverride           *struct{}                  `asn1:"tag:1,context,implicit,optional" json:"PrivacyOverride,omitempty"`
	Imsi                      *IMSI3                     `asn1:"tag:2,context,implicit,optional" json:"Imsi,omitempty"`
	Msisdn                    *ISDNAddressString3        `asn1:"tag:3,context,implicit,optional" json:"Msisdn,omitempty"`
	Lmsi                      *LMSI3                     `asn1:"tag:4,context,implicit,optional" json:"Lmsi,omitempty"`
	Imei                      *IMEI3                     `asn1:"tag:5,context,implicit,optional" json:"Imei,omitempty"`
	LcsPriority               *LCSLCSPriority            `asn1:"tag:6,context,implicit,optional" json:"LcsPriority,omitempty"`
	LcsQoS                    *LCSLCSQoS                 `asn1:"tag:7,context,implicit,optional" json:"LcsQoS,omitempty"`
	ExtensionContainer        *ExtensionContainer3       `asn1:"tag:8,context,implicit,optional" json:"ExtensionContainer,omitempty"`
	SupportedGADShapes        *LCSSupportedGADShapes     `asn1:"tag:9,context,implicit,optional" json:"SupportedGADShapes,omitempty"`
	LcsReferenceNumber        *LCSLCSReferenceNumber     `asn1:"tag:10,context,implicit,optional" json:"LcsReferenceNumber,omitempty"`
	LcsServiceTypeID          *LCSServiceTypeID3         `asn1:"tag:11,context,implicit,optional" json:"LcsServiceTypeID,omitempty"`
	LcsCodeword               *LCSLCSCodeword            `asn1:"tag:12,context,implicit,optional" json:"LcsCodeword,omitempty"`
	LcsPrivacyCheck           *LCSLCSPrivacyCheck        `asn1:"tag:13,context,implicit,optional" json:"LcsPrivacyCheck,omitempty"`
	AreaEventInfo             *LCSAreaEventInfo          `asn1:"tag:14,context,implicit,optional" json:"AreaEventInfo,omitempty"`
	HGmlcAddress              *CommonDataTypesGSNAddress `asn1:"tag:15,context,implicit,optional" json:"HGmlcAddress,omitempty"`
	MoLrShortCircuitIndicator *struct{}                  `asn1:"tag:16,context,implicit,optional" json:"MoLrShortCircuitIndicator,omitempty"`
	PeriodicLDRInfo           *LCSPeriodicLDRInfo        `asn1:"tag:17,context,implicit,optional" json:"PeriodicLDRInfo,omitempty"`
	ReportingPLMNList         *LCSReportingPLMNList      `asn1:"tag:18,context,implicit,optional" json:"ReportingPLMNList,omitempty"`
	ExtCount_                 int64                      `asn1:"-" json:"-"`
	ExtPresent_               []bool                     `asn1:"-" json:"-"`
	ExtData_                  [][]byte                   `asn1:"-" json:"-"`
	berOriginal_              []byte                     `asn1:"-" json:"-"`
	berSnapshot_              []byte                     `asn1:"-" json:"-"`
}

// LCSLocationType represents the ASN.1 type LocationType (SEQUENCE).
type LCSLocationType struct {
	LocationEstimateType      LCSLocationEstimateType       `asn1:"tag:0,context,implicit"`
	DeferredLocationEventType *LCSDeferredLocationEventType `asn1:"tag:1,context,implicit,optional" json:"DeferredLocationEventType,omitempty"`
	ExtCount_                 int64                         `asn1:"-" json:"-"`
	ExtPresent_               []bool                        `asn1:"-" json:"-"`
	ExtData_                  [][]byte                      `asn1:"-" json:"-"`
	berOriginal_              []byte                        `asn1:"-" json:"-"`
	berSnapshot_              []byte                        `asn1:"-" json:"-"`
}

// LCSLocationEstimateType represents the ASN.1 ENUMERATED type LocationEstimateType.
type LCSLocationEstimateType int64

const (
	LCSLocationEstimateTypeCurrentLocation              LCSLocationEstimateType = 0
	LCSLocationEstimateTypeCurrentOrLastKnownLocation   LCSLocationEstimateType = 1
	LCSLocationEstimateTypeInitialLocation              LCSLocationEstimateType = 2
	LCSLocationEstimateTypeActivateDeferredLocation     LCSLocationEstimateType = 3
	LCSLocationEstimateTypeCancelDeferredLocation       LCSLocationEstimateType = 4
	LCSLocationEstimateTypeNotificationVerificationOnly LCSLocationEstimateType = 5
)

func (v LCSLocationEstimateType) String() string {
	switch v {
	case LCSLocationEstimateTypeCurrentLocation:
		return "currentLocation"
	case LCSLocationEstimateTypeCurrentOrLastKnownLocation:
		return "currentOrLastKnownLocation"
	case LCSLocationEstimateTypeInitialLocation:
		return "initialLocation"
	case LCSLocationEstimateTypeActivateDeferredLocation:
		return "activateDeferredLocation"
	case LCSLocationEstimateTypeCancelDeferredLocation:
		return "cancelDeferredLocation"
	case LCSLocationEstimateTypeNotificationVerificationOnly:
		return "notificationVerificationOnly"
	default:
		return "unknown"
	}
}

// LCSDeferredLocationEventType represents the ASN.1 type DeferredLocationEventType (BIT_STRING).
type LCSDeferredLocationEventType = runtime.BitString

// LCSLCSClientID represents the ASN.1 type LCS-ClientID (SEQUENCE).
type LCSLCSClientID struct {
	LcsClientType       LCSLCSClientType      `asn1:"tag:0,context,implicit"`
	LcsClientExternalID *LCSClientExternalID3 `asn1:"tag:1,context,implicit,optional" json:"LcsClientExternalID,omitempty"`
	LcsClientDialedByMS *AddressString3       `asn1:"tag:2,context,implicit,optional" json:"LcsClientDialedByMS,omitempty"`
	LcsClientInternalID *LCSClientInternalID3 `asn1:"tag:3,context,implicit,optional" json:"LcsClientInternalID,omitempty"`
	LcsClientName       *LCSLCSClientName     `asn1:"tag:4,context,implicit,optional" json:"LcsClientName,omitempty"`
	LcsAPN              *APN4                 `asn1:"tag:5,context,implicit,optional" json:"LcsAPN,omitempty"`
	LcsRequestorID      *LCSLCSRequestorID    `asn1:"tag:6,context,implicit,optional" json:"LcsRequestorID,omitempty"`
	ExtCount_           int64                 `asn1:"-" json:"-"`
	ExtPresent_         []bool                `asn1:"-" json:"-"`
	ExtData_            [][]byte              `asn1:"-" json:"-"`
	berOriginal_        []byte                `asn1:"-" json:"-"`
	berSnapshot_        []byte                `asn1:"-" json:"-"`
}

// LCSLCSClientType represents the ASN.1 ENUMERATED type LCSClientType.
type LCSLCSClientType int64

const (
	LCSLCSClientTypeEmergencyServices       LCSLCSClientType = 0
	LCSLCSClientTypeValueAddedServices      LCSLCSClientType = 1
	LCSLCSClientTypePlmnOperatorServices    LCSLCSClientType = 2
	LCSLCSClientTypeLawfulInterceptServices LCSLCSClientType = 3
)

func (v LCSLCSClientType) String() string {
	switch v {
	case LCSLCSClientTypeEmergencyServices:
		return "emergencyServices"
	case LCSLCSClientTypeValueAddedServices:
		return "valueAddedServices"
	case LCSLCSClientTypePlmnOperatorServices:
		return "plmnOperatorServices"
	case LCSLCSClientTypeLawfulInterceptServices:
		return "lawfulInterceptServices"
	default:
		return "unknown"
	}
}

// LCSLCSClientName represents the ASN.1 type LCSClientName (SEQUENCE).
type LCSLCSClientName struct {
	DataCodingScheme   USSDDataCodingScheme3  `asn1:"tag:0,context,implicit"`
	NameString         LCSNameString          `asn1:"tag:2,context,implicit"`
	LcsFormatIndicator *LCSLCSFormatIndicator `asn1:"tag:3,context,implicit,optional" json:"LcsFormatIndicator,omitempty"`
	ExtCount_          int64                  `asn1:"-" json:"-"`
	ExtPresent_        []bool                 `asn1:"-" json:"-"`
	ExtData_           [][]byte               `asn1:"-" json:"-"`
	berOriginal_       []byte                 `asn1:"-" json:"-"`
	berSnapshot_       []byte                 `asn1:"-" json:"-"`
}

// LCSNameString represents the ASN.1 type NameString (OCTET_STRING).
type LCSNameString = USSDString3

// LCSLCSRequestorID represents the ASN.1 type LCSRequestorID (SEQUENCE).
type LCSLCSRequestorID struct {
	DataCodingScheme   USSDDataCodingScheme3  `asn1:"tag:0,context,implicit"`
	RequestorIDString  LCSRequestorIDString   `asn1:"tag:1,context,implicit"`
	LcsFormatIndicator *LCSLCSFormatIndicator `asn1:"tag:2,context,implicit,optional" json:"LcsFormatIndicator,omitempty"`
	ExtCount_          int64                  `asn1:"-" json:"-"`
	ExtPresent_        []bool                 `asn1:"-" json:"-"`
	ExtData_           [][]byte               `asn1:"-" json:"-"`
	berOriginal_       []byte                 `asn1:"-" json:"-"`
	berSnapshot_       []byte                 `asn1:"-" json:"-"`
}

// LCSRequestorIDString represents the ASN.1 type RequestorIDString (OCTET_STRING).
type LCSRequestorIDString = USSDString3

// LCSLCSFormatIndicator represents the ASN.1 ENUMERATED type LCS-FormatIndicator.
type LCSLCSFormatIndicator int64

const (
	LCSLCSFormatIndicatorLogicalName  LCSLCSFormatIndicator = 0
	LCSLCSFormatIndicatorEMailAddress LCSLCSFormatIndicator = 1
	LCSLCSFormatIndicatorMsisdn       LCSLCSFormatIndicator = 2
	LCSLCSFormatIndicatorUrl          LCSLCSFormatIndicator = 3
	LCSLCSFormatIndicatorSipUrl       LCSLCSFormatIndicator = 4
)

func (v LCSLCSFormatIndicator) String() string {
	switch v {
	case LCSLCSFormatIndicatorLogicalName:
		return "logicalName"
	case LCSLCSFormatIndicatorEMailAddress:
		return "e-mailAddress"
	case LCSLCSFormatIndicatorMsisdn:
		return "msisdn"
	case LCSLCSFormatIndicatorUrl:
		return "url"
	case LCSLCSFormatIndicatorSipUrl:
		return "sipUrl"
	default:
		return "unknown"
	}
}

// LCSLCSPriority represents the ASN.1 type LCS-Priority (OCTET_STRING).
type LCSLCSPriority = []byte

// LCSLCSQoS represents the ASN.1 type LCS-QoS (SEQUENCE).
type LCSLCSQoS struct {
	HorizontalAccuracy        *LCSHorizontalAccuracy `asn1:"tag:0,context,implicit,optional" json:"HorizontalAccuracy,omitempty"`
	VerticalCoordinateRequest *struct{}              `asn1:"tag:1,context,implicit,optional" json:"VerticalCoordinateRequest,omitempty"`
	VerticalAccuracy          *LCSVerticalAccuracy   `asn1:"tag:2,context,implicit,optional" json:"VerticalAccuracy,omitempty"`
	ResponseTime              *LCSResponseTime       `asn1:"tag:3,context,implicit,optional" json:"ResponseTime,omitempty"`
	ExtensionContainer        *ExtensionContainer3   `asn1:"tag:4,context,implicit,optional" json:"ExtensionContainer,omitempty"`
	VelocityRequest           *struct{}              `asn1:"tag:5,context,implicit,optional" json:"VelocityRequest,omitempty"`
	LcsQosClass               *LCSLCSQoSClass        `asn1:"tag:6,context,implicit,optional" json:"LcsQosClass,omitempty"`
	ExtCount_                 int64                  `asn1:"-" json:"-"`
	ExtPresent_               []bool                 `asn1:"-" json:"-"`
	ExtData_                  [][]byte               `asn1:"-" json:"-"`
	berOriginal_              []byte                 `asn1:"-" json:"-"`
	berSnapshot_              []byte                 `asn1:"-" json:"-"`
}

// LCSHorizontalAccuracy represents the ASN.1 type Horizontal-Accuracy (OCTET_STRING).
type LCSHorizontalAccuracy = []byte

// LCSVerticalAccuracy represents the ASN.1 type Vertical-Accuracy (OCTET_STRING).
type LCSVerticalAccuracy = []byte

// LCSResponseTime represents the ASN.1 type ResponseTime (SEQUENCE).
type LCSResponseTime struct {
	ResponseTimeCategory LCSResponseTimeCategory `asn1:""`
	ExtCount_            int64                   `asn1:"-" json:"-"`
	ExtPresent_          []bool                  `asn1:"-" json:"-"`
	ExtData_             [][]byte                `asn1:"-" json:"-"`
	berOriginal_         []byte                  `asn1:"-" json:"-"`
	berSnapshot_         []byte                  `asn1:"-" json:"-"`
}

// LCSResponseTimeCategory represents the ASN.1 ENUMERATED type ResponseTimeCategory.
type LCSResponseTimeCategory int64

const (
	LCSResponseTimeCategoryLowdelay      LCSResponseTimeCategory = 0
	LCSResponseTimeCategoryDelaytolerant LCSResponseTimeCategory = 1
)

func (v LCSResponseTimeCategory) String() string {
	switch v {
	case LCSResponseTimeCategoryLowdelay:
		return "lowdelay"
	case LCSResponseTimeCategoryDelaytolerant:
		return "delaytolerant"
	default:
		return "unknown"
	}
}

// LCSLCSQoSClass represents the ASN.1 ENUMERATED type LCS-QoS-Class.
type LCSLCSQoSClass int64

const (
	LCSLCSQoSClassBestEffort LCSLCSQoSClass = 0
	LCSLCSQoSClassAssured    LCSLCSQoSClass = 1
)

func (v LCSLCSQoSClass) String() string {
	switch v {
	case LCSLCSQoSClassBestEffort:
		return "bestEffort"
	case LCSLCSQoSClassAssured:
		return "assured"
	default:
		return "unknown"
	}
}

// LCSSupportedGADShapes represents the ASN.1 type SupportedGADShapes (BIT_STRING).
type LCSSupportedGADShapes = runtime.BitString

// LCSLCSReferenceNumber represents the ASN.1 type LCS-ReferenceNumber (OCTET_STRING).
type LCSLCSReferenceNumber = []byte

// LCSLCSCodeword represents the ASN.1 type LCSCodeword (SEQUENCE).
type LCSLCSCodeword struct {
	DataCodingScheme  USSDDataCodingScheme3 `asn1:"tag:0,context,implicit"`
	LcsCodewordString LCSLCSCodewordString  `asn1:"tag:1,context,implicit"`
	ExtCount_         int64                 `asn1:"-" json:"-"`
	ExtPresent_       []bool                `asn1:"-" json:"-"`
	ExtData_          [][]byte              `asn1:"-" json:"-"`
	berOriginal_      []byte                `asn1:"-" json:"-"`
	berSnapshot_      []byte                `asn1:"-" json:"-"`
}

// LCSLCSCodewordString represents the ASN.1 type LCSCodewordString (OCTET_STRING).
type LCSLCSCodewordString = USSDString3

// LCSLCSPrivacyCheck represents the ASN.1 type LCS-PrivacyCheck (SEQUENCE).
type LCSLCSPrivacyCheck struct {
	CallSessionUnrelated LCSPrivacyCheckRelatedAction  `asn1:"tag:0,context,implicit"`
	CallSessionRelated   *LCSPrivacyCheckRelatedAction `asn1:"tag:1,context,implicit,optional" json:"CallSessionRelated,omitempty"`
	ExtCount_            int64                         `asn1:"-" json:"-"`
	ExtPresent_          []bool                        `asn1:"-" json:"-"`
	ExtData_             [][]byte                      `asn1:"-" json:"-"`
	berOriginal_         []byte                        `asn1:"-" json:"-"`
	berSnapshot_         []byte                        `asn1:"-" json:"-"`
}

// LCSPrivacyCheckRelatedAction represents the ASN.1 ENUMERATED type PrivacyCheckRelatedAction.
type LCSPrivacyCheckRelatedAction int64

const (
	LCSPrivacyCheckRelatedActionAllowedWithoutNotification LCSPrivacyCheckRelatedAction = 0
	LCSPrivacyCheckRelatedActionAllowedWithNotification    LCSPrivacyCheckRelatedAction = 1
	LCSPrivacyCheckRelatedActionAllowedIfNoResponse        LCSPrivacyCheckRelatedAction = 2
	LCSPrivacyCheckRelatedActionRestrictedIfNoResponse     LCSPrivacyCheckRelatedAction = 3
	LCSPrivacyCheckRelatedActionNotAllowed                 LCSPrivacyCheckRelatedAction = 4
)

func (v LCSPrivacyCheckRelatedAction) String() string {
	switch v {
	case LCSPrivacyCheckRelatedActionAllowedWithoutNotification:
		return "allowedWithoutNotification"
	case LCSPrivacyCheckRelatedActionAllowedWithNotification:
		return "allowedWithNotification"
	case LCSPrivacyCheckRelatedActionAllowedIfNoResponse:
		return "allowedIfNoResponse"
	case LCSPrivacyCheckRelatedActionRestrictedIfNoResponse:
		return "restrictedIfNoResponse"
	case LCSPrivacyCheckRelatedActionNotAllowed:
		return "notAllowed"
	default:
		return "unknown"
	}
}

// LCSAreaEventInfo represents the ASN.1 type AreaEventInfo (SEQUENCE).
type LCSAreaEventInfo struct {
	AreaDefinition LCSAreaDefinition  `asn1:"tag:0,context,implicit"`
	OccurrenceInfo *LCSOccurrenceInfo `asn1:"tag:1,context,implicit,optional" json:"OccurrenceInfo,omitempty"`
	IntervalTime   *LCSIntervalTime   `asn1:"tag:2,context,implicit,optional" json:"IntervalTime,omitempty"`
	ExtCount_      int64              `asn1:"-" json:"-"`
	ExtPresent_    []bool             `asn1:"-" json:"-"`
	ExtData_       [][]byte           `asn1:"-" json:"-"`
	berOriginal_   []byte             `asn1:"-" json:"-"`
	berSnapshot_   []byte             `asn1:"-" json:"-"`
}

// LCSAreaDefinition represents the ASN.1 type AreaDefinition (SEQUENCE).
type LCSAreaDefinition struct {
	AreaList       *LCSAreaList `asn1:"tag:0,context,implicit"`
	AreaListIndef_ bool         `asn1:"-" json:"-"`
	ExtCount_      int64        `asn1:"-" json:"-"`
	ExtPresent_    []bool       `asn1:"-" json:"-"`
	ExtData_       [][]byte     `asn1:"-" json:"-"`
	berOriginal_   []byte       `asn1:"-" json:"-"`
	berSnapshot_   []byte       `asn1:"-" json:"-"`
}

// LCSAreaList represents the ASN.1 type AreaList (SEQUENCE_OF).
type LCSAreaList struct {
	Values       []LCSArea `json:"Values"`
	berOriginal_ []byte    `json:"-"`
	berSnapshot_ []byte    `json:"-"`
}

// LCSArea represents the ASN.1 type Area (SEQUENCE).
type LCSArea struct {
	AreaType           LCSAreaType           `asn1:"tag:0,context,implicit"`
	AreaIdentification LCSAreaIdentification `asn1:"tag:1,context,implicit"`
	ExtCount_          int64                 `asn1:"-" json:"-"`
	ExtPresent_        []bool                `asn1:"-" json:"-"`
	ExtData_           [][]byte              `asn1:"-" json:"-"`
	berOriginal_       []byte                `asn1:"-" json:"-"`
	berSnapshot_       []byte                `asn1:"-" json:"-"`
}

// LCSAreaType represents the ASN.1 ENUMERATED type AreaType.
type LCSAreaType int64

const (
	LCSAreaTypeCountryCode    LCSAreaType = 0
	LCSAreaTypePlmnId         LCSAreaType = 1
	LCSAreaTypeLocationAreaId LCSAreaType = 2
	LCSAreaTypeRoutingAreaId  LCSAreaType = 3
	LCSAreaTypeCellGlobalId   LCSAreaType = 4
	LCSAreaTypeUtranCellId    LCSAreaType = 5
)

func (v LCSAreaType) String() string {
	switch v {
	case LCSAreaTypeCountryCode:
		return "countryCode"
	case LCSAreaTypePlmnId:
		return "plmnId"
	case LCSAreaTypeLocationAreaId:
		return "locationAreaId"
	case LCSAreaTypeRoutingAreaId:
		return "routingAreaId"
	case LCSAreaTypeCellGlobalId:
		return "cellGlobalId"
	case LCSAreaTypeUtranCellId:
		return "utranCellId"
	default:
		return "unknown"
	}
}

// LCSAreaIdentification represents the ASN.1 type AreaIdentification (OCTET_STRING).
type LCSAreaIdentification = []byte

// LCSOccurrenceInfo represents the ASN.1 ENUMERATED type OccurrenceInfo.
type LCSOccurrenceInfo int64

const (
	LCSOccurrenceInfoOneTimeEvent      LCSOccurrenceInfo = 0
	LCSOccurrenceInfoMultipleTimeEvent LCSOccurrenceInfo = 1
)

func (v LCSOccurrenceInfo) String() string {
	switch v {
	case LCSOccurrenceInfoOneTimeEvent:
		return "oneTimeEvent"
	case LCSOccurrenceInfoMultipleTimeEvent:
		return "multipleTimeEvent"
	default:
		return "unknown"
	}
}

// LCSIntervalTime represents the ASN.1 type IntervalTime (INTEGER).
type LCSIntervalTime = int64

// LCSPeriodicLDRInfo represents the ASN.1 type PeriodicLDRInfo (SEQUENCE).
type LCSPeriodicLDRInfo struct {
	ReportingAmount             LCSReportingAmount              `asn1:""`
	ReportingInterval           LCSReportingInterval            `asn1:""`
	ReportingOptionMilliseconds *LCSReportingOptionMilliseconds `asn1:"tag:0,context,implicit,optional" json:"ReportingOptionMilliseconds,omitempty"`
	ExtCount_                   int64                           `asn1:"-" json:"-"`
	ExtPresent_                 []bool                          `asn1:"-" json:"-"`
	ExtData_                    [][]byte                        `asn1:"-" json:"-"`
	berOriginal_                []byte                          `asn1:"-" json:"-"`
	berSnapshot_                []byte                          `asn1:"-" json:"-"`
}

// LCSReportingAmount represents the ASN.1 type ReportingAmount (INTEGER).
type LCSReportingAmount = int64

// LCSReportingInterval represents the ASN.1 type ReportingInterval (INTEGER).
type LCSReportingInterval = int64

// LCSReportingOptionMilliseconds represents the ASN.1 type ReportingOptionMilliseconds (SEQUENCE).
type LCSReportingOptionMilliseconds struct {
	ReportingAmountMilliseconds   LCSReportingAmountMilliseconds   `asn1:""`
	ReportingIntervalMilliseconds LCSReportingIntervalMilliseconds `asn1:""`
	ExtCount_                     int64                            `asn1:"-" json:"-"`
	ExtPresent_                   []bool                           `asn1:"-" json:"-"`
	ExtData_                      [][]byte                         `asn1:"-" json:"-"`
	berOriginal_                  []byte                           `asn1:"-" json:"-"`
	berSnapshot_                  []byte                           `asn1:"-" json:"-"`
}

// LCSReportingAmountMilliseconds represents the ASN.1 type ReportingAmountMilliseconds (INTEGER).
type LCSReportingAmountMilliseconds = int64

// LCSReportingIntervalMilliseconds represents the ASN.1 type ReportingIntervalMilliseconds (INTEGER).
type LCSReportingIntervalMilliseconds = int64

// LCSReportingPLMNList represents the ASN.1 type ReportingPLMNList (SEQUENCE).
type LCSReportingPLMNList struct {
	PlmnListPrioritized *struct{}    `asn1:"tag:0,context,implicit,optional" json:"PlmnListPrioritized,omitempty"`
	PlmnList            *LCSPLMNList `asn1:"tag:1,context,implicit"`
	PlmnListIndef_      bool         `asn1:"-" json:"-"`
	ExtCount_           int64        `asn1:"-" json:"-"`
	ExtPresent_         []bool       `asn1:"-" json:"-"`
	ExtData_            [][]byte     `asn1:"-" json:"-"`
	berOriginal_        []byte       `asn1:"-" json:"-"`
	berSnapshot_        []byte       `asn1:"-" json:"-"`
}

// LCSPLMNList represents the ASN.1 type PLMNList (SEQUENCE_OF).
type LCSPLMNList struct {
	Values       []LCSReportingPLMN `json:"Values"`
	berOriginal_ []byte             `json:"-"`
	berSnapshot_ []byte             `json:"-"`
}

// LCSReportingPLMN represents the ASN.1 type ReportingPLMN (SEQUENCE).
type LCSReportingPLMN struct {
	PlmnId                     PLMNId3           `asn1:"tag:0,context,implicit"`
	RanTechnology              *LCSRANTechnology `asn1:"tag:1,context,implicit,optional" json:"RanTechnology,omitempty"`
	RanPeriodicLocationSupport *struct{}         `asn1:"tag:2,context,implicit,optional" json:"RanPeriodicLocationSupport,omitempty"`
	ExtCount_                  int64             `asn1:"-" json:"-"`
	ExtPresent_                []bool            `asn1:"-" json:"-"`
	ExtData_                   [][]byte          `asn1:"-" json:"-"`
	berOriginal_               []byte            `asn1:"-" json:"-"`
	berSnapshot_               []byte            `asn1:"-" json:"-"`
}

// LCSRANTechnology represents the ASN.1 ENUMERATED type RAN-Technology.
type LCSRANTechnology int64

const (
	LCSRANTechnologyGsm  LCSRANTechnology = 0
	LCSRANTechnologyUmts LCSRANTechnology = 1
)

func (v LCSRANTechnology) String() string {
	switch v {
	case LCSRANTechnologyGsm:
		return "gsm"
	case LCSRANTechnologyUmts:
		return "umts"
	default:
		return "unknown"
	}
}

// LCSProvideSubscriberLocationRes represents the ASN.1 type ProvideSubscriberLocation-Res (SEQUENCE).
type LCSProvideSubscriberLocationRes struct {
	LocationEstimate               LCSExtGeographicalInformation      `asn1:""`
	AgeOfLocationEstimate          *AgeOfLocationInformation3         `asn1:"tag:0,context,implicit,optional" json:"AgeOfLocationEstimate,omitempty"`
	ExtensionContainer             *ExtensionContainer3               `asn1:"tag:1,context,implicit,optional" json:"ExtensionContainer,omitempty"`
	AddLocationEstimate            *LCSAddGeographicalInformation     `asn1:"tag:2,context,implicit,optional" json:"AddLocationEstimate,omitempty"`
	DeferredmtLrResponseIndicator  *struct{}                          `asn1:"tag:3,context,implicit,optional" json:"DeferredmtLrResponseIndicator,omitempty"`
	GeranPositioningData           *LCSPositioningDataInformation     `asn1:"tag:4,context,implicit,optional" json:"GeranPositioningData,omitempty"`
	UtranPositioningData           *LCSUtranPositioningDataInfo       `asn1:"tag:5,context,implicit,optional" json:"UtranPositioningData,omitempty"`
	CellIdOrSai                    *CellGlobalIdOrServiceAreaIdOrLAI3 `asn1:"tag:6,context,explicit,optional" json:"CellIdOrSai,omitempty"`
	SaiPresent                     *struct{}                          `asn1:"tag:7,context,implicit,optional" json:"SaiPresent,omitempty"`
	AccuracyFulfilmentIndicator    *LCSAccuracyFulfilmentIndicator    `asn1:"tag:8,context,implicit,optional" json:"AccuracyFulfilmentIndicator,omitempty"`
	VelocityEstimate               *LCSVelocityEstimate               `asn1:"tag:9,context,implicit,optional" json:"VelocityEstimate,omitempty"`
	MoLrShortCircuitIndicator      *struct{}                          `asn1:"tag:10,context,implicit,optional" json:"MoLrShortCircuitIndicator,omitempty"`
	GeranGANSSpositioningData      *LCSGeranGANSSpositioningData      `asn1:"tag:11,context,implicit,optional" json:"GeranGANSSpositioningData,omitempty"`
	UtranGANSSpositioningData      *LCSUtranGANSSpositioningData      `asn1:"tag:12,context,implicit,optional" json:"UtranGANSSpositioningData,omitempty"`
	TargetServingNodeForHandover   *LCSServingNodeAddress             `asn1:"tag:13,context,explicit,optional" json:"TargetServingNodeForHandover,omitempty"`
	UtranAdditionalPositioningData *LCSUtranAdditionalPositioningData `asn1:"tag:14,context,implicit,optional" json:"UtranAdditionalPositioningData,omitempty"`
	UtranBaroPressureMeas          *LCSUtranBaroPressureMeas          `asn1:"tag:15,context,implicit,optional" json:"UtranBaroPressureMeas,omitempty"`
	UtranCivicAddress              *LCSUtranCivicAddress              `asn1:"tag:16,context,implicit,optional" json:"UtranCivicAddress,omitempty"`
	ExtCount_                      int64                              `asn1:"-" json:"-"`
	ExtPresent_                    []bool                             `asn1:"-" json:"-"`
	ExtData_                       [][]byte                           `asn1:"-" json:"-"`
	berOriginal_                   []byte                             `asn1:"-" json:"-"`
	berSnapshot_                   []byte                             `asn1:"-" json:"-"`
}

// LCSAccuracyFulfilmentIndicator represents the ASN.1 ENUMERATED type AccuracyFulfilmentIndicator.
type LCSAccuracyFulfilmentIndicator int64

const (
	LCSAccuracyFulfilmentIndicatorRequestedAccuracyFulfilled    LCSAccuracyFulfilmentIndicator = 0
	LCSAccuracyFulfilmentIndicatorRequestedAccuracyNotFulfilled LCSAccuracyFulfilmentIndicator = 1
)

func (v LCSAccuracyFulfilmentIndicator) String() string {
	switch v {
	case LCSAccuracyFulfilmentIndicatorRequestedAccuracyFulfilled:
		return "requestedAccuracyFulfilled"
	case LCSAccuracyFulfilmentIndicatorRequestedAccuracyNotFulfilled:
		return "requestedAccuracyNotFulfilled"
	default:
		return "unknown"
	}
}

// LCSExtGeographicalInformation represents the ASN.1 type Ext-GeographicalInformation (OCTET_STRING).
type LCSExtGeographicalInformation = []byte

// LCSVelocityEstimate represents the ASN.1 type VelocityEstimate (OCTET_STRING).
type LCSVelocityEstimate = []byte

// LCSPositioningDataInformation represents the ASN.1 type PositioningDataInformation (OCTET_STRING).
type LCSPositioningDataInformation = []byte

// LCSUtranPositioningDataInfo represents the ASN.1 type UtranPositioningDataInfo (OCTET_STRING).
type LCSUtranPositioningDataInfo = []byte

// LCSGeranGANSSpositioningData represents the ASN.1 type GeranGANSSpositioningData (OCTET_STRING).
type LCSGeranGANSSpositioningData = []byte

// LCSUtranGANSSpositioningData represents the ASN.1 type UtranGANSSpositioningData (OCTET_STRING).
type LCSUtranGANSSpositioningData = []byte

// LCSUtranAdditionalPositioningData represents the ASN.1 type UtranAdditionalPositioningData (OCTET_STRING).
type LCSUtranAdditionalPositioningData = []byte

// LCSUtranBaroPressureMeas represents the ASN.1 type UtranBaroPressureMeas (INTEGER).
type LCSUtranBaroPressureMeas = int64

// LCSUtranCivicAddress represents the ASN.1 type UtranCivicAddress (OCTET_STRING).
type LCSUtranCivicAddress = []byte

// LCSAddGeographicalInformation represents the ASN.1 type Add-GeographicalInformation (OCTET_STRING).
type LCSAddGeographicalInformation = []byte

// LCSSubscriberLocationReportArg represents the ASN.1 type SubscriberLocationReport-Arg (SEQUENCE).
type LCSSubscriberLocationReportArg struct {
	LcsEvent                       LCSLCSEvent                        `asn1:""`
	LcsClientID                    LCSLCSClientID                     `asn1:""`
	LcsLocationInfo                LCSLCSLocationInfo                 `asn1:""`
	Msisdn                         *ISDNAddressString3                `asn1:"tag:0,context,implicit,optional" json:"Msisdn,omitempty"`
	Imsi                           *IMSI3                             `asn1:"tag:1,context,implicit,optional" json:"Imsi,omitempty"`
	Imei                           *IMEI3                             `asn1:"tag:2,context,implicit,optional" json:"Imei,omitempty"`
	NaESRD                         *ISDNAddressString3                `asn1:"tag:3,context,implicit,optional" json:"NaESRD,omitempty"`
	NaESRK                         *ISDNAddressString3                `asn1:"tag:4,context,implicit,optional" json:"NaESRK,omitempty"`
	LocationEstimate               *LCSExtGeographicalInformation     `asn1:"tag:5,context,implicit,optional" json:"LocationEstimate,omitempty"`
	AgeOfLocationEstimate          *AgeOfLocationInformation3         `asn1:"tag:6,context,implicit,optional" json:"AgeOfLocationEstimate,omitempty"`
	SlrArgExtensionContainer       *SLRArgExtensionContainer3         `asn1:"tag:7,context,implicit,optional" json:"SlrArgExtensionContainer,omitempty"`
	AddLocationEstimate            *LCSAddGeographicalInformation     `asn1:"tag:8,context,implicit,optional" json:"AddLocationEstimate,omitempty"`
	DeferredmtLrData               *LCSDeferredmtLrData               `asn1:"tag:9,context,implicit,optional" json:"DeferredmtLrData,omitempty"`
	LcsReferenceNumber             *LCSLCSReferenceNumber             `asn1:"tag:10,context,implicit,optional" json:"LcsReferenceNumber,omitempty"`
	GeranPositioningData           *LCSPositioningDataInformation     `asn1:"tag:11,context,implicit,optional" json:"GeranPositioningData,omitempty"`
	UtranPositioningData           *LCSUtranPositioningDataInfo       `asn1:"tag:12,context,implicit,optional" json:"UtranPositioningData,omitempty"`
	CellIdOrSai                    *CellGlobalIdOrServiceAreaIdOrLAI3 `asn1:"tag:13,context,explicit,optional" json:"CellIdOrSai,omitempty"`
	HGmlcAddress                   *CommonDataTypesGSNAddress         `asn1:"tag:14,context,implicit,optional" json:"HGmlcAddress,omitempty"`
	LcsServiceTypeID               *LCSServiceTypeID3                 `asn1:"tag:15,context,implicit,optional" json:"LcsServiceTypeID,omitempty"`
	SaiPresent                     *struct{}                          `asn1:"tag:17,context,implicit,optional" json:"SaiPresent,omitempty"`
	PseudonymIndicator             *struct{}                          `asn1:"tag:18,context,implicit,optional" json:"PseudonymIndicator,omitempty"`
	AccuracyFulfilmentIndicator    *LCSAccuracyFulfilmentIndicator    `asn1:"tag:19,context,implicit,optional" json:"AccuracyFulfilmentIndicator,omitempty"`
	VelocityEstimate               *LCSVelocityEstimate               `asn1:"tag:20,context,implicit,optional" json:"VelocityEstimate,omitempty"`
	SequenceNumber                 *LCSSequenceNumber                 `asn1:"tag:21,context,implicit,optional" json:"SequenceNumber,omitempty"`
	PeriodicLDRInfo                *LCSPeriodicLDRInfo                `asn1:"tag:22,context,implicit,optional" json:"PeriodicLDRInfo,omitempty"`
	MoLrShortCircuitIndicator      *struct{}                          `asn1:"tag:23,context,implicit,optional" json:"MoLrShortCircuitIndicator,omitempty"`
	GeranGANSSpositioningData      *LCSGeranGANSSpositioningData      `asn1:"tag:24,context,implicit,optional" json:"GeranGANSSpositioningData,omitempty"`
	UtranGANSSpositioningData      *LCSUtranGANSSpositioningData      `asn1:"tag:25,context,implicit,optional" json:"UtranGANSSpositioningData,omitempty"`
	TargetServingNodeForHandover   *LCSServingNodeAddress             `asn1:"tag:26,context,explicit,optional" json:"TargetServingNodeForHandover,omitempty"`
	UtranAdditionalPositioningData *LCSUtranAdditionalPositioningData `asn1:"tag:27,context,implicit,optional" json:"UtranAdditionalPositioningData,omitempty"`
	UtranBaroPressureMeas          *LCSUtranBaroPressureMeas          `asn1:"tag:28,context,implicit,optional" json:"UtranBaroPressureMeas,omitempty"`
	UtranCivicAddress              *LCSUtranCivicAddress              `asn1:"tag:29,context,implicit,optional" json:"UtranCivicAddress,omitempty"`
	ExtCount_                      int64                              `asn1:"-" json:"-"`
	ExtPresent_                    []bool                             `asn1:"-" json:"-"`
	ExtData_                       [][]byte                           `asn1:"-" json:"-"`
	berOriginal_                   []byte                             `asn1:"-" json:"-"`
	berSnapshot_                   []byte                             `asn1:"-" json:"-"`
}

// LCSDeferredmtLrData represents the ASN.1 type Deferredmt-lrData (SEQUENCE).
type LCSDeferredmtLrData struct {
	DeferredLocationEventType LCSDeferredLocationEventType `asn1:""`
	TerminationCause          *LCSTerminationCause         `asn1:"tag:0,context,implicit,optional" json:"TerminationCause,omitempty"`
	LcsLocationInfo           *LCSLCSLocationInfo          `asn1:"tag:1,context,implicit,optional" json:"LcsLocationInfo,omitempty"`
	ExtCount_                 int64                        `asn1:"-" json:"-"`
	ExtPresent_               []bool                       `asn1:"-" json:"-"`
	ExtData_                  [][]byte                     `asn1:"-" json:"-"`
	berOriginal_              []byte                       `asn1:"-" json:"-"`
	berSnapshot_              []byte                       `asn1:"-" json:"-"`
}

// LCSLCSEvent represents the ASN.1 ENUMERATED type LCS-Event.
type LCSLCSEvent int64

const (
	LCSLCSEventEmergencyCallOrigination   LCSLCSEvent = 0
	LCSLCSEventEmergencyCallRelease       LCSLCSEvent = 1
	LCSLCSEventMoLr                       LCSLCSEvent = 2
	LCSLCSEventDeferredmtLrResponse       LCSLCSEvent = 3
	LCSLCSEventDeferredmoLrTTTPInitiation LCSLCSEvent = 4
	LCSLCSEventEmergencyCallHandover      LCSLCSEvent = 5
)

func (v LCSLCSEvent) String() string {
	switch v {
	case LCSLCSEventEmergencyCallOrigination:
		return "emergencyCallOrigination"
	case LCSLCSEventEmergencyCallRelease:
		return "emergencyCallRelease"
	case LCSLCSEventMoLr:
		return "mo-lr"
	case LCSLCSEventDeferredmtLrResponse:
		return "deferredmt-lrResponse"
	case LCSLCSEventDeferredmoLrTTTPInitiation:
		return "deferredmo-lrTTTPInitiation"
	case LCSLCSEventEmergencyCallHandover:
		return "emergencyCallHandover"
	default:
		return "unknown"
	}
}

// LCSTerminationCause represents the ASN.1 ENUMERATED type TerminationCause.
type LCSTerminationCause int64

const (
	LCSTerminationCauseNormal                              LCSTerminationCause = 0
	LCSTerminationCauseErrorundefined                      LCSTerminationCause = 1
	LCSTerminationCauseInternalTimeout                     LCSTerminationCause = 2
	LCSTerminationCauseCongestion                          LCSTerminationCause = 3
	LCSTerminationCauseMtLrRestart                         LCSTerminationCause = 4
	LCSTerminationCausePrivacyViolation                    LCSTerminationCause = 5
	LCSTerminationCauseShapeOfLocationEstimateNotSupported LCSTerminationCause = 6
	LCSTerminationCauseSubscriberTermination               LCSTerminationCause = 7
	LCSTerminationCauseUETermination                       LCSTerminationCause = 8
	LCSTerminationCauseNetworkTermination                  LCSTerminationCause = 9
)

func (v LCSTerminationCause) String() string {
	switch v {
	case LCSTerminationCauseNormal:
		return "normal"
	case LCSTerminationCauseErrorundefined:
		return "errorundefined"
	case LCSTerminationCauseInternalTimeout:
		return "internalTimeout"
	case LCSTerminationCauseCongestion:
		return "congestion"
	case LCSTerminationCauseMtLrRestart:
		return "mt-lrRestart"
	case LCSTerminationCausePrivacyViolation:
		return "privacyViolation"
	case LCSTerminationCauseShapeOfLocationEstimateNotSupported:
		return "shapeOfLocationEstimateNotSupported"
	case LCSTerminationCauseSubscriberTermination:
		return "subscriberTermination"
	case LCSTerminationCauseUETermination:
		return "uETermination"
	case LCSTerminationCauseNetworkTermination:
		return "networkTermination"
	default:
		return "unknown"
	}
}

// LCSSequenceNumber represents the ASN.1 type SequenceNumber (INTEGER).
type LCSSequenceNumber = int64

// LCSServingNodeAddress choice constants.
const (
	LCSServingNodeAddressChoiceMscNumber  = 1
	LCSServingNodeAddressChoiceSgsnNumber = 2
	LCSServingNodeAddressChoiceMmeNumber  = 3
)

// LCSServingNodeAddress represents the ASN.1 CHOICE type ServingNodeAddress.
type LCSServingNodeAddress struct {
	Choice       int
	berOriginal_ []byte                           `json:"-"`
	berSnapshot_ []byte                           `json:"-"`
	MscNumber    *ISDNAddressString3              `json:"MscNumber,omitempty"`
	SgsnNumber   *ISDNAddressString3              `json:"SgsnNumber,omitempty"`
	MmeNumber    *CommonDataTypesDiameterIdentity `json:"MmeNumber,omitempty"`
}

// NewLCSServingNodeAddressMscNumber creates a LCSServingNodeAddress with the msc-Number alternative.
func NewLCSServingNodeAddressMscNumber(v ISDNAddressString3) LCSServingNodeAddress {
	return LCSServingNodeAddress{
		Choice:    LCSServingNodeAddressChoiceMscNumber,
		MscNumber: &v,
	}
}

// NewLCSServingNodeAddressSgsnNumber creates a LCSServingNodeAddress with the sgsn-Number alternative.
func NewLCSServingNodeAddressSgsnNumber(v ISDNAddressString3) LCSServingNodeAddress {
	return LCSServingNodeAddress{
		Choice:     LCSServingNodeAddressChoiceSgsnNumber,
		SgsnNumber: &v,
	}
}

// NewLCSServingNodeAddressMmeNumber creates a LCSServingNodeAddress with the mme-Number alternative.
func NewLCSServingNodeAddressMmeNumber(v CommonDataTypesDiameterIdentity) LCSServingNodeAddress {
	return LCSServingNodeAddress{
		Choice:    LCSServingNodeAddressChoiceMmeNumber,
		MmeNumber: &v,
	}
}

// LCSSubscriberLocationReportRes represents the ASN.1 type SubscriberLocationReport-Res (SEQUENCE).
type LCSSubscriberLocationReportRes struct {
	ExtensionContainer        *ExtensionContainer3       `asn1:",optional" json:"ExtensionContainer,omitempty"`
	NaESRK                    *ISDNAddressString3        `asn1:"tag:0,context,implicit,optional" json:"NaESRK,omitempty"`
	NaESRD                    *ISDNAddressString3        `asn1:"tag:1,context,implicit,optional" json:"NaESRD,omitempty"`
	HGmlcAddress              *CommonDataTypesGSNAddress `asn1:"tag:2,context,implicit,optional" json:"HGmlcAddress,omitempty"`
	MoLrShortCircuitIndicator *struct{}                  `asn1:"tag:3,context,implicit,optional" json:"MoLrShortCircuitIndicator,omitempty"`
	ReportingPLMNList         *LCSReportingPLMNList      `asn1:"tag:4,context,implicit,optional" json:"ReportingPLMNList,omitempty"`
	LcsReferenceNumber        *LCSLCSReferenceNumber     `asn1:"tag:5,context,implicit,optional" json:"LcsReferenceNumber,omitempty"`
	ExtCount_                 int64                      `asn1:"-" json:"-"`
	ExtPresent_               []bool                     `asn1:"-" json:"-"`
	ExtData_                  [][]byte                   `asn1:"-" json:"-"`
	berOriginal_              []byte                     `asn1:"-" json:"-"`
	berSnapshot_              []byte                     `asn1:"-" json:"-"`
}

// MarshalBER encodes LCSRoutingInfoForLCSArg to BER format.
func (v *LCSRoutingInfoForLCSArg) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: LCSRoutingInfoForLCSArg receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *LCSRoutingInfoForLCSArg) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if len(v.MlcNumber) < 1 || len(v.MlcNumber) > 9 {
		if constraintErr := ber.CheckEncodedLength(opts, "mlcNumber", "SIZE (1..9)", len(v.MlcNumber)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	if len(v.MlcNumber) < 1 || len(v.MlcNumber) > 20 {
		if constraintErr := ber.CheckEncodedLength(opts, "mlcNumber", "SIZE (1..20)", len(v.MlcNumber)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_mlcnumber, encodeErr_enc_mlcnumber := ber.EncodeOctetString([]byte(v.MlcNumber))
	if encodeErr_enc_mlcnumber != nil {
		return nil, fmt.Errorf("encoding mlcNumber: %w", encodeErr_enc_mlcnumber)
	}
	retagged_enc_mlcnumber, tagErr_enc_mlcnumber := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_mlcnumber)
	if tagErr_enc_mlcnumber != nil {
		return nil, fmt.Errorf("encoding mlcNumber: %w", tagErr_enc_mlcnumber)
	}
	enc_mlcnumber = retagged_enc_mlcnumber
	children = append(children, enc_mlcnumber...)
	enc_targetms, err := v.TargetMS.MarshalBER(ber.ChildEncodeOptions(opts, "targetMS")...)
	if err != nil {
		return nil, fmt.Errorf("encoding targetMS: %w", err)
	}
	{
		var encodeErr error
		enc_targetms, encodeErr = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 1, enc_targetms)
		if encodeErr != nil {
			return nil, fmt.Errorf("encoding targetMS: %w", encodeErr)
		}
	}
	children = append(children, enc_targetms...)
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

// MarshalDER encodes LCSRoutingInfoForLCSArg to DER format.
func (v *LCSRoutingInfoForLCSArg) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: LCSRoutingInfoForLCSArg receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if len(v.MlcNumber) < 1 || len(v.MlcNumber) > 9 {
		if constraintErr := ber.CheckEncodedLength(nil, "mlcNumber", "SIZE (1..9)", len(v.MlcNumber)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	if len(v.MlcNumber) < 1 || len(v.MlcNumber) > 20 {
		if constraintErr := ber.CheckEncodedLength(nil, "mlcNumber", "SIZE (1..20)", len(v.MlcNumber)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_mlcnumber, encodeErr_enc_mlcnumber := ber.EncodeOctetString([]byte(v.MlcNumber))
	if encodeErr_enc_mlcnumber != nil {
		return nil, fmt.Errorf("encoding mlcNumber: %w", encodeErr_enc_mlcnumber)
	}
	retagged_enc_mlcnumber, tagErr_enc_mlcnumber := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_mlcnumber)
	if tagErr_enc_mlcnumber != nil {
		return nil, fmt.Errorf("encoding mlcNumber: %w", tagErr_enc_mlcnumber)
	}
	enc_mlcnumber = retagged_enc_mlcnumber
	children = append(children, enc_mlcnumber...)
	enc_targetms, err := v.TargetMS.MarshalDER()
	if err != nil {
		return nil, fmt.Errorf("encoding targetMS: %w", err)
	}
	{
		var encodeErr error
		enc_targetms, encodeErr = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 1, enc_targetms)
		if encodeErr != nil {
			return nil, fmt.Errorf("encoding targetMS: %w", encodeErr)
		}
	}
	children = append(children, enc_targetms...)
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
		return nil, fmt.Errorf("encoding LCSRoutingInfoForLCSArg as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes LCSRoutingInfoForLCSArg from BER/DER format.
func (v *LCSRoutingInfoForLCSArg) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: LCSRoutingInfoForLCSArg destination is nil", ber.ErrInvalidValue)
	}
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = LCSRoutingInfoForLCSArg{}
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
		return fmt.Errorf("decoding LCSRoutingInfoForLCSArg SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "LCSRoutingInfoForLCSArg", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode mlcNumber
	if offset >= len(content) {
		return fmt.Errorf("missing required field mlcNumber")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 0 {
			return fmt.Errorf("expected tag [%s %d] for mlcNumber, got %s", "CONTEXT", 0, reqTag_)
		}
	}
	decodedTag_mlcnumber, n_mlcnumber, rawVal_mlcnumber, err := ber.DecodeTLV(content[offset:], opts...)
	if err != nil {
		return fmt.Errorf("decoding mlcNumber: %w", err)
	}
	if decodedTag_mlcnumber.Class != tag.ClassContextSpecific || decodedTag_mlcnumber.Number != 0 {
		return fmt.Errorf("decoding mlcNumber: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_mlcnumber)
	}
	decVal_mlcnumber, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_mlcnumber.Constructed, rawVal_mlcnumber, opts...)
	if octetErr != nil {
		return fmt.Errorf("decoding mlcNumber: %w", octetErr)
	}
	v.MlcNumber = ISDNAddressString3(decVal_mlcnumber)
	if offset < 0 || offset >
		len(content) || n_mlcnumber < 0 || n_mlcnumber > len(content[offset:]) {
		return fmt.Errorf("invalid BER content window")
	}

	offset += n_mlcnumber
	if len(v.MlcNumber) < 1 || len(v.MlcNumber) > 9 {
		if constraintErr := ber.CheckDecodedLength(opts, "mlcNumber", "SIZE (1..9)", len(v.MlcNumber)); constraintErr != nil {
			return constraintErr
		}
	}
	if len(v.MlcNumber) < 1 || len(v.MlcNumber) > 20 {
		if constraintErr := ber.CheckDecodedLength(opts, "mlcNumber", "SIZE (1..20)", len(v.MlcNumber)); constraintErr != nil {
			return constraintErr
		}
	}
	// Decode targetMS
	if offset >= len(content) {
		return fmt.Errorf("missing required field targetMS")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 1 {
			return fmt.Errorf("expected tag [%s %d] for targetMS, got %s", "CONTEXT", 1, reqTag_)
		}
	}
	decodedTag_targetms, n_targetms, innerData_targetms, err := ber.DecodeTLV(content[offset:], opts...)
	if err != nil {
		return fmt.Errorf("decoding targetMS: %w", err)
	}
	if decodedTag_targetms.Class != tag.ClassContextSpecific || decodedTag_targetms.Number != 1 || decodedTag_targetms.Constructed != true {
		return fmt.Errorf("decoding targetMS: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_targetms)
	}
	// Decode inner value from explicit tag wrapper
	if unmErr := v.TargetMS.UnmarshalBER(innerData_targetms, ber.ChildDecodeOptions(opts, "targetMS")...); unmErr != nil {
		return fmt.Errorf("decoding targetMS: %w", unmErr)
	}
	if offset < 0 || offset >
		len(content) || n_targetms < 0 || n_targetms > len(content[offset:]) {
		return fmt.Errorf("invalid BER content window")
	}

	offset += n_targetms
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
				var dec_extensioncontainer ExtensionContainer3
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
			return &ber.DecodeError{Offset: offset, TypeName: "LCSRoutingInfoForLCSArg", Cause: extErr_}
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

// MarshalBER encodes LCSRoutingInfoForLCSRes to BER format.
func (v *LCSRoutingInfoForLCSRes) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: LCSRoutingInfoForLCSRes receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *LCSRoutingInfoForLCSRes) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	enc_targetms, err := v.TargetMS.MarshalBER(ber.ChildEncodeOptions(opts, "targetMS")...)
	if err != nil {
		return nil, fmt.Errorf("encoding targetMS: %w", err)
	}
	{
		var encodeErr error
		enc_targetms, encodeErr = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 0, enc_targetms)
		if encodeErr != nil {
			return nil, fmt.Errorf("encoding targetMS: %w", encodeErr)
		}
	}
	children = append(children, enc_targetms...)
	enc_lcslocationinfo, err := v.LcsLocationInfo.MarshalBER(ber.ChildEncodeOptions(opts, "lcsLocationInfo")...)
	if err != nil {
		return nil, fmt.Errorf("encoding lcsLocationInfo: %w", err)
	}
	retagged_enc_lcslocationinfo, tagErr_enc_lcslocationinfo := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_lcslocationinfo)
	if tagErr_enc_lcslocationinfo != nil {
		return nil, fmt.Errorf("encoding lcsLocationInfo: %w", tagErr_enc_lcslocationinfo)
	}
	enc_lcslocationinfo = retagged_enc_lcslocationinfo
	children = append(children, enc_lcslocationinfo...)
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
	if v.VGmlcAddress != nil {
		if len(*v.VGmlcAddress) < 5 || len(*v.VGmlcAddress) > 17 {
			if constraintErr := ber.CheckEncodedLength(opts, "v-gmlc-Address", "SIZE (5..17)", len(*v.VGmlcAddress)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_vgmlcaddress, encodeErr_enc_vgmlcaddress := ber.EncodeOctetString([]byte(*v.VGmlcAddress))
		if encodeErr_enc_vgmlcaddress != nil {
			return nil, fmt.Errorf("encoding v-gmlc-Address: %w", encodeErr_enc_vgmlcaddress)
		}
		retagged_enc_vgmlcaddress, tagErr_enc_vgmlcaddress := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, enc_vgmlcaddress)
		if tagErr_enc_vgmlcaddress != nil {
			return nil, fmt.Errorf("encoding v-gmlc-Address: %w", tagErr_enc_vgmlcaddress)
		}
		enc_vgmlcaddress = retagged_enc_vgmlcaddress
		children = append(children, enc_vgmlcaddress...)
	}
	if v.HGmlcAddress != nil {
		if len(*v.HGmlcAddress) < 5 || len(*v.HGmlcAddress) > 17 {
			if constraintErr := ber.CheckEncodedLength(opts, "h-gmlc-Address", "SIZE (5..17)", len(*v.HGmlcAddress)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_hgmlcaddress, encodeErr_enc_hgmlcaddress := ber.EncodeOctetString([]byte(*v.HGmlcAddress))
		if encodeErr_enc_hgmlcaddress != nil {
			return nil, fmt.Errorf("encoding h-gmlc-Address: %w", encodeErr_enc_hgmlcaddress)
		}
		retagged_enc_hgmlcaddress, tagErr_enc_hgmlcaddress := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, enc_hgmlcaddress)
		if tagErr_enc_hgmlcaddress != nil {
			return nil, fmt.Errorf("encoding h-gmlc-Address: %w", tagErr_enc_hgmlcaddress)
		}
		enc_hgmlcaddress = retagged_enc_hgmlcaddress
		children = append(children, enc_hgmlcaddress...)
	}
	if v.PprAddress != nil {
		if len(*v.PprAddress) < 5 || len(*v.PprAddress) > 17 {
			if constraintErr := ber.CheckEncodedLength(opts, "ppr-Address", "SIZE (5..17)", len(*v.PprAddress)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_ppraddress, encodeErr_enc_ppraddress := ber.EncodeOctetString([]byte(*v.PprAddress))
		if encodeErr_enc_ppraddress != nil {
			return nil, fmt.Errorf("encoding ppr-Address: %w", encodeErr_enc_ppraddress)
		}
		retagged_enc_ppraddress, tagErr_enc_ppraddress := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 5, enc_ppraddress)
		if tagErr_enc_ppraddress != nil {
			return nil, fmt.Errorf("encoding ppr-Address: %w", tagErr_enc_ppraddress)
		}
		enc_ppraddress = retagged_enc_ppraddress
		children = append(children, enc_ppraddress...)
	}
	if v.AdditionalVGmlcAddress != nil {
		if len(*v.AdditionalVGmlcAddress) < 5 || len(*v.AdditionalVGmlcAddress) > 17 {
			if constraintErr := ber.CheckEncodedLength(opts, "additional-v-gmlc-Address", "SIZE (5..17)", len(*v.AdditionalVGmlcAddress)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_additionalvgmlcaddress, encodeErr_enc_additionalvgmlcaddress := ber.EncodeOctetString([]byte(*v.AdditionalVGmlcAddress))
		if encodeErr_enc_additionalvgmlcaddress != nil {
			return nil, fmt.Errorf("encoding additional-v-gmlc-Address: %w", encodeErr_enc_additionalvgmlcaddress)
		}
		retagged_enc_additionalvgmlcaddress, tagErr_enc_additionalvgmlcaddress := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 6, enc_additionalvgmlcaddress)
		if tagErr_enc_additionalvgmlcaddress != nil {
			return nil, fmt.Errorf("encoding additional-v-gmlc-Address: %w", tagErr_enc_additionalvgmlcaddress)
		}
		enc_additionalvgmlcaddress = retagged_enc_additionalvgmlcaddress
		children = append(children, enc_additionalvgmlcaddress...)
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

// MarshalDER encodes LCSRoutingInfoForLCSRes to DER format.
func (v *LCSRoutingInfoForLCSRes) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: LCSRoutingInfoForLCSRes receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	enc_targetms, err := v.TargetMS.MarshalDER()
	if err != nil {
		return nil, fmt.Errorf("encoding targetMS: %w", err)
	}
	{
		var encodeErr error
		enc_targetms, encodeErr = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 0, enc_targetms)
		if encodeErr != nil {
			return nil, fmt.Errorf("encoding targetMS: %w", encodeErr)
		}
	}
	children = append(children, enc_targetms...)
	enc_lcslocationinfo, err := v.LcsLocationInfo.MarshalDER()
	if err != nil {
		return nil, fmt.Errorf("encoding lcsLocationInfo: %w", err)
	}
	retagged_enc_lcslocationinfo, tagErr_enc_lcslocationinfo := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_lcslocationinfo)
	if tagErr_enc_lcslocationinfo != nil {
		return nil, fmt.Errorf("encoding lcsLocationInfo: %w", tagErr_enc_lcslocationinfo)
	}
	enc_lcslocationinfo = retagged_enc_lcslocationinfo
	children = append(children, enc_lcslocationinfo...)
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
	if v.VGmlcAddress != nil {
		if len(*v.VGmlcAddress) < 5 || len(*v.VGmlcAddress) > 17 {
			if constraintErr := ber.CheckEncodedLength(nil, "v-gmlc-Address", "SIZE (5..17)", len(*v.VGmlcAddress)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_vgmlcaddress, encodeErr_enc_vgmlcaddress := ber.EncodeOctetString([]byte(*v.VGmlcAddress))
		if encodeErr_enc_vgmlcaddress != nil {
			return nil, fmt.Errorf("encoding v-gmlc-Address: %w", encodeErr_enc_vgmlcaddress)
		}
		retagged_enc_vgmlcaddress, tagErr_enc_vgmlcaddress := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, enc_vgmlcaddress)
		if tagErr_enc_vgmlcaddress != nil {
			return nil, fmt.Errorf("encoding v-gmlc-Address: %w", tagErr_enc_vgmlcaddress)
		}
		enc_vgmlcaddress = retagged_enc_vgmlcaddress
		children = append(children, enc_vgmlcaddress...)
	}
	if v.HGmlcAddress != nil {
		if len(*v.HGmlcAddress) < 5 || len(*v.HGmlcAddress) > 17 {
			if constraintErr := ber.CheckEncodedLength(nil, "h-gmlc-Address", "SIZE (5..17)", len(*v.HGmlcAddress)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_hgmlcaddress, encodeErr_enc_hgmlcaddress := ber.EncodeOctetString([]byte(*v.HGmlcAddress))
		if encodeErr_enc_hgmlcaddress != nil {
			return nil, fmt.Errorf("encoding h-gmlc-Address: %w", encodeErr_enc_hgmlcaddress)
		}
		retagged_enc_hgmlcaddress, tagErr_enc_hgmlcaddress := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, enc_hgmlcaddress)
		if tagErr_enc_hgmlcaddress != nil {
			return nil, fmt.Errorf("encoding h-gmlc-Address: %w", tagErr_enc_hgmlcaddress)
		}
		enc_hgmlcaddress = retagged_enc_hgmlcaddress
		children = append(children, enc_hgmlcaddress...)
	}
	if v.PprAddress != nil {
		if len(*v.PprAddress) < 5 || len(*v.PprAddress) > 17 {
			if constraintErr := ber.CheckEncodedLength(nil, "ppr-Address", "SIZE (5..17)", len(*v.PprAddress)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_ppraddress, encodeErr_enc_ppraddress := ber.EncodeOctetString([]byte(*v.PprAddress))
		if encodeErr_enc_ppraddress != nil {
			return nil, fmt.Errorf("encoding ppr-Address: %w", encodeErr_enc_ppraddress)
		}
		retagged_enc_ppraddress, tagErr_enc_ppraddress := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 5, enc_ppraddress)
		if tagErr_enc_ppraddress != nil {
			return nil, fmt.Errorf("encoding ppr-Address: %w", tagErr_enc_ppraddress)
		}
		enc_ppraddress = retagged_enc_ppraddress
		children = append(children, enc_ppraddress...)
	}
	if v.AdditionalVGmlcAddress != nil {
		if len(*v.AdditionalVGmlcAddress) < 5 || len(*v.AdditionalVGmlcAddress) > 17 {
			if constraintErr := ber.CheckEncodedLength(nil, "additional-v-gmlc-Address", "SIZE (5..17)", len(*v.AdditionalVGmlcAddress)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_additionalvgmlcaddress, encodeErr_enc_additionalvgmlcaddress := ber.EncodeOctetString([]byte(*v.AdditionalVGmlcAddress))
		if encodeErr_enc_additionalvgmlcaddress != nil {
			return nil, fmt.Errorf("encoding additional-v-gmlc-Address: %w", encodeErr_enc_additionalvgmlcaddress)
		}
		retagged_enc_additionalvgmlcaddress, tagErr_enc_additionalvgmlcaddress := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 6, enc_additionalvgmlcaddress)
		if tagErr_enc_additionalvgmlcaddress != nil {
			return nil, fmt.Errorf("encoding additional-v-gmlc-Address: %w", tagErr_enc_additionalvgmlcaddress)
		}
		enc_additionalvgmlcaddress = retagged_enc_additionalvgmlcaddress
		children = append(children, enc_additionalvgmlcaddress...)
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
		return nil, fmt.Errorf("encoding LCSRoutingInfoForLCSRes as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes LCSRoutingInfoForLCSRes from BER/DER format.
func (v *LCSRoutingInfoForLCSRes) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: LCSRoutingInfoForLCSRes destination is nil", ber.ErrInvalidValue)
	}
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = LCSRoutingInfoForLCSRes{}
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
		return fmt.Errorf("decoding LCSRoutingInfoForLCSRes SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "LCSRoutingInfoForLCSRes", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode targetMS
	if offset >= len(content) {
		return fmt.Errorf("missing required field targetMS")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 0 {
			return fmt.Errorf("expected tag [%s %d] for targetMS, got %s", "CONTEXT", 0, reqTag_)
		}
	}
	decodedTag_targetms, n_targetms, innerData_targetms, err := ber.DecodeTLV(content[offset:], opts...)
	if err != nil {
		return fmt.Errorf("decoding targetMS: %w", err)
	}
	if decodedTag_targetms.Class != tag.ClassContextSpecific || decodedTag_targetms.Number != 0 || decodedTag_targetms.Constructed != true {
		return fmt.Errorf("decoding targetMS: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_targetms)
	}
	// Decode inner value from explicit tag wrapper
	if unmErr := v.TargetMS.UnmarshalBER(innerData_targetms, ber.ChildDecodeOptions(opts, "targetMS")...); unmErr != nil {
		return fmt.Errorf("decoding targetMS: %w", unmErr)
	}
	if offset < 0 || offset >
		len(content) || n_targetms < 0 || n_targetms > len(content[offset:]) {
		return fmt.Errorf("invalid BER content window")
	}

	offset += n_targetms
	// Decode lcsLocationInfo
	if offset >= len(content) {
		return fmt.Errorf("missing required field lcsLocationInfo")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 1 {
			return fmt.Errorf("expected tag [%s %d] for lcsLocationInfo, got %s", "CONTEXT", 1, reqTag_)
		}
	}
	decodedTag_lcslocationinfo, n_lcslocationinfo, rawVal_lcslocationinfo, err := ber.DecodeTLV(content[offset:], opts...)
	if err != nil {
		return fmt.Errorf("decoding lcsLocationInfo: %w", err)
	}
	if decodedTag_lcslocationinfo.Class != tag.ClassContextSpecific || decodedTag_lcslocationinfo.Number != 1 || decodedTag_lcslocationinfo.Constructed != true {
		return fmt.Errorf("decoding lcsLocationInfo: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_lcslocationinfo)
	}
	reconstructed_lcslocationinfo, reconstructionErr_lcslocationinfo := ber.EncodeSequence(rawVal_lcslocationinfo)
	if reconstructionErr_lcslocationinfo != nil {
		return fmt.Errorf("decoding lcsLocationInfo: %w", reconstructionErr_lcslocationinfo)
	}
	if unmErr := v.LcsLocationInfo.UnmarshalBER(reconstructed_lcslocationinfo, ber.ChildDecodeOptions(opts, "lcsLocationInfo")...); unmErr != nil {
		return fmt.Errorf("decoding lcsLocationInfo: %w", unmErr)
	}
	if offset < 0 || offset >
		len(content) || n_lcslocationinfo < 0 || n_lcslocationinfo > len(content[offset:]) {
		return fmt.Errorf("invalid BER content window")
	}

	offset += n_lcslocationinfo
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
				var dec_extensioncontainer ExtensionContainer3
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
	// Decode v-gmlc-Address
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3 {
				decodedTag_vgmlcaddress, n_vgmlcaddress, rawVal_vgmlcaddress, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding v-gmlc-Address: %w", err)
				}
				if decodedTag_vgmlcaddress.Class != tag.ClassContextSpecific || decodedTag_vgmlcaddress.Number != 3 {
					return fmt.Errorf("decoding v-gmlc-Address: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_vgmlcaddress)
				}
				decVal_vgmlcaddress, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_vgmlcaddress.Constructed, rawVal_vgmlcaddress, opts...)
				if octetErr != nil {
					return fmt.Errorf("decoding v-gmlc-Address: %w", octetErr)
				}
				tmp_vgmlcaddress := CommonDataTypesGSNAddress(decVal_vgmlcaddress)
				v.VGmlcAddress = &tmp_vgmlcaddress
				if offset < 0 || offset >
					len(content) || n_vgmlcaddress < 0 || n_vgmlcaddress > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_vgmlcaddress
				if len(*v.VGmlcAddress) < 5 || len(*v.VGmlcAddress) > 17 {
					if constraintErr := ber.CheckDecodedLength(opts, "v-gmlc-Address", "SIZE (5..17)", len(*v.VGmlcAddress)); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode h-gmlc-Address
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4 {
				decodedTag_hgmlcaddress, n_hgmlcaddress, rawVal_hgmlcaddress, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding h-gmlc-Address: %w", err)
				}
				if decodedTag_hgmlcaddress.Class != tag.ClassContextSpecific || decodedTag_hgmlcaddress.Number != 4 {
					return fmt.Errorf("decoding h-gmlc-Address: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_hgmlcaddress)
				}
				decVal_hgmlcaddress, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_hgmlcaddress.Constructed, rawVal_hgmlcaddress, opts...)
				if octetErr != nil {
					return fmt.Errorf("decoding h-gmlc-Address: %w", octetErr)
				}
				tmp_hgmlcaddress := CommonDataTypesGSNAddress(decVal_hgmlcaddress)
				v.HGmlcAddress = &tmp_hgmlcaddress
				if offset < 0 || offset >
					len(content) || n_hgmlcaddress < 0 || n_hgmlcaddress > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_hgmlcaddress
				if len(*v.HGmlcAddress) < 5 || len(*v.HGmlcAddress) > 17 {
					if constraintErr := ber.CheckDecodedLength(opts, "h-gmlc-Address", "SIZE (5..17)", len(*v.HGmlcAddress)); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode ppr-Address
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 5 {
				decodedTag_ppraddress, n_ppraddress, rawVal_ppraddress, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding ppr-Address: %w", err)
				}
				if decodedTag_ppraddress.Class != tag.ClassContextSpecific || decodedTag_ppraddress.Number != 5 {
					return fmt.Errorf("decoding ppr-Address: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_ppraddress)
				}
				decVal_ppraddress, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_ppraddress.Constructed, rawVal_ppraddress, opts...)
				if octetErr != nil {
					return fmt.Errorf("decoding ppr-Address: %w", octetErr)
				}
				tmp_ppraddress := CommonDataTypesGSNAddress(decVal_ppraddress)
				v.PprAddress = &tmp_ppraddress
				if offset < 0 || offset >
					len(content) || n_ppraddress < 0 || n_ppraddress > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_ppraddress
				if len(*v.PprAddress) < 5 || len(*v.PprAddress) > 17 {
					if constraintErr := ber.CheckDecodedLength(opts, "ppr-Address", "SIZE (5..17)", len(*v.PprAddress)); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode additional-v-gmlc-Address
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 6 {
				decodedTag_additionalvgmlcaddress, n_additionalvgmlcaddress, rawVal_additionalvgmlcaddress, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding additional-v-gmlc-Address: %w", err)
				}
				if decodedTag_additionalvgmlcaddress.Class != tag.ClassContextSpecific || decodedTag_additionalvgmlcaddress.Number != 6 {
					return fmt.Errorf("decoding additional-v-gmlc-Address: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_additionalvgmlcaddress)
				}
				decVal_additionalvgmlcaddress, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_additionalvgmlcaddress.Constructed, rawVal_additionalvgmlcaddress, opts...)
				if octetErr != nil {
					return fmt.Errorf("decoding additional-v-gmlc-Address: %w", octetErr)
				}
				tmp_additionalvgmlcaddress := CommonDataTypesGSNAddress(decVal_additionalvgmlcaddress)
				v.AdditionalVGmlcAddress = &tmp_additionalvgmlcaddress
				if offset < 0 || offset >
					len(content) || n_additionalvgmlcaddress < 0 || n_additionalvgmlcaddress >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_additionalvgmlcaddress
				if len(*v.AdditionalVGmlcAddress) < 5 || len(*v.AdditionalVGmlcAddress) > 17 {
					if constraintErr := ber.CheckDecodedLength(opts, "additional-v-gmlc-Address", "SIZE (5..17)", len(*v.AdditionalVGmlcAddress)); constraintErr != nil {
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
			return &ber.DecodeError{Offset: offset, TypeName: "LCSRoutingInfoForLCSRes", Cause: extErr_}
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

// MarshalBER encodes LCSLCSLocationInfo to BER format.
func (v *LCSLCSLocationInfo) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: LCSLCSLocationInfo receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *LCSLCSLocationInfo) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if len(v.NetworkNodeNumber) < 1 || len(v.NetworkNodeNumber) > 9 {
		if constraintErr := ber.CheckEncodedLength(opts, "networkNode-Number", "SIZE (1..9)", len(v.NetworkNodeNumber)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	if len(v.NetworkNodeNumber) < 1 || len(v.NetworkNodeNumber) > 20 {
		if constraintErr := ber.CheckEncodedLength(opts, "networkNode-Number", "SIZE (1..20)", len(v.NetworkNodeNumber)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_networknodenumber, encodeErr_enc_networknodenumber := ber.EncodeOctetString([]byte(v.NetworkNodeNumber))
	if encodeErr_enc_networknodenumber != nil {
		return nil, fmt.Errorf("encoding networkNode-Number: %w", encodeErr_enc_networknodenumber)
	}
	children = append(children, enc_networknodenumber...)
	if v.Lmsi != nil {
		if len(*v.Lmsi) < 4 || len(*v.Lmsi) > 4 {
			if constraintErr := ber.CheckEncodedLength(opts, "lmsi", "SIZE (4)", len(*v.Lmsi)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_lmsi, encodeErr_enc_lmsi := ber.EncodeOctetString([]byte(*v.Lmsi))
		if encodeErr_enc_lmsi != nil {
			return nil, fmt.Errorf("encoding lmsi: %w", encodeErr_enc_lmsi)
		}
		retagged_enc_lmsi, tagErr_enc_lmsi := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_lmsi)
		if tagErr_enc_lmsi != nil {
			return nil, fmt.Errorf("encoding lmsi: %w", tagErr_enc_lmsi)
		}
		enc_lmsi = retagged_enc_lmsi
		children = append(children, enc_lmsi...)
	}
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalBER(ber.ChildEncodeOptions(opts, "extensionContainer")...)
		if err != nil {
			return nil, fmt.Errorf("encoding extensionContainer: %w", err)
		}
		retagged_enc_extensioncontainer, tagErr_enc_extensioncontainer := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_extensioncontainer)
		if tagErr_enc_extensioncontainer != nil {
			return nil, fmt.Errorf("encoding extensionContainer: %w", tagErr_enc_extensioncontainer)
		}
		enc_extensioncontainer = retagged_enc_extensioncontainer
		children = append(children, enc_extensioncontainer...)
	}
	if v.GprsNodeIndicator != nil {
		enc_gprsnodeindicator := ber.EncodeNull()
		retagged_enc_gprsnodeindicator, tagErr_enc_gprsnodeindicator := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_gprsnodeindicator)
		if tagErr_enc_gprsnodeindicator != nil {
			return nil, fmt.Errorf("encoding gprsNodeIndicator: %w", tagErr_enc_gprsnodeindicator)
		}
		enc_gprsnodeindicator = retagged_enc_gprsnodeindicator
		children = append(children, enc_gprsnodeindicator...)
	}
	if v.AdditionalNumber != nil {
		enc_additionalnumber, err := v.AdditionalNumber.MarshalBER(ber.ChildEncodeOptions(opts, "additional-Number")...)
		if err != nil {
			return nil, fmt.Errorf("encoding additional-Number: %w", err)
		}
		{
			var encodeErr error
			enc_additionalnumber, encodeErr = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 3, enc_additionalnumber)
			if encodeErr != nil {
				return nil, fmt.Errorf("encoding additional-Number: %w", encodeErr)
			}
		}
		children = append(children, enc_additionalnumber...)
	}
	if v.SupportedLCSCapabilitySets != nil {
		if (*v.SupportedLCSCapabilitySets).BitLength < 2 || (*v.SupportedLCSCapabilitySets).BitLength > 16 {
			if constraintErr := ber.CheckEncodedLength(opts, "supportedLCS-CapabilitySets", "SIZE (2..16)", (*v.SupportedLCSCapabilitySets).BitLength); constraintErr != nil {
				return nil, constraintErr
			}
		}
		if bitStringErr := ber.ValidateBitStringLength(v.SupportedLCSCapabilitySets.Bytes, v.SupportedLCSCapabilitySets.BitLength); bitStringErr != nil {
			return nil, fmt.Errorf("encoding %s: %w", "supportedLCS-CapabilitySets", bitStringErr)
		}
		// arithmetic pattern BER_BITSTRING_FIELD: 0 <= bit length before modulo and subtraction; gen/codegen.go:526
		if v.SupportedLCSCapabilitySets.BitLength < 0 {
			return nil, fmt.Errorf("negative bit string length")
		}
		enc_supportedlcscapabilitysets, encodeErr_enc_supportedlcscapabilitysets := ber.EncodeBitString(v.SupportedLCSCapabilitySets.Bytes, (8-(v.SupportedLCSCapabilitySets.BitLength%8))%8)
		if encodeErr_enc_supportedlcscapabilitysets != nil {
			return nil, fmt.Errorf("encoding supportedLCS-CapabilitySets: %w", encodeErr_enc_supportedlcscapabilitysets)
		}
		retagged_enc_supportedlcscapabilitysets, tagErr_enc_supportedlcscapabilitysets := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, enc_supportedlcscapabilitysets)
		if tagErr_enc_supportedlcscapabilitysets != nil {
			return nil, fmt.Errorf("encoding supportedLCS-CapabilitySets: %w", tagErr_enc_supportedlcscapabilitysets)
		}
		enc_supportedlcscapabilitysets = retagged_enc_supportedlcscapabilitysets
		children = append(children, enc_supportedlcscapabilitysets...)
	}
	if v.AdditionalLCSCapabilitySets != nil {
		if (*v.AdditionalLCSCapabilitySets).BitLength < 2 || (*v.AdditionalLCSCapabilitySets).BitLength > 16 {
			if constraintErr := ber.CheckEncodedLength(opts, "additional-LCS-CapabilitySets", "SIZE (2..16)", (*v.AdditionalLCSCapabilitySets).BitLength); constraintErr != nil {
				return nil, constraintErr
			}
		}
		if bitStringErr := ber.ValidateBitStringLength(v.AdditionalLCSCapabilitySets.Bytes, v.AdditionalLCSCapabilitySets.BitLength); bitStringErr != nil {
			return nil, fmt.Errorf("encoding %s: %w", "additional-LCS-CapabilitySets", bitStringErr)
		}
		// arithmetic pattern BER_BITSTRING_FIELD: 0 <= bit length before modulo and subtraction; gen/codegen.go:526
		if v.AdditionalLCSCapabilitySets.BitLength < 0 {
			return nil, fmt.Errorf("negative bit string length")
		}
		enc_additionallcscapabilitysets, encodeErr_enc_additionallcscapabilitysets := ber.EncodeBitString(v.AdditionalLCSCapabilitySets.Bytes, (8-(v.AdditionalLCSCapabilitySets.BitLength%8))%8)
		if encodeErr_enc_additionallcscapabilitysets != nil {
			return nil, fmt.Errorf("encoding additional-LCS-CapabilitySets: %w", encodeErr_enc_additionallcscapabilitysets)
		}
		retagged_enc_additionallcscapabilitysets, tagErr_enc_additionallcscapabilitysets := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 5, enc_additionallcscapabilitysets)
		if tagErr_enc_additionallcscapabilitysets != nil {
			return nil, fmt.Errorf("encoding additional-LCS-CapabilitySets: %w", tagErr_enc_additionallcscapabilitysets)
		}
		enc_additionallcscapabilitysets = retagged_enc_additionallcscapabilitysets
		children = append(children, enc_additionallcscapabilitysets...)
	}
	if v.MmeName != nil {
		if len(*v.MmeName) < 9 || len(*v.MmeName) > 255 {
			if constraintErr := ber.CheckEncodedLength(opts, "mme-Name", "SIZE (9..255)", len(*v.MmeName)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_mmename, encodeErr_enc_mmename := ber.EncodeOctetString([]byte(*v.MmeName))
		if encodeErr_enc_mmename != nil {
			return nil, fmt.Errorf("encoding mme-Name: %w", encodeErr_enc_mmename)
		}
		retagged_enc_mmename, tagErr_enc_mmename := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 6, enc_mmename)
		if tagErr_enc_mmename != nil {
			return nil, fmt.Errorf("encoding mme-Name: %w", tagErr_enc_mmename)
		}
		enc_mmename = retagged_enc_mmename
		children = append(children, enc_mmename...)
	}
	if v.AaaServerName != nil {
		if len(*v.AaaServerName) < 9 || len(*v.AaaServerName) > 255 {
			if constraintErr := ber.CheckEncodedLength(opts, "aaa-Server-Name", "SIZE (9..255)", len(*v.AaaServerName)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_aaaservername, encodeErr_enc_aaaservername := ber.EncodeOctetString([]byte(*v.AaaServerName))
		if encodeErr_enc_aaaservername != nil {
			return nil, fmt.Errorf("encoding aaa-Server-Name: %w", encodeErr_enc_aaaservername)
		}
		retagged_enc_aaaservername, tagErr_enc_aaaservername := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 8, enc_aaaservername)
		if tagErr_enc_aaaservername != nil {
			return nil, fmt.Errorf("encoding aaa-Server-Name: %w", tagErr_enc_aaaservername)
		}
		enc_aaaservername = retagged_enc_aaaservername
		children = append(children, enc_aaaservername...)
	}
	if v.SgsnName != nil {
		if len(*v.SgsnName) < 9 || len(*v.SgsnName) > 255 {
			if constraintErr := ber.CheckEncodedLength(opts, "sgsn-Name", "SIZE (9..255)", len(*v.SgsnName)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_sgsnname, encodeErr_enc_sgsnname := ber.EncodeOctetString([]byte(*v.SgsnName))
		if encodeErr_enc_sgsnname != nil {
			return nil, fmt.Errorf("encoding sgsn-Name: %w", encodeErr_enc_sgsnname)
		}
		retagged_enc_sgsnname, tagErr_enc_sgsnname := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 9, enc_sgsnname)
		if tagErr_enc_sgsnname != nil {
			return nil, fmt.Errorf("encoding sgsn-Name: %w", tagErr_enc_sgsnname)
		}
		enc_sgsnname = retagged_enc_sgsnname
		children = append(children, enc_sgsnname...)
	}
	if v.SgsnRealm != nil {
		if len(*v.SgsnRealm) < 9 || len(*v.SgsnRealm) > 255 {
			if constraintErr := ber.CheckEncodedLength(opts, "sgsn-Realm", "SIZE (9..255)", len(*v.SgsnRealm)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_sgsnrealm, encodeErr_enc_sgsnrealm := ber.EncodeOctetString([]byte(*v.SgsnRealm))
		if encodeErr_enc_sgsnrealm != nil {
			return nil, fmt.Errorf("encoding sgsn-Realm: %w", encodeErr_enc_sgsnrealm)
		}
		retagged_enc_sgsnrealm, tagErr_enc_sgsnrealm := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 10, enc_sgsnrealm)
		if tagErr_enc_sgsnrealm != nil {
			return nil, fmt.Errorf("encoding sgsn-Realm: %w", tagErr_enc_sgsnrealm)
		}
		enc_sgsnrealm = retagged_enc_sgsnrealm
		children = append(children, enc_sgsnrealm...)
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

// MarshalDER encodes LCSLCSLocationInfo to DER format.
func (v *LCSLCSLocationInfo) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: LCSLCSLocationInfo receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if len(v.NetworkNodeNumber) < 1 || len(v.NetworkNodeNumber) > 9 {
		if constraintErr := ber.CheckEncodedLength(nil, "networkNode-Number", "SIZE (1..9)", len(v.NetworkNodeNumber)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	if len(v.NetworkNodeNumber) < 1 || len(v.NetworkNodeNumber) > 20 {
		if constraintErr := ber.CheckEncodedLength(nil, "networkNode-Number", "SIZE (1..20)", len(v.NetworkNodeNumber)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_networknodenumber, encodeErr_enc_networknodenumber := ber.EncodeOctetString([]byte(v.NetworkNodeNumber))
	if encodeErr_enc_networknodenumber != nil {
		return nil, fmt.Errorf("encoding networkNode-Number: %w", encodeErr_enc_networknodenumber)
	}
	children = append(children, enc_networknodenumber...)
	if v.Lmsi != nil {
		if len(*v.Lmsi) < 4 || len(*v.Lmsi) > 4 {
			if constraintErr := ber.CheckEncodedLength(nil, "lmsi", "SIZE (4)", len(*v.Lmsi)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_lmsi, encodeErr_enc_lmsi := ber.EncodeOctetString([]byte(*v.Lmsi))
		if encodeErr_enc_lmsi != nil {
			return nil, fmt.Errorf("encoding lmsi: %w", encodeErr_enc_lmsi)
		}
		retagged_enc_lmsi, tagErr_enc_lmsi := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_lmsi)
		if tagErr_enc_lmsi != nil {
			return nil, fmt.Errorf("encoding lmsi: %w", tagErr_enc_lmsi)
		}
		enc_lmsi = retagged_enc_lmsi
		children = append(children, enc_lmsi...)
	}
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding extensionContainer: %w", err)
		}
		retagged_enc_extensioncontainer, tagErr_enc_extensioncontainer := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_extensioncontainer)
		if tagErr_enc_extensioncontainer != nil {
			return nil, fmt.Errorf("encoding extensionContainer: %w", tagErr_enc_extensioncontainer)
		}
		enc_extensioncontainer = retagged_enc_extensioncontainer
		children = append(children, enc_extensioncontainer...)
	}
	if v.GprsNodeIndicator != nil {
		enc_gprsnodeindicator := ber.EncodeNull()
		retagged_enc_gprsnodeindicator, tagErr_enc_gprsnodeindicator := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_gprsnodeindicator)
		if tagErr_enc_gprsnodeindicator != nil {
			return nil, fmt.Errorf("encoding gprsNodeIndicator: %w", tagErr_enc_gprsnodeindicator)
		}
		enc_gprsnodeindicator = retagged_enc_gprsnodeindicator
		children = append(children, enc_gprsnodeindicator...)
	}
	if v.AdditionalNumber != nil {
		enc_additionalnumber, err := v.AdditionalNumber.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding additional-Number: %w", err)
		}
		{
			var encodeErr error
			enc_additionalnumber, encodeErr = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 3, enc_additionalnumber)
			if encodeErr != nil {
				return nil, fmt.Errorf("encoding additional-Number: %w", encodeErr)
			}
		}
		children = append(children, enc_additionalnumber...)
	}
	if v.SupportedLCSCapabilitySets != nil {
		if (*v.SupportedLCSCapabilitySets).BitLength < 2 || (*v.SupportedLCSCapabilitySets).BitLength > 16 {
			if constraintErr := ber.CheckEncodedLength(nil, "supportedLCS-CapabilitySets", "SIZE (2..16)", (*v.SupportedLCSCapabilitySets).BitLength); constraintErr != nil {
				return nil, constraintErr
			}
		}
		if bitStringErr := ber.ValidateBitStringLength(v.SupportedLCSCapabilitySets.Bytes, v.SupportedLCSCapabilitySets.BitLength); bitStringErr != nil {
			return nil, fmt.Errorf("encoding %s: %w", "supportedLCS-CapabilitySets", bitStringErr)
		}
		if bitStringErr := ber.ValidateDERBitString(v.SupportedLCSCapabilitySets.Bytes, v.SupportedLCSCapabilitySets.BitLength); bitStringErr != nil {
			return nil, fmt.Errorf("encoding %s: %w", "supportedLCS-CapabilitySets", bitStringErr)
		}
		// arithmetic pattern BER_BITSTRING_FIELD: 0 <= bit length before modulo and subtraction; gen/codegen.go:526
		if v.SupportedLCSCapabilitySets.BitLength < 0 {
			return nil, fmt.Errorf("negative bit string length")
		}
		enc_supportedlcscapabilitysets, encodeErr_enc_supportedlcscapabilitysets := ber.EncodeDERNamedBitString(v.SupportedLCSCapabilitySets.Bytes, v.SupportedLCSCapabilitySets.BitLength)
		if encodeErr_enc_supportedlcscapabilitysets != nil {
			return nil, fmt.Errorf("encoding supportedLCS-CapabilitySets: %w", encodeErr_enc_supportedlcscapabilitysets)
		}
		retagged_enc_supportedlcscapabilitysets, tagErr_enc_supportedlcscapabilitysets := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, enc_supportedlcscapabilitysets)
		if tagErr_enc_supportedlcscapabilitysets != nil {
			return nil, fmt.Errorf("encoding supportedLCS-CapabilitySets: %w", tagErr_enc_supportedlcscapabilitysets)
		}
		enc_supportedlcscapabilitysets = retagged_enc_supportedlcscapabilitysets
		children = append(children, enc_supportedlcscapabilitysets...)
	}
	if v.AdditionalLCSCapabilitySets != nil {
		if (*v.AdditionalLCSCapabilitySets).BitLength < 2 || (*v.AdditionalLCSCapabilitySets).BitLength > 16 {
			if constraintErr := ber.CheckEncodedLength(nil, "additional-LCS-CapabilitySets", "SIZE (2..16)", (*v.AdditionalLCSCapabilitySets).BitLength); constraintErr != nil {
				return nil, constraintErr
			}
		}
		if bitStringErr := ber.ValidateBitStringLength(v.AdditionalLCSCapabilitySets.Bytes, v.AdditionalLCSCapabilitySets.BitLength); bitStringErr != nil {
			return nil, fmt.Errorf("encoding %s: %w", "additional-LCS-CapabilitySets", bitStringErr)
		}
		if bitStringErr := ber.ValidateDERBitString(v.AdditionalLCSCapabilitySets.Bytes, v.AdditionalLCSCapabilitySets.BitLength); bitStringErr != nil {
			return nil, fmt.Errorf("encoding %s: %w", "additional-LCS-CapabilitySets", bitStringErr)
		}
		// arithmetic pattern BER_BITSTRING_FIELD: 0 <= bit length before modulo and subtraction; gen/codegen.go:526
		if v.AdditionalLCSCapabilitySets.BitLength < 0 {
			return nil, fmt.Errorf("negative bit string length")
		}
		enc_additionallcscapabilitysets, encodeErr_enc_additionallcscapabilitysets := ber.EncodeDERNamedBitString(v.AdditionalLCSCapabilitySets.Bytes, v.AdditionalLCSCapabilitySets.BitLength)
		if encodeErr_enc_additionallcscapabilitysets != nil {
			return nil, fmt.Errorf("encoding additional-LCS-CapabilitySets: %w", encodeErr_enc_additionallcscapabilitysets)
		}
		retagged_enc_additionallcscapabilitysets, tagErr_enc_additionallcscapabilitysets := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 5, enc_additionallcscapabilitysets)
		if tagErr_enc_additionallcscapabilitysets != nil {
			return nil, fmt.Errorf("encoding additional-LCS-CapabilitySets: %w", tagErr_enc_additionallcscapabilitysets)
		}
		enc_additionallcscapabilitysets = retagged_enc_additionallcscapabilitysets
		children = append(children, enc_additionallcscapabilitysets...)
	}
	if v.MmeName != nil {
		if len(*v.MmeName) < 9 || len(*v.MmeName) > 255 {
			if constraintErr := ber.CheckEncodedLength(nil, "mme-Name", "SIZE (9..255)", len(*v.MmeName)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_mmename, encodeErr_enc_mmename := ber.EncodeOctetString([]byte(*v.MmeName))
		if encodeErr_enc_mmename != nil {
			return nil, fmt.Errorf("encoding mme-Name: %w", encodeErr_enc_mmename)
		}
		retagged_enc_mmename, tagErr_enc_mmename := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 6, enc_mmename)
		if tagErr_enc_mmename != nil {
			return nil, fmt.Errorf("encoding mme-Name: %w", tagErr_enc_mmename)
		}
		enc_mmename = retagged_enc_mmename
		children = append(children, enc_mmename...)
	}
	if v.AaaServerName != nil {
		if len(*v.AaaServerName) < 9 || len(*v.AaaServerName) > 255 {
			if constraintErr := ber.CheckEncodedLength(nil, "aaa-Server-Name", "SIZE (9..255)", len(*v.AaaServerName)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_aaaservername, encodeErr_enc_aaaservername := ber.EncodeOctetString([]byte(*v.AaaServerName))
		if encodeErr_enc_aaaservername != nil {
			return nil, fmt.Errorf("encoding aaa-Server-Name: %w", encodeErr_enc_aaaservername)
		}
		retagged_enc_aaaservername, tagErr_enc_aaaservername := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 8, enc_aaaservername)
		if tagErr_enc_aaaservername != nil {
			return nil, fmt.Errorf("encoding aaa-Server-Name: %w", tagErr_enc_aaaservername)
		}
		enc_aaaservername = retagged_enc_aaaservername
		children = append(children, enc_aaaservername...)
	}
	if v.SgsnName != nil {
		if len(*v.SgsnName) < 9 || len(*v.SgsnName) > 255 {
			if constraintErr := ber.CheckEncodedLength(nil, "sgsn-Name", "SIZE (9..255)", len(*v.SgsnName)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_sgsnname, encodeErr_enc_sgsnname := ber.EncodeOctetString([]byte(*v.SgsnName))
		if encodeErr_enc_sgsnname != nil {
			return nil, fmt.Errorf("encoding sgsn-Name: %w", encodeErr_enc_sgsnname)
		}
		retagged_enc_sgsnname, tagErr_enc_sgsnname := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 9, enc_sgsnname)
		if tagErr_enc_sgsnname != nil {
			return nil, fmt.Errorf("encoding sgsn-Name: %w", tagErr_enc_sgsnname)
		}
		enc_sgsnname = retagged_enc_sgsnname
		children = append(children, enc_sgsnname...)
	}
	if v.SgsnRealm != nil {
		if len(*v.SgsnRealm) < 9 || len(*v.SgsnRealm) > 255 {
			if constraintErr := ber.CheckEncodedLength(nil, "sgsn-Realm", "SIZE (9..255)", len(*v.SgsnRealm)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_sgsnrealm, encodeErr_enc_sgsnrealm := ber.EncodeOctetString([]byte(*v.SgsnRealm))
		if encodeErr_enc_sgsnrealm != nil {
			return nil, fmt.Errorf("encoding sgsn-Realm: %w", encodeErr_enc_sgsnrealm)
		}
		retagged_enc_sgsnrealm, tagErr_enc_sgsnrealm := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 10, enc_sgsnrealm)
		if tagErr_enc_sgsnrealm != nil {
			return nil, fmt.Errorf("encoding sgsn-Realm: %w", tagErr_enc_sgsnrealm)
		}
		enc_sgsnrealm = retagged_enc_sgsnrealm
		children = append(children, enc_sgsnrealm...)
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
		return nil, fmt.Errorf("encoding LCSLCSLocationInfo as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes LCSLCSLocationInfo from BER/DER format.
func (v *LCSLCSLocationInfo) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: LCSLCSLocationInfo destination is nil", ber.ErrInvalidValue)
	}
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = LCSLCSLocationInfo{}
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
		return fmt.Errorf("decoding LCSLCSLocationInfo SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "LCSLCSLocationInfo", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode networkNode-Number
	if offset >= len(content) {
		return fmt.Errorf("missing required field networkNode-Number")
	}
	val_networknodenumber, n, err := ber.DecodeOctetString(content[offset:], opts...)
	if err != nil {
		return fmt.Errorf("decoding networkNode-Number: %w", err)
	}
	v.NetworkNodeNumber = ISDNAddressString3(val_networknodenumber)
	if offset < 0 || offset >
		len(content) || n < 0 || n > len(content[offset:]) {
		return fmt.Errorf("invalid BER content window")
	}

	offset += n
	if len(v.NetworkNodeNumber) < 1 || len(v.NetworkNodeNumber) > 9 {
		if constraintErr := ber.CheckDecodedLength(opts, "networkNode-Number", "SIZE (1..9)", len(v.NetworkNodeNumber)); constraintErr != nil {
			return constraintErr
		}
	}
	if len(v.NetworkNodeNumber) < 1 || len(v.NetworkNodeNumber) > 20 {
		if constraintErr := ber.CheckDecodedLength(opts, "networkNode-Number", "SIZE (1..20)", len(v.NetworkNodeNumber)); constraintErr != nil {
			return constraintErr
		}
	}
	// Decode lmsi
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
				decodedTag_lmsi, n_lmsi, rawVal_lmsi, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding lmsi: %w", err)
				}
				if decodedTag_lmsi.Class != tag.ClassContextSpecific || decodedTag_lmsi.Number != 0 {
					return fmt.Errorf("decoding lmsi: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_lmsi)
				}
				decVal_lmsi, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_lmsi.Constructed, rawVal_lmsi, opts...)
				if octetErr != nil {
					return fmt.Errorf("decoding lmsi: %w", octetErr)
				}
				tmp_lmsi := LMSI3(decVal_lmsi)
				v.Lmsi = &tmp_lmsi
				if offset < 0 || offset >
					len(content) || n_lmsi < 0 || n_lmsi > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_lmsi
				if len(*v.Lmsi) < 4 || len(*v.Lmsi) > 4 {
					if constraintErr := ber.CheckDecodedLength(opts, "lmsi", "SIZE (4)", len(*v.Lmsi)); constraintErr != nil {
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
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
				decodedTag_extensioncontainer, n_extensioncontainer, rawVal_extensioncontainer, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding extensionContainer: %w", err)
				}
				if decodedTag_extensioncontainer.Class != tag.ClassContextSpecific || decodedTag_extensioncontainer.Number != 1 || decodedTag_extensioncontainer.Constructed != true {
					return fmt.Errorf("decoding extensionContainer: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_extensioncontainer)
				}
				reconstructed_extensioncontainer, reconstructionErr_extensioncontainer := ber.EncodeSequence(rawVal_extensioncontainer)
				if reconstructionErr_extensioncontainer != nil {
					return fmt.Errorf("decoding extensionContainer: %w", reconstructionErr_extensioncontainer)
				}
				var dec_extensioncontainer ExtensionContainer3
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
	// Decode gprsNodeIndicator
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2 {
				decodedTag_gprsnodeindicator, n_gprsnodeindicator, rawVal_gprsnodeindicator, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding gprsNodeIndicator: %w", err)
				}
				if decodedTag_gprsnodeindicator.Class != tag.ClassContextSpecific || decodedTag_gprsnodeindicator.Number != 2 || decodedTag_gprsnodeindicator.Constructed != false {
					return fmt.Errorf("decoding gprsNodeIndicator: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_gprsnodeindicator)
				}
				if len(rawVal_gprsnodeindicator) != 0 {
					return fmt.Errorf("decoding gprsNodeIndicator: %w: NULL content length %d", ber.ErrInvalidValue, len(rawVal_gprsnodeindicator))
				}
				v.GprsNodeIndicator = &struct{}{}
				if offset < 0 || offset >
					len(content) || n_gprsnodeindicator < 0 || n_gprsnodeindicator >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_gprsnodeindicator
			}
		}
	}
	// Decode additional-Number
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3 {
				decodedTag_additionalnumber, n_additionalnumber, innerData_additionalnumber, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding additional-Number: %w", err)
				}
				if decodedTag_additionalnumber.Class != tag.ClassContextSpecific || decodedTag_additionalnumber.Number != 3 || decodedTag_additionalnumber.Constructed != true {
					return fmt.Errorf("decoding additional-Number: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_additionalnumber)
				}
				// Decode inner value from explicit tag wrapper
				var dec_additionalnumber AdditionalNumber3
				if unmErr := dec_additionalnumber.UnmarshalBER(innerData_additionalnumber, ber.ChildDecodeOptions(opts, "additional-Number")...); unmErr != nil {
					return fmt.Errorf("decoding additional-Number: %w", unmErr)
				}
				v.AdditionalNumber = &dec_additionalnumber
				if offset < 0 || offset >
					len(content) || n_additionalnumber < 0 || n_additionalnumber >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_additionalnumber
			}
		}
	}
	// Decode supportedLCS-CapabilitySets
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4 {
				decodedTag_supportedlcscapabilitysets, n_supportedlcscapabilitysets, rawVal_supportedlcscapabilitysets, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding supportedLCS-CapabilitySets: %w", err)
				}
				if decodedTag_supportedlcscapabilitysets.Class != tag.ClassContextSpecific || decodedTag_supportedlcscapabilitysets.Number != 4 {
					return fmt.Errorf("decoding supportedLCS-CapabilitySets: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_supportedlcscapabilitysets)
				}
				bsBytes_supportedlcscapabilitysets, bsUnused_supportedlcscapabilitysets, bsErr := ber.DecodeImplicitBitStringValue(decodedTag_supportedlcscapabilitysets.Constructed, rawVal_supportedlcscapabilitysets, opts...)
				if bsErr != nil {
					return fmt.Errorf("decoding supportedLCS-CapabilitySets: %w", bsErr)
				}
				bsBitLength_supportedlcscapabilitysets, bsLenErr_supportedlcscapabilitysets := ber.BitStringBitLength(len(bsBytes_supportedlcscapabilitysets), bsUnused_supportedlcscapabilitysets)
				if bsLenErr_supportedlcscapabilitysets != nil {
					return fmt.Errorf("decoding supportedLCS-CapabilitySets: %w", bsLenErr_supportedlcscapabilitysets)
				}
				tmp_supportedlcscapabilitysets := runtime.BitString{Bytes: bsBytes_supportedlcscapabilitysets, BitLength: bsBitLength_supportedlcscapabilitysets}
				v.SupportedLCSCapabilitySets = &tmp_supportedlcscapabilitysets
				if offset < 0 || offset >
					len(content) || n_supportedlcscapabilitysets < 0 || n_supportedlcscapabilitysets >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_supportedlcscapabilitysets
				*v.SupportedLCSCapabilitySets = ber.NormalizeNamedBitStringSize(*v.SupportedLCSCapabilitySets, []ber.NamedBitSizeSet{{{Min: 2, Max: 16}}}, opts...)
				if (*v.SupportedLCSCapabilitySets).BitLength < 2 || (*v.SupportedLCSCapabilitySets).BitLength > 16 {
					if constraintErr := ber.CheckDecodedLength(opts, "supportedLCS-CapabilitySets", "SIZE (2..16)", (*v.SupportedLCSCapabilitySets).BitLength); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode additional-LCS-CapabilitySets
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 5 {
				decodedTag_additionallcscapabilitysets, n_additionallcscapabilitysets, rawVal_additionallcscapabilitysets, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding additional-LCS-CapabilitySets: %w", err)
				}
				if decodedTag_additionallcscapabilitysets.Class != tag.ClassContextSpecific || decodedTag_additionallcscapabilitysets.Number != 5 {
					return fmt.Errorf("decoding additional-LCS-CapabilitySets: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_additionallcscapabilitysets)
				}
				bsBytes_additionallcscapabilitysets, bsUnused_additionallcscapabilitysets, bsErr := ber.DecodeImplicitBitStringValue(decodedTag_additionallcscapabilitysets.Constructed, rawVal_additionallcscapabilitysets, opts...)
				if bsErr != nil {
					return fmt.Errorf("decoding additional-LCS-CapabilitySets: %w", bsErr)
				}
				bsBitLength_additionallcscapabilitysets, bsLenErr_additionallcscapabilitysets := ber.BitStringBitLength(len(bsBytes_additionallcscapabilitysets), bsUnused_additionallcscapabilitysets)
				if bsLenErr_additionallcscapabilitysets != nil {
					return fmt.Errorf("decoding additional-LCS-CapabilitySets: %w", bsLenErr_additionallcscapabilitysets)
				}
				tmp_additionallcscapabilitysets := runtime.BitString{Bytes: bsBytes_additionallcscapabilitysets, BitLength: bsBitLength_additionallcscapabilitysets}
				v.AdditionalLCSCapabilitySets = &tmp_additionallcscapabilitysets
				if offset < 0 || offset >
					len(content) || n_additionallcscapabilitysets < 0 || n_additionallcscapabilitysets >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_additionallcscapabilitysets
				*v.AdditionalLCSCapabilitySets = ber.NormalizeNamedBitStringSize(*v.AdditionalLCSCapabilitySets, []ber.NamedBitSizeSet{{{Min: 2, Max: 16}}}, opts...)
				if (*v.AdditionalLCSCapabilitySets).BitLength < 2 || (*v.AdditionalLCSCapabilitySets).BitLength > 16 {
					if constraintErr := ber.CheckDecodedLength(opts, "additional-LCS-CapabilitySets", "SIZE (2..16)", (*v.AdditionalLCSCapabilitySets).BitLength); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode mme-Name
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 6 {
				decodedTag_mmename, n_mmename, rawVal_mmename, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding mme-Name: %w", err)
				}
				if decodedTag_mmename.Class != tag.ClassContextSpecific || decodedTag_mmename.Number != 6 {
					return fmt.Errorf("decoding mme-Name: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_mmename)
				}
				decVal_mmename, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_mmename.Constructed, rawVal_mmename, opts...)
				if octetErr != nil {
					return fmt.Errorf("decoding mme-Name: %w", octetErr)
				}
				tmp_mmename := CommonDataTypesDiameterIdentity(decVal_mmename)
				v.MmeName = &tmp_mmename
				if offset < 0 || offset >
					len(content) || n_mmename < 0 || n_mmename > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_mmename
				if len(*v.MmeName) < 9 || len(*v.MmeName) > 255 {
					if constraintErr := ber.CheckDecodedLength(opts, "mme-Name", "SIZE (9..255)", len(*v.MmeName)); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode aaa-Server-Name
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 8 {
				decodedTag_aaaservername, n_aaaservername, rawVal_aaaservername, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding aaa-Server-Name: %w", err)
				}
				if decodedTag_aaaservername.Class != tag.ClassContextSpecific || decodedTag_aaaservername.Number != 8 {
					return fmt.Errorf("decoding aaa-Server-Name: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_aaaservername)
				}
				decVal_aaaservername, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_aaaservername.Constructed, rawVal_aaaservername, opts...)
				if octetErr != nil {
					return fmt.Errorf("decoding aaa-Server-Name: %w", octetErr)
				}
				tmp_aaaservername := CommonDataTypesDiameterIdentity(decVal_aaaservername)
				v.AaaServerName = &tmp_aaaservername
				if offset < 0 || offset >
					len(content) || n_aaaservername < 0 || n_aaaservername > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_aaaservername
				if len(*v.AaaServerName) < 9 || len(*v.AaaServerName) > 255 {
					if constraintErr := ber.CheckDecodedLength(opts, "aaa-Server-Name", "SIZE (9..255)", len(*v.AaaServerName)); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode sgsn-Name
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 9 {
				decodedTag_sgsnname, n_sgsnname, rawVal_sgsnname, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding sgsn-Name: %w", err)
				}
				if decodedTag_sgsnname.Class != tag.ClassContextSpecific || decodedTag_sgsnname.Number != 9 {
					return fmt.Errorf("decoding sgsn-Name: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_sgsnname)
				}
				decVal_sgsnname, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_sgsnname.Constructed, rawVal_sgsnname, opts...)
				if octetErr != nil {
					return fmt.Errorf("decoding sgsn-Name: %w", octetErr)
				}
				tmp_sgsnname := CommonDataTypesDiameterIdentity(decVal_sgsnname)
				v.SgsnName = &tmp_sgsnname
				if offset < 0 || offset >
					len(content) || n_sgsnname < 0 || n_sgsnname > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_sgsnname
				if len(*v.SgsnName) < 9 || len(*v.SgsnName) > 255 {
					if constraintErr := ber.CheckDecodedLength(opts, "sgsn-Name", "SIZE (9..255)", len(*v.SgsnName)); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode sgsn-Realm
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 10 {
				decodedTag_sgsnrealm, n_sgsnrealm, rawVal_sgsnrealm, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding sgsn-Realm: %w", err)
				}
				if decodedTag_sgsnrealm.Class != tag.ClassContextSpecific || decodedTag_sgsnrealm.Number != 10 {
					return fmt.Errorf("decoding sgsn-Realm: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_sgsnrealm)
				}
				decVal_sgsnrealm, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_sgsnrealm.Constructed, rawVal_sgsnrealm, opts...)
				if octetErr != nil {
					return fmt.Errorf("decoding sgsn-Realm: %w", octetErr)
				}
				tmp_sgsnrealm := CommonDataTypesDiameterIdentity(decVal_sgsnrealm)
				v.SgsnRealm = &tmp_sgsnrealm
				if offset < 0 || offset >
					len(content) || n_sgsnrealm < 0 || n_sgsnrealm > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_sgsnrealm
				if len(*v.SgsnRealm) < 9 || len(*v.SgsnRealm) > 255 {
					if constraintErr := ber.CheckDecodedLength(opts, "sgsn-Realm", "SIZE (9..255)", len(*v.SgsnRealm)); constraintErr != nil {
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
			return &ber.DecodeError{Offset: offset, TypeName: "LCSLCSLocationInfo", Cause: extErr_}
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

// MarshalBER encodes LCSProvideSubscriberLocationArg to BER format.
func (v *LCSProvideSubscriberLocationArg) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: LCSProvideSubscriberLocationArg receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *LCSProvideSubscriberLocationArg) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	enc_locationtype, err := v.LocationType.MarshalBER(ber.ChildEncodeOptions(opts, "locationType")...)
	if err != nil {
		return nil, fmt.Errorf("encoding locationType: %w", err)
	}
	children = append(children, enc_locationtype...)
	if len(v.MlcNumber) < 1 || len(v.MlcNumber) > 9 {
		if constraintErr := ber.CheckEncodedLength(opts, "mlc-Number", "SIZE (1..9)", len(v.MlcNumber)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	if len(v.MlcNumber) < 1 || len(v.MlcNumber) > 20 {
		if constraintErr := ber.CheckEncodedLength(opts, "mlc-Number", "SIZE (1..20)", len(v.MlcNumber)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_mlcnumber, encodeErr_enc_mlcnumber := ber.EncodeOctetString([]byte(v.MlcNumber))
	if encodeErr_enc_mlcnumber != nil {
		return nil, fmt.Errorf("encoding mlc-Number: %w", encodeErr_enc_mlcnumber)
	}
	children = append(children, enc_mlcnumber...)
	if v.LcsClientID != nil {
		enc_lcsclientid, err := v.LcsClientID.MarshalBER(ber.ChildEncodeOptions(opts, "lcs-ClientID")...)
		if err != nil {
			return nil, fmt.Errorf("encoding lcs-ClientID: %w", err)
		}
		retagged_enc_lcsclientid, tagErr_enc_lcsclientid := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_lcsclientid)
		if tagErr_enc_lcsclientid != nil {
			return nil, fmt.Errorf("encoding lcs-ClientID: %w", tagErr_enc_lcsclientid)
		}
		enc_lcsclientid = retagged_enc_lcsclientid
		children = append(children, enc_lcsclientid...)
	}
	if v.PrivacyOverride != nil {
		enc_privacyoverride := ber.EncodeNull()
		retagged_enc_privacyoverride, tagErr_enc_privacyoverride := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_privacyoverride)
		if tagErr_enc_privacyoverride != nil {
			return nil, fmt.Errorf("encoding privacyOverride: %w", tagErr_enc_privacyoverride)
		}
		enc_privacyoverride = retagged_enc_privacyoverride
		children = append(children, enc_privacyoverride...)
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
		retagged_enc_imsi, tagErr_enc_imsi := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_imsi)
		if tagErr_enc_imsi != nil {
			return nil, fmt.Errorf("encoding imsi: %w", tagErr_enc_imsi)
		}
		enc_imsi = retagged_enc_imsi
		children = append(children, enc_imsi...)
	}
	if v.Msisdn != nil {
		if len(*v.Msisdn) < 1 || len(*v.Msisdn) > 9 {
			if constraintErr := ber.CheckEncodedLength(opts, "msisdn", "SIZE (1..9)", len(*v.Msisdn)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		if len(*v.Msisdn) < 1 || len(*v.Msisdn) > 20 {
			if constraintErr := ber.CheckEncodedLength(opts, "msisdn", "SIZE (1..20)", len(*v.Msisdn)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_msisdn, encodeErr_enc_msisdn := ber.EncodeOctetString([]byte(*v.Msisdn))
		if encodeErr_enc_msisdn != nil {
			return nil, fmt.Errorf("encoding msisdn: %w", encodeErr_enc_msisdn)
		}
		retagged_enc_msisdn, tagErr_enc_msisdn := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, enc_msisdn)
		if tagErr_enc_msisdn != nil {
			return nil, fmt.Errorf("encoding msisdn: %w", tagErr_enc_msisdn)
		}
		enc_msisdn = retagged_enc_msisdn
		children = append(children, enc_msisdn...)
	}
	if v.Lmsi != nil {
		if len(*v.Lmsi) < 4 || len(*v.Lmsi) > 4 {
			if constraintErr := ber.CheckEncodedLength(opts, "lmsi", "SIZE (4)", len(*v.Lmsi)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_lmsi, encodeErr_enc_lmsi := ber.EncodeOctetString([]byte(*v.Lmsi))
		if encodeErr_enc_lmsi != nil {
			return nil, fmt.Errorf("encoding lmsi: %w", encodeErr_enc_lmsi)
		}
		retagged_enc_lmsi, tagErr_enc_lmsi := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, enc_lmsi)
		if tagErr_enc_lmsi != nil {
			return nil, fmt.Errorf("encoding lmsi: %w", tagErr_enc_lmsi)
		}
		enc_lmsi = retagged_enc_lmsi
		children = append(children, enc_lmsi...)
	}
	if v.Imei != nil {
		if len(*v.Imei) < 8 || len(*v.Imei) > 8 {
			if constraintErr := ber.CheckEncodedLength(opts, "imei", "SIZE (8)", len(*v.Imei)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_imei, encodeErr_enc_imei := ber.EncodeOctetString([]byte(*v.Imei))
		if encodeErr_enc_imei != nil {
			return nil, fmt.Errorf("encoding imei: %w", encodeErr_enc_imei)
		}
		retagged_enc_imei, tagErr_enc_imei := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 5, enc_imei)
		if tagErr_enc_imei != nil {
			return nil, fmt.Errorf("encoding imei: %w", tagErr_enc_imei)
		}
		enc_imei = retagged_enc_imei
		children = append(children, enc_imei...)
	}
	if v.LcsPriority != nil {
		if len(*v.LcsPriority) < 1 || len(*v.LcsPriority) > 1 {
			if constraintErr := ber.CheckEncodedLength(opts, "lcs-Priority", "SIZE (1)", len(*v.LcsPriority)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_lcspriority, encodeErr_enc_lcspriority := ber.EncodeOctetString([]byte(*v.LcsPriority))
		if encodeErr_enc_lcspriority != nil {
			return nil, fmt.Errorf("encoding lcs-Priority: %w", encodeErr_enc_lcspriority)
		}
		retagged_enc_lcspriority, tagErr_enc_lcspriority := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 6, enc_lcspriority)
		if tagErr_enc_lcspriority != nil {
			return nil, fmt.Errorf("encoding lcs-Priority: %w", tagErr_enc_lcspriority)
		}
		enc_lcspriority = retagged_enc_lcspriority
		children = append(children, enc_lcspriority...)
	}
	if v.LcsQoS != nil {
		enc_lcsqos, err := v.LcsQoS.MarshalBER(ber.ChildEncodeOptions(opts, "lcs-QoS")...)
		if err != nil {
			return nil, fmt.Errorf("encoding lcs-QoS: %w", err)
		}
		retagged_enc_lcsqos, tagErr_enc_lcsqos := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 7, enc_lcsqos)
		if tagErr_enc_lcsqos != nil {
			return nil, fmt.Errorf("encoding lcs-QoS: %w", tagErr_enc_lcsqos)
		}
		enc_lcsqos = retagged_enc_lcsqos
		children = append(children, enc_lcsqos...)
	}
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalBER(ber.ChildEncodeOptions(opts, "extensionContainer")...)
		if err != nil {
			return nil, fmt.Errorf("encoding extensionContainer: %w", err)
		}
		retagged_enc_extensioncontainer, tagErr_enc_extensioncontainer := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 8, enc_extensioncontainer)
		if tagErr_enc_extensioncontainer != nil {
			return nil, fmt.Errorf("encoding extensionContainer: %w", tagErr_enc_extensioncontainer)
		}
		enc_extensioncontainer = retagged_enc_extensioncontainer
		children = append(children, enc_extensioncontainer...)
	}
	if v.SupportedGADShapes != nil {
		if (*v.SupportedGADShapes).BitLength < 7 || (*v.SupportedGADShapes).BitLength > 16 {
			if constraintErr := ber.CheckEncodedLength(opts, "supportedGADShapes", "SIZE (7..16)", (*v.SupportedGADShapes).BitLength); constraintErr != nil {
				return nil, constraintErr
			}
		}
		if bitStringErr := ber.ValidateBitStringLength(v.SupportedGADShapes.Bytes, v.SupportedGADShapes.BitLength); bitStringErr != nil {
			return nil, fmt.Errorf("encoding %s: %w", "supportedGADShapes", bitStringErr)
		}
		// arithmetic pattern BER_BITSTRING_FIELD: 0 <= bit length before modulo and subtraction; gen/codegen.go:526
		if v.SupportedGADShapes.BitLength < 0 {
			return nil, fmt.Errorf("negative bit string length")
		}
		enc_supportedgadshapes, encodeErr_enc_supportedgadshapes := ber.EncodeBitString(v.SupportedGADShapes.Bytes, (8-(v.SupportedGADShapes.BitLength%8))%8)
		if encodeErr_enc_supportedgadshapes != nil {
			return nil, fmt.Errorf("encoding supportedGADShapes: %w", encodeErr_enc_supportedgadshapes)
		}
		retagged_enc_supportedgadshapes, tagErr_enc_supportedgadshapes := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 9, enc_supportedgadshapes)
		if tagErr_enc_supportedgadshapes != nil {
			return nil, fmt.Errorf("encoding supportedGADShapes: %w", tagErr_enc_supportedgadshapes)
		}
		enc_supportedgadshapes = retagged_enc_supportedgadshapes
		children = append(children, enc_supportedgadshapes...)
	}
	if v.LcsReferenceNumber != nil {
		if len(*v.LcsReferenceNumber) < 1 || len(*v.LcsReferenceNumber) > 1 {
			if constraintErr := ber.CheckEncodedLength(opts, "lcs-ReferenceNumber", "SIZE (1)", len(*v.LcsReferenceNumber)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_lcsreferencenumber, encodeErr_enc_lcsreferencenumber := ber.EncodeOctetString([]byte(*v.LcsReferenceNumber))
		if encodeErr_enc_lcsreferencenumber != nil {
			return nil, fmt.Errorf("encoding lcs-ReferenceNumber: %w", encodeErr_enc_lcsreferencenumber)
		}
		retagged_enc_lcsreferencenumber, tagErr_enc_lcsreferencenumber := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 10, enc_lcsreferencenumber)
		if tagErr_enc_lcsreferencenumber != nil {
			return nil, fmt.Errorf("encoding lcs-ReferenceNumber: %w", tagErr_enc_lcsreferencenumber)
		}
		enc_lcsreferencenumber = retagged_enc_lcsreferencenumber
		children = append(children, enc_lcsreferencenumber...)
	}
	if v.LcsServiceTypeID != nil {
		if !(int64(*v.LcsServiceTypeID) >= 0 && int64(*v.LcsServiceTypeID) <= 127) {
			if constraintErr := ber.CheckEncodedValue(opts, "lcsServiceTypeID", "(0..127)", fmt.Sprint(int64(*v.LcsServiceTypeID))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_lcsservicetypeid := ber.EncodeInteger(int64(*v.LcsServiceTypeID))
		retagged_enc_lcsservicetypeid, tagErr_enc_lcsservicetypeid := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 11, enc_lcsservicetypeid)
		if tagErr_enc_lcsservicetypeid != nil {
			return nil, fmt.Errorf("encoding lcsServiceTypeID: %w", tagErr_enc_lcsservicetypeid)
		}
		enc_lcsservicetypeid = retagged_enc_lcsservicetypeid
		children = append(children, enc_lcsservicetypeid...)
	}
	if v.LcsCodeword != nil {
		enc_lcscodeword, err := v.LcsCodeword.MarshalBER(ber.ChildEncodeOptions(opts, "lcsCodeword")...)
		if err != nil {
			return nil, fmt.Errorf("encoding lcsCodeword: %w", err)
		}
		retagged_enc_lcscodeword, tagErr_enc_lcscodeword := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 12, enc_lcscodeword)
		if tagErr_enc_lcscodeword != nil {
			return nil, fmt.Errorf("encoding lcsCodeword: %w", tagErr_enc_lcscodeword)
		}
		enc_lcscodeword = retagged_enc_lcscodeword
		children = append(children, enc_lcscodeword...)
	}
	if v.LcsPrivacyCheck != nil {
		enc_lcsprivacycheck, err := v.LcsPrivacyCheck.MarshalBER(ber.ChildEncodeOptions(opts, "lcs-PrivacyCheck")...)
		if err != nil {
			return nil, fmt.Errorf("encoding lcs-PrivacyCheck: %w", err)
		}
		retagged_enc_lcsprivacycheck, tagErr_enc_lcsprivacycheck := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 13, enc_lcsprivacycheck)
		if tagErr_enc_lcsprivacycheck != nil {
			return nil, fmt.Errorf("encoding lcs-PrivacyCheck: %w", tagErr_enc_lcsprivacycheck)
		}
		enc_lcsprivacycheck = retagged_enc_lcsprivacycheck
		children = append(children, enc_lcsprivacycheck...)
	}
	if v.AreaEventInfo != nil {
		enc_areaeventinfo, err := v.AreaEventInfo.MarshalBER(ber.ChildEncodeOptions(opts, "areaEventInfo")...)
		if err != nil {
			return nil, fmt.Errorf("encoding areaEventInfo: %w", err)
		}
		retagged_enc_areaeventinfo, tagErr_enc_areaeventinfo := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 14, enc_areaeventinfo)
		if tagErr_enc_areaeventinfo != nil {
			return nil, fmt.Errorf("encoding areaEventInfo: %w", tagErr_enc_areaeventinfo)
		}
		enc_areaeventinfo = retagged_enc_areaeventinfo
		children = append(children, enc_areaeventinfo...)
	}
	if v.HGmlcAddress != nil {
		if len(*v.HGmlcAddress) < 5 || len(*v.HGmlcAddress) > 17 {
			if constraintErr := ber.CheckEncodedLength(opts, "h-gmlc-Address", "SIZE (5..17)", len(*v.HGmlcAddress)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_hgmlcaddress, encodeErr_enc_hgmlcaddress := ber.EncodeOctetString([]byte(*v.HGmlcAddress))
		if encodeErr_enc_hgmlcaddress != nil {
			return nil, fmt.Errorf("encoding h-gmlc-Address: %w", encodeErr_enc_hgmlcaddress)
		}
		retagged_enc_hgmlcaddress, tagErr_enc_hgmlcaddress := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 15, enc_hgmlcaddress)
		if tagErr_enc_hgmlcaddress != nil {
			return nil, fmt.Errorf("encoding h-gmlc-Address: %w", tagErr_enc_hgmlcaddress)
		}
		enc_hgmlcaddress = retagged_enc_hgmlcaddress
		children = append(children, enc_hgmlcaddress...)
	}
	if v.MoLrShortCircuitIndicator != nil {
		enc_molrshortcircuitindicator := ber.EncodeNull()
		retagged_enc_molrshortcircuitindicator, tagErr_enc_molrshortcircuitindicator := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 16, enc_molrshortcircuitindicator)
		if tagErr_enc_molrshortcircuitindicator != nil {
			return nil, fmt.Errorf("encoding mo-lrShortCircuitIndicator: %w", tagErr_enc_molrshortcircuitindicator)
		}
		enc_molrshortcircuitindicator = retagged_enc_molrshortcircuitindicator
		children = append(children, enc_molrshortcircuitindicator...)
	}
	if v.PeriodicLDRInfo != nil {
		enc_periodicldrinfo, err := v.PeriodicLDRInfo.MarshalBER(ber.ChildEncodeOptions(opts, "periodicLDRInfo")...)
		if err != nil {
			return nil, fmt.Errorf("encoding periodicLDRInfo: %w", err)
		}
		retagged_enc_periodicldrinfo, tagErr_enc_periodicldrinfo := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 17, enc_periodicldrinfo)
		if tagErr_enc_periodicldrinfo != nil {
			return nil, fmt.Errorf("encoding periodicLDRInfo: %w", tagErr_enc_periodicldrinfo)
		}
		enc_periodicldrinfo = retagged_enc_periodicldrinfo
		children = append(children, enc_periodicldrinfo...)
	}
	if v.ReportingPLMNList != nil {
		enc_reportingplmnlist, err := v.ReportingPLMNList.MarshalBER(ber.ChildEncodeOptions(opts, "reportingPLMNList")...)
		if err != nil {
			return nil, fmt.Errorf("encoding reportingPLMNList: %w", err)
		}
		retagged_enc_reportingplmnlist, tagErr_enc_reportingplmnlist := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 18, enc_reportingplmnlist)
		if tagErr_enc_reportingplmnlist != nil {
			return nil, fmt.Errorf("encoding reportingPLMNList: %w", tagErr_enc_reportingplmnlist)
		}
		enc_reportingplmnlist = retagged_enc_reportingplmnlist
		children = append(children, enc_reportingplmnlist...)
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

// MarshalDER encodes LCSProvideSubscriberLocationArg to DER format.
func (v *LCSProvideSubscriberLocationArg) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: LCSProvideSubscriberLocationArg receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	enc_locationtype, err := v.LocationType.MarshalDER()
	if err != nil {
		return nil, fmt.Errorf("encoding locationType: %w", err)
	}
	children = append(children, enc_locationtype...)
	if len(v.MlcNumber) < 1 || len(v.MlcNumber) > 9 {
		if constraintErr := ber.CheckEncodedLength(nil, "mlc-Number", "SIZE (1..9)", len(v.MlcNumber)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	if len(v.MlcNumber) < 1 || len(v.MlcNumber) > 20 {
		if constraintErr := ber.CheckEncodedLength(nil, "mlc-Number", "SIZE (1..20)", len(v.MlcNumber)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_mlcnumber, encodeErr_enc_mlcnumber := ber.EncodeOctetString([]byte(v.MlcNumber))
	if encodeErr_enc_mlcnumber != nil {
		return nil, fmt.Errorf("encoding mlc-Number: %w", encodeErr_enc_mlcnumber)
	}
	children = append(children, enc_mlcnumber...)
	if v.LcsClientID != nil {
		enc_lcsclientid, err := v.LcsClientID.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding lcs-ClientID: %w", err)
		}
		retagged_enc_lcsclientid, tagErr_enc_lcsclientid := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_lcsclientid)
		if tagErr_enc_lcsclientid != nil {
			return nil, fmt.Errorf("encoding lcs-ClientID: %w", tagErr_enc_lcsclientid)
		}
		enc_lcsclientid = retagged_enc_lcsclientid
		children = append(children, enc_lcsclientid...)
	}
	if v.PrivacyOverride != nil {
		enc_privacyoverride := ber.EncodeNull()
		retagged_enc_privacyoverride, tagErr_enc_privacyoverride := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_privacyoverride)
		if tagErr_enc_privacyoverride != nil {
			return nil, fmt.Errorf("encoding privacyOverride: %w", tagErr_enc_privacyoverride)
		}
		enc_privacyoverride = retagged_enc_privacyoverride
		children = append(children, enc_privacyoverride...)
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
		retagged_enc_imsi, tagErr_enc_imsi := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_imsi)
		if tagErr_enc_imsi != nil {
			return nil, fmt.Errorf("encoding imsi: %w", tagErr_enc_imsi)
		}
		enc_imsi = retagged_enc_imsi
		children = append(children, enc_imsi...)
	}
	if v.Msisdn != nil {
		if len(*v.Msisdn) < 1 || len(*v.Msisdn) > 9 {
			if constraintErr := ber.CheckEncodedLength(nil, "msisdn", "SIZE (1..9)", len(*v.Msisdn)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		if len(*v.Msisdn) < 1 || len(*v.Msisdn) > 20 {
			if constraintErr := ber.CheckEncodedLength(nil, "msisdn", "SIZE (1..20)", len(*v.Msisdn)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_msisdn, encodeErr_enc_msisdn := ber.EncodeOctetString([]byte(*v.Msisdn))
		if encodeErr_enc_msisdn != nil {
			return nil, fmt.Errorf("encoding msisdn: %w", encodeErr_enc_msisdn)
		}
		retagged_enc_msisdn, tagErr_enc_msisdn := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, enc_msisdn)
		if tagErr_enc_msisdn != nil {
			return nil, fmt.Errorf("encoding msisdn: %w", tagErr_enc_msisdn)
		}
		enc_msisdn = retagged_enc_msisdn
		children = append(children, enc_msisdn...)
	}
	if v.Lmsi != nil {
		if len(*v.Lmsi) < 4 || len(*v.Lmsi) > 4 {
			if constraintErr := ber.CheckEncodedLength(nil, "lmsi", "SIZE (4)", len(*v.Lmsi)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_lmsi, encodeErr_enc_lmsi := ber.EncodeOctetString([]byte(*v.Lmsi))
		if encodeErr_enc_lmsi != nil {
			return nil, fmt.Errorf("encoding lmsi: %w", encodeErr_enc_lmsi)
		}
		retagged_enc_lmsi, tagErr_enc_lmsi := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, enc_lmsi)
		if tagErr_enc_lmsi != nil {
			return nil, fmt.Errorf("encoding lmsi: %w", tagErr_enc_lmsi)
		}
		enc_lmsi = retagged_enc_lmsi
		children = append(children, enc_lmsi...)
	}
	if v.Imei != nil {
		if len(*v.Imei) < 8 || len(*v.Imei) > 8 {
			if constraintErr := ber.CheckEncodedLength(nil, "imei", "SIZE (8)", len(*v.Imei)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_imei, encodeErr_enc_imei := ber.EncodeOctetString([]byte(*v.Imei))
		if encodeErr_enc_imei != nil {
			return nil, fmt.Errorf("encoding imei: %w", encodeErr_enc_imei)
		}
		retagged_enc_imei, tagErr_enc_imei := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 5, enc_imei)
		if tagErr_enc_imei != nil {
			return nil, fmt.Errorf("encoding imei: %w", tagErr_enc_imei)
		}
		enc_imei = retagged_enc_imei
		children = append(children, enc_imei...)
	}
	if v.LcsPriority != nil {
		if len(*v.LcsPriority) < 1 || len(*v.LcsPriority) > 1 {
			if constraintErr := ber.CheckEncodedLength(nil, "lcs-Priority", "SIZE (1)", len(*v.LcsPriority)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_lcspriority, encodeErr_enc_lcspriority := ber.EncodeOctetString([]byte(*v.LcsPriority))
		if encodeErr_enc_lcspriority != nil {
			return nil, fmt.Errorf("encoding lcs-Priority: %w", encodeErr_enc_lcspriority)
		}
		retagged_enc_lcspriority, tagErr_enc_lcspriority := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 6, enc_lcspriority)
		if tagErr_enc_lcspriority != nil {
			return nil, fmt.Errorf("encoding lcs-Priority: %w", tagErr_enc_lcspriority)
		}
		enc_lcspriority = retagged_enc_lcspriority
		children = append(children, enc_lcspriority...)
	}
	if v.LcsQoS != nil {
		enc_lcsqos, err := v.LcsQoS.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding lcs-QoS: %w", err)
		}
		retagged_enc_lcsqos, tagErr_enc_lcsqos := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 7, enc_lcsqos)
		if tagErr_enc_lcsqos != nil {
			return nil, fmt.Errorf("encoding lcs-QoS: %w", tagErr_enc_lcsqos)
		}
		enc_lcsqos = retagged_enc_lcsqos
		children = append(children, enc_lcsqos...)
	}
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding extensionContainer: %w", err)
		}
		retagged_enc_extensioncontainer, tagErr_enc_extensioncontainer := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 8, enc_extensioncontainer)
		if tagErr_enc_extensioncontainer != nil {
			return nil, fmt.Errorf("encoding extensionContainer: %w", tagErr_enc_extensioncontainer)
		}
		enc_extensioncontainer = retagged_enc_extensioncontainer
		children = append(children, enc_extensioncontainer...)
	}
	if v.SupportedGADShapes != nil {
		if (*v.SupportedGADShapes).BitLength < 7 || (*v.SupportedGADShapes).BitLength > 16 {
			if constraintErr := ber.CheckEncodedLength(nil, "supportedGADShapes", "SIZE (7..16)", (*v.SupportedGADShapes).BitLength); constraintErr != nil {
				return nil, constraintErr
			}
		}
		if bitStringErr := ber.ValidateBitStringLength(v.SupportedGADShapes.Bytes, v.SupportedGADShapes.BitLength); bitStringErr != nil {
			return nil, fmt.Errorf("encoding %s: %w", "supportedGADShapes", bitStringErr)
		}
		if bitStringErr := ber.ValidateDERBitString(v.SupportedGADShapes.Bytes, v.SupportedGADShapes.BitLength); bitStringErr != nil {
			return nil, fmt.Errorf("encoding %s: %w", "supportedGADShapes", bitStringErr)
		}
		// arithmetic pattern BER_BITSTRING_FIELD: 0 <= bit length before modulo and subtraction; gen/codegen.go:526
		if v.SupportedGADShapes.BitLength < 0 {
			return nil, fmt.Errorf("negative bit string length")
		}
		enc_supportedgadshapes, encodeErr_enc_supportedgadshapes := ber.EncodeDERNamedBitString(v.SupportedGADShapes.Bytes, v.SupportedGADShapes.BitLength)
		if encodeErr_enc_supportedgadshapes != nil {
			return nil, fmt.Errorf("encoding supportedGADShapes: %w", encodeErr_enc_supportedgadshapes)
		}
		retagged_enc_supportedgadshapes, tagErr_enc_supportedgadshapes := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 9, enc_supportedgadshapes)
		if tagErr_enc_supportedgadshapes != nil {
			return nil, fmt.Errorf("encoding supportedGADShapes: %w", tagErr_enc_supportedgadshapes)
		}
		enc_supportedgadshapes = retagged_enc_supportedgadshapes
		children = append(children, enc_supportedgadshapes...)
	}
	if v.LcsReferenceNumber != nil {
		if len(*v.LcsReferenceNumber) < 1 || len(*v.LcsReferenceNumber) > 1 {
			if constraintErr := ber.CheckEncodedLength(nil, "lcs-ReferenceNumber", "SIZE (1)", len(*v.LcsReferenceNumber)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_lcsreferencenumber, encodeErr_enc_lcsreferencenumber := ber.EncodeOctetString([]byte(*v.LcsReferenceNumber))
		if encodeErr_enc_lcsreferencenumber != nil {
			return nil, fmt.Errorf("encoding lcs-ReferenceNumber: %w", encodeErr_enc_lcsreferencenumber)
		}
		retagged_enc_lcsreferencenumber, tagErr_enc_lcsreferencenumber := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 10, enc_lcsreferencenumber)
		if tagErr_enc_lcsreferencenumber != nil {
			return nil, fmt.Errorf("encoding lcs-ReferenceNumber: %w", tagErr_enc_lcsreferencenumber)
		}
		enc_lcsreferencenumber = retagged_enc_lcsreferencenumber
		children = append(children, enc_lcsreferencenumber...)
	}
	if v.LcsServiceTypeID != nil {
		if !(int64(*v.LcsServiceTypeID) >= 0 && int64(*v.LcsServiceTypeID) <= 127) {
			if constraintErr := ber.CheckEncodedValue(nil, "lcsServiceTypeID", "(0..127)", fmt.Sprint(int64(*v.LcsServiceTypeID))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_lcsservicetypeid := ber.EncodeInteger(int64(*v.LcsServiceTypeID))
		retagged_enc_lcsservicetypeid, tagErr_enc_lcsservicetypeid := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 11, enc_lcsservicetypeid)
		if tagErr_enc_lcsservicetypeid != nil {
			return nil, fmt.Errorf("encoding lcsServiceTypeID: %w", tagErr_enc_lcsservicetypeid)
		}
		enc_lcsservicetypeid = retagged_enc_lcsservicetypeid
		children = append(children, enc_lcsservicetypeid...)
	}
	if v.LcsCodeword != nil {
		enc_lcscodeword, err := v.LcsCodeword.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding lcsCodeword: %w", err)
		}
		retagged_enc_lcscodeword, tagErr_enc_lcscodeword := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 12, enc_lcscodeword)
		if tagErr_enc_lcscodeword != nil {
			return nil, fmt.Errorf("encoding lcsCodeword: %w", tagErr_enc_lcscodeword)
		}
		enc_lcscodeword = retagged_enc_lcscodeword
		children = append(children, enc_lcscodeword...)
	}
	if v.LcsPrivacyCheck != nil {
		enc_lcsprivacycheck, err := v.LcsPrivacyCheck.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding lcs-PrivacyCheck: %w", err)
		}
		retagged_enc_lcsprivacycheck, tagErr_enc_lcsprivacycheck := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 13, enc_lcsprivacycheck)
		if tagErr_enc_lcsprivacycheck != nil {
			return nil, fmt.Errorf("encoding lcs-PrivacyCheck: %w", tagErr_enc_lcsprivacycheck)
		}
		enc_lcsprivacycheck = retagged_enc_lcsprivacycheck
		children = append(children, enc_lcsprivacycheck...)
	}
	if v.AreaEventInfo != nil {
		enc_areaeventinfo, err := v.AreaEventInfo.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding areaEventInfo: %w", err)
		}
		retagged_enc_areaeventinfo, tagErr_enc_areaeventinfo := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 14, enc_areaeventinfo)
		if tagErr_enc_areaeventinfo != nil {
			return nil, fmt.Errorf("encoding areaEventInfo: %w", tagErr_enc_areaeventinfo)
		}
		enc_areaeventinfo = retagged_enc_areaeventinfo
		children = append(children, enc_areaeventinfo...)
	}
	if v.HGmlcAddress != nil {
		if len(*v.HGmlcAddress) < 5 || len(*v.HGmlcAddress) > 17 {
			if constraintErr := ber.CheckEncodedLength(nil, "h-gmlc-Address", "SIZE (5..17)", len(*v.HGmlcAddress)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_hgmlcaddress, encodeErr_enc_hgmlcaddress := ber.EncodeOctetString([]byte(*v.HGmlcAddress))
		if encodeErr_enc_hgmlcaddress != nil {
			return nil, fmt.Errorf("encoding h-gmlc-Address: %w", encodeErr_enc_hgmlcaddress)
		}
		retagged_enc_hgmlcaddress, tagErr_enc_hgmlcaddress := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 15, enc_hgmlcaddress)
		if tagErr_enc_hgmlcaddress != nil {
			return nil, fmt.Errorf("encoding h-gmlc-Address: %w", tagErr_enc_hgmlcaddress)
		}
		enc_hgmlcaddress = retagged_enc_hgmlcaddress
		children = append(children, enc_hgmlcaddress...)
	}
	if v.MoLrShortCircuitIndicator != nil {
		enc_molrshortcircuitindicator := ber.EncodeNull()
		retagged_enc_molrshortcircuitindicator, tagErr_enc_molrshortcircuitindicator := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 16, enc_molrshortcircuitindicator)
		if tagErr_enc_molrshortcircuitindicator != nil {
			return nil, fmt.Errorf("encoding mo-lrShortCircuitIndicator: %w", tagErr_enc_molrshortcircuitindicator)
		}
		enc_molrshortcircuitindicator = retagged_enc_molrshortcircuitindicator
		children = append(children, enc_molrshortcircuitindicator...)
	}
	if v.PeriodicLDRInfo != nil {
		enc_periodicldrinfo, err := v.PeriodicLDRInfo.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding periodicLDRInfo: %w", err)
		}
		retagged_enc_periodicldrinfo, tagErr_enc_periodicldrinfo := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 17, enc_periodicldrinfo)
		if tagErr_enc_periodicldrinfo != nil {
			return nil, fmt.Errorf("encoding periodicLDRInfo: %w", tagErr_enc_periodicldrinfo)
		}
		enc_periodicldrinfo = retagged_enc_periodicldrinfo
		children = append(children, enc_periodicldrinfo...)
	}
	if v.ReportingPLMNList != nil {
		enc_reportingplmnlist, err := v.ReportingPLMNList.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding reportingPLMNList: %w", err)
		}
		retagged_enc_reportingplmnlist, tagErr_enc_reportingplmnlist := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 18, enc_reportingplmnlist)
		if tagErr_enc_reportingplmnlist != nil {
			return nil, fmt.Errorf("encoding reportingPLMNList: %w", tagErr_enc_reportingplmnlist)
		}
		enc_reportingplmnlist = retagged_enc_reportingplmnlist
		children = append(children, enc_reportingplmnlist...)
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
		return nil, fmt.Errorf("encoding LCSProvideSubscriberLocationArg as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes LCSProvideSubscriberLocationArg from BER/DER format.
func (v *LCSProvideSubscriberLocationArg) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: LCSProvideSubscriberLocationArg destination is nil", ber.ErrInvalidValue)
	}
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = LCSProvideSubscriberLocationArg{}
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
		return fmt.Errorf("decoding LCSProvideSubscriberLocationArg SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "LCSProvideSubscriberLocationArg", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode locationType
	if offset >= len(content) {
		return fmt.Errorf("missing required field locationType")
	}
	// Decode nested SEQUENCE (LCSLocationType)
	_, n_locationtype, _, tlvErr_locationtype := ber.DecodeTLV(content[offset:], opts...)
	if tlvErr_locationtype != nil {
		return fmt.Errorf("decoding locationType: %w", tlvErr_locationtype)
	}
	if offset < 0 || offset >
		len(content) || n_locationtype < 0 || n_locationtype > len(content[offset:]) {
		return fmt.Errorf("invalid BER content window")
	}

	if unmErr := v.LocationType.UnmarshalBER(content[offset:offset+n_locationtype], ber.ChildDecodeOptions(opts, "locationType")...); unmErr != nil {
		return fmt.Errorf("decoding locationType: %w", unmErr)
	}
	if offset < 0 || offset >
		len(content) || n_locationtype < 0 || n_locationtype > len(content[offset:]) {
		return fmt.Errorf("invalid BER content window")
	}

	offset += n_locationtype
	// Decode mlc-Number
	if offset >= len(content) {
		return fmt.Errorf("missing required field mlc-Number")
	}
	val_mlcnumber, n, err := ber.DecodeOctetString(content[offset:], opts...)
	if err != nil {
		return fmt.Errorf("decoding mlc-Number: %w", err)
	}
	v.MlcNumber = ISDNAddressString3(val_mlcnumber)
	if offset < 0 || offset >
		len(content) || n < 0 || n > len(content[offset:]) {
		return fmt.Errorf("invalid BER content window")
	}

	offset += n
	if len(v.MlcNumber) < 1 || len(v.MlcNumber) > 9 {
		if constraintErr := ber.CheckDecodedLength(opts, "mlc-Number", "SIZE (1..9)", len(v.MlcNumber)); constraintErr != nil {
			return constraintErr
		}
	}
	if len(v.MlcNumber) < 1 || len(v.MlcNumber) > 20 {
		if constraintErr := ber.CheckDecodedLength(opts, "mlc-Number", "SIZE (1..20)", len(v.MlcNumber)); constraintErr != nil {
			return constraintErr
		}
	}
	// Decode lcs-ClientID
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
				decodedTag_lcsclientid, n_lcsclientid, rawVal_lcsclientid, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding lcs-ClientID: %w", err)
				}
				if decodedTag_lcsclientid.Class != tag.ClassContextSpecific || decodedTag_lcsclientid.Number != 0 || decodedTag_lcsclientid.Constructed != true {
					return fmt.Errorf("decoding lcs-ClientID: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_lcsclientid)
				}
				reconstructed_lcsclientid, reconstructionErr_lcsclientid := ber.EncodeSequence(rawVal_lcsclientid)
				if reconstructionErr_lcsclientid != nil {
					return fmt.Errorf("decoding lcs-ClientID: %w", reconstructionErr_lcsclientid)
				}
				var dec_lcsclientid LCSLCSClientID
				if unmErr := dec_lcsclientid.UnmarshalBER(reconstructed_lcsclientid, ber.ChildDecodeOptions(opts, "lcs-ClientID")...); unmErr != nil {
					return fmt.Errorf("decoding lcs-ClientID: %w", unmErr)
				}
				v.LcsClientID = &dec_lcsclientid
				if offset < 0 || offset >
					len(content) || n_lcsclientid < 0 || n_lcsclientid > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_lcsclientid
			}
		}
	}
	// Decode privacyOverride
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
				decodedTag_privacyoverride, n_privacyoverride, rawVal_privacyoverride, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding privacyOverride: %w", err)
				}
				if decodedTag_privacyoverride.Class != tag.ClassContextSpecific || decodedTag_privacyoverride.Number != 1 || decodedTag_privacyoverride.Constructed != false {
					return fmt.Errorf("decoding privacyOverride: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_privacyoverride)
				}
				if len(rawVal_privacyoverride) != 0 {
					return fmt.Errorf("decoding privacyOverride: %w: NULL content length %d", ber.ErrInvalidValue, len(rawVal_privacyoverride))
				}
				v.PrivacyOverride = &struct{}{}
				if offset < 0 || offset >
					len(content) || n_privacyoverride < 0 || n_privacyoverride > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_privacyoverride
			}
		}
	}
	// Decode imsi
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2 {
				decodedTag_imsi, n_imsi, rawVal_imsi, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding imsi: %w", err)
				}
				if decodedTag_imsi.Class != tag.ClassContextSpecific || decodedTag_imsi.Number != 2 {
					return fmt.Errorf("decoding imsi: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_imsi)
				}
				decVal_imsi, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_imsi.Constructed, rawVal_imsi, opts...)
				if octetErr != nil {
					return fmt.Errorf("decoding imsi: %w", octetErr)
				}
				tmp_imsi := IMSI3(decVal_imsi)
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
	// Decode msisdn
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3 {
				decodedTag_msisdn, n_msisdn, rawVal_msisdn, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding msisdn: %w", err)
				}
				if decodedTag_msisdn.Class != tag.ClassContextSpecific || decodedTag_msisdn.Number != 3 {
					return fmt.Errorf("decoding msisdn: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_msisdn)
				}
				decVal_msisdn, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_msisdn.Constructed, rawVal_msisdn, opts...)
				if octetErr != nil {
					return fmt.Errorf("decoding msisdn: %w", octetErr)
				}
				tmp_msisdn := ISDNAddressString3(decVal_msisdn)
				v.Msisdn = &tmp_msisdn
				if offset < 0 || offset >
					len(content) || n_msisdn < 0 || n_msisdn > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_msisdn
				if len(*v.Msisdn) < 1 || len(*v.Msisdn) > 9 {
					if constraintErr := ber.CheckDecodedLength(opts, "msisdn", "SIZE (1..9)", len(*v.Msisdn)); constraintErr != nil {
						return constraintErr
					}
				}
				if len(*v.Msisdn) < 1 || len(*v.Msisdn) > 20 {
					if constraintErr := ber.CheckDecodedLength(opts, "msisdn", "SIZE (1..20)", len(*v.Msisdn)); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode lmsi
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4 {
				decodedTag_lmsi, n_lmsi, rawVal_lmsi, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding lmsi: %w", err)
				}
				if decodedTag_lmsi.Class != tag.ClassContextSpecific || decodedTag_lmsi.Number != 4 {
					return fmt.Errorf("decoding lmsi: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_lmsi)
				}
				decVal_lmsi, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_lmsi.Constructed, rawVal_lmsi, opts...)
				if octetErr != nil {
					return fmt.Errorf("decoding lmsi: %w", octetErr)
				}
				tmp_lmsi := LMSI3(decVal_lmsi)
				v.Lmsi = &tmp_lmsi
				if offset < 0 || offset >
					len(content) || n_lmsi < 0 || n_lmsi > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_lmsi
				if len(*v.Lmsi) < 4 || len(*v.Lmsi) > 4 {
					if constraintErr := ber.CheckDecodedLength(opts, "lmsi", "SIZE (4)", len(*v.Lmsi)); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode imei
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 5 {
				decodedTag_imei, n_imei, rawVal_imei, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding imei: %w", err)
				}
				if decodedTag_imei.Class != tag.ClassContextSpecific || decodedTag_imei.Number != 5 {
					return fmt.Errorf("decoding imei: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_imei)
				}
				decVal_imei, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_imei.Constructed, rawVal_imei, opts...)
				if octetErr != nil {
					return fmt.Errorf("decoding imei: %w", octetErr)
				}
				tmp_imei := IMEI3(decVal_imei)
				v.Imei = &tmp_imei
				if offset < 0 || offset >
					len(content) || n_imei < 0 || n_imei > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_imei
				if len(*v.Imei) < 8 || len(*v.Imei) > 8 {
					if constraintErr := ber.CheckDecodedLength(opts, "imei", "SIZE (8)", len(*v.Imei)); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode lcs-Priority
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 6 {
				decodedTag_lcspriority, n_lcspriority, rawVal_lcspriority, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding lcs-Priority: %w", err)
				}
				if decodedTag_lcspriority.Class != tag.ClassContextSpecific || decodedTag_lcspriority.Number != 6 {
					return fmt.Errorf("decoding lcs-Priority: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_lcspriority)
				}
				decVal_lcspriority, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_lcspriority.Constructed, rawVal_lcspriority, opts...)
				if octetErr != nil {
					return fmt.Errorf("decoding lcs-Priority: %w", octetErr)
				}
				tmp_lcspriority := LCSLCSPriority(decVal_lcspriority)
				v.LcsPriority = &tmp_lcspriority
				if offset < 0 || offset >
					len(content) || n_lcspriority < 0 || n_lcspriority > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_lcspriority
				if len(*v.LcsPriority) < 1 || len(*v.LcsPriority) > 1 {
					if constraintErr := ber.CheckDecodedLength(opts, "lcs-Priority", "SIZE (1)", len(*v.LcsPriority)); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode lcs-QoS
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 7 {
				decodedTag_lcsqos, n_lcsqos, rawVal_lcsqos, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding lcs-QoS: %w", err)
				}
				if decodedTag_lcsqos.Class != tag.ClassContextSpecific || decodedTag_lcsqos.Number != 7 || decodedTag_lcsqos.Constructed != true {
					return fmt.Errorf("decoding lcs-QoS: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_lcsqos)
				}
				reconstructed_lcsqos, reconstructionErr_lcsqos := ber.EncodeSequence(rawVal_lcsqos)
				if reconstructionErr_lcsqos != nil {
					return fmt.Errorf("decoding lcs-QoS: %w", reconstructionErr_lcsqos)
				}
				var dec_lcsqos LCSLCSQoS
				if unmErr := dec_lcsqos.UnmarshalBER(reconstructed_lcsqos, ber.ChildDecodeOptions(opts, "lcs-QoS")...); unmErr != nil {
					return fmt.Errorf("decoding lcs-QoS: %w", unmErr)
				}
				v.LcsQoS = &dec_lcsqos
				if offset < 0 || offset >
					len(content) || n_lcsqos < 0 || n_lcsqos > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_lcsqos
			}
		}
	}
	// Decode extensionContainer
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 8 {
				decodedTag_extensioncontainer, n_extensioncontainer, rawVal_extensioncontainer, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding extensionContainer: %w", err)
				}
				if decodedTag_extensioncontainer.Class != tag.ClassContextSpecific || decodedTag_extensioncontainer.Number != 8 || decodedTag_extensioncontainer.Constructed != true {
					return fmt.Errorf("decoding extensionContainer: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_extensioncontainer)
				}
				reconstructed_extensioncontainer, reconstructionErr_extensioncontainer := ber.EncodeSequence(rawVal_extensioncontainer)
				if reconstructionErr_extensioncontainer != nil {
					return fmt.Errorf("decoding extensionContainer: %w", reconstructionErr_extensioncontainer)
				}
				var dec_extensioncontainer ExtensionContainer3
				if unmErr := dec_extensioncontainer.UnmarshalBER(reconstructed_extensioncontainer, ber.ChildDecodeOptions(opts, "extensionContainer")...); unmErr != nil {
					return fmt.Errorf("decoding extensionContainer: %w", unmErr)
				}
				v.ExtensionContainer = &dec_extensioncontainer
				if offset < 0 || offset >
					len(content) || n_extensioncontainer < 0 || n_extensioncontainer > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_extensioncontainer
			}
		}
	}
	// Decode supportedGADShapes
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 9 {
				decodedTag_supportedgadshapes, n_supportedgadshapes, rawVal_supportedgadshapes, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding supportedGADShapes: %w", err)
				}
				if decodedTag_supportedgadshapes.Class != tag.ClassContextSpecific || decodedTag_supportedgadshapes.Number != 9 {
					return fmt.Errorf("decoding supportedGADShapes: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_supportedgadshapes)
				}
				bsBytes_supportedgadshapes, bsUnused_supportedgadshapes, bsErr := ber.DecodeImplicitBitStringValue(decodedTag_supportedgadshapes.Constructed, rawVal_supportedgadshapes, opts...)
				if bsErr != nil {
					return fmt.Errorf("decoding supportedGADShapes: %w", bsErr)
				}
				bsBitLength_supportedgadshapes, bsLenErr_supportedgadshapes := ber.BitStringBitLength(len(bsBytes_supportedgadshapes), bsUnused_supportedgadshapes)
				if bsLenErr_supportedgadshapes != nil {
					return fmt.Errorf("decoding supportedGADShapes: %w", bsLenErr_supportedgadshapes)
				}
				tmp_supportedgadshapes := runtime.BitString{Bytes: bsBytes_supportedgadshapes, BitLength: bsBitLength_supportedgadshapes}
				v.SupportedGADShapes = &tmp_supportedgadshapes
				if offset < 0 || offset >
					len(content) || n_supportedgadshapes < 0 || n_supportedgadshapes > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_supportedgadshapes
				*v.SupportedGADShapes = ber.NormalizeNamedBitStringSize(*v.SupportedGADShapes, []ber.NamedBitSizeSet{{{Min: 7, Max: 16}}}, opts...)
				if (*v.SupportedGADShapes).BitLength < 7 || (*v.SupportedGADShapes).BitLength > 16 {
					if constraintErr := ber.CheckDecodedLength(opts, "supportedGADShapes", "SIZE (7..16)", (*v.SupportedGADShapes).BitLength); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode lcs-ReferenceNumber
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 10 {
				decodedTag_lcsreferencenumber, n_lcsreferencenumber, rawVal_lcsreferencenumber, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding lcs-ReferenceNumber: %w", err)
				}
				if decodedTag_lcsreferencenumber.Class != tag.ClassContextSpecific || decodedTag_lcsreferencenumber.Number != 10 {
					return fmt.Errorf("decoding lcs-ReferenceNumber: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_lcsreferencenumber)
				}
				decVal_lcsreferencenumber, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_lcsreferencenumber.Constructed, rawVal_lcsreferencenumber, opts...)
				if octetErr != nil {
					return fmt.Errorf("decoding lcs-ReferenceNumber: %w", octetErr)
				}
				tmp_lcsreferencenumber := LCSLCSReferenceNumber(decVal_lcsreferencenumber)
				v.LcsReferenceNumber = &tmp_lcsreferencenumber
				if offset < 0 || offset >
					len(content) || n_lcsreferencenumber < 0 || n_lcsreferencenumber > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_lcsreferencenumber
				if len(*v.LcsReferenceNumber) < 1 || len(*v.LcsReferenceNumber) > 1 {
					if constraintErr := ber.CheckDecodedLength(opts, "lcs-ReferenceNumber", "SIZE (1)", len(*v.LcsReferenceNumber)); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode lcsServiceTypeID
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 11 {
				decodedTag_lcsservicetypeid, n_lcsservicetypeid, rawVal_lcsservicetypeid, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding lcsServiceTypeID: %w", err)
				}
				if decodedTag_lcsservicetypeid.Class != tag.ClassContextSpecific || decodedTag_lcsservicetypeid.Number != 11 || decodedTag_lcsservicetypeid.Constructed != false {
					return fmt.Errorf("decoding lcsServiceTypeID: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_lcsservicetypeid)
				}
				decVal_lcsservicetypeid, intErr := ber.DecodeIntegerValue(rawVal_lcsservicetypeid)
				if intErr != nil {
					return fmt.Errorf("decoding lcsServiceTypeID: %w", intErr)
				}
				tmp_lcsservicetypeid := LCSServiceTypeID3(decVal_lcsservicetypeid)
				v.LcsServiceTypeID = &tmp_lcsservicetypeid
				if offset < 0 || offset >
					len(content) || n_lcsservicetypeid < 0 || n_lcsservicetypeid > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_lcsservicetypeid
				if !(int64(*v.LcsServiceTypeID) >= 0 && int64(*v.LcsServiceTypeID) <= 127) {
					if constraintErr := ber.CheckDecodedValue(opts, "lcsServiceTypeID", "(0..127)", fmt.Sprint(int64(*v.LcsServiceTypeID))); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode lcsCodeword
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 12 {
				decodedTag_lcscodeword, n_lcscodeword, rawVal_lcscodeword, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding lcsCodeword: %w", err)
				}
				if decodedTag_lcscodeword.Class != tag.ClassContextSpecific || decodedTag_lcscodeword.Number != 12 || decodedTag_lcscodeword.Constructed != true {
					return fmt.Errorf("decoding lcsCodeword: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_lcscodeword)
				}
				reconstructed_lcscodeword, reconstructionErr_lcscodeword := ber.EncodeSequence(rawVal_lcscodeword)
				if reconstructionErr_lcscodeword != nil {
					return fmt.Errorf("decoding lcsCodeword: %w", reconstructionErr_lcscodeword)
				}
				var dec_lcscodeword LCSLCSCodeword
				if unmErr := dec_lcscodeword.UnmarshalBER(reconstructed_lcscodeword, ber.ChildDecodeOptions(opts, "lcsCodeword")...); unmErr != nil {
					return fmt.Errorf("decoding lcsCodeword: %w", unmErr)
				}
				v.LcsCodeword = &dec_lcscodeword
				if offset < 0 || offset >
					len(content) || n_lcscodeword < 0 || n_lcscodeword > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_lcscodeword
			}
		}
	}
	// Decode lcs-PrivacyCheck
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 13 {
				decodedTag_lcsprivacycheck, n_lcsprivacycheck, rawVal_lcsprivacycheck, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding lcs-PrivacyCheck: %w", err)
				}
				if decodedTag_lcsprivacycheck.Class != tag.ClassContextSpecific || decodedTag_lcsprivacycheck.Number != 13 || decodedTag_lcsprivacycheck.Constructed != true {
					return fmt.Errorf("decoding lcs-PrivacyCheck: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_lcsprivacycheck)
				}
				reconstructed_lcsprivacycheck, reconstructionErr_lcsprivacycheck := ber.EncodeSequence(rawVal_lcsprivacycheck)
				if reconstructionErr_lcsprivacycheck != nil {
					return fmt.Errorf("decoding lcs-PrivacyCheck: %w", reconstructionErr_lcsprivacycheck)
				}
				var dec_lcsprivacycheck LCSLCSPrivacyCheck
				if unmErr := dec_lcsprivacycheck.UnmarshalBER(reconstructed_lcsprivacycheck, ber.ChildDecodeOptions(opts, "lcs-PrivacyCheck")...); unmErr != nil {
					return fmt.Errorf("decoding lcs-PrivacyCheck: %w", unmErr)
				}
				v.LcsPrivacyCheck = &dec_lcsprivacycheck
				if offset < 0 || offset >
					len(content) || n_lcsprivacycheck < 0 || n_lcsprivacycheck > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_lcsprivacycheck
			}
		}
	}
	// Decode areaEventInfo
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 14 {
				decodedTag_areaeventinfo, n_areaeventinfo, rawVal_areaeventinfo, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding areaEventInfo: %w", err)
				}
				if decodedTag_areaeventinfo.Class != tag.ClassContextSpecific || decodedTag_areaeventinfo.Number != 14 || decodedTag_areaeventinfo.Constructed != true {
					return fmt.Errorf("decoding areaEventInfo: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_areaeventinfo)
				}
				reconstructed_areaeventinfo, reconstructionErr_areaeventinfo := ber.EncodeSequence(rawVal_areaeventinfo)
				if reconstructionErr_areaeventinfo != nil {
					return fmt.Errorf("decoding areaEventInfo: %w", reconstructionErr_areaeventinfo)
				}
				var dec_areaeventinfo LCSAreaEventInfo
				if unmErr := dec_areaeventinfo.UnmarshalBER(reconstructed_areaeventinfo, ber.ChildDecodeOptions(opts, "areaEventInfo")...); unmErr != nil {
					return fmt.Errorf("decoding areaEventInfo: %w", unmErr)
				}
				v.AreaEventInfo = &dec_areaeventinfo
				if offset < 0 || offset >
					len(content) || n_areaeventinfo < 0 || n_areaeventinfo > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_areaeventinfo
			}
		}
	}
	// Decode h-gmlc-Address
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 15 {
				decodedTag_hgmlcaddress, n_hgmlcaddress, rawVal_hgmlcaddress, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding h-gmlc-Address: %w", err)
				}
				if decodedTag_hgmlcaddress.Class != tag.ClassContextSpecific || decodedTag_hgmlcaddress.Number != 15 {
					return fmt.Errorf("decoding h-gmlc-Address: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_hgmlcaddress)
				}
				decVal_hgmlcaddress, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_hgmlcaddress.Constructed, rawVal_hgmlcaddress, opts...)
				if octetErr != nil {
					return fmt.Errorf("decoding h-gmlc-Address: %w", octetErr)
				}
				tmp_hgmlcaddress := CommonDataTypesGSNAddress(decVal_hgmlcaddress)
				v.HGmlcAddress = &tmp_hgmlcaddress
				if offset < 0 || offset >
					len(content) || n_hgmlcaddress < 0 || n_hgmlcaddress > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_hgmlcaddress
				if len(*v.HGmlcAddress) < 5 || len(*v.HGmlcAddress) > 17 {
					if constraintErr := ber.CheckDecodedLength(opts, "h-gmlc-Address", "SIZE (5..17)", len(*v.HGmlcAddress)); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode mo-lrShortCircuitIndicator
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 16 {
				decodedTag_molrshortcircuitindicator, n_molrshortcircuitindicator, rawVal_molrshortcircuitindicator, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding mo-lrShortCircuitIndicator: %w", err)
				}
				if decodedTag_molrshortcircuitindicator.Class != tag.ClassContextSpecific || decodedTag_molrshortcircuitindicator.Number != 16 || decodedTag_molrshortcircuitindicator.Constructed != false {
					return fmt.Errorf("decoding mo-lrShortCircuitIndicator: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_molrshortcircuitindicator)
				}
				if len(rawVal_molrshortcircuitindicator) != 0 {
					return fmt.Errorf("decoding mo-lrShortCircuitIndicator: %w: NULL content length %d", ber.ErrInvalidValue, len(rawVal_molrshortcircuitindicator))
				}
				v.MoLrShortCircuitIndicator = &struct{}{}
				if offset < 0 || offset >
					len(content) || n_molrshortcircuitindicator < 0 || n_molrshortcircuitindicator >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_molrshortcircuitindicator
			}
		}
	}
	// Decode periodicLDRInfo
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 17 {
				decodedTag_periodicldrinfo, n_periodicldrinfo, rawVal_periodicldrinfo, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding periodicLDRInfo: %w", err)
				}
				if decodedTag_periodicldrinfo.Class != tag.ClassContextSpecific || decodedTag_periodicldrinfo.Number != 17 || decodedTag_periodicldrinfo.Constructed != true {
					return fmt.Errorf("decoding periodicLDRInfo: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_periodicldrinfo)
				}
				reconstructed_periodicldrinfo, reconstructionErr_periodicldrinfo := ber.EncodeSequence(rawVal_periodicldrinfo)
				if reconstructionErr_periodicldrinfo != nil {
					return fmt.Errorf("decoding periodicLDRInfo: %w", reconstructionErr_periodicldrinfo)
				}
				var dec_periodicldrinfo LCSPeriodicLDRInfo
				if unmErr := dec_periodicldrinfo.UnmarshalBER(reconstructed_periodicldrinfo, ber.ChildDecodeOptions(opts, "periodicLDRInfo")...); unmErr != nil {
					return fmt.Errorf("decoding periodicLDRInfo: %w", unmErr)
				}
				v.PeriodicLDRInfo = &dec_periodicldrinfo
				if offset < 0 || offset >
					len(content) || n_periodicldrinfo < 0 || n_periodicldrinfo > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_periodicldrinfo
			}
		}
	}
	// Decode reportingPLMNList
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 18 {
				decodedTag_reportingplmnlist, n_reportingplmnlist, rawVal_reportingplmnlist, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding reportingPLMNList: %w", err)
				}
				if decodedTag_reportingplmnlist.Class != tag.ClassContextSpecific || decodedTag_reportingplmnlist.Number != 18 || decodedTag_reportingplmnlist.Constructed != true {
					return fmt.Errorf("decoding reportingPLMNList: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_reportingplmnlist)
				}
				reconstructed_reportingplmnlist, reconstructionErr_reportingplmnlist := ber.EncodeSequence(rawVal_reportingplmnlist)
				if reconstructionErr_reportingplmnlist != nil {
					return fmt.Errorf("decoding reportingPLMNList: %w", reconstructionErr_reportingplmnlist)
				}
				var dec_reportingplmnlist LCSReportingPLMNList
				if unmErr := dec_reportingplmnlist.UnmarshalBER(reconstructed_reportingplmnlist, ber.ChildDecodeOptions(opts, "reportingPLMNList")...); unmErr != nil {
					return fmt.Errorf("decoding reportingPLMNList: %w", unmErr)
				}
				v.ReportingPLMNList = &dec_reportingplmnlist
				if offset < 0 || offset >
					len(content) || n_reportingplmnlist < 0 || n_reportingplmnlist > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_reportingplmnlist
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:], opts...)
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "LCSProvideSubscriberLocationArg", Cause: extErr_}
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

// MarshalBER encodes LCSLocationType to BER format.
func (v *LCSLocationType) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: LCSLocationType receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *LCSLocationType) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	enc_locationestimatetype := ber.EncodeEnumerated(int64(v.LocationEstimateType))
	retagged_enc_locationestimatetype, tagErr_enc_locationestimatetype := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_locationestimatetype)
	if tagErr_enc_locationestimatetype != nil {
		return nil, fmt.Errorf("encoding locationEstimateType: %w", tagErr_enc_locationestimatetype)
	}
	enc_locationestimatetype = retagged_enc_locationestimatetype
	children = append(children, enc_locationestimatetype...)
	if v.DeferredLocationEventType != nil {
		if (*v.DeferredLocationEventType).BitLength < 1 || (*v.DeferredLocationEventType).BitLength > 16 {
			if constraintErr := ber.CheckEncodedLength(opts, "deferredLocationEventType", "SIZE (1..16)", (*v.DeferredLocationEventType).BitLength); constraintErr != nil {
				return nil, constraintErr
			}
		}
		if bitStringErr := ber.ValidateBitStringLength(v.DeferredLocationEventType.Bytes, v.DeferredLocationEventType.BitLength); bitStringErr != nil {
			return nil, fmt.Errorf("encoding %s: %w", "deferredLocationEventType", bitStringErr)
		}
		// arithmetic pattern BER_BITSTRING_FIELD: 0 <= bit length before modulo and subtraction; gen/codegen.go:526
		if v.DeferredLocationEventType.BitLength < 0 {
			return nil, fmt.Errorf("negative bit string length")
		}
		enc_deferredlocationeventtype, encodeErr_enc_deferredlocationeventtype := ber.EncodeBitString(v.DeferredLocationEventType.Bytes, (8-(v.DeferredLocationEventType.BitLength%8))%8)
		if encodeErr_enc_deferredlocationeventtype != nil {
			return nil, fmt.Errorf("encoding deferredLocationEventType: %w", encodeErr_enc_deferredlocationeventtype)
		}
		retagged_enc_deferredlocationeventtype, tagErr_enc_deferredlocationeventtype := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_deferredlocationeventtype)
		if tagErr_enc_deferredlocationeventtype != nil {
			return nil, fmt.Errorf("encoding deferredLocationEventType: %w", tagErr_enc_deferredlocationeventtype)
		}
		enc_deferredlocationeventtype = retagged_enc_deferredlocationeventtype
		children = append(children, enc_deferredlocationeventtype...)
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

// MarshalDER encodes LCSLocationType to DER format.
func (v *LCSLocationType) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: LCSLocationType receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	enc_locationestimatetype := ber.EncodeEnumerated(int64(v.LocationEstimateType))
	retagged_enc_locationestimatetype, tagErr_enc_locationestimatetype := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_locationestimatetype)
	if tagErr_enc_locationestimatetype != nil {
		return nil, fmt.Errorf("encoding locationEstimateType: %w", tagErr_enc_locationestimatetype)
	}
	enc_locationestimatetype = retagged_enc_locationestimatetype
	children = append(children, enc_locationestimatetype...)
	if v.DeferredLocationEventType != nil {
		if (*v.DeferredLocationEventType).BitLength < 1 || (*v.DeferredLocationEventType).BitLength > 16 {
			if constraintErr := ber.CheckEncodedLength(nil, "deferredLocationEventType", "SIZE (1..16)", (*v.DeferredLocationEventType).BitLength); constraintErr != nil {
				return nil, constraintErr
			}
		}
		if bitStringErr := ber.ValidateBitStringLength(v.DeferredLocationEventType.Bytes, v.DeferredLocationEventType.BitLength); bitStringErr != nil {
			return nil, fmt.Errorf("encoding %s: %w", "deferredLocationEventType", bitStringErr)
		}
		if bitStringErr := ber.ValidateDERBitString(v.DeferredLocationEventType.Bytes, v.DeferredLocationEventType.BitLength); bitStringErr != nil {
			return nil, fmt.Errorf("encoding %s: %w", "deferredLocationEventType", bitStringErr)
		}
		// arithmetic pattern BER_BITSTRING_FIELD: 0 <= bit length before modulo and subtraction; gen/codegen.go:526
		if v.DeferredLocationEventType.BitLength < 0 {
			return nil, fmt.Errorf("negative bit string length")
		}
		enc_deferredlocationeventtype, encodeErr_enc_deferredlocationeventtype := ber.EncodeDERNamedBitString(v.DeferredLocationEventType.Bytes, v.DeferredLocationEventType.BitLength)
		if encodeErr_enc_deferredlocationeventtype != nil {
			return nil, fmt.Errorf("encoding deferredLocationEventType: %w", encodeErr_enc_deferredlocationeventtype)
		}
		retagged_enc_deferredlocationeventtype, tagErr_enc_deferredlocationeventtype := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_deferredlocationeventtype)
		if tagErr_enc_deferredlocationeventtype != nil {
			return nil, fmt.Errorf("encoding deferredLocationEventType: %w", tagErr_enc_deferredlocationeventtype)
		}
		enc_deferredlocationeventtype = retagged_enc_deferredlocationeventtype
		children = append(children, enc_deferredlocationeventtype...)
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
		return nil, fmt.Errorf("encoding LCSLocationType as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes LCSLocationType from BER/DER format.
func (v *LCSLocationType) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: LCSLocationType destination is nil", ber.ErrInvalidValue)
	}
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = LCSLocationType{}
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
		return fmt.Errorf("decoding LCSLocationType SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "LCSLocationType", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode locationEstimateType
	if offset >= len(content) {
		return fmt.Errorf("missing required field locationEstimateType")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 0 {
			return fmt.Errorf("expected tag [%s %d] for locationEstimateType, got %s", "CONTEXT", 0, reqTag_)
		}
	}
	decodedTag_locationestimatetype, n_locationestimatetype, rawVal_locationestimatetype, err := ber.DecodeTLV(content[offset:], opts...)
	if err != nil {
		return fmt.Errorf("decoding locationEstimateType: %w", err)
	}
	if decodedTag_locationestimatetype.Class != tag.ClassContextSpecific || decodedTag_locationestimatetype.Number != 0 || decodedTag_locationestimatetype.Constructed != false {
		return fmt.Errorf("decoding locationEstimateType: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_locationestimatetype)
	}
	decVal_locationestimatetype, intErr := ber.DecodeEnumeratedValue(rawVal_locationestimatetype)
	if intErr != nil {
		return fmt.Errorf("decoding locationEstimateType: %w", intErr)
	}
	v.LocationEstimateType = LCSLocationEstimateType(decVal_locationestimatetype)
	if offset < 0 || offset >
		len(content) || n_locationestimatetype < 0 || n_locationestimatetype >
		len(content[offset:]) {
		return fmt.Errorf("invalid BER content window")
	}

	offset += n_locationestimatetype
	// Decode deferredLocationEventType
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
				decodedTag_deferredlocationeventtype, n_deferredlocationeventtype, rawVal_deferredlocationeventtype, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding deferredLocationEventType: %w", err)
				}
				if decodedTag_deferredlocationeventtype.Class != tag.ClassContextSpecific || decodedTag_deferredlocationeventtype.Number != 1 {
					return fmt.Errorf("decoding deferredLocationEventType: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_deferredlocationeventtype)
				}
				bsBytes_deferredlocationeventtype, bsUnused_deferredlocationeventtype, bsErr := ber.DecodeImplicitBitStringValue(decodedTag_deferredlocationeventtype.Constructed, rawVal_deferredlocationeventtype, opts...)
				if bsErr != nil {
					return fmt.Errorf("decoding deferredLocationEventType: %w", bsErr)
				}
				bsBitLength_deferredlocationeventtype, bsLenErr_deferredlocationeventtype := ber.BitStringBitLength(len(bsBytes_deferredlocationeventtype), bsUnused_deferredlocationeventtype)
				if bsLenErr_deferredlocationeventtype != nil {
					return fmt.Errorf("decoding deferredLocationEventType: %w", bsLenErr_deferredlocationeventtype)
				}
				tmp_deferredlocationeventtype := runtime.BitString{Bytes: bsBytes_deferredlocationeventtype, BitLength: bsBitLength_deferredlocationeventtype}
				v.DeferredLocationEventType = &tmp_deferredlocationeventtype
				if offset < 0 || offset >
					len(content) || n_deferredlocationeventtype < 0 || n_deferredlocationeventtype >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_deferredlocationeventtype
				*v.DeferredLocationEventType = ber.NormalizeNamedBitStringSize(*v.DeferredLocationEventType, []ber.NamedBitSizeSet{{{Min: 1, Max: 16}}}, opts...)
				if (*v.DeferredLocationEventType).BitLength < 1 || (*v.DeferredLocationEventType).BitLength > 16 {
					if constraintErr := ber.CheckDecodedLength(opts, "deferredLocationEventType", "SIZE (1..16)", (*v.DeferredLocationEventType).BitLength); constraintErr != nil {
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
			return &ber.DecodeError{Offset: offset, TypeName: "LCSLocationType", Cause: extErr_}
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

// MarshalBER encodes LCSLCSClientID to BER format.
func (v *LCSLCSClientID) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: LCSLCSClientID receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *LCSLCSClientID) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	enc_lcsclienttype := ber.EncodeEnumerated(int64(v.LcsClientType))
	retagged_enc_lcsclienttype, tagErr_enc_lcsclienttype := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_lcsclienttype)
	if tagErr_enc_lcsclienttype != nil {
		return nil, fmt.Errorf("encoding lcsClientType: %w", tagErr_enc_lcsclienttype)
	}
	enc_lcsclienttype = retagged_enc_lcsclienttype
	children = append(children, enc_lcsclienttype...)
	if v.LcsClientExternalID != nil {
		enc_lcsclientexternalid, err := v.LcsClientExternalID.MarshalBER(ber.ChildEncodeOptions(opts, "lcsClientExternalID")...)
		if err != nil {
			return nil, fmt.Errorf("encoding lcsClientExternalID: %w", err)
		}
		retagged_enc_lcsclientexternalid, tagErr_enc_lcsclientexternalid := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_lcsclientexternalid)
		if tagErr_enc_lcsclientexternalid != nil {
			return nil, fmt.Errorf("encoding lcsClientExternalID: %w", tagErr_enc_lcsclientexternalid)
		}
		enc_lcsclientexternalid = retagged_enc_lcsclientexternalid
		children = append(children, enc_lcsclientexternalid...)
	}
	if v.LcsClientDialedByMS != nil {
		if len(*v.LcsClientDialedByMS) < 1 || len(*v.LcsClientDialedByMS) > 20 {
			if constraintErr := ber.CheckEncodedLength(opts, "lcsClientDialedByMS", "SIZE (1..20)", len(*v.LcsClientDialedByMS)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_lcsclientdialedbyms, encodeErr_enc_lcsclientdialedbyms := ber.EncodeOctetString([]byte(*v.LcsClientDialedByMS))
		if encodeErr_enc_lcsclientdialedbyms != nil {
			return nil, fmt.Errorf("encoding lcsClientDialedByMS: %w", encodeErr_enc_lcsclientdialedbyms)
		}
		retagged_enc_lcsclientdialedbyms, tagErr_enc_lcsclientdialedbyms := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_lcsclientdialedbyms)
		if tagErr_enc_lcsclientdialedbyms != nil {
			return nil, fmt.Errorf("encoding lcsClientDialedByMS: %w", tagErr_enc_lcsclientdialedbyms)
		}
		enc_lcsclientdialedbyms = retagged_enc_lcsclientdialedbyms
		children = append(children, enc_lcsclientdialedbyms...)
	}
	if v.LcsClientInternalID != nil {
		enc_lcsclientinternalid := ber.EncodeEnumerated(int64(*v.LcsClientInternalID))
		retagged_enc_lcsclientinternalid, tagErr_enc_lcsclientinternalid := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, enc_lcsclientinternalid)
		if tagErr_enc_lcsclientinternalid != nil {
			return nil, fmt.Errorf("encoding lcsClientInternalID: %w", tagErr_enc_lcsclientinternalid)
		}
		enc_lcsclientinternalid = retagged_enc_lcsclientinternalid
		children = append(children, enc_lcsclientinternalid...)
	}
	if v.LcsClientName != nil {
		enc_lcsclientname, err := v.LcsClientName.MarshalBER(ber.ChildEncodeOptions(opts, "lcsClientName")...)
		if err != nil {
			return nil, fmt.Errorf("encoding lcsClientName: %w", err)
		}
		retagged_enc_lcsclientname, tagErr_enc_lcsclientname := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, enc_lcsclientname)
		if tagErr_enc_lcsclientname != nil {
			return nil, fmt.Errorf("encoding lcsClientName: %w", tagErr_enc_lcsclientname)
		}
		enc_lcsclientname = retagged_enc_lcsclientname
		children = append(children, enc_lcsclientname...)
	}
	if v.LcsAPN != nil {
		if len(*v.LcsAPN) < 2 || len(*v.LcsAPN) > 63 {
			if constraintErr := ber.CheckEncodedLength(opts, "lcsAPN", "SIZE (2..63)", len(*v.LcsAPN)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_lcsapn, encodeErr_enc_lcsapn := ber.EncodeOctetString([]byte(*v.LcsAPN))
		if encodeErr_enc_lcsapn != nil {
			return nil, fmt.Errorf("encoding lcsAPN: %w", encodeErr_enc_lcsapn)
		}
		retagged_enc_lcsapn, tagErr_enc_lcsapn := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 5, enc_lcsapn)
		if tagErr_enc_lcsapn != nil {
			return nil, fmt.Errorf("encoding lcsAPN: %w", tagErr_enc_lcsapn)
		}
		enc_lcsapn = retagged_enc_lcsapn
		children = append(children, enc_lcsapn...)
	}
	if v.LcsRequestorID != nil {
		enc_lcsrequestorid, err := v.LcsRequestorID.MarshalBER(ber.ChildEncodeOptions(opts, "lcsRequestorID")...)
		if err != nil {
			return nil, fmt.Errorf("encoding lcsRequestorID: %w", err)
		}
		retagged_enc_lcsrequestorid, tagErr_enc_lcsrequestorid := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 6, enc_lcsrequestorid)
		if tagErr_enc_lcsrequestorid != nil {
			return nil, fmt.Errorf("encoding lcsRequestorID: %w", tagErr_enc_lcsrequestorid)
		}
		enc_lcsrequestorid = retagged_enc_lcsrequestorid
		children = append(children, enc_lcsrequestorid...)
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

// MarshalDER encodes LCSLCSClientID to DER format.
func (v *LCSLCSClientID) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: LCSLCSClientID receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	enc_lcsclienttype := ber.EncodeEnumerated(int64(v.LcsClientType))
	retagged_enc_lcsclienttype, tagErr_enc_lcsclienttype := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_lcsclienttype)
	if tagErr_enc_lcsclienttype != nil {
		return nil, fmt.Errorf("encoding lcsClientType: %w", tagErr_enc_lcsclienttype)
	}
	enc_lcsclienttype = retagged_enc_lcsclienttype
	children = append(children, enc_lcsclienttype...)
	if v.LcsClientExternalID != nil {
		enc_lcsclientexternalid, err := v.LcsClientExternalID.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding lcsClientExternalID: %w", err)
		}
		retagged_enc_lcsclientexternalid, tagErr_enc_lcsclientexternalid := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_lcsclientexternalid)
		if tagErr_enc_lcsclientexternalid != nil {
			return nil, fmt.Errorf("encoding lcsClientExternalID: %w", tagErr_enc_lcsclientexternalid)
		}
		enc_lcsclientexternalid = retagged_enc_lcsclientexternalid
		children = append(children, enc_lcsclientexternalid...)
	}
	if v.LcsClientDialedByMS != nil {
		if len(*v.LcsClientDialedByMS) < 1 || len(*v.LcsClientDialedByMS) > 20 {
			if constraintErr := ber.CheckEncodedLength(nil, "lcsClientDialedByMS", "SIZE (1..20)", len(*v.LcsClientDialedByMS)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_lcsclientdialedbyms, encodeErr_enc_lcsclientdialedbyms := ber.EncodeOctetString([]byte(*v.LcsClientDialedByMS))
		if encodeErr_enc_lcsclientdialedbyms != nil {
			return nil, fmt.Errorf("encoding lcsClientDialedByMS: %w", encodeErr_enc_lcsclientdialedbyms)
		}
		retagged_enc_lcsclientdialedbyms, tagErr_enc_lcsclientdialedbyms := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_lcsclientdialedbyms)
		if tagErr_enc_lcsclientdialedbyms != nil {
			return nil, fmt.Errorf("encoding lcsClientDialedByMS: %w", tagErr_enc_lcsclientdialedbyms)
		}
		enc_lcsclientdialedbyms = retagged_enc_lcsclientdialedbyms
		children = append(children, enc_lcsclientdialedbyms...)
	}
	if v.LcsClientInternalID != nil {
		enc_lcsclientinternalid := ber.EncodeEnumerated(int64(*v.LcsClientInternalID))
		retagged_enc_lcsclientinternalid, tagErr_enc_lcsclientinternalid := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, enc_lcsclientinternalid)
		if tagErr_enc_lcsclientinternalid != nil {
			return nil, fmt.Errorf("encoding lcsClientInternalID: %w", tagErr_enc_lcsclientinternalid)
		}
		enc_lcsclientinternalid = retagged_enc_lcsclientinternalid
		children = append(children, enc_lcsclientinternalid...)
	}
	if v.LcsClientName != nil {
		enc_lcsclientname, err := v.LcsClientName.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding lcsClientName: %w", err)
		}
		retagged_enc_lcsclientname, tagErr_enc_lcsclientname := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, enc_lcsclientname)
		if tagErr_enc_lcsclientname != nil {
			return nil, fmt.Errorf("encoding lcsClientName: %w", tagErr_enc_lcsclientname)
		}
		enc_lcsclientname = retagged_enc_lcsclientname
		children = append(children, enc_lcsclientname...)
	}
	if v.LcsAPN != nil {
		if len(*v.LcsAPN) < 2 || len(*v.LcsAPN) > 63 {
			if constraintErr := ber.CheckEncodedLength(nil, "lcsAPN", "SIZE (2..63)", len(*v.LcsAPN)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_lcsapn, encodeErr_enc_lcsapn := ber.EncodeOctetString([]byte(*v.LcsAPN))
		if encodeErr_enc_lcsapn != nil {
			return nil, fmt.Errorf("encoding lcsAPN: %w", encodeErr_enc_lcsapn)
		}
		retagged_enc_lcsapn, tagErr_enc_lcsapn := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 5, enc_lcsapn)
		if tagErr_enc_lcsapn != nil {
			return nil, fmt.Errorf("encoding lcsAPN: %w", tagErr_enc_lcsapn)
		}
		enc_lcsapn = retagged_enc_lcsapn
		children = append(children, enc_lcsapn...)
	}
	if v.LcsRequestorID != nil {
		enc_lcsrequestorid, err := v.LcsRequestorID.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding lcsRequestorID: %w", err)
		}
		retagged_enc_lcsrequestorid, tagErr_enc_lcsrequestorid := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 6, enc_lcsrequestorid)
		if tagErr_enc_lcsrequestorid != nil {
			return nil, fmt.Errorf("encoding lcsRequestorID: %w", tagErr_enc_lcsrequestorid)
		}
		enc_lcsrequestorid = retagged_enc_lcsrequestorid
		children = append(children, enc_lcsrequestorid...)
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
		return nil, fmt.Errorf("encoding LCSLCSClientID as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes LCSLCSClientID from BER/DER format.
func (v *LCSLCSClientID) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: LCSLCSClientID destination is nil", ber.ErrInvalidValue)
	}
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = LCSLCSClientID{}
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
		return fmt.Errorf("decoding LCSLCSClientID SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "LCSLCSClientID", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode lcsClientType
	if offset >= len(content) {
		return fmt.Errorf("missing required field lcsClientType")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 0 {
			return fmt.Errorf("expected tag [%s %d] for lcsClientType, got %s", "CONTEXT", 0, reqTag_)
		}
	}
	decodedTag_lcsclienttype, n_lcsclienttype, rawVal_lcsclienttype, err := ber.DecodeTLV(content[offset:], opts...)
	if err != nil {
		return fmt.Errorf("decoding lcsClientType: %w", err)
	}
	if decodedTag_lcsclienttype.Class != tag.ClassContextSpecific || decodedTag_lcsclienttype.Number != 0 || decodedTag_lcsclienttype.Constructed != false {
		return fmt.Errorf("decoding lcsClientType: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_lcsclienttype)
	}
	decVal_lcsclienttype, intErr := ber.DecodeEnumeratedValue(rawVal_lcsclienttype)
	if intErr != nil {
		return fmt.Errorf("decoding lcsClientType: %w", intErr)
	}
	v.LcsClientType = LCSLCSClientType(decVal_lcsclienttype)
	if offset < 0 || offset >
		len(content) || n_lcsclienttype < 0 || n_lcsclienttype >
		len(content[offset:]) {
		return fmt.Errorf("invalid BER content window")
	}

	offset += n_lcsclienttype
	// Decode lcsClientExternalID
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
				decodedTag_lcsclientexternalid, n_lcsclientexternalid, rawVal_lcsclientexternalid, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding lcsClientExternalID: %w", err)
				}
				if decodedTag_lcsclientexternalid.Class != tag.ClassContextSpecific || decodedTag_lcsclientexternalid.Number != 1 || decodedTag_lcsclientexternalid.Constructed != true {
					return fmt.Errorf("decoding lcsClientExternalID: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_lcsclientexternalid)
				}
				reconstructed_lcsclientexternalid, reconstructionErr_lcsclientexternalid := ber.EncodeSequence(rawVal_lcsclientexternalid)
				if reconstructionErr_lcsclientexternalid != nil {
					return fmt.Errorf("decoding lcsClientExternalID: %w", reconstructionErr_lcsclientexternalid)
				}
				var dec_lcsclientexternalid LCSClientExternalID3
				if unmErr := dec_lcsclientexternalid.UnmarshalBER(reconstructed_lcsclientexternalid, ber.ChildDecodeOptions(opts, "lcsClientExternalID")...); unmErr != nil {
					return fmt.Errorf("decoding lcsClientExternalID: %w", unmErr)
				}
				v.LcsClientExternalID = &dec_lcsclientexternalid
				if offset < 0 || offset >
					len(content) || n_lcsclientexternalid < 0 || n_lcsclientexternalid >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_lcsclientexternalid
			}
		}
	}
	// Decode lcsClientDialedByMS
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2 {
				decodedTag_lcsclientdialedbyms, n_lcsclientdialedbyms, rawVal_lcsclientdialedbyms, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding lcsClientDialedByMS: %w", err)
				}
				if decodedTag_lcsclientdialedbyms.Class != tag.ClassContextSpecific || decodedTag_lcsclientdialedbyms.Number != 2 {
					return fmt.Errorf("decoding lcsClientDialedByMS: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_lcsclientdialedbyms)
				}
				decVal_lcsclientdialedbyms, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_lcsclientdialedbyms.Constructed, rawVal_lcsclientdialedbyms, opts...)
				if octetErr != nil {
					return fmt.Errorf("decoding lcsClientDialedByMS: %w", octetErr)
				}
				tmp_lcsclientdialedbyms := AddressString3(decVal_lcsclientdialedbyms)
				v.LcsClientDialedByMS = &tmp_lcsclientdialedbyms
				if offset < 0 || offset >
					len(content) || n_lcsclientdialedbyms < 0 || n_lcsclientdialedbyms >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_lcsclientdialedbyms
				if len(*v.LcsClientDialedByMS) < 1 || len(*v.LcsClientDialedByMS) > 20 {
					if constraintErr := ber.CheckDecodedLength(opts, "lcsClientDialedByMS", "SIZE (1..20)", len(*v.LcsClientDialedByMS)); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode lcsClientInternalID
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3 {
				decodedTag_lcsclientinternalid, n_lcsclientinternalid, rawVal_lcsclientinternalid, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding lcsClientInternalID: %w", err)
				}
				if decodedTag_lcsclientinternalid.Class != tag.ClassContextSpecific || decodedTag_lcsclientinternalid.Number != 3 || decodedTag_lcsclientinternalid.Constructed != false {
					return fmt.Errorf("decoding lcsClientInternalID: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_lcsclientinternalid)
				}
				decVal_lcsclientinternalid, intErr := ber.DecodeEnumeratedValue(rawVal_lcsclientinternalid)
				if intErr != nil {
					return fmt.Errorf("decoding lcsClientInternalID: %w", intErr)
				}
				tmp_lcsclientinternalid := LCSClientInternalID3(decVal_lcsclientinternalid)
				v.LcsClientInternalID = &tmp_lcsclientinternalid
				if offset < 0 || offset >
					len(content) || n_lcsclientinternalid < 0 || n_lcsclientinternalid >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_lcsclientinternalid
			}
		}
	}
	// Decode lcsClientName
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4 {
				decodedTag_lcsclientname, n_lcsclientname, rawVal_lcsclientname, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding lcsClientName: %w", err)
				}
				if decodedTag_lcsclientname.Class != tag.ClassContextSpecific || decodedTag_lcsclientname.Number != 4 || decodedTag_lcsclientname.Constructed != true {
					return fmt.Errorf("decoding lcsClientName: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_lcsclientname)
				}
				reconstructed_lcsclientname, reconstructionErr_lcsclientname := ber.EncodeSequence(rawVal_lcsclientname)
				if reconstructionErr_lcsclientname != nil {
					return fmt.Errorf("decoding lcsClientName: %w", reconstructionErr_lcsclientname)
				}
				var dec_lcsclientname LCSLCSClientName
				if unmErr := dec_lcsclientname.UnmarshalBER(reconstructed_lcsclientname, ber.ChildDecodeOptions(opts, "lcsClientName")...); unmErr != nil {
					return fmt.Errorf("decoding lcsClientName: %w", unmErr)
				}
				v.LcsClientName = &dec_lcsclientname
				if offset < 0 || offset >
					len(content) || n_lcsclientname < 0 || n_lcsclientname >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_lcsclientname
			}
		}
	}
	// Decode lcsAPN
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 5 {
				decodedTag_lcsapn, n_lcsapn, rawVal_lcsapn, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding lcsAPN: %w", err)
				}
				if decodedTag_lcsapn.Class != tag.ClassContextSpecific || decodedTag_lcsapn.Number != 5 {
					return fmt.Errorf("decoding lcsAPN: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_lcsapn)
				}
				decVal_lcsapn, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_lcsapn.Constructed, rawVal_lcsapn, opts...)
				if octetErr != nil {
					return fmt.Errorf("decoding lcsAPN: %w", octetErr)
				}
				tmp_lcsapn := APN4(decVal_lcsapn)
				v.LcsAPN = &tmp_lcsapn
				if offset < 0 || offset >
					len(content) || n_lcsapn < 0 || n_lcsapn > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_lcsapn
				if len(*v.LcsAPN) < 2 || len(*v.LcsAPN) > 63 {
					if constraintErr := ber.CheckDecodedLength(opts, "lcsAPN", "SIZE (2..63)", len(*v.LcsAPN)); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode lcsRequestorID
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 6 {
				decodedTag_lcsrequestorid, n_lcsrequestorid, rawVal_lcsrequestorid, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding lcsRequestorID: %w", err)
				}
				if decodedTag_lcsrequestorid.Class != tag.ClassContextSpecific || decodedTag_lcsrequestorid.Number != 6 || decodedTag_lcsrequestorid.Constructed != true {
					return fmt.Errorf("decoding lcsRequestorID: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_lcsrequestorid)
				}
				reconstructed_lcsrequestorid, reconstructionErr_lcsrequestorid := ber.EncodeSequence(rawVal_lcsrequestorid)
				if reconstructionErr_lcsrequestorid != nil {
					return fmt.Errorf("decoding lcsRequestorID: %w", reconstructionErr_lcsrequestorid)
				}
				var dec_lcsrequestorid LCSLCSRequestorID
				if unmErr := dec_lcsrequestorid.UnmarshalBER(reconstructed_lcsrequestorid, ber.ChildDecodeOptions(opts, "lcsRequestorID")...); unmErr != nil {
					return fmt.Errorf("decoding lcsRequestorID: %w", unmErr)
				}
				v.LcsRequestorID = &dec_lcsrequestorid
				if offset < 0 || offset >
					len(content) || n_lcsrequestorid < 0 || n_lcsrequestorid >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_lcsrequestorid
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:], opts...)
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "LCSLCSClientID", Cause: extErr_}
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

// MarshalBER encodes LCSLCSClientName to BER format.
func (v *LCSLCSClientName) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: LCSLCSClientName receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *LCSLCSClientName) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if len(v.DataCodingScheme) < 1 || len(v.DataCodingScheme) > 1 {
		if constraintErr := ber.CheckEncodedLength(opts, "dataCodingScheme", "SIZE (1)", len(v.DataCodingScheme)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_datacodingscheme, encodeErr_enc_datacodingscheme := ber.EncodeOctetString([]byte(v.DataCodingScheme))
	if encodeErr_enc_datacodingscheme != nil {
		return nil, fmt.Errorf("encoding dataCodingScheme: %w", encodeErr_enc_datacodingscheme)
	}
	retagged_enc_datacodingscheme, tagErr_enc_datacodingscheme := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_datacodingscheme)
	if tagErr_enc_datacodingscheme != nil {
		return nil, fmt.Errorf("encoding dataCodingScheme: %w", tagErr_enc_datacodingscheme)
	}
	enc_datacodingscheme = retagged_enc_datacodingscheme
	children = append(children, enc_datacodingscheme...)
	if len(v.NameString) < 1 || len(v.NameString) > 63 {
		if constraintErr := ber.CheckEncodedLength(opts, "nameString", "SIZE (1..63)", len(v.NameString)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	if len(v.NameString) < 1 || len(v.NameString) > 160 {
		if constraintErr := ber.CheckEncodedLength(opts, "nameString", "SIZE (1..160)", len(v.NameString)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_namestring, encodeErr_enc_namestring := ber.EncodeOctetString([]byte(v.NameString))
	if encodeErr_enc_namestring != nil {
		return nil, fmt.Errorf("encoding nameString: %w", encodeErr_enc_namestring)
	}
	retagged_enc_namestring, tagErr_enc_namestring := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_namestring)
	if tagErr_enc_namestring != nil {
		return nil, fmt.Errorf("encoding nameString: %w", tagErr_enc_namestring)
	}
	enc_namestring = retagged_enc_namestring
	children = append(children, enc_namestring...)
	if v.LcsFormatIndicator != nil {
		enc_lcsformatindicator := ber.EncodeEnumerated(int64(*v.LcsFormatIndicator))
		retagged_enc_lcsformatindicator, tagErr_enc_lcsformatindicator := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, enc_lcsformatindicator)
		if tagErr_enc_lcsformatindicator != nil {
			return nil, fmt.Errorf("encoding lcs-FormatIndicator: %w", tagErr_enc_lcsformatindicator)
		}
		enc_lcsformatindicator = retagged_enc_lcsformatindicator
		children = append(children, enc_lcsformatindicator...)
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

// MarshalDER encodes LCSLCSClientName to DER format.
func (v *LCSLCSClientName) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: LCSLCSClientName receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if len(v.DataCodingScheme) < 1 || len(v.DataCodingScheme) > 1 {
		if constraintErr := ber.CheckEncodedLength(nil, "dataCodingScheme", "SIZE (1)", len(v.DataCodingScheme)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_datacodingscheme, encodeErr_enc_datacodingscheme := ber.EncodeOctetString([]byte(v.DataCodingScheme))
	if encodeErr_enc_datacodingscheme != nil {
		return nil, fmt.Errorf("encoding dataCodingScheme: %w", encodeErr_enc_datacodingscheme)
	}
	retagged_enc_datacodingscheme, tagErr_enc_datacodingscheme := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_datacodingscheme)
	if tagErr_enc_datacodingscheme != nil {
		return nil, fmt.Errorf("encoding dataCodingScheme: %w", tagErr_enc_datacodingscheme)
	}
	enc_datacodingscheme = retagged_enc_datacodingscheme
	children = append(children, enc_datacodingscheme...)
	if len(v.NameString) < 1 || len(v.NameString) > 63 {
		if constraintErr := ber.CheckEncodedLength(nil, "nameString", "SIZE (1..63)", len(v.NameString)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	if len(v.NameString) < 1 || len(v.NameString) > 160 {
		if constraintErr := ber.CheckEncodedLength(nil, "nameString", "SIZE (1..160)", len(v.NameString)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_namestring, encodeErr_enc_namestring := ber.EncodeOctetString([]byte(v.NameString))
	if encodeErr_enc_namestring != nil {
		return nil, fmt.Errorf("encoding nameString: %w", encodeErr_enc_namestring)
	}
	retagged_enc_namestring, tagErr_enc_namestring := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_namestring)
	if tagErr_enc_namestring != nil {
		return nil, fmt.Errorf("encoding nameString: %w", tagErr_enc_namestring)
	}
	enc_namestring = retagged_enc_namestring
	children = append(children, enc_namestring...)
	if v.LcsFormatIndicator != nil {
		enc_lcsformatindicator := ber.EncodeEnumerated(int64(*v.LcsFormatIndicator))
		retagged_enc_lcsformatindicator, tagErr_enc_lcsformatindicator := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, enc_lcsformatindicator)
		if tagErr_enc_lcsformatindicator != nil {
			return nil, fmt.Errorf("encoding lcs-FormatIndicator: %w", tagErr_enc_lcsformatindicator)
		}
		enc_lcsformatindicator = retagged_enc_lcsformatindicator
		children = append(children, enc_lcsformatindicator...)
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
		return nil, fmt.Errorf("encoding LCSLCSClientName as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes LCSLCSClientName from BER/DER format.
func (v *LCSLCSClientName) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: LCSLCSClientName destination is nil", ber.ErrInvalidValue)
	}
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = LCSLCSClientName{}
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
		return fmt.Errorf("decoding LCSLCSClientName SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "LCSLCSClientName", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode dataCodingScheme
	if offset >= len(content) {
		return fmt.Errorf("missing required field dataCodingScheme")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 0 {
			return fmt.Errorf("expected tag [%s %d] for dataCodingScheme, got %s", "CONTEXT", 0, reqTag_)
		}
	}
	decodedTag_datacodingscheme, n_datacodingscheme, rawVal_datacodingscheme, err := ber.DecodeTLV(content[offset:], opts...)
	if err != nil {
		return fmt.Errorf("decoding dataCodingScheme: %w", err)
	}
	if decodedTag_datacodingscheme.Class != tag.ClassContextSpecific || decodedTag_datacodingscheme.Number != 0 {
		return fmt.Errorf("decoding dataCodingScheme: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_datacodingscheme)
	}
	decVal_datacodingscheme, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_datacodingscheme.Constructed, rawVal_datacodingscheme, opts...)
	if octetErr != nil {
		return fmt.Errorf("decoding dataCodingScheme: %w", octetErr)
	}
	v.DataCodingScheme = USSDDataCodingScheme3(decVal_datacodingscheme)
	if offset < 0 || offset >
		len(content) || n_datacodingscheme < 0 || n_datacodingscheme >
		len(content[offset:]) {
		return fmt.Errorf("invalid BER content window")
	}

	offset += n_datacodingscheme
	if len(v.DataCodingScheme) < 1 || len(v.DataCodingScheme) > 1 {
		if constraintErr := ber.CheckDecodedLength(opts, "dataCodingScheme", "SIZE (1)", len(v.DataCodingScheme)); constraintErr != nil {
			return constraintErr
		}
	}
	// Decode nameString
	if offset >= len(content) {
		return fmt.Errorf("missing required field nameString")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 2 {
			return fmt.Errorf("expected tag [%s %d] for nameString, got %s", "CONTEXT", 2, reqTag_)
		}
	}
	decodedTag_namestring, n_namestring, rawVal_namestring, err := ber.DecodeTLV(content[offset:], opts...)
	if err != nil {
		return fmt.Errorf("decoding nameString: %w", err)
	}
	if decodedTag_namestring.Class != tag.ClassContextSpecific || decodedTag_namestring.Number != 2 {
		return fmt.Errorf("decoding nameString: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_namestring)
	}
	decVal_namestring, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_namestring.Constructed, rawVal_namestring, opts...)
	if octetErr != nil {
		return fmt.Errorf("decoding nameString: %w", octetErr)
	}
	v.NameString = LCSNameString(decVal_namestring)
	if offset < 0 || offset >
		len(content) || n_namestring < 0 || n_namestring > len(content[offset:]) {
		return fmt.Errorf("invalid BER content window")
	}

	offset += n_namestring
	if len(v.NameString) < 1 || len(v.NameString) > 63 {
		if constraintErr := ber.CheckDecodedLength(opts, "nameString", "SIZE (1..63)", len(v.NameString)); constraintErr != nil {
			return constraintErr
		}
	}
	if len(v.NameString) < 1 || len(v.NameString) > 160 {
		if constraintErr := ber.CheckDecodedLength(opts, "nameString", "SIZE (1..160)", len(v.NameString)); constraintErr != nil {
			return constraintErr
		}
	}
	// Decode lcs-FormatIndicator
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3 {
				decodedTag_lcsformatindicator, n_lcsformatindicator, rawVal_lcsformatindicator, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding lcs-FormatIndicator: %w", err)
				}
				if decodedTag_lcsformatindicator.Class != tag.ClassContextSpecific || decodedTag_lcsformatindicator.Number != 3 || decodedTag_lcsformatindicator.Constructed != false {
					return fmt.Errorf("decoding lcs-FormatIndicator: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_lcsformatindicator)
				}
				decVal_lcsformatindicator, intErr := ber.DecodeEnumeratedValue(rawVal_lcsformatindicator)
				if intErr != nil {
					return fmt.Errorf("decoding lcs-FormatIndicator: %w", intErr)
				}
				tmp_lcsformatindicator := LCSLCSFormatIndicator(decVal_lcsformatindicator)
				v.LcsFormatIndicator = &tmp_lcsformatindicator
				if offset < 0 || offset >
					len(content) || n_lcsformatindicator < 0 || n_lcsformatindicator >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_lcsformatindicator
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:], opts...)
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "LCSLCSClientName", Cause: extErr_}
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

// MarshalBER encodes LCSLCSRequestorID to BER format.
func (v *LCSLCSRequestorID) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: LCSLCSRequestorID receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *LCSLCSRequestorID) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if len(v.DataCodingScheme) < 1 || len(v.DataCodingScheme) > 1 {
		if constraintErr := ber.CheckEncodedLength(opts, "dataCodingScheme", "SIZE (1)", len(v.DataCodingScheme)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_datacodingscheme, encodeErr_enc_datacodingscheme := ber.EncodeOctetString([]byte(v.DataCodingScheme))
	if encodeErr_enc_datacodingscheme != nil {
		return nil, fmt.Errorf("encoding dataCodingScheme: %w", encodeErr_enc_datacodingscheme)
	}
	retagged_enc_datacodingscheme, tagErr_enc_datacodingscheme := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_datacodingscheme)
	if tagErr_enc_datacodingscheme != nil {
		return nil, fmt.Errorf("encoding dataCodingScheme: %w", tagErr_enc_datacodingscheme)
	}
	enc_datacodingscheme = retagged_enc_datacodingscheme
	children = append(children, enc_datacodingscheme...)
	if len(v.RequestorIDString) < 1 || len(v.RequestorIDString) > 63 {
		if constraintErr := ber.CheckEncodedLength(opts, "requestorIDString", "SIZE (1..63)", len(v.RequestorIDString)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	if len(v.RequestorIDString) < 1 || len(v.RequestorIDString) > 160 {
		if constraintErr := ber.CheckEncodedLength(opts, "requestorIDString", "SIZE (1..160)", len(v.RequestorIDString)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_requestoridstring, encodeErr_enc_requestoridstring := ber.EncodeOctetString([]byte(v.RequestorIDString))
	if encodeErr_enc_requestoridstring != nil {
		return nil, fmt.Errorf("encoding requestorIDString: %w", encodeErr_enc_requestoridstring)
	}
	retagged_enc_requestoridstring, tagErr_enc_requestoridstring := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_requestoridstring)
	if tagErr_enc_requestoridstring != nil {
		return nil, fmt.Errorf("encoding requestorIDString: %w", tagErr_enc_requestoridstring)
	}
	enc_requestoridstring = retagged_enc_requestoridstring
	children = append(children, enc_requestoridstring...)
	if v.LcsFormatIndicator != nil {
		enc_lcsformatindicator := ber.EncodeEnumerated(int64(*v.LcsFormatIndicator))
		retagged_enc_lcsformatindicator, tagErr_enc_lcsformatindicator := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_lcsformatindicator)
		if tagErr_enc_lcsformatindicator != nil {
			return nil, fmt.Errorf("encoding lcs-FormatIndicator: %w", tagErr_enc_lcsformatindicator)
		}
		enc_lcsformatindicator = retagged_enc_lcsformatindicator
		children = append(children, enc_lcsformatindicator...)
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

// MarshalDER encodes LCSLCSRequestorID to DER format.
func (v *LCSLCSRequestorID) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: LCSLCSRequestorID receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if len(v.DataCodingScheme) < 1 || len(v.DataCodingScheme) > 1 {
		if constraintErr := ber.CheckEncodedLength(nil, "dataCodingScheme", "SIZE (1)", len(v.DataCodingScheme)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_datacodingscheme, encodeErr_enc_datacodingscheme := ber.EncodeOctetString([]byte(v.DataCodingScheme))
	if encodeErr_enc_datacodingscheme != nil {
		return nil, fmt.Errorf("encoding dataCodingScheme: %w", encodeErr_enc_datacodingscheme)
	}
	retagged_enc_datacodingscheme, tagErr_enc_datacodingscheme := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_datacodingscheme)
	if tagErr_enc_datacodingscheme != nil {
		return nil, fmt.Errorf("encoding dataCodingScheme: %w", tagErr_enc_datacodingscheme)
	}
	enc_datacodingscheme = retagged_enc_datacodingscheme
	children = append(children, enc_datacodingscheme...)
	if len(v.RequestorIDString) < 1 || len(v.RequestorIDString) > 63 {
		if constraintErr := ber.CheckEncodedLength(nil, "requestorIDString", "SIZE (1..63)", len(v.RequestorIDString)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	if len(v.RequestorIDString) < 1 || len(v.RequestorIDString) > 160 {
		if constraintErr := ber.CheckEncodedLength(nil, "requestorIDString", "SIZE (1..160)", len(v.RequestorIDString)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_requestoridstring, encodeErr_enc_requestoridstring := ber.EncodeOctetString([]byte(v.RequestorIDString))
	if encodeErr_enc_requestoridstring != nil {
		return nil, fmt.Errorf("encoding requestorIDString: %w", encodeErr_enc_requestoridstring)
	}
	retagged_enc_requestoridstring, tagErr_enc_requestoridstring := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_requestoridstring)
	if tagErr_enc_requestoridstring != nil {
		return nil, fmt.Errorf("encoding requestorIDString: %w", tagErr_enc_requestoridstring)
	}
	enc_requestoridstring = retagged_enc_requestoridstring
	children = append(children, enc_requestoridstring...)
	if v.LcsFormatIndicator != nil {
		enc_lcsformatindicator := ber.EncodeEnumerated(int64(*v.LcsFormatIndicator))
		retagged_enc_lcsformatindicator, tagErr_enc_lcsformatindicator := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_lcsformatindicator)
		if tagErr_enc_lcsformatindicator != nil {
			return nil, fmt.Errorf("encoding lcs-FormatIndicator: %w", tagErr_enc_lcsformatindicator)
		}
		enc_lcsformatindicator = retagged_enc_lcsformatindicator
		children = append(children, enc_lcsformatindicator...)
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
		return nil, fmt.Errorf("encoding LCSLCSRequestorID as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes LCSLCSRequestorID from BER/DER format.
func (v *LCSLCSRequestorID) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: LCSLCSRequestorID destination is nil", ber.ErrInvalidValue)
	}
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = LCSLCSRequestorID{}
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
		return fmt.Errorf("decoding LCSLCSRequestorID SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "LCSLCSRequestorID", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode dataCodingScheme
	if offset >= len(content) {
		return fmt.Errorf("missing required field dataCodingScheme")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 0 {
			return fmt.Errorf("expected tag [%s %d] for dataCodingScheme, got %s", "CONTEXT", 0, reqTag_)
		}
	}
	decodedTag_datacodingscheme, n_datacodingscheme, rawVal_datacodingscheme, err := ber.DecodeTLV(content[offset:], opts...)
	if err != nil {
		return fmt.Errorf("decoding dataCodingScheme: %w", err)
	}
	if decodedTag_datacodingscheme.Class != tag.ClassContextSpecific || decodedTag_datacodingscheme.Number != 0 {
		return fmt.Errorf("decoding dataCodingScheme: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_datacodingscheme)
	}
	decVal_datacodingscheme, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_datacodingscheme.Constructed, rawVal_datacodingscheme, opts...)
	if octetErr != nil {
		return fmt.Errorf("decoding dataCodingScheme: %w", octetErr)
	}
	v.DataCodingScheme = USSDDataCodingScheme3(decVal_datacodingscheme)
	if offset < 0 || offset >
		len(content) || n_datacodingscheme < 0 || n_datacodingscheme >
		len(content[offset:]) {
		return fmt.Errorf("invalid BER content window")
	}

	offset += n_datacodingscheme
	if len(v.DataCodingScheme) < 1 || len(v.DataCodingScheme) > 1 {
		if constraintErr := ber.CheckDecodedLength(opts, "dataCodingScheme", "SIZE (1)", len(v.DataCodingScheme)); constraintErr != nil {
			return constraintErr
		}
	}
	// Decode requestorIDString
	if offset >= len(content) {
		return fmt.Errorf("missing required field requestorIDString")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 1 {
			return fmt.Errorf("expected tag [%s %d] for requestorIDString, got %s", "CONTEXT", 1, reqTag_)
		}
	}
	decodedTag_requestoridstring, n_requestoridstring, rawVal_requestoridstring, err := ber.DecodeTLV(content[offset:], opts...)
	if err != nil {
		return fmt.Errorf("decoding requestorIDString: %w", err)
	}
	if decodedTag_requestoridstring.Class != tag.ClassContextSpecific || decodedTag_requestoridstring.Number != 1 {
		return fmt.Errorf("decoding requestorIDString: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_requestoridstring)
	}
	decVal_requestoridstring, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_requestoridstring.Constructed, rawVal_requestoridstring, opts...)
	if octetErr != nil {
		return fmt.Errorf("decoding requestorIDString: %w", octetErr)
	}
	v.RequestorIDString = LCSRequestorIDString(decVal_requestoridstring)
	if offset < 0 || offset >
		len(content) || n_requestoridstring < 0 || n_requestoridstring >
		len(content[offset:]) {
		return fmt.Errorf("invalid BER content window")
	}

	offset += n_requestoridstring
	if len(v.RequestorIDString) < 1 || len(v.RequestorIDString) > 63 {
		if constraintErr := ber.CheckDecodedLength(opts, "requestorIDString", "SIZE (1..63)", len(v.RequestorIDString)); constraintErr != nil {
			return constraintErr
		}
	}
	if len(v.RequestorIDString) < 1 || len(v.RequestorIDString) > 160 {
		if constraintErr := ber.CheckDecodedLength(opts, "requestorIDString", "SIZE (1..160)", len(v.RequestorIDString)); constraintErr != nil {
			return constraintErr
		}
	}
	// Decode lcs-FormatIndicator
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2 {
				decodedTag_lcsformatindicator, n_lcsformatindicator, rawVal_lcsformatindicator, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding lcs-FormatIndicator: %w", err)
				}
				if decodedTag_lcsformatindicator.Class != tag.ClassContextSpecific || decodedTag_lcsformatindicator.Number != 2 || decodedTag_lcsformatindicator.Constructed != false {
					return fmt.Errorf("decoding lcs-FormatIndicator: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_lcsformatindicator)
				}
				decVal_lcsformatindicator, intErr := ber.DecodeEnumeratedValue(rawVal_lcsformatindicator)
				if intErr != nil {
					return fmt.Errorf("decoding lcs-FormatIndicator: %w", intErr)
				}
				tmp_lcsformatindicator := LCSLCSFormatIndicator(decVal_lcsformatindicator)
				v.LcsFormatIndicator = &tmp_lcsformatindicator
				if offset < 0 || offset >
					len(content) || n_lcsformatindicator < 0 || n_lcsformatindicator >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_lcsformatindicator
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:], opts...)
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "LCSLCSRequestorID", Cause: extErr_}
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

// MarshalBER encodes LCSLCSQoS to BER format.
func (v *LCSLCSQoS) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: LCSLCSQoS receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *LCSLCSQoS) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if v.HorizontalAccuracy != nil {
		if len(*v.HorizontalAccuracy) < 1 || len(*v.HorizontalAccuracy) > 1 {
			if constraintErr := ber.CheckEncodedLength(opts, "horizontal-accuracy", "SIZE (1)", len(*v.HorizontalAccuracy)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_horizontalaccuracy, encodeErr_enc_horizontalaccuracy := ber.EncodeOctetString([]byte(*v.HorizontalAccuracy))
		if encodeErr_enc_horizontalaccuracy != nil {
			return nil, fmt.Errorf("encoding horizontal-accuracy: %w", encodeErr_enc_horizontalaccuracy)
		}
		retagged_enc_horizontalaccuracy, tagErr_enc_horizontalaccuracy := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_horizontalaccuracy)
		if tagErr_enc_horizontalaccuracy != nil {
			return nil, fmt.Errorf("encoding horizontal-accuracy: %w", tagErr_enc_horizontalaccuracy)
		}
		enc_horizontalaccuracy = retagged_enc_horizontalaccuracy
		children = append(children, enc_horizontalaccuracy...)
	}
	if v.VerticalCoordinateRequest != nil {
		enc_verticalcoordinaterequest := ber.EncodeNull()
		retagged_enc_verticalcoordinaterequest, tagErr_enc_verticalcoordinaterequest := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_verticalcoordinaterequest)
		if tagErr_enc_verticalcoordinaterequest != nil {
			return nil, fmt.Errorf("encoding verticalCoordinateRequest: %w", tagErr_enc_verticalcoordinaterequest)
		}
		enc_verticalcoordinaterequest = retagged_enc_verticalcoordinaterequest
		children = append(children, enc_verticalcoordinaterequest...)
	}
	if v.VerticalAccuracy != nil {
		if len(*v.VerticalAccuracy) < 1 || len(*v.VerticalAccuracy) > 1 {
			if constraintErr := ber.CheckEncodedLength(opts, "vertical-accuracy", "SIZE (1)", len(*v.VerticalAccuracy)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_verticalaccuracy, encodeErr_enc_verticalaccuracy := ber.EncodeOctetString([]byte(*v.VerticalAccuracy))
		if encodeErr_enc_verticalaccuracy != nil {
			return nil, fmt.Errorf("encoding vertical-accuracy: %w", encodeErr_enc_verticalaccuracy)
		}
		retagged_enc_verticalaccuracy, tagErr_enc_verticalaccuracy := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_verticalaccuracy)
		if tagErr_enc_verticalaccuracy != nil {
			return nil, fmt.Errorf("encoding vertical-accuracy: %w", tagErr_enc_verticalaccuracy)
		}
		enc_verticalaccuracy = retagged_enc_verticalaccuracy
		children = append(children, enc_verticalaccuracy...)
	}
	if v.ResponseTime != nil {
		enc_responsetime, err := v.ResponseTime.MarshalBER(ber.ChildEncodeOptions(opts, "responseTime")...)
		if err != nil {
			return nil, fmt.Errorf("encoding responseTime: %w", err)
		}
		retagged_enc_responsetime, tagErr_enc_responsetime := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, enc_responsetime)
		if tagErr_enc_responsetime != nil {
			return nil, fmt.Errorf("encoding responseTime: %w", tagErr_enc_responsetime)
		}
		enc_responsetime = retagged_enc_responsetime
		children = append(children, enc_responsetime...)
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
	if v.VelocityRequest != nil {
		enc_velocityrequest := ber.EncodeNull()
		retagged_enc_velocityrequest, tagErr_enc_velocityrequest := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 5, enc_velocityrequest)
		if tagErr_enc_velocityrequest != nil {
			return nil, fmt.Errorf("encoding velocityRequest: %w", tagErr_enc_velocityrequest)
		}
		enc_velocityrequest = retagged_enc_velocityrequest
		children = append(children, enc_velocityrequest...)
	}
	if v.LcsQosClass != nil {
		enc_lcsqosclass := ber.EncodeEnumerated(int64(*v.LcsQosClass))
		retagged_enc_lcsqosclass, tagErr_enc_lcsqosclass := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 6, enc_lcsqosclass)
		if tagErr_enc_lcsqosclass != nil {
			return nil, fmt.Errorf("encoding lcs-qos-class: %w", tagErr_enc_lcsqosclass)
		}
		enc_lcsqosclass = retagged_enc_lcsqosclass
		children = append(children, enc_lcsqosclass...)
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

// MarshalDER encodes LCSLCSQoS to DER format.
func (v *LCSLCSQoS) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: LCSLCSQoS receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if v.HorizontalAccuracy != nil {
		if len(*v.HorizontalAccuracy) < 1 || len(*v.HorizontalAccuracy) > 1 {
			if constraintErr := ber.CheckEncodedLength(nil, "horizontal-accuracy", "SIZE (1)", len(*v.HorizontalAccuracy)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_horizontalaccuracy, encodeErr_enc_horizontalaccuracy := ber.EncodeOctetString([]byte(*v.HorizontalAccuracy))
		if encodeErr_enc_horizontalaccuracy != nil {
			return nil, fmt.Errorf("encoding horizontal-accuracy: %w", encodeErr_enc_horizontalaccuracy)
		}
		retagged_enc_horizontalaccuracy, tagErr_enc_horizontalaccuracy := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_horizontalaccuracy)
		if tagErr_enc_horizontalaccuracy != nil {
			return nil, fmt.Errorf("encoding horizontal-accuracy: %w", tagErr_enc_horizontalaccuracy)
		}
		enc_horizontalaccuracy = retagged_enc_horizontalaccuracy
		children = append(children, enc_horizontalaccuracy...)
	}
	if v.VerticalCoordinateRequest != nil {
		enc_verticalcoordinaterequest := ber.EncodeNull()
		retagged_enc_verticalcoordinaterequest, tagErr_enc_verticalcoordinaterequest := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_verticalcoordinaterequest)
		if tagErr_enc_verticalcoordinaterequest != nil {
			return nil, fmt.Errorf("encoding verticalCoordinateRequest: %w", tagErr_enc_verticalcoordinaterequest)
		}
		enc_verticalcoordinaterequest = retagged_enc_verticalcoordinaterequest
		children = append(children, enc_verticalcoordinaterequest...)
	}
	if v.VerticalAccuracy != nil {
		if len(*v.VerticalAccuracy) < 1 || len(*v.VerticalAccuracy) > 1 {
			if constraintErr := ber.CheckEncodedLength(nil, "vertical-accuracy", "SIZE (1)", len(*v.VerticalAccuracy)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_verticalaccuracy, encodeErr_enc_verticalaccuracy := ber.EncodeOctetString([]byte(*v.VerticalAccuracy))
		if encodeErr_enc_verticalaccuracy != nil {
			return nil, fmt.Errorf("encoding vertical-accuracy: %w", encodeErr_enc_verticalaccuracy)
		}
		retagged_enc_verticalaccuracy, tagErr_enc_verticalaccuracy := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_verticalaccuracy)
		if tagErr_enc_verticalaccuracy != nil {
			return nil, fmt.Errorf("encoding vertical-accuracy: %w", tagErr_enc_verticalaccuracy)
		}
		enc_verticalaccuracy = retagged_enc_verticalaccuracy
		children = append(children, enc_verticalaccuracy...)
	}
	if v.ResponseTime != nil {
		enc_responsetime, err := v.ResponseTime.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding responseTime: %w", err)
		}
		retagged_enc_responsetime, tagErr_enc_responsetime := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, enc_responsetime)
		if tagErr_enc_responsetime != nil {
			return nil, fmt.Errorf("encoding responseTime: %w", tagErr_enc_responsetime)
		}
		enc_responsetime = retagged_enc_responsetime
		children = append(children, enc_responsetime...)
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
	if v.VelocityRequest != nil {
		enc_velocityrequest := ber.EncodeNull()
		retagged_enc_velocityrequest, tagErr_enc_velocityrequest := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 5, enc_velocityrequest)
		if tagErr_enc_velocityrequest != nil {
			return nil, fmt.Errorf("encoding velocityRequest: %w", tagErr_enc_velocityrequest)
		}
		enc_velocityrequest = retagged_enc_velocityrequest
		children = append(children, enc_velocityrequest...)
	}
	if v.LcsQosClass != nil {
		enc_lcsqosclass := ber.EncodeEnumerated(int64(*v.LcsQosClass))
		retagged_enc_lcsqosclass, tagErr_enc_lcsqosclass := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 6, enc_lcsqosclass)
		if tagErr_enc_lcsqosclass != nil {
			return nil, fmt.Errorf("encoding lcs-qos-class: %w", tagErr_enc_lcsqosclass)
		}
		enc_lcsqosclass = retagged_enc_lcsqosclass
		children = append(children, enc_lcsqosclass...)
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
		return nil, fmt.Errorf("encoding LCSLCSQoS as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes LCSLCSQoS from BER/DER format.
func (v *LCSLCSQoS) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: LCSLCSQoS destination is nil", ber.ErrInvalidValue)
	}
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = LCSLCSQoS{}
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
		return fmt.Errorf("decoding LCSLCSQoS SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "LCSLCSQoS", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode horizontal-accuracy
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
				decodedTag_horizontalaccuracy, n_horizontalaccuracy, rawVal_horizontalaccuracy, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding horizontal-accuracy: %w", err)
				}
				if decodedTag_horizontalaccuracy.Class != tag.ClassContextSpecific || decodedTag_horizontalaccuracy.Number != 0 {
					return fmt.Errorf("decoding horizontal-accuracy: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_horizontalaccuracy)
				}
				decVal_horizontalaccuracy, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_horizontalaccuracy.Constructed, rawVal_horizontalaccuracy, opts...)
				if octetErr != nil {
					return fmt.Errorf("decoding horizontal-accuracy: %w", octetErr)
				}
				tmp_horizontalaccuracy := LCSHorizontalAccuracy(decVal_horizontalaccuracy)
				v.HorizontalAccuracy = &tmp_horizontalaccuracy
				if offset < 0 || offset >
					len(content) || n_horizontalaccuracy < 0 || n_horizontalaccuracy >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_horizontalaccuracy
				if len(*v.HorizontalAccuracy) < 1 || len(*v.HorizontalAccuracy) > 1 {
					if constraintErr := ber.CheckDecodedLength(opts, "horizontal-accuracy", "SIZE (1)", len(*v.HorizontalAccuracy)); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode verticalCoordinateRequest
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
				decodedTag_verticalcoordinaterequest, n_verticalcoordinaterequest, rawVal_verticalcoordinaterequest, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding verticalCoordinateRequest: %w", err)
				}
				if decodedTag_verticalcoordinaterequest.Class != tag.ClassContextSpecific || decodedTag_verticalcoordinaterequest.Number != 1 || decodedTag_verticalcoordinaterequest.Constructed != false {
					return fmt.Errorf("decoding verticalCoordinateRequest: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_verticalcoordinaterequest)
				}
				if len(rawVal_verticalcoordinaterequest) != 0 {
					return fmt.Errorf("decoding verticalCoordinateRequest: %w: NULL content length %d", ber.ErrInvalidValue, len(rawVal_verticalcoordinaterequest))
				}
				v.VerticalCoordinateRequest = &struct{}{}
				if offset < 0 || offset >
					len(content) || n_verticalcoordinaterequest < 0 ||
					n_verticalcoordinaterequest > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_verticalcoordinaterequest
			}
		}
	}
	// Decode vertical-accuracy
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2 {
				decodedTag_verticalaccuracy, n_verticalaccuracy, rawVal_verticalaccuracy, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding vertical-accuracy: %w", err)
				}
				if decodedTag_verticalaccuracy.Class != tag.ClassContextSpecific || decodedTag_verticalaccuracy.Number != 2 {
					return fmt.Errorf("decoding vertical-accuracy: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_verticalaccuracy)
				}
				decVal_verticalaccuracy, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_verticalaccuracy.Constructed, rawVal_verticalaccuracy, opts...)
				if octetErr != nil {
					return fmt.Errorf("decoding vertical-accuracy: %w", octetErr)
				}
				tmp_verticalaccuracy := LCSVerticalAccuracy(decVal_verticalaccuracy)
				v.VerticalAccuracy = &tmp_verticalaccuracy
				if offset < 0 || offset >
					len(content) || n_verticalaccuracy < 0 || n_verticalaccuracy >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_verticalaccuracy
				if len(*v.VerticalAccuracy) < 1 || len(*v.VerticalAccuracy) > 1 {
					if constraintErr := ber.CheckDecodedLength(opts, "vertical-accuracy", "SIZE (1)", len(*v.VerticalAccuracy)); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode responseTime
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3 {
				decodedTag_responsetime, n_responsetime, rawVal_responsetime, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding responseTime: %w", err)
				}
				if decodedTag_responsetime.Class != tag.ClassContextSpecific || decodedTag_responsetime.Number != 3 || decodedTag_responsetime.Constructed != true {
					return fmt.Errorf("decoding responseTime: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_responsetime)
				}
				reconstructed_responsetime, reconstructionErr_responsetime := ber.EncodeSequence(rawVal_responsetime)
				if reconstructionErr_responsetime != nil {
					return fmt.Errorf("decoding responseTime: %w", reconstructionErr_responsetime)
				}
				var dec_responsetime LCSResponseTime
				if unmErr := dec_responsetime.UnmarshalBER(reconstructed_responsetime, ber.ChildDecodeOptions(opts, "responseTime")...); unmErr != nil {
					return fmt.Errorf("decoding responseTime: %w", unmErr)
				}
				v.ResponseTime = &dec_responsetime
				if offset < 0 || offset >
					len(content) || n_responsetime < 0 || n_responsetime >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_responsetime
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
				var dec_extensioncontainer ExtensionContainer3
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
	// Decode velocityRequest
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 5 {
				decodedTag_velocityrequest, n_velocityrequest, rawVal_velocityrequest, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding velocityRequest: %w", err)
				}
				if decodedTag_velocityrequest.Class != tag.ClassContextSpecific || decodedTag_velocityrequest.Number != 5 || decodedTag_velocityrequest.Constructed != false {
					return fmt.Errorf("decoding velocityRequest: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_velocityrequest)
				}
				if len(rawVal_velocityrequest) != 0 {
					return fmt.Errorf("decoding velocityRequest: %w: NULL content length %d", ber.ErrInvalidValue, len(rawVal_velocityrequest))
				}
				v.VelocityRequest = &struct{}{}
				if offset < 0 || offset >
					len(content) || n_velocityrequest < 0 || n_velocityrequest >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_velocityrequest
			}
		}
	}
	// Decode lcs-qos-class
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 6 {
				decodedTag_lcsqosclass, n_lcsqosclass, rawVal_lcsqosclass, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding lcs-qos-class: %w", err)
				}
				if decodedTag_lcsqosclass.Class != tag.ClassContextSpecific || decodedTag_lcsqosclass.Number != 6 || decodedTag_lcsqosclass.Constructed != false {
					return fmt.Errorf("decoding lcs-qos-class: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_lcsqosclass)
				}
				decVal_lcsqosclass, intErr := ber.DecodeEnumeratedValue(rawVal_lcsqosclass)
				if intErr != nil {
					return fmt.Errorf("decoding lcs-qos-class: %w", intErr)
				}
				tmp_lcsqosclass := LCSLCSQoSClass(decVal_lcsqosclass)
				v.LcsQosClass = &tmp_lcsqosclass
				if offset < 0 || offset >
					len(content) || n_lcsqosclass < 0 || n_lcsqosclass >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_lcsqosclass
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:], opts...)
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "LCSLCSQoS", Cause: extErr_}
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

// MarshalBER encodes LCSResponseTime to BER format.
func (v *LCSResponseTime) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: LCSResponseTime receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *LCSResponseTime) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	enc_responsetimecategory := ber.EncodeEnumerated(int64(v.ResponseTimeCategory))
	children = append(children, enc_responsetimecategory...)
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

// MarshalDER encodes LCSResponseTime to DER format.
func (v *LCSResponseTime) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: LCSResponseTime receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	enc_responsetimecategory := ber.EncodeEnumerated(int64(v.ResponseTimeCategory))
	children = append(children, enc_responsetimecategory...)
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
		return nil, fmt.Errorf("encoding LCSResponseTime as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes LCSResponseTime from BER/DER format.
func (v *LCSResponseTime) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: LCSResponseTime destination is nil", ber.ErrInvalidValue)
	}
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = LCSResponseTime{}
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
		return fmt.Errorf("decoding LCSResponseTime SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "LCSResponseTime", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode responseTimeCategory
	if offset >= len(content) {
		return fmt.Errorf("missing required field responseTimeCategory")
	}
	val_responsetimecategory, n, err := ber.DecodeEnumerated(content[offset:], opts...)
	if err != nil {
		return fmt.Errorf("decoding responseTimeCategory: %w", err)
	}
	v.ResponseTimeCategory = LCSResponseTimeCategory(val_responsetimecategory)
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
			return &ber.DecodeError{Offset: offset, TypeName: "LCSResponseTime", Cause: extErr_}
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

// MarshalBER encodes LCSLCSCodeword to BER format.
func (v *LCSLCSCodeword) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: LCSLCSCodeword receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *LCSLCSCodeword) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if len(v.DataCodingScheme) < 1 || len(v.DataCodingScheme) > 1 {
		if constraintErr := ber.CheckEncodedLength(opts, "dataCodingScheme", "SIZE (1)", len(v.DataCodingScheme)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_datacodingscheme, encodeErr_enc_datacodingscheme := ber.EncodeOctetString([]byte(v.DataCodingScheme))
	if encodeErr_enc_datacodingscheme != nil {
		return nil, fmt.Errorf("encoding dataCodingScheme: %w", encodeErr_enc_datacodingscheme)
	}
	retagged_enc_datacodingscheme, tagErr_enc_datacodingscheme := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_datacodingscheme)
	if tagErr_enc_datacodingscheme != nil {
		return nil, fmt.Errorf("encoding dataCodingScheme: %w", tagErr_enc_datacodingscheme)
	}
	enc_datacodingscheme = retagged_enc_datacodingscheme
	children = append(children, enc_datacodingscheme...)
	if len(v.LcsCodewordString) < 1 || len(v.LcsCodewordString) > 20 {
		if constraintErr := ber.CheckEncodedLength(opts, "lcsCodewordString", "SIZE (1..20)", len(v.LcsCodewordString)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	if len(v.LcsCodewordString) < 1 || len(v.LcsCodewordString) > 160 {
		if constraintErr := ber.CheckEncodedLength(opts, "lcsCodewordString", "SIZE (1..160)", len(v.LcsCodewordString)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_lcscodewordstring, encodeErr_enc_lcscodewordstring := ber.EncodeOctetString([]byte(v.LcsCodewordString))
	if encodeErr_enc_lcscodewordstring != nil {
		return nil, fmt.Errorf("encoding lcsCodewordString: %w", encodeErr_enc_lcscodewordstring)
	}
	retagged_enc_lcscodewordstring, tagErr_enc_lcscodewordstring := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_lcscodewordstring)
	if tagErr_enc_lcscodewordstring != nil {
		return nil, fmt.Errorf("encoding lcsCodewordString: %w", tagErr_enc_lcscodewordstring)
	}
	enc_lcscodewordstring = retagged_enc_lcscodewordstring
	children = append(children, enc_lcscodewordstring...)
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

// MarshalDER encodes LCSLCSCodeword to DER format.
func (v *LCSLCSCodeword) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: LCSLCSCodeword receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if len(v.DataCodingScheme) < 1 || len(v.DataCodingScheme) > 1 {
		if constraintErr := ber.CheckEncodedLength(nil, "dataCodingScheme", "SIZE (1)", len(v.DataCodingScheme)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_datacodingscheme, encodeErr_enc_datacodingscheme := ber.EncodeOctetString([]byte(v.DataCodingScheme))
	if encodeErr_enc_datacodingscheme != nil {
		return nil, fmt.Errorf("encoding dataCodingScheme: %w", encodeErr_enc_datacodingscheme)
	}
	retagged_enc_datacodingscheme, tagErr_enc_datacodingscheme := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_datacodingscheme)
	if tagErr_enc_datacodingscheme != nil {
		return nil, fmt.Errorf("encoding dataCodingScheme: %w", tagErr_enc_datacodingscheme)
	}
	enc_datacodingscheme = retagged_enc_datacodingscheme
	children = append(children, enc_datacodingscheme...)
	if len(v.LcsCodewordString) < 1 || len(v.LcsCodewordString) > 20 {
		if constraintErr := ber.CheckEncodedLength(nil, "lcsCodewordString", "SIZE (1..20)", len(v.LcsCodewordString)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	if len(v.LcsCodewordString) < 1 || len(v.LcsCodewordString) > 160 {
		if constraintErr := ber.CheckEncodedLength(nil, "lcsCodewordString", "SIZE (1..160)", len(v.LcsCodewordString)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_lcscodewordstring, encodeErr_enc_lcscodewordstring := ber.EncodeOctetString([]byte(v.LcsCodewordString))
	if encodeErr_enc_lcscodewordstring != nil {
		return nil, fmt.Errorf("encoding lcsCodewordString: %w", encodeErr_enc_lcscodewordstring)
	}
	retagged_enc_lcscodewordstring, tagErr_enc_lcscodewordstring := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_lcscodewordstring)
	if tagErr_enc_lcscodewordstring != nil {
		return nil, fmt.Errorf("encoding lcsCodewordString: %w", tagErr_enc_lcscodewordstring)
	}
	enc_lcscodewordstring = retagged_enc_lcscodewordstring
	children = append(children, enc_lcscodewordstring...)
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
		return nil, fmt.Errorf("encoding LCSLCSCodeword as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes LCSLCSCodeword from BER/DER format.
func (v *LCSLCSCodeword) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: LCSLCSCodeword destination is nil", ber.ErrInvalidValue)
	}
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = LCSLCSCodeword{}
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
		return fmt.Errorf("decoding LCSLCSCodeword SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "LCSLCSCodeword", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode dataCodingScheme
	if offset >= len(content) {
		return fmt.Errorf("missing required field dataCodingScheme")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 0 {
			return fmt.Errorf("expected tag [%s %d] for dataCodingScheme, got %s", "CONTEXT", 0, reqTag_)
		}
	}
	decodedTag_datacodingscheme, n_datacodingscheme, rawVal_datacodingscheme, err := ber.DecodeTLV(content[offset:], opts...)
	if err != nil {
		return fmt.Errorf("decoding dataCodingScheme: %w", err)
	}
	if decodedTag_datacodingscheme.Class != tag.ClassContextSpecific || decodedTag_datacodingscheme.Number != 0 {
		return fmt.Errorf("decoding dataCodingScheme: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_datacodingscheme)
	}
	decVal_datacodingscheme, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_datacodingscheme.Constructed, rawVal_datacodingscheme, opts...)
	if octetErr != nil {
		return fmt.Errorf("decoding dataCodingScheme: %w", octetErr)
	}
	v.DataCodingScheme = USSDDataCodingScheme3(decVal_datacodingscheme)
	if offset < 0 || offset >
		len(content) || n_datacodingscheme < 0 || n_datacodingscheme >
		len(content[offset:]) {
		return fmt.Errorf("invalid BER content window")
	}

	offset += n_datacodingscheme
	if len(v.DataCodingScheme) < 1 || len(v.DataCodingScheme) > 1 {
		if constraintErr := ber.CheckDecodedLength(opts, "dataCodingScheme", "SIZE (1)", len(v.DataCodingScheme)); constraintErr != nil {
			return constraintErr
		}
	}
	// Decode lcsCodewordString
	if offset >= len(content) {
		return fmt.Errorf("missing required field lcsCodewordString")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 1 {
			return fmt.Errorf("expected tag [%s %d] for lcsCodewordString, got %s", "CONTEXT", 1, reqTag_)
		}
	}
	decodedTag_lcscodewordstring, n_lcscodewordstring, rawVal_lcscodewordstring, err := ber.DecodeTLV(content[offset:], opts...)
	if err != nil {
		return fmt.Errorf("decoding lcsCodewordString: %w", err)
	}
	if decodedTag_lcscodewordstring.Class != tag.ClassContextSpecific || decodedTag_lcscodewordstring.Number != 1 {
		return fmt.Errorf("decoding lcsCodewordString: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_lcscodewordstring)
	}
	decVal_lcscodewordstring, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_lcscodewordstring.Constructed, rawVal_lcscodewordstring, opts...)
	if octetErr != nil {
		return fmt.Errorf("decoding lcsCodewordString: %w", octetErr)
	}
	v.LcsCodewordString = LCSLCSCodewordString(decVal_lcscodewordstring)
	if offset < 0 || offset >
		len(content) || n_lcscodewordstring < 0 || n_lcscodewordstring >
		len(content[offset:]) {
		return fmt.Errorf("invalid BER content window")
	}

	offset += n_lcscodewordstring
	if len(v.LcsCodewordString) < 1 || len(v.LcsCodewordString) > 20 {
		if constraintErr := ber.CheckDecodedLength(opts, "lcsCodewordString", "SIZE (1..20)", len(v.LcsCodewordString)); constraintErr != nil {
			return constraintErr
		}
	}
	if len(v.LcsCodewordString) < 1 || len(v.LcsCodewordString) > 160 {
		if constraintErr := ber.CheckDecodedLength(opts, "lcsCodewordString", "SIZE (1..160)", len(v.LcsCodewordString)); constraintErr != nil {
			return constraintErr
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:], opts...)
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "LCSLCSCodeword", Cause: extErr_}
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

// MarshalBER encodes LCSLCSPrivacyCheck to BER format.
func (v *LCSLCSPrivacyCheck) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: LCSLCSPrivacyCheck receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *LCSLCSPrivacyCheck) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	enc_callsessionunrelated := ber.EncodeEnumerated(int64(v.CallSessionUnrelated))
	retagged_enc_callsessionunrelated, tagErr_enc_callsessionunrelated := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_callsessionunrelated)
	if tagErr_enc_callsessionunrelated != nil {
		return nil, fmt.Errorf("encoding callSessionUnrelated: %w", tagErr_enc_callsessionunrelated)
	}
	enc_callsessionunrelated = retagged_enc_callsessionunrelated
	children = append(children, enc_callsessionunrelated...)
	if v.CallSessionRelated != nil {
		enc_callsessionrelated := ber.EncodeEnumerated(int64(*v.CallSessionRelated))
		retagged_enc_callsessionrelated, tagErr_enc_callsessionrelated := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_callsessionrelated)
		if tagErr_enc_callsessionrelated != nil {
			return nil, fmt.Errorf("encoding callSessionRelated: %w", tagErr_enc_callsessionrelated)
		}
		enc_callsessionrelated = retagged_enc_callsessionrelated
		children = append(children, enc_callsessionrelated...)
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

// MarshalDER encodes LCSLCSPrivacyCheck to DER format.
func (v *LCSLCSPrivacyCheck) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: LCSLCSPrivacyCheck receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	enc_callsessionunrelated := ber.EncodeEnumerated(int64(v.CallSessionUnrelated))
	retagged_enc_callsessionunrelated, tagErr_enc_callsessionunrelated := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_callsessionunrelated)
	if tagErr_enc_callsessionunrelated != nil {
		return nil, fmt.Errorf("encoding callSessionUnrelated: %w", tagErr_enc_callsessionunrelated)
	}
	enc_callsessionunrelated = retagged_enc_callsessionunrelated
	children = append(children, enc_callsessionunrelated...)
	if v.CallSessionRelated != nil {
		enc_callsessionrelated := ber.EncodeEnumerated(int64(*v.CallSessionRelated))
		retagged_enc_callsessionrelated, tagErr_enc_callsessionrelated := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_callsessionrelated)
		if tagErr_enc_callsessionrelated != nil {
			return nil, fmt.Errorf("encoding callSessionRelated: %w", tagErr_enc_callsessionrelated)
		}
		enc_callsessionrelated = retagged_enc_callsessionrelated
		children = append(children, enc_callsessionrelated...)
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
		return nil, fmt.Errorf("encoding LCSLCSPrivacyCheck as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes LCSLCSPrivacyCheck from BER/DER format.
func (v *LCSLCSPrivacyCheck) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: LCSLCSPrivacyCheck destination is nil", ber.ErrInvalidValue)
	}
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = LCSLCSPrivacyCheck{}
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
		return fmt.Errorf("decoding LCSLCSPrivacyCheck SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "LCSLCSPrivacyCheck", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode callSessionUnrelated
	if offset >= len(content) {
		return fmt.Errorf("missing required field callSessionUnrelated")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 0 {
			return fmt.Errorf("expected tag [%s %d] for callSessionUnrelated, got %s", "CONTEXT", 0, reqTag_)
		}
	}
	decodedTag_callsessionunrelated, n_callsessionunrelated, rawVal_callsessionunrelated, err := ber.DecodeTLV(content[offset:], opts...)
	if err != nil {
		return fmt.Errorf("decoding callSessionUnrelated: %w", err)
	}
	if decodedTag_callsessionunrelated.Class != tag.ClassContextSpecific || decodedTag_callsessionunrelated.Number != 0 || decodedTag_callsessionunrelated.Constructed != false {
		return fmt.Errorf("decoding callSessionUnrelated: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_callsessionunrelated)
	}
	decVal_callsessionunrelated, intErr := ber.DecodeEnumeratedValue(rawVal_callsessionunrelated)
	if intErr != nil {
		return fmt.Errorf("decoding callSessionUnrelated: %w", intErr)
	}
	v.CallSessionUnrelated = LCSPrivacyCheckRelatedAction(decVal_callsessionunrelated)
	if offset < 0 || offset >
		len(content) || n_callsessionunrelated < 0 || n_callsessionunrelated >
		len(content[offset:]) {
		return fmt.Errorf("invalid BER content window")
	}

	offset += n_callsessionunrelated
	// Decode callSessionRelated
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
				decodedTag_callsessionrelated, n_callsessionrelated, rawVal_callsessionrelated, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding callSessionRelated: %w", err)
				}
				if decodedTag_callsessionrelated.Class != tag.ClassContextSpecific || decodedTag_callsessionrelated.Number != 1 || decodedTag_callsessionrelated.Constructed != false {
					return fmt.Errorf("decoding callSessionRelated: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_callsessionrelated)
				}
				decVal_callsessionrelated, intErr := ber.DecodeEnumeratedValue(rawVal_callsessionrelated)
				if intErr != nil {
					return fmt.Errorf("decoding callSessionRelated: %w", intErr)
				}
				tmp_callsessionrelated := LCSPrivacyCheckRelatedAction(decVal_callsessionrelated)
				v.CallSessionRelated = &tmp_callsessionrelated
				if offset < 0 || offset >
					len(content) || n_callsessionrelated < 0 || n_callsessionrelated >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_callsessionrelated
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:], opts...)
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "LCSLCSPrivacyCheck", Cause: extErr_}
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

// MarshalBER encodes LCSAreaEventInfo to BER format.
func (v *LCSAreaEventInfo) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: LCSAreaEventInfo receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *LCSAreaEventInfo) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	enc_areadefinition, err := v.AreaDefinition.MarshalBER(ber.ChildEncodeOptions(opts, "areaDefinition")...)
	if err != nil {
		return nil, fmt.Errorf("encoding areaDefinition: %w", err)
	}
	retagged_enc_areadefinition, tagErr_enc_areadefinition := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_areadefinition)
	if tagErr_enc_areadefinition != nil {
		return nil, fmt.Errorf("encoding areaDefinition: %w", tagErr_enc_areadefinition)
	}
	enc_areadefinition = retagged_enc_areadefinition
	children = append(children, enc_areadefinition...)
	if v.OccurrenceInfo != nil {
		enc_occurrenceinfo := ber.EncodeEnumerated(int64(*v.OccurrenceInfo))
		retagged_enc_occurrenceinfo, tagErr_enc_occurrenceinfo := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_occurrenceinfo)
		if tagErr_enc_occurrenceinfo != nil {
			return nil, fmt.Errorf("encoding occurrenceInfo: %w", tagErr_enc_occurrenceinfo)
		}
		enc_occurrenceinfo = retagged_enc_occurrenceinfo
		children = append(children, enc_occurrenceinfo...)
	}
	if v.IntervalTime != nil {
		if !(int64(*v.IntervalTime) >= 1 && int64(*v.IntervalTime) <= 32767) {
			if constraintErr := ber.CheckEncodedValue(opts, "intervalTime", "(1..32767)", fmt.Sprint(int64(*v.IntervalTime))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_intervaltime := ber.EncodeInteger(int64(*v.IntervalTime))
		retagged_enc_intervaltime, tagErr_enc_intervaltime := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_intervaltime)
		if tagErr_enc_intervaltime != nil {
			return nil, fmt.Errorf("encoding intervalTime: %w", tagErr_enc_intervaltime)
		}
		enc_intervaltime = retagged_enc_intervaltime
		children = append(children, enc_intervaltime...)
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

// MarshalDER encodes LCSAreaEventInfo to DER format.
func (v *LCSAreaEventInfo) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: LCSAreaEventInfo receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	enc_areadefinition, err := v.AreaDefinition.MarshalDER()
	if err != nil {
		return nil, fmt.Errorf("encoding areaDefinition: %w", err)
	}
	retagged_enc_areadefinition, tagErr_enc_areadefinition := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_areadefinition)
	if tagErr_enc_areadefinition != nil {
		return nil, fmt.Errorf("encoding areaDefinition: %w", tagErr_enc_areadefinition)
	}
	enc_areadefinition = retagged_enc_areadefinition
	children = append(children, enc_areadefinition...)
	if v.OccurrenceInfo != nil {
		enc_occurrenceinfo := ber.EncodeEnumerated(int64(*v.OccurrenceInfo))
		retagged_enc_occurrenceinfo, tagErr_enc_occurrenceinfo := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_occurrenceinfo)
		if tagErr_enc_occurrenceinfo != nil {
			return nil, fmt.Errorf("encoding occurrenceInfo: %w", tagErr_enc_occurrenceinfo)
		}
		enc_occurrenceinfo = retagged_enc_occurrenceinfo
		children = append(children, enc_occurrenceinfo...)
	}
	if v.IntervalTime != nil {
		if !(int64(*v.IntervalTime) >= 1 && int64(*v.IntervalTime) <= 32767) {
			if constraintErr := ber.CheckEncodedValue(nil, "intervalTime", "(1..32767)", fmt.Sprint(int64(*v.IntervalTime))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_intervaltime := ber.EncodeInteger(int64(*v.IntervalTime))
		retagged_enc_intervaltime, tagErr_enc_intervaltime := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_intervaltime)
		if tagErr_enc_intervaltime != nil {
			return nil, fmt.Errorf("encoding intervalTime: %w", tagErr_enc_intervaltime)
		}
		enc_intervaltime = retagged_enc_intervaltime
		children = append(children, enc_intervaltime...)
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
		return nil, fmt.Errorf("encoding LCSAreaEventInfo as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes LCSAreaEventInfo from BER/DER format.
func (v *LCSAreaEventInfo) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: LCSAreaEventInfo destination is nil", ber.ErrInvalidValue)
	}
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = LCSAreaEventInfo{}
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
		return fmt.Errorf("decoding LCSAreaEventInfo SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "LCSAreaEventInfo", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode areaDefinition
	if offset >= len(content) {
		return fmt.Errorf("missing required field areaDefinition")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 0 {
			return fmt.Errorf("expected tag [%s %d] for areaDefinition, got %s", "CONTEXT", 0, reqTag_)
		}
	}
	decodedTag_areadefinition, n_areadefinition, rawVal_areadefinition, err := ber.DecodeTLV(content[offset:], opts...)
	if err != nil {
		return fmt.Errorf("decoding areaDefinition: %w", err)
	}
	if decodedTag_areadefinition.Class != tag.ClassContextSpecific || decodedTag_areadefinition.Number != 0 || decodedTag_areadefinition.Constructed != true {
		return fmt.Errorf("decoding areaDefinition: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_areadefinition)
	}
	reconstructed_areadefinition, reconstructionErr_areadefinition := ber.EncodeSequence(rawVal_areadefinition)
	if reconstructionErr_areadefinition != nil {
		return fmt.Errorf("decoding areaDefinition: %w", reconstructionErr_areadefinition)
	}
	if unmErr := v.AreaDefinition.UnmarshalBER(reconstructed_areadefinition, ber.ChildDecodeOptions(opts, "areaDefinition")...); unmErr != nil {
		return fmt.Errorf("decoding areaDefinition: %w", unmErr)
	}
	if offset < 0 || offset >
		len(content) || n_areadefinition < 0 || n_areadefinition >
		len(content[offset:]) {
		return fmt.Errorf("invalid BER content window")
	}

	offset += n_areadefinition
	// Decode occurrenceInfo
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
				decodedTag_occurrenceinfo, n_occurrenceinfo, rawVal_occurrenceinfo, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding occurrenceInfo: %w", err)
				}
				if decodedTag_occurrenceinfo.Class != tag.ClassContextSpecific || decodedTag_occurrenceinfo.Number != 1 || decodedTag_occurrenceinfo.Constructed != false {
					return fmt.Errorf("decoding occurrenceInfo: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_occurrenceinfo)
				}
				decVal_occurrenceinfo, intErr := ber.DecodeEnumeratedValue(rawVal_occurrenceinfo)
				if intErr != nil {
					return fmt.Errorf("decoding occurrenceInfo: %w", intErr)
				}
				tmp_occurrenceinfo := LCSOccurrenceInfo(decVal_occurrenceinfo)
				v.OccurrenceInfo = &tmp_occurrenceinfo
				if offset < 0 || offset >
					len(content) || n_occurrenceinfo < 0 || n_occurrenceinfo >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_occurrenceinfo
			}
		}
	}
	// Decode intervalTime
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2 {
				decodedTag_intervaltime, n_intervaltime, rawVal_intervaltime, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding intervalTime: %w", err)
				}
				if decodedTag_intervaltime.Class != tag.ClassContextSpecific || decodedTag_intervaltime.Number != 2 || decodedTag_intervaltime.Constructed != false {
					return fmt.Errorf("decoding intervalTime: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_intervaltime)
				}
				decVal_intervaltime, intErr := ber.DecodeIntegerValue(rawVal_intervaltime)
				if intErr != nil {
					return fmt.Errorf("decoding intervalTime: %w", intErr)
				}
				tmp_intervaltime := LCSIntervalTime(decVal_intervaltime)
				v.IntervalTime = &tmp_intervaltime
				if offset < 0 || offset >
					len(content) || n_intervaltime < 0 || n_intervaltime > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_intervaltime
				if !(int64(*v.IntervalTime) >= 1 && int64(*v.IntervalTime) <= 32767) {
					if constraintErr := ber.CheckDecodedValue(opts, "intervalTime", "(1..32767)", fmt.Sprint(int64(*v.IntervalTime))); constraintErr != nil {
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
			return &ber.DecodeError{Offset: offset, TypeName: "LCSAreaEventInfo", Cause: extErr_}
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

// MarshalBER encodes LCSAreaDefinition to BER format.
func (v *LCSAreaDefinition) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: LCSAreaDefinition receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *LCSAreaDefinition) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if v.AreaList == nil {
		return nil, fmt.Errorf("encoding areaList: %w: required collection is nil", ber.ErrInvalidValue)
	}
	if len((v.AreaList).Values) < 1 || len((v.AreaList).Values) > 10 {
		if constraintErr := ber.CheckEncodedLength(opts, "areaList", "SIZE (1..10)", len((v.AreaList).Values)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_arealist, err := MarshalBERLCSAreaList(v.AreaList, ber.ChildEncodeOptions(opts, "areaList")...)
	if err != nil {
		return nil, fmt.Errorf("encoding areaList: %w", err)
	}
	if v.AreaListIndef_ {
		// Strip the outer SEQUENCE tag from marshalBER output to get raw children.
		_, _, seqContent_, tlvErr_ := ber.DecodeEncodedTLV(enc_arealist)
		if tlvErr_ != nil {
			return nil, tlvErr_
		}
		{
			var encodeErr error
			enc_arealist, encodeErr = ber.EncodeConstructedIndefinite(tag.Tag{Class: tag.ClassContextSpecific, Number: 0}, seqContent_)
			if encodeErr != nil {
				return nil, fmt.Errorf("encoding areaList: %w", encodeErr)
			}
		}
	} else {
		retagged_enc_arealist, tagErr_enc_arealist := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_arealist)
		if tagErr_enc_arealist != nil {
			return nil, fmt.Errorf("encoding areaList: %w", tagErr_enc_arealist)
		}
		enc_arealist = retagged_enc_arealist
	}
	children = append(children, enc_arealist...)
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

// MarshalDER encodes LCSAreaDefinition to DER format.
func (v *LCSAreaDefinition) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: LCSAreaDefinition receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if v.AreaList == nil {
		return nil, fmt.Errorf("encoding areaList: %w: required collection is nil", ber.ErrInvalidValue)
	}
	if len((v.AreaList).Values) < 1 || len((v.AreaList).Values) > 10 {
		if constraintErr := ber.CheckEncodedLength(nil, "areaList", "SIZE (1..10)", len((v.AreaList).Values)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_arealist, err := MarshalDERLCSAreaList(v.AreaList)
	if err != nil {
		return nil, fmt.Errorf("encoding areaList: %w", err)
	}
	retagged_enc_arealist, tagErr_enc_arealist := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_arealist)
	if tagErr_enc_arealist != nil {
		return nil, fmt.Errorf("encoding areaList: %w", tagErr_enc_arealist)
	}
	enc_arealist = retagged_enc_arealist
	children = append(children, enc_arealist...)
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
		return nil, fmt.Errorf("encoding LCSAreaDefinition as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes LCSAreaDefinition from BER/DER format.
func (v *LCSAreaDefinition) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: LCSAreaDefinition destination is nil", ber.ErrInvalidValue)
	}
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = LCSAreaDefinition{}
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
		return fmt.Errorf("decoding LCSAreaDefinition SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "LCSAreaDefinition", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode areaList
	if offset >= len(content) {
		return fmt.Errorf("missing required field areaList")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 0 {
			return fmt.Errorf("expected tag [%s %d] for areaList, got %s", "CONTEXT", 0, reqTag_)
		}
	}
	v.AreaListIndef_ = false
	decodedTag_arealist, n_arealist, rawVal_arealist, err := ber.DecodeTLV(content[offset:], opts...)
	if err != nil {
		return fmt.Errorf("decoding areaList: %w", err)
	}
	if decodedTag_arealist.Class != tag.ClassContextSpecific || decodedTag_arealist.Number != 0 || decodedTag_arealist.Constructed != true {
		return fmt.Errorf("decoding areaList: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_arealist)
	}
	reconstructed_arealist, reconstructionErr_arealist := ber.EncodeSequence(rawVal_arealist)
	if reconstructionErr_arealist != nil {
		return fmt.Errorf("decoding areaList: %w", reconstructionErr_arealist)
	}
	dec_arealist, unmErr := UnmarshalBERLCSAreaList(reconstructed_arealist, ber.ChildDecodeOptions(opts, "areaList")...)
	if unmErr != nil {
		return fmt.Errorf("decoding areaList: %w", unmErr)
	}
	v.AreaList = dec_arealist
	{
		_, tagSz_, _ := ber.DecodeTag(content[offset:])
		if offset < 0 || offset >
			len(content) || tagSz_ < 0 || tagSz_ > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		if offset+tagSz_ < len(content) && content[offset+tagSz_] == 0x80 {
			v.AreaListIndef_ = true
		}
	}
	if offset < 0 || offset >
		len(content) || n_arealist < 0 || n_arealist > len(content[offset:]) {
		return fmt.Errorf("invalid BER content window")
	}

	offset += n_arealist
	if len((v.AreaList).Values) < 1 || len((v.AreaList).Values) > 10 {
		if constraintErr := ber.CheckDecodedLength(opts, "areaList", "SIZE (1..10)", len((v.AreaList).Values)); constraintErr != nil {
			return constraintErr
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:], opts...)
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "LCSAreaDefinition", Cause: extErr_}
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

// MarshalBERLCSAreaList encodes a LCSAreaList list to BER.
func MarshalBERLCSAreaList(collection *LCSAreaList, opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	if collection == nil {
		return nil, fmt.Errorf("%w: required collection is nil", ber.ErrInvalidValue)
	}
	encoded, err := marshalBERLCSAreaList(collection, opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, collection.berOriginal_, collection.berSnapshot_, opts), nil
}
func marshalBERLCSAreaList(collection *LCSAreaList, opts ...ber.EncodeOption) ([]byte, error) {
	list := collection.Values
	if len(list) < 1 || len(list) > 10 {
		if constraintErr := ber.CheckEncodedLength(opts, "LCSAreaList", "SIZE (1..10)", len(list)); constraintErr != nil {
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

// MarshalDERLCSAreaList encodes a LCSAreaList list to DER.
func MarshalDERLCSAreaList(collection *LCSAreaList) ([]byte, error) {
	if collection == nil {
		return nil, fmt.Errorf("%w: required collection is nil", ber.ErrInvalidValue)
	}
	list := collection.Values
	if len(list) < 1 || len(list) > 10 {
		if constraintErr := ber.CheckEncodedLength(nil, "LCSAreaList", "SIZE (1..10)", len(list)); constraintErr != nil {
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
		return nil, fmt.Errorf("encoding LCSAreaList as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBERLCSAreaList decodes a LCSAreaList list from BER.
func UnmarshalBERLCSAreaList(data []byte, opts ...ber.DecodeOption) (returnValue *LCSAreaList, returnErr error) {
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return nil, err
	}
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return nil, fmt.Errorf("decoding LCSAreaList: %w", err)
	}
	if total != len(data) {
		return nil, &ber.DecodeError{Offset: total, TypeName: "LCSAreaList", Cause: ber.ErrExtraData}
	}
	var result []LCSArea
	offset := 0
	for offset < len(content) {
		elementData := content[offset:]
		var elem LCSArea
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
	if len(result) < 1 || len(result) > 10 {
		if constraintErr := ber.CheckDecodedLength(opts, "LCSAreaList", "SIZE (1..10)", len(result)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	decoded := &LCSAreaList{Values: result}
	if ber.BERNeedsPreservation(opts) {
		var snapshotReports ber.ViolationLog
		snapshot, snapshotErr := MarshalBERLCSAreaList(decoded, ber.WithConstraintTolerance(&snapshotReports))
		if snapshotErr != nil {
			return nil, snapshotErr
		}
		decoded.berOriginal_ = append([]byte(nil), data...)
		decoded.berSnapshot_ = snapshot
	}
	return decoded, nil
}

// MarshalBER encodes LCSArea to BER format.
func (v *LCSArea) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: LCSArea receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *LCSArea) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	enc_areatype := ber.EncodeEnumerated(int64(v.AreaType))
	retagged_enc_areatype, tagErr_enc_areatype := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_areatype)
	if tagErr_enc_areatype != nil {
		return nil, fmt.Errorf("encoding areaType: %w", tagErr_enc_areatype)
	}
	enc_areatype = retagged_enc_areatype
	children = append(children, enc_areatype...)
	if len(v.AreaIdentification) < 2 || len(v.AreaIdentification) > 7 {
		if constraintErr := ber.CheckEncodedLength(opts, "areaIdentification", "SIZE (2..7)", len(v.AreaIdentification)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_areaidentification, encodeErr_enc_areaidentification := ber.EncodeOctetString([]byte(v.AreaIdentification))
	if encodeErr_enc_areaidentification != nil {
		return nil, fmt.Errorf("encoding areaIdentification: %w", encodeErr_enc_areaidentification)
	}
	retagged_enc_areaidentification, tagErr_enc_areaidentification := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_areaidentification)
	if tagErr_enc_areaidentification != nil {
		return nil, fmt.Errorf("encoding areaIdentification: %w", tagErr_enc_areaidentification)
	}
	enc_areaidentification = retagged_enc_areaidentification
	children = append(children, enc_areaidentification...)
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

// MarshalDER encodes LCSArea to DER format.
func (v *LCSArea) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: LCSArea receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	enc_areatype := ber.EncodeEnumerated(int64(v.AreaType))
	retagged_enc_areatype, tagErr_enc_areatype := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_areatype)
	if tagErr_enc_areatype != nil {
		return nil, fmt.Errorf("encoding areaType: %w", tagErr_enc_areatype)
	}
	enc_areatype = retagged_enc_areatype
	children = append(children, enc_areatype...)
	if len(v.AreaIdentification) < 2 || len(v.AreaIdentification) > 7 {
		if constraintErr := ber.CheckEncodedLength(nil, "areaIdentification", "SIZE (2..7)", len(v.AreaIdentification)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_areaidentification, encodeErr_enc_areaidentification := ber.EncodeOctetString([]byte(v.AreaIdentification))
	if encodeErr_enc_areaidentification != nil {
		return nil, fmt.Errorf("encoding areaIdentification: %w", encodeErr_enc_areaidentification)
	}
	retagged_enc_areaidentification, tagErr_enc_areaidentification := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_areaidentification)
	if tagErr_enc_areaidentification != nil {
		return nil, fmt.Errorf("encoding areaIdentification: %w", tagErr_enc_areaidentification)
	}
	enc_areaidentification = retagged_enc_areaidentification
	children = append(children, enc_areaidentification...)
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
		return nil, fmt.Errorf("encoding LCSArea as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes LCSArea from BER/DER format.
func (v *LCSArea) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: LCSArea destination is nil", ber.ErrInvalidValue)
	}
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = LCSArea{}
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
		return fmt.Errorf("decoding LCSArea SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "LCSArea", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode areaType
	if offset >= len(content) {
		return fmt.Errorf("missing required field areaType")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 0 {
			return fmt.Errorf("expected tag [%s %d] for areaType, got %s", "CONTEXT", 0, reqTag_)
		}
	}
	decodedTag_areatype, n_areatype, rawVal_areatype, err := ber.DecodeTLV(content[offset:], opts...)
	if err != nil {
		return fmt.Errorf("decoding areaType: %w", err)
	}
	if decodedTag_areatype.Class != tag.ClassContextSpecific || decodedTag_areatype.Number != 0 || decodedTag_areatype.Constructed != false {
		return fmt.Errorf("decoding areaType: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_areatype)
	}
	decVal_areatype, intErr := ber.DecodeEnumeratedValue(rawVal_areatype)
	if intErr != nil {
		return fmt.Errorf("decoding areaType: %w", intErr)
	}
	v.AreaType = LCSAreaType(decVal_areatype)
	if offset < 0 || offset >
		len(content) || n_areatype < 0 || n_areatype > len(content[offset:]) {
		return fmt.Errorf("invalid BER content window")
	}

	offset += n_areatype
	// Decode areaIdentification
	if offset >= len(content) {
		return fmt.Errorf("missing required field areaIdentification")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 1 {
			return fmt.Errorf("expected tag [%s %d] for areaIdentification, got %s", "CONTEXT", 1, reqTag_)
		}
	}
	decodedTag_areaidentification, n_areaidentification, rawVal_areaidentification, err := ber.DecodeTLV(content[offset:], opts...)
	if err != nil {
		return fmt.Errorf("decoding areaIdentification: %w", err)
	}
	if decodedTag_areaidentification.Class != tag.ClassContextSpecific || decodedTag_areaidentification.Number != 1 {
		return fmt.Errorf("decoding areaIdentification: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_areaidentification)
	}
	decVal_areaidentification, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_areaidentification.Constructed, rawVal_areaidentification, opts...)
	if octetErr != nil {
		return fmt.Errorf("decoding areaIdentification: %w", octetErr)
	}
	v.AreaIdentification = LCSAreaIdentification(decVal_areaidentification)
	if offset < 0 || offset >
		len(content) || n_areaidentification < 0 || n_areaidentification >
		len(content[offset:]) {
		return fmt.Errorf("invalid BER content window")
	}

	offset += n_areaidentification
	if len(v.AreaIdentification) < 2 || len(v.AreaIdentification) > 7 {
		if constraintErr := ber.CheckDecodedLength(opts, "areaIdentification", "SIZE (2..7)", len(v.AreaIdentification)); constraintErr != nil {
			return constraintErr
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:], opts...)
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "LCSArea", Cause: extErr_}
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

// MarshalBER encodes LCSPeriodicLDRInfo to BER format.
func (v *LCSPeriodicLDRInfo) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: LCSPeriodicLDRInfo receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *LCSPeriodicLDRInfo) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if !(int64(v.ReportingAmount) >= 1 && int64(v.ReportingAmount) <= 8639999) {
		if constraintErr := ber.CheckEncodedValue(opts, "reportingAmount", "(1..8639999)", fmt.Sprint(int64(v.ReportingAmount))); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_reportingamount := ber.EncodeInteger(int64(v.ReportingAmount))
	children = append(children, enc_reportingamount...)
	if !(int64(v.ReportingInterval) >= 1 && int64(v.ReportingInterval) <= 8639999) {
		if constraintErr := ber.CheckEncodedValue(opts, "reportingInterval", "(1..8639999)", fmt.Sprint(int64(v.ReportingInterval))); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_reportinginterval := ber.EncodeInteger(int64(v.ReportingInterval))
	children = append(children, enc_reportinginterval...)
	if v.ReportingOptionMilliseconds != nil {
		enc_reportingoptionmilliseconds, err := v.ReportingOptionMilliseconds.MarshalBER(ber.ChildEncodeOptions(opts, "reportingOptionMilliseconds")...)
		if err != nil {
			return nil, fmt.Errorf("encoding reportingOptionMilliseconds: %w", err)
		}
		retagged_enc_reportingoptionmilliseconds, tagErr_enc_reportingoptionmilliseconds := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_reportingoptionmilliseconds)
		if tagErr_enc_reportingoptionmilliseconds != nil {
			return nil, fmt.Errorf("encoding reportingOptionMilliseconds: %w", tagErr_enc_reportingoptionmilliseconds)
		}
		enc_reportingoptionmilliseconds = retagged_enc_reportingoptionmilliseconds
		children = append(children, enc_reportingoptionmilliseconds...)
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

// MarshalDER encodes LCSPeriodicLDRInfo to DER format.
func (v *LCSPeriodicLDRInfo) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: LCSPeriodicLDRInfo receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if !(int64(v.ReportingAmount) >= 1 && int64(v.ReportingAmount) <= 8639999) {
		if constraintErr := ber.CheckEncodedValue(nil, "reportingAmount", "(1..8639999)", fmt.Sprint(int64(v.ReportingAmount))); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_reportingamount := ber.EncodeInteger(int64(v.ReportingAmount))
	children = append(children, enc_reportingamount...)
	if !(int64(v.ReportingInterval) >= 1 && int64(v.ReportingInterval) <= 8639999) {
		if constraintErr := ber.CheckEncodedValue(nil, "reportingInterval", "(1..8639999)", fmt.Sprint(int64(v.ReportingInterval))); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_reportinginterval := ber.EncodeInteger(int64(v.ReportingInterval))
	children = append(children, enc_reportinginterval...)
	if v.ReportingOptionMilliseconds != nil {
		enc_reportingoptionmilliseconds, err := v.ReportingOptionMilliseconds.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding reportingOptionMilliseconds: %w", err)
		}
		retagged_enc_reportingoptionmilliseconds, tagErr_enc_reportingoptionmilliseconds := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_reportingoptionmilliseconds)
		if tagErr_enc_reportingoptionmilliseconds != nil {
			return nil, fmt.Errorf("encoding reportingOptionMilliseconds: %w", tagErr_enc_reportingoptionmilliseconds)
		}
		enc_reportingoptionmilliseconds = retagged_enc_reportingoptionmilliseconds
		children = append(children, enc_reportingoptionmilliseconds...)
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
		return nil, fmt.Errorf("encoding LCSPeriodicLDRInfo as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes LCSPeriodicLDRInfo from BER/DER format.
func (v *LCSPeriodicLDRInfo) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: LCSPeriodicLDRInfo destination is nil", ber.ErrInvalidValue)
	}
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = LCSPeriodicLDRInfo{}
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
		return fmt.Errorf("decoding LCSPeriodicLDRInfo SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "LCSPeriodicLDRInfo", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode reportingAmount
	if offset >= len(content) {
		return fmt.Errorf("missing required field reportingAmount")
	}
	val_reportingamount, n, err := ber.DecodeInteger(content[offset:], opts...)
	if err != nil {
		return fmt.Errorf("decoding reportingAmount: %w", err)
	}
	v.ReportingAmount = LCSReportingAmount(val_reportingamount)
	if offset < 0 || offset >
		len(content) || n < 0 || n > len(content[offset:]) {
		return fmt.Errorf("invalid BER content window")
	}

	offset += n
	if !(int64(v.ReportingAmount) >= 1 && int64(v.ReportingAmount) <= 8639999) {
		if constraintErr := ber.CheckDecodedValue(opts, "reportingAmount", "(1..8639999)", fmt.Sprint(int64(v.ReportingAmount))); constraintErr != nil {
			return constraintErr
		}
	}
	// Decode reportingInterval
	if offset >= len(content) {
		return fmt.Errorf("missing required field reportingInterval")
	}
	val_reportinginterval, n, err := ber.DecodeInteger(content[offset:], opts...)
	if err != nil {
		return fmt.Errorf("decoding reportingInterval: %w", err)
	}
	v.ReportingInterval = LCSReportingInterval(val_reportinginterval)
	if offset < 0 || offset >
		len(content) || n < 0 || n > len(content[offset:]) {
		return fmt.Errorf("invalid BER content window")
	}

	offset += n
	if !(int64(v.ReportingInterval) >= 1 && int64(v.ReportingInterval) <= 8639999) {
		if constraintErr := ber.CheckDecodedValue(opts, "reportingInterval", "(1..8639999)", fmt.Sprint(int64(v.ReportingInterval))); constraintErr != nil {
			return constraintErr
		}
	}
	// Decode reportingOptionMilliseconds
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
				decodedTag_reportingoptionmilliseconds, n_reportingoptionmilliseconds, rawVal_reportingoptionmilliseconds, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding reportingOptionMilliseconds: %w", err)
				}
				if decodedTag_reportingoptionmilliseconds.Class != tag.ClassContextSpecific || decodedTag_reportingoptionmilliseconds.Number != 0 || decodedTag_reportingoptionmilliseconds.Constructed != true {
					return fmt.Errorf("decoding reportingOptionMilliseconds: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_reportingoptionmilliseconds)
				}
				reconstructed_reportingoptionmilliseconds, reconstructionErr_reportingoptionmilliseconds := ber.EncodeSequence(rawVal_reportingoptionmilliseconds)
				if reconstructionErr_reportingoptionmilliseconds != nil {
					return fmt.Errorf("decoding reportingOptionMilliseconds: %w", reconstructionErr_reportingoptionmilliseconds)
				}
				var dec_reportingoptionmilliseconds LCSReportingOptionMilliseconds
				if unmErr := dec_reportingoptionmilliseconds.UnmarshalBER(reconstructed_reportingoptionmilliseconds, ber.ChildDecodeOptions(opts, "reportingOptionMilliseconds")...); unmErr != nil {
					return fmt.Errorf("decoding reportingOptionMilliseconds: %w", unmErr)
				}
				v.ReportingOptionMilliseconds = &dec_reportingoptionmilliseconds
				if offset < 0 || offset >
					len(content) || n_reportingoptionmilliseconds < 0 || n_reportingoptionmilliseconds >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_reportingoptionmilliseconds
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:], opts...)
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "LCSPeriodicLDRInfo", Cause: extErr_}
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

// MarshalBER encodes LCSReportingOptionMilliseconds to BER format.
func (v *LCSReportingOptionMilliseconds) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: LCSReportingOptionMilliseconds receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *LCSReportingOptionMilliseconds) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if !(int64(v.ReportingAmountMilliseconds) >= 1 && int64(v.ReportingAmountMilliseconds) <= 8639999000) {
		if constraintErr := ber.CheckEncodedValue(opts, "reportingAmountMilliseconds", "(1..8639999000)", fmt.Sprint(int64(v.ReportingAmountMilliseconds))); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_reportingamountmilliseconds := ber.EncodeInteger(int64(v.ReportingAmountMilliseconds))
	children = append(children, enc_reportingamountmilliseconds...)
	if !(int64(v.ReportingIntervalMilliseconds) >= 1 && int64(v.ReportingIntervalMilliseconds) <= 999) {
		if constraintErr := ber.CheckEncodedValue(opts, "reportingIntervalMilliseconds", "(1..999)", fmt.Sprint(int64(v.ReportingIntervalMilliseconds))); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_reportingintervalmilliseconds := ber.EncodeInteger(int64(v.ReportingIntervalMilliseconds))
	children = append(children, enc_reportingintervalmilliseconds...)
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

// MarshalDER encodes LCSReportingOptionMilliseconds to DER format.
func (v *LCSReportingOptionMilliseconds) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: LCSReportingOptionMilliseconds receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if !(int64(v.ReportingAmountMilliseconds) >= 1 && int64(v.ReportingAmountMilliseconds) <= 8639999000) {
		if constraintErr := ber.CheckEncodedValue(nil, "reportingAmountMilliseconds", "(1..8639999000)", fmt.Sprint(int64(v.ReportingAmountMilliseconds))); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_reportingamountmilliseconds := ber.EncodeInteger(int64(v.ReportingAmountMilliseconds))
	children = append(children, enc_reportingamountmilliseconds...)
	if !(int64(v.ReportingIntervalMilliseconds) >= 1 && int64(v.ReportingIntervalMilliseconds) <= 999) {
		if constraintErr := ber.CheckEncodedValue(nil, "reportingIntervalMilliseconds", "(1..999)", fmt.Sprint(int64(v.ReportingIntervalMilliseconds))); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_reportingintervalmilliseconds := ber.EncodeInteger(int64(v.ReportingIntervalMilliseconds))
	children = append(children, enc_reportingintervalmilliseconds...)
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
		return nil, fmt.Errorf("encoding LCSReportingOptionMilliseconds as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes LCSReportingOptionMilliseconds from BER/DER format.
func (v *LCSReportingOptionMilliseconds) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: LCSReportingOptionMilliseconds destination is nil", ber.ErrInvalidValue)
	}
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = LCSReportingOptionMilliseconds{}
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
		return fmt.Errorf("decoding LCSReportingOptionMilliseconds SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "LCSReportingOptionMilliseconds", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode reportingAmountMilliseconds
	if offset >= len(content) {
		return fmt.Errorf("missing required field reportingAmountMilliseconds")
	}
	val_reportingamountmilliseconds, n, err := ber.DecodeInteger(content[offset:], opts...)
	if err != nil {
		return fmt.Errorf("decoding reportingAmountMilliseconds: %w", err)
	}
	v.ReportingAmountMilliseconds = LCSReportingAmountMilliseconds(val_reportingamountmilliseconds)
	if offset < 0 || offset >
		len(content) || n < 0 || n > len(content[offset:]) {
		return fmt.Errorf("invalid BER content window")
	}

	offset += n
	if !(int64(v.ReportingAmountMilliseconds) >= 1 && int64(v.ReportingAmountMilliseconds) <= 8639999000) {
		if constraintErr := ber.CheckDecodedValue(opts, "reportingAmountMilliseconds", "(1..8639999000)", fmt.Sprint(int64(v.ReportingAmountMilliseconds))); constraintErr != nil {
			return constraintErr
		}
	}
	// Decode reportingIntervalMilliseconds
	if offset >= len(content) {
		return fmt.Errorf("missing required field reportingIntervalMilliseconds")
	}
	val_reportingintervalmilliseconds, n, err := ber.DecodeInteger(content[offset:], opts...)
	if err != nil {
		return fmt.Errorf("decoding reportingIntervalMilliseconds: %w", err)
	}
	v.ReportingIntervalMilliseconds = LCSReportingIntervalMilliseconds(val_reportingintervalmilliseconds)
	if offset < 0 || offset >
		len(content) || n < 0 || n > len(content[offset:]) {
		return fmt.Errorf("invalid BER content window")
	}

	offset += n
	if !(int64(v.ReportingIntervalMilliseconds) >= 1 && int64(v.ReportingIntervalMilliseconds) <= 999) {
		if constraintErr := ber.CheckDecodedValue(opts, "reportingIntervalMilliseconds", "(1..999)", fmt.Sprint(int64(v.ReportingIntervalMilliseconds))); constraintErr != nil {
			return constraintErr
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:], opts...)
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "LCSReportingOptionMilliseconds", Cause: extErr_}
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

// MarshalBER encodes LCSReportingPLMNList to BER format.
func (v *LCSReportingPLMNList) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: LCSReportingPLMNList receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *LCSReportingPLMNList) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if v.PlmnListPrioritized != nil {
		enc_plmnlistprioritized := ber.EncodeNull()
		retagged_enc_plmnlistprioritized, tagErr_enc_plmnlistprioritized := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_plmnlistprioritized)
		if tagErr_enc_plmnlistprioritized != nil {
			return nil, fmt.Errorf("encoding plmn-ListPrioritized: %w", tagErr_enc_plmnlistprioritized)
		}
		enc_plmnlistprioritized = retagged_enc_plmnlistprioritized
		children = append(children, enc_plmnlistprioritized...)
	}
	if v.PlmnList == nil {
		return nil, fmt.Errorf("encoding plmn-List: %w: required collection is nil", ber.ErrInvalidValue)
	}
	if len((v.PlmnList).Values) < 1 || len((v.PlmnList).Values) > 20 {
		if constraintErr := ber.CheckEncodedLength(opts, "plmn-List", "SIZE (1..20)", len((v.PlmnList).Values)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_plmnlist, err := MarshalBERLCSPLMNList(v.PlmnList, ber.ChildEncodeOptions(opts, "plmn-List")...)
	if err != nil {
		return nil, fmt.Errorf("encoding plmn-List: %w", err)
	}
	if v.PlmnListIndef_ {
		// Strip the outer SEQUENCE tag from marshalBER output to get raw children.
		_, _, seqContent_, tlvErr_ := ber.DecodeEncodedTLV(enc_plmnlist)
		if tlvErr_ != nil {
			return nil, tlvErr_
		}
		{
			var encodeErr error
			enc_plmnlist, encodeErr = ber.EncodeConstructedIndefinite(tag.Tag{Class: tag.ClassContextSpecific, Number: 1}, seqContent_)
			if encodeErr != nil {
				return nil, fmt.Errorf("encoding plmn-List: %w", encodeErr)
			}
		}
	} else {
		retagged_enc_plmnlist, tagErr_enc_plmnlist := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_plmnlist)
		if tagErr_enc_plmnlist != nil {
			return nil, fmt.Errorf("encoding plmn-List: %w", tagErr_enc_plmnlist)
		}
		enc_plmnlist = retagged_enc_plmnlist
	}
	children = append(children, enc_plmnlist...)
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

// MarshalDER encodes LCSReportingPLMNList to DER format.
func (v *LCSReportingPLMNList) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: LCSReportingPLMNList receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if v.PlmnListPrioritized != nil {
		enc_plmnlistprioritized := ber.EncodeNull()
		retagged_enc_plmnlistprioritized, tagErr_enc_plmnlistprioritized := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_plmnlistprioritized)
		if tagErr_enc_plmnlistprioritized != nil {
			return nil, fmt.Errorf("encoding plmn-ListPrioritized: %w", tagErr_enc_plmnlistprioritized)
		}
		enc_plmnlistprioritized = retagged_enc_plmnlistprioritized
		children = append(children, enc_plmnlistprioritized...)
	}
	if v.PlmnList == nil {
		return nil, fmt.Errorf("encoding plmn-List: %w: required collection is nil", ber.ErrInvalidValue)
	}
	if len((v.PlmnList).Values) < 1 || len((v.PlmnList).Values) > 20 {
		if constraintErr := ber.CheckEncodedLength(nil, "plmn-List", "SIZE (1..20)", len((v.PlmnList).Values)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_plmnlist, err := MarshalDERLCSPLMNList(v.PlmnList)
	if err != nil {
		return nil, fmt.Errorf("encoding plmn-List: %w", err)
	}
	retagged_enc_plmnlist, tagErr_enc_plmnlist := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_plmnlist)
	if tagErr_enc_plmnlist != nil {
		return nil, fmt.Errorf("encoding plmn-List: %w", tagErr_enc_plmnlist)
	}
	enc_plmnlist = retagged_enc_plmnlist
	children = append(children, enc_plmnlist...)
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
		return nil, fmt.Errorf("encoding LCSReportingPLMNList as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes LCSReportingPLMNList from BER/DER format.
func (v *LCSReportingPLMNList) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: LCSReportingPLMNList destination is nil", ber.ErrInvalidValue)
	}
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = LCSReportingPLMNList{}
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
		return fmt.Errorf("decoding LCSReportingPLMNList SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "LCSReportingPLMNList", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode plmn-ListPrioritized
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
				decodedTag_plmnlistprioritized, n_plmnlistprioritized, rawVal_plmnlistprioritized, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding plmn-ListPrioritized: %w", err)
				}
				if decodedTag_plmnlistprioritized.Class != tag.ClassContextSpecific || decodedTag_plmnlistprioritized.Number != 0 || decodedTag_plmnlistprioritized.Constructed != false {
					return fmt.Errorf("decoding plmn-ListPrioritized: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_plmnlistprioritized)
				}
				if len(rawVal_plmnlistprioritized) != 0 {
					return fmt.Errorf("decoding plmn-ListPrioritized: %w: NULL content length %d", ber.ErrInvalidValue, len(rawVal_plmnlistprioritized))
				}
				v.PlmnListPrioritized = &struct{}{}
				if offset < 0 || offset >
					len(content) || n_plmnlistprioritized < 0 || n_plmnlistprioritized >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_plmnlistprioritized
			}
		}
	}
	// Decode plmn-List
	if offset >= len(content) {
		return fmt.Errorf("missing required field plmn-List")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 1 {
			return fmt.Errorf("expected tag [%s %d] for plmn-List, got %s", "CONTEXT", 1, reqTag_)
		}
	}
	v.PlmnListIndef_ = false
	decodedTag_plmnlist, n_plmnlist, rawVal_plmnlist, err := ber.DecodeTLV(content[offset:], opts...)
	if err != nil {
		return fmt.Errorf("decoding plmn-List: %w", err)
	}
	if decodedTag_plmnlist.Class != tag.ClassContextSpecific || decodedTag_plmnlist.Number != 1 || decodedTag_plmnlist.Constructed != true {
		return fmt.Errorf("decoding plmn-List: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_plmnlist)
	}
	reconstructed_plmnlist, reconstructionErr_plmnlist := ber.EncodeSequence(rawVal_plmnlist)
	if reconstructionErr_plmnlist != nil {
		return fmt.Errorf("decoding plmn-List: %w", reconstructionErr_plmnlist)
	}
	dec_plmnlist, unmErr := UnmarshalBERLCSPLMNList(reconstructed_plmnlist, ber.ChildDecodeOptions(opts, "plmn-List")...)
	if unmErr != nil {
		return fmt.Errorf("decoding plmn-List: %w", unmErr)
	}
	v.PlmnList = dec_plmnlist
	{
		_, tagSz_, _ := ber.DecodeTag(content[offset:])
		if offset < 0 || offset >
			len(content) || tagSz_ < 0 || tagSz_ > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		if offset+tagSz_ < len(content) && content[offset+tagSz_] == 0x80 {
			v.PlmnListIndef_ = true
		}
	}
	if offset < 0 || offset >
		len(content) || n_plmnlist < 0 || n_plmnlist > len(content[offset:]) {
		return fmt.Errorf("invalid BER content window")
	}

	offset += n_plmnlist
	if len((v.PlmnList).Values) < 1 || len((v.PlmnList).Values) > 20 {
		if constraintErr := ber.CheckDecodedLength(opts, "plmn-List", "SIZE (1..20)", len((v.PlmnList).Values)); constraintErr != nil {
			return constraintErr
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:], opts...)
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "LCSReportingPLMNList", Cause: extErr_}
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

// MarshalBERLCSPLMNList encodes a LCSPLMNList list to BER.
func MarshalBERLCSPLMNList(collection *LCSPLMNList, opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	if collection == nil {
		return nil, fmt.Errorf("%w: required collection is nil", ber.ErrInvalidValue)
	}
	encoded, err := marshalBERLCSPLMNList(collection, opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, collection.berOriginal_, collection.berSnapshot_, opts), nil
}
func marshalBERLCSPLMNList(collection *LCSPLMNList, opts ...ber.EncodeOption) ([]byte, error) {
	list := collection.Values
	if len(list) < 1 || len(list) > 20 {
		if constraintErr := ber.CheckEncodedLength(opts, "LCSPLMNList", "SIZE (1..20)", len(list)); constraintErr != nil {
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

// MarshalDERLCSPLMNList encodes a LCSPLMNList list to DER.
func MarshalDERLCSPLMNList(collection *LCSPLMNList) ([]byte, error) {
	if collection == nil {
		return nil, fmt.Errorf("%w: required collection is nil", ber.ErrInvalidValue)
	}
	list := collection.Values
	if len(list) < 1 || len(list) > 20 {
		if constraintErr := ber.CheckEncodedLength(nil, "LCSPLMNList", "SIZE (1..20)", len(list)); constraintErr != nil {
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
		return nil, fmt.Errorf("encoding LCSPLMNList as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBERLCSPLMNList decodes a LCSPLMNList list from BER.
func UnmarshalBERLCSPLMNList(data []byte, opts ...ber.DecodeOption) (returnValue *LCSPLMNList, returnErr error) {
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return nil, err
	}
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return nil, fmt.Errorf("decoding LCSPLMNList: %w", err)
	}
	if total != len(data) {
		return nil, &ber.DecodeError{Offset: total, TypeName: "LCSPLMNList", Cause: ber.ErrExtraData}
	}
	var result []LCSReportingPLMN
	offset := 0
	for offset < len(content) {
		elementData := content[offset:]
		var elem LCSReportingPLMN
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
		if constraintErr := ber.CheckDecodedLength(opts, "LCSPLMNList", "SIZE (1..20)", len(result)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	decoded := &LCSPLMNList{Values: result}
	if ber.BERNeedsPreservation(opts) {
		var snapshotReports ber.ViolationLog
		snapshot, snapshotErr := MarshalBERLCSPLMNList(decoded, ber.WithConstraintTolerance(&snapshotReports))
		if snapshotErr != nil {
			return nil, snapshotErr
		}
		decoded.berOriginal_ = append([]byte(nil), data...)
		decoded.berSnapshot_ = snapshot
	}
	return decoded, nil
}

// MarshalBER encodes LCSReportingPLMN to BER format.
func (v *LCSReportingPLMN) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: LCSReportingPLMN receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *LCSReportingPLMN) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if len(v.PlmnId) < 3 || len(v.PlmnId) > 3 {
		if constraintErr := ber.CheckEncodedLength(opts, "plmn-Id", "SIZE (3)", len(v.PlmnId)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_plmnid, encodeErr_enc_plmnid := ber.EncodeOctetString([]byte(v.PlmnId))
	if encodeErr_enc_plmnid != nil {
		return nil, fmt.Errorf("encoding plmn-Id: %w", encodeErr_enc_plmnid)
	}
	retagged_enc_plmnid, tagErr_enc_plmnid := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_plmnid)
	if tagErr_enc_plmnid != nil {
		return nil, fmt.Errorf("encoding plmn-Id: %w", tagErr_enc_plmnid)
	}
	enc_plmnid = retagged_enc_plmnid
	children = append(children, enc_plmnid...)
	if v.RanTechnology != nil {
		enc_rantechnology := ber.EncodeEnumerated(int64(*v.RanTechnology))
		retagged_enc_rantechnology, tagErr_enc_rantechnology := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_rantechnology)
		if tagErr_enc_rantechnology != nil {
			return nil, fmt.Errorf("encoding ran-Technology: %w", tagErr_enc_rantechnology)
		}
		enc_rantechnology = retagged_enc_rantechnology
		children = append(children, enc_rantechnology...)
	}
	if v.RanPeriodicLocationSupport != nil {
		enc_ranperiodiclocationsupport := ber.EncodeNull()
		retagged_enc_ranperiodiclocationsupport, tagErr_enc_ranperiodiclocationsupport := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_ranperiodiclocationsupport)
		if tagErr_enc_ranperiodiclocationsupport != nil {
			return nil, fmt.Errorf("encoding ran-PeriodicLocationSupport: %w", tagErr_enc_ranperiodiclocationsupport)
		}
		enc_ranperiodiclocationsupport = retagged_enc_ranperiodiclocationsupport
		children = append(children, enc_ranperiodiclocationsupport...)
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

// MarshalDER encodes LCSReportingPLMN to DER format.
func (v *LCSReportingPLMN) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: LCSReportingPLMN receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if len(v.PlmnId) < 3 || len(v.PlmnId) > 3 {
		if constraintErr := ber.CheckEncodedLength(nil, "plmn-Id", "SIZE (3)", len(v.PlmnId)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_plmnid, encodeErr_enc_plmnid := ber.EncodeOctetString([]byte(v.PlmnId))
	if encodeErr_enc_plmnid != nil {
		return nil, fmt.Errorf("encoding plmn-Id: %w", encodeErr_enc_plmnid)
	}
	retagged_enc_plmnid, tagErr_enc_plmnid := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_plmnid)
	if tagErr_enc_plmnid != nil {
		return nil, fmt.Errorf("encoding plmn-Id: %w", tagErr_enc_plmnid)
	}
	enc_plmnid = retagged_enc_plmnid
	children = append(children, enc_plmnid...)
	if v.RanTechnology != nil {
		enc_rantechnology := ber.EncodeEnumerated(int64(*v.RanTechnology))
		retagged_enc_rantechnology, tagErr_enc_rantechnology := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_rantechnology)
		if tagErr_enc_rantechnology != nil {
			return nil, fmt.Errorf("encoding ran-Technology: %w", tagErr_enc_rantechnology)
		}
		enc_rantechnology = retagged_enc_rantechnology
		children = append(children, enc_rantechnology...)
	}
	if v.RanPeriodicLocationSupport != nil {
		enc_ranperiodiclocationsupport := ber.EncodeNull()
		retagged_enc_ranperiodiclocationsupport, tagErr_enc_ranperiodiclocationsupport := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_ranperiodiclocationsupport)
		if tagErr_enc_ranperiodiclocationsupport != nil {
			return nil, fmt.Errorf("encoding ran-PeriodicLocationSupport: %w", tagErr_enc_ranperiodiclocationsupport)
		}
		enc_ranperiodiclocationsupport = retagged_enc_ranperiodiclocationsupport
		children = append(children, enc_ranperiodiclocationsupport...)
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
		return nil, fmt.Errorf("encoding LCSReportingPLMN as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes LCSReportingPLMN from BER/DER format.
func (v *LCSReportingPLMN) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: LCSReportingPLMN destination is nil", ber.ErrInvalidValue)
	}
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = LCSReportingPLMN{}
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
		return fmt.Errorf("decoding LCSReportingPLMN SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "LCSReportingPLMN", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode plmn-Id
	if offset >= len(content) {
		return fmt.Errorf("missing required field plmn-Id")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 0 {
			return fmt.Errorf("expected tag [%s %d] for plmn-Id, got %s", "CONTEXT", 0, reqTag_)
		}
	}
	decodedTag_plmnid, n_plmnid, rawVal_plmnid, err := ber.DecodeTLV(content[offset:], opts...)
	if err != nil {
		return fmt.Errorf("decoding plmn-Id: %w", err)
	}
	if decodedTag_plmnid.Class != tag.ClassContextSpecific || decodedTag_plmnid.Number != 0 {
		return fmt.Errorf("decoding plmn-Id: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_plmnid)
	}
	decVal_plmnid, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_plmnid.Constructed, rawVal_plmnid, opts...)
	if octetErr != nil {
		return fmt.Errorf("decoding plmn-Id: %w", octetErr)
	}
	v.PlmnId = PLMNId3(decVal_plmnid)
	if offset < 0 || offset >
		len(content) || n_plmnid < 0 || n_plmnid > len(content[offset:]) {
		return fmt.Errorf("invalid BER content window")
	}

	offset += n_plmnid
	if len(v.PlmnId) < 3 || len(v.PlmnId) > 3 {
		if constraintErr := ber.CheckDecodedLength(opts, "plmn-Id", "SIZE (3)", len(v.PlmnId)); constraintErr != nil {
			return constraintErr
		}
	}
	// Decode ran-Technology
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
				decodedTag_rantechnology, n_rantechnology, rawVal_rantechnology, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding ran-Technology: %w", err)
				}
				if decodedTag_rantechnology.Class != tag.ClassContextSpecific || decodedTag_rantechnology.Number != 1 || decodedTag_rantechnology.Constructed != false {
					return fmt.Errorf("decoding ran-Technology: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_rantechnology)
				}
				decVal_rantechnology, intErr := ber.DecodeEnumeratedValue(rawVal_rantechnology)
				if intErr != nil {
					return fmt.Errorf("decoding ran-Technology: %w", intErr)
				}
				tmp_rantechnology := LCSRANTechnology(decVal_rantechnology)
				v.RanTechnology = &tmp_rantechnology
				if offset < 0 || offset >
					len(content) || n_rantechnology < 0 || n_rantechnology >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_rantechnology
			}
		}
	}
	// Decode ran-PeriodicLocationSupport
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2 {
				decodedTag_ranperiodiclocationsupport, n_ranperiodiclocationsupport, rawVal_ranperiodiclocationsupport, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding ran-PeriodicLocationSupport: %w", err)
				}
				if decodedTag_ranperiodiclocationsupport.Class != tag.ClassContextSpecific || decodedTag_ranperiodiclocationsupport.Number != 2 || decodedTag_ranperiodiclocationsupport.Constructed != false {
					return fmt.Errorf("decoding ran-PeriodicLocationSupport: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_ranperiodiclocationsupport)
				}
				if len(rawVal_ranperiodiclocationsupport) != 0 {
					return fmt.Errorf("decoding ran-PeriodicLocationSupport: %w: NULL content length %d", ber.ErrInvalidValue, len(rawVal_ranperiodiclocationsupport))
				}
				v.RanPeriodicLocationSupport = &struct{}{}
				if offset < 0 || offset >
					len(content) || n_ranperiodiclocationsupport < 0 || n_ranperiodiclocationsupport >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_ranperiodiclocationsupport
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:], opts...)
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "LCSReportingPLMN", Cause: extErr_}
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

// MarshalBER encodes LCSProvideSubscriberLocationRes to BER format.
func (v *LCSProvideSubscriberLocationRes) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: LCSProvideSubscriberLocationRes receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *LCSProvideSubscriberLocationRes) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if len(v.LocationEstimate) < 1 || len(v.LocationEstimate) > 20 {
		if constraintErr := ber.CheckEncodedLength(opts, "locationEstimate", "SIZE (1..20)", len(v.LocationEstimate)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_locationestimate, encodeErr_enc_locationestimate := ber.EncodeOctetString([]byte(v.LocationEstimate))
	if encodeErr_enc_locationestimate != nil {
		return nil, fmt.Errorf("encoding locationEstimate: %w", encodeErr_enc_locationestimate)
	}
	children = append(children, enc_locationestimate...)
	if v.AgeOfLocationEstimate != nil {
		if !(int64(*v.AgeOfLocationEstimate) >= 0 && int64(*v.AgeOfLocationEstimate) <= 32767) {
			if constraintErr := ber.CheckEncodedValue(opts, "ageOfLocationEstimate", "(0..32767)", fmt.Sprint(int64(*v.AgeOfLocationEstimate))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_ageoflocationestimate := ber.EncodeInteger(int64(*v.AgeOfLocationEstimate))
		retagged_enc_ageoflocationestimate, tagErr_enc_ageoflocationestimate := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_ageoflocationestimate)
		if tagErr_enc_ageoflocationestimate != nil {
			return nil, fmt.Errorf("encoding ageOfLocationEstimate: %w", tagErr_enc_ageoflocationestimate)
		}
		enc_ageoflocationestimate = retagged_enc_ageoflocationestimate
		children = append(children, enc_ageoflocationestimate...)
	}
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalBER(ber.ChildEncodeOptions(opts, "extensionContainer")...)
		if err != nil {
			return nil, fmt.Errorf("encoding extensionContainer: %w", err)
		}
		retagged_enc_extensioncontainer, tagErr_enc_extensioncontainer := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_extensioncontainer)
		if tagErr_enc_extensioncontainer != nil {
			return nil, fmt.Errorf("encoding extensionContainer: %w", tagErr_enc_extensioncontainer)
		}
		enc_extensioncontainer = retagged_enc_extensioncontainer
		children = append(children, enc_extensioncontainer...)
	}
	if v.AddLocationEstimate != nil {
		if len(*v.AddLocationEstimate) < 1 || len(*v.AddLocationEstimate) > 91 {
			if constraintErr := ber.CheckEncodedLength(opts, "add-LocationEstimate", "SIZE (1..91)", len(*v.AddLocationEstimate)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_addlocationestimate, encodeErr_enc_addlocationestimate := ber.EncodeOctetString([]byte(*v.AddLocationEstimate))
		if encodeErr_enc_addlocationestimate != nil {
			return nil, fmt.Errorf("encoding add-LocationEstimate: %w", encodeErr_enc_addlocationestimate)
		}
		retagged_enc_addlocationestimate, tagErr_enc_addlocationestimate := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_addlocationestimate)
		if tagErr_enc_addlocationestimate != nil {
			return nil, fmt.Errorf("encoding add-LocationEstimate: %w", tagErr_enc_addlocationestimate)
		}
		enc_addlocationestimate = retagged_enc_addlocationestimate
		children = append(children, enc_addlocationestimate...)
	}
	if v.DeferredmtLrResponseIndicator != nil {
		enc_deferredmtlrresponseindicator := ber.EncodeNull()
		retagged_enc_deferredmtlrresponseindicator, tagErr_enc_deferredmtlrresponseindicator := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, enc_deferredmtlrresponseindicator)
		if tagErr_enc_deferredmtlrresponseindicator != nil {
			return nil, fmt.Errorf("encoding deferredmt-lrResponseIndicator: %w", tagErr_enc_deferredmtlrresponseindicator)
		}
		enc_deferredmtlrresponseindicator = retagged_enc_deferredmtlrresponseindicator
		children = append(children, enc_deferredmtlrresponseindicator...)
	}
	if v.GeranPositioningData != nil {
		if len(*v.GeranPositioningData) < 2 || len(*v.GeranPositioningData) > 10 {
			if constraintErr := ber.CheckEncodedLength(opts, "geranPositioningData", "SIZE (2..10)", len(*v.GeranPositioningData)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_geranpositioningdata, encodeErr_enc_geranpositioningdata := ber.EncodeOctetString([]byte(*v.GeranPositioningData))
		if encodeErr_enc_geranpositioningdata != nil {
			return nil, fmt.Errorf("encoding geranPositioningData: %w", encodeErr_enc_geranpositioningdata)
		}
		retagged_enc_geranpositioningdata, tagErr_enc_geranpositioningdata := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, enc_geranpositioningdata)
		if tagErr_enc_geranpositioningdata != nil {
			return nil, fmt.Errorf("encoding geranPositioningData: %w", tagErr_enc_geranpositioningdata)
		}
		enc_geranpositioningdata = retagged_enc_geranpositioningdata
		children = append(children, enc_geranpositioningdata...)
	}
	if v.UtranPositioningData != nil {
		if len(*v.UtranPositioningData) < 3 || len(*v.UtranPositioningData) > 11 {
			if constraintErr := ber.CheckEncodedLength(opts, "utranPositioningData", "SIZE (3..11)", len(*v.UtranPositioningData)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_utranpositioningdata, encodeErr_enc_utranpositioningdata := ber.EncodeOctetString([]byte(*v.UtranPositioningData))
		if encodeErr_enc_utranpositioningdata != nil {
			return nil, fmt.Errorf("encoding utranPositioningData: %w", encodeErr_enc_utranpositioningdata)
		}
		retagged_enc_utranpositioningdata, tagErr_enc_utranpositioningdata := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 5, enc_utranpositioningdata)
		if tagErr_enc_utranpositioningdata != nil {
			return nil, fmt.Errorf("encoding utranPositioningData: %w", tagErr_enc_utranpositioningdata)
		}
		enc_utranpositioningdata = retagged_enc_utranpositioningdata
		children = append(children, enc_utranpositioningdata...)
	}
	if v.CellIdOrSai != nil {
		enc_cellidorsai, err := v.CellIdOrSai.MarshalBER(ber.ChildEncodeOptions(opts, "cellIdOrSai")...)
		if err != nil {
			return nil, fmt.Errorf("encoding cellIdOrSai: %w", err)
		}
		{
			var encodeErr error
			enc_cellidorsai, encodeErr = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 6, enc_cellidorsai)
			if encodeErr != nil {
				return nil, fmt.Errorf("encoding cellIdOrSai: %w", encodeErr)
			}
		}
		children = append(children, enc_cellidorsai...)
	}
	if v.SaiPresent != nil {
		enc_saipresent := ber.EncodeNull()
		retagged_enc_saipresent, tagErr_enc_saipresent := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 7, enc_saipresent)
		if tagErr_enc_saipresent != nil {
			return nil, fmt.Errorf("encoding sai-Present: %w", tagErr_enc_saipresent)
		}
		enc_saipresent = retagged_enc_saipresent
		children = append(children, enc_saipresent...)
	}
	if v.AccuracyFulfilmentIndicator != nil {
		enc_accuracyfulfilmentindicator := ber.EncodeEnumerated(int64(*v.AccuracyFulfilmentIndicator))
		retagged_enc_accuracyfulfilmentindicator, tagErr_enc_accuracyfulfilmentindicator := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 8, enc_accuracyfulfilmentindicator)
		if tagErr_enc_accuracyfulfilmentindicator != nil {
			return nil, fmt.Errorf("encoding accuracyFulfilmentIndicator: %w", tagErr_enc_accuracyfulfilmentindicator)
		}
		enc_accuracyfulfilmentindicator = retagged_enc_accuracyfulfilmentindicator
		children = append(children, enc_accuracyfulfilmentindicator...)
	}
	if v.VelocityEstimate != nil {
		if len(*v.VelocityEstimate) < 4 || len(*v.VelocityEstimate) > 7 {
			if constraintErr := ber.CheckEncodedLength(opts, "velocityEstimate", "SIZE (4..7)", len(*v.VelocityEstimate)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_velocityestimate, encodeErr_enc_velocityestimate := ber.EncodeOctetString([]byte(*v.VelocityEstimate))
		if encodeErr_enc_velocityestimate != nil {
			return nil, fmt.Errorf("encoding velocityEstimate: %w", encodeErr_enc_velocityestimate)
		}
		retagged_enc_velocityestimate, tagErr_enc_velocityestimate := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 9, enc_velocityestimate)
		if tagErr_enc_velocityestimate != nil {
			return nil, fmt.Errorf("encoding velocityEstimate: %w", tagErr_enc_velocityestimate)
		}
		enc_velocityestimate = retagged_enc_velocityestimate
		children = append(children, enc_velocityestimate...)
	}
	if v.MoLrShortCircuitIndicator != nil {
		enc_molrshortcircuitindicator := ber.EncodeNull()
		retagged_enc_molrshortcircuitindicator, tagErr_enc_molrshortcircuitindicator := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 10, enc_molrshortcircuitindicator)
		if tagErr_enc_molrshortcircuitindicator != nil {
			return nil, fmt.Errorf("encoding mo-lrShortCircuitIndicator: %w", tagErr_enc_molrshortcircuitindicator)
		}
		enc_molrshortcircuitindicator = retagged_enc_molrshortcircuitindicator
		children = append(children, enc_molrshortcircuitindicator...)
	}
	if v.GeranGANSSpositioningData != nil {
		if len(*v.GeranGANSSpositioningData) < 2 || len(*v.GeranGANSSpositioningData) > 10 {
			if constraintErr := ber.CheckEncodedLength(opts, "geranGANSSpositioningData", "SIZE (2..10)", len(*v.GeranGANSSpositioningData)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_gerangansspositioningdata, encodeErr_enc_gerangansspositioningdata := ber.EncodeOctetString([]byte(*v.GeranGANSSpositioningData))
		if encodeErr_enc_gerangansspositioningdata != nil {
			return nil, fmt.Errorf("encoding geranGANSSpositioningData: %w", encodeErr_enc_gerangansspositioningdata)
		}
		retagged_enc_gerangansspositioningdata, tagErr_enc_gerangansspositioningdata := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 11, enc_gerangansspositioningdata)
		if tagErr_enc_gerangansspositioningdata != nil {
			return nil, fmt.Errorf("encoding geranGANSSpositioningData: %w", tagErr_enc_gerangansspositioningdata)
		}
		enc_gerangansspositioningdata = retagged_enc_gerangansspositioningdata
		children = append(children, enc_gerangansspositioningdata...)
	}
	if v.UtranGANSSpositioningData != nil {
		if len(*v.UtranGANSSpositioningData) < 1 || len(*v.UtranGANSSpositioningData) > 9 {
			if constraintErr := ber.CheckEncodedLength(opts, "utranGANSSpositioningData", "SIZE (1..9)", len(*v.UtranGANSSpositioningData)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_utrangansspositioningdata, encodeErr_enc_utrangansspositioningdata := ber.EncodeOctetString([]byte(*v.UtranGANSSpositioningData))
		if encodeErr_enc_utrangansspositioningdata != nil {
			return nil, fmt.Errorf("encoding utranGANSSpositioningData: %w", encodeErr_enc_utrangansspositioningdata)
		}
		retagged_enc_utrangansspositioningdata, tagErr_enc_utrangansspositioningdata := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 12, enc_utrangansspositioningdata)
		if tagErr_enc_utrangansspositioningdata != nil {
			return nil, fmt.Errorf("encoding utranGANSSpositioningData: %w", tagErr_enc_utrangansspositioningdata)
		}
		enc_utrangansspositioningdata = retagged_enc_utrangansspositioningdata
		children = append(children, enc_utrangansspositioningdata...)
	}
	if v.TargetServingNodeForHandover != nil {
		enc_targetservingnodeforhandover, err := v.TargetServingNodeForHandover.MarshalBER(ber.ChildEncodeOptions(opts, "targetServingNodeForHandover")...)
		if err != nil {
			return nil, fmt.Errorf("encoding targetServingNodeForHandover: %w", err)
		}
		{
			var encodeErr error
			enc_targetservingnodeforhandover, encodeErr = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 13, enc_targetservingnodeforhandover)
			if encodeErr != nil {
				return nil, fmt.Errorf("encoding targetServingNodeForHandover: %w", encodeErr)
			}
		}
		children = append(children, enc_targetservingnodeforhandover...)
	}
	if v.UtranAdditionalPositioningData != nil {
		if len(*v.UtranAdditionalPositioningData) < 1 || len(*v.UtranAdditionalPositioningData) > 8 {
			if constraintErr := ber.CheckEncodedLength(opts, "utranAdditionalPositioningData", "SIZE (1..8)", len(*v.UtranAdditionalPositioningData)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_utranadditionalpositioningdata, encodeErr_enc_utranadditionalpositioningdata := ber.EncodeOctetString([]byte(*v.UtranAdditionalPositioningData))
		if encodeErr_enc_utranadditionalpositioningdata != nil {
			return nil, fmt.Errorf("encoding utranAdditionalPositioningData: %w", encodeErr_enc_utranadditionalpositioningdata)
		}
		retagged_enc_utranadditionalpositioningdata, tagErr_enc_utranadditionalpositioningdata := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 14, enc_utranadditionalpositioningdata)
		if tagErr_enc_utranadditionalpositioningdata != nil {
			return nil, fmt.Errorf("encoding utranAdditionalPositioningData: %w", tagErr_enc_utranadditionalpositioningdata)
		}
		enc_utranadditionalpositioningdata = retagged_enc_utranadditionalpositioningdata
		children = append(children, enc_utranadditionalpositioningdata...)
	}
	if v.UtranBaroPressureMeas != nil {
		if !(int64(*v.UtranBaroPressureMeas) >= 30000 && int64(*v.UtranBaroPressureMeas) <= 115000) {
			if constraintErr := ber.CheckEncodedValue(opts, "utranBaroPressureMeas", "(30000..115000)", fmt.Sprint(int64(*v.UtranBaroPressureMeas))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_utranbaropressuremeas := ber.EncodeInteger(int64(*v.UtranBaroPressureMeas))
		retagged_enc_utranbaropressuremeas, tagErr_enc_utranbaropressuremeas := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 15, enc_utranbaropressuremeas)
		if tagErr_enc_utranbaropressuremeas != nil {
			return nil, fmt.Errorf("encoding utranBaroPressureMeas: %w", tagErr_enc_utranbaropressuremeas)
		}
		enc_utranbaropressuremeas = retagged_enc_utranbaropressuremeas
		children = append(children, enc_utranbaropressuremeas...)
	}
	if v.UtranCivicAddress != nil {
		enc_utrancivicaddress, encodeErr_enc_utrancivicaddress := ber.EncodeOctetString([]byte(*v.UtranCivicAddress))
		if encodeErr_enc_utrancivicaddress != nil {
			return nil, fmt.Errorf("encoding utranCivicAddress: %w", encodeErr_enc_utrancivicaddress)
		}
		retagged_enc_utrancivicaddress, tagErr_enc_utrancivicaddress := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 16, enc_utrancivicaddress)
		if tagErr_enc_utrancivicaddress != nil {
			return nil, fmt.Errorf("encoding utranCivicAddress: %w", tagErr_enc_utrancivicaddress)
		}
		enc_utrancivicaddress = retagged_enc_utrancivicaddress
		children = append(children, enc_utrancivicaddress...)
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

// MarshalDER encodes LCSProvideSubscriberLocationRes to DER format.
func (v *LCSProvideSubscriberLocationRes) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: LCSProvideSubscriberLocationRes receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if len(v.LocationEstimate) < 1 || len(v.LocationEstimate) > 20 {
		if constraintErr := ber.CheckEncodedLength(nil, "locationEstimate", "SIZE (1..20)", len(v.LocationEstimate)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_locationestimate, encodeErr_enc_locationestimate := ber.EncodeOctetString([]byte(v.LocationEstimate))
	if encodeErr_enc_locationestimate != nil {
		return nil, fmt.Errorf("encoding locationEstimate: %w", encodeErr_enc_locationestimate)
	}
	children = append(children, enc_locationestimate...)
	if v.AgeOfLocationEstimate != nil {
		if !(int64(*v.AgeOfLocationEstimate) >= 0 && int64(*v.AgeOfLocationEstimate) <= 32767) {
			if constraintErr := ber.CheckEncodedValue(nil, "ageOfLocationEstimate", "(0..32767)", fmt.Sprint(int64(*v.AgeOfLocationEstimate))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_ageoflocationestimate := ber.EncodeInteger(int64(*v.AgeOfLocationEstimate))
		retagged_enc_ageoflocationestimate, tagErr_enc_ageoflocationestimate := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_ageoflocationestimate)
		if tagErr_enc_ageoflocationestimate != nil {
			return nil, fmt.Errorf("encoding ageOfLocationEstimate: %w", tagErr_enc_ageoflocationestimate)
		}
		enc_ageoflocationestimate = retagged_enc_ageoflocationestimate
		children = append(children, enc_ageoflocationestimate...)
	}
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding extensionContainer: %w", err)
		}
		retagged_enc_extensioncontainer, tagErr_enc_extensioncontainer := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_extensioncontainer)
		if tagErr_enc_extensioncontainer != nil {
			return nil, fmt.Errorf("encoding extensionContainer: %w", tagErr_enc_extensioncontainer)
		}
		enc_extensioncontainer = retagged_enc_extensioncontainer
		children = append(children, enc_extensioncontainer...)
	}
	if v.AddLocationEstimate != nil {
		if len(*v.AddLocationEstimate) < 1 || len(*v.AddLocationEstimate) > 91 {
			if constraintErr := ber.CheckEncodedLength(nil, "add-LocationEstimate", "SIZE (1..91)", len(*v.AddLocationEstimate)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_addlocationestimate, encodeErr_enc_addlocationestimate := ber.EncodeOctetString([]byte(*v.AddLocationEstimate))
		if encodeErr_enc_addlocationestimate != nil {
			return nil, fmt.Errorf("encoding add-LocationEstimate: %w", encodeErr_enc_addlocationestimate)
		}
		retagged_enc_addlocationestimate, tagErr_enc_addlocationestimate := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_addlocationestimate)
		if tagErr_enc_addlocationestimate != nil {
			return nil, fmt.Errorf("encoding add-LocationEstimate: %w", tagErr_enc_addlocationestimate)
		}
		enc_addlocationestimate = retagged_enc_addlocationestimate
		children = append(children, enc_addlocationestimate...)
	}
	if v.DeferredmtLrResponseIndicator != nil {
		enc_deferredmtlrresponseindicator := ber.EncodeNull()
		retagged_enc_deferredmtlrresponseindicator, tagErr_enc_deferredmtlrresponseindicator := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, enc_deferredmtlrresponseindicator)
		if tagErr_enc_deferredmtlrresponseindicator != nil {
			return nil, fmt.Errorf("encoding deferredmt-lrResponseIndicator: %w", tagErr_enc_deferredmtlrresponseindicator)
		}
		enc_deferredmtlrresponseindicator = retagged_enc_deferredmtlrresponseindicator
		children = append(children, enc_deferredmtlrresponseindicator...)
	}
	if v.GeranPositioningData != nil {
		if len(*v.GeranPositioningData) < 2 || len(*v.GeranPositioningData) > 10 {
			if constraintErr := ber.CheckEncodedLength(nil, "geranPositioningData", "SIZE (2..10)", len(*v.GeranPositioningData)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_geranpositioningdata, encodeErr_enc_geranpositioningdata := ber.EncodeOctetString([]byte(*v.GeranPositioningData))
		if encodeErr_enc_geranpositioningdata != nil {
			return nil, fmt.Errorf("encoding geranPositioningData: %w", encodeErr_enc_geranpositioningdata)
		}
		retagged_enc_geranpositioningdata, tagErr_enc_geranpositioningdata := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, enc_geranpositioningdata)
		if tagErr_enc_geranpositioningdata != nil {
			return nil, fmt.Errorf("encoding geranPositioningData: %w", tagErr_enc_geranpositioningdata)
		}
		enc_geranpositioningdata = retagged_enc_geranpositioningdata
		children = append(children, enc_geranpositioningdata...)
	}
	if v.UtranPositioningData != nil {
		if len(*v.UtranPositioningData) < 3 || len(*v.UtranPositioningData) > 11 {
			if constraintErr := ber.CheckEncodedLength(nil, "utranPositioningData", "SIZE (3..11)", len(*v.UtranPositioningData)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_utranpositioningdata, encodeErr_enc_utranpositioningdata := ber.EncodeOctetString([]byte(*v.UtranPositioningData))
		if encodeErr_enc_utranpositioningdata != nil {
			return nil, fmt.Errorf("encoding utranPositioningData: %w", encodeErr_enc_utranpositioningdata)
		}
		retagged_enc_utranpositioningdata, tagErr_enc_utranpositioningdata := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 5, enc_utranpositioningdata)
		if tagErr_enc_utranpositioningdata != nil {
			return nil, fmt.Errorf("encoding utranPositioningData: %w", tagErr_enc_utranpositioningdata)
		}
		enc_utranpositioningdata = retagged_enc_utranpositioningdata
		children = append(children, enc_utranpositioningdata...)
	}
	if v.CellIdOrSai != nil {
		enc_cellidorsai, err := v.CellIdOrSai.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding cellIdOrSai: %w", err)
		}
		{
			var encodeErr error
			enc_cellidorsai, encodeErr = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 6, enc_cellidorsai)
			if encodeErr != nil {
				return nil, fmt.Errorf("encoding cellIdOrSai: %w", encodeErr)
			}
		}
		children = append(children, enc_cellidorsai...)
	}
	if v.SaiPresent != nil {
		enc_saipresent := ber.EncodeNull()
		retagged_enc_saipresent, tagErr_enc_saipresent := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 7, enc_saipresent)
		if tagErr_enc_saipresent != nil {
			return nil, fmt.Errorf("encoding sai-Present: %w", tagErr_enc_saipresent)
		}
		enc_saipresent = retagged_enc_saipresent
		children = append(children, enc_saipresent...)
	}
	if v.AccuracyFulfilmentIndicator != nil {
		enc_accuracyfulfilmentindicator := ber.EncodeEnumerated(int64(*v.AccuracyFulfilmentIndicator))
		retagged_enc_accuracyfulfilmentindicator, tagErr_enc_accuracyfulfilmentindicator := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 8, enc_accuracyfulfilmentindicator)
		if tagErr_enc_accuracyfulfilmentindicator != nil {
			return nil, fmt.Errorf("encoding accuracyFulfilmentIndicator: %w", tagErr_enc_accuracyfulfilmentindicator)
		}
		enc_accuracyfulfilmentindicator = retagged_enc_accuracyfulfilmentindicator
		children = append(children, enc_accuracyfulfilmentindicator...)
	}
	if v.VelocityEstimate != nil {
		if len(*v.VelocityEstimate) < 4 || len(*v.VelocityEstimate) > 7 {
			if constraintErr := ber.CheckEncodedLength(nil, "velocityEstimate", "SIZE (4..7)", len(*v.VelocityEstimate)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_velocityestimate, encodeErr_enc_velocityestimate := ber.EncodeOctetString([]byte(*v.VelocityEstimate))
		if encodeErr_enc_velocityestimate != nil {
			return nil, fmt.Errorf("encoding velocityEstimate: %w", encodeErr_enc_velocityestimate)
		}
		retagged_enc_velocityestimate, tagErr_enc_velocityestimate := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 9, enc_velocityestimate)
		if tagErr_enc_velocityestimate != nil {
			return nil, fmt.Errorf("encoding velocityEstimate: %w", tagErr_enc_velocityestimate)
		}
		enc_velocityestimate = retagged_enc_velocityestimate
		children = append(children, enc_velocityestimate...)
	}
	if v.MoLrShortCircuitIndicator != nil {
		enc_molrshortcircuitindicator := ber.EncodeNull()
		retagged_enc_molrshortcircuitindicator, tagErr_enc_molrshortcircuitindicator := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 10, enc_molrshortcircuitindicator)
		if tagErr_enc_molrshortcircuitindicator != nil {
			return nil, fmt.Errorf("encoding mo-lrShortCircuitIndicator: %w", tagErr_enc_molrshortcircuitindicator)
		}
		enc_molrshortcircuitindicator = retagged_enc_molrshortcircuitindicator
		children = append(children, enc_molrshortcircuitindicator...)
	}
	if v.GeranGANSSpositioningData != nil {
		if len(*v.GeranGANSSpositioningData) < 2 || len(*v.GeranGANSSpositioningData) > 10 {
			if constraintErr := ber.CheckEncodedLength(nil, "geranGANSSpositioningData", "SIZE (2..10)", len(*v.GeranGANSSpositioningData)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_gerangansspositioningdata, encodeErr_enc_gerangansspositioningdata := ber.EncodeOctetString([]byte(*v.GeranGANSSpositioningData))
		if encodeErr_enc_gerangansspositioningdata != nil {
			return nil, fmt.Errorf("encoding geranGANSSpositioningData: %w", encodeErr_enc_gerangansspositioningdata)
		}
		retagged_enc_gerangansspositioningdata, tagErr_enc_gerangansspositioningdata := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 11, enc_gerangansspositioningdata)
		if tagErr_enc_gerangansspositioningdata != nil {
			return nil, fmt.Errorf("encoding geranGANSSpositioningData: %w", tagErr_enc_gerangansspositioningdata)
		}
		enc_gerangansspositioningdata = retagged_enc_gerangansspositioningdata
		children = append(children, enc_gerangansspositioningdata...)
	}
	if v.UtranGANSSpositioningData != nil {
		if len(*v.UtranGANSSpositioningData) < 1 || len(*v.UtranGANSSpositioningData) > 9 {
			if constraintErr := ber.CheckEncodedLength(nil, "utranGANSSpositioningData", "SIZE (1..9)", len(*v.UtranGANSSpositioningData)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_utrangansspositioningdata, encodeErr_enc_utrangansspositioningdata := ber.EncodeOctetString([]byte(*v.UtranGANSSpositioningData))
		if encodeErr_enc_utrangansspositioningdata != nil {
			return nil, fmt.Errorf("encoding utranGANSSpositioningData: %w", encodeErr_enc_utrangansspositioningdata)
		}
		retagged_enc_utrangansspositioningdata, tagErr_enc_utrangansspositioningdata := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 12, enc_utrangansspositioningdata)
		if tagErr_enc_utrangansspositioningdata != nil {
			return nil, fmt.Errorf("encoding utranGANSSpositioningData: %w", tagErr_enc_utrangansspositioningdata)
		}
		enc_utrangansspositioningdata = retagged_enc_utrangansspositioningdata
		children = append(children, enc_utrangansspositioningdata...)
	}
	if v.TargetServingNodeForHandover != nil {
		enc_targetservingnodeforhandover, err := v.TargetServingNodeForHandover.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding targetServingNodeForHandover: %w", err)
		}
		{
			var encodeErr error
			enc_targetservingnodeforhandover, encodeErr = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 13, enc_targetservingnodeforhandover)
			if encodeErr != nil {
				return nil, fmt.Errorf("encoding targetServingNodeForHandover: %w", encodeErr)
			}
		}
		children = append(children, enc_targetservingnodeforhandover...)
	}
	if v.UtranAdditionalPositioningData != nil {
		if len(*v.UtranAdditionalPositioningData) < 1 || len(*v.UtranAdditionalPositioningData) > 8 {
			if constraintErr := ber.CheckEncodedLength(nil, "utranAdditionalPositioningData", "SIZE (1..8)", len(*v.UtranAdditionalPositioningData)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_utranadditionalpositioningdata, encodeErr_enc_utranadditionalpositioningdata := ber.EncodeOctetString([]byte(*v.UtranAdditionalPositioningData))
		if encodeErr_enc_utranadditionalpositioningdata != nil {
			return nil, fmt.Errorf("encoding utranAdditionalPositioningData: %w", encodeErr_enc_utranadditionalpositioningdata)
		}
		retagged_enc_utranadditionalpositioningdata, tagErr_enc_utranadditionalpositioningdata := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 14, enc_utranadditionalpositioningdata)
		if tagErr_enc_utranadditionalpositioningdata != nil {
			return nil, fmt.Errorf("encoding utranAdditionalPositioningData: %w", tagErr_enc_utranadditionalpositioningdata)
		}
		enc_utranadditionalpositioningdata = retagged_enc_utranadditionalpositioningdata
		children = append(children, enc_utranadditionalpositioningdata...)
	}
	if v.UtranBaroPressureMeas != nil {
		if !(int64(*v.UtranBaroPressureMeas) >= 30000 && int64(*v.UtranBaroPressureMeas) <= 115000) {
			if constraintErr := ber.CheckEncodedValue(nil, "utranBaroPressureMeas", "(30000..115000)", fmt.Sprint(int64(*v.UtranBaroPressureMeas))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_utranbaropressuremeas := ber.EncodeInteger(int64(*v.UtranBaroPressureMeas))
		retagged_enc_utranbaropressuremeas, tagErr_enc_utranbaropressuremeas := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 15, enc_utranbaropressuremeas)
		if tagErr_enc_utranbaropressuremeas != nil {
			return nil, fmt.Errorf("encoding utranBaroPressureMeas: %w", tagErr_enc_utranbaropressuremeas)
		}
		enc_utranbaropressuremeas = retagged_enc_utranbaropressuremeas
		children = append(children, enc_utranbaropressuremeas...)
	}
	if v.UtranCivicAddress != nil {
		enc_utrancivicaddress, encodeErr_enc_utrancivicaddress := ber.EncodeOctetString([]byte(*v.UtranCivicAddress))
		if encodeErr_enc_utrancivicaddress != nil {
			return nil, fmt.Errorf("encoding utranCivicAddress: %w", encodeErr_enc_utrancivicaddress)
		}
		retagged_enc_utrancivicaddress, tagErr_enc_utrancivicaddress := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 16, enc_utrancivicaddress)
		if tagErr_enc_utrancivicaddress != nil {
			return nil, fmt.Errorf("encoding utranCivicAddress: %w", tagErr_enc_utrancivicaddress)
		}
		enc_utrancivicaddress = retagged_enc_utrancivicaddress
		children = append(children, enc_utrancivicaddress...)
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
		return nil, fmt.Errorf("encoding LCSProvideSubscriberLocationRes as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes LCSProvideSubscriberLocationRes from BER/DER format.
func (v *LCSProvideSubscriberLocationRes) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: LCSProvideSubscriberLocationRes destination is nil", ber.ErrInvalidValue)
	}
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = LCSProvideSubscriberLocationRes{}
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
		return fmt.Errorf("decoding LCSProvideSubscriberLocationRes SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "LCSProvideSubscriberLocationRes", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode locationEstimate
	if offset >= len(content) {
		return fmt.Errorf("missing required field locationEstimate")
	}
	val_locationestimate, n, err := ber.DecodeOctetString(content[offset:], opts...)
	if err != nil {
		return fmt.Errorf("decoding locationEstimate: %w", err)
	}
	v.LocationEstimate = LCSExtGeographicalInformation(val_locationestimate)
	if offset < 0 || offset >
		len(content) || n < 0 || n > len(content[offset:]) {
		return fmt.Errorf("invalid BER content window")
	}

	offset += n
	if len(v.LocationEstimate) < 1 || len(v.LocationEstimate) > 20 {
		if constraintErr := ber.CheckDecodedLength(opts, "locationEstimate", "SIZE (1..20)", len(v.LocationEstimate)); constraintErr != nil {
			return constraintErr
		}
	}
	// Decode ageOfLocationEstimate
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
				decodedTag_ageoflocationestimate, n_ageoflocationestimate, rawVal_ageoflocationestimate, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding ageOfLocationEstimate: %w", err)
				}
				if decodedTag_ageoflocationestimate.Class != tag.ClassContextSpecific || decodedTag_ageoflocationestimate.Number != 0 || decodedTag_ageoflocationestimate.Constructed != false {
					return fmt.Errorf("decoding ageOfLocationEstimate: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_ageoflocationestimate)
				}
				decVal_ageoflocationestimate, intErr := ber.DecodeIntegerValue(rawVal_ageoflocationestimate)
				if intErr != nil {
					return fmt.Errorf("decoding ageOfLocationEstimate: %w", intErr)
				}
				tmp_ageoflocationestimate := AgeOfLocationInformation3(decVal_ageoflocationestimate)
				v.AgeOfLocationEstimate = &tmp_ageoflocationestimate
				if offset < 0 || offset >
					len(content) || n_ageoflocationestimate < 0 || n_ageoflocationestimate >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_ageoflocationestimate
				if !(int64(*v.AgeOfLocationEstimate) >= 0 && int64(*v.AgeOfLocationEstimate) <= 32767) {
					if constraintErr := ber.CheckDecodedValue(opts, "ageOfLocationEstimate", "(0..32767)", fmt.Sprint(int64(*v.AgeOfLocationEstimate))); constraintErr != nil {
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
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
				decodedTag_extensioncontainer, n_extensioncontainer, rawVal_extensioncontainer, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding extensionContainer: %w", err)
				}
				if decodedTag_extensioncontainer.Class != tag.ClassContextSpecific || decodedTag_extensioncontainer.Number != 1 || decodedTag_extensioncontainer.Constructed != true {
					return fmt.Errorf("decoding extensionContainer: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_extensioncontainer)
				}
				reconstructed_extensioncontainer, reconstructionErr_extensioncontainer := ber.EncodeSequence(rawVal_extensioncontainer)
				if reconstructionErr_extensioncontainer != nil {
					return fmt.Errorf("decoding extensionContainer: %w", reconstructionErr_extensioncontainer)
				}
				var dec_extensioncontainer ExtensionContainer3
				if unmErr := dec_extensioncontainer.UnmarshalBER(reconstructed_extensioncontainer, ber.ChildDecodeOptions(opts, "extensionContainer")...); unmErr != nil {
					return fmt.Errorf("decoding extensionContainer: %w", unmErr)
				}
				v.ExtensionContainer = &dec_extensioncontainer
				if offset < 0 || offset >
					len(content) || n_extensioncontainer < 0 || n_extensioncontainer > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_extensioncontainer
			}
		}
	}
	// Decode add-LocationEstimate
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2 {
				decodedTag_addlocationestimate, n_addlocationestimate, rawVal_addlocationestimate, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding add-LocationEstimate: %w", err)
				}
				if decodedTag_addlocationestimate.Class != tag.ClassContextSpecific || decodedTag_addlocationestimate.Number != 2 {
					return fmt.Errorf("decoding add-LocationEstimate: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_addlocationestimate)
				}
				decVal_addlocationestimate, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_addlocationestimate.Constructed, rawVal_addlocationestimate, opts...)
				if octetErr != nil {
					return fmt.Errorf("decoding add-LocationEstimate: %w", octetErr)
				}
				tmp_addlocationestimate := LCSAddGeographicalInformation(decVal_addlocationestimate)
				v.AddLocationEstimate = &tmp_addlocationestimate
				if offset < 0 || offset >
					len(content) || n_addlocationestimate < 0 || n_addlocationestimate > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_addlocationestimate
				if len(*v.AddLocationEstimate) < 1 || len(*v.AddLocationEstimate) > 91 {
					if constraintErr := ber.CheckDecodedLength(opts, "add-LocationEstimate", "SIZE (1..91)", len(*v.AddLocationEstimate)); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode deferredmt-lrResponseIndicator
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3 {
				decodedTag_deferredmtlrresponseindicator, n_deferredmtlrresponseindicator, rawVal_deferredmtlrresponseindicator, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding deferredmt-lrResponseIndicator: %w", err)
				}
				if decodedTag_deferredmtlrresponseindicator.Class != tag.ClassContextSpecific || decodedTag_deferredmtlrresponseindicator.Number != 3 || decodedTag_deferredmtlrresponseindicator.Constructed != false {
					return fmt.Errorf("decoding deferredmt-lrResponseIndicator: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_deferredmtlrresponseindicator)
				}
				if len(rawVal_deferredmtlrresponseindicator) != 0 {
					return fmt.Errorf("decoding deferredmt-lrResponseIndicator: %w: NULL content length %d", ber.ErrInvalidValue, len(rawVal_deferredmtlrresponseindicator))
				}
				v.DeferredmtLrResponseIndicator = &struct{}{}
				if offset < 0 || offset >
					len(content) || n_deferredmtlrresponseindicator < 0 || n_deferredmtlrresponseindicator >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_deferredmtlrresponseindicator
			}
		}
	}
	// Decode geranPositioningData
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4 {
				decodedTag_geranpositioningdata, n_geranpositioningdata, rawVal_geranpositioningdata, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding geranPositioningData: %w", err)
				}
				if decodedTag_geranpositioningdata.Class != tag.ClassContextSpecific || decodedTag_geranpositioningdata.Number != 4 {
					return fmt.Errorf("decoding geranPositioningData: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_geranpositioningdata)
				}
				decVal_geranpositioningdata, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_geranpositioningdata.Constructed, rawVal_geranpositioningdata, opts...)
				if octetErr != nil {
					return fmt.Errorf("decoding geranPositioningData: %w", octetErr)
				}
				tmp_geranpositioningdata := LCSPositioningDataInformation(decVal_geranpositioningdata)
				v.GeranPositioningData = &tmp_geranpositioningdata
				if offset < 0 || offset >
					len(content) || n_geranpositioningdata < 0 || n_geranpositioningdata > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_geranpositioningdata
				if len(*v.GeranPositioningData) < 2 || len(*v.GeranPositioningData) > 10 {
					if constraintErr := ber.CheckDecodedLength(opts, "geranPositioningData", "SIZE (2..10)", len(*v.GeranPositioningData)); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode utranPositioningData
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 5 {
				decodedTag_utranpositioningdata, n_utranpositioningdata, rawVal_utranpositioningdata, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding utranPositioningData: %w", err)
				}
				if decodedTag_utranpositioningdata.Class != tag.ClassContextSpecific || decodedTag_utranpositioningdata.Number != 5 {
					return fmt.Errorf("decoding utranPositioningData: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_utranpositioningdata)
				}
				decVal_utranpositioningdata, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_utranpositioningdata.Constructed, rawVal_utranpositioningdata, opts...)
				if octetErr != nil {
					return fmt.Errorf("decoding utranPositioningData: %w", octetErr)
				}
				tmp_utranpositioningdata := LCSUtranPositioningDataInfo(decVal_utranpositioningdata)
				v.UtranPositioningData = &tmp_utranpositioningdata
				if offset < 0 || offset >
					len(content) || n_utranpositioningdata < 0 || n_utranpositioningdata > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_utranpositioningdata
				if len(*v.UtranPositioningData) < 3 || len(*v.UtranPositioningData) > 11 {
					if constraintErr := ber.CheckDecodedLength(opts, "utranPositioningData", "SIZE (3..11)", len(*v.UtranPositioningData)); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode cellIdOrSai
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 6 {
				decodedTag_cellidorsai, n_cellidorsai, innerData_cellidorsai, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding cellIdOrSai: %w", err)
				}
				if decodedTag_cellidorsai.Class != tag.ClassContextSpecific || decodedTag_cellidorsai.Number != 6 || decodedTag_cellidorsai.Constructed != true {
					return fmt.Errorf("decoding cellIdOrSai: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_cellidorsai)
				}
				// Decode inner value from explicit tag wrapper
				var dec_cellidorsai CellGlobalIdOrServiceAreaIdOrLAI3
				if unmErr := dec_cellidorsai.UnmarshalBER(innerData_cellidorsai, ber.ChildDecodeOptions(opts, "cellIdOrSai")...); unmErr != nil {
					return fmt.Errorf("decoding cellIdOrSai: %w", unmErr)
				}
				v.CellIdOrSai = &dec_cellidorsai
				if offset < 0 || offset >
					len(content) || n_cellidorsai < 0 || n_cellidorsai > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_cellidorsai
			}
		}
	}
	// Decode sai-Present
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 7 {
				decodedTag_saipresent, n_saipresent, rawVal_saipresent, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding sai-Present: %w", err)
				}
				if decodedTag_saipresent.Class != tag.ClassContextSpecific || decodedTag_saipresent.Number != 7 || decodedTag_saipresent.Constructed != false {
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
	// Decode accuracyFulfilmentIndicator
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 8 {
				decodedTag_accuracyfulfilmentindicator, n_accuracyfulfilmentindicator, rawVal_accuracyfulfilmentindicator, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding accuracyFulfilmentIndicator: %w", err)
				}
				if decodedTag_accuracyfulfilmentindicator.Class != tag.ClassContextSpecific || decodedTag_accuracyfulfilmentindicator.Number != 8 || decodedTag_accuracyfulfilmentindicator.Constructed != false {
					return fmt.Errorf("decoding accuracyFulfilmentIndicator: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_accuracyfulfilmentindicator)
				}
				decVal_accuracyfulfilmentindicator, intErr := ber.DecodeEnumeratedValue(rawVal_accuracyfulfilmentindicator)
				if intErr != nil {
					return fmt.Errorf("decoding accuracyFulfilmentIndicator: %w", intErr)
				}
				tmp_accuracyfulfilmentindicator := LCSAccuracyFulfilmentIndicator(decVal_accuracyfulfilmentindicator)
				v.AccuracyFulfilmentIndicator = &tmp_accuracyfulfilmentindicator
				if offset < 0 || offset >
					len(content) || n_accuracyfulfilmentindicator < 0 || n_accuracyfulfilmentindicator >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_accuracyfulfilmentindicator
			}
		}
	}
	// Decode velocityEstimate
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 9 {
				decodedTag_velocityestimate, n_velocityestimate, rawVal_velocityestimate, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding velocityEstimate: %w", err)
				}
				if decodedTag_velocityestimate.Class != tag.ClassContextSpecific || decodedTag_velocityestimate.Number != 9 {
					return fmt.Errorf("decoding velocityEstimate: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_velocityestimate)
				}
				decVal_velocityestimate, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_velocityestimate.Constructed, rawVal_velocityestimate, opts...)
				if octetErr != nil {
					return fmt.Errorf("decoding velocityEstimate: %w", octetErr)
				}
				tmp_velocityestimate := LCSVelocityEstimate(decVal_velocityestimate)
				v.VelocityEstimate = &tmp_velocityestimate
				if offset < 0 || offset >
					len(content) || n_velocityestimate < 0 || n_velocityestimate > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_velocityestimate
				if len(*v.VelocityEstimate) < 4 || len(*v.VelocityEstimate) > 7 {
					if constraintErr := ber.CheckDecodedLength(opts, "velocityEstimate", "SIZE (4..7)", len(*v.VelocityEstimate)); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode mo-lrShortCircuitIndicator
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 10 {
				decodedTag_molrshortcircuitindicator, n_molrshortcircuitindicator, rawVal_molrshortcircuitindicator, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding mo-lrShortCircuitIndicator: %w", err)
				}
				if decodedTag_molrshortcircuitindicator.Class != tag.ClassContextSpecific || decodedTag_molrshortcircuitindicator.Number != 10 || decodedTag_molrshortcircuitindicator.Constructed != false {
					return fmt.Errorf("decoding mo-lrShortCircuitIndicator: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_molrshortcircuitindicator)
				}
				if len(rawVal_molrshortcircuitindicator) != 0 {
					return fmt.Errorf("decoding mo-lrShortCircuitIndicator: %w: NULL content length %d", ber.ErrInvalidValue, len(rawVal_molrshortcircuitindicator))
				}
				v.MoLrShortCircuitIndicator = &struct{}{}
				if offset < 0 || offset >
					len(content) || n_molrshortcircuitindicator < 0 || n_molrshortcircuitindicator >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_molrshortcircuitindicator
			}
		}
	}
	// Decode geranGANSSpositioningData
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 11 {
				decodedTag_gerangansspositioningdata, n_gerangansspositioningdata, rawVal_gerangansspositioningdata, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding geranGANSSpositioningData: %w", err)
				}
				if decodedTag_gerangansspositioningdata.Class != tag.ClassContextSpecific || decodedTag_gerangansspositioningdata.Number != 11 {
					return fmt.Errorf("decoding geranGANSSpositioningData: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_gerangansspositioningdata)
				}
				decVal_gerangansspositioningdata, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_gerangansspositioningdata.Constructed, rawVal_gerangansspositioningdata, opts...)
				if octetErr != nil {
					return fmt.Errorf("decoding geranGANSSpositioningData: %w", octetErr)
				}
				tmp_gerangansspositioningdata := LCSGeranGANSSpositioningData(decVal_gerangansspositioningdata)
				v.GeranGANSSpositioningData = &tmp_gerangansspositioningdata
				if offset < 0 || offset >
					len(content) || n_gerangansspositioningdata < 0 || n_gerangansspositioningdata >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_gerangansspositioningdata
				if len(*v.GeranGANSSpositioningData) < 2 || len(*v.GeranGANSSpositioningData) > 10 {
					if constraintErr := ber.CheckDecodedLength(opts, "geranGANSSpositioningData", "SIZE (2..10)", len(*v.GeranGANSSpositioningData)); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode utranGANSSpositioningData
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 12 {
				decodedTag_utrangansspositioningdata, n_utrangansspositioningdata, rawVal_utrangansspositioningdata, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding utranGANSSpositioningData: %w", err)
				}
				if decodedTag_utrangansspositioningdata.Class != tag.ClassContextSpecific || decodedTag_utrangansspositioningdata.Number != 12 {
					return fmt.Errorf("decoding utranGANSSpositioningData: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_utrangansspositioningdata)
				}
				decVal_utrangansspositioningdata, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_utrangansspositioningdata.Constructed, rawVal_utrangansspositioningdata, opts...)
				if octetErr != nil {
					return fmt.Errorf("decoding utranGANSSpositioningData: %w", octetErr)
				}
				tmp_utrangansspositioningdata := LCSUtranGANSSpositioningData(decVal_utrangansspositioningdata)
				v.UtranGANSSpositioningData = &tmp_utrangansspositioningdata
				if offset < 0 || offset >
					len(content) || n_utrangansspositioningdata < 0 || n_utrangansspositioningdata >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_utrangansspositioningdata
				if len(*v.UtranGANSSpositioningData) < 1 || len(*v.UtranGANSSpositioningData) > 9 {
					if constraintErr := ber.CheckDecodedLength(opts, "utranGANSSpositioningData", "SIZE (1..9)", len(*v.UtranGANSSpositioningData)); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode targetServingNodeForHandover
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 13 {
				decodedTag_targetservingnodeforhandover, n_targetservingnodeforhandover, innerData_targetservingnodeforhandover, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding targetServingNodeForHandover: %w", err)
				}
				if decodedTag_targetservingnodeforhandover.Class != tag.ClassContextSpecific || decodedTag_targetservingnodeforhandover.Number != 13 || decodedTag_targetservingnodeforhandover.Constructed != true {
					return fmt.Errorf("decoding targetServingNodeForHandover: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_targetservingnodeforhandover)
				}
				// Decode inner value from explicit tag wrapper
				var dec_targetservingnodeforhandover LCSServingNodeAddress
				if unmErr := dec_targetservingnodeforhandover.UnmarshalBER(innerData_targetservingnodeforhandover, ber.ChildDecodeOptions(opts, "targetServingNodeForHandover")...); unmErr != nil {
					return fmt.Errorf("decoding targetServingNodeForHandover: %w", unmErr)
				}
				v.TargetServingNodeForHandover = &dec_targetservingnodeforhandover
				if offset < 0 || offset >
					len(content) || n_targetservingnodeforhandover < 0 || n_targetservingnodeforhandover >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_targetservingnodeforhandover
			}
		}
	}
	// Decode utranAdditionalPositioningData
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 14 {
				decodedTag_utranadditionalpositioningdata, n_utranadditionalpositioningdata, rawVal_utranadditionalpositioningdata, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding utranAdditionalPositioningData: %w", err)
				}
				if decodedTag_utranadditionalpositioningdata.Class != tag.ClassContextSpecific || decodedTag_utranadditionalpositioningdata.Number != 14 {
					return fmt.Errorf("decoding utranAdditionalPositioningData: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_utranadditionalpositioningdata)
				}
				decVal_utranadditionalpositioningdata, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_utranadditionalpositioningdata.Constructed, rawVal_utranadditionalpositioningdata, opts...)
				if octetErr != nil {
					return fmt.Errorf("decoding utranAdditionalPositioningData: %w", octetErr)
				}
				tmp_utranadditionalpositioningdata := LCSUtranAdditionalPositioningData(decVal_utranadditionalpositioningdata)
				v.UtranAdditionalPositioningData = &tmp_utranadditionalpositioningdata
				if offset < 0 || offset >
					len(content) || n_utranadditionalpositioningdata < 0 || n_utranadditionalpositioningdata >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_utranadditionalpositioningdata
				if len(*v.UtranAdditionalPositioningData) < 1 || len(*v.UtranAdditionalPositioningData) > 8 {
					if constraintErr := ber.CheckDecodedLength(opts, "utranAdditionalPositioningData", "SIZE (1..8)", len(*v.UtranAdditionalPositioningData)); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode utranBaroPressureMeas
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 15 {
				decodedTag_utranbaropressuremeas, n_utranbaropressuremeas, rawVal_utranbaropressuremeas, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding utranBaroPressureMeas: %w", err)
				}
				if decodedTag_utranbaropressuremeas.Class != tag.ClassContextSpecific || decodedTag_utranbaropressuremeas.Number != 15 || decodedTag_utranbaropressuremeas.Constructed != false {
					return fmt.Errorf("decoding utranBaroPressureMeas: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_utranbaropressuremeas)
				}
				decVal_utranbaropressuremeas, intErr := ber.DecodeIntegerValue(rawVal_utranbaropressuremeas)
				if intErr != nil {
					return fmt.Errorf("decoding utranBaroPressureMeas: %w", intErr)
				}
				tmp_utranbaropressuremeas := LCSUtranBaroPressureMeas(decVal_utranbaropressuremeas)
				v.UtranBaroPressureMeas = &tmp_utranbaropressuremeas
				if offset < 0 || offset >
					len(content) || n_utranbaropressuremeas < 0 || n_utranbaropressuremeas >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_utranbaropressuremeas
				if !(int64(*v.UtranBaroPressureMeas) >= 30000 && int64(*v.UtranBaroPressureMeas) <= 115000) {
					if constraintErr := ber.CheckDecodedValue(opts, "utranBaroPressureMeas", "(30000..115000)", fmt.Sprint(int64(*v.UtranBaroPressureMeas))); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode utranCivicAddress
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 16 {
				decodedTag_utrancivicaddress, n_utrancivicaddress, rawVal_utrancivicaddress, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding utranCivicAddress: %w", err)
				}
				if decodedTag_utrancivicaddress.Class != tag.ClassContextSpecific || decodedTag_utrancivicaddress.Number != 16 {
					return fmt.Errorf("decoding utranCivicAddress: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_utrancivicaddress)
				}
				decVal_utrancivicaddress, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_utrancivicaddress.Constructed, rawVal_utrancivicaddress, opts...)
				if octetErr != nil {
					return fmt.Errorf("decoding utranCivicAddress: %w", octetErr)
				}
				tmp_utrancivicaddress := LCSUtranCivicAddress(decVal_utrancivicaddress)
				v.UtranCivicAddress = &tmp_utrancivicaddress
				if offset < 0 || offset >
					len(content) || n_utrancivicaddress < 0 || n_utrancivicaddress > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_utrancivicaddress
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:], opts...)
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "LCSProvideSubscriberLocationRes", Cause: extErr_}
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

// MarshalBER encodes LCSSubscriberLocationReportArg to BER format.
func (v *LCSSubscriberLocationReportArg) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: LCSSubscriberLocationReportArg receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *LCSSubscriberLocationReportArg) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	enc_lcsevent := ber.EncodeEnumerated(int64(v.LcsEvent))
	children = append(children, enc_lcsevent...)
	enc_lcsclientid, err := v.LcsClientID.MarshalBER(ber.ChildEncodeOptions(opts, "lcs-ClientID")...)
	if err != nil {
		return nil, fmt.Errorf("encoding lcs-ClientID: %w", err)
	}
	children = append(children, enc_lcsclientid...)
	enc_lcslocationinfo, err := v.LcsLocationInfo.MarshalBER(ber.ChildEncodeOptions(opts, "lcsLocationInfo")...)
	if err != nil {
		return nil, fmt.Errorf("encoding lcsLocationInfo: %w", err)
	}
	children = append(children, enc_lcslocationinfo...)
	if v.Msisdn != nil {
		if len(*v.Msisdn) < 1 || len(*v.Msisdn) > 9 {
			if constraintErr := ber.CheckEncodedLength(opts, "msisdn", "SIZE (1..9)", len(*v.Msisdn)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		if len(*v.Msisdn) < 1 || len(*v.Msisdn) > 20 {
			if constraintErr := ber.CheckEncodedLength(opts, "msisdn", "SIZE (1..20)", len(*v.Msisdn)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_msisdn, encodeErr_enc_msisdn := ber.EncodeOctetString([]byte(*v.Msisdn))
		if encodeErr_enc_msisdn != nil {
			return nil, fmt.Errorf("encoding msisdn: %w", encodeErr_enc_msisdn)
		}
		retagged_enc_msisdn, tagErr_enc_msisdn := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_msisdn)
		if tagErr_enc_msisdn != nil {
			return nil, fmt.Errorf("encoding msisdn: %w", tagErr_enc_msisdn)
		}
		enc_msisdn = retagged_enc_msisdn
		children = append(children, enc_msisdn...)
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
	if v.Imei != nil {
		if len(*v.Imei) < 8 || len(*v.Imei) > 8 {
			if constraintErr := ber.CheckEncodedLength(opts, "imei", "SIZE (8)", len(*v.Imei)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_imei, encodeErr_enc_imei := ber.EncodeOctetString([]byte(*v.Imei))
		if encodeErr_enc_imei != nil {
			return nil, fmt.Errorf("encoding imei: %w", encodeErr_enc_imei)
		}
		retagged_enc_imei, tagErr_enc_imei := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_imei)
		if tagErr_enc_imei != nil {
			return nil, fmt.Errorf("encoding imei: %w", tagErr_enc_imei)
		}
		enc_imei = retagged_enc_imei
		children = append(children, enc_imei...)
	}
	if v.NaESRD != nil {
		if len(*v.NaESRD) < 1 || len(*v.NaESRD) > 9 {
			if constraintErr := ber.CheckEncodedLength(opts, "na-ESRD", "SIZE (1..9)", len(*v.NaESRD)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		if len(*v.NaESRD) < 1 || len(*v.NaESRD) > 20 {
			if constraintErr := ber.CheckEncodedLength(opts, "na-ESRD", "SIZE (1..20)", len(*v.NaESRD)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_naesrd, encodeErr_enc_naesrd := ber.EncodeOctetString([]byte(*v.NaESRD))
		if encodeErr_enc_naesrd != nil {
			return nil, fmt.Errorf("encoding na-ESRD: %w", encodeErr_enc_naesrd)
		}
		retagged_enc_naesrd, tagErr_enc_naesrd := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, enc_naesrd)
		if tagErr_enc_naesrd != nil {
			return nil, fmt.Errorf("encoding na-ESRD: %w", tagErr_enc_naesrd)
		}
		enc_naesrd = retagged_enc_naesrd
		children = append(children, enc_naesrd...)
	}
	if v.NaESRK != nil {
		if len(*v.NaESRK) < 1 || len(*v.NaESRK) > 9 {
			if constraintErr := ber.CheckEncodedLength(opts, "na-ESRK", "SIZE (1..9)", len(*v.NaESRK)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		if len(*v.NaESRK) < 1 || len(*v.NaESRK) > 20 {
			if constraintErr := ber.CheckEncodedLength(opts, "na-ESRK", "SIZE (1..20)", len(*v.NaESRK)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_naesrk, encodeErr_enc_naesrk := ber.EncodeOctetString([]byte(*v.NaESRK))
		if encodeErr_enc_naesrk != nil {
			return nil, fmt.Errorf("encoding na-ESRK: %w", encodeErr_enc_naesrk)
		}
		retagged_enc_naesrk, tagErr_enc_naesrk := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, enc_naesrk)
		if tagErr_enc_naesrk != nil {
			return nil, fmt.Errorf("encoding na-ESRK: %w", tagErr_enc_naesrk)
		}
		enc_naesrk = retagged_enc_naesrk
		children = append(children, enc_naesrk...)
	}
	if v.LocationEstimate != nil {
		if len(*v.LocationEstimate) < 1 || len(*v.LocationEstimate) > 20 {
			if constraintErr := ber.CheckEncodedLength(opts, "locationEstimate", "SIZE (1..20)", len(*v.LocationEstimate)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_locationestimate, encodeErr_enc_locationestimate := ber.EncodeOctetString([]byte(*v.LocationEstimate))
		if encodeErr_enc_locationestimate != nil {
			return nil, fmt.Errorf("encoding locationEstimate: %w", encodeErr_enc_locationestimate)
		}
		retagged_enc_locationestimate, tagErr_enc_locationestimate := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 5, enc_locationestimate)
		if tagErr_enc_locationestimate != nil {
			return nil, fmt.Errorf("encoding locationEstimate: %w", tagErr_enc_locationestimate)
		}
		enc_locationestimate = retagged_enc_locationestimate
		children = append(children, enc_locationestimate...)
	}
	if v.AgeOfLocationEstimate != nil {
		if !(int64(*v.AgeOfLocationEstimate) >= 0 && int64(*v.AgeOfLocationEstimate) <= 32767) {
			if constraintErr := ber.CheckEncodedValue(opts, "ageOfLocationEstimate", "(0..32767)", fmt.Sprint(int64(*v.AgeOfLocationEstimate))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_ageoflocationestimate := ber.EncodeInteger(int64(*v.AgeOfLocationEstimate))
		retagged_enc_ageoflocationestimate, tagErr_enc_ageoflocationestimate := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 6, enc_ageoflocationestimate)
		if tagErr_enc_ageoflocationestimate != nil {
			return nil, fmt.Errorf("encoding ageOfLocationEstimate: %w", tagErr_enc_ageoflocationestimate)
		}
		enc_ageoflocationestimate = retagged_enc_ageoflocationestimate
		children = append(children, enc_ageoflocationestimate...)
	}
	if v.SlrArgExtensionContainer != nil {
		enc_slrargextensioncontainer, err := v.SlrArgExtensionContainer.MarshalBER(ber.ChildEncodeOptions(opts, "slr-ArgExtensionContainer")...)
		if err != nil {
			return nil, fmt.Errorf("encoding slr-ArgExtensionContainer: %w", err)
		}
		retagged_enc_slrargextensioncontainer, tagErr_enc_slrargextensioncontainer := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 7, enc_slrargextensioncontainer)
		if tagErr_enc_slrargextensioncontainer != nil {
			return nil, fmt.Errorf("encoding slr-ArgExtensionContainer: %w", tagErr_enc_slrargextensioncontainer)
		}
		enc_slrargextensioncontainer = retagged_enc_slrargextensioncontainer
		children = append(children, enc_slrargextensioncontainer...)
	}
	if v.AddLocationEstimate != nil {
		if len(*v.AddLocationEstimate) < 1 || len(*v.AddLocationEstimate) > 91 {
			if constraintErr := ber.CheckEncodedLength(opts, "add-LocationEstimate", "SIZE (1..91)", len(*v.AddLocationEstimate)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_addlocationestimate, encodeErr_enc_addlocationestimate := ber.EncodeOctetString([]byte(*v.AddLocationEstimate))
		if encodeErr_enc_addlocationestimate != nil {
			return nil, fmt.Errorf("encoding add-LocationEstimate: %w", encodeErr_enc_addlocationestimate)
		}
		retagged_enc_addlocationestimate, tagErr_enc_addlocationestimate := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 8, enc_addlocationestimate)
		if tagErr_enc_addlocationestimate != nil {
			return nil, fmt.Errorf("encoding add-LocationEstimate: %w", tagErr_enc_addlocationestimate)
		}
		enc_addlocationestimate = retagged_enc_addlocationestimate
		children = append(children, enc_addlocationestimate...)
	}
	if v.DeferredmtLrData != nil {
		enc_deferredmtlrdata, err := v.DeferredmtLrData.MarshalBER(ber.ChildEncodeOptions(opts, "deferredmt-lrData")...)
		if err != nil {
			return nil, fmt.Errorf("encoding deferredmt-lrData: %w", err)
		}
		retagged_enc_deferredmtlrdata, tagErr_enc_deferredmtlrdata := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 9, enc_deferredmtlrdata)
		if tagErr_enc_deferredmtlrdata != nil {
			return nil, fmt.Errorf("encoding deferredmt-lrData: %w", tagErr_enc_deferredmtlrdata)
		}
		enc_deferredmtlrdata = retagged_enc_deferredmtlrdata
		children = append(children, enc_deferredmtlrdata...)
	}
	if v.LcsReferenceNumber != nil {
		if len(*v.LcsReferenceNumber) < 1 || len(*v.LcsReferenceNumber) > 1 {
			if constraintErr := ber.CheckEncodedLength(opts, "lcs-ReferenceNumber", "SIZE (1)", len(*v.LcsReferenceNumber)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_lcsreferencenumber, encodeErr_enc_lcsreferencenumber := ber.EncodeOctetString([]byte(*v.LcsReferenceNumber))
		if encodeErr_enc_lcsreferencenumber != nil {
			return nil, fmt.Errorf("encoding lcs-ReferenceNumber: %w", encodeErr_enc_lcsreferencenumber)
		}
		retagged_enc_lcsreferencenumber, tagErr_enc_lcsreferencenumber := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 10, enc_lcsreferencenumber)
		if tagErr_enc_lcsreferencenumber != nil {
			return nil, fmt.Errorf("encoding lcs-ReferenceNumber: %w", tagErr_enc_lcsreferencenumber)
		}
		enc_lcsreferencenumber = retagged_enc_lcsreferencenumber
		children = append(children, enc_lcsreferencenumber...)
	}
	if v.GeranPositioningData != nil {
		if len(*v.GeranPositioningData) < 2 || len(*v.GeranPositioningData) > 10 {
			if constraintErr := ber.CheckEncodedLength(opts, "geranPositioningData", "SIZE (2..10)", len(*v.GeranPositioningData)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_geranpositioningdata, encodeErr_enc_geranpositioningdata := ber.EncodeOctetString([]byte(*v.GeranPositioningData))
		if encodeErr_enc_geranpositioningdata != nil {
			return nil, fmt.Errorf("encoding geranPositioningData: %w", encodeErr_enc_geranpositioningdata)
		}
		retagged_enc_geranpositioningdata, tagErr_enc_geranpositioningdata := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 11, enc_geranpositioningdata)
		if tagErr_enc_geranpositioningdata != nil {
			return nil, fmt.Errorf("encoding geranPositioningData: %w", tagErr_enc_geranpositioningdata)
		}
		enc_geranpositioningdata = retagged_enc_geranpositioningdata
		children = append(children, enc_geranpositioningdata...)
	}
	if v.UtranPositioningData != nil {
		if len(*v.UtranPositioningData) < 3 || len(*v.UtranPositioningData) > 11 {
			if constraintErr := ber.CheckEncodedLength(opts, "utranPositioningData", "SIZE (3..11)", len(*v.UtranPositioningData)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_utranpositioningdata, encodeErr_enc_utranpositioningdata := ber.EncodeOctetString([]byte(*v.UtranPositioningData))
		if encodeErr_enc_utranpositioningdata != nil {
			return nil, fmt.Errorf("encoding utranPositioningData: %w", encodeErr_enc_utranpositioningdata)
		}
		retagged_enc_utranpositioningdata, tagErr_enc_utranpositioningdata := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 12, enc_utranpositioningdata)
		if tagErr_enc_utranpositioningdata != nil {
			return nil, fmt.Errorf("encoding utranPositioningData: %w", tagErr_enc_utranpositioningdata)
		}
		enc_utranpositioningdata = retagged_enc_utranpositioningdata
		children = append(children, enc_utranpositioningdata...)
	}
	if v.CellIdOrSai != nil {
		enc_cellidorsai, err := v.CellIdOrSai.MarshalBER(ber.ChildEncodeOptions(opts, "cellIdOrSai")...)
		if err != nil {
			return nil, fmt.Errorf("encoding cellIdOrSai: %w", err)
		}
		{
			var encodeErr error
			enc_cellidorsai, encodeErr = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 13, enc_cellidorsai)
			if encodeErr != nil {
				return nil, fmt.Errorf("encoding cellIdOrSai: %w", encodeErr)
			}
		}
		children = append(children, enc_cellidorsai...)
	}
	if v.HGmlcAddress != nil {
		if len(*v.HGmlcAddress) < 5 || len(*v.HGmlcAddress) > 17 {
			if constraintErr := ber.CheckEncodedLength(opts, "h-gmlc-Address", "SIZE (5..17)", len(*v.HGmlcAddress)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_hgmlcaddress, encodeErr_enc_hgmlcaddress := ber.EncodeOctetString([]byte(*v.HGmlcAddress))
		if encodeErr_enc_hgmlcaddress != nil {
			return nil, fmt.Errorf("encoding h-gmlc-Address: %w", encodeErr_enc_hgmlcaddress)
		}
		retagged_enc_hgmlcaddress, tagErr_enc_hgmlcaddress := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 14, enc_hgmlcaddress)
		if tagErr_enc_hgmlcaddress != nil {
			return nil, fmt.Errorf("encoding h-gmlc-Address: %w", tagErr_enc_hgmlcaddress)
		}
		enc_hgmlcaddress = retagged_enc_hgmlcaddress
		children = append(children, enc_hgmlcaddress...)
	}
	if v.LcsServiceTypeID != nil {
		if !(int64(*v.LcsServiceTypeID) >= 0 && int64(*v.LcsServiceTypeID) <= 127) {
			if constraintErr := ber.CheckEncodedValue(opts, "lcsServiceTypeID", "(0..127)", fmt.Sprint(int64(*v.LcsServiceTypeID))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_lcsservicetypeid := ber.EncodeInteger(int64(*v.LcsServiceTypeID))
		retagged_enc_lcsservicetypeid, tagErr_enc_lcsservicetypeid := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 15, enc_lcsservicetypeid)
		if tagErr_enc_lcsservicetypeid != nil {
			return nil, fmt.Errorf("encoding lcsServiceTypeID: %w", tagErr_enc_lcsservicetypeid)
		}
		enc_lcsservicetypeid = retagged_enc_lcsservicetypeid
		children = append(children, enc_lcsservicetypeid...)
	}
	if v.SaiPresent != nil {
		enc_saipresent := ber.EncodeNull()
		retagged_enc_saipresent, tagErr_enc_saipresent := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 17, enc_saipresent)
		if tagErr_enc_saipresent != nil {
			return nil, fmt.Errorf("encoding sai-Present: %w", tagErr_enc_saipresent)
		}
		enc_saipresent = retagged_enc_saipresent
		children = append(children, enc_saipresent...)
	}
	if v.PseudonymIndicator != nil {
		enc_pseudonymindicator := ber.EncodeNull()
		retagged_enc_pseudonymindicator, tagErr_enc_pseudonymindicator := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 18, enc_pseudonymindicator)
		if tagErr_enc_pseudonymindicator != nil {
			return nil, fmt.Errorf("encoding pseudonymIndicator: %w", tagErr_enc_pseudonymindicator)
		}
		enc_pseudonymindicator = retagged_enc_pseudonymindicator
		children = append(children, enc_pseudonymindicator...)
	}
	if v.AccuracyFulfilmentIndicator != nil {
		enc_accuracyfulfilmentindicator := ber.EncodeEnumerated(int64(*v.AccuracyFulfilmentIndicator))
		retagged_enc_accuracyfulfilmentindicator, tagErr_enc_accuracyfulfilmentindicator := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 19, enc_accuracyfulfilmentindicator)
		if tagErr_enc_accuracyfulfilmentindicator != nil {
			return nil, fmt.Errorf("encoding accuracyFulfilmentIndicator: %w", tagErr_enc_accuracyfulfilmentindicator)
		}
		enc_accuracyfulfilmentindicator = retagged_enc_accuracyfulfilmentindicator
		children = append(children, enc_accuracyfulfilmentindicator...)
	}
	if v.VelocityEstimate != nil {
		if len(*v.VelocityEstimate) < 4 || len(*v.VelocityEstimate) > 7 {
			if constraintErr := ber.CheckEncodedLength(opts, "velocityEstimate", "SIZE (4..7)", len(*v.VelocityEstimate)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_velocityestimate, encodeErr_enc_velocityestimate := ber.EncodeOctetString([]byte(*v.VelocityEstimate))
		if encodeErr_enc_velocityestimate != nil {
			return nil, fmt.Errorf("encoding velocityEstimate: %w", encodeErr_enc_velocityestimate)
		}
		retagged_enc_velocityestimate, tagErr_enc_velocityestimate := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 20, enc_velocityestimate)
		if tagErr_enc_velocityestimate != nil {
			return nil, fmt.Errorf("encoding velocityEstimate: %w", tagErr_enc_velocityestimate)
		}
		enc_velocityestimate = retagged_enc_velocityestimate
		children = append(children, enc_velocityestimate...)
	}
	if v.SequenceNumber != nil {
		if !(int64(*v.SequenceNumber) >= 1 && int64(*v.SequenceNumber) <= 8639999) {
			if constraintErr := ber.CheckEncodedValue(opts, "sequenceNumber", "(1..8639999)", fmt.Sprint(int64(*v.SequenceNumber))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_sequencenumber := ber.EncodeInteger(int64(*v.SequenceNumber))
		retagged_enc_sequencenumber, tagErr_enc_sequencenumber := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 21, enc_sequencenumber)
		if tagErr_enc_sequencenumber != nil {
			return nil, fmt.Errorf("encoding sequenceNumber: %w", tagErr_enc_sequencenumber)
		}
		enc_sequencenumber = retagged_enc_sequencenumber
		children = append(children, enc_sequencenumber...)
	}
	if v.PeriodicLDRInfo != nil {
		enc_periodicldrinfo, err := v.PeriodicLDRInfo.MarshalBER(ber.ChildEncodeOptions(opts, "periodicLDRInfo")...)
		if err != nil {
			return nil, fmt.Errorf("encoding periodicLDRInfo: %w", err)
		}
		retagged_enc_periodicldrinfo, tagErr_enc_periodicldrinfo := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 22, enc_periodicldrinfo)
		if tagErr_enc_periodicldrinfo != nil {
			return nil, fmt.Errorf("encoding periodicLDRInfo: %w", tagErr_enc_periodicldrinfo)
		}
		enc_periodicldrinfo = retagged_enc_periodicldrinfo
		children = append(children, enc_periodicldrinfo...)
	}
	if v.MoLrShortCircuitIndicator != nil {
		enc_molrshortcircuitindicator := ber.EncodeNull()
		retagged_enc_molrshortcircuitindicator, tagErr_enc_molrshortcircuitindicator := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 23, enc_molrshortcircuitindicator)
		if tagErr_enc_molrshortcircuitindicator != nil {
			return nil, fmt.Errorf("encoding mo-lrShortCircuitIndicator: %w", tagErr_enc_molrshortcircuitindicator)
		}
		enc_molrshortcircuitindicator = retagged_enc_molrshortcircuitindicator
		children = append(children, enc_molrshortcircuitindicator...)
	}
	if v.GeranGANSSpositioningData != nil {
		if len(*v.GeranGANSSpositioningData) < 2 || len(*v.GeranGANSSpositioningData) > 10 {
			if constraintErr := ber.CheckEncodedLength(opts, "geranGANSSpositioningData", "SIZE (2..10)", len(*v.GeranGANSSpositioningData)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_gerangansspositioningdata, encodeErr_enc_gerangansspositioningdata := ber.EncodeOctetString([]byte(*v.GeranGANSSpositioningData))
		if encodeErr_enc_gerangansspositioningdata != nil {
			return nil, fmt.Errorf("encoding geranGANSSpositioningData: %w", encodeErr_enc_gerangansspositioningdata)
		}
		retagged_enc_gerangansspositioningdata, tagErr_enc_gerangansspositioningdata := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 24, enc_gerangansspositioningdata)
		if tagErr_enc_gerangansspositioningdata != nil {
			return nil, fmt.Errorf("encoding geranGANSSpositioningData: %w", tagErr_enc_gerangansspositioningdata)
		}
		enc_gerangansspositioningdata = retagged_enc_gerangansspositioningdata
		children = append(children, enc_gerangansspositioningdata...)
	}
	if v.UtranGANSSpositioningData != nil {
		if len(*v.UtranGANSSpositioningData) < 1 || len(*v.UtranGANSSpositioningData) > 9 {
			if constraintErr := ber.CheckEncodedLength(opts, "utranGANSSpositioningData", "SIZE (1..9)", len(*v.UtranGANSSpositioningData)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_utrangansspositioningdata, encodeErr_enc_utrangansspositioningdata := ber.EncodeOctetString([]byte(*v.UtranGANSSpositioningData))
		if encodeErr_enc_utrangansspositioningdata != nil {
			return nil, fmt.Errorf("encoding utranGANSSpositioningData: %w", encodeErr_enc_utrangansspositioningdata)
		}
		retagged_enc_utrangansspositioningdata, tagErr_enc_utrangansspositioningdata := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 25, enc_utrangansspositioningdata)
		if tagErr_enc_utrangansspositioningdata != nil {
			return nil, fmt.Errorf("encoding utranGANSSpositioningData: %w", tagErr_enc_utrangansspositioningdata)
		}
		enc_utrangansspositioningdata = retagged_enc_utrangansspositioningdata
		children = append(children, enc_utrangansspositioningdata...)
	}
	if v.TargetServingNodeForHandover != nil {
		enc_targetservingnodeforhandover, err := v.TargetServingNodeForHandover.MarshalBER(ber.ChildEncodeOptions(opts, "targetServingNodeForHandover")...)
		if err != nil {
			return nil, fmt.Errorf("encoding targetServingNodeForHandover: %w", err)
		}
		{
			var encodeErr error
			enc_targetservingnodeforhandover, encodeErr = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 26, enc_targetservingnodeforhandover)
			if encodeErr != nil {
				return nil, fmt.Errorf("encoding targetServingNodeForHandover: %w", encodeErr)
			}
		}
		children = append(children, enc_targetservingnodeforhandover...)
	}
	if v.UtranAdditionalPositioningData != nil {
		if len(*v.UtranAdditionalPositioningData) < 1 || len(*v.UtranAdditionalPositioningData) > 8 {
			if constraintErr := ber.CheckEncodedLength(opts, "utranAdditionalPositioningData", "SIZE (1..8)", len(*v.UtranAdditionalPositioningData)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_utranadditionalpositioningdata, encodeErr_enc_utranadditionalpositioningdata := ber.EncodeOctetString([]byte(*v.UtranAdditionalPositioningData))
		if encodeErr_enc_utranadditionalpositioningdata != nil {
			return nil, fmt.Errorf("encoding utranAdditionalPositioningData: %w", encodeErr_enc_utranadditionalpositioningdata)
		}
		retagged_enc_utranadditionalpositioningdata, tagErr_enc_utranadditionalpositioningdata := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 27, enc_utranadditionalpositioningdata)
		if tagErr_enc_utranadditionalpositioningdata != nil {
			return nil, fmt.Errorf("encoding utranAdditionalPositioningData: %w", tagErr_enc_utranadditionalpositioningdata)
		}
		enc_utranadditionalpositioningdata = retagged_enc_utranadditionalpositioningdata
		children = append(children, enc_utranadditionalpositioningdata...)
	}
	if v.UtranBaroPressureMeas != nil {
		if !(int64(*v.UtranBaroPressureMeas) >= 30000 && int64(*v.UtranBaroPressureMeas) <= 115000) {
			if constraintErr := ber.CheckEncodedValue(opts, "utranBaroPressureMeas", "(30000..115000)", fmt.Sprint(int64(*v.UtranBaroPressureMeas))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_utranbaropressuremeas := ber.EncodeInteger(int64(*v.UtranBaroPressureMeas))
		retagged_enc_utranbaropressuremeas, tagErr_enc_utranbaropressuremeas := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 28, enc_utranbaropressuremeas)
		if tagErr_enc_utranbaropressuremeas != nil {
			return nil, fmt.Errorf("encoding utranBaroPressureMeas: %w", tagErr_enc_utranbaropressuremeas)
		}
		enc_utranbaropressuremeas = retagged_enc_utranbaropressuremeas
		children = append(children, enc_utranbaropressuremeas...)
	}
	if v.UtranCivicAddress != nil {
		enc_utrancivicaddress, encodeErr_enc_utrancivicaddress := ber.EncodeOctetString([]byte(*v.UtranCivicAddress))
		if encodeErr_enc_utrancivicaddress != nil {
			return nil, fmt.Errorf("encoding utranCivicAddress: %w", encodeErr_enc_utrancivicaddress)
		}
		retagged_enc_utrancivicaddress, tagErr_enc_utrancivicaddress := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 29, enc_utrancivicaddress)
		if tagErr_enc_utrancivicaddress != nil {
			return nil, fmt.Errorf("encoding utranCivicAddress: %w", tagErr_enc_utrancivicaddress)
		}
		enc_utrancivicaddress = retagged_enc_utrancivicaddress
		children = append(children, enc_utrancivicaddress...)
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

// MarshalDER encodes LCSSubscriberLocationReportArg to DER format.
func (v *LCSSubscriberLocationReportArg) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: LCSSubscriberLocationReportArg receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	enc_lcsevent := ber.EncodeEnumerated(int64(v.LcsEvent))
	children = append(children, enc_lcsevent...)
	enc_lcsclientid, err := v.LcsClientID.MarshalDER()
	if err != nil {
		return nil, fmt.Errorf("encoding lcs-ClientID: %w", err)
	}
	children = append(children, enc_lcsclientid...)
	enc_lcslocationinfo, err := v.LcsLocationInfo.MarshalDER()
	if err != nil {
		return nil, fmt.Errorf("encoding lcsLocationInfo: %w", err)
	}
	children = append(children, enc_lcslocationinfo...)
	if v.Msisdn != nil {
		if len(*v.Msisdn) < 1 || len(*v.Msisdn) > 9 {
			if constraintErr := ber.CheckEncodedLength(nil, "msisdn", "SIZE (1..9)", len(*v.Msisdn)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		if len(*v.Msisdn) < 1 || len(*v.Msisdn) > 20 {
			if constraintErr := ber.CheckEncodedLength(nil, "msisdn", "SIZE (1..20)", len(*v.Msisdn)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_msisdn, encodeErr_enc_msisdn := ber.EncodeOctetString([]byte(*v.Msisdn))
		if encodeErr_enc_msisdn != nil {
			return nil, fmt.Errorf("encoding msisdn: %w", encodeErr_enc_msisdn)
		}
		retagged_enc_msisdn, tagErr_enc_msisdn := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_msisdn)
		if tagErr_enc_msisdn != nil {
			return nil, fmt.Errorf("encoding msisdn: %w", tagErr_enc_msisdn)
		}
		enc_msisdn = retagged_enc_msisdn
		children = append(children, enc_msisdn...)
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
	if v.Imei != nil {
		if len(*v.Imei) < 8 || len(*v.Imei) > 8 {
			if constraintErr := ber.CheckEncodedLength(nil, "imei", "SIZE (8)", len(*v.Imei)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_imei, encodeErr_enc_imei := ber.EncodeOctetString([]byte(*v.Imei))
		if encodeErr_enc_imei != nil {
			return nil, fmt.Errorf("encoding imei: %w", encodeErr_enc_imei)
		}
		retagged_enc_imei, tagErr_enc_imei := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_imei)
		if tagErr_enc_imei != nil {
			return nil, fmt.Errorf("encoding imei: %w", tagErr_enc_imei)
		}
		enc_imei = retagged_enc_imei
		children = append(children, enc_imei...)
	}
	if v.NaESRD != nil {
		if len(*v.NaESRD) < 1 || len(*v.NaESRD) > 9 {
			if constraintErr := ber.CheckEncodedLength(nil, "na-ESRD", "SIZE (1..9)", len(*v.NaESRD)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		if len(*v.NaESRD) < 1 || len(*v.NaESRD) > 20 {
			if constraintErr := ber.CheckEncodedLength(nil, "na-ESRD", "SIZE (1..20)", len(*v.NaESRD)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_naesrd, encodeErr_enc_naesrd := ber.EncodeOctetString([]byte(*v.NaESRD))
		if encodeErr_enc_naesrd != nil {
			return nil, fmt.Errorf("encoding na-ESRD: %w", encodeErr_enc_naesrd)
		}
		retagged_enc_naesrd, tagErr_enc_naesrd := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, enc_naesrd)
		if tagErr_enc_naesrd != nil {
			return nil, fmt.Errorf("encoding na-ESRD: %w", tagErr_enc_naesrd)
		}
		enc_naesrd = retagged_enc_naesrd
		children = append(children, enc_naesrd...)
	}
	if v.NaESRK != nil {
		if len(*v.NaESRK) < 1 || len(*v.NaESRK) > 9 {
			if constraintErr := ber.CheckEncodedLength(nil, "na-ESRK", "SIZE (1..9)", len(*v.NaESRK)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		if len(*v.NaESRK) < 1 || len(*v.NaESRK) > 20 {
			if constraintErr := ber.CheckEncodedLength(nil, "na-ESRK", "SIZE (1..20)", len(*v.NaESRK)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_naesrk, encodeErr_enc_naesrk := ber.EncodeOctetString([]byte(*v.NaESRK))
		if encodeErr_enc_naesrk != nil {
			return nil, fmt.Errorf("encoding na-ESRK: %w", encodeErr_enc_naesrk)
		}
		retagged_enc_naesrk, tagErr_enc_naesrk := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, enc_naesrk)
		if tagErr_enc_naesrk != nil {
			return nil, fmt.Errorf("encoding na-ESRK: %w", tagErr_enc_naesrk)
		}
		enc_naesrk = retagged_enc_naesrk
		children = append(children, enc_naesrk...)
	}
	if v.LocationEstimate != nil {
		if len(*v.LocationEstimate) < 1 || len(*v.LocationEstimate) > 20 {
			if constraintErr := ber.CheckEncodedLength(nil, "locationEstimate", "SIZE (1..20)", len(*v.LocationEstimate)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_locationestimate, encodeErr_enc_locationestimate := ber.EncodeOctetString([]byte(*v.LocationEstimate))
		if encodeErr_enc_locationestimate != nil {
			return nil, fmt.Errorf("encoding locationEstimate: %w", encodeErr_enc_locationestimate)
		}
		retagged_enc_locationestimate, tagErr_enc_locationestimate := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 5, enc_locationestimate)
		if tagErr_enc_locationestimate != nil {
			return nil, fmt.Errorf("encoding locationEstimate: %w", tagErr_enc_locationestimate)
		}
		enc_locationestimate = retagged_enc_locationestimate
		children = append(children, enc_locationestimate...)
	}
	if v.AgeOfLocationEstimate != nil {
		if !(int64(*v.AgeOfLocationEstimate) >= 0 && int64(*v.AgeOfLocationEstimate) <= 32767) {
			if constraintErr := ber.CheckEncodedValue(nil, "ageOfLocationEstimate", "(0..32767)", fmt.Sprint(int64(*v.AgeOfLocationEstimate))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_ageoflocationestimate := ber.EncodeInteger(int64(*v.AgeOfLocationEstimate))
		retagged_enc_ageoflocationestimate, tagErr_enc_ageoflocationestimate := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 6, enc_ageoflocationestimate)
		if tagErr_enc_ageoflocationestimate != nil {
			return nil, fmt.Errorf("encoding ageOfLocationEstimate: %w", tagErr_enc_ageoflocationestimate)
		}
		enc_ageoflocationestimate = retagged_enc_ageoflocationestimate
		children = append(children, enc_ageoflocationestimate...)
	}
	if v.SlrArgExtensionContainer != nil {
		enc_slrargextensioncontainer, err := v.SlrArgExtensionContainer.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding slr-ArgExtensionContainer: %w", err)
		}
		retagged_enc_slrargextensioncontainer, tagErr_enc_slrargextensioncontainer := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 7, enc_slrargextensioncontainer)
		if tagErr_enc_slrargextensioncontainer != nil {
			return nil, fmt.Errorf("encoding slr-ArgExtensionContainer: %w", tagErr_enc_slrargextensioncontainer)
		}
		enc_slrargextensioncontainer = retagged_enc_slrargextensioncontainer
		children = append(children, enc_slrargextensioncontainer...)
	}
	if v.AddLocationEstimate != nil {
		if len(*v.AddLocationEstimate) < 1 || len(*v.AddLocationEstimate) > 91 {
			if constraintErr := ber.CheckEncodedLength(nil, "add-LocationEstimate", "SIZE (1..91)", len(*v.AddLocationEstimate)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_addlocationestimate, encodeErr_enc_addlocationestimate := ber.EncodeOctetString([]byte(*v.AddLocationEstimate))
		if encodeErr_enc_addlocationestimate != nil {
			return nil, fmt.Errorf("encoding add-LocationEstimate: %w", encodeErr_enc_addlocationestimate)
		}
		retagged_enc_addlocationestimate, tagErr_enc_addlocationestimate := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 8, enc_addlocationestimate)
		if tagErr_enc_addlocationestimate != nil {
			return nil, fmt.Errorf("encoding add-LocationEstimate: %w", tagErr_enc_addlocationestimate)
		}
		enc_addlocationestimate = retagged_enc_addlocationestimate
		children = append(children, enc_addlocationestimate...)
	}
	if v.DeferredmtLrData != nil {
		enc_deferredmtlrdata, err := v.DeferredmtLrData.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding deferredmt-lrData: %w", err)
		}
		retagged_enc_deferredmtlrdata, tagErr_enc_deferredmtlrdata := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 9, enc_deferredmtlrdata)
		if tagErr_enc_deferredmtlrdata != nil {
			return nil, fmt.Errorf("encoding deferredmt-lrData: %w", tagErr_enc_deferredmtlrdata)
		}
		enc_deferredmtlrdata = retagged_enc_deferredmtlrdata
		children = append(children, enc_deferredmtlrdata...)
	}
	if v.LcsReferenceNumber != nil {
		if len(*v.LcsReferenceNumber) < 1 || len(*v.LcsReferenceNumber) > 1 {
			if constraintErr := ber.CheckEncodedLength(nil, "lcs-ReferenceNumber", "SIZE (1)", len(*v.LcsReferenceNumber)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_lcsreferencenumber, encodeErr_enc_lcsreferencenumber := ber.EncodeOctetString([]byte(*v.LcsReferenceNumber))
		if encodeErr_enc_lcsreferencenumber != nil {
			return nil, fmt.Errorf("encoding lcs-ReferenceNumber: %w", encodeErr_enc_lcsreferencenumber)
		}
		retagged_enc_lcsreferencenumber, tagErr_enc_lcsreferencenumber := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 10, enc_lcsreferencenumber)
		if tagErr_enc_lcsreferencenumber != nil {
			return nil, fmt.Errorf("encoding lcs-ReferenceNumber: %w", tagErr_enc_lcsreferencenumber)
		}
		enc_lcsreferencenumber = retagged_enc_lcsreferencenumber
		children = append(children, enc_lcsreferencenumber...)
	}
	if v.GeranPositioningData != nil {
		if len(*v.GeranPositioningData) < 2 || len(*v.GeranPositioningData) > 10 {
			if constraintErr := ber.CheckEncodedLength(nil, "geranPositioningData", "SIZE (2..10)", len(*v.GeranPositioningData)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_geranpositioningdata, encodeErr_enc_geranpositioningdata := ber.EncodeOctetString([]byte(*v.GeranPositioningData))
		if encodeErr_enc_geranpositioningdata != nil {
			return nil, fmt.Errorf("encoding geranPositioningData: %w", encodeErr_enc_geranpositioningdata)
		}
		retagged_enc_geranpositioningdata, tagErr_enc_geranpositioningdata := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 11, enc_geranpositioningdata)
		if tagErr_enc_geranpositioningdata != nil {
			return nil, fmt.Errorf("encoding geranPositioningData: %w", tagErr_enc_geranpositioningdata)
		}
		enc_geranpositioningdata = retagged_enc_geranpositioningdata
		children = append(children, enc_geranpositioningdata...)
	}
	if v.UtranPositioningData != nil {
		if len(*v.UtranPositioningData) < 3 || len(*v.UtranPositioningData) > 11 {
			if constraintErr := ber.CheckEncodedLength(nil, "utranPositioningData", "SIZE (3..11)", len(*v.UtranPositioningData)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_utranpositioningdata, encodeErr_enc_utranpositioningdata := ber.EncodeOctetString([]byte(*v.UtranPositioningData))
		if encodeErr_enc_utranpositioningdata != nil {
			return nil, fmt.Errorf("encoding utranPositioningData: %w", encodeErr_enc_utranpositioningdata)
		}
		retagged_enc_utranpositioningdata, tagErr_enc_utranpositioningdata := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 12, enc_utranpositioningdata)
		if tagErr_enc_utranpositioningdata != nil {
			return nil, fmt.Errorf("encoding utranPositioningData: %w", tagErr_enc_utranpositioningdata)
		}
		enc_utranpositioningdata = retagged_enc_utranpositioningdata
		children = append(children, enc_utranpositioningdata...)
	}
	if v.CellIdOrSai != nil {
		enc_cellidorsai, err := v.CellIdOrSai.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding cellIdOrSai: %w", err)
		}
		{
			var encodeErr error
			enc_cellidorsai, encodeErr = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 13, enc_cellidorsai)
			if encodeErr != nil {
				return nil, fmt.Errorf("encoding cellIdOrSai: %w", encodeErr)
			}
		}
		children = append(children, enc_cellidorsai...)
	}
	if v.HGmlcAddress != nil {
		if len(*v.HGmlcAddress) < 5 || len(*v.HGmlcAddress) > 17 {
			if constraintErr := ber.CheckEncodedLength(nil, "h-gmlc-Address", "SIZE (5..17)", len(*v.HGmlcAddress)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_hgmlcaddress, encodeErr_enc_hgmlcaddress := ber.EncodeOctetString([]byte(*v.HGmlcAddress))
		if encodeErr_enc_hgmlcaddress != nil {
			return nil, fmt.Errorf("encoding h-gmlc-Address: %w", encodeErr_enc_hgmlcaddress)
		}
		retagged_enc_hgmlcaddress, tagErr_enc_hgmlcaddress := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 14, enc_hgmlcaddress)
		if tagErr_enc_hgmlcaddress != nil {
			return nil, fmt.Errorf("encoding h-gmlc-Address: %w", tagErr_enc_hgmlcaddress)
		}
		enc_hgmlcaddress = retagged_enc_hgmlcaddress
		children = append(children, enc_hgmlcaddress...)
	}
	if v.LcsServiceTypeID != nil {
		if !(int64(*v.LcsServiceTypeID) >= 0 && int64(*v.LcsServiceTypeID) <= 127) {
			if constraintErr := ber.CheckEncodedValue(nil, "lcsServiceTypeID", "(0..127)", fmt.Sprint(int64(*v.LcsServiceTypeID))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_lcsservicetypeid := ber.EncodeInteger(int64(*v.LcsServiceTypeID))
		retagged_enc_lcsservicetypeid, tagErr_enc_lcsservicetypeid := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 15, enc_lcsservicetypeid)
		if tagErr_enc_lcsservicetypeid != nil {
			return nil, fmt.Errorf("encoding lcsServiceTypeID: %w", tagErr_enc_lcsservicetypeid)
		}
		enc_lcsservicetypeid = retagged_enc_lcsservicetypeid
		children = append(children, enc_lcsservicetypeid...)
	}
	if v.SaiPresent != nil {
		enc_saipresent := ber.EncodeNull()
		retagged_enc_saipresent, tagErr_enc_saipresent := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 17, enc_saipresent)
		if tagErr_enc_saipresent != nil {
			return nil, fmt.Errorf("encoding sai-Present: %w", tagErr_enc_saipresent)
		}
		enc_saipresent = retagged_enc_saipresent
		children = append(children, enc_saipresent...)
	}
	if v.PseudonymIndicator != nil {
		enc_pseudonymindicator := ber.EncodeNull()
		retagged_enc_pseudonymindicator, tagErr_enc_pseudonymindicator := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 18, enc_pseudonymindicator)
		if tagErr_enc_pseudonymindicator != nil {
			return nil, fmt.Errorf("encoding pseudonymIndicator: %w", tagErr_enc_pseudonymindicator)
		}
		enc_pseudonymindicator = retagged_enc_pseudonymindicator
		children = append(children, enc_pseudonymindicator...)
	}
	if v.AccuracyFulfilmentIndicator != nil {
		enc_accuracyfulfilmentindicator := ber.EncodeEnumerated(int64(*v.AccuracyFulfilmentIndicator))
		retagged_enc_accuracyfulfilmentindicator, tagErr_enc_accuracyfulfilmentindicator := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 19, enc_accuracyfulfilmentindicator)
		if tagErr_enc_accuracyfulfilmentindicator != nil {
			return nil, fmt.Errorf("encoding accuracyFulfilmentIndicator: %w", tagErr_enc_accuracyfulfilmentindicator)
		}
		enc_accuracyfulfilmentindicator = retagged_enc_accuracyfulfilmentindicator
		children = append(children, enc_accuracyfulfilmentindicator...)
	}
	if v.VelocityEstimate != nil {
		if len(*v.VelocityEstimate) < 4 || len(*v.VelocityEstimate) > 7 {
			if constraintErr := ber.CheckEncodedLength(nil, "velocityEstimate", "SIZE (4..7)", len(*v.VelocityEstimate)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_velocityestimate, encodeErr_enc_velocityestimate := ber.EncodeOctetString([]byte(*v.VelocityEstimate))
		if encodeErr_enc_velocityestimate != nil {
			return nil, fmt.Errorf("encoding velocityEstimate: %w", encodeErr_enc_velocityestimate)
		}
		retagged_enc_velocityestimate, tagErr_enc_velocityestimate := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 20, enc_velocityestimate)
		if tagErr_enc_velocityestimate != nil {
			return nil, fmt.Errorf("encoding velocityEstimate: %w", tagErr_enc_velocityestimate)
		}
		enc_velocityestimate = retagged_enc_velocityestimate
		children = append(children, enc_velocityestimate...)
	}
	if v.SequenceNumber != nil {
		if !(int64(*v.SequenceNumber) >= 1 && int64(*v.SequenceNumber) <= 8639999) {
			if constraintErr := ber.CheckEncodedValue(nil, "sequenceNumber", "(1..8639999)", fmt.Sprint(int64(*v.SequenceNumber))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_sequencenumber := ber.EncodeInteger(int64(*v.SequenceNumber))
		retagged_enc_sequencenumber, tagErr_enc_sequencenumber := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 21, enc_sequencenumber)
		if tagErr_enc_sequencenumber != nil {
			return nil, fmt.Errorf("encoding sequenceNumber: %w", tagErr_enc_sequencenumber)
		}
		enc_sequencenumber = retagged_enc_sequencenumber
		children = append(children, enc_sequencenumber...)
	}
	if v.PeriodicLDRInfo != nil {
		enc_periodicldrinfo, err := v.PeriodicLDRInfo.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding periodicLDRInfo: %w", err)
		}
		retagged_enc_periodicldrinfo, tagErr_enc_periodicldrinfo := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 22, enc_periodicldrinfo)
		if tagErr_enc_periodicldrinfo != nil {
			return nil, fmt.Errorf("encoding periodicLDRInfo: %w", tagErr_enc_periodicldrinfo)
		}
		enc_periodicldrinfo = retagged_enc_periodicldrinfo
		children = append(children, enc_periodicldrinfo...)
	}
	if v.MoLrShortCircuitIndicator != nil {
		enc_molrshortcircuitindicator := ber.EncodeNull()
		retagged_enc_molrshortcircuitindicator, tagErr_enc_molrshortcircuitindicator := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 23, enc_molrshortcircuitindicator)
		if tagErr_enc_molrshortcircuitindicator != nil {
			return nil, fmt.Errorf("encoding mo-lrShortCircuitIndicator: %w", tagErr_enc_molrshortcircuitindicator)
		}
		enc_molrshortcircuitindicator = retagged_enc_molrshortcircuitindicator
		children = append(children, enc_molrshortcircuitindicator...)
	}
	if v.GeranGANSSpositioningData != nil {
		if len(*v.GeranGANSSpositioningData) < 2 || len(*v.GeranGANSSpositioningData) > 10 {
			if constraintErr := ber.CheckEncodedLength(nil, "geranGANSSpositioningData", "SIZE (2..10)", len(*v.GeranGANSSpositioningData)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_gerangansspositioningdata, encodeErr_enc_gerangansspositioningdata := ber.EncodeOctetString([]byte(*v.GeranGANSSpositioningData))
		if encodeErr_enc_gerangansspositioningdata != nil {
			return nil, fmt.Errorf("encoding geranGANSSpositioningData: %w", encodeErr_enc_gerangansspositioningdata)
		}
		retagged_enc_gerangansspositioningdata, tagErr_enc_gerangansspositioningdata := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 24, enc_gerangansspositioningdata)
		if tagErr_enc_gerangansspositioningdata != nil {
			return nil, fmt.Errorf("encoding geranGANSSpositioningData: %w", tagErr_enc_gerangansspositioningdata)
		}
		enc_gerangansspositioningdata = retagged_enc_gerangansspositioningdata
		children = append(children, enc_gerangansspositioningdata...)
	}
	if v.UtranGANSSpositioningData != nil {
		if len(*v.UtranGANSSpositioningData) < 1 || len(*v.UtranGANSSpositioningData) > 9 {
			if constraintErr := ber.CheckEncodedLength(nil, "utranGANSSpositioningData", "SIZE (1..9)", len(*v.UtranGANSSpositioningData)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_utrangansspositioningdata, encodeErr_enc_utrangansspositioningdata := ber.EncodeOctetString([]byte(*v.UtranGANSSpositioningData))
		if encodeErr_enc_utrangansspositioningdata != nil {
			return nil, fmt.Errorf("encoding utranGANSSpositioningData: %w", encodeErr_enc_utrangansspositioningdata)
		}
		retagged_enc_utrangansspositioningdata, tagErr_enc_utrangansspositioningdata := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 25, enc_utrangansspositioningdata)
		if tagErr_enc_utrangansspositioningdata != nil {
			return nil, fmt.Errorf("encoding utranGANSSpositioningData: %w", tagErr_enc_utrangansspositioningdata)
		}
		enc_utrangansspositioningdata = retagged_enc_utrangansspositioningdata
		children = append(children, enc_utrangansspositioningdata...)
	}
	if v.TargetServingNodeForHandover != nil {
		enc_targetservingnodeforhandover, err := v.TargetServingNodeForHandover.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding targetServingNodeForHandover: %w", err)
		}
		{
			var encodeErr error
			enc_targetservingnodeforhandover, encodeErr = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 26, enc_targetservingnodeforhandover)
			if encodeErr != nil {
				return nil, fmt.Errorf("encoding targetServingNodeForHandover: %w", encodeErr)
			}
		}
		children = append(children, enc_targetservingnodeforhandover...)
	}
	if v.UtranAdditionalPositioningData != nil {
		if len(*v.UtranAdditionalPositioningData) < 1 || len(*v.UtranAdditionalPositioningData) > 8 {
			if constraintErr := ber.CheckEncodedLength(nil, "utranAdditionalPositioningData", "SIZE (1..8)", len(*v.UtranAdditionalPositioningData)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_utranadditionalpositioningdata, encodeErr_enc_utranadditionalpositioningdata := ber.EncodeOctetString([]byte(*v.UtranAdditionalPositioningData))
		if encodeErr_enc_utranadditionalpositioningdata != nil {
			return nil, fmt.Errorf("encoding utranAdditionalPositioningData: %w", encodeErr_enc_utranadditionalpositioningdata)
		}
		retagged_enc_utranadditionalpositioningdata, tagErr_enc_utranadditionalpositioningdata := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 27, enc_utranadditionalpositioningdata)
		if tagErr_enc_utranadditionalpositioningdata != nil {
			return nil, fmt.Errorf("encoding utranAdditionalPositioningData: %w", tagErr_enc_utranadditionalpositioningdata)
		}
		enc_utranadditionalpositioningdata = retagged_enc_utranadditionalpositioningdata
		children = append(children, enc_utranadditionalpositioningdata...)
	}
	if v.UtranBaroPressureMeas != nil {
		if !(int64(*v.UtranBaroPressureMeas) >= 30000 && int64(*v.UtranBaroPressureMeas) <= 115000) {
			if constraintErr := ber.CheckEncodedValue(nil, "utranBaroPressureMeas", "(30000..115000)", fmt.Sprint(int64(*v.UtranBaroPressureMeas))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_utranbaropressuremeas := ber.EncodeInteger(int64(*v.UtranBaroPressureMeas))
		retagged_enc_utranbaropressuremeas, tagErr_enc_utranbaropressuremeas := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 28, enc_utranbaropressuremeas)
		if tagErr_enc_utranbaropressuremeas != nil {
			return nil, fmt.Errorf("encoding utranBaroPressureMeas: %w", tagErr_enc_utranbaropressuremeas)
		}
		enc_utranbaropressuremeas = retagged_enc_utranbaropressuremeas
		children = append(children, enc_utranbaropressuremeas...)
	}
	if v.UtranCivicAddress != nil {
		enc_utrancivicaddress, encodeErr_enc_utrancivicaddress := ber.EncodeOctetString([]byte(*v.UtranCivicAddress))
		if encodeErr_enc_utrancivicaddress != nil {
			return nil, fmt.Errorf("encoding utranCivicAddress: %w", encodeErr_enc_utrancivicaddress)
		}
		retagged_enc_utrancivicaddress, tagErr_enc_utrancivicaddress := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 29, enc_utrancivicaddress)
		if tagErr_enc_utrancivicaddress != nil {
			return nil, fmt.Errorf("encoding utranCivicAddress: %w", tagErr_enc_utrancivicaddress)
		}
		enc_utrancivicaddress = retagged_enc_utrancivicaddress
		children = append(children, enc_utrancivicaddress...)
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
		return nil, fmt.Errorf("encoding LCSSubscriberLocationReportArg as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes LCSSubscriberLocationReportArg from BER/DER format.
func (v *LCSSubscriberLocationReportArg) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: LCSSubscriberLocationReportArg destination is nil", ber.ErrInvalidValue)
	}
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = LCSSubscriberLocationReportArg{}
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
		return fmt.Errorf("decoding LCSSubscriberLocationReportArg SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "LCSSubscriberLocationReportArg", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode lcs-Event
	if offset >= len(content) {
		return fmt.Errorf("missing required field lcs-Event")
	}
	val_lcsevent, n, err := ber.DecodeEnumerated(content[offset:], opts...)
	if err != nil {
		return fmt.Errorf("decoding lcs-Event: %w", err)
	}
	v.LcsEvent = LCSLCSEvent(val_lcsevent)
	if offset < 0 || offset >
		len(content) || n < 0 || n > len(content[offset:]) {
		return fmt.Errorf("invalid BER content window")
	}

	offset += n
	// Decode lcs-ClientID
	if offset >= len(content) {
		return fmt.Errorf("missing required field lcs-ClientID")
	}
	// Decode nested SEQUENCE (LCSLCSClientID)
	_, n_lcsclientid, _, tlvErr_lcsclientid := ber.DecodeTLV(content[offset:], opts...)
	if tlvErr_lcsclientid != nil {
		return fmt.Errorf("decoding lcs-ClientID: %w", tlvErr_lcsclientid)
	}
	if offset < 0 || offset >
		len(content) || n_lcsclientid < 0 || n_lcsclientid > len(content[offset:]) {
		return fmt.Errorf("invalid BER content window")
	}

	if unmErr := v.LcsClientID.UnmarshalBER(content[offset:offset+n_lcsclientid], ber.ChildDecodeOptions(opts, "lcs-ClientID")...); unmErr != nil {
		return fmt.Errorf("decoding lcs-ClientID: %w", unmErr)
	}
	if offset < 0 || offset >
		len(content) || n_lcsclientid < 0 || n_lcsclientid > len(content[offset:]) {
		return fmt.Errorf("invalid BER content window")
	}

	offset += n_lcsclientid
	// Decode lcsLocationInfo
	if offset >= len(content) {
		return fmt.Errorf("missing required field lcsLocationInfo")
	}
	// Decode nested SEQUENCE (LCSLCSLocationInfo)
	_, n_lcslocationinfo, _, tlvErr_lcslocationinfo := ber.DecodeTLV(content[offset:], opts...)
	if tlvErr_lcslocationinfo != nil {
		return fmt.Errorf("decoding lcsLocationInfo: %w", tlvErr_lcslocationinfo)
	}
	if offset < 0 || offset >
		len(content) || n_lcslocationinfo < 0 || n_lcslocationinfo > len(content[offset:]) {
		return fmt.Errorf("invalid BER content window")
	}

	if unmErr := v.LcsLocationInfo.UnmarshalBER(content[offset:offset+n_lcslocationinfo], ber.ChildDecodeOptions(opts, "lcsLocationInfo")...); unmErr != nil {
		return fmt.Errorf("decoding lcsLocationInfo: %w", unmErr)
	}
	if offset < 0 || offset >
		len(content) || n_lcslocationinfo < 0 || n_lcslocationinfo > len(content[offset:]) {
		return fmt.Errorf("invalid BER content window")
	}

	offset += n_lcslocationinfo
	// Decode msisdn
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
				decodedTag_msisdn, n_msisdn, rawVal_msisdn, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding msisdn: %w", err)
				}
				if decodedTag_msisdn.Class != tag.ClassContextSpecific || decodedTag_msisdn.Number != 0 {
					return fmt.Errorf("decoding msisdn: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_msisdn)
				}
				decVal_msisdn, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_msisdn.Constructed, rawVal_msisdn, opts...)
				if octetErr != nil {
					return fmt.Errorf("decoding msisdn: %w", octetErr)
				}
				tmp_msisdn := ISDNAddressString3(decVal_msisdn)
				v.Msisdn = &tmp_msisdn
				if offset < 0 || offset >
					len(content) || n_msisdn < 0 || n_msisdn > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_msisdn
				if len(*v.Msisdn) < 1 || len(*v.Msisdn) > 9 {
					if constraintErr := ber.CheckDecodedLength(opts, "msisdn", "SIZE (1..9)", len(*v.Msisdn)); constraintErr != nil {
						return constraintErr
					}
				}
				if len(*v.Msisdn) < 1 || len(*v.Msisdn) > 20 {
					if constraintErr := ber.CheckDecodedLength(opts, "msisdn", "SIZE (1..20)", len(*v.Msisdn)); constraintErr != nil {
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
				tmp_imsi := IMSI3(decVal_imsi)
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
	// Decode imei
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2 {
				decodedTag_imei, n_imei, rawVal_imei, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding imei: %w", err)
				}
				if decodedTag_imei.Class != tag.ClassContextSpecific || decodedTag_imei.Number != 2 {
					return fmt.Errorf("decoding imei: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_imei)
				}
				decVal_imei, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_imei.Constructed, rawVal_imei, opts...)
				if octetErr != nil {
					return fmt.Errorf("decoding imei: %w", octetErr)
				}
				tmp_imei := IMEI3(decVal_imei)
				v.Imei = &tmp_imei
				if offset < 0 || offset >
					len(content) || n_imei < 0 || n_imei > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_imei
				if len(*v.Imei) < 8 || len(*v.Imei) > 8 {
					if constraintErr := ber.CheckDecodedLength(opts, "imei", "SIZE (8)", len(*v.Imei)); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode na-ESRD
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3 {
				decodedTag_naesrd, n_naesrd, rawVal_naesrd, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding na-ESRD: %w", err)
				}
				if decodedTag_naesrd.Class != tag.ClassContextSpecific || decodedTag_naesrd.Number != 3 {
					return fmt.Errorf("decoding na-ESRD: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_naesrd)
				}
				decVal_naesrd, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_naesrd.Constructed, rawVal_naesrd, opts...)
				if octetErr != nil {
					return fmt.Errorf("decoding na-ESRD: %w", octetErr)
				}
				tmp_naesrd := ISDNAddressString3(decVal_naesrd)
				v.NaESRD = &tmp_naesrd
				if offset < 0 || offset >
					len(content) || n_naesrd < 0 || n_naesrd > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_naesrd
				if len(*v.NaESRD) < 1 || len(*v.NaESRD) > 9 {
					if constraintErr := ber.CheckDecodedLength(opts, "na-ESRD", "SIZE (1..9)", len(*v.NaESRD)); constraintErr != nil {
						return constraintErr
					}
				}
				if len(*v.NaESRD) < 1 || len(*v.NaESRD) > 20 {
					if constraintErr := ber.CheckDecodedLength(opts, "na-ESRD", "SIZE (1..20)", len(*v.NaESRD)); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode na-ESRK
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4 {
				decodedTag_naesrk, n_naesrk, rawVal_naesrk, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding na-ESRK: %w", err)
				}
				if decodedTag_naesrk.Class != tag.ClassContextSpecific || decodedTag_naesrk.Number != 4 {
					return fmt.Errorf("decoding na-ESRK: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_naesrk)
				}
				decVal_naesrk, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_naesrk.Constructed, rawVal_naesrk, opts...)
				if octetErr != nil {
					return fmt.Errorf("decoding na-ESRK: %w", octetErr)
				}
				tmp_naesrk := ISDNAddressString3(decVal_naesrk)
				v.NaESRK = &tmp_naesrk
				if offset < 0 || offset >
					len(content) || n_naesrk < 0 || n_naesrk > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_naesrk
				if len(*v.NaESRK) < 1 || len(*v.NaESRK) > 9 {
					if constraintErr := ber.CheckDecodedLength(opts, "na-ESRK", "SIZE (1..9)", len(*v.NaESRK)); constraintErr != nil {
						return constraintErr
					}
				}
				if len(*v.NaESRK) < 1 || len(*v.NaESRK) > 20 {
					if constraintErr := ber.CheckDecodedLength(opts, "na-ESRK", "SIZE (1..20)", len(*v.NaESRK)); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode locationEstimate
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 5 {
				decodedTag_locationestimate, n_locationestimate, rawVal_locationestimate, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding locationEstimate: %w", err)
				}
				if decodedTag_locationestimate.Class != tag.ClassContextSpecific || decodedTag_locationestimate.Number != 5 {
					return fmt.Errorf("decoding locationEstimate: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_locationestimate)
				}
				decVal_locationestimate, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_locationestimate.Constructed, rawVal_locationestimate, opts...)
				if octetErr != nil {
					return fmt.Errorf("decoding locationEstimate: %w", octetErr)
				}
				tmp_locationestimate := LCSExtGeographicalInformation(decVal_locationestimate)
				v.LocationEstimate = &tmp_locationestimate
				if offset < 0 || offset >
					len(content) || n_locationestimate < 0 || n_locationestimate > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_locationestimate
				if len(*v.LocationEstimate) < 1 || len(*v.LocationEstimate) > 20 {
					if constraintErr := ber.CheckDecodedLength(opts, "locationEstimate", "SIZE (1..20)", len(*v.LocationEstimate)); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode ageOfLocationEstimate
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 6 {
				decodedTag_ageoflocationestimate, n_ageoflocationestimate, rawVal_ageoflocationestimate, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding ageOfLocationEstimate: %w", err)
				}
				if decodedTag_ageoflocationestimate.Class != tag.ClassContextSpecific || decodedTag_ageoflocationestimate.Number != 6 || decodedTag_ageoflocationestimate.Constructed != false {
					return fmt.Errorf("decoding ageOfLocationEstimate: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_ageoflocationestimate)
				}
				decVal_ageoflocationestimate, intErr := ber.DecodeIntegerValue(rawVal_ageoflocationestimate)
				if intErr != nil {
					return fmt.Errorf("decoding ageOfLocationEstimate: %w", intErr)
				}
				tmp_ageoflocationestimate := AgeOfLocationInformation3(decVal_ageoflocationestimate)
				v.AgeOfLocationEstimate = &tmp_ageoflocationestimate
				if offset < 0 || offset >
					len(content) || n_ageoflocationestimate < 0 || n_ageoflocationestimate >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_ageoflocationestimate
				if !(int64(*v.AgeOfLocationEstimate) >= 0 && int64(*v.AgeOfLocationEstimate) <= 32767) {
					if constraintErr := ber.CheckDecodedValue(opts, "ageOfLocationEstimate", "(0..32767)", fmt.Sprint(int64(*v.AgeOfLocationEstimate))); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode slr-ArgExtensionContainer
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 7 {
				decodedTag_slrargextensioncontainer, n_slrargextensioncontainer, rawVal_slrargextensioncontainer, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding slr-ArgExtensionContainer: %w", err)
				}
				if decodedTag_slrargextensioncontainer.Class != tag.ClassContextSpecific || decodedTag_slrargextensioncontainer.Number != 7 || decodedTag_slrargextensioncontainer.Constructed != true {
					return fmt.Errorf("decoding slr-ArgExtensionContainer: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_slrargextensioncontainer)
				}
				reconstructed_slrargextensioncontainer, reconstructionErr_slrargextensioncontainer := ber.EncodeSequence(rawVal_slrargextensioncontainer)
				if reconstructionErr_slrargextensioncontainer != nil {
					return fmt.Errorf("decoding slr-ArgExtensionContainer: %w", reconstructionErr_slrargextensioncontainer)
				}
				var dec_slrargextensioncontainer SLRArgExtensionContainer3
				if unmErr := dec_slrargextensioncontainer.UnmarshalBER(reconstructed_slrargextensioncontainer, ber.ChildDecodeOptions(opts, "slr-ArgExtensionContainer")...); unmErr != nil {
					return fmt.Errorf("decoding slr-ArgExtensionContainer: %w", unmErr)
				}
				v.SlrArgExtensionContainer = &dec_slrargextensioncontainer
				if offset < 0 || offset >
					len(content) || n_slrargextensioncontainer < 0 || n_slrargextensioncontainer >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_slrargextensioncontainer
			}
		}
	}
	// Decode add-LocationEstimate
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 8 {
				decodedTag_addlocationestimate, n_addlocationestimate, rawVal_addlocationestimate, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding add-LocationEstimate: %w", err)
				}
				if decodedTag_addlocationestimate.Class != tag.ClassContextSpecific || decodedTag_addlocationestimate.Number != 8 {
					return fmt.Errorf("decoding add-LocationEstimate: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_addlocationestimate)
				}
				decVal_addlocationestimate, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_addlocationestimate.Constructed, rawVal_addlocationestimate, opts...)
				if octetErr != nil {
					return fmt.Errorf("decoding add-LocationEstimate: %w", octetErr)
				}
				tmp_addlocationestimate := LCSAddGeographicalInformation(decVal_addlocationestimate)
				v.AddLocationEstimate = &tmp_addlocationestimate
				if offset < 0 || offset >
					len(content) || n_addlocationestimate < 0 || n_addlocationestimate > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_addlocationestimate
				if len(*v.AddLocationEstimate) < 1 || len(*v.AddLocationEstimate) > 91 {
					if constraintErr := ber.CheckDecodedLength(opts, "add-LocationEstimate", "SIZE (1..91)", len(*v.AddLocationEstimate)); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode deferredmt-lrData
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 9 {
				decodedTag_deferredmtlrdata, n_deferredmtlrdata, rawVal_deferredmtlrdata, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding deferredmt-lrData: %w", err)
				}
				if decodedTag_deferredmtlrdata.Class != tag.ClassContextSpecific || decodedTag_deferredmtlrdata.Number != 9 || decodedTag_deferredmtlrdata.Constructed != true {
					return fmt.Errorf("decoding deferredmt-lrData: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_deferredmtlrdata)
				}
				reconstructed_deferredmtlrdata, reconstructionErr_deferredmtlrdata := ber.EncodeSequence(rawVal_deferredmtlrdata)
				if reconstructionErr_deferredmtlrdata != nil {
					return fmt.Errorf("decoding deferredmt-lrData: %w", reconstructionErr_deferredmtlrdata)
				}
				var dec_deferredmtlrdata LCSDeferredmtLrData
				if unmErr := dec_deferredmtlrdata.UnmarshalBER(reconstructed_deferredmtlrdata, ber.ChildDecodeOptions(opts, "deferredmt-lrData")...); unmErr != nil {
					return fmt.Errorf("decoding deferredmt-lrData: %w", unmErr)
				}
				v.DeferredmtLrData = &dec_deferredmtlrdata
				if offset < 0 || offset >
					len(content) || n_deferredmtlrdata < 0 || n_deferredmtlrdata > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_deferredmtlrdata
			}
		}
	}
	// Decode lcs-ReferenceNumber
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 10 {
				decodedTag_lcsreferencenumber, n_lcsreferencenumber, rawVal_lcsreferencenumber, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding lcs-ReferenceNumber: %w", err)
				}
				if decodedTag_lcsreferencenumber.Class != tag.ClassContextSpecific || decodedTag_lcsreferencenumber.Number != 10 {
					return fmt.Errorf("decoding lcs-ReferenceNumber: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_lcsreferencenumber)
				}
				decVal_lcsreferencenumber, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_lcsreferencenumber.Constructed, rawVal_lcsreferencenumber, opts...)
				if octetErr != nil {
					return fmt.Errorf("decoding lcs-ReferenceNumber: %w", octetErr)
				}
				tmp_lcsreferencenumber := LCSLCSReferenceNumber(decVal_lcsreferencenumber)
				v.LcsReferenceNumber = &tmp_lcsreferencenumber
				if offset < 0 || offset >
					len(content) || n_lcsreferencenumber < 0 || n_lcsreferencenumber > len(
					content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_lcsreferencenumber
				if len(*v.LcsReferenceNumber) < 1 || len(*v.LcsReferenceNumber) > 1 {
					if constraintErr := ber.CheckDecodedLength(opts, "lcs-ReferenceNumber", "SIZE (1)", len(*v.LcsReferenceNumber)); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode geranPositioningData
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 11 {
				decodedTag_geranpositioningdata, n_geranpositioningdata, rawVal_geranpositioningdata, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding geranPositioningData: %w", err)
				}
				if decodedTag_geranpositioningdata.Class != tag.ClassContextSpecific || decodedTag_geranpositioningdata.Number != 11 {
					return fmt.Errorf("decoding geranPositioningData: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_geranpositioningdata)
				}
				decVal_geranpositioningdata, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_geranpositioningdata.Constructed, rawVal_geranpositioningdata, opts...)
				if octetErr != nil {
					return fmt.Errorf("decoding geranPositioningData: %w", octetErr)
				}
				tmp_geranpositioningdata := LCSPositioningDataInformation(decVal_geranpositioningdata)
				v.GeranPositioningData = &tmp_geranpositioningdata
				if offset < 0 || offset >
					len(content) || n_geranpositioningdata < 0 || n_geranpositioningdata >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_geranpositioningdata
				if len(*v.GeranPositioningData) < 2 || len(*v.GeranPositioningData) > 10 {
					if constraintErr := ber.CheckDecodedLength(opts, "geranPositioningData", "SIZE (2..10)", len(*v.GeranPositioningData)); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode utranPositioningData
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 12 {
				decodedTag_utranpositioningdata, n_utranpositioningdata, rawVal_utranpositioningdata, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding utranPositioningData: %w", err)
				}
				if decodedTag_utranpositioningdata.Class != tag.ClassContextSpecific || decodedTag_utranpositioningdata.Number != 12 {
					return fmt.Errorf("decoding utranPositioningData: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_utranpositioningdata)
				}
				decVal_utranpositioningdata, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_utranpositioningdata.Constructed, rawVal_utranpositioningdata, opts...)
				if octetErr != nil {
					return fmt.Errorf("decoding utranPositioningData: %w", octetErr)
				}
				tmp_utranpositioningdata := LCSUtranPositioningDataInfo(decVal_utranpositioningdata)
				v.UtranPositioningData = &tmp_utranpositioningdata
				if offset < 0 || offset >
					len(content) || n_utranpositioningdata < 0 || n_utranpositioningdata >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_utranpositioningdata
				if len(*v.UtranPositioningData) < 3 || len(*v.UtranPositioningData) > 11 {
					if constraintErr := ber.CheckDecodedLength(opts, "utranPositioningData", "SIZE (3..11)", len(*v.UtranPositioningData)); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode cellIdOrSai
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 13 {
				decodedTag_cellidorsai, n_cellidorsai, innerData_cellidorsai, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding cellIdOrSai: %w", err)
				}
				if decodedTag_cellidorsai.Class != tag.ClassContextSpecific || decodedTag_cellidorsai.Number != 13 || decodedTag_cellidorsai.Constructed != true {
					return fmt.Errorf("decoding cellIdOrSai: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_cellidorsai)
				}
				// Decode inner value from explicit tag wrapper
				var dec_cellidorsai CellGlobalIdOrServiceAreaIdOrLAI3
				if unmErr := dec_cellidorsai.UnmarshalBER(innerData_cellidorsai, ber.ChildDecodeOptions(opts, "cellIdOrSai")...); unmErr != nil {
					return fmt.Errorf("decoding cellIdOrSai: %w", unmErr)
				}
				v.CellIdOrSai = &dec_cellidorsai
				if offset < 0 || offset >
					len(content) || n_cellidorsai < 0 || n_cellidorsai > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_cellidorsai
			}
		}
	}
	// Decode h-gmlc-Address
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 14 {
				decodedTag_hgmlcaddress, n_hgmlcaddress, rawVal_hgmlcaddress, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding h-gmlc-Address: %w", err)
				}
				if decodedTag_hgmlcaddress.Class != tag.ClassContextSpecific || decodedTag_hgmlcaddress.Number != 14 {
					return fmt.Errorf("decoding h-gmlc-Address: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_hgmlcaddress)
				}
				decVal_hgmlcaddress, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_hgmlcaddress.Constructed, rawVal_hgmlcaddress, opts...)
				if octetErr != nil {
					return fmt.Errorf("decoding h-gmlc-Address: %w", octetErr)
				}
				tmp_hgmlcaddress := CommonDataTypesGSNAddress(decVal_hgmlcaddress)
				v.HGmlcAddress = &tmp_hgmlcaddress
				if offset < 0 || offset >
					len(content) || n_hgmlcaddress < 0 || n_hgmlcaddress > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_hgmlcaddress
				if len(*v.HGmlcAddress) < 5 || len(*v.HGmlcAddress) > 17 {
					if constraintErr := ber.CheckDecodedLength(opts, "h-gmlc-Address", "SIZE (5..17)", len(*v.HGmlcAddress)); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode lcsServiceTypeID
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 15 {
				decodedTag_lcsservicetypeid, n_lcsservicetypeid, rawVal_lcsservicetypeid, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding lcsServiceTypeID: %w", err)
				}
				if decodedTag_lcsservicetypeid.Class != tag.ClassContextSpecific || decodedTag_lcsservicetypeid.Number != 15 || decodedTag_lcsservicetypeid.Constructed != false {
					return fmt.Errorf("decoding lcsServiceTypeID: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_lcsservicetypeid)
				}
				decVal_lcsservicetypeid, intErr := ber.DecodeIntegerValue(rawVal_lcsservicetypeid)
				if intErr != nil {
					return fmt.Errorf("decoding lcsServiceTypeID: %w", intErr)
				}
				tmp_lcsservicetypeid := LCSServiceTypeID3(decVal_lcsservicetypeid)
				v.LcsServiceTypeID = &tmp_lcsservicetypeid
				if offset < 0 || offset >
					len(content) || n_lcsservicetypeid < 0 || n_lcsservicetypeid > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_lcsservicetypeid
				if !(int64(*v.LcsServiceTypeID) >= 0 && int64(*v.LcsServiceTypeID) <= 127) {
					if constraintErr := ber.CheckDecodedValue(opts, "lcsServiceTypeID", "(0..127)", fmt.Sprint(int64(*v.LcsServiceTypeID))); constraintErr != nil {
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
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 17 {
				decodedTag_saipresent, n_saipresent, rawVal_saipresent, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding sai-Present: %w", err)
				}
				if decodedTag_saipresent.Class != tag.ClassContextSpecific || decodedTag_saipresent.Number != 17 || decodedTag_saipresent.Constructed != false {
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
	// Decode pseudonymIndicator
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 18 {
				decodedTag_pseudonymindicator, n_pseudonymindicator, rawVal_pseudonymindicator, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding pseudonymIndicator: %w", err)
				}
				if decodedTag_pseudonymindicator.Class != tag.ClassContextSpecific || decodedTag_pseudonymindicator.Number != 18 || decodedTag_pseudonymindicator.Constructed != false {
					return fmt.Errorf("decoding pseudonymIndicator: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_pseudonymindicator)
				}
				if len(rawVal_pseudonymindicator) != 0 {
					return fmt.Errorf("decoding pseudonymIndicator: %w: NULL content length %d", ber.ErrInvalidValue, len(rawVal_pseudonymindicator))
				}
				v.PseudonymIndicator = &struct{}{}
				if offset < 0 || offset >
					len(content) || n_pseudonymindicator < 0 || n_pseudonymindicator > len(
					content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_pseudonymindicator
			}
		}
	}
	// Decode accuracyFulfilmentIndicator
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 19 {
				decodedTag_accuracyfulfilmentindicator, n_accuracyfulfilmentindicator, rawVal_accuracyfulfilmentindicator, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding accuracyFulfilmentIndicator: %w", err)
				}
				if decodedTag_accuracyfulfilmentindicator.Class != tag.ClassContextSpecific || decodedTag_accuracyfulfilmentindicator.Number != 19 || decodedTag_accuracyfulfilmentindicator.Constructed != false {
					return fmt.Errorf("decoding accuracyFulfilmentIndicator: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_accuracyfulfilmentindicator)
				}
				decVal_accuracyfulfilmentindicator, intErr := ber.DecodeEnumeratedValue(rawVal_accuracyfulfilmentindicator)
				if intErr != nil {
					return fmt.Errorf("decoding accuracyFulfilmentIndicator: %w", intErr)
				}
				tmp_accuracyfulfilmentindicator := LCSAccuracyFulfilmentIndicator(decVal_accuracyfulfilmentindicator)
				v.AccuracyFulfilmentIndicator = &tmp_accuracyfulfilmentindicator
				if offset < 0 || offset >
					len(content) || n_accuracyfulfilmentindicator < 0 || n_accuracyfulfilmentindicator >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_accuracyfulfilmentindicator
			}
		}
	}
	// Decode velocityEstimate
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 20 {
				decodedTag_velocityestimate, n_velocityestimate, rawVal_velocityestimate, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding velocityEstimate: %w", err)
				}
				if decodedTag_velocityestimate.Class != tag.ClassContextSpecific || decodedTag_velocityestimate.Number != 20 {
					return fmt.Errorf("decoding velocityEstimate: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_velocityestimate)
				}
				decVal_velocityestimate, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_velocityestimate.Constructed, rawVal_velocityestimate, opts...)
				if octetErr != nil {
					return fmt.Errorf("decoding velocityEstimate: %w", octetErr)
				}
				tmp_velocityestimate := LCSVelocityEstimate(decVal_velocityestimate)
				v.VelocityEstimate = &tmp_velocityestimate
				if offset < 0 || offset >
					len(content) || n_velocityestimate < 0 || n_velocityestimate > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_velocityestimate
				if len(*v.VelocityEstimate) < 4 || len(*v.VelocityEstimate) > 7 {
					if constraintErr := ber.CheckDecodedLength(opts, "velocityEstimate", "SIZE (4..7)", len(*v.VelocityEstimate)); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode sequenceNumber
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 21 {
				decodedTag_sequencenumber, n_sequencenumber, rawVal_sequencenumber, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding sequenceNumber: %w", err)
				}
				if decodedTag_sequencenumber.Class != tag.ClassContextSpecific || decodedTag_sequencenumber.Number != 21 || decodedTag_sequencenumber.Constructed != false {
					return fmt.Errorf("decoding sequenceNumber: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_sequencenumber)
				}
				decVal_sequencenumber, intErr := ber.DecodeIntegerValue(rawVal_sequencenumber)
				if intErr != nil {
					return fmt.Errorf("decoding sequenceNumber: %w", intErr)
				}
				tmp_sequencenumber := LCSSequenceNumber(decVal_sequencenumber)
				v.SequenceNumber = &tmp_sequencenumber
				if offset < 0 || offset >
					len(content) || n_sequencenumber < 0 || n_sequencenumber > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_sequencenumber
				if !(int64(*v.SequenceNumber) >= 1 && int64(*v.SequenceNumber) <= 8639999) {
					if constraintErr := ber.CheckDecodedValue(opts, "sequenceNumber", "(1..8639999)", fmt.Sprint(int64(*v.SequenceNumber))); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode periodicLDRInfo
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 22 {
				decodedTag_periodicldrinfo, n_periodicldrinfo, rawVal_periodicldrinfo, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding periodicLDRInfo: %w", err)
				}
				if decodedTag_periodicldrinfo.Class != tag.ClassContextSpecific || decodedTag_periodicldrinfo.Number != 22 || decodedTag_periodicldrinfo.Constructed != true {
					return fmt.Errorf("decoding periodicLDRInfo: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_periodicldrinfo)
				}
				reconstructed_periodicldrinfo, reconstructionErr_periodicldrinfo := ber.EncodeSequence(rawVal_periodicldrinfo)
				if reconstructionErr_periodicldrinfo != nil {
					return fmt.Errorf("decoding periodicLDRInfo: %w", reconstructionErr_periodicldrinfo)
				}
				var dec_periodicldrinfo LCSPeriodicLDRInfo
				if unmErr := dec_periodicldrinfo.UnmarshalBER(reconstructed_periodicldrinfo, ber.ChildDecodeOptions(opts, "periodicLDRInfo")...); unmErr != nil {
					return fmt.Errorf("decoding periodicLDRInfo: %w", unmErr)
				}
				v.PeriodicLDRInfo = &dec_periodicldrinfo
				if offset < 0 || offset >
					len(content) || n_periodicldrinfo < 0 || n_periodicldrinfo > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_periodicldrinfo
			}
		}
	}
	// Decode mo-lrShortCircuitIndicator
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 23 {
				decodedTag_molrshortcircuitindicator, n_molrshortcircuitindicator, rawVal_molrshortcircuitindicator, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding mo-lrShortCircuitIndicator: %w", err)
				}
				if decodedTag_molrshortcircuitindicator.Class != tag.ClassContextSpecific || decodedTag_molrshortcircuitindicator.Number != 23 || decodedTag_molrshortcircuitindicator.Constructed != false {
					return fmt.Errorf("decoding mo-lrShortCircuitIndicator: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_molrshortcircuitindicator)
				}
				if len(rawVal_molrshortcircuitindicator) != 0 {
					return fmt.Errorf("decoding mo-lrShortCircuitIndicator: %w: NULL content length %d", ber.ErrInvalidValue, len(rawVal_molrshortcircuitindicator))
				}
				v.MoLrShortCircuitIndicator = &struct{}{}
				if offset < 0 || offset >
					len(content) || n_molrshortcircuitindicator < 0 || n_molrshortcircuitindicator >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_molrshortcircuitindicator
			}
		}
	}
	// Decode geranGANSSpositioningData
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 24 {
				decodedTag_gerangansspositioningdata, n_gerangansspositioningdata, rawVal_gerangansspositioningdata, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding geranGANSSpositioningData: %w", err)
				}
				if decodedTag_gerangansspositioningdata.Class != tag.ClassContextSpecific || decodedTag_gerangansspositioningdata.Number != 24 {
					return fmt.Errorf("decoding geranGANSSpositioningData: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_gerangansspositioningdata)
				}
				decVal_gerangansspositioningdata, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_gerangansspositioningdata.Constructed, rawVal_gerangansspositioningdata, opts...)
				if octetErr != nil {
					return fmt.Errorf("decoding geranGANSSpositioningData: %w", octetErr)
				}
				tmp_gerangansspositioningdata := LCSGeranGANSSpositioningData(decVal_gerangansspositioningdata)
				v.GeranGANSSpositioningData = &tmp_gerangansspositioningdata
				if offset < 0 || offset >
					len(content) || n_gerangansspositioningdata < 0 || n_gerangansspositioningdata >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_gerangansspositioningdata
				if len(*v.GeranGANSSpositioningData) < 2 || len(*v.GeranGANSSpositioningData) > 10 {
					if constraintErr := ber.CheckDecodedLength(opts, "geranGANSSpositioningData", "SIZE (2..10)", len(*v.GeranGANSSpositioningData)); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode utranGANSSpositioningData
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 25 {
				decodedTag_utrangansspositioningdata, n_utrangansspositioningdata, rawVal_utrangansspositioningdata, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding utranGANSSpositioningData: %w", err)
				}
				if decodedTag_utrangansspositioningdata.Class != tag.ClassContextSpecific || decodedTag_utrangansspositioningdata.Number != 25 {
					return fmt.Errorf("decoding utranGANSSpositioningData: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_utrangansspositioningdata)
				}
				decVal_utrangansspositioningdata, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_utrangansspositioningdata.Constructed, rawVal_utrangansspositioningdata, opts...)
				if octetErr != nil {
					return fmt.Errorf("decoding utranGANSSpositioningData: %w", octetErr)
				}
				tmp_utrangansspositioningdata := LCSUtranGANSSpositioningData(decVal_utrangansspositioningdata)
				v.UtranGANSSpositioningData = &tmp_utrangansspositioningdata
				if offset < 0 || offset >
					len(content) || n_utrangansspositioningdata < 0 || n_utrangansspositioningdata >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_utrangansspositioningdata
				if len(*v.UtranGANSSpositioningData) < 1 || len(*v.UtranGANSSpositioningData) > 9 {
					if constraintErr := ber.CheckDecodedLength(opts, "utranGANSSpositioningData", "SIZE (1..9)", len(*v.UtranGANSSpositioningData)); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode targetServingNodeForHandover
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 26 {
				decodedTag_targetservingnodeforhandover, n_targetservingnodeforhandover, innerData_targetservingnodeforhandover, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding targetServingNodeForHandover: %w", err)
				}
				if decodedTag_targetservingnodeforhandover.Class != tag.ClassContextSpecific || decodedTag_targetservingnodeforhandover.Number != 26 || decodedTag_targetservingnodeforhandover.Constructed != true {
					return fmt.Errorf("decoding targetServingNodeForHandover: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_targetservingnodeforhandover)
				}
				// Decode inner value from explicit tag wrapper
				var dec_targetservingnodeforhandover LCSServingNodeAddress
				if unmErr := dec_targetservingnodeforhandover.UnmarshalBER(innerData_targetservingnodeforhandover, ber.ChildDecodeOptions(opts, "targetServingNodeForHandover")...); unmErr != nil {
					return fmt.Errorf("decoding targetServingNodeForHandover: %w", unmErr)
				}
				v.TargetServingNodeForHandover = &dec_targetservingnodeforhandover
				if offset < 0 || offset >
					len(content) || n_targetservingnodeforhandover < 0 || n_targetservingnodeforhandover >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_targetservingnodeforhandover
			}
		}
	}
	// Decode utranAdditionalPositioningData
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 27 {
				decodedTag_utranadditionalpositioningdata, n_utranadditionalpositioningdata, rawVal_utranadditionalpositioningdata, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding utranAdditionalPositioningData: %w", err)
				}
				if decodedTag_utranadditionalpositioningdata.Class != tag.ClassContextSpecific || decodedTag_utranadditionalpositioningdata.Number != 27 {
					return fmt.Errorf("decoding utranAdditionalPositioningData: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_utranadditionalpositioningdata)
				}
				decVal_utranadditionalpositioningdata, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_utranadditionalpositioningdata.Constructed, rawVal_utranadditionalpositioningdata, opts...)
				if octetErr != nil {
					return fmt.Errorf("decoding utranAdditionalPositioningData: %w", octetErr)
				}
				tmp_utranadditionalpositioningdata := LCSUtranAdditionalPositioningData(decVal_utranadditionalpositioningdata)
				v.UtranAdditionalPositioningData = &tmp_utranadditionalpositioningdata
				if offset < 0 || offset >
					len(content) || n_utranadditionalpositioningdata < 0 || n_utranadditionalpositioningdata >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_utranadditionalpositioningdata
				if len(*v.UtranAdditionalPositioningData) < 1 || len(*v.UtranAdditionalPositioningData) > 8 {
					if constraintErr := ber.CheckDecodedLength(opts, "utranAdditionalPositioningData", "SIZE (1..8)", len(*v.UtranAdditionalPositioningData)); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode utranBaroPressureMeas
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 28 {
				decodedTag_utranbaropressuremeas, n_utranbaropressuremeas, rawVal_utranbaropressuremeas, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding utranBaroPressureMeas: %w", err)
				}
				if decodedTag_utranbaropressuremeas.Class != tag.ClassContextSpecific || decodedTag_utranbaropressuremeas.Number != 28 || decodedTag_utranbaropressuremeas.Constructed != false {
					return fmt.Errorf("decoding utranBaroPressureMeas: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_utranbaropressuremeas)
				}
				decVal_utranbaropressuremeas, intErr := ber.DecodeIntegerValue(rawVal_utranbaropressuremeas)
				if intErr != nil {
					return fmt.Errorf("decoding utranBaroPressureMeas: %w", intErr)
				}
				tmp_utranbaropressuremeas := LCSUtranBaroPressureMeas(decVal_utranbaropressuremeas)
				v.UtranBaroPressureMeas = &tmp_utranbaropressuremeas
				if offset < 0 || offset >
					len(content) || n_utranbaropressuremeas < 0 || n_utranbaropressuremeas >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_utranbaropressuremeas
				if !(int64(*v.UtranBaroPressureMeas) >= 30000 && int64(*v.UtranBaroPressureMeas) <= 115000) {
					if constraintErr := ber.CheckDecodedValue(opts, "utranBaroPressureMeas", "(30000..115000)", fmt.Sprint(int64(*v.UtranBaroPressureMeas))); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode utranCivicAddress
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 29 {
				decodedTag_utrancivicaddress, n_utrancivicaddress, rawVal_utrancivicaddress, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding utranCivicAddress: %w", err)
				}
				if decodedTag_utrancivicaddress.Class != tag.ClassContextSpecific || decodedTag_utrancivicaddress.Number != 29 {
					return fmt.Errorf("decoding utranCivicAddress: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_utrancivicaddress)
				}
				decVal_utrancivicaddress, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_utrancivicaddress.Constructed, rawVal_utrancivicaddress, opts...)
				if octetErr != nil {
					return fmt.Errorf("decoding utranCivicAddress: %w", octetErr)
				}
				tmp_utrancivicaddress := LCSUtranCivicAddress(decVal_utrancivicaddress)
				v.UtranCivicAddress = &tmp_utrancivicaddress
				if offset < 0 || offset >
					len(content) || n_utrancivicaddress < 0 || n_utrancivicaddress > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_utrancivicaddress
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:], opts...)
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "LCSSubscriberLocationReportArg", Cause: extErr_}
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

// MarshalBER encodes LCSDeferredmtLrData to BER format.
func (v *LCSDeferredmtLrData) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: LCSDeferredmtLrData receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *LCSDeferredmtLrData) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if (v.DeferredLocationEventType).BitLength < 1 || (v.DeferredLocationEventType).BitLength > 16 {
		if constraintErr := ber.CheckEncodedLength(opts, "deferredLocationEventType", "SIZE (1..16)", (v.DeferredLocationEventType).BitLength); constraintErr != nil {
			return nil, constraintErr
		}
	}
	if bitStringErr := ber.ValidateBitStringLength(v.DeferredLocationEventType.Bytes, v.DeferredLocationEventType.BitLength); bitStringErr != nil {
		return nil, fmt.Errorf("encoding %s: %w", "deferredLocationEventType", bitStringErr)
	}
	// arithmetic pattern BER_BITSTRING_FIELD: 0 <= bit length before modulo and subtraction; gen/codegen.go:526
	if v.DeferredLocationEventType.BitLength < 0 {
		return nil, fmt.Errorf("negative bit string length")
	}
	enc_deferredlocationeventtype, encodeErr_enc_deferredlocationeventtype := ber.EncodeBitString(v.DeferredLocationEventType.Bytes, (8-(v.DeferredLocationEventType.BitLength%8))%8)
	if encodeErr_enc_deferredlocationeventtype != nil {
		return nil, fmt.Errorf("encoding deferredLocationEventType: %w", encodeErr_enc_deferredlocationeventtype)
	}
	children = append(children, enc_deferredlocationeventtype...)
	if v.TerminationCause != nil {
		enc_terminationcause := ber.EncodeEnumerated(int64(*v.TerminationCause))
		retagged_enc_terminationcause, tagErr_enc_terminationcause := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_terminationcause)
		if tagErr_enc_terminationcause != nil {
			return nil, fmt.Errorf("encoding terminationCause: %w", tagErr_enc_terminationcause)
		}
		enc_terminationcause = retagged_enc_terminationcause
		children = append(children, enc_terminationcause...)
	}
	if v.LcsLocationInfo != nil {
		enc_lcslocationinfo, err := v.LcsLocationInfo.MarshalBER(ber.ChildEncodeOptions(opts, "lcsLocationInfo")...)
		if err != nil {
			return nil, fmt.Errorf("encoding lcsLocationInfo: %w", err)
		}
		retagged_enc_lcslocationinfo, tagErr_enc_lcslocationinfo := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_lcslocationinfo)
		if tagErr_enc_lcslocationinfo != nil {
			return nil, fmt.Errorf("encoding lcsLocationInfo: %w", tagErr_enc_lcslocationinfo)
		}
		enc_lcslocationinfo = retagged_enc_lcslocationinfo
		children = append(children, enc_lcslocationinfo...)
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

// MarshalDER encodes LCSDeferredmtLrData to DER format.
func (v *LCSDeferredmtLrData) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: LCSDeferredmtLrData receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if (v.DeferredLocationEventType).BitLength < 1 || (v.DeferredLocationEventType).BitLength > 16 {
		if constraintErr := ber.CheckEncodedLength(nil, "deferredLocationEventType", "SIZE (1..16)", (v.DeferredLocationEventType).BitLength); constraintErr != nil {
			return nil, constraintErr
		}
	}
	if bitStringErr := ber.ValidateBitStringLength(v.DeferredLocationEventType.Bytes, v.DeferredLocationEventType.BitLength); bitStringErr != nil {
		return nil, fmt.Errorf("encoding %s: %w", "deferredLocationEventType", bitStringErr)
	}
	if bitStringErr := ber.ValidateDERBitString(v.DeferredLocationEventType.Bytes, v.DeferredLocationEventType.BitLength); bitStringErr != nil {
		return nil, fmt.Errorf("encoding %s: %w", "deferredLocationEventType", bitStringErr)
	}
	// arithmetic pattern BER_BITSTRING_FIELD: 0 <= bit length before modulo and subtraction; gen/codegen.go:526
	if v.DeferredLocationEventType.BitLength < 0 {
		return nil, fmt.Errorf("negative bit string length")
	}
	enc_deferredlocationeventtype, encodeErr_enc_deferredlocationeventtype := ber.EncodeDERNamedBitString(v.DeferredLocationEventType.Bytes, v.DeferredLocationEventType.BitLength)
	if encodeErr_enc_deferredlocationeventtype != nil {
		return nil, fmt.Errorf("encoding deferredLocationEventType: %w", encodeErr_enc_deferredlocationeventtype)
	}
	children = append(children, enc_deferredlocationeventtype...)
	if v.TerminationCause != nil {
		enc_terminationcause := ber.EncodeEnumerated(int64(*v.TerminationCause))
		retagged_enc_terminationcause, tagErr_enc_terminationcause := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_terminationcause)
		if tagErr_enc_terminationcause != nil {
			return nil, fmt.Errorf("encoding terminationCause: %w", tagErr_enc_terminationcause)
		}
		enc_terminationcause = retagged_enc_terminationcause
		children = append(children, enc_terminationcause...)
	}
	if v.LcsLocationInfo != nil {
		enc_lcslocationinfo, err := v.LcsLocationInfo.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding lcsLocationInfo: %w", err)
		}
		retagged_enc_lcslocationinfo, tagErr_enc_lcslocationinfo := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_lcslocationinfo)
		if tagErr_enc_lcslocationinfo != nil {
			return nil, fmt.Errorf("encoding lcsLocationInfo: %w", tagErr_enc_lcslocationinfo)
		}
		enc_lcslocationinfo = retagged_enc_lcslocationinfo
		children = append(children, enc_lcslocationinfo...)
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
		return nil, fmt.Errorf("encoding LCSDeferredmtLrData as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes LCSDeferredmtLrData from BER/DER format.
func (v *LCSDeferredmtLrData) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: LCSDeferredmtLrData destination is nil", ber.ErrInvalidValue)
	}
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = LCSDeferredmtLrData{}
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
		return fmt.Errorf("decoding LCSDeferredmtLrData SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "LCSDeferredmtLrData", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode deferredLocationEventType
	if offset >= len(content) {
		return fmt.Errorf("missing required field deferredLocationEventType")
	}
	bsBytes_deferredlocationeventtype, bsUnused_deferredlocationeventtype, n, err := ber.DecodeBitString(content[offset:], opts...)
	if err != nil {
		return fmt.Errorf("decoding deferredLocationEventType: %w", err)
	}
	bsBitLength_deferredlocationeventtype, bsLenErr_deferredlocationeventtype := ber.BitStringBitLength(len(bsBytes_deferredlocationeventtype), bsUnused_deferredlocationeventtype)
	if bsLenErr_deferredlocationeventtype != nil {
		return fmt.Errorf("decoding deferredLocationEventType: %w", bsLenErr_deferredlocationeventtype)
	}
	v.DeferredLocationEventType = runtime.BitString{Bytes: bsBytes_deferredlocationeventtype, BitLength: bsBitLength_deferredlocationeventtype}
	if offset < 0 || offset >
		len(content) || n < 0 || n > len(content[offset:]) {
		return fmt.Errorf("invalid BER content window")
	}

	offset += n
	v.DeferredLocationEventType = ber.NormalizeNamedBitStringSize(v.DeferredLocationEventType, []ber.NamedBitSizeSet{{{Min: 1, Max: 16}}}, opts...)
	if (v.DeferredLocationEventType).BitLength < 1 || (v.DeferredLocationEventType).BitLength > 16 {
		if constraintErr := ber.CheckDecodedLength(opts, "deferredLocationEventType", "SIZE (1..16)", (v.DeferredLocationEventType).BitLength); constraintErr != nil {
			return constraintErr
		}
	}
	// Decode terminationCause
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
				decodedTag_terminationcause, n_terminationcause, rawVal_terminationcause, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding terminationCause: %w", err)
				}
				if decodedTag_terminationcause.Class != tag.ClassContextSpecific || decodedTag_terminationcause.Number != 0 || decodedTag_terminationcause.Constructed != false {
					return fmt.Errorf("decoding terminationCause: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_terminationcause)
				}
				decVal_terminationcause, intErr := ber.DecodeEnumeratedValue(rawVal_terminationcause)
				if intErr != nil {
					return fmt.Errorf("decoding terminationCause: %w", intErr)
				}
				tmp_terminationcause := LCSTerminationCause(decVal_terminationcause)
				v.TerminationCause = &tmp_terminationcause
				if offset < 0 || offset >
					len(content) || n_terminationcause < 0 || n_terminationcause >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_terminationcause
			}
		}
	}
	// Decode lcsLocationInfo
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
				decodedTag_lcslocationinfo, n_lcslocationinfo, rawVal_lcslocationinfo, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding lcsLocationInfo: %w", err)
				}
				if decodedTag_lcslocationinfo.Class != tag.ClassContextSpecific || decodedTag_lcslocationinfo.Number != 1 || decodedTag_lcslocationinfo.Constructed != true {
					return fmt.Errorf("decoding lcsLocationInfo: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_lcslocationinfo)
				}
				reconstructed_lcslocationinfo, reconstructionErr_lcslocationinfo := ber.EncodeSequence(rawVal_lcslocationinfo)
				if reconstructionErr_lcslocationinfo != nil {
					return fmt.Errorf("decoding lcsLocationInfo: %w", reconstructionErr_lcslocationinfo)
				}
				var dec_lcslocationinfo LCSLCSLocationInfo
				if unmErr := dec_lcslocationinfo.UnmarshalBER(reconstructed_lcslocationinfo, ber.ChildDecodeOptions(opts, "lcsLocationInfo")...); unmErr != nil {
					return fmt.Errorf("decoding lcsLocationInfo: %w", unmErr)
				}
				v.LcsLocationInfo = &dec_lcslocationinfo
				if offset < 0 || offset >
					len(content) || n_lcslocationinfo < 0 || n_lcslocationinfo >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_lcslocationinfo
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:], opts...)
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "LCSDeferredmtLrData", Cause: extErr_}
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

// MarshalBER encodes LCSServingNodeAddress to BER format.
func (v *LCSServingNodeAddress) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: LCSServingNodeAddress receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *LCSServingNodeAddress) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	switch v.Choice {
	case LCSServingNodeAddressChoiceMscNumber:
		if v.MscNumber == nil {
			return nil, fmt.Errorf("%w: choice LCSServingNodeAddress: msc-Number is nil", ber.ErrInvalidValue)
		}
		enc_0, encodeErr_enc_0 := ber.EncodeOctetString([]byte(*v.MscNumber))
		if encodeErr_enc_0 != nil {
			return nil, fmt.Errorf("encoding msc-Number: %w", encodeErr_enc_0)
		}
		if len(*v.MscNumber) < 1 || len(*v.MscNumber) > 9 {
			if constraintErr := ber.CheckEncodedLength(opts, "msc-Number", "SIZE (1..9)", len(*v.MscNumber)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		if len(*v.MscNumber) < 1 || len(*v.MscNumber) > 20 {
			if constraintErr := ber.CheckEncodedLength(opts, "msc-Number", "SIZE (1..20)", len(*v.MscNumber)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		retagged_enc_0, tagErr_enc_0 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_0)
		if tagErr_enc_0 != nil {
			return nil, fmt.Errorf("encoding msc-Number: %w", tagErr_enc_0)
		}
		enc_0 = retagged_enc_0
		return enc_0, nil
	case LCSServingNodeAddressChoiceSgsnNumber:
		if v.SgsnNumber == nil {
			return nil, fmt.Errorf("%w: choice LCSServingNodeAddress: sgsn-Number is nil", ber.ErrInvalidValue)
		}
		enc_1, encodeErr_enc_1 := ber.EncodeOctetString([]byte(*v.SgsnNumber))
		if encodeErr_enc_1 != nil {
			return nil, fmt.Errorf("encoding sgsn-Number: %w", encodeErr_enc_1)
		}
		if len(*v.SgsnNumber) < 1 || len(*v.SgsnNumber) > 9 {
			if constraintErr := ber.CheckEncodedLength(opts, "sgsn-Number", "SIZE (1..9)", len(*v.SgsnNumber)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		if len(*v.SgsnNumber) < 1 || len(*v.SgsnNumber) > 20 {
			if constraintErr := ber.CheckEncodedLength(opts, "sgsn-Number", "SIZE (1..20)", len(*v.SgsnNumber)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		retagged_enc_1, tagErr_enc_1 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_1)
		if tagErr_enc_1 != nil {
			return nil, fmt.Errorf("encoding sgsn-Number: %w", tagErr_enc_1)
		}
		enc_1 = retagged_enc_1
		return enc_1, nil
	case LCSServingNodeAddressChoiceMmeNumber:
		if v.MmeNumber == nil {
			return nil, fmt.Errorf("%w: choice LCSServingNodeAddress: mme-Number is nil", ber.ErrInvalidValue)
		}
		enc_2, encodeErr_enc_2 := ber.EncodeOctetString([]byte(*v.MmeNumber))
		if encodeErr_enc_2 != nil {
			return nil, fmt.Errorf("encoding mme-Number: %w", encodeErr_enc_2)
		}
		if len(*v.MmeNumber) < 9 || len(*v.MmeNumber) > 255 {
			if constraintErr := ber.CheckEncodedLength(opts, "mme-Number", "SIZE (9..255)", len(*v.MmeNumber)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		retagged_enc_2, tagErr_enc_2 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_2)
		if tagErr_enc_2 != nil {
			return nil, fmt.Errorf("encoding mme-Number: %w", tagErr_enc_2)
		}
		enc_2 = retagged_enc_2
		return enc_2, nil
	default:
		return nil, fmt.Errorf("unknown choice %d for LCSServingNodeAddress", v.Choice)
	}
}

// MarshalDER encodes LCSServingNodeAddress to DER format.
func (v *LCSServingNodeAddress) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: LCSServingNodeAddress receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER()
	if err != nil {
		return nil, err
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding LCSServingNodeAddress as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes LCSServingNodeAddress from BER/DER format.
func (v *LCSServingNodeAddress) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: LCSServingNodeAddress destination is nil", ber.ErrInvalidValue)
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
	*v = LCSServingNodeAddress{}
	if len(data) == 0 {
		return fmt.Errorf("empty data for LCSServingNodeAddress CHOICE")
	}
	choiceData := data
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for LCSServingNodeAddress: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData, opts...)
	if tlvErr != nil {
		return fmt.Errorf("decoding LCSServingNodeAddress CHOICE: %w", tlvErr)
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "LCSServingNodeAddress", Cause: ber.ErrExtraData}
	}

	if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
		v.Choice = LCSServingNodeAddressChoiceMscNumber
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData, opts...)
		if tlvErr != nil {
			return fmt.Errorf("decoding msc-Number: %w", tlvErr)
		}
		decVal, octetErr := ber.DecodeImplicitOctetStringValue(peekTag.Constructed, rawVal, opts...)
		if octetErr != nil {
			return fmt.Errorf("decoding msc-Number: %w", octetErr)
		}
		tmp := ISDNAddressString3(decVal)
		v.MscNumber = &tmp
		if len(*v.MscNumber) < 1 || len(*v.MscNumber) > 9 {
			if constraintErr := ber.CheckDecodedLength(opts, "msc-Number", "SIZE (1..9)", len(*v.MscNumber)); constraintErr != nil {
				return constraintErr
			}
		}
		if len(*v.MscNumber) < 1 || len(*v.MscNumber) > 20 {
			if constraintErr := ber.CheckDecodedLength(opts, "msc-Number", "SIZE (1..20)", len(*v.MscNumber)); constraintErr != nil {
				return constraintErr
			}
		}
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
		v.Choice = LCSServingNodeAddressChoiceSgsnNumber
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData, opts...)
		if tlvErr != nil {
			return fmt.Errorf("decoding sgsn-Number: %w", tlvErr)
		}
		decVal, octetErr := ber.DecodeImplicitOctetStringValue(peekTag.Constructed, rawVal, opts...)
		if octetErr != nil {
			return fmt.Errorf("decoding sgsn-Number: %w", octetErr)
		}
		tmp := ISDNAddressString3(decVal)
		v.SgsnNumber = &tmp
		if len(*v.SgsnNumber) < 1 || len(*v.SgsnNumber) > 9 {
			if constraintErr := ber.CheckDecodedLength(opts, "sgsn-Number", "SIZE (1..9)", len(*v.SgsnNumber)); constraintErr != nil {
				return constraintErr
			}
		}
		if len(*v.SgsnNumber) < 1 || len(*v.SgsnNumber) > 20 {
			if constraintErr := ber.CheckDecodedLength(opts, "sgsn-Number", "SIZE (1..20)", len(*v.SgsnNumber)); constraintErr != nil {
				return constraintErr
			}
		}
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2 {
		v.Choice = LCSServingNodeAddressChoiceMmeNumber
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData, opts...)
		if tlvErr != nil {
			return fmt.Errorf("decoding mme-Number: %w", tlvErr)
		}
		decVal, octetErr := ber.DecodeImplicitOctetStringValue(peekTag.Constructed, rawVal, opts...)
		if octetErr != nil {
			return fmt.Errorf("decoding mme-Number: %w", octetErr)
		}
		tmp := CommonDataTypesDiameterIdentity(decVal)
		v.MmeNumber = &tmp
		if len(*v.MmeNumber) < 9 || len(*v.MmeNumber) > 255 {
			if constraintErr := ber.CheckDecodedLength(opts, "mme-Number", "SIZE (9..255)", len(*v.MmeNumber)); constraintErr != nil {
				return constraintErr
			}
		}
	} else {
		return fmt.Errorf("unknown tag %s for LCSServingNodeAddress CHOICE", peekTag)
	}
	return nil
}

// MarshalBER encodes LCSSubscriberLocationReportRes to BER format.
func (v *LCSSubscriberLocationReportRes) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: LCSSubscriberLocationReportRes receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *LCSSubscriberLocationReportRes) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalBER(ber.ChildEncodeOptions(opts, "extensionContainer")...)
		if err != nil {
			return nil, fmt.Errorf("encoding extensionContainer: %w", err)
		}
		children = append(children, enc_extensioncontainer...)
	}
	if v.NaESRK != nil {
		if len(*v.NaESRK) < 1 || len(*v.NaESRK) > 9 {
			if constraintErr := ber.CheckEncodedLength(opts, "na-ESRK", "SIZE (1..9)", len(*v.NaESRK)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		if len(*v.NaESRK) < 1 || len(*v.NaESRK) > 20 {
			if constraintErr := ber.CheckEncodedLength(opts, "na-ESRK", "SIZE (1..20)", len(*v.NaESRK)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_naesrk, encodeErr_enc_naesrk := ber.EncodeOctetString([]byte(*v.NaESRK))
		if encodeErr_enc_naesrk != nil {
			return nil, fmt.Errorf("encoding na-ESRK: %w", encodeErr_enc_naesrk)
		}
		retagged_enc_naesrk, tagErr_enc_naesrk := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_naesrk)
		if tagErr_enc_naesrk != nil {
			return nil, fmt.Errorf("encoding na-ESRK: %w", tagErr_enc_naesrk)
		}
		enc_naesrk = retagged_enc_naesrk
		children = append(children, enc_naesrk...)
	}
	if v.NaESRD != nil {
		if len(*v.NaESRD) < 1 || len(*v.NaESRD) > 9 {
			if constraintErr := ber.CheckEncodedLength(opts, "na-ESRD", "SIZE (1..9)", len(*v.NaESRD)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		if len(*v.NaESRD) < 1 || len(*v.NaESRD) > 20 {
			if constraintErr := ber.CheckEncodedLength(opts, "na-ESRD", "SIZE (1..20)", len(*v.NaESRD)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_naesrd, encodeErr_enc_naesrd := ber.EncodeOctetString([]byte(*v.NaESRD))
		if encodeErr_enc_naesrd != nil {
			return nil, fmt.Errorf("encoding na-ESRD: %w", encodeErr_enc_naesrd)
		}
		retagged_enc_naesrd, tagErr_enc_naesrd := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_naesrd)
		if tagErr_enc_naesrd != nil {
			return nil, fmt.Errorf("encoding na-ESRD: %w", tagErr_enc_naesrd)
		}
		enc_naesrd = retagged_enc_naesrd
		children = append(children, enc_naesrd...)
	}
	if v.HGmlcAddress != nil {
		if len(*v.HGmlcAddress) < 5 || len(*v.HGmlcAddress) > 17 {
			if constraintErr := ber.CheckEncodedLength(opts, "h-gmlc-Address", "SIZE (5..17)", len(*v.HGmlcAddress)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_hgmlcaddress, encodeErr_enc_hgmlcaddress := ber.EncodeOctetString([]byte(*v.HGmlcAddress))
		if encodeErr_enc_hgmlcaddress != nil {
			return nil, fmt.Errorf("encoding h-gmlc-Address: %w", encodeErr_enc_hgmlcaddress)
		}
		retagged_enc_hgmlcaddress, tagErr_enc_hgmlcaddress := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_hgmlcaddress)
		if tagErr_enc_hgmlcaddress != nil {
			return nil, fmt.Errorf("encoding h-gmlc-Address: %w", tagErr_enc_hgmlcaddress)
		}
		enc_hgmlcaddress = retagged_enc_hgmlcaddress
		children = append(children, enc_hgmlcaddress...)
	}
	if v.MoLrShortCircuitIndicator != nil {
		enc_molrshortcircuitindicator := ber.EncodeNull()
		retagged_enc_molrshortcircuitindicator, tagErr_enc_molrshortcircuitindicator := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, enc_molrshortcircuitindicator)
		if tagErr_enc_molrshortcircuitindicator != nil {
			return nil, fmt.Errorf("encoding mo-lrShortCircuitIndicator: %w", tagErr_enc_molrshortcircuitindicator)
		}
		enc_molrshortcircuitindicator = retagged_enc_molrshortcircuitindicator
		children = append(children, enc_molrshortcircuitindicator...)
	}
	if v.ReportingPLMNList != nil {
		enc_reportingplmnlist, err := v.ReportingPLMNList.MarshalBER(ber.ChildEncodeOptions(opts, "reportingPLMNList")...)
		if err != nil {
			return nil, fmt.Errorf("encoding reportingPLMNList: %w", err)
		}
		retagged_enc_reportingplmnlist, tagErr_enc_reportingplmnlist := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, enc_reportingplmnlist)
		if tagErr_enc_reportingplmnlist != nil {
			return nil, fmt.Errorf("encoding reportingPLMNList: %w", tagErr_enc_reportingplmnlist)
		}
		enc_reportingplmnlist = retagged_enc_reportingplmnlist
		children = append(children, enc_reportingplmnlist...)
	}
	if v.LcsReferenceNumber != nil {
		if len(*v.LcsReferenceNumber) < 1 || len(*v.LcsReferenceNumber) > 1 {
			if constraintErr := ber.CheckEncodedLength(opts, "lcs-ReferenceNumber", "SIZE (1)", len(*v.LcsReferenceNumber)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_lcsreferencenumber, encodeErr_enc_lcsreferencenumber := ber.EncodeOctetString([]byte(*v.LcsReferenceNumber))
		if encodeErr_enc_lcsreferencenumber != nil {
			return nil, fmt.Errorf("encoding lcs-ReferenceNumber: %w", encodeErr_enc_lcsreferencenumber)
		}
		retagged_enc_lcsreferencenumber, tagErr_enc_lcsreferencenumber := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 5, enc_lcsreferencenumber)
		if tagErr_enc_lcsreferencenumber != nil {
			return nil, fmt.Errorf("encoding lcs-ReferenceNumber: %w", tagErr_enc_lcsreferencenumber)
		}
		enc_lcsreferencenumber = retagged_enc_lcsreferencenumber
		children = append(children, enc_lcsreferencenumber...)
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

// MarshalDER encodes LCSSubscriberLocationReportRes to DER format.
func (v *LCSSubscriberLocationReportRes) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: LCSSubscriberLocationReportRes receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding extensionContainer: %w", err)
		}
		children = append(children, enc_extensioncontainer...)
	}
	if v.NaESRK != nil {
		if len(*v.NaESRK) < 1 || len(*v.NaESRK) > 9 {
			if constraintErr := ber.CheckEncodedLength(nil, "na-ESRK", "SIZE (1..9)", len(*v.NaESRK)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		if len(*v.NaESRK) < 1 || len(*v.NaESRK) > 20 {
			if constraintErr := ber.CheckEncodedLength(nil, "na-ESRK", "SIZE (1..20)", len(*v.NaESRK)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_naesrk, encodeErr_enc_naesrk := ber.EncodeOctetString([]byte(*v.NaESRK))
		if encodeErr_enc_naesrk != nil {
			return nil, fmt.Errorf("encoding na-ESRK: %w", encodeErr_enc_naesrk)
		}
		retagged_enc_naesrk, tagErr_enc_naesrk := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_naesrk)
		if tagErr_enc_naesrk != nil {
			return nil, fmt.Errorf("encoding na-ESRK: %w", tagErr_enc_naesrk)
		}
		enc_naesrk = retagged_enc_naesrk
		children = append(children, enc_naesrk...)
	}
	if v.NaESRD != nil {
		if len(*v.NaESRD) < 1 || len(*v.NaESRD) > 9 {
			if constraintErr := ber.CheckEncodedLength(nil, "na-ESRD", "SIZE (1..9)", len(*v.NaESRD)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		if len(*v.NaESRD) < 1 || len(*v.NaESRD) > 20 {
			if constraintErr := ber.CheckEncodedLength(nil, "na-ESRD", "SIZE (1..20)", len(*v.NaESRD)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_naesrd, encodeErr_enc_naesrd := ber.EncodeOctetString([]byte(*v.NaESRD))
		if encodeErr_enc_naesrd != nil {
			return nil, fmt.Errorf("encoding na-ESRD: %w", encodeErr_enc_naesrd)
		}
		retagged_enc_naesrd, tagErr_enc_naesrd := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_naesrd)
		if tagErr_enc_naesrd != nil {
			return nil, fmt.Errorf("encoding na-ESRD: %w", tagErr_enc_naesrd)
		}
		enc_naesrd = retagged_enc_naesrd
		children = append(children, enc_naesrd...)
	}
	if v.HGmlcAddress != nil {
		if len(*v.HGmlcAddress) < 5 || len(*v.HGmlcAddress) > 17 {
			if constraintErr := ber.CheckEncodedLength(nil, "h-gmlc-Address", "SIZE (5..17)", len(*v.HGmlcAddress)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_hgmlcaddress, encodeErr_enc_hgmlcaddress := ber.EncodeOctetString([]byte(*v.HGmlcAddress))
		if encodeErr_enc_hgmlcaddress != nil {
			return nil, fmt.Errorf("encoding h-gmlc-Address: %w", encodeErr_enc_hgmlcaddress)
		}
		retagged_enc_hgmlcaddress, tagErr_enc_hgmlcaddress := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_hgmlcaddress)
		if tagErr_enc_hgmlcaddress != nil {
			return nil, fmt.Errorf("encoding h-gmlc-Address: %w", tagErr_enc_hgmlcaddress)
		}
		enc_hgmlcaddress = retagged_enc_hgmlcaddress
		children = append(children, enc_hgmlcaddress...)
	}
	if v.MoLrShortCircuitIndicator != nil {
		enc_molrshortcircuitindicator := ber.EncodeNull()
		retagged_enc_molrshortcircuitindicator, tagErr_enc_molrshortcircuitindicator := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, enc_molrshortcircuitindicator)
		if tagErr_enc_molrshortcircuitindicator != nil {
			return nil, fmt.Errorf("encoding mo-lrShortCircuitIndicator: %w", tagErr_enc_molrshortcircuitindicator)
		}
		enc_molrshortcircuitindicator = retagged_enc_molrshortcircuitindicator
		children = append(children, enc_molrshortcircuitindicator...)
	}
	if v.ReportingPLMNList != nil {
		enc_reportingplmnlist, err := v.ReportingPLMNList.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding reportingPLMNList: %w", err)
		}
		retagged_enc_reportingplmnlist, tagErr_enc_reportingplmnlist := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, enc_reportingplmnlist)
		if tagErr_enc_reportingplmnlist != nil {
			return nil, fmt.Errorf("encoding reportingPLMNList: %w", tagErr_enc_reportingplmnlist)
		}
		enc_reportingplmnlist = retagged_enc_reportingplmnlist
		children = append(children, enc_reportingplmnlist...)
	}
	if v.LcsReferenceNumber != nil {
		if len(*v.LcsReferenceNumber) < 1 || len(*v.LcsReferenceNumber) > 1 {
			if constraintErr := ber.CheckEncodedLength(nil, "lcs-ReferenceNumber", "SIZE (1)", len(*v.LcsReferenceNumber)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_lcsreferencenumber, encodeErr_enc_lcsreferencenumber := ber.EncodeOctetString([]byte(*v.LcsReferenceNumber))
		if encodeErr_enc_lcsreferencenumber != nil {
			return nil, fmt.Errorf("encoding lcs-ReferenceNumber: %w", encodeErr_enc_lcsreferencenumber)
		}
		retagged_enc_lcsreferencenumber, tagErr_enc_lcsreferencenumber := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 5, enc_lcsreferencenumber)
		if tagErr_enc_lcsreferencenumber != nil {
			return nil, fmt.Errorf("encoding lcs-ReferenceNumber: %w", tagErr_enc_lcsreferencenumber)
		}
		enc_lcsreferencenumber = retagged_enc_lcsreferencenumber
		children = append(children, enc_lcsreferencenumber...)
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
		return nil, fmt.Errorf("encoding LCSSubscriberLocationReportRes as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes LCSSubscriberLocationReportRes from BER/DER format.
func (v *LCSSubscriberLocationReportRes) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: LCSSubscriberLocationReportRes destination is nil", ber.ErrInvalidValue)
	}
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = LCSSubscriberLocationReportRes{}
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
		return fmt.Errorf("decoding LCSSubscriberLocationReportRes SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "LCSSubscriberLocationReportRes", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode extensionContainer
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassUniversal && peekTag.Number == 16 {
				// Decode nested SEQUENCE (ExtensionContainer3)
				_, n_extensioncontainer, _, tlvErr_extensioncontainer := ber.DecodeTLV(content[offset:], opts...)
				if tlvErr_extensioncontainer != nil {
					return fmt.Errorf("decoding extensionContainer: %w", tlvErr_extensioncontainer)
				}
				var dec_extensioncontainer ExtensionContainer3
				if offset < 0 || offset >
					len(content) || n_extensioncontainer < 0 || n_extensioncontainer > len(
					content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				if unmErr := dec_extensioncontainer.UnmarshalBER(content[offset:offset+n_extensioncontainer], ber.ChildDecodeOptions(opts, "extensionContainer")...); unmErr != nil {
					return fmt.Errorf("decoding extensionContainer: %w", unmErr)
				}
				v.ExtensionContainer = &dec_extensioncontainer
				if offset < 0 || offset >
					len(content) || n_extensioncontainer < 0 || n_extensioncontainer > len(
					content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_extensioncontainer
			}
		}
	}
	// Decode na-ESRK
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
				decodedTag_naesrk, n_naesrk, rawVal_naesrk, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding na-ESRK: %w", err)
				}
				if decodedTag_naesrk.Class != tag.ClassContextSpecific || decodedTag_naesrk.Number != 0 {
					return fmt.Errorf("decoding na-ESRK: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_naesrk)
				}
				decVal_naesrk, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_naesrk.Constructed, rawVal_naesrk, opts...)
				if octetErr != nil {
					return fmt.Errorf("decoding na-ESRK: %w", octetErr)
				}
				tmp_naesrk := ISDNAddressString3(decVal_naesrk)
				v.NaESRK = &tmp_naesrk
				if offset < 0 || offset >
					len(content) || n_naesrk < 0 || n_naesrk > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_naesrk
				if len(*v.NaESRK) < 1 || len(*v.NaESRK) > 9 {
					if constraintErr := ber.CheckDecodedLength(opts, "na-ESRK", "SIZE (1..9)", len(*v.NaESRK)); constraintErr != nil {
						return constraintErr
					}
				}
				if len(*v.NaESRK) < 1 || len(*v.NaESRK) > 20 {
					if constraintErr := ber.CheckDecodedLength(opts, "na-ESRK", "SIZE (1..20)", len(*v.NaESRK)); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode na-ESRD
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
				decodedTag_naesrd, n_naesrd, rawVal_naesrd, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding na-ESRD: %w", err)
				}
				if decodedTag_naesrd.Class != tag.ClassContextSpecific || decodedTag_naesrd.Number != 1 {
					return fmt.Errorf("decoding na-ESRD: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_naesrd)
				}
				decVal_naesrd, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_naesrd.Constructed, rawVal_naesrd, opts...)
				if octetErr != nil {
					return fmt.Errorf("decoding na-ESRD: %w", octetErr)
				}
				tmp_naesrd := ISDNAddressString3(decVal_naesrd)
				v.NaESRD = &tmp_naesrd
				if offset < 0 || offset >
					len(content) || n_naesrd < 0 || n_naesrd > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_naesrd
				if len(*v.NaESRD) < 1 || len(*v.NaESRD) > 9 {
					if constraintErr := ber.CheckDecodedLength(opts, "na-ESRD", "SIZE (1..9)", len(*v.NaESRD)); constraintErr != nil {
						return constraintErr
					}
				}
				if len(*v.NaESRD) < 1 || len(*v.NaESRD) > 20 {
					if constraintErr := ber.CheckDecodedLength(opts, "na-ESRD", "SIZE (1..20)", len(*v.NaESRD)); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode h-gmlc-Address
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2 {
				decodedTag_hgmlcaddress, n_hgmlcaddress, rawVal_hgmlcaddress, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding h-gmlc-Address: %w", err)
				}
				if decodedTag_hgmlcaddress.Class != tag.ClassContextSpecific || decodedTag_hgmlcaddress.Number != 2 {
					return fmt.Errorf("decoding h-gmlc-Address: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_hgmlcaddress)
				}
				decVal_hgmlcaddress, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_hgmlcaddress.Constructed, rawVal_hgmlcaddress, opts...)
				if octetErr != nil {
					return fmt.Errorf("decoding h-gmlc-Address: %w", octetErr)
				}
				tmp_hgmlcaddress := CommonDataTypesGSNAddress(decVal_hgmlcaddress)
				v.HGmlcAddress = &tmp_hgmlcaddress
				if offset < 0 || offset >
					len(content) || n_hgmlcaddress < 0 || n_hgmlcaddress > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_hgmlcaddress
				if len(*v.HGmlcAddress) < 5 || len(*v.HGmlcAddress) > 17 {
					if constraintErr := ber.CheckDecodedLength(opts, "h-gmlc-Address", "SIZE (5..17)", len(*v.HGmlcAddress)); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode mo-lrShortCircuitIndicator
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3 {
				decodedTag_molrshortcircuitindicator, n_molrshortcircuitindicator, rawVal_molrshortcircuitindicator, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding mo-lrShortCircuitIndicator: %w", err)
				}
				if decodedTag_molrshortcircuitindicator.Class != tag.ClassContextSpecific || decodedTag_molrshortcircuitindicator.Number != 3 || decodedTag_molrshortcircuitindicator.Constructed != false {
					return fmt.Errorf("decoding mo-lrShortCircuitIndicator: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_molrshortcircuitindicator)
				}
				if len(rawVal_molrshortcircuitindicator) != 0 {
					return fmt.Errorf("decoding mo-lrShortCircuitIndicator: %w: NULL content length %d", ber.ErrInvalidValue, len(rawVal_molrshortcircuitindicator))
				}
				v.MoLrShortCircuitIndicator = &struct{}{}
				if offset < 0 || offset >
					len(content) || n_molrshortcircuitindicator < 0 || n_molrshortcircuitindicator >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_molrshortcircuitindicator
			}
		}
	}
	// Decode reportingPLMNList
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4 {
				decodedTag_reportingplmnlist, n_reportingplmnlist, rawVal_reportingplmnlist, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding reportingPLMNList: %w", err)
				}
				if decodedTag_reportingplmnlist.Class != tag.ClassContextSpecific || decodedTag_reportingplmnlist.Number != 4 || decodedTag_reportingplmnlist.Constructed != true {
					return fmt.Errorf("decoding reportingPLMNList: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_reportingplmnlist)
				}
				reconstructed_reportingplmnlist, reconstructionErr_reportingplmnlist := ber.EncodeSequence(rawVal_reportingplmnlist)
				if reconstructionErr_reportingplmnlist != nil {
					return fmt.Errorf("decoding reportingPLMNList: %w", reconstructionErr_reportingplmnlist)
				}
				var dec_reportingplmnlist LCSReportingPLMNList
				if unmErr := dec_reportingplmnlist.UnmarshalBER(reconstructed_reportingplmnlist, ber.ChildDecodeOptions(opts, "reportingPLMNList")...); unmErr != nil {
					return fmt.Errorf("decoding reportingPLMNList: %w", unmErr)
				}
				v.ReportingPLMNList = &dec_reportingplmnlist
				if offset < 0 || offset >
					len(content) || n_reportingplmnlist < 0 || n_reportingplmnlist > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_reportingplmnlist
			}
		}
	}
	// Decode lcs-ReferenceNumber
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 5 {
				decodedTag_lcsreferencenumber, n_lcsreferencenumber, rawVal_lcsreferencenumber, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding lcs-ReferenceNumber: %w", err)
				}
				if decodedTag_lcsreferencenumber.Class != tag.ClassContextSpecific || decodedTag_lcsreferencenumber.Number != 5 {
					return fmt.Errorf("decoding lcs-ReferenceNumber: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_lcsreferencenumber)
				}
				decVal_lcsreferencenumber, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_lcsreferencenumber.Constructed, rawVal_lcsreferencenumber, opts...)
				if octetErr != nil {
					return fmt.Errorf("decoding lcs-ReferenceNumber: %w", octetErr)
				}
				tmp_lcsreferencenumber := LCSLCSReferenceNumber(decVal_lcsreferencenumber)
				v.LcsReferenceNumber = &tmp_lcsreferencenumber
				if offset < 0 || offset >
					len(content) || n_lcsreferencenumber < 0 || n_lcsreferencenumber > len(
					content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_lcsreferencenumber
				if len(*v.LcsReferenceNumber) < 1 || len(*v.LcsReferenceNumber) > 1 {
					if constraintErr := ber.CheckDecodedLength(opts, "lcs-ReferenceNumber", "SIZE (1)", len(*v.LcsReferenceNumber)); constraintErr != nil {
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
			return &ber.DecodeError{Offset: offset, TypeName: "LCSSubscriberLocationReportRes", Cause: extErr_}
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
