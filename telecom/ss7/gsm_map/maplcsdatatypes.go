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

	// MaxNameStringLength is the integer constant for MaxNameStringLength.
	MaxNameStringLength int64 = 63

	// MaxRequestorIDStringLength is the integer constant for MaxRequestorIDStringLength.
	MaxRequestorIDStringLength int64 = 63

	// MaxLCSCodewordStringLength is the integer constant for MaxLCSCodewordStringLength.
	MaxLCSCodewordStringLength int64 = 20

	// MaxNumOfAreas is the integer constant for MaxNumOfAreas.
	MaxNumOfAreas int64 = 10

	// MaxReportingAmount is the integer constant for MaxReportingAmount.
	MaxReportingAmount int64 = 8.639999e+06

	// MaxReportingInterval is the integer constant for MaxReportingInterval.
	MaxReportingInterval int64 = 8.639999e+06

	// MaxReportingAmountMilliseconds is the integer constant for MaxReportingAmountMilliseconds.
	MaxReportingAmountMilliseconds int64 = 8.639999e+09

	// MaxReportingIntervalMilliseconds is the integer constant for MaxReportingIntervalMilliseconds.
	MaxReportingIntervalMilliseconds int64 = 999

	// MaxNumOfReportingPLMN is the integer constant for MaxNumOfReportingPLMN.
	MaxNumOfReportingPLMN int64 = 20

	// MaxExtGeographicalInformation is the integer constant for MaxExtGeographicalInformation.
	MaxExtGeographicalInformation int64 = 20

	// MaxPositioningDataInformation is the integer constant for MaxPositioningDataInformation.
	MaxPositioningDataInformation int64 = 10

	// MaxUtranPositioningDataInfo is the integer constant for MaxUtranPositioningDataInfo.
	MaxUtranPositioningDataInfo int64 = 11

	// MaxGeranGANSSpositioningData is the integer constant for MaxGeranGANSSpositioningData.
	MaxGeranGANSSpositioningData int64 = 10

	// MaxUtranGANSSpositioningData is the integer constant for MaxUtranGANSSpositioningData.
	MaxUtranGANSSpositioningData int64 = 9

	// MaxUtranAdditionalPositioningData is the integer constant for MaxUtranAdditionalPositioningData.
	MaxUtranAdditionalPositioningData int64 = 8

	// MaxAddGeographicalInformation is the integer constant for MaxAddGeographicalInformation.
	MaxAddGeographicalInformation int64 = 91
)

// RoutingInfoForLCSArg represents the ASN.1 type RoutingInfoForLCS-Arg (SEQUENCE).
type RoutingInfoForLCSArg struct {
	MlcNumber          ISDNAddressString   `asn1:"tag:0,context,implicit"`
	TargetMS           SubscriberIdentity  `asn1:"tag:1,context,explicit"`
	ExtensionContainer *ExtensionContainer `asn1:"tag:2,context,implicit,optional" json:"ExtensionContainer,omitempty"`
	ExtCount_          int64               `asn1:"-" json:"-"`
	ExtPresent_        []bool              `asn1:"-" json:"-"`
	ExtData_           [][]byte            `asn1:"-" json:"-"`
}

// RoutingInfoForLCSRes represents the ASN.1 type RoutingInfoForLCS-Res (SEQUENCE).
type RoutingInfoForLCSRes struct {
	TargetMS               SubscriberIdentity  `asn1:"tag:0,context,explicit"`
	LcsLocationInfo        LCSLocationInfo     `asn1:"tag:1,context,implicit"`
	ExtensionContainer     *ExtensionContainer `asn1:"tag:2,context,implicit,optional" json:"ExtensionContainer,omitempty"`
	VGmlcAddress           *GSNAddress         `asn1:"tag:3,context,implicit,optional" json:"VGmlcAddress,omitempty"`
	HGmlcAddress           *GSNAddress         `asn1:"tag:4,context,implicit,optional" json:"HGmlcAddress,omitempty"`
	PprAddress             *GSNAddress         `asn1:"tag:5,context,implicit,optional" json:"PprAddress,omitempty"`
	AdditionalVGmlcAddress *GSNAddress         `asn1:"tag:6,context,implicit,optional" json:"AdditionalVGmlcAddress,omitempty"`
	ExtCount_              int64               `asn1:"-" json:"-"`
	ExtPresent_            []bool              `asn1:"-" json:"-"`
	ExtData_               [][]byte            `asn1:"-" json:"-"`
}

// LCSLocationInfo represents the ASN.1 type LCSLocationInfo (SEQUENCE).
type LCSLocationInfo struct {
	NetworkNodeNumber           ISDNAddressString           `asn1:""`
	Lmsi                        *LMSI                       `asn1:"tag:0,context,implicit,optional" json:"Lmsi,omitempty"`
	ExtensionContainer          *ExtensionContainer         `asn1:"tag:1,context,implicit,optional" json:"ExtensionContainer,omitempty"`
	GprsNodeIndicator           *struct{}                   `asn1:"tag:2,context,implicit,optional" json:"GprsNodeIndicator,omitempty"`
	AdditionalNumber            *AdditionalNumber           `asn1:"tag:3,context,explicit,optional" json:"AdditionalNumber,omitempty"`
	SupportedLCSCapabilitySets  *SupportedLCSCapabilitySets `asn1:"tag:4,context,implicit,optional" json:"SupportedLCSCapabilitySets,omitempty"`
	AdditionalLCSCapabilitySets *SupportedLCSCapabilitySets `asn1:"tag:5,context,implicit,optional" json:"AdditionalLCSCapabilitySets,omitempty"`
	MmeName                     *DiameterIdentity           `asn1:"tag:6,context,implicit,optional" json:"MmeName,omitempty"`
	AaaServerName               *DiameterIdentity           `asn1:"tag:8,context,implicit,optional" json:"AaaServerName,omitempty"`
	SgsnName                    *DiameterIdentity           `asn1:"tag:9,context,implicit,optional" json:"SgsnName,omitempty"`
	SgsnRealm                   *DiameterIdentity           `asn1:"tag:10,context,implicit,optional" json:"SgsnRealm,omitempty"`
	ExtCount_                   int64                       `asn1:"-" json:"-"`
	ExtPresent_                 []bool                      `asn1:"-" json:"-"`
	ExtData_                    [][]byte                    `asn1:"-" json:"-"`
}

// ProvideSubscriberLocationArg represents the ASN.1 type ProvideSubscriberLocation-Arg (SEQUENCE).
type ProvideSubscriberLocationArg struct {
	LocationType              LocationType        `asn1:""`
	MlcNumber                 ISDNAddressString   `asn1:""`
	LcsClientID               *LCSClientID        `asn1:"tag:0,context,implicit,optional" json:"LcsClientID,omitempty"`
	PrivacyOverride           *struct{}           `asn1:"tag:1,context,implicit,optional" json:"PrivacyOverride,omitempty"`
	Imsi                      *IMSI               `asn1:"tag:2,context,implicit,optional" json:"Imsi,omitempty"`
	Msisdn                    *ISDNAddressString  `asn1:"tag:3,context,implicit,optional" json:"Msisdn,omitempty"`
	Lmsi                      *LMSI               `asn1:"tag:4,context,implicit,optional" json:"Lmsi,omitempty"`
	Imei                      *IMEI               `asn1:"tag:5,context,implicit,optional" json:"Imei,omitempty"`
	LcsPriority               *LCSPriority        `asn1:"tag:6,context,implicit,optional" json:"LcsPriority,omitempty"`
	LcsQoS                    *LCSQoS             `asn1:"tag:7,context,implicit,optional" json:"LcsQoS,omitempty"`
	ExtensionContainer        *ExtensionContainer `asn1:"tag:8,context,implicit,optional" json:"ExtensionContainer,omitempty"`
	SupportedGADShapes        *SupportedGADShapes `asn1:"tag:9,context,implicit,optional" json:"SupportedGADShapes,omitempty"`
	LcsReferenceNumber        *LCSReferenceNumber `asn1:"tag:10,context,implicit,optional" json:"LcsReferenceNumber,omitempty"`
	LcsServiceTypeID          *LCSServiceTypeID   `asn1:"tag:11,context,implicit,optional" json:"LcsServiceTypeID,omitempty"`
	LcsCodeword               *LCSCodeword        `asn1:"tag:12,context,implicit,optional" json:"LcsCodeword,omitempty"`
	LcsPrivacyCheck           *LCSPrivacyCheck    `asn1:"tag:13,context,implicit,optional" json:"LcsPrivacyCheck,omitempty"`
	AreaEventInfo             *AreaEventInfo      `asn1:"tag:14,context,implicit,optional" json:"AreaEventInfo,omitempty"`
	HGmlcAddress              *GSNAddress         `asn1:"tag:15,context,implicit,optional" json:"HGmlcAddress,omitempty"`
	MoLrShortCircuitIndicator *struct{}           `asn1:"tag:16,context,implicit,optional" json:"MoLrShortCircuitIndicator,omitempty"`
	PeriodicLDRInfo           *PeriodicLDRInfo    `asn1:"tag:17,context,implicit,optional" json:"PeriodicLDRInfo,omitempty"`
	ReportingPLMNList         *ReportingPLMNList  `asn1:"tag:18,context,implicit,optional" json:"ReportingPLMNList,omitempty"`
	ExtCount_                 int64               `asn1:"-" json:"-"`
	ExtPresent_               []bool              `asn1:"-" json:"-"`
	ExtData_                  [][]byte            `asn1:"-" json:"-"`
}

// LocationType represents the ASN.1 type LocationType (SEQUENCE).
type LocationType struct {
	LocationEstimateType      LocationEstimateType       `asn1:"tag:0,context,implicit"`
	DeferredLocationEventType *DeferredLocationEventType `asn1:"tag:1,context,implicit,optional" json:"DeferredLocationEventType,omitempty"`
	ExtCount_                 int64                      `asn1:"-" json:"-"`
	ExtPresent_               []bool                     `asn1:"-" json:"-"`
	ExtData_                  [][]byte                   `asn1:"-" json:"-"`
}

// LocationEstimateType represents the ASN.1 ENUMERATED type LocationEstimateType.
type LocationEstimateType int64

const (
	LocationEstimateTypeCurrentLocation              LocationEstimateType = 0
	LocationEstimateTypeCurrentOrLastKnownLocation   LocationEstimateType = 1
	LocationEstimateTypeInitialLocation              LocationEstimateType = 2
	LocationEstimateTypeActivateDeferredLocation     LocationEstimateType = 3
	LocationEstimateTypeCancelDeferredLocation       LocationEstimateType = 4
	LocationEstimateTypeNotificationVerificationOnly LocationEstimateType = 5
)

func (v LocationEstimateType) String() string {
	switch v {
	case LocationEstimateTypeCurrentLocation:
		return "currentLocation"
	case LocationEstimateTypeCurrentOrLastKnownLocation:
		return "currentOrLastKnownLocation"
	case LocationEstimateTypeInitialLocation:
		return "initialLocation"
	case LocationEstimateTypeActivateDeferredLocation:
		return "activateDeferredLocation"
	case LocationEstimateTypeCancelDeferredLocation:
		return "cancelDeferredLocation"
	case LocationEstimateTypeNotificationVerificationOnly:
		return "notificationVerificationOnly"
	default:
		return "unknown"
	}
}

// DeferredLocationEventType represents the ASN.1 type DeferredLocationEventType (BIT_STRING).
type DeferredLocationEventType = runtime.BitString

// LCSClientID represents the ASN.1 type LCS-ClientID (SEQUENCE).
type LCSClientID struct {
	LcsClientType       LCSClientType        `asn1:"tag:0,context,implicit"`
	LcsClientExternalID *LCSClientExternalID `asn1:"tag:1,context,implicit,optional" json:"LcsClientExternalID,omitempty"`
	LcsClientDialedByMS *AddressString       `asn1:"tag:2,context,implicit,optional" json:"LcsClientDialedByMS,omitempty"`
	LcsClientInternalID *LCSClientInternalID `asn1:"tag:3,context,implicit,optional" json:"LcsClientInternalID,omitempty"`
	LcsClientName       *LCSClientName       `asn1:"tag:4,context,implicit,optional" json:"LcsClientName,omitempty"`
	LcsAPN              *APN                 `asn1:"tag:5,context,implicit,optional" json:"LcsAPN,omitempty"`
	LcsRequestorID      *LCSRequestorID      `asn1:"tag:6,context,implicit,optional" json:"LcsRequestorID,omitempty"`
	ExtCount_           int64                `asn1:"-" json:"-"`
	ExtPresent_         []bool               `asn1:"-" json:"-"`
	ExtData_            [][]byte             `asn1:"-" json:"-"`
}

// LCSClientType represents the ASN.1 ENUMERATED type LCSClientType.
type LCSClientType int64

const (
	LCSClientTypeEmergencyServices       LCSClientType = 0
	LCSClientTypeValueAddedServices      LCSClientType = 1
	LCSClientTypePlmnOperatorServices    LCSClientType = 2
	LCSClientTypeLawfulInterceptServices LCSClientType = 3
)

func (v LCSClientType) String() string {
	switch v {
	case LCSClientTypeEmergencyServices:
		return "emergencyServices"
	case LCSClientTypeValueAddedServices:
		return "valueAddedServices"
	case LCSClientTypePlmnOperatorServices:
		return "plmnOperatorServices"
	case LCSClientTypeLawfulInterceptServices:
		return "lawfulInterceptServices"
	default:
		return "unknown"
	}
}

// LCSClientName represents the ASN.1 type LCSClientName (SEQUENCE).
type LCSClientName struct {
	DataCodingScheme   USSDDataCodingScheme `asn1:"tag:0,context,implicit"`
	NameString         NameString           `asn1:"tag:2,context,implicit"`
	LcsFormatIndicator *LCSFormatIndicator  `asn1:"tag:3,context,implicit,optional" json:"LcsFormatIndicator,omitempty"`
	ExtCount_          int64                `asn1:"-" json:"-"`
	ExtPresent_        []bool               `asn1:"-" json:"-"`
	ExtData_           [][]byte             `asn1:"-" json:"-"`
}

// NameString represents the ASN.1 type NameString (OCTET_STRING).
type NameString = USSDString

// LCSRequestorID represents the ASN.1 type LCSRequestorID (SEQUENCE).
type LCSRequestorID struct {
	DataCodingScheme   USSDDataCodingScheme `asn1:"tag:0,context,implicit"`
	RequestorIDString  RequestorIDString    `asn1:"tag:1,context,implicit"`
	LcsFormatIndicator *LCSFormatIndicator  `asn1:"tag:2,context,implicit,optional" json:"LcsFormatIndicator,omitempty"`
	ExtCount_          int64                `asn1:"-" json:"-"`
	ExtPresent_        []bool               `asn1:"-" json:"-"`
	ExtData_           [][]byte             `asn1:"-" json:"-"`
}

// RequestorIDString represents the ASN.1 type RequestorIDString (OCTET_STRING).
type RequestorIDString = USSDString

// LCSFormatIndicator represents the ASN.1 ENUMERATED type LCS-FormatIndicator.
type LCSFormatIndicator int64

const (
	LCSFormatIndicatorLogicalName  LCSFormatIndicator = 0
	LCSFormatIndicatorEMailAddress LCSFormatIndicator = 1
	LCSFormatIndicatorMsisdn       LCSFormatIndicator = 2
	LCSFormatIndicatorUrl          LCSFormatIndicator = 3
	LCSFormatIndicatorSipUrl       LCSFormatIndicator = 4
)

func (v LCSFormatIndicator) String() string {
	switch v {
	case LCSFormatIndicatorLogicalName:
		return "logicalName"
	case LCSFormatIndicatorEMailAddress:
		return "e-mailAddress"
	case LCSFormatIndicatorMsisdn:
		return "msisdn"
	case LCSFormatIndicatorUrl:
		return "url"
	case LCSFormatIndicatorSipUrl:
		return "sipUrl"
	default:
		return "unknown"
	}
}

// LCSPriority represents the ASN.1 type LCS-Priority (OCTET_STRING).
type LCSPriority = []byte

// LCSQoS represents the ASN.1 type LCS-QoS (SEQUENCE).
type LCSQoS struct {
	HorizontalAccuracy        *HorizontalAccuracy `asn1:"tag:0,context,implicit,optional" json:"HorizontalAccuracy,omitempty"`
	VerticalCoordinateRequest *struct{}           `asn1:"tag:1,context,implicit,optional" json:"VerticalCoordinateRequest,omitempty"`
	VerticalAccuracy          *VerticalAccuracy   `asn1:"tag:2,context,implicit,optional" json:"VerticalAccuracy,omitempty"`
	ResponseTime              *ResponseTime       `asn1:"tag:3,context,implicit,optional" json:"ResponseTime,omitempty"`
	ExtensionContainer        *ExtensionContainer `asn1:"tag:4,context,implicit,optional" json:"ExtensionContainer,omitempty"`
	VelocityRequest           *struct{}           `asn1:"tag:5,context,implicit,optional" json:"VelocityRequest,omitempty"`
	LcsQosClass               *LCSQoSClass        `asn1:"tag:6,context,implicit,optional" json:"LcsQosClass,omitempty"`
	ExtCount_                 int64               `asn1:"-" json:"-"`
	ExtPresent_               []bool              `asn1:"-" json:"-"`
	ExtData_                  [][]byte            `asn1:"-" json:"-"`
}

// HorizontalAccuracy represents the ASN.1 type Horizontal-Accuracy (OCTET_STRING).
type HorizontalAccuracy = []byte

// VerticalAccuracy represents the ASN.1 type Vertical-Accuracy (OCTET_STRING).
type VerticalAccuracy = []byte

// ResponseTime represents the ASN.1 type ResponseTime (SEQUENCE).
type ResponseTime struct {
	ResponseTimeCategory ResponseTimeCategory `asn1:""`
	ExtCount_            int64                `asn1:"-" json:"-"`
	ExtPresent_          []bool               `asn1:"-" json:"-"`
	ExtData_             [][]byte             `asn1:"-" json:"-"`
}

// ResponseTimeCategory represents the ASN.1 ENUMERATED type ResponseTimeCategory.
type ResponseTimeCategory int64

const (
	ResponseTimeCategoryLowdelay      ResponseTimeCategory = 0
	ResponseTimeCategoryDelaytolerant ResponseTimeCategory = 1
)

func (v ResponseTimeCategory) String() string {
	switch v {
	case ResponseTimeCategoryLowdelay:
		return "lowdelay"
	case ResponseTimeCategoryDelaytolerant:
		return "delaytolerant"
	default:
		return "unknown"
	}
}

// LCSQoSClass represents the ASN.1 ENUMERATED type LCS-QoS-Class.
type LCSQoSClass int64

const (
	LCSQoSClassBestEffort LCSQoSClass = 0
	LCSQoSClassAssured    LCSQoSClass = 1
)

func (v LCSQoSClass) String() string {
	switch v {
	case LCSQoSClassBestEffort:
		return "bestEffort"
	case LCSQoSClassAssured:
		return "assured"
	default:
		return "unknown"
	}
}

// SupportedGADShapes represents the ASN.1 type SupportedGADShapes (BIT_STRING).
type SupportedGADShapes = runtime.BitString

// LCSReferenceNumber represents the ASN.1 type LCS-ReferenceNumber (OCTET_STRING).
type LCSReferenceNumber = []byte

// LCSCodeword represents the ASN.1 type LCSCodeword (SEQUENCE).
type LCSCodeword struct {
	DataCodingScheme  USSDDataCodingScheme `asn1:"tag:0,context,implicit"`
	LcsCodewordString LCSCodewordString    `asn1:"tag:1,context,implicit"`
	ExtCount_         int64                `asn1:"-" json:"-"`
	ExtPresent_       []bool               `asn1:"-" json:"-"`
	ExtData_          [][]byte             `asn1:"-" json:"-"`
}

// LCSCodewordString represents the ASN.1 type LCSCodewordString (OCTET_STRING).
type LCSCodewordString = USSDString

// LCSPrivacyCheck represents the ASN.1 type LCS-PrivacyCheck (SEQUENCE).
type LCSPrivacyCheck struct {
	CallSessionUnrelated PrivacyCheckRelatedAction  `asn1:"tag:0,context,implicit"`
	CallSessionRelated   *PrivacyCheckRelatedAction `asn1:"tag:1,context,implicit,optional" json:"CallSessionRelated,omitempty"`
	ExtCount_            int64                      `asn1:"-" json:"-"`
	ExtPresent_          []bool                     `asn1:"-" json:"-"`
	ExtData_             [][]byte                   `asn1:"-" json:"-"`
}

// PrivacyCheckRelatedAction represents the ASN.1 ENUMERATED type PrivacyCheckRelatedAction.
type PrivacyCheckRelatedAction int64

const (
	PrivacyCheckRelatedActionAllowedWithoutNotification PrivacyCheckRelatedAction = 0
	PrivacyCheckRelatedActionAllowedWithNotification    PrivacyCheckRelatedAction = 1
	PrivacyCheckRelatedActionAllowedIfNoResponse        PrivacyCheckRelatedAction = 2
	PrivacyCheckRelatedActionRestrictedIfNoResponse     PrivacyCheckRelatedAction = 3
	PrivacyCheckRelatedActionNotAllowed                 PrivacyCheckRelatedAction = 4
)

func (v PrivacyCheckRelatedAction) String() string {
	switch v {
	case PrivacyCheckRelatedActionAllowedWithoutNotification:
		return "allowedWithoutNotification"
	case PrivacyCheckRelatedActionAllowedWithNotification:
		return "allowedWithNotification"
	case PrivacyCheckRelatedActionAllowedIfNoResponse:
		return "allowedIfNoResponse"
	case PrivacyCheckRelatedActionRestrictedIfNoResponse:
		return "restrictedIfNoResponse"
	case PrivacyCheckRelatedActionNotAllowed:
		return "notAllowed"
	default:
		return "unknown"
	}
}

// AreaEventInfo represents the ASN.1 type AreaEventInfo (SEQUENCE).
type AreaEventInfo struct {
	AreaDefinition AreaDefinition  `asn1:"tag:0,context,implicit"`
	OccurrenceInfo *OccurrenceInfo `asn1:"tag:1,context,implicit,optional" json:"OccurrenceInfo,omitempty"`
	IntervalTime   *IntervalTime   `asn1:"tag:2,context,implicit,optional" json:"IntervalTime,omitempty"`
	ExtCount_      int64           `asn1:"-" json:"-"`
	ExtPresent_    []bool          `asn1:"-" json:"-"`
	ExtData_       [][]byte        `asn1:"-" json:"-"`
}

// AreaDefinition represents the ASN.1 type AreaDefinition (SEQUENCE).
type AreaDefinition struct {
	AreaList       AreaList `asn1:"tag:0,context,implicit"`
	AreaListIndef_ bool     `asn1:"-" json:"-"`
	ExtCount_      int64    `asn1:"-" json:"-"`
	ExtPresent_    []bool   `asn1:"-" json:"-"`
	ExtData_       [][]byte `asn1:"-" json:"-"`
}

// AreaList represents the ASN.1 type AreaList (SEQUENCE_OF).
type AreaList = []Area

// Area represents the ASN.1 type Area (SEQUENCE).
type Area struct {
	AreaType           AreaType           `asn1:"tag:0,context,implicit"`
	AreaIdentification AreaIdentification `asn1:"tag:1,context,implicit"`
	ExtCount_          int64              `asn1:"-" json:"-"`
	ExtPresent_        []bool             `asn1:"-" json:"-"`
	ExtData_           [][]byte           `asn1:"-" json:"-"`
}

// AreaType represents the ASN.1 ENUMERATED type AreaType.
type AreaType int64

const (
	AreaTypeCountryCode    AreaType = 0
	AreaTypePlmnId         AreaType = 1
	AreaTypeLocationAreaId AreaType = 2
	AreaTypeRoutingAreaId  AreaType = 3
	AreaTypeCellGlobalId   AreaType = 4
	AreaTypeUtranCellId    AreaType = 5
)

func (v AreaType) String() string {
	switch v {
	case AreaTypeCountryCode:
		return "countryCode"
	case AreaTypePlmnId:
		return "plmnId"
	case AreaTypeLocationAreaId:
		return "locationAreaId"
	case AreaTypeRoutingAreaId:
		return "routingAreaId"
	case AreaTypeCellGlobalId:
		return "cellGlobalId"
	case AreaTypeUtranCellId:
		return "utranCellId"
	default:
		return "unknown"
	}
}

// AreaIdentification represents the ASN.1 type AreaIdentification (OCTET_STRING).
type AreaIdentification = []byte

// OccurrenceInfo represents the ASN.1 ENUMERATED type OccurrenceInfo.
type OccurrenceInfo int64

const (
	OccurrenceInfoOneTimeEvent      OccurrenceInfo = 0
	OccurrenceInfoMultipleTimeEvent OccurrenceInfo = 1
)

func (v OccurrenceInfo) String() string {
	switch v {
	case OccurrenceInfoOneTimeEvent:
		return "oneTimeEvent"
	case OccurrenceInfoMultipleTimeEvent:
		return "multipleTimeEvent"
	default:
		return "unknown"
	}
}

// IntervalTime represents the ASN.1 type IntervalTime (INTEGER).
type IntervalTime = int64

// PeriodicLDRInfo represents the ASN.1 type PeriodicLDRInfo (SEQUENCE).
type PeriodicLDRInfo struct {
	ReportingAmount             ReportingAmount              `asn1:""`
	ReportingInterval           ReportingInterval            `asn1:""`
	ReportingOptionMilliseconds *ReportingOptionMilliseconds `asn1:"tag:0,context,implicit,optional" json:"ReportingOptionMilliseconds,omitempty"`
	ExtCount_                   int64                        `asn1:"-" json:"-"`
	ExtPresent_                 []bool                       `asn1:"-" json:"-"`
	ExtData_                    [][]byte                     `asn1:"-" json:"-"`
}

// ReportingAmount represents the ASN.1 type ReportingAmount (INTEGER).
type ReportingAmount = int64

// ReportingInterval represents the ASN.1 type ReportingInterval (INTEGER).
type ReportingInterval = int64

// ReportingOptionMilliseconds represents the ASN.1 type ReportingOptionMilliseconds (SEQUENCE).
type ReportingOptionMilliseconds struct {
	ReportingAmountMilliseconds   ReportingAmountMilliseconds   `asn1:""`
	ReportingIntervalMilliseconds ReportingIntervalMilliseconds `asn1:""`
	ExtCount_                     int64                         `asn1:"-" json:"-"`
	ExtPresent_                   []bool                        `asn1:"-" json:"-"`
	ExtData_                      [][]byte                      `asn1:"-" json:"-"`
}

// ReportingAmountMilliseconds represents the ASN.1 type ReportingAmountMilliseconds (INTEGER).
type ReportingAmountMilliseconds = int64

// ReportingIntervalMilliseconds represents the ASN.1 type ReportingIntervalMilliseconds (INTEGER).
type ReportingIntervalMilliseconds = int64

// ReportingPLMNList represents the ASN.1 type ReportingPLMNList (SEQUENCE).
type ReportingPLMNList struct {
	PlmnListPrioritized *struct{} `asn1:"tag:0,context,implicit,optional" json:"PlmnListPrioritized,omitempty"`
	PlmnList            PLMNList  `asn1:"tag:1,context,implicit"`
	PlmnListIndef_      bool      `asn1:"-" json:"-"`
	ExtCount_           int64     `asn1:"-" json:"-"`
	ExtPresent_         []bool    `asn1:"-" json:"-"`
	ExtData_            [][]byte  `asn1:"-" json:"-"`
}

// PLMNList represents the ASN.1 type PLMNList (SEQUENCE_OF).
type PLMNList = []ReportingPLMN

// ReportingPLMN represents the ASN.1 type ReportingPLMN (SEQUENCE).
type ReportingPLMN struct {
	PlmnId                     PLMNId         `asn1:"tag:0,context,implicit"`
	RanTechnology              *RANTechnology `asn1:"tag:1,context,implicit,optional" json:"RanTechnology,omitempty"`
	RanPeriodicLocationSupport *struct{}      `asn1:"tag:2,context,implicit,optional" json:"RanPeriodicLocationSupport,omitempty"`
	ExtCount_                  int64          `asn1:"-" json:"-"`
	ExtPresent_                []bool         `asn1:"-" json:"-"`
	ExtData_                   [][]byte       `asn1:"-" json:"-"`
}

// RANTechnology represents the ASN.1 ENUMERATED type RAN-Technology.
type RANTechnology int64

const (
	RANTechnologyGsm  RANTechnology = 0
	RANTechnologyUmts RANTechnology = 1
)

func (v RANTechnology) String() string {
	switch v {
	case RANTechnologyGsm:
		return "gsm"
	case RANTechnologyUmts:
		return "umts"
	default:
		return "unknown"
	}
}

// ProvideSubscriberLocationRes represents the ASN.1 type ProvideSubscriberLocation-Res (SEQUENCE).
type ProvideSubscriberLocationRes struct {
	LocationEstimate               ExtGeographicalInformation        `asn1:""`
	AgeOfLocationEstimate          *AgeOfLocationInformation         `asn1:"tag:0,context,implicit,optional" json:"AgeOfLocationEstimate,omitempty"`
	ExtensionContainer             *ExtensionContainer               `asn1:"tag:1,context,implicit,optional" json:"ExtensionContainer,omitempty"`
	AddLocationEstimate            *AddGeographicalInformation       `asn1:"tag:2,context,implicit,optional" json:"AddLocationEstimate,omitempty"`
	DeferredmtLrResponseIndicator  *struct{}                         `asn1:"tag:3,context,implicit,optional" json:"DeferredmtLrResponseIndicator,omitempty"`
	GeranPositioningData           *PositioningDataInformation       `asn1:"tag:4,context,implicit,optional" json:"GeranPositioningData,omitempty"`
	UtranPositioningData           *UtranPositioningDataInfo         `asn1:"tag:5,context,implicit,optional" json:"UtranPositioningData,omitempty"`
	CellIdOrSai                    *CellGlobalIdOrServiceAreaIdOrLAI `asn1:"tag:6,context,explicit,optional" json:"CellIdOrSai,omitempty"`
	SaiPresent                     *struct{}                         `asn1:"tag:7,context,implicit,optional" json:"SaiPresent,omitempty"`
	AccuracyFulfilmentIndicator    *AccuracyFulfilmentIndicator      `asn1:"tag:8,context,implicit,optional" json:"AccuracyFulfilmentIndicator,omitempty"`
	VelocityEstimate               *VelocityEstimate                 `asn1:"tag:9,context,implicit,optional" json:"VelocityEstimate,omitempty"`
	MoLrShortCircuitIndicator      *struct{}                         `asn1:"tag:10,context,implicit,optional" json:"MoLrShortCircuitIndicator,omitempty"`
	GeranGANSSpositioningData      *GeranGANSSpositioningData        `asn1:"tag:11,context,implicit,optional" json:"GeranGANSSpositioningData,omitempty"`
	UtranGANSSpositioningData      *UtranGANSSpositioningData        `asn1:"tag:12,context,implicit,optional" json:"UtranGANSSpositioningData,omitempty"`
	TargetServingNodeForHandover   *ServingNodeAddress               `asn1:"tag:13,context,explicit,optional" json:"TargetServingNodeForHandover,omitempty"`
	UtranAdditionalPositioningData *UtranAdditionalPositioningData   `asn1:"tag:14,context,implicit,optional" json:"UtranAdditionalPositioningData,omitempty"`
	UtranBaroPressureMeas          *UtranBaroPressureMeas            `asn1:"tag:15,context,implicit,optional" json:"UtranBaroPressureMeas,omitempty"`
	UtranCivicAddress              *UtranCivicAddress                `asn1:"tag:16,context,implicit,optional" json:"UtranCivicAddress,omitempty"`
	ExtCount_                      int64                             `asn1:"-" json:"-"`
	ExtPresent_                    []bool                            `asn1:"-" json:"-"`
	ExtData_                       [][]byte                          `asn1:"-" json:"-"`
}

// AccuracyFulfilmentIndicator represents the ASN.1 ENUMERATED type AccuracyFulfilmentIndicator.
type AccuracyFulfilmentIndicator int64

const (
	AccuracyFulfilmentIndicatorRequestedAccuracyFulfilled    AccuracyFulfilmentIndicator = 0
	AccuracyFulfilmentIndicatorRequestedAccuracyNotFulfilled AccuracyFulfilmentIndicator = 1
)

func (v AccuracyFulfilmentIndicator) String() string {
	switch v {
	case AccuracyFulfilmentIndicatorRequestedAccuracyFulfilled:
		return "requestedAccuracyFulfilled"
	case AccuracyFulfilmentIndicatorRequestedAccuracyNotFulfilled:
		return "requestedAccuracyNotFulfilled"
	default:
		return "unknown"
	}
}

// ExtGeographicalInformation represents the ASN.1 type Ext-GeographicalInformation (OCTET_STRING).
type ExtGeographicalInformation = []byte

// VelocityEstimate represents the ASN.1 type VelocityEstimate (OCTET_STRING).
type VelocityEstimate = []byte

// PositioningDataInformation represents the ASN.1 type PositioningDataInformation (OCTET_STRING).
type PositioningDataInformation = []byte

// UtranPositioningDataInfo represents the ASN.1 type UtranPositioningDataInfo (OCTET_STRING).
type UtranPositioningDataInfo = []byte

// GeranGANSSpositioningData represents the ASN.1 type GeranGANSSpositioningData (OCTET_STRING).
type GeranGANSSpositioningData = []byte

// UtranGANSSpositioningData represents the ASN.1 type UtranGANSSpositioningData (OCTET_STRING).
type UtranGANSSpositioningData = []byte

// UtranAdditionalPositioningData represents the ASN.1 type UtranAdditionalPositioningData (OCTET_STRING).
type UtranAdditionalPositioningData = []byte

// UtranBaroPressureMeas represents the ASN.1 type UtranBaroPressureMeas (INTEGER).
type UtranBaroPressureMeas = int64

// UtranCivicAddress represents the ASN.1 type UtranCivicAddress (OCTET_STRING).
type UtranCivicAddress = []byte

// AddGeographicalInformation represents the ASN.1 type Add-GeographicalInformation (OCTET_STRING).
type AddGeographicalInformation = []byte

// SubscriberLocationReportArg represents the ASN.1 type SubscriberLocationReport-Arg (SEQUENCE).
type SubscriberLocationReportArg struct {
	LcsEvent                       LCSEvent                          `asn1:""`
	LcsClientID                    LCSClientID                       `asn1:""`
	LcsLocationInfo                LCSLocationInfo                   `asn1:""`
	Msisdn                         *ISDNAddressString                `asn1:"tag:0,context,implicit,optional" json:"Msisdn,omitempty"`
	Imsi                           *IMSI                             `asn1:"tag:1,context,implicit,optional" json:"Imsi,omitempty"`
	Imei                           *IMEI                             `asn1:"tag:2,context,implicit,optional" json:"Imei,omitempty"`
	NaESRD                         *ISDNAddressString                `asn1:"tag:3,context,implicit,optional" json:"NaESRD,omitempty"`
	NaESRK                         *ISDNAddressString                `asn1:"tag:4,context,implicit,optional" json:"NaESRK,omitempty"`
	LocationEstimate               *ExtGeographicalInformation       `asn1:"tag:5,context,implicit,optional" json:"LocationEstimate,omitempty"`
	AgeOfLocationEstimate          *AgeOfLocationInformation         `asn1:"tag:6,context,implicit,optional" json:"AgeOfLocationEstimate,omitempty"`
	SlrArgExtensionContainer       *SLRArgExtensionContainer         `asn1:"tag:7,context,implicit,optional" json:"SlrArgExtensionContainer,omitempty"`
	AddLocationEstimate            *AddGeographicalInformation       `asn1:"tag:8,context,implicit,optional" json:"AddLocationEstimate,omitempty"`
	DeferredmtLrData               *DeferredmtLrData                 `asn1:"tag:9,context,implicit,optional" json:"DeferredmtLrData,omitempty"`
	LcsReferenceNumber             *LCSReferenceNumber               `asn1:"tag:10,context,implicit,optional" json:"LcsReferenceNumber,omitempty"`
	GeranPositioningData           *PositioningDataInformation       `asn1:"tag:11,context,implicit,optional" json:"GeranPositioningData,omitempty"`
	UtranPositioningData           *UtranPositioningDataInfo         `asn1:"tag:12,context,implicit,optional" json:"UtranPositioningData,omitempty"`
	CellIdOrSai                    *CellGlobalIdOrServiceAreaIdOrLAI `asn1:"tag:13,context,explicit,optional" json:"CellIdOrSai,omitempty"`
	HGmlcAddress                   *GSNAddress                       `asn1:"tag:14,context,implicit,optional" json:"HGmlcAddress,omitempty"`
	LcsServiceTypeID               *LCSServiceTypeID                 `asn1:"tag:15,context,implicit,optional" json:"LcsServiceTypeID,omitempty"`
	SaiPresent                     *struct{}                         `asn1:"tag:17,context,implicit,optional" json:"SaiPresent,omitempty"`
	PseudonymIndicator             *struct{}                         `asn1:"tag:18,context,implicit,optional" json:"PseudonymIndicator,omitempty"`
	AccuracyFulfilmentIndicator    *AccuracyFulfilmentIndicator      `asn1:"tag:19,context,implicit,optional" json:"AccuracyFulfilmentIndicator,omitempty"`
	VelocityEstimate               *VelocityEstimate                 `asn1:"tag:20,context,implicit,optional" json:"VelocityEstimate,omitempty"`
	SequenceNumber                 *SequenceNumber                   `asn1:"tag:21,context,implicit,optional" json:"SequenceNumber,omitempty"`
	PeriodicLDRInfo                *PeriodicLDRInfo                  `asn1:"tag:22,context,implicit,optional" json:"PeriodicLDRInfo,omitempty"`
	MoLrShortCircuitIndicator      *struct{}                         `asn1:"tag:23,context,implicit,optional" json:"MoLrShortCircuitIndicator,omitempty"`
	GeranGANSSpositioningData      *GeranGANSSpositioningData        `asn1:"tag:24,context,implicit,optional" json:"GeranGANSSpositioningData,omitempty"`
	UtranGANSSpositioningData      *UtranGANSSpositioningData        `asn1:"tag:25,context,implicit,optional" json:"UtranGANSSpositioningData,omitempty"`
	TargetServingNodeForHandover   *ServingNodeAddress               `asn1:"tag:26,context,explicit,optional" json:"TargetServingNodeForHandover,omitempty"`
	UtranAdditionalPositioningData *UtranAdditionalPositioningData   `asn1:"tag:27,context,implicit,optional" json:"UtranAdditionalPositioningData,omitempty"`
	UtranBaroPressureMeas          *UtranBaroPressureMeas            `asn1:"tag:28,context,implicit,optional" json:"UtranBaroPressureMeas,omitempty"`
	UtranCivicAddress              *UtranCivicAddress                `asn1:"tag:29,context,implicit,optional" json:"UtranCivicAddress,omitempty"`
	ExtCount_                      int64                             `asn1:"-" json:"-"`
	ExtPresent_                    []bool                            `asn1:"-" json:"-"`
	ExtData_                       [][]byte                          `asn1:"-" json:"-"`
}

// DeferredmtLrData represents the ASN.1 type Deferredmt-lrData (SEQUENCE).
type DeferredmtLrData struct {
	DeferredLocationEventType DeferredLocationEventType `asn1:""`
	TerminationCause          *TerminationCause         `asn1:"tag:0,context,implicit,optional" json:"TerminationCause,omitempty"`
	LcsLocationInfo           *LCSLocationInfo          `asn1:"tag:1,context,implicit,optional" json:"LcsLocationInfo,omitempty"`
	ExtCount_                 int64                     `asn1:"-" json:"-"`
	ExtPresent_               []bool                    `asn1:"-" json:"-"`
	ExtData_                  [][]byte                  `asn1:"-" json:"-"`
}

// LCSEvent represents the ASN.1 ENUMERATED type LCS-Event.
type LCSEvent int64

const (
	LCSEventEmergencyCallOrigination   LCSEvent = 0
	LCSEventEmergencyCallRelease       LCSEvent = 1
	LCSEventMoLr                       LCSEvent = 2
	LCSEventDeferredmtLrResponse       LCSEvent = 3
	LCSEventDeferredmoLrTTTPInitiation LCSEvent = 4
	LCSEventEmergencyCallHandover      LCSEvent = 5
)

func (v LCSEvent) String() string {
	switch v {
	case LCSEventEmergencyCallOrigination:
		return "emergencyCallOrigination"
	case LCSEventEmergencyCallRelease:
		return "emergencyCallRelease"
	case LCSEventMoLr:
		return "mo-lr"
	case LCSEventDeferredmtLrResponse:
		return "deferredmt-lrResponse"
	case LCSEventDeferredmoLrTTTPInitiation:
		return "deferredmo-lrTTTPInitiation"
	case LCSEventEmergencyCallHandover:
		return "emergencyCallHandover"
	default:
		return "unknown"
	}
}

// TerminationCause represents the ASN.1 ENUMERATED type TerminationCause.
type TerminationCause int64

const (
	TerminationCauseNormal                              TerminationCause = 0
	TerminationCauseErrorundefined                      TerminationCause = 1
	TerminationCauseInternalTimeout                     TerminationCause = 2
	TerminationCauseCongestion                          TerminationCause = 3
	TerminationCauseMtLrRestart                         TerminationCause = 4
	TerminationCausePrivacyViolation                    TerminationCause = 5
	TerminationCauseShapeOfLocationEstimateNotSupported TerminationCause = 6
	TerminationCauseSubscriberTermination               TerminationCause = 7
	TerminationCauseUETermination                       TerminationCause = 8
	TerminationCauseNetworkTermination                  TerminationCause = 9
)

func (v TerminationCause) String() string {
	switch v {
	case TerminationCauseNormal:
		return "normal"
	case TerminationCauseErrorundefined:
		return "errorundefined"
	case TerminationCauseInternalTimeout:
		return "internalTimeout"
	case TerminationCauseCongestion:
		return "congestion"
	case TerminationCauseMtLrRestart:
		return "mt-lrRestart"
	case TerminationCausePrivacyViolation:
		return "privacyViolation"
	case TerminationCauseShapeOfLocationEstimateNotSupported:
		return "shapeOfLocationEstimateNotSupported"
	case TerminationCauseSubscriberTermination:
		return "subscriberTermination"
	case TerminationCauseUETermination:
		return "uETermination"
	case TerminationCauseNetworkTermination:
		return "networkTermination"
	default:
		return "unknown"
	}
}

// SequenceNumber represents the ASN.1 type SequenceNumber (INTEGER).
type SequenceNumber = int64

// ServingNodeAddress choice constants.
const (
	ServingNodeAddressChoiceMscNumber  = 1
	ServingNodeAddressChoiceSgsnNumber = 2
	ServingNodeAddressChoiceMmeNumber  = 3
)

// ServingNodeAddress represents the ASN.1 CHOICE type ServingNodeAddress.
type ServingNodeAddress struct {
	Choice     int
	MscNumber  *ISDNAddressString `json:"MscNumber,omitempty"`
	SgsnNumber *ISDNAddressString `json:"SgsnNumber,omitempty"`
	MmeNumber  *DiameterIdentity  `json:"MmeNumber,omitempty"`
}

// NewServingNodeAddressMscNumber creates a ServingNodeAddress with the msc-Number alternative.
func NewServingNodeAddressMscNumber(v ISDNAddressString) ServingNodeAddress {
	return ServingNodeAddress{
		Choice:    ServingNodeAddressChoiceMscNumber,
		MscNumber: &v,
	}
}

// NewServingNodeAddressSgsnNumber creates a ServingNodeAddress with the sgsn-Number alternative.
func NewServingNodeAddressSgsnNumber(v ISDNAddressString) ServingNodeAddress {
	return ServingNodeAddress{
		Choice:     ServingNodeAddressChoiceSgsnNumber,
		SgsnNumber: &v,
	}
}

// NewServingNodeAddressMmeNumber creates a ServingNodeAddress with the mme-Number alternative.
func NewServingNodeAddressMmeNumber(v DiameterIdentity) ServingNodeAddress {
	return ServingNodeAddress{
		Choice:    ServingNodeAddressChoiceMmeNumber,
		MmeNumber: &v,
	}
}

// SubscriberLocationReportRes represents the ASN.1 type SubscriberLocationReport-Res (SEQUENCE).
type SubscriberLocationReportRes struct {
	ExtensionContainer        *ExtensionContainer `asn1:",optional" json:"ExtensionContainer,omitempty"`
	NaESRK                    *ISDNAddressString  `asn1:"tag:0,context,implicit,optional" json:"NaESRK,omitempty"`
	NaESRD                    *ISDNAddressString  `asn1:"tag:1,context,implicit,optional" json:"NaESRD,omitempty"`
	HGmlcAddress              *GSNAddress         `asn1:"tag:2,context,implicit,optional" json:"HGmlcAddress,omitempty"`
	MoLrShortCircuitIndicator *struct{}           `asn1:"tag:3,context,implicit,optional" json:"MoLrShortCircuitIndicator,omitempty"`
	ReportingPLMNList         *ReportingPLMNList  `asn1:"tag:4,context,implicit,optional" json:"ReportingPLMNList,omitempty"`
	LcsReferenceNumber        *LCSReferenceNumber `asn1:"tag:5,context,implicit,optional" json:"LcsReferenceNumber,omitempty"`
	ExtCount_                 int64               `asn1:"-" json:"-"`
	ExtPresent_               []bool              `asn1:"-" json:"-"`
	ExtData_                  [][]byte            `asn1:"-" json:"-"`
}

// MarshalBER encodes RoutingInfoForLCSArg to BER format.
func (v *RoutingInfoForLCSArg) MarshalBER() ([]byte, error) {
	var children []byte
	enc_mlcnumber := ber.EncodeOctetString([]byte(v.MlcNumber))
	retagged_enc_mlcnumber, tagErr_enc_mlcnumber := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_mlcnumber)
	if tagErr_enc_mlcnumber != nil {
		return nil, fmt.Errorf("encoding mlcNumber: %w", tagErr_enc_mlcnumber)
	}
	enc_mlcnumber = retagged_enc_mlcnumber
	children = append(children, enc_mlcnumber...)
	enc_targetms, err := v.TargetMS.MarshalBER()
	if err != nil {
		return nil, fmt.Errorf("encoding targetMS: %w", err)
	}
	enc_targetms = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 1, enc_targetms)
	children = append(children, enc_targetms...)
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalBER()
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

// MarshalDER encodes RoutingInfoForLCSArg to DER format.
func (v *RoutingInfoForLCSArg) MarshalDER() ([]byte, error) {
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
		return nil, fmt.Errorf("encoding RoutingInfoForLCSArg as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes RoutingInfoForLCSArg from BER/DER format.
func (v *RoutingInfoForLCSArg) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding RoutingInfoForLCSArg SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "RoutingInfoForLCSArg", Cause: ber.ErrExtraData}
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
	decodedTag_mlcnumber, n_mlcnumber, rawVal_mlcnumber, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding mlcNumber: %w", err)
	}
	if decodedTag_mlcnumber.Class != tag.ClassContextSpecific || decodedTag_mlcnumber.Number != 0 {
		return fmt.Errorf("decoding mlcNumber: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_mlcnumber)
	}
	v.MlcNumber = ISDNAddressString(rawVal_mlcnumber)
	offset += n_mlcnumber
	// Decode targetMS
	if offset >= len(content) {
		return fmt.Errorf("missing required field targetMS")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 1 {
			return fmt.Errorf("expected tag [%s %d] for targetMS, got %s", "CONTEXT", 1, reqTag_)
		}
	}
	decodedTag_targetms, n_targetms, innerData_targetms, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding targetMS: %w", err)
	}
	if decodedTag_targetms.Class != tag.ClassContextSpecific || decodedTag_targetms.Number != 1 || decodedTag_targetms.Constructed != true {
		return fmt.Errorf("decoding targetMS: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_targetms)
	}
	// Decode inner value from explicit tag wrapper
	if unmErr := v.TargetMS.UnmarshalBER(innerData_targetms); unmErr != nil {
		return fmt.Errorf("decoding targetMS: %w", unmErr)
	}
	offset += n_targetms
	// Decode extensionContainer
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2 {
				decodedTag_extensioncontainer, n_extensioncontainer, rawVal_extensioncontainer, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding extensionContainer: %w", err)
				}
				if decodedTag_extensioncontainer.Class != tag.ClassContextSpecific || decodedTag_extensioncontainer.Number != 2 || decodedTag_extensioncontainer.Constructed != true {
					return fmt.Errorf("decoding extensionContainer: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_extensioncontainer)
				}
				reconstructed_extensioncontainer := ber.EncodeSequence(rawVal_extensioncontainer)
				var dec_extensioncontainer ExtensionContainer
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
			return &ber.DecodeError{Offset: offset, TypeName: "RoutingInfoForLCSArg", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes RoutingInfoForLCSRes to BER format.
func (v *RoutingInfoForLCSRes) MarshalBER() ([]byte, error) {
	var children []byte
	enc_targetms, err := v.TargetMS.MarshalBER()
	if err != nil {
		return nil, fmt.Errorf("encoding targetMS: %w", err)
	}
	enc_targetms = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 0, enc_targetms)
	children = append(children, enc_targetms...)
	enc_lcslocationinfo, err := v.LcsLocationInfo.MarshalBER()
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
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalBER()
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
		enc_vgmlcaddress := ber.EncodeOctetString([]byte(*v.VGmlcAddress))
		retagged_enc_vgmlcaddress, tagErr_enc_vgmlcaddress := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, enc_vgmlcaddress)
		if tagErr_enc_vgmlcaddress != nil {
			return nil, fmt.Errorf("encoding v-gmlc-Address: %w", tagErr_enc_vgmlcaddress)
		}
		enc_vgmlcaddress = retagged_enc_vgmlcaddress
		children = append(children, enc_vgmlcaddress...)
	}
	if v.HGmlcAddress != nil {
		enc_hgmlcaddress := ber.EncodeOctetString([]byte(*v.HGmlcAddress))
		retagged_enc_hgmlcaddress, tagErr_enc_hgmlcaddress := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, enc_hgmlcaddress)
		if tagErr_enc_hgmlcaddress != nil {
			return nil, fmt.Errorf("encoding h-gmlc-Address: %w", tagErr_enc_hgmlcaddress)
		}
		enc_hgmlcaddress = retagged_enc_hgmlcaddress
		children = append(children, enc_hgmlcaddress...)
	}
	if v.PprAddress != nil {
		enc_ppraddress := ber.EncodeOctetString([]byte(*v.PprAddress))
		retagged_enc_ppraddress, tagErr_enc_ppraddress := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 5, enc_ppraddress)
		if tagErr_enc_ppraddress != nil {
			return nil, fmt.Errorf("encoding ppr-Address: %w", tagErr_enc_ppraddress)
		}
		enc_ppraddress = retagged_enc_ppraddress
		children = append(children, enc_ppraddress...)
	}
	if v.AdditionalVGmlcAddress != nil {
		enc_additionalvgmlcaddress := ber.EncodeOctetString([]byte(*v.AdditionalVGmlcAddress))
		retagged_enc_additionalvgmlcaddress, tagErr_enc_additionalvgmlcaddress := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 6, enc_additionalvgmlcaddress)
		if tagErr_enc_additionalvgmlcaddress != nil {
			return nil, fmt.Errorf("encoding additional-v-gmlc-Address: %w", tagErr_enc_additionalvgmlcaddress)
		}
		enc_additionalvgmlcaddress = retagged_enc_additionalvgmlcaddress
		children = append(children, enc_additionalvgmlcaddress...)
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

// MarshalDER encodes RoutingInfoForLCSRes to DER format.
func (v *RoutingInfoForLCSRes) MarshalDER() ([]byte, error) {
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
		return nil, fmt.Errorf("encoding RoutingInfoForLCSRes as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes RoutingInfoForLCSRes from BER/DER format.
func (v *RoutingInfoForLCSRes) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding RoutingInfoForLCSRes SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "RoutingInfoForLCSRes", Cause: ber.ErrExtraData}
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
	decodedTag_targetms, n_targetms, innerData_targetms, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding targetMS: %w", err)
	}
	if decodedTag_targetms.Class != tag.ClassContextSpecific || decodedTag_targetms.Number != 0 || decodedTag_targetms.Constructed != true {
		return fmt.Errorf("decoding targetMS: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_targetms)
	}
	// Decode inner value from explicit tag wrapper
	if unmErr := v.TargetMS.UnmarshalBER(innerData_targetms); unmErr != nil {
		return fmt.Errorf("decoding targetMS: %w", unmErr)
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
	decodedTag_lcslocationinfo, n_lcslocationinfo, rawVal_lcslocationinfo, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding lcsLocationInfo: %w", err)
	}
	if decodedTag_lcslocationinfo.Class != tag.ClassContextSpecific || decodedTag_lcslocationinfo.Number != 1 || decodedTag_lcslocationinfo.Constructed != true {
		return fmt.Errorf("decoding lcsLocationInfo: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_lcslocationinfo)
	}
	reconstructed_lcslocationinfo := ber.EncodeSequence(rawVal_lcslocationinfo)
	if unmErr := v.LcsLocationInfo.UnmarshalBER(reconstructed_lcslocationinfo); unmErr != nil {
		return fmt.Errorf("decoding lcsLocationInfo: %w", unmErr)
	}
	offset += n_lcslocationinfo
	// Decode extensionContainer
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2 {
				decodedTag_extensioncontainer, n_extensioncontainer, rawVal_extensioncontainer, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding extensionContainer: %w", err)
				}
				if decodedTag_extensioncontainer.Class != tag.ClassContextSpecific || decodedTag_extensioncontainer.Number != 2 || decodedTag_extensioncontainer.Constructed != true {
					return fmt.Errorf("decoding extensionContainer: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_extensioncontainer)
				}
				reconstructed_extensioncontainer := ber.EncodeSequence(rawVal_extensioncontainer)
				var dec_extensioncontainer ExtensionContainer
				if unmErr := dec_extensioncontainer.UnmarshalBER(reconstructed_extensioncontainer); unmErr != nil {
					return fmt.Errorf("decoding extensionContainer: %w", unmErr)
				}
				v.ExtensionContainer = &dec_extensioncontainer
				offset += n_extensioncontainer
			}
		}
	}
	// Decode v-gmlc-Address
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3 {
				decodedTag_vgmlcaddress, n_vgmlcaddress, rawVal_vgmlcaddress, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding v-gmlc-Address: %w", err)
				}
				if decodedTag_vgmlcaddress.Class != tag.ClassContextSpecific || decodedTag_vgmlcaddress.Number != 3 {
					return fmt.Errorf("decoding v-gmlc-Address: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_vgmlcaddress)
				}
				tmp_vgmlcaddress := GSNAddress(rawVal_vgmlcaddress)
				v.VGmlcAddress = &tmp_vgmlcaddress
				offset += n_vgmlcaddress
			}
		}
	}
	// Decode h-gmlc-Address
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4 {
				decodedTag_hgmlcaddress, n_hgmlcaddress, rawVal_hgmlcaddress, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding h-gmlc-Address: %w", err)
				}
				if decodedTag_hgmlcaddress.Class != tag.ClassContextSpecific || decodedTag_hgmlcaddress.Number != 4 {
					return fmt.Errorf("decoding h-gmlc-Address: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_hgmlcaddress)
				}
				tmp_hgmlcaddress := GSNAddress(rawVal_hgmlcaddress)
				v.HGmlcAddress = &tmp_hgmlcaddress
				offset += n_hgmlcaddress
			}
		}
	}
	// Decode ppr-Address
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 5 {
				decodedTag_ppraddress, n_ppraddress, rawVal_ppraddress, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding ppr-Address: %w", err)
				}
				if decodedTag_ppraddress.Class != tag.ClassContextSpecific || decodedTag_ppraddress.Number != 5 {
					return fmt.Errorf("decoding ppr-Address: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_ppraddress)
				}
				tmp_ppraddress := GSNAddress(rawVal_ppraddress)
				v.PprAddress = &tmp_ppraddress
				offset += n_ppraddress
			}
		}
	}
	// Decode additional-v-gmlc-Address
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 6 {
				decodedTag_additionalvgmlcaddress, n_additionalvgmlcaddress, rawVal_additionalvgmlcaddress, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding additional-v-gmlc-Address: %w", err)
				}
				if decodedTag_additionalvgmlcaddress.Class != tag.ClassContextSpecific || decodedTag_additionalvgmlcaddress.Number != 6 {
					return fmt.Errorf("decoding additional-v-gmlc-Address: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_additionalvgmlcaddress)
				}
				tmp_additionalvgmlcaddress := GSNAddress(rawVal_additionalvgmlcaddress)
				v.AdditionalVGmlcAddress = &tmp_additionalvgmlcaddress
				offset += n_additionalvgmlcaddress
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "RoutingInfoForLCSRes", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes LCSLocationInfo to BER format.
func (v *LCSLocationInfo) MarshalBER() ([]byte, error) {
	var children []byte
	enc_networknodenumber := ber.EncodeOctetString([]byte(v.NetworkNodeNumber))
	children = append(children, enc_networknodenumber...)
	if v.Lmsi != nil {
		enc_lmsi := ber.EncodeOctetString([]byte(*v.Lmsi))
		retagged_enc_lmsi, tagErr_enc_lmsi := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_lmsi)
		if tagErr_enc_lmsi != nil {
			return nil, fmt.Errorf("encoding lmsi: %w", tagErr_enc_lmsi)
		}
		enc_lmsi = retagged_enc_lmsi
		children = append(children, enc_lmsi...)
	}
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalBER()
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
		enc_additionalnumber, err := v.AdditionalNumber.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding additional-Number: %w", err)
		}
		enc_additionalnumber = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 3, enc_additionalnumber)
		children = append(children, enc_additionalnumber...)
	}
	if v.SupportedLCSCapabilitySets != nil {
		enc_supportedlcscapabilitysets := ber.EncodeBitString(v.SupportedLCSCapabilitySets.Bytes, (8-(v.SupportedLCSCapabilitySets.BitLength%8))%8)
		retagged_enc_supportedlcscapabilitysets, tagErr_enc_supportedlcscapabilitysets := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, enc_supportedlcscapabilitysets)
		if tagErr_enc_supportedlcscapabilitysets != nil {
			return nil, fmt.Errorf("encoding supportedLCS-CapabilitySets: %w", tagErr_enc_supportedlcscapabilitysets)
		}
		enc_supportedlcscapabilitysets = retagged_enc_supportedlcscapabilitysets
		children = append(children, enc_supportedlcscapabilitysets...)
	}
	if v.AdditionalLCSCapabilitySets != nil {
		enc_additionallcscapabilitysets := ber.EncodeBitString(v.AdditionalLCSCapabilitySets.Bytes, (8-(v.AdditionalLCSCapabilitySets.BitLength%8))%8)
		retagged_enc_additionallcscapabilitysets, tagErr_enc_additionallcscapabilitysets := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 5, enc_additionallcscapabilitysets)
		if tagErr_enc_additionallcscapabilitysets != nil {
			return nil, fmt.Errorf("encoding additional-LCS-CapabilitySets: %w", tagErr_enc_additionallcscapabilitysets)
		}
		enc_additionallcscapabilitysets = retagged_enc_additionallcscapabilitysets
		children = append(children, enc_additionallcscapabilitysets...)
	}
	if v.MmeName != nil {
		enc_mmename := ber.EncodeOctetString([]byte(*v.MmeName))
		retagged_enc_mmename, tagErr_enc_mmename := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 6, enc_mmename)
		if tagErr_enc_mmename != nil {
			return nil, fmt.Errorf("encoding mme-Name: %w", tagErr_enc_mmename)
		}
		enc_mmename = retagged_enc_mmename
		children = append(children, enc_mmename...)
	}
	if v.AaaServerName != nil {
		enc_aaaservername := ber.EncodeOctetString([]byte(*v.AaaServerName))
		retagged_enc_aaaservername, tagErr_enc_aaaservername := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 8, enc_aaaservername)
		if tagErr_enc_aaaservername != nil {
			return nil, fmt.Errorf("encoding aaa-Server-Name: %w", tagErr_enc_aaaservername)
		}
		enc_aaaservername = retagged_enc_aaaservername
		children = append(children, enc_aaaservername...)
	}
	if v.SgsnName != nil {
		enc_sgsnname := ber.EncodeOctetString([]byte(*v.SgsnName))
		retagged_enc_sgsnname, tagErr_enc_sgsnname := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 9, enc_sgsnname)
		if tagErr_enc_sgsnname != nil {
			return nil, fmt.Errorf("encoding sgsn-Name: %w", tagErr_enc_sgsnname)
		}
		enc_sgsnname = retagged_enc_sgsnname
		children = append(children, enc_sgsnname...)
	}
	if v.SgsnRealm != nil {
		enc_sgsnrealm := ber.EncodeOctetString([]byte(*v.SgsnRealm))
		retagged_enc_sgsnrealm, tagErr_enc_sgsnrealm := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 10, enc_sgsnrealm)
		if tagErr_enc_sgsnrealm != nil {
			return nil, fmt.Errorf("encoding sgsn-Realm: %w", tagErr_enc_sgsnrealm)
		}
		enc_sgsnrealm = retagged_enc_sgsnrealm
		children = append(children, enc_sgsnrealm...)
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

// MarshalDER encodes LCSLocationInfo to DER format.
func (v *LCSLocationInfo) MarshalDER() ([]byte, error) {
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
		return nil, fmt.Errorf("encoding LCSLocationInfo as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes LCSLocationInfo from BER/DER format.
func (v *LCSLocationInfo) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding LCSLocationInfo SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "LCSLocationInfo", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode networkNode-Number
	if offset >= len(content) {
		return fmt.Errorf("missing required field networkNode-Number")
	}
	val_networknodenumber, n, err := ber.DecodeOctetString(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding networkNode-Number: %w", err)
	}
	v.NetworkNodeNumber = ISDNAddressString(val_networknodenumber)
	offset += n
	// Decode lmsi
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
				decodedTag_lmsi, n_lmsi, rawVal_lmsi, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding lmsi: %w", err)
				}
				if decodedTag_lmsi.Class != tag.ClassContextSpecific || decodedTag_lmsi.Number != 0 {
					return fmt.Errorf("decoding lmsi: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_lmsi)
				}
				tmp_lmsi := LMSI(rawVal_lmsi)
				v.Lmsi = &tmp_lmsi
				offset += n_lmsi
			}
		}
	}
	// Decode extensionContainer
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
				decodedTag_extensioncontainer, n_extensioncontainer, rawVal_extensioncontainer, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding extensionContainer: %w", err)
				}
				if decodedTag_extensioncontainer.Class != tag.ClassContextSpecific || decodedTag_extensioncontainer.Number != 1 || decodedTag_extensioncontainer.Constructed != true {
					return fmt.Errorf("decoding extensionContainer: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_extensioncontainer)
				}
				reconstructed_extensioncontainer := ber.EncodeSequence(rawVal_extensioncontainer)
				var dec_extensioncontainer ExtensionContainer
				if unmErr := dec_extensioncontainer.UnmarshalBER(reconstructed_extensioncontainer); unmErr != nil {
					return fmt.Errorf("decoding extensionContainer: %w", unmErr)
				}
				v.ExtensionContainer = &dec_extensioncontainer
				offset += n_extensioncontainer
			}
		}
	}
	// Decode gprsNodeIndicator
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2 {
				decodedTag_gprsnodeindicator, n_gprsnodeindicator, rawVal_gprsnodeindicator, err := ber.DecodeTLV(content[offset:])
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
				offset += n_gprsnodeindicator
			}
		}
	}
	// Decode additional-Number
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3 {
				decodedTag_additionalnumber, n_additionalnumber, innerData_additionalnumber, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding additional-Number: %w", err)
				}
				if decodedTag_additionalnumber.Class != tag.ClassContextSpecific || decodedTag_additionalnumber.Number != 3 || decodedTag_additionalnumber.Constructed != true {
					return fmt.Errorf("decoding additional-Number: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_additionalnumber)
				}
				// Decode inner value from explicit tag wrapper
				var dec_additionalnumber AdditionalNumber
				if unmErr := dec_additionalnumber.UnmarshalBER(innerData_additionalnumber); unmErr != nil {
					return fmt.Errorf("decoding additional-Number: %w", unmErr)
				}
				v.AdditionalNumber = &dec_additionalnumber
				offset += n_additionalnumber
			}
		}
	}
	// Decode supportedLCS-CapabilitySets
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4 {
				decodedTag_supportedlcscapabilitysets, n_supportedlcscapabilitysets, rawVal_supportedlcscapabilitysets, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding supportedLCS-CapabilitySets: %w", err)
				}
				if decodedTag_supportedlcscapabilitysets.Class != tag.ClassContextSpecific || decodedTag_supportedlcscapabilitysets.Number != 4 {
					return fmt.Errorf("decoding supportedLCS-CapabilitySets: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_supportedlcscapabilitysets)
				}
				bsBytes_supportedlcscapabilitysets, bsUnused_supportedlcscapabilitysets, bsErr := ber.DecodeBitStringValue(rawVal_supportedlcscapabilitysets)
				if bsErr != nil {
					return fmt.Errorf("decoding supportedLCS-CapabilitySets: %w", bsErr)
				}
				tmp_supportedlcscapabilitysets := runtime.BitString{Bytes: bsBytes_supportedlcscapabilitysets, BitLength: len(bsBytes_supportedlcscapabilitysets)*8 - bsUnused_supportedlcscapabilitysets}
				v.SupportedLCSCapabilitySets = &tmp_supportedlcscapabilitysets
				offset += n_supportedlcscapabilitysets
			}
		}
	}
	// Decode additional-LCS-CapabilitySets
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 5 {
				decodedTag_additionallcscapabilitysets, n_additionallcscapabilitysets, rawVal_additionallcscapabilitysets, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding additional-LCS-CapabilitySets: %w", err)
				}
				if decodedTag_additionallcscapabilitysets.Class != tag.ClassContextSpecific || decodedTag_additionallcscapabilitysets.Number != 5 {
					return fmt.Errorf("decoding additional-LCS-CapabilitySets: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_additionallcscapabilitysets)
				}
				bsBytes_additionallcscapabilitysets, bsUnused_additionallcscapabilitysets, bsErr := ber.DecodeBitStringValue(rawVal_additionallcscapabilitysets)
				if bsErr != nil {
					return fmt.Errorf("decoding additional-LCS-CapabilitySets: %w", bsErr)
				}
				tmp_additionallcscapabilitysets := runtime.BitString{Bytes: bsBytes_additionallcscapabilitysets, BitLength: len(bsBytes_additionallcscapabilitysets)*8 - bsUnused_additionallcscapabilitysets}
				v.AdditionalLCSCapabilitySets = &tmp_additionallcscapabilitysets
				offset += n_additionallcscapabilitysets
			}
		}
	}
	// Decode mme-Name
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 6 {
				decodedTag_mmename, n_mmename, rawVal_mmename, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding mme-Name: %w", err)
				}
				if decodedTag_mmename.Class != tag.ClassContextSpecific || decodedTag_mmename.Number != 6 {
					return fmt.Errorf("decoding mme-Name: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_mmename)
				}
				tmp_mmename := DiameterIdentity(rawVal_mmename)
				v.MmeName = &tmp_mmename
				offset += n_mmename
			}
		}
	}
	// Decode aaa-Server-Name
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 8 {
				decodedTag_aaaservername, n_aaaservername, rawVal_aaaservername, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding aaa-Server-Name: %w", err)
				}
				if decodedTag_aaaservername.Class != tag.ClassContextSpecific || decodedTag_aaaservername.Number != 8 {
					return fmt.Errorf("decoding aaa-Server-Name: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_aaaservername)
				}
				tmp_aaaservername := DiameterIdentity(rawVal_aaaservername)
				v.AaaServerName = &tmp_aaaservername
				offset += n_aaaservername
			}
		}
	}
	// Decode sgsn-Name
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 9 {
				decodedTag_sgsnname, n_sgsnname, rawVal_sgsnname, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding sgsn-Name: %w", err)
				}
				if decodedTag_sgsnname.Class != tag.ClassContextSpecific || decodedTag_sgsnname.Number != 9 {
					return fmt.Errorf("decoding sgsn-Name: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_sgsnname)
				}
				tmp_sgsnname := DiameterIdentity(rawVal_sgsnname)
				v.SgsnName = &tmp_sgsnname
				offset += n_sgsnname
			}
		}
	}
	// Decode sgsn-Realm
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 10 {
				decodedTag_sgsnrealm, n_sgsnrealm, rawVal_sgsnrealm, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding sgsn-Realm: %w", err)
				}
				if decodedTag_sgsnrealm.Class != tag.ClassContextSpecific || decodedTag_sgsnrealm.Number != 10 {
					return fmt.Errorf("decoding sgsn-Realm: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_sgsnrealm)
				}
				tmp_sgsnrealm := DiameterIdentity(rawVal_sgsnrealm)
				v.SgsnRealm = &tmp_sgsnrealm
				offset += n_sgsnrealm
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "LCSLocationInfo", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes ProvideSubscriberLocationArg to BER format.
func (v *ProvideSubscriberLocationArg) MarshalBER() ([]byte, error) {
	var children []byte
	enc_locationtype, err := v.LocationType.MarshalBER()
	if err != nil {
		return nil, fmt.Errorf("encoding locationType: %w", err)
	}
	children = append(children, enc_locationtype...)
	enc_mlcnumber := ber.EncodeOctetString([]byte(v.MlcNumber))
	children = append(children, enc_mlcnumber...)
	if v.LcsClientID != nil {
		enc_lcsclientid, err := v.LcsClientID.MarshalBER()
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
		enc_imsi := ber.EncodeOctetString([]byte(*v.Imsi))
		retagged_enc_imsi, tagErr_enc_imsi := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_imsi)
		if tagErr_enc_imsi != nil {
			return nil, fmt.Errorf("encoding imsi: %w", tagErr_enc_imsi)
		}
		enc_imsi = retagged_enc_imsi
		children = append(children, enc_imsi...)
	}
	if v.Msisdn != nil {
		enc_msisdn := ber.EncodeOctetString([]byte(*v.Msisdn))
		retagged_enc_msisdn, tagErr_enc_msisdn := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, enc_msisdn)
		if tagErr_enc_msisdn != nil {
			return nil, fmt.Errorf("encoding msisdn: %w", tagErr_enc_msisdn)
		}
		enc_msisdn = retagged_enc_msisdn
		children = append(children, enc_msisdn...)
	}
	if v.Lmsi != nil {
		enc_lmsi := ber.EncodeOctetString([]byte(*v.Lmsi))
		retagged_enc_lmsi, tagErr_enc_lmsi := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, enc_lmsi)
		if tagErr_enc_lmsi != nil {
			return nil, fmt.Errorf("encoding lmsi: %w", tagErr_enc_lmsi)
		}
		enc_lmsi = retagged_enc_lmsi
		children = append(children, enc_lmsi...)
	}
	if v.Imei != nil {
		enc_imei := ber.EncodeOctetString([]byte(*v.Imei))
		retagged_enc_imei, tagErr_enc_imei := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 5, enc_imei)
		if tagErr_enc_imei != nil {
			return nil, fmt.Errorf("encoding imei: %w", tagErr_enc_imei)
		}
		enc_imei = retagged_enc_imei
		children = append(children, enc_imei...)
	}
	if v.LcsPriority != nil {
		enc_lcspriority := ber.EncodeOctetString([]byte(*v.LcsPriority))
		retagged_enc_lcspriority, tagErr_enc_lcspriority := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 6, enc_lcspriority)
		if tagErr_enc_lcspriority != nil {
			return nil, fmt.Errorf("encoding lcs-Priority: %w", tagErr_enc_lcspriority)
		}
		enc_lcspriority = retagged_enc_lcspriority
		children = append(children, enc_lcspriority...)
	}
	if v.LcsQoS != nil {
		enc_lcsqos, err := v.LcsQoS.MarshalBER()
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
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalBER()
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
		enc_supportedgadshapes := ber.EncodeBitString(v.SupportedGADShapes.Bytes, (8-(v.SupportedGADShapes.BitLength%8))%8)
		retagged_enc_supportedgadshapes, tagErr_enc_supportedgadshapes := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 9, enc_supportedgadshapes)
		if tagErr_enc_supportedgadshapes != nil {
			return nil, fmt.Errorf("encoding supportedGADShapes: %w", tagErr_enc_supportedgadshapes)
		}
		enc_supportedgadshapes = retagged_enc_supportedgadshapes
		children = append(children, enc_supportedgadshapes...)
	}
	if v.LcsReferenceNumber != nil {
		enc_lcsreferencenumber := ber.EncodeOctetString([]byte(*v.LcsReferenceNumber))
		retagged_enc_lcsreferencenumber, tagErr_enc_lcsreferencenumber := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 10, enc_lcsreferencenumber)
		if tagErr_enc_lcsreferencenumber != nil {
			return nil, fmt.Errorf("encoding lcs-ReferenceNumber: %w", tagErr_enc_lcsreferencenumber)
		}
		enc_lcsreferencenumber = retagged_enc_lcsreferencenumber
		children = append(children, enc_lcsreferencenumber...)
	}
	if v.LcsServiceTypeID != nil {
		enc_lcsservicetypeid := ber.EncodeInteger(int64(*v.LcsServiceTypeID))
		retagged_enc_lcsservicetypeid, tagErr_enc_lcsservicetypeid := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 11, enc_lcsservicetypeid)
		if tagErr_enc_lcsservicetypeid != nil {
			return nil, fmt.Errorf("encoding lcsServiceTypeID: %w", tagErr_enc_lcsservicetypeid)
		}
		enc_lcsservicetypeid = retagged_enc_lcsservicetypeid
		children = append(children, enc_lcsservicetypeid...)
	}
	if v.LcsCodeword != nil {
		enc_lcscodeword, err := v.LcsCodeword.MarshalBER()
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
		enc_lcsprivacycheck, err := v.LcsPrivacyCheck.MarshalBER()
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
		enc_areaeventinfo, err := v.AreaEventInfo.MarshalBER()
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
		enc_hgmlcaddress := ber.EncodeOctetString([]byte(*v.HGmlcAddress))
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
		enc_periodicldrinfo, err := v.PeriodicLDRInfo.MarshalBER()
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
		enc_reportingplmnlist, err := v.ReportingPLMNList.MarshalBER()
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

// MarshalDER encodes ProvideSubscriberLocationArg to DER format.
func (v *ProvideSubscriberLocationArg) MarshalDER() ([]byte, error) {
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
		return nil, fmt.Errorf("encoding ProvideSubscriberLocationArg as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes ProvideSubscriberLocationArg from BER/DER format.
func (v *ProvideSubscriberLocationArg) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding ProvideSubscriberLocationArg SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "ProvideSubscriberLocationArg", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode locationType
	if offset >= len(content) {
		return fmt.Errorf("missing required field locationType")
	}
	// Decode nested SEQUENCE (LocationType)
	_, n_locationtype, _, tlvErr_locationtype := ber.DecodeTLV(content[offset:])
	if tlvErr_locationtype != nil {
		return fmt.Errorf("decoding locationType: %w", tlvErr_locationtype)
	}
	if unmErr := v.LocationType.UnmarshalBER(content[offset : offset+n_locationtype]); unmErr != nil {
		return fmt.Errorf("decoding locationType: %w", unmErr)
	}
	offset += n_locationtype
	// Decode mlc-Number
	if offset >= len(content) {
		return fmt.Errorf("missing required field mlc-Number")
	}
	val_mlcnumber, n, err := ber.DecodeOctetString(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding mlc-Number: %w", err)
	}
	v.MlcNumber = ISDNAddressString(val_mlcnumber)
	offset += n
	// Decode lcs-ClientID
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
				decodedTag_lcsclientid, n_lcsclientid, rawVal_lcsclientid, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding lcs-ClientID: %w", err)
				}
				if decodedTag_lcsclientid.Class != tag.ClassContextSpecific || decodedTag_lcsclientid.Number != 0 || decodedTag_lcsclientid.Constructed != true {
					return fmt.Errorf("decoding lcs-ClientID: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_lcsclientid)
				}
				reconstructed_lcsclientid := ber.EncodeSequence(rawVal_lcsclientid)
				var dec_lcsclientid LCSClientID
				if unmErr := dec_lcsclientid.UnmarshalBER(reconstructed_lcsclientid); unmErr != nil {
					return fmt.Errorf("decoding lcs-ClientID: %w", unmErr)
				}
				v.LcsClientID = &dec_lcsclientid
				offset += n_lcsclientid
			}
		}
	}
	// Decode privacyOverride
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
				decodedTag_privacyoverride, n_privacyoverride, rawVal_privacyoverride, err := ber.DecodeTLV(content[offset:])
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
				offset += n_privacyoverride
			}
		}
	}
	// Decode imsi
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2 {
				decodedTag_imsi, n_imsi, rawVal_imsi, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding imsi: %w", err)
				}
				if decodedTag_imsi.Class != tag.ClassContextSpecific || decodedTag_imsi.Number != 2 {
					return fmt.Errorf("decoding imsi: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_imsi)
				}
				tmp_imsi := IMSI(rawVal_imsi)
				v.Imsi = &tmp_imsi
				offset += n_imsi
			}
		}
	}
	// Decode msisdn
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3 {
				decodedTag_msisdn, n_msisdn, rawVal_msisdn, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding msisdn: %w", err)
				}
				if decodedTag_msisdn.Class != tag.ClassContextSpecific || decodedTag_msisdn.Number != 3 {
					return fmt.Errorf("decoding msisdn: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_msisdn)
				}
				tmp_msisdn := ISDNAddressString(rawVal_msisdn)
				v.Msisdn = &tmp_msisdn
				offset += n_msisdn
			}
		}
	}
	// Decode lmsi
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4 {
				decodedTag_lmsi, n_lmsi, rawVal_lmsi, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding lmsi: %w", err)
				}
				if decodedTag_lmsi.Class != tag.ClassContextSpecific || decodedTag_lmsi.Number != 4 {
					return fmt.Errorf("decoding lmsi: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_lmsi)
				}
				tmp_lmsi := LMSI(rawVal_lmsi)
				v.Lmsi = &tmp_lmsi
				offset += n_lmsi
			}
		}
	}
	// Decode imei
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 5 {
				decodedTag_imei, n_imei, rawVal_imei, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding imei: %w", err)
				}
				if decodedTag_imei.Class != tag.ClassContextSpecific || decodedTag_imei.Number != 5 {
					return fmt.Errorf("decoding imei: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_imei)
				}
				tmp_imei := IMEI(rawVal_imei)
				v.Imei = &tmp_imei
				offset += n_imei
			}
		}
	}
	// Decode lcs-Priority
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 6 {
				decodedTag_lcspriority, n_lcspriority, rawVal_lcspriority, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding lcs-Priority: %w", err)
				}
				if decodedTag_lcspriority.Class != tag.ClassContextSpecific || decodedTag_lcspriority.Number != 6 {
					return fmt.Errorf("decoding lcs-Priority: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_lcspriority)
				}
				tmp_lcspriority := LCSPriority(rawVal_lcspriority)
				v.LcsPriority = &tmp_lcspriority
				offset += n_lcspriority
			}
		}
	}
	// Decode lcs-QoS
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 7 {
				decodedTag_lcsqos, n_lcsqos, rawVal_lcsqos, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding lcs-QoS: %w", err)
				}
				if decodedTag_lcsqos.Class != tag.ClassContextSpecific || decodedTag_lcsqos.Number != 7 || decodedTag_lcsqos.Constructed != true {
					return fmt.Errorf("decoding lcs-QoS: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_lcsqos)
				}
				reconstructed_lcsqos := ber.EncodeSequence(rawVal_lcsqos)
				var dec_lcsqos LCSQoS
				if unmErr := dec_lcsqos.UnmarshalBER(reconstructed_lcsqos); unmErr != nil {
					return fmt.Errorf("decoding lcs-QoS: %w", unmErr)
				}
				v.LcsQoS = &dec_lcsqos
				offset += n_lcsqos
			}
		}
	}
	// Decode extensionContainer
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 8 {
				decodedTag_extensioncontainer, n_extensioncontainer, rawVal_extensioncontainer, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding extensionContainer: %w", err)
				}
				if decodedTag_extensioncontainer.Class != tag.ClassContextSpecific || decodedTag_extensioncontainer.Number != 8 || decodedTag_extensioncontainer.Constructed != true {
					return fmt.Errorf("decoding extensionContainer: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_extensioncontainer)
				}
				reconstructed_extensioncontainer := ber.EncodeSequence(rawVal_extensioncontainer)
				var dec_extensioncontainer ExtensionContainer
				if unmErr := dec_extensioncontainer.UnmarshalBER(reconstructed_extensioncontainer); unmErr != nil {
					return fmt.Errorf("decoding extensionContainer: %w", unmErr)
				}
				v.ExtensionContainer = &dec_extensioncontainer
				offset += n_extensioncontainer
			}
		}
	}
	// Decode supportedGADShapes
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 9 {
				decodedTag_supportedgadshapes, n_supportedgadshapes, rawVal_supportedgadshapes, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding supportedGADShapes: %w", err)
				}
				if decodedTag_supportedgadshapes.Class != tag.ClassContextSpecific || decodedTag_supportedgadshapes.Number != 9 {
					return fmt.Errorf("decoding supportedGADShapes: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_supportedgadshapes)
				}
				bsBytes_supportedgadshapes, bsUnused_supportedgadshapes, bsErr := ber.DecodeBitStringValue(rawVal_supportedgadshapes)
				if bsErr != nil {
					return fmt.Errorf("decoding supportedGADShapes: %w", bsErr)
				}
				tmp_supportedgadshapes := runtime.BitString{Bytes: bsBytes_supportedgadshapes, BitLength: len(bsBytes_supportedgadshapes)*8 - bsUnused_supportedgadshapes}
				v.SupportedGADShapes = &tmp_supportedgadshapes
				offset += n_supportedgadshapes
			}
		}
	}
	// Decode lcs-ReferenceNumber
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 10 {
				decodedTag_lcsreferencenumber, n_lcsreferencenumber, rawVal_lcsreferencenumber, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding lcs-ReferenceNumber: %w", err)
				}
				if decodedTag_lcsreferencenumber.Class != tag.ClassContextSpecific || decodedTag_lcsreferencenumber.Number != 10 {
					return fmt.Errorf("decoding lcs-ReferenceNumber: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_lcsreferencenumber)
				}
				tmp_lcsreferencenumber := LCSReferenceNumber(rawVal_lcsreferencenumber)
				v.LcsReferenceNumber = &tmp_lcsreferencenumber
				offset += n_lcsreferencenumber
			}
		}
	}
	// Decode lcsServiceTypeID
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 11 {
				decodedTag_lcsservicetypeid, n_lcsservicetypeid, rawVal_lcsservicetypeid, err := ber.DecodeTLV(content[offset:])
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
				tmp_lcsservicetypeid := LCSServiceTypeID(decVal_lcsservicetypeid)
				v.LcsServiceTypeID = &tmp_lcsservicetypeid
				offset += n_lcsservicetypeid
			}
		}
	}
	// Decode lcsCodeword
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 12 {
				decodedTag_lcscodeword, n_lcscodeword, rawVal_lcscodeword, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding lcsCodeword: %w", err)
				}
				if decodedTag_lcscodeword.Class != tag.ClassContextSpecific || decodedTag_lcscodeword.Number != 12 || decodedTag_lcscodeword.Constructed != true {
					return fmt.Errorf("decoding lcsCodeword: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_lcscodeword)
				}
				reconstructed_lcscodeword := ber.EncodeSequence(rawVal_lcscodeword)
				var dec_lcscodeword LCSCodeword
				if unmErr := dec_lcscodeword.UnmarshalBER(reconstructed_lcscodeword); unmErr != nil {
					return fmt.Errorf("decoding lcsCodeword: %w", unmErr)
				}
				v.LcsCodeword = &dec_lcscodeword
				offset += n_lcscodeword
			}
		}
	}
	// Decode lcs-PrivacyCheck
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 13 {
				decodedTag_lcsprivacycheck, n_lcsprivacycheck, rawVal_lcsprivacycheck, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding lcs-PrivacyCheck: %w", err)
				}
				if decodedTag_lcsprivacycheck.Class != tag.ClassContextSpecific || decodedTag_lcsprivacycheck.Number != 13 || decodedTag_lcsprivacycheck.Constructed != true {
					return fmt.Errorf("decoding lcs-PrivacyCheck: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_lcsprivacycheck)
				}
				reconstructed_lcsprivacycheck := ber.EncodeSequence(rawVal_lcsprivacycheck)
				var dec_lcsprivacycheck LCSPrivacyCheck
				if unmErr := dec_lcsprivacycheck.UnmarshalBER(reconstructed_lcsprivacycheck); unmErr != nil {
					return fmt.Errorf("decoding lcs-PrivacyCheck: %w", unmErr)
				}
				v.LcsPrivacyCheck = &dec_lcsprivacycheck
				offset += n_lcsprivacycheck
			}
		}
	}
	// Decode areaEventInfo
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 14 {
				decodedTag_areaeventinfo, n_areaeventinfo, rawVal_areaeventinfo, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding areaEventInfo: %w", err)
				}
				if decodedTag_areaeventinfo.Class != tag.ClassContextSpecific || decodedTag_areaeventinfo.Number != 14 || decodedTag_areaeventinfo.Constructed != true {
					return fmt.Errorf("decoding areaEventInfo: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_areaeventinfo)
				}
				reconstructed_areaeventinfo := ber.EncodeSequence(rawVal_areaeventinfo)
				var dec_areaeventinfo AreaEventInfo
				if unmErr := dec_areaeventinfo.UnmarshalBER(reconstructed_areaeventinfo); unmErr != nil {
					return fmt.Errorf("decoding areaEventInfo: %w", unmErr)
				}
				v.AreaEventInfo = &dec_areaeventinfo
				offset += n_areaeventinfo
			}
		}
	}
	// Decode h-gmlc-Address
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 15 {
				decodedTag_hgmlcaddress, n_hgmlcaddress, rawVal_hgmlcaddress, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding h-gmlc-Address: %w", err)
				}
				if decodedTag_hgmlcaddress.Class != tag.ClassContextSpecific || decodedTag_hgmlcaddress.Number != 15 {
					return fmt.Errorf("decoding h-gmlc-Address: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_hgmlcaddress)
				}
				tmp_hgmlcaddress := GSNAddress(rawVal_hgmlcaddress)
				v.HGmlcAddress = &tmp_hgmlcaddress
				offset += n_hgmlcaddress
			}
		}
	}
	// Decode mo-lrShortCircuitIndicator
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 16 {
				decodedTag_molrshortcircuitindicator, n_molrshortcircuitindicator, rawVal_molrshortcircuitindicator, err := ber.DecodeTLV(content[offset:])
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
				offset += n_molrshortcircuitindicator
			}
		}
	}
	// Decode periodicLDRInfo
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 17 {
				decodedTag_periodicldrinfo, n_periodicldrinfo, rawVal_periodicldrinfo, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding periodicLDRInfo: %w", err)
				}
				if decodedTag_periodicldrinfo.Class != tag.ClassContextSpecific || decodedTag_periodicldrinfo.Number != 17 || decodedTag_periodicldrinfo.Constructed != true {
					return fmt.Errorf("decoding periodicLDRInfo: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_periodicldrinfo)
				}
				reconstructed_periodicldrinfo := ber.EncodeSequence(rawVal_periodicldrinfo)
				var dec_periodicldrinfo PeriodicLDRInfo
				if unmErr := dec_periodicldrinfo.UnmarshalBER(reconstructed_periodicldrinfo); unmErr != nil {
					return fmt.Errorf("decoding periodicLDRInfo: %w", unmErr)
				}
				v.PeriodicLDRInfo = &dec_periodicldrinfo
				offset += n_periodicldrinfo
			}
		}
	}
	// Decode reportingPLMNList
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 18 {
				decodedTag_reportingplmnlist, n_reportingplmnlist, rawVal_reportingplmnlist, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding reportingPLMNList: %w", err)
				}
				if decodedTag_reportingplmnlist.Class != tag.ClassContextSpecific || decodedTag_reportingplmnlist.Number != 18 || decodedTag_reportingplmnlist.Constructed != true {
					return fmt.Errorf("decoding reportingPLMNList: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_reportingplmnlist)
				}
				reconstructed_reportingplmnlist := ber.EncodeSequence(rawVal_reportingplmnlist)
				var dec_reportingplmnlist ReportingPLMNList
				if unmErr := dec_reportingplmnlist.UnmarshalBER(reconstructed_reportingplmnlist); unmErr != nil {
					return fmt.Errorf("decoding reportingPLMNList: %w", unmErr)
				}
				v.ReportingPLMNList = &dec_reportingplmnlist
				offset += n_reportingplmnlist
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "ProvideSubscriberLocationArg", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes LocationType to BER format.
func (v *LocationType) MarshalBER() ([]byte, error) {
	var children []byte
	enc_locationestimatetype := ber.EncodeEnumerated(int64(v.LocationEstimateType))
	retagged_enc_locationestimatetype, tagErr_enc_locationestimatetype := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_locationestimatetype)
	if tagErr_enc_locationestimatetype != nil {
		return nil, fmt.Errorf("encoding locationEstimateType: %w", tagErr_enc_locationestimatetype)
	}
	enc_locationestimatetype = retagged_enc_locationestimatetype
	children = append(children, enc_locationestimatetype...)
	if v.DeferredLocationEventType != nil {
		enc_deferredlocationeventtype := ber.EncodeBitString(v.DeferredLocationEventType.Bytes, (8-(v.DeferredLocationEventType.BitLength%8))%8)
		retagged_enc_deferredlocationeventtype, tagErr_enc_deferredlocationeventtype := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_deferredlocationeventtype)
		if tagErr_enc_deferredlocationeventtype != nil {
			return nil, fmt.Errorf("encoding deferredLocationEventType: %w", tagErr_enc_deferredlocationeventtype)
		}
		enc_deferredlocationeventtype = retagged_enc_deferredlocationeventtype
		children = append(children, enc_deferredlocationeventtype...)
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

// MarshalDER encodes LocationType to DER format.
func (v *LocationType) MarshalDER() ([]byte, error) {
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
		return nil, fmt.Errorf("encoding LocationType as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes LocationType from BER/DER format.
func (v *LocationType) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding LocationType SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "LocationType", Cause: ber.ErrExtraData}
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
	decodedTag_locationestimatetype, n_locationestimatetype, rawVal_locationestimatetype, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding locationEstimateType: %w", err)
	}
	if decodedTag_locationestimatetype.Class != tag.ClassContextSpecific || decodedTag_locationestimatetype.Number != 0 || decodedTag_locationestimatetype.Constructed != false {
		return fmt.Errorf("decoding locationEstimateType: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_locationestimatetype)
	}
	decVal_locationestimatetype, intErr := ber.DecodeIntegerValue(rawVal_locationestimatetype)
	if intErr != nil {
		return fmt.Errorf("decoding locationEstimateType: %w", intErr)
	}
	v.LocationEstimateType = LocationEstimateType(decVal_locationestimatetype)
	offset += n_locationestimatetype
	// Decode deferredLocationEventType
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
				decodedTag_deferredlocationeventtype, n_deferredlocationeventtype, rawVal_deferredlocationeventtype, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding deferredLocationEventType: %w", err)
				}
				if decodedTag_deferredlocationeventtype.Class != tag.ClassContextSpecific || decodedTag_deferredlocationeventtype.Number != 1 {
					return fmt.Errorf("decoding deferredLocationEventType: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_deferredlocationeventtype)
				}
				bsBytes_deferredlocationeventtype, bsUnused_deferredlocationeventtype, bsErr := ber.DecodeBitStringValue(rawVal_deferredlocationeventtype)
				if bsErr != nil {
					return fmt.Errorf("decoding deferredLocationEventType: %w", bsErr)
				}
				tmp_deferredlocationeventtype := runtime.BitString{Bytes: bsBytes_deferredlocationeventtype, BitLength: len(bsBytes_deferredlocationeventtype)*8 - bsUnused_deferredlocationeventtype}
				v.DeferredLocationEventType = &tmp_deferredlocationeventtype
				offset += n_deferredlocationeventtype
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "LocationType", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes LCSClientID to BER format.
func (v *LCSClientID) MarshalBER() ([]byte, error) {
	var children []byte
	enc_lcsclienttype := ber.EncodeEnumerated(int64(v.LcsClientType))
	retagged_enc_lcsclienttype, tagErr_enc_lcsclienttype := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_lcsclienttype)
	if tagErr_enc_lcsclienttype != nil {
		return nil, fmt.Errorf("encoding lcsClientType: %w", tagErr_enc_lcsclienttype)
	}
	enc_lcsclienttype = retagged_enc_lcsclienttype
	children = append(children, enc_lcsclienttype...)
	if v.LcsClientExternalID != nil {
		enc_lcsclientexternalid, err := v.LcsClientExternalID.MarshalBER()
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
		enc_lcsclientdialedbyms := ber.EncodeOctetString([]byte(*v.LcsClientDialedByMS))
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
		enc_lcsclientname, err := v.LcsClientName.MarshalBER()
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
		enc_lcsapn := ber.EncodeOctetString([]byte(*v.LcsAPN))
		retagged_enc_lcsapn, tagErr_enc_lcsapn := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 5, enc_lcsapn)
		if tagErr_enc_lcsapn != nil {
			return nil, fmt.Errorf("encoding lcsAPN: %w", tagErr_enc_lcsapn)
		}
		enc_lcsapn = retagged_enc_lcsapn
		children = append(children, enc_lcsapn...)
	}
	if v.LcsRequestorID != nil {
		enc_lcsrequestorid, err := v.LcsRequestorID.MarshalBER()
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

// MarshalDER encodes LCSClientID to DER format.
func (v *LCSClientID) MarshalDER() ([]byte, error) {
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
		return nil, fmt.Errorf("encoding LCSClientID as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes LCSClientID from BER/DER format.
func (v *LCSClientID) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding LCSClientID SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "LCSClientID", Cause: ber.ErrExtraData}
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
	decodedTag_lcsclienttype, n_lcsclienttype, rawVal_lcsclienttype, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding lcsClientType: %w", err)
	}
	if decodedTag_lcsclienttype.Class != tag.ClassContextSpecific || decodedTag_lcsclienttype.Number != 0 || decodedTag_lcsclienttype.Constructed != false {
		return fmt.Errorf("decoding lcsClientType: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_lcsclienttype)
	}
	decVal_lcsclienttype, intErr := ber.DecodeIntegerValue(rawVal_lcsclienttype)
	if intErr != nil {
		return fmt.Errorf("decoding lcsClientType: %w", intErr)
	}
	v.LcsClientType = LCSClientType(decVal_lcsclienttype)
	offset += n_lcsclienttype
	// Decode lcsClientExternalID
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
				decodedTag_lcsclientexternalid, n_lcsclientexternalid, rawVal_lcsclientexternalid, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding lcsClientExternalID: %w", err)
				}
				if decodedTag_lcsclientexternalid.Class != tag.ClassContextSpecific || decodedTag_lcsclientexternalid.Number != 1 || decodedTag_lcsclientexternalid.Constructed != true {
					return fmt.Errorf("decoding lcsClientExternalID: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_lcsclientexternalid)
				}
				reconstructed_lcsclientexternalid := ber.EncodeSequence(rawVal_lcsclientexternalid)
				var dec_lcsclientexternalid LCSClientExternalID
				if unmErr := dec_lcsclientexternalid.UnmarshalBER(reconstructed_lcsclientexternalid); unmErr != nil {
					return fmt.Errorf("decoding lcsClientExternalID: %w", unmErr)
				}
				v.LcsClientExternalID = &dec_lcsclientexternalid
				offset += n_lcsclientexternalid
			}
		}
	}
	// Decode lcsClientDialedByMS
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2 {
				decodedTag_lcsclientdialedbyms, n_lcsclientdialedbyms, rawVal_lcsclientdialedbyms, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding lcsClientDialedByMS: %w", err)
				}
				if decodedTag_lcsclientdialedbyms.Class != tag.ClassContextSpecific || decodedTag_lcsclientdialedbyms.Number != 2 {
					return fmt.Errorf("decoding lcsClientDialedByMS: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_lcsclientdialedbyms)
				}
				tmp_lcsclientdialedbyms := AddressString(rawVal_lcsclientdialedbyms)
				v.LcsClientDialedByMS = &tmp_lcsclientdialedbyms
				offset += n_lcsclientdialedbyms
			}
		}
	}
	// Decode lcsClientInternalID
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3 {
				decodedTag_lcsclientinternalid, n_lcsclientinternalid, rawVal_lcsclientinternalid, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding lcsClientInternalID: %w", err)
				}
				if decodedTag_lcsclientinternalid.Class != tag.ClassContextSpecific || decodedTag_lcsclientinternalid.Number != 3 || decodedTag_lcsclientinternalid.Constructed != false {
					return fmt.Errorf("decoding lcsClientInternalID: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_lcsclientinternalid)
				}
				decVal_lcsclientinternalid, intErr := ber.DecodeIntegerValue(rawVal_lcsclientinternalid)
				if intErr != nil {
					return fmt.Errorf("decoding lcsClientInternalID: %w", intErr)
				}
				tmp_lcsclientinternalid := LCSClientInternalID(decVal_lcsclientinternalid)
				v.LcsClientInternalID = &tmp_lcsclientinternalid
				offset += n_lcsclientinternalid
			}
		}
	}
	// Decode lcsClientName
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4 {
				decodedTag_lcsclientname, n_lcsclientname, rawVal_lcsclientname, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding lcsClientName: %w", err)
				}
				if decodedTag_lcsclientname.Class != tag.ClassContextSpecific || decodedTag_lcsclientname.Number != 4 || decodedTag_lcsclientname.Constructed != true {
					return fmt.Errorf("decoding lcsClientName: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_lcsclientname)
				}
				reconstructed_lcsclientname := ber.EncodeSequence(rawVal_lcsclientname)
				var dec_lcsclientname LCSClientName
				if unmErr := dec_lcsclientname.UnmarshalBER(reconstructed_lcsclientname); unmErr != nil {
					return fmt.Errorf("decoding lcsClientName: %w", unmErr)
				}
				v.LcsClientName = &dec_lcsclientname
				offset += n_lcsclientname
			}
		}
	}
	// Decode lcsAPN
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 5 {
				decodedTag_lcsapn, n_lcsapn, rawVal_lcsapn, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding lcsAPN: %w", err)
				}
				if decodedTag_lcsapn.Class != tag.ClassContextSpecific || decodedTag_lcsapn.Number != 5 {
					return fmt.Errorf("decoding lcsAPN: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_lcsapn)
				}
				tmp_lcsapn := APN(rawVal_lcsapn)
				v.LcsAPN = &tmp_lcsapn
				offset += n_lcsapn
			}
		}
	}
	// Decode lcsRequestorID
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 6 {
				decodedTag_lcsrequestorid, n_lcsrequestorid, rawVal_lcsrequestorid, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding lcsRequestorID: %w", err)
				}
				if decodedTag_lcsrequestorid.Class != tag.ClassContextSpecific || decodedTag_lcsrequestorid.Number != 6 || decodedTag_lcsrequestorid.Constructed != true {
					return fmt.Errorf("decoding lcsRequestorID: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_lcsrequestorid)
				}
				reconstructed_lcsrequestorid := ber.EncodeSequence(rawVal_lcsrequestorid)
				var dec_lcsrequestorid LCSRequestorID
				if unmErr := dec_lcsrequestorid.UnmarshalBER(reconstructed_lcsrequestorid); unmErr != nil {
					return fmt.Errorf("decoding lcsRequestorID: %w", unmErr)
				}
				v.LcsRequestorID = &dec_lcsrequestorid
				offset += n_lcsrequestorid
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "LCSClientID", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes LCSClientName to BER format.
func (v *LCSClientName) MarshalBER() ([]byte, error) {
	var children []byte
	enc_datacodingscheme := ber.EncodeOctetString([]byte(v.DataCodingScheme))
	retagged_enc_datacodingscheme, tagErr_enc_datacodingscheme := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_datacodingscheme)
	if tagErr_enc_datacodingscheme != nil {
		return nil, fmt.Errorf("encoding dataCodingScheme: %w", tagErr_enc_datacodingscheme)
	}
	enc_datacodingscheme = retagged_enc_datacodingscheme
	children = append(children, enc_datacodingscheme...)
	enc_namestring := ber.EncodeOctetString([]byte(v.NameString))
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

// MarshalDER encodes LCSClientName to DER format.
func (v *LCSClientName) MarshalDER() ([]byte, error) {
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
		return nil, fmt.Errorf("encoding LCSClientName as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes LCSClientName from BER/DER format.
func (v *LCSClientName) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding LCSClientName SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "LCSClientName", Cause: ber.ErrExtraData}
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
	decodedTag_datacodingscheme, n_datacodingscheme, rawVal_datacodingscheme, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding dataCodingScheme: %w", err)
	}
	if decodedTag_datacodingscheme.Class != tag.ClassContextSpecific || decodedTag_datacodingscheme.Number != 0 {
		return fmt.Errorf("decoding dataCodingScheme: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_datacodingscheme)
	}
	v.DataCodingScheme = USSDDataCodingScheme(rawVal_datacodingscheme)
	offset += n_datacodingscheme
	// Decode nameString
	if offset >= len(content) {
		return fmt.Errorf("missing required field nameString")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 2 {
			return fmt.Errorf("expected tag [%s %d] for nameString, got %s", "CONTEXT", 2, reqTag_)
		}
	}
	decodedTag_namestring, n_namestring, rawVal_namestring, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding nameString: %w", err)
	}
	if decodedTag_namestring.Class != tag.ClassContextSpecific || decodedTag_namestring.Number != 2 {
		return fmt.Errorf("decoding nameString: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_namestring)
	}
	v.NameString = NameString(rawVal_namestring)
	offset += n_namestring
	// Decode lcs-FormatIndicator
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3 {
				decodedTag_lcsformatindicator, n_lcsformatindicator, rawVal_lcsformatindicator, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding lcs-FormatIndicator: %w", err)
				}
				if decodedTag_lcsformatindicator.Class != tag.ClassContextSpecific || decodedTag_lcsformatindicator.Number != 3 || decodedTag_lcsformatindicator.Constructed != false {
					return fmt.Errorf("decoding lcs-FormatIndicator: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_lcsformatindicator)
				}
				decVal_lcsformatindicator, intErr := ber.DecodeIntegerValue(rawVal_lcsformatindicator)
				if intErr != nil {
					return fmt.Errorf("decoding lcs-FormatIndicator: %w", intErr)
				}
				tmp_lcsformatindicator := LCSFormatIndicator(decVal_lcsformatindicator)
				v.LcsFormatIndicator = &tmp_lcsformatindicator
				offset += n_lcsformatindicator
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "LCSClientName", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes LCSRequestorID to BER format.
func (v *LCSRequestorID) MarshalBER() ([]byte, error) {
	var children []byte
	enc_datacodingscheme := ber.EncodeOctetString([]byte(v.DataCodingScheme))
	retagged_enc_datacodingscheme, tagErr_enc_datacodingscheme := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_datacodingscheme)
	if tagErr_enc_datacodingscheme != nil {
		return nil, fmt.Errorf("encoding dataCodingScheme: %w", tagErr_enc_datacodingscheme)
	}
	enc_datacodingscheme = retagged_enc_datacodingscheme
	children = append(children, enc_datacodingscheme...)
	enc_requestoridstring := ber.EncodeOctetString([]byte(v.RequestorIDString))
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

// MarshalDER encodes LCSRequestorID to DER format.
func (v *LCSRequestorID) MarshalDER() ([]byte, error) {
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
		return nil, fmt.Errorf("encoding LCSRequestorID as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes LCSRequestorID from BER/DER format.
func (v *LCSRequestorID) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding LCSRequestorID SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "LCSRequestorID", Cause: ber.ErrExtraData}
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
	decodedTag_datacodingscheme, n_datacodingscheme, rawVal_datacodingscheme, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding dataCodingScheme: %w", err)
	}
	if decodedTag_datacodingscheme.Class != tag.ClassContextSpecific || decodedTag_datacodingscheme.Number != 0 {
		return fmt.Errorf("decoding dataCodingScheme: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_datacodingscheme)
	}
	v.DataCodingScheme = USSDDataCodingScheme(rawVal_datacodingscheme)
	offset += n_datacodingscheme
	// Decode requestorIDString
	if offset >= len(content) {
		return fmt.Errorf("missing required field requestorIDString")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 1 {
			return fmt.Errorf("expected tag [%s %d] for requestorIDString, got %s", "CONTEXT", 1, reqTag_)
		}
	}
	decodedTag_requestoridstring, n_requestoridstring, rawVal_requestoridstring, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding requestorIDString: %w", err)
	}
	if decodedTag_requestoridstring.Class != tag.ClassContextSpecific || decodedTag_requestoridstring.Number != 1 {
		return fmt.Errorf("decoding requestorIDString: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_requestoridstring)
	}
	v.RequestorIDString = RequestorIDString(rawVal_requestoridstring)
	offset += n_requestoridstring
	// Decode lcs-FormatIndicator
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2 {
				decodedTag_lcsformatindicator, n_lcsformatindicator, rawVal_lcsformatindicator, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding lcs-FormatIndicator: %w", err)
				}
				if decodedTag_lcsformatindicator.Class != tag.ClassContextSpecific || decodedTag_lcsformatindicator.Number != 2 || decodedTag_lcsformatindicator.Constructed != false {
					return fmt.Errorf("decoding lcs-FormatIndicator: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_lcsformatindicator)
				}
				decVal_lcsformatindicator, intErr := ber.DecodeIntegerValue(rawVal_lcsformatindicator)
				if intErr != nil {
					return fmt.Errorf("decoding lcs-FormatIndicator: %w", intErr)
				}
				tmp_lcsformatindicator := LCSFormatIndicator(decVal_lcsformatindicator)
				v.LcsFormatIndicator = &tmp_lcsformatindicator
				offset += n_lcsformatindicator
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "LCSRequestorID", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes LCSQoS to BER format.
func (v *LCSQoS) MarshalBER() ([]byte, error) {
	var children []byte
	if v.HorizontalAccuracy != nil {
		enc_horizontalaccuracy := ber.EncodeOctetString([]byte(*v.HorizontalAccuracy))
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
		enc_verticalaccuracy := ber.EncodeOctetString([]byte(*v.VerticalAccuracy))
		retagged_enc_verticalaccuracy, tagErr_enc_verticalaccuracy := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_verticalaccuracy)
		if tagErr_enc_verticalaccuracy != nil {
			return nil, fmt.Errorf("encoding vertical-accuracy: %w", tagErr_enc_verticalaccuracy)
		}
		enc_verticalaccuracy = retagged_enc_verticalaccuracy
		children = append(children, enc_verticalaccuracy...)
	}
	if v.ResponseTime != nil {
		enc_responsetime, err := v.ResponseTime.MarshalBER()
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
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalBER()
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

// MarshalDER encodes LCSQoS to DER format.
func (v *LCSQoS) MarshalDER() ([]byte, error) {
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
		return nil, fmt.Errorf("encoding LCSQoS as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes LCSQoS from BER/DER format.
func (v *LCSQoS) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding LCSQoS SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "LCSQoS", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode horizontal-accuracy
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
				decodedTag_horizontalaccuracy, n_horizontalaccuracy, rawVal_horizontalaccuracy, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding horizontal-accuracy: %w", err)
				}
				if decodedTag_horizontalaccuracy.Class != tag.ClassContextSpecific || decodedTag_horizontalaccuracy.Number != 0 {
					return fmt.Errorf("decoding horizontal-accuracy: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_horizontalaccuracy)
				}
				tmp_horizontalaccuracy := HorizontalAccuracy(rawVal_horizontalaccuracy)
				v.HorizontalAccuracy = &tmp_horizontalaccuracy
				offset += n_horizontalaccuracy
			}
		}
	}
	// Decode verticalCoordinateRequest
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
				decodedTag_verticalcoordinaterequest, n_verticalcoordinaterequest, rawVal_verticalcoordinaterequest, err := ber.DecodeTLV(content[offset:])
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
				offset += n_verticalcoordinaterequest
			}
		}
	}
	// Decode vertical-accuracy
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2 {
				decodedTag_verticalaccuracy, n_verticalaccuracy, rawVal_verticalaccuracy, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding vertical-accuracy: %w", err)
				}
				if decodedTag_verticalaccuracy.Class != tag.ClassContextSpecific || decodedTag_verticalaccuracy.Number != 2 {
					return fmt.Errorf("decoding vertical-accuracy: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_verticalaccuracy)
				}
				tmp_verticalaccuracy := VerticalAccuracy(rawVal_verticalaccuracy)
				v.VerticalAccuracy = &tmp_verticalaccuracy
				offset += n_verticalaccuracy
			}
		}
	}
	// Decode responseTime
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3 {
				decodedTag_responsetime, n_responsetime, rawVal_responsetime, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding responseTime: %w", err)
				}
				if decodedTag_responsetime.Class != tag.ClassContextSpecific || decodedTag_responsetime.Number != 3 || decodedTag_responsetime.Constructed != true {
					return fmt.Errorf("decoding responseTime: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_responsetime)
				}
				reconstructed_responsetime := ber.EncodeSequence(rawVal_responsetime)
				var dec_responsetime ResponseTime
				if unmErr := dec_responsetime.UnmarshalBER(reconstructed_responsetime); unmErr != nil {
					return fmt.Errorf("decoding responseTime: %w", unmErr)
				}
				v.ResponseTime = &dec_responsetime
				offset += n_responsetime
			}
		}
	}
	// Decode extensionContainer
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4 {
				decodedTag_extensioncontainer, n_extensioncontainer, rawVal_extensioncontainer, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding extensionContainer: %w", err)
				}
				if decodedTag_extensioncontainer.Class != tag.ClassContextSpecific || decodedTag_extensioncontainer.Number != 4 || decodedTag_extensioncontainer.Constructed != true {
					return fmt.Errorf("decoding extensionContainer: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_extensioncontainer)
				}
				reconstructed_extensioncontainer := ber.EncodeSequence(rawVal_extensioncontainer)
				var dec_extensioncontainer ExtensionContainer
				if unmErr := dec_extensioncontainer.UnmarshalBER(reconstructed_extensioncontainer); unmErr != nil {
					return fmt.Errorf("decoding extensionContainer: %w", unmErr)
				}
				v.ExtensionContainer = &dec_extensioncontainer
				offset += n_extensioncontainer
			}
		}
	}
	// Decode velocityRequest
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 5 {
				decodedTag_velocityrequest, n_velocityrequest, rawVal_velocityrequest, err := ber.DecodeTLV(content[offset:])
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
				offset += n_velocityrequest
			}
		}
	}
	// Decode lcs-qos-class
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 6 {
				decodedTag_lcsqosclass, n_lcsqosclass, rawVal_lcsqosclass, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding lcs-qos-class: %w", err)
				}
				if decodedTag_lcsqosclass.Class != tag.ClassContextSpecific || decodedTag_lcsqosclass.Number != 6 || decodedTag_lcsqosclass.Constructed != false {
					return fmt.Errorf("decoding lcs-qos-class: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_lcsqosclass)
				}
				decVal_lcsqosclass, intErr := ber.DecodeIntegerValue(rawVal_lcsqosclass)
				if intErr != nil {
					return fmt.Errorf("decoding lcs-qos-class: %w", intErr)
				}
				tmp_lcsqosclass := LCSQoSClass(decVal_lcsqosclass)
				v.LcsQosClass = &tmp_lcsqosclass
				offset += n_lcsqosclass
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "LCSQoS", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes ResponseTime to BER format.
func (v *ResponseTime) MarshalBER() ([]byte, error) {
	var children []byte
	enc_responsetimecategory := ber.EncodeEnumerated(int64(v.ResponseTimeCategory))
	children = append(children, enc_responsetimecategory...)
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

// MarshalDER encodes ResponseTime to DER format.
func (v *ResponseTime) MarshalDER() ([]byte, error) {
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
		return nil, fmt.Errorf("encoding ResponseTime as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes ResponseTime from BER/DER format.
func (v *ResponseTime) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding ResponseTime SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "ResponseTime", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode responseTimeCategory
	if offset >= len(content) {
		return fmt.Errorf("missing required field responseTimeCategory")
	}
	val_responsetimecategory, n, err := ber.DecodeInteger(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding responseTimeCategory: %w", err)
	}
	v.ResponseTimeCategory = ResponseTimeCategory(val_responsetimecategory)
	offset += n
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "ResponseTime", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes LCSCodeword to BER format.
func (v *LCSCodeword) MarshalBER() ([]byte, error) {
	var children []byte
	enc_datacodingscheme := ber.EncodeOctetString([]byte(v.DataCodingScheme))
	retagged_enc_datacodingscheme, tagErr_enc_datacodingscheme := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_datacodingscheme)
	if tagErr_enc_datacodingscheme != nil {
		return nil, fmt.Errorf("encoding dataCodingScheme: %w", tagErr_enc_datacodingscheme)
	}
	enc_datacodingscheme = retagged_enc_datacodingscheme
	children = append(children, enc_datacodingscheme...)
	enc_lcscodewordstring := ber.EncodeOctetString([]byte(v.LcsCodewordString))
	retagged_enc_lcscodewordstring, tagErr_enc_lcscodewordstring := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_lcscodewordstring)
	if tagErr_enc_lcscodewordstring != nil {
		return nil, fmt.Errorf("encoding lcsCodewordString: %w", tagErr_enc_lcscodewordstring)
	}
	enc_lcscodewordstring = retagged_enc_lcscodewordstring
	children = append(children, enc_lcscodewordstring...)
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

// MarshalDER encodes LCSCodeword to DER format.
func (v *LCSCodeword) MarshalDER() ([]byte, error) {
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
		return nil, fmt.Errorf("encoding LCSCodeword as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes LCSCodeword from BER/DER format.
func (v *LCSCodeword) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding LCSCodeword SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "LCSCodeword", Cause: ber.ErrExtraData}
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
	decodedTag_datacodingscheme, n_datacodingscheme, rawVal_datacodingscheme, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding dataCodingScheme: %w", err)
	}
	if decodedTag_datacodingscheme.Class != tag.ClassContextSpecific || decodedTag_datacodingscheme.Number != 0 {
		return fmt.Errorf("decoding dataCodingScheme: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_datacodingscheme)
	}
	v.DataCodingScheme = USSDDataCodingScheme(rawVal_datacodingscheme)
	offset += n_datacodingscheme
	// Decode lcsCodewordString
	if offset >= len(content) {
		return fmt.Errorf("missing required field lcsCodewordString")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 1 {
			return fmt.Errorf("expected tag [%s %d] for lcsCodewordString, got %s", "CONTEXT", 1, reqTag_)
		}
	}
	decodedTag_lcscodewordstring, n_lcscodewordstring, rawVal_lcscodewordstring, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding lcsCodewordString: %w", err)
	}
	if decodedTag_lcscodewordstring.Class != tag.ClassContextSpecific || decodedTag_lcscodewordstring.Number != 1 {
		return fmt.Errorf("decoding lcsCodewordString: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_lcscodewordstring)
	}
	v.LcsCodewordString = LCSCodewordString(rawVal_lcscodewordstring)
	offset += n_lcscodewordstring
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "LCSCodeword", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes LCSPrivacyCheck to BER format.
func (v *LCSPrivacyCheck) MarshalBER() ([]byte, error) {
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

// MarshalDER encodes LCSPrivacyCheck to DER format.
func (v *LCSPrivacyCheck) MarshalDER() ([]byte, error) {
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
		return nil, fmt.Errorf("encoding LCSPrivacyCheck as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes LCSPrivacyCheck from BER/DER format.
func (v *LCSPrivacyCheck) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding LCSPrivacyCheck SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "LCSPrivacyCheck", Cause: ber.ErrExtraData}
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
	decodedTag_callsessionunrelated, n_callsessionunrelated, rawVal_callsessionunrelated, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding callSessionUnrelated: %w", err)
	}
	if decodedTag_callsessionunrelated.Class != tag.ClassContextSpecific || decodedTag_callsessionunrelated.Number != 0 || decodedTag_callsessionunrelated.Constructed != false {
		return fmt.Errorf("decoding callSessionUnrelated: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_callsessionunrelated)
	}
	decVal_callsessionunrelated, intErr := ber.DecodeIntegerValue(rawVal_callsessionunrelated)
	if intErr != nil {
		return fmt.Errorf("decoding callSessionUnrelated: %w", intErr)
	}
	v.CallSessionUnrelated = PrivacyCheckRelatedAction(decVal_callsessionunrelated)
	offset += n_callsessionunrelated
	// Decode callSessionRelated
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
				decodedTag_callsessionrelated, n_callsessionrelated, rawVal_callsessionrelated, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding callSessionRelated: %w", err)
				}
				if decodedTag_callsessionrelated.Class != tag.ClassContextSpecific || decodedTag_callsessionrelated.Number != 1 || decodedTag_callsessionrelated.Constructed != false {
					return fmt.Errorf("decoding callSessionRelated: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_callsessionrelated)
				}
				decVal_callsessionrelated, intErr := ber.DecodeIntegerValue(rawVal_callsessionrelated)
				if intErr != nil {
					return fmt.Errorf("decoding callSessionRelated: %w", intErr)
				}
				tmp_callsessionrelated := PrivacyCheckRelatedAction(decVal_callsessionrelated)
				v.CallSessionRelated = &tmp_callsessionrelated
				offset += n_callsessionrelated
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "LCSPrivacyCheck", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes AreaEventInfo to BER format.
func (v *AreaEventInfo) MarshalBER() ([]byte, error) {
	var children []byte
	enc_areadefinition, err := v.AreaDefinition.MarshalBER()
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
		enc_intervaltime := ber.EncodeInteger(int64(*v.IntervalTime))
		retagged_enc_intervaltime, tagErr_enc_intervaltime := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_intervaltime)
		if tagErr_enc_intervaltime != nil {
			return nil, fmt.Errorf("encoding intervalTime: %w", tagErr_enc_intervaltime)
		}
		enc_intervaltime = retagged_enc_intervaltime
		children = append(children, enc_intervaltime...)
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

// MarshalDER encodes AreaEventInfo to DER format.
func (v *AreaEventInfo) MarshalDER() ([]byte, error) {
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
		return nil, fmt.Errorf("encoding AreaEventInfo as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes AreaEventInfo from BER/DER format.
func (v *AreaEventInfo) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding AreaEventInfo SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "AreaEventInfo", Cause: ber.ErrExtraData}
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
	decodedTag_areadefinition, n_areadefinition, rawVal_areadefinition, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding areaDefinition: %w", err)
	}
	if decodedTag_areadefinition.Class != tag.ClassContextSpecific || decodedTag_areadefinition.Number != 0 || decodedTag_areadefinition.Constructed != true {
		return fmt.Errorf("decoding areaDefinition: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_areadefinition)
	}
	reconstructed_areadefinition := ber.EncodeSequence(rawVal_areadefinition)
	if unmErr := v.AreaDefinition.UnmarshalBER(reconstructed_areadefinition); unmErr != nil {
		return fmt.Errorf("decoding areaDefinition: %w", unmErr)
	}
	offset += n_areadefinition
	// Decode occurrenceInfo
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
				decodedTag_occurrenceinfo, n_occurrenceinfo, rawVal_occurrenceinfo, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding occurrenceInfo: %w", err)
				}
				if decodedTag_occurrenceinfo.Class != tag.ClassContextSpecific || decodedTag_occurrenceinfo.Number != 1 || decodedTag_occurrenceinfo.Constructed != false {
					return fmt.Errorf("decoding occurrenceInfo: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_occurrenceinfo)
				}
				decVal_occurrenceinfo, intErr := ber.DecodeIntegerValue(rawVal_occurrenceinfo)
				if intErr != nil {
					return fmt.Errorf("decoding occurrenceInfo: %w", intErr)
				}
				tmp_occurrenceinfo := OccurrenceInfo(decVal_occurrenceinfo)
				v.OccurrenceInfo = &tmp_occurrenceinfo
				offset += n_occurrenceinfo
			}
		}
	}
	// Decode intervalTime
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2 {
				decodedTag_intervaltime, n_intervaltime, rawVal_intervaltime, err := ber.DecodeTLV(content[offset:])
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
				tmp_intervaltime := IntervalTime(decVal_intervaltime)
				v.IntervalTime = &tmp_intervaltime
				offset += n_intervaltime
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "AreaEventInfo", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes AreaDefinition to BER format.
func (v *AreaDefinition) MarshalBER() ([]byte, error) {
	var children []byte
	enc_arealist, err := MarshalBERAreaList(v.AreaList)
	if err != nil {
		return nil, fmt.Errorf("encoding areaList: %w", err)
	}
	if v.AreaListIndef_ {
		// Strip the outer SEQUENCE tag from marshalBER output to get raw children.
		_, _, seqContent_, tlvErr_ := ber.DecodeTLV(enc_arealist)
		if tlvErr_ != nil {
			return nil, tlvErr_
		}
		enc_arealist = ber.EncodeConstructedIndefinite(tag.Tag{Class: tag.ClassContextSpecific, Number: 0}, seqContent_)
	} else {
		retagged_enc_arealist, tagErr_enc_arealist := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_arealist)
		if tagErr_enc_arealist != nil {
			return nil, fmt.Errorf("encoding areaList: %w", tagErr_enc_arealist)
		}
		enc_arealist = retagged_enc_arealist
	}
	children = append(children, enc_arealist...)
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

// MarshalDER encodes AreaDefinition to DER format.
func (v *AreaDefinition) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// ITU-T X.690 (02/2021) Section 10.1 requires DER length forms to be definite.
	derValue := *v
	derValue.AreaListIndef_ = false
	v = &derValue
	encoded, err := v.MarshalBER()
	if err != nil {
		return nil, err
	}
	if err := ber.ValidateDERElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding AreaDefinition as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes AreaDefinition from BER/DER format.
func (v *AreaDefinition) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding AreaDefinition SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "AreaDefinition", Cause: ber.ErrExtraData}
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
	decodedTag_arealist, n_arealist, rawVal_arealist, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding areaList: %w", err)
	}
	if decodedTag_arealist.Class != tag.ClassContextSpecific || decodedTag_arealist.Number != 0 || decodedTag_arealist.Constructed != true {
		return fmt.Errorf("decoding areaList: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_arealist)
	}
	reconstructed_arealist := ber.EncodeSequence(rawVal_arealist)
	dec_arealist, unmErr := UnmarshalBERAreaList(reconstructed_arealist)
	if unmErr != nil {
		return fmt.Errorf("decoding areaList: %w", unmErr)
	}
	v.AreaList = dec_arealist
	{
		_, tagSz_, _ := ber.DecodeTag(content[offset:])
		if offset+tagSz_ < len(content) && content[offset+tagSz_] == 0x80 {
			v.AreaListIndef_ = true
		}
	}
	offset += n_arealist
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "AreaDefinition", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBERAreaList encodes a AreaList list to BER.
func MarshalBERAreaList(list AreaList) ([]byte, error) {
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

// UnmarshalBERAreaList decodes a AreaList list from BER.
func UnmarshalBERAreaList(data []byte) (AreaList, error) {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return nil, fmt.Errorf("decoding AreaList: %w", err)
	}
	if total != len(data) {
		return nil, &ber.DecodeError{Offset: total, TypeName: "AreaList", Cause: ber.ErrExtraData}
	}
	var result AreaList
	offset := 0
	for offset < len(content) {
		var elem Area
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

// MarshalBER encodes Area to BER format.
func (v *Area) MarshalBER() ([]byte, error) {
	var children []byte
	enc_areatype := ber.EncodeEnumerated(int64(v.AreaType))
	retagged_enc_areatype, tagErr_enc_areatype := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_areatype)
	if tagErr_enc_areatype != nil {
		return nil, fmt.Errorf("encoding areaType: %w", tagErr_enc_areatype)
	}
	enc_areatype = retagged_enc_areatype
	children = append(children, enc_areatype...)
	enc_areaidentification := ber.EncodeOctetString([]byte(v.AreaIdentification))
	retagged_enc_areaidentification, tagErr_enc_areaidentification := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_areaidentification)
	if tagErr_enc_areaidentification != nil {
		return nil, fmt.Errorf("encoding areaIdentification: %w", tagErr_enc_areaidentification)
	}
	enc_areaidentification = retagged_enc_areaidentification
	children = append(children, enc_areaidentification...)
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

// MarshalDER encodes Area to DER format.
func (v *Area) MarshalDER() ([]byte, error) {
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
		return nil, fmt.Errorf("encoding Area as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes Area from BER/DER format.
func (v *Area) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding Area SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "Area", Cause: ber.ErrExtraData}
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
	decodedTag_areatype, n_areatype, rawVal_areatype, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding areaType: %w", err)
	}
	if decodedTag_areatype.Class != tag.ClassContextSpecific || decodedTag_areatype.Number != 0 || decodedTag_areatype.Constructed != false {
		return fmt.Errorf("decoding areaType: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_areatype)
	}
	decVal_areatype, intErr := ber.DecodeIntegerValue(rawVal_areatype)
	if intErr != nil {
		return fmt.Errorf("decoding areaType: %w", intErr)
	}
	v.AreaType = AreaType(decVal_areatype)
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
	decodedTag_areaidentification, n_areaidentification, rawVal_areaidentification, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding areaIdentification: %w", err)
	}
	if decodedTag_areaidentification.Class != tag.ClassContextSpecific || decodedTag_areaidentification.Number != 1 {
		return fmt.Errorf("decoding areaIdentification: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_areaidentification)
	}
	v.AreaIdentification = AreaIdentification(rawVal_areaidentification)
	offset += n_areaidentification
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "Area", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes PeriodicLDRInfo to BER format.
func (v *PeriodicLDRInfo) MarshalBER() ([]byte, error) {
	var children []byte
	enc_reportingamount := ber.EncodeInteger(int64(v.ReportingAmount))
	children = append(children, enc_reportingamount...)
	enc_reportinginterval := ber.EncodeInteger(int64(v.ReportingInterval))
	children = append(children, enc_reportinginterval...)
	if v.ReportingOptionMilliseconds != nil {
		enc_reportingoptionmilliseconds, err := v.ReportingOptionMilliseconds.MarshalBER()
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

// MarshalDER encodes PeriodicLDRInfo to DER format.
func (v *PeriodicLDRInfo) MarshalDER() ([]byte, error) {
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
		return nil, fmt.Errorf("encoding PeriodicLDRInfo as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes PeriodicLDRInfo from BER/DER format.
func (v *PeriodicLDRInfo) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding PeriodicLDRInfo SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "PeriodicLDRInfo", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode reportingAmount
	if offset >= len(content) {
		return fmt.Errorf("missing required field reportingAmount")
	}
	val_reportingamount, n, err := ber.DecodeInteger(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding reportingAmount: %w", err)
	}
	v.ReportingAmount = ReportingAmount(val_reportingamount)
	offset += n
	// Decode reportingInterval
	if offset >= len(content) {
		return fmt.Errorf("missing required field reportingInterval")
	}
	val_reportinginterval, n, err := ber.DecodeInteger(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding reportingInterval: %w", err)
	}
	v.ReportingInterval = ReportingInterval(val_reportinginterval)
	offset += n
	// Decode reportingOptionMilliseconds
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
				decodedTag_reportingoptionmilliseconds, n_reportingoptionmilliseconds, rawVal_reportingoptionmilliseconds, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding reportingOptionMilliseconds: %w", err)
				}
				if decodedTag_reportingoptionmilliseconds.Class != tag.ClassContextSpecific || decodedTag_reportingoptionmilliseconds.Number != 0 || decodedTag_reportingoptionmilliseconds.Constructed != true {
					return fmt.Errorf("decoding reportingOptionMilliseconds: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_reportingoptionmilliseconds)
				}
				reconstructed_reportingoptionmilliseconds := ber.EncodeSequence(rawVal_reportingoptionmilliseconds)
				var dec_reportingoptionmilliseconds ReportingOptionMilliseconds
				if unmErr := dec_reportingoptionmilliseconds.UnmarshalBER(reconstructed_reportingoptionmilliseconds); unmErr != nil {
					return fmt.Errorf("decoding reportingOptionMilliseconds: %w", unmErr)
				}
				v.ReportingOptionMilliseconds = &dec_reportingoptionmilliseconds
				offset += n_reportingoptionmilliseconds
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "PeriodicLDRInfo", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes ReportingOptionMilliseconds to BER format.
func (v *ReportingOptionMilliseconds) MarshalBER() ([]byte, error) {
	var children []byte
	enc_reportingamountmilliseconds := ber.EncodeInteger(int64(v.ReportingAmountMilliseconds))
	children = append(children, enc_reportingamountmilliseconds...)
	enc_reportingintervalmilliseconds := ber.EncodeInteger(int64(v.ReportingIntervalMilliseconds))
	children = append(children, enc_reportingintervalmilliseconds...)
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

// MarshalDER encodes ReportingOptionMilliseconds to DER format.
func (v *ReportingOptionMilliseconds) MarshalDER() ([]byte, error) {
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
		return nil, fmt.Errorf("encoding ReportingOptionMilliseconds as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes ReportingOptionMilliseconds from BER/DER format.
func (v *ReportingOptionMilliseconds) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding ReportingOptionMilliseconds SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "ReportingOptionMilliseconds", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode reportingAmountMilliseconds
	if offset >= len(content) {
		return fmt.Errorf("missing required field reportingAmountMilliseconds")
	}
	val_reportingamountmilliseconds, n, err := ber.DecodeInteger(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding reportingAmountMilliseconds: %w", err)
	}
	v.ReportingAmountMilliseconds = ReportingAmountMilliseconds(val_reportingamountmilliseconds)
	offset += n
	// Decode reportingIntervalMilliseconds
	if offset >= len(content) {
		return fmt.Errorf("missing required field reportingIntervalMilliseconds")
	}
	val_reportingintervalmilliseconds, n, err := ber.DecodeInteger(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding reportingIntervalMilliseconds: %w", err)
	}
	v.ReportingIntervalMilliseconds = ReportingIntervalMilliseconds(val_reportingintervalmilliseconds)
	offset += n
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "ReportingOptionMilliseconds", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes ReportingPLMNList to BER format.
func (v *ReportingPLMNList) MarshalBER() ([]byte, error) {
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
	enc_plmnlist, err := MarshalBERPLMNList(v.PlmnList)
	if err != nil {
		return nil, fmt.Errorf("encoding plmn-List: %w", err)
	}
	if v.PlmnListIndef_ {
		// Strip the outer SEQUENCE tag from marshalBER output to get raw children.
		_, _, seqContent_, tlvErr_ := ber.DecodeTLV(enc_plmnlist)
		if tlvErr_ != nil {
			return nil, tlvErr_
		}
		enc_plmnlist = ber.EncodeConstructedIndefinite(tag.Tag{Class: tag.ClassContextSpecific, Number: 1}, seqContent_)
	} else {
		retagged_enc_plmnlist, tagErr_enc_plmnlist := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_plmnlist)
		if tagErr_enc_plmnlist != nil {
			return nil, fmt.Errorf("encoding plmn-List: %w", tagErr_enc_plmnlist)
		}
		enc_plmnlist = retagged_enc_plmnlist
	}
	children = append(children, enc_plmnlist...)
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

// MarshalDER encodes ReportingPLMNList to DER format.
func (v *ReportingPLMNList) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// ITU-T X.690 (02/2021) Section 10.1 requires DER length forms to be definite.
	derValue := *v
	derValue.PlmnListIndef_ = false
	v = &derValue
	encoded, err := v.MarshalBER()
	if err != nil {
		return nil, err
	}
	if err := ber.ValidateDERElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding ReportingPLMNList as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes ReportingPLMNList from BER/DER format.
func (v *ReportingPLMNList) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding ReportingPLMNList SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "ReportingPLMNList", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode plmn-ListPrioritized
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
				decodedTag_plmnlistprioritized, n_plmnlistprioritized, rawVal_plmnlistprioritized, err := ber.DecodeTLV(content[offset:])
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
	decodedTag_plmnlist, n_plmnlist, rawVal_plmnlist, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding plmn-List: %w", err)
	}
	if decodedTag_plmnlist.Class != tag.ClassContextSpecific || decodedTag_plmnlist.Number != 1 || decodedTag_plmnlist.Constructed != true {
		return fmt.Errorf("decoding plmn-List: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_plmnlist)
	}
	reconstructed_plmnlist := ber.EncodeSequence(rawVal_plmnlist)
	dec_plmnlist, unmErr := UnmarshalBERPLMNList(reconstructed_plmnlist)
	if unmErr != nil {
		return fmt.Errorf("decoding plmn-List: %w", unmErr)
	}
	v.PlmnList = dec_plmnlist
	{
		_, tagSz_, _ := ber.DecodeTag(content[offset:])
		if offset+tagSz_ < len(content) && content[offset+tagSz_] == 0x80 {
			v.PlmnListIndef_ = true
		}
	}
	offset += n_plmnlist
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "ReportingPLMNList", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBERPLMNList encodes a PLMNList list to BER.
func MarshalBERPLMNList(list PLMNList) ([]byte, error) {
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

// UnmarshalBERPLMNList decodes a PLMNList list from BER.
func UnmarshalBERPLMNList(data []byte) (PLMNList, error) {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return nil, fmt.Errorf("decoding PLMNList: %w", err)
	}
	if total != len(data) {
		return nil, &ber.DecodeError{Offset: total, TypeName: "PLMNList", Cause: ber.ErrExtraData}
	}
	var result PLMNList
	offset := 0
	for offset < len(content) {
		var elem ReportingPLMN
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

// MarshalBER encodes ReportingPLMN to BER format.
func (v *ReportingPLMN) MarshalBER() ([]byte, error) {
	var children []byte
	enc_plmnid := ber.EncodeOctetString([]byte(v.PlmnId))
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

// MarshalDER encodes ReportingPLMN to DER format.
func (v *ReportingPLMN) MarshalDER() ([]byte, error) {
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
		return nil, fmt.Errorf("encoding ReportingPLMN as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes ReportingPLMN from BER/DER format.
func (v *ReportingPLMN) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding ReportingPLMN SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "ReportingPLMN", Cause: ber.ErrExtraData}
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
	decodedTag_plmnid, n_plmnid, rawVal_plmnid, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding plmn-Id: %w", err)
	}
	if decodedTag_plmnid.Class != tag.ClassContextSpecific || decodedTag_plmnid.Number != 0 {
		return fmt.Errorf("decoding plmn-Id: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_plmnid)
	}
	v.PlmnId = PLMNId(rawVal_plmnid)
	offset += n_plmnid
	// Decode ran-Technology
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
				decodedTag_rantechnology, n_rantechnology, rawVal_rantechnology, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding ran-Technology: %w", err)
				}
				if decodedTag_rantechnology.Class != tag.ClassContextSpecific || decodedTag_rantechnology.Number != 1 || decodedTag_rantechnology.Constructed != false {
					return fmt.Errorf("decoding ran-Technology: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_rantechnology)
				}
				decVal_rantechnology, intErr := ber.DecodeIntegerValue(rawVal_rantechnology)
				if intErr != nil {
					return fmt.Errorf("decoding ran-Technology: %w", intErr)
				}
				tmp_rantechnology := RANTechnology(decVal_rantechnology)
				v.RanTechnology = &tmp_rantechnology
				offset += n_rantechnology
			}
		}
	}
	// Decode ran-PeriodicLocationSupport
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2 {
				decodedTag_ranperiodiclocationsupport, n_ranperiodiclocationsupport, rawVal_ranperiodiclocationsupport, err := ber.DecodeTLV(content[offset:])
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
				offset += n_ranperiodiclocationsupport
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "ReportingPLMN", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes ProvideSubscriberLocationRes to BER format.
func (v *ProvideSubscriberLocationRes) MarshalBER() ([]byte, error) {
	var children []byte
	enc_locationestimate := ber.EncodeOctetString([]byte(v.LocationEstimate))
	children = append(children, enc_locationestimate...)
	if v.AgeOfLocationEstimate != nil {
		enc_ageoflocationestimate := ber.EncodeInteger(int64(*v.AgeOfLocationEstimate))
		retagged_enc_ageoflocationestimate, tagErr_enc_ageoflocationestimate := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_ageoflocationestimate)
		if tagErr_enc_ageoflocationestimate != nil {
			return nil, fmt.Errorf("encoding ageOfLocationEstimate: %w", tagErr_enc_ageoflocationestimate)
		}
		enc_ageoflocationestimate = retagged_enc_ageoflocationestimate
		children = append(children, enc_ageoflocationestimate...)
	}
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalBER()
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
		enc_addlocationestimate := ber.EncodeOctetString([]byte(*v.AddLocationEstimate))
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
		enc_geranpositioningdata := ber.EncodeOctetString([]byte(*v.GeranPositioningData))
		retagged_enc_geranpositioningdata, tagErr_enc_geranpositioningdata := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, enc_geranpositioningdata)
		if tagErr_enc_geranpositioningdata != nil {
			return nil, fmt.Errorf("encoding geranPositioningData: %w", tagErr_enc_geranpositioningdata)
		}
		enc_geranpositioningdata = retagged_enc_geranpositioningdata
		children = append(children, enc_geranpositioningdata...)
	}
	if v.UtranPositioningData != nil {
		enc_utranpositioningdata := ber.EncodeOctetString([]byte(*v.UtranPositioningData))
		retagged_enc_utranpositioningdata, tagErr_enc_utranpositioningdata := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 5, enc_utranpositioningdata)
		if tagErr_enc_utranpositioningdata != nil {
			return nil, fmt.Errorf("encoding utranPositioningData: %w", tagErr_enc_utranpositioningdata)
		}
		enc_utranpositioningdata = retagged_enc_utranpositioningdata
		children = append(children, enc_utranpositioningdata...)
	}
	if v.CellIdOrSai != nil {
		enc_cellidorsai, err := v.CellIdOrSai.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding cellIdOrSai: %w", err)
		}
		enc_cellidorsai = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 6, enc_cellidorsai)
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
		enc_velocityestimate := ber.EncodeOctetString([]byte(*v.VelocityEstimate))
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
		enc_gerangansspositioningdata := ber.EncodeOctetString([]byte(*v.GeranGANSSpositioningData))
		retagged_enc_gerangansspositioningdata, tagErr_enc_gerangansspositioningdata := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 11, enc_gerangansspositioningdata)
		if tagErr_enc_gerangansspositioningdata != nil {
			return nil, fmt.Errorf("encoding geranGANSSpositioningData: %w", tagErr_enc_gerangansspositioningdata)
		}
		enc_gerangansspositioningdata = retagged_enc_gerangansspositioningdata
		children = append(children, enc_gerangansspositioningdata...)
	}
	if v.UtranGANSSpositioningData != nil {
		enc_utrangansspositioningdata := ber.EncodeOctetString([]byte(*v.UtranGANSSpositioningData))
		retagged_enc_utrangansspositioningdata, tagErr_enc_utrangansspositioningdata := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 12, enc_utrangansspositioningdata)
		if tagErr_enc_utrangansspositioningdata != nil {
			return nil, fmt.Errorf("encoding utranGANSSpositioningData: %w", tagErr_enc_utrangansspositioningdata)
		}
		enc_utrangansspositioningdata = retagged_enc_utrangansspositioningdata
		children = append(children, enc_utrangansspositioningdata...)
	}
	if v.TargetServingNodeForHandover != nil {
		enc_targetservingnodeforhandover, err := v.TargetServingNodeForHandover.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding targetServingNodeForHandover: %w", err)
		}
		enc_targetservingnodeforhandover = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 13, enc_targetservingnodeforhandover)
		children = append(children, enc_targetservingnodeforhandover...)
	}
	if v.UtranAdditionalPositioningData != nil {
		enc_utranadditionalpositioningdata := ber.EncodeOctetString([]byte(*v.UtranAdditionalPositioningData))
		retagged_enc_utranadditionalpositioningdata, tagErr_enc_utranadditionalpositioningdata := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 14, enc_utranadditionalpositioningdata)
		if tagErr_enc_utranadditionalpositioningdata != nil {
			return nil, fmt.Errorf("encoding utranAdditionalPositioningData: %w", tagErr_enc_utranadditionalpositioningdata)
		}
		enc_utranadditionalpositioningdata = retagged_enc_utranadditionalpositioningdata
		children = append(children, enc_utranadditionalpositioningdata...)
	}
	if v.UtranBaroPressureMeas != nil {
		enc_utranbaropressuremeas := ber.EncodeInteger(int64(*v.UtranBaroPressureMeas))
		retagged_enc_utranbaropressuremeas, tagErr_enc_utranbaropressuremeas := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 15, enc_utranbaropressuremeas)
		if tagErr_enc_utranbaropressuremeas != nil {
			return nil, fmt.Errorf("encoding utranBaroPressureMeas: %w", tagErr_enc_utranbaropressuremeas)
		}
		enc_utranbaropressuremeas = retagged_enc_utranbaropressuremeas
		children = append(children, enc_utranbaropressuremeas...)
	}
	if v.UtranCivicAddress != nil {
		enc_utrancivicaddress := ber.EncodeOctetString([]byte(*v.UtranCivicAddress))
		retagged_enc_utrancivicaddress, tagErr_enc_utrancivicaddress := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 16, enc_utrancivicaddress)
		if tagErr_enc_utrancivicaddress != nil {
			return nil, fmt.Errorf("encoding utranCivicAddress: %w", tagErr_enc_utrancivicaddress)
		}
		enc_utrancivicaddress = retagged_enc_utrancivicaddress
		children = append(children, enc_utrancivicaddress...)
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

// MarshalDER encodes ProvideSubscriberLocationRes to DER format.
func (v *ProvideSubscriberLocationRes) MarshalDER() ([]byte, error) {
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
		return nil, fmt.Errorf("encoding ProvideSubscriberLocationRes as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes ProvideSubscriberLocationRes from BER/DER format.
func (v *ProvideSubscriberLocationRes) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding ProvideSubscriberLocationRes SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "ProvideSubscriberLocationRes", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode locationEstimate
	if offset >= len(content) {
		return fmt.Errorf("missing required field locationEstimate")
	}
	val_locationestimate, n, err := ber.DecodeOctetString(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding locationEstimate: %w", err)
	}
	v.LocationEstimate = ExtGeographicalInformation(val_locationestimate)
	offset += n
	// Decode ageOfLocationEstimate
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
				decodedTag_ageoflocationestimate, n_ageoflocationestimate, rawVal_ageoflocationestimate, err := ber.DecodeTLV(content[offset:])
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
				tmp_ageoflocationestimate := AgeOfLocationInformation(decVal_ageoflocationestimate)
				v.AgeOfLocationEstimate = &tmp_ageoflocationestimate
				offset += n_ageoflocationestimate
			}
		}
	}
	// Decode extensionContainer
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
				decodedTag_extensioncontainer, n_extensioncontainer, rawVal_extensioncontainer, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding extensionContainer: %w", err)
				}
				if decodedTag_extensioncontainer.Class != tag.ClassContextSpecific || decodedTag_extensioncontainer.Number != 1 || decodedTag_extensioncontainer.Constructed != true {
					return fmt.Errorf("decoding extensionContainer: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_extensioncontainer)
				}
				reconstructed_extensioncontainer := ber.EncodeSequence(rawVal_extensioncontainer)
				var dec_extensioncontainer ExtensionContainer
				if unmErr := dec_extensioncontainer.UnmarshalBER(reconstructed_extensioncontainer); unmErr != nil {
					return fmt.Errorf("decoding extensionContainer: %w", unmErr)
				}
				v.ExtensionContainer = &dec_extensioncontainer
				offset += n_extensioncontainer
			}
		}
	}
	// Decode add-LocationEstimate
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2 {
				decodedTag_addlocationestimate, n_addlocationestimate, rawVal_addlocationestimate, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding add-LocationEstimate: %w", err)
				}
				if decodedTag_addlocationestimate.Class != tag.ClassContextSpecific || decodedTag_addlocationestimate.Number != 2 {
					return fmt.Errorf("decoding add-LocationEstimate: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_addlocationestimate)
				}
				tmp_addlocationestimate := AddGeographicalInformation(rawVal_addlocationestimate)
				v.AddLocationEstimate = &tmp_addlocationestimate
				offset += n_addlocationestimate
			}
		}
	}
	// Decode deferredmt-lrResponseIndicator
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3 {
				decodedTag_deferredmtlrresponseindicator, n_deferredmtlrresponseindicator, rawVal_deferredmtlrresponseindicator, err := ber.DecodeTLV(content[offset:])
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
				offset += n_deferredmtlrresponseindicator
			}
		}
	}
	// Decode geranPositioningData
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4 {
				decodedTag_geranpositioningdata, n_geranpositioningdata, rawVal_geranpositioningdata, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding geranPositioningData: %w", err)
				}
				if decodedTag_geranpositioningdata.Class != tag.ClassContextSpecific || decodedTag_geranpositioningdata.Number != 4 {
					return fmt.Errorf("decoding geranPositioningData: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_geranpositioningdata)
				}
				tmp_geranpositioningdata := PositioningDataInformation(rawVal_geranpositioningdata)
				v.GeranPositioningData = &tmp_geranpositioningdata
				offset += n_geranpositioningdata
			}
		}
	}
	// Decode utranPositioningData
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 5 {
				decodedTag_utranpositioningdata, n_utranpositioningdata, rawVal_utranpositioningdata, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding utranPositioningData: %w", err)
				}
				if decodedTag_utranpositioningdata.Class != tag.ClassContextSpecific || decodedTag_utranpositioningdata.Number != 5 {
					return fmt.Errorf("decoding utranPositioningData: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_utranpositioningdata)
				}
				tmp_utranpositioningdata := UtranPositioningDataInfo(rawVal_utranpositioningdata)
				v.UtranPositioningData = &tmp_utranpositioningdata
				offset += n_utranpositioningdata
			}
		}
	}
	// Decode cellIdOrSai
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 6 {
				decodedTag_cellidorsai, n_cellidorsai, innerData_cellidorsai, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding cellIdOrSai: %w", err)
				}
				if decodedTag_cellidorsai.Class != tag.ClassContextSpecific || decodedTag_cellidorsai.Number != 6 || decodedTag_cellidorsai.Constructed != true {
					return fmt.Errorf("decoding cellIdOrSai: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_cellidorsai)
				}
				// Decode inner value from explicit tag wrapper
				var dec_cellidorsai CellGlobalIdOrServiceAreaIdOrLAI
				if unmErr := dec_cellidorsai.UnmarshalBER(innerData_cellidorsai); unmErr != nil {
					return fmt.Errorf("decoding cellIdOrSai: %w", unmErr)
				}
				v.CellIdOrSai = &dec_cellidorsai
				offset += n_cellidorsai
			}
		}
	}
	// Decode sai-Present
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 7 {
				decodedTag_saipresent, n_saipresent, rawVal_saipresent, err := ber.DecodeTLV(content[offset:])
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
				offset += n_saipresent
			}
		}
	}
	// Decode accuracyFulfilmentIndicator
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 8 {
				decodedTag_accuracyfulfilmentindicator, n_accuracyfulfilmentindicator, rawVal_accuracyfulfilmentindicator, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding accuracyFulfilmentIndicator: %w", err)
				}
				if decodedTag_accuracyfulfilmentindicator.Class != tag.ClassContextSpecific || decodedTag_accuracyfulfilmentindicator.Number != 8 || decodedTag_accuracyfulfilmentindicator.Constructed != false {
					return fmt.Errorf("decoding accuracyFulfilmentIndicator: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_accuracyfulfilmentindicator)
				}
				decVal_accuracyfulfilmentindicator, intErr := ber.DecodeIntegerValue(rawVal_accuracyfulfilmentindicator)
				if intErr != nil {
					return fmt.Errorf("decoding accuracyFulfilmentIndicator: %w", intErr)
				}
				tmp_accuracyfulfilmentindicator := AccuracyFulfilmentIndicator(decVal_accuracyfulfilmentindicator)
				v.AccuracyFulfilmentIndicator = &tmp_accuracyfulfilmentindicator
				offset += n_accuracyfulfilmentindicator
			}
		}
	}
	// Decode velocityEstimate
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 9 {
				decodedTag_velocityestimate, n_velocityestimate, rawVal_velocityestimate, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding velocityEstimate: %w", err)
				}
				if decodedTag_velocityestimate.Class != tag.ClassContextSpecific || decodedTag_velocityestimate.Number != 9 {
					return fmt.Errorf("decoding velocityEstimate: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_velocityestimate)
				}
				tmp_velocityestimate := VelocityEstimate(rawVal_velocityestimate)
				v.VelocityEstimate = &tmp_velocityestimate
				offset += n_velocityestimate
			}
		}
	}
	// Decode mo-lrShortCircuitIndicator
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 10 {
				decodedTag_molrshortcircuitindicator, n_molrshortcircuitindicator, rawVal_molrshortcircuitindicator, err := ber.DecodeTLV(content[offset:])
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
				offset += n_molrshortcircuitindicator
			}
		}
	}
	// Decode geranGANSSpositioningData
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 11 {
				decodedTag_gerangansspositioningdata, n_gerangansspositioningdata, rawVal_gerangansspositioningdata, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding geranGANSSpositioningData: %w", err)
				}
				if decodedTag_gerangansspositioningdata.Class != tag.ClassContextSpecific || decodedTag_gerangansspositioningdata.Number != 11 {
					return fmt.Errorf("decoding geranGANSSpositioningData: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_gerangansspositioningdata)
				}
				tmp_gerangansspositioningdata := GeranGANSSpositioningData(rawVal_gerangansspositioningdata)
				v.GeranGANSSpositioningData = &tmp_gerangansspositioningdata
				offset += n_gerangansspositioningdata
			}
		}
	}
	// Decode utranGANSSpositioningData
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 12 {
				decodedTag_utrangansspositioningdata, n_utrangansspositioningdata, rawVal_utrangansspositioningdata, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding utranGANSSpositioningData: %w", err)
				}
				if decodedTag_utrangansspositioningdata.Class != tag.ClassContextSpecific || decodedTag_utrangansspositioningdata.Number != 12 {
					return fmt.Errorf("decoding utranGANSSpositioningData: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_utrangansspositioningdata)
				}
				tmp_utrangansspositioningdata := UtranGANSSpositioningData(rawVal_utrangansspositioningdata)
				v.UtranGANSSpositioningData = &tmp_utrangansspositioningdata
				offset += n_utrangansspositioningdata
			}
		}
	}
	// Decode targetServingNodeForHandover
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 13 {
				decodedTag_targetservingnodeforhandover, n_targetservingnodeforhandover, innerData_targetservingnodeforhandover, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding targetServingNodeForHandover: %w", err)
				}
				if decodedTag_targetservingnodeforhandover.Class != tag.ClassContextSpecific || decodedTag_targetservingnodeforhandover.Number != 13 || decodedTag_targetservingnodeforhandover.Constructed != true {
					return fmt.Errorf("decoding targetServingNodeForHandover: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_targetservingnodeforhandover)
				}
				// Decode inner value from explicit tag wrapper
				var dec_targetservingnodeforhandover ServingNodeAddress
				if unmErr := dec_targetservingnodeforhandover.UnmarshalBER(innerData_targetservingnodeforhandover); unmErr != nil {
					return fmt.Errorf("decoding targetServingNodeForHandover: %w", unmErr)
				}
				v.TargetServingNodeForHandover = &dec_targetservingnodeforhandover
				offset += n_targetservingnodeforhandover
			}
		}
	}
	// Decode utranAdditionalPositioningData
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 14 {
				decodedTag_utranadditionalpositioningdata, n_utranadditionalpositioningdata, rawVal_utranadditionalpositioningdata, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding utranAdditionalPositioningData: %w", err)
				}
				if decodedTag_utranadditionalpositioningdata.Class != tag.ClassContextSpecific || decodedTag_utranadditionalpositioningdata.Number != 14 {
					return fmt.Errorf("decoding utranAdditionalPositioningData: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_utranadditionalpositioningdata)
				}
				tmp_utranadditionalpositioningdata := UtranAdditionalPositioningData(rawVal_utranadditionalpositioningdata)
				v.UtranAdditionalPositioningData = &tmp_utranadditionalpositioningdata
				offset += n_utranadditionalpositioningdata
			}
		}
	}
	// Decode utranBaroPressureMeas
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 15 {
				decodedTag_utranbaropressuremeas, n_utranbaropressuremeas, rawVal_utranbaropressuremeas, err := ber.DecodeTLV(content[offset:])
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
				tmp_utranbaropressuremeas := UtranBaroPressureMeas(decVal_utranbaropressuremeas)
				v.UtranBaroPressureMeas = &tmp_utranbaropressuremeas
				offset += n_utranbaropressuremeas
			}
		}
	}
	// Decode utranCivicAddress
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 16 {
				decodedTag_utrancivicaddress, n_utrancivicaddress, rawVal_utrancivicaddress, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding utranCivicAddress: %w", err)
				}
				if decodedTag_utrancivicaddress.Class != tag.ClassContextSpecific || decodedTag_utrancivicaddress.Number != 16 {
					return fmt.Errorf("decoding utranCivicAddress: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_utrancivicaddress)
				}
				tmp_utrancivicaddress := UtranCivicAddress(rawVal_utrancivicaddress)
				v.UtranCivicAddress = &tmp_utrancivicaddress
				offset += n_utrancivicaddress
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "ProvideSubscriberLocationRes", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes SubscriberLocationReportArg to BER format.
func (v *SubscriberLocationReportArg) MarshalBER() ([]byte, error) {
	var children []byte
	enc_lcsevent := ber.EncodeEnumerated(int64(v.LcsEvent))
	children = append(children, enc_lcsevent...)
	enc_lcsclientid, err := v.LcsClientID.MarshalBER()
	if err != nil {
		return nil, fmt.Errorf("encoding lcs-ClientID: %w", err)
	}
	children = append(children, enc_lcsclientid...)
	enc_lcslocationinfo, err := v.LcsLocationInfo.MarshalBER()
	if err != nil {
		return nil, fmt.Errorf("encoding lcsLocationInfo: %w", err)
	}
	children = append(children, enc_lcslocationinfo...)
	if v.Msisdn != nil {
		enc_msisdn := ber.EncodeOctetString([]byte(*v.Msisdn))
		retagged_enc_msisdn, tagErr_enc_msisdn := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_msisdn)
		if tagErr_enc_msisdn != nil {
			return nil, fmt.Errorf("encoding msisdn: %w", tagErr_enc_msisdn)
		}
		enc_msisdn = retagged_enc_msisdn
		children = append(children, enc_msisdn...)
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
	if v.Imei != nil {
		enc_imei := ber.EncodeOctetString([]byte(*v.Imei))
		retagged_enc_imei, tagErr_enc_imei := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_imei)
		if tagErr_enc_imei != nil {
			return nil, fmt.Errorf("encoding imei: %w", tagErr_enc_imei)
		}
		enc_imei = retagged_enc_imei
		children = append(children, enc_imei...)
	}
	if v.NaESRD != nil {
		enc_naesrd := ber.EncodeOctetString([]byte(*v.NaESRD))
		retagged_enc_naesrd, tagErr_enc_naesrd := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, enc_naesrd)
		if tagErr_enc_naesrd != nil {
			return nil, fmt.Errorf("encoding na-ESRD: %w", tagErr_enc_naesrd)
		}
		enc_naesrd = retagged_enc_naesrd
		children = append(children, enc_naesrd...)
	}
	if v.NaESRK != nil {
		enc_naesrk := ber.EncodeOctetString([]byte(*v.NaESRK))
		retagged_enc_naesrk, tagErr_enc_naesrk := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, enc_naesrk)
		if tagErr_enc_naesrk != nil {
			return nil, fmt.Errorf("encoding na-ESRK: %w", tagErr_enc_naesrk)
		}
		enc_naesrk = retagged_enc_naesrk
		children = append(children, enc_naesrk...)
	}
	if v.LocationEstimate != nil {
		enc_locationestimate := ber.EncodeOctetString([]byte(*v.LocationEstimate))
		retagged_enc_locationestimate, tagErr_enc_locationestimate := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 5, enc_locationestimate)
		if tagErr_enc_locationestimate != nil {
			return nil, fmt.Errorf("encoding locationEstimate: %w", tagErr_enc_locationestimate)
		}
		enc_locationestimate = retagged_enc_locationestimate
		children = append(children, enc_locationestimate...)
	}
	if v.AgeOfLocationEstimate != nil {
		enc_ageoflocationestimate := ber.EncodeInteger(int64(*v.AgeOfLocationEstimate))
		retagged_enc_ageoflocationestimate, tagErr_enc_ageoflocationestimate := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 6, enc_ageoflocationestimate)
		if tagErr_enc_ageoflocationestimate != nil {
			return nil, fmt.Errorf("encoding ageOfLocationEstimate: %w", tagErr_enc_ageoflocationestimate)
		}
		enc_ageoflocationestimate = retagged_enc_ageoflocationestimate
		children = append(children, enc_ageoflocationestimate...)
	}
	if v.SlrArgExtensionContainer != nil {
		enc_slrargextensioncontainer, err := v.SlrArgExtensionContainer.MarshalBER()
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
		enc_addlocationestimate := ber.EncodeOctetString([]byte(*v.AddLocationEstimate))
		retagged_enc_addlocationestimate, tagErr_enc_addlocationestimate := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 8, enc_addlocationestimate)
		if tagErr_enc_addlocationestimate != nil {
			return nil, fmt.Errorf("encoding add-LocationEstimate: %w", tagErr_enc_addlocationestimate)
		}
		enc_addlocationestimate = retagged_enc_addlocationestimate
		children = append(children, enc_addlocationestimate...)
	}
	if v.DeferredmtLrData != nil {
		enc_deferredmtlrdata, err := v.DeferredmtLrData.MarshalBER()
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
		enc_lcsreferencenumber := ber.EncodeOctetString([]byte(*v.LcsReferenceNumber))
		retagged_enc_lcsreferencenumber, tagErr_enc_lcsreferencenumber := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 10, enc_lcsreferencenumber)
		if tagErr_enc_lcsreferencenumber != nil {
			return nil, fmt.Errorf("encoding lcs-ReferenceNumber: %w", tagErr_enc_lcsreferencenumber)
		}
		enc_lcsreferencenumber = retagged_enc_lcsreferencenumber
		children = append(children, enc_lcsreferencenumber...)
	}
	if v.GeranPositioningData != nil {
		enc_geranpositioningdata := ber.EncodeOctetString([]byte(*v.GeranPositioningData))
		retagged_enc_geranpositioningdata, tagErr_enc_geranpositioningdata := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 11, enc_geranpositioningdata)
		if tagErr_enc_geranpositioningdata != nil {
			return nil, fmt.Errorf("encoding geranPositioningData: %w", tagErr_enc_geranpositioningdata)
		}
		enc_geranpositioningdata = retagged_enc_geranpositioningdata
		children = append(children, enc_geranpositioningdata...)
	}
	if v.UtranPositioningData != nil {
		enc_utranpositioningdata := ber.EncodeOctetString([]byte(*v.UtranPositioningData))
		retagged_enc_utranpositioningdata, tagErr_enc_utranpositioningdata := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 12, enc_utranpositioningdata)
		if tagErr_enc_utranpositioningdata != nil {
			return nil, fmt.Errorf("encoding utranPositioningData: %w", tagErr_enc_utranpositioningdata)
		}
		enc_utranpositioningdata = retagged_enc_utranpositioningdata
		children = append(children, enc_utranpositioningdata...)
	}
	if v.CellIdOrSai != nil {
		enc_cellidorsai, err := v.CellIdOrSai.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding cellIdOrSai: %w", err)
		}
		enc_cellidorsai = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 13, enc_cellidorsai)
		children = append(children, enc_cellidorsai...)
	}
	if v.HGmlcAddress != nil {
		enc_hgmlcaddress := ber.EncodeOctetString([]byte(*v.HGmlcAddress))
		retagged_enc_hgmlcaddress, tagErr_enc_hgmlcaddress := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 14, enc_hgmlcaddress)
		if tagErr_enc_hgmlcaddress != nil {
			return nil, fmt.Errorf("encoding h-gmlc-Address: %w", tagErr_enc_hgmlcaddress)
		}
		enc_hgmlcaddress = retagged_enc_hgmlcaddress
		children = append(children, enc_hgmlcaddress...)
	}
	if v.LcsServiceTypeID != nil {
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
		enc_velocityestimate := ber.EncodeOctetString([]byte(*v.VelocityEstimate))
		retagged_enc_velocityestimate, tagErr_enc_velocityestimate := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 20, enc_velocityestimate)
		if tagErr_enc_velocityestimate != nil {
			return nil, fmt.Errorf("encoding velocityEstimate: %w", tagErr_enc_velocityestimate)
		}
		enc_velocityestimate = retagged_enc_velocityestimate
		children = append(children, enc_velocityestimate...)
	}
	if v.SequenceNumber != nil {
		enc_sequencenumber := ber.EncodeInteger(int64(*v.SequenceNumber))
		retagged_enc_sequencenumber, tagErr_enc_sequencenumber := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 21, enc_sequencenumber)
		if tagErr_enc_sequencenumber != nil {
			return nil, fmt.Errorf("encoding sequenceNumber: %w", tagErr_enc_sequencenumber)
		}
		enc_sequencenumber = retagged_enc_sequencenumber
		children = append(children, enc_sequencenumber...)
	}
	if v.PeriodicLDRInfo != nil {
		enc_periodicldrinfo, err := v.PeriodicLDRInfo.MarshalBER()
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
		enc_gerangansspositioningdata := ber.EncodeOctetString([]byte(*v.GeranGANSSpositioningData))
		retagged_enc_gerangansspositioningdata, tagErr_enc_gerangansspositioningdata := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 24, enc_gerangansspositioningdata)
		if tagErr_enc_gerangansspositioningdata != nil {
			return nil, fmt.Errorf("encoding geranGANSSpositioningData: %w", tagErr_enc_gerangansspositioningdata)
		}
		enc_gerangansspositioningdata = retagged_enc_gerangansspositioningdata
		children = append(children, enc_gerangansspositioningdata...)
	}
	if v.UtranGANSSpositioningData != nil {
		enc_utrangansspositioningdata := ber.EncodeOctetString([]byte(*v.UtranGANSSpositioningData))
		retagged_enc_utrangansspositioningdata, tagErr_enc_utrangansspositioningdata := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 25, enc_utrangansspositioningdata)
		if tagErr_enc_utrangansspositioningdata != nil {
			return nil, fmt.Errorf("encoding utranGANSSpositioningData: %w", tagErr_enc_utrangansspositioningdata)
		}
		enc_utrangansspositioningdata = retagged_enc_utrangansspositioningdata
		children = append(children, enc_utrangansspositioningdata...)
	}
	if v.TargetServingNodeForHandover != nil {
		enc_targetservingnodeforhandover, err := v.TargetServingNodeForHandover.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding targetServingNodeForHandover: %w", err)
		}
		enc_targetservingnodeforhandover = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 26, enc_targetservingnodeforhandover)
		children = append(children, enc_targetservingnodeforhandover...)
	}
	if v.UtranAdditionalPositioningData != nil {
		enc_utranadditionalpositioningdata := ber.EncodeOctetString([]byte(*v.UtranAdditionalPositioningData))
		retagged_enc_utranadditionalpositioningdata, tagErr_enc_utranadditionalpositioningdata := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 27, enc_utranadditionalpositioningdata)
		if tagErr_enc_utranadditionalpositioningdata != nil {
			return nil, fmt.Errorf("encoding utranAdditionalPositioningData: %w", tagErr_enc_utranadditionalpositioningdata)
		}
		enc_utranadditionalpositioningdata = retagged_enc_utranadditionalpositioningdata
		children = append(children, enc_utranadditionalpositioningdata...)
	}
	if v.UtranBaroPressureMeas != nil {
		enc_utranbaropressuremeas := ber.EncodeInteger(int64(*v.UtranBaroPressureMeas))
		retagged_enc_utranbaropressuremeas, tagErr_enc_utranbaropressuremeas := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 28, enc_utranbaropressuremeas)
		if tagErr_enc_utranbaropressuremeas != nil {
			return nil, fmt.Errorf("encoding utranBaroPressureMeas: %w", tagErr_enc_utranbaropressuremeas)
		}
		enc_utranbaropressuremeas = retagged_enc_utranbaropressuremeas
		children = append(children, enc_utranbaropressuremeas...)
	}
	if v.UtranCivicAddress != nil {
		enc_utrancivicaddress := ber.EncodeOctetString([]byte(*v.UtranCivicAddress))
		retagged_enc_utrancivicaddress, tagErr_enc_utrancivicaddress := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 29, enc_utrancivicaddress)
		if tagErr_enc_utrancivicaddress != nil {
			return nil, fmt.Errorf("encoding utranCivicAddress: %w", tagErr_enc_utrancivicaddress)
		}
		enc_utrancivicaddress = retagged_enc_utrancivicaddress
		children = append(children, enc_utrancivicaddress...)
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

// MarshalDER encodes SubscriberLocationReportArg to DER format.
func (v *SubscriberLocationReportArg) MarshalDER() ([]byte, error) {
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
		return nil, fmt.Errorf("encoding SubscriberLocationReportArg as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes SubscriberLocationReportArg from BER/DER format.
func (v *SubscriberLocationReportArg) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding SubscriberLocationReportArg SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "SubscriberLocationReportArg", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode lcs-Event
	if offset >= len(content) {
		return fmt.Errorf("missing required field lcs-Event")
	}
	val_lcsevent, n, err := ber.DecodeInteger(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding lcs-Event: %w", err)
	}
	v.LcsEvent = LCSEvent(val_lcsevent)
	offset += n
	// Decode lcs-ClientID
	if offset >= len(content) {
		return fmt.Errorf("missing required field lcs-ClientID")
	}
	// Decode nested SEQUENCE (LCSClientID)
	_, n_lcsclientid, _, tlvErr_lcsclientid := ber.DecodeTLV(content[offset:])
	if tlvErr_lcsclientid != nil {
		return fmt.Errorf("decoding lcs-ClientID: %w", tlvErr_lcsclientid)
	}
	if unmErr := v.LcsClientID.UnmarshalBER(content[offset : offset+n_lcsclientid]); unmErr != nil {
		return fmt.Errorf("decoding lcs-ClientID: %w", unmErr)
	}
	offset += n_lcsclientid
	// Decode lcsLocationInfo
	if offset >= len(content) {
		return fmt.Errorf("missing required field lcsLocationInfo")
	}
	// Decode nested SEQUENCE (LCSLocationInfo)
	_, n_lcslocationinfo, _, tlvErr_lcslocationinfo := ber.DecodeTLV(content[offset:])
	if tlvErr_lcslocationinfo != nil {
		return fmt.Errorf("decoding lcsLocationInfo: %w", tlvErr_lcslocationinfo)
	}
	if unmErr := v.LcsLocationInfo.UnmarshalBER(content[offset : offset+n_lcslocationinfo]); unmErr != nil {
		return fmt.Errorf("decoding lcsLocationInfo: %w", unmErr)
	}
	offset += n_lcslocationinfo
	// Decode msisdn
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
				decodedTag_msisdn, n_msisdn, rawVal_msisdn, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding msisdn: %w", err)
				}
				if decodedTag_msisdn.Class != tag.ClassContextSpecific || decodedTag_msisdn.Number != 0 {
					return fmt.Errorf("decoding msisdn: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_msisdn)
				}
				tmp_msisdn := ISDNAddressString(rawVal_msisdn)
				v.Msisdn = &tmp_msisdn
				offset += n_msisdn
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
				tmp_imsi := IMSI(rawVal_imsi)
				v.Imsi = &tmp_imsi
				offset += n_imsi
			}
		}
	}
	// Decode imei
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2 {
				decodedTag_imei, n_imei, rawVal_imei, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding imei: %w", err)
				}
				if decodedTag_imei.Class != tag.ClassContextSpecific || decodedTag_imei.Number != 2 {
					return fmt.Errorf("decoding imei: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_imei)
				}
				tmp_imei := IMEI(rawVal_imei)
				v.Imei = &tmp_imei
				offset += n_imei
			}
		}
	}
	// Decode na-ESRD
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3 {
				decodedTag_naesrd, n_naesrd, rawVal_naesrd, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding na-ESRD: %w", err)
				}
				if decodedTag_naesrd.Class != tag.ClassContextSpecific || decodedTag_naesrd.Number != 3 {
					return fmt.Errorf("decoding na-ESRD: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_naesrd)
				}
				tmp_naesrd := ISDNAddressString(rawVal_naesrd)
				v.NaESRD = &tmp_naesrd
				offset += n_naesrd
			}
		}
	}
	// Decode na-ESRK
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4 {
				decodedTag_naesrk, n_naesrk, rawVal_naesrk, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding na-ESRK: %w", err)
				}
				if decodedTag_naesrk.Class != tag.ClassContextSpecific || decodedTag_naesrk.Number != 4 {
					return fmt.Errorf("decoding na-ESRK: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_naesrk)
				}
				tmp_naesrk := ISDNAddressString(rawVal_naesrk)
				v.NaESRK = &tmp_naesrk
				offset += n_naesrk
			}
		}
	}
	// Decode locationEstimate
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 5 {
				decodedTag_locationestimate, n_locationestimate, rawVal_locationestimate, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding locationEstimate: %w", err)
				}
				if decodedTag_locationestimate.Class != tag.ClassContextSpecific || decodedTag_locationestimate.Number != 5 {
					return fmt.Errorf("decoding locationEstimate: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_locationestimate)
				}
				tmp_locationestimate := ExtGeographicalInformation(rawVal_locationestimate)
				v.LocationEstimate = &tmp_locationestimate
				offset += n_locationestimate
			}
		}
	}
	// Decode ageOfLocationEstimate
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 6 {
				decodedTag_ageoflocationestimate, n_ageoflocationestimate, rawVal_ageoflocationestimate, err := ber.DecodeTLV(content[offset:])
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
				tmp_ageoflocationestimate := AgeOfLocationInformation(decVal_ageoflocationestimate)
				v.AgeOfLocationEstimate = &tmp_ageoflocationestimate
				offset += n_ageoflocationestimate
			}
		}
	}
	// Decode slr-ArgExtensionContainer
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 7 {
				decodedTag_slrargextensioncontainer, n_slrargextensioncontainer, rawVal_slrargextensioncontainer, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding slr-ArgExtensionContainer: %w", err)
				}
				if decodedTag_slrargextensioncontainer.Class != tag.ClassContextSpecific || decodedTag_slrargextensioncontainer.Number != 7 || decodedTag_slrargextensioncontainer.Constructed != true {
					return fmt.Errorf("decoding slr-ArgExtensionContainer: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_slrargextensioncontainer)
				}
				reconstructed_slrargextensioncontainer := ber.EncodeSequence(rawVal_slrargextensioncontainer)
				var dec_slrargextensioncontainer SLRArgExtensionContainer
				if unmErr := dec_slrargextensioncontainer.UnmarshalBER(reconstructed_slrargextensioncontainer); unmErr != nil {
					return fmt.Errorf("decoding slr-ArgExtensionContainer: %w", unmErr)
				}
				v.SlrArgExtensionContainer = &dec_slrargextensioncontainer
				offset += n_slrargextensioncontainer
			}
		}
	}
	// Decode add-LocationEstimate
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 8 {
				decodedTag_addlocationestimate, n_addlocationestimate, rawVal_addlocationestimate, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding add-LocationEstimate: %w", err)
				}
				if decodedTag_addlocationestimate.Class != tag.ClassContextSpecific || decodedTag_addlocationestimate.Number != 8 {
					return fmt.Errorf("decoding add-LocationEstimate: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_addlocationestimate)
				}
				tmp_addlocationestimate := AddGeographicalInformation(rawVal_addlocationestimate)
				v.AddLocationEstimate = &tmp_addlocationestimate
				offset += n_addlocationestimate
			}
		}
	}
	// Decode deferredmt-lrData
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 9 {
				decodedTag_deferredmtlrdata, n_deferredmtlrdata, rawVal_deferredmtlrdata, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding deferredmt-lrData: %w", err)
				}
				if decodedTag_deferredmtlrdata.Class != tag.ClassContextSpecific || decodedTag_deferredmtlrdata.Number != 9 || decodedTag_deferredmtlrdata.Constructed != true {
					return fmt.Errorf("decoding deferredmt-lrData: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_deferredmtlrdata)
				}
				reconstructed_deferredmtlrdata := ber.EncodeSequence(rawVal_deferredmtlrdata)
				var dec_deferredmtlrdata DeferredmtLrData
				if unmErr := dec_deferredmtlrdata.UnmarshalBER(reconstructed_deferredmtlrdata); unmErr != nil {
					return fmt.Errorf("decoding deferredmt-lrData: %w", unmErr)
				}
				v.DeferredmtLrData = &dec_deferredmtlrdata
				offset += n_deferredmtlrdata
			}
		}
	}
	// Decode lcs-ReferenceNumber
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 10 {
				decodedTag_lcsreferencenumber, n_lcsreferencenumber, rawVal_lcsreferencenumber, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding lcs-ReferenceNumber: %w", err)
				}
				if decodedTag_lcsreferencenumber.Class != tag.ClassContextSpecific || decodedTag_lcsreferencenumber.Number != 10 {
					return fmt.Errorf("decoding lcs-ReferenceNumber: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_lcsreferencenumber)
				}
				tmp_lcsreferencenumber := LCSReferenceNumber(rawVal_lcsreferencenumber)
				v.LcsReferenceNumber = &tmp_lcsreferencenumber
				offset += n_lcsreferencenumber
			}
		}
	}
	// Decode geranPositioningData
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 11 {
				decodedTag_geranpositioningdata, n_geranpositioningdata, rawVal_geranpositioningdata, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding geranPositioningData: %w", err)
				}
				if decodedTag_geranpositioningdata.Class != tag.ClassContextSpecific || decodedTag_geranpositioningdata.Number != 11 {
					return fmt.Errorf("decoding geranPositioningData: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_geranpositioningdata)
				}
				tmp_geranpositioningdata := PositioningDataInformation(rawVal_geranpositioningdata)
				v.GeranPositioningData = &tmp_geranpositioningdata
				offset += n_geranpositioningdata
			}
		}
	}
	// Decode utranPositioningData
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 12 {
				decodedTag_utranpositioningdata, n_utranpositioningdata, rawVal_utranpositioningdata, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding utranPositioningData: %w", err)
				}
				if decodedTag_utranpositioningdata.Class != tag.ClassContextSpecific || decodedTag_utranpositioningdata.Number != 12 {
					return fmt.Errorf("decoding utranPositioningData: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_utranpositioningdata)
				}
				tmp_utranpositioningdata := UtranPositioningDataInfo(rawVal_utranpositioningdata)
				v.UtranPositioningData = &tmp_utranpositioningdata
				offset += n_utranpositioningdata
			}
		}
	}
	// Decode cellIdOrSai
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 13 {
				decodedTag_cellidorsai, n_cellidorsai, innerData_cellidorsai, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding cellIdOrSai: %w", err)
				}
				if decodedTag_cellidorsai.Class != tag.ClassContextSpecific || decodedTag_cellidorsai.Number != 13 || decodedTag_cellidorsai.Constructed != true {
					return fmt.Errorf("decoding cellIdOrSai: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_cellidorsai)
				}
				// Decode inner value from explicit tag wrapper
				var dec_cellidorsai CellGlobalIdOrServiceAreaIdOrLAI
				if unmErr := dec_cellidorsai.UnmarshalBER(innerData_cellidorsai); unmErr != nil {
					return fmt.Errorf("decoding cellIdOrSai: %w", unmErr)
				}
				v.CellIdOrSai = &dec_cellidorsai
				offset += n_cellidorsai
			}
		}
	}
	// Decode h-gmlc-Address
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 14 {
				decodedTag_hgmlcaddress, n_hgmlcaddress, rawVal_hgmlcaddress, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding h-gmlc-Address: %w", err)
				}
				if decodedTag_hgmlcaddress.Class != tag.ClassContextSpecific || decodedTag_hgmlcaddress.Number != 14 {
					return fmt.Errorf("decoding h-gmlc-Address: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_hgmlcaddress)
				}
				tmp_hgmlcaddress := GSNAddress(rawVal_hgmlcaddress)
				v.HGmlcAddress = &tmp_hgmlcaddress
				offset += n_hgmlcaddress
			}
		}
	}
	// Decode lcsServiceTypeID
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 15 {
				decodedTag_lcsservicetypeid, n_lcsservicetypeid, rawVal_lcsservicetypeid, err := ber.DecodeTLV(content[offset:])
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
				tmp_lcsservicetypeid := LCSServiceTypeID(decVal_lcsservicetypeid)
				v.LcsServiceTypeID = &tmp_lcsservicetypeid
				offset += n_lcsservicetypeid
			}
		}
	}
	// Decode sai-Present
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 17 {
				decodedTag_saipresent, n_saipresent, rawVal_saipresent, err := ber.DecodeTLV(content[offset:])
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
				offset += n_saipresent
			}
		}
	}
	// Decode pseudonymIndicator
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 18 {
				decodedTag_pseudonymindicator, n_pseudonymindicator, rawVal_pseudonymindicator, err := ber.DecodeTLV(content[offset:])
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
				offset += n_pseudonymindicator
			}
		}
	}
	// Decode accuracyFulfilmentIndicator
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 19 {
				decodedTag_accuracyfulfilmentindicator, n_accuracyfulfilmentindicator, rawVal_accuracyfulfilmentindicator, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding accuracyFulfilmentIndicator: %w", err)
				}
				if decodedTag_accuracyfulfilmentindicator.Class != tag.ClassContextSpecific || decodedTag_accuracyfulfilmentindicator.Number != 19 || decodedTag_accuracyfulfilmentindicator.Constructed != false {
					return fmt.Errorf("decoding accuracyFulfilmentIndicator: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_accuracyfulfilmentindicator)
				}
				decVal_accuracyfulfilmentindicator, intErr := ber.DecodeIntegerValue(rawVal_accuracyfulfilmentindicator)
				if intErr != nil {
					return fmt.Errorf("decoding accuracyFulfilmentIndicator: %w", intErr)
				}
				tmp_accuracyfulfilmentindicator := AccuracyFulfilmentIndicator(decVal_accuracyfulfilmentindicator)
				v.AccuracyFulfilmentIndicator = &tmp_accuracyfulfilmentindicator
				offset += n_accuracyfulfilmentindicator
			}
		}
	}
	// Decode velocityEstimate
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 20 {
				decodedTag_velocityestimate, n_velocityestimate, rawVal_velocityestimate, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding velocityEstimate: %w", err)
				}
				if decodedTag_velocityestimate.Class != tag.ClassContextSpecific || decodedTag_velocityestimate.Number != 20 {
					return fmt.Errorf("decoding velocityEstimate: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_velocityestimate)
				}
				tmp_velocityestimate := VelocityEstimate(rawVal_velocityestimate)
				v.VelocityEstimate = &tmp_velocityestimate
				offset += n_velocityestimate
			}
		}
	}
	// Decode sequenceNumber
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 21 {
				decodedTag_sequencenumber, n_sequencenumber, rawVal_sequencenumber, err := ber.DecodeTLV(content[offset:])
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
				tmp_sequencenumber := SequenceNumber(decVal_sequencenumber)
				v.SequenceNumber = &tmp_sequencenumber
				offset += n_sequencenumber
			}
		}
	}
	// Decode periodicLDRInfo
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 22 {
				decodedTag_periodicldrinfo, n_periodicldrinfo, rawVal_periodicldrinfo, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding periodicLDRInfo: %w", err)
				}
				if decodedTag_periodicldrinfo.Class != tag.ClassContextSpecific || decodedTag_periodicldrinfo.Number != 22 || decodedTag_periodicldrinfo.Constructed != true {
					return fmt.Errorf("decoding periodicLDRInfo: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_periodicldrinfo)
				}
				reconstructed_periodicldrinfo := ber.EncodeSequence(rawVal_periodicldrinfo)
				var dec_periodicldrinfo PeriodicLDRInfo
				if unmErr := dec_periodicldrinfo.UnmarshalBER(reconstructed_periodicldrinfo); unmErr != nil {
					return fmt.Errorf("decoding periodicLDRInfo: %w", unmErr)
				}
				v.PeriodicLDRInfo = &dec_periodicldrinfo
				offset += n_periodicldrinfo
			}
		}
	}
	// Decode mo-lrShortCircuitIndicator
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 23 {
				decodedTag_molrshortcircuitindicator, n_molrshortcircuitindicator, rawVal_molrshortcircuitindicator, err := ber.DecodeTLV(content[offset:])
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
				offset += n_molrshortcircuitindicator
			}
		}
	}
	// Decode geranGANSSpositioningData
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 24 {
				decodedTag_gerangansspositioningdata, n_gerangansspositioningdata, rawVal_gerangansspositioningdata, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding geranGANSSpositioningData: %w", err)
				}
				if decodedTag_gerangansspositioningdata.Class != tag.ClassContextSpecific || decodedTag_gerangansspositioningdata.Number != 24 {
					return fmt.Errorf("decoding geranGANSSpositioningData: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_gerangansspositioningdata)
				}
				tmp_gerangansspositioningdata := GeranGANSSpositioningData(rawVal_gerangansspositioningdata)
				v.GeranGANSSpositioningData = &tmp_gerangansspositioningdata
				offset += n_gerangansspositioningdata
			}
		}
	}
	// Decode utranGANSSpositioningData
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 25 {
				decodedTag_utrangansspositioningdata, n_utrangansspositioningdata, rawVal_utrangansspositioningdata, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding utranGANSSpositioningData: %w", err)
				}
				if decodedTag_utrangansspositioningdata.Class != tag.ClassContextSpecific || decodedTag_utrangansspositioningdata.Number != 25 {
					return fmt.Errorf("decoding utranGANSSpositioningData: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_utrangansspositioningdata)
				}
				tmp_utrangansspositioningdata := UtranGANSSpositioningData(rawVal_utrangansspositioningdata)
				v.UtranGANSSpositioningData = &tmp_utrangansspositioningdata
				offset += n_utrangansspositioningdata
			}
		}
	}
	// Decode targetServingNodeForHandover
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 26 {
				decodedTag_targetservingnodeforhandover, n_targetservingnodeforhandover, innerData_targetservingnodeforhandover, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding targetServingNodeForHandover: %w", err)
				}
				if decodedTag_targetservingnodeforhandover.Class != tag.ClassContextSpecific || decodedTag_targetservingnodeforhandover.Number != 26 || decodedTag_targetservingnodeforhandover.Constructed != true {
					return fmt.Errorf("decoding targetServingNodeForHandover: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_targetservingnodeforhandover)
				}
				// Decode inner value from explicit tag wrapper
				var dec_targetservingnodeforhandover ServingNodeAddress
				if unmErr := dec_targetservingnodeforhandover.UnmarshalBER(innerData_targetservingnodeforhandover); unmErr != nil {
					return fmt.Errorf("decoding targetServingNodeForHandover: %w", unmErr)
				}
				v.TargetServingNodeForHandover = &dec_targetservingnodeforhandover
				offset += n_targetservingnodeforhandover
			}
		}
	}
	// Decode utranAdditionalPositioningData
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 27 {
				decodedTag_utranadditionalpositioningdata, n_utranadditionalpositioningdata, rawVal_utranadditionalpositioningdata, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding utranAdditionalPositioningData: %w", err)
				}
				if decodedTag_utranadditionalpositioningdata.Class != tag.ClassContextSpecific || decodedTag_utranadditionalpositioningdata.Number != 27 {
					return fmt.Errorf("decoding utranAdditionalPositioningData: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_utranadditionalpositioningdata)
				}
				tmp_utranadditionalpositioningdata := UtranAdditionalPositioningData(rawVal_utranadditionalpositioningdata)
				v.UtranAdditionalPositioningData = &tmp_utranadditionalpositioningdata
				offset += n_utranadditionalpositioningdata
			}
		}
	}
	// Decode utranBaroPressureMeas
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 28 {
				decodedTag_utranbaropressuremeas, n_utranbaropressuremeas, rawVal_utranbaropressuremeas, err := ber.DecodeTLV(content[offset:])
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
				tmp_utranbaropressuremeas := UtranBaroPressureMeas(decVal_utranbaropressuremeas)
				v.UtranBaroPressureMeas = &tmp_utranbaropressuremeas
				offset += n_utranbaropressuremeas
			}
		}
	}
	// Decode utranCivicAddress
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 29 {
				decodedTag_utrancivicaddress, n_utrancivicaddress, rawVal_utrancivicaddress, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding utranCivicAddress: %w", err)
				}
				if decodedTag_utrancivicaddress.Class != tag.ClassContextSpecific || decodedTag_utrancivicaddress.Number != 29 {
					return fmt.Errorf("decoding utranCivicAddress: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_utrancivicaddress)
				}
				tmp_utrancivicaddress := UtranCivicAddress(rawVal_utrancivicaddress)
				v.UtranCivicAddress = &tmp_utrancivicaddress
				offset += n_utrancivicaddress
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "SubscriberLocationReportArg", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes DeferredmtLrData to BER format.
func (v *DeferredmtLrData) MarshalBER() ([]byte, error) {
	var children []byte
	enc_deferredlocationeventtype := ber.EncodeBitString(v.DeferredLocationEventType.Bytes, (8-(v.DeferredLocationEventType.BitLength%8))%8)
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
		enc_lcslocationinfo, err := v.LcsLocationInfo.MarshalBER()
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

// MarshalDER encodes DeferredmtLrData to DER format.
func (v *DeferredmtLrData) MarshalDER() ([]byte, error) {
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
		return nil, fmt.Errorf("encoding DeferredmtLrData as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes DeferredmtLrData from BER/DER format.
func (v *DeferredmtLrData) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding DeferredmtLrData SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "DeferredmtLrData", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode deferredLocationEventType
	if offset >= len(content) {
		return fmt.Errorf("missing required field deferredLocationEventType")
	}
	bsBytes_deferredlocationeventtype, bsUnused_deferredlocationeventtype, n, err := ber.DecodeBitString(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding deferredLocationEventType: %w", err)
	}
	v.DeferredLocationEventType = runtime.BitString{Bytes: bsBytes_deferredlocationeventtype, BitLength: len(bsBytes_deferredlocationeventtype)*8 - bsUnused_deferredlocationeventtype}
	offset += n
	// Decode terminationCause
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
				decodedTag_terminationcause, n_terminationcause, rawVal_terminationcause, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding terminationCause: %w", err)
				}
				if decodedTag_terminationcause.Class != tag.ClassContextSpecific || decodedTag_terminationcause.Number != 0 || decodedTag_terminationcause.Constructed != false {
					return fmt.Errorf("decoding terminationCause: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_terminationcause)
				}
				decVal_terminationcause, intErr := ber.DecodeIntegerValue(rawVal_terminationcause)
				if intErr != nil {
					return fmt.Errorf("decoding terminationCause: %w", intErr)
				}
				tmp_terminationcause := TerminationCause(decVal_terminationcause)
				v.TerminationCause = &tmp_terminationcause
				offset += n_terminationcause
			}
		}
	}
	// Decode lcsLocationInfo
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
				decodedTag_lcslocationinfo, n_lcslocationinfo, rawVal_lcslocationinfo, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding lcsLocationInfo: %w", err)
				}
				if decodedTag_lcslocationinfo.Class != tag.ClassContextSpecific || decodedTag_lcslocationinfo.Number != 1 || decodedTag_lcslocationinfo.Constructed != true {
					return fmt.Errorf("decoding lcsLocationInfo: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_lcslocationinfo)
				}
				reconstructed_lcslocationinfo := ber.EncodeSequence(rawVal_lcslocationinfo)
				var dec_lcslocationinfo LCSLocationInfo
				if unmErr := dec_lcslocationinfo.UnmarshalBER(reconstructed_lcslocationinfo); unmErr != nil {
					return fmt.Errorf("decoding lcsLocationInfo: %w", unmErr)
				}
				v.LcsLocationInfo = &dec_lcslocationinfo
				offset += n_lcslocationinfo
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "DeferredmtLrData", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes ServingNodeAddress to BER format.
func (v *ServingNodeAddress) MarshalBER() ([]byte, error) {
	switch v.Choice {
	case ServingNodeAddressChoiceMscNumber:
		if v.MscNumber == nil {
			return nil, fmt.Errorf("choice ServingNodeAddress: msc-Number is nil")
		}
		enc_0 := ber.EncodeOctetString([]byte(*v.MscNumber))
		retagged_enc_0, tagErr_enc_0 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_0)
		if tagErr_enc_0 != nil {
			return nil, fmt.Errorf("encoding msc-Number: %w", tagErr_enc_0)
		}
		enc_0 = retagged_enc_0
		return enc_0, nil
	case ServingNodeAddressChoiceSgsnNumber:
		if v.SgsnNumber == nil {
			return nil, fmt.Errorf("choice ServingNodeAddress: sgsn-Number is nil")
		}
		enc_1 := ber.EncodeOctetString([]byte(*v.SgsnNumber))
		retagged_enc_1, tagErr_enc_1 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_1)
		if tagErr_enc_1 != nil {
			return nil, fmt.Errorf("encoding sgsn-Number: %w", tagErr_enc_1)
		}
		enc_1 = retagged_enc_1
		return enc_1, nil
	case ServingNodeAddressChoiceMmeNumber:
		if v.MmeNumber == nil {
			return nil, fmt.Errorf("choice ServingNodeAddress: mme-Number is nil")
		}
		enc_2 := ber.EncodeOctetString([]byte(*v.MmeNumber))
		retagged_enc_2, tagErr_enc_2 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_2)
		if tagErr_enc_2 != nil {
			return nil, fmt.Errorf("encoding mme-Number: %w", tagErr_enc_2)
		}
		enc_2 = retagged_enc_2
		return enc_2, nil
	default:
		return nil, fmt.Errorf("unknown choice %d for ServingNodeAddress", v.Choice)
	}
}

// MarshalDER encodes ServingNodeAddress to DER format.
func (v *ServingNodeAddress) MarshalDER() ([]byte, error) {
	encoded, err := v.MarshalBER()
	if err != nil {
		return nil, err
	}
	if err := ber.ValidateDERElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding ServingNodeAddress as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes ServingNodeAddress from BER/DER format.
func (v *ServingNodeAddress) UnmarshalBER(data []byte) error {
	if len(data) == 0 {
		return fmt.Errorf("empty data for ServingNodeAddress CHOICE")
	}
	choiceData := data
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for ServingNodeAddress: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData)
	if tlvErr != nil {
		return fmt.Errorf("decoding ServingNodeAddress CHOICE: %w", tlvErr)
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "ServingNodeAddress", Cause: ber.ErrExtraData}
	}

	if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
		v.Choice = ServingNodeAddressChoiceMscNumber
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding msc-Number: %w", tlvErr)
		}
		tmp := ISDNAddressString(rawVal)
		v.MscNumber = &tmp
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
		v.Choice = ServingNodeAddressChoiceSgsnNumber
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding sgsn-Number: %w", tlvErr)
		}
		tmp := ISDNAddressString(rawVal)
		v.SgsnNumber = &tmp
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2 {
		v.Choice = ServingNodeAddressChoiceMmeNumber
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding mme-Number: %w", tlvErr)
		}
		tmp := DiameterIdentity(rawVal)
		v.MmeNumber = &tmp
	} else {
		return fmt.Errorf("unknown tag %s for ServingNodeAddress CHOICE", peekTag)
	}
	return nil
}

// MarshalBER encodes SubscriberLocationReportRes to BER format.
func (v *SubscriberLocationReportRes) MarshalBER() ([]byte, error) {
	var children []byte
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding extensionContainer: %w", err)
		}
		children = append(children, enc_extensioncontainer...)
	}
	if v.NaESRK != nil {
		enc_naesrk := ber.EncodeOctetString([]byte(*v.NaESRK))
		retagged_enc_naesrk, tagErr_enc_naesrk := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_naesrk)
		if tagErr_enc_naesrk != nil {
			return nil, fmt.Errorf("encoding na-ESRK: %w", tagErr_enc_naesrk)
		}
		enc_naesrk = retagged_enc_naesrk
		children = append(children, enc_naesrk...)
	}
	if v.NaESRD != nil {
		enc_naesrd := ber.EncodeOctetString([]byte(*v.NaESRD))
		retagged_enc_naesrd, tagErr_enc_naesrd := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_naesrd)
		if tagErr_enc_naesrd != nil {
			return nil, fmt.Errorf("encoding na-ESRD: %w", tagErr_enc_naesrd)
		}
		enc_naesrd = retagged_enc_naesrd
		children = append(children, enc_naesrd...)
	}
	if v.HGmlcAddress != nil {
		enc_hgmlcaddress := ber.EncodeOctetString([]byte(*v.HGmlcAddress))
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
		enc_reportingplmnlist, err := v.ReportingPLMNList.MarshalBER()
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
		enc_lcsreferencenumber := ber.EncodeOctetString([]byte(*v.LcsReferenceNumber))
		retagged_enc_lcsreferencenumber, tagErr_enc_lcsreferencenumber := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 5, enc_lcsreferencenumber)
		if tagErr_enc_lcsreferencenumber != nil {
			return nil, fmt.Errorf("encoding lcs-ReferenceNumber: %w", tagErr_enc_lcsreferencenumber)
		}
		enc_lcsreferencenumber = retagged_enc_lcsreferencenumber
		children = append(children, enc_lcsreferencenumber...)
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

// MarshalDER encodes SubscriberLocationReportRes to DER format.
func (v *SubscriberLocationReportRes) MarshalDER() ([]byte, error) {
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
		return nil, fmt.Errorf("encoding SubscriberLocationReportRes as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes SubscriberLocationReportRes from BER/DER format.
func (v *SubscriberLocationReportRes) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding SubscriberLocationReportRes SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "SubscriberLocationReportRes", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode extensionContainer
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassUniversal && peekTag.Number == 16 {
				// Decode nested SEQUENCE (ExtensionContainer)
				_, n_extensioncontainer, _, tlvErr_extensioncontainer := ber.DecodeTLV(content[offset:])
				if tlvErr_extensioncontainer != nil {
					return fmt.Errorf("decoding extensionContainer: %w", tlvErr_extensioncontainer)
				}
				var dec_extensioncontainer ExtensionContainer
				if unmErr := dec_extensioncontainer.UnmarshalBER(content[offset : offset+n_extensioncontainer]); unmErr != nil {
					return fmt.Errorf("decoding extensionContainer: %w", unmErr)
				}
				v.ExtensionContainer = &dec_extensioncontainer
				offset += n_extensioncontainer
			}
		}
	}
	// Decode na-ESRK
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
				decodedTag_naesrk, n_naesrk, rawVal_naesrk, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding na-ESRK: %w", err)
				}
				if decodedTag_naesrk.Class != tag.ClassContextSpecific || decodedTag_naesrk.Number != 0 {
					return fmt.Errorf("decoding na-ESRK: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_naesrk)
				}
				tmp_naesrk := ISDNAddressString(rawVal_naesrk)
				v.NaESRK = &tmp_naesrk
				offset += n_naesrk
			}
		}
	}
	// Decode na-ESRD
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
				decodedTag_naesrd, n_naesrd, rawVal_naesrd, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding na-ESRD: %w", err)
				}
				if decodedTag_naesrd.Class != tag.ClassContextSpecific || decodedTag_naesrd.Number != 1 {
					return fmt.Errorf("decoding na-ESRD: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_naesrd)
				}
				tmp_naesrd := ISDNAddressString(rawVal_naesrd)
				v.NaESRD = &tmp_naesrd
				offset += n_naesrd
			}
		}
	}
	// Decode h-gmlc-Address
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2 {
				decodedTag_hgmlcaddress, n_hgmlcaddress, rawVal_hgmlcaddress, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding h-gmlc-Address: %w", err)
				}
				if decodedTag_hgmlcaddress.Class != tag.ClassContextSpecific || decodedTag_hgmlcaddress.Number != 2 {
					return fmt.Errorf("decoding h-gmlc-Address: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_hgmlcaddress)
				}
				tmp_hgmlcaddress := GSNAddress(rawVal_hgmlcaddress)
				v.HGmlcAddress = &tmp_hgmlcaddress
				offset += n_hgmlcaddress
			}
		}
	}
	// Decode mo-lrShortCircuitIndicator
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3 {
				decodedTag_molrshortcircuitindicator, n_molrshortcircuitindicator, rawVal_molrshortcircuitindicator, err := ber.DecodeTLV(content[offset:])
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
				offset += n_molrshortcircuitindicator
			}
		}
	}
	// Decode reportingPLMNList
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4 {
				decodedTag_reportingplmnlist, n_reportingplmnlist, rawVal_reportingplmnlist, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding reportingPLMNList: %w", err)
				}
				if decodedTag_reportingplmnlist.Class != tag.ClassContextSpecific || decodedTag_reportingplmnlist.Number != 4 || decodedTag_reportingplmnlist.Constructed != true {
					return fmt.Errorf("decoding reportingPLMNList: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_reportingplmnlist)
				}
				reconstructed_reportingplmnlist := ber.EncodeSequence(rawVal_reportingplmnlist)
				var dec_reportingplmnlist ReportingPLMNList
				if unmErr := dec_reportingplmnlist.UnmarshalBER(reconstructed_reportingplmnlist); unmErr != nil {
					return fmt.Errorf("decoding reportingPLMNList: %w", unmErr)
				}
				v.ReportingPLMNList = &dec_reportingplmnlist
				offset += n_reportingplmnlist
			}
		}
	}
	// Decode lcs-ReferenceNumber
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 5 {
				decodedTag_lcsreferencenumber, n_lcsreferencenumber, rawVal_lcsreferencenumber, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding lcs-ReferenceNumber: %w", err)
				}
				if decodedTag_lcsreferencenumber.Class != tag.ClassContextSpecific || decodedTag_lcsreferencenumber.Number != 5 {
					return fmt.Errorf("decoding lcs-ReferenceNumber: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_lcsreferencenumber)
				}
				tmp_lcsreferencenumber := LCSReferenceNumber(rawVal_lcsreferencenumber)
				v.LcsReferenceNumber = &tmp_lcsreferencenumber
				offset += n_lcsreferencenumber
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "SubscriberLocationReportRes", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}
