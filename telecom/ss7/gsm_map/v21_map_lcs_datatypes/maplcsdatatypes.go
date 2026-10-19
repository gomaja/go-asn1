// Code generated from ASN.1 module "MAP-LCS-DataTypes". DO NOT EDIT.

package v21_map_lcs_datatypes

import (
	"fmt"

	"github.com/gomaja/go-asn1/telecom/ss7/gsm_map/runtime"
	"github.com/gomaja/go-asn1/telecom/ss7/gsm_map/runtime/ber"
	"github.com/gomaja/go-asn1/telecom/ss7/gsm_map/runtime/tag"
	"github.com/gomaja/go-asn1/telecom/ss7/gsm_map/v21_map_commondatatypes"
	"github.com/gomaja/go-asn1/telecom/ss7/gsm_map/v21_map_extensiondatatypes"
	"github.com/gomaja/go-asn1/telecom/ss7/gsm_map/v21_map_ms_datatypes"
	"github.com/gomaja/go-asn1/telecom/ss7/gsm_map/v21_map_sm_datatypes"
	"github.com/gomaja/go-asn1/telecom/ss7/gsm_map/v21_map_ss_datatypes"
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
	MlcNumber          v21_map_commondatatypes.CommonDataTypesISDNAddressString         `asn1:"tag:0,context,implicit"`
	TargetMS           v21_map_commondatatypes.CommonDataTypesSubscriberIdentity        `asn1:"tag:1,context,explicit"`
	ExtensionContainer *v21_map_extensiondatatypes.ExtensionDataTypesExtensionContainer `asn1:"tag:2,context,implicit,optional" json:"ExtensionContainer,omitempty"`
	ExtCount_          int64                                                            `asn1:"-" json:"-"`
	ExtPresent_        []bool                                                           `asn1:"-" json:"-"`
	// ExtData_ retains complete unknown addition TLVs in received order. Fresh
	// BER and DER copy admissible elements without inferring a foreign schema.
	ExtData_       [][]byte        `asn1:"-" json:"-"`
	berReplayNode_ *ber.ReplayNode `asn1:"-" json:"-"`
}

// LCSRoutingInfoForLCSRes represents the ASN.1 type RoutingInfoForLCS-Res (SEQUENCE).
type LCSRoutingInfoForLCSRes struct {
	TargetMS               v21_map_commondatatypes.CommonDataTypesSubscriberIdentity        `asn1:"tag:0,context,explicit"`
	LcsLocationInfo        LCSLCSLocationInfo                                               `asn1:"tag:1,context,implicit"`
	ExtensionContainer     *v21_map_extensiondatatypes.ExtensionDataTypesExtensionContainer `asn1:"tag:2,context,implicit,optional" json:"ExtensionContainer,omitempty"`
	VGmlcAddress           *v21_map_commondatatypes.CommonDataTypesGSNAddress               `asn1:"tag:3,context,implicit,optional" json:"VGmlcAddress,omitempty"`
	HGmlcAddress           *v21_map_commondatatypes.CommonDataTypesGSNAddress               `asn1:"tag:4,context,implicit,optional" json:"HGmlcAddress,omitempty"`
	PprAddress             *v21_map_commondatatypes.CommonDataTypesGSNAddress               `asn1:"tag:5,context,implicit,optional" json:"PprAddress,omitempty"`
	AdditionalVGmlcAddress *v21_map_commondatatypes.CommonDataTypesGSNAddress               `asn1:"tag:6,context,implicit,optional" json:"AdditionalVGmlcAddress,omitempty"`
	ExtCount_              int64                                                            `asn1:"-" json:"-"`
	ExtPresent_            []bool                                                           `asn1:"-" json:"-"`
	// ExtData_ retains complete unknown addition TLVs in received order. Fresh
	// BER and DER copy admissible elements without inferring a foreign schema.
	ExtData_       [][]byte        `asn1:"-" json:"-"`
	berReplayNode_ *ber.ReplayNode `asn1:"-" json:"-"`
}

// LCSLCSLocationInfo represents the ASN.1 type LCSLocationInfo (SEQUENCE).
type LCSLCSLocationInfo struct {
	NetworkNodeNumber           v21_map_commondatatypes.CommonDataTypesISDNAddressString         `asn1:""`
	Lmsi                        *v21_map_commondatatypes.CommonDataTypesLMSI                     `asn1:"tag:0,context,implicit,optional" json:"Lmsi,omitempty"`
	ExtensionContainer          *v21_map_extensiondatatypes.ExtensionDataTypesExtensionContainer `asn1:"tag:1,context,implicit,optional" json:"ExtensionContainer,omitempty"`
	GprsNodeIndicator           *struct{}                                                        `asn1:"tag:2,context,implicit,optional" json:"GprsNodeIndicator,omitempty"`
	AdditionalNumber            *v21_map_sm_datatypes.SMAdditionalNumber                         `asn1:"tag:3,context,explicit,optional" json:"AdditionalNumber,omitempty"`
	SupportedLCSCapabilitySets  *v21_map_ms_datatypes.MSSupportedLCSCapabilitySets               `asn1:"tag:4,context,implicit,optional" json:"SupportedLCSCapabilitySets,omitempty"`
	AdditionalLCSCapabilitySets *v21_map_ms_datatypes.MSSupportedLCSCapabilitySets               `asn1:"tag:5,context,implicit,optional" json:"AdditionalLCSCapabilitySets,omitempty"`
	MmeName                     *v21_map_commondatatypes.CommonDataTypesDiameterIdentity         `asn1:"tag:6,context,implicit,optional" json:"MmeName,omitempty"`
	AaaServerName               *v21_map_commondatatypes.CommonDataTypesDiameterIdentity         `asn1:"tag:8,context,implicit,optional" json:"AaaServerName,omitempty"`
	SgsnName                    *v21_map_commondatatypes.CommonDataTypesDiameterIdentity         `asn1:"tag:9,context,implicit,optional" json:"SgsnName,omitempty"`
	SgsnRealm                   *v21_map_commondatatypes.CommonDataTypesDiameterIdentity         `asn1:"tag:10,context,implicit,optional" json:"SgsnRealm,omitempty"`
	ExtCount_                   int64                                                            `asn1:"-" json:"-"`
	ExtPresent_                 []bool                                                           `asn1:"-" json:"-"`
	// ExtData_ retains complete unknown addition TLVs in received order. Fresh
	// BER and DER copy admissible elements without inferring a foreign schema.
	ExtData_       [][]byte        `asn1:"-" json:"-"`
	berReplayNode_ *ber.ReplayNode `asn1:"-" json:"-"`
}

// LCSProvideSubscriberLocationArg represents the ASN.1 type ProvideSubscriberLocation-Arg (SEQUENCE).
type LCSProvideSubscriberLocationArg struct {
	LocationType              LCSLocationType                                                  `asn1:""`
	MlcNumber                 v21_map_commondatatypes.CommonDataTypesISDNAddressString         `asn1:""`
	LcsClientID               *LCSLCSClientID                                                  `asn1:"tag:0,context,implicit,optional" json:"LcsClientID,omitempty"`
	PrivacyOverride           *struct{}                                                        `asn1:"tag:1,context,implicit,optional" json:"PrivacyOverride,omitempty"`
	Imsi                      *v21_map_commondatatypes.CommonDataTypesIMSI                     `asn1:"tag:2,context,implicit,optional" json:"Imsi,omitempty"`
	Msisdn                    *v21_map_commondatatypes.CommonDataTypesISDNAddressString        `asn1:"tag:3,context,implicit,optional" json:"Msisdn,omitempty"`
	Lmsi                      *v21_map_commondatatypes.CommonDataTypesLMSI                     `asn1:"tag:4,context,implicit,optional" json:"Lmsi,omitempty"`
	Imei                      *v21_map_commondatatypes.CommonDataTypesIMEI                     `asn1:"tag:5,context,implicit,optional" json:"Imei,omitempty"`
	LcsPriority               *LCSLCSPriority                                                  `asn1:"tag:6,context,implicit,optional" json:"LcsPriority,omitempty"`
	LcsQoS                    *LCSLCSQoS                                                       `asn1:"tag:7,context,implicit,optional" json:"LcsQoS,omitempty"`
	ExtensionContainer        *v21_map_extensiondatatypes.ExtensionDataTypesExtensionContainer `asn1:"tag:8,context,implicit,optional" json:"ExtensionContainer,omitempty"`
	SupportedGADShapes        *LCSSupportedGADShapes                                           `asn1:"tag:9,context,implicit,optional" json:"SupportedGADShapes,omitempty"`
	LcsReferenceNumber        *LCSLCSReferenceNumber                                           `asn1:"tag:10,context,implicit,optional" json:"LcsReferenceNumber,omitempty"`
	LcsServiceTypeID          *v21_map_commondatatypes.CommonDataTypesLCSServiceTypeID         `asn1:"tag:11,context,implicit,optional" json:"LcsServiceTypeID,omitempty"`
	LcsCodeword               *LCSLCSCodeword                                                  `asn1:"tag:12,context,implicit,optional" json:"LcsCodeword,omitempty"`
	LcsPrivacyCheck           *LCSLCSPrivacyCheck                                              `asn1:"tag:13,context,implicit,optional" json:"LcsPrivacyCheck,omitempty"`
	AreaEventInfo             *LCSAreaEventInfo                                                `asn1:"tag:14,context,implicit,optional" json:"AreaEventInfo,omitempty"`
	HGmlcAddress              *v21_map_commondatatypes.CommonDataTypesGSNAddress               `asn1:"tag:15,context,implicit,optional" json:"HGmlcAddress,omitempty"`
	MoLrShortCircuitIndicator *struct{}                                                        `asn1:"tag:16,context,implicit,optional" json:"MoLrShortCircuitIndicator,omitempty"`
	PeriodicLDRInfo           *LCSPeriodicLDRInfo                                              `asn1:"tag:17,context,implicit,optional" json:"PeriodicLDRInfo,omitempty"`
	ReportingPLMNList         *LCSReportingPLMNList                                            `asn1:"tag:18,context,implicit,optional" json:"ReportingPLMNList,omitempty"`
	ExtCount_                 int64                                                            `asn1:"-" json:"-"`
	ExtPresent_               []bool                                                           `asn1:"-" json:"-"`
	// ExtData_ retains complete unknown addition TLVs in received order. Fresh
	// BER and DER copy admissible elements without inferring a foreign schema.
	ExtData_       [][]byte        `asn1:"-" json:"-"`
	berReplayNode_ *ber.ReplayNode `asn1:"-" json:"-"`
}

// LCSLocationType represents the ASN.1 type LocationType (SEQUENCE).
type LCSLocationType struct {
	LocationEstimateType      LCSLocationEstimateType       `asn1:"tag:0,context,implicit"`
	DeferredLocationEventType *LCSDeferredLocationEventType `asn1:"tag:1,context,implicit,optional" json:"DeferredLocationEventType,omitempty"`
	ExtCount_                 int64                         `asn1:"-" json:"-"`
	ExtPresent_               []bool                        `asn1:"-" json:"-"`
	// ExtData_ retains complete unknown addition TLVs in received order. Fresh
	// BER and DER copy admissible elements without inferring a foreign schema.
	ExtData_       [][]byte        `asn1:"-" json:"-"`
	berReplayNode_ *ber.ReplayNode `asn1:"-" json:"-"`
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

const (
	// LCSDeferredLocationEventTypeMsAvailable is position 0 of ASN.1 named bit msAvailable of DeferredLocationEventType (ITU-T X.680 (02/2021) §22).
	LCSDeferredLocationEventTypeMsAvailable = 0
	// LCSDeferredLocationEventTypeEnteringIntoArea is position 1 of ASN.1 named bit enteringIntoArea of DeferredLocationEventType (ITU-T X.680 (02/2021) §22).
	LCSDeferredLocationEventTypeEnteringIntoArea = 1
	// LCSDeferredLocationEventTypeLeavingFromArea is position 2 of ASN.1 named bit leavingFromArea of DeferredLocationEventType (ITU-T X.680 (02/2021) §22).
	LCSDeferredLocationEventTypeLeavingFromArea = 2
	// LCSDeferredLocationEventTypeBeingInsideArea is position 3 of ASN.1 named bit beingInsideArea of DeferredLocationEventType (ITU-T X.680 (02/2021) §22).
	LCSDeferredLocationEventTypeBeingInsideArea = 3
	// LCSDeferredLocationEventTypePeriodicLDR is position 4 of ASN.1 named bit periodicLDR of DeferredLocationEventType (ITU-T X.680 (02/2021) §22).
	LCSDeferredLocationEventTypePeriodicLDR = 4
)

// LCSLCSClientID represents the ASN.1 type LCS-ClientID (SEQUENCE).
type LCSLCSClientID struct {
	LcsClientType       LCSLCSClientType                                            `asn1:"tag:0,context,implicit"`
	LcsClientExternalID *v21_map_commondatatypes.CommonDataTypesLCSClientExternalID `asn1:"tag:1,context,implicit,optional" json:"LcsClientExternalID,omitempty"`
	LcsClientDialedByMS *v21_map_commondatatypes.CommonDataTypesAddressString       `asn1:"tag:2,context,implicit,optional" json:"LcsClientDialedByMS,omitempty"`
	LcsClientInternalID *v21_map_commondatatypes.CommonDataTypesLCSClientInternalID `asn1:"tag:3,context,implicit,optional" json:"LcsClientInternalID,omitempty"`
	LcsClientName       *LCSLCSClientName                                           `asn1:"tag:4,context,implicit,optional" json:"LcsClientName,omitempty"`
	LcsAPN              *v21_map_ms_datatypes.MSAPN                                 `asn1:"tag:5,context,implicit,optional" json:"LcsAPN,omitempty"`
	LcsRequestorID      *LCSLCSRequestorID                                          `asn1:"tag:6,context,implicit,optional" json:"LcsRequestorID,omitempty"`
	ExtCount_           int64                                                       `asn1:"-" json:"-"`
	ExtPresent_         []bool                                                      `asn1:"-" json:"-"`
	// ExtData_ retains complete unknown addition TLVs in received order. Fresh
	// BER and DER copy admissible elements without inferring a foreign schema.
	ExtData_       [][]byte        `asn1:"-" json:"-"`
	berReplayNode_ *ber.ReplayNode `asn1:"-" json:"-"`
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
	DataCodingScheme   v21_map_ss_datatypes.SSUSSDDataCodingScheme `asn1:"tag:0,context,implicit"`
	NameString         LCSNameString                               `asn1:"tag:2,context,implicit"`
	LcsFormatIndicator *LCSLCSFormatIndicator                      `asn1:"tag:3,context,implicit,optional" json:"LcsFormatIndicator,omitempty"`
	ExtCount_          int64                                       `asn1:"-" json:"-"`
	ExtPresent_        []bool                                      `asn1:"-" json:"-"`
	// ExtData_ retains complete unknown addition TLVs in received order. Fresh
	// BER and DER copy admissible elements without inferring a foreign schema.
	ExtData_       [][]byte        `asn1:"-" json:"-"`
	berReplayNode_ *ber.ReplayNode `asn1:"-" json:"-"`
}

// LCSNameString represents the ASN.1 type NameString (OCTET_STRING).
type LCSNameString = v21_map_ss_datatypes.SSUSSDString

// LCSLCSRequestorID represents the ASN.1 type LCSRequestorID (SEQUENCE).
type LCSLCSRequestorID struct {
	DataCodingScheme   v21_map_ss_datatypes.SSUSSDDataCodingScheme `asn1:"tag:0,context,implicit"`
	RequestorIDString  LCSRequestorIDString                        `asn1:"tag:1,context,implicit"`
	LcsFormatIndicator *LCSLCSFormatIndicator                      `asn1:"tag:2,context,implicit,optional" json:"LcsFormatIndicator,omitempty"`
	ExtCount_          int64                                       `asn1:"-" json:"-"`
	ExtPresent_        []bool                                      `asn1:"-" json:"-"`
	// ExtData_ retains complete unknown addition TLVs in received order. Fresh
	// BER and DER copy admissible elements without inferring a foreign schema.
	ExtData_       [][]byte        `asn1:"-" json:"-"`
	berReplayNode_ *ber.ReplayNode `asn1:"-" json:"-"`
}

// LCSRequestorIDString represents the ASN.1 type RequestorIDString (OCTET_STRING).
type LCSRequestorIDString = v21_map_ss_datatypes.SSUSSDString

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
	HorizontalAccuracy        *LCSHorizontalAccuracy                                           `asn1:"tag:0,context,implicit,optional" json:"HorizontalAccuracy,omitempty"`
	VerticalCoordinateRequest *struct{}                                                        `asn1:"tag:1,context,implicit,optional" json:"VerticalCoordinateRequest,omitempty"`
	VerticalAccuracy          *LCSVerticalAccuracy                                             `asn1:"tag:2,context,implicit,optional" json:"VerticalAccuracy,omitempty"`
	ResponseTime              *LCSResponseTime                                                 `asn1:"tag:3,context,implicit,optional" json:"ResponseTime,omitempty"`
	ExtensionContainer        *v21_map_extensiondatatypes.ExtensionDataTypesExtensionContainer `asn1:"tag:4,context,implicit,optional" json:"ExtensionContainer,omitempty"`
	VelocityRequest           *struct{}                                                        `asn1:"tag:5,context,implicit,optional" json:"VelocityRequest,omitempty"`
	LcsQosClass               *LCSLCSQoSClass                                                  `asn1:"tag:6,context,implicit,optional" json:"LcsQosClass,omitempty"`
	ExtCount_                 int64                                                            `asn1:"-" json:"-"`
	ExtPresent_               []bool                                                           `asn1:"-" json:"-"`
	// ExtData_ retains complete unknown addition TLVs in received order. Fresh
	// BER and DER copy admissible elements without inferring a foreign schema.
	ExtData_       [][]byte        `asn1:"-" json:"-"`
	berReplayNode_ *ber.ReplayNode `asn1:"-" json:"-"`
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
	// ExtData_ retains complete unknown addition TLVs in received order. Fresh
	// BER and DER copy admissible elements without inferring a foreign schema.
	ExtData_       [][]byte        `asn1:"-" json:"-"`
	berReplayNode_ *ber.ReplayNode `asn1:"-" json:"-"`
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

const (
	// LCSSupportedGADShapesEllipsoidPoint is position 0 of ASN.1 named bit ellipsoidPoint of SupportedGADShapes (ITU-T X.680 (02/2021) §22).
	LCSSupportedGADShapesEllipsoidPoint = 0
	// LCSSupportedGADShapesEllipsoidPointWithUncertaintyCircle is position 1 of ASN.1 named bit ellipsoidPointWithUncertaintyCircle of SupportedGADShapes (ITU-T X.680 (02/2021) §22).
	LCSSupportedGADShapesEllipsoidPointWithUncertaintyCircle = 1
	// LCSSupportedGADShapesEllipsoidPointWithUncertaintyEllipse is position 2 of ASN.1 named bit ellipsoidPointWithUncertaintyEllipse of SupportedGADShapes (ITU-T X.680 (02/2021) §22).
	LCSSupportedGADShapesEllipsoidPointWithUncertaintyEllipse = 2
	// LCSSupportedGADShapesPolygon is position 3 of ASN.1 named bit polygon of SupportedGADShapes (ITU-T X.680 (02/2021) §22).
	LCSSupportedGADShapesPolygon = 3
	// LCSSupportedGADShapesEllipsoidPointWithAltitude is position 4 of ASN.1 named bit ellipsoidPointWithAltitude of SupportedGADShapes (ITU-T X.680 (02/2021) §22).
	LCSSupportedGADShapesEllipsoidPointWithAltitude = 4
	// LCSSupportedGADShapesEllipsoidPointWithAltitudeAndUncertaintyElipsoid is position 5 of ASN.1 named bit ellipsoidPointWithAltitudeAndUncertaintyElipsoid of SupportedGADShapes (ITU-T X.680 (02/2021) §22).
	LCSSupportedGADShapesEllipsoidPointWithAltitudeAndUncertaintyElipsoid = 5
	// LCSSupportedGADShapesEllipsoidArc is position 6 of ASN.1 named bit ellipsoidArc of SupportedGADShapes (ITU-T X.680 (02/2021) §22).
	LCSSupportedGADShapesEllipsoidArc = 6
)

// LCSLCSReferenceNumber represents the ASN.1 type LCS-ReferenceNumber (OCTET_STRING).
type LCSLCSReferenceNumber = []byte

// LCSLCSCodeword represents the ASN.1 type LCSCodeword (SEQUENCE).
type LCSLCSCodeword struct {
	DataCodingScheme  v21_map_ss_datatypes.SSUSSDDataCodingScheme `asn1:"tag:0,context,implicit"`
	LcsCodewordString LCSLCSCodewordString                        `asn1:"tag:1,context,implicit"`
	ExtCount_         int64                                       `asn1:"-" json:"-"`
	ExtPresent_       []bool                                      `asn1:"-" json:"-"`
	// ExtData_ retains complete unknown addition TLVs in received order. Fresh
	// BER and DER copy admissible elements without inferring a foreign schema.
	ExtData_       [][]byte        `asn1:"-" json:"-"`
	berReplayNode_ *ber.ReplayNode `asn1:"-" json:"-"`
}

// LCSLCSCodewordString represents the ASN.1 type LCSCodewordString (OCTET_STRING).
type LCSLCSCodewordString = v21_map_ss_datatypes.SSUSSDString

// LCSLCSPrivacyCheck represents the ASN.1 type LCS-PrivacyCheck (SEQUENCE).
type LCSLCSPrivacyCheck struct {
	CallSessionUnrelated LCSPrivacyCheckRelatedAction  `asn1:"tag:0,context,implicit"`
	CallSessionRelated   *LCSPrivacyCheckRelatedAction `asn1:"tag:1,context,implicit,optional" json:"CallSessionRelated,omitempty"`
	ExtCount_            int64                         `asn1:"-" json:"-"`
	ExtPresent_          []bool                        `asn1:"-" json:"-"`
	// ExtData_ retains complete unknown addition TLVs in received order. Fresh
	// BER and DER copy admissible elements without inferring a foreign schema.
	ExtData_       [][]byte        `asn1:"-" json:"-"`
	berReplayNode_ *ber.ReplayNode `asn1:"-" json:"-"`
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
	// ExtData_ retains complete unknown addition TLVs in received order. Fresh
	// BER and DER copy admissible elements without inferring a foreign schema.
	ExtData_       [][]byte        `asn1:"-" json:"-"`
	berReplayNode_ *ber.ReplayNode `asn1:"-" json:"-"`
}

// LCSAreaDefinition represents the ASN.1 type AreaDefinition (SEQUENCE).
type LCSAreaDefinition struct {
	AreaList          *LCSAreaList `asn1:"tag:0,context,implicit"`
	berAreaListIndef_ bool         `asn1:"-" json:"-"`
	ExtCount_         int64        `asn1:"-" json:"-"`
	ExtPresent_       []bool       `asn1:"-" json:"-"`
	// ExtData_ retains complete unknown addition TLVs in received order. Fresh
	// BER and DER copy admissible elements without inferring a foreign schema.
	ExtData_       [][]byte        `asn1:"-" json:"-"`
	berReplayNode_ *ber.ReplayNode `asn1:"-" json:"-"`
}

// LCSAreaList represents the ASN.1 type AreaList (SEQUENCE_OF).
type LCSAreaList struct {
	Values         []LCSArea       `json:"Values"`
	berReplayNode_ *ber.ReplayNode `json:"-"`
}

// LCSArea represents the ASN.1 type Area (SEQUENCE).
type LCSArea struct {
	AreaType           LCSAreaType           `asn1:"tag:0,context,implicit"`
	AreaIdentification LCSAreaIdentification `asn1:"tag:1,context,implicit"`
	ExtCount_          int64                 `asn1:"-" json:"-"`
	ExtPresent_        []bool                `asn1:"-" json:"-"`
	// ExtData_ retains complete unknown addition TLVs in received order. Fresh
	// BER and DER copy admissible elements without inferring a foreign schema.
	ExtData_       [][]byte        `asn1:"-" json:"-"`
	berReplayNode_ *ber.ReplayNode `asn1:"-" json:"-"`
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
	// ExtData_ retains complete unknown addition TLVs in received order. Fresh
	// BER and DER copy admissible elements without inferring a foreign schema.
	ExtData_       [][]byte        `asn1:"-" json:"-"`
	berReplayNode_ *ber.ReplayNode `asn1:"-" json:"-"`
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
	// ExtData_ retains complete unknown addition TLVs in received order. Fresh
	// BER and DER copy admissible elements without inferring a foreign schema.
	ExtData_       [][]byte        `asn1:"-" json:"-"`
	berReplayNode_ *ber.ReplayNode `asn1:"-" json:"-"`
}

// LCSReportingAmountMilliseconds represents the ASN.1 type ReportingAmountMilliseconds (INTEGER).
type LCSReportingAmountMilliseconds = int64

// LCSReportingIntervalMilliseconds represents the ASN.1 type ReportingIntervalMilliseconds (INTEGER).
type LCSReportingIntervalMilliseconds = int64

// LCSReportingPLMNList represents the ASN.1 type ReportingPLMNList (SEQUENCE).
type LCSReportingPLMNList struct {
	PlmnListPrioritized *struct{}    `asn1:"tag:0,context,implicit,optional" json:"PlmnListPrioritized,omitempty"`
	PlmnList            *LCSPLMNList `asn1:"tag:1,context,implicit"`
	berPlmnListIndef_   bool         `asn1:"-" json:"-"`
	ExtCount_           int64        `asn1:"-" json:"-"`
	ExtPresent_         []bool       `asn1:"-" json:"-"`
	// ExtData_ retains complete unknown addition TLVs in received order. Fresh
	// BER and DER copy admissible elements without inferring a foreign schema.
	ExtData_       [][]byte        `asn1:"-" json:"-"`
	berReplayNode_ *ber.ReplayNode `asn1:"-" json:"-"`
}

// LCSPLMNList represents the ASN.1 type PLMNList (SEQUENCE_OF).
type LCSPLMNList struct {
	Values         []LCSReportingPLMN `json:"Values"`
	berReplayNode_ *ber.ReplayNode    `json:"-"`
}

// LCSReportingPLMN represents the ASN.1 type ReportingPLMN (SEQUENCE).
type LCSReportingPLMN struct {
	PlmnId                     v21_map_commondatatypes.CommonDataTypesPLMNId `asn1:"tag:0,context,implicit"`
	RanTechnology              *LCSRANTechnology                             `asn1:"tag:1,context,implicit,optional" json:"RanTechnology,omitempty"`
	RanPeriodicLocationSupport *struct{}                                     `asn1:"tag:2,context,implicit,optional" json:"RanPeriodicLocationSupport,omitempty"`
	ExtCount_                  int64                                         `asn1:"-" json:"-"`
	ExtPresent_                []bool                                        `asn1:"-" json:"-"`
	// ExtData_ retains complete unknown addition TLVs in received order. Fresh
	// BER and DER copy admissible elements without inferring a foreign schema.
	ExtData_       [][]byte        `asn1:"-" json:"-"`
	berReplayNode_ *ber.ReplayNode `asn1:"-" json:"-"`
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
	LocationEstimate               LCSExtGeographicalInformation                                            `asn1:""`
	AgeOfLocationEstimate          *v21_map_commondatatypes.CommonDataTypesAgeOfLocationInformation         `asn1:"tag:0,context,implicit,optional" json:"AgeOfLocationEstimate,omitempty"`
	ExtensionContainer             *v21_map_extensiondatatypes.ExtensionDataTypesExtensionContainer         `asn1:"tag:1,context,implicit,optional" json:"ExtensionContainer,omitempty"`
	AddLocationEstimate            *LCSAddGeographicalInformation                                           `asn1:"tag:2,context,implicit,optional" json:"AddLocationEstimate,omitempty"`
	DeferredmtLrResponseIndicator  *struct{}                                                                `asn1:"tag:3,context,implicit,optional" json:"DeferredmtLrResponseIndicator,omitempty"`
	GeranPositioningData           *LCSPositioningDataInformation                                           `asn1:"tag:4,context,implicit,optional" json:"GeranPositioningData,omitempty"`
	UtranPositioningData           *LCSUtranPositioningDataInfo                                             `asn1:"tag:5,context,implicit,optional" json:"UtranPositioningData,omitempty"`
	CellIdOrSai                    *v21_map_commondatatypes.CommonDataTypesCellGlobalIdOrServiceAreaIdOrLAI `asn1:"tag:6,context,explicit,optional" json:"CellIdOrSai,omitempty"`
	SaiPresent                     *struct{}                                                                `asn1:"tag:7,context,implicit,optional" json:"SaiPresent,omitempty"`
	AccuracyFulfilmentIndicator    *LCSAccuracyFulfilmentIndicator                                          `asn1:"tag:8,context,implicit,optional" json:"AccuracyFulfilmentIndicator,omitempty"`
	VelocityEstimate               *LCSVelocityEstimate                                                     `asn1:"tag:9,context,implicit,optional" json:"VelocityEstimate,omitempty"`
	MoLrShortCircuitIndicator      *struct{}                                                                `asn1:"tag:10,context,implicit,optional" json:"MoLrShortCircuitIndicator,omitempty"`
	GeranGANSSpositioningData      *LCSGeranGANSSpositioningData                                            `asn1:"tag:11,context,implicit,optional" json:"GeranGANSSpositioningData,omitempty"`
	UtranGANSSpositioningData      *LCSUtranGANSSpositioningData                                            `asn1:"tag:12,context,implicit,optional" json:"UtranGANSSpositioningData,omitempty"`
	TargetServingNodeForHandover   *LCSServingNodeAddress                                                   `asn1:"tag:13,context,explicit,optional" json:"TargetServingNodeForHandover,omitempty"`
	UtranAdditionalPositioningData *LCSUtranAdditionalPositioningData                                       `asn1:"tag:14,context,implicit,optional" json:"UtranAdditionalPositioningData,omitempty"`
	UtranBaroPressureMeas          *LCSUtranBaroPressureMeas                                                `asn1:"tag:15,context,implicit,optional" json:"UtranBaroPressureMeas,omitempty"`
	UtranCivicAddress              *LCSUtranCivicAddress                                                    `asn1:"tag:16,context,implicit,optional" json:"UtranCivicAddress,omitempty"`
	ExtCount_                      int64                                                                    `asn1:"-" json:"-"`
	ExtPresent_                    []bool                                                                   `asn1:"-" json:"-"`
	// ExtData_ retains complete unknown addition TLVs in received order. Fresh
	// BER and DER copy admissible elements without inferring a foreign schema.
	ExtData_       [][]byte        `asn1:"-" json:"-"`
	berReplayNode_ *ber.ReplayNode `asn1:"-" json:"-"`
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
	LcsEvent                       LCSLCSEvent                                                              `asn1:""`
	LcsClientID                    LCSLCSClientID                                                           `asn1:""`
	LcsLocationInfo                LCSLCSLocationInfo                                                       `asn1:""`
	Msisdn                         *v21_map_commondatatypes.CommonDataTypesISDNAddressString                `asn1:"tag:0,context,implicit,optional" json:"Msisdn,omitempty"`
	Imsi                           *v21_map_commondatatypes.CommonDataTypesIMSI                             `asn1:"tag:1,context,implicit,optional" json:"Imsi,omitempty"`
	Imei                           *v21_map_commondatatypes.CommonDataTypesIMEI                             `asn1:"tag:2,context,implicit,optional" json:"Imei,omitempty"`
	NaESRD                         *v21_map_commondatatypes.CommonDataTypesISDNAddressString                `asn1:"tag:3,context,implicit,optional" json:"NaESRD,omitempty"`
	NaESRK                         *v21_map_commondatatypes.CommonDataTypesISDNAddressString                `asn1:"tag:4,context,implicit,optional" json:"NaESRK,omitempty"`
	LocationEstimate               *LCSExtGeographicalInformation                                           `asn1:"tag:5,context,implicit,optional" json:"LocationEstimate,omitempty"`
	AgeOfLocationEstimate          *v21_map_commondatatypes.CommonDataTypesAgeOfLocationInformation         `asn1:"tag:6,context,implicit,optional" json:"AgeOfLocationEstimate,omitempty"`
	SlrArgExtensionContainer       *v21_map_extensiondatatypes.ExtensionDataTypesSLRArgExtensionContainer   `asn1:"tag:7,context,implicit,optional" json:"SlrArgExtensionContainer,omitempty"`
	AddLocationEstimate            *LCSAddGeographicalInformation                                           `asn1:"tag:8,context,implicit,optional" json:"AddLocationEstimate,omitempty"`
	DeferredmtLrData               *LCSDeferredmtLrData                                                     `asn1:"tag:9,context,implicit,optional" json:"DeferredmtLrData,omitempty"`
	LcsReferenceNumber             *LCSLCSReferenceNumber                                                   `asn1:"tag:10,context,implicit,optional" json:"LcsReferenceNumber,omitempty"`
	GeranPositioningData           *LCSPositioningDataInformation                                           `asn1:"tag:11,context,implicit,optional" json:"GeranPositioningData,omitempty"`
	UtranPositioningData           *LCSUtranPositioningDataInfo                                             `asn1:"tag:12,context,implicit,optional" json:"UtranPositioningData,omitempty"`
	CellIdOrSai                    *v21_map_commondatatypes.CommonDataTypesCellGlobalIdOrServiceAreaIdOrLAI `asn1:"tag:13,context,explicit,optional" json:"CellIdOrSai,omitempty"`
	HGmlcAddress                   *v21_map_commondatatypes.CommonDataTypesGSNAddress                       `asn1:"tag:14,context,implicit,optional" json:"HGmlcAddress,omitempty"`
	LcsServiceTypeID               *v21_map_commondatatypes.CommonDataTypesLCSServiceTypeID                 `asn1:"tag:15,context,implicit,optional" json:"LcsServiceTypeID,omitempty"`
	SaiPresent                     *struct{}                                                                `asn1:"tag:17,context,implicit,optional" json:"SaiPresent,omitempty"`
	PseudonymIndicator             *struct{}                                                                `asn1:"tag:18,context,implicit,optional" json:"PseudonymIndicator,omitempty"`
	AccuracyFulfilmentIndicator    *LCSAccuracyFulfilmentIndicator                                          `asn1:"tag:19,context,implicit,optional" json:"AccuracyFulfilmentIndicator,omitempty"`
	VelocityEstimate               *LCSVelocityEstimate                                                     `asn1:"tag:20,context,implicit,optional" json:"VelocityEstimate,omitempty"`
	SequenceNumber                 *LCSSequenceNumber                                                       `asn1:"tag:21,context,implicit,optional" json:"SequenceNumber,omitempty"`
	PeriodicLDRInfo                *LCSPeriodicLDRInfo                                                      `asn1:"tag:22,context,implicit,optional" json:"PeriodicLDRInfo,omitempty"`
	MoLrShortCircuitIndicator      *struct{}                                                                `asn1:"tag:23,context,implicit,optional" json:"MoLrShortCircuitIndicator,omitempty"`
	GeranGANSSpositioningData      *LCSGeranGANSSpositioningData                                            `asn1:"tag:24,context,implicit,optional" json:"GeranGANSSpositioningData,omitempty"`
	UtranGANSSpositioningData      *LCSUtranGANSSpositioningData                                            `asn1:"tag:25,context,implicit,optional" json:"UtranGANSSpositioningData,omitempty"`
	TargetServingNodeForHandover   *LCSServingNodeAddress                                                   `asn1:"tag:26,context,explicit,optional" json:"TargetServingNodeForHandover,omitempty"`
	UtranAdditionalPositioningData *LCSUtranAdditionalPositioningData                                       `asn1:"tag:27,context,implicit,optional" json:"UtranAdditionalPositioningData,omitempty"`
	UtranBaroPressureMeas          *LCSUtranBaroPressureMeas                                                `asn1:"tag:28,context,implicit,optional" json:"UtranBaroPressureMeas,omitempty"`
	UtranCivicAddress              *LCSUtranCivicAddress                                                    `asn1:"tag:29,context,implicit,optional" json:"UtranCivicAddress,omitempty"`
	ExtCount_                      int64                                                                    `asn1:"-" json:"-"`
	ExtPresent_                    []bool                                                                   `asn1:"-" json:"-"`
	// ExtData_ retains complete unknown addition TLVs in received order. Fresh
	// BER and DER copy admissible elements without inferring a foreign schema.
	ExtData_       [][]byte        `asn1:"-" json:"-"`
	berReplayNode_ *ber.ReplayNode `asn1:"-" json:"-"`
}

// LCSDeferredmtLrData represents the ASN.1 type Deferredmt-lrData (SEQUENCE).
type LCSDeferredmtLrData struct {
	DeferredLocationEventType LCSDeferredLocationEventType `asn1:""`
	TerminationCause          *LCSTerminationCause         `asn1:"tag:0,context,implicit,optional" json:"TerminationCause,omitempty"`
	LcsLocationInfo           *LCSLCSLocationInfo          `asn1:"tag:1,context,implicit,optional" json:"LcsLocationInfo,omitempty"`
	ExtCount_                 int64                        `asn1:"-" json:"-"`
	ExtPresent_               []bool                       `asn1:"-" json:"-"`
	// ExtData_ retains complete unknown addition TLVs in received order. Fresh
	// BER and DER copy admissible elements without inferring a foreign schema.
	ExtData_       [][]byte        `asn1:"-" json:"-"`
	berReplayNode_ *ber.ReplayNode `asn1:"-" json:"-"`
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
	Choice         int
	berReplayNode_ *ber.ReplayNode                                           `json:"-"`
	MscNumber      *v21_map_commondatatypes.CommonDataTypesISDNAddressString `json:"MscNumber,omitempty"`
	SgsnNumber     *v21_map_commondatatypes.CommonDataTypesISDNAddressString `json:"SgsnNumber,omitempty"`
	MmeNumber      *v21_map_commondatatypes.CommonDataTypesDiameterIdentity  `json:"MmeNumber,omitempty"`
}

// NewLCSServingNodeAddressMscNumber creates a LCSServingNodeAddress with the msc-Number alternative.
func NewLCSServingNodeAddressMscNumber(v v21_map_commondatatypes.CommonDataTypesISDNAddressString) LCSServingNodeAddress {
	return LCSServingNodeAddress{
		Choice:    LCSServingNodeAddressChoiceMscNumber,
		MscNumber: &v,
	}
}

// NewLCSServingNodeAddressSgsnNumber creates a LCSServingNodeAddress with the sgsn-Number alternative.
func NewLCSServingNodeAddressSgsnNumber(v v21_map_commondatatypes.CommonDataTypesISDNAddressString) LCSServingNodeAddress {
	return LCSServingNodeAddress{
		Choice:     LCSServingNodeAddressChoiceSgsnNumber,
		SgsnNumber: &v,
	}
}

// NewLCSServingNodeAddressMmeNumber creates a LCSServingNodeAddress with the mme-Number alternative.
func NewLCSServingNodeAddressMmeNumber(v v21_map_commondatatypes.CommonDataTypesDiameterIdentity) LCSServingNodeAddress {
	return LCSServingNodeAddress{
		Choice:    LCSServingNodeAddressChoiceMmeNumber,
		MmeNumber: &v,
	}
}

// LCSSubscriberLocationReportRes represents the ASN.1 type SubscriberLocationReport-Res (SEQUENCE).
type LCSSubscriberLocationReportRes struct {
	ExtensionContainer        *v21_map_extensiondatatypes.ExtensionDataTypesExtensionContainer `asn1:",optional" json:"ExtensionContainer,omitempty"`
	NaESRK                    *v21_map_commondatatypes.CommonDataTypesISDNAddressString        `asn1:"tag:0,context,implicit,optional" json:"NaESRK,omitempty"`
	NaESRD                    *v21_map_commondatatypes.CommonDataTypesISDNAddressString        `asn1:"tag:1,context,implicit,optional" json:"NaESRD,omitempty"`
	HGmlcAddress              *v21_map_commondatatypes.CommonDataTypesGSNAddress               `asn1:"tag:2,context,implicit,optional" json:"HGmlcAddress,omitempty"`
	MoLrShortCircuitIndicator *struct{}                                                        `asn1:"tag:3,context,implicit,optional" json:"MoLrShortCircuitIndicator,omitempty"`
	ReportingPLMNList         *LCSReportingPLMNList                                            `asn1:"tag:4,context,implicit,optional" json:"ReportingPLMNList,omitempty"`
	LcsReferenceNumber        *LCSLCSReferenceNumber                                           `asn1:"tag:5,context,implicit,optional" json:"LcsReferenceNumber,omitempty"`
	ExtCount_                 int64                                                            `asn1:"-" json:"-"`
	ExtPresent_               []bool                                                           `asn1:"-" json:"-"`
	// ExtData_ retains complete unknown addition TLVs in received order. Fresh
	// BER and DER copy admissible elements without inferring a foreign schema.
	ExtData_       [][]byte        `asn1:"-" json:"-"`
	berReplayNode_ *ber.ReplayNode `asn1:"-" json:"-"`
}

// MarshalBER encodes LCSRoutingInfoForLCSArg to BER format.
func (v *LCSRoutingInfoForLCSArg) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: LCSRoutingInfoForLCSArg receiver is nil", ber.ErrInvalidValue)
	}
	if v.berReplayNode_ == nil {
		return v.marshalBER(opts...)
	}
	var replayErr error
	opts, replayErr = ber.PrepareBERReplay(v.berReplayNode_, opts, func(mode ber.EncodeOption) ([]byte, error) { return v.MarshalBER([]ber.EncodeOption{mode}...) }, v)
	if replayErr != nil {
		return nil, replayErr
	}
	if replayBytes, ok := ber.PreparedBERReplay(v.berReplayNode_, opts); ok {
		return replayBytes, nil
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBERNode(encoded, v.berReplayNode_, opts), nil
}
func (v *LCSRoutingInfoForLCSArg) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if len(v.MlcNumber) < 1 || len(v.MlcNumber) > 9 {
		if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(opts, "MAP-LCS-DataTypes.RoutingInfoForLCS-Arg", ber.RuleRef{Document: "ITU-T X.680", Edition: "02/2021", Clause: "51.5"}), "mlcNumber", "SIZE (1..9)", len(v.MlcNumber)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	if len(v.MlcNumber) < 1 || len(v.MlcNumber) > 20 {
		if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(opts, "MAP-LCS-DataTypes.RoutingInfoForLCS-Arg", ber.RuleRef{Document: "ITU-T X.680", Edition: "02/2021", Clause: "51.5"}), "mlcNumber", "SIZE (1..20)", len(v.MlcNumber)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_mlcnumber, encodeErr_enc_mlcnumber := ber.EncodeOctetString([]byte(v.MlcNumber))
	if encodeErr_enc_mlcnumber != nil {
		return nil, qualifyBERError(encodeErr_enc_mlcnumber, "mlcNumber", "encoding", false)
	}
	retagged_enc_mlcnumber, tagErr_enc_mlcnumber := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_mlcnumber)
	if tagErr_enc_mlcnumber != nil {
		return nil, qualifyBERError(tagErr_enc_mlcnumber, "mlcNumber", "encoding", false)
	}
	enc_mlcnumber = retagged_enc_mlcnumber
	children = append(children, enc_mlcnumber...)
	enc_targetms, err := v.TargetMS.MarshalBER(ber.ChildEncodeOptions(opts, "targetMS")...)
	if err != nil {
		return nil, qualifyBERError(err, "targetMS", "encoding", false)
	}
	{
		var encodeErr error
		enc_targetms, encodeErr = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 1, enc_targetms)
		if encodeErr != nil {
			return nil, qualifyBERError(encodeErr, "targetMS", "encoding", false)
		}
	}
	ber.RecordGeneratedBERChildPlacement(opts, len(children), enc_targetms)
	children = append(children, enc_targetms...)
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
		ber.RecordGeneratedBERChildPlacement(opts, len(children), enc_extensioncontainer)
		children = append(children, enc_extensioncontainer...)
	}
	for i, ext := range v.ExtData_ {
		if err := ber.CheckBEROpaqueElement(ext, opts...); err != nil {
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
		if i == 0 && (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2) {
			if constraintErr := ber.CheckEncodedValue(ber.EncodeRule(opts, "MAP-LCS-DataTypes.RoutingInfoForLCS-Arg", ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
				return nil, constraintErr
			}
		}
		children = append(children, ext...)
	}
	ber.RecordGeneratedBERContainer(opts, children)
	return ber.EncodeSequence(children)
}
func (v *LCSRoutingInfoForLCSArg) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// MarshalDER encodes LCSRoutingInfoForLCSArg to DER format.
// Opaque descendants pass generic DER checks; foreign schema rules need a typed binding.
func (v *LCSRoutingInfoForLCSArg) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: LCSRoutingInfoForLCSArg receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if len(v.MlcNumber) < 1 || len(v.MlcNumber) > 9 {
		if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(nil, "MAP-LCS-DataTypes.RoutingInfoForLCS-Arg", ber.RuleRef{Document: "ITU-T X.680", Edition: "02/2021", Clause: "51.5"}), "mlcNumber", "SIZE (1..9)", len(v.MlcNumber)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	if len(v.MlcNumber) < 1 || len(v.MlcNumber) > 20 {
		if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(nil, "MAP-LCS-DataTypes.RoutingInfoForLCS-Arg", ber.RuleRef{Document: "ITU-T X.680", Edition: "02/2021", Clause: "51.5"}), "mlcNumber", "SIZE (1..20)", len(v.MlcNumber)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_mlcnumber, encodeErr_enc_mlcnumber := ber.EncodeOctetString([]byte(v.MlcNumber))
	if encodeErr_enc_mlcnumber != nil {
		return nil, qualifyBERError(encodeErr_enc_mlcnumber, "mlcNumber", "encoding", true)
	}
	retagged_enc_mlcnumber, tagErr_enc_mlcnumber := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_mlcnumber)
	if tagErr_enc_mlcnumber != nil {
		return nil, qualifyBERError(tagErr_enc_mlcnumber, "mlcNumber", "encoding", true)
	}
	enc_mlcnumber = retagged_enc_mlcnumber
	children = append(children, enc_mlcnumber...)
	enc_targetms, err := v.TargetMS.MarshalDER()
	if err != nil {
		return nil, qualifyBERError(err, "targetMS", "encoding", true)
	}
	{
		var encodeErr error
		enc_targetms, encodeErr = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 1, enc_targetms)
		if encodeErr != nil {
			return nil, qualifyBERError(encodeErr, "targetMS", "encoding", true)
		}
	}
	children = append(children, enc_targetms...)
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
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDEREncodedElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
		peekTag, _, _, extErr := ber.DecodeEncodedTLV(ext)
		if extErr != nil {
			return nil, extErr
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: only the first addition is restricted.
		if i == 0 && (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2) {
			if constraintErr := ber.CheckEncodedValue(ber.EncodeRule(nil, "MAP-LCS-DataTypes.RoutingInfoForLCS-Arg", ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
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
		return nil, fmt.Errorf("%s: %w", "encoding LCSRoutingInfoForLCSArg as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}
func (v *LCSRoutingInfoForLCSArg) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	encoded, err := v.MarshalDER()
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBER decodes LCSRoutingInfoForLCSArg from BER/DER format.
func (destination *LCSRoutingInfoForLCSArg) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if destination == nil {
		return fmt.Errorf("%w: LCSRoutingInfoForLCSArg destination is nil", ber.ErrInvalidValue)
	}
	var berNextValue_ LCSRoutingInfoForLCSArg
	v := &berNextValue_

	defer func() {
		if returnErr ==
			nil {
			*destination = *v
		}
	}()

	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	ownedData, ownErr := ber.OwnGeneratedBERInput(data, opts)
	if ownErr != nil {
		return ownErr
	}
	data = ownedData
	preparedData, preparedOptions, prepareErr := ber.PrepareGeneratedBERInput(data, opts)
	if prepareErr != nil {
		return ber.DiagnosePreflight(prepareErr, data, opts, "child", func(probeOpts []ber.DecodeOption) error {
			var probe LCSRoutingInfoForLCSArg
			return probe.UnmarshalBER(data, probeOpts...)
		})
	}
	data, opts = preparedData, preparedOptions
	opts = ber.LocateDecodedElement(data, "MAP-LCS-DataTypes.RoutingInfoForLCS-Arg", opts)
	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
	*v = LCSRoutingInfoForLCSArg{}
	defer func() {
		if returnErr != nil || !ber.BERNeedsPreservation(opts) {
			return
		}
		v.berReplayNode_ = ber.CaptureGeneratedBERReplay(data, opts)
		returnErr = ber.CompleteGeneratedBERDecode(opts, v, func(base *LCSRoutingInfoForLCSArg, replayOpts ...ber.EncodeOption) ([]byte, error) {
			return base.MarshalBER(replayOpts...)
		})
	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("%s: %w", "decoding LCSRoutingInfoForLCSArg SEQUENCE", qualifyBERError(err, "", "decoding", false))
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
	{
		ber.MarkPreflightTarget(opts, "mlcNumber", content[offset:])
		decodedTag_mlcnumber, n_mlcnumber, rawVal_mlcnumber, err := ber.DecodeTLV(content[offset:], opts...)
		if err != nil {
			return qualifyBERError(err, "mlcNumber", "decoding", false)
		}
		if decodedTag_mlcnumber.Class != tag.ClassContextSpecific || decodedTag_mlcnumber.Number != 0 {
			return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_mlcnumber), "mlcNumber", "decoding", false)
		}
		decVal_mlcnumber, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_mlcnumber.Constructed, rawVal_mlcnumber, opts...)
		if octetErr != nil {
			return qualifyBERError(octetErr, "mlcNumber", "decoding", false)
		}
		v.MlcNumber = v21_map_commondatatypes.CommonDataTypesISDNAddressString(decVal_mlcnumber)
		if offset > len(content) || n_mlcnumber < 0 || n_mlcnumber > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n_mlcnumber
		if len(v.MlcNumber) < 1 || len(v.MlcNumber) > 9 {
			if constraintErr := ber.CheckDecodedLength(ber.DecodeRule(opts, "MAP-LCS-DataTypes.RoutingInfoForLCS-Arg", ber.RuleRef{Document: "ITU-T X.680", Edition: "02/2021", Clause: "51.5"}), "mlcNumber", "SIZE (1..9)", len(v.MlcNumber)); constraintErr != nil {
				return constraintErr
			}
		}
		if len(v.MlcNumber) < 1 || len(v.MlcNumber) > 20 {
			if constraintErr := ber.CheckDecodedLength(ber.DecodeRule(opts, "MAP-LCS-DataTypes.RoutingInfoForLCS-Arg", ber.RuleRef{Document: "ITU-T X.680", Edition: "02/2021", Clause: "51.5"}), "mlcNumber", "SIZE (1..20)", len(v.MlcNumber)); constraintErr != nil {
				return constraintErr
			}
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
	{
		ber.MarkPreflightTarget(opts, "targetMS", content[offset:])
		decodedTag_targetms, n_targetms, innerData_targetms, err := ber.DecodeTLV(content[offset:], opts...)
		if err != nil {
			return qualifyBERError(err, "targetMS", "decoding", false)
		}
		if decodedTag_targetms.Class != tag.ClassContextSpecific || decodedTag_targetms.Number != 1 || decodedTag_targetms.Constructed != true {
			return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_targetms), "targetMS", "decoding", false)
		}
		_, innerUsed_targetms, _, innerErr_targetms := ber.DecodeTLV(innerData_targetms, opts...)
		if innerErr_targetms != nil {
			return qualifyBERError(innerErr_targetms, "targetMS", "decoding", false)
		}
		if innerUsed_targetms != len(innerData_targetms) {
			return qualifyBERError(ber.ErrExtraData, "targetMS", "decoding", false)
		}
		// Decode inner value from explicit tag wrapper
		ber.MarkPreflightTarget(opts, "targetMS", innerData_targetms)
		if unmErr := v.TargetMS.UnmarshalBER(innerData_targetms, ber.ChildDecodeOptions(opts, "targetMS")...); unmErr != nil {
			return qualifyBERError(unmErr, "targetMS", "decoding", false)
		}
		if offset < 0 || offset >
			len(content) || n_targetms < 0 || n_targetms > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n_targetms
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
				_ = rawVal_extensioncontainer
				if offset < 0 || offset >
					len(content) || n_extensioncontainer < 0 || n_extensioncontainer >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				reconstructed_extensioncontainer, reconstructionErr_extensioncontainer := ber.EncodeImplicitTagWithClass(tag.ClassUniversal, tag.TagSequence, content[offset:offset+n_extensioncontainer])
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
			return &ber.DecodeError{Offset: offset, TypeName: "LCSRoutingInfoForLCSArg", Cause: extErr_}
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: the first unknown addition must differ from trailing OPTIONAL/DEFAULT tags.
		if len(v.ExtData_) == 0 && (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2) {
			if !ber.ToleranceEnabled(opts) {
				return &ber.DecodeError{Offset: offset, TypeName: "LCSRoutingInfoForLCSArg", Cause: fmt.Errorf("%w: repeated or out-of-order SEQUENCE component tag %s", ber.ErrInvalidTag, peekTag)}
			}
			if orderErr_ := ber.CheckDecodedValue(ber.DecodeRule(opts, "MAP-LCS-DataTypes.RoutingInfoForLCS-Arg", ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), fmt.Sprintf("ExtData_[%d]", len(v.ExtData_)), "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); orderErr_ != nil {
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

// MarshalBER encodes LCSRoutingInfoForLCSRes to BER format.
func (v *LCSRoutingInfoForLCSRes) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: LCSRoutingInfoForLCSRes receiver is nil", ber.ErrInvalidValue)
	}
	if v.berReplayNode_ == nil {
		return v.marshalBER(opts...)
	}
	var replayErr error
	opts, replayErr = ber.PrepareBERReplay(v.berReplayNode_, opts, func(mode ber.EncodeOption) ([]byte, error) { return v.MarshalBER([]ber.EncodeOption{mode}...) }, v)
	if replayErr != nil {
		return nil, replayErr
	}
	if replayBytes, ok := ber.PreparedBERReplay(v.berReplayNode_, opts); ok {
		return replayBytes, nil
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBERNode(encoded, v.berReplayNode_, opts), nil
}
func (v *LCSRoutingInfoForLCSRes) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	enc_targetms, err := v.TargetMS.MarshalBER(ber.ChildEncodeOptions(opts, "targetMS")...)
	if err != nil {
		return nil, qualifyBERError(err, "targetMS", "encoding", false)
	}
	{
		var encodeErr error
		enc_targetms, encodeErr = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 0, enc_targetms)
		if encodeErr != nil {
			return nil, qualifyBERError(encodeErr, "targetMS", "encoding", false)
		}
	}
	ber.RecordGeneratedBERChildPlacement(opts, len(children), enc_targetms)
	children = append(children, enc_targetms...)
	enc_lcslocationinfo, err := v.LcsLocationInfo.MarshalBER(ber.ChildEncodeOptions(opts, "lcsLocationInfo")...)
	if err != nil {
		return nil, qualifyBERError(err, "lcsLocationInfo", "encoding", false)
	}
	retagged_enc_lcslocationinfo, tagErr_enc_lcslocationinfo := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_lcslocationinfo)
	if tagErr_enc_lcslocationinfo != nil {
		return nil, qualifyBERError(tagErr_enc_lcslocationinfo, "lcsLocationInfo", "encoding", false)
	}
	enc_lcslocationinfo = retagged_enc_lcslocationinfo
	ber.RecordGeneratedBERChildPlacement(opts, len(children), enc_lcslocationinfo)
	children = append(children, enc_lcslocationinfo...)
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
		ber.RecordGeneratedBERChildPlacement(opts, len(children), enc_extensioncontainer)
		children = append(children, enc_extensioncontainer...)
	}
	if v.VGmlcAddress != nil {
		if len(*v.VGmlcAddress) < 5 || len(*v.VGmlcAddress) > 17 {
			if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(opts, "MAP-LCS-DataTypes.RoutingInfoForLCS-Res", ber.RuleRef{Document: "ITU-T X.680", Edition: "02/2021", Clause: "51.5"}), "v-gmlc-Address", "SIZE (5..17)", len(*v.VGmlcAddress)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_vgmlcaddress, encodeErr_enc_vgmlcaddress := ber.EncodeOctetString([]byte(*v.VGmlcAddress))
		if encodeErr_enc_vgmlcaddress != nil {
			return nil, qualifyBERError(encodeErr_enc_vgmlcaddress, "v-gmlc-Address", "encoding", false)
		}
		retagged_enc_vgmlcaddress, tagErr_enc_vgmlcaddress := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, enc_vgmlcaddress)
		if tagErr_enc_vgmlcaddress != nil {
			return nil, qualifyBERError(tagErr_enc_vgmlcaddress, "v-gmlc-Address", "encoding", false)
		}
		enc_vgmlcaddress = retagged_enc_vgmlcaddress
		children = append(children, enc_vgmlcaddress...)
	}
	if v.HGmlcAddress != nil {
		if len(*v.HGmlcAddress) < 5 || len(*v.HGmlcAddress) > 17 {
			if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(opts, "MAP-LCS-DataTypes.RoutingInfoForLCS-Res", ber.RuleRef{Document: "ITU-T X.680", Edition: "02/2021", Clause: "51.5"}), "h-gmlc-Address", "SIZE (5..17)", len(*v.HGmlcAddress)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_hgmlcaddress, encodeErr_enc_hgmlcaddress := ber.EncodeOctetString([]byte(*v.HGmlcAddress))
		if encodeErr_enc_hgmlcaddress != nil {
			return nil, qualifyBERError(encodeErr_enc_hgmlcaddress, "h-gmlc-Address", "encoding", false)
		}
		retagged_enc_hgmlcaddress, tagErr_enc_hgmlcaddress := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, enc_hgmlcaddress)
		if tagErr_enc_hgmlcaddress != nil {
			return nil, qualifyBERError(tagErr_enc_hgmlcaddress, "h-gmlc-Address", "encoding", false)
		}
		enc_hgmlcaddress = retagged_enc_hgmlcaddress
		children = append(children, enc_hgmlcaddress...)
	}
	if v.PprAddress != nil {
		if len(*v.PprAddress) < 5 || len(*v.PprAddress) > 17 {
			if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(opts, "MAP-LCS-DataTypes.RoutingInfoForLCS-Res", ber.RuleRef{Document: "ITU-T X.680", Edition: "02/2021", Clause: "51.5"}), "ppr-Address", "SIZE (5..17)", len(*v.PprAddress)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_ppraddress, encodeErr_enc_ppraddress := ber.EncodeOctetString([]byte(*v.PprAddress))
		if encodeErr_enc_ppraddress != nil {
			return nil, qualifyBERError(encodeErr_enc_ppraddress, "ppr-Address", "encoding", false)
		}
		retagged_enc_ppraddress, tagErr_enc_ppraddress := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 5, enc_ppraddress)
		if tagErr_enc_ppraddress != nil {
			return nil, qualifyBERError(tagErr_enc_ppraddress, "ppr-Address", "encoding", false)
		}
		enc_ppraddress = retagged_enc_ppraddress
		children = append(children, enc_ppraddress...)
	}
	if v.AdditionalVGmlcAddress != nil {
		if len(*v.AdditionalVGmlcAddress) < 5 || len(*v.AdditionalVGmlcAddress) > 17 {
			if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(opts, "MAP-LCS-DataTypes.RoutingInfoForLCS-Res", ber.RuleRef{Document: "ITU-T X.680", Edition: "02/2021", Clause: "51.5"}), "additional-v-gmlc-Address", "SIZE (5..17)", len(*v.AdditionalVGmlcAddress)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_additionalvgmlcaddress, encodeErr_enc_additionalvgmlcaddress := ber.EncodeOctetString([]byte(*v.AdditionalVGmlcAddress))
		if encodeErr_enc_additionalvgmlcaddress != nil {
			return nil, qualifyBERError(encodeErr_enc_additionalvgmlcaddress, "additional-v-gmlc-Address", "encoding", false)
		}
		retagged_enc_additionalvgmlcaddress, tagErr_enc_additionalvgmlcaddress := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 6, enc_additionalvgmlcaddress)
		if tagErr_enc_additionalvgmlcaddress != nil {
			return nil, qualifyBERError(tagErr_enc_additionalvgmlcaddress, "additional-v-gmlc-Address", "encoding", false)
		}
		enc_additionalvgmlcaddress = retagged_enc_additionalvgmlcaddress
		children = append(children, enc_additionalvgmlcaddress...)
	}
	for i, ext := range v.ExtData_ {
		if err := ber.CheckBEROpaqueElement(ext, opts...); err != nil {
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
		if i == 0 && ((peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 6) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 5) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2)) {
			if constraintErr := ber.CheckEncodedValue(ber.EncodeRule(opts, "MAP-LCS-DataTypes.RoutingInfoForLCS-Res", ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
				return nil, constraintErr
			}
		}
		children = append(children, ext...)
	}
	ber.RecordGeneratedBERContainer(opts, children)
	return ber.EncodeSequence(children)
}
func (v *LCSRoutingInfoForLCSRes) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// MarshalDER encodes LCSRoutingInfoForLCSRes to DER format.
// Opaque descendants pass generic DER checks; foreign schema rules need a typed binding.
func (v *LCSRoutingInfoForLCSRes) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: LCSRoutingInfoForLCSRes receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	enc_targetms, err := v.TargetMS.MarshalDER()
	if err != nil {
		return nil, qualifyBERError(err, "targetMS", "encoding", true)
	}
	{
		var encodeErr error
		enc_targetms, encodeErr = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 0, enc_targetms)
		if encodeErr != nil {
			return nil, qualifyBERError(encodeErr, "targetMS", "encoding", true)
		}
	}
	children = append(children, enc_targetms...)
	enc_lcslocationinfo, err := v.LcsLocationInfo.MarshalDER()
	if err != nil {
		return nil, qualifyBERError(err, "lcsLocationInfo", "encoding", true)
	}
	retagged_enc_lcslocationinfo, tagErr_enc_lcslocationinfo := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_lcslocationinfo)
	if tagErr_enc_lcslocationinfo != nil {
		return nil, qualifyBERError(tagErr_enc_lcslocationinfo, "lcsLocationInfo", "encoding", true)
	}
	enc_lcslocationinfo = retagged_enc_lcslocationinfo
	children = append(children, enc_lcslocationinfo...)
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
	if v.VGmlcAddress != nil {
		if len(*v.VGmlcAddress) < 5 || len(*v.VGmlcAddress) > 17 {
			if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(nil, "MAP-LCS-DataTypes.RoutingInfoForLCS-Res", ber.RuleRef{Document: "ITU-T X.680", Edition: "02/2021", Clause: "51.5"}), "v-gmlc-Address", "SIZE (5..17)", len(*v.VGmlcAddress)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_vgmlcaddress, encodeErr_enc_vgmlcaddress := ber.EncodeOctetString([]byte(*v.VGmlcAddress))
		if encodeErr_enc_vgmlcaddress != nil {
			return nil, qualifyBERError(encodeErr_enc_vgmlcaddress, "v-gmlc-Address", "encoding", true)
		}
		retagged_enc_vgmlcaddress, tagErr_enc_vgmlcaddress := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, enc_vgmlcaddress)
		if tagErr_enc_vgmlcaddress != nil {
			return nil, qualifyBERError(tagErr_enc_vgmlcaddress, "v-gmlc-Address", "encoding", true)
		}
		enc_vgmlcaddress = retagged_enc_vgmlcaddress
		children = append(children, enc_vgmlcaddress...)
	}
	if v.HGmlcAddress != nil {
		if len(*v.HGmlcAddress) < 5 || len(*v.HGmlcAddress) > 17 {
			if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(nil, "MAP-LCS-DataTypes.RoutingInfoForLCS-Res", ber.RuleRef{Document: "ITU-T X.680", Edition: "02/2021", Clause: "51.5"}), "h-gmlc-Address", "SIZE (5..17)", len(*v.HGmlcAddress)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_hgmlcaddress, encodeErr_enc_hgmlcaddress := ber.EncodeOctetString([]byte(*v.HGmlcAddress))
		if encodeErr_enc_hgmlcaddress != nil {
			return nil, qualifyBERError(encodeErr_enc_hgmlcaddress, "h-gmlc-Address", "encoding", true)
		}
		retagged_enc_hgmlcaddress, tagErr_enc_hgmlcaddress := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, enc_hgmlcaddress)
		if tagErr_enc_hgmlcaddress != nil {
			return nil, qualifyBERError(tagErr_enc_hgmlcaddress, "h-gmlc-Address", "encoding", true)
		}
		enc_hgmlcaddress = retagged_enc_hgmlcaddress
		children = append(children, enc_hgmlcaddress...)
	}
	if v.PprAddress != nil {
		if len(*v.PprAddress) < 5 || len(*v.PprAddress) > 17 {
			if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(nil, "MAP-LCS-DataTypes.RoutingInfoForLCS-Res", ber.RuleRef{Document: "ITU-T X.680", Edition: "02/2021", Clause: "51.5"}), "ppr-Address", "SIZE (5..17)", len(*v.PprAddress)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_ppraddress, encodeErr_enc_ppraddress := ber.EncodeOctetString([]byte(*v.PprAddress))
		if encodeErr_enc_ppraddress != nil {
			return nil, qualifyBERError(encodeErr_enc_ppraddress, "ppr-Address", "encoding", true)
		}
		retagged_enc_ppraddress, tagErr_enc_ppraddress := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 5, enc_ppraddress)
		if tagErr_enc_ppraddress != nil {
			return nil, qualifyBERError(tagErr_enc_ppraddress, "ppr-Address", "encoding", true)
		}
		enc_ppraddress = retagged_enc_ppraddress
		children = append(children, enc_ppraddress...)
	}
	if v.AdditionalVGmlcAddress != nil {
		if len(*v.AdditionalVGmlcAddress) < 5 || len(*v.AdditionalVGmlcAddress) > 17 {
			if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(nil, "MAP-LCS-DataTypes.RoutingInfoForLCS-Res", ber.RuleRef{Document: "ITU-T X.680", Edition: "02/2021", Clause: "51.5"}), "additional-v-gmlc-Address", "SIZE (5..17)", len(*v.AdditionalVGmlcAddress)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_additionalvgmlcaddress, encodeErr_enc_additionalvgmlcaddress := ber.EncodeOctetString([]byte(*v.AdditionalVGmlcAddress))
		if encodeErr_enc_additionalvgmlcaddress != nil {
			return nil, qualifyBERError(encodeErr_enc_additionalvgmlcaddress, "additional-v-gmlc-Address", "encoding", true)
		}
		retagged_enc_additionalvgmlcaddress, tagErr_enc_additionalvgmlcaddress := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 6, enc_additionalvgmlcaddress)
		if tagErr_enc_additionalvgmlcaddress != nil {
			return nil, qualifyBERError(tagErr_enc_additionalvgmlcaddress, "additional-v-gmlc-Address", "encoding", true)
		}
		enc_additionalvgmlcaddress = retagged_enc_additionalvgmlcaddress
		children = append(children, enc_additionalvgmlcaddress...)
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
		if i == 0 && ((peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 6) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 5) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2)) {
			if constraintErr := ber.CheckEncodedValue(ber.EncodeRule(nil, "MAP-LCS-DataTypes.RoutingInfoForLCS-Res", ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
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
		return nil, fmt.Errorf("%s: %w", "encoding LCSRoutingInfoForLCSRes as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}
func (v *LCSRoutingInfoForLCSRes) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	encoded, err := v.MarshalDER()
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBER decodes LCSRoutingInfoForLCSRes from BER/DER format.
func (destination *LCSRoutingInfoForLCSRes) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if destination == nil {
		return fmt.Errorf("%w: LCSRoutingInfoForLCSRes destination is nil", ber.ErrInvalidValue)
	}
	var berNextValue_ LCSRoutingInfoForLCSRes
	v := &berNextValue_

	defer func() {
		if returnErr ==
			nil {
			*destination = *v
		}
	}()

	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	ownedData, ownErr := ber.OwnGeneratedBERInput(data, opts)
	if ownErr != nil {
		return ownErr
	}
	data = ownedData
	preparedData, preparedOptions, prepareErr := ber.PrepareGeneratedBERInput(data, opts)
	if prepareErr != nil {
		return ber.DiagnosePreflight(prepareErr, data, opts, "child", func(probeOpts []ber.DecodeOption) error {
			var probe LCSRoutingInfoForLCSRes
			return probe.UnmarshalBER(data, probeOpts...)
		})
	}
	data, opts = preparedData, preparedOptions
	opts = ber.LocateDecodedElement(data, "MAP-LCS-DataTypes.RoutingInfoForLCS-Res", opts)
	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
	*v = LCSRoutingInfoForLCSRes{}
	defer func() {
		if returnErr != nil || !ber.BERNeedsPreservation(opts) {
			return
		}
		v.berReplayNode_ = ber.CaptureGeneratedBERReplay(data, opts)
		returnErr = ber.CompleteGeneratedBERDecode(opts, v, func(base *LCSRoutingInfoForLCSRes, replayOpts ...ber.EncodeOption) ([]byte, error) {
			return base.MarshalBER(replayOpts...)
		})
	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("%s: %w", "decoding LCSRoutingInfoForLCSRes SEQUENCE", qualifyBERError(err, "", "decoding", false))
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
	{
		ber.MarkPreflightTarget(opts, "targetMS", content[offset:])
		decodedTag_targetms, n_targetms, innerData_targetms, err := ber.DecodeTLV(content[offset:], opts...)
		if err != nil {
			return qualifyBERError(err, "targetMS", "decoding", false)
		}
		if decodedTag_targetms.Class != tag.ClassContextSpecific || decodedTag_targetms.Number != 0 || decodedTag_targetms.Constructed != true {
			return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_targetms), "targetMS", "decoding", false)
		}
		_, innerUsed_targetms, _, innerErr_targetms := ber.DecodeTLV(innerData_targetms, opts...)
		if innerErr_targetms != nil {
			return qualifyBERError(innerErr_targetms, "targetMS", "decoding", false)
		}
		if innerUsed_targetms != len(innerData_targetms) {
			return qualifyBERError(ber.ErrExtraData, "targetMS", "decoding", false)
		}
		// Decode inner value from explicit tag wrapper
		ber.MarkPreflightTarget(opts, "targetMS", innerData_targetms)
		if unmErr := v.TargetMS.UnmarshalBER(innerData_targetms, ber.ChildDecodeOptions(opts, "targetMS")...); unmErr != nil {
			return qualifyBERError(unmErr, "targetMS", "decoding", false)
		}
		if offset > len(content) || n_targetms < 0 || n_targetms > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n_targetms
	}
	// Decode lcsLocationInfo
	if offset >= len(content) {
		return fmt.Errorf("missing required field lcsLocationInfo")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 1 {
			return fmt.Errorf("expected tag [%s %d] for lcsLocationInfo, got %s", "CONTEXT", 1, reqTag_)
		}
	}
	{
		ber.MarkPreflightTarget(opts, "lcsLocationInfo", content[offset:])
		decodedTag_lcslocationinfo, n_lcslocationinfo, rawVal_lcslocationinfo, err := ber.DecodeTLV(content[offset:], opts...)
		if err != nil {
			return qualifyBERError(err, "lcsLocationInfo", "decoding", false)
		}
		if decodedTag_lcslocationinfo.Class != tag.ClassContextSpecific || decodedTag_lcslocationinfo.Number != 1 || decodedTag_lcslocationinfo.Constructed != true {
			return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_lcslocationinfo), "lcsLocationInfo", "decoding", false)
		}
		_ = rawVal_lcslocationinfo
		if offset < 0 || offset >
			len(content) || n_lcslocationinfo < 0 || n_lcslocationinfo > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		reconstructed_lcslocationinfo, reconstructionErr_lcslocationinfo := ber.EncodeImplicitTagWithClass(tag.ClassUniversal, tag.TagSequence, content[offset:offset+n_lcslocationinfo])
		if reconstructionErr_lcslocationinfo != nil {
			return qualifyBERError(reconstructionErr_lcslocationinfo, "lcsLocationInfo", "decoding", false)
		}
		if unmErr := v.LcsLocationInfo.UnmarshalBER(reconstructed_lcslocationinfo, ber.ChildDecodeOptions(opts, "lcsLocationInfo")...); unmErr != nil {
			return qualifyBERError(unmErr, "lcsLocationInfo", "decoding", false)
		}
		if offset < 0 || offset >
			len(content) || n_lcslocationinfo < 0 || n_lcslocationinfo > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n_lcslocationinfo
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
				_ = rawVal_extensioncontainer
				if offset < 0 || offset >
					len(content) || n_extensioncontainer < 0 || n_extensioncontainer >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				reconstructed_extensioncontainer, reconstructionErr_extensioncontainer := ber.EncodeImplicitTagWithClass(tag.ClassUniversal, tag.TagSequence, content[offset:offset+n_extensioncontainer])
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
	// Decode v-gmlc-Address
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3 {
				ber.MarkPreflightTarget(opts, "v-gmlc-Address", content[offset:])
				decodedTag_vgmlcaddress, n_vgmlcaddress, rawVal_vgmlcaddress, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "v-gmlc-Address", "decoding", false)
				}
				if decodedTag_vgmlcaddress.Class != tag.ClassContextSpecific || decodedTag_vgmlcaddress.Number != 3 {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_vgmlcaddress), "v-gmlc-Address", "decoding", false)
				}
				decVal_vgmlcaddress, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_vgmlcaddress.Constructed, rawVal_vgmlcaddress, opts...)
				if octetErr != nil {
					return qualifyBERError(octetErr, "v-gmlc-Address", "decoding", false)
				}
				tmp_vgmlcaddress := v21_map_commondatatypes.CommonDataTypesGSNAddress(decVal_vgmlcaddress)
				v.VGmlcAddress = &tmp_vgmlcaddress
				if offset < 0 || offset >
					len(content) || n_vgmlcaddress < 0 || n_vgmlcaddress > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_vgmlcaddress
				if len(*v.VGmlcAddress) < 5 || len(*v.VGmlcAddress) > 17 {
					if constraintErr := ber.CheckDecodedLength(ber.DecodeRule(opts, "MAP-LCS-DataTypes.RoutingInfoForLCS-Res", ber.RuleRef{Document: "ITU-T X.680", Edition: "02/2021", Clause: "51.5"}), "v-gmlc-Address", "SIZE (5..17)", len(*v.VGmlcAddress)); constraintErr != nil {
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
				ber.MarkPreflightTarget(opts, "h-gmlc-Address", content[offset:])
				decodedTag_hgmlcaddress, n_hgmlcaddress, rawVal_hgmlcaddress, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "h-gmlc-Address", "decoding", false)
				}
				if decodedTag_hgmlcaddress.Class != tag.ClassContextSpecific || decodedTag_hgmlcaddress.Number != 4 {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_hgmlcaddress), "h-gmlc-Address", "decoding", false)
				}
				decVal_hgmlcaddress, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_hgmlcaddress.Constructed, rawVal_hgmlcaddress, opts...)
				if octetErr != nil {
					return qualifyBERError(octetErr, "h-gmlc-Address", "decoding", false)
				}
				tmp_hgmlcaddress := v21_map_commondatatypes.CommonDataTypesGSNAddress(decVal_hgmlcaddress)
				v.HGmlcAddress = &tmp_hgmlcaddress
				if offset < 0 || offset >
					len(content) || n_hgmlcaddress < 0 || n_hgmlcaddress > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_hgmlcaddress
				if len(*v.HGmlcAddress) < 5 || len(*v.HGmlcAddress) > 17 {
					if constraintErr := ber.CheckDecodedLength(ber.DecodeRule(opts, "MAP-LCS-DataTypes.RoutingInfoForLCS-Res", ber.RuleRef{Document: "ITU-T X.680", Edition: "02/2021", Clause: "51.5"}), "h-gmlc-Address", "SIZE (5..17)", len(*v.HGmlcAddress)); constraintErr != nil {
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
				ber.MarkPreflightTarget(opts, "ppr-Address", content[offset:])
				decodedTag_ppraddress, n_ppraddress, rawVal_ppraddress, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "ppr-Address", "decoding", false)
				}
				if decodedTag_ppraddress.Class != tag.ClassContextSpecific || decodedTag_ppraddress.Number != 5 {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_ppraddress), "ppr-Address", "decoding", false)
				}
				decVal_ppraddress, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_ppraddress.Constructed, rawVal_ppraddress, opts...)
				if octetErr != nil {
					return qualifyBERError(octetErr, "ppr-Address", "decoding", false)
				}
				tmp_ppraddress := v21_map_commondatatypes.CommonDataTypesGSNAddress(decVal_ppraddress)
				v.PprAddress = &tmp_ppraddress
				if offset < 0 || offset >
					len(content) || n_ppraddress < 0 || n_ppraddress > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_ppraddress
				if len(*v.PprAddress) < 5 || len(*v.PprAddress) > 17 {
					if constraintErr := ber.CheckDecodedLength(ber.DecodeRule(opts, "MAP-LCS-DataTypes.RoutingInfoForLCS-Res", ber.RuleRef{Document: "ITU-T X.680", Edition: "02/2021", Clause: "51.5"}), "ppr-Address", "SIZE (5..17)", len(*v.PprAddress)); constraintErr != nil {
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
				ber.MarkPreflightTarget(opts, "additional-v-gmlc-Address", content[offset:])
				decodedTag_additionalvgmlcaddress, n_additionalvgmlcaddress, rawVal_additionalvgmlcaddress, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "additional-v-gmlc-Address", "decoding", false)
				}
				if decodedTag_additionalvgmlcaddress.Class != tag.ClassContextSpecific || decodedTag_additionalvgmlcaddress.Number != 6 {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_additionalvgmlcaddress), "additional-v-gmlc-Address", "decoding", false)
				}
				decVal_additionalvgmlcaddress, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_additionalvgmlcaddress.Constructed, rawVal_additionalvgmlcaddress, opts...)
				if octetErr != nil {
					return qualifyBERError(octetErr, "additional-v-gmlc-Address", "decoding", false)
				}
				tmp_additionalvgmlcaddress := v21_map_commondatatypes.CommonDataTypesGSNAddress(decVal_additionalvgmlcaddress)
				v.AdditionalVGmlcAddress = &tmp_additionalvgmlcaddress
				if offset < 0 || offset >
					len(content) || n_additionalvgmlcaddress < 0 || n_additionalvgmlcaddress >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_additionalvgmlcaddress
				if len(*v.AdditionalVGmlcAddress) < 5 || len(*v.AdditionalVGmlcAddress) > 17 {
					if constraintErr := ber.CheckDecodedLength(ber.DecodeRule(opts, "MAP-LCS-DataTypes.RoutingInfoForLCS-Res", ber.RuleRef{Document: "ITU-T X.680", Edition: "02/2021", Clause: "51.5"}), "additional-v-gmlc-Address", "SIZE (5..17)", len(*v.AdditionalVGmlcAddress)); constraintErr != nil {
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
			return &ber.DecodeError{Offset: offset, TypeName: "LCSRoutingInfoForLCSRes", Cause: extErr_}
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: the first unknown addition must differ from trailing OPTIONAL/DEFAULT tags.
		if len(v.ExtData_) == 0 && ((peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 6) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 5) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2)) {
			if !ber.ToleranceEnabled(opts) {
				return &ber.DecodeError{Offset: offset, TypeName: "LCSRoutingInfoForLCSRes", Cause: fmt.Errorf("%w: repeated or out-of-order SEQUENCE component tag %s", ber.ErrInvalidTag, peekTag)}
			}
			if orderErr_ := ber.CheckDecodedValue(ber.DecodeRule(opts, "MAP-LCS-DataTypes.RoutingInfoForLCS-Res", ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), fmt.Sprintf("ExtData_[%d]", len(v.ExtData_)), "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); orderErr_ != nil {
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

// MarshalBER encodes LCSLCSLocationInfo to BER format.
func (v *LCSLCSLocationInfo) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: LCSLCSLocationInfo receiver is nil", ber.ErrInvalidValue)
	}
	if v.berReplayNode_ == nil {
		return v.marshalBER(opts...)
	}
	var replayErr error
	opts, replayErr = ber.PrepareBERReplay(v.berReplayNode_, opts, func(mode ber.EncodeOption) ([]byte, error) { return v.MarshalBER([]ber.EncodeOption{mode}...) }, v)
	if replayErr != nil {
		return nil, replayErr
	}
	if replayBytes, ok := ber.PreparedBERReplay(v.berReplayNode_, opts); ok {
		return replayBytes, nil
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBERNode(encoded, v.berReplayNode_, opts), nil
}
func (v *LCSLCSLocationInfo) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if len(v.NetworkNodeNumber) < 1 || len(v.NetworkNodeNumber) > 9 {
		if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(opts, "MAP-LCS-DataTypes.LCSLocationInfo", ber.RuleRef{Document: "ITU-T X.680", Edition: "02/2021", Clause: "51.5"}), "networkNode-Number", "SIZE (1..9)", len(v.NetworkNodeNumber)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	if len(v.NetworkNodeNumber) < 1 || len(v.NetworkNodeNumber) > 20 {
		if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(opts, "MAP-LCS-DataTypes.LCSLocationInfo", ber.RuleRef{Document: "ITU-T X.680", Edition: "02/2021", Clause: "51.5"}), "networkNode-Number", "SIZE (1..20)", len(v.NetworkNodeNumber)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_networknodenumber, encodeErr_enc_networknodenumber := ber.EncodeOctetString([]byte(v.NetworkNodeNumber))
	if encodeErr_enc_networknodenumber != nil {
		return nil, qualifyBERError(encodeErr_enc_networknodenumber, "networkNode-Number", "encoding", false)
	}
	children = append(children, enc_networknodenumber...)
	if v.Lmsi != nil {
		if len(*v.Lmsi) < 4 || len(*v.Lmsi) > 4 {
			if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(opts, "MAP-LCS-DataTypes.LCSLocationInfo", ber.RuleRef{Document: "ITU-T X.680", Edition: "02/2021", Clause: "51.5"}), "lmsi", "SIZE (4)", len(*v.Lmsi)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_lmsi, encodeErr_enc_lmsi := ber.EncodeOctetString([]byte(*v.Lmsi))
		if encodeErr_enc_lmsi != nil {
			return nil, qualifyBERError(encodeErr_enc_lmsi, "lmsi", "encoding", false)
		}
		retagged_enc_lmsi, tagErr_enc_lmsi := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_lmsi)
		if tagErr_enc_lmsi != nil {
			return nil, qualifyBERError(tagErr_enc_lmsi, "lmsi", "encoding", false)
		}
		enc_lmsi = retagged_enc_lmsi
		children = append(children, enc_lmsi...)
	}
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalBER(ber.ChildEncodeOptions(opts, "extensionContainer")...)
		if err != nil {
			return nil, qualifyBERError(err, "extensionContainer", "encoding", false)
		}
		retagged_enc_extensioncontainer, tagErr_enc_extensioncontainer := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_extensioncontainer)
		if tagErr_enc_extensioncontainer != nil {
			return nil, qualifyBERError(tagErr_enc_extensioncontainer, "extensionContainer", "encoding", false)
		}
		enc_extensioncontainer = retagged_enc_extensioncontainer
		ber.RecordGeneratedBERChildPlacement(opts, len(children), enc_extensioncontainer)
		children = append(children, enc_extensioncontainer...)
	}
	if v.GprsNodeIndicator != nil {
		enc_gprsnodeindicator := ber.EncodeNull()
		retagged_enc_gprsnodeindicator, tagErr_enc_gprsnodeindicator := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_gprsnodeindicator)
		if tagErr_enc_gprsnodeindicator != nil {
			return nil, qualifyBERError(tagErr_enc_gprsnodeindicator, "gprsNodeIndicator", "encoding", false)
		}
		enc_gprsnodeindicator = retagged_enc_gprsnodeindicator
		children = append(children, enc_gprsnodeindicator...)
	}
	if v.AdditionalNumber != nil {
		enc_additionalnumber, err := v.AdditionalNumber.MarshalBER(ber.ChildEncodeOptions(opts, "additional-Number")...)
		if err != nil {
			return nil, qualifyBERError(err, "additional-Number", "encoding", false)
		}
		{
			var encodeErr error
			enc_additionalnumber, encodeErr = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 3, enc_additionalnumber)
			if encodeErr != nil {
				return nil, qualifyBERError(encodeErr, "additional-Number", "encoding", false)
			}
		}
		ber.RecordGeneratedBERChildPlacement(opts, len(children), enc_additionalnumber)
		children = append(children, enc_additionalnumber...)
	}
	if v.SupportedLCSCapabilitySets != nil {
		if bitStringErr := ber.ValidateBitStringLength(v.SupportedLCSCapabilitySets.Bytes, v.SupportedLCSCapabilitySets.BitLength); bitStringErr != nil {
			return nil, qualifyBERError(bitStringErr, "supportedLCS-CapabilitySets", "encoding", false)
		}
		// arithmetic pattern BER_BITSTRING_FIELD: 0 <= bit length before modulo and subtraction; gen/codegen.go:743
		if v.SupportedLCSCapabilitySets.BitLength < 0 {
			return nil, fmt.Errorf("negative bit string length")
		}
		if (*v.SupportedLCSCapabilitySets).BitLength < 2 || (*v.SupportedLCSCapabilitySets).BitLength > 16 {
			if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(opts, "MAP-LCS-DataTypes.LCSLocationInfo", ber.RuleRef{Document: "ITU-T X.680", Edition: "02/2021", Clause: "51.5"}), "supportedLCS-CapabilitySets", "SIZE (2..16)", (*v.SupportedLCSCapabilitySets).BitLength); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_supportedlcscapabilitysets, encodeErr_enc_supportedlcscapabilitysets := ber.EncodeBitString(v.SupportedLCSCapabilitySets.Bytes, ber.UnusedBitCount(v.SupportedLCSCapabilitySets.BitLength))
		if encodeErr_enc_supportedlcscapabilitysets != nil {
			return nil, qualifyBERError(encodeErr_enc_supportedlcscapabilitysets, "supportedLCS-CapabilitySets", "encoding", false)
		}
		retagged_enc_supportedlcscapabilitysets, tagErr_enc_supportedlcscapabilitysets := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, enc_supportedlcscapabilitysets)
		if tagErr_enc_supportedlcscapabilitysets != nil {
			return nil, qualifyBERError(tagErr_enc_supportedlcscapabilitysets, "supportedLCS-CapabilitySets", "encoding", false)
		}
		enc_supportedlcscapabilitysets = retagged_enc_supportedlcscapabilitysets
		children = append(children, enc_supportedlcscapabilitysets...)
	}
	if v.AdditionalLCSCapabilitySets != nil {
		if bitStringErr := ber.ValidateBitStringLength(v.AdditionalLCSCapabilitySets.Bytes, v.AdditionalLCSCapabilitySets.BitLength); bitStringErr != nil {
			return nil, qualifyBERError(bitStringErr, "additional-LCS-CapabilitySets", "encoding", false)
		}
		// arithmetic pattern BER_BITSTRING_FIELD: 0 <= bit length before modulo and subtraction; gen/codegen.go:743
		if v.AdditionalLCSCapabilitySets.BitLength < 0 {
			return nil, fmt.Errorf("negative bit string length")
		}
		if (*v.AdditionalLCSCapabilitySets).BitLength < 2 || (*v.AdditionalLCSCapabilitySets).BitLength > 16 {
			if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(opts, "MAP-LCS-DataTypes.LCSLocationInfo", ber.RuleRef{Document: "ITU-T X.680", Edition: "02/2021", Clause: "51.5"}), "additional-LCS-CapabilitySets", "SIZE (2..16)", (*v.AdditionalLCSCapabilitySets).BitLength); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_additionallcscapabilitysets, encodeErr_enc_additionallcscapabilitysets := ber.EncodeBitString(v.AdditionalLCSCapabilitySets.Bytes, ber.UnusedBitCount(v.AdditionalLCSCapabilitySets.BitLength))
		if encodeErr_enc_additionallcscapabilitysets != nil {
			return nil, qualifyBERError(encodeErr_enc_additionallcscapabilitysets, "additional-LCS-CapabilitySets", "encoding", false)
		}
		retagged_enc_additionallcscapabilitysets, tagErr_enc_additionallcscapabilitysets := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 5, enc_additionallcscapabilitysets)
		if tagErr_enc_additionallcscapabilitysets != nil {
			return nil, qualifyBERError(tagErr_enc_additionallcscapabilitysets, "additional-LCS-CapabilitySets", "encoding", false)
		}
		enc_additionallcscapabilitysets = retagged_enc_additionallcscapabilitysets
		children = append(children, enc_additionallcscapabilitysets...)
	}
	if v.MmeName != nil {
		if len(*v.MmeName) < 9 || len(*v.MmeName) > 255 {
			if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(opts, "MAP-LCS-DataTypes.LCSLocationInfo", ber.RuleRef{Document: "ITU-T X.680", Edition: "02/2021", Clause: "51.5"}), "mme-Name", "SIZE (9..255)", len(*v.MmeName)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_mmename, encodeErr_enc_mmename := ber.EncodeOctetString([]byte(*v.MmeName))
		if encodeErr_enc_mmename != nil {
			return nil, qualifyBERError(encodeErr_enc_mmename, "mme-Name", "encoding", false)
		}
		retagged_enc_mmename, tagErr_enc_mmename := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 6, enc_mmename)
		if tagErr_enc_mmename != nil {
			return nil, qualifyBERError(tagErr_enc_mmename, "mme-Name", "encoding", false)
		}
		enc_mmename = retagged_enc_mmename
		children = append(children, enc_mmename...)
	}
	if v.AaaServerName != nil {
		if len(*v.AaaServerName) < 9 || len(*v.AaaServerName) > 255 {
			if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(opts, "MAP-LCS-DataTypes.LCSLocationInfo", ber.RuleRef{Document: "ITU-T X.680", Edition: "02/2021", Clause: "51.5"}), "aaa-Server-Name", "SIZE (9..255)", len(*v.AaaServerName)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_aaaservername, encodeErr_enc_aaaservername := ber.EncodeOctetString([]byte(*v.AaaServerName))
		if encodeErr_enc_aaaservername != nil {
			return nil, qualifyBERError(encodeErr_enc_aaaservername, "aaa-Server-Name", "encoding", false)
		}
		retagged_enc_aaaservername, tagErr_enc_aaaservername := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 8, enc_aaaservername)
		if tagErr_enc_aaaservername != nil {
			return nil, qualifyBERError(tagErr_enc_aaaservername, "aaa-Server-Name", "encoding", false)
		}
		enc_aaaservername = retagged_enc_aaaservername
		children = append(children, enc_aaaservername...)
	}
	if v.SgsnName != nil {
		if len(*v.SgsnName) < 9 || len(*v.SgsnName) > 255 {
			if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(opts, "MAP-LCS-DataTypes.LCSLocationInfo", ber.RuleRef{Document: "ITU-T X.680", Edition: "02/2021", Clause: "51.5"}), "sgsn-Name", "SIZE (9..255)", len(*v.SgsnName)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_sgsnname, encodeErr_enc_sgsnname := ber.EncodeOctetString([]byte(*v.SgsnName))
		if encodeErr_enc_sgsnname != nil {
			return nil, qualifyBERError(encodeErr_enc_sgsnname, "sgsn-Name", "encoding", false)
		}
		retagged_enc_sgsnname, tagErr_enc_sgsnname := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 9, enc_sgsnname)
		if tagErr_enc_sgsnname != nil {
			return nil, qualifyBERError(tagErr_enc_sgsnname, "sgsn-Name", "encoding", false)
		}
		enc_sgsnname = retagged_enc_sgsnname
		children = append(children, enc_sgsnname...)
	}
	if v.SgsnRealm != nil {
		if len(*v.SgsnRealm) < 9 || len(*v.SgsnRealm) > 255 {
			if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(opts, "MAP-LCS-DataTypes.LCSLocationInfo", ber.RuleRef{Document: "ITU-T X.680", Edition: "02/2021", Clause: "51.5"}), "sgsn-Realm", "SIZE (9..255)", len(*v.SgsnRealm)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_sgsnrealm, encodeErr_enc_sgsnrealm := ber.EncodeOctetString([]byte(*v.SgsnRealm))
		if encodeErr_enc_sgsnrealm != nil {
			return nil, qualifyBERError(encodeErr_enc_sgsnrealm, "sgsn-Realm", "encoding", false)
		}
		retagged_enc_sgsnrealm, tagErr_enc_sgsnrealm := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 10, enc_sgsnrealm)
		if tagErr_enc_sgsnrealm != nil {
			return nil, qualifyBERError(tagErr_enc_sgsnrealm, "sgsn-Realm", "encoding", false)
		}
		enc_sgsnrealm = retagged_enc_sgsnrealm
		children = append(children, enc_sgsnrealm...)
	}
	for i, ext := range v.ExtData_ {
		if err := ber.CheckBEROpaqueElement(ext, opts...); err != nil {
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
		if i == 0 && ((peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 10) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 9) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 8) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 6) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 5) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0)) {
			if constraintErr := ber.CheckEncodedValue(ber.EncodeRule(opts, "MAP-LCS-DataTypes.LCSLocationInfo", ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
				return nil, constraintErr
			}
		}
		children = append(children, ext...)
	}
	ber.RecordGeneratedBERContainer(opts, children)
	return ber.EncodeSequence(children)
}
func (v *LCSLCSLocationInfo) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// MarshalDER encodes LCSLCSLocationInfo to DER format.
// Opaque descendants pass generic DER checks; foreign schema rules need a typed binding.
func (v *LCSLCSLocationInfo) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: LCSLCSLocationInfo receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if len(v.NetworkNodeNumber) < 1 || len(v.NetworkNodeNumber) > 9 {
		if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(nil, "MAP-LCS-DataTypes.LCSLocationInfo", ber.RuleRef{Document: "ITU-T X.680", Edition: "02/2021", Clause: "51.5"}), "networkNode-Number", "SIZE (1..9)", len(v.NetworkNodeNumber)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	if len(v.NetworkNodeNumber) < 1 || len(v.NetworkNodeNumber) > 20 {
		if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(nil, "MAP-LCS-DataTypes.LCSLocationInfo", ber.RuleRef{Document: "ITU-T X.680", Edition: "02/2021", Clause: "51.5"}), "networkNode-Number", "SIZE (1..20)", len(v.NetworkNodeNumber)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_networknodenumber, encodeErr_enc_networknodenumber := ber.EncodeOctetString([]byte(v.NetworkNodeNumber))
	if encodeErr_enc_networknodenumber != nil {
		return nil, qualifyBERError(encodeErr_enc_networknodenumber, "networkNode-Number", "encoding", true)
	}
	children = append(children, enc_networknodenumber...)
	if v.Lmsi != nil {
		if len(*v.Lmsi) < 4 || len(*v.Lmsi) > 4 {
			if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(nil, "MAP-LCS-DataTypes.LCSLocationInfo", ber.RuleRef{Document: "ITU-T X.680", Edition: "02/2021", Clause: "51.5"}), "lmsi", "SIZE (4)", len(*v.Lmsi)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_lmsi, encodeErr_enc_lmsi := ber.EncodeOctetString([]byte(*v.Lmsi))
		if encodeErr_enc_lmsi != nil {
			return nil, qualifyBERError(encodeErr_enc_lmsi, "lmsi", "encoding", true)
		}
		retagged_enc_lmsi, tagErr_enc_lmsi := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_lmsi)
		if tagErr_enc_lmsi != nil {
			return nil, qualifyBERError(tagErr_enc_lmsi, "lmsi", "encoding", true)
		}
		enc_lmsi = retagged_enc_lmsi
		children = append(children, enc_lmsi...)
	}
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalDER()
		if err != nil {
			return nil, qualifyBERError(err, "extensionContainer", "encoding", true)
		}
		retagged_enc_extensioncontainer, tagErr_enc_extensioncontainer := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_extensioncontainer)
		if tagErr_enc_extensioncontainer != nil {
			return nil, qualifyBERError(tagErr_enc_extensioncontainer, "extensionContainer", "encoding", true)
		}
		enc_extensioncontainer = retagged_enc_extensioncontainer
		children = append(children, enc_extensioncontainer...)
	}
	if v.GprsNodeIndicator != nil {
		enc_gprsnodeindicator := ber.EncodeNull()
		retagged_enc_gprsnodeindicator, tagErr_enc_gprsnodeindicator := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_gprsnodeindicator)
		if tagErr_enc_gprsnodeindicator != nil {
			return nil, qualifyBERError(tagErr_enc_gprsnodeindicator, "gprsNodeIndicator", "encoding", true)
		}
		enc_gprsnodeindicator = retagged_enc_gprsnodeindicator
		children = append(children, enc_gprsnodeindicator...)
	}
	if v.AdditionalNumber != nil {
		enc_additionalnumber, err := v.AdditionalNumber.MarshalDER()
		if err != nil {
			return nil, qualifyBERError(err, "additional-Number", "encoding", true)
		}
		{
			var encodeErr error
			enc_additionalnumber, encodeErr = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 3, enc_additionalnumber)
			if encodeErr != nil {
				return nil, qualifyBERError(encodeErr, "additional-Number", "encoding", true)
			}
		}
		children = append(children, enc_additionalnumber...)
	}
	if v.SupportedLCSCapabilitySets != nil {
		if bitStringErr := ber.ValidateBitStringLength(v.SupportedLCSCapabilitySets.Bytes, v.SupportedLCSCapabilitySets.BitLength); bitStringErr != nil {
			return nil, qualifyBERError(bitStringErr, "supportedLCS-CapabilitySets", "encoding", true)
		}
		if bitStringErr := ber.ValidateDERBitString(v.SupportedLCSCapabilitySets.Bytes, v.SupportedLCSCapabilitySets.BitLength); bitStringErr != nil {
			return nil, qualifyBERError(bitStringErr, "supportedLCS-CapabilitySets", "encoding", true)
		}
		// arithmetic pattern BER_BITSTRING_FIELD: 0 <= bit length before modulo and subtraction; gen/codegen.go:743
		if v.SupportedLCSCapabilitySets.BitLength < 0 {
			return nil, fmt.Errorf("negative bit string length")
		}
		if (*v.SupportedLCSCapabilitySets).BitLength < 2 || (*v.SupportedLCSCapabilitySets).BitLength > 16 {
			if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(nil, "MAP-LCS-DataTypes.LCSLocationInfo", ber.RuleRef{Document: "ITU-T X.680", Edition: "02/2021", Clause: "51.5"}), "supportedLCS-CapabilitySets", "SIZE (2..16)", (*v.SupportedLCSCapabilitySets).BitLength); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_supportedlcscapabilitysets, encodeErr_enc_supportedlcscapabilitysets := ber.EncodeDERNamedBitString(v.SupportedLCSCapabilitySets.Bytes, v.SupportedLCSCapabilitySets.BitLength)
		if encodeErr_enc_supportedlcscapabilitysets != nil {
			return nil, qualifyBERError(encodeErr_enc_supportedlcscapabilitysets, "supportedLCS-CapabilitySets", "encoding", true)
		}
		retagged_enc_supportedlcscapabilitysets, tagErr_enc_supportedlcscapabilitysets := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, enc_supportedlcscapabilitysets)
		if tagErr_enc_supportedlcscapabilitysets != nil {
			return nil, qualifyBERError(tagErr_enc_supportedlcscapabilitysets, "supportedLCS-CapabilitySets", "encoding", true)
		}
		enc_supportedlcscapabilitysets = retagged_enc_supportedlcscapabilitysets
		children = append(children, enc_supportedlcscapabilitysets...)
	}
	if v.AdditionalLCSCapabilitySets != nil {
		if bitStringErr := ber.ValidateBitStringLength(v.AdditionalLCSCapabilitySets.Bytes, v.AdditionalLCSCapabilitySets.BitLength); bitStringErr != nil {
			return nil, qualifyBERError(bitStringErr, "additional-LCS-CapabilitySets", "encoding", true)
		}
		if bitStringErr := ber.ValidateDERBitString(v.AdditionalLCSCapabilitySets.Bytes, v.AdditionalLCSCapabilitySets.BitLength); bitStringErr != nil {
			return nil, qualifyBERError(bitStringErr, "additional-LCS-CapabilitySets", "encoding", true)
		}
		// arithmetic pattern BER_BITSTRING_FIELD: 0 <= bit length before modulo and subtraction; gen/codegen.go:743
		if v.AdditionalLCSCapabilitySets.BitLength < 0 {
			return nil, fmt.Errorf("negative bit string length")
		}
		if (*v.AdditionalLCSCapabilitySets).BitLength < 2 || (*v.AdditionalLCSCapabilitySets).BitLength > 16 {
			if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(nil, "MAP-LCS-DataTypes.LCSLocationInfo", ber.RuleRef{Document: "ITU-T X.680", Edition: "02/2021", Clause: "51.5"}), "additional-LCS-CapabilitySets", "SIZE (2..16)", (*v.AdditionalLCSCapabilitySets).BitLength); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_additionallcscapabilitysets, encodeErr_enc_additionallcscapabilitysets := ber.EncodeDERNamedBitString(v.AdditionalLCSCapabilitySets.Bytes, v.AdditionalLCSCapabilitySets.BitLength)
		if encodeErr_enc_additionallcscapabilitysets != nil {
			return nil, qualifyBERError(encodeErr_enc_additionallcscapabilitysets, "additional-LCS-CapabilitySets", "encoding", true)
		}
		retagged_enc_additionallcscapabilitysets, tagErr_enc_additionallcscapabilitysets := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 5, enc_additionallcscapabilitysets)
		if tagErr_enc_additionallcscapabilitysets != nil {
			return nil, qualifyBERError(tagErr_enc_additionallcscapabilitysets, "additional-LCS-CapabilitySets", "encoding", true)
		}
		enc_additionallcscapabilitysets = retagged_enc_additionallcscapabilitysets
		children = append(children, enc_additionallcscapabilitysets...)
	}
	if v.MmeName != nil {
		if len(*v.MmeName) < 9 || len(*v.MmeName) > 255 {
			if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(nil, "MAP-LCS-DataTypes.LCSLocationInfo", ber.RuleRef{Document: "ITU-T X.680", Edition: "02/2021", Clause: "51.5"}), "mme-Name", "SIZE (9..255)", len(*v.MmeName)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_mmename, encodeErr_enc_mmename := ber.EncodeOctetString([]byte(*v.MmeName))
		if encodeErr_enc_mmename != nil {
			return nil, qualifyBERError(encodeErr_enc_mmename, "mme-Name", "encoding", true)
		}
		retagged_enc_mmename, tagErr_enc_mmename := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 6, enc_mmename)
		if tagErr_enc_mmename != nil {
			return nil, qualifyBERError(tagErr_enc_mmename, "mme-Name", "encoding", true)
		}
		enc_mmename = retagged_enc_mmename
		children = append(children, enc_mmename...)
	}
	if v.AaaServerName != nil {
		if len(*v.AaaServerName) < 9 || len(*v.AaaServerName) > 255 {
			if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(nil, "MAP-LCS-DataTypes.LCSLocationInfo", ber.RuleRef{Document: "ITU-T X.680", Edition: "02/2021", Clause: "51.5"}), "aaa-Server-Name", "SIZE (9..255)", len(*v.AaaServerName)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_aaaservername, encodeErr_enc_aaaservername := ber.EncodeOctetString([]byte(*v.AaaServerName))
		if encodeErr_enc_aaaservername != nil {
			return nil, qualifyBERError(encodeErr_enc_aaaservername, "aaa-Server-Name", "encoding", true)
		}
		retagged_enc_aaaservername, tagErr_enc_aaaservername := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 8, enc_aaaservername)
		if tagErr_enc_aaaservername != nil {
			return nil, qualifyBERError(tagErr_enc_aaaservername, "aaa-Server-Name", "encoding", true)
		}
		enc_aaaservername = retagged_enc_aaaservername
		children = append(children, enc_aaaservername...)
	}
	if v.SgsnName != nil {
		if len(*v.SgsnName) < 9 || len(*v.SgsnName) > 255 {
			if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(nil, "MAP-LCS-DataTypes.LCSLocationInfo", ber.RuleRef{Document: "ITU-T X.680", Edition: "02/2021", Clause: "51.5"}), "sgsn-Name", "SIZE (9..255)", len(*v.SgsnName)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_sgsnname, encodeErr_enc_sgsnname := ber.EncodeOctetString([]byte(*v.SgsnName))
		if encodeErr_enc_sgsnname != nil {
			return nil, qualifyBERError(encodeErr_enc_sgsnname, "sgsn-Name", "encoding", true)
		}
		retagged_enc_sgsnname, tagErr_enc_sgsnname := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 9, enc_sgsnname)
		if tagErr_enc_sgsnname != nil {
			return nil, qualifyBERError(tagErr_enc_sgsnname, "sgsn-Name", "encoding", true)
		}
		enc_sgsnname = retagged_enc_sgsnname
		children = append(children, enc_sgsnname...)
	}
	if v.SgsnRealm != nil {
		if len(*v.SgsnRealm) < 9 || len(*v.SgsnRealm) > 255 {
			if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(nil, "MAP-LCS-DataTypes.LCSLocationInfo", ber.RuleRef{Document: "ITU-T X.680", Edition: "02/2021", Clause: "51.5"}), "sgsn-Realm", "SIZE (9..255)", len(*v.SgsnRealm)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_sgsnrealm, encodeErr_enc_sgsnrealm := ber.EncodeOctetString([]byte(*v.SgsnRealm))
		if encodeErr_enc_sgsnrealm != nil {
			return nil, qualifyBERError(encodeErr_enc_sgsnrealm, "sgsn-Realm", "encoding", true)
		}
		retagged_enc_sgsnrealm, tagErr_enc_sgsnrealm := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 10, enc_sgsnrealm)
		if tagErr_enc_sgsnrealm != nil {
			return nil, qualifyBERError(tagErr_enc_sgsnrealm, "sgsn-Realm", "encoding", true)
		}
		enc_sgsnrealm = retagged_enc_sgsnrealm
		children = append(children, enc_sgsnrealm...)
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
		if i == 0 && ((peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 10) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 9) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 8) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 6) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 5) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0)) {
			if constraintErr := ber.CheckEncodedValue(ber.EncodeRule(nil, "MAP-LCS-DataTypes.LCSLocationInfo", ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
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
		return nil, fmt.Errorf("%s: %w", "encoding LCSLCSLocationInfo as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}
func (v *LCSLCSLocationInfo) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	encoded, err := v.MarshalDER()
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBER decodes LCSLCSLocationInfo from BER/DER format.
func (destination *LCSLCSLocationInfo) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if destination == nil {
		return fmt.Errorf("%w: LCSLCSLocationInfo destination is nil", ber.ErrInvalidValue)
	}
	var berNextValue_ LCSLCSLocationInfo
	v := &berNextValue_

	defer func() {
		if returnErr ==
			nil {
			*destination =
				*v
		}
	}()

	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	ownedData, ownErr := ber.OwnGeneratedBERInput(data, opts)
	if ownErr != nil {
		return ownErr
	}
	data = ownedData
	preparedData, preparedOptions, prepareErr := ber.PrepareGeneratedBERInput(data, opts)
	if prepareErr != nil {
		return ber.DiagnosePreflight(prepareErr, data, opts, "child", func(probeOpts []ber.DecodeOption) error {
			var probe LCSLCSLocationInfo
			return probe.UnmarshalBER(data, probeOpts...)
		})
	}
	data, opts = preparedData, preparedOptions
	opts = ber.LocateDecodedElement(data, "MAP-LCS-DataTypes.LCSLocationInfo", opts)
	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
	*v = LCSLCSLocationInfo{}
	defer func() {
		if returnErr != nil || !ber.BERNeedsPreservation(opts) {
			return
		}
		v.berReplayNode_ = ber.CaptureGeneratedBERReplay(data, opts)
		returnErr = ber.CompleteGeneratedBERDecode(opts, v, func(base *LCSLCSLocationInfo, replayOpts ...ber.EncodeOption) ([]byte, error) {
			return base.MarshalBER(replayOpts...)
		})
	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("%s: %w", "decoding LCSLCSLocationInfo SEQUENCE", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "LCSLCSLocationInfo", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode networkNode-Number
	if offset >= len(content) {
		return fmt.Errorf("missing required field networkNode-Number")
	}
	{
		ber.MarkPreflightTarget(opts, "networkNode-Number", content[offset:])
		val_networknodenumber, n, err := ber.DecodeOctetString(content[offset:], opts...)
		if err != nil {
			return qualifyBERError(err, "networkNode-Number", "decoding", false)
		}
		v.NetworkNodeNumber = v21_map_commondatatypes.CommonDataTypesISDNAddressString(val_networknodenumber)
		if offset > len(content) || n < 0 || n > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n
		if len(v.NetworkNodeNumber) < 1 || len(v.NetworkNodeNumber) > 9 {
			if constraintErr := ber.CheckDecodedLength(ber.DecodeRule(opts, "MAP-LCS-DataTypes.LCSLocationInfo", ber.RuleRef{Document: "ITU-T X.680", Edition: "02/2021", Clause: "51.5"}), "networkNode-Number", "SIZE (1..9)", len(v.NetworkNodeNumber)); constraintErr != nil {
				return constraintErr
			}
		}
		if len(v.NetworkNodeNumber) < 1 || len(v.NetworkNodeNumber) > 20 {
			if constraintErr := ber.CheckDecodedLength(ber.DecodeRule(opts, "MAP-LCS-DataTypes.LCSLocationInfo", ber.RuleRef{Document: "ITU-T X.680", Edition: "02/2021", Clause: "51.5"}), "networkNode-Number", "SIZE (1..20)", len(v.NetworkNodeNumber)); constraintErr != nil {
				return constraintErr
			}
		}
	}
	// Decode lmsi
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
				ber.MarkPreflightTarget(opts, "lmsi", content[offset:])
				decodedTag_lmsi, n_lmsi, rawVal_lmsi, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "lmsi", "decoding", false)
				}
				if decodedTag_lmsi.Class != tag.ClassContextSpecific || decodedTag_lmsi.Number != 0 {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_lmsi), "lmsi", "decoding", false)
				}
				decVal_lmsi, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_lmsi.Constructed, rawVal_lmsi, opts...)
				if octetErr != nil {
					return qualifyBERError(octetErr, "lmsi", "decoding", false)
				}
				tmp_lmsi := v21_map_commondatatypes.CommonDataTypesLMSI(decVal_lmsi)
				v.Lmsi = &tmp_lmsi
				if offset < 0 || offset >
					len(content) || n_lmsi < 0 || n_lmsi > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_lmsi
				if len(*v.Lmsi) < 4 || len(*v.Lmsi) > 4 {
					if constraintErr := ber.CheckDecodedLength(ber.DecodeRule(opts, "MAP-LCS-DataTypes.LCSLocationInfo", ber.RuleRef{Document: "ITU-T X.680", Edition: "02/2021", Clause: "51.5"}), "lmsi", "SIZE (4)", len(*v.Lmsi)); constraintErr != nil {
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
				ber.MarkPreflightTarget(opts, "extensionContainer", content[offset:])
				decodedTag_extensioncontainer, n_extensioncontainer, rawVal_extensioncontainer, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "extensionContainer", "decoding", false)
				}
				if decodedTag_extensioncontainer.Class != tag.ClassContextSpecific || decodedTag_extensioncontainer.Number != 1 || decodedTag_extensioncontainer.Constructed != true {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_extensioncontainer), "extensionContainer", "decoding", false)
				}
				_ = rawVal_extensioncontainer
				if offset < 0 || offset >
					len(content) || n_extensioncontainer < 0 || n_extensioncontainer >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				reconstructed_extensioncontainer, reconstructionErr_extensioncontainer := ber.EncodeImplicitTagWithClass(tag.ClassUniversal, tag.TagSequence, content[offset:offset+n_extensioncontainer])
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
	// Decode gprsNodeIndicator
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2 {
				ber.MarkPreflightTarget(opts, "gprsNodeIndicator", content[offset:])
				decodedTag_gprsnodeindicator, n_gprsnodeindicator, rawVal_gprsnodeindicator, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "gprsNodeIndicator", "decoding", false)
				}
				if decodedTag_gprsnodeindicator.Class != tag.ClassContextSpecific || decodedTag_gprsnodeindicator.Number != 2 || decodedTag_gprsnodeindicator.Constructed != false {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_gprsnodeindicator), "gprsNodeIndicator", "decoding", false)
				}
				if len(rawVal_gprsnodeindicator) != 0 {
					return qualifyBERError(fmt.Errorf("%w: NULL content length %d", ber.ErrInvalidValue, len(rawVal_gprsnodeindicator)), "gprsNodeIndicator", "decoding", false)
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
				ber.MarkPreflightTarget(opts, "additional-Number", content[offset:])
				decodedTag_additionalnumber, n_additionalnumber, innerData_additionalnumber, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "additional-Number", "decoding", false)
				}
				if decodedTag_additionalnumber.Class != tag.ClassContextSpecific || decodedTag_additionalnumber.Number != 3 || decodedTag_additionalnumber.Constructed != true {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_additionalnumber), "additional-Number", "decoding", false)
				}
				_, innerUsed_additionalnumber, _, innerErr_additionalnumber := ber.DecodeTLV(innerData_additionalnumber, opts...)
				if innerErr_additionalnumber != nil {
					return qualifyBERError(innerErr_additionalnumber, "additional-Number", "decoding", false)
				}
				if innerUsed_additionalnumber != len(innerData_additionalnumber) {
					return qualifyBERError(ber.ErrExtraData, "additional-Number", "decoding", false)
				}
				// Decode inner value from explicit tag wrapper
				ber.MarkPreflightTarget(opts, "additional-Number", innerData_additionalnumber)
				var dec_additionalnumber v21_map_sm_datatypes.SMAdditionalNumber
				if unmErr := dec_additionalnumber.UnmarshalBER(innerData_additionalnumber, ber.ChildDecodeOptions(opts, "additional-Number")...); unmErr != nil {
					return qualifyBERError(unmErr, "additional-Number", "decoding", false)
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
				ber.MarkPreflightTarget(opts, "supportedLCS-CapabilitySets", content[offset:])
				decodedTag_supportedlcscapabilitysets, n_supportedlcscapabilitysets, rawVal_supportedlcscapabilitysets, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "supportedLCS-CapabilitySets", "decoding", false)
				}
				if decodedTag_supportedlcscapabilitysets.Class != tag.ClassContextSpecific || decodedTag_supportedlcscapabilitysets.Number != 4 {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_supportedlcscapabilitysets), "supportedLCS-CapabilitySets", "decoding", false)
				}
				bsBytes_supportedlcscapabilitysets, bsUnused_supportedlcscapabilitysets, bsErr := ber.DecodeImplicitBitStringValue(decodedTag_supportedlcscapabilitysets.Constructed, rawVal_supportedlcscapabilitysets, opts...)
				if bsErr != nil {
					return qualifyBERError(bsErr, "supportedLCS-CapabilitySets", "decoding", false)
				}
				bsBitLength_supportedlcscapabilitysets, bsLenErr_supportedlcscapabilitysets := ber.BitStringBitLength(len(bsBytes_supportedlcscapabilitysets), bsUnused_supportedlcscapabilitysets)
				if bsLenErr_supportedlcscapabilitysets != nil {
					return qualifyBERError(bsLenErr_supportedlcscapabilitysets, "supportedLCS-CapabilitySets", "decoding", false)
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
					if constraintErr := ber.CheckDecodedLength(ber.DecodeRule(opts, "MAP-LCS-DataTypes.LCSLocationInfo", ber.RuleRef{Document: "ITU-T X.680", Edition: "02/2021", Clause: "51.5"}), "supportedLCS-CapabilitySets", "SIZE (2..16)", (*v.SupportedLCSCapabilitySets).BitLength); constraintErr != nil {
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
				ber.MarkPreflightTarget(opts, "additional-LCS-CapabilitySets", content[offset:])
				decodedTag_additionallcscapabilitysets, n_additionallcscapabilitysets, rawVal_additionallcscapabilitysets, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "additional-LCS-CapabilitySets", "decoding", false)
				}
				if decodedTag_additionallcscapabilitysets.Class != tag.ClassContextSpecific || decodedTag_additionallcscapabilitysets.Number != 5 {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_additionallcscapabilitysets), "additional-LCS-CapabilitySets", "decoding", false)
				}
				bsBytes_additionallcscapabilitysets, bsUnused_additionallcscapabilitysets, bsErr := ber.DecodeImplicitBitStringValue(decodedTag_additionallcscapabilitysets.Constructed, rawVal_additionallcscapabilitysets, opts...)
				if bsErr != nil {
					return qualifyBERError(bsErr, "additional-LCS-CapabilitySets", "decoding", false)
				}
				bsBitLength_additionallcscapabilitysets, bsLenErr_additionallcscapabilitysets := ber.BitStringBitLength(len(bsBytes_additionallcscapabilitysets), bsUnused_additionallcscapabilitysets)
				if bsLenErr_additionallcscapabilitysets != nil {
					return qualifyBERError(bsLenErr_additionallcscapabilitysets, "additional-LCS-CapabilitySets", "decoding", false)
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
					if constraintErr := ber.CheckDecodedLength(ber.DecodeRule(opts, "MAP-LCS-DataTypes.LCSLocationInfo", ber.RuleRef{Document: "ITU-T X.680", Edition: "02/2021", Clause: "51.5"}), "additional-LCS-CapabilitySets", "SIZE (2..16)", (*v.AdditionalLCSCapabilitySets).BitLength); constraintErr != nil {
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
				ber.MarkPreflightTarget(opts, "mme-Name", content[offset:])
				decodedTag_mmename, n_mmename, rawVal_mmename, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "mme-Name", "decoding", false)
				}
				if decodedTag_mmename.Class != tag.ClassContextSpecific || decodedTag_mmename.Number != 6 {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_mmename), "mme-Name", "decoding", false)
				}
				decVal_mmename, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_mmename.Constructed, rawVal_mmename, opts...)
				if octetErr != nil {
					return qualifyBERError(octetErr, "mme-Name", "decoding", false)
				}
				tmp_mmename := v21_map_commondatatypes.CommonDataTypesDiameterIdentity(decVal_mmename)
				v.MmeName = &tmp_mmename
				if offset < 0 || offset >
					len(content) || n_mmename < 0 || n_mmename > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_mmename
				if len(*v.MmeName) < 9 || len(*v.MmeName) > 255 {
					if constraintErr := ber.CheckDecodedLength(ber.DecodeRule(opts, "MAP-LCS-DataTypes.LCSLocationInfo", ber.RuleRef{Document: "ITU-T X.680", Edition: "02/2021", Clause: "51.5"}), "mme-Name", "SIZE (9..255)", len(*v.MmeName)); constraintErr != nil {
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
				ber.MarkPreflightTarget(opts, "aaa-Server-Name", content[offset:])
				decodedTag_aaaservername, n_aaaservername, rawVal_aaaservername, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "aaa-Server-Name", "decoding", false)
				}
				if decodedTag_aaaservername.Class != tag.ClassContextSpecific || decodedTag_aaaservername.Number != 8 {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_aaaservername), "aaa-Server-Name", "decoding", false)
				}
				decVal_aaaservername, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_aaaservername.Constructed, rawVal_aaaservername, opts...)
				if octetErr != nil {
					return qualifyBERError(octetErr, "aaa-Server-Name", "decoding", false)
				}
				tmp_aaaservername := v21_map_commondatatypes.CommonDataTypesDiameterIdentity(decVal_aaaservername)
				v.AaaServerName = &tmp_aaaservername
				if offset < 0 || offset >
					len(content) || n_aaaservername < 0 || n_aaaservername > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_aaaservername
				if len(*v.AaaServerName) < 9 || len(*v.AaaServerName) > 255 {
					if constraintErr := ber.CheckDecodedLength(ber.DecodeRule(opts, "MAP-LCS-DataTypes.LCSLocationInfo", ber.RuleRef{Document: "ITU-T X.680", Edition: "02/2021", Clause: "51.5"}), "aaa-Server-Name", "SIZE (9..255)", len(*v.AaaServerName)); constraintErr != nil {
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
				ber.MarkPreflightTarget(opts, "sgsn-Name", content[offset:])
				decodedTag_sgsnname, n_sgsnname, rawVal_sgsnname, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "sgsn-Name", "decoding", false)
				}
				if decodedTag_sgsnname.Class != tag.ClassContextSpecific || decodedTag_sgsnname.Number != 9 {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_sgsnname), "sgsn-Name", "decoding", false)
				}
				decVal_sgsnname, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_sgsnname.Constructed, rawVal_sgsnname, opts...)
				if octetErr != nil {
					return qualifyBERError(octetErr, "sgsn-Name", "decoding", false)
				}
				tmp_sgsnname := v21_map_commondatatypes.CommonDataTypesDiameterIdentity(decVal_sgsnname)
				v.SgsnName = &tmp_sgsnname
				if offset < 0 || offset >
					len(content) || n_sgsnname < 0 || n_sgsnname > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_sgsnname
				if len(*v.SgsnName) < 9 || len(*v.SgsnName) > 255 {
					if constraintErr := ber.CheckDecodedLength(ber.DecodeRule(opts, "MAP-LCS-DataTypes.LCSLocationInfo", ber.RuleRef{Document: "ITU-T X.680", Edition: "02/2021", Clause: "51.5"}), "sgsn-Name", "SIZE (9..255)", len(*v.SgsnName)); constraintErr != nil {
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
				ber.MarkPreflightTarget(opts, "sgsn-Realm", content[offset:])
				decodedTag_sgsnrealm, n_sgsnrealm, rawVal_sgsnrealm, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "sgsn-Realm", "decoding", false)
				}
				if decodedTag_sgsnrealm.Class != tag.ClassContextSpecific || decodedTag_sgsnrealm.Number != 10 {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_sgsnrealm), "sgsn-Realm", "decoding", false)
				}
				decVal_sgsnrealm, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_sgsnrealm.Constructed, rawVal_sgsnrealm, opts...)
				if octetErr != nil {
					return qualifyBERError(octetErr, "sgsn-Realm", "decoding", false)
				}
				tmp_sgsnrealm := v21_map_commondatatypes.CommonDataTypesDiameterIdentity(decVal_sgsnrealm)
				v.SgsnRealm = &tmp_sgsnrealm
				if offset < 0 || offset >
					len(content) || n_sgsnrealm < 0 || n_sgsnrealm > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_sgsnrealm
				if len(*v.SgsnRealm) < 9 || len(*v.SgsnRealm) > 255 {
					if constraintErr := ber.CheckDecodedLength(ber.DecodeRule(opts, "MAP-LCS-DataTypes.LCSLocationInfo", ber.RuleRef{Document: "ITU-T X.680", Edition: "02/2021", Clause: "51.5"}), "sgsn-Realm", "SIZE (9..255)", len(*v.SgsnRealm)); constraintErr != nil {
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
			return &ber.DecodeError{Offset: offset, TypeName: "LCSLCSLocationInfo", Cause: extErr_}
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: the first unknown addition must differ from trailing OPTIONAL/DEFAULT tags.
		if len(v.ExtData_) == 0 && ((peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 10) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 9) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 8) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 6) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 5) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0)) {
			if !ber.ToleranceEnabled(opts) {
				return &ber.DecodeError{Offset: offset, TypeName: "LCSLCSLocationInfo", Cause: fmt.Errorf("%w: repeated or out-of-order SEQUENCE component tag %s", ber.ErrInvalidTag, peekTag)}
			}
			if orderErr_ := ber.CheckDecodedValue(ber.DecodeRule(opts, "MAP-LCS-DataTypes.LCSLocationInfo", ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), fmt.Sprintf("ExtData_[%d]", len(v.ExtData_)), "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); orderErr_ != nil {
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

// MarshalBER encodes LCSProvideSubscriberLocationArg to BER format.
func (v *LCSProvideSubscriberLocationArg) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: LCSProvideSubscriberLocationArg receiver is nil", ber.ErrInvalidValue)
	}
	if v.berReplayNode_ == nil {
		return v.marshalBER(opts...)
	}
	var replayErr error
	opts, replayErr = ber.PrepareBERReplay(v.berReplayNode_, opts, func(mode ber.EncodeOption) ([]byte, error) { return v.MarshalBER([]ber.EncodeOption{mode}...) }, v)
	if replayErr != nil {
		return nil, replayErr
	}
	if replayBytes, ok := ber.PreparedBERReplay(v.berReplayNode_, opts); ok {
		return replayBytes, nil
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBERNode(encoded, v.berReplayNode_, opts), nil
}
func (v *LCSProvideSubscriberLocationArg) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	enc_locationtype, err := v.LocationType.MarshalBER(ber.ChildEncodeOptions(opts, "locationType")...)
	if err != nil {
		return nil, qualifyBERError(err, "locationType", "encoding", false)
	}
	ber.RecordGeneratedBERChildPlacement(opts, len(children), enc_locationtype)
	children = append(children, enc_locationtype...)
	if len(v.MlcNumber) < 1 || len(v.MlcNumber) > 9 {
		if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(opts, "MAP-LCS-DataTypes.ProvideSubscriberLocation-Arg", ber.RuleRef{Document: "ITU-T X.680", Edition: "02/2021", Clause: "51.5"}), "mlc-Number", "SIZE (1..9)", len(v.MlcNumber)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	if len(v.MlcNumber) < 1 || len(v.MlcNumber) > 20 {
		if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(opts, "MAP-LCS-DataTypes.ProvideSubscriberLocation-Arg", ber.RuleRef{Document: "ITU-T X.680", Edition: "02/2021", Clause: "51.5"}), "mlc-Number", "SIZE (1..20)", len(v.MlcNumber)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_mlcnumber, encodeErr_enc_mlcnumber := ber.EncodeOctetString([]byte(v.MlcNumber))
	if encodeErr_enc_mlcnumber != nil {
		return nil, qualifyBERError(encodeErr_enc_mlcnumber, "mlc-Number", "encoding", false)
	}
	children = append(children, enc_mlcnumber...)
	if v.LcsClientID != nil {
		enc_lcsclientid, err := v.LcsClientID.MarshalBER(ber.ChildEncodeOptions(opts, "lcs-ClientID")...)
		if err != nil {
			return nil, qualifyBERError(err, "lcs-ClientID", "encoding", false)
		}
		retagged_enc_lcsclientid, tagErr_enc_lcsclientid := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_lcsclientid)
		if tagErr_enc_lcsclientid != nil {
			return nil, qualifyBERError(tagErr_enc_lcsclientid, "lcs-ClientID", "encoding", false)
		}
		enc_lcsclientid = retagged_enc_lcsclientid
		ber.RecordGeneratedBERChildPlacement(opts, len(children), enc_lcsclientid)
		children = append(children, enc_lcsclientid...)
	}
	if v.PrivacyOverride != nil {
		enc_privacyoverride := ber.EncodeNull()
		retagged_enc_privacyoverride, tagErr_enc_privacyoverride := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_privacyoverride)
		if tagErr_enc_privacyoverride != nil {
			return nil, qualifyBERError(tagErr_enc_privacyoverride, "privacyOverride", "encoding", false)
		}
		enc_privacyoverride = retagged_enc_privacyoverride
		children = append(children, enc_privacyoverride...)
	}
	if v.Imsi != nil {
		if len(*v.Imsi) < 3 || len(*v.Imsi) > 8 {
			if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(opts, "MAP-LCS-DataTypes.ProvideSubscriberLocation-Arg", ber.RuleRef{Document: "ITU-T X.680", Edition: "02/2021", Clause: "51.5"}), "imsi", "SIZE (3..8)", len(*v.Imsi)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_imsi, encodeErr_enc_imsi := ber.EncodeOctetString([]byte(*v.Imsi))
		if encodeErr_enc_imsi != nil {
			return nil, qualifyBERError(encodeErr_enc_imsi, "imsi", "encoding", false)
		}
		retagged_enc_imsi, tagErr_enc_imsi := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_imsi)
		if tagErr_enc_imsi != nil {
			return nil, qualifyBERError(tagErr_enc_imsi, "imsi", "encoding", false)
		}
		enc_imsi = retagged_enc_imsi
		children = append(children, enc_imsi...)
	}
	if v.Msisdn != nil {
		if len(*v.Msisdn) < 1 || len(*v.Msisdn) > 9 {
			if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(opts, "MAP-LCS-DataTypes.ProvideSubscriberLocation-Arg", ber.RuleRef{Document: "ITU-T X.680", Edition: "02/2021", Clause: "51.5"}), "msisdn", "SIZE (1..9)", len(*v.Msisdn)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		if len(*v.Msisdn) < 1 || len(*v.Msisdn) > 20 {
			if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(opts, "MAP-LCS-DataTypes.ProvideSubscriberLocation-Arg", ber.RuleRef{Document: "ITU-T X.680", Edition: "02/2021", Clause: "51.5"}), "msisdn", "SIZE (1..20)", len(*v.Msisdn)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_msisdn, encodeErr_enc_msisdn := ber.EncodeOctetString([]byte(*v.Msisdn))
		if encodeErr_enc_msisdn != nil {
			return nil, qualifyBERError(encodeErr_enc_msisdn, "msisdn", "encoding", false)
		}
		retagged_enc_msisdn, tagErr_enc_msisdn := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, enc_msisdn)
		if tagErr_enc_msisdn != nil {
			return nil, qualifyBERError(tagErr_enc_msisdn, "msisdn", "encoding", false)
		}
		enc_msisdn = retagged_enc_msisdn
		children = append(children, enc_msisdn...)
	}
	if v.Lmsi != nil {
		if len(*v.Lmsi) < 4 || len(*v.Lmsi) > 4 {
			if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(opts, "MAP-LCS-DataTypes.ProvideSubscriberLocation-Arg", ber.RuleRef{Document: "ITU-T X.680", Edition: "02/2021", Clause: "51.5"}), "lmsi", "SIZE (4)", len(*v.Lmsi)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_lmsi, encodeErr_enc_lmsi := ber.EncodeOctetString([]byte(*v.Lmsi))
		if encodeErr_enc_lmsi != nil {
			return nil, qualifyBERError(encodeErr_enc_lmsi, "lmsi", "encoding", false)
		}
		retagged_enc_lmsi, tagErr_enc_lmsi := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, enc_lmsi)
		if tagErr_enc_lmsi != nil {
			return nil, qualifyBERError(tagErr_enc_lmsi, "lmsi", "encoding", false)
		}
		enc_lmsi = retagged_enc_lmsi
		children = append(children, enc_lmsi...)
	}
	if v.Imei != nil {
		if len(*v.Imei) < 8 || len(*v.Imei) > 8 {
			if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(opts, "MAP-LCS-DataTypes.ProvideSubscriberLocation-Arg", ber.RuleRef{Document: "ITU-T X.680", Edition: "02/2021", Clause: "51.5"}), "imei", "SIZE (8)", len(*v.Imei)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_imei, encodeErr_enc_imei := ber.EncodeOctetString([]byte(*v.Imei))
		if encodeErr_enc_imei != nil {
			return nil, qualifyBERError(encodeErr_enc_imei, "imei", "encoding", false)
		}
		retagged_enc_imei, tagErr_enc_imei := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 5, enc_imei)
		if tagErr_enc_imei != nil {
			return nil, qualifyBERError(tagErr_enc_imei, "imei", "encoding", false)
		}
		enc_imei = retagged_enc_imei
		children = append(children, enc_imei...)
	}
	if v.LcsPriority != nil {
		if len(*v.LcsPriority) < 1 || len(*v.LcsPriority) > 1 {
			if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(opts, "MAP-LCS-DataTypes.ProvideSubscriberLocation-Arg", ber.RuleRef{Document: "ITU-T X.680", Edition: "02/2021", Clause: "51.5"}), "lcs-Priority", "SIZE (1)", len(*v.LcsPriority)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_lcspriority, encodeErr_enc_lcspriority := ber.EncodeOctetString([]byte(*v.LcsPriority))
		if encodeErr_enc_lcspriority != nil {
			return nil, qualifyBERError(encodeErr_enc_lcspriority, "lcs-Priority", "encoding", false)
		}
		retagged_enc_lcspriority, tagErr_enc_lcspriority := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 6, enc_lcspriority)
		if tagErr_enc_lcspriority != nil {
			return nil, qualifyBERError(tagErr_enc_lcspriority, "lcs-Priority", "encoding", false)
		}
		enc_lcspriority = retagged_enc_lcspriority
		children = append(children, enc_lcspriority...)
	}
	if v.LcsQoS != nil {
		enc_lcsqos, err := v.LcsQoS.MarshalBER(ber.ChildEncodeOptions(opts, "lcs-QoS")...)
		if err != nil {
			return nil, qualifyBERError(err, "lcs-QoS", "encoding", false)
		}
		retagged_enc_lcsqos, tagErr_enc_lcsqos := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 7, enc_lcsqos)
		if tagErr_enc_lcsqos != nil {
			return nil, qualifyBERError(tagErr_enc_lcsqos, "lcs-QoS", "encoding", false)
		}
		enc_lcsqos = retagged_enc_lcsqos
		ber.RecordGeneratedBERChildPlacement(opts, len(children), enc_lcsqos)
		children = append(children, enc_lcsqos...)
	}
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalBER(ber.ChildEncodeOptions(opts, "extensionContainer")...)
		if err != nil {
			return nil, qualifyBERError(err, "extensionContainer", "encoding", false)
		}
		retagged_enc_extensioncontainer, tagErr_enc_extensioncontainer := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 8, enc_extensioncontainer)
		if tagErr_enc_extensioncontainer != nil {
			return nil, qualifyBERError(tagErr_enc_extensioncontainer, "extensionContainer", "encoding", false)
		}
		enc_extensioncontainer = retagged_enc_extensioncontainer
		ber.RecordGeneratedBERChildPlacement(opts, len(children), enc_extensioncontainer)
		children = append(children, enc_extensioncontainer...)
	}
	if v.SupportedGADShapes != nil {
		if bitStringErr := ber.ValidateBitStringLength(v.SupportedGADShapes.Bytes, v.SupportedGADShapes.BitLength); bitStringErr != nil {
			return nil, qualifyBERError(bitStringErr, "supportedGADShapes", "encoding", false)
		}
		// arithmetic pattern BER_BITSTRING_FIELD: 0 <= bit length before modulo and subtraction; gen/codegen.go:743
		if v.SupportedGADShapes.BitLength < 0 {
			return nil, fmt.Errorf("negative bit string length")
		}
		if (*v.SupportedGADShapes).BitLength < 7 || (*v.SupportedGADShapes).BitLength > 16 {
			if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(opts, "MAP-LCS-DataTypes.ProvideSubscriberLocation-Arg", ber.RuleRef{Document: "ITU-T X.680", Edition: "02/2021", Clause: "51.5"}), "supportedGADShapes", "SIZE (7..16)", (*v.SupportedGADShapes).BitLength); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_supportedgadshapes, encodeErr_enc_supportedgadshapes := ber.EncodeBitString(v.SupportedGADShapes.Bytes, ber.UnusedBitCount(v.SupportedGADShapes.BitLength))
		if encodeErr_enc_supportedgadshapes != nil {
			return nil, qualifyBERError(encodeErr_enc_supportedgadshapes, "supportedGADShapes", "encoding", false)
		}
		retagged_enc_supportedgadshapes, tagErr_enc_supportedgadshapes := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 9, enc_supportedgadshapes)
		if tagErr_enc_supportedgadshapes != nil {
			return nil, qualifyBERError(tagErr_enc_supportedgadshapes, "supportedGADShapes", "encoding", false)
		}
		enc_supportedgadshapes = retagged_enc_supportedgadshapes
		children = append(children, enc_supportedgadshapes...)
	}
	if v.LcsReferenceNumber != nil {
		if len(*v.LcsReferenceNumber) < 1 || len(*v.LcsReferenceNumber) > 1 {
			if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(opts, "MAP-LCS-DataTypes.ProvideSubscriberLocation-Arg", ber.RuleRef{Document: "ITU-T X.680", Edition: "02/2021", Clause: "51.5"}), "lcs-ReferenceNumber", "SIZE (1)", len(*v.LcsReferenceNumber)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_lcsreferencenumber, encodeErr_enc_lcsreferencenumber := ber.EncodeOctetString([]byte(*v.LcsReferenceNumber))
		if encodeErr_enc_lcsreferencenumber != nil {
			return nil, qualifyBERError(encodeErr_enc_lcsreferencenumber, "lcs-ReferenceNumber", "encoding", false)
		}
		retagged_enc_lcsreferencenumber, tagErr_enc_lcsreferencenumber := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 10, enc_lcsreferencenumber)
		if tagErr_enc_lcsreferencenumber != nil {
			return nil, qualifyBERError(tagErr_enc_lcsreferencenumber, "lcs-ReferenceNumber", "encoding", false)
		}
		enc_lcsreferencenumber = retagged_enc_lcsreferencenumber
		children = append(children, enc_lcsreferencenumber...)
	}
	if v.LcsServiceTypeID != nil {
		if !(int64(*v.LcsServiceTypeID) >= 0 && int64(*v.LcsServiceTypeID) <= 127) {
			if constraintErr := ber.CheckEncodedValue(ber.EncodeRule(opts, "MAP-LCS-DataTypes.ProvideSubscriberLocation-Arg", ber.RuleRef{Document: "ITU-T X.680", Edition: "02/2021", Clause: "51.4"}), "lcsServiceTypeID", "(0..127)", ber.ObserveInteger(int64(*v.LcsServiceTypeID))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_lcsservicetypeid := ber.EncodeInteger(int64(*v.LcsServiceTypeID))
		retagged_enc_lcsservicetypeid, tagErr_enc_lcsservicetypeid := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 11, enc_lcsservicetypeid)
		if tagErr_enc_lcsservicetypeid != nil {
			return nil, qualifyBERError(tagErr_enc_lcsservicetypeid, "lcsServiceTypeID", "encoding", false)
		}
		enc_lcsservicetypeid = retagged_enc_lcsservicetypeid
		children = append(children, enc_lcsservicetypeid...)
	}
	if v.LcsCodeword != nil {
		enc_lcscodeword, err := v.LcsCodeword.MarshalBER(ber.ChildEncodeOptions(opts, "lcsCodeword")...)
		if err != nil {
			return nil, qualifyBERError(err, "lcsCodeword", "encoding", false)
		}
		retagged_enc_lcscodeword, tagErr_enc_lcscodeword := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 12, enc_lcscodeword)
		if tagErr_enc_lcscodeword != nil {
			return nil, qualifyBERError(tagErr_enc_lcscodeword, "lcsCodeword", "encoding", false)
		}
		enc_lcscodeword = retagged_enc_lcscodeword
		ber.RecordGeneratedBERChildPlacement(opts, len(children), enc_lcscodeword)
		children = append(children, enc_lcscodeword...)
	}
	if v.LcsPrivacyCheck != nil {
		enc_lcsprivacycheck, err := v.LcsPrivacyCheck.MarshalBER(ber.ChildEncodeOptions(opts, "lcs-PrivacyCheck")...)
		if err != nil {
			return nil, qualifyBERError(err, "lcs-PrivacyCheck", "encoding", false)
		}
		retagged_enc_lcsprivacycheck, tagErr_enc_lcsprivacycheck := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 13, enc_lcsprivacycheck)
		if tagErr_enc_lcsprivacycheck != nil {
			return nil, qualifyBERError(tagErr_enc_lcsprivacycheck, "lcs-PrivacyCheck", "encoding", false)
		}
		enc_lcsprivacycheck = retagged_enc_lcsprivacycheck
		ber.RecordGeneratedBERChildPlacement(opts, len(children), enc_lcsprivacycheck)
		children = append(children, enc_lcsprivacycheck...)
	}
	if v.AreaEventInfo != nil {
		enc_areaeventinfo, err := v.AreaEventInfo.MarshalBER(ber.ChildEncodeOptions(opts, "areaEventInfo")...)
		if err != nil {
			return nil, qualifyBERError(err, "areaEventInfo", "encoding", false)
		}
		retagged_enc_areaeventinfo, tagErr_enc_areaeventinfo := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 14, enc_areaeventinfo)
		if tagErr_enc_areaeventinfo != nil {
			return nil, qualifyBERError(tagErr_enc_areaeventinfo, "areaEventInfo", "encoding", false)
		}
		enc_areaeventinfo = retagged_enc_areaeventinfo
		ber.RecordGeneratedBERChildPlacement(opts, len(children), enc_areaeventinfo)
		children = append(children, enc_areaeventinfo...)
	}
	if v.HGmlcAddress != nil {
		if len(*v.HGmlcAddress) < 5 || len(*v.HGmlcAddress) > 17 {
			if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(opts, "MAP-LCS-DataTypes.ProvideSubscriberLocation-Arg", ber.RuleRef{Document: "ITU-T X.680", Edition: "02/2021", Clause: "51.5"}), "h-gmlc-Address", "SIZE (5..17)", len(*v.HGmlcAddress)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_hgmlcaddress, encodeErr_enc_hgmlcaddress := ber.EncodeOctetString([]byte(*v.HGmlcAddress))
		if encodeErr_enc_hgmlcaddress != nil {
			return nil, qualifyBERError(encodeErr_enc_hgmlcaddress, "h-gmlc-Address", "encoding", false)
		}
		retagged_enc_hgmlcaddress, tagErr_enc_hgmlcaddress := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 15, enc_hgmlcaddress)
		if tagErr_enc_hgmlcaddress != nil {
			return nil, qualifyBERError(tagErr_enc_hgmlcaddress, "h-gmlc-Address", "encoding", false)
		}
		enc_hgmlcaddress = retagged_enc_hgmlcaddress
		children = append(children, enc_hgmlcaddress...)
	}
	if v.MoLrShortCircuitIndicator != nil {
		enc_molrshortcircuitindicator := ber.EncodeNull()
		retagged_enc_molrshortcircuitindicator, tagErr_enc_molrshortcircuitindicator := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 16, enc_molrshortcircuitindicator)
		if tagErr_enc_molrshortcircuitindicator != nil {
			return nil, qualifyBERError(tagErr_enc_molrshortcircuitindicator, "mo-lrShortCircuitIndicator", "encoding", false)
		}
		enc_molrshortcircuitindicator = retagged_enc_molrshortcircuitindicator
		children = append(children, enc_molrshortcircuitindicator...)
	}
	if v.PeriodicLDRInfo != nil {
		enc_periodicldrinfo, err := v.PeriodicLDRInfo.MarshalBER(ber.ChildEncodeOptions(opts, "periodicLDRInfo")...)
		if err != nil {
			return nil, qualifyBERError(err, "periodicLDRInfo", "encoding", false)
		}
		retagged_enc_periodicldrinfo, tagErr_enc_periodicldrinfo := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 17, enc_periodicldrinfo)
		if tagErr_enc_periodicldrinfo != nil {
			return nil, qualifyBERError(tagErr_enc_periodicldrinfo, "periodicLDRInfo", "encoding", false)
		}
		enc_periodicldrinfo = retagged_enc_periodicldrinfo
		ber.RecordGeneratedBERChildPlacement(opts, len(children), enc_periodicldrinfo)
		children = append(children, enc_periodicldrinfo...)
	}
	if v.ReportingPLMNList != nil {
		enc_reportingplmnlist, err := v.ReportingPLMNList.MarshalBER(ber.ChildEncodeOptions(opts, "reportingPLMNList")...)
		if err != nil {
			return nil, qualifyBERError(err, "reportingPLMNList", "encoding", false)
		}
		retagged_enc_reportingplmnlist, tagErr_enc_reportingplmnlist := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 18, enc_reportingplmnlist)
		if tagErr_enc_reportingplmnlist != nil {
			return nil, qualifyBERError(tagErr_enc_reportingplmnlist, "reportingPLMNList", "encoding", false)
		}
		enc_reportingplmnlist = retagged_enc_reportingplmnlist
		ber.RecordGeneratedBERChildPlacement(opts, len(children), enc_reportingplmnlist)
		children = append(children, enc_reportingplmnlist...)
	}
	for i, ext := range v.ExtData_ {
		if err := ber.CheckBEROpaqueElement(ext, opts...); err != nil {
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
		if i == 0 && ((peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 18) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 17) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 16) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 15) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 14) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 13) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 12) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 11) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 10) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 9) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 8) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 7) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 6) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 5) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0)) {
			if constraintErr := ber.CheckEncodedValue(ber.EncodeRule(opts, "MAP-LCS-DataTypes.ProvideSubscriberLocation-Arg", ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
				return nil, constraintErr
			}
		}
		children = append(children, ext...)
	}
	ber.RecordGeneratedBERContainer(opts, children)
	return ber.EncodeSequence(children)
}
func (v *LCSProvideSubscriberLocationArg) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// MarshalDER encodes LCSProvideSubscriberLocationArg to DER format.
// Opaque descendants pass generic DER checks; foreign schema rules need a typed binding.
func (v *LCSProvideSubscriberLocationArg) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: LCSProvideSubscriberLocationArg receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	enc_locationtype, err := v.LocationType.MarshalDER()
	if err != nil {
		return nil, qualifyBERError(err, "locationType", "encoding", true)
	}
	children = append(children, enc_locationtype...)
	if len(v.MlcNumber) < 1 || len(v.MlcNumber) > 9 {
		if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(nil, "MAP-LCS-DataTypes.ProvideSubscriberLocation-Arg", ber.RuleRef{Document: "ITU-T X.680", Edition: "02/2021", Clause: "51.5"}), "mlc-Number", "SIZE (1..9)", len(v.MlcNumber)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	if len(v.MlcNumber) < 1 || len(v.MlcNumber) > 20 {
		if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(nil, "MAP-LCS-DataTypes.ProvideSubscriberLocation-Arg", ber.RuleRef{Document: "ITU-T X.680", Edition: "02/2021", Clause: "51.5"}), "mlc-Number", "SIZE (1..20)", len(v.MlcNumber)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_mlcnumber, encodeErr_enc_mlcnumber := ber.EncodeOctetString([]byte(v.MlcNumber))
	if encodeErr_enc_mlcnumber != nil {
		return nil, qualifyBERError(encodeErr_enc_mlcnumber, "mlc-Number", "encoding", true)
	}
	children = append(children, enc_mlcnumber...)
	if v.LcsClientID != nil {
		enc_lcsclientid, err := v.LcsClientID.MarshalDER()
		if err != nil {
			return nil, qualifyBERError(err, "lcs-ClientID", "encoding", true)
		}
		retagged_enc_lcsclientid, tagErr_enc_lcsclientid := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_lcsclientid)
		if tagErr_enc_lcsclientid != nil {
			return nil, qualifyBERError(tagErr_enc_lcsclientid, "lcs-ClientID", "encoding", true)
		}
		enc_lcsclientid = retagged_enc_lcsclientid
		children = append(children, enc_lcsclientid...)
	}
	if v.PrivacyOverride != nil {
		enc_privacyoverride := ber.EncodeNull()
		retagged_enc_privacyoverride, tagErr_enc_privacyoverride := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_privacyoverride)
		if tagErr_enc_privacyoverride != nil {
			return nil, qualifyBERError(tagErr_enc_privacyoverride, "privacyOverride", "encoding", true)
		}
		enc_privacyoverride = retagged_enc_privacyoverride
		children = append(children, enc_privacyoverride...)
	}
	if v.Imsi != nil {
		if len(*v.Imsi) < 3 || len(*v.Imsi) > 8 {
			if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(nil, "MAP-LCS-DataTypes.ProvideSubscriberLocation-Arg", ber.RuleRef{Document: "ITU-T X.680", Edition: "02/2021", Clause: "51.5"}), "imsi", "SIZE (3..8)", len(*v.Imsi)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_imsi, encodeErr_enc_imsi := ber.EncodeOctetString([]byte(*v.Imsi))
		if encodeErr_enc_imsi != nil {
			return nil, qualifyBERError(encodeErr_enc_imsi, "imsi", "encoding", true)
		}
		retagged_enc_imsi, tagErr_enc_imsi := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_imsi)
		if tagErr_enc_imsi != nil {
			return nil, qualifyBERError(tagErr_enc_imsi, "imsi", "encoding", true)
		}
		enc_imsi = retagged_enc_imsi
		children = append(children, enc_imsi...)
	}
	if v.Msisdn != nil {
		if len(*v.Msisdn) < 1 || len(*v.Msisdn) > 9 {
			if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(nil, "MAP-LCS-DataTypes.ProvideSubscriberLocation-Arg", ber.RuleRef{Document: "ITU-T X.680", Edition: "02/2021", Clause: "51.5"}), "msisdn", "SIZE (1..9)", len(*v.Msisdn)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		if len(*v.Msisdn) < 1 || len(*v.Msisdn) > 20 {
			if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(nil, "MAP-LCS-DataTypes.ProvideSubscriberLocation-Arg", ber.RuleRef{Document: "ITU-T X.680", Edition: "02/2021", Clause: "51.5"}), "msisdn", "SIZE (1..20)", len(*v.Msisdn)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_msisdn, encodeErr_enc_msisdn := ber.EncodeOctetString([]byte(*v.Msisdn))
		if encodeErr_enc_msisdn != nil {
			return nil, qualifyBERError(encodeErr_enc_msisdn, "msisdn", "encoding", true)
		}
		retagged_enc_msisdn, tagErr_enc_msisdn := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, enc_msisdn)
		if tagErr_enc_msisdn != nil {
			return nil, qualifyBERError(tagErr_enc_msisdn, "msisdn", "encoding", true)
		}
		enc_msisdn = retagged_enc_msisdn
		children = append(children, enc_msisdn...)
	}
	if v.Lmsi != nil {
		if len(*v.Lmsi) < 4 || len(*v.Lmsi) > 4 {
			if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(nil, "MAP-LCS-DataTypes.ProvideSubscriberLocation-Arg", ber.RuleRef{Document: "ITU-T X.680", Edition: "02/2021", Clause: "51.5"}), "lmsi", "SIZE (4)", len(*v.Lmsi)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_lmsi, encodeErr_enc_lmsi := ber.EncodeOctetString([]byte(*v.Lmsi))
		if encodeErr_enc_lmsi != nil {
			return nil, qualifyBERError(encodeErr_enc_lmsi, "lmsi", "encoding", true)
		}
		retagged_enc_lmsi, tagErr_enc_lmsi := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, enc_lmsi)
		if tagErr_enc_lmsi != nil {
			return nil, qualifyBERError(tagErr_enc_lmsi, "lmsi", "encoding", true)
		}
		enc_lmsi = retagged_enc_lmsi
		children = append(children, enc_lmsi...)
	}
	if v.Imei != nil {
		if len(*v.Imei) < 8 || len(*v.Imei) > 8 {
			if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(nil, "MAP-LCS-DataTypes.ProvideSubscriberLocation-Arg", ber.RuleRef{Document: "ITU-T X.680", Edition: "02/2021", Clause: "51.5"}), "imei", "SIZE (8)", len(*v.Imei)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_imei, encodeErr_enc_imei := ber.EncodeOctetString([]byte(*v.Imei))
		if encodeErr_enc_imei != nil {
			return nil, qualifyBERError(encodeErr_enc_imei, "imei", "encoding", true)
		}
		retagged_enc_imei, tagErr_enc_imei := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 5, enc_imei)
		if tagErr_enc_imei != nil {
			return nil, qualifyBERError(tagErr_enc_imei, "imei", "encoding", true)
		}
		enc_imei = retagged_enc_imei
		children = append(children, enc_imei...)
	}
	if v.LcsPriority != nil {
		if len(*v.LcsPriority) < 1 || len(*v.LcsPriority) > 1 {
			if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(nil, "MAP-LCS-DataTypes.ProvideSubscriberLocation-Arg", ber.RuleRef{Document: "ITU-T X.680", Edition: "02/2021", Clause: "51.5"}), "lcs-Priority", "SIZE (1)", len(*v.LcsPriority)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_lcspriority, encodeErr_enc_lcspriority := ber.EncodeOctetString([]byte(*v.LcsPriority))
		if encodeErr_enc_lcspriority != nil {
			return nil, qualifyBERError(encodeErr_enc_lcspriority, "lcs-Priority", "encoding", true)
		}
		retagged_enc_lcspriority, tagErr_enc_lcspriority := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 6, enc_lcspriority)
		if tagErr_enc_lcspriority != nil {
			return nil, qualifyBERError(tagErr_enc_lcspriority, "lcs-Priority", "encoding", true)
		}
		enc_lcspriority = retagged_enc_lcspriority
		children = append(children, enc_lcspriority...)
	}
	if v.LcsQoS != nil {
		enc_lcsqos, err := v.LcsQoS.MarshalDER()
		if err != nil {
			return nil, qualifyBERError(err, "lcs-QoS", "encoding", true)
		}
		retagged_enc_lcsqos, tagErr_enc_lcsqos := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 7, enc_lcsqos)
		if tagErr_enc_lcsqos != nil {
			return nil, qualifyBERError(tagErr_enc_lcsqos, "lcs-QoS", "encoding", true)
		}
		enc_lcsqos = retagged_enc_lcsqos
		children = append(children, enc_lcsqos...)
	}
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalDER()
		if err != nil {
			return nil, qualifyBERError(err, "extensionContainer", "encoding", true)
		}
		retagged_enc_extensioncontainer, tagErr_enc_extensioncontainer := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 8, enc_extensioncontainer)
		if tagErr_enc_extensioncontainer != nil {
			return nil, qualifyBERError(tagErr_enc_extensioncontainer, "extensionContainer", "encoding", true)
		}
		enc_extensioncontainer = retagged_enc_extensioncontainer
		children = append(children, enc_extensioncontainer...)
	}
	if v.SupportedGADShapes != nil {
		if bitStringErr := ber.ValidateBitStringLength(v.SupportedGADShapes.Bytes, v.SupportedGADShapes.BitLength); bitStringErr != nil {
			return nil, qualifyBERError(bitStringErr, "supportedGADShapes", "encoding", true)
		}
		if bitStringErr := ber.ValidateDERBitString(v.SupportedGADShapes.Bytes, v.SupportedGADShapes.BitLength); bitStringErr != nil {
			return nil, qualifyBERError(bitStringErr, "supportedGADShapes", "encoding", true)
		}
		// arithmetic pattern BER_BITSTRING_FIELD: 0 <= bit length before modulo and subtraction; gen/codegen.go:743
		if v.SupportedGADShapes.BitLength < 0 {
			return nil, fmt.Errorf("negative bit string length")
		}
		if (*v.SupportedGADShapes).BitLength < 7 || (*v.SupportedGADShapes).BitLength > 16 {
			if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(nil, "MAP-LCS-DataTypes.ProvideSubscriberLocation-Arg", ber.RuleRef{Document: "ITU-T X.680", Edition: "02/2021", Clause: "51.5"}), "supportedGADShapes", "SIZE (7..16)", (*v.SupportedGADShapes).BitLength); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_supportedgadshapes, encodeErr_enc_supportedgadshapes := ber.EncodeDERNamedBitString(v.SupportedGADShapes.Bytes, v.SupportedGADShapes.BitLength)
		if encodeErr_enc_supportedgadshapes != nil {
			return nil, qualifyBERError(encodeErr_enc_supportedgadshapes, "supportedGADShapes", "encoding", true)
		}
		retagged_enc_supportedgadshapes, tagErr_enc_supportedgadshapes := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 9, enc_supportedgadshapes)
		if tagErr_enc_supportedgadshapes != nil {
			return nil, qualifyBERError(tagErr_enc_supportedgadshapes, "supportedGADShapes", "encoding", true)
		}
		enc_supportedgadshapes = retagged_enc_supportedgadshapes
		children = append(children, enc_supportedgadshapes...)
	}
	if v.LcsReferenceNumber != nil {
		if len(*v.LcsReferenceNumber) < 1 || len(*v.LcsReferenceNumber) > 1 {
			if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(nil, "MAP-LCS-DataTypes.ProvideSubscriberLocation-Arg", ber.RuleRef{Document: "ITU-T X.680", Edition: "02/2021", Clause: "51.5"}), "lcs-ReferenceNumber", "SIZE (1)", len(*v.LcsReferenceNumber)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_lcsreferencenumber, encodeErr_enc_lcsreferencenumber := ber.EncodeOctetString([]byte(*v.LcsReferenceNumber))
		if encodeErr_enc_lcsreferencenumber != nil {
			return nil, qualifyBERError(encodeErr_enc_lcsreferencenumber, "lcs-ReferenceNumber", "encoding", true)
		}
		retagged_enc_lcsreferencenumber, tagErr_enc_lcsreferencenumber := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 10, enc_lcsreferencenumber)
		if tagErr_enc_lcsreferencenumber != nil {
			return nil, qualifyBERError(tagErr_enc_lcsreferencenumber, "lcs-ReferenceNumber", "encoding", true)
		}
		enc_lcsreferencenumber = retagged_enc_lcsreferencenumber
		children = append(children, enc_lcsreferencenumber...)
	}
	if v.LcsServiceTypeID != nil {
		if !(int64(*v.LcsServiceTypeID) >= 0 && int64(*v.LcsServiceTypeID) <= 127) {
			if constraintErr := ber.CheckEncodedValue(ber.EncodeRule(nil, "MAP-LCS-DataTypes.ProvideSubscriberLocation-Arg", ber.RuleRef{Document: "ITU-T X.680", Edition: "02/2021", Clause: "51.4"}), "lcsServiceTypeID", "(0..127)", ber.ObserveInteger(int64(*v.LcsServiceTypeID))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_lcsservicetypeid := ber.EncodeInteger(int64(*v.LcsServiceTypeID))
		retagged_enc_lcsservicetypeid, tagErr_enc_lcsservicetypeid := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 11, enc_lcsservicetypeid)
		if tagErr_enc_lcsservicetypeid != nil {
			return nil, qualifyBERError(tagErr_enc_lcsservicetypeid, "lcsServiceTypeID", "encoding", true)
		}
		enc_lcsservicetypeid = retagged_enc_lcsservicetypeid
		children = append(children, enc_lcsservicetypeid...)
	}
	if v.LcsCodeword != nil {
		enc_lcscodeword, err := v.LcsCodeword.MarshalDER()
		if err != nil {
			return nil, qualifyBERError(err, "lcsCodeword", "encoding", true)
		}
		retagged_enc_lcscodeword, tagErr_enc_lcscodeword := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 12, enc_lcscodeword)
		if tagErr_enc_lcscodeword != nil {
			return nil, qualifyBERError(tagErr_enc_lcscodeword, "lcsCodeword", "encoding", true)
		}
		enc_lcscodeword = retagged_enc_lcscodeword
		children = append(children, enc_lcscodeword...)
	}
	if v.LcsPrivacyCheck != nil {
		enc_lcsprivacycheck, err := v.LcsPrivacyCheck.MarshalDER()
		if err != nil {
			return nil, qualifyBERError(err, "lcs-PrivacyCheck", "encoding", true)
		}
		retagged_enc_lcsprivacycheck, tagErr_enc_lcsprivacycheck := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 13, enc_lcsprivacycheck)
		if tagErr_enc_lcsprivacycheck != nil {
			return nil, qualifyBERError(tagErr_enc_lcsprivacycheck, "lcs-PrivacyCheck", "encoding", true)
		}
		enc_lcsprivacycheck = retagged_enc_lcsprivacycheck
		children = append(children, enc_lcsprivacycheck...)
	}
	if v.AreaEventInfo != nil {
		enc_areaeventinfo, err := v.AreaEventInfo.MarshalDER()
		if err != nil {
			return nil, qualifyBERError(err, "areaEventInfo", "encoding", true)
		}
		retagged_enc_areaeventinfo, tagErr_enc_areaeventinfo := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 14, enc_areaeventinfo)
		if tagErr_enc_areaeventinfo != nil {
			return nil, qualifyBERError(tagErr_enc_areaeventinfo, "areaEventInfo", "encoding", true)
		}
		enc_areaeventinfo = retagged_enc_areaeventinfo
		children = append(children, enc_areaeventinfo...)
	}
	if v.HGmlcAddress != nil {
		if len(*v.HGmlcAddress) < 5 || len(*v.HGmlcAddress) > 17 {
			if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(nil, "MAP-LCS-DataTypes.ProvideSubscriberLocation-Arg", ber.RuleRef{Document: "ITU-T X.680", Edition: "02/2021", Clause: "51.5"}), "h-gmlc-Address", "SIZE (5..17)", len(*v.HGmlcAddress)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_hgmlcaddress, encodeErr_enc_hgmlcaddress := ber.EncodeOctetString([]byte(*v.HGmlcAddress))
		if encodeErr_enc_hgmlcaddress != nil {
			return nil, qualifyBERError(encodeErr_enc_hgmlcaddress, "h-gmlc-Address", "encoding", true)
		}
		retagged_enc_hgmlcaddress, tagErr_enc_hgmlcaddress := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 15, enc_hgmlcaddress)
		if tagErr_enc_hgmlcaddress != nil {
			return nil, qualifyBERError(tagErr_enc_hgmlcaddress, "h-gmlc-Address", "encoding", true)
		}
		enc_hgmlcaddress = retagged_enc_hgmlcaddress
		children = append(children, enc_hgmlcaddress...)
	}
	if v.MoLrShortCircuitIndicator != nil {
		enc_molrshortcircuitindicator := ber.EncodeNull()
		retagged_enc_molrshortcircuitindicator, tagErr_enc_molrshortcircuitindicator := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 16, enc_molrshortcircuitindicator)
		if tagErr_enc_molrshortcircuitindicator != nil {
			return nil, qualifyBERError(tagErr_enc_molrshortcircuitindicator, "mo-lrShortCircuitIndicator", "encoding", true)
		}
		enc_molrshortcircuitindicator = retagged_enc_molrshortcircuitindicator
		children = append(children, enc_molrshortcircuitindicator...)
	}
	if v.PeriodicLDRInfo != nil {
		enc_periodicldrinfo, err := v.PeriodicLDRInfo.MarshalDER()
		if err != nil {
			return nil, qualifyBERError(err, "periodicLDRInfo", "encoding", true)
		}
		retagged_enc_periodicldrinfo, tagErr_enc_periodicldrinfo := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 17, enc_periodicldrinfo)
		if tagErr_enc_periodicldrinfo != nil {
			return nil, qualifyBERError(tagErr_enc_periodicldrinfo, "periodicLDRInfo", "encoding", true)
		}
		enc_periodicldrinfo = retagged_enc_periodicldrinfo
		children = append(children, enc_periodicldrinfo...)
	}
	if v.ReportingPLMNList != nil {
		enc_reportingplmnlist, err := v.ReportingPLMNList.MarshalDER()
		if err != nil {
			return nil, qualifyBERError(err, "reportingPLMNList", "encoding", true)
		}
		retagged_enc_reportingplmnlist, tagErr_enc_reportingplmnlist := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 18, enc_reportingplmnlist)
		if tagErr_enc_reportingplmnlist != nil {
			return nil, qualifyBERError(tagErr_enc_reportingplmnlist, "reportingPLMNList", "encoding", true)
		}
		enc_reportingplmnlist = retagged_enc_reportingplmnlist
		children = append(children, enc_reportingplmnlist...)
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
		if i == 0 && ((peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 18) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 17) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 16) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 15) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 14) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 13) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 12) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 11) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 10) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 9) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 8) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 7) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 6) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 5) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0)) {
			if constraintErr := ber.CheckEncodedValue(ber.EncodeRule(nil, "MAP-LCS-DataTypes.ProvideSubscriberLocation-Arg", ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
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
		return nil, fmt.Errorf("%s: %w", "encoding LCSProvideSubscriberLocationArg as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}
func (v *LCSProvideSubscriberLocationArg) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	encoded, err := v.MarshalDER()
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBER decodes LCSProvideSubscriberLocationArg from BER/DER format.
func (destination *LCSProvideSubscriberLocationArg) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if destination == nil {
		return fmt.Errorf("%w: LCSProvideSubscriberLocationArg destination is nil", ber.ErrInvalidValue)
	}
	var berNextValue_ LCSProvideSubscriberLocationArg
	v :=
		&berNextValue_
	defer func() {
		if returnErr ==
			nil {
			*destination = *v
		}
	}()

	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	ownedData, ownErr := ber.OwnGeneratedBERInput(data, opts)
	if ownErr != nil {
		return ownErr
	}
	data = ownedData
	preparedData, preparedOptions, prepareErr := ber.PrepareGeneratedBERInput(data, opts)
	if prepareErr != nil {
		return ber.DiagnosePreflight(prepareErr, data, opts, "child", func(probeOpts []ber.DecodeOption) error {
			var probe LCSProvideSubscriberLocationArg
			return probe.UnmarshalBER(data, probeOpts...)
		})
	}
	data, opts = preparedData, preparedOptions
	opts = ber.LocateDecodedElement(data, "MAP-LCS-DataTypes.ProvideSubscriberLocation-Arg", opts)
	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
	*v = LCSProvideSubscriberLocationArg{}
	defer func() {
		if returnErr != nil || !ber.BERNeedsPreservation(opts) {
			return
		}
		v.berReplayNode_ = ber.CaptureGeneratedBERReplay(data, opts)
		returnErr = ber.CompleteGeneratedBERDecode(opts, v, func(base *LCSProvideSubscriberLocationArg, replayOpts ...ber.EncodeOption) ([]byte, error) {
			return base.MarshalBER(replayOpts...)
		})
	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("%s: %w", "decoding LCSProvideSubscriberLocationArg SEQUENCE", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "LCSProvideSubscriberLocationArg", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode locationType
	if offset >= len(content) {
		return fmt.Errorf("missing required field locationType")
	}
	{
		ber.MarkPreflightTarget(opts, "locationType", content[offset:])
		// Decode nested SEQUENCE (LCSLocationType)
		_, n_locationtype, _, tlvErr_locationtype := ber.DecodeTLV(content[offset:], opts...)
		if tlvErr_locationtype != nil {
			return qualifyBERError(tlvErr_locationtype, "locationType", "decoding", false)
		}
		if offset > len(content) || n_locationtype < 0 || n_locationtype > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		if unmErr := v.LocationType.UnmarshalBER(content[offset:offset+n_locationtype], ber.ChildDecodeOptions(opts, "locationType")...); unmErr != nil {
			return qualifyBERError(unmErr, "locationType", "decoding", false)
		}
		if offset > len(content) || n_locationtype < 0 || n_locationtype > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n_locationtype
	}
	// Decode mlc-Number
	if offset >= len(content) {
		return fmt.Errorf("missing required field mlc-Number")
	}
	{
		ber.MarkPreflightTarget(opts, "mlc-Number", content[offset:])
		val_mlcnumber, n, err := ber.DecodeOctetString(content[offset:], opts...)
		if err != nil {
			return qualifyBERError(err, "mlc-Number", "decoding", false)
		}
		v.MlcNumber = v21_map_commondatatypes.CommonDataTypesISDNAddressString(val_mlcnumber)
		if offset < 0 || offset >
			len(content) || n < 0 || n > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n
		if len(v.MlcNumber) < 1 || len(v.MlcNumber) > 9 {
			if constraintErr := ber.CheckDecodedLength(ber.DecodeRule(opts, "MAP-LCS-DataTypes.ProvideSubscriberLocation-Arg", ber.RuleRef{Document: "ITU-T X.680", Edition: "02/2021", Clause: "51.5"}), "mlc-Number", "SIZE (1..9)", len(v.MlcNumber)); constraintErr != nil {
				return constraintErr
			}
		}
		if len(v.MlcNumber) < 1 || len(v.MlcNumber) > 20 {
			if constraintErr := ber.CheckDecodedLength(ber.DecodeRule(opts, "MAP-LCS-DataTypes.ProvideSubscriberLocation-Arg", ber.RuleRef{Document: "ITU-T X.680", Edition: "02/2021", Clause: "51.5"}), "mlc-Number", "SIZE (1..20)", len(v.MlcNumber)); constraintErr != nil {
				return constraintErr
			}
		}
	}
	// Decode lcs-ClientID
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
				ber.MarkPreflightTarget(opts, "lcs-ClientID", content[offset:])
				decodedTag_lcsclientid, n_lcsclientid, rawVal_lcsclientid, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "lcs-ClientID", "decoding", false)
				}
				if decodedTag_lcsclientid.Class != tag.ClassContextSpecific || decodedTag_lcsclientid.Number != 0 || decodedTag_lcsclientid.Constructed != true {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_lcsclientid), "lcs-ClientID", "decoding", false)
				}
				_ = rawVal_lcsclientid
				if offset < 0 || offset >
					len(content) || n_lcsclientid < 0 || n_lcsclientid > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				reconstructed_lcsclientid, reconstructionErr_lcsclientid := ber.EncodeImplicitTagWithClass(tag.ClassUniversal, tag.TagSequence, content[offset:offset+n_lcsclientid])
				if reconstructionErr_lcsclientid != nil {
					return qualifyBERError(reconstructionErr_lcsclientid, "lcs-ClientID", "decoding", false)
				}
				var dec_lcsclientid LCSLCSClientID
				if unmErr := dec_lcsclientid.UnmarshalBER(reconstructed_lcsclientid, ber.ChildDecodeOptions(opts, "lcs-ClientID")...); unmErr != nil {
					return qualifyBERError(unmErr, "lcs-ClientID", "decoding", false)
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
				ber.MarkPreflightTarget(opts, "privacyOverride", content[offset:])
				decodedTag_privacyoverride, n_privacyoverride, rawVal_privacyoverride, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "privacyOverride", "decoding", false)
				}
				if decodedTag_privacyoverride.Class != tag.ClassContextSpecific || decodedTag_privacyoverride.Number != 1 || decodedTag_privacyoverride.Constructed != false {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_privacyoverride), "privacyOverride", "decoding", false)
				}
				if len(rawVal_privacyoverride) != 0 {
					return qualifyBERError(fmt.Errorf("%w: NULL content length %d", ber.ErrInvalidValue, len(rawVal_privacyoverride)), "privacyOverride", "decoding", false)
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
				ber.MarkPreflightTarget(opts, "imsi", content[offset:])
				decodedTag_imsi, n_imsi, rawVal_imsi, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "imsi", "decoding", false)
				}
				if decodedTag_imsi.Class != tag.ClassContextSpecific || decodedTag_imsi.Number != 2 {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_imsi), "imsi", "decoding", false)
				}
				decVal_imsi, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_imsi.Constructed, rawVal_imsi, opts...)
				if octetErr != nil {
					return qualifyBERError(octetErr, "imsi", "decoding", false)
				}
				tmp_imsi := v21_map_commondatatypes.CommonDataTypesIMSI(decVal_imsi)
				v.Imsi = &tmp_imsi
				if offset < 0 || offset >
					len(content) || n_imsi < 0 || n_imsi > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_imsi
				if len(*v.Imsi) < 3 || len(*v.Imsi) > 8 {
					if constraintErr := ber.CheckDecodedLength(ber.DecodeRule(opts, "MAP-LCS-DataTypes.ProvideSubscriberLocation-Arg", ber.RuleRef{Document: "ITU-T X.680", Edition: "02/2021", Clause: "51.5"}), "imsi", "SIZE (3..8)", len(*v.Imsi)); constraintErr != nil {
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
				ber.MarkPreflightTarget(opts, "msisdn", content[offset:])
				decodedTag_msisdn, n_msisdn, rawVal_msisdn, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "msisdn", "decoding", false)
				}
				if decodedTag_msisdn.Class != tag.ClassContextSpecific || decodedTag_msisdn.Number != 3 {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_msisdn), "msisdn", "decoding", false)
				}
				decVal_msisdn, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_msisdn.Constructed, rawVal_msisdn, opts...)
				if octetErr != nil {
					return qualifyBERError(octetErr, "msisdn", "decoding", false)
				}
				tmp_msisdn := v21_map_commondatatypes.CommonDataTypesISDNAddressString(decVal_msisdn)
				v.Msisdn = &tmp_msisdn
				if offset < 0 || offset >
					len(content) || n_msisdn < 0 || n_msisdn > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_msisdn
				if len(*v.Msisdn) < 1 || len(*v.Msisdn) > 9 {
					if constraintErr := ber.CheckDecodedLength(ber.DecodeRule(opts, "MAP-LCS-DataTypes.ProvideSubscriberLocation-Arg", ber.RuleRef{Document: "ITU-T X.680", Edition: "02/2021", Clause: "51.5"}), "msisdn", "SIZE (1..9)", len(*v.Msisdn)); constraintErr != nil {
						return constraintErr
					}
				}
				if len(*v.Msisdn) < 1 || len(*v.Msisdn) > 20 {
					if constraintErr := ber.CheckDecodedLength(ber.DecodeRule(opts, "MAP-LCS-DataTypes.ProvideSubscriberLocation-Arg", ber.RuleRef{Document: "ITU-T X.680", Edition: "02/2021", Clause: "51.5"}), "msisdn", "SIZE (1..20)", len(*v.Msisdn)); constraintErr != nil {
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
				ber.MarkPreflightTarget(opts, "lmsi", content[offset:])
				decodedTag_lmsi, n_lmsi, rawVal_lmsi, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "lmsi", "decoding", false)
				}
				if decodedTag_lmsi.Class != tag.ClassContextSpecific || decodedTag_lmsi.Number != 4 {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_lmsi), "lmsi", "decoding", false)
				}
				decVal_lmsi, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_lmsi.Constructed, rawVal_lmsi, opts...)
				if octetErr != nil {
					return qualifyBERError(octetErr, "lmsi", "decoding", false)
				}
				tmp_lmsi := v21_map_commondatatypes.CommonDataTypesLMSI(decVal_lmsi)
				v.Lmsi = &tmp_lmsi
				if offset < 0 || offset >
					len(content) || n_lmsi < 0 || n_lmsi > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_lmsi
				if len(*v.Lmsi) < 4 || len(*v.Lmsi) > 4 {
					if constraintErr := ber.CheckDecodedLength(ber.DecodeRule(opts, "MAP-LCS-DataTypes.ProvideSubscriberLocation-Arg", ber.RuleRef{Document: "ITU-T X.680", Edition: "02/2021", Clause: "51.5"}), "lmsi", "SIZE (4)", len(*v.Lmsi)); constraintErr != nil {
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
				ber.MarkPreflightTarget(opts, "imei", content[offset:])
				decodedTag_imei, n_imei, rawVal_imei, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "imei", "decoding", false)
				}
				if decodedTag_imei.Class != tag.ClassContextSpecific || decodedTag_imei.Number != 5 {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_imei), "imei", "decoding", false)
				}
				decVal_imei, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_imei.Constructed, rawVal_imei, opts...)
				if octetErr != nil {
					return qualifyBERError(octetErr, "imei", "decoding", false)
				}
				tmp_imei := v21_map_commondatatypes.CommonDataTypesIMEI(decVal_imei)
				v.Imei = &tmp_imei
				if offset < 0 || offset >
					len(content) || n_imei < 0 || n_imei > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_imei
				if len(*v.Imei) < 8 || len(*v.Imei) > 8 {
					if constraintErr := ber.CheckDecodedLength(ber.DecodeRule(opts, "MAP-LCS-DataTypes.ProvideSubscriberLocation-Arg", ber.RuleRef{Document: "ITU-T X.680", Edition: "02/2021", Clause: "51.5"}), "imei", "SIZE (8)", len(*v.Imei)); constraintErr != nil {
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
				ber.MarkPreflightTarget(opts, "lcs-Priority", content[offset:])
				decodedTag_lcspriority, n_lcspriority, rawVal_lcspriority, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "lcs-Priority", "decoding", false)
				}
				if decodedTag_lcspriority.Class != tag.ClassContextSpecific || decodedTag_lcspriority.Number != 6 {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_lcspriority), "lcs-Priority", "decoding", false)
				}
				decVal_lcspriority, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_lcspriority.Constructed, rawVal_lcspriority, opts...)
				if octetErr != nil {
					return qualifyBERError(octetErr, "lcs-Priority", "decoding", false)
				}
				tmp_lcspriority := LCSLCSPriority(decVal_lcspriority)
				v.LcsPriority = &tmp_lcspriority
				if offset < 0 || offset >
					len(content) || n_lcspriority < 0 || n_lcspriority > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_lcspriority
				if len(*v.LcsPriority) < 1 || len(*v.LcsPriority) > 1 {
					if constraintErr := ber.CheckDecodedLength(ber.DecodeRule(opts, "MAP-LCS-DataTypes.ProvideSubscriberLocation-Arg", ber.RuleRef{Document: "ITU-T X.680", Edition: "02/2021", Clause: "51.5"}), "lcs-Priority", "SIZE (1)", len(*v.LcsPriority)); constraintErr != nil {
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
				ber.MarkPreflightTarget(opts, "lcs-QoS", content[offset:])
				decodedTag_lcsqos, n_lcsqos, rawVal_lcsqos, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "lcs-QoS", "decoding", false)
				}
				if decodedTag_lcsqos.Class != tag.ClassContextSpecific || decodedTag_lcsqos.Number != 7 || decodedTag_lcsqos.Constructed != true {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_lcsqos), "lcs-QoS", "decoding", false)
				}
				_ = rawVal_lcsqos
				if offset < 0 || offset >
					len(content) || n_lcsqos < 0 || n_lcsqos > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				reconstructed_lcsqos, reconstructionErr_lcsqos := ber.EncodeImplicitTagWithClass(tag.ClassUniversal, tag.TagSequence, content[offset:offset+n_lcsqos])
				if reconstructionErr_lcsqos != nil {
					return qualifyBERError(reconstructionErr_lcsqos, "lcs-QoS", "decoding", false)
				}
				var dec_lcsqos LCSLCSQoS
				if unmErr := dec_lcsqos.UnmarshalBER(reconstructed_lcsqos, ber.ChildDecodeOptions(opts, "lcs-QoS")...); unmErr != nil {
					return qualifyBERError(unmErr, "lcs-QoS", "decoding", false)
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
				ber.MarkPreflightTarget(opts, "extensionContainer", content[offset:])
				decodedTag_extensioncontainer, n_extensioncontainer, rawVal_extensioncontainer, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "extensionContainer", "decoding", false)
				}
				if decodedTag_extensioncontainer.Class != tag.ClassContextSpecific || decodedTag_extensioncontainer.Number != 8 || decodedTag_extensioncontainer.Constructed != true {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_extensioncontainer), "extensionContainer", "decoding", false)
				}
				_ = rawVal_extensioncontainer
				if offset < 0 || offset >
					len(content) || n_extensioncontainer < 0 || n_extensioncontainer > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				reconstructed_extensioncontainer, reconstructionErr_extensioncontainer := ber.EncodeImplicitTagWithClass(tag.ClassUniversal, tag.TagSequence, content[offset:offset+n_extensioncontainer])
				if reconstructionErr_extensioncontainer != nil {
					return qualifyBERError(reconstructionErr_extensioncontainer, "extensionContainer", "decoding", false)
				}
				var dec_extensioncontainer v21_map_extensiondatatypes.ExtensionDataTypesExtensionContainer
				if unmErr := dec_extensioncontainer.UnmarshalBER(reconstructed_extensioncontainer, ber.ChildDecodeOptions(opts, "extensionContainer")...); unmErr != nil {
					return qualifyBERError(unmErr, "extensionContainer", "decoding", false)
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
				ber.MarkPreflightTarget(opts, "supportedGADShapes", content[offset:])
				decodedTag_supportedgadshapes, n_supportedgadshapes, rawVal_supportedgadshapes, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "supportedGADShapes", "decoding", false)
				}
				if decodedTag_supportedgadshapes.Class != tag.ClassContextSpecific || decodedTag_supportedgadshapes.Number != 9 {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_supportedgadshapes), "supportedGADShapes", "decoding", false)
				}
				bsBytes_supportedgadshapes, bsUnused_supportedgadshapes, bsErr := ber.DecodeImplicitBitStringValue(decodedTag_supportedgadshapes.Constructed, rawVal_supportedgadshapes, opts...)
				if bsErr != nil {
					return qualifyBERError(bsErr, "supportedGADShapes", "decoding", false)
				}
				bsBitLength_supportedgadshapes, bsLenErr_supportedgadshapes := ber.BitStringBitLength(len(bsBytes_supportedgadshapes), bsUnused_supportedgadshapes)
				if bsLenErr_supportedgadshapes != nil {
					return qualifyBERError(bsLenErr_supportedgadshapes, "supportedGADShapes", "decoding", false)
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
					if constraintErr := ber.CheckDecodedLength(ber.DecodeRule(opts, "MAP-LCS-DataTypes.ProvideSubscriberLocation-Arg", ber.RuleRef{Document: "ITU-T X.680", Edition: "02/2021", Clause: "51.5"}), "supportedGADShapes", "SIZE (7..16)", (*v.SupportedGADShapes).BitLength); constraintErr != nil {
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
				ber.MarkPreflightTarget(opts, "lcs-ReferenceNumber", content[offset:])
				decodedTag_lcsreferencenumber, n_lcsreferencenumber, rawVal_lcsreferencenumber, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "lcs-ReferenceNumber", "decoding", false)
				}
				if decodedTag_lcsreferencenumber.Class != tag.ClassContextSpecific || decodedTag_lcsreferencenumber.Number != 10 {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_lcsreferencenumber), "lcs-ReferenceNumber", "decoding", false)
				}
				decVal_lcsreferencenumber, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_lcsreferencenumber.Constructed, rawVal_lcsreferencenumber, opts...)
				if octetErr != nil {
					return qualifyBERError(octetErr, "lcs-ReferenceNumber", "decoding", false)
				}
				tmp_lcsreferencenumber := LCSLCSReferenceNumber(decVal_lcsreferencenumber)
				v.LcsReferenceNumber = &tmp_lcsreferencenumber
				if offset < 0 || offset >
					len(content) || n_lcsreferencenumber < 0 || n_lcsreferencenumber > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_lcsreferencenumber
				if len(*v.LcsReferenceNumber) < 1 || len(*v.LcsReferenceNumber) > 1 {
					if constraintErr := ber.CheckDecodedLength(ber.DecodeRule(opts, "MAP-LCS-DataTypes.ProvideSubscriberLocation-Arg", ber.RuleRef{Document: "ITU-T X.680", Edition: "02/2021", Clause: "51.5"}), "lcs-ReferenceNumber", "SIZE (1)", len(*v.LcsReferenceNumber)); constraintErr != nil {
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
				ber.MarkPreflightTarget(opts, "lcsServiceTypeID", content[offset:])
				decodedTag_lcsservicetypeid, n_lcsservicetypeid, rawVal_lcsservicetypeid, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "lcsServiceTypeID", "decoding", false)
				}
				if decodedTag_lcsservicetypeid.Class != tag.ClassContextSpecific || decodedTag_lcsservicetypeid.Number != 11 || decodedTag_lcsservicetypeid.Constructed != false {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_lcsservicetypeid), "lcsServiceTypeID", "decoding", false)
				}
				decVal_lcsservicetypeid, intErr := ber.DecodeIntegerValue(rawVal_lcsservicetypeid)
				if intErr != nil {
					return qualifyBERError(intErr, "lcsServiceTypeID", "decoding", false)
				}
				tmp_lcsservicetypeid := v21_map_commondatatypes.CommonDataTypesLCSServiceTypeID(decVal_lcsservicetypeid)
				v.LcsServiceTypeID = &tmp_lcsservicetypeid
				if offset < 0 || offset >
					len(content) || n_lcsservicetypeid < 0 || n_lcsservicetypeid > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_lcsservicetypeid
				if !(int64(*v.LcsServiceTypeID) >= 0 && int64(*v.LcsServiceTypeID) <= 127) {
					if constraintErr := ber.CheckDecodedValue(ber.DecodeRule(opts, "MAP-LCS-DataTypes.ProvideSubscriberLocation-Arg", ber.RuleRef{Document: "ITU-T X.680", Edition: "02/2021", Clause: "51.4"}), "lcsServiceTypeID", "(0..127)", ber.ObserveInteger(int64(*v.LcsServiceTypeID))); constraintErr != nil {
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
				ber.MarkPreflightTarget(opts, "lcsCodeword", content[offset:])
				decodedTag_lcscodeword, n_lcscodeword, rawVal_lcscodeword, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "lcsCodeword", "decoding", false)
				}
				if decodedTag_lcscodeword.Class != tag.ClassContextSpecific || decodedTag_lcscodeword.Number != 12 || decodedTag_lcscodeword.Constructed != true {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_lcscodeword), "lcsCodeword", "decoding", false)
				}
				_ = rawVal_lcscodeword
				if offset < 0 || offset >
					len(content) || n_lcscodeword < 0 || n_lcscodeword > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				reconstructed_lcscodeword, reconstructionErr_lcscodeword := ber.EncodeImplicitTagWithClass(tag.ClassUniversal, tag.TagSequence, content[offset:offset+n_lcscodeword])
				if reconstructionErr_lcscodeword != nil {
					return qualifyBERError(reconstructionErr_lcscodeword, "lcsCodeword", "decoding", false)
				}
				var dec_lcscodeword LCSLCSCodeword
				if unmErr := dec_lcscodeword.UnmarshalBER(reconstructed_lcscodeword, ber.ChildDecodeOptions(opts, "lcsCodeword")...); unmErr != nil {
					return qualifyBERError(unmErr, "lcsCodeword", "decoding", false)
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
				ber.MarkPreflightTarget(opts, "lcs-PrivacyCheck", content[offset:])
				decodedTag_lcsprivacycheck, n_lcsprivacycheck, rawVal_lcsprivacycheck, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "lcs-PrivacyCheck", "decoding", false)
				}
				if decodedTag_lcsprivacycheck.Class != tag.ClassContextSpecific || decodedTag_lcsprivacycheck.Number != 13 || decodedTag_lcsprivacycheck.Constructed != true {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_lcsprivacycheck), "lcs-PrivacyCheck", "decoding", false)
				}
				_ = rawVal_lcsprivacycheck
				if offset < 0 || offset >
					len(content) || n_lcsprivacycheck < 0 || n_lcsprivacycheck > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				reconstructed_lcsprivacycheck, reconstructionErr_lcsprivacycheck := ber.EncodeImplicitTagWithClass(tag.ClassUniversal, tag.TagSequence, content[offset:offset+n_lcsprivacycheck])
				if reconstructionErr_lcsprivacycheck != nil {
					return qualifyBERError(reconstructionErr_lcsprivacycheck, "lcs-PrivacyCheck", "decoding", false)
				}
				var dec_lcsprivacycheck LCSLCSPrivacyCheck
				if unmErr := dec_lcsprivacycheck.UnmarshalBER(reconstructed_lcsprivacycheck, ber.ChildDecodeOptions(opts, "lcs-PrivacyCheck")...); unmErr != nil {
					return qualifyBERError(unmErr, "lcs-PrivacyCheck", "decoding", false)
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
				ber.MarkPreflightTarget(opts, "areaEventInfo", content[offset:])
				decodedTag_areaeventinfo, n_areaeventinfo, rawVal_areaeventinfo, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "areaEventInfo", "decoding", false)
				}
				if decodedTag_areaeventinfo.Class != tag.ClassContextSpecific || decodedTag_areaeventinfo.Number != 14 || decodedTag_areaeventinfo.Constructed != true {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_areaeventinfo), "areaEventInfo", "decoding", false)
				}
				_ = rawVal_areaeventinfo
				if offset < 0 || offset >
					len(content) || n_areaeventinfo < 0 || n_areaeventinfo > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				reconstructed_areaeventinfo, reconstructionErr_areaeventinfo := ber.EncodeImplicitTagWithClass(tag.ClassUniversal, tag.TagSequence, content[offset:offset+n_areaeventinfo])
				if reconstructionErr_areaeventinfo != nil {
					return qualifyBERError(reconstructionErr_areaeventinfo, "areaEventInfo", "decoding", false)
				}
				var dec_areaeventinfo LCSAreaEventInfo
				if unmErr := dec_areaeventinfo.UnmarshalBER(reconstructed_areaeventinfo, ber.ChildDecodeOptions(opts, "areaEventInfo")...); unmErr != nil {
					return qualifyBERError(unmErr, "areaEventInfo", "decoding", false)
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
				ber.MarkPreflightTarget(opts, "h-gmlc-Address", content[offset:])
				decodedTag_hgmlcaddress, n_hgmlcaddress, rawVal_hgmlcaddress, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "h-gmlc-Address", "decoding", false)
				}
				if decodedTag_hgmlcaddress.Class != tag.ClassContextSpecific || decodedTag_hgmlcaddress.Number != 15 {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_hgmlcaddress), "h-gmlc-Address", "decoding", false)
				}
				decVal_hgmlcaddress, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_hgmlcaddress.Constructed, rawVal_hgmlcaddress, opts...)
				if octetErr != nil {
					return qualifyBERError(octetErr, "h-gmlc-Address", "decoding", false)
				}
				tmp_hgmlcaddress := v21_map_commondatatypes.CommonDataTypesGSNAddress(decVal_hgmlcaddress)
				v.HGmlcAddress = &tmp_hgmlcaddress
				if offset < 0 || offset >
					len(content) || n_hgmlcaddress < 0 || n_hgmlcaddress > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_hgmlcaddress
				if len(*v.HGmlcAddress) < 5 || len(*v.HGmlcAddress) > 17 {
					if constraintErr := ber.CheckDecodedLength(ber.DecodeRule(opts, "MAP-LCS-DataTypes.ProvideSubscriberLocation-Arg", ber.RuleRef{Document: "ITU-T X.680", Edition: "02/2021", Clause: "51.5"}), "h-gmlc-Address", "SIZE (5..17)", len(*v.HGmlcAddress)); constraintErr != nil {
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
				ber.MarkPreflightTarget(opts, "mo-lrShortCircuitIndicator", content[offset:])
				decodedTag_molrshortcircuitindicator, n_molrshortcircuitindicator, rawVal_molrshortcircuitindicator, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "mo-lrShortCircuitIndicator", "decoding", false)
				}
				if decodedTag_molrshortcircuitindicator.Class != tag.ClassContextSpecific || decodedTag_molrshortcircuitindicator.Number != 16 || decodedTag_molrshortcircuitindicator.Constructed != false {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_molrshortcircuitindicator), "mo-lrShortCircuitIndicator", "decoding", false)
				}
				if len(rawVal_molrshortcircuitindicator) != 0 {
					return qualifyBERError(fmt.Errorf("%w: NULL content length %d", ber.ErrInvalidValue, len(rawVal_molrshortcircuitindicator)), "mo-lrShortCircuitIndicator", "decoding", false)
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
				ber.MarkPreflightTarget(opts, "periodicLDRInfo", content[offset:])
				decodedTag_periodicldrinfo, n_periodicldrinfo, rawVal_periodicldrinfo, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "periodicLDRInfo", "decoding", false)
				}
				if decodedTag_periodicldrinfo.Class != tag.ClassContextSpecific || decodedTag_periodicldrinfo.Number != 17 || decodedTag_periodicldrinfo.Constructed != true {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_periodicldrinfo), "periodicLDRInfo", "decoding", false)
				}
				_ = rawVal_periodicldrinfo
				if offset < 0 || offset >
					len(content) || n_periodicldrinfo < 0 || n_periodicldrinfo > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				reconstructed_periodicldrinfo, reconstructionErr_periodicldrinfo := ber.EncodeImplicitTagWithClass(tag.ClassUniversal, tag.TagSequence, content[offset:offset+n_periodicldrinfo])
				if reconstructionErr_periodicldrinfo != nil {
					return qualifyBERError(reconstructionErr_periodicldrinfo, "periodicLDRInfo", "decoding", false)
				}
				var dec_periodicldrinfo LCSPeriodicLDRInfo
				if unmErr := dec_periodicldrinfo.UnmarshalBER(reconstructed_periodicldrinfo, ber.ChildDecodeOptions(opts, "periodicLDRInfo")...); unmErr != nil {
					return qualifyBERError(unmErr, "periodicLDRInfo", "decoding", false)
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
				ber.MarkPreflightTarget(opts, "reportingPLMNList", content[offset:])
				decodedTag_reportingplmnlist, n_reportingplmnlist, rawVal_reportingplmnlist, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "reportingPLMNList", "decoding", false)
				}
				if decodedTag_reportingplmnlist.Class != tag.ClassContextSpecific || decodedTag_reportingplmnlist.Number != 18 || decodedTag_reportingplmnlist.Constructed != true {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_reportingplmnlist), "reportingPLMNList", "decoding", false)
				}
				_ = rawVal_reportingplmnlist
				if offset < 0 || offset >
					len(content) || n_reportingplmnlist < 0 || n_reportingplmnlist > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				reconstructed_reportingplmnlist, reconstructionErr_reportingplmnlist := ber.EncodeImplicitTagWithClass(tag.ClassUniversal, tag.TagSequence, content[offset:offset+n_reportingplmnlist])
				if reconstructionErr_reportingplmnlist != nil {
					return qualifyBERError(reconstructionErr_reportingplmnlist, "reportingPLMNList", "decoding", false)
				}
				var dec_reportingplmnlist LCSReportingPLMNList
				if unmErr := dec_reportingplmnlist.UnmarshalBER(reconstructed_reportingplmnlist, ber.ChildDecodeOptions(opts, "reportingPLMNList")...); unmErr != nil {
					return qualifyBERError(unmErr, "reportingPLMNList", "decoding", false)
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
		peekTag, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:], opts...)
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "LCSProvideSubscriberLocationArg", Cause: extErr_}
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: the first unknown addition must differ from trailing OPTIONAL/DEFAULT tags.
		if len(v.ExtData_) == 0 && ((peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 18) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 17) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 16) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 15) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 14) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 13) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 12) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 11) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 10) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 9) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 8) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 7) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 6) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 5) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0)) {
			if !ber.ToleranceEnabled(opts) {
				return &ber.DecodeError{Offset: offset, TypeName: "LCSProvideSubscriberLocationArg", Cause: fmt.Errorf("%w: repeated or out-of-order SEQUENCE component tag %s", ber.ErrInvalidTag, peekTag)}
			}
			if orderErr_ := ber.CheckDecodedValue(ber.DecodeRule(opts, "MAP-LCS-DataTypes.ProvideSubscriberLocation-Arg", ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), fmt.Sprintf("ExtData_[%d]", len(v.ExtData_)), "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); orderErr_ != nil {
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

// MarshalBER encodes LCSLocationType to BER format.
func (v *LCSLocationType) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: LCSLocationType receiver is nil", ber.ErrInvalidValue)
	}
	if v.berReplayNode_ == nil {
		return v.marshalBER(opts...)
	}
	var replayErr error
	opts, replayErr = ber.PrepareBERReplay(v.berReplayNode_, opts, func(mode ber.EncodeOption) ([]byte, error) { return v.MarshalBER([]ber.EncodeOption{mode}...) }, v)
	if replayErr != nil {
		return nil, replayErr
	}
	if replayBytes, ok := ber.PreparedBERReplay(v.berReplayNode_, opts); ok {
		return replayBytes, nil
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBERNode(encoded, v.berReplayNode_, opts), nil
}
func (v *LCSLocationType) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	enc_locationestimatetype := ber.EncodeEnumerated(int64(v.LocationEstimateType))
	retagged_enc_locationestimatetype, tagErr_enc_locationestimatetype := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_locationestimatetype)
	if tagErr_enc_locationestimatetype != nil {
		return nil, qualifyBERError(tagErr_enc_locationestimatetype, "locationEstimateType", "encoding", false)
	}
	enc_locationestimatetype = retagged_enc_locationestimatetype
	children = append(children, enc_locationestimatetype...)
	if v.DeferredLocationEventType != nil {
		if bitStringErr := ber.ValidateBitStringLength(v.DeferredLocationEventType.Bytes, v.DeferredLocationEventType.BitLength); bitStringErr != nil {
			return nil, qualifyBERError(bitStringErr, "deferredLocationEventType", "encoding", false)
		}
		// arithmetic pattern BER_BITSTRING_FIELD: 0 <= bit length before modulo and subtraction; gen/codegen.go:743
		if v.DeferredLocationEventType.BitLength < 0 {
			return nil, fmt.Errorf("negative bit string length")
		}
		if (*v.DeferredLocationEventType).BitLength < 1 || (*v.DeferredLocationEventType).BitLength > 16 {
			if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(opts, "MAP-LCS-DataTypes.LocationType", ber.RuleRef{Document: "ITU-T X.680", Edition: "02/2021", Clause: "51.5"}), "deferredLocationEventType", "SIZE (1..16)", (*v.DeferredLocationEventType).BitLength); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_deferredlocationeventtype, encodeErr_enc_deferredlocationeventtype := ber.EncodeBitString(v.DeferredLocationEventType.Bytes, ber.UnusedBitCount(v.DeferredLocationEventType.BitLength))
		if encodeErr_enc_deferredlocationeventtype != nil {
			return nil, qualifyBERError(encodeErr_enc_deferredlocationeventtype, "deferredLocationEventType", "encoding", false)
		}
		retagged_enc_deferredlocationeventtype, tagErr_enc_deferredlocationeventtype := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_deferredlocationeventtype)
		if tagErr_enc_deferredlocationeventtype != nil {
			return nil, qualifyBERError(tagErr_enc_deferredlocationeventtype, "deferredLocationEventType", "encoding", false)
		}
		enc_deferredlocationeventtype = retagged_enc_deferredlocationeventtype
		children = append(children, enc_deferredlocationeventtype...)
	}
	for i, ext := range v.ExtData_ {
		if err := ber.CheckBEROpaqueElement(ext, opts...); err != nil {
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
		if i == 0 && (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1) {
			if constraintErr := ber.CheckEncodedValue(ber.EncodeRule(opts, "MAP-LCS-DataTypes.LocationType", ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
				return nil, constraintErr
			}
		}
		children = append(children, ext...)
	}
	ber.RecordGeneratedBERContainer(opts, children)
	return ber.EncodeSequence(children)
}
func (v *LCSLocationType) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// MarshalDER encodes LCSLocationType to DER format.
// Opaque descendants pass generic DER checks; foreign schema rules need a typed binding.
func (v *LCSLocationType) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: LCSLocationType receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	enc_locationestimatetype := ber.EncodeEnumerated(int64(v.LocationEstimateType))
	retagged_enc_locationestimatetype, tagErr_enc_locationestimatetype := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_locationestimatetype)
	if tagErr_enc_locationestimatetype != nil {
		return nil, qualifyBERError(tagErr_enc_locationestimatetype, "locationEstimateType", "encoding", true)
	}
	enc_locationestimatetype = retagged_enc_locationestimatetype
	children = append(children, enc_locationestimatetype...)
	if v.DeferredLocationEventType != nil {
		if bitStringErr := ber.ValidateBitStringLength(v.DeferredLocationEventType.Bytes, v.DeferredLocationEventType.BitLength); bitStringErr != nil {
			return nil, qualifyBERError(bitStringErr, "deferredLocationEventType", "encoding", true)
		}
		if bitStringErr := ber.ValidateDERBitString(v.DeferredLocationEventType.Bytes, v.DeferredLocationEventType.BitLength); bitStringErr != nil {
			return nil, qualifyBERError(bitStringErr, "deferredLocationEventType", "encoding", true)
		}
		// arithmetic pattern BER_BITSTRING_FIELD: 0 <= bit length before modulo and subtraction; gen/codegen.go:743
		if v.DeferredLocationEventType.BitLength < 0 {
			return nil, fmt.Errorf("negative bit string length")
		}
		if (*v.DeferredLocationEventType).BitLength < 1 || (*v.DeferredLocationEventType).BitLength > 16 {
			if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(nil, "MAP-LCS-DataTypes.LocationType", ber.RuleRef{Document: "ITU-T X.680", Edition: "02/2021", Clause: "51.5"}), "deferredLocationEventType", "SIZE (1..16)", (*v.DeferredLocationEventType).BitLength); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_deferredlocationeventtype, encodeErr_enc_deferredlocationeventtype := ber.EncodeDERNamedBitString(v.DeferredLocationEventType.Bytes, v.DeferredLocationEventType.BitLength)
		if encodeErr_enc_deferredlocationeventtype != nil {
			return nil, qualifyBERError(encodeErr_enc_deferredlocationeventtype, "deferredLocationEventType", "encoding", true)
		}
		retagged_enc_deferredlocationeventtype, tagErr_enc_deferredlocationeventtype := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_deferredlocationeventtype)
		if tagErr_enc_deferredlocationeventtype != nil {
			return nil, qualifyBERError(tagErr_enc_deferredlocationeventtype, "deferredLocationEventType", "encoding", true)
		}
		enc_deferredlocationeventtype = retagged_enc_deferredlocationeventtype
		children = append(children, enc_deferredlocationeventtype...)
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
		if i == 0 && (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1) {
			if constraintErr := ber.CheckEncodedValue(ber.EncodeRule(nil, "MAP-LCS-DataTypes.LocationType", ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
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
		return nil, fmt.Errorf("%s: %w", "encoding LCSLocationType as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}
func (v *LCSLocationType) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	encoded, err := v.MarshalDER()
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBER decodes LCSLocationType from BER/DER format.
func (destination *LCSLocationType) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if destination == nil {
		return fmt.Errorf("%w: LCSLocationType destination is nil", ber.ErrInvalidValue)
	}
	var berNextValue_ LCSLocationType
	v := &berNextValue_

	defer func() {
		if returnErr == nil {
			*destination = *v
		}
	}()

	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	ownedData, ownErr := ber.OwnGeneratedBERInput(data, opts)
	if ownErr != nil {
		return ownErr
	}
	data = ownedData
	preparedData, preparedOptions, prepareErr := ber.PrepareGeneratedBERInput(data, opts)
	if prepareErr != nil {
		return ber.DiagnosePreflight(prepareErr, data, opts, "child", func(probeOpts []ber.DecodeOption) error {
			var probe LCSLocationType
			return probe.UnmarshalBER(data, probeOpts...)
		})
	}
	data, opts = preparedData, preparedOptions
	opts = ber.LocateDecodedElement(data, "MAP-LCS-DataTypes.LocationType", opts)
	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
	*v = LCSLocationType{}
	defer func() {
		if returnErr != nil || !ber.BERNeedsPreservation(opts) {
			return
		}
		v.berReplayNode_ = ber.CaptureGeneratedBERReplay(data, opts)
		returnErr = ber.CompleteGeneratedBERDecode(opts, v, func(base *LCSLocationType, replayOpts ...ber.EncodeOption) ([]byte, error) {
			return base.MarshalBER(replayOpts...)
		})
	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("%s: %w", "decoding LCSLocationType SEQUENCE", qualifyBERError(err, "", "decoding", false))
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
	{
		ber.MarkPreflightTarget(opts, "locationEstimateType", content[offset:])
		decodedTag_locationestimatetype, n_locationestimatetype, rawVal_locationestimatetype, err := ber.DecodeTLV(content[offset:], opts...)
		if err != nil {
			return qualifyBERError(err, "locationEstimateType", "decoding", false)
		}
		if decodedTag_locationestimatetype.Class != tag.ClassContextSpecific || decodedTag_locationestimatetype.Number != 0 || decodedTag_locationestimatetype.Constructed != false {
			return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_locationestimatetype), "locationEstimateType", "decoding", false)
		}
		decVal_locationestimatetype, intErr := ber.DecodeEnumeratedValue(rawVal_locationestimatetype)
		if intErr != nil {
			return qualifyBERError(intErr, "locationEstimateType", "decoding", false)
		}
		v.LocationEstimateType = LCSLocationEstimateType(decVal_locationestimatetype)
		if offset > len(content) || n_locationestimatetype < 0 || n_locationestimatetype >
			len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n_locationestimatetype
	}
	// Decode deferredLocationEventType
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
				ber.MarkPreflightTarget(opts, "deferredLocationEventType", content[offset:])
				decodedTag_deferredlocationeventtype, n_deferredlocationeventtype, rawVal_deferredlocationeventtype, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "deferredLocationEventType", "decoding", false)
				}
				if decodedTag_deferredlocationeventtype.Class != tag.ClassContextSpecific || decodedTag_deferredlocationeventtype.Number != 1 {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_deferredlocationeventtype), "deferredLocationEventType", "decoding", false)
				}
				bsBytes_deferredlocationeventtype, bsUnused_deferredlocationeventtype, bsErr := ber.DecodeImplicitBitStringValue(decodedTag_deferredlocationeventtype.Constructed, rawVal_deferredlocationeventtype, opts...)
				if bsErr != nil {
					return qualifyBERError(bsErr, "deferredLocationEventType", "decoding", false)
				}
				bsBitLength_deferredlocationeventtype, bsLenErr_deferredlocationeventtype := ber.BitStringBitLength(len(bsBytes_deferredlocationeventtype), bsUnused_deferredlocationeventtype)
				if bsLenErr_deferredlocationeventtype != nil {
					return qualifyBERError(bsLenErr_deferredlocationeventtype, "deferredLocationEventType", "decoding", false)
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
					if constraintErr := ber.CheckDecodedLength(ber.DecodeRule(opts, "MAP-LCS-DataTypes.LocationType", ber.RuleRef{Document: "ITU-T X.680", Edition: "02/2021", Clause: "51.5"}), "deferredLocationEventType", "SIZE (1..16)", (*v.DeferredLocationEventType).BitLength); constraintErr != nil {
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
			return &ber.DecodeError{Offset: offset, TypeName: "LCSLocationType", Cause: extErr_}
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: the first unknown addition must differ from trailing OPTIONAL/DEFAULT tags.
		if len(v.ExtData_) == 0 && (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1) {
			if !ber.ToleranceEnabled(opts) {
				return &ber.DecodeError{Offset: offset, TypeName: "LCSLocationType", Cause: fmt.Errorf("%w: repeated or out-of-order SEQUENCE component tag %s", ber.ErrInvalidTag, peekTag)}
			}
			if orderErr_ := ber.CheckDecodedValue(ber.DecodeRule(opts, "MAP-LCS-DataTypes.LocationType", ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), fmt.Sprintf("ExtData_[%d]", len(v.ExtData_)), "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); orderErr_ != nil {
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

// MarshalBER encodes LCSLCSClientID to BER format.
func (v *LCSLCSClientID) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: LCSLCSClientID receiver is nil", ber.ErrInvalidValue)
	}
	if v.berReplayNode_ == nil {
		return v.marshalBER(opts...)
	}
	var replayErr error
	opts, replayErr = ber.PrepareBERReplay(v.berReplayNode_, opts, func(mode ber.EncodeOption) ([]byte, error) { return v.MarshalBER([]ber.EncodeOption{mode}...) }, v)
	if replayErr != nil {
		return nil, replayErr
	}
	if replayBytes, ok := ber.PreparedBERReplay(v.berReplayNode_, opts); ok {
		return replayBytes, nil
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBERNode(encoded, v.berReplayNode_, opts), nil
}
func (v *LCSLCSClientID) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	enc_lcsclienttype := ber.EncodeEnumerated(int64(v.LcsClientType))
	retagged_enc_lcsclienttype, tagErr_enc_lcsclienttype := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_lcsclienttype)
	if tagErr_enc_lcsclienttype != nil {
		return nil, qualifyBERError(tagErr_enc_lcsclienttype, "lcsClientType", "encoding", false)
	}
	enc_lcsclienttype = retagged_enc_lcsclienttype
	children = append(children, enc_lcsclienttype...)
	if v.LcsClientExternalID != nil {
		enc_lcsclientexternalid, err := v.LcsClientExternalID.MarshalBER(ber.ChildEncodeOptions(opts, "lcsClientExternalID")...)
		if err != nil {
			return nil, qualifyBERError(err, "lcsClientExternalID", "encoding", false)
		}
		retagged_enc_lcsclientexternalid, tagErr_enc_lcsclientexternalid := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_lcsclientexternalid)
		if tagErr_enc_lcsclientexternalid != nil {
			return nil, qualifyBERError(tagErr_enc_lcsclientexternalid, "lcsClientExternalID", "encoding", false)
		}
		enc_lcsclientexternalid = retagged_enc_lcsclientexternalid
		ber.RecordGeneratedBERChildPlacement(opts, len(children), enc_lcsclientexternalid)
		children = append(children, enc_lcsclientexternalid...)
	}
	if v.LcsClientDialedByMS != nil {
		if len(*v.LcsClientDialedByMS) < 1 || len(*v.LcsClientDialedByMS) > 20 {
			if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(opts, "MAP-LCS-DataTypes.LCS-ClientID", ber.RuleRef{Document: "ITU-T X.680", Edition: "02/2021", Clause: "51.5"}), "lcsClientDialedByMS", "SIZE (1..20)", len(*v.LcsClientDialedByMS)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_lcsclientdialedbyms, encodeErr_enc_lcsclientdialedbyms := ber.EncodeOctetString([]byte(*v.LcsClientDialedByMS))
		if encodeErr_enc_lcsclientdialedbyms != nil {
			return nil, qualifyBERError(encodeErr_enc_lcsclientdialedbyms, "lcsClientDialedByMS", "encoding", false)
		}
		retagged_enc_lcsclientdialedbyms, tagErr_enc_lcsclientdialedbyms := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_lcsclientdialedbyms)
		if tagErr_enc_lcsclientdialedbyms != nil {
			return nil, qualifyBERError(tagErr_enc_lcsclientdialedbyms, "lcsClientDialedByMS", "encoding", false)
		}
		enc_lcsclientdialedbyms = retagged_enc_lcsclientdialedbyms
		children = append(children, enc_lcsclientdialedbyms...)
	}
	if v.LcsClientInternalID != nil {
		enc_lcsclientinternalid := ber.EncodeEnumerated(int64(*v.LcsClientInternalID))
		retagged_enc_lcsclientinternalid, tagErr_enc_lcsclientinternalid := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, enc_lcsclientinternalid)
		if tagErr_enc_lcsclientinternalid != nil {
			return nil, qualifyBERError(tagErr_enc_lcsclientinternalid, "lcsClientInternalID", "encoding", false)
		}
		enc_lcsclientinternalid = retagged_enc_lcsclientinternalid
		children = append(children, enc_lcsclientinternalid...)
	}
	if v.LcsClientName != nil {
		enc_lcsclientname, err := v.LcsClientName.MarshalBER(ber.ChildEncodeOptions(opts, "lcsClientName")...)
		if err != nil {
			return nil, qualifyBERError(err, "lcsClientName", "encoding", false)
		}
		retagged_enc_lcsclientname, tagErr_enc_lcsclientname := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, enc_lcsclientname)
		if tagErr_enc_lcsclientname != nil {
			return nil, qualifyBERError(tagErr_enc_lcsclientname, "lcsClientName", "encoding", false)
		}
		enc_lcsclientname = retagged_enc_lcsclientname
		ber.RecordGeneratedBERChildPlacement(opts, len(children), enc_lcsclientname)
		children = append(children, enc_lcsclientname...)
	}
	if v.LcsAPN != nil {
		if len(*v.LcsAPN) < 2 || len(*v.LcsAPN) > 63 {
			if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(opts, "MAP-LCS-DataTypes.LCS-ClientID", ber.RuleRef{Document: "ITU-T X.680", Edition: "02/2021", Clause: "51.5"}), "lcsAPN", "SIZE (2..63)", len(*v.LcsAPN)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_lcsapn, encodeErr_enc_lcsapn := ber.EncodeOctetString([]byte(*v.LcsAPN))
		if encodeErr_enc_lcsapn != nil {
			return nil, qualifyBERError(encodeErr_enc_lcsapn, "lcsAPN", "encoding", false)
		}
		retagged_enc_lcsapn, tagErr_enc_lcsapn := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 5, enc_lcsapn)
		if tagErr_enc_lcsapn != nil {
			return nil, qualifyBERError(tagErr_enc_lcsapn, "lcsAPN", "encoding", false)
		}
		enc_lcsapn = retagged_enc_lcsapn
		children = append(children, enc_lcsapn...)
	}
	if v.LcsRequestorID != nil {
		enc_lcsrequestorid, err := v.LcsRequestorID.MarshalBER(ber.ChildEncodeOptions(opts, "lcsRequestorID")...)
		if err != nil {
			return nil, qualifyBERError(err, "lcsRequestorID", "encoding", false)
		}
		retagged_enc_lcsrequestorid, tagErr_enc_lcsrequestorid := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 6, enc_lcsrequestorid)
		if tagErr_enc_lcsrequestorid != nil {
			return nil, qualifyBERError(tagErr_enc_lcsrequestorid, "lcsRequestorID", "encoding", false)
		}
		enc_lcsrequestorid = retagged_enc_lcsrequestorid
		ber.RecordGeneratedBERChildPlacement(opts, len(children), enc_lcsrequestorid)
		children = append(children, enc_lcsrequestorid...)
	}
	for i, ext := range v.ExtData_ {
		if err := ber.CheckBEROpaqueElement(ext, opts...); err != nil {
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
		if i == 0 && ((peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 6) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 5) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1)) {
			if constraintErr := ber.CheckEncodedValue(ber.EncodeRule(opts, "MAP-LCS-DataTypes.LCS-ClientID", ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
				return nil, constraintErr
			}
		}
		children = append(children, ext...)
	}
	ber.RecordGeneratedBERContainer(opts, children)
	return ber.EncodeSequence(children)
}
func (v *LCSLCSClientID) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// MarshalDER encodes LCSLCSClientID to DER format.
// Opaque descendants pass generic DER checks; foreign schema rules need a typed binding.
func (v *LCSLCSClientID) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: LCSLCSClientID receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	enc_lcsclienttype := ber.EncodeEnumerated(int64(v.LcsClientType))
	retagged_enc_lcsclienttype, tagErr_enc_lcsclienttype := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_lcsclienttype)
	if tagErr_enc_lcsclienttype != nil {
		return nil, qualifyBERError(tagErr_enc_lcsclienttype, "lcsClientType", "encoding", true)
	}
	enc_lcsclienttype = retagged_enc_lcsclienttype
	children = append(children, enc_lcsclienttype...)
	if v.LcsClientExternalID != nil {
		enc_lcsclientexternalid, err := v.LcsClientExternalID.MarshalDER()
		if err != nil {
			return nil, qualifyBERError(err, "lcsClientExternalID", "encoding", true)
		}
		retagged_enc_lcsclientexternalid, tagErr_enc_lcsclientexternalid := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_lcsclientexternalid)
		if tagErr_enc_lcsclientexternalid != nil {
			return nil, qualifyBERError(tagErr_enc_lcsclientexternalid, "lcsClientExternalID", "encoding", true)
		}
		enc_lcsclientexternalid = retagged_enc_lcsclientexternalid
		children = append(children, enc_lcsclientexternalid...)
	}
	if v.LcsClientDialedByMS != nil {
		if len(*v.LcsClientDialedByMS) < 1 || len(*v.LcsClientDialedByMS) > 20 {
			if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(nil, "MAP-LCS-DataTypes.LCS-ClientID", ber.RuleRef{Document: "ITU-T X.680", Edition: "02/2021", Clause: "51.5"}), "lcsClientDialedByMS", "SIZE (1..20)", len(*v.LcsClientDialedByMS)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_lcsclientdialedbyms, encodeErr_enc_lcsclientdialedbyms := ber.EncodeOctetString([]byte(*v.LcsClientDialedByMS))
		if encodeErr_enc_lcsclientdialedbyms != nil {
			return nil, qualifyBERError(encodeErr_enc_lcsclientdialedbyms, "lcsClientDialedByMS", "encoding", true)
		}
		retagged_enc_lcsclientdialedbyms, tagErr_enc_lcsclientdialedbyms := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_lcsclientdialedbyms)
		if tagErr_enc_lcsclientdialedbyms != nil {
			return nil, qualifyBERError(tagErr_enc_lcsclientdialedbyms, "lcsClientDialedByMS", "encoding", true)
		}
		enc_lcsclientdialedbyms = retagged_enc_lcsclientdialedbyms
		children = append(children, enc_lcsclientdialedbyms...)
	}
	if v.LcsClientInternalID != nil {
		enc_lcsclientinternalid := ber.EncodeEnumerated(int64(*v.LcsClientInternalID))
		retagged_enc_lcsclientinternalid, tagErr_enc_lcsclientinternalid := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, enc_lcsclientinternalid)
		if tagErr_enc_lcsclientinternalid != nil {
			return nil, qualifyBERError(tagErr_enc_lcsclientinternalid, "lcsClientInternalID", "encoding", true)
		}
		enc_lcsclientinternalid = retagged_enc_lcsclientinternalid
		children = append(children, enc_lcsclientinternalid...)
	}
	if v.LcsClientName != nil {
		enc_lcsclientname, err := v.LcsClientName.MarshalDER()
		if err != nil {
			return nil, qualifyBERError(err, "lcsClientName", "encoding", true)
		}
		retagged_enc_lcsclientname, tagErr_enc_lcsclientname := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, enc_lcsclientname)
		if tagErr_enc_lcsclientname != nil {
			return nil, qualifyBERError(tagErr_enc_lcsclientname, "lcsClientName", "encoding", true)
		}
		enc_lcsclientname = retagged_enc_lcsclientname
		children = append(children, enc_lcsclientname...)
	}
	if v.LcsAPN != nil {
		if len(*v.LcsAPN) < 2 || len(*v.LcsAPN) > 63 {
			if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(nil, "MAP-LCS-DataTypes.LCS-ClientID", ber.RuleRef{Document: "ITU-T X.680", Edition: "02/2021", Clause: "51.5"}), "lcsAPN", "SIZE (2..63)", len(*v.LcsAPN)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_lcsapn, encodeErr_enc_lcsapn := ber.EncodeOctetString([]byte(*v.LcsAPN))
		if encodeErr_enc_lcsapn != nil {
			return nil, qualifyBERError(encodeErr_enc_lcsapn, "lcsAPN", "encoding", true)
		}
		retagged_enc_lcsapn, tagErr_enc_lcsapn := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 5, enc_lcsapn)
		if tagErr_enc_lcsapn != nil {
			return nil, qualifyBERError(tagErr_enc_lcsapn, "lcsAPN", "encoding", true)
		}
		enc_lcsapn = retagged_enc_lcsapn
		children = append(children, enc_lcsapn...)
	}
	if v.LcsRequestorID != nil {
		enc_lcsrequestorid, err := v.LcsRequestorID.MarshalDER()
		if err != nil {
			return nil, qualifyBERError(err, "lcsRequestorID", "encoding", true)
		}
		retagged_enc_lcsrequestorid, tagErr_enc_lcsrequestorid := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 6, enc_lcsrequestorid)
		if tagErr_enc_lcsrequestorid != nil {
			return nil, qualifyBERError(tagErr_enc_lcsrequestorid, "lcsRequestorID", "encoding", true)
		}
		enc_lcsrequestorid = retagged_enc_lcsrequestorid
		children = append(children, enc_lcsrequestorid...)
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
		if i == 0 && ((peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 6) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 5) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1)) {
			if constraintErr := ber.CheckEncodedValue(ber.EncodeRule(nil, "MAP-LCS-DataTypes.LCS-ClientID", ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
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
		return nil, fmt.Errorf("%s: %w", "encoding LCSLCSClientID as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}
func (v *LCSLCSClientID) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	encoded, err := v.MarshalDER()
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBER decodes LCSLCSClientID from BER/DER format.
func (destination *LCSLCSClientID) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if destination == nil {
		return fmt.Errorf("%w: LCSLCSClientID destination is nil", ber.ErrInvalidValue)
	}
	var berNextValue_ LCSLCSClientID
	v := &berNextValue_
	defer func() {
		if returnErr == nil {
			*destination = *v
		}
	}()

	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	ownedData, ownErr := ber.OwnGeneratedBERInput(data, opts)
	if ownErr != nil {
		return ownErr
	}
	data = ownedData
	preparedData, preparedOptions, prepareErr := ber.PrepareGeneratedBERInput(data, opts)
	if prepareErr != nil {
		return ber.DiagnosePreflight(prepareErr, data, opts, "child", func(probeOpts []ber.DecodeOption) error {
			var probe LCSLCSClientID
			return probe.UnmarshalBER(data, probeOpts...)
		})
	}
	data, opts = preparedData, preparedOptions
	opts = ber.LocateDecodedElement(data, "MAP-LCS-DataTypes.LCS-ClientID", opts)
	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
	*v = LCSLCSClientID{}
	defer func() {
		if returnErr != nil || !ber.BERNeedsPreservation(opts) {
			return
		}
		v.berReplayNode_ = ber.CaptureGeneratedBERReplay(data, opts)
		returnErr = ber.CompleteGeneratedBERDecode(opts, v, func(base *LCSLCSClientID, replayOpts ...ber.EncodeOption) ([]byte, error) {
			return base.MarshalBER(replayOpts...)
		})
	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("%s: %w", "decoding LCSLCSClientID SEQUENCE", qualifyBERError(err, "", "decoding", false))
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
	{
		ber.MarkPreflightTarget(opts, "lcsClientType", content[offset:])
		decodedTag_lcsclienttype, n_lcsclienttype, rawVal_lcsclienttype, err := ber.DecodeTLV(content[offset:], opts...)
		if err != nil {
			return qualifyBERError(err, "lcsClientType", "decoding", false)
		}
		if decodedTag_lcsclienttype.Class != tag.ClassContextSpecific || decodedTag_lcsclienttype.Number != 0 || decodedTag_lcsclienttype.Constructed != false {
			return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_lcsclienttype), "lcsClientType", "decoding", false)
		}
		decVal_lcsclienttype, intErr := ber.DecodeEnumeratedValue(rawVal_lcsclienttype)
		if intErr != nil {
			return qualifyBERError(intErr, "lcsClientType", "decoding", false)
		}
		v.LcsClientType = LCSLCSClientType(decVal_lcsclienttype)
		if offset > len(content) || n_lcsclienttype < 0 || n_lcsclienttype > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n_lcsclienttype
	}
	// Decode lcsClientExternalID
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
				ber.MarkPreflightTarget(opts, "lcsClientExternalID", content[offset:])
				decodedTag_lcsclientexternalid, n_lcsclientexternalid, rawVal_lcsclientexternalid, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "lcsClientExternalID", "decoding", false)
				}
				if decodedTag_lcsclientexternalid.Class != tag.ClassContextSpecific || decodedTag_lcsclientexternalid.Number != 1 || decodedTag_lcsclientexternalid.Constructed != true {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_lcsclientexternalid), "lcsClientExternalID", "decoding", false)
				}
				_ = rawVal_lcsclientexternalid
				if offset < 0 || offset >
					len(content) || n_lcsclientexternalid < 0 || n_lcsclientexternalid >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				reconstructed_lcsclientexternalid, reconstructionErr_lcsclientexternalid := ber.EncodeImplicitTagWithClass(tag.ClassUniversal, tag.TagSequence, content[offset:offset+n_lcsclientexternalid])
				if reconstructionErr_lcsclientexternalid != nil {
					return qualifyBERError(reconstructionErr_lcsclientexternalid, "lcsClientExternalID", "decoding", false)
				}
				var dec_lcsclientexternalid v21_map_commondatatypes.CommonDataTypesLCSClientExternalID
				if unmErr := dec_lcsclientexternalid.UnmarshalBER(reconstructed_lcsclientexternalid, ber.ChildDecodeOptions(opts, "lcsClientExternalID")...); unmErr != nil {
					return qualifyBERError(unmErr, "lcsClientExternalID", "decoding", false)
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
				ber.MarkPreflightTarget(opts, "lcsClientDialedByMS", content[offset:])
				decodedTag_lcsclientdialedbyms, n_lcsclientdialedbyms, rawVal_lcsclientdialedbyms, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "lcsClientDialedByMS", "decoding", false)
				}
				if decodedTag_lcsclientdialedbyms.Class != tag.ClassContextSpecific || decodedTag_lcsclientdialedbyms.Number != 2 {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_lcsclientdialedbyms), "lcsClientDialedByMS", "decoding", false)
				}
				decVal_lcsclientdialedbyms, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_lcsclientdialedbyms.Constructed, rawVal_lcsclientdialedbyms, opts...)
				if octetErr != nil {
					return qualifyBERError(octetErr, "lcsClientDialedByMS", "decoding", false)
				}
				tmp_lcsclientdialedbyms := v21_map_commondatatypes.CommonDataTypesAddressString(decVal_lcsclientdialedbyms)
				v.LcsClientDialedByMS = &tmp_lcsclientdialedbyms
				if offset < 0 || offset >
					len(content) || n_lcsclientdialedbyms < 0 || n_lcsclientdialedbyms >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_lcsclientdialedbyms
				if len(*v.LcsClientDialedByMS) < 1 || len(*v.LcsClientDialedByMS) > 20 {
					if constraintErr := ber.CheckDecodedLength(ber.DecodeRule(opts, "MAP-LCS-DataTypes.LCS-ClientID", ber.RuleRef{Document: "ITU-T X.680", Edition: "02/2021", Clause: "51.5"}), "lcsClientDialedByMS", "SIZE (1..20)", len(*v.LcsClientDialedByMS)); constraintErr != nil {
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
				ber.MarkPreflightTarget(opts, "lcsClientInternalID", content[offset:])
				decodedTag_lcsclientinternalid, n_lcsclientinternalid, rawVal_lcsclientinternalid, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "lcsClientInternalID", "decoding", false)
				}
				if decodedTag_lcsclientinternalid.Class != tag.ClassContextSpecific || decodedTag_lcsclientinternalid.Number != 3 || decodedTag_lcsclientinternalid.Constructed != false {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_lcsclientinternalid), "lcsClientInternalID", "decoding", false)
				}
				decVal_lcsclientinternalid, intErr := ber.DecodeEnumeratedValue(rawVal_lcsclientinternalid)
				if intErr != nil {
					return qualifyBERError(intErr, "lcsClientInternalID", "decoding", false)
				}
				tmp_lcsclientinternalid := v21_map_commondatatypes.CommonDataTypesLCSClientInternalID(decVal_lcsclientinternalid)
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
				ber.MarkPreflightTarget(opts, "lcsClientName", content[offset:])
				decodedTag_lcsclientname, n_lcsclientname, rawVal_lcsclientname, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "lcsClientName", "decoding", false)
				}
				if decodedTag_lcsclientname.Class != tag.ClassContextSpecific || decodedTag_lcsclientname.Number != 4 || decodedTag_lcsclientname.Constructed != true {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_lcsclientname), "lcsClientName", "decoding", false)
				}
				_ = rawVal_lcsclientname
				if offset < 0 || offset >
					len(content) || n_lcsclientname < 0 || n_lcsclientname >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				reconstructed_lcsclientname, reconstructionErr_lcsclientname := ber.EncodeImplicitTagWithClass(tag.ClassUniversal, tag.TagSequence, content[offset:offset+n_lcsclientname])
				if reconstructionErr_lcsclientname != nil {
					return qualifyBERError(reconstructionErr_lcsclientname, "lcsClientName", "decoding", false)
				}
				var dec_lcsclientname LCSLCSClientName
				if unmErr := dec_lcsclientname.UnmarshalBER(reconstructed_lcsclientname, ber.ChildDecodeOptions(opts, "lcsClientName")...); unmErr != nil {
					return qualifyBERError(unmErr, "lcsClientName", "decoding", false)
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
				ber.MarkPreflightTarget(opts, "lcsAPN", content[offset:])
				decodedTag_lcsapn, n_lcsapn, rawVal_lcsapn, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "lcsAPN", "decoding", false)
				}
				if decodedTag_lcsapn.Class != tag.ClassContextSpecific || decodedTag_lcsapn.Number != 5 {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_lcsapn), "lcsAPN", "decoding", false)
				}
				decVal_lcsapn, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_lcsapn.Constructed, rawVal_lcsapn, opts...)
				if octetErr != nil {
					return qualifyBERError(octetErr, "lcsAPN", "decoding", false)
				}
				tmp_lcsapn := v21_map_ms_datatypes.MSAPN(decVal_lcsapn)
				v.LcsAPN = &tmp_lcsapn
				if offset < 0 || offset >
					len(content) || n_lcsapn < 0 || n_lcsapn > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_lcsapn
				if len(*v.LcsAPN) < 2 || len(*v.LcsAPN) > 63 {
					if constraintErr := ber.CheckDecodedLength(ber.DecodeRule(opts, "MAP-LCS-DataTypes.LCS-ClientID", ber.RuleRef{Document: "ITU-T X.680", Edition: "02/2021", Clause: "51.5"}), "lcsAPN", "SIZE (2..63)", len(*v.LcsAPN)); constraintErr != nil {
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
				ber.MarkPreflightTarget(opts, "lcsRequestorID", content[offset:])
				decodedTag_lcsrequestorid, n_lcsrequestorid, rawVal_lcsrequestorid, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "lcsRequestorID", "decoding", false)
				}
				if decodedTag_lcsrequestorid.Class != tag.ClassContextSpecific || decodedTag_lcsrequestorid.Number != 6 || decodedTag_lcsrequestorid.Constructed != true {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_lcsrequestorid), "lcsRequestorID", "decoding", false)
				}
				_ = rawVal_lcsrequestorid
				if offset < 0 || offset >
					len(content) || n_lcsrequestorid < 0 || n_lcsrequestorid >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				reconstructed_lcsrequestorid, reconstructionErr_lcsrequestorid := ber.EncodeImplicitTagWithClass(tag.ClassUniversal, tag.TagSequence, content[offset:offset+n_lcsrequestorid])
				if reconstructionErr_lcsrequestorid != nil {
					return qualifyBERError(reconstructionErr_lcsrequestorid, "lcsRequestorID", "decoding", false)
				}
				var dec_lcsrequestorid LCSLCSRequestorID
				if unmErr := dec_lcsrequestorid.UnmarshalBER(reconstructed_lcsrequestorid, ber.ChildDecodeOptions(opts, "lcsRequestorID")...); unmErr != nil {
					return qualifyBERError(unmErr, "lcsRequestorID", "decoding", false)
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
		peekTag, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:], opts...)
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "LCSLCSClientID", Cause: extErr_}
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: the first unknown addition must differ from trailing OPTIONAL/DEFAULT tags.
		if len(v.ExtData_) == 0 && ((peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 6) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 5) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1)) {
			if !ber.ToleranceEnabled(opts) {
				return &ber.DecodeError{Offset: offset, TypeName: "LCSLCSClientID", Cause: fmt.Errorf("%w: repeated or out-of-order SEQUENCE component tag %s", ber.ErrInvalidTag, peekTag)}
			}
			if orderErr_ := ber.CheckDecodedValue(ber.DecodeRule(opts, "MAP-LCS-DataTypes.LCS-ClientID", ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), fmt.Sprintf("ExtData_[%d]", len(v.ExtData_)), "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); orderErr_ != nil {
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

// MarshalBER encodes LCSLCSClientName to BER format.
func (v *LCSLCSClientName) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: LCSLCSClientName receiver is nil", ber.ErrInvalidValue)
	}
	if v.berReplayNode_ == nil {
		return v.marshalBER(opts...)
	}
	var replayErr error
	opts, replayErr = ber.PrepareBERReplay(v.berReplayNode_, opts, func(mode ber.EncodeOption) ([]byte, error) { return v.MarshalBER([]ber.EncodeOption{mode}...) }, v)
	if replayErr != nil {
		return nil, replayErr
	}
	if replayBytes, ok := ber.PreparedBERReplay(v.berReplayNode_, opts); ok {
		return replayBytes, nil
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBERNode(encoded, v.berReplayNode_, opts), nil
}
func (v *LCSLCSClientName) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if len(v.DataCodingScheme) < 1 || len(v.DataCodingScheme) > 1 {
		if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(opts, "MAP-LCS-DataTypes.LCSClientName", ber.RuleRef{Document: "ITU-T X.680", Edition: "02/2021", Clause: "51.5"}), "dataCodingScheme", "SIZE (1)", len(v.DataCodingScheme)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_datacodingscheme, encodeErr_enc_datacodingscheme := ber.EncodeOctetString([]byte(v.DataCodingScheme))
	if encodeErr_enc_datacodingscheme != nil {
		return nil, qualifyBERError(encodeErr_enc_datacodingscheme, "dataCodingScheme", "encoding", false)
	}
	retagged_enc_datacodingscheme, tagErr_enc_datacodingscheme := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_datacodingscheme)
	if tagErr_enc_datacodingscheme != nil {
		return nil, qualifyBERError(tagErr_enc_datacodingscheme, "dataCodingScheme", "encoding", false)
	}
	enc_datacodingscheme = retagged_enc_datacodingscheme
	children = append(children, enc_datacodingscheme...)
	if len(v.NameString) < 1 || len(v.NameString) > 63 {
		if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(opts, "MAP-LCS-DataTypes.LCSClientName", ber.RuleRef{Document: "ITU-T X.680", Edition: "02/2021", Clause: "51.5"}), "nameString", "SIZE (1..63)", len(v.NameString)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	if len(v.NameString) < 1 || len(v.NameString) > 160 {
		if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(opts, "MAP-LCS-DataTypes.LCSClientName", ber.RuleRef{Document: "ITU-T X.680", Edition: "02/2021", Clause: "51.5"}), "nameString", "SIZE (1..160)", len(v.NameString)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_namestring, encodeErr_enc_namestring := ber.EncodeOctetString([]byte(v.NameString))
	if encodeErr_enc_namestring != nil {
		return nil, qualifyBERError(encodeErr_enc_namestring, "nameString", "encoding", false)
	}
	retagged_enc_namestring, tagErr_enc_namestring := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_namestring)
	if tagErr_enc_namestring != nil {
		return nil, qualifyBERError(tagErr_enc_namestring, "nameString", "encoding", false)
	}
	enc_namestring = retagged_enc_namestring
	children = append(children, enc_namestring...)
	if v.LcsFormatIndicator != nil {
		enc_lcsformatindicator := ber.EncodeEnumerated(int64(*v.LcsFormatIndicator))
		retagged_enc_lcsformatindicator, tagErr_enc_lcsformatindicator := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, enc_lcsformatindicator)
		if tagErr_enc_lcsformatindicator != nil {
			return nil, qualifyBERError(tagErr_enc_lcsformatindicator, "lcs-FormatIndicator", "encoding", false)
		}
		enc_lcsformatindicator = retagged_enc_lcsformatindicator
		children = append(children, enc_lcsformatindicator...)
	}
	for i, ext := range v.ExtData_ {
		if err := ber.CheckBEROpaqueElement(ext, opts...); err != nil {
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
		if i == 0 && (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3) {
			if constraintErr := ber.CheckEncodedValue(ber.EncodeRule(opts, "MAP-LCS-DataTypes.LCSClientName", ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
				return nil, constraintErr
			}
		}
		children = append(children, ext...)
	}
	ber.RecordGeneratedBERContainer(opts, children)
	return ber.EncodeSequence(children)
}
func (v *LCSLCSClientName) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// MarshalDER encodes LCSLCSClientName to DER format.
// Opaque descendants pass generic DER checks; foreign schema rules need a typed binding.
func (v *LCSLCSClientName) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: LCSLCSClientName receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if len(v.DataCodingScheme) < 1 || len(v.DataCodingScheme) > 1 {
		if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(nil, "MAP-LCS-DataTypes.LCSClientName", ber.RuleRef{Document: "ITU-T X.680", Edition: "02/2021", Clause: "51.5"}), "dataCodingScheme", "SIZE (1)", len(v.DataCodingScheme)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_datacodingscheme, encodeErr_enc_datacodingscheme := ber.EncodeOctetString([]byte(v.DataCodingScheme))
	if encodeErr_enc_datacodingscheme != nil {
		return nil, qualifyBERError(encodeErr_enc_datacodingscheme, "dataCodingScheme", "encoding", true)
	}
	retagged_enc_datacodingscheme, tagErr_enc_datacodingscheme := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_datacodingscheme)
	if tagErr_enc_datacodingscheme != nil {
		return nil, qualifyBERError(tagErr_enc_datacodingscheme, "dataCodingScheme", "encoding", true)
	}
	enc_datacodingscheme = retagged_enc_datacodingscheme
	children = append(children, enc_datacodingscheme...)
	if len(v.NameString) < 1 || len(v.NameString) > 63 {
		if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(nil, "MAP-LCS-DataTypes.LCSClientName", ber.RuleRef{Document: "ITU-T X.680", Edition: "02/2021", Clause: "51.5"}), "nameString", "SIZE (1..63)", len(v.NameString)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	if len(v.NameString) < 1 || len(v.NameString) > 160 {
		if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(nil, "MAP-LCS-DataTypes.LCSClientName", ber.RuleRef{Document: "ITU-T X.680", Edition: "02/2021", Clause: "51.5"}), "nameString", "SIZE (1..160)", len(v.NameString)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_namestring, encodeErr_enc_namestring := ber.EncodeOctetString([]byte(v.NameString))
	if encodeErr_enc_namestring != nil {
		return nil, qualifyBERError(encodeErr_enc_namestring, "nameString", "encoding", true)
	}
	retagged_enc_namestring, tagErr_enc_namestring := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_namestring)
	if tagErr_enc_namestring != nil {
		return nil, qualifyBERError(tagErr_enc_namestring, "nameString", "encoding", true)
	}
	enc_namestring = retagged_enc_namestring
	children = append(children, enc_namestring...)
	if v.LcsFormatIndicator != nil {
		enc_lcsformatindicator := ber.EncodeEnumerated(int64(*v.LcsFormatIndicator))
		retagged_enc_lcsformatindicator, tagErr_enc_lcsformatindicator := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, enc_lcsformatindicator)
		if tagErr_enc_lcsformatindicator != nil {
			return nil, qualifyBERError(tagErr_enc_lcsformatindicator, "lcs-FormatIndicator", "encoding", true)
		}
		enc_lcsformatindicator = retagged_enc_lcsformatindicator
		children = append(children, enc_lcsformatindicator...)
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
		if i == 0 && (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3) {
			if constraintErr := ber.CheckEncodedValue(ber.EncodeRule(nil, "MAP-LCS-DataTypes.LCSClientName", ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
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
		return nil, fmt.Errorf("%s: %w", "encoding LCSLCSClientName as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}
func (v *LCSLCSClientName) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	encoded, err := v.MarshalDER()
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBER decodes LCSLCSClientName from BER/DER format.
func (destination *LCSLCSClientName) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if destination == nil {
		return fmt.Errorf("%w: LCSLCSClientName destination is nil", ber.ErrInvalidValue)
	}
	var berNextValue_ LCSLCSClientName
	v := &berNextValue_

	defer func() {
		if returnErr == nil {
			*destination = *v
		}
	}()

	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	ownedData, ownErr := ber.OwnGeneratedBERInput(data, opts)
	if ownErr != nil {
		return ownErr
	}
	data = ownedData
	preparedData, preparedOptions, prepareErr := ber.PrepareGeneratedBERInput(data, opts)
	if prepareErr != nil {
		return ber.DiagnosePreflight(prepareErr, data, opts, "child", func(probeOpts []ber.DecodeOption) error {
			var probe LCSLCSClientName
			return probe.UnmarshalBER(data, probeOpts...)
		})
	}
	data, opts = preparedData, preparedOptions
	opts = ber.LocateDecodedElement(data, "MAP-LCS-DataTypes.LCSClientName", opts)
	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
	*v = LCSLCSClientName{}
	defer func() {
		if returnErr != nil || !ber.BERNeedsPreservation(opts) {
			return
		}
		v.berReplayNode_ = ber.CaptureGeneratedBERReplay(data, opts)
		returnErr = ber.CompleteGeneratedBERDecode(opts, v, func(base *LCSLCSClientName, replayOpts ...ber.EncodeOption) ([]byte, error) {
			return base.MarshalBER(replayOpts...)
		})
	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("%s: %w", "decoding LCSLCSClientName SEQUENCE", qualifyBERError(err, "", "decoding", false))
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
	{
		ber.MarkPreflightTarget(opts, "dataCodingScheme", content[offset:])
		decodedTag_datacodingscheme, n_datacodingscheme, rawVal_datacodingscheme, err := ber.DecodeTLV(content[offset:], opts...)
		if err != nil {
			return qualifyBERError(err, "dataCodingScheme", "decoding", false)
		}
		if decodedTag_datacodingscheme.Class != tag.ClassContextSpecific || decodedTag_datacodingscheme.Number != 0 {
			return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_datacodingscheme), "dataCodingScheme", "decoding", false)
		}
		decVal_datacodingscheme, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_datacodingscheme.Constructed, rawVal_datacodingscheme, opts...)
		if octetErr != nil {
			return qualifyBERError(octetErr, "dataCodingScheme", "decoding", false)
		}
		v.DataCodingScheme = v21_map_ss_datatypes.SSUSSDDataCodingScheme(decVal_datacodingscheme)
		if offset > len(content) || n_datacodingscheme < 0 || n_datacodingscheme > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n_datacodingscheme
		if len(v.DataCodingScheme) < 1 || len(v.DataCodingScheme) > 1 {
			if constraintErr := ber.CheckDecodedLength(ber.DecodeRule(opts, "MAP-LCS-DataTypes.LCSClientName", ber.RuleRef{Document: "ITU-T X.680", Edition: "02/2021", Clause: "51.5"}), "dataCodingScheme", "SIZE (1)", len(v.DataCodingScheme)); constraintErr != nil {
				return constraintErr
			}
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
	{
		ber.MarkPreflightTarget(opts, "nameString", content[offset:])
		decodedTag_namestring, n_namestring, rawVal_namestring, err := ber.DecodeTLV(content[offset:], opts...)
		if err != nil {
			return qualifyBERError(err, "nameString", "decoding", false)
		}
		if decodedTag_namestring.Class != tag.ClassContextSpecific || decodedTag_namestring.Number != 2 {
			return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_namestring), "nameString", "decoding", false)
		}
		decVal_namestring, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_namestring.Constructed, rawVal_namestring, opts...)
		if octetErr != nil {
			return qualifyBERError(octetErr, "nameString", "decoding", false)
		}
		v.NameString = LCSNameString(decVal_namestring)
		if offset < 0 || offset >
			len(content) || n_namestring < 0 || n_namestring > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n_namestring
		if len(v.NameString) < 1 || len(v.NameString) > 63 {
			if constraintErr := ber.CheckDecodedLength(ber.DecodeRule(opts, "MAP-LCS-DataTypes.LCSClientName", ber.RuleRef{Document: "ITU-T X.680", Edition: "02/2021", Clause: "51.5"}), "nameString", "SIZE (1..63)", len(v.NameString)); constraintErr != nil {
				return constraintErr
			}
		}
		if len(v.NameString) < 1 || len(v.NameString) > 160 {
			if constraintErr := ber.CheckDecodedLength(ber.DecodeRule(opts, "MAP-LCS-DataTypes.LCSClientName", ber.RuleRef{Document: "ITU-T X.680", Edition: "02/2021", Clause: "51.5"}), "nameString", "SIZE (1..160)", len(v.NameString)); constraintErr != nil {
				return constraintErr
			}
		}
	}
	// Decode lcs-FormatIndicator
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3 {
				ber.MarkPreflightTarget(opts, "lcs-FormatIndicator", content[offset:])
				decodedTag_lcsformatindicator, n_lcsformatindicator, rawVal_lcsformatindicator, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "lcs-FormatIndicator", "decoding", false)
				}
				if decodedTag_lcsformatindicator.Class != tag.ClassContextSpecific || decodedTag_lcsformatindicator.Number != 3 || decodedTag_lcsformatindicator.Constructed != false {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_lcsformatindicator), "lcs-FormatIndicator", "decoding", false)
				}
				decVal_lcsformatindicator, intErr := ber.DecodeEnumeratedValue(rawVal_lcsformatindicator)
				if intErr != nil {
					return qualifyBERError(intErr, "lcs-FormatIndicator", "decoding", false)
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
		peekTag, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:], opts...)
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "LCSLCSClientName", Cause: extErr_}
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: the first unknown addition must differ from trailing OPTIONAL/DEFAULT tags.
		if len(v.ExtData_) == 0 && (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3) {
			if !ber.ToleranceEnabled(opts) {
				return &ber.DecodeError{Offset: offset, TypeName: "LCSLCSClientName", Cause: fmt.Errorf("%w: repeated or out-of-order SEQUENCE component tag %s", ber.ErrInvalidTag, peekTag)}
			}
			if orderErr_ := ber.CheckDecodedValue(ber.DecodeRule(opts, "MAP-LCS-DataTypes.LCSClientName", ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), fmt.Sprintf("ExtData_[%d]", len(v.ExtData_)), "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); orderErr_ != nil {
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

// MarshalBER encodes LCSLCSRequestorID to BER format.
func (v *LCSLCSRequestorID) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: LCSLCSRequestorID receiver is nil", ber.ErrInvalidValue)
	}
	if v.berReplayNode_ == nil {
		return v.marshalBER(opts...)
	}
	var replayErr error
	opts, replayErr = ber.PrepareBERReplay(v.berReplayNode_, opts, func(mode ber.EncodeOption) ([]byte, error) { return v.MarshalBER([]ber.EncodeOption{mode}...) }, v)
	if replayErr != nil {
		return nil, replayErr
	}
	if replayBytes, ok := ber.PreparedBERReplay(v.berReplayNode_, opts); ok {
		return replayBytes, nil
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBERNode(encoded, v.berReplayNode_, opts), nil
}
func (v *LCSLCSRequestorID) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if len(v.DataCodingScheme) < 1 || len(v.DataCodingScheme) > 1 {
		if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(opts, "MAP-LCS-DataTypes.LCSRequestorID", ber.RuleRef{Document: "ITU-T X.680", Edition: "02/2021", Clause: "51.5"}), "dataCodingScheme", "SIZE (1)", len(v.DataCodingScheme)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_datacodingscheme, encodeErr_enc_datacodingscheme := ber.EncodeOctetString([]byte(v.DataCodingScheme))
	if encodeErr_enc_datacodingscheme != nil {
		return nil, qualifyBERError(encodeErr_enc_datacodingscheme, "dataCodingScheme", "encoding", false)
	}
	retagged_enc_datacodingscheme, tagErr_enc_datacodingscheme := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_datacodingscheme)
	if tagErr_enc_datacodingscheme != nil {
		return nil, qualifyBERError(tagErr_enc_datacodingscheme, "dataCodingScheme", "encoding", false)
	}
	enc_datacodingscheme = retagged_enc_datacodingscheme
	children = append(children, enc_datacodingscheme...)
	if len(v.RequestorIDString) < 1 || len(v.RequestorIDString) > 63 {
		if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(opts, "MAP-LCS-DataTypes.LCSRequestorID", ber.RuleRef{Document: "ITU-T X.680", Edition: "02/2021", Clause: "51.5"}), "requestorIDString", "SIZE (1..63)", len(v.RequestorIDString)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	if len(v.RequestorIDString) < 1 || len(v.RequestorIDString) > 160 {
		if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(opts, "MAP-LCS-DataTypes.LCSRequestorID", ber.RuleRef{Document: "ITU-T X.680", Edition: "02/2021", Clause: "51.5"}), "requestorIDString", "SIZE (1..160)", len(v.RequestorIDString)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_requestoridstring, encodeErr_enc_requestoridstring := ber.EncodeOctetString([]byte(v.RequestorIDString))
	if encodeErr_enc_requestoridstring != nil {
		return nil, qualifyBERError(encodeErr_enc_requestoridstring, "requestorIDString", "encoding", false)
	}
	retagged_enc_requestoridstring, tagErr_enc_requestoridstring := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_requestoridstring)
	if tagErr_enc_requestoridstring != nil {
		return nil, qualifyBERError(tagErr_enc_requestoridstring, "requestorIDString", "encoding", false)
	}
	enc_requestoridstring = retagged_enc_requestoridstring
	children = append(children, enc_requestoridstring...)
	if v.LcsFormatIndicator != nil {
		enc_lcsformatindicator := ber.EncodeEnumerated(int64(*v.LcsFormatIndicator))
		retagged_enc_lcsformatindicator, tagErr_enc_lcsformatindicator := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_lcsformatindicator)
		if tagErr_enc_lcsformatindicator != nil {
			return nil, qualifyBERError(tagErr_enc_lcsformatindicator, "lcs-FormatIndicator", "encoding", false)
		}
		enc_lcsformatindicator = retagged_enc_lcsformatindicator
		children = append(children, enc_lcsformatindicator...)
	}
	for i, ext := range v.ExtData_ {
		if err := ber.CheckBEROpaqueElement(ext, opts...); err != nil {
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
		if i == 0 && (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2) {
			if constraintErr := ber.CheckEncodedValue(ber.EncodeRule(opts, "MAP-LCS-DataTypes.LCSRequestorID", ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
				return nil, constraintErr
			}
		}
		children = append(children, ext...)
	}
	ber.RecordGeneratedBERContainer(opts, children)
	return ber.EncodeSequence(children)
}
func (v *LCSLCSRequestorID) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// MarshalDER encodes LCSLCSRequestorID to DER format.
// Opaque descendants pass generic DER checks; foreign schema rules need a typed binding.
func (v *LCSLCSRequestorID) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: LCSLCSRequestorID receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if len(v.DataCodingScheme) < 1 || len(v.DataCodingScheme) > 1 {
		if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(nil, "MAP-LCS-DataTypes.LCSRequestorID", ber.RuleRef{Document: "ITU-T X.680", Edition: "02/2021", Clause: "51.5"}), "dataCodingScheme", "SIZE (1)", len(v.DataCodingScheme)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_datacodingscheme, encodeErr_enc_datacodingscheme := ber.EncodeOctetString([]byte(v.DataCodingScheme))
	if encodeErr_enc_datacodingscheme != nil {
		return nil, qualifyBERError(encodeErr_enc_datacodingscheme, "dataCodingScheme", "encoding", true)
	}
	retagged_enc_datacodingscheme, tagErr_enc_datacodingscheme := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_datacodingscheme)
	if tagErr_enc_datacodingscheme != nil {
		return nil, qualifyBERError(tagErr_enc_datacodingscheme, "dataCodingScheme", "encoding", true)
	}
	enc_datacodingscheme = retagged_enc_datacodingscheme
	children = append(children, enc_datacodingscheme...)
	if len(v.RequestorIDString) < 1 || len(v.RequestorIDString) > 63 {
		if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(nil, "MAP-LCS-DataTypes.LCSRequestorID", ber.RuleRef{Document: "ITU-T X.680", Edition: "02/2021", Clause: "51.5"}), "requestorIDString", "SIZE (1..63)", len(v.RequestorIDString)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	if len(v.RequestorIDString) < 1 || len(v.RequestorIDString) > 160 {
		if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(nil, "MAP-LCS-DataTypes.LCSRequestorID", ber.RuleRef{Document: "ITU-T X.680", Edition: "02/2021", Clause: "51.5"}), "requestorIDString", "SIZE (1..160)", len(v.RequestorIDString)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_requestoridstring, encodeErr_enc_requestoridstring := ber.EncodeOctetString([]byte(v.RequestorIDString))
	if encodeErr_enc_requestoridstring != nil {
		return nil, qualifyBERError(encodeErr_enc_requestoridstring, "requestorIDString", "encoding", true)
	}
	retagged_enc_requestoridstring, tagErr_enc_requestoridstring := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_requestoridstring)
	if tagErr_enc_requestoridstring != nil {
		return nil, qualifyBERError(tagErr_enc_requestoridstring, "requestorIDString", "encoding", true)
	}
	enc_requestoridstring = retagged_enc_requestoridstring
	children = append(children, enc_requestoridstring...)
	if v.LcsFormatIndicator != nil {
		enc_lcsformatindicator := ber.EncodeEnumerated(int64(*v.LcsFormatIndicator))
		retagged_enc_lcsformatindicator, tagErr_enc_lcsformatindicator := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_lcsformatindicator)
		if tagErr_enc_lcsformatindicator != nil {
			return nil, qualifyBERError(tagErr_enc_lcsformatindicator, "lcs-FormatIndicator", "encoding", true)
		}
		enc_lcsformatindicator = retagged_enc_lcsformatindicator
		children = append(children, enc_lcsformatindicator...)
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
		if i == 0 && (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2) {
			if constraintErr := ber.CheckEncodedValue(ber.EncodeRule(nil, "MAP-LCS-DataTypes.LCSRequestorID", ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
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
		return nil, fmt.Errorf("%s: %w", "encoding LCSLCSRequestorID as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}
func (v *LCSLCSRequestorID) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	encoded, err := v.MarshalDER()
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBER decodes LCSLCSRequestorID from BER/DER format.
func (destination *LCSLCSRequestorID) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if destination == nil {
		return fmt.Errorf("%w: LCSLCSRequestorID destination is nil", ber.ErrInvalidValue)
	}
	var berNextValue_ LCSLCSRequestorID
	v := &berNextValue_

	defer func() {
		if returnErr == nil {
			*destination = *v
		}
	}()

	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	ownedData, ownErr := ber.OwnGeneratedBERInput(data, opts)
	if ownErr != nil {
		return ownErr
	}
	data = ownedData
	preparedData, preparedOptions, prepareErr := ber.PrepareGeneratedBERInput(data, opts)
	if prepareErr != nil {
		return ber.DiagnosePreflight(prepareErr, data, opts, "child", func(probeOpts []ber.DecodeOption) error {
			var probe LCSLCSRequestorID
			return probe.UnmarshalBER(data, probeOpts...)
		})
	}
	data, opts = preparedData, preparedOptions
	opts = ber.LocateDecodedElement(data, "MAP-LCS-DataTypes.LCSRequestorID", opts)
	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
	*v = LCSLCSRequestorID{}
	defer func() {
		if returnErr != nil || !ber.BERNeedsPreservation(opts) {
			return
		}
		v.berReplayNode_ = ber.CaptureGeneratedBERReplay(data, opts)
		returnErr = ber.CompleteGeneratedBERDecode(opts, v, func(base *LCSLCSRequestorID, replayOpts ...ber.EncodeOption) ([]byte, error) {
			return base.MarshalBER(replayOpts...)
		})
	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("%s: %w", "decoding LCSLCSRequestorID SEQUENCE", qualifyBERError(err, "", "decoding", false))
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
	{
		ber.MarkPreflightTarget(opts, "dataCodingScheme", content[offset:])
		decodedTag_datacodingscheme, n_datacodingscheme, rawVal_datacodingscheme, err := ber.DecodeTLV(content[offset:], opts...)
		if err != nil {
			return qualifyBERError(err, "dataCodingScheme", "decoding", false)
		}
		if decodedTag_datacodingscheme.Class != tag.ClassContextSpecific || decodedTag_datacodingscheme.Number != 0 {
			return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_datacodingscheme), "dataCodingScheme", "decoding", false)
		}
		decVal_datacodingscheme, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_datacodingscheme.Constructed, rawVal_datacodingscheme, opts...)
		if octetErr != nil {
			return qualifyBERError(octetErr, "dataCodingScheme", "decoding", false)
		}
		v.DataCodingScheme = v21_map_ss_datatypes.SSUSSDDataCodingScheme(decVal_datacodingscheme)
		if offset > len(content) || n_datacodingscheme < 0 || n_datacodingscheme > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n_datacodingscheme
		if len(v.DataCodingScheme) < 1 || len(v.DataCodingScheme) > 1 {
			if constraintErr := ber.CheckDecodedLength(ber.DecodeRule(opts, "MAP-LCS-DataTypes.LCSRequestorID", ber.RuleRef{Document: "ITU-T X.680", Edition: "02/2021", Clause: "51.5"}), "dataCodingScheme", "SIZE (1)", len(v.DataCodingScheme)); constraintErr != nil {
				return constraintErr
			}
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
	{
		ber.MarkPreflightTarget(opts, "requestorIDString", content[offset:])
		decodedTag_requestoridstring, n_requestoridstring, rawVal_requestoridstring, err := ber.DecodeTLV(content[offset:], opts...)
		if err != nil {
			return qualifyBERError(err, "requestorIDString", "decoding", false)
		}
		if decodedTag_requestoridstring.Class != tag.ClassContextSpecific || decodedTag_requestoridstring.Number != 1 {
			return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_requestoridstring), "requestorIDString", "decoding", false)
		}
		decVal_requestoridstring, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_requestoridstring.Constructed, rawVal_requestoridstring, opts...)
		if octetErr != nil {
			return qualifyBERError(octetErr, "requestorIDString", "decoding", false)
		}
		v.RequestorIDString = LCSRequestorIDString(decVal_requestoridstring)
		if offset < 0 || offset >
			len(content) || n_requestoridstring < 0 || n_requestoridstring >
			len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n_requestoridstring
		if len(v.RequestorIDString) < 1 || len(v.RequestorIDString) > 63 {
			if constraintErr := ber.CheckDecodedLength(ber.DecodeRule(opts, "MAP-LCS-DataTypes.LCSRequestorID", ber.RuleRef{Document: "ITU-T X.680", Edition: "02/2021", Clause: "51.5"}), "requestorIDString", "SIZE (1..63)", len(v.RequestorIDString)); constraintErr != nil {
				return constraintErr
			}
		}
		if len(v.RequestorIDString) < 1 || len(v.RequestorIDString) > 160 {
			if constraintErr := ber.CheckDecodedLength(ber.DecodeRule(opts, "MAP-LCS-DataTypes.LCSRequestorID", ber.RuleRef{Document: "ITU-T X.680", Edition: "02/2021", Clause: "51.5"}), "requestorIDString", "SIZE (1..160)", len(v.RequestorIDString)); constraintErr != nil {
				return constraintErr
			}
		}
	}
	// Decode lcs-FormatIndicator
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2 {
				ber.MarkPreflightTarget(opts, "lcs-FormatIndicator", content[offset:])
				decodedTag_lcsformatindicator, n_lcsformatindicator, rawVal_lcsformatindicator, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "lcs-FormatIndicator", "decoding", false)
				}
				if decodedTag_lcsformatindicator.Class != tag.ClassContextSpecific || decodedTag_lcsformatindicator.Number != 2 || decodedTag_lcsformatindicator.Constructed != false {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_lcsformatindicator), "lcs-FormatIndicator", "decoding", false)
				}
				decVal_lcsformatindicator, intErr := ber.DecodeEnumeratedValue(rawVal_lcsformatindicator)
				if intErr != nil {
					return qualifyBERError(intErr, "lcs-FormatIndicator", "decoding", false)
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
		peekTag, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:], opts...)
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "LCSLCSRequestorID", Cause: extErr_}
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: the first unknown addition must differ from trailing OPTIONAL/DEFAULT tags.
		if len(v.ExtData_) == 0 && (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2) {
			if !ber.ToleranceEnabled(opts) {
				return &ber.DecodeError{Offset: offset, TypeName: "LCSLCSRequestorID", Cause: fmt.Errorf("%w: repeated or out-of-order SEQUENCE component tag %s", ber.ErrInvalidTag, peekTag)}
			}
			if orderErr_ := ber.CheckDecodedValue(ber.DecodeRule(opts, "MAP-LCS-DataTypes.LCSRequestorID", ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), fmt.Sprintf("ExtData_[%d]", len(v.ExtData_)), "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); orderErr_ != nil {
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

// MarshalBER encodes LCSLCSQoS to BER format.
func (v *LCSLCSQoS) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: LCSLCSQoS receiver is nil", ber.ErrInvalidValue)
	}
	if v.berReplayNode_ == nil {
		return v.marshalBER(opts...)
	}
	var replayErr error
	opts, replayErr = ber.PrepareBERReplay(v.berReplayNode_, opts, func(mode ber.EncodeOption) ([]byte, error) { return v.MarshalBER([]ber.EncodeOption{mode}...) }, v)
	if replayErr != nil {
		return nil, replayErr
	}
	if replayBytes, ok := ber.PreparedBERReplay(v.berReplayNode_, opts); ok {
		return replayBytes, nil
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBERNode(encoded, v.berReplayNode_, opts), nil
}
func (v *LCSLCSQoS) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if v.HorizontalAccuracy != nil {
		if len(*v.HorizontalAccuracy) < 1 || len(*v.HorizontalAccuracy) > 1 {
			if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(opts, "MAP-LCS-DataTypes.LCS-QoS", ber.RuleRef{Document: "ITU-T X.680", Edition: "02/2021", Clause: "51.5"}), "horizontal-accuracy", "SIZE (1)", len(*v.HorizontalAccuracy)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_horizontalaccuracy, encodeErr_enc_horizontalaccuracy := ber.EncodeOctetString([]byte(*v.HorizontalAccuracy))
		if encodeErr_enc_horizontalaccuracy != nil {
			return nil, qualifyBERError(encodeErr_enc_horizontalaccuracy, "horizontal-accuracy", "encoding", false)
		}
		retagged_enc_horizontalaccuracy, tagErr_enc_horizontalaccuracy := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_horizontalaccuracy)
		if tagErr_enc_horizontalaccuracy != nil {
			return nil, qualifyBERError(tagErr_enc_horizontalaccuracy, "horizontal-accuracy", "encoding", false)
		}
		enc_horizontalaccuracy = retagged_enc_horizontalaccuracy
		children = append(children, enc_horizontalaccuracy...)
	}
	if v.VerticalCoordinateRequest != nil {
		enc_verticalcoordinaterequest := ber.EncodeNull()
		retagged_enc_verticalcoordinaterequest, tagErr_enc_verticalcoordinaterequest := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_verticalcoordinaterequest)
		if tagErr_enc_verticalcoordinaterequest != nil {
			return nil, qualifyBERError(tagErr_enc_verticalcoordinaterequest, "verticalCoordinateRequest", "encoding", false)
		}
		enc_verticalcoordinaterequest = retagged_enc_verticalcoordinaterequest
		children = append(children, enc_verticalcoordinaterequest...)
	}
	if v.VerticalAccuracy != nil {
		if len(*v.VerticalAccuracy) < 1 || len(*v.VerticalAccuracy) > 1 {
			if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(opts, "MAP-LCS-DataTypes.LCS-QoS", ber.RuleRef{Document: "ITU-T X.680", Edition: "02/2021", Clause: "51.5"}), "vertical-accuracy", "SIZE (1)", len(*v.VerticalAccuracy)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_verticalaccuracy, encodeErr_enc_verticalaccuracy := ber.EncodeOctetString([]byte(*v.VerticalAccuracy))
		if encodeErr_enc_verticalaccuracy != nil {
			return nil, qualifyBERError(encodeErr_enc_verticalaccuracy, "vertical-accuracy", "encoding", false)
		}
		retagged_enc_verticalaccuracy, tagErr_enc_verticalaccuracy := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_verticalaccuracy)
		if tagErr_enc_verticalaccuracy != nil {
			return nil, qualifyBERError(tagErr_enc_verticalaccuracy, "vertical-accuracy", "encoding", false)
		}
		enc_verticalaccuracy = retagged_enc_verticalaccuracy
		children = append(children, enc_verticalaccuracy...)
	}
	if v.ResponseTime != nil {
		enc_responsetime, err := v.ResponseTime.MarshalBER(ber.ChildEncodeOptions(opts, "responseTime")...)
		if err != nil {
			return nil, qualifyBERError(err, "responseTime", "encoding", false)
		}
		retagged_enc_responsetime, tagErr_enc_responsetime := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, enc_responsetime)
		if tagErr_enc_responsetime != nil {
			return nil, qualifyBERError(tagErr_enc_responsetime, "responseTime", "encoding", false)
		}
		enc_responsetime = retagged_enc_responsetime
		ber.RecordGeneratedBERChildPlacement(opts, len(children), enc_responsetime)
		children = append(children, enc_responsetime...)
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
		ber.RecordGeneratedBERChildPlacement(opts, len(children), enc_extensioncontainer)
		children = append(children, enc_extensioncontainer...)
	}
	if v.VelocityRequest != nil {
		enc_velocityrequest := ber.EncodeNull()
		retagged_enc_velocityrequest, tagErr_enc_velocityrequest := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 5, enc_velocityrequest)
		if tagErr_enc_velocityrequest != nil {
			return nil, qualifyBERError(tagErr_enc_velocityrequest, "velocityRequest", "encoding", false)
		}
		enc_velocityrequest = retagged_enc_velocityrequest
		children = append(children, enc_velocityrequest...)
	}
	if v.LcsQosClass != nil {
		enc_lcsqosclass := ber.EncodeEnumerated(int64(*v.LcsQosClass))
		retagged_enc_lcsqosclass, tagErr_enc_lcsqosclass := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 6, enc_lcsqosclass)
		if tagErr_enc_lcsqosclass != nil {
			return nil, qualifyBERError(tagErr_enc_lcsqosclass, "lcs-qos-class", "encoding", false)
		}
		enc_lcsqosclass = retagged_enc_lcsqosclass
		children = append(children, enc_lcsqosclass...)
	}
	for i, ext := range v.ExtData_ {
		if err := ber.CheckBEROpaqueElement(ext, opts...); err != nil {
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
		if i == 0 && ((peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 6) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 5) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0)) {
			if constraintErr := ber.CheckEncodedValue(ber.EncodeRule(opts, "MAP-LCS-DataTypes.LCS-QoS", ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
				return nil, constraintErr
			}
		}
		children = append(children, ext...)
	}
	ber.RecordGeneratedBERContainer(opts, children)
	return ber.EncodeSequence(children)
}
func (v *LCSLCSQoS) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// MarshalDER encodes LCSLCSQoS to DER format.
// Opaque descendants pass generic DER checks; foreign schema rules need a typed binding.
func (v *LCSLCSQoS) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: LCSLCSQoS receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if v.HorizontalAccuracy != nil {
		if len(*v.HorizontalAccuracy) < 1 || len(*v.HorizontalAccuracy) > 1 {
			if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(nil, "MAP-LCS-DataTypes.LCS-QoS", ber.RuleRef{Document: "ITU-T X.680", Edition: "02/2021", Clause: "51.5"}), "horizontal-accuracy", "SIZE (1)", len(*v.HorizontalAccuracy)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_horizontalaccuracy, encodeErr_enc_horizontalaccuracy := ber.EncodeOctetString([]byte(*v.HorizontalAccuracy))
		if encodeErr_enc_horizontalaccuracy != nil {
			return nil, qualifyBERError(encodeErr_enc_horizontalaccuracy, "horizontal-accuracy", "encoding", true)
		}
		retagged_enc_horizontalaccuracy, tagErr_enc_horizontalaccuracy := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_horizontalaccuracy)
		if tagErr_enc_horizontalaccuracy != nil {
			return nil, qualifyBERError(tagErr_enc_horizontalaccuracy, "horizontal-accuracy", "encoding", true)
		}
		enc_horizontalaccuracy = retagged_enc_horizontalaccuracy
		children = append(children, enc_horizontalaccuracy...)
	}
	if v.VerticalCoordinateRequest != nil {
		enc_verticalcoordinaterequest := ber.EncodeNull()
		retagged_enc_verticalcoordinaterequest, tagErr_enc_verticalcoordinaterequest := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_verticalcoordinaterequest)
		if tagErr_enc_verticalcoordinaterequest != nil {
			return nil, qualifyBERError(tagErr_enc_verticalcoordinaterequest, "verticalCoordinateRequest", "encoding", true)
		}
		enc_verticalcoordinaterequest = retagged_enc_verticalcoordinaterequest
		children = append(children, enc_verticalcoordinaterequest...)
	}
	if v.VerticalAccuracy != nil {
		if len(*v.VerticalAccuracy) < 1 || len(*v.VerticalAccuracy) > 1 {
			if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(nil, "MAP-LCS-DataTypes.LCS-QoS", ber.RuleRef{Document: "ITU-T X.680", Edition: "02/2021", Clause: "51.5"}), "vertical-accuracy", "SIZE (1)", len(*v.VerticalAccuracy)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_verticalaccuracy, encodeErr_enc_verticalaccuracy := ber.EncodeOctetString([]byte(*v.VerticalAccuracy))
		if encodeErr_enc_verticalaccuracy != nil {
			return nil, qualifyBERError(encodeErr_enc_verticalaccuracy, "vertical-accuracy", "encoding", true)
		}
		retagged_enc_verticalaccuracy, tagErr_enc_verticalaccuracy := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_verticalaccuracy)
		if tagErr_enc_verticalaccuracy != nil {
			return nil, qualifyBERError(tagErr_enc_verticalaccuracy, "vertical-accuracy", "encoding", true)
		}
		enc_verticalaccuracy = retagged_enc_verticalaccuracy
		children = append(children, enc_verticalaccuracy...)
	}
	if v.ResponseTime != nil {
		enc_responsetime, err := v.ResponseTime.MarshalDER()
		if err != nil {
			return nil, qualifyBERError(err, "responseTime", "encoding", true)
		}
		retagged_enc_responsetime, tagErr_enc_responsetime := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, enc_responsetime)
		if tagErr_enc_responsetime != nil {
			return nil, qualifyBERError(tagErr_enc_responsetime, "responseTime", "encoding", true)
		}
		enc_responsetime = retagged_enc_responsetime
		children = append(children, enc_responsetime...)
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
	if v.VelocityRequest != nil {
		enc_velocityrequest := ber.EncodeNull()
		retagged_enc_velocityrequest, tagErr_enc_velocityrequest := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 5, enc_velocityrequest)
		if tagErr_enc_velocityrequest != nil {
			return nil, qualifyBERError(tagErr_enc_velocityrequest, "velocityRequest", "encoding", true)
		}
		enc_velocityrequest = retagged_enc_velocityrequest
		children = append(children, enc_velocityrequest...)
	}
	if v.LcsQosClass != nil {
		enc_lcsqosclass := ber.EncodeEnumerated(int64(*v.LcsQosClass))
		retagged_enc_lcsqosclass, tagErr_enc_lcsqosclass := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 6, enc_lcsqosclass)
		if tagErr_enc_lcsqosclass != nil {
			return nil, qualifyBERError(tagErr_enc_lcsqosclass, "lcs-qos-class", "encoding", true)
		}
		enc_lcsqosclass = retagged_enc_lcsqosclass
		children = append(children, enc_lcsqosclass...)
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
		if i == 0 && ((peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 6) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 5) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0)) {
			if constraintErr := ber.CheckEncodedValue(ber.EncodeRule(nil, "MAP-LCS-DataTypes.LCS-QoS", ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
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
		return nil, fmt.Errorf("%s: %w", "encoding LCSLCSQoS as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}
func (v *LCSLCSQoS) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	encoded, err := v.MarshalDER()
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBER decodes LCSLCSQoS from BER/DER format.
func (destination *LCSLCSQoS) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if destination == nil {
		return fmt.Errorf("%w: LCSLCSQoS destination is nil", ber.ErrInvalidValue)
	}
	var berNextValue_ LCSLCSQoS
	v := &berNextValue_
	defer func() {
		if returnErr == nil {
			*destination = *v
		}
	}()

	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	ownedData, ownErr := ber.OwnGeneratedBERInput(data, opts)
	if ownErr != nil {
		return ownErr
	}
	data = ownedData
	preparedData, preparedOptions, prepareErr := ber.PrepareGeneratedBERInput(data, opts)
	if prepareErr != nil {
		return ber.DiagnosePreflight(prepareErr, data, opts, "child", func(probeOpts []ber.DecodeOption) error {
			var probe LCSLCSQoS
			return probe.UnmarshalBER(data, probeOpts...)
		})
	}
	data, opts = preparedData, preparedOptions
	opts = ber.LocateDecodedElement(data, "MAP-LCS-DataTypes.LCS-QoS", opts)
	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
	*v = LCSLCSQoS{}
	defer func() {
		if returnErr != nil || !ber.BERNeedsPreservation(opts) {
			return
		}
		v.berReplayNode_ = ber.CaptureGeneratedBERReplay(data, opts)
		returnErr = ber.CompleteGeneratedBERDecode(opts, v, func(base *LCSLCSQoS, replayOpts ...ber.EncodeOption) ([]byte, error) {
			return base.MarshalBER(replayOpts...)
		})
	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("%s: %w", "decoding LCSLCSQoS SEQUENCE", qualifyBERError(err, "", "decoding", false))
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
				ber.MarkPreflightTarget(opts, "horizontal-accuracy", content[offset:])
				decodedTag_horizontalaccuracy, n_horizontalaccuracy, rawVal_horizontalaccuracy, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "horizontal-accuracy", "decoding", false)
				}
				if decodedTag_horizontalaccuracy.Class != tag.ClassContextSpecific || decodedTag_horizontalaccuracy.Number != 0 {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_horizontalaccuracy), "horizontal-accuracy", "decoding", false)
				}
				decVal_horizontalaccuracy, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_horizontalaccuracy.Constructed, rawVal_horizontalaccuracy, opts...)
				if octetErr != nil {
					return qualifyBERError(octetErr, "horizontal-accuracy", "decoding", false)
				}
				tmp_horizontalaccuracy := LCSHorizontalAccuracy(decVal_horizontalaccuracy)
				v.HorizontalAccuracy = &tmp_horizontalaccuracy
				if offset > len(content) || n_horizontalaccuracy < 0 || n_horizontalaccuracy >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_horizontalaccuracy
				if len(*v.HorizontalAccuracy) < 1 || len(*v.HorizontalAccuracy) > 1 {
					if constraintErr := ber.CheckDecodedLength(ber.DecodeRule(opts, "MAP-LCS-DataTypes.LCS-QoS", ber.RuleRef{Document: "ITU-T X.680", Edition: "02/2021", Clause: "51.5"}), "horizontal-accuracy", "SIZE (1)", len(*v.HorizontalAccuracy)); constraintErr != nil {
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
				ber.MarkPreflightTarget(opts, "verticalCoordinateRequest", content[offset:])
				decodedTag_verticalcoordinaterequest, n_verticalcoordinaterequest, rawVal_verticalcoordinaterequest, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "verticalCoordinateRequest", "decoding", false)
				}
				if decodedTag_verticalcoordinaterequest.Class != tag.ClassContextSpecific || decodedTag_verticalcoordinaterequest.Number != 1 || decodedTag_verticalcoordinaterequest.Constructed != false {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_verticalcoordinaterequest), "verticalCoordinateRequest", "decoding", false)
				}
				if len(rawVal_verticalcoordinaterequest) != 0 {
					return qualifyBERError(fmt.Errorf("%w: NULL content length %d", ber.ErrInvalidValue, len(rawVal_verticalcoordinaterequest)), "verticalCoordinateRequest", "decoding", false)
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
				ber.MarkPreflightTarget(opts, "vertical-accuracy", content[offset:])
				decodedTag_verticalaccuracy, n_verticalaccuracy, rawVal_verticalaccuracy, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "vertical-accuracy", "decoding", false)
				}
				if decodedTag_verticalaccuracy.Class != tag.ClassContextSpecific || decodedTag_verticalaccuracy.Number != 2 {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_verticalaccuracy), "vertical-accuracy", "decoding", false)
				}
				decVal_verticalaccuracy, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_verticalaccuracy.Constructed, rawVal_verticalaccuracy, opts...)
				if octetErr != nil {
					return qualifyBERError(octetErr, "vertical-accuracy", "decoding", false)
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
					if constraintErr := ber.CheckDecodedLength(ber.DecodeRule(opts, "MAP-LCS-DataTypes.LCS-QoS", ber.RuleRef{Document: "ITU-T X.680", Edition: "02/2021", Clause: "51.5"}), "vertical-accuracy", "SIZE (1)", len(*v.VerticalAccuracy)); constraintErr != nil {
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
				ber.MarkPreflightTarget(opts, "responseTime", content[offset:])
				decodedTag_responsetime, n_responsetime, rawVal_responsetime, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "responseTime", "decoding", false)
				}
				if decodedTag_responsetime.Class != tag.ClassContextSpecific || decodedTag_responsetime.Number != 3 || decodedTag_responsetime.Constructed != true {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_responsetime), "responseTime", "decoding", false)
				}
				_ = rawVal_responsetime
				if offset < 0 || offset >
					len(content) || n_responsetime < 0 || n_responsetime >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				reconstructed_responsetime, reconstructionErr_responsetime := ber.EncodeImplicitTagWithClass(tag.ClassUniversal, tag.TagSequence, content[offset:offset+n_responsetime])
				if reconstructionErr_responsetime != nil {
					return qualifyBERError(reconstructionErr_responsetime, "responseTime", "decoding", false)
				}
				var dec_responsetime LCSResponseTime
				if unmErr := dec_responsetime.UnmarshalBER(reconstructed_responsetime, ber.ChildDecodeOptions(opts, "responseTime")...); unmErr != nil {
					return qualifyBERError(unmErr, "responseTime", "decoding", false)
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
				ber.MarkPreflightTarget(opts, "extensionContainer", content[offset:])
				decodedTag_extensioncontainer, n_extensioncontainer, rawVal_extensioncontainer, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "extensionContainer", "decoding", false)
				}
				if decodedTag_extensioncontainer.Class != tag.ClassContextSpecific || decodedTag_extensioncontainer.Number != 4 || decodedTag_extensioncontainer.Constructed != true {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_extensioncontainer), "extensionContainer", "decoding", false)
				}
				_ = rawVal_extensioncontainer
				if offset < 0 || offset >
					len(content) || n_extensioncontainer < 0 || n_extensioncontainer >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				reconstructed_extensioncontainer, reconstructionErr_extensioncontainer := ber.EncodeImplicitTagWithClass(tag.ClassUniversal, tag.TagSequence, content[offset:offset+n_extensioncontainer])
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
	// Decode velocityRequest
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 5 {
				ber.MarkPreflightTarget(opts, "velocityRequest", content[offset:])
				decodedTag_velocityrequest, n_velocityrequest, rawVal_velocityrequest, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "velocityRequest", "decoding", false)
				}
				if decodedTag_velocityrequest.Class != tag.ClassContextSpecific || decodedTag_velocityrequest.Number != 5 || decodedTag_velocityrequest.Constructed != false {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_velocityrequest), "velocityRequest", "decoding", false)
				}
				if len(rawVal_velocityrequest) != 0 {
					return qualifyBERError(fmt.Errorf("%w: NULL content length %d", ber.ErrInvalidValue, len(rawVal_velocityrequest)), "velocityRequest", "decoding", false)
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
				ber.MarkPreflightTarget(opts, "lcs-qos-class", content[offset:])
				decodedTag_lcsqosclass, n_lcsqosclass, rawVal_lcsqosclass, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "lcs-qos-class", "decoding", false)
				}
				if decodedTag_lcsqosclass.Class != tag.ClassContextSpecific || decodedTag_lcsqosclass.Number != 6 || decodedTag_lcsqosclass.Constructed != false {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_lcsqosclass), "lcs-qos-class", "decoding", false)
				}
				decVal_lcsqosclass, intErr := ber.DecodeEnumeratedValue(rawVal_lcsqosclass)
				if intErr != nil {
					return qualifyBERError(intErr, "lcs-qos-class", "decoding", false)
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
		peekTag, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:], opts...)
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "LCSLCSQoS", Cause: extErr_}
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: the first unknown addition must differ from trailing OPTIONAL/DEFAULT tags.
		if len(v.ExtData_) == 0 && ((peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 6) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 5) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0)) {
			if !ber.ToleranceEnabled(opts) {
				return &ber.DecodeError{Offset: offset, TypeName: "LCSLCSQoS", Cause: fmt.Errorf("%w: repeated or out-of-order SEQUENCE component tag %s", ber.ErrInvalidTag, peekTag)}
			}
			if orderErr_ := ber.CheckDecodedValue(ber.DecodeRule(opts, "MAP-LCS-DataTypes.LCS-QoS", ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), fmt.Sprintf("ExtData_[%d]", len(v.ExtData_)), "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); orderErr_ != nil {
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

// MarshalBER encodes LCSResponseTime to BER format.
func (v *LCSResponseTime) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: LCSResponseTime receiver is nil", ber.ErrInvalidValue)
	}
	if v.berReplayNode_ == nil {
		return v.marshalBER(opts...)
	}
	var replayErr error
	opts, replayErr = ber.PrepareBERReplay(v.berReplayNode_, opts, func(mode ber.EncodeOption) ([]byte, error) { return v.MarshalBER([]ber.EncodeOption{mode}...) }, v)
	if replayErr != nil {
		return nil, replayErr
	}
	if replayBytes, ok := ber.PreparedBERReplay(v.berReplayNode_, opts); ok {
		return replayBytes, nil
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBERNode(encoded, v.berReplayNode_, opts), nil
}
func (v *LCSResponseTime) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	enc_responsetimecategory := ber.EncodeEnumerated(int64(v.ResponseTimeCategory))
	children = append(children, enc_responsetimecategory...)
	for i, ext := range v.ExtData_ {
		if err := ber.CheckBEROpaqueElement(ext, opts...); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
		_, n, _, extErr := ber.DecodeEncodedTLV(ext)
		if extErr != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, extErr)
		}
		if n != len(ext) {
			return nil, fmt.Errorf("encoding extension %d: %w", i, ber.ErrExtraData)
		}
		children = append(children, ext...)
	}
	ber.RecordGeneratedBERContainer(opts, children)
	return ber.EncodeSequence(children)
}
func (v *LCSResponseTime) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// MarshalDER encodes LCSResponseTime to DER format.
// Opaque descendants pass generic DER checks; foreign schema rules need a typed binding.
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
		return nil, fmt.Errorf("%s: %w", "encoding LCSResponseTime as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}
func (v *LCSResponseTime) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	encoded, err := v.MarshalDER()
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBER decodes LCSResponseTime from BER/DER format.
func (destination *LCSResponseTime) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if destination == nil {
		return fmt.Errorf("%w: LCSResponseTime destination is nil", ber.ErrInvalidValue)
	}
	var berNextValue_ LCSResponseTime
	v := &berNextValue_

	defer func() {
		if returnErr == nil {
			*destination = *v
		}
	}()

	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	ownedData, ownErr := ber.OwnGeneratedBERInput(data, opts)
	if ownErr != nil {
		return ownErr
	}
	data = ownedData
	preparedData, preparedOptions, prepareErr := ber.PrepareGeneratedBERInput(data, opts)
	if prepareErr != nil {
		return ber.DiagnosePreflight(prepareErr, data, opts, "child", func(probeOpts []ber.DecodeOption) error {
			var probe LCSResponseTime
			return probe.UnmarshalBER(data, probeOpts...)
		})
	}
	data, opts = preparedData, preparedOptions
	opts = ber.LocateDecodedElement(data, "MAP-LCS-DataTypes.ResponseTime", opts)
	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
	*v = LCSResponseTime{}
	defer func() {
		if returnErr != nil || !ber.BERNeedsPreservation(opts) {
			return
		}
		v.berReplayNode_ = ber.CaptureGeneratedBERReplay(data, opts)
		returnErr = ber.CompleteGeneratedBERDecode(opts, v, func(base *LCSResponseTime, replayOpts ...ber.EncodeOption) ([]byte, error) {
			return base.MarshalBER(replayOpts...)
		})
	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("%s: %w", "decoding LCSResponseTime SEQUENCE", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "LCSResponseTime", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode responseTimeCategory
	if offset >= len(content) {
		return fmt.Errorf("missing required field responseTimeCategory")
	}
	{
		ber.MarkPreflightTarget(opts, "responseTimeCategory", content[offset:])
		val_responsetimecategory, n, err := ber.DecodeEnumerated(content[offset:], opts...)
		if err != nil {
			return qualifyBERError(err, "responseTimeCategory", "decoding", false)
		}
		v.ResponseTimeCategory = LCSResponseTimeCategory(val_responsetimecategory)
		if offset > len(content) || n < 0 || n > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n
	}
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
	if v.berReplayNode_ == nil {
		return v.marshalBER(opts...)
	}
	var replayErr error
	opts, replayErr = ber.PrepareBERReplay(v.berReplayNode_, opts, func(mode ber.EncodeOption) ([]byte, error) { return v.MarshalBER([]ber.EncodeOption{mode}...) }, v)
	if replayErr != nil {
		return nil, replayErr
	}
	if replayBytes, ok := ber.PreparedBERReplay(v.berReplayNode_, opts); ok {
		return replayBytes, nil
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBERNode(encoded, v.berReplayNode_, opts), nil
}
func (v *LCSLCSCodeword) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if len(v.DataCodingScheme) < 1 || len(v.DataCodingScheme) > 1 {
		if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(opts, "MAP-LCS-DataTypes.LCSCodeword", ber.RuleRef{Document: "ITU-T X.680", Edition: "02/2021", Clause: "51.5"}), "dataCodingScheme", "SIZE (1)", len(v.DataCodingScheme)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_datacodingscheme, encodeErr_enc_datacodingscheme := ber.EncodeOctetString([]byte(v.DataCodingScheme))
	if encodeErr_enc_datacodingscheme != nil {
		return nil, qualifyBERError(encodeErr_enc_datacodingscheme, "dataCodingScheme", "encoding", false)
	}
	retagged_enc_datacodingscheme, tagErr_enc_datacodingscheme := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_datacodingscheme)
	if tagErr_enc_datacodingscheme != nil {
		return nil, qualifyBERError(tagErr_enc_datacodingscheme, "dataCodingScheme", "encoding", false)
	}
	enc_datacodingscheme = retagged_enc_datacodingscheme
	children = append(children, enc_datacodingscheme...)
	if len(v.LcsCodewordString) < 1 || len(v.LcsCodewordString) > 20 {
		if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(opts, "MAP-LCS-DataTypes.LCSCodeword", ber.RuleRef{Document: "ITU-T X.680", Edition: "02/2021", Clause: "51.5"}), "lcsCodewordString", "SIZE (1..20)", len(v.LcsCodewordString)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	if len(v.LcsCodewordString) < 1 || len(v.LcsCodewordString) > 160 {
		if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(opts, "MAP-LCS-DataTypes.LCSCodeword", ber.RuleRef{Document: "ITU-T X.680", Edition: "02/2021", Clause: "51.5"}), "lcsCodewordString", "SIZE (1..160)", len(v.LcsCodewordString)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_lcscodewordstring, encodeErr_enc_lcscodewordstring := ber.EncodeOctetString([]byte(v.LcsCodewordString))
	if encodeErr_enc_lcscodewordstring != nil {
		return nil, qualifyBERError(encodeErr_enc_lcscodewordstring, "lcsCodewordString", "encoding", false)
	}
	retagged_enc_lcscodewordstring, tagErr_enc_lcscodewordstring := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_lcscodewordstring)
	if tagErr_enc_lcscodewordstring != nil {
		return nil, qualifyBERError(tagErr_enc_lcscodewordstring, "lcsCodewordString", "encoding", false)
	}
	enc_lcscodewordstring = retagged_enc_lcscodewordstring
	children = append(children, enc_lcscodewordstring...)
	for i, ext := range v.ExtData_ {
		if err := ber.CheckBEROpaqueElement(ext, opts...); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
		_, n, _, extErr := ber.DecodeEncodedTLV(ext)
		if extErr != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, extErr)
		}
		if n != len(ext) {
			return nil, fmt.Errorf("encoding extension %d: %w", i, ber.ErrExtraData)
		}
		children = append(children, ext...)
	}
	ber.RecordGeneratedBERContainer(opts, children)
	return ber.EncodeSequence(children)
}
func (v *LCSLCSCodeword) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// MarshalDER encodes LCSLCSCodeword to DER format.
// Opaque descendants pass generic DER checks; foreign schema rules need a typed binding.
func (v *LCSLCSCodeword) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: LCSLCSCodeword receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if len(v.DataCodingScheme) < 1 || len(v.DataCodingScheme) > 1 {
		if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(nil, "MAP-LCS-DataTypes.LCSCodeword", ber.RuleRef{Document: "ITU-T X.680", Edition: "02/2021", Clause: "51.5"}), "dataCodingScheme", "SIZE (1)", len(v.DataCodingScheme)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_datacodingscheme, encodeErr_enc_datacodingscheme := ber.EncodeOctetString([]byte(v.DataCodingScheme))
	if encodeErr_enc_datacodingscheme != nil {
		return nil, qualifyBERError(encodeErr_enc_datacodingscheme, "dataCodingScheme", "encoding", true)
	}
	retagged_enc_datacodingscheme, tagErr_enc_datacodingscheme := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_datacodingscheme)
	if tagErr_enc_datacodingscheme != nil {
		return nil, qualifyBERError(tagErr_enc_datacodingscheme, "dataCodingScheme", "encoding", true)
	}
	enc_datacodingscheme = retagged_enc_datacodingscheme
	children = append(children, enc_datacodingscheme...)
	if len(v.LcsCodewordString) < 1 || len(v.LcsCodewordString) > 20 {
		if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(nil, "MAP-LCS-DataTypes.LCSCodeword", ber.RuleRef{Document: "ITU-T X.680", Edition: "02/2021", Clause: "51.5"}), "lcsCodewordString", "SIZE (1..20)", len(v.LcsCodewordString)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	if len(v.LcsCodewordString) < 1 || len(v.LcsCodewordString) > 160 {
		if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(nil, "MAP-LCS-DataTypes.LCSCodeword", ber.RuleRef{Document: "ITU-T X.680", Edition: "02/2021", Clause: "51.5"}), "lcsCodewordString", "SIZE (1..160)", len(v.LcsCodewordString)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_lcscodewordstring, encodeErr_enc_lcscodewordstring := ber.EncodeOctetString([]byte(v.LcsCodewordString))
	if encodeErr_enc_lcscodewordstring != nil {
		return nil, qualifyBERError(encodeErr_enc_lcscodewordstring, "lcsCodewordString", "encoding", true)
	}
	retagged_enc_lcscodewordstring, tagErr_enc_lcscodewordstring := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_lcscodewordstring)
	if tagErr_enc_lcscodewordstring != nil {
		return nil, qualifyBERError(tagErr_enc_lcscodewordstring, "lcsCodewordString", "encoding", true)
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
		return nil, fmt.Errorf("%s: %w", "encoding LCSLCSCodeword as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}
func (v *LCSLCSCodeword) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	encoded, err := v.MarshalDER()
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBER decodes LCSLCSCodeword from BER/DER format.
func (destination *LCSLCSCodeword) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if destination == nil {
		return fmt.Errorf("%w: LCSLCSCodeword destination is nil", ber.ErrInvalidValue)
	}
	var berNextValue_ LCSLCSCodeword
	v := &berNextValue_
	defer func() {
		if returnErr == nil {
			*destination = *v
		}
	}()

	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	ownedData, ownErr := ber.OwnGeneratedBERInput(data, opts)
	if ownErr != nil {
		return ownErr
	}
	data = ownedData
	preparedData, preparedOptions, prepareErr := ber.PrepareGeneratedBERInput(data, opts)
	if prepareErr != nil {
		return ber.DiagnosePreflight(prepareErr, data, opts, "child", func(probeOpts []ber.DecodeOption) error {
			var probe LCSLCSCodeword
			return probe.UnmarshalBER(data, probeOpts...)
		})
	}
	data, opts = preparedData, preparedOptions
	opts = ber.LocateDecodedElement(data, "MAP-LCS-DataTypes.LCSCodeword", opts)
	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
	*v = LCSLCSCodeword{}
	defer func() {
		if returnErr != nil || !ber.BERNeedsPreservation(opts) {
			return
		}
		v.berReplayNode_ = ber.CaptureGeneratedBERReplay(data, opts)
		returnErr = ber.CompleteGeneratedBERDecode(opts, v, func(base *LCSLCSCodeword, replayOpts ...ber.EncodeOption) ([]byte, error) {
			return base.MarshalBER(replayOpts...)
		})
	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("%s: %w", "decoding LCSLCSCodeword SEQUENCE", qualifyBERError(err, "", "decoding", false))
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
	{
		ber.MarkPreflightTarget(opts, "dataCodingScheme", content[offset:])
		decodedTag_datacodingscheme, n_datacodingscheme, rawVal_datacodingscheme, err := ber.DecodeTLV(content[offset:], opts...)
		if err != nil {
			return qualifyBERError(err, "dataCodingScheme", "decoding", false)
		}
		if decodedTag_datacodingscheme.Class != tag.ClassContextSpecific || decodedTag_datacodingscheme.Number != 0 {
			return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_datacodingscheme), "dataCodingScheme", "decoding", false)
		}
		decVal_datacodingscheme, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_datacodingscheme.Constructed, rawVal_datacodingscheme, opts...)
		if octetErr != nil {
			return qualifyBERError(octetErr, "dataCodingScheme", "decoding", false)
		}
		v.DataCodingScheme = v21_map_ss_datatypes.SSUSSDDataCodingScheme(decVal_datacodingscheme)
		if offset > len(content) || n_datacodingscheme < 0 || n_datacodingscheme > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n_datacodingscheme
		if len(v.DataCodingScheme) < 1 || len(v.DataCodingScheme) > 1 {
			if constraintErr := ber.CheckDecodedLength(ber.DecodeRule(opts, "MAP-LCS-DataTypes.LCSCodeword", ber.RuleRef{Document: "ITU-T X.680", Edition: "02/2021", Clause: "51.5"}), "dataCodingScheme", "SIZE (1)", len(v.DataCodingScheme)); constraintErr != nil {
				return constraintErr
			}
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
	{
		ber.MarkPreflightTarget(opts, "lcsCodewordString", content[offset:])
		decodedTag_lcscodewordstring, n_lcscodewordstring, rawVal_lcscodewordstring, err := ber.DecodeTLV(content[offset:], opts...)
		if err != nil {
			return qualifyBERError(err, "lcsCodewordString", "decoding", false)
		}
		if decodedTag_lcscodewordstring.Class != tag.ClassContextSpecific || decodedTag_lcscodewordstring.Number != 1 {
			return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_lcscodewordstring), "lcsCodewordString", "decoding", false)
		}
		decVal_lcscodewordstring, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_lcscodewordstring.Constructed, rawVal_lcscodewordstring, opts...)
		if octetErr != nil {
			return qualifyBERError(octetErr, "lcsCodewordString", "decoding", false)
		}
		v.LcsCodewordString = LCSLCSCodewordString(decVal_lcscodewordstring)
		if offset < 0 || offset >
			len(content) || n_lcscodewordstring < 0 || n_lcscodewordstring >
			len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n_lcscodewordstring
		if len(v.LcsCodewordString) < 1 || len(v.LcsCodewordString) > 20 {
			if constraintErr := ber.CheckDecodedLength(ber.DecodeRule(opts, "MAP-LCS-DataTypes.LCSCodeword", ber.RuleRef{Document: "ITU-T X.680", Edition: "02/2021", Clause: "51.5"}), "lcsCodewordString", "SIZE (1..20)", len(v.LcsCodewordString)); constraintErr != nil {
				return constraintErr
			}
		}
		if len(v.LcsCodewordString) < 1 || len(v.LcsCodewordString) > 160 {
			if constraintErr := ber.CheckDecodedLength(ber.DecodeRule(opts, "MAP-LCS-DataTypes.LCSCodeword", ber.RuleRef{Document: "ITU-T X.680", Edition: "02/2021", Clause: "51.5"}), "lcsCodewordString", "SIZE (1..160)", len(v.LcsCodewordString)); constraintErr != nil {
				return constraintErr
			}
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
	if v.berReplayNode_ == nil {
		return v.marshalBER(opts...)
	}
	var replayErr error
	opts, replayErr = ber.PrepareBERReplay(v.berReplayNode_, opts, func(mode ber.EncodeOption) ([]byte, error) { return v.MarshalBER([]ber.EncodeOption{mode}...) }, v)
	if replayErr != nil {
		return nil, replayErr
	}
	if replayBytes, ok := ber.PreparedBERReplay(v.berReplayNode_, opts); ok {
		return replayBytes, nil
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBERNode(encoded, v.berReplayNode_, opts), nil
}
func (v *LCSLCSPrivacyCheck) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	enc_callsessionunrelated := ber.EncodeEnumerated(int64(v.CallSessionUnrelated))
	retagged_enc_callsessionunrelated, tagErr_enc_callsessionunrelated := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_callsessionunrelated)
	if tagErr_enc_callsessionunrelated != nil {
		return nil, qualifyBERError(tagErr_enc_callsessionunrelated, "callSessionUnrelated", "encoding", false)
	}
	enc_callsessionunrelated = retagged_enc_callsessionunrelated
	children = append(children, enc_callsessionunrelated...)
	if v.CallSessionRelated != nil {
		enc_callsessionrelated := ber.EncodeEnumerated(int64(*v.CallSessionRelated))
		retagged_enc_callsessionrelated, tagErr_enc_callsessionrelated := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_callsessionrelated)
		if tagErr_enc_callsessionrelated != nil {
			return nil, qualifyBERError(tagErr_enc_callsessionrelated, "callSessionRelated", "encoding", false)
		}
		enc_callsessionrelated = retagged_enc_callsessionrelated
		children = append(children, enc_callsessionrelated...)
	}
	for i, ext := range v.ExtData_ {
		if err := ber.CheckBEROpaqueElement(ext, opts...); err != nil {
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
		if i == 0 && (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1) {
			if constraintErr := ber.CheckEncodedValue(ber.EncodeRule(opts, "MAP-LCS-DataTypes.LCS-PrivacyCheck", ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
				return nil, constraintErr
			}
		}
		children = append(children, ext...)
	}
	ber.RecordGeneratedBERContainer(opts, children)
	return ber.EncodeSequence(children)
}
func (v *LCSLCSPrivacyCheck) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// MarshalDER encodes LCSLCSPrivacyCheck to DER format.
// Opaque descendants pass generic DER checks; foreign schema rules need a typed binding.
func (v *LCSLCSPrivacyCheck) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: LCSLCSPrivacyCheck receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	enc_callsessionunrelated := ber.EncodeEnumerated(int64(v.CallSessionUnrelated))
	retagged_enc_callsessionunrelated, tagErr_enc_callsessionunrelated := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_callsessionunrelated)
	if tagErr_enc_callsessionunrelated != nil {
		return nil, qualifyBERError(tagErr_enc_callsessionunrelated, "callSessionUnrelated", "encoding", true)
	}
	enc_callsessionunrelated = retagged_enc_callsessionunrelated
	children = append(children, enc_callsessionunrelated...)
	if v.CallSessionRelated != nil {
		enc_callsessionrelated := ber.EncodeEnumerated(int64(*v.CallSessionRelated))
		retagged_enc_callsessionrelated, tagErr_enc_callsessionrelated := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_callsessionrelated)
		if tagErr_enc_callsessionrelated != nil {
			return nil, qualifyBERError(tagErr_enc_callsessionrelated, "callSessionRelated", "encoding", true)
		}
		enc_callsessionrelated = retagged_enc_callsessionrelated
		children = append(children, enc_callsessionrelated...)
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
		if i == 0 && (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1) {
			if constraintErr := ber.CheckEncodedValue(ber.EncodeRule(nil, "MAP-LCS-DataTypes.LCS-PrivacyCheck", ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
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
		return nil, fmt.Errorf("%s: %w", "encoding LCSLCSPrivacyCheck as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}
func (v *LCSLCSPrivacyCheck) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	encoded, err := v.MarshalDER()
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBER decodes LCSLCSPrivacyCheck from BER/DER format.
func (destination *LCSLCSPrivacyCheck) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if destination == nil {
		return fmt.Errorf("%w: LCSLCSPrivacyCheck destination is nil", ber.ErrInvalidValue)
	}
	var berNextValue_ LCSLCSPrivacyCheck
	v := &berNextValue_

	defer func() {
		if returnErr ==
			nil {
			*destination =
				*v
		}
	}()

	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	ownedData, ownErr := ber.OwnGeneratedBERInput(data, opts)
	if ownErr != nil {
		return ownErr
	}
	data = ownedData
	preparedData, preparedOptions, prepareErr := ber.PrepareGeneratedBERInput(data, opts)
	if prepareErr != nil {
		return ber.DiagnosePreflight(prepareErr, data, opts, "child", func(probeOpts []ber.DecodeOption) error {
			var probe LCSLCSPrivacyCheck
			return probe.UnmarshalBER(data, probeOpts...)
		})
	}
	data, opts = preparedData, preparedOptions
	opts = ber.LocateDecodedElement(data, "MAP-LCS-DataTypes.LCS-PrivacyCheck", opts)
	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
	*v = LCSLCSPrivacyCheck{}
	defer func() {
		if returnErr != nil || !ber.BERNeedsPreservation(opts) {
			return
		}
		v.berReplayNode_ = ber.CaptureGeneratedBERReplay(data, opts)
		returnErr = ber.CompleteGeneratedBERDecode(opts, v, func(base *LCSLCSPrivacyCheck, replayOpts ...ber.EncodeOption) ([]byte, error) {
			return base.MarshalBER(replayOpts...)
		})
	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("%s: %w", "decoding LCSLCSPrivacyCheck SEQUENCE", qualifyBERError(err, "", "decoding", false))
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
	{
		ber.MarkPreflightTarget(opts, "callSessionUnrelated", content[offset:])
		decodedTag_callsessionunrelated, n_callsessionunrelated, rawVal_callsessionunrelated, err := ber.DecodeTLV(content[offset:], opts...)
		if err != nil {
			return qualifyBERError(err, "callSessionUnrelated", "decoding", false)
		}
		if decodedTag_callsessionunrelated.Class != tag.ClassContextSpecific || decodedTag_callsessionunrelated.Number != 0 || decodedTag_callsessionunrelated.Constructed != false {
			return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_callsessionunrelated), "callSessionUnrelated", "decoding", false)
		}
		decVal_callsessionunrelated, intErr := ber.DecodeEnumeratedValue(rawVal_callsessionunrelated)
		if intErr != nil {
			return qualifyBERError(intErr, "callSessionUnrelated", "decoding", false)
		}
		v.CallSessionUnrelated = LCSPrivacyCheckRelatedAction(decVal_callsessionunrelated)
		if offset > len(content) || n_callsessionunrelated < 0 || n_callsessionunrelated > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n_callsessionunrelated
	}
	// Decode callSessionRelated
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
				ber.MarkPreflightTarget(opts, "callSessionRelated", content[offset:])
				decodedTag_callsessionrelated, n_callsessionrelated, rawVal_callsessionrelated, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "callSessionRelated", "decoding", false)
				}
				if decodedTag_callsessionrelated.Class != tag.ClassContextSpecific || decodedTag_callsessionrelated.Number != 1 || decodedTag_callsessionrelated.Constructed != false {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_callsessionrelated), "callSessionRelated", "decoding", false)
				}
				decVal_callsessionrelated, intErr := ber.DecodeEnumeratedValue(rawVal_callsessionrelated)
				if intErr != nil {
					return qualifyBERError(intErr, "callSessionRelated", "decoding", false)
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
		peekTag, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:], opts...)
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "LCSLCSPrivacyCheck", Cause: extErr_}
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: the first unknown addition must differ from trailing OPTIONAL/DEFAULT tags.
		if len(v.ExtData_) == 0 && (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1) {
			if !ber.ToleranceEnabled(opts) {
				return &ber.DecodeError{Offset: offset, TypeName: "LCSLCSPrivacyCheck", Cause: fmt.Errorf("%w: repeated or out-of-order SEQUENCE component tag %s", ber.ErrInvalidTag, peekTag)}
			}
			if orderErr_ := ber.CheckDecodedValue(ber.DecodeRule(opts, "MAP-LCS-DataTypes.LCS-PrivacyCheck", ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), fmt.Sprintf("ExtData_[%d]", len(v.ExtData_)), "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); orderErr_ != nil {
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

// MarshalBER encodes LCSAreaEventInfo to BER format.
func (v *LCSAreaEventInfo) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: LCSAreaEventInfo receiver is nil", ber.ErrInvalidValue)
	}
	if v.berReplayNode_ == nil {
		return v.marshalBER(opts...)
	}
	var replayErr error
	opts, replayErr = ber.PrepareBERReplay(v.berReplayNode_, opts, func(mode ber.EncodeOption) ([]byte, error) { return v.MarshalBER([]ber.EncodeOption{mode}...) }, v)
	if replayErr != nil {
		return nil, replayErr
	}
	if replayBytes, ok := ber.PreparedBERReplay(v.berReplayNode_, opts); ok {
		return replayBytes, nil
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBERNode(encoded, v.berReplayNode_, opts), nil
}
func (v *LCSAreaEventInfo) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	enc_areadefinition, err := v.AreaDefinition.MarshalBER(ber.ChildEncodeOptions(opts, "areaDefinition")...)
	if err != nil {
		return nil, qualifyBERError(err, "areaDefinition", "encoding", false)
	}
	retagged_enc_areadefinition, tagErr_enc_areadefinition := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_areadefinition)
	if tagErr_enc_areadefinition != nil {
		return nil, qualifyBERError(tagErr_enc_areadefinition, "areaDefinition", "encoding", false)
	}
	enc_areadefinition = retagged_enc_areadefinition
	ber.RecordGeneratedBERChildPlacement(opts, len(children), enc_areadefinition)
	children = append(children, enc_areadefinition...)
	if v.OccurrenceInfo != nil {
		enc_occurrenceinfo := ber.EncodeEnumerated(int64(*v.OccurrenceInfo))
		retagged_enc_occurrenceinfo, tagErr_enc_occurrenceinfo := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_occurrenceinfo)
		if tagErr_enc_occurrenceinfo != nil {
			return nil, qualifyBERError(tagErr_enc_occurrenceinfo, "occurrenceInfo", "encoding", false)
		}
		enc_occurrenceinfo = retagged_enc_occurrenceinfo
		children = append(children, enc_occurrenceinfo...)
	}
	if v.IntervalTime != nil {
		if !(int64(*v.IntervalTime) >= 1 && int64(*v.IntervalTime) <= 32767) {
			if constraintErr := ber.CheckEncodedValue(ber.EncodeRule(opts, "MAP-LCS-DataTypes.AreaEventInfo", ber.RuleRef{Document: "ITU-T X.680", Edition: "02/2021", Clause: "51.4"}), "intervalTime", "(1..32767)", ber.ObserveInteger(int64(*v.IntervalTime))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_intervaltime := ber.EncodeInteger(int64(*v.IntervalTime))
		retagged_enc_intervaltime, tagErr_enc_intervaltime := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_intervaltime)
		if tagErr_enc_intervaltime != nil {
			return nil, qualifyBERError(tagErr_enc_intervaltime, "intervalTime", "encoding", false)
		}
		enc_intervaltime = retagged_enc_intervaltime
		children = append(children, enc_intervaltime...)
	}
	for i, ext := range v.ExtData_ {
		if err := ber.CheckBEROpaqueElement(ext, opts...); err != nil {
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
		if i == 0 && ((peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1)) {
			if constraintErr := ber.CheckEncodedValue(ber.EncodeRule(opts, "MAP-LCS-DataTypes.AreaEventInfo", ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
				return nil, constraintErr
			}
		}
		children = append(children, ext...)
	}
	ber.RecordGeneratedBERContainer(opts, children)
	return ber.EncodeSequence(children)
}
func (v *LCSAreaEventInfo) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// MarshalDER encodes LCSAreaEventInfo to DER format.
// Opaque descendants pass generic DER checks; foreign schema rules need a typed binding.
func (v *LCSAreaEventInfo) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: LCSAreaEventInfo receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	enc_areadefinition, err := v.AreaDefinition.MarshalDER()
	if err != nil {
		return nil, qualifyBERError(err, "areaDefinition", "encoding", true)
	}
	retagged_enc_areadefinition, tagErr_enc_areadefinition := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_areadefinition)
	if tagErr_enc_areadefinition != nil {
		return nil, qualifyBERError(tagErr_enc_areadefinition, "areaDefinition", "encoding", true)
	}
	enc_areadefinition = retagged_enc_areadefinition
	children = append(children, enc_areadefinition...)
	if v.OccurrenceInfo != nil {
		enc_occurrenceinfo := ber.EncodeEnumerated(int64(*v.OccurrenceInfo))
		retagged_enc_occurrenceinfo, tagErr_enc_occurrenceinfo := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_occurrenceinfo)
		if tagErr_enc_occurrenceinfo != nil {
			return nil, qualifyBERError(tagErr_enc_occurrenceinfo, "occurrenceInfo", "encoding", true)
		}
		enc_occurrenceinfo = retagged_enc_occurrenceinfo
		children = append(children, enc_occurrenceinfo...)
	}
	if v.IntervalTime != nil {
		if !(int64(*v.IntervalTime) >= 1 && int64(*v.IntervalTime) <= 32767) {
			if constraintErr := ber.CheckEncodedValue(ber.EncodeRule(nil, "MAP-LCS-DataTypes.AreaEventInfo", ber.RuleRef{Document: "ITU-T X.680", Edition: "02/2021", Clause: "51.4"}), "intervalTime", "(1..32767)", ber.ObserveInteger(int64(*v.IntervalTime))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_intervaltime := ber.EncodeInteger(int64(*v.IntervalTime))
		retagged_enc_intervaltime, tagErr_enc_intervaltime := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_intervaltime)
		if tagErr_enc_intervaltime != nil {
			return nil, qualifyBERError(tagErr_enc_intervaltime, "intervalTime", "encoding", true)
		}
		enc_intervaltime = retagged_enc_intervaltime
		children = append(children, enc_intervaltime...)
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
		if i == 0 && ((peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1)) {
			if constraintErr := ber.CheckEncodedValue(ber.EncodeRule(nil, "MAP-LCS-DataTypes.AreaEventInfo", ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
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
		return nil, fmt.Errorf("%s: %w", "encoding LCSAreaEventInfo as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}
func (v *LCSAreaEventInfo) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	encoded, err := v.MarshalDER()
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBER decodes LCSAreaEventInfo from BER/DER format.
func (destination *LCSAreaEventInfo) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if destination == nil {
		return fmt.Errorf("%w: LCSAreaEventInfo destination is nil", ber.ErrInvalidValue)
	}
	var berNextValue_ LCSAreaEventInfo
	v := &berNextValue_

	defer func() {
		if returnErr == nil {
			*destination = *v
		}
	}()

	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	ownedData, ownErr := ber.OwnGeneratedBERInput(data, opts)
	if ownErr != nil {
		return ownErr
	}
	data = ownedData
	preparedData, preparedOptions, prepareErr := ber.PrepareGeneratedBERInput(data, opts)
	if prepareErr != nil {
		return ber.DiagnosePreflight(prepareErr, data, opts, "child", func(probeOpts []ber.DecodeOption) error {
			var probe LCSAreaEventInfo
			return probe.UnmarshalBER(data, probeOpts...)
		})
	}
	data, opts = preparedData, preparedOptions
	opts = ber.LocateDecodedElement(data, "MAP-LCS-DataTypes.AreaEventInfo", opts)
	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
	*v = LCSAreaEventInfo{}
	defer func() {
		if returnErr != nil || !ber.BERNeedsPreservation(opts) {
			return
		}
		v.berReplayNode_ = ber.CaptureGeneratedBERReplay(data, opts)
		returnErr = ber.CompleteGeneratedBERDecode(opts, v, func(base *LCSAreaEventInfo, replayOpts ...ber.EncodeOption) ([]byte, error) {
			return base.MarshalBER(replayOpts...)
		})
	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("%s: %w", "decoding LCSAreaEventInfo SEQUENCE", qualifyBERError(err, "", "decoding", false))
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
	{
		ber.MarkPreflightTarget(opts, "areaDefinition", content[offset:])
		decodedTag_areadefinition, n_areadefinition, rawVal_areadefinition, err := ber.DecodeTLV(content[offset:], opts...)
		if err != nil {
			return qualifyBERError(err, "areaDefinition", "decoding", false)
		}
		if decodedTag_areadefinition.Class != tag.ClassContextSpecific || decodedTag_areadefinition.Number != 0 || decodedTag_areadefinition.Constructed != true {
			return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_areadefinition), "areaDefinition", "decoding", false)
		}
		_ = rawVal_areadefinition
		if offset > len(content) || n_areadefinition < 0 || n_areadefinition > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		reconstructed_areadefinition, reconstructionErr_areadefinition := ber.EncodeImplicitTagWithClass(tag.ClassUniversal, tag.TagSequence, content[offset:offset+n_areadefinition])
		if reconstructionErr_areadefinition != nil {
			return qualifyBERError(reconstructionErr_areadefinition, "areaDefinition", "decoding", false)
		}
		if unmErr := v.AreaDefinition.UnmarshalBER(reconstructed_areadefinition, ber.ChildDecodeOptions(opts, "areaDefinition")...); unmErr != nil {
			return qualifyBERError(unmErr, "areaDefinition", "decoding", false)
		}
		if offset > len(content) || n_areadefinition < 0 || n_areadefinition > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n_areadefinition
	}
	// Decode occurrenceInfo
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
				ber.MarkPreflightTarget(opts, "occurrenceInfo", content[offset:])
				decodedTag_occurrenceinfo, n_occurrenceinfo, rawVal_occurrenceinfo, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "occurrenceInfo", "decoding", false)
				}
				if decodedTag_occurrenceinfo.Class != tag.ClassContextSpecific || decodedTag_occurrenceinfo.Number != 1 || decodedTag_occurrenceinfo.Constructed != false {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_occurrenceinfo), "occurrenceInfo", "decoding", false)
				}
				decVal_occurrenceinfo, intErr := ber.DecodeEnumeratedValue(rawVal_occurrenceinfo)
				if intErr != nil {
					return qualifyBERError(intErr, "occurrenceInfo", "decoding", false)
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
				ber.MarkPreflightTarget(opts, "intervalTime", content[offset:])
				decodedTag_intervaltime, n_intervaltime, rawVal_intervaltime, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "intervalTime", "decoding", false)
				}
				if decodedTag_intervaltime.Class != tag.ClassContextSpecific || decodedTag_intervaltime.Number != 2 || decodedTag_intervaltime.Constructed != false {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_intervaltime), "intervalTime", "decoding", false)
				}
				decVal_intervaltime, intErr := ber.DecodeIntegerValue(rawVal_intervaltime)
				if intErr != nil {
					return qualifyBERError(intErr, "intervalTime", "decoding", false)
				}
				tmp_intervaltime := LCSIntervalTime(decVal_intervaltime)
				v.IntervalTime = &tmp_intervaltime
				if offset < 0 || offset >
					len(content) || n_intervaltime < 0 || n_intervaltime > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_intervaltime
				if !(int64(*v.IntervalTime) >= 1 && int64(*v.IntervalTime) <= 32767) {
					if constraintErr := ber.CheckDecodedValue(ber.DecodeRule(opts, "MAP-LCS-DataTypes.AreaEventInfo", ber.RuleRef{Document: "ITU-T X.680", Edition: "02/2021", Clause: "51.4"}), "intervalTime", "(1..32767)", ber.ObserveInteger(int64(*v.IntervalTime))); constraintErr != nil {
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
			return &ber.DecodeError{Offset: offset, TypeName: "LCSAreaEventInfo", Cause: extErr_}
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: the first unknown addition must differ from trailing OPTIONAL/DEFAULT tags.
		if len(v.ExtData_) == 0 && ((peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1)) {
			if !ber.ToleranceEnabled(opts) {
				return &ber.DecodeError{Offset: offset, TypeName: "LCSAreaEventInfo", Cause: fmt.Errorf("%w: repeated or out-of-order SEQUENCE component tag %s", ber.ErrInvalidTag, peekTag)}
			}
			if orderErr_ := ber.CheckDecodedValue(ber.DecodeRule(opts, "MAP-LCS-DataTypes.AreaEventInfo", ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), fmt.Sprintf("ExtData_[%d]", len(v.ExtData_)), "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); orderErr_ != nil {
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

// MarshalBER encodes LCSAreaDefinition to BER format.
func (v *LCSAreaDefinition) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: LCSAreaDefinition receiver is nil", ber.ErrInvalidValue)
	}
	if v.berReplayNode_ == nil {
		return v.marshalBER(opts...)
	}
	var replayErr error
	opts, replayErr = ber.PrepareBERReplay(v.berReplayNode_, opts, func(mode ber.EncodeOption) ([]byte, error) { return v.MarshalBER([]ber.EncodeOption{mode}...) }, v)
	if replayErr != nil {
		return nil, replayErr
	}
	if replayBytes, ok := ber.PreparedBERReplay(v.berReplayNode_, opts); ok {
		return replayBytes, nil
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBERNode(encoded, v.berReplayNode_, opts), nil
}
func (v *LCSAreaDefinition) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if v.AreaList == nil {
		return nil, qualifyBERError(fmt.Errorf("%w: required collection is nil", ber.ErrInvalidValue), "areaList", "encoding", false)
	}
	if len((v.AreaList).Values) < 1 || len((v.AreaList).Values) > 10 {
		if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(opts, "MAP-LCS-DataTypes.AreaDefinition", ber.RuleRef{Document: "ITU-T X.680", Edition: "02/2021", Clause: "51.5"}), "areaList", "SIZE (1..10)", len((v.AreaList).Values)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_arealist, err := MarshalBERLCSAreaList(v.AreaList, ber.ParentCollectionSizeEncodeOptions(ber.ChildEncodeOptions(opts, "areaList"))...)
	if err != nil {
		return nil, qualifyBERError(err, "areaList", "encoding", false)
	}
	if ber.BERReplayEnabled(opts) && v.berAreaListIndef_ {
		// Strip the outer SEQUENCE tag from marshalBER output to get raw children.
		_, _, seqContent_, tlvErr_ := ber.DecodeEncodedTLV(enc_arealist)
		if tlvErr_ != nil {
			return nil, tlvErr_
		}
		{
			var encodeErr error
			enc_arealist, encodeErr = ber.EncodeConstructedIndefinite(tag.Tag{Class: tag.ClassContextSpecific, Number: 0}, seqContent_)
			if encodeErr != nil {
				return nil, qualifyBERError(encodeErr, "areaList", "encoding", false)
			}
		}
	} else {
		retagged_enc_arealist, tagErr_enc_arealist := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_arealist)
		if tagErr_enc_arealist != nil {
			return nil, qualifyBERError(tagErr_enc_arealist, "areaList", "encoding", false)
		}
		enc_arealist = retagged_enc_arealist
	}
	ber.RecordGeneratedBERChildPlacement(opts, len(children), enc_arealist)
	children = append(children, enc_arealist...)
	for i, ext := range v.ExtData_ {
		if err := ber.CheckBEROpaqueElement(ext, opts...); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
		_, n, _, extErr := ber.DecodeEncodedTLV(ext)
		if extErr != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, extErr)
		}
		if n != len(ext) {
			return nil, fmt.Errorf("encoding extension %d: %w", i, ber.ErrExtraData)
		}
		children = append(children, ext...)
	}
	ber.RecordGeneratedBERContainer(opts, children)
	return ber.EncodeSequence(children)
}
func (v *LCSAreaDefinition) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// MarshalDER encodes LCSAreaDefinition to DER format.
// Opaque descendants pass generic DER checks; foreign schema rules need a typed binding.
func (v *LCSAreaDefinition) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: LCSAreaDefinition receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if v.AreaList == nil {
		return nil, qualifyBERError(fmt.Errorf("%w: required collection is nil", ber.ErrInvalidValue), "areaList", "encoding", true)
	}
	if len((v.AreaList).Values) < 1 || len((v.AreaList).Values) > 10 {
		if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(nil, "MAP-LCS-DataTypes.AreaDefinition", ber.RuleRef{Document: "ITU-T X.680", Edition: "02/2021", Clause: "51.5"}), "areaList", "SIZE (1..10)", len((v.AreaList).Values)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_arealist, err := MarshalDERLCSAreaList(v.AreaList)
	if err != nil {
		return nil, qualifyBERError(err, "areaList", "encoding", true)
	}
	retagged_enc_arealist, tagErr_enc_arealist := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_arealist)
	if tagErr_enc_arealist != nil {
		return nil, qualifyBERError(tagErr_enc_arealist, "areaList", "encoding", true)
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
		return nil, fmt.Errorf("%s: %w", "encoding LCSAreaDefinition as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}
func (v *LCSAreaDefinition) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	encoded, err := v.MarshalDER()
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBER decodes LCSAreaDefinition from BER/DER format.
func (destination *LCSAreaDefinition) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if destination == nil {
		return fmt.Errorf("%w: LCSAreaDefinition destination is nil", ber.ErrInvalidValue)
	}
	var berNextValue_ LCSAreaDefinition
	v := &berNextValue_

	defer func() {
		if returnErr == nil {
			*destination = *v
		}
	}()

	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	ownedData, ownErr := ber.OwnGeneratedBERInput(data, opts)
	if ownErr != nil {
		return ownErr
	}
	data = ownedData
	preparedData, preparedOptions, prepareErr := ber.PrepareGeneratedBERInput(data, opts)
	if prepareErr != nil {
		return ber.DiagnosePreflight(prepareErr, data, opts, "child", func(probeOpts []ber.DecodeOption) error {
			var probe LCSAreaDefinition
			return probe.UnmarshalBER(data, probeOpts...)
		})
	}
	data, opts = preparedData, preparedOptions
	opts = ber.LocateDecodedElement(data, "MAP-LCS-DataTypes.AreaDefinition", opts)
	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
	*v = LCSAreaDefinition{}
	defer func() {
		if returnErr != nil || !ber.BERNeedsPreservation(opts) {
			return
		}
		v.berReplayNode_ = ber.CaptureGeneratedBERReplay(data, opts)
		returnErr = ber.CompleteGeneratedBERDecode(opts, v, func(base *LCSAreaDefinition, replayOpts ...ber.EncodeOption) ([]byte, error) {
			return base.MarshalBER(replayOpts...)
		})
	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("%s: %w", "decoding LCSAreaDefinition SEQUENCE", qualifyBERError(err, "", "decoding", false))
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
	{
		v.berAreaListIndef_ = false
		ber.MarkPreflightTarget(opts, "areaList", content[offset:])
		decodedTag_arealist, n_arealist, rawVal_arealist, err := ber.DecodeTLV(content[offset:], opts...)
		if err != nil {
			return qualifyBERError(err, "areaList", "decoding", false)
		}
		if decodedTag_arealist.Class != tag.ClassContextSpecific || decodedTag_arealist.Number != 0 || decodedTag_arealist.Constructed != true {
			return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_arealist), "areaList", "decoding", false)
		}
		_ = rawVal_arealist
		if offset > len(content) || n_arealist < 0 || n_arealist > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		reconstructed_arealist, reconstructionErr_arealist := ber.EncodeImplicitTagWithClass(tag.ClassUniversal, tag.TagSequence, content[offset:offset+n_arealist])
		if reconstructionErr_arealist != nil {
			return qualifyBERError(reconstructionErr_arealist, "areaList", "decoding", false)
		}
		dec_arealist, unmErr := UnmarshalBERLCSAreaList(reconstructed_arealist, ber.ParentCollectionSizeDecodeOptions(ber.ChildDecodeOptions(opts, "areaList"))...)
		if unmErr != nil {
			return qualifyBERError(unmErr, "areaList", "decoding", false)
		}
		v.AreaList = dec_arealist
		{
			_, tagSz_, _ := ber.DecodeTag(content[offset:])
			if offset > len(content) || tagSz_ < 0 || tagSz_ > len(content[offset:]) {
				return fmt.Errorf("invalid BER content window")
			}

			if offset+tagSz_ < len(content) && content[offset+tagSz_] == 0x80 {
				v.berAreaListIndef_ = true
			}
		}
		if offset > len(content) || n_arealist < 0 || n_arealist > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n_arealist
		if len((v.AreaList).Values) < 1 || len((v.AreaList).Values) > 10 {
			if constraintErr := ber.CheckDecodedLength(ber.DecodeRule(opts, "MAP-LCS-DataTypes.AreaDefinition", ber.RuleRef{Document: "ITU-T X.680", Edition: "02/2021", Clause: "51.5"}), "areaList", "SIZE (1..10)", len((v.AreaList).Values)); constraintErr != nil {
				return constraintErr
			}
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
	if collection.berReplayNode_ == nil {
		return marshalBERLCSAreaList(collection, opts...)
	}
	var replayErr error
	opts, replayErr = ber.PrepareBERReplay(collection.berReplayNode_, opts, func(mode ber.EncodeOption) ([]byte, error) {
		return MarshalBERLCSAreaList(collection, []ber.EncodeOption{mode}...)
	}, collection)
	if replayErr != nil {
		return nil, replayErr
	}
	if replayBytes, ok := ber.PreparedBERReplay(collection.berReplayNode_, opts); ok {
		return replayBytes, nil
	}
	encoded, err := marshalBERLCSAreaList(collection, opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBERNode(encoded, collection.berReplayNode_, opts), nil
}
func marshalBERLCSAreaList(collection *LCSAreaList, opts ...ber.EncodeOption) ([]byte, error) {
	list := collection.Values
	if len(list) < 1 || len(list) > 10 {
		if constraintErr := ber.CheckEncodedCollectionLength(ber.EncodeRule(opts, "MAP-LCS-DataTypes.marshalBERLCSAreaList", ber.RuleRef{Document: "ITU-T X.680", Edition: "02/2021", Clause: "51.5"}), "AreaList", "SIZE (1..10)", len(list)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	var children []byte
	for elemIndex := range list {
		_ = elemIndex
		elem := &list[elemIndex]
		enc, err := elem.MarshalBER(ber.ChildEncodeOptions(opts, fmt.Sprintf("element[%d]", elemIndex))...)
		if err != nil {
			return nil, qualifyBERError(err, fmt.Sprintf("element[%d]",
				elemIndex),

				"encoding", false)
		}
		children = append(children, enc...)
		ber.RecordGeneratedBERChildPlacement(opts, len(children)-len(enc), enc)
	}
	ber.RecordGeneratedBERContainer(opts, children)
	return ber.EncodeSequence(children)
}

func appendBERLinearLCSAreaList(encoder *ber.LinearEncoder, collection *LCSAreaList, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := MarshalBERLCSAreaList(collection, opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// MarshalDERLCSAreaList encodes a LCSAreaList list to DER.
func MarshalDERLCSAreaList(collection *LCSAreaList) ([]byte, error) {
	if collection == nil {
		return nil, fmt.Errorf("%w: required collection is nil", ber.ErrInvalidValue)
	}
	list := collection.Values
	if len(list) < 1 || len(list) > 10 {
		if constraintErr := ber.CheckEncodedCollectionLength(ber.EncodeRule(nil, "MAP-LCS-DataTypes.AreaList", ber.RuleRef{Document: "ITU-T X.680", Edition: "02/2021", Clause: "51.5"}), "AreaList", "SIZE (1..10)", len(list)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	var children []byte
	for elemIndex := range list {
		_ = elemIndex
		elem := &list[elemIndex]
		enc, err := elem.MarshalDER()
		if err != nil {
			return nil, qualifyBERError(err, fmt.Sprintf("element[%d]",
				elemIndex),

				"encoding", true)
		}
		children = append(children, enc...)
	}
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("%s: %w", "encoding LCSAreaList as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}

func appendDERLinearLCSAreaList(encoder *ber.LinearEncoder, collection *LCSAreaList) ([]byte, error) {
	encoded, err := MarshalDERLCSAreaList(collection)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBERLCSAreaList decodes a LCSAreaList list from BER.
func UnmarshalBERLCSAreaList(data []byte, opts ...ber.DecodeOption) (returnValue *LCSAreaList, returnErr error) {
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	ownedData, ownErr := ber.OwnGeneratedBERInput(data, opts)
	if ownErr != nil {
		return nil, ownErr
	}
	data = ownedData
	preparedData, preparedOptions, prepareErr := ber.PrepareGeneratedBERInput(data, opts)
	if prepareErr != nil {
		return nil, ber.DiagnosePreflight(prepareErr, data, opts, "element", func(probeOpts []ber.DecodeOption) error {
			_, probeErr := UnmarshalBERLCSAreaList(data, probeOpts...)
			return probeErr
		})
	}
	data, opts = preparedData, preparedOptions
	opts = ber.LocateDecodedElement(data, "MAP-LCS-DataTypes.AreaList", opts)
	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", "decoding LCSAreaList", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return nil, &ber.DecodeError{Offset: total, TypeName: "LCSAreaList", Cause: ber.ErrExtraData}
	}
	var result []LCSArea
	offset := 0
	for offset < len(content) {
		elementIndex := len(result)
		_ = elementIndex
		elementData := content[offset:]
		ber.MarkPreflightElement(opts, elementIndex, elementData)
		var elem LCSArea
		_, n, _, tlvErr := ber.DecodeTLV(elementData, opts...)
		if tlvErr != nil {
			return nil, qualifyBERError(tlvErr, fmt.Sprintf("element[%d]",
				elementIndex),

				"decoding", false)
		}
		if unmErr := elem.UnmarshalBER(elementData[:n], ber.ChildDecodeIndexOptions(opts, len(result))...); unmErr != nil {
			return nil, qualifyBERError(unmErr, fmt.Sprintf("element[%d]",
				elementIndex),

				"decoding", false)
		}
		result = append(result, elem)
		if offset < 0 || offset >
			len(content) || n < 0 || n > len(content[offset:]) {
			return nil, fmt.Errorf("invalid BER content window")
		}

		offset += n
	}
	if len(result) < 1 || len(result) > 10 {
		if constraintErr := ber.CheckDecodedCollectionLength(ber.DecodeRule(opts, "MAP-LCS-DataTypes.AreaList", ber.RuleRef{Document: "ITU-T X.680", Edition: "02/2021", Clause: "51.5"}), "AreaList", "SIZE (1..10)", len(result)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	decoded := &LCSAreaList{Values: result}
	if ber.BERNeedsPreservation(opts) {
		decoded.berReplayNode_ = ber.CaptureGeneratedBERReplay(data, opts)
		if replayErr := ber.CompleteGeneratedBERDecode(opts, decoded, func(base *LCSAreaList, replayOpts ...ber.EncodeOption) ([]byte, error) {
			return MarshalBERLCSAreaList(base, replayOpts...)
		}); replayErr != nil {
			return nil, replayErr
		}
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
	if v.berReplayNode_ == nil {
		return v.marshalBER(opts...)
	}
	var replayErr error
	opts, replayErr = ber.PrepareBERReplay(v.berReplayNode_, opts, func(mode ber.EncodeOption) ([]byte, error) { return v.MarshalBER([]ber.EncodeOption{mode}...) }, v)
	if replayErr != nil {
		return nil, replayErr
	}
	if replayBytes, ok := ber.PreparedBERReplay(v.berReplayNode_, opts); ok {
		return replayBytes, nil
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBERNode(encoded, v.berReplayNode_, opts), nil
}
func (v *LCSArea) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	enc_areatype := ber.EncodeEnumerated(int64(v.AreaType))
	retagged_enc_areatype, tagErr_enc_areatype := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_areatype)
	if tagErr_enc_areatype != nil {
		return nil, qualifyBERError(tagErr_enc_areatype, "areaType", "encoding", false)
	}
	enc_areatype = retagged_enc_areatype
	children = append(children, enc_areatype...)
	if len(v.AreaIdentification) < 2 || len(v.AreaIdentification) > 7 {
		if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(opts, "MAP-LCS-DataTypes.Area", ber.RuleRef{Document: "ITU-T X.680", Edition: "02/2021", Clause: "51.5"}), "areaIdentification", "SIZE (2..7)", len(v.AreaIdentification)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_areaidentification, encodeErr_enc_areaidentification := ber.EncodeOctetString([]byte(v.AreaIdentification))
	if encodeErr_enc_areaidentification != nil {
		return nil, qualifyBERError(encodeErr_enc_areaidentification, "areaIdentification", "encoding", false)
	}
	retagged_enc_areaidentification, tagErr_enc_areaidentification := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_areaidentification)
	if tagErr_enc_areaidentification != nil {
		return nil, qualifyBERError(tagErr_enc_areaidentification, "areaIdentification", "encoding", false)
	}
	enc_areaidentification = retagged_enc_areaidentification
	children = append(children, enc_areaidentification...)
	for i, ext := range v.ExtData_ {
		if err := ber.CheckBEROpaqueElement(ext, opts...); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
		_, n, _, extErr := ber.DecodeEncodedTLV(ext)
		if extErr != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, extErr)
		}
		if n != len(ext) {
			return nil, fmt.Errorf("encoding extension %d: %w", i, ber.ErrExtraData)
		}
		children = append(children, ext...)
	}
	ber.RecordGeneratedBERContainer(opts, children)
	return ber.EncodeSequence(children)
}
func (v *LCSArea) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// MarshalDER encodes LCSArea to DER format.
// Opaque descendants pass generic DER checks; foreign schema rules need a typed binding.
func (v *LCSArea) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: LCSArea receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	enc_areatype := ber.EncodeEnumerated(int64(v.AreaType))
	retagged_enc_areatype, tagErr_enc_areatype := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_areatype)
	if tagErr_enc_areatype != nil {
		return nil, qualifyBERError(tagErr_enc_areatype, "areaType", "encoding", true)
	}
	enc_areatype = retagged_enc_areatype
	children = append(children, enc_areatype...)
	if len(v.AreaIdentification) < 2 || len(v.AreaIdentification) > 7 {
		if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(nil, "MAP-LCS-DataTypes.Area", ber.RuleRef{Document: "ITU-T X.680", Edition: "02/2021", Clause: "51.5"}), "areaIdentification", "SIZE (2..7)", len(v.AreaIdentification)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_areaidentification, encodeErr_enc_areaidentification := ber.EncodeOctetString([]byte(v.AreaIdentification))
	if encodeErr_enc_areaidentification != nil {
		return nil, qualifyBERError(encodeErr_enc_areaidentification, "areaIdentification", "encoding", true)
	}
	retagged_enc_areaidentification, tagErr_enc_areaidentification := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_areaidentification)
	if tagErr_enc_areaidentification != nil {
		return nil, qualifyBERError(tagErr_enc_areaidentification, "areaIdentification", "encoding", true)
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
		return nil, fmt.Errorf("%s: %w", "encoding LCSArea as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}
func (v *LCSArea) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	encoded, err := v.MarshalDER()
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBER decodes LCSArea from BER/DER format.
func (destination *LCSArea) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if destination == nil {
		return fmt.Errorf("%w: LCSArea destination is nil", ber.ErrInvalidValue)
	}
	var berNextValue_ LCSArea
	v := &berNextValue_
	defer func() {
		if returnErr == nil {
			*destination = *v
		}
	}()

	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	ownedData, ownErr := ber.OwnGeneratedBERInput(data, opts)
	if ownErr != nil {
		return ownErr
	}
	data = ownedData
	preparedData, preparedOptions, prepareErr := ber.PrepareGeneratedBERInput(data, opts)
	if prepareErr != nil {
		return ber.DiagnosePreflight(prepareErr, data, opts, "child", func(probeOpts []ber.DecodeOption) error {
			var probe LCSArea
			return probe.UnmarshalBER(data, probeOpts...)
		})
	}
	data, opts = preparedData, preparedOptions
	opts = ber.LocateDecodedElement(data, "MAP-LCS-DataTypes.Area", opts)
	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
	*v = LCSArea{}
	defer func() {
		if returnErr != nil || !ber.BERNeedsPreservation(opts) {
			return
		}
		v.berReplayNode_ = ber.CaptureGeneratedBERReplay(data, opts)
		returnErr = ber.CompleteGeneratedBERDecode(opts, v, func(base *LCSArea, replayOpts ...ber.EncodeOption) ([]byte, error) {
			return base.MarshalBER(replayOpts...)
		})
	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("%s: %w", "decoding LCSArea SEQUENCE", qualifyBERError(err, "", "decoding", false))
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
	{
		ber.MarkPreflightTarget(opts, "areaType", content[offset:])
		decodedTag_areatype, n_areatype, rawVal_areatype, err := ber.DecodeTLV(content[offset:], opts...)
		if err != nil {
			return qualifyBERError(err, "areaType", "decoding", false)
		}
		if decodedTag_areatype.Class != tag.ClassContextSpecific || decodedTag_areatype.Number != 0 || decodedTag_areatype.Constructed != false {
			return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_areatype), "areaType", "decoding", false)
		}
		decVal_areatype, intErr := ber.DecodeEnumeratedValue(rawVal_areatype)
		if intErr != nil {
			return qualifyBERError(intErr, "areaType", "decoding", false)
		}
		v.AreaType = LCSAreaType(decVal_areatype)
		if offset > len(content) || n_areatype < 0 || n_areatype > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n_areatype
	}
	// Decode areaIdentification
	if offset >= len(content) {
		return fmt.Errorf("missing required field areaIdentification")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 1 {
			return fmt.Errorf("expected tag [%s %d] for areaIdentification, got %s", "CONTEXT", 1, reqTag_)
		}
	}
	{
		ber.MarkPreflightTarget(opts, "areaIdentification", content[offset:])
		decodedTag_areaidentification, n_areaidentification, rawVal_areaidentification, err := ber.DecodeTLV(content[offset:], opts...)
		if err != nil {
			return qualifyBERError(err, "areaIdentification", "decoding", false)
		}
		if decodedTag_areaidentification.Class != tag.ClassContextSpecific || decodedTag_areaidentification.Number != 1 {
			return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_areaidentification), "areaIdentification", "decoding", false)
		}
		decVal_areaidentification, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_areaidentification.Constructed, rawVal_areaidentification, opts...)
		if octetErr != nil {
			return qualifyBERError(octetErr, "areaIdentification", "decoding", false)
		}
		v.AreaIdentification = LCSAreaIdentification(decVal_areaidentification)
		if offset < 0 || offset >
			len(content) || n_areaidentification < 0 || n_areaidentification >
			len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n_areaidentification
		if len(v.AreaIdentification) < 2 || len(v.AreaIdentification) > 7 {
			if constraintErr := ber.CheckDecodedLength(ber.DecodeRule(opts, "MAP-LCS-DataTypes.Area", ber.RuleRef{Document: "ITU-T X.680", Edition: "02/2021", Clause: "51.5"}), "areaIdentification", "SIZE (2..7)", len(v.AreaIdentification)); constraintErr != nil {
				return constraintErr
			}
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
	if v.berReplayNode_ == nil {
		return v.marshalBER(opts...)
	}
	var replayErr error
	opts, replayErr = ber.PrepareBERReplay(v.berReplayNode_, opts, func(mode ber.EncodeOption) ([]byte, error) { return v.MarshalBER([]ber.EncodeOption{mode}...) }, v)
	if replayErr != nil {
		return nil, replayErr
	}
	if replayBytes, ok := ber.PreparedBERReplay(v.berReplayNode_, opts); ok {
		return replayBytes, nil
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBERNode(encoded, v.berReplayNode_, opts), nil
}
func (v *LCSPeriodicLDRInfo) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if !(int64(v.ReportingAmount) >= 1 && int64(v.ReportingAmount) <= 8639999) {
		if constraintErr := ber.CheckEncodedValue(ber.EncodeRule(opts, "MAP-LCS-DataTypes.PeriodicLDRInfo", ber.RuleRef{Document: "ITU-T X.680", Edition: "02/2021", Clause: "51.4"}), "reportingAmount", "(1..8639999)", ber.ObserveInteger(int64(v.ReportingAmount))); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_reportingamount := ber.EncodeInteger(int64(v.ReportingAmount))
	children = append(children, enc_reportingamount...)
	if !(int64(v.ReportingInterval) >= 1 && int64(v.ReportingInterval) <= 8639999) {
		if constraintErr := ber.CheckEncodedValue(ber.EncodeRule(opts, "MAP-LCS-DataTypes.PeriodicLDRInfo", ber.RuleRef{Document: "ITU-T X.680", Edition: "02/2021", Clause: "51.4"}), "reportingInterval", "(1..8639999)", ber.ObserveInteger(int64(v.ReportingInterval))); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_reportinginterval := ber.EncodeInteger(int64(v.ReportingInterval))
	children = append(children, enc_reportinginterval...)
	if v.ReportingOptionMilliseconds != nil {
		enc_reportingoptionmilliseconds, err := v.ReportingOptionMilliseconds.MarshalBER(ber.ChildEncodeOptions(opts, "reportingOptionMilliseconds")...)
		if err != nil {
			return nil, qualifyBERError(err, "reportingOptionMilliseconds", "encoding", false)
		}
		retagged_enc_reportingoptionmilliseconds, tagErr_enc_reportingoptionmilliseconds := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_reportingoptionmilliseconds)
		if tagErr_enc_reportingoptionmilliseconds != nil {
			return nil, qualifyBERError(tagErr_enc_reportingoptionmilliseconds, "reportingOptionMilliseconds", "encoding", false)
		}
		enc_reportingoptionmilliseconds = retagged_enc_reportingoptionmilliseconds
		ber.RecordGeneratedBERChildPlacement(opts, len(children), enc_reportingoptionmilliseconds)
		children = append(children, enc_reportingoptionmilliseconds...)
	}
	for i, ext := range v.ExtData_ {
		if err := ber.CheckBEROpaqueElement(ext, opts...); err != nil {
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
			if constraintErr := ber.CheckEncodedValue(ber.EncodeRule(opts, "MAP-LCS-DataTypes.PeriodicLDRInfo", ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
				return nil, constraintErr
			}
		}
		children = append(children, ext...)
	}
	ber.RecordGeneratedBERContainer(opts, children)
	return ber.EncodeSequence(children)
}
func (v *LCSPeriodicLDRInfo) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// MarshalDER encodes LCSPeriodicLDRInfo to DER format.
// Opaque descendants pass generic DER checks; foreign schema rules need a typed binding.
func (v *LCSPeriodicLDRInfo) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: LCSPeriodicLDRInfo receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if !(int64(v.ReportingAmount) >= 1 && int64(v.ReportingAmount) <= 8639999) {
		if constraintErr := ber.CheckEncodedValue(ber.EncodeRule(nil, "MAP-LCS-DataTypes.PeriodicLDRInfo", ber.RuleRef{Document: "ITU-T X.680", Edition: "02/2021", Clause: "51.4"}), "reportingAmount", "(1..8639999)", ber.ObserveInteger(int64(v.ReportingAmount))); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_reportingamount := ber.EncodeInteger(int64(v.ReportingAmount))
	children = append(children, enc_reportingamount...)
	if !(int64(v.ReportingInterval) >= 1 && int64(v.ReportingInterval) <= 8639999) {
		if constraintErr := ber.CheckEncodedValue(ber.EncodeRule(nil, "MAP-LCS-DataTypes.PeriodicLDRInfo", ber.RuleRef{Document: "ITU-T X.680", Edition: "02/2021", Clause: "51.4"}), "reportingInterval", "(1..8639999)", ber.ObserveInteger(int64(v.ReportingInterval))); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_reportinginterval := ber.EncodeInteger(int64(v.ReportingInterval))
	children = append(children, enc_reportinginterval...)
	if v.ReportingOptionMilliseconds != nil {
		enc_reportingoptionmilliseconds, err := v.ReportingOptionMilliseconds.MarshalDER()
		if err != nil {
			return nil, qualifyBERError(err, "reportingOptionMilliseconds", "encoding", true)
		}
		retagged_enc_reportingoptionmilliseconds, tagErr_enc_reportingoptionmilliseconds := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_reportingoptionmilliseconds)
		if tagErr_enc_reportingoptionmilliseconds != nil {
			return nil, qualifyBERError(tagErr_enc_reportingoptionmilliseconds, "reportingOptionMilliseconds", "encoding", true)
		}
		enc_reportingoptionmilliseconds = retagged_enc_reportingoptionmilliseconds
		children = append(children, enc_reportingoptionmilliseconds...)
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
			if constraintErr := ber.CheckEncodedValue(ber.EncodeRule(nil, "MAP-LCS-DataTypes.PeriodicLDRInfo", ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
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
		return nil, fmt.Errorf("%s: %w", "encoding LCSPeriodicLDRInfo as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}
func (v *LCSPeriodicLDRInfo) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	encoded, err := v.MarshalDER()
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBER decodes LCSPeriodicLDRInfo from BER/DER format.
func (destination *LCSPeriodicLDRInfo) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if destination == nil {
		return fmt.Errorf("%w: LCSPeriodicLDRInfo destination is nil", ber.ErrInvalidValue)
	}
	var berNextValue_ LCSPeriodicLDRInfo
	v := &berNextValue_

	defer func() {
		if returnErr ==
			nil {
			*destination =
				*v
		}
	}()

	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	ownedData, ownErr := ber.OwnGeneratedBERInput(data, opts)
	if ownErr != nil {
		return ownErr
	}
	data = ownedData
	preparedData, preparedOptions, prepareErr := ber.PrepareGeneratedBERInput(data, opts)
	if prepareErr != nil {
		return ber.DiagnosePreflight(prepareErr, data, opts, "child", func(probeOpts []ber.DecodeOption) error {
			var probe LCSPeriodicLDRInfo
			return probe.UnmarshalBER(data, probeOpts...)
		})
	}
	data, opts = preparedData, preparedOptions
	opts = ber.LocateDecodedElement(data, "MAP-LCS-DataTypes.PeriodicLDRInfo", opts)
	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
	*v = LCSPeriodicLDRInfo{}
	defer func() {
		if returnErr != nil || !ber.BERNeedsPreservation(opts) {
			return
		}
		v.berReplayNode_ = ber.CaptureGeneratedBERReplay(data, opts)
		returnErr = ber.CompleteGeneratedBERDecode(opts, v, func(base *LCSPeriodicLDRInfo, replayOpts ...ber.EncodeOption) ([]byte, error) {
			return base.MarshalBER(replayOpts...)
		})
	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("%s: %w", "decoding LCSPeriodicLDRInfo SEQUENCE", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "LCSPeriodicLDRInfo", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode reportingAmount
	if offset >= len(content) {
		return fmt.Errorf("missing required field reportingAmount")
	}
	{
		ber.MarkPreflightTarget(opts, "reportingAmount", content[offset:])
		val_reportingamount, n, err := ber.DecodeInteger(content[offset:], opts...)
		if err != nil {
			return qualifyBERError(err, "reportingAmount", "decoding", false)
		}
		v.ReportingAmount = LCSReportingAmount(val_reportingamount)
		if offset > len(content) || n < 0 || n > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n
		if !(int64(v.ReportingAmount) >= 1 && int64(v.ReportingAmount) <= 8639999) {
			if constraintErr := ber.CheckDecodedValue(ber.DecodeRule(opts, "MAP-LCS-DataTypes.PeriodicLDRInfo", ber.RuleRef{Document: "ITU-T X.680", Edition: "02/2021", Clause: "51.4"}), "reportingAmount", "(1..8639999)", ber.ObserveInteger(int64(v.ReportingAmount))); constraintErr != nil {
				return constraintErr
			}
		}
	}
	// Decode reportingInterval
	if offset >= len(content) {
		return fmt.Errorf("missing required field reportingInterval")
	}
	{
		ber.MarkPreflightTarget(opts, "reportingInterval", content[offset:])
		val_reportinginterval, n, err := ber.DecodeInteger(content[offset:], opts...)
		if err != nil {
			return qualifyBERError(err, "reportingInterval", "decoding", false)
		}
		v.ReportingInterval = LCSReportingInterval(val_reportinginterval)
		if offset < 0 || offset >
			len(content) || n < 0 || n > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n
		if !(int64(v.ReportingInterval) >= 1 && int64(v.ReportingInterval) <= 8639999) {
			if constraintErr := ber.CheckDecodedValue(ber.DecodeRule(opts, "MAP-LCS-DataTypes.PeriodicLDRInfo", ber.RuleRef{Document: "ITU-T X.680", Edition: "02/2021", Clause: "51.4"}), "reportingInterval", "(1..8639999)", ber.ObserveInteger(int64(v.ReportingInterval))); constraintErr != nil {
				return constraintErr
			}
		}
	}
	// Decode reportingOptionMilliseconds
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
				ber.MarkPreflightTarget(opts, "reportingOptionMilliseconds", content[offset:])
				decodedTag_reportingoptionmilliseconds, n_reportingoptionmilliseconds, rawVal_reportingoptionmilliseconds, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "reportingOptionMilliseconds", "decoding", false)
				}
				if decodedTag_reportingoptionmilliseconds.Class != tag.ClassContextSpecific || decodedTag_reportingoptionmilliseconds.Number != 0 || decodedTag_reportingoptionmilliseconds.Constructed != true {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_reportingoptionmilliseconds), "reportingOptionMilliseconds", "decoding", false)
				}
				_ = rawVal_reportingoptionmilliseconds
				if offset < 0 || offset >
					len(content) || n_reportingoptionmilliseconds < 0 || n_reportingoptionmilliseconds >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				reconstructed_reportingoptionmilliseconds, reconstructionErr_reportingoptionmilliseconds := ber.EncodeImplicitTagWithClass(tag.ClassUniversal, tag.TagSequence, content[offset:offset+n_reportingoptionmilliseconds])
				if reconstructionErr_reportingoptionmilliseconds != nil {
					return qualifyBERError(reconstructionErr_reportingoptionmilliseconds, "reportingOptionMilliseconds", "decoding", false)
				}
				var dec_reportingoptionmilliseconds LCSReportingOptionMilliseconds
				if unmErr := dec_reportingoptionmilliseconds.UnmarshalBER(reconstructed_reportingoptionmilliseconds, ber.ChildDecodeOptions(opts, "reportingOptionMilliseconds")...); unmErr != nil {
					return qualifyBERError(unmErr, "reportingOptionMilliseconds", "decoding", false)
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
		peekTag, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:], opts...)
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "LCSPeriodicLDRInfo", Cause: extErr_}
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: the first unknown addition must differ from trailing OPTIONAL/DEFAULT tags.
		if len(v.ExtData_) == 0 && (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0) {
			if !ber.ToleranceEnabled(opts) {
				return &ber.DecodeError{Offset: offset, TypeName: "LCSPeriodicLDRInfo", Cause: fmt.Errorf("%w: repeated or out-of-order SEQUENCE component tag %s", ber.ErrInvalidTag, peekTag)}
			}
			if orderErr_ := ber.CheckDecodedValue(ber.DecodeRule(opts, "MAP-LCS-DataTypes.PeriodicLDRInfo", ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), fmt.Sprintf("ExtData_[%d]", len(v.ExtData_)), "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); orderErr_ != nil {
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

// MarshalBER encodes LCSReportingOptionMilliseconds to BER format.
func (v *LCSReportingOptionMilliseconds) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: LCSReportingOptionMilliseconds receiver is nil", ber.ErrInvalidValue)
	}
	if v.berReplayNode_ == nil {
		return v.marshalBER(opts...)
	}
	var replayErr error
	opts, replayErr = ber.PrepareBERReplay(v.berReplayNode_, opts, func(mode ber.EncodeOption) ([]byte, error) { return v.MarshalBER([]ber.EncodeOption{mode}...) }, v)
	if replayErr != nil {
		return nil, replayErr
	}
	if replayBytes, ok := ber.PreparedBERReplay(v.berReplayNode_, opts); ok {
		return replayBytes, nil
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBERNode(encoded, v.berReplayNode_, opts), nil
}
func (v *LCSReportingOptionMilliseconds) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if !(int64(v.ReportingAmountMilliseconds) >= 1 && int64(v.ReportingAmountMilliseconds) <= 8639999000) {
		if constraintErr := ber.CheckEncodedValue(ber.EncodeRule(opts, "MAP-LCS-DataTypes.ReportingOptionMilliseconds", ber.RuleRef{Document: "ITU-T X.680", Edition: "02/2021", Clause: "51.4"}), "reportingAmountMilliseconds", "(1..8639999000)", ber.ObserveInteger(int64(v.ReportingAmountMilliseconds))); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_reportingamountmilliseconds := ber.EncodeInteger(int64(v.ReportingAmountMilliseconds))
	children = append(children, enc_reportingamountmilliseconds...)
	if !(int64(v.ReportingIntervalMilliseconds) >= 1 && int64(v.ReportingIntervalMilliseconds) <= 999) {
		if constraintErr := ber.CheckEncodedValue(ber.EncodeRule(opts, "MAP-LCS-DataTypes.ReportingOptionMilliseconds", ber.RuleRef{Document: "ITU-T X.680", Edition: "02/2021", Clause: "51.4"}), "reportingIntervalMilliseconds", "(1..999)", ber.ObserveInteger(int64(v.ReportingIntervalMilliseconds))); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_reportingintervalmilliseconds := ber.EncodeInteger(int64(v.ReportingIntervalMilliseconds))
	children = append(children, enc_reportingintervalmilliseconds...)
	for i, ext := range v.ExtData_ {
		if err := ber.CheckBEROpaqueElement(ext, opts...); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
		_, n, _, extErr := ber.DecodeEncodedTLV(ext)
		if extErr != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, extErr)
		}
		if n != len(ext) {
			return nil, fmt.Errorf("encoding extension %d: %w", i, ber.ErrExtraData)
		}
		children = append(children, ext...)
	}
	ber.RecordGeneratedBERContainer(opts, children)
	return ber.EncodeSequence(children)
}
func (v *LCSReportingOptionMilliseconds) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// MarshalDER encodes LCSReportingOptionMilliseconds to DER format.
// Opaque descendants pass generic DER checks; foreign schema rules need a typed binding.
func (v *LCSReportingOptionMilliseconds) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: LCSReportingOptionMilliseconds receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if !(int64(v.ReportingAmountMilliseconds) >= 1 && int64(v.ReportingAmountMilliseconds) <= 8639999000) {
		if constraintErr := ber.CheckEncodedValue(ber.EncodeRule(nil, "MAP-LCS-DataTypes.ReportingOptionMilliseconds", ber.RuleRef{Document: "ITU-T X.680", Edition: "02/2021", Clause: "51.4"}), "reportingAmountMilliseconds", "(1..8639999000)", ber.ObserveInteger(int64(v.ReportingAmountMilliseconds))); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_reportingamountmilliseconds := ber.EncodeInteger(int64(v.ReportingAmountMilliseconds))
	children = append(children, enc_reportingamountmilliseconds...)
	if !(int64(v.ReportingIntervalMilliseconds) >= 1 && int64(v.ReportingIntervalMilliseconds) <= 999) {
		if constraintErr := ber.CheckEncodedValue(ber.EncodeRule(nil, "MAP-LCS-DataTypes.ReportingOptionMilliseconds", ber.RuleRef{Document: "ITU-T X.680", Edition: "02/2021", Clause: "51.4"}), "reportingIntervalMilliseconds", "(1..999)", ber.ObserveInteger(int64(v.ReportingIntervalMilliseconds))); constraintErr != nil {
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
		return nil, fmt.Errorf("%s: %w", "encoding LCSReportingOptionMilliseconds as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}
func (v *LCSReportingOptionMilliseconds) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	encoded, err := v.MarshalDER()
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBER decodes LCSReportingOptionMilliseconds from BER/DER format.
func (destination *LCSReportingOptionMilliseconds) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if destination == nil {
		return fmt.Errorf("%w: LCSReportingOptionMilliseconds destination is nil", ber.ErrInvalidValue)
	}
	var berNextValue_ LCSReportingOptionMilliseconds
	v :=

		&berNextValue_
	defer func() {
		if returnErr ==
			nil {
			*destination = *v
		}
	}()

	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	ownedData, ownErr := ber.OwnGeneratedBERInput(data, opts)
	if ownErr != nil {
		return ownErr
	}
	data = ownedData
	preparedData, preparedOptions, prepareErr := ber.PrepareGeneratedBERInput(data, opts)
	if prepareErr != nil {
		return ber.DiagnosePreflight(prepareErr, data, opts, "child", func(probeOpts []ber.DecodeOption) error {
			var probe LCSReportingOptionMilliseconds
			return probe.UnmarshalBER(data, probeOpts...)
		})
	}
	data, opts = preparedData, preparedOptions
	opts = ber.LocateDecodedElement(data, "MAP-LCS-DataTypes.ReportingOptionMilliseconds", opts)
	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
	*v = LCSReportingOptionMilliseconds{}
	defer func() {
		if returnErr != nil || !ber.BERNeedsPreservation(opts) {
			return
		}
		v.berReplayNode_ = ber.CaptureGeneratedBERReplay(data, opts)
		returnErr = ber.CompleteGeneratedBERDecode(opts, v, func(base *LCSReportingOptionMilliseconds, replayOpts ...ber.EncodeOption) ([]byte, error) {
			return base.MarshalBER(replayOpts...)
		})
	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("%s: %w", "decoding LCSReportingOptionMilliseconds SEQUENCE", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "LCSReportingOptionMilliseconds", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode reportingAmountMilliseconds
	if offset >= len(content) {
		return fmt.Errorf("missing required field reportingAmountMilliseconds")
	}
	{
		ber.MarkPreflightTarget(opts, "reportingAmountMilliseconds", content[offset:])
		val_reportingamountmilliseconds, n, err := ber.DecodeInteger(content[offset:], opts...)
		if err != nil {
			return qualifyBERError(err, "reportingAmountMilliseconds", "decoding", false)
		}
		v.ReportingAmountMilliseconds = LCSReportingAmountMilliseconds(val_reportingamountmilliseconds)
		if offset > len(content) || n < 0 || n > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n
		if !(int64(v.ReportingAmountMilliseconds) >= 1 && int64(v.ReportingAmountMilliseconds) <= 8639999000) {
			if constraintErr := ber.CheckDecodedValue(ber.DecodeRule(opts, "MAP-LCS-DataTypes.ReportingOptionMilliseconds", ber.RuleRef{Document: "ITU-T X.680", Edition: "02/2021", Clause: "51.4"}), "reportingAmountMilliseconds", "(1..8639999000)", ber.ObserveInteger(int64(v.ReportingAmountMilliseconds))); constraintErr != nil {
				return constraintErr
			}
		}
	}
	// Decode reportingIntervalMilliseconds
	if offset >= len(content) {
		return fmt.Errorf("missing required field reportingIntervalMilliseconds")
	}
	{
		ber.MarkPreflightTarget(opts, "reportingIntervalMilliseconds", content[offset:])
		val_reportingintervalmilliseconds, n, err := ber.DecodeInteger(content[offset:], opts...)
		if err != nil {
			return qualifyBERError(err, "reportingIntervalMilliseconds", "decoding", false)
		}
		v.ReportingIntervalMilliseconds = LCSReportingIntervalMilliseconds(val_reportingintervalmilliseconds)
		if offset < 0 || offset >
			len(content) || n < 0 || n > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n
		if !(int64(v.ReportingIntervalMilliseconds) >= 1 && int64(v.ReportingIntervalMilliseconds) <= 999) {
			if constraintErr := ber.CheckDecodedValue(ber.DecodeRule(opts, "MAP-LCS-DataTypes.ReportingOptionMilliseconds", ber.RuleRef{Document: "ITU-T X.680", Edition: "02/2021", Clause: "51.4"}), "reportingIntervalMilliseconds", "(1..999)", ber.ObserveInteger(int64(v.ReportingIntervalMilliseconds))); constraintErr != nil {
				return constraintErr
			}
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
	if v.berReplayNode_ == nil {
		return v.marshalBER(opts...)
	}
	var replayErr error
	opts, replayErr = ber.PrepareBERReplay(v.berReplayNode_, opts, func(mode ber.EncodeOption) ([]byte, error) { return v.MarshalBER([]ber.EncodeOption{mode}...) }, v)
	if replayErr != nil {
		return nil, replayErr
	}
	if replayBytes, ok := ber.PreparedBERReplay(v.berReplayNode_, opts); ok {
		return replayBytes, nil
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBERNode(encoded, v.berReplayNode_, opts), nil
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
			return nil, qualifyBERError(tagErr_enc_plmnlistprioritized, "plmn-ListPrioritized", "encoding", false)
		}
		enc_plmnlistprioritized = retagged_enc_plmnlistprioritized
		children = append(children, enc_plmnlistprioritized...)
	}
	if v.PlmnList == nil {
		return nil, qualifyBERError(fmt.Errorf("%w: required collection is nil", ber.ErrInvalidValue), "plmn-List", "encoding", false)
	}
	if len((v.PlmnList).Values) < 1 || len((v.PlmnList).Values) > 20 {
		if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(opts, "MAP-LCS-DataTypes.ReportingPLMNList", ber.RuleRef{Document: "ITU-T X.680", Edition: "02/2021", Clause: "51.5"}), "plmn-List", "SIZE (1..20)", len((v.PlmnList).Values)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_plmnlist, err := MarshalBERLCSPLMNList(v.PlmnList, ber.ParentCollectionSizeEncodeOptions(ber.ChildEncodeOptions(opts, "plmn-List"))...)
	if err != nil {
		return nil, qualifyBERError(err, "plmn-List", "encoding", false)
	}
	if ber.BERReplayEnabled(opts) && v.berPlmnListIndef_ {
		// Strip the outer SEQUENCE tag from marshalBER output to get raw children.
		_, _, seqContent_, tlvErr_ := ber.DecodeEncodedTLV(enc_plmnlist)
		if tlvErr_ != nil {
			return nil, tlvErr_
		}
		{
			var encodeErr error
			enc_plmnlist, encodeErr = ber.EncodeConstructedIndefinite(tag.Tag{Class: tag.ClassContextSpecific, Number: 1}, seqContent_)
			if encodeErr != nil {
				return nil, qualifyBERError(encodeErr, "plmn-List", "encoding", false)
			}
		}
	} else {
		retagged_enc_plmnlist, tagErr_enc_plmnlist := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_plmnlist)
		if tagErr_enc_plmnlist != nil {
			return nil, qualifyBERError(tagErr_enc_plmnlist, "plmn-List", "encoding", false)
		}
		enc_plmnlist = retagged_enc_plmnlist
	}
	ber.RecordGeneratedBERChildPlacement(opts, len(children), enc_plmnlist)
	children = append(children, enc_plmnlist...)
	for i, ext := range v.ExtData_ {
		if err := ber.CheckBEROpaqueElement(ext, opts...); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
		_, n, _, extErr := ber.DecodeEncodedTLV(ext)
		if extErr != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, extErr)
		}
		if n != len(ext) {
			return nil, fmt.Errorf("encoding extension %d: %w", i, ber.ErrExtraData)
		}
		children = append(children, ext...)
	}
	ber.RecordGeneratedBERContainer(opts, children)
	return ber.EncodeSequence(children)
}
func (v *LCSReportingPLMNList) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// MarshalDER encodes LCSReportingPLMNList to DER format.
// Opaque descendants pass generic DER checks; foreign schema rules need a typed binding.
func (v *LCSReportingPLMNList) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: LCSReportingPLMNList receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if v.PlmnListPrioritized != nil {
		enc_plmnlistprioritized := ber.EncodeNull()
		retagged_enc_plmnlistprioritized, tagErr_enc_plmnlistprioritized := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_plmnlistprioritized)
		if tagErr_enc_plmnlistprioritized != nil {
			return nil, qualifyBERError(tagErr_enc_plmnlistprioritized, "plmn-ListPrioritized", "encoding", true)
		}
		enc_plmnlistprioritized = retagged_enc_plmnlistprioritized
		children = append(children, enc_plmnlistprioritized...)
	}
	if v.PlmnList == nil {
		return nil, qualifyBERError(fmt.Errorf("%w: required collection is nil", ber.ErrInvalidValue), "plmn-List", "encoding", true)
	}
	if len((v.PlmnList).Values) < 1 || len((v.PlmnList).Values) > 20 {
		if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(nil, "MAP-LCS-DataTypes.ReportingPLMNList", ber.RuleRef{Document: "ITU-T X.680", Edition: "02/2021", Clause: "51.5"}), "plmn-List", "SIZE (1..20)", len((v.PlmnList).Values)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_plmnlist, err := MarshalDERLCSPLMNList(v.PlmnList)
	if err != nil {
		return nil, qualifyBERError(err, "plmn-List", "encoding", true)
	}
	retagged_enc_plmnlist, tagErr_enc_plmnlist := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_plmnlist)
	if tagErr_enc_plmnlist != nil {
		return nil, qualifyBERError(tagErr_enc_plmnlist, "plmn-List", "encoding", true)
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
		return nil, fmt.Errorf("%s: %w", "encoding LCSReportingPLMNList as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}
func (v *LCSReportingPLMNList) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	encoded, err := v.MarshalDER()
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBER decodes LCSReportingPLMNList from BER/DER format.
func (destination *LCSReportingPLMNList) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if destination == nil {
		return fmt.Errorf("%w: LCSReportingPLMNList destination is nil", ber.ErrInvalidValue)
	}
	var berNextValue_ LCSReportingPLMNList
	v := &berNextValue_

	defer func() {
		if returnErr ==
			nil {
			*destination = *v
		}
	}()

	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	ownedData, ownErr := ber.OwnGeneratedBERInput(data, opts)
	if ownErr != nil {
		return ownErr
	}
	data = ownedData
	preparedData, preparedOptions, prepareErr := ber.PrepareGeneratedBERInput(data, opts)
	if prepareErr != nil {
		return ber.DiagnosePreflight(prepareErr, data, opts, "child", func(probeOpts []ber.DecodeOption) error {
			var probe LCSReportingPLMNList
			return probe.UnmarshalBER(data, probeOpts...)
		})
	}
	data, opts = preparedData, preparedOptions
	opts = ber.LocateDecodedElement(data, "MAP-LCS-DataTypes.ReportingPLMNList", opts)
	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
	*v = LCSReportingPLMNList{}
	defer func() {
		if returnErr != nil || !ber.BERNeedsPreservation(opts) {
			return
		}
		v.berReplayNode_ = ber.CaptureGeneratedBERReplay(data, opts)
		returnErr = ber.CompleteGeneratedBERDecode(opts, v, func(base *LCSReportingPLMNList, replayOpts ...ber.EncodeOption) ([]byte, error) {
			return base.MarshalBER(replayOpts...)
		})
	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("%s: %w", "decoding LCSReportingPLMNList SEQUENCE", qualifyBERError(err, "", "decoding", false))
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
				ber.MarkPreflightTarget(opts, "plmn-ListPrioritized", content[offset:])
				decodedTag_plmnlistprioritized, n_plmnlistprioritized, rawVal_plmnlistprioritized, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "plmn-ListPrioritized", "decoding", false)
				}
				if decodedTag_plmnlistprioritized.Class != tag.ClassContextSpecific || decodedTag_plmnlistprioritized.Number != 0 || decodedTag_plmnlistprioritized.Constructed != false {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_plmnlistprioritized), "plmn-ListPrioritized", "decoding", false)
				}
				if len(rawVal_plmnlistprioritized) != 0 {
					return qualifyBERError(fmt.Errorf("%w: NULL content length %d", ber.ErrInvalidValue, len(rawVal_plmnlistprioritized)), "plmn-ListPrioritized", "decoding", false)
				}
				v.PlmnListPrioritized = &struct{}{}
				if offset > len(content) || n_plmnlistprioritized < 0 || n_plmnlistprioritized > len(content[offset:]) {
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
	{
		v.berPlmnListIndef_ = false
		ber.MarkPreflightTarget(opts, "plmn-List", content[offset:])
		decodedTag_plmnlist, n_plmnlist, rawVal_plmnlist, err := ber.DecodeTLV(content[offset:], opts...)
		if err != nil {
			return qualifyBERError(err, "plmn-List", "decoding", false)
		}
		if decodedTag_plmnlist.Class != tag.ClassContextSpecific || decodedTag_plmnlist.Number != 1 || decodedTag_plmnlist.Constructed != true {
			return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_plmnlist), "plmn-List", "decoding", false)
		}
		_ = rawVal_plmnlist
		if offset < 0 || offset >
			len(content) || n_plmnlist < 0 || n_plmnlist > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		reconstructed_plmnlist, reconstructionErr_plmnlist := ber.EncodeImplicitTagWithClass(tag.ClassUniversal, tag.TagSequence, content[offset:offset+n_plmnlist])
		if reconstructionErr_plmnlist != nil {
			return qualifyBERError(reconstructionErr_plmnlist, "plmn-List", "decoding", false)
		}
		dec_plmnlist, unmErr := UnmarshalBERLCSPLMNList(reconstructed_plmnlist, ber.ParentCollectionSizeDecodeOptions(ber.ChildDecodeOptions(opts, "plmn-List"))...)
		if unmErr != nil {
			return qualifyBERError(unmErr, "plmn-List", "decoding", false)
		}
		v.PlmnList = dec_plmnlist
		{
			_, tagSz_, _ := ber.DecodeTag(content[offset:])
			if offset < 0 || offset >
				len(content) || tagSz_ < 0 || tagSz_ > len(content[offset:]) {
				return fmt.Errorf("invalid BER content window")
			}

			if offset+tagSz_ < len(content) && content[offset+tagSz_] == 0x80 {
				v.berPlmnListIndef_ = true
			}
		}
		if offset < 0 || offset >
			len(content) || n_plmnlist < 0 || n_plmnlist > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n_plmnlist
		if len((v.PlmnList).Values) < 1 || len((v.PlmnList).Values) > 20 {
			if constraintErr := ber.CheckDecodedLength(ber.DecodeRule(opts, "MAP-LCS-DataTypes.ReportingPLMNList", ber.RuleRef{Document: "ITU-T X.680", Edition: "02/2021", Clause: "51.5"}), "plmn-List", "SIZE (1..20)", len((v.PlmnList).Values)); constraintErr != nil {
				return constraintErr
			}
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
	if collection.berReplayNode_ == nil {
		return marshalBERLCSPLMNList(collection, opts...)
	}
	var replayErr error
	opts, replayErr = ber.PrepareBERReplay(collection.berReplayNode_, opts, func(mode ber.EncodeOption) ([]byte, error) {
		return MarshalBERLCSPLMNList(collection, []ber.EncodeOption{mode}...)
	}, collection)
	if replayErr != nil {
		return nil, replayErr
	}
	if replayBytes, ok := ber.PreparedBERReplay(collection.berReplayNode_, opts); ok {
		return replayBytes, nil
	}
	encoded, err := marshalBERLCSPLMNList(collection, opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBERNode(encoded, collection.berReplayNode_, opts), nil
}
func marshalBERLCSPLMNList(collection *LCSPLMNList, opts ...ber.EncodeOption) ([]byte, error) {
	list := collection.Values
	if len(list) < 1 || len(list) > 20 {
		if constraintErr := ber.CheckEncodedCollectionLength(ber.EncodeRule(opts, "MAP-LCS-DataTypes.marshalBERLCSPLMNList", ber.RuleRef{Document: "ITU-T X.680", Edition: "02/2021", Clause: "51.5"}), "PLMNList", "SIZE (1..20)", len(list)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	var children []byte
	for elemIndex := range list {
		_ = elemIndex
		elem := &list[elemIndex]
		enc, err := elem.MarshalBER(ber.ChildEncodeOptions(opts, fmt.Sprintf("element[%d]", elemIndex))...)
		if err != nil {
			return nil, qualifyBERError(err, fmt.Sprintf("element[%d]",
				elemIndex),

				"encoding", false)
		}
		children = append(children, enc...)
		ber.RecordGeneratedBERChildPlacement(opts, len(children)-len(enc), enc)
	}
	ber.RecordGeneratedBERContainer(opts, children)
	return ber.EncodeSequence(children)
}

func appendBERLinearLCSPLMNList(encoder *ber.LinearEncoder, collection *LCSPLMNList, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := MarshalBERLCSPLMNList(collection, opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// MarshalDERLCSPLMNList encodes a LCSPLMNList list to DER.
func MarshalDERLCSPLMNList(collection *LCSPLMNList) ([]byte, error) {
	if collection == nil {
		return nil, fmt.Errorf("%w: required collection is nil", ber.ErrInvalidValue)
	}
	list := collection.Values
	if len(list) < 1 || len(list) > 20 {
		if constraintErr := ber.CheckEncodedCollectionLength(ber.EncodeRule(nil, "MAP-LCS-DataTypes.PLMNList", ber.RuleRef{Document: "ITU-T X.680", Edition: "02/2021", Clause: "51.5"}), "PLMNList", "SIZE (1..20)", len(list)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	var children []byte
	for elemIndex := range list {
		_ = elemIndex
		elem := &list[elemIndex]
		enc, err := elem.MarshalDER()
		if err != nil {
			return nil, qualifyBERError(err, fmt.Sprintf("element[%d]",
				elemIndex),

				"encoding", true)
		}
		children = append(children, enc...)
	}
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("%s: %w", "encoding LCSPLMNList as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}

func appendDERLinearLCSPLMNList(encoder *ber.LinearEncoder, collection *LCSPLMNList) ([]byte, error) {
	encoded, err := MarshalDERLCSPLMNList(collection)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBERLCSPLMNList decodes a LCSPLMNList list from BER.
func UnmarshalBERLCSPLMNList(data []byte, opts ...ber.DecodeOption) (returnValue *LCSPLMNList, returnErr error) {
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	ownedData, ownErr := ber.OwnGeneratedBERInput(data, opts)
	if ownErr != nil {
		return nil, ownErr
	}
	data = ownedData
	preparedData, preparedOptions, prepareErr := ber.PrepareGeneratedBERInput(data, opts)
	if prepareErr != nil {
		return nil, ber.DiagnosePreflight(prepareErr, data, opts, "element", func(probeOpts []ber.DecodeOption) error {
			_, probeErr := UnmarshalBERLCSPLMNList(data, probeOpts...)
			return probeErr
		})
	}
	data, opts = preparedData, preparedOptions
	opts = ber.LocateDecodedElement(data, "MAP-LCS-DataTypes.PLMNList", opts)
	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", "decoding LCSPLMNList", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return nil, &ber.DecodeError{Offset: total, TypeName: "LCSPLMNList", Cause: ber.ErrExtraData}
	}
	var result []LCSReportingPLMN
	offset := 0
	for offset < len(content) {
		elementIndex := len(result)
		_ = elementIndex
		elementData := content[offset:]
		ber.MarkPreflightElement(opts, elementIndex, elementData)
		var elem LCSReportingPLMN
		_, n, _, tlvErr := ber.DecodeTLV(elementData, opts...)
		if tlvErr != nil {
			return nil, qualifyBERError(tlvErr, fmt.Sprintf("element[%d]",
				elementIndex),

				"decoding", false)
		}
		if unmErr := elem.UnmarshalBER(elementData[:n], ber.ChildDecodeIndexOptions(opts, len(result))...); unmErr != nil {
			return nil, qualifyBERError(unmErr, fmt.Sprintf("element[%d]",
				elementIndex),

				"decoding", false)
		}
		result = append(result, elem)
		if offset < 0 || offset >
			len(content) || n < 0 || n > len(content[offset:]) {
			return nil, fmt.Errorf("invalid BER content window")
		}

		offset += n
	}
	if len(result) < 1 || len(result) > 20 {
		if constraintErr := ber.CheckDecodedCollectionLength(ber.DecodeRule(opts, "MAP-LCS-DataTypes.PLMNList", ber.RuleRef{Document: "ITU-T X.680", Edition: "02/2021", Clause: "51.5"}), "PLMNList", "SIZE (1..20)", len(result)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	decoded := &LCSPLMNList{Values: result}
	if ber.BERNeedsPreservation(opts) {
		decoded.berReplayNode_ = ber.CaptureGeneratedBERReplay(data, opts)
		if replayErr := ber.CompleteGeneratedBERDecode(opts, decoded, func(base *LCSPLMNList, replayOpts ...ber.EncodeOption) ([]byte, error) {
			return MarshalBERLCSPLMNList(base, replayOpts...)
		}); replayErr != nil {
			return nil, replayErr
		}
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
	if v.berReplayNode_ == nil {
		return v.marshalBER(opts...)
	}
	var replayErr error
	opts, replayErr = ber.PrepareBERReplay(v.berReplayNode_, opts, func(mode ber.EncodeOption) ([]byte, error) { return v.MarshalBER([]ber.EncodeOption{mode}...) }, v)
	if replayErr != nil {
		return nil, replayErr
	}
	if replayBytes, ok := ber.PreparedBERReplay(v.berReplayNode_, opts); ok {
		return replayBytes, nil
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBERNode(encoded, v.berReplayNode_, opts), nil
}
func (v *LCSReportingPLMN) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if len(v.PlmnId) < 3 || len(v.PlmnId) > 3 {
		if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(opts, "MAP-LCS-DataTypes.ReportingPLMN", ber.RuleRef{Document: "ITU-T X.680", Edition: "02/2021", Clause: "51.5"}), "plmn-Id", "SIZE (3)", len(v.PlmnId)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_plmnid, encodeErr_enc_plmnid := ber.EncodeOctetString([]byte(v.PlmnId))
	if encodeErr_enc_plmnid != nil {
		return nil, qualifyBERError(encodeErr_enc_plmnid, "plmn-Id", "encoding", false)
	}
	retagged_enc_plmnid, tagErr_enc_plmnid := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_plmnid)
	if tagErr_enc_plmnid != nil {
		return nil, qualifyBERError(tagErr_enc_plmnid, "plmn-Id", "encoding", false)
	}
	enc_plmnid = retagged_enc_plmnid
	children = append(children, enc_plmnid...)
	if v.RanTechnology != nil {
		enc_rantechnology := ber.EncodeEnumerated(int64(*v.RanTechnology))
		retagged_enc_rantechnology, tagErr_enc_rantechnology := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_rantechnology)
		if tagErr_enc_rantechnology != nil {
			return nil, qualifyBERError(tagErr_enc_rantechnology, "ran-Technology", "encoding", false)
		}
		enc_rantechnology = retagged_enc_rantechnology
		children = append(children, enc_rantechnology...)
	}
	if v.RanPeriodicLocationSupport != nil {
		enc_ranperiodiclocationsupport := ber.EncodeNull()
		retagged_enc_ranperiodiclocationsupport, tagErr_enc_ranperiodiclocationsupport := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_ranperiodiclocationsupport)
		if tagErr_enc_ranperiodiclocationsupport != nil {
			return nil, qualifyBERError(tagErr_enc_ranperiodiclocationsupport, "ran-PeriodicLocationSupport", "encoding", false)
		}
		enc_ranperiodiclocationsupport = retagged_enc_ranperiodiclocationsupport
		children = append(children, enc_ranperiodiclocationsupport...)
	}
	for i, ext := range v.ExtData_ {
		if err := ber.CheckBEROpaqueElement(ext, opts...); err != nil {
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
		if i == 0 && ((peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1)) {
			if constraintErr := ber.CheckEncodedValue(ber.EncodeRule(opts, "MAP-LCS-DataTypes.ReportingPLMN", ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
				return nil, constraintErr
			}
		}
		children = append(children, ext...)
	}
	ber.RecordGeneratedBERContainer(opts, children)
	return ber.EncodeSequence(children)
}
func (v *LCSReportingPLMN) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// MarshalDER encodes LCSReportingPLMN to DER format.
// Opaque descendants pass generic DER checks; foreign schema rules need a typed binding.
func (v *LCSReportingPLMN) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: LCSReportingPLMN receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if len(v.PlmnId) < 3 || len(v.PlmnId) > 3 {
		if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(nil, "MAP-LCS-DataTypes.ReportingPLMN", ber.RuleRef{Document: "ITU-T X.680", Edition: "02/2021", Clause: "51.5"}), "plmn-Id", "SIZE (3)", len(v.PlmnId)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_plmnid, encodeErr_enc_plmnid := ber.EncodeOctetString([]byte(v.PlmnId))
	if encodeErr_enc_plmnid != nil {
		return nil, qualifyBERError(encodeErr_enc_plmnid, "plmn-Id", "encoding", true)
	}
	retagged_enc_plmnid, tagErr_enc_plmnid := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_plmnid)
	if tagErr_enc_plmnid != nil {
		return nil, qualifyBERError(tagErr_enc_plmnid, "plmn-Id", "encoding", true)
	}
	enc_plmnid = retagged_enc_plmnid
	children = append(children, enc_plmnid...)
	if v.RanTechnology != nil {
		enc_rantechnology := ber.EncodeEnumerated(int64(*v.RanTechnology))
		retagged_enc_rantechnology, tagErr_enc_rantechnology := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_rantechnology)
		if tagErr_enc_rantechnology != nil {
			return nil, qualifyBERError(tagErr_enc_rantechnology, "ran-Technology", "encoding", true)
		}
		enc_rantechnology = retagged_enc_rantechnology
		children = append(children, enc_rantechnology...)
	}
	if v.RanPeriodicLocationSupport != nil {
		enc_ranperiodiclocationsupport := ber.EncodeNull()
		retagged_enc_ranperiodiclocationsupport, tagErr_enc_ranperiodiclocationsupport := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_ranperiodiclocationsupport)
		if tagErr_enc_ranperiodiclocationsupport != nil {
			return nil, qualifyBERError(tagErr_enc_ranperiodiclocationsupport, "ran-PeriodicLocationSupport", "encoding", true)
		}
		enc_ranperiodiclocationsupport = retagged_enc_ranperiodiclocationsupport
		children = append(children, enc_ranperiodiclocationsupport...)
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
		if i == 0 && ((peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1)) {
			if constraintErr := ber.CheckEncodedValue(ber.EncodeRule(nil, "MAP-LCS-DataTypes.ReportingPLMN", ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
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
		return nil, fmt.Errorf("%s: %w", "encoding LCSReportingPLMN as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}
func (v *LCSReportingPLMN) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	encoded, err := v.MarshalDER()
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBER decodes LCSReportingPLMN from BER/DER format.
func (destination *LCSReportingPLMN) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if destination == nil {
		return fmt.Errorf("%w: LCSReportingPLMN destination is nil", ber.ErrInvalidValue)
	}
	var berNextValue_ LCSReportingPLMN
	v := &berNextValue_

	defer func() {
		if returnErr == nil {
			*destination = *v
		}
	}()

	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	ownedData, ownErr := ber.OwnGeneratedBERInput(data, opts)
	if ownErr != nil {
		return ownErr
	}
	data = ownedData
	preparedData, preparedOptions, prepareErr := ber.PrepareGeneratedBERInput(data, opts)
	if prepareErr != nil {
		return ber.DiagnosePreflight(prepareErr, data, opts, "child", func(probeOpts []ber.DecodeOption) error {
			var probe LCSReportingPLMN
			return probe.UnmarshalBER(data, probeOpts...)
		})
	}
	data, opts = preparedData, preparedOptions
	opts = ber.LocateDecodedElement(data, "MAP-LCS-DataTypes.ReportingPLMN", opts)
	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
	*v = LCSReportingPLMN{}
	defer func() {
		if returnErr != nil || !ber.BERNeedsPreservation(opts) {
			return
		}
		v.berReplayNode_ = ber.CaptureGeneratedBERReplay(data, opts)
		returnErr = ber.CompleteGeneratedBERDecode(opts, v, func(base *LCSReportingPLMN, replayOpts ...ber.EncodeOption) ([]byte, error) {
			return base.MarshalBER(replayOpts...)
		})
	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("%s: %w", "decoding LCSReportingPLMN SEQUENCE", qualifyBERError(err, "", "decoding", false))
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
	{
		ber.MarkPreflightTarget(opts, "plmn-Id", content[offset:])
		decodedTag_plmnid, n_plmnid, rawVal_plmnid, err := ber.DecodeTLV(content[offset:], opts...)
		if err != nil {
			return qualifyBERError(err, "plmn-Id", "decoding", false)
		}
		if decodedTag_plmnid.Class != tag.ClassContextSpecific || decodedTag_plmnid.Number != 0 {
			return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_plmnid), "plmn-Id", "decoding", false)
		}
		decVal_plmnid, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_plmnid.Constructed, rawVal_plmnid, opts...)
		if octetErr != nil {
			return qualifyBERError(octetErr, "plmn-Id", "decoding", false)
		}
		v.PlmnId = v21_map_commondatatypes.CommonDataTypesPLMNId(decVal_plmnid)
		if offset > len(content) || n_plmnid < 0 || n_plmnid > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n_plmnid
		if len(v.PlmnId) < 3 || len(v.PlmnId) > 3 {
			if constraintErr := ber.CheckDecodedLength(ber.DecodeRule(opts, "MAP-LCS-DataTypes.ReportingPLMN", ber.RuleRef{Document: "ITU-T X.680", Edition: "02/2021", Clause: "51.5"}), "plmn-Id", "SIZE (3)", len(v.PlmnId)); constraintErr != nil {
				return constraintErr
			}
		}
	}
	// Decode ran-Technology
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
				ber.MarkPreflightTarget(opts, "ran-Technology", content[offset:])
				decodedTag_rantechnology, n_rantechnology, rawVal_rantechnology, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "ran-Technology", "decoding", false)
				}
				if decodedTag_rantechnology.Class != tag.ClassContextSpecific || decodedTag_rantechnology.Number != 1 || decodedTag_rantechnology.Constructed != false {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_rantechnology), "ran-Technology", "decoding", false)
				}
				decVal_rantechnology, intErr := ber.DecodeEnumeratedValue(rawVal_rantechnology)
				if intErr != nil {
					return qualifyBERError(intErr, "ran-Technology", "decoding", false)
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
				ber.MarkPreflightTarget(opts, "ran-PeriodicLocationSupport", content[offset:])
				decodedTag_ranperiodiclocationsupport, n_ranperiodiclocationsupport, rawVal_ranperiodiclocationsupport, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "ran-PeriodicLocationSupport", "decoding", false)
				}
				if decodedTag_ranperiodiclocationsupport.Class != tag.ClassContextSpecific || decodedTag_ranperiodiclocationsupport.Number != 2 || decodedTag_ranperiodiclocationsupport.Constructed != false {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_ranperiodiclocationsupport), "ran-PeriodicLocationSupport", "decoding", false)
				}
				if len(rawVal_ranperiodiclocationsupport) != 0 {
					return qualifyBERError(fmt.Errorf("%w: NULL content length %d", ber.ErrInvalidValue, len(rawVal_ranperiodiclocationsupport)), "ran-PeriodicLocationSupport", "decoding", false)
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
		peekTag, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:], opts...)
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "LCSReportingPLMN", Cause: extErr_}
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: the first unknown addition must differ from trailing OPTIONAL/DEFAULT tags.
		if len(v.ExtData_) == 0 && ((peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1)) {
			if !ber.ToleranceEnabled(opts) {
				return &ber.DecodeError{Offset: offset, TypeName: "LCSReportingPLMN", Cause: fmt.Errorf("%w: repeated or out-of-order SEQUENCE component tag %s", ber.ErrInvalidTag, peekTag)}
			}
			if orderErr_ := ber.CheckDecodedValue(ber.DecodeRule(opts, "MAP-LCS-DataTypes.ReportingPLMN", ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), fmt.Sprintf("ExtData_[%d]", len(v.ExtData_)), "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); orderErr_ != nil {
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

// MarshalBER encodes LCSProvideSubscriberLocationRes to BER format.
func (v *LCSProvideSubscriberLocationRes) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: LCSProvideSubscriberLocationRes receiver is nil", ber.ErrInvalidValue)
	}
	if v.berReplayNode_ == nil {
		return v.marshalBER(opts...)
	}
	var replayErr error
	opts, replayErr = ber.PrepareBERReplay(v.berReplayNode_, opts, func(mode ber.EncodeOption) ([]byte, error) { return v.MarshalBER([]ber.EncodeOption{mode}...) }, v)
	if replayErr != nil {
		return nil, replayErr
	}
	if replayBytes, ok := ber.PreparedBERReplay(v.berReplayNode_, opts); ok {
		return replayBytes, nil
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBERNode(encoded, v.berReplayNode_, opts), nil
}
func (v *LCSProvideSubscriberLocationRes) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if len(v.LocationEstimate) < 1 || len(v.LocationEstimate) > 20 {
		if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(opts, "MAP-LCS-DataTypes.ProvideSubscriberLocation-Res", ber.RuleRef{Document: "ITU-T X.680", Edition: "02/2021", Clause: "51.5"}), "locationEstimate", "SIZE (1..20)", len(v.LocationEstimate)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_locationestimate, encodeErr_enc_locationestimate := ber.EncodeOctetString([]byte(v.LocationEstimate))
	if encodeErr_enc_locationestimate != nil {
		return nil, qualifyBERError(encodeErr_enc_locationestimate, "locationEstimate", "encoding", false)
	}
	children = append(children, enc_locationestimate...)
	if v.AgeOfLocationEstimate != nil {
		if !(int64(*v.AgeOfLocationEstimate) >= 0 && int64(*v.AgeOfLocationEstimate) <= 32767) {
			if constraintErr := ber.CheckEncodedValue(ber.EncodeRule(opts, "MAP-LCS-DataTypes.ProvideSubscriberLocation-Res", ber.RuleRef{Document: "ITU-T X.680", Edition: "02/2021", Clause: "51.4"}), "ageOfLocationEstimate", "(0..32767)", ber.ObserveInteger(int64(*v.AgeOfLocationEstimate))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_ageoflocationestimate := ber.EncodeInteger(int64(*v.AgeOfLocationEstimate))
		retagged_enc_ageoflocationestimate, tagErr_enc_ageoflocationestimate := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_ageoflocationestimate)
		if tagErr_enc_ageoflocationestimate != nil {
			return nil, qualifyBERError(tagErr_enc_ageoflocationestimate, "ageOfLocationEstimate", "encoding", false)
		}
		enc_ageoflocationestimate = retagged_enc_ageoflocationestimate
		children = append(children, enc_ageoflocationestimate...)
	}
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalBER(ber.ChildEncodeOptions(opts, "extensionContainer")...)
		if err != nil {
			return nil, qualifyBERError(err, "extensionContainer", "encoding", false)
		}
		retagged_enc_extensioncontainer, tagErr_enc_extensioncontainer := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_extensioncontainer)
		if tagErr_enc_extensioncontainer != nil {
			return nil, qualifyBERError(tagErr_enc_extensioncontainer, "extensionContainer", "encoding", false)
		}
		enc_extensioncontainer = retagged_enc_extensioncontainer
		ber.RecordGeneratedBERChildPlacement(opts, len(children), enc_extensioncontainer)
		children = append(children, enc_extensioncontainer...)
	}
	if v.AddLocationEstimate != nil {
		if len(*v.AddLocationEstimate) < 1 || len(*v.AddLocationEstimate) > 91 {
			if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(opts, "MAP-LCS-DataTypes.ProvideSubscriberLocation-Res", ber.RuleRef{Document: "ITU-T X.680", Edition: "02/2021", Clause: "51.5"}), "add-LocationEstimate", "SIZE (1..91)", len(*v.AddLocationEstimate)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_addlocationestimate, encodeErr_enc_addlocationestimate := ber.EncodeOctetString([]byte(*v.AddLocationEstimate))
		if encodeErr_enc_addlocationestimate != nil {
			return nil, qualifyBERError(encodeErr_enc_addlocationestimate, "add-LocationEstimate", "encoding", false)
		}
		retagged_enc_addlocationestimate, tagErr_enc_addlocationestimate := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_addlocationestimate)
		if tagErr_enc_addlocationestimate != nil {
			return nil, qualifyBERError(tagErr_enc_addlocationestimate, "add-LocationEstimate", "encoding", false)
		}
		enc_addlocationestimate = retagged_enc_addlocationestimate
		children = append(children, enc_addlocationestimate...)
	}
	if v.DeferredmtLrResponseIndicator != nil {
		enc_deferredmtlrresponseindicator := ber.EncodeNull()
		retagged_enc_deferredmtlrresponseindicator, tagErr_enc_deferredmtlrresponseindicator := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, enc_deferredmtlrresponseindicator)
		if tagErr_enc_deferredmtlrresponseindicator != nil {
			return nil, qualifyBERError(tagErr_enc_deferredmtlrresponseindicator, "deferredmt-lrResponseIndicator", "encoding", false)
		}
		enc_deferredmtlrresponseindicator = retagged_enc_deferredmtlrresponseindicator
		children = append(children, enc_deferredmtlrresponseindicator...)
	}
	if v.GeranPositioningData != nil {
		if len(*v.GeranPositioningData) < 2 || len(*v.GeranPositioningData) > 10 {
			if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(opts, "MAP-LCS-DataTypes.ProvideSubscriberLocation-Res", ber.RuleRef{Document: "ITU-T X.680", Edition: "02/2021", Clause: "51.5"}), "geranPositioningData", "SIZE (2..10)", len(*v.GeranPositioningData)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_geranpositioningdata, encodeErr_enc_geranpositioningdata := ber.EncodeOctetString([]byte(*v.GeranPositioningData))
		if encodeErr_enc_geranpositioningdata != nil {
			return nil, qualifyBERError(encodeErr_enc_geranpositioningdata, "geranPositioningData", "encoding", false)
		}
		retagged_enc_geranpositioningdata, tagErr_enc_geranpositioningdata := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, enc_geranpositioningdata)
		if tagErr_enc_geranpositioningdata != nil {
			return nil, qualifyBERError(tagErr_enc_geranpositioningdata, "geranPositioningData", "encoding", false)
		}
		enc_geranpositioningdata = retagged_enc_geranpositioningdata
		children = append(children, enc_geranpositioningdata...)
	}
	if v.UtranPositioningData != nil {
		if len(*v.UtranPositioningData) < 3 || len(*v.UtranPositioningData) > 11 {
			if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(opts, "MAP-LCS-DataTypes.ProvideSubscriberLocation-Res", ber.RuleRef{Document: "ITU-T X.680", Edition: "02/2021", Clause: "51.5"}), "utranPositioningData", "SIZE (3..11)", len(*v.UtranPositioningData)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_utranpositioningdata, encodeErr_enc_utranpositioningdata := ber.EncodeOctetString([]byte(*v.UtranPositioningData))
		if encodeErr_enc_utranpositioningdata != nil {
			return nil, qualifyBERError(encodeErr_enc_utranpositioningdata, "utranPositioningData", "encoding", false)
		}
		retagged_enc_utranpositioningdata, tagErr_enc_utranpositioningdata := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 5, enc_utranpositioningdata)
		if tagErr_enc_utranpositioningdata != nil {
			return nil, qualifyBERError(tagErr_enc_utranpositioningdata, "utranPositioningData", "encoding", false)
		}
		enc_utranpositioningdata = retagged_enc_utranpositioningdata
		children = append(children, enc_utranpositioningdata...)
	}
	if v.CellIdOrSai != nil {
		enc_cellidorsai, err := v.CellIdOrSai.MarshalBER(ber.ChildEncodeOptions(opts, "cellIdOrSai")...)
		if err != nil {
			return nil, qualifyBERError(err, "cellIdOrSai", "encoding", false)
		}
		{
			var encodeErr error
			enc_cellidorsai, encodeErr = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 6, enc_cellidorsai)
			if encodeErr != nil {
				return nil, qualifyBERError(encodeErr, "cellIdOrSai", "encoding", false)
			}
		}
		ber.RecordGeneratedBERChildPlacement(opts, len(children), enc_cellidorsai)
		children = append(children, enc_cellidorsai...)
	}
	if v.SaiPresent != nil {
		enc_saipresent := ber.EncodeNull()
		retagged_enc_saipresent, tagErr_enc_saipresent := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 7, enc_saipresent)
		if tagErr_enc_saipresent != nil {
			return nil, qualifyBERError(tagErr_enc_saipresent, "sai-Present", "encoding", false)
		}
		enc_saipresent = retagged_enc_saipresent
		children = append(children, enc_saipresent...)
	}
	if v.AccuracyFulfilmentIndicator != nil {
		enc_accuracyfulfilmentindicator := ber.EncodeEnumerated(int64(*v.AccuracyFulfilmentIndicator))
		retagged_enc_accuracyfulfilmentindicator, tagErr_enc_accuracyfulfilmentindicator := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 8, enc_accuracyfulfilmentindicator)
		if tagErr_enc_accuracyfulfilmentindicator != nil {
			return nil, qualifyBERError(tagErr_enc_accuracyfulfilmentindicator, "accuracyFulfilmentIndicator", "encoding", false)
		}
		enc_accuracyfulfilmentindicator = retagged_enc_accuracyfulfilmentindicator
		children = append(children, enc_accuracyfulfilmentindicator...)
	}
	if v.VelocityEstimate != nil {
		if len(*v.VelocityEstimate) < 4 || len(*v.VelocityEstimate) > 7 {
			if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(opts, "MAP-LCS-DataTypes.ProvideSubscriberLocation-Res", ber.RuleRef{Document: "ITU-T X.680", Edition: "02/2021", Clause: "51.5"}), "velocityEstimate", "SIZE (4..7)", len(*v.VelocityEstimate)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_velocityestimate, encodeErr_enc_velocityestimate := ber.EncodeOctetString([]byte(*v.VelocityEstimate))
		if encodeErr_enc_velocityestimate != nil {
			return nil, qualifyBERError(encodeErr_enc_velocityestimate, "velocityEstimate", "encoding", false)
		}
		retagged_enc_velocityestimate, tagErr_enc_velocityestimate := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 9, enc_velocityestimate)
		if tagErr_enc_velocityestimate != nil {
			return nil, qualifyBERError(tagErr_enc_velocityestimate, "velocityEstimate", "encoding", false)
		}
		enc_velocityestimate = retagged_enc_velocityestimate
		children = append(children, enc_velocityestimate...)
	}
	if v.MoLrShortCircuitIndicator != nil {
		enc_molrshortcircuitindicator := ber.EncodeNull()
		retagged_enc_molrshortcircuitindicator, tagErr_enc_molrshortcircuitindicator := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 10, enc_molrshortcircuitindicator)
		if tagErr_enc_molrshortcircuitindicator != nil {
			return nil, qualifyBERError(tagErr_enc_molrshortcircuitindicator, "mo-lrShortCircuitIndicator", "encoding", false)
		}
		enc_molrshortcircuitindicator = retagged_enc_molrshortcircuitindicator
		children = append(children, enc_molrshortcircuitindicator...)
	}
	if v.GeranGANSSpositioningData != nil {
		if len(*v.GeranGANSSpositioningData) < 2 || len(*v.GeranGANSSpositioningData) > 10 {
			if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(opts, "MAP-LCS-DataTypes.ProvideSubscriberLocation-Res", ber.RuleRef{Document: "ITU-T X.680", Edition: "02/2021", Clause: "51.5"}), "geranGANSSpositioningData", "SIZE (2..10)", len(*v.GeranGANSSpositioningData)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_gerangansspositioningdata, encodeErr_enc_gerangansspositioningdata := ber.EncodeOctetString([]byte(*v.GeranGANSSpositioningData))
		if encodeErr_enc_gerangansspositioningdata != nil {
			return nil, qualifyBERError(encodeErr_enc_gerangansspositioningdata, "geranGANSSpositioningData", "encoding", false)
		}
		retagged_enc_gerangansspositioningdata, tagErr_enc_gerangansspositioningdata := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 11, enc_gerangansspositioningdata)
		if tagErr_enc_gerangansspositioningdata != nil {
			return nil, qualifyBERError(tagErr_enc_gerangansspositioningdata, "geranGANSSpositioningData", "encoding", false)
		}
		enc_gerangansspositioningdata = retagged_enc_gerangansspositioningdata
		children = append(children, enc_gerangansspositioningdata...)
	}
	if v.UtranGANSSpositioningData != nil {
		if len(*v.UtranGANSSpositioningData) < 1 || len(*v.UtranGANSSpositioningData) > 9 {
			if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(opts, "MAP-LCS-DataTypes.ProvideSubscriberLocation-Res", ber.RuleRef{Document: "ITU-T X.680", Edition: "02/2021", Clause: "51.5"}), "utranGANSSpositioningData", "SIZE (1..9)", len(*v.UtranGANSSpositioningData)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_utrangansspositioningdata, encodeErr_enc_utrangansspositioningdata := ber.EncodeOctetString([]byte(*v.UtranGANSSpositioningData))
		if encodeErr_enc_utrangansspositioningdata != nil {
			return nil, qualifyBERError(encodeErr_enc_utrangansspositioningdata, "utranGANSSpositioningData", "encoding", false)
		}
		retagged_enc_utrangansspositioningdata, tagErr_enc_utrangansspositioningdata := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 12, enc_utrangansspositioningdata)
		if tagErr_enc_utrangansspositioningdata != nil {
			return nil, qualifyBERError(tagErr_enc_utrangansspositioningdata, "utranGANSSpositioningData", "encoding", false)
		}
		enc_utrangansspositioningdata = retagged_enc_utrangansspositioningdata
		children = append(children, enc_utrangansspositioningdata...)
	}
	if v.TargetServingNodeForHandover != nil {
		enc_targetservingnodeforhandover, err := v.TargetServingNodeForHandover.MarshalBER(ber.ChildEncodeOptions(opts, "targetServingNodeForHandover")...)
		if err != nil {
			return nil, qualifyBERError(err, "targetServingNodeForHandover", "encoding", false)
		}
		{
			var encodeErr error
			enc_targetservingnodeforhandover, encodeErr = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 13, enc_targetservingnodeforhandover)
			if encodeErr != nil {
				return nil, qualifyBERError(encodeErr, "targetServingNodeForHandover", "encoding", false)
			}
		}
		ber.RecordGeneratedBERChildPlacement(opts, len(children), enc_targetservingnodeforhandover)
		children = append(children, enc_targetservingnodeforhandover...)
	}
	if v.UtranAdditionalPositioningData != nil {
		if len(*v.UtranAdditionalPositioningData) < 1 || len(*v.UtranAdditionalPositioningData) > 8 {
			if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(opts, "MAP-LCS-DataTypes.ProvideSubscriberLocation-Res", ber.RuleRef{Document: "ITU-T X.680", Edition: "02/2021", Clause: "51.5"}), "utranAdditionalPositioningData", "SIZE (1..8)", len(*v.UtranAdditionalPositioningData)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_utranadditionalpositioningdata, encodeErr_enc_utranadditionalpositioningdata := ber.EncodeOctetString([]byte(*v.UtranAdditionalPositioningData))
		if encodeErr_enc_utranadditionalpositioningdata != nil {
			return nil, qualifyBERError(encodeErr_enc_utranadditionalpositioningdata, "utranAdditionalPositioningData", "encoding", false)
		}
		retagged_enc_utranadditionalpositioningdata, tagErr_enc_utranadditionalpositioningdata := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 14, enc_utranadditionalpositioningdata)
		if tagErr_enc_utranadditionalpositioningdata != nil {
			return nil, qualifyBERError(tagErr_enc_utranadditionalpositioningdata, "utranAdditionalPositioningData", "encoding", false)
		}
		enc_utranadditionalpositioningdata = retagged_enc_utranadditionalpositioningdata
		children = append(children, enc_utranadditionalpositioningdata...)
	}
	if v.UtranBaroPressureMeas != nil {
		if !(int64(*v.UtranBaroPressureMeas) >= 30000 && int64(*v.UtranBaroPressureMeas) <= 115000) {
			if constraintErr := ber.CheckEncodedValue(ber.EncodeRule(opts, "MAP-LCS-DataTypes.ProvideSubscriberLocation-Res", ber.RuleRef{Document: "ITU-T X.680", Edition: "02/2021", Clause: "51.4"}), "utranBaroPressureMeas", "(30000..115000)", ber.ObserveInteger(int64(*v.UtranBaroPressureMeas))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_utranbaropressuremeas := ber.EncodeInteger(int64(*v.UtranBaroPressureMeas))
		retagged_enc_utranbaropressuremeas, tagErr_enc_utranbaropressuremeas := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 15, enc_utranbaropressuremeas)
		if tagErr_enc_utranbaropressuremeas != nil {
			return nil, qualifyBERError(tagErr_enc_utranbaropressuremeas, "utranBaroPressureMeas", "encoding", false)
		}
		enc_utranbaropressuremeas = retagged_enc_utranbaropressuremeas
		children = append(children, enc_utranbaropressuremeas...)
	}
	if v.UtranCivicAddress != nil {
		enc_utrancivicaddress, encodeErr_enc_utrancivicaddress := ber.EncodeOctetString([]byte(*v.UtranCivicAddress))
		if encodeErr_enc_utrancivicaddress != nil {
			return nil, qualifyBERError(encodeErr_enc_utrancivicaddress, "utranCivicAddress", "encoding", false)
		}
		retagged_enc_utrancivicaddress, tagErr_enc_utrancivicaddress := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 16, enc_utrancivicaddress)
		if tagErr_enc_utrancivicaddress != nil {
			return nil, qualifyBERError(tagErr_enc_utrancivicaddress, "utranCivicAddress", "encoding", false)
		}
		enc_utrancivicaddress = retagged_enc_utrancivicaddress
		children = append(children, enc_utrancivicaddress...)
	}
	for i, ext := range v.ExtData_ {
		if err := ber.CheckBEROpaqueElement(ext, opts...); err != nil {
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
		if i == 0 && ((peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 16) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 15) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 14) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 13) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 12) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 11) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 10) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 9) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 8) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 7) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 6) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 5) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0)) {
			if constraintErr := ber.CheckEncodedValue(ber.EncodeRule(opts, "MAP-LCS-DataTypes.ProvideSubscriberLocation-Res", ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
				return nil, constraintErr
			}
		}
		children = append(children, ext...)
	}
	ber.RecordGeneratedBERContainer(opts, children)
	return ber.EncodeSequence(children)
}
func (v *LCSProvideSubscriberLocationRes) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// MarshalDER encodes LCSProvideSubscriberLocationRes to DER format.
// Opaque descendants pass generic DER checks; foreign schema rules need a typed binding.
func (v *LCSProvideSubscriberLocationRes) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: LCSProvideSubscriberLocationRes receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if len(v.LocationEstimate) < 1 || len(v.LocationEstimate) > 20 {
		if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(nil, "MAP-LCS-DataTypes.ProvideSubscriberLocation-Res", ber.RuleRef{Document: "ITU-T X.680", Edition: "02/2021", Clause: "51.5"}), "locationEstimate", "SIZE (1..20)", len(v.LocationEstimate)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_locationestimate, encodeErr_enc_locationestimate := ber.EncodeOctetString([]byte(v.LocationEstimate))
	if encodeErr_enc_locationestimate != nil {
		return nil, qualifyBERError(encodeErr_enc_locationestimate, "locationEstimate", "encoding", true)
	}
	children = append(children, enc_locationestimate...)
	if v.AgeOfLocationEstimate != nil {
		if !(int64(*v.AgeOfLocationEstimate) >= 0 && int64(*v.AgeOfLocationEstimate) <= 32767) {
			if constraintErr := ber.CheckEncodedValue(ber.EncodeRule(nil, "MAP-LCS-DataTypes.ProvideSubscriberLocation-Res", ber.RuleRef{Document: "ITU-T X.680", Edition: "02/2021", Clause: "51.4"}), "ageOfLocationEstimate", "(0..32767)", ber.ObserveInteger(int64(*v.AgeOfLocationEstimate))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_ageoflocationestimate := ber.EncodeInteger(int64(*v.AgeOfLocationEstimate))
		retagged_enc_ageoflocationestimate, tagErr_enc_ageoflocationestimate := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_ageoflocationestimate)
		if tagErr_enc_ageoflocationestimate != nil {
			return nil, qualifyBERError(tagErr_enc_ageoflocationestimate, "ageOfLocationEstimate", "encoding", true)
		}
		enc_ageoflocationestimate = retagged_enc_ageoflocationestimate
		children = append(children, enc_ageoflocationestimate...)
	}
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalDER()
		if err != nil {
			return nil, qualifyBERError(err, "extensionContainer", "encoding", true)
		}
		retagged_enc_extensioncontainer, tagErr_enc_extensioncontainer := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_extensioncontainer)
		if tagErr_enc_extensioncontainer != nil {
			return nil, qualifyBERError(tagErr_enc_extensioncontainer, "extensionContainer", "encoding", true)
		}
		enc_extensioncontainer = retagged_enc_extensioncontainer
		children = append(children, enc_extensioncontainer...)
	}
	if v.AddLocationEstimate != nil {
		if len(*v.AddLocationEstimate) < 1 || len(*v.AddLocationEstimate) > 91 {
			if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(nil, "MAP-LCS-DataTypes.ProvideSubscriberLocation-Res", ber.RuleRef{Document: "ITU-T X.680", Edition: "02/2021", Clause: "51.5"}), "add-LocationEstimate", "SIZE (1..91)", len(*v.AddLocationEstimate)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_addlocationestimate, encodeErr_enc_addlocationestimate := ber.EncodeOctetString([]byte(*v.AddLocationEstimate))
		if encodeErr_enc_addlocationestimate != nil {
			return nil, qualifyBERError(encodeErr_enc_addlocationestimate, "add-LocationEstimate", "encoding", true)
		}
		retagged_enc_addlocationestimate, tagErr_enc_addlocationestimate := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_addlocationestimate)
		if tagErr_enc_addlocationestimate != nil {
			return nil, qualifyBERError(tagErr_enc_addlocationestimate, "add-LocationEstimate", "encoding", true)
		}
		enc_addlocationestimate = retagged_enc_addlocationestimate
		children = append(children, enc_addlocationestimate...)
	}
	if v.DeferredmtLrResponseIndicator != nil {
		enc_deferredmtlrresponseindicator := ber.EncodeNull()
		retagged_enc_deferredmtlrresponseindicator, tagErr_enc_deferredmtlrresponseindicator := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, enc_deferredmtlrresponseindicator)
		if tagErr_enc_deferredmtlrresponseindicator != nil {
			return nil, qualifyBERError(tagErr_enc_deferredmtlrresponseindicator, "deferredmt-lrResponseIndicator", "encoding", true)
		}
		enc_deferredmtlrresponseindicator = retagged_enc_deferredmtlrresponseindicator
		children = append(children, enc_deferredmtlrresponseindicator...)
	}
	if v.GeranPositioningData != nil {
		if len(*v.GeranPositioningData) < 2 || len(*v.GeranPositioningData) > 10 {
			if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(nil, "MAP-LCS-DataTypes.ProvideSubscriberLocation-Res", ber.RuleRef{Document: "ITU-T X.680", Edition: "02/2021", Clause: "51.5"}), "geranPositioningData", "SIZE (2..10)", len(*v.GeranPositioningData)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_geranpositioningdata, encodeErr_enc_geranpositioningdata := ber.EncodeOctetString([]byte(*v.GeranPositioningData))
		if encodeErr_enc_geranpositioningdata != nil {
			return nil, qualifyBERError(encodeErr_enc_geranpositioningdata, "geranPositioningData", "encoding", true)
		}
		retagged_enc_geranpositioningdata, tagErr_enc_geranpositioningdata := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, enc_geranpositioningdata)
		if tagErr_enc_geranpositioningdata != nil {
			return nil, qualifyBERError(tagErr_enc_geranpositioningdata, "geranPositioningData", "encoding", true)
		}
		enc_geranpositioningdata = retagged_enc_geranpositioningdata
		children = append(children, enc_geranpositioningdata...)
	}
	if v.UtranPositioningData != nil {
		if len(*v.UtranPositioningData) < 3 || len(*v.UtranPositioningData) > 11 {
			if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(nil, "MAP-LCS-DataTypes.ProvideSubscriberLocation-Res", ber.RuleRef{Document: "ITU-T X.680", Edition: "02/2021", Clause: "51.5"}), "utranPositioningData", "SIZE (3..11)", len(*v.UtranPositioningData)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_utranpositioningdata, encodeErr_enc_utranpositioningdata := ber.EncodeOctetString([]byte(*v.UtranPositioningData))
		if encodeErr_enc_utranpositioningdata != nil {
			return nil, qualifyBERError(encodeErr_enc_utranpositioningdata, "utranPositioningData", "encoding", true)
		}
		retagged_enc_utranpositioningdata, tagErr_enc_utranpositioningdata := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 5, enc_utranpositioningdata)
		if tagErr_enc_utranpositioningdata != nil {
			return nil, qualifyBERError(tagErr_enc_utranpositioningdata, "utranPositioningData", "encoding", true)
		}
		enc_utranpositioningdata = retagged_enc_utranpositioningdata
		children = append(children, enc_utranpositioningdata...)
	}
	if v.CellIdOrSai != nil {
		enc_cellidorsai, err := v.CellIdOrSai.MarshalDER()
		if err != nil {
			return nil, qualifyBERError(err, "cellIdOrSai", "encoding", true)
		}
		{
			var encodeErr error
			enc_cellidorsai, encodeErr = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 6, enc_cellidorsai)
			if encodeErr != nil {
				return nil, qualifyBERError(encodeErr, "cellIdOrSai", "encoding", true)
			}
		}
		children = append(children, enc_cellidorsai...)
	}
	if v.SaiPresent != nil {
		enc_saipresent := ber.EncodeNull()
		retagged_enc_saipresent, tagErr_enc_saipresent := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 7, enc_saipresent)
		if tagErr_enc_saipresent != nil {
			return nil, qualifyBERError(tagErr_enc_saipresent, "sai-Present", "encoding", true)
		}
		enc_saipresent = retagged_enc_saipresent
		children = append(children, enc_saipresent...)
	}
	if v.AccuracyFulfilmentIndicator != nil {
		enc_accuracyfulfilmentindicator := ber.EncodeEnumerated(int64(*v.AccuracyFulfilmentIndicator))
		retagged_enc_accuracyfulfilmentindicator, tagErr_enc_accuracyfulfilmentindicator := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 8, enc_accuracyfulfilmentindicator)
		if tagErr_enc_accuracyfulfilmentindicator != nil {
			return nil, qualifyBERError(tagErr_enc_accuracyfulfilmentindicator, "accuracyFulfilmentIndicator", "encoding", true)
		}
		enc_accuracyfulfilmentindicator = retagged_enc_accuracyfulfilmentindicator
		children = append(children, enc_accuracyfulfilmentindicator...)
	}
	if v.VelocityEstimate != nil {
		if len(*v.VelocityEstimate) < 4 || len(*v.VelocityEstimate) > 7 {
			if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(nil, "MAP-LCS-DataTypes.ProvideSubscriberLocation-Res", ber.RuleRef{Document: "ITU-T X.680", Edition: "02/2021", Clause: "51.5"}), "velocityEstimate", "SIZE (4..7)", len(*v.VelocityEstimate)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_velocityestimate, encodeErr_enc_velocityestimate := ber.EncodeOctetString([]byte(*v.VelocityEstimate))
		if encodeErr_enc_velocityestimate != nil {
			return nil, qualifyBERError(encodeErr_enc_velocityestimate, "velocityEstimate", "encoding", true)
		}
		retagged_enc_velocityestimate, tagErr_enc_velocityestimate := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 9, enc_velocityestimate)
		if tagErr_enc_velocityestimate != nil {
			return nil, qualifyBERError(tagErr_enc_velocityestimate, "velocityEstimate", "encoding", true)
		}
		enc_velocityestimate = retagged_enc_velocityestimate
		children = append(children, enc_velocityestimate...)
	}
	if v.MoLrShortCircuitIndicator != nil {
		enc_molrshortcircuitindicator := ber.EncodeNull()
		retagged_enc_molrshortcircuitindicator, tagErr_enc_molrshortcircuitindicator := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 10, enc_molrshortcircuitindicator)
		if tagErr_enc_molrshortcircuitindicator != nil {
			return nil, qualifyBERError(tagErr_enc_molrshortcircuitindicator, "mo-lrShortCircuitIndicator", "encoding", true)
		}
		enc_molrshortcircuitindicator = retagged_enc_molrshortcircuitindicator
		children = append(children, enc_molrshortcircuitindicator...)
	}
	if v.GeranGANSSpositioningData != nil {
		if len(*v.GeranGANSSpositioningData) < 2 || len(*v.GeranGANSSpositioningData) > 10 {
			if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(nil, "MAP-LCS-DataTypes.ProvideSubscriberLocation-Res", ber.RuleRef{Document: "ITU-T X.680", Edition: "02/2021", Clause: "51.5"}), "geranGANSSpositioningData", "SIZE (2..10)", len(*v.GeranGANSSpositioningData)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_gerangansspositioningdata, encodeErr_enc_gerangansspositioningdata := ber.EncodeOctetString([]byte(*v.GeranGANSSpositioningData))
		if encodeErr_enc_gerangansspositioningdata != nil {
			return nil, qualifyBERError(encodeErr_enc_gerangansspositioningdata, "geranGANSSpositioningData", "encoding", true)
		}
		retagged_enc_gerangansspositioningdata, tagErr_enc_gerangansspositioningdata := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 11, enc_gerangansspositioningdata)
		if tagErr_enc_gerangansspositioningdata != nil {
			return nil, qualifyBERError(tagErr_enc_gerangansspositioningdata, "geranGANSSpositioningData", "encoding", true)
		}
		enc_gerangansspositioningdata = retagged_enc_gerangansspositioningdata
		children = append(children, enc_gerangansspositioningdata...)
	}
	if v.UtranGANSSpositioningData != nil {
		if len(*v.UtranGANSSpositioningData) < 1 || len(*v.UtranGANSSpositioningData) > 9 {
			if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(nil, "MAP-LCS-DataTypes.ProvideSubscriberLocation-Res", ber.RuleRef{Document: "ITU-T X.680", Edition: "02/2021", Clause: "51.5"}), "utranGANSSpositioningData", "SIZE (1..9)", len(*v.UtranGANSSpositioningData)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_utrangansspositioningdata, encodeErr_enc_utrangansspositioningdata := ber.EncodeOctetString([]byte(*v.UtranGANSSpositioningData))
		if encodeErr_enc_utrangansspositioningdata != nil {
			return nil, qualifyBERError(encodeErr_enc_utrangansspositioningdata, "utranGANSSpositioningData", "encoding", true)
		}
		retagged_enc_utrangansspositioningdata, tagErr_enc_utrangansspositioningdata := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 12, enc_utrangansspositioningdata)
		if tagErr_enc_utrangansspositioningdata != nil {
			return nil, qualifyBERError(tagErr_enc_utrangansspositioningdata, "utranGANSSpositioningData", "encoding", true)
		}
		enc_utrangansspositioningdata = retagged_enc_utrangansspositioningdata
		children = append(children, enc_utrangansspositioningdata...)
	}
	if v.TargetServingNodeForHandover != nil {
		enc_targetservingnodeforhandover, err := v.TargetServingNodeForHandover.MarshalDER()
		if err != nil {
			return nil, qualifyBERError(err, "targetServingNodeForHandover", "encoding", true)
		}
		{
			var encodeErr error
			enc_targetservingnodeforhandover, encodeErr = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 13, enc_targetservingnodeforhandover)
			if encodeErr != nil {
				return nil, qualifyBERError(encodeErr, "targetServingNodeForHandover", "encoding", true)
			}
		}
		children = append(children, enc_targetservingnodeforhandover...)
	}
	if v.UtranAdditionalPositioningData != nil {
		if len(*v.UtranAdditionalPositioningData) < 1 || len(*v.UtranAdditionalPositioningData) > 8 {
			if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(nil, "MAP-LCS-DataTypes.ProvideSubscriberLocation-Res", ber.RuleRef{Document: "ITU-T X.680", Edition: "02/2021", Clause: "51.5"}), "utranAdditionalPositioningData", "SIZE (1..8)", len(*v.UtranAdditionalPositioningData)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_utranadditionalpositioningdata, encodeErr_enc_utranadditionalpositioningdata := ber.EncodeOctetString([]byte(*v.UtranAdditionalPositioningData))
		if encodeErr_enc_utranadditionalpositioningdata != nil {
			return nil, qualifyBERError(encodeErr_enc_utranadditionalpositioningdata, "utranAdditionalPositioningData", "encoding", true)
		}
		retagged_enc_utranadditionalpositioningdata, tagErr_enc_utranadditionalpositioningdata := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 14, enc_utranadditionalpositioningdata)
		if tagErr_enc_utranadditionalpositioningdata != nil {
			return nil, qualifyBERError(tagErr_enc_utranadditionalpositioningdata, "utranAdditionalPositioningData", "encoding", true)
		}
		enc_utranadditionalpositioningdata = retagged_enc_utranadditionalpositioningdata
		children = append(children, enc_utranadditionalpositioningdata...)
	}
	if v.UtranBaroPressureMeas != nil {
		if !(int64(*v.UtranBaroPressureMeas) >= 30000 && int64(*v.UtranBaroPressureMeas) <= 115000) {
			if constraintErr := ber.CheckEncodedValue(ber.EncodeRule(nil, "MAP-LCS-DataTypes.ProvideSubscriberLocation-Res", ber.RuleRef{Document: "ITU-T X.680", Edition: "02/2021", Clause: "51.4"}), "utranBaroPressureMeas", "(30000..115000)", ber.ObserveInteger(int64(*v.UtranBaroPressureMeas))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_utranbaropressuremeas := ber.EncodeInteger(int64(*v.UtranBaroPressureMeas))
		retagged_enc_utranbaropressuremeas, tagErr_enc_utranbaropressuremeas := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 15, enc_utranbaropressuremeas)
		if tagErr_enc_utranbaropressuremeas != nil {
			return nil, qualifyBERError(tagErr_enc_utranbaropressuremeas, "utranBaroPressureMeas", "encoding", true)
		}
		enc_utranbaropressuremeas = retagged_enc_utranbaropressuremeas
		children = append(children, enc_utranbaropressuremeas...)
	}
	if v.UtranCivicAddress != nil {
		enc_utrancivicaddress, encodeErr_enc_utrancivicaddress := ber.EncodeOctetString([]byte(*v.UtranCivicAddress))
		if encodeErr_enc_utrancivicaddress != nil {
			return nil, qualifyBERError(encodeErr_enc_utrancivicaddress, "utranCivicAddress", "encoding", true)
		}
		retagged_enc_utrancivicaddress, tagErr_enc_utrancivicaddress := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 16, enc_utrancivicaddress)
		if tagErr_enc_utrancivicaddress != nil {
			return nil, qualifyBERError(tagErr_enc_utrancivicaddress, "utranCivicAddress", "encoding", true)
		}
		enc_utrancivicaddress = retagged_enc_utrancivicaddress
		children = append(children, enc_utrancivicaddress...)
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
		if i == 0 && ((peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 16) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 15) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 14) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 13) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 12) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 11) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 10) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 9) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 8) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 7) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 6) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 5) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0)) {
			if constraintErr := ber.CheckEncodedValue(ber.EncodeRule(nil, "MAP-LCS-DataTypes.ProvideSubscriberLocation-Res", ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
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
		return nil, fmt.Errorf("%s: %w", "encoding LCSProvideSubscriberLocationRes as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}
func (v *LCSProvideSubscriberLocationRes) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	encoded, err := v.MarshalDER()
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBER decodes LCSProvideSubscriberLocationRes from BER/DER format.
func (destination *LCSProvideSubscriberLocationRes) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if destination == nil {
		return fmt.Errorf("%w: LCSProvideSubscriberLocationRes destination is nil", ber.ErrInvalidValue)
	}
	var berNextValue_ LCSProvideSubscriberLocationRes
	v :=
		&berNextValue_
	defer func() {
		if returnErr ==
			nil {
			*destination = *v
		}
	}()

	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	ownedData, ownErr := ber.OwnGeneratedBERInput(data, opts)
	if ownErr != nil {
		return ownErr
	}
	data = ownedData
	preparedData, preparedOptions, prepareErr := ber.PrepareGeneratedBERInput(data, opts)
	if prepareErr != nil {
		return ber.DiagnosePreflight(prepareErr, data, opts, "child", func(probeOpts []ber.DecodeOption) error {
			var probe LCSProvideSubscriberLocationRes
			return probe.UnmarshalBER(data, probeOpts...)
		})
	}
	data, opts = preparedData, preparedOptions
	opts = ber.LocateDecodedElement(data, "MAP-LCS-DataTypes.ProvideSubscriberLocation-Res", opts)
	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
	*v = LCSProvideSubscriberLocationRes{}
	defer func() {
		if returnErr != nil || !ber.BERNeedsPreservation(opts) {
			return
		}
		v.berReplayNode_ = ber.CaptureGeneratedBERReplay(data, opts)
		returnErr = ber.CompleteGeneratedBERDecode(opts, v, func(base *LCSProvideSubscriberLocationRes, replayOpts ...ber.EncodeOption) ([]byte, error) {
			return base.MarshalBER(replayOpts...)
		})
	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("%s: %w", "decoding LCSProvideSubscriberLocationRes SEQUENCE", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "LCSProvideSubscriberLocationRes", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode locationEstimate
	if offset >= len(content) {
		return fmt.Errorf("missing required field locationEstimate")
	}
	{
		ber.MarkPreflightTarget(opts, "locationEstimate", content[offset:])
		val_locationestimate, n, err := ber.DecodeOctetString(content[offset:], opts...)
		if err != nil {
			return qualifyBERError(err, "locationEstimate", "decoding", false)
		}
		v.LocationEstimate = LCSExtGeographicalInformation(val_locationestimate)
		if offset > len(content) || n < 0 || n > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n
		if len(v.LocationEstimate) < 1 || len(v.LocationEstimate) > 20 {
			if constraintErr := ber.CheckDecodedLength(ber.DecodeRule(opts, "MAP-LCS-DataTypes.ProvideSubscriberLocation-Res", ber.RuleRef{Document: "ITU-T X.680", Edition: "02/2021", Clause: "51.5"}), "locationEstimate", "SIZE (1..20)", len(v.LocationEstimate)); constraintErr != nil {
				return constraintErr
			}
		}
	}
	// Decode ageOfLocationEstimate
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
				ber.MarkPreflightTarget(opts, "ageOfLocationEstimate", content[offset:])
				decodedTag_ageoflocationestimate, n_ageoflocationestimate, rawVal_ageoflocationestimate, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "ageOfLocationEstimate", "decoding", false)
				}
				if decodedTag_ageoflocationestimate.Class != tag.ClassContextSpecific || decodedTag_ageoflocationestimate.Number != 0 || decodedTag_ageoflocationestimate.Constructed != false {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_ageoflocationestimate), "ageOfLocationEstimate", "decoding", false)
				}
				decVal_ageoflocationestimate, intErr := ber.DecodeIntegerValue(rawVal_ageoflocationestimate)
				if intErr != nil {
					return qualifyBERError(intErr, "ageOfLocationEstimate", "decoding", false)
				}
				tmp_ageoflocationestimate := v21_map_commondatatypes.CommonDataTypesAgeOfLocationInformation(decVal_ageoflocationestimate)
				v.AgeOfLocationEstimate = &tmp_ageoflocationestimate
				if offset < 0 || offset >
					len(content) || n_ageoflocationestimate < 0 || n_ageoflocationestimate >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_ageoflocationestimate
				if !(int64(*v.AgeOfLocationEstimate) >= 0 && int64(*v.AgeOfLocationEstimate) <= 32767) {
					if constraintErr := ber.CheckDecodedValue(ber.DecodeRule(opts, "MAP-LCS-DataTypes.ProvideSubscriberLocation-Res", ber.RuleRef{Document: "ITU-T X.680", Edition: "02/2021", Clause: "51.4"}), "ageOfLocationEstimate", "(0..32767)", ber.ObserveInteger(int64(*v.AgeOfLocationEstimate))); constraintErr != nil {
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
				ber.MarkPreflightTarget(opts, "extensionContainer", content[offset:])
				decodedTag_extensioncontainer, n_extensioncontainer, rawVal_extensioncontainer, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "extensionContainer", "decoding", false)
				}
				if decodedTag_extensioncontainer.Class != tag.ClassContextSpecific || decodedTag_extensioncontainer.Number != 1 || decodedTag_extensioncontainer.Constructed != true {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_extensioncontainer), "extensionContainer", "decoding", false)
				}
				_ = rawVal_extensioncontainer
				if offset < 0 || offset >
					len(content) || n_extensioncontainer < 0 || n_extensioncontainer > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				reconstructed_extensioncontainer, reconstructionErr_extensioncontainer := ber.EncodeImplicitTagWithClass(tag.ClassUniversal, tag.TagSequence, content[offset:offset+n_extensioncontainer])
				if reconstructionErr_extensioncontainer != nil {
					return qualifyBERError(reconstructionErr_extensioncontainer, "extensionContainer", "decoding", false)
				}
				var dec_extensioncontainer v21_map_extensiondatatypes.ExtensionDataTypesExtensionContainer
				if unmErr := dec_extensioncontainer.UnmarshalBER(reconstructed_extensioncontainer, ber.ChildDecodeOptions(opts, "extensionContainer")...); unmErr != nil {
					return qualifyBERError(unmErr, "extensionContainer", "decoding", false)
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
				ber.MarkPreflightTarget(opts, "add-LocationEstimate", content[offset:])
				decodedTag_addlocationestimate, n_addlocationestimate, rawVal_addlocationestimate, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "add-LocationEstimate", "decoding", false)
				}
				if decodedTag_addlocationestimate.Class != tag.ClassContextSpecific || decodedTag_addlocationestimate.Number != 2 {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_addlocationestimate), "add-LocationEstimate", "decoding", false)
				}
				decVal_addlocationestimate, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_addlocationestimate.Constructed, rawVal_addlocationestimate, opts...)
				if octetErr != nil {
					return qualifyBERError(octetErr, "add-LocationEstimate", "decoding", false)
				}
				tmp_addlocationestimate := LCSAddGeographicalInformation(decVal_addlocationestimate)
				v.AddLocationEstimate = &tmp_addlocationestimate
				if offset < 0 || offset >
					len(content) || n_addlocationestimate < 0 || n_addlocationestimate > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_addlocationestimate
				if len(*v.AddLocationEstimate) < 1 || len(*v.AddLocationEstimate) > 91 {
					if constraintErr := ber.CheckDecodedLength(ber.DecodeRule(opts, "MAP-LCS-DataTypes.ProvideSubscriberLocation-Res", ber.RuleRef{Document: "ITU-T X.680", Edition: "02/2021", Clause: "51.5"}), "add-LocationEstimate", "SIZE (1..91)", len(*v.AddLocationEstimate)); constraintErr != nil {
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
				ber.MarkPreflightTarget(opts, "deferredmt-lrResponseIndicator", content[offset:])
				decodedTag_deferredmtlrresponseindicator, n_deferredmtlrresponseindicator, rawVal_deferredmtlrresponseindicator, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "deferredmt-lrResponseIndicator", "decoding", false)
				}
				if decodedTag_deferredmtlrresponseindicator.Class != tag.ClassContextSpecific || decodedTag_deferredmtlrresponseindicator.Number != 3 || decodedTag_deferredmtlrresponseindicator.Constructed != false {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_deferredmtlrresponseindicator), "deferredmt-lrResponseIndicator", "decoding", false)
				}
				if len(rawVal_deferredmtlrresponseindicator) != 0 {
					return qualifyBERError(fmt.Errorf("%w: NULL content length %d", ber.ErrInvalidValue, len(rawVal_deferredmtlrresponseindicator)), "deferredmt-lrResponseIndicator", "decoding", false)
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
				ber.MarkPreflightTarget(opts, "geranPositioningData", content[offset:])
				decodedTag_geranpositioningdata, n_geranpositioningdata, rawVal_geranpositioningdata, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "geranPositioningData", "decoding", false)
				}
				if decodedTag_geranpositioningdata.Class != tag.ClassContextSpecific || decodedTag_geranpositioningdata.Number != 4 {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_geranpositioningdata), "geranPositioningData", "decoding", false)
				}
				decVal_geranpositioningdata, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_geranpositioningdata.Constructed, rawVal_geranpositioningdata, opts...)
				if octetErr != nil {
					return qualifyBERError(octetErr, "geranPositioningData", "decoding", false)
				}
				tmp_geranpositioningdata := LCSPositioningDataInformation(decVal_geranpositioningdata)
				v.GeranPositioningData = &tmp_geranpositioningdata
				if offset < 0 || offset >
					len(content) || n_geranpositioningdata < 0 || n_geranpositioningdata > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_geranpositioningdata
				if len(*v.GeranPositioningData) < 2 || len(*v.GeranPositioningData) > 10 {
					if constraintErr := ber.CheckDecodedLength(ber.DecodeRule(opts, "MAP-LCS-DataTypes.ProvideSubscriberLocation-Res", ber.RuleRef{Document: "ITU-T X.680", Edition: "02/2021", Clause: "51.5"}), "geranPositioningData", "SIZE (2..10)", len(*v.GeranPositioningData)); constraintErr != nil {
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
				ber.MarkPreflightTarget(opts, "utranPositioningData", content[offset:])
				decodedTag_utranpositioningdata, n_utranpositioningdata, rawVal_utranpositioningdata, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "utranPositioningData", "decoding", false)
				}
				if decodedTag_utranpositioningdata.Class != tag.ClassContextSpecific || decodedTag_utranpositioningdata.Number != 5 {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_utranpositioningdata), "utranPositioningData", "decoding", false)
				}
				decVal_utranpositioningdata, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_utranpositioningdata.Constructed, rawVal_utranpositioningdata, opts...)
				if octetErr != nil {
					return qualifyBERError(octetErr, "utranPositioningData", "decoding", false)
				}
				tmp_utranpositioningdata := LCSUtranPositioningDataInfo(decVal_utranpositioningdata)
				v.UtranPositioningData = &tmp_utranpositioningdata
				if offset < 0 || offset >
					len(content) || n_utranpositioningdata < 0 || n_utranpositioningdata > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_utranpositioningdata
				if len(*v.UtranPositioningData) < 3 || len(*v.UtranPositioningData) > 11 {
					if constraintErr := ber.CheckDecodedLength(ber.DecodeRule(opts, "MAP-LCS-DataTypes.ProvideSubscriberLocation-Res", ber.RuleRef{Document: "ITU-T X.680", Edition: "02/2021", Clause: "51.5"}), "utranPositioningData", "SIZE (3..11)", len(*v.UtranPositioningData)); constraintErr != nil {
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
				ber.MarkPreflightTarget(opts, "cellIdOrSai", content[offset:])
				decodedTag_cellidorsai, n_cellidorsai, innerData_cellidorsai, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "cellIdOrSai", "decoding", false)
				}
				if decodedTag_cellidorsai.Class != tag.ClassContextSpecific || decodedTag_cellidorsai.Number != 6 || decodedTag_cellidorsai.Constructed != true {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_cellidorsai), "cellIdOrSai", "decoding", false)
				}
				_, innerUsed_cellidorsai, _, innerErr_cellidorsai := ber.DecodeTLV(innerData_cellidorsai, opts...)
				if innerErr_cellidorsai != nil {
					return qualifyBERError(innerErr_cellidorsai, "cellIdOrSai", "decoding", false)
				}
				if innerUsed_cellidorsai != len(innerData_cellidorsai) {
					return qualifyBERError(ber.ErrExtraData, "cellIdOrSai", "decoding", false)
				}
				// Decode inner value from explicit tag wrapper
				ber.MarkPreflightTarget(opts, "cellIdOrSai", innerData_cellidorsai)
				var dec_cellidorsai v21_map_commondatatypes.CommonDataTypesCellGlobalIdOrServiceAreaIdOrLAI
				if unmErr := dec_cellidorsai.UnmarshalBER(innerData_cellidorsai, ber.ChildDecodeOptions(opts, "cellIdOrSai")...); unmErr != nil {
					return qualifyBERError(unmErr, "cellIdOrSai", "decoding", false)
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
				ber.MarkPreflightTarget(opts, "sai-Present", content[offset:])
				decodedTag_saipresent, n_saipresent, rawVal_saipresent, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "sai-Present", "decoding", false)
				}
				if decodedTag_saipresent.Class != tag.ClassContextSpecific || decodedTag_saipresent.Number != 7 || decodedTag_saipresent.Constructed != false {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_saipresent), "sai-Present", "decoding", false)
				}
				if len(rawVal_saipresent) != 0 {
					return qualifyBERError(fmt.Errorf("%w: NULL content length %d", ber.ErrInvalidValue, len(rawVal_saipresent)), "sai-Present", "decoding", false)
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
				ber.MarkPreflightTarget(opts, "accuracyFulfilmentIndicator", content[offset:])
				decodedTag_accuracyfulfilmentindicator, n_accuracyfulfilmentindicator, rawVal_accuracyfulfilmentindicator, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "accuracyFulfilmentIndicator", "decoding", false)
				}
				if decodedTag_accuracyfulfilmentindicator.Class != tag.ClassContextSpecific || decodedTag_accuracyfulfilmentindicator.Number != 8 || decodedTag_accuracyfulfilmentindicator.Constructed != false {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_accuracyfulfilmentindicator), "accuracyFulfilmentIndicator", "decoding", false)
				}
				decVal_accuracyfulfilmentindicator, intErr := ber.DecodeEnumeratedValue(rawVal_accuracyfulfilmentindicator)
				if intErr != nil {
					return qualifyBERError(intErr, "accuracyFulfilmentIndicator", "decoding", false)
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
				ber.MarkPreflightTarget(opts, "velocityEstimate", content[offset:])
				decodedTag_velocityestimate, n_velocityestimate, rawVal_velocityestimate, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "velocityEstimate", "decoding", false)
				}
				if decodedTag_velocityestimate.Class != tag.ClassContextSpecific || decodedTag_velocityestimate.Number != 9 {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_velocityestimate), "velocityEstimate", "decoding", false)
				}
				decVal_velocityestimate, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_velocityestimate.Constructed, rawVal_velocityestimate, opts...)
				if octetErr != nil {
					return qualifyBERError(octetErr, "velocityEstimate", "decoding", false)
				}
				tmp_velocityestimate := LCSVelocityEstimate(decVal_velocityestimate)
				v.VelocityEstimate = &tmp_velocityestimate
				if offset < 0 || offset >
					len(content) || n_velocityestimate < 0 || n_velocityestimate > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_velocityestimate
				if len(*v.VelocityEstimate) < 4 || len(*v.VelocityEstimate) > 7 {
					if constraintErr := ber.CheckDecodedLength(ber.DecodeRule(opts, "MAP-LCS-DataTypes.ProvideSubscriberLocation-Res", ber.RuleRef{Document: "ITU-T X.680", Edition: "02/2021", Clause: "51.5"}), "velocityEstimate", "SIZE (4..7)", len(*v.VelocityEstimate)); constraintErr != nil {
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
				ber.MarkPreflightTarget(opts, "mo-lrShortCircuitIndicator", content[offset:])
				decodedTag_molrshortcircuitindicator, n_molrshortcircuitindicator, rawVal_molrshortcircuitindicator, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "mo-lrShortCircuitIndicator", "decoding", false)
				}
				if decodedTag_molrshortcircuitindicator.Class != tag.ClassContextSpecific || decodedTag_molrshortcircuitindicator.Number != 10 || decodedTag_molrshortcircuitindicator.Constructed != false {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_molrshortcircuitindicator), "mo-lrShortCircuitIndicator", "decoding", false)
				}
				if len(rawVal_molrshortcircuitindicator) != 0 {
					return qualifyBERError(fmt.Errorf("%w: NULL content length %d", ber.ErrInvalidValue, len(rawVal_molrshortcircuitindicator)), "mo-lrShortCircuitIndicator", "decoding", false)
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
				ber.MarkPreflightTarget(opts, "geranGANSSpositioningData", content[offset:])
				decodedTag_gerangansspositioningdata, n_gerangansspositioningdata, rawVal_gerangansspositioningdata, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "geranGANSSpositioningData", "decoding", false)
				}
				if decodedTag_gerangansspositioningdata.Class != tag.ClassContextSpecific || decodedTag_gerangansspositioningdata.Number != 11 {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_gerangansspositioningdata), "geranGANSSpositioningData", "decoding", false)
				}
				decVal_gerangansspositioningdata, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_gerangansspositioningdata.Constructed, rawVal_gerangansspositioningdata, opts...)
				if octetErr != nil {
					return qualifyBERError(octetErr, "geranGANSSpositioningData", "decoding", false)
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
					if constraintErr := ber.CheckDecodedLength(ber.DecodeRule(opts, "MAP-LCS-DataTypes.ProvideSubscriberLocation-Res", ber.RuleRef{Document: "ITU-T X.680", Edition: "02/2021", Clause: "51.5"}), "geranGANSSpositioningData", "SIZE (2..10)", len(*v.GeranGANSSpositioningData)); constraintErr != nil {
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
				ber.MarkPreflightTarget(opts, "utranGANSSpositioningData", content[offset:])
				decodedTag_utrangansspositioningdata, n_utrangansspositioningdata, rawVal_utrangansspositioningdata, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "utranGANSSpositioningData", "decoding", false)
				}
				if decodedTag_utrangansspositioningdata.Class != tag.ClassContextSpecific || decodedTag_utrangansspositioningdata.Number != 12 {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_utrangansspositioningdata), "utranGANSSpositioningData", "decoding", false)
				}
				decVal_utrangansspositioningdata, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_utrangansspositioningdata.Constructed, rawVal_utrangansspositioningdata, opts...)
				if octetErr != nil {
					return qualifyBERError(octetErr, "utranGANSSpositioningData", "decoding", false)
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
					if constraintErr := ber.CheckDecodedLength(ber.DecodeRule(opts, "MAP-LCS-DataTypes.ProvideSubscriberLocation-Res", ber.RuleRef{Document: "ITU-T X.680", Edition: "02/2021", Clause: "51.5"}), "utranGANSSpositioningData", "SIZE (1..9)", len(*v.UtranGANSSpositioningData)); constraintErr != nil {
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
				ber.MarkPreflightTarget(opts, "targetServingNodeForHandover", content[offset:])
				decodedTag_targetservingnodeforhandover, n_targetservingnodeforhandover, innerData_targetservingnodeforhandover, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "targetServingNodeForHandover", "decoding", false)
				}
				if decodedTag_targetservingnodeforhandover.Class != tag.ClassContextSpecific || decodedTag_targetservingnodeforhandover.Number != 13 || decodedTag_targetservingnodeforhandover.Constructed != true {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_targetservingnodeforhandover), "targetServingNodeForHandover", "decoding", false)
				}
				_, innerUsed_targetservingnodeforhandover, _, innerErr_targetservingnodeforhandover := ber.DecodeTLV(innerData_targetservingnodeforhandover, opts...)
				if innerErr_targetservingnodeforhandover != nil {
					return qualifyBERError(innerErr_targetservingnodeforhandover, "targetServingNodeForHandover", "decoding", false)
				}
				if innerUsed_targetservingnodeforhandover != len(innerData_targetservingnodeforhandover) {
					return qualifyBERError(ber.ErrExtraData, "targetServingNodeForHandover", "decoding", false)
				}
				// Decode inner value from explicit tag wrapper
				ber.MarkPreflightTarget(opts, "targetServingNodeForHandover", innerData_targetservingnodeforhandover)
				var dec_targetservingnodeforhandover LCSServingNodeAddress
				if unmErr := dec_targetservingnodeforhandover.UnmarshalBER(innerData_targetservingnodeforhandover, ber.ChildDecodeOptions(opts, "targetServingNodeForHandover")...); unmErr != nil {
					return qualifyBERError(unmErr, "targetServingNodeForHandover", "decoding", false)
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
				ber.MarkPreflightTarget(opts, "utranAdditionalPositioningData", content[offset:])
				decodedTag_utranadditionalpositioningdata, n_utranadditionalpositioningdata, rawVal_utranadditionalpositioningdata, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "utranAdditionalPositioningData", "decoding", false)
				}
				if decodedTag_utranadditionalpositioningdata.Class != tag.ClassContextSpecific || decodedTag_utranadditionalpositioningdata.Number != 14 {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_utranadditionalpositioningdata), "utranAdditionalPositioningData", "decoding", false)
				}
				decVal_utranadditionalpositioningdata, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_utranadditionalpositioningdata.Constructed, rawVal_utranadditionalpositioningdata, opts...)
				if octetErr != nil {
					return qualifyBERError(octetErr, "utranAdditionalPositioningData", "decoding", false)
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
					if constraintErr := ber.CheckDecodedLength(ber.DecodeRule(opts, "MAP-LCS-DataTypes.ProvideSubscriberLocation-Res", ber.RuleRef{Document: "ITU-T X.680", Edition: "02/2021", Clause: "51.5"}), "utranAdditionalPositioningData", "SIZE (1..8)", len(*v.UtranAdditionalPositioningData)); constraintErr != nil {
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
				ber.MarkPreflightTarget(opts, "utranBaroPressureMeas", content[offset:])
				decodedTag_utranbaropressuremeas, n_utranbaropressuremeas, rawVal_utranbaropressuremeas, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "utranBaroPressureMeas", "decoding", false)
				}
				if decodedTag_utranbaropressuremeas.Class != tag.ClassContextSpecific || decodedTag_utranbaropressuremeas.Number != 15 || decodedTag_utranbaropressuremeas.Constructed != false {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_utranbaropressuremeas), "utranBaroPressureMeas", "decoding", false)
				}
				decVal_utranbaropressuremeas, intErr := ber.DecodeIntegerValue(rawVal_utranbaropressuremeas)
				if intErr != nil {
					return qualifyBERError(intErr, "utranBaroPressureMeas", "decoding", false)
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
					if constraintErr := ber.CheckDecodedValue(ber.DecodeRule(opts, "MAP-LCS-DataTypes.ProvideSubscriberLocation-Res", ber.RuleRef{Document: "ITU-T X.680", Edition: "02/2021", Clause: "51.4"}), "utranBaroPressureMeas", "(30000..115000)", ber.ObserveInteger(int64(*v.UtranBaroPressureMeas))); constraintErr != nil {
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
				ber.MarkPreflightTarget(opts, "utranCivicAddress", content[offset:])
				decodedTag_utrancivicaddress, n_utrancivicaddress, rawVal_utrancivicaddress, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "utranCivicAddress", "decoding", false)
				}
				if decodedTag_utrancivicaddress.Class != tag.ClassContextSpecific || decodedTag_utrancivicaddress.Number != 16 {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_utrancivicaddress), "utranCivicAddress", "decoding", false)
				}
				decVal_utrancivicaddress, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_utrancivicaddress.Constructed, rawVal_utrancivicaddress, opts...)
				if octetErr != nil {
					return qualifyBERError(octetErr, "utranCivicAddress", "decoding", false)
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
		peekTag, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:], opts...)
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "LCSProvideSubscriberLocationRes", Cause: extErr_}
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: the first unknown addition must differ from trailing OPTIONAL/DEFAULT tags.
		if len(v.ExtData_) == 0 && ((peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 16) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 15) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 14) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 13) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 12) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 11) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 10) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 9) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 8) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 7) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 6) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 5) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0)) {
			if !ber.ToleranceEnabled(opts) {
				return &ber.DecodeError{Offset: offset, TypeName: "LCSProvideSubscriberLocationRes", Cause: fmt.Errorf("%w: repeated or out-of-order SEQUENCE component tag %s", ber.ErrInvalidTag, peekTag)}
			}
			if orderErr_ := ber.CheckDecodedValue(ber.DecodeRule(opts, "MAP-LCS-DataTypes.ProvideSubscriberLocation-Res", ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), fmt.Sprintf("ExtData_[%d]", len(v.ExtData_)), "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); orderErr_ != nil {
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

// MarshalBER encodes LCSSubscriberLocationReportArg to BER format.
func (v *LCSSubscriberLocationReportArg) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: LCSSubscriberLocationReportArg receiver is nil", ber.ErrInvalidValue)
	}
	if v.berReplayNode_ == nil {
		return v.marshalBER(opts...)
	}
	var replayErr error
	opts, replayErr = ber.PrepareBERReplay(v.berReplayNode_, opts, func(mode ber.EncodeOption) ([]byte, error) { return v.MarshalBER([]ber.EncodeOption{mode}...) }, v)
	if replayErr != nil {
		return nil, replayErr
	}
	if replayBytes, ok := ber.PreparedBERReplay(v.berReplayNode_, opts); ok {
		return replayBytes, nil
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBERNode(encoded, v.berReplayNode_, opts), nil
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
		return nil, qualifyBERError(err, "lcs-ClientID", "encoding", false)
	}
	ber.RecordGeneratedBERChildPlacement(opts, len(children), enc_lcsclientid)
	children = append(children, enc_lcsclientid...)
	enc_lcslocationinfo, err := v.LcsLocationInfo.MarshalBER(ber.ChildEncodeOptions(opts, "lcsLocationInfo")...)
	if err != nil {
		return nil, qualifyBERError(err, "lcsLocationInfo", "encoding", false)
	}
	ber.RecordGeneratedBERChildPlacement(opts, len(children), enc_lcslocationinfo)
	children = append(children, enc_lcslocationinfo...)
	if v.Msisdn != nil {
		if len(*v.Msisdn) < 1 || len(*v.Msisdn) > 9 {
			if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(opts, "MAP-LCS-DataTypes.SubscriberLocationReport-Arg", ber.RuleRef{Document: "ITU-T X.680", Edition: "02/2021", Clause: "51.5"}), "msisdn", "SIZE (1..9)", len(*v.Msisdn)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		if len(*v.Msisdn) < 1 || len(*v.Msisdn) > 20 {
			if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(opts, "MAP-LCS-DataTypes.SubscriberLocationReport-Arg", ber.RuleRef{Document: "ITU-T X.680", Edition: "02/2021", Clause: "51.5"}), "msisdn", "SIZE (1..20)", len(*v.Msisdn)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_msisdn, encodeErr_enc_msisdn := ber.EncodeOctetString([]byte(*v.Msisdn))
		if encodeErr_enc_msisdn != nil {
			return nil, qualifyBERError(encodeErr_enc_msisdn, "msisdn", "encoding", false)
		}
		retagged_enc_msisdn, tagErr_enc_msisdn := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_msisdn)
		if tagErr_enc_msisdn != nil {
			return nil, qualifyBERError(tagErr_enc_msisdn, "msisdn", "encoding", false)
		}
		enc_msisdn = retagged_enc_msisdn
		children = append(children, enc_msisdn...)
	}
	if v.Imsi != nil {
		if len(*v.Imsi) < 3 || len(*v.Imsi) > 8 {
			if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(opts, "MAP-LCS-DataTypes.SubscriberLocationReport-Arg", ber.RuleRef{Document: "ITU-T X.680", Edition: "02/2021", Clause: "51.5"}), "imsi", "SIZE (3..8)", len(*v.Imsi)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_imsi, encodeErr_enc_imsi := ber.EncodeOctetString([]byte(*v.Imsi))
		if encodeErr_enc_imsi != nil {
			return nil, qualifyBERError(encodeErr_enc_imsi, "imsi", "encoding", false)
		}
		retagged_enc_imsi, tagErr_enc_imsi := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_imsi)
		if tagErr_enc_imsi != nil {
			return nil, qualifyBERError(tagErr_enc_imsi, "imsi", "encoding", false)
		}
		enc_imsi = retagged_enc_imsi
		children = append(children, enc_imsi...)
	}
	if v.Imei != nil {
		if len(*v.Imei) < 8 || len(*v.Imei) > 8 {
			if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(opts, "MAP-LCS-DataTypes.SubscriberLocationReport-Arg", ber.RuleRef{Document: "ITU-T X.680", Edition: "02/2021", Clause: "51.5"}), "imei", "SIZE (8)", len(*v.Imei)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_imei, encodeErr_enc_imei := ber.EncodeOctetString([]byte(*v.Imei))
		if encodeErr_enc_imei != nil {
			return nil, qualifyBERError(encodeErr_enc_imei, "imei", "encoding", false)
		}
		retagged_enc_imei, tagErr_enc_imei := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_imei)
		if tagErr_enc_imei != nil {
			return nil, qualifyBERError(tagErr_enc_imei, "imei", "encoding", false)
		}
		enc_imei = retagged_enc_imei
		children = append(children, enc_imei...)
	}
	if v.NaESRD != nil {
		if len(*v.NaESRD) < 1 || len(*v.NaESRD) > 9 {
			if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(opts, "MAP-LCS-DataTypes.SubscriberLocationReport-Arg", ber.RuleRef{Document: "ITU-T X.680", Edition: "02/2021", Clause: "51.5"}), "na-ESRD", "SIZE (1..9)", len(*v.NaESRD)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		if len(*v.NaESRD) < 1 || len(*v.NaESRD) > 20 {
			if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(opts, "MAP-LCS-DataTypes.SubscriberLocationReport-Arg", ber.RuleRef{Document: "ITU-T X.680", Edition: "02/2021", Clause: "51.5"}), "na-ESRD", "SIZE (1..20)", len(*v.NaESRD)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_naesrd, encodeErr_enc_naesrd := ber.EncodeOctetString([]byte(*v.NaESRD))
		if encodeErr_enc_naesrd != nil {
			return nil, qualifyBERError(encodeErr_enc_naesrd, "na-ESRD", "encoding", false)
		}
		retagged_enc_naesrd, tagErr_enc_naesrd := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, enc_naesrd)
		if tagErr_enc_naesrd != nil {
			return nil, qualifyBERError(tagErr_enc_naesrd, "na-ESRD", "encoding", false)
		}
		enc_naesrd = retagged_enc_naesrd
		children = append(children, enc_naesrd...)
	}
	if v.NaESRK != nil {
		if len(*v.NaESRK) < 1 || len(*v.NaESRK) > 9 {
			if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(opts, "MAP-LCS-DataTypes.SubscriberLocationReport-Arg", ber.RuleRef{Document: "ITU-T X.680", Edition: "02/2021", Clause: "51.5"}), "na-ESRK", "SIZE (1..9)", len(*v.NaESRK)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		if len(*v.NaESRK) < 1 || len(*v.NaESRK) > 20 {
			if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(opts, "MAP-LCS-DataTypes.SubscriberLocationReport-Arg", ber.RuleRef{Document: "ITU-T X.680", Edition: "02/2021", Clause: "51.5"}), "na-ESRK", "SIZE (1..20)", len(*v.NaESRK)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_naesrk, encodeErr_enc_naesrk := ber.EncodeOctetString([]byte(*v.NaESRK))
		if encodeErr_enc_naesrk != nil {
			return nil, qualifyBERError(encodeErr_enc_naesrk, "na-ESRK", "encoding", false)
		}
		retagged_enc_naesrk, tagErr_enc_naesrk := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, enc_naesrk)
		if tagErr_enc_naesrk != nil {
			return nil, qualifyBERError(tagErr_enc_naesrk, "na-ESRK", "encoding", false)
		}
		enc_naesrk = retagged_enc_naesrk
		children = append(children, enc_naesrk...)
	}
	if v.LocationEstimate != nil {
		if len(*v.LocationEstimate) < 1 || len(*v.LocationEstimate) > 20 {
			if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(opts, "MAP-LCS-DataTypes.SubscriberLocationReport-Arg", ber.RuleRef{Document: "ITU-T X.680", Edition: "02/2021", Clause: "51.5"}), "locationEstimate", "SIZE (1..20)", len(*v.LocationEstimate)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_locationestimate, encodeErr_enc_locationestimate := ber.EncodeOctetString([]byte(*v.LocationEstimate))
		if encodeErr_enc_locationestimate != nil {
			return nil, qualifyBERError(encodeErr_enc_locationestimate, "locationEstimate", "encoding", false)
		}
		retagged_enc_locationestimate, tagErr_enc_locationestimate := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 5, enc_locationestimate)
		if tagErr_enc_locationestimate != nil {
			return nil, qualifyBERError(tagErr_enc_locationestimate, "locationEstimate", "encoding", false)
		}
		enc_locationestimate = retagged_enc_locationestimate
		children = append(children, enc_locationestimate...)
	}
	if v.AgeOfLocationEstimate != nil {
		if !(int64(*v.AgeOfLocationEstimate) >= 0 && int64(*v.AgeOfLocationEstimate) <= 32767) {
			if constraintErr := ber.CheckEncodedValue(ber.EncodeRule(opts, "MAP-LCS-DataTypes.SubscriberLocationReport-Arg", ber.RuleRef{Document: "ITU-T X.680", Edition: "02/2021", Clause: "51.4"}), "ageOfLocationEstimate", "(0..32767)", ber.ObserveInteger(int64(*v.AgeOfLocationEstimate))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_ageoflocationestimate := ber.EncodeInteger(int64(*v.AgeOfLocationEstimate))
		retagged_enc_ageoflocationestimate, tagErr_enc_ageoflocationestimate := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 6, enc_ageoflocationestimate)
		if tagErr_enc_ageoflocationestimate != nil {
			return nil, qualifyBERError(tagErr_enc_ageoflocationestimate, "ageOfLocationEstimate", "encoding", false)
		}
		enc_ageoflocationestimate = retagged_enc_ageoflocationestimate
		children = append(children, enc_ageoflocationestimate...)
	}
	if v.SlrArgExtensionContainer != nil {
		enc_slrargextensioncontainer, err := v.SlrArgExtensionContainer.MarshalBER(ber.ChildEncodeOptions(opts, "slr-ArgExtensionContainer")...)
		if err != nil {
			return nil, qualifyBERError(err, "slr-ArgExtensionContainer", "encoding", false)
		}
		retagged_enc_slrargextensioncontainer, tagErr_enc_slrargextensioncontainer := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 7, enc_slrargextensioncontainer)
		if tagErr_enc_slrargextensioncontainer != nil {
			return nil, qualifyBERError(tagErr_enc_slrargextensioncontainer, "slr-ArgExtensionContainer", "encoding", false)
		}
		enc_slrargextensioncontainer = retagged_enc_slrargextensioncontainer
		ber.RecordGeneratedBERChildPlacement(opts, len(children), enc_slrargextensioncontainer)
		children = append(children, enc_slrargextensioncontainer...)
	}
	if v.AddLocationEstimate != nil {
		if len(*v.AddLocationEstimate) < 1 || len(*v.AddLocationEstimate) > 91 {
			if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(opts, "MAP-LCS-DataTypes.SubscriberLocationReport-Arg", ber.RuleRef{Document: "ITU-T X.680", Edition: "02/2021", Clause: "51.5"}), "add-LocationEstimate", "SIZE (1..91)", len(*v.AddLocationEstimate)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_addlocationestimate, encodeErr_enc_addlocationestimate := ber.EncodeOctetString([]byte(*v.AddLocationEstimate))
		if encodeErr_enc_addlocationestimate != nil {
			return nil, qualifyBERError(encodeErr_enc_addlocationestimate, "add-LocationEstimate", "encoding", false)
		}
		retagged_enc_addlocationestimate, tagErr_enc_addlocationestimate := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 8, enc_addlocationestimate)
		if tagErr_enc_addlocationestimate != nil {
			return nil, qualifyBERError(tagErr_enc_addlocationestimate, "add-LocationEstimate", "encoding", false)
		}
		enc_addlocationestimate = retagged_enc_addlocationestimate
		children = append(children, enc_addlocationestimate...)
	}
	if v.DeferredmtLrData != nil {
		enc_deferredmtlrdata, err := v.DeferredmtLrData.MarshalBER(ber.ChildEncodeOptions(opts, "deferredmt-lrData")...)
		if err != nil {
			return nil, qualifyBERError(err, "deferredmt-lrData", "encoding", false)
		}
		retagged_enc_deferredmtlrdata, tagErr_enc_deferredmtlrdata := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 9, enc_deferredmtlrdata)
		if tagErr_enc_deferredmtlrdata != nil {
			return nil, qualifyBERError(tagErr_enc_deferredmtlrdata, "deferredmt-lrData", "encoding", false)
		}
		enc_deferredmtlrdata = retagged_enc_deferredmtlrdata
		ber.RecordGeneratedBERChildPlacement(opts, len(children), enc_deferredmtlrdata)
		children = append(children, enc_deferredmtlrdata...)
	}
	if v.LcsReferenceNumber != nil {
		if len(*v.LcsReferenceNumber) < 1 || len(*v.LcsReferenceNumber) > 1 {
			if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(opts, "MAP-LCS-DataTypes.SubscriberLocationReport-Arg", ber.RuleRef{Document: "ITU-T X.680", Edition: "02/2021", Clause: "51.5"}), "lcs-ReferenceNumber", "SIZE (1)", len(*v.LcsReferenceNumber)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_lcsreferencenumber, encodeErr_enc_lcsreferencenumber := ber.EncodeOctetString([]byte(*v.LcsReferenceNumber))
		if encodeErr_enc_lcsreferencenumber != nil {
			return nil, qualifyBERError(encodeErr_enc_lcsreferencenumber, "lcs-ReferenceNumber", "encoding", false)
		}
		retagged_enc_lcsreferencenumber, tagErr_enc_lcsreferencenumber := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 10, enc_lcsreferencenumber)
		if tagErr_enc_lcsreferencenumber != nil {
			return nil, qualifyBERError(tagErr_enc_lcsreferencenumber, "lcs-ReferenceNumber", "encoding", false)
		}
		enc_lcsreferencenumber = retagged_enc_lcsreferencenumber
		children = append(children, enc_lcsreferencenumber...)
	}
	if v.GeranPositioningData != nil {
		if len(*v.GeranPositioningData) < 2 || len(*v.GeranPositioningData) > 10 {
			if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(opts, "MAP-LCS-DataTypes.SubscriberLocationReport-Arg", ber.RuleRef{Document: "ITU-T X.680", Edition: "02/2021", Clause: "51.5"}), "geranPositioningData", "SIZE (2..10)", len(*v.GeranPositioningData)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_geranpositioningdata, encodeErr_enc_geranpositioningdata := ber.EncodeOctetString([]byte(*v.GeranPositioningData))
		if encodeErr_enc_geranpositioningdata != nil {
			return nil, qualifyBERError(encodeErr_enc_geranpositioningdata, "geranPositioningData", "encoding", false)
		}
		retagged_enc_geranpositioningdata, tagErr_enc_geranpositioningdata := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 11, enc_geranpositioningdata)
		if tagErr_enc_geranpositioningdata != nil {
			return nil, qualifyBERError(tagErr_enc_geranpositioningdata, "geranPositioningData", "encoding", false)
		}
		enc_geranpositioningdata = retagged_enc_geranpositioningdata
		children = append(children, enc_geranpositioningdata...)
	}
	if v.UtranPositioningData != nil {
		if len(*v.UtranPositioningData) < 3 || len(*v.UtranPositioningData) > 11 {
			if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(opts, "MAP-LCS-DataTypes.SubscriberLocationReport-Arg", ber.RuleRef{Document: "ITU-T X.680", Edition: "02/2021", Clause: "51.5"}), "utranPositioningData", "SIZE (3..11)", len(*v.UtranPositioningData)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_utranpositioningdata, encodeErr_enc_utranpositioningdata := ber.EncodeOctetString([]byte(*v.UtranPositioningData))
		if encodeErr_enc_utranpositioningdata != nil {
			return nil, qualifyBERError(encodeErr_enc_utranpositioningdata, "utranPositioningData", "encoding", false)
		}
		retagged_enc_utranpositioningdata, tagErr_enc_utranpositioningdata := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 12, enc_utranpositioningdata)
		if tagErr_enc_utranpositioningdata != nil {
			return nil, qualifyBERError(tagErr_enc_utranpositioningdata, "utranPositioningData", "encoding", false)
		}
		enc_utranpositioningdata = retagged_enc_utranpositioningdata
		children = append(children, enc_utranpositioningdata...)
	}
	if v.CellIdOrSai != nil {
		enc_cellidorsai, err := v.CellIdOrSai.MarshalBER(ber.ChildEncodeOptions(opts, "cellIdOrSai")...)
		if err != nil {
			return nil, qualifyBERError(err, "cellIdOrSai", "encoding", false)
		}
		{
			var encodeErr error
			enc_cellidorsai, encodeErr = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 13, enc_cellidorsai)
			if encodeErr != nil {
				return nil, qualifyBERError(encodeErr, "cellIdOrSai", "encoding", false)
			}
		}
		ber.RecordGeneratedBERChildPlacement(opts, len(children), enc_cellidorsai)
		children = append(children, enc_cellidorsai...)
	}
	if v.HGmlcAddress != nil {
		if len(*v.HGmlcAddress) < 5 || len(*v.HGmlcAddress) > 17 {
			if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(opts, "MAP-LCS-DataTypes.SubscriberLocationReport-Arg", ber.RuleRef{Document: "ITU-T X.680", Edition: "02/2021", Clause: "51.5"}), "h-gmlc-Address", "SIZE (5..17)", len(*v.HGmlcAddress)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_hgmlcaddress, encodeErr_enc_hgmlcaddress := ber.EncodeOctetString([]byte(*v.HGmlcAddress))
		if encodeErr_enc_hgmlcaddress != nil {
			return nil, qualifyBERError(encodeErr_enc_hgmlcaddress, "h-gmlc-Address", "encoding", false)
		}
		retagged_enc_hgmlcaddress, tagErr_enc_hgmlcaddress := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 14, enc_hgmlcaddress)
		if tagErr_enc_hgmlcaddress != nil {
			return nil, qualifyBERError(tagErr_enc_hgmlcaddress, "h-gmlc-Address", "encoding", false)
		}
		enc_hgmlcaddress = retagged_enc_hgmlcaddress
		children = append(children, enc_hgmlcaddress...)
	}
	if v.LcsServiceTypeID != nil {
		if !(int64(*v.LcsServiceTypeID) >= 0 && int64(*v.LcsServiceTypeID) <= 127) {
			if constraintErr := ber.CheckEncodedValue(ber.EncodeRule(opts, "MAP-LCS-DataTypes.SubscriberLocationReport-Arg", ber.RuleRef{Document: "ITU-T X.680", Edition: "02/2021", Clause: "51.4"}), "lcsServiceTypeID", "(0..127)", ber.ObserveInteger(int64(*v.LcsServiceTypeID))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_lcsservicetypeid := ber.EncodeInteger(int64(*v.LcsServiceTypeID))
		retagged_enc_lcsservicetypeid, tagErr_enc_lcsservicetypeid := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 15, enc_lcsservicetypeid)
		if tagErr_enc_lcsservicetypeid != nil {
			return nil, qualifyBERError(tagErr_enc_lcsservicetypeid, "lcsServiceTypeID", "encoding", false)
		}
		enc_lcsservicetypeid = retagged_enc_lcsservicetypeid
		children = append(children, enc_lcsservicetypeid...)
	}
	if v.SaiPresent != nil {
		enc_saipresent := ber.EncodeNull()
		retagged_enc_saipresent, tagErr_enc_saipresent := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 17, enc_saipresent)
		if tagErr_enc_saipresent != nil {
			return nil, qualifyBERError(tagErr_enc_saipresent, "sai-Present", "encoding", false)
		}
		enc_saipresent = retagged_enc_saipresent
		children = append(children, enc_saipresent...)
	}
	if v.PseudonymIndicator != nil {
		enc_pseudonymindicator := ber.EncodeNull()
		retagged_enc_pseudonymindicator, tagErr_enc_pseudonymindicator := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 18, enc_pseudonymindicator)
		if tagErr_enc_pseudonymindicator != nil {
			return nil, qualifyBERError(tagErr_enc_pseudonymindicator, "pseudonymIndicator", "encoding", false)
		}
		enc_pseudonymindicator = retagged_enc_pseudonymindicator
		children = append(children, enc_pseudonymindicator...)
	}
	if v.AccuracyFulfilmentIndicator != nil {
		enc_accuracyfulfilmentindicator := ber.EncodeEnumerated(int64(*v.AccuracyFulfilmentIndicator))
		retagged_enc_accuracyfulfilmentindicator, tagErr_enc_accuracyfulfilmentindicator := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 19, enc_accuracyfulfilmentindicator)
		if tagErr_enc_accuracyfulfilmentindicator != nil {
			return nil, qualifyBERError(tagErr_enc_accuracyfulfilmentindicator, "accuracyFulfilmentIndicator", "encoding", false)
		}
		enc_accuracyfulfilmentindicator = retagged_enc_accuracyfulfilmentindicator
		children = append(children, enc_accuracyfulfilmentindicator...)
	}
	if v.VelocityEstimate != nil {
		if len(*v.VelocityEstimate) < 4 || len(*v.VelocityEstimate) > 7 {
			if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(opts, "MAP-LCS-DataTypes.SubscriberLocationReport-Arg", ber.RuleRef{Document: "ITU-T X.680", Edition: "02/2021", Clause: "51.5"}), "velocityEstimate", "SIZE (4..7)", len(*v.VelocityEstimate)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_velocityestimate, encodeErr_enc_velocityestimate := ber.EncodeOctetString([]byte(*v.VelocityEstimate))
		if encodeErr_enc_velocityestimate != nil {
			return nil, qualifyBERError(encodeErr_enc_velocityestimate, "velocityEstimate", "encoding", false)
		}
		retagged_enc_velocityestimate, tagErr_enc_velocityestimate := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 20, enc_velocityestimate)
		if tagErr_enc_velocityestimate != nil {
			return nil, qualifyBERError(tagErr_enc_velocityestimate, "velocityEstimate", "encoding", false)
		}
		enc_velocityestimate = retagged_enc_velocityestimate
		children = append(children, enc_velocityestimate...)
	}
	if v.SequenceNumber != nil {
		if !(int64(*v.SequenceNumber) >= 1 && int64(*v.SequenceNumber) <= 8639999) {
			if constraintErr := ber.CheckEncodedValue(ber.EncodeRule(opts, "MAP-LCS-DataTypes.SubscriberLocationReport-Arg", ber.RuleRef{Document: "ITU-T X.680", Edition: "02/2021", Clause: "51.4"}), "sequenceNumber", "(1..8639999)", ber.ObserveInteger(int64(*v.SequenceNumber))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_sequencenumber := ber.EncodeInteger(int64(*v.SequenceNumber))
		retagged_enc_sequencenumber, tagErr_enc_sequencenumber := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 21, enc_sequencenumber)
		if tagErr_enc_sequencenumber != nil {
			return nil, qualifyBERError(tagErr_enc_sequencenumber, "sequenceNumber", "encoding", false)
		}
		enc_sequencenumber = retagged_enc_sequencenumber
		children = append(children, enc_sequencenumber...)
	}
	if v.PeriodicLDRInfo != nil {
		enc_periodicldrinfo, err := v.PeriodicLDRInfo.MarshalBER(ber.ChildEncodeOptions(opts, "periodicLDRInfo")...)
		if err != nil {
			return nil, qualifyBERError(err, "periodicLDRInfo", "encoding", false)
		}
		retagged_enc_periodicldrinfo, tagErr_enc_periodicldrinfo := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 22, enc_periodicldrinfo)
		if tagErr_enc_periodicldrinfo != nil {
			return nil, qualifyBERError(tagErr_enc_periodicldrinfo, "periodicLDRInfo", "encoding", false)
		}
		enc_periodicldrinfo = retagged_enc_periodicldrinfo
		ber.RecordGeneratedBERChildPlacement(opts, len(children), enc_periodicldrinfo)
		children = append(children, enc_periodicldrinfo...)
	}
	if v.MoLrShortCircuitIndicator != nil {
		enc_molrshortcircuitindicator := ber.EncodeNull()
		retagged_enc_molrshortcircuitindicator, tagErr_enc_molrshortcircuitindicator := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 23, enc_molrshortcircuitindicator)
		if tagErr_enc_molrshortcircuitindicator != nil {
			return nil, qualifyBERError(tagErr_enc_molrshortcircuitindicator, "mo-lrShortCircuitIndicator", "encoding", false)
		}
		enc_molrshortcircuitindicator = retagged_enc_molrshortcircuitindicator
		children = append(children, enc_molrshortcircuitindicator...)
	}
	if v.GeranGANSSpositioningData != nil {
		if len(*v.GeranGANSSpositioningData) < 2 || len(*v.GeranGANSSpositioningData) > 10 {
			if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(opts, "MAP-LCS-DataTypes.SubscriberLocationReport-Arg", ber.RuleRef{Document: "ITU-T X.680", Edition: "02/2021", Clause: "51.5"}), "geranGANSSpositioningData", "SIZE (2..10)", len(*v.GeranGANSSpositioningData)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_gerangansspositioningdata, encodeErr_enc_gerangansspositioningdata := ber.EncodeOctetString([]byte(*v.GeranGANSSpositioningData))
		if encodeErr_enc_gerangansspositioningdata != nil {
			return nil, qualifyBERError(encodeErr_enc_gerangansspositioningdata, "geranGANSSpositioningData", "encoding", false)
		}
		retagged_enc_gerangansspositioningdata, tagErr_enc_gerangansspositioningdata := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 24, enc_gerangansspositioningdata)
		if tagErr_enc_gerangansspositioningdata != nil {
			return nil, qualifyBERError(tagErr_enc_gerangansspositioningdata, "geranGANSSpositioningData", "encoding", false)
		}
		enc_gerangansspositioningdata = retagged_enc_gerangansspositioningdata
		children = append(children, enc_gerangansspositioningdata...)
	}
	if v.UtranGANSSpositioningData != nil {
		if len(*v.UtranGANSSpositioningData) < 1 || len(*v.UtranGANSSpositioningData) > 9 {
			if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(opts, "MAP-LCS-DataTypes.SubscriberLocationReport-Arg", ber.RuleRef{Document: "ITU-T X.680", Edition: "02/2021", Clause: "51.5"}), "utranGANSSpositioningData", "SIZE (1..9)", len(*v.UtranGANSSpositioningData)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_utrangansspositioningdata, encodeErr_enc_utrangansspositioningdata := ber.EncodeOctetString([]byte(*v.UtranGANSSpositioningData))
		if encodeErr_enc_utrangansspositioningdata != nil {
			return nil, qualifyBERError(encodeErr_enc_utrangansspositioningdata, "utranGANSSpositioningData", "encoding", false)
		}
		retagged_enc_utrangansspositioningdata, tagErr_enc_utrangansspositioningdata := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 25, enc_utrangansspositioningdata)
		if tagErr_enc_utrangansspositioningdata != nil {
			return nil, qualifyBERError(tagErr_enc_utrangansspositioningdata, "utranGANSSpositioningData", "encoding", false)
		}
		enc_utrangansspositioningdata = retagged_enc_utrangansspositioningdata
		children = append(children, enc_utrangansspositioningdata...)
	}
	if v.TargetServingNodeForHandover != nil {
		enc_targetservingnodeforhandover, err := v.TargetServingNodeForHandover.MarshalBER(ber.ChildEncodeOptions(opts, "targetServingNodeForHandover")...)
		if err != nil {
			return nil, qualifyBERError(err, "targetServingNodeForHandover", "encoding", false)
		}
		{
			var encodeErr error
			enc_targetservingnodeforhandover, encodeErr = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 26, enc_targetservingnodeforhandover)
			if encodeErr != nil {
				return nil, qualifyBERError(encodeErr, "targetServingNodeForHandover", "encoding", false)
			}
		}
		ber.RecordGeneratedBERChildPlacement(opts, len(children), enc_targetservingnodeforhandover)
		children = append(children, enc_targetservingnodeforhandover...)
	}
	if v.UtranAdditionalPositioningData != nil {
		if len(*v.UtranAdditionalPositioningData) < 1 || len(*v.UtranAdditionalPositioningData) > 8 {
			if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(opts, "MAP-LCS-DataTypes.SubscriberLocationReport-Arg", ber.RuleRef{Document: "ITU-T X.680", Edition: "02/2021", Clause: "51.5"}), "utranAdditionalPositioningData", "SIZE (1..8)", len(*v.UtranAdditionalPositioningData)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_utranadditionalpositioningdata, encodeErr_enc_utranadditionalpositioningdata := ber.EncodeOctetString([]byte(*v.UtranAdditionalPositioningData))
		if encodeErr_enc_utranadditionalpositioningdata != nil {
			return nil, qualifyBERError(encodeErr_enc_utranadditionalpositioningdata, "utranAdditionalPositioningData", "encoding", false)
		}
		retagged_enc_utranadditionalpositioningdata, tagErr_enc_utranadditionalpositioningdata := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 27, enc_utranadditionalpositioningdata)
		if tagErr_enc_utranadditionalpositioningdata != nil {
			return nil, qualifyBERError(tagErr_enc_utranadditionalpositioningdata, "utranAdditionalPositioningData", "encoding", false)
		}
		enc_utranadditionalpositioningdata = retagged_enc_utranadditionalpositioningdata
		children = append(children, enc_utranadditionalpositioningdata...)
	}
	if v.UtranBaroPressureMeas != nil {
		if !(int64(*v.UtranBaroPressureMeas) >= 30000 && int64(*v.UtranBaroPressureMeas) <= 115000) {
			if constraintErr := ber.CheckEncodedValue(ber.EncodeRule(opts, "MAP-LCS-DataTypes.SubscriberLocationReport-Arg", ber.RuleRef{Document: "ITU-T X.680", Edition: "02/2021", Clause: "51.4"}), "utranBaroPressureMeas", "(30000..115000)", ber.ObserveInteger(int64(*v.UtranBaroPressureMeas))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_utranbaropressuremeas := ber.EncodeInteger(int64(*v.UtranBaroPressureMeas))
		retagged_enc_utranbaropressuremeas, tagErr_enc_utranbaropressuremeas := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 28, enc_utranbaropressuremeas)
		if tagErr_enc_utranbaropressuremeas != nil {
			return nil, qualifyBERError(tagErr_enc_utranbaropressuremeas, "utranBaroPressureMeas", "encoding", false)
		}
		enc_utranbaropressuremeas = retagged_enc_utranbaropressuremeas
		children = append(children, enc_utranbaropressuremeas...)
	}
	if v.UtranCivicAddress != nil {
		enc_utrancivicaddress, encodeErr_enc_utrancivicaddress := ber.EncodeOctetString([]byte(*v.UtranCivicAddress))
		if encodeErr_enc_utrancivicaddress != nil {
			return nil, qualifyBERError(encodeErr_enc_utrancivicaddress, "utranCivicAddress", "encoding", false)
		}
		retagged_enc_utrancivicaddress, tagErr_enc_utrancivicaddress := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 29, enc_utrancivicaddress)
		if tagErr_enc_utrancivicaddress != nil {
			return nil, qualifyBERError(tagErr_enc_utrancivicaddress, "utranCivicAddress", "encoding", false)
		}
		enc_utrancivicaddress = retagged_enc_utrancivicaddress
		children = append(children, enc_utrancivicaddress...)
	}
	for i, ext := range v.ExtData_ {
		if err := ber.CheckBEROpaqueElement(ext, opts...); err != nil {
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
		if i == 0 && ((peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 29) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 28) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 27) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 26) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 25) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 24) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 23) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 22) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 21) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 20) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 19) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 18) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 17) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 15) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 14) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 13) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 12) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 11) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 10) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 9) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 8) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 7) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 6) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 5) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0)) {
			if constraintErr := ber.CheckEncodedValue(ber.EncodeRule(opts, "MAP-LCS-DataTypes.SubscriberLocationReport-Arg", ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
				return nil, constraintErr
			}
		}
		children = append(children, ext...)
	}
	ber.RecordGeneratedBERContainer(opts, children)
	return ber.EncodeSequence(children)
}
func (v *LCSSubscriberLocationReportArg) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// MarshalDER encodes LCSSubscriberLocationReportArg to DER format.
// Opaque descendants pass generic DER checks; foreign schema rules need a typed binding.
func (v *LCSSubscriberLocationReportArg) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: LCSSubscriberLocationReportArg receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	enc_lcsevent := ber.EncodeEnumerated(int64(v.LcsEvent))
	children = append(children, enc_lcsevent...)
	enc_lcsclientid, err := v.LcsClientID.MarshalDER()
	if err != nil {
		return nil, qualifyBERError(err, "lcs-ClientID", "encoding", true)
	}
	children = append(children, enc_lcsclientid...)
	enc_lcslocationinfo, err := v.LcsLocationInfo.MarshalDER()
	if err != nil {
		return nil, qualifyBERError(err, "lcsLocationInfo", "encoding", true)
	}
	children = append(children, enc_lcslocationinfo...)
	if v.Msisdn != nil {
		if len(*v.Msisdn) < 1 || len(*v.Msisdn) > 9 {
			if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(nil, "MAP-LCS-DataTypes.SubscriberLocationReport-Arg", ber.RuleRef{Document: "ITU-T X.680", Edition: "02/2021", Clause: "51.5"}), "msisdn", "SIZE (1..9)", len(*v.Msisdn)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		if len(*v.Msisdn) < 1 || len(*v.Msisdn) > 20 {
			if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(nil, "MAP-LCS-DataTypes.SubscriberLocationReport-Arg", ber.RuleRef{Document: "ITU-T X.680", Edition: "02/2021", Clause: "51.5"}), "msisdn", "SIZE (1..20)", len(*v.Msisdn)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_msisdn, encodeErr_enc_msisdn := ber.EncodeOctetString([]byte(*v.Msisdn))
		if encodeErr_enc_msisdn != nil {
			return nil, qualifyBERError(encodeErr_enc_msisdn, "msisdn", "encoding", true)
		}
		retagged_enc_msisdn, tagErr_enc_msisdn := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_msisdn)
		if tagErr_enc_msisdn != nil {
			return nil, qualifyBERError(tagErr_enc_msisdn, "msisdn", "encoding", true)
		}
		enc_msisdn = retagged_enc_msisdn
		children = append(children, enc_msisdn...)
	}
	if v.Imsi != nil {
		if len(*v.Imsi) < 3 || len(*v.Imsi) > 8 {
			if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(nil, "MAP-LCS-DataTypes.SubscriberLocationReport-Arg", ber.RuleRef{Document: "ITU-T X.680", Edition: "02/2021", Clause: "51.5"}), "imsi", "SIZE (3..8)", len(*v.Imsi)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_imsi, encodeErr_enc_imsi := ber.EncodeOctetString([]byte(*v.Imsi))
		if encodeErr_enc_imsi != nil {
			return nil, qualifyBERError(encodeErr_enc_imsi, "imsi", "encoding", true)
		}
		retagged_enc_imsi, tagErr_enc_imsi := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_imsi)
		if tagErr_enc_imsi != nil {
			return nil, qualifyBERError(tagErr_enc_imsi, "imsi", "encoding", true)
		}
		enc_imsi = retagged_enc_imsi
		children = append(children, enc_imsi...)
	}
	if v.Imei != nil {
		if len(*v.Imei) < 8 || len(*v.Imei) > 8 {
			if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(nil, "MAP-LCS-DataTypes.SubscriberLocationReport-Arg", ber.RuleRef{Document: "ITU-T X.680", Edition: "02/2021", Clause: "51.5"}), "imei", "SIZE (8)", len(*v.Imei)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_imei, encodeErr_enc_imei := ber.EncodeOctetString([]byte(*v.Imei))
		if encodeErr_enc_imei != nil {
			return nil, qualifyBERError(encodeErr_enc_imei, "imei", "encoding", true)
		}
		retagged_enc_imei, tagErr_enc_imei := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_imei)
		if tagErr_enc_imei != nil {
			return nil, qualifyBERError(tagErr_enc_imei, "imei", "encoding", true)
		}
		enc_imei = retagged_enc_imei
		children = append(children, enc_imei...)
	}
	if v.NaESRD != nil {
		if len(*v.NaESRD) < 1 || len(*v.NaESRD) > 9 {
			if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(nil, "MAP-LCS-DataTypes.SubscriberLocationReport-Arg", ber.RuleRef{Document: "ITU-T X.680", Edition: "02/2021", Clause: "51.5"}), "na-ESRD", "SIZE (1..9)", len(*v.NaESRD)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		if len(*v.NaESRD) < 1 || len(*v.NaESRD) > 20 {
			if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(nil, "MAP-LCS-DataTypes.SubscriberLocationReport-Arg", ber.RuleRef{Document: "ITU-T X.680", Edition: "02/2021", Clause: "51.5"}), "na-ESRD", "SIZE (1..20)", len(*v.NaESRD)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_naesrd, encodeErr_enc_naesrd := ber.EncodeOctetString([]byte(*v.NaESRD))
		if encodeErr_enc_naesrd != nil {
			return nil, qualifyBERError(encodeErr_enc_naesrd, "na-ESRD", "encoding", true)
		}
		retagged_enc_naesrd, tagErr_enc_naesrd := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, enc_naesrd)
		if tagErr_enc_naesrd != nil {
			return nil, qualifyBERError(tagErr_enc_naesrd, "na-ESRD", "encoding", true)
		}
		enc_naesrd = retagged_enc_naesrd
		children = append(children, enc_naesrd...)
	}
	if v.NaESRK != nil {
		if len(*v.NaESRK) < 1 || len(*v.NaESRK) > 9 {
			if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(nil, "MAP-LCS-DataTypes.SubscriberLocationReport-Arg", ber.RuleRef{Document: "ITU-T X.680", Edition: "02/2021", Clause: "51.5"}), "na-ESRK", "SIZE (1..9)", len(*v.NaESRK)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		if len(*v.NaESRK) < 1 || len(*v.NaESRK) > 20 {
			if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(nil, "MAP-LCS-DataTypes.SubscriberLocationReport-Arg", ber.RuleRef{Document: "ITU-T X.680", Edition: "02/2021", Clause: "51.5"}), "na-ESRK", "SIZE (1..20)", len(*v.NaESRK)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_naesrk, encodeErr_enc_naesrk := ber.EncodeOctetString([]byte(*v.NaESRK))
		if encodeErr_enc_naesrk != nil {
			return nil, qualifyBERError(encodeErr_enc_naesrk, "na-ESRK", "encoding", true)
		}
		retagged_enc_naesrk, tagErr_enc_naesrk := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, enc_naesrk)
		if tagErr_enc_naesrk != nil {
			return nil, qualifyBERError(tagErr_enc_naesrk, "na-ESRK", "encoding", true)
		}
		enc_naesrk = retagged_enc_naesrk
		children = append(children, enc_naesrk...)
	}
	if v.LocationEstimate != nil {
		if len(*v.LocationEstimate) < 1 || len(*v.LocationEstimate) > 20 {
			if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(nil, "MAP-LCS-DataTypes.SubscriberLocationReport-Arg", ber.RuleRef{Document: "ITU-T X.680", Edition: "02/2021", Clause: "51.5"}), "locationEstimate", "SIZE (1..20)", len(*v.LocationEstimate)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_locationestimate, encodeErr_enc_locationestimate := ber.EncodeOctetString([]byte(*v.LocationEstimate))
		if encodeErr_enc_locationestimate != nil {
			return nil, qualifyBERError(encodeErr_enc_locationestimate, "locationEstimate", "encoding", true)
		}
		retagged_enc_locationestimate, tagErr_enc_locationestimate := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 5, enc_locationestimate)
		if tagErr_enc_locationestimate != nil {
			return nil, qualifyBERError(tagErr_enc_locationestimate, "locationEstimate", "encoding", true)
		}
		enc_locationestimate = retagged_enc_locationestimate
		children = append(children, enc_locationestimate...)
	}
	if v.AgeOfLocationEstimate != nil {
		if !(int64(*v.AgeOfLocationEstimate) >= 0 && int64(*v.AgeOfLocationEstimate) <= 32767) {
			if constraintErr := ber.CheckEncodedValue(ber.EncodeRule(nil, "MAP-LCS-DataTypes.SubscriberLocationReport-Arg", ber.RuleRef{Document: "ITU-T X.680", Edition: "02/2021", Clause: "51.4"}), "ageOfLocationEstimate", "(0..32767)", ber.ObserveInteger(int64(*v.AgeOfLocationEstimate))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_ageoflocationestimate := ber.EncodeInteger(int64(*v.AgeOfLocationEstimate))
		retagged_enc_ageoflocationestimate, tagErr_enc_ageoflocationestimate := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 6, enc_ageoflocationestimate)
		if tagErr_enc_ageoflocationestimate != nil {
			return nil, qualifyBERError(tagErr_enc_ageoflocationestimate, "ageOfLocationEstimate", "encoding", true)
		}
		enc_ageoflocationestimate = retagged_enc_ageoflocationestimate
		children = append(children, enc_ageoflocationestimate...)
	}
	if v.SlrArgExtensionContainer != nil {
		enc_slrargextensioncontainer, err := v.SlrArgExtensionContainer.MarshalDER()
		if err != nil {
			return nil, qualifyBERError(err, "slr-ArgExtensionContainer", "encoding", true)
		}
		retagged_enc_slrargextensioncontainer, tagErr_enc_slrargextensioncontainer := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 7, enc_slrargextensioncontainer)
		if tagErr_enc_slrargextensioncontainer != nil {
			return nil, qualifyBERError(tagErr_enc_slrargextensioncontainer, "slr-ArgExtensionContainer", "encoding", true)
		}
		enc_slrargextensioncontainer = retagged_enc_slrargextensioncontainer
		children = append(children, enc_slrargextensioncontainer...)
	}
	if v.AddLocationEstimate != nil {
		if len(*v.AddLocationEstimate) < 1 || len(*v.AddLocationEstimate) > 91 {
			if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(nil, "MAP-LCS-DataTypes.SubscriberLocationReport-Arg", ber.RuleRef{Document: "ITU-T X.680", Edition: "02/2021", Clause: "51.5"}), "add-LocationEstimate", "SIZE (1..91)", len(*v.AddLocationEstimate)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_addlocationestimate, encodeErr_enc_addlocationestimate := ber.EncodeOctetString([]byte(*v.AddLocationEstimate))
		if encodeErr_enc_addlocationestimate != nil {
			return nil, qualifyBERError(encodeErr_enc_addlocationestimate, "add-LocationEstimate", "encoding", true)
		}
		retagged_enc_addlocationestimate, tagErr_enc_addlocationestimate := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 8, enc_addlocationestimate)
		if tagErr_enc_addlocationestimate != nil {
			return nil, qualifyBERError(tagErr_enc_addlocationestimate, "add-LocationEstimate", "encoding", true)
		}
		enc_addlocationestimate = retagged_enc_addlocationestimate
		children = append(children, enc_addlocationestimate...)
	}
	if v.DeferredmtLrData != nil {
		enc_deferredmtlrdata, err := v.DeferredmtLrData.MarshalDER()
		if err != nil {
			return nil, qualifyBERError(err, "deferredmt-lrData", "encoding", true)
		}
		retagged_enc_deferredmtlrdata, tagErr_enc_deferredmtlrdata := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 9, enc_deferredmtlrdata)
		if tagErr_enc_deferredmtlrdata != nil {
			return nil, qualifyBERError(tagErr_enc_deferredmtlrdata, "deferredmt-lrData", "encoding", true)
		}
		enc_deferredmtlrdata = retagged_enc_deferredmtlrdata
		children = append(children, enc_deferredmtlrdata...)
	}
	if v.LcsReferenceNumber != nil {
		if len(*v.LcsReferenceNumber) < 1 || len(*v.LcsReferenceNumber) > 1 {
			if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(nil, "MAP-LCS-DataTypes.SubscriberLocationReport-Arg", ber.RuleRef{Document: "ITU-T X.680", Edition: "02/2021", Clause: "51.5"}), "lcs-ReferenceNumber", "SIZE (1)", len(*v.LcsReferenceNumber)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_lcsreferencenumber, encodeErr_enc_lcsreferencenumber := ber.EncodeOctetString([]byte(*v.LcsReferenceNumber))
		if encodeErr_enc_lcsreferencenumber != nil {
			return nil, qualifyBERError(encodeErr_enc_lcsreferencenumber, "lcs-ReferenceNumber", "encoding", true)
		}
		retagged_enc_lcsreferencenumber, tagErr_enc_lcsreferencenumber := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 10, enc_lcsreferencenumber)
		if tagErr_enc_lcsreferencenumber != nil {
			return nil, qualifyBERError(tagErr_enc_lcsreferencenumber, "lcs-ReferenceNumber", "encoding", true)
		}
		enc_lcsreferencenumber = retagged_enc_lcsreferencenumber
		children = append(children, enc_lcsreferencenumber...)
	}
	if v.GeranPositioningData != nil {
		if len(*v.GeranPositioningData) < 2 || len(*v.GeranPositioningData) > 10 {
			if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(nil, "MAP-LCS-DataTypes.SubscriberLocationReport-Arg", ber.RuleRef{Document: "ITU-T X.680", Edition: "02/2021", Clause: "51.5"}), "geranPositioningData", "SIZE (2..10)", len(*v.GeranPositioningData)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_geranpositioningdata, encodeErr_enc_geranpositioningdata := ber.EncodeOctetString([]byte(*v.GeranPositioningData))
		if encodeErr_enc_geranpositioningdata != nil {
			return nil, qualifyBERError(encodeErr_enc_geranpositioningdata, "geranPositioningData", "encoding", true)
		}
		retagged_enc_geranpositioningdata, tagErr_enc_geranpositioningdata := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 11, enc_geranpositioningdata)
		if tagErr_enc_geranpositioningdata != nil {
			return nil, qualifyBERError(tagErr_enc_geranpositioningdata, "geranPositioningData", "encoding", true)
		}
		enc_geranpositioningdata = retagged_enc_geranpositioningdata
		children = append(children, enc_geranpositioningdata...)
	}
	if v.UtranPositioningData != nil {
		if len(*v.UtranPositioningData) < 3 || len(*v.UtranPositioningData) > 11 {
			if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(nil, "MAP-LCS-DataTypes.SubscriberLocationReport-Arg", ber.RuleRef{Document: "ITU-T X.680", Edition: "02/2021", Clause: "51.5"}), "utranPositioningData", "SIZE (3..11)", len(*v.UtranPositioningData)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_utranpositioningdata, encodeErr_enc_utranpositioningdata := ber.EncodeOctetString([]byte(*v.UtranPositioningData))
		if encodeErr_enc_utranpositioningdata != nil {
			return nil, qualifyBERError(encodeErr_enc_utranpositioningdata, "utranPositioningData", "encoding", true)
		}
		retagged_enc_utranpositioningdata, tagErr_enc_utranpositioningdata := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 12, enc_utranpositioningdata)
		if tagErr_enc_utranpositioningdata != nil {
			return nil, qualifyBERError(tagErr_enc_utranpositioningdata, "utranPositioningData", "encoding", true)
		}
		enc_utranpositioningdata = retagged_enc_utranpositioningdata
		children = append(children, enc_utranpositioningdata...)
	}
	if v.CellIdOrSai != nil {
		enc_cellidorsai, err := v.CellIdOrSai.MarshalDER()
		if err != nil {
			return nil, qualifyBERError(err, "cellIdOrSai", "encoding", true)
		}
		{
			var encodeErr error
			enc_cellidorsai, encodeErr = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 13, enc_cellidorsai)
			if encodeErr != nil {
				return nil, qualifyBERError(encodeErr, "cellIdOrSai", "encoding", true)
			}
		}
		children = append(children, enc_cellidorsai...)
	}
	if v.HGmlcAddress != nil {
		if len(*v.HGmlcAddress) < 5 || len(*v.HGmlcAddress) > 17 {
			if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(nil, "MAP-LCS-DataTypes.SubscriberLocationReport-Arg", ber.RuleRef{Document: "ITU-T X.680", Edition: "02/2021", Clause: "51.5"}), "h-gmlc-Address", "SIZE (5..17)", len(*v.HGmlcAddress)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_hgmlcaddress, encodeErr_enc_hgmlcaddress := ber.EncodeOctetString([]byte(*v.HGmlcAddress))
		if encodeErr_enc_hgmlcaddress != nil {
			return nil, qualifyBERError(encodeErr_enc_hgmlcaddress, "h-gmlc-Address", "encoding", true)
		}
		retagged_enc_hgmlcaddress, tagErr_enc_hgmlcaddress := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 14, enc_hgmlcaddress)
		if tagErr_enc_hgmlcaddress != nil {
			return nil, qualifyBERError(tagErr_enc_hgmlcaddress, "h-gmlc-Address", "encoding", true)
		}
		enc_hgmlcaddress = retagged_enc_hgmlcaddress
		children = append(children, enc_hgmlcaddress...)
	}
	if v.LcsServiceTypeID != nil {
		if !(int64(*v.LcsServiceTypeID) >= 0 && int64(*v.LcsServiceTypeID) <= 127) {
			if constraintErr := ber.CheckEncodedValue(ber.EncodeRule(nil, "MAP-LCS-DataTypes.SubscriberLocationReport-Arg", ber.RuleRef{Document: "ITU-T X.680", Edition: "02/2021", Clause: "51.4"}), "lcsServiceTypeID", "(0..127)", ber.ObserveInteger(int64(*v.LcsServiceTypeID))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_lcsservicetypeid := ber.EncodeInteger(int64(*v.LcsServiceTypeID))
		retagged_enc_lcsservicetypeid, tagErr_enc_lcsservicetypeid := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 15, enc_lcsservicetypeid)
		if tagErr_enc_lcsservicetypeid != nil {
			return nil, qualifyBERError(tagErr_enc_lcsservicetypeid, "lcsServiceTypeID", "encoding", true)
		}
		enc_lcsservicetypeid = retagged_enc_lcsservicetypeid
		children = append(children, enc_lcsservicetypeid...)
	}
	if v.SaiPresent != nil {
		enc_saipresent := ber.EncodeNull()
		retagged_enc_saipresent, tagErr_enc_saipresent := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 17, enc_saipresent)
		if tagErr_enc_saipresent != nil {
			return nil, qualifyBERError(tagErr_enc_saipresent, "sai-Present", "encoding", true)
		}
		enc_saipresent = retagged_enc_saipresent
		children = append(children, enc_saipresent...)
	}
	if v.PseudonymIndicator != nil {
		enc_pseudonymindicator := ber.EncodeNull()
		retagged_enc_pseudonymindicator, tagErr_enc_pseudonymindicator := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 18, enc_pseudonymindicator)
		if tagErr_enc_pseudonymindicator != nil {
			return nil, qualifyBERError(tagErr_enc_pseudonymindicator, "pseudonymIndicator", "encoding", true)
		}
		enc_pseudonymindicator = retagged_enc_pseudonymindicator
		children = append(children, enc_pseudonymindicator...)
	}
	if v.AccuracyFulfilmentIndicator != nil {
		enc_accuracyfulfilmentindicator := ber.EncodeEnumerated(int64(*v.AccuracyFulfilmentIndicator))
		retagged_enc_accuracyfulfilmentindicator, tagErr_enc_accuracyfulfilmentindicator := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 19, enc_accuracyfulfilmentindicator)
		if tagErr_enc_accuracyfulfilmentindicator != nil {
			return nil, qualifyBERError(tagErr_enc_accuracyfulfilmentindicator, "accuracyFulfilmentIndicator", "encoding", true)
		}
		enc_accuracyfulfilmentindicator = retagged_enc_accuracyfulfilmentindicator
		children = append(children, enc_accuracyfulfilmentindicator...)
	}
	if v.VelocityEstimate != nil {
		if len(*v.VelocityEstimate) < 4 || len(*v.VelocityEstimate) > 7 {
			if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(nil, "MAP-LCS-DataTypes.SubscriberLocationReport-Arg", ber.RuleRef{Document: "ITU-T X.680", Edition: "02/2021", Clause: "51.5"}), "velocityEstimate", "SIZE (4..7)", len(*v.VelocityEstimate)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_velocityestimate, encodeErr_enc_velocityestimate := ber.EncodeOctetString([]byte(*v.VelocityEstimate))
		if encodeErr_enc_velocityestimate != nil {
			return nil, qualifyBERError(encodeErr_enc_velocityestimate, "velocityEstimate", "encoding", true)
		}
		retagged_enc_velocityestimate, tagErr_enc_velocityestimate := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 20, enc_velocityestimate)
		if tagErr_enc_velocityestimate != nil {
			return nil, qualifyBERError(tagErr_enc_velocityestimate, "velocityEstimate", "encoding", true)
		}
		enc_velocityestimate = retagged_enc_velocityestimate
		children = append(children, enc_velocityestimate...)
	}
	if v.SequenceNumber != nil {
		if !(int64(*v.SequenceNumber) >= 1 && int64(*v.SequenceNumber) <= 8639999) {
			if constraintErr := ber.CheckEncodedValue(ber.EncodeRule(nil, "MAP-LCS-DataTypes.SubscriberLocationReport-Arg", ber.RuleRef{Document: "ITU-T X.680", Edition: "02/2021", Clause: "51.4"}), "sequenceNumber", "(1..8639999)", ber.ObserveInteger(int64(*v.SequenceNumber))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_sequencenumber := ber.EncodeInteger(int64(*v.SequenceNumber))
		retagged_enc_sequencenumber, tagErr_enc_sequencenumber := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 21, enc_sequencenumber)
		if tagErr_enc_sequencenumber != nil {
			return nil, qualifyBERError(tagErr_enc_sequencenumber, "sequenceNumber", "encoding", true)
		}
		enc_sequencenumber = retagged_enc_sequencenumber
		children = append(children, enc_sequencenumber...)
	}
	if v.PeriodicLDRInfo != nil {
		enc_periodicldrinfo, err := v.PeriodicLDRInfo.MarshalDER()
		if err != nil {
			return nil, qualifyBERError(err, "periodicLDRInfo", "encoding", true)
		}
		retagged_enc_periodicldrinfo, tagErr_enc_periodicldrinfo := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 22, enc_periodicldrinfo)
		if tagErr_enc_periodicldrinfo != nil {
			return nil, qualifyBERError(tagErr_enc_periodicldrinfo, "periodicLDRInfo", "encoding", true)
		}
		enc_periodicldrinfo = retagged_enc_periodicldrinfo
		children = append(children, enc_periodicldrinfo...)
	}
	if v.MoLrShortCircuitIndicator != nil {
		enc_molrshortcircuitindicator := ber.EncodeNull()
		retagged_enc_molrshortcircuitindicator, tagErr_enc_molrshortcircuitindicator := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 23, enc_molrshortcircuitindicator)
		if tagErr_enc_molrshortcircuitindicator != nil {
			return nil, qualifyBERError(tagErr_enc_molrshortcircuitindicator, "mo-lrShortCircuitIndicator", "encoding", true)
		}
		enc_molrshortcircuitindicator = retagged_enc_molrshortcircuitindicator
		children = append(children, enc_molrshortcircuitindicator...)
	}
	if v.GeranGANSSpositioningData != nil {
		if len(*v.GeranGANSSpositioningData) < 2 || len(*v.GeranGANSSpositioningData) > 10 {
			if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(nil, "MAP-LCS-DataTypes.SubscriberLocationReport-Arg", ber.RuleRef{Document: "ITU-T X.680", Edition: "02/2021", Clause: "51.5"}), "geranGANSSpositioningData", "SIZE (2..10)", len(*v.GeranGANSSpositioningData)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_gerangansspositioningdata, encodeErr_enc_gerangansspositioningdata := ber.EncodeOctetString([]byte(*v.GeranGANSSpositioningData))
		if encodeErr_enc_gerangansspositioningdata != nil {
			return nil, qualifyBERError(encodeErr_enc_gerangansspositioningdata, "geranGANSSpositioningData", "encoding", true)
		}
		retagged_enc_gerangansspositioningdata, tagErr_enc_gerangansspositioningdata := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 24, enc_gerangansspositioningdata)
		if tagErr_enc_gerangansspositioningdata != nil {
			return nil, qualifyBERError(tagErr_enc_gerangansspositioningdata, "geranGANSSpositioningData", "encoding", true)
		}
		enc_gerangansspositioningdata = retagged_enc_gerangansspositioningdata
		children = append(children, enc_gerangansspositioningdata...)
	}
	if v.UtranGANSSpositioningData != nil {
		if len(*v.UtranGANSSpositioningData) < 1 || len(*v.UtranGANSSpositioningData) > 9 {
			if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(nil, "MAP-LCS-DataTypes.SubscriberLocationReport-Arg", ber.RuleRef{Document: "ITU-T X.680", Edition: "02/2021", Clause: "51.5"}), "utranGANSSpositioningData", "SIZE (1..9)", len(*v.UtranGANSSpositioningData)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_utrangansspositioningdata, encodeErr_enc_utrangansspositioningdata := ber.EncodeOctetString([]byte(*v.UtranGANSSpositioningData))
		if encodeErr_enc_utrangansspositioningdata != nil {
			return nil, qualifyBERError(encodeErr_enc_utrangansspositioningdata, "utranGANSSpositioningData", "encoding", true)
		}
		retagged_enc_utrangansspositioningdata, tagErr_enc_utrangansspositioningdata := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 25, enc_utrangansspositioningdata)
		if tagErr_enc_utrangansspositioningdata != nil {
			return nil, qualifyBERError(tagErr_enc_utrangansspositioningdata, "utranGANSSpositioningData", "encoding", true)
		}
		enc_utrangansspositioningdata = retagged_enc_utrangansspositioningdata
		children = append(children, enc_utrangansspositioningdata...)
	}
	if v.TargetServingNodeForHandover != nil {
		enc_targetservingnodeforhandover, err := v.TargetServingNodeForHandover.MarshalDER()
		if err != nil {
			return nil, qualifyBERError(err, "targetServingNodeForHandover", "encoding", true)
		}
		{
			var encodeErr error
			enc_targetservingnodeforhandover, encodeErr = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 26, enc_targetservingnodeforhandover)
			if encodeErr != nil {
				return nil, qualifyBERError(encodeErr, "targetServingNodeForHandover", "encoding", true)
			}
		}
		children = append(children, enc_targetservingnodeforhandover...)
	}
	if v.UtranAdditionalPositioningData != nil {
		if len(*v.UtranAdditionalPositioningData) < 1 || len(*v.UtranAdditionalPositioningData) > 8 {
			if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(nil, "MAP-LCS-DataTypes.SubscriberLocationReport-Arg", ber.RuleRef{Document: "ITU-T X.680", Edition: "02/2021", Clause: "51.5"}), "utranAdditionalPositioningData", "SIZE (1..8)", len(*v.UtranAdditionalPositioningData)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_utranadditionalpositioningdata, encodeErr_enc_utranadditionalpositioningdata := ber.EncodeOctetString([]byte(*v.UtranAdditionalPositioningData))
		if encodeErr_enc_utranadditionalpositioningdata != nil {
			return nil, qualifyBERError(encodeErr_enc_utranadditionalpositioningdata, "utranAdditionalPositioningData", "encoding", true)
		}
		retagged_enc_utranadditionalpositioningdata, tagErr_enc_utranadditionalpositioningdata := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 27, enc_utranadditionalpositioningdata)
		if tagErr_enc_utranadditionalpositioningdata != nil {
			return nil, qualifyBERError(tagErr_enc_utranadditionalpositioningdata, "utranAdditionalPositioningData", "encoding", true)
		}
		enc_utranadditionalpositioningdata = retagged_enc_utranadditionalpositioningdata
		children = append(children, enc_utranadditionalpositioningdata...)
	}
	if v.UtranBaroPressureMeas != nil {
		if !(int64(*v.UtranBaroPressureMeas) >= 30000 && int64(*v.UtranBaroPressureMeas) <= 115000) {
			if constraintErr := ber.CheckEncodedValue(ber.EncodeRule(nil, "MAP-LCS-DataTypes.SubscriberLocationReport-Arg", ber.RuleRef{Document: "ITU-T X.680", Edition: "02/2021", Clause: "51.4"}), "utranBaroPressureMeas", "(30000..115000)", ber.ObserveInteger(int64(*v.UtranBaroPressureMeas))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_utranbaropressuremeas := ber.EncodeInteger(int64(*v.UtranBaroPressureMeas))
		retagged_enc_utranbaropressuremeas, tagErr_enc_utranbaropressuremeas := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 28, enc_utranbaropressuremeas)
		if tagErr_enc_utranbaropressuremeas != nil {
			return nil, qualifyBERError(tagErr_enc_utranbaropressuremeas, "utranBaroPressureMeas", "encoding", true)
		}
		enc_utranbaropressuremeas = retagged_enc_utranbaropressuremeas
		children = append(children, enc_utranbaropressuremeas...)
	}
	if v.UtranCivicAddress != nil {
		enc_utrancivicaddress, encodeErr_enc_utrancivicaddress := ber.EncodeOctetString([]byte(*v.UtranCivicAddress))
		if encodeErr_enc_utrancivicaddress != nil {
			return nil, qualifyBERError(encodeErr_enc_utrancivicaddress, "utranCivicAddress", "encoding", true)
		}
		retagged_enc_utrancivicaddress, tagErr_enc_utrancivicaddress := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 29, enc_utrancivicaddress)
		if tagErr_enc_utrancivicaddress != nil {
			return nil, qualifyBERError(tagErr_enc_utrancivicaddress, "utranCivicAddress", "encoding", true)
		}
		enc_utrancivicaddress = retagged_enc_utrancivicaddress
		children = append(children, enc_utrancivicaddress...)
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
		if i == 0 && ((peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 29) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 28) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 27) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 26) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 25) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 24) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 23) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 22) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 21) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 20) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 19) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 18) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 17) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 15) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 14) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 13) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 12) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 11) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 10) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 9) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 8) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 7) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 6) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 5) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0)) {
			if constraintErr := ber.CheckEncodedValue(ber.EncodeRule(nil, "MAP-LCS-DataTypes.SubscriberLocationReport-Arg", ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
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
		return nil, fmt.Errorf("%s: %w", "encoding LCSSubscriberLocationReportArg as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}
func (v *LCSSubscriberLocationReportArg) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	encoded, err := v.MarshalDER()
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBER decodes LCSSubscriberLocationReportArg from BER/DER format.
func (destination *LCSSubscriberLocationReportArg) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if destination == nil {
		return fmt.Errorf("%w: LCSSubscriberLocationReportArg destination is nil", ber.ErrInvalidValue)
	}
	var berNextValue_ LCSSubscriberLocationReportArg
	v :=

		&berNextValue_
	defer func() {
		if returnErr ==
			nil {
			*destination = *v
		}
	}()

	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	ownedData, ownErr := ber.OwnGeneratedBERInput(data, opts)
	if ownErr != nil {
		return ownErr
	}
	data = ownedData
	preparedData, preparedOptions, prepareErr := ber.PrepareGeneratedBERInput(data, opts)
	if prepareErr != nil {
		return ber.DiagnosePreflight(prepareErr, data, opts, "child", func(probeOpts []ber.DecodeOption) error {
			var probe LCSSubscriberLocationReportArg
			return probe.UnmarshalBER(data, probeOpts...)
		})
	}
	data, opts = preparedData, preparedOptions
	opts = ber.LocateDecodedElement(data, "MAP-LCS-DataTypes.SubscriberLocationReport-Arg", opts)
	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
	*v = LCSSubscriberLocationReportArg{}
	defer func() {
		if returnErr != nil || !ber.BERNeedsPreservation(opts) {
			return
		}
		v.berReplayNode_ = ber.CaptureGeneratedBERReplay(data, opts)
		returnErr = ber.CompleteGeneratedBERDecode(opts, v, func(base *LCSSubscriberLocationReportArg, replayOpts ...ber.EncodeOption) ([]byte, error) {
			return base.MarshalBER(replayOpts...)
		})
	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("%s: %w", "decoding LCSSubscriberLocationReportArg SEQUENCE", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "LCSSubscriberLocationReportArg", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode lcs-Event
	if offset >= len(content) {
		return fmt.Errorf("missing required field lcs-Event")
	}
	{
		ber.MarkPreflightTarget(opts, "lcs-Event", content[offset:])
		val_lcsevent, n, err := ber.DecodeEnumerated(content[offset:], opts...)
		if err != nil {
			return qualifyBERError(err, "lcs-Event", "decoding", false)
		}
		v.LcsEvent = LCSLCSEvent(val_lcsevent)
		if offset > len(content) || n < 0 || n > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n
	}
	// Decode lcs-ClientID
	if offset >= len(content) {
		return fmt.Errorf("missing required field lcs-ClientID")
	}
	{
		ber.MarkPreflightTarget(opts, "lcs-ClientID", content[offset:])
		// Decode nested SEQUENCE (LCSLCSClientID)
		_, n_lcsclientid, _, tlvErr_lcsclientid := ber.DecodeTLV(content[offset:], opts...)
		if tlvErr_lcsclientid != nil {
			return qualifyBERError(tlvErr_lcsclientid, "lcs-ClientID", "decoding", false)
		}
		if offset < 0 || offset >
			len(content) || n_lcsclientid < 0 || n_lcsclientid > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		if unmErr := v.LcsClientID.UnmarshalBER(content[offset:offset+n_lcsclientid], ber.ChildDecodeOptions(opts, "lcs-ClientID")...); unmErr != nil {
			return qualifyBERError(unmErr, "lcs-ClientID", "decoding", false)
		}
		if offset < 0 || offset >
			len(content) || n_lcsclientid < 0 || n_lcsclientid > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n_lcsclientid
	}
	// Decode lcsLocationInfo
	if offset >= len(content) {
		return fmt.Errorf("missing required field lcsLocationInfo")
	}
	{
		ber.MarkPreflightTarget(opts, "lcsLocationInfo", content[offset:])
		// Decode nested SEQUENCE (LCSLCSLocationInfo)
		_, n_lcslocationinfo, _, tlvErr_lcslocationinfo := ber.DecodeTLV(content[offset:], opts...)
		if tlvErr_lcslocationinfo != nil {
			return qualifyBERError(tlvErr_lcslocationinfo, "lcsLocationInfo", "decoding", false)
		}
		if offset < 0 || offset >
			len(content) || n_lcslocationinfo < 0 || n_lcslocationinfo > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		if unmErr := v.LcsLocationInfo.UnmarshalBER(content[offset:offset+n_lcslocationinfo], ber.ChildDecodeOptions(opts, "lcsLocationInfo")...); unmErr != nil {
			return qualifyBERError(unmErr, "lcsLocationInfo", "decoding", false)
		}
		if offset < 0 || offset >
			len(content) || n_lcslocationinfo < 0 || n_lcslocationinfo > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n_lcslocationinfo
	}
	// Decode msisdn
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
				ber.MarkPreflightTarget(opts, "msisdn", content[offset:])
				decodedTag_msisdn, n_msisdn, rawVal_msisdn, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "msisdn", "decoding", false)
				}
				if decodedTag_msisdn.Class != tag.ClassContextSpecific || decodedTag_msisdn.Number != 0 {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_msisdn), "msisdn", "decoding", false)
				}
				decVal_msisdn, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_msisdn.Constructed, rawVal_msisdn, opts...)
				if octetErr != nil {
					return qualifyBERError(octetErr, "msisdn", "decoding", false)
				}
				tmp_msisdn := v21_map_commondatatypes.CommonDataTypesISDNAddressString(decVal_msisdn)
				v.Msisdn = &tmp_msisdn
				if offset < 0 || offset >
					len(content) || n_msisdn < 0 || n_msisdn > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_msisdn
				if len(*v.Msisdn) < 1 || len(*v.Msisdn) > 9 {
					if constraintErr := ber.CheckDecodedLength(ber.DecodeRule(opts, "MAP-LCS-DataTypes.SubscriberLocationReport-Arg", ber.RuleRef{Document: "ITU-T X.680", Edition: "02/2021", Clause: "51.5"}), "msisdn", "SIZE (1..9)", len(*v.Msisdn)); constraintErr != nil {
						return constraintErr
					}
				}
				if len(*v.Msisdn) < 1 || len(*v.Msisdn) > 20 {
					if constraintErr := ber.CheckDecodedLength(ber.DecodeRule(opts, "MAP-LCS-DataTypes.SubscriberLocationReport-Arg", ber.RuleRef{Document: "ITU-T X.680", Edition: "02/2021", Clause: "51.5"}), "msisdn", "SIZE (1..20)", len(*v.Msisdn)); constraintErr != nil {
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
				ber.MarkPreflightTarget(opts, "imsi", content[offset:])
				decodedTag_imsi, n_imsi, rawVal_imsi, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "imsi", "decoding", false)
				}
				if decodedTag_imsi.Class != tag.ClassContextSpecific || decodedTag_imsi.Number != 1 {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_imsi), "imsi", "decoding", false)
				}
				decVal_imsi, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_imsi.Constructed, rawVal_imsi, opts...)
				if octetErr != nil {
					return qualifyBERError(octetErr, "imsi", "decoding", false)
				}
				tmp_imsi := v21_map_commondatatypes.CommonDataTypesIMSI(decVal_imsi)
				v.Imsi = &tmp_imsi
				if offset < 0 || offset >
					len(content) || n_imsi < 0 || n_imsi > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_imsi
				if len(*v.Imsi) < 3 || len(*v.Imsi) > 8 {
					if constraintErr := ber.CheckDecodedLength(ber.DecodeRule(opts, "MAP-LCS-DataTypes.SubscriberLocationReport-Arg", ber.RuleRef{Document: "ITU-T X.680", Edition: "02/2021", Clause: "51.5"}), "imsi", "SIZE (3..8)", len(*v.Imsi)); constraintErr != nil {
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
				ber.MarkPreflightTarget(opts, "imei", content[offset:])
				decodedTag_imei, n_imei, rawVal_imei, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "imei", "decoding", false)
				}
				if decodedTag_imei.Class != tag.ClassContextSpecific || decodedTag_imei.Number != 2 {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_imei), "imei", "decoding", false)
				}
				decVal_imei, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_imei.Constructed, rawVal_imei, opts...)
				if octetErr != nil {
					return qualifyBERError(octetErr, "imei", "decoding", false)
				}
				tmp_imei := v21_map_commondatatypes.CommonDataTypesIMEI(decVal_imei)
				v.Imei = &tmp_imei
				if offset < 0 || offset >
					len(content) || n_imei < 0 || n_imei > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_imei
				if len(*v.Imei) < 8 || len(*v.Imei) > 8 {
					if constraintErr := ber.CheckDecodedLength(ber.DecodeRule(opts, "MAP-LCS-DataTypes.SubscriberLocationReport-Arg", ber.RuleRef{Document: "ITU-T X.680", Edition: "02/2021", Clause: "51.5"}), "imei", "SIZE (8)", len(*v.Imei)); constraintErr != nil {
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
				ber.MarkPreflightTarget(opts, "na-ESRD", content[offset:])
				decodedTag_naesrd, n_naesrd, rawVal_naesrd, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "na-ESRD", "decoding", false)
				}
				if decodedTag_naesrd.Class != tag.ClassContextSpecific || decodedTag_naesrd.Number != 3 {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_naesrd), "na-ESRD", "decoding", false)
				}
				decVal_naesrd, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_naesrd.Constructed, rawVal_naesrd, opts...)
				if octetErr != nil {
					return qualifyBERError(octetErr, "na-ESRD", "decoding", false)
				}
				tmp_naesrd := v21_map_commondatatypes.CommonDataTypesISDNAddressString(decVal_naesrd)
				v.NaESRD = &tmp_naesrd
				if offset < 0 || offset >
					len(content) || n_naesrd < 0 || n_naesrd > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_naesrd
				if len(*v.NaESRD) < 1 || len(*v.NaESRD) > 9 {
					if constraintErr := ber.CheckDecodedLength(ber.DecodeRule(opts, "MAP-LCS-DataTypes.SubscriberLocationReport-Arg", ber.RuleRef{Document: "ITU-T X.680", Edition: "02/2021", Clause: "51.5"}), "na-ESRD", "SIZE (1..9)", len(*v.NaESRD)); constraintErr != nil {
						return constraintErr
					}
				}
				if len(*v.NaESRD) < 1 || len(*v.NaESRD) > 20 {
					if constraintErr := ber.CheckDecodedLength(ber.DecodeRule(opts, "MAP-LCS-DataTypes.SubscriberLocationReport-Arg", ber.RuleRef{Document: "ITU-T X.680", Edition: "02/2021", Clause: "51.5"}), "na-ESRD", "SIZE (1..20)", len(*v.NaESRD)); constraintErr != nil {
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
				ber.MarkPreflightTarget(opts, "na-ESRK", content[offset:])
				decodedTag_naesrk, n_naesrk, rawVal_naesrk, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "na-ESRK", "decoding", false)
				}
				if decodedTag_naesrk.Class != tag.ClassContextSpecific || decodedTag_naesrk.Number != 4 {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_naesrk), "na-ESRK", "decoding", false)
				}
				decVal_naesrk, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_naesrk.Constructed, rawVal_naesrk, opts...)
				if octetErr != nil {
					return qualifyBERError(octetErr, "na-ESRK", "decoding", false)
				}
				tmp_naesrk := v21_map_commondatatypes.CommonDataTypesISDNAddressString(decVal_naesrk)
				v.NaESRK = &tmp_naesrk
				if offset < 0 || offset >
					len(content) || n_naesrk < 0 || n_naesrk > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_naesrk
				if len(*v.NaESRK) < 1 || len(*v.NaESRK) > 9 {
					if constraintErr := ber.CheckDecodedLength(ber.DecodeRule(opts, "MAP-LCS-DataTypes.SubscriberLocationReport-Arg", ber.RuleRef{Document: "ITU-T X.680", Edition: "02/2021", Clause: "51.5"}), "na-ESRK", "SIZE (1..9)", len(*v.NaESRK)); constraintErr != nil {
						return constraintErr
					}
				}
				if len(*v.NaESRK) < 1 || len(*v.NaESRK) > 20 {
					if constraintErr := ber.CheckDecodedLength(ber.DecodeRule(opts, "MAP-LCS-DataTypes.SubscriberLocationReport-Arg", ber.RuleRef{Document: "ITU-T X.680", Edition: "02/2021", Clause: "51.5"}), "na-ESRK", "SIZE (1..20)", len(*v.NaESRK)); constraintErr != nil {
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
				ber.MarkPreflightTarget(opts, "locationEstimate", content[offset:])
				decodedTag_locationestimate, n_locationestimate, rawVal_locationestimate, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "locationEstimate", "decoding", false)
				}
				if decodedTag_locationestimate.Class != tag.ClassContextSpecific || decodedTag_locationestimate.Number != 5 {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_locationestimate), "locationEstimate", "decoding", false)
				}
				decVal_locationestimate, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_locationestimate.Constructed, rawVal_locationestimate, opts...)
				if octetErr != nil {
					return qualifyBERError(octetErr, "locationEstimate", "decoding", false)
				}
				tmp_locationestimate := LCSExtGeographicalInformation(decVal_locationestimate)
				v.LocationEstimate = &tmp_locationestimate
				if offset < 0 || offset >
					len(content) || n_locationestimate < 0 || n_locationestimate > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_locationestimate
				if len(*v.LocationEstimate) < 1 || len(*v.LocationEstimate) > 20 {
					if constraintErr := ber.CheckDecodedLength(ber.DecodeRule(opts, "MAP-LCS-DataTypes.SubscriberLocationReport-Arg", ber.RuleRef{Document: "ITU-T X.680", Edition: "02/2021", Clause: "51.5"}), "locationEstimate", "SIZE (1..20)", len(*v.LocationEstimate)); constraintErr != nil {
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
				ber.MarkPreflightTarget(opts, "ageOfLocationEstimate", content[offset:])
				decodedTag_ageoflocationestimate, n_ageoflocationestimate, rawVal_ageoflocationestimate, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "ageOfLocationEstimate", "decoding", false)
				}
				if decodedTag_ageoflocationestimate.Class != tag.ClassContextSpecific || decodedTag_ageoflocationestimate.Number != 6 || decodedTag_ageoflocationestimate.Constructed != false {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_ageoflocationestimate), "ageOfLocationEstimate", "decoding", false)
				}
				decVal_ageoflocationestimate, intErr := ber.DecodeIntegerValue(rawVal_ageoflocationestimate)
				if intErr != nil {
					return qualifyBERError(intErr, "ageOfLocationEstimate", "decoding", false)
				}
				tmp_ageoflocationestimate := v21_map_commondatatypes.CommonDataTypesAgeOfLocationInformation(decVal_ageoflocationestimate)
				v.AgeOfLocationEstimate = &tmp_ageoflocationestimate
				if offset < 0 || offset >
					len(content) || n_ageoflocationestimate < 0 || n_ageoflocationestimate >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_ageoflocationestimate
				if !(int64(*v.AgeOfLocationEstimate) >= 0 && int64(*v.AgeOfLocationEstimate) <= 32767) {
					if constraintErr := ber.CheckDecodedValue(ber.DecodeRule(opts, "MAP-LCS-DataTypes.SubscriberLocationReport-Arg", ber.RuleRef{Document: "ITU-T X.680", Edition: "02/2021", Clause: "51.4"}), "ageOfLocationEstimate", "(0..32767)", ber.ObserveInteger(int64(*v.AgeOfLocationEstimate))); constraintErr != nil {
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
				ber.MarkPreflightTarget(opts, "slr-ArgExtensionContainer", content[offset:])
				decodedTag_slrargextensioncontainer, n_slrargextensioncontainer, rawVal_slrargextensioncontainer, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "slr-ArgExtensionContainer", "decoding", false)
				}
				if decodedTag_slrargextensioncontainer.Class != tag.ClassContextSpecific || decodedTag_slrargextensioncontainer.Number != 7 || decodedTag_slrargextensioncontainer.Constructed != true {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_slrargextensioncontainer), "slr-ArgExtensionContainer", "decoding", false)
				}
				_ = rawVal_slrargextensioncontainer
				if offset < 0 || offset >
					len(content) || n_slrargextensioncontainer < 0 || n_slrargextensioncontainer >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				reconstructed_slrargextensioncontainer, reconstructionErr_slrargextensioncontainer := ber.EncodeImplicitTagWithClass(tag.ClassUniversal, tag.TagSequence, content[offset:offset+n_slrargextensioncontainer])
				if reconstructionErr_slrargextensioncontainer != nil {
					return qualifyBERError(reconstructionErr_slrargextensioncontainer, "slr-ArgExtensionContainer", "decoding", false)
				}
				var dec_slrargextensioncontainer v21_map_extensiondatatypes.ExtensionDataTypesSLRArgExtensionContainer
				if unmErr := dec_slrargextensioncontainer.UnmarshalBER(reconstructed_slrargextensioncontainer, ber.ChildDecodeOptions(opts, "slr-ArgExtensionContainer")...); unmErr != nil {
					return qualifyBERError(unmErr, "slr-ArgExtensionContainer", "decoding", false)
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
				ber.MarkPreflightTarget(opts, "add-LocationEstimate", content[offset:])
				decodedTag_addlocationestimate, n_addlocationestimate, rawVal_addlocationestimate, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "add-LocationEstimate", "decoding", false)
				}
				if decodedTag_addlocationestimate.Class != tag.ClassContextSpecific || decodedTag_addlocationestimate.Number != 8 {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_addlocationestimate), "add-LocationEstimate", "decoding", false)
				}
				decVal_addlocationestimate, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_addlocationestimate.Constructed, rawVal_addlocationestimate, opts...)
				if octetErr != nil {
					return qualifyBERError(octetErr, "add-LocationEstimate", "decoding", false)
				}
				tmp_addlocationestimate := LCSAddGeographicalInformation(decVal_addlocationestimate)
				v.AddLocationEstimate = &tmp_addlocationestimate
				if offset < 0 || offset >
					len(content) || n_addlocationestimate < 0 || n_addlocationestimate > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_addlocationestimate
				if len(*v.AddLocationEstimate) < 1 || len(*v.AddLocationEstimate) > 91 {
					if constraintErr := ber.CheckDecodedLength(ber.DecodeRule(opts, "MAP-LCS-DataTypes.SubscriberLocationReport-Arg", ber.RuleRef{Document: "ITU-T X.680", Edition: "02/2021", Clause: "51.5"}), "add-LocationEstimate", "SIZE (1..91)", len(*v.AddLocationEstimate)); constraintErr != nil {
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
				ber.MarkPreflightTarget(opts, "deferredmt-lrData", content[offset:])
				decodedTag_deferredmtlrdata, n_deferredmtlrdata, rawVal_deferredmtlrdata, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "deferredmt-lrData", "decoding", false)
				}
				if decodedTag_deferredmtlrdata.Class != tag.ClassContextSpecific || decodedTag_deferredmtlrdata.Number != 9 || decodedTag_deferredmtlrdata.Constructed != true {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_deferredmtlrdata), "deferredmt-lrData", "decoding", false)
				}
				_ = rawVal_deferredmtlrdata
				if offset < 0 || offset >
					len(content) || n_deferredmtlrdata < 0 || n_deferredmtlrdata > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				reconstructed_deferredmtlrdata, reconstructionErr_deferredmtlrdata := ber.EncodeImplicitTagWithClass(tag.ClassUniversal, tag.TagSequence, content[offset:offset+n_deferredmtlrdata])
				if reconstructionErr_deferredmtlrdata != nil {
					return qualifyBERError(reconstructionErr_deferredmtlrdata, "deferredmt-lrData", "decoding", false)
				}
				var dec_deferredmtlrdata LCSDeferredmtLrData
				if unmErr := dec_deferredmtlrdata.UnmarshalBER(reconstructed_deferredmtlrdata, ber.ChildDecodeOptions(opts, "deferredmt-lrData")...); unmErr != nil {
					return qualifyBERError(unmErr, "deferredmt-lrData", "decoding", false)
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
				ber.MarkPreflightTarget(opts, "lcs-ReferenceNumber", content[offset:])
				decodedTag_lcsreferencenumber, n_lcsreferencenumber, rawVal_lcsreferencenumber, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "lcs-ReferenceNumber", "decoding", false)
				}
				if decodedTag_lcsreferencenumber.Class != tag.ClassContextSpecific || decodedTag_lcsreferencenumber.Number != 10 {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_lcsreferencenumber), "lcs-ReferenceNumber", "decoding", false)
				}
				decVal_lcsreferencenumber, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_lcsreferencenumber.Constructed, rawVal_lcsreferencenumber, opts...)
				if octetErr != nil {
					return qualifyBERError(octetErr, "lcs-ReferenceNumber", "decoding", false)
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
					if constraintErr := ber.CheckDecodedLength(ber.DecodeRule(opts, "MAP-LCS-DataTypes.SubscriberLocationReport-Arg", ber.RuleRef{Document: "ITU-T X.680", Edition: "02/2021", Clause: "51.5"}), "lcs-ReferenceNumber", "SIZE (1)", len(*v.LcsReferenceNumber)); constraintErr != nil {
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
				ber.MarkPreflightTarget(opts, "geranPositioningData", content[offset:])
				decodedTag_geranpositioningdata, n_geranpositioningdata, rawVal_geranpositioningdata, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "geranPositioningData", "decoding", false)
				}
				if decodedTag_geranpositioningdata.Class != tag.ClassContextSpecific || decodedTag_geranpositioningdata.Number != 11 {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_geranpositioningdata), "geranPositioningData", "decoding", false)
				}
				decVal_geranpositioningdata, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_geranpositioningdata.Constructed, rawVal_geranpositioningdata, opts...)
				if octetErr != nil {
					return qualifyBERError(octetErr, "geranPositioningData", "decoding", false)
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
					if constraintErr := ber.CheckDecodedLength(ber.DecodeRule(opts, "MAP-LCS-DataTypes.SubscriberLocationReport-Arg", ber.RuleRef{Document: "ITU-T X.680", Edition: "02/2021", Clause: "51.5"}), "geranPositioningData", "SIZE (2..10)", len(*v.GeranPositioningData)); constraintErr != nil {
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
				ber.MarkPreflightTarget(opts, "utranPositioningData", content[offset:])
				decodedTag_utranpositioningdata, n_utranpositioningdata, rawVal_utranpositioningdata, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "utranPositioningData", "decoding", false)
				}
				if decodedTag_utranpositioningdata.Class != tag.ClassContextSpecific || decodedTag_utranpositioningdata.Number != 12 {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_utranpositioningdata), "utranPositioningData", "decoding", false)
				}
				decVal_utranpositioningdata, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_utranpositioningdata.Constructed, rawVal_utranpositioningdata, opts...)
				if octetErr != nil {
					return qualifyBERError(octetErr, "utranPositioningData", "decoding", false)
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
					if constraintErr := ber.CheckDecodedLength(ber.DecodeRule(opts, "MAP-LCS-DataTypes.SubscriberLocationReport-Arg", ber.RuleRef{Document: "ITU-T X.680", Edition: "02/2021", Clause: "51.5"}), "utranPositioningData", "SIZE (3..11)", len(*v.UtranPositioningData)); constraintErr != nil {
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
				ber.MarkPreflightTarget(opts, "cellIdOrSai", content[offset:])
				decodedTag_cellidorsai, n_cellidorsai, innerData_cellidorsai, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "cellIdOrSai", "decoding", false)
				}
				if decodedTag_cellidorsai.Class != tag.ClassContextSpecific || decodedTag_cellidorsai.Number != 13 || decodedTag_cellidorsai.Constructed != true {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_cellidorsai), "cellIdOrSai", "decoding", false)
				}
				_, innerUsed_cellidorsai, _, innerErr_cellidorsai := ber.DecodeTLV(innerData_cellidorsai, opts...)
				if innerErr_cellidorsai != nil {
					return qualifyBERError(innerErr_cellidorsai, "cellIdOrSai", "decoding", false)
				}
				if innerUsed_cellidorsai != len(innerData_cellidorsai) {
					return qualifyBERError(ber.ErrExtraData, "cellIdOrSai", "decoding", false)
				}
				// Decode inner value from explicit tag wrapper
				ber.MarkPreflightTarget(opts, "cellIdOrSai", innerData_cellidorsai)
				var dec_cellidorsai v21_map_commondatatypes.CommonDataTypesCellGlobalIdOrServiceAreaIdOrLAI
				if unmErr := dec_cellidorsai.UnmarshalBER(innerData_cellidorsai, ber.ChildDecodeOptions(opts, "cellIdOrSai")...); unmErr != nil {
					return qualifyBERError(unmErr, "cellIdOrSai", "decoding", false)
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
				ber.MarkPreflightTarget(opts, "h-gmlc-Address", content[offset:])
				decodedTag_hgmlcaddress, n_hgmlcaddress, rawVal_hgmlcaddress, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "h-gmlc-Address", "decoding", false)
				}
				if decodedTag_hgmlcaddress.Class != tag.ClassContextSpecific || decodedTag_hgmlcaddress.Number != 14 {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_hgmlcaddress), "h-gmlc-Address", "decoding", false)
				}
				decVal_hgmlcaddress, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_hgmlcaddress.Constructed, rawVal_hgmlcaddress, opts...)
				if octetErr != nil {
					return qualifyBERError(octetErr, "h-gmlc-Address", "decoding", false)
				}
				tmp_hgmlcaddress := v21_map_commondatatypes.CommonDataTypesGSNAddress(decVal_hgmlcaddress)
				v.HGmlcAddress = &tmp_hgmlcaddress
				if offset < 0 || offset >
					len(content) || n_hgmlcaddress < 0 || n_hgmlcaddress > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_hgmlcaddress
				if len(*v.HGmlcAddress) < 5 || len(*v.HGmlcAddress) > 17 {
					if constraintErr := ber.CheckDecodedLength(ber.DecodeRule(opts, "MAP-LCS-DataTypes.SubscriberLocationReport-Arg", ber.RuleRef{Document: "ITU-T X.680", Edition: "02/2021", Clause: "51.5"}), "h-gmlc-Address", "SIZE (5..17)", len(*v.HGmlcAddress)); constraintErr != nil {
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
				ber.MarkPreflightTarget(opts, "lcsServiceTypeID", content[offset:])
				decodedTag_lcsservicetypeid, n_lcsservicetypeid, rawVal_lcsservicetypeid, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "lcsServiceTypeID", "decoding", false)
				}
				if decodedTag_lcsservicetypeid.Class != tag.ClassContextSpecific || decodedTag_lcsservicetypeid.Number != 15 || decodedTag_lcsservicetypeid.Constructed != false {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_lcsservicetypeid), "lcsServiceTypeID", "decoding", false)
				}
				decVal_lcsservicetypeid, intErr := ber.DecodeIntegerValue(rawVal_lcsservicetypeid)
				if intErr != nil {
					return qualifyBERError(intErr, "lcsServiceTypeID", "decoding", false)
				}
				tmp_lcsservicetypeid := v21_map_commondatatypes.CommonDataTypesLCSServiceTypeID(decVal_lcsservicetypeid)
				v.LcsServiceTypeID = &tmp_lcsservicetypeid
				if offset < 0 || offset >
					len(content) || n_lcsservicetypeid < 0 || n_lcsservicetypeid > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_lcsservicetypeid
				if !(int64(*v.LcsServiceTypeID) >= 0 && int64(*v.LcsServiceTypeID) <= 127) {
					if constraintErr := ber.CheckDecodedValue(ber.DecodeRule(opts, "MAP-LCS-DataTypes.SubscriberLocationReport-Arg", ber.RuleRef{Document: "ITU-T X.680", Edition: "02/2021", Clause: "51.4"}), "lcsServiceTypeID", "(0..127)", ber.ObserveInteger(int64(*v.LcsServiceTypeID))); constraintErr != nil {
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
				ber.MarkPreflightTarget(opts, "sai-Present", content[offset:])
				decodedTag_saipresent, n_saipresent, rawVal_saipresent, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "sai-Present", "decoding", false)
				}
				if decodedTag_saipresent.Class != tag.ClassContextSpecific || decodedTag_saipresent.Number != 17 || decodedTag_saipresent.Constructed != false {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_saipresent), "sai-Present", "decoding", false)
				}
				if len(rawVal_saipresent) != 0 {
					return qualifyBERError(fmt.Errorf("%w: NULL content length %d", ber.ErrInvalidValue, len(rawVal_saipresent)), "sai-Present", "decoding", false)
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
				ber.MarkPreflightTarget(opts, "pseudonymIndicator", content[offset:])
				decodedTag_pseudonymindicator, n_pseudonymindicator, rawVal_pseudonymindicator, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "pseudonymIndicator", "decoding", false)
				}
				if decodedTag_pseudonymindicator.Class != tag.ClassContextSpecific || decodedTag_pseudonymindicator.Number != 18 || decodedTag_pseudonymindicator.Constructed != false {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_pseudonymindicator), "pseudonymIndicator", "decoding", false)
				}
				if len(rawVal_pseudonymindicator) != 0 {
					return qualifyBERError(fmt.Errorf("%w: NULL content length %d", ber.ErrInvalidValue, len(rawVal_pseudonymindicator)), "pseudonymIndicator", "decoding", false)
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
				ber.MarkPreflightTarget(opts, "accuracyFulfilmentIndicator", content[offset:])
				decodedTag_accuracyfulfilmentindicator, n_accuracyfulfilmentindicator, rawVal_accuracyfulfilmentindicator, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "accuracyFulfilmentIndicator", "decoding", false)
				}
				if decodedTag_accuracyfulfilmentindicator.Class != tag.ClassContextSpecific || decodedTag_accuracyfulfilmentindicator.Number != 19 || decodedTag_accuracyfulfilmentindicator.Constructed != false {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_accuracyfulfilmentindicator), "accuracyFulfilmentIndicator", "decoding", false)
				}
				decVal_accuracyfulfilmentindicator, intErr := ber.DecodeEnumeratedValue(rawVal_accuracyfulfilmentindicator)
				if intErr != nil {
					return qualifyBERError(intErr, "accuracyFulfilmentIndicator", "decoding", false)
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
				ber.MarkPreflightTarget(opts, "velocityEstimate", content[offset:])
				decodedTag_velocityestimate, n_velocityestimate, rawVal_velocityestimate, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "velocityEstimate", "decoding", false)
				}
				if decodedTag_velocityestimate.Class != tag.ClassContextSpecific || decodedTag_velocityestimate.Number != 20 {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_velocityestimate), "velocityEstimate", "decoding", false)
				}
				decVal_velocityestimate, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_velocityestimate.Constructed, rawVal_velocityestimate, opts...)
				if octetErr != nil {
					return qualifyBERError(octetErr, "velocityEstimate", "decoding", false)
				}
				tmp_velocityestimate := LCSVelocityEstimate(decVal_velocityestimate)
				v.VelocityEstimate = &tmp_velocityestimate
				if offset < 0 || offset >
					len(content) || n_velocityestimate < 0 || n_velocityestimate > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_velocityestimate
				if len(*v.VelocityEstimate) < 4 || len(*v.VelocityEstimate) > 7 {
					if constraintErr := ber.CheckDecodedLength(ber.DecodeRule(opts, "MAP-LCS-DataTypes.SubscriberLocationReport-Arg", ber.RuleRef{Document: "ITU-T X.680", Edition: "02/2021", Clause: "51.5"}), "velocityEstimate", "SIZE (4..7)", len(*v.VelocityEstimate)); constraintErr != nil {
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
				ber.MarkPreflightTarget(opts, "sequenceNumber", content[offset:])
				decodedTag_sequencenumber, n_sequencenumber, rawVal_sequencenumber, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "sequenceNumber", "decoding", false)
				}
				if decodedTag_sequencenumber.Class != tag.ClassContextSpecific || decodedTag_sequencenumber.Number != 21 || decodedTag_sequencenumber.Constructed != false {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_sequencenumber), "sequenceNumber", "decoding", false)
				}
				decVal_sequencenumber, intErr := ber.DecodeIntegerValue(rawVal_sequencenumber)
				if intErr != nil {
					return qualifyBERError(intErr, "sequenceNumber", "decoding", false)
				}
				tmp_sequencenumber := LCSSequenceNumber(decVal_sequencenumber)
				v.SequenceNumber = &tmp_sequencenumber
				if offset < 0 || offset >
					len(content) || n_sequencenumber < 0 || n_sequencenumber > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_sequencenumber
				if !(int64(*v.SequenceNumber) >= 1 && int64(*v.SequenceNumber) <= 8639999) {
					if constraintErr := ber.CheckDecodedValue(ber.DecodeRule(opts, "MAP-LCS-DataTypes.SubscriberLocationReport-Arg", ber.RuleRef{Document: "ITU-T X.680", Edition: "02/2021", Clause: "51.4"}), "sequenceNumber", "(1..8639999)", ber.ObserveInteger(int64(*v.SequenceNumber))); constraintErr != nil {
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
				ber.MarkPreflightTarget(opts, "periodicLDRInfo", content[offset:])
				decodedTag_periodicldrinfo, n_periodicldrinfo, rawVal_periodicldrinfo, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "periodicLDRInfo", "decoding", false)
				}
				if decodedTag_periodicldrinfo.Class != tag.ClassContextSpecific || decodedTag_periodicldrinfo.Number != 22 || decodedTag_periodicldrinfo.Constructed != true {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_periodicldrinfo), "periodicLDRInfo", "decoding", false)
				}
				_ = rawVal_periodicldrinfo
				if offset < 0 || offset >
					len(content) || n_periodicldrinfo < 0 || n_periodicldrinfo > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				reconstructed_periodicldrinfo, reconstructionErr_periodicldrinfo := ber.EncodeImplicitTagWithClass(tag.ClassUniversal, tag.TagSequence, content[offset:offset+n_periodicldrinfo])
				if reconstructionErr_periodicldrinfo != nil {
					return qualifyBERError(reconstructionErr_periodicldrinfo, "periodicLDRInfo", "decoding", false)
				}
				var dec_periodicldrinfo LCSPeriodicLDRInfo
				if unmErr := dec_periodicldrinfo.UnmarshalBER(reconstructed_periodicldrinfo, ber.ChildDecodeOptions(opts, "periodicLDRInfo")...); unmErr != nil {
					return qualifyBERError(unmErr, "periodicLDRInfo", "decoding", false)
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
				ber.MarkPreflightTarget(opts, "mo-lrShortCircuitIndicator", content[offset:])
				decodedTag_molrshortcircuitindicator, n_molrshortcircuitindicator, rawVal_molrshortcircuitindicator, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "mo-lrShortCircuitIndicator", "decoding", false)
				}
				if decodedTag_molrshortcircuitindicator.Class != tag.ClassContextSpecific || decodedTag_molrshortcircuitindicator.Number != 23 || decodedTag_molrshortcircuitindicator.Constructed != false {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_molrshortcircuitindicator), "mo-lrShortCircuitIndicator", "decoding", false)
				}
				if len(rawVal_molrshortcircuitindicator) != 0 {
					return qualifyBERError(fmt.Errorf("%w: NULL content length %d", ber.ErrInvalidValue, len(rawVal_molrshortcircuitindicator)), "mo-lrShortCircuitIndicator", "decoding", false)
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
				ber.MarkPreflightTarget(opts, "geranGANSSpositioningData", content[offset:])
				decodedTag_gerangansspositioningdata, n_gerangansspositioningdata, rawVal_gerangansspositioningdata, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "geranGANSSpositioningData", "decoding", false)
				}
				if decodedTag_gerangansspositioningdata.Class != tag.ClassContextSpecific || decodedTag_gerangansspositioningdata.Number != 24 {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_gerangansspositioningdata), "geranGANSSpositioningData", "decoding", false)
				}
				decVal_gerangansspositioningdata, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_gerangansspositioningdata.Constructed, rawVal_gerangansspositioningdata, opts...)
				if octetErr != nil {
					return qualifyBERError(octetErr, "geranGANSSpositioningData", "decoding", false)
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
					if constraintErr := ber.CheckDecodedLength(ber.DecodeRule(opts, "MAP-LCS-DataTypes.SubscriberLocationReport-Arg", ber.RuleRef{Document: "ITU-T X.680", Edition: "02/2021", Clause: "51.5"}), "geranGANSSpositioningData", "SIZE (2..10)", len(*v.GeranGANSSpositioningData)); constraintErr != nil {
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
				ber.MarkPreflightTarget(opts, "utranGANSSpositioningData", content[offset:])
				decodedTag_utrangansspositioningdata, n_utrangansspositioningdata, rawVal_utrangansspositioningdata, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "utranGANSSpositioningData", "decoding", false)
				}
				if decodedTag_utrangansspositioningdata.Class != tag.ClassContextSpecific || decodedTag_utrangansspositioningdata.Number != 25 {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_utrangansspositioningdata), "utranGANSSpositioningData", "decoding", false)
				}
				decVal_utrangansspositioningdata, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_utrangansspositioningdata.Constructed, rawVal_utrangansspositioningdata, opts...)
				if octetErr != nil {
					return qualifyBERError(octetErr, "utranGANSSpositioningData", "decoding", false)
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
					if constraintErr := ber.CheckDecodedLength(ber.DecodeRule(opts, "MAP-LCS-DataTypes.SubscriberLocationReport-Arg", ber.RuleRef{Document: "ITU-T X.680", Edition: "02/2021", Clause: "51.5"}), "utranGANSSpositioningData", "SIZE (1..9)", len(*v.UtranGANSSpositioningData)); constraintErr != nil {
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
				ber.MarkPreflightTarget(opts, "targetServingNodeForHandover", content[offset:])
				decodedTag_targetservingnodeforhandover, n_targetservingnodeforhandover, innerData_targetservingnodeforhandover, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "targetServingNodeForHandover", "decoding", false)
				}
				if decodedTag_targetservingnodeforhandover.Class != tag.ClassContextSpecific || decodedTag_targetservingnodeforhandover.Number != 26 || decodedTag_targetservingnodeforhandover.Constructed != true {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_targetservingnodeforhandover), "targetServingNodeForHandover", "decoding", false)
				}
				_, innerUsed_targetservingnodeforhandover, _, innerErr_targetservingnodeforhandover := ber.DecodeTLV(innerData_targetservingnodeforhandover, opts...)
				if innerErr_targetservingnodeforhandover != nil {
					return qualifyBERError(innerErr_targetservingnodeforhandover, "targetServingNodeForHandover", "decoding", false)
				}
				if innerUsed_targetservingnodeforhandover != len(innerData_targetservingnodeforhandover) {
					return qualifyBERError(ber.ErrExtraData, "targetServingNodeForHandover", "decoding", false)
				}
				// Decode inner value from explicit tag wrapper
				ber.MarkPreflightTarget(opts, "targetServingNodeForHandover", innerData_targetservingnodeforhandover)
				var dec_targetservingnodeforhandover LCSServingNodeAddress
				if unmErr := dec_targetservingnodeforhandover.UnmarshalBER(innerData_targetservingnodeforhandover, ber.ChildDecodeOptions(opts, "targetServingNodeForHandover")...); unmErr != nil {
					return qualifyBERError(unmErr, "targetServingNodeForHandover", "decoding", false)
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
				ber.MarkPreflightTarget(opts, "utranAdditionalPositioningData", content[offset:])
				decodedTag_utranadditionalpositioningdata, n_utranadditionalpositioningdata, rawVal_utranadditionalpositioningdata, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "utranAdditionalPositioningData", "decoding", false)
				}
				if decodedTag_utranadditionalpositioningdata.Class != tag.ClassContextSpecific || decodedTag_utranadditionalpositioningdata.Number != 27 {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_utranadditionalpositioningdata), "utranAdditionalPositioningData", "decoding", false)
				}
				decVal_utranadditionalpositioningdata, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_utranadditionalpositioningdata.Constructed, rawVal_utranadditionalpositioningdata, opts...)
				if octetErr != nil {
					return qualifyBERError(octetErr, "utranAdditionalPositioningData", "decoding", false)
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
					if constraintErr := ber.CheckDecodedLength(ber.DecodeRule(opts, "MAP-LCS-DataTypes.SubscriberLocationReport-Arg", ber.RuleRef{Document: "ITU-T X.680", Edition: "02/2021", Clause: "51.5"}), "utranAdditionalPositioningData", "SIZE (1..8)", len(*v.UtranAdditionalPositioningData)); constraintErr != nil {
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
				ber.MarkPreflightTarget(opts, "utranBaroPressureMeas", content[offset:])
				decodedTag_utranbaropressuremeas, n_utranbaropressuremeas, rawVal_utranbaropressuremeas, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "utranBaroPressureMeas", "decoding", false)
				}
				if decodedTag_utranbaropressuremeas.Class != tag.ClassContextSpecific || decodedTag_utranbaropressuremeas.Number != 28 || decodedTag_utranbaropressuremeas.Constructed != false {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_utranbaropressuremeas), "utranBaroPressureMeas", "decoding", false)
				}
				decVal_utranbaropressuremeas, intErr := ber.DecodeIntegerValue(rawVal_utranbaropressuremeas)
				if intErr != nil {
					return qualifyBERError(intErr, "utranBaroPressureMeas", "decoding", false)
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
					if constraintErr := ber.CheckDecodedValue(ber.DecodeRule(opts, "MAP-LCS-DataTypes.SubscriberLocationReport-Arg", ber.RuleRef{Document: "ITU-T X.680", Edition: "02/2021", Clause: "51.4"}), "utranBaroPressureMeas", "(30000..115000)", ber.ObserveInteger(int64(*v.UtranBaroPressureMeas))); constraintErr != nil {
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
				ber.MarkPreflightTarget(opts, "utranCivicAddress", content[offset:])
				decodedTag_utrancivicaddress, n_utrancivicaddress, rawVal_utrancivicaddress, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "utranCivicAddress", "decoding", false)
				}
				if decodedTag_utrancivicaddress.Class != tag.ClassContextSpecific || decodedTag_utrancivicaddress.Number != 29 {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_utrancivicaddress), "utranCivicAddress", "decoding", false)
				}
				decVal_utrancivicaddress, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_utrancivicaddress.Constructed, rawVal_utrancivicaddress, opts...)
				if octetErr != nil {
					return qualifyBERError(octetErr, "utranCivicAddress", "decoding", false)
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
		peekTag, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:], opts...)
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "LCSSubscriberLocationReportArg", Cause: extErr_}
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: the first unknown addition must differ from trailing OPTIONAL/DEFAULT tags.
		if len(v.ExtData_) == 0 && ((peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 29) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 28) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 27) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 26) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 25) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 24) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 23) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 22) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 21) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 20) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 19) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 18) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 17) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 15) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 14) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 13) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 12) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 11) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 10) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 9) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 8) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 7) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 6) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 5) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0)) {
			if !ber.ToleranceEnabled(opts) {
				return &ber.DecodeError{Offset: offset, TypeName: "LCSSubscriberLocationReportArg", Cause: fmt.Errorf("%w: repeated or out-of-order SEQUENCE component tag %s", ber.ErrInvalidTag, peekTag)}
			}
			if orderErr_ := ber.CheckDecodedValue(ber.DecodeRule(opts, "MAP-LCS-DataTypes.SubscriberLocationReport-Arg", ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), fmt.Sprintf("ExtData_[%d]", len(v.ExtData_)), "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); orderErr_ != nil {
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

// MarshalBER encodes LCSDeferredmtLrData to BER format.
func (v *LCSDeferredmtLrData) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: LCSDeferredmtLrData receiver is nil", ber.ErrInvalidValue)
	}
	if v.berReplayNode_ == nil {
		return v.marshalBER(opts...)
	}
	var replayErr error
	opts, replayErr = ber.PrepareBERReplay(v.berReplayNode_, opts, func(mode ber.EncodeOption) ([]byte, error) { return v.MarshalBER([]ber.EncodeOption{mode}...) }, v)
	if replayErr != nil {
		return nil, replayErr
	}
	if replayBytes, ok := ber.PreparedBERReplay(v.berReplayNode_, opts); ok {
		return replayBytes, nil
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBERNode(encoded, v.berReplayNode_, opts), nil
}
func (v *LCSDeferredmtLrData) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if bitStringErr := ber.ValidateBitStringLength(v.DeferredLocationEventType.Bytes, v.DeferredLocationEventType.BitLength); bitStringErr != nil {
		return nil, qualifyBERError(bitStringErr, "deferredLocationEventType", "encoding", false)
	}
	// arithmetic pattern BER_BITSTRING_FIELD: 0 <= bit length before modulo and subtraction; gen/codegen.go:743
	if v.DeferredLocationEventType.BitLength < 0 {
		return nil, fmt.Errorf("negative bit string length")
	}
	if (v.DeferredLocationEventType).BitLength < 1 || (v.DeferredLocationEventType).BitLength > 16 {
		if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(opts, "MAP-LCS-DataTypes.Deferredmt-lrData", ber.RuleRef{Document: "ITU-T X.680", Edition: "02/2021", Clause: "51.5"}), "deferredLocationEventType", "SIZE (1..16)", (v.DeferredLocationEventType).BitLength); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_deferredlocationeventtype, encodeErr_enc_deferredlocationeventtype := ber.EncodeBitString(v.DeferredLocationEventType.Bytes, ber.UnusedBitCount(v.DeferredLocationEventType.BitLength))
	if encodeErr_enc_deferredlocationeventtype != nil {
		return nil, qualifyBERError(encodeErr_enc_deferredlocationeventtype, "deferredLocationEventType", "encoding", false)
	}
	children = append(children, enc_deferredlocationeventtype...)
	if v.TerminationCause != nil {
		enc_terminationcause := ber.EncodeEnumerated(int64(*v.TerminationCause))
		retagged_enc_terminationcause, tagErr_enc_terminationcause := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_terminationcause)
		if tagErr_enc_terminationcause != nil {
			return nil, qualifyBERError(tagErr_enc_terminationcause, "terminationCause", "encoding", false)
		}
		enc_terminationcause = retagged_enc_terminationcause
		children = append(children, enc_terminationcause...)
	}
	if v.LcsLocationInfo != nil {
		enc_lcslocationinfo, err := v.LcsLocationInfo.MarshalBER(ber.ChildEncodeOptions(opts, "lcsLocationInfo")...)
		if err != nil {
			return nil, qualifyBERError(err, "lcsLocationInfo", "encoding", false)
		}
		retagged_enc_lcslocationinfo, tagErr_enc_lcslocationinfo := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_lcslocationinfo)
		if tagErr_enc_lcslocationinfo != nil {
			return nil, qualifyBERError(tagErr_enc_lcslocationinfo, "lcsLocationInfo", "encoding", false)
		}
		enc_lcslocationinfo = retagged_enc_lcslocationinfo
		ber.RecordGeneratedBERChildPlacement(opts, len(children), enc_lcslocationinfo)
		children = append(children, enc_lcslocationinfo...)
	}
	for i, ext := range v.ExtData_ {
		if err := ber.CheckBEROpaqueElement(ext, opts...); err != nil {
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
			if constraintErr := ber.CheckEncodedValue(ber.EncodeRule(opts, "MAP-LCS-DataTypes.Deferredmt-lrData", ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
				return nil, constraintErr
			}
		}
		children = append(children, ext...)
	}
	ber.RecordGeneratedBERContainer(opts, children)
	return ber.EncodeSequence(children)
}
func (v *LCSDeferredmtLrData) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// MarshalDER encodes LCSDeferredmtLrData to DER format.
// Opaque descendants pass generic DER checks; foreign schema rules need a typed binding.
func (v *LCSDeferredmtLrData) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: LCSDeferredmtLrData receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if bitStringErr := ber.ValidateBitStringLength(v.DeferredLocationEventType.Bytes, v.DeferredLocationEventType.BitLength); bitStringErr != nil {
		return nil, qualifyBERError(bitStringErr, "deferredLocationEventType", "encoding", true)
	}
	if bitStringErr := ber.ValidateDERBitString(v.DeferredLocationEventType.Bytes, v.DeferredLocationEventType.BitLength); bitStringErr != nil {
		return nil, qualifyBERError(bitStringErr, "deferredLocationEventType", "encoding", true)
	}
	// arithmetic pattern BER_BITSTRING_FIELD: 0 <= bit length before modulo and subtraction; gen/codegen.go:743
	if v.DeferredLocationEventType.BitLength < 0 {
		return nil, fmt.Errorf("negative bit string length")
	}
	if (v.DeferredLocationEventType).BitLength < 1 || (v.DeferredLocationEventType).BitLength > 16 {
		if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(nil, "MAP-LCS-DataTypes.Deferredmt-lrData", ber.RuleRef{Document: "ITU-T X.680", Edition: "02/2021", Clause: "51.5"}), "deferredLocationEventType", "SIZE (1..16)", (v.DeferredLocationEventType).BitLength); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_deferredlocationeventtype, encodeErr_enc_deferredlocationeventtype := ber.EncodeDERNamedBitString(v.DeferredLocationEventType.Bytes, v.DeferredLocationEventType.BitLength)
	if encodeErr_enc_deferredlocationeventtype != nil {
		return nil, qualifyBERError(encodeErr_enc_deferredlocationeventtype, "deferredLocationEventType", "encoding", true)
	}
	children = append(children, enc_deferredlocationeventtype...)
	if v.TerminationCause != nil {
		enc_terminationcause := ber.EncodeEnumerated(int64(*v.TerminationCause))
		retagged_enc_terminationcause, tagErr_enc_terminationcause := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_terminationcause)
		if tagErr_enc_terminationcause != nil {
			return nil, qualifyBERError(tagErr_enc_terminationcause, "terminationCause", "encoding", true)
		}
		enc_terminationcause = retagged_enc_terminationcause
		children = append(children, enc_terminationcause...)
	}
	if v.LcsLocationInfo != nil {
		enc_lcslocationinfo, err := v.LcsLocationInfo.MarshalDER()
		if err != nil {
			return nil, qualifyBERError(err, "lcsLocationInfo", "encoding", true)
		}
		retagged_enc_lcslocationinfo, tagErr_enc_lcslocationinfo := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_lcslocationinfo)
		if tagErr_enc_lcslocationinfo != nil {
			return nil, qualifyBERError(tagErr_enc_lcslocationinfo, "lcsLocationInfo", "encoding", true)
		}
		enc_lcslocationinfo = retagged_enc_lcslocationinfo
		children = append(children, enc_lcslocationinfo...)
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
			if constraintErr := ber.CheckEncodedValue(ber.EncodeRule(nil, "MAP-LCS-DataTypes.Deferredmt-lrData", ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
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
		return nil, fmt.Errorf("%s: %w", "encoding LCSDeferredmtLrData as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}
func (v *LCSDeferredmtLrData) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	encoded, err := v.MarshalDER()
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBER decodes LCSDeferredmtLrData from BER/DER format.
func (destination *LCSDeferredmtLrData) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if destination == nil {
		return fmt.Errorf("%w: LCSDeferredmtLrData destination is nil", ber.ErrInvalidValue)
	}
	var berNextValue_ LCSDeferredmtLrData
	v := &berNextValue_

	defer func() {
		if returnErr ==

			nil {
			*destination =
				*v
		}
	}()

	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	ownedData, ownErr := ber.OwnGeneratedBERInput(data, opts)
	if ownErr != nil {
		return ownErr
	}
	data = ownedData
	preparedData, preparedOptions, prepareErr := ber.PrepareGeneratedBERInput(data, opts)
	if prepareErr != nil {
		return ber.DiagnosePreflight(prepareErr, data, opts, "child", func(probeOpts []ber.DecodeOption) error {
			var probe LCSDeferredmtLrData
			return probe.UnmarshalBER(data, probeOpts...)
		})
	}
	data, opts = preparedData, preparedOptions
	opts = ber.LocateDecodedElement(data, "MAP-LCS-DataTypes.Deferredmt-lrData", opts)
	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
	*v = LCSDeferredmtLrData{}
	defer func() {
		if returnErr != nil || !ber.BERNeedsPreservation(opts) {
			return
		}
		v.berReplayNode_ = ber.CaptureGeneratedBERReplay(data, opts)
		returnErr = ber.CompleteGeneratedBERDecode(opts, v, func(base *LCSDeferredmtLrData, replayOpts ...ber.EncodeOption) ([]byte, error) {
			return base.MarshalBER(replayOpts...)
		})
	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("%s: %w", "decoding LCSDeferredmtLrData SEQUENCE", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "LCSDeferredmtLrData", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode deferredLocationEventType
	if offset >= len(content) {
		return fmt.Errorf("missing required field deferredLocationEventType")
	}
	{
		ber.MarkPreflightTarget(opts, "deferredLocationEventType", content[offset:])
		bsBytes_deferredlocationeventtype, bsUnused_deferredlocationeventtype, n, err := ber.DecodeBitString(content[offset:], opts...)
		if err != nil {
			return qualifyBERError(err, "deferredLocationEventType", "decoding", false)
		}
		bsBitLength_deferredlocationeventtype, bsLenErr_deferredlocationeventtype := ber.BitStringBitLength(len(bsBytes_deferredlocationeventtype), bsUnused_deferredlocationeventtype)
		if bsLenErr_deferredlocationeventtype != nil {
			return qualifyBERError(bsLenErr_deferredlocationeventtype, "deferredLocationEventType", "decoding", false)
		}
		v.DeferredLocationEventType = runtime.BitString{Bytes: bsBytes_deferredlocationeventtype, BitLength: bsBitLength_deferredlocationeventtype}
		if offset > len(content) || n < 0 || n > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n
		v.DeferredLocationEventType = ber.NormalizeNamedBitStringSize(v.DeferredLocationEventType, []ber.NamedBitSizeSet{{{Min: 1, Max: 16}}}, opts...)
		if (v.DeferredLocationEventType).BitLength < 1 || (v.DeferredLocationEventType).BitLength > 16 {
			if constraintErr := ber.CheckDecodedLength(ber.DecodeRule(opts, "MAP-LCS-DataTypes.Deferredmt-lrData", ber.RuleRef{Document: "ITU-T X.680", Edition: "02/2021", Clause: "51.5"}), "deferredLocationEventType", "SIZE (1..16)", (v.DeferredLocationEventType).BitLength); constraintErr != nil {
				return constraintErr
			}
		}
	}
	// Decode terminationCause
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
				ber.MarkPreflightTarget(opts, "terminationCause", content[offset:])
				decodedTag_terminationcause, n_terminationcause, rawVal_terminationcause, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "terminationCause", "decoding", false)
				}
				if decodedTag_terminationcause.Class != tag.ClassContextSpecific || decodedTag_terminationcause.Number != 0 || decodedTag_terminationcause.Constructed != false {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_terminationcause), "terminationCause", "decoding", false)
				}
				decVal_terminationcause, intErr := ber.DecodeEnumeratedValue(rawVal_terminationcause)
				if intErr != nil {
					return qualifyBERError(intErr, "terminationCause", "decoding", false)
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
				ber.MarkPreflightTarget(opts, "lcsLocationInfo", content[offset:])
				decodedTag_lcslocationinfo, n_lcslocationinfo, rawVal_lcslocationinfo, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "lcsLocationInfo", "decoding", false)
				}
				if decodedTag_lcslocationinfo.Class != tag.ClassContextSpecific || decodedTag_lcslocationinfo.Number != 1 || decodedTag_lcslocationinfo.Constructed != true {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_lcslocationinfo), "lcsLocationInfo", "decoding", false)
				}
				_ = rawVal_lcslocationinfo
				if offset < 0 || offset >
					len(content) || n_lcslocationinfo < 0 || n_lcslocationinfo >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				reconstructed_lcslocationinfo, reconstructionErr_lcslocationinfo := ber.EncodeImplicitTagWithClass(tag.ClassUniversal, tag.TagSequence, content[offset:offset+n_lcslocationinfo])
				if reconstructionErr_lcslocationinfo != nil {
					return qualifyBERError(reconstructionErr_lcslocationinfo, "lcsLocationInfo", "decoding", false)
				}
				var dec_lcslocationinfo LCSLCSLocationInfo
				if unmErr := dec_lcslocationinfo.UnmarshalBER(reconstructed_lcslocationinfo, ber.ChildDecodeOptions(opts, "lcsLocationInfo")...); unmErr != nil {
					return qualifyBERError(unmErr, "lcsLocationInfo", "decoding", false)
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
		peekTag, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:], opts...)
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "LCSDeferredmtLrData", Cause: extErr_}
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: the first unknown addition must differ from trailing OPTIONAL/DEFAULT tags.
		if len(v.ExtData_) == 0 && ((peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0)) {
			if !ber.ToleranceEnabled(opts) {
				return &ber.DecodeError{Offset: offset, TypeName: "LCSDeferredmtLrData", Cause: fmt.Errorf("%w: repeated or out-of-order SEQUENCE component tag %s", ber.ErrInvalidTag, peekTag)}
			}
			if orderErr_ := ber.CheckDecodedValue(ber.DecodeRule(opts, "MAP-LCS-DataTypes.Deferredmt-lrData", ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), fmt.Sprintf("ExtData_[%d]", len(v.ExtData_)), "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); orderErr_ != nil {
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

// MarshalBER encodes LCSServingNodeAddress to BER format.
func (v *LCSServingNodeAddress) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: LCSServingNodeAddress receiver is nil", ber.ErrInvalidValue)
	}
	if v.berReplayNode_ == nil {
		return v.marshalBER(opts...)
	}
	var replayErr error
	opts, replayErr = ber.PrepareBERReplay(v.berReplayNode_, opts, func(mode ber.EncodeOption) ([]byte, error) { return v.MarshalBER([]ber.EncodeOption{mode}...) }, v)
	if replayErr != nil {
		return nil, replayErr
	}
	if replayBytes, ok := ber.PreparedBERReplay(v.berReplayNode_, opts); ok {
		return replayBytes, nil
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBERNode(encoded, v.berReplayNode_, opts), nil
}
func (v *LCSServingNodeAddress) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
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
			return nil, qualifyBERError(encodeErr_enc_0, "msc-Number", "encoding", false)
		}
		if len(*v.MscNumber) < 1 || len(*v.MscNumber) > 9 {
			if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(opts, "MAP-LCS-DataTypes.ServingNodeAddress", ber.RuleRef{Document: "ITU-T X.680", Edition: "02/2021", Clause: "51.5"}), "msc-Number", "SIZE (1..9)", len(*v.MscNumber)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		if len(*v.MscNumber) < 1 || len(*v.MscNumber) > 20 {
			if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(opts, "MAP-LCS-DataTypes.ServingNodeAddress", ber.RuleRef{Document: "ITU-T X.680", Edition: "02/2021", Clause: "51.5"}), "msc-Number", "SIZE (1..20)", len(*v.MscNumber)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		retagged_enc_0, tagErr_enc_0 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_0)
		if tagErr_enc_0 != nil {
			return nil, qualifyBERError(tagErr_enc_0, "msc-Number", "encoding", false)
		}
		enc_0 = retagged_enc_0
		return enc_0, nil
	case LCSServingNodeAddressChoiceSgsnNumber:
		if v.SgsnNumber == nil {
			return nil, fmt.Errorf("%w: choice LCSServingNodeAddress: sgsn-Number is nil", ber.ErrInvalidValue)
		}
		enc_1, encodeErr_enc_1 := ber.EncodeOctetString([]byte(*v.SgsnNumber))
		if encodeErr_enc_1 != nil {
			return nil, qualifyBERError(encodeErr_enc_1, "sgsn-Number", "encoding", false)
		}
		if len(*v.SgsnNumber) < 1 || len(*v.SgsnNumber) > 9 {
			if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(opts, "MAP-LCS-DataTypes.ServingNodeAddress", ber.RuleRef{Document: "ITU-T X.680", Edition: "02/2021", Clause: "51.5"}), "sgsn-Number", "SIZE (1..9)", len(*v.SgsnNumber)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		if len(*v.SgsnNumber) < 1 || len(*v.SgsnNumber) > 20 {
			if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(opts, "MAP-LCS-DataTypes.ServingNodeAddress", ber.RuleRef{Document: "ITU-T X.680", Edition: "02/2021", Clause: "51.5"}), "sgsn-Number", "SIZE (1..20)", len(*v.SgsnNumber)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		retagged_enc_1, tagErr_enc_1 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_1)
		if tagErr_enc_1 != nil {
			return nil, qualifyBERError(tagErr_enc_1, "sgsn-Number", "encoding", false)
		}
		enc_1 = retagged_enc_1
		return enc_1, nil
	case LCSServingNodeAddressChoiceMmeNumber:
		if v.MmeNumber == nil {
			return nil, fmt.Errorf("%w: choice LCSServingNodeAddress: mme-Number is nil", ber.ErrInvalidValue)
		}
		enc_2, encodeErr_enc_2 := ber.EncodeOctetString([]byte(*v.MmeNumber))
		if encodeErr_enc_2 != nil {
			return nil, qualifyBERError(encodeErr_enc_2, "mme-Number", "encoding", false)
		}
		if len(*v.MmeNumber) < 9 || len(*v.MmeNumber) > 255 {
			if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(opts, "MAP-LCS-DataTypes.ServingNodeAddress", ber.RuleRef{Document: "ITU-T X.680", Edition: "02/2021", Clause: "51.5"}), "mme-Number", "SIZE (9..255)", len(*v.MmeNumber)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		retagged_enc_2, tagErr_enc_2 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_2)
		if tagErr_enc_2 != nil {
			return nil, qualifyBERError(tagErr_enc_2, "mme-Number", "encoding", false)
		}
		enc_2 = retagged_enc_2
		return enc_2, nil
	default:
		return nil, fmt.Errorf("unknown choice %d for LCSServingNodeAddress", v.Choice)
	}
}

// MarshalDER encodes LCSServingNodeAddress to DER format.
// Opaque descendants pass generic DER checks; foreign schema rules need a typed binding.
func (v *LCSServingNodeAddress) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: LCSServingNodeAddress receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER()
	if err != nil {
		return nil, err
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		switch v.Choice {
		case LCSServingNodeAddressChoiceMscNumber:
			return nil, qualifyBERError(err, "msc-Number", "encoding", true)
		case LCSServingNodeAddressChoiceSgsnNumber:
			return nil, qualifyBERError(err, "sgsn-Number", "encoding", true)
		case LCSServingNodeAddressChoiceMmeNumber:
			return nil, qualifyBERError(err, "mme-Number", "encoding", true)
		}
		return nil, fmt.Errorf("%s: %w", "encoding LCSServingNodeAddress as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}

func (v *LCSServingNodeAddress) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	encoded, err := v.MarshalDER()
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBER decodes LCSServingNodeAddress from BER/DER format.
func (destination *LCSServingNodeAddress) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if destination == nil {
		return fmt.Errorf("%w: LCSServingNodeAddress destination is nil", ber.ErrInvalidValue)
	}
	var berNextValue_ LCSServingNodeAddress
	v := &berNextValue_

	defer func() {
		if returnErr ==
			nil {
			*destination = *v
		}
	}()

	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	ownedData, ownErr := ber.OwnGeneratedBERInput(data, opts)
	if ownErr != nil {
		return ownErr
	}
	data = ownedData
	defer func() {
		if returnErr != nil || !ber.BERNeedsPreservation(opts) {
			return
		}
		v.berReplayNode_ = ber.CaptureGeneratedBERReplay(data, opts)
		returnErr = ber.CompleteGeneratedBERDecode(opts, v, func(base *LCSServingNodeAddress, replayOpts ...ber.EncodeOption) ([]byte, error) {
			return base.MarshalBER(replayOpts...)
		})
	}()
	preparedData, preparedOptions, prepareErr := ber.PrepareGeneratedBERInput(data, opts)
	if prepareErr != nil {
		return ber.DiagnosePreflight(prepareErr, data, opts, "child", func(probeOpts []ber.DecodeOption) error {
			var probe LCSServingNodeAddress
			return probe.UnmarshalBER(data, probeOpts...)
		})
	}
	data, opts = preparedData, preparedOptions
	opts = ber.LocateDecodedElement(data, "MAP-LCS-DataTypes.ServingNodeAddress", opts)
	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
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
		return fmt.Errorf("%s: %w", "decoding LCSServingNodeAddress CHOICE", qualifyBERError(tlvErr, "", "decoding", false))
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "LCSServingNodeAddress", Cause: ber.ErrExtraData}
	}

	if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
		v.Choice = LCSServingNodeAddressChoiceMscNumber
		ber.MarkPreflightTarget(opts, "msc-Number", choiceData)
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData, opts...)
		if tlvErr != nil {
			return qualifyBERError(tlvErr, "msc-Number", "decoding", false)
		}
		_ = rawVal
		decVal, octetErr := ber.DecodeImplicitOctetStringValue(peekTag.Constructed, rawVal, opts...)
		if octetErr != nil {
			return qualifyBERError(octetErr, "msc-Number", "decoding", false)
		}
		tmp := v21_map_commondatatypes.CommonDataTypesISDNAddressString(decVal)
		v.MscNumber = &tmp
		if len(*v.MscNumber) < 1 || len(*v.MscNumber) > 9 {
			if constraintErr := ber.CheckDecodedLength(ber.DecodeRule(opts, "MAP-LCS-DataTypes.ServingNodeAddress", ber.RuleRef{Document: "ITU-T X.680", Edition: "02/2021", Clause: "51.5"}), "msc-Number", "SIZE (1..9)", len(*v.MscNumber)); constraintErr != nil {
				return constraintErr
			}
		}
		if len(*v.MscNumber) < 1 || len(*v.MscNumber) > 20 {
			if constraintErr := ber.CheckDecodedLength(ber.DecodeRule(opts, "MAP-LCS-DataTypes.ServingNodeAddress", ber.RuleRef{Document: "ITU-T X.680", Edition: "02/2021", Clause: "51.5"}), "msc-Number", "SIZE (1..20)", len(*v.MscNumber)); constraintErr != nil {
				return constraintErr
			}
		}
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
		v.Choice = LCSServingNodeAddressChoiceSgsnNumber
		ber.MarkPreflightTarget(opts, "sgsn-Number", choiceData)
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData, opts...)
		if tlvErr != nil {
			return qualifyBERError(tlvErr, "sgsn-Number", "decoding", false)
		}
		_ = rawVal
		decVal, octetErr := ber.DecodeImplicitOctetStringValue(peekTag.Constructed, rawVal, opts...)
		if octetErr != nil {
			return qualifyBERError(octetErr, "sgsn-Number", "decoding", false)
		}
		tmp := v21_map_commondatatypes.CommonDataTypesISDNAddressString(decVal)
		v.SgsnNumber = &tmp
		if len(*v.SgsnNumber) < 1 || len(*v.SgsnNumber) > 9 {
			if constraintErr := ber.CheckDecodedLength(ber.DecodeRule(opts, "MAP-LCS-DataTypes.ServingNodeAddress", ber.RuleRef{Document: "ITU-T X.680", Edition: "02/2021", Clause: "51.5"}), "sgsn-Number", "SIZE (1..9)", len(*v.SgsnNumber)); constraintErr != nil {
				return constraintErr
			}
		}
		if len(*v.SgsnNumber) < 1 || len(*v.SgsnNumber) > 20 {
			if constraintErr := ber.CheckDecodedLength(ber.DecodeRule(opts, "MAP-LCS-DataTypes.ServingNodeAddress", ber.RuleRef{Document: "ITU-T X.680", Edition: "02/2021", Clause: "51.5"}), "sgsn-Number", "SIZE (1..20)", len(*v.SgsnNumber)); constraintErr != nil {
				return constraintErr
			}
		}
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2 {
		v.Choice = LCSServingNodeAddressChoiceMmeNumber
		ber.MarkPreflightTarget(opts, "mme-Number", choiceData)
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData, opts...)
		if tlvErr != nil {
			return qualifyBERError(tlvErr, "mme-Number", "decoding", false)
		}
		_ = rawVal
		decVal, octetErr := ber.DecodeImplicitOctetStringValue(peekTag.Constructed, rawVal, opts...)
		if octetErr != nil {
			return qualifyBERError(octetErr, "mme-Number", "decoding", false)
		}
		tmp := v21_map_commondatatypes.CommonDataTypesDiameterIdentity(decVal)
		v.MmeNumber = &tmp
		if len(*v.MmeNumber) < 9 || len(*v.MmeNumber) > 255 {
			if constraintErr := ber.CheckDecodedLength(ber.DecodeRule(opts, "MAP-LCS-DataTypes.ServingNodeAddress", ber.RuleRef{Document: "ITU-T X.680", Edition: "02/2021", Clause: "51.5"}), "mme-Number", "SIZE (9..255)", len(*v.MmeNumber)); constraintErr != nil {
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
	if v.berReplayNode_ == nil {
		return v.marshalBER(opts...)
	}
	var replayErr error
	opts, replayErr = ber.PrepareBERReplay(v.berReplayNode_, opts, func(mode ber.EncodeOption) ([]byte, error) { return v.MarshalBER([]ber.EncodeOption{mode}...) }, v)
	if replayErr != nil {
		return nil, replayErr
	}
	if replayBytes, ok := ber.PreparedBERReplay(v.berReplayNode_, opts); ok {
		return replayBytes, nil
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBERNode(encoded, v.berReplayNode_, opts), nil
}
func (v *LCSSubscriberLocationReportRes) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalBER(ber.ChildEncodeOptions(opts, "extensionContainer")...)
		if err != nil {
			return nil, qualifyBERError(err, "extensionContainer", "encoding", false)
		}
		ber.RecordGeneratedBERChildPlacement(opts, len(children), enc_extensioncontainer)
		children = append(children, enc_extensioncontainer...)
	}
	if v.NaESRK != nil {
		if len(*v.NaESRK) < 1 || len(*v.NaESRK) > 9 {
			if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(opts, "MAP-LCS-DataTypes.SubscriberLocationReport-Res", ber.RuleRef{Document: "ITU-T X.680", Edition: "02/2021", Clause: "51.5"}), "na-ESRK", "SIZE (1..9)", len(*v.NaESRK)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		if len(*v.NaESRK) < 1 || len(*v.NaESRK) > 20 {
			if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(opts, "MAP-LCS-DataTypes.SubscriberLocationReport-Res", ber.RuleRef{Document: "ITU-T X.680", Edition: "02/2021", Clause: "51.5"}), "na-ESRK", "SIZE (1..20)", len(*v.NaESRK)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_naesrk, encodeErr_enc_naesrk := ber.EncodeOctetString([]byte(*v.NaESRK))
		if encodeErr_enc_naesrk != nil {
			return nil, qualifyBERError(encodeErr_enc_naesrk, "na-ESRK", "encoding", false)
		}
		retagged_enc_naesrk, tagErr_enc_naesrk := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_naesrk)
		if tagErr_enc_naesrk != nil {
			return nil, qualifyBERError(tagErr_enc_naesrk, "na-ESRK", "encoding", false)
		}
		enc_naesrk = retagged_enc_naesrk
		children = append(children, enc_naesrk...)
	}
	if v.NaESRD != nil {
		if len(*v.NaESRD) < 1 || len(*v.NaESRD) > 9 {
			if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(opts, "MAP-LCS-DataTypes.SubscriberLocationReport-Res", ber.RuleRef{Document: "ITU-T X.680", Edition: "02/2021", Clause: "51.5"}), "na-ESRD", "SIZE (1..9)", len(*v.NaESRD)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		if len(*v.NaESRD) < 1 || len(*v.NaESRD) > 20 {
			if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(opts, "MAP-LCS-DataTypes.SubscriberLocationReport-Res", ber.RuleRef{Document: "ITU-T X.680", Edition: "02/2021", Clause: "51.5"}), "na-ESRD", "SIZE (1..20)", len(*v.NaESRD)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_naesrd, encodeErr_enc_naesrd := ber.EncodeOctetString([]byte(*v.NaESRD))
		if encodeErr_enc_naesrd != nil {
			return nil, qualifyBERError(encodeErr_enc_naesrd, "na-ESRD", "encoding", false)
		}
		retagged_enc_naesrd, tagErr_enc_naesrd := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_naesrd)
		if tagErr_enc_naesrd != nil {
			return nil, qualifyBERError(tagErr_enc_naesrd, "na-ESRD", "encoding", false)
		}
		enc_naesrd = retagged_enc_naesrd
		children = append(children, enc_naesrd...)
	}
	if v.HGmlcAddress != nil {
		if len(*v.HGmlcAddress) < 5 || len(*v.HGmlcAddress) > 17 {
			if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(opts, "MAP-LCS-DataTypes.SubscriberLocationReport-Res", ber.RuleRef{Document: "ITU-T X.680", Edition: "02/2021", Clause: "51.5"}), "h-gmlc-Address", "SIZE (5..17)", len(*v.HGmlcAddress)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_hgmlcaddress, encodeErr_enc_hgmlcaddress := ber.EncodeOctetString([]byte(*v.HGmlcAddress))
		if encodeErr_enc_hgmlcaddress != nil {
			return nil, qualifyBERError(encodeErr_enc_hgmlcaddress, "h-gmlc-Address", "encoding", false)
		}
		retagged_enc_hgmlcaddress, tagErr_enc_hgmlcaddress := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_hgmlcaddress)
		if tagErr_enc_hgmlcaddress != nil {
			return nil, qualifyBERError(tagErr_enc_hgmlcaddress, "h-gmlc-Address", "encoding", false)
		}
		enc_hgmlcaddress = retagged_enc_hgmlcaddress
		children = append(children, enc_hgmlcaddress...)
	}
	if v.MoLrShortCircuitIndicator != nil {
		enc_molrshortcircuitindicator := ber.EncodeNull()
		retagged_enc_molrshortcircuitindicator, tagErr_enc_molrshortcircuitindicator := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, enc_molrshortcircuitindicator)
		if tagErr_enc_molrshortcircuitindicator != nil {
			return nil, qualifyBERError(tagErr_enc_molrshortcircuitindicator, "mo-lrShortCircuitIndicator", "encoding", false)
		}
		enc_molrshortcircuitindicator = retagged_enc_molrshortcircuitindicator
		children = append(children, enc_molrshortcircuitindicator...)
	}
	if v.ReportingPLMNList != nil {
		enc_reportingplmnlist, err := v.ReportingPLMNList.MarshalBER(ber.ChildEncodeOptions(opts, "reportingPLMNList")...)
		if err != nil {
			return nil, qualifyBERError(err, "reportingPLMNList", "encoding", false)
		}
		retagged_enc_reportingplmnlist, tagErr_enc_reportingplmnlist := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, enc_reportingplmnlist)
		if tagErr_enc_reportingplmnlist != nil {
			return nil, qualifyBERError(tagErr_enc_reportingplmnlist, "reportingPLMNList", "encoding", false)
		}
		enc_reportingplmnlist = retagged_enc_reportingplmnlist
		ber.RecordGeneratedBERChildPlacement(opts, len(children), enc_reportingplmnlist)
		children = append(children, enc_reportingplmnlist...)
	}
	if v.LcsReferenceNumber != nil {
		if len(*v.LcsReferenceNumber) < 1 || len(*v.LcsReferenceNumber) > 1 {
			if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(opts, "MAP-LCS-DataTypes.SubscriberLocationReport-Res", ber.RuleRef{Document: "ITU-T X.680", Edition: "02/2021", Clause: "51.5"}), "lcs-ReferenceNumber", "SIZE (1)", len(*v.LcsReferenceNumber)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_lcsreferencenumber, encodeErr_enc_lcsreferencenumber := ber.EncodeOctetString([]byte(*v.LcsReferenceNumber))
		if encodeErr_enc_lcsreferencenumber != nil {
			return nil, qualifyBERError(encodeErr_enc_lcsreferencenumber, "lcs-ReferenceNumber", "encoding", false)
		}
		retagged_enc_lcsreferencenumber, tagErr_enc_lcsreferencenumber := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 5, enc_lcsreferencenumber)
		if tagErr_enc_lcsreferencenumber != nil {
			return nil, qualifyBERError(tagErr_enc_lcsreferencenumber, "lcs-ReferenceNumber", "encoding", false)
		}
		enc_lcsreferencenumber = retagged_enc_lcsreferencenumber
		children = append(children, enc_lcsreferencenumber...)
	}
	for i, ext := range v.ExtData_ {
		if err := ber.CheckBEROpaqueElement(ext, opts...); err != nil {
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
		if i == 0 && ((peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 5) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0) || (peekTag.Class == tag.ClassUniversal && peekTag.Number == 16)) {
			if constraintErr := ber.CheckEncodedValue(ber.EncodeRule(opts, "MAP-LCS-DataTypes.SubscriberLocationReport-Res", ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
				return nil, constraintErr
			}
		}
		children = append(children, ext...)
	}
	ber.RecordGeneratedBERContainer(opts, children)
	return ber.EncodeSequence(children)
}
func (v *LCSSubscriberLocationReportRes) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// MarshalDER encodes LCSSubscriberLocationReportRes to DER format.
// Opaque descendants pass generic DER checks; foreign schema rules need a typed binding.
func (v *LCSSubscriberLocationReportRes) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: LCSSubscriberLocationReportRes receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalDER()
		if err != nil {
			return nil, qualifyBERError(err, "extensionContainer", "encoding", true)
		}
		children = append(children, enc_extensioncontainer...)
	}
	if v.NaESRK != nil {
		if len(*v.NaESRK) < 1 || len(*v.NaESRK) > 9 {
			if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(nil, "MAP-LCS-DataTypes.SubscriberLocationReport-Res", ber.RuleRef{Document: "ITU-T X.680", Edition: "02/2021", Clause: "51.5"}), "na-ESRK", "SIZE (1..9)", len(*v.NaESRK)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		if len(*v.NaESRK) < 1 || len(*v.NaESRK) > 20 {
			if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(nil, "MAP-LCS-DataTypes.SubscriberLocationReport-Res", ber.RuleRef{Document: "ITU-T X.680", Edition: "02/2021", Clause: "51.5"}), "na-ESRK", "SIZE (1..20)", len(*v.NaESRK)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_naesrk, encodeErr_enc_naesrk := ber.EncodeOctetString([]byte(*v.NaESRK))
		if encodeErr_enc_naesrk != nil {
			return nil, qualifyBERError(encodeErr_enc_naesrk, "na-ESRK", "encoding", true)
		}
		retagged_enc_naesrk, tagErr_enc_naesrk := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_naesrk)
		if tagErr_enc_naesrk != nil {
			return nil, qualifyBERError(tagErr_enc_naesrk, "na-ESRK", "encoding", true)
		}
		enc_naesrk = retagged_enc_naesrk
		children = append(children, enc_naesrk...)
	}
	if v.NaESRD != nil {
		if len(*v.NaESRD) < 1 || len(*v.NaESRD) > 9 {
			if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(nil, "MAP-LCS-DataTypes.SubscriberLocationReport-Res", ber.RuleRef{Document: "ITU-T X.680", Edition: "02/2021", Clause: "51.5"}), "na-ESRD", "SIZE (1..9)", len(*v.NaESRD)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		if len(*v.NaESRD) < 1 || len(*v.NaESRD) > 20 {
			if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(nil, "MAP-LCS-DataTypes.SubscriberLocationReport-Res", ber.RuleRef{Document: "ITU-T X.680", Edition: "02/2021", Clause: "51.5"}), "na-ESRD", "SIZE (1..20)", len(*v.NaESRD)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_naesrd, encodeErr_enc_naesrd := ber.EncodeOctetString([]byte(*v.NaESRD))
		if encodeErr_enc_naesrd != nil {
			return nil, qualifyBERError(encodeErr_enc_naesrd, "na-ESRD", "encoding", true)
		}
		retagged_enc_naesrd, tagErr_enc_naesrd := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_naesrd)
		if tagErr_enc_naesrd != nil {
			return nil, qualifyBERError(tagErr_enc_naesrd, "na-ESRD", "encoding", true)
		}
		enc_naesrd = retagged_enc_naesrd
		children = append(children, enc_naesrd...)
	}
	if v.HGmlcAddress != nil {
		if len(*v.HGmlcAddress) < 5 || len(*v.HGmlcAddress) > 17 {
			if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(nil, "MAP-LCS-DataTypes.SubscriberLocationReport-Res", ber.RuleRef{Document: "ITU-T X.680", Edition: "02/2021", Clause: "51.5"}), "h-gmlc-Address", "SIZE (5..17)", len(*v.HGmlcAddress)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_hgmlcaddress, encodeErr_enc_hgmlcaddress := ber.EncodeOctetString([]byte(*v.HGmlcAddress))
		if encodeErr_enc_hgmlcaddress != nil {
			return nil, qualifyBERError(encodeErr_enc_hgmlcaddress, "h-gmlc-Address", "encoding", true)
		}
		retagged_enc_hgmlcaddress, tagErr_enc_hgmlcaddress := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_hgmlcaddress)
		if tagErr_enc_hgmlcaddress != nil {
			return nil, qualifyBERError(tagErr_enc_hgmlcaddress, "h-gmlc-Address", "encoding", true)
		}
		enc_hgmlcaddress = retagged_enc_hgmlcaddress
		children = append(children, enc_hgmlcaddress...)
	}
	if v.MoLrShortCircuitIndicator != nil {
		enc_molrshortcircuitindicator := ber.EncodeNull()
		retagged_enc_molrshortcircuitindicator, tagErr_enc_molrshortcircuitindicator := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, enc_molrshortcircuitindicator)
		if tagErr_enc_molrshortcircuitindicator != nil {
			return nil, qualifyBERError(tagErr_enc_molrshortcircuitindicator, "mo-lrShortCircuitIndicator", "encoding", true)
		}
		enc_molrshortcircuitindicator = retagged_enc_molrshortcircuitindicator
		children = append(children, enc_molrshortcircuitindicator...)
	}
	if v.ReportingPLMNList != nil {
		enc_reportingplmnlist, err := v.ReportingPLMNList.MarshalDER()
		if err != nil {
			return nil, qualifyBERError(err, "reportingPLMNList", "encoding", true)
		}
		retagged_enc_reportingplmnlist, tagErr_enc_reportingplmnlist := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, enc_reportingplmnlist)
		if tagErr_enc_reportingplmnlist != nil {
			return nil, qualifyBERError(tagErr_enc_reportingplmnlist, "reportingPLMNList", "encoding", true)
		}
		enc_reportingplmnlist = retagged_enc_reportingplmnlist
		children = append(children, enc_reportingplmnlist...)
	}
	if v.LcsReferenceNumber != nil {
		if len(*v.LcsReferenceNumber) < 1 || len(*v.LcsReferenceNumber) > 1 {
			if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(nil, "MAP-LCS-DataTypes.SubscriberLocationReport-Res", ber.RuleRef{Document: "ITU-T X.680", Edition: "02/2021", Clause: "51.5"}), "lcs-ReferenceNumber", "SIZE (1)", len(*v.LcsReferenceNumber)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_lcsreferencenumber, encodeErr_enc_lcsreferencenumber := ber.EncodeOctetString([]byte(*v.LcsReferenceNumber))
		if encodeErr_enc_lcsreferencenumber != nil {
			return nil, qualifyBERError(encodeErr_enc_lcsreferencenumber, "lcs-ReferenceNumber", "encoding", true)
		}
		retagged_enc_lcsreferencenumber, tagErr_enc_lcsreferencenumber := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 5, enc_lcsreferencenumber)
		if tagErr_enc_lcsreferencenumber != nil {
			return nil, qualifyBERError(tagErr_enc_lcsreferencenumber, "lcs-ReferenceNumber", "encoding", true)
		}
		enc_lcsreferencenumber = retagged_enc_lcsreferencenumber
		children = append(children, enc_lcsreferencenumber...)
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
		if i == 0 && ((peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 5) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0) || (peekTag.Class == tag.ClassUniversal && peekTag.Number == 16)) {
			if constraintErr := ber.CheckEncodedValue(ber.EncodeRule(nil, "MAP-LCS-DataTypes.SubscriberLocationReport-Res", ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
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
		return nil, fmt.Errorf("%s: %w", "encoding LCSSubscriberLocationReportRes as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}
func (v *LCSSubscriberLocationReportRes) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	encoded, err := v.MarshalDER()
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBER decodes LCSSubscriberLocationReportRes from BER/DER format.
func (destination *LCSSubscriberLocationReportRes) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if destination == nil {
		return fmt.Errorf("%w: LCSSubscriberLocationReportRes destination is nil", ber.ErrInvalidValue)
	}
	var berNextValue_ LCSSubscriberLocationReportRes
	v :=

		&berNextValue_
	defer func() {
		if returnErr ==
			nil {
			*destination = *v
		}
	}()

	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	ownedData, ownErr := ber.OwnGeneratedBERInput(data, opts)
	if ownErr != nil {
		return ownErr
	}
	data = ownedData
	preparedData, preparedOptions, prepareErr := ber.PrepareGeneratedBERInput(data, opts)
	if prepareErr != nil {
		return ber.DiagnosePreflight(prepareErr, data, opts, "child", func(probeOpts []ber.DecodeOption) error {
			var probe LCSSubscriberLocationReportRes
			return probe.UnmarshalBER(data, probeOpts...)
		})
	}
	data, opts = preparedData, preparedOptions
	opts = ber.LocateDecodedElement(data, "MAP-LCS-DataTypes.SubscriberLocationReport-Res", opts)
	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
	*v = LCSSubscriberLocationReportRes{}
	defer func() {
		if returnErr != nil || !ber.BERNeedsPreservation(opts) {
			return
		}
		v.berReplayNode_ = ber.CaptureGeneratedBERReplay(data, opts)
		returnErr = ber.CompleteGeneratedBERDecode(opts, v, func(base *LCSSubscriberLocationReportRes, replayOpts ...ber.EncodeOption) ([]byte, error) {
			return base.MarshalBER(replayOpts...)
		})
	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("%s: %w", "decoding LCSSubscriberLocationReportRes SEQUENCE", qualifyBERError(err, "", "decoding", false))
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
				ber.MarkPreflightTarget(opts, "extensionContainer", content[offset:])
				// Decode nested SEQUENCE (__asn1pkg_v21_map_extensiondatatypes.ExtensionDataTypesExtensionContainer)
				_, n_extensioncontainer, _, tlvErr_extensioncontainer := ber.DecodeTLV(content[offset:], opts...)
				if tlvErr_extensioncontainer != nil {
					return qualifyBERError(tlvErr_extensioncontainer, "extensionContainer", "decoding", false)
				}
				var dec_extensioncontainer v21_map_extensiondatatypes.ExtensionDataTypesExtensionContainer
				if offset > len(content) || n_extensioncontainer < 0 || n_extensioncontainer > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				if unmErr := dec_extensioncontainer.UnmarshalBER(content[offset:offset+n_extensioncontainer], ber.ChildDecodeOptions(opts, "extensionContainer")...); unmErr != nil {
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
	// Decode na-ESRK
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
				ber.MarkPreflightTarget(opts, "na-ESRK", content[offset:])
				decodedTag_naesrk, n_naesrk, rawVal_naesrk, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "na-ESRK", "decoding", false)
				}
				if decodedTag_naesrk.Class != tag.ClassContextSpecific || decodedTag_naesrk.Number != 0 {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_naesrk), "na-ESRK", "decoding", false)
				}
				decVal_naesrk, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_naesrk.Constructed, rawVal_naesrk, opts...)
				if octetErr != nil {
					return qualifyBERError(octetErr, "na-ESRK", "decoding", false)
				}
				tmp_naesrk := v21_map_commondatatypes.CommonDataTypesISDNAddressString(decVal_naesrk)
				v.NaESRK = &tmp_naesrk
				if offset < 0 || offset >
					len(content) || n_naesrk < 0 || n_naesrk > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_naesrk
				if len(*v.NaESRK) < 1 || len(*v.NaESRK) > 9 {
					if constraintErr := ber.CheckDecodedLength(ber.DecodeRule(opts, "MAP-LCS-DataTypes.SubscriberLocationReport-Res", ber.RuleRef{Document: "ITU-T X.680", Edition: "02/2021", Clause: "51.5"}), "na-ESRK", "SIZE (1..9)", len(*v.NaESRK)); constraintErr != nil {
						return constraintErr
					}
				}
				if len(*v.NaESRK) < 1 || len(*v.NaESRK) > 20 {
					if constraintErr := ber.CheckDecodedLength(ber.DecodeRule(opts, "MAP-LCS-DataTypes.SubscriberLocationReport-Res", ber.RuleRef{Document: "ITU-T X.680", Edition: "02/2021", Clause: "51.5"}), "na-ESRK", "SIZE (1..20)", len(*v.NaESRK)); constraintErr != nil {
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
				ber.MarkPreflightTarget(opts, "na-ESRD", content[offset:])
				decodedTag_naesrd, n_naesrd, rawVal_naesrd, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "na-ESRD", "decoding", false)
				}
				if decodedTag_naesrd.Class != tag.ClassContextSpecific || decodedTag_naesrd.Number != 1 {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_naesrd), "na-ESRD", "decoding", false)
				}
				decVal_naesrd, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_naesrd.Constructed, rawVal_naesrd, opts...)
				if octetErr != nil {
					return qualifyBERError(octetErr, "na-ESRD", "decoding", false)
				}
				tmp_naesrd := v21_map_commondatatypes.CommonDataTypesISDNAddressString(decVal_naesrd)
				v.NaESRD = &tmp_naesrd
				if offset < 0 || offset >
					len(content) || n_naesrd < 0 || n_naesrd > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_naesrd
				if len(*v.NaESRD) < 1 || len(*v.NaESRD) > 9 {
					if constraintErr := ber.CheckDecodedLength(ber.DecodeRule(opts, "MAP-LCS-DataTypes.SubscriberLocationReport-Res", ber.RuleRef{Document: "ITU-T X.680", Edition: "02/2021", Clause: "51.5"}), "na-ESRD", "SIZE (1..9)", len(*v.NaESRD)); constraintErr != nil {
						return constraintErr
					}
				}
				if len(*v.NaESRD) < 1 || len(*v.NaESRD) > 20 {
					if constraintErr := ber.CheckDecodedLength(ber.DecodeRule(opts, "MAP-LCS-DataTypes.SubscriberLocationReport-Res", ber.RuleRef{Document: "ITU-T X.680", Edition: "02/2021", Clause: "51.5"}), "na-ESRD", "SIZE (1..20)", len(*v.NaESRD)); constraintErr != nil {
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
				ber.MarkPreflightTarget(opts, "h-gmlc-Address", content[offset:])
				decodedTag_hgmlcaddress, n_hgmlcaddress, rawVal_hgmlcaddress, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "h-gmlc-Address", "decoding", false)
				}
				if decodedTag_hgmlcaddress.Class != tag.ClassContextSpecific || decodedTag_hgmlcaddress.Number != 2 {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_hgmlcaddress), "h-gmlc-Address", "decoding", false)
				}
				decVal_hgmlcaddress, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_hgmlcaddress.Constructed, rawVal_hgmlcaddress, opts...)
				if octetErr != nil {
					return qualifyBERError(octetErr, "h-gmlc-Address", "decoding", false)
				}
				tmp_hgmlcaddress := v21_map_commondatatypes.CommonDataTypesGSNAddress(decVal_hgmlcaddress)
				v.HGmlcAddress = &tmp_hgmlcaddress
				if offset < 0 || offset >
					len(content) || n_hgmlcaddress < 0 || n_hgmlcaddress > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_hgmlcaddress
				if len(*v.HGmlcAddress) < 5 || len(*v.HGmlcAddress) > 17 {
					if constraintErr := ber.CheckDecodedLength(ber.DecodeRule(opts, "MAP-LCS-DataTypes.SubscriberLocationReport-Res", ber.RuleRef{Document: "ITU-T X.680", Edition: "02/2021", Clause: "51.5"}), "h-gmlc-Address", "SIZE (5..17)", len(*v.HGmlcAddress)); constraintErr != nil {
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
				ber.MarkPreflightTarget(opts, "mo-lrShortCircuitIndicator", content[offset:])
				decodedTag_molrshortcircuitindicator, n_molrshortcircuitindicator, rawVal_molrshortcircuitindicator, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "mo-lrShortCircuitIndicator", "decoding", false)
				}
				if decodedTag_molrshortcircuitindicator.Class != tag.ClassContextSpecific || decodedTag_molrshortcircuitindicator.Number != 3 || decodedTag_molrshortcircuitindicator.Constructed != false {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_molrshortcircuitindicator), "mo-lrShortCircuitIndicator", "decoding", false)
				}
				if len(rawVal_molrshortcircuitindicator) != 0 {
					return qualifyBERError(fmt.Errorf("%w: NULL content length %d", ber.ErrInvalidValue, len(rawVal_molrshortcircuitindicator)), "mo-lrShortCircuitIndicator", "decoding", false)
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
				ber.MarkPreflightTarget(opts, "reportingPLMNList", content[offset:])
				decodedTag_reportingplmnlist, n_reportingplmnlist, rawVal_reportingplmnlist, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "reportingPLMNList", "decoding", false)
				}
				if decodedTag_reportingplmnlist.Class != tag.ClassContextSpecific || decodedTag_reportingplmnlist.Number != 4 || decodedTag_reportingplmnlist.Constructed != true {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_reportingplmnlist), "reportingPLMNList", "decoding", false)
				}
				_ = rawVal_reportingplmnlist
				if offset < 0 || offset >
					len(content) || n_reportingplmnlist < 0 || n_reportingplmnlist > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				reconstructed_reportingplmnlist, reconstructionErr_reportingplmnlist := ber.EncodeImplicitTagWithClass(tag.ClassUniversal, tag.TagSequence, content[offset:offset+n_reportingplmnlist])
				if reconstructionErr_reportingplmnlist != nil {
					return qualifyBERError(reconstructionErr_reportingplmnlist, "reportingPLMNList", "decoding", false)
				}
				var dec_reportingplmnlist LCSReportingPLMNList
				if unmErr := dec_reportingplmnlist.UnmarshalBER(reconstructed_reportingplmnlist, ber.ChildDecodeOptions(opts, "reportingPLMNList")...); unmErr != nil {
					return qualifyBERError(unmErr, "reportingPLMNList", "decoding", false)
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
				ber.MarkPreflightTarget(opts, "lcs-ReferenceNumber", content[offset:])
				decodedTag_lcsreferencenumber, n_lcsreferencenumber, rawVal_lcsreferencenumber, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "lcs-ReferenceNumber", "decoding", false)
				}
				if decodedTag_lcsreferencenumber.Class != tag.ClassContextSpecific || decodedTag_lcsreferencenumber.Number != 5 {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_lcsreferencenumber), "lcs-ReferenceNumber", "decoding", false)
				}
				decVal_lcsreferencenumber, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_lcsreferencenumber.Constructed, rawVal_lcsreferencenumber, opts...)
				if octetErr != nil {
					return qualifyBERError(octetErr, "lcs-ReferenceNumber", "decoding", false)
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
					if constraintErr := ber.CheckDecodedLength(ber.DecodeRule(opts, "MAP-LCS-DataTypes.SubscriberLocationReport-Res", ber.RuleRef{Document: "ITU-T X.680", Edition: "02/2021", Clause: "51.5"}), "lcs-ReferenceNumber", "SIZE (1)", len(*v.LcsReferenceNumber)); constraintErr != nil {
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
			return &ber.DecodeError{Offset: offset, TypeName: "LCSSubscriberLocationReportRes", Cause: extErr_}
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: the first unknown addition must differ from trailing OPTIONAL/DEFAULT tags.
		if len(v.ExtData_) == 0 && ((peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 5) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0) || (peekTag.Class == tag.ClassUniversal && peekTag.Number == 16)) {
			if !ber.ToleranceEnabled(opts) {
				return &ber.DecodeError{Offset: offset, TypeName: "LCSSubscriberLocationReportRes", Cause: fmt.Errorf("%w: repeated or out-of-order SEQUENCE component tag %s", ber.ErrInvalidTag, peekTag)}
			}
			if orderErr_ := ber.CheckDecodedValue(ber.DecodeRule(opts, "MAP-LCS-DataTypes.SubscriberLocationReport-Res", ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), fmt.Sprintf("ExtData_[%d]", len(v.ExtData_)), "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); orderErr_ != nil {
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
