// Code generated from ASN.1 module "SS-DataTypes". DO NOT EDIT.

package gsm_map

import (
	"fmt"
	"math/big"

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

	// Max10TimesUnitsPerTime is the integer constant for Max10TimesUnitsPerTime.
	Max10TimesUnitsPerTime int64 = 8191

	// Max10TimesTimeInterval is the integer constant for Max10TimesTimeInterval.
	Max10TimesTimeInterval int64 = 8191

	// Max100TimesScalingFactor is the integer constant for Max100TimesScalingFactor.
	Max100TimesScalingFactor int64 = 8191

	// Max10TimesIncrement is the integer constant for Max10TimesIncrement.
	Max10TimesIncrement int64 = 8191

	// Max10TimesIncrementPerDataInterval is the integer constant for Max10TimesIncrementPerDataInterval.
	Max10TimesIncrementPerDataInterval int64 = 8191

	// MaxNumberOfSegmentsPerDataInterval is the integer constant for MaxNumberOfSegmentsPerDataInterval.
	MaxNumberOfSegmentsPerDataInterval int64 = 8191

	// Max10TimesInitialTime is the integer constant for Max10TimesInitialTime.
	Max10TimesInitialTime int64 = 8191

	// MaxNumLPPMsg is the integer constant for MaxNumLPPMsg.
	MaxNumLPPMsg int64 = 3

	// MaxRelatedUE is the integer constant for MaxRelatedUE.
	MaxRelatedUE int64 = 16

	// MaxAreas is the integer constant for MaxAreas.
	MaxAreas int64 = 250

	// MaxNumSLPPMsg is the integer constant for MaxNumSLPPMsg.
	MaxNumSLPPMsg int64 = 63
)

// SSUserData represents the ASN.1 type SSUserData (IA5String).
type SSUserData = string

// NotifySSArg represents the ASN.1 type NotifySSArg (SEQUENCE).
type NotifySSArg struct {
	SsCode                  *SSCode              `asn1:"tag:1,context,implicit,optional" json:"SsCode,omitempty"`
	SsStatus                *SSStatus            `asn1:"tag:4,context,implicit,optional" json:"SsStatus,omitempty"`
	SsNotification          *SSNotification      `asn1:"tag:5,context,implicit,optional" json:"SsNotification,omitempty"`
	CallIsWaitingIndicator  *struct{}            `asn1:"tag:14,context,implicit,optional" json:"CallIsWaitingIndicator,omitempty"`
	CallOnHoldIndicator     *CallOnHoldIndicator `asn1:"tag:15,context,implicit,optional" json:"CallOnHoldIndicator,omitempty"`
	MptyIndicator           *struct{}            `asn1:"tag:16,context,implicit,optional" json:"MptyIndicator,omitempty"`
	CugIndex                *CUGIndex            `asn1:"tag:17,context,implicit,optional" json:"CugIndex,omitempty"`
	ClirSuppressionRejected *struct{}            `asn1:"tag:18,context,implicit,optional" json:"ClirSuppressionRejected,omitempty"`
	EctIndicator            *ECTIndicator        `asn1:"tag:19,context,implicit,optional" json:"EctIndicator,omitempty"`
	NameIndicator           *NameIndicator       `asn1:"tag:20,context,implicit,optional" json:"NameIndicator,omitempty"`
	CcbsFeature             *CCBSFeature         `asn1:"tag:21,context,implicit,optional" json:"CcbsFeature,omitempty"`
	AlertingPattern         *AlertingPattern     `asn1:"tag:22,context,implicit,optional" json:"AlertingPattern,omitempty"`
	MulticallIndicator      *MulticallIndicator  `asn1:"tag:23,context,implicit,optional" json:"MulticallIndicator,omitempty"`
	ExtCount_               int64                `asn1:"-" json:"-"`
	ExtPresent_             []bool               `asn1:"-" json:"-"`
	ExtData_                [][]byte             `asn1:"-" json:"-"`
}

// MulticallIndicator represents the ASN.1 ENUMERATED type MulticallIndicator.
type MulticallIndicator int64

const (
	MulticallIndicatorNbrSNexceeded   MulticallIndicator = 0
	MulticallIndicatorNbrUserexceeded MulticallIndicator = 1
)

func (v MulticallIndicator) String() string {
	switch v {
	case MulticallIndicatorNbrSNexceeded:
		return "nbr-SNexceeded"
	case MulticallIndicatorNbrUserexceeded:
		return "nbr-Userexceeded"
	default:
		return "unknown"
	}
}

// ForwardChargeAdviceArg represents the ASN.1 type ForwardChargeAdviceArg (SEQUENCE).
type ForwardChargeAdviceArg struct {
	SsCode              SSCode              `asn1:"tag:0,context,implicit"`
	ChargingInformation ChargingInformation `asn1:"tag:1,context,implicit"`
	ExtCount_           int64               `asn1:"-" json:"-"`
	ExtPresent_         []bool              `asn1:"-" json:"-"`
	ExtData_            [][]byte            `asn1:"-" json:"-"`
}

// SSNotification represents the ASN.1 type SSNotification (OCTET_STRING).
type SSNotification = []byte

// ChargingInformation represents the ASN.1 type ChargingInformation (SEQUENCE).
type ChargingInformation struct {
	E1          *E1      `asn1:"tag:1,context,implicit,optional" json:"E1,omitempty"`
	E2          *E2      `asn1:"tag:2,context,implicit,optional" json:"E2,omitempty"`
	E3          *E3      `asn1:"tag:3,context,implicit,optional" json:"E3,omitempty"`
	E4          *E4      `asn1:"tag:4,context,implicit,optional" json:"E4,omitempty"`
	E5          *E5      `asn1:"tag:5,context,implicit,optional" json:"E5,omitempty"`
	E6          *E6      `asn1:"tag:6,context,implicit,optional" json:"E6,omitempty"`
	E7          *E7      `asn1:"tag:7,context,implicit,optional" json:"E7,omitempty"`
	ExtCount_   int64    `asn1:"-" json:"-"`
	ExtPresent_ []bool   `asn1:"-" json:"-"`
	ExtData_    [][]byte `asn1:"-" json:"-"`
}

// E1 represents the ASN.1 type E1 (INTEGER).
type E1 = int64

// E2 represents the ASN.1 type E2 (INTEGER).
type E2 = int64

// E3 represents the ASN.1 type E3 (INTEGER).
type E3 = int64

// E4 represents the ASN.1 type E4 (INTEGER).
type E4 = int64

// E5 represents the ASN.1 type E5 (INTEGER).
type E5 = int64

// E6 represents the ASN.1 type E6 (INTEGER).
type E6 = int64

// E7 represents the ASN.1 type E7 (INTEGER).
type E7 = int64

// CallOnHoldIndicator represents the ASN.1 ENUMERATED type CallOnHoldIndicator.
type CallOnHoldIndicator int64

const (
	CallOnHoldIndicatorCallRetrieved CallOnHoldIndicator = 0
	CallOnHoldIndicatorCallOnHold    CallOnHoldIndicator = 1
)

func (v CallOnHoldIndicator) String() string {
	switch v {
	case CallOnHoldIndicatorCallRetrieved:
		return "callRetrieved"
	case CallOnHoldIndicatorCallOnHold:
		return "callOnHold"
	default:
		return "unknown"
	}
}

// ForwardCUGInfoArg represents the ASN.1 type ForwardCUGInfoArg (SEQUENCE).
type ForwardCUGInfoArg struct {
	CugIndex        *CUGIndex `asn1:"tag:0,context,implicit,optional" json:"CugIndex,omitempty"`
	SuppressPrefCUG *struct{} `asn1:"tag:1,context,implicit,optional" json:"SuppressPrefCUG,omitempty"`
	SuppressOA      *struct{} `asn1:"tag:2,context,implicit,optional" json:"SuppressOA,omitempty"`
	ExtCount_       int64     `asn1:"-" json:"-"`
	ExtPresent_     []bool    `asn1:"-" json:"-"`
	ExtData_        [][]byte  `asn1:"-" json:"-"`
}

// ECTIndicator represents the ASN.1 type ECTIndicator (SEQUENCE).
type ECTIndicator struct {
	EctCallState ECTCallState `asn1:"tag:0,context,implicit"`
	Rdn          *RDN         `asn1:"tag:1,context,explicit,optional" json:"Rdn,omitempty"`
	ExtCount_    int64        `asn1:"-" json:"-"`
	ExtPresent_  []bool       `asn1:"-" json:"-"`
	ExtData_     [][]byte     `asn1:"-" json:"-"`
}

// ECTCallState represents the ASN.1 ENUMERATED type ECTCallState.
type ECTCallState int64

const (
	ECTCallStateAlerting ECTCallState = 0
	ECTCallStateActive   ECTCallState = 1
)

func (v ECTCallState) String() string {
	switch v {
	case ECTCallStateAlerting:
		return "alerting"
	case ECTCallStateActive:
		return "active"
	default:
		return "unknown"
	}
}

// NameIndicator represents the ASN.1 type NameIndicator (SEQUENCE).
type NameIndicator struct {
	CallingName *Name    `asn1:"tag:0,context,explicit,optional" json:"CallingName,omitempty"`
	ExtCount_   int64    `asn1:"-" json:"-"`
	ExtPresent_ []bool   `asn1:"-" json:"-"`
	ExtData_    [][]byte `asn1:"-" json:"-"`
}

// Name choice constants.
const (
	NameChoiceNamePresentationAllowed    = 1
	NameChoicePresentationRestricted     = 2
	NameChoiceNameUnavailable            = 3
	NameChoiceNamePresentationRestricted = 4
)

// Name represents the ASN.1 CHOICE type Name.
type Name struct {
	Choice                     int
	NamePresentationAllowed    *NameSet  `json:"NamePresentationAllowed,omitempty"`
	PresentationRestricted     *struct{} `json:"PresentationRestricted,omitempty"`
	NameUnavailable            *struct{} `json:"NameUnavailable,omitempty"`
	NamePresentationRestricted *NameSet  `json:"NamePresentationRestricted,omitempty"`
}

// NewNameNamePresentationAllowed creates a Name with the namePresentationAllowed alternative.
func NewNameNamePresentationAllowed(v NameSet) Name {
	return Name{
		Choice:                  NameChoiceNamePresentationAllowed,
		NamePresentationAllowed: &v,
	}
}

// NewNamePresentationRestricted creates a Name with the presentationRestricted alternative.
func NewNamePresentationRestricted(v struct{}) Name {
	return Name{
		Choice:                 NameChoicePresentationRestricted,
		PresentationRestricted: &v,
	}
}

// NewNameNameUnavailable creates a Name with the nameUnavailable alternative.
func NewNameNameUnavailable(v struct{}) Name {
	return Name{
		Choice:          NameChoiceNameUnavailable,
		NameUnavailable: &v,
	}
}

// NewNameNamePresentationRestricted creates a Name with the namePresentationRestricted alternative.
func NewNameNamePresentationRestricted(v NameSet) Name {
	return Name{
		Choice:                     NameChoiceNamePresentationRestricted,
		NamePresentationRestricted: &v,
	}
}

// NameSet represents the ASN.1 type NameSet (SEQUENCE).
type NameSet struct {
	DataCodingScheme   USSDDataCodingScheme `asn1:"tag:0,context,implicit"`
	LengthInCharacters *big.Int             `asn1:"tag:1,context,implicit"`
	NameString         USSDString           `asn1:"tag:2,context,implicit"`
	ExtCount_          int64                `asn1:"-" json:"-"`
	ExtPresent_        []bool               `asn1:"-" json:"-"`
	ExtData_           [][]byte             `asn1:"-" json:"-"`
}

// RDN choice constants.
const (
	RDNChoicePresentationAllowedAddress          = 1
	RDNChoicePresentationRestricted              = 2
	RDNChoiceNumberNotAvailableDueToInterworking = 3
	RDNChoicePresentationRestrictedAddress       = 4
)

// RDN represents the ASN.1 CHOICE type RDN.
type RDN struct {
	Choice                              int
	PresentationAllowedAddress          *RemotePartyNumber `json:"PresentationAllowedAddress,omitempty"`
	PresentationRestricted              *struct{}          `json:"PresentationRestricted,omitempty"`
	NumberNotAvailableDueToInterworking *struct{}          `json:"NumberNotAvailableDueToInterworking,omitempty"`
	PresentationRestrictedAddress       *RemotePartyNumber `json:"PresentationRestrictedAddress,omitempty"`
}

// NewRDNPresentationAllowedAddress creates a RDN with the presentationAllowedAddress alternative.
func NewRDNPresentationAllowedAddress(v RemotePartyNumber) RDN {
	return RDN{
		Choice:                     RDNChoicePresentationAllowedAddress,
		PresentationAllowedAddress: &v,
	}
}

// NewRDNPresentationRestricted creates a RDN with the presentationRestricted alternative.
func NewRDNPresentationRestricted(v struct{}) RDN {
	return RDN{
		Choice:                 RDNChoicePresentationRestricted,
		PresentationRestricted: &v,
	}
}

// NewRDNNumberNotAvailableDueToInterworking creates a RDN with the numberNotAvailableDueToInterworking alternative.
func NewRDNNumberNotAvailableDueToInterworking(v struct{}) RDN {
	return RDN{
		Choice:                              RDNChoiceNumberNotAvailableDueToInterworking,
		NumberNotAvailableDueToInterworking: &v,
	}
}

// NewRDNPresentationRestrictedAddress creates a RDN with the presentationRestrictedAddress alternative.
func NewRDNPresentationRestrictedAddress(v RemotePartyNumber) RDN {
	return RDN{
		Choice:                        RDNChoicePresentationRestrictedAddress,
		PresentationRestrictedAddress: &v,
	}
}

// RemotePartyNumber represents the ASN.1 type RemotePartyNumber (SEQUENCE).
type RemotePartyNumber struct {
	PartyNumber           ISDNAddressString     `asn1:"tag:0,context,implicit"`
	PartyNumberSubaddress *ISDNSubaddressString `asn1:"tag:1,context,implicit,optional" json:"PartyNumberSubaddress,omitempty"`
	ExtCount_             int64                 `asn1:"-" json:"-"`
	ExtPresent_           []bool                `asn1:"-" json:"-"`
	ExtData_              [][]byte              `asn1:"-" json:"-"`
}

// AccessRegisterCCEntryArg represents the ASN.1 type AccessRegisterCCEntryArg (SEQUENCE).
type AccessRegisterCCEntryArg struct {
	ExtCount_   int64    `asn1:"-" json:"-"`
	ExtPresent_ []bool   `asn1:"-" json:"-"`
	ExtData_    [][]byte `asn1:"-" json:"-"`
}

// CallDeflectionArg represents the ASN.1 type CallDeflectionArg (SEQUENCE).
type CallDeflectionArg struct {
	DeflectedToNumber     AddressString         `asn1:"tag:0,context,implicit"`
	DeflectedToSubaddress *ISDNSubaddressString `asn1:"tag:1,context,implicit,optional" json:"DeflectedToSubaddress,omitempty"`
	ExtCount_             int64                 `asn1:"-" json:"-"`
	ExtPresent_           []bool                `asn1:"-" json:"-"`
	ExtData_              [][]byte              `asn1:"-" json:"-"`
}

// UserUserServiceArg represents the ASN.1 type UserUserServiceArg (SEQUENCE).
type UserUserServiceArg struct {
	UUSService      UUSService `asn1:"tag:0,context,implicit"`
	UUSRequired     bool       `asn1:"tag:1,context,implicit"`
	UUSRequiredRaw_ byte       `asn1:"-" json:"-"`
	ExtCount_       int64      `asn1:"-" json:"-"`
	ExtPresent_     []bool     `asn1:"-" json:"-"`
	ExtData_        [][]byte   `asn1:"-" json:"-"`
}

// UUSService represents the ASN.1 ENUMERATED type UUSService.
type UUSService int64

const (
	UUSServiceUUS1 UUSService = 1
	UUSServiceUUS2 UUSService = 2
	UUSServiceUUS3 UUSService = 3
)

func (v UUSService) String() string {
	switch v {
	case UUSServiceUUS1:
		return "uUS1"
	case UUSServiceUUS2:
		return "uUS2"
	case UUSServiceUUS3:
		return "uUS3"
	default:
		return "unknown"
	}
}

// LocationNotificationArg represents the ASN.1 type LocationNotificationArg (SEQUENCE).
type LocationNotificationArg struct {
	NotificationType    NotificationToMSUser `asn1:"tag:0,context,implicit"`
	LocationType        LocationType         `asn1:"tag:1,context,implicit"`
	LcsClientExternalID *LCSClientExternalID `asn1:"tag:2,context,implicit,optional" json:"LcsClientExternalID,omitempty"`
	LcsClientName       *LCSClientName       `asn1:"tag:3,context,implicit,optional" json:"LcsClientName,omitempty"`
	LcsRequestorID      *LCSRequestorID      `asn1:"tag:4,context,implicit,optional" json:"LcsRequestorID,omitempty"`
	LcsCodeword         *LCSCodeword         `asn1:"tag:5,context,implicit,optional" json:"LcsCodeword,omitempty"`
	LcsServiceTypeID    *LCSServiceTypeID    `asn1:"tag:6,context,implicit,optional" json:"LcsServiceTypeID,omitempty"`
	DeferredLocationExt *DeferredLocationExt `asn1:"tag:7,context,implicit,optional" json:"DeferredLocationExt,omitempty"`
	RangingSlExt        *RangingSlExt        `asn1:"tag:8,context,implicit,optional" json:"RangingSlExt,omitempty"`
	ExtCount_           int64                `asn1:"-" json:"-"`
	ExtPresent_         []bool               `asn1:"-" json:"-"`
	ExtData_            [][]byte             `asn1:"-" json:"-"`
}

// DeferredLocationExt represents the ASN.1 type DeferredLocationExt (BIT_STRING).
type DeferredLocationExt = runtime.BitString

// RangingSlExt represents the ASN.1 type RangingSlExt (BIT_STRING).
type RangingSlExt = runtime.BitString

// LocationNotificationRes represents the ASN.1 type LocationNotificationRes (SEQUENCE).
type LocationNotificationRes struct {
	VerificationResponse      *VerificationResponse         `asn1:"tag:0,context,implicit,optional" json:"VerificationResponse,omitempty"`
	LocationPrivacyIndication *LCSLocationPrivacyIndication `asn1:"tag:1,context,implicit,optional" json:"LocationPrivacyIndication,omitempty"`
	ValidTimePeriod           *LCSValidTimePeriod           `asn1:"tag:2,context,implicit,optional" json:"ValidTimePeriod,omitempty"`
	ExtCount_                 int64                         `asn1:"-" json:"-"`
	ExtPresent_               []bool                        `asn1:"-" json:"-"`
	ExtData_                  [][]byte                      `asn1:"-" json:"-"`
}

// VerificationResponse represents the ASN.1 ENUMERATED type VerificationResponse.
type VerificationResponse int64

const (
	VerificationResponsePermissionDenied  VerificationResponse = 0
	VerificationResponsePermissionGranted VerificationResponse = 1
)

func (v VerificationResponse) String() string {
	switch v {
	case VerificationResponsePermissionDenied:
		return "permissionDenied"
	case VerificationResponsePermissionGranted:
		return "permissionGranted"
	default:
		return "unknown"
	}
}

// LCSMOLRArg represents the ASN.1 type LCSMOLRArg (SEQUENCE).
type LCSMOLRArg struct {
	MolrType                              MOLRType                        `asn1:"tag:0,context,implicit"`
	LocationMethod                        *LocationMethod                 `asn1:"tag:1,context,implicit,optional" json:"LocationMethod,omitempty"`
	LcsQoS                                *LCSQoS                         `asn1:"tag:2,context,implicit,optional" json:"LcsQoS,omitempty"`
	LcsClientExternalID                   *LCSClientExternalID            `asn1:"tag:3,context,implicit,optional" json:"LcsClientExternalID,omitempty"`
	MlcNumber                             *ISDNAddressString              `asn1:"tag:4,context,implicit,optional" json:"MlcNumber,omitempty"`
	GpsAssistanceData                     *GPSAssistanceData              `asn1:"tag:5,context,implicit,optional" json:"GpsAssistanceData,omitempty"`
	SupportedGADShapes                    *SupportedGADShapes             `asn1:"tag:6,context,implicit,optional" json:"SupportedGADShapes,omitempty"`
	LcsServiceTypeID                      *LCSServiceTypeID               `asn1:"tag:7,context,implicit,optional" json:"LcsServiceTypeID,omitempty"`
	AgeOfLocationInfo                     *AgeOfLocationInformation       `asn1:"tag:8,context,implicit,optional" json:"AgeOfLocationInfo,omitempty"`
	LocationType                          *LocationType                   `asn1:"tag:9,context,implicit,optional" json:"LocationType,omitempty"`
	PseudonymIndicator                    *struct{}                       `asn1:"tag:10,context,implicit,optional" json:"PseudonymIndicator,omitempty"`
	HGmlcAddress                          *GSNAddress                     `asn1:"tag:11,context,implicit,optional" json:"HGmlcAddress,omitempty"`
	LocationEstimate                      *ExtGeographicalInformation     `asn1:"tag:12,context,implicit,optional" json:"LocationEstimate,omitempty"`
	VelocityEstimate                      *VelocityEstimate               `asn1:"tag:13,context,implicit,optional" json:"VelocityEstimate,omitempty"`
	ReferenceNumber                       *LCSReferenceNumber             `asn1:"tag:14,context,implicit,optional" json:"ReferenceNumber,omitempty"`
	PeriodicLDRInfo                       *PeriodicLDRInfo                `asn1:"tag:15,context,implicit,optional" json:"PeriodicLDRInfo,omitempty"`
	LocationUpdateRequest                 *struct{}                       `asn1:"tag:16,context,implicit,optional" json:"LocationUpdateRequest,omitempty"`
	SequenceNumber                        *SequenceNumber                 `asn1:"tag:17,context,implicit,optional" json:"SequenceNumber,omitempty"`
	TerminationCause                      *DataTypesTerminationCause      `asn1:"tag:18,context,implicit,optional" json:"TerminationCause,omitempty"`
	MoLrShortCircuit                      *struct{}                       `asn1:"tag:19,context,implicit,optional" json:"MoLrShortCircuit,omitempty"`
	GanssAssistanceData                   *GANSSAssistanceData            `asn1:"tag:20,context,implicit,optional" json:"GanssAssistanceData,omitempty"`
	MultiplePositioningProtocolPDUs       MultiplePositioningProtocolPDUs `asn1:"tag:21,context,implicit,optional" json:"MultiplePositioningProtocolPDUs,omitempty"`
	MultiplePositioningProtocolPDUsIndef_ bool                            `asn1:"-" json:"-"`
	LocationInfo                          *DataTypesLocationInfo          `asn1:"tag:22,context,implicit,optional" json:"LocationInfo,omitempty"`
	ScheduledLocTime                      *DateTime                       `asn1:"tag:23,context,implicit,optional" json:"ScheduledLocTime,omitempty"`
	ExtCount_                             int64                           `asn1:"-" json:"-"`
	ExtPresent_                           []bool                          `asn1:"-" json:"-"`
	ExtData_                              [][]byte                        `asn1:"-" json:"-"`
}

// MOLRType represents the ASN.1 ENUMERATED type MOLRType.
type MOLRType int64

const (
	MOLRTypeLocationEstimate                       MOLRType = 0
	MOLRTypeAssistanceData                         MOLRType = 1
	MOLRTypeDeCipheringKeys                        MOLRType = 2
	MOLRTypeDeferredMoLrTTTPInitiation             MOLRType = 3
	MOLRTypeDeferredMoLrSelfLocationInitiation     MOLRType = 4
	MOLRTypeDeferredMtLrOrmoLrTTTPLocationEstimate MOLRType = 5
	MOLRTypeDeferredMtLrOrmoLrCancellation         MOLRType = 6
	MOLRTypePeriodicEvent                          MOLRType = 7
	MOLRTypeEnteringAreaEvent                      MOLRType = 8
	MOLRTypeLeavingAreaEvent                       MOLRType = 9
	MOLRTypeBeingInsideAreaEvent                   MOLRType = 10
	MOLRTypeMotionEvent                            MOLRType = 11
	MOLRTypeMaximumIntervalExpirationEvent         MOLRType = 12
)

func (v MOLRType) String() string {
	switch v {
	case MOLRTypeLocationEstimate:
		return "locationEstimate"
	case MOLRTypeAssistanceData:
		return "assistanceData"
	case MOLRTypeDeCipheringKeys:
		return "deCipheringKeys"
	case MOLRTypeDeferredMoLrTTTPInitiation:
		return "deferredMo-lrTTTPInitiation"
	case MOLRTypeDeferredMoLrSelfLocationInitiation:
		return "deferredMo-lrSelfLocationInitiation"
	case MOLRTypeDeferredMtLrOrmoLrTTTPLocationEstimate:
		return "deferredMt-lrOrmo-lrTTTPLocationEstimate"
	case MOLRTypeDeferredMtLrOrmoLrCancellation:
		return "deferredMt-lrOrmo-lrCancellation"
	case MOLRTypePeriodicEvent:
		return "periodicEvent"
	case MOLRTypeEnteringAreaEvent:
		return "enteringAreaEvent"
	case MOLRTypeLeavingAreaEvent:
		return "leavingAreaEvent"
	case MOLRTypeBeingInsideAreaEvent:
		return "beingInsideAreaEvent"
	case MOLRTypeMotionEvent:
		return "motionEvent"
	case MOLRTypeMaximumIntervalExpirationEvent:
		return "maximumIntervalExpirationEvent"
	default:
		return "unknown"
	}
}

// LocationMethod represents the ASN.1 ENUMERATED type LocationMethod.
type LocationMethod int64

const (
	LocationMethodMsBasedEOTD         LocationMethod = 0
	LocationMethodMsAssistedEOTD      LocationMethod = 1
	LocationMethodAssistedGPS         LocationMethod = 2
	LocationMethodMsBasedOTDOA        LocationMethod = 3
	LocationMethodAssistedGANSS       LocationMethod = 4
	LocationMethodAssistedGPSandGANSS LocationMethod = 5
)

func (v LocationMethod) String() string {
	switch v {
	case LocationMethodMsBasedEOTD:
		return "msBasedEOTD"
	case LocationMethodMsAssistedEOTD:
		return "msAssistedEOTD"
	case LocationMethodAssistedGPS:
		return "assistedGPS"
	case LocationMethodMsBasedOTDOA:
		return "msBasedOTDOA"
	case LocationMethodAssistedGANSS:
		return "assistedGANSS"
	case LocationMethodAssistedGPSandGANSS:
		return "assistedGPSandGANSS"
	default:
		return "unknown"
	}
}

// GPSAssistanceData represents the ASN.1 type GPSAssistanceData (OCTET_STRING).
type GPSAssistanceData = []byte

// GANSSAssistanceData represents the ASN.1 type GANSSAssistanceData (OCTET_STRING).
type GANSSAssistanceData = []byte

// DataTypesTerminationCause represents the ASN.1 ENUMERATED type DataTypesTerminationCause.
type DataTypesTerminationCause int64

const (
	DataTypesTerminationCauseSubscriberTermination DataTypesTerminationCause = 0
	DataTypesTerminationCauseUETermination         DataTypesTerminationCause = 1
	DataTypesTerminationCauseNormalTermination     DataTypesTerminationCause = 2
	DataTypesTerminationCauseNetworkTermination    DataTypesTerminationCause = 3
)

func (v DataTypesTerminationCause) String() string {
	switch v {
	case DataTypesTerminationCauseSubscriberTermination:
		return "subscriberTermination"
	case DataTypesTerminationCauseUETermination:
		return "uETermination"
	case DataTypesTerminationCauseNormalTermination:
		return "normalTermination"
	case DataTypesTerminationCauseNetworkTermination:
		return "networkTermination"
	default:
		return "unknown"
	}
}

// MultiplePositioningProtocolPDUs represents the ASN.1 type MultiplePositioningProtocolPDUs (SEQUENCE_OF).
type MultiplePositioningProtocolPDUs = []PositioningProtocolPDU

// PositioningProtocolPDU represents the ASN.1 type PositioningProtocolPDU (OCTET_STRING).
type PositioningProtocolPDU = []byte

// LCSMOLRRes represents the ASN.1 type LCSMOLRRes (SEQUENCE).
type LCSMOLRRes struct {
	LocationEstimate            *ExtGeographicalInformation `asn1:"tag:0,context,implicit,optional" json:"LocationEstimate,omitempty"`
	DecipheringKeys             *DecipheringKeys            `asn1:"tag:1,context,implicit,optional" json:"DecipheringKeys,omitempty"`
	AddLocationEstimate         *AddGeographicalInformation `asn1:"tag:2,context,implicit,optional" json:"AddLocationEstimate,omitempty"`
	VelocityEstimate            *VelocityEstimate           `asn1:"tag:3,context,implicit,optional" json:"VelocityEstimate,omitempty"`
	ReferenceNumber             *LCSReferenceNumber         `asn1:"tag:4,context,implicit,optional" json:"ReferenceNumber,omitempty"`
	HGmlcAddress                *GSNAddress                 `asn1:"tag:5,context,implicit,optional" json:"HGmlcAddress,omitempty"`
	MoLrShortCircuit            *struct{}                   `asn1:"tag:6,context,implicit,optional" json:"MoLrShortCircuit,omitempty"`
	ReportingPLMNList           *ReportingPLMNList          `asn1:"tag:7,context,implicit,optional" json:"ReportingPLMNList,omitempty"`
	TimestampOfLocationEstimate *DateTime                   `asn1:"tag:8,context,implicit,optional" json:"TimestampOfLocationEstimate,omitempty"`
	ExtCount_                   int64                       `asn1:"-" json:"-"`
	ExtPresent_                 []bool                      `asn1:"-" json:"-"`
	ExtData_                    [][]byte                    `asn1:"-" json:"-"`
}

// DecipheringKeys represents the ASN.1 type DecipheringKeys (OCTET_STRING).
type DecipheringKeys = []byte

// LCSAreaEventRequestArg represents the ASN.1 type LCSAreaEventRequestArg (SEQUENCE).
type LCSAreaEventRequestArg struct {
	ReferenceNumber           LCSReferenceNumber        `asn1:"tag:0,context,implicit"`
	HGmlcAddress              GSNAddress                `asn1:"tag:1,context,implicit"`
	DeferredLocationEventType DeferredLocationEventType `asn1:"tag:3,context,implicit"`
	AreaEventInfo             AreaEventInfo             `asn1:"tag:4,context,implicit"`
	ExtCount_                 int64                     `asn1:"-" json:"-"`
	ExtPresent_               []bool                    `asn1:"-" json:"-"`
	ExtData_                  [][]byte                  `asn1:"-" json:"-"`
}

// SLMOLRType represents the ASN.1 ENUMERATED type SLMOLRType.
type SLMOLRType int64

const (
	SLMOLRTypeRangingSidelink SLMOLRType = 0
)

func (v SLMOLRType) String() string {
	switch v {
	case SLMOLRTypeRangingSidelink:
		return "rangingSidelink"
	default:
		return "unknown"
	}
}

// LCSSLMOLRArg represents the ASN.1 type LCSSLMOLRArg (SEQUENCE).
type LCSSLMOLRArg struct {
	SlmolrType                     SLMOLRType              `asn1:"tag:0,context,implicit"`
	LcsQoS                         *LCSQoS                 `asn1:"tag:1,context,implicit,optional" json:"LcsQoS,omitempty"`
	LcsClientExternalID            *LCSClientExternalID    `asn1:"tag:2,context,implicit,optional" json:"LcsClientExternalID,omitempty"`
	MlcNumber                      *ISDNAddressString      `asn1:"tag:3,context,implicit,optional" json:"MlcNumber,omitempty"`
	SupportedGADShapes             *SupportedGADShapes     `asn1:"tag:4,context,implicit,optional" json:"SupportedGADShapes,omitempty"`
	LcsServiceTypeID               *LCSServiceTypeID       `asn1:"tag:5,context,implicit,optional" json:"LcsServiceTypeID,omitempty"`
	PseudonymIndicator             *struct{}               `asn1:"tag:7,context,implicit,optional" json:"PseudonymIndicator,omitempty"`
	HGmlcAddress                   *GSNAddress             `asn1:"tag:8,context,implicit,optional" json:"HGmlcAddress,omitempty"`
	CalculationAssistIndicator     *bool                   `asn1:"tag:9,context,implicit,optional" json:"CalculationAssistIndicator,omitempty"`
	CalculationAssistIndicatorRaw_ byte                    `asn1:"-" json:"-"`
	PreferredRangingResult         *PreferredRangingResult `asn1:"tag:10,context,implicit,optional" json:"PreferredRangingResult,omitempty"`
	RelatedUEInfo                  RelatedUEInfo           `asn1:"tag:11,context,implicit,optional" json:"RelatedUEInfo,omitempty"`
	RelatedUEInfoIndef_            bool                    `asn1:"-" json:"-"`
	ExtCount_                      int64                   `asn1:"-" json:"-"`
	ExtPresent_                    []bool                  `asn1:"-" json:"-"`
	ExtData_                       [][]byte                `asn1:"-" json:"-"`
}

// PreferredRangingResult represents the ASN.1 type PreferredRangingResult (SEQUENCE).
type PreferredRangingResult struct {
	AbsoluteLocationIndicator     *bool    `asn1:"tag:0,context,implicit,optional" json:"AbsoluteLocationIndicator,omitempty"`
	AbsoluteLocationIndicatorRaw_ byte     `asn1:"-" json:"-"`
	AbsoluteVelocityIndicator     *bool    `asn1:"tag:1,context,implicit,optional" json:"AbsoluteVelocityIndicator,omitempty"`
	AbsoluteVelocityIndicatorRaw_ byte     `asn1:"-" json:"-"`
	RelativeLocationIndicator     *bool    `asn1:"tag:2,context,implicit,optional" json:"RelativeLocationIndicator,omitempty"`
	RelativeLocationIndicatorRaw_ byte     `asn1:"-" json:"-"`
	RangeDirection                *bool    `asn1:"tag:3,context,implicit,optional" json:"RangeDirection,omitempty"`
	RangeDirectionRaw_            byte     `asn1:"-" json:"-"`
	RelativeVelocityIndicator     *bool    `asn1:"tag:4,context,implicit,optional" json:"RelativeVelocityIndicator,omitempty"`
	RelativeVelocityIndicatorRaw_ byte     `asn1:"-" json:"-"`
	ExtCount_                     int64    `asn1:"-" json:"-"`
	ExtPresent_                   []bool   `asn1:"-" json:"-"`
	ExtData_                      [][]byte `asn1:"-" json:"-"`
}

// RelatedUEInfo represents the ASN.1 type RelatedUEInfo (SEQUENCE_OF).
type RelatedUEInfo = []RangingUEInfo

// RangingUEInfo represents the ASN.1 type RangingUEInfo (SEQUENCE).
type RangingUEInfo struct {
	ApplicationLayerID []byte       `asn1:"tag:0,context,implicit"`
	RangingRole        *RangingRole `asn1:"tag:1,context,implicit,optional" json:"RangingRole,omitempty"`
	ExtCount_          int64        `asn1:"-" json:"-"`
	ExtPresent_        []bool       `asn1:"-" json:"-"`
	ExtData_           [][]byte     `asn1:"-" json:"-"`
}

// RangingRole represents the ASN.1 ENUMERATED type RangingRole.
type RangingRole int64

const (
	RangingRoleTargetUE      RangingRole = 0
	RangingRoleLocatedUE     RangingRole = 1
	RangingRoleSlReferenceUE RangingRole = 2
	RangingRoleSlServerUE    RangingRole = 3
	RangingRoleSlClientUE    RangingRole = 4
)

func (v RangingRole) String() string {
	switch v {
	case RangingRoleTargetUE:
		return "targetUE"
	case RangingRoleLocatedUE:
		return "locatedUE"
	case RangingRoleSlReferenceUE:
		return "slReferenceUE"
	case RangingRoleSlServerUE:
		return "slServerUE"
	case RangingRoleSlClientUE:
		return "slClientUE"
	default:
		return "unknown"
	}
}

// LCSSLMOLRRes represents the ASN.1 type LCSSLMOLRRes (SEQUENCE).
type LCSSLMOLRRes struct {
	AbsoluteLocation     *ExtGeographicalInformation `asn1:"tag:0,context,implicit,optional" json:"AbsoluteLocation,omitempty"`
	AbsoluteVelocity     *VelocityEstimate           `asn1:"tag:1,context,implicit,optional" json:"AbsoluteVelocity,omitempty"`
	RelativeResult       RelativeResult              `asn1:"tag:2,context,implicit,optional" json:"RelativeResult,omitempty"`
	RelativeResultIndef_ bool                        `asn1:"-" json:"-"`
	UeOnlyRSLPosAllowed  *Duration                   `asn1:"tag:4,context,implicit,optional" json:"UeOnlyRSLPosAllowed,omitempty"`
	Timestamp            *DateTime                   `asn1:"tag:5,context,implicit,optional" json:"Timestamp,omitempty"`
	ExtCount_            int64                       `asn1:"-" json:"-"`
	ExtPresent_          []bool                      `asn1:"-" json:"-"`
	ExtData_             [][]byte                    `asn1:"-" json:"-"`
}

// RelativeResult represents the ASN.1 type RelativeResult (SEQUENCE_OF).
type RelativeResult = []SingleRelativeResult

// SingleRelativeResult represents the ASN.1 type SingleRelativeResult (SEQUENCE).
type SingleRelativeResult struct {
	RelatedUEInfo       RelatedUEInfo                `asn1:"tag:0,context,implicit,optional" json:"RelatedUEInfo,omitempty"`
	RelatedUEInfoIndef_ bool                         `asn1:"-" json:"-"`
	RelativeLocation    *RelativeLocationCoordinates `asn1:"tag:1,context,implicit,optional" json:"RelativeLocation,omitempty"`
	RangeDirection      *RangeDirection              `asn1:"tag:2,context,implicit,optional" json:"RangeDirection,omitempty"`
	RelativeVelocity    *VelocityEstimate            `asn1:"tag:3,context,implicit,optional" json:"RelativeVelocity,omitempty"`
	ExtCount_           int64                        `asn1:"-" json:"-"`
	ExtPresent_         []bool                       `asn1:"-" json:"-"`
	ExtData_            [][]byte                     `asn1:"-" json:"-"`
}

// RelativeLocationCoordinates represents the ASN.1 type RelativeLocationCoordinates (SEQUENCE).
type RelativeLocationCoordinates struct {
	Relative2DLocationWithUncertaintyEllipse   *Relative2DLocationWithUncertaintyEllipse   `asn1:"tag:0,context,implicit,optional" json:"Relative2DLocationWithUncertaintyEllipse,omitempty"`
	Relative3DLocationWithUncertaintyEllipsoid *Relative3DLocationWithUncertaintyEllipsoid `asn1:"tag:1,context,implicit,optional" json:"Relative3DLocationWithUncertaintyEllipsoid,omitempty"`
	ExtCount_                                  int64                                       `asn1:"-" json:"-"`
	ExtPresent_                                []bool                                      `asn1:"-" json:"-"`
	ExtData_                                   [][]byte                                    `asn1:"-" json:"-"`
}

// Relative2DLocationWithUncertaintyEllipse represents the ASN.1 type Relative2DLocationWithUncertaintyEllipse (SEQUENCE).
type Relative2DLocationWithUncertaintyEllipse struct {
	XCoordinates         RangeXYCoordinates   `asn1:"tag:0,context,implicit"`
	YCoordinates         RangeXYCoordinates   `asn1:"tag:1,context,implicit"`
	UncertaintySemiMajor Uncertainty          `asn1:"tag:2,context,implicit"`
	UncertaintySemiMinor Uncertainty          `asn1:"tag:3,context,implicit"`
	OrientationMajorAxis OrientationMajorAxis `asn1:"tag:4,context,implicit"`
	Confidence           *Confidence          `asn1:"tag:5,context,implicit,optional" json:"Confidence,omitempty"`
	ExtCount_            int64                `asn1:"-" json:"-"`
	ExtPresent_          []bool               `asn1:"-" json:"-"`
	ExtData_             [][]byte             `asn1:"-" json:"-"`
}

// Relative3DLocationWithUncertaintyEllipsoid represents the ASN.1 type Relative3DLocationWithUncertaintyEllipsoid (SEQUENCE).
type Relative3DLocationWithUncertaintyEllipsoid struct {
	XCoordinates         RangeXYCoordinates   `asn1:"tag:0,context,implicit"`
	YCoordinates         RangeXYCoordinates   `asn1:"tag:1,context,implicit"`
	ZCoordinates         RangeZCoordinates    `asn1:"tag:2,context,implicit"`
	UncertaintySemiMajor Uncertainty          `asn1:"tag:3,context,implicit"`
	UncertaintySemiMinor Uncertainty          `asn1:"tag:4,context,implicit"`
	OrientationMajorAxis OrientationMajorAxis `asn1:"tag:5,context,implicit"`
	UncertaintyAltitude  Uncertainty          `asn1:"tag:6,context,implicit"`
	Confidence           *Confidence          `asn1:"tag:7,context,implicit,optional" json:"Confidence,omitempty"`
	ExtCount_            int64                `asn1:"-" json:"-"`
	ExtPresent_          []bool               `asn1:"-" json:"-"`
	ExtData_             [][]byte             `asn1:"-" json:"-"`
}

// RangeXYCoordinates represents the ASN.1 type RangeXYCoordinates (INTEGER).
type RangeXYCoordinates = int64

// RangeZCoordinates represents the ASN.1 type RangeZCoordinates (INTEGER).
type RangeZCoordinates = int64

// Uncertainty represents the ASN.1 type Uncertainty (INTEGER).
type Uncertainty = int64

// OrientationMajorAxis represents the ASN.1 type OrientationMajorAxis (INTEGER).
type OrientationMajorAxis = int64

// Confidence represents the ASN.1 type Confidence (INTEGER).
type Confidence = int64

// RangeDirection represents the ASN.1 type RangeDirection (SEQUENCE).
type RangeDirection struct {
	Range       *Range     `asn1:"tag:0,context,implicit,optional" json:"Range,omitempty"`
	Azimuth     *Azimuth   `asn1:"tag:1,context,implicit,optional" json:"Azimuth,omitempty"`
	Elevation   *Elevation `asn1:"tag:2,context,implicit,optional" json:"Elevation,omitempty"`
	ExtCount_   int64      `asn1:"-" json:"-"`
	ExtPresent_ []bool     `asn1:"-" json:"-"`
	ExtData_    [][]byte   `asn1:"-" json:"-"`
}

// Range represents the ASN.1 type Range (SEQUENCE).
type Range struct {
	RangeResult RangeResult `asn1:"tag:0,context,implicit"`
	Uncertainty Uncertainty `asn1:"tag:1,context,implicit"`
	Confidence  *Confidence `asn1:"tag:2,context,implicit,optional" json:"Confidence,omitempty"`
	ExtCount_   int64       `asn1:"-" json:"-"`
	ExtPresent_ []bool      `asn1:"-" json:"-"`
	ExtData_    [][]byte    `asn1:"-" json:"-"`
}

// Azimuth represents the ASN.1 type Azimuth (SEQUENCE).
type Azimuth struct {
	AzimuthResult AzimuthResult `asn1:"tag:0,context,implicit"`
	Uncertainty   Uncertainty   `asn1:"tag:1,context,implicit"`
	Confidence    *Confidence   `asn1:"tag:2,context,implicit,optional" json:"Confidence,omitempty"`
	ExtCount_     int64         `asn1:"-" json:"-"`
	ExtPresent_   []bool        `asn1:"-" json:"-"`
	ExtData_      [][]byte      `asn1:"-" json:"-"`
}

// Elevation represents the ASN.1 type Elevation (SEQUENCE).
type Elevation struct {
	ElevationResult ElevationResult `asn1:"tag:0,context,implicit"`
	Uncertainty     Uncertainty     `asn1:"tag:1,context,implicit"`
	Confidence      *Confidence     `asn1:"tag:2,context,implicit,optional" json:"Confidence,omitempty"`
	ExtCount_       int64           `asn1:"-" json:"-"`
	ExtPresent_     []bool          `asn1:"-" json:"-"`
	ExtData_        [][]byte        `asn1:"-" json:"-"`
}

// RangeResult represents the ASN.1 type RangeResult (INTEGER).
type RangeResult = int64

// AzimuthResult represents the ASN.1 type AzimuthResult (INTEGER).
type AzimuthResult = int64

// ElevationResult represents the ASN.1 type ElevationResult (INTEGER).
type ElevationResult = int64

// LCSAreaEventReportArg represents the ASN.1 type LCSAreaEventReportArg (SEQUENCE).
type LCSAreaEventReportArg struct {
	ReferenceNumber LCSReferenceNumber `asn1:"tag:0,context,implicit"`
	HGmlcAddress    GSNAddress         `asn1:"tag:1,context,implicit"`
	ExtCount_       int64              `asn1:"-" json:"-"`
	ExtPresent_     []bool             `asn1:"-" json:"-"`
	ExtData_        [][]byte           `asn1:"-" json:"-"`
}

// LCSAreaEventCancellationArg represents the ASN.1 type LCSAreaEventCancellationArg (SEQUENCE).
type LCSAreaEventCancellationArg struct {
	ReferenceNumber LCSReferenceNumber `asn1:"tag:0,context,implicit"`
	HGmlcAddress    GSNAddress         `asn1:"tag:1,context,implicit"`
	ExtCount_       int64              `asn1:"-" json:"-"`
	ExtPresent_     []bool             `asn1:"-" json:"-"`
	ExtData_        [][]byte           `asn1:"-" json:"-"`
}

// LCSPeriodicLocationRequestArg represents the ASN.1 type LCSPeriodicLocationRequestArg (SEQUENCE).
type LCSPeriodicLocationRequestArg struct {
	ReferenceNumber     LCSReferenceNumber  `asn1:"tag:0,context,implicit"`
	PeriodicLDRInfo     PeriodicLDRInfo     `asn1:"tag:1,context,implicit"`
	LcsClientExternalID LCSClientExternalID `asn1:"tag:2,context,implicit"`
	QoS                 *LCSQoS             `asn1:"tag:3,context,implicit,optional" json:"QoS,omitempty"`
	HGmlcAddress        *GSNAddress         `asn1:"tag:4,context,implicit,optional" json:"HGmlcAddress,omitempty"`
	MoLrShortCircuit    *struct{}           `asn1:"tag:5,context,implicit,optional" json:"MoLrShortCircuit,omitempty"`
	ReportingPLMNList   *ReportingPLMNList  `asn1:"tag:6,context,implicit,optional" json:"ReportingPLMNList,omitempty"`
	ExtCount_           int64               `asn1:"-" json:"-"`
	ExtPresent_         []bool              `asn1:"-" json:"-"`
	ExtData_            [][]byte            `asn1:"-" json:"-"`
}

// LCSPeriodicLocationRequestRes represents the ASN.1 type LCSPeriodicLocationRequestRes (SEQUENCE).
type LCSPeriodicLocationRequestRes struct {
	MoLrShortCircuit *struct{} `asn1:"tag:0,context,implicit,optional" json:"MoLrShortCircuit,omitempty"`
	ExtCount_        int64     `asn1:"-" json:"-"`
	ExtPresent_      []bool    `asn1:"-" json:"-"`
	ExtData_         [][]byte  `asn1:"-" json:"-"`
}

// LCSLocationUpdateArg represents the ASN.1 type LCSLocationUpdateArg (SEQUENCE).
type LCSLocationUpdateArg struct {
	ReferenceNumber     *LCSReferenceNumber         `asn1:"tag:0,context,implicit,optional" json:"ReferenceNumber,omitempty"`
	AddLocationEstimate *AddGeographicalInformation `asn1:"tag:1,context,implicit,optional" json:"AddLocationEstimate,omitempty"`
	VelocityEstimate    *VelocityEstimate           `asn1:"tag:2,context,implicit,optional" json:"VelocityEstimate,omitempty"`
	SequenceNumber      *SequenceNumber             `asn1:"tag:3,context,implicit,optional" json:"SequenceNumber,omitempty"`
	ExtCount_           int64                       `asn1:"-" json:"-"`
	ExtPresent_         []bool                      `asn1:"-" json:"-"`
	ExtData_            [][]byte                    `asn1:"-" json:"-"`
}

// LCSLocationUpdateRes represents the ASN.1 type LCSLocationUpdateRes (SEQUENCE).
type LCSLocationUpdateRes struct {
	TerminationCause *DataTypesTerminationCause `asn1:"tag:0,context,implicit,optional" json:"TerminationCause,omitempty"`
	ExtCount_        int64                      `asn1:"-" json:"-"`
	ExtPresent_      []bool                     `asn1:"-" json:"-"`
	ExtData_         [][]byte                   `asn1:"-" json:"-"`
}

// LCSPeriodicLocationCancellationArg represents the ASN.1 type LCSPeriodicLocationCancellationArg (SEQUENCE).
type LCSPeriodicLocationCancellationArg struct {
	ReferenceNumber LCSReferenceNumber `asn1:"tag:0,context,implicit"`
	HGmlcAddress    *GSNAddress        `asn1:"tag:1,context,implicit,optional" json:"HGmlcAddress,omitempty"`
	ExtCount_       int64              `asn1:"-" json:"-"`
	ExtPresent_     []bool             `asn1:"-" json:"-"`
	ExtData_        [][]byte           `asn1:"-" json:"-"`
}

// LCSPeriodicTriggeredInvokeArg represents the ASN.1 type LCSPeriodicTriggeredInvokeArg (SEQUENCE).
type LCSPeriodicTriggeredInvokeArg struct {
	ReferenceNumber                       LCSReferenceNumber               `asn1:"tag:0,context,implicit"`
	HGmlcAddress                          GSNAddress                       `asn1:"tag:1,context,implicit"`
	QoS                                   *LCSQoS                          `asn1:"tag:2,context,implicit,optional" json:"QoS,omitempty"`
	ReportingPLMNList                     *ReportingPLMNList               `asn1:"tag:3,context,implicit,optional" json:"ReportingPLMNList,omitempty"`
	PeriodicLocation                      *PeriodicLocation                `asn1:"tag:4,context,implicit,optional" json:"PeriodicLocation,omitempty"`
	AreaEventReporting                    *AreaEventReporting              `asn1:"tag:5,context,implicit,optional" json:"AreaEventReporting,omitempty"`
	MotionEventReporting                  *MotionEventReporting            `asn1:"tag:6,context,implicit,optional" json:"MotionEventReporting,omitempty"`
	ReferenceNumberExt                    *LCSReferenceNumberExt           `asn1:"tag:7,context,implicit,optional" json:"ReferenceNumberExt,omitempty"`
	HGmlcCallBackUri                      *string                          `asn1:"tag:8,context,implicit,optional" json:"HGmlcCallBackUri,omitempty"`
	SupportedGADShapes                    *SupportedGADShapes              `asn1:"tag:9,context,implicit,optional" json:"SupportedGADShapes,omitempty"`
	DeferredRoutingIdentifier             []byte                           `asn1:"tag:10,context,implicit,optional" json:"DeferredRoutingIdentifier,omitempty"`
	ReportingAccessTypes                  *ReportingAccessTypes            `asn1:"tag:11,context,implicit,optional" json:"ReportingAccessTypes,omitempty"`
	MultiplePositioningProtocolPDUs       MultiplePositioningProtocolPDUs  `asn1:"tag:12,context,implicit,optional" json:"MultiplePositioningProtocolPDUs,omitempty"`
	MultiplePositioningProtocolPDUsIndef_ bool                             `asn1:"-" json:"-"`
	ControlPlaneCIoT5GSOptimisation       *ControlPlaneCIoT5GSOptimisation `asn1:"tag:13,context,implicit,optional" json:"ControlPlaneCIoT5GSOptimisation,omitempty"`
	ScheduledLocTime                      *DateTime                        `asn1:"tag:14,context,implicit" json:"ScheduledLocTime,omitempty"`
	EventReportAllowedArea                DataTypesAreaList                `asn1:"tag:15,context,implicit,optional" json:"EventReportAllowedArea,omitempty"`
	EventReportAllowedAreaIndef_          bool                             `asn1:"-" json:"-"`
	ReportingInd                          *ReportingInd                    `asn1:"tag:16,context,implicit,optional" json:"ReportingInd,omitempty"`
	MappedQoS                             *LCSQoS                          `asn1:"tag:17,context,implicit,optional" json:"MappedQoS,omitempty"`
	UserPlaneReportAFAddr                 *LCSUserPlaneReportAFAddr        `asn1:"tag:18,context,implicit,optional" json:"UserPlaneReportAFAddr,omitempty"`
	CumulativeReportCriteria              *LCSCumulativeReportCriteria     `asn1:"tag:19,context,implicit,optional" json:"CumulativeReportCriteria,omitempty"`
	ExtCount_                             int64                            `asn1:"-" json:"-"`
	ExtPresent_                           []bool                           `asn1:"-" json:"-"`
	ExtData_                              [][]byte                         `asn1:"-" json:"-"`
}

// PeriodicLocation represents the ASN.1 type PeriodicLocation (SEQUENCE).
type PeriodicLocation struct {
	PeriodicLDRInfo PeriodicLDRInfo `asn1:"tag:0,context,implicit"`
	ExtCount_       int64           `asn1:"-" json:"-"`
	ExtPresent_     []bool          `asn1:"-" json:"-"`
	ExtData_        [][]byte        `asn1:"-" json:"-"`
}

// AreaEventReporting represents the ASN.1 type AreaEventReporting (SEQUENCE).
type AreaEventReporting struct {
	DeferredLocationEventType DeferredLocationEventType `asn1:"tag:0,context,implicit"`
	AreaList                  DataTypesAreaList         `asn1:"tag:1,context,implicit"`
	AreaListIndef_            bool                      `asn1:"-" json:"-"`
	OccurrenceInfo            *DataTypesOccurrenceInfo  `asn1:"tag:2,context,implicit,optional" json:"OccurrenceInfo,omitempty"`
	IntervalTime              *IntervalTime             `asn1:"tag:3,context,implicit,optional" json:"IntervalTime,omitempty"`
	MaximumInterval           *MaximumInterval          `asn1:"tag:4,context,implicit,optional" json:"MaximumInterval,omitempty"`
	SamplingInterval          *SamplingInterval         `asn1:"tag:5,context,implicit,optional" json:"SamplingInterval,omitempty"`
	Duration                  *Duration                 `asn1:"tag:6,context,implicit,optional" json:"Duration,omitempty"`
	LocationInfo              *DataTypesLocationInfo    `asn1:"tag:7,context,implicit,optional" json:"LocationInfo,omitempty"`
	ExtCount_                 int64                     `asn1:"-" json:"-"`
	ExtPresent_               []bool                    `asn1:"-" json:"-"`
	ExtData_                  [][]byte                  `asn1:"-" json:"-"`
}

// DataTypesAreaList represents the ASN.1 type DataTypesAreaList (SEQUENCE_OF).
type DataTypesAreaList = []DataTypesArea

// DataTypesArea represents the ASN.1 type DataTypesArea (SEQUENCE).
type DataTypesArea struct {
	AreaType              DataTypesAreaType           `asn1:"tag:0,context,implicit"`
	AreaIdentification    DataTypesAreaIdentification `asn1:"tag:1,context,implicit"`
	AreaIdentificationExt *AreaIdentificationExt      `asn1:"tag:2,context,implicit" json:"AreaIdentificationExt,omitempty"`
	ExtCount_             int64                       `asn1:"-" json:"-"`
	ExtPresent_           []bool                      `asn1:"-" json:"-"`
	ExtData_              [][]byte                    `asn1:"-" json:"-"`
}

// DataTypesAreaType represents the ASN.1 ENUMERATED type DataTypesAreaType.
type DataTypesAreaType int64

const (
	DataTypesAreaTypeTrackingArea    DataTypesAreaType = 0
	DataTypesAreaTypeEcgi            DataTypesAreaType = 1
	DataTypesAreaTypeTrackingArea5GS DataTypesAreaType = 2
	DataTypesAreaTypeNcgi            DataTypesAreaType = 3
)

func (v DataTypesAreaType) String() string {
	switch v {
	case DataTypesAreaTypeTrackingArea:
		return "trackingArea"
	case DataTypesAreaTypeEcgi:
		return "ecgi"
	case DataTypesAreaTypeTrackingArea5GS:
		return "trackingArea5GS"
	case DataTypesAreaTypeNcgi:
		return "ncgi"
	default:
		return "unknown"
	}
}

// DataTypesAreaIdentification represents the ASN.1 type DataTypesAreaIdentification (OCTET_STRING).
type DataTypesAreaIdentification = []byte

// AreaIdentificationExt represents the ASN.1 type AreaIdentificationExt (OCTET_STRING).
type AreaIdentificationExt = []byte

// DataTypesOccurrenceInfo represents the ASN.1 ENUMERATED type DataTypesOccurrenceInfo.
type DataTypesOccurrenceInfo int64

const (
	DataTypesOccurrenceInfoOneTimeEvent      DataTypesOccurrenceInfo = 0
	DataTypesOccurrenceInfoMultipleTimeEvent DataTypesOccurrenceInfo = 1
)

func (v DataTypesOccurrenceInfo) String() string {
	switch v {
	case DataTypesOccurrenceInfoOneTimeEvent:
		return "oneTimeEvent"
	case DataTypesOccurrenceInfoMultipleTimeEvent:
		return "multipleTimeEvent"
	default:
		return "unknown"
	}
}

// MaximumInterval represents the ASN.1 type MaximumInterval (INTEGER).
type MaximumInterval = int64

// SamplingInterval represents the ASN.1 type SamplingInterval (INTEGER).
type SamplingInterval = int64

// Duration represents the ASN.1 type Duration (INTEGER).
type Duration = int64

// DataTypesLocationInfo represents the ASN.1 type DataTypesLocationInfo (BIT_STRING).
type DataTypesLocationInfo = runtime.BitString

// MotionEventReporting represents the ASN.1 type MotionEventReporting (SEQUENCE).
type MotionEventReporting struct {
	LinearDistance   LinearDistance           `asn1:"tag:0,context,implicit"`
	OccurrenceInfo   *DataTypesOccurrenceInfo `asn1:"tag:1,context,implicit,optional" json:"OccurrenceInfo,omitempty"`
	IntervalTime     *IntervalTime            `asn1:"tag:2,context,implicit,optional" json:"IntervalTime,omitempty"`
	MaximumInterval  *MaximumInterval         `asn1:"tag:3,context,implicit,optional" json:"MaximumInterval,omitempty"`
	SamplingInterval *SamplingInterval        `asn1:"tag:4,context,implicit,optional" json:"SamplingInterval,omitempty"`
	Duration         *Duration                `asn1:"tag:5,context,implicit,optional" json:"Duration,omitempty"`
	LocationInfo     *DataTypesLocationInfo   `asn1:"tag:6,context,implicit,optional" json:"LocationInfo,omitempty"`
	ExtCount_        int64                    `asn1:"-" json:"-"`
	ExtPresent_      []bool                   `asn1:"-" json:"-"`
	ExtData_         [][]byte                 `asn1:"-" json:"-"`
}

// LinearDistance represents the ASN.1 type LinearDistance (INTEGER).
type LinearDistance = int64

// LCSReferenceNumberExt represents the ASN.1 type LCSReferenceNumberExt (OCTET_STRING).
type LCSReferenceNumberExt = []byte

// ReportingAccessTypes represents the ASN.1 type ReportingAccessTypes (BIT_STRING).
type ReportingAccessTypes = runtime.BitString

// ReportingInd represents the ASN.1 ENUMERATED type ReportingInd.
type ReportingInd int64

const (
	ReportingIndInsideReporting  ReportingInd = 0
	ReportingIndOutsideReporting ReportingInd = 1
)

func (v ReportingInd) String() string {
	switch v {
	case ReportingIndInsideReporting:
		return "insideReporting"
	case ReportingIndOutsideReporting:
		return "outsideReporting"
	default:
		return "unknown"
	}
}

// LCSPeriodicTriggeredInvokeRes represents the ASN.1 type LCSPeriodicTriggeredInvokeRes (SEQUENCE).
type LCSPeriodicTriggeredInvokeRes struct {
	ExtCount_   int64    `asn1:"-" json:"-"`
	ExtPresent_ []bool   `asn1:"-" json:"-"`
	ExtData_    [][]byte `asn1:"-" json:"-"`
}

// LCSEventReportArg represents the ASN.1 type LCSEventReportArg (SEQUENCE).
type LCSEventReportArg struct {
	EventType                             EventType                       `asn1:"tag:0,context,implicit"`
	ReferenceNumberExt                    LCSReferenceNumberExt           `asn1:"tag:1,context,implicit"`
	HGmlcCallBackUri                      string                          `asn1:"tag:2,context,implicit"`
	LocationInfo                          *DataTypesLocationInfo          `asn1:"tag:3,context,implicit,optional" json:"LocationInfo,omitempty"`
	SupportedGADShapes                    *SupportedGADShapes             `asn1:"tag:4,context,implicit,optional" json:"SupportedGADShapes,omitempty"`
	LcsQoS                                *LCSQoS                         `asn1:"tag:5,context,implicit,optional" json:"LcsQoS,omitempty"`
	MultiplePositioningProtocolPDUs       MultiplePositioningProtocolPDUs `asn1:"tag:6,context,implicit,optional" json:"MultiplePositioningProtocolPDUs,omitempty"`
	MultiplePositioningProtocolPDUsIndef_ bool                            `asn1:"-" json:"-"`
	TerminationCause                      *DataTypesTerminationCause      `asn1:"tag:7,context,implicit,optional" json:"TerminationCause,omitempty"`
	UserPlaneEventReportStat              *LCSUserPlaneEventReportStat    `asn1:"tag:8,context,implicit,optional" json:"UserPlaneEventReportStat,omitempty"`
	ExtCount_                             int64                           `asn1:"-" json:"-"`
	ExtPresent_                           []bool                          `asn1:"-" json:"-"`
	ExtData_                              [][]byte                        `asn1:"-" json:"-"`
}

// EventType represents the ASN.1 ENUMERATED type EventType.
type EventType int64

const (
	EventTypePeriodicEvent                  EventType = 0
	EventTypeEnteringAreaEvent              EventType = 1
	EventTypeLeavingAreaEvent               EventType = 2
	EventTypeBeingInsideAreaEvent           EventType = 3
	EventTypeMotionEvent                    EventType = 4
	EventTypeMaximumIntervalExpirationEvent EventType = 5
	EventTypeLocationCancellationEvent      EventType = 6
	EventTypeCumulativeEventReport          EventType = 7
)

func (v EventType) String() string {
	switch v {
	case EventTypePeriodicEvent:
		return "periodicEvent"
	case EventTypeEnteringAreaEvent:
		return "enteringAreaEvent"
	case EventTypeLeavingAreaEvent:
		return "leavingAreaEvent"
	case EventTypeBeingInsideAreaEvent:
		return "beingInsideAreaEvent"
	case EventTypeMotionEvent:
		return "motionEvent"
	case EventTypeMaximumIntervalExpirationEvent:
		return "maximumIntervalExpirationEvent"
	case EventTypeLocationCancellationEvent:
		return "locationCancellationEvent"
	case EventTypeCumulativeEventReport:
		return "cumulativeEventReport"
	default:
		return "unknown"
	}
}

// ControlPlaneCIoT5GSOptimisation represents the ASN.1 type ControlPlaneCIoT5GSOptimisation (SEQUENCE).
type ControlPlaneCIoT5GSOptimisation struct {
	MaximumDuration                *MaximumDuration                `asn1:"tag:0,context,implicit,optional" json:"MaximumDuration,omitempty"`
	MaximumConsecutiveEventReports *MaximumConsecutiveEventReports `asn1:"tag:1,context,implicit,optional" json:"MaximumConsecutiveEventReports,omitempty"`
	ExtCount_                      int64                           `asn1:"-" json:"-"`
	ExtPresent_                    []bool                          `asn1:"-" json:"-"`
	ExtData_                       [][]byte                        `asn1:"-" json:"-"`
}

// MaximumDuration represents the ASN.1 type MaximumDuration (INTEGER).
type MaximumDuration = int64

// MaximumConsecutiveEventReports represents the ASN.1 type MaximumConsecutiveEventReports (INTEGER).
type MaximumConsecutiveEventReports = int64

// LCSUserPlaneEventReportStat represents the ASN.1 type LCSUserPlaneEventReportStat (INTEGER).
type LCSUserPlaneEventReportStat = int64

// LCSUserPlaneReportAFAddr represents the ASN.1 type LCSUserPlaneReportAFAddr (SEQUENCE).
type LCSUserPlaneReportAFAddr struct {
	AfIpv4Addrs       Ipv4Addrs      `asn1:"tag:0,context,implicit,optional" json:"AfIpv4Addrs,omitempty"`
	AfIpv4AddrsIndef_ bool           `asn1:"-" json:"-"`
	AfIpv6Addrs       Ipv6Addrs      `asn1:"tag:1,context,implicit,optional" json:"AfIpv6Addrs,omitempty"`
	AfIpv6AddrsIndef_ bool           `asn1:"-" json:"-"`
	AfFqdn            *DataTypesFQDN `asn1:"tag:2,context,implicit,optional" json:"AfFqdn,omitempty"`
}

// Ipv4Addrs represents the ASN.1 type Ipv4Addrs (SEQUENCE_OF).
type Ipv4Addrs = []Ipv4Addr

// Ipv6Addrs represents the ASN.1 type Ipv6Addrs (SEQUENCE_OF).
type Ipv6Addrs = []Ipv6Addr

// Ipv4Addr represents the ASN.1 type Ipv4Addr (OCTET_STRING).
type Ipv4Addr = []byte

// Ipv6Addr represents the ASN.1 type Ipv6Addr (OCTET_STRING).
type Ipv6Addr = []byte

// LCSCumulativeReportCriteria represents the ASN.1 type LCSCumulativeReportCriteria (SEQUENCE).
type LCSCumulativeReportCriteria struct {
	TimerCriteria   *LCSCumulativeReportTimerCriteria   `asn1:"tag:0,context,implicit,optional" json:"TimerCriteria,omitempty"`
	CounterCriteria *LCSCumulativeReportCounterCriteria `asn1:"tag:1,context,implicit,optional" json:"CounterCriteria,omitempty"`
}

// LCSCumulativeReportTimerCriteria represents the ASN.1 type LCSCumulativeReportTimerCriteria (INTEGER).
type LCSCumulativeReportTimerCriteria = int64

// LCSCumulativeReportCounterCriteria represents the ASN.1 type LCSCumulativeReportCounterCriteria (INTEGER).
type LCSCumulativeReportCounterCriteria = int64

// DataTypesFQDN represents the ASN.1 type DataTypesFQDN (OCTET_STRING).
type DataTypesFQDN = []byte

// LCSEventReportRes represents the ASN.1 type LCSEventReportRes (SEQUENCE).
type LCSEventReportRes struct {
	DeferredRoutingIdentifier []byte                     `asn1:"tag:0,context,implicit,optional" json:"DeferredRoutingIdentifier,omitempty"`
	TerminationCause          *DataTypesTerminationCause `asn1:"tag:1,context,implicit,optional" json:"TerminationCause,omitempty"`
	ExtCount_                 int64                      `asn1:"-" json:"-"`
	ExtPresent_               []bool                     `asn1:"-" json:"-"`
	ExtData_                  [][]byte                   `asn1:"-" json:"-"`
}

// LCSCancelDeferredLocationArg represents the ASN.1 type LCSCancelDeferredLocationArg (SEQUENCE).
type LCSCancelDeferredLocationArg struct {
	ReferenceNumberExt LCSReferenceNumberExt `asn1:"tag:0,context,implicit"`
	HGmlcCallBackUri   string                `asn1:"tag:2,context,implicit"`
	ExtCount_          int64                 `asn1:"-" json:"-"`
	ExtPresent_        []bool                `asn1:"-" json:"-"`
	ExtData_           [][]byte              `asn1:"-" json:"-"`
}

// LCSLocationPrivacySettingArg represents the ASN.1 type LCSLocationPrivacySettingArg (SEQUENCE).
type LCSLocationPrivacySettingArg struct {
	LocationPrivacyIndication LCSLocationPrivacyIndication `asn1:"tag:0,context,implicit"`
	ValidTimePeriod           *LCSValidTimePeriod          `asn1:"tag:1,context,implicit,optional" json:"ValidTimePeriod,omitempty"`
	EventReportExpectedArea   *ExtGeographicalInformation  `asn1:"tag:2,context,implicit,optional" json:"EventReportExpectedArea,omitempty"`
	AreaUsageInd              *ReportingInd                `asn1:"tag:3,context,implicit,optional" json:"AreaUsageInd,omitempty"`
	ExtCount_                 int64                        `asn1:"-" json:"-"`
	ExtPresent_               []bool                       `asn1:"-" json:"-"`
	ExtData_                  [][]byte                     `asn1:"-" json:"-"`
}

// LCSLocationPrivacyIndication represents the ASN.1 ENUMERATED type LCSLocationPrivacyIndication.
type LCSLocationPrivacyIndication int64

const (
	LCSLocationPrivacyIndicationLocationDisallowed LCSLocationPrivacyIndication = 0
	LCSLocationPrivacyIndicationLocationAllowed    LCSLocationPrivacyIndication = 1
	LCSLocationPrivacyIndicationRangingDisallowed  LCSLocationPrivacyIndication = 2
	LCSLocationPrivacyIndicationRangingAllowed     LCSLocationPrivacyIndication = 3
)

func (v LCSLocationPrivacyIndication) String() string {
	switch v {
	case LCSLocationPrivacyIndicationLocationDisallowed:
		return "locationDisallowed"
	case LCSLocationPrivacyIndicationLocationAllowed:
		return "locationAllowed"
	case LCSLocationPrivacyIndicationRangingDisallowed:
		return "rangingDisallowed"
	case LCSLocationPrivacyIndicationRangingAllowed:
		return "rangingAllowed"
	default:
		return "unknown"
	}
}

// LCSValidTimePeriod represents the ASN.1 type LCSValidTimePeriod (SEQUENCE).
type LCSValidTimePeriod struct {
	StartTime   *DateTime `asn1:"tag:0,context,implicit,optional" json:"StartTime,omitempty"`
	EndTime     *DateTime `asn1:"tag:1,context,implicit,optional" json:"EndTime,omitempty"`
	ExtCount_   int64     `asn1:"-" json:"-"`
	ExtPresent_ []bool    `asn1:"-" json:"-"`
	ExtData_    [][]byte  `asn1:"-" json:"-"`
}

// DateTime represents the ASN.1 type DateTime (OCTET_STRING).
type DateTime = []byte

// LCSPruAssociationArg represents the ASN.1 type LCSPruAssociationArg (SEQUENCE).
type LCSPruAssociationArg struct {
	AssociationType         LCSAssociationType          `asn1:"tag:0,context,implicit"`
	PositioningCapabilities []byte                      `asn1:"tag:1,context,implicit"`
	LocationOfPru           *ExtGeographicalInformation `asn1:"tag:2,context,implicit,optional" json:"LocationOfPru,omitempty"`
	StateOfPru              *LCSStateOfPru              `asn1:"tag:3,context,implicit,optional" json:"StateOfPru,omitempty"`
	ExtCount_               int64                       `asn1:"-" json:"-"`
	ExtPresent_             []bool                      `asn1:"-" json:"-"`
	ExtData_                [][]byte                    `asn1:"-" json:"-"`
}

// LCSAssociationType represents the ASN.1 ENUMERATED type LCSAssociationType.
type LCSAssociationType int64

const (
	LCSAssociationTypeInitialAssociation LCSAssociationType = 0
	LCSAssociationTypeAssociationUpdate  LCSAssociationType = 1
)

func (v LCSAssociationType) String() string {
	switch v {
	case LCSAssociationTypeInitialAssociation:
		return "initialAssociation"
	case LCSAssociationTypeAssociationUpdate:
		return "associationUpdate"
	default:
		return "unknown"
	}
}

// LCSStateOfPru represents the ASN.1 ENUMERATED type LCSStateOfPru.
type LCSStateOfPru int64

const (
	LCSStateOfPruOn  LCSStateOfPru = 0
	LCSStateOfPruOff LCSStateOfPru = 1
)

func (v LCSStateOfPru) String() string {
	switch v {
	case LCSStateOfPruOn:
		return "on"
	case LCSStateOfPruOff:
		return "off"
	default:
		return "unknown"
	}
}

// LCSPruAssociationRes represents the ASN.1 type LCSPruAssociationRes (SEQUENCE).
type LCSPruAssociationRes struct {
	PeriodicUpdateTimer *LCSPeriodicUpdateTimer `asn1:"tag:0,context,implicit,optional" json:"PeriodicUpdateTimer,omitempty"`
	UpdateTrigger       *LCSPruUpdateTrigger    `asn1:"tag:1,context,implicit,optional" json:"UpdateTrigger,omitempty"`
	ExtCount_           int64                   `asn1:"-" json:"-"`
	ExtPresent_         []bool                  `asn1:"-" json:"-"`
	ExtData_            [][]byte                `asn1:"-" json:"-"`
}

// LCSPeriodicUpdateTimer represents the ASN.1 type LCSPeriodicUpdateTimer (INTEGER).
type LCSPeriodicUpdateTimer = int64

// LCSPruUpdateTrigger represents the ASN.1 type LCSPruUpdateTrigger (BIT_STRING).
type LCSPruUpdateTrigger = runtime.BitString

// LCSPruDisassociationArg represents the ASN.1 type LCSPruDisassociationArg (SEQUENCE).
type LCSPruDisassociationArg struct {
	AckIndication     *bool    `asn1:"tag:0,context,implicit,optional" json:"AckIndication,omitempty"`
	AckIndicationRaw_ byte     `asn1:"-" json:"-"`
	NewLmfRoutingId   []byte   `asn1:"tag:1,context,implicit,optional" json:"NewLmfRoutingId,omitempty"`
	ExtCount_         int64    `asn1:"-" json:"-"`
	ExtPresent_       []bool   `asn1:"-" json:"-"`
	ExtData_          [][]byte `asn1:"-" json:"-"`
}

// SLMTLRType represents the ASN.1 ENUMERATED type SLMTLRType.
type SLMTLRType int64

const (
	SLMTLRTypeRangingSidelink SLMTLRType = 0
)

func (v SLMTLRType) String() string {
	switch v {
	case SLMTLRTypeRangingSidelink:
		return "rangingSidelink"
	default:
		return "unknown"
	}
}

// LCSSLMTLRArg represents the ASN.1 type LCSSLMTLRArg (SEQUENCE).
type LCSSLMTLRArg struct {
	SlmtlrType          SLMTLRType          `asn1:"tag:0,context,implicit"`
	SupportedGADShapes  *SupportedGADShapes `asn1:"tag:1,context,implicit,optional" json:"SupportedGADShapes,omitempty"`
	RelatedUEInfo       RelatedUEInfo       `asn1:"tag:2,context,implicit,optional" json:"RelatedUEInfo,omitempty"`
	RelatedUEInfoIndef_ bool                `asn1:"-" json:"-"`
	LocatedUEselect     *LocatedUEselect    `asn1:"tag:3,context,implicit,optional" json:"LocatedUEselect,omitempty"`
	CoordinateID        *CoordinateID       `asn1:"tag:4,context,implicit,optional" json:"CoordinateID,omitempty"`
	ExtCount_           int64               `asn1:"-" json:"-"`
	ExtPresent_         []bool              `asn1:"-" json:"-"`
	ExtData_            [][]byte            `asn1:"-" json:"-"`
}

// LocatedUEselect represents the ASN.1 ENUMERATED type LocatedUEselect.
type LocatedUEselect int64

const (
	LocatedUEselectTargetUESelect LocatedUEselect = 0
	LocatedUEselectLmfselect      LocatedUEselect = 1
)

func (v LocatedUEselect) String() string {
	switch v {
	case LocatedUEselectTargetUESelect:
		return "targetUESelect"
	case LocatedUEselectLmfselect:
		return "lmfselect"
	default:
		return "unknown"
	}
}

// CoordinateID represents the ASN.1 type CoordinateID (INTEGER).
type CoordinateID = int64

// LCSSLMTLRRes represents the ASN.1 type LCSSLMTLRRes (SEQUENCE).
type LCSSLMTLRRes struct {
	RelatedUEInfo         RelatedUEInfo   `asn1:"tag:0,context,implicit"`
	RelatedUEInfoIndef_   bool            `asn1:"-" json:"-"`
	RangingSLPPList       RangingSLPPList `asn1:"tag:1,context,implicit,optional" json:"RangingSLPPList,omitempty"`
	RangingSLPPListIndef_ bool            `asn1:"-" json:"-"`
	ExtCount_             int64           `asn1:"-" json:"-"`
	ExtPresent_           []bool          `asn1:"-" json:"-"`
	ExtData_              [][]byte        `asn1:"-" json:"-"`
}

// RangingSLPPList represents the ASN.1 type RangingSLPPList (SEQUENCE_OF).
type RangingSLPPList = []RangingSLPPInfo

// RangingSLPPInfo represents the ASN.1 type RangingSLPPInfo (SEQUENCE).
type RangingSLPPInfo struct {
	SLPPMsg   SlPosProtocolPDU `asn1:"tag:0,context,implicit"`
	RelatedUE []byte           `asn1:"tag:1,context,implicit,optional" json:"RelatedUE,omitempty"`
}

// SlPosProtocolPDU represents the ASN.1 type SlPosProtocolPDU (OCTET_STRING).
type SlPosProtocolPDU = []byte

// UEBased represents the ASN.1 ENUMERATED type UEBased.
type UEBased int64

const (
	UEBasedNotcalculatedbyUE UEBased = 0
	UEBasedCalculatedbyUE    UEBased = 1
)

func (v UEBased) String() string {
	switch v {
	case UEBasedNotcalculatedbyUE:
		return "notcalculatedbyUE"
	case UEBasedCalculatedbyUE:
		return "calculatedbyUE"
	default:
		return "unknown"
	}
}

// LCSDLRSPPTransportArg represents the ASN.1 type LCSDLRSPPTransportArg (SEQUENCE).
type LCSDLRSPPTransportArg struct {
	RangingSLPPList       RangingSLPPList `asn1:"tag:0,context,implicit,optional" json:"RangingSLPPList,omitempty"`
	RangingSLPPListIndef_ bool            `asn1:"-" json:"-"`
	ScheduledLocTime      *DateTime       `asn1:"tag:1,context,implicit,optional" json:"ScheduledLocTime,omitempty"`
	UeBased               *UEBased        `asn1:"tag:2,context,implicit,optional" json:"UeBased,omitempty"`
	RelatedUEInfo         RelatedUEInfo   `asn1:"tag:3,context,implicit,optional" json:"RelatedUEInfo,omitempty"`
	RelatedUEInfoIndef_   bool            `asn1:"-" json:"-"`
	ExtCount_             int64           `asn1:"-" json:"-"`
	ExtPresent_           []bool          `asn1:"-" json:"-"`
	ExtData_              [][]byte        `asn1:"-" json:"-"`
}

// LCSDLRSPPTransportRes represents the ASN.1 type LCSDLRSPPTransportRes (SEQUENCE).
type LCSDLRSPPTransportRes struct {
}

// LCSULRSPPTransportArg represents the ASN.1 type LCSULRSPPTransportArg (SEQUENCE).
type LCSULRSPPTransportArg struct {
	RangingSLPPList       RangingSLPPList `asn1:"tag:0,context,implicit,optional" json:"RangingSLPPList,omitempty"`
	RangingSLPPListIndef_ bool            `asn1:"-" json:"-"`
	ExtCount_             int64           `asn1:"-" json:"-"`
	ExtPresent_           []bool          `asn1:"-" json:"-"`
	ExtData_              [][]byte        `asn1:"-" json:"-"`
}

// LCSULRSPPTransportRes represents the ASN.1 type LCSULRSPPTransportRes (SEQUENCE).
type LCSULRSPPTransportRes struct {
}

// MarshalBER encodes NotifySSArg to BER format.
func (v *NotifySSArg) MarshalBER() ([]byte, error) {
	var children []byte
	if v.SsCode != nil {
		enc_sscode := ber.EncodeOctetString([]byte(*v.SsCode))
		enc_sscode = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, false, enc_sscode)
		children = append(children, enc_sscode...)
	}
	if v.SsStatus != nil {
		enc_ssstatus := ber.EncodeOctetString([]byte(*v.SsStatus))
		enc_ssstatus = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, false, enc_ssstatus)
		children = append(children, enc_ssstatus...)
	}
	if v.SsNotification != nil {
		enc_ssnotification := ber.EncodeOctetString([]byte(*v.SsNotification))
		enc_ssnotification = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 5, false, enc_ssnotification)
		children = append(children, enc_ssnotification...)
	}
	if v.CallIsWaitingIndicator != nil {
		enc_calliswaitingindicator := ber.EncodeNull()
		enc_calliswaitingindicator = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 14, false, enc_calliswaitingindicator)
		children = append(children, enc_calliswaitingindicator...)
	}
	if v.CallOnHoldIndicator != nil {
		enc_callonholdindicator := ber.EncodeEnumerated(int64(*v.CallOnHoldIndicator))
		enc_callonholdindicator = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 15, false, enc_callonholdindicator)
		children = append(children, enc_callonholdindicator...)
	}
	if v.MptyIndicator != nil {
		enc_mptyindicator := ber.EncodeNull()
		enc_mptyindicator = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 16, false, enc_mptyindicator)
		children = append(children, enc_mptyindicator...)
	}
	if v.CugIndex != nil {
		enc_cugindex := ber.EncodeInteger(int64(*v.CugIndex))
		enc_cugindex = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 17, false, enc_cugindex)
		children = append(children, enc_cugindex...)
	}
	if v.ClirSuppressionRejected != nil {
		enc_clirsuppressionrejected := ber.EncodeNull()
		enc_clirsuppressionrejected = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 18, false, enc_clirsuppressionrejected)
		children = append(children, enc_clirsuppressionrejected...)
	}
	if v.EctIndicator != nil {
		enc_ectindicator, err := v.EctIndicator.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding ect-Indicator: %w", err)
		}
		enc_ectindicator = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 19, true, enc_ectindicator)
		children = append(children, enc_ectindicator...)
	}
	if v.NameIndicator != nil {
		enc_nameindicator, err := v.NameIndicator.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding nameIndicator: %w", err)
		}
		enc_nameindicator = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 20, true, enc_nameindicator)
		children = append(children, enc_nameindicator...)
	}
	if v.CcbsFeature != nil {
		enc_ccbsfeature, err := v.CcbsFeature.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding ccbs-Feature: %w", err)
		}
		enc_ccbsfeature = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 21, true, enc_ccbsfeature)
		children = append(children, enc_ccbsfeature...)
	}
	if v.AlertingPattern != nil {
		enc_alertingpattern := ber.EncodeOctetString([]byte(*v.AlertingPattern))
		enc_alertingpattern = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 22, false, enc_alertingpattern)
		children = append(children, enc_alertingpattern...)
	}
	if v.MulticallIndicator != nil {
		enc_multicallindicator := ber.EncodeEnumerated(int64(*v.MulticallIndicator))
		enc_multicallindicator = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 23, false, enc_multicallindicator)
		children = append(children, enc_multicallindicator...)
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

// MarshalDER encodes NotifySSArg to DER format.
func (v *NotifySSArg) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes NotifySSArg from BER/DER format.
func (v *NotifySSArg) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding NotifySSArg SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "NotifySSArg", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode ss-Code
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
				_, n_sscode, rawVal_sscode, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding ss-Code: %w", err)
				}
				tmp_sscode := SSCode(rawVal_sscode)
				v.SsCode = &tmp_sscode
				offset += n_sscode
			}
		}
	}
	// Decode ss-Status
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4 {
				_, n_ssstatus, rawVal_ssstatus, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding ss-Status: %w", err)
				}
				tmp_ssstatus := SSStatus(rawVal_ssstatus)
				v.SsStatus = &tmp_ssstatus
				offset += n_ssstatus
			}
		}
	}
	// Decode ss-Notification
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 5 {
				_, n_ssnotification, rawVal_ssnotification, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding ss-Notification: %w", err)
				}
				tmp_ssnotification := SSNotification(rawVal_ssnotification)
				v.SsNotification = &tmp_ssnotification
				offset += n_ssnotification
			}
		}
	}
	// Decode callIsWaiting-Indicator
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 14 {
				_, n_calliswaitingindicator, rawVal_calliswaitingindicator, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding callIsWaiting-Indicator: %w", err)
				}
				_ = rawVal_calliswaitingindicator
				v.CallIsWaitingIndicator = &struct{}{}
				offset += n_calliswaitingindicator
			}
		}
	}
	// Decode callOnHold-Indicator
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 15 {
				_, n_callonholdindicator, rawVal_callonholdindicator, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding callOnHold-Indicator: %w", err)
				}
				decVal_callonholdindicator, intErr := ber.DecodeIntegerValue(rawVal_callonholdindicator)
				if intErr != nil {
					return fmt.Errorf("decoding callOnHold-Indicator: %w", intErr)
				}
				tmp_callonholdindicator := CallOnHoldIndicator(decVal_callonholdindicator)
				v.CallOnHoldIndicator = &tmp_callonholdindicator
				offset += n_callonholdindicator
			}
		}
	}
	// Decode mpty-Indicator
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 16 {
				_, n_mptyindicator, rawVal_mptyindicator, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding mpty-Indicator: %w", err)
				}
				_ = rawVal_mptyindicator
				v.MptyIndicator = &struct{}{}
				offset += n_mptyindicator
			}
		}
	}
	// Decode cug-Index
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 17 {
				_, n_cugindex, rawVal_cugindex, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding cug-Index: %w", err)
				}
				decVal_cugindex, intErr := ber.DecodeIntegerValue(rawVal_cugindex)
				if intErr != nil {
					return fmt.Errorf("decoding cug-Index: %w", intErr)
				}
				tmp_cugindex := CUGIndex(decVal_cugindex)
				v.CugIndex = &tmp_cugindex
				offset += n_cugindex
			}
		}
	}
	// Decode clirSuppressionRejected
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 18 {
				_, n_clirsuppressionrejected, rawVal_clirsuppressionrejected, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding clirSuppressionRejected: %w", err)
				}
				_ = rawVal_clirsuppressionrejected
				v.ClirSuppressionRejected = &struct{}{}
				offset += n_clirsuppressionrejected
			}
		}
	}
	// Decode ect-Indicator
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 19 {
				_, n_ectindicator, rawVal_ectindicator, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding ect-Indicator: %w", err)
				}
				reconstructed_ectindicator := ber.EncodeSequence(rawVal_ectindicator)
				var dec_ectindicator ECTIndicator
				if unmErr := dec_ectindicator.UnmarshalBER(reconstructed_ectindicator); unmErr != nil {
					return fmt.Errorf("decoding ect-Indicator: %w", unmErr)
				}
				v.EctIndicator = &dec_ectindicator
				offset += n_ectindicator
			}
		}
	}
	// Decode nameIndicator
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 20 {
				_, n_nameindicator, rawVal_nameindicator, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding nameIndicator: %w", err)
				}
				reconstructed_nameindicator := ber.EncodeSequence(rawVal_nameindicator)
				var dec_nameindicator NameIndicator
				if unmErr := dec_nameindicator.UnmarshalBER(reconstructed_nameindicator); unmErr != nil {
					return fmt.Errorf("decoding nameIndicator: %w", unmErr)
				}
				v.NameIndicator = &dec_nameindicator
				offset += n_nameindicator
			}
		}
	}
	// Decode ccbs-Feature
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 21 {
				_, n_ccbsfeature, rawVal_ccbsfeature, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding ccbs-Feature: %w", err)
				}
				reconstructed_ccbsfeature := ber.EncodeSequence(rawVal_ccbsfeature)
				var dec_ccbsfeature CCBSFeature
				if unmErr := dec_ccbsfeature.UnmarshalBER(reconstructed_ccbsfeature); unmErr != nil {
					return fmt.Errorf("decoding ccbs-Feature: %w", unmErr)
				}
				v.CcbsFeature = &dec_ccbsfeature
				offset += n_ccbsfeature
			}
		}
	}
	// Decode alertingPattern
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 22 {
				_, n_alertingpattern, rawVal_alertingpattern, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding alertingPattern: %w", err)
				}
				tmp_alertingpattern := AlertingPattern(rawVal_alertingpattern)
				v.AlertingPattern = &tmp_alertingpattern
				offset += n_alertingpattern
			}
		}
	}
	// Decode multicall-Indicator
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 23 {
				_, n_multicallindicator, rawVal_multicallindicator, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding multicall-Indicator: %w", err)
				}
				decVal_multicallindicator, intErr := ber.DecodeIntegerValue(rawVal_multicallindicator)
				if intErr != nil {
					return fmt.Errorf("decoding multicall-Indicator: %w", intErr)
				}
				tmp_multicallindicator := MulticallIndicator(decVal_multicallindicator)
				v.MulticallIndicator = &tmp_multicallindicator
				offset += n_multicallindicator
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "NotifySSArg", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes ForwardChargeAdviceArg to BER format.
func (v *ForwardChargeAdviceArg) MarshalBER() ([]byte, error) {
	var children []byte
	enc_sscode := ber.EncodeOctetString([]byte(v.SsCode))
	enc_sscode = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, false, enc_sscode)
	children = append(children, enc_sscode...)
	enc_charginginformation, err := v.ChargingInformation.MarshalBER()
	if err != nil {
		return nil, fmt.Errorf("encoding chargingInformation: %w", err)
	}
	enc_charginginformation = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, true, enc_charginginformation)
	children = append(children, enc_charginginformation...)
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

// MarshalDER encodes ForwardChargeAdviceArg to DER format.
func (v *ForwardChargeAdviceArg) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes ForwardChargeAdviceArg from BER/DER format.
func (v *ForwardChargeAdviceArg) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding ForwardChargeAdviceArg SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "ForwardChargeAdviceArg", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode ss-Code
	if offset >= len(content) {
		return fmt.Errorf("missing required field ss-Code")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 0 {
			return fmt.Errorf("expected tag [%s %d] for ss-Code, got %s", "CONTEXT", 0, reqTag_)
		}
	}
	_, n_sscode, rawVal_sscode, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding ss-Code: %w", err)
	}
	v.SsCode = SSCode(rawVal_sscode)
	offset += n_sscode
	// Decode chargingInformation
	if offset >= len(content) {
		return fmt.Errorf("missing required field chargingInformation")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 1 {
			return fmt.Errorf("expected tag [%s %d] for chargingInformation, got %s", "CONTEXT", 1, reqTag_)
		}
	}
	_, n_charginginformation, rawVal_charginginformation, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding chargingInformation: %w", err)
	}
	reconstructed_charginginformation := ber.EncodeSequence(rawVal_charginginformation)
	if unmErr := v.ChargingInformation.UnmarshalBER(reconstructed_charginginformation); unmErr != nil {
		return fmt.Errorf("decoding chargingInformation: %w", unmErr)
	}
	offset += n_charginginformation
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "ForwardChargeAdviceArg", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes ChargingInformation to BER format.
func (v *ChargingInformation) MarshalBER() ([]byte, error) {
	var children []byte
	if v.E1 != nil {
		enc_e1 := ber.EncodeInteger(int64(*v.E1))
		enc_e1 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, false, enc_e1)
		children = append(children, enc_e1...)
	}
	if v.E2 != nil {
		enc_e2 := ber.EncodeInteger(int64(*v.E2))
		enc_e2 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, false, enc_e2)
		children = append(children, enc_e2...)
	}
	if v.E3 != nil {
		enc_e3 := ber.EncodeInteger(int64(*v.E3))
		enc_e3 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, false, enc_e3)
		children = append(children, enc_e3...)
	}
	if v.E4 != nil {
		enc_e4 := ber.EncodeInteger(int64(*v.E4))
		enc_e4 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, false, enc_e4)
		children = append(children, enc_e4...)
	}
	if v.E5 != nil {
		enc_e5 := ber.EncodeInteger(int64(*v.E5))
		enc_e5 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 5, false, enc_e5)
		children = append(children, enc_e5...)
	}
	if v.E6 != nil {
		enc_e6 := ber.EncodeInteger(int64(*v.E6))
		enc_e6 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 6, false, enc_e6)
		children = append(children, enc_e6...)
	}
	if v.E7 != nil {
		enc_e7 := ber.EncodeInteger(int64(*v.E7))
		enc_e7 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 7, false, enc_e7)
		children = append(children, enc_e7...)
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

// MarshalDER encodes ChargingInformation to DER format.
func (v *ChargingInformation) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes ChargingInformation from BER/DER format.
func (v *ChargingInformation) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding ChargingInformation SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "ChargingInformation", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode e1
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
				_, n_e1, rawVal_e1, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding e1: %w", err)
				}
				decVal_e1, intErr := ber.DecodeIntegerValue(rawVal_e1)
				if intErr != nil {
					return fmt.Errorf("decoding e1: %w", intErr)
				}
				tmp_e1 := E1(decVal_e1)
				v.E1 = &tmp_e1
				offset += n_e1
			}
		}
	}
	// Decode e2
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2 {
				_, n_e2, rawVal_e2, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding e2: %w", err)
				}
				decVal_e2, intErr := ber.DecodeIntegerValue(rawVal_e2)
				if intErr != nil {
					return fmt.Errorf("decoding e2: %w", intErr)
				}
				tmp_e2 := E2(decVal_e2)
				v.E2 = &tmp_e2
				offset += n_e2
			}
		}
	}
	// Decode e3
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3 {
				_, n_e3, rawVal_e3, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding e3: %w", err)
				}
				decVal_e3, intErr := ber.DecodeIntegerValue(rawVal_e3)
				if intErr != nil {
					return fmt.Errorf("decoding e3: %w", intErr)
				}
				tmp_e3 := E3(decVal_e3)
				v.E3 = &tmp_e3
				offset += n_e3
			}
		}
	}
	// Decode e4
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4 {
				_, n_e4, rawVal_e4, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding e4: %w", err)
				}
				decVal_e4, intErr := ber.DecodeIntegerValue(rawVal_e4)
				if intErr != nil {
					return fmt.Errorf("decoding e4: %w", intErr)
				}
				tmp_e4 := E4(decVal_e4)
				v.E4 = &tmp_e4
				offset += n_e4
			}
		}
	}
	// Decode e5
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 5 {
				_, n_e5, rawVal_e5, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding e5: %w", err)
				}
				decVal_e5, intErr := ber.DecodeIntegerValue(rawVal_e5)
				if intErr != nil {
					return fmt.Errorf("decoding e5: %w", intErr)
				}
				tmp_e5 := E5(decVal_e5)
				v.E5 = &tmp_e5
				offset += n_e5
			}
		}
	}
	// Decode e6
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 6 {
				_, n_e6, rawVal_e6, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding e6: %w", err)
				}
				decVal_e6, intErr := ber.DecodeIntegerValue(rawVal_e6)
				if intErr != nil {
					return fmt.Errorf("decoding e6: %w", intErr)
				}
				tmp_e6 := E6(decVal_e6)
				v.E6 = &tmp_e6
				offset += n_e6
			}
		}
	}
	// Decode e7
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 7 {
				_, n_e7, rawVal_e7, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding e7: %w", err)
				}
				decVal_e7, intErr := ber.DecodeIntegerValue(rawVal_e7)
				if intErr != nil {
					return fmt.Errorf("decoding e7: %w", intErr)
				}
				tmp_e7 := E7(decVal_e7)
				v.E7 = &tmp_e7
				offset += n_e7
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "ChargingInformation", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes ForwardCUGInfoArg to BER format.
func (v *ForwardCUGInfoArg) MarshalBER() ([]byte, error) {
	var children []byte
	if v.CugIndex != nil {
		enc_cugindex := ber.EncodeInteger(int64(*v.CugIndex))
		enc_cugindex = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, false, enc_cugindex)
		children = append(children, enc_cugindex...)
	}
	if v.SuppressPrefCUG != nil {
		enc_suppressprefcug := ber.EncodeNull()
		enc_suppressprefcug = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, false, enc_suppressprefcug)
		children = append(children, enc_suppressprefcug...)
	}
	if v.SuppressOA != nil {
		enc_suppressoa := ber.EncodeNull()
		enc_suppressoa = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, false, enc_suppressoa)
		children = append(children, enc_suppressoa...)
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

// MarshalDER encodes ForwardCUGInfoArg to DER format.
func (v *ForwardCUGInfoArg) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes ForwardCUGInfoArg from BER/DER format.
func (v *ForwardCUGInfoArg) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding ForwardCUGInfoArg SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "ForwardCUGInfoArg", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode cug-Index
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
				_, n_cugindex, rawVal_cugindex, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding cug-Index: %w", err)
				}
				decVal_cugindex, intErr := ber.DecodeIntegerValue(rawVal_cugindex)
				if intErr != nil {
					return fmt.Errorf("decoding cug-Index: %w", intErr)
				}
				tmp_cugindex := CUGIndex(decVal_cugindex)
				v.CugIndex = &tmp_cugindex
				offset += n_cugindex
			}
		}
	}
	// Decode suppressPrefCUG
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
				_, n_suppressprefcug, rawVal_suppressprefcug, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding suppressPrefCUG: %w", err)
				}
				_ = rawVal_suppressprefcug
				v.SuppressPrefCUG = &struct{}{}
				offset += n_suppressprefcug
			}
		}
	}
	// Decode suppressOA
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2 {
				_, n_suppressoa, rawVal_suppressoa, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding suppressOA: %w", err)
				}
				_ = rawVal_suppressoa
				v.SuppressOA = &struct{}{}
				offset += n_suppressoa
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "ForwardCUGInfoArg", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes ECTIndicator to BER format.
func (v *ECTIndicator) MarshalBER() ([]byte, error) {
	var children []byte
	enc_ectcallstate := ber.EncodeEnumerated(int64(v.EctCallState))
	enc_ectcallstate = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, false, enc_ectcallstate)
	children = append(children, enc_ectcallstate...)
	if v.Rdn != nil {
		enc_rdn, err := v.Rdn.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding rdn: %w", err)
		}
		enc_rdn = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 1, enc_rdn)
		children = append(children, enc_rdn...)
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

// MarshalDER encodes ECTIndicator to DER format.
func (v *ECTIndicator) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes ECTIndicator from BER/DER format.
func (v *ECTIndicator) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding ECTIndicator SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "ECTIndicator", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode ect-CallState
	if offset >= len(content) {
		return fmt.Errorf("missing required field ect-CallState")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 0 {
			return fmt.Errorf("expected tag [%s %d] for ect-CallState, got %s", "CONTEXT", 0, reqTag_)
		}
	}
	_, n_ectcallstate, rawVal_ectcallstate, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding ect-CallState: %w", err)
	}
	decVal_ectcallstate, intErr := ber.DecodeIntegerValue(rawVal_ectcallstate)
	if intErr != nil {
		return fmt.Errorf("decoding ect-CallState: %w", intErr)
	}
	v.EctCallState = ECTCallState(decVal_ectcallstate)
	offset += n_ectcallstate
	// Decode rdn
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
				_, n_rdn, innerData_rdn, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding rdn: %w", err)
				}
				// Decode inner value from explicit tag wrapper
				var dec_rdn RDN
				if unmErr := dec_rdn.UnmarshalBER(innerData_rdn); unmErr != nil {
					return fmt.Errorf("decoding rdn: %w", unmErr)
				}
				v.Rdn = &dec_rdn
				offset += n_rdn
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "ECTIndicator", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes NameIndicator to BER format.
func (v *NameIndicator) MarshalBER() ([]byte, error) {
	var children []byte
	if v.CallingName != nil {
		enc_callingname, err := v.CallingName.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding callingName: %w", err)
		}
		enc_callingname = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 0, enc_callingname)
		children = append(children, enc_callingname...)
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

// MarshalDER encodes NameIndicator to DER format.
func (v *NameIndicator) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes NameIndicator from BER/DER format.
func (v *NameIndicator) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding NameIndicator SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "NameIndicator", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode callingName
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
				_, n_callingname, innerData_callingname, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding callingName: %w", err)
				}
				// Decode inner value from explicit tag wrapper
				var dec_callingname Name
				if unmErr := dec_callingname.UnmarshalBER(innerData_callingname); unmErr != nil {
					return fmt.Errorf("decoding callingName: %w", unmErr)
				}
				v.CallingName = &dec_callingname
				offset += n_callingname
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "NameIndicator", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes Name to BER format.
func (v *Name) MarshalBER() ([]byte, error) {
	switch v.Choice {
	case NameChoiceNamePresentationAllowed:
		if v.NamePresentationAllowed == nil {
			return nil, fmt.Errorf("choice Name: namePresentationAllowed is nil")
		}
		enc_0, err := v.NamePresentationAllowed.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding namePresentationAllowed: %w", err)
		}
		enc_0 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, true, enc_0)
		return enc_0, nil
	case NameChoicePresentationRestricted:
		enc_1 := ber.EncodeNull()
		enc_1 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, false, enc_1)
		return enc_1, nil
	case NameChoiceNameUnavailable:
		enc_2 := ber.EncodeNull()
		enc_2 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, false, enc_2)
		return enc_2, nil
	case NameChoiceNamePresentationRestricted:
		if v.NamePresentationRestricted == nil {
			return nil, fmt.Errorf("choice Name: namePresentationRestricted is nil")
		}
		enc_3, err := v.NamePresentationRestricted.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding namePresentationRestricted: %w", err)
		}
		enc_3 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, true, enc_3)
		return enc_3, nil
	default:
		return nil, fmt.Errorf("unknown choice %d for Name", v.Choice)
	}
}

// MarshalDER encodes Name to DER format.
func (v *Name) MarshalDER() ([]byte, error) {
	switch v.Choice {
	case NameChoiceNamePresentationAllowed:
		if v.NamePresentationAllowed == nil {
			return nil, fmt.Errorf("choice Name: namePresentationAllowed is nil")
		}
		enc_der_0, err := v.NamePresentationAllowed.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding namePresentationAllowed: %w", err)
		}
		enc_der_0 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, true, enc_der_0)
		return enc_der_0, nil
	case NameChoiceNamePresentationRestricted:
		if v.NamePresentationRestricted == nil {
			return nil, fmt.Errorf("choice Name: namePresentationRestricted is nil")
		}
		enc_der_3, err := v.NamePresentationRestricted.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding namePresentationRestricted: %w", err)
		}
		enc_der_3 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, true, enc_der_3)
		return enc_der_3, nil
	}
	return v.MarshalBER()
}

// UnmarshalBER decodes Name from BER/DER format.
func (v *Name) UnmarshalBER(data []byte) error {
	if len(data) == 0 {
		return fmt.Errorf("empty data for Name CHOICE")
	}
	choiceData := data
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for Name: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData)
	if tlvErr != nil {
		return fmt.Errorf("decoding Name CHOICE: %w", tlvErr)
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "Name", Cause: ber.ErrExtraData}
	}

	if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
		v.Choice = NameChoiceNamePresentationAllowed
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding namePresentationAllowed: %w", tlvErr)
		}
		reconstructed := ber.EncodeSequence(rawVal)
		var dec NameSet
		if unmErr := dec.UnmarshalBER(reconstructed); unmErr != nil {
			return fmt.Errorf("decoding namePresentationAllowed: %w", unmErr)
		}
		v.NamePresentationAllowed = &dec
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
		v.Choice = NameChoicePresentationRestricted
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding presentationRestricted: %w", tlvErr)
		}
		_ = rawVal // NULL has no content
		v.PresentationRestricted = &struct{}{}
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2 {
		v.Choice = NameChoiceNameUnavailable
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding nameUnavailable: %w", tlvErr)
		}
		_ = rawVal // NULL has no content
		v.NameUnavailable = &struct{}{}
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3 {
		v.Choice = NameChoiceNamePresentationRestricted
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding namePresentationRestricted: %w", tlvErr)
		}
		reconstructed := ber.EncodeSequence(rawVal)
		var dec NameSet
		if unmErr := dec.UnmarshalBER(reconstructed); unmErr != nil {
			return fmt.Errorf("decoding namePresentationRestricted: %w", unmErr)
		}
		v.NamePresentationRestricted = &dec
	} else {
		return fmt.Errorf("unknown tag %s for Name CHOICE", peekTag)
	}
	return nil
}

// MarshalBER encodes NameSet to BER format.
func (v *NameSet) MarshalBER() ([]byte, error) {
	var children []byte
	enc_datacodingscheme := ber.EncodeOctetString([]byte(v.DataCodingScheme))
	enc_datacodingscheme = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, false, enc_datacodingscheme)
	children = append(children, enc_datacodingscheme...)
	if v.LengthInCharacters == nil {
		return nil, fmt.Errorf("encoding lengthInCharacters: required INTEGER is nil")
	}
	enc_lengthincharacters := ber.EncodeBigInt(v.LengthInCharacters)
	enc_lengthincharacters = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, false, enc_lengthincharacters)
	children = append(children, enc_lengthincharacters...)
	enc_namestring := ber.EncodeOctetString([]byte(v.NameString))
	enc_namestring = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, false, enc_namestring)
	children = append(children, enc_namestring...)
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

// MarshalDER encodes NameSet to DER format.
func (v *NameSet) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes NameSet from BER/DER format.
func (v *NameSet) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding NameSet SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "NameSet", Cause: ber.ErrExtraData}
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
	_, n_datacodingscheme, rawVal_datacodingscheme, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding dataCodingScheme: %w", err)
	}
	v.DataCodingScheme = USSDDataCodingScheme(rawVal_datacodingscheme)
	offset += n_datacodingscheme
	// Decode lengthInCharacters
	if offset >= len(content) {
		return fmt.Errorf("missing required field lengthInCharacters")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 1 {
			return fmt.Errorf("expected tag [%s %d] for lengthInCharacters, got %s", "CONTEXT", 1, reqTag_)
		}
	}
	_, n_lengthincharacters, rawVal_lengthincharacters, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding lengthInCharacters: %w", err)
	}
	decVal_lengthincharacters, intErr := ber.DecodeBigIntValue(rawVal_lengthincharacters)
	if intErr != nil {
		return fmt.Errorf("decoding lengthInCharacters: %w", intErr)
	}
	v.LengthInCharacters = decVal_lengthincharacters
	offset += n_lengthincharacters
	// Decode nameString
	if offset >= len(content) {
		return fmt.Errorf("missing required field nameString")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 2 {
			return fmt.Errorf("expected tag [%s %d] for nameString, got %s", "CONTEXT", 2, reqTag_)
		}
	}
	_, n_namestring, rawVal_namestring, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding nameString: %w", err)
	}
	v.NameString = USSDString(rawVal_namestring)
	offset += n_namestring
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "NameSet", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes RDN to BER format.
func (v *RDN) MarshalBER() ([]byte, error) {
	switch v.Choice {
	case RDNChoicePresentationAllowedAddress:
		if v.PresentationAllowedAddress == nil {
			return nil, fmt.Errorf("choice RDN: presentationAllowedAddress is nil")
		}
		enc_0, err := v.PresentationAllowedAddress.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding presentationAllowedAddress: %w", err)
		}
		enc_0 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, true, enc_0)
		return enc_0, nil
	case RDNChoicePresentationRestricted:
		enc_1 := ber.EncodeNull()
		enc_1 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, false, enc_1)
		return enc_1, nil
	case RDNChoiceNumberNotAvailableDueToInterworking:
		enc_2 := ber.EncodeNull()
		enc_2 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, false, enc_2)
		return enc_2, nil
	case RDNChoicePresentationRestrictedAddress:
		if v.PresentationRestrictedAddress == nil {
			return nil, fmt.Errorf("choice RDN: presentationRestrictedAddress is nil")
		}
		enc_3, err := v.PresentationRestrictedAddress.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding presentationRestrictedAddress: %w", err)
		}
		enc_3 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, true, enc_3)
		return enc_3, nil
	default:
		return nil, fmt.Errorf("unknown choice %d for RDN", v.Choice)
	}
}

// MarshalDER encodes RDN to DER format.
func (v *RDN) MarshalDER() ([]byte, error) {
	switch v.Choice {
	case RDNChoicePresentationAllowedAddress:
		if v.PresentationAllowedAddress == nil {
			return nil, fmt.Errorf("choice RDN: presentationAllowedAddress is nil")
		}
		enc_der_0, err := v.PresentationAllowedAddress.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding presentationAllowedAddress: %w", err)
		}
		enc_der_0 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, true, enc_der_0)
		return enc_der_0, nil
	case RDNChoicePresentationRestrictedAddress:
		if v.PresentationRestrictedAddress == nil {
			return nil, fmt.Errorf("choice RDN: presentationRestrictedAddress is nil")
		}
		enc_der_3, err := v.PresentationRestrictedAddress.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding presentationRestrictedAddress: %w", err)
		}
		enc_der_3 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, true, enc_der_3)
		return enc_der_3, nil
	}
	return v.MarshalBER()
}

// UnmarshalBER decodes RDN from BER/DER format.
func (v *RDN) UnmarshalBER(data []byte) error {
	if len(data) == 0 {
		return fmt.Errorf("empty data for RDN CHOICE")
	}
	choiceData := data
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for RDN: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData)
	if tlvErr != nil {
		return fmt.Errorf("decoding RDN CHOICE: %w", tlvErr)
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "RDN", Cause: ber.ErrExtraData}
	}

	if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
		v.Choice = RDNChoicePresentationAllowedAddress
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding presentationAllowedAddress: %w", tlvErr)
		}
		reconstructed := ber.EncodeSequence(rawVal)
		var dec RemotePartyNumber
		if unmErr := dec.UnmarshalBER(reconstructed); unmErr != nil {
			return fmt.Errorf("decoding presentationAllowedAddress: %w", unmErr)
		}
		v.PresentationAllowedAddress = &dec
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
		v.Choice = RDNChoicePresentationRestricted
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding presentationRestricted: %w", tlvErr)
		}
		_ = rawVal // NULL has no content
		v.PresentationRestricted = &struct{}{}
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2 {
		v.Choice = RDNChoiceNumberNotAvailableDueToInterworking
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding numberNotAvailableDueToInterworking: %w", tlvErr)
		}
		_ = rawVal // NULL has no content
		v.NumberNotAvailableDueToInterworking = &struct{}{}
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3 {
		v.Choice = RDNChoicePresentationRestrictedAddress
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding presentationRestrictedAddress: %w", tlvErr)
		}
		reconstructed := ber.EncodeSequence(rawVal)
		var dec RemotePartyNumber
		if unmErr := dec.UnmarshalBER(reconstructed); unmErr != nil {
			return fmt.Errorf("decoding presentationRestrictedAddress: %w", unmErr)
		}
		v.PresentationRestrictedAddress = &dec
	} else {
		return fmt.Errorf("unknown tag %s for RDN CHOICE", peekTag)
	}
	return nil
}

// MarshalBER encodes RemotePartyNumber to BER format.
func (v *RemotePartyNumber) MarshalBER() ([]byte, error) {
	var children []byte
	enc_partynumber := ber.EncodeOctetString([]byte(v.PartyNumber))
	enc_partynumber = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, false, enc_partynumber)
	children = append(children, enc_partynumber...)
	if v.PartyNumberSubaddress != nil {
		enc_partynumbersubaddress := ber.EncodeOctetString([]byte(*v.PartyNumberSubaddress))
		enc_partynumbersubaddress = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, false, enc_partynumbersubaddress)
		children = append(children, enc_partynumbersubaddress...)
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

// MarshalDER encodes RemotePartyNumber to DER format.
func (v *RemotePartyNumber) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes RemotePartyNumber from BER/DER format.
func (v *RemotePartyNumber) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding RemotePartyNumber SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "RemotePartyNumber", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode partyNumber
	if offset >= len(content) {
		return fmt.Errorf("missing required field partyNumber")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 0 {
			return fmt.Errorf("expected tag [%s %d] for partyNumber, got %s", "CONTEXT", 0, reqTag_)
		}
	}
	_, n_partynumber, rawVal_partynumber, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding partyNumber: %w", err)
	}
	v.PartyNumber = ISDNAddressString(rawVal_partynumber)
	offset += n_partynumber
	// Decode partyNumberSubaddress
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
				_, n_partynumbersubaddress, rawVal_partynumbersubaddress, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding partyNumberSubaddress: %w", err)
				}
				tmp_partynumbersubaddress := ISDNSubaddressString(rawVal_partynumbersubaddress)
				v.PartyNumberSubaddress = &tmp_partynumbersubaddress
				offset += n_partynumbersubaddress
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "RemotePartyNumber", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes AccessRegisterCCEntryArg to BER format.
func (v *AccessRegisterCCEntryArg) MarshalBER() ([]byte, error) {
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

// MarshalDER encodes AccessRegisterCCEntryArg to DER format.
func (v *AccessRegisterCCEntryArg) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes AccessRegisterCCEntryArg from BER/DER format.
func (v *AccessRegisterCCEntryArg) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding AccessRegisterCCEntryArg SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "AccessRegisterCCEntryArg", Cause: ber.ErrExtraData}
	}
	offset := 0
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "AccessRegisterCCEntryArg", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes CallDeflectionArg to BER format.
func (v *CallDeflectionArg) MarshalBER() ([]byte, error) {
	var children []byte
	enc_deflectedtonumber := ber.EncodeOctetString([]byte(v.DeflectedToNumber))
	enc_deflectedtonumber = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, false, enc_deflectedtonumber)
	children = append(children, enc_deflectedtonumber...)
	if v.DeflectedToSubaddress != nil {
		enc_deflectedtosubaddress := ber.EncodeOctetString([]byte(*v.DeflectedToSubaddress))
		enc_deflectedtosubaddress = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, false, enc_deflectedtosubaddress)
		children = append(children, enc_deflectedtosubaddress...)
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

// MarshalDER encodes CallDeflectionArg to DER format.
func (v *CallDeflectionArg) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes CallDeflectionArg from BER/DER format.
func (v *CallDeflectionArg) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding CallDeflectionArg SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "CallDeflectionArg", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode deflectedToNumber
	if offset >= len(content) {
		return fmt.Errorf("missing required field deflectedToNumber")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 0 {
			return fmt.Errorf("expected tag [%s %d] for deflectedToNumber, got %s", "CONTEXT", 0, reqTag_)
		}
	}
	_, n_deflectedtonumber, rawVal_deflectedtonumber, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding deflectedToNumber: %w", err)
	}
	v.DeflectedToNumber = AddressString(rawVal_deflectedtonumber)
	offset += n_deflectedtonumber
	// Decode deflectedToSubaddress
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
				_, n_deflectedtosubaddress, rawVal_deflectedtosubaddress, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding deflectedToSubaddress: %w", err)
				}
				tmp_deflectedtosubaddress := ISDNSubaddressString(rawVal_deflectedtosubaddress)
				v.DeflectedToSubaddress = &tmp_deflectedtosubaddress
				offset += n_deflectedtosubaddress
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "CallDeflectionArg", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes UserUserServiceArg to BER format.
func (v *UserUserServiceArg) MarshalBER() ([]byte, error) {
	var children []byte
	enc_uusservice := ber.EncodeEnumerated(int64(v.UUSService))
	enc_uusservice = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, false, enc_uusservice)
	children = append(children, enc_uusservice...)
	var enc_uusrequired []byte
	if v.UUSRequiredRaw_ != 0 {
		enc_uusrequired = ber.EncodeBooleanRaw(v.UUSRequiredRaw_)
	} else {
		enc_uusrequired = ber.EncodeBoolean(v.UUSRequired)
	}
	enc_uusrequired = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, false, enc_uusrequired)
	children = append(children, enc_uusrequired...)
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

// MarshalDER encodes UserUserServiceArg to DER format.
func (v *UserUserServiceArg) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes UserUserServiceArg from BER/DER format.
func (v *UserUserServiceArg) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding UserUserServiceArg SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "UserUserServiceArg", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode uUS-Service
	if offset >= len(content) {
		return fmt.Errorf("missing required field uUS-Service")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 0 {
			return fmt.Errorf("expected tag [%s %d] for uUS-Service, got %s", "CONTEXT", 0, reqTag_)
		}
	}
	_, n_uusservice, rawVal_uusservice, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding uUS-Service: %w", err)
	}
	decVal_uusservice, intErr := ber.DecodeIntegerValue(rawVal_uusservice)
	if intErr != nil {
		return fmt.Errorf("decoding uUS-Service: %w", intErr)
	}
	v.UUSService = UUSService(decVal_uusservice)
	offset += n_uusservice
	// Decode uUS-Required
	if offset >= len(content) {
		return fmt.Errorf("missing required field uUS-Required")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 1 {
			return fmt.Errorf("expected tag [%s %d] for uUS-Required, got %s", "CONTEXT", 1, reqTag_)
		}
	}
	_, n_uusrequired, rawVal_uusrequired, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding uUS-Required: %w", err)
	}
	decVal_uusrequired, boolErr := ber.DecodeBooleanValue(rawVal_uusrequired)
	if boolErr != nil {
		return fmt.Errorf("decoding uUS-Required: %w", boolErr)
	}
	if len(rawVal_uusrequired) == 1 {
		v.UUSRequiredRaw_ = rawVal_uusrequired[0]
	}
	v.UUSRequired = decVal_uusrequired
	offset += n_uusrequired
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "UserUserServiceArg", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes LocationNotificationArg to BER format.
func (v *LocationNotificationArg) MarshalBER() ([]byte, error) {
	var children []byte
	enc_notificationtype := ber.EncodeEnumerated(int64(v.NotificationType))
	enc_notificationtype = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, false, enc_notificationtype)
	children = append(children, enc_notificationtype...)
	enc_locationtype, err := v.LocationType.MarshalBER()
	if err != nil {
		return nil, fmt.Errorf("encoding locationType: %w", err)
	}
	enc_locationtype = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, true, enc_locationtype)
	children = append(children, enc_locationtype...)
	if v.LcsClientExternalID != nil {
		enc_lcsclientexternalid, err := v.LcsClientExternalID.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding lcsClientExternalID: %w", err)
		}
		enc_lcsclientexternalid = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, true, enc_lcsclientexternalid)
		children = append(children, enc_lcsclientexternalid...)
	}
	if v.LcsClientName != nil {
		enc_lcsclientname, err := v.LcsClientName.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding lcsClientName: %w", err)
		}
		enc_lcsclientname = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, true, enc_lcsclientname)
		children = append(children, enc_lcsclientname...)
	}
	if v.LcsRequestorID != nil {
		enc_lcsrequestorid, err := v.LcsRequestorID.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding lcsRequestorID: %w", err)
		}
		enc_lcsrequestorid = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, true, enc_lcsrequestorid)
		children = append(children, enc_lcsrequestorid...)
	}
	if v.LcsCodeword != nil {
		enc_lcscodeword, err := v.LcsCodeword.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding lcsCodeword: %w", err)
		}
		enc_lcscodeword = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 5, true, enc_lcscodeword)
		children = append(children, enc_lcscodeword...)
	}
	if v.LcsServiceTypeID != nil {
		enc_lcsservicetypeid := ber.EncodeInteger(int64(*v.LcsServiceTypeID))
		enc_lcsservicetypeid = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 6, false, enc_lcsservicetypeid)
		children = append(children, enc_lcsservicetypeid...)
	}
	if v.DeferredLocationExt != nil {
		enc_deferredlocationext := ber.EncodeBitString(v.DeferredLocationExt.Bytes, (8-(v.DeferredLocationExt.BitLength%8))%8)
		enc_deferredlocationext = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 7, false, enc_deferredlocationext)
		children = append(children, enc_deferredlocationext...)
	}
	if v.RangingSlExt != nil {
		enc_rangingslext := ber.EncodeBitString(v.RangingSlExt.Bytes, (8-(v.RangingSlExt.BitLength%8))%8)
		enc_rangingslext = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 8, false, enc_rangingslext)
		children = append(children, enc_rangingslext...)
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

// MarshalDER encodes LocationNotificationArg to DER format.
func (v *LocationNotificationArg) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes LocationNotificationArg from BER/DER format.
func (v *LocationNotificationArg) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding LocationNotificationArg SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "LocationNotificationArg", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode notificationType
	if offset >= len(content) {
		return fmt.Errorf("missing required field notificationType")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 0 {
			return fmt.Errorf("expected tag [%s %d] for notificationType, got %s", "CONTEXT", 0, reqTag_)
		}
	}
	_, n_notificationtype, rawVal_notificationtype, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding notificationType: %w", err)
	}
	decVal_notificationtype, intErr := ber.DecodeIntegerValue(rawVal_notificationtype)
	if intErr != nil {
		return fmt.Errorf("decoding notificationType: %w", intErr)
	}
	v.NotificationType = NotificationToMSUser(decVal_notificationtype)
	offset += n_notificationtype
	// Decode locationType
	if offset >= len(content) {
		return fmt.Errorf("missing required field locationType")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 1 {
			return fmt.Errorf("expected tag [%s %d] for locationType, got %s", "CONTEXT", 1, reqTag_)
		}
	}
	_, n_locationtype, rawVal_locationtype, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding locationType: %w", err)
	}
	reconstructed_locationtype := ber.EncodeSequence(rawVal_locationtype)
	if unmErr := v.LocationType.UnmarshalBER(reconstructed_locationtype); unmErr != nil {
		return fmt.Errorf("decoding locationType: %w", unmErr)
	}
	offset += n_locationtype
	// Decode lcsClientExternalID
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2 {
				_, n_lcsclientexternalid, rawVal_lcsclientexternalid, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding lcsClientExternalID: %w", err)
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
	// Decode lcsClientName
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3 {
				_, n_lcsclientname, rawVal_lcsclientname, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding lcsClientName: %w", err)
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
	// Decode lcsRequestorID
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4 {
				_, n_lcsrequestorid, rawVal_lcsrequestorid, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding lcsRequestorID: %w", err)
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
	// Decode lcsCodeword
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 5 {
				_, n_lcscodeword, rawVal_lcscodeword, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding lcsCodeword: %w", err)
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
	// Decode lcsServiceTypeID
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 6 {
				_, n_lcsservicetypeid, rawVal_lcsservicetypeid, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding lcsServiceTypeID: %w", err)
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
	// Decode deferredLocationExt
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 7 {
				_, n_deferredlocationext, rawVal_deferredlocationext, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding deferredLocationExt: %w", err)
				}
				bsBytes_deferredlocationext, bsUnused_deferredlocationext, bsErr := ber.DecodeBitStringValue(rawVal_deferredlocationext)
				if bsErr != nil {
					return fmt.Errorf("decoding deferredLocationExt: %w", bsErr)
				}
				tmp_deferredlocationext := runtime.BitString{Bytes: bsBytes_deferredlocationext, BitLength: len(bsBytes_deferredlocationext)*8 - bsUnused_deferredlocationext}
				v.DeferredLocationExt = &tmp_deferredlocationext
				offset += n_deferredlocationext
			}
		}
	}
	// Decode rangingSlExt
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 8 {
				_, n_rangingslext, rawVal_rangingslext, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding rangingSlExt: %w", err)
				}
				bsBytes_rangingslext, bsUnused_rangingslext, bsErr := ber.DecodeBitStringValue(rawVal_rangingslext)
				if bsErr != nil {
					return fmt.Errorf("decoding rangingSlExt: %w", bsErr)
				}
				tmp_rangingslext := runtime.BitString{Bytes: bsBytes_rangingslext, BitLength: len(bsBytes_rangingslext)*8 - bsUnused_rangingslext}
				v.RangingSlExt = &tmp_rangingslext
				offset += n_rangingslext
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "LocationNotificationArg", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes LocationNotificationRes to BER format.
func (v *LocationNotificationRes) MarshalBER() ([]byte, error) {
	var children []byte
	if v.VerificationResponse != nil {
		enc_verificationresponse := ber.EncodeEnumerated(int64(*v.VerificationResponse))
		enc_verificationresponse = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, false, enc_verificationresponse)
		children = append(children, enc_verificationresponse...)
	}
	if v.LocationPrivacyIndication != nil {
		enc_locationprivacyindication := ber.EncodeEnumerated(int64(*v.LocationPrivacyIndication))
		enc_locationprivacyindication = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, false, enc_locationprivacyindication)
		children = append(children, enc_locationprivacyindication...)
	}
	if v.ValidTimePeriod != nil {
		enc_validtimeperiod, err := v.ValidTimePeriod.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding validTimePeriod: %w", err)
		}
		enc_validtimeperiod = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, true, enc_validtimeperiod)
		children = append(children, enc_validtimeperiod...)
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

// MarshalDER encodes LocationNotificationRes to DER format.
func (v *LocationNotificationRes) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes LocationNotificationRes from BER/DER format.
func (v *LocationNotificationRes) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding LocationNotificationRes SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "LocationNotificationRes", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode verificationResponse
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
				_, n_verificationresponse, rawVal_verificationresponse, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding verificationResponse: %w", err)
				}
				decVal_verificationresponse, intErr := ber.DecodeIntegerValue(rawVal_verificationresponse)
				if intErr != nil {
					return fmt.Errorf("decoding verificationResponse: %w", intErr)
				}
				tmp_verificationresponse := VerificationResponse(decVal_verificationresponse)
				v.VerificationResponse = &tmp_verificationresponse
				offset += n_verificationresponse
			}
		}
	}
	// Decode locationPrivacyIndication
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
				_, n_locationprivacyindication, rawVal_locationprivacyindication, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding locationPrivacyIndication: %w", err)
				}
				decVal_locationprivacyindication, intErr := ber.DecodeIntegerValue(rawVal_locationprivacyindication)
				if intErr != nil {
					return fmt.Errorf("decoding locationPrivacyIndication: %w", intErr)
				}
				tmp_locationprivacyindication := LCSLocationPrivacyIndication(decVal_locationprivacyindication)
				v.LocationPrivacyIndication = &tmp_locationprivacyindication
				offset += n_locationprivacyindication
			}
		}
	}
	// Decode validTimePeriod
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2 {
				_, n_validtimeperiod, rawVal_validtimeperiod, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding validTimePeriod: %w", err)
				}
				reconstructed_validtimeperiod := ber.EncodeSequence(rawVal_validtimeperiod)
				var dec_validtimeperiod LCSValidTimePeriod
				if unmErr := dec_validtimeperiod.UnmarshalBER(reconstructed_validtimeperiod); unmErr != nil {
					return fmt.Errorf("decoding validTimePeriod: %w", unmErr)
				}
				v.ValidTimePeriod = &dec_validtimeperiod
				offset += n_validtimeperiod
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "LocationNotificationRes", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes LCSMOLRArg to BER format.
func (v *LCSMOLRArg) MarshalBER() ([]byte, error) {
	var children []byte
	enc_molrtype := ber.EncodeEnumerated(int64(v.MolrType))
	enc_molrtype = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, false, enc_molrtype)
	children = append(children, enc_molrtype...)
	if v.LocationMethod != nil {
		enc_locationmethod := ber.EncodeEnumerated(int64(*v.LocationMethod))
		enc_locationmethod = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, false, enc_locationmethod)
		children = append(children, enc_locationmethod...)
	}
	if v.LcsQoS != nil {
		enc_lcsqos, err := v.LcsQoS.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding lcs-QoS: %w", err)
		}
		enc_lcsqos = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, true, enc_lcsqos)
		children = append(children, enc_lcsqos...)
	}
	if v.LcsClientExternalID != nil {
		enc_lcsclientexternalid, err := v.LcsClientExternalID.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding lcsClientExternalID: %w", err)
		}
		enc_lcsclientexternalid = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, true, enc_lcsclientexternalid)
		children = append(children, enc_lcsclientexternalid...)
	}
	if v.MlcNumber != nil {
		enc_mlcnumber := ber.EncodeOctetString([]byte(*v.MlcNumber))
		enc_mlcnumber = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, false, enc_mlcnumber)
		children = append(children, enc_mlcnumber...)
	}
	if v.GpsAssistanceData != nil {
		enc_gpsassistancedata := ber.EncodeOctetString([]byte(*v.GpsAssistanceData))
		enc_gpsassistancedata = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 5, false, enc_gpsassistancedata)
		children = append(children, enc_gpsassistancedata...)
	}
	if v.SupportedGADShapes != nil {
		enc_supportedgadshapes := ber.EncodeBitString(v.SupportedGADShapes.Bytes, (8-(v.SupportedGADShapes.BitLength%8))%8)
		enc_supportedgadshapes = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 6, false, enc_supportedgadshapes)
		children = append(children, enc_supportedgadshapes...)
	}
	if v.LcsServiceTypeID != nil {
		enc_lcsservicetypeid := ber.EncodeInteger(int64(*v.LcsServiceTypeID))
		enc_lcsservicetypeid = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 7, false, enc_lcsservicetypeid)
		children = append(children, enc_lcsservicetypeid...)
	}
	if v.AgeOfLocationInfo != nil {
		enc_ageoflocationinfo := ber.EncodeInteger(int64(*v.AgeOfLocationInfo))
		enc_ageoflocationinfo = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 8, false, enc_ageoflocationinfo)
		children = append(children, enc_ageoflocationinfo...)
	}
	if v.LocationType != nil {
		enc_locationtype, err := v.LocationType.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding locationType: %w", err)
		}
		enc_locationtype = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 9, true, enc_locationtype)
		children = append(children, enc_locationtype...)
	}
	if v.PseudonymIndicator != nil {
		enc_pseudonymindicator := ber.EncodeNull()
		enc_pseudonymindicator = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 10, false, enc_pseudonymindicator)
		children = append(children, enc_pseudonymindicator...)
	}
	if v.HGmlcAddress != nil {
		enc_hgmlcaddress := ber.EncodeOctetString([]byte(*v.HGmlcAddress))
		enc_hgmlcaddress = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 11, false, enc_hgmlcaddress)
		children = append(children, enc_hgmlcaddress...)
	}
	if v.LocationEstimate != nil {
		enc_locationestimate := ber.EncodeOctetString([]byte(*v.LocationEstimate))
		enc_locationestimate = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 12, false, enc_locationestimate)
		children = append(children, enc_locationestimate...)
	}
	if v.VelocityEstimate != nil {
		enc_velocityestimate := ber.EncodeOctetString([]byte(*v.VelocityEstimate))
		enc_velocityestimate = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 13, false, enc_velocityestimate)
		children = append(children, enc_velocityestimate...)
	}
	if v.ReferenceNumber != nil {
		enc_referencenumber := ber.EncodeOctetString([]byte(*v.ReferenceNumber))
		enc_referencenumber = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 14, false, enc_referencenumber)
		children = append(children, enc_referencenumber...)
	}
	if v.PeriodicLDRInfo != nil {
		enc_periodicldrinfo, err := v.PeriodicLDRInfo.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding periodicLDRInfo: %w", err)
		}
		enc_periodicldrinfo = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 15, true, enc_periodicldrinfo)
		children = append(children, enc_periodicldrinfo...)
	}
	if v.LocationUpdateRequest != nil {
		enc_locationupdaterequest := ber.EncodeNull()
		enc_locationupdaterequest = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 16, false, enc_locationupdaterequest)
		children = append(children, enc_locationupdaterequest...)
	}
	if v.SequenceNumber != nil {
		enc_sequencenumber := ber.EncodeInteger(int64(*v.SequenceNumber))
		enc_sequencenumber = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 17, false, enc_sequencenumber)
		children = append(children, enc_sequencenumber...)
	}
	if v.TerminationCause != nil {
		enc_terminationcause := ber.EncodeEnumerated(int64(*v.TerminationCause))
		enc_terminationcause = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 18, false, enc_terminationcause)
		children = append(children, enc_terminationcause...)
	}
	if v.MoLrShortCircuit != nil {
		enc_molrshortcircuit := ber.EncodeNull()
		enc_molrshortcircuit = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 19, false, enc_molrshortcircuit)
		children = append(children, enc_molrshortcircuit...)
	}
	if v.GanssAssistanceData != nil {
		enc_ganssassistancedata := ber.EncodeOctetString([]byte(*v.GanssAssistanceData))
		enc_ganssassistancedata = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 20, false, enc_ganssassistancedata)
		children = append(children, enc_ganssassistancedata...)
	}
	if v.MultiplePositioningProtocolPDUs != nil {
		enc_multiplepositioningprotocolpdus, err := MarshalBERMultiplePositioningProtocolPDUs(v.MultiplePositioningProtocolPDUs)
		if err != nil {
			return nil, fmt.Errorf("encoding multiplePositioningProtocolPDUs: %w", err)
		}
		if v.MultiplePositioningProtocolPDUsIndef_ {
			// Strip the outer SEQUENCE tag from marshalBER output to get raw children.
			_, _, seqContent_, tlvErr_ := ber.DecodeTLV(enc_multiplepositioningprotocolpdus)
			if tlvErr_ != nil {
				return nil, tlvErr_
			}
			enc_multiplepositioningprotocolpdus = ber.EncodeConstructedIndefinite(tag.Tag{Class: tag.ClassContextSpecific, Number: 21}, seqContent_)
		} else {
			enc_multiplepositioningprotocolpdus = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 21, true, enc_multiplepositioningprotocolpdus)
		}
		children = append(children, enc_multiplepositioningprotocolpdus...)
	}
	if v.LocationInfo != nil {
		enc_locationinfo := ber.EncodeBitString(v.LocationInfo.Bytes, (8-(v.LocationInfo.BitLength%8))%8)
		enc_locationinfo = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 22, false, enc_locationinfo)
		children = append(children, enc_locationinfo...)
	}
	if v.ScheduledLocTime != nil {
		enc_scheduledloctime := ber.EncodeOctetString([]byte(*v.ScheduledLocTime))
		enc_scheduledloctime = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 23, false, enc_scheduledloctime)
		children = append(children, enc_scheduledloctime...)
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

// MarshalDER encodes LCSMOLRArg to DER format.
func (v *LCSMOLRArg) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// ITU-T X.690 (02/2021) Section 10.1 requires DER length forms to be definite.
	derValue := *v
	derValue.MultiplePositioningProtocolPDUsIndef_ = false
	v = &derValue
	return v.MarshalBER()
}

// UnmarshalBER decodes LCSMOLRArg from BER/DER format.
func (v *LCSMOLRArg) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding LCSMOLRArg SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "LCSMOLRArg", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode molr-Type
	if offset >= len(content) {
		return fmt.Errorf("missing required field molr-Type")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 0 {
			return fmt.Errorf("expected tag [%s %d] for molr-Type, got %s", "CONTEXT", 0, reqTag_)
		}
	}
	_, n_molrtype, rawVal_molrtype, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding molr-Type: %w", err)
	}
	decVal_molrtype, intErr := ber.DecodeIntegerValue(rawVal_molrtype)
	if intErr != nil {
		return fmt.Errorf("decoding molr-Type: %w", intErr)
	}
	v.MolrType = MOLRType(decVal_molrtype)
	offset += n_molrtype
	// Decode locationMethod
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
				_, n_locationmethod, rawVal_locationmethod, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding locationMethod: %w", err)
				}
				decVal_locationmethod, intErr := ber.DecodeIntegerValue(rawVal_locationmethod)
				if intErr != nil {
					return fmt.Errorf("decoding locationMethod: %w", intErr)
				}
				tmp_locationmethod := LocationMethod(decVal_locationmethod)
				v.LocationMethod = &tmp_locationmethod
				offset += n_locationmethod
			}
		}
	}
	// Decode lcs-QoS
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2 {
				_, n_lcsqos, rawVal_lcsqos, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding lcs-QoS: %w", err)
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
	// Decode lcsClientExternalID
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3 {
				_, n_lcsclientexternalid, rawVal_lcsclientexternalid, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding lcsClientExternalID: %w", err)
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
	// Decode mlc-Number
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4 {
				_, n_mlcnumber, rawVal_mlcnumber, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding mlc-Number: %w", err)
				}
				tmp_mlcnumber := ISDNAddressString(rawVal_mlcnumber)
				v.MlcNumber = &tmp_mlcnumber
				offset += n_mlcnumber
			}
		}
	}
	// Decode gpsAssistanceData
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 5 {
				_, n_gpsassistancedata, rawVal_gpsassistancedata, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding gpsAssistanceData: %w", err)
				}
				tmp_gpsassistancedata := GPSAssistanceData(rawVal_gpsassistancedata)
				v.GpsAssistanceData = &tmp_gpsassistancedata
				offset += n_gpsassistancedata
			}
		}
	}
	// Decode supportedGADShapes
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 6 {
				_, n_supportedgadshapes, rawVal_supportedgadshapes, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding supportedGADShapes: %w", err)
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
	// Decode lcsServiceTypeID
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 7 {
				_, n_lcsservicetypeid, rawVal_lcsservicetypeid, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding lcsServiceTypeID: %w", err)
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
	// Decode ageOfLocationInfo
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 8 {
				_, n_ageoflocationinfo, rawVal_ageoflocationinfo, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding ageOfLocationInfo: %w", err)
				}
				decVal_ageoflocationinfo, intErr := ber.DecodeIntegerValue(rawVal_ageoflocationinfo)
				if intErr != nil {
					return fmt.Errorf("decoding ageOfLocationInfo: %w", intErr)
				}
				tmp_ageoflocationinfo := AgeOfLocationInformation(decVal_ageoflocationinfo)
				v.AgeOfLocationInfo = &tmp_ageoflocationinfo
				offset += n_ageoflocationinfo
			}
		}
	}
	// Decode locationType
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 9 {
				_, n_locationtype, rawVal_locationtype, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding locationType: %w", err)
				}
				reconstructed_locationtype := ber.EncodeSequence(rawVal_locationtype)
				var dec_locationtype LocationType
				if unmErr := dec_locationtype.UnmarshalBER(reconstructed_locationtype); unmErr != nil {
					return fmt.Errorf("decoding locationType: %w", unmErr)
				}
				v.LocationType = &dec_locationtype
				offset += n_locationtype
			}
		}
	}
	// Decode pseudonymIndicator
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 10 {
				_, n_pseudonymindicator, rawVal_pseudonymindicator, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding pseudonymIndicator: %w", err)
				}
				_ = rawVal_pseudonymindicator
				v.PseudonymIndicator = &struct{}{}
				offset += n_pseudonymindicator
			}
		}
	}
	// Decode h-gmlc-address
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 11 {
				_, n_hgmlcaddress, rawVal_hgmlcaddress, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding h-gmlc-address: %w", err)
				}
				tmp_hgmlcaddress := GSNAddress(rawVal_hgmlcaddress)
				v.HGmlcAddress = &tmp_hgmlcaddress
				offset += n_hgmlcaddress
			}
		}
	}
	// Decode locationEstimate
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 12 {
				_, n_locationestimate, rawVal_locationestimate, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding locationEstimate: %w", err)
				}
				tmp_locationestimate := ExtGeographicalInformation(rawVal_locationestimate)
				v.LocationEstimate = &tmp_locationestimate
				offset += n_locationestimate
			}
		}
	}
	// Decode velocityEstimate
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 13 {
				_, n_velocityestimate, rawVal_velocityestimate, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding velocityEstimate: %w", err)
				}
				tmp_velocityestimate := VelocityEstimate(rawVal_velocityestimate)
				v.VelocityEstimate = &tmp_velocityestimate
				offset += n_velocityestimate
			}
		}
	}
	// Decode referenceNumber
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 14 {
				_, n_referencenumber, rawVal_referencenumber, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding referenceNumber: %w", err)
				}
				tmp_referencenumber := LCSReferenceNumber(rawVal_referencenumber)
				v.ReferenceNumber = &tmp_referencenumber
				offset += n_referencenumber
			}
		}
	}
	// Decode periodicLDRInfo
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 15 {
				_, n_periodicldrinfo, rawVal_periodicldrinfo, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding periodicLDRInfo: %w", err)
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
	// Decode locationUpdateRequest
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 16 {
				_, n_locationupdaterequest, rawVal_locationupdaterequest, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding locationUpdateRequest: %w", err)
				}
				_ = rawVal_locationupdaterequest
				v.LocationUpdateRequest = &struct{}{}
				offset += n_locationupdaterequest
			}
		}
	}
	// Decode sequenceNumber
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 17 {
				_, n_sequencenumber, rawVal_sequencenumber, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding sequenceNumber: %w", err)
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
	// Decode terminationCause
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 18 {
				_, n_terminationcause, rawVal_terminationcause, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding terminationCause: %w", err)
				}
				decVal_terminationcause, intErr := ber.DecodeIntegerValue(rawVal_terminationcause)
				if intErr != nil {
					return fmt.Errorf("decoding terminationCause: %w", intErr)
				}
				tmp_terminationcause := DataTypesTerminationCause(decVal_terminationcause)
				v.TerminationCause = &tmp_terminationcause
				offset += n_terminationcause
			}
		}
	}
	// Decode mo-lrShortCircuit
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 19 {
				_, n_molrshortcircuit, rawVal_molrshortcircuit, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding mo-lrShortCircuit: %w", err)
				}
				_ = rawVal_molrshortcircuit
				v.MoLrShortCircuit = &struct{}{}
				offset += n_molrshortcircuit
			}
		}
	}
	// Decode ganssAssistanceData
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 20 {
				_, n_ganssassistancedata, rawVal_ganssassistancedata, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding ganssAssistanceData: %w", err)
				}
				tmp_ganssassistancedata := GANSSAssistanceData(rawVal_ganssassistancedata)
				v.GanssAssistanceData = &tmp_ganssassistancedata
				offset += n_ganssassistancedata
			}
		}
	}
	// Decode multiplePositioningProtocolPDUs
	v.MultiplePositioningProtocolPDUsIndef_ = false
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 21 {
				_, n_multiplepositioningprotocolpdus, rawVal_multiplepositioningprotocolpdus, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding multiplePositioningProtocolPDUs: %w", err)
				}
				reconstructed_multiplepositioningprotocolpdus := ber.EncodeSequence(rawVal_multiplepositioningprotocolpdus)
				dec_multiplepositioningprotocolpdus, unmErr := UnmarshalBERMultiplePositioningProtocolPDUs(reconstructed_multiplepositioningprotocolpdus)
				if unmErr != nil {
					return fmt.Errorf("decoding multiplePositioningProtocolPDUs: %w", unmErr)
				}
				v.MultiplePositioningProtocolPDUs = dec_multiplepositioningprotocolpdus
				{
					_, tagSz_, _ := ber.DecodeTag(content[offset:])
					if offset+tagSz_ < len(content) && content[offset+tagSz_] == 0x80 {
						v.MultiplePositioningProtocolPDUsIndef_ = true
					}
				}
				offset += n_multiplepositioningprotocolpdus
			}
		}
	}
	// Decode locationInfo
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 22 {
				_, n_locationinfo, rawVal_locationinfo, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding locationInfo: %w", err)
				}
				bsBytes_locationinfo, bsUnused_locationinfo, bsErr := ber.DecodeBitStringValue(rawVal_locationinfo)
				if bsErr != nil {
					return fmt.Errorf("decoding locationInfo: %w", bsErr)
				}
				tmp_locationinfo := runtime.BitString{Bytes: bsBytes_locationinfo, BitLength: len(bsBytes_locationinfo)*8 - bsUnused_locationinfo}
				v.LocationInfo = &tmp_locationinfo
				offset += n_locationinfo
			}
		}
	}
	// Decode scheduledLocTime
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 23 {
				_, n_scheduledloctime, rawVal_scheduledloctime, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding scheduledLocTime: %w", err)
				}
				tmp_scheduledloctime := DateTime(rawVal_scheduledloctime)
				v.ScheduledLocTime = &tmp_scheduledloctime
				offset += n_scheduledloctime
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "LCSMOLRArg", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBERMultiplePositioningProtocolPDUs encodes a MultiplePositioningProtocolPDUs list to BER.
func MarshalBERMultiplePositioningProtocolPDUs(list MultiplePositioningProtocolPDUs) ([]byte, error) {
	var children []byte
	for _, elem := range list {
		children = append(children, ber.EncodeOctetString([]byte(elem))...)
	}
	return ber.EncodeSequence(children), nil
}

// UnmarshalBERMultiplePositioningProtocolPDUs decodes a MultiplePositioningProtocolPDUs list from BER.
func UnmarshalBERMultiplePositioningProtocolPDUs(data []byte) (MultiplePositioningProtocolPDUs, error) {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return nil, fmt.Errorf("decoding MultiplePositioningProtocolPDUs: %w", err)
	}
	if total != len(data) {
		return nil, &ber.DecodeError{Offset: total, TypeName: "MultiplePositioningProtocolPDUs", Cause: ber.ErrExtraData}
	}
	var result MultiplePositioningProtocolPDUs
	offset := 0
	for offset < len(content) {
		val, n, osErr := ber.DecodeOctetString(content[offset:])
		if osErr != nil {
			return nil, fmt.Errorf("decoding element: %w", osErr)
		}
		result = append(result, PositioningProtocolPDU(val))
		offset += n
	}
	return result, nil
}

// MarshalBER encodes LCSMOLRRes to BER format.
func (v *LCSMOLRRes) MarshalBER() ([]byte, error) {
	var children []byte
	if v.LocationEstimate != nil {
		enc_locationestimate := ber.EncodeOctetString([]byte(*v.LocationEstimate))
		enc_locationestimate = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, false, enc_locationestimate)
		children = append(children, enc_locationestimate...)
	}
	if v.DecipheringKeys != nil {
		enc_decipheringkeys := ber.EncodeOctetString([]byte(*v.DecipheringKeys))
		enc_decipheringkeys = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, false, enc_decipheringkeys)
		children = append(children, enc_decipheringkeys...)
	}
	if v.AddLocationEstimate != nil {
		enc_addlocationestimate := ber.EncodeOctetString([]byte(*v.AddLocationEstimate))
		enc_addlocationestimate = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, false, enc_addlocationestimate)
		children = append(children, enc_addlocationestimate...)
	}
	if v.VelocityEstimate != nil {
		enc_velocityestimate := ber.EncodeOctetString([]byte(*v.VelocityEstimate))
		enc_velocityestimate = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, false, enc_velocityestimate)
		children = append(children, enc_velocityestimate...)
	}
	if v.ReferenceNumber != nil {
		enc_referencenumber := ber.EncodeOctetString([]byte(*v.ReferenceNumber))
		enc_referencenumber = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, false, enc_referencenumber)
		children = append(children, enc_referencenumber...)
	}
	if v.HGmlcAddress != nil {
		enc_hgmlcaddress := ber.EncodeOctetString([]byte(*v.HGmlcAddress))
		enc_hgmlcaddress = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 5, false, enc_hgmlcaddress)
		children = append(children, enc_hgmlcaddress...)
	}
	if v.MoLrShortCircuit != nil {
		enc_molrshortcircuit := ber.EncodeNull()
		enc_molrshortcircuit = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 6, false, enc_molrshortcircuit)
		children = append(children, enc_molrshortcircuit...)
	}
	if v.ReportingPLMNList != nil {
		enc_reportingplmnlist, err := v.ReportingPLMNList.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding reportingPLMNList: %w", err)
		}
		enc_reportingplmnlist = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 7, true, enc_reportingplmnlist)
		children = append(children, enc_reportingplmnlist...)
	}
	if v.TimestampOfLocationEstimate != nil {
		enc_timestampoflocationestimate := ber.EncodeOctetString([]byte(*v.TimestampOfLocationEstimate))
		enc_timestampoflocationestimate = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 8, false, enc_timestampoflocationestimate)
		children = append(children, enc_timestampoflocationestimate...)
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

// MarshalDER encodes LCSMOLRRes to DER format.
func (v *LCSMOLRRes) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes LCSMOLRRes from BER/DER format.
func (v *LCSMOLRRes) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding LCSMOLRRes SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "LCSMOLRRes", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode locationEstimate
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
				_, n_locationestimate, rawVal_locationestimate, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding locationEstimate: %w", err)
				}
				tmp_locationestimate := ExtGeographicalInformation(rawVal_locationestimate)
				v.LocationEstimate = &tmp_locationestimate
				offset += n_locationestimate
			}
		}
	}
	// Decode decipheringKeys
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
				_, n_decipheringkeys, rawVal_decipheringkeys, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding decipheringKeys: %w", err)
				}
				tmp_decipheringkeys := DecipheringKeys(rawVal_decipheringkeys)
				v.DecipheringKeys = &tmp_decipheringkeys
				offset += n_decipheringkeys
			}
		}
	}
	// Decode add-LocationEstimate
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2 {
				_, n_addlocationestimate, rawVal_addlocationestimate, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding add-LocationEstimate: %w", err)
				}
				tmp_addlocationestimate := AddGeographicalInformation(rawVal_addlocationestimate)
				v.AddLocationEstimate = &tmp_addlocationestimate
				offset += n_addlocationestimate
			}
		}
	}
	// Decode velocityEstimate
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3 {
				_, n_velocityestimate, rawVal_velocityestimate, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding velocityEstimate: %w", err)
				}
				tmp_velocityestimate := VelocityEstimate(rawVal_velocityestimate)
				v.VelocityEstimate = &tmp_velocityestimate
				offset += n_velocityestimate
			}
		}
	}
	// Decode referenceNumber
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4 {
				_, n_referencenumber, rawVal_referencenumber, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding referenceNumber: %w", err)
				}
				tmp_referencenumber := LCSReferenceNumber(rawVal_referencenumber)
				v.ReferenceNumber = &tmp_referencenumber
				offset += n_referencenumber
			}
		}
	}
	// Decode h-gmlc-address
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 5 {
				_, n_hgmlcaddress, rawVal_hgmlcaddress, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding h-gmlc-address: %w", err)
				}
				tmp_hgmlcaddress := GSNAddress(rawVal_hgmlcaddress)
				v.HGmlcAddress = &tmp_hgmlcaddress
				offset += n_hgmlcaddress
			}
		}
	}
	// Decode mo-lrShortCircuit
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 6 {
				_, n_molrshortcircuit, rawVal_molrshortcircuit, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding mo-lrShortCircuit: %w", err)
				}
				_ = rawVal_molrshortcircuit
				v.MoLrShortCircuit = &struct{}{}
				offset += n_molrshortcircuit
			}
		}
	}
	// Decode reportingPLMNList
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 7 {
				_, n_reportingplmnlist, rawVal_reportingplmnlist, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding reportingPLMNList: %w", err)
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
	// Decode timestampOfLocationEstimate
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 8 {
				_, n_timestampoflocationestimate, rawVal_timestampoflocationestimate, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding timestampOfLocationEstimate: %w", err)
				}
				tmp_timestampoflocationestimate := DateTime(rawVal_timestampoflocationestimate)
				v.TimestampOfLocationEstimate = &tmp_timestampoflocationestimate
				offset += n_timestampoflocationestimate
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "LCSMOLRRes", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes LCSAreaEventRequestArg to BER format.
func (v *LCSAreaEventRequestArg) MarshalBER() ([]byte, error) {
	var children []byte
	enc_referencenumber := ber.EncodeOctetString([]byte(v.ReferenceNumber))
	enc_referencenumber = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, false, enc_referencenumber)
	children = append(children, enc_referencenumber...)
	enc_hgmlcaddress := ber.EncodeOctetString([]byte(v.HGmlcAddress))
	enc_hgmlcaddress = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, false, enc_hgmlcaddress)
	children = append(children, enc_hgmlcaddress...)
	enc_deferredlocationeventtype := ber.EncodeBitString(v.DeferredLocationEventType.Bytes, (8-(v.DeferredLocationEventType.BitLength%8))%8)
	enc_deferredlocationeventtype = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, false, enc_deferredlocationeventtype)
	children = append(children, enc_deferredlocationeventtype...)
	enc_areaeventinfo, err := v.AreaEventInfo.MarshalBER()
	if err != nil {
		return nil, fmt.Errorf("encoding areaEventInfo: %w", err)
	}
	enc_areaeventinfo = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, true, enc_areaeventinfo)
	children = append(children, enc_areaeventinfo...)
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

// MarshalDER encodes LCSAreaEventRequestArg to DER format.
func (v *LCSAreaEventRequestArg) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes LCSAreaEventRequestArg from BER/DER format.
func (v *LCSAreaEventRequestArg) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding LCSAreaEventRequestArg SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "LCSAreaEventRequestArg", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode referenceNumber
	if offset >= len(content) {
		return fmt.Errorf("missing required field referenceNumber")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 0 {
			return fmt.Errorf("expected tag [%s %d] for referenceNumber, got %s", "CONTEXT", 0, reqTag_)
		}
	}
	_, n_referencenumber, rawVal_referencenumber, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding referenceNumber: %w", err)
	}
	v.ReferenceNumber = LCSReferenceNumber(rawVal_referencenumber)
	offset += n_referencenumber
	// Decode h-gmlc-address
	if offset >= len(content) {
		return fmt.Errorf("missing required field h-gmlc-address")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 1 {
			return fmt.Errorf("expected tag [%s %d] for h-gmlc-address, got %s", "CONTEXT", 1, reqTag_)
		}
	}
	_, n_hgmlcaddress, rawVal_hgmlcaddress, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding h-gmlc-address: %w", err)
	}
	v.HGmlcAddress = GSNAddress(rawVal_hgmlcaddress)
	offset += n_hgmlcaddress
	// Decode deferredLocationEventType
	if offset >= len(content) {
		return fmt.Errorf("missing required field deferredLocationEventType")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 3 {
			return fmt.Errorf("expected tag [%s %d] for deferredLocationEventType, got %s", "CONTEXT", 3, reqTag_)
		}
	}
	_, n_deferredlocationeventtype, rawVal_deferredlocationeventtype, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding deferredLocationEventType: %w", err)
	}
	bsBytes_deferredlocationeventtype, bsUnused_deferredlocationeventtype, bsErr := ber.DecodeBitStringValue(rawVal_deferredlocationeventtype)
	if bsErr != nil {
		return fmt.Errorf("decoding deferredLocationEventType: %w", bsErr)
	}
	v.DeferredLocationEventType = runtime.BitString{Bytes: bsBytes_deferredlocationeventtype, BitLength: len(bsBytes_deferredlocationeventtype)*8 - bsUnused_deferredlocationeventtype}
	offset += n_deferredlocationeventtype
	// Decode areaEventInfo
	if offset >= len(content) {
		return fmt.Errorf("missing required field areaEventInfo")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 4 {
			return fmt.Errorf("expected tag [%s %d] for areaEventInfo, got %s", "CONTEXT", 4, reqTag_)
		}
	}
	_, n_areaeventinfo, rawVal_areaeventinfo, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding areaEventInfo: %w", err)
	}
	reconstructed_areaeventinfo := ber.EncodeSequence(rawVal_areaeventinfo)
	if unmErr := v.AreaEventInfo.UnmarshalBER(reconstructed_areaeventinfo); unmErr != nil {
		return fmt.Errorf("decoding areaEventInfo: %w", unmErr)
	}
	offset += n_areaeventinfo
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "LCSAreaEventRequestArg", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes LCSSLMOLRArg to BER format.
func (v *LCSSLMOLRArg) MarshalBER() ([]byte, error) {
	var children []byte
	enc_slmolrtype := ber.EncodeEnumerated(int64(v.SlmolrType))
	enc_slmolrtype = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, false, enc_slmolrtype)
	children = append(children, enc_slmolrtype...)
	if v.LcsQoS != nil {
		enc_lcsqos, err := v.LcsQoS.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding lcs-QoS: %w", err)
		}
		enc_lcsqos = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, true, enc_lcsqos)
		children = append(children, enc_lcsqos...)
	}
	if v.LcsClientExternalID != nil {
		enc_lcsclientexternalid, err := v.LcsClientExternalID.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding lcsClientExternalID: %w", err)
		}
		enc_lcsclientexternalid = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, true, enc_lcsclientexternalid)
		children = append(children, enc_lcsclientexternalid...)
	}
	if v.MlcNumber != nil {
		enc_mlcnumber := ber.EncodeOctetString([]byte(*v.MlcNumber))
		enc_mlcnumber = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, false, enc_mlcnumber)
		children = append(children, enc_mlcnumber...)
	}
	if v.SupportedGADShapes != nil {
		enc_supportedgadshapes := ber.EncodeBitString(v.SupportedGADShapes.Bytes, (8-(v.SupportedGADShapes.BitLength%8))%8)
		enc_supportedgadshapes = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, false, enc_supportedgadshapes)
		children = append(children, enc_supportedgadshapes...)
	}
	if v.LcsServiceTypeID != nil {
		enc_lcsservicetypeid := ber.EncodeInteger(int64(*v.LcsServiceTypeID))
		enc_lcsservicetypeid = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 5, false, enc_lcsservicetypeid)
		children = append(children, enc_lcsservicetypeid...)
	}
	if v.PseudonymIndicator != nil {
		enc_pseudonymindicator := ber.EncodeNull()
		enc_pseudonymindicator = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 7, false, enc_pseudonymindicator)
		children = append(children, enc_pseudonymindicator...)
	}
	if v.HGmlcAddress != nil {
		enc_hgmlcaddress := ber.EncodeOctetString([]byte(*v.HGmlcAddress))
		enc_hgmlcaddress = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 8, false, enc_hgmlcaddress)
		children = append(children, enc_hgmlcaddress...)
	}
	if v.CalculationAssistIndicator != nil {
		var enc_calculationassistindicator []byte
		if v.CalculationAssistIndicatorRaw_ != 0 {
			enc_calculationassistindicator = ber.EncodeBooleanRaw(v.CalculationAssistIndicatorRaw_)
		} else {
			enc_calculationassistindicator = ber.EncodeBoolean(*v.CalculationAssistIndicator)
		}
		enc_calculationassistindicator = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 9, false, enc_calculationassistindicator)
		children = append(children, enc_calculationassistindicator...)
	}
	if v.PreferredRangingResult != nil {
		enc_preferredrangingresult, err := v.PreferredRangingResult.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding preferredRangingResult: %w", err)
		}
		enc_preferredrangingresult = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 10, true, enc_preferredrangingresult)
		children = append(children, enc_preferredrangingresult...)
	}
	if v.RelatedUEInfo != nil {
		enc_relatedueinfo, err := MarshalBERRelatedUEInfo(v.RelatedUEInfo)
		if err != nil {
			return nil, fmt.Errorf("encoding relatedUEInfo: %w", err)
		}
		if v.RelatedUEInfoIndef_ {
			// Strip the outer SEQUENCE tag from marshalBER output to get raw children.
			_, _, seqContent_, tlvErr_ := ber.DecodeTLV(enc_relatedueinfo)
			if tlvErr_ != nil {
				return nil, tlvErr_
			}
			enc_relatedueinfo = ber.EncodeConstructedIndefinite(tag.Tag{Class: tag.ClassContextSpecific, Number: 11}, seqContent_)
		} else {
			enc_relatedueinfo = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 11, true, enc_relatedueinfo)
		}
		children = append(children, enc_relatedueinfo...)
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

// MarshalDER encodes LCSSLMOLRArg to DER format.
func (v *LCSSLMOLRArg) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// ITU-T X.690 (02/2021) Section 10.1 requires DER length forms to be definite.
	derValue := *v
	derValue.RelatedUEInfoIndef_ = false
	v = &derValue
	return v.MarshalBER()
}

// UnmarshalBER decodes LCSSLMOLRArg from BER/DER format.
func (v *LCSSLMOLRArg) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding LCSSLMOLRArg SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "LCSSLMOLRArg", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode slmolr-Type
	if offset >= len(content) {
		return fmt.Errorf("missing required field slmolr-Type")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 0 {
			return fmt.Errorf("expected tag [%s %d] for slmolr-Type, got %s", "CONTEXT", 0, reqTag_)
		}
	}
	_, n_slmolrtype, rawVal_slmolrtype, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding slmolr-Type: %w", err)
	}
	decVal_slmolrtype, intErr := ber.DecodeIntegerValue(rawVal_slmolrtype)
	if intErr != nil {
		return fmt.Errorf("decoding slmolr-Type: %w", intErr)
	}
	v.SlmolrType = SLMOLRType(decVal_slmolrtype)
	offset += n_slmolrtype
	// Decode lcs-QoS
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
				_, n_lcsqos, rawVal_lcsqos, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding lcs-QoS: %w", err)
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
	// Decode lcsClientExternalID
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2 {
				_, n_lcsclientexternalid, rawVal_lcsclientexternalid, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding lcsClientExternalID: %w", err)
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
	// Decode mlc-Number
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3 {
				_, n_mlcnumber, rawVal_mlcnumber, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding mlc-Number: %w", err)
				}
				tmp_mlcnumber := ISDNAddressString(rawVal_mlcnumber)
				v.MlcNumber = &tmp_mlcnumber
				offset += n_mlcnumber
			}
		}
	}
	// Decode supportedGADShapes
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4 {
				_, n_supportedgadshapes, rawVal_supportedgadshapes, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding supportedGADShapes: %w", err)
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
	// Decode lcsServiceTypeID
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 5 {
				_, n_lcsservicetypeid, rawVal_lcsservicetypeid, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding lcsServiceTypeID: %w", err)
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
	// Decode pseudonymIndicator
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 7 {
				_, n_pseudonymindicator, rawVal_pseudonymindicator, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding pseudonymIndicator: %w", err)
				}
				_ = rawVal_pseudonymindicator
				v.PseudonymIndicator = &struct{}{}
				offset += n_pseudonymindicator
			}
		}
	}
	// Decode h-gmlc-address
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 8 {
				_, n_hgmlcaddress, rawVal_hgmlcaddress, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding h-gmlc-address: %w", err)
				}
				tmp_hgmlcaddress := GSNAddress(rawVal_hgmlcaddress)
				v.HGmlcAddress = &tmp_hgmlcaddress
				offset += n_hgmlcaddress
			}
		}
	}
	// Decode calculationAssistIndicator
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 9 {
				_, n_calculationassistindicator, rawVal_calculationassistindicator, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding calculationAssistIndicator: %w", err)
				}
				decVal_calculationassistindicator, boolErr := ber.DecodeBooleanValue(rawVal_calculationassistindicator)
				if boolErr != nil {
					return fmt.Errorf("decoding calculationAssistIndicator: %w", boolErr)
				}
				if len(rawVal_calculationassistindicator) == 1 {
					v.CalculationAssistIndicatorRaw_ = rawVal_calculationassistindicator[0]
				}
				v.CalculationAssistIndicator = &decVal_calculationassistindicator
				offset += n_calculationassistindicator
			}
		}
	}
	// Decode preferredRangingResult
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 10 {
				_, n_preferredrangingresult, rawVal_preferredrangingresult, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding preferredRangingResult: %w", err)
				}
				reconstructed_preferredrangingresult := ber.EncodeSequence(rawVal_preferredrangingresult)
				var dec_preferredrangingresult PreferredRangingResult
				if unmErr := dec_preferredrangingresult.UnmarshalBER(reconstructed_preferredrangingresult); unmErr != nil {
					return fmt.Errorf("decoding preferredRangingResult: %w", unmErr)
				}
				v.PreferredRangingResult = &dec_preferredrangingresult
				offset += n_preferredrangingresult
			}
		}
	}
	// Decode relatedUEInfo
	v.RelatedUEInfoIndef_ = false
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 11 {
				_, n_relatedueinfo, rawVal_relatedueinfo, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding relatedUEInfo: %w", err)
				}
				reconstructed_relatedueinfo := ber.EncodeSequence(rawVal_relatedueinfo)
				dec_relatedueinfo, unmErr := UnmarshalBERRelatedUEInfo(reconstructed_relatedueinfo)
				if unmErr != nil {
					return fmt.Errorf("decoding relatedUEInfo: %w", unmErr)
				}
				v.RelatedUEInfo = dec_relatedueinfo
				{
					_, tagSz_, _ := ber.DecodeTag(content[offset:])
					if offset+tagSz_ < len(content) && content[offset+tagSz_] == 0x80 {
						v.RelatedUEInfoIndef_ = true
					}
				}
				offset += n_relatedueinfo
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "LCSSLMOLRArg", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes PreferredRangingResult to BER format.
func (v *PreferredRangingResult) MarshalBER() ([]byte, error) {
	var children []byte
	if v.AbsoluteLocationIndicator != nil {
		var enc_absolutelocationindicator []byte
		if v.AbsoluteLocationIndicatorRaw_ != 0 {
			enc_absolutelocationindicator = ber.EncodeBooleanRaw(v.AbsoluteLocationIndicatorRaw_)
		} else {
			enc_absolutelocationindicator = ber.EncodeBoolean(*v.AbsoluteLocationIndicator)
		}
		enc_absolutelocationindicator = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, false, enc_absolutelocationindicator)
		children = append(children, enc_absolutelocationindicator...)
	}
	if v.AbsoluteVelocityIndicator != nil {
		var enc_absolutevelocityindicator []byte
		if v.AbsoluteVelocityIndicatorRaw_ != 0 {
			enc_absolutevelocityindicator = ber.EncodeBooleanRaw(v.AbsoluteVelocityIndicatorRaw_)
		} else {
			enc_absolutevelocityindicator = ber.EncodeBoolean(*v.AbsoluteVelocityIndicator)
		}
		enc_absolutevelocityindicator = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, false, enc_absolutevelocityindicator)
		children = append(children, enc_absolutevelocityindicator...)
	}
	if v.RelativeLocationIndicator != nil {
		var enc_relativelocationindicator []byte
		if v.RelativeLocationIndicatorRaw_ != 0 {
			enc_relativelocationindicator = ber.EncodeBooleanRaw(v.RelativeLocationIndicatorRaw_)
		} else {
			enc_relativelocationindicator = ber.EncodeBoolean(*v.RelativeLocationIndicator)
		}
		enc_relativelocationindicator = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, false, enc_relativelocationindicator)
		children = append(children, enc_relativelocationindicator...)
	}
	if v.RangeDirection != nil {
		var enc_rangedirection []byte
		if v.RangeDirectionRaw_ != 0 {
			enc_rangedirection = ber.EncodeBooleanRaw(v.RangeDirectionRaw_)
		} else {
			enc_rangedirection = ber.EncodeBoolean(*v.RangeDirection)
		}
		enc_rangedirection = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, false, enc_rangedirection)
		children = append(children, enc_rangedirection...)
	}
	if v.RelativeVelocityIndicator != nil {
		var enc_relativevelocityindicator []byte
		if v.RelativeVelocityIndicatorRaw_ != 0 {
			enc_relativevelocityindicator = ber.EncodeBooleanRaw(v.RelativeVelocityIndicatorRaw_)
		} else {
			enc_relativevelocityindicator = ber.EncodeBoolean(*v.RelativeVelocityIndicator)
		}
		enc_relativevelocityindicator = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, false, enc_relativevelocityindicator)
		children = append(children, enc_relativevelocityindicator...)
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

// MarshalDER encodes PreferredRangingResult to DER format.
func (v *PreferredRangingResult) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes PreferredRangingResult from BER/DER format.
func (v *PreferredRangingResult) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding PreferredRangingResult SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "PreferredRangingResult", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode absoluteLocationIndicator
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
				_, n_absolutelocationindicator, rawVal_absolutelocationindicator, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding absoluteLocationIndicator: %w", err)
				}
				decVal_absolutelocationindicator, boolErr := ber.DecodeBooleanValue(rawVal_absolutelocationindicator)
				if boolErr != nil {
					return fmt.Errorf("decoding absoluteLocationIndicator: %w", boolErr)
				}
				if len(rawVal_absolutelocationindicator) == 1 {
					v.AbsoluteLocationIndicatorRaw_ = rawVal_absolutelocationindicator[0]
				}
				v.AbsoluteLocationIndicator = &decVal_absolutelocationindicator
				offset += n_absolutelocationindicator
			}
		}
	}
	// Decode absoluteVelocityIndicator
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
				_, n_absolutevelocityindicator, rawVal_absolutevelocityindicator, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding absoluteVelocityIndicator: %w", err)
				}
				decVal_absolutevelocityindicator, boolErr := ber.DecodeBooleanValue(rawVal_absolutevelocityindicator)
				if boolErr != nil {
					return fmt.Errorf("decoding absoluteVelocityIndicator: %w", boolErr)
				}
				if len(rawVal_absolutevelocityindicator) == 1 {
					v.AbsoluteVelocityIndicatorRaw_ = rawVal_absolutevelocityindicator[0]
				}
				v.AbsoluteVelocityIndicator = &decVal_absolutevelocityindicator
				offset += n_absolutevelocityindicator
			}
		}
	}
	// Decode relativeLocationIndicator
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2 {
				_, n_relativelocationindicator, rawVal_relativelocationindicator, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding relativeLocationIndicator: %w", err)
				}
				decVal_relativelocationindicator, boolErr := ber.DecodeBooleanValue(rawVal_relativelocationindicator)
				if boolErr != nil {
					return fmt.Errorf("decoding relativeLocationIndicator: %w", boolErr)
				}
				if len(rawVal_relativelocationindicator) == 1 {
					v.RelativeLocationIndicatorRaw_ = rawVal_relativelocationindicator[0]
				}
				v.RelativeLocationIndicator = &decVal_relativelocationindicator
				offset += n_relativelocationindicator
			}
		}
	}
	// Decode rangeDirection
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3 {
				_, n_rangedirection, rawVal_rangedirection, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding rangeDirection: %w", err)
				}
				decVal_rangedirection, boolErr := ber.DecodeBooleanValue(rawVal_rangedirection)
				if boolErr != nil {
					return fmt.Errorf("decoding rangeDirection: %w", boolErr)
				}
				if len(rawVal_rangedirection) == 1 {
					v.RangeDirectionRaw_ = rawVal_rangedirection[0]
				}
				v.RangeDirection = &decVal_rangedirection
				offset += n_rangedirection
			}
		}
	}
	// Decode relativeVelocityIndicator
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4 {
				_, n_relativevelocityindicator, rawVal_relativevelocityindicator, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding relativeVelocityIndicator: %w", err)
				}
				decVal_relativevelocityindicator, boolErr := ber.DecodeBooleanValue(rawVal_relativevelocityindicator)
				if boolErr != nil {
					return fmt.Errorf("decoding relativeVelocityIndicator: %w", boolErr)
				}
				if len(rawVal_relativevelocityindicator) == 1 {
					v.RelativeVelocityIndicatorRaw_ = rawVal_relativevelocityindicator[0]
				}
				v.RelativeVelocityIndicator = &decVal_relativevelocityindicator
				offset += n_relativevelocityindicator
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "PreferredRangingResult", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBERRelatedUEInfo encodes a RelatedUEInfo list to BER.
func MarshalBERRelatedUEInfo(list RelatedUEInfo) ([]byte, error) {
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

// UnmarshalBERRelatedUEInfo decodes a RelatedUEInfo list from BER.
func UnmarshalBERRelatedUEInfo(data []byte) (RelatedUEInfo, error) {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return nil, fmt.Errorf("decoding RelatedUEInfo: %w", err)
	}
	if total != len(data) {
		return nil, &ber.DecodeError{Offset: total, TypeName: "RelatedUEInfo", Cause: ber.ErrExtraData}
	}
	var result RelatedUEInfo
	offset := 0
	for offset < len(content) {
		var elem RangingUEInfo
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

// MarshalBER encodes RangingUEInfo to BER format.
func (v *RangingUEInfo) MarshalBER() ([]byte, error) {
	var children []byte
	enc_applicationlayerid := ber.EncodeOctetString(v.ApplicationLayerID)
	enc_applicationlayerid = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, false, enc_applicationlayerid)
	children = append(children, enc_applicationlayerid...)
	if v.RangingRole != nil {
		enc_rangingrole := ber.EncodeEnumerated(int64(*v.RangingRole))
		enc_rangingrole = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, false, enc_rangingrole)
		children = append(children, enc_rangingrole...)
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

// MarshalDER encodes RangingUEInfo to DER format.
func (v *RangingUEInfo) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes RangingUEInfo from BER/DER format.
func (v *RangingUEInfo) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding RangingUEInfo SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "RangingUEInfo", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode applicationLayerID
	if offset >= len(content) {
		return fmt.Errorf("missing required field applicationLayerID")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 0 {
			return fmt.Errorf("expected tag [%s %d] for applicationLayerID, got %s", "CONTEXT", 0, reqTag_)
		}
	}
	_, n_applicationlayerid, rawVal_applicationlayerid, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding applicationLayerID: %w", err)
	}
	v.ApplicationLayerID = rawVal_applicationlayerid
	offset += n_applicationlayerid
	// Decode rangingRole
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
				_, n_rangingrole, rawVal_rangingrole, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding rangingRole: %w", err)
				}
				decVal_rangingrole, intErr := ber.DecodeIntegerValue(rawVal_rangingrole)
				if intErr != nil {
					return fmt.Errorf("decoding rangingRole: %w", intErr)
				}
				tmp_rangingrole := RangingRole(decVal_rangingrole)
				v.RangingRole = &tmp_rangingrole
				offset += n_rangingrole
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "RangingUEInfo", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes LCSSLMOLRRes to BER format.
func (v *LCSSLMOLRRes) MarshalBER() ([]byte, error) {
	var children []byte
	if v.AbsoluteLocation != nil {
		enc_absolutelocation := ber.EncodeOctetString([]byte(*v.AbsoluteLocation))
		enc_absolutelocation = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, false, enc_absolutelocation)
		children = append(children, enc_absolutelocation...)
	}
	if v.AbsoluteVelocity != nil {
		enc_absolutevelocity := ber.EncodeOctetString([]byte(*v.AbsoluteVelocity))
		enc_absolutevelocity = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, false, enc_absolutevelocity)
		children = append(children, enc_absolutevelocity...)
	}
	if v.RelativeResult != nil {
		enc_relativeresult, err := MarshalBERRelativeResult(v.RelativeResult)
		if err != nil {
			return nil, fmt.Errorf("encoding relativeResult: %w", err)
		}
		if v.RelativeResultIndef_ {
			// Strip the outer SEQUENCE tag from marshalBER output to get raw children.
			_, _, seqContent_, tlvErr_ := ber.DecodeTLV(enc_relativeresult)
			if tlvErr_ != nil {
				return nil, tlvErr_
			}
			enc_relativeresult = ber.EncodeConstructedIndefinite(tag.Tag{Class: tag.ClassContextSpecific, Number: 2}, seqContent_)
		} else {
			enc_relativeresult = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, true, enc_relativeresult)
		}
		children = append(children, enc_relativeresult...)
	}
	if v.UeOnlyRSLPosAllowed != nil {
		enc_ueonlyrslposallowed := ber.EncodeInteger(int64(*v.UeOnlyRSLPosAllowed))
		enc_ueonlyrslposallowed = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, false, enc_ueonlyrslposallowed)
		children = append(children, enc_ueonlyrslposallowed...)
	}
	if v.Timestamp != nil {
		enc_timestamp := ber.EncodeOctetString([]byte(*v.Timestamp))
		enc_timestamp = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 5, false, enc_timestamp)
		children = append(children, enc_timestamp...)
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

// MarshalDER encodes LCSSLMOLRRes to DER format.
func (v *LCSSLMOLRRes) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// ITU-T X.690 (02/2021) Section 10.1 requires DER length forms to be definite.
	derValue := *v
	derValue.RelativeResultIndef_ = false
	v = &derValue
	return v.MarshalBER()
}

// UnmarshalBER decodes LCSSLMOLRRes from BER/DER format.
func (v *LCSSLMOLRRes) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding LCSSLMOLRRes SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "LCSSLMOLRRes", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode absoluteLocation
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
				_, n_absolutelocation, rawVal_absolutelocation, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding absoluteLocation: %w", err)
				}
				tmp_absolutelocation := ExtGeographicalInformation(rawVal_absolutelocation)
				v.AbsoluteLocation = &tmp_absolutelocation
				offset += n_absolutelocation
			}
		}
	}
	// Decode absoluteVelocity
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
				_, n_absolutevelocity, rawVal_absolutevelocity, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding absoluteVelocity: %w", err)
				}
				tmp_absolutevelocity := VelocityEstimate(rawVal_absolutevelocity)
				v.AbsoluteVelocity = &tmp_absolutevelocity
				offset += n_absolutevelocity
			}
		}
	}
	// Decode relativeResult
	v.RelativeResultIndef_ = false
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2 {
				_, n_relativeresult, rawVal_relativeresult, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding relativeResult: %w", err)
				}
				reconstructed_relativeresult := ber.EncodeSequence(rawVal_relativeresult)
				dec_relativeresult, unmErr := UnmarshalBERRelativeResult(reconstructed_relativeresult)
				if unmErr != nil {
					return fmt.Errorf("decoding relativeResult: %w", unmErr)
				}
				v.RelativeResult = dec_relativeresult
				{
					_, tagSz_, _ := ber.DecodeTag(content[offset:])
					if offset+tagSz_ < len(content) && content[offset+tagSz_] == 0x80 {
						v.RelativeResultIndef_ = true
					}
				}
				offset += n_relativeresult
			}
		}
	}
	// Decode ueOnlyRSLPosAllowed
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4 {
				_, n_ueonlyrslposallowed, rawVal_ueonlyrslposallowed, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding ueOnlyRSLPosAllowed: %w", err)
				}
				decVal_ueonlyrslposallowed, intErr := ber.DecodeIntegerValue(rawVal_ueonlyrslposallowed)
				if intErr != nil {
					return fmt.Errorf("decoding ueOnlyRSLPosAllowed: %w", intErr)
				}
				tmp_ueonlyrslposallowed := Duration(decVal_ueonlyrslposallowed)
				v.UeOnlyRSLPosAllowed = &tmp_ueonlyrslposallowed
				offset += n_ueonlyrslposallowed
			}
		}
	}
	// Decode timestamp
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 5 {
				_, n_timestamp, rawVal_timestamp, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding timestamp: %w", err)
				}
				tmp_timestamp := DateTime(rawVal_timestamp)
				v.Timestamp = &tmp_timestamp
				offset += n_timestamp
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "LCSSLMOLRRes", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBERRelativeResult encodes a RelativeResult list to BER.
func MarshalBERRelativeResult(list RelativeResult) ([]byte, error) {
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

// UnmarshalBERRelativeResult decodes a RelativeResult list from BER.
func UnmarshalBERRelativeResult(data []byte) (RelativeResult, error) {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return nil, fmt.Errorf("decoding RelativeResult: %w", err)
	}
	if total != len(data) {
		return nil, &ber.DecodeError{Offset: total, TypeName: "RelativeResult", Cause: ber.ErrExtraData}
	}
	var result RelativeResult
	offset := 0
	for offset < len(content) {
		var elem SingleRelativeResult
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

// MarshalBER encodes SingleRelativeResult to BER format.
func (v *SingleRelativeResult) MarshalBER() ([]byte, error) {
	var children []byte
	if v.RelatedUEInfo != nil {
		enc_relatedueinfo, err := MarshalBERRelatedUEInfo(v.RelatedUEInfo)
		if err != nil {
			return nil, fmt.Errorf("encoding relatedUEInfo: %w", err)
		}
		if v.RelatedUEInfoIndef_ {
			// Strip the outer SEQUENCE tag from marshalBER output to get raw children.
			_, _, seqContent_, tlvErr_ := ber.DecodeTLV(enc_relatedueinfo)
			if tlvErr_ != nil {
				return nil, tlvErr_
			}
			enc_relatedueinfo = ber.EncodeConstructedIndefinite(tag.Tag{Class: tag.ClassContextSpecific, Number: 0}, seqContent_)
		} else {
			enc_relatedueinfo = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, true, enc_relatedueinfo)
		}
		children = append(children, enc_relatedueinfo...)
	}
	if v.RelativeLocation != nil {
		enc_relativelocation, err := v.RelativeLocation.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding relativeLocation: %w", err)
		}
		enc_relativelocation = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, true, enc_relativelocation)
		children = append(children, enc_relativelocation...)
	}
	if v.RangeDirection != nil {
		enc_rangedirection, err := v.RangeDirection.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding rangeDirection: %w", err)
		}
		enc_rangedirection = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, true, enc_rangedirection)
		children = append(children, enc_rangedirection...)
	}
	if v.RelativeVelocity != nil {
		enc_relativevelocity := ber.EncodeOctetString([]byte(*v.RelativeVelocity))
		enc_relativevelocity = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, false, enc_relativevelocity)
		children = append(children, enc_relativevelocity...)
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

// MarshalDER encodes SingleRelativeResult to DER format.
func (v *SingleRelativeResult) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// ITU-T X.690 (02/2021) Section 10.1 requires DER length forms to be definite.
	derValue := *v
	derValue.RelatedUEInfoIndef_ = false
	v = &derValue
	return v.MarshalBER()
}

// UnmarshalBER decodes SingleRelativeResult from BER/DER format.
func (v *SingleRelativeResult) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding SingleRelativeResult SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "SingleRelativeResult", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode relatedUEInfo
	v.RelatedUEInfoIndef_ = false
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
				_, n_relatedueinfo, rawVal_relatedueinfo, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding relatedUEInfo: %w", err)
				}
				reconstructed_relatedueinfo := ber.EncodeSequence(rawVal_relatedueinfo)
				dec_relatedueinfo, unmErr := UnmarshalBERRelatedUEInfo(reconstructed_relatedueinfo)
				if unmErr != nil {
					return fmt.Errorf("decoding relatedUEInfo: %w", unmErr)
				}
				v.RelatedUEInfo = dec_relatedueinfo
				{
					_, tagSz_, _ := ber.DecodeTag(content[offset:])
					if offset+tagSz_ < len(content) && content[offset+tagSz_] == 0x80 {
						v.RelatedUEInfoIndef_ = true
					}
				}
				offset += n_relatedueinfo
			}
		}
	}
	// Decode relativeLocation
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
				_, n_relativelocation, rawVal_relativelocation, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding relativeLocation: %w", err)
				}
				reconstructed_relativelocation := ber.EncodeSequence(rawVal_relativelocation)
				var dec_relativelocation RelativeLocationCoordinates
				if unmErr := dec_relativelocation.UnmarshalBER(reconstructed_relativelocation); unmErr != nil {
					return fmt.Errorf("decoding relativeLocation: %w", unmErr)
				}
				v.RelativeLocation = &dec_relativelocation
				offset += n_relativelocation
			}
		}
	}
	// Decode rangeDirection
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2 {
				_, n_rangedirection, rawVal_rangedirection, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding rangeDirection: %w", err)
				}
				reconstructed_rangedirection := ber.EncodeSequence(rawVal_rangedirection)
				var dec_rangedirection RangeDirection
				if unmErr := dec_rangedirection.UnmarshalBER(reconstructed_rangedirection); unmErr != nil {
					return fmt.Errorf("decoding rangeDirection: %w", unmErr)
				}
				v.RangeDirection = &dec_rangedirection
				offset += n_rangedirection
			}
		}
	}
	// Decode relativeVelocity
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3 {
				_, n_relativevelocity, rawVal_relativevelocity, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding relativeVelocity: %w", err)
				}
				tmp_relativevelocity := VelocityEstimate(rawVal_relativevelocity)
				v.RelativeVelocity = &tmp_relativevelocity
				offset += n_relativevelocity
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "SingleRelativeResult", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes RelativeLocationCoordinates to BER format.
func (v *RelativeLocationCoordinates) MarshalBER() ([]byte, error) {
	var children []byte
	if v.Relative2DLocationWithUncertaintyEllipse != nil {
		enc_relative2dlocationwithuncertaintyellipse, err := v.Relative2DLocationWithUncertaintyEllipse.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding relative2D-LocationWithUncertaintyEllipse: %w", err)
		}
		enc_relative2dlocationwithuncertaintyellipse = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, true, enc_relative2dlocationwithuncertaintyellipse)
		children = append(children, enc_relative2dlocationwithuncertaintyellipse...)
	}
	if v.Relative3DLocationWithUncertaintyEllipsoid != nil {
		enc_relative3dlocationwithuncertaintyellipsoid, err := v.Relative3DLocationWithUncertaintyEllipsoid.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding relative3D-LocationWithUncertaintyEllipsoid: %w", err)
		}
		enc_relative3dlocationwithuncertaintyellipsoid = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, true, enc_relative3dlocationwithuncertaintyellipsoid)
		children = append(children, enc_relative3dlocationwithuncertaintyellipsoid...)
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

// MarshalDER encodes RelativeLocationCoordinates to DER format.
func (v *RelativeLocationCoordinates) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes RelativeLocationCoordinates from BER/DER format.
func (v *RelativeLocationCoordinates) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding RelativeLocationCoordinates SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "RelativeLocationCoordinates", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode relative2D-LocationWithUncertaintyEllipse
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
				_, n_relative2dlocationwithuncertaintyellipse, rawVal_relative2dlocationwithuncertaintyellipse, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding relative2D-LocationWithUncertaintyEllipse: %w", err)
				}
				reconstructed_relative2dlocationwithuncertaintyellipse := ber.EncodeSequence(rawVal_relative2dlocationwithuncertaintyellipse)
				var dec_relative2dlocationwithuncertaintyellipse Relative2DLocationWithUncertaintyEllipse
				if unmErr := dec_relative2dlocationwithuncertaintyellipse.UnmarshalBER(reconstructed_relative2dlocationwithuncertaintyellipse); unmErr != nil {
					return fmt.Errorf("decoding relative2D-LocationWithUncertaintyEllipse: %w", unmErr)
				}
				v.Relative2DLocationWithUncertaintyEllipse = &dec_relative2dlocationwithuncertaintyellipse
				offset += n_relative2dlocationwithuncertaintyellipse
			}
		}
	}
	// Decode relative3D-LocationWithUncertaintyEllipsoid
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
				_, n_relative3dlocationwithuncertaintyellipsoid, rawVal_relative3dlocationwithuncertaintyellipsoid, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding relative3D-LocationWithUncertaintyEllipsoid: %w", err)
				}
				reconstructed_relative3dlocationwithuncertaintyellipsoid := ber.EncodeSequence(rawVal_relative3dlocationwithuncertaintyellipsoid)
				var dec_relative3dlocationwithuncertaintyellipsoid Relative3DLocationWithUncertaintyEllipsoid
				if unmErr := dec_relative3dlocationwithuncertaintyellipsoid.UnmarshalBER(reconstructed_relative3dlocationwithuncertaintyellipsoid); unmErr != nil {
					return fmt.Errorf("decoding relative3D-LocationWithUncertaintyEllipsoid: %w", unmErr)
				}
				v.Relative3DLocationWithUncertaintyEllipsoid = &dec_relative3dlocationwithuncertaintyellipsoid
				offset += n_relative3dlocationwithuncertaintyellipsoid
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "RelativeLocationCoordinates", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes Relative2DLocationWithUncertaintyEllipse to BER format.
func (v *Relative2DLocationWithUncertaintyEllipse) MarshalBER() ([]byte, error) {
	var children []byte
	enc_xcoordinates := ber.EncodeInteger(int64(v.XCoordinates))
	enc_xcoordinates = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, false, enc_xcoordinates)
	children = append(children, enc_xcoordinates...)
	enc_ycoordinates := ber.EncodeInteger(int64(v.YCoordinates))
	enc_ycoordinates = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, false, enc_ycoordinates)
	children = append(children, enc_ycoordinates...)
	enc_uncertaintysemimajor := ber.EncodeInteger(int64(v.UncertaintySemiMajor))
	enc_uncertaintysemimajor = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, false, enc_uncertaintysemimajor)
	children = append(children, enc_uncertaintysemimajor...)
	enc_uncertaintysemiminor := ber.EncodeInteger(int64(v.UncertaintySemiMinor))
	enc_uncertaintysemiminor = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, false, enc_uncertaintysemiminor)
	children = append(children, enc_uncertaintysemiminor...)
	enc_orientationmajoraxis := ber.EncodeInteger(int64(v.OrientationMajorAxis))
	enc_orientationmajoraxis = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, false, enc_orientationmajoraxis)
	children = append(children, enc_orientationmajoraxis...)
	if v.Confidence != nil {
		enc_confidence := ber.EncodeInteger(int64(*v.Confidence))
		enc_confidence = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 5, false, enc_confidence)
		children = append(children, enc_confidence...)
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

// MarshalDER encodes Relative2DLocationWithUncertaintyEllipse to DER format.
func (v *Relative2DLocationWithUncertaintyEllipse) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes Relative2DLocationWithUncertaintyEllipse from BER/DER format.
func (v *Relative2DLocationWithUncertaintyEllipse) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding Relative2DLocationWithUncertaintyEllipse SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "Relative2DLocationWithUncertaintyEllipse", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode xCoordinates
	if offset >= len(content) {
		return fmt.Errorf("missing required field xCoordinates")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 0 {
			return fmt.Errorf("expected tag [%s %d] for xCoordinates, got %s", "CONTEXT", 0, reqTag_)
		}
	}
	_, n_xcoordinates, rawVal_xcoordinates, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding xCoordinates: %w", err)
	}
	decVal_xcoordinates, intErr := ber.DecodeIntegerValue(rawVal_xcoordinates)
	if intErr != nil {
		return fmt.Errorf("decoding xCoordinates: %w", intErr)
	}
	v.XCoordinates = RangeXYCoordinates(decVal_xcoordinates)
	offset += n_xcoordinates
	// Decode yCoordinates
	if offset >= len(content) {
		return fmt.Errorf("missing required field yCoordinates")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 1 {
			return fmt.Errorf("expected tag [%s %d] for yCoordinates, got %s", "CONTEXT", 1, reqTag_)
		}
	}
	_, n_ycoordinates, rawVal_ycoordinates, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding yCoordinates: %w", err)
	}
	decVal_ycoordinates, intErr := ber.DecodeIntegerValue(rawVal_ycoordinates)
	if intErr != nil {
		return fmt.Errorf("decoding yCoordinates: %w", intErr)
	}
	v.YCoordinates = RangeXYCoordinates(decVal_ycoordinates)
	offset += n_ycoordinates
	// Decode uncertaintySemiMajor
	if offset >= len(content) {
		return fmt.Errorf("missing required field uncertaintySemiMajor")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 2 {
			return fmt.Errorf("expected tag [%s %d] for uncertaintySemiMajor, got %s", "CONTEXT", 2, reqTag_)
		}
	}
	_, n_uncertaintysemimajor, rawVal_uncertaintysemimajor, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding uncertaintySemiMajor: %w", err)
	}
	decVal_uncertaintysemimajor, intErr := ber.DecodeIntegerValue(rawVal_uncertaintysemimajor)
	if intErr != nil {
		return fmt.Errorf("decoding uncertaintySemiMajor: %w", intErr)
	}
	v.UncertaintySemiMajor = Uncertainty(decVal_uncertaintysemimajor)
	offset += n_uncertaintysemimajor
	// Decode uncertaintySemiMinor
	if offset >= len(content) {
		return fmt.Errorf("missing required field uncertaintySemiMinor")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 3 {
			return fmt.Errorf("expected tag [%s %d] for uncertaintySemiMinor, got %s", "CONTEXT", 3, reqTag_)
		}
	}
	_, n_uncertaintysemiminor, rawVal_uncertaintysemiminor, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding uncertaintySemiMinor: %w", err)
	}
	decVal_uncertaintysemiminor, intErr := ber.DecodeIntegerValue(rawVal_uncertaintysemiminor)
	if intErr != nil {
		return fmt.Errorf("decoding uncertaintySemiMinor: %w", intErr)
	}
	v.UncertaintySemiMinor = Uncertainty(decVal_uncertaintysemiminor)
	offset += n_uncertaintysemiminor
	// Decode orientationMajorAxis
	if offset >= len(content) {
		return fmt.Errorf("missing required field orientationMajorAxis")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 4 {
			return fmt.Errorf("expected tag [%s %d] for orientationMajorAxis, got %s", "CONTEXT", 4, reqTag_)
		}
	}
	_, n_orientationmajoraxis, rawVal_orientationmajoraxis, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding orientationMajorAxis: %w", err)
	}
	decVal_orientationmajoraxis, intErr := ber.DecodeIntegerValue(rawVal_orientationmajoraxis)
	if intErr != nil {
		return fmt.Errorf("decoding orientationMajorAxis: %w", intErr)
	}
	v.OrientationMajorAxis = OrientationMajorAxis(decVal_orientationmajoraxis)
	offset += n_orientationmajoraxis
	// Decode confidence
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 5 {
				_, n_confidence, rawVal_confidence, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding confidence: %w", err)
				}
				decVal_confidence, intErr := ber.DecodeIntegerValue(rawVal_confidence)
				if intErr != nil {
					return fmt.Errorf("decoding confidence: %w", intErr)
				}
				tmp_confidence := Confidence(decVal_confidence)
				v.Confidence = &tmp_confidence
				offset += n_confidence
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "Relative2DLocationWithUncertaintyEllipse", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes Relative3DLocationWithUncertaintyEllipsoid to BER format.
func (v *Relative3DLocationWithUncertaintyEllipsoid) MarshalBER() ([]byte, error) {
	var children []byte
	enc_xcoordinates := ber.EncodeInteger(int64(v.XCoordinates))
	enc_xcoordinates = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, false, enc_xcoordinates)
	children = append(children, enc_xcoordinates...)
	enc_ycoordinates := ber.EncodeInteger(int64(v.YCoordinates))
	enc_ycoordinates = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, false, enc_ycoordinates)
	children = append(children, enc_ycoordinates...)
	enc_zcoordinates := ber.EncodeInteger(int64(v.ZCoordinates))
	enc_zcoordinates = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, false, enc_zcoordinates)
	children = append(children, enc_zcoordinates...)
	enc_uncertaintysemimajor := ber.EncodeInteger(int64(v.UncertaintySemiMajor))
	enc_uncertaintysemimajor = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, false, enc_uncertaintysemimajor)
	children = append(children, enc_uncertaintysemimajor...)
	enc_uncertaintysemiminor := ber.EncodeInteger(int64(v.UncertaintySemiMinor))
	enc_uncertaintysemiminor = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, false, enc_uncertaintysemiminor)
	children = append(children, enc_uncertaintysemiminor...)
	enc_orientationmajoraxis := ber.EncodeInteger(int64(v.OrientationMajorAxis))
	enc_orientationmajoraxis = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 5, false, enc_orientationmajoraxis)
	children = append(children, enc_orientationmajoraxis...)
	enc_uncertaintyaltitude := ber.EncodeInteger(int64(v.UncertaintyAltitude))
	enc_uncertaintyaltitude = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 6, false, enc_uncertaintyaltitude)
	children = append(children, enc_uncertaintyaltitude...)
	if v.Confidence != nil {
		enc_confidence := ber.EncodeInteger(int64(*v.Confidence))
		enc_confidence = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 7, false, enc_confidence)
		children = append(children, enc_confidence...)
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

// MarshalDER encodes Relative3DLocationWithUncertaintyEllipsoid to DER format.
func (v *Relative3DLocationWithUncertaintyEllipsoid) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes Relative3DLocationWithUncertaintyEllipsoid from BER/DER format.
func (v *Relative3DLocationWithUncertaintyEllipsoid) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding Relative3DLocationWithUncertaintyEllipsoid SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "Relative3DLocationWithUncertaintyEllipsoid", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode xCoordinates
	if offset >= len(content) {
		return fmt.Errorf("missing required field xCoordinates")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 0 {
			return fmt.Errorf("expected tag [%s %d] for xCoordinates, got %s", "CONTEXT", 0, reqTag_)
		}
	}
	_, n_xcoordinates, rawVal_xcoordinates, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding xCoordinates: %w", err)
	}
	decVal_xcoordinates, intErr := ber.DecodeIntegerValue(rawVal_xcoordinates)
	if intErr != nil {
		return fmt.Errorf("decoding xCoordinates: %w", intErr)
	}
	v.XCoordinates = RangeXYCoordinates(decVal_xcoordinates)
	offset += n_xcoordinates
	// Decode yCoordinates
	if offset >= len(content) {
		return fmt.Errorf("missing required field yCoordinates")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 1 {
			return fmt.Errorf("expected tag [%s %d] for yCoordinates, got %s", "CONTEXT", 1, reqTag_)
		}
	}
	_, n_ycoordinates, rawVal_ycoordinates, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding yCoordinates: %w", err)
	}
	decVal_ycoordinates, intErr := ber.DecodeIntegerValue(rawVal_ycoordinates)
	if intErr != nil {
		return fmt.Errorf("decoding yCoordinates: %w", intErr)
	}
	v.YCoordinates = RangeXYCoordinates(decVal_ycoordinates)
	offset += n_ycoordinates
	// Decode zCoordinates
	if offset >= len(content) {
		return fmt.Errorf("missing required field zCoordinates")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 2 {
			return fmt.Errorf("expected tag [%s %d] for zCoordinates, got %s", "CONTEXT", 2, reqTag_)
		}
	}
	_, n_zcoordinates, rawVal_zcoordinates, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding zCoordinates: %w", err)
	}
	decVal_zcoordinates, intErr := ber.DecodeIntegerValue(rawVal_zcoordinates)
	if intErr != nil {
		return fmt.Errorf("decoding zCoordinates: %w", intErr)
	}
	v.ZCoordinates = RangeZCoordinates(decVal_zcoordinates)
	offset += n_zcoordinates
	// Decode uncertaintySemiMajor
	if offset >= len(content) {
		return fmt.Errorf("missing required field uncertaintySemiMajor")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 3 {
			return fmt.Errorf("expected tag [%s %d] for uncertaintySemiMajor, got %s", "CONTEXT", 3, reqTag_)
		}
	}
	_, n_uncertaintysemimajor, rawVal_uncertaintysemimajor, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding uncertaintySemiMajor: %w", err)
	}
	decVal_uncertaintysemimajor, intErr := ber.DecodeIntegerValue(rawVal_uncertaintysemimajor)
	if intErr != nil {
		return fmt.Errorf("decoding uncertaintySemiMajor: %w", intErr)
	}
	v.UncertaintySemiMajor = Uncertainty(decVal_uncertaintysemimajor)
	offset += n_uncertaintysemimajor
	// Decode uncertaintySemiMinor
	if offset >= len(content) {
		return fmt.Errorf("missing required field uncertaintySemiMinor")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 4 {
			return fmt.Errorf("expected tag [%s %d] for uncertaintySemiMinor, got %s", "CONTEXT", 4, reqTag_)
		}
	}
	_, n_uncertaintysemiminor, rawVal_uncertaintysemiminor, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding uncertaintySemiMinor: %w", err)
	}
	decVal_uncertaintysemiminor, intErr := ber.DecodeIntegerValue(rawVal_uncertaintysemiminor)
	if intErr != nil {
		return fmt.Errorf("decoding uncertaintySemiMinor: %w", intErr)
	}
	v.UncertaintySemiMinor = Uncertainty(decVal_uncertaintysemiminor)
	offset += n_uncertaintysemiminor
	// Decode orientationMajorAxis
	if offset >= len(content) {
		return fmt.Errorf("missing required field orientationMajorAxis")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 5 {
			return fmt.Errorf("expected tag [%s %d] for orientationMajorAxis, got %s", "CONTEXT", 5, reqTag_)
		}
	}
	_, n_orientationmajoraxis, rawVal_orientationmajoraxis, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding orientationMajorAxis: %w", err)
	}
	decVal_orientationmajoraxis, intErr := ber.DecodeIntegerValue(rawVal_orientationmajoraxis)
	if intErr != nil {
		return fmt.Errorf("decoding orientationMajorAxis: %w", intErr)
	}
	v.OrientationMajorAxis = OrientationMajorAxis(decVal_orientationmajoraxis)
	offset += n_orientationmajoraxis
	// Decode uncertaintyAltitude
	if offset >= len(content) {
		return fmt.Errorf("missing required field uncertaintyAltitude")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 6 {
			return fmt.Errorf("expected tag [%s %d] for uncertaintyAltitude, got %s", "CONTEXT", 6, reqTag_)
		}
	}
	_, n_uncertaintyaltitude, rawVal_uncertaintyaltitude, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding uncertaintyAltitude: %w", err)
	}
	decVal_uncertaintyaltitude, intErr := ber.DecodeIntegerValue(rawVal_uncertaintyaltitude)
	if intErr != nil {
		return fmt.Errorf("decoding uncertaintyAltitude: %w", intErr)
	}
	v.UncertaintyAltitude = Uncertainty(decVal_uncertaintyaltitude)
	offset += n_uncertaintyaltitude
	// Decode confidence
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 7 {
				_, n_confidence, rawVal_confidence, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding confidence: %w", err)
				}
				decVal_confidence, intErr := ber.DecodeIntegerValue(rawVal_confidence)
				if intErr != nil {
					return fmt.Errorf("decoding confidence: %w", intErr)
				}
				tmp_confidence := Confidence(decVal_confidence)
				v.Confidence = &tmp_confidence
				offset += n_confidence
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "Relative3DLocationWithUncertaintyEllipsoid", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes RangeDirection to BER format.
func (v *RangeDirection) MarshalBER() ([]byte, error) {
	var children []byte
	if v.Range != nil {
		enc_range, err := v.Range.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding range: %w", err)
		}
		enc_range = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, true, enc_range)
		children = append(children, enc_range...)
	}
	if v.Azimuth != nil {
		enc_azimuth, err := v.Azimuth.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding azimuth: %w", err)
		}
		enc_azimuth = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, true, enc_azimuth)
		children = append(children, enc_azimuth...)
	}
	if v.Elevation != nil {
		enc_elevation, err := v.Elevation.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding elevation: %w", err)
		}
		enc_elevation = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, true, enc_elevation)
		children = append(children, enc_elevation...)
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

// MarshalDER encodes RangeDirection to DER format.
func (v *RangeDirection) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes RangeDirection from BER/DER format.
func (v *RangeDirection) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding RangeDirection SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "RangeDirection", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode range
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
				_, n_range, rawVal_range, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding range: %w", err)
				}
				reconstructed_range := ber.EncodeSequence(rawVal_range)
				var dec_range Range
				if unmErr := dec_range.UnmarshalBER(reconstructed_range); unmErr != nil {
					return fmt.Errorf("decoding range: %w", unmErr)
				}
				v.Range = &dec_range
				offset += n_range
			}
		}
	}
	// Decode azimuth
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
				_, n_azimuth, rawVal_azimuth, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding azimuth: %w", err)
				}
				reconstructed_azimuth := ber.EncodeSequence(rawVal_azimuth)
				var dec_azimuth Azimuth
				if unmErr := dec_azimuth.UnmarshalBER(reconstructed_azimuth); unmErr != nil {
					return fmt.Errorf("decoding azimuth: %w", unmErr)
				}
				v.Azimuth = &dec_azimuth
				offset += n_azimuth
			}
		}
	}
	// Decode elevation
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2 {
				_, n_elevation, rawVal_elevation, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding elevation: %w", err)
				}
				reconstructed_elevation := ber.EncodeSequence(rawVal_elevation)
				var dec_elevation Elevation
				if unmErr := dec_elevation.UnmarshalBER(reconstructed_elevation); unmErr != nil {
					return fmt.Errorf("decoding elevation: %w", unmErr)
				}
				v.Elevation = &dec_elevation
				offset += n_elevation
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "RangeDirection", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes Range to BER format.
func (v *Range) MarshalBER() ([]byte, error) {
	var children []byte
	enc_rangeresult := ber.EncodeInteger(int64(v.RangeResult))
	enc_rangeresult = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, false, enc_rangeresult)
	children = append(children, enc_rangeresult...)
	enc_uncertainty := ber.EncodeInteger(int64(v.Uncertainty))
	enc_uncertainty = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, false, enc_uncertainty)
	children = append(children, enc_uncertainty...)
	if v.Confidence != nil {
		enc_confidence := ber.EncodeInteger(int64(*v.Confidence))
		enc_confidence = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, false, enc_confidence)
		children = append(children, enc_confidence...)
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

// MarshalDER encodes Range to DER format.
func (v *Range) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes Range from BER/DER format.
func (v *Range) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding Range SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "Range", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode rangeResult
	if offset >= len(content) {
		return fmt.Errorf("missing required field rangeResult")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 0 {
			return fmt.Errorf("expected tag [%s %d] for rangeResult, got %s", "CONTEXT", 0, reqTag_)
		}
	}
	_, n_rangeresult, rawVal_rangeresult, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding rangeResult: %w", err)
	}
	decVal_rangeresult, intErr := ber.DecodeIntegerValue(rawVal_rangeresult)
	if intErr != nil {
		return fmt.Errorf("decoding rangeResult: %w", intErr)
	}
	v.RangeResult = RangeResult(decVal_rangeresult)
	offset += n_rangeresult
	// Decode uncertainty
	if offset >= len(content) {
		return fmt.Errorf("missing required field uncertainty")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 1 {
			return fmt.Errorf("expected tag [%s %d] for uncertainty, got %s", "CONTEXT", 1, reqTag_)
		}
	}
	_, n_uncertainty, rawVal_uncertainty, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding uncertainty: %w", err)
	}
	decVal_uncertainty, intErr := ber.DecodeIntegerValue(rawVal_uncertainty)
	if intErr != nil {
		return fmt.Errorf("decoding uncertainty: %w", intErr)
	}
	v.Uncertainty = Uncertainty(decVal_uncertainty)
	offset += n_uncertainty
	// Decode confidence
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2 {
				_, n_confidence, rawVal_confidence, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding confidence: %w", err)
				}
				decVal_confidence, intErr := ber.DecodeIntegerValue(rawVal_confidence)
				if intErr != nil {
					return fmt.Errorf("decoding confidence: %w", intErr)
				}
				tmp_confidence := Confidence(decVal_confidence)
				v.Confidence = &tmp_confidence
				offset += n_confidence
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "Range", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes Azimuth to BER format.
func (v *Azimuth) MarshalBER() ([]byte, error) {
	var children []byte
	enc_azimuthresult := ber.EncodeInteger(int64(v.AzimuthResult))
	enc_azimuthresult = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, false, enc_azimuthresult)
	children = append(children, enc_azimuthresult...)
	enc_uncertainty := ber.EncodeInteger(int64(v.Uncertainty))
	enc_uncertainty = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, false, enc_uncertainty)
	children = append(children, enc_uncertainty...)
	if v.Confidence != nil {
		enc_confidence := ber.EncodeInteger(int64(*v.Confidence))
		enc_confidence = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, false, enc_confidence)
		children = append(children, enc_confidence...)
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

// MarshalDER encodes Azimuth to DER format.
func (v *Azimuth) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes Azimuth from BER/DER format.
func (v *Azimuth) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding Azimuth SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "Azimuth", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode azimuthResult
	if offset >= len(content) {
		return fmt.Errorf("missing required field azimuthResult")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 0 {
			return fmt.Errorf("expected tag [%s %d] for azimuthResult, got %s", "CONTEXT", 0, reqTag_)
		}
	}
	_, n_azimuthresult, rawVal_azimuthresult, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding azimuthResult: %w", err)
	}
	decVal_azimuthresult, intErr := ber.DecodeIntegerValue(rawVal_azimuthresult)
	if intErr != nil {
		return fmt.Errorf("decoding azimuthResult: %w", intErr)
	}
	v.AzimuthResult = AzimuthResult(decVal_azimuthresult)
	offset += n_azimuthresult
	// Decode uncertainty
	if offset >= len(content) {
		return fmt.Errorf("missing required field uncertainty")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 1 {
			return fmt.Errorf("expected tag [%s %d] for uncertainty, got %s", "CONTEXT", 1, reqTag_)
		}
	}
	_, n_uncertainty, rawVal_uncertainty, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding uncertainty: %w", err)
	}
	decVal_uncertainty, intErr := ber.DecodeIntegerValue(rawVal_uncertainty)
	if intErr != nil {
		return fmt.Errorf("decoding uncertainty: %w", intErr)
	}
	v.Uncertainty = Uncertainty(decVal_uncertainty)
	offset += n_uncertainty
	// Decode confidence
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2 {
				_, n_confidence, rawVal_confidence, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding confidence: %w", err)
				}
				decVal_confidence, intErr := ber.DecodeIntegerValue(rawVal_confidence)
				if intErr != nil {
					return fmt.Errorf("decoding confidence: %w", intErr)
				}
				tmp_confidence := Confidence(decVal_confidence)
				v.Confidence = &tmp_confidence
				offset += n_confidence
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "Azimuth", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes Elevation to BER format.
func (v *Elevation) MarshalBER() ([]byte, error) {
	var children []byte
	enc_elevationresult := ber.EncodeInteger(int64(v.ElevationResult))
	enc_elevationresult = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, false, enc_elevationresult)
	children = append(children, enc_elevationresult...)
	enc_uncertainty := ber.EncodeInteger(int64(v.Uncertainty))
	enc_uncertainty = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, false, enc_uncertainty)
	children = append(children, enc_uncertainty...)
	if v.Confidence != nil {
		enc_confidence := ber.EncodeInteger(int64(*v.Confidence))
		enc_confidence = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, false, enc_confidence)
		children = append(children, enc_confidence...)
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

// MarshalDER encodes Elevation to DER format.
func (v *Elevation) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes Elevation from BER/DER format.
func (v *Elevation) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding Elevation SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "Elevation", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode elevationResult
	if offset >= len(content) {
		return fmt.Errorf("missing required field elevationResult")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 0 {
			return fmt.Errorf("expected tag [%s %d] for elevationResult, got %s", "CONTEXT", 0, reqTag_)
		}
	}
	_, n_elevationresult, rawVal_elevationresult, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding elevationResult: %w", err)
	}
	decVal_elevationresult, intErr := ber.DecodeIntegerValue(rawVal_elevationresult)
	if intErr != nil {
		return fmt.Errorf("decoding elevationResult: %w", intErr)
	}
	v.ElevationResult = ElevationResult(decVal_elevationresult)
	offset += n_elevationresult
	// Decode uncertainty
	if offset >= len(content) {
		return fmt.Errorf("missing required field uncertainty")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 1 {
			return fmt.Errorf("expected tag [%s %d] for uncertainty, got %s", "CONTEXT", 1, reqTag_)
		}
	}
	_, n_uncertainty, rawVal_uncertainty, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding uncertainty: %w", err)
	}
	decVal_uncertainty, intErr := ber.DecodeIntegerValue(rawVal_uncertainty)
	if intErr != nil {
		return fmt.Errorf("decoding uncertainty: %w", intErr)
	}
	v.Uncertainty = Uncertainty(decVal_uncertainty)
	offset += n_uncertainty
	// Decode confidence
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2 {
				_, n_confidence, rawVal_confidence, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding confidence: %w", err)
				}
				decVal_confidence, intErr := ber.DecodeIntegerValue(rawVal_confidence)
				if intErr != nil {
					return fmt.Errorf("decoding confidence: %w", intErr)
				}
				tmp_confidence := Confidence(decVal_confidence)
				v.Confidence = &tmp_confidence
				offset += n_confidence
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "Elevation", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes LCSAreaEventReportArg to BER format.
func (v *LCSAreaEventReportArg) MarshalBER() ([]byte, error) {
	var children []byte
	enc_referencenumber := ber.EncodeOctetString([]byte(v.ReferenceNumber))
	enc_referencenumber = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, false, enc_referencenumber)
	children = append(children, enc_referencenumber...)
	enc_hgmlcaddress := ber.EncodeOctetString([]byte(v.HGmlcAddress))
	enc_hgmlcaddress = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, false, enc_hgmlcaddress)
	children = append(children, enc_hgmlcaddress...)
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

// MarshalDER encodes LCSAreaEventReportArg to DER format.
func (v *LCSAreaEventReportArg) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes LCSAreaEventReportArg from BER/DER format.
func (v *LCSAreaEventReportArg) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding LCSAreaEventReportArg SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "LCSAreaEventReportArg", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode referenceNumber
	if offset >= len(content) {
		return fmt.Errorf("missing required field referenceNumber")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 0 {
			return fmt.Errorf("expected tag [%s %d] for referenceNumber, got %s", "CONTEXT", 0, reqTag_)
		}
	}
	_, n_referencenumber, rawVal_referencenumber, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding referenceNumber: %w", err)
	}
	v.ReferenceNumber = LCSReferenceNumber(rawVal_referencenumber)
	offset += n_referencenumber
	// Decode h-gmlc-address
	if offset >= len(content) {
		return fmt.Errorf("missing required field h-gmlc-address")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 1 {
			return fmt.Errorf("expected tag [%s %d] for h-gmlc-address, got %s", "CONTEXT", 1, reqTag_)
		}
	}
	_, n_hgmlcaddress, rawVal_hgmlcaddress, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding h-gmlc-address: %w", err)
	}
	v.HGmlcAddress = GSNAddress(rawVal_hgmlcaddress)
	offset += n_hgmlcaddress
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "LCSAreaEventReportArg", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes LCSAreaEventCancellationArg to BER format.
func (v *LCSAreaEventCancellationArg) MarshalBER() ([]byte, error) {
	var children []byte
	enc_referencenumber := ber.EncodeOctetString([]byte(v.ReferenceNumber))
	enc_referencenumber = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, false, enc_referencenumber)
	children = append(children, enc_referencenumber...)
	enc_hgmlcaddress := ber.EncodeOctetString([]byte(v.HGmlcAddress))
	enc_hgmlcaddress = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, false, enc_hgmlcaddress)
	children = append(children, enc_hgmlcaddress...)
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

// MarshalDER encodes LCSAreaEventCancellationArg to DER format.
func (v *LCSAreaEventCancellationArg) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes LCSAreaEventCancellationArg from BER/DER format.
func (v *LCSAreaEventCancellationArg) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding LCSAreaEventCancellationArg SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "LCSAreaEventCancellationArg", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode referenceNumber
	if offset >= len(content) {
		return fmt.Errorf("missing required field referenceNumber")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 0 {
			return fmt.Errorf("expected tag [%s %d] for referenceNumber, got %s", "CONTEXT", 0, reqTag_)
		}
	}
	_, n_referencenumber, rawVal_referencenumber, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding referenceNumber: %w", err)
	}
	v.ReferenceNumber = LCSReferenceNumber(rawVal_referencenumber)
	offset += n_referencenumber
	// Decode h-gmlc-address
	if offset >= len(content) {
		return fmt.Errorf("missing required field h-gmlc-address")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 1 {
			return fmt.Errorf("expected tag [%s %d] for h-gmlc-address, got %s", "CONTEXT", 1, reqTag_)
		}
	}
	_, n_hgmlcaddress, rawVal_hgmlcaddress, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding h-gmlc-address: %w", err)
	}
	v.HGmlcAddress = GSNAddress(rawVal_hgmlcaddress)
	offset += n_hgmlcaddress
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "LCSAreaEventCancellationArg", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes LCSPeriodicLocationRequestArg to BER format.
func (v *LCSPeriodicLocationRequestArg) MarshalBER() ([]byte, error) {
	var children []byte
	enc_referencenumber := ber.EncodeOctetString([]byte(v.ReferenceNumber))
	enc_referencenumber = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, false, enc_referencenumber)
	children = append(children, enc_referencenumber...)
	enc_periodicldrinfo, err := v.PeriodicLDRInfo.MarshalBER()
	if err != nil {
		return nil, fmt.Errorf("encoding periodicLDRInfo: %w", err)
	}
	enc_periodicldrinfo = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, true, enc_periodicldrinfo)
	children = append(children, enc_periodicldrinfo...)
	enc_lcsclientexternalid, err := v.LcsClientExternalID.MarshalBER()
	if err != nil {
		return nil, fmt.Errorf("encoding lcsClientExternalID: %w", err)
	}
	enc_lcsclientexternalid = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, true, enc_lcsclientexternalid)
	children = append(children, enc_lcsclientexternalid...)
	if v.QoS != nil {
		enc_qos, err := v.QoS.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding qoS: %w", err)
		}
		enc_qos = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, true, enc_qos)
		children = append(children, enc_qos...)
	}
	if v.HGmlcAddress != nil {
		enc_hgmlcaddress := ber.EncodeOctetString([]byte(*v.HGmlcAddress))
		enc_hgmlcaddress = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, false, enc_hgmlcaddress)
		children = append(children, enc_hgmlcaddress...)
	}
	if v.MoLrShortCircuit != nil {
		enc_molrshortcircuit := ber.EncodeNull()
		enc_molrshortcircuit = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 5, false, enc_molrshortcircuit)
		children = append(children, enc_molrshortcircuit...)
	}
	if v.ReportingPLMNList != nil {
		enc_reportingplmnlist, err := v.ReportingPLMNList.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding reportingPLMNList: %w", err)
		}
		enc_reportingplmnlist = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 6, true, enc_reportingplmnlist)
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

// MarshalDER encodes LCSPeriodicLocationRequestArg to DER format.
func (v *LCSPeriodicLocationRequestArg) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes LCSPeriodicLocationRequestArg from BER/DER format.
func (v *LCSPeriodicLocationRequestArg) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding LCSPeriodicLocationRequestArg SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "LCSPeriodicLocationRequestArg", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode referenceNumber
	if offset >= len(content) {
		return fmt.Errorf("missing required field referenceNumber")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 0 {
			return fmt.Errorf("expected tag [%s %d] for referenceNumber, got %s", "CONTEXT", 0, reqTag_)
		}
	}
	_, n_referencenumber, rawVal_referencenumber, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding referenceNumber: %w", err)
	}
	v.ReferenceNumber = LCSReferenceNumber(rawVal_referencenumber)
	offset += n_referencenumber
	// Decode periodicLDRInfo
	if offset >= len(content) {
		return fmt.Errorf("missing required field periodicLDRInfo")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 1 {
			return fmt.Errorf("expected tag [%s %d] for periodicLDRInfo, got %s", "CONTEXT", 1, reqTag_)
		}
	}
	_, n_periodicldrinfo, rawVal_periodicldrinfo, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding periodicLDRInfo: %w", err)
	}
	reconstructed_periodicldrinfo := ber.EncodeSequence(rawVal_periodicldrinfo)
	if unmErr := v.PeriodicLDRInfo.UnmarshalBER(reconstructed_periodicldrinfo); unmErr != nil {
		return fmt.Errorf("decoding periodicLDRInfo: %w", unmErr)
	}
	offset += n_periodicldrinfo
	// Decode lcsClientExternalID
	if offset >= len(content) {
		return fmt.Errorf("missing required field lcsClientExternalID")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 2 {
			return fmt.Errorf("expected tag [%s %d] for lcsClientExternalID, got %s", "CONTEXT", 2, reqTag_)
		}
	}
	_, n_lcsclientexternalid, rawVal_lcsclientexternalid, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding lcsClientExternalID: %w", err)
	}
	reconstructed_lcsclientexternalid := ber.EncodeSequence(rawVal_lcsclientexternalid)
	if unmErr := v.LcsClientExternalID.UnmarshalBER(reconstructed_lcsclientexternalid); unmErr != nil {
		return fmt.Errorf("decoding lcsClientExternalID: %w", unmErr)
	}
	offset += n_lcsclientexternalid
	// Decode qoS
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3 {
				_, n_qos, rawVal_qos, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding qoS: %w", err)
				}
				reconstructed_qos := ber.EncodeSequence(rawVal_qos)
				var dec_qos LCSQoS
				if unmErr := dec_qos.UnmarshalBER(reconstructed_qos); unmErr != nil {
					return fmt.Errorf("decoding qoS: %w", unmErr)
				}
				v.QoS = &dec_qos
				offset += n_qos
			}
		}
	}
	// Decode h-gmlc-address
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4 {
				_, n_hgmlcaddress, rawVal_hgmlcaddress, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding h-gmlc-address: %w", err)
				}
				tmp_hgmlcaddress := GSNAddress(rawVal_hgmlcaddress)
				v.HGmlcAddress = &tmp_hgmlcaddress
				offset += n_hgmlcaddress
			}
		}
	}
	// Decode mo-lrShortCircuit
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 5 {
				_, n_molrshortcircuit, rawVal_molrshortcircuit, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding mo-lrShortCircuit: %w", err)
				}
				_ = rawVal_molrshortcircuit
				v.MoLrShortCircuit = &struct{}{}
				offset += n_molrshortcircuit
			}
		}
	}
	// Decode reportingPLMNList
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 6 {
				_, n_reportingplmnlist, rawVal_reportingplmnlist, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding reportingPLMNList: %w", err)
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
			return &ber.DecodeError{Offset: offset, TypeName: "LCSPeriodicLocationRequestArg", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes LCSPeriodicLocationRequestRes to BER format.
func (v *LCSPeriodicLocationRequestRes) MarshalBER() ([]byte, error) {
	var children []byte
	if v.MoLrShortCircuit != nil {
		enc_molrshortcircuit := ber.EncodeNull()
		enc_molrshortcircuit = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, false, enc_molrshortcircuit)
		children = append(children, enc_molrshortcircuit...)
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

// MarshalDER encodes LCSPeriodicLocationRequestRes to DER format.
func (v *LCSPeriodicLocationRequestRes) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes LCSPeriodicLocationRequestRes from BER/DER format.
func (v *LCSPeriodicLocationRequestRes) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding LCSPeriodicLocationRequestRes SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "LCSPeriodicLocationRequestRes", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode mo-lrShortCircuit
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
				_, n_molrshortcircuit, rawVal_molrshortcircuit, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding mo-lrShortCircuit: %w", err)
				}
				_ = rawVal_molrshortcircuit
				v.MoLrShortCircuit = &struct{}{}
				offset += n_molrshortcircuit
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "LCSPeriodicLocationRequestRes", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes LCSLocationUpdateArg to BER format.
func (v *LCSLocationUpdateArg) MarshalBER() ([]byte, error) {
	var children []byte
	if v.ReferenceNumber != nil {
		enc_referencenumber := ber.EncodeOctetString([]byte(*v.ReferenceNumber))
		enc_referencenumber = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, false, enc_referencenumber)
		children = append(children, enc_referencenumber...)
	}
	if v.AddLocationEstimate != nil {
		enc_addlocationestimate := ber.EncodeOctetString([]byte(*v.AddLocationEstimate))
		enc_addlocationestimate = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, false, enc_addlocationestimate)
		children = append(children, enc_addlocationestimate...)
	}
	if v.VelocityEstimate != nil {
		enc_velocityestimate := ber.EncodeOctetString([]byte(*v.VelocityEstimate))
		enc_velocityestimate = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, false, enc_velocityestimate)
		children = append(children, enc_velocityestimate...)
	}
	if v.SequenceNumber != nil {
		enc_sequencenumber := ber.EncodeInteger(int64(*v.SequenceNumber))
		enc_sequencenumber = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, false, enc_sequencenumber)
		children = append(children, enc_sequencenumber...)
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

// MarshalDER encodes LCSLocationUpdateArg to DER format.
func (v *LCSLocationUpdateArg) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes LCSLocationUpdateArg from BER/DER format.
func (v *LCSLocationUpdateArg) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding LCSLocationUpdateArg SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "LCSLocationUpdateArg", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode referenceNumber
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
				_, n_referencenumber, rawVal_referencenumber, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding referenceNumber: %w", err)
				}
				tmp_referencenumber := LCSReferenceNumber(rawVal_referencenumber)
				v.ReferenceNumber = &tmp_referencenumber
				offset += n_referencenumber
			}
		}
	}
	// Decode add-LocationEstimate
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
				_, n_addlocationestimate, rawVal_addlocationestimate, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding add-LocationEstimate: %w", err)
				}
				tmp_addlocationestimate := AddGeographicalInformation(rawVal_addlocationestimate)
				v.AddLocationEstimate = &tmp_addlocationestimate
				offset += n_addlocationestimate
			}
		}
	}
	// Decode velocityEstimate
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2 {
				_, n_velocityestimate, rawVal_velocityestimate, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding velocityEstimate: %w", err)
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
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3 {
				_, n_sequencenumber, rawVal_sequencenumber, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding sequenceNumber: %w", err)
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
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "LCSLocationUpdateArg", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes LCSLocationUpdateRes to BER format.
func (v *LCSLocationUpdateRes) MarshalBER() ([]byte, error) {
	var children []byte
	if v.TerminationCause != nil {
		enc_terminationcause := ber.EncodeEnumerated(int64(*v.TerminationCause))
		enc_terminationcause = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, false, enc_terminationcause)
		children = append(children, enc_terminationcause...)
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

// MarshalDER encodes LCSLocationUpdateRes to DER format.
func (v *LCSLocationUpdateRes) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes LCSLocationUpdateRes from BER/DER format.
func (v *LCSLocationUpdateRes) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding LCSLocationUpdateRes SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "LCSLocationUpdateRes", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode terminationCause
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
				_, n_terminationcause, rawVal_terminationcause, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding terminationCause: %w", err)
				}
				decVal_terminationcause, intErr := ber.DecodeIntegerValue(rawVal_terminationcause)
				if intErr != nil {
					return fmt.Errorf("decoding terminationCause: %w", intErr)
				}
				tmp_terminationcause := DataTypesTerminationCause(decVal_terminationcause)
				v.TerminationCause = &tmp_terminationcause
				offset += n_terminationcause
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "LCSLocationUpdateRes", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes LCSPeriodicLocationCancellationArg to BER format.
func (v *LCSPeriodicLocationCancellationArg) MarshalBER() ([]byte, error) {
	var children []byte
	enc_referencenumber := ber.EncodeOctetString([]byte(v.ReferenceNumber))
	enc_referencenumber = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, false, enc_referencenumber)
	children = append(children, enc_referencenumber...)
	if v.HGmlcAddress != nil {
		enc_hgmlcaddress := ber.EncodeOctetString([]byte(*v.HGmlcAddress))
		enc_hgmlcaddress = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, false, enc_hgmlcaddress)
		children = append(children, enc_hgmlcaddress...)
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

// MarshalDER encodes LCSPeriodicLocationCancellationArg to DER format.
func (v *LCSPeriodicLocationCancellationArg) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes LCSPeriodicLocationCancellationArg from BER/DER format.
func (v *LCSPeriodicLocationCancellationArg) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding LCSPeriodicLocationCancellationArg SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "LCSPeriodicLocationCancellationArg", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode referenceNumber
	if offset >= len(content) {
		return fmt.Errorf("missing required field referenceNumber")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 0 {
			return fmt.Errorf("expected tag [%s %d] for referenceNumber, got %s", "CONTEXT", 0, reqTag_)
		}
	}
	_, n_referencenumber, rawVal_referencenumber, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding referenceNumber: %w", err)
	}
	v.ReferenceNumber = LCSReferenceNumber(rawVal_referencenumber)
	offset += n_referencenumber
	// Decode h-gmlc-address
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
				_, n_hgmlcaddress, rawVal_hgmlcaddress, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding h-gmlc-address: %w", err)
				}
				tmp_hgmlcaddress := GSNAddress(rawVal_hgmlcaddress)
				v.HGmlcAddress = &tmp_hgmlcaddress
				offset += n_hgmlcaddress
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "LCSPeriodicLocationCancellationArg", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes LCSPeriodicTriggeredInvokeArg to BER format.
func (v *LCSPeriodicTriggeredInvokeArg) MarshalBER() ([]byte, error) {
	var children []byte
	enc_referencenumber := ber.EncodeOctetString([]byte(v.ReferenceNumber))
	enc_referencenumber = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, false, enc_referencenumber)
	children = append(children, enc_referencenumber...)
	enc_hgmlcaddress := ber.EncodeOctetString([]byte(v.HGmlcAddress))
	enc_hgmlcaddress = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, false, enc_hgmlcaddress)
	children = append(children, enc_hgmlcaddress...)
	if v.QoS != nil {
		enc_qos, err := v.QoS.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding qoS: %w", err)
		}
		enc_qos = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, true, enc_qos)
		children = append(children, enc_qos...)
	}
	if v.ReportingPLMNList != nil {
		enc_reportingplmnlist, err := v.ReportingPLMNList.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding reportingPLMNList: %w", err)
		}
		enc_reportingplmnlist = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, true, enc_reportingplmnlist)
		children = append(children, enc_reportingplmnlist...)
	}
	if v.PeriodicLocation != nil {
		enc_periodiclocation, err := v.PeriodicLocation.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding periodicLocation: %w", err)
		}
		enc_periodiclocation = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, true, enc_periodiclocation)
		children = append(children, enc_periodiclocation...)
	}
	if v.AreaEventReporting != nil {
		enc_areaeventreporting, err := v.AreaEventReporting.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding areaEventReporting: %w", err)
		}
		enc_areaeventreporting = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 5, true, enc_areaeventreporting)
		children = append(children, enc_areaeventreporting...)
	}
	if v.MotionEventReporting != nil {
		enc_motioneventreporting, err := v.MotionEventReporting.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding motionEventReporting: %w", err)
		}
		enc_motioneventreporting = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 6, true, enc_motioneventreporting)
		children = append(children, enc_motioneventreporting...)
	}
	if v.ReferenceNumberExt != nil {
		enc_referencenumberext := ber.EncodeOctetString([]byte(*v.ReferenceNumberExt))
		enc_referencenumberext = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 7, false, enc_referencenumberext)
		children = append(children, enc_referencenumberext...)
	}
	if v.HGmlcCallBackUri != nil {
		enc_hgmlccallbackuri, stringErr := ber.EncodeStringTagChecked(12, *v.HGmlcCallBackUri)
		if stringErr != nil {
			return nil, fmt.Errorf("encoding h-gmlc-callBackUri: %w", stringErr)
		}
		enc_hgmlccallbackuri = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 8, false, enc_hgmlccallbackuri)
		children = append(children, enc_hgmlccallbackuri...)
	}
	if v.SupportedGADShapes != nil {
		enc_supportedgadshapes := ber.EncodeBitString(v.SupportedGADShapes.Bytes, (8-(v.SupportedGADShapes.BitLength%8))%8)
		enc_supportedgadshapes = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 9, false, enc_supportedgadshapes)
		children = append(children, enc_supportedgadshapes...)
	}
	if v.DeferredRoutingIdentifier != nil {
		enc_deferredroutingidentifier := ber.EncodeOctetString(v.DeferredRoutingIdentifier)
		enc_deferredroutingidentifier = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 10, false, enc_deferredroutingidentifier)
		children = append(children, enc_deferredroutingidentifier...)
	}
	if v.ReportingAccessTypes != nil {
		enc_reportingaccesstypes := ber.EncodeBitString(v.ReportingAccessTypes.Bytes, (8-(v.ReportingAccessTypes.BitLength%8))%8)
		enc_reportingaccesstypes = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 11, false, enc_reportingaccesstypes)
		children = append(children, enc_reportingaccesstypes...)
	}
	if v.MultiplePositioningProtocolPDUs != nil {
		enc_multiplepositioningprotocolpdus, err := MarshalBERMultiplePositioningProtocolPDUs(v.MultiplePositioningProtocolPDUs)
		if err != nil {
			return nil, fmt.Errorf("encoding multiplePositioningProtocolPDUs: %w", err)
		}
		if v.MultiplePositioningProtocolPDUsIndef_ {
			// Strip the outer SEQUENCE tag from marshalBER output to get raw children.
			_, _, seqContent_, tlvErr_ := ber.DecodeTLV(enc_multiplepositioningprotocolpdus)
			if tlvErr_ != nil {
				return nil, tlvErr_
			}
			enc_multiplepositioningprotocolpdus = ber.EncodeConstructedIndefinite(tag.Tag{Class: tag.ClassContextSpecific, Number: 12}, seqContent_)
		} else {
			enc_multiplepositioningprotocolpdus = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 12, true, enc_multiplepositioningprotocolpdus)
		}
		children = append(children, enc_multiplepositioningprotocolpdus...)
	}
	if v.ControlPlaneCIoT5GSOptimisation != nil {
		enc_controlplaneciot5gsoptimisation, err := v.ControlPlaneCIoT5GSOptimisation.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding controlPlane-CIoT-5GS-Optimisation: %w", err)
		}
		enc_controlplaneciot5gsoptimisation = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 13, true, enc_controlplaneciot5gsoptimisation)
		children = append(children, enc_controlplaneciot5gsoptimisation...)
	}
	if v.ScheduledLocTime != nil {
		enc_scheduledloctime := ber.EncodeOctetString([]byte(*v.ScheduledLocTime))
		enc_scheduledloctime = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 14, false, enc_scheduledloctime)
		children = append(children, enc_scheduledloctime...)
	}
	if v.EventReportAllowedArea != nil {
		enc_eventreportallowedarea, err := MarshalBERDataTypesAreaList(v.EventReportAllowedArea)
		if err != nil {
			return nil, fmt.Errorf("encoding eventReportAllowedArea: %w", err)
		}
		if v.EventReportAllowedAreaIndef_ {
			// Strip the outer SEQUENCE tag from marshalBER output to get raw children.
			_, _, seqContent_, tlvErr_ := ber.DecodeTLV(enc_eventreportallowedarea)
			if tlvErr_ != nil {
				return nil, tlvErr_
			}
			enc_eventreportallowedarea = ber.EncodeConstructedIndefinite(tag.Tag{Class: tag.ClassContextSpecific, Number: 15}, seqContent_)
		} else {
			enc_eventreportallowedarea = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 15, true, enc_eventreportallowedarea)
		}
		children = append(children, enc_eventreportallowedarea...)
	}
	if v.ReportingInd != nil {
		enc_reportingind := ber.EncodeEnumerated(int64(*v.ReportingInd))
		enc_reportingind = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 16, false, enc_reportingind)
		children = append(children, enc_reportingind...)
	}
	if v.MappedQoS != nil {
		enc_mappedqos, err := v.MappedQoS.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding mappedQoS: %w", err)
		}
		enc_mappedqos = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 17, true, enc_mappedqos)
		children = append(children, enc_mappedqos...)
	}
	if v.UserPlaneReportAFAddr != nil {
		enc_userplanereportafaddr, err := v.UserPlaneReportAFAddr.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding userPlaneReportAFAddr: %w", err)
		}
		enc_userplanereportafaddr = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 18, true, enc_userplanereportafaddr)
		children = append(children, enc_userplanereportafaddr...)
	}
	if v.CumulativeReportCriteria != nil {
		enc_cumulativereportcriteria, err := v.CumulativeReportCriteria.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding cumulativeReportCriteria: %w", err)
		}
		enc_cumulativereportcriteria = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 19, true, enc_cumulativereportcriteria)
		children = append(children, enc_cumulativereportcriteria...)
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

// MarshalDER encodes LCSPeriodicTriggeredInvokeArg to DER format.
func (v *LCSPeriodicTriggeredInvokeArg) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// ITU-T X.690 (02/2021) Section 10.1 requires DER length forms to be definite.
	derValue := *v
	derValue.MultiplePositioningProtocolPDUsIndef_ = false
	derValue.EventReportAllowedAreaIndef_ = false
	v = &derValue
	return v.MarshalBER()
}

// UnmarshalBER decodes LCSPeriodicTriggeredInvokeArg from BER/DER format.
func (v *LCSPeriodicTriggeredInvokeArg) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding LCSPeriodicTriggeredInvokeArg SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "LCSPeriodicTriggeredInvokeArg", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode referenceNumber
	if offset >= len(content) {
		return fmt.Errorf("missing required field referenceNumber")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 0 {
			return fmt.Errorf("expected tag [%s %d] for referenceNumber, got %s", "CONTEXT", 0, reqTag_)
		}
	}
	_, n_referencenumber, rawVal_referencenumber, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding referenceNumber: %w", err)
	}
	v.ReferenceNumber = LCSReferenceNumber(rawVal_referencenumber)
	offset += n_referencenumber
	// Decode h-gmlc-address
	if offset >= len(content) {
		return fmt.Errorf("missing required field h-gmlc-address")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 1 {
			return fmt.Errorf("expected tag [%s %d] for h-gmlc-address, got %s", "CONTEXT", 1, reqTag_)
		}
	}
	_, n_hgmlcaddress, rawVal_hgmlcaddress, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding h-gmlc-address: %w", err)
	}
	v.HGmlcAddress = GSNAddress(rawVal_hgmlcaddress)
	offset += n_hgmlcaddress
	// Decode qoS
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2 {
				_, n_qos, rawVal_qos, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding qoS: %w", err)
				}
				reconstructed_qos := ber.EncodeSequence(rawVal_qos)
				var dec_qos LCSQoS
				if unmErr := dec_qos.UnmarshalBER(reconstructed_qos); unmErr != nil {
					return fmt.Errorf("decoding qoS: %w", unmErr)
				}
				v.QoS = &dec_qos
				offset += n_qos
			}
		}
	}
	// Decode reportingPLMNList
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3 {
				_, n_reportingplmnlist, rawVal_reportingplmnlist, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding reportingPLMNList: %w", err)
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
	// Decode periodicLocation
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4 {
				_, n_periodiclocation, rawVal_periodiclocation, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding periodicLocation: %w", err)
				}
				reconstructed_periodiclocation := ber.EncodeSequence(rawVal_periodiclocation)
				var dec_periodiclocation PeriodicLocation
				if unmErr := dec_periodiclocation.UnmarshalBER(reconstructed_periodiclocation); unmErr != nil {
					return fmt.Errorf("decoding periodicLocation: %w", unmErr)
				}
				v.PeriodicLocation = &dec_periodiclocation
				offset += n_periodiclocation
			}
		}
	}
	// Decode areaEventReporting
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 5 {
				_, n_areaeventreporting, rawVal_areaeventreporting, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding areaEventReporting: %w", err)
				}
				reconstructed_areaeventreporting := ber.EncodeSequence(rawVal_areaeventreporting)
				var dec_areaeventreporting AreaEventReporting
				if unmErr := dec_areaeventreporting.UnmarshalBER(reconstructed_areaeventreporting); unmErr != nil {
					return fmt.Errorf("decoding areaEventReporting: %w", unmErr)
				}
				v.AreaEventReporting = &dec_areaeventreporting
				offset += n_areaeventreporting
			}
		}
	}
	// Decode motionEventReporting
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 6 {
				_, n_motioneventreporting, rawVal_motioneventreporting, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding motionEventReporting: %w", err)
				}
				reconstructed_motioneventreporting := ber.EncodeSequence(rawVal_motioneventreporting)
				var dec_motioneventreporting MotionEventReporting
				if unmErr := dec_motioneventreporting.UnmarshalBER(reconstructed_motioneventreporting); unmErr != nil {
					return fmt.Errorf("decoding motionEventReporting: %w", unmErr)
				}
				v.MotionEventReporting = &dec_motioneventreporting
				offset += n_motioneventreporting
			}
		}
	}
	// Decode referenceNumberExt
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 7 {
				_, n_referencenumberext, rawVal_referencenumberext, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding referenceNumberExt: %w", err)
				}
				tmp_referencenumberext := LCSReferenceNumberExt(rawVal_referencenumberext)
				v.ReferenceNumberExt = &tmp_referencenumberext
				offset += n_referencenumberext
			}
		}
	}
	// Decode h-gmlc-callBackUri
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 8 {
				_, n_hgmlccallbackuri, rawVal_hgmlccallbackuri, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding h-gmlc-callBackUri: %w", err)
				}
				decVal_hgmlccallbackuri, stringErr := ber.DecodeStringValueTag(12, rawVal_hgmlccallbackuri)
				if stringErr != nil {
					return fmt.Errorf("decoding h-gmlc-callBackUri: %w", stringErr)
				}
				v.HGmlcCallBackUri = &decVal_hgmlccallbackuri
				offset += n_hgmlccallbackuri
			}
		}
	}
	// Decode supportedGADShapes
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 9 {
				_, n_supportedgadshapes, rawVal_supportedgadshapes, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding supportedGADShapes: %w", err)
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
	// Decode deferredRoutingIdentifier
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 10 {
				_, n_deferredroutingidentifier, rawVal_deferredroutingidentifier, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding deferredRoutingIdentifier: %w", err)
				}
				tmp_deferredroutingidentifier := rawVal_deferredroutingidentifier
				v.DeferredRoutingIdentifier = tmp_deferredroutingidentifier
				offset += n_deferredroutingidentifier
			}
		}
	}
	// Decode reportingAccessTypes
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 11 {
				_, n_reportingaccesstypes, rawVal_reportingaccesstypes, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding reportingAccessTypes: %w", err)
				}
				bsBytes_reportingaccesstypes, bsUnused_reportingaccesstypes, bsErr := ber.DecodeBitStringValue(rawVal_reportingaccesstypes)
				if bsErr != nil {
					return fmt.Errorf("decoding reportingAccessTypes: %w", bsErr)
				}
				tmp_reportingaccesstypes := runtime.BitString{Bytes: bsBytes_reportingaccesstypes, BitLength: len(bsBytes_reportingaccesstypes)*8 - bsUnused_reportingaccesstypes}
				v.ReportingAccessTypes = &tmp_reportingaccesstypes
				offset += n_reportingaccesstypes
			}
		}
	}
	// Decode multiplePositioningProtocolPDUs
	v.MultiplePositioningProtocolPDUsIndef_ = false
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 12 {
				_, n_multiplepositioningprotocolpdus, rawVal_multiplepositioningprotocolpdus, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding multiplePositioningProtocolPDUs: %w", err)
				}
				reconstructed_multiplepositioningprotocolpdus := ber.EncodeSequence(rawVal_multiplepositioningprotocolpdus)
				dec_multiplepositioningprotocolpdus, unmErr := UnmarshalBERMultiplePositioningProtocolPDUs(reconstructed_multiplepositioningprotocolpdus)
				if unmErr != nil {
					return fmt.Errorf("decoding multiplePositioningProtocolPDUs: %w", unmErr)
				}
				v.MultiplePositioningProtocolPDUs = dec_multiplepositioningprotocolpdus
				{
					_, tagSz_, _ := ber.DecodeTag(content[offset:])
					if offset+tagSz_ < len(content) && content[offset+tagSz_] == 0x80 {
						v.MultiplePositioningProtocolPDUsIndef_ = true
					}
				}
				offset += n_multiplepositioningprotocolpdus
			}
		}
	}
	// Decode controlPlane-CIoT-5GS-Optimisation
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 13 {
				_, n_controlplaneciot5gsoptimisation, rawVal_controlplaneciot5gsoptimisation, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding controlPlane-CIoT-5GS-Optimisation: %w", err)
				}
				reconstructed_controlplaneciot5gsoptimisation := ber.EncodeSequence(rawVal_controlplaneciot5gsoptimisation)
				var dec_controlplaneciot5gsoptimisation ControlPlaneCIoT5GSOptimisation
				if unmErr := dec_controlplaneciot5gsoptimisation.UnmarshalBER(reconstructed_controlplaneciot5gsoptimisation); unmErr != nil {
					return fmt.Errorf("decoding controlPlane-CIoT-5GS-Optimisation: %w", unmErr)
				}
				v.ControlPlaneCIoT5GSOptimisation = &dec_controlplaneciot5gsoptimisation
				offset += n_controlplaneciot5gsoptimisation
			}
		}
	}
	// Decode scheduledLocTime
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 14 {
				_, n_scheduledloctime, rawVal_scheduledloctime, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding scheduledLocTime: %w", err)
				}
				tmp_scheduledloctime := DateTime(rawVal_scheduledloctime)
				v.ScheduledLocTime = &tmp_scheduledloctime
				offset += n_scheduledloctime
			}
		}
	}
	// Decode eventReportAllowedArea
	v.EventReportAllowedAreaIndef_ = false
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 15 {
				_, n_eventreportallowedarea, rawVal_eventreportallowedarea, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding eventReportAllowedArea: %w", err)
				}
				reconstructed_eventreportallowedarea := ber.EncodeSequence(rawVal_eventreportallowedarea)
				dec_eventreportallowedarea, unmErr := UnmarshalBERDataTypesAreaList(reconstructed_eventreportallowedarea)
				if unmErr != nil {
					return fmt.Errorf("decoding eventReportAllowedArea: %w", unmErr)
				}
				v.EventReportAllowedArea = dec_eventreportallowedarea
				{
					_, tagSz_, _ := ber.DecodeTag(content[offset:])
					if offset+tagSz_ < len(content) && content[offset+tagSz_] == 0x80 {
						v.EventReportAllowedAreaIndef_ = true
					}
				}
				offset += n_eventreportallowedarea
			}
		}
	}
	// Decode reportingInd
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 16 {
				_, n_reportingind, rawVal_reportingind, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding reportingInd: %w", err)
				}
				decVal_reportingind, intErr := ber.DecodeIntegerValue(rawVal_reportingind)
				if intErr != nil {
					return fmt.Errorf("decoding reportingInd: %w", intErr)
				}
				tmp_reportingind := ReportingInd(decVal_reportingind)
				v.ReportingInd = &tmp_reportingind
				offset += n_reportingind
			}
		}
	}
	// Decode mappedQoS
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 17 {
				_, n_mappedqos, rawVal_mappedqos, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding mappedQoS: %w", err)
				}
				reconstructed_mappedqos := ber.EncodeSequence(rawVal_mappedqos)
				var dec_mappedqos LCSQoS
				if unmErr := dec_mappedqos.UnmarshalBER(reconstructed_mappedqos); unmErr != nil {
					return fmt.Errorf("decoding mappedQoS: %w", unmErr)
				}
				v.MappedQoS = &dec_mappedqos
				offset += n_mappedqos
			}
		}
	}
	// Decode userPlaneReportAFAddr
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 18 {
				_, n_userplanereportafaddr, rawVal_userplanereportafaddr, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding userPlaneReportAFAddr: %w", err)
				}
				reconstructed_userplanereportafaddr := ber.EncodeSequence(rawVal_userplanereportafaddr)
				var dec_userplanereportafaddr LCSUserPlaneReportAFAddr
				if unmErr := dec_userplanereportafaddr.UnmarshalBER(reconstructed_userplanereportafaddr); unmErr != nil {
					return fmt.Errorf("decoding userPlaneReportAFAddr: %w", unmErr)
				}
				v.UserPlaneReportAFAddr = &dec_userplanereportafaddr
				offset += n_userplanereportafaddr
			}
		}
	}
	// Decode cumulativeReportCriteria
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 19 {
				_, n_cumulativereportcriteria, rawVal_cumulativereportcriteria, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding cumulativeReportCriteria: %w", err)
				}
				reconstructed_cumulativereportcriteria := ber.EncodeSequence(rawVal_cumulativereportcriteria)
				var dec_cumulativereportcriteria LCSCumulativeReportCriteria
				if unmErr := dec_cumulativereportcriteria.UnmarshalBER(reconstructed_cumulativereportcriteria); unmErr != nil {
					return fmt.Errorf("decoding cumulativeReportCriteria: %w", unmErr)
				}
				v.CumulativeReportCriteria = &dec_cumulativereportcriteria
				offset += n_cumulativereportcriteria
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "LCSPeriodicTriggeredInvokeArg", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes PeriodicLocation to BER format.
func (v *PeriodicLocation) MarshalBER() ([]byte, error) {
	var children []byte
	enc_periodicldrinfo, err := v.PeriodicLDRInfo.MarshalBER()
	if err != nil {
		return nil, fmt.Errorf("encoding periodicLDRInfo: %w", err)
	}
	enc_periodicldrinfo = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, true, enc_periodicldrinfo)
	children = append(children, enc_periodicldrinfo...)
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

// MarshalDER encodes PeriodicLocation to DER format.
func (v *PeriodicLocation) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes PeriodicLocation from BER/DER format.
func (v *PeriodicLocation) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding PeriodicLocation SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "PeriodicLocation", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode periodicLDRInfo
	if offset >= len(content) {
		return fmt.Errorf("missing required field periodicLDRInfo")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 0 {
			return fmt.Errorf("expected tag [%s %d] for periodicLDRInfo, got %s", "CONTEXT", 0, reqTag_)
		}
	}
	_, n_periodicldrinfo, rawVal_periodicldrinfo, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding periodicLDRInfo: %w", err)
	}
	reconstructed_periodicldrinfo := ber.EncodeSequence(rawVal_periodicldrinfo)
	if unmErr := v.PeriodicLDRInfo.UnmarshalBER(reconstructed_periodicldrinfo); unmErr != nil {
		return fmt.Errorf("decoding periodicLDRInfo: %w", unmErr)
	}
	offset += n_periodicldrinfo
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "PeriodicLocation", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes AreaEventReporting to BER format.
func (v *AreaEventReporting) MarshalBER() ([]byte, error) {
	var children []byte
	enc_deferredlocationeventtype := ber.EncodeBitString(v.DeferredLocationEventType.Bytes, (8-(v.DeferredLocationEventType.BitLength%8))%8)
	enc_deferredlocationeventtype = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, false, enc_deferredlocationeventtype)
	children = append(children, enc_deferredlocationeventtype...)
	enc_arealist, err := MarshalBERDataTypesAreaList(v.AreaList)
	if err != nil {
		return nil, fmt.Errorf("encoding areaList: %w", err)
	}
	if v.AreaListIndef_ {
		// Strip the outer SEQUENCE tag from marshalBER output to get raw children.
		_, _, seqContent_, tlvErr_ := ber.DecodeTLV(enc_arealist)
		if tlvErr_ != nil {
			return nil, tlvErr_
		}
		enc_arealist = ber.EncodeConstructedIndefinite(tag.Tag{Class: tag.ClassContextSpecific, Number: 1}, seqContent_)
	} else {
		enc_arealist = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, true, enc_arealist)
	}
	children = append(children, enc_arealist...)
	if v.OccurrenceInfo != nil {
		enc_occurrenceinfo := ber.EncodeEnumerated(int64(*v.OccurrenceInfo))
		enc_occurrenceinfo = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, false, enc_occurrenceinfo)
		children = append(children, enc_occurrenceinfo...)
	}
	if v.IntervalTime != nil {
		enc_intervaltime := ber.EncodeInteger(int64(*v.IntervalTime))
		enc_intervaltime = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, false, enc_intervaltime)
		children = append(children, enc_intervaltime...)
	}
	if v.MaximumInterval != nil {
		enc_maximuminterval := ber.EncodeInteger(int64(*v.MaximumInterval))
		enc_maximuminterval = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, false, enc_maximuminterval)
		children = append(children, enc_maximuminterval...)
	}
	if v.SamplingInterval != nil {
		enc_samplinginterval := ber.EncodeInteger(int64(*v.SamplingInterval))
		enc_samplinginterval = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 5, false, enc_samplinginterval)
		children = append(children, enc_samplinginterval...)
	}
	if v.Duration != nil {
		enc_duration := ber.EncodeInteger(int64(*v.Duration))
		enc_duration = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 6, false, enc_duration)
		children = append(children, enc_duration...)
	}
	if v.LocationInfo != nil {
		enc_locationinfo := ber.EncodeBitString(v.LocationInfo.Bytes, (8-(v.LocationInfo.BitLength%8))%8)
		enc_locationinfo = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 7, false, enc_locationinfo)
		children = append(children, enc_locationinfo...)
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

// MarshalDER encodes AreaEventReporting to DER format.
func (v *AreaEventReporting) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// ITU-T X.690 (02/2021) Section 10.1 requires DER length forms to be definite.
	derValue := *v
	derValue.AreaListIndef_ = false
	v = &derValue
	return v.MarshalBER()
}

// UnmarshalBER decodes AreaEventReporting from BER/DER format.
func (v *AreaEventReporting) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding AreaEventReporting SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "AreaEventReporting", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode deferredLocationEventType
	if offset >= len(content) {
		return fmt.Errorf("missing required field deferredLocationEventType")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 0 {
			return fmt.Errorf("expected tag [%s %d] for deferredLocationEventType, got %s", "CONTEXT", 0, reqTag_)
		}
	}
	_, n_deferredlocationeventtype, rawVal_deferredlocationeventtype, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding deferredLocationEventType: %w", err)
	}
	bsBytes_deferredlocationeventtype, bsUnused_deferredlocationeventtype, bsErr := ber.DecodeBitStringValue(rawVal_deferredlocationeventtype)
	if bsErr != nil {
		return fmt.Errorf("decoding deferredLocationEventType: %w", bsErr)
	}
	v.DeferredLocationEventType = runtime.BitString{Bytes: bsBytes_deferredlocationeventtype, BitLength: len(bsBytes_deferredlocationeventtype)*8 - bsUnused_deferredlocationeventtype}
	offset += n_deferredlocationeventtype
	// Decode areaList
	if offset >= len(content) {
		return fmt.Errorf("missing required field areaList")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 1 {
			return fmt.Errorf("expected tag [%s %d] for areaList, got %s", "CONTEXT", 1, reqTag_)
		}
	}
	v.AreaListIndef_ = false
	_, n_arealist, rawVal_arealist, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding areaList: %w", err)
	}
	reconstructed_arealist := ber.EncodeSequence(rawVal_arealist)
	dec_arealist, unmErr := UnmarshalBERDataTypesAreaList(reconstructed_arealist)
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
	// Decode occurrenceInfo
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2 {
				_, n_occurrenceinfo, rawVal_occurrenceinfo, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding occurrenceInfo: %w", err)
				}
				decVal_occurrenceinfo, intErr := ber.DecodeIntegerValue(rawVal_occurrenceinfo)
				if intErr != nil {
					return fmt.Errorf("decoding occurrenceInfo: %w", intErr)
				}
				tmp_occurrenceinfo := DataTypesOccurrenceInfo(decVal_occurrenceinfo)
				v.OccurrenceInfo = &tmp_occurrenceinfo
				offset += n_occurrenceinfo
			}
		}
	}
	// Decode intervalTime
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3 {
				_, n_intervaltime, rawVal_intervaltime, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding intervalTime: %w", err)
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
	// Decode maximumInterval
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4 {
				_, n_maximuminterval, rawVal_maximuminterval, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding maximumInterval: %w", err)
				}
				decVal_maximuminterval, intErr := ber.DecodeIntegerValue(rawVal_maximuminterval)
				if intErr != nil {
					return fmt.Errorf("decoding maximumInterval: %w", intErr)
				}
				tmp_maximuminterval := MaximumInterval(decVal_maximuminterval)
				v.MaximumInterval = &tmp_maximuminterval
				offset += n_maximuminterval
			}
		}
	}
	// Decode samplingInterval
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 5 {
				_, n_samplinginterval, rawVal_samplinginterval, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding samplingInterval: %w", err)
				}
				decVal_samplinginterval, intErr := ber.DecodeIntegerValue(rawVal_samplinginterval)
				if intErr != nil {
					return fmt.Errorf("decoding samplingInterval: %w", intErr)
				}
				tmp_samplinginterval := SamplingInterval(decVal_samplinginterval)
				v.SamplingInterval = &tmp_samplinginterval
				offset += n_samplinginterval
			}
		}
	}
	// Decode duration
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 6 {
				_, n_duration, rawVal_duration, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding duration: %w", err)
				}
				decVal_duration, intErr := ber.DecodeIntegerValue(rawVal_duration)
				if intErr != nil {
					return fmt.Errorf("decoding duration: %w", intErr)
				}
				tmp_duration := Duration(decVal_duration)
				v.Duration = &tmp_duration
				offset += n_duration
			}
		}
	}
	// Decode locationInfo
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 7 {
				_, n_locationinfo, rawVal_locationinfo, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding locationInfo: %w", err)
				}
				bsBytes_locationinfo, bsUnused_locationinfo, bsErr := ber.DecodeBitStringValue(rawVal_locationinfo)
				if bsErr != nil {
					return fmt.Errorf("decoding locationInfo: %w", bsErr)
				}
				tmp_locationinfo := runtime.BitString{Bytes: bsBytes_locationinfo, BitLength: len(bsBytes_locationinfo)*8 - bsUnused_locationinfo}
				v.LocationInfo = &tmp_locationinfo
				offset += n_locationinfo
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "AreaEventReporting", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBERDataTypesAreaList encodes a DataTypesAreaList list to BER.
func MarshalBERDataTypesAreaList(list DataTypesAreaList) ([]byte, error) {
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

// UnmarshalBERDataTypesAreaList decodes a DataTypesAreaList list from BER.
func UnmarshalBERDataTypesAreaList(data []byte) (DataTypesAreaList, error) {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return nil, fmt.Errorf("decoding DataTypesAreaList: %w", err)
	}
	if total != len(data) {
		return nil, &ber.DecodeError{Offset: total, TypeName: "DataTypesAreaList", Cause: ber.ErrExtraData}
	}
	var result DataTypesAreaList
	offset := 0
	for offset < len(content) {
		var elem DataTypesArea
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

// MarshalBER encodes DataTypesArea to BER format.
func (v *DataTypesArea) MarshalBER() ([]byte, error) {
	var children []byte
	enc_areatype := ber.EncodeEnumerated(int64(v.AreaType))
	enc_areatype = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, false, enc_areatype)
	children = append(children, enc_areatype...)
	enc_areaidentification := ber.EncodeOctetString([]byte(v.AreaIdentification))
	enc_areaidentification = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, false, enc_areaidentification)
	children = append(children, enc_areaidentification...)
	if v.AreaIdentificationExt != nil {
		enc_areaidentificationext := ber.EncodeOctetString([]byte(*v.AreaIdentificationExt))
		enc_areaidentificationext = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, false, enc_areaidentificationext)
		children = append(children, enc_areaidentificationext...)
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

// MarshalDER encodes DataTypesArea to DER format.
func (v *DataTypesArea) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes DataTypesArea from BER/DER format.
func (v *DataTypesArea) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding DataTypesArea SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "DataTypesArea", Cause: ber.ErrExtraData}
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
	_, n_areatype, rawVal_areatype, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding areaType: %w", err)
	}
	decVal_areatype, intErr := ber.DecodeIntegerValue(rawVal_areatype)
	if intErr != nil {
		return fmt.Errorf("decoding areaType: %w", intErr)
	}
	v.AreaType = DataTypesAreaType(decVal_areatype)
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
	_, n_areaidentification, rawVal_areaidentification, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding areaIdentification: %w", err)
	}
	v.AreaIdentification = DataTypesAreaIdentification(rawVal_areaidentification)
	offset += n_areaidentification
	// Decode areaIdentificationExt
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2 {
				_, n_areaidentificationext, rawVal_areaidentificationext, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding areaIdentificationExt: %w", err)
				}
				tmp_areaidentificationext := AreaIdentificationExt(rawVal_areaidentificationext)
				v.AreaIdentificationExt = &tmp_areaidentificationext
				offset += n_areaidentificationext
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "DataTypesArea", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes MotionEventReporting to BER format.
func (v *MotionEventReporting) MarshalBER() ([]byte, error) {
	var children []byte
	enc_lineardistance := ber.EncodeInteger(int64(v.LinearDistance))
	enc_lineardistance = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, false, enc_lineardistance)
	children = append(children, enc_lineardistance...)
	if v.OccurrenceInfo != nil {
		enc_occurrenceinfo := ber.EncodeEnumerated(int64(*v.OccurrenceInfo))
		enc_occurrenceinfo = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, false, enc_occurrenceinfo)
		children = append(children, enc_occurrenceinfo...)
	}
	if v.IntervalTime != nil {
		enc_intervaltime := ber.EncodeInteger(int64(*v.IntervalTime))
		enc_intervaltime = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, false, enc_intervaltime)
		children = append(children, enc_intervaltime...)
	}
	if v.MaximumInterval != nil {
		enc_maximuminterval := ber.EncodeInteger(int64(*v.MaximumInterval))
		enc_maximuminterval = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, false, enc_maximuminterval)
		children = append(children, enc_maximuminterval...)
	}
	if v.SamplingInterval != nil {
		enc_samplinginterval := ber.EncodeInteger(int64(*v.SamplingInterval))
		enc_samplinginterval = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, false, enc_samplinginterval)
		children = append(children, enc_samplinginterval...)
	}
	if v.Duration != nil {
		enc_duration := ber.EncodeInteger(int64(*v.Duration))
		enc_duration = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 5, false, enc_duration)
		children = append(children, enc_duration...)
	}
	if v.LocationInfo != nil {
		enc_locationinfo := ber.EncodeBitString(v.LocationInfo.Bytes, (8-(v.LocationInfo.BitLength%8))%8)
		enc_locationinfo = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 6, false, enc_locationinfo)
		children = append(children, enc_locationinfo...)
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

// MarshalDER encodes MotionEventReporting to DER format.
func (v *MotionEventReporting) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes MotionEventReporting from BER/DER format.
func (v *MotionEventReporting) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding MotionEventReporting SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "MotionEventReporting", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode linearDistance
	if offset >= len(content) {
		return fmt.Errorf("missing required field linearDistance")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 0 {
			return fmt.Errorf("expected tag [%s %d] for linearDistance, got %s", "CONTEXT", 0, reqTag_)
		}
	}
	_, n_lineardistance, rawVal_lineardistance, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding linearDistance: %w", err)
	}
	decVal_lineardistance, intErr := ber.DecodeIntegerValue(rawVal_lineardistance)
	if intErr != nil {
		return fmt.Errorf("decoding linearDistance: %w", intErr)
	}
	v.LinearDistance = LinearDistance(decVal_lineardistance)
	offset += n_lineardistance
	// Decode occurrenceInfo
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
				_, n_occurrenceinfo, rawVal_occurrenceinfo, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding occurrenceInfo: %w", err)
				}
				decVal_occurrenceinfo, intErr := ber.DecodeIntegerValue(rawVal_occurrenceinfo)
				if intErr != nil {
					return fmt.Errorf("decoding occurrenceInfo: %w", intErr)
				}
				tmp_occurrenceinfo := DataTypesOccurrenceInfo(decVal_occurrenceinfo)
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
				_, n_intervaltime, rawVal_intervaltime, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding intervalTime: %w", err)
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
	// Decode maximumInterval
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3 {
				_, n_maximuminterval, rawVal_maximuminterval, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding maximumInterval: %w", err)
				}
				decVal_maximuminterval, intErr := ber.DecodeIntegerValue(rawVal_maximuminterval)
				if intErr != nil {
					return fmt.Errorf("decoding maximumInterval: %w", intErr)
				}
				tmp_maximuminterval := MaximumInterval(decVal_maximuminterval)
				v.MaximumInterval = &tmp_maximuminterval
				offset += n_maximuminterval
			}
		}
	}
	// Decode samplingInterval
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4 {
				_, n_samplinginterval, rawVal_samplinginterval, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding samplingInterval: %w", err)
				}
				decVal_samplinginterval, intErr := ber.DecodeIntegerValue(rawVal_samplinginterval)
				if intErr != nil {
					return fmt.Errorf("decoding samplingInterval: %w", intErr)
				}
				tmp_samplinginterval := SamplingInterval(decVal_samplinginterval)
				v.SamplingInterval = &tmp_samplinginterval
				offset += n_samplinginterval
			}
		}
	}
	// Decode duration
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 5 {
				_, n_duration, rawVal_duration, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding duration: %w", err)
				}
				decVal_duration, intErr := ber.DecodeIntegerValue(rawVal_duration)
				if intErr != nil {
					return fmt.Errorf("decoding duration: %w", intErr)
				}
				tmp_duration := Duration(decVal_duration)
				v.Duration = &tmp_duration
				offset += n_duration
			}
		}
	}
	// Decode locationInfo
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 6 {
				_, n_locationinfo, rawVal_locationinfo, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding locationInfo: %w", err)
				}
				bsBytes_locationinfo, bsUnused_locationinfo, bsErr := ber.DecodeBitStringValue(rawVal_locationinfo)
				if bsErr != nil {
					return fmt.Errorf("decoding locationInfo: %w", bsErr)
				}
				tmp_locationinfo := runtime.BitString{Bytes: bsBytes_locationinfo, BitLength: len(bsBytes_locationinfo)*8 - bsUnused_locationinfo}
				v.LocationInfo = &tmp_locationinfo
				offset += n_locationinfo
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "MotionEventReporting", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes LCSPeriodicTriggeredInvokeRes to BER format.
func (v *LCSPeriodicTriggeredInvokeRes) MarshalBER() ([]byte, error) {
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

// MarshalDER encodes LCSPeriodicTriggeredInvokeRes to DER format.
func (v *LCSPeriodicTriggeredInvokeRes) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes LCSPeriodicTriggeredInvokeRes from BER/DER format.
func (v *LCSPeriodicTriggeredInvokeRes) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding LCSPeriodicTriggeredInvokeRes SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "LCSPeriodicTriggeredInvokeRes", Cause: ber.ErrExtraData}
	}
	offset := 0
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "LCSPeriodicTriggeredInvokeRes", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes LCSEventReportArg to BER format.
func (v *LCSEventReportArg) MarshalBER() ([]byte, error) {
	var children []byte
	enc_eventtype := ber.EncodeEnumerated(int64(v.EventType))
	enc_eventtype = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, false, enc_eventtype)
	children = append(children, enc_eventtype...)
	enc_referencenumberext := ber.EncodeOctetString([]byte(v.ReferenceNumberExt))
	enc_referencenumberext = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, false, enc_referencenumberext)
	children = append(children, enc_referencenumberext...)
	enc_hgmlccallbackuri, stringErr := ber.EncodeStringTagChecked(12, v.HGmlcCallBackUri)
	if stringErr != nil {
		return nil, fmt.Errorf("encoding h-gmlc-callBackUri: %w", stringErr)
	}
	enc_hgmlccallbackuri = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, false, enc_hgmlccallbackuri)
	children = append(children, enc_hgmlccallbackuri...)
	if v.LocationInfo != nil {
		enc_locationinfo := ber.EncodeBitString(v.LocationInfo.Bytes, (8-(v.LocationInfo.BitLength%8))%8)
		enc_locationinfo = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, false, enc_locationinfo)
		children = append(children, enc_locationinfo...)
	}
	if v.SupportedGADShapes != nil {
		enc_supportedgadshapes := ber.EncodeBitString(v.SupportedGADShapes.Bytes, (8-(v.SupportedGADShapes.BitLength%8))%8)
		enc_supportedgadshapes = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, false, enc_supportedgadshapes)
		children = append(children, enc_supportedgadshapes...)
	}
	if v.LcsQoS != nil {
		enc_lcsqos, err := v.LcsQoS.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding lcs-QoS: %w", err)
		}
		enc_lcsqos = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 5, true, enc_lcsqos)
		children = append(children, enc_lcsqos...)
	}
	if v.MultiplePositioningProtocolPDUs != nil {
		enc_multiplepositioningprotocolpdus, err := MarshalBERMultiplePositioningProtocolPDUs(v.MultiplePositioningProtocolPDUs)
		if err != nil {
			return nil, fmt.Errorf("encoding multiplePositioningProtocolPDUs: %w", err)
		}
		if v.MultiplePositioningProtocolPDUsIndef_ {
			// Strip the outer SEQUENCE tag from marshalBER output to get raw children.
			_, _, seqContent_, tlvErr_ := ber.DecodeTLV(enc_multiplepositioningprotocolpdus)
			if tlvErr_ != nil {
				return nil, tlvErr_
			}
			enc_multiplepositioningprotocolpdus = ber.EncodeConstructedIndefinite(tag.Tag{Class: tag.ClassContextSpecific, Number: 6}, seqContent_)
		} else {
			enc_multiplepositioningprotocolpdus = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 6, true, enc_multiplepositioningprotocolpdus)
		}
		children = append(children, enc_multiplepositioningprotocolpdus...)
	}
	if v.TerminationCause != nil {
		enc_terminationcause := ber.EncodeEnumerated(int64(*v.TerminationCause))
		enc_terminationcause = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 7, false, enc_terminationcause)
		children = append(children, enc_terminationcause...)
	}
	if v.UserPlaneEventReportStat != nil {
		enc_userplaneeventreportstat := ber.EncodeInteger(int64(*v.UserPlaneEventReportStat))
		enc_userplaneeventreportstat = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 8, false, enc_userplaneeventreportstat)
		children = append(children, enc_userplaneeventreportstat...)
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

// MarshalDER encodes LCSEventReportArg to DER format.
func (v *LCSEventReportArg) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// ITU-T X.690 (02/2021) Section 10.1 requires DER length forms to be definite.
	derValue := *v
	derValue.MultiplePositioningProtocolPDUsIndef_ = false
	v = &derValue
	return v.MarshalBER()
}

// UnmarshalBER decodes LCSEventReportArg from BER/DER format.
func (v *LCSEventReportArg) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding LCSEventReportArg SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "LCSEventReportArg", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode eventType
	if offset >= len(content) {
		return fmt.Errorf("missing required field eventType")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 0 {
			return fmt.Errorf("expected tag [%s %d] for eventType, got %s", "CONTEXT", 0, reqTag_)
		}
	}
	_, n_eventtype, rawVal_eventtype, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding eventType: %w", err)
	}
	decVal_eventtype, intErr := ber.DecodeIntegerValue(rawVal_eventtype)
	if intErr != nil {
		return fmt.Errorf("decoding eventType: %w", intErr)
	}
	v.EventType = EventType(decVal_eventtype)
	offset += n_eventtype
	// Decode referenceNumberExt
	if offset >= len(content) {
		return fmt.Errorf("missing required field referenceNumberExt")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 1 {
			return fmt.Errorf("expected tag [%s %d] for referenceNumberExt, got %s", "CONTEXT", 1, reqTag_)
		}
	}
	_, n_referencenumberext, rawVal_referencenumberext, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding referenceNumberExt: %w", err)
	}
	v.ReferenceNumberExt = LCSReferenceNumberExt(rawVal_referencenumberext)
	offset += n_referencenumberext
	// Decode h-gmlc-callBackUri
	if offset >= len(content) {
		return fmt.Errorf("missing required field h-gmlc-callBackUri")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 2 {
			return fmt.Errorf("expected tag [%s %d] for h-gmlc-callBackUri, got %s", "CONTEXT", 2, reqTag_)
		}
	}
	_, n_hgmlccallbackuri, rawVal_hgmlccallbackuri, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding h-gmlc-callBackUri: %w", err)
	}
	decVal_hgmlccallbackuri, stringErr := ber.DecodeStringValueTag(12, rawVal_hgmlccallbackuri)
	if stringErr != nil {
		return fmt.Errorf("decoding h-gmlc-callBackUri: %w", stringErr)
	}
	v.HGmlcCallBackUri = decVal_hgmlccallbackuri
	offset += n_hgmlccallbackuri
	// Decode locationInfo
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3 {
				_, n_locationinfo, rawVal_locationinfo, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding locationInfo: %w", err)
				}
				bsBytes_locationinfo, bsUnused_locationinfo, bsErr := ber.DecodeBitStringValue(rawVal_locationinfo)
				if bsErr != nil {
					return fmt.Errorf("decoding locationInfo: %w", bsErr)
				}
				tmp_locationinfo := runtime.BitString{Bytes: bsBytes_locationinfo, BitLength: len(bsBytes_locationinfo)*8 - bsUnused_locationinfo}
				v.LocationInfo = &tmp_locationinfo
				offset += n_locationinfo
			}
		}
	}
	// Decode supportedGADShapes
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4 {
				_, n_supportedgadshapes, rawVal_supportedgadshapes, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding supportedGADShapes: %w", err)
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
	// Decode lcs-QoS
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 5 {
				_, n_lcsqos, rawVal_lcsqos, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding lcs-QoS: %w", err)
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
	// Decode multiplePositioningProtocolPDUs
	v.MultiplePositioningProtocolPDUsIndef_ = false
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 6 {
				_, n_multiplepositioningprotocolpdus, rawVal_multiplepositioningprotocolpdus, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding multiplePositioningProtocolPDUs: %w", err)
				}
				reconstructed_multiplepositioningprotocolpdus := ber.EncodeSequence(rawVal_multiplepositioningprotocolpdus)
				dec_multiplepositioningprotocolpdus, unmErr := UnmarshalBERMultiplePositioningProtocolPDUs(reconstructed_multiplepositioningprotocolpdus)
				if unmErr != nil {
					return fmt.Errorf("decoding multiplePositioningProtocolPDUs: %w", unmErr)
				}
				v.MultiplePositioningProtocolPDUs = dec_multiplepositioningprotocolpdus
				{
					_, tagSz_, _ := ber.DecodeTag(content[offset:])
					if offset+tagSz_ < len(content) && content[offset+tagSz_] == 0x80 {
						v.MultiplePositioningProtocolPDUsIndef_ = true
					}
				}
				offset += n_multiplepositioningprotocolpdus
			}
		}
	}
	// Decode terminationCause
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 7 {
				_, n_terminationcause, rawVal_terminationcause, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding terminationCause: %w", err)
				}
				decVal_terminationcause, intErr := ber.DecodeIntegerValue(rawVal_terminationcause)
				if intErr != nil {
					return fmt.Errorf("decoding terminationCause: %w", intErr)
				}
				tmp_terminationcause := DataTypesTerminationCause(decVal_terminationcause)
				v.TerminationCause = &tmp_terminationcause
				offset += n_terminationcause
			}
		}
	}
	// Decode userPlaneEventReportStat
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 8 {
				_, n_userplaneeventreportstat, rawVal_userplaneeventreportstat, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding userPlaneEventReportStat: %w", err)
				}
				decVal_userplaneeventreportstat, intErr := ber.DecodeIntegerValue(rawVal_userplaneeventreportstat)
				if intErr != nil {
					return fmt.Errorf("decoding userPlaneEventReportStat: %w", intErr)
				}
				tmp_userplaneeventreportstat := LCSUserPlaneEventReportStat(decVal_userplaneeventreportstat)
				v.UserPlaneEventReportStat = &tmp_userplaneeventreportstat
				offset += n_userplaneeventreportstat
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "LCSEventReportArg", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes ControlPlaneCIoT5GSOptimisation to BER format.
func (v *ControlPlaneCIoT5GSOptimisation) MarshalBER() ([]byte, error) {
	var children []byte
	if v.MaximumDuration != nil {
		enc_maximumduration := ber.EncodeInteger(int64(*v.MaximumDuration))
		enc_maximumduration = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, false, enc_maximumduration)
		children = append(children, enc_maximumduration...)
	}
	if v.MaximumConsecutiveEventReports != nil {
		enc_maximumconsecutiveeventreports := ber.EncodeInteger(int64(*v.MaximumConsecutiveEventReports))
		enc_maximumconsecutiveeventreports = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, false, enc_maximumconsecutiveeventreports)
		children = append(children, enc_maximumconsecutiveeventreports...)
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

// MarshalDER encodes ControlPlaneCIoT5GSOptimisation to DER format.
func (v *ControlPlaneCIoT5GSOptimisation) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes ControlPlaneCIoT5GSOptimisation from BER/DER format.
func (v *ControlPlaneCIoT5GSOptimisation) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding ControlPlaneCIoT5GSOptimisation SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "ControlPlaneCIoT5GSOptimisation", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode maximumDuration
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
				_, n_maximumduration, rawVal_maximumduration, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding maximumDuration: %w", err)
				}
				decVal_maximumduration, intErr := ber.DecodeIntegerValue(rawVal_maximumduration)
				if intErr != nil {
					return fmt.Errorf("decoding maximumDuration: %w", intErr)
				}
				tmp_maximumduration := MaximumDuration(decVal_maximumduration)
				v.MaximumDuration = &tmp_maximumduration
				offset += n_maximumduration
			}
		}
	}
	// Decode maximumConsecutiveEventReports
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
				_, n_maximumconsecutiveeventreports, rawVal_maximumconsecutiveeventreports, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding maximumConsecutiveEventReports: %w", err)
				}
				decVal_maximumconsecutiveeventreports, intErr := ber.DecodeIntegerValue(rawVal_maximumconsecutiveeventreports)
				if intErr != nil {
					return fmt.Errorf("decoding maximumConsecutiveEventReports: %w", intErr)
				}
				tmp_maximumconsecutiveeventreports := MaximumConsecutiveEventReports(decVal_maximumconsecutiveeventreports)
				v.MaximumConsecutiveEventReports = &tmp_maximumconsecutiveeventreports
				offset += n_maximumconsecutiveeventreports
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "ControlPlaneCIoT5GSOptimisation", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes LCSUserPlaneReportAFAddr to BER format.
func (v *LCSUserPlaneReportAFAddr) MarshalBER() ([]byte, error) {
	var children []byte
	if v.AfIpv4Addrs != nil {
		enc_afipv4addrs, err := MarshalBERIpv4Addrs(v.AfIpv4Addrs)
		if err != nil {
			return nil, fmt.Errorf("encoding af-Ipv4-Addrs: %w", err)
		}
		if v.AfIpv4AddrsIndef_ {
			// Strip the outer SEQUENCE tag from marshalBER output to get raw children.
			_, _, seqContent_, tlvErr_ := ber.DecodeTLV(enc_afipv4addrs)
			if tlvErr_ != nil {
				return nil, tlvErr_
			}
			enc_afipv4addrs = ber.EncodeConstructedIndefinite(tag.Tag{Class: tag.ClassContextSpecific, Number: 0}, seqContent_)
		} else {
			enc_afipv4addrs = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, true, enc_afipv4addrs)
		}
		children = append(children, enc_afipv4addrs...)
	}
	if v.AfIpv6Addrs != nil {
		enc_afipv6addrs, err := MarshalBERIpv6Addrs(v.AfIpv6Addrs)
		if err != nil {
			return nil, fmt.Errorf("encoding af-Ipv6-Addrs: %w", err)
		}
		if v.AfIpv6AddrsIndef_ {
			// Strip the outer SEQUENCE tag from marshalBER output to get raw children.
			_, _, seqContent_, tlvErr_ := ber.DecodeTLV(enc_afipv6addrs)
			if tlvErr_ != nil {
				return nil, tlvErr_
			}
			enc_afipv6addrs = ber.EncodeConstructedIndefinite(tag.Tag{Class: tag.ClassContextSpecific, Number: 1}, seqContent_)
		} else {
			enc_afipv6addrs = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, true, enc_afipv6addrs)
		}
		children = append(children, enc_afipv6addrs...)
	}
	if v.AfFqdn != nil {
		enc_affqdn := ber.EncodeOctetString([]byte(*v.AfFqdn))
		enc_affqdn = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, false, enc_affqdn)
		children = append(children, enc_affqdn...)
	}
	return ber.EncodeSequence(children), nil
}

// MarshalDER encodes LCSUserPlaneReportAFAddr to DER format.
func (v *LCSUserPlaneReportAFAddr) MarshalDER() ([]byte, error) {
	// ITU-T X.690 (02/2021) Section 10.1 requires DER length forms to be definite.
	derValue := *v
	derValue.AfIpv4AddrsIndef_ = false
	derValue.AfIpv6AddrsIndef_ = false
	v = &derValue
	return v.MarshalBER()
}

// UnmarshalBER decodes LCSUserPlaneReportAFAddr from BER/DER format.
func (v *LCSUserPlaneReportAFAddr) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding LCSUserPlaneReportAFAddr SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "LCSUserPlaneReportAFAddr", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode af-Ipv4-Addrs
	v.AfIpv4AddrsIndef_ = false
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
				_, n_afipv4addrs, rawVal_afipv4addrs, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding af-Ipv4-Addrs: %w", err)
				}
				reconstructed_afipv4addrs := ber.EncodeSequence(rawVal_afipv4addrs)
				dec_afipv4addrs, unmErr := UnmarshalBERIpv4Addrs(reconstructed_afipv4addrs)
				if unmErr != nil {
					return fmt.Errorf("decoding af-Ipv4-Addrs: %w", unmErr)
				}
				v.AfIpv4Addrs = dec_afipv4addrs
				{
					_, tagSz_, _ := ber.DecodeTag(content[offset:])
					if offset+tagSz_ < len(content) && content[offset+tagSz_] == 0x80 {
						v.AfIpv4AddrsIndef_ = true
					}
				}
				offset += n_afipv4addrs
			}
		}
	}
	// Decode af-Ipv6-Addrs
	v.AfIpv6AddrsIndef_ = false
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
				_, n_afipv6addrs, rawVal_afipv6addrs, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding af-Ipv6-Addrs: %w", err)
				}
				reconstructed_afipv6addrs := ber.EncodeSequence(rawVal_afipv6addrs)
				dec_afipv6addrs, unmErr := UnmarshalBERIpv6Addrs(reconstructed_afipv6addrs)
				if unmErr != nil {
					return fmt.Errorf("decoding af-Ipv6-Addrs: %w", unmErr)
				}
				v.AfIpv6Addrs = dec_afipv6addrs
				{
					_, tagSz_, _ := ber.DecodeTag(content[offset:])
					if offset+tagSz_ < len(content) && content[offset+tagSz_] == 0x80 {
						v.AfIpv6AddrsIndef_ = true
					}
				}
				offset += n_afipv6addrs
			}
		}
	}
	// Decode af-Fqdn
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2 {
				_, n_affqdn, rawVal_affqdn, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding af-Fqdn: %w", err)
				}
				tmp_affqdn := DataTypesFQDN(rawVal_affqdn)
				v.AfFqdn = &tmp_affqdn
				offset += n_affqdn
			}
		}
	}
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "LCSUserPlaneReportAFAddr", Cause: ber.ErrExtraData}
	}
	return nil
}

// MarshalBERIpv4Addrs encodes a Ipv4Addrs list to BER.
func MarshalBERIpv4Addrs(list Ipv4Addrs) ([]byte, error) {
	var children []byte
	for _, elem := range list {
		children = append(children, ber.EncodeOctetString([]byte(elem))...)
	}
	return ber.EncodeSequence(children), nil
}

// UnmarshalBERIpv4Addrs decodes a Ipv4Addrs list from BER.
func UnmarshalBERIpv4Addrs(data []byte) (Ipv4Addrs, error) {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return nil, fmt.Errorf("decoding Ipv4Addrs: %w", err)
	}
	if total != len(data) {
		return nil, &ber.DecodeError{Offset: total, TypeName: "Ipv4Addrs", Cause: ber.ErrExtraData}
	}
	var result Ipv4Addrs
	offset := 0
	for offset < len(content) {
		val, n, osErr := ber.DecodeOctetString(content[offset:])
		if osErr != nil {
			return nil, fmt.Errorf("decoding element: %w", osErr)
		}
		result = append(result, Ipv4Addr(val))
		offset += n
	}
	return result, nil
}

// MarshalBERIpv6Addrs encodes a Ipv6Addrs list to BER.
func MarshalBERIpv6Addrs(list Ipv6Addrs) ([]byte, error) {
	var children []byte
	for _, elem := range list {
		children = append(children, ber.EncodeOctetString([]byte(elem))...)
	}
	return ber.EncodeSequence(children), nil
}

// UnmarshalBERIpv6Addrs decodes a Ipv6Addrs list from BER.
func UnmarshalBERIpv6Addrs(data []byte) (Ipv6Addrs, error) {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return nil, fmt.Errorf("decoding Ipv6Addrs: %w", err)
	}
	if total != len(data) {
		return nil, &ber.DecodeError{Offset: total, TypeName: "Ipv6Addrs", Cause: ber.ErrExtraData}
	}
	var result Ipv6Addrs
	offset := 0
	for offset < len(content) {
		val, n, osErr := ber.DecodeOctetString(content[offset:])
		if osErr != nil {
			return nil, fmt.Errorf("decoding element: %w", osErr)
		}
		result = append(result, Ipv6Addr(val))
		offset += n
	}
	return result, nil
}

// MarshalBER encodes LCSCumulativeReportCriteria to BER format.
func (v *LCSCumulativeReportCriteria) MarshalBER() ([]byte, error) {
	var children []byte
	if v.TimerCriteria != nil {
		enc_timercriteria := ber.EncodeInteger(int64(*v.TimerCriteria))
		enc_timercriteria = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, false, enc_timercriteria)
		children = append(children, enc_timercriteria...)
	}
	if v.CounterCriteria != nil {
		enc_countercriteria := ber.EncodeInteger(int64(*v.CounterCriteria))
		enc_countercriteria = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, false, enc_countercriteria)
		children = append(children, enc_countercriteria...)
	}
	return ber.EncodeSequence(children), nil
}

// MarshalDER encodes LCSCumulativeReportCriteria to DER format.
func (v *LCSCumulativeReportCriteria) MarshalDER() ([]byte, error) {
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes LCSCumulativeReportCriteria from BER/DER format.
func (v *LCSCumulativeReportCriteria) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding LCSCumulativeReportCriteria SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "LCSCumulativeReportCriteria", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode timerCriteria
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
				_, n_timercriteria, rawVal_timercriteria, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding timerCriteria: %w", err)
				}
				decVal_timercriteria, intErr := ber.DecodeIntegerValue(rawVal_timercriteria)
				if intErr != nil {
					return fmt.Errorf("decoding timerCriteria: %w", intErr)
				}
				tmp_timercriteria := LCSCumulativeReportTimerCriteria(decVal_timercriteria)
				v.TimerCriteria = &tmp_timercriteria
				offset += n_timercriteria
			}
		}
	}
	// Decode counterCriteria
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
				_, n_countercriteria, rawVal_countercriteria, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding counterCriteria: %w", err)
				}
				decVal_countercriteria, intErr := ber.DecodeIntegerValue(rawVal_countercriteria)
				if intErr != nil {
					return fmt.Errorf("decoding counterCriteria: %w", intErr)
				}
				tmp_countercriteria := LCSCumulativeReportCounterCriteria(decVal_countercriteria)
				v.CounterCriteria = &tmp_countercriteria
				offset += n_countercriteria
			}
		}
	}
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "LCSCumulativeReportCriteria", Cause: ber.ErrExtraData}
	}
	return nil
}

// MarshalBER encodes LCSEventReportRes to BER format.
func (v *LCSEventReportRes) MarshalBER() ([]byte, error) {
	var children []byte
	if v.DeferredRoutingIdentifier != nil {
		enc_deferredroutingidentifier := ber.EncodeOctetString(v.DeferredRoutingIdentifier)
		enc_deferredroutingidentifier = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, false, enc_deferredroutingidentifier)
		children = append(children, enc_deferredroutingidentifier...)
	}
	if v.TerminationCause != nil {
		enc_terminationcause := ber.EncodeEnumerated(int64(*v.TerminationCause))
		enc_terminationcause = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, false, enc_terminationcause)
		children = append(children, enc_terminationcause...)
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

// MarshalDER encodes LCSEventReportRes to DER format.
func (v *LCSEventReportRes) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes LCSEventReportRes from BER/DER format.
func (v *LCSEventReportRes) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding LCSEventReportRes SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "LCSEventReportRes", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode deferredRoutingIdentifier
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
				_, n_deferredroutingidentifier, rawVal_deferredroutingidentifier, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding deferredRoutingIdentifier: %w", err)
				}
				tmp_deferredroutingidentifier := rawVal_deferredroutingidentifier
				v.DeferredRoutingIdentifier = tmp_deferredroutingidentifier
				offset += n_deferredroutingidentifier
			}
		}
	}
	// Decode terminationCause
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
				_, n_terminationcause, rawVal_terminationcause, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding terminationCause: %w", err)
				}
				decVal_terminationcause, intErr := ber.DecodeIntegerValue(rawVal_terminationcause)
				if intErr != nil {
					return fmt.Errorf("decoding terminationCause: %w", intErr)
				}
				tmp_terminationcause := DataTypesTerminationCause(decVal_terminationcause)
				v.TerminationCause = &tmp_terminationcause
				offset += n_terminationcause
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "LCSEventReportRes", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes LCSCancelDeferredLocationArg to BER format.
func (v *LCSCancelDeferredLocationArg) MarshalBER() ([]byte, error) {
	var children []byte
	enc_referencenumberext := ber.EncodeOctetString([]byte(v.ReferenceNumberExt))
	enc_referencenumberext = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, false, enc_referencenumberext)
	children = append(children, enc_referencenumberext...)
	enc_hgmlccallbackuri, stringErr := ber.EncodeStringTagChecked(12, v.HGmlcCallBackUri)
	if stringErr != nil {
		return nil, fmt.Errorf("encoding h-gmlc-callBackUri: %w", stringErr)
	}
	enc_hgmlccallbackuri = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, false, enc_hgmlccallbackuri)
	children = append(children, enc_hgmlccallbackuri...)
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

// MarshalDER encodes LCSCancelDeferredLocationArg to DER format.
func (v *LCSCancelDeferredLocationArg) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes LCSCancelDeferredLocationArg from BER/DER format.
func (v *LCSCancelDeferredLocationArg) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding LCSCancelDeferredLocationArg SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "LCSCancelDeferredLocationArg", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode referenceNumberExt
	if offset >= len(content) {
		return fmt.Errorf("missing required field referenceNumberExt")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 0 {
			return fmt.Errorf("expected tag [%s %d] for referenceNumberExt, got %s", "CONTEXT", 0, reqTag_)
		}
	}
	_, n_referencenumberext, rawVal_referencenumberext, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding referenceNumberExt: %w", err)
	}
	v.ReferenceNumberExt = LCSReferenceNumberExt(rawVal_referencenumberext)
	offset += n_referencenumberext
	// Decode h-gmlc-callBackUri
	if offset >= len(content) {
		return fmt.Errorf("missing required field h-gmlc-callBackUri")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 2 {
			return fmt.Errorf("expected tag [%s %d] for h-gmlc-callBackUri, got %s", "CONTEXT", 2, reqTag_)
		}
	}
	_, n_hgmlccallbackuri, rawVal_hgmlccallbackuri, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding h-gmlc-callBackUri: %w", err)
	}
	decVal_hgmlccallbackuri, stringErr := ber.DecodeStringValueTag(12, rawVal_hgmlccallbackuri)
	if stringErr != nil {
		return fmt.Errorf("decoding h-gmlc-callBackUri: %w", stringErr)
	}
	v.HGmlcCallBackUri = decVal_hgmlccallbackuri
	offset += n_hgmlccallbackuri
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "LCSCancelDeferredLocationArg", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes LCSLocationPrivacySettingArg to BER format.
func (v *LCSLocationPrivacySettingArg) MarshalBER() ([]byte, error) {
	var children []byte
	enc_locationprivacyindication := ber.EncodeEnumerated(int64(v.LocationPrivacyIndication))
	enc_locationprivacyindication = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, false, enc_locationprivacyindication)
	children = append(children, enc_locationprivacyindication...)
	if v.ValidTimePeriod != nil {
		enc_validtimeperiod, err := v.ValidTimePeriod.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding validTimePeriod: %w", err)
		}
		enc_validtimeperiod = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, true, enc_validtimeperiod)
		children = append(children, enc_validtimeperiod...)
	}
	if v.EventReportExpectedArea != nil {
		enc_eventreportexpectedarea := ber.EncodeOctetString([]byte(*v.EventReportExpectedArea))
		enc_eventreportexpectedarea = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, false, enc_eventreportexpectedarea)
		children = append(children, enc_eventreportexpectedarea...)
	}
	if v.AreaUsageInd != nil {
		enc_areausageind := ber.EncodeEnumerated(int64(*v.AreaUsageInd))
		enc_areausageind = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, false, enc_areausageind)
		children = append(children, enc_areausageind...)
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

// MarshalDER encodes LCSLocationPrivacySettingArg to DER format.
func (v *LCSLocationPrivacySettingArg) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes LCSLocationPrivacySettingArg from BER/DER format.
func (v *LCSLocationPrivacySettingArg) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding LCSLocationPrivacySettingArg SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "LCSLocationPrivacySettingArg", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode locationPrivacyIndication
	if offset >= len(content) {
		return fmt.Errorf("missing required field locationPrivacyIndication")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 0 {
			return fmt.Errorf("expected tag [%s %d] for locationPrivacyIndication, got %s", "CONTEXT", 0, reqTag_)
		}
	}
	_, n_locationprivacyindication, rawVal_locationprivacyindication, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding locationPrivacyIndication: %w", err)
	}
	decVal_locationprivacyindication, intErr := ber.DecodeIntegerValue(rawVal_locationprivacyindication)
	if intErr != nil {
		return fmt.Errorf("decoding locationPrivacyIndication: %w", intErr)
	}
	v.LocationPrivacyIndication = LCSLocationPrivacyIndication(decVal_locationprivacyindication)
	offset += n_locationprivacyindication
	// Decode validTimePeriod
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
				_, n_validtimeperiod, rawVal_validtimeperiod, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding validTimePeriod: %w", err)
				}
				reconstructed_validtimeperiod := ber.EncodeSequence(rawVal_validtimeperiod)
				var dec_validtimeperiod LCSValidTimePeriod
				if unmErr := dec_validtimeperiod.UnmarshalBER(reconstructed_validtimeperiod); unmErr != nil {
					return fmt.Errorf("decoding validTimePeriod: %w", unmErr)
				}
				v.ValidTimePeriod = &dec_validtimeperiod
				offset += n_validtimeperiod
			}
		}
	}
	// Decode eventReportExpectedArea
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2 {
				_, n_eventreportexpectedarea, rawVal_eventreportexpectedarea, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding eventReportExpectedArea: %w", err)
				}
				tmp_eventreportexpectedarea := ExtGeographicalInformation(rawVal_eventreportexpectedarea)
				v.EventReportExpectedArea = &tmp_eventreportexpectedarea
				offset += n_eventreportexpectedarea
			}
		}
	}
	// Decode areaUsageInd
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3 {
				_, n_areausageind, rawVal_areausageind, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding areaUsageInd: %w", err)
				}
				decVal_areausageind, intErr := ber.DecodeIntegerValue(rawVal_areausageind)
				if intErr != nil {
					return fmt.Errorf("decoding areaUsageInd: %w", intErr)
				}
				tmp_areausageind := ReportingInd(decVal_areausageind)
				v.AreaUsageInd = &tmp_areausageind
				offset += n_areausageind
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "LCSLocationPrivacySettingArg", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes LCSValidTimePeriod to BER format.
func (v *LCSValidTimePeriod) MarshalBER() ([]byte, error) {
	var children []byte
	if v.StartTime != nil {
		enc_starttime := ber.EncodeOctetString([]byte(*v.StartTime))
		enc_starttime = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, false, enc_starttime)
		children = append(children, enc_starttime...)
	}
	if v.EndTime != nil {
		enc_endtime := ber.EncodeOctetString([]byte(*v.EndTime))
		enc_endtime = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, false, enc_endtime)
		children = append(children, enc_endtime...)
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

// MarshalDER encodes LCSValidTimePeriod to DER format.
func (v *LCSValidTimePeriod) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes LCSValidTimePeriod from BER/DER format.
func (v *LCSValidTimePeriod) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding LCSValidTimePeriod SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "LCSValidTimePeriod", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode startTime
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
				_, n_starttime, rawVal_starttime, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding startTime: %w", err)
				}
				tmp_starttime := DateTime(rawVal_starttime)
				v.StartTime = &tmp_starttime
				offset += n_starttime
			}
		}
	}
	// Decode endTime
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
				_, n_endtime, rawVal_endtime, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding endTime: %w", err)
				}
				tmp_endtime := DateTime(rawVal_endtime)
				v.EndTime = &tmp_endtime
				offset += n_endtime
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "LCSValidTimePeriod", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes LCSPruAssociationArg to BER format.
func (v *LCSPruAssociationArg) MarshalBER() ([]byte, error) {
	var children []byte
	enc_associationtype := ber.EncodeEnumerated(int64(v.AssociationType))
	enc_associationtype = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, false, enc_associationtype)
	children = append(children, enc_associationtype...)
	enc_positioningcapabilities := ber.EncodeOctetString(v.PositioningCapabilities)
	enc_positioningcapabilities = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, false, enc_positioningcapabilities)
	children = append(children, enc_positioningcapabilities...)
	if v.LocationOfPru != nil {
		enc_locationofpru := ber.EncodeOctetString([]byte(*v.LocationOfPru))
		enc_locationofpru = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, false, enc_locationofpru)
		children = append(children, enc_locationofpru...)
	}
	if v.StateOfPru != nil {
		enc_stateofpru := ber.EncodeEnumerated(int64(*v.StateOfPru))
		enc_stateofpru = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, false, enc_stateofpru)
		children = append(children, enc_stateofpru...)
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

// MarshalDER encodes LCSPruAssociationArg to DER format.
func (v *LCSPruAssociationArg) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes LCSPruAssociationArg from BER/DER format.
func (v *LCSPruAssociationArg) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding LCSPruAssociationArg SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "LCSPruAssociationArg", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode associationType
	if offset >= len(content) {
		return fmt.Errorf("missing required field associationType")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 0 {
			return fmt.Errorf("expected tag [%s %d] for associationType, got %s", "CONTEXT", 0, reqTag_)
		}
	}
	_, n_associationtype, rawVal_associationtype, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding associationType: %w", err)
	}
	decVal_associationtype, intErr := ber.DecodeIntegerValue(rawVal_associationtype)
	if intErr != nil {
		return fmt.Errorf("decoding associationType: %w", intErr)
	}
	v.AssociationType = LCSAssociationType(decVal_associationtype)
	offset += n_associationtype
	// Decode positioningCapabilities
	if offset >= len(content) {
		return fmt.Errorf("missing required field positioningCapabilities")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 1 {
			return fmt.Errorf("expected tag [%s %d] for positioningCapabilities, got %s", "CONTEXT", 1, reqTag_)
		}
	}
	_, n_positioningcapabilities, rawVal_positioningcapabilities, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding positioningCapabilities: %w", err)
	}
	v.PositioningCapabilities = rawVal_positioningcapabilities
	offset += n_positioningcapabilities
	// Decode locationOfPru
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2 {
				_, n_locationofpru, rawVal_locationofpru, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding locationOfPru: %w", err)
				}
				tmp_locationofpru := ExtGeographicalInformation(rawVal_locationofpru)
				v.LocationOfPru = &tmp_locationofpru
				offset += n_locationofpru
			}
		}
	}
	// Decode stateOfPru
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3 {
				_, n_stateofpru, rawVal_stateofpru, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding stateOfPru: %w", err)
				}
				decVal_stateofpru, intErr := ber.DecodeIntegerValue(rawVal_stateofpru)
				if intErr != nil {
					return fmt.Errorf("decoding stateOfPru: %w", intErr)
				}
				tmp_stateofpru := LCSStateOfPru(decVal_stateofpru)
				v.StateOfPru = &tmp_stateofpru
				offset += n_stateofpru
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "LCSPruAssociationArg", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes LCSPruAssociationRes to BER format.
func (v *LCSPruAssociationRes) MarshalBER() ([]byte, error) {
	var children []byte
	if v.PeriodicUpdateTimer != nil {
		enc_periodicupdatetimer := ber.EncodeInteger(int64(*v.PeriodicUpdateTimer))
		enc_periodicupdatetimer = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, false, enc_periodicupdatetimer)
		children = append(children, enc_periodicupdatetimer...)
	}
	if v.UpdateTrigger != nil {
		enc_updatetrigger := ber.EncodeBitString(v.UpdateTrigger.Bytes, (8-(v.UpdateTrigger.BitLength%8))%8)
		enc_updatetrigger = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, false, enc_updatetrigger)
		children = append(children, enc_updatetrigger...)
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

// MarshalDER encodes LCSPruAssociationRes to DER format.
func (v *LCSPruAssociationRes) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes LCSPruAssociationRes from BER/DER format.
func (v *LCSPruAssociationRes) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding LCSPruAssociationRes SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "LCSPruAssociationRes", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode periodicUpdateTimer
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
				_, n_periodicupdatetimer, rawVal_periodicupdatetimer, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding periodicUpdateTimer: %w", err)
				}
				decVal_periodicupdatetimer, intErr := ber.DecodeIntegerValue(rawVal_periodicupdatetimer)
				if intErr != nil {
					return fmt.Errorf("decoding periodicUpdateTimer: %w", intErr)
				}
				tmp_periodicupdatetimer := LCSPeriodicUpdateTimer(decVal_periodicupdatetimer)
				v.PeriodicUpdateTimer = &tmp_periodicupdatetimer
				offset += n_periodicupdatetimer
			}
		}
	}
	// Decode updateTrigger
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
				_, n_updatetrigger, rawVal_updatetrigger, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding updateTrigger: %w", err)
				}
				bsBytes_updatetrigger, bsUnused_updatetrigger, bsErr := ber.DecodeBitStringValue(rawVal_updatetrigger)
				if bsErr != nil {
					return fmt.Errorf("decoding updateTrigger: %w", bsErr)
				}
				tmp_updatetrigger := runtime.BitString{Bytes: bsBytes_updatetrigger, BitLength: len(bsBytes_updatetrigger)*8 - bsUnused_updatetrigger}
				v.UpdateTrigger = &tmp_updatetrigger
				offset += n_updatetrigger
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "LCSPruAssociationRes", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes LCSPruDisassociationArg to BER format.
func (v *LCSPruDisassociationArg) MarshalBER() ([]byte, error) {
	var children []byte
	if v.AckIndication != nil {
		var enc_ackindication []byte
		if v.AckIndicationRaw_ != 0 {
			enc_ackindication = ber.EncodeBooleanRaw(v.AckIndicationRaw_)
		} else {
			enc_ackindication = ber.EncodeBoolean(*v.AckIndication)
		}
		enc_ackindication = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, false, enc_ackindication)
		children = append(children, enc_ackindication...)
	}
	if v.NewLmfRoutingId != nil {
		enc_newlmfroutingid := ber.EncodeOctetString(v.NewLmfRoutingId)
		enc_newlmfroutingid = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, false, enc_newlmfroutingid)
		children = append(children, enc_newlmfroutingid...)
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

// MarshalDER encodes LCSPruDisassociationArg to DER format.
func (v *LCSPruDisassociationArg) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes LCSPruDisassociationArg from BER/DER format.
func (v *LCSPruDisassociationArg) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding LCSPruDisassociationArg SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "LCSPruDisassociationArg", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode ackIndication
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
				_, n_ackindication, rawVal_ackindication, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding ackIndication: %w", err)
				}
				decVal_ackindication, boolErr := ber.DecodeBooleanValue(rawVal_ackindication)
				if boolErr != nil {
					return fmt.Errorf("decoding ackIndication: %w", boolErr)
				}
				if len(rawVal_ackindication) == 1 {
					v.AckIndicationRaw_ = rawVal_ackindication[0]
				}
				v.AckIndication = &decVal_ackindication
				offset += n_ackindication
			}
		}
	}
	// Decode newLmfRoutingId
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
				_, n_newlmfroutingid, rawVal_newlmfroutingid, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding newLmfRoutingId: %w", err)
				}
				tmp_newlmfroutingid := rawVal_newlmfroutingid
				v.NewLmfRoutingId = tmp_newlmfroutingid
				offset += n_newlmfroutingid
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "LCSPruDisassociationArg", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes LCSSLMTLRArg to BER format.
func (v *LCSSLMTLRArg) MarshalBER() ([]byte, error) {
	var children []byte
	enc_slmtlrtype := ber.EncodeEnumerated(int64(v.SlmtlrType))
	enc_slmtlrtype = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, false, enc_slmtlrtype)
	children = append(children, enc_slmtlrtype...)
	if v.SupportedGADShapes != nil {
		enc_supportedgadshapes := ber.EncodeBitString(v.SupportedGADShapes.Bytes, (8-(v.SupportedGADShapes.BitLength%8))%8)
		enc_supportedgadshapes = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, false, enc_supportedgadshapes)
		children = append(children, enc_supportedgadshapes...)
	}
	if v.RelatedUEInfo != nil {
		enc_relatedueinfo, err := MarshalBERRelatedUEInfo(v.RelatedUEInfo)
		if err != nil {
			return nil, fmt.Errorf("encoding relatedUEInfo: %w", err)
		}
		if v.RelatedUEInfoIndef_ {
			// Strip the outer SEQUENCE tag from marshalBER output to get raw children.
			_, _, seqContent_, tlvErr_ := ber.DecodeTLV(enc_relatedueinfo)
			if tlvErr_ != nil {
				return nil, tlvErr_
			}
			enc_relatedueinfo = ber.EncodeConstructedIndefinite(tag.Tag{Class: tag.ClassContextSpecific, Number: 2}, seqContent_)
		} else {
			enc_relatedueinfo = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, true, enc_relatedueinfo)
		}
		children = append(children, enc_relatedueinfo...)
	}
	if v.LocatedUEselect != nil {
		enc_locatedueselect := ber.EncodeEnumerated(int64(*v.LocatedUEselect))
		enc_locatedueselect = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, false, enc_locatedueselect)
		children = append(children, enc_locatedueselect...)
	}
	if v.CoordinateID != nil {
		enc_coordinateid := ber.EncodeInteger(int64(*v.CoordinateID))
		enc_coordinateid = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, false, enc_coordinateid)
		children = append(children, enc_coordinateid...)
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

// MarshalDER encodes LCSSLMTLRArg to DER format.
func (v *LCSSLMTLRArg) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// ITU-T X.690 (02/2021) Section 10.1 requires DER length forms to be definite.
	derValue := *v
	derValue.RelatedUEInfoIndef_ = false
	v = &derValue
	return v.MarshalBER()
}

// UnmarshalBER decodes LCSSLMTLRArg from BER/DER format.
func (v *LCSSLMTLRArg) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding LCSSLMTLRArg SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "LCSSLMTLRArg", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode slmtlr-Type
	if offset >= len(content) {
		return fmt.Errorf("missing required field slmtlr-Type")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 0 {
			return fmt.Errorf("expected tag [%s %d] for slmtlr-Type, got %s", "CONTEXT", 0, reqTag_)
		}
	}
	_, n_slmtlrtype, rawVal_slmtlrtype, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding slmtlr-Type: %w", err)
	}
	decVal_slmtlrtype, intErr := ber.DecodeIntegerValue(rawVal_slmtlrtype)
	if intErr != nil {
		return fmt.Errorf("decoding slmtlr-Type: %w", intErr)
	}
	v.SlmtlrType = SLMTLRType(decVal_slmtlrtype)
	offset += n_slmtlrtype
	// Decode supportedGADShapes
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
				_, n_supportedgadshapes, rawVal_supportedgadshapes, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding supportedGADShapes: %w", err)
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
	// Decode relatedUEInfo
	v.RelatedUEInfoIndef_ = false
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2 {
				_, n_relatedueinfo, rawVal_relatedueinfo, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding relatedUEInfo: %w", err)
				}
				reconstructed_relatedueinfo := ber.EncodeSequence(rawVal_relatedueinfo)
				dec_relatedueinfo, unmErr := UnmarshalBERRelatedUEInfo(reconstructed_relatedueinfo)
				if unmErr != nil {
					return fmt.Errorf("decoding relatedUEInfo: %w", unmErr)
				}
				v.RelatedUEInfo = dec_relatedueinfo
				{
					_, tagSz_, _ := ber.DecodeTag(content[offset:])
					if offset+tagSz_ < len(content) && content[offset+tagSz_] == 0x80 {
						v.RelatedUEInfoIndef_ = true
					}
				}
				offset += n_relatedueinfo
			}
		}
	}
	// Decode locatedUEselect
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3 {
				_, n_locatedueselect, rawVal_locatedueselect, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding locatedUEselect: %w", err)
				}
				decVal_locatedueselect, intErr := ber.DecodeIntegerValue(rawVal_locatedueselect)
				if intErr != nil {
					return fmt.Errorf("decoding locatedUEselect: %w", intErr)
				}
				tmp_locatedueselect := LocatedUEselect(decVal_locatedueselect)
				v.LocatedUEselect = &tmp_locatedueselect
				offset += n_locatedueselect
			}
		}
	}
	// Decode coordinateID
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4 {
				_, n_coordinateid, rawVal_coordinateid, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding coordinateID: %w", err)
				}
				decVal_coordinateid, intErr := ber.DecodeIntegerValue(rawVal_coordinateid)
				if intErr != nil {
					return fmt.Errorf("decoding coordinateID: %w", intErr)
				}
				tmp_coordinateid := CoordinateID(decVal_coordinateid)
				v.CoordinateID = &tmp_coordinateid
				offset += n_coordinateid
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "LCSSLMTLRArg", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes LCSSLMTLRRes to BER format.
func (v *LCSSLMTLRRes) MarshalBER() ([]byte, error) {
	var children []byte
	enc_relatedueinfo, err := MarshalBERRelatedUEInfo(v.RelatedUEInfo)
	if err != nil {
		return nil, fmt.Errorf("encoding relatedUEInfo: %w", err)
	}
	if v.RelatedUEInfoIndef_ {
		// Strip the outer SEQUENCE tag from marshalBER output to get raw children.
		_, _, seqContent_, tlvErr_ := ber.DecodeTLV(enc_relatedueinfo)
		if tlvErr_ != nil {
			return nil, tlvErr_
		}
		enc_relatedueinfo = ber.EncodeConstructedIndefinite(tag.Tag{Class: tag.ClassContextSpecific, Number: 0}, seqContent_)
	} else {
		enc_relatedueinfo = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, true, enc_relatedueinfo)
	}
	children = append(children, enc_relatedueinfo...)
	if v.RangingSLPPList != nil {
		enc_rangingslpplist, err := MarshalBERRangingSLPPList(v.RangingSLPPList)
		if err != nil {
			return nil, fmt.Errorf("encoding rangingSLPPList: %w", err)
		}
		if v.RangingSLPPListIndef_ {
			// Strip the outer SEQUENCE tag from marshalBER output to get raw children.
			_, _, seqContent_, tlvErr_ := ber.DecodeTLV(enc_rangingslpplist)
			if tlvErr_ != nil {
				return nil, tlvErr_
			}
			enc_rangingslpplist = ber.EncodeConstructedIndefinite(tag.Tag{Class: tag.ClassContextSpecific, Number: 1}, seqContent_)
		} else {
			enc_rangingslpplist = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, true, enc_rangingslpplist)
		}
		children = append(children, enc_rangingslpplist...)
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

// MarshalDER encodes LCSSLMTLRRes to DER format.
func (v *LCSSLMTLRRes) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// ITU-T X.690 (02/2021) Section 10.1 requires DER length forms to be definite.
	derValue := *v
	derValue.RelatedUEInfoIndef_ = false
	derValue.RangingSLPPListIndef_ = false
	v = &derValue
	return v.MarshalBER()
}

// UnmarshalBER decodes LCSSLMTLRRes from BER/DER format.
func (v *LCSSLMTLRRes) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding LCSSLMTLRRes SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "LCSSLMTLRRes", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode relatedUEInfo
	if offset >= len(content) {
		return fmt.Errorf("missing required field relatedUEInfo")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 0 {
			return fmt.Errorf("expected tag [%s %d] for relatedUEInfo, got %s", "CONTEXT", 0, reqTag_)
		}
	}
	v.RelatedUEInfoIndef_ = false
	_, n_relatedueinfo, rawVal_relatedueinfo, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding relatedUEInfo: %w", err)
	}
	reconstructed_relatedueinfo := ber.EncodeSequence(rawVal_relatedueinfo)
	dec_relatedueinfo, unmErr := UnmarshalBERRelatedUEInfo(reconstructed_relatedueinfo)
	if unmErr != nil {
		return fmt.Errorf("decoding relatedUEInfo: %w", unmErr)
	}
	v.RelatedUEInfo = dec_relatedueinfo
	{
		_, tagSz_, _ := ber.DecodeTag(content[offset:])
		if offset+tagSz_ < len(content) && content[offset+tagSz_] == 0x80 {
			v.RelatedUEInfoIndef_ = true
		}
	}
	offset += n_relatedueinfo
	// Decode rangingSLPPList
	v.RangingSLPPListIndef_ = false
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
				_, n_rangingslpplist, rawVal_rangingslpplist, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding rangingSLPPList: %w", err)
				}
				reconstructed_rangingslpplist := ber.EncodeSequence(rawVal_rangingslpplist)
				dec_rangingslpplist, unmErr := UnmarshalBERRangingSLPPList(reconstructed_rangingslpplist)
				if unmErr != nil {
					return fmt.Errorf("decoding rangingSLPPList: %w", unmErr)
				}
				v.RangingSLPPList = dec_rangingslpplist
				{
					_, tagSz_, _ := ber.DecodeTag(content[offset:])
					if offset+tagSz_ < len(content) && content[offset+tagSz_] == 0x80 {
						v.RangingSLPPListIndef_ = true
					}
				}
				offset += n_rangingslpplist
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "LCSSLMTLRRes", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBERRangingSLPPList encodes a RangingSLPPList list to BER.
func MarshalBERRangingSLPPList(list RangingSLPPList) ([]byte, error) {
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

// UnmarshalBERRangingSLPPList decodes a RangingSLPPList list from BER.
func UnmarshalBERRangingSLPPList(data []byte) (RangingSLPPList, error) {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return nil, fmt.Errorf("decoding RangingSLPPList: %w", err)
	}
	if total != len(data) {
		return nil, &ber.DecodeError{Offset: total, TypeName: "RangingSLPPList", Cause: ber.ErrExtraData}
	}
	var result RangingSLPPList
	offset := 0
	for offset < len(content) {
		var elem RangingSLPPInfo
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

// MarshalBER encodes RangingSLPPInfo to BER format.
func (v *RangingSLPPInfo) MarshalBER() ([]byte, error) {
	var children []byte
	enc_slppmsg := ber.EncodeOctetString([]byte(v.SLPPMsg))
	enc_slppmsg = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, false, enc_slppmsg)
	children = append(children, enc_slppmsg...)
	if v.RelatedUE != nil {
		enc_relatedue := ber.EncodeOctetString(v.RelatedUE)
		enc_relatedue = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, false, enc_relatedue)
		children = append(children, enc_relatedue...)
	}
	return ber.EncodeSequence(children), nil
}

// MarshalDER encodes RangingSLPPInfo to DER format.
func (v *RangingSLPPInfo) MarshalDER() ([]byte, error) {
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes RangingSLPPInfo from BER/DER format.
func (v *RangingSLPPInfo) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding RangingSLPPInfo SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "RangingSLPPInfo", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode sLPPMsg
	if offset >= len(content) {
		return fmt.Errorf("missing required field sLPPMsg")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 0 {
			return fmt.Errorf("expected tag [%s %d] for sLPPMsg, got %s", "CONTEXT", 0, reqTag_)
		}
	}
	_, n_slppmsg, rawVal_slppmsg, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding sLPPMsg: %w", err)
	}
	v.SLPPMsg = SlPosProtocolPDU(rawVal_slppmsg)
	offset += n_slppmsg
	// Decode relatedUE
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
				_, n_relatedue, rawVal_relatedue, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding relatedUE: %w", err)
				}
				tmp_relatedue := rawVal_relatedue
				v.RelatedUE = tmp_relatedue
				offset += n_relatedue
			}
		}
	}
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "RangingSLPPInfo", Cause: ber.ErrExtraData}
	}
	return nil
}

// MarshalBER encodes LCSDLRSPPTransportArg to BER format.
func (v *LCSDLRSPPTransportArg) MarshalBER() ([]byte, error) {
	var children []byte
	if v.RangingSLPPList != nil {
		enc_rangingslpplist, err := MarshalBERRangingSLPPList(v.RangingSLPPList)
		if err != nil {
			return nil, fmt.Errorf("encoding rangingSLPPList: %w", err)
		}
		if v.RangingSLPPListIndef_ {
			// Strip the outer SEQUENCE tag from marshalBER output to get raw children.
			_, _, seqContent_, tlvErr_ := ber.DecodeTLV(enc_rangingslpplist)
			if tlvErr_ != nil {
				return nil, tlvErr_
			}
			enc_rangingslpplist = ber.EncodeConstructedIndefinite(tag.Tag{Class: tag.ClassContextSpecific, Number: 0}, seqContent_)
		} else {
			enc_rangingslpplist = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, true, enc_rangingslpplist)
		}
		children = append(children, enc_rangingslpplist...)
	}
	if v.ScheduledLocTime != nil {
		enc_scheduledloctime := ber.EncodeOctetString([]byte(*v.ScheduledLocTime))
		enc_scheduledloctime = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, false, enc_scheduledloctime)
		children = append(children, enc_scheduledloctime...)
	}
	if v.UeBased != nil {
		enc_uebased := ber.EncodeEnumerated(int64(*v.UeBased))
		enc_uebased = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, false, enc_uebased)
		children = append(children, enc_uebased...)
	}
	if v.RelatedUEInfo != nil {
		enc_relatedueinfo, err := MarshalBERRelatedUEInfo(v.RelatedUEInfo)
		if err != nil {
			return nil, fmt.Errorf("encoding relatedUEInfo: %w", err)
		}
		if v.RelatedUEInfoIndef_ {
			// Strip the outer SEQUENCE tag from marshalBER output to get raw children.
			_, _, seqContent_, tlvErr_ := ber.DecodeTLV(enc_relatedueinfo)
			if tlvErr_ != nil {
				return nil, tlvErr_
			}
			enc_relatedueinfo = ber.EncodeConstructedIndefinite(tag.Tag{Class: tag.ClassContextSpecific, Number: 3}, seqContent_)
		} else {
			enc_relatedueinfo = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, true, enc_relatedueinfo)
		}
		children = append(children, enc_relatedueinfo...)
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

// MarshalDER encodes LCSDLRSPPTransportArg to DER format.
func (v *LCSDLRSPPTransportArg) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// ITU-T X.690 (02/2021) Section 10.1 requires DER length forms to be definite.
	derValue := *v
	derValue.RangingSLPPListIndef_ = false
	derValue.RelatedUEInfoIndef_ = false
	v = &derValue
	return v.MarshalBER()
}

// UnmarshalBER decodes LCSDLRSPPTransportArg from BER/DER format.
func (v *LCSDLRSPPTransportArg) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding LCSDLRSPPTransportArg SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "LCSDLRSPPTransportArg", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode rangingSLPPList
	v.RangingSLPPListIndef_ = false
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
				_, n_rangingslpplist, rawVal_rangingslpplist, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding rangingSLPPList: %w", err)
				}
				reconstructed_rangingslpplist := ber.EncodeSequence(rawVal_rangingslpplist)
				dec_rangingslpplist, unmErr := UnmarshalBERRangingSLPPList(reconstructed_rangingslpplist)
				if unmErr != nil {
					return fmt.Errorf("decoding rangingSLPPList: %w", unmErr)
				}
				v.RangingSLPPList = dec_rangingslpplist
				{
					_, tagSz_, _ := ber.DecodeTag(content[offset:])
					if offset+tagSz_ < len(content) && content[offset+tagSz_] == 0x80 {
						v.RangingSLPPListIndef_ = true
					}
				}
				offset += n_rangingslpplist
			}
		}
	}
	// Decode scheduledLocTime
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
				_, n_scheduledloctime, rawVal_scheduledloctime, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding scheduledLocTime: %w", err)
				}
				tmp_scheduledloctime := DateTime(rawVal_scheduledloctime)
				v.ScheduledLocTime = &tmp_scheduledloctime
				offset += n_scheduledloctime
			}
		}
	}
	// Decode ueBased
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2 {
				_, n_uebased, rawVal_uebased, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding ueBased: %w", err)
				}
				decVal_uebased, intErr := ber.DecodeIntegerValue(rawVal_uebased)
				if intErr != nil {
					return fmt.Errorf("decoding ueBased: %w", intErr)
				}
				tmp_uebased := UEBased(decVal_uebased)
				v.UeBased = &tmp_uebased
				offset += n_uebased
			}
		}
	}
	// Decode relatedUEInfo
	v.RelatedUEInfoIndef_ = false
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3 {
				_, n_relatedueinfo, rawVal_relatedueinfo, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding relatedUEInfo: %w", err)
				}
				reconstructed_relatedueinfo := ber.EncodeSequence(rawVal_relatedueinfo)
				dec_relatedueinfo, unmErr := UnmarshalBERRelatedUEInfo(reconstructed_relatedueinfo)
				if unmErr != nil {
					return fmt.Errorf("decoding relatedUEInfo: %w", unmErr)
				}
				v.RelatedUEInfo = dec_relatedueinfo
				{
					_, tagSz_, _ := ber.DecodeTag(content[offset:])
					if offset+tagSz_ < len(content) && content[offset+tagSz_] == 0x80 {
						v.RelatedUEInfoIndef_ = true
					}
				}
				offset += n_relatedueinfo
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "LCSDLRSPPTransportArg", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes LCSDLRSPPTransportRes to BER format.
func (v *LCSDLRSPPTransportRes) MarshalBER() ([]byte, error) {
	return ber.EncodeSequence(nil), nil
}

// MarshalDER encodes LCSDLRSPPTransportRes to DER format.
func (v *LCSDLRSPPTransportRes) MarshalDER() ([]byte, error) {
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes LCSDLRSPPTransportRes from BER/DER format.
func (v *LCSDLRSPPTransportRes) UnmarshalBER(data []byte) error {
	_, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding LCSDLRSPPTransportRes SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "LCSDLRSPPTransportRes", Cause: ber.ErrExtraData}
	}
	return nil
}

// MarshalBER encodes LCSULRSPPTransportArg to BER format.
func (v *LCSULRSPPTransportArg) MarshalBER() ([]byte, error) {
	var children []byte
	if v.RangingSLPPList != nil {
		enc_rangingslpplist, err := MarshalBERRangingSLPPList(v.RangingSLPPList)
		if err != nil {
			return nil, fmt.Errorf("encoding rangingSLPPList: %w", err)
		}
		if v.RangingSLPPListIndef_ {
			// Strip the outer SEQUENCE tag from marshalBER output to get raw children.
			_, _, seqContent_, tlvErr_ := ber.DecodeTLV(enc_rangingslpplist)
			if tlvErr_ != nil {
				return nil, tlvErr_
			}
			enc_rangingslpplist = ber.EncodeConstructedIndefinite(tag.Tag{Class: tag.ClassContextSpecific, Number: 0}, seqContent_)
		} else {
			enc_rangingslpplist = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, true, enc_rangingslpplist)
		}
		children = append(children, enc_rangingslpplist...)
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

// MarshalDER encodes LCSULRSPPTransportArg to DER format.
func (v *LCSULRSPPTransportArg) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// ITU-T X.690 (02/2021) Section 10.1 requires DER length forms to be definite.
	derValue := *v
	derValue.RangingSLPPListIndef_ = false
	v = &derValue
	return v.MarshalBER()
}

// UnmarshalBER decodes LCSULRSPPTransportArg from BER/DER format.
func (v *LCSULRSPPTransportArg) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding LCSULRSPPTransportArg SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "LCSULRSPPTransportArg", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode rangingSLPPList
	v.RangingSLPPListIndef_ = false
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
				_, n_rangingslpplist, rawVal_rangingslpplist, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding rangingSLPPList: %w", err)
				}
				reconstructed_rangingslpplist := ber.EncodeSequence(rawVal_rangingslpplist)
				dec_rangingslpplist, unmErr := UnmarshalBERRangingSLPPList(reconstructed_rangingslpplist)
				if unmErr != nil {
					return fmt.Errorf("decoding rangingSLPPList: %w", unmErr)
				}
				v.RangingSLPPList = dec_rangingslpplist
				{
					_, tagSz_, _ := ber.DecodeTag(content[offset:])
					if offset+tagSz_ < len(content) && content[offset+tagSz_] == 0x80 {
						v.RangingSLPPListIndef_ = true
					}
				}
				offset += n_rangingslpplist
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "LCSULRSPPTransportArg", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes LCSULRSPPTransportRes to BER format.
func (v *LCSULRSPPTransportRes) MarshalBER() ([]byte, error) {
	return ber.EncodeSequence(nil), nil
}

// MarshalDER encodes LCSULRSPPTransportRes to DER format.
func (v *LCSULRSPPTransportRes) MarshalDER() ([]byte, error) {
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes LCSULRSPPTransportRes from BER/DER format.
func (v *LCSULRSPPTransportRes) UnmarshalBER(data []byte) error {
	_, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding LCSULRSPPTransportRes SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "LCSULRSPPTransportRes", Cause: ber.ErrExtraData}
	}
	return nil
}
