// Code generated from ASN.1 module "MAP-CH-DataTypes". DO NOT EDIT.

package gsm_map

import (
	"fmt"

	"github.com/gomaja/go-asn1/telecom/ss7/gsm_map/runtime"
	"github.com/gomaja/go-asn1/telecom/ss7/gsm_map/runtime/ber"
	"github.com/gomaja/go-asn1/telecom/ss7/gsm_map/runtime/tag"
)

// Ensure imports are used.
var (
	_ runtime.BitString
	_ = ber.EncodeTLV
	_ = tag.ClassUniversal
)

// CUGCheckInfo represents the ASN.1 type CUG-CheckInfo (SEQUENCE).
type CUGCheckInfo struct {
	CugInterlock       CUGInterlock        `asn1:""`
	CugOutgoingAccess  *struct{}           `asn1:",optional" json:"CugOutgoingAccess,omitempty"`
	ExtensionContainer *ExtensionContainer `asn1:",optional" json:"ExtensionContainer,omitempty"`
	ExtCount_          int64               `asn1:"-" json:"-"`
	ExtPresent_        []bool              `asn1:"-" json:"-"`
	// ExtData_ retains complete unknown addition TLVs in received order. Fresh
	// BER and DER copy admissible elements without inferring a foreign schema.
	ExtData_       [][]byte        `asn1:"-" json:"-"`
	berReplayNode_ *ber.ReplayNode `asn1:"-" json:"-"`
}

// NumberOfForwarding represents the ASN.1 type NumberOfForwarding (INTEGER).
type NumberOfForwarding = int64

// SendRoutingInfoArg represents the ASN.1 type SendRoutingInfoArg (SEQUENCE).
type SendRoutingInfoArg struct {
	Msisdn                          ISDNAddressString                `asn1:"tag:0,context,implicit"`
	CugCheckInfo                    *CUGCheckInfo                    `asn1:"tag:1,context,implicit,optional" json:"CugCheckInfo,omitempty"`
	NumberOfForwarding              *NumberOfForwarding              `asn1:"tag:2,context,implicit,optional" json:"NumberOfForwarding,omitempty"`
	InterrogationType               InterrogationType                `asn1:"tag:3,context,implicit"`
	OrInterrogation                 *struct{}                        `asn1:"tag:4,context,implicit,optional" json:"OrInterrogation,omitempty"`
	OrCapability                    *ORPhase                         `asn1:"tag:5,context,implicit,optional" json:"OrCapability,omitempty"`
	GmscOrGsmSCFAddress             ISDNAddressString                `asn1:"tag:6,context,implicit"`
	CallReferenceNumber             *CallReferenceNumber             `asn1:"tag:7,context,implicit,optional" json:"CallReferenceNumber,omitempty"`
	ForwardingReason                *ForwardingReason                `asn1:"tag:8,context,implicit,optional" json:"ForwardingReason,omitempty"`
	BasicServiceGroup               *ExtBasicServiceCode             `asn1:"tag:9,context,explicit,optional" json:"BasicServiceGroup,omitempty"`
	NetworkSignalInfo               *ExternalSignalInfo              `asn1:"tag:10,context,implicit,optional" json:"NetworkSignalInfo,omitempty"`
	CamelInfo                       *CamelInfo                       `asn1:"tag:11,context,implicit,optional" json:"CamelInfo,omitempty"`
	SuppressionOfAnnouncement       *SuppressionOfAnnouncement       `asn1:"tag:12,context,implicit,optional" json:"SuppressionOfAnnouncement,omitempty"`
	ExtensionContainer              *ExtensionContainer              `asn1:"tag:13,context,implicit,optional" json:"ExtensionContainer,omitempty"`
	AlertingPattern                 *AlertingPattern                 `asn1:"tag:14,context,implicit,optional" json:"AlertingPattern,omitempty"`
	CcbsCall                        *struct{}                        `asn1:"tag:15,context,implicit,optional" json:"CcbsCall,omitempty"`
	SupportedCCBSPhase              *SupportedCCBSPhase              `asn1:"tag:16,context,implicit,optional" json:"SupportedCCBSPhase,omitempty"`
	AdditionalSignalInfo            *ExtExternalSignalInfo           `asn1:"tag:17,context,implicit,optional" json:"AdditionalSignalInfo,omitempty"`
	IstSupportIndicator             *ISTSupportIndicator             `asn1:"tag:18,context,implicit,optional" json:"IstSupportIndicator,omitempty"`
	PrePagingSupported              *struct{}                        `asn1:"tag:19,context,implicit,optional" json:"PrePagingSupported,omitempty"`
	CallDiversionTreatmentIndicator *CallDiversionTreatmentIndicator `asn1:"tag:20,context,implicit,optional" json:"CallDiversionTreatmentIndicator,omitempty"`
	LongFTNSupported                *struct{}                        `asn1:"tag:21,context,implicit,optional" json:"LongFTNSupported,omitempty"`
	SuppressVTCSI                   *struct{}                        `asn1:"tag:22,context,implicit,optional" json:"SuppressVTCSI,omitempty"`
	SuppressIncomingCallBarring     *struct{}                        `asn1:"tag:23,context,implicit,optional" json:"SuppressIncomingCallBarring,omitempty"`
	GsmSCFInitiatedCall             *struct{}                        `asn1:"tag:24,context,implicit,optional" json:"GsmSCFInitiatedCall,omitempty"`
	BasicServiceGroup2              *ExtBasicServiceCode             `asn1:"tag:25,context,explicit,optional" json:"BasicServiceGroup2,omitempty"`
	NetworkSignalInfo2              *ExternalSignalInfo              `asn1:"tag:26,context,implicit,optional" json:"NetworkSignalInfo2,omitempty"`
	SuppressMTSS                    *SuppressMTSS                    `asn1:"tag:27,context,implicit,optional" json:"SuppressMTSS,omitempty"`
	MtRoamingRetrySupported         *struct{}                        `asn1:"tag:28,context,implicit,optional" json:"MtRoamingRetrySupported,omitempty"`
	CallPriority                    *EMLPPPriority                   `asn1:"tag:29,context,implicit,optional" json:"CallPriority,omitempty"`
	ExtCount_                       int64                            `asn1:"-" json:"-"`
	ExtPresent_                     []bool                           `asn1:"-" json:"-"`
	// ExtData_ retains complete unknown addition TLVs in received order. Fresh
	// BER and DER copy admissible elements without inferring a foreign schema.
	ExtData_       [][]byte        `asn1:"-" json:"-"`
	berReplayNode_ *ber.ReplayNode `asn1:"-" json:"-"`
}

// SuppressionOfAnnouncement represents the ASN.1 type SuppressionOfAnnouncement (NULL).
type SuppressionOfAnnouncement = struct{}

// SuppressMTSS represents the ASN.1 type SuppressMTSS (BIT_STRING).
type SuppressMTSS = runtime.BitString

const (
	// SuppressMTSSSuppressCUG is position 0 of ASN.1 named bit suppressCUG of SuppressMTSS (ITU-T X.680 (02/2021) §22).
	SuppressMTSSSuppressCUG = 0
	// SuppressMTSSSuppressCCBS is position 1 of ASN.1 named bit suppressCCBS of SuppressMTSS (ITU-T X.680 (02/2021) §22).
	SuppressMTSSSuppressCCBS = 1
)

// InterrogationType represents the ASN.1 ENUMERATED type InterrogationType.
type InterrogationType int64

const (
	InterrogationTypeBasicCall  InterrogationType = 0
	InterrogationTypeForwarding InterrogationType = 1
)

// String returns the ASN.1 named label, or "unknown" for an unlisted value.
func (v InterrogationType) String() string {
	switch v {
	case InterrogationTypeBasicCall:
		return "basicCall"
	case InterrogationTypeForwarding:
		return "forwarding"
	default:
		return "unknown"
	}
}

// ORPhase represents the ASN.1 type OR-Phase (INTEGER).
type ORPhase = int64

// CallReferenceNumber represents the ASN.1 type CallReferenceNumber (OCTET_STRING).
type CallReferenceNumber = []byte

// ForwardingReason represents the ASN.1 ENUMERATED type ForwardingReason.
type ForwardingReason int64

const (
	ForwardingReasonNotReachable ForwardingReason = 0
	ForwardingReasonBusy         ForwardingReason = 1
	ForwardingReasonNoReply      ForwardingReason = 2
)

// String returns the ASN.1 named label, or "unknown" for an unlisted value.
func (v ForwardingReason) String() string {
	switch v {
	case ForwardingReasonNotReachable:
		return "notReachable"
	case ForwardingReasonBusy:
		return "busy"
	case ForwardingReasonNoReply:
		return "noReply"
	default:
		return "unknown"
	}
}

// SupportedCCBSPhase represents the ASN.1 type SupportedCCBS-Phase (INTEGER).
type SupportedCCBSPhase = int64

// CallDiversionTreatmentIndicator represents the ASN.1 type CallDiversionTreatmentIndicator (OCTET_STRING).
type CallDiversionTreatmentIndicator = []byte

// SendRoutingInfoRes represents the ASN.1 type SendRoutingInfoRes (SEQUENCE).
type SendRoutingInfoRes struct {
	Imsi                            *IMSI                    `asn1:"tag:9,context,implicit,optional" json:"Imsi,omitempty"`
	ExtendedRoutingInfo             *ExtendedRoutingInfo     `asn1:",optional" json:"ExtendedRoutingInfo,omitempty"`
	CugCheckInfo                    *CUGCheckInfo            `asn1:"tag:3,context,implicit,optional" json:"CugCheckInfo,omitempty"`
	CugSubscriptionFlag             *struct{}                `asn1:"tag:6,context,implicit,optional" json:"CugSubscriptionFlag,omitempty"`
	SubscriberInfo                  *SubscriberInfo          `asn1:"tag:7,context,implicit,optional" json:"SubscriberInfo,omitempty"`
	SsList                          *SSList                  `asn1:"tag:1,context,implicit,optional" json:"SsList,omitempty"`
	berSsListIndef_                 bool                     `asn1:"-" json:"-"`
	BasicService                    *ExtBasicServiceCode     `asn1:"tag:5,context,explicit,optional" json:"BasicService,omitempty"`
	ForwardingInterrogationRequired *struct{}                `asn1:"tag:4,context,implicit,optional" json:"ForwardingInterrogationRequired,omitempty"`
	VmscAddress                     *ISDNAddressString       `asn1:"tag:2,context,implicit,optional" json:"VmscAddress,omitempty"`
	ExtensionContainer              *ExtensionContainer      `asn1:"tag:0,context,implicit,optional" json:"ExtensionContainer,omitempty"`
	NaeaPreferredCI                 *NAEAPreferredCI         `asn1:"tag:10,context,implicit,optional" json:"NaeaPreferredCI,omitempty"`
	CcbsIndicators                  *CCBSIndicators          `asn1:"tag:11,context,implicit,optional" json:"CcbsIndicators,omitempty"`
	Msisdn                          *ISDNAddressString       `asn1:"tag:12,context,implicit,optional" json:"Msisdn,omitempty"`
	NumberPortabilityStatus         *NumberPortabilityStatus `asn1:"tag:13,context,implicit,optional" json:"NumberPortabilityStatus,omitempty"`
	IstAlertTimer                   *ISTAlertTimerValue      `asn1:"tag:14,context,implicit,optional" json:"IstAlertTimer,omitempty"`
	SupportedCamelPhasesInVMSC      *SupportedCamelPhases    `asn1:"tag:15,context,implicit,optional" json:"SupportedCamelPhasesInVMSC,omitempty"`
	OfferedCamel4CSIsInVMSC         *OfferedCamel4CSIs       `asn1:"tag:16,context,implicit,optional" json:"OfferedCamel4CSIsInVMSC,omitempty"`
	RoutingInfo2                    *RoutingInfo             `asn1:"tag:17,context,explicit,optional" json:"RoutingInfo2,omitempty"`
	SsList2                         *SSList                  `asn1:"tag:18,context,implicit,optional" json:"SsList2,omitempty"`
	berSsList2Indef_                bool                     `asn1:"-" json:"-"`
	BasicService2                   *ExtBasicServiceCode     `asn1:"tag:19,context,explicit,optional" json:"BasicService2,omitempty"`
	AllowedServices                 *AllowedServices         `asn1:"tag:20,context,implicit,optional" json:"AllowedServices,omitempty"`
	UnavailabilityCause             *UnavailabilityCause     `asn1:"tag:21,context,implicit,optional" json:"UnavailabilityCause,omitempty"`
	ReleaseResourcesSupported       *struct{}                `asn1:"tag:22,context,implicit,optional" json:"ReleaseResourcesSupported,omitempty"`
	GsmBearerCapability             *ExternalSignalInfo      `asn1:"tag:23,context,implicit,optional" json:"GsmBearerCapability,omitempty"`
	ExtCount_                       int64                    `asn1:"-" json:"-"`
	ExtPresent_                     []bool                   `asn1:"-" json:"-"`
	// ExtData_ retains complete unknown addition TLVs in received order. Fresh
	// BER and DER copy admissible elements without inferring a foreign schema.
	ExtData_       [][]byte        `asn1:"-" json:"-"`
	berReplayNode_ *ber.ReplayNode `asn1:"-" json:"-"`
}

// AllowedServices represents the ASN.1 type AllowedServices (BIT_STRING).
type AllowedServices = runtime.BitString

const (
	// AllowedServicesFirstServiceAllowed is position 0 of ASN.1 named bit firstServiceAllowed of AllowedServices (ITU-T X.680 (02/2021) §22).
	AllowedServicesFirstServiceAllowed = 0
	// AllowedServicesSecondServiceAllowed is position 1 of ASN.1 named bit secondServiceAllowed of AllowedServices (ITU-T X.680 (02/2021) §22).
	AllowedServicesSecondServiceAllowed = 1
)

// UnavailabilityCause represents the ASN.1 ENUMERATED type UnavailabilityCause.
type UnavailabilityCause int64

const (
	UnavailabilityCauseBearerServiceNotProvisioned UnavailabilityCause = 1
	UnavailabilityCauseTeleserviceNotProvisioned   UnavailabilityCause = 2
	UnavailabilityCauseAbsentSubscriber            UnavailabilityCause = 3
	UnavailabilityCauseBusySubscriber              UnavailabilityCause = 4
	UnavailabilityCauseCallBarred                  UnavailabilityCause = 5
	UnavailabilityCauseCugReject                   UnavailabilityCause = 6
)

// String returns the ASN.1 named label, or "unknown" for an unlisted value.
func (v UnavailabilityCause) String() string {
	switch v {
	case UnavailabilityCauseBearerServiceNotProvisioned:
		return "bearerServiceNotProvisioned"
	case UnavailabilityCauseTeleserviceNotProvisioned:
		return "teleserviceNotProvisioned"
	case UnavailabilityCauseAbsentSubscriber:
		return "absentSubscriber"
	case UnavailabilityCauseBusySubscriber:
		return "busySubscriber"
	case UnavailabilityCauseCallBarred:
		return "callBarred"
	case UnavailabilityCauseCugReject:
		return "cug-Reject"
	default:
		return "unknown"
	}
}

// CCBSIndicators represents the ASN.1 type CCBS-Indicators (SEQUENCE).
type CCBSIndicators struct {
	CcbsPossible          *struct{}           `asn1:"tag:0,context,implicit,optional" json:"CcbsPossible,omitempty"`
	KeepCCBSCallIndicator *struct{}           `asn1:"tag:1,context,implicit,optional" json:"KeepCCBSCallIndicator,omitempty"`
	ExtensionContainer    *ExtensionContainer `asn1:"tag:2,context,implicit,optional" json:"ExtensionContainer,omitempty"`
	ExtCount_             int64               `asn1:"-" json:"-"`
	ExtPresent_           []bool              `asn1:"-" json:"-"`
	// ExtData_ retains complete unknown addition TLVs in received order. Fresh
	// BER and DER copy admissible elements without inferring a foreign schema.
	ExtData_       [][]byte        `asn1:"-" json:"-"`
	berReplayNode_ *ber.ReplayNode `asn1:"-" json:"-"`
}

// RoutingInfo choice constants.
const (
	RoutingInfoChoiceRoamingNumber  = 1
	RoutingInfoChoiceForwardingData = 2
)

// RoutingInfo represents the ASN.1 CHOICE type RoutingInfo.
type RoutingInfo struct {
	Choice         int
	berReplayNode_ *ber.ReplayNode    `json:"-"`
	RoamingNumber  *ISDNAddressString `json:"RoamingNumber,omitempty"`
	ForwardingData *ForwardingData    `json:"ForwardingData,omitempty"`
}

// NewRoutingInfoRoamingNumber creates a RoutingInfo with the roamingNumber alternative.
func NewRoutingInfoRoamingNumber(v ISDNAddressString) RoutingInfo {
	return RoutingInfo{
		Choice:        RoutingInfoChoiceRoamingNumber,
		RoamingNumber: &v,
	}
}

// NewRoutingInfoForwardingData creates a RoutingInfo with the forwardingData alternative.
func NewRoutingInfoForwardingData(v ForwardingData) RoutingInfo {
	return RoutingInfo{
		Choice:         RoutingInfoChoiceForwardingData,
		ForwardingData: &v,
	}
}

// ForwardingData represents the ASN.1 type ForwardingData (SEQUENCE).
type ForwardingData struct {
	ForwardedToNumber     *ISDNAddressString    `asn1:"tag:5,context,implicit,optional" json:"ForwardedToNumber,omitempty"`
	ForwardedToSubaddress *ISDNSubaddressString `asn1:"tag:4,context,implicit,optional" json:"ForwardedToSubaddress,omitempty"`
	ForwardingOptions     *ForwardingOptions    `asn1:"tag:6,context,implicit,optional" json:"ForwardingOptions,omitempty"`
	ExtensionContainer    *ExtensionContainer   `asn1:"tag:7,context,implicit,optional" json:"ExtensionContainer,omitempty"`
	LongForwardedToNumber *FTNAddressString     `asn1:"tag:8,context,implicit,optional" json:"LongForwardedToNumber,omitempty"`
	ExtCount_             int64                 `asn1:"-" json:"-"`
	ExtPresent_           []bool                `asn1:"-" json:"-"`
	// ExtData_ retains complete unknown addition TLVs in received order. Fresh
	// BER and DER copy admissible elements without inferring a foreign schema.
	ExtData_       [][]byte        `asn1:"-" json:"-"`
	berReplayNode_ *ber.ReplayNode `asn1:"-" json:"-"`
}

// ProvideRoamingNumberArg represents the ASN.1 type ProvideRoamingNumberArg (SEQUENCE).
type ProvideRoamingNumberArg struct {
	Imsi                                    IMSI                       `asn1:"tag:0,context,implicit"`
	MscNumber                               ISDNAddressString          `asn1:"tag:1,context,implicit"`
	Msisdn                                  *ISDNAddressString         `asn1:"tag:2,context,implicit,optional" json:"Msisdn,omitempty"`
	Lmsi                                    *LMSI                      `asn1:"tag:4,context,implicit,optional" json:"Lmsi,omitempty"`
	GsmBearerCapability                     *ExternalSignalInfo        `asn1:"tag:5,context,implicit,optional" json:"GsmBearerCapability,omitempty"`
	NetworkSignalInfo                       *ExternalSignalInfo        `asn1:"tag:6,context,implicit,optional" json:"NetworkSignalInfo,omitempty"`
	SuppressionOfAnnouncement               *SuppressionOfAnnouncement `asn1:"tag:7,context,implicit,optional" json:"SuppressionOfAnnouncement,omitempty"`
	GmscAddress                             *ISDNAddressString         `asn1:"tag:8,context,implicit,optional" json:"GmscAddress,omitempty"`
	CallReferenceNumber                     *CallReferenceNumber       `asn1:"tag:9,context,implicit,optional" json:"CallReferenceNumber,omitempty"`
	OrInterrogation                         *struct{}                  `asn1:"tag:10,context,implicit,optional" json:"OrInterrogation,omitempty"`
	ExtensionContainer                      *ExtensionContainer        `asn1:"tag:11,context,implicit,optional" json:"ExtensionContainer,omitempty"`
	AlertingPattern                         *AlertingPattern           `asn1:"tag:12,context,implicit,optional" json:"AlertingPattern,omitempty"`
	CcbsCall                                *struct{}                  `asn1:"tag:13,context,implicit,optional" json:"CcbsCall,omitempty"`
	SupportedCamelPhasesInInterrogatingNode *SupportedCamelPhases      `asn1:"tag:15,context,implicit,optional" json:"SupportedCamelPhasesInInterrogatingNode,omitempty"`
	AdditionalSignalInfo                    *ExtExternalSignalInfo     `asn1:"tag:14,context,implicit,optional" json:"AdditionalSignalInfo,omitempty"`
	OrNotSupportedInGMSC                    *struct{}                  `asn1:"tag:16,context,implicit,optional" json:"OrNotSupportedInGMSC,omitempty"`
	PrePagingSupported                      *struct{}                  `asn1:"tag:17,context,implicit,optional" json:"PrePagingSupported,omitempty"`
	LongFTNSupported                        *struct{}                  `asn1:"tag:18,context,implicit,optional" json:"LongFTNSupported,omitempty"`
	SuppressVTCSI                           *struct{}                  `asn1:"tag:19,context,implicit,optional" json:"SuppressVTCSI,omitempty"`
	OfferedCamel4CSIsInInterrogatingNode    *OfferedCamel4CSIs         `asn1:"tag:20,context,implicit,optional" json:"OfferedCamel4CSIsInInterrogatingNode,omitempty"`
	MtRoamingRetrySupported                 *struct{}                  `asn1:"tag:21,context,implicit,optional" json:"MtRoamingRetrySupported,omitempty"`
	PagingArea                              *PagingArea                `asn1:"tag:22,context,implicit,optional" json:"PagingArea,omitempty"`
	berPagingAreaIndef_                     bool                       `asn1:"-" json:"-"`
	CallPriority                            *EMLPPPriority             `asn1:"tag:23,context,implicit,optional" json:"CallPriority,omitempty"`
	MtrfIndicator                           *struct{}                  `asn1:"tag:24,context,implicit,optional" json:"MtrfIndicator,omitempty"`
	OldMSCNumber                            *ISDNAddressString         `asn1:"tag:25,context,implicit,optional" json:"OldMSCNumber,omitempty"`
	LastUsedLtePLMNId                       *PLMNId                    `asn1:"tag:26,context,implicit,optional" json:"LastUsedLtePLMNId,omitempty"`
	ExtCount_                               int64                      `asn1:"-" json:"-"`
	ExtPresent_                             []bool                     `asn1:"-" json:"-"`
	// ExtData_ retains complete unknown addition TLVs in received order. Fresh
	// BER and DER copy admissible elements without inferring a foreign schema.
	ExtData_       [][]byte        `asn1:"-" json:"-"`
	berReplayNode_ *ber.ReplayNode `asn1:"-" json:"-"`
}

// ProvideRoamingNumberRes represents the ASN.1 type ProvideRoamingNumberRes (SEQUENCE).
type ProvideRoamingNumberRes struct {
	RoamingNumber             ISDNAddressString   `asn1:""`
	ExtensionContainer        *ExtensionContainer `asn1:",optional" json:"ExtensionContainer,omitempty"`
	ReleaseResourcesSupported *struct{}           `asn1:",optional" json:"ReleaseResourcesSupported,omitempty"`
	VmscAddress               *ISDNAddressString  `asn1:",optional" json:"VmscAddress,omitempty"`
	ExtCount_                 int64               `asn1:"-" json:"-"`
	ExtPresent_               []bool              `asn1:"-" json:"-"`
	// ExtData_ retains complete unknown addition TLVs in received order. Fresh
	// BER and DER copy admissible elements without inferring a foreign schema.
	ExtData_       [][]byte        `asn1:"-" json:"-"`
	berReplayNode_ *ber.ReplayNode `asn1:"-" json:"-"`
}

// ResumeCallHandlingArg represents the ASN.1 type ResumeCallHandlingArg (SEQUENCE).
type ResumeCallHandlingArg struct {
	CallReferenceNumber                *CallReferenceNumber       `asn1:"tag:0,context,implicit,optional" json:"CallReferenceNumber,omitempty"`
	BasicServiceGroup                  *ExtBasicServiceCode       `asn1:"tag:1,context,explicit,optional" json:"BasicServiceGroup,omitempty"`
	ForwardingData                     *ForwardingData            `asn1:"tag:2,context,implicit,optional" json:"ForwardingData,omitempty"`
	Imsi                               *IMSI                      `asn1:"tag:3,context,implicit,optional" json:"Imsi,omitempty"`
	CugCheckInfo                       *CUGCheckInfo              `asn1:"tag:4,context,implicit,optional" json:"CugCheckInfo,omitempty"`
	OCSI                               *OCSI                      `asn1:"tag:5,context,implicit,optional" json:"OCSI,omitempty"`
	ExtensionContainer                 *ExtensionContainer        `asn1:"tag:7,context,implicit,optional" json:"ExtensionContainer,omitempty"`
	CcbsPossible                       *struct{}                  `asn1:"tag:8,context,implicit,optional" json:"CcbsPossible,omitempty"`
	Msisdn                             *ISDNAddressString         `asn1:"tag:9,context,implicit,optional" json:"Msisdn,omitempty"`
	UuData                             *UUData                    `asn1:"tag:10,context,implicit,optional" json:"UuData,omitempty"`
	AllInformationSent                 *struct{}                  `asn1:"tag:11,context,implicit,optional" json:"AllInformationSent,omitempty"`
	DCsi                               *DCSI                      `asn1:"tag:12,context,implicit,optional" json:"DCsi,omitempty"`
	OBcsmCamelTDPCriteriaList          *OBcsmCamelTDPCriteriaList `asn1:"tag:13,context,implicit,optional" json:"OBcsmCamelTDPCriteriaList,omitempty"`
	berOBcsmCamelTDPCriteriaListIndef_ bool                       `asn1:"-" json:"-"`
	BasicServiceGroup2                 *ExtBasicServiceCode       `asn1:"tag:14,context,explicit,optional" json:"BasicServiceGroup2,omitempty"`
	MtRoamingRetry                     *struct{}                  `asn1:"tag:15,context,implicit,optional" json:"MtRoamingRetry,omitempty"`
	ExtCount_                          int64                      `asn1:"-" json:"-"`
	ExtPresent_                        []bool                     `asn1:"-" json:"-"`
	// ExtData_ retains complete unknown addition TLVs in received order. Fresh
	// BER and DER copy admissible elements without inferring a foreign schema.
	ExtData_       [][]byte        `asn1:"-" json:"-"`
	berReplayNode_ *ber.ReplayNode `asn1:"-" json:"-"`
}

// UUData represents the ASN.1 type UU-Data (SEQUENCE).
type UUData struct {
	UuIndicator        *UUIndicator        `asn1:"tag:0,context,implicit,optional" json:"UuIndicator,omitempty"`
	Uui                *UUI                `asn1:"tag:1,context,implicit,optional" json:"Uui,omitempty"`
	UusCFInteraction   *struct{}           `asn1:"tag:2,context,implicit,optional" json:"UusCFInteraction,omitempty"`
	ExtensionContainer *ExtensionContainer `asn1:"tag:3,context,implicit,optional" json:"ExtensionContainer,omitempty"`
	ExtCount_          int64               `asn1:"-" json:"-"`
	ExtPresent_        []bool              `asn1:"-" json:"-"`
	// ExtData_ retains complete unknown addition TLVs in received order. Fresh
	// BER and DER copy admissible elements without inferring a foreign schema.
	ExtData_       [][]byte        `asn1:"-" json:"-"`
	berReplayNode_ *ber.ReplayNode `asn1:"-" json:"-"`
}

// UUIndicator represents the ASN.1 type UUIndicator (OCTET_STRING).
type UUIndicator = []byte

// UUI represents the ASN.1 type UUI (OCTET_STRING).
type UUI = []byte

// ResumeCallHandlingRes represents the ASN.1 type ResumeCallHandlingRes (SEQUENCE).
type ResumeCallHandlingRes struct {
	ExtensionContainer *ExtensionContainer `asn1:",optional" json:"ExtensionContainer,omitempty"`
	ExtCount_          int64               `asn1:"-" json:"-"`
	ExtPresent_        []bool              `asn1:"-" json:"-"`
	// ExtData_ retains complete unknown addition TLVs in received order. Fresh
	// BER and DER copy admissible elements without inferring a foreign schema.
	ExtData_       [][]byte        `asn1:"-" json:"-"`
	berReplayNode_ *ber.ReplayNode `asn1:"-" json:"-"`
}

// CamelInfo represents the ASN.1 type CamelInfo (SEQUENCE).
type CamelInfo struct {
	SupportedCamelPhases SupportedCamelPhases `asn1:""`
	SuppressTCSI         *struct{}            `asn1:",optional" json:"SuppressTCSI,omitempty"`
	ExtensionContainer   *ExtensionContainer  `asn1:",optional" json:"ExtensionContainer,omitempty"`
	OfferedCamel4CSIs    *OfferedCamel4CSIs   `asn1:"tag:0,context,implicit,optional" json:"OfferedCamel4CSIs,omitempty"`
	ExtCount_            int64                `asn1:"-" json:"-"`
	ExtPresent_          []bool               `asn1:"-" json:"-"`
	// ExtData_ retains complete unknown addition TLVs in received order. Fresh
	// BER and DER copy admissible elements without inferring a foreign schema.
	ExtData_       [][]byte        `asn1:"-" json:"-"`
	berReplayNode_ *ber.ReplayNode `asn1:"-" json:"-"`
}

// ExtendedRoutingInfo choice constants.
const (
	ExtendedRoutingInfoChoiceRoutingInfo      = 1
	ExtendedRoutingInfoChoiceCamelRoutingInfo = 2
)

// ExtendedRoutingInfo represents the ASN.1 CHOICE type ExtendedRoutingInfo.
type ExtendedRoutingInfo struct {
	Choice           int
	berReplayNode_   *ber.ReplayNode   `json:"-"`
	RoutingInfo      *RoutingInfo      `json:"RoutingInfo,omitempty"`
	CamelRoutingInfo *CamelRoutingInfo `json:"CamelRoutingInfo,omitempty"`
}

// NewExtendedRoutingInfoRoutingInfo creates a ExtendedRoutingInfo with the routingInfo alternative.
func NewExtendedRoutingInfoRoutingInfo(v RoutingInfo) ExtendedRoutingInfo {
	return ExtendedRoutingInfo{
		Choice:      ExtendedRoutingInfoChoiceRoutingInfo,
		RoutingInfo: &v,
	}
}

// NewExtendedRoutingInfoCamelRoutingInfo creates a ExtendedRoutingInfo with the camelRoutingInfo alternative.
func NewExtendedRoutingInfoCamelRoutingInfo(v CamelRoutingInfo) ExtendedRoutingInfo {
	return ExtendedRoutingInfo{
		Choice:           ExtendedRoutingInfoChoiceCamelRoutingInfo,
		CamelRoutingInfo: &v,
	}
}

// CamelRoutingInfo represents the ASN.1 type CamelRoutingInfo (SEQUENCE).
type CamelRoutingInfo struct {
	ForwardingData            *ForwardingData           `asn1:",optional" json:"ForwardingData,omitempty"`
	GmscCamelSubscriptionInfo GmscCamelSubscriptionInfo `asn1:"tag:0,context,implicit"`
	ExtensionContainer        *ExtensionContainer       `asn1:"tag:1,context,implicit,optional" json:"ExtensionContainer,omitempty"`
	ExtCount_                 int64                     `asn1:"-" json:"-"`
	ExtPresent_               []bool                    `asn1:"-" json:"-"`
	// ExtData_ retains complete unknown addition TLVs in received order. Fresh
	// BER and DER copy admissible elements without inferring a foreign schema.
	ExtData_       [][]byte        `asn1:"-" json:"-"`
	berReplayNode_ *ber.ReplayNode `asn1:"-" json:"-"`
}

// GmscCamelSubscriptionInfo represents the ASN.1 type GmscCamelSubscriptionInfo (SEQUENCE).
type GmscCamelSubscriptionInfo struct {
	TCSI                               *TCSI                      `asn1:"tag:0,context,implicit,optional" json:"TCSI,omitempty"`
	OCSI                               *OCSI                      `asn1:"tag:1,context,implicit,optional" json:"OCSI,omitempty"`
	ExtensionContainer                 *ExtensionContainer        `asn1:"tag:2,context,implicit,optional" json:"ExtensionContainer,omitempty"`
	OBcsmCamelTDPCriteriaList          *OBcsmCamelTDPCriteriaList `asn1:"tag:3,context,implicit,optional" json:"OBcsmCamelTDPCriteriaList,omitempty"`
	berOBcsmCamelTDPCriteriaListIndef_ bool                       `asn1:"-" json:"-"`
	TBCSMCAMELTDPCriteriaList          *TBCSMCAMELTDPCriteriaList `asn1:"tag:4,context,implicit,optional" json:"TBCSMCAMELTDPCriteriaList,omitempty"`
	berTBCSMCAMELTDPCriteriaListIndef_ bool                       `asn1:"-" json:"-"`
	DCsi                               *DCSI                      `asn1:"tag:5,context,implicit,optional" json:"DCsi,omitempty"`
	ExtCount_                          int64                      `asn1:"-" json:"-"`
	ExtPresent_                        []bool                     `asn1:"-" json:"-"`
	// ExtData_ retains complete unknown addition TLVs in received order. Fresh
	// BER and DER copy admissible elements without inferring a foreign schema.
	ExtData_       [][]byte        `asn1:"-" json:"-"`
	berReplayNode_ *ber.ReplayNode `asn1:"-" json:"-"`
}

// SetReportingStateArg represents the ASN.1 type SetReportingStateArg (SEQUENCE).
type SetReportingStateArg struct {
	Imsi               *IMSI               `asn1:"tag:0,context,implicit,optional" json:"Imsi,omitempty"`
	Lmsi               *LMSI               `asn1:"tag:1,context,implicit,optional" json:"Lmsi,omitempty"`
	CcbsMonitoring     *ReportingState     `asn1:"tag:2,context,implicit,optional" json:"CcbsMonitoring,omitempty"`
	ExtensionContainer *ExtensionContainer `asn1:"tag:3,context,implicit,optional" json:"ExtensionContainer,omitempty"`
	ExtCount_          int64               `asn1:"-" json:"-"`
	ExtPresent_        []bool              `asn1:"-" json:"-"`
	// ExtData_ retains complete unknown addition TLVs in received order. Fresh
	// BER and DER copy admissible elements without inferring a foreign schema.
	ExtData_       [][]byte        `asn1:"-" json:"-"`
	berReplayNode_ *ber.ReplayNode `asn1:"-" json:"-"`
}

// ReportingState represents the ASN.1 ENUMERATED type ReportingState.
type ReportingState int64

const (
	ReportingStateStopMonitoring  ReportingState = 0
	ReportingStateStartMonitoring ReportingState = 1
)

// String returns the ASN.1 named label, or "unknown" for an unlisted value.
func (v ReportingState) String() string {
	switch v {
	case ReportingStateStopMonitoring:
		return "stopMonitoring"
	case ReportingStateStartMonitoring:
		return "startMonitoring"
	default:
		return "unknown"
	}
}

// SetReportingStateRes represents the ASN.1 type SetReportingStateRes (SEQUENCE).
type SetReportingStateRes struct {
	CcbsSubscriberStatus *CCBSSubscriberStatus `asn1:"tag:0,context,implicit,optional" json:"CcbsSubscriberStatus,omitempty"`
	ExtensionContainer   *ExtensionContainer   `asn1:"tag:1,context,implicit,optional" json:"ExtensionContainer,omitempty"`
	ExtCount_            int64                 `asn1:"-" json:"-"`
	ExtPresent_          []bool                `asn1:"-" json:"-"`
	// ExtData_ retains complete unknown addition TLVs in received order. Fresh
	// BER and DER copy admissible elements without inferring a foreign schema.
	ExtData_       [][]byte        `asn1:"-" json:"-"`
	berReplayNode_ *ber.ReplayNode `asn1:"-" json:"-"`
}

// CCBSSubscriberStatus represents the ASN.1 ENUMERATED type CCBS-SubscriberStatus.
type CCBSSubscriberStatus int64

const (
	CCBSSubscriberStatusCcbsNotIdle      CCBSSubscriberStatus = 0
	CCBSSubscriberStatusCcbsIdle         CCBSSubscriberStatus = 1
	CCBSSubscriberStatusCcbsNotReachable CCBSSubscriberStatus = 2
)

// String returns the ASN.1 named label, or "unknown" for an unlisted value.
func (v CCBSSubscriberStatus) String() string {
	switch v {
	case CCBSSubscriberStatusCcbsNotIdle:
		return "ccbsNotIdle"
	case CCBSSubscriberStatusCcbsIdle:
		return "ccbsIdle"
	case CCBSSubscriberStatusCcbsNotReachable:
		return "ccbsNotReachable"
	default:
		return "unknown"
	}
}

// StatusReportArg represents the ASN.1 type StatusReportArg (SEQUENCE).
type StatusReportArg struct {
	Imsi               IMSI                `asn1:"tag:0,context,implicit"`
	EventReportData    *EventReportData    `asn1:"tag:1,context,implicit,optional" json:"EventReportData,omitempty"`
	CallReportdata     *CallReportData     `asn1:"tag:2,context,implicit,optional" json:"CallReportdata,omitempty"`
	ExtensionContainer *ExtensionContainer `asn1:"tag:3,context,implicit,optional" json:"ExtensionContainer,omitempty"`
	ExtCount_          int64               `asn1:"-" json:"-"`
	ExtPresent_        []bool              `asn1:"-" json:"-"`
	// ExtData_ retains complete unknown addition TLVs in received order. Fresh
	// BER and DER copy admissible elements without inferring a foreign schema.
	ExtData_       [][]byte        `asn1:"-" json:"-"`
	berReplayNode_ *ber.ReplayNode `asn1:"-" json:"-"`
}

// EventReportData represents the ASN.1 type EventReportData (SEQUENCE).
type EventReportData struct {
	CcbsSubscriberStatus *CCBSSubscriberStatus `asn1:"tag:0,context,implicit,optional" json:"CcbsSubscriberStatus,omitempty"`
	ExtensionContainer   *ExtensionContainer   `asn1:"tag:1,context,implicit,optional" json:"ExtensionContainer,omitempty"`
	ExtCount_            int64                 `asn1:"-" json:"-"`
	ExtPresent_          []bool                `asn1:"-" json:"-"`
	// ExtData_ retains complete unknown addition TLVs in received order. Fresh
	// BER and DER copy admissible elements without inferring a foreign schema.
	ExtData_       [][]byte        `asn1:"-" json:"-"`
	berReplayNode_ *ber.ReplayNode `asn1:"-" json:"-"`
}

// CallReportData represents the ASN.1 type CallReportData (SEQUENCE).
type CallReportData struct {
	MonitoringMode     *MonitoringMode     `asn1:"tag:0,context,implicit,optional" json:"MonitoringMode,omitempty"`
	CallOutcome        *CallOutcome        `asn1:"tag:1,context,implicit,optional" json:"CallOutcome,omitempty"`
	ExtensionContainer *ExtensionContainer `asn1:"tag:2,context,implicit,optional" json:"ExtensionContainer,omitempty"`
	ExtCount_          int64               `asn1:"-" json:"-"`
	ExtPresent_        []bool              `asn1:"-" json:"-"`
	// ExtData_ retains complete unknown addition TLVs in received order. Fresh
	// BER and DER copy admissible elements without inferring a foreign schema.
	ExtData_       [][]byte        `asn1:"-" json:"-"`
	berReplayNode_ *ber.ReplayNode `asn1:"-" json:"-"`
}

// MonitoringMode represents the ASN.1 ENUMERATED type MonitoringMode.
type MonitoringMode int64

const (
	MonitoringModeASide MonitoringMode = 0
	MonitoringModeBSide MonitoringMode = 1
)

// String returns the ASN.1 named label, or "unknown" for an unlisted value.
func (v MonitoringMode) String() string {
	switch v {
	case MonitoringModeASide:
		return "a-side"
	case MonitoringModeBSide:
		return "b-side"
	default:
		return "unknown"
	}
}

// CallOutcome represents the ASN.1 ENUMERATED type CallOutcome.
type CallOutcome int64

const (
	CallOutcomeSuccess CallOutcome = 0
	CallOutcomeFailure CallOutcome = 1
	CallOutcomeBusy    CallOutcome = 2
)

// String returns the ASN.1 named label, or "unknown" for an unlisted value.
func (v CallOutcome) String() string {
	switch v {
	case CallOutcomeSuccess:
		return "success"
	case CallOutcomeFailure:
		return "failure"
	case CallOutcomeBusy:
		return "busy"
	default:
		return "unknown"
	}
}

// StatusReportRes represents the ASN.1 type StatusReportRes (SEQUENCE).
type StatusReportRes struct {
	ExtensionContainer *ExtensionContainer `asn1:"tag:0,context,implicit,optional" json:"ExtensionContainer,omitempty"`
	ExtCount_          int64               `asn1:"-" json:"-"`
	ExtPresent_        []bool              `asn1:"-" json:"-"`
	// ExtData_ retains complete unknown addition TLVs in received order. Fresh
	// BER and DER copy admissible elements without inferring a foreign schema.
	ExtData_       [][]byte        `asn1:"-" json:"-"`
	berReplayNode_ *ber.ReplayNode `asn1:"-" json:"-"`
}

// RemoteUserFreeArg represents the ASN.1 type RemoteUserFreeArg (SEQUENCE).
type RemoteUserFreeArg struct {
	Imsi               IMSI                `asn1:"tag:0,context,implicit"`
	CallInfo           ExternalSignalInfo  `asn1:"tag:1,context,implicit"`
	CcbsFeature        CCBSFeature         `asn1:"tag:2,context,implicit"`
	TranslatedBNumber  ISDNAddressString   `asn1:"tag:3,context,implicit"`
	ReplaceBNumber     *struct{}           `asn1:"tag:4,context,implicit,optional" json:"ReplaceBNumber,omitempty"`
	AlertingPattern    *AlertingPattern    `asn1:"tag:5,context,implicit,optional" json:"AlertingPattern,omitempty"`
	ExtensionContainer *ExtensionContainer `asn1:"tag:6,context,implicit,optional" json:"ExtensionContainer,omitempty"`
	ExtCount_          int64               `asn1:"-" json:"-"`
	ExtPresent_        []bool              `asn1:"-" json:"-"`
	// ExtData_ retains complete unknown addition TLVs in received order. Fresh
	// BER and DER copy admissible elements without inferring a foreign schema.
	ExtData_       [][]byte        `asn1:"-" json:"-"`
	berReplayNode_ *ber.ReplayNode `asn1:"-" json:"-"`
}

// RemoteUserFreeRes represents the ASN.1 type RemoteUserFreeRes (SEQUENCE).
type RemoteUserFreeRes struct {
	RufOutcome         RUFOutcome          `asn1:"tag:0,context,implicit"`
	ExtensionContainer *ExtensionContainer `asn1:"tag:1,context,implicit,optional" json:"ExtensionContainer,omitempty"`
	ExtCount_          int64               `asn1:"-" json:"-"`
	ExtPresent_        []bool              `asn1:"-" json:"-"`
	// ExtData_ retains complete unknown addition TLVs in received order. Fresh
	// BER and DER copy admissible elements without inferring a foreign schema.
	ExtData_       [][]byte        `asn1:"-" json:"-"`
	berReplayNode_ *ber.ReplayNode `asn1:"-" json:"-"`
}

// RUFOutcome represents the ASN.1 ENUMERATED type RUF-Outcome.
type RUFOutcome int64

const (
	RUFOutcomeAccepted             RUFOutcome = 0
	RUFOutcomeRejected             RUFOutcome = 1
	RUFOutcomeNoResponseFromFreeMS RUFOutcome = 2
	RUFOutcomeNoResponseFromBusyMS RUFOutcome = 3
	RUFOutcomeUdubFromFreeMS       RUFOutcome = 4
	RUFOutcomeUdubFromBusyMS       RUFOutcome = 5
)

// String returns the ASN.1 named label, or "unknown" for an unlisted value.
func (v RUFOutcome) String() string {
	switch v {
	case RUFOutcomeAccepted:
		return "accepted"
	case RUFOutcomeRejected:
		return "rejected"
	case RUFOutcomeNoResponseFromFreeMS:
		return "noResponseFromFreeMS"
	case RUFOutcomeNoResponseFromBusyMS:
		return "noResponseFromBusyMS"
	case RUFOutcomeUdubFromFreeMS:
		return "udubFromFreeMS"
	case RUFOutcomeUdubFromBusyMS:
		return "udubFromBusyMS"
	default:
		return "unknown"
	}
}

// ISTAlertArg represents the ASN.1 type IST-AlertArg (SEQUENCE).
type ISTAlertArg struct {
	Imsi               IMSI                `asn1:"tag:0,context,implicit"`
	ExtensionContainer *ExtensionContainer `asn1:"tag:1,context,implicit,optional" json:"ExtensionContainer,omitempty"`
	ExtCount_          int64               `asn1:"-" json:"-"`
	ExtPresent_        []bool              `asn1:"-" json:"-"`
	// ExtData_ retains complete unknown addition TLVs in received order. Fresh
	// BER and DER copy admissible elements without inferring a foreign schema.
	ExtData_       [][]byte        `asn1:"-" json:"-"`
	berReplayNode_ *ber.ReplayNode `asn1:"-" json:"-"`
}

// ISTAlertRes represents the ASN.1 type IST-AlertRes (SEQUENCE).
type ISTAlertRes struct {
	IstAlertTimer            *ISTAlertTimerValue       `asn1:"tag:0,context,implicit,optional" json:"IstAlertTimer,omitempty"`
	IstInformationWithdraw   *struct{}                 `asn1:"tag:1,context,implicit,optional" json:"IstInformationWithdraw,omitempty"`
	CallTerminationIndicator *CallTerminationIndicator `asn1:"tag:2,context,implicit,optional" json:"CallTerminationIndicator,omitempty"`
	ExtensionContainer       *ExtensionContainer       `asn1:"tag:3,context,implicit,optional" json:"ExtensionContainer,omitempty"`
	ExtCount_                int64                     `asn1:"-" json:"-"`
	ExtPresent_              []bool                    `asn1:"-" json:"-"`
	// ExtData_ retains complete unknown addition TLVs in received order. Fresh
	// BER and DER copy admissible elements without inferring a foreign schema.
	ExtData_       [][]byte        `asn1:"-" json:"-"`
	berReplayNode_ *ber.ReplayNode `asn1:"-" json:"-"`
}

// ISTCommandArg represents the ASN.1 type IST-CommandArg (SEQUENCE).
type ISTCommandArg struct {
	Imsi               IMSI                `asn1:"tag:0,context,implicit"`
	ExtensionContainer *ExtensionContainer `asn1:"tag:1,context,implicit,optional" json:"ExtensionContainer,omitempty"`
	ExtCount_          int64               `asn1:"-" json:"-"`
	ExtPresent_        []bool              `asn1:"-" json:"-"`
	// ExtData_ retains complete unknown addition TLVs in received order. Fresh
	// BER and DER copy admissible elements without inferring a foreign schema.
	ExtData_       [][]byte        `asn1:"-" json:"-"`
	berReplayNode_ *ber.ReplayNode `asn1:"-" json:"-"`
}

// ISTCommandRes represents the ASN.1 type IST-CommandRes (SEQUENCE).
type ISTCommandRes struct {
	ExtensionContainer *ExtensionContainer `asn1:",optional" json:"ExtensionContainer,omitempty"`
	ExtCount_          int64               `asn1:"-" json:"-"`
	ExtPresent_        []bool              `asn1:"-" json:"-"`
	// ExtData_ retains complete unknown addition TLVs in received order. Fresh
	// BER and DER copy admissible elements without inferring a foreign schema.
	ExtData_       [][]byte        `asn1:"-" json:"-"`
	berReplayNode_ *ber.ReplayNode `asn1:"-" json:"-"`
}

// CallTerminationIndicator represents the ASN.1 ENUMERATED type CallTerminationIndicator.
type CallTerminationIndicator int64

const (
	CallTerminationIndicatorTerminateCallActivityReferred CallTerminationIndicator = 0
	CallTerminationIndicatorTerminateAllCallActivities    CallTerminationIndicator = 1
)

// String returns the ASN.1 named label, or "unknown" for an unlisted value.
func (v CallTerminationIndicator) String() string {
	switch v {
	case CallTerminationIndicatorTerminateCallActivityReferred:
		return "terminateCallActivityReferred"
	case CallTerminationIndicatorTerminateAllCallActivities:
		return "terminateAllCallActivities"
	default:
		return "unknown"
	}
}

// ReleaseResourcesArg represents the ASN.1 type ReleaseResourcesArg (SEQUENCE).
type ReleaseResourcesArg struct {
	Msrn               ISDNAddressString   `asn1:""`
	ExtensionContainer *ExtensionContainer `asn1:",optional" json:"ExtensionContainer,omitempty"`
	ExtCount_          int64               `asn1:"-" json:"-"`
	ExtPresent_        []bool              `asn1:"-" json:"-"`
	// ExtData_ retains complete unknown addition TLVs in received order. Fresh
	// BER and DER copy admissible elements without inferring a foreign schema.
	ExtData_       [][]byte        `asn1:"-" json:"-"`
	berReplayNode_ *ber.ReplayNode `asn1:"-" json:"-"`
}

// ReleaseResourcesRes represents the ASN.1 type ReleaseResourcesRes (SEQUENCE).
type ReleaseResourcesRes struct {
	ExtensionContainer *ExtensionContainer `asn1:",optional" json:"ExtensionContainer,omitempty"`
	ExtCount_          int64               `asn1:"-" json:"-"`
	ExtPresent_        []bool              `asn1:"-" json:"-"`
	// ExtData_ retains complete unknown addition TLVs in received order. Fresh
	// BER and DER copy admissible elements without inferring a foreign schema.
	ExtData_       [][]byte        `asn1:"-" json:"-"`
	berReplayNode_ *ber.ReplayNode `asn1:"-" json:"-"`
}

// MarshalBER encodes CUGCheckInfo to BER format.
func (v *CUGCheckInfo) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {

	if v == nil {
		return nil, fmt.Errorf("%w: CUGCheckInfo receiver is nil", ber.ErrInvalidValue)
	}
	return marshalFramedValue(v, v.berReplayNode_, opts, (*CUGCheckInfo).MarshalBER, (*CUGCheckInfo).marshalBER, 3)

}
func (v *CUGCheckInfo) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if len(v.CugInterlock) < 4 || len(v.CugInterlock) > 4 {
		if constraintErr := checkEncodedLength(opts, s47bb6e_0, "51.5", "cug-Interlock", "SIZE (4)", len(v.CugInterlock)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_cuginterlock, encodeErr_enc_cuginterlock := ber.EncodeOctetString([]byte(v.CugInterlock))
	if encodeErr_enc_cuginterlock != nil {
		return nil, qualifyBERError(encodeErr_enc_cuginterlock, "cug-Interlock", "encoding", false)
	}
	children = append(children, enc_cuginterlock...)
	if v.CugOutgoingAccess != nil {
		enc_cugoutgoingaccess := ber.EncodeNull()
		children = append(children, enc_cugoutgoingaccess...)
	}
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalBER(ber.ChildEncodeOptions(opts, "extensionContainer")...)
		if err != nil {
			return nil, qualifyBERError(err, "extensionContainer", "encoding", false)
		}
		ber.RecordGeneratedBERChildPlacement(opts, len(children), enc_extensioncontainer)
		children = append(children, enc_extensioncontainer...)
	}
	base_ := -1
	for i, ext := range v.ExtData_ {
		if err := checkOpaqueAddition(ext, opts, s47bb6e_0, children, i, &base_); err != nil {
			return nil, opaqueExtensionError(err, i)
		}
		peekTag, n, _, extErr := ber.DecodeEncodedTLV(ext)
		if extErr != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, extErr)
		}
		if n != len(ext) {
			return nil, fmt.Errorf("encoding extension %d: %w", i, ber.ErrExtraData)
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: only the first addition is restricted.
		if i == 0 && ((peekTag.Class == tag.ClassUniversal && peekTag.Number == 16) || (peekTag.Class == tag.ClassUniversal && peekTag.Number == 5)) {
			if constraintErr := ber.CheckEncodedValue(ber.EncodeRule(opts, s47bb6e_0, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
				return nil, constraintErr
			}
		}
		children = append(children, ext...)
	}
	ber.RecordGeneratedBERContainer(opts, children)
	return ber.EncodeSequence(children)
}
func (v *CUGCheckInfo) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// MarshalDER encodes CUGCheckInfo to DER format.
// Opaque descendants pass generic DER checks; foreign schema rules need a typed binding.
func (v *CUGCheckInfo) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: CUGCheckInfo receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if len(v.CugInterlock) < 4 || len(v.CugInterlock) > 4 {
		if constraintErr := checkEncodedLength(nil, s47bb6e_0, "51.5", "cug-Interlock", "SIZE (4)", len(v.CugInterlock)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_cuginterlock, encodeErr_enc_cuginterlock := ber.EncodeOctetString([]byte(v.CugInterlock))
	if encodeErr_enc_cuginterlock != nil {
		return nil, qualifyBERError(encodeErr_enc_cuginterlock, "cug-Interlock", "encoding", true)
	}
	children = append(children, enc_cuginterlock...)
	if v.CugOutgoingAccess != nil {
		enc_cugoutgoingaccess := ber.EncodeNull()
		children = append(children, enc_cugoutgoingaccess...)
	}
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalDER()
		if err != nil {
			return nil, qualifyBERError(err, "extensionContainer", "encoding", true)
		}
		children = append(children, enc_extensioncontainer...)
	}
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDEREncodedElement(ext); err != nil {
			return nil, invalidDERAddition(ext, s47bb6e_0, children, i)
		}
		peekTag, _, _, extErr := ber.DecodeEncodedTLV(ext)
		if extErr != nil {
			return nil, extErr
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: only the first addition is restricted.
		if i == 0 && ((peekTag.Class == tag.ClassUniversal && peekTag.Number == 16) || (peekTag.Class == tag.ClassUniversal && peekTag.Number == 5)) {
			if constraintErr := ber.CheckEncodedValue(ber.EncodeRule(nil, s47bb6e_0, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
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
		return nil, fmt.Errorf("%s: %w", "encoding CUGCheckInfo as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}
func (v *CUGCheckInfo) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	encoded, err := v.MarshalDER()
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBER decodes CUGCheckInfo from BER/DER format.
func (destination *CUGCheckInfo) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if destination == nil {
		return fmt.Errorf("%w: CUGCheckInfo destination is nil", ber.ErrInvalidValue)
	}
	v := new(CUGCheckInfo)
	defer publishDecodedValue(destination, v, &returnErr)

	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	preparedData, preparedOptions, prepareErr := prepareCompositeBER(data, opts, s47bb6e_0, "child", (*CUGCheckInfo).UnmarshalBER)
	if prepareErr != nil {
		return prepareErr
	}
	data, opts = preparedData, preparedOptions

	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
	*v = CUGCheckInfo{}
	defer func() {
		if returnErr == nil {
			returnErr = completeValueBER(data,
				opts, v, &v.berReplayNode_, (*CUGCheckInfo).MarshalBER)
		}

	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("%s: %w", "decoding CUGCheckInfo SEQUENCE", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "CUGCheckInfo", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode cug-Interlock
	if offset >= len(content) {
		return fmt.Errorf("missing required field cug-Interlock")
	}
	{
		ber.MarkPreflightTarget(opts, "cug-Interlock", content[offset:])
		val_cuginterlock, n, err := ber.DecodeOctetString(content[offset:], opts...)
		if err != nil {
			return qualifyBERError(err, "cug-Interlock", "decoding", false)
		}
		v.CugInterlock = CUGInterlock(val_cuginterlock)
		if offset > len(content) || n < 0 || n > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n
		if len(v.CugInterlock) < 4 || len(v.CugInterlock) > 4 {
			if constraintErr := checkDecodedLength(opts, s47bb6e_0, "51.5", "cug-Interlock", "SIZE (4)", len(v.CugInterlock)); constraintErr != nil {
				return constraintErr
			}
		}
	}
	// Decode cug-OutgoingAccess
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassUniversal && peekTag.Number == 5 {
				ber.MarkPreflightTarget(opts, "cug-OutgoingAccess", content[offset:])
				n, err := ber.DecodeNull(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "cug-OutgoingAccess", "decoding", false)
				}
				v.CugOutgoingAccess = &struct{}{}
				if offset < 0 || offset >
					len(content) || n < 0 || n > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n
			}
		}
	}
	// Decode extensionContainer
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassUniversal && peekTag.Number == 16 {
				ber.MarkPreflightTarget(opts, "extensionContainer", content[offset:])
				// Decode nested SEQUENCE (ExtensionContainer)
				_, n_extensioncontainer, _, tlvErr_extensioncontainer := ber.DecodeTLV(content[offset:], opts...)
				if tlvErr_extensioncontainer != nil {
					return qualifyBERError(tlvErr_extensioncontainer, "extensionContainer", "decoding", false)
				}
				var dec_extensioncontainer ExtensionContainer
				if offset < 0 || offset >
					len(content) || n_extensioncontainer < 0 || n_extensioncontainer >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				if unmErr := dec_extensioncontainer.UnmarshalBER(content[offset:offset+n_extensioncontainer], ber.ChildDecodeOptions(opts, "extensionContainer")...); unmErr != nil {
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
			return &ber.DecodeError{Offset: offset, TypeName: "CUGCheckInfo", Cause: extErr_}
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: the first unknown addition must differ from trailing OPTIONAL/DEFAULT tags.
		if len(v.ExtData_) == 0 && ((peekTag.Class == tag.ClassUniversal && peekTag.Number == 16) || (peekTag.Class == tag.ClassUniversal && peekTag.Number == 5)) {
			if !ber.ToleranceEnabled(opts) {
				return &ber.DecodeError{Offset: offset, TypeName: "CUGCheckInfo", Cause: fmt.Errorf("%w: repeated or out-of-order SEQUENCE component tag %s", ber.ErrInvalidTag, peekTag)}
			}
			if orderErr_ := ber.CheckDecodedValue(ber.DecodeRule(opts, s47bb6e_0, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), fmt.Sprintf("ExtData_[%d]", len(v.ExtData_)), "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); orderErr_ != nil {
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

// MarshalBER encodes SendRoutingInfoArg to BER format.
func (v *SendRoutingInfoArg) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {

	if v == nil {
		return nil, fmt.Errorf("%w: SendRoutingInfoArg receiver is nil", ber.ErrInvalidValue)
	}
	return marshalFramedValue(v, v.berReplayNode_, opts, (*SendRoutingInfoArg).MarshalBER, (*SendRoutingInfoArg).marshalBER, 3)

}
func (v *SendRoutingInfoArg) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if len(v.Msisdn) < 1 || len(v.Msisdn) > 9 {
		if constraintErr := checkEncodedLength(opts, s47bb6e_1, "51.5", "msisdn", "SIZE (1..9)", len(v.Msisdn)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	if len(v.Msisdn) < 1 || len(v.Msisdn) > 20 {
		if constraintErr := checkEncodedLength(opts, s47bb6e_1, "51.5", "msisdn", "SIZE (1..20)", len(v.Msisdn)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_msisdn, encodeErr_enc_msisdn := ber.EncodeOctetString([]byte(v.Msisdn))
	if encodeErr_enc_msisdn != nil {
		return nil, qualifyBERError(encodeErr_enc_msisdn, "msisdn", "encoding", false)
	}
	retagged_enc_msisdn, tagErr_enc_msisdn := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_msisdn)
	if tagErr_enc_msisdn != nil {
		return nil, qualifyBERError(tagErr_enc_msisdn, "msisdn", "encoding", false)
	}
	enc_msisdn = retagged_enc_msisdn
	children = append(children, enc_msisdn...)
	if v.CugCheckInfo != nil {
		enc_cugcheckinfo, err := v.CugCheckInfo.MarshalBER(ber.ChildEncodeOptions(opts, "cug-CheckInfo")...)
		if err != nil {
			return nil, qualifyBERError(err, "cug-CheckInfo", "encoding", false)
		}
		retagged_enc_cugcheckinfo, tagErr_enc_cugcheckinfo := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_cugcheckinfo)
		if tagErr_enc_cugcheckinfo != nil {
			return nil, qualifyBERError(tagErr_enc_cugcheckinfo, "cug-CheckInfo", "encoding", false)
		}
		enc_cugcheckinfo = retagged_enc_cugcheckinfo
		ber.RecordGeneratedBERChildPlacement(opts, len(children), enc_cugcheckinfo)
		children = append(children, enc_cugcheckinfo...)
	}
	if v.NumberOfForwarding != nil {
		if !(int64(*v.NumberOfForwarding) >= 1 && int64(*v.NumberOfForwarding) <= 5) {
			if constraintErr := checkEncodedValue(opts, s47bb6e_1, "51.4", "numberOfForwarding", "(1..5)", ber.ObserveInteger(int64(*v.NumberOfForwarding))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_numberofforwarding := ber.EncodeInteger(int64(*v.NumberOfForwarding))
		retagged_enc_numberofforwarding, tagErr_enc_numberofforwarding := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_numberofforwarding)
		if tagErr_enc_numberofforwarding != nil {
			return nil, qualifyBERError(tagErr_enc_numberofforwarding, "numberOfForwarding", "encoding", false)
		}
		enc_numberofforwarding = retagged_enc_numberofforwarding
		children = append(children, enc_numberofforwarding...)
	}
	if int64(v.InterrogationType) != 0 && int64(v.InterrogationType) != 1 {
		if constraintErr := checkEncodedValue(opts, s47bb6e_1, "20", "interrogationType", "ENUMERATED {0, 1}", ber.ObserveInteger(int64(v.InterrogationType))); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_interrogationtype := ber.EncodeEnumerated(int64(v.InterrogationType))
	retagged_enc_interrogationtype, tagErr_enc_interrogationtype := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, enc_interrogationtype)
	if tagErr_enc_interrogationtype != nil {
		return nil, qualifyBERError(tagErr_enc_interrogationtype, "interrogationType", "encoding", false)
	}
	enc_interrogationtype = retagged_enc_interrogationtype
	children = append(children, enc_interrogationtype...)
	if v.OrInterrogation != nil {
		enc_orinterrogation := ber.EncodeNull()
		retagged_enc_orinterrogation, tagErr_enc_orinterrogation := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, enc_orinterrogation)
		if tagErr_enc_orinterrogation != nil {
			return nil, qualifyBERError(tagErr_enc_orinterrogation, "or-Interrogation", "encoding", false)
		}
		enc_orinterrogation = retagged_enc_orinterrogation
		children = append(children, enc_orinterrogation...)
	}
	if v.OrCapability != nil {
		if !(int64(*v.OrCapability) >= 1 && int64(*v.OrCapability) <= 127) {
			if constraintErr := checkEncodedValue(opts, s47bb6e_1, "51.4", "or-Capability", "(1..127)", ber.ObserveInteger(int64(*v.OrCapability))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_orcapability := ber.EncodeInteger(int64(*v.OrCapability))
		retagged_enc_orcapability, tagErr_enc_orcapability := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 5, enc_orcapability)
		if tagErr_enc_orcapability != nil {
			return nil, qualifyBERError(tagErr_enc_orcapability, "or-Capability", "encoding", false)
		}
		enc_orcapability = retagged_enc_orcapability
		children = append(children, enc_orcapability...)
	}
	if len(v.GmscOrGsmSCFAddress) < 1 || len(v.GmscOrGsmSCFAddress) > 9 {
		if constraintErr := checkEncodedLength(opts, s47bb6e_1, "51.5", "gmsc-OrGsmSCF-Address", "SIZE (1..9)", len(v.GmscOrGsmSCFAddress)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	if len(v.GmscOrGsmSCFAddress) < 1 || len(v.GmscOrGsmSCFAddress) > 20 {
		if constraintErr := checkEncodedLength(opts, s47bb6e_1, "51.5", "gmsc-OrGsmSCF-Address", "SIZE (1..20)", len(v.GmscOrGsmSCFAddress)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_gmscorgsmscfaddress, encodeErr_enc_gmscorgsmscfaddress := ber.EncodeOctetString([]byte(v.GmscOrGsmSCFAddress))
	if encodeErr_enc_gmscorgsmscfaddress != nil {
		return nil, qualifyBERError(encodeErr_enc_gmscorgsmscfaddress, "gmsc-OrGsmSCF-Address", "encoding", false)
	}
	retagged_enc_gmscorgsmscfaddress, tagErr_enc_gmscorgsmscfaddress := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 6, enc_gmscorgsmscfaddress)
	if tagErr_enc_gmscorgsmscfaddress != nil {
		return nil, qualifyBERError(tagErr_enc_gmscorgsmscfaddress, "gmsc-OrGsmSCF-Address", "encoding", false)
	}
	enc_gmscorgsmscfaddress = retagged_enc_gmscorgsmscfaddress
	children = append(children, enc_gmscorgsmscfaddress...)
	if v.CallReferenceNumber != nil {
		if len(*v.CallReferenceNumber) < 1 || len(*v.CallReferenceNumber) > 8 {
			if constraintErr := checkEncodedLength(opts, s47bb6e_1, "51.5", "callReferenceNumber", "SIZE (1..8)", len(*v.CallReferenceNumber)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_callreferencenumber, encodeErr_enc_callreferencenumber := ber.EncodeOctetString([]byte(*v.CallReferenceNumber))
		if encodeErr_enc_callreferencenumber != nil {
			return nil, qualifyBERError(encodeErr_enc_callreferencenumber, "callReferenceNumber", "encoding", false)
		}
		retagged_enc_callreferencenumber, tagErr_enc_callreferencenumber := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 7, enc_callreferencenumber)
		if tagErr_enc_callreferencenumber != nil {
			return nil, qualifyBERError(tagErr_enc_callreferencenumber, "callReferenceNumber", "encoding", false)
		}
		enc_callreferencenumber = retagged_enc_callreferencenumber
		children = append(children, enc_callreferencenumber...)
	}
	if v.ForwardingReason != nil {
		if int64(*v.ForwardingReason) != 0 && int64(*v.ForwardingReason) != 1 && int64(*v.ForwardingReason) != 2 {
			if constraintErr := checkEncodedValue(opts, s47bb6e_1, "20", "forwardingReason", "ENUMERATED {0, 1, 2}", ber.ObserveInteger(int64(*v.ForwardingReason))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_forwardingreason := ber.EncodeEnumerated(int64(*v.ForwardingReason))
		retagged_enc_forwardingreason, tagErr_enc_forwardingreason := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 8, enc_forwardingreason)
		if tagErr_enc_forwardingreason != nil {
			return nil, qualifyBERError(tagErr_enc_forwardingreason, "forwardingReason", "encoding", false)
		}
		enc_forwardingreason = retagged_enc_forwardingreason
		children = append(children, enc_forwardingreason...)
	}
	if v.BasicServiceGroup != nil {
		enc_basicservicegroup, err := v.BasicServiceGroup.MarshalBER(ber.ChildEncodeOptions(opts, "basicServiceGroup")...)
		if err != nil {
			return nil, qualifyBERError(err, "basicServiceGroup", "encoding", false)
		}
		{
			var encodeErr error
			enc_basicservicegroup, encodeErr = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 9, enc_basicservicegroup)
			if encodeErr != nil {
				return nil, qualifyBERError(encodeErr, "basicServiceGroup", "encoding", false)
			}
		}
		ber.RecordGeneratedBERChildPlacement(opts, len(children), enc_basicservicegroup)
		children = append(children, enc_basicservicegroup...)
	}
	if v.NetworkSignalInfo != nil {
		enc_networksignalinfo, err := v.NetworkSignalInfo.MarshalBER(ber.ChildEncodeOptions(opts, "networkSignalInfo")...)
		if err != nil {
			return nil, qualifyBERError(err, "networkSignalInfo", "encoding", false)
		}
		retagged_enc_networksignalinfo, tagErr_enc_networksignalinfo := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 10, enc_networksignalinfo)
		if tagErr_enc_networksignalinfo != nil {
			return nil, qualifyBERError(tagErr_enc_networksignalinfo, "networkSignalInfo", "encoding", false)
		}
		enc_networksignalinfo = retagged_enc_networksignalinfo
		ber.RecordGeneratedBERChildPlacement(opts, len(children), enc_networksignalinfo)
		children = append(children, enc_networksignalinfo...)
	}
	if v.CamelInfo != nil {
		enc_camelinfo, err := v.CamelInfo.MarshalBER(ber.ChildEncodeOptions(opts, "camelInfo")...)
		if err != nil {
			return nil, qualifyBERError(err, "camelInfo", "encoding", false)
		}
		retagged_enc_camelinfo, tagErr_enc_camelinfo := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 11, enc_camelinfo)
		if tagErr_enc_camelinfo != nil {
			return nil, qualifyBERError(tagErr_enc_camelinfo, "camelInfo", "encoding", false)
		}
		enc_camelinfo = retagged_enc_camelinfo
		ber.RecordGeneratedBERChildPlacement(opts, len(children), enc_camelinfo)
		children = append(children, enc_camelinfo...)
	}
	if v.SuppressionOfAnnouncement != nil {
		enc_suppressionofannouncement := ber.EncodeNull()
		retagged_enc_suppressionofannouncement, tagErr_enc_suppressionofannouncement := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 12, enc_suppressionofannouncement)
		if tagErr_enc_suppressionofannouncement != nil {
			return nil, qualifyBERError(tagErr_enc_suppressionofannouncement, "suppressionOfAnnouncement", "encoding", false)
		}
		enc_suppressionofannouncement = retagged_enc_suppressionofannouncement
		children = append(children, enc_suppressionofannouncement...)
	}
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalBER(ber.ChildEncodeOptions(opts, "extensionContainer")...)
		if err != nil {
			return nil, qualifyBERError(err, "extensionContainer", "encoding", false)
		}
		retagged_enc_extensioncontainer, tagErr_enc_extensioncontainer := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 13, enc_extensioncontainer)
		if tagErr_enc_extensioncontainer != nil {
			return nil, qualifyBERError(tagErr_enc_extensioncontainer, "extensionContainer", "encoding", false)
		}
		enc_extensioncontainer = retagged_enc_extensioncontainer
		ber.RecordGeneratedBERChildPlacement(opts, len(children), enc_extensioncontainer)
		children = append(children, enc_extensioncontainer...)
	}
	if v.AlertingPattern != nil {
		if len(*v.AlertingPattern) < 1 || len(*v.AlertingPattern) > 1 {
			if constraintErr := checkEncodedLength(opts, s47bb6e_1, "51.5", "alertingPattern", "SIZE (1)", len(*v.AlertingPattern)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_alertingpattern, encodeErr_enc_alertingpattern := ber.EncodeOctetString([]byte(*v.AlertingPattern))
		if encodeErr_enc_alertingpattern != nil {
			return nil, qualifyBERError(encodeErr_enc_alertingpattern, "alertingPattern", "encoding", false)
		}
		retagged_enc_alertingpattern, tagErr_enc_alertingpattern := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 14, enc_alertingpattern)
		if tagErr_enc_alertingpattern != nil {
			return nil, qualifyBERError(tagErr_enc_alertingpattern, "alertingPattern", "encoding", false)
		}
		enc_alertingpattern = retagged_enc_alertingpattern
		children = append(children, enc_alertingpattern...)
	}
	if v.CcbsCall != nil {
		enc_ccbscall := ber.EncodeNull()
		retagged_enc_ccbscall, tagErr_enc_ccbscall := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 15, enc_ccbscall)
		if tagErr_enc_ccbscall != nil {
			return nil, qualifyBERError(tagErr_enc_ccbscall, "ccbs-Call", "encoding", false)
		}
		enc_ccbscall = retagged_enc_ccbscall
		children = append(children, enc_ccbscall...)
	}
	if v.SupportedCCBSPhase != nil {
		if !(int64(*v.SupportedCCBSPhase) >= 1 && int64(*v.SupportedCCBSPhase) <= 127) {
			if constraintErr := checkEncodedValue(opts, s47bb6e_1, "51.4", "supportedCCBS-Phase", "(1..127)", ber.ObserveInteger(int64(*v.SupportedCCBSPhase))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_supportedccbsphase := ber.EncodeInteger(int64(*v.SupportedCCBSPhase))
		retagged_enc_supportedccbsphase, tagErr_enc_supportedccbsphase := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 16, enc_supportedccbsphase)
		if tagErr_enc_supportedccbsphase != nil {
			return nil, qualifyBERError(tagErr_enc_supportedccbsphase, "supportedCCBS-Phase", "encoding", false)
		}
		enc_supportedccbsphase = retagged_enc_supportedccbsphase
		children = append(children, enc_supportedccbsphase...)
	}
	if v.AdditionalSignalInfo != nil {
		enc_additionalsignalinfo, err := v.AdditionalSignalInfo.MarshalBER(ber.ChildEncodeOptions(opts, "additionalSignalInfo")...)
		if err != nil {
			return nil, qualifyBERError(err, "additionalSignalInfo", "encoding", false)
		}
		retagged_enc_additionalsignalinfo, tagErr_enc_additionalsignalinfo := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 17, enc_additionalsignalinfo)
		if tagErr_enc_additionalsignalinfo != nil {
			return nil, qualifyBERError(tagErr_enc_additionalsignalinfo, "additionalSignalInfo", "encoding", false)
		}
		enc_additionalsignalinfo = retagged_enc_additionalsignalinfo
		ber.RecordGeneratedBERChildPlacement(opts, len(children), enc_additionalsignalinfo)
		children = append(children, enc_additionalsignalinfo...)
	}
	if v.IstSupportIndicator != nil {
		enc_istsupportindicator := ber.EncodeEnumerated(int64(*v.IstSupportIndicator))
		retagged_enc_istsupportindicator, tagErr_enc_istsupportindicator := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 18, enc_istsupportindicator)
		if tagErr_enc_istsupportindicator != nil {
			return nil, qualifyBERError(tagErr_enc_istsupportindicator, "istSupportIndicator", "encoding", false)
		}
		enc_istsupportindicator = retagged_enc_istsupportindicator
		children = append(children, enc_istsupportindicator...)
	}
	if v.PrePagingSupported != nil {
		enc_prepagingsupported := ber.EncodeNull()
		retagged_enc_prepagingsupported, tagErr_enc_prepagingsupported := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 19, enc_prepagingsupported)
		if tagErr_enc_prepagingsupported != nil {
			return nil, qualifyBERError(tagErr_enc_prepagingsupported, "pre-pagingSupported", "encoding", false)
		}
		enc_prepagingsupported = retagged_enc_prepagingsupported
		children = append(children, enc_prepagingsupported...)
	}
	if v.CallDiversionTreatmentIndicator != nil {
		if len(*v.CallDiversionTreatmentIndicator) < 1 || len(*v.CallDiversionTreatmentIndicator) > 1 {
			if constraintErr := checkEncodedLength(opts, s47bb6e_1, "51.5", "callDiversionTreatmentIndicator", "SIZE (1)", len(*v.CallDiversionTreatmentIndicator)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_calldiversiontreatmentindicator, encodeErr_enc_calldiversiontreatmentindicator := ber.EncodeOctetString([]byte(*v.CallDiversionTreatmentIndicator))
		if encodeErr_enc_calldiversiontreatmentindicator != nil {
			return nil, qualifyBERError(encodeErr_enc_calldiversiontreatmentindicator, "callDiversionTreatmentIndicator", "encoding", false)
		}
		retagged_enc_calldiversiontreatmentindicator, tagErr_enc_calldiversiontreatmentindicator := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 20, enc_calldiversiontreatmentindicator)
		if tagErr_enc_calldiversiontreatmentindicator != nil {
			return nil, qualifyBERError(tagErr_enc_calldiversiontreatmentindicator, "callDiversionTreatmentIndicator", "encoding", false)
		}
		enc_calldiversiontreatmentindicator = retagged_enc_calldiversiontreatmentindicator
		children = append(children, enc_calldiversiontreatmentindicator...)
	}
	if v.LongFTNSupported != nil {
		enc_longftnsupported := ber.EncodeNull()
		retagged_enc_longftnsupported, tagErr_enc_longftnsupported := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 21, enc_longftnsupported)
		if tagErr_enc_longftnsupported != nil {
			return nil, qualifyBERError(tagErr_enc_longftnsupported, "longFTN-Supported", "encoding", false)
		}
		enc_longftnsupported = retagged_enc_longftnsupported
		children = append(children, enc_longftnsupported...)
	}
	if v.SuppressVTCSI != nil {
		enc_suppressvtcsi := ber.EncodeNull()
		retagged_enc_suppressvtcsi, tagErr_enc_suppressvtcsi := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 22, enc_suppressvtcsi)
		if tagErr_enc_suppressvtcsi != nil {
			return nil, qualifyBERError(tagErr_enc_suppressvtcsi, "suppress-VT-CSI", "encoding", false)
		}
		enc_suppressvtcsi = retagged_enc_suppressvtcsi
		children = append(children, enc_suppressvtcsi...)
	}
	if v.SuppressIncomingCallBarring != nil {
		enc_suppressincomingcallbarring := ber.EncodeNull()
		retagged_enc_suppressincomingcallbarring, tagErr_enc_suppressincomingcallbarring := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 23, enc_suppressincomingcallbarring)
		if tagErr_enc_suppressincomingcallbarring != nil {
			return nil, qualifyBERError(tagErr_enc_suppressincomingcallbarring, "suppressIncomingCallBarring", "encoding", false)
		}
		enc_suppressincomingcallbarring = retagged_enc_suppressincomingcallbarring
		children = append(children, enc_suppressincomingcallbarring...)
	}
	if v.GsmSCFInitiatedCall != nil {
		enc_gsmscfinitiatedcall := ber.EncodeNull()
		retagged_enc_gsmscfinitiatedcall, tagErr_enc_gsmscfinitiatedcall := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 24, enc_gsmscfinitiatedcall)
		if tagErr_enc_gsmscfinitiatedcall != nil {
			return nil, qualifyBERError(tagErr_enc_gsmscfinitiatedcall, "gsmSCF-InitiatedCall", "encoding", false)
		}
		enc_gsmscfinitiatedcall = retagged_enc_gsmscfinitiatedcall
		children = append(children, enc_gsmscfinitiatedcall...)
	}
	if v.BasicServiceGroup2 != nil {
		enc_basicservicegroup2, err := v.BasicServiceGroup2.MarshalBER(ber.ChildEncodeOptions(opts, "basicServiceGroup2")...)
		if err != nil {
			return nil, qualifyBERError(err, "basicServiceGroup2", "encoding", false)
		}
		{
			var encodeErr error
			enc_basicservicegroup2, encodeErr = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 25, enc_basicservicegroup2)
			if encodeErr != nil {
				return nil, qualifyBERError(encodeErr, "basicServiceGroup2", "encoding", false)
			}
		}
		ber.RecordGeneratedBERChildPlacement(opts, len(children), enc_basicservicegroup2)
		children = append(children, enc_basicservicegroup2...)
	}
	if v.NetworkSignalInfo2 != nil {
		enc_networksignalinfo2, err := v.NetworkSignalInfo2.MarshalBER(ber.ChildEncodeOptions(opts, "networkSignalInfo2")...)
		if err != nil {
			return nil, qualifyBERError(err, "networkSignalInfo2", "encoding", false)
		}
		retagged_enc_networksignalinfo2, tagErr_enc_networksignalinfo2 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 26, enc_networksignalinfo2)
		if tagErr_enc_networksignalinfo2 != nil {
			return nil, qualifyBERError(tagErr_enc_networksignalinfo2, "networkSignalInfo2", "encoding", false)
		}
		enc_networksignalinfo2 = retagged_enc_networksignalinfo2
		ber.RecordGeneratedBERChildPlacement(opts, len(children), enc_networksignalinfo2)
		children = append(children, enc_networksignalinfo2...)
	}
	if v.SuppressMTSS != nil {
		namedBits_SuppressMTSS, namedBitErr_ := normalizeNamedBits(*v.SuppressMTSS, []ber.NamedBitSizeSet{{{Min: 2, Max: 16}}}, opts, "suppressMTSS", s47bb6e_1)
		if namedBitErr_ != nil {
			return nil, namedBitErr_
		}
		if bitStringErr := ber.ValidateBitStringLength(namedBits_SuppressMTSS.Bytes, namedBits_SuppressMTSS.BitLength); bitStringErr != nil {
			return nil, qualifyBERError(bitStringErr, "suppressMTSS", "encoding", false)
		}
		// arithmetic pattern BER_BITSTRING_FIELD: 0 <= bit length before modulo and subtraction; gen/codegen.go:750
		if namedBits_SuppressMTSS.BitLength < 0 {
			return nil, fmt.Errorf("negative bit string length")
		}
		if (namedBits_SuppressMTSS).BitLength < 2 || (namedBits_SuppressMTSS).BitLength > 16 {
			if constraintErr := checkEncodedLength(opts, s47bb6e_1, "51.5", "suppressMTSS", "SIZE (2..16)", namedBitObservedLength(namedBits_SuppressMTSS)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_suppressmtss, encodeErr_enc_suppressmtss := ber.EncodeBitString(namedBits_SuppressMTSS.Bytes, ber.UnusedBitCount(namedBits_SuppressMTSS.BitLength))
		if encodeErr_enc_suppressmtss != nil {
			return nil, qualifyBERError(encodeErr_enc_suppressmtss, "suppressMTSS", "encoding", false)
		}
		retagged_enc_suppressmtss, tagErr_enc_suppressmtss := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 27, enc_suppressmtss)
		if tagErr_enc_suppressmtss != nil {
			return nil, qualifyBERError(tagErr_enc_suppressmtss, "suppressMTSS", "encoding", false)
		}
		enc_suppressmtss = retagged_enc_suppressmtss
		children = append(children, enc_suppressmtss...)
	}
	if v.MtRoamingRetrySupported != nil {
		enc_mtroamingretrysupported := ber.EncodeNull()
		retagged_enc_mtroamingretrysupported, tagErr_enc_mtroamingretrysupported := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 28, enc_mtroamingretrysupported)
		if tagErr_enc_mtroamingretrysupported != nil {
			return nil, qualifyBERError(tagErr_enc_mtroamingretrysupported, "mtRoamingRetrySupported", "encoding", false)
		}
		enc_mtroamingretrysupported = retagged_enc_mtroamingretrysupported
		children = append(children, enc_mtroamingretrysupported...)
	}
	if v.CallPriority != nil {
		if !(int64(*v.CallPriority) >= 0 && int64(*v.CallPriority) <= 15) {
			if constraintErr := checkEncodedValue(opts, s47bb6e_1, "51.4", "callPriority", "(0..15)", ber.ObserveInteger(int64(*v.CallPriority))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_callpriority := ber.EncodeInteger(int64(*v.CallPriority))
		retagged_enc_callpriority, tagErr_enc_callpriority := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 29, enc_callpriority)
		if tagErr_enc_callpriority != nil {
			return nil, qualifyBERError(tagErr_enc_callpriority, "callPriority", "encoding", false)
		}
		enc_callpriority = retagged_enc_callpriority
		children = append(children, enc_callpriority...)
	}
	base_ := -1
	for i, ext := range v.ExtData_ {
		if err := checkOpaqueAddition(ext, opts, s47bb6e_1, children, i, &base_); err != nil {
			return nil, opaqueExtensionError(err, i)
		}
		peekTag, n, _, extErr := ber.DecodeEncodedTLV(ext)
		if extErr != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, extErr)
		}
		if n != len(ext) {
			return nil, fmt.Errorf("encoding extension %d: %w", i, ber.ErrExtraData)
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: only the first addition is restricted.
		if i == 0 && ((peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 29) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 28) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 27) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 26) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 25) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 24) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 23) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 22) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 21) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 20) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 19) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 18) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 17) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 16) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 15) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 14) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 13) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 12) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 11) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 10) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 9) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 8) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 7)) {
			if constraintErr := ber.CheckEncodedValue(ber.EncodeRule(opts, s47bb6e_1, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
				return nil, constraintErr
			}
		}
		children = append(children, ext...)
	}
	ber.RecordGeneratedBERContainer(opts, children)
	return ber.EncodeSequence(children)
}
func (v *SendRoutingInfoArg) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// MarshalDER encodes SendRoutingInfoArg to DER format.
// Opaque descendants pass generic DER checks; foreign schema rules need a typed binding.
func (v *SendRoutingInfoArg) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: SendRoutingInfoArg receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if len(v.Msisdn) < 1 || len(v.Msisdn) > 9 {
		if constraintErr := checkEncodedLength(nil, s47bb6e_1, "51.5", "msisdn", "SIZE (1..9)", len(v.Msisdn)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	if len(v.Msisdn) < 1 || len(v.Msisdn) > 20 {
		if constraintErr := checkEncodedLength(nil, s47bb6e_1, "51.5", "msisdn", "SIZE (1..20)", len(v.Msisdn)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_msisdn, encodeErr_enc_msisdn := ber.EncodeOctetString([]byte(v.Msisdn))
	if encodeErr_enc_msisdn != nil {
		return nil, qualifyBERError(encodeErr_enc_msisdn, "msisdn", "encoding", true)
	}
	retagged_enc_msisdn, tagErr_enc_msisdn := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_msisdn)
	if tagErr_enc_msisdn != nil {
		return nil, qualifyBERError(tagErr_enc_msisdn, "msisdn", "encoding", true)
	}
	enc_msisdn = retagged_enc_msisdn
	children = append(children, enc_msisdn...)
	if v.CugCheckInfo != nil {
		enc_cugcheckinfo, err := v.CugCheckInfo.MarshalDER()
		if err != nil {
			return nil, qualifyBERError(err, "cug-CheckInfo", "encoding", true)
		}
		retagged_enc_cugcheckinfo, tagErr_enc_cugcheckinfo := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_cugcheckinfo)
		if tagErr_enc_cugcheckinfo != nil {
			return nil, qualifyBERError(tagErr_enc_cugcheckinfo, "cug-CheckInfo", "encoding", true)
		}
		enc_cugcheckinfo = retagged_enc_cugcheckinfo
		children = append(children, enc_cugcheckinfo...)
	}
	if v.NumberOfForwarding != nil {
		if !(int64(*v.NumberOfForwarding) >= 1 && int64(*v.NumberOfForwarding) <= 5) {
			if constraintErr := checkEncodedValue(nil, s47bb6e_1, "51.4", "numberOfForwarding", "(1..5)", ber.ObserveInteger(int64(*v.NumberOfForwarding))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_numberofforwarding := ber.EncodeInteger(int64(*v.NumberOfForwarding))
		retagged_enc_numberofforwarding, tagErr_enc_numberofforwarding := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_numberofforwarding)
		if tagErr_enc_numberofforwarding != nil {
			return nil, qualifyBERError(tagErr_enc_numberofforwarding, "numberOfForwarding", "encoding", true)
		}
		enc_numberofforwarding = retagged_enc_numberofforwarding
		children = append(children, enc_numberofforwarding...)
	}
	if int64(v.InterrogationType) != 0 && int64(v.InterrogationType) != 1 {
		if constraintErr := checkEncodedValue(nil, s47bb6e_1, "20", "interrogationType", "ENUMERATED {0, 1}", ber.ObserveInteger(int64(v.InterrogationType))); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_interrogationtype := ber.EncodeEnumerated(int64(v.InterrogationType))
	retagged_enc_interrogationtype, tagErr_enc_interrogationtype := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, enc_interrogationtype)
	if tagErr_enc_interrogationtype != nil {
		return nil, qualifyBERError(tagErr_enc_interrogationtype, "interrogationType", "encoding", true)
	}
	enc_interrogationtype = retagged_enc_interrogationtype
	children = append(children, enc_interrogationtype...)
	if v.OrInterrogation != nil {
		enc_orinterrogation := ber.EncodeNull()
		retagged_enc_orinterrogation, tagErr_enc_orinterrogation := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, enc_orinterrogation)
		if tagErr_enc_orinterrogation != nil {
			return nil, qualifyBERError(tagErr_enc_orinterrogation, "or-Interrogation", "encoding", true)
		}
		enc_orinterrogation = retagged_enc_orinterrogation
		children = append(children, enc_orinterrogation...)
	}
	if v.OrCapability != nil {
		if !(int64(*v.OrCapability) >= 1 && int64(*v.OrCapability) <= 127) {
			if constraintErr := checkEncodedValue(nil, s47bb6e_1, "51.4", "or-Capability", "(1..127)", ber.ObserveInteger(int64(*v.OrCapability))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_orcapability := ber.EncodeInteger(int64(*v.OrCapability))
		retagged_enc_orcapability, tagErr_enc_orcapability := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 5, enc_orcapability)
		if tagErr_enc_orcapability != nil {
			return nil, qualifyBERError(tagErr_enc_orcapability, "or-Capability", "encoding", true)
		}
		enc_orcapability = retagged_enc_orcapability
		children = append(children, enc_orcapability...)
	}
	if len(v.GmscOrGsmSCFAddress) < 1 || len(v.GmscOrGsmSCFAddress) > 9 {
		if constraintErr := checkEncodedLength(nil, s47bb6e_1, "51.5", "gmsc-OrGsmSCF-Address", "SIZE (1..9)", len(v.GmscOrGsmSCFAddress)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	if len(v.GmscOrGsmSCFAddress) < 1 || len(v.GmscOrGsmSCFAddress) > 20 {
		if constraintErr := checkEncodedLength(nil, s47bb6e_1, "51.5", "gmsc-OrGsmSCF-Address", "SIZE (1..20)", len(v.GmscOrGsmSCFAddress)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_gmscorgsmscfaddress, encodeErr_enc_gmscorgsmscfaddress := ber.EncodeOctetString([]byte(v.GmscOrGsmSCFAddress))
	if encodeErr_enc_gmscorgsmscfaddress != nil {
		return nil, qualifyBERError(encodeErr_enc_gmscorgsmscfaddress, "gmsc-OrGsmSCF-Address", "encoding", true)
	}
	retagged_enc_gmscorgsmscfaddress, tagErr_enc_gmscorgsmscfaddress := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 6, enc_gmscorgsmscfaddress)
	if tagErr_enc_gmscorgsmscfaddress != nil {
		return nil, qualifyBERError(tagErr_enc_gmscorgsmscfaddress, "gmsc-OrGsmSCF-Address", "encoding", true)
	}
	enc_gmscorgsmscfaddress = retagged_enc_gmscorgsmscfaddress
	children = append(children, enc_gmscorgsmscfaddress...)
	if v.CallReferenceNumber != nil {
		if len(*v.CallReferenceNumber) < 1 || len(*v.CallReferenceNumber) > 8 {
			if constraintErr := checkEncodedLength(nil, s47bb6e_1, "51.5", "callReferenceNumber", "SIZE (1..8)", len(*v.CallReferenceNumber)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_callreferencenumber, encodeErr_enc_callreferencenumber := ber.EncodeOctetString([]byte(*v.CallReferenceNumber))
		if encodeErr_enc_callreferencenumber != nil {
			return nil, qualifyBERError(encodeErr_enc_callreferencenumber, "callReferenceNumber", "encoding", true)
		}
		retagged_enc_callreferencenumber, tagErr_enc_callreferencenumber := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 7, enc_callreferencenumber)
		if tagErr_enc_callreferencenumber != nil {
			return nil, qualifyBERError(tagErr_enc_callreferencenumber, "callReferenceNumber", "encoding", true)
		}
		enc_callreferencenumber = retagged_enc_callreferencenumber
		children = append(children, enc_callreferencenumber...)
	}
	if v.ForwardingReason != nil {
		if int64(*v.ForwardingReason) != 0 && int64(*v.ForwardingReason) != 1 && int64(*v.ForwardingReason) != 2 {
			if constraintErr := checkEncodedValue(nil, s47bb6e_1, "20", "forwardingReason", "ENUMERATED {0, 1, 2}", ber.ObserveInteger(int64(*v.ForwardingReason))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_forwardingreason := ber.EncodeEnumerated(int64(*v.ForwardingReason))
		retagged_enc_forwardingreason, tagErr_enc_forwardingreason := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 8, enc_forwardingreason)
		if tagErr_enc_forwardingreason != nil {
			return nil, qualifyBERError(tagErr_enc_forwardingreason, "forwardingReason", "encoding", true)
		}
		enc_forwardingreason = retagged_enc_forwardingreason
		children = append(children, enc_forwardingreason...)
	}
	if v.BasicServiceGroup != nil {
		enc_basicservicegroup, err := v.BasicServiceGroup.MarshalDER()
		if err != nil {
			return nil, qualifyBERError(err, "basicServiceGroup", "encoding", true)
		}
		{
			var encodeErr error
			enc_basicservicegroup, encodeErr = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 9, enc_basicservicegroup)
			if encodeErr != nil {
				return nil, qualifyBERError(encodeErr, "basicServiceGroup", "encoding", true)
			}
		}
		children = append(children, enc_basicservicegroup...)
	}
	if v.NetworkSignalInfo != nil {
		enc_networksignalinfo, err := v.NetworkSignalInfo.MarshalDER()
		if err != nil {
			return nil, qualifyBERError(err, "networkSignalInfo", "encoding", true)
		}
		retagged_enc_networksignalinfo, tagErr_enc_networksignalinfo := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 10, enc_networksignalinfo)
		if tagErr_enc_networksignalinfo != nil {
			return nil, qualifyBERError(tagErr_enc_networksignalinfo, "networkSignalInfo", "encoding", true)
		}
		enc_networksignalinfo = retagged_enc_networksignalinfo
		children = append(children, enc_networksignalinfo...)
	}
	if v.CamelInfo != nil {
		enc_camelinfo, err := v.CamelInfo.MarshalDER()
		if err != nil {
			return nil, qualifyBERError(err, "camelInfo", "encoding", true)
		}
		retagged_enc_camelinfo, tagErr_enc_camelinfo := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 11, enc_camelinfo)
		if tagErr_enc_camelinfo != nil {
			return nil, qualifyBERError(tagErr_enc_camelinfo, "camelInfo", "encoding", true)
		}
		enc_camelinfo = retagged_enc_camelinfo
		children = append(children, enc_camelinfo...)
	}
	if v.SuppressionOfAnnouncement != nil {
		enc_suppressionofannouncement := ber.EncodeNull()
		retagged_enc_suppressionofannouncement, tagErr_enc_suppressionofannouncement := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 12, enc_suppressionofannouncement)
		if tagErr_enc_suppressionofannouncement != nil {
			return nil, qualifyBERError(tagErr_enc_suppressionofannouncement, "suppressionOfAnnouncement", "encoding", true)
		}
		enc_suppressionofannouncement = retagged_enc_suppressionofannouncement
		children = append(children, enc_suppressionofannouncement...)
	}
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalDER()
		if err != nil {
			return nil, qualifyBERError(err, "extensionContainer", "encoding", true)
		}
		retagged_enc_extensioncontainer, tagErr_enc_extensioncontainer := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 13, enc_extensioncontainer)
		if tagErr_enc_extensioncontainer != nil {
			return nil, qualifyBERError(tagErr_enc_extensioncontainer, "extensionContainer", "encoding", true)
		}
		enc_extensioncontainer = retagged_enc_extensioncontainer
		children = append(children, enc_extensioncontainer...)
	}
	if v.AlertingPattern != nil {
		if len(*v.AlertingPattern) < 1 || len(*v.AlertingPattern) > 1 {
			if constraintErr := checkEncodedLength(nil, s47bb6e_1, "51.5", "alertingPattern", "SIZE (1)", len(*v.AlertingPattern)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_alertingpattern, encodeErr_enc_alertingpattern := ber.EncodeOctetString([]byte(*v.AlertingPattern))
		if encodeErr_enc_alertingpattern != nil {
			return nil, qualifyBERError(encodeErr_enc_alertingpattern, "alertingPattern", "encoding", true)
		}
		retagged_enc_alertingpattern, tagErr_enc_alertingpattern := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 14, enc_alertingpattern)
		if tagErr_enc_alertingpattern != nil {
			return nil, qualifyBERError(tagErr_enc_alertingpattern, "alertingPattern", "encoding", true)
		}
		enc_alertingpattern = retagged_enc_alertingpattern
		children = append(children, enc_alertingpattern...)
	}
	if v.CcbsCall != nil {
		enc_ccbscall := ber.EncodeNull()
		retagged_enc_ccbscall, tagErr_enc_ccbscall := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 15, enc_ccbscall)
		if tagErr_enc_ccbscall != nil {
			return nil, qualifyBERError(tagErr_enc_ccbscall, "ccbs-Call", "encoding", true)
		}
		enc_ccbscall = retagged_enc_ccbscall
		children = append(children, enc_ccbscall...)
	}
	if v.SupportedCCBSPhase != nil {
		if !(int64(*v.SupportedCCBSPhase) >= 1 && int64(*v.SupportedCCBSPhase) <= 127) {
			if constraintErr := checkEncodedValue(nil, s47bb6e_1, "51.4", "supportedCCBS-Phase", "(1..127)", ber.ObserveInteger(int64(*v.SupportedCCBSPhase))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_supportedccbsphase := ber.EncodeInteger(int64(*v.SupportedCCBSPhase))
		retagged_enc_supportedccbsphase, tagErr_enc_supportedccbsphase := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 16, enc_supportedccbsphase)
		if tagErr_enc_supportedccbsphase != nil {
			return nil, qualifyBERError(tagErr_enc_supportedccbsphase, "supportedCCBS-Phase", "encoding", true)
		}
		enc_supportedccbsphase = retagged_enc_supportedccbsphase
		children = append(children, enc_supportedccbsphase...)
	}
	if v.AdditionalSignalInfo != nil {
		enc_additionalsignalinfo, err := v.AdditionalSignalInfo.MarshalDER()
		if err != nil {
			return nil, qualifyBERError(err, "additionalSignalInfo", "encoding", true)
		}
		retagged_enc_additionalsignalinfo, tagErr_enc_additionalsignalinfo := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 17, enc_additionalsignalinfo)
		if tagErr_enc_additionalsignalinfo != nil {
			return nil, qualifyBERError(tagErr_enc_additionalsignalinfo, "additionalSignalInfo", "encoding", true)
		}
		enc_additionalsignalinfo = retagged_enc_additionalsignalinfo
		children = append(children, enc_additionalsignalinfo...)
	}
	if v.IstSupportIndicator != nil {
		enc_istsupportindicator := ber.EncodeEnumerated(int64(*v.IstSupportIndicator))
		retagged_enc_istsupportindicator, tagErr_enc_istsupportindicator := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 18, enc_istsupportindicator)
		if tagErr_enc_istsupportindicator != nil {
			return nil, qualifyBERError(tagErr_enc_istsupportindicator, "istSupportIndicator", "encoding", true)
		}
		enc_istsupportindicator = retagged_enc_istsupportindicator
		children = append(children, enc_istsupportindicator...)
	}
	if v.PrePagingSupported != nil {
		enc_prepagingsupported := ber.EncodeNull()
		retagged_enc_prepagingsupported, tagErr_enc_prepagingsupported := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 19, enc_prepagingsupported)
		if tagErr_enc_prepagingsupported != nil {
			return nil, qualifyBERError(tagErr_enc_prepagingsupported, "pre-pagingSupported", "encoding", true)
		}
		enc_prepagingsupported = retagged_enc_prepagingsupported
		children = append(children, enc_prepagingsupported...)
	}
	if v.CallDiversionTreatmentIndicator != nil {
		if len(*v.CallDiversionTreatmentIndicator) < 1 || len(*v.CallDiversionTreatmentIndicator) > 1 {
			if constraintErr := checkEncodedLength(nil, s47bb6e_1, "51.5", "callDiversionTreatmentIndicator", "SIZE (1)", len(*v.CallDiversionTreatmentIndicator)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_calldiversiontreatmentindicator, encodeErr_enc_calldiversiontreatmentindicator := ber.EncodeOctetString([]byte(*v.CallDiversionTreatmentIndicator))
		if encodeErr_enc_calldiversiontreatmentindicator != nil {
			return nil, qualifyBERError(encodeErr_enc_calldiversiontreatmentindicator, "callDiversionTreatmentIndicator", "encoding", true)
		}
		retagged_enc_calldiversiontreatmentindicator, tagErr_enc_calldiversiontreatmentindicator := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 20, enc_calldiversiontreatmentindicator)
		if tagErr_enc_calldiversiontreatmentindicator != nil {
			return nil, qualifyBERError(tagErr_enc_calldiversiontreatmentindicator, "callDiversionTreatmentIndicator", "encoding", true)
		}
		enc_calldiversiontreatmentindicator = retagged_enc_calldiversiontreatmentindicator
		children = append(children, enc_calldiversiontreatmentindicator...)
	}
	if v.LongFTNSupported != nil {
		enc_longftnsupported := ber.EncodeNull()
		retagged_enc_longftnsupported, tagErr_enc_longftnsupported := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 21, enc_longftnsupported)
		if tagErr_enc_longftnsupported != nil {
			return nil, qualifyBERError(tagErr_enc_longftnsupported, "longFTN-Supported", "encoding", true)
		}
		enc_longftnsupported = retagged_enc_longftnsupported
		children = append(children, enc_longftnsupported...)
	}
	if v.SuppressVTCSI != nil {
		enc_suppressvtcsi := ber.EncodeNull()
		retagged_enc_suppressvtcsi, tagErr_enc_suppressvtcsi := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 22, enc_suppressvtcsi)
		if tagErr_enc_suppressvtcsi != nil {
			return nil, qualifyBERError(tagErr_enc_suppressvtcsi, "suppress-VT-CSI", "encoding", true)
		}
		enc_suppressvtcsi = retagged_enc_suppressvtcsi
		children = append(children, enc_suppressvtcsi...)
	}
	if v.SuppressIncomingCallBarring != nil {
		enc_suppressincomingcallbarring := ber.EncodeNull()
		retagged_enc_suppressincomingcallbarring, tagErr_enc_suppressincomingcallbarring := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 23, enc_suppressincomingcallbarring)
		if tagErr_enc_suppressincomingcallbarring != nil {
			return nil, qualifyBERError(tagErr_enc_suppressincomingcallbarring, "suppressIncomingCallBarring", "encoding", true)
		}
		enc_suppressincomingcallbarring = retagged_enc_suppressincomingcallbarring
		children = append(children, enc_suppressincomingcallbarring...)
	}
	if v.GsmSCFInitiatedCall != nil {
		enc_gsmscfinitiatedcall := ber.EncodeNull()
		retagged_enc_gsmscfinitiatedcall, tagErr_enc_gsmscfinitiatedcall := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 24, enc_gsmscfinitiatedcall)
		if tagErr_enc_gsmscfinitiatedcall != nil {
			return nil, qualifyBERError(tagErr_enc_gsmscfinitiatedcall, "gsmSCF-InitiatedCall", "encoding", true)
		}
		enc_gsmscfinitiatedcall = retagged_enc_gsmscfinitiatedcall
		children = append(children, enc_gsmscfinitiatedcall...)
	}
	if v.BasicServiceGroup2 != nil {
		enc_basicservicegroup2, err := v.BasicServiceGroup2.MarshalDER()
		if err != nil {
			return nil, qualifyBERError(err, "basicServiceGroup2", "encoding", true)
		}
		{
			var encodeErr error
			enc_basicservicegroup2, encodeErr = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 25, enc_basicservicegroup2)
			if encodeErr != nil {
				return nil, qualifyBERError(encodeErr, "basicServiceGroup2", "encoding", true)
			}
		}
		children = append(children, enc_basicservicegroup2...)
	}
	if v.NetworkSignalInfo2 != nil {
		enc_networksignalinfo2, err := v.NetworkSignalInfo2.MarshalDER()
		if err != nil {
			return nil, qualifyBERError(err, "networkSignalInfo2", "encoding", true)
		}
		retagged_enc_networksignalinfo2, tagErr_enc_networksignalinfo2 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 26, enc_networksignalinfo2)
		if tagErr_enc_networksignalinfo2 != nil {
			return nil, qualifyBERError(tagErr_enc_networksignalinfo2, "networkSignalInfo2", "encoding", true)
		}
		enc_networksignalinfo2 = retagged_enc_networksignalinfo2
		children = append(children, enc_networksignalinfo2...)
	}
	if v.SuppressMTSS != nil {
		namedBits_SuppressMTSS, namedBitErr_ := normalizeNamedBits(*v.SuppressMTSS, []ber.NamedBitSizeSet{{{Min: 2, Max: 16}}}, nil, "suppressMTSS", s47bb6e_1)
		if namedBitErr_ != nil {
			return nil, namedBitErr_
		}
		if bitStringErr := ber.ValidateBitStringLength(namedBits_SuppressMTSS.Bytes, namedBits_SuppressMTSS.BitLength); bitStringErr != nil {
			return nil, qualifyBERError(bitStringErr, "suppressMTSS", "encoding", true)
		}
		// arithmetic pattern BER_BITSTRING_FIELD: 0 <= bit length before modulo and subtraction; gen/codegen.go:750
		if namedBits_SuppressMTSS.BitLength < 0 {
			return nil, fmt.Errorf("negative bit string length")
		}
		if (namedBits_SuppressMTSS).BitLength < 2 || (namedBits_SuppressMTSS).BitLength > 16 {
			if constraintErr := checkEncodedLength(nil, s47bb6e_1, "51.5", "suppressMTSS", "SIZE (2..16)", namedBitObservedLength(namedBits_SuppressMTSS)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_suppressmtss, encodeErr_enc_suppressmtss := ber.EncodeDERNamedBitString(namedBits_SuppressMTSS.Bytes, namedBits_SuppressMTSS.BitLength)
		if encodeErr_enc_suppressmtss != nil {
			return nil, qualifyBERError(encodeErr_enc_suppressmtss, "suppressMTSS", "encoding", true)
		}
		retagged_enc_suppressmtss, tagErr_enc_suppressmtss := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 27, enc_suppressmtss)
		if tagErr_enc_suppressmtss != nil {
			return nil, qualifyBERError(tagErr_enc_suppressmtss, "suppressMTSS", "encoding", true)
		}
		enc_suppressmtss = retagged_enc_suppressmtss
		children = append(children, enc_suppressmtss...)
	}
	if v.MtRoamingRetrySupported != nil {
		enc_mtroamingretrysupported := ber.EncodeNull()
		retagged_enc_mtroamingretrysupported, tagErr_enc_mtroamingretrysupported := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 28, enc_mtroamingretrysupported)
		if tagErr_enc_mtroamingretrysupported != nil {
			return nil, qualifyBERError(tagErr_enc_mtroamingretrysupported, "mtRoamingRetrySupported", "encoding", true)
		}
		enc_mtroamingretrysupported = retagged_enc_mtroamingretrysupported
		children = append(children, enc_mtroamingretrysupported...)
	}
	if v.CallPriority != nil {
		if !(int64(*v.CallPriority) >= 0 && int64(*v.CallPriority) <= 15) {
			if constraintErr := checkEncodedValue(nil, s47bb6e_1, "51.4", "callPriority", "(0..15)", ber.ObserveInteger(int64(*v.CallPriority))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_callpriority := ber.EncodeInteger(int64(*v.CallPriority))
		retagged_enc_callpriority, tagErr_enc_callpriority := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 29, enc_callpriority)
		if tagErr_enc_callpriority != nil {
			return nil, qualifyBERError(tagErr_enc_callpriority, "callPriority", "encoding", true)
		}
		enc_callpriority = retagged_enc_callpriority
		children = append(children, enc_callpriority...)
	}
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDEREncodedElement(ext); err != nil {
			return nil, invalidDERAddition(ext, s47bb6e_1, children, i)
		}
		peekTag, _, _, extErr := ber.DecodeEncodedTLV(ext)
		if extErr != nil {
			return nil, extErr
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: only the first addition is restricted.
		if i == 0 && ((peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 29) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 28) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 27) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 26) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 25) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 24) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 23) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 22) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 21) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 20) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 19) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 18) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 17) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 16) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 15) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 14) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 13) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 12) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 11) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 10) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 9) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 8) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 7)) {
			if constraintErr := ber.CheckEncodedValue(ber.EncodeRule(nil, s47bb6e_1, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
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
		return nil, fmt.Errorf("%s: %w", "encoding SendRoutingInfoArg as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}
func (v *SendRoutingInfoArg) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	encoded, err := v.MarshalDER()
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBER decodes SendRoutingInfoArg from BER/DER format.
func (destination *SendRoutingInfoArg) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if destination == nil {
		return fmt.Errorf("%w: SendRoutingInfoArg destination is nil", ber.ErrInvalidValue)
	}
	v := new(SendRoutingInfoArg)

	defer publishDecodedValue(destination, v, &returnErr)

	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	preparedData, preparedOptions, prepareErr := prepareCompositeBER(data, opts, s47bb6e_1, "child", (*SendRoutingInfoArg).UnmarshalBER)
	if prepareErr != nil {
		return prepareErr
	}
	data, opts = preparedData, preparedOptions

	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
	*v = SendRoutingInfoArg{}
	defer func() {
		if returnErr == nil {
			returnErr = completeValueBER(data,
				opts, v, &v.berReplayNode_, (*SendRoutingInfoArg).MarshalBER)
		}

	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("%s: %w", "decoding SendRoutingInfoArg SEQUENCE", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "SendRoutingInfoArg", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode msisdn
	if offset >= len(content) {
		return fmt.Errorf("missing required field msisdn")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 0 {
			return fmt.Errorf("expected tag [%s %d] for msisdn, got %s", "CONTEXT", 0, reqTag_)
		}
	}
	{
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
		v.Msisdn = ISDNAddressString(decVal_msisdn)
		if offset > len(content) || n_msisdn < 0 || n_msisdn > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n_msisdn
		if len(v.Msisdn) < 1 || len(v.Msisdn) > 9 {
			if constraintErr := checkDecodedLength(opts, s47bb6e_1, "51.5", "msisdn", "SIZE (1..9)", len(v.Msisdn)); constraintErr != nil {
				return constraintErr
			}
		}
		if len(v.Msisdn) < 1 || len(v.Msisdn) > 20 {
			if constraintErr := checkDecodedLength(opts, s47bb6e_1, "51.5", "msisdn", "SIZE (1..20)", len(v.Msisdn)); constraintErr != nil {
				return constraintErr
			}
		}
	}
	// Decode cug-CheckInfo
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
				ber.MarkPreflightTarget(opts, "cug-CheckInfo", content[offset:])
				decodedTag_cugcheckinfo, n_cugcheckinfo, rawVal_cugcheckinfo, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "cug-CheckInfo", "decoding", false)
				}
				if decodedTag_cugcheckinfo.Class != tag.ClassContextSpecific || decodedTag_cugcheckinfo.Number != 1 || decodedTag_cugcheckinfo.Constructed != true {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_cugcheckinfo), "cug-CheckInfo", "decoding", false)
				}
				_ = rawVal_cugcheckinfo
				if offset < 0 || offset >
					len(content) || n_cugcheckinfo < 0 || n_cugcheckinfo > len(
					content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				reconstructed_cugcheckinfo, reconstructionErr_cugcheckinfo := ber.EncodeImplicitTagWithClass(tag.ClassUniversal, tag.TagSequence, content[offset:offset+n_cugcheckinfo])
				if reconstructionErr_cugcheckinfo != nil {
					return qualifyBERError(reconstructionErr_cugcheckinfo, "cug-CheckInfo", "decoding", false)
				}
				var dec_cugcheckinfo CUGCheckInfo
				if unmErr := dec_cugcheckinfo.UnmarshalBER(reconstructed_cugcheckinfo, ber.ChildDecodeOptions(opts, "cug-CheckInfo")...); unmErr != nil {
					return qualifyBERError(unmErr, "cug-CheckInfo", "decoding", false)
				}
				v.CugCheckInfo = &dec_cugcheckinfo
				if offset < 0 || offset >
					len(content) || n_cugcheckinfo < 0 || n_cugcheckinfo > len(
					content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_cugcheckinfo
			}
		}
	}
	// Decode numberOfForwarding
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2 {
				ber.MarkPreflightTarget(opts, "numberOfForwarding", content[offset:])
				decodedTag_numberofforwarding, n_numberofforwarding, rawVal_numberofforwarding, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "numberOfForwarding", "decoding", false)
				}
				if decodedTag_numberofforwarding.Class != tag.ClassContextSpecific || decodedTag_numberofforwarding.Number != 2 || decodedTag_numberofforwarding.Constructed != false {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_numberofforwarding), "numberOfForwarding", "decoding", false)
				}
				decVal_numberofforwarding, intErr := ber.DecodeIntegerValue(rawVal_numberofforwarding)
				if intErr != nil {
					return qualifyBERError(intErr, "numberOfForwarding", "decoding", false)
				}
				tmp_numberofforwarding := NumberOfForwarding(decVal_numberofforwarding)
				v.NumberOfForwarding = &tmp_numberofforwarding
				if offset < 0 || offset >
					len(content) || n_numberofforwarding < 0 || n_numberofforwarding >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_numberofforwarding
				if !(int64(*v.NumberOfForwarding) >= 1 && int64(*v.NumberOfForwarding) <= 5) {
					if constraintErr := checkDecodedValue(opts, s47bb6e_1, "51.4", "numberOfForwarding", "(1..5)", ber.ObserveInteger(int64(*v.NumberOfForwarding))); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode interrogationType
	if offset >= len(content) {
		return fmt.Errorf("missing required field interrogationType")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 3 {
			return fmt.Errorf("expected tag [%s %d] for interrogationType, got %s", "CONTEXT", 3, reqTag_)
		}
	}
	{
		ber.MarkPreflightTarget(opts, "interrogationType", content[offset:])
		decodedTag_interrogationtype, n_interrogationtype, rawVal_interrogationtype, err := ber.DecodeTLV(content[offset:], opts...)
		if err != nil {
			return qualifyBERError(err, "interrogationType", "decoding", false)
		}
		if decodedTag_interrogationtype.Class != tag.ClassContextSpecific || decodedTag_interrogationtype.Number != 3 || decodedTag_interrogationtype.Constructed != false {
			return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_interrogationtype), "interrogationType", "decoding", false)
		}
		decVal_interrogationtype, intErr := ber.DecodeEnumeratedValue(rawVal_interrogationtype)
		if intErr != nil {
			return qualifyBERError(intErr, "interrogationType", "decoding", false)
		}
		v.InterrogationType = InterrogationType(decVal_interrogationtype)
		if offset < 0 || offset >
			len(content) || n_interrogationtype < 0 || n_interrogationtype >
			len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n_interrogationtype
		if int64(v.InterrogationType) != 0 && int64(v.InterrogationType) != 1 {
			if constraintErr := checkDecodedValue(opts, s47bb6e_1, "20", "interrogationType", "ENUMERATED {0, 1}", ber.ObserveInteger(int64(v.InterrogationType))); constraintErr != nil {
				return constraintErr
			}
		}
	}
	// Decode or-Interrogation
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4 {
				ber.MarkPreflightTarget(opts, "or-Interrogation", content[offset:])
				decodedTag_orinterrogation, n_orinterrogation, rawVal_orinterrogation, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "or-Interrogation", "decoding", false)
				}
				if decodedTag_orinterrogation.Class != tag.ClassContextSpecific || decodedTag_orinterrogation.Number != 4 || decodedTag_orinterrogation.Constructed != false {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_orinterrogation), "or-Interrogation", "decoding", false)
				}
				if len(rawVal_orinterrogation) != 0 {
					return qualifyBERError(fmt.Errorf("%w: NULL content length %d", ber.ErrInvalidValue, len(rawVal_orinterrogation)), "or-Interrogation", "decoding", false)
				}
				v.OrInterrogation = &struct{}{}
				if offset < 0 || offset >
					len(content) || n_orinterrogation < 0 || n_orinterrogation >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_orinterrogation
			}
		}
	}
	// Decode or-Capability
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 5 {
				ber.MarkPreflightTarget(opts, "or-Capability", content[offset:])
				decodedTag_orcapability, n_orcapability, rawVal_orcapability, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "or-Capability", "decoding", false)
				}
				if decodedTag_orcapability.Class != tag.ClassContextSpecific || decodedTag_orcapability.Number != 5 || decodedTag_orcapability.Constructed != false {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_orcapability), "or-Capability", "decoding", false)
				}
				decVal_orcapability, intErr := ber.DecodeIntegerValue(rawVal_orcapability)
				if intErr != nil {
					return qualifyBERError(intErr, "or-Capability", "decoding", false)
				}
				tmp_orcapability := ORPhase(decVal_orcapability)
				v.OrCapability = &tmp_orcapability
				if offset < 0 || offset >
					len(content) || n_orcapability < 0 || n_orcapability > len(
					content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_orcapability
				if !(int64(*v.OrCapability) >= 1 && int64(*v.OrCapability) <= 127) {
					if constraintErr := checkDecodedValue(opts, s47bb6e_1, "51.4", "or-Capability", "(1..127)", ber.ObserveInteger(int64(*v.OrCapability))); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode gmsc-OrGsmSCF-Address
	if offset >= len(content) {
		return fmt.Errorf("missing required field gmsc-OrGsmSCF-Address")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 6 {
			return fmt.Errorf("expected tag [%s %d] for gmsc-OrGsmSCF-Address, got %s", "CONTEXT", 6, reqTag_)
		}
	}
	{
		ber.MarkPreflightTarget(opts, "gmsc-OrGsmSCF-Address", content[offset:])
		decodedTag_gmscorgsmscfaddress, n_gmscorgsmscfaddress, rawVal_gmscorgsmscfaddress, err := ber.DecodeTLV(content[offset:], opts...)
		if err != nil {
			return qualifyBERError(err, "gmsc-OrGsmSCF-Address", "decoding", false)
		}
		if decodedTag_gmscorgsmscfaddress.Class != tag.ClassContextSpecific || decodedTag_gmscorgsmscfaddress.Number != 6 {
			return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_gmscorgsmscfaddress), "gmsc-OrGsmSCF-Address", "decoding", false)
		}
		decVal_gmscorgsmscfaddress, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_gmscorgsmscfaddress.Constructed, rawVal_gmscorgsmscfaddress, opts...)
		if octetErr != nil {
			return qualifyBERError(octetErr, "gmsc-OrGsmSCF-Address", "decoding", false)
		}
		v.GmscOrGsmSCFAddress = ISDNAddressString(decVal_gmscorgsmscfaddress)
		if offset < 0 || offset >
			len(content) || n_gmscorgsmscfaddress < 0 || n_gmscorgsmscfaddress >
			len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n_gmscorgsmscfaddress
		if len(v.GmscOrGsmSCFAddress) < 1 || len(v.GmscOrGsmSCFAddress) > 9 {
			if constraintErr := checkDecodedLength(opts, s47bb6e_1, "51.5", "gmsc-OrGsmSCF-Address", "SIZE (1..9)", len(v.GmscOrGsmSCFAddress)); constraintErr != nil {
				return constraintErr
			}
		}
		if len(v.GmscOrGsmSCFAddress) < 1 || len(v.GmscOrGsmSCFAddress) > 20 {
			if constraintErr := checkDecodedLength(opts, s47bb6e_1, "51.5", "gmsc-OrGsmSCF-Address", "SIZE (1..20)", len(v.GmscOrGsmSCFAddress)); constraintErr != nil {
				return constraintErr
			}
		}
	}
	// Decode callReferenceNumber
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 7 {
				ber.MarkPreflightTarget(opts, "callReferenceNumber", content[offset:])
				decodedTag_callreferencenumber, n_callreferencenumber, rawVal_callreferencenumber, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "callReferenceNumber", "decoding", false)
				}
				if decodedTag_callreferencenumber.Class != tag.ClassContextSpecific || decodedTag_callreferencenumber.Number != 7 {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_callreferencenumber), "callReferenceNumber", "decoding", false)
				}
				decVal_callreferencenumber, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_callreferencenumber.Constructed, rawVal_callreferencenumber, opts...)
				if octetErr != nil {
					return qualifyBERError(octetErr, "callReferenceNumber", "decoding", false)
				}
				tmp_callreferencenumber := CallReferenceNumber(decVal_callreferencenumber)
				v.CallReferenceNumber = &tmp_callreferencenumber
				if offset < 0 || offset >
					len(content) || n_callreferencenumber < 0 || n_callreferencenumber >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_callreferencenumber
				if len(*v.CallReferenceNumber) < 1 || len(*v.CallReferenceNumber) > 8 {
					if constraintErr := checkDecodedLength(opts, s47bb6e_1, "51.5", "callReferenceNumber", "SIZE (1..8)", len(*v.CallReferenceNumber)); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode forwardingReason
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 8 {
				ber.MarkPreflightTarget(opts, "forwardingReason", content[offset:])
				decodedTag_forwardingreason, n_forwardingreason, rawVal_forwardingreason, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "forwardingReason", "decoding", false)
				}
				if decodedTag_forwardingreason.Class != tag.ClassContextSpecific || decodedTag_forwardingreason.Number != 8 || decodedTag_forwardingreason.Constructed != false {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_forwardingreason), "forwardingReason", "decoding", false)
				}
				decVal_forwardingreason, intErr := ber.DecodeEnumeratedValue(rawVal_forwardingreason)
				if intErr != nil {
					return qualifyBERError(intErr, "forwardingReason", "decoding", false)
				}
				tmp_forwardingreason := ForwardingReason(decVal_forwardingreason)
				v.ForwardingReason = &tmp_forwardingreason
				if offset < 0 || offset >
					len(content) || n_forwardingreason < 0 || n_forwardingreason >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_forwardingreason
				if int64(*v.ForwardingReason) != 0 && int64(*v.ForwardingReason) != 1 && int64(*v.ForwardingReason) != 2 {
					if constraintErr := checkDecodedValue(opts, s47bb6e_1, "20", "forwardingReason", "ENUMERATED {0, 1, 2}", ber.ObserveInteger(int64(*v.ForwardingReason))); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode basicServiceGroup
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 9 {
				ber.MarkPreflightTarget(opts, "basicServiceGroup", content[offset:])
				decodedTag_basicservicegroup, n_basicservicegroup, innerData_basicservicegroup, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "basicServiceGroup", "decoding", false)
				}
				if decodedTag_basicservicegroup.Class != tag.ClassContextSpecific || decodedTag_basicservicegroup.Number != 9 || decodedTag_basicservicegroup.Constructed != true {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_basicservicegroup), "basicServiceGroup", "decoding", false)
				}
				_, innerUsed_basicservicegroup, _, innerErr_basicservicegroup := ber.DecodeTLV(innerData_basicservicegroup, opts...)
				if innerErr_basicservicegroup != nil {
					return qualifyBERError(innerErr_basicservicegroup, "basicServiceGroup", "decoding", false)
				}
				if innerUsed_basicservicegroup != len(innerData_basicservicegroup) {
					return qualifyBERError(ber.ErrExtraData, "basicServiceGroup", "decoding", false)
				}
				// Decode inner value from explicit tag wrapper
				ber.MarkPreflightTarget(opts, "basicServiceGroup", innerData_basicservicegroup)
				var dec_basicservicegroup ExtBasicServiceCode
				if unmErr := dec_basicservicegroup.UnmarshalBER(innerData_basicservicegroup, ber.ChildDecodeOptions(opts, "basicServiceGroup")...); unmErr != nil {
					return qualifyBERError(unmErr, "basicServiceGroup", "decoding", false)
				}
				v.BasicServiceGroup = &dec_basicservicegroup
				if offset < 0 || offset >
					len(content) || n_basicservicegroup < 0 || n_basicservicegroup >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_basicservicegroup
			}
		}
	}
	// Decode networkSignalInfo
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 10 {
				ber.MarkPreflightTarget(opts, "networkSignalInfo", content[offset:])
				decodedTag_networksignalinfo, n_networksignalinfo, rawVal_networksignalinfo, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "networkSignalInfo", "decoding", false)
				}
				if decodedTag_networksignalinfo.Class != tag.ClassContextSpecific || decodedTag_networksignalinfo.Number != 10 || decodedTag_networksignalinfo.Constructed != true {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_networksignalinfo), "networkSignalInfo", "decoding", false)
				}
				_ = rawVal_networksignalinfo
				if offset < 0 || offset >
					len(content) || n_networksignalinfo < 0 || n_networksignalinfo >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				reconstructed_networksignalinfo, reconstructionErr_networksignalinfo := ber.EncodeImplicitTagWithClass(tag.ClassUniversal, tag.TagSequence, content[offset:offset+n_networksignalinfo])
				if reconstructionErr_networksignalinfo != nil {
					return qualifyBERError(reconstructionErr_networksignalinfo, "networkSignalInfo", "decoding", false)
				}
				var dec_networksignalinfo ExternalSignalInfo
				if unmErr := dec_networksignalinfo.UnmarshalBER(reconstructed_networksignalinfo, ber.ChildDecodeOptions(opts, "networkSignalInfo")...); unmErr != nil {
					return qualifyBERError(unmErr, "networkSignalInfo", "decoding", false)
				}
				v.NetworkSignalInfo = &dec_networksignalinfo
				if offset < 0 || offset >
					len(content) || n_networksignalinfo < 0 || n_networksignalinfo >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_networksignalinfo
			}
		}
	}
	// Decode camelInfo
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 11 {
				ber.MarkPreflightTarget(opts, "camelInfo", content[offset:])
				decodedTag_camelinfo, n_camelinfo, rawVal_camelinfo, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "camelInfo", "decoding", false)
				}
				if decodedTag_camelinfo.Class != tag.ClassContextSpecific || decodedTag_camelinfo.Number != 11 || decodedTag_camelinfo.Constructed != true {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_camelinfo), "camelInfo", "decoding", false)
				}
				_ = rawVal_camelinfo
				if offset < 0 || offset >
					len(content) || n_camelinfo < 0 || n_camelinfo > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				reconstructed_camelinfo, reconstructionErr_camelinfo := ber.EncodeImplicitTagWithClass(tag.ClassUniversal, tag.TagSequence, content[offset:offset+n_camelinfo])
				if reconstructionErr_camelinfo != nil {
					return qualifyBERError(reconstructionErr_camelinfo, "camelInfo", "decoding", false)
				}
				var dec_camelinfo CamelInfo
				if unmErr := dec_camelinfo.UnmarshalBER(reconstructed_camelinfo, ber.ChildDecodeOptions(opts, "camelInfo")...); unmErr != nil {
					return qualifyBERError(unmErr, "camelInfo", "decoding", false)
				}
				v.CamelInfo = &dec_camelinfo
				if offset < 0 || offset >
					len(content) || n_camelinfo < 0 || n_camelinfo > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_camelinfo
			}
		}
	}
	// Decode suppressionOfAnnouncement
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 12 {
				ber.MarkPreflightTarget(opts, "suppressionOfAnnouncement", content[offset:])
				decodedTag_suppressionofannouncement, n_suppressionofannouncement, rawVal_suppressionofannouncement, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "suppressionOfAnnouncement", "decoding", false)
				}
				if decodedTag_suppressionofannouncement.Class != tag.ClassContextSpecific || decodedTag_suppressionofannouncement.Number != 12 || decodedTag_suppressionofannouncement.Constructed != false {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_suppressionofannouncement), "suppressionOfAnnouncement", "decoding", false)
				}
				if len(rawVal_suppressionofannouncement) != 0 {
					return qualifyBERError(fmt.Errorf("%w: NULL content length %d", ber.ErrInvalidValue, len(rawVal_suppressionofannouncement)), "suppressionOfAnnouncement", "decoding", false)
				}
				v.SuppressionOfAnnouncement = &struct{}{}
				if offset < 0 || offset >
					len(content) || n_suppressionofannouncement < 0 || n_suppressionofannouncement >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_suppressionofannouncement
			}
		}
	}
	// Decode extensionContainer
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 13 {
				ber.MarkPreflightTarget(opts, "extensionContainer", content[offset:])
				decodedTag_extensioncontainer, n_extensioncontainer, rawVal_extensioncontainer, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "extensionContainer", "decoding", false)
				}
				if decodedTag_extensioncontainer.Class != tag.ClassContextSpecific || decodedTag_extensioncontainer.Number != 13 || decodedTag_extensioncontainer.Constructed != true {
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
				var dec_extensioncontainer ExtensionContainer
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
	// Decode alertingPattern
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 14 {
				ber.MarkPreflightTarget(opts, "alertingPattern", content[offset:])
				decodedTag_alertingpattern, n_alertingpattern, rawVal_alertingpattern, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "alertingPattern", "decoding", false)
				}
				if decodedTag_alertingpattern.Class != tag.ClassContextSpecific || decodedTag_alertingpattern.Number != 14 {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_alertingpattern), "alertingPattern", "decoding", false)
				}
				decVal_alertingpattern, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_alertingpattern.Constructed, rawVal_alertingpattern, opts...)
				if octetErr != nil {
					return qualifyBERError(octetErr, "alertingPattern", "decoding", false)
				}
				tmp_alertingpattern := AlertingPattern(decVal_alertingpattern)
				v.AlertingPattern = &tmp_alertingpattern
				if offset < 0 || offset >
					len(content) || n_alertingpattern < 0 || n_alertingpattern >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_alertingpattern
				if len(*v.AlertingPattern) < 1 || len(*v.AlertingPattern) > 1 {
					if constraintErr := checkDecodedLength(opts, s47bb6e_1, "51.5", "alertingPattern", "SIZE (1)", len(*v.AlertingPattern)); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode ccbs-Call
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 15 {
				ber.MarkPreflightTarget(opts, "ccbs-Call", content[offset:])
				decodedTag_ccbscall, n_ccbscall, rawVal_ccbscall, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "ccbs-Call", "decoding", false)
				}
				if decodedTag_ccbscall.Class != tag.ClassContextSpecific || decodedTag_ccbscall.Number != 15 || decodedTag_ccbscall.Constructed != false {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_ccbscall), "ccbs-Call", "decoding", false)
				}
				if len(rawVal_ccbscall) != 0 {
					return qualifyBERError(fmt.Errorf("%w: NULL content length %d", ber.ErrInvalidValue, len(rawVal_ccbscall)), "ccbs-Call", "decoding", false)
				}
				v.CcbsCall = &struct{}{}
				if offset < 0 || offset >
					len(content) || n_ccbscall < 0 || n_ccbscall > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_ccbscall
			}
		}
	}
	// Decode supportedCCBS-Phase
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 16 {
				ber.MarkPreflightTarget(opts, "supportedCCBS-Phase", content[offset:])
				decodedTag_supportedccbsphase, n_supportedccbsphase, rawVal_supportedccbsphase, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "supportedCCBS-Phase", "decoding", false)
				}
				if decodedTag_supportedccbsphase.Class != tag.ClassContextSpecific || decodedTag_supportedccbsphase.Number != 16 || decodedTag_supportedccbsphase.Constructed != false {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_supportedccbsphase), "supportedCCBS-Phase", "decoding", false)
				}
				decVal_supportedccbsphase, intErr := ber.DecodeIntegerValue(rawVal_supportedccbsphase)
				if intErr != nil {
					return qualifyBERError(intErr, "supportedCCBS-Phase", "decoding", false)
				}
				tmp_supportedccbsphase := SupportedCCBSPhase(decVal_supportedccbsphase)
				v.SupportedCCBSPhase = &tmp_supportedccbsphase
				if offset < 0 || offset >
					len(content) || n_supportedccbsphase < 0 || n_supportedccbsphase >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_supportedccbsphase
				if !(int64(*v.SupportedCCBSPhase) >= 1 && int64(*v.SupportedCCBSPhase) <= 127) {
					if constraintErr := checkDecodedValue(opts, s47bb6e_1, "51.4", "supportedCCBS-Phase", "(1..127)", ber.ObserveInteger(int64(*v.SupportedCCBSPhase))); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode additionalSignalInfo
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 17 {
				ber.MarkPreflightTarget(opts, "additionalSignalInfo", content[offset:])
				decodedTag_additionalsignalinfo, n_additionalsignalinfo, rawVal_additionalsignalinfo, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "additionalSignalInfo", "decoding", false)
				}
				if decodedTag_additionalsignalinfo.Class != tag.ClassContextSpecific || decodedTag_additionalsignalinfo.Number != 17 || decodedTag_additionalsignalinfo.Constructed != true {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_additionalsignalinfo), "additionalSignalInfo", "decoding", false)
				}
				_ = rawVal_additionalsignalinfo
				if offset < 0 || offset >
					len(content) || n_additionalsignalinfo < 0 || n_additionalsignalinfo >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				reconstructed_additionalsignalinfo, reconstructionErr_additionalsignalinfo := ber.EncodeImplicitTagWithClass(tag.ClassUniversal, tag.TagSequence, content[offset:offset+n_additionalsignalinfo])
				if reconstructionErr_additionalsignalinfo != nil {
					return qualifyBERError(reconstructionErr_additionalsignalinfo, "additionalSignalInfo", "decoding", false)
				}
				var dec_additionalsignalinfo ExtExternalSignalInfo
				if unmErr := dec_additionalsignalinfo.UnmarshalBER(reconstructed_additionalsignalinfo, ber.ChildDecodeOptions(opts, "additionalSignalInfo")...); unmErr != nil {
					return qualifyBERError(unmErr, "additionalSignalInfo", "decoding", false)
				}
				v.AdditionalSignalInfo = &dec_additionalsignalinfo
				if offset < 0 || offset >
					len(content) || n_additionalsignalinfo < 0 || n_additionalsignalinfo >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_additionalsignalinfo
			}
		}
	}
	// Decode istSupportIndicator
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 18 {
				ber.MarkPreflightTarget(opts, "istSupportIndicator", content[offset:])
				decodedTag_istsupportindicator, n_istsupportindicator, rawVal_istsupportindicator, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "istSupportIndicator", "decoding", false)
				}
				if decodedTag_istsupportindicator.Class != tag.ClassContextSpecific || decodedTag_istsupportindicator.Number != 18 || decodedTag_istsupportindicator.Constructed != false {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_istsupportindicator), "istSupportIndicator", "decoding", false)
				}
				decVal_istsupportindicator, intErr := ber.DecodeEnumeratedValue(rawVal_istsupportindicator)
				if intErr != nil {
					return qualifyBERError(intErr, "istSupportIndicator", "decoding", false)
				}
				tmp_istsupportindicator := ISTSupportIndicator(decVal_istsupportindicator)
				v.IstSupportIndicator = &tmp_istsupportindicator
				if offset < 0 || offset >
					len(content) || n_istsupportindicator < 0 || n_istsupportindicator >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_istsupportindicator
			}
		}
	}
	// Decode pre-pagingSupported
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 19 {
				ber.MarkPreflightTarget(opts, "pre-pagingSupported", content[offset:])
				decodedTag_prepagingsupported, n_prepagingsupported, rawVal_prepagingsupported, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "pre-pagingSupported", "decoding", false)
				}
				if decodedTag_prepagingsupported.Class != tag.ClassContextSpecific || decodedTag_prepagingsupported.Number != 19 || decodedTag_prepagingsupported.Constructed != false {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_prepagingsupported), "pre-pagingSupported", "decoding", false)
				}
				if len(rawVal_prepagingsupported) != 0 {
					return qualifyBERError(fmt.Errorf("%w: NULL content length %d", ber.ErrInvalidValue, len(rawVal_prepagingsupported)), "pre-pagingSupported", "decoding", false)
				}
				v.PrePagingSupported = &struct{}{}
				if offset < 0 || offset >
					len(content) || n_prepagingsupported < 0 || n_prepagingsupported >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_prepagingsupported
			}
		}
	}
	// Decode callDiversionTreatmentIndicator
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 20 {
				ber.MarkPreflightTarget(opts, "callDiversionTreatmentIndicator", content[offset:])
				decodedTag_calldiversiontreatmentindicator, n_calldiversiontreatmentindicator, rawVal_calldiversiontreatmentindicator, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "callDiversionTreatmentIndicator", "decoding", false)
				}
				if decodedTag_calldiversiontreatmentindicator.Class != tag.ClassContextSpecific || decodedTag_calldiversiontreatmentindicator.Number != 20 {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_calldiversiontreatmentindicator), "callDiversionTreatmentIndicator", "decoding", false)
				}
				decVal_calldiversiontreatmentindicator, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_calldiversiontreatmentindicator.Constructed, rawVal_calldiversiontreatmentindicator, opts...)
				if octetErr != nil {
					return qualifyBERError(octetErr, "callDiversionTreatmentIndicator", "decoding", false)
				}
				tmp_calldiversiontreatmentindicator := CallDiversionTreatmentIndicator(decVal_calldiversiontreatmentindicator)
				v.CallDiversionTreatmentIndicator = &tmp_calldiversiontreatmentindicator
				if offset < 0 || offset >
					len(content) || n_calldiversiontreatmentindicator < 0 || n_calldiversiontreatmentindicator >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_calldiversiontreatmentindicator
				if len(*v.CallDiversionTreatmentIndicator) < 1 || len(*v.CallDiversionTreatmentIndicator) > 1 {
					if constraintErr := checkDecodedLength(opts, s47bb6e_1, "51.5", "callDiversionTreatmentIndicator", "SIZE (1)", len(*v.CallDiversionTreatmentIndicator)); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode longFTN-Supported
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 21 {
				ber.MarkPreflightTarget(opts, "longFTN-Supported", content[offset:])
				decodedTag_longftnsupported, n_longftnsupported, rawVal_longftnsupported, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "longFTN-Supported", "decoding", false)
				}
				if decodedTag_longftnsupported.Class != tag.ClassContextSpecific || decodedTag_longftnsupported.Number != 21 || decodedTag_longftnsupported.Constructed != false {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_longftnsupported), "longFTN-Supported", "decoding", false)
				}
				if len(rawVal_longftnsupported) != 0 {
					return qualifyBERError(fmt.Errorf("%w: NULL content length %d", ber.ErrInvalidValue, len(rawVal_longftnsupported)), "longFTN-Supported", "decoding", false)
				}
				v.LongFTNSupported = &struct{}{}
				if offset < 0 || offset >
					len(content) || n_longftnsupported < 0 || n_longftnsupported >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_longftnsupported
			}
		}
	}
	// Decode suppress-VT-CSI
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 22 {
				ber.MarkPreflightTarget(opts, "suppress-VT-CSI", content[offset:])
				decodedTag_suppressvtcsi, n_suppressvtcsi, rawVal_suppressvtcsi, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "suppress-VT-CSI", "decoding", false)
				}
				if decodedTag_suppressvtcsi.Class != tag.ClassContextSpecific || decodedTag_suppressvtcsi.Number != 22 || decodedTag_suppressvtcsi.Constructed != false {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_suppressvtcsi), "suppress-VT-CSI", "decoding", false)
				}
				if len(rawVal_suppressvtcsi) != 0 {
					return qualifyBERError(fmt.Errorf("%w: NULL content length %d", ber.ErrInvalidValue, len(rawVal_suppressvtcsi)), "suppress-VT-CSI", "decoding", false)
				}
				v.SuppressVTCSI = &struct{}{}
				if offset < 0 || offset >
					len(content) || n_suppressvtcsi < 0 || n_suppressvtcsi > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_suppressvtcsi
			}
		}
	}
	// Decode suppressIncomingCallBarring
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 23 {
				ber.MarkPreflightTarget(opts, "suppressIncomingCallBarring", content[offset:])
				decodedTag_suppressincomingcallbarring, n_suppressincomingcallbarring, rawVal_suppressincomingcallbarring, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "suppressIncomingCallBarring", "decoding", false)
				}
				if decodedTag_suppressincomingcallbarring.Class != tag.ClassContextSpecific || decodedTag_suppressincomingcallbarring.Number != 23 || decodedTag_suppressincomingcallbarring.Constructed != false {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_suppressincomingcallbarring), "suppressIncomingCallBarring", "decoding", false)
				}
				if len(rawVal_suppressincomingcallbarring) != 0 {
					return qualifyBERError(fmt.Errorf("%w: NULL content length %d", ber.ErrInvalidValue, len(rawVal_suppressincomingcallbarring)), "suppressIncomingCallBarring", "decoding", false)
				}
				v.SuppressIncomingCallBarring = &struct{}{}
				if offset < 0 || offset >
					len(content) || n_suppressincomingcallbarring < 0 || n_suppressincomingcallbarring >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_suppressincomingcallbarring
			}
		}
	}
	// Decode gsmSCF-InitiatedCall
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 24 {
				ber.MarkPreflightTarget(opts, "gsmSCF-InitiatedCall", content[offset:])
				decodedTag_gsmscfinitiatedcall, n_gsmscfinitiatedcall, rawVal_gsmscfinitiatedcall, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "gsmSCF-InitiatedCall", "decoding", false)
				}
				if decodedTag_gsmscfinitiatedcall.Class != tag.ClassContextSpecific || decodedTag_gsmscfinitiatedcall.Number != 24 || decodedTag_gsmscfinitiatedcall.Constructed != false {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_gsmscfinitiatedcall), "gsmSCF-InitiatedCall", "decoding", false)
				}
				if len(rawVal_gsmscfinitiatedcall) != 0 {
					return qualifyBERError(fmt.Errorf("%w: NULL content length %d", ber.ErrInvalidValue, len(rawVal_gsmscfinitiatedcall)), "gsmSCF-InitiatedCall", "decoding", false)
				}
				v.GsmSCFInitiatedCall = &struct{}{}
				if offset < 0 || offset >
					len(content) || n_gsmscfinitiatedcall < 0 || n_gsmscfinitiatedcall >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_gsmscfinitiatedcall
			}
		}
	}
	// Decode basicServiceGroup2
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 25 {
				ber.MarkPreflightTarget(opts, "basicServiceGroup2", content[offset:])
				decodedTag_basicservicegroup2, n_basicservicegroup2, innerData_basicservicegroup2, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "basicServiceGroup2", "decoding", false)
				}
				if decodedTag_basicservicegroup2.Class != tag.ClassContextSpecific || decodedTag_basicservicegroup2.Number != 25 || decodedTag_basicservicegroup2.Constructed != true {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_basicservicegroup2), "basicServiceGroup2", "decoding", false)
				}
				_, innerUsed_basicservicegroup2, _, innerErr_basicservicegroup2 := ber.DecodeTLV(innerData_basicservicegroup2, opts...)
				if innerErr_basicservicegroup2 != nil {
					return qualifyBERError(innerErr_basicservicegroup2, "basicServiceGroup2", "decoding", false)
				}
				if innerUsed_basicservicegroup2 != len(innerData_basicservicegroup2) {
					return qualifyBERError(ber.ErrExtraData, "basicServiceGroup2", "decoding", false)
				}
				// Decode inner value from explicit tag wrapper
				ber.MarkPreflightTarget(opts, "basicServiceGroup2", innerData_basicservicegroup2)
				var dec_basicservicegroup2 ExtBasicServiceCode
				if unmErr := dec_basicservicegroup2.UnmarshalBER(innerData_basicservicegroup2, ber.ChildDecodeOptions(opts, "basicServiceGroup2")...); unmErr != nil {
					return qualifyBERError(unmErr, "basicServiceGroup2", "decoding", false)
				}
				v.BasicServiceGroup2 = &dec_basicservicegroup2
				if offset < 0 || offset >
					len(content) || n_basicservicegroup2 < 0 || n_basicservicegroup2 >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_basicservicegroup2
			}
		}
	}
	// Decode networkSignalInfo2
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 26 {
				ber.MarkPreflightTarget(opts, "networkSignalInfo2", content[offset:])
				decodedTag_networksignalinfo2, n_networksignalinfo2, rawVal_networksignalinfo2, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "networkSignalInfo2", "decoding", false)
				}
				if decodedTag_networksignalinfo2.Class != tag.ClassContextSpecific || decodedTag_networksignalinfo2.Number != 26 || decodedTag_networksignalinfo2.Constructed != true {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_networksignalinfo2), "networkSignalInfo2", "decoding", false)
				}
				_ = rawVal_networksignalinfo2
				if offset < 0 || offset >
					len(content) || n_networksignalinfo2 < 0 || n_networksignalinfo2 >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				reconstructed_networksignalinfo2, reconstructionErr_networksignalinfo2 := ber.EncodeImplicitTagWithClass(tag.ClassUniversal, tag.TagSequence, content[offset:offset+n_networksignalinfo2])
				if reconstructionErr_networksignalinfo2 != nil {
					return qualifyBERError(reconstructionErr_networksignalinfo2, "networkSignalInfo2", "decoding", false)
				}
				var dec_networksignalinfo2 ExternalSignalInfo
				if unmErr := dec_networksignalinfo2.UnmarshalBER(reconstructed_networksignalinfo2, ber.ChildDecodeOptions(opts, "networkSignalInfo2")...); unmErr != nil {
					return qualifyBERError(unmErr, "networkSignalInfo2", "decoding", false)
				}
				v.NetworkSignalInfo2 = &dec_networksignalinfo2
				if offset < 0 || offset >
					len(content) || n_networksignalinfo2 < 0 || n_networksignalinfo2 >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_networksignalinfo2
			}
		}
	}
	// Decode suppressMTSS
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 27 {
				ber.MarkPreflightTarget(opts, "suppressMTSS", content[offset:])
				decodedTag_suppressmtss, n_suppressmtss, rawVal_suppressmtss, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "suppressMTSS", "decoding", false)
				}
				if decodedTag_suppressmtss.Class != tag.ClassContextSpecific || decodedTag_suppressmtss.Number != 27 {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_suppressmtss), "suppressMTSS", "decoding", false)
				}
				bsBytes_suppressmtss, bsUnused_suppressmtss, bsErr := ber.DecodeImplicitBitStringValue(decodedTag_suppressmtss.Constructed, rawVal_suppressmtss, opts...)
				if bsErr != nil {
					return qualifyBERError(bsErr, "suppressMTSS", "decoding", false)
				}
				bsBitLength_suppressmtss, bsLenErr_suppressmtss := ber.BitStringBitLength(len(bsBytes_suppressmtss), bsUnused_suppressmtss)
				if bsLenErr_suppressmtss != nil {
					return qualifyBERError(bsLenErr_suppressmtss, "suppressMTSS", "decoding", false)
				}
				tmp_suppressmtss := runtime.BitString{Bytes: bsBytes_suppressmtss, BitLength: bsBitLength_suppressmtss}
				v.SuppressMTSS = &tmp_suppressmtss
				if offset < 0 || offset >
					len(content) || n_suppressmtss < 0 || n_suppressmtss > len(
					content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_suppressmtss
				*v.SuppressMTSS = ber.NormalizeNamedBitStringSize(*v.SuppressMTSS, []ber.NamedBitSizeSet{{{Min: 2, Max: 16}}}, opts...)
				if (*v.SuppressMTSS).BitLength < 2 || (*v.SuppressMTSS).BitLength > 16 {
					if constraintErr := checkDecodedLength(opts, s47bb6e_1, "51.5", "suppressMTSS", "SIZE (2..16)", (*v.SuppressMTSS).BitLength); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode mtRoamingRetrySupported
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 28 {
				ber.MarkPreflightTarget(opts, "mtRoamingRetrySupported", content[offset:])
				decodedTag_mtroamingretrysupported, n_mtroamingretrysupported, rawVal_mtroamingretrysupported, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "mtRoamingRetrySupported", "decoding", false)
				}
				if decodedTag_mtroamingretrysupported.Class != tag.ClassContextSpecific || decodedTag_mtroamingretrysupported.Number != 28 || decodedTag_mtroamingretrysupported.Constructed != false {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_mtroamingretrysupported), "mtRoamingRetrySupported", "decoding", false)
				}
				if len(rawVal_mtroamingretrysupported) != 0 {
					return qualifyBERError(fmt.Errorf("%w: NULL content length %d", ber.ErrInvalidValue, len(rawVal_mtroamingretrysupported)), "mtRoamingRetrySupported", "decoding", false)
				}
				v.MtRoamingRetrySupported = &struct{}{}
				if offset < 0 || offset >
					len(content) || n_mtroamingretrysupported < 0 || n_mtroamingretrysupported >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_mtroamingretrysupported
			}
		}
	}
	// Decode callPriority
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 29 {
				ber.MarkPreflightTarget(opts, "callPriority", content[offset:])
				decodedTag_callpriority, n_callpriority, rawVal_callpriority, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "callPriority", "decoding", false)
				}
				if decodedTag_callpriority.Class != tag.ClassContextSpecific || decodedTag_callpriority.Number != 29 || decodedTag_callpriority.Constructed != false {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_callpriority), "callPriority", "decoding", false)
				}
				decVal_callpriority, intErr := ber.DecodeIntegerValue(rawVal_callpriority)
				if intErr != nil {
					return qualifyBERError(intErr, "callPriority", "decoding", false)
				}
				tmp_callpriority := EMLPPPriority(decVal_callpriority)
				v.CallPriority = &tmp_callpriority
				if offset < 0 || offset >
					len(content) || n_callpriority < 0 || n_callpriority > len(
					content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_callpriority
				if !(int64(*v.CallPriority) >= 0 && int64(*v.CallPriority) <= 15) {
					if constraintErr := checkDecodedValue(opts, s47bb6e_1, "51.4", "callPriority", "(0..15)", ber.ObserveInteger(int64(*v.CallPriority))); constraintErr != nil {
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
			return &ber.DecodeError{Offset: offset, TypeName: "SendRoutingInfoArg", Cause: extErr_}
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: the first unknown addition must differ from trailing OPTIONAL/DEFAULT tags.
		if len(v.ExtData_) == 0 && ((peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 29) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 28) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 27) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 26) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 25) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 24) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 23) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 22) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 21) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 20) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 19) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 18) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 17) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 16) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 15) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 14) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 13) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 12) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 11) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 10) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 9) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 8) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 7)) {
			if !ber.ToleranceEnabled(opts) {
				return &ber.DecodeError{Offset: offset, TypeName: "SendRoutingInfoArg", Cause: fmt.Errorf("%w: repeated or out-of-order SEQUENCE component tag %s", ber.ErrInvalidTag, peekTag)}
			}
			if orderErr_ := ber.CheckDecodedValue(ber.DecodeRule(opts, s47bb6e_1, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), fmt.Sprintf("ExtData_[%d]", len(v.ExtData_)), "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); orderErr_ != nil {
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

// MarshalBERSuppressionOfAnnouncement encodes a typed standalone SuppressionOfAnnouncement, preserving unchanged received BER.
func MarshalBERSuppressionOfAnnouncement(value *BERValue[SuppressionOfAnnouncement], opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {

	if value == nil {
		return nil, fmt.Errorf("%w: required SuppressionOfAnnouncement is nil", ber.ErrInvalidValue)
	}
	return marshalFramedValue(value, value.berReplayNode_, opts, MarshalBERSuppressionOfAnnouncement, marshalBERSuppressionOfAnnouncement, 2, UnmarshalBERSuppressionOfAnnouncement)

}
func marshalBERSuppressionOfAnnouncement(value *BERValue[SuppressionOfAnnouncement], opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	v := &struct{ Value SuppressionOfAnnouncement }{Value: value.Value}
	_ = v
	var children []byte
	enc_value := ber.EncodeNull()
	children = append(children, enc_value...)
	return children, nil
}

// MarshalDERSuppressionOfAnnouncement encodes a typed standalone SuppressionOfAnnouncement using DER.
func MarshalDERSuppressionOfAnnouncement(value *BERValue[SuppressionOfAnnouncement]) ([]byte, error) {
	if value == nil {
		return nil, fmt.Errorf("%w: required SuppressionOfAnnouncement is nil", ber.ErrInvalidValue)
	}
	v := &struct{ Value SuppressionOfAnnouncement }{Value: value.Value}
	_ = v
	var children []byte
	enc_value := ber.EncodeNull()
	children = append(children, enc_value...)
	return children, nil
}

// UnmarshalBERSuppressionOfAnnouncement decodes one complete typed standalone SuppressionOfAnnouncement from BER/DER.
func UnmarshalBERSuppressionOfAnnouncement(data []byte, opts ...ber.DecodeOption) (returnValue *BERValue[SuppressionOfAnnouncement], returnErr error) {
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	preparedData, preparedOptions, prepareErr := prepareValueBER(data, opts, "MAP-CH-DataTypes.SuppressionOfAnnouncement", "child", func(data []byte,

		probeOpts []ber.DecodeOption) error {
		_, probeErr := UnmarshalBERSuppressionOfAnnouncement(data, probeOpts...)
		return probeErr
	})
	if prepareErr != nil {
		return nil, prepareErr
	}
	data, opts = preparedData, preparedOptions

	defer func() {
		returnErr = ber.LocateDecodeError(returnErr, opts)
		if returnErr != nil {
			returnValue = nil
		}
	}()
	v := &struct{ Value SuppressionOfAnnouncement }{}
	decode := func() error {
		content := data
		offset := 0
		ber.MarkPreflightTarget(opts, "SuppressionOfAnnouncement", content[offset:])
		n, err := ber.DecodeNull(content[offset:], opts...)
		if err != nil {
			return fmt.Errorf("%s: %w", "decoding SuppressionOfAnnouncement", qualifyBERError(err, "", "decoding", false))
		}
		if offset > len(content) || n < 0 || n > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n
		if offset != len(content) {
			return ber.ErrExtraData
		}
		return nil
	}
	if err := decode(); err != nil {
		return nil, err
	}
	decoded := &BERValue[SuppressionOfAnnouncement]{Value: v.Value}
	if replayErr := completeValueBER(data,
		opts, decoded, &decoded.berReplayNode_, MarshalBERSuppressionOfAnnouncement); replayErr != nil {
		return nil, replayErr
	}

	return decoded, nil
}

// MarshalBER encodes SendRoutingInfoRes to BER format.
func (v *SendRoutingInfoRes) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {

	if v == nil {
		return nil, fmt.Errorf("%w: SendRoutingInfoRes receiver is nil", ber.ErrInvalidValue)
	}
	return marshalFramedValue(v, v.berReplayNode_, opts, (*SendRoutingInfoRes).MarshalBER, (*SendRoutingInfoRes).marshalBER, 3)

}
func (v *SendRoutingInfoRes) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if v.Imsi != nil {
		if len(*v.Imsi) < 3 || len(*v.Imsi) > 8 {
			if constraintErr := checkEncodedLength(opts, s47bb6e_2, "51.5", "imsi", "SIZE (3..8)", len(*v.Imsi)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_imsi, encodeErr_enc_imsi := ber.EncodeOctetString([]byte(*v.Imsi))
		if encodeErr_enc_imsi != nil {
			return nil, qualifyBERError(encodeErr_enc_imsi, "imsi", "encoding", false)
		}
		retagged_enc_imsi, tagErr_enc_imsi := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 9, enc_imsi)
		if tagErr_enc_imsi != nil {
			return nil, qualifyBERError(tagErr_enc_imsi, "imsi", "encoding", false)
		}
		enc_imsi = retagged_enc_imsi
		children = append(children, enc_imsi...)
	}
	if v.ExtendedRoutingInfo != nil {
		enc_extendedroutinginfo, err := v.ExtendedRoutingInfo.MarshalBER(ber.ChildEncodeOptions(opts, "extendedRoutingInfo")...)
		if err != nil {
			return nil, qualifyBERError(err, "extendedRoutingInfo", "encoding", false)
		}
		ber.RecordGeneratedBERChildPlacement(opts, len(children), enc_extendedroutinginfo)
		children = append(children, enc_extendedroutinginfo...)
	}
	if v.CugCheckInfo != nil {
		enc_cugcheckinfo, err := v.CugCheckInfo.MarshalBER(ber.ChildEncodeOptions(opts, "cug-CheckInfo")...)
		if err != nil {
			return nil, qualifyBERError(err, "cug-CheckInfo", "encoding", false)
		}
		retagged_enc_cugcheckinfo, tagErr_enc_cugcheckinfo := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, enc_cugcheckinfo)
		if tagErr_enc_cugcheckinfo != nil {
			return nil, qualifyBERError(tagErr_enc_cugcheckinfo, "cug-CheckInfo", "encoding", false)
		}
		enc_cugcheckinfo = retagged_enc_cugcheckinfo
		ber.RecordGeneratedBERChildPlacement(opts, len(children), enc_cugcheckinfo)
		children = append(children, enc_cugcheckinfo...)
	}
	if v.CugSubscriptionFlag != nil {
		enc_cugsubscriptionflag := ber.EncodeNull()
		retagged_enc_cugsubscriptionflag, tagErr_enc_cugsubscriptionflag := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 6, enc_cugsubscriptionflag)
		if tagErr_enc_cugsubscriptionflag != nil {
			return nil, qualifyBERError(tagErr_enc_cugsubscriptionflag, "cugSubscriptionFlag", "encoding", false)
		}
		enc_cugsubscriptionflag = retagged_enc_cugsubscriptionflag
		children = append(children, enc_cugsubscriptionflag...)
	}
	if v.SubscriberInfo != nil {
		enc_subscriberinfo, err := v.SubscriberInfo.MarshalBER(ber.ChildEncodeOptions(opts, "subscriberInfo")...)
		if err != nil {
			return nil, qualifyBERError(err, "subscriberInfo", "encoding", false)
		}
		retagged_enc_subscriberinfo, tagErr_enc_subscriberinfo := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 7, enc_subscriberinfo)
		if tagErr_enc_subscriberinfo != nil {
			return nil, qualifyBERError(tagErr_enc_subscriberinfo, "subscriberInfo", "encoding", false)
		}
		enc_subscriberinfo = retagged_enc_subscriberinfo
		ber.RecordGeneratedBERChildPlacement(opts, len(children), enc_subscriberinfo)
		children = append(children, enc_subscriberinfo...)
	}
	if v.SsList != nil {
		if len((v.SsList).Values) < 1 || len((v.SsList).Values) > 30 {
			if constraintErr := checkEncodedLength(opts, s47bb6e_2, "51.5", "ss-List", "SIZE (1..30)", len((v.SsList).Values)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_sslist, err := MarshalBERSSList(v.SsList, ber.ParentCollectionSizeEncodeOptions(ber.ChildEncodeOptions(opts, "ss-List"))...)
		if err != nil {
			return nil, qualifyBERError(err, "ss-List", "encoding", false)
		}
		if ber.BERReplayEnabled(opts) && v.berSsListIndef_ {
			// Strip the outer SEQUENCE tag from marshalBER output to get raw children.
			_, _, seqContent_, tlvErr_ := ber.DecodeEncodedTLV(enc_sslist)
			if tlvErr_ != nil {
				return nil, tlvErr_
			}
			{
				var encodeErr error
				enc_sslist, encodeErr = ber.EncodeConstructedIndefinite(tag.Tag{Class: tag.ClassContextSpecific, Number: 1}, seqContent_)
				if encodeErr != nil {
					return nil, qualifyBERError(encodeErr, "ss-List", "encoding", false)
				}
			}
		} else {
			retagged_enc_sslist, tagErr_enc_sslist := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_sslist)
			if tagErr_enc_sslist != nil {
				return nil, qualifyBERError(tagErr_enc_sslist, "ss-List", "encoding", false)
			}
			enc_sslist = retagged_enc_sslist
		}
		ber.RecordGeneratedBERChildPlacement(opts, len(children), enc_sslist)
		children = append(children, enc_sslist...)
	}
	if v.BasicService != nil {
		enc_basicservice, err := v.BasicService.MarshalBER(ber.ChildEncodeOptions(opts, "basicService")...)
		if err != nil {
			return nil, qualifyBERError(err, "basicService", "encoding", false)
		}
		{
			var encodeErr error
			enc_basicservice, encodeErr = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 5, enc_basicservice)
			if encodeErr != nil {
				return nil, qualifyBERError(encodeErr, "basicService", "encoding", false)
			}
		}
		ber.RecordGeneratedBERChildPlacement(opts, len(children), enc_basicservice)
		children = append(children, enc_basicservice...)
	}
	if v.ForwardingInterrogationRequired != nil {
		enc_forwardinginterrogationrequired := ber.EncodeNull()
		retagged_enc_forwardinginterrogationrequired, tagErr_enc_forwardinginterrogationrequired := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, enc_forwardinginterrogationrequired)
		if tagErr_enc_forwardinginterrogationrequired != nil {
			return nil, qualifyBERError(tagErr_enc_forwardinginterrogationrequired, "forwardingInterrogationRequired", "encoding", false)
		}
		enc_forwardinginterrogationrequired = retagged_enc_forwardinginterrogationrequired
		children = append(children, enc_forwardinginterrogationrequired...)
	}
	if v.VmscAddress != nil {
		if len(*v.VmscAddress) < 1 || len(*v.VmscAddress) > 9 {
			if constraintErr := checkEncodedLength(opts, s47bb6e_2, "51.5", "vmsc-Address", "SIZE (1..9)", len(*v.VmscAddress)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		if len(*v.VmscAddress) < 1 || len(*v.VmscAddress) > 20 {
			if constraintErr := checkEncodedLength(opts, s47bb6e_2, "51.5", "vmsc-Address", "SIZE (1..20)", len(*v.VmscAddress)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_vmscaddress, encodeErr_enc_vmscaddress := ber.EncodeOctetString([]byte(*v.VmscAddress))
		if encodeErr_enc_vmscaddress != nil {
			return nil, qualifyBERError(encodeErr_enc_vmscaddress, "vmsc-Address", "encoding", false)
		}
		retagged_enc_vmscaddress, tagErr_enc_vmscaddress := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_vmscaddress)
		if tagErr_enc_vmscaddress != nil {
			return nil, qualifyBERError(tagErr_enc_vmscaddress, "vmsc-Address", "encoding", false)
		}
		enc_vmscaddress = retagged_enc_vmscaddress
		children = append(children, enc_vmscaddress...)
	}
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
		ber.RecordGeneratedBERChildPlacement(opts, len(children), enc_extensioncontainer)
		children = append(children, enc_extensioncontainer...)
	}
	if v.NaeaPreferredCI != nil {
		enc_naeapreferredci, err := v.NaeaPreferredCI.MarshalBER(ber.ChildEncodeOptions(opts, "naea-PreferredCI")...)
		if err != nil {
			return nil, qualifyBERError(err, "naea-PreferredCI", "encoding", false)
		}
		retagged_enc_naeapreferredci, tagErr_enc_naeapreferredci := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 10, enc_naeapreferredci)
		if tagErr_enc_naeapreferredci != nil {
			return nil, qualifyBERError(tagErr_enc_naeapreferredci, "naea-PreferredCI", "encoding", false)
		}
		enc_naeapreferredci = retagged_enc_naeapreferredci
		ber.RecordGeneratedBERChildPlacement(opts, len(children), enc_naeapreferredci)
		children = append(children, enc_naeapreferredci...)
	}
	if v.CcbsIndicators != nil {
		enc_ccbsindicators, err := v.CcbsIndicators.MarshalBER(ber.ChildEncodeOptions(opts, "ccbs-Indicators")...)
		if err != nil {
			return nil, qualifyBERError(err, "ccbs-Indicators", "encoding", false)
		}
		retagged_enc_ccbsindicators, tagErr_enc_ccbsindicators := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 11, enc_ccbsindicators)
		if tagErr_enc_ccbsindicators != nil {
			return nil, qualifyBERError(tagErr_enc_ccbsindicators, "ccbs-Indicators", "encoding", false)
		}
		enc_ccbsindicators = retagged_enc_ccbsindicators
		ber.RecordGeneratedBERChildPlacement(opts, len(children), enc_ccbsindicators)
		children = append(children, enc_ccbsindicators...)
	}
	if v.Msisdn != nil {
		if len(*v.Msisdn) < 1 || len(*v.Msisdn) > 9 {
			if constraintErr := checkEncodedLength(opts, s47bb6e_2, "51.5", "msisdn", "SIZE (1..9)", len(*v.Msisdn)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		if len(*v.Msisdn) < 1 || len(*v.Msisdn) > 20 {
			if constraintErr := checkEncodedLength(opts, s47bb6e_2, "51.5", "msisdn", "SIZE (1..20)", len(*v.Msisdn)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_msisdn, encodeErr_enc_msisdn := ber.EncodeOctetString([]byte(*v.Msisdn))
		if encodeErr_enc_msisdn != nil {
			return nil, qualifyBERError(encodeErr_enc_msisdn, "msisdn", "encoding", false)
		}
		retagged_enc_msisdn, tagErr_enc_msisdn := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 12, enc_msisdn)
		if tagErr_enc_msisdn != nil {
			return nil, qualifyBERError(tagErr_enc_msisdn, "msisdn", "encoding", false)
		}
		enc_msisdn = retagged_enc_msisdn
		children = append(children, enc_msisdn...)
	}
	if v.NumberPortabilityStatus != nil {
		enc_numberportabilitystatus := ber.EncodeEnumerated(int64(*v.NumberPortabilityStatus))
		retagged_enc_numberportabilitystatus, tagErr_enc_numberportabilitystatus := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 13, enc_numberportabilitystatus)
		if tagErr_enc_numberportabilitystatus != nil {
			return nil, qualifyBERError(tagErr_enc_numberportabilitystatus, "numberPortabilityStatus", "encoding", false)
		}
		enc_numberportabilitystatus = retagged_enc_numberportabilitystatus
		children = append(children, enc_numberportabilitystatus...)
	}
	if v.IstAlertTimer != nil {
		if !(int64(*v.IstAlertTimer) >= 15 && int64(*v.IstAlertTimer) <= 255) {
			if constraintErr := checkEncodedValue(opts, s47bb6e_2, "51.4", "istAlertTimer", "(15..255)", ber.ObserveInteger(int64(*v.IstAlertTimer))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_istalerttimer := ber.EncodeInteger(int64(*v.IstAlertTimer))
		retagged_enc_istalerttimer, tagErr_enc_istalerttimer := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 14, enc_istalerttimer)
		if tagErr_enc_istalerttimer != nil {
			return nil, qualifyBERError(tagErr_enc_istalerttimer, "istAlertTimer", "encoding", false)
		}
		enc_istalerttimer = retagged_enc_istalerttimer
		children = append(children, enc_istalerttimer...)
	}
	if v.SupportedCamelPhasesInVMSC != nil {
		namedBits_SupportedCamelPhasesInVMSC, namedBitErr_ := normalizeNamedBits(*v.SupportedCamelPhasesInVMSC, []ber.NamedBitSizeSet{{{Min: 1, Max: 16}}}, opts, "supportedCamelPhasesInVMSC", s47bb6e_2)
		if namedBitErr_ != nil {
			return nil, namedBitErr_
		}
		if bitStringErr := ber.ValidateBitStringLength(namedBits_SupportedCamelPhasesInVMSC.Bytes, namedBits_SupportedCamelPhasesInVMSC.BitLength); bitStringErr != nil {
			return nil, qualifyBERError(bitStringErr, "supportedCamelPhasesInVMSC", "encoding", false)
		}
		// arithmetic pattern BER_BITSTRING_FIELD: 0 <= bit length before modulo and subtraction; gen/codegen.go:750
		if namedBits_SupportedCamelPhasesInVMSC.BitLength < 0 {
			return nil, fmt.Errorf("negative bit string length")
		}
		if (namedBits_SupportedCamelPhasesInVMSC).BitLength < 1 || (namedBits_SupportedCamelPhasesInVMSC).BitLength > 16 {
			if constraintErr := checkEncodedLength(opts, s47bb6e_2, "51.5", "supportedCamelPhasesInVMSC", "SIZE (1..16)", namedBitObservedLength(namedBits_SupportedCamelPhasesInVMSC)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_supportedcamelphasesinvmsc, encodeErr_enc_supportedcamelphasesinvmsc := ber.EncodeBitString(namedBits_SupportedCamelPhasesInVMSC.Bytes, ber.UnusedBitCount(namedBits_SupportedCamelPhasesInVMSC.BitLength))
		if encodeErr_enc_supportedcamelphasesinvmsc != nil {
			return nil, qualifyBERError(encodeErr_enc_supportedcamelphasesinvmsc, "supportedCamelPhasesInVMSC", "encoding", false)
		}
		retagged_enc_supportedcamelphasesinvmsc, tagErr_enc_supportedcamelphasesinvmsc := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 15, enc_supportedcamelphasesinvmsc)
		if tagErr_enc_supportedcamelphasesinvmsc != nil {
			return nil, qualifyBERError(tagErr_enc_supportedcamelphasesinvmsc, "supportedCamelPhasesInVMSC", "encoding", false)
		}
		enc_supportedcamelphasesinvmsc = retagged_enc_supportedcamelphasesinvmsc
		children = append(children, enc_supportedcamelphasesinvmsc...)
	}
	if v.OfferedCamel4CSIsInVMSC != nil {
		namedBits_OfferedCamel4CSIsInVMSC, namedBitErr_ := normalizeNamedBits(*v.OfferedCamel4CSIsInVMSC, []ber.NamedBitSizeSet{{{Min: 7, Max: 16}}}, opts, "offeredCamel4CSIsInVMSC", s47bb6e_2)
		if namedBitErr_ != nil {
			return nil, namedBitErr_
		}
		if bitStringErr := ber.ValidateBitStringLength(namedBits_OfferedCamel4CSIsInVMSC.Bytes, namedBits_OfferedCamel4CSIsInVMSC.BitLength); bitStringErr != nil {
			return nil, qualifyBERError(bitStringErr, "offeredCamel4CSIsInVMSC", "encoding", false)
		}
		// arithmetic pattern BER_BITSTRING_FIELD: 0 <= bit length before modulo and subtraction; gen/codegen.go:750
		if namedBits_OfferedCamel4CSIsInVMSC.BitLength < 0 {
			return nil, fmt.Errorf("negative bit string length")
		}
		if (namedBits_OfferedCamel4CSIsInVMSC).BitLength < 7 || (namedBits_OfferedCamel4CSIsInVMSC).BitLength > 16 {
			if constraintErr := checkEncodedLength(opts, s47bb6e_2, "51.5", "offeredCamel4CSIsInVMSC", "SIZE (7..16)", namedBitObservedLength(namedBits_OfferedCamel4CSIsInVMSC)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_offeredcamel4csisinvmsc, encodeErr_enc_offeredcamel4csisinvmsc := ber.EncodeBitString(namedBits_OfferedCamel4CSIsInVMSC.Bytes, ber.UnusedBitCount(namedBits_OfferedCamel4CSIsInVMSC.BitLength))
		if encodeErr_enc_offeredcamel4csisinvmsc != nil {
			return nil, qualifyBERError(encodeErr_enc_offeredcamel4csisinvmsc, "offeredCamel4CSIsInVMSC", "encoding", false)
		}
		retagged_enc_offeredcamel4csisinvmsc, tagErr_enc_offeredcamel4csisinvmsc := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 16, enc_offeredcamel4csisinvmsc)
		if tagErr_enc_offeredcamel4csisinvmsc != nil {
			return nil, qualifyBERError(tagErr_enc_offeredcamel4csisinvmsc, "offeredCamel4CSIsInVMSC", "encoding", false)
		}
		enc_offeredcamel4csisinvmsc = retagged_enc_offeredcamel4csisinvmsc
		children = append(children, enc_offeredcamel4csisinvmsc...)
	}
	if v.RoutingInfo2 != nil {
		enc_routinginfo2, err := v.RoutingInfo2.MarshalBER(ber.ChildEncodeOptions(opts, "routingInfo2")...)
		if err != nil {
			return nil, qualifyBERError(err, "routingInfo2", "encoding", false)
		}
		{
			var encodeErr error
			enc_routinginfo2, encodeErr = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 17, enc_routinginfo2)
			if encodeErr != nil {
				return nil, qualifyBERError(encodeErr, "routingInfo2", "encoding", false)
			}
		}
		ber.RecordGeneratedBERChildPlacement(opts, len(children), enc_routinginfo2)
		children = append(children, enc_routinginfo2...)
	}
	if v.SsList2 != nil {
		if len((v.SsList2).Values) < 1 || len((v.SsList2).Values) > 30 {
			if constraintErr := checkEncodedLength(opts, s47bb6e_2, "51.5", "ss-List2", "SIZE (1..30)", len((v.SsList2).Values)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_sslist2, err := MarshalBERSSList(v.SsList2, ber.ParentCollectionSizeEncodeOptions(ber.ChildEncodeOptions(opts, "ss-List2"))...)
		if err != nil {
			return nil, qualifyBERError(err, "ss-List2", "encoding", false)
		}
		if ber.BERReplayEnabled(opts) && v.berSsList2Indef_ {
			// Strip the outer SEQUENCE tag from marshalBER output to get raw children.
			_, _, seqContent_, tlvErr_ := ber.DecodeEncodedTLV(enc_sslist2)
			if tlvErr_ != nil {
				return nil, tlvErr_
			}
			{
				var encodeErr error
				enc_sslist2, encodeErr = ber.EncodeConstructedIndefinite(tag.Tag{Class: tag.ClassContextSpecific, Number: 18}, seqContent_)
				if encodeErr != nil {
					return nil, qualifyBERError(encodeErr, "ss-List2", "encoding", false)
				}
			}
		} else {
			retagged_enc_sslist2, tagErr_enc_sslist2 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 18, enc_sslist2)
			if tagErr_enc_sslist2 != nil {
				return nil, qualifyBERError(tagErr_enc_sslist2, "ss-List2", "encoding", false)
			}
			enc_sslist2 = retagged_enc_sslist2
		}
		ber.RecordGeneratedBERChildPlacement(opts, len(children), enc_sslist2)
		children = append(children, enc_sslist2...)
	}
	if v.BasicService2 != nil {
		enc_basicservice2, err := v.BasicService2.MarshalBER(ber.ChildEncodeOptions(opts, "basicService2")...)
		if err != nil {
			return nil, qualifyBERError(err, "basicService2", "encoding", false)
		}
		{
			var encodeErr error
			enc_basicservice2, encodeErr = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 19, enc_basicservice2)
			if encodeErr != nil {
				return nil, qualifyBERError(encodeErr, "basicService2", "encoding", false)
			}
		}
		ber.RecordGeneratedBERChildPlacement(opts, len(children), enc_basicservice2)
		children = append(children, enc_basicservice2...)
	}
	if v.AllowedServices != nil {
		namedBits_AllowedServices, namedBitErr_ := normalizeNamedBits(*v.AllowedServices, []ber.NamedBitSizeSet{{{Min: 2, Max: 8}}}, opts, "allowedServices", s47bb6e_2)
		if namedBitErr_ != nil {
			return nil, namedBitErr_
		}
		if bitStringErr := ber.ValidateBitStringLength(namedBits_AllowedServices.Bytes, namedBits_AllowedServices.BitLength); bitStringErr != nil {
			return nil, qualifyBERError(bitStringErr, "allowedServices", "encoding", false)
		}
		// arithmetic pattern BER_BITSTRING_FIELD: 0 <= bit length before modulo and subtraction; gen/codegen.go:750
		if namedBits_AllowedServices.BitLength < 0 {
			return nil, fmt.Errorf("negative bit string length")
		}
		if (namedBits_AllowedServices).BitLength < 2 || (namedBits_AllowedServices).BitLength > 8 {
			if constraintErr := checkEncodedLength(opts, s47bb6e_2, "51.5", "allowedServices", "SIZE (2..8)", namedBitObservedLength(namedBits_AllowedServices)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_allowedservices, encodeErr_enc_allowedservices := ber.EncodeBitString(namedBits_AllowedServices.Bytes, ber.UnusedBitCount(namedBits_AllowedServices.BitLength))
		if encodeErr_enc_allowedservices != nil {
			return nil, qualifyBERError(encodeErr_enc_allowedservices, "allowedServices", "encoding", false)
		}
		retagged_enc_allowedservices, tagErr_enc_allowedservices := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 20, enc_allowedservices)
		if tagErr_enc_allowedservices != nil {
			return nil, qualifyBERError(tagErr_enc_allowedservices, "allowedServices", "encoding", false)
		}
		enc_allowedservices = retagged_enc_allowedservices
		children = append(children, enc_allowedservices...)
	}
	if v.UnavailabilityCause != nil {
		enc_unavailabilitycause := ber.EncodeEnumerated(int64(*v.UnavailabilityCause))
		retagged_enc_unavailabilitycause, tagErr_enc_unavailabilitycause := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 21, enc_unavailabilitycause)
		if tagErr_enc_unavailabilitycause != nil {
			return nil, qualifyBERError(tagErr_enc_unavailabilitycause, "unavailabilityCause", "encoding", false)
		}
		enc_unavailabilitycause = retagged_enc_unavailabilitycause
		children = append(children, enc_unavailabilitycause...)
	}
	if v.ReleaseResourcesSupported != nil {
		enc_releaseresourcessupported := ber.EncodeNull()
		retagged_enc_releaseresourcessupported, tagErr_enc_releaseresourcessupported := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 22, enc_releaseresourcessupported)
		if tagErr_enc_releaseresourcessupported != nil {
			return nil, qualifyBERError(tagErr_enc_releaseresourcessupported, "releaseResourcesSupported", "encoding", false)
		}
		enc_releaseresourcessupported = retagged_enc_releaseresourcessupported
		children = append(children, enc_releaseresourcessupported...)
	}
	if v.GsmBearerCapability != nil {
		enc_gsmbearercapability, err := v.GsmBearerCapability.MarshalBER(ber.ChildEncodeOptions(opts, "gsm-BearerCapability")...)
		if err != nil {
			return nil, qualifyBERError(err, "gsm-BearerCapability", "encoding", false)
		}
		retagged_enc_gsmbearercapability, tagErr_enc_gsmbearercapability := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 23, enc_gsmbearercapability)
		if tagErr_enc_gsmbearercapability != nil {
			return nil, qualifyBERError(tagErr_enc_gsmbearercapability, "gsm-BearerCapability", "encoding", false)
		}
		enc_gsmbearercapability = retagged_enc_gsmbearercapability
		ber.RecordGeneratedBERChildPlacement(opts, len(children), enc_gsmbearercapability)
		children = append(children, enc_gsmbearercapability...)
	}
	base_ := -1
	for i, ext := range v.ExtData_ {
		if err := checkOpaqueAddition(ext, opts, s47bb6e_2, children, i, &base_); err != nil {
			return nil, opaqueExtensionError(err, i)
		}
		peekTag, n, _, extErr := ber.DecodeEncodedTLV(ext)
		if extErr != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, extErr)
		}
		if n != len(ext) {
			return nil, fmt.Errorf("encoding extension %d: %w", i, ber.ErrExtraData)
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: only the first addition is restricted.
		if i == 0 && ((peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 23) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 22) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 21) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 20) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 19) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 18) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 17) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 16) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 15) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 14) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 13) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 12) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 11) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 10) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 5) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 7) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 6) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3) || (peekTag.Class == tag.ClassUniversal && peekTag.Number == 4) || (peekTag.Class == tag.ClassUniversal && peekTag.Number == 16) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 8) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 9)) {
			if constraintErr := ber.CheckEncodedValue(ber.EncodeRule(opts, s47bb6e_2, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
				return nil, constraintErr
			}
		}
		children = append(children, ext...)
	}
	ber.RecordGeneratedBERContainer(opts, children)
	return ber.EncodeConstructed(tag.Tag{Class: tag.ClassContextSpecific, Number: 3, Constructed: true}, children)
}
func (v *SendRoutingInfoRes) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// MarshalDER encodes SendRoutingInfoRes to DER format.
// Opaque descendants pass generic DER checks; foreign schema rules need a typed binding.
func (v *SendRoutingInfoRes) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: SendRoutingInfoRes receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if v.Imsi != nil {
		if len(*v.Imsi) < 3 || len(*v.Imsi) > 8 {
			if constraintErr := checkEncodedLength(nil, s47bb6e_2, "51.5", "imsi", "SIZE (3..8)", len(*v.Imsi)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_imsi, encodeErr_enc_imsi := ber.EncodeOctetString([]byte(*v.Imsi))
		if encodeErr_enc_imsi != nil {
			return nil, qualifyBERError(encodeErr_enc_imsi, "imsi", "encoding", true)
		}
		retagged_enc_imsi, tagErr_enc_imsi := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 9, enc_imsi)
		if tagErr_enc_imsi != nil {
			return nil, qualifyBERError(tagErr_enc_imsi, "imsi", "encoding", true)
		}
		enc_imsi = retagged_enc_imsi
		children = append(children, enc_imsi...)
	}
	if v.ExtendedRoutingInfo != nil {
		enc_extendedroutinginfo, err := v.ExtendedRoutingInfo.MarshalDER()
		if err != nil {
			return nil, qualifyBERError(err, "extendedRoutingInfo", "encoding", true)
		}
		children = append(children, enc_extendedroutinginfo...)
	}
	if v.CugCheckInfo != nil {
		enc_cugcheckinfo, err := v.CugCheckInfo.MarshalDER()
		if err != nil {
			return nil, qualifyBERError(err, "cug-CheckInfo", "encoding", true)
		}
		retagged_enc_cugcheckinfo, tagErr_enc_cugcheckinfo := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, enc_cugcheckinfo)
		if tagErr_enc_cugcheckinfo != nil {
			return nil, qualifyBERError(tagErr_enc_cugcheckinfo, "cug-CheckInfo", "encoding", true)
		}
		enc_cugcheckinfo = retagged_enc_cugcheckinfo
		children = append(children, enc_cugcheckinfo...)
	}
	if v.CugSubscriptionFlag != nil {
		enc_cugsubscriptionflag := ber.EncodeNull()
		retagged_enc_cugsubscriptionflag, tagErr_enc_cugsubscriptionflag := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 6, enc_cugsubscriptionflag)
		if tagErr_enc_cugsubscriptionflag != nil {
			return nil, qualifyBERError(tagErr_enc_cugsubscriptionflag, "cugSubscriptionFlag", "encoding", true)
		}
		enc_cugsubscriptionflag = retagged_enc_cugsubscriptionflag
		children = append(children, enc_cugsubscriptionflag...)
	}
	if v.SubscriberInfo != nil {
		enc_subscriberinfo, err := v.SubscriberInfo.MarshalDER()
		if err != nil {
			return nil, qualifyBERError(err, "subscriberInfo", "encoding", true)
		}
		retagged_enc_subscriberinfo, tagErr_enc_subscriberinfo := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 7, enc_subscriberinfo)
		if tagErr_enc_subscriberinfo != nil {
			return nil, qualifyBERError(tagErr_enc_subscriberinfo, "subscriberInfo", "encoding", true)
		}
		enc_subscriberinfo = retagged_enc_subscriberinfo
		children = append(children, enc_subscriberinfo...)
	}
	if v.SsList != nil {
		if len((v.SsList).Values) < 1 || len((v.SsList).Values) > 30 {
			if constraintErr := checkEncodedLength(nil, s47bb6e_2, "51.5", "ss-List", "SIZE (1..30)", len((v.SsList).Values)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_sslist, err := MarshalDERSSList(v.SsList)
		if err != nil {
			return nil, qualifyBERError(err, "ss-List", "encoding", true)
		}
		retagged_enc_sslist, tagErr_enc_sslist := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_sslist)
		if tagErr_enc_sslist != nil {
			return nil, qualifyBERError(tagErr_enc_sslist, "ss-List", "encoding", true)
		}
		enc_sslist = retagged_enc_sslist
		children = append(children, enc_sslist...)
	}
	if v.BasicService != nil {
		enc_basicservice, err := v.BasicService.MarshalDER()
		if err != nil {
			return nil, qualifyBERError(err, "basicService", "encoding", true)
		}
		{
			var encodeErr error
			enc_basicservice, encodeErr = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 5, enc_basicservice)
			if encodeErr != nil {
				return nil, qualifyBERError(encodeErr, "basicService", "encoding", true)
			}
		}
		children = append(children, enc_basicservice...)
	}
	if v.ForwardingInterrogationRequired != nil {
		enc_forwardinginterrogationrequired := ber.EncodeNull()
		retagged_enc_forwardinginterrogationrequired, tagErr_enc_forwardinginterrogationrequired := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, enc_forwardinginterrogationrequired)
		if tagErr_enc_forwardinginterrogationrequired != nil {
			return nil, qualifyBERError(tagErr_enc_forwardinginterrogationrequired, "forwardingInterrogationRequired", "encoding", true)
		}
		enc_forwardinginterrogationrequired = retagged_enc_forwardinginterrogationrequired
		children = append(children, enc_forwardinginterrogationrequired...)
	}
	if v.VmscAddress != nil {
		if len(*v.VmscAddress) < 1 || len(*v.VmscAddress) > 9 {
			if constraintErr := checkEncodedLength(nil, s47bb6e_2, "51.5", "vmsc-Address", "SIZE (1..9)", len(*v.VmscAddress)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		if len(*v.VmscAddress) < 1 || len(*v.VmscAddress) > 20 {
			if constraintErr := checkEncodedLength(nil, s47bb6e_2, "51.5", "vmsc-Address", "SIZE (1..20)", len(*v.VmscAddress)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_vmscaddress, encodeErr_enc_vmscaddress := ber.EncodeOctetString([]byte(*v.VmscAddress))
		if encodeErr_enc_vmscaddress != nil {
			return nil, qualifyBERError(encodeErr_enc_vmscaddress, "vmsc-Address", "encoding", true)
		}
		retagged_enc_vmscaddress, tagErr_enc_vmscaddress := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_vmscaddress)
		if tagErr_enc_vmscaddress != nil {
			return nil, qualifyBERError(tagErr_enc_vmscaddress, "vmsc-Address", "encoding", true)
		}
		enc_vmscaddress = retagged_enc_vmscaddress
		children = append(children, enc_vmscaddress...)
	}
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
	if v.NaeaPreferredCI != nil {
		enc_naeapreferredci, err := v.NaeaPreferredCI.MarshalDER()
		if err != nil {
			return nil, qualifyBERError(err, "naea-PreferredCI", "encoding", true)
		}
		retagged_enc_naeapreferredci, tagErr_enc_naeapreferredci := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 10, enc_naeapreferredci)
		if tagErr_enc_naeapreferredci != nil {
			return nil, qualifyBERError(tagErr_enc_naeapreferredci, "naea-PreferredCI", "encoding", true)
		}
		enc_naeapreferredci = retagged_enc_naeapreferredci
		children = append(children, enc_naeapreferredci...)
	}
	if v.CcbsIndicators != nil {
		enc_ccbsindicators, err := v.CcbsIndicators.MarshalDER()
		if err != nil {
			return nil, qualifyBERError(err, "ccbs-Indicators", "encoding", true)
		}
		retagged_enc_ccbsindicators, tagErr_enc_ccbsindicators := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 11, enc_ccbsindicators)
		if tagErr_enc_ccbsindicators != nil {
			return nil, qualifyBERError(tagErr_enc_ccbsindicators, "ccbs-Indicators", "encoding", true)
		}
		enc_ccbsindicators = retagged_enc_ccbsindicators
		children = append(children, enc_ccbsindicators...)
	}
	if v.Msisdn != nil {
		if len(*v.Msisdn) < 1 || len(*v.Msisdn) > 9 {
			if constraintErr := checkEncodedLength(nil, s47bb6e_2, "51.5", "msisdn", "SIZE (1..9)", len(*v.Msisdn)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		if len(*v.Msisdn) < 1 || len(*v.Msisdn) > 20 {
			if constraintErr := checkEncodedLength(nil, s47bb6e_2, "51.5", "msisdn", "SIZE (1..20)", len(*v.Msisdn)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_msisdn, encodeErr_enc_msisdn := ber.EncodeOctetString([]byte(*v.Msisdn))
		if encodeErr_enc_msisdn != nil {
			return nil, qualifyBERError(encodeErr_enc_msisdn, "msisdn", "encoding", true)
		}
		retagged_enc_msisdn, tagErr_enc_msisdn := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 12, enc_msisdn)
		if tagErr_enc_msisdn != nil {
			return nil, qualifyBERError(tagErr_enc_msisdn, "msisdn", "encoding", true)
		}
		enc_msisdn = retagged_enc_msisdn
		children = append(children, enc_msisdn...)
	}
	if v.NumberPortabilityStatus != nil {
		enc_numberportabilitystatus := ber.EncodeEnumerated(int64(*v.NumberPortabilityStatus))
		retagged_enc_numberportabilitystatus, tagErr_enc_numberportabilitystatus := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 13, enc_numberportabilitystatus)
		if tagErr_enc_numberportabilitystatus != nil {
			return nil, qualifyBERError(tagErr_enc_numberportabilitystatus, "numberPortabilityStatus", "encoding", true)
		}
		enc_numberportabilitystatus = retagged_enc_numberportabilitystatus
		children = append(children, enc_numberportabilitystatus...)
	}
	if v.IstAlertTimer != nil {
		if !(int64(*v.IstAlertTimer) >= 15 && int64(*v.IstAlertTimer) <= 255) {
			if constraintErr := checkEncodedValue(nil, s47bb6e_2, "51.4", "istAlertTimer", "(15..255)", ber.ObserveInteger(int64(*v.IstAlertTimer))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_istalerttimer := ber.EncodeInteger(int64(*v.IstAlertTimer))
		retagged_enc_istalerttimer, tagErr_enc_istalerttimer := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 14, enc_istalerttimer)
		if tagErr_enc_istalerttimer != nil {
			return nil, qualifyBERError(tagErr_enc_istalerttimer, "istAlertTimer", "encoding", true)
		}
		enc_istalerttimer = retagged_enc_istalerttimer
		children = append(children, enc_istalerttimer...)
	}
	if v.SupportedCamelPhasesInVMSC != nil {
		namedBits_SupportedCamelPhasesInVMSC, namedBitErr_ := normalizeNamedBits(*v.SupportedCamelPhasesInVMSC, []ber.NamedBitSizeSet{{{Min: 1, Max: 16}}}, nil, "supportedCamelPhasesInVMSC", s47bb6e_2)
		if namedBitErr_ != nil {
			return nil, namedBitErr_
		}
		if bitStringErr := ber.ValidateBitStringLength(namedBits_SupportedCamelPhasesInVMSC.Bytes, namedBits_SupportedCamelPhasesInVMSC.BitLength); bitStringErr != nil {
			return nil, qualifyBERError(bitStringErr, "supportedCamelPhasesInVMSC", "encoding", true)
		}
		// arithmetic pattern BER_BITSTRING_FIELD: 0 <= bit length before modulo and subtraction; gen/codegen.go:750
		if namedBits_SupportedCamelPhasesInVMSC.BitLength < 0 {
			return nil, fmt.Errorf("negative bit string length")
		}
		if (namedBits_SupportedCamelPhasesInVMSC).BitLength < 1 || (namedBits_SupportedCamelPhasesInVMSC).BitLength > 16 {
			if constraintErr := checkEncodedLength(nil, s47bb6e_2, "51.5", "supportedCamelPhasesInVMSC", "SIZE (1..16)", namedBitObservedLength(namedBits_SupportedCamelPhasesInVMSC)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_supportedcamelphasesinvmsc, encodeErr_enc_supportedcamelphasesinvmsc := ber.EncodeDERNamedBitString(namedBits_SupportedCamelPhasesInVMSC.Bytes, namedBits_SupportedCamelPhasesInVMSC.BitLength)
		if encodeErr_enc_supportedcamelphasesinvmsc != nil {
			return nil, qualifyBERError(encodeErr_enc_supportedcamelphasesinvmsc, "supportedCamelPhasesInVMSC", "encoding", true)
		}
		retagged_enc_supportedcamelphasesinvmsc, tagErr_enc_supportedcamelphasesinvmsc := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 15, enc_supportedcamelphasesinvmsc)
		if tagErr_enc_supportedcamelphasesinvmsc != nil {
			return nil, qualifyBERError(tagErr_enc_supportedcamelphasesinvmsc, "supportedCamelPhasesInVMSC", "encoding", true)
		}
		enc_supportedcamelphasesinvmsc = retagged_enc_supportedcamelphasesinvmsc
		children = append(children, enc_supportedcamelphasesinvmsc...)
	}
	if v.OfferedCamel4CSIsInVMSC != nil {
		namedBits_OfferedCamel4CSIsInVMSC, namedBitErr_ := normalizeNamedBits(*v.OfferedCamel4CSIsInVMSC, []ber.NamedBitSizeSet{{{Min: 7, Max: 16}}}, nil, "offeredCamel4CSIsInVMSC", s47bb6e_2)
		if namedBitErr_ != nil {
			return nil, namedBitErr_
		}
		if bitStringErr := ber.ValidateBitStringLength(namedBits_OfferedCamel4CSIsInVMSC.Bytes, namedBits_OfferedCamel4CSIsInVMSC.BitLength); bitStringErr != nil {
			return nil, qualifyBERError(bitStringErr, "offeredCamel4CSIsInVMSC", "encoding", true)
		}
		// arithmetic pattern BER_BITSTRING_FIELD: 0 <= bit length before modulo and subtraction; gen/codegen.go:750
		if namedBits_OfferedCamel4CSIsInVMSC.BitLength < 0 {
			return nil, fmt.Errorf("negative bit string length")
		}
		if (namedBits_OfferedCamel4CSIsInVMSC).BitLength < 7 || (namedBits_OfferedCamel4CSIsInVMSC).BitLength > 16 {
			if constraintErr := checkEncodedLength(nil, s47bb6e_2, "51.5", "offeredCamel4CSIsInVMSC", "SIZE (7..16)", namedBitObservedLength(namedBits_OfferedCamel4CSIsInVMSC)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_offeredcamel4csisinvmsc, encodeErr_enc_offeredcamel4csisinvmsc := ber.EncodeDERNamedBitString(namedBits_OfferedCamel4CSIsInVMSC.Bytes, namedBits_OfferedCamel4CSIsInVMSC.BitLength)
		if encodeErr_enc_offeredcamel4csisinvmsc != nil {
			return nil, qualifyBERError(encodeErr_enc_offeredcamel4csisinvmsc, "offeredCamel4CSIsInVMSC", "encoding", true)
		}
		retagged_enc_offeredcamel4csisinvmsc, tagErr_enc_offeredcamel4csisinvmsc := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 16, enc_offeredcamel4csisinvmsc)
		if tagErr_enc_offeredcamel4csisinvmsc != nil {
			return nil, qualifyBERError(tagErr_enc_offeredcamel4csisinvmsc, "offeredCamel4CSIsInVMSC", "encoding", true)
		}
		enc_offeredcamel4csisinvmsc = retagged_enc_offeredcamel4csisinvmsc
		children = append(children, enc_offeredcamel4csisinvmsc...)
	}
	if v.RoutingInfo2 != nil {
		enc_routinginfo2, err := v.RoutingInfo2.MarshalDER()
		if err != nil {
			return nil, qualifyBERError(err, "routingInfo2", "encoding", true)
		}
		{
			var encodeErr error
			enc_routinginfo2, encodeErr = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 17, enc_routinginfo2)
			if encodeErr != nil {
				return nil, qualifyBERError(encodeErr, "routingInfo2", "encoding", true)
			}
		}
		children = append(children, enc_routinginfo2...)
	}
	if v.SsList2 != nil {
		if len((v.SsList2).Values) < 1 || len((v.SsList2).Values) > 30 {
			if constraintErr := checkEncodedLength(nil, s47bb6e_2, "51.5", "ss-List2", "SIZE (1..30)", len((v.SsList2).Values)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_sslist2, err := MarshalDERSSList(v.SsList2)
		if err != nil {
			return nil, qualifyBERError(err, "ss-List2", "encoding", true)
		}
		retagged_enc_sslist2, tagErr_enc_sslist2 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 18, enc_sslist2)
		if tagErr_enc_sslist2 != nil {
			return nil, qualifyBERError(tagErr_enc_sslist2, "ss-List2", "encoding", true)
		}
		enc_sslist2 = retagged_enc_sslist2
		children = append(children, enc_sslist2...)
	}
	if v.BasicService2 != nil {
		enc_basicservice2, err := v.BasicService2.MarshalDER()
		if err != nil {
			return nil, qualifyBERError(err, "basicService2", "encoding", true)
		}
		{
			var encodeErr error
			enc_basicservice2, encodeErr = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 19, enc_basicservice2)
			if encodeErr != nil {
				return nil, qualifyBERError(encodeErr, "basicService2", "encoding", true)
			}
		}
		children = append(children, enc_basicservice2...)
	}
	if v.AllowedServices != nil {
		namedBits_AllowedServices, namedBitErr_ := normalizeNamedBits(*v.AllowedServices, []ber.NamedBitSizeSet{{{Min: 2, Max: 8}}}, nil, "allowedServices", s47bb6e_2)
		if namedBitErr_ != nil {
			return nil, namedBitErr_
		}
		if bitStringErr := ber.ValidateBitStringLength(namedBits_AllowedServices.Bytes, namedBits_AllowedServices.BitLength); bitStringErr != nil {
			return nil, qualifyBERError(bitStringErr, "allowedServices", "encoding", true)
		}
		// arithmetic pattern BER_BITSTRING_FIELD: 0 <= bit length before modulo and subtraction; gen/codegen.go:750
		if namedBits_AllowedServices.BitLength < 0 {
			return nil, fmt.Errorf("negative bit string length")
		}
		if (namedBits_AllowedServices).BitLength < 2 || (namedBits_AllowedServices).BitLength > 8 {
			if constraintErr := checkEncodedLength(nil, s47bb6e_2, "51.5", "allowedServices", "SIZE (2..8)", namedBitObservedLength(namedBits_AllowedServices)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_allowedservices, encodeErr_enc_allowedservices := ber.EncodeDERNamedBitString(namedBits_AllowedServices.Bytes, namedBits_AllowedServices.BitLength)
		if encodeErr_enc_allowedservices != nil {
			return nil, qualifyBERError(encodeErr_enc_allowedservices, "allowedServices", "encoding", true)
		}
		retagged_enc_allowedservices, tagErr_enc_allowedservices := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 20, enc_allowedservices)
		if tagErr_enc_allowedservices != nil {
			return nil, qualifyBERError(tagErr_enc_allowedservices, "allowedServices", "encoding", true)
		}
		enc_allowedservices = retagged_enc_allowedservices
		children = append(children, enc_allowedservices...)
	}
	if v.UnavailabilityCause != nil {
		enc_unavailabilitycause := ber.EncodeEnumerated(int64(*v.UnavailabilityCause))
		retagged_enc_unavailabilitycause, tagErr_enc_unavailabilitycause := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 21, enc_unavailabilitycause)
		if tagErr_enc_unavailabilitycause != nil {
			return nil, qualifyBERError(tagErr_enc_unavailabilitycause, "unavailabilityCause", "encoding", true)
		}
		enc_unavailabilitycause = retagged_enc_unavailabilitycause
		children = append(children, enc_unavailabilitycause...)
	}
	if v.ReleaseResourcesSupported != nil {
		enc_releaseresourcessupported := ber.EncodeNull()
		retagged_enc_releaseresourcessupported, tagErr_enc_releaseresourcessupported := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 22, enc_releaseresourcessupported)
		if tagErr_enc_releaseresourcessupported != nil {
			return nil, qualifyBERError(tagErr_enc_releaseresourcessupported, "releaseResourcesSupported", "encoding", true)
		}
		enc_releaseresourcessupported = retagged_enc_releaseresourcessupported
		children = append(children, enc_releaseresourcessupported...)
	}
	if v.GsmBearerCapability != nil {
		enc_gsmbearercapability, err := v.GsmBearerCapability.MarshalDER()
		if err != nil {
			return nil, qualifyBERError(err, "gsm-BearerCapability", "encoding", true)
		}
		retagged_enc_gsmbearercapability, tagErr_enc_gsmbearercapability := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 23, enc_gsmbearercapability)
		if tagErr_enc_gsmbearercapability != nil {
			return nil, qualifyBERError(tagErr_enc_gsmbearercapability, "gsm-BearerCapability", "encoding", true)
		}
		enc_gsmbearercapability = retagged_enc_gsmbearercapability
		children = append(children, enc_gsmbearercapability...)
	}
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDEREncodedElement(ext); err != nil {
			return nil, invalidDERAddition(ext, s47bb6e_2, children, i)
		}
		peekTag, _, _, extErr := ber.DecodeEncodedTLV(ext)
		if extErr != nil {
			return nil, extErr
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: only the first addition is restricted.
		if i == 0 && ((peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 23) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 22) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 21) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 20) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 19) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 18) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 17) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 16) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 15) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 14) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 13) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 12) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 11) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 10) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 5) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 7) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 6) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3) || (peekTag.Class == tag.ClassUniversal && peekTag.Number == 4) || (peekTag.Class == tag.ClassUniversal && peekTag.Number == 16) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 8) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 9)) {
			if constraintErr := ber.CheckEncodedValue(ber.EncodeRule(nil, s47bb6e_2, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
				return nil, constraintErr
			}
		}
		children = append(children, ext...)
	}
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	retagged_encoded, tagErr_encoded := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, encoded)
	if tagErr_encoded != nil {
		return nil, qualifyBERError(tagErr_encoded, "SendRoutingInfoRes", "encoding", true)
	}
	encoded = retagged_encoded
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("%s: %w", "encoding SendRoutingInfoRes as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}
func (v *SendRoutingInfoRes) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	encoded, err := v.MarshalDER()
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBER decodes SendRoutingInfoRes from BER/DER format.
func (destination *SendRoutingInfoRes) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if destination == nil {
		return fmt.Errorf("%w: SendRoutingInfoRes destination is nil", ber.ErrInvalidValue)
	}
	v := new(SendRoutingInfoRes)

	defer publishDecodedValue(destination, v, &returnErr)

	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	preparedData, preparedOptions, prepareErr := prepareCompositeBER(data, opts, s47bb6e_2, "child", (*SendRoutingInfoRes).UnmarshalBER)
	if prepareErr != nil {
		return prepareErr
	}
	data, opts = preparedData, preparedOptions

	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
	*v = SendRoutingInfoRes{}
	defer func() {
		if returnErr == nil {
			returnErr = completeValueBER(data,
				opts, v, &v.berReplayNode_, (*SendRoutingInfoRes).MarshalBER)
		}

	}()
	decodedTag, content, total, err := ber.DecodeConstructedContent(data, opts...)
	if err != nil {
		return fmt.Errorf("%s: %w", "decoding SendRoutingInfoRes", qualifyBERError(err, "", "decoding", false))
	}
	if decodedTag.Class != tag.ClassContextSpecific || decodedTag.Number != 3 || !decodedTag.Constructed {
		return fmt.Errorf("%s: %w", "decoding SendRoutingInfoRes", qualifyBERError(fmt.Errorf("%w: expected tag [CONTEXT 3], got %s", ber.ErrInvalidTag, decodedTag), "", "decoding", false))
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "SendRoutingInfoRes", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode imsi
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 9 {
				ber.MarkPreflightTarget(opts, "imsi", content[offset:])
				decodedTag_imsi, n_imsi, rawVal_imsi, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "imsi", "decoding", false)
				}
				if decodedTag_imsi.Class != tag.ClassContextSpecific || decodedTag_imsi.Number != 9 {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_imsi), "imsi", "decoding", false)
				}
				decVal_imsi, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_imsi.Constructed, rawVal_imsi, opts...)
				if octetErr != nil {
					return qualifyBERError(octetErr, "imsi", "decoding", false)
				}
				tmp_imsi := IMSI(decVal_imsi)
				v.Imsi = &tmp_imsi
				if offset > len(content) || n_imsi < 0 || n_imsi > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_imsi
				if len(*v.Imsi) < 3 || len(*v.Imsi) > 8 {
					if constraintErr := checkDecodedLength(opts, s47bb6e_2, "51.5", "imsi", "SIZE (3..8)", len(*v.Imsi)); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode extendedRoutingInfo
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if (peekTag.Class == tag.ClassUniversal && peekTag.Number == 4) || (peekTag.Class == tag.ClassUniversal && peekTag.Number == 16) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 8) {
				ber.MarkPreflightTarget(opts, "extendedRoutingInfo", content[offset:])
				// Decode nested CHOICE (ExtendedRoutingInfo)
				_, n_extendedroutinginfo, _, tlvErr_extendedroutinginfo := ber.DecodeTLV(content[offset:], opts...)
				if tlvErr_extendedroutinginfo != nil {
					return qualifyBERError(tlvErr_extendedroutinginfo, "extendedRoutingInfo", "decoding", false)
				}
				var dec_extendedroutinginfo ExtendedRoutingInfo
				if offset < 0 || offset >
					len(content) || n_extendedroutinginfo < 0 || n_extendedroutinginfo >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				if unmErr := dec_extendedroutinginfo.UnmarshalBER(content[offset:offset+n_extendedroutinginfo], ber.ChildDecodeOptions(opts, "extendedRoutingInfo")...); unmErr != nil {
					return qualifyBERError(unmErr, "extendedRoutingInfo", "decoding", false)
				}
				v.ExtendedRoutingInfo = &dec_extendedroutinginfo
				if offset < 0 || offset >
					len(content) || n_extendedroutinginfo < 0 || n_extendedroutinginfo >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_extendedroutinginfo
			}
		}
	}
	// Decode cug-CheckInfo
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3 {
				ber.MarkPreflightTarget(opts, "cug-CheckInfo", content[offset:])
				decodedTag_cugcheckinfo, n_cugcheckinfo, rawVal_cugcheckinfo, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "cug-CheckInfo", "decoding", false)
				}
				if decodedTag_cugcheckinfo.Class != tag.ClassContextSpecific || decodedTag_cugcheckinfo.Number != 3 || decodedTag_cugcheckinfo.Constructed != true {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_cugcheckinfo), "cug-CheckInfo", "decoding", false)
				}
				_ = rawVal_cugcheckinfo
				if offset < 0 || offset >
					len(content) || n_cugcheckinfo < 0 || n_cugcheckinfo > len(
					content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				reconstructed_cugcheckinfo, reconstructionErr_cugcheckinfo := ber.EncodeImplicitTagWithClass(tag.ClassUniversal, tag.TagSequence, content[offset:offset+n_cugcheckinfo])
				if reconstructionErr_cugcheckinfo != nil {
					return qualifyBERError(reconstructionErr_cugcheckinfo, "cug-CheckInfo", "decoding", false)
				}
				var dec_cugcheckinfo CUGCheckInfo
				if unmErr := dec_cugcheckinfo.UnmarshalBER(reconstructed_cugcheckinfo, ber.ChildDecodeOptions(opts, "cug-CheckInfo")...); unmErr != nil {
					return qualifyBERError(unmErr, "cug-CheckInfo", "decoding", false)
				}
				v.CugCheckInfo = &dec_cugcheckinfo
				if offset < 0 || offset >
					len(content) || n_cugcheckinfo < 0 || n_cugcheckinfo > len(
					content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_cugcheckinfo
			}
		}
	}
	// Decode cugSubscriptionFlag
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 6 {
				ber.MarkPreflightTarget(opts, "cugSubscriptionFlag", content[offset:])
				decodedTag_cugsubscriptionflag, n_cugsubscriptionflag, rawVal_cugsubscriptionflag, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "cugSubscriptionFlag", "decoding", false)
				}
				if decodedTag_cugsubscriptionflag.Class != tag.ClassContextSpecific || decodedTag_cugsubscriptionflag.Number != 6 || decodedTag_cugsubscriptionflag.Constructed != false {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_cugsubscriptionflag), "cugSubscriptionFlag", "decoding", false)
				}
				if len(rawVal_cugsubscriptionflag) != 0 {
					return qualifyBERError(fmt.Errorf("%w: NULL content length %d", ber.ErrInvalidValue, len(rawVal_cugsubscriptionflag)), "cugSubscriptionFlag", "decoding", false)
				}
				v.CugSubscriptionFlag = &struct{}{}
				if offset < 0 || offset >
					len(content) || n_cugsubscriptionflag < 0 || n_cugsubscriptionflag >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_cugsubscriptionflag
			}
		}
	}
	// Decode subscriberInfo
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 7 {
				ber.MarkPreflightTarget(opts, "subscriberInfo", content[offset:])
				decodedTag_subscriberinfo, n_subscriberinfo, rawVal_subscriberinfo, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "subscriberInfo", "decoding", false)
				}
				if decodedTag_subscriberinfo.Class != tag.ClassContextSpecific || decodedTag_subscriberinfo.Number != 7 || decodedTag_subscriberinfo.Constructed != true {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_subscriberinfo), "subscriberInfo", "decoding", false)
				}
				_ = rawVal_subscriberinfo
				if offset < 0 || offset >
					len(content) || n_subscriberinfo < 0 || n_subscriberinfo >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				reconstructed_subscriberinfo, reconstructionErr_subscriberinfo := ber.EncodeImplicitTagWithClass(tag.ClassUniversal, tag.TagSequence, content[offset:offset+n_subscriberinfo])
				if reconstructionErr_subscriberinfo != nil {
					return qualifyBERError(reconstructionErr_subscriberinfo, "subscriberInfo", "decoding", false)
				}
				var dec_subscriberinfo SubscriberInfo
				if unmErr := dec_subscriberinfo.UnmarshalBER(reconstructed_subscriberinfo, ber.ChildDecodeOptions(opts, "subscriberInfo")...); unmErr != nil {
					return qualifyBERError(unmErr, "subscriberInfo", "decoding", false)
				}
				v.SubscriberInfo = &dec_subscriberinfo
				if offset < 0 || offset >
					len(content) || n_subscriberinfo < 0 || n_subscriberinfo >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_subscriberinfo
			}
		}
	}
	// Decode ss-List
	v.berSsListIndef_ = false
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
				ber.MarkPreflightTarget(opts, "ss-List", content[offset:])
				decodedTag_sslist, n_sslist, rawVal_sslist, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "ss-List", "decoding", false)
				}
				if decodedTag_sslist.Class != tag.ClassContextSpecific || decodedTag_sslist.Number != 1 || decodedTag_sslist.Constructed != true {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_sslist), "ss-List", "decoding", false)
				}
				_ = rawVal_sslist
				if offset < 0 || offset >
					len(content) || n_sslist < 0 || n_sslist > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				reconstructed_sslist, reconstructionErr_sslist := ber.EncodeImplicitTagWithClass(tag.ClassUniversal, tag.TagSequence, content[offset:offset+n_sslist])
				if reconstructionErr_sslist != nil {
					return qualifyBERError(reconstructionErr_sslist, "ss-List", "decoding", false)
				}
				dec_sslist, unmErr := UnmarshalBERSSList(reconstructed_sslist, ber.ParentCollectionSizeDecodeOptions(ber.ChildDecodeOptions(opts, "ss-List"))...)
				if unmErr != nil {
					return qualifyBERError(unmErr, "ss-List", "decoding", false)
				}
				v.SsList = dec_sslist
				{
					_, tagSz_, _ := ber.DecodeTag(content[offset:])
					if offset < 0 || offset >
						len(content) || tagSz_ < 0 || tagSz_ > len(content[offset:]) {
						return fmt.Errorf("invalid BER content window")
					}

					if offset+tagSz_ < len(content) && content[offset+tagSz_] == 0x80 {
						v.berSsListIndef_ = true
					}
				}
				if offset < 0 || offset >
					len(content) || n_sslist < 0 || n_sslist > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_sslist
				if len((v.SsList).Values) < 1 || len((v.SsList).Values) > 30 {
					if constraintErr := checkDecodedLength(opts, s47bb6e_2, "51.5", "ss-List", "SIZE (1..30)", len((v.SsList).Values)); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode basicService
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 5 {
				ber.MarkPreflightTarget(opts, "basicService", content[offset:])
				decodedTag_basicservice, n_basicservice, innerData_basicservice, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "basicService", "decoding", false)
				}
				if decodedTag_basicservice.Class != tag.ClassContextSpecific || decodedTag_basicservice.Number != 5 || decodedTag_basicservice.Constructed != true {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_basicservice), "basicService", "decoding", false)
				}
				_, innerUsed_basicservice, _, innerErr_basicservice := ber.DecodeTLV(innerData_basicservice, opts...)
				if innerErr_basicservice != nil {
					return qualifyBERError(innerErr_basicservice, "basicService", "decoding", false)
				}
				if innerUsed_basicservice != len(innerData_basicservice) {
					return qualifyBERError(ber.ErrExtraData, "basicService", "decoding", false)
				}
				// Decode inner value from explicit tag wrapper
				ber.MarkPreflightTarget(opts, "basicService", innerData_basicservice)
				var dec_basicservice ExtBasicServiceCode
				if unmErr := dec_basicservice.UnmarshalBER(innerData_basicservice, ber.ChildDecodeOptions(opts, "basicService")...); unmErr != nil {
					return qualifyBERError(unmErr, "basicService", "decoding", false)
				}
				v.BasicService = &dec_basicservice
				if offset < 0 || offset >
					len(content) || n_basicservice < 0 || n_basicservice > len(
					content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_basicservice
			}
		}
	}
	// Decode forwardingInterrogationRequired
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4 {
				ber.MarkPreflightTarget(opts, "forwardingInterrogationRequired", content[offset:])
				decodedTag_forwardinginterrogationrequired, n_forwardinginterrogationrequired, rawVal_forwardinginterrogationrequired, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "forwardingInterrogationRequired", "decoding", false)
				}
				if decodedTag_forwardinginterrogationrequired.Class != tag.ClassContextSpecific || decodedTag_forwardinginterrogationrequired.Number != 4 || decodedTag_forwardinginterrogationrequired.Constructed != false {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_forwardinginterrogationrequired), "forwardingInterrogationRequired", "decoding", false)
				}
				if len(rawVal_forwardinginterrogationrequired) != 0 {
					return qualifyBERError(fmt.Errorf("%w: NULL content length %d", ber.ErrInvalidValue, len(rawVal_forwardinginterrogationrequired)), "forwardingInterrogationRequired", "decoding", false)
				}
				v.ForwardingInterrogationRequired = &struct{}{}
				if offset < 0 || offset >
					len(content) || n_forwardinginterrogationrequired < 0 || n_forwardinginterrogationrequired >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_forwardinginterrogationrequired
			}
		}
	}
	// Decode vmsc-Address
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2 {
				ber.MarkPreflightTarget(opts, "vmsc-Address", content[offset:])
				decodedTag_vmscaddress, n_vmscaddress, rawVal_vmscaddress, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "vmsc-Address", "decoding", false)
				}
				if decodedTag_vmscaddress.Class != tag.ClassContextSpecific || decodedTag_vmscaddress.Number != 2 {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_vmscaddress), "vmsc-Address", "decoding", false)
				}
				decVal_vmscaddress, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_vmscaddress.Constructed, rawVal_vmscaddress, opts...)
				if octetErr != nil {
					return qualifyBERError(octetErr, "vmsc-Address", "decoding", false)
				}
				tmp_vmscaddress := ISDNAddressString(decVal_vmscaddress)
				v.VmscAddress = &tmp_vmscaddress
				if offset < 0 || offset >
					len(content) || n_vmscaddress < 0 || n_vmscaddress > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_vmscaddress
				if len(*v.VmscAddress) < 1 || len(*v.VmscAddress) > 9 {
					if constraintErr := checkDecodedLength(opts, s47bb6e_2, "51.5", "vmsc-Address", "SIZE (1..9)", len(*v.VmscAddress)); constraintErr != nil {
						return constraintErr
					}
				}
				if len(*v.VmscAddress) < 1 || len(*v.VmscAddress) > 20 {
					if constraintErr := checkDecodedLength(opts, s47bb6e_2, "51.5", "vmsc-Address", "SIZE (1..20)", len(*v.VmscAddress)); constraintErr != nil {
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
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
				ber.MarkPreflightTarget(opts, "extensionContainer", content[offset:])
				decodedTag_extensioncontainer, n_extensioncontainer, rawVal_extensioncontainer, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "extensionContainer", "decoding", false)
				}
				if decodedTag_extensioncontainer.Class != tag.ClassContextSpecific || decodedTag_extensioncontainer.Number != 0 || decodedTag_extensioncontainer.Constructed != true {
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
				var dec_extensioncontainer ExtensionContainer
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
	// Decode naea-PreferredCI
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 10 {
				ber.MarkPreflightTarget(opts, "naea-PreferredCI", content[offset:])
				decodedTag_naeapreferredci, n_naeapreferredci, rawVal_naeapreferredci, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "naea-PreferredCI", "decoding", false)
				}
				if decodedTag_naeapreferredci.Class != tag.ClassContextSpecific || decodedTag_naeapreferredci.Number != 10 || decodedTag_naeapreferredci.Constructed != true {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_naeapreferredci), "naea-PreferredCI", "decoding", false)
				}
				_ = rawVal_naeapreferredci
				if offset < 0 || offset >
					len(content) || n_naeapreferredci < 0 || n_naeapreferredci >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				reconstructed_naeapreferredci, reconstructionErr_naeapreferredci := ber.EncodeImplicitTagWithClass(tag.ClassUniversal, tag.TagSequence, content[offset:offset+n_naeapreferredci])
				if reconstructionErr_naeapreferredci != nil {
					return qualifyBERError(reconstructionErr_naeapreferredci, "naea-PreferredCI", "decoding", false)
				}
				var dec_naeapreferredci NAEAPreferredCI
				if unmErr := dec_naeapreferredci.UnmarshalBER(reconstructed_naeapreferredci, ber.ChildDecodeOptions(opts, "naea-PreferredCI")...); unmErr != nil {
					return qualifyBERError(unmErr, "naea-PreferredCI", "decoding", false)
				}
				v.NaeaPreferredCI = &dec_naeapreferredci
				if offset < 0 || offset >
					len(content) || n_naeapreferredci < 0 || n_naeapreferredci >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_naeapreferredci
			}
		}
	}
	// Decode ccbs-Indicators
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 11 {
				ber.MarkPreflightTarget(opts, "ccbs-Indicators", content[offset:])
				decodedTag_ccbsindicators, n_ccbsindicators, rawVal_ccbsindicators, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "ccbs-Indicators", "decoding", false)
				}
				if decodedTag_ccbsindicators.Class != tag.ClassContextSpecific || decodedTag_ccbsindicators.Number != 11 || decodedTag_ccbsindicators.Constructed != true {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_ccbsindicators), "ccbs-Indicators", "decoding", false)
				}
				_ = rawVal_ccbsindicators
				if offset < 0 || offset >
					len(content) || n_ccbsindicators < 0 || n_ccbsindicators >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				reconstructed_ccbsindicators, reconstructionErr_ccbsindicators := ber.EncodeImplicitTagWithClass(tag.ClassUniversal, tag.TagSequence, content[offset:offset+n_ccbsindicators])
				if reconstructionErr_ccbsindicators != nil {
					return qualifyBERError(reconstructionErr_ccbsindicators, "ccbs-Indicators", "decoding", false)
				}
				var dec_ccbsindicators CCBSIndicators
				if unmErr := dec_ccbsindicators.UnmarshalBER(reconstructed_ccbsindicators, ber.ChildDecodeOptions(opts, "ccbs-Indicators")...); unmErr != nil {
					return qualifyBERError(unmErr, "ccbs-Indicators", "decoding", false)
				}
				v.CcbsIndicators = &dec_ccbsindicators
				if offset < 0 || offset >
					len(content) || n_ccbsindicators < 0 || n_ccbsindicators >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_ccbsindicators
			}
		}
	}
	// Decode msisdn
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 12 {
				ber.MarkPreflightTarget(opts, "msisdn", content[offset:])
				decodedTag_msisdn, n_msisdn, rawVal_msisdn, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "msisdn", "decoding", false)
				}
				if decodedTag_msisdn.Class != tag.ClassContextSpecific || decodedTag_msisdn.Number != 12 {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_msisdn), "msisdn", "decoding", false)
				}
				decVal_msisdn, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_msisdn.Constructed, rawVal_msisdn, opts...)
				if octetErr != nil {
					return qualifyBERError(octetErr, "msisdn", "decoding", false)
				}
				tmp_msisdn := ISDNAddressString(decVal_msisdn)
				v.Msisdn = &tmp_msisdn
				if offset < 0 || offset >
					len(content) || n_msisdn < 0 || n_msisdn > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_msisdn
				if len(*v.Msisdn) < 1 || len(*v.Msisdn) > 9 {
					if constraintErr := checkDecodedLength(opts, s47bb6e_2, "51.5", "msisdn", "SIZE (1..9)", len(*v.Msisdn)); constraintErr != nil {
						return constraintErr
					}
				}
				if len(*v.Msisdn) < 1 || len(*v.Msisdn) > 20 {
					if constraintErr := checkDecodedLength(opts, s47bb6e_2, "51.5", "msisdn", "SIZE (1..20)", len(*v.Msisdn)); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode numberPortabilityStatus
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 13 {
				ber.MarkPreflightTarget(opts, "numberPortabilityStatus", content[offset:])
				decodedTag_numberportabilitystatus, n_numberportabilitystatus, rawVal_numberportabilitystatus, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "numberPortabilityStatus", "decoding", false)
				}
				if decodedTag_numberportabilitystatus.Class != tag.ClassContextSpecific || decodedTag_numberportabilitystatus.Number != 13 || decodedTag_numberportabilitystatus.Constructed != false {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_numberportabilitystatus), "numberPortabilityStatus", "decoding", false)
				}
				decVal_numberportabilitystatus, intErr := ber.DecodeEnumeratedValue(rawVal_numberportabilitystatus)
				if intErr != nil {
					return qualifyBERError(intErr, "numberPortabilityStatus", "decoding", false)
				}
				tmp_numberportabilitystatus := NumberPortabilityStatus(decVal_numberportabilitystatus)
				v.NumberPortabilityStatus = &tmp_numberportabilitystatus
				if offset < 0 || offset >
					len(content) || n_numberportabilitystatus < 0 || n_numberportabilitystatus >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_numberportabilitystatus
			}
		}
	}
	// Decode istAlertTimer
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 14 {
				ber.MarkPreflightTarget(opts, "istAlertTimer", content[offset:])
				decodedTag_istalerttimer, n_istalerttimer, rawVal_istalerttimer, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "istAlertTimer", "decoding", false)
				}
				if decodedTag_istalerttimer.Class != tag.ClassContextSpecific || decodedTag_istalerttimer.Number != 14 || decodedTag_istalerttimer.Constructed != false {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_istalerttimer), "istAlertTimer", "decoding", false)
				}
				decVal_istalerttimer, intErr := ber.DecodeIntegerValue(rawVal_istalerttimer)
				if intErr != nil {
					return qualifyBERError(intErr, "istAlertTimer", "decoding", false)
				}
				tmp_istalerttimer := ISTAlertTimerValue(decVal_istalerttimer)
				v.IstAlertTimer = &tmp_istalerttimer
				if offset < 0 || offset >
					len(content) || n_istalerttimer < 0 || n_istalerttimer > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_istalerttimer
				if !(int64(*v.IstAlertTimer) >= 15 && int64(*v.IstAlertTimer) <= 255) {
					if constraintErr := checkDecodedValue(opts, s47bb6e_2, "51.4", "istAlertTimer", "(15..255)", ber.ObserveInteger(int64(*v.IstAlertTimer))); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode supportedCamelPhasesInVMSC
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 15 {
				ber.MarkPreflightTarget(opts, "supportedCamelPhasesInVMSC", content[offset:])
				decodedTag_supportedcamelphasesinvmsc, n_supportedcamelphasesinvmsc, rawVal_supportedcamelphasesinvmsc, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "supportedCamelPhasesInVMSC", "decoding", false)
				}
				if decodedTag_supportedcamelphasesinvmsc.Class != tag.ClassContextSpecific || decodedTag_supportedcamelphasesinvmsc.Number != 15 {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_supportedcamelphasesinvmsc), "supportedCamelPhasesInVMSC", "decoding", false)
				}
				bsBytes_supportedcamelphasesinvmsc, bsUnused_supportedcamelphasesinvmsc, bsErr := ber.DecodeImplicitBitStringValue(decodedTag_supportedcamelphasesinvmsc.Constructed, rawVal_supportedcamelphasesinvmsc, opts...)
				if bsErr != nil {
					return qualifyBERError(bsErr, "supportedCamelPhasesInVMSC", "decoding", false)
				}
				bsBitLength_supportedcamelphasesinvmsc, bsLenErr_supportedcamelphasesinvmsc := ber.BitStringBitLength(len(bsBytes_supportedcamelphasesinvmsc), bsUnused_supportedcamelphasesinvmsc)
				if bsLenErr_supportedcamelphasesinvmsc != nil {
					return qualifyBERError(bsLenErr_supportedcamelphasesinvmsc, "supportedCamelPhasesInVMSC", "decoding", false)
				}
				tmp_supportedcamelphasesinvmsc := runtime.BitString{Bytes: bsBytes_supportedcamelphasesinvmsc, BitLength: bsBitLength_supportedcamelphasesinvmsc}
				v.SupportedCamelPhasesInVMSC = &tmp_supportedcamelphasesinvmsc
				if offset < 0 || offset >
					len(content) || n_supportedcamelphasesinvmsc < 0 || n_supportedcamelphasesinvmsc >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_supportedcamelphasesinvmsc
				*v.SupportedCamelPhasesInVMSC = ber.NormalizeNamedBitStringSize(*v.SupportedCamelPhasesInVMSC, []ber.NamedBitSizeSet{{{Min: 1, Max: 16}}}, opts...)
				if (*v.SupportedCamelPhasesInVMSC).BitLength < 1 || (*v.SupportedCamelPhasesInVMSC).BitLength > 16 {
					if constraintErr := checkDecodedLength(opts, s47bb6e_2, "51.5", "supportedCamelPhasesInVMSC", "SIZE (1..16)", (*v.SupportedCamelPhasesInVMSC).BitLength); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode offeredCamel4CSIsInVMSC
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 16 {
				ber.MarkPreflightTarget(opts, "offeredCamel4CSIsInVMSC", content[offset:])
				decodedTag_offeredcamel4csisinvmsc, n_offeredcamel4csisinvmsc, rawVal_offeredcamel4csisinvmsc, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "offeredCamel4CSIsInVMSC", "decoding", false)
				}
				if decodedTag_offeredcamel4csisinvmsc.Class != tag.ClassContextSpecific || decodedTag_offeredcamel4csisinvmsc.Number != 16 {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_offeredcamel4csisinvmsc), "offeredCamel4CSIsInVMSC", "decoding", false)
				}
				bsBytes_offeredcamel4csisinvmsc, bsUnused_offeredcamel4csisinvmsc, bsErr := ber.DecodeImplicitBitStringValue(decodedTag_offeredcamel4csisinvmsc.Constructed, rawVal_offeredcamel4csisinvmsc, opts...)
				if bsErr != nil {
					return qualifyBERError(bsErr, "offeredCamel4CSIsInVMSC", "decoding", false)
				}
				bsBitLength_offeredcamel4csisinvmsc, bsLenErr_offeredcamel4csisinvmsc := ber.BitStringBitLength(len(bsBytes_offeredcamel4csisinvmsc), bsUnused_offeredcamel4csisinvmsc)
				if bsLenErr_offeredcamel4csisinvmsc != nil {
					return qualifyBERError(bsLenErr_offeredcamel4csisinvmsc, "offeredCamel4CSIsInVMSC", "decoding", false)
				}
				tmp_offeredcamel4csisinvmsc := runtime.BitString{Bytes: bsBytes_offeredcamel4csisinvmsc, BitLength: bsBitLength_offeredcamel4csisinvmsc}
				v.OfferedCamel4CSIsInVMSC = &tmp_offeredcamel4csisinvmsc
				if offset < 0 || offset >
					len(content) || n_offeredcamel4csisinvmsc < 0 || n_offeredcamel4csisinvmsc >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_offeredcamel4csisinvmsc
				*v.OfferedCamel4CSIsInVMSC = ber.NormalizeNamedBitStringSize(*v.OfferedCamel4CSIsInVMSC, []ber.NamedBitSizeSet{{{Min: 7, Max: 16}}}, opts...)
				if (*v.OfferedCamel4CSIsInVMSC).BitLength < 7 || (*v.OfferedCamel4CSIsInVMSC).BitLength > 16 {
					if constraintErr := checkDecodedLength(opts, s47bb6e_2, "51.5", "offeredCamel4CSIsInVMSC", "SIZE (7..16)", (*v.OfferedCamel4CSIsInVMSC).BitLength); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode routingInfo2
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 17 {
				ber.MarkPreflightTarget(opts, "routingInfo2", content[offset:])
				decodedTag_routinginfo2, n_routinginfo2, innerData_routinginfo2, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "routingInfo2", "decoding", false)
				}
				if decodedTag_routinginfo2.Class != tag.ClassContextSpecific || decodedTag_routinginfo2.Number != 17 || decodedTag_routinginfo2.Constructed != true {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_routinginfo2), "routingInfo2", "decoding", false)
				}
				_, innerUsed_routinginfo2, _, innerErr_routinginfo2 := ber.DecodeTLV(innerData_routinginfo2, opts...)
				if innerErr_routinginfo2 != nil {
					return qualifyBERError(innerErr_routinginfo2, "routingInfo2", "decoding", false)
				}
				if innerUsed_routinginfo2 != len(innerData_routinginfo2) {
					return qualifyBERError(ber.ErrExtraData, "routingInfo2", "decoding", false)
				}
				// Decode inner value from explicit tag wrapper
				ber.MarkPreflightTarget(opts, "routingInfo2", innerData_routinginfo2)
				var dec_routinginfo2 RoutingInfo
				if unmErr := dec_routinginfo2.UnmarshalBER(innerData_routinginfo2, ber.ChildDecodeOptions(opts, "routingInfo2")...); unmErr != nil {
					return qualifyBERError(unmErr, "routingInfo2", "decoding", false)
				}
				v.RoutingInfo2 = &dec_routinginfo2
				if offset < 0 || offset >
					len(content) || n_routinginfo2 < 0 || n_routinginfo2 > len(
					content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_routinginfo2
			}
		}
	}
	// Decode ss-List2
	v.berSsList2Indef_ = false
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 18 {
				ber.MarkPreflightTarget(opts, "ss-List2", content[offset:])
				decodedTag_sslist2, n_sslist2, rawVal_sslist2, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "ss-List2", "decoding", false)
				}
				if decodedTag_sslist2.Class != tag.ClassContextSpecific || decodedTag_sslist2.Number != 18 || decodedTag_sslist2.Constructed != true {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_sslist2), "ss-List2", "decoding", false)
				}
				_ = rawVal_sslist2
				if offset < 0 || offset >
					len(content) || n_sslist2 < 0 || n_sslist2 > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				reconstructed_sslist2, reconstructionErr_sslist2 := ber.EncodeImplicitTagWithClass(tag.ClassUniversal, tag.TagSequence, content[offset:offset+n_sslist2])
				if reconstructionErr_sslist2 != nil {
					return qualifyBERError(reconstructionErr_sslist2, "ss-List2", "decoding", false)
				}
				dec_sslist2, unmErr := UnmarshalBERSSList(reconstructed_sslist2, ber.ParentCollectionSizeDecodeOptions(ber.ChildDecodeOptions(opts, "ss-List2"))...)
				if unmErr != nil {
					return qualifyBERError(unmErr, "ss-List2", "decoding", false)
				}
				v.SsList2 = dec_sslist2
				{
					_, tagSz_, _ := ber.DecodeTag(content[offset:])
					if offset < 0 || offset >
						len(content) || tagSz_ < 0 || tagSz_ > len(content[offset:]) {
						return fmt.Errorf("invalid BER content window")
					}

					if offset+tagSz_ < len(content) && content[offset+tagSz_] == 0x80 {
						v.berSsList2Indef_ = true
					}
				}
				if offset < 0 || offset >
					len(content) || n_sslist2 < 0 || n_sslist2 > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_sslist2
				if len((v.SsList2).Values) < 1 || len((v.SsList2).Values) > 30 {
					if constraintErr := checkDecodedLength(opts, s47bb6e_2, "51.5", "ss-List2", "SIZE (1..30)", len((v.SsList2).Values)); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode basicService2
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 19 {
				ber.MarkPreflightTarget(opts, "basicService2", content[offset:])
				decodedTag_basicservice2, n_basicservice2, innerData_basicservice2, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "basicService2", "decoding", false)
				}
				if decodedTag_basicservice2.Class != tag.ClassContextSpecific || decodedTag_basicservice2.Number != 19 || decodedTag_basicservice2.Constructed != true {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_basicservice2), "basicService2", "decoding", false)
				}
				_, innerUsed_basicservice2, _, innerErr_basicservice2 := ber.DecodeTLV(innerData_basicservice2, opts...)
				if innerErr_basicservice2 != nil {
					return qualifyBERError(innerErr_basicservice2, "basicService2", "decoding", false)
				}
				if innerUsed_basicservice2 != len(innerData_basicservice2) {
					return qualifyBERError(ber.ErrExtraData, "basicService2", "decoding", false)
				}
				// Decode inner value from explicit tag wrapper
				ber.MarkPreflightTarget(opts, "basicService2", innerData_basicservice2)
				var dec_basicservice2 ExtBasicServiceCode
				if unmErr := dec_basicservice2.UnmarshalBER(innerData_basicservice2, ber.ChildDecodeOptions(opts, "basicService2")...); unmErr != nil {
					return qualifyBERError(unmErr, "basicService2", "decoding", false)
				}
				v.BasicService2 = &dec_basicservice2
				if offset < 0 || offset >
					len(content) || n_basicservice2 < 0 || n_basicservice2 > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_basicservice2
			}
		}
	}
	// Decode allowedServices
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 20 {
				ber.MarkPreflightTarget(opts, "allowedServices", content[offset:])
				decodedTag_allowedservices, n_allowedservices, rawVal_allowedservices, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "allowedServices", "decoding", false)
				}
				if decodedTag_allowedservices.Class != tag.ClassContextSpecific || decodedTag_allowedservices.Number != 20 {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_allowedservices), "allowedServices", "decoding", false)
				}
				bsBytes_allowedservices, bsUnused_allowedservices, bsErr := ber.DecodeImplicitBitStringValue(decodedTag_allowedservices.Constructed, rawVal_allowedservices, opts...)
				if bsErr != nil {
					return qualifyBERError(bsErr, "allowedServices", "decoding", false)
				}
				bsBitLength_allowedservices, bsLenErr_allowedservices := ber.BitStringBitLength(len(bsBytes_allowedservices), bsUnused_allowedservices)
				if bsLenErr_allowedservices != nil {
					return qualifyBERError(bsLenErr_allowedservices, "allowedServices", "decoding", false)
				}
				tmp_allowedservices := runtime.BitString{Bytes: bsBytes_allowedservices, BitLength: bsBitLength_allowedservices}
				v.AllowedServices = &tmp_allowedservices
				if offset < 0 || offset >
					len(content) || n_allowedservices < 0 || n_allowedservices >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_allowedservices
				*v.AllowedServices = ber.NormalizeNamedBitStringSize(*v.AllowedServices, []ber.NamedBitSizeSet{{{Min: 2, Max: 8}}}, opts...)
				if (*v.AllowedServices).BitLength < 2 || (*v.AllowedServices).BitLength > 8 {
					if constraintErr := checkDecodedLength(opts, s47bb6e_2, "51.5", "allowedServices", "SIZE (2..8)", (*v.AllowedServices).BitLength); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode unavailabilityCause
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 21 {
				ber.MarkPreflightTarget(opts, "unavailabilityCause", content[offset:])
				decodedTag_unavailabilitycause, n_unavailabilitycause, rawVal_unavailabilitycause, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "unavailabilityCause", "decoding", false)
				}
				if decodedTag_unavailabilitycause.Class != tag.ClassContextSpecific || decodedTag_unavailabilitycause.Number != 21 || decodedTag_unavailabilitycause.Constructed != false {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_unavailabilitycause), "unavailabilityCause", "decoding", false)
				}
				decVal_unavailabilitycause, intErr := ber.DecodeEnumeratedValue(rawVal_unavailabilitycause)
				if intErr != nil {
					return qualifyBERError(intErr, "unavailabilityCause", "decoding", false)
				}
				tmp_unavailabilitycause := UnavailabilityCause(decVal_unavailabilitycause)
				v.UnavailabilityCause = &tmp_unavailabilitycause
				if offset < 0 || offset >
					len(content) || n_unavailabilitycause < 0 || n_unavailabilitycause >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_unavailabilitycause
			}
		}
	}
	// Decode releaseResourcesSupported
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 22 {
				ber.MarkPreflightTarget(opts, "releaseResourcesSupported", content[offset:])
				decodedTag_releaseresourcessupported, n_releaseresourcessupported, rawVal_releaseresourcessupported, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "releaseResourcesSupported", "decoding", false)
				}
				if decodedTag_releaseresourcessupported.Class != tag.ClassContextSpecific || decodedTag_releaseresourcessupported.Number != 22 || decodedTag_releaseresourcessupported.Constructed != false {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_releaseresourcessupported), "releaseResourcesSupported", "decoding", false)
				}
				if len(rawVal_releaseresourcessupported) != 0 {
					return qualifyBERError(fmt.Errorf("%w: NULL content length %d", ber.ErrInvalidValue, len(rawVal_releaseresourcessupported)), "releaseResourcesSupported", "decoding", false)
				}
				v.ReleaseResourcesSupported = &struct{}{}
				if offset < 0 || offset >
					len(content) || n_releaseresourcessupported < 0 || n_releaseresourcessupported >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_releaseresourcessupported
			}
		}
	}
	// Decode gsm-BearerCapability
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 23 {
				ber.MarkPreflightTarget(opts, "gsm-BearerCapability", content[offset:])
				decodedTag_gsmbearercapability, n_gsmbearercapability, rawVal_gsmbearercapability, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "gsm-BearerCapability", "decoding", false)
				}
				if decodedTag_gsmbearercapability.Class != tag.ClassContextSpecific || decodedTag_gsmbearercapability.Number != 23 || decodedTag_gsmbearercapability.Constructed != true {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_gsmbearercapability), "gsm-BearerCapability", "decoding", false)
				}
				_ = rawVal_gsmbearercapability
				if offset < 0 || offset >
					len(content) || n_gsmbearercapability < 0 || n_gsmbearercapability >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				reconstructed_gsmbearercapability, reconstructionErr_gsmbearercapability := ber.EncodeImplicitTagWithClass(tag.ClassUniversal, tag.TagSequence, content[offset:offset+n_gsmbearercapability])
				if reconstructionErr_gsmbearercapability != nil {
					return qualifyBERError(reconstructionErr_gsmbearercapability, "gsm-BearerCapability", "decoding", false)
				}
				var dec_gsmbearercapability ExternalSignalInfo
				if unmErr := dec_gsmbearercapability.UnmarshalBER(reconstructed_gsmbearercapability, ber.ChildDecodeOptions(opts, "gsm-BearerCapability")...); unmErr != nil {
					return qualifyBERError(unmErr, "gsm-BearerCapability", "decoding", false)
				}
				v.GsmBearerCapability = &dec_gsmbearercapability
				if offset < 0 || offset >
					len(content) || n_gsmbearercapability < 0 || n_gsmbearercapability >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_gsmbearercapability
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		peekTag, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:], opts...)
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "SendRoutingInfoRes", Cause: extErr_}
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: the first unknown addition must differ from trailing OPTIONAL/DEFAULT tags.
		if len(v.ExtData_) == 0 && ((peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 23) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 22) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 21) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 20) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 19) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 18) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 17) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 16) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 15) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 14) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 13) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 12) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 11) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 10) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 5) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 7) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 6) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3) || (peekTag.Class == tag.ClassUniversal && peekTag.Number == 4) || (peekTag.Class == tag.ClassUniversal && peekTag.Number == 16) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 8) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 9)) {
			if !ber.ToleranceEnabled(opts) {
				return &ber.DecodeError{Offset: offset, TypeName: "SendRoutingInfoRes", Cause: fmt.Errorf("%w: repeated or out-of-order SEQUENCE component tag %s", ber.ErrInvalidTag, peekTag)}
			}
			if orderErr_ := ber.CheckDecodedValue(ber.DecodeRule(opts, s47bb6e_2, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), fmt.Sprintf("ExtData_[%d]", len(v.ExtData_)), "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); orderErr_ != nil {
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

// MarshalBER encodes CCBSIndicators to BER format.
func (v *CCBSIndicators) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {

	if v == nil {
		return nil, fmt.Errorf("%w: CCBSIndicators receiver is nil", ber.ErrInvalidValue)
	}
	return marshalFramedValue(v, v.berReplayNode_, opts, (*CCBSIndicators).MarshalBER, (*CCBSIndicators).marshalBER, 3)

}
func (v *CCBSIndicators) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if v.CcbsPossible != nil {
		enc_ccbspossible := ber.EncodeNull()
		retagged_enc_ccbspossible, tagErr_enc_ccbspossible := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_ccbspossible)
		if tagErr_enc_ccbspossible != nil {
			return nil, qualifyBERError(tagErr_enc_ccbspossible, "ccbs-Possible", "encoding", false)
		}
		enc_ccbspossible = retagged_enc_ccbspossible
		children = append(children, enc_ccbspossible...)
	}
	if v.KeepCCBSCallIndicator != nil {
		enc_keepccbscallindicator := ber.EncodeNull()
		retagged_enc_keepccbscallindicator, tagErr_enc_keepccbscallindicator := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_keepccbscallindicator)
		if tagErr_enc_keepccbscallindicator != nil {
			return nil, qualifyBERError(tagErr_enc_keepccbscallindicator, "keepCCBS-CallIndicator", "encoding", false)
		}
		enc_keepccbscallindicator = retagged_enc_keepccbscallindicator
		children = append(children, enc_keepccbscallindicator...)
	}
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
	base_ := -1
	for i, ext := range v.ExtData_ {
		if err := checkOpaqueAddition(ext, opts, s47bb6e_3, children, i, &base_); err != nil {
			return nil, opaqueExtensionError(err, i)
		}
		peekTag, n, _, extErr := ber.DecodeEncodedTLV(ext)
		if extErr != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, extErr)
		}
		if n != len(ext) {
			return nil, fmt.Errorf("encoding extension %d: %w", i, ber.ErrExtraData)
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: only the first addition is restricted.
		if i == 0 && ((peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0)) {
			if constraintErr := ber.CheckEncodedValue(ber.EncodeRule(opts, s47bb6e_3, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
				return nil, constraintErr
			}
		}
		children = append(children, ext...)
	}
	ber.RecordGeneratedBERContainer(opts, children)
	return ber.EncodeSequence(children)
}
func (v *CCBSIndicators) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// MarshalDER encodes CCBSIndicators to DER format.
// Opaque descendants pass generic DER checks; foreign schema rules need a typed binding.
func (v *CCBSIndicators) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: CCBSIndicators receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if v.CcbsPossible != nil {
		enc_ccbspossible := ber.EncodeNull()
		retagged_enc_ccbspossible, tagErr_enc_ccbspossible := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_ccbspossible)
		if tagErr_enc_ccbspossible != nil {
			return nil, qualifyBERError(tagErr_enc_ccbspossible, "ccbs-Possible", "encoding", true)
		}
		enc_ccbspossible = retagged_enc_ccbspossible
		children = append(children, enc_ccbspossible...)
	}
	if v.KeepCCBSCallIndicator != nil {
		enc_keepccbscallindicator := ber.EncodeNull()
		retagged_enc_keepccbscallindicator, tagErr_enc_keepccbscallindicator := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_keepccbscallindicator)
		if tagErr_enc_keepccbscallindicator != nil {
			return nil, qualifyBERError(tagErr_enc_keepccbscallindicator, "keepCCBS-CallIndicator", "encoding", true)
		}
		enc_keepccbscallindicator = retagged_enc_keepccbscallindicator
		children = append(children, enc_keepccbscallindicator...)
	}
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
			return nil, invalidDERAddition(ext, s47bb6e_3, children, i)
		}
		peekTag, _, _, extErr := ber.DecodeEncodedTLV(ext)
		if extErr != nil {
			return nil, extErr
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: only the first addition is restricted.
		if i == 0 && ((peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0)) {
			if constraintErr := ber.CheckEncodedValue(ber.EncodeRule(nil, s47bb6e_3, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
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
		return nil, fmt.Errorf("%s: %w", "encoding CCBSIndicators as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}
func (v *CCBSIndicators) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	encoded, err := v.MarshalDER()
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBER decodes CCBSIndicators from BER/DER format.
func (destination *CCBSIndicators) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if destination == nil {
		return fmt.Errorf("%w: CCBSIndicators destination is nil", ber.ErrInvalidValue)
	}
	v := new(CCBSIndicators)

	defer publishDecodedValue(destination, v, &returnErr)

	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	preparedData, preparedOptions, prepareErr := prepareCompositeBER(data, opts, s47bb6e_3, "child", (*CCBSIndicators).UnmarshalBER)
	if prepareErr != nil {
		return prepareErr
	}
	data, opts = preparedData, preparedOptions

	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
	*v = CCBSIndicators{}
	defer func() {
		if returnErr == nil {
			returnErr = completeValueBER(data,
				opts, v, &v.berReplayNode_, (*CCBSIndicators).MarshalBER)
		}

	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("%s: %w", "decoding CCBSIndicators SEQUENCE", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "CCBSIndicators", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode ccbs-Possible
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
				ber.MarkPreflightTarget(opts, "ccbs-Possible", content[offset:])
				decodedTag_ccbspossible, n_ccbspossible, rawVal_ccbspossible, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "ccbs-Possible", "decoding", false)
				}
				if decodedTag_ccbspossible.Class != tag.ClassContextSpecific || decodedTag_ccbspossible.Number != 0 || decodedTag_ccbspossible.Constructed != false {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_ccbspossible), "ccbs-Possible", "decoding", false)
				}
				if len(rawVal_ccbspossible) != 0 {
					return qualifyBERError(fmt.Errorf("%w: NULL content length %d", ber.ErrInvalidValue, len(rawVal_ccbspossible)), "ccbs-Possible", "decoding", false)
				}
				v.CcbsPossible = &struct{}{}
				if offset > len(content) || n_ccbspossible < 0 || n_ccbspossible > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_ccbspossible
			}
		}
	}
	// Decode keepCCBS-CallIndicator
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
				ber.MarkPreflightTarget(opts, "keepCCBS-CallIndicator", content[offset:])
				decodedTag_keepccbscallindicator, n_keepccbscallindicator, rawVal_keepccbscallindicator, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "keepCCBS-CallIndicator", "decoding", false)
				}
				if decodedTag_keepccbscallindicator.Class != tag.ClassContextSpecific || decodedTag_keepccbscallindicator.Number != 1 || decodedTag_keepccbscallindicator.Constructed != false {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_keepccbscallindicator), "keepCCBS-CallIndicator", "decoding", false)
				}
				if len(rawVal_keepccbscallindicator) != 0 {
					return qualifyBERError(fmt.Errorf("%w: NULL content length %d", ber.ErrInvalidValue, len(rawVal_keepccbscallindicator)), "keepCCBS-CallIndicator", "decoding", false)
				}
				v.KeepCCBSCallIndicator = &struct{}{}
				if offset < 0 || offset >
					len(content) || n_keepccbscallindicator < 0 || n_keepccbscallindicator >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_keepccbscallindicator
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
				var dec_extensioncontainer ExtensionContainer
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
			return &ber.DecodeError{Offset: offset, TypeName: "CCBSIndicators", Cause: extErr_}
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: the first unknown addition must differ from trailing OPTIONAL/DEFAULT tags.
		if len(v.ExtData_) == 0 && ((peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0)) {
			if !ber.ToleranceEnabled(opts) {
				return &ber.DecodeError{Offset: offset, TypeName: "CCBSIndicators", Cause: fmt.Errorf("%w: repeated or out-of-order SEQUENCE component tag %s", ber.ErrInvalidTag, peekTag)}
			}
			if orderErr_ := ber.CheckDecodedValue(ber.DecodeRule(opts, s47bb6e_3, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), fmt.Sprintf("ExtData_[%d]", len(v.ExtData_)), "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); orderErr_ != nil {
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

// MarshalBER encodes RoutingInfo to BER format.
func (v *RoutingInfo) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {

	if v == nil {
		return nil, fmt.Errorf("%w: RoutingInfo receiver is nil", ber.ErrInvalidValue)
	}
	return marshalFramedValue(v, v.berReplayNode_, opts, (*RoutingInfo).MarshalBER, (*RoutingInfo).marshalBER, 3)

}
func (v *RoutingInfo) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}
func (v *RoutingInfo) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	switch v.Choice {
	case RoutingInfoChoiceRoamingNumber:
		if v.RoamingNumber == nil {
			return nil, fmt.Errorf("%w: choice RoutingInfo: roamingNumber is nil", ber.ErrInvalidValue)
		}
		enc_0, encodeErr_enc_0 := ber.EncodeOctetString([]byte(*v.RoamingNumber))
		if encodeErr_enc_0 != nil {
			return nil, qualifyBERError(encodeErr_enc_0, "roamingNumber", "encoding", false)
		}
		if len(*v.RoamingNumber) < 1 || len(*v.RoamingNumber) > 9 {
			if constraintErr := checkEncodedLength(opts, s47bb6e_4, "51.5", "roamingNumber", "SIZE (1..9)", len(*v.RoamingNumber)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		if len(*v.RoamingNumber) < 1 || len(*v.RoamingNumber) > 20 {
			if constraintErr := checkEncodedLength(opts, s47bb6e_4, "51.5", "roamingNumber", "SIZE (1..20)", len(*v.RoamingNumber)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		return enc_0, nil
	case RoutingInfoChoiceForwardingData:
		if v.ForwardingData == nil {
			return nil, fmt.Errorf("%w: choice RoutingInfo: forwardingData is nil", ber.ErrInvalidValue)
		}
		enc_1, err := v.ForwardingData.MarshalBER(ber.ChildEncodeOptions(opts, "forwardingData")...)
		if err != nil {
			return nil, qualifyBERError(err, "forwardingData", "encoding", false)
		}
		return enc_1, nil
	default:
		return nil, fmt.Errorf("unknown choice %d for RoutingInfo", v.Choice)
	}
}

// MarshalDER encodes RoutingInfo to DER format.
// Opaque descendants pass generic DER checks; foreign schema rules need a typed binding.
func (v *RoutingInfo) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: RoutingInfo receiver is nil", ber.ErrInvalidValue)
	}
	switch v.Choice {
	case RoutingInfoChoiceForwardingData:
		if v.ForwardingData == nil {
			return nil, fmt.Errorf("%w: choice RoutingInfo: forwardingData is nil", ber.ErrInvalidValue)
		}
		enc_der_1, err := v.ForwardingData.MarshalDER()
		if err != nil {
			return nil, qualifyBERError(err, "forwardingData", "encoding", true)
		}
		if derErr := ber.ValidateDEREncodedElement(enc_der_1); derErr != nil {
			return nil, qualifyBERError(derErr, "forwardingData", "encoding", true)
		}
		return enc_der_1, nil
	}
	encoded, err := v.marshalBER()
	if err != nil {
		return nil, err
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		switch v.Choice {
		case RoutingInfoChoiceRoamingNumber:
			return nil, qualifyBERError(err, "roamingNumber", "encoding", true)
		case RoutingInfoChoiceForwardingData:
			return nil, qualifyBERError(err, "forwardingData", "encoding", true)
		}
		return nil, fmt.Errorf("%s: %w", "encoding RoutingInfo as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}

func (v *RoutingInfo) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	encoded, err := v.MarshalDER()
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBER decodes RoutingInfo from BER/DER format.
func (destination *RoutingInfo) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if destination == nil {
		return fmt.Errorf("%w: RoutingInfo destination is nil", ber.ErrInvalidValue)
	}
	v := new(RoutingInfo)
	defer publishDecodedValue(destination, v, &returnErr)

	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	preparedData, preparedOptions, prepareErr := prepareCompositeBER(data, opts, s47bb6e_4, "child", (*RoutingInfo).UnmarshalBER)
	if prepareErr != nil {
		return prepareErr
	}
	data, opts = preparedData, preparedOptions
	defer func() {
		if returnErr == nil {
			returnErr = completeValueBER(data,
				opts, v, &v.berReplayNode_, (*RoutingInfo).MarshalBER)
		}

	}()

	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
	*v = RoutingInfo{}
	if len(data) == 0 {
		return fmt.Errorf("empty data for RoutingInfo CHOICE")
	}
	choiceData := data
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for RoutingInfo: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData, opts...)
	if tlvErr != nil {
		return fmt.Errorf("%s: %w", "decoding RoutingInfo CHOICE", qualifyBERError(tlvErr, "", "decoding", false))
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "RoutingInfo", Cause: ber.ErrExtraData}
	}

	if (peekTag.Class == tag.ClassUniversal && peekTag.Number == 16) && peekTag.Constructed != true {
		return qualifyBERError(fmt.Errorf("%w: invalid primitive/constructed form for tag %s", ber.ErrInvalidTag, peekTag), "RoutingInfo.forwardingData", "decoding", false)
	}
	if peekTag.Class == tag.ClassUniversal && peekTag.Number == 4 {
		v.Choice = RoutingInfoChoiceRoamingNumber
		ber.MarkPreflightTarget(opts, "roamingNumber", choiceData)
		decVal, _, osErr := ber.DecodeOctetString(choiceData, opts...)
		if osErr != nil {
			return qualifyBERError(osErr, "roamingNumber", "decoding", false)
		}
		tmp := ISDNAddressString(decVal)
		v.RoamingNumber = &tmp
		if len(*v.RoamingNumber) < 1 || len(*v.RoamingNumber) > 9 {
			if constraintErr := checkDecodedLength(opts, s47bb6e_4, "51.5", "roamingNumber", "SIZE (1..9)", len(*v.RoamingNumber)); constraintErr != nil {
				return constraintErr
			}
		}
		if len(*v.RoamingNumber) < 1 || len(*v.RoamingNumber) > 20 {
			if constraintErr := checkDecodedLength(opts, s47bb6e_4, "51.5", "roamingNumber", "SIZE (1..20)", len(*v.RoamingNumber)); constraintErr != nil {
				return constraintErr
			}
		}
	} else if peekTag.Class == tag.ClassUniversal && peekTag.Number == 16 && peekTag.Constructed == true {
		v.Choice = RoutingInfoChoiceForwardingData
		ber.MarkPreflightTarget(opts, "forwardingData", choiceData)
		var dec ForwardingData
		if unmErr := dec.UnmarshalBER(choiceData, ber.ChildDecodeOptions(opts, "forwardingData")...); unmErr != nil {
			return qualifyBERError(unmErr, "forwardingData", "decoding", false)
		}
		v.ForwardingData = &dec
	} else {
		return fmt.Errorf("unknown tag %s for RoutingInfo CHOICE", peekTag)
	}
	return nil
}

// MarshalBER encodes ForwardingData to BER format.
func (v *ForwardingData) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {

	if v == nil {
		return nil, fmt.Errorf("%w: ForwardingData receiver is nil", ber.ErrInvalidValue)
	}
	return marshalFramedValue(v, v.berReplayNode_, opts, (*ForwardingData).MarshalBER, (*ForwardingData).marshalBER, 3)

}
func (v *ForwardingData) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if v.ForwardedToNumber != nil {
		if len(*v.ForwardedToNumber) < 1 || len(*v.ForwardedToNumber) > 9 {
			if constraintErr := checkEncodedLength(opts, s47bb6e_5, "51.5", "forwardedToNumber", "SIZE (1..9)", len(*v.ForwardedToNumber)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		if len(*v.ForwardedToNumber) < 1 || len(*v.ForwardedToNumber) > 20 {
			if constraintErr := checkEncodedLength(opts, s47bb6e_5, "51.5", "forwardedToNumber", "SIZE (1..20)", len(*v.ForwardedToNumber)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_forwardedtonumber, encodeErr_enc_forwardedtonumber := ber.EncodeOctetString([]byte(*v.ForwardedToNumber))
		if encodeErr_enc_forwardedtonumber != nil {
			return nil, qualifyBERError(encodeErr_enc_forwardedtonumber, "forwardedToNumber", "encoding", false)
		}
		retagged_enc_forwardedtonumber, tagErr_enc_forwardedtonumber := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 5, enc_forwardedtonumber)
		if tagErr_enc_forwardedtonumber != nil {
			return nil, qualifyBERError(tagErr_enc_forwardedtonumber, "forwardedToNumber", "encoding", false)
		}
		enc_forwardedtonumber = retagged_enc_forwardedtonumber
		children = append(children, enc_forwardedtonumber...)
	}
	if v.ForwardedToSubaddress != nil {
		if len(*v.ForwardedToSubaddress) < 1 || len(*v.ForwardedToSubaddress) > 21 {
			if constraintErr := checkEncodedLength(opts, s47bb6e_5, "51.5", "forwardedToSubaddress", "SIZE (1..21)", len(*v.ForwardedToSubaddress)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_forwardedtosubaddress, encodeErr_enc_forwardedtosubaddress := ber.EncodeOctetString([]byte(*v.ForwardedToSubaddress))
		if encodeErr_enc_forwardedtosubaddress != nil {
			return nil, qualifyBERError(encodeErr_enc_forwardedtosubaddress, "forwardedToSubaddress", "encoding", false)
		}
		retagged_enc_forwardedtosubaddress, tagErr_enc_forwardedtosubaddress := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, enc_forwardedtosubaddress)
		if tagErr_enc_forwardedtosubaddress != nil {
			return nil, qualifyBERError(tagErr_enc_forwardedtosubaddress, "forwardedToSubaddress", "encoding", false)
		}
		enc_forwardedtosubaddress = retagged_enc_forwardedtosubaddress
		children = append(children, enc_forwardedtosubaddress...)
	}
	if v.ForwardingOptions != nil {
		if len(*v.ForwardingOptions) < 1 || len(*v.ForwardingOptions) > 1 {
			if constraintErr := checkEncodedLength(opts, s47bb6e_5, "51.5", "forwardingOptions", "SIZE (1)", len(*v.ForwardingOptions)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_forwardingoptions, encodeErr_enc_forwardingoptions := ber.EncodeOctetString([]byte(*v.ForwardingOptions))
		if encodeErr_enc_forwardingoptions != nil {
			return nil, qualifyBERError(encodeErr_enc_forwardingoptions, "forwardingOptions", "encoding", false)
		}
		retagged_enc_forwardingoptions, tagErr_enc_forwardingoptions := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 6, enc_forwardingoptions)
		if tagErr_enc_forwardingoptions != nil {
			return nil, qualifyBERError(tagErr_enc_forwardingoptions, "forwardingOptions", "encoding", false)
		}
		enc_forwardingoptions = retagged_enc_forwardingoptions
		children = append(children, enc_forwardingoptions...)
	}
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalBER(ber.ChildEncodeOptions(opts, "extensionContainer")...)
		if err != nil {
			return nil, qualifyBERError(err, "extensionContainer", "encoding", false)
		}
		retagged_enc_extensioncontainer, tagErr_enc_extensioncontainer := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 7, enc_extensioncontainer)
		if tagErr_enc_extensioncontainer != nil {
			return nil, qualifyBERError(tagErr_enc_extensioncontainer, "extensionContainer", "encoding", false)
		}
		enc_extensioncontainer = retagged_enc_extensioncontainer
		ber.RecordGeneratedBERChildPlacement(opts, len(children), enc_extensioncontainer)
		children = append(children, enc_extensioncontainer...)
	}
	if v.LongForwardedToNumber != nil {
		if len(*v.LongForwardedToNumber) < 1 || len(*v.LongForwardedToNumber) > 15 {
			if constraintErr := checkEncodedLength(opts, s47bb6e_5, "51.5", "longForwardedToNumber", "SIZE (1..15)", len(*v.LongForwardedToNumber)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		if len(*v.LongForwardedToNumber) < 1 || len(*v.LongForwardedToNumber) > 20 {
			if constraintErr := checkEncodedLength(opts, s47bb6e_5, "51.5", "longForwardedToNumber", "SIZE (1..20)", len(*v.LongForwardedToNumber)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_longforwardedtonumber, encodeErr_enc_longforwardedtonumber := ber.EncodeOctetString([]byte(*v.LongForwardedToNumber))
		if encodeErr_enc_longforwardedtonumber != nil {
			return nil, qualifyBERError(encodeErr_enc_longforwardedtonumber, "longForwardedToNumber", "encoding", false)
		}
		retagged_enc_longforwardedtonumber, tagErr_enc_longforwardedtonumber := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 8, enc_longforwardedtonumber)
		if tagErr_enc_longforwardedtonumber != nil {
			return nil, qualifyBERError(tagErr_enc_longforwardedtonumber, "longForwardedToNumber", "encoding", false)
		}
		enc_longforwardedtonumber = retagged_enc_longforwardedtonumber
		children = append(children, enc_longforwardedtonumber...)
	}
	base_ := -1
	for i, ext := range v.ExtData_ {
		if err := checkOpaqueAddition(ext, opts, s47bb6e_5, children, i, &base_); err != nil {
			return nil, opaqueExtensionError(err, i)
		}
		peekTag, n, _, extErr := ber.DecodeEncodedTLV(ext)
		if extErr != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, extErr)
		}
		if n != len(ext) {
			return nil, fmt.Errorf("encoding extension %d: %w", i, ber.ErrExtraData)
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: only the first addition is restricted.
		if i == 0 && ((peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 8) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 7) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 6) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 5)) {
			if constraintErr := ber.CheckEncodedValue(ber.EncodeRule(opts, s47bb6e_5, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
				return nil, constraintErr
			}
		}
		children = append(children, ext...)
	}
	ber.RecordGeneratedBERContainer(opts, children)
	return ber.EncodeSequence(children)
}
func (v *ForwardingData) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// MarshalDER encodes ForwardingData to DER format.
// Opaque descendants pass generic DER checks; foreign schema rules need a typed binding.
func (v *ForwardingData) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: ForwardingData receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if v.ForwardedToNumber != nil {
		if len(*v.ForwardedToNumber) < 1 || len(*v.ForwardedToNumber) > 9 {
			if constraintErr := checkEncodedLength(nil, s47bb6e_5, "51.5", "forwardedToNumber", "SIZE (1..9)", len(*v.ForwardedToNumber)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		if len(*v.ForwardedToNumber) < 1 || len(*v.ForwardedToNumber) > 20 {
			if constraintErr := checkEncodedLength(nil, s47bb6e_5, "51.5", "forwardedToNumber", "SIZE (1..20)", len(*v.ForwardedToNumber)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_forwardedtonumber, encodeErr_enc_forwardedtonumber := ber.EncodeOctetString([]byte(*v.ForwardedToNumber))
		if encodeErr_enc_forwardedtonumber != nil {
			return nil, qualifyBERError(encodeErr_enc_forwardedtonumber, "forwardedToNumber", "encoding", true)
		}
		retagged_enc_forwardedtonumber, tagErr_enc_forwardedtonumber := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 5, enc_forwardedtonumber)
		if tagErr_enc_forwardedtonumber != nil {
			return nil, qualifyBERError(tagErr_enc_forwardedtonumber, "forwardedToNumber", "encoding", true)
		}
		enc_forwardedtonumber = retagged_enc_forwardedtonumber
		children = append(children, enc_forwardedtonumber...)
	}
	if v.ForwardedToSubaddress != nil {
		if len(*v.ForwardedToSubaddress) < 1 || len(*v.ForwardedToSubaddress) > 21 {
			if constraintErr := checkEncodedLength(nil, s47bb6e_5, "51.5", "forwardedToSubaddress", "SIZE (1..21)", len(*v.ForwardedToSubaddress)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_forwardedtosubaddress, encodeErr_enc_forwardedtosubaddress := ber.EncodeOctetString([]byte(*v.ForwardedToSubaddress))
		if encodeErr_enc_forwardedtosubaddress != nil {
			return nil, qualifyBERError(encodeErr_enc_forwardedtosubaddress, "forwardedToSubaddress", "encoding", true)
		}
		retagged_enc_forwardedtosubaddress, tagErr_enc_forwardedtosubaddress := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, enc_forwardedtosubaddress)
		if tagErr_enc_forwardedtosubaddress != nil {
			return nil, qualifyBERError(tagErr_enc_forwardedtosubaddress, "forwardedToSubaddress", "encoding", true)
		}
		enc_forwardedtosubaddress = retagged_enc_forwardedtosubaddress
		children = append(children, enc_forwardedtosubaddress...)
	}
	if v.ForwardingOptions != nil {
		if len(*v.ForwardingOptions) < 1 || len(*v.ForwardingOptions) > 1 {
			if constraintErr := checkEncodedLength(nil, s47bb6e_5, "51.5", "forwardingOptions", "SIZE (1)", len(*v.ForwardingOptions)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_forwardingoptions, encodeErr_enc_forwardingoptions := ber.EncodeOctetString([]byte(*v.ForwardingOptions))
		if encodeErr_enc_forwardingoptions != nil {
			return nil, qualifyBERError(encodeErr_enc_forwardingoptions, "forwardingOptions", "encoding", true)
		}
		retagged_enc_forwardingoptions, tagErr_enc_forwardingoptions := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 6, enc_forwardingoptions)
		if tagErr_enc_forwardingoptions != nil {
			return nil, qualifyBERError(tagErr_enc_forwardingoptions, "forwardingOptions", "encoding", true)
		}
		enc_forwardingoptions = retagged_enc_forwardingoptions
		children = append(children, enc_forwardingoptions...)
	}
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalDER()
		if err != nil {
			return nil, qualifyBERError(err, "extensionContainer", "encoding", true)
		}
		retagged_enc_extensioncontainer, tagErr_enc_extensioncontainer := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 7, enc_extensioncontainer)
		if tagErr_enc_extensioncontainer != nil {
			return nil, qualifyBERError(tagErr_enc_extensioncontainer, "extensionContainer", "encoding", true)
		}
		enc_extensioncontainer = retagged_enc_extensioncontainer
		children = append(children, enc_extensioncontainer...)
	}
	if v.LongForwardedToNumber != nil {
		if len(*v.LongForwardedToNumber) < 1 || len(*v.LongForwardedToNumber) > 15 {
			if constraintErr := checkEncodedLength(nil, s47bb6e_5, "51.5", "longForwardedToNumber", "SIZE (1..15)", len(*v.LongForwardedToNumber)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		if len(*v.LongForwardedToNumber) < 1 || len(*v.LongForwardedToNumber) > 20 {
			if constraintErr := checkEncodedLength(nil, s47bb6e_5, "51.5", "longForwardedToNumber", "SIZE (1..20)", len(*v.LongForwardedToNumber)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_longforwardedtonumber, encodeErr_enc_longforwardedtonumber := ber.EncodeOctetString([]byte(*v.LongForwardedToNumber))
		if encodeErr_enc_longforwardedtonumber != nil {
			return nil, qualifyBERError(encodeErr_enc_longforwardedtonumber, "longForwardedToNumber", "encoding", true)
		}
		retagged_enc_longforwardedtonumber, tagErr_enc_longforwardedtonumber := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 8, enc_longforwardedtonumber)
		if tagErr_enc_longforwardedtonumber != nil {
			return nil, qualifyBERError(tagErr_enc_longforwardedtonumber, "longForwardedToNumber", "encoding", true)
		}
		enc_longforwardedtonumber = retagged_enc_longforwardedtonumber
		children = append(children, enc_longforwardedtonumber...)
	}
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDEREncodedElement(ext); err != nil {
			return nil, invalidDERAddition(ext, s47bb6e_5, children, i)
		}
		peekTag, _, _, extErr := ber.DecodeEncodedTLV(ext)
		if extErr != nil {
			return nil, extErr
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: only the first addition is restricted.
		if i == 0 && ((peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 8) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 7) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 6) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 5)) {
			if constraintErr := ber.CheckEncodedValue(ber.EncodeRule(nil, s47bb6e_5, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
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
		return nil, fmt.Errorf("%s: %w", "encoding ForwardingData as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}
func (v *ForwardingData) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	encoded, err := v.MarshalDER()
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBER decodes ForwardingData from BER/DER format.
func (destination *ForwardingData) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if destination == nil {
		return fmt.Errorf("%w: ForwardingData destination is nil", ber.ErrInvalidValue)
	}
	v := new(ForwardingData)

	defer publishDecodedValue(destination, v, &returnErr)

	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	preparedData, preparedOptions, prepareErr := prepareCompositeBER(data, opts, s47bb6e_5, "child", (*ForwardingData).UnmarshalBER)
	if prepareErr != nil {
		return prepareErr
	}
	data, opts = preparedData, preparedOptions

	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
	*v = ForwardingData{}
	defer func() {
		if returnErr == nil {
			returnErr = completeValueBER(data,
				opts, v, &v.berReplayNode_, (*ForwardingData).MarshalBER)
		}

	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("%s: %w", "decoding ForwardingData SEQUENCE", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "ForwardingData", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode forwardedToNumber
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 5 {
				ber.MarkPreflightTarget(opts, "forwardedToNumber", content[offset:])
				decodedTag_forwardedtonumber, n_forwardedtonumber, rawVal_forwardedtonumber, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "forwardedToNumber", "decoding", false)
				}
				if decodedTag_forwardedtonumber.Class != tag.ClassContextSpecific || decodedTag_forwardedtonumber.Number != 5 {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_forwardedtonumber), "forwardedToNumber", "decoding", false)
				}
				decVal_forwardedtonumber, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_forwardedtonumber.Constructed, rawVal_forwardedtonumber, opts...)
				if octetErr != nil {
					return qualifyBERError(octetErr, "forwardedToNumber", "decoding", false)
				}
				tmp_forwardedtonumber := ISDNAddressString(decVal_forwardedtonumber)
				v.ForwardedToNumber = &tmp_forwardedtonumber
				if offset > len(content) || n_forwardedtonumber < 0 || n_forwardedtonumber > len(
					content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_forwardedtonumber
				if len(*v.ForwardedToNumber) < 1 || len(*v.ForwardedToNumber) > 9 {
					if constraintErr := checkDecodedLength(opts, s47bb6e_5, "51.5", "forwardedToNumber", "SIZE (1..9)", len(*v.ForwardedToNumber)); constraintErr != nil {
						return constraintErr
					}
				}
				if len(*v.ForwardedToNumber) < 1 || len(*v.ForwardedToNumber) > 20 {
					if constraintErr := checkDecodedLength(opts, s47bb6e_5, "51.5", "forwardedToNumber", "SIZE (1..20)", len(*v.ForwardedToNumber)); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode forwardedToSubaddress
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4 {
				ber.MarkPreflightTarget(opts, "forwardedToSubaddress", content[offset:])
				decodedTag_forwardedtosubaddress, n_forwardedtosubaddress, rawVal_forwardedtosubaddress, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "forwardedToSubaddress", "decoding", false)
				}
				if decodedTag_forwardedtosubaddress.Class != tag.ClassContextSpecific || decodedTag_forwardedtosubaddress.Number != 4 {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_forwardedtosubaddress), "forwardedToSubaddress", "decoding", false)
				}
				decVal_forwardedtosubaddress, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_forwardedtosubaddress.Constructed, rawVal_forwardedtosubaddress, opts...)
				if octetErr != nil {
					return qualifyBERError(octetErr, "forwardedToSubaddress", "decoding", false)
				}
				tmp_forwardedtosubaddress := ISDNSubaddressString(decVal_forwardedtosubaddress)
				v.ForwardedToSubaddress = &tmp_forwardedtosubaddress
				if offset < 0 || offset >
					len(content) || n_forwardedtosubaddress < 0 || n_forwardedtosubaddress >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_forwardedtosubaddress
				if len(*v.ForwardedToSubaddress) < 1 || len(*v.ForwardedToSubaddress) > 21 {
					if constraintErr := checkDecodedLength(opts, s47bb6e_5, "51.5", "forwardedToSubaddress", "SIZE (1..21)", len(*v.ForwardedToSubaddress)); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode forwardingOptions
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 6 {
				ber.MarkPreflightTarget(opts, "forwardingOptions", content[offset:])
				decodedTag_forwardingoptions, n_forwardingoptions, rawVal_forwardingoptions, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "forwardingOptions", "decoding", false)
				}
				if decodedTag_forwardingoptions.Class != tag.ClassContextSpecific || decodedTag_forwardingoptions.Number != 6 {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_forwardingoptions), "forwardingOptions", "decoding", false)
				}
				decVal_forwardingoptions, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_forwardingoptions.Constructed, rawVal_forwardingoptions, opts...)
				if octetErr != nil {
					return qualifyBERError(octetErr, "forwardingOptions", "decoding", false)
				}
				tmp_forwardingoptions := ForwardingOptions(decVal_forwardingoptions)
				v.ForwardingOptions = &tmp_forwardingoptions
				if offset < 0 || offset >
					len(content) || n_forwardingoptions < 0 || n_forwardingoptions >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_forwardingoptions
				if len(*v.ForwardingOptions) < 1 || len(*v.ForwardingOptions) > 1 {
					if constraintErr := checkDecodedLength(opts, s47bb6e_5, "51.5", "forwardingOptions", "SIZE (1)", len(*v.ForwardingOptions)); constraintErr != nil {
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
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 7 {
				ber.MarkPreflightTarget(opts, "extensionContainer", content[offset:])
				decodedTag_extensioncontainer, n_extensioncontainer, rawVal_extensioncontainer, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "extensionContainer", "decoding", false)
				}
				if decodedTag_extensioncontainer.Class != tag.ClassContextSpecific || decodedTag_extensioncontainer.Number != 7 || decodedTag_extensioncontainer.Constructed != true {
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
				var dec_extensioncontainer ExtensionContainer
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
	// Decode longForwardedToNumber
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 8 {
				ber.MarkPreflightTarget(opts, "longForwardedToNumber", content[offset:])
				decodedTag_longforwardedtonumber, n_longforwardedtonumber, rawVal_longforwardedtonumber, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "longForwardedToNumber", "decoding", false)
				}
				if decodedTag_longforwardedtonumber.Class != tag.ClassContextSpecific || decodedTag_longforwardedtonumber.Number != 8 {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_longforwardedtonumber), "longForwardedToNumber", "decoding", false)
				}
				decVal_longforwardedtonumber, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_longforwardedtonumber.Constructed, rawVal_longforwardedtonumber, opts...)
				if octetErr != nil {
					return qualifyBERError(octetErr, "longForwardedToNumber", "decoding", false)
				}
				tmp_longforwardedtonumber := FTNAddressString(decVal_longforwardedtonumber)
				v.LongForwardedToNumber = &tmp_longforwardedtonumber
				if offset < 0 || offset >
					len(content) || n_longforwardedtonumber < 0 || n_longforwardedtonumber >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_longforwardedtonumber
				if len(*v.LongForwardedToNumber) < 1 || len(*v.LongForwardedToNumber) > 15 {
					if constraintErr := checkDecodedLength(opts, s47bb6e_5, "51.5", "longForwardedToNumber", "SIZE (1..15)", len(*v.LongForwardedToNumber)); constraintErr != nil {
						return constraintErr
					}
				}
				if len(*v.LongForwardedToNumber) < 1 || len(*v.LongForwardedToNumber) > 20 {
					if constraintErr := checkDecodedLength(opts, s47bb6e_5, "51.5", "longForwardedToNumber", "SIZE (1..20)", len(*v.LongForwardedToNumber)); constraintErr != nil {
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
			return &ber.DecodeError{Offset: offset, TypeName: "ForwardingData", Cause: extErr_}
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: the first unknown addition must differ from trailing OPTIONAL/DEFAULT tags.
		if len(v.ExtData_) == 0 && ((peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 8) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 7) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 6) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 5)) {
			if !ber.ToleranceEnabled(opts) {
				return &ber.DecodeError{Offset: offset, TypeName: "ForwardingData", Cause: fmt.Errorf("%w: repeated or out-of-order SEQUENCE component tag %s", ber.ErrInvalidTag, peekTag)}
			}
			if orderErr_ := ber.CheckDecodedValue(ber.DecodeRule(opts, s47bb6e_5, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), fmt.Sprintf("ExtData_[%d]", len(v.ExtData_)), "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); orderErr_ != nil {
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

// MarshalBER encodes ProvideRoamingNumberArg to BER format.
func (v *ProvideRoamingNumberArg) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {

	if v == nil {
		return nil, fmt.Errorf("%w: ProvideRoamingNumberArg receiver is nil", ber.ErrInvalidValue)
	}
	return marshalFramedValue(v, v.berReplayNode_, opts, (*ProvideRoamingNumberArg).MarshalBER, (*ProvideRoamingNumberArg).marshalBER, 3)

}
func (v *ProvideRoamingNumberArg) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if len(v.Imsi) < 3 || len(v.Imsi) > 8 {
		if constraintErr := checkEncodedLength(opts, s47bb6e_6, "51.5", "imsi", "SIZE (3..8)", len(v.Imsi)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_imsi, encodeErr_enc_imsi := ber.EncodeOctetString([]byte(v.Imsi))
	if encodeErr_enc_imsi != nil {
		return nil, qualifyBERError(encodeErr_enc_imsi, "imsi", "encoding", false)
	}
	retagged_enc_imsi, tagErr_enc_imsi := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_imsi)
	if tagErr_enc_imsi != nil {
		return nil, qualifyBERError(tagErr_enc_imsi, "imsi", "encoding", false)
	}
	enc_imsi = retagged_enc_imsi
	children = append(children, enc_imsi...)
	if len(v.MscNumber) < 1 || len(v.MscNumber) > 9 {
		if constraintErr := checkEncodedLength(opts, s47bb6e_6, "51.5", "msc-Number", "SIZE (1..9)", len(v.MscNumber)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	if len(v.MscNumber) < 1 || len(v.MscNumber) > 20 {
		if constraintErr := checkEncodedLength(opts, s47bb6e_6, "51.5", "msc-Number", "SIZE (1..20)", len(v.MscNumber)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_mscnumber, encodeErr_enc_mscnumber := ber.EncodeOctetString([]byte(v.MscNumber))
	if encodeErr_enc_mscnumber != nil {
		return nil, qualifyBERError(encodeErr_enc_mscnumber, "msc-Number", "encoding", false)
	}
	retagged_enc_mscnumber, tagErr_enc_mscnumber := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_mscnumber)
	if tagErr_enc_mscnumber != nil {
		return nil, qualifyBERError(tagErr_enc_mscnumber, "msc-Number", "encoding", false)
	}
	enc_mscnumber = retagged_enc_mscnumber
	children = append(children, enc_mscnumber...)
	if v.Msisdn != nil {
		if len(*v.Msisdn) < 1 || len(*v.Msisdn) > 9 {
			if constraintErr := checkEncodedLength(opts, s47bb6e_6, "51.5", "msisdn", "SIZE (1..9)", len(*v.Msisdn)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		if len(*v.Msisdn) < 1 || len(*v.Msisdn) > 20 {
			if constraintErr := checkEncodedLength(opts, s47bb6e_6, "51.5", "msisdn", "SIZE (1..20)", len(*v.Msisdn)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_msisdn, encodeErr_enc_msisdn := ber.EncodeOctetString([]byte(*v.Msisdn))
		if encodeErr_enc_msisdn != nil {
			return nil, qualifyBERError(encodeErr_enc_msisdn, "msisdn", "encoding", false)
		}
		retagged_enc_msisdn, tagErr_enc_msisdn := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_msisdn)
		if tagErr_enc_msisdn != nil {
			return nil, qualifyBERError(tagErr_enc_msisdn, "msisdn", "encoding", false)
		}
		enc_msisdn = retagged_enc_msisdn
		children = append(children, enc_msisdn...)
	}
	if v.Lmsi != nil {
		if len(*v.Lmsi) < 4 || len(*v.Lmsi) > 4 {
			if constraintErr := checkEncodedLength(opts, s47bb6e_6, "51.5", "lmsi", "SIZE (4)", len(*v.Lmsi)); constraintErr != nil {
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
	if v.GsmBearerCapability != nil {
		enc_gsmbearercapability, err := v.GsmBearerCapability.MarshalBER(ber.ChildEncodeOptions(opts, "gsm-BearerCapability")...)
		if err != nil {
			return nil, qualifyBERError(err, "gsm-BearerCapability", "encoding", false)
		}
		retagged_enc_gsmbearercapability, tagErr_enc_gsmbearercapability := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 5, enc_gsmbearercapability)
		if tagErr_enc_gsmbearercapability != nil {
			return nil, qualifyBERError(tagErr_enc_gsmbearercapability, "gsm-BearerCapability", "encoding", false)
		}
		enc_gsmbearercapability = retagged_enc_gsmbearercapability
		ber.RecordGeneratedBERChildPlacement(opts, len(children), enc_gsmbearercapability)
		children = append(children, enc_gsmbearercapability...)
	}
	if v.NetworkSignalInfo != nil {
		enc_networksignalinfo, err := v.NetworkSignalInfo.MarshalBER(ber.ChildEncodeOptions(opts, "networkSignalInfo")...)
		if err != nil {
			return nil, qualifyBERError(err, "networkSignalInfo", "encoding", false)
		}
		retagged_enc_networksignalinfo, tagErr_enc_networksignalinfo := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 6, enc_networksignalinfo)
		if tagErr_enc_networksignalinfo != nil {
			return nil, qualifyBERError(tagErr_enc_networksignalinfo, "networkSignalInfo", "encoding", false)
		}
		enc_networksignalinfo = retagged_enc_networksignalinfo
		ber.RecordGeneratedBERChildPlacement(opts, len(children), enc_networksignalinfo)
		children = append(children, enc_networksignalinfo...)
	}
	if v.SuppressionOfAnnouncement != nil {
		enc_suppressionofannouncement := ber.EncodeNull()
		retagged_enc_suppressionofannouncement, tagErr_enc_suppressionofannouncement := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 7, enc_suppressionofannouncement)
		if tagErr_enc_suppressionofannouncement != nil {
			return nil, qualifyBERError(tagErr_enc_suppressionofannouncement, "suppressionOfAnnouncement", "encoding", false)
		}
		enc_suppressionofannouncement = retagged_enc_suppressionofannouncement
		children = append(children, enc_suppressionofannouncement...)
	}
	if v.GmscAddress != nil {
		if len(*v.GmscAddress) < 1 || len(*v.GmscAddress) > 9 {
			if constraintErr := checkEncodedLength(opts, s47bb6e_6, "51.5", "gmsc-Address", "SIZE (1..9)", len(*v.GmscAddress)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		if len(*v.GmscAddress) < 1 || len(*v.GmscAddress) > 20 {
			if constraintErr := checkEncodedLength(opts, s47bb6e_6, "51.5", "gmsc-Address", "SIZE (1..20)", len(*v.GmscAddress)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_gmscaddress, encodeErr_enc_gmscaddress := ber.EncodeOctetString([]byte(*v.GmscAddress))
		if encodeErr_enc_gmscaddress != nil {
			return nil, qualifyBERError(encodeErr_enc_gmscaddress, "gmsc-Address", "encoding", false)
		}
		retagged_enc_gmscaddress, tagErr_enc_gmscaddress := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 8, enc_gmscaddress)
		if tagErr_enc_gmscaddress != nil {
			return nil, qualifyBERError(tagErr_enc_gmscaddress, "gmsc-Address", "encoding", false)
		}
		enc_gmscaddress = retagged_enc_gmscaddress
		children = append(children, enc_gmscaddress...)
	}
	if v.CallReferenceNumber != nil {
		if len(*v.CallReferenceNumber) < 1 || len(*v.CallReferenceNumber) > 8 {
			if constraintErr := checkEncodedLength(opts, s47bb6e_6, "51.5", "callReferenceNumber", "SIZE (1..8)", len(*v.CallReferenceNumber)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_callreferencenumber, encodeErr_enc_callreferencenumber := ber.EncodeOctetString([]byte(*v.CallReferenceNumber))
		if encodeErr_enc_callreferencenumber != nil {
			return nil, qualifyBERError(encodeErr_enc_callreferencenumber, "callReferenceNumber", "encoding", false)
		}
		retagged_enc_callreferencenumber, tagErr_enc_callreferencenumber := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 9, enc_callreferencenumber)
		if tagErr_enc_callreferencenumber != nil {
			return nil, qualifyBERError(tagErr_enc_callreferencenumber, "callReferenceNumber", "encoding", false)
		}
		enc_callreferencenumber = retagged_enc_callreferencenumber
		children = append(children, enc_callreferencenumber...)
	}
	if v.OrInterrogation != nil {
		enc_orinterrogation := ber.EncodeNull()
		retagged_enc_orinterrogation, tagErr_enc_orinterrogation := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 10, enc_orinterrogation)
		if tagErr_enc_orinterrogation != nil {
			return nil, qualifyBERError(tagErr_enc_orinterrogation, "or-Interrogation", "encoding", false)
		}
		enc_orinterrogation = retagged_enc_orinterrogation
		children = append(children, enc_orinterrogation...)
	}
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalBER(ber.ChildEncodeOptions(opts, "extensionContainer")...)
		if err != nil {
			return nil, qualifyBERError(err, "extensionContainer", "encoding", false)
		}
		retagged_enc_extensioncontainer, tagErr_enc_extensioncontainer := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 11, enc_extensioncontainer)
		if tagErr_enc_extensioncontainer != nil {
			return nil, qualifyBERError(tagErr_enc_extensioncontainer, "extensionContainer", "encoding", false)
		}
		enc_extensioncontainer = retagged_enc_extensioncontainer
		ber.RecordGeneratedBERChildPlacement(opts, len(children), enc_extensioncontainer)
		children = append(children, enc_extensioncontainer...)
	}
	if v.AlertingPattern != nil {
		if len(*v.AlertingPattern) < 1 || len(*v.AlertingPattern) > 1 {
			if constraintErr := checkEncodedLength(opts, s47bb6e_6, "51.5", "alertingPattern", "SIZE (1)", len(*v.AlertingPattern)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_alertingpattern, encodeErr_enc_alertingpattern := ber.EncodeOctetString([]byte(*v.AlertingPattern))
		if encodeErr_enc_alertingpattern != nil {
			return nil, qualifyBERError(encodeErr_enc_alertingpattern, "alertingPattern", "encoding", false)
		}
		retagged_enc_alertingpattern, tagErr_enc_alertingpattern := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 12, enc_alertingpattern)
		if tagErr_enc_alertingpattern != nil {
			return nil, qualifyBERError(tagErr_enc_alertingpattern, "alertingPattern", "encoding", false)
		}
		enc_alertingpattern = retagged_enc_alertingpattern
		children = append(children, enc_alertingpattern...)
	}
	if v.CcbsCall != nil {
		enc_ccbscall := ber.EncodeNull()
		retagged_enc_ccbscall, tagErr_enc_ccbscall := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 13, enc_ccbscall)
		if tagErr_enc_ccbscall != nil {
			return nil, qualifyBERError(tagErr_enc_ccbscall, "ccbs-Call", "encoding", false)
		}
		enc_ccbscall = retagged_enc_ccbscall
		children = append(children, enc_ccbscall...)
	}
	if v.SupportedCamelPhasesInInterrogatingNode != nil {
		namedBits_SupportedCamelPhasesInInterrogatingNode, namedBitErr_ := normalizeNamedBits(*v.SupportedCamelPhasesInInterrogatingNode, []ber.NamedBitSizeSet{{{Min: 1, Max: 16}}}, opts, "supportedCamelPhasesInInterrogatingNode", s47bb6e_6)
		if namedBitErr_ != nil {
			return nil, namedBitErr_
		}
		if bitStringErr := ber.ValidateBitStringLength(namedBits_SupportedCamelPhasesInInterrogatingNode.Bytes, namedBits_SupportedCamelPhasesInInterrogatingNode.BitLength); bitStringErr != nil {
			return nil, qualifyBERError(bitStringErr, "supportedCamelPhasesInInterrogatingNode", "encoding", false)
		}
		// arithmetic pattern BER_BITSTRING_FIELD: 0 <= bit length before modulo and subtraction; gen/codegen.go:750
		if namedBits_SupportedCamelPhasesInInterrogatingNode.BitLength < 0 {
			return nil, fmt.Errorf("negative bit string length")
		}
		if (namedBits_SupportedCamelPhasesInInterrogatingNode).BitLength < 1 || (namedBits_SupportedCamelPhasesInInterrogatingNode).BitLength > 16 {
			if constraintErr := checkEncodedLength(opts, s47bb6e_6, "51.5", "supportedCamelPhasesInInterrogatingNode", "SIZE (1..16)", namedBitObservedLength(namedBits_SupportedCamelPhasesInInterrogatingNode)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_supportedcamelphasesininterrogatingnode, encodeErr_enc_supportedcamelphasesininterrogatingnode := ber.EncodeBitString(namedBits_SupportedCamelPhasesInInterrogatingNode.Bytes, ber.UnusedBitCount(namedBits_SupportedCamelPhasesInInterrogatingNode.BitLength))
		if encodeErr_enc_supportedcamelphasesininterrogatingnode != nil {
			return nil, qualifyBERError(encodeErr_enc_supportedcamelphasesininterrogatingnode, "supportedCamelPhasesInInterrogatingNode", "encoding", false)
		}
		retagged_enc_supportedcamelphasesininterrogatingnode, tagErr_enc_supportedcamelphasesininterrogatingnode := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 15, enc_supportedcamelphasesininterrogatingnode)
		if tagErr_enc_supportedcamelphasesininterrogatingnode != nil {
			return nil, qualifyBERError(tagErr_enc_supportedcamelphasesininterrogatingnode, "supportedCamelPhasesInInterrogatingNode", "encoding", false)
		}
		enc_supportedcamelphasesininterrogatingnode = retagged_enc_supportedcamelphasesininterrogatingnode
		children = append(children, enc_supportedcamelphasesininterrogatingnode...)
	}
	if v.AdditionalSignalInfo != nil {
		enc_additionalsignalinfo, err := v.AdditionalSignalInfo.MarshalBER(ber.ChildEncodeOptions(opts, "additionalSignalInfo")...)
		if err != nil {
			return nil, qualifyBERError(err, "additionalSignalInfo", "encoding", false)
		}
		retagged_enc_additionalsignalinfo, tagErr_enc_additionalsignalinfo := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 14, enc_additionalsignalinfo)
		if tagErr_enc_additionalsignalinfo != nil {
			return nil, qualifyBERError(tagErr_enc_additionalsignalinfo, "additionalSignalInfo", "encoding", false)
		}
		enc_additionalsignalinfo = retagged_enc_additionalsignalinfo
		ber.RecordGeneratedBERChildPlacement(opts, len(children), enc_additionalsignalinfo)
		children = append(children, enc_additionalsignalinfo...)
	}
	if v.OrNotSupportedInGMSC != nil {
		enc_ornotsupportedingmsc := ber.EncodeNull()
		retagged_enc_ornotsupportedingmsc, tagErr_enc_ornotsupportedingmsc := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 16, enc_ornotsupportedingmsc)
		if tagErr_enc_ornotsupportedingmsc != nil {
			return nil, qualifyBERError(tagErr_enc_ornotsupportedingmsc, "orNotSupportedInGMSC", "encoding", false)
		}
		enc_ornotsupportedingmsc = retagged_enc_ornotsupportedingmsc
		children = append(children, enc_ornotsupportedingmsc...)
	}
	if v.PrePagingSupported != nil {
		enc_prepagingsupported := ber.EncodeNull()
		retagged_enc_prepagingsupported, tagErr_enc_prepagingsupported := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 17, enc_prepagingsupported)
		if tagErr_enc_prepagingsupported != nil {
			return nil, qualifyBERError(tagErr_enc_prepagingsupported, "pre-pagingSupported", "encoding", false)
		}
		enc_prepagingsupported = retagged_enc_prepagingsupported
		children = append(children, enc_prepagingsupported...)
	}
	if v.LongFTNSupported != nil {
		enc_longftnsupported := ber.EncodeNull()
		retagged_enc_longftnsupported, tagErr_enc_longftnsupported := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 18, enc_longftnsupported)
		if tagErr_enc_longftnsupported != nil {
			return nil, qualifyBERError(tagErr_enc_longftnsupported, "longFTN-Supported", "encoding", false)
		}
		enc_longftnsupported = retagged_enc_longftnsupported
		children = append(children, enc_longftnsupported...)
	}
	if v.SuppressVTCSI != nil {
		enc_suppressvtcsi := ber.EncodeNull()
		retagged_enc_suppressvtcsi, tagErr_enc_suppressvtcsi := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 19, enc_suppressvtcsi)
		if tagErr_enc_suppressvtcsi != nil {
			return nil, qualifyBERError(tagErr_enc_suppressvtcsi, "suppress-VT-CSI", "encoding", false)
		}
		enc_suppressvtcsi = retagged_enc_suppressvtcsi
		children = append(children, enc_suppressvtcsi...)
	}
	if v.OfferedCamel4CSIsInInterrogatingNode != nil {
		namedBits_OfferedCamel4CSIsInInterrogatingNode, namedBitErr_ := normalizeNamedBits(*v.OfferedCamel4CSIsInInterrogatingNode, []ber.NamedBitSizeSet{{{Min: 7, Max: 16}}}, opts, "offeredCamel4CSIsInInterrogatingNode", s47bb6e_6)
		if namedBitErr_ != nil {
			return nil, namedBitErr_
		}
		if bitStringErr := ber.ValidateBitStringLength(namedBits_OfferedCamel4CSIsInInterrogatingNode.Bytes, namedBits_OfferedCamel4CSIsInInterrogatingNode.BitLength); bitStringErr != nil {
			return nil, qualifyBERError(bitStringErr, "offeredCamel4CSIsInInterrogatingNode", "encoding", false)
		}
		// arithmetic pattern BER_BITSTRING_FIELD: 0 <= bit length before modulo and subtraction; gen/codegen.go:750
		if namedBits_OfferedCamel4CSIsInInterrogatingNode.BitLength < 0 {
			return nil, fmt.Errorf("negative bit string length")
		}
		if (namedBits_OfferedCamel4CSIsInInterrogatingNode).BitLength < 7 || (namedBits_OfferedCamel4CSIsInInterrogatingNode).BitLength > 16 {
			if constraintErr := checkEncodedLength(opts, s47bb6e_6, "51.5", "offeredCamel4CSIsInInterrogatingNode", "SIZE (7..16)", namedBitObservedLength(namedBits_OfferedCamel4CSIsInInterrogatingNode)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_offeredcamel4csisininterrogatingnode, encodeErr_enc_offeredcamel4csisininterrogatingnode := ber.EncodeBitString(namedBits_OfferedCamel4CSIsInInterrogatingNode.Bytes, ber.UnusedBitCount(namedBits_OfferedCamel4CSIsInInterrogatingNode.BitLength))
		if encodeErr_enc_offeredcamel4csisininterrogatingnode != nil {
			return nil, qualifyBERError(encodeErr_enc_offeredcamel4csisininterrogatingnode, "offeredCamel4CSIsInInterrogatingNode", "encoding", false)
		}
		retagged_enc_offeredcamel4csisininterrogatingnode, tagErr_enc_offeredcamel4csisininterrogatingnode := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 20, enc_offeredcamel4csisininterrogatingnode)
		if tagErr_enc_offeredcamel4csisininterrogatingnode != nil {
			return nil, qualifyBERError(tagErr_enc_offeredcamel4csisininterrogatingnode, "offeredCamel4CSIsInInterrogatingNode", "encoding", false)
		}
		enc_offeredcamel4csisininterrogatingnode = retagged_enc_offeredcamel4csisininterrogatingnode
		children = append(children, enc_offeredcamel4csisininterrogatingnode...)
	}
	if v.MtRoamingRetrySupported != nil {
		enc_mtroamingretrysupported := ber.EncodeNull()
		retagged_enc_mtroamingretrysupported, tagErr_enc_mtroamingretrysupported := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 21, enc_mtroamingretrysupported)
		if tagErr_enc_mtroamingretrysupported != nil {
			return nil, qualifyBERError(tagErr_enc_mtroamingretrysupported, "mtRoamingRetrySupported", "encoding", false)
		}
		enc_mtroamingretrysupported = retagged_enc_mtroamingretrysupported
		children = append(children, enc_mtroamingretrysupported...)
	}
	if v.PagingArea != nil {
		if len((v.PagingArea).Values) < 1 || len((v.PagingArea).Values) > 5 {
			if constraintErr := checkEncodedLength(opts, s47bb6e_6, "51.5", "pagingArea", "SIZE (1..5)", len((v.PagingArea).Values)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_pagingarea, err := MarshalBERPagingArea(v.PagingArea, ber.ParentCollectionSizeEncodeOptions(ber.ChildEncodeOptions(opts, "pagingArea"))...)
		if err != nil {
			return nil, qualifyBERError(err, "pagingArea", "encoding", false)
		}
		if ber.BERReplayEnabled(opts) && v.berPagingAreaIndef_ {
			// Strip the outer SEQUENCE tag from marshalBER output to get raw children.
			_, _, seqContent_, tlvErr_ := ber.DecodeEncodedTLV(enc_pagingarea)
			if tlvErr_ != nil {
				return nil, tlvErr_
			}
			{
				var encodeErr error
				enc_pagingarea, encodeErr = ber.EncodeConstructedIndefinite(tag.Tag{Class: tag.ClassContextSpecific, Number: 22}, seqContent_)
				if encodeErr != nil {
					return nil, qualifyBERError(encodeErr, "pagingArea", "encoding", false)
				}
			}
		} else {
			retagged_enc_pagingarea, tagErr_enc_pagingarea := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 22, enc_pagingarea)
			if tagErr_enc_pagingarea != nil {
				return nil, qualifyBERError(tagErr_enc_pagingarea, "pagingArea", "encoding", false)
			}
			enc_pagingarea = retagged_enc_pagingarea
		}
		ber.RecordGeneratedBERChildPlacement(opts, len(children), enc_pagingarea)
		children = append(children, enc_pagingarea...)
	}
	if v.CallPriority != nil {
		if !(int64(*v.CallPriority) >= 0 && int64(*v.CallPriority) <= 15) {
			if constraintErr := checkEncodedValue(opts, s47bb6e_6, "51.4", "callPriority", "(0..15)", ber.ObserveInteger(int64(*v.CallPriority))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_callpriority := ber.EncodeInteger(int64(*v.CallPriority))
		retagged_enc_callpriority, tagErr_enc_callpriority := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 23, enc_callpriority)
		if tagErr_enc_callpriority != nil {
			return nil, qualifyBERError(tagErr_enc_callpriority, "callPriority", "encoding", false)
		}
		enc_callpriority = retagged_enc_callpriority
		children = append(children, enc_callpriority...)
	}
	if v.MtrfIndicator != nil {
		enc_mtrfindicator := ber.EncodeNull()
		retagged_enc_mtrfindicator, tagErr_enc_mtrfindicator := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 24, enc_mtrfindicator)
		if tagErr_enc_mtrfindicator != nil {
			return nil, qualifyBERError(tagErr_enc_mtrfindicator, "mtrf-Indicator", "encoding", false)
		}
		enc_mtrfindicator = retagged_enc_mtrfindicator
		children = append(children, enc_mtrfindicator...)
	}
	if v.OldMSCNumber != nil {
		if len(*v.OldMSCNumber) < 1 || len(*v.OldMSCNumber) > 9 {
			if constraintErr := checkEncodedLength(opts, s47bb6e_6, "51.5", "oldMSC-Number", "SIZE (1..9)", len(*v.OldMSCNumber)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		if len(*v.OldMSCNumber) < 1 || len(*v.OldMSCNumber) > 20 {
			if constraintErr := checkEncodedLength(opts, s47bb6e_6, "51.5", "oldMSC-Number", "SIZE (1..20)", len(*v.OldMSCNumber)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_oldmscnumber, encodeErr_enc_oldmscnumber := ber.EncodeOctetString([]byte(*v.OldMSCNumber))
		if encodeErr_enc_oldmscnumber != nil {
			return nil, qualifyBERError(encodeErr_enc_oldmscnumber, "oldMSC-Number", "encoding", false)
		}
		retagged_enc_oldmscnumber, tagErr_enc_oldmscnumber := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 25, enc_oldmscnumber)
		if tagErr_enc_oldmscnumber != nil {
			return nil, qualifyBERError(tagErr_enc_oldmscnumber, "oldMSC-Number", "encoding", false)
		}
		enc_oldmscnumber = retagged_enc_oldmscnumber
		children = append(children, enc_oldmscnumber...)
	}
	if v.LastUsedLtePLMNId != nil {
		if len(*v.LastUsedLtePLMNId) < 3 || len(*v.LastUsedLtePLMNId) > 3 {
			if constraintErr := checkEncodedLength(opts, s47bb6e_6, "51.5", "lastUsedLtePLMN-Id", "SIZE (3)", len(*v.LastUsedLtePLMNId)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_lastusedlteplmnid, encodeErr_enc_lastusedlteplmnid := ber.EncodeOctetString([]byte(*v.LastUsedLtePLMNId))
		if encodeErr_enc_lastusedlteplmnid != nil {
			return nil, qualifyBERError(encodeErr_enc_lastusedlteplmnid, "lastUsedLtePLMN-Id", "encoding", false)
		}
		retagged_enc_lastusedlteplmnid, tagErr_enc_lastusedlteplmnid := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 26, enc_lastusedlteplmnid)
		if tagErr_enc_lastusedlteplmnid != nil {
			return nil, qualifyBERError(tagErr_enc_lastusedlteplmnid, "lastUsedLtePLMN-Id", "encoding", false)
		}
		enc_lastusedlteplmnid = retagged_enc_lastusedlteplmnid
		children = append(children, enc_lastusedlteplmnid...)
	}
	base_ := -1
	for i, ext := range v.ExtData_ {
		if err := checkOpaqueAddition(ext, opts, s47bb6e_6, children, i, &base_); err != nil {
			return nil, opaqueExtensionError(err, i)
		}
		peekTag, n, _, extErr := ber.DecodeEncodedTLV(ext)
		if extErr != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, extErr)
		}
		if n != len(ext) {
			return nil, fmt.Errorf("encoding extension %d: %w", i, ber.ErrExtraData)
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: only the first addition is restricted.
		if i == 0 && ((peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 26) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 25) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 24) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 23) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 22) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 21) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 20) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 19) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 18) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 17) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 16) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 14) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 15) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 13) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 12) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 11) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 10) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 9) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 8) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 7) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 6) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 5) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2)) {
			if constraintErr := ber.CheckEncodedValue(ber.EncodeRule(opts, s47bb6e_6, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
				return nil, constraintErr
			}
		}
		children = append(children, ext...)
	}
	ber.RecordGeneratedBERContainer(opts, children)
	return ber.EncodeSequence(children)
}
func (v *ProvideRoamingNumberArg) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// MarshalDER encodes ProvideRoamingNumberArg to DER format.
// Opaque descendants pass generic DER checks; foreign schema rules need a typed binding.
func (v *ProvideRoamingNumberArg) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: ProvideRoamingNumberArg receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if len(v.Imsi) < 3 || len(v.Imsi) > 8 {
		if constraintErr := checkEncodedLength(nil, s47bb6e_6, "51.5", "imsi", "SIZE (3..8)", len(v.Imsi)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_imsi, encodeErr_enc_imsi := ber.EncodeOctetString([]byte(v.Imsi))
	if encodeErr_enc_imsi != nil {
		return nil, qualifyBERError(encodeErr_enc_imsi, "imsi", "encoding", true)
	}
	retagged_enc_imsi, tagErr_enc_imsi := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_imsi)
	if tagErr_enc_imsi != nil {
		return nil, qualifyBERError(tagErr_enc_imsi, "imsi", "encoding", true)
	}
	enc_imsi = retagged_enc_imsi
	children = append(children, enc_imsi...)
	if len(v.MscNumber) < 1 || len(v.MscNumber) > 9 {
		if constraintErr := checkEncodedLength(nil, s47bb6e_6, "51.5", "msc-Number", "SIZE (1..9)", len(v.MscNumber)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	if len(v.MscNumber) < 1 || len(v.MscNumber) > 20 {
		if constraintErr := checkEncodedLength(nil, s47bb6e_6, "51.5", "msc-Number", "SIZE (1..20)", len(v.MscNumber)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_mscnumber, encodeErr_enc_mscnumber := ber.EncodeOctetString([]byte(v.MscNumber))
	if encodeErr_enc_mscnumber != nil {
		return nil, qualifyBERError(encodeErr_enc_mscnumber, "msc-Number", "encoding", true)
	}
	retagged_enc_mscnumber, tagErr_enc_mscnumber := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_mscnumber)
	if tagErr_enc_mscnumber != nil {
		return nil, qualifyBERError(tagErr_enc_mscnumber, "msc-Number", "encoding", true)
	}
	enc_mscnumber = retagged_enc_mscnumber
	children = append(children, enc_mscnumber...)
	if v.Msisdn != nil {
		if len(*v.Msisdn) < 1 || len(*v.Msisdn) > 9 {
			if constraintErr := checkEncodedLength(nil, s47bb6e_6, "51.5", "msisdn", "SIZE (1..9)", len(*v.Msisdn)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		if len(*v.Msisdn) < 1 || len(*v.Msisdn) > 20 {
			if constraintErr := checkEncodedLength(nil, s47bb6e_6, "51.5", "msisdn", "SIZE (1..20)", len(*v.Msisdn)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_msisdn, encodeErr_enc_msisdn := ber.EncodeOctetString([]byte(*v.Msisdn))
		if encodeErr_enc_msisdn != nil {
			return nil, qualifyBERError(encodeErr_enc_msisdn, "msisdn", "encoding", true)
		}
		retagged_enc_msisdn, tagErr_enc_msisdn := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_msisdn)
		if tagErr_enc_msisdn != nil {
			return nil, qualifyBERError(tagErr_enc_msisdn, "msisdn", "encoding", true)
		}
		enc_msisdn = retagged_enc_msisdn
		children = append(children, enc_msisdn...)
	}
	if v.Lmsi != nil {
		if len(*v.Lmsi) < 4 || len(*v.Lmsi) > 4 {
			if constraintErr := checkEncodedLength(nil, s47bb6e_6, "51.5", "lmsi", "SIZE (4)", len(*v.Lmsi)); constraintErr != nil {
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
	if v.GsmBearerCapability != nil {
		enc_gsmbearercapability, err := v.GsmBearerCapability.MarshalDER()
		if err != nil {
			return nil, qualifyBERError(err, "gsm-BearerCapability", "encoding", true)
		}
		retagged_enc_gsmbearercapability, tagErr_enc_gsmbearercapability := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 5, enc_gsmbearercapability)
		if tagErr_enc_gsmbearercapability != nil {
			return nil, qualifyBERError(tagErr_enc_gsmbearercapability, "gsm-BearerCapability", "encoding", true)
		}
		enc_gsmbearercapability = retagged_enc_gsmbearercapability
		children = append(children, enc_gsmbearercapability...)
	}
	if v.NetworkSignalInfo != nil {
		enc_networksignalinfo, err := v.NetworkSignalInfo.MarshalDER()
		if err != nil {
			return nil, qualifyBERError(err, "networkSignalInfo", "encoding", true)
		}
		retagged_enc_networksignalinfo, tagErr_enc_networksignalinfo := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 6, enc_networksignalinfo)
		if tagErr_enc_networksignalinfo != nil {
			return nil, qualifyBERError(tagErr_enc_networksignalinfo, "networkSignalInfo", "encoding", true)
		}
		enc_networksignalinfo = retagged_enc_networksignalinfo
		children = append(children, enc_networksignalinfo...)
	}
	if v.SuppressionOfAnnouncement != nil {
		enc_suppressionofannouncement := ber.EncodeNull()
		retagged_enc_suppressionofannouncement, tagErr_enc_suppressionofannouncement := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 7, enc_suppressionofannouncement)
		if tagErr_enc_suppressionofannouncement != nil {
			return nil, qualifyBERError(tagErr_enc_suppressionofannouncement, "suppressionOfAnnouncement", "encoding", true)
		}
		enc_suppressionofannouncement = retagged_enc_suppressionofannouncement
		children = append(children, enc_suppressionofannouncement...)
	}
	if v.GmscAddress != nil {
		if len(*v.GmscAddress) < 1 || len(*v.GmscAddress) > 9 {
			if constraintErr := checkEncodedLength(nil, s47bb6e_6, "51.5", "gmsc-Address", "SIZE (1..9)", len(*v.GmscAddress)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		if len(*v.GmscAddress) < 1 || len(*v.GmscAddress) > 20 {
			if constraintErr := checkEncodedLength(nil, s47bb6e_6, "51.5", "gmsc-Address", "SIZE (1..20)", len(*v.GmscAddress)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_gmscaddress, encodeErr_enc_gmscaddress := ber.EncodeOctetString([]byte(*v.GmscAddress))
		if encodeErr_enc_gmscaddress != nil {
			return nil, qualifyBERError(encodeErr_enc_gmscaddress, "gmsc-Address", "encoding", true)
		}
		retagged_enc_gmscaddress, tagErr_enc_gmscaddress := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 8, enc_gmscaddress)
		if tagErr_enc_gmscaddress != nil {
			return nil, qualifyBERError(tagErr_enc_gmscaddress, "gmsc-Address", "encoding", true)
		}
		enc_gmscaddress = retagged_enc_gmscaddress
		children = append(children, enc_gmscaddress...)
	}
	if v.CallReferenceNumber != nil {
		if len(*v.CallReferenceNumber) < 1 || len(*v.CallReferenceNumber) > 8 {
			if constraintErr := checkEncodedLength(nil, s47bb6e_6, "51.5", "callReferenceNumber", "SIZE (1..8)", len(*v.CallReferenceNumber)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_callreferencenumber, encodeErr_enc_callreferencenumber := ber.EncodeOctetString([]byte(*v.CallReferenceNumber))
		if encodeErr_enc_callreferencenumber != nil {
			return nil, qualifyBERError(encodeErr_enc_callreferencenumber, "callReferenceNumber", "encoding", true)
		}
		retagged_enc_callreferencenumber, tagErr_enc_callreferencenumber := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 9, enc_callreferencenumber)
		if tagErr_enc_callreferencenumber != nil {
			return nil, qualifyBERError(tagErr_enc_callreferencenumber, "callReferenceNumber", "encoding", true)
		}
		enc_callreferencenumber = retagged_enc_callreferencenumber
		children = append(children, enc_callreferencenumber...)
	}
	if v.OrInterrogation != nil {
		enc_orinterrogation := ber.EncodeNull()
		retagged_enc_orinterrogation, tagErr_enc_orinterrogation := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 10, enc_orinterrogation)
		if tagErr_enc_orinterrogation != nil {
			return nil, qualifyBERError(tagErr_enc_orinterrogation, "or-Interrogation", "encoding", true)
		}
		enc_orinterrogation = retagged_enc_orinterrogation
		children = append(children, enc_orinterrogation...)
	}
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalDER()
		if err != nil {
			return nil, qualifyBERError(err, "extensionContainer", "encoding", true)
		}
		retagged_enc_extensioncontainer, tagErr_enc_extensioncontainer := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 11, enc_extensioncontainer)
		if tagErr_enc_extensioncontainer != nil {
			return nil, qualifyBERError(tagErr_enc_extensioncontainer, "extensionContainer", "encoding", true)
		}
		enc_extensioncontainer = retagged_enc_extensioncontainer
		children = append(children, enc_extensioncontainer...)
	}
	if v.AlertingPattern != nil {
		if len(*v.AlertingPattern) < 1 || len(*v.AlertingPattern) > 1 {
			if constraintErr := checkEncodedLength(nil, s47bb6e_6, "51.5", "alertingPattern", "SIZE (1)", len(*v.AlertingPattern)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_alertingpattern, encodeErr_enc_alertingpattern := ber.EncodeOctetString([]byte(*v.AlertingPattern))
		if encodeErr_enc_alertingpattern != nil {
			return nil, qualifyBERError(encodeErr_enc_alertingpattern, "alertingPattern", "encoding", true)
		}
		retagged_enc_alertingpattern, tagErr_enc_alertingpattern := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 12, enc_alertingpattern)
		if tagErr_enc_alertingpattern != nil {
			return nil, qualifyBERError(tagErr_enc_alertingpattern, "alertingPattern", "encoding", true)
		}
		enc_alertingpattern = retagged_enc_alertingpattern
		children = append(children, enc_alertingpattern...)
	}
	if v.CcbsCall != nil {
		enc_ccbscall := ber.EncodeNull()
		retagged_enc_ccbscall, tagErr_enc_ccbscall := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 13, enc_ccbscall)
		if tagErr_enc_ccbscall != nil {
			return nil, qualifyBERError(tagErr_enc_ccbscall, "ccbs-Call", "encoding", true)
		}
		enc_ccbscall = retagged_enc_ccbscall
		children = append(children, enc_ccbscall...)
	}
	if v.SupportedCamelPhasesInInterrogatingNode != nil {
		namedBits_SupportedCamelPhasesInInterrogatingNode, namedBitErr_ := normalizeNamedBits(*v.SupportedCamelPhasesInInterrogatingNode, []ber.NamedBitSizeSet{{{Min: 1, Max: 16}}}, nil, "supportedCamelPhasesInInterrogatingNode", s47bb6e_6)
		if namedBitErr_ != nil {
			return nil, namedBitErr_
		}
		if bitStringErr := ber.ValidateBitStringLength(namedBits_SupportedCamelPhasesInInterrogatingNode.Bytes, namedBits_SupportedCamelPhasesInInterrogatingNode.BitLength); bitStringErr != nil {
			return nil, qualifyBERError(bitStringErr, "supportedCamelPhasesInInterrogatingNode", "encoding", true)
		}
		// arithmetic pattern BER_BITSTRING_FIELD: 0 <= bit length before modulo and subtraction; gen/codegen.go:750
		if namedBits_SupportedCamelPhasesInInterrogatingNode.BitLength < 0 {
			return nil, fmt.Errorf("negative bit string length")
		}
		if (namedBits_SupportedCamelPhasesInInterrogatingNode).BitLength < 1 || (namedBits_SupportedCamelPhasesInInterrogatingNode).BitLength > 16 {
			if constraintErr := checkEncodedLength(nil, s47bb6e_6, "51.5", "supportedCamelPhasesInInterrogatingNode", "SIZE (1..16)", namedBitObservedLength(namedBits_SupportedCamelPhasesInInterrogatingNode)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_supportedcamelphasesininterrogatingnode, encodeErr_enc_supportedcamelphasesininterrogatingnode := ber.EncodeDERNamedBitString(namedBits_SupportedCamelPhasesInInterrogatingNode.Bytes, namedBits_SupportedCamelPhasesInInterrogatingNode.BitLength)
		if encodeErr_enc_supportedcamelphasesininterrogatingnode != nil {
			return nil, qualifyBERError(encodeErr_enc_supportedcamelphasesininterrogatingnode, "supportedCamelPhasesInInterrogatingNode", "encoding", true)
		}
		retagged_enc_supportedcamelphasesininterrogatingnode, tagErr_enc_supportedcamelphasesininterrogatingnode := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 15, enc_supportedcamelphasesininterrogatingnode)
		if tagErr_enc_supportedcamelphasesininterrogatingnode != nil {
			return nil, qualifyBERError(tagErr_enc_supportedcamelphasesininterrogatingnode, "supportedCamelPhasesInInterrogatingNode", "encoding", true)
		}
		enc_supportedcamelphasesininterrogatingnode = retagged_enc_supportedcamelphasesininterrogatingnode
		children = append(children, enc_supportedcamelphasesininterrogatingnode...)
	}
	if v.AdditionalSignalInfo != nil {
		enc_additionalsignalinfo, err := v.AdditionalSignalInfo.MarshalDER()
		if err != nil {
			return nil, qualifyBERError(err, "additionalSignalInfo", "encoding", true)
		}
		retagged_enc_additionalsignalinfo, tagErr_enc_additionalsignalinfo := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 14, enc_additionalsignalinfo)
		if tagErr_enc_additionalsignalinfo != nil {
			return nil, qualifyBERError(tagErr_enc_additionalsignalinfo, "additionalSignalInfo", "encoding", true)
		}
		enc_additionalsignalinfo = retagged_enc_additionalsignalinfo
		children = append(children, enc_additionalsignalinfo...)
	}
	if v.OrNotSupportedInGMSC != nil {
		enc_ornotsupportedingmsc := ber.EncodeNull()
		retagged_enc_ornotsupportedingmsc, tagErr_enc_ornotsupportedingmsc := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 16, enc_ornotsupportedingmsc)
		if tagErr_enc_ornotsupportedingmsc != nil {
			return nil, qualifyBERError(tagErr_enc_ornotsupportedingmsc, "orNotSupportedInGMSC", "encoding", true)
		}
		enc_ornotsupportedingmsc = retagged_enc_ornotsupportedingmsc
		children = append(children, enc_ornotsupportedingmsc...)
	}
	if v.PrePagingSupported != nil {
		enc_prepagingsupported := ber.EncodeNull()
		retagged_enc_prepagingsupported, tagErr_enc_prepagingsupported := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 17, enc_prepagingsupported)
		if tagErr_enc_prepagingsupported != nil {
			return nil, qualifyBERError(tagErr_enc_prepagingsupported, "pre-pagingSupported", "encoding", true)
		}
		enc_prepagingsupported = retagged_enc_prepagingsupported
		children = append(children, enc_prepagingsupported...)
	}
	if v.LongFTNSupported != nil {
		enc_longftnsupported := ber.EncodeNull()
		retagged_enc_longftnsupported, tagErr_enc_longftnsupported := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 18, enc_longftnsupported)
		if tagErr_enc_longftnsupported != nil {
			return nil, qualifyBERError(tagErr_enc_longftnsupported, "longFTN-Supported", "encoding", true)
		}
		enc_longftnsupported = retagged_enc_longftnsupported
		children = append(children, enc_longftnsupported...)
	}
	if v.SuppressVTCSI != nil {
		enc_suppressvtcsi := ber.EncodeNull()
		retagged_enc_suppressvtcsi, tagErr_enc_suppressvtcsi := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 19, enc_suppressvtcsi)
		if tagErr_enc_suppressvtcsi != nil {
			return nil, qualifyBERError(tagErr_enc_suppressvtcsi, "suppress-VT-CSI", "encoding", true)
		}
		enc_suppressvtcsi = retagged_enc_suppressvtcsi
		children = append(children, enc_suppressvtcsi...)
	}
	if v.OfferedCamel4CSIsInInterrogatingNode != nil {
		namedBits_OfferedCamel4CSIsInInterrogatingNode, namedBitErr_ := normalizeNamedBits(*v.OfferedCamel4CSIsInInterrogatingNode, []ber.NamedBitSizeSet{{{Min: 7, Max: 16}}}, nil, "offeredCamel4CSIsInInterrogatingNode", s47bb6e_6)
		if namedBitErr_ != nil {
			return nil, namedBitErr_
		}
		if bitStringErr := ber.ValidateBitStringLength(namedBits_OfferedCamel4CSIsInInterrogatingNode.Bytes, namedBits_OfferedCamel4CSIsInInterrogatingNode.BitLength); bitStringErr != nil {
			return nil, qualifyBERError(bitStringErr, "offeredCamel4CSIsInInterrogatingNode", "encoding", true)
		}
		// arithmetic pattern BER_BITSTRING_FIELD: 0 <= bit length before modulo and subtraction; gen/codegen.go:750
		if namedBits_OfferedCamel4CSIsInInterrogatingNode.BitLength < 0 {
			return nil, fmt.Errorf("negative bit string length")
		}
		if (namedBits_OfferedCamel4CSIsInInterrogatingNode).BitLength < 7 || (namedBits_OfferedCamel4CSIsInInterrogatingNode).BitLength > 16 {
			if constraintErr := checkEncodedLength(nil, s47bb6e_6, "51.5", "offeredCamel4CSIsInInterrogatingNode", "SIZE (7..16)", namedBitObservedLength(namedBits_OfferedCamel4CSIsInInterrogatingNode)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_offeredcamel4csisininterrogatingnode, encodeErr_enc_offeredcamel4csisininterrogatingnode := ber.EncodeDERNamedBitString(namedBits_OfferedCamel4CSIsInInterrogatingNode.Bytes, namedBits_OfferedCamel4CSIsInInterrogatingNode.BitLength)
		if encodeErr_enc_offeredcamel4csisininterrogatingnode != nil {
			return nil, qualifyBERError(encodeErr_enc_offeredcamel4csisininterrogatingnode, "offeredCamel4CSIsInInterrogatingNode", "encoding", true)
		}
		retagged_enc_offeredcamel4csisininterrogatingnode, tagErr_enc_offeredcamel4csisininterrogatingnode := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 20, enc_offeredcamel4csisininterrogatingnode)
		if tagErr_enc_offeredcamel4csisininterrogatingnode != nil {
			return nil, qualifyBERError(tagErr_enc_offeredcamel4csisininterrogatingnode, "offeredCamel4CSIsInInterrogatingNode", "encoding", true)
		}
		enc_offeredcamel4csisininterrogatingnode = retagged_enc_offeredcamel4csisininterrogatingnode
		children = append(children, enc_offeredcamel4csisininterrogatingnode...)
	}
	if v.MtRoamingRetrySupported != nil {
		enc_mtroamingretrysupported := ber.EncodeNull()
		retagged_enc_mtroamingretrysupported, tagErr_enc_mtroamingretrysupported := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 21, enc_mtroamingretrysupported)
		if tagErr_enc_mtroamingretrysupported != nil {
			return nil, qualifyBERError(tagErr_enc_mtroamingretrysupported, "mtRoamingRetrySupported", "encoding", true)
		}
		enc_mtroamingretrysupported = retagged_enc_mtroamingretrysupported
		children = append(children, enc_mtroamingretrysupported...)
	}
	if v.PagingArea != nil {
		if len((v.PagingArea).Values) < 1 || len((v.PagingArea).Values) > 5 {
			if constraintErr := checkEncodedLength(nil, s47bb6e_6, "51.5", "pagingArea", "SIZE (1..5)", len((v.PagingArea).Values)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_pagingarea, err := MarshalDERPagingArea(v.PagingArea)
		if err != nil {
			return nil, qualifyBERError(err, "pagingArea", "encoding", true)
		}
		retagged_enc_pagingarea, tagErr_enc_pagingarea := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 22, enc_pagingarea)
		if tagErr_enc_pagingarea != nil {
			return nil, qualifyBERError(tagErr_enc_pagingarea, "pagingArea", "encoding", true)
		}
		enc_pagingarea = retagged_enc_pagingarea
		children = append(children, enc_pagingarea...)
	}
	if v.CallPriority != nil {
		if !(int64(*v.CallPriority) >= 0 && int64(*v.CallPriority) <= 15) {
			if constraintErr := checkEncodedValue(nil, s47bb6e_6, "51.4", "callPriority", "(0..15)", ber.ObserveInteger(int64(*v.CallPriority))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_callpriority := ber.EncodeInteger(int64(*v.CallPriority))
		retagged_enc_callpriority, tagErr_enc_callpriority := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 23, enc_callpriority)
		if tagErr_enc_callpriority != nil {
			return nil, qualifyBERError(tagErr_enc_callpriority, "callPriority", "encoding", true)
		}
		enc_callpriority = retagged_enc_callpriority
		children = append(children, enc_callpriority...)
	}
	if v.MtrfIndicator != nil {
		enc_mtrfindicator := ber.EncodeNull()
		retagged_enc_mtrfindicator, tagErr_enc_mtrfindicator := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 24, enc_mtrfindicator)
		if tagErr_enc_mtrfindicator != nil {
			return nil, qualifyBERError(tagErr_enc_mtrfindicator, "mtrf-Indicator", "encoding", true)
		}
		enc_mtrfindicator = retagged_enc_mtrfindicator
		children = append(children, enc_mtrfindicator...)
	}
	if v.OldMSCNumber != nil {
		if len(*v.OldMSCNumber) < 1 || len(*v.OldMSCNumber) > 9 {
			if constraintErr := checkEncodedLength(nil, s47bb6e_6, "51.5", "oldMSC-Number", "SIZE (1..9)", len(*v.OldMSCNumber)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		if len(*v.OldMSCNumber) < 1 || len(*v.OldMSCNumber) > 20 {
			if constraintErr := checkEncodedLength(nil, s47bb6e_6, "51.5", "oldMSC-Number", "SIZE (1..20)", len(*v.OldMSCNumber)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_oldmscnumber, encodeErr_enc_oldmscnumber := ber.EncodeOctetString([]byte(*v.OldMSCNumber))
		if encodeErr_enc_oldmscnumber != nil {
			return nil, qualifyBERError(encodeErr_enc_oldmscnumber, "oldMSC-Number", "encoding", true)
		}
		retagged_enc_oldmscnumber, tagErr_enc_oldmscnumber := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 25, enc_oldmscnumber)
		if tagErr_enc_oldmscnumber != nil {
			return nil, qualifyBERError(tagErr_enc_oldmscnumber, "oldMSC-Number", "encoding", true)
		}
		enc_oldmscnumber = retagged_enc_oldmscnumber
		children = append(children, enc_oldmscnumber...)
	}
	if v.LastUsedLtePLMNId != nil {
		if len(*v.LastUsedLtePLMNId) < 3 || len(*v.LastUsedLtePLMNId) > 3 {
			if constraintErr := checkEncodedLength(nil, s47bb6e_6, "51.5", "lastUsedLtePLMN-Id", "SIZE (3)", len(*v.LastUsedLtePLMNId)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_lastusedlteplmnid, encodeErr_enc_lastusedlteplmnid := ber.EncodeOctetString([]byte(*v.LastUsedLtePLMNId))
		if encodeErr_enc_lastusedlteplmnid != nil {
			return nil, qualifyBERError(encodeErr_enc_lastusedlteplmnid, "lastUsedLtePLMN-Id", "encoding", true)
		}
		retagged_enc_lastusedlteplmnid, tagErr_enc_lastusedlteplmnid := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 26, enc_lastusedlteplmnid)
		if tagErr_enc_lastusedlteplmnid != nil {
			return nil, qualifyBERError(tagErr_enc_lastusedlteplmnid, "lastUsedLtePLMN-Id", "encoding", true)
		}
		enc_lastusedlteplmnid = retagged_enc_lastusedlteplmnid
		children = append(children, enc_lastusedlteplmnid...)
	}
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDEREncodedElement(ext); err != nil {
			return nil, invalidDERAddition(ext, s47bb6e_6, children, i)
		}
		peekTag, _, _, extErr := ber.DecodeEncodedTLV(ext)
		if extErr != nil {
			return nil, extErr
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: only the first addition is restricted.
		if i == 0 && ((peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 26) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 25) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 24) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 23) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 22) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 21) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 20) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 19) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 18) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 17) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 16) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 14) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 15) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 13) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 12) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 11) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 10) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 9) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 8) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 7) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 6) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 5) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2)) {
			if constraintErr := ber.CheckEncodedValue(ber.EncodeRule(nil, s47bb6e_6, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
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
		return nil, fmt.Errorf("%s: %w", "encoding ProvideRoamingNumberArg as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}
func (v *ProvideRoamingNumberArg) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	encoded, err := v.MarshalDER()
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBER decodes ProvideRoamingNumberArg from BER/DER format.
func (destination *ProvideRoamingNumberArg) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if destination == nil {
		return fmt.Errorf("%w: ProvideRoamingNumberArg destination is nil", ber.ErrInvalidValue)
	}
	v := new(ProvideRoamingNumberArg)

	defer publishDecodedValue(destination, v, &returnErr)

	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	preparedData, preparedOptions, prepareErr := prepareCompositeBER(data, opts, s47bb6e_6, "child", (*ProvideRoamingNumberArg).UnmarshalBER)
	if prepareErr != nil {
		return prepareErr
	}
	data, opts = preparedData, preparedOptions

	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
	*v = ProvideRoamingNumberArg{}
	defer func() {
		if returnErr == nil {
			returnErr = completeValueBER(data,
				opts, v, &v.berReplayNode_, (*ProvideRoamingNumberArg).MarshalBER)
		}

	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("%s: %w", "decoding ProvideRoamingNumberArg SEQUENCE", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "ProvideRoamingNumberArg", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode imsi
	if offset >= len(content) {
		return fmt.Errorf("missing required field imsi")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 0 {
			return fmt.Errorf("expected tag [%s %d] for imsi, got %s", "CONTEXT", 0, reqTag_)
		}
	}
	{
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
		v.Imsi = IMSI(decVal_imsi)
		if offset > len(content) || n_imsi < 0 || n_imsi > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n_imsi
		if len(v.Imsi) < 3 || len(v.Imsi) > 8 {
			if constraintErr := checkDecodedLength(opts, s47bb6e_6, "51.5", "imsi", "SIZE (3..8)", len(v.Imsi)); constraintErr != nil {
				return constraintErr
			}
		}
	}
	// Decode msc-Number
	if offset >= len(content) {
		return fmt.Errorf("missing required field msc-Number")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 1 {
			return fmt.Errorf("expected tag [%s %d] for msc-Number, got %s", "CONTEXT", 1, reqTag_)
		}
	}
	{
		ber.MarkPreflightTarget(opts, "msc-Number", content[offset:])
		decodedTag_mscnumber, n_mscnumber, rawVal_mscnumber, err := ber.DecodeTLV(content[offset:], opts...)
		if err != nil {
			return qualifyBERError(err, "msc-Number", "decoding", false)
		}
		if decodedTag_mscnumber.Class != tag.ClassContextSpecific || decodedTag_mscnumber.Number != 1 {
			return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_mscnumber), "msc-Number", "decoding", false)
		}
		decVal_mscnumber, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_mscnumber.Constructed, rawVal_mscnumber, opts...)
		if octetErr != nil {
			return qualifyBERError(octetErr, "msc-Number", "decoding", false)
		}
		v.MscNumber = ISDNAddressString(decVal_mscnumber)
		if offset < 0 || offset >
			len(content) || n_mscnumber < 0 || n_mscnumber > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n_mscnumber
		if len(v.MscNumber) < 1 || len(v.MscNumber) > 9 {
			if constraintErr := checkDecodedLength(opts, s47bb6e_6, "51.5", "msc-Number", "SIZE (1..9)", len(v.MscNumber)); constraintErr != nil {
				return constraintErr
			}
		}
		if len(v.MscNumber) < 1 || len(v.MscNumber) > 20 {
			if constraintErr := checkDecodedLength(opts, s47bb6e_6, "51.5", "msc-Number", "SIZE (1..20)", len(v.MscNumber)); constraintErr != nil {
				return constraintErr
			}
		}
	}
	// Decode msisdn
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2 {
				ber.MarkPreflightTarget(opts, "msisdn", content[offset:])
				decodedTag_msisdn, n_msisdn, rawVal_msisdn, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "msisdn", "decoding", false)
				}
				if decodedTag_msisdn.Class != tag.ClassContextSpecific || decodedTag_msisdn.Number != 2 {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_msisdn), "msisdn", "decoding", false)
				}
				decVal_msisdn, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_msisdn.Constructed, rawVal_msisdn, opts...)
				if octetErr != nil {
					return qualifyBERError(octetErr, "msisdn", "decoding", false)
				}
				tmp_msisdn := ISDNAddressString(decVal_msisdn)
				v.Msisdn = &tmp_msisdn
				if offset < 0 || offset >
					len(content) || n_msisdn < 0 || n_msisdn > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_msisdn
				if len(*v.Msisdn) < 1 || len(*v.Msisdn) > 9 {
					if constraintErr := checkDecodedLength(opts, s47bb6e_6, "51.5", "msisdn", "SIZE (1..9)", len(*v.Msisdn)); constraintErr != nil {
						return constraintErr
					}
				}
				if len(*v.Msisdn) < 1 || len(*v.Msisdn) > 20 {
					if constraintErr := checkDecodedLength(opts, s47bb6e_6, "51.5", "msisdn", "SIZE (1..20)", len(*v.Msisdn)); constraintErr != nil {
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
				tmp_lmsi := LMSI(decVal_lmsi)
				v.Lmsi = &tmp_lmsi
				if offset < 0 || offset >
					len(content) || n_lmsi < 0 || n_lmsi > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_lmsi
				if len(*v.Lmsi) < 4 || len(*v.Lmsi) > 4 {
					if constraintErr := checkDecodedLength(opts, s47bb6e_6, "51.5", "lmsi", "SIZE (4)", len(*v.Lmsi)); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode gsm-BearerCapability
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 5 {
				ber.MarkPreflightTarget(opts, "gsm-BearerCapability", content[offset:])
				decodedTag_gsmbearercapability, n_gsmbearercapability, rawVal_gsmbearercapability, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "gsm-BearerCapability", "decoding", false)
				}
				if decodedTag_gsmbearercapability.Class != tag.ClassContextSpecific || decodedTag_gsmbearercapability.Number != 5 || decodedTag_gsmbearercapability.Constructed != true {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_gsmbearercapability), "gsm-BearerCapability", "decoding", false)
				}
				_ = rawVal_gsmbearercapability
				if offset < 0 || offset >
					len(content) || n_gsmbearercapability < 0 || n_gsmbearercapability >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				reconstructed_gsmbearercapability, reconstructionErr_gsmbearercapability := ber.EncodeImplicitTagWithClass(tag.ClassUniversal, tag.TagSequence, content[offset:offset+n_gsmbearercapability])
				if reconstructionErr_gsmbearercapability != nil {
					return qualifyBERError(reconstructionErr_gsmbearercapability, "gsm-BearerCapability", "decoding", false)
				}
				var dec_gsmbearercapability ExternalSignalInfo
				if unmErr := dec_gsmbearercapability.UnmarshalBER(reconstructed_gsmbearercapability, ber.ChildDecodeOptions(opts, "gsm-BearerCapability")...); unmErr != nil {
					return qualifyBERError(unmErr, "gsm-BearerCapability", "decoding", false)
				}
				v.GsmBearerCapability = &dec_gsmbearercapability
				if offset < 0 || offset >
					len(content) || n_gsmbearercapability < 0 || n_gsmbearercapability >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_gsmbearercapability
			}
		}
	}
	// Decode networkSignalInfo
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 6 {
				ber.MarkPreflightTarget(opts, "networkSignalInfo", content[offset:])
				decodedTag_networksignalinfo, n_networksignalinfo, rawVal_networksignalinfo, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "networkSignalInfo", "decoding", false)
				}
				if decodedTag_networksignalinfo.Class != tag.ClassContextSpecific || decodedTag_networksignalinfo.Number != 6 || decodedTag_networksignalinfo.Constructed != true {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_networksignalinfo), "networkSignalInfo", "decoding", false)
				}
				_ = rawVal_networksignalinfo
				if offset < 0 || offset >
					len(content) || n_networksignalinfo < 0 || n_networksignalinfo >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				reconstructed_networksignalinfo, reconstructionErr_networksignalinfo := ber.EncodeImplicitTagWithClass(tag.ClassUniversal, tag.TagSequence, content[offset:offset+n_networksignalinfo])
				if reconstructionErr_networksignalinfo != nil {
					return qualifyBERError(reconstructionErr_networksignalinfo, "networkSignalInfo", "decoding", false)
				}
				var dec_networksignalinfo ExternalSignalInfo
				if unmErr := dec_networksignalinfo.UnmarshalBER(reconstructed_networksignalinfo, ber.ChildDecodeOptions(opts, "networkSignalInfo")...); unmErr != nil {
					return qualifyBERError(unmErr, "networkSignalInfo", "decoding", false)
				}
				v.NetworkSignalInfo = &dec_networksignalinfo
				if offset < 0 || offset >
					len(content) || n_networksignalinfo < 0 || n_networksignalinfo >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_networksignalinfo
			}
		}
	}
	// Decode suppressionOfAnnouncement
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 7 {
				ber.MarkPreflightTarget(opts, "suppressionOfAnnouncement", content[offset:])
				decodedTag_suppressionofannouncement, n_suppressionofannouncement, rawVal_suppressionofannouncement, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "suppressionOfAnnouncement", "decoding", false)
				}
				if decodedTag_suppressionofannouncement.Class != tag.ClassContextSpecific || decodedTag_suppressionofannouncement.Number != 7 || decodedTag_suppressionofannouncement.Constructed != false {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_suppressionofannouncement), "suppressionOfAnnouncement", "decoding", false)
				}
				if len(rawVal_suppressionofannouncement) != 0 {
					return qualifyBERError(fmt.Errorf("%w: NULL content length %d", ber.ErrInvalidValue, len(rawVal_suppressionofannouncement)), "suppressionOfAnnouncement", "decoding", false)
				}
				v.SuppressionOfAnnouncement = &struct{}{}
				if offset < 0 || offset >
					len(content) || n_suppressionofannouncement < 0 || n_suppressionofannouncement >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_suppressionofannouncement
			}
		}
	}
	// Decode gmsc-Address
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 8 {
				ber.MarkPreflightTarget(opts, "gmsc-Address", content[offset:])
				decodedTag_gmscaddress, n_gmscaddress, rawVal_gmscaddress, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "gmsc-Address", "decoding", false)
				}
				if decodedTag_gmscaddress.Class != tag.ClassContextSpecific || decodedTag_gmscaddress.Number != 8 {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_gmscaddress), "gmsc-Address", "decoding", false)
				}
				decVal_gmscaddress, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_gmscaddress.Constructed, rawVal_gmscaddress, opts...)
				if octetErr != nil {
					return qualifyBERError(octetErr, "gmsc-Address", "decoding", false)
				}
				tmp_gmscaddress := ISDNAddressString(decVal_gmscaddress)
				v.GmscAddress = &tmp_gmscaddress
				if offset < 0 || offset >
					len(content) || n_gmscaddress < 0 || n_gmscaddress > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_gmscaddress
				if len(*v.GmscAddress) < 1 || len(*v.GmscAddress) > 9 {
					if constraintErr := checkDecodedLength(opts, s47bb6e_6, "51.5", "gmsc-Address", "SIZE (1..9)", len(*v.GmscAddress)); constraintErr != nil {
						return constraintErr
					}
				}
				if len(*v.GmscAddress) < 1 || len(*v.GmscAddress) > 20 {
					if constraintErr := checkDecodedLength(opts, s47bb6e_6, "51.5", "gmsc-Address", "SIZE (1..20)", len(*v.GmscAddress)); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode callReferenceNumber
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 9 {
				ber.MarkPreflightTarget(opts, "callReferenceNumber", content[offset:])
				decodedTag_callreferencenumber, n_callreferencenumber, rawVal_callreferencenumber, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "callReferenceNumber", "decoding", false)
				}
				if decodedTag_callreferencenumber.Class != tag.ClassContextSpecific || decodedTag_callreferencenumber.Number != 9 {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_callreferencenumber), "callReferenceNumber", "decoding", false)
				}
				decVal_callreferencenumber, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_callreferencenumber.Constructed, rawVal_callreferencenumber, opts...)
				if octetErr != nil {
					return qualifyBERError(octetErr, "callReferenceNumber", "decoding", false)
				}
				tmp_callreferencenumber := CallReferenceNumber(decVal_callreferencenumber)
				v.CallReferenceNumber = &tmp_callreferencenumber
				if offset < 0 || offset >
					len(content) || n_callreferencenumber < 0 || n_callreferencenumber >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_callreferencenumber
				if len(*v.CallReferenceNumber) < 1 || len(*v.CallReferenceNumber) > 8 {
					if constraintErr := checkDecodedLength(opts, s47bb6e_6, "51.5", "callReferenceNumber", "SIZE (1..8)", len(*v.CallReferenceNumber)); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode or-Interrogation
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 10 {
				ber.MarkPreflightTarget(opts, "or-Interrogation", content[offset:])
				decodedTag_orinterrogation, n_orinterrogation, rawVal_orinterrogation, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "or-Interrogation", "decoding", false)
				}
				if decodedTag_orinterrogation.Class != tag.ClassContextSpecific || decodedTag_orinterrogation.Number != 10 || decodedTag_orinterrogation.Constructed != false {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_orinterrogation), "or-Interrogation", "decoding", false)
				}
				if len(rawVal_orinterrogation) != 0 {
					return qualifyBERError(fmt.Errorf("%w: NULL content length %d", ber.ErrInvalidValue, len(rawVal_orinterrogation)), "or-Interrogation", "decoding", false)
				}
				v.OrInterrogation = &struct{}{}
				if offset < 0 || offset >
					len(content) || n_orinterrogation < 0 || n_orinterrogation > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_orinterrogation
			}
		}
	}
	// Decode extensionContainer
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 11 {
				ber.MarkPreflightTarget(opts, "extensionContainer", content[offset:])
				decodedTag_extensioncontainer, n_extensioncontainer, rawVal_extensioncontainer, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "extensionContainer", "decoding", false)
				}
				if decodedTag_extensioncontainer.Class != tag.ClassContextSpecific || decodedTag_extensioncontainer.Number != 11 || decodedTag_extensioncontainer.Constructed != true {
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
				var dec_extensioncontainer ExtensionContainer
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
	// Decode alertingPattern
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 12 {
				ber.MarkPreflightTarget(opts, "alertingPattern", content[offset:])
				decodedTag_alertingpattern, n_alertingpattern, rawVal_alertingpattern, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "alertingPattern", "decoding", false)
				}
				if decodedTag_alertingpattern.Class != tag.ClassContextSpecific || decodedTag_alertingpattern.Number != 12 {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_alertingpattern), "alertingPattern", "decoding", false)
				}
				decVal_alertingpattern, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_alertingpattern.Constructed, rawVal_alertingpattern, opts...)
				if octetErr != nil {
					return qualifyBERError(octetErr, "alertingPattern", "decoding", false)
				}
				tmp_alertingpattern := AlertingPattern(decVal_alertingpattern)
				v.AlertingPattern = &tmp_alertingpattern
				if offset < 0 || offset >
					len(content) || n_alertingpattern < 0 || n_alertingpattern > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_alertingpattern
				if len(*v.AlertingPattern) < 1 || len(*v.AlertingPattern) > 1 {
					if constraintErr := checkDecodedLength(opts, s47bb6e_6, "51.5", "alertingPattern", "SIZE (1)", len(*v.AlertingPattern)); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode ccbs-Call
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 13 {
				ber.MarkPreflightTarget(opts, "ccbs-Call", content[offset:])
				decodedTag_ccbscall, n_ccbscall, rawVal_ccbscall, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "ccbs-Call", "decoding", false)
				}
				if decodedTag_ccbscall.Class != tag.ClassContextSpecific || decodedTag_ccbscall.Number != 13 || decodedTag_ccbscall.Constructed != false {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_ccbscall), "ccbs-Call", "decoding", false)
				}
				if len(rawVal_ccbscall) != 0 {
					return qualifyBERError(fmt.Errorf("%w: NULL content length %d", ber.ErrInvalidValue, len(rawVal_ccbscall)), "ccbs-Call", "decoding", false)
				}
				v.CcbsCall = &struct{}{}
				if offset < 0 || offset >
					len(content) || n_ccbscall < 0 || n_ccbscall > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_ccbscall
			}
		}
	}
	// Decode supportedCamelPhasesInInterrogatingNode
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 15 {
				ber.MarkPreflightTarget(opts, "supportedCamelPhasesInInterrogatingNode", content[offset:])
				decodedTag_supportedcamelphasesininterrogatingnode, n_supportedcamelphasesininterrogatingnode, rawVal_supportedcamelphasesininterrogatingnode, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "supportedCamelPhasesInInterrogatingNode", "decoding", false)
				}
				if decodedTag_supportedcamelphasesininterrogatingnode.Class != tag.ClassContextSpecific || decodedTag_supportedcamelphasesininterrogatingnode.Number != 15 {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_supportedcamelphasesininterrogatingnode), "supportedCamelPhasesInInterrogatingNode", "decoding", false)
				}
				bsBytes_supportedcamelphasesininterrogatingnode, bsUnused_supportedcamelphasesininterrogatingnode, bsErr := ber.DecodeImplicitBitStringValue(decodedTag_supportedcamelphasesininterrogatingnode.Constructed, rawVal_supportedcamelphasesininterrogatingnode, opts...)
				if bsErr != nil {
					return qualifyBERError(bsErr, "supportedCamelPhasesInInterrogatingNode", "decoding", false)
				}
				bsBitLength_supportedcamelphasesininterrogatingnode, bsLenErr_supportedcamelphasesininterrogatingnode := ber.BitStringBitLength(len(bsBytes_supportedcamelphasesininterrogatingnode), bsUnused_supportedcamelphasesininterrogatingnode)
				if bsLenErr_supportedcamelphasesininterrogatingnode != nil {
					return qualifyBERError(bsLenErr_supportedcamelphasesininterrogatingnode, "supportedCamelPhasesInInterrogatingNode", "decoding", false)
				}
				tmp_supportedcamelphasesininterrogatingnode := runtime.BitString{Bytes: bsBytes_supportedcamelphasesininterrogatingnode, BitLength: bsBitLength_supportedcamelphasesininterrogatingnode}
				v.SupportedCamelPhasesInInterrogatingNode = &tmp_supportedcamelphasesininterrogatingnode
				if offset < 0 || offset >
					len(content) || n_supportedcamelphasesininterrogatingnode < 0 ||
					n_supportedcamelphasesininterrogatingnode > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_supportedcamelphasesininterrogatingnode
				*v.SupportedCamelPhasesInInterrogatingNode = ber.NormalizeNamedBitStringSize(*v.SupportedCamelPhasesInInterrogatingNode, []ber.NamedBitSizeSet{{{Min: 1, Max: 16}}}, opts...)
				if (*v.SupportedCamelPhasesInInterrogatingNode).BitLength < 1 || (*v.SupportedCamelPhasesInInterrogatingNode).BitLength > 16 {
					if constraintErr := checkDecodedLength(opts, s47bb6e_6, "51.5", "supportedCamelPhasesInInterrogatingNode", "SIZE (1..16)", (*v.SupportedCamelPhasesInInterrogatingNode).BitLength); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode additionalSignalInfo
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 14 {
				ber.MarkPreflightTarget(opts, "additionalSignalInfo", content[offset:])
				decodedTag_additionalsignalinfo, n_additionalsignalinfo, rawVal_additionalsignalinfo, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "additionalSignalInfo", "decoding", false)
				}
				if decodedTag_additionalsignalinfo.Class != tag.ClassContextSpecific || decodedTag_additionalsignalinfo.Number != 14 || decodedTag_additionalsignalinfo.Constructed != true {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_additionalsignalinfo), "additionalSignalInfo", "decoding", false)
				}
				_ = rawVal_additionalsignalinfo
				if offset < 0 || offset >
					len(content) || n_additionalsignalinfo < 0 || n_additionalsignalinfo >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				reconstructed_additionalsignalinfo, reconstructionErr_additionalsignalinfo := ber.EncodeImplicitTagWithClass(tag.ClassUniversal, tag.TagSequence, content[offset:offset+n_additionalsignalinfo])
				if reconstructionErr_additionalsignalinfo != nil {
					return qualifyBERError(reconstructionErr_additionalsignalinfo, "additionalSignalInfo", "decoding", false)
				}
				var dec_additionalsignalinfo ExtExternalSignalInfo
				if unmErr := dec_additionalsignalinfo.UnmarshalBER(reconstructed_additionalsignalinfo, ber.ChildDecodeOptions(opts, "additionalSignalInfo")...); unmErr != nil {
					return qualifyBERError(unmErr, "additionalSignalInfo", "decoding", false)
				}
				v.AdditionalSignalInfo = &dec_additionalsignalinfo
				if offset < 0 || offset >
					len(content) || n_additionalsignalinfo < 0 || n_additionalsignalinfo >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_additionalsignalinfo
			}
		}
	}
	// Decode orNotSupportedInGMSC
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 16 {
				ber.MarkPreflightTarget(opts, "orNotSupportedInGMSC", content[offset:])
				decodedTag_ornotsupportedingmsc, n_ornotsupportedingmsc, rawVal_ornotsupportedingmsc, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "orNotSupportedInGMSC", "decoding", false)
				}
				if decodedTag_ornotsupportedingmsc.Class != tag.ClassContextSpecific || decodedTag_ornotsupportedingmsc.Number != 16 || decodedTag_ornotsupportedingmsc.Constructed != false {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_ornotsupportedingmsc), "orNotSupportedInGMSC", "decoding", false)
				}
				if len(rawVal_ornotsupportedingmsc) != 0 {
					return qualifyBERError(fmt.Errorf("%w: NULL content length %d", ber.ErrInvalidValue, len(rawVal_ornotsupportedingmsc)), "orNotSupportedInGMSC", "decoding", false)
				}
				v.OrNotSupportedInGMSC = &struct{}{}
				if offset < 0 || offset >
					len(content) || n_ornotsupportedingmsc < 0 || n_ornotsupportedingmsc >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_ornotsupportedingmsc
			}
		}
	}
	// Decode pre-pagingSupported
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 17 {
				ber.MarkPreflightTarget(opts, "pre-pagingSupported", content[offset:])
				decodedTag_prepagingsupported, n_prepagingsupported, rawVal_prepagingsupported, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "pre-pagingSupported", "decoding", false)
				}
				if decodedTag_prepagingsupported.Class != tag.ClassContextSpecific || decodedTag_prepagingsupported.Number != 17 || decodedTag_prepagingsupported.Constructed != false {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_prepagingsupported), "pre-pagingSupported", "decoding", false)
				}
				if len(rawVal_prepagingsupported) != 0 {
					return qualifyBERError(fmt.Errorf("%w: NULL content length %d", ber.ErrInvalidValue, len(rawVal_prepagingsupported)), "pre-pagingSupported", "decoding", false)
				}
				v.PrePagingSupported = &struct{}{}
				if offset < 0 || offset >
					len(content) || n_prepagingsupported < 0 || n_prepagingsupported >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_prepagingsupported
			}
		}
	}
	// Decode longFTN-Supported
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 18 {
				ber.MarkPreflightTarget(opts, "longFTN-Supported", content[offset:])
				decodedTag_longftnsupported, n_longftnsupported, rawVal_longftnsupported, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "longFTN-Supported", "decoding", false)
				}
				if decodedTag_longftnsupported.Class != tag.ClassContextSpecific || decodedTag_longftnsupported.Number != 18 || decodedTag_longftnsupported.Constructed != false {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_longftnsupported), "longFTN-Supported", "decoding", false)
				}
				if len(rawVal_longftnsupported) != 0 {
					return qualifyBERError(fmt.Errorf("%w: NULL content length %d", ber.ErrInvalidValue, len(rawVal_longftnsupported)), "longFTN-Supported", "decoding", false)
				}
				v.LongFTNSupported = &struct{}{}
				if offset < 0 || offset >
					len(content) || n_longftnsupported < 0 || n_longftnsupported > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_longftnsupported
			}
		}
	}
	// Decode suppress-VT-CSI
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 19 {
				ber.MarkPreflightTarget(opts, "suppress-VT-CSI", content[offset:])
				decodedTag_suppressvtcsi, n_suppressvtcsi, rawVal_suppressvtcsi, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "suppress-VT-CSI", "decoding", false)
				}
				if decodedTag_suppressvtcsi.Class != tag.ClassContextSpecific || decodedTag_suppressvtcsi.Number != 19 || decodedTag_suppressvtcsi.Constructed != false {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_suppressvtcsi), "suppress-VT-CSI", "decoding", false)
				}
				if len(rawVal_suppressvtcsi) != 0 {
					return qualifyBERError(fmt.Errorf("%w: NULL content length %d", ber.ErrInvalidValue, len(rawVal_suppressvtcsi)), "suppress-VT-CSI", "decoding", false)
				}
				v.SuppressVTCSI = &struct{}{}
				if offset < 0 || offset >
					len(content) || n_suppressvtcsi < 0 || n_suppressvtcsi > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_suppressvtcsi
			}
		}
	}
	// Decode offeredCamel4CSIsInInterrogatingNode
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 20 {
				ber.MarkPreflightTarget(opts, "offeredCamel4CSIsInInterrogatingNode", content[offset:])
				decodedTag_offeredcamel4csisininterrogatingnode, n_offeredcamel4csisininterrogatingnode, rawVal_offeredcamel4csisininterrogatingnode, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "offeredCamel4CSIsInInterrogatingNode", "decoding", false)
				}
				if decodedTag_offeredcamel4csisininterrogatingnode.Class != tag.ClassContextSpecific || decodedTag_offeredcamel4csisininterrogatingnode.Number != 20 {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_offeredcamel4csisininterrogatingnode), "offeredCamel4CSIsInInterrogatingNode", "decoding", false)
				}
				bsBytes_offeredcamel4csisininterrogatingnode, bsUnused_offeredcamel4csisininterrogatingnode, bsErr := ber.DecodeImplicitBitStringValue(decodedTag_offeredcamel4csisininterrogatingnode.Constructed, rawVal_offeredcamel4csisininterrogatingnode, opts...)
				if bsErr != nil {
					return qualifyBERError(bsErr, "offeredCamel4CSIsInInterrogatingNode", "decoding", false)
				}
				bsBitLength_offeredcamel4csisininterrogatingnode, bsLenErr_offeredcamel4csisininterrogatingnode := ber.BitStringBitLength(len(bsBytes_offeredcamel4csisininterrogatingnode), bsUnused_offeredcamel4csisininterrogatingnode)
				if bsLenErr_offeredcamel4csisininterrogatingnode != nil {
					return qualifyBERError(bsLenErr_offeredcamel4csisininterrogatingnode, "offeredCamel4CSIsInInterrogatingNode", "decoding", false)
				}
				tmp_offeredcamel4csisininterrogatingnode := runtime.BitString{Bytes: bsBytes_offeredcamel4csisininterrogatingnode, BitLength: bsBitLength_offeredcamel4csisininterrogatingnode}
				v.OfferedCamel4CSIsInInterrogatingNode = &tmp_offeredcamel4csisininterrogatingnode
				if offset < 0 || offset >
					len(content) || n_offeredcamel4csisininterrogatingnode < 0 || n_offeredcamel4csisininterrogatingnode >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_offeredcamel4csisininterrogatingnode
				*v.OfferedCamel4CSIsInInterrogatingNode = ber.NormalizeNamedBitStringSize(*v.OfferedCamel4CSIsInInterrogatingNode, []ber.NamedBitSizeSet{{{Min: 7, Max: 16}}}, opts...)
				if (*v.OfferedCamel4CSIsInInterrogatingNode).BitLength < 7 || (*v.OfferedCamel4CSIsInInterrogatingNode).BitLength > 16 {
					if constraintErr := checkDecodedLength(opts, s47bb6e_6, "51.5", "offeredCamel4CSIsInInterrogatingNode", "SIZE (7..16)", (*v.OfferedCamel4CSIsInInterrogatingNode).BitLength); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode mtRoamingRetrySupported
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 21 {
				ber.MarkPreflightTarget(opts, "mtRoamingRetrySupported", content[offset:])
				decodedTag_mtroamingretrysupported, n_mtroamingretrysupported, rawVal_mtroamingretrysupported, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "mtRoamingRetrySupported", "decoding", false)
				}
				if decodedTag_mtroamingretrysupported.Class != tag.ClassContextSpecific || decodedTag_mtroamingretrysupported.Number != 21 || decodedTag_mtroamingretrysupported.Constructed != false {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_mtroamingretrysupported), "mtRoamingRetrySupported", "decoding", false)
				}
				if len(rawVal_mtroamingretrysupported) != 0 {
					return qualifyBERError(fmt.Errorf("%w: NULL content length %d", ber.ErrInvalidValue, len(rawVal_mtroamingretrysupported)), "mtRoamingRetrySupported", "decoding", false)
				}
				v.MtRoamingRetrySupported = &struct{}{}
				if offset < 0 || offset >
					len(content) || n_mtroamingretrysupported < 0 || n_mtroamingretrysupported >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_mtroamingretrysupported
			}
		}
	}
	// Decode pagingArea
	v.berPagingAreaIndef_ = false
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 22 {
				ber.MarkPreflightTarget(opts, "pagingArea", content[offset:])
				decodedTag_pagingarea, n_pagingarea, rawVal_pagingarea, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "pagingArea", "decoding", false)
				}
				if decodedTag_pagingarea.Class != tag.ClassContextSpecific || decodedTag_pagingarea.Number != 22 || decodedTag_pagingarea.Constructed != true {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_pagingarea), "pagingArea", "decoding", false)
				}
				_ = rawVal_pagingarea
				if offset < 0 || offset >
					len(content) || n_pagingarea < 0 || n_pagingarea > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				reconstructed_pagingarea, reconstructionErr_pagingarea := ber.EncodeImplicitTagWithClass(tag.ClassUniversal, tag.TagSequence, content[offset:offset+n_pagingarea])
				if reconstructionErr_pagingarea != nil {
					return qualifyBERError(reconstructionErr_pagingarea, "pagingArea", "decoding", false)
				}
				dec_pagingarea, unmErr := UnmarshalBERPagingArea(reconstructed_pagingarea, ber.ParentCollectionSizeDecodeOptions(ber.ChildDecodeOptions(opts, "pagingArea"))...)
				if unmErr != nil {
					return qualifyBERError(unmErr, "pagingArea", "decoding", false)
				}
				v.PagingArea = dec_pagingarea
				{
					_, tagSz_, _ := ber.DecodeTag(content[offset:])
					if offset < 0 || offset >
						len(content) || tagSz_ < 0 || tagSz_ > len(content[offset:]) {
						return fmt.Errorf("invalid BER content window")
					}

					if offset+tagSz_ < len(content) && content[offset+tagSz_] == 0x80 {
						v.berPagingAreaIndef_ = true
					}
				}
				if offset < 0 || offset >
					len(content) || n_pagingarea < 0 || n_pagingarea > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_pagingarea
				if len((v.PagingArea).Values) < 1 || len((v.PagingArea).Values) > 5 {
					if constraintErr := checkDecodedLength(opts, s47bb6e_6, "51.5", "pagingArea", "SIZE (1..5)", len((v.PagingArea).Values)); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode callPriority
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 23 {
				ber.MarkPreflightTarget(opts, "callPriority", content[offset:])
				decodedTag_callpriority, n_callpriority, rawVal_callpriority, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "callPriority", "decoding", false)
				}
				if decodedTag_callpriority.Class != tag.ClassContextSpecific || decodedTag_callpriority.Number != 23 || decodedTag_callpriority.Constructed != false {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_callpriority), "callPriority", "decoding", false)
				}
				decVal_callpriority, intErr := ber.DecodeIntegerValue(rawVal_callpriority)
				if intErr != nil {
					return qualifyBERError(intErr, "callPriority", "decoding", false)
				}
				tmp_callpriority := EMLPPPriority(decVal_callpriority)
				v.CallPriority = &tmp_callpriority
				if offset < 0 || offset >
					len(content) || n_callpriority < 0 || n_callpriority > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_callpriority
				if !(int64(*v.CallPriority) >= 0 && int64(*v.CallPriority) <= 15) {
					if constraintErr := checkDecodedValue(opts, s47bb6e_6, "51.4", "callPriority", "(0..15)", ber.ObserveInteger(int64(*v.CallPriority))); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode mtrf-Indicator
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 24 {
				ber.MarkPreflightTarget(opts, "mtrf-Indicator", content[offset:])
				decodedTag_mtrfindicator, n_mtrfindicator, rawVal_mtrfindicator, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "mtrf-Indicator", "decoding", false)
				}
				if decodedTag_mtrfindicator.Class != tag.ClassContextSpecific || decodedTag_mtrfindicator.Number != 24 || decodedTag_mtrfindicator.Constructed != false {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_mtrfindicator), "mtrf-Indicator", "decoding", false)
				}
				if len(rawVal_mtrfindicator) != 0 {
					return qualifyBERError(fmt.Errorf("%w: NULL content length %d", ber.ErrInvalidValue, len(rawVal_mtrfindicator)), "mtrf-Indicator", "decoding", false)
				}
				v.MtrfIndicator = &struct{}{}
				if offset < 0 || offset >
					len(content) || n_mtrfindicator < 0 || n_mtrfindicator > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_mtrfindicator
			}
		}
	}
	// Decode oldMSC-Number
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 25 {
				ber.MarkPreflightTarget(opts, "oldMSC-Number", content[offset:])
				decodedTag_oldmscnumber, n_oldmscnumber, rawVal_oldmscnumber, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "oldMSC-Number", "decoding", false)
				}
				if decodedTag_oldmscnumber.Class != tag.ClassContextSpecific || decodedTag_oldmscnumber.Number != 25 {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_oldmscnumber), "oldMSC-Number", "decoding", false)
				}
				decVal_oldmscnumber, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_oldmscnumber.Constructed, rawVal_oldmscnumber, opts...)
				if octetErr != nil {
					return qualifyBERError(octetErr, "oldMSC-Number", "decoding", false)
				}
				tmp_oldmscnumber := ISDNAddressString(decVal_oldmscnumber)
				v.OldMSCNumber = &tmp_oldmscnumber
				if offset < 0 || offset >
					len(content) || n_oldmscnumber < 0 || n_oldmscnumber > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_oldmscnumber
				if len(*v.OldMSCNumber) < 1 || len(*v.OldMSCNumber) > 9 {
					if constraintErr := checkDecodedLength(opts, s47bb6e_6, "51.5", "oldMSC-Number", "SIZE (1..9)", len(*v.OldMSCNumber)); constraintErr != nil {
						return constraintErr
					}
				}
				if len(*v.OldMSCNumber) < 1 || len(*v.OldMSCNumber) > 20 {
					if constraintErr := checkDecodedLength(opts, s47bb6e_6, "51.5", "oldMSC-Number", "SIZE (1..20)", len(*v.OldMSCNumber)); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode lastUsedLtePLMN-Id
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 26 {
				ber.MarkPreflightTarget(opts, "lastUsedLtePLMN-Id", content[offset:])
				decodedTag_lastusedlteplmnid, n_lastusedlteplmnid, rawVal_lastusedlteplmnid, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "lastUsedLtePLMN-Id", "decoding", false)
				}
				if decodedTag_lastusedlteplmnid.Class != tag.ClassContextSpecific || decodedTag_lastusedlteplmnid.Number != 26 {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_lastusedlteplmnid), "lastUsedLtePLMN-Id", "decoding", false)
				}
				decVal_lastusedlteplmnid, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_lastusedlteplmnid.Constructed, rawVal_lastusedlteplmnid, opts...)
				if octetErr != nil {
					return qualifyBERError(octetErr, "lastUsedLtePLMN-Id", "decoding", false)
				}
				tmp_lastusedlteplmnid := PLMNId(decVal_lastusedlteplmnid)
				v.LastUsedLtePLMNId = &tmp_lastusedlteplmnid
				if offset < 0 || offset >
					len(content) || n_lastusedlteplmnid < 0 || n_lastusedlteplmnid >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_lastusedlteplmnid
				if len(*v.LastUsedLtePLMNId) < 3 || len(*v.LastUsedLtePLMNId) > 3 {
					if constraintErr := checkDecodedLength(opts, s47bb6e_6, "51.5", "lastUsedLtePLMN-Id", "SIZE (3)", len(*v.LastUsedLtePLMNId)); constraintErr != nil {
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
			return &ber.DecodeError{Offset: offset, TypeName: "ProvideRoamingNumberArg", Cause: extErr_}
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: the first unknown addition must differ from trailing OPTIONAL/DEFAULT tags.
		if len(v.ExtData_) == 0 && ((peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 26) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 25) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 24) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 23) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 22) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 21) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 20) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 19) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 18) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 17) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 16) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 14) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 15) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 13) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 12) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 11) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 10) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 9) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 8) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 7) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 6) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 5) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2)) {
			if !ber.ToleranceEnabled(opts) {
				return &ber.DecodeError{Offset: offset, TypeName: "ProvideRoamingNumberArg", Cause: fmt.Errorf("%w: repeated or out-of-order SEQUENCE component tag %s", ber.ErrInvalidTag, peekTag)}
			}
			if orderErr_ := ber.CheckDecodedValue(ber.DecodeRule(opts, s47bb6e_6, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), fmt.Sprintf("ExtData_[%d]", len(v.ExtData_)), "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); orderErr_ != nil {
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

// MarshalBER encodes ProvideRoamingNumberRes to BER format.
func (v *ProvideRoamingNumberRes) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {

	if v == nil {
		return nil, fmt.Errorf("%w: ProvideRoamingNumberRes receiver is nil", ber.ErrInvalidValue)
	}
	return marshalFramedValue(v, v.berReplayNode_, opts, (*ProvideRoamingNumberRes).MarshalBER, (*ProvideRoamingNumberRes).marshalBER, 3)

}
func (v *ProvideRoamingNumberRes) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if len(v.RoamingNumber) < 1 || len(v.RoamingNumber) > 9 {
		if constraintErr := checkEncodedLength(opts, s47bb6e_7, "51.5", "roamingNumber", "SIZE (1..9)", len(v.RoamingNumber)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	if len(v.RoamingNumber) < 1 || len(v.RoamingNumber) > 20 {
		if constraintErr := checkEncodedLength(opts, s47bb6e_7, "51.5", "roamingNumber", "SIZE (1..20)", len(v.RoamingNumber)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_roamingnumber, encodeErr_enc_roamingnumber := ber.EncodeOctetString([]byte(v.RoamingNumber))
	if encodeErr_enc_roamingnumber != nil {
		return nil, qualifyBERError(encodeErr_enc_roamingnumber, "roamingNumber", "encoding", false)
	}
	children = append(children, enc_roamingnumber...)
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalBER(ber.ChildEncodeOptions(opts, "extensionContainer")...)
		if err != nil {
			return nil, qualifyBERError(err, "extensionContainer", "encoding", false)
		}
		ber.RecordGeneratedBERChildPlacement(opts, len(children), enc_extensioncontainer)
		children = append(children, enc_extensioncontainer...)
	}
	if v.ReleaseResourcesSupported != nil {
		enc_releaseresourcessupported := ber.EncodeNull()
		children = append(children, enc_releaseresourcessupported...)
	}
	if v.VmscAddress != nil {
		if len(*v.VmscAddress) < 1 || len(*v.VmscAddress) > 9 {
			if constraintErr := checkEncodedLength(opts, s47bb6e_7, "51.5", "vmsc-Address", "SIZE (1..9)", len(*v.VmscAddress)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		if len(*v.VmscAddress) < 1 || len(*v.VmscAddress) > 20 {
			if constraintErr := checkEncodedLength(opts, s47bb6e_7, "51.5", "vmsc-Address", "SIZE (1..20)", len(*v.VmscAddress)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_vmscaddress, encodeErr_enc_vmscaddress := ber.EncodeOctetString([]byte(*v.VmscAddress))
		if encodeErr_enc_vmscaddress != nil {
			return nil, qualifyBERError(encodeErr_enc_vmscaddress, "vmsc-Address", "encoding", false)
		}
		children = append(children, enc_vmscaddress...)
	}
	base_ := -1
	for i, ext := range v.ExtData_ {
		if err := checkOpaqueAddition(ext, opts, s47bb6e_7, children, i, &base_); err != nil {
			return nil, opaqueExtensionError(err, i)
		}
		peekTag, n, _, extErr := ber.DecodeEncodedTLV(ext)
		if extErr != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, extErr)
		}
		if n != len(ext) {
			return nil, fmt.Errorf("encoding extension %d: %w", i, ber.ErrExtraData)
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: only the first addition is restricted.
		if i == 0 && ((peekTag.Class == tag.ClassUniversal && peekTag.Number == 4) || (peekTag.Class == tag.ClassUniversal && peekTag.Number == 5) || (peekTag.Class == tag.ClassUniversal && peekTag.Number == 16)) {
			if constraintErr := ber.CheckEncodedValue(ber.EncodeRule(opts, s47bb6e_7, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
				return nil, constraintErr
			}
		}
		children = append(children, ext...)
	}
	ber.RecordGeneratedBERContainer(opts, children)
	return ber.EncodeSequence(children)
}
func (v *ProvideRoamingNumberRes) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// MarshalDER encodes ProvideRoamingNumberRes to DER format.
// Opaque descendants pass generic DER checks; foreign schema rules need a typed binding.
func (v *ProvideRoamingNumberRes) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: ProvideRoamingNumberRes receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if len(v.RoamingNumber) < 1 || len(v.RoamingNumber) > 9 {
		if constraintErr := checkEncodedLength(nil, s47bb6e_7, "51.5", "roamingNumber", "SIZE (1..9)", len(v.RoamingNumber)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	if len(v.RoamingNumber) < 1 || len(v.RoamingNumber) > 20 {
		if constraintErr := checkEncodedLength(nil, s47bb6e_7, "51.5", "roamingNumber", "SIZE (1..20)", len(v.RoamingNumber)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_roamingnumber, encodeErr_enc_roamingnumber := ber.EncodeOctetString([]byte(v.RoamingNumber))
	if encodeErr_enc_roamingnumber != nil {
		return nil, qualifyBERError(encodeErr_enc_roamingnumber, "roamingNumber", "encoding", true)
	}
	children = append(children, enc_roamingnumber...)
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalDER()
		if err != nil {
			return nil, qualifyBERError(err, "extensionContainer", "encoding", true)
		}
		children = append(children, enc_extensioncontainer...)
	}
	if v.ReleaseResourcesSupported != nil {
		enc_releaseresourcessupported := ber.EncodeNull()
		children = append(children, enc_releaseresourcessupported...)
	}
	if v.VmscAddress != nil {
		if len(*v.VmscAddress) < 1 || len(*v.VmscAddress) > 9 {
			if constraintErr := checkEncodedLength(nil, s47bb6e_7, "51.5", "vmsc-Address", "SIZE (1..9)", len(*v.VmscAddress)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		if len(*v.VmscAddress) < 1 || len(*v.VmscAddress) > 20 {
			if constraintErr := checkEncodedLength(nil, s47bb6e_7, "51.5", "vmsc-Address", "SIZE (1..20)", len(*v.VmscAddress)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_vmscaddress, encodeErr_enc_vmscaddress := ber.EncodeOctetString([]byte(*v.VmscAddress))
		if encodeErr_enc_vmscaddress != nil {
			return nil, qualifyBERError(encodeErr_enc_vmscaddress, "vmsc-Address", "encoding", true)
		}
		children = append(children, enc_vmscaddress...)
	}
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDEREncodedElement(ext); err != nil {
			return nil, invalidDERAddition(ext, s47bb6e_7, children, i)
		}
		peekTag, _, _, extErr := ber.DecodeEncodedTLV(ext)
		if extErr != nil {
			return nil, extErr
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: only the first addition is restricted.
		if i == 0 && ((peekTag.Class == tag.ClassUniversal && peekTag.Number == 4) || (peekTag.Class == tag.ClassUniversal && peekTag.Number == 5) || (peekTag.Class == tag.ClassUniversal && peekTag.Number == 16)) {
			if constraintErr := ber.CheckEncodedValue(ber.EncodeRule(nil, s47bb6e_7, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
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
		return nil, fmt.Errorf("%s: %w", "encoding ProvideRoamingNumberRes as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}
func (v *ProvideRoamingNumberRes) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	encoded, err := v.MarshalDER()
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBER decodes ProvideRoamingNumberRes from BER/DER format.
func (destination *ProvideRoamingNumberRes) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if destination == nil {
		return fmt.Errorf("%w: ProvideRoamingNumberRes destination is nil", ber.ErrInvalidValue)
	}
	v := new(ProvideRoamingNumberRes)

	defer publishDecodedValue(destination, v, &returnErr)

	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	preparedData, preparedOptions, prepareErr := prepareCompositeBER(data, opts, s47bb6e_7, "child", (*ProvideRoamingNumberRes).UnmarshalBER)
	if prepareErr != nil {
		return prepareErr
	}
	data, opts = preparedData, preparedOptions

	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
	*v = ProvideRoamingNumberRes{}
	defer func() {
		if returnErr == nil {
			returnErr = completeValueBER(data,
				opts, v, &v.berReplayNode_, (*ProvideRoamingNumberRes).MarshalBER)
		}

	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("%s: %w", "decoding ProvideRoamingNumberRes SEQUENCE", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "ProvideRoamingNumberRes", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode roamingNumber
	if offset >= len(content) {
		return fmt.Errorf("missing required field roamingNumber")
	}
	{
		ber.MarkPreflightTarget(opts, "roamingNumber", content[offset:])
		val_roamingnumber, n, err := ber.DecodeOctetString(content[offset:], opts...)
		if err != nil {
			return qualifyBERError(err, "roamingNumber", "decoding", false)
		}
		v.RoamingNumber = ISDNAddressString(val_roamingnumber)
		if offset > len(content) || n < 0 || n > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n
		if len(v.RoamingNumber) < 1 || len(v.RoamingNumber) > 9 {
			if constraintErr := checkDecodedLength(opts, s47bb6e_7, "51.5", "roamingNumber", "SIZE (1..9)", len(v.RoamingNumber)); constraintErr != nil {
				return constraintErr
			}
		}
		if len(v.RoamingNumber) < 1 || len(v.RoamingNumber) > 20 {
			if constraintErr := checkDecodedLength(opts, s47bb6e_7, "51.5", "roamingNumber", "SIZE (1..20)", len(v.RoamingNumber)); constraintErr != nil {
				return constraintErr
			}
		}
	}
	// Decode extensionContainer
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassUniversal && peekTag.Number == 16 {
				ber.MarkPreflightTarget(opts, "extensionContainer", content[offset:])
				// Decode nested SEQUENCE (ExtensionContainer)
				_, n_extensioncontainer, _, tlvErr_extensioncontainer := ber.DecodeTLV(content[offset:], opts...)
				if tlvErr_extensioncontainer != nil {
					return qualifyBERError(tlvErr_extensioncontainer, "extensionContainer", "decoding", false)
				}
				var dec_extensioncontainer ExtensionContainer
				if offset < 0 || offset >
					len(content) || n_extensioncontainer < 0 || n_extensioncontainer >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				if unmErr := dec_extensioncontainer.UnmarshalBER(content[offset:offset+n_extensioncontainer], ber.ChildDecodeOptions(opts, "extensionContainer")...); unmErr != nil {
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
	// Decode releaseResourcesSupported
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassUniversal && peekTag.Number == 5 {
				ber.MarkPreflightTarget(opts, "releaseResourcesSupported", content[offset:])
				n, err := ber.DecodeNull(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "releaseResourcesSupported", "decoding", false)
				}
				v.ReleaseResourcesSupported = &struct{}{}
				if offset < 0 || offset >
					len(content) || n < 0 || n > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n
			}
		}
	}
	// Decode vmsc-Address
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassUniversal && peekTag.Number == 4 {
				ber.MarkPreflightTarget(opts, "vmsc-Address", content[offset:])
				val_vmscaddress, n, err := ber.DecodeOctetString(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "vmsc-Address", "decoding", false)
				}
				tmp_vmscaddress := ISDNAddressString(val_vmscaddress)
				v.VmscAddress = &tmp_vmscaddress
				if offset < 0 || offset >
					len(content) || n < 0 || n > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n
				if len(*v.VmscAddress) < 1 || len(*v.VmscAddress) > 9 {
					if constraintErr := checkDecodedLength(opts, s47bb6e_7, "51.5", "vmsc-Address", "SIZE (1..9)", len(*v.VmscAddress)); constraintErr != nil {
						return constraintErr
					}
				}
				if len(*v.VmscAddress) < 1 || len(*v.VmscAddress) > 20 {
					if constraintErr := checkDecodedLength(opts, s47bb6e_7, "51.5", "vmsc-Address", "SIZE (1..20)", len(*v.VmscAddress)); constraintErr != nil {
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
			return &ber.DecodeError{Offset: offset, TypeName: "ProvideRoamingNumberRes", Cause: extErr_}
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: the first unknown addition must differ from trailing OPTIONAL/DEFAULT tags.
		if len(v.ExtData_) == 0 && ((peekTag.Class == tag.ClassUniversal && peekTag.Number == 4) || (peekTag.Class == tag.ClassUniversal && peekTag.Number == 5) || (peekTag.Class == tag.ClassUniversal && peekTag.Number == 16)) {
			if !ber.ToleranceEnabled(opts) {
				return &ber.DecodeError{Offset: offset, TypeName: "ProvideRoamingNumberRes", Cause: fmt.Errorf("%w: repeated or out-of-order SEQUENCE component tag %s", ber.ErrInvalidTag, peekTag)}
			}
			if orderErr_ := ber.CheckDecodedValue(ber.DecodeRule(opts, s47bb6e_7, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), fmt.Sprintf("ExtData_[%d]", len(v.ExtData_)), "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); orderErr_ != nil {
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

// MarshalBER encodes ResumeCallHandlingArg to BER format.
func (v *ResumeCallHandlingArg) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {

	if v == nil {
		return nil, fmt.Errorf("%w: ResumeCallHandlingArg receiver is nil", ber.ErrInvalidValue)
	}
	return marshalFramedValue(v, v.berReplayNode_, opts, (*ResumeCallHandlingArg).MarshalBER, (*ResumeCallHandlingArg).marshalBER, 3)

}
func (v *ResumeCallHandlingArg) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if v.CallReferenceNumber != nil {
		if len(*v.CallReferenceNumber) < 1 || len(*v.CallReferenceNumber) > 8 {
			if constraintErr := checkEncodedLength(opts, s47bb6e_8, "51.5", "callReferenceNumber", "SIZE (1..8)", len(*v.CallReferenceNumber)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_callreferencenumber, encodeErr_enc_callreferencenumber := ber.EncodeOctetString([]byte(*v.CallReferenceNumber))
		if encodeErr_enc_callreferencenumber != nil {
			return nil, qualifyBERError(encodeErr_enc_callreferencenumber, "callReferenceNumber", "encoding", false)
		}
		retagged_enc_callreferencenumber, tagErr_enc_callreferencenumber := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_callreferencenumber)
		if tagErr_enc_callreferencenumber != nil {
			return nil, qualifyBERError(tagErr_enc_callreferencenumber, "callReferenceNumber", "encoding", false)
		}
		enc_callreferencenumber = retagged_enc_callreferencenumber
		children = append(children, enc_callreferencenumber...)
	}
	if v.BasicServiceGroup != nil {
		enc_basicservicegroup, err := v.BasicServiceGroup.MarshalBER(ber.ChildEncodeOptions(opts, "basicServiceGroup")...)
		if err != nil {
			return nil, qualifyBERError(err, "basicServiceGroup", "encoding", false)
		}
		{
			var encodeErr error
			enc_basicservicegroup, encodeErr = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 1, enc_basicservicegroup)
			if encodeErr != nil {
				return nil, qualifyBERError(encodeErr, "basicServiceGroup", "encoding", false)
			}
		}
		ber.RecordGeneratedBERChildPlacement(opts, len(children), enc_basicservicegroup)
		children = append(children, enc_basicservicegroup...)
	}
	if v.ForwardingData != nil {
		enc_forwardingdata, err := v.ForwardingData.MarshalBER(ber.ChildEncodeOptions(opts, "forwardingData")...)
		if err != nil {
			return nil, qualifyBERError(err, "forwardingData", "encoding", false)
		}
		retagged_enc_forwardingdata, tagErr_enc_forwardingdata := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_forwardingdata)
		if tagErr_enc_forwardingdata != nil {
			return nil, qualifyBERError(tagErr_enc_forwardingdata, "forwardingData", "encoding", false)
		}
		enc_forwardingdata = retagged_enc_forwardingdata
		ber.RecordGeneratedBERChildPlacement(opts, len(children), enc_forwardingdata)
		children = append(children, enc_forwardingdata...)
	}
	if v.Imsi != nil {
		if len(*v.Imsi) < 3 || len(*v.Imsi) > 8 {
			if constraintErr := checkEncodedLength(opts, s47bb6e_8, "51.5", "imsi", "SIZE (3..8)", len(*v.Imsi)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_imsi, encodeErr_enc_imsi := ber.EncodeOctetString([]byte(*v.Imsi))
		if encodeErr_enc_imsi != nil {
			return nil, qualifyBERError(encodeErr_enc_imsi, "imsi", "encoding", false)
		}
		retagged_enc_imsi, tagErr_enc_imsi := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, enc_imsi)
		if tagErr_enc_imsi != nil {
			return nil, qualifyBERError(tagErr_enc_imsi, "imsi", "encoding", false)
		}
		enc_imsi = retagged_enc_imsi
		children = append(children, enc_imsi...)
	}
	if v.CugCheckInfo != nil {
		enc_cugcheckinfo, err := v.CugCheckInfo.MarshalBER(ber.ChildEncodeOptions(opts, "cug-CheckInfo")...)
		if err != nil {
			return nil, qualifyBERError(err, "cug-CheckInfo", "encoding", false)
		}
		retagged_enc_cugcheckinfo, tagErr_enc_cugcheckinfo := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, enc_cugcheckinfo)
		if tagErr_enc_cugcheckinfo != nil {
			return nil, qualifyBERError(tagErr_enc_cugcheckinfo, "cug-CheckInfo", "encoding", false)
		}
		enc_cugcheckinfo = retagged_enc_cugcheckinfo
		ber.RecordGeneratedBERChildPlacement(opts, len(children), enc_cugcheckinfo)
		children = append(children, enc_cugcheckinfo...)
	}
	if v.OCSI != nil {
		enc_ocsi, err := v.OCSI.MarshalBER(ber.ChildEncodeOptions(opts, "o-CSI")...)
		if err != nil {
			return nil, qualifyBERError(err, "o-CSI", "encoding", false)
		}
		retagged_enc_ocsi, tagErr_enc_ocsi := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 5, enc_ocsi)
		if tagErr_enc_ocsi != nil {
			return nil, qualifyBERError(tagErr_enc_ocsi, "o-CSI", "encoding", false)
		}
		enc_ocsi = retagged_enc_ocsi
		ber.RecordGeneratedBERChildPlacement(opts, len(children), enc_ocsi)
		children = append(children, enc_ocsi...)
	}
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalBER(ber.ChildEncodeOptions(opts, "extensionContainer")...)
		if err != nil {
			return nil, qualifyBERError(err, "extensionContainer", "encoding", false)
		}
		retagged_enc_extensioncontainer, tagErr_enc_extensioncontainer := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 7, enc_extensioncontainer)
		if tagErr_enc_extensioncontainer != nil {
			return nil, qualifyBERError(tagErr_enc_extensioncontainer, "extensionContainer", "encoding", false)
		}
		enc_extensioncontainer = retagged_enc_extensioncontainer
		ber.RecordGeneratedBERChildPlacement(opts, len(children), enc_extensioncontainer)
		children = append(children, enc_extensioncontainer...)
	}
	if v.CcbsPossible != nil {
		enc_ccbspossible := ber.EncodeNull()
		retagged_enc_ccbspossible, tagErr_enc_ccbspossible := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 8, enc_ccbspossible)
		if tagErr_enc_ccbspossible != nil {
			return nil, qualifyBERError(tagErr_enc_ccbspossible, "ccbs-Possible", "encoding", false)
		}
		enc_ccbspossible = retagged_enc_ccbspossible
		children = append(children, enc_ccbspossible...)
	}
	if v.Msisdn != nil {
		if len(*v.Msisdn) < 1 || len(*v.Msisdn) > 9 {
			if constraintErr := checkEncodedLength(opts, s47bb6e_8, "51.5", "msisdn", "SIZE (1..9)", len(*v.Msisdn)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		if len(*v.Msisdn) < 1 || len(*v.Msisdn) > 20 {
			if constraintErr := checkEncodedLength(opts, s47bb6e_8, "51.5", "msisdn", "SIZE (1..20)", len(*v.Msisdn)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_msisdn, encodeErr_enc_msisdn := ber.EncodeOctetString([]byte(*v.Msisdn))
		if encodeErr_enc_msisdn != nil {
			return nil, qualifyBERError(encodeErr_enc_msisdn, "msisdn", "encoding", false)
		}
		retagged_enc_msisdn, tagErr_enc_msisdn := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 9, enc_msisdn)
		if tagErr_enc_msisdn != nil {
			return nil, qualifyBERError(tagErr_enc_msisdn, "msisdn", "encoding", false)
		}
		enc_msisdn = retagged_enc_msisdn
		children = append(children, enc_msisdn...)
	}
	if v.UuData != nil {
		enc_uudata, err := v.UuData.MarshalBER(ber.ChildEncodeOptions(opts, "uu-Data")...)
		if err != nil {
			return nil, qualifyBERError(err, "uu-Data", "encoding", false)
		}
		retagged_enc_uudata, tagErr_enc_uudata := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 10, enc_uudata)
		if tagErr_enc_uudata != nil {
			return nil, qualifyBERError(tagErr_enc_uudata, "uu-Data", "encoding", false)
		}
		enc_uudata = retagged_enc_uudata
		ber.RecordGeneratedBERChildPlacement(opts, len(children), enc_uudata)
		children = append(children, enc_uudata...)
	}
	if v.AllInformationSent != nil {
		enc_allinformationsent := ber.EncodeNull()
		retagged_enc_allinformationsent, tagErr_enc_allinformationsent := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 11, enc_allinformationsent)
		if tagErr_enc_allinformationsent != nil {
			return nil, qualifyBERError(tagErr_enc_allinformationsent, "allInformationSent", "encoding", false)
		}
		enc_allinformationsent = retagged_enc_allinformationsent
		children = append(children, enc_allinformationsent...)
	}
	if v.DCsi != nil {
		enc_dcsi, err := v.DCsi.MarshalBER(ber.ChildEncodeOptions(opts, "d-csi")...)
		if err != nil {
			return nil, qualifyBERError(err, "d-csi", "encoding", false)
		}
		retagged_enc_dcsi, tagErr_enc_dcsi := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 12, enc_dcsi)
		if tagErr_enc_dcsi != nil {
			return nil, qualifyBERError(tagErr_enc_dcsi, "d-csi", "encoding", false)
		}
		enc_dcsi = retagged_enc_dcsi
		ber.RecordGeneratedBERChildPlacement(opts, len(children), enc_dcsi)
		children = append(children, enc_dcsi...)
	}
	if v.OBcsmCamelTDPCriteriaList != nil {
		if len((v.OBcsmCamelTDPCriteriaList).Values) < 1 || len((v.OBcsmCamelTDPCriteriaList).Values) > 10 {
			if constraintErr := checkEncodedLength(opts, s47bb6e_8, "51.5", "o-BcsmCamelTDPCriteriaList", "SIZE (1..10)", len((v.OBcsmCamelTDPCriteriaList).Values)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_obcsmcameltdpcriterialist, err := MarshalBEROBcsmCamelTDPCriteriaList(v.OBcsmCamelTDPCriteriaList, ber.ParentCollectionSizeEncodeOptions(ber.ChildEncodeOptions(opts, "o-BcsmCamelTDPCriteriaList"))...)
		if err != nil {
			return nil, qualifyBERError(err, "o-BcsmCamelTDPCriteriaList", "encoding", false)
		}
		if ber.BERReplayEnabled(opts) && v.berOBcsmCamelTDPCriteriaListIndef_ {
			// Strip the outer SEQUENCE tag from marshalBER output to get raw children.
			_, _, seqContent_, tlvErr_ := ber.DecodeEncodedTLV(enc_obcsmcameltdpcriterialist)
			if tlvErr_ != nil {
				return nil, tlvErr_
			}
			{
				var encodeErr error
				enc_obcsmcameltdpcriterialist, encodeErr = ber.EncodeConstructedIndefinite(tag.Tag{Class: tag.ClassContextSpecific, Number: 13}, seqContent_)
				if encodeErr != nil {
					return nil, qualifyBERError(encodeErr, "o-BcsmCamelTDPCriteriaList", "encoding", false)
				}
			}
		} else {
			retagged_enc_obcsmcameltdpcriterialist, tagErr_enc_obcsmcameltdpcriterialist := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 13, enc_obcsmcameltdpcriterialist)
			if tagErr_enc_obcsmcameltdpcriterialist != nil {
				return nil, qualifyBERError(tagErr_enc_obcsmcameltdpcriterialist, "o-BcsmCamelTDPCriteriaList", "encoding", false)
			}
			enc_obcsmcameltdpcriterialist = retagged_enc_obcsmcameltdpcriterialist
		}
		ber.RecordGeneratedBERChildPlacement(opts, len(children), enc_obcsmcameltdpcriterialist)
		children = append(children, enc_obcsmcameltdpcriterialist...)
	}
	if v.BasicServiceGroup2 != nil {
		enc_basicservicegroup2, err := v.BasicServiceGroup2.MarshalBER(ber.ChildEncodeOptions(opts, "basicServiceGroup2")...)
		if err != nil {
			return nil, qualifyBERError(err, "basicServiceGroup2", "encoding", false)
		}
		{
			var encodeErr error
			enc_basicservicegroup2, encodeErr = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 14, enc_basicservicegroup2)
			if encodeErr != nil {
				return nil, qualifyBERError(encodeErr, "basicServiceGroup2", "encoding", false)
			}
		}
		ber.RecordGeneratedBERChildPlacement(opts, len(children), enc_basicservicegroup2)
		children = append(children, enc_basicservicegroup2...)
	}
	if v.MtRoamingRetry != nil {
		enc_mtroamingretry := ber.EncodeNull()
		retagged_enc_mtroamingretry, tagErr_enc_mtroamingretry := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 15, enc_mtroamingretry)
		if tagErr_enc_mtroamingretry != nil {
			return nil, qualifyBERError(tagErr_enc_mtroamingretry, "mtRoamingRetry", "encoding", false)
		}
		enc_mtroamingretry = retagged_enc_mtroamingretry
		children = append(children, enc_mtroamingretry...)
	}
	base_ := -1
	for i, ext := range v.ExtData_ {
		if err := checkOpaqueAddition(ext, opts, s47bb6e_8, children, i, &base_); err != nil {
			return nil, opaqueExtensionError(err, i)
		}
		peekTag, n, _, extErr := ber.DecodeEncodedTLV(ext)
		if extErr != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, extErr)
		}
		if n != len(ext) {
			return nil, fmt.Errorf("encoding extension %d: %w", i, ber.ErrExtraData)
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: only the first addition is restricted.
		if i == 0 && ((peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 15) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 14) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 13) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 12) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 11) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 10) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 9) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 8) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 7) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 5) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0)) {
			if constraintErr := ber.CheckEncodedValue(ber.EncodeRule(opts, s47bb6e_8, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
				return nil, constraintErr
			}
		}
		children = append(children, ext...)
	}
	ber.RecordGeneratedBERContainer(opts, children)
	return ber.EncodeSequence(children)
}
func (v *ResumeCallHandlingArg) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// MarshalDER encodes ResumeCallHandlingArg to DER format.
// Opaque descendants pass generic DER checks; foreign schema rules need a typed binding.
func (v *ResumeCallHandlingArg) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: ResumeCallHandlingArg receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if v.CallReferenceNumber != nil {
		if len(*v.CallReferenceNumber) < 1 || len(*v.CallReferenceNumber) > 8 {
			if constraintErr := checkEncodedLength(nil, s47bb6e_8, "51.5", "callReferenceNumber", "SIZE (1..8)", len(*v.CallReferenceNumber)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_callreferencenumber, encodeErr_enc_callreferencenumber := ber.EncodeOctetString([]byte(*v.CallReferenceNumber))
		if encodeErr_enc_callreferencenumber != nil {
			return nil, qualifyBERError(encodeErr_enc_callreferencenumber, "callReferenceNumber", "encoding", true)
		}
		retagged_enc_callreferencenumber, tagErr_enc_callreferencenumber := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_callreferencenumber)
		if tagErr_enc_callreferencenumber != nil {
			return nil, qualifyBERError(tagErr_enc_callreferencenumber, "callReferenceNumber", "encoding", true)
		}
		enc_callreferencenumber = retagged_enc_callreferencenumber
		children = append(children, enc_callreferencenumber...)
	}
	if v.BasicServiceGroup != nil {
		enc_basicservicegroup, err := v.BasicServiceGroup.MarshalDER()
		if err != nil {
			return nil, qualifyBERError(err, "basicServiceGroup", "encoding", true)
		}
		{
			var encodeErr error
			enc_basicservicegroup, encodeErr = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 1, enc_basicservicegroup)
			if encodeErr != nil {
				return nil, qualifyBERError(encodeErr, "basicServiceGroup", "encoding", true)
			}
		}
		children = append(children, enc_basicservicegroup...)
	}
	if v.ForwardingData != nil {
		enc_forwardingdata, err := v.ForwardingData.MarshalDER()
		if err != nil {
			return nil, qualifyBERError(err, "forwardingData", "encoding", true)
		}
		retagged_enc_forwardingdata, tagErr_enc_forwardingdata := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_forwardingdata)
		if tagErr_enc_forwardingdata != nil {
			return nil, qualifyBERError(tagErr_enc_forwardingdata, "forwardingData", "encoding", true)
		}
		enc_forwardingdata = retagged_enc_forwardingdata
		children = append(children, enc_forwardingdata...)
	}
	if v.Imsi != nil {
		if len(*v.Imsi) < 3 || len(*v.Imsi) > 8 {
			if constraintErr := checkEncodedLength(nil, s47bb6e_8, "51.5", "imsi", "SIZE (3..8)", len(*v.Imsi)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_imsi, encodeErr_enc_imsi := ber.EncodeOctetString([]byte(*v.Imsi))
		if encodeErr_enc_imsi != nil {
			return nil, qualifyBERError(encodeErr_enc_imsi, "imsi", "encoding", true)
		}
		retagged_enc_imsi, tagErr_enc_imsi := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, enc_imsi)
		if tagErr_enc_imsi != nil {
			return nil, qualifyBERError(tagErr_enc_imsi, "imsi", "encoding", true)
		}
		enc_imsi = retagged_enc_imsi
		children = append(children, enc_imsi...)
	}
	if v.CugCheckInfo != nil {
		enc_cugcheckinfo, err := v.CugCheckInfo.MarshalDER()
		if err != nil {
			return nil, qualifyBERError(err, "cug-CheckInfo", "encoding", true)
		}
		retagged_enc_cugcheckinfo, tagErr_enc_cugcheckinfo := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, enc_cugcheckinfo)
		if tagErr_enc_cugcheckinfo != nil {
			return nil, qualifyBERError(tagErr_enc_cugcheckinfo, "cug-CheckInfo", "encoding", true)
		}
		enc_cugcheckinfo = retagged_enc_cugcheckinfo
		children = append(children, enc_cugcheckinfo...)
	}
	if v.OCSI != nil {
		enc_ocsi, err := v.OCSI.MarshalDER()
		if err != nil {
			return nil, qualifyBERError(err, "o-CSI", "encoding", true)
		}
		retagged_enc_ocsi, tagErr_enc_ocsi := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 5, enc_ocsi)
		if tagErr_enc_ocsi != nil {
			return nil, qualifyBERError(tagErr_enc_ocsi, "o-CSI", "encoding", true)
		}
		enc_ocsi = retagged_enc_ocsi
		children = append(children, enc_ocsi...)
	}
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalDER()
		if err != nil {
			return nil, qualifyBERError(err, "extensionContainer", "encoding", true)
		}
		retagged_enc_extensioncontainer, tagErr_enc_extensioncontainer := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 7, enc_extensioncontainer)
		if tagErr_enc_extensioncontainer != nil {
			return nil, qualifyBERError(tagErr_enc_extensioncontainer, "extensionContainer", "encoding", true)
		}
		enc_extensioncontainer = retagged_enc_extensioncontainer
		children = append(children, enc_extensioncontainer...)
	}
	if v.CcbsPossible != nil {
		enc_ccbspossible := ber.EncodeNull()
		retagged_enc_ccbspossible, tagErr_enc_ccbspossible := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 8, enc_ccbspossible)
		if tagErr_enc_ccbspossible != nil {
			return nil, qualifyBERError(tagErr_enc_ccbspossible, "ccbs-Possible", "encoding", true)
		}
		enc_ccbspossible = retagged_enc_ccbspossible
		children = append(children, enc_ccbspossible...)
	}
	if v.Msisdn != nil {
		if len(*v.Msisdn) < 1 || len(*v.Msisdn) > 9 {
			if constraintErr := checkEncodedLength(nil, s47bb6e_8, "51.5", "msisdn", "SIZE (1..9)", len(*v.Msisdn)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		if len(*v.Msisdn) < 1 || len(*v.Msisdn) > 20 {
			if constraintErr := checkEncodedLength(nil, s47bb6e_8, "51.5", "msisdn", "SIZE (1..20)", len(*v.Msisdn)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_msisdn, encodeErr_enc_msisdn := ber.EncodeOctetString([]byte(*v.Msisdn))
		if encodeErr_enc_msisdn != nil {
			return nil, qualifyBERError(encodeErr_enc_msisdn, "msisdn", "encoding", true)
		}
		retagged_enc_msisdn, tagErr_enc_msisdn := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 9, enc_msisdn)
		if tagErr_enc_msisdn != nil {
			return nil, qualifyBERError(tagErr_enc_msisdn, "msisdn", "encoding", true)
		}
		enc_msisdn = retagged_enc_msisdn
		children = append(children, enc_msisdn...)
	}
	if v.UuData != nil {
		enc_uudata, err := v.UuData.MarshalDER()
		if err != nil {
			return nil, qualifyBERError(err, "uu-Data", "encoding", true)
		}
		retagged_enc_uudata, tagErr_enc_uudata := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 10, enc_uudata)
		if tagErr_enc_uudata != nil {
			return nil, qualifyBERError(tagErr_enc_uudata, "uu-Data", "encoding", true)
		}
		enc_uudata = retagged_enc_uudata
		children = append(children, enc_uudata...)
	}
	if v.AllInformationSent != nil {
		enc_allinformationsent := ber.EncodeNull()
		retagged_enc_allinformationsent, tagErr_enc_allinformationsent := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 11, enc_allinformationsent)
		if tagErr_enc_allinformationsent != nil {
			return nil, qualifyBERError(tagErr_enc_allinformationsent, "allInformationSent", "encoding", true)
		}
		enc_allinformationsent = retagged_enc_allinformationsent
		children = append(children, enc_allinformationsent...)
	}
	if v.DCsi != nil {
		enc_dcsi, err := v.DCsi.MarshalDER()
		if err != nil {
			return nil, qualifyBERError(err, "d-csi", "encoding", true)
		}
		retagged_enc_dcsi, tagErr_enc_dcsi := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 12, enc_dcsi)
		if tagErr_enc_dcsi != nil {
			return nil, qualifyBERError(tagErr_enc_dcsi, "d-csi", "encoding", true)
		}
		enc_dcsi = retagged_enc_dcsi
		children = append(children, enc_dcsi...)
	}
	if v.OBcsmCamelTDPCriteriaList != nil {
		if len((v.OBcsmCamelTDPCriteriaList).Values) < 1 || len((v.OBcsmCamelTDPCriteriaList).Values) > 10 {
			if constraintErr := checkEncodedLength(nil, s47bb6e_8, "51.5", "o-BcsmCamelTDPCriteriaList", "SIZE (1..10)", len((v.OBcsmCamelTDPCriteriaList).Values)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_obcsmcameltdpcriterialist, err := MarshalDEROBcsmCamelTDPCriteriaList(v.OBcsmCamelTDPCriteriaList)
		if err != nil {
			return nil, qualifyBERError(err, "o-BcsmCamelTDPCriteriaList", "encoding", true)
		}
		retagged_enc_obcsmcameltdpcriterialist, tagErr_enc_obcsmcameltdpcriterialist := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 13, enc_obcsmcameltdpcriterialist)
		if tagErr_enc_obcsmcameltdpcriterialist != nil {
			return nil, qualifyBERError(tagErr_enc_obcsmcameltdpcriterialist, "o-BcsmCamelTDPCriteriaList", "encoding", true)
		}
		enc_obcsmcameltdpcriterialist = retagged_enc_obcsmcameltdpcriterialist
		children = append(children, enc_obcsmcameltdpcriterialist...)
	}
	if v.BasicServiceGroup2 != nil {
		enc_basicservicegroup2, err := v.BasicServiceGroup2.MarshalDER()
		if err != nil {
			return nil, qualifyBERError(err, "basicServiceGroup2", "encoding", true)
		}
		{
			var encodeErr error
			enc_basicservicegroup2, encodeErr = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 14, enc_basicservicegroup2)
			if encodeErr != nil {
				return nil, qualifyBERError(encodeErr, "basicServiceGroup2", "encoding", true)
			}
		}
		children = append(children, enc_basicservicegroup2...)
	}
	if v.MtRoamingRetry != nil {
		enc_mtroamingretry := ber.EncodeNull()
		retagged_enc_mtroamingretry, tagErr_enc_mtroamingretry := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 15, enc_mtroamingretry)
		if tagErr_enc_mtroamingretry != nil {
			return nil, qualifyBERError(tagErr_enc_mtroamingretry, "mtRoamingRetry", "encoding", true)
		}
		enc_mtroamingretry = retagged_enc_mtroamingretry
		children = append(children, enc_mtroamingretry...)
	}
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDEREncodedElement(ext); err != nil {
			return nil, invalidDERAddition(ext, s47bb6e_8, children, i)
		}
		peekTag, _, _, extErr := ber.DecodeEncodedTLV(ext)
		if extErr != nil {
			return nil, extErr
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: only the first addition is restricted.
		if i == 0 && ((peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 15) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 14) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 13) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 12) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 11) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 10) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 9) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 8) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 7) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 5) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0)) {
			if constraintErr := ber.CheckEncodedValue(ber.EncodeRule(nil, s47bb6e_8, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
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
		return nil, fmt.Errorf("%s: %w", "encoding ResumeCallHandlingArg as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}
func (v *ResumeCallHandlingArg) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	encoded, err := v.MarshalDER()
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBER decodes ResumeCallHandlingArg from BER/DER format.
func (destination *ResumeCallHandlingArg) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if destination == nil {
		return fmt.Errorf("%w: ResumeCallHandlingArg destination is nil", ber.ErrInvalidValue)
	}
	v := new(ResumeCallHandlingArg)

	defer publishDecodedValue(destination, v, &returnErr)

	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	preparedData, preparedOptions, prepareErr := prepareCompositeBER(data, opts, s47bb6e_8, "child", (*ResumeCallHandlingArg).UnmarshalBER)
	if prepareErr != nil {
		return prepareErr
	}
	data, opts = preparedData, preparedOptions

	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
	*v = ResumeCallHandlingArg{}
	defer func() {
		if returnErr == nil {
			returnErr = completeValueBER(data,
				opts, v, &v.berReplayNode_, (*ResumeCallHandlingArg).MarshalBER)
		}

	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("%s: %w", "decoding ResumeCallHandlingArg SEQUENCE", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "ResumeCallHandlingArg", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode callReferenceNumber
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
				ber.MarkPreflightTarget(opts, "callReferenceNumber", content[offset:])
				decodedTag_callreferencenumber, n_callreferencenumber, rawVal_callreferencenumber, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "callReferenceNumber", "decoding", false)
				}
				if decodedTag_callreferencenumber.Class != tag.ClassContextSpecific || decodedTag_callreferencenumber.Number != 0 {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_callreferencenumber), "callReferenceNumber", "decoding", false)
				}
				decVal_callreferencenumber, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_callreferencenumber.Constructed, rawVal_callreferencenumber, opts...)
				if octetErr != nil {
					return qualifyBERError(octetErr, "callReferenceNumber", "decoding", false)
				}
				tmp_callreferencenumber := CallReferenceNumber(decVal_callreferencenumber)
				v.CallReferenceNumber = &tmp_callreferencenumber
				if offset > len(content) || n_callreferencenumber < 0 || n_callreferencenumber > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_callreferencenumber
				if len(*v.CallReferenceNumber) < 1 || len(*v.CallReferenceNumber) > 8 {
					if constraintErr := checkDecodedLength(opts, s47bb6e_8, "51.5", "callReferenceNumber", "SIZE (1..8)", len(*v.CallReferenceNumber)); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode basicServiceGroup
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
				ber.MarkPreflightTarget(opts, "basicServiceGroup", content[offset:])
				decodedTag_basicservicegroup, n_basicservicegroup, innerData_basicservicegroup, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "basicServiceGroup", "decoding", false)
				}
				if decodedTag_basicservicegroup.Class != tag.ClassContextSpecific || decodedTag_basicservicegroup.Number != 1 || decodedTag_basicservicegroup.Constructed != true {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_basicservicegroup), "basicServiceGroup", "decoding", false)
				}
				_, innerUsed_basicservicegroup, _, innerErr_basicservicegroup := ber.DecodeTLV(innerData_basicservicegroup, opts...)
				if innerErr_basicservicegroup != nil {
					return qualifyBERError(innerErr_basicservicegroup, "basicServiceGroup", "decoding", false)
				}
				if innerUsed_basicservicegroup != len(innerData_basicservicegroup) {
					return qualifyBERError(ber.ErrExtraData, "basicServiceGroup", "decoding", false)
				}
				// Decode inner value from explicit tag wrapper
				ber.MarkPreflightTarget(opts, "basicServiceGroup", innerData_basicservicegroup)
				var dec_basicservicegroup ExtBasicServiceCode
				if unmErr := dec_basicservicegroup.UnmarshalBER(innerData_basicservicegroup, ber.ChildDecodeOptions(opts, "basicServiceGroup")...); unmErr != nil {
					return qualifyBERError(unmErr, "basicServiceGroup", "decoding", false)
				}
				v.BasicServiceGroup = &dec_basicservicegroup
				if offset < 0 || offset >
					len(content) || n_basicservicegroup < 0 || n_basicservicegroup >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_basicservicegroup
			}
		}
	}
	// Decode forwardingData
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2 {
				ber.MarkPreflightTarget(opts, "forwardingData", content[offset:])
				decodedTag_forwardingdata, n_forwardingdata, rawVal_forwardingdata, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "forwardingData", "decoding", false)
				}
				if decodedTag_forwardingdata.Class != tag.ClassContextSpecific || decodedTag_forwardingdata.Number != 2 || decodedTag_forwardingdata.Constructed != true {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_forwardingdata), "forwardingData", "decoding", false)
				}
				_ = rawVal_forwardingdata
				if offset < 0 || offset >
					len(content) || n_forwardingdata < 0 || n_forwardingdata > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				reconstructed_forwardingdata, reconstructionErr_forwardingdata := ber.EncodeImplicitTagWithClass(tag.ClassUniversal, tag.TagSequence, content[offset:offset+n_forwardingdata])
				if reconstructionErr_forwardingdata != nil {
					return qualifyBERError(reconstructionErr_forwardingdata, "forwardingData", "decoding", false)
				}
				var dec_forwardingdata ForwardingData
				if unmErr := dec_forwardingdata.UnmarshalBER(reconstructed_forwardingdata, ber.ChildDecodeOptions(opts, "forwardingData")...); unmErr != nil {
					return qualifyBERError(unmErr, "forwardingData", "decoding", false)
				}
				v.ForwardingData = &dec_forwardingdata
				if offset < 0 || offset >
					len(content) || n_forwardingdata < 0 || n_forwardingdata > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_forwardingdata
			}
		}
	}
	// Decode imsi
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3 {
				ber.MarkPreflightTarget(opts, "imsi", content[offset:])
				decodedTag_imsi, n_imsi, rawVal_imsi, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "imsi", "decoding", false)
				}
				if decodedTag_imsi.Class != tag.ClassContextSpecific || decodedTag_imsi.Number != 3 {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_imsi), "imsi", "decoding", false)
				}
				decVal_imsi, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_imsi.Constructed, rawVal_imsi, opts...)
				if octetErr != nil {
					return qualifyBERError(octetErr, "imsi", "decoding", false)
				}
				tmp_imsi := IMSI(decVal_imsi)
				v.Imsi = &tmp_imsi
				if offset < 0 || offset >
					len(content) || n_imsi < 0 || n_imsi > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_imsi
				if len(*v.Imsi) < 3 || len(*v.Imsi) > 8 {
					if constraintErr := checkDecodedLength(opts, s47bb6e_8, "51.5", "imsi", "SIZE (3..8)", len(*v.Imsi)); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode cug-CheckInfo
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4 {
				ber.MarkPreflightTarget(opts, "cug-CheckInfo", content[offset:])
				decodedTag_cugcheckinfo, n_cugcheckinfo, rawVal_cugcheckinfo, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "cug-CheckInfo", "decoding", false)
				}
				if decodedTag_cugcheckinfo.Class != tag.ClassContextSpecific || decodedTag_cugcheckinfo.Number != 4 || decodedTag_cugcheckinfo.Constructed != true {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_cugcheckinfo), "cug-CheckInfo", "decoding", false)
				}
				_ = rawVal_cugcheckinfo
				if offset < 0 || offset >
					len(content) || n_cugcheckinfo < 0 || n_cugcheckinfo > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				reconstructed_cugcheckinfo, reconstructionErr_cugcheckinfo := ber.EncodeImplicitTagWithClass(tag.ClassUniversal, tag.TagSequence, content[offset:offset+n_cugcheckinfo])
				if reconstructionErr_cugcheckinfo != nil {
					return qualifyBERError(reconstructionErr_cugcheckinfo, "cug-CheckInfo", "decoding", false)
				}
				var dec_cugcheckinfo CUGCheckInfo
				if unmErr := dec_cugcheckinfo.UnmarshalBER(reconstructed_cugcheckinfo, ber.ChildDecodeOptions(opts, "cug-CheckInfo")...); unmErr != nil {
					return qualifyBERError(unmErr, "cug-CheckInfo", "decoding", false)
				}
				v.CugCheckInfo = &dec_cugcheckinfo
				if offset < 0 || offset >
					len(content) || n_cugcheckinfo < 0 || n_cugcheckinfo > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_cugcheckinfo
			}
		}
	}
	// Decode o-CSI
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 5 {
				ber.MarkPreflightTarget(opts, "o-CSI", content[offset:])
				decodedTag_ocsi, n_ocsi, rawVal_ocsi, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "o-CSI", "decoding", false)
				}
				if decodedTag_ocsi.Class != tag.ClassContextSpecific || decodedTag_ocsi.Number != 5 || decodedTag_ocsi.Constructed != true {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_ocsi), "o-CSI", "decoding", false)
				}
				_ = rawVal_ocsi
				if offset < 0 || offset >
					len(content) || n_ocsi < 0 || n_ocsi > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				reconstructed_ocsi, reconstructionErr_ocsi := ber.EncodeImplicitTagWithClass(tag.ClassUniversal, tag.TagSequence, content[offset:offset+n_ocsi])
				if reconstructionErr_ocsi != nil {
					return qualifyBERError(reconstructionErr_ocsi, "o-CSI", "decoding", false)
				}
				var dec_ocsi OCSI
				if unmErr := dec_ocsi.UnmarshalBER(reconstructed_ocsi, ber.ChildDecodeOptions(opts, "o-CSI")...); unmErr != nil {
					return qualifyBERError(unmErr, "o-CSI", "decoding", false)
				}
				v.OCSI = &dec_ocsi
				if offset < 0 || offset >
					len(content) || n_ocsi < 0 || n_ocsi > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_ocsi
			}
		}
	}
	// Decode extensionContainer
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 7 {
				ber.MarkPreflightTarget(opts, "extensionContainer", content[offset:])
				decodedTag_extensioncontainer, n_extensioncontainer, rawVal_extensioncontainer, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "extensionContainer", "decoding", false)
				}
				if decodedTag_extensioncontainer.Class != tag.ClassContextSpecific || decodedTag_extensioncontainer.Number != 7 || decodedTag_extensioncontainer.Constructed != true {
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
				var dec_extensioncontainer ExtensionContainer
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
	// Decode ccbs-Possible
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 8 {
				ber.MarkPreflightTarget(opts, "ccbs-Possible", content[offset:])
				decodedTag_ccbspossible, n_ccbspossible, rawVal_ccbspossible, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "ccbs-Possible", "decoding", false)
				}
				if decodedTag_ccbspossible.Class != tag.ClassContextSpecific || decodedTag_ccbspossible.Number != 8 || decodedTag_ccbspossible.Constructed != false {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_ccbspossible), "ccbs-Possible", "decoding", false)
				}
				if len(rawVal_ccbspossible) != 0 {
					return qualifyBERError(fmt.Errorf("%w: NULL content length %d", ber.ErrInvalidValue, len(rawVal_ccbspossible)), "ccbs-Possible", "decoding", false)
				}
				v.CcbsPossible = &struct{}{}
				if offset < 0 || offset >
					len(content) || n_ccbspossible < 0 || n_ccbspossible > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_ccbspossible
			}
		}
	}
	// Decode msisdn
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 9 {
				ber.MarkPreflightTarget(opts, "msisdn", content[offset:])
				decodedTag_msisdn, n_msisdn, rawVal_msisdn, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "msisdn", "decoding", false)
				}
				if decodedTag_msisdn.Class != tag.ClassContextSpecific || decodedTag_msisdn.Number != 9 {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_msisdn), "msisdn", "decoding", false)
				}
				decVal_msisdn, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_msisdn.Constructed, rawVal_msisdn, opts...)
				if octetErr != nil {
					return qualifyBERError(octetErr, "msisdn", "decoding", false)
				}
				tmp_msisdn := ISDNAddressString(decVal_msisdn)
				v.Msisdn = &tmp_msisdn
				if offset < 0 || offset >
					len(content) || n_msisdn < 0 || n_msisdn > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_msisdn
				if len(*v.Msisdn) < 1 || len(*v.Msisdn) > 9 {
					if constraintErr := checkDecodedLength(opts, s47bb6e_8, "51.5", "msisdn", "SIZE (1..9)", len(*v.Msisdn)); constraintErr != nil {
						return constraintErr
					}
				}
				if len(*v.Msisdn) < 1 || len(*v.Msisdn) > 20 {
					if constraintErr := checkDecodedLength(opts, s47bb6e_8, "51.5", "msisdn", "SIZE (1..20)", len(*v.Msisdn)); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode uu-Data
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 10 {
				ber.MarkPreflightTarget(opts, "uu-Data", content[offset:])
				decodedTag_uudata, n_uudata, rawVal_uudata, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "uu-Data", "decoding", false)
				}
				if decodedTag_uudata.Class != tag.ClassContextSpecific || decodedTag_uudata.Number != 10 || decodedTag_uudata.Constructed != true {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_uudata), "uu-Data", "decoding", false)
				}
				_ = rawVal_uudata
				if offset < 0 || offset >
					len(content) || n_uudata < 0 || n_uudata > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				reconstructed_uudata, reconstructionErr_uudata := ber.EncodeImplicitTagWithClass(tag.ClassUniversal, tag.TagSequence, content[offset:offset+n_uudata])
				if reconstructionErr_uudata != nil {
					return qualifyBERError(reconstructionErr_uudata, "uu-Data", "decoding", false)
				}
				var dec_uudata UUData
				if unmErr := dec_uudata.UnmarshalBER(reconstructed_uudata, ber.ChildDecodeOptions(opts, "uu-Data")...); unmErr != nil {
					return qualifyBERError(unmErr, "uu-Data", "decoding", false)
				}
				v.UuData = &dec_uudata
				if offset < 0 || offset >
					len(content) || n_uudata < 0 || n_uudata > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_uudata
			}
		}
	}
	// Decode allInformationSent
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 11 {
				ber.MarkPreflightTarget(opts, "allInformationSent", content[offset:])
				decodedTag_allinformationsent, n_allinformationsent, rawVal_allinformationsent, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "allInformationSent", "decoding", false)
				}
				if decodedTag_allinformationsent.Class != tag.ClassContextSpecific || decodedTag_allinformationsent.Number != 11 || decodedTag_allinformationsent.Constructed != false {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_allinformationsent), "allInformationSent", "decoding", false)
				}
				if len(rawVal_allinformationsent) != 0 {
					return qualifyBERError(fmt.Errorf("%w: NULL content length %d", ber.ErrInvalidValue, len(rawVal_allinformationsent)), "allInformationSent", "decoding", false)
				}
				v.AllInformationSent = &struct{}{}
				if offset < 0 || offset >
					len(content) || n_allinformationsent < 0 || n_allinformationsent >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_allinformationsent
			}
		}
	}
	// Decode d-csi
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 12 {
				ber.MarkPreflightTarget(opts, "d-csi", content[offset:])
				decodedTag_dcsi, n_dcsi, rawVal_dcsi, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "d-csi", "decoding", false)
				}
				if decodedTag_dcsi.Class != tag.ClassContextSpecific || decodedTag_dcsi.Number != 12 || decodedTag_dcsi.Constructed != true {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_dcsi), "d-csi", "decoding", false)
				}
				_ = rawVal_dcsi
				if offset < 0 || offset >
					len(content) || n_dcsi < 0 || n_dcsi > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				reconstructed_dcsi, reconstructionErr_dcsi := ber.EncodeImplicitTagWithClass(tag.ClassUniversal, tag.TagSequence, content[offset:offset+n_dcsi])
				if reconstructionErr_dcsi != nil {
					return qualifyBERError(reconstructionErr_dcsi, "d-csi", "decoding", false)
				}
				var dec_dcsi DCSI
				if unmErr := dec_dcsi.UnmarshalBER(reconstructed_dcsi, ber.ChildDecodeOptions(opts, "d-csi")...); unmErr != nil {
					return qualifyBERError(unmErr, "d-csi", "decoding", false)
				}
				v.DCsi = &dec_dcsi
				if offset < 0 || offset >
					len(content) || n_dcsi < 0 || n_dcsi > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_dcsi
			}
		}
	}
	// Decode o-BcsmCamelTDPCriteriaList
	v.berOBcsmCamelTDPCriteriaListIndef_ = false
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 13 {
				ber.MarkPreflightTarget(opts, "o-BcsmCamelTDPCriteriaList", content[offset:])
				decodedTag_obcsmcameltdpcriterialist, n_obcsmcameltdpcriterialist, rawVal_obcsmcameltdpcriterialist, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "o-BcsmCamelTDPCriteriaList", "decoding", false)
				}
				if decodedTag_obcsmcameltdpcriterialist.Class != tag.ClassContextSpecific || decodedTag_obcsmcameltdpcriterialist.Number != 13 || decodedTag_obcsmcameltdpcriterialist.Constructed != true {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_obcsmcameltdpcriterialist), "o-BcsmCamelTDPCriteriaList", "decoding", false)
				}
				_ = rawVal_obcsmcameltdpcriterialist
				if offset < 0 || offset >
					len(content) || n_obcsmcameltdpcriterialist < 0 || n_obcsmcameltdpcriterialist >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				reconstructed_obcsmcameltdpcriterialist, reconstructionErr_obcsmcameltdpcriterialist := ber.EncodeImplicitTagWithClass(tag.ClassUniversal, tag.TagSequence, content[offset:offset+n_obcsmcameltdpcriterialist])
				if reconstructionErr_obcsmcameltdpcriterialist != nil {
					return qualifyBERError(reconstructionErr_obcsmcameltdpcriterialist, "o-BcsmCamelTDPCriteriaList", "decoding", false)
				}
				dec_obcsmcameltdpcriterialist, unmErr := UnmarshalBEROBcsmCamelTDPCriteriaList(reconstructed_obcsmcameltdpcriterialist, ber.ParentCollectionSizeDecodeOptions(ber.ChildDecodeOptions(opts, "o-BcsmCamelTDPCriteriaList"))...)
				if unmErr != nil {
					return qualifyBERError(unmErr, "o-BcsmCamelTDPCriteriaList", "decoding", false)
				}
				v.OBcsmCamelTDPCriteriaList = dec_obcsmcameltdpcriterialist
				{
					_, tagSz_, _ := ber.DecodeTag(content[offset:])
					if offset < 0 || offset >
						len(content) || tagSz_ < 0 || tagSz_ > len(content[offset:]) {
						return fmt.Errorf("invalid BER content window")
					}

					if offset+tagSz_ < len(content) && content[offset+tagSz_] == 0x80 {
						v.berOBcsmCamelTDPCriteriaListIndef_ = true
					}
				}
				if offset < 0 || offset >
					len(content) || n_obcsmcameltdpcriterialist < 0 || n_obcsmcameltdpcriterialist >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_obcsmcameltdpcriterialist
				if len((v.OBcsmCamelTDPCriteriaList).Values) < 1 || len((v.OBcsmCamelTDPCriteriaList).Values) > 10 {
					if constraintErr := checkDecodedLength(opts, s47bb6e_8, "51.5", "o-BcsmCamelTDPCriteriaList", "SIZE (1..10)", len((v.OBcsmCamelTDPCriteriaList).Values)); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode basicServiceGroup2
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 14 {
				ber.MarkPreflightTarget(opts, "basicServiceGroup2", content[offset:])
				decodedTag_basicservicegroup2, n_basicservicegroup2, innerData_basicservicegroup2, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "basicServiceGroup2", "decoding", false)
				}
				if decodedTag_basicservicegroup2.Class != tag.ClassContextSpecific || decodedTag_basicservicegroup2.Number != 14 || decodedTag_basicservicegroup2.Constructed != true {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_basicservicegroup2), "basicServiceGroup2", "decoding", false)
				}
				_, innerUsed_basicservicegroup2, _, innerErr_basicservicegroup2 := ber.DecodeTLV(innerData_basicservicegroup2, opts...)
				if innerErr_basicservicegroup2 != nil {
					return qualifyBERError(innerErr_basicservicegroup2, "basicServiceGroup2", "decoding", false)
				}
				if innerUsed_basicservicegroup2 != len(innerData_basicservicegroup2) {
					return qualifyBERError(ber.ErrExtraData, "basicServiceGroup2", "decoding", false)
				}
				// Decode inner value from explicit tag wrapper
				ber.MarkPreflightTarget(opts, "basicServiceGroup2", innerData_basicservicegroup2)
				var dec_basicservicegroup2 ExtBasicServiceCode
				if unmErr := dec_basicservicegroup2.UnmarshalBER(innerData_basicservicegroup2, ber.ChildDecodeOptions(opts, "basicServiceGroup2")...); unmErr != nil {
					return qualifyBERError(unmErr, "basicServiceGroup2", "decoding", false)
				}
				v.BasicServiceGroup2 = &dec_basicservicegroup2
				if offset < 0 || offset >
					len(content) || n_basicservicegroup2 < 0 || n_basicservicegroup2 >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_basicservicegroup2
			}
		}
	}
	// Decode mtRoamingRetry
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 15 {
				ber.MarkPreflightTarget(opts, "mtRoamingRetry", content[offset:])
				decodedTag_mtroamingretry, n_mtroamingretry, rawVal_mtroamingretry, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "mtRoamingRetry", "decoding", false)
				}
				if decodedTag_mtroamingretry.Class != tag.ClassContextSpecific || decodedTag_mtroamingretry.Number != 15 || decodedTag_mtroamingretry.Constructed != false {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_mtroamingretry), "mtRoamingRetry", "decoding", false)
				}
				if len(rawVal_mtroamingretry) != 0 {
					return qualifyBERError(fmt.Errorf("%w: NULL content length %d", ber.ErrInvalidValue, len(rawVal_mtroamingretry)), "mtRoamingRetry", "decoding", false)
				}
				v.MtRoamingRetry = &struct{}{}
				if offset < 0 || offset >
					len(content) || n_mtroamingretry < 0 || n_mtroamingretry > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_mtroamingretry
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		peekTag, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:], opts...)
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "ResumeCallHandlingArg", Cause: extErr_}
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: the first unknown addition must differ from trailing OPTIONAL/DEFAULT tags.
		if len(v.ExtData_) == 0 && ((peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 15) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 14) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 13) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 12) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 11) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 10) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 9) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 8) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 7) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 5) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0)) {
			if !ber.ToleranceEnabled(opts) {
				return &ber.DecodeError{Offset: offset, TypeName: "ResumeCallHandlingArg", Cause: fmt.Errorf("%w: repeated or out-of-order SEQUENCE component tag %s", ber.ErrInvalidTag, peekTag)}
			}
			if orderErr_ := ber.CheckDecodedValue(ber.DecodeRule(opts, s47bb6e_8, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), fmt.Sprintf("ExtData_[%d]", len(v.ExtData_)), "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); orderErr_ != nil {
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

// MarshalBER encodes UUData to BER format.
func (v *UUData) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {

	if v == nil {
		return nil, fmt.Errorf("%w: UUData receiver is nil", ber.ErrInvalidValue)
	}
	return marshalFramedValue(v, v.berReplayNode_, opts, (*UUData).MarshalBER, (*UUData).marshalBER, 3)

}
func (v *UUData) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if v.UuIndicator != nil {
		if len(*v.UuIndicator) < 1 || len(*v.UuIndicator) > 1 {
			if constraintErr := checkEncodedLength(opts, s47bb6e_9, "51.5", "uuIndicator", "SIZE (1)", len(*v.UuIndicator)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_uuindicator, encodeErr_enc_uuindicator := ber.EncodeOctetString([]byte(*v.UuIndicator))
		if encodeErr_enc_uuindicator != nil {
			return nil, qualifyBERError(encodeErr_enc_uuindicator, "uuIndicator", "encoding", false)
		}
		retagged_enc_uuindicator, tagErr_enc_uuindicator := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_uuindicator)
		if tagErr_enc_uuindicator != nil {
			return nil, qualifyBERError(tagErr_enc_uuindicator, "uuIndicator", "encoding", false)
		}
		enc_uuindicator = retagged_enc_uuindicator
		children = append(children, enc_uuindicator...)
	}
	if v.Uui != nil {
		if len(*v.Uui) < 1 || len(*v.Uui) > 131 {
			if constraintErr := checkEncodedLength(opts, s47bb6e_9, "51.5", "uui", "SIZE (1..131)", len(*v.Uui)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_uui, encodeErr_enc_uui := ber.EncodeOctetString([]byte(*v.Uui))
		if encodeErr_enc_uui != nil {
			return nil, qualifyBERError(encodeErr_enc_uui, "uui", "encoding", false)
		}
		retagged_enc_uui, tagErr_enc_uui := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_uui)
		if tagErr_enc_uui != nil {
			return nil, qualifyBERError(tagErr_enc_uui, "uui", "encoding", false)
		}
		enc_uui = retagged_enc_uui
		children = append(children, enc_uui...)
	}
	if v.UusCFInteraction != nil {
		enc_uuscfinteraction := ber.EncodeNull()
		retagged_enc_uuscfinteraction, tagErr_enc_uuscfinteraction := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_uuscfinteraction)
		if tagErr_enc_uuscfinteraction != nil {
			return nil, qualifyBERError(tagErr_enc_uuscfinteraction, "uusCFInteraction", "encoding", false)
		}
		enc_uuscfinteraction = retagged_enc_uuscfinteraction
		children = append(children, enc_uuscfinteraction...)
	}
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalBER(ber.ChildEncodeOptions(opts, "extensionContainer")...)
		if err != nil {
			return nil, qualifyBERError(err, "extensionContainer", "encoding", false)
		}
		retagged_enc_extensioncontainer, tagErr_enc_extensioncontainer := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, enc_extensioncontainer)
		if tagErr_enc_extensioncontainer != nil {
			return nil, qualifyBERError(tagErr_enc_extensioncontainer, "extensionContainer", "encoding", false)
		}
		enc_extensioncontainer = retagged_enc_extensioncontainer
		ber.RecordGeneratedBERChildPlacement(opts, len(children), enc_extensioncontainer)
		children = append(children, enc_extensioncontainer...)
	}
	base_ := -1
	for i, ext := range v.ExtData_ {
		if err := checkOpaqueAddition(ext, opts, s47bb6e_9, children, i, &base_); err != nil {
			return nil, opaqueExtensionError(err, i)
		}
		peekTag, n, _, extErr := ber.DecodeEncodedTLV(ext)
		if extErr != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, extErr)
		}
		if n != len(ext) {
			return nil, fmt.Errorf("encoding extension %d: %w", i, ber.ErrExtraData)
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: only the first addition is restricted.
		if i == 0 && ((peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0)) {
			if constraintErr := ber.CheckEncodedValue(ber.EncodeRule(opts, s47bb6e_9, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
				return nil, constraintErr
			}
		}
		children = append(children, ext...)
	}
	ber.RecordGeneratedBERContainer(opts, children)
	return ber.EncodeSequence(children)
}
func (v *UUData) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// MarshalDER encodes UUData to DER format.
// Opaque descendants pass generic DER checks; foreign schema rules need a typed binding.
func (v *UUData) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: UUData receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if v.UuIndicator != nil {
		if len(*v.UuIndicator) < 1 || len(*v.UuIndicator) > 1 {
			if constraintErr := checkEncodedLength(nil, s47bb6e_9, "51.5", "uuIndicator", "SIZE (1)", len(*v.UuIndicator)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_uuindicator, encodeErr_enc_uuindicator := ber.EncodeOctetString([]byte(*v.UuIndicator))
		if encodeErr_enc_uuindicator != nil {
			return nil, qualifyBERError(encodeErr_enc_uuindicator, "uuIndicator", "encoding", true)
		}
		retagged_enc_uuindicator, tagErr_enc_uuindicator := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_uuindicator)
		if tagErr_enc_uuindicator != nil {
			return nil, qualifyBERError(tagErr_enc_uuindicator, "uuIndicator", "encoding", true)
		}
		enc_uuindicator = retagged_enc_uuindicator
		children = append(children, enc_uuindicator...)
	}
	if v.Uui != nil {
		if len(*v.Uui) < 1 || len(*v.Uui) > 131 {
			if constraintErr := checkEncodedLength(nil, s47bb6e_9, "51.5", "uui", "SIZE (1..131)", len(*v.Uui)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_uui, encodeErr_enc_uui := ber.EncodeOctetString([]byte(*v.Uui))
		if encodeErr_enc_uui != nil {
			return nil, qualifyBERError(encodeErr_enc_uui, "uui", "encoding", true)
		}
		retagged_enc_uui, tagErr_enc_uui := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_uui)
		if tagErr_enc_uui != nil {
			return nil, qualifyBERError(tagErr_enc_uui, "uui", "encoding", true)
		}
		enc_uui = retagged_enc_uui
		children = append(children, enc_uui...)
	}
	if v.UusCFInteraction != nil {
		enc_uuscfinteraction := ber.EncodeNull()
		retagged_enc_uuscfinteraction, tagErr_enc_uuscfinteraction := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_uuscfinteraction)
		if tagErr_enc_uuscfinteraction != nil {
			return nil, qualifyBERError(tagErr_enc_uuscfinteraction, "uusCFInteraction", "encoding", true)
		}
		enc_uuscfinteraction = retagged_enc_uuscfinteraction
		children = append(children, enc_uuscfinteraction...)
	}
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalDER()
		if err != nil {
			return nil, qualifyBERError(err, "extensionContainer", "encoding", true)
		}
		retagged_enc_extensioncontainer, tagErr_enc_extensioncontainer := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, enc_extensioncontainer)
		if tagErr_enc_extensioncontainer != nil {
			return nil, qualifyBERError(tagErr_enc_extensioncontainer, "extensionContainer", "encoding", true)
		}
		enc_extensioncontainer = retagged_enc_extensioncontainer
		children = append(children, enc_extensioncontainer...)
	}
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDEREncodedElement(ext); err != nil {
			return nil, invalidDERAddition(ext, s47bb6e_9, children, i)
		}
		peekTag, _, _, extErr := ber.DecodeEncodedTLV(ext)
		if extErr != nil {
			return nil, extErr
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: only the first addition is restricted.
		if i == 0 && ((peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0)) {
			if constraintErr := ber.CheckEncodedValue(ber.EncodeRule(nil, s47bb6e_9, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
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
		return nil, fmt.Errorf("%s: %w", "encoding UUData as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}
func (v *UUData) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	encoded, err := v.MarshalDER()
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBER decodes UUData from BER/DER format.
func (destination *UUData) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if destination == nil {
		return fmt.Errorf("%w: UUData destination is nil", ber.ErrInvalidValue)
	}
	v := new(UUData)
	defer publishDecodedValue(destination, v, &returnErr)

	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	preparedData, preparedOptions, prepareErr := prepareCompositeBER(data, opts, s47bb6e_9, "child", (*UUData).UnmarshalBER)
	if prepareErr != nil {
		return prepareErr
	}
	data, opts = preparedData, preparedOptions

	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
	*v = UUData{}
	defer func() {
		if returnErr == nil {
			returnErr = completeValueBER(data,
				opts, v, &v.berReplayNode_, (*UUData).MarshalBER)
		}

	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("%s: %w", "decoding UUData SEQUENCE", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "UUData", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode uuIndicator
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
				ber.MarkPreflightTarget(opts, "uuIndicator", content[offset:])
				decodedTag_uuindicator, n_uuindicator, rawVal_uuindicator, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "uuIndicator", "decoding", false)
				}
				if decodedTag_uuindicator.Class != tag.ClassContextSpecific || decodedTag_uuindicator.Number != 0 {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_uuindicator), "uuIndicator", "decoding", false)
				}
				decVal_uuindicator, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_uuindicator.Constructed, rawVal_uuindicator, opts...)
				if octetErr != nil {
					return qualifyBERError(octetErr, "uuIndicator", "decoding", false)
				}
				tmp_uuindicator := UUIndicator(decVal_uuindicator)
				v.UuIndicator = &tmp_uuindicator
				if offset > len(content) || n_uuindicator < 0 || n_uuindicator > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_uuindicator
				if len(*v.UuIndicator) < 1 || len(*v.UuIndicator) > 1 {
					if constraintErr := checkDecodedLength(opts, s47bb6e_9, "51.5", "uuIndicator", "SIZE (1)", len(*v.UuIndicator)); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode uui
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
				ber.MarkPreflightTarget(opts, "uui", content[offset:])
				decodedTag_uui, n_uui, rawVal_uui, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "uui", "decoding", false)
				}
				if decodedTag_uui.Class != tag.ClassContextSpecific || decodedTag_uui.Number != 1 {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_uui), "uui", "decoding", false)
				}
				decVal_uui, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_uui.Constructed, rawVal_uui, opts...)
				if octetErr != nil {
					return qualifyBERError(octetErr, "uui", "decoding", false)
				}
				tmp_uui := UUI(decVal_uui)
				v.Uui = &tmp_uui
				if offset < 0 || offset >
					len(content) || n_uui < 0 || n_uui > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_uui
				if len(*v.Uui) < 1 || len(*v.Uui) > 131 {
					if constraintErr := checkDecodedLength(opts, s47bb6e_9, "51.5", "uui", "SIZE (1..131)", len(*v.Uui)); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode uusCFInteraction
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2 {
				ber.MarkPreflightTarget(opts, "uusCFInteraction", content[offset:])
				decodedTag_uuscfinteraction, n_uuscfinteraction, rawVal_uuscfinteraction, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "uusCFInteraction", "decoding", false)
				}
				if decodedTag_uuscfinteraction.Class != tag.ClassContextSpecific || decodedTag_uuscfinteraction.Number != 2 || decodedTag_uuscfinteraction.Constructed != false {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_uuscfinteraction), "uusCFInteraction", "decoding", false)
				}
				if len(rawVal_uuscfinteraction) != 0 {
					return qualifyBERError(fmt.Errorf("%w: NULL content length %d", ber.ErrInvalidValue, len(rawVal_uuscfinteraction)), "uusCFInteraction", "decoding", false)
				}
				v.UusCFInteraction = &struct{}{}
				if offset < 0 || offset >
					len(content) || n_uuscfinteraction < 0 || n_uuscfinteraction >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_uuscfinteraction
			}
		}
	}
	// Decode extensionContainer
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3 {
				ber.MarkPreflightTarget(opts, "extensionContainer", content[offset:])
				decodedTag_extensioncontainer, n_extensioncontainer, rawVal_extensioncontainer, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "extensionContainer", "decoding", false)
				}
				if decodedTag_extensioncontainer.Class != tag.ClassContextSpecific || decodedTag_extensioncontainer.Number != 3 || decodedTag_extensioncontainer.Constructed != true {
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
				var dec_extensioncontainer ExtensionContainer
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
			return &ber.DecodeError{Offset: offset, TypeName: "UUData", Cause: extErr_}
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: the first unknown addition must differ from trailing OPTIONAL/DEFAULT tags.
		if len(v.ExtData_) == 0 && ((peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0)) {
			if !ber.ToleranceEnabled(opts) {
				return &ber.DecodeError{Offset: offset, TypeName: "UUData", Cause: fmt.Errorf("%w: repeated or out-of-order SEQUENCE component tag %s", ber.ErrInvalidTag, peekTag)}
			}
			if orderErr_ := ber.CheckDecodedValue(ber.DecodeRule(opts, s47bb6e_9, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), fmt.Sprintf("ExtData_[%d]", len(v.ExtData_)), "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); orderErr_ != nil {
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

// MarshalBER encodes ResumeCallHandlingRes to BER format.
func (v *ResumeCallHandlingRes) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {

	if v == nil {
		return nil, fmt.Errorf("%w: ResumeCallHandlingRes receiver is nil", ber.ErrInvalidValue)
	}
	return marshalFramedValue(v, v.berReplayNode_, opts, (*ResumeCallHandlingRes).MarshalBER, (*ResumeCallHandlingRes).marshalBER, 3)

}
func (v *ResumeCallHandlingRes) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
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
	base_ := -1
	for i, ext := range v.ExtData_ {
		if err := checkOpaqueAddition(ext, opts, s47bb6e_10, children, i, &base_); err != nil {
			return nil, opaqueExtensionError(err, i)
		}
		peekTag, n, _, extErr := ber.DecodeEncodedTLV(ext)
		if extErr != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, extErr)
		}
		if n != len(ext) {
			return nil, fmt.Errorf("encoding extension %d: %w", i, ber.ErrExtraData)
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: only the first addition is restricted.
		if i == 0 && (peekTag.Class == tag.ClassUniversal && peekTag.Number == 16) {
			if constraintErr := ber.CheckEncodedValue(ber.EncodeRule(opts, s47bb6e_10, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
				return nil, constraintErr
			}
		}
		children = append(children, ext...)
	}
	ber.RecordGeneratedBERContainer(opts, children)
	return ber.EncodeSequence(children)
}
func (v *ResumeCallHandlingRes) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// MarshalDER encodes ResumeCallHandlingRes to DER format.
// Opaque descendants pass generic DER checks; foreign schema rules need a typed binding.
func (v *ResumeCallHandlingRes) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: ResumeCallHandlingRes receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalDER()
		if err != nil {
			return nil, qualifyBERError(err, "extensionContainer", "encoding", true)
		}
		children = append(children, enc_extensioncontainer...)
	}
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDEREncodedElement(ext); err != nil {
			return nil, invalidDERAddition(ext, s47bb6e_10, children, i)
		}
		peekTag, _, _, extErr := ber.DecodeEncodedTLV(ext)
		if extErr != nil {
			return nil, extErr
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: only the first addition is restricted.
		if i == 0 && (peekTag.Class == tag.ClassUniversal && peekTag.Number == 16) {
			if constraintErr := ber.CheckEncodedValue(ber.EncodeRule(nil, s47bb6e_10, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
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
		return nil, fmt.Errorf("%s: %w", "encoding ResumeCallHandlingRes as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}
func (v *ResumeCallHandlingRes) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	encoded, err := v.MarshalDER()
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBER decodes ResumeCallHandlingRes from BER/DER format.
func (destination *ResumeCallHandlingRes) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if destination == nil {
		return fmt.Errorf("%w: ResumeCallHandlingRes destination is nil", ber.ErrInvalidValue)
	}
	v := new(ResumeCallHandlingRes)

	defer publishDecodedValue(destination, v, &returnErr)

	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	preparedData, preparedOptions, prepareErr := prepareCompositeBER(data, opts, s47bb6e_10, "child", (*ResumeCallHandlingRes).UnmarshalBER)
	if prepareErr != nil {
		return prepareErr
	}
	data, opts = preparedData, preparedOptions

	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
	*v = ResumeCallHandlingRes{}
	defer func() {
		if returnErr == nil {
			returnErr = completeValueBER(data,
				opts, v, &v.berReplayNode_, (*ResumeCallHandlingRes).MarshalBER)
		}

	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("%s: %w", "decoding ResumeCallHandlingRes SEQUENCE", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "ResumeCallHandlingRes", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode extensionContainer
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassUniversal && peekTag.Number == 16 {
				ber.MarkPreflightTarget(opts, "extensionContainer", content[offset:])
				// Decode nested SEQUENCE (ExtensionContainer)
				_, n_extensioncontainer, _, tlvErr_extensioncontainer := ber.DecodeTLV(content[offset:], opts...)
				if tlvErr_extensioncontainer != nil {
					return qualifyBERError(tlvErr_extensioncontainer, "extensionContainer", "decoding", false)
				}
				var dec_extensioncontainer ExtensionContainer
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
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		peekTag, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:], opts...)
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "ResumeCallHandlingRes", Cause: extErr_}
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: the first unknown addition must differ from trailing OPTIONAL/DEFAULT tags.
		if len(v.ExtData_) == 0 && (peekTag.Class == tag.ClassUniversal && peekTag.Number == 16) {
			if !ber.ToleranceEnabled(opts) {
				return &ber.DecodeError{Offset: offset, TypeName: "ResumeCallHandlingRes", Cause: fmt.Errorf("%w: repeated or out-of-order SEQUENCE component tag %s", ber.ErrInvalidTag, peekTag)}
			}
			if orderErr_ := ber.CheckDecodedValue(ber.DecodeRule(opts, s47bb6e_10, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), fmt.Sprintf("ExtData_[%d]", len(v.ExtData_)), "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); orderErr_ != nil {
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

// MarshalBER encodes CamelInfo to BER format.
func (v *CamelInfo) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {

	if v == nil {
		return nil, fmt.Errorf("%w: CamelInfo receiver is nil", ber.ErrInvalidValue)
	}
	return marshalFramedValue(v, v.berReplayNode_, opts, (*CamelInfo).MarshalBER, (*CamelInfo).marshalBER, 3)

}
func (v *CamelInfo) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	namedBits_SupportedCamelPhases, namedBitErr_ := normalizeNamedBits(v.SupportedCamelPhases, []ber.NamedBitSizeSet{{{Min: 1, Max: 16}}}, opts, "supportedCamelPhases", s47bb6e_11)
	if namedBitErr_ != nil {
		return nil, namedBitErr_
	}
	if bitStringErr := ber.ValidateBitStringLength(namedBits_SupportedCamelPhases.Bytes, namedBits_SupportedCamelPhases.BitLength); bitStringErr != nil {
		return nil, qualifyBERError(bitStringErr, "supportedCamelPhases", "encoding", false)
	}
	// arithmetic pattern BER_BITSTRING_FIELD: 0 <= bit length before modulo and subtraction; gen/codegen.go:750
	if namedBits_SupportedCamelPhases.BitLength < 0 {
		return nil, fmt.Errorf("negative bit string length")
	}
	if (namedBits_SupportedCamelPhases).BitLength < 1 || (namedBits_SupportedCamelPhases).BitLength > 16 {
		if constraintErr := checkEncodedLength(opts, s47bb6e_11, "51.5", "supportedCamelPhases", "SIZE (1..16)", namedBitObservedLength(namedBits_SupportedCamelPhases)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_supportedcamelphases, encodeErr_enc_supportedcamelphases := ber.EncodeBitString(namedBits_SupportedCamelPhases.Bytes, ber.UnusedBitCount(namedBits_SupportedCamelPhases.BitLength))
	if encodeErr_enc_supportedcamelphases != nil {
		return nil, qualifyBERError(encodeErr_enc_supportedcamelphases, "supportedCamelPhases", "encoding", false)
	}
	children = append(children, enc_supportedcamelphases...)
	if v.SuppressTCSI != nil {
		enc_suppresstcsi := ber.EncodeNull()
		children = append(children, enc_suppresstcsi...)
	}
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalBER(ber.ChildEncodeOptions(opts, "extensionContainer")...)
		if err != nil {
			return nil, qualifyBERError(err, "extensionContainer", "encoding", false)
		}
		ber.RecordGeneratedBERChildPlacement(opts, len(children), enc_extensioncontainer)
		children = append(children, enc_extensioncontainer...)
	}
	if v.OfferedCamel4CSIs != nil {
		namedBits_OfferedCamel4CSIs, namedBitErr_ := normalizeNamedBits(*v.OfferedCamel4CSIs, []ber.NamedBitSizeSet{{{Min: 7, Max: 16}}}, opts, "offeredCamel4CSIs", s47bb6e_11)
		if namedBitErr_ != nil {
			return nil, namedBitErr_
		}
		if bitStringErr := ber.ValidateBitStringLength(namedBits_OfferedCamel4CSIs.Bytes, namedBits_OfferedCamel4CSIs.BitLength); bitStringErr != nil {
			return nil, qualifyBERError(bitStringErr, "offeredCamel4CSIs", "encoding", false)
		}
		// arithmetic pattern BER_BITSTRING_FIELD: 0 <= bit length before modulo and subtraction; gen/codegen.go:750
		if namedBits_OfferedCamel4CSIs.BitLength < 0 {
			return nil, fmt.Errorf("negative bit string length")
		}
		if (namedBits_OfferedCamel4CSIs).BitLength < 7 || (namedBits_OfferedCamel4CSIs).BitLength > 16 {
			if constraintErr := checkEncodedLength(opts, s47bb6e_11, "51.5", "offeredCamel4CSIs", "SIZE (7..16)", namedBitObservedLength(namedBits_OfferedCamel4CSIs)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_offeredcamel4csis, encodeErr_enc_offeredcamel4csis := ber.EncodeBitString(namedBits_OfferedCamel4CSIs.Bytes, ber.UnusedBitCount(namedBits_OfferedCamel4CSIs.BitLength))
		if encodeErr_enc_offeredcamel4csis != nil {
			return nil, qualifyBERError(encodeErr_enc_offeredcamel4csis, "offeredCamel4CSIs", "encoding", false)
		}
		retagged_enc_offeredcamel4csis, tagErr_enc_offeredcamel4csis := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_offeredcamel4csis)
		if tagErr_enc_offeredcamel4csis != nil {
			return nil, qualifyBERError(tagErr_enc_offeredcamel4csis, "offeredCamel4CSIs", "encoding", false)
		}
		enc_offeredcamel4csis = retagged_enc_offeredcamel4csis
		children = append(children, enc_offeredcamel4csis...)
	}
	base_ := -1
	for i, ext := range v.ExtData_ {
		if err := checkOpaqueAddition(ext, opts, s47bb6e_11, children, i, &base_); err != nil {
			return nil, opaqueExtensionError(err, i)
		}
		peekTag, n, _, extErr := ber.DecodeEncodedTLV(ext)
		if extErr != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, extErr)
		}
		if n != len(ext) {
			return nil, fmt.Errorf("encoding extension %d: %w", i, ber.ErrExtraData)
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: only the first addition is restricted.
		if i == 0 && ((peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0) || (peekTag.Class == tag.ClassUniversal && peekTag.Number == 16) || (peekTag.Class == tag.ClassUniversal && peekTag.Number == 5)) {
			if constraintErr := ber.CheckEncodedValue(ber.EncodeRule(opts, s47bb6e_11, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
				return nil, constraintErr
			}
		}
		children = append(children, ext...)
	}
	ber.RecordGeneratedBERContainer(opts, children)
	return ber.EncodeSequence(children)
}
func (v *CamelInfo) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// MarshalDER encodes CamelInfo to DER format.
// Opaque descendants pass generic DER checks; foreign schema rules need a typed binding.
func (v *CamelInfo) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: CamelInfo receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	namedBits_SupportedCamelPhases, namedBitErr_ := normalizeNamedBits(v.SupportedCamelPhases, []ber.NamedBitSizeSet{{{Min: 1, Max: 16}}}, nil, "supportedCamelPhases", s47bb6e_11)
	if namedBitErr_ != nil {
		return nil, namedBitErr_
	}
	if bitStringErr := ber.ValidateBitStringLength(namedBits_SupportedCamelPhases.Bytes, namedBits_SupportedCamelPhases.BitLength); bitStringErr != nil {
		return nil, qualifyBERError(bitStringErr, "supportedCamelPhases", "encoding", true)
	}
	// arithmetic pattern BER_BITSTRING_FIELD: 0 <= bit length before modulo and subtraction; gen/codegen.go:750
	if namedBits_SupportedCamelPhases.BitLength < 0 {
		return nil, fmt.Errorf("negative bit string length")
	}
	if (namedBits_SupportedCamelPhases).BitLength < 1 || (namedBits_SupportedCamelPhases).BitLength > 16 {
		if constraintErr := checkEncodedLength(nil, s47bb6e_11, "51.5", "supportedCamelPhases", "SIZE (1..16)", namedBitObservedLength(namedBits_SupportedCamelPhases)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_supportedcamelphases, encodeErr_enc_supportedcamelphases := ber.EncodeDERNamedBitString(namedBits_SupportedCamelPhases.Bytes, namedBits_SupportedCamelPhases.BitLength)
	if encodeErr_enc_supportedcamelphases != nil {
		return nil, qualifyBERError(encodeErr_enc_supportedcamelphases, "supportedCamelPhases", "encoding", true)
	}
	children = append(children, enc_supportedcamelphases...)
	if v.SuppressTCSI != nil {
		enc_suppresstcsi := ber.EncodeNull()
		children = append(children, enc_suppresstcsi...)
	}
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalDER()
		if err != nil {
			return nil, qualifyBERError(err, "extensionContainer", "encoding", true)
		}
		children = append(children, enc_extensioncontainer...)
	}
	if v.OfferedCamel4CSIs != nil {
		namedBits_OfferedCamel4CSIs, namedBitErr_ := normalizeNamedBits(*v.OfferedCamel4CSIs, []ber.NamedBitSizeSet{{{Min: 7, Max: 16}}}, nil, "offeredCamel4CSIs", s47bb6e_11)
		if namedBitErr_ != nil {
			return nil, namedBitErr_
		}
		if bitStringErr := ber.ValidateBitStringLength(namedBits_OfferedCamel4CSIs.Bytes, namedBits_OfferedCamel4CSIs.BitLength); bitStringErr != nil {
			return nil, qualifyBERError(bitStringErr, "offeredCamel4CSIs", "encoding", true)
		}
		// arithmetic pattern BER_BITSTRING_FIELD: 0 <= bit length before modulo and subtraction; gen/codegen.go:750
		if namedBits_OfferedCamel4CSIs.BitLength < 0 {
			return nil, fmt.Errorf("negative bit string length")
		}
		if (namedBits_OfferedCamel4CSIs).BitLength < 7 || (namedBits_OfferedCamel4CSIs).BitLength > 16 {
			if constraintErr := checkEncodedLength(nil, s47bb6e_11, "51.5", "offeredCamel4CSIs", "SIZE (7..16)", namedBitObservedLength(namedBits_OfferedCamel4CSIs)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_offeredcamel4csis, encodeErr_enc_offeredcamel4csis := ber.EncodeDERNamedBitString(namedBits_OfferedCamel4CSIs.Bytes, namedBits_OfferedCamel4CSIs.BitLength)
		if encodeErr_enc_offeredcamel4csis != nil {
			return nil, qualifyBERError(encodeErr_enc_offeredcamel4csis, "offeredCamel4CSIs", "encoding", true)
		}
		retagged_enc_offeredcamel4csis, tagErr_enc_offeredcamel4csis := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_offeredcamel4csis)
		if tagErr_enc_offeredcamel4csis != nil {
			return nil, qualifyBERError(tagErr_enc_offeredcamel4csis, "offeredCamel4CSIs", "encoding", true)
		}
		enc_offeredcamel4csis = retagged_enc_offeredcamel4csis
		children = append(children, enc_offeredcamel4csis...)
	}
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDEREncodedElement(ext); err != nil {
			return nil, invalidDERAddition(ext, s47bb6e_11, children, i)
		}
		peekTag, _, _, extErr := ber.DecodeEncodedTLV(ext)
		if extErr != nil {
			return nil, extErr
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: only the first addition is restricted.
		if i == 0 && ((peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0) || (peekTag.Class == tag.ClassUniversal && peekTag.Number == 16) || (peekTag.Class == tag.ClassUniversal && peekTag.Number == 5)) {
			if constraintErr := ber.CheckEncodedValue(ber.EncodeRule(nil, s47bb6e_11, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
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
		return nil, fmt.Errorf("%s: %w", "encoding CamelInfo as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}
func (v *CamelInfo) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	encoded, err := v.MarshalDER()
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBER decodes CamelInfo from BER/DER format.
func (destination *CamelInfo) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if destination == nil {
		return fmt.Errorf("%w: CamelInfo destination is nil", ber.ErrInvalidValue)
	}
	v := new(CamelInfo)
	defer publishDecodedValue(destination, v, &returnErr)

	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	preparedData, preparedOptions, prepareErr := prepareCompositeBER(data, opts, s47bb6e_11, "child", (*CamelInfo).UnmarshalBER)
	if prepareErr != nil {
		return prepareErr
	}
	data, opts = preparedData, preparedOptions

	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
	*v = CamelInfo{}
	defer func() {
		if returnErr == nil {
			returnErr = completeValueBER(data,
				opts, v, &v.berReplayNode_, (*CamelInfo).MarshalBER)
		}

	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("%s: %w", "decoding CamelInfo SEQUENCE", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "CamelInfo", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode supportedCamelPhases
	if offset >= len(content) {
		return fmt.Errorf("missing required field supportedCamelPhases")
	}
	{
		ber.MarkPreflightTarget(opts, "supportedCamelPhases", content[offset:])
		bsBytes_supportedcamelphases, bsUnused_supportedcamelphases, n, err := ber.DecodeBitString(content[offset:], opts...)
		if err != nil {
			return qualifyBERError(err, "supportedCamelPhases", "decoding", false)
		}
		bsBitLength_supportedcamelphases, bsLenErr_supportedcamelphases := ber.BitStringBitLength(len(bsBytes_supportedcamelphases), bsUnused_supportedcamelphases)
		if bsLenErr_supportedcamelphases != nil {
			return qualifyBERError(bsLenErr_supportedcamelphases, "supportedCamelPhases", "decoding", false)
		}
		v.SupportedCamelPhases = runtime.BitString{Bytes: bsBytes_supportedcamelphases, BitLength: bsBitLength_supportedcamelphases}
		if offset > len(content) || n < 0 || n > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n
		v.SupportedCamelPhases = ber.NormalizeNamedBitStringSize(v.SupportedCamelPhases, []ber.NamedBitSizeSet{{{Min: 1, Max: 16}}}, opts...)
		if (v.SupportedCamelPhases).BitLength < 1 || (v.SupportedCamelPhases).BitLength > 16 {
			if constraintErr := checkDecodedLength(opts, s47bb6e_11, "51.5", "supportedCamelPhases", "SIZE (1..16)", (v.SupportedCamelPhases).BitLength); constraintErr != nil {
				return constraintErr
			}
		}
	}
	// Decode suppress-T-CSI
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassUniversal && peekTag.Number == 5 {
				ber.MarkPreflightTarget(opts, "suppress-T-CSI", content[offset:])
				n, err := ber.DecodeNull(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "suppress-T-CSI", "decoding", false)
				}
				v.SuppressTCSI = &struct{}{}
				if offset < 0 || offset >
					len(content) || n < 0 || n > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n
			}
		}
	}
	// Decode extensionContainer
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassUniversal && peekTag.Number == 16 {
				ber.MarkPreflightTarget(opts, "extensionContainer", content[offset:])
				// Decode nested SEQUENCE (ExtensionContainer)
				_, n_extensioncontainer, _, tlvErr_extensioncontainer := ber.DecodeTLV(content[offset:], opts...)
				if tlvErr_extensioncontainer != nil {
					return qualifyBERError(tlvErr_extensioncontainer, "extensionContainer", "decoding", false)
				}
				var dec_extensioncontainer ExtensionContainer
				if offset < 0 || offset >
					len(content) || n_extensioncontainer < 0 || n_extensioncontainer >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				if unmErr := dec_extensioncontainer.UnmarshalBER(content[offset:offset+n_extensioncontainer], ber.ChildDecodeOptions(opts, "extensionContainer")...); unmErr != nil {
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
	// Decode offeredCamel4CSIs
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
				ber.MarkPreflightTarget(opts, "offeredCamel4CSIs", content[offset:])
				decodedTag_offeredcamel4csis, n_offeredcamel4csis, rawVal_offeredcamel4csis, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "offeredCamel4CSIs", "decoding", false)
				}
				if decodedTag_offeredcamel4csis.Class != tag.ClassContextSpecific || decodedTag_offeredcamel4csis.Number != 0 {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_offeredcamel4csis), "offeredCamel4CSIs", "decoding", false)
				}
				bsBytes_offeredcamel4csis, bsUnused_offeredcamel4csis, bsErr := ber.DecodeImplicitBitStringValue(decodedTag_offeredcamel4csis.Constructed, rawVal_offeredcamel4csis, opts...)
				if bsErr != nil {
					return qualifyBERError(bsErr, "offeredCamel4CSIs", "decoding", false)
				}
				bsBitLength_offeredcamel4csis, bsLenErr_offeredcamel4csis := ber.BitStringBitLength(len(bsBytes_offeredcamel4csis), bsUnused_offeredcamel4csis)
				if bsLenErr_offeredcamel4csis != nil {
					return qualifyBERError(bsLenErr_offeredcamel4csis, "offeredCamel4CSIs", "decoding", false)
				}
				tmp_offeredcamel4csis := runtime.BitString{Bytes: bsBytes_offeredcamel4csis, BitLength: bsBitLength_offeredcamel4csis}
				v.OfferedCamel4CSIs = &tmp_offeredcamel4csis
				if offset < 0 || offset >
					len(content) || n_offeredcamel4csis < 0 || n_offeredcamel4csis >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_offeredcamel4csis
				*v.OfferedCamel4CSIs = ber.NormalizeNamedBitStringSize(*v.OfferedCamel4CSIs, []ber.NamedBitSizeSet{{{Min: 7, Max: 16}}}, opts...)
				if (*v.OfferedCamel4CSIs).BitLength < 7 || (*v.OfferedCamel4CSIs).BitLength > 16 {
					if constraintErr := checkDecodedLength(opts, s47bb6e_11, "51.5", "offeredCamel4CSIs", "SIZE (7..16)", (*v.OfferedCamel4CSIs).BitLength); constraintErr != nil {
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
			return &ber.DecodeError{Offset: offset, TypeName: "CamelInfo", Cause: extErr_}
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: the first unknown addition must differ from trailing OPTIONAL/DEFAULT tags.
		if len(v.ExtData_) == 0 && ((peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0) || (peekTag.Class == tag.ClassUniversal && peekTag.Number == 16) || (peekTag.Class == tag.ClassUniversal && peekTag.Number == 5)) {
			if !ber.ToleranceEnabled(opts) {
				return &ber.DecodeError{Offset: offset, TypeName: "CamelInfo", Cause: fmt.Errorf("%w: repeated or out-of-order SEQUENCE component tag %s", ber.ErrInvalidTag, peekTag)}
			}
			if orderErr_ := ber.CheckDecodedValue(ber.DecodeRule(opts, s47bb6e_11, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), fmt.Sprintf("ExtData_[%d]", len(v.ExtData_)), "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); orderErr_ != nil {
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

// MarshalBER encodes ExtendedRoutingInfo to BER format.
func (v *ExtendedRoutingInfo) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {

	if v == nil {
		return nil, fmt.Errorf("%w: ExtendedRoutingInfo receiver is nil", ber.ErrInvalidValue)
	}
	return marshalFramedValue(v, v.berReplayNode_, opts, (*ExtendedRoutingInfo).MarshalBER, (*ExtendedRoutingInfo).marshalBER, 3)

}
func (v *ExtendedRoutingInfo) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}
func (v *ExtendedRoutingInfo) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	switch v.Choice {
	case ExtendedRoutingInfoChoiceRoutingInfo:
		if v.RoutingInfo == nil {
			return nil, fmt.Errorf("%w: choice ExtendedRoutingInfo: routingInfo is nil", ber.ErrInvalidValue)
		}
		enc_0, err := v.RoutingInfo.MarshalBER(ber.ChildEncodeOptions(opts, "routingInfo")...)
		if err != nil {
			return nil, qualifyBERError(err, "routingInfo", "encoding", false)
		}
		return enc_0, nil
	case ExtendedRoutingInfoChoiceCamelRoutingInfo:
		if v.CamelRoutingInfo == nil {
			return nil, fmt.Errorf("%w: choice ExtendedRoutingInfo: camelRoutingInfo is nil", ber.ErrInvalidValue)
		}
		enc_1, err := v.CamelRoutingInfo.MarshalBER(ber.ChildEncodeOptions(opts, "camelRoutingInfo")...)
		if err != nil {
			return nil, qualifyBERError(err, "camelRoutingInfo", "encoding", false)
		}
		retagged_enc_1, tagErr_enc_1 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 8, enc_1)
		if tagErr_enc_1 != nil {
			return nil, qualifyBERError(tagErr_enc_1, "camelRoutingInfo", "encoding", false)
		}
		enc_1 = retagged_enc_1
		return enc_1, nil
	default:
		return nil, fmt.Errorf("unknown choice %d for ExtendedRoutingInfo", v.Choice)
	}
}

// MarshalDER encodes ExtendedRoutingInfo to DER format.
// Opaque descendants pass generic DER checks; foreign schema rules need a typed binding.
func (v *ExtendedRoutingInfo) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: ExtendedRoutingInfo receiver is nil", ber.ErrInvalidValue)
	}
	switch v.Choice {
	case ExtendedRoutingInfoChoiceRoutingInfo:
		if v.RoutingInfo == nil {
			return nil, fmt.Errorf("%w: choice ExtendedRoutingInfo: routingInfo is nil", ber.ErrInvalidValue)
		}
		enc_der_0, err := v.RoutingInfo.MarshalDER()
		if err != nil {
			return nil, qualifyBERError(err, "routingInfo", "encoding", true)
		}
		if derErr := ber.ValidateDEREncodedElement(enc_der_0); derErr != nil {
			return nil, qualifyBERError(derErr, "routingInfo", "encoding", true)
		}
		return enc_der_0, nil
	case ExtendedRoutingInfoChoiceCamelRoutingInfo:
		if v.CamelRoutingInfo == nil {
			return nil, fmt.Errorf("%w: choice ExtendedRoutingInfo: camelRoutingInfo is nil", ber.ErrInvalidValue)
		}
		enc_der_1, err := v.CamelRoutingInfo.MarshalDER()
		if err != nil {
			return nil, qualifyBERError(err, "camelRoutingInfo", "encoding", true)
		}
		retagged_enc_der_1, tagErr_enc_der_1 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 8, enc_der_1)
		if tagErr_enc_der_1 != nil {
			return nil, qualifyBERError(tagErr_enc_der_1, "camelRoutingInfo", "encoding", true)
		}
		enc_der_1 = retagged_enc_der_1
		if derErr := ber.ValidateDEREncodedElement(enc_der_1); derErr != nil {
			return nil, qualifyBERError(derErr, "camelRoutingInfo", "encoding", true)
		}
		return enc_der_1, nil
	}
	encoded, err := v.marshalBER()
	if err != nil {
		return nil, err
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		switch v.Choice {
		case ExtendedRoutingInfoChoiceRoutingInfo:
			return nil, qualifyBERError(err, "routingInfo", "encoding", true)
		case ExtendedRoutingInfoChoiceCamelRoutingInfo:
			return nil, qualifyBERError(err, "camelRoutingInfo", "encoding", true)
		}
		return nil, fmt.Errorf("%s: %w", "encoding ExtendedRoutingInfo as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}

func (v *ExtendedRoutingInfo) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	encoded, err := v.MarshalDER()
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBER decodes ExtendedRoutingInfo from BER/DER format.
func (destination *ExtendedRoutingInfo) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if destination == nil {
		return fmt.Errorf("%w: ExtendedRoutingInfo destination is nil", ber.ErrInvalidValue)
	}
	v := new(ExtendedRoutingInfo)

	defer publishDecodedValue(destination, v, &returnErr)

	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	preparedData, preparedOptions, prepareErr := prepareCompositeBER(data, opts, "MAP-CH-DataTypes.ExtendedRoutingInfo", "child", (*ExtendedRoutingInfo).UnmarshalBER)
	if prepareErr != nil {
		return prepareErr
	}
	data, opts = preparedData, preparedOptions
	defer func() {
		if returnErr == nil {
			returnErr = completeValueBER(data,
				opts, v, &v.berReplayNode_, (*ExtendedRoutingInfo).MarshalBER)
		}

	}()

	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
	*v = ExtendedRoutingInfo{}
	if len(data) == 0 {
		return fmt.Errorf("empty data for ExtendedRoutingInfo CHOICE")
	}
	choiceData := data
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for ExtendedRoutingInfo: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData, opts...)
	if tlvErr != nil {
		return fmt.Errorf("%s: %w", "decoding ExtendedRoutingInfo CHOICE", qualifyBERError(tlvErr, "", "decoding", false))
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "ExtendedRoutingInfo", Cause: ber.ErrExtraData}
	}

	if (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 8) && peekTag.Constructed != true {
		return qualifyBERError(fmt.Errorf("%w: invalid primitive/constructed form for tag %s", ber.ErrInvalidTag, peekTag), "ExtendedRoutingInfo.camelRoutingInfo", "decoding", false)
	}
	if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 8 && peekTag.Constructed == true {
		v.Choice = ExtendedRoutingInfoChoiceCamelRoutingInfo
		ber.MarkPreflightTarget(opts, "camelRoutingInfo", choiceData)
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData, opts...)
		if tlvErr != nil {
			return qualifyBERError(tlvErr, "camelRoutingInfo", "decoding", false)
		}
		_ = rawVal
		reconstructed, reconstructionErr := ber.EncodeImplicitTagWithClass(tag.ClassUniversal, tag.TagSequence, choiceData)
		if reconstructionErr != nil {
			return reconstructionErr
		}
		var dec CamelRoutingInfo
		if unmErr := dec.UnmarshalBER(reconstructed, ber.ChildDecodeOptions(opts, "camelRoutingInfo")...); unmErr != nil {
			return qualifyBERError(unmErr, "camelRoutingInfo", "decoding", false)
		}
		v.CamelRoutingInfo = &dec
	} else {
		v.Choice = ExtendedRoutingInfoChoiceRoutingInfo
		var dec RoutingInfo
		if unmErr := dec.UnmarshalBER(choiceData, ber.ChildDecodeOptions(opts, "routingInfo")...); unmErr != nil {
			return qualifyBERError(unmErr, "routingInfo", "decoding", false)
		}
		v.RoutingInfo = &dec
	}
	return nil
}

// MarshalBER encodes CamelRoutingInfo to BER format.
func (v *CamelRoutingInfo) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {

	if v == nil {
		return nil, fmt.Errorf("%w: CamelRoutingInfo receiver is nil", ber.ErrInvalidValue)
	}
	return marshalFramedValue(v, v.berReplayNode_, opts, (*CamelRoutingInfo).MarshalBER, (*CamelRoutingInfo).marshalBER, 3)

}
func (v *CamelRoutingInfo) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if v.ForwardingData != nil {
		enc_forwardingdata, err := v.ForwardingData.MarshalBER(ber.ChildEncodeOptions(opts, "forwardingData")...)
		if err != nil {
			return nil, qualifyBERError(err, "forwardingData", "encoding", false)
		}
		ber.RecordGeneratedBERChildPlacement(opts, len(children), enc_forwardingdata)
		children = append(children, enc_forwardingdata...)
	}
	enc_gmsccamelsubscriptioninfo, err := v.GmscCamelSubscriptionInfo.MarshalBER(ber.ChildEncodeOptions(opts, "gmscCamelSubscriptionInfo")...)
	if err != nil {
		return nil, qualifyBERError(err, "gmscCamelSubscriptionInfo", "encoding", false)
	}
	retagged_enc_gmsccamelsubscriptioninfo, tagErr_enc_gmsccamelsubscriptioninfo := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_gmsccamelsubscriptioninfo)
	if tagErr_enc_gmsccamelsubscriptioninfo != nil {
		return nil, qualifyBERError(tagErr_enc_gmsccamelsubscriptioninfo, "gmscCamelSubscriptionInfo", "encoding", false)
	}
	enc_gmsccamelsubscriptioninfo = retagged_enc_gmsccamelsubscriptioninfo
	ber.RecordGeneratedBERChildPlacement(opts, len(children), enc_gmsccamelsubscriptioninfo)
	children = append(children, enc_gmsccamelsubscriptioninfo...)
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
	base_ := -1
	for i, ext := range v.ExtData_ {
		if err := checkOpaqueAddition(ext, opts, s47bb6e_12, children, i, &base_); err != nil {
			return nil, opaqueExtensionError(err, i)
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
			if constraintErr := ber.CheckEncodedValue(ber.EncodeRule(opts, s47bb6e_12, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
				return nil, constraintErr
			}
		}
		children = append(children, ext...)
	}
	ber.RecordGeneratedBERContainer(opts, children)
	return ber.EncodeSequence(children)
}
func (v *CamelRoutingInfo) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// MarshalDER encodes CamelRoutingInfo to DER format.
// Opaque descendants pass generic DER checks; foreign schema rules need a typed binding.
func (v *CamelRoutingInfo) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: CamelRoutingInfo receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if v.ForwardingData != nil {
		enc_forwardingdata, err := v.ForwardingData.MarshalDER()
		if err != nil {
			return nil, qualifyBERError(err, "forwardingData", "encoding", true)
		}
		children = append(children, enc_forwardingdata...)
	}
	enc_gmsccamelsubscriptioninfo, err := v.GmscCamelSubscriptionInfo.MarshalDER()
	if err != nil {
		return nil, qualifyBERError(err, "gmscCamelSubscriptionInfo", "encoding", true)
	}
	retagged_enc_gmsccamelsubscriptioninfo, tagErr_enc_gmsccamelsubscriptioninfo := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_gmsccamelsubscriptioninfo)
	if tagErr_enc_gmsccamelsubscriptioninfo != nil {
		return nil, qualifyBERError(tagErr_enc_gmsccamelsubscriptioninfo, "gmscCamelSubscriptionInfo", "encoding", true)
	}
	enc_gmsccamelsubscriptioninfo = retagged_enc_gmsccamelsubscriptioninfo
	children = append(children, enc_gmsccamelsubscriptioninfo...)
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
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDEREncodedElement(ext); err != nil {
			return nil, invalidDERAddition(ext, s47bb6e_12, children, i)
		}
		peekTag, _, _, extErr := ber.DecodeEncodedTLV(ext)
		if extErr != nil {
			return nil, extErr
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: only the first addition is restricted.
		if i == 0 && (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1) {
			if constraintErr := ber.CheckEncodedValue(ber.EncodeRule(nil, s47bb6e_12, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
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
		return nil, fmt.Errorf("%s: %w", "encoding CamelRoutingInfo as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}
func (v *CamelRoutingInfo) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	encoded, err := v.MarshalDER()
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBER decodes CamelRoutingInfo from BER/DER format.
func (destination *CamelRoutingInfo) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if destination == nil {
		return fmt.Errorf("%w: CamelRoutingInfo destination is nil", ber.ErrInvalidValue)
	}
	v := new(CamelRoutingInfo)

	defer publishDecodedValue(destination, v, &returnErr)

	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	preparedData, preparedOptions, prepareErr := prepareCompositeBER(data, opts, s47bb6e_12, "child", (*CamelRoutingInfo).UnmarshalBER)
	if prepareErr != nil {
		return prepareErr
	}
	data, opts = preparedData, preparedOptions

	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
	*v = CamelRoutingInfo{}
	defer func() {
		if returnErr == nil {
			returnErr = completeValueBER(data,
				opts, v, &v.berReplayNode_, (*CamelRoutingInfo).MarshalBER)
		}

	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("%s: %w", "decoding CamelRoutingInfo SEQUENCE", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "CamelRoutingInfo", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode forwardingData
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassUniversal && peekTag.Number == 16 {
				ber.MarkPreflightTarget(opts, "forwardingData", content[offset:])
				// Decode nested SEQUENCE (ForwardingData)
				_, n_forwardingdata, _, tlvErr_forwardingdata := ber.DecodeTLV(content[offset:], opts...)
				if tlvErr_forwardingdata != nil {
					return qualifyBERError(tlvErr_forwardingdata, "forwardingData", "decoding", false)
				}
				var dec_forwardingdata ForwardingData
				if offset > len(content) || n_forwardingdata < 0 || n_forwardingdata > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				if unmErr := dec_forwardingdata.UnmarshalBER(content[offset:offset+n_forwardingdata], ber.ChildDecodeOptions(opts, "forwardingData")...); unmErr != nil {
					return qualifyBERError(unmErr, "forwardingData", "decoding", false)
				}
				v.ForwardingData = &dec_forwardingdata
				if offset > len(content) || n_forwardingdata < 0 || n_forwardingdata > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_forwardingdata
			}
		}
	}
	// Decode gmscCamelSubscriptionInfo
	if offset >= len(content) {
		return fmt.Errorf("missing required field gmscCamelSubscriptionInfo")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 0 {
			return fmt.Errorf("expected tag [%s %d] for gmscCamelSubscriptionInfo, got %s", "CONTEXT", 0, reqTag_)
		}
	}
	{
		ber.MarkPreflightTarget(opts, "gmscCamelSubscriptionInfo", content[offset:])
		decodedTag_gmsccamelsubscriptioninfo, n_gmsccamelsubscriptioninfo, rawVal_gmsccamelsubscriptioninfo, err := ber.DecodeTLV(content[offset:], opts...)
		if err != nil {
			return qualifyBERError(err, "gmscCamelSubscriptionInfo", "decoding", false)
		}
		if decodedTag_gmsccamelsubscriptioninfo.Class != tag.ClassContextSpecific || decodedTag_gmsccamelsubscriptioninfo.Number != 0 || decodedTag_gmsccamelsubscriptioninfo.Constructed != true {
			return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_gmsccamelsubscriptioninfo), "gmscCamelSubscriptionInfo", "decoding", false)
		}
		_ = rawVal_gmsccamelsubscriptioninfo
		if offset < 0 || offset >
			len(content) || n_gmsccamelsubscriptioninfo < 0 || n_gmsccamelsubscriptioninfo >
			len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		reconstructed_gmsccamelsubscriptioninfo, reconstructionErr_gmsccamelsubscriptioninfo := ber.EncodeImplicitTagWithClass(tag.ClassUniversal, tag.TagSequence, content[offset:offset+n_gmsccamelsubscriptioninfo])
		if reconstructionErr_gmsccamelsubscriptioninfo != nil {
			return qualifyBERError(reconstructionErr_gmsccamelsubscriptioninfo, "gmscCamelSubscriptionInfo", "decoding", false)
		}
		if unmErr := v.GmscCamelSubscriptionInfo.UnmarshalBER(reconstructed_gmsccamelsubscriptioninfo, ber.ChildDecodeOptions(opts, "gmscCamelSubscriptionInfo")...); unmErr != nil {
			return qualifyBERError(unmErr, "gmscCamelSubscriptionInfo", "decoding", false)
		}
		if offset < 0 || offset >
			len(content) || n_gmsccamelsubscriptioninfo < 0 || n_gmsccamelsubscriptioninfo >
			len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n_gmsccamelsubscriptioninfo
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
				var dec_extensioncontainer ExtensionContainer
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
			return &ber.DecodeError{Offset: offset, TypeName: "CamelRoutingInfo", Cause: extErr_}
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: the first unknown addition must differ from trailing OPTIONAL/DEFAULT tags.
		if len(v.ExtData_) == 0 && (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1) {
			if !ber.ToleranceEnabled(opts) {
				return &ber.DecodeError{Offset: offset, TypeName: "CamelRoutingInfo", Cause: fmt.Errorf("%w: repeated or out-of-order SEQUENCE component tag %s", ber.ErrInvalidTag, peekTag)}
			}
			if orderErr_ := ber.CheckDecodedValue(ber.DecodeRule(opts, s47bb6e_12, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), fmt.Sprintf("ExtData_[%d]", len(v.ExtData_)), "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); orderErr_ != nil {
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

// MarshalBER encodes GmscCamelSubscriptionInfo to BER format.
func (v *GmscCamelSubscriptionInfo) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {

	if v == nil {
		return nil, fmt.Errorf("%w: GmscCamelSubscriptionInfo receiver is nil", ber.ErrInvalidValue)
	}
	return marshalFramedValue(v, v.berReplayNode_, opts, (*GmscCamelSubscriptionInfo).MarshalBER, (*GmscCamelSubscriptionInfo).marshalBER, 3)

}
func (v *GmscCamelSubscriptionInfo) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if v.TCSI != nil {
		enc_tcsi, err := v.TCSI.MarshalBER(ber.ChildEncodeOptions(opts, "t-CSI")...)
		if err != nil {
			return nil, qualifyBERError(err, "t-CSI", "encoding", false)
		}
		retagged_enc_tcsi, tagErr_enc_tcsi := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_tcsi)
		if tagErr_enc_tcsi != nil {
			return nil, qualifyBERError(tagErr_enc_tcsi, "t-CSI", "encoding", false)
		}
		enc_tcsi = retagged_enc_tcsi
		ber.RecordGeneratedBERChildPlacement(opts, len(children), enc_tcsi)
		children = append(children, enc_tcsi...)
	}
	if v.OCSI != nil {
		enc_ocsi, err := v.OCSI.MarshalBER(ber.ChildEncodeOptions(opts, "o-CSI")...)
		if err != nil {
			return nil, qualifyBERError(err, "o-CSI", "encoding", false)
		}
		retagged_enc_ocsi, tagErr_enc_ocsi := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_ocsi)
		if tagErr_enc_ocsi != nil {
			return nil, qualifyBERError(tagErr_enc_ocsi, "o-CSI", "encoding", false)
		}
		enc_ocsi = retagged_enc_ocsi
		ber.RecordGeneratedBERChildPlacement(opts, len(children), enc_ocsi)
		children = append(children, enc_ocsi...)
	}
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
	if v.OBcsmCamelTDPCriteriaList != nil {
		if len((v.OBcsmCamelTDPCriteriaList).Values) < 1 || len((v.OBcsmCamelTDPCriteriaList).Values) > 10 {
			if constraintErr := checkEncodedLength(opts, s47bb6e_13, "51.5", "o-BcsmCamelTDP-CriteriaList", "SIZE (1..10)", len((v.OBcsmCamelTDPCriteriaList).Values)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_obcsmcameltdpcriterialist, err := MarshalBEROBcsmCamelTDPCriteriaList(v.OBcsmCamelTDPCriteriaList, ber.ParentCollectionSizeEncodeOptions(ber.ChildEncodeOptions(opts, "o-BcsmCamelTDP-CriteriaList"))...)
		if err != nil {
			return nil, qualifyBERError(err, "o-BcsmCamelTDP-CriteriaList", "encoding", false)
		}
		if ber.BERReplayEnabled(opts) && v.berOBcsmCamelTDPCriteriaListIndef_ {
			// Strip the outer SEQUENCE tag from marshalBER output to get raw children.
			_, _, seqContent_, tlvErr_ := ber.DecodeEncodedTLV(enc_obcsmcameltdpcriterialist)
			if tlvErr_ != nil {
				return nil, tlvErr_
			}
			{
				var encodeErr error
				enc_obcsmcameltdpcriterialist, encodeErr = ber.EncodeConstructedIndefinite(tag.Tag{Class: tag.ClassContextSpecific, Number: 3}, seqContent_)
				if encodeErr != nil {
					return nil, qualifyBERError(encodeErr, "o-BcsmCamelTDP-CriteriaList", "encoding", false)
				}
			}
		} else {
			retagged_enc_obcsmcameltdpcriterialist, tagErr_enc_obcsmcameltdpcriterialist := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, enc_obcsmcameltdpcriterialist)
			if tagErr_enc_obcsmcameltdpcriterialist != nil {
				return nil, qualifyBERError(tagErr_enc_obcsmcameltdpcriterialist, "o-BcsmCamelTDP-CriteriaList", "encoding", false)
			}
			enc_obcsmcameltdpcriterialist = retagged_enc_obcsmcameltdpcriterialist
		}
		ber.RecordGeneratedBERChildPlacement(opts, len(children), enc_obcsmcameltdpcriterialist)
		children = append(children, enc_obcsmcameltdpcriterialist...)
	}
	if v.TBCSMCAMELTDPCriteriaList != nil {
		if len((v.TBCSMCAMELTDPCriteriaList).Values) < 1 || len((v.TBCSMCAMELTDPCriteriaList).Values) > 10 {
			if constraintErr := checkEncodedLength(opts, s47bb6e_13, "51.5", "t-BCSM-CAMEL-TDP-CriteriaList", "SIZE (1..10)", len((v.TBCSMCAMELTDPCriteriaList).Values)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_tbcsmcameltdpcriterialist, err := MarshalBERTBCSMCAMELTDPCriteriaList(v.TBCSMCAMELTDPCriteriaList, ber.ParentCollectionSizeEncodeOptions(ber.ChildEncodeOptions(opts, "t-BCSM-CAMEL-TDP-CriteriaList"))...)
		if err != nil {
			return nil, qualifyBERError(err, "t-BCSM-CAMEL-TDP-CriteriaList", "encoding", false)
		}
		if ber.BERReplayEnabled(opts) && v.berTBCSMCAMELTDPCriteriaListIndef_ {
			// Strip the outer SEQUENCE tag from marshalBER output to get raw children.
			_, _, seqContent_, tlvErr_ := ber.DecodeEncodedTLV(enc_tbcsmcameltdpcriterialist)
			if tlvErr_ != nil {
				return nil, tlvErr_
			}
			{
				var encodeErr error
				enc_tbcsmcameltdpcriterialist, encodeErr = ber.EncodeConstructedIndefinite(tag.Tag{Class: tag.ClassContextSpecific, Number: 4}, seqContent_)
				if encodeErr != nil {
					return nil, qualifyBERError(encodeErr, "t-BCSM-CAMEL-TDP-CriteriaList", "encoding", false)
				}
			}
		} else {
			retagged_enc_tbcsmcameltdpcriterialist, tagErr_enc_tbcsmcameltdpcriterialist := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, enc_tbcsmcameltdpcriterialist)
			if tagErr_enc_tbcsmcameltdpcriterialist != nil {
				return nil, qualifyBERError(tagErr_enc_tbcsmcameltdpcriterialist, "t-BCSM-CAMEL-TDP-CriteriaList", "encoding", false)
			}
			enc_tbcsmcameltdpcriterialist = retagged_enc_tbcsmcameltdpcriterialist
		}
		ber.RecordGeneratedBERChildPlacement(opts, len(children), enc_tbcsmcameltdpcriterialist)
		children = append(children, enc_tbcsmcameltdpcriterialist...)
	}
	if v.DCsi != nil {
		enc_dcsi, err := v.DCsi.MarshalBER(ber.ChildEncodeOptions(opts, "d-csi")...)
		if err != nil {
			return nil, qualifyBERError(err, "d-csi", "encoding", false)
		}
		retagged_enc_dcsi, tagErr_enc_dcsi := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 5, enc_dcsi)
		if tagErr_enc_dcsi != nil {
			return nil, qualifyBERError(tagErr_enc_dcsi, "d-csi", "encoding", false)
		}
		enc_dcsi = retagged_enc_dcsi
		ber.RecordGeneratedBERChildPlacement(opts, len(children), enc_dcsi)
		children = append(children, enc_dcsi...)
	}
	base_ := -1
	for i, ext := range v.ExtData_ {
		if err := checkOpaqueAddition(ext, opts, s47bb6e_13, children, i, &base_); err != nil {
			return nil, opaqueExtensionError(err, i)
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
			if constraintErr := ber.CheckEncodedValue(ber.EncodeRule(opts, s47bb6e_13, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
				return nil, constraintErr
			}
		}
		children = append(children, ext...)
	}
	ber.RecordGeneratedBERContainer(opts, children)
	return ber.EncodeSequence(children)
}
func (v *GmscCamelSubscriptionInfo) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// MarshalDER encodes GmscCamelSubscriptionInfo to DER format.
// Opaque descendants pass generic DER checks; foreign schema rules need a typed binding.
func (v *GmscCamelSubscriptionInfo) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: GmscCamelSubscriptionInfo receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if v.TCSI != nil {
		enc_tcsi, err := v.TCSI.MarshalDER()
		if err != nil {
			return nil, qualifyBERError(err, "t-CSI", "encoding", true)
		}
		retagged_enc_tcsi, tagErr_enc_tcsi := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_tcsi)
		if tagErr_enc_tcsi != nil {
			return nil, qualifyBERError(tagErr_enc_tcsi, "t-CSI", "encoding", true)
		}
		enc_tcsi = retagged_enc_tcsi
		children = append(children, enc_tcsi...)
	}
	if v.OCSI != nil {
		enc_ocsi, err := v.OCSI.MarshalDER()
		if err != nil {
			return nil, qualifyBERError(err, "o-CSI", "encoding", true)
		}
		retagged_enc_ocsi, tagErr_enc_ocsi := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_ocsi)
		if tagErr_enc_ocsi != nil {
			return nil, qualifyBERError(tagErr_enc_ocsi, "o-CSI", "encoding", true)
		}
		enc_ocsi = retagged_enc_ocsi
		children = append(children, enc_ocsi...)
	}
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
	if v.OBcsmCamelTDPCriteriaList != nil {
		if len((v.OBcsmCamelTDPCriteriaList).Values) < 1 || len((v.OBcsmCamelTDPCriteriaList).Values) > 10 {
			if constraintErr := checkEncodedLength(nil, s47bb6e_13, "51.5", "o-BcsmCamelTDP-CriteriaList", "SIZE (1..10)", len((v.OBcsmCamelTDPCriteriaList).Values)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_obcsmcameltdpcriterialist, err := MarshalDEROBcsmCamelTDPCriteriaList(v.OBcsmCamelTDPCriteriaList)
		if err != nil {
			return nil, qualifyBERError(err, "o-BcsmCamelTDP-CriteriaList", "encoding", true)
		}
		retagged_enc_obcsmcameltdpcriterialist, tagErr_enc_obcsmcameltdpcriterialist := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, enc_obcsmcameltdpcriterialist)
		if tagErr_enc_obcsmcameltdpcriterialist != nil {
			return nil, qualifyBERError(tagErr_enc_obcsmcameltdpcriterialist, "o-BcsmCamelTDP-CriteriaList", "encoding", true)
		}
		enc_obcsmcameltdpcriterialist = retagged_enc_obcsmcameltdpcriterialist
		children = append(children, enc_obcsmcameltdpcriterialist...)
	}
	if v.TBCSMCAMELTDPCriteriaList != nil {
		if len((v.TBCSMCAMELTDPCriteriaList).Values) < 1 || len((v.TBCSMCAMELTDPCriteriaList).Values) > 10 {
			if constraintErr := checkEncodedLength(nil, s47bb6e_13, "51.5", "t-BCSM-CAMEL-TDP-CriteriaList", "SIZE (1..10)", len((v.TBCSMCAMELTDPCriteriaList).Values)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_tbcsmcameltdpcriterialist, err := MarshalDERTBCSMCAMELTDPCriteriaList(v.TBCSMCAMELTDPCriteriaList)
		if err != nil {
			return nil, qualifyBERError(err, "t-BCSM-CAMEL-TDP-CriteriaList", "encoding", true)
		}
		retagged_enc_tbcsmcameltdpcriterialist, tagErr_enc_tbcsmcameltdpcriterialist := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, enc_tbcsmcameltdpcriterialist)
		if tagErr_enc_tbcsmcameltdpcriterialist != nil {
			return nil, qualifyBERError(tagErr_enc_tbcsmcameltdpcriterialist, "t-BCSM-CAMEL-TDP-CriteriaList", "encoding", true)
		}
		enc_tbcsmcameltdpcriterialist = retagged_enc_tbcsmcameltdpcriterialist
		children = append(children, enc_tbcsmcameltdpcriterialist...)
	}
	if v.DCsi != nil {
		enc_dcsi, err := v.DCsi.MarshalDER()
		if err != nil {
			return nil, qualifyBERError(err, "d-csi", "encoding", true)
		}
		retagged_enc_dcsi, tagErr_enc_dcsi := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 5, enc_dcsi)
		if tagErr_enc_dcsi != nil {
			return nil, qualifyBERError(tagErr_enc_dcsi, "d-csi", "encoding", true)
		}
		enc_dcsi = retagged_enc_dcsi
		children = append(children, enc_dcsi...)
	}
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDEREncodedElement(ext); err != nil {
			return nil, invalidDERAddition(ext, s47bb6e_13, children, i)
		}
		peekTag, _, _, extErr := ber.DecodeEncodedTLV(ext)
		if extErr != nil {
			return nil, extErr
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: only the first addition is restricted.
		if i == 0 && ((peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 5) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0)) {
			if constraintErr := ber.CheckEncodedValue(ber.EncodeRule(nil, s47bb6e_13, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
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
		return nil, fmt.Errorf("%s: %w", "encoding GmscCamelSubscriptionInfo as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}
func (v *GmscCamelSubscriptionInfo) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	encoded, err := v.MarshalDER()
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBER decodes GmscCamelSubscriptionInfo from BER/DER format.
func (destination *GmscCamelSubscriptionInfo) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if destination == nil {
		return fmt.Errorf("%w: GmscCamelSubscriptionInfo destination is nil", ber.ErrInvalidValue)
	}
	v := new(GmscCamelSubscriptionInfo)

	defer publishDecodedValue(destination, v, &returnErr)

	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	preparedData, preparedOptions, prepareErr := prepareCompositeBER(data, opts, s47bb6e_13, "child", (*GmscCamelSubscriptionInfo).UnmarshalBER)
	if prepareErr != nil {
		return prepareErr
	}
	data, opts = preparedData, preparedOptions

	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
	*v = GmscCamelSubscriptionInfo{}
	defer func() {
		if returnErr == nil {
			returnErr = completeValueBER(data,
				opts, v, &v.berReplayNode_, (*GmscCamelSubscriptionInfo).MarshalBER)
		}

	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("%s: %w", "decoding GmscCamelSubscriptionInfo SEQUENCE", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "GmscCamelSubscriptionInfo", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode t-CSI
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
				ber.MarkPreflightTarget(opts, "t-CSI", content[offset:])
				decodedTag_tcsi, n_tcsi, rawVal_tcsi, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "t-CSI", "decoding", false)
				}
				if decodedTag_tcsi.Class != tag.ClassContextSpecific || decodedTag_tcsi.Number != 0 || decodedTag_tcsi.Constructed != true {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_tcsi), "t-CSI", "decoding", false)
				}
				_ = rawVal_tcsi
				if offset > len(content) || n_tcsi < 0 || n_tcsi > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				reconstructed_tcsi, reconstructionErr_tcsi := ber.EncodeImplicitTagWithClass(tag.ClassUniversal, tag.TagSequence, content[offset:offset+n_tcsi])
				if reconstructionErr_tcsi != nil {
					return qualifyBERError(reconstructionErr_tcsi, "t-CSI", "decoding", false)
				}
				var dec_tcsi TCSI
				if unmErr := dec_tcsi.UnmarshalBER(reconstructed_tcsi, ber.ChildDecodeOptions(opts, "t-CSI")...); unmErr != nil {
					return qualifyBERError(unmErr, "t-CSI", "decoding", false)
				}
				v.TCSI = &dec_tcsi
				if offset > len(content) || n_tcsi < 0 || n_tcsi > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_tcsi
			}
		}
	}
	// Decode o-CSI
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
				ber.MarkPreflightTarget(opts, "o-CSI", content[offset:])
				decodedTag_ocsi, n_ocsi, rawVal_ocsi, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "o-CSI", "decoding", false)
				}
				if decodedTag_ocsi.Class != tag.ClassContextSpecific || decodedTag_ocsi.Number != 1 || decodedTag_ocsi.Constructed != true {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_ocsi), "o-CSI", "decoding", false)
				}
				_ = rawVal_ocsi
				if offset < 0 || offset >
					len(content) || n_ocsi < 0 || n_ocsi > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				reconstructed_ocsi, reconstructionErr_ocsi := ber.EncodeImplicitTagWithClass(tag.ClassUniversal, tag.TagSequence, content[offset:offset+n_ocsi])
				if reconstructionErr_ocsi != nil {
					return qualifyBERError(reconstructionErr_ocsi, "o-CSI", "decoding", false)
				}
				var dec_ocsi OCSI
				if unmErr := dec_ocsi.UnmarshalBER(reconstructed_ocsi, ber.ChildDecodeOptions(opts, "o-CSI")...); unmErr != nil {
					return qualifyBERError(unmErr, "o-CSI", "decoding", false)
				}
				v.OCSI = &dec_ocsi
				if offset < 0 || offset >
					len(content) || n_ocsi < 0 || n_ocsi > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_ocsi
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
				var dec_extensioncontainer ExtensionContainer
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
	// Decode o-BcsmCamelTDP-CriteriaList
	v.berOBcsmCamelTDPCriteriaListIndef_ = false
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3 {
				ber.MarkPreflightTarget(opts, "o-BcsmCamelTDP-CriteriaList", content[offset:])
				decodedTag_obcsmcameltdpcriterialist, n_obcsmcameltdpcriterialist, rawVal_obcsmcameltdpcriterialist, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "o-BcsmCamelTDP-CriteriaList", "decoding", false)
				}
				if decodedTag_obcsmcameltdpcriterialist.Class != tag.ClassContextSpecific || decodedTag_obcsmcameltdpcriterialist.Number != 3 || decodedTag_obcsmcameltdpcriterialist.Constructed != true {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_obcsmcameltdpcriterialist), "o-BcsmCamelTDP-CriteriaList", "decoding", false)
				}
				_ = rawVal_obcsmcameltdpcriterialist
				if offset < 0 || offset >
					len(content) || n_obcsmcameltdpcriterialist < 0 || n_obcsmcameltdpcriterialist >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				reconstructed_obcsmcameltdpcriterialist, reconstructionErr_obcsmcameltdpcriterialist := ber.EncodeImplicitTagWithClass(tag.ClassUniversal, tag.TagSequence, content[offset:offset+n_obcsmcameltdpcriterialist])
				if reconstructionErr_obcsmcameltdpcriterialist != nil {
					return qualifyBERError(reconstructionErr_obcsmcameltdpcriterialist, "o-BcsmCamelTDP-CriteriaList", "decoding", false)
				}
				dec_obcsmcameltdpcriterialist, unmErr := UnmarshalBEROBcsmCamelTDPCriteriaList(reconstructed_obcsmcameltdpcriterialist, ber.ParentCollectionSizeDecodeOptions(ber.ChildDecodeOptions(opts, "o-BcsmCamelTDP-CriteriaList"))...)
				if unmErr != nil {
					return qualifyBERError(unmErr, "o-BcsmCamelTDP-CriteriaList", "decoding", false)
				}
				v.OBcsmCamelTDPCriteriaList = dec_obcsmcameltdpcriterialist
				{
					_, tagSz_, _ := ber.DecodeTag(content[offset:])
					if offset < 0 || offset >
						len(content) || tagSz_ < 0 || tagSz_ > len(content[offset:]) {
						return fmt.Errorf("invalid BER content window")
					}

					if offset+tagSz_ < len(content) && content[offset+tagSz_] == 0x80 {
						v.berOBcsmCamelTDPCriteriaListIndef_ = true
					}
				}
				if offset < 0 || offset >
					len(content) || n_obcsmcameltdpcriterialist < 0 || n_obcsmcameltdpcriterialist >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_obcsmcameltdpcriterialist
				if len((v.OBcsmCamelTDPCriteriaList).Values) < 1 || len((v.OBcsmCamelTDPCriteriaList).Values) > 10 {
					if constraintErr := checkDecodedLength(opts, s47bb6e_13, "51.5", "o-BcsmCamelTDP-CriteriaList", "SIZE (1..10)", len((v.OBcsmCamelTDPCriteriaList).Values)); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode t-BCSM-CAMEL-TDP-CriteriaList
	v.berTBCSMCAMELTDPCriteriaListIndef_ = false
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4 {
				ber.MarkPreflightTarget(opts, "t-BCSM-CAMEL-TDP-CriteriaList", content[offset:])
				decodedTag_tbcsmcameltdpcriterialist, n_tbcsmcameltdpcriterialist, rawVal_tbcsmcameltdpcriterialist, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "t-BCSM-CAMEL-TDP-CriteriaList", "decoding", false)
				}
				if decodedTag_tbcsmcameltdpcriterialist.Class != tag.ClassContextSpecific || decodedTag_tbcsmcameltdpcriterialist.Number != 4 || decodedTag_tbcsmcameltdpcriterialist.Constructed != true {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_tbcsmcameltdpcriterialist), "t-BCSM-CAMEL-TDP-CriteriaList", "decoding", false)
				}
				_ = rawVal_tbcsmcameltdpcriterialist
				if offset < 0 || offset >
					len(content) || n_tbcsmcameltdpcriterialist < 0 || n_tbcsmcameltdpcriterialist >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				reconstructed_tbcsmcameltdpcriterialist, reconstructionErr_tbcsmcameltdpcriterialist := ber.EncodeImplicitTagWithClass(tag.ClassUniversal, tag.TagSequence, content[offset:offset+n_tbcsmcameltdpcriterialist])
				if reconstructionErr_tbcsmcameltdpcriterialist != nil {
					return qualifyBERError(reconstructionErr_tbcsmcameltdpcriterialist, "t-BCSM-CAMEL-TDP-CriteriaList", "decoding", false)
				}
				dec_tbcsmcameltdpcriterialist, unmErr := UnmarshalBERTBCSMCAMELTDPCriteriaList(reconstructed_tbcsmcameltdpcriterialist, ber.ParentCollectionSizeDecodeOptions(ber.ChildDecodeOptions(opts, "t-BCSM-CAMEL-TDP-CriteriaList"))...)
				if unmErr != nil {
					return qualifyBERError(unmErr, "t-BCSM-CAMEL-TDP-CriteriaList", "decoding", false)
				}
				v.TBCSMCAMELTDPCriteriaList = dec_tbcsmcameltdpcriterialist
				{
					_, tagSz_, _ := ber.DecodeTag(content[offset:])
					if offset < 0 || offset >
						len(content) || tagSz_ < 0 || tagSz_ > len(content[offset:]) {
						return fmt.Errorf("invalid BER content window")
					}

					if offset+tagSz_ < len(content) && content[offset+tagSz_] == 0x80 {
						v.berTBCSMCAMELTDPCriteriaListIndef_ = true
					}
				}
				if offset < 0 || offset >
					len(content) || n_tbcsmcameltdpcriterialist < 0 || n_tbcsmcameltdpcriterialist >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_tbcsmcameltdpcriterialist
				if len((v.TBCSMCAMELTDPCriteriaList).Values) < 1 || len((v.TBCSMCAMELTDPCriteriaList).Values) > 10 {
					if constraintErr := checkDecodedLength(opts, s47bb6e_13, "51.5", "t-BCSM-CAMEL-TDP-CriteriaList", "SIZE (1..10)", len((v.TBCSMCAMELTDPCriteriaList).Values)); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode d-csi
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 5 {
				ber.MarkPreflightTarget(opts, "d-csi", content[offset:])
				decodedTag_dcsi, n_dcsi, rawVal_dcsi, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "d-csi", "decoding", false)
				}
				if decodedTag_dcsi.Class != tag.ClassContextSpecific || decodedTag_dcsi.Number != 5 || decodedTag_dcsi.Constructed != true {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_dcsi), "d-csi", "decoding", false)
				}
				_ = rawVal_dcsi
				if offset < 0 || offset >
					len(content) || n_dcsi < 0 || n_dcsi > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				reconstructed_dcsi, reconstructionErr_dcsi := ber.EncodeImplicitTagWithClass(tag.ClassUniversal, tag.TagSequence, content[offset:offset+n_dcsi])
				if reconstructionErr_dcsi != nil {
					return qualifyBERError(reconstructionErr_dcsi, "d-csi", "decoding", false)
				}
				var dec_dcsi DCSI
				if unmErr := dec_dcsi.UnmarshalBER(reconstructed_dcsi, ber.ChildDecodeOptions(opts, "d-csi")...); unmErr != nil {
					return qualifyBERError(unmErr, "d-csi", "decoding", false)
				}
				v.DCsi = &dec_dcsi
				if offset < 0 || offset >
					len(content) || n_dcsi < 0 || n_dcsi > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_dcsi
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		peekTag, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:], opts...)
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "GmscCamelSubscriptionInfo", Cause: extErr_}
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: the first unknown addition must differ from trailing OPTIONAL/DEFAULT tags.
		if len(v.ExtData_) == 0 && ((peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 5) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0)) {
			if !ber.ToleranceEnabled(opts) {
				return &ber.DecodeError{Offset: offset, TypeName: "GmscCamelSubscriptionInfo", Cause: fmt.Errorf("%w: repeated or out-of-order SEQUENCE component tag %s", ber.ErrInvalidTag, peekTag)}
			}
			if orderErr_ := ber.CheckDecodedValue(ber.DecodeRule(opts, s47bb6e_13, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), fmt.Sprintf("ExtData_[%d]", len(v.ExtData_)), "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); orderErr_ != nil {
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

// MarshalBER encodes SetReportingStateArg to BER format.
func (v *SetReportingStateArg) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {

	if v == nil {
		return nil, fmt.Errorf("%w: SetReportingStateArg receiver is nil", ber.ErrInvalidValue)
	}
	return marshalFramedValue(v, v.berReplayNode_, opts, (*SetReportingStateArg).MarshalBER, (*SetReportingStateArg).marshalBER, 3)

}
func (v *SetReportingStateArg) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if v.Imsi != nil {
		if len(*v.Imsi) < 3 || len(*v.Imsi) > 8 {
			if constraintErr := checkEncodedLength(opts, s47bb6e_14, "51.5", "imsi", "SIZE (3..8)", len(*v.Imsi)); constraintErr != nil {
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
	if v.Lmsi != nil {
		if len(*v.Lmsi) < 4 || len(*v.Lmsi) > 4 {
			if constraintErr := checkEncodedLength(opts, s47bb6e_14, "51.5", "lmsi", "SIZE (4)", len(*v.Lmsi)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_lmsi, encodeErr_enc_lmsi := ber.EncodeOctetString([]byte(*v.Lmsi))
		if encodeErr_enc_lmsi != nil {
			return nil, qualifyBERError(encodeErr_enc_lmsi, "lmsi", "encoding", false)
		}
		retagged_enc_lmsi, tagErr_enc_lmsi := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_lmsi)
		if tagErr_enc_lmsi != nil {
			return nil, qualifyBERError(tagErr_enc_lmsi, "lmsi", "encoding", false)
		}
		enc_lmsi = retagged_enc_lmsi
		children = append(children, enc_lmsi...)
	}
	if v.CcbsMonitoring != nil {
		enc_ccbsmonitoring := ber.EncodeEnumerated(int64(*v.CcbsMonitoring))
		retagged_enc_ccbsmonitoring, tagErr_enc_ccbsmonitoring := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_ccbsmonitoring)
		if tagErr_enc_ccbsmonitoring != nil {
			return nil, qualifyBERError(tagErr_enc_ccbsmonitoring, "ccbs-Monitoring", "encoding", false)
		}
		enc_ccbsmonitoring = retagged_enc_ccbsmonitoring
		children = append(children, enc_ccbsmonitoring...)
	}
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalBER(ber.ChildEncodeOptions(opts, "extensionContainer")...)
		if err != nil {
			return nil, qualifyBERError(err, "extensionContainer", "encoding", false)
		}
		retagged_enc_extensioncontainer, tagErr_enc_extensioncontainer := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, enc_extensioncontainer)
		if tagErr_enc_extensioncontainer != nil {
			return nil, qualifyBERError(tagErr_enc_extensioncontainer, "extensionContainer", "encoding", false)
		}
		enc_extensioncontainer = retagged_enc_extensioncontainer
		ber.RecordGeneratedBERChildPlacement(opts, len(children), enc_extensioncontainer)
		children = append(children, enc_extensioncontainer...)
	}
	base_ := -1
	for i, ext := range v.ExtData_ {
		if err := checkOpaqueAddition(ext, opts, s47bb6e_14, children, i, &base_); err != nil {
			return nil, opaqueExtensionError(err, i)
		}
		peekTag, n, _, extErr := ber.DecodeEncodedTLV(ext)
		if extErr != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, extErr)
		}
		if n != len(ext) {
			return nil, fmt.Errorf("encoding extension %d: %w", i, ber.ErrExtraData)
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: only the first addition is restricted.
		if i == 0 && ((peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0)) {
			if constraintErr := ber.CheckEncodedValue(ber.EncodeRule(opts, s47bb6e_14, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
				return nil, constraintErr
			}
		}
		children = append(children, ext...)
	}
	ber.RecordGeneratedBERContainer(opts, children)
	return ber.EncodeSequence(children)
}
func (v *SetReportingStateArg) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// MarshalDER encodes SetReportingStateArg to DER format.
// Opaque descendants pass generic DER checks; foreign schema rules need a typed binding.
func (v *SetReportingStateArg) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: SetReportingStateArg receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if v.Imsi != nil {
		if len(*v.Imsi) < 3 || len(*v.Imsi) > 8 {
			if constraintErr := checkEncodedLength(nil, s47bb6e_14, "51.5", "imsi", "SIZE (3..8)", len(*v.Imsi)); constraintErr != nil {
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
	if v.Lmsi != nil {
		if len(*v.Lmsi) < 4 || len(*v.Lmsi) > 4 {
			if constraintErr := checkEncodedLength(nil, s47bb6e_14, "51.5", "lmsi", "SIZE (4)", len(*v.Lmsi)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_lmsi, encodeErr_enc_lmsi := ber.EncodeOctetString([]byte(*v.Lmsi))
		if encodeErr_enc_lmsi != nil {
			return nil, qualifyBERError(encodeErr_enc_lmsi, "lmsi", "encoding", true)
		}
		retagged_enc_lmsi, tagErr_enc_lmsi := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_lmsi)
		if tagErr_enc_lmsi != nil {
			return nil, qualifyBERError(tagErr_enc_lmsi, "lmsi", "encoding", true)
		}
		enc_lmsi = retagged_enc_lmsi
		children = append(children, enc_lmsi...)
	}
	if v.CcbsMonitoring != nil {
		enc_ccbsmonitoring := ber.EncodeEnumerated(int64(*v.CcbsMonitoring))
		retagged_enc_ccbsmonitoring, tagErr_enc_ccbsmonitoring := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_ccbsmonitoring)
		if tagErr_enc_ccbsmonitoring != nil {
			return nil, qualifyBERError(tagErr_enc_ccbsmonitoring, "ccbs-Monitoring", "encoding", true)
		}
		enc_ccbsmonitoring = retagged_enc_ccbsmonitoring
		children = append(children, enc_ccbsmonitoring...)
	}
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalDER()
		if err != nil {
			return nil, qualifyBERError(err, "extensionContainer", "encoding", true)
		}
		retagged_enc_extensioncontainer, tagErr_enc_extensioncontainer := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, enc_extensioncontainer)
		if tagErr_enc_extensioncontainer != nil {
			return nil, qualifyBERError(tagErr_enc_extensioncontainer, "extensionContainer", "encoding", true)
		}
		enc_extensioncontainer = retagged_enc_extensioncontainer
		children = append(children, enc_extensioncontainer...)
	}
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDEREncodedElement(ext); err != nil {
			return nil, invalidDERAddition(ext, s47bb6e_14, children, i)
		}
		peekTag, _, _, extErr := ber.DecodeEncodedTLV(ext)
		if extErr != nil {
			return nil, extErr
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: only the first addition is restricted.
		if i == 0 && ((peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0)) {
			if constraintErr := ber.CheckEncodedValue(ber.EncodeRule(nil, s47bb6e_14, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
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
		return nil, fmt.Errorf("%s: %w", "encoding SetReportingStateArg as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}
func (v *SetReportingStateArg) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	encoded, err := v.MarshalDER()
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBER decodes SetReportingStateArg from BER/DER format.
func (destination *SetReportingStateArg) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if destination == nil {
		return fmt.Errorf("%w: SetReportingStateArg destination is nil", ber.ErrInvalidValue)
	}
	v := new(SetReportingStateArg)

	defer publishDecodedValue(destination, v, &returnErr)

	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	preparedData, preparedOptions, prepareErr := prepareCompositeBER(data, opts, s47bb6e_14, "child", (*SetReportingStateArg).UnmarshalBER)
	if prepareErr != nil {
		return prepareErr
	}
	data, opts = preparedData, preparedOptions

	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
	*v = SetReportingStateArg{}
	defer func() {
		if returnErr == nil {
			returnErr = completeValueBER(data,
				opts, v, &v.berReplayNode_, (*SetReportingStateArg).MarshalBER)
		}

	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("%s: %w", "decoding SetReportingStateArg SEQUENCE", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "SetReportingStateArg", Cause: ber.ErrExtraData}
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
				tmp_imsi := IMSI(decVal_imsi)
				v.Imsi = &tmp_imsi
				if offset > len(content) || n_imsi < 0 || n_imsi > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_imsi
				if len(*v.Imsi) < 3 || len(*v.Imsi) > 8 {
					if constraintErr := checkDecodedLength(opts, s47bb6e_14, "51.5", "imsi", "SIZE (3..8)", len(*v.Imsi)); constraintErr != nil {
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
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
				ber.MarkPreflightTarget(opts, "lmsi", content[offset:])
				decodedTag_lmsi, n_lmsi, rawVal_lmsi, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "lmsi", "decoding", false)
				}
				if decodedTag_lmsi.Class != tag.ClassContextSpecific || decodedTag_lmsi.Number != 1 {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_lmsi), "lmsi", "decoding", false)
				}
				decVal_lmsi, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_lmsi.Constructed, rawVal_lmsi, opts...)
				if octetErr != nil {
					return qualifyBERError(octetErr, "lmsi", "decoding", false)
				}
				tmp_lmsi := LMSI(decVal_lmsi)
				v.Lmsi = &tmp_lmsi
				if offset < 0 || offset >
					len(content) || n_lmsi < 0 || n_lmsi > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_lmsi
				if len(*v.Lmsi) < 4 || len(*v.Lmsi) > 4 {
					if constraintErr := checkDecodedLength(opts, s47bb6e_14, "51.5", "lmsi", "SIZE (4)", len(*v.Lmsi)); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode ccbs-Monitoring
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2 {
				ber.MarkPreflightTarget(opts, "ccbs-Monitoring", content[offset:])
				decodedTag_ccbsmonitoring, n_ccbsmonitoring, rawVal_ccbsmonitoring, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "ccbs-Monitoring", "decoding", false)
				}
				if decodedTag_ccbsmonitoring.Class != tag.ClassContextSpecific || decodedTag_ccbsmonitoring.Number != 2 || decodedTag_ccbsmonitoring.Constructed != false {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_ccbsmonitoring), "ccbs-Monitoring", "decoding", false)
				}
				decVal_ccbsmonitoring, intErr := ber.DecodeEnumeratedValue(rawVal_ccbsmonitoring)
				if intErr != nil {
					return qualifyBERError(intErr, "ccbs-Monitoring", "decoding", false)
				}
				tmp_ccbsmonitoring := ReportingState(decVal_ccbsmonitoring)
				v.CcbsMonitoring = &tmp_ccbsmonitoring
				if offset < 0 || offset >
					len(content) || n_ccbsmonitoring < 0 || n_ccbsmonitoring > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_ccbsmonitoring
			}
		}
	}
	// Decode extensionContainer
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3 {
				ber.MarkPreflightTarget(opts, "extensionContainer", content[offset:])
				decodedTag_extensioncontainer, n_extensioncontainer, rawVal_extensioncontainer, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "extensionContainer", "decoding", false)
				}
				if decodedTag_extensioncontainer.Class != tag.ClassContextSpecific || decodedTag_extensioncontainer.Number != 3 || decodedTag_extensioncontainer.Constructed != true {
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
				var dec_extensioncontainer ExtensionContainer
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
			return &ber.DecodeError{Offset: offset, TypeName: "SetReportingStateArg", Cause: extErr_}
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: the first unknown addition must differ from trailing OPTIONAL/DEFAULT tags.
		if len(v.ExtData_) == 0 && ((peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0)) {
			if !ber.ToleranceEnabled(opts) {
				return &ber.DecodeError{Offset: offset, TypeName: "SetReportingStateArg", Cause: fmt.Errorf("%w: repeated or out-of-order SEQUENCE component tag %s", ber.ErrInvalidTag, peekTag)}
			}
			if orderErr_ := ber.CheckDecodedValue(ber.DecodeRule(opts, s47bb6e_14, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), fmt.Sprintf("ExtData_[%d]", len(v.ExtData_)), "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); orderErr_ != nil {
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

// MarshalBER encodes SetReportingStateRes to BER format.
func (v *SetReportingStateRes) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {

	if v == nil {
		return nil, fmt.Errorf("%w: SetReportingStateRes receiver is nil", ber.ErrInvalidValue)
	}
	return marshalFramedValue(v, v.berReplayNode_, opts, (*SetReportingStateRes).MarshalBER, (*SetReportingStateRes).marshalBER, 3)

}
func (v *SetReportingStateRes) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if v.CcbsSubscriberStatus != nil {
		enc_ccbssubscriberstatus := ber.EncodeEnumerated(int64(*v.CcbsSubscriberStatus))
		retagged_enc_ccbssubscriberstatus, tagErr_enc_ccbssubscriberstatus := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_ccbssubscriberstatus)
		if tagErr_enc_ccbssubscriberstatus != nil {
			return nil, qualifyBERError(tagErr_enc_ccbssubscriberstatus, "ccbs-SubscriberStatus", "encoding", false)
		}
		enc_ccbssubscriberstatus = retagged_enc_ccbssubscriberstatus
		children = append(children, enc_ccbssubscriberstatus...)
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
	base_ := -1
	for i, ext := range v.ExtData_ {
		if err := checkOpaqueAddition(ext, opts, s47bb6e_15, children, i, &base_); err != nil {
			return nil, opaqueExtensionError(err, i)
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
			if constraintErr := ber.CheckEncodedValue(ber.EncodeRule(opts, s47bb6e_15, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
				return nil, constraintErr
			}
		}
		children = append(children, ext...)
	}
	ber.RecordGeneratedBERContainer(opts, children)
	return ber.EncodeSequence(children)
}
func (v *SetReportingStateRes) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// MarshalDER encodes SetReportingStateRes to DER format.
// Opaque descendants pass generic DER checks; foreign schema rules need a typed binding.
func (v *SetReportingStateRes) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: SetReportingStateRes receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if v.CcbsSubscriberStatus != nil {
		enc_ccbssubscriberstatus := ber.EncodeEnumerated(int64(*v.CcbsSubscriberStatus))
		retagged_enc_ccbssubscriberstatus, tagErr_enc_ccbssubscriberstatus := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_ccbssubscriberstatus)
		if tagErr_enc_ccbssubscriberstatus != nil {
			return nil, qualifyBERError(tagErr_enc_ccbssubscriberstatus, "ccbs-SubscriberStatus", "encoding", true)
		}
		enc_ccbssubscriberstatus = retagged_enc_ccbssubscriberstatus
		children = append(children, enc_ccbssubscriberstatus...)
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
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDEREncodedElement(ext); err != nil {
			return nil, invalidDERAddition(ext, s47bb6e_15, children, i)
		}
		peekTag, _, _, extErr := ber.DecodeEncodedTLV(ext)
		if extErr != nil {
			return nil, extErr
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: only the first addition is restricted.
		if i == 0 && ((peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0)) {
			if constraintErr := ber.CheckEncodedValue(ber.EncodeRule(nil, s47bb6e_15, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
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
		return nil, fmt.Errorf("%s: %w", "encoding SetReportingStateRes as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}
func (v *SetReportingStateRes) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	encoded, err := v.MarshalDER()
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBER decodes SetReportingStateRes from BER/DER format.
func (destination *SetReportingStateRes) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if destination == nil {
		return fmt.Errorf("%w: SetReportingStateRes destination is nil", ber.ErrInvalidValue)
	}
	v := new(SetReportingStateRes)

	defer publishDecodedValue(destination, v, &returnErr)

	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	preparedData, preparedOptions, prepareErr := prepareCompositeBER(data, opts, s47bb6e_15, "child", (*SetReportingStateRes).UnmarshalBER)
	if prepareErr != nil {
		return prepareErr
	}
	data, opts = preparedData, preparedOptions

	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
	*v = SetReportingStateRes{}
	defer func() {
		if returnErr == nil {
			returnErr = completeValueBER(data,
				opts, v, &v.berReplayNode_, (*SetReportingStateRes).MarshalBER)
		}

	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("%s: %w", "decoding SetReportingStateRes SEQUENCE", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "SetReportingStateRes", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode ccbs-SubscriberStatus
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
				ber.MarkPreflightTarget(opts, "ccbs-SubscriberStatus", content[offset:])
				decodedTag_ccbssubscriberstatus, n_ccbssubscriberstatus, rawVal_ccbssubscriberstatus, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "ccbs-SubscriberStatus", "decoding", false)
				}
				if decodedTag_ccbssubscriberstatus.Class != tag.ClassContextSpecific || decodedTag_ccbssubscriberstatus.Number != 0 || decodedTag_ccbssubscriberstatus.Constructed != false {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_ccbssubscriberstatus), "ccbs-SubscriberStatus", "decoding", false)
				}
				decVal_ccbssubscriberstatus, intErr := ber.DecodeEnumeratedValue(rawVal_ccbssubscriberstatus)
				if intErr != nil {
					return qualifyBERError(intErr, "ccbs-SubscriberStatus", "decoding", false)
				}
				tmp_ccbssubscriberstatus := CCBSSubscriberStatus(decVal_ccbssubscriberstatus)
				v.CcbsSubscriberStatus = &tmp_ccbssubscriberstatus
				if offset > len(content) || n_ccbssubscriberstatus < 0 || n_ccbssubscriberstatus > len(
					content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_ccbssubscriberstatus
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
				var dec_extensioncontainer ExtensionContainer
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
			return &ber.DecodeError{Offset: offset, TypeName: "SetReportingStateRes", Cause: extErr_}
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: the first unknown addition must differ from trailing OPTIONAL/DEFAULT tags.
		if len(v.ExtData_) == 0 && ((peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0)) {
			if !ber.ToleranceEnabled(opts) {
				return &ber.DecodeError{Offset: offset, TypeName: "SetReportingStateRes", Cause: fmt.Errorf("%w: repeated or out-of-order SEQUENCE component tag %s", ber.ErrInvalidTag, peekTag)}
			}
			if orderErr_ := ber.CheckDecodedValue(ber.DecodeRule(opts, s47bb6e_15, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), fmt.Sprintf("ExtData_[%d]", len(v.ExtData_)), "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); orderErr_ != nil {
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

// MarshalBER encodes StatusReportArg to BER format.
func (v *StatusReportArg) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {

	if v == nil {
		return nil, fmt.Errorf("%w: StatusReportArg receiver is nil", ber.ErrInvalidValue)
	}
	return marshalFramedValue(v, v.berReplayNode_, opts, (*StatusReportArg).MarshalBER, (*StatusReportArg).marshalBER, 3)

}
func (v *StatusReportArg) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if len(v.Imsi) < 3 || len(v.Imsi) > 8 {
		if constraintErr := checkEncodedLength(opts, s47bb6e_16, "51.5", "imsi", "SIZE (3..8)", len(v.Imsi)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_imsi, encodeErr_enc_imsi := ber.EncodeOctetString([]byte(v.Imsi))
	if encodeErr_enc_imsi != nil {
		return nil, qualifyBERError(encodeErr_enc_imsi, "imsi", "encoding", false)
	}
	retagged_enc_imsi, tagErr_enc_imsi := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_imsi)
	if tagErr_enc_imsi != nil {
		return nil, qualifyBERError(tagErr_enc_imsi, "imsi", "encoding", false)
	}
	enc_imsi = retagged_enc_imsi
	children = append(children, enc_imsi...)
	if v.EventReportData != nil {
		enc_eventreportdata, err := v.EventReportData.MarshalBER(ber.ChildEncodeOptions(opts, "eventReportData")...)
		if err != nil {
			return nil, qualifyBERError(err, "eventReportData", "encoding", false)
		}
		retagged_enc_eventreportdata, tagErr_enc_eventreportdata := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_eventreportdata)
		if tagErr_enc_eventreportdata != nil {
			return nil, qualifyBERError(tagErr_enc_eventreportdata, "eventReportData", "encoding", false)
		}
		enc_eventreportdata = retagged_enc_eventreportdata
		ber.RecordGeneratedBERChildPlacement(opts, len(children), enc_eventreportdata)
		children = append(children, enc_eventreportdata...)
	}
	if v.CallReportdata != nil {
		enc_callreportdata, err := v.CallReportdata.MarshalBER(ber.ChildEncodeOptions(opts, "callReportdata")...)
		if err != nil {
			return nil, qualifyBERError(err, "callReportdata", "encoding", false)
		}
		retagged_enc_callreportdata, tagErr_enc_callreportdata := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_callreportdata)
		if tagErr_enc_callreportdata != nil {
			return nil, qualifyBERError(tagErr_enc_callreportdata, "callReportdata", "encoding", false)
		}
		enc_callreportdata = retagged_enc_callreportdata
		ber.RecordGeneratedBERChildPlacement(opts, len(children), enc_callreportdata)
		children = append(children, enc_callreportdata...)
	}
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalBER(ber.ChildEncodeOptions(opts, "extensionContainer")...)
		if err != nil {
			return nil, qualifyBERError(err, "extensionContainer", "encoding", false)
		}
		retagged_enc_extensioncontainer, tagErr_enc_extensioncontainer := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, enc_extensioncontainer)
		if tagErr_enc_extensioncontainer != nil {
			return nil, qualifyBERError(tagErr_enc_extensioncontainer, "extensionContainer", "encoding", false)
		}
		enc_extensioncontainer = retagged_enc_extensioncontainer
		ber.RecordGeneratedBERChildPlacement(opts, len(children), enc_extensioncontainer)
		children = append(children, enc_extensioncontainer...)
	}
	base_ := -1
	for i, ext := range v.ExtData_ {
		if err := checkOpaqueAddition(ext, opts, s47bb6e_16, children, i, &base_); err != nil {
			return nil, opaqueExtensionError(err, i)
		}
		peekTag, n, _, extErr := ber.DecodeEncodedTLV(ext)
		if extErr != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, extErr)
		}
		if n != len(ext) {
			return nil, fmt.Errorf("encoding extension %d: %w", i, ber.ErrExtraData)
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: only the first addition is restricted.
		if i == 0 && ((peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1)) {
			if constraintErr := ber.CheckEncodedValue(ber.EncodeRule(opts, s47bb6e_16, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
				return nil, constraintErr
			}
		}
		children = append(children, ext...)
	}
	ber.RecordGeneratedBERContainer(opts, children)
	return ber.EncodeSequence(children)
}
func (v *StatusReportArg) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// MarshalDER encodes StatusReportArg to DER format.
// Opaque descendants pass generic DER checks; foreign schema rules need a typed binding.
func (v *StatusReportArg) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: StatusReportArg receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if len(v.Imsi) < 3 || len(v.Imsi) > 8 {
		if constraintErr := checkEncodedLength(nil, s47bb6e_16, "51.5", "imsi", "SIZE (3..8)", len(v.Imsi)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_imsi, encodeErr_enc_imsi := ber.EncodeOctetString([]byte(v.Imsi))
	if encodeErr_enc_imsi != nil {
		return nil, qualifyBERError(encodeErr_enc_imsi, "imsi", "encoding", true)
	}
	retagged_enc_imsi, tagErr_enc_imsi := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_imsi)
	if tagErr_enc_imsi != nil {
		return nil, qualifyBERError(tagErr_enc_imsi, "imsi", "encoding", true)
	}
	enc_imsi = retagged_enc_imsi
	children = append(children, enc_imsi...)
	if v.EventReportData != nil {
		enc_eventreportdata, err := v.EventReportData.MarshalDER()
		if err != nil {
			return nil, qualifyBERError(err, "eventReportData", "encoding", true)
		}
		retagged_enc_eventreportdata, tagErr_enc_eventreportdata := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_eventreportdata)
		if tagErr_enc_eventreportdata != nil {
			return nil, qualifyBERError(tagErr_enc_eventreportdata, "eventReportData", "encoding", true)
		}
		enc_eventreportdata = retagged_enc_eventreportdata
		children = append(children, enc_eventreportdata...)
	}
	if v.CallReportdata != nil {
		enc_callreportdata, err := v.CallReportdata.MarshalDER()
		if err != nil {
			return nil, qualifyBERError(err, "callReportdata", "encoding", true)
		}
		retagged_enc_callreportdata, tagErr_enc_callreportdata := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_callreportdata)
		if tagErr_enc_callreportdata != nil {
			return nil, qualifyBERError(tagErr_enc_callreportdata, "callReportdata", "encoding", true)
		}
		enc_callreportdata = retagged_enc_callreportdata
		children = append(children, enc_callreportdata...)
	}
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalDER()
		if err != nil {
			return nil, qualifyBERError(err, "extensionContainer", "encoding", true)
		}
		retagged_enc_extensioncontainer, tagErr_enc_extensioncontainer := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, enc_extensioncontainer)
		if tagErr_enc_extensioncontainer != nil {
			return nil, qualifyBERError(tagErr_enc_extensioncontainer, "extensionContainer", "encoding", true)
		}
		enc_extensioncontainer = retagged_enc_extensioncontainer
		children = append(children, enc_extensioncontainer...)
	}
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDEREncodedElement(ext); err != nil {
			return nil, invalidDERAddition(ext, s47bb6e_16, children, i)
		}
		peekTag, _, _, extErr := ber.DecodeEncodedTLV(ext)
		if extErr != nil {
			return nil, extErr
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: only the first addition is restricted.
		if i == 0 && ((peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1)) {
			if constraintErr := ber.CheckEncodedValue(ber.EncodeRule(nil, s47bb6e_16, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
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
		return nil, fmt.Errorf("%s: %w", "encoding StatusReportArg as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}
func (v *StatusReportArg) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	encoded, err := v.MarshalDER()
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBER decodes StatusReportArg from BER/DER format.
func (destination *StatusReportArg) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if destination == nil {
		return fmt.Errorf("%w: StatusReportArg destination is nil", ber.ErrInvalidValue)
	}
	v := new(StatusReportArg)

	defer publishDecodedValue(destination, v, &returnErr)

	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	preparedData, preparedOptions, prepareErr := prepareCompositeBER(data, opts, s47bb6e_16, "child", (*StatusReportArg).UnmarshalBER)
	if prepareErr != nil {
		return prepareErr
	}
	data, opts = preparedData, preparedOptions

	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
	*v = StatusReportArg{}
	defer func() {
		if returnErr == nil {
			returnErr = completeValueBER(data,
				opts, v, &v.berReplayNode_, (*StatusReportArg).MarshalBER)
		}

	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("%s: %w", "decoding StatusReportArg SEQUENCE", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "StatusReportArg", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode imsi
	if offset >= len(content) {
		return fmt.Errorf("missing required field imsi")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 0 {
			return fmt.Errorf("expected tag [%s %d] for imsi, got %s", "CONTEXT", 0, reqTag_)
		}
	}
	{
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
		v.Imsi = IMSI(decVal_imsi)
		if offset > len(content) || n_imsi < 0 || n_imsi > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n_imsi
		if len(v.Imsi) < 3 || len(v.Imsi) > 8 {
			if constraintErr := checkDecodedLength(opts, s47bb6e_16, "51.5", "imsi", "SIZE (3..8)", len(v.Imsi)); constraintErr != nil {
				return constraintErr
			}
		}
	}
	// Decode eventReportData
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
				ber.MarkPreflightTarget(opts, "eventReportData", content[offset:])
				decodedTag_eventreportdata, n_eventreportdata, rawVal_eventreportdata, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "eventReportData", "decoding", false)
				}
				if decodedTag_eventreportdata.Class != tag.ClassContextSpecific || decodedTag_eventreportdata.Number != 1 || decodedTag_eventreportdata.Constructed != true {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_eventreportdata), "eventReportData", "decoding", false)
				}
				_ = rawVal_eventreportdata
				if offset < 0 || offset >
					len(content) || n_eventreportdata < 0 || n_eventreportdata >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				reconstructed_eventreportdata, reconstructionErr_eventreportdata := ber.EncodeImplicitTagWithClass(tag.ClassUniversal, tag.TagSequence, content[offset:offset+n_eventreportdata])
				if reconstructionErr_eventreportdata != nil {
					return qualifyBERError(reconstructionErr_eventreportdata, "eventReportData", "decoding", false)
				}
				var dec_eventreportdata EventReportData
				if unmErr := dec_eventreportdata.UnmarshalBER(reconstructed_eventreportdata, ber.ChildDecodeOptions(opts, "eventReportData")...); unmErr != nil {
					return qualifyBERError(unmErr, "eventReportData", "decoding", false)
				}
				v.EventReportData = &dec_eventreportdata
				if offset < 0 || offset >
					len(content) || n_eventreportdata < 0 || n_eventreportdata >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_eventreportdata
			}
		}
	}
	// Decode callReportdata
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2 {
				ber.MarkPreflightTarget(opts, "callReportdata", content[offset:])
				decodedTag_callreportdata, n_callreportdata, rawVal_callreportdata, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "callReportdata", "decoding", false)
				}
				if decodedTag_callreportdata.Class != tag.ClassContextSpecific || decodedTag_callreportdata.Number != 2 || decodedTag_callreportdata.Constructed != true {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_callreportdata), "callReportdata", "decoding", false)
				}
				_ = rawVal_callreportdata
				if offset < 0 || offset >
					len(content) || n_callreportdata < 0 || n_callreportdata >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				reconstructed_callreportdata, reconstructionErr_callreportdata := ber.EncodeImplicitTagWithClass(tag.ClassUniversal, tag.TagSequence, content[offset:offset+n_callreportdata])
				if reconstructionErr_callreportdata != nil {
					return qualifyBERError(reconstructionErr_callreportdata, "callReportdata", "decoding", false)
				}
				var dec_callreportdata CallReportData
				if unmErr := dec_callreportdata.UnmarshalBER(reconstructed_callreportdata, ber.ChildDecodeOptions(opts, "callReportdata")...); unmErr != nil {
					return qualifyBERError(unmErr, "callReportdata", "decoding", false)
				}
				v.CallReportdata = &dec_callreportdata
				if offset < 0 || offset >
					len(content) || n_callreportdata < 0 || n_callreportdata >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_callreportdata
			}
		}
	}
	// Decode extensionContainer
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3 {
				ber.MarkPreflightTarget(opts, "extensionContainer", content[offset:])
				decodedTag_extensioncontainer, n_extensioncontainer, rawVal_extensioncontainer, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "extensionContainer", "decoding", false)
				}
				if decodedTag_extensioncontainer.Class != tag.ClassContextSpecific || decodedTag_extensioncontainer.Number != 3 || decodedTag_extensioncontainer.Constructed != true {
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
				var dec_extensioncontainer ExtensionContainer
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
			return &ber.DecodeError{Offset: offset, TypeName: "StatusReportArg", Cause: extErr_}
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: the first unknown addition must differ from trailing OPTIONAL/DEFAULT tags.
		if len(v.ExtData_) == 0 && ((peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1)) {
			if !ber.ToleranceEnabled(opts) {
				return &ber.DecodeError{Offset: offset, TypeName: "StatusReportArg", Cause: fmt.Errorf("%w: repeated or out-of-order SEQUENCE component tag %s", ber.ErrInvalidTag, peekTag)}
			}
			if orderErr_ := ber.CheckDecodedValue(ber.DecodeRule(opts, s47bb6e_16, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), fmt.Sprintf("ExtData_[%d]", len(v.ExtData_)), "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); orderErr_ != nil {
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

// MarshalBER encodes EventReportData to BER format.
func (v *EventReportData) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {

	if v == nil {
		return nil, fmt.Errorf("%w: EventReportData receiver is nil", ber.ErrInvalidValue)
	}
	return marshalFramedValue(v, v.berReplayNode_, opts, (*EventReportData).MarshalBER, (*EventReportData).marshalBER, 3)

}
func (v *EventReportData) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if v.CcbsSubscriberStatus != nil {
		enc_ccbssubscriberstatus := ber.EncodeEnumerated(int64(*v.CcbsSubscriberStatus))
		retagged_enc_ccbssubscriberstatus, tagErr_enc_ccbssubscriberstatus := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_ccbssubscriberstatus)
		if tagErr_enc_ccbssubscriberstatus != nil {
			return nil, qualifyBERError(tagErr_enc_ccbssubscriberstatus, "ccbs-SubscriberStatus", "encoding", false)
		}
		enc_ccbssubscriberstatus = retagged_enc_ccbssubscriberstatus
		children = append(children, enc_ccbssubscriberstatus...)
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
	base_ := -1
	for i, ext := range v.ExtData_ {
		if err := checkOpaqueAddition(ext, opts, s47bb6e_17, children, i, &base_); err != nil {
			return nil, opaqueExtensionError(err, i)
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
			if constraintErr := ber.CheckEncodedValue(ber.EncodeRule(opts, s47bb6e_17, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
				return nil, constraintErr
			}
		}
		children = append(children, ext...)
	}
	ber.RecordGeneratedBERContainer(opts, children)
	return ber.EncodeSequence(children)
}
func (v *EventReportData) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// MarshalDER encodes EventReportData to DER format.
// Opaque descendants pass generic DER checks; foreign schema rules need a typed binding.
func (v *EventReportData) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: EventReportData receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if v.CcbsSubscriberStatus != nil {
		enc_ccbssubscriberstatus := ber.EncodeEnumerated(int64(*v.CcbsSubscriberStatus))
		retagged_enc_ccbssubscriberstatus, tagErr_enc_ccbssubscriberstatus := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_ccbssubscriberstatus)
		if tagErr_enc_ccbssubscriberstatus != nil {
			return nil, qualifyBERError(tagErr_enc_ccbssubscriberstatus, "ccbs-SubscriberStatus", "encoding", true)
		}
		enc_ccbssubscriberstatus = retagged_enc_ccbssubscriberstatus
		children = append(children, enc_ccbssubscriberstatus...)
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
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDEREncodedElement(ext); err != nil {
			return nil, invalidDERAddition(ext, s47bb6e_17, children, i)
		}
		peekTag, _, _, extErr := ber.DecodeEncodedTLV(ext)
		if extErr != nil {
			return nil, extErr
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: only the first addition is restricted.
		if i == 0 && ((peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0)) {
			if constraintErr := ber.CheckEncodedValue(ber.EncodeRule(nil, s47bb6e_17, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
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
		return nil, fmt.Errorf("%s: %w", "encoding EventReportData as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}
func (v *EventReportData) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	encoded, err := v.MarshalDER()
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBER decodes EventReportData from BER/DER format.
func (destination *EventReportData) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if destination == nil {
		return fmt.Errorf("%w: EventReportData destination is nil", ber.ErrInvalidValue)
	}
	v := new(EventReportData)

	defer publishDecodedValue(destination, v, &returnErr)

	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	preparedData, preparedOptions, prepareErr := prepareCompositeBER(data, opts, s47bb6e_17, "child", (*EventReportData).UnmarshalBER)
	if prepareErr != nil {
		return prepareErr
	}
	data, opts = preparedData, preparedOptions

	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
	*v = EventReportData{}
	defer func() {
		if returnErr == nil {
			returnErr = completeValueBER(data,
				opts, v, &v.berReplayNode_, (*EventReportData).MarshalBER)
		}

	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("%s: %w", "decoding EventReportData SEQUENCE", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "EventReportData", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode ccbs-SubscriberStatus
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
				ber.MarkPreflightTarget(opts, "ccbs-SubscriberStatus", content[offset:])
				decodedTag_ccbssubscriberstatus, n_ccbssubscriberstatus, rawVal_ccbssubscriberstatus, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "ccbs-SubscriberStatus", "decoding", false)
				}
				if decodedTag_ccbssubscriberstatus.Class != tag.ClassContextSpecific || decodedTag_ccbssubscriberstatus.Number != 0 || decodedTag_ccbssubscriberstatus.Constructed != false {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_ccbssubscriberstatus), "ccbs-SubscriberStatus", "decoding", false)
				}
				decVal_ccbssubscriberstatus, intErr := ber.DecodeEnumeratedValue(rawVal_ccbssubscriberstatus)
				if intErr != nil {
					return qualifyBERError(intErr, "ccbs-SubscriberStatus", "decoding", false)
				}
				tmp_ccbssubscriberstatus := CCBSSubscriberStatus(decVal_ccbssubscriberstatus)
				v.CcbsSubscriberStatus = &tmp_ccbssubscriberstatus
				if offset > len(content) || n_ccbssubscriberstatus < 0 || n_ccbssubscriberstatus >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_ccbssubscriberstatus
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
				var dec_extensioncontainer ExtensionContainer
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
			return &ber.DecodeError{Offset: offset, TypeName: "EventReportData", Cause: extErr_}
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: the first unknown addition must differ from trailing OPTIONAL/DEFAULT tags.
		if len(v.ExtData_) == 0 && ((peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0)) {
			if !ber.ToleranceEnabled(opts) {
				return &ber.DecodeError{Offset: offset, TypeName: "EventReportData", Cause: fmt.Errorf("%w: repeated or out-of-order SEQUENCE component tag %s", ber.ErrInvalidTag, peekTag)}
			}
			if orderErr_ := ber.CheckDecodedValue(ber.DecodeRule(opts, s47bb6e_17, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), fmt.Sprintf("ExtData_[%d]", len(v.ExtData_)), "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); orderErr_ != nil {
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

// MarshalBER encodes CallReportData to BER format.
func (v *CallReportData) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {

	if v == nil {
		return nil, fmt.Errorf("%w: CallReportData receiver is nil", ber.ErrInvalidValue)
	}
	return marshalFramedValue(v, v.berReplayNode_, opts, (*CallReportData).MarshalBER, (*CallReportData).marshalBER, 3)

}
func (v *CallReportData) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if v.MonitoringMode != nil {
		enc_monitoringmode := ber.EncodeEnumerated(int64(*v.MonitoringMode))
		retagged_enc_monitoringmode, tagErr_enc_monitoringmode := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_monitoringmode)
		if tagErr_enc_monitoringmode != nil {
			return nil, qualifyBERError(tagErr_enc_monitoringmode, "monitoringMode", "encoding", false)
		}
		enc_monitoringmode = retagged_enc_monitoringmode
		children = append(children, enc_monitoringmode...)
	}
	if v.CallOutcome != nil {
		enc_calloutcome := ber.EncodeEnumerated(int64(*v.CallOutcome))
		retagged_enc_calloutcome, tagErr_enc_calloutcome := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_calloutcome)
		if tagErr_enc_calloutcome != nil {
			return nil, qualifyBERError(tagErr_enc_calloutcome, "callOutcome", "encoding", false)
		}
		enc_calloutcome = retagged_enc_calloutcome
		children = append(children, enc_calloutcome...)
	}
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
	base_ := -1
	for i, ext := range v.ExtData_ {
		if err := checkOpaqueAddition(ext, opts, s47bb6e_18, children, i, &base_); err != nil {
			return nil, opaqueExtensionError(err, i)
		}
		peekTag, n, _, extErr := ber.DecodeEncodedTLV(ext)
		if extErr != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, extErr)
		}
		if n != len(ext) {
			return nil, fmt.Errorf("encoding extension %d: %w", i, ber.ErrExtraData)
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: only the first addition is restricted.
		if i == 0 && ((peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0)) {
			if constraintErr := ber.CheckEncodedValue(ber.EncodeRule(opts, s47bb6e_18, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
				return nil, constraintErr
			}
		}
		children = append(children, ext...)
	}
	ber.RecordGeneratedBERContainer(opts, children)
	return ber.EncodeSequence(children)
}
func (v *CallReportData) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// MarshalDER encodes CallReportData to DER format.
// Opaque descendants pass generic DER checks; foreign schema rules need a typed binding.
func (v *CallReportData) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: CallReportData receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if v.MonitoringMode != nil {
		enc_monitoringmode := ber.EncodeEnumerated(int64(*v.MonitoringMode))
		retagged_enc_monitoringmode, tagErr_enc_monitoringmode := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_monitoringmode)
		if tagErr_enc_monitoringmode != nil {
			return nil, qualifyBERError(tagErr_enc_monitoringmode, "monitoringMode", "encoding", true)
		}
		enc_monitoringmode = retagged_enc_monitoringmode
		children = append(children, enc_monitoringmode...)
	}
	if v.CallOutcome != nil {
		enc_calloutcome := ber.EncodeEnumerated(int64(*v.CallOutcome))
		retagged_enc_calloutcome, tagErr_enc_calloutcome := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_calloutcome)
		if tagErr_enc_calloutcome != nil {
			return nil, qualifyBERError(tagErr_enc_calloutcome, "callOutcome", "encoding", true)
		}
		enc_calloutcome = retagged_enc_calloutcome
		children = append(children, enc_calloutcome...)
	}
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
			return nil, invalidDERAddition(ext, s47bb6e_18, children, i)
		}
		peekTag, _, _, extErr := ber.DecodeEncodedTLV(ext)
		if extErr != nil {
			return nil, extErr
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: only the first addition is restricted.
		if i == 0 && ((peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0)) {
			if constraintErr := ber.CheckEncodedValue(ber.EncodeRule(nil, s47bb6e_18, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
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
		return nil, fmt.Errorf("%s: %w", "encoding CallReportData as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}
func (v *CallReportData) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	encoded, err := v.MarshalDER()
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBER decodes CallReportData from BER/DER format.
func (destination *CallReportData) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if destination == nil {
		return fmt.Errorf("%w: CallReportData destination is nil", ber.ErrInvalidValue)
	}
	v := new(CallReportData)

	defer publishDecodedValue(destination, v, &returnErr)

	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	preparedData, preparedOptions, prepareErr := prepareCompositeBER(data, opts, s47bb6e_18, "child", (*CallReportData).UnmarshalBER)
	if prepareErr != nil {
		return prepareErr
	}
	data, opts = preparedData, preparedOptions

	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
	*v = CallReportData{}
	defer func() {
		if returnErr == nil {
			returnErr = completeValueBER(data,
				opts, v, &v.berReplayNode_, (*CallReportData).MarshalBER)
		}

	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("%s: %w", "decoding CallReportData SEQUENCE", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "CallReportData", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode monitoringMode
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
				ber.MarkPreflightTarget(opts, "monitoringMode", content[offset:])
				decodedTag_monitoringmode, n_monitoringmode, rawVal_monitoringmode, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "monitoringMode", "decoding", false)
				}
				if decodedTag_monitoringmode.Class != tag.ClassContextSpecific || decodedTag_monitoringmode.Number != 0 || decodedTag_monitoringmode.Constructed != false {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_monitoringmode), "monitoringMode", "decoding", false)
				}
				decVal_monitoringmode, intErr := ber.DecodeEnumeratedValue(rawVal_monitoringmode)
				if intErr != nil {
					return qualifyBERError(intErr, "monitoringMode", "decoding", false)
				}
				tmp_monitoringmode := MonitoringMode(decVal_monitoringmode)
				v.MonitoringMode = &tmp_monitoringmode
				if offset > len(content) || n_monitoringmode < 0 || n_monitoringmode > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_monitoringmode
			}
		}
	}
	// Decode callOutcome
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
				ber.MarkPreflightTarget(opts, "callOutcome", content[offset:])
				decodedTag_calloutcome, n_calloutcome, rawVal_calloutcome, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "callOutcome", "decoding", false)
				}
				if decodedTag_calloutcome.Class != tag.ClassContextSpecific || decodedTag_calloutcome.Number != 1 || decodedTag_calloutcome.Constructed != false {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_calloutcome), "callOutcome", "decoding", false)
				}
				decVal_calloutcome, intErr := ber.DecodeEnumeratedValue(rawVal_calloutcome)
				if intErr != nil {
					return qualifyBERError(intErr, "callOutcome", "decoding", false)
				}
				tmp_calloutcome := CallOutcome(decVal_calloutcome)
				v.CallOutcome = &tmp_calloutcome
				if offset < 0 || offset >
					len(content) || n_calloutcome < 0 || n_calloutcome > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_calloutcome
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
				var dec_extensioncontainer ExtensionContainer
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
			return &ber.DecodeError{Offset: offset, TypeName: "CallReportData", Cause: extErr_}
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: the first unknown addition must differ from trailing OPTIONAL/DEFAULT tags.
		if len(v.ExtData_) == 0 && ((peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0)) {
			if !ber.ToleranceEnabled(opts) {
				return &ber.DecodeError{Offset: offset, TypeName: "CallReportData", Cause: fmt.Errorf("%w: repeated or out-of-order SEQUENCE component tag %s", ber.ErrInvalidTag, peekTag)}
			}
			if orderErr_ := ber.CheckDecodedValue(ber.DecodeRule(opts, s47bb6e_18, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), fmt.Sprintf("ExtData_[%d]", len(v.ExtData_)), "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); orderErr_ != nil {
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

// MarshalBER encodes StatusReportRes to BER format.
func (v *StatusReportRes) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {

	if v == nil {
		return nil, fmt.Errorf("%w: StatusReportRes receiver is nil", ber.ErrInvalidValue)
	}
	return marshalFramedValue(v, v.berReplayNode_, opts, (*StatusReportRes).MarshalBER, (*StatusReportRes).marshalBER, 3)

}
func (v *StatusReportRes) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
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
		ber.RecordGeneratedBERChildPlacement(opts, len(children), enc_extensioncontainer)
		children = append(children, enc_extensioncontainer...)
	}
	base_ := -1
	for i, ext := range v.ExtData_ {
		if err := checkOpaqueAddition(ext, opts, s47bb6e_19, children, i, &base_); err != nil {
			return nil, opaqueExtensionError(err, i)
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
			if constraintErr := ber.CheckEncodedValue(ber.EncodeRule(opts, s47bb6e_19, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
				return nil, constraintErr
			}
		}
		children = append(children, ext...)
	}
	ber.RecordGeneratedBERContainer(opts, children)
	return ber.EncodeSequence(children)
}
func (v *StatusReportRes) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// MarshalDER encodes StatusReportRes to DER format.
// Opaque descendants pass generic DER checks; foreign schema rules need a typed binding.
func (v *StatusReportRes) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: StatusReportRes receiver is nil", ber.ErrInvalidValue)
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
			return nil, invalidDERAddition(ext, s47bb6e_19, children, i)
		}
		peekTag, _, _, extErr := ber.DecodeEncodedTLV(ext)
		if extErr != nil {
			return nil, extErr
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: only the first addition is restricted.
		if i == 0 && (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0) {
			if constraintErr := ber.CheckEncodedValue(ber.EncodeRule(nil, s47bb6e_19, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
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
		return nil, fmt.Errorf("%s: %w", "encoding StatusReportRes as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}
func (v *StatusReportRes) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	encoded, err := v.MarshalDER()
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBER decodes StatusReportRes from BER/DER format.
func (destination *StatusReportRes) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if destination == nil {
		return fmt.Errorf("%w: StatusReportRes destination is nil", ber.ErrInvalidValue)
	}
	v := new(StatusReportRes)

	defer publishDecodedValue(destination, v, &returnErr)

	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	preparedData, preparedOptions, prepareErr := prepareCompositeBER(data, opts, s47bb6e_19, "child", (*StatusReportRes).UnmarshalBER)
	if prepareErr != nil {
		return prepareErr
	}
	data, opts = preparedData, preparedOptions

	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
	*v = StatusReportRes{}
	defer func() {
		if returnErr == nil {
			returnErr = completeValueBER(data,
				opts, v, &v.berReplayNode_, (*StatusReportRes).MarshalBER)
		}

	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("%s: %w", "decoding StatusReportRes SEQUENCE", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "StatusReportRes", Cause: ber.ErrExtraData}
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
				_ = rawVal_extensioncontainer
				if offset > len(content) || n_extensioncontainer < 0 || n_extensioncontainer > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				reconstructed_extensioncontainer, reconstructionErr_extensioncontainer := ber.EncodeImplicitTagWithClass(tag.ClassUniversal, tag.TagSequence, content[offset:offset+n_extensioncontainer])
				if reconstructionErr_extensioncontainer != nil {
					return qualifyBERError(reconstructionErr_extensioncontainer, "extensionContainer", "decoding", false)
				}
				var dec_extensioncontainer ExtensionContainer
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
			return &ber.DecodeError{Offset: offset, TypeName: "StatusReportRes", Cause: extErr_}
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: the first unknown addition must differ from trailing OPTIONAL/DEFAULT tags.
		if len(v.ExtData_) == 0 && (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0) {
			if !ber.ToleranceEnabled(opts) {
				return &ber.DecodeError{Offset: offset, TypeName: "StatusReportRes", Cause: fmt.Errorf("%w: repeated or out-of-order SEQUENCE component tag %s", ber.ErrInvalidTag, peekTag)}
			}
			if orderErr_ := ber.CheckDecodedValue(ber.DecodeRule(opts, s47bb6e_19, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), fmt.Sprintf("ExtData_[%d]", len(v.ExtData_)), "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); orderErr_ != nil {
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

// MarshalBER encodes RemoteUserFreeArg to BER format.
func (v *RemoteUserFreeArg) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {

	if v == nil {
		return nil, fmt.Errorf("%w: RemoteUserFreeArg receiver is nil", ber.ErrInvalidValue)
	}
	return marshalFramedValue(v, v.berReplayNode_, opts, (*RemoteUserFreeArg).MarshalBER, (*RemoteUserFreeArg).marshalBER, 3)

}
func (v *RemoteUserFreeArg) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if len(v.Imsi) < 3 || len(v.Imsi) > 8 {
		if constraintErr := checkEncodedLength(opts, s47bb6e_20, "51.5", "imsi", "SIZE (3..8)", len(v.Imsi)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_imsi, encodeErr_enc_imsi := ber.EncodeOctetString([]byte(v.Imsi))
	if encodeErr_enc_imsi != nil {
		return nil, qualifyBERError(encodeErr_enc_imsi, "imsi", "encoding", false)
	}
	retagged_enc_imsi, tagErr_enc_imsi := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_imsi)
	if tagErr_enc_imsi != nil {
		return nil, qualifyBERError(tagErr_enc_imsi, "imsi", "encoding", false)
	}
	enc_imsi = retagged_enc_imsi
	children = append(children, enc_imsi...)
	enc_callinfo, err := v.CallInfo.MarshalBER(ber.ChildEncodeOptions(opts, "callInfo")...)
	if err != nil {
		return nil, qualifyBERError(err, "callInfo", "encoding", false)
	}
	retagged_enc_callinfo, tagErr_enc_callinfo := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_callinfo)
	if tagErr_enc_callinfo != nil {
		return nil, qualifyBERError(tagErr_enc_callinfo, "callInfo", "encoding", false)
	}
	enc_callinfo = retagged_enc_callinfo
	ber.RecordGeneratedBERChildPlacement(opts, len(children), enc_callinfo)
	children = append(children, enc_callinfo...)
	enc_ccbsfeature, err := v.CcbsFeature.MarshalBER(ber.ChildEncodeOptions(opts, "ccbs-Feature")...)
	if err != nil {
		return nil, qualifyBERError(err, "ccbs-Feature", "encoding", false)
	}
	retagged_enc_ccbsfeature, tagErr_enc_ccbsfeature := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_ccbsfeature)
	if tagErr_enc_ccbsfeature != nil {
		return nil, qualifyBERError(tagErr_enc_ccbsfeature, "ccbs-Feature", "encoding", false)
	}
	enc_ccbsfeature = retagged_enc_ccbsfeature
	ber.RecordGeneratedBERChildPlacement(opts, len(children), enc_ccbsfeature)
	children = append(children, enc_ccbsfeature...)
	if len(v.TranslatedBNumber) < 1 || len(v.TranslatedBNumber) > 9 {
		if constraintErr := checkEncodedLength(opts, s47bb6e_20, "51.5", "translatedB-Number", "SIZE (1..9)", len(v.TranslatedBNumber)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	if len(v.TranslatedBNumber) < 1 || len(v.TranslatedBNumber) > 20 {
		if constraintErr := checkEncodedLength(opts, s47bb6e_20, "51.5", "translatedB-Number", "SIZE (1..20)", len(v.TranslatedBNumber)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_translatedbnumber, encodeErr_enc_translatedbnumber := ber.EncodeOctetString([]byte(v.TranslatedBNumber))
	if encodeErr_enc_translatedbnumber != nil {
		return nil, qualifyBERError(encodeErr_enc_translatedbnumber, "translatedB-Number", "encoding", false)
	}
	retagged_enc_translatedbnumber, tagErr_enc_translatedbnumber := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, enc_translatedbnumber)
	if tagErr_enc_translatedbnumber != nil {
		return nil, qualifyBERError(tagErr_enc_translatedbnumber, "translatedB-Number", "encoding", false)
	}
	enc_translatedbnumber = retagged_enc_translatedbnumber
	children = append(children, enc_translatedbnumber...)
	if v.ReplaceBNumber != nil {
		enc_replacebnumber := ber.EncodeNull()
		retagged_enc_replacebnumber, tagErr_enc_replacebnumber := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, enc_replacebnumber)
		if tagErr_enc_replacebnumber != nil {
			return nil, qualifyBERError(tagErr_enc_replacebnumber, "replaceB-Number", "encoding", false)
		}
		enc_replacebnumber = retagged_enc_replacebnumber
		children = append(children, enc_replacebnumber...)
	}
	if v.AlertingPattern != nil {
		if len(*v.AlertingPattern) < 1 || len(*v.AlertingPattern) > 1 {
			if constraintErr := checkEncodedLength(opts, s47bb6e_20, "51.5", "alertingPattern", "SIZE (1)", len(*v.AlertingPattern)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_alertingpattern, encodeErr_enc_alertingpattern := ber.EncodeOctetString([]byte(*v.AlertingPattern))
		if encodeErr_enc_alertingpattern != nil {
			return nil, qualifyBERError(encodeErr_enc_alertingpattern, "alertingPattern", "encoding", false)
		}
		retagged_enc_alertingpattern, tagErr_enc_alertingpattern := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 5, enc_alertingpattern)
		if tagErr_enc_alertingpattern != nil {
			return nil, qualifyBERError(tagErr_enc_alertingpattern, "alertingPattern", "encoding", false)
		}
		enc_alertingpattern = retagged_enc_alertingpattern
		children = append(children, enc_alertingpattern...)
	}
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalBER(ber.ChildEncodeOptions(opts, "extensionContainer")...)
		if err != nil {
			return nil, qualifyBERError(err, "extensionContainer", "encoding", false)
		}
		retagged_enc_extensioncontainer, tagErr_enc_extensioncontainer := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 6, enc_extensioncontainer)
		if tagErr_enc_extensioncontainer != nil {
			return nil, qualifyBERError(tagErr_enc_extensioncontainer, "extensionContainer", "encoding", false)
		}
		enc_extensioncontainer = retagged_enc_extensioncontainer
		ber.RecordGeneratedBERChildPlacement(opts, len(children), enc_extensioncontainer)
		children = append(children, enc_extensioncontainer...)
	}
	base_ := -1
	for i, ext := range v.ExtData_ {
		if err := checkOpaqueAddition(ext, opts, s47bb6e_20, children, i, &base_); err != nil {
			return nil, opaqueExtensionError(err, i)
		}
		peekTag, n, _, extErr := ber.DecodeEncodedTLV(ext)
		if extErr != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, extErr)
		}
		if n != len(ext) {
			return nil, fmt.Errorf("encoding extension %d: %w", i, ber.ErrExtraData)
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: only the first addition is restricted.
		if i == 0 && ((peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 6) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 5) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4)) {
			if constraintErr := ber.CheckEncodedValue(ber.EncodeRule(opts, s47bb6e_20, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
				return nil, constraintErr
			}
		}
		children = append(children, ext...)
	}
	ber.RecordGeneratedBERContainer(opts, children)
	return ber.EncodeSequence(children)
}
func (v *RemoteUserFreeArg) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// MarshalDER encodes RemoteUserFreeArg to DER format.
// Opaque descendants pass generic DER checks; foreign schema rules need a typed binding.
func (v *RemoteUserFreeArg) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: RemoteUserFreeArg receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if len(v.Imsi) < 3 || len(v.Imsi) > 8 {
		if constraintErr := checkEncodedLength(nil, s47bb6e_20, "51.5", "imsi", "SIZE (3..8)", len(v.Imsi)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_imsi, encodeErr_enc_imsi := ber.EncodeOctetString([]byte(v.Imsi))
	if encodeErr_enc_imsi != nil {
		return nil, qualifyBERError(encodeErr_enc_imsi, "imsi", "encoding", true)
	}
	retagged_enc_imsi, tagErr_enc_imsi := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_imsi)
	if tagErr_enc_imsi != nil {
		return nil, qualifyBERError(tagErr_enc_imsi, "imsi", "encoding", true)
	}
	enc_imsi = retagged_enc_imsi
	children = append(children, enc_imsi...)
	enc_callinfo, err := v.CallInfo.MarshalDER()
	if err != nil {
		return nil, qualifyBERError(err, "callInfo", "encoding", true)
	}
	retagged_enc_callinfo, tagErr_enc_callinfo := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_callinfo)
	if tagErr_enc_callinfo != nil {
		return nil, qualifyBERError(tagErr_enc_callinfo, "callInfo", "encoding", true)
	}
	enc_callinfo = retagged_enc_callinfo
	children = append(children, enc_callinfo...)
	enc_ccbsfeature, err := v.CcbsFeature.MarshalDER()
	if err != nil {
		return nil, qualifyBERError(err, "ccbs-Feature", "encoding", true)
	}
	retagged_enc_ccbsfeature, tagErr_enc_ccbsfeature := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_ccbsfeature)
	if tagErr_enc_ccbsfeature != nil {
		return nil, qualifyBERError(tagErr_enc_ccbsfeature, "ccbs-Feature", "encoding", true)
	}
	enc_ccbsfeature = retagged_enc_ccbsfeature
	children = append(children, enc_ccbsfeature...)
	if len(v.TranslatedBNumber) < 1 || len(v.TranslatedBNumber) > 9 {
		if constraintErr := checkEncodedLength(nil, s47bb6e_20, "51.5", "translatedB-Number", "SIZE (1..9)", len(v.TranslatedBNumber)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	if len(v.TranslatedBNumber) < 1 || len(v.TranslatedBNumber) > 20 {
		if constraintErr := checkEncodedLength(nil, s47bb6e_20, "51.5", "translatedB-Number", "SIZE (1..20)", len(v.TranslatedBNumber)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_translatedbnumber, encodeErr_enc_translatedbnumber := ber.EncodeOctetString([]byte(v.TranslatedBNumber))
	if encodeErr_enc_translatedbnumber != nil {
		return nil, qualifyBERError(encodeErr_enc_translatedbnumber, "translatedB-Number", "encoding", true)
	}
	retagged_enc_translatedbnumber, tagErr_enc_translatedbnumber := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, enc_translatedbnumber)
	if tagErr_enc_translatedbnumber != nil {
		return nil, qualifyBERError(tagErr_enc_translatedbnumber, "translatedB-Number", "encoding", true)
	}
	enc_translatedbnumber = retagged_enc_translatedbnumber
	children = append(children, enc_translatedbnumber...)
	if v.ReplaceBNumber != nil {
		enc_replacebnumber := ber.EncodeNull()
		retagged_enc_replacebnumber, tagErr_enc_replacebnumber := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, enc_replacebnumber)
		if tagErr_enc_replacebnumber != nil {
			return nil, qualifyBERError(tagErr_enc_replacebnumber, "replaceB-Number", "encoding", true)
		}
		enc_replacebnumber = retagged_enc_replacebnumber
		children = append(children, enc_replacebnumber...)
	}
	if v.AlertingPattern != nil {
		if len(*v.AlertingPattern) < 1 || len(*v.AlertingPattern) > 1 {
			if constraintErr := checkEncodedLength(nil, s47bb6e_20, "51.5", "alertingPattern", "SIZE (1)", len(*v.AlertingPattern)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_alertingpattern, encodeErr_enc_alertingpattern := ber.EncodeOctetString([]byte(*v.AlertingPattern))
		if encodeErr_enc_alertingpattern != nil {
			return nil, qualifyBERError(encodeErr_enc_alertingpattern, "alertingPattern", "encoding", true)
		}
		retagged_enc_alertingpattern, tagErr_enc_alertingpattern := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 5, enc_alertingpattern)
		if tagErr_enc_alertingpattern != nil {
			return nil, qualifyBERError(tagErr_enc_alertingpattern, "alertingPattern", "encoding", true)
		}
		enc_alertingpattern = retagged_enc_alertingpattern
		children = append(children, enc_alertingpattern...)
	}
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalDER()
		if err != nil {
			return nil, qualifyBERError(err, "extensionContainer", "encoding", true)
		}
		retagged_enc_extensioncontainer, tagErr_enc_extensioncontainer := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 6, enc_extensioncontainer)
		if tagErr_enc_extensioncontainer != nil {
			return nil, qualifyBERError(tagErr_enc_extensioncontainer, "extensionContainer", "encoding", true)
		}
		enc_extensioncontainer = retagged_enc_extensioncontainer
		children = append(children, enc_extensioncontainer...)
	}
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDEREncodedElement(ext); err != nil {
			return nil, invalidDERAddition(ext, s47bb6e_20, children, i)
		}
		peekTag, _, _, extErr := ber.DecodeEncodedTLV(ext)
		if extErr != nil {
			return nil, extErr
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: only the first addition is restricted.
		if i == 0 && ((peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 6) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 5) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4)) {
			if constraintErr := ber.CheckEncodedValue(ber.EncodeRule(nil, s47bb6e_20, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
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
		return nil, fmt.Errorf("%s: %w", "encoding RemoteUserFreeArg as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}
func (v *RemoteUserFreeArg) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	encoded, err := v.MarshalDER()
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBER decodes RemoteUserFreeArg from BER/DER format.
func (destination *RemoteUserFreeArg) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if destination == nil {
		return fmt.Errorf("%w: RemoteUserFreeArg destination is nil", ber.ErrInvalidValue)
	}
	v := new(RemoteUserFreeArg)

	defer publishDecodedValue(destination, v, &returnErr)

	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	preparedData, preparedOptions, prepareErr := prepareCompositeBER(data, opts, s47bb6e_20, "child", (*RemoteUserFreeArg).UnmarshalBER)
	if prepareErr != nil {
		return prepareErr
	}
	data, opts = preparedData, preparedOptions

	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
	*v = RemoteUserFreeArg{}
	defer func() {
		if returnErr == nil {
			returnErr = completeValueBER(data,
				opts, v, &v.berReplayNode_, (*RemoteUserFreeArg).MarshalBER)
		}

	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("%s: %w", "decoding RemoteUserFreeArg SEQUENCE", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "RemoteUserFreeArg", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode imsi
	if offset >= len(content) {
		return fmt.Errorf("missing required field imsi")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 0 {
			return fmt.Errorf("expected tag [%s %d] for imsi, got %s", "CONTEXT", 0, reqTag_)
		}
	}
	{
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
		v.Imsi = IMSI(decVal_imsi)
		if offset > len(content) || n_imsi < 0 || n_imsi > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n_imsi
		if len(v.Imsi) < 3 || len(v.Imsi) > 8 {
			if constraintErr := checkDecodedLength(opts, s47bb6e_20, "51.5", "imsi", "SIZE (3..8)", len(v.Imsi)); constraintErr != nil {
				return constraintErr
			}
		}
	}
	// Decode callInfo
	if offset >= len(content) {
		return fmt.Errorf("missing required field callInfo")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 1 {
			return fmt.Errorf("expected tag [%s %d] for callInfo, got %s", "CONTEXT", 1, reqTag_)
		}
	}
	{
		ber.MarkPreflightTarget(opts, "callInfo", content[offset:])
		decodedTag_callinfo, n_callinfo, rawVal_callinfo, err := ber.DecodeTLV(content[offset:], opts...)
		if err != nil {
			return qualifyBERError(err, "callInfo", "decoding", false)
		}
		if decodedTag_callinfo.Class != tag.ClassContextSpecific || decodedTag_callinfo.Number != 1 || decodedTag_callinfo.Constructed != true {
			return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_callinfo), "callInfo", "decoding", false)
		}
		_ = rawVal_callinfo
		if offset < 0 || offset >
			len(content) || n_callinfo < 0 || n_callinfo > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		reconstructed_callinfo, reconstructionErr_callinfo := ber.EncodeImplicitTagWithClass(tag.ClassUniversal, tag.TagSequence, content[offset:offset+n_callinfo])
		if reconstructionErr_callinfo != nil {
			return qualifyBERError(reconstructionErr_callinfo, "callInfo", "decoding", false)
		}
		if unmErr := v.CallInfo.UnmarshalBER(reconstructed_callinfo, ber.ChildDecodeOptions(opts, "callInfo")...); unmErr != nil {
			return qualifyBERError(unmErr, "callInfo", "decoding", false)
		}
		if offset < 0 || offset >
			len(content) || n_callinfo < 0 || n_callinfo > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n_callinfo
	}
	// Decode ccbs-Feature
	if offset >= len(content) {
		return fmt.Errorf("missing required field ccbs-Feature")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 2 {
			return fmt.Errorf("expected tag [%s %d] for ccbs-Feature, got %s", "CONTEXT", 2, reqTag_)
		}
	}
	{
		ber.MarkPreflightTarget(opts, "ccbs-Feature", content[offset:])
		decodedTag_ccbsfeature, n_ccbsfeature, rawVal_ccbsfeature, err := ber.DecodeTLV(content[offset:], opts...)
		if err != nil {
			return qualifyBERError(err, "ccbs-Feature", "decoding", false)
		}
		if decodedTag_ccbsfeature.Class != tag.ClassContextSpecific || decodedTag_ccbsfeature.Number != 2 || decodedTag_ccbsfeature.Constructed != true {
			return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_ccbsfeature), "ccbs-Feature", "decoding", false)
		}
		_ = rawVal_ccbsfeature
		if offset < 0 || offset >
			len(content) || n_ccbsfeature < 0 || n_ccbsfeature > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		reconstructed_ccbsfeature, reconstructionErr_ccbsfeature := ber.EncodeImplicitTagWithClass(tag.ClassUniversal, tag.TagSequence, content[offset:offset+n_ccbsfeature])
		if reconstructionErr_ccbsfeature != nil {
			return qualifyBERError(reconstructionErr_ccbsfeature, "ccbs-Feature", "decoding", false)
		}
		if unmErr := v.CcbsFeature.UnmarshalBER(reconstructed_ccbsfeature, ber.ChildDecodeOptions(opts, "ccbs-Feature")...); unmErr != nil {
			return qualifyBERError(unmErr, "ccbs-Feature", "decoding", false)
		}
		if offset < 0 || offset >
			len(content) || n_ccbsfeature < 0 || n_ccbsfeature > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n_ccbsfeature
	}
	// Decode translatedB-Number
	if offset >= len(content) {
		return fmt.Errorf("missing required field translatedB-Number")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 3 {
			return fmt.Errorf("expected tag [%s %d] for translatedB-Number, got %s", "CONTEXT", 3, reqTag_)
		}
	}
	{
		ber.MarkPreflightTarget(opts, "translatedB-Number", content[offset:])
		decodedTag_translatedbnumber, n_translatedbnumber, rawVal_translatedbnumber, err := ber.DecodeTLV(content[offset:], opts...)
		if err != nil {
			return qualifyBERError(err, "translatedB-Number", "decoding", false)
		}
		if decodedTag_translatedbnumber.Class != tag.ClassContextSpecific || decodedTag_translatedbnumber.Number != 3 {
			return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_translatedbnumber), "translatedB-Number", "decoding", false)
		}
		decVal_translatedbnumber, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_translatedbnumber.Constructed, rawVal_translatedbnumber, opts...)
		if octetErr != nil {
			return qualifyBERError(octetErr, "translatedB-Number", "decoding", false)
		}
		v.TranslatedBNumber = ISDNAddressString(decVal_translatedbnumber)
		if offset < 0 || offset >
			len(content) || n_translatedbnumber < 0 || n_translatedbnumber >
			len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n_translatedbnumber
		if len(v.TranslatedBNumber) < 1 || len(v.TranslatedBNumber) > 9 {
			if constraintErr := checkDecodedLength(opts, s47bb6e_20, "51.5", "translatedB-Number", "SIZE (1..9)", len(v.TranslatedBNumber)); constraintErr != nil {
				return constraintErr
			}
		}
		if len(v.TranslatedBNumber) < 1 || len(v.TranslatedBNumber) > 20 {
			if constraintErr := checkDecodedLength(opts, s47bb6e_20, "51.5", "translatedB-Number", "SIZE (1..20)", len(v.TranslatedBNumber)); constraintErr != nil {
				return constraintErr
			}
		}
	}
	// Decode replaceB-Number
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4 {
				ber.MarkPreflightTarget(opts, "replaceB-Number", content[offset:])
				decodedTag_replacebnumber, n_replacebnumber, rawVal_replacebnumber, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "replaceB-Number", "decoding", false)
				}
				if decodedTag_replacebnumber.Class != tag.ClassContextSpecific || decodedTag_replacebnumber.Number != 4 || decodedTag_replacebnumber.Constructed != false {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_replacebnumber), "replaceB-Number", "decoding", false)
				}
				if len(rawVal_replacebnumber) != 0 {
					return qualifyBERError(fmt.Errorf("%w: NULL content length %d", ber.ErrInvalidValue, len(rawVal_replacebnumber)), "replaceB-Number", "decoding", false)
				}
				v.ReplaceBNumber = &struct{}{}
				if offset < 0 || offset >
					len(content) || n_replacebnumber < 0 || n_replacebnumber >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_replacebnumber
			}
		}
	}
	// Decode alertingPattern
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 5 {
				ber.MarkPreflightTarget(opts, "alertingPattern", content[offset:])
				decodedTag_alertingpattern, n_alertingpattern, rawVal_alertingpattern, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "alertingPattern", "decoding", false)
				}
				if decodedTag_alertingpattern.Class != tag.ClassContextSpecific || decodedTag_alertingpattern.Number != 5 {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_alertingpattern), "alertingPattern", "decoding", false)
				}
				decVal_alertingpattern, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_alertingpattern.Constructed, rawVal_alertingpattern, opts...)
				if octetErr != nil {
					return qualifyBERError(octetErr, "alertingPattern", "decoding", false)
				}
				tmp_alertingpattern := AlertingPattern(decVal_alertingpattern)
				v.AlertingPattern = &tmp_alertingpattern
				if offset < 0 || offset >
					len(content) || n_alertingpattern < 0 || n_alertingpattern >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_alertingpattern
				if len(*v.AlertingPattern) < 1 || len(*v.AlertingPattern) > 1 {
					if constraintErr := checkDecodedLength(opts, s47bb6e_20, "51.5", "alertingPattern", "SIZE (1)", len(*v.AlertingPattern)); constraintErr != nil {
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
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 6 {
				ber.MarkPreflightTarget(opts, "extensionContainer", content[offset:])
				decodedTag_extensioncontainer, n_extensioncontainer, rawVal_extensioncontainer, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "extensionContainer", "decoding", false)
				}
				if decodedTag_extensioncontainer.Class != tag.ClassContextSpecific || decodedTag_extensioncontainer.Number != 6 || decodedTag_extensioncontainer.Constructed != true {
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
				var dec_extensioncontainer ExtensionContainer
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
			return &ber.DecodeError{Offset: offset, TypeName: "RemoteUserFreeArg", Cause: extErr_}
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: the first unknown addition must differ from trailing OPTIONAL/DEFAULT tags.
		if len(v.ExtData_) == 0 && ((peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 6) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 5) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4)) {
			if !ber.ToleranceEnabled(opts) {
				return &ber.DecodeError{Offset: offset, TypeName: "RemoteUserFreeArg", Cause: fmt.Errorf("%w: repeated or out-of-order SEQUENCE component tag %s", ber.ErrInvalidTag, peekTag)}
			}
			if orderErr_ := ber.CheckDecodedValue(ber.DecodeRule(opts, s47bb6e_20, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), fmt.Sprintf("ExtData_[%d]", len(v.ExtData_)), "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); orderErr_ != nil {
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

// MarshalBER encodes RemoteUserFreeRes to BER format.
func (v *RemoteUserFreeRes) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {

	if v == nil {
		return nil, fmt.Errorf("%w: RemoteUserFreeRes receiver is nil", ber.ErrInvalidValue)
	}
	return marshalFramedValue(v, v.berReplayNode_, opts, (*RemoteUserFreeRes).MarshalBER, (*RemoteUserFreeRes).marshalBER, 3)

}
func (v *RemoteUserFreeRes) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	enc_rufoutcome := ber.EncodeEnumerated(int64(v.RufOutcome))
	retagged_enc_rufoutcome, tagErr_enc_rufoutcome := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_rufoutcome)
	if tagErr_enc_rufoutcome != nil {
		return nil, qualifyBERError(tagErr_enc_rufoutcome, "ruf-Outcome", "encoding", false)
	}
	enc_rufoutcome = retagged_enc_rufoutcome
	children = append(children, enc_rufoutcome...)
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
	base_ := -1
	for i, ext := range v.ExtData_ {
		if err := checkOpaqueAddition(ext, opts, s47bb6e_21, children, i, &base_); err != nil {
			return nil, opaqueExtensionError(err, i)
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
			if constraintErr := ber.CheckEncodedValue(ber.EncodeRule(opts, s47bb6e_21, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
				return nil, constraintErr
			}
		}
		children = append(children, ext...)
	}
	ber.RecordGeneratedBERContainer(opts, children)
	return ber.EncodeSequence(children)
}
func (v *RemoteUserFreeRes) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// MarshalDER encodes RemoteUserFreeRes to DER format.
// Opaque descendants pass generic DER checks; foreign schema rules need a typed binding.
func (v *RemoteUserFreeRes) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: RemoteUserFreeRes receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	enc_rufoutcome := ber.EncodeEnumerated(int64(v.RufOutcome))
	retagged_enc_rufoutcome, tagErr_enc_rufoutcome := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_rufoutcome)
	if tagErr_enc_rufoutcome != nil {
		return nil, qualifyBERError(tagErr_enc_rufoutcome, "ruf-Outcome", "encoding", true)
	}
	enc_rufoutcome = retagged_enc_rufoutcome
	children = append(children, enc_rufoutcome...)
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
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDEREncodedElement(ext); err != nil {
			return nil, invalidDERAddition(ext, s47bb6e_21, children, i)
		}
		peekTag, _, _, extErr := ber.DecodeEncodedTLV(ext)
		if extErr != nil {
			return nil, extErr
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: only the first addition is restricted.
		if i == 0 && (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1) {
			if constraintErr := ber.CheckEncodedValue(ber.EncodeRule(nil, s47bb6e_21, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
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
		return nil, fmt.Errorf("%s: %w", "encoding RemoteUserFreeRes as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}
func (v *RemoteUserFreeRes) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	encoded, err := v.MarshalDER()
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBER decodes RemoteUserFreeRes from BER/DER format.
func (destination *RemoteUserFreeRes) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if destination == nil {
		return fmt.Errorf("%w: RemoteUserFreeRes destination is nil", ber.ErrInvalidValue)
	}
	v := new(RemoteUserFreeRes)

	defer publishDecodedValue(destination, v, &returnErr)

	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	preparedData, preparedOptions, prepareErr := prepareCompositeBER(data, opts, s47bb6e_21, "child", (*RemoteUserFreeRes).UnmarshalBER)
	if prepareErr != nil {
		return prepareErr
	}
	data, opts = preparedData, preparedOptions

	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
	*v = RemoteUserFreeRes{}
	defer func() {
		if returnErr == nil {
			returnErr = completeValueBER(data,
				opts, v, &v.berReplayNode_, (*RemoteUserFreeRes).MarshalBER)
		}

	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("%s: %w", "decoding RemoteUserFreeRes SEQUENCE", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "RemoteUserFreeRes", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode ruf-Outcome
	if offset >= len(content) {
		return fmt.Errorf("missing required field ruf-Outcome")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 0 {
			return fmt.Errorf("expected tag [%s %d] for ruf-Outcome, got %s", "CONTEXT", 0, reqTag_)
		}
	}
	{
		ber.MarkPreflightTarget(opts, "ruf-Outcome", content[offset:])
		decodedTag_rufoutcome, n_rufoutcome, rawVal_rufoutcome, err := ber.DecodeTLV(content[offset:], opts...)
		if err != nil {
			return qualifyBERError(err, "ruf-Outcome", "decoding", false)
		}
		if decodedTag_rufoutcome.Class != tag.ClassContextSpecific || decodedTag_rufoutcome.Number != 0 || decodedTag_rufoutcome.Constructed != false {
			return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_rufoutcome), "ruf-Outcome", "decoding", false)
		}
		decVal_rufoutcome, intErr := ber.DecodeEnumeratedValue(rawVal_rufoutcome)
		if intErr != nil {
			return qualifyBERError(intErr, "ruf-Outcome", "decoding", false)
		}
		v.RufOutcome = RUFOutcome(decVal_rufoutcome)
		if offset > len(content) || n_rufoutcome < 0 || n_rufoutcome > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n_rufoutcome
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
				var dec_extensioncontainer ExtensionContainer
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
			return &ber.DecodeError{Offset: offset, TypeName: "RemoteUserFreeRes", Cause: extErr_}
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: the first unknown addition must differ from trailing OPTIONAL/DEFAULT tags.
		if len(v.ExtData_) == 0 && (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1) {
			if !ber.ToleranceEnabled(opts) {
				return &ber.DecodeError{Offset: offset, TypeName: "RemoteUserFreeRes", Cause: fmt.Errorf("%w: repeated or out-of-order SEQUENCE component tag %s", ber.ErrInvalidTag, peekTag)}
			}
			if orderErr_ := ber.CheckDecodedValue(ber.DecodeRule(opts, s47bb6e_21, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), fmt.Sprintf("ExtData_[%d]", len(v.ExtData_)), "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); orderErr_ != nil {
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

// MarshalBER encodes ISTAlertArg to BER format.
func (v *ISTAlertArg) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {

	if v == nil {
		return nil, fmt.Errorf("%w: ISTAlertArg receiver is nil", ber.ErrInvalidValue)
	}
	return marshalFramedValue(v, v.berReplayNode_, opts, (*ISTAlertArg).MarshalBER, (*ISTAlertArg).marshalBER, 3)

}
func (v *ISTAlertArg) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if len(v.Imsi) < 3 || len(v.Imsi) > 8 {
		if constraintErr := checkEncodedLength(opts, s47bb6e_22, "51.5", "imsi", "SIZE (3..8)", len(v.Imsi)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_imsi, encodeErr_enc_imsi := ber.EncodeOctetString([]byte(v.Imsi))
	if encodeErr_enc_imsi != nil {
		return nil, qualifyBERError(encodeErr_enc_imsi, "imsi", "encoding", false)
	}
	retagged_enc_imsi, tagErr_enc_imsi := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_imsi)
	if tagErr_enc_imsi != nil {
		return nil, qualifyBERError(tagErr_enc_imsi, "imsi", "encoding", false)
	}
	enc_imsi = retagged_enc_imsi
	children = append(children, enc_imsi...)
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
	base_ := -1
	for i, ext := range v.ExtData_ {
		if err := checkOpaqueAddition(ext, opts, s47bb6e_22, children, i, &base_); err != nil {
			return nil, opaqueExtensionError(err, i)
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
			if constraintErr := ber.CheckEncodedValue(ber.EncodeRule(opts, s47bb6e_22, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
				return nil, constraintErr
			}
		}
		children = append(children, ext...)
	}
	ber.RecordGeneratedBERContainer(opts, children)
	return ber.EncodeSequence(children)
}
func (v *ISTAlertArg) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// MarshalDER encodes ISTAlertArg to DER format.
// Opaque descendants pass generic DER checks; foreign schema rules need a typed binding.
func (v *ISTAlertArg) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: ISTAlertArg receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if len(v.Imsi) < 3 || len(v.Imsi) > 8 {
		if constraintErr := checkEncodedLength(nil, s47bb6e_22, "51.5", "imsi", "SIZE (3..8)", len(v.Imsi)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_imsi, encodeErr_enc_imsi := ber.EncodeOctetString([]byte(v.Imsi))
	if encodeErr_enc_imsi != nil {
		return nil, qualifyBERError(encodeErr_enc_imsi, "imsi", "encoding", true)
	}
	retagged_enc_imsi, tagErr_enc_imsi := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_imsi)
	if tagErr_enc_imsi != nil {
		return nil, qualifyBERError(tagErr_enc_imsi, "imsi", "encoding", true)
	}
	enc_imsi = retagged_enc_imsi
	children = append(children, enc_imsi...)
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
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDEREncodedElement(ext); err != nil {
			return nil, invalidDERAddition(ext, s47bb6e_22, children, i)
		}
		peekTag, _, _, extErr := ber.DecodeEncodedTLV(ext)
		if extErr != nil {
			return nil, extErr
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: only the first addition is restricted.
		if i == 0 && (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1) {
			if constraintErr := ber.CheckEncodedValue(ber.EncodeRule(nil, s47bb6e_22, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
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
		return nil, fmt.Errorf("%s: %w", "encoding ISTAlertArg as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}
func (v *ISTAlertArg) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	encoded, err := v.MarshalDER()
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBER decodes ISTAlertArg from BER/DER format.
func (destination *ISTAlertArg) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if destination == nil {
		return fmt.Errorf("%w: ISTAlertArg destination is nil", ber.ErrInvalidValue)
	}
	v := new(ISTAlertArg)
	defer publishDecodedValue(destination, v, &returnErr)

	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	preparedData, preparedOptions, prepareErr := prepareCompositeBER(data, opts, s47bb6e_22, "child", (*ISTAlertArg).UnmarshalBER)
	if prepareErr != nil {
		return prepareErr
	}
	data, opts = preparedData, preparedOptions

	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
	*v = ISTAlertArg{}
	defer func() {
		if returnErr == nil {
			returnErr = completeValueBER(data,
				opts, v, &v.berReplayNode_, (*ISTAlertArg).MarshalBER)
		}

	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("%s: %w", "decoding ISTAlertArg SEQUENCE", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "ISTAlertArg", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode imsi
	if offset >= len(content) {
		return fmt.Errorf("missing required field imsi")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 0 {
			return fmt.Errorf("expected tag [%s %d] for imsi, got %s", "CONTEXT", 0, reqTag_)
		}
	}
	{
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
		v.Imsi = IMSI(decVal_imsi)
		if offset > len(content) || n_imsi < 0 || n_imsi > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n_imsi
		if len(v.Imsi) < 3 || len(v.Imsi) > 8 {
			if constraintErr := checkDecodedLength(opts, s47bb6e_22, "51.5", "imsi", "SIZE (3..8)", len(v.Imsi)); constraintErr != nil {
				return constraintErr
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
				var dec_extensioncontainer ExtensionContainer
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
			return &ber.DecodeError{Offset: offset, TypeName: "ISTAlertArg", Cause: extErr_}
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: the first unknown addition must differ from trailing OPTIONAL/DEFAULT tags.
		if len(v.ExtData_) == 0 && (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1) {
			if !ber.ToleranceEnabled(opts) {
				return &ber.DecodeError{Offset: offset, TypeName: "ISTAlertArg", Cause: fmt.Errorf("%w: repeated or out-of-order SEQUENCE component tag %s", ber.ErrInvalidTag, peekTag)}
			}
			if orderErr_ := ber.CheckDecodedValue(ber.DecodeRule(opts, s47bb6e_22, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), fmt.Sprintf("ExtData_[%d]", len(v.ExtData_)), "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); orderErr_ != nil {
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

// MarshalBER encodes ISTAlertRes to BER format.
func (v *ISTAlertRes) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {

	if v == nil {
		return nil, fmt.Errorf("%w: ISTAlertRes receiver is nil", ber.ErrInvalidValue)
	}
	return marshalFramedValue(v, v.berReplayNode_, opts, (*ISTAlertRes).MarshalBER, (*ISTAlertRes).marshalBER, 3)

}
func (v *ISTAlertRes) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if v.IstAlertTimer != nil {
		if !(int64(*v.IstAlertTimer) >= 15 && int64(*v.IstAlertTimer) <= 255) {
			if constraintErr := checkEncodedValue(opts, s47bb6e_23, "51.4", "istAlertTimer", "(15..255)", ber.ObserveInteger(int64(*v.IstAlertTimer))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_istalerttimer := ber.EncodeInteger(int64(*v.IstAlertTimer))
		retagged_enc_istalerttimer, tagErr_enc_istalerttimer := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_istalerttimer)
		if tagErr_enc_istalerttimer != nil {
			return nil, qualifyBERError(tagErr_enc_istalerttimer, "istAlertTimer", "encoding", false)
		}
		enc_istalerttimer = retagged_enc_istalerttimer
		children = append(children, enc_istalerttimer...)
	}
	if v.IstInformationWithdraw != nil {
		enc_istinformationwithdraw := ber.EncodeNull()
		retagged_enc_istinformationwithdraw, tagErr_enc_istinformationwithdraw := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_istinformationwithdraw)
		if tagErr_enc_istinformationwithdraw != nil {
			return nil, qualifyBERError(tagErr_enc_istinformationwithdraw, "istInformationWithdraw", "encoding", false)
		}
		enc_istinformationwithdraw = retagged_enc_istinformationwithdraw
		children = append(children, enc_istinformationwithdraw...)
	}
	if v.CallTerminationIndicator != nil {
		enc_callterminationindicator := ber.EncodeEnumerated(int64(*v.CallTerminationIndicator))
		retagged_enc_callterminationindicator, tagErr_enc_callterminationindicator := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_callterminationindicator)
		if tagErr_enc_callterminationindicator != nil {
			return nil, qualifyBERError(tagErr_enc_callterminationindicator, "callTerminationIndicator", "encoding", false)
		}
		enc_callterminationindicator = retagged_enc_callterminationindicator
		children = append(children, enc_callterminationindicator...)
	}
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalBER(ber.ChildEncodeOptions(opts, "extensionContainer")...)
		if err != nil {
			return nil, qualifyBERError(err, "extensionContainer", "encoding", false)
		}
		retagged_enc_extensioncontainer, tagErr_enc_extensioncontainer := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, enc_extensioncontainer)
		if tagErr_enc_extensioncontainer != nil {
			return nil, qualifyBERError(tagErr_enc_extensioncontainer, "extensionContainer", "encoding", false)
		}
		enc_extensioncontainer = retagged_enc_extensioncontainer
		ber.RecordGeneratedBERChildPlacement(opts, len(children), enc_extensioncontainer)
		children = append(children, enc_extensioncontainer...)
	}
	base_ := -1
	for i, ext := range v.ExtData_ {
		if err := checkOpaqueAddition(ext, opts, s47bb6e_23, children, i, &base_); err != nil {
			return nil, opaqueExtensionError(err, i)
		}
		peekTag, n, _, extErr := ber.DecodeEncodedTLV(ext)
		if extErr != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, extErr)
		}
		if n != len(ext) {
			return nil, fmt.Errorf("encoding extension %d: %w", i, ber.ErrExtraData)
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: only the first addition is restricted.
		if i == 0 && ((peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0)) {
			if constraintErr := ber.CheckEncodedValue(ber.EncodeRule(opts, s47bb6e_23, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
				return nil, constraintErr
			}
		}
		children = append(children, ext...)
	}
	ber.RecordGeneratedBERContainer(opts, children)
	return ber.EncodeSequence(children)
}
func (v *ISTAlertRes) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// MarshalDER encodes ISTAlertRes to DER format.
// Opaque descendants pass generic DER checks; foreign schema rules need a typed binding.
func (v *ISTAlertRes) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: ISTAlertRes receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if v.IstAlertTimer != nil {
		if !(int64(*v.IstAlertTimer) >= 15 && int64(*v.IstAlertTimer) <= 255) {
			if constraintErr := checkEncodedValue(nil, s47bb6e_23, "51.4", "istAlertTimer", "(15..255)", ber.ObserveInteger(int64(*v.IstAlertTimer))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_istalerttimer := ber.EncodeInteger(int64(*v.IstAlertTimer))
		retagged_enc_istalerttimer, tagErr_enc_istalerttimer := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_istalerttimer)
		if tagErr_enc_istalerttimer != nil {
			return nil, qualifyBERError(tagErr_enc_istalerttimer, "istAlertTimer", "encoding", true)
		}
		enc_istalerttimer = retagged_enc_istalerttimer
		children = append(children, enc_istalerttimer...)
	}
	if v.IstInformationWithdraw != nil {
		enc_istinformationwithdraw := ber.EncodeNull()
		retagged_enc_istinformationwithdraw, tagErr_enc_istinformationwithdraw := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_istinformationwithdraw)
		if tagErr_enc_istinformationwithdraw != nil {
			return nil, qualifyBERError(tagErr_enc_istinformationwithdraw, "istInformationWithdraw", "encoding", true)
		}
		enc_istinformationwithdraw = retagged_enc_istinformationwithdraw
		children = append(children, enc_istinformationwithdraw...)
	}
	if v.CallTerminationIndicator != nil {
		enc_callterminationindicator := ber.EncodeEnumerated(int64(*v.CallTerminationIndicator))
		retagged_enc_callterminationindicator, tagErr_enc_callterminationindicator := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_callterminationindicator)
		if tagErr_enc_callterminationindicator != nil {
			return nil, qualifyBERError(tagErr_enc_callterminationindicator, "callTerminationIndicator", "encoding", true)
		}
		enc_callterminationindicator = retagged_enc_callterminationindicator
		children = append(children, enc_callterminationindicator...)
	}
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalDER()
		if err != nil {
			return nil, qualifyBERError(err, "extensionContainer", "encoding", true)
		}
		retagged_enc_extensioncontainer, tagErr_enc_extensioncontainer := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, enc_extensioncontainer)
		if tagErr_enc_extensioncontainer != nil {
			return nil, qualifyBERError(tagErr_enc_extensioncontainer, "extensionContainer", "encoding", true)
		}
		enc_extensioncontainer = retagged_enc_extensioncontainer
		children = append(children, enc_extensioncontainer...)
	}
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDEREncodedElement(ext); err != nil {
			return nil, invalidDERAddition(ext, s47bb6e_23, children, i)
		}
		peekTag, _, _, extErr := ber.DecodeEncodedTLV(ext)
		if extErr != nil {
			return nil, extErr
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: only the first addition is restricted.
		if i == 0 && ((peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0)) {
			if constraintErr := ber.CheckEncodedValue(ber.EncodeRule(nil, s47bb6e_23, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
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
		return nil, fmt.Errorf("%s: %w", "encoding ISTAlertRes as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}
func (v *ISTAlertRes) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	encoded, err := v.MarshalDER()
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBER decodes ISTAlertRes from BER/DER format.
func (destination *ISTAlertRes) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if destination == nil {
		return fmt.Errorf("%w: ISTAlertRes destination is nil", ber.ErrInvalidValue)
	}
	v := new(ISTAlertRes)
	defer publishDecodedValue(destination, v, &returnErr)

	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	preparedData, preparedOptions, prepareErr := prepareCompositeBER(data, opts, s47bb6e_23, "child", (*ISTAlertRes).UnmarshalBER)
	if prepareErr != nil {
		return prepareErr
	}
	data, opts = preparedData, preparedOptions

	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
	*v = ISTAlertRes{}
	defer func() {
		if returnErr == nil {
			returnErr = completeValueBER(data,
				opts, v, &v.berReplayNode_, (*ISTAlertRes).MarshalBER)
		}

	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("%s: %w", "decoding ISTAlertRes SEQUENCE", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "ISTAlertRes", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode istAlertTimer
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
				ber.MarkPreflightTarget(opts, "istAlertTimer", content[offset:])
				decodedTag_istalerttimer, n_istalerttimer, rawVal_istalerttimer, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "istAlertTimer", "decoding", false)
				}
				if decodedTag_istalerttimer.Class != tag.ClassContextSpecific || decodedTag_istalerttimer.Number != 0 || decodedTag_istalerttimer.Constructed != false {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_istalerttimer), "istAlertTimer", "decoding", false)
				}
				decVal_istalerttimer, intErr := ber.DecodeIntegerValue(rawVal_istalerttimer)
				if intErr != nil {
					return qualifyBERError(intErr, "istAlertTimer", "decoding", false)
				}
				tmp_istalerttimer := ISTAlertTimerValue(decVal_istalerttimer)
				v.IstAlertTimer = &tmp_istalerttimer
				if offset > len(content) || n_istalerttimer < 0 || n_istalerttimer > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_istalerttimer
				if !(int64(*v.IstAlertTimer) >= 15 && int64(*v.IstAlertTimer) <= 255) {
					if constraintErr := checkDecodedValue(opts, s47bb6e_23, "51.4", "istAlertTimer", "(15..255)", ber.ObserveInteger(int64(*v.IstAlertTimer))); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode istInformationWithdraw
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
				ber.MarkPreflightTarget(opts, "istInformationWithdraw", content[offset:])
				decodedTag_istinformationwithdraw, n_istinformationwithdraw, rawVal_istinformationwithdraw, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "istInformationWithdraw", "decoding", false)
				}
				if decodedTag_istinformationwithdraw.Class != tag.ClassContextSpecific || decodedTag_istinformationwithdraw.Number != 1 || decodedTag_istinformationwithdraw.Constructed != false {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_istinformationwithdraw), "istInformationWithdraw", "decoding", false)
				}
				if len(rawVal_istinformationwithdraw) != 0 {
					return qualifyBERError(fmt.Errorf("%w: NULL content length %d", ber.ErrInvalidValue, len(rawVal_istinformationwithdraw)), "istInformationWithdraw", "decoding", false)
				}
				v.IstInformationWithdraw = &struct{}{}
				if offset < 0 || offset >
					len(content) || n_istinformationwithdraw < 0 || n_istinformationwithdraw >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_istinformationwithdraw
			}
		}
	}
	// Decode callTerminationIndicator
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2 {
				ber.MarkPreflightTarget(opts, "callTerminationIndicator", content[offset:])
				decodedTag_callterminationindicator, n_callterminationindicator, rawVal_callterminationindicator, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "callTerminationIndicator", "decoding", false)
				}
				if decodedTag_callterminationindicator.Class != tag.ClassContextSpecific || decodedTag_callterminationindicator.Number != 2 || decodedTag_callterminationindicator.Constructed != false {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_callterminationindicator), "callTerminationIndicator", "decoding", false)
				}
				decVal_callterminationindicator, intErr := ber.DecodeEnumeratedValue(rawVal_callterminationindicator)
				if intErr != nil {
					return qualifyBERError(intErr, "callTerminationIndicator", "decoding", false)
				}
				tmp_callterminationindicator := CallTerminationIndicator(decVal_callterminationindicator)
				v.CallTerminationIndicator = &tmp_callterminationindicator
				if offset < 0 || offset >
					len(content) || n_callterminationindicator < 0 || n_callterminationindicator >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_callterminationindicator
			}
		}
	}
	// Decode extensionContainer
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3 {
				ber.MarkPreflightTarget(opts, "extensionContainer", content[offset:])
				decodedTag_extensioncontainer, n_extensioncontainer, rawVal_extensioncontainer, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "extensionContainer", "decoding", false)
				}
				if decodedTag_extensioncontainer.Class != tag.ClassContextSpecific || decodedTag_extensioncontainer.Number != 3 || decodedTag_extensioncontainer.Constructed != true {
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
				var dec_extensioncontainer ExtensionContainer
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
			return &ber.DecodeError{Offset: offset, TypeName: "ISTAlertRes", Cause: extErr_}
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: the first unknown addition must differ from trailing OPTIONAL/DEFAULT tags.
		if len(v.ExtData_) == 0 && ((peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0)) {
			if !ber.ToleranceEnabled(opts) {
				return &ber.DecodeError{Offset: offset, TypeName: "ISTAlertRes", Cause: fmt.Errorf("%w: repeated or out-of-order SEQUENCE component tag %s", ber.ErrInvalidTag, peekTag)}
			}
			if orderErr_ := ber.CheckDecodedValue(ber.DecodeRule(opts, s47bb6e_23, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), fmt.Sprintf("ExtData_[%d]", len(v.ExtData_)), "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); orderErr_ != nil {
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

// MarshalBER encodes ISTCommandArg to BER format.
func (v *ISTCommandArg) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {

	if v == nil {
		return nil, fmt.Errorf("%w: ISTCommandArg receiver is nil", ber.ErrInvalidValue)
	}
	return marshalFramedValue(v, v.berReplayNode_, opts, (*ISTCommandArg).MarshalBER, (*ISTCommandArg).marshalBER, 3)

}
func (v *ISTCommandArg) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if len(v.Imsi) < 3 || len(v.Imsi) > 8 {
		if constraintErr := checkEncodedLength(opts, s47bb6e_24, "51.5", "imsi", "SIZE (3..8)", len(v.Imsi)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_imsi, encodeErr_enc_imsi := ber.EncodeOctetString([]byte(v.Imsi))
	if encodeErr_enc_imsi != nil {
		return nil, qualifyBERError(encodeErr_enc_imsi, "imsi", "encoding", false)
	}
	retagged_enc_imsi, tagErr_enc_imsi := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_imsi)
	if tagErr_enc_imsi != nil {
		return nil, qualifyBERError(tagErr_enc_imsi, "imsi", "encoding", false)
	}
	enc_imsi = retagged_enc_imsi
	children = append(children, enc_imsi...)
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
	base_ := -1
	for i, ext := range v.ExtData_ {
		if err := checkOpaqueAddition(ext, opts, s47bb6e_24, children, i, &base_); err != nil {
			return nil, opaqueExtensionError(err, i)
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
			if constraintErr := ber.CheckEncodedValue(ber.EncodeRule(opts, s47bb6e_24, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
				return nil, constraintErr
			}
		}
		children = append(children, ext...)
	}
	ber.RecordGeneratedBERContainer(opts, children)
	return ber.EncodeSequence(children)
}
func (v *ISTCommandArg) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// MarshalDER encodes ISTCommandArg to DER format.
// Opaque descendants pass generic DER checks; foreign schema rules need a typed binding.
func (v *ISTCommandArg) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: ISTCommandArg receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if len(v.Imsi) < 3 || len(v.Imsi) > 8 {
		if constraintErr := checkEncodedLength(nil, s47bb6e_24, "51.5", "imsi", "SIZE (3..8)", len(v.Imsi)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_imsi, encodeErr_enc_imsi := ber.EncodeOctetString([]byte(v.Imsi))
	if encodeErr_enc_imsi != nil {
		return nil, qualifyBERError(encodeErr_enc_imsi, "imsi", "encoding", true)
	}
	retagged_enc_imsi, tagErr_enc_imsi := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_imsi)
	if tagErr_enc_imsi != nil {
		return nil, qualifyBERError(tagErr_enc_imsi, "imsi", "encoding", true)
	}
	enc_imsi = retagged_enc_imsi
	children = append(children, enc_imsi...)
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
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDEREncodedElement(ext); err != nil {
			return nil, invalidDERAddition(ext, s47bb6e_24, children, i)
		}
		peekTag, _, _, extErr := ber.DecodeEncodedTLV(ext)
		if extErr != nil {
			return nil, extErr
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: only the first addition is restricted.
		if i == 0 && (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1) {
			if constraintErr := ber.CheckEncodedValue(ber.EncodeRule(nil, s47bb6e_24, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
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
		return nil, fmt.Errorf("%s: %w", "encoding ISTCommandArg as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}
func (v *ISTCommandArg) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	encoded, err := v.MarshalDER()
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBER decodes ISTCommandArg from BER/DER format.
func (destination *ISTCommandArg) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if destination == nil {
		return fmt.Errorf("%w: ISTCommandArg destination is nil", ber.ErrInvalidValue)
	}
	v := new(ISTCommandArg)
	defer publishDecodedValue(destination, v, &returnErr)

	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	preparedData, preparedOptions, prepareErr := prepareCompositeBER(data, opts, s47bb6e_24, "child", (*ISTCommandArg).UnmarshalBER)
	if prepareErr != nil {
		return prepareErr
	}
	data, opts = preparedData, preparedOptions

	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
	*v = ISTCommandArg{}
	defer func() {
		if returnErr == nil {
			returnErr = completeValueBER(data,
				opts, v, &v.berReplayNode_, (*ISTCommandArg).MarshalBER)
		}

	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("%s: %w", "decoding ISTCommandArg SEQUENCE", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "ISTCommandArg", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode imsi
	if offset >= len(content) {
		return fmt.Errorf("missing required field imsi")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 0 {
			return fmt.Errorf("expected tag [%s %d] for imsi, got %s", "CONTEXT", 0, reqTag_)
		}
	}
	{
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
		v.Imsi = IMSI(decVal_imsi)
		if offset > len(content) || n_imsi < 0 || n_imsi > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n_imsi
		if len(v.Imsi) < 3 || len(v.Imsi) > 8 {
			if constraintErr := checkDecodedLength(opts, s47bb6e_24, "51.5", "imsi", "SIZE (3..8)", len(v.Imsi)); constraintErr != nil {
				return constraintErr
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
				var dec_extensioncontainer ExtensionContainer
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
			return &ber.DecodeError{Offset: offset, TypeName: "ISTCommandArg", Cause: extErr_}
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: the first unknown addition must differ from trailing OPTIONAL/DEFAULT tags.
		if len(v.ExtData_) == 0 && (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1) {
			if !ber.ToleranceEnabled(opts) {
				return &ber.DecodeError{Offset: offset, TypeName: "ISTCommandArg", Cause: fmt.Errorf("%w: repeated or out-of-order SEQUENCE component tag %s", ber.ErrInvalidTag, peekTag)}
			}
			if orderErr_ := ber.CheckDecodedValue(ber.DecodeRule(opts, s47bb6e_24, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), fmt.Sprintf("ExtData_[%d]", len(v.ExtData_)), "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); orderErr_ != nil {
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

// MarshalBER encodes ISTCommandRes to BER format.
func (v *ISTCommandRes) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {

	if v == nil {
		return nil, fmt.Errorf("%w: ISTCommandRes receiver is nil", ber.ErrInvalidValue)
	}
	return marshalFramedValue(v, v.berReplayNode_, opts, (*ISTCommandRes).MarshalBER, (*ISTCommandRes).marshalBER, 3)

}
func (v *ISTCommandRes) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
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
	base_ := -1
	for i, ext := range v.ExtData_ {
		if err := checkOpaqueAddition(ext, opts, s47bb6e_25, children, i, &base_); err != nil {
			return nil, opaqueExtensionError(err, i)
		}
		peekTag, n, _, extErr := ber.DecodeEncodedTLV(ext)
		if extErr != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, extErr)
		}
		if n != len(ext) {
			return nil, fmt.Errorf("encoding extension %d: %w", i, ber.ErrExtraData)
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: only the first addition is restricted.
		if i == 0 && (peekTag.Class == tag.ClassUniversal && peekTag.Number == 16) {
			if constraintErr := ber.CheckEncodedValue(ber.EncodeRule(opts, s47bb6e_25, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
				return nil, constraintErr
			}
		}
		children = append(children, ext...)
	}
	ber.RecordGeneratedBERContainer(opts, children)
	return ber.EncodeSequence(children)
}
func (v *ISTCommandRes) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// MarshalDER encodes ISTCommandRes to DER format.
// Opaque descendants pass generic DER checks; foreign schema rules need a typed binding.
func (v *ISTCommandRes) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: ISTCommandRes receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalDER()
		if err != nil {
			return nil, qualifyBERError(err, "extensionContainer", "encoding", true)
		}
		children = append(children, enc_extensioncontainer...)
	}
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDEREncodedElement(ext); err != nil {
			return nil, invalidDERAddition(ext, s47bb6e_25, children, i)
		}
		peekTag, _, _, extErr := ber.DecodeEncodedTLV(ext)
		if extErr != nil {
			return nil, extErr
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: only the first addition is restricted.
		if i == 0 && (peekTag.Class == tag.ClassUniversal && peekTag.Number == 16) {
			if constraintErr := ber.CheckEncodedValue(ber.EncodeRule(nil, s47bb6e_25, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
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
		return nil, fmt.Errorf("%s: %w", "encoding ISTCommandRes as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}
func (v *ISTCommandRes) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	encoded, err := v.MarshalDER()
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBER decodes ISTCommandRes from BER/DER format.
func (destination *ISTCommandRes) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if destination == nil {
		return fmt.Errorf("%w: ISTCommandRes destination is nil", ber.ErrInvalidValue)
	}
	v := new(ISTCommandRes)
	defer publishDecodedValue(destination, v, &returnErr)

	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	preparedData, preparedOptions, prepareErr := prepareCompositeBER(data, opts, s47bb6e_25, "child", (*ISTCommandRes).UnmarshalBER)
	if prepareErr != nil {
		return prepareErr
	}
	data, opts = preparedData, preparedOptions

	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
	*v = ISTCommandRes{}
	defer func() {
		if returnErr == nil {
			returnErr = completeValueBER(data,
				opts, v, &v.berReplayNode_, (*ISTCommandRes).MarshalBER)
		}

	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("%s: %w", "decoding ISTCommandRes SEQUENCE", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "ISTCommandRes", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode extensionContainer
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassUniversal && peekTag.Number == 16 {
				ber.MarkPreflightTarget(opts, "extensionContainer", content[offset:])
				// Decode nested SEQUENCE (ExtensionContainer)
				_, n_extensioncontainer, _, tlvErr_extensioncontainer := ber.DecodeTLV(content[offset:], opts...)
				if tlvErr_extensioncontainer != nil {
					return qualifyBERError(tlvErr_extensioncontainer, "extensionContainer", "decoding", false)
				}
				var dec_extensioncontainer ExtensionContainer
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
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		peekTag, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:], opts...)
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "ISTCommandRes", Cause: extErr_}
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: the first unknown addition must differ from trailing OPTIONAL/DEFAULT tags.
		if len(v.ExtData_) == 0 && (peekTag.Class == tag.ClassUniversal && peekTag.Number == 16) {
			if !ber.ToleranceEnabled(opts) {
				return &ber.DecodeError{Offset: offset, TypeName: "ISTCommandRes", Cause: fmt.Errorf("%w: repeated or out-of-order SEQUENCE component tag %s", ber.ErrInvalidTag, peekTag)}
			}
			if orderErr_ := ber.CheckDecodedValue(ber.DecodeRule(opts, s47bb6e_25, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), fmt.Sprintf("ExtData_[%d]", len(v.ExtData_)), "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); orderErr_ != nil {
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

// MarshalBER encodes ReleaseResourcesArg to BER format.
func (v *ReleaseResourcesArg) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {

	if v == nil {
		return nil, fmt.Errorf("%w: ReleaseResourcesArg receiver is nil", ber.ErrInvalidValue)
	}
	return marshalFramedValue(v, v.berReplayNode_, opts, (*ReleaseResourcesArg).MarshalBER, (*ReleaseResourcesArg).marshalBER, 3)

}
func (v *ReleaseResourcesArg) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if len(v.Msrn) < 1 || len(v.Msrn) > 9 {
		if constraintErr := checkEncodedLength(opts, s47bb6e_26, "51.5", "msrn", "SIZE (1..9)", len(v.Msrn)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	if len(v.Msrn) < 1 || len(v.Msrn) > 20 {
		if constraintErr := checkEncodedLength(opts, s47bb6e_26, "51.5", "msrn", "SIZE (1..20)", len(v.Msrn)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_msrn, encodeErr_enc_msrn := ber.EncodeOctetString([]byte(v.Msrn))
	if encodeErr_enc_msrn != nil {
		return nil, qualifyBERError(encodeErr_enc_msrn, "msrn", "encoding", false)
	}
	children = append(children, enc_msrn...)
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalBER(ber.ChildEncodeOptions(opts, "extensionContainer")...)
		if err != nil {
			return nil, qualifyBERError(err, "extensionContainer", "encoding", false)
		}
		ber.RecordGeneratedBERChildPlacement(opts, len(children), enc_extensioncontainer)
		children = append(children, enc_extensioncontainer...)
	}
	base_ := -1
	for i, ext := range v.ExtData_ {
		if err := checkOpaqueAddition(ext, opts, s47bb6e_26, children, i, &base_); err != nil {
			return nil, opaqueExtensionError(err, i)
		}
		peekTag, n, _, extErr := ber.DecodeEncodedTLV(ext)
		if extErr != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, extErr)
		}
		if n != len(ext) {
			return nil, fmt.Errorf("encoding extension %d: %w", i, ber.ErrExtraData)
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: only the first addition is restricted.
		if i == 0 && (peekTag.Class == tag.ClassUniversal && peekTag.Number == 16) {
			if constraintErr := ber.CheckEncodedValue(ber.EncodeRule(opts, s47bb6e_26, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
				return nil, constraintErr
			}
		}
		children = append(children, ext...)
	}
	ber.RecordGeneratedBERContainer(opts, children)
	return ber.EncodeSequence(children)
}
func (v *ReleaseResourcesArg) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// MarshalDER encodes ReleaseResourcesArg to DER format.
// Opaque descendants pass generic DER checks; foreign schema rules need a typed binding.
func (v *ReleaseResourcesArg) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: ReleaseResourcesArg receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if len(v.Msrn) < 1 || len(v.Msrn) > 9 {
		if constraintErr := checkEncodedLength(nil, s47bb6e_26, "51.5", "msrn", "SIZE (1..9)", len(v.Msrn)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	if len(v.Msrn) < 1 || len(v.Msrn) > 20 {
		if constraintErr := checkEncodedLength(nil, s47bb6e_26, "51.5", "msrn", "SIZE (1..20)", len(v.Msrn)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_msrn, encodeErr_enc_msrn := ber.EncodeOctetString([]byte(v.Msrn))
	if encodeErr_enc_msrn != nil {
		return nil, qualifyBERError(encodeErr_enc_msrn, "msrn", "encoding", true)
	}
	children = append(children, enc_msrn...)
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalDER()
		if err != nil {
			return nil, qualifyBERError(err, "extensionContainer", "encoding", true)
		}
		children = append(children, enc_extensioncontainer...)
	}
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDEREncodedElement(ext); err != nil {
			return nil, invalidDERAddition(ext, s47bb6e_26, children, i)
		}
		peekTag, _, _, extErr := ber.DecodeEncodedTLV(ext)
		if extErr != nil {
			return nil, extErr
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: only the first addition is restricted.
		if i == 0 && (peekTag.Class == tag.ClassUniversal && peekTag.Number == 16) {
			if constraintErr := ber.CheckEncodedValue(ber.EncodeRule(nil, s47bb6e_26, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
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
		return nil, fmt.Errorf("%s: %w", "encoding ReleaseResourcesArg as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}
func (v *ReleaseResourcesArg) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	encoded, err := v.MarshalDER()
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBER decodes ReleaseResourcesArg from BER/DER format.
func (destination *ReleaseResourcesArg) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if destination == nil {
		return fmt.Errorf("%w: ReleaseResourcesArg destination is nil", ber.ErrInvalidValue)
	}
	v := new(ReleaseResourcesArg)

	defer publishDecodedValue(destination, v, &returnErr)

	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	preparedData, preparedOptions, prepareErr := prepareCompositeBER(data, opts, s47bb6e_26, "child", (*ReleaseResourcesArg).UnmarshalBER)
	if prepareErr != nil {
		return prepareErr
	}
	data, opts = preparedData, preparedOptions

	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
	*v = ReleaseResourcesArg{}
	defer func() {
		if returnErr == nil {
			returnErr = completeValueBER(data,
				opts, v, &v.berReplayNode_, (*ReleaseResourcesArg).MarshalBER)
		}

	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("%s: %w", "decoding ReleaseResourcesArg SEQUENCE", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "ReleaseResourcesArg", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode msrn
	if offset >= len(content) {
		return fmt.Errorf("missing required field msrn")
	}
	{
		ber.MarkPreflightTarget(opts, "msrn", content[offset:])
		val_msrn, n, err := ber.DecodeOctetString(content[offset:], opts...)
		if err != nil {
			return qualifyBERError(err, "msrn", "decoding", false)
		}
		v.Msrn = ISDNAddressString(val_msrn)
		if offset > len(content) || n < 0 || n > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n
		if len(v.Msrn) < 1 || len(v.Msrn) > 9 {
			if constraintErr := checkDecodedLength(opts, s47bb6e_26, "51.5", "msrn", "SIZE (1..9)", len(v.Msrn)); constraintErr != nil {
				return constraintErr
			}
		}
		if len(v.Msrn) < 1 || len(v.Msrn) > 20 {
			if constraintErr := checkDecodedLength(opts, s47bb6e_26, "51.5", "msrn", "SIZE (1..20)", len(v.Msrn)); constraintErr != nil {
				return constraintErr
			}
		}
	}
	// Decode extensionContainer
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassUniversal && peekTag.Number == 16 {
				ber.MarkPreflightTarget(opts, "extensionContainer", content[offset:])
				// Decode nested SEQUENCE (ExtensionContainer)
				_, n_extensioncontainer, _, tlvErr_extensioncontainer := ber.DecodeTLV(content[offset:], opts...)
				if tlvErr_extensioncontainer != nil {
					return qualifyBERError(tlvErr_extensioncontainer, "extensionContainer", "decoding", false)
				}
				var dec_extensioncontainer ExtensionContainer
				if offset < 0 || offset >
					len(content) || n_extensioncontainer < 0 || n_extensioncontainer >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				if unmErr := dec_extensioncontainer.UnmarshalBER(content[offset:offset+n_extensioncontainer], ber.ChildDecodeOptions(opts, "extensionContainer")...); unmErr != nil {
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
			return &ber.DecodeError{Offset: offset, TypeName: "ReleaseResourcesArg", Cause: extErr_}
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: the first unknown addition must differ from trailing OPTIONAL/DEFAULT tags.
		if len(v.ExtData_) == 0 && (peekTag.Class == tag.ClassUniversal && peekTag.Number == 16) {
			if !ber.ToleranceEnabled(opts) {
				return &ber.DecodeError{Offset: offset, TypeName: "ReleaseResourcesArg", Cause: fmt.Errorf("%w: repeated or out-of-order SEQUENCE component tag %s", ber.ErrInvalidTag, peekTag)}
			}
			if orderErr_ := ber.CheckDecodedValue(ber.DecodeRule(opts, s47bb6e_26, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), fmt.Sprintf("ExtData_[%d]", len(v.ExtData_)), "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); orderErr_ != nil {
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

// MarshalBER encodes ReleaseResourcesRes to BER format.
func (v *ReleaseResourcesRes) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {

	if v == nil {
		return nil, fmt.Errorf("%w: ReleaseResourcesRes receiver is nil", ber.ErrInvalidValue)
	}
	return marshalFramedValue(v, v.berReplayNode_, opts, (*ReleaseResourcesRes).MarshalBER, (*ReleaseResourcesRes).marshalBER, 3)

}
func (v *ReleaseResourcesRes) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
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
	base_ := -1
	for i, ext := range v.ExtData_ {
		if err := checkOpaqueAddition(ext, opts, s47bb6e_27, children, i, &base_); err != nil {
			return nil, opaqueExtensionError(err, i)
		}
		peekTag, n, _, extErr := ber.DecodeEncodedTLV(ext)
		if extErr != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, extErr)
		}
		if n != len(ext) {
			return nil, fmt.Errorf("encoding extension %d: %w", i, ber.ErrExtraData)
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: only the first addition is restricted.
		if i == 0 && (peekTag.Class == tag.ClassUniversal && peekTag.Number == 16) {
			if constraintErr := ber.CheckEncodedValue(ber.EncodeRule(opts, s47bb6e_27, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
				return nil, constraintErr
			}
		}
		children = append(children, ext...)
	}
	ber.RecordGeneratedBERContainer(opts, children)
	return ber.EncodeSequence(children)
}
func (v *ReleaseResourcesRes) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// MarshalDER encodes ReleaseResourcesRes to DER format.
// Opaque descendants pass generic DER checks; foreign schema rules need a typed binding.
func (v *ReleaseResourcesRes) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: ReleaseResourcesRes receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalDER()
		if err != nil {
			return nil, qualifyBERError(err, "extensionContainer", "encoding", true)
		}
		children = append(children, enc_extensioncontainer...)
	}
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDEREncodedElement(ext); err != nil {
			return nil, invalidDERAddition(ext, s47bb6e_27, children, i)
		}
		peekTag, _, _, extErr := ber.DecodeEncodedTLV(ext)
		if extErr != nil {
			return nil, extErr
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: only the first addition is restricted.
		if i == 0 && (peekTag.Class == tag.ClassUniversal && peekTag.Number == 16) {
			if constraintErr := ber.CheckEncodedValue(ber.EncodeRule(nil, s47bb6e_27, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
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
		return nil, fmt.Errorf("%s: %w", "encoding ReleaseResourcesRes as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}
func (v *ReleaseResourcesRes) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	encoded, err := v.MarshalDER()
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBER decodes ReleaseResourcesRes from BER/DER format.
func (destination *ReleaseResourcesRes) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if destination == nil {
		return fmt.Errorf("%w: ReleaseResourcesRes destination is nil", ber.ErrInvalidValue)
	}
	v := new(ReleaseResourcesRes)

	defer publishDecodedValue(destination, v, &returnErr)

	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	preparedData, preparedOptions, prepareErr := prepareCompositeBER(data, opts, s47bb6e_27, "child", (*ReleaseResourcesRes).UnmarshalBER)
	if prepareErr != nil {
		return prepareErr
	}
	data, opts = preparedData, preparedOptions

	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
	*v = ReleaseResourcesRes{}
	defer func() {
		if returnErr == nil {
			returnErr = completeValueBER(data,
				opts, v, &v.berReplayNode_, (*ReleaseResourcesRes).MarshalBER)
		}

	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("%s: %w", "decoding ReleaseResourcesRes SEQUENCE", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "ReleaseResourcesRes", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode extensionContainer
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassUniversal && peekTag.Number == 16 {
				ber.MarkPreflightTarget(opts, "extensionContainer", content[offset:])
				// Decode nested SEQUENCE (ExtensionContainer)
				_, n_extensioncontainer, _, tlvErr_extensioncontainer := ber.DecodeTLV(content[offset:], opts...)
				if tlvErr_extensioncontainer != nil {
					return qualifyBERError(tlvErr_extensioncontainer, "extensionContainer", "decoding", false)
				}
				var dec_extensioncontainer ExtensionContainer
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
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		peekTag, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:], opts...)
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "ReleaseResourcesRes", Cause: extErr_}
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: the first unknown addition must differ from trailing OPTIONAL/DEFAULT tags.
		if len(v.ExtData_) == 0 && (peekTag.Class == tag.ClassUniversal && peekTag.Number == 16) {
			if !ber.ToleranceEnabled(opts) {
				return &ber.DecodeError{Offset: offset, TypeName: "ReleaseResourcesRes", Cause: fmt.Errorf("%w: repeated or out-of-order SEQUENCE component tag %s", ber.ErrInvalidTag, peekTag)}
			}
			if orderErr_ := ber.CheckDecodedValue(ber.DecodeRule(opts, s47bb6e_27, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), fmt.Sprintf("ExtData_[%d]", len(v.ExtData_)), "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); orderErr_ != nil {
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

const (
	s47bb6e_0  = "MAP-CH-DataTypes.CUG-CheckInfo"
	s47bb6e_1  = "MAP-CH-DataTypes.SendRoutingInfoArg"
	s47bb6e_2  = "MAP-CH-DataTypes.SendRoutingInfoRes"
	s47bb6e_3  = "MAP-CH-DataTypes.CCBS-Indicators"
	s47bb6e_4  = "MAP-CH-DataTypes.RoutingInfo"
	s47bb6e_5  = "MAP-CH-DataTypes.ForwardingData"
	s47bb6e_6  = "MAP-CH-DataTypes.ProvideRoamingNumberArg"
	s47bb6e_7  = "MAP-CH-DataTypes.ProvideRoamingNumberRes"
	s47bb6e_8  = "MAP-CH-DataTypes.ResumeCallHandlingArg"
	s47bb6e_9  = "MAP-CH-DataTypes.UU-Data"
	s47bb6e_10 = "MAP-CH-DataTypes.ResumeCallHandlingRes"
	s47bb6e_11 = "MAP-CH-DataTypes.CamelInfo"
	s47bb6e_12 = "MAP-CH-DataTypes.CamelRoutingInfo"
	s47bb6e_13 = "MAP-CH-DataTypes.GmscCamelSubscriptionInfo"
	s47bb6e_14 = "MAP-CH-DataTypes.SetReportingStateArg"
	s47bb6e_15 = "MAP-CH-DataTypes.SetReportingStateRes"
	s47bb6e_16 = "MAP-CH-DataTypes.StatusReportArg"
	s47bb6e_17 = "MAP-CH-DataTypes.EventReportData"
	s47bb6e_18 = "MAP-CH-DataTypes.CallReportData"
	s47bb6e_19 = "MAP-CH-DataTypes.StatusReportRes"
	s47bb6e_20 = "MAP-CH-DataTypes.RemoteUserFreeArg"
	s47bb6e_21 = "MAP-CH-DataTypes.RemoteUserFreeRes"
	s47bb6e_22 = "MAP-CH-DataTypes.IST-AlertArg"
	s47bb6e_23 = "MAP-CH-DataTypes.IST-AlertRes"
	s47bb6e_24 = "MAP-CH-DataTypes.IST-CommandArg"
	s47bb6e_25 = "MAP-CH-DataTypes.IST-CommandRes"
	s47bb6e_26 = "MAP-CH-DataTypes.ReleaseResourcesArg"
	s47bb6e_27 = "MAP-CH-DataTypes.ReleaseResourcesRes"
)
