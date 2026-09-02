// Code generated from ASN.1 module "MAP-CH-DataTypes". DO NOT EDIT.

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

// CUGCheckInfo represents the ASN.1 type CUG-CheckInfo (SEQUENCE).
type CUGCheckInfo struct {
	CugInterlock       CUGInterlock        `asn1:""`
	CugOutgoingAccess  *struct{}           `asn1:",optional" json:"CugOutgoingAccess,omitempty"`
	ExtensionContainer *ExtensionContainer `asn1:",optional" json:"ExtensionContainer,omitempty"`
	ExtCount_          int64               `asn1:"-" json:"-"`
	ExtPresent_        []bool              `asn1:"-" json:"-"`
	ExtData_           [][]byte            `asn1:"-" json:"-"`
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
	ExtData_                        [][]byte                         `asn1:"-" json:"-"`
}

// SuppressionOfAnnouncement represents the ASN.1 type SuppressionOfAnnouncement (NULL).
type SuppressionOfAnnouncement = struct{}

// SuppressMTSS represents the ASN.1 type SuppressMTSS (BIT_STRING).
type SuppressMTSS = runtime.BitString

// InterrogationType represents the ASN.1 ENUMERATED type InterrogationType.
type InterrogationType int64

const (
	InterrogationTypeBasicCall  InterrogationType = 0
	InterrogationTypeForwarding InterrogationType = 1
)

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
	SsList                          SSList                   `asn1:"tag:1,context,implicit,optional" json:"SsList,omitempty"`
	SsListIndef_                    bool                     `asn1:"-" json:"-"`
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
	SsList2                         SSList                   `asn1:"tag:18,context,implicit,optional" json:"SsList2,omitempty"`
	SsList2Indef_                   bool                     `asn1:"-" json:"-"`
	BasicService2                   *ExtBasicServiceCode     `asn1:"tag:19,context,explicit,optional" json:"BasicService2,omitempty"`
	AllowedServices                 *AllowedServices         `asn1:"tag:20,context,implicit,optional" json:"AllowedServices,omitempty"`
	UnavailabilityCause             *UnavailabilityCause     `asn1:"tag:21,context,implicit,optional" json:"UnavailabilityCause,omitempty"`
	ReleaseResourcesSupported       *struct{}                `asn1:"tag:22,context,implicit,optional" json:"ReleaseResourcesSupported,omitempty"`
	GsmBearerCapability             *ExternalSignalInfo      `asn1:"tag:23,context,implicit,optional" json:"GsmBearerCapability,omitempty"`
	ExtCount_                       int64                    `asn1:"-" json:"-"`
	ExtPresent_                     []bool                   `asn1:"-" json:"-"`
	ExtData_                        [][]byte                 `asn1:"-" json:"-"`
}

// AllowedServices represents the ASN.1 type AllowedServices (BIT_STRING).
type AllowedServices = runtime.BitString

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
	ExtData_              [][]byte            `asn1:"-" json:"-"`
}

// RoutingInfo choice constants.
const (
	RoutingInfoChoiceRoamingNumber  = 1
	RoutingInfoChoiceForwardingData = 2
)

// RoutingInfo represents the ASN.1 CHOICE type RoutingInfo.
type RoutingInfo struct {
	Choice         int
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
	ExtData_              [][]byte              `asn1:"-" json:"-"`
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
	PagingArea                              PagingArea                 `asn1:"tag:22,context,implicit,optional" json:"PagingArea,omitempty"`
	PagingAreaIndef_                        bool                       `asn1:"-" json:"-"`
	CallPriority                            *EMLPPPriority             `asn1:"tag:23,context,implicit,optional" json:"CallPriority,omitempty"`
	MtrfIndicator                           *struct{}                  `asn1:"tag:24,context,implicit,optional" json:"MtrfIndicator,omitempty"`
	OldMSCNumber                            *ISDNAddressString         `asn1:"tag:25,context,implicit,optional" json:"OldMSCNumber,omitempty"`
	LastUsedLtePLMNId                       *PLMNId                    `asn1:"tag:26,context,implicit,optional" json:"LastUsedLtePLMNId,omitempty"`
	ExtCount_                               int64                      `asn1:"-" json:"-"`
	ExtPresent_                             []bool                     `asn1:"-" json:"-"`
	ExtData_                                [][]byte                   `asn1:"-" json:"-"`
}

// ProvideRoamingNumberRes represents the ASN.1 type ProvideRoamingNumberRes (SEQUENCE).
type ProvideRoamingNumberRes struct {
	RoamingNumber             ISDNAddressString   `asn1:""`
	ExtensionContainer        *ExtensionContainer `asn1:",optional" json:"ExtensionContainer,omitempty"`
	ReleaseResourcesSupported *struct{}           `asn1:",optional" json:"ReleaseResourcesSupported,omitempty"`
	VmscAddress               *ISDNAddressString  `asn1:",optional" json:"VmscAddress,omitempty"`
	ExtCount_                 int64               `asn1:"-" json:"-"`
	ExtPresent_               []bool              `asn1:"-" json:"-"`
	ExtData_                  [][]byte            `asn1:"-" json:"-"`
}

// ResumeCallHandlingArg represents the ASN.1 type ResumeCallHandlingArg (SEQUENCE).
type ResumeCallHandlingArg struct {
	CallReferenceNumber             *CallReferenceNumber      `asn1:"tag:0,context,implicit,optional" json:"CallReferenceNumber,omitempty"`
	BasicServiceGroup               *ExtBasicServiceCode      `asn1:"tag:1,context,explicit,optional" json:"BasicServiceGroup,omitempty"`
	ForwardingData                  *ForwardingData           `asn1:"tag:2,context,implicit,optional" json:"ForwardingData,omitempty"`
	Imsi                            *IMSI                     `asn1:"tag:3,context,implicit,optional" json:"Imsi,omitempty"`
	CugCheckInfo                    *CUGCheckInfo             `asn1:"tag:4,context,implicit,optional" json:"CugCheckInfo,omitempty"`
	OCSI                            *OCSI                     `asn1:"tag:5,context,implicit,optional" json:"OCSI,omitempty"`
	ExtensionContainer              *ExtensionContainer       `asn1:"tag:7,context,implicit,optional" json:"ExtensionContainer,omitempty"`
	CcbsPossible                    *struct{}                 `asn1:"tag:8,context,implicit,optional" json:"CcbsPossible,omitempty"`
	Msisdn                          *ISDNAddressString        `asn1:"tag:9,context,implicit,optional" json:"Msisdn,omitempty"`
	UuData                          *UUData                   `asn1:"tag:10,context,implicit,optional" json:"UuData,omitempty"`
	AllInformationSent              *struct{}                 `asn1:"tag:11,context,implicit,optional" json:"AllInformationSent,omitempty"`
	DCsi                            *DCSI                     `asn1:"tag:12,context,implicit,optional" json:"DCsi,omitempty"`
	OBcsmCamelTDPCriteriaList       OBcsmCamelTDPCriteriaList `asn1:"tag:13,context,implicit,optional" json:"OBcsmCamelTDPCriteriaList,omitempty"`
	OBcsmCamelTDPCriteriaListIndef_ bool                      `asn1:"-" json:"-"`
	BasicServiceGroup2              *ExtBasicServiceCode      `asn1:"tag:14,context,explicit,optional" json:"BasicServiceGroup2,omitempty"`
	MtRoamingRetry                  *struct{}                 `asn1:"tag:15,context,implicit,optional" json:"MtRoamingRetry,omitempty"`
	ExtCount_                       int64                     `asn1:"-" json:"-"`
	ExtPresent_                     []bool                    `asn1:"-" json:"-"`
	ExtData_                        [][]byte                  `asn1:"-" json:"-"`
}

// UUData represents the ASN.1 type UU-Data (SEQUENCE).
type UUData struct {
	UuIndicator        *UUIndicator        `asn1:"tag:0,context,implicit,optional" json:"UuIndicator,omitempty"`
	Uui                *UUI                `asn1:"tag:1,context,implicit,optional" json:"Uui,omitempty"`
	UusCFInteraction   *struct{}           `asn1:"tag:2,context,implicit,optional" json:"UusCFInteraction,omitempty"`
	ExtensionContainer *ExtensionContainer `asn1:"tag:3,context,implicit,optional" json:"ExtensionContainer,omitempty"`
	ExtCount_          int64               `asn1:"-" json:"-"`
	ExtPresent_        []bool              `asn1:"-" json:"-"`
	ExtData_           [][]byte            `asn1:"-" json:"-"`
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
	ExtData_           [][]byte            `asn1:"-" json:"-"`
}

// CamelInfo represents the ASN.1 type CamelInfo (SEQUENCE).
type CamelInfo struct {
	SupportedCamelPhases SupportedCamelPhases `asn1:""`
	SuppressTCSI         *struct{}            `asn1:",optional" json:"SuppressTCSI,omitempty"`
	ExtensionContainer   *ExtensionContainer  `asn1:",optional" json:"ExtensionContainer,omitempty"`
	OfferedCamel4CSIs    *OfferedCamel4CSIs   `asn1:"tag:0,context,implicit,optional" json:"OfferedCamel4CSIs,omitempty"`
	ExtCount_            int64                `asn1:"-" json:"-"`
	ExtPresent_          []bool               `asn1:"-" json:"-"`
	ExtData_             [][]byte             `asn1:"-" json:"-"`
}

// ExtendedRoutingInfo choice constants.
const (
	ExtendedRoutingInfoChoiceRoutingInfo      = 1
	ExtendedRoutingInfoChoiceCamelRoutingInfo = 2
)

// ExtendedRoutingInfo represents the ASN.1 CHOICE type ExtendedRoutingInfo.
type ExtendedRoutingInfo struct {
	Choice           int
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
	ExtData_                  [][]byte                  `asn1:"-" json:"-"`
}

// GmscCamelSubscriptionInfo represents the ASN.1 type GmscCamelSubscriptionInfo (SEQUENCE).
type GmscCamelSubscriptionInfo struct {
	TCSI                            *TCSI                     `asn1:"tag:0,context,implicit,optional" json:"TCSI,omitempty"`
	OCSI                            *OCSI                     `asn1:"tag:1,context,implicit,optional" json:"OCSI,omitempty"`
	ExtensionContainer              *ExtensionContainer       `asn1:"tag:2,context,implicit,optional" json:"ExtensionContainer,omitempty"`
	OBcsmCamelTDPCriteriaList       OBcsmCamelTDPCriteriaList `asn1:"tag:3,context,implicit,optional" json:"OBcsmCamelTDPCriteriaList,omitempty"`
	OBcsmCamelTDPCriteriaListIndef_ bool                      `asn1:"-" json:"-"`
	TBCSMCAMELTDPCriteriaList       TBCSMCAMELTDPCriteriaList `asn1:"tag:4,context,implicit,optional" json:"TBCSMCAMELTDPCriteriaList,omitempty"`
	TBCSMCAMELTDPCriteriaListIndef_ bool                      `asn1:"-" json:"-"`
	DCsi                            *DCSI                     `asn1:"tag:5,context,implicit,optional" json:"DCsi,omitempty"`
	ExtCount_                       int64                     `asn1:"-" json:"-"`
	ExtPresent_                     []bool                    `asn1:"-" json:"-"`
	ExtData_                        [][]byte                  `asn1:"-" json:"-"`
}

// SetReportingStateArg represents the ASN.1 type SetReportingStateArg (SEQUENCE).
type SetReportingStateArg struct {
	Imsi               *IMSI               `asn1:"tag:0,context,implicit,optional" json:"Imsi,omitempty"`
	Lmsi               *LMSI               `asn1:"tag:1,context,implicit,optional" json:"Lmsi,omitempty"`
	CcbsMonitoring     *ReportingState     `asn1:"tag:2,context,implicit,optional" json:"CcbsMonitoring,omitempty"`
	ExtensionContainer *ExtensionContainer `asn1:"tag:3,context,implicit,optional" json:"ExtensionContainer,omitempty"`
	ExtCount_          int64               `asn1:"-" json:"-"`
	ExtPresent_        []bool              `asn1:"-" json:"-"`
	ExtData_           [][]byte            `asn1:"-" json:"-"`
}

// ReportingState represents the ASN.1 ENUMERATED type ReportingState.
type ReportingState int64

const (
	ReportingStateStopMonitoring  ReportingState = 0
	ReportingStateStartMonitoring ReportingState = 1
)

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
	ExtData_             [][]byte              `asn1:"-" json:"-"`
}

// CCBSSubscriberStatus represents the ASN.1 ENUMERATED type CCBS-SubscriberStatus.
type CCBSSubscriberStatus int64

const (
	CCBSSubscriberStatusCcbsNotIdle      CCBSSubscriberStatus = 0
	CCBSSubscriberStatusCcbsIdle         CCBSSubscriberStatus = 1
	CCBSSubscriberStatusCcbsNotReachable CCBSSubscriberStatus = 2
)

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
	ExtData_           [][]byte            `asn1:"-" json:"-"`
}

// EventReportData represents the ASN.1 type EventReportData (SEQUENCE).
type EventReportData struct {
	CcbsSubscriberStatus *CCBSSubscriberStatus `asn1:"tag:0,context,implicit,optional" json:"CcbsSubscriberStatus,omitempty"`
	ExtensionContainer   *ExtensionContainer   `asn1:"tag:1,context,implicit,optional" json:"ExtensionContainer,omitempty"`
	ExtCount_            int64                 `asn1:"-" json:"-"`
	ExtPresent_          []bool                `asn1:"-" json:"-"`
	ExtData_             [][]byte              `asn1:"-" json:"-"`
}

// CallReportData represents the ASN.1 type CallReportData (SEQUENCE).
type CallReportData struct {
	MonitoringMode     *MonitoringMode     `asn1:"tag:0,context,implicit,optional" json:"MonitoringMode,omitempty"`
	CallOutcome        *CallOutcome        `asn1:"tag:1,context,implicit,optional" json:"CallOutcome,omitempty"`
	ExtensionContainer *ExtensionContainer `asn1:"tag:2,context,implicit,optional" json:"ExtensionContainer,omitempty"`
	ExtCount_          int64               `asn1:"-" json:"-"`
	ExtPresent_        []bool              `asn1:"-" json:"-"`
	ExtData_           [][]byte            `asn1:"-" json:"-"`
}

// MonitoringMode represents the ASN.1 ENUMERATED type MonitoringMode.
type MonitoringMode int64

const (
	MonitoringModeASide MonitoringMode = 0
	MonitoringModeBSide MonitoringMode = 1
)

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
	ExtData_           [][]byte            `asn1:"-" json:"-"`
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
	ExtData_           [][]byte            `asn1:"-" json:"-"`
}

// RemoteUserFreeRes represents the ASN.1 type RemoteUserFreeRes (SEQUENCE).
type RemoteUserFreeRes struct {
	RufOutcome         RUFOutcome          `asn1:"tag:0,context,implicit"`
	ExtensionContainer *ExtensionContainer `asn1:"tag:1,context,implicit,optional" json:"ExtensionContainer,omitempty"`
	ExtCount_          int64               `asn1:"-" json:"-"`
	ExtPresent_        []bool              `asn1:"-" json:"-"`
	ExtData_           [][]byte            `asn1:"-" json:"-"`
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
	ExtData_           [][]byte            `asn1:"-" json:"-"`
}

// ISTAlertRes represents the ASN.1 type IST-AlertRes (SEQUENCE).
type ISTAlertRes struct {
	IstAlertTimer            *ISTAlertTimerValue       `asn1:"tag:0,context,implicit,optional" json:"IstAlertTimer,omitempty"`
	IstInformationWithdraw   *struct{}                 `asn1:"tag:1,context,implicit,optional" json:"IstInformationWithdraw,omitempty"`
	CallTerminationIndicator *CallTerminationIndicator `asn1:"tag:2,context,implicit,optional" json:"CallTerminationIndicator,omitempty"`
	ExtensionContainer       *ExtensionContainer       `asn1:"tag:3,context,implicit,optional" json:"ExtensionContainer,omitempty"`
	ExtCount_                int64                     `asn1:"-" json:"-"`
	ExtPresent_              []bool                    `asn1:"-" json:"-"`
	ExtData_                 [][]byte                  `asn1:"-" json:"-"`
}

// ISTCommandArg represents the ASN.1 type IST-CommandArg (SEQUENCE).
type ISTCommandArg struct {
	Imsi               IMSI                `asn1:"tag:0,context,implicit"`
	ExtensionContainer *ExtensionContainer `asn1:"tag:1,context,implicit,optional" json:"ExtensionContainer,omitempty"`
	ExtCount_          int64               `asn1:"-" json:"-"`
	ExtPresent_        []bool              `asn1:"-" json:"-"`
	ExtData_           [][]byte            `asn1:"-" json:"-"`
}

// ISTCommandRes represents the ASN.1 type IST-CommandRes (SEQUENCE).
type ISTCommandRes struct {
	ExtensionContainer *ExtensionContainer `asn1:",optional" json:"ExtensionContainer,omitempty"`
	ExtCount_          int64               `asn1:"-" json:"-"`
	ExtPresent_        []bool              `asn1:"-" json:"-"`
	ExtData_           [][]byte            `asn1:"-" json:"-"`
}

// CallTerminationIndicator represents the ASN.1 ENUMERATED type CallTerminationIndicator.
type CallTerminationIndicator int64

const (
	CallTerminationIndicatorTerminateCallActivityReferred CallTerminationIndicator = 0
	CallTerminationIndicatorTerminateAllCallActivities    CallTerminationIndicator = 1
)

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
	ExtData_           [][]byte            `asn1:"-" json:"-"`
}

// ReleaseResourcesRes represents the ASN.1 type ReleaseResourcesRes (SEQUENCE).
type ReleaseResourcesRes struct {
	ExtensionContainer *ExtensionContainer `asn1:",optional" json:"ExtensionContainer,omitempty"`
	ExtCount_          int64               `asn1:"-" json:"-"`
	ExtPresent_        []bool              `asn1:"-" json:"-"`
	ExtData_           [][]byte            `asn1:"-" json:"-"`
}

// MarshalBER encodes CUGCheckInfo to BER format.
func (v *CUGCheckInfo) MarshalBER() ([]byte, error) {
	var children []byte
	enc_cuginterlock := ber.EncodeOctetString([]byte(v.CugInterlock))
	children = append(children, enc_cuginterlock...)
	if v.CugOutgoingAccess != nil {
		enc_cugoutgoingaccess := ber.EncodeNull()
		children = append(children, enc_cugoutgoingaccess...)
	}
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding extensionContainer: %w", err)
		}
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

// MarshalDER encodes CUGCheckInfo to DER format.
func (v *CUGCheckInfo) MarshalDER() ([]byte, error) {
	var children []byte
	enc_cuginterlock := ber.EncodeOctetString([]byte(v.CugInterlock))
	children = append(children, enc_cuginterlock...)
	if v.CugOutgoingAccess != nil {
		enc_cugoutgoingaccess := ber.EncodeNull()
		children = append(children, enc_cugoutgoingaccess...)
	}
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding extensionContainer: %w", err)
		}
		children = append(children, enc_extensioncontainer...)
	}
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
		children = append(children, ext...)
	}
	encoded := ber.EncodeSequence(children)
	if err := ber.ValidateDERElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding CUGCheckInfo as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes CUGCheckInfo from BER/DER format.
func (v *CUGCheckInfo) UnmarshalBER(data []byte) error {
	*v = CUGCheckInfo{}
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding CUGCheckInfo SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "CUGCheckInfo", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode cug-Interlock
	if offset >= len(content) {
		return fmt.Errorf("missing required field cug-Interlock")
	}
	val_cuginterlock, n, err := ber.DecodeOctetString(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding cug-Interlock: %w", err)
	}
	v.CugInterlock = CUGInterlock(val_cuginterlock)
	offset += n
	// Decode cug-OutgoingAccess
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassUniversal && peekTag.Number == 5 {
				n, err := ber.DecodeNull(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding cug-OutgoingAccess: %w", err)
				}
				v.CugOutgoingAccess = &struct{}{}
				offset += n
			}
		}
	}
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
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "CUGCheckInfo", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes SendRoutingInfoArg to BER format.
func (v *SendRoutingInfoArg) MarshalBER() ([]byte, error) {
	var children []byte
	enc_msisdn := ber.EncodeOctetString([]byte(v.Msisdn))
	retagged_enc_msisdn, tagErr_enc_msisdn := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_msisdn)
	if tagErr_enc_msisdn != nil {
		return nil, fmt.Errorf("encoding msisdn: %w", tagErr_enc_msisdn)
	}
	enc_msisdn = retagged_enc_msisdn
	children = append(children, enc_msisdn...)
	if v.CugCheckInfo != nil {
		enc_cugcheckinfo, err := v.CugCheckInfo.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding cug-CheckInfo: %w", err)
		}
		retagged_enc_cugcheckinfo, tagErr_enc_cugcheckinfo := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_cugcheckinfo)
		if tagErr_enc_cugcheckinfo != nil {
			return nil, fmt.Errorf("encoding cug-CheckInfo: %w", tagErr_enc_cugcheckinfo)
		}
		enc_cugcheckinfo = retagged_enc_cugcheckinfo
		children = append(children, enc_cugcheckinfo...)
	}
	if v.NumberOfForwarding != nil {
		enc_numberofforwarding := ber.EncodeInteger(int64(*v.NumberOfForwarding))
		retagged_enc_numberofforwarding, tagErr_enc_numberofforwarding := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_numberofforwarding)
		if tagErr_enc_numberofforwarding != nil {
			return nil, fmt.Errorf("encoding numberOfForwarding: %w", tagErr_enc_numberofforwarding)
		}
		enc_numberofforwarding = retagged_enc_numberofforwarding
		children = append(children, enc_numberofforwarding...)
	}
	enc_interrogationtype := ber.EncodeEnumerated(int64(v.InterrogationType))
	retagged_enc_interrogationtype, tagErr_enc_interrogationtype := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, enc_interrogationtype)
	if tagErr_enc_interrogationtype != nil {
		return nil, fmt.Errorf("encoding interrogationType: %w", tagErr_enc_interrogationtype)
	}
	enc_interrogationtype = retagged_enc_interrogationtype
	children = append(children, enc_interrogationtype...)
	if v.OrInterrogation != nil {
		enc_orinterrogation := ber.EncodeNull()
		retagged_enc_orinterrogation, tagErr_enc_orinterrogation := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, enc_orinterrogation)
		if tagErr_enc_orinterrogation != nil {
			return nil, fmt.Errorf("encoding or-Interrogation: %w", tagErr_enc_orinterrogation)
		}
		enc_orinterrogation = retagged_enc_orinterrogation
		children = append(children, enc_orinterrogation...)
	}
	if v.OrCapability != nil {
		enc_orcapability := ber.EncodeInteger(int64(*v.OrCapability))
		retagged_enc_orcapability, tagErr_enc_orcapability := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 5, enc_orcapability)
		if tagErr_enc_orcapability != nil {
			return nil, fmt.Errorf("encoding or-Capability: %w", tagErr_enc_orcapability)
		}
		enc_orcapability = retagged_enc_orcapability
		children = append(children, enc_orcapability...)
	}
	enc_gmscorgsmscfaddress := ber.EncodeOctetString([]byte(v.GmscOrGsmSCFAddress))
	retagged_enc_gmscorgsmscfaddress, tagErr_enc_gmscorgsmscfaddress := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 6, enc_gmscorgsmscfaddress)
	if tagErr_enc_gmscorgsmscfaddress != nil {
		return nil, fmt.Errorf("encoding gmsc-OrGsmSCF-Address: %w", tagErr_enc_gmscorgsmscfaddress)
	}
	enc_gmscorgsmscfaddress = retagged_enc_gmscorgsmscfaddress
	children = append(children, enc_gmscorgsmscfaddress...)
	if v.CallReferenceNumber != nil {
		enc_callreferencenumber := ber.EncodeOctetString([]byte(*v.CallReferenceNumber))
		retagged_enc_callreferencenumber, tagErr_enc_callreferencenumber := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 7, enc_callreferencenumber)
		if tagErr_enc_callreferencenumber != nil {
			return nil, fmt.Errorf("encoding callReferenceNumber: %w", tagErr_enc_callreferencenumber)
		}
		enc_callreferencenumber = retagged_enc_callreferencenumber
		children = append(children, enc_callreferencenumber...)
	}
	if v.ForwardingReason != nil {
		enc_forwardingreason := ber.EncodeEnumerated(int64(*v.ForwardingReason))
		retagged_enc_forwardingreason, tagErr_enc_forwardingreason := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 8, enc_forwardingreason)
		if tagErr_enc_forwardingreason != nil {
			return nil, fmt.Errorf("encoding forwardingReason: %w", tagErr_enc_forwardingreason)
		}
		enc_forwardingreason = retagged_enc_forwardingreason
		children = append(children, enc_forwardingreason...)
	}
	if v.BasicServiceGroup != nil {
		enc_basicservicegroup, err := v.BasicServiceGroup.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding basicServiceGroup: %w", err)
		}
		enc_basicservicegroup = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 9, enc_basicservicegroup)
		children = append(children, enc_basicservicegroup...)
	}
	if v.NetworkSignalInfo != nil {
		enc_networksignalinfo, err := v.NetworkSignalInfo.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding networkSignalInfo: %w", err)
		}
		retagged_enc_networksignalinfo, tagErr_enc_networksignalinfo := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 10, enc_networksignalinfo)
		if tagErr_enc_networksignalinfo != nil {
			return nil, fmt.Errorf("encoding networkSignalInfo: %w", tagErr_enc_networksignalinfo)
		}
		enc_networksignalinfo = retagged_enc_networksignalinfo
		children = append(children, enc_networksignalinfo...)
	}
	if v.CamelInfo != nil {
		enc_camelinfo, err := v.CamelInfo.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding camelInfo: %w", err)
		}
		retagged_enc_camelinfo, tagErr_enc_camelinfo := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 11, enc_camelinfo)
		if tagErr_enc_camelinfo != nil {
			return nil, fmt.Errorf("encoding camelInfo: %w", tagErr_enc_camelinfo)
		}
		enc_camelinfo = retagged_enc_camelinfo
		children = append(children, enc_camelinfo...)
	}
	if v.SuppressionOfAnnouncement != nil {
		enc_suppressionofannouncement := ber.EncodeNull()
		retagged_enc_suppressionofannouncement, tagErr_enc_suppressionofannouncement := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 12, enc_suppressionofannouncement)
		if tagErr_enc_suppressionofannouncement != nil {
			return nil, fmt.Errorf("encoding suppressionOfAnnouncement: %w", tagErr_enc_suppressionofannouncement)
		}
		enc_suppressionofannouncement = retagged_enc_suppressionofannouncement
		children = append(children, enc_suppressionofannouncement...)
	}
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding extensionContainer: %w", err)
		}
		retagged_enc_extensioncontainer, tagErr_enc_extensioncontainer := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 13, enc_extensioncontainer)
		if tagErr_enc_extensioncontainer != nil {
			return nil, fmt.Errorf("encoding extensionContainer: %w", tagErr_enc_extensioncontainer)
		}
		enc_extensioncontainer = retagged_enc_extensioncontainer
		children = append(children, enc_extensioncontainer...)
	}
	if v.AlertingPattern != nil {
		enc_alertingpattern := ber.EncodeOctetString([]byte(*v.AlertingPattern))
		retagged_enc_alertingpattern, tagErr_enc_alertingpattern := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 14, enc_alertingpattern)
		if tagErr_enc_alertingpattern != nil {
			return nil, fmt.Errorf("encoding alertingPattern: %w", tagErr_enc_alertingpattern)
		}
		enc_alertingpattern = retagged_enc_alertingpattern
		children = append(children, enc_alertingpattern...)
	}
	if v.CcbsCall != nil {
		enc_ccbscall := ber.EncodeNull()
		retagged_enc_ccbscall, tagErr_enc_ccbscall := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 15, enc_ccbscall)
		if tagErr_enc_ccbscall != nil {
			return nil, fmt.Errorf("encoding ccbs-Call: %w", tagErr_enc_ccbscall)
		}
		enc_ccbscall = retagged_enc_ccbscall
		children = append(children, enc_ccbscall...)
	}
	if v.SupportedCCBSPhase != nil {
		enc_supportedccbsphase := ber.EncodeInteger(int64(*v.SupportedCCBSPhase))
		retagged_enc_supportedccbsphase, tagErr_enc_supportedccbsphase := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 16, enc_supportedccbsphase)
		if tagErr_enc_supportedccbsphase != nil {
			return nil, fmt.Errorf("encoding supportedCCBS-Phase: %w", tagErr_enc_supportedccbsphase)
		}
		enc_supportedccbsphase = retagged_enc_supportedccbsphase
		children = append(children, enc_supportedccbsphase...)
	}
	if v.AdditionalSignalInfo != nil {
		enc_additionalsignalinfo, err := v.AdditionalSignalInfo.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding additionalSignalInfo: %w", err)
		}
		retagged_enc_additionalsignalinfo, tagErr_enc_additionalsignalinfo := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 17, enc_additionalsignalinfo)
		if tagErr_enc_additionalsignalinfo != nil {
			return nil, fmt.Errorf("encoding additionalSignalInfo: %w", tagErr_enc_additionalsignalinfo)
		}
		enc_additionalsignalinfo = retagged_enc_additionalsignalinfo
		children = append(children, enc_additionalsignalinfo...)
	}
	if v.IstSupportIndicator != nil {
		enc_istsupportindicator := ber.EncodeEnumerated(int64(*v.IstSupportIndicator))
		retagged_enc_istsupportindicator, tagErr_enc_istsupportindicator := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 18, enc_istsupportindicator)
		if tagErr_enc_istsupportindicator != nil {
			return nil, fmt.Errorf("encoding istSupportIndicator: %w", tagErr_enc_istsupportindicator)
		}
		enc_istsupportindicator = retagged_enc_istsupportindicator
		children = append(children, enc_istsupportindicator...)
	}
	if v.PrePagingSupported != nil {
		enc_prepagingsupported := ber.EncodeNull()
		retagged_enc_prepagingsupported, tagErr_enc_prepagingsupported := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 19, enc_prepagingsupported)
		if tagErr_enc_prepagingsupported != nil {
			return nil, fmt.Errorf("encoding pre-pagingSupported: %w", tagErr_enc_prepagingsupported)
		}
		enc_prepagingsupported = retagged_enc_prepagingsupported
		children = append(children, enc_prepagingsupported...)
	}
	if v.CallDiversionTreatmentIndicator != nil {
		enc_calldiversiontreatmentindicator := ber.EncodeOctetString([]byte(*v.CallDiversionTreatmentIndicator))
		retagged_enc_calldiversiontreatmentindicator, tagErr_enc_calldiversiontreatmentindicator := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 20, enc_calldiversiontreatmentindicator)
		if tagErr_enc_calldiversiontreatmentindicator != nil {
			return nil, fmt.Errorf("encoding callDiversionTreatmentIndicator: %w", tagErr_enc_calldiversiontreatmentindicator)
		}
		enc_calldiversiontreatmentindicator = retagged_enc_calldiversiontreatmentindicator
		children = append(children, enc_calldiversiontreatmentindicator...)
	}
	if v.LongFTNSupported != nil {
		enc_longftnsupported := ber.EncodeNull()
		retagged_enc_longftnsupported, tagErr_enc_longftnsupported := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 21, enc_longftnsupported)
		if tagErr_enc_longftnsupported != nil {
			return nil, fmt.Errorf("encoding longFTN-Supported: %w", tagErr_enc_longftnsupported)
		}
		enc_longftnsupported = retagged_enc_longftnsupported
		children = append(children, enc_longftnsupported...)
	}
	if v.SuppressVTCSI != nil {
		enc_suppressvtcsi := ber.EncodeNull()
		retagged_enc_suppressvtcsi, tagErr_enc_suppressvtcsi := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 22, enc_suppressvtcsi)
		if tagErr_enc_suppressvtcsi != nil {
			return nil, fmt.Errorf("encoding suppress-VT-CSI: %w", tagErr_enc_suppressvtcsi)
		}
		enc_suppressvtcsi = retagged_enc_suppressvtcsi
		children = append(children, enc_suppressvtcsi...)
	}
	if v.SuppressIncomingCallBarring != nil {
		enc_suppressincomingcallbarring := ber.EncodeNull()
		retagged_enc_suppressincomingcallbarring, tagErr_enc_suppressincomingcallbarring := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 23, enc_suppressincomingcallbarring)
		if tagErr_enc_suppressincomingcallbarring != nil {
			return nil, fmt.Errorf("encoding suppressIncomingCallBarring: %w", tagErr_enc_suppressincomingcallbarring)
		}
		enc_suppressincomingcallbarring = retagged_enc_suppressincomingcallbarring
		children = append(children, enc_suppressincomingcallbarring...)
	}
	if v.GsmSCFInitiatedCall != nil {
		enc_gsmscfinitiatedcall := ber.EncodeNull()
		retagged_enc_gsmscfinitiatedcall, tagErr_enc_gsmscfinitiatedcall := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 24, enc_gsmscfinitiatedcall)
		if tagErr_enc_gsmscfinitiatedcall != nil {
			return nil, fmt.Errorf("encoding gsmSCF-InitiatedCall: %w", tagErr_enc_gsmscfinitiatedcall)
		}
		enc_gsmscfinitiatedcall = retagged_enc_gsmscfinitiatedcall
		children = append(children, enc_gsmscfinitiatedcall...)
	}
	if v.BasicServiceGroup2 != nil {
		enc_basicservicegroup2, err := v.BasicServiceGroup2.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding basicServiceGroup2: %w", err)
		}
		enc_basicservicegroup2 = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 25, enc_basicservicegroup2)
		children = append(children, enc_basicservicegroup2...)
	}
	if v.NetworkSignalInfo2 != nil {
		enc_networksignalinfo2, err := v.NetworkSignalInfo2.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding networkSignalInfo2: %w", err)
		}
		retagged_enc_networksignalinfo2, tagErr_enc_networksignalinfo2 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 26, enc_networksignalinfo2)
		if tagErr_enc_networksignalinfo2 != nil {
			return nil, fmt.Errorf("encoding networkSignalInfo2: %w", tagErr_enc_networksignalinfo2)
		}
		enc_networksignalinfo2 = retagged_enc_networksignalinfo2
		children = append(children, enc_networksignalinfo2...)
	}
	if v.SuppressMTSS != nil {
		enc_suppressmtss := ber.EncodeBitString(v.SuppressMTSS.Bytes, (8-(v.SuppressMTSS.BitLength%8))%8)
		retagged_enc_suppressmtss, tagErr_enc_suppressmtss := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 27, enc_suppressmtss)
		if tagErr_enc_suppressmtss != nil {
			return nil, fmt.Errorf("encoding suppressMTSS: %w", tagErr_enc_suppressmtss)
		}
		enc_suppressmtss = retagged_enc_suppressmtss
		children = append(children, enc_suppressmtss...)
	}
	if v.MtRoamingRetrySupported != nil {
		enc_mtroamingretrysupported := ber.EncodeNull()
		retagged_enc_mtroamingretrysupported, tagErr_enc_mtroamingretrysupported := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 28, enc_mtroamingretrysupported)
		if tagErr_enc_mtroamingretrysupported != nil {
			return nil, fmt.Errorf("encoding mtRoamingRetrySupported: %w", tagErr_enc_mtroamingretrysupported)
		}
		enc_mtroamingretrysupported = retagged_enc_mtroamingretrysupported
		children = append(children, enc_mtroamingretrysupported...)
	}
	if v.CallPriority != nil {
		enc_callpriority := ber.EncodeInteger(int64(*v.CallPriority))
		retagged_enc_callpriority, tagErr_enc_callpriority := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 29, enc_callpriority)
		if tagErr_enc_callpriority != nil {
			return nil, fmt.Errorf("encoding callPriority: %w", tagErr_enc_callpriority)
		}
		enc_callpriority = retagged_enc_callpriority
		children = append(children, enc_callpriority...)
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

// MarshalDER encodes SendRoutingInfoArg to DER format.
func (v *SendRoutingInfoArg) MarshalDER() ([]byte, error) {
	var children []byte
	enc_msisdn := ber.EncodeOctetString([]byte(v.Msisdn))
	retagged_enc_msisdn, tagErr_enc_msisdn := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_msisdn)
	if tagErr_enc_msisdn != nil {
		return nil, fmt.Errorf("encoding msisdn: %w", tagErr_enc_msisdn)
	}
	enc_msisdn = retagged_enc_msisdn
	children = append(children, enc_msisdn...)
	if v.CugCheckInfo != nil {
		enc_cugcheckinfo, err := v.CugCheckInfo.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding cug-CheckInfo: %w", err)
		}
		retagged_enc_cugcheckinfo, tagErr_enc_cugcheckinfo := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_cugcheckinfo)
		if tagErr_enc_cugcheckinfo != nil {
			return nil, fmt.Errorf("encoding cug-CheckInfo: %w", tagErr_enc_cugcheckinfo)
		}
		enc_cugcheckinfo = retagged_enc_cugcheckinfo
		children = append(children, enc_cugcheckinfo...)
	}
	if v.NumberOfForwarding != nil {
		enc_numberofforwarding := ber.EncodeInteger(int64(*v.NumberOfForwarding))
		retagged_enc_numberofforwarding, tagErr_enc_numberofforwarding := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_numberofforwarding)
		if tagErr_enc_numberofforwarding != nil {
			return nil, fmt.Errorf("encoding numberOfForwarding: %w", tagErr_enc_numberofforwarding)
		}
		enc_numberofforwarding = retagged_enc_numberofforwarding
		children = append(children, enc_numberofforwarding...)
	}
	enc_interrogationtype := ber.EncodeEnumerated(int64(v.InterrogationType))
	retagged_enc_interrogationtype, tagErr_enc_interrogationtype := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, enc_interrogationtype)
	if tagErr_enc_interrogationtype != nil {
		return nil, fmt.Errorf("encoding interrogationType: %w", tagErr_enc_interrogationtype)
	}
	enc_interrogationtype = retagged_enc_interrogationtype
	children = append(children, enc_interrogationtype...)
	if v.OrInterrogation != nil {
		enc_orinterrogation := ber.EncodeNull()
		retagged_enc_orinterrogation, tagErr_enc_orinterrogation := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, enc_orinterrogation)
		if tagErr_enc_orinterrogation != nil {
			return nil, fmt.Errorf("encoding or-Interrogation: %w", tagErr_enc_orinterrogation)
		}
		enc_orinterrogation = retagged_enc_orinterrogation
		children = append(children, enc_orinterrogation...)
	}
	if v.OrCapability != nil {
		enc_orcapability := ber.EncodeInteger(int64(*v.OrCapability))
		retagged_enc_orcapability, tagErr_enc_orcapability := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 5, enc_orcapability)
		if tagErr_enc_orcapability != nil {
			return nil, fmt.Errorf("encoding or-Capability: %w", tagErr_enc_orcapability)
		}
		enc_orcapability = retagged_enc_orcapability
		children = append(children, enc_orcapability...)
	}
	enc_gmscorgsmscfaddress := ber.EncodeOctetString([]byte(v.GmscOrGsmSCFAddress))
	retagged_enc_gmscorgsmscfaddress, tagErr_enc_gmscorgsmscfaddress := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 6, enc_gmscorgsmscfaddress)
	if tagErr_enc_gmscorgsmscfaddress != nil {
		return nil, fmt.Errorf("encoding gmsc-OrGsmSCF-Address: %w", tagErr_enc_gmscorgsmscfaddress)
	}
	enc_gmscorgsmscfaddress = retagged_enc_gmscorgsmscfaddress
	children = append(children, enc_gmscorgsmscfaddress...)
	if v.CallReferenceNumber != nil {
		enc_callreferencenumber := ber.EncodeOctetString([]byte(*v.CallReferenceNumber))
		retagged_enc_callreferencenumber, tagErr_enc_callreferencenumber := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 7, enc_callreferencenumber)
		if tagErr_enc_callreferencenumber != nil {
			return nil, fmt.Errorf("encoding callReferenceNumber: %w", tagErr_enc_callreferencenumber)
		}
		enc_callreferencenumber = retagged_enc_callreferencenumber
		children = append(children, enc_callreferencenumber...)
	}
	if v.ForwardingReason != nil {
		enc_forwardingreason := ber.EncodeEnumerated(int64(*v.ForwardingReason))
		retagged_enc_forwardingreason, tagErr_enc_forwardingreason := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 8, enc_forwardingreason)
		if tagErr_enc_forwardingreason != nil {
			return nil, fmt.Errorf("encoding forwardingReason: %w", tagErr_enc_forwardingreason)
		}
		enc_forwardingreason = retagged_enc_forwardingreason
		children = append(children, enc_forwardingreason...)
	}
	if v.BasicServiceGroup != nil {
		enc_basicservicegroup, err := v.BasicServiceGroup.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding basicServiceGroup: %w", err)
		}
		enc_basicservicegroup = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 9, enc_basicservicegroup)
		children = append(children, enc_basicservicegroup...)
	}
	if v.NetworkSignalInfo != nil {
		enc_networksignalinfo, err := v.NetworkSignalInfo.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding networkSignalInfo: %w", err)
		}
		retagged_enc_networksignalinfo, tagErr_enc_networksignalinfo := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 10, enc_networksignalinfo)
		if tagErr_enc_networksignalinfo != nil {
			return nil, fmt.Errorf("encoding networkSignalInfo: %w", tagErr_enc_networksignalinfo)
		}
		enc_networksignalinfo = retagged_enc_networksignalinfo
		children = append(children, enc_networksignalinfo...)
	}
	if v.CamelInfo != nil {
		enc_camelinfo, err := v.CamelInfo.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding camelInfo: %w", err)
		}
		retagged_enc_camelinfo, tagErr_enc_camelinfo := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 11, enc_camelinfo)
		if tagErr_enc_camelinfo != nil {
			return nil, fmt.Errorf("encoding camelInfo: %w", tagErr_enc_camelinfo)
		}
		enc_camelinfo = retagged_enc_camelinfo
		children = append(children, enc_camelinfo...)
	}
	if v.SuppressionOfAnnouncement != nil {
		enc_suppressionofannouncement := ber.EncodeNull()
		retagged_enc_suppressionofannouncement, tagErr_enc_suppressionofannouncement := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 12, enc_suppressionofannouncement)
		if tagErr_enc_suppressionofannouncement != nil {
			return nil, fmt.Errorf("encoding suppressionOfAnnouncement: %w", tagErr_enc_suppressionofannouncement)
		}
		enc_suppressionofannouncement = retagged_enc_suppressionofannouncement
		children = append(children, enc_suppressionofannouncement...)
	}
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding extensionContainer: %w", err)
		}
		retagged_enc_extensioncontainer, tagErr_enc_extensioncontainer := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 13, enc_extensioncontainer)
		if tagErr_enc_extensioncontainer != nil {
			return nil, fmt.Errorf("encoding extensionContainer: %w", tagErr_enc_extensioncontainer)
		}
		enc_extensioncontainer = retagged_enc_extensioncontainer
		children = append(children, enc_extensioncontainer...)
	}
	if v.AlertingPattern != nil {
		enc_alertingpattern := ber.EncodeOctetString([]byte(*v.AlertingPattern))
		retagged_enc_alertingpattern, tagErr_enc_alertingpattern := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 14, enc_alertingpattern)
		if tagErr_enc_alertingpattern != nil {
			return nil, fmt.Errorf("encoding alertingPattern: %w", tagErr_enc_alertingpattern)
		}
		enc_alertingpattern = retagged_enc_alertingpattern
		children = append(children, enc_alertingpattern...)
	}
	if v.CcbsCall != nil {
		enc_ccbscall := ber.EncodeNull()
		retagged_enc_ccbscall, tagErr_enc_ccbscall := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 15, enc_ccbscall)
		if tagErr_enc_ccbscall != nil {
			return nil, fmt.Errorf("encoding ccbs-Call: %w", tagErr_enc_ccbscall)
		}
		enc_ccbscall = retagged_enc_ccbscall
		children = append(children, enc_ccbscall...)
	}
	if v.SupportedCCBSPhase != nil {
		enc_supportedccbsphase := ber.EncodeInteger(int64(*v.SupportedCCBSPhase))
		retagged_enc_supportedccbsphase, tagErr_enc_supportedccbsphase := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 16, enc_supportedccbsphase)
		if tagErr_enc_supportedccbsphase != nil {
			return nil, fmt.Errorf("encoding supportedCCBS-Phase: %w", tagErr_enc_supportedccbsphase)
		}
		enc_supportedccbsphase = retagged_enc_supportedccbsphase
		children = append(children, enc_supportedccbsphase...)
	}
	if v.AdditionalSignalInfo != nil {
		enc_additionalsignalinfo, err := v.AdditionalSignalInfo.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding additionalSignalInfo: %w", err)
		}
		retagged_enc_additionalsignalinfo, tagErr_enc_additionalsignalinfo := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 17, enc_additionalsignalinfo)
		if tagErr_enc_additionalsignalinfo != nil {
			return nil, fmt.Errorf("encoding additionalSignalInfo: %w", tagErr_enc_additionalsignalinfo)
		}
		enc_additionalsignalinfo = retagged_enc_additionalsignalinfo
		children = append(children, enc_additionalsignalinfo...)
	}
	if v.IstSupportIndicator != nil {
		enc_istsupportindicator := ber.EncodeEnumerated(int64(*v.IstSupportIndicator))
		retagged_enc_istsupportindicator, tagErr_enc_istsupportindicator := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 18, enc_istsupportindicator)
		if tagErr_enc_istsupportindicator != nil {
			return nil, fmt.Errorf("encoding istSupportIndicator: %w", tagErr_enc_istsupportindicator)
		}
		enc_istsupportindicator = retagged_enc_istsupportindicator
		children = append(children, enc_istsupportindicator...)
	}
	if v.PrePagingSupported != nil {
		enc_prepagingsupported := ber.EncodeNull()
		retagged_enc_prepagingsupported, tagErr_enc_prepagingsupported := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 19, enc_prepagingsupported)
		if tagErr_enc_prepagingsupported != nil {
			return nil, fmt.Errorf("encoding pre-pagingSupported: %w", tagErr_enc_prepagingsupported)
		}
		enc_prepagingsupported = retagged_enc_prepagingsupported
		children = append(children, enc_prepagingsupported...)
	}
	if v.CallDiversionTreatmentIndicator != nil {
		enc_calldiversiontreatmentindicator := ber.EncodeOctetString([]byte(*v.CallDiversionTreatmentIndicator))
		retagged_enc_calldiversiontreatmentindicator, tagErr_enc_calldiversiontreatmentindicator := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 20, enc_calldiversiontreatmentindicator)
		if tagErr_enc_calldiversiontreatmentindicator != nil {
			return nil, fmt.Errorf("encoding callDiversionTreatmentIndicator: %w", tagErr_enc_calldiversiontreatmentindicator)
		}
		enc_calldiversiontreatmentindicator = retagged_enc_calldiversiontreatmentindicator
		children = append(children, enc_calldiversiontreatmentindicator...)
	}
	if v.LongFTNSupported != nil {
		enc_longftnsupported := ber.EncodeNull()
		retagged_enc_longftnsupported, tagErr_enc_longftnsupported := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 21, enc_longftnsupported)
		if tagErr_enc_longftnsupported != nil {
			return nil, fmt.Errorf("encoding longFTN-Supported: %w", tagErr_enc_longftnsupported)
		}
		enc_longftnsupported = retagged_enc_longftnsupported
		children = append(children, enc_longftnsupported...)
	}
	if v.SuppressVTCSI != nil {
		enc_suppressvtcsi := ber.EncodeNull()
		retagged_enc_suppressvtcsi, tagErr_enc_suppressvtcsi := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 22, enc_suppressvtcsi)
		if tagErr_enc_suppressvtcsi != nil {
			return nil, fmt.Errorf("encoding suppress-VT-CSI: %w", tagErr_enc_suppressvtcsi)
		}
		enc_suppressvtcsi = retagged_enc_suppressvtcsi
		children = append(children, enc_suppressvtcsi...)
	}
	if v.SuppressIncomingCallBarring != nil {
		enc_suppressincomingcallbarring := ber.EncodeNull()
		retagged_enc_suppressincomingcallbarring, tagErr_enc_suppressincomingcallbarring := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 23, enc_suppressincomingcallbarring)
		if tagErr_enc_suppressincomingcallbarring != nil {
			return nil, fmt.Errorf("encoding suppressIncomingCallBarring: %w", tagErr_enc_suppressincomingcallbarring)
		}
		enc_suppressincomingcallbarring = retagged_enc_suppressincomingcallbarring
		children = append(children, enc_suppressincomingcallbarring...)
	}
	if v.GsmSCFInitiatedCall != nil {
		enc_gsmscfinitiatedcall := ber.EncodeNull()
		retagged_enc_gsmscfinitiatedcall, tagErr_enc_gsmscfinitiatedcall := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 24, enc_gsmscfinitiatedcall)
		if tagErr_enc_gsmscfinitiatedcall != nil {
			return nil, fmt.Errorf("encoding gsmSCF-InitiatedCall: %w", tagErr_enc_gsmscfinitiatedcall)
		}
		enc_gsmscfinitiatedcall = retagged_enc_gsmscfinitiatedcall
		children = append(children, enc_gsmscfinitiatedcall...)
	}
	if v.BasicServiceGroup2 != nil {
		enc_basicservicegroup2, err := v.BasicServiceGroup2.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding basicServiceGroup2: %w", err)
		}
		enc_basicservicegroup2 = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 25, enc_basicservicegroup2)
		children = append(children, enc_basicservicegroup2...)
	}
	if v.NetworkSignalInfo2 != nil {
		enc_networksignalinfo2, err := v.NetworkSignalInfo2.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding networkSignalInfo2: %w", err)
		}
		retagged_enc_networksignalinfo2, tagErr_enc_networksignalinfo2 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 26, enc_networksignalinfo2)
		if tagErr_enc_networksignalinfo2 != nil {
			return nil, fmt.Errorf("encoding networkSignalInfo2: %w", tagErr_enc_networksignalinfo2)
		}
		enc_networksignalinfo2 = retagged_enc_networksignalinfo2
		children = append(children, enc_networksignalinfo2...)
	}
	if v.SuppressMTSS != nil {
		enc_suppressmtss := ber.EncodeBitString(v.SuppressMTSS.Bytes, (8-(v.SuppressMTSS.BitLength%8))%8)
		retagged_enc_suppressmtss, tagErr_enc_suppressmtss := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 27, enc_suppressmtss)
		if tagErr_enc_suppressmtss != nil {
			return nil, fmt.Errorf("encoding suppressMTSS: %w", tagErr_enc_suppressmtss)
		}
		enc_suppressmtss = retagged_enc_suppressmtss
		children = append(children, enc_suppressmtss...)
	}
	if v.MtRoamingRetrySupported != nil {
		enc_mtroamingretrysupported := ber.EncodeNull()
		retagged_enc_mtroamingretrysupported, tagErr_enc_mtroamingretrysupported := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 28, enc_mtroamingretrysupported)
		if tagErr_enc_mtroamingretrysupported != nil {
			return nil, fmt.Errorf("encoding mtRoamingRetrySupported: %w", tagErr_enc_mtroamingretrysupported)
		}
		enc_mtroamingretrysupported = retagged_enc_mtroamingretrysupported
		children = append(children, enc_mtroamingretrysupported...)
	}
	if v.CallPriority != nil {
		enc_callpriority := ber.EncodeInteger(int64(*v.CallPriority))
		retagged_enc_callpriority, tagErr_enc_callpriority := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 29, enc_callpriority)
		if tagErr_enc_callpriority != nil {
			return nil, fmt.Errorf("encoding callPriority: %w", tagErr_enc_callpriority)
		}
		enc_callpriority = retagged_enc_callpriority
		children = append(children, enc_callpriority...)
	}
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
		children = append(children, ext...)
	}
	encoded := ber.EncodeSequence(children)
	if err := ber.ValidateDERElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding SendRoutingInfoArg as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes SendRoutingInfoArg from BER/DER format.
func (v *SendRoutingInfoArg) UnmarshalBER(data []byte) error {
	*v = SendRoutingInfoArg{}
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding SendRoutingInfoArg SEQUENCE: %w", err)
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
	decodedTag_msisdn, n_msisdn, rawVal_msisdn, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding msisdn: %w", err)
	}
	if decodedTag_msisdn.Class != tag.ClassContextSpecific || decodedTag_msisdn.Number != 0 {
		return fmt.Errorf("decoding msisdn: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_msisdn)
	}
	v.Msisdn = ISDNAddressString(rawVal_msisdn)
	offset += n_msisdn
	// Decode cug-CheckInfo
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
				decodedTag_cugcheckinfo, n_cugcheckinfo, rawVal_cugcheckinfo, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding cug-CheckInfo: %w", err)
				}
				if decodedTag_cugcheckinfo.Class != tag.ClassContextSpecific || decodedTag_cugcheckinfo.Number != 1 || decodedTag_cugcheckinfo.Constructed != true {
					return fmt.Errorf("decoding cug-CheckInfo: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_cugcheckinfo)
				}
				reconstructed_cugcheckinfo := ber.EncodeSequence(rawVal_cugcheckinfo)
				var dec_cugcheckinfo CUGCheckInfo
				if unmErr := dec_cugcheckinfo.UnmarshalBER(reconstructed_cugcheckinfo); unmErr != nil {
					return fmt.Errorf("decoding cug-CheckInfo: %w", unmErr)
				}
				v.CugCheckInfo = &dec_cugcheckinfo
				offset += n_cugcheckinfo
			}
		}
	}
	// Decode numberOfForwarding
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2 {
				decodedTag_numberofforwarding, n_numberofforwarding, rawVal_numberofforwarding, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding numberOfForwarding: %w", err)
				}
				if decodedTag_numberofforwarding.Class != tag.ClassContextSpecific || decodedTag_numberofforwarding.Number != 2 || decodedTag_numberofforwarding.Constructed != false {
					return fmt.Errorf("decoding numberOfForwarding: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_numberofforwarding)
				}
				decVal_numberofforwarding, intErr := ber.DecodeIntegerValue(rawVal_numberofforwarding)
				if intErr != nil {
					return fmt.Errorf("decoding numberOfForwarding: %w", intErr)
				}
				tmp_numberofforwarding := NumberOfForwarding(decVal_numberofforwarding)
				v.NumberOfForwarding = &tmp_numberofforwarding
				offset += n_numberofforwarding
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
	decodedTag_interrogationtype, n_interrogationtype, rawVal_interrogationtype, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding interrogationType: %w", err)
	}
	if decodedTag_interrogationtype.Class != tag.ClassContextSpecific || decodedTag_interrogationtype.Number != 3 || decodedTag_interrogationtype.Constructed != false {
		return fmt.Errorf("decoding interrogationType: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_interrogationtype)
	}
	decVal_interrogationtype, intErr := ber.DecodeEnumeratedValue(rawVal_interrogationtype)
	if intErr != nil {
		return fmt.Errorf("decoding interrogationType: %w", intErr)
	}
	v.InterrogationType = InterrogationType(decVal_interrogationtype)
	offset += n_interrogationtype
	// Decode or-Interrogation
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4 {
				decodedTag_orinterrogation, n_orinterrogation, rawVal_orinterrogation, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding or-Interrogation: %w", err)
				}
				if decodedTag_orinterrogation.Class != tag.ClassContextSpecific || decodedTag_orinterrogation.Number != 4 || decodedTag_orinterrogation.Constructed != false {
					return fmt.Errorf("decoding or-Interrogation: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_orinterrogation)
				}
				if len(rawVal_orinterrogation) != 0 {
					return fmt.Errorf("decoding or-Interrogation: %w: NULL content length %d", ber.ErrInvalidValue, len(rawVal_orinterrogation))
				}
				v.OrInterrogation = &struct{}{}
				offset += n_orinterrogation
			}
		}
	}
	// Decode or-Capability
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 5 {
				decodedTag_orcapability, n_orcapability, rawVal_orcapability, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding or-Capability: %w", err)
				}
				if decodedTag_orcapability.Class != tag.ClassContextSpecific || decodedTag_orcapability.Number != 5 || decodedTag_orcapability.Constructed != false {
					return fmt.Errorf("decoding or-Capability: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_orcapability)
				}
				decVal_orcapability, intErr := ber.DecodeIntegerValue(rawVal_orcapability)
				if intErr != nil {
					return fmt.Errorf("decoding or-Capability: %w", intErr)
				}
				tmp_orcapability := ORPhase(decVal_orcapability)
				v.OrCapability = &tmp_orcapability
				offset += n_orcapability
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
	decodedTag_gmscorgsmscfaddress, n_gmscorgsmscfaddress, rawVal_gmscorgsmscfaddress, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding gmsc-OrGsmSCF-Address: %w", err)
	}
	if decodedTag_gmscorgsmscfaddress.Class != tag.ClassContextSpecific || decodedTag_gmscorgsmscfaddress.Number != 6 {
		return fmt.Errorf("decoding gmsc-OrGsmSCF-Address: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_gmscorgsmscfaddress)
	}
	v.GmscOrGsmSCFAddress = ISDNAddressString(rawVal_gmscorgsmscfaddress)
	offset += n_gmscorgsmscfaddress
	// Decode callReferenceNumber
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 7 {
				decodedTag_callreferencenumber, n_callreferencenumber, rawVal_callreferencenumber, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding callReferenceNumber: %w", err)
				}
				if decodedTag_callreferencenumber.Class != tag.ClassContextSpecific || decodedTag_callreferencenumber.Number != 7 {
					return fmt.Errorf("decoding callReferenceNumber: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_callreferencenumber)
				}
				tmp_callreferencenumber := CallReferenceNumber(rawVal_callreferencenumber)
				v.CallReferenceNumber = &tmp_callreferencenumber
				offset += n_callreferencenumber
			}
		}
	}
	// Decode forwardingReason
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 8 {
				decodedTag_forwardingreason, n_forwardingreason, rawVal_forwardingreason, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding forwardingReason: %w", err)
				}
				if decodedTag_forwardingreason.Class != tag.ClassContextSpecific || decodedTag_forwardingreason.Number != 8 || decodedTag_forwardingreason.Constructed != false {
					return fmt.Errorf("decoding forwardingReason: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_forwardingreason)
				}
				decVal_forwardingreason, intErr := ber.DecodeEnumeratedValue(rawVal_forwardingreason)
				if intErr != nil {
					return fmt.Errorf("decoding forwardingReason: %w", intErr)
				}
				tmp_forwardingreason := ForwardingReason(decVal_forwardingreason)
				v.ForwardingReason = &tmp_forwardingreason
				offset += n_forwardingreason
			}
		}
	}
	// Decode basicServiceGroup
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 9 {
				decodedTag_basicservicegroup, n_basicservicegroup, innerData_basicservicegroup, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding basicServiceGroup: %w", err)
				}
				if decodedTag_basicservicegroup.Class != tag.ClassContextSpecific || decodedTag_basicservicegroup.Number != 9 || decodedTag_basicservicegroup.Constructed != true {
					return fmt.Errorf("decoding basicServiceGroup: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_basicservicegroup)
				}
				// Decode inner value from explicit tag wrapper
				var dec_basicservicegroup ExtBasicServiceCode
				if unmErr := dec_basicservicegroup.UnmarshalBER(innerData_basicservicegroup); unmErr != nil {
					return fmt.Errorf("decoding basicServiceGroup: %w", unmErr)
				}
				v.BasicServiceGroup = &dec_basicservicegroup
				offset += n_basicservicegroup
			}
		}
	}
	// Decode networkSignalInfo
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 10 {
				decodedTag_networksignalinfo, n_networksignalinfo, rawVal_networksignalinfo, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding networkSignalInfo: %w", err)
				}
				if decodedTag_networksignalinfo.Class != tag.ClassContextSpecific || decodedTag_networksignalinfo.Number != 10 || decodedTag_networksignalinfo.Constructed != true {
					return fmt.Errorf("decoding networkSignalInfo: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_networksignalinfo)
				}
				reconstructed_networksignalinfo := ber.EncodeSequence(rawVal_networksignalinfo)
				var dec_networksignalinfo ExternalSignalInfo
				if unmErr := dec_networksignalinfo.UnmarshalBER(reconstructed_networksignalinfo); unmErr != nil {
					return fmt.Errorf("decoding networkSignalInfo: %w", unmErr)
				}
				v.NetworkSignalInfo = &dec_networksignalinfo
				offset += n_networksignalinfo
			}
		}
	}
	// Decode camelInfo
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 11 {
				decodedTag_camelinfo, n_camelinfo, rawVal_camelinfo, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding camelInfo: %w", err)
				}
				if decodedTag_camelinfo.Class != tag.ClassContextSpecific || decodedTag_camelinfo.Number != 11 || decodedTag_camelinfo.Constructed != true {
					return fmt.Errorf("decoding camelInfo: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_camelinfo)
				}
				reconstructed_camelinfo := ber.EncodeSequence(rawVal_camelinfo)
				var dec_camelinfo CamelInfo
				if unmErr := dec_camelinfo.UnmarshalBER(reconstructed_camelinfo); unmErr != nil {
					return fmt.Errorf("decoding camelInfo: %w", unmErr)
				}
				v.CamelInfo = &dec_camelinfo
				offset += n_camelinfo
			}
		}
	}
	// Decode suppressionOfAnnouncement
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 12 {
				decodedTag_suppressionofannouncement, n_suppressionofannouncement, rawVal_suppressionofannouncement, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding suppressionOfAnnouncement: %w", err)
				}
				if decodedTag_suppressionofannouncement.Class != tag.ClassContextSpecific || decodedTag_suppressionofannouncement.Number != 12 || decodedTag_suppressionofannouncement.Constructed != false {
					return fmt.Errorf("decoding suppressionOfAnnouncement: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_suppressionofannouncement)
				}
				if len(rawVal_suppressionofannouncement) != 0 {
					return fmt.Errorf("decoding suppressionOfAnnouncement: %w: NULL content length %d", ber.ErrInvalidValue, len(rawVal_suppressionofannouncement))
				}
				v.SuppressionOfAnnouncement = &struct{}{}
				offset += n_suppressionofannouncement
			}
		}
	}
	// Decode extensionContainer
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 13 {
				decodedTag_extensioncontainer, n_extensioncontainer, rawVal_extensioncontainer, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding extensionContainer: %w", err)
				}
				if decodedTag_extensioncontainer.Class != tag.ClassContextSpecific || decodedTag_extensioncontainer.Number != 13 || decodedTag_extensioncontainer.Constructed != true {
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
	// Decode alertingPattern
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 14 {
				decodedTag_alertingpattern, n_alertingpattern, rawVal_alertingpattern, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding alertingPattern: %w", err)
				}
				if decodedTag_alertingpattern.Class != tag.ClassContextSpecific || decodedTag_alertingpattern.Number != 14 {
					return fmt.Errorf("decoding alertingPattern: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_alertingpattern)
				}
				tmp_alertingpattern := AlertingPattern(rawVal_alertingpattern)
				v.AlertingPattern = &tmp_alertingpattern
				offset += n_alertingpattern
			}
		}
	}
	// Decode ccbs-Call
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 15 {
				decodedTag_ccbscall, n_ccbscall, rawVal_ccbscall, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding ccbs-Call: %w", err)
				}
				if decodedTag_ccbscall.Class != tag.ClassContextSpecific || decodedTag_ccbscall.Number != 15 || decodedTag_ccbscall.Constructed != false {
					return fmt.Errorf("decoding ccbs-Call: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_ccbscall)
				}
				if len(rawVal_ccbscall) != 0 {
					return fmt.Errorf("decoding ccbs-Call: %w: NULL content length %d", ber.ErrInvalidValue, len(rawVal_ccbscall))
				}
				v.CcbsCall = &struct{}{}
				offset += n_ccbscall
			}
		}
	}
	// Decode supportedCCBS-Phase
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 16 {
				decodedTag_supportedccbsphase, n_supportedccbsphase, rawVal_supportedccbsphase, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding supportedCCBS-Phase: %w", err)
				}
				if decodedTag_supportedccbsphase.Class != tag.ClassContextSpecific || decodedTag_supportedccbsphase.Number != 16 || decodedTag_supportedccbsphase.Constructed != false {
					return fmt.Errorf("decoding supportedCCBS-Phase: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_supportedccbsphase)
				}
				decVal_supportedccbsphase, intErr := ber.DecodeIntegerValue(rawVal_supportedccbsphase)
				if intErr != nil {
					return fmt.Errorf("decoding supportedCCBS-Phase: %w", intErr)
				}
				tmp_supportedccbsphase := SupportedCCBSPhase(decVal_supportedccbsphase)
				v.SupportedCCBSPhase = &tmp_supportedccbsphase
				offset += n_supportedccbsphase
			}
		}
	}
	// Decode additionalSignalInfo
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 17 {
				decodedTag_additionalsignalinfo, n_additionalsignalinfo, rawVal_additionalsignalinfo, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding additionalSignalInfo: %w", err)
				}
				if decodedTag_additionalsignalinfo.Class != tag.ClassContextSpecific || decodedTag_additionalsignalinfo.Number != 17 || decodedTag_additionalsignalinfo.Constructed != true {
					return fmt.Errorf("decoding additionalSignalInfo: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_additionalsignalinfo)
				}
				reconstructed_additionalsignalinfo := ber.EncodeSequence(rawVal_additionalsignalinfo)
				var dec_additionalsignalinfo ExtExternalSignalInfo
				if unmErr := dec_additionalsignalinfo.UnmarshalBER(reconstructed_additionalsignalinfo); unmErr != nil {
					return fmt.Errorf("decoding additionalSignalInfo: %w", unmErr)
				}
				v.AdditionalSignalInfo = &dec_additionalsignalinfo
				offset += n_additionalsignalinfo
			}
		}
	}
	// Decode istSupportIndicator
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 18 {
				decodedTag_istsupportindicator, n_istsupportindicator, rawVal_istsupportindicator, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding istSupportIndicator: %w", err)
				}
				if decodedTag_istsupportindicator.Class != tag.ClassContextSpecific || decodedTag_istsupportindicator.Number != 18 || decodedTag_istsupportindicator.Constructed != false {
					return fmt.Errorf("decoding istSupportIndicator: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_istsupportindicator)
				}
				decVal_istsupportindicator, intErr := ber.DecodeEnumeratedValue(rawVal_istsupportindicator)
				if intErr != nil {
					return fmt.Errorf("decoding istSupportIndicator: %w", intErr)
				}
				tmp_istsupportindicator := ISTSupportIndicator(decVal_istsupportindicator)
				v.IstSupportIndicator = &tmp_istsupportindicator
				offset += n_istsupportindicator
			}
		}
	}
	// Decode pre-pagingSupported
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 19 {
				decodedTag_prepagingsupported, n_prepagingsupported, rawVal_prepagingsupported, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding pre-pagingSupported: %w", err)
				}
				if decodedTag_prepagingsupported.Class != tag.ClassContextSpecific || decodedTag_prepagingsupported.Number != 19 || decodedTag_prepagingsupported.Constructed != false {
					return fmt.Errorf("decoding pre-pagingSupported: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_prepagingsupported)
				}
				if len(rawVal_prepagingsupported) != 0 {
					return fmt.Errorf("decoding pre-pagingSupported: %w: NULL content length %d", ber.ErrInvalidValue, len(rawVal_prepagingsupported))
				}
				v.PrePagingSupported = &struct{}{}
				offset += n_prepagingsupported
			}
		}
	}
	// Decode callDiversionTreatmentIndicator
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 20 {
				decodedTag_calldiversiontreatmentindicator, n_calldiversiontreatmentindicator, rawVal_calldiversiontreatmentindicator, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding callDiversionTreatmentIndicator: %w", err)
				}
				if decodedTag_calldiversiontreatmentindicator.Class != tag.ClassContextSpecific || decodedTag_calldiversiontreatmentindicator.Number != 20 {
					return fmt.Errorf("decoding callDiversionTreatmentIndicator: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_calldiversiontreatmentindicator)
				}
				tmp_calldiversiontreatmentindicator := CallDiversionTreatmentIndicator(rawVal_calldiversiontreatmentindicator)
				v.CallDiversionTreatmentIndicator = &tmp_calldiversiontreatmentindicator
				offset += n_calldiversiontreatmentindicator
			}
		}
	}
	// Decode longFTN-Supported
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 21 {
				decodedTag_longftnsupported, n_longftnsupported, rawVal_longftnsupported, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding longFTN-Supported: %w", err)
				}
				if decodedTag_longftnsupported.Class != tag.ClassContextSpecific || decodedTag_longftnsupported.Number != 21 || decodedTag_longftnsupported.Constructed != false {
					return fmt.Errorf("decoding longFTN-Supported: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_longftnsupported)
				}
				if len(rawVal_longftnsupported) != 0 {
					return fmt.Errorf("decoding longFTN-Supported: %w: NULL content length %d", ber.ErrInvalidValue, len(rawVal_longftnsupported))
				}
				v.LongFTNSupported = &struct{}{}
				offset += n_longftnsupported
			}
		}
	}
	// Decode suppress-VT-CSI
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 22 {
				decodedTag_suppressvtcsi, n_suppressvtcsi, rawVal_suppressvtcsi, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding suppress-VT-CSI: %w", err)
				}
				if decodedTag_suppressvtcsi.Class != tag.ClassContextSpecific || decodedTag_suppressvtcsi.Number != 22 || decodedTag_suppressvtcsi.Constructed != false {
					return fmt.Errorf("decoding suppress-VT-CSI: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_suppressvtcsi)
				}
				if len(rawVal_suppressvtcsi) != 0 {
					return fmt.Errorf("decoding suppress-VT-CSI: %w: NULL content length %d", ber.ErrInvalidValue, len(rawVal_suppressvtcsi))
				}
				v.SuppressVTCSI = &struct{}{}
				offset += n_suppressvtcsi
			}
		}
	}
	// Decode suppressIncomingCallBarring
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 23 {
				decodedTag_suppressincomingcallbarring, n_suppressincomingcallbarring, rawVal_suppressincomingcallbarring, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding suppressIncomingCallBarring: %w", err)
				}
				if decodedTag_suppressincomingcallbarring.Class != tag.ClassContextSpecific || decodedTag_suppressincomingcallbarring.Number != 23 || decodedTag_suppressincomingcallbarring.Constructed != false {
					return fmt.Errorf("decoding suppressIncomingCallBarring: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_suppressincomingcallbarring)
				}
				if len(rawVal_suppressincomingcallbarring) != 0 {
					return fmt.Errorf("decoding suppressIncomingCallBarring: %w: NULL content length %d", ber.ErrInvalidValue, len(rawVal_suppressincomingcallbarring))
				}
				v.SuppressIncomingCallBarring = &struct{}{}
				offset += n_suppressincomingcallbarring
			}
		}
	}
	// Decode gsmSCF-InitiatedCall
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 24 {
				decodedTag_gsmscfinitiatedcall, n_gsmscfinitiatedcall, rawVal_gsmscfinitiatedcall, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding gsmSCF-InitiatedCall: %w", err)
				}
				if decodedTag_gsmscfinitiatedcall.Class != tag.ClassContextSpecific || decodedTag_gsmscfinitiatedcall.Number != 24 || decodedTag_gsmscfinitiatedcall.Constructed != false {
					return fmt.Errorf("decoding gsmSCF-InitiatedCall: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_gsmscfinitiatedcall)
				}
				if len(rawVal_gsmscfinitiatedcall) != 0 {
					return fmt.Errorf("decoding gsmSCF-InitiatedCall: %w: NULL content length %d", ber.ErrInvalidValue, len(rawVal_gsmscfinitiatedcall))
				}
				v.GsmSCFInitiatedCall = &struct{}{}
				offset += n_gsmscfinitiatedcall
			}
		}
	}
	// Decode basicServiceGroup2
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 25 {
				decodedTag_basicservicegroup2, n_basicservicegroup2, innerData_basicservicegroup2, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding basicServiceGroup2: %w", err)
				}
				if decodedTag_basicservicegroup2.Class != tag.ClassContextSpecific || decodedTag_basicservicegroup2.Number != 25 || decodedTag_basicservicegroup2.Constructed != true {
					return fmt.Errorf("decoding basicServiceGroup2: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_basicservicegroup2)
				}
				// Decode inner value from explicit tag wrapper
				var dec_basicservicegroup2 ExtBasicServiceCode
				if unmErr := dec_basicservicegroup2.UnmarshalBER(innerData_basicservicegroup2); unmErr != nil {
					return fmt.Errorf("decoding basicServiceGroup2: %w", unmErr)
				}
				v.BasicServiceGroup2 = &dec_basicservicegroup2
				offset += n_basicservicegroup2
			}
		}
	}
	// Decode networkSignalInfo2
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 26 {
				decodedTag_networksignalinfo2, n_networksignalinfo2, rawVal_networksignalinfo2, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding networkSignalInfo2: %w", err)
				}
				if decodedTag_networksignalinfo2.Class != tag.ClassContextSpecific || decodedTag_networksignalinfo2.Number != 26 || decodedTag_networksignalinfo2.Constructed != true {
					return fmt.Errorf("decoding networkSignalInfo2: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_networksignalinfo2)
				}
				reconstructed_networksignalinfo2 := ber.EncodeSequence(rawVal_networksignalinfo2)
				var dec_networksignalinfo2 ExternalSignalInfo
				if unmErr := dec_networksignalinfo2.UnmarshalBER(reconstructed_networksignalinfo2); unmErr != nil {
					return fmt.Errorf("decoding networkSignalInfo2: %w", unmErr)
				}
				v.NetworkSignalInfo2 = &dec_networksignalinfo2
				offset += n_networksignalinfo2
			}
		}
	}
	// Decode suppressMTSS
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 27 {
				decodedTag_suppressmtss, n_suppressmtss, rawVal_suppressmtss, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding suppressMTSS: %w", err)
				}
				if decodedTag_suppressmtss.Class != tag.ClassContextSpecific || decodedTag_suppressmtss.Number != 27 {
					return fmt.Errorf("decoding suppressMTSS: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_suppressmtss)
				}
				bsBytes_suppressmtss, bsUnused_suppressmtss, bsErr := ber.DecodeImplicitBitStringValue(decodedTag_suppressmtss.Constructed, rawVal_suppressmtss)
				if bsErr != nil {
					return fmt.Errorf("decoding suppressMTSS: %w", bsErr)
				}
				tmp_suppressmtss := runtime.BitString{Bytes: bsBytes_suppressmtss, BitLength: len(bsBytes_suppressmtss)*8 - bsUnused_suppressmtss}
				v.SuppressMTSS = &tmp_suppressmtss
				offset += n_suppressmtss
			}
		}
	}
	// Decode mtRoamingRetrySupported
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 28 {
				decodedTag_mtroamingretrysupported, n_mtroamingretrysupported, rawVal_mtroamingretrysupported, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding mtRoamingRetrySupported: %w", err)
				}
				if decodedTag_mtroamingretrysupported.Class != tag.ClassContextSpecific || decodedTag_mtroamingretrysupported.Number != 28 || decodedTag_mtroamingretrysupported.Constructed != false {
					return fmt.Errorf("decoding mtRoamingRetrySupported: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_mtroamingretrysupported)
				}
				if len(rawVal_mtroamingretrysupported) != 0 {
					return fmt.Errorf("decoding mtRoamingRetrySupported: %w: NULL content length %d", ber.ErrInvalidValue, len(rawVal_mtroamingretrysupported))
				}
				v.MtRoamingRetrySupported = &struct{}{}
				offset += n_mtroamingretrysupported
			}
		}
	}
	// Decode callPriority
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 29 {
				decodedTag_callpriority, n_callpriority, rawVal_callpriority, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding callPriority: %w", err)
				}
				if decodedTag_callpriority.Class != tag.ClassContextSpecific || decodedTag_callpriority.Number != 29 || decodedTag_callpriority.Constructed != false {
					return fmt.Errorf("decoding callPriority: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_callpriority)
				}
				decVal_callpriority, intErr := ber.DecodeIntegerValue(rawVal_callpriority)
				if intErr != nil {
					return fmt.Errorf("decoding callPriority: %w", intErr)
				}
				tmp_callpriority := EMLPPPriority(decVal_callpriority)
				v.CallPriority = &tmp_callpriority
				offset += n_callpriority
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "SendRoutingInfoArg", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes SendRoutingInfoRes to BER format.
func (v *SendRoutingInfoRes) MarshalBER() ([]byte, error) {
	var children []byte
	if v.Imsi != nil {
		enc_imsi := ber.EncodeOctetString([]byte(*v.Imsi))
		retagged_enc_imsi, tagErr_enc_imsi := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 9, enc_imsi)
		if tagErr_enc_imsi != nil {
			return nil, fmt.Errorf("encoding imsi: %w", tagErr_enc_imsi)
		}
		enc_imsi = retagged_enc_imsi
		children = append(children, enc_imsi...)
	}
	if v.ExtendedRoutingInfo != nil {
		enc_extendedroutinginfo, err := v.ExtendedRoutingInfo.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding extendedRoutingInfo: %w", err)
		}
		children = append(children, enc_extendedroutinginfo...)
	}
	if v.CugCheckInfo != nil {
		enc_cugcheckinfo, err := v.CugCheckInfo.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding cug-CheckInfo: %w", err)
		}
		retagged_enc_cugcheckinfo, tagErr_enc_cugcheckinfo := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, enc_cugcheckinfo)
		if tagErr_enc_cugcheckinfo != nil {
			return nil, fmt.Errorf("encoding cug-CheckInfo: %w", tagErr_enc_cugcheckinfo)
		}
		enc_cugcheckinfo = retagged_enc_cugcheckinfo
		children = append(children, enc_cugcheckinfo...)
	}
	if v.CugSubscriptionFlag != nil {
		enc_cugsubscriptionflag := ber.EncodeNull()
		retagged_enc_cugsubscriptionflag, tagErr_enc_cugsubscriptionflag := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 6, enc_cugsubscriptionflag)
		if tagErr_enc_cugsubscriptionflag != nil {
			return nil, fmt.Errorf("encoding cugSubscriptionFlag: %w", tagErr_enc_cugsubscriptionflag)
		}
		enc_cugsubscriptionflag = retagged_enc_cugsubscriptionflag
		children = append(children, enc_cugsubscriptionflag...)
	}
	if v.SubscriberInfo != nil {
		enc_subscriberinfo, err := v.SubscriberInfo.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding subscriberInfo: %w", err)
		}
		retagged_enc_subscriberinfo, tagErr_enc_subscriberinfo := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 7, enc_subscriberinfo)
		if tagErr_enc_subscriberinfo != nil {
			return nil, fmt.Errorf("encoding subscriberInfo: %w", tagErr_enc_subscriberinfo)
		}
		enc_subscriberinfo = retagged_enc_subscriberinfo
		children = append(children, enc_subscriberinfo...)
	}
	if v.SsList != nil {
		enc_sslist, err := MarshalBERSSList(v.SsList)
		if err != nil {
			return nil, fmt.Errorf("encoding ss-List: %w", err)
		}
		if v.SsListIndef_ {
			// Strip the outer SEQUENCE tag from marshalBER output to get raw children.
			_, _, seqContent_, tlvErr_ := ber.DecodeTLV(enc_sslist)
			if tlvErr_ != nil {
				return nil, tlvErr_
			}
			enc_sslist = ber.EncodeConstructedIndefinite(tag.Tag{Class: tag.ClassContextSpecific, Number: 1}, seqContent_)
		} else {
			retagged_enc_sslist, tagErr_enc_sslist := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_sslist)
			if tagErr_enc_sslist != nil {
				return nil, fmt.Errorf("encoding ss-List: %w", tagErr_enc_sslist)
			}
			enc_sslist = retagged_enc_sslist
		}
		children = append(children, enc_sslist...)
	}
	if v.BasicService != nil {
		enc_basicservice, err := v.BasicService.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding basicService: %w", err)
		}
		enc_basicservice = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 5, enc_basicservice)
		children = append(children, enc_basicservice...)
	}
	if v.ForwardingInterrogationRequired != nil {
		enc_forwardinginterrogationrequired := ber.EncodeNull()
		retagged_enc_forwardinginterrogationrequired, tagErr_enc_forwardinginterrogationrequired := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, enc_forwardinginterrogationrequired)
		if tagErr_enc_forwardinginterrogationrequired != nil {
			return nil, fmt.Errorf("encoding forwardingInterrogationRequired: %w", tagErr_enc_forwardinginterrogationrequired)
		}
		enc_forwardinginterrogationrequired = retagged_enc_forwardinginterrogationrequired
		children = append(children, enc_forwardinginterrogationrequired...)
	}
	if v.VmscAddress != nil {
		enc_vmscaddress := ber.EncodeOctetString([]byte(*v.VmscAddress))
		retagged_enc_vmscaddress, tagErr_enc_vmscaddress := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_vmscaddress)
		if tagErr_enc_vmscaddress != nil {
			return nil, fmt.Errorf("encoding vmsc-Address: %w", tagErr_enc_vmscaddress)
		}
		enc_vmscaddress = retagged_enc_vmscaddress
		children = append(children, enc_vmscaddress...)
	}
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalBER()
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
	if v.NaeaPreferredCI != nil {
		enc_naeapreferredci, err := v.NaeaPreferredCI.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding naea-PreferredCI: %w", err)
		}
		retagged_enc_naeapreferredci, tagErr_enc_naeapreferredci := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 10, enc_naeapreferredci)
		if tagErr_enc_naeapreferredci != nil {
			return nil, fmt.Errorf("encoding naea-PreferredCI: %w", tagErr_enc_naeapreferredci)
		}
		enc_naeapreferredci = retagged_enc_naeapreferredci
		children = append(children, enc_naeapreferredci...)
	}
	if v.CcbsIndicators != nil {
		enc_ccbsindicators, err := v.CcbsIndicators.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding ccbs-Indicators: %w", err)
		}
		retagged_enc_ccbsindicators, tagErr_enc_ccbsindicators := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 11, enc_ccbsindicators)
		if tagErr_enc_ccbsindicators != nil {
			return nil, fmt.Errorf("encoding ccbs-Indicators: %w", tagErr_enc_ccbsindicators)
		}
		enc_ccbsindicators = retagged_enc_ccbsindicators
		children = append(children, enc_ccbsindicators...)
	}
	if v.Msisdn != nil {
		enc_msisdn := ber.EncodeOctetString([]byte(*v.Msisdn))
		retagged_enc_msisdn, tagErr_enc_msisdn := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 12, enc_msisdn)
		if tagErr_enc_msisdn != nil {
			return nil, fmt.Errorf("encoding msisdn: %w", tagErr_enc_msisdn)
		}
		enc_msisdn = retagged_enc_msisdn
		children = append(children, enc_msisdn...)
	}
	if v.NumberPortabilityStatus != nil {
		enc_numberportabilitystatus := ber.EncodeEnumerated(int64(*v.NumberPortabilityStatus))
		retagged_enc_numberportabilitystatus, tagErr_enc_numberportabilitystatus := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 13, enc_numberportabilitystatus)
		if tagErr_enc_numberportabilitystatus != nil {
			return nil, fmt.Errorf("encoding numberPortabilityStatus: %w", tagErr_enc_numberportabilitystatus)
		}
		enc_numberportabilitystatus = retagged_enc_numberportabilitystatus
		children = append(children, enc_numberportabilitystatus...)
	}
	if v.IstAlertTimer != nil {
		enc_istalerttimer := ber.EncodeInteger(int64(*v.IstAlertTimer))
		retagged_enc_istalerttimer, tagErr_enc_istalerttimer := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 14, enc_istalerttimer)
		if tagErr_enc_istalerttimer != nil {
			return nil, fmt.Errorf("encoding istAlertTimer: %w", tagErr_enc_istalerttimer)
		}
		enc_istalerttimer = retagged_enc_istalerttimer
		children = append(children, enc_istalerttimer...)
	}
	if v.SupportedCamelPhasesInVMSC != nil {
		enc_supportedcamelphasesinvmsc := ber.EncodeBitString(v.SupportedCamelPhasesInVMSC.Bytes, (8-(v.SupportedCamelPhasesInVMSC.BitLength%8))%8)
		retagged_enc_supportedcamelphasesinvmsc, tagErr_enc_supportedcamelphasesinvmsc := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 15, enc_supportedcamelphasesinvmsc)
		if tagErr_enc_supportedcamelphasesinvmsc != nil {
			return nil, fmt.Errorf("encoding supportedCamelPhasesInVMSC: %w", tagErr_enc_supportedcamelphasesinvmsc)
		}
		enc_supportedcamelphasesinvmsc = retagged_enc_supportedcamelphasesinvmsc
		children = append(children, enc_supportedcamelphasesinvmsc...)
	}
	if v.OfferedCamel4CSIsInVMSC != nil {
		enc_offeredcamel4csisinvmsc := ber.EncodeBitString(v.OfferedCamel4CSIsInVMSC.Bytes, (8-(v.OfferedCamel4CSIsInVMSC.BitLength%8))%8)
		retagged_enc_offeredcamel4csisinvmsc, tagErr_enc_offeredcamel4csisinvmsc := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 16, enc_offeredcamel4csisinvmsc)
		if tagErr_enc_offeredcamel4csisinvmsc != nil {
			return nil, fmt.Errorf("encoding offeredCamel4CSIsInVMSC: %w", tagErr_enc_offeredcamel4csisinvmsc)
		}
		enc_offeredcamel4csisinvmsc = retagged_enc_offeredcamel4csisinvmsc
		children = append(children, enc_offeredcamel4csisinvmsc...)
	}
	if v.RoutingInfo2 != nil {
		enc_routinginfo2, err := v.RoutingInfo2.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding routingInfo2: %w", err)
		}
		enc_routinginfo2 = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 17, enc_routinginfo2)
		children = append(children, enc_routinginfo2...)
	}
	if v.SsList2 != nil {
		enc_sslist2, err := MarshalBERSSList(v.SsList2)
		if err != nil {
			return nil, fmt.Errorf("encoding ss-List2: %w", err)
		}
		if v.SsList2Indef_ {
			// Strip the outer SEQUENCE tag from marshalBER output to get raw children.
			_, _, seqContent_, tlvErr_ := ber.DecodeTLV(enc_sslist2)
			if tlvErr_ != nil {
				return nil, tlvErr_
			}
			enc_sslist2 = ber.EncodeConstructedIndefinite(tag.Tag{Class: tag.ClassContextSpecific, Number: 18}, seqContent_)
		} else {
			retagged_enc_sslist2, tagErr_enc_sslist2 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 18, enc_sslist2)
			if tagErr_enc_sslist2 != nil {
				return nil, fmt.Errorf("encoding ss-List2: %w", tagErr_enc_sslist2)
			}
			enc_sslist2 = retagged_enc_sslist2
		}
		children = append(children, enc_sslist2...)
	}
	if v.BasicService2 != nil {
		enc_basicservice2, err := v.BasicService2.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding basicService2: %w", err)
		}
		enc_basicservice2 = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 19, enc_basicservice2)
		children = append(children, enc_basicservice2...)
	}
	if v.AllowedServices != nil {
		enc_allowedservices := ber.EncodeBitString(v.AllowedServices.Bytes, (8-(v.AllowedServices.BitLength%8))%8)
		retagged_enc_allowedservices, tagErr_enc_allowedservices := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 20, enc_allowedservices)
		if tagErr_enc_allowedservices != nil {
			return nil, fmt.Errorf("encoding allowedServices: %w", tagErr_enc_allowedservices)
		}
		enc_allowedservices = retagged_enc_allowedservices
		children = append(children, enc_allowedservices...)
	}
	if v.UnavailabilityCause != nil {
		enc_unavailabilitycause := ber.EncodeEnumerated(int64(*v.UnavailabilityCause))
		retagged_enc_unavailabilitycause, tagErr_enc_unavailabilitycause := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 21, enc_unavailabilitycause)
		if tagErr_enc_unavailabilitycause != nil {
			return nil, fmt.Errorf("encoding unavailabilityCause: %w", tagErr_enc_unavailabilitycause)
		}
		enc_unavailabilitycause = retagged_enc_unavailabilitycause
		children = append(children, enc_unavailabilitycause...)
	}
	if v.ReleaseResourcesSupported != nil {
		enc_releaseresourcessupported := ber.EncodeNull()
		retagged_enc_releaseresourcessupported, tagErr_enc_releaseresourcessupported := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 22, enc_releaseresourcessupported)
		if tagErr_enc_releaseresourcessupported != nil {
			return nil, fmt.Errorf("encoding releaseResourcesSupported: %w", tagErr_enc_releaseresourcessupported)
		}
		enc_releaseresourcessupported = retagged_enc_releaseresourcessupported
		children = append(children, enc_releaseresourcessupported...)
	}
	if v.GsmBearerCapability != nil {
		enc_gsmbearercapability, err := v.GsmBearerCapability.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding gsm-BearerCapability: %w", err)
		}
		retagged_enc_gsmbearercapability, tagErr_enc_gsmbearercapability := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 23, enc_gsmbearercapability)
		if tagErr_enc_gsmbearercapability != nil {
			return nil, fmt.Errorf("encoding gsm-BearerCapability: %w", tagErr_enc_gsmbearercapability)
		}
		enc_gsmbearercapability = retagged_enc_gsmbearercapability
		children = append(children, enc_gsmbearercapability...)
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
	return ber.EncodeConstructed(tag.Tag{Class: tag.ClassContextSpecific, Number: 3, Constructed: true}, children), nil
}

// MarshalDER encodes SendRoutingInfoRes to DER format.
func (v *SendRoutingInfoRes) MarshalDER() ([]byte, error) {
	var children []byte
	if v.Imsi != nil {
		enc_imsi := ber.EncodeOctetString([]byte(*v.Imsi))
		retagged_enc_imsi, tagErr_enc_imsi := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 9, enc_imsi)
		if tagErr_enc_imsi != nil {
			return nil, fmt.Errorf("encoding imsi: %w", tagErr_enc_imsi)
		}
		enc_imsi = retagged_enc_imsi
		children = append(children, enc_imsi...)
	}
	if v.ExtendedRoutingInfo != nil {
		enc_extendedroutinginfo, err := v.ExtendedRoutingInfo.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding extendedRoutingInfo: %w", err)
		}
		children = append(children, enc_extendedroutinginfo...)
	}
	if v.CugCheckInfo != nil {
		enc_cugcheckinfo, err := v.CugCheckInfo.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding cug-CheckInfo: %w", err)
		}
		retagged_enc_cugcheckinfo, tagErr_enc_cugcheckinfo := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, enc_cugcheckinfo)
		if tagErr_enc_cugcheckinfo != nil {
			return nil, fmt.Errorf("encoding cug-CheckInfo: %w", tagErr_enc_cugcheckinfo)
		}
		enc_cugcheckinfo = retagged_enc_cugcheckinfo
		children = append(children, enc_cugcheckinfo...)
	}
	if v.CugSubscriptionFlag != nil {
		enc_cugsubscriptionflag := ber.EncodeNull()
		retagged_enc_cugsubscriptionflag, tagErr_enc_cugsubscriptionflag := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 6, enc_cugsubscriptionflag)
		if tagErr_enc_cugsubscriptionflag != nil {
			return nil, fmt.Errorf("encoding cugSubscriptionFlag: %w", tagErr_enc_cugsubscriptionflag)
		}
		enc_cugsubscriptionflag = retagged_enc_cugsubscriptionflag
		children = append(children, enc_cugsubscriptionflag...)
	}
	if v.SubscriberInfo != nil {
		enc_subscriberinfo, err := v.SubscriberInfo.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding subscriberInfo: %w", err)
		}
		retagged_enc_subscriberinfo, tagErr_enc_subscriberinfo := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 7, enc_subscriberinfo)
		if tagErr_enc_subscriberinfo != nil {
			return nil, fmt.Errorf("encoding subscriberInfo: %w", tagErr_enc_subscriberinfo)
		}
		enc_subscriberinfo = retagged_enc_subscriberinfo
		children = append(children, enc_subscriberinfo...)
	}
	if v.SsList != nil {
		enc_sslist, err := MarshalDERSSList(v.SsList)
		if err != nil {
			return nil, fmt.Errorf("encoding ss-List: %w", err)
		}
		retagged_enc_sslist, tagErr_enc_sslist := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_sslist)
		if tagErr_enc_sslist != nil {
			return nil, fmt.Errorf("encoding ss-List: %w", tagErr_enc_sslist)
		}
		enc_sslist = retagged_enc_sslist
		children = append(children, enc_sslist...)
	}
	if v.BasicService != nil {
		enc_basicservice, err := v.BasicService.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding basicService: %w", err)
		}
		enc_basicservice = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 5, enc_basicservice)
		children = append(children, enc_basicservice...)
	}
	if v.ForwardingInterrogationRequired != nil {
		enc_forwardinginterrogationrequired := ber.EncodeNull()
		retagged_enc_forwardinginterrogationrequired, tagErr_enc_forwardinginterrogationrequired := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, enc_forwardinginterrogationrequired)
		if tagErr_enc_forwardinginterrogationrequired != nil {
			return nil, fmt.Errorf("encoding forwardingInterrogationRequired: %w", tagErr_enc_forwardinginterrogationrequired)
		}
		enc_forwardinginterrogationrequired = retagged_enc_forwardinginterrogationrequired
		children = append(children, enc_forwardinginterrogationrequired...)
	}
	if v.VmscAddress != nil {
		enc_vmscaddress := ber.EncodeOctetString([]byte(*v.VmscAddress))
		retagged_enc_vmscaddress, tagErr_enc_vmscaddress := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_vmscaddress)
		if tagErr_enc_vmscaddress != nil {
			return nil, fmt.Errorf("encoding vmsc-Address: %w", tagErr_enc_vmscaddress)
		}
		enc_vmscaddress = retagged_enc_vmscaddress
		children = append(children, enc_vmscaddress...)
	}
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
	if v.NaeaPreferredCI != nil {
		enc_naeapreferredci, err := v.NaeaPreferredCI.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding naea-PreferredCI: %w", err)
		}
		retagged_enc_naeapreferredci, tagErr_enc_naeapreferredci := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 10, enc_naeapreferredci)
		if tagErr_enc_naeapreferredci != nil {
			return nil, fmt.Errorf("encoding naea-PreferredCI: %w", tagErr_enc_naeapreferredci)
		}
		enc_naeapreferredci = retagged_enc_naeapreferredci
		children = append(children, enc_naeapreferredci...)
	}
	if v.CcbsIndicators != nil {
		enc_ccbsindicators, err := v.CcbsIndicators.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding ccbs-Indicators: %w", err)
		}
		retagged_enc_ccbsindicators, tagErr_enc_ccbsindicators := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 11, enc_ccbsindicators)
		if tagErr_enc_ccbsindicators != nil {
			return nil, fmt.Errorf("encoding ccbs-Indicators: %w", tagErr_enc_ccbsindicators)
		}
		enc_ccbsindicators = retagged_enc_ccbsindicators
		children = append(children, enc_ccbsindicators...)
	}
	if v.Msisdn != nil {
		enc_msisdn := ber.EncodeOctetString([]byte(*v.Msisdn))
		retagged_enc_msisdn, tagErr_enc_msisdn := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 12, enc_msisdn)
		if tagErr_enc_msisdn != nil {
			return nil, fmt.Errorf("encoding msisdn: %w", tagErr_enc_msisdn)
		}
		enc_msisdn = retagged_enc_msisdn
		children = append(children, enc_msisdn...)
	}
	if v.NumberPortabilityStatus != nil {
		enc_numberportabilitystatus := ber.EncodeEnumerated(int64(*v.NumberPortabilityStatus))
		retagged_enc_numberportabilitystatus, tagErr_enc_numberportabilitystatus := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 13, enc_numberportabilitystatus)
		if tagErr_enc_numberportabilitystatus != nil {
			return nil, fmt.Errorf("encoding numberPortabilityStatus: %w", tagErr_enc_numberportabilitystatus)
		}
		enc_numberportabilitystatus = retagged_enc_numberportabilitystatus
		children = append(children, enc_numberportabilitystatus...)
	}
	if v.IstAlertTimer != nil {
		enc_istalerttimer := ber.EncodeInteger(int64(*v.IstAlertTimer))
		retagged_enc_istalerttimer, tagErr_enc_istalerttimer := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 14, enc_istalerttimer)
		if tagErr_enc_istalerttimer != nil {
			return nil, fmt.Errorf("encoding istAlertTimer: %w", tagErr_enc_istalerttimer)
		}
		enc_istalerttimer = retagged_enc_istalerttimer
		children = append(children, enc_istalerttimer...)
	}
	if v.SupportedCamelPhasesInVMSC != nil {
		enc_supportedcamelphasesinvmsc := ber.EncodeBitString(v.SupportedCamelPhasesInVMSC.Bytes, (8-(v.SupportedCamelPhasesInVMSC.BitLength%8))%8)
		retagged_enc_supportedcamelphasesinvmsc, tagErr_enc_supportedcamelphasesinvmsc := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 15, enc_supportedcamelphasesinvmsc)
		if tagErr_enc_supportedcamelphasesinvmsc != nil {
			return nil, fmt.Errorf("encoding supportedCamelPhasesInVMSC: %w", tagErr_enc_supportedcamelphasesinvmsc)
		}
		enc_supportedcamelphasesinvmsc = retagged_enc_supportedcamelphasesinvmsc
		children = append(children, enc_supportedcamelphasesinvmsc...)
	}
	if v.OfferedCamel4CSIsInVMSC != nil {
		enc_offeredcamel4csisinvmsc := ber.EncodeBitString(v.OfferedCamel4CSIsInVMSC.Bytes, (8-(v.OfferedCamel4CSIsInVMSC.BitLength%8))%8)
		retagged_enc_offeredcamel4csisinvmsc, tagErr_enc_offeredcamel4csisinvmsc := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 16, enc_offeredcamel4csisinvmsc)
		if tagErr_enc_offeredcamel4csisinvmsc != nil {
			return nil, fmt.Errorf("encoding offeredCamel4CSIsInVMSC: %w", tagErr_enc_offeredcamel4csisinvmsc)
		}
		enc_offeredcamel4csisinvmsc = retagged_enc_offeredcamel4csisinvmsc
		children = append(children, enc_offeredcamel4csisinvmsc...)
	}
	if v.RoutingInfo2 != nil {
		enc_routinginfo2, err := v.RoutingInfo2.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding routingInfo2: %w", err)
		}
		enc_routinginfo2 = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 17, enc_routinginfo2)
		children = append(children, enc_routinginfo2...)
	}
	if v.SsList2 != nil {
		enc_sslist2, err := MarshalDERSSList(v.SsList2)
		if err != nil {
			return nil, fmt.Errorf("encoding ss-List2: %w", err)
		}
		retagged_enc_sslist2, tagErr_enc_sslist2 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 18, enc_sslist2)
		if tagErr_enc_sslist2 != nil {
			return nil, fmt.Errorf("encoding ss-List2: %w", tagErr_enc_sslist2)
		}
		enc_sslist2 = retagged_enc_sslist2
		children = append(children, enc_sslist2...)
	}
	if v.BasicService2 != nil {
		enc_basicservice2, err := v.BasicService2.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding basicService2: %w", err)
		}
		enc_basicservice2 = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 19, enc_basicservice2)
		children = append(children, enc_basicservice2...)
	}
	if v.AllowedServices != nil {
		enc_allowedservices := ber.EncodeBitString(v.AllowedServices.Bytes, (8-(v.AllowedServices.BitLength%8))%8)
		retagged_enc_allowedservices, tagErr_enc_allowedservices := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 20, enc_allowedservices)
		if tagErr_enc_allowedservices != nil {
			return nil, fmt.Errorf("encoding allowedServices: %w", tagErr_enc_allowedservices)
		}
		enc_allowedservices = retagged_enc_allowedservices
		children = append(children, enc_allowedservices...)
	}
	if v.UnavailabilityCause != nil {
		enc_unavailabilitycause := ber.EncodeEnumerated(int64(*v.UnavailabilityCause))
		retagged_enc_unavailabilitycause, tagErr_enc_unavailabilitycause := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 21, enc_unavailabilitycause)
		if tagErr_enc_unavailabilitycause != nil {
			return nil, fmt.Errorf("encoding unavailabilityCause: %w", tagErr_enc_unavailabilitycause)
		}
		enc_unavailabilitycause = retagged_enc_unavailabilitycause
		children = append(children, enc_unavailabilitycause...)
	}
	if v.ReleaseResourcesSupported != nil {
		enc_releaseresourcessupported := ber.EncodeNull()
		retagged_enc_releaseresourcessupported, tagErr_enc_releaseresourcessupported := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 22, enc_releaseresourcessupported)
		if tagErr_enc_releaseresourcessupported != nil {
			return nil, fmt.Errorf("encoding releaseResourcesSupported: %w", tagErr_enc_releaseresourcessupported)
		}
		enc_releaseresourcessupported = retagged_enc_releaseresourcessupported
		children = append(children, enc_releaseresourcessupported...)
	}
	if v.GsmBearerCapability != nil {
		enc_gsmbearercapability, err := v.GsmBearerCapability.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding gsm-BearerCapability: %w", err)
		}
		retagged_enc_gsmbearercapability, tagErr_enc_gsmbearercapability := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 23, enc_gsmbearercapability)
		if tagErr_enc_gsmbearercapability != nil {
			return nil, fmt.Errorf("encoding gsm-BearerCapability: %w", tagErr_enc_gsmbearercapability)
		}
		enc_gsmbearercapability = retagged_enc_gsmbearercapability
		children = append(children, enc_gsmbearercapability...)
	}
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
		children = append(children, ext...)
	}
	encoded := ber.EncodeSequence(children)
	retagged_encoded, tagErr_encoded := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, encoded)
	if tagErr_encoded != nil {
		return nil, fmt.Errorf("encoding SendRoutingInfoRes: %w", tagErr_encoded)
	}
	encoded = retagged_encoded
	if err := ber.ValidateDERElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding SendRoutingInfoRes as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes SendRoutingInfoRes from BER/DER format.
func (v *SendRoutingInfoRes) UnmarshalBER(data []byte) error {
	*v = SendRoutingInfoRes{}
	decodedTag, content, total, err := ber.DecodeConstructedContent(data)
	if err != nil {
		return fmt.Errorf("decoding SendRoutingInfoRes: %w", err)
	}
	if decodedTag.Class != tag.ClassContextSpecific || decodedTag.Number != 3 || !decodedTag.Constructed {
		return fmt.Errorf("decoding SendRoutingInfoRes: %w: expected tag [CONTEXT 3], got %s", ber.ErrInvalidTag, decodedTag)
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
				decodedTag_imsi, n_imsi, rawVal_imsi, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding imsi: %w", err)
				}
				if decodedTag_imsi.Class != tag.ClassContextSpecific || decodedTag_imsi.Number != 9 {
					return fmt.Errorf("decoding imsi: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_imsi)
				}
				tmp_imsi := IMSI(rawVal_imsi)
				v.Imsi = &tmp_imsi
				offset += n_imsi
			}
		}
	}
	// Decode extendedRoutingInfo
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if (peekTag.Class == tag.ClassUniversal && peekTag.Number == 4) || (peekTag.Class == tag.ClassUniversal && peekTag.Number == 16) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 8) {
				// Decode nested CHOICE (ExtendedRoutingInfo)
				_, n_extendedroutinginfo, _, tlvErr_extendedroutinginfo := ber.DecodeTLV(content[offset:])
				if tlvErr_extendedroutinginfo != nil {
					return fmt.Errorf("decoding extendedRoutingInfo: %w", tlvErr_extendedroutinginfo)
				}
				var dec_extendedroutinginfo ExtendedRoutingInfo
				if unmErr := dec_extendedroutinginfo.UnmarshalBER(content[offset : offset+n_extendedroutinginfo]); unmErr != nil {
					return fmt.Errorf("decoding extendedRoutingInfo: %w", unmErr)
				}
				v.ExtendedRoutingInfo = &dec_extendedroutinginfo
				offset += n_extendedroutinginfo
			}
		}
	}
	// Decode cug-CheckInfo
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3 {
				decodedTag_cugcheckinfo, n_cugcheckinfo, rawVal_cugcheckinfo, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding cug-CheckInfo: %w", err)
				}
				if decodedTag_cugcheckinfo.Class != tag.ClassContextSpecific || decodedTag_cugcheckinfo.Number != 3 || decodedTag_cugcheckinfo.Constructed != true {
					return fmt.Errorf("decoding cug-CheckInfo: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_cugcheckinfo)
				}
				reconstructed_cugcheckinfo := ber.EncodeSequence(rawVal_cugcheckinfo)
				var dec_cugcheckinfo CUGCheckInfo
				if unmErr := dec_cugcheckinfo.UnmarshalBER(reconstructed_cugcheckinfo); unmErr != nil {
					return fmt.Errorf("decoding cug-CheckInfo: %w", unmErr)
				}
				v.CugCheckInfo = &dec_cugcheckinfo
				offset += n_cugcheckinfo
			}
		}
	}
	// Decode cugSubscriptionFlag
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 6 {
				decodedTag_cugsubscriptionflag, n_cugsubscriptionflag, rawVal_cugsubscriptionflag, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding cugSubscriptionFlag: %w", err)
				}
				if decodedTag_cugsubscriptionflag.Class != tag.ClassContextSpecific || decodedTag_cugsubscriptionflag.Number != 6 || decodedTag_cugsubscriptionflag.Constructed != false {
					return fmt.Errorf("decoding cugSubscriptionFlag: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_cugsubscriptionflag)
				}
				if len(rawVal_cugsubscriptionflag) != 0 {
					return fmt.Errorf("decoding cugSubscriptionFlag: %w: NULL content length %d", ber.ErrInvalidValue, len(rawVal_cugsubscriptionflag))
				}
				v.CugSubscriptionFlag = &struct{}{}
				offset += n_cugsubscriptionflag
			}
		}
	}
	// Decode subscriberInfo
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 7 {
				decodedTag_subscriberinfo, n_subscriberinfo, rawVal_subscriberinfo, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding subscriberInfo: %w", err)
				}
				if decodedTag_subscriberinfo.Class != tag.ClassContextSpecific || decodedTag_subscriberinfo.Number != 7 || decodedTag_subscriberinfo.Constructed != true {
					return fmt.Errorf("decoding subscriberInfo: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_subscriberinfo)
				}
				reconstructed_subscriberinfo := ber.EncodeSequence(rawVal_subscriberinfo)
				var dec_subscriberinfo SubscriberInfo
				if unmErr := dec_subscriberinfo.UnmarshalBER(reconstructed_subscriberinfo); unmErr != nil {
					return fmt.Errorf("decoding subscriberInfo: %w", unmErr)
				}
				v.SubscriberInfo = &dec_subscriberinfo
				offset += n_subscriberinfo
			}
		}
	}
	// Decode ss-List
	v.SsListIndef_ = false
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
				decodedTag_sslist, n_sslist, rawVal_sslist, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding ss-List: %w", err)
				}
				if decodedTag_sslist.Class != tag.ClassContextSpecific || decodedTag_sslist.Number != 1 || decodedTag_sslist.Constructed != true {
					return fmt.Errorf("decoding ss-List: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_sslist)
				}
				reconstructed_sslist := ber.EncodeSequence(rawVal_sslist)
				dec_sslist, unmErr := UnmarshalBERSSList(reconstructed_sslist)
				if unmErr != nil {
					return fmt.Errorf("decoding ss-List: %w", unmErr)
				}
				v.SsList = dec_sslist
				{
					_, tagSz_, _ := ber.DecodeTag(content[offset:])
					if offset+tagSz_ < len(content) && content[offset+tagSz_] == 0x80 {
						v.SsListIndef_ = true
					}
				}
				offset += n_sslist
			}
		}
	}
	// Decode basicService
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 5 {
				decodedTag_basicservice, n_basicservice, innerData_basicservice, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding basicService: %w", err)
				}
				if decodedTag_basicservice.Class != tag.ClassContextSpecific || decodedTag_basicservice.Number != 5 || decodedTag_basicservice.Constructed != true {
					return fmt.Errorf("decoding basicService: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_basicservice)
				}
				// Decode inner value from explicit tag wrapper
				var dec_basicservice ExtBasicServiceCode
				if unmErr := dec_basicservice.UnmarshalBER(innerData_basicservice); unmErr != nil {
					return fmt.Errorf("decoding basicService: %w", unmErr)
				}
				v.BasicService = &dec_basicservice
				offset += n_basicservice
			}
		}
	}
	// Decode forwardingInterrogationRequired
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4 {
				decodedTag_forwardinginterrogationrequired, n_forwardinginterrogationrequired, rawVal_forwardinginterrogationrequired, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding forwardingInterrogationRequired: %w", err)
				}
				if decodedTag_forwardinginterrogationrequired.Class != tag.ClassContextSpecific || decodedTag_forwardinginterrogationrequired.Number != 4 || decodedTag_forwardinginterrogationrequired.Constructed != false {
					return fmt.Errorf("decoding forwardingInterrogationRequired: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_forwardinginterrogationrequired)
				}
				if len(rawVal_forwardinginterrogationrequired) != 0 {
					return fmt.Errorf("decoding forwardingInterrogationRequired: %w: NULL content length %d", ber.ErrInvalidValue, len(rawVal_forwardinginterrogationrequired))
				}
				v.ForwardingInterrogationRequired = &struct{}{}
				offset += n_forwardinginterrogationrequired
			}
		}
	}
	// Decode vmsc-Address
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2 {
				decodedTag_vmscaddress, n_vmscaddress, rawVal_vmscaddress, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding vmsc-Address: %w", err)
				}
				if decodedTag_vmscaddress.Class != tag.ClassContextSpecific || decodedTag_vmscaddress.Number != 2 {
					return fmt.Errorf("decoding vmsc-Address: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_vmscaddress)
				}
				tmp_vmscaddress := ISDNAddressString(rawVal_vmscaddress)
				v.VmscAddress = &tmp_vmscaddress
				offset += n_vmscaddress
			}
		}
	}
	// Decode extensionContainer
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
				decodedTag_extensioncontainer, n_extensioncontainer, rawVal_extensioncontainer, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding extensionContainer: %w", err)
				}
				if decodedTag_extensioncontainer.Class != tag.ClassContextSpecific || decodedTag_extensioncontainer.Number != 0 || decodedTag_extensioncontainer.Constructed != true {
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
	// Decode naea-PreferredCI
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 10 {
				decodedTag_naeapreferredci, n_naeapreferredci, rawVal_naeapreferredci, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding naea-PreferredCI: %w", err)
				}
				if decodedTag_naeapreferredci.Class != tag.ClassContextSpecific || decodedTag_naeapreferredci.Number != 10 || decodedTag_naeapreferredci.Constructed != true {
					return fmt.Errorf("decoding naea-PreferredCI: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_naeapreferredci)
				}
				reconstructed_naeapreferredci := ber.EncodeSequence(rawVal_naeapreferredci)
				var dec_naeapreferredci NAEAPreferredCI
				if unmErr := dec_naeapreferredci.UnmarshalBER(reconstructed_naeapreferredci); unmErr != nil {
					return fmt.Errorf("decoding naea-PreferredCI: %w", unmErr)
				}
				v.NaeaPreferredCI = &dec_naeapreferredci
				offset += n_naeapreferredci
			}
		}
	}
	// Decode ccbs-Indicators
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 11 {
				decodedTag_ccbsindicators, n_ccbsindicators, rawVal_ccbsindicators, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding ccbs-Indicators: %w", err)
				}
				if decodedTag_ccbsindicators.Class != tag.ClassContextSpecific || decodedTag_ccbsindicators.Number != 11 || decodedTag_ccbsindicators.Constructed != true {
					return fmt.Errorf("decoding ccbs-Indicators: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_ccbsindicators)
				}
				reconstructed_ccbsindicators := ber.EncodeSequence(rawVal_ccbsindicators)
				var dec_ccbsindicators CCBSIndicators
				if unmErr := dec_ccbsindicators.UnmarshalBER(reconstructed_ccbsindicators); unmErr != nil {
					return fmt.Errorf("decoding ccbs-Indicators: %w", unmErr)
				}
				v.CcbsIndicators = &dec_ccbsindicators
				offset += n_ccbsindicators
			}
		}
	}
	// Decode msisdn
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 12 {
				decodedTag_msisdn, n_msisdn, rawVal_msisdn, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding msisdn: %w", err)
				}
				if decodedTag_msisdn.Class != tag.ClassContextSpecific || decodedTag_msisdn.Number != 12 {
					return fmt.Errorf("decoding msisdn: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_msisdn)
				}
				tmp_msisdn := ISDNAddressString(rawVal_msisdn)
				v.Msisdn = &tmp_msisdn
				offset += n_msisdn
			}
		}
	}
	// Decode numberPortabilityStatus
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 13 {
				decodedTag_numberportabilitystatus, n_numberportabilitystatus, rawVal_numberportabilitystatus, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding numberPortabilityStatus: %w", err)
				}
				if decodedTag_numberportabilitystatus.Class != tag.ClassContextSpecific || decodedTag_numberportabilitystatus.Number != 13 || decodedTag_numberportabilitystatus.Constructed != false {
					return fmt.Errorf("decoding numberPortabilityStatus: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_numberportabilitystatus)
				}
				decVal_numberportabilitystatus, intErr := ber.DecodeEnumeratedValue(rawVal_numberportabilitystatus)
				if intErr != nil {
					return fmt.Errorf("decoding numberPortabilityStatus: %w", intErr)
				}
				tmp_numberportabilitystatus := NumberPortabilityStatus(decVal_numberportabilitystatus)
				v.NumberPortabilityStatus = &tmp_numberportabilitystatus
				offset += n_numberportabilitystatus
			}
		}
	}
	// Decode istAlertTimer
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 14 {
				decodedTag_istalerttimer, n_istalerttimer, rawVal_istalerttimer, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding istAlertTimer: %w", err)
				}
				if decodedTag_istalerttimer.Class != tag.ClassContextSpecific || decodedTag_istalerttimer.Number != 14 || decodedTag_istalerttimer.Constructed != false {
					return fmt.Errorf("decoding istAlertTimer: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_istalerttimer)
				}
				decVal_istalerttimer, intErr := ber.DecodeIntegerValue(rawVal_istalerttimer)
				if intErr != nil {
					return fmt.Errorf("decoding istAlertTimer: %w", intErr)
				}
				tmp_istalerttimer := ISTAlertTimerValue(decVal_istalerttimer)
				v.IstAlertTimer = &tmp_istalerttimer
				offset += n_istalerttimer
			}
		}
	}
	// Decode supportedCamelPhasesInVMSC
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 15 {
				decodedTag_supportedcamelphasesinvmsc, n_supportedcamelphasesinvmsc, rawVal_supportedcamelphasesinvmsc, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding supportedCamelPhasesInVMSC: %w", err)
				}
				if decodedTag_supportedcamelphasesinvmsc.Class != tag.ClassContextSpecific || decodedTag_supportedcamelphasesinvmsc.Number != 15 {
					return fmt.Errorf("decoding supportedCamelPhasesInVMSC: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_supportedcamelphasesinvmsc)
				}
				bsBytes_supportedcamelphasesinvmsc, bsUnused_supportedcamelphasesinvmsc, bsErr := ber.DecodeImplicitBitStringValue(decodedTag_supportedcamelphasesinvmsc.Constructed, rawVal_supportedcamelphasesinvmsc)
				if bsErr != nil {
					return fmt.Errorf("decoding supportedCamelPhasesInVMSC: %w", bsErr)
				}
				tmp_supportedcamelphasesinvmsc := runtime.BitString{Bytes: bsBytes_supportedcamelphasesinvmsc, BitLength: len(bsBytes_supportedcamelphasesinvmsc)*8 - bsUnused_supportedcamelphasesinvmsc}
				v.SupportedCamelPhasesInVMSC = &tmp_supportedcamelphasesinvmsc
				offset += n_supportedcamelphasesinvmsc
			}
		}
	}
	// Decode offeredCamel4CSIsInVMSC
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 16 {
				decodedTag_offeredcamel4csisinvmsc, n_offeredcamel4csisinvmsc, rawVal_offeredcamel4csisinvmsc, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding offeredCamel4CSIsInVMSC: %w", err)
				}
				if decodedTag_offeredcamel4csisinvmsc.Class != tag.ClassContextSpecific || decodedTag_offeredcamel4csisinvmsc.Number != 16 {
					return fmt.Errorf("decoding offeredCamel4CSIsInVMSC: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_offeredcamel4csisinvmsc)
				}
				bsBytes_offeredcamel4csisinvmsc, bsUnused_offeredcamel4csisinvmsc, bsErr := ber.DecodeImplicitBitStringValue(decodedTag_offeredcamel4csisinvmsc.Constructed, rawVal_offeredcamel4csisinvmsc)
				if bsErr != nil {
					return fmt.Errorf("decoding offeredCamel4CSIsInVMSC: %w", bsErr)
				}
				tmp_offeredcamel4csisinvmsc := runtime.BitString{Bytes: bsBytes_offeredcamel4csisinvmsc, BitLength: len(bsBytes_offeredcamel4csisinvmsc)*8 - bsUnused_offeredcamel4csisinvmsc}
				v.OfferedCamel4CSIsInVMSC = &tmp_offeredcamel4csisinvmsc
				offset += n_offeredcamel4csisinvmsc
			}
		}
	}
	// Decode routingInfo2
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 17 {
				decodedTag_routinginfo2, n_routinginfo2, innerData_routinginfo2, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding routingInfo2: %w", err)
				}
				if decodedTag_routinginfo2.Class != tag.ClassContextSpecific || decodedTag_routinginfo2.Number != 17 || decodedTag_routinginfo2.Constructed != true {
					return fmt.Errorf("decoding routingInfo2: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_routinginfo2)
				}
				// Decode inner value from explicit tag wrapper
				var dec_routinginfo2 RoutingInfo
				if unmErr := dec_routinginfo2.UnmarshalBER(innerData_routinginfo2); unmErr != nil {
					return fmt.Errorf("decoding routingInfo2: %w", unmErr)
				}
				v.RoutingInfo2 = &dec_routinginfo2
				offset += n_routinginfo2
			}
		}
	}
	// Decode ss-List2
	v.SsList2Indef_ = false
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 18 {
				decodedTag_sslist2, n_sslist2, rawVal_sslist2, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding ss-List2: %w", err)
				}
				if decodedTag_sslist2.Class != tag.ClassContextSpecific || decodedTag_sslist2.Number != 18 || decodedTag_sslist2.Constructed != true {
					return fmt.Errorf("decoding ss-List2: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_sslist2)
				}
				reconstructed_sslist2 := ber.EncodeSequence(rawVal_sslist2)
				dec_sslist2, unmErr := UnmarshalBERSSList(reconstructed_sslist2)
				if unmErr != nil {
					return fmt.Errorf("decoding ss-List2: %w", unmErr)
				}
				v.SsList2 = dec_sslist2
				{
					_, tagSz_, _ := ber.DecodeTag(content[offset:])
					if offset+tagSz_ < len(content) && content[offset+tagSz_] == 0x80 {
						v.SsList2Indef_ = true
					}
				}
				offset += n_sslist2
			}
		}
	}
	// Decode basicService2
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 19 {
				decodedTag_basicservice2, n_basicservice2, innerData_basicservice2, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding basicService2: %w", err)
				}
				if decodedTag_basicservice2.Class != tag.ClassContextSpecific || decodedTag_basicservice2.Number != 19 || decodedTag_basicservice2.Constructed != true {
					return fmt.Errorf("decoding basicService2: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_basicservice2)
				}
				// Decode inner value from explicit tag wrapper
				var dec_basicservice2 ExtBasicServiceCode
				if unmErr := dec_basicservice2.UnmarshalBER(innerData_basicservice2); unmErr != nil {
					return fmt.Errorf("decoding basicService2: %w", unmErr)
				}
				v.BasicService2 = &dec_basicservice2
				offset += n_basicservice2
			}
		}
	}
	// Decode allowedServices
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 20 {
				decodedTag_allowedservices, n_allowedservices, rawVal_allowedservices, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding allowedServices: %w", err)
				}
				if decodedTag_allowedservices.Class != tag.ClassContextSpecific || decodedTag_allowedservices.Number != 20 {
					return fmt.Errorf("decoding allowedServices: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_allowedservices)
				}
				bsBytes_allowedservices, bsUnused_allowedservices, bsErr := ber.DecodeImplicitBitStringValue(decodedTag_allowedservices.Constructed, rawVal_allowedservices)
				if bsErr != nil {
					return fmt.Errorf("decoding allowedServices: %w", bsErr)
				}
				tmp_allowedservices := runtime.BitString{Bytes: bsBytes_allowedservices, BitLength: len(bsBytes_allowedservices)*8 - bsUnused_allowedservices}
				v.AllowedServices = &tmp_allowedservices
				offset += n_allowedservices
			}
		}
	}
	// Decode unavailabilityCause
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 21 {
				decodedTag_unavailabilitycause, n_unavailabilitycause, rawVal_unavailabilitycause, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding unavailabilityCause: %w", err)
				}
				if decodedTag_unavailabilitycause.Class != tag.ClassContextSpecific || decodedTag_unavailabilitycause.Number != 21 || decodedTag_unavailabilitycause.Constructed != false {
					return fmt.Errorf("decoding unavailabilityCause: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_unavailabilitycause)
				}
				decVal_unavailabilitycause, intErr := ber.DecodeEnumeratedValue(rawVal_unavailabilitycause)
				if intErr != nil {
					return fmt.Errorf("decoding unavailabilityCause: %w", intErr)
				}
				tmp_unavailabilitycause := UnavailabilityCause(decVal_unavailabilitycause)
				v.UnavailabilityCause = &tmp_unavailabilitycause
				offset += n_unavailabilitycause
			}
		}
	}
	// Decode releaseResourcesSupported
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 22 {
				decodedTag_releaseresourcessupported, n_releaseresourcessupported, rawVal_releaseresourcessupported, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding releaseResourcesSupported: %w", err)
				}
				if decodedTag_releaseresourcessupported.Class != tag.ClassContextSpecific || decodedTag_releaseresourcessupported.Number != 22 || decodedTag_releaseresourcessupported.Constructed != false {
					return fmt.Errorf("decoding releaseResourcesSupported: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_releaseresourcessupported)
				}
				if len(rawVal_releaseresourcessupported) != 0 {
					return fmt.Errorf("decoding releaseResourcesSupported: %w: NULL content length %d", ber.ErrInvalidValue, len(rawVal_releaseresourcessupported))
				}
				v.ReleaseResourcesSupported = &struct{}{}
				offset += n_releaseresourcessupported
			}
		}
	}
	// Decode gsm-BearerCapability
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 23 {
				decodedTag_gsmbearercapability, n_gsmbearercapability, rawVal_gsmbearercapability, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding gsm-BearerCapability: %w", err)
				}
				if decodedTag_gsmbearercapability.Class != tag.ClassContextSpecific || decodedTag_gsmbearercapability.Number != 23 || decodedTag_gsmbearercapability.Constructed != true {
					return fmt.Errorf("decoding gsm-BearerCapability: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_gsmbearercapability)
				}
				reconstructed_gsmbearercapability := ber.EncodeSequence(rawVal_gsmbearercapability)
				var dec_gsmbearercapability ExternalSignalInfo
				if unmErr := dec_gsmbearercapability.UnmarshalBER(reconstructed_gsmbearercapability); unmErr != nil {
					return fmt.Errorf("decoding gsm-BearerCapability: %w", unmErr)
				}
				v.GsmBearerCapability = &dec_gsmbearercapability
				offset += n_gsmbearercapability
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "SendRoutingInfoRes", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes CCBSIndicators to BER format.
func (v *CCBSIndicators) MarshalBER() ([]byte, error) {
	var children []byte
	if v.CcbsPossible != nil {
		enc_ccbspossible := ber.EncodeNull()
		retagged_enc_ccbspossible, tagErr_enc_ccbspossible := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_ccbspossible)
		if tagErr_enc_ccbspossible != nil {
			return nil, fmt.Errorf("encoding ccbs-Possible: %w", tagErr_enc_ccbspossible)
		}
		enc_ccbspossible = retagged_enc_ccbspossible
		children = append(children, enc_ccbspossible...)
	}
	if v.KeepCCBSCallIndicator != nil {
		enc_keepccbscallindicator := ber.EncodeNull()
		retagged_enc_keepccbscallindicator, tagErr_enc_keepccbscallindicator := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_keepccbscallindicator)
		if tagErr_enc_keepccbscallindicator != nil {
			return nil, fmt.Errorf("encoding keepCCBS-CallIndicator: %w", tagErr_enc_keepccbscallindicator)
		}
		enc_keepccbscallindicator = retagged_enc_keepccbscallindicator
		children = append(children, enc_keepccbscallindicator...)
	}
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

// MarshalDER encodes CCBSIndicators to DER format.
func (v *CCBSIndicators) MarshalDER() ([]byte, error) {
	var children []byte
	if v.CcbsPossible != nil {
		enc_ccbspossible := ber.EncodeNull()
		retagged_enc_ccbspossible, tagErr_enc_ccbspossible := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_ccbspossible)
		if tagErr_enc_ccbspossible != nil {
			return nil, fmt.Errorf("encoding ccbs-Possible: %w", tagErr_enc_ccbspossible)
		}
		enc_ccbspossible = retagged_enc_ccbspossible
		children = append(children, enc_ccbspossible...)
	}
	if v.KeepCCBSCallIndicator != nil {
		enc_keepccbscallindicator := ber.EncodeNull()
		retagged_enc_keepccbscallindicator, tagErr_enc_keepccbscallindicator := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_keepccbscallindicator)
		if tagErr_enc_keepccbscallindicator != nil {
			return nil, fmt.Errorf("encoding keepCCBS-CallIndicator: %w", tagErr_enc_keepccbscallindicator)
		}
		enc_keepccbscallindicator = retagged_enc_keepccbscallindicator
		children = append(children, enc_keepccbscallindicator...)
	}
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
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
		children = append(children, ext...)
	}
	encoded := ber.EncodeSequence(children)
	if err := ber.ValidateDERElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding CCBSIndicators as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes CCBSIndicators from BER/DER format.
func (v *CCBSIndicators) UnmarshalBER(data []byte) error {
	*v = CCBSIndicators{}
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding CCBSIndicators SEQUENCE: %w", err)
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
				decodedTag_ccbspossible, n_ccbspossible, rawVal_ccbspossible, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding ccbs-Possible: %w", err)
				}
				if decodedTag_ccbspossible.Class != tag.ClassContextSpecific || decodedTag_ccbspossible.Number != 0 || decodedTag_ccbspossible.Constructed != false {
					return fmt.Errorf("decoding ccbs-Possible: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_ccbspossible)
				}
				if len(rawVal_ccbspossible) != 0 {
					return fmt.Errorf("decoding ccbs-Possible: %w: NULL content length %d", ber.ErrInvalidValue, len(rawVal_ccbspossible))
				}
				v.CcbsPossible = &struct{}{}
				offset += n_ccbspossible
			}
		}
	}
	// Decode keepCCBS-CallIndicator
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
				decodedTag_keepccbscallindicator, n_keepccbscallindicator, rawVal_keepccbscallindicator, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding keepCCBS-CallIndicator: %w", err)
				}
				if decodedTag_keepccbscallindicator.Class != tag.ClassContextSpecific || decodedTag_keepccbscallindicator.Number != 1 || decodedTag_keepccbscallindicator.Constructed != false {
					return fmt.Errorf("decoding keepCCBS-CallIndicator: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_keepccbscallindicator)
				}
				if len(rawVal_keepccbscallindicator) != 0 {
					return fmt.Errorf("decoding keepCCBS-CallIndicator: %w: NULL content length %d", ber.ErrInvalidValue, len(rawVal_keepccbscallindicator))
				}
				v.KeepCCBSCallIndicator = &struct{}{}
				offset += n_keepccbscallindicator
			}
		}
	}
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
			return &ber.DecodeError{Offset: offset, TypeName: "CCBSIndicators", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes RoutingInfo to BER format.
func (v *RoutingInfo) MarshalBER() ([]byte, error) {
	switch v.Choice {
	case RoutingInfoChoiceRoamingNumber:
		if v.RoamingNumber == nil {
			return nil, fmt.Errorf("choice RoutingInfo: roamingNumber is nil")
		}
		enc_0 := ber.EncodeOctetString([]byte(*v.RoamingNumber))
		return enc_0, nil
	case RoutingInfoChoiceForwardingData:
		if v.ForwardingData == nil {
			return nil, fmt.Errorf("choice RoutingInfo: forwardingData is nil")
		}
		enc_1, err := v.ForwardingData.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding forwardingData: %w", err)
		}
		return enc_1, nil
	default:
		return nil, fmt.Errorf("unknown choice %d for RoutingInfo", v.Choice)
	}
}

// MarshalDER encodes RoutingInfo to DER format.
func (v *RoutingInfo) MarshalDER() ([]byte, error) {
	switch v.Choice {
	case RoutingInfoChoiceForwardingData:
		if v.ForwardingData == nil {
			return nil, fmt.Errorf("choice RoutingInfo: forwardingData is nil")
		}
		enc_der_1, err := v.ForwardingData.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding forwardingData: %w", err)
		}
		if derErr := ber.ValidateDERElement(enc_der_1); derErr != nil {
			return nil, fmt.Errorf("encoding forwardingData as DER: %w", derErr)
		}
		return enc_der_1, nil
	}
	encoded, err := v.MarshalBER()
	if err != nil {
		return nil, err
	}
	if err := ber.ValidateDERElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding RoutingInfo as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes RoutingInfo from BER/DER format.
func (v *RoutingInfo) UnmarshalBER(data []byte) error {
	*v = RoutingInfo{}
	if len(data) == 0 {
		return fmt.Errorf("empty data for RoutingInfo CHOICE")
	}
	choiceData := data
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for RoutingInfo: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData)
	if tlvErr != nil {
		return fmt.Errorf("decoding RoutingInfo CHOICE: %w", tlvErr)
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "RoutingInfo", Cause: ber.ErrExtraData}
	}

	if peekTag.Class == tag.ClassUniversal && peekTag.Number == 4 {
		v.Choice = RoutingInfoChoiceRoamingNumber
		decVal, _, osErr := ber.DecodeOctetString(choiceData)
		if osErr != nil {
			return fmt.Errorf("decoding roamingNumber: %w", osErr)
		}
		tmp := ISDNAddressString(decVal)
		v.RoamingNumber = &tmp
	} else if peekTag.Class == tag.ClassUniversal && peekTag.Number == 16 && peekTag.Constructed == true {
		v.Choice = RoutingInfoChoiceForwardingData
		var dec ForwardingData
		if unmErr := dec.UnmarshalBER(choiceData); unmErr != nil {
			return fmt.Errorf("decoding forwardingData: %w", unmErr)
		}
		v.ForwardingData = &dec
	} else {
		return fmt.Errorf("unknown tag %s for RoutingInfo CHOICE", peekTag)
	}
	return nil
}

// MarshalBER encodes ForwardingData to BER format.
func (v *ForwardingData) MarshalBER() ([]byte, error) {
	var children []byte
	if v.ForwardedToNumber != nil {
		enc_forwardedtonumber := ber.EncodeOctetString([]byte(*v.ForwardedToNumber))
		retagged_enc_forwardedtonumber, tagErr_enc_forwardedtonumber := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 5, enc_forwardedtonumber)
		if tagErr_enc_forwardedtonumber != nil {
			return nil, fmt.Errorf("encoding forwardedToNumber: %w", tagErr_enc_forwardedtonumber)
		}
		enc_forwardedtonumber = retagged_enc_forwardedtonumber
		children = append(children, enc_forwardedtonumber...)
	}
	if v.ForwardedToSubaddress != nil {
		enc_forwardedtosubaddress := ber.EncodeOctetString([]byte(*v.ForwardedToSubaddress))
		retagged_enc_forwardedtosubaddress, tagErr_enc_forwardedtosubaddress := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, enc_forwardedtosubaddress)
		if tagErr_enc_forwardedtosubaddress != nil {
			return nil, fmt.Errorf("encoding forwardedToSubaddress: %w", tagErr_enc_forwardedtosubaddress)
		}
		enc_forwardedtosubaddress = retagged_enc_forwardedtosubaddress
		children = append(children, enc_forwardedtosubaddress...)
	}
	if v.ForwardingOptions != nil {
		enc_forwardingoptions := ber.EncodeOctetString([]byte(*v.ForwardingOptions))
		retagged_enc_forwardingoptions, tagErr_enc_forwardingoptions := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 6, enc_forwardingoptions)
		if tagErr_enc_forwardingoptions != nil {
			return nil, fmt.Errorf("encoding forwardingOptions: %w", tagErr_enc_forwardingoptions)
		}
		enc_forwardingoptions = retagged_enc_forwardingoptions
		children = append(children, enc_forwardingoptions...)
	}
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding extensionContainer: %w", err)
		}
		retagged_enc_extensioncontainer, tagErr_enc_extensioncontainer := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 7, enc_extensioncontainer)
		if tagErr_enc_extensioncontainer != nil {
			return nil, fmt.Errorf("encoding extensionContainer: %w", tagErr_enc_extensioncontainer)
		}
		enc_extensioncontainer = retagged_enc_extensioncontainer
		children = append(children, enc_extensioncontainer...)
	}
	if v.LongForwardedToNumber != nil {
		enc_longforwardedtonumber := ber.EncodeOctetString([]byte(*v.LongForwardedToNumber))
		retagged_enc_longforwardedtonumber, tagErr_enc_longforwardedtonumber := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 8, enc_longforwardedtonumber)
		if tagErr_enc_longforwardedtonumber != nil {
			return nil, fmt.Errorf("encoding longForwardedToNumber: %w", tagErr_enc_longforwardedtonumber)
		}
		enc_longforwardedtonumber = retagged_enc_longforwardedtonumber
		children = append(children, enc_longforwardedtonumber...)
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

// MarshalDER encodes ForwardingData to DER format.
func (v *ForwardingData) MarshalDER() ([]byte, error) {
	var children []byte
	if v.ForwardedToNumber != nil {
		enc_forwardedtonumber := ber.EncodeOctetString([]byte(*v.ForwardedToNumber))
		retagged_enc_forwardedtonumber, tagErr_enc_forwardedtonumber := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 5, enc_forwardedtonumber)
		if tagErr_enc_forwardedtonumber != nil {
			return nil, fmt.Errorf("encoding forwardedToNumber: %w", tagErr_enc_forwardedtonumber)
		}
		enc_forwardedtonumber = retagged_enc_forwardedtonumber
		children = append(children, enc_forwardedtonumber...)
	}
	if v.ForwardedToSubaddress != nil {
		enc_forwardedtosubaddress := ber.EncodeOctetString([]byte(*v.ForwardedToSubaddress))
		retagged_enc_forwardedtosubaddress, tagErr_enc_forwardedtosubaddress := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, enc_forwardedtosubaddress)
		if tagErr_enc_forwardedtosubaddress != nil {
			return nil, fmt.Errorf("encoding forwardedToSubaddress: %w", tagErr_enc_forwardedtosubaddress)
		}
		enc_forwardedtosubaddress = retagged_enc_forwardedtosubaddress
		children = append(children, enc_forwardedtosubaddress...)
	}
	if v.ForwardingOptions != nil {
		enc_forwardingoptions := ber.EncodeOctetString([]byte(*v.ForwardingOptions))
		retagged_enc_forwardingoptions, tagErr_enc_forwardingoptions := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 6, enc_forwardingoptions)
		if tagErr_enc_forwardingoptions != nil {
			return nil, fmt.Errorf("encoding forwardingOptions: %w", tagErr_enc_forwardingoptions)
		}
		enc_forwardingoptions = retagged_enc_forwardingoptions
		children = append(children, enc_forwardingoptions...)
	}
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding extensionContainer: %w", err)
		}
		retagged_enc_extensioncontainer, tagErr_enc_extensioncontainer := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 7, enc_extensioncontainer)
		if tagErr_enc_extensioncontainer != nil {
			return nil, fmt.Errorf("encoding extensionContainer: %w", tagErr_enc_extensioncontainer)
		}
		enc_extensioncontainer = retagged_enc_extensioncontainer
		children = append(children, enc_extensioncontainer...)
	}
	if v.LongForwardedToNumber != nil {
		enc_longforwardedtonumber := ber.EncodeOctetString([]byte(*v.LongForwardedToNumber))
		retagged_enc_longforwardedtonumber, tagErr_enc_longforwardedtonumber := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 8, enc_longforwardedtonumber)
		if tagErr_enc_longforwardedtonumber != nil {
			return nil, fmt.Errorf("encoding longForwardedToNumber: %w", tagErr_enc_longforwardedtonumber)
		}
		enc_longforwardedtonumber = retagged_enc_longforwardedtonumber
		children = append(children, enc_longforwardedtonumber...)
	}
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
		children = append(children, ext...)
	}
	encoded := ber.EncodeSequence(children)
	if err := ber.ValidateDERElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding ForwardingData as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes ForwardingData from BER/DER format.
func (v *ForwardingData) UnmarshalBER(data []byte) error {
	*v = ForwardingData{}
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding ForwardingData SEQUENCE: %w", err)
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
				decodedTag_forwardedtonumber, n_forwardedtonumber, rawVal_forwardedtonumber, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding forwardedToNumber: %w", err)
				}
				if decodedTag_forwardedtonumber.Class != tag.ClassContextSpecific || decodedTag_forwardedtonumber.Number != 5 {
					return fmt.Errorf("decoding forwardedToNumber: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_forwardedtonumber)
				}
				tmp_forwardedtonumber := ISDNAddressString(rawVal_forwardedtonumber)
				v.ForwardedToNumber = &tmp_forwardedtonumber
				offset += n_forwardedtonumber
			}
		}
	}
	// Decode forwardedToSubaddress
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4 {
				decodedTag_forwardedtosubaddress, n_forwardedtosubaddress, rawVal_forwardedtosubaddress, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding forwardedToSubaddress: %w", err)
				}
				if decodedTag_forwardedtosubaddress.Class != tag.ClassContextSpecific || decodedTag_forwardedtosubaddress.Number != 4 {
					return fmt.Errorf("decoding forwardedToSubaddress: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_forwardedtosubaddress)
				}
				tmp_forwardedtosubaddress := ISDNSubaddressString(rawVal_forwardedtosubaddress)
				v.ForwardedToSubaddress = &tmp_forwardedtosubaddress
				offset += n_forwardedtosubaddress
			}
		}
	}
	// Decode forwardingOptions
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 6 {
				decodedTag_forwardingoptions, n_forwardingoptions, rawVal_forwardingoptions, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding forwardingOptions: %w", err)
				}
				if decodedTag_forwardingoptions.Class != tag.ClassContextSpecific || decodedTag_forwardingoptions.Number != 6 {
					return fmt.Errorf("decoding forwardingOptions: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_forwardingoptions)
				}
				tmp_forwardingoptions := ForwardingOptions(rawVal_forwardingoptions)
				v.ForwardingOptions = &tmp_forwardingoptions
				offset += n_forwardingoptions
			}
		}
	}
	// Decode extensionContainer
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 7 {
				decodedTag_extensioncontainer, n_extensioncontainer, rawVal_extensioncontainer, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding extensionContainer: %w", err)
				}
				if decodedTag_extensioncontainer.Class != tag.ClassContextSpecific || decodedTag_extensioncontainer.Number != 7 || decodedTag_extensioncontainer.Constructed != true {
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
	// Decode longForwardedToNumber
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 8 {
				decodedTag_longforwardedtonumber, n_longforwardedtonumber, rawVal_longforwardedtonumber, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding longForwardedToNumber: %w", err)
				}
				if decodedTag_longforwardedtonumber.Class != tag.ClassContextSpecific || decodedTag_longforwardedtonumber.Number != 8 {
					return fmt.Errorf("decoding longForwardedToNumber: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_longforwardedtonumber)
				}
				tmp_longforwardedtonumber := FTNAddressString(rawVal_longforwardedtonumber)
				v.LongForwardedToNumber = &tmp_longforwardedtonumber
				offset += n_longforwardedtonumber
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "ForwardingData", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes ProvideRoamingNumberArg to BER format.
func (v *ProvideRoamingNumberArg) MarshalBER() ([]byte, error) {
	var children []byte
	enc_imsi := ber.EncodeOctetString([]byte(v.Imsi))
	retagged_enc_imsi, tagErr_enc_imsi := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_imsi)
	if tagErr_enc_imsi != nil {
		return nil, fmt.Errorf("encoding imsi: %w", tagErr_enc_imsi)
	}
	enc_imsi = retagged_enc_imsi
	children = append(children, enc_imsi...)
	enc_mscnumber := ber.EncodeOctetString([]byte(v.MscNumber))
	retagged_enc_mscnumber, tagErr_enc_mscnumber := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_mscnumber)
	if tagErr_enc_mscnumber != nil {
		return nil, fmt.Errorf("encoding msc-Number: %w", tagErr_enc_mscnumber)
	}
	enc_mscnumber = retagged_enc_mscnumber
	children = append(children, enc_mscnumber...)
	if v.Msisdn != nil {
		enc_msisdn := ber.EncodeOctetString([]byte(*v.Msisdn))
		retagged_enc_msisdn, tagErr_enc_msisdn := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_msisdn)
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
	if v.GsmBearerCapability != nil {
		enc_gsmbearercapability, err := v.GsmBearerCapability.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding gsm-BearerCapability: %w", err)
		}
		retagged_enc_gsmbearercapability, tagErr_enc_gsmbearercapability := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 5, enc_gsmbearercapability)
		if tagErr_enc_gsmbearercapability != nil {
			return nil, fmt.Errorf("encoding gsm-BearerCapability: %w", tagErr_enc_gsmbearercapability)
		}
		enc_gsmbearercapability = retagged_enc_gsmbearercapability
		children = append(children, enc_gsmbearercapability...)
	}
	if v.NetworkSignalInfo != nil {
		enc_networksignalinfo, err := v.NetworkSignalInfo.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding networkSignalInfo: %w", err)
		}
		retagged_enc_networksignalinfo, tagErr_enc_networksignalinfo := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 6, enc_networksignalinfo)
		if tagErr_enc_networksignalinfo != nil {
			return nil, fmt.Errorf("encoding networkSignalInfo: %w", tagErr_enc_networksignalinfo)
		}
		enc_networksignalinfo = retagged_enc_networksignalinfo
		children = append(children, enc_networksignalinfo...)
	}
	if v.SuppressionOfAnnouncement != nil {
		enc_suppressionofannouncement := ber.EncodeNull()
		retagged_enc_suppressionofannouncement, tagErr_enc_suppressionofannouncement := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 7, enc_suppressionofannouncement)
		if tagErr_enc_suppressionofannouncement != nil {
			return nil, fmt.Errorf("encoding suppressionOfAnnouncement: %w", tagErr_enc_suppressionofannouncement)
		}
		enc_suppressionofannouncement = retagged_enc_suppressionofannouncement
		children = append(children, enc_suppressionofannouncement...)
	}
	if v.GmscAddress != nil {
		enc_gmscaddress := ber.EncodeOctetString([]byte(*v.GmscAddress))
		retagged_enc_gmscaddress, tagErr_enc_gmscaddress := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 8, enc_gmscaddress)
		if tagErr_enc_gmscaddress != nil {
			return nil, fmt.Errorf("encoding gmsc-Address: %w", tagErr_enc_gmscaddress)
		}
		enc_gmscaddress = retagged_enc_gmscaddress
		children = append(children, enc_gmscaddress...)
	}
	if v.CallReferenceNumber != nil {
		enc_callreferencenumber := ber.EncodeOctetString([]byte(*v.CallReferenceNumber))
		retagged_enc_callreferencenumber, tagErr_enc_callreferencenumber := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 9, enc_callreferencenumber)
		if tagErr_enc_callreferencenumber != nil {
			return nil, fmt.Errorf("encoding callReferenceNumber: %w", tagErr_enc_callreferencenumber)
		}
		enc_callreferencenumber = retagged_enc_callreferencenumber
		children = append(children, enc_callreferencenumber...)
	}
	if v.OrInterrogation != nil {
		enc_orinterrogation := ber.EncodeNull()
		retagged_enc_orinterrogation, tagErr_enc_orinterrogation := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 10, enc_orinterrogation)
		if tagErr_enc_orinterrogation != nil {
			return nil, fmt.Errorf("encoding or-Interrogation: %w", tagErr_enc_orinterrogation)
		}
		enc_orinterrogation = retagged_enc_orinterrogation
		children = append(children, enc_orinterrogation...)
	}
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding extensionContainer: %w", err)
		}
		retagged_enc_extensioncontainer, tagErr_enc_extensioncontainer := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 11, enc_extensioncontainer)
		if tagErr_enc_extensioncontainer != nil {
			return nil, fmt.Errorf("encoding extensionContainer: %w", tagErr_enc_extensioncontainer)
		}
		enc_extensioncontainer = retagged_enc_extensioncontainer
		children = append(children, enc_extensioncontainer...)
	}
	if v.AlertingPattern != nil {
		enc_alertingpattern := ber.EncodeOctetString([]byte(*v.AlertingPattern))
		retagged_enc_alertingpattern, tagErr_enc_alertingpattern := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 12, enc_alertingpattern)
		if tagErr_enc_alertingpattern != nil {
			return nil, fmt.Errorf("encoding alertingPattern: %w", tagErr_enc_alertingpattern)
		}
		enc_alertingpattern = retagged_enc_alertingpattern
		children = append(children, enc_alertingpattern...)
	}
	if v.CcbsCall != nil {
		enc_ccbscall := ber.EncodeNull()
		retagged_enc_ccbscall, tagErr_enc_ccbscall := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 13, enc_ccbscall)
		if tagErr_enc_ccbscall != nil {
			return nil, fmt.Errorf("encoding ccbs-Call: %w", tagErr_enc_ccbscall)
		}
		enc_ccbscall = retagged_enc_ccbscall
		children = append(children, enc_ccbscall...)
	}
	if v.SupportedCamelPhasesInInterrogatingNode != nil {
		enc_supportedcamelphasesininterrogatingnode := ber.EncodeBitString(v.SupportedCamelPhasesInInterrogatingNode.Bytes, (8-(v.SupportedCamelPhasesInInterrogatingNode.BitLength%8))%8)
		retagged_enc_supportedcamelphasesininterrogatingnode, tagErr_enc_supportedcamelphasesininterrogatingnode := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 15, enc_supportedcamelphasesininterrogatingnode)
		if tagErr_enc_supportedcamelphasesininterrogatingnode != nil {
			return nil, fmt.Errorf("encoding supportedCamelPhasesInInterrogatingNode: %w", tagErr_enc_supportedcamelphasesininterrogatingnode)
		}
		enc_supportedcamelphasesininterrogatingnode = retagged_enc_supportedcamelphasesininterrogatingnode
		children = append(children, enc_supportedcamelphasesininterrogatingnode...)
	}
	if v.AdditionalSignalInfo != nil {
		enc_additionalsignalinfo, err := v.AdditionalSignalInfo.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding additionalSignalInfo: %w", err)
		}
		retagged_enc_additionalsignalinfo, tagErr_enc_additionalsignalinfo := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 14, enc_additionalsignalinfo)
		if tagErr_enc_additionalsignalinfo != nil {
			return nil, fmt.Errorf("encoding additionalSignalInfo: %w", tagErr_enc_additionalsignalinfo)
		}
		enc_additionalsignalinfo = retagged_enc_additionalsignalinfo
		children = append(children, enc_additionalsignalinfo...)
	}
	if v.OrNotSupportedInGMSC != nil {
		enc_ornotsupportedingmsc := ber.EncodeNull()
		retagged_enc_ornotsupportedingmsc, tagErr_enc_ornotsupportedingmsc := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 16, enc_ornotsupportedingmsc)
		if tagErr_enc_ornotsupportedingmsc != nil {
			return nil, fmt.Errorf("encoding orNotSupportedInGMSC: %w", tagErr_enc_ornotsupportedingmsc)
		}
		enc_ornotsupportedingmsc = retagged_enc_ornotsupportedingmsc
		children = append(children, enc_ornotsupportedingmsc...)
	}
	if v.PrePagingSupported != nil {
		enc_prepagingsupported := ber.EncodeNull()
		retagged_enc_prepagingsupported, tagErr_enc_prepagingsupported := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 17, enc_prepagingsupported)
		if tagErr_enc_prepagingsupported != nil {
			return nil, fmt.Errorf("encoding pre-pagingSupported: %w", tagErr_enc_prepagingsupported)
		}
		enc_prepagingsupported = retagged_enc_prepagingsupported
		children = append(children, enc_prepagingsupported...)
	}
	if v.LongFTNSupported != nil {
		enc_longftnsupported := ber.EncodeNull()
		retagged_enc_longftnsupported, tagErr_enc_longftnsupported := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 18, enc_longftnsupported)
		if tagErr_enc_longftnsupported != nil {
			return nil, fmt.Errorf("encoding longFTN-Supported: %w", tagErr_enc_longftnsupported)
		}
		enc_longftnsupported = retagged_enc_longftnsupported
		children = append(children, enc_longftnsupported...)
	}
	if v.SuppressVTCSI != nil {
		enc_suppressvtcsi := ber.EncodeNull()
		retagged_enc_suppressvtcsi, tagErr_enc_suppressvtcsi := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 19, enc_suppressvtcsi)
		if tagErr_enc_suppressvtcsi != nil {
			return nil, fmt.Errorf("encoding suppress-VT-CSI: %w", tagErr_enc_suppressvtcsi)
		}
		enc_suppressvtcsi = retagged_enc_suppressvtcsi
		children = append(children, enc_suppressvtcsi...)
	}
	if v.OfferedCamel4CSIsInInterrogatingNode != nil {
		enc_offeredcamel4csisininterrogatingnode := ber.EncodeBitString(v.OfferedCamel4CSIsInInterrogatingNode.Bytes, (8-(v.OfferedCamel4CSIsInInterrogatingNode.BitLength%8))%8)
		retagged_enc_offeredcamel4csisininterrogatingnode, tagErr_enc_offeredcamel4csisininterrogatingnode := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 20, enc_offeredcamel4csisininterrogatingnode)
		if tagErr_enc_offeredcamel4csisininterrogatingnode != nil {
			return nil, fmt.Errorf("encoding offeredCamel4CSIsInInterrogatingNode: %w", tagErr_enc_offeredcamel4csisininterrogatingnode)
		}
		enc_offeredcamel4csisininterrogatingnode = retagged_enc_offeredcamel4csisininterrogatingnode
		children = append(children, enc_offeredcamel4csisininterrogatingnode...)
	}
	if v.MtRoamingRetrySupported != nil {
		enc_mtroamingretrysupported := ber.EncodeNull()
		retagged_enc_mtroamingretrysupported, tagErr_enc_mtroamingretrysupported := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 21, enc_mtroamingretrysupported)
		if tagErr_enc_mtroamingretrysupported != nil {
			return nil, fmt.Errorf("encoding mtRoamingRetrySupported: %w", tagErr_enc_mtroamingretrysupported)
		}
		enc_mtroamingretrysupported = retagged_enc_mtroamingretrysupported
		children = append(children, enc_mtroamingretrysupported...)
	}
	if v.PagingArea != nil {
		enc_pagingarea, err := MarshalBERPagingArea(v.PagingArea)
		if err != nil {
			return nil, fmt.Errorf("encoding pagingArea: %w", err)
		}
		if v.PagingAreaIndef_ {
			// Strip the outer SEQUENCE tag from marshalBER output to get raw children.
			_, _, seqContent_, tlvErr_ := ber.DecodeTLV(enc_pagingarea)
			if tlvErr_ != nil {
				return nil, tlvErr_
			}
			enc_pagingarea = ber.EncodeConstructedIndefinite(tag.Tag{Class: tag.ClassContextSpecific, Number: 22}, seqContent_)
		} else {
			retagged_enc_pagingarea, tagErr_enc_pagingarea := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 22, enc_pagingarea)
			if tagErr_enc_pagingarea != nil {
				return nil, fmt.Errorf("encoding pagingArea: %w", tagErr_enc_pagingarea)
			}
			enc_pagingarea = retagged_enc_pagingarea
		}
		children = append(children, enc_pagingarea...)
	}
	if v.CallPriority != nil {
		enc_callpriority := ber.EncodeInteger(int64(*v.CallPriority))
		retagged_enc_callpriority, tagErr_enc_callpriority := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 23, enc_callpriority)
		if tagErr_enc_callpriority != nil {
			return nil, fmt.Errorf("encoding callPriority: %w", tagErr_enc_callpriority)
		}
		enc_callpriority = retagged_enc_callpriority
		children = append(children, enc_callpriority...)
	}
	if v.MtrfIndicator != nil {
		enc_mtrfindicator := ber.EncodeNull()
		retagged_enc_mtrfindicator, tagErr_enc_mtrfindicator := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 24, enc_mtrfindicator)
		if tagErr_enc_mtrfindicator != nil {
			return nil, fmt.Errorf("encoding mtrf-Indicator: %w", tagErr_enc_mtrfindicator)
		}
		enc_mtrfindicator = retagged_enc_mtrfindicator
		children = append(children, enc_mtrfindicator...)
	}
	if v.OldMSCNumber != nil {
		enc_oldmscnumber := ber.EncodeOctetString([]byte(*v.OldMSCNumber))
		retagged_enc_oldmscnumber, tagErr_enc_oldmscnumber := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 25, enc_oldmscnumber)
		if tagErr_enc_oldmscnumber != nil {
			return nil, fmt.Errorf("encoding oldMSC-Number: %w", tagErr_enc_oldmscnumber)
		}
		enc_oldmscnumber = retagged_enc_oldmscnumber
		children = append(children, enc_oldmscnumber...)
	}
	if v.LastUsedLtePLMNId != nil {
		enc_lastusedlteplmnid := ber.EncodeOctetString([]byte(*v.LastUsedLtePLMNId))
		retagged_enc_lastusedlteplmnid, tagErr_enc_lastusedlteplmnid := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 26, enc_lastusedlteplmnid)
		if tagErr_enc_lastusedlteplmnid != nil {
			return nil, fmt.Errorf("encoding lastUsedLtePLMN-Id: %w", tagErr_enc_lastusedlteplmnid)
		}
		enc_lastusedlteplmnid = retagged_enc_lastusedlteplmnid
		children = append(children, enc_lastusedlteplmnid...)
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

// MarshalDER encodes ProvideRoamingNumberArg to DER format.
func (v *ProvideRoamingNumberArg) MarshalDER() ([]byte, error) {
	var children []byte
	enc_imsi := ber.EncodeOctetString([]byte(v.Imsi))
	retagged_enc_imsi, tagErr_enc_imsi := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_imsi)
	if tagErr_enc_imsi != nil {
		return nil, fmt.Errorf("encoding imsi: %w", tagErr_enc_imsi)
	}
	enc_imsi = retagged_enc_imsi
	children = append(children, enc_imsi...)
	enc_mscnumber := ber.EncodeOctetString([]byte(v.MscNumber))
	retagged_enc_mscnumber, tagErr_enc_mscnumber := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_mscnumber)
	if tagErr_enc_mscnumber != nil {
		return nil, fmt.Errorf("encoding msc-Number: %w", tagErr_enc_mscnumber)
	}
	enc_mscnumber = retagged_enc_mscnumber
	children = append(children, enc_mscnumber...)
	if v.Msisdn != nil {
		enc_msisdn := ber.EncodeOctetString([]byte(*v.Msisdn))
		retagged_enc_msisdn, tagErr_enc_msisdn := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_msisdn)
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
	if v.GsmBearerCapability != nil {
		enc_gsmbearercapability, err := v.GsmBearerCapability.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding gsm-BearerCapability: %w", err)
		}
		retagged_enc_gsmbearercapability, tagErr_enc_gsmbearercapability := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 5, enc_gsmbearercapability)
		if tagErr_enc_gsmbearercapability != nil {
			return nil, fmt.Errorf("encoding gsm-BearerCapability: %w", tagErr_enc_gsmbearercapability)
		}
		enc_gsmbearercapability = retagged_enc_gsmbearercapability
		children = append(children, enc_gsmbearercapability...)
	}
	if v.NetworkSignalInfo != nil {
		enc_networksignalinfo, err := v.NetworkSignalInfo.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding networkSignalInfo: %w", err)
		}
		retagged_enc_networksignalinfo, tagErr_enc_networksignalinfo := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 6, enc_networksignalinfo)
		if tagErr_enc_networksignalinfo != nil {
			return nil, fmt.Errorf("encoding networkSignalInfo: %w", tagErr_enc_networksignalinfo)
		}
		enc_networksignalinfo = retagged_enc_networksignalinfo
		children = append(children, enc_networksignalinfo...)
	}
	if v.SuppressionOfAnnouncement != nil {
		enc_suppressionofannouncement := ber.EncodeNull()
		retagged_enc_suppressionofannouncement, tagErr_enc_suppressionofannouncement := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 7, enc_suppressionofannouncement)
		if tagErr_enc_suppressionofannouncement != nil {
			return nil, fmt.Errorf("encoding suppressionOfAnnouncement: %w", tagErr_enc_suppressionofannouncement)
		}
		enc_suppressionofannouncement = retagged_enc_suppressionofannouncement
		children = append(children, enc_suppressionofannouncement...)
	}
	if v.GmscAddress != nil {
		enc_gmscaddress := ber.EncodeOctetString([]byte(*v.GmscAddress))
		retagged_enc_gmscaddress, tagErr_enc_gmscaddress := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 8, enc_gmscaddress)
		if tagErr_enc_gmscaddress != nil {
			return nil, fmt.Errorf("encoding gmsc-Address: %w", tagErr_enc_gmscaddress)
		}
		enc_gmscaddress = retagged_enc_gmscaddress
		children = append(children, enc_gmscaddress...)
	}
	if v.CallReferenceNumber != nil {
		enc_callreferencenumber := ber.EncodeOctetString([]byte(*v.CallReferenceNumber))
		retagged_enc_callreferencenumber, tagErr_enc_callreferencenumber := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 9, enc_callreferencenumber)
		if tagErr_enc_callreferencenumber != nil {
			return nil, fmt.Errorf("encoding callReferenceNumber: %w", tagErr_enc_callreferencenumber)
		}
		enc_callreferencenumber = retagged_enc_callreferencenumber
		children = append(children, enc_callreferencenumber...)
	}
	if v.OrInterrogation != nil {
		enc_orinterrogation := ber.EncodeNull()
		retagged_enc_orinterrogation, tagErr_enc_orinterrogation := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 10, enc_orinterrogation)
		if tagErr_enc_orinterrogation != nil {
			return nil, fmt.Errorf("encoding or-Interrogation: %w", tagErr_enc_orinterrogation)
		}
		enc_orinterrogation = retagged_enc_orinterrogation
		children = append(children, enc_orinterrogation...)
	}
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding extensionContainer: %w", err)
		}
		retagged_enc_extensioncontainer, tagErr_enc_extensioncontainer := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 11, enc_extensioncontainer)
		if tagErr_enc_extensioncontainer != nil {
			return nil, fmt.Errorf("encoding extensionContainer: %w", tagErr_enc_extensioncontainer)
		}
		enc_extensioncontainer = retagged_enc_extensioncontainer
		children = append(children, enc_extensioncontainer...)
	}
	if v.AlertingPattern != nil {
		enc_alertingpattern := ber.EncodeOctetString([]byte(*v.AlertingPattern))
		retagged_enc_alertingpattern, tagErr_enc_alertingpattern := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 12, enc_alertingpattern)
		if tagErr_enc_alertingpattern != nil {
			return nil, fmt.Errorf("encoding alertingPattern: %w", tagErr_enc_alertingpattern)
		}
		enc_alertingpattern = retagged_enc_alertingpattern
		children = append(children, enc_alertingpattern...)
	}
	if v.CcbsCall != nil {
		enc_ccbscall := ber.EncodeNull()
		retagged_enc_ccbscall, tagErr_enc_ccbscall := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 13, enc_ccbscall)
		if tagErr_enc_ccbscall != nil {
			return nil, fmt.Errorf("encoding ccbs-Call: %w", tagErr_enc_ccbscall)
		}
		enc_ccbscall = retagged_enc_ccbscall
		children = append(children, enc_ccbscall...)
	}
	if v.SupportedCamelPhasesInInterrogatingNode != nil {
		enc_supportedcamelphasesininterrogatingnode := ber.EncodeBitString(v.SupportedCamelPhasesInInterrogatingNode.Bytes, (8-(v.SupportedCamelPhasesInInterrogatingNode.BitLength%8))%8)
		retagged_enc_supportedcamelphasesininterrogatingnode, tagErr_enc_supportedcamelphasesininterrogatingnode := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 15, enc_supportedcamelphasesininterrogatingnode)
		if tagErr_enc_supportedcamelphasesininterrogatingnode != nil {
			return nil, fmt.Errorf("encoding supportedCamelPhasesInInterrogatingNode: %w", tagErr_enc_supportedcamelphasesininterrogatingnode)
		}
		enc_supportedcamelphasesininterrogatingnode = retagged_enc_supportedcamelphasesininterrogatingnode
		children = append(children, enc_supportedcamelphasesininterrogatingnode...)
	}
	if v.AdditionalSignalInfo != nil {
		enc_additionalsignalinfo, err := v.AdditionalSignalInfo.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding additionalSignalInfo: %w", err)
		}
		retagged_enc_additionalsignalinfo, tagErr_enc_additionalsignalinfo := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 14, enc_additionalsignalinfo)
		if tagErr_enc_additionalsignalinfo != nil {
			return nil, fmt.Errorf("encoding additionalSignalInfo: %w", tagErr_enc_additionalsignalinfo)
		}
		enc_additionalsignalinfo = retagged_enc_additionalsignalinfo
		children = append(children, enc_additionalsignalinfo...)
	}
	if v.OrNotSupportedInGMSC != nil {
		enc_ornotsupportedingmsc := ber.EncodeNull()
		retagged_enc_ornotsupportedingmsc, tagErr_enc_ornotsupportedingmsc := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 16, enc_ornotsupportedingmsc)
		if tagErr_enc_ornotsupportedingmsc != nil {
			return nil, fmt.Errorf("encoding orNotSupportedInGMSC: %w", tagErr_enc_ornotsupportedingmsc)
		}
		enc_ornotsupportedingmsc = retagged_enc_ornotsupportedingmsc
		children = append(children, enc_ornotsupportedingmsc...)
	}
	if v.PrePagingSupported != nil {
		enc_prepagingsupported := ber.EncodeNull()
		retagged_enc_prepagingsupported, tagErr_enc_prepagingsupported := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 17, enc_prepagingsupported)
		if tagErr_enc_prepagingsupported != nil {
			return nil, fmt.Errorf("encoding pre-pagingSupported: %w", tagErr_enc_prepagingsupported)
		}
		enc_prepagingsupported = retagged_enc_prepagingsupported
		children = append(children, enc_prepagingsupported...)
	}
	if v.LongFTNSupported != nil {
		enc_longftnsupported := ber.EncodeNull()
		retagged_enc_longftnsupported, tagErr_enc_longftnsupported := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 18, enc_longftnsupported)
		if tagErr_enc_longftnsupported != nil {
			return nil, fmt.Errorf("encoding longFTN-Supported: %w", tagErr_enc_longftnsupported)
		}
		enc_longftnsupported = retagged_enc_longftnsupported
		children = append(children, enc_longftnsupported...)
	}
	if v.SuppressVTCSI != nil {
		enc_suppressvtcsi := ber.EncodeNull()
		retagged_enc_suppressvtcsi, tagErr_enc_suppressvtcsi := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 19, enc_suppressvtcsi)
		if tagErr_enc_suppressvtcsi != nil {
			return nil, fmt.Errorf("encoding suppress-VT-CSI: %w", tagErr_enc_suppressvtcsi)
		}
		enc_suppressvtcsi = retagged_enc_suppressvtcsi
		children = append(children, enc_suppressvtcsi...)
	}
	if v.OfferedCamel4CSIsInInterrogatingNode != nil {
		enc_offeredcamel4csisininterrogatingnode := ber.EncodeBitString(v.OfferedCamel4CSIsInInterrogatingNode.Bytes, (8-(v.OfferedCamel4CSIsInInterrogatingNode.BitLength%8))%8)
		retagged_enc_offeredcamel4csisininterrogatingnode, tagErr_enc_offeredcamel4csisininterrogatingnode := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 20, enc_offeredcamel4csisininterrogatingnode)
		if tagErr_enc_offeredcamel4csisininterrogatingnode != nil {
			return nil, fmt.Errorf("encoding offeredCamel4CSIsInInterrogatingNode: %w", tagErr_enc_offeredcamel4csisininterrogatingnode)
		}
		enc_offeredcamel4csisininterrogatingnode = retagged_enc_offeredcamel4csisininterrogatingnode
		children = append(children, enc_offeredcamel4csisininterrogatingnode...)
	}
	if v.MtRoamingRetrySupported != nil {
		enc_mtroamingretrysupported := ber.EncodeNull()
		retagged_enc_mtroamingretrysupported, tagErr_enc_mtroamingretrysupported := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 21, enc_mtroamingretrysupported)
		if tagErr_enc_mtroamingretrysupported != nil {
			return nil, fmt.Errorf("encoding mtRoamingRetrySupported: %w", tagErr_enc_mtroamingretrysupported)
		}
		enc_mtroamingretrysupported = retagged_enc_mtroamingretrysupported
		children = append(children, enc_mtroamingretrysupported...)
	}
	if v.PagingArea != nil {
		enc_pagingarea, err := MarshalDERPagingArea(v.PagingArea)
		if err != nil {
			return nil, fmt.Errorf("encoding pagingArea: %w", err)
		}
		retagged_enc_pagingarea, tagErr_enc_pagingarea := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 22, enc_pagingarea)
		if tagErr_enc_pagingarea != nil {
			return nil, fmt.Errorf("encoding pagingArea: %w", tagErr_enc_pagingarea)
		}
		enc_pagingarea = retagged_enc_pagingarea
		children = append(children, enc_pagingarea...)
	}
	if v.CallPriority != nil {
		enc_callpriority := ber.EncodeInteger(int64(*v.CallPriority))
		retagged_enc_callpriority, tagErr_enc_callpriority := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 23, enc_callpriority)
		if tagErr_enc_callpriority != nil {
			return nil, fmt.Errorf("encoding callPriority: %w", tagErr_enc_callpriority)
		}
		enc_callpriority = retagged_enc_callpriority
		children = append(children, enc_callpriority...)
	}
	if v.MtrfIndicator != nil {
		enc_mtrfindicator := ber.EncodeNull()
		retagged_enc_mtrfindicator, tagErr_enc_mtrfindicator := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 24, enc_mtrfindicator)
		if tagErr_enc_mtrfindicator != nil {
			return nil, fmt.Errorf("encoding mtrf-Indicator: %w", tagErr_enc_mtrfindicator)
		}
		enc_mtrfindicator = retagged_enc_mtrfindicator
		children = append(children, enc_mtrfindicator...)
	}
	if v.OldMSCNumber != nil {
		enc_oldmscnumber := ber.EncodeOctetString([]byte(*v.OldMSCNumber))
		retagged_enc_oldmscnumber, tagErr_enc_oldmscnumber := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 25, enc_oldmscnumber)
		if tagErr_enc_oldmscnumber != nil {
			return nil, fmt.Errorf("encoding oldMSC-Number: %w", tagErr_enc_oldmscnumber)
		}
		enc_oldmscnumber = retagged_enc_oldmscnumber
		children = append(children, enc_oldmscnumber...)
	}
	if v.LastUsedLtePLMNId != nil {
		enc_lastusedlteplmnid := ber.EncodeOctetString([]byte(*v.LastUsedLtePLMNId))
		retagged_enc_lastusedlteplmnid, tagErr_enc_lastusedlteplmnid := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 26, enc_lastusedlteplmnid)
		if tagErr_enc_lastusedlteplmnid != nil {
			return nil, fmt.Errorf("encoding lastUsedLtePLMN-Id: %w", tagErr_enc_lastusedlteplmnid)
		}
		enc_lastusedlteplmnid = retagged_enc_lastusedlteplmnid
		children = append(children, enc_lastusedlteplmnid...)
	}
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
		children = append(children, ext...)
	}
	encoded := ber.EncodeSequence(children)
	if err := ber.ValidateDERElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding ProvideRoamingNumberArg as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes ProvideRoamingNumberArg from BER/DER format.
func (v *ProvideRoamingNumberArg) UnmarshalBER(data []byte) error {
	*v = ProvideRoamingNumberArg{}
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding ProvideRoamingNumberArg SEQUENCE: %w", err)
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
	decodedTag_imsi, n_imsi, rawVal_imsi, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding imsi: %w", err)
	}
	if decodedTag_imsi.Class != tag.ClassContextSpecific || decodedTag_imsi.Number != 0 {
		return fmt.Errorf("decoding imsi: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_imsi)
	}
	v.Imsi = IMSI(rawVal_imsi)
	offset += n_imsi
	// Decode msc-Number
	if offset >= len(content) {
		return fmt.Errorf("missing required field msc-Number")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 1 {
			return fmt.Errorf("expected tag [%s %d] for msc-Number, got %s", "CONTEXT", 1, reqTag_)
		}
	}
	decodedTag_mscnumber, n_mscnumber, rawVal_mscnumber, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding msc-Number: %w", err)
	}
	if decodedTag_mscnumber.Class != tag.ClassContextSpecific || decodedTag_mscnumber.Number != 1 {
		return fmt.Errorf("decoding msc-Number: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_mscnumber)
	}
	v.MscNumber = ISDNAddressString(rawVal_mscnumber)
	offset += n_mscnumber
	// Decode msisdn
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2 {
				decodedTag_msisdn, n_msisdn, rawVal_msisdn, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding msisdn: %w", err)
				}
				if decodedTag_msisdn.Class != tag.ClassContextSpecific || decodedTag_msisdn.Number != 2 {
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
	// Decode gsm-BearerCapability
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 5 {
				decodedTag_gsmbearercapability, n_gsmbearercapability, rawVal_gsmbearercapability, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding gsm-BearerCapability: %w", err)
				}
				if decodedTag_gsmbearercapability.Class != tag.ClassContextSpecific || decodedTag_gsmbearercapability.Number != 5 || decodedTag_gsmbearercapability.Constructed != true {
					return fmt.Errorf("decoding gsm-BearerCapability: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_gsmbearercapability)
				}
				reconstructed_gsmbearercapability := ber.EncodeSequence(rawVal_gsmbearercapability)
				var dec_gsmbearercapability ExternalSignalInfo
				if unmErr := dec_gsmbearercapability.UnmarshalBER(reconstructed_gsmbearercapability); unmErr != nil {
					return fmt.Errorf("decoding gsm-BearerCapability: %w", unmErr)
				}
				v.GsmBearerCapability = &dec_gsmbearercapability
				offset += n_gsmbearercapability
			}
		}
	}
	// Decode networkSignalInfo
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 6 {
				decodedTag_networksignalinfo, n_networksignalinfo, rawVal_networksignalinfo, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding networkSignalInfo: %w", err)
				}
				if decodedTag_networksignalinfo.Class != tag.ClassContextSpecific || decodedTag_networksignalinfo.Number != 6 || decodedTag_networksignalinfo.Constructed != true {
					return fmt.Errorf("decoding networkSignalInfo: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_networksignalinfo)
				}
				reconstructed_networksignalinfo := ber.EncodeSequence(rawVal_networksignalinfo)
				var dec_networksignalinfo ExternalSignalInfo
				if unmErr := dec_networksignalinfo.UnmarshalBER(reconstructed_networksignalinfo); unmErr != nil {
					return fmt.Errorf("decoding networkSignalInfo: %w", unmErr)
				}
				v.NetworkSignalInfo = &dec_networksignalinfo
				offset += n_networksignalinfo
			}
		}
	}
	// Decode suppressionOfAnnouncement
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 7 {
				decodedTag_suppressionofannouncement, n_suppressionofannouncement, rawVal_suppressionofannouncement, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding suppressionOfAnnouncement: %w", err)
				}
				if decodedTag_suppressionofannouncement.Class != tag.ClassContextSpecific || decodedTag_suppressionofannouncement.Number != 7 || decodedTag_suppressionofannouncement.Constructed != false {
					return fmt.Errorf("decoding suppressionOfAnnouncement: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_suppressionofannouncement)
				}
				if len(rawVal_suppressionofannouncement) != 0 {
					return fmt.Errorf("decoding suppressionOfAnnouncement: %w: NULL content length %d", ber.ErrInvalidValue, len(rawVal_suppressionofannouncement))
				}
				v.SuppressionOfAnnouncement = &struct{}{}
				offset += n_suppressionofannouncement
			}
		}
	}
	// Decode gmsc-Address
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 8 {
				decodedTag_gmscaddress, n_gmscaddress, rawVal_gmscaddress, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding gmsc-Address: %w", err)
				}
				if decodedTag_gmscaddress.Class != tag.ClassContextSpecific || decodedTag_gmscaddress.Number != 8 {
					return fmt.Errorf("decoding gmsc-Address: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_gmscaddress)
				}
				tmp_gmscaddress := ISDNAddressString(rawVal_gmscaddress)
				v.GmscAddress = &tmp_gmscaddress
				offset += n_gmscaddress
			}
		}
	}
	// Decode callReferenceNumber
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 9 {
				decodedTag_callreferencenumber, n_callreferencenumber, rawVal_callreferencenumber, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding callReferenceNumber: %w", err)
				}
				if decodedTag_callreferencenumber.Class != tag.ClassContextSpecific || decodedTag_callreferencenumber.Number != 9 {
					return fmt.Errorf("decoding callReferenceNumber: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_callreferencenumber)
				}
				tmp_callreferencenumber := CallReferenceNumber(rawVal_callreferencenumber)
				v.CallReferenceNumber = &tmp_callreferencenumber
				offset += n_callreferencenumber
			}
		}
	}
	// Decode or-Interrogation
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 10 {
				decodedTag_orinterrogation, n_orinterrogation, rawVal_orinterrogation, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding or-Interrogation: %w", err)
				}
				if decodedTag_orinterrogation.Class != tag.ClassContextSpecific || decodedTag_orinterrogation.Number != 10 || decodedTag_orinterrogation.Constructed != false {
					return fmt.Errorf("decoding or-Interrogation: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_orinterrogation)
				}
				if len(rawVal_orinterrogation) != 0 {
					return fmt.Errorf("decoding or-Interrogation: %w: NULL content length %d", ber.ErrInvalidValue, len(rawVal_orinterrogation))
				}
				v.OrInterrogation = &struct{}{}
				offset += n_orinterrogation
			}
		}
	}
	// Decode extensionContainer
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 11 {
				decodedTag_extensioncontainer, n_extensioncontainer, rawVal_extensioncontainer, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding extensionContainer: %w", err)
				}
				if decodedTag_extensioncontainer.Class != tag.ClassContextSpecific || decodedTag_extensioncontainer.Number != 11 || decodedTag_extensioncontainer.Constructed != true {
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
	// Decode alertingPattern
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 12 {
				decodedTag_alertingpattern, n_alertingpattern, rawVal_alertingpattern, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding alertingPattern: %w", err)
				}
				if decodedTag_alertingpattern.Class != tag.ClassContextSpecific || decodedTag_alertingpattern.Number != 12 {
					return fmt.Errorf("decoding alertingPattern: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_alertingpattern)
				}
				tmp_alertingpattern := AlertingPattern(rawVal_alertingpattern)
				v.AlertingPattern = &tmp_alertingpattern
				offset += n_alertingpattern
			}
		}
	}
	// Decode ccbs-Call
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 13 {
				decodedTag_ccbscall, n_ccbscall, rawVal_ccbscall, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding ccbs-Call: %w", err)
				}
				if decodedTag_ccbscall.Class != tag.ClassContextSpecific || decodedTag_ccbscall.Number != 13 || decodedTag_ccbscall.Constructed != false {
					return fmt.Errorf("decoding ccbs-Call: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_ccbscall)
				}
				if len(rawVal_ccbscall) != 0 {
					return fmt.Errorf("decoding ccbs-Call: %w: NULL content length %d", ber.ErrInvalidValue, len(rawVal_ccbscall))
				}
				v.CcbsCall = &struct{}{}
				offset += n_ccbscall
			}
		}
	}
	// Decode supportedCamelPhasesInInterrogatingNode
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 15 {
				decodedTag_supportedcamelphasesininterrogatingnode, n_supportedcamelphasesininterrogatingnode, rawVal_supportedcamelphasesininterrogatingnode, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding supportedCamelPhasesInInterrogatingNode: %w", err)
				}
				if decodedTag_supportedcamelphasesininterrogatingnode.Class != tag.ClassContextSpecific || decodedTag_supportedcamelphasesininterrogatingnode.Number != 15 {
					return fmt.Errorf("decoding supportedCamelPhasesInInterrogatingNode: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_supportedcamelphasesininterrogatingnode)
				}
				bsBytes_supportedcamelphasesininterrogatingnode, bsUnused_supportedcamelphasesininterrogatingnode, bsErr := ber.DecodeImplicitBitStringValue(decodedTag_supportedcamelphasesininterrogatingnode.Constructed, rawVal_supportedcamelphasesininterrogatingnode)
				if bsErr != nil {
					return fmt.Errorf("decoding supportedCamelPhasesInInterrogatingNode: %w", bsErr)
				}
				tmp_supportedcamelphasesininterrogatingnode := runtime.BitString{Bytes: bsBytes_supportedcamelphasesininterrogatingnode, BitLength: len(bsBytes_supportedcamelphasesininterrogatingnode)*8 - bsUnused_supportedcamelphasesininterrogatingnode}
				v.SupportedCamelPhasesInInterrogatingNode = &tmp_supportedcamelphasesininterrogatingnode
				offset += n_supportedcamelphasesininterrogatingnode
			}
		}
	}
	// Decode additionalSignalInfo
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 14 {
				decodedTag_additionalsignalinfo, n_additionalsignalinfo, rawVal_additionalsignalinfo, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding additionalSignalInfo: %w", err)
				}
				if decodedTag_additionalsignalinfo.Class != tag.ClassContextSpecific || decodedTag_additionalsignalinfo.Number != 14 || decodedTag_additionalsignalinfo.Constructed != true {
					return fmt.Errorf("decoding additionalSignalInfo: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_additionalsignalinfo)
				}
				reconstructed_additionalsignalinfo := ber.EncodeSequence(rawVal_additionalsignalinfo)
				var dec_additionalsignalinfo ExtExternalSignalInfo
				if unmErr := dec_additionalsignalinfo.UnmarshalBER(reconstructed_additionalsignalinfo); unmErr != nil {
					return fmt.Errorf("decoding additionalSignalInfo: %w", unmErr)
				}
				v.AdditionalSignalInfo = &dec_additionalsignalinfo
				offset += n_additionalsignalinfo
			}
		}
	}
	// Decode orNotSupportedInGMSC
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 16 {
				decodedTag_ornotsupportedingmsc, n_ornotsupportedingmsc, rawVal_ornotsupportedingmsc, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding orNotSupportedInGMSC: %w", err)
				}
				if decodedTag_ornotsupportedingmsc.Class != tag.ClassContextSpecific || decodedTag_ornotsupportedingmsc.Number != 16 || decodedTag_ornotsupportedingmsc.Constructed != false {
					return fmt.Errorf("decoding orNotSupportedInGMSC: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_ornotsupportedingmsc)
				}
				if len(rawVal_ornotsupportedingmsc) != 0 {
					return fmt.Errorf("decoding orNotSupportedInGMSC: %w: NULL content length %d", ber.ErrInvalidValue, len(rawVal_ornotsupportedingmsc))
				}
				v.OrNotSupportedInGMSC = &struct{}{}
				offset += n_ornotsupportedingmsc
			}
		}
	}
	// Decode pre-pagingSupported
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 17 {
				decodedTag_prepagingsupported, n_prepagingsupported, rawVal_prepagingsupported, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding pre-pagingSupported: %w", err)
				}
				if decodedTag_prepagingsupported.Class != tag.ClassContextSpecific || decodedTag_prepagingsupported.Number != 17 || decodedTag_prepagingsupported.Constructed != false {
					return fmt.Errorf("decoding pre-pagingSupported: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_prepagingsupported)
				}
				if len(rawVal_prepagingsupported) != 0 {
					return fmt.Errorf("decoding pre-pagingSupported: %w: NULL content length %d", ber.ErrInvalidValue, len(rawVal_prepagingsupported))
				}
				v.PrePagingSupported = &struct{}{}
				offset += n_prepagingsupported
			}
		}
	}
	// Decode longFTN-Supported
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 18 {
				decodedTag_longftnsupported, n_longftnsupported, rawVal_longftnsupported, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding longFTN-Supported: %w", err)
				}
				if decodedTag_longftnsupported.Class != tag.ClassContextSpecific || decodedTag_longftnsupported.Number != 18 || decodedTag_longftnsupported.Constructed != false {
					return fmt.Errorf("decoding longFTN-Supported: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_longftnsupported)
				}
				if len(rawVal_longftnsupported) != 0 {
					return fmt.Errorf("decoding longFTN-Supported: %w: NULL content length %d", ber.ErrInvalidValue, len(rawVal_longftnsupported))
				}
				v.LongFTNSupported = &struct{}{}
				offset += n_longftnsupported
			}
		}
	}
	// Decode suppress-VT-CSI
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 19 {
				decodedTag_suppressvtcsi, n_suppressvtcsi, rawVal_suppressvtcsi, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding suppress-VT-CSI: %w", err)
				}
				if decodedTag_suppressvtcsi.Class != tag.ClassContextSpecific || decodedTag_suppressvtcsi.Number != 19 || decodedTag_suppressvtcsi.Constructed != false {
					return fmt.Errorf("decoding suppress-VT-CSI: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_suppressvtcsi)
				}
				if len(rawVal_suppressvtcsi) != 0 {
					return fmt.Errorf("decoding suppress-VT-CSI: %w: NULL content length %d", ber.ErrInvalidValue, len(rawVal_suppressvtcsi))
				}
				v.SuppressVTCSI = &struct{}{}
				offset += n_suppressvtcsi
			}
		}
	}
	// Decode offeredCamel4CSIsInInterrogatingNode
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 20 {
				decodedTag_offeredcamel4csisininterrogatingnode, n_offeredcamel4csisininterrogatingnode, rawVal_offeredcamel4csisininterrogatingnode, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding offeredCamel4CSIsInInterrogatingNode: %w", err)
				}
				if decodedTag_offeredcamel4csisininterrogatingnode.Class != tag.ClassContextSpecific || decodedTag_offeredcamel4csisininterrogatingnode.Number != 20 {
					return fmt.Errorf("decoding offeredCamel4CSIsInInterrogatingNode: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_offeredcamel4csisininterrogatingnode)
				}
				bsBytes_offeredcamel4csisininterrogatingnode, bsUnused_offeredcamel4csisininterrogatingnode, bsErr := ber.DecodeImplicitBitStringValue(decodedTag_offeredcamel4csisininterrogatingnode.Constructed, rawVal_offeredcamel4csisininterrogatingnode)
				if bsErr != nil {
					return fmt.Errorf("decoding offeredCamel4CSIsInInterrogatingNode: %w", bsErr)
				}
				tmp_offeredcamel4csisininterrogatingnode := runtime.BitString{Bytes: bsBytes_offeredcamel4csisininterrogatingnode, BitLength: len(bsBytes_offeredcamel4csisininterrogatingnode)*8 - bsUnused_offeredcamel4csisininterrogatingnode}
				v.OfferedCamel4CSIsInInterrogatingNode = &tmp_offeredcamel4csisininterrogatingnode
				offset += n_offeredcamel4csisininterrogatingnode
			}
		}
	}
	// Decode mtRoamingRetrySupported
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 21 {
				decodedTag_mtroamingretrysupported, n_mtroamingretrysupported, rawVal_mtroamingretrysupported, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding mtRoamingRetrySupported: %w", err)
				}
				if decodedTag_mtroamingretrysupported.Class != tag.ClassContextSpecific || decodedTag_mtroamingretrysupported.Number != 21 || decodedTag_mtroamingretrysupported.Constructed != false {
					return fmt.Errorf("decoding mtRoamingRetrySupported: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_mtroamingretrysupported)
				}
				if len(rawVal_mtroamingretrysupported) != 0 {
					return fmt.Errorf("decoding mtRoamingRetrySupported: %w: NULL content length %d", ber.ErrInvalidValue, len(rawVal_mtroamingretrysupported))
				}
				v.MtRoamingRetrySupported = &struct{}{}
				offset += n_mtroamingretrysupported
			}
		}
	}
	// Decode pagingArea
	v.PagingAreaIndef_ = false
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 22 {
				decodedTag_pagingarea, n_pagingarea, rawVal_pagingarea, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding pagingArea: %w", err)
				}
				if decodedTag_pagingarea.Class != tag.ClassContextSpecific || decodedTag_pagingarea.Number != 22 || decodedTag_pagingarea.Constructed != true {
					return fmt.Errorf("decoding pagingArea: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_pagingarea)
				}
				reconstructed_pagingarea := ber.EncodeSequence(rawVal_pagingarea)
				dec_pagingarea, unmErr := UnmarshalBERPagingArea(reconstructed_pagingarea)
				if unmErr != nil {
					return fmt.Errorf("decoding pagingArea: %w", unmErr)
				}
				v.PagingArea = dec_pagingarea
				{
					_, tagSz_, _ := ber.DecodeTag(content[offset:])
					if offset+tagSz_ < len(content) && content[offset+tagSz_] == 0x80 {
						v.PagingAreaIndef_ = true
					}
				}
				offset += n_pagingarea
			}
		}
	}
	// Decode callPriority
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 23 {
				decodedTag_callpriority, n_callpriority, rawVal_callpriority, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding callPriority: %w", err)
				}
				if decodedTag_callpriority.Class != tag.ClassContextSpecific || decodedTag_callpriority.Number != 23 || decodedTag_callpriority.Constructed != false {
					return fmt.Errorf("decoding callPriority: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_callpriority)
				}
				decVal_callpriority, intErr := ber.DecodeIntegerValue(rawVal_callpriority)
				if intErr != nil {
					return fmt.Errorf("decoding callPriority: %w", intErr)
				}
				tmp_callpriority := EMLPPPriority(decVal_callpriority)
				v.CallPriority = &tmp_callpriority
				offset += n_callpriority
			}
		}
	}
	// Decode mtrf-Indicator
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 24 {
				decodedTag_mtrfindicator, n_mtrfindicator, rawVal_mtrfindicator, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding mtrf-Indicator: %w", err)
				}
				if decodedTag_mtrfindicator.Class != tag.ClassContextSpecific || decodedTag_mtrfindicator.Number != 24 || decodedTag_mtrfindicator.Constructed != false {
					return fmt.Errorf("decoding mtrf-Indicator: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_mtrfindicator)
				}
				if len(rawVal_mtrfindicator) != 0 {
					return fmt.Errorf("decoding mtrf-Indicator: %w: NULL content length %d", ber.ErrInvalidValue, len(rawVal_mtrfindicator))
				}
				v.MtrfIndicator = &struct{}{}
				offset += n_mtrfindicator
			}
		}
	}
	// Decode oldMSC-Number
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 25 {
				decodedTag_oldmscnumber, n_oldmscnumber, rawVal_oldmscnumber, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding oldMSC-Number: %w", err)
				}
				if decodedTag_oldmscnumber.Class != tag.ClassContextSpecific || decodedTag_oldmscnumber.Number != 25 {
					return fmt.Errorf("decoding oldMSC-Number: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_oldmscnumber)
				}
				tmp_oldmscnumber := ISDNAddressString(rawVal_oldmscnumber)
				v.OldMSCNumber = &tmp_oldmscnumber
				offset += n_oldmscnumber
			}
		}
	}
	// Decode lastUsedLtePLMN-Id
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 26 {
				decodedTag_lastusedlteplmnid, n_lastusedlteplmnid, rawVal_lastusedlteplmnid, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding lastUsedLtePLMN-Id: %w", err)
				}
				if decodedTag_lastusedlteplmnid.Class != tag.ClassContextSpecific || decodedTag_lastusedlteplmnid.Number != 26 {
					return fmt.Errorf("decoding lastUsedLtePLMN-Id: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_lastusedlteplmnid)
				}
				tmp_lastusedlteplmnid := PLMNId(rawVal_lastusedlteplmnid)
				v.LastUsedLtePLMNId = &tmp_lastusedlteplmnid
				offset += n_lastusedlteplmnid
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "ProvideRoamingNumberArg", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes ProvideRoamingNumberRes to BER format.
func (v *ProvideRoamingNumberRes) MarshalBER() ([]byte, error) {
	var children []byte
	enc_roamingnumber := ber.EncodeOctetString([]byte(v.RoamingNumber))
	children = append(children, enc_roamingnumber...)
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding extensionContainer: %w", err)
		}
		children = append(children, enc_extensioncontainer...)
	}
	if v.ReleaseResourcesSupported != nil {
		enc_releaseresourcessupported := ber.EncodeNull()
		children = append(children, enc_releaseresourcessupported...)
	}
	if v.VmscAddress != nil {
		enc_vmscaddress := ber.EncodeOctetString([]byte(*v.VmscAddress))
		children = append(children, enc_vmscaddress...)
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

// MarshalDER encodes ProvideRoamingNumberRes to DER format.
func (v *ProvideRoamingNumberRes) MarshalDER() ([]byte, error) {
	var children []byte
	enc_roamingnumber := ber.EncodeOctetString([]byte(v.RoamingNumber))
	children = append(children, enc_roamingnumber...)
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding extensionContainer: %w", err)
		}
		children = append(children, enc_extensioncontainer...)
	}
	if v.ReleaseResourcesSupported != nil {
		enc_releaseresourcessupported := ber.EncodeNull()
		children = append(children, enc_releaseresourcessupported...)
	}
	if v.VmscAddress != nil {
		enc_vmscaddress := ber.EncodeOctetString([]byte(*v.VmscAddress))
		children = append(children, enc_vmscaddress...)
	}
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
		children = append(children, ext...)
	}
	encoded := ber.EncodeSequence(children)
	if err := ber.ValidateDERElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding ProvideRoamingNumberRes as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes ProvideRoamingNumberRes from BER/DER format.
func (v *ProvideRoamingNumberRes) UnmarshalBER(data []byte) error {
	*v = ProvideRoamingNumberRes{}
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding ProvideRoamingNumberRes SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "ProvideRoamingNumberRes", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode roamingNumber
	if offset >= len(content) {
		return fmt.Errorf("missing required field roamingNumber")
	}
	val_roamingnumber, n, err := ber.DecodeOctetString(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding roamingNumber: %w", err)
	}
	v.RoamingNumber = ISDNAddressString(val_roamingnumber)
	offset += n
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
	// Decode releaseResourcesSupported
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassUniversal && peekTag.Number == 5 {
				n, err := ber.DecodeNull(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding releaseResourcesSupported: %w", err)
				}
				v.ReleaseResourcesSupported = &struct{}{}
				offset += n
			}
		}
	}
	// Decode vmsc-Address
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassUniversal && peekTag.Number == 4 {
				val_vmscaddress, n, err := ber.DecodeOctetString(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding vmsc-Address: %w", err)
				}
				tmp_vmscaddress := ISDNAddressString(val_vmscaddress)
				v.VmscAddress = &tmp_vmscaddress
				offset += n
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "ProvideRoamingNumberRes", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes ResumeCallHandlingArg to BER format.
func (v *ResumeCallHandlingArg) MarshalBER() ([]byte, error) {
	var children []byte
	if v.CallReferenceNumber != nil {
		enc_callreferencenumber := ber.EncodeOctetString([]byte(*v.CallReferenceNumber))
		retagged_enc_callreferencenumber, tagErr_enc_callreferencenumber := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_callreferencenumber)
		if tagErr_enc_callreferencenumber != nil {
			return nil, fmt.Errorf("encoding callReferenceNumber: %w", tagErr_enc_callreferencenumber)
		}
		enc_callreferencenumber = retagged_enc_callreferencenumber
		children = append(children, enc_callreferencenumber...)
	}
	if v.BasicServiceGroup != nil {
		enc_basicservicegroup, err := v.BasicServiceGroup.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding basicServiceGroup: %w", err)
		}
		enc_basicservicegroup = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 1, enc_basicservicegroup)
		children = append(children, enc_basicservicegroup...)
	}
	if v.ForwardingData != nil {
		enc_forwardingdata, err := v.ForwardingData.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding forwardingData: %w", err)
		}
		retagged_enc_forwardingdata, tagErr_enc_forwardingdata := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_forwardingdata)
		if tagErr_enc_forwardingdata != nil {
			return nil, fmt.Errorf("encoding forwardingData: %w", tagErr_enc_forwardingdata)
		}
		enc_forwardingdata = retagged_enc_forwardingdata
		children = append(children, enc_forwardingdata...)
	}
	if v.Imsi != nil {
		enc_imsi := ber.EncodeOctetString([]byte(*v.Imsi))
		retagged_enc_imsi, tagErr_enc_imsi := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, enc_imsi)
		if tagErr_enc_imsi != nil {
			return nil, fmt.Errorf("encoding imsi: %w", tagErr_enc_imsi)
		}
		enc_imsi = retagged_enc_imsi
		children = append(children, enc_imsi...)
	}
	if v.CugCheckInfo != nil {
		enc_cugcheckinfo, err := v.CugCheckInfo.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding cug-CheckInfo: %w", err)
		}
		retagged_enc_cugcheckinfo, tagErr_enc_cugcheckinfo := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, enc_cugcheckinfo)
		if tagErr_enc_cugcheckinfo != nil {
			return nil, fmt.Errorf("encoding cug-CheckInfo: %w", tagErr_enc_cugcheckinfo)
		}
		enc_cugcheckinfo = retagged_enc_cugcheckinfo
		children = append(children, enc_cugcheckinfo...)
	}
	if v.OCSI != nil {
		enc_ocsi, err := v.OCSI.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding o-CSI: %w", err)
		}
		retagged_enc_ocsi, tagErr_enc_ocsi := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 5, enc_ocsi)
		if tagErr_enc_ocsi != nil {
			return nil, fmt.Errorf("encoding o-CSI: %w", tagErr_enc_ocsi)
		}
		enc_ocsi = retagged_enc_ocsi
		children = append(children, enc_ocsi...)
	}
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding extensionContainer: %w", err)
		}
		retagged_enc_extensioncontainer, tagErr_enc_extensioncontainer := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 7, enc_extensioncontainer)
		if tagErr_enc_extensioncontainer != nil {
			return nil, fmt.Errorf("encoding extensionContainer: %w", tagErr_enc_extensioncontainer)
		}
		enc_extensioncontainer = retagged_enc_extensioncontainer
		children = append(children, enc_extensioncontainer...)
	}
	if v.CcbsPossible != nil {
		enc_ccbspossible := ber.EncodeNull()
		retagged_enc_ccbspossible, tagErr_enc_ccbspossible := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 8, enc_ccbspossible)
		if tagErr_enc_ccbspossible != nil {
			return nil, fmt.Errorf("encoding ccbs-Possible: %w", tagErr_enc_ccbspossible)
		}
		enc_ccbspossible = retagged_enc_ccbspossible
		children = append(children, enc_ccbspossible...)
	}
	if v.Msisdn != nil {
		enc_msisdn := ber.EncodeOctetString([]byte(*v.Msisdn))
		retagged_enc_msisdn, tagErr_enc_msisdn := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 9, enc_msisdn)
		if tagErr_enc_msisdn != nil {
			return nil, fmt.Errorf("encoding msisdn: %w", tagErr_enc_msisdn)
		}
		enc_msisdn = retagged_enc_msisdn
		children = append(children, enc_msisdn...)
	}
	if v.UuData != nil {
		enc_uudata, err := v.UuData.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding uu-Data: %w", err)
		}
		retagged_enc_uudata, tagErr_enc_uudata := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 10, enc_uudata)
		if tagErr_enc_uudata != nil {
			return nil, fmt.Errorf("encoding uu-Data: %w", tagErr_enc_uudata)
		}
		enc_uudata = retagged_enc_uudata
		children = append(children, enc_uudata...)
	}
	if v.AllInformationSent != nil {
		enc_allinformationsent := ber.EncodeNull()
		retagged_enc_allinformationsent, tagErr_enc_allinformationsent := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 11, enc_allinformationsent)
		if tagErr_enc_allinformationsent != nil {
			return nil, fmt.Errorf("encoding allInformationSent: %w", tagErr_enc_allinformationsent)
		}
		enc_allinformationsent = retagged_enc_allinformationsent
		children = append(children, enc_allinformationsent...)
	}
	if v.DCsi != nil {
		enc_dcsi, err := v.DCsi.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding d-csi: %w", err)
		}
		retagged_enc_dcsi, tagErr_enc_dcsi := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 12, enc_dcsi)
		if tagErr_enc_dcsi != nil {
			return nil, fmt.Errorf("encoding d-csi: %w", tagErr_enc_dcsi)
		}
		enc_dcsi = retagged_enc_dcsi
		children = append(children, enc_dcsi...)
	}
	if v.OBcsmCamelTDPCriteriaList != nil {
		enc_obcsmcameltdpcriterialist, err := MarshalBEROBcsmCamelTDPCriteriaList(v.OBcsmCamelTDPCriteriaList)
		if err != nil {
			return nil, fmt.Errorf("encoding o-BcsmCamelTDPCriteriaList: %w", err)
		}
		if v.OBcsmCamelTDPCriteriaListIndef_ {
			// Strip the outer SEQUENCE tag from marshalBER output to get raw children.
			_, _, seqContent_, tlvErr_ := ber.DecodeTLV(enc_obcsmcameltdpcriterialist)
			if tlvErr_ != nil {
				return nil, tlvErr_
			}
			enc_obcsmcameltdpcriterialist = ber.EncodeConstructedIndefinite(tag.Tag{Class: tag.ClassContextSpecific, Number: 13}, seqContent_)
		} else {
			retagged_enc_obcsmcameltdpcriterialist, tagErr_enc_obcsmcameltdpcriterialist := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 13, enc_obcsmcameltdpcriterialist)
			if tagErr_enc_obcsmcameltdpcriterialist != nil {
				return nil, fmt.Errorf("encoding o-BcsmCamelTDPCriteriaList: %w", tagErr_enc_obcsmcameltdpcriterialist)
			}
			enc_obcsmcameltdpcriterialist = retagged_enc_obcsmcameltdpcriterialist
		}
		children = append(children, enc_obcsmcameltdpcriterialist...)
	}
	if v.BasicServiceGroup2 != nil {
		enc_basicservicegroup2, err := v.BasicServiceGroup2.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding basicServiceGroup2: %w", err)
		}
		enc_basicservicegroup2 = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 14, enc_basicservicegroup2)
		children = append(children, enc_basicservicegroup2...)
	}
	if v.MtRoamingRetry != nil {
		enc_mtroamingretry := ber.EncodeNull()
		retagged_enc_mtroamingretry, tagErr_enc_mtroamingretry := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 15, enc_mtroamingretry)
		if tagErr_enc_mtroamingretry != nil {
			return nil, fmt.Errorf("encoding mtRoamingRetry: %w", tagErr_enc_mtroamingretry)
		}
		enc_mtroamingretry = retagged_enc_mtroamingretry
		children = append(children, enc_mtroamingretry...)
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

// MarshalDER encodes ResumeCallHandlingArg to DER format.
func (v *ResumeCallHandlingArg) MarshalDER() ([]byte, error) {
	var children []byte
	if v.CallReferenceNumber != nil {
		enc_callreferencenumber := ber.EncodeOctetString([]byte(*v.CallReferenceNumber))
		retagged_enc_callreferencenumber, tagErr_enc_callreferencenumber := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_callreferencenumber)
		if tagErr_enc_callreferencenumber != nil {
			return nil, fmt.Errorf("encoding callReferenceNumber: %w", tagErr_enc_callreferencenumber)
		}
		enc_callreferencenumber = retagged_enc_callreferencenumber
		children = append(children, enc_callreferencenumber...)
	}
	if v.BasicServiceGroup != nil {
		enc_basicservicegroup, err := v.BasicServiceGroup.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding basicServiceGroup: %w", err)
		}
		enc_basicservicegroup = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 1, enc_basicservicegroup)
		children = append(children, enc_basicservicegroup...)
	}
	if v.ForwardingData != nil {
		enc_forwardingdata, err := v.ForwardingData.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding forwardingData: %w", err)
		}
		retagged_enc_forwardingdata, tagErr_enc_forwardingdata := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_forwardingdata)
		if tagErr_enc_forwardingdata != nil {
			return nil, fmt.Errorf("encoding forwardingData: %w", tagErr_enc_forwardingdata)
		}
		enc_forwardingdata = retagged_enc_forwardingdata
		children = append(children, enc_forwardingdata...)
	}
	if v.Imsi != nil {
		enc_imsi := ber.EncodeOctetString([]byte(*v.Imsi))
		retagged_enc_imsi, tagErr_enc_imsi := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, enc_imsi)
		if tagErr_enc_imsi != nil {
			return nil, fmt.Errorf("encoding imsi: %w", tagErr_enc_imsi)
		}
		enc_imsi = retagged_enc_imsi
		children = append(children, enc_imsi...)
	}
	if v.CugCheckInfo != nil {
		enc_cugcheckinfo, err := v.CugCheckInfo.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding cug-CheckInfo: %w", err)
		}
		retagged_enc_cugcheckinfo, tagErr_enc_cugcheckinfo := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, enc_cugcheckinfo)
		if tagErr_enc_cugcheckinfo != nil {
			return nil, fmt.Errorf("encoding cug-CheckInfo: %w", tagErr_enc_cugcheckinfo)
		}
		enc_cugcheckinfo = retagged_enc_cugcheckinfo
		children = append(children, enc_cugcheckinfo...)
	}
	if v.OCSI != nil {
		enc_ocsi, err := v.OCSI.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding o-CSI: %w", err)
		}
		retagged_enc_ocsi, tagErr_enc_ocsi := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 5, enc_ocsi)
		if tagErr_enc_ocsi != nil {
			return nil, fmt.Errorf("encoding o-CSI: %w", tagErr_enc_ocsi)
		}
		enc_ocsi = retagged_enc_ocsi
		children = append(children, enc_ocsi...)
	}
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding extensionContainer: %w", err)
		}
		retagged_enc_extensioncontainer, tagErr_enc_extensioncontainer := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 7, enc_extensioncontainer)
		if tagErr_enc_extensioncontainer != nil {
			return nil, fmt.Errorf("encoding extensionContainer: %w", tagErr_enc_extensioncontainer)
		}
		enc_extensioncontainer = retagged_enc_extensioncontainer
		children = append(children, enc_extensioncontainer...)
	}
	if v.CcbsPossible != nil {
		enc_ccbspossible := ber.EncodeNull()
		retagged_enc_ccbspossible, tagErr_enc_ccbspossible := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 8, enc_ccbspossible)
		if tagErr_enc_ccbspossible != nil {
			return nil, fmt.Errorf("encoding ccbs-Possible: %w", tagErr_enc_ccbspossible)
		}
		enc_ccbspossible = retagged_enc_ccbspossible
		children = append(children, enc_ccbspossible...)
	}
	if v.Msisdn != nil {
		enc_msisdn := ber.EncodeOctetString([]byte(*v.Msisdn))
		retagged_enc_msisdn, tagErr_enc_msisdn := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 9, enc_msisdn)
		if tagErr_enc_msisdn != nil {
			return nil, fmt.Errorf("encoding msisdn: %w", tagErr_enc_msisdn)
		}
		enc_msisdn = retagged_enc_msisdn
		children = append(children, enc_msisdn...)
	}
	if v.UuData != nil {
		enc_uudata, err := v.UuData.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding uu-Data: %w", err)
		}
		retagged_enc_uudata, tagErr_enc_uudata := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 10, enc_uudata)
		if tagErr_enc_uudata != nil {
			return nil, fmt.Errorf("encoding uu-Data: %w", tagErr_enc_uudata)
		}
		enc_uudata = retagged_enc_uudata
		children = append(children, enc_uudata...)
	}
	if v.AllInformationSent != nil {
		enc_allinformationsent := ber.EncodeNull()
		retagged_enc_allinformationsent, tagErr_enc_allinformationsent := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 11, enc_allinformationsent)
		if tagErr_enc_allinformationsent != nil {
			return nil, fmt.Errorf("encoding allInformationSent: %w", tagErr_enc_allinformationsent)
		}
		enc_allinformationsent = retagged_enc_allinformationsent
		children = append(children, enc_allinformationsent...)
	}
	if v.DCsi != nil {
		enc_dcsi, err := v.DCsi.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding d-csi: %w", err)
		}
		retagged_enc_dcsi, tagErr_enc_dcsi := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 12, enc_dcsi)
		if tagErr_enc_dcsi != nil {
			return nil, fmt.Errorf("encoding d-csi: %w", tagErr_enc_dcsi)
		}
		enc_dcsi = retagged_enc_dcsi
		children = append(children, enc_dcsi...)
	}
	if v.OBcsmCamelTDPCriteriaList != nil {
		enc_obcsmcameltdpcriterialist, err := MarshalDEROBcsmCamelTDPCriteriaList(v.OBcsmCamelTDPCriteriaList)
		if err != nil {
			return nil, fmt.Errorf("encoding o-BcsmCamelTDPCriteriaList: %w", err)
		}
		retagged_enc_obcsmcameltdpcriterialist, tagErr_enc_obcsmcameltdpcriterialist := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 13, enc_obcsmcameltdpcriterialist)
		if tagErr_enc_obcsmcameltdpcriterialist != nil {
			return nil, fmt.Errorf("encoding o-BcsmCamelTDPCriteriaList: %w", tagErr_enc_obcsmcameltdpcriterialist)
		}
		enc_obcsmcameltdpcriterialist = retagged_enc_obcsmcameltdpcriterialist
		children = append(children, enc_obcsmcameltdpcriterialist...)
	}
	if v.BasicServiceGroup2 != nil {
		enc_basicservicegroup2, err := v.BasicServiceGroup2.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding basicServiceGroup2: %w", err)
		}
		enc_basicservicegroup2 = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 14, enc_basicservicegroup2)
		children = append(children, enc_basicservicegroup2...)
	}
	if v.MtRoamingRetry != nil {
		enc_mtroamingretry := ber.EncodeNull()
		retagged_enc_mtroamingretry, tagErr_enc_mtroamingretry := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 15, enc_mtroamingretry)
		if tagErr_enc_mtroamingretry != nil {
			return nil, fmt.Errorf("encoding mtRoamingRetry: %w", tagErr_enc_mtroamingretry)
		}
		enc_mtroamingretry = retagged_enc_mtroamingretry
		children = append(children, enc_mtroamingretry...)
	}
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
		children = append(children, ext...)
	}
	encoded := ber.EncodeSequence(children)
	if err := ber.ValidateDERElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding ResumeCallHandlingArg as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes ResumeCallHandlingArg from BER/DER format.
func (v *ResumeCallHandlingArg) UnmarshalBER(data []byte) error {
	*v = ResumeCallHandlingArg{}
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding ResumeCallHandlingArg SEQUENCE: %w", err)
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
				decodedTag_callreferencenumber, n_callreferencenumber, rawVal_callreferencenumber, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding callReferenceNumber: %w", err)
				}
				if decodedTag_callreferencenumber.Class != tag.ClassContextSpecific || decodedTag_callreferencenumber.Number != 0 {
					return fmt.Errorf("decoding callReferenceNumber: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_callreferencenumber)
				}
				tmp_callreferencenumber := CallReferenceNumber(rawVal_callreferencenumber)
				v.CallReferenceNumber = &tmp_callreferencenumber
				offset += n_callreferencenumber
			}
		}
	}
	// Decode basicServiceGroup
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
				decodedTag_basicservicegroup, n_basicservicegroup, innerData_basicservicegroup, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding basicServiceGroup: %w", err)
				}
				if decodedTag_basicservicegroup.Class != tag.ClassContextSpecific || decodedTag_basicservicegroup.Number != 1 || decodedTag_basicservicegroup.Constructed != true {
					return fmt.Errorf("decoding basicServiceGroup: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_basicservicegroup)
				}
				// Decode inner value from explicit tag wrapper
				var dec_basicservicegroup ExtBasicServiceCode
				if unmErr := dec_basicservicegroup.UnmarshalBER(innerData_basicservicegroup); unmErr != nil {
					return fmt.Errorf("decoding basicServiceGroup: %w", unmErr)
				}
				v.BasicServiceGroup = &dec_basicservicegroup
				offset += n_basicservicegroup
			}
		}
	}
	// Decode forwardingData
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2 {
				decodedTag_forwardingdata, n_forwardingdata, rawVal_forwardingdata, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding forwardingData: %w", err)
				}
				if decodedTag_forwardingdata.Class != tag.ClassContextSpecific || decodedTag_forwardingdata.Number != 2 || decodedTag_forwardingdata.Constructed != true {
					return fmt.Errorf("decoding forwardingData: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_forwardingdata)
				}
				reconstructed_forwardingdata := ber.EncodeSequence(rawVal_forwardingdata)
				var dec_forwardingdata ForwardingData
				if unmErr := dec_forwardingdata.UnmarshalBER(reconstructed_forwardingdata); unmErr != nil {
					return fmt.Errorf("decoding forwardingData: %w", unmErr)
				}
				v.ForwardingData = &dec_forwardingdata
				offset += n_forwardingdata
			}
		}
	}
	// Decode imsi
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3 {
				decodedTag_imsi, n_imsi, rawVal_imsi, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding imsi: %w", err)
				}
				if decodedTag_imsi.Class != tag.ClassContextSpecific || decodedTag_imsi.Number != 3 {
					return fmt.Errorf("decoding imsi: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_imsi)
				}
				tmp_imsi := IMSI(rawVal_imsi)
				v.Imsi = &tmp_imsi
				offset += n_imsi
			}
		}
	}
	// Decode cug-CheckInfo
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4 {
				decodedTag_cugcheckinfo, n_cugcheckinfo, rawVal_cugcheckinfo, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding cug-CheckInfo: %w", err)
				}
				if decodedTag_cugcheckinfo.Class != tag.ClassContextSpecific || decodedTag_cugcheckinfo.Number != 4 || decodedTag_cugcheckinfo.Constructed != true {
					return fmt.Errorf("decoding cug-CheckInfo: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_cugcheckinfo)
				}
				reconstructed_cugcheckinfo := ber.EncodeSequence(rawVal_cugcheckinfo)
				var dec_cugcheckinfo CUGCheckInfo
				if unmErr := dec_cugcheckinfo.UnmarshalBER(reconstructed_cugcheckinfo); unmErr != nil {
					return fmt.Errorf("decoding cug-CheckInfo: %w", unmErr)
				}
				v.CugCheckInfo = &dec_cugcheckinfo
				offset += n_cugcheckinfo
			}
		}
	}
	// Decode o-CSI
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 5 {
				decodedTag_ocsi, n_ocsi, rawVal_ocsi, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding o-CSI: %w", err)
				}
				if decodedTag_ocsi.Class != tag.ClassContextSpecific || decodedTag_ocsi.Number != 5 || decodedTag_ocsi.Constructed != true {
					return fmt.Errorf("decoding o-CSI: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_ocsi)
				}
				reconstructed_ocsi := ber.EncodeSequence(rawVal_ocsi)
				var dec_ocsi OCSI
				if unmErr := dec_ocsi.UnmarshalBER(reconstructed_ocsi); unmErr != nil {
					return fmt.Errorf("decoding o-CSI: %w", unmErr)
				}
				v.OCSI = &dec_ocsi
				offset += n_ocsi
			}
		}
	}
	// Decode extensionContainer
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 7 {
				decodedTag_extensioncontainer, n_extensioncontainer, rawVal_extensioncontainer, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding extensionContainer: %w", err)
				}
				if decodedTag_extensioncontainer.Class != tag.ClassContextSpecific || decodedTag_extensioncontainer.Number != 7 || decodedTag_extensioncontainer.Constructed != true {
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
	// Decode ccbs-Possible
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 8 {
				decodedTag_ccbspossible, n_ccbspossible, rawVal_ccbspossible, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding ccbs-Possible: %w", err)
				}
				if decodedTag_ccbspossible.Class != tag.ClassContextSpecific || decodedTag_ccbspossible.Number != 8 || decodedTag_ccbspossible.Constructed != false {
					return fmt.Errorf("decoding ccbs-Possible: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_ccbspossible)
				}
				if len(rawVal_ccbspossible) != 0 {
					return fmt.Errorf("decoding ccbs-Possible: %w: NULL content length %d", ber.ErrInvalidValue, len(rawVal_ccbspossible))
				}
				v.CcbsPossible = &struct{}{}
				offset += n_ccbspossible
			}
		}
	}
	// Decode msisdn
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 9 {
				decodedTag_msisdn, n_msisdn, rawVal_msisdn, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding msisdn: %w", err)
				}
				if decodedTag_msisdn.Class != tag.ClassContextSpecific || decodedTag_msisdn.Number != 9 {
					return fmt.Errorf("decoding msisdn: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_msisdn)
				}
				tmp_msisdn := ISDNAddressString(rawVal_msisdn)
				v.Msisdn = &tmp_msisdn
				offset += n_msisdn
			}
		}
	}
	// Decode uu-Data
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 10 {
				decodedTag_uudata, n_uudata, rawVal_uudata, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding uu-Data: %w", err)
				}
				if decodedTag_uudata.Class != tag.ClassContextSpecific || decodedTag_uudata.Number != 10 || decodedTag_uudata.Constructed != true {
					return fmt.Errorf("decoding uu-Data: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_uudata)
				}
				reconstructed_uudata := ber.EncodeSequence(rawVal_uudata)
				var dec_uudata UUData
				if unmErr := dec_uudata.UnmarshalBER(reconstructed_uudata); unmErr != nil {
					return fmt.Errorf("decoding uu-Data: %w", unmErr)
				}
				v.UuData = &dec_uudata
				offset += n_uudata
			}
		}
	}
	// Decode allInformationSent
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 11 {
				decodedTag_allinformationsent, n_allinformationsent, rawVal_allinformationsent, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding allInformationSent: %w", err)
				}
				if decodedTag_allinformationsent.Class != tag.ClassContextSpecific || decodedTag_allinformationsent.Number != 11 || decodedTag_allinformationsent.Constructed != false {
					return fmt.Errorf("decoding allInformationSent: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_allinformationsent)
				}
				if len(rawVal_allinformationsent) != 0 {
					return fmt.Errorf("decoding allInformationSent: %w: NULL content length %d", ber.ErrInvalidValue, len(rawVal_allinformationsent))
				}
				v.AllInformationSent = &struct{}{}
				offset += n_allinformationsent
			}
		}
	}
	// Decode d-csi
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 12 {
				decodedTag_dcsi, n_dcsi, rawVal_dcsi, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding d-csi: %w", err)
				}
				if decodedTag_dcsi.Class != tag.ClassContextSpecific || decodedTag_dcsi.Number != 12 || decodedTag_dcsi.Constructed != true {
					return fmt.Errorf("decoding d-csi: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_dcsi)
				}
				reconstructed_dcsi := ber.EncodeSequence(rawVal_dcsi)
				var dec_dcsi DCSI
				if unmErr := dec_dcsi.UnmarshalBER(reconstructed_dcsi); unmErr != nil {
					return fmt.Errorf("decoding d-csi: %w", unmErr)
				}
				v.DCsi = &dec_dcsi
				offset += n_dcsi
			}
		}
	}
	// Decode o-BcsmCamelTDPCriteriaList
	v.OBcsmCamelTDPCriteriaListIndef_ = false
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 13 {
				decodedTag_obcsmcameltdpcriterialist, n_obcsmcameltdpcriterialist, rawVal_obcsmcameltdpcriterialist, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding o-BcsmCamelTDPCriteriaList: %w", err)
				}
				if decodedTag_obcsmcameltdpcriterialist.Class != tag.ClassContextSpecific || decodedTag_obcsmcameltdpcriterialist.Number != 13 || decodedTag_obcsmcameltdpcriterialist.Constructed != true {
					return fmt.Errorf("decoding o-BcsmCamelTDPCriteriaList: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_obcsmcameltdpcriterialist)
				}
				reconstructed_obcsmcameltdpcriterialist := ber.EncodeSequence(rawVal_obcsmcameltdpcriterialist)
				dec_obcsmcameltdpcriterialist, unmErr := UnmarshalBEROBcsmCamelTDPCriteriaList(reconstructed_obcsmcameltdpcriterialist)
				if unmErr != nil {
					return fmt.Errorf("decoding o-BcsmCamelTDPCriteriaList: %w", unmErr)
				}
				v.OBcsmCamelTDPCriteriaList = dec_obcsmcameltdpcriterialist
				{
					_, tagSz_, _ := ber.DecodeTag(content[offset:])
					if offset+tagSz_ < len(content) && content[offset+tagSz_] == 0x80 {
						v.OBcsmCamelTDPCriteriaListIndef_ = true
					}
				}
				offset += n_obcsmcameltdpcriterialist
			}
		}
	}
	// Decode basicServiceGroup2
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 14 {
				decodedTag_basicservicegroup2, n_basicservicegroup2, innerData_basicservicegroup2, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding basicServiceGroup2: %w", err)
				}
				if decodedTag_basicservicegroup2.Class != tag.ClassContextSpecific || decodedTag_basicservicegroup2.Number != 14 || decodedTag_basicservicegroup2.Constructed != true {
					return fmt.Errorf("decoding basicServiceGroup2: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_basicservicegroup2)
				}
				// Decode inner value from explicit tag wrapper
				var dec_basicservicegroup2 ExtBasicServiceCode
				if unmErr := dec_basicservicegroup2.UnmarshalBER(innerData_basicservicegroup2); unmErr != nil {
					return fmt.Errorf("decoding basicServiceGroup2: %w", unmErr)
				}
				v.BasicServiceGroup2 = &dec_basicservicegroup2
				offset += n_basicservicegroup2
			}
		}
	}
	// Decode mtRoamingRetry
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 15 {
				decodedTag_mtroamingretry, n_mtroamingretry, rawVal_mtroamingretry, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding mtRoamingRetry: %w", err)
				}
				if decodedTag_mtroamingretry.Class != tag.ClassContextSpecific || decodedTag_mtroamingretry.Number != 15 || decodedTag_mtroamingretry.Constructed != false {
					return fmt.Errorf("decoding mtRoamingRetry: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_mtroamingretry)
				}
				if len(rawVal_mtroamingretry) != 0 {
					return fmt.Errorf("decoding mtRoamingRetry: %w: NULL content length %d", ber.ErrInvalidValue, len(rawVal_mtroamingretry))
				}
				v.MtRoamingRetry = &struct{}{}
				offset += n_mtroamingretry
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "ResumeCallHandlingArg", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes UUData to BER format.
func (v *UUData) MarshalBER() ([]byte, error) {
	var children []byte
	if v.UuIndicator != nil {
		enc_uuindicator := ber.EncodeOctetString([]byte(*v.UuIndicator))
		retagged_enc_uuindicator, tagErr_enc_uuindicator := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_uuindicator)
		if tagErr_enc_uuindicator != nil {
			return nil, fmt.Errorf("encoding uuIndicator: %w", tagErr_enc_uuindicator)
		}
		enc_uuindicator = retagged_enc_uuindicator
		children = append(children, enc_uuindicator...)
	}
	if v.Uui != nil {
		enc_uui := ber.EncodeOctetString([]byte(*v.Uui))
		retagged_enc_uui, tagErr_enc_uui := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_uui)
		if tagErr_enc_uui != nil {
			return nil, fmt.Errorf("encoding uui: %w", tagErr_enc_uui)
		}
		enc_uui = retagged_enc_uui
		children = append(children, enc_uui...)
	}
	if v.UusCFInteraction != nil {
		enc_uuscfinteraction := ber.EncodeNull()
		retagged_enc_uuscfinteraction, tagErr_enc_uuscfinteraction := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_uuscfinteraction)
		if tagErr_enc_uuscfinteraction != nil {
			return nil, fmt.Errorf("encoding uusCFInteraction: %w", tagErr_enc_uuscfinteraction)
		}
		enc_uuscfinteraction = retagged_enc_uuscfinteraction
		children = append(children, enc_uuscfinteraction...)
	}
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding extensionContainer: %w", err)
		}
		retagged_enc_extensioncontainer, tagErr_enc_extensioncontainer := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, enc_extensioncontainer)
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

// MarshalDER encodes UUData to DER format.
func (v *UUData) MarshalDER() ([]byte, error) {
	var children []byte
	if v.UuIndicator != nil {
		enc_uuindicator := ber.EncodeOctetString([]byte(*v.UuIndicator))
		retagged_enc_uuindicator, tagErr_enc_uuindicator := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_uuindicator)
		if tagErr_enc_uuindicator != nil {
			return nil, fmt.Errorf("encoding uuIndicator: %w", tagErr_enc_uuindicator)
		}
		enc_uuindicator = retagged_enc_uuindicator
		children = append(children, enc_uuindicator...)
	}
	if v.Uui != nil {
		enc_uui := ber.EncodeOctetString([]byte(*v.Uui))
		retagged_enc_uui, tagErr_enc_uui := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_uui)
		if tagErr_enc_uui != nil {
			return nil, fmt.Errorf("encoding uui: %w", tagErr_enc_uui)
		}
		enc_uui = retagged_enc_uui
		children = append(children, enc_uui...)
	}
	if v.UusCFInteraction != nil {
		enc_uuscfinteraction := ber.EncodeNull()
		retagged_enc_uuscfinteraction, tagErr_enc_uuscfinteraction := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_uuscfinteraction)
		if tagErr_enc_uuscfinteraction != nil {
			return nil, fmt.Errorf("encoding uusCFInteraction: %w", tagErr_enc_uuscfinteraction)
		}
		enc_uuscfinteraction = retagged_enc_uuscfinteraction
		children = append(children, enc_uuscfinteraction...)
	}
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding extensionContainer: %w", err)
		}
		retagged_enc_extensioncontainer, tagErr_enc_extensioncontainer := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, enc_extensioncontainer)
		if tagErr_enc_extensioncontainer != nil {
			return nil, fmt.Errorf("encoding extensionContainer: %w", tagErr_enc_extensioncontainer)
		}
		enc_extensioncontainer = retagged_enc_extensioncontainer
		children = append(children, enc_extensioncontainer...)
	}
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
		children = append(children, ext...)
	}
	encoded := ber.EncodeSequence(children)
	if err := ber.ValidateDERElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding UUData as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes UUData from BER/DER format.
func (v *UUData) UnmarshalBER(data []byte) error {
	*v = UUData{}
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding UUData SEQUENCE: %w", err)
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
				decodedTag_uuindicator, n_uuindicator, rawVal_uuindicator, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding uuIndicator: %w", err)
				}
				if decodedTag_uuindicator.Class != tag.ClassContextSpecific || decodedTag_uuindicator.Number != 0 {
					return fmt.Errorf("decoding uuIndicator: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_uuindicator)
				}
				tmp_uuindicator := UUIndicator(rawVal_uuindicator)
				v.UuIndicator = &tmp_uuindicator
				offset += n_uuindicator
			}
		}
	}
	// Decode uui
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
				decodedTag_uui, n_uui, rawVal_uui, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding uui: %w", err)
				}
				if decodedTag_uui.Class != tag.ClassContextSpecific || decodedTag_uui.Number != 1 {
					return fmt.Errorf("decoding uui: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_uui)
				}
				tmp_uui := UUI(rawVal_uui)
				v.Uui = &tmp_uui
				offset += n_uui
			}
		}
	}
	// Decode uusCFInteraction
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2 {
				decodedTag_uuscfinteraction, n_uuscfinteraction, rawVal_uuscfinteraction, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding uusCFInteraction: %w", err)
				}
				if decodedTag_uuscfinteraction.Class != tag.ClassContextSpecific || decodedTag_uuscfinteraction.Number != 2 || decodedTag_uuscfinteraction.Constructed != false {
					return fmt.Errorf("decoding uusCFInteraction: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_uuscfinteraction)
				}
				if len(rawVal_uuscfinteraction) != 0 {
					return fmt.Errorf("decoding uusCFInteraction: %w: NULL content length %d", ber.ErrInvalidValue, len(rawVal_uuscfinteraction))
				}
				v.UusCFInteraction = &struct{}{}
				offset += n_uuscfinteraction
			}
		}
	}
	// Decode extensionContainer
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3 {
				decodedTag_extensioncontainer, n_extensioncontainer, rawVal_extensioncontainer, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding extensionContainer: %w", err)
				}
				if decodedTag_extensioncontainer.Class != tag.ClassContextSpecific || decodedTag_extensioncontainer.Number != 3 || decodedTag_extensioncontainer.Constructed != true {
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
			return &ber.DecodeError{Offset: offset, TypeName: "UUData", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes ResumeCallHandlingRes to BER format.
func (v *ResumeCallHandlingRes) MarshalBER() ([]byte, error) {
	var children []byte
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding extensionContainer: %w", err)
		}
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

// MarshalDER encodes ResumeCallHandlingRes to DER format.
func (v *ResumeCallHandlingRes) MarshalDER() ([]byte, error) {
	var children []byte
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding extensionContainer: %w", err)
		}
		children = append(children, enc_extensioncontainer...)
	}
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
		children = append(children, ext...)
	}
	encoded := ber.EncodeSequence(children)
	if err := ber.ValidateDERElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding ResumeCallHandlingRes as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes ResumeCallHandlingRes from BER/DER format.
func (v *ResumeCallHandlingRes) UnmarshalBER(data []byte) error {
	*v = ResumeCallHandlingRes{}
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding ResumeCallHandlingRes SEQUENCE: %w", err)
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
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "ResumeCallHandlingRes", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes CamelInfo to BER format.
func (v *CamelInfo) MarshalBER() ([]byte, error) {
	var children []byte
	enc_supportedcamelphases := ber.EncodeBitString(v.SupportedCamelPhases.Bytes, (8-(v.SupportedCamelPhases.BitLength%8))%8)
	children = append(children, enc_supportedcamelphases...)
	if v.SuppressTCSI != nil {
		enc_suppresstcsi := ber.EncodeNull()
		children = append(children, enc_suppresstcsi...)
	}
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding extensionContainer: %w", err)
		}
		children = append(children, enc_extensioncontainer...)
	}
	if v.OfferedCamel4CSIs != nil {
		enc_offeredcamel4csis := ber.EncodeBitString(v.OfferedCamel4CSIs.Bytes, (8-(v.OfferedCamel4CSIs.BitLength%8))%8)
		retagged_enc_offeredcamel4csis, tagErr_enc_offeredcamel4csis := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_offeredcamel4csis)
		if tagErr_enc_offeredcamel4csis != nil {
			return nil, fmt.Errorf("encoding offeredCamel4CSIs: %w", tagErr_enc_offeredcamel4csis)
		}
		enc_offeredcamel4csis = retagged_enc_offeredcamel4csis
		children = append(children, enc_offeredcamel4csis...)
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

// MarshalDER encodes CamelInfo to DER format.
func (v *CamelInfo) MarshalDER() ([]byte, error) {
	var children []byte
	enc_supportedcamelphases := ber.EncodeBitString(v.SupportedCamelPhases.Bytes, (8-(v.SupportedCamelPhases.BitLength%8))%8)
	children = append(children, enc_supportedcamelphases...)
	if v.SuppressTCSI != nil {
		enc_suppresstcsi := ber.EncodeNull()
		children = append(children, enc_suppresstcsi...)
	}
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding extensionContainer: %w", err)
		}
		children = append(children, enc_extensioncontainer...)
	}
	if v.OfferedCamel4CSIs != nil {
		enc_offeredcamel4csis := ber.EncodeBitString(v.OfferedCamel4CSIs.Bytes, (8-(v.OfferedCamel4CSIs.BitLength%8))%8)
		retagged_enc_offeredcamel4csis, tagErr_enc_offeredcamel4csis := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_offeredcamel4csis)
		if tagErr_enc_offeredcamel4csis != nil {
			return nil, fmt.Errorf("encoding offeredCamel4CSIs: %w", tagErr_enc_offeredcamel4csis)
		}
		enc_offeredcamel4csis = retagged_enc_offeredcamel4csis
		children = append(children, enc_offeredcamel4csis...)
	}
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
		children = append(children, ext...)
	}
	encoded := ber.EncodeSequence(children)
	if err := ber.ValidateDERElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding CamelInfo as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes CamelInfo from BER/DER format.
func (v *CamelInfo) UnmarshalBER(data []byte) error {
	*v = CamelInfo{}
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding CamelInfo SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "CamelInfo", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode supportedCamelPhases
	if offset >= len(content) {
		return fmt.Errorf("missing required field supportedCamelPhases")
	}
	bsBytes_supportedcamelphases, bsUnused_supportedcamelphases, n, err := ber.DecodeBitString(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding supportedCamelPhases: %w", err)
	}
	v.SupportedCamelPhases = runtime.BitString{Bytes: bsBytes_supportedcamelphases, BitLength: len(bsBytes_supportedcamelphases)*8 - bsUnused_supportedcamelphases}
	offset += n
	// Decode suppress-T-CSI
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassUniversal && peekTag.Number == 5 {
				n, err := ber.DecodeNull(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding suppress-T-CSI: %w", err)
				}
				v.SuppressTCSI = &struct{}{}
				offset += n
			}
		}
	}
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
	// Decode offeredCamel4CSIs
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
				decodedTag_offeredcamel4csis, n_offeredcamel4csis, rawVal_offeredcamel4csis, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding offeredCamel4CSIs: %w", err)
				}
				if decodedTag_offeredcamel4csis.Class != tag.ClassContextSpecific || decodedTag_offeredcamel4csis.Number != 0 {
					return fmt.Errorf("decoding offeredCamel4CSIs: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_offeredcamel4csis)
				}
				bsBytes_offeredcamel4csis, bsUnused_offeredcamel4csis, bsErr := ber.DecodeImplicitBitStringValue(decodedTag_offeredcamel4csis.Constructed, rawVal_offeredcamel4csis)
				if bsErr != nil {
					return fmt.Errorf("decoding offeredCamel4CSIs: %w", bsErr)
				}
				tmp_offeredcamel4csis := runtime.BitString{Bytes: bsBytes_offeredcamel4csis, BitLength: len(bsBytes_offeredcamel4csis)*8 - bsUnused_offeredcamel4csis}
				v.OfferedCamel4CSIs = &tmp_offeredcamel4csis
				offset += n_offeredcamel4csis
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "CamelInfo", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes ExtendedRoutingInfo to BER format.
func (v *ExtendedRoutingInfo) MarshalBER() ([]byte, error) {
	switch v.Choice {
	case ExtendedRoutingInfoChoiceRoutingInfo:
		if v.RoutingInfo == nil {
			return nil, fmt.Errorf("choice ExtendedRoutingInfo: routingInfo is nil")
		}
		enc_0, err := v.RoutingInfo.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding routingInfo: %w", err)
		}
		return enc_0, nil
	case ExtendedRoutingInfoChoiceCamelRoutingInfo:
		if v.CamelRoutingInfo == nil {
			return nil, fmt.Errorf("choice ExtendedRoutingInfo: camelRoutingInfo is nil")
		}
		enc_1, err := v.CamelRoutingInfo.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding camelRoutingInfo: %w", err)
		}
		retagged_enc_1, tagErr_enc_1 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 8, enc_1)
		if tagErr_enc_1 != nil {
			return nil, fmt.Errorf("encoding camelRoutingInfo: %w", tagErr_enc_1)
		}
		enc_1 = retagged_enc_1
		return enc_1, nil
	default:
		return nil, fmt.Errorf("unknown choice %d for ExtendedRoutingInfo", v.Choice)
	}
}

// MarshalDER encodes ExtendedRoutingInfo to DER format.
func (v *ExtendedRoutingInfo) MarshalDER() ([]byte, error) {
	switch v.Choice {
	case ExtendedRoutingInfoChoiceRoutingInfo:
		if v.RoutingInfo == nil {
			return nil, fmt.Errorf("choice ExtendedRoutingInfo: routingInfo is nil")
		}
		enc_der_0, err := v.RoutingInfo.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding routingInfo: %w", err)
		}
		if derErr := ber.ValidateDERElement(enc_der_0); derErr != nil {
			return nil, fmt.Errorf("encoding routingInfo as DER: %w", derErr)
		}
		return enc_der_0, nil
	case ExtendedRoutingInfoChoiceCamelRoutingInfo:
		if v.CamelRoutingInfo == nil {
			return nil, fmt.Errorf("choice ExtendedRoutingInfo: camelRoutingInfo is nil")
		}
		enc_der_1, err := v.CamelRoutingInfo.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding camelRoutingInfo: %w", err)
		}
		retagged_enc_der_1, tagErr_enc_der_1 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 8, enc_der_1)
		if tagErr_enc_der_1 != nil {
			return nil, fmt.Errorf("encoding camelRoutingInfo: %w", tagErr_enc_der_1)
		}
		enc_der_1 = retagged_enc_der_1
		if derErr := ber.ValidateDERElement(enc_der_1); derErr != nil {
			return nil, fmt.Errorf("encoding camelRoutingInfo as DER: %w", derErr)
		}
		return enc_der_1, nil
	}
	encoded, err := v.MarshalBER()
	if err != nil {
		return nil, err
	}
	if err := ber.ValidateDERElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding ExtendedRoutingInfo as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes ExtendedRoutingInfo from BER/DER format.
func (v *ExtendedRoutingInfo) UnmarshalBER(data []byte) error {
	*v = ExtendedRoutingInfo{}
	if len(data) == 0 {
		return fmt.Errorf("empty data for ExtendedRoutingInfo CHOICE")
	}
	choiceData := data
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for ExtendedRoutingInfo: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData)
	if tlvErr != nil {
		return fmt.Errorf("decoding ExtendedRoutingInfo CHOICE: %w", tlvErr)
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "ExtendedRoutingInfo", Cause: ber.ErrExtraData}
	}

	if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 8 && peekTag.Constructed == true {
		v.Choice = ExtendedRoutingInfoChoiceCamelRoutingInfo
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding camelRoutingInfo: %w", tlvErr)
		}
		reconstructed := ber.EncodeSequence(rawVal)
		var dec CamelRoutingInfo
		if unmErr := dec.UnmarshalBER(reconstructed); unmErr != nil {
			return fmt.Errorf("decoding camelRoutingInfo: %w", unmErr)
		}
		v.CamelRoutingInfo = &dec
	} else {
		v.Choice = ExtendedRoutingInfoChoiceRoutingInfo
		var dec RoutingInfo
		if unmErr := dec.UnmarshalBER(choiceData); unmErr != nil {
			return fmt.Errorf("decoding routingInfo: %w", unmErr)
		}
		v.RoutingInfo = &dec
	}
	return nil
}

// MarshalBER encodes CamelRoutingInfo to BER format.
func (v *CamelRoutingInfo) MarshalBER() ([]byte, error) {
	var children []byte
	if v.ForwardingData != nil {
		enc_forwardingdata, err := v.ForwardingData.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding forwardingData: %w", err)
		}
		children = append(children, enc_forwardingdata...)
	}
	enc_gmsccamelsubscriptioninfo, err := v.GmscCamelSubscriptionInfo.MarshalBER()
	if err != nil {
		return nil, fmt.Errorf("encoding gmscCamelSubscriptionInfo: %w", err)
	}
	retagged_enc_gmsccamelsubscriptioninfo, tagErr_enc_gmsccamelsubscriptioninfo := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_gmsccamelsubscriptioninfo)
	if tagErr_enc_gmsccamelsubscriptioninfo != nil {
		return nil, fmt.Errorf("encoding gmscCamelSubscriptionInfo: %w", tagErr_enc_gmsccamelsubscriptioninfo)
	}
	enc_gmsccamelsubscriptioninfo = retagged_enc_gmsccamelsubscriptioninfo
	children = append(children, enc_gmsccamelsubscriptioninfo...)
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

// MarshalDER encodes CamelRoutingInfo to DER format.
func (v *CamelRoutingInfo) MarshalDER() ([]byte, error) {
	var children []byte
	if v.ForwardingData != nil {
		enc_forwardingdata, err := v.ForwardingData.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding forwardingData: %w", err)
		}
		children = append(children, enc_forwardingdata...)
	}
	enc_gmsccamelsubscriptioninfo, err := v.GmscCamelSubscriptionInfo.MarshalDER()
	if err != nil {
		return nil, fmt.Errorf("encoding gmscCamelSubscriptionInfo: %w", err)
	}
	retagged_enc_gmsccamelsubscriptioninfo, tagErr_enc_gmsccamelsubscriptioninfo := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_gmsccamelsubscriptioninfo)
	if tagErr_enc_gmsccamelsubscriptioninfo != nil {
		return nil, fmt.Errorf("encoding gmscCamelSubscriptionInfo: %w", tagErr_enc_gmsccamelsubscriptioninfo)
	}
	enc_gmsccamelsubscriptioninfo = retagged_enc_gmsccamelsubscriptioninfo
	children = append(children, enc_gmsccamelsubscriptioninfo...)
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
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
		children = append(children, ext...)
	}
	encoded := ber.EncodeSequence(children)
	if err := ber.ValidateDERElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding CamelRoutingInfo as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes CamelRoutingInfo from BER/DER format.
func (v *CamelRoutingInfo) UnmarshalBER(data []byte) error {
	*v = CamelRoutingInfo{}
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding CamelRoutingInfo SEQUENCE: %w", err)
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
				// Decode nested SEQUENCE (ForwardingData)
				_, n_forwardingdata, _, tlvErr_forwardingdata := ber.DecodeTLV(content[offset:])
				if tlvErr_forwardingdata != nil {
					return fmt.Errorf("decoding forwardingData: %w", tlvErr_forwardingdata)
				}
				var dec_forwardingdata ForwardingData
				if unmErr := dec_forwardingdata.UnmarshalBER(content[offset : offset+n_forwardingdata]); unmErr != nil {
					return fmt.Errorf("decoding forwardingData: %w", unmErr)
				}
				v.ForwardingData = &dec_forwardingdata
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
	decodedTag_gmsccamelsubscriptioninfo, n_gmsccamelsubscriptioninfo, rawVal_gmsccamelsubscriptioninfo, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding gmscCamelSubscriptionInfo: %w", err)
	}
	if decodedTag_gmsccamelsubscriptioninfo.Class != tag.ClassContextSpecific || decodedTag_gmsccamelsubscriptioninfo.Number != 0 || decodedTag_gmsccamelsubscriptioninfo.Constructed != true {
		return fmt.Errorf("decoding gmscCamelSubscriptionInfo: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_gmsccamelsubscriptioninfo)
	}
	reconstructed_gmsccamelsubscriptioninfo := ber.EncodeSequence(rawVal_gmsccamelsubscriptioninfo)
	if unmErr := v.GmscCamelSubscriptionInfo.UnmarshalBER(reconstructed_gmsccamelsubscriptioninfo); unmErr != nil {
		return fmt.Errorf("decoding gmscCamelSubscriptionInfo: %w", unmErr)
	}
	offset += n_gmsccamelsubscriptioninfo
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
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "CamelRoutingInfo", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes GmscCamelSubscriptionInfo to BER format.
func (v *GmscCamelSubscriptionInfo) MarshalBER() ([]byte, error) {
	var children []byte
	if v.TCSI != nil {
		enc_tcsi, err := v.TCSI.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding t-CSI: %w", err)
		}
		retagged_enc_tcsi, tagErr_enc_tcsi := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_tcsi)
		if tagErr_enc_tcsi != nil {
			return nil, fmt.Errorf("encoding t-CSI: %w", tagErr_enc_tcsi)
		}
		enc_tcsi = retagged_enc_tcsi
		children = append(children, enc_tcsi...)
	}
	if v.OCSI != nil {
		enc_ocsi, err := v.OCSI.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding o-CSI: %w", err)
		}
		retagged_enc_ocsi, tagErr_enc_ocsi := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_ocsi)
		if tagErr_enc_ocsi != nil {
			return nil, fmt.Errorf("encoding o-CSI: %w", tagErr_enc_ocsi)
		}
		enc_ocsi = retagged_enc_ocsi
		children = append(children, enc_ocsi...)
	}
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
	if v.OBcsmCamelTDPCriteriaList != nil {
		enc_obcsmcameltdpcriterialist, err := MarshalBEROBcsmCamelTDPCriteriaList(v.OBcsmCamelTDPCriteriaList)
		if err != nil {
			return nil, fmt.Errorf("encoding o-BcsmCamelTDP-CriteriaList: %w", err)
		}
		if v.OBcsmCamelTDPCriteriaListIndef_ {
			// Strip the outer SEQUENCE tag from marshalBER output to get raw children.
			_, _, seqContent_, tlvErr_ := ber.DecodeTLV(enc_obcsmcameltdpcriterialist)
			if tlvErr_ != nil {
				return nil, tlvErr_
			}
			enc_obcsmcameltdpcriterialist = ber.EncodeConstructedIndefinite(tag.Tag{Class: tag.ClassContextSpecific, Number: 3}, seqContent_)
		} else {
			retagged_enc_obcsmcameltdpcriterialist, tagErr_enc_obcsmcameltdpcriterialist := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, enc_obcsmcameltdpcriterialist)
			if tagErr_enc_obcsmcameltdpcriterialist != nil {
				return nil, fmt.Errorf("encoding o-BcsmCamelTDP-CriteriaList: %w", tagErr_enc_obcsmcameltdpcriterialist)
			}
			enc_obcsmcameltdpcriterialist = retagged_enc_obcsmcameltdpcriterialist
		}
		children = append(children, enc_obcsmcameltdpcriterialist...)
	}
	if v.TBCSMCAMELTDPCriteriaList != nil {
		enc_tbcsmcameltdpcriterialist, err := MarshalBERTBCSMCAMELTDPCriteriaList(v.TBCSMCAMELTDPCriteriaList)
		if err != nil {
			return nil, fmt.Errorf("encoding t-BCSM-CAMEL-TDP-CriteriaList: %w", err)
		}
		if v.TBCSMCAMELTDPCriteriaListIndef_ {
			// Strip the outer SEQUENCE tag from marshalBER output to get raw children.
			_, _, seqContent_, tlvErr_ := ber.DecodeTLV(enc_tbcsmcameltdpcriterialist)
			if tlvErr_ != nil {
				return nil, tlvErr_
			}
			enc_tbcsmcameltdpcriterialist = ber.EncodeConstructedIndefinite(tag.Tag{Class: tag.ClassContextSpecific, Number: 4}, seqContent_)
		} else {
			retagged_enc_tbcsmcameltdpcriterialist, tagErr_enc_tbcsmcameltdpcriterialist := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, enc_tbcsmcameltdpcriterialist)
			if tagErr_enc_tbcsmcameltdpcriterialist != nil {
				return nil, fmt.Errorf("encoding t-BCSM-CAMEL-TDP-CriteriaList: %w", tagErr_enc_tbcsmcameltdpcriterialist)
			}
			enc_tbcsmcameltdpcriterialist = retagged_enc_tbcsmcameltdpcriterialist
		}
		children = append(children, enc_tbcsmcameltdpcriterialist...)
	}
	if v.DCsi != nil {
		enc_dcsi, err := v.DCsi.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding d-csi: %w", err)
		}
		retagged_enc_dcsi, tagErr_enc_dcsi := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 5, enc_dcsi)
		if tagErr_enc_dcsi != nil {
			return nil, fmt.Errorf("encoding d-csi: %w", tagErr_enc_dcsi)
		}
		enc_dcsi = retagged_enc_dcsi
		children = append(children, enc_dcsi...)
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

// MarshalDER encodes GmscCamelSubscriptionInfo to DER format.
func (v *GmscCamelSubscriptionInfo) MarshalDER() ([]byte, error) {
	var children []byte
	if v.TCSI != nil {
		enc_tcsi, err := v.TCSI.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding t-CSI: %w", err)
		}
		retagged_enc_tcsi, tagErr_enc_tcsi := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_tcsi)
		if tagErr_enc_tcsi != nil {
			return nil, fmt.Errorf("encoding t-CSI: %w", tagErr_enc_tcsi)
		}
		enc_tcsi = retagged_enc_tcsi
		children = append(children, enc_tcsi...)
	}
	if v.OCSI != nil {
		enc_ocsi, err := v.OCSI.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding o-CSI: %w", err)
		}
		retagged_enc_ocsi, tagErr_enc_ocsi := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_ocsi)
		if tagErr_enc_ocsi != nil {
			return nil, fmt.Errorf("encoding o-CSI: %w", tagErr_enc_ocsi)
		}
		enc_ocsi = retagged_enc_ocsi
		children = append(children, enc_ocsi...)
	}
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
	if v.OBcsmCamelTDPCriteriaList != nil {
		enc_obcsmcameltdpcriterialist, err := MarshalDEROBcsmCamelTDPCriteriaList(v.OBcsmCamelTDPCriteriaList)
		if err != nil {
			return nil, fmt.Errorf("encoding o-BcsmCamelTDP-CriteriaList: %w", err)
		}
		retagged_enc_obcsmcameltdpcriterialist, tagErr_enc_obcsmcameltdpcriterialist := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, enc_obcsmcameltdpcriterialist)
		if tagErr_enc_obcsmcameltdpcriterialist != nil {
			return nil, fmt.Errorf("encoding o-BcsmCamelTDP-CriteriaList: %w", tagErr_enc_obcsmcameltdpcriterialist)
		}
		enc_obcsmcameltdpcriterialist = retagged_enc_obcsmcameltdpcriterialist
		children = append(children, enc_obcsmcameltdpcriterialist...)
	}
	if v.TBCSMCAMELTDPCriteriaList != nil {
		enc_tbcsmcameltdpcriterialist, err := MarshalDERTBCSMCAMELTDPCriteriaList(v.TBCSMCAMELTDPCriteriaList)
		if err != nil {
			return nil, fmt.Errorf("encoding t-BCSM-CAMEL-TDP-CriteriaList: %w", err)
		}
		retagged_enc_tbcsmcameltdpcriterialist, tagErr_enc_tbcsmcameltdpcriterialist := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, enc_tbcsmcameltdpcriterialist)
		if tagErr_enc_tbcsmcameltdpcriterialist != nil {
			return nil, fmt.Errorf("encoding t-BCSM-CAMEL-TDP-CriteriaList: %w", tagErr_enc_tbcsmcameltdpcriterialist)
		}
		enc_tbcsmcameltdpcriterialist = retagged_enc_tbcsmcameltdpcriterialist
		children = append(children, enc_tbcsmcameltdpcriterialist...)
	}
	if v.DCsi != nil {
		enc_dcsi, err := v.DCsi.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding d-csi: %w", err)
		}
		retagged_enc_dcsi, tagErr_enc_dcsi := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 5, enc_dcsi)
		if tagErr_enc_dcsi != nil {
			return nil, fmt.Errorf("encoding d-csi: %w", tagErr_enc_dcsi)
		}
		enc_dcsi = retagged_enc_dcsi
		children = append(children, enc_dcsi...)
	}
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
		children = append(children, ext...)
	}
	encoded := ber.EncodeSequence(children)
	if err := ber.ValidateDERElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding GmscCamelSubscriptionInfo as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes GmscCamelSubscriptionInfo from BER/DER format.
func (v *GmscCamelSubscriptionInfo) UnmarshalBER(data []byte) error {
	*v = GmscCamelSubscriptionInfo{}
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding GmscCamelSubscriptionInfo SEQUENCE: %w", err)
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
				decodedTag_tcsi, n_tcsi, rawVal_tcsi, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding t-CSI: %w", err)
				}
				if decodedTag_tcsi.Class != tag.ClassContextSpecific || decodedTag_tcsi.Number != 0 || decodedTag_tcsi.Constructed != true {
					return fmt.Errorf("decoding t-CSI: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_tcsi)
				}
				reconstructed_tcsi := ber.EncodeSequence(rawVal_tcsi)
				var dec_tcsi TCSI
				if unmErr := dec_tcsi.UnmarshalBER(reconstructed_tcsi); unmErr != nil {
					return fmt.Errorf("decoding t-CSI: %w", unmErr)
				}
				v.TCSI = &dec_tcsi
				offset += n_tcsi
			}
		}
	}
	// Decode o-CSI
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
				decodedTag_ocsi, n_ocsi, rawVal_ocsi, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding o-CSI: %w", err)
				}
				if decodedTag_ocsi.Class != tag.ClassContextSpecific || decodedTag_ocsi.Number != 1 || decodedTag_ocsi.Constructed != true {
					return fmt.Errorf("decoding o-CSI: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_ocsi)
				}
				reconstructed_ocsi := ber.EncodeSequence(rawVal_ocsi)
				var dec_ocsi OCSI
				if unmErr := dec_ocsi.UnmarshalBER(reconstructed_ocsi); unmErr != nil {
					return fmt.Errorf("decoding o-CSI: %w", unmErr)
				}
				v.OCSI = &dec_ocsi
				offset += n_ocsi
			}
		}
	}
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
	// Decode o-BcsmCamelTDP-CriteriaList
	v.OBcsmCamelTDPCriteriaListIndef_ = false
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3 {
				decodedTag_obcsmcameltdpcriterialist, n_obcsmcameltdpcriterialist, rawVal_obcsmcameltdpcriterialist, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding o-BcsmCamelTDP-CriteriaList: %w", err)
				}
				if decodedTag_obcsmcameltdpcriterialist.Class != tag.ClassContextSpecific || decodedTag_obcsmcameltdpcriterialist.Number != 3 || decodedTag_obcsmcameltdpcriterialist.Constructed != true {
					return fmt.Errorf("decoding o-BcsmCamelTDP-CriteriaList: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_obcsmcameltdpcriterialist)
				}
				reconstructed_obcsmcameltdpcriterialist := ber.EncodeSequence(rawVal_obcsmcameltdpcriterialist)
				dec_obcsmcameltdpcriterialist, unmErr := UnmarshalBEROBcsmCamelTDPCriteriaList(reconstructed_obcsmcameltdpcriterialist)
				if unmErr != nil {
					return fmt.Errorf("decoding o-BcsmCamelTDP-CriteriaList: %w", unmErr)
				}
				v.OBcsmCamelTDPCriteriaList = dec_obcsmcameltdpcriterialist
				{
					_, tagSz_, _ := ber.DecodeTag(content[offset:])
					if offset+tagSz_ < len(content) && content[offset+tagSz_] == 0x80 {
						v.OBcsmCamelTDPCriteriaListIndef_ = true
					}
				}
				offset += n_obcsmcameltdpcriterialist
			}
		}
	}
	// Decode t-BCSM-CAMEL-TDP-CriteriaList
	v.TBCSMCAMELTDPCriteriaListIndef_ = false
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4 {
				decodedTag_tbcsmcameltdpcriterialist, n_tbcsmcameltdpcriterialist, rawVal_tbcsmcameltdpcriterialist, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding t-BCSM-CAMEL-TDP-CriteriaList: %w", err)
				}
				if decodedTag_tbcsmcameltdpcriterialist.Class != tag.ClassContextSpecific || decodedTag_tbcsmcameltdpcriterialist.Number != 4 || decodedTag_tbcsmcameltdpcriterialist.Constructed != true {
					return fmt.Errorf("decoding t-BCSM-CAMEL-TDP-CriteriaList: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_tbcsmcameltdpcriterialist)
				}
				reconstructed_tbcsmcameltdpcriterialist := ber.EncodeSequence(rawVal_tbcsmcameltdpcriterialist)
				dec_tbcsmcameltdpcriterialist, unmErr := UnmarshalBERTBCSMCAMELTDPCriteriaList(reconstructed_tbcsmcameltdpcriterialist)
				if unmErr != nil {
					return fmt.Errorf("decoding t-BCSM-CAMEL-TDP-CriteriaList: %w", unmErr)
				}
				v.TBCSMCAMELTDPCriteriaList = dec_tbcsmcameltdpcriterialist
				{
					_, tagSz_, _ := ber.DecodeTag(content[offset:])
					if offset+tagSz_ < len(content) && content[offset+tagSz_] == 0x80 {
						v.TBCSMCAMELTDPCriteriaListIndef_ = true
					}
				}
				offset += n_tbcsmcameltdpcriterialist
			}
		}
	}
	// Decode d-csi
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 5 {
				decodedTag_dcsi, n_dcsi, rawVal_dcsi, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding d-csi: %w", err)
				}
				if decodedTag_dcsi.Class != tag.ClassContextSpecific || decodedTag_dcsi.Number != 5 || decodedTag_dcsi.Constructed != true {
					return fmt.Errorf("decoding d-csi: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_dcsi)
				}
				reconstructed_dcsi := ber.EncodeSequence(rawVal_dcsi)
				var dec_dcsi DCSI
				if unmErr := dec_dcsi.UnmarshalBER(reconstructed_dcsi); unmErr != nil {
					return fmt.Errorf("decoding d-csi: %w", unmErr)
				}
				v.DCsi = &dec_dcsi
				offset += n_dcsi
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "GmscCamelSubscriptionInfo", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes SetReportingStateArg to BER format.
func (v *SetReportingStateArg) MarshalBER() ([]byte, error) {
	var children []byte
	if v.Imsi != nil {
		enc_imsi := ber.EncodeOctetString([]byte(*v.Imsi))
		retagged_enc_imsi, tagErr_enc_imsi := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_imsi)
		if tagErr_enc_imsi != nil {
			return nil, fmt.Errorf("encoding imsi: %w", tagErr_enc_imsi)
		}
		enc_imsi = retagged_enc_imsi
		children = append(children, enc_imsi...)
	}
	if v.Lmsi != nil {
		enc_lmsi := ber.EncodeOctetString([]byte(*v.Lmsi))
		retagged_enc_lmsi, tagErr_enc_lmsi := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_lmsi)
		if tagErr_enc_lmsi != nil {
			return nil, fmt.Errorf("encoding lmsi: %w", tagErr_enc_lmsi)
		}
		enc_lmsi = retagged_enc_lmsi
		children = append(children, enc_lmsi...)
	}
	if v.CcbsMonitoring != nil {
		enc_ccbsmonitoring := ber.EncodeEnumerated(int64(*v.CcbsMonitoring))
		retagged_enc_ccbsmonitoring, tagErr_enc_ccbsmonitoring := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_ccbsmonitoring)
		if tagErr_enc_ccbsmonitoring != nil {
			return nil, fmt.Errorf("encoding ccbs-Monitoring: %w", tagErr_enc_ccbsmonitoring)
		}
		enc_ccbsmonitoring = retagged_enc_ccbsmonitoring
		children = append(children, enc_ccbsmonitoring...)
	}
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding extensionContainer: %w", err)
		}
		retagged_enc_extensioncontainer, tagErr_enc_extensioncontainer := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, enc_extensioncontainer)
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

// MarshalDER encodes SetReportingStateArg to DER format.
func (v *SetReportingStateArg) MarshalDER() ([]byte, error) {
	var children []byte
	if v.Imsi != nil {
		enc_imsi := ber.EncodeOctetString([]byte(*v.Imsi))
		retagged_enc_imsi, tagErr_enc_imsi := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_imsi)
		if tagErr_enc_imsi != nil {
			return nil, fmt.Errorf("encoding imsi: %w", tagErr_enc_imsi)
		}
		enc_imsi = retagged_enc_imsi
		children = append(children, enc_imsi...)
	}
	if v.Lmsi != nil {
		enc_lmsi := ber.EncodeOctetString([]byte(*v.Lmsi))
		retagged_enc_lmsi, tagErr_enc_lmsi := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_lmsi)
		if tagErr_enc_lmsi != nil {
			return nil, fmt.Errorf("encoding lmsi: %w", tagErr_enc_lmsi)
		}
		enc_lmsi = retagged_enc_lmsi
		children = append(children, enc_lmsi...)
	}
	if v.CcbsMonitoring != nil {
		enc_ccbsmonitoring := ber.EncodeEnumerated(int64(*v.CcbsMonitoring))
		retagged_enc_ccbsmonitoring, tagErr_enc_ccbsmonitoring := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_ccbsmonitoring)
		if tagErr_enc_ccbsmonitoring != nil {
			return nil, fmt.Errorf("encoding ccbs-Monitoring: %w", tagErr_enc_ccbsmonitoring)
		}
		enc_ccbsmonitoring = retagged_enc_ccbsmonitoring
		children = append(children, enc_ccbsmonitoring...)
	}
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding extensionContainer: %w", err)
		}
		retagged_enc_extensioncontainer, tagErr_enc_extensioncontainer := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, enc_extensioncontainer)
		if tagErr_enc_extensioncontainer != nil {
			return nil, fmt.Errorf("encoding extensionContainer: %w", tagErr_enc_extensioncontainer)
		}
		enc_extensioncontainer = retagged_enc_extensioncontainer
		children = append(children, enc_extensioncontainer...)
	}
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
		children = append(children, ext...)
	}
	encoded := ber.EncodeSequence(children)
	if err := ber.ValidateDERElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding SetReportingStateArg as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes SetReportingStateArg from BER/DER format.
func (v *SetReportingStateArg) UnmarshalBER(data []byte) error {
	*v = SetReportingStateArg{}
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding SetReportingStateArg SEQUENCE: %w", err)
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
				decodedTag_imsi, n_imsi, rawVal_imsi, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding imsi: %w", err)
				}
				if decodedTag_imsi.Class != tag.ClassContextSpecific || decodedTag_imsi.Number != 0 {
					return fmt.Errorf("decoding imsi: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_imsi)
				}
				tmp_imsi := IMSI(rawVal_imsi)
				v.Imsi = &tmp_imsi
				offset += n_imsi
			}
		}
	}
	// Decode lmsi
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
				decodedTag_lmsi, n_lmsi, rawVal_lmsi, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding lmsi: %w", err)
				}
				if decodedTag_lmsi.Class != tag.ClassContextSpecific || decodedTag_lmsi.Number != 1 {
					return fmt.Errorf("decoding lmsi: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_lmsi)
				}
				tmp_lmsi := LMSI(rawVal_lmsi)
				v.Lmsi = &tmp_lmsi
				offset += n_lmsi
			}
		}
	}
	// Decode ccbs-Monitoring
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2 {
				decodedTag_ccbsmonitoring, n_ccbsmonitoring, rawVal_ccbsmonitoring, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding ccbs-Monitoring: %w", err)
				}
				if decodedTag_ccbsmonitoring.Class != tag.ClassContextSpecific || decodedTag_ccbsmonitoring.Number != 2 || decodedTag_ccbsmonitoring.Constructed != false {
					return fmt.Errorf("decoding ccbs-Monitoring: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_ccbsmonitoring)
				}
				decVal_ccbsmonitoring, intErr := ber.DecodeEnumeratedValue(rawVal_ccbsmonitoring)
				if intErr != nil {
					return fmt.Errorf("decoding ccbs-Monitoring: %w", intErr)
				}
				tmp_ccbsmonitoring := ReportingState(decVal_ccbsmonitoring)
				v.CcbsMonitoring = &tmp_ccbsmonitoring
				offset += n_ccbsmonitoring
			}
		}
	}
	// Decode extensionContainer
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3 {
				decodedTag_extensioncontainer, n_extensioncontainer, rawVal_extensioncontainer, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding extensionContainer: %w", err)
				}
				if decodedTag_extensioncontainer.Class != tag.ClassContextSpecific || decodedTag_extensioncontainer.Number != 3 || decodedTag_extensioncontainer.Constructed != true {
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
			return &ber.DecodeError{Offset: offset, TypeName: "SetReportingStateArg", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes SetReportingStateRes to BER format.
func (v *SetReportingStateRes) MarshalBER() ([]byte, error) {
	var children []byte
	if v.CcbsSubscriberStatus != nil {
		enc_ccbssubscriberstatus := ber.EncodeEnumerated(int64(*v.CcbsSubscriberStatus))
		retagged_enc_ccbssubscriberstatus, tagErr_enc_ccbssubscriberstatus := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_ccbssubscriberstatus)
		if tagErr_enc_ccbssubscriberstatus != nil {
			return nil, fmt.Errorf("encoding ccbs-SubscriberStatus: %w", tagErr_enc_ccbssubscriberstatus)
		}
		enc_ccbssubscriberstatus = retagged_enc_ccbssubscriberstatus
		children = append(children, enc_ccbssubscriberstatus...)
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

// MarshalDER encodes SetReportingStateRes to DER format.
func (v *SetReportingStateRes) MarshalDER() ([]byte, error) {
	var children []byte
	if v.CcbsSubscriberStatus != nil {
		enc_ccbssubscriberstatus := ber.EncodeEnumerated(int64(*v.CcbsSubscriberStatus))
		retagged_enc_ccbssubscriberstatus, tagErr_enc_ccbssubscriberstatus := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_ccbssubscriberstatus)
		if tagErr_enc_ccbssubscriberstatus != nil {
			return nil, fmt.Errorf("encoding ccbs-SubscriberStatus: %w", tagErr_enc_ccbssubscriberstatus)
		}
		enc_ccbssubscriberstatus = retagged_enc_ccbssubscriberstatus
		children = append(children, enc_ccbssubscriberstatus...)
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
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
		children = append(children, ext...)
	}
	encoded := ber.EncodeSequence(children)
	if err := ber.ValidateDERElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding SetReportingStateRes as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes SetReportingStateRes from BER/DER format.
func (v *SetReportingStateRes) UnmarshalBER(data []byte) error {
	*v = SetReportingStateRes{}
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding SetReportingStateRes SEQUENCE: %w", err)
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
				decodedTag_ccbssubscriberstatus, n_ccbssubscriberstatus, rawVal_ccbssubscriberstatus, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding ccbs-SubscriberStatus: %w", err)
				}
				if decodedTag_ccbssubscriberstatus.Class != tag.ClassContextSpecific || decodedTag_ccbssubscriberstatus.Number != 0 || decodedTag_ccbssubscriberstatus.Constructed != false {
					return fmt.Errorf("decoding ccbs-SubscriberStatus: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_ccbssubscriberstatus)
				}
				decVal_ccbssubscriberstatus, intErr := ber.DecodeEnumeratedValue(rawVal_ccbssubscriberstatus)
				if intErr != nil {
					return fmt.Errorf("decoding ccbs-SubscriberStatus: %w", intErr)
				}
				tmp_ccbssubscriberstatus := CCBSSubscriberStatus(decVal_ccbssubscriberstatus)
				v.CcbsSubscriberStatus = &tmp_ccbssubscriberstatus
				offset += n_ccbssubscriberstatus
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
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "SetReportingStateRes", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes StatusReportArg to BER format.
func (v *StatusReportArg) MarshalBER() ([]byte, error) {
	var children []byte
	enc_imsi := ber.EncodeOctetString([]byte(v.Imsi))
	retagged_enc_imsi, tagErr_enc_imsi := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_imsi)
	if tagErr_enc_imsi != nil {
		return nil, fmt.Errorf("encoding imsi: %w", tagErr_enc_imsi)
	}
	enc_imsi = retagged_enc_imsi
	children = append(children, enc_imsi...)
	if v.EventReportData != nil {
		enc_eventreportdata, err := v.EventReportData.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding eventReportData: %w", err)
		}
		retagged_enc_eventreportdata, tagErr_enc_eventreportdata := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_eventreportdata)
		if tagErr_enc_eventreportdata != nil {
			return nil, fmt.Errorf("encoding eventReportData: %w", tagErr_enc_eventreportdata)
		}
		enc_eventreportdata = retagged_enc_eventreportdata
		children = append(children, enc_eventreportdata...)
	}
	if v.CallReportdata != nil {
		enc_callreportdata, err := v.CallReportdata.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding callReportdata: %w", err)
		}
		retagged_enc_callreportdata, tagErr_enc_callreportdata := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_callreportdata)
		if tagErr_enc_callreportdata != nil {
			return nil, fmt.Errorf("encoding callReportdata: %w", tagErr_enc_callreportdata)
		}
		enc_callreportdata = retagged_enc_callreportdata
		children = append(children, enc_callreportdata...)
	}
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding extensionContainer: %w", err)
		}
		retagged_enc_extensioncontainer, tagErr_enc_extensioncontainer := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, enc_extensioncontainer)
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

// MarshalDER encodes StatusReportArg to DER format.
func (v *StatusReportArg) MarshalDER() ([]byte, error) {
	var children []byte
	enc_imsi := ber.EncodeOctetString([]byte(v.Imsi))
	retagged_enc_imsi, tagErr_enc_imsi := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_imsi)
	if tagErr_enc_imsi != nil {
		return nil, fmt.Errorf("encoding imsi: %w", tagErr_enc_imsi)
	}
	enc_imsi = retagged_enc_imsi
	children = append(children, enc_imsi...)
	if v.EventReportData != nil {
		enc_eventreportdata, err := v.EventReportData.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding eventReportData: %w", err)
		}
		retagged_enc_eventreportdata, tagErr_enc_eventreportdata := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_eventreportdata)
		if tagErr_enc_eventreportdata != nil {
			return nil, fmt.Errorf("encoding eventReportData: %w", tagErr_enc_eventreportdata)
		}
		enc_eventreportdata = retagged_enc_eventreportdata
		children = append(children, enc_eventreportdata...)
	}
	if v.CallReportdata != nil {
		enc_callreportdata, err := v.CallReportdata.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding callReportdata: %w", err)
		}
		retagged_enc_callreportdata, tagErr_enc_callreportdata := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_callreportdata)
		if tagErr_enc_callreportdata != nil {
			return nil, fmt.Errorf("encoding callReportdata: %w", tagErr_enc_callreportdata)
		}
		enc_callreportdata = retagged_enc_callreportdata
		children = append(children, enc_callreportdata...)
	}
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding extensionContainer: %w", err)
		}
		retagged_enc_extensioncontainer, tagErr_enc_extensioncontainer := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, enc_extensioncontainer)
		if tagErr_enc_extensioncontainer != nil {
			return nil, fmt.Errorf("encoding extensionContainer: %w", tagErr_enc_extensioncontainer)
		}
		enc_extensioncontainer = retagged_enc_extensioncontainer
		children = append(children, enc_extensioncontainer...)
	}
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
		children = append(children, ext...)
	}
	encoded := ber.EncodeSequence(children)
	if err := ber.ValidateDERElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding StatusReportArg as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes StatusReportArg from BER/DER format.
func (v *StatusReportArg) UnmarshalBER(data []byte) error {
	*v = StatusReportArg{}
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding StatusReportArg SEQUENCE: %w", err)
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
	decodedTag_imsi, n_imsi, rawVal_imsi, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding imsi: %w", err)
	}
	if decodedTag_imsi.Class != tag.ClassContextSpecific || decodedTag_imsi.Number != 0 {
		return fmt.Errorf("decoding imsi: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_imsi)
	}
	v.Imsi = IMSI(rawVal_imsi)
	offset += n_imsi
	// Decode eventReportData
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
				decodedTag_eventreportdata, n_eventreportdata, rawVal_eventreportdata, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding eventReportData: %w", err)
				}
				if decodedTag_eventreportdata.Class != tag.ClassContextSpecific || decodedTag_eventreportdata.Number != 1 || decodedTag_eventreportdata.Constructed != true {
					return fmt.Errorf("decoding eventReportData: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_eventreportdata)
				}
				reconstructed_eventreportdata := ber.EncodeSequence(rawVal_eventreportdata)
				var dec_eventreportdata EventReportData
				if unmErr := dec_eventreportdata.UnmarshalBER(reconstructed_eventreportdata); unmErr != nil {
					return fmt.Errorf("decoding eventReportData: %w", unmErr)
				}
				v.EventReportData = &dec_eventreportdata
				offset += n_eventreportdata
			}
		}
	}
	// Decode callReportdata
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2 {
				decodedTag_callreportdata, n_callreportdata, rawVal_callreportdata, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding callReportdata: %w", err)
				}
				if decodedTag_callreportdata.Class != tag.ClassContextSpecific || decodedTag_callreportdata.Number != 2 || decodedTag_callreportdata.Constructed != true {
					return fmt.Errorf("decoding callReportdata: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_callreportdata)
				}
				reconstructed_callreportdata := ber.EncodeSequence(rawVal_callreportdata)
				var dec_callreportdata CallReportData
				if unmErr := dec_callreportdata.UnmarshalBER(reconstructed_callreportdata); unmErr != nil {
					return fmt.Errorf("decoding callReportdata: %w", unmErr)
				}
				v.CallReportdata = &dec_callreportdata
				offset += n_callreportdata
			}
		}
	}
	// Decode extensionContainer
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3 {
				decodedTag_extensioncontainer, n_extensioncontainer, rawVal_extensioncontainer, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding extensionContainer: %w", err)
				}
				if decodedTag_extensioncontainer.Class != tag.ClassContextSpecific || decodedTag_extensioncontainer.Number != 3 || decodedTag_extensioncontainer.Constructed != true {
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
			return &ber.DecodeError{Offset: offset, TypeName: "StatusReportArg", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes EventReportData to BER format.
func (v *EventReportData) MarshalBER() ([]byte, error) {
	var children []byte
	if v.CcbsSubscriberStatus != nil {
		enc_ccbssubscriberstatus := ber.EncodeEnumerated(int64(*v.CcbsSubscriberStatus))
		retagged_enc_ccbssubscriberstatus, tagErr_enc_ccbssubscriberstatus := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_ccbssubscriberstatus)
		if tagErr_enc_ccbssubscriberstatus != nil {
			return nil, fmt.Errorf("encoding ccbs-SubscriberStatus: %w", tagErr_enc_ccbssubscriberstatus)
		}
		enc_ccbssubscriberstatus = retagged_enc_ccbssubscriberstatus
		children = append(children, enc_ccbssubscriberstatus...)
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

// MarshalDER encodes EventReportData to DER format.
func (v *EventReportData) MarshalDER() ([]byte, error) {
	var children []byte
	if v.CcbsSubscriberStatus != nil {
		enc_ccbssubscriberstatus := ber.EncodeEnumerated(int64(*v.CcbsSubscriberStatus))
		retagged_enc_ccbssubscriberstatus, tagErr_enc_ccbssubscriberstatus := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_ccbssubscriberstatus)
		if tagErr_enc_ccbssubscriberstatus != nil {
			return nil, fmt.Errorf("encoding ccbs-SubscriberStatus: %w", tagErr_enc_ccbssubscriberstatus)
		}
		enc_ccbssubscriberstatus = retagged_enc_ccbssubscriberstatus
		children = append(children, enc_ccbssubscriberstatus...)
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
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
		children = append(children, ext...)
	}
	encoded := ber.EncodeSequence(children)
	if err := ber.ValidateDERElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding EventReportData as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes EventReportData from BER/DER format.
func (v *EventReportData) UnmarshalBER(data []byte) error {
	*v = EventReportData{}
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding EventReportData SEQUENCE: %w", err)
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
				decodedTag_ccbssubscriberstatus, n_ccbssubscriberstatus, rawVal_ccbssubscriberstatus, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding ccbs-SubscriberStatus: %w", err)
				}
				if decodedTag_ccbssubscriberstatus.Class != tag.ClassContextSpecific || decodedTag_ccbssubscriberstatus.Number != 0 || decodedTag_ccbssubscriberstatus.Constructed != false {
					return fmt.Errorf("decoding ccbs-SubscriberStatus: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_ccbssubscriberstatus)
				}
				decVal_ccbssubscriberstatus, intErr := ber.DecodeEnumeratedValue(rawVal_ccbssubscriberstatus)
				if intErr != nil {
					return fmt.Errorf("decoding ccbs-SubscriberStatus: %w", intErr)
				}
				tmp_ccbssubscriberstatus := CCBSSubscriberStatus(decVal_ccbssubscriberstatus)
				v.CcbsSubscriberStatus = &tmp_ccbssubscriberstatus
				offset += n_ccbssubscriberstatus
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
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "EventReportData", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes CallReportData to BER format.
func (v *CallReportData) MarshalBER() ([]byte, error) {
	var children []byte
	if v.MonitoringMode != nil {
		enc_monitoringmode := ber.EncodeEnumerated(int64(*v.MonitoringMode))
		retagged_enc_monitoringmode, tagErr_enc_monitoringmode := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_monitoringmode)
		if tagErr_enc_monitoringmode != nil {
			return nil, fmt.Errorf("encoding monitoringMode: %w", tagErr_enc_monitoringmode)
		}
		enc_monitoringmode = retagged_enc_monitoringmode
		children = append(children, enc_monitoringmode...)
	}
	if v.CallOutcome != nil {
		enc_calloutcome := ber.EncodeEnumerated(int64(*v.CallOutcome))
		retagged_enc_calloutcome, tagErr_enc_calloutcome := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_calloutcome)
		if tagErr_enc_calloutcome != nil {
			return nil, fmt.Errorf("encoding callOutcome: %w", tagErr_enc_calloutcome)
		}
		enc_calloutcome = retagged_enc_calloutcome
		children = append(children, enc_calloutcome...)
	}
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

// MarshalDER encodes CallReportData to DER format.
func (v *CallReportData) MarshalDER() ([]byte, error) {
	var children []byte
	if v.MonitoringMode != nil {
		enc_monitoringmode := ber.EncodeEnumerated(int64(*v.MonitoringMode))
		retagged_enc_monitoringmode, tagErr_enc_monitoringmode := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_monitoringmode)
		if tagErr_enc_monitoringmode != nil {
			return nil, fmt.Errorf("encoding monitoringMode: %w", tagErr_enc_monitoringmode)
		}
		enc_monitoringmode = retagged_enc_monitoringmode
		children = append(children, enc_monitoringmode...)
	}
	if v.CallOutcome != nil {
		enc_calloutcome := ber.EncodeEnumerated(int64(*v.CallOutcome))
		retagged_enc_calloutcome, tagErr_enc_calloutcome := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_calloutcome)
		if tagErr_enc_calloutcome != nil {
			return nil, fmt.Errorf("encoding callOutcome: %w", tagErr_enc_calloutcome)
		}
		enc_calloutcome = retagged_enc_calloutcome
		children = append(children, enc_calloutcome...)
	}
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
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
		children = append(children, ext...)
	}
	encoded := ber.EncodeSequence(children)
	if err := ber.ValidateDERElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding CallReportData as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes CallReportData from BER/DER format.
func (v *CallReportData) UnmarshalBER(data []byte) error {
	*v = CallReportData{}
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding CallReportData SEQUENCE: %w", err)
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
				decodedTag_monitoringmode, n_monitoringmode, rawVal_monitoringmode, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding monitoringMode: %w", err)
				}
				if decodedTag_monitoringmode.Class != tag.ClassContextSpecific || decodedTag_monitoringmode.Number != 0 || decodedTag_monitoringmode.Constructed != false {
					return fmt.Errorf("decoding monitoringMode: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_monitoringmode)
				}
				decVal_monitoringmode, intErr := ber.DecodeEnumeratedValue(rawVal_monitoringmode)
				if intErr != nil {
					return fmt.Errorf("decoding monitoringMode: %w", intErr)
				}
				tmp_monitoringmode := MonitoringMode(decVal_monitoringmode)
				v.MonitoringMode = &tmp_monitoringmode
				offset += n_monitoringmode
			}
		}
	}
	// Decode callOutcome
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
				decodedTag_calloutcome, n_calloutcome, rawVal_calloutcome, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding callOutcome: %w", err)
				}
				if decodedTag_calloutcome.Class != tag.ClassContextSpecific || decodedTag_calloutcome.Number != 1 || decodedTag_calloutcome.Constructed != false {
					return fmt.Errorf("decoding callOutcome: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_calloutcome)
				}
				decVal_calloutcome, intErr := ber.DecodeEnumeratedValue(rawVal_calloutcome)
				if intErr != nil {
					return fmt.Errorf("decoding callOutcome: %w", intErr)
				}
				tmp_calloutcome := CallOutcome(decVal_calloutcome)
				v.CallOutcome = &tmp_calloutcome
				offset += n_calloutcome
			}
		}
	}
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
			return &ber.DecodeError{Offset: offset, TypeName: "CallReportData", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes StatusReportRes to BER format.
func (v *StatusReportRes) MarshalBER() ([]byte, error) {
	var children []byte
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalBER()
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

// MarshalDER encodes StatusReportRes to DER format.
func (v *StatusReportRes) MarshalDER() ([]byte, error) {
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
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
		children = append(children, ext...)
	}
	encoded := ber.EncodeSequence(children)
	if err := ber.ValidateDERElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding StatusReportRes as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes StatusReportRes from BER/DER format.
func (v *StatusReportRes) UnmarshalBER(data []byte) error {
	*v = StatusReportRes{}
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding StatusReportRes SEQUENCE: %w", err)
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
				decodedTag_extensioncontainer, n_extensioncontainer, rawVal_extensioncontainer, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding extensionContainer: %w", err)
				}
				if decodedTag_extensioncontainer.Class != tag.ClassContextSpecific || decodedTag_extensioncontainer.Number != 0 || decodedTag_extensioncontainer.Constructed != true {
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
			return &ber.DecodeError{Offset: offset, TypeName: "StatusReportRes", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes RemoteUserFreeArg to BER format.
func (v *RemoteUserFreeArg) MarshalBER() ([]byte, error) {
	var children []byte
	enc_imsi := ber.EncodeOctetString([]byte(v.Imsi))
	retagged_enc_imsi, tagErr_enc_imsi := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_imsi)
	if tagErr_enc_imsi != nil {
		return nil, fmt.Errorf("encoding imsi: %w", tagErr_enc_imsi)
	}
	enc_imsi = retagged_enc_imsi
	children = append(children, enc_imsi...)
	enc_callinfo, err := v.CallInfo.MarshalBER()
	if err != nil {
		return nil, fmt.Errorf("encoding callInfo: %w", err)
	}
	retagged_enc_callinfo, tagErr_enc_callinfo := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_callinfo)
	if tagErr_enc_callinfo != nil {
		return nil, fmt.Errorf("encoding callInfo: %w", tagErr_enc_callinfo)
	}
	enc_callinfo = retagged_enc_callinfo
	children = append(children, enc_callinfo...)
	enc_ccbsfeature, err := v.CcbsFeature.MarshalBER()
	if err != nil {
		return nil, fmt.Errorf("encoding ccbs-Feature: %w", err)
	}
	retagged_enc_ccbsfeature, tagErr_enc_ccbsfeature := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_ccbsfeature)
	if tagErr_enc_ccbsfeature != nil {
		return nil, fmt.Errorf("encoding ccbs-Feature: %w", tagErr_enc_ccbsfeature)
	}
	enc_ccbsfeature = retagged_enc_ccbsfeature
	children = append(children, enc_ccbsfeature...)
	enc_translatedbnumber := ber.EncodeOctetString([]byte(v.TranslatedBNumber))
	retagged_enc_translatedbnumber, tagErr_enc_translatedbnumber := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, enc_translatedbnumber)
	if tagErr_enc_translatedbnumber != nil {
		return nil, fmt.Errorf("encoding translatedB-Number: %w", tagErr_enc_translatedbnumber)
	}
	enc_translatedbnumber = retagged_enc_translatedbnumber
	children = append(children, enc_translatedbnumber...)
	if v.ReplaceBNumber != nil {
		enc_replacebnumber := ber.EncodeNull()
		retagged_enc_replacebnumber, tagErr_enc_replacebnumber := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, enc_replacebnumber)
		if tagErr_enc_replacebnumber != nil {
			return nil, fmt.Errorf("encoding replaceB-Number: %w", tagErr_enc_replacebnumber)
		}
		enc_replacebnumber = retagged_enc_replacebnumber
		children = append(children, enc_replacebnumber...)
	}
	if v.AlertingPattern != nil {
		enc_alertingpattern := ber.EncodeOctetString([]byte(*v.AlertingPattern))
		retagged_enc_alertingpattern, tagErr_enc_alertingpattern := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 5, enc_alertingpattern)
		if tagErr_enc_alertingpattern != nil {
			return nil, fmt.Errorf("encoding alertingPattern: %w", tagErr_enc_alertingpattern)
		}
		enc_alertingpattern = retagged_enc_alertingpattern
		children = append(children, enc_alertingpattern...)
	}
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding extensionContainer: %w", err)
		}
		retagged_enc_extensioncontainer, tagErr_enc_extensioncontainer := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 6, enc_extensioncontainer)
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

// MarshalDER encodes RemoteUserFreeArg to DER format.
func (v *RemoteUserFreeArg) MarshalDER() ([]byte, error) {
	var children []byte
	enc_imsi := ber.EncodeOctetString([]byte(v.Imsi))
	retagged_enc_imsi, tagErr_enc_imsi := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_imsi)
	if tagErr_enc_imsi != nil {
		return nil, fmt.Errorf("encoding imsi: %w", tagErr_enc_imsi)
	}
	enc_imsi = retagged_enc_imsi
	children = append(children, enc_imsi...)
	enc_callinfo, err := v.CallInfo.MarshalDER()
	if err != nil {
		return nil, fmt.Errorf("encoding callInfo: %w", err)
	}
	retagged_enc_callinfo, tagErr_enc_callinfo := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_callinfo)
	if tagErr_enc_callinfo != nil {
		return nil, fmt.Errorf("encoding callInfo: %w", tagErr_enc_callinfo)
	}
	enc_callinfo = retagged_enc_callinfo
	children = append(children, enc_callinfo...)
	enc_ccbsfeature, err := v.CcbsFeature.MarshalDER()
	if err != nil {
		return nil, fmt.Errorf("encoding ccbs-Feature: %w", err)
	}
	retagged_enc_ccbsfeature, tagErr_enc_ccbsfeature := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_ccbsfeature)
	if tagErr_enc_ccbsfeature != nil {
		return nil, fmt.Errorf("encoding ccbs-Feature: %w", tagErr_enc_ccbsfeature)
	}
	enc_ccbsfeature = retagged_enc_ccbsfeature
	children = append(children, enc_ccbsfeature...)
	enc_translatedbnumber := ber.EncodeOctetString([]byte(v.TranslatedBNumber))
	retagged_enc_translatedbnumber, tagErr_enc_translatedbnumber := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, enc_translatedbnumber)
	if tagErr_enc_translatedbnumber != nil {
		return nil, fmt.Errorf("encoding translatedB-Number: %w", tagErr_enc_translatedbnumber)
	}
	enc_translatedbnumber = retagged_enc_translatedbnumber
	children = append(children, enc_translatedbnumber...)
	if v.ReplaceBNumber != nil {
		enc_replacebnumber := ber.EncodeNull()
		retagged_enc_replacebnumber, tagErr_enc_replacebnumber := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, enc_replacebnumber)
		if tagErr_enc_replacebnumber != nil {
			return nil, fmt.Errorf("encoding replaceB-Number: %w", tagErr_enc_replacebnumber)
		}
		enc_replacebnumber = retagged_enc_replacebnumber
		children = append(children, enc_replacebnumber...)
	}
	if v.AlertingPattern != nil {
		enc_alertingpattern := ber.EncodeOctetString([]byte(*v.AlertingPattern))
		retagged_enc_alertingpattern, tagErr_enc_alertingpattern := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 5, enc_alertingpattern)
		if tagErr_enc_alertingpattern != nil {
			return nil, fmt.Errorf("encoding alertingPattern: %w", tagErr_enc_alertingpattern)
		}
		enc_alertingpattern = retagged_enc_alertingpattern
		children = append(children, enc_alertingpattern...)
	}
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding extensionContainer: %w", err)
		}
		retagged_enc_extensioncontainer, tagErr_enc_extensioncontainer := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 6, enc_extensioncontainer)
		if tagErr_enc_extensioncontainer != nil {
			return nil, fmt.Errorf("encoding extensionContainer: %w", tagErr_enc_extensioncontainer)
		}
		enc_extensioncontainer = retagged_enc_extensioncontainer
		children = append(children, enc_extensioncontainer...)
	}
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
		children = append(children, ext...)
	}
	encoded := ber.EncodeSequence(children)
	if err := ber.ValidateDERElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding RemoteUserFreeArg as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes RemoteUserFreeArg from BER/DER format.
func (v *RemoteUserFreeArg) UnmarshalBER(data []byte) error {
	*v = RemoteUserFreeArg{}
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding RemoteUserFreeArg SEQUENCE: %w", err)
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
	decodedTag_imsi, n_imsi, rawVal_imsi, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding imsi: %w", err)
	}
	if decodedTag_imsi.Class != tag.ClassContextSpecific || decodedTag_imsi.Number != 0 {
		return fmt.Errorf("decoding imsi: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_imsi)
	}
	v.Imsi = IMSI(rawVal_imsi)
	offset += n_imsi
	// Decode callInfo
	if offset >= len(content) {
		return fmt.Errorf("missing required field callInfo")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 1 {
			return fmt.Errorf("expected tag [%s %d] for callInfo, got %s", "CONTEXT", 1, reqTag_)
		}
	}
	decodedTag_callinfo, n_callinfo, rawVal_callinfo, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding callInfo: %w", err)
	}
	if decodedTag_callinfo.Class != tag.ClassContextSpecific || decodedTag_callinfo.Number != 1 || decodedTag_callinfo.Constructed != true {
		return fmt.Errorf("decoding callInfo: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_callinfo)
	}
	reconstructed_callinfo := ber.EncodeSequence(rawVal_callinfo)
	if unmErr := v.CallInfo.UnmarshalBER(reconstructed_callinfo); unmErr != nil {
		return fmt.Errorf("decoding callInfo: %w", unmErr)
	}
	offset += n_callinfo
	// Decode ccbs-Feature
	if offset >= len(content) {
		return fmt.Errorf("missing required field ccbs-Feature")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 2 {
			return fmt.Errorf("expected tag [%s %d] for ccbs-Feature, got %s", "CONTEXT", 2, reqTag_)
		}
	}
	decodedTag_ccbsfeature, n_ccbsfeature, rawVal_ccbsfeature, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding ccbs-Feature: %w", err)
	}
	if decodedTag_ccbsfeature.Class != tag.ClassContextSpecific || decodedTag_ccbsfeature.Number != 2 || decodedTag_ccbsfeature.Constructed != true {
		return fmt.Errorf("decoding ccbs-Feature: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_ccbsfeature)
	}
	reconstructed_ccbsfeature := ber.EncodeSequence(rawVal_ccbsfeature)
	if unmErr := v.CcbsFeature.UnmarshalBER(reconstructed_ccbsfeature); unmErr != nil {
		return fmt.Errorf("decoding ccbs-Feature: %w", unmErr)
	}
	offset += n_ccbsfeature
	// Decode translatedB-Number
	if offset >= len(content) {
		return fmt.Errorf("missing required field translatedB-Number")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 3 {
			return fmt.Errorf("expected tag [%s %d] for translatedB-Number, got %s", "CONTEXT", 3, reqTag_)
		}
	}
	decodedTag_translatedbnumber, n_translatedbnumber, rawVal_translatedbnumber, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding translatedB-Number: %w", err)
	}
	if decodedTag_translatedbnumber.Class != tag.ClassContextSpecific || decodedTag_translatedbnumber.Number != 3 {
		return fmt.Errorf("decoding translatedB-Number: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_translatedbnumber)
	}
	v.TranslatedBNumber = ISDNAddressString(rawVal_translatedbnumber)
	offset += n_translatedbnumber
	// Decode replaceB-Number
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4 {
				decodedTag_replacebnumber, n_replacebnumber, rawVal_replacebnumber, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding replaceB-Number: %w", err)
				}
				if decodedTag_replacebnumber.Class != tag.ClassContextSpecific || decodedTag_replacebnumber.Number != 4 || decodedTag_replacebnumber.Constructed != false {
					return fmt.Errorf("decoding replaceB-Number: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_replacebnumber)
				}
				if len(rawVal_replacebnumber) != 0 {
					return fmt.Errorf("decoding replaceB-Number: %w: NULL content length %d", ber.ErrInvalidValue, len(rawVal_replacebnumber))
				}
				v.ReplaceBNumber = &struct{}{}
				offset += n_replacebnumber
			}
		}
	}
	// Decode alertingPattern
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 5 {
				decodedTag_alertingpattern, n_alertingpattern, rawVal_alertingpattern, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding alertingPattern: %w", err)
				}
				if decodedTag_alertingpattern.Class != tag.ClassContextSpecific || decodedTag_alertingpattern.Number != 5 {
					return fmt.Errorf("decoding alertingPattern: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_alertingpattern)
				}
				tmp_alertingpattern := AlertingPattern(rawVal_alertingpattern)
				v.AlertingPattern = &tmp_alertingpattern
				offset += n_alertingpattern
			}
		}
	}
	// Decode extensionContainer
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 6 {
				decodedTag_extensioncontainer, n_extensioncontainer, rawVal_extensioncontainer, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding extensionContainer: %w", err)
				}
				if decodedTag_extensioncontainer.Class != tag.ClassContextSpecific || decodedTag_extensioncontainer.Number != 6 || decodedTag_extensioncontainer.Constructed != true {
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
			return &ber.DecodeError{Offset: offset, TypeName: "RemoteUserFreeArg", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes RemoteUserFreeRes to BER format.
func (v *RemoteUserFreeRes) MarshalBER() ([]byte, error) {
	var children []byte
	enc_rufoutcome := ber.EncodeEnumerated(int64(v.RufOutcome))
	retagged_enc_rufoutcome, tagErr_enc_rufoutcome := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_rufoutcome)
	if tagErr_enc_rufoutcome != nil {
		return nil, fmt.Errorf("encoding ruf-Outcome: %w", tagErr_enc_rufoutcome)
	}
	enc_rufoutcome = retagged_enc_rufoutcome
	children = append(children, enc_rufoutcome...)
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

// MarshalDER encodes RemoteUserFreeRes to DER format.
func (v *RemoteUserFreeRes) MarshalDER() ([]byte, error) {
	var children []byte
	enc_rufoutcome := ber.EncodeEnumerated(int64(v.RufOutcome))
	retagged_enc_rufoutcome, tagErr_enc_rufoutcome := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_rufoutcome)
	if tagErr_enc_rufoutcome != nil {
		return nil, fmt.Errorf("encoding ruf-Outcome: %w", tagErr_enc_rufoutcome)
	}
	enc_rufoutcome = retagged_enc_rufoutcome
	children = append(children, enc_rufoutcome...)
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
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
		children = append(children, ext...)
	}
	encoded := ber.EncodeSequence(children)
	if err := ber.ValidateDERElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding RemoteUserFreeRes as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes RemoteUserFreeRes from BER/DER format.
func (v *RemoteUserFreeRes) UnmarshalBER(data []byte) error {
	*v = RemoteUserFreeRes{}
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding RemoteUserFreeRes SEQUENCE: %w", err)
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
	decodedTag_rufoutcome, n_rufoutcome, rawVal_rufoutcome, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding ruf-Outcome: %w", err)
	}
	if decodedTag_rufoutcome.Class != tag.ClassContextSpecific || decodedTag_rufoutcome.Number != 0 || decodedTag_rufoutcome.Constructed != false {
		return fmt.Errorf("decoding ruf-Outcome: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_rufoutcome)
	}
	decVal_rufoutcome, intErr := ber.DecodeEnumeratedValue(rawVal_rufoutcome)
	if intErr != nil {
		return fmt.Errorf("decoding ruf-Outcome: %w", intErr)
	}
	v.RufOutcome = RUFOutcome(decVal_rufoutcome)
	offset += n_rufoutcome
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
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "RemoteUserFreeRes", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes ISTAlertArg to BER format.
func (v *ISTAlertArg) MarshalBER() ([]byte, error) {
	var children []byte
	enc_imsi := ber.EncodeOctetString([]byte(v.Imsi))
	retagged_enc_imsi, tagErr_enc_imsi := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_imsi)
	if tagErr_enc_imsi != nil {
		return nil, fmt.Errorf("encoding imsi: %w", tagErr_enc_imsi)
	}
	enc_imsi = retagged_enc_imsi
	children = append(children, enc_imsi...)
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

// MarshalDER encodes ISTAlertArg to DER format.
func (v *ISTAlertArg) MarshalDER() ([]byte, error) {
	var children []byte
	enc_imsi := ber.EncodeOctetString([]byte(v.Imsi))
	retagged_enc_imsi, tagErr_enc_imsi := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_imsi)
	if tagErr_enc_imsi != nil {
		return nil, fmt.Errorf("encoding imsi: %w", tagErr_enc_imsi)
	}
	enc_imsi = retagged_enc_imsi
	children = append(children, enc_imsi...)
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
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
		children = append(children, ext...)
	}
	encoded := ber.EncodeSequence(children)
	if err := ber.ValidateDERElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding ISTAlertArg as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes ISTAlertArg from BER/DER format.
func (v *ISTAlertArg) UnmarshalBER(data []byte) error {
	*v = ISTAlertArg{}
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding ISTAlertArg SEQUENCE: %w", err)
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
	decodedTag_imsi, n_imsi, rawVal_imsi, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding imsi: %w", err)
	}
	if decodedTag_imsi.Class != tag.ClassContextSpecific || decodedTag_imsi.Number != 0 {
		return fmt.Errorf("decoding imsi: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_imsi)
	}
	v.Imsi = IMSI(rawVal_imsi)
	offset += n_imsi
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
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "ISTAlertArg", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes ISTAlertRes to BER format.
func (v *ISTAlertRes) MarshalBER() ([]byte, error) {
	var children []byte
	if v.IstAlertTimer != nil {
		enc_istalerttimer := ber.EncodeInteger(int64(*v.IstAlertTimer))
		retagged_enc_istalerttimer, tagErr_enc_istalerttimer := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_istalerttimer)
		if tagErr_enc_istalerttimer != nil {
			return nil, fmt.Errorf("encoding istAlertTimer: %w", tagErr_enc_istalerttimer)
		}
		enc_istalerttimer = retagged_enc_istalerttimer
		children = append(children, enc_istalerttimer...)
	}
	if v.IstInformationWithdraw != nil {
		enc_istinformationwithdraw := ber.EncodeNull()
		retagged_enc_istinformationwithdraw, tagErr_enc_istinformationwithdraw := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_istinformationwithdraw)
		if tagErr_enc_istinformationwithdraw != nil {
			return nil, fmt.Errorf("encoding istInformationWithdraw: %w", tagErr_enc_istinformationwithdraw)
		}
		enc_istinformationwithdraw = retagged_enc_istinformationwithdraw
		children = append(children, enc_istinformationwithdraw...)
	}
	if v.CallTerminationIndicator != nil {
		enc_callterminationindicator := ber.EncodeEnumerated(int64(*v.CallTerminationIndicator))
		retagged_enc_callterminationindicator, tagErr_enc_callterminationindicator := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_callterminationindicator)
		if tagErr_enc_callterminationindicator != nil {
			return nil, fmt.Errorf("encoding callTerminationIndicator: %w", tagErr_enc_callterminationindicator)
		}
		enc_callterminationindicator = retagged_enc_callterminationindicator
		children = append(children, enc_callterminationindicator...)
	}
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding extensionContainer: %w", err)
		}
		retagged_enc_extensioncontainer, tagErr_enc_extensioncontainer := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, enc_extensioncontainer)
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

// MarshalDER encodes ISTAlertRes to DER format.
func (v *ISTAlertRes) MarshalDER() ([]byte, error) {
	var children []byte
	if v.IstAlertTimer != nil {
		enc_istalerttimer := ber.EncodeInteger(int64(*v.IstAlertTimer))
		retagged_enc_istalerttimer, tagErr_enc_istalerttimer := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_istalerttimer)
		if tagErr_enc_istalerttimer != nil {
			return nil, fmt.Errorf("encoding istAlertTimer: %w", tagErr_enc_istalerttimer)
		}
		enc_istalerttimer = retagged_enc_istalerttimer
		children = append(children, enc_istalerttimer...)
	}
	if v.IstInformationWithdraw != nil {
		enc_istinformationwithdraw := ber.EncodeNull()
		retagged_enc_istinformationwithdraw, tagErr_enc_istinformationwithdraw := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_istinformationwithdraw)
		if tagErr_enc_istinformationwithdraw != nil {
			return nil, fmt.Errorf("encoding istInformationWithdraw: %w", tagErr_enc_istinformationwithdraw)
		}
		enc_istinformationwithdraw = retagged_enc_istinformationwithdraw
		children = append(children, enc_istinformationwithdraw...)
	}
	if v.CallTerminationIndicator != nil {
		enc_callterminationindicator := ber.EncodeEnumerated(int64(*v.CallTerminationIndicator))
		retagged_enc_callterminationindicator, tagErr_enc_callterminationindicator := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_callterminationindicator)
		if tagErr_enc_callterminationindicator != nil {
			return nil, fmt.Errorf("encoding callTerminationIndicator: %w", tagErr_enc_callterminationindicator)
		}
		enc_callterminationindicator = retagged_enc_callterminationindicator
		children = append(children, enc_callterminationindicator...)
	}
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding extensionContainer: %w", err)
		}
		retagged_enc_extensioncontainer, tagErr_enc_extensioncontainer := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, enc_extensioncontainer)
		if tagErr_enc_extensioncontainer != nil {
			return nil, fmt.Errorf("encoding extensionContainer: %w", tagErr_enc_extensioncontainer)
		}
		enc_extensioncontainer = retagged_enc_extensioncontainer
		children = append(children, enc_extensioncontainer...)
	}
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
		children = append(children, ext...)
	}
	encoded := ber.EncodeSequence(children)
	if err := ber.ValidateDERElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding ISTAlertRes as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes ISTAlertRes from BER/DER format.
func (v *ISTAlertRes) UnmarshalBER(data []byte) error {
	*v = ISTAlertRes{}
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding ISTAlertRes SEQUENCE: %w", err)
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
				decodedTag_istalerttimer, n_istalerttimer, rawVal_istalerttimer, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding istAlertTimer: %w", err)
				}
				if decodedTag_istalerttimer.Class != tag.ClassContextSpecific || decodedTag_istalerttimer.Number != 0 || decodedTag_istalerttimer.Constructed != false {
					return fmt.Errorf("decoding istAlertTimer: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_istalerttimer)
				}
				decVal_istalerttimer, intErr := ber.DecodeIntegerValue(rawVal_istalerttimer)
				if intErr != nil {
					return fmt.Errorf("decoding istAlertTimer: %w", intErr)
				}
				tmp_istalerttimer := ISTAlertTimerValue(decVal_istalerttimer)
				v.IstAlertTimer = &tmp_istalerttimer
				offset += n_istalerttimer
			}
		}
	}
	// Decode istInformationWithdraw
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
				decodedTag_istinformationwithdraw, n_istinformationwithdraw, rawVal_istinformationwithdraw, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding istInformationWithdraw: %w", err)
				}
				if decodedTag_istinformationwithdraw.Class != tag.ClassContextSpecific || decodedTag_istinformationwithdraw.Number != 1 || decodedTag_istinformationwithdraw.Constructed != false {
					return fmt.Errorf("decoding istInformationWithdraw: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_istinformationwithdraw)
				}
				if len(rawVal_istinformationwithdraw) != 0 {
					return fmt.Errorf("decoding istInformationWithdraw: %w: NULL content length %d", ber.ErrInvalidValue, len(rawVal_istinformationwithdraw))
				}
				v.IstInformationWithdraw = &struct{}{}
				offset += n_istinformationwithdraw
			}
		}
	}
	// Decode callTerminationIndicator
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2 {
				decodedTag_callterminationindicator, n_callterminationindicator, rawVal_callterminationindicator, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding callTerminationIndicator: %w", err)
				}
				if decodedTag_callterminationindicator.Class != tag.ClassContextSpecific || decodedTag_callterminationindicator.Number != 2 || decodedTag_callterminationindicator.Constructed != false {
					return fmt.Errorf("decoding callTerminationIndicator: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_callterminationindicator)
				}
				decVal_callterminationindicator, intErr := ber.DecodeEnumeratedValue(rawVal_callterminationindicator)
				if intErr != nil {
					return fmt.Errorf("decoding callTerminationIndicator: %w", intErr)
				}
				tmp_callterminationindicator := CallTerminationIndicator(decVal_callterminationindicator)
				v.CallTerminationIndicator = &tmp_callterminationindicator
				offset += n_callterminationindicator
			}
		}
	}
	// Decode extensionContainer
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3 {
				decodedTag_extensioncontainer, n_extensioncontainer, rawVal_extensioncontainer, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding extensionContainer: %w", err)
				}
				if decodedTag_extensioncontainer.Class != tag.ClassContextSpecific || decodedTag_extensioncontainer.Number != 3 || decodedTag_extensioncontainer.Constructed != true {
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
			return &ber.DecodeError{Offset: offset, TypeName: "ISTAlertRes", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes ISTCommandArg to BER format.
func (v *ISTCommandArg) MarshalBER() ([]byte, error) {
	var children []byte
	enc_imsi := ber.EncodeOctetString([]byte(v.Imsi))
	retagged_enc_imsi, tagErr_enc_imsi := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_imsi)
	if tagErr_enc_imsi != nil {
		return nil, fmt.Errorf("encoding imsi: %w", tagErr_enc_imsi)
	}
	enc_imsi = retagged_enc_imsi
	children = append(children, enc_imsi...)
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

// MarshalDER encodes ISTCommandArg to DER format.
func (v *ISTCommandArg) MarshalDER() ([]byte, error) {
	var children []byte
	enc_imsi := ber.EncodeOctetString([]byte(v.Imsi))
	retagged_enc_imsi, tagErr_enc_imsi := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_imsi)
	if tagErr_enc_imsi != nil {
		return nil, fmt.Errorf("encoding imsi: %w", tagErr_enc_imsi)
	}
	enc_imsi = retagged_enc_imsi
	children = append(children, enc_imsi...)
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
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
		children = append(children, ext...)
	}
	encoded := ber.EncodeSequence(children)
	if err := ber.ValidateDERElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding ISTCommandArg as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes ISTCommandArg from BER/DER format.
func (v *ISTCommandArg) UnmarshalBER(data []byte) error {
	*v = ISTCommandArg{}
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding ISTCommandArg SEQUENCE: %w", err)
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
	decodedTag_imsi, n_imsi, rawVal_imsi, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding imsi: %w", err)
	}
	if decodedTag_imsi.Class != tag.ClassContextSpecific || decodedTag_imsi.Number != 0 {
		return fmt.Errorf("decoding imsi: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_imsi)
	}
	v.Imsi = IMSI(rawVal_imsi)
	offset += n_imsi
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
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "ISTCommandArg", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes ISTCommandRes to BER format.
func (v *ISTCommandRes) MarshalBER() ([]byte, error) {
	var children []byte
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding extensionContainer: %w", err)
		}
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

// MarshalDER encodes ISTCommandRes to DER format.
func (v *ISTCommandRes) MarshalDER() ([]byte, error) {
	var children []byte
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding extensionContainer: %w", err)
		}
		children = append(children, enc_extensioncontainer...)
	}
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
		children = append(children, ext...)
	}
	encoded := ber.EncodeSequence(children)
	if err := ber.ValidateDERElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding ISTCommandRes as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes ISTCommandRes from BER/DER format.
func (v *ISTCommandRes) UnmarshalBER(data []byte) error {
	*v = ISTCommandRes{}
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding ISTCommandRes SEQUENCE: %w", err)
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
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "ISTCommandRes", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes ReleaseResourcesArg to BER format.
func (v *ReleaseResourcesArg) MarshalBER() ([]byte, error) {
	var children []byte
	enc_msrn := ber.EncodeOctetString([]byte(v.Msrn))
	children = append(children, enc_msrn...)
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding extensionContainer: %w", err)
		}
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

// MarshalDER encodes ReleaseResourcesArg to DER format.
func (v *ReleaseResourcesArg) MarshalDER() ([]byte, error) {
	var children []byte
	enc_msrn := ber.EncodeOctetString([]byte(v.Msrn))
	children = append(children, enc_msrn...)
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding extensionContainer: %w", err)
		}
		children = append(children, enc_extensioncontainer...)
	}
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
		children = append(children, ext...)
	}
	encoded := ber.EncodeSequence(children)
	if err := ber.ValidateDERElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding ReleaseResourcesArg as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes ReleaseResourcesArg from BER/DER format.
func (v *ReleaseResourcesArg) UnmarshalBER(data []byte) error {
	*v = ReleaseResourcesArg{}
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding ReleaseResourcesArg SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "ReleaseResourcesArg", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode msrn
	if offset >= len(content) {
		return fmt.Errorf("missing required field msrn")
	}
	val_msrn, n, err := ber.DecodeOctetString(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding msrn: %w", err)
	}
	v.Msrn = ISDNAddressString(val_msrn)
	offset += n
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
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "ReleaseResourcesArg", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes ReleaseResourcesRes to BER format.
func (v *ReleaseResourcesRes) MarshalBER() ([]byte, error) {
	var children []byte
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding extensionContainer: %w", err)
		}
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

// MarshalDER encodes ReleaseResourcesRes to DER format.
func (v *ReleaseResourcesRes) MarshalDER() ([]byte, error) {
	var children []byte
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding extensionContainer: %w", err)
		}
		children = append(children, enc_extensioncontainer...)
	}
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
		children = append(children, ext...)
	}
	encoded := ber.EncodeSequence(children)
	if err := ber.ValidateDERElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding ReleaseResourcesRes as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes ReleaseResourcesRes from BER/DER format.
func (v *ReleaseResourcesRes) UnmarshalBER(data []byte) error {
	*v = ReleaseResourcesRes{}
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding ReleaseResourcesRes SEQUENCE: %w", err)
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
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "ReleaseResourcesRes", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}
