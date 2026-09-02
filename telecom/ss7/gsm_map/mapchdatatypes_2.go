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

// CHCUGCheckInfo represents the ASN.1 type CUG-CheckInfo (SEQUENCE).
type CHCUGCheckInfo struct {
	CugInterlock       MSCUGInterlock                        `asn1:""`
	CugOutgoingAccess  *struct{}                             `asn1:",optional" json:"CugOutgoingAccess,omitempty"`
	ExtensionContainer *ExtensionDataTypesExtensionContainer `asn1:",optional" json:"ExtensionContainer,omitempty"`
	ExtCount_          int64                                 `asn1:"-" json:"-"`
	ExtPresent_        []bool                                `asn1:"-" json:"-"`
	ExtData_           [][]byte                              `asn1:"-" json:"-"`
}

// CHNumberOfForwarding represents the ASN.1 type NumberOfForwarding (INTEGER).
type CHNumberOfForwarding = int64

// CHSendRoutingInfoArg represents the ASN.1 type SendRoutingInfoArg (SEQUENCE).
type CHSendRoutingInfoArg struct {
	Msisdn                          CommonDataTypesISDNAddressString      `asn1:"tag:0,context,implicit"`
	CugCheckInfo                    *CHCUGCheckInfo                       `asn1:"tag:1,context,implicit,optional" json:"CugCheckInfo,omitempty"`
	NumberOfForwarding              *CHNumberOfForwarding                 `asn1:"tag:2,context,implicit,optional" json:"NumberOfForwarding,omitempty"`
	InterrogationType               CHInterrogationType                   `asn1:"tag:3,context,implicit"`
	OrInterrogation                 *struct{}                             `asn1:"tag:4,context,implicit,optional" json:"OrInterrogation,omitempty"`
	OrCapability                    *CHORPhase                            `asn1:"tag:5,context,implicit,optional" json:"OrCapability,omitempty"`
	GmscOrGsmSCFAddress             CommonDataTypesISDNAddressString      `asn1:"tag:6,context,implicit"`
	CallReferenceNumber             *CHCallReferenceNumber                `asn1:"tag:7,context,implicit,optional" json:"CallReferenceNumber,omitempty"`
	ForwardingReason                *CHForwardingReason                   `asn1:"tag:8,context,implicit,optional" json:"ForwardingReason,omitempty"`
	BasicServiceGroup               *CommonDataTypesExtBasicServiceCode   `asn1:"tag:9,context,explicit,optional" json:"BasicServiceGroup,omitempty"`
	NetworkSignalInfo               *CommonDataTypesExternalSignalInfo    `asn1:"tag:10,context,implicit,optional" json:"NetworkSignalInfo,omitempty"`
	CamelInfo                       *CHCamelInfo                          `asn1:"tag:11,context,implicit,optional" json:"CamelInfo,omitempty"`
	SuppressionOfAnnouncement       *CHSuppressionOfAnnouncement          `asn1:"tag:12,context,implicit,optional" json:"SuppressionOfAnnouncement,omitempty"`
	ExtensionContainer              *ExtensionDataTypesExtensionContainer `asn1:"tag:13,context,implicit,optional" json:"ExtensionContainer,omitempty"`
	AlertingPattern                 *CommonDataTypesAlertingPattern       `asn1:"tag:14,context,implicit,optional" json:"AlertingPattern,omitempty"`
	CcbsCall                        *struct{}                             `asn1:"tag:15,context,implicit,optional" json:"CcbsCall,omitempty"`
	SupportedCCBSPhase              *CHSupportedCCBSPhase                 `asn1:"tag:16,context,implicit,optional" json:"SupportedCCBSPhase,omitempty"`
	AdditionalSignalInfo            *CommonDataTypesExtExternalSignalInfo `asn1:"tag:17,context,implicit,optional" json:"AdditionalSignalInfo,omitempty"`
	IstSupportIndicator             *MSISTSupportIndicator                `asn1:"tag:18,context,implicit,optional" json:"IstSupportIndicator,omitempty"`
	PrePagingSupported              *struct{}                             `asn1:"tag:19,context,implicit,optional" json:"PrePagingSupported,omitempty"`
	CallDiversionTreatmentIndicator *CHCallDiversionTreatmentIndicator    `asn1:"tag:20,context,implicit,optional" json:"CallDiversionTreatmentIndicator,omitempty"`
	LongFTNSupported                *struct{}                             `asn1:"tag:21,context,implicit,optional" json:"LongFTNSupported,omitempty"`
	SuppressVTCSI                   *struct{}                             `asn1:"tag:22,context,implicit,optional" json:"SuppressVTCSI,omitempty"`
	SuppressIncomingCallBarring     *struct{}                             `asn1:"tag:23,context,implicit,optional" json:"SuppressIncomingCallBarring,omitempty"`
	GsmSCFInitiatedCall             *struct{}                             `asn1:"tag:24,context,implicit,optional" json:"GsmSCFInitiatedCall,omitempty"`
	BasicServiceGroup2              *CommonDataTypesExtBasicServiceCode   `asn1:"tag:25,context,explicit,optional" json:"BasicServiceGroup2,omitempty"`
	NetworkSignalInfo2              *CommonDataTypesExternalSignalInfo    `asn1:"tag:26,context,implicit,optional" json:"NetworkSignalInfo2,omitempty"`
	SuppressMTSS                    *CHSuppressMTSS                       `asn1:"tag:27,context,implicit,optional" json:"SuppressMTSS,omitempty"`
	ExtCount_                       int64                                 `asn1:"-" json:"-"`
	ExtPresent_                     []bool                                `asn1:"-" json:"-"`
	ExtData_                        [][]byte                              `asn1:"-" json:"-"`
}

// CHSuppressionOfAnnouncement represents the ASN.1 type SuppressionOfAnnouncement (NULL).
type CHSuppressionOfAnnouncement = struct{}

// CHSuppressMTSS represents the ASN.1 type SuppressMTSS (BIT_STRING).
type CHSuppressMTSS = runtime.BitString

// CHInterrogationType represents the ASN.1 ENUMERATED type InterrogationType.
type CHInterrogationType int64

const (
	CHInterrogationTypeBasicCall  CHInterrogationType = 0
	CHInterrogationTypeForwarding CHInterrogationType = 1
)

func (v CHInterrogationType) String() string {
	switch v {
	case CHInterrogationTypeBasicCall:
		return "basicCall"
	case CHInterrogationTypeForwarding:
		return "forwarding"
	default:
		return "unknown"
	}
}

// CHORPhase represents the ASN.1 type OR-Phase (INTEGER).
type CHORPhase = int64

// CHCallReferenceNumber represents the ASN.1 type CallReferenceNumber (OCTET_STRING).
type CHCallReferenceNumber = []byte

// CHForwardingReason represents the ASN.1 ENUMERATED type ForwardingReason.
type CHForwardingReason int64

const (
	CHForwardingReasonNotReachable CHForwardingReason = 0
	CHForwardingReasonBusy         CHForwardingReason = 1
	CHForwardingReasonNoReply      CHForwardingReason = 2
)

func (v CHForwardingReason) String() string {
	switch v {
	case CHForwardingReasonNotReachable:
		return "notReachable"
	case CHForwardingReasonBusy:
		return "busy"
	case CHForwardingReasonNoReply:
		return "noReply"
	default:
		return "unknown"
	}
}

// CHSupportedCCBSPhase represents the ASN.1 type SupportedCCBS-Phase (INTEGER).
type CHSupportedCCBSPhase = int64

// CHCallDiversionTreatmentIndicator represents the ASN.1 type CallDiversionTreatmentIndicator (OCTET_STRING).
type CHCallDiversionTreatmentIndicator = []byte

// CHSendRoutingInfoRes represents the ASN.1 type SendRoutingInfoRes (SEQUENCE).
type CHSendRoutingInfoRes struct {
	Imsi                            *CommonDataTypesIMSI                  `asn1:"tag:9,context,implicit,optional" json:"Imsi,omitempty"`
	ExtendedRoutingInfo             *CHExtendedRoutingInfo                `asn1:",optional" json:"ExtendedRoutingInfo,omitempty"`
	CugCheckInfo                    *CHCUGCheckInfo                       `asn1:"tag:3,context,implicit,optional" json:"CugCheckInfo,omitempty"`
	CugSubscriptionFlag             *struct{}                             `asn1:"tag:6,context,implicit,optional" json:"CugSubscriptionFlag,omitempty"`
	SubscriberInfo                  *MSSubscriberInfo                     `asn1:"tag:7,context,implicit,optional" json:"SubscriberInfo,omitempty"`
	SsList                          SSSSList                              `asn1:"tag:1,context,implicit,optional" json:"SsList,omitempty"`
	SsListIndef_                    bool                                  `asn1:"-" json:"-"`
	BasicService                    *CommonDataTypesExtBasicServiceCode   `asn1:"tag:5,context,explicit,optional" json:"BasicService,omitempty"`
	ForwardingInterrogationRequired *struct{}                             `asn1:"tag:4,context,implicit,optional" json:"ForwardingInterrogationRequired,omitempty"`
	VmscAddress                     *CommonDataTypesISDNAddressString     `asn1:"tag:2,context,implicit,optional" json:"VmscAddress,omitempty"`
	ExtensionContainer              *ExtensionDataTypesExtensionContainer `asn1:"tag:0,context,implicit,optional" json:"ExtensionContainer,omitempty"`
	NaeaPreferredCI                 *CommonDataTypesNAEAPreferredCI       `asn1:"tag:10,context,implicit,optional" json:"NaeaPreferredCI,omitempty"`
	CcbsIndicators                  *CHCCBSIndicators                     `asn1:"tag:11,context,implicit,optional" json:"CcbsIndicators,omitempty"`
	Msisdn                          *CommonDataTypesISDNAddressString     `asn1:"tag:12,context,implicit,optional" json:"Msisdn,omitempty"`
	NumberPortabilityStatus         *MSNumberPortabilityStatus            `asn1:"tag:13,context,implicit,optional" json:"NumberPortabilityStatus,omitempty"`
	IstAlertTimer                   *MSISTAlertTimerValue                 `asn1:"tag:14,context,implicit,optional" json:"IstAlertTimer,omitempty"`
	SupportedCamelPhasesInVMSC      *MSSupportedCamelPhases               `asn1:"tag:15,context,implicit,optional" json:"SupportedCamelPhasesInVMSC,omitempty"`
	OfferedCamel4CSIsInVMSC         *MSOfferedCamel4CSIs                  `asn1:"tag:16,context,implicit,optional" json:"OfferedCamel4CSIsInVMSC,omitempty"`
	RoutingInfo2                    *CHRoutingInfo                        `asn1:"tag:17,context,explicit,optional" json:"RoutingInfo2,omitempty"`
	SsList2                         SSSSList                              `asn1:"tag:18,context,implicit,optional" json:"SsList2,omitempty"`
	SsList2Indef_                   bool                                  `asn1:"-" json:"-"`
	BasicService2                   *CommonDataTypesExtBasicServiceCode   `asn1:"tag:19,context,explicit,optional" json:"BasicService2,omitempty"`
	AllowedServices                 *CHAllowedServices                    `asn1:"tag:20,context,implicit,optional" json:"AllowedServices,omitempty"`
	UnavailabilityCause             *CHUnavailabilityCause                `asn1:"tag:21,context,implicit,optional" json:"UnavailabilityCause,omitempty"`
	ReleaseResourcesSupported       *struct{}                             `asn1:"tag:22,context,implicit,optional" json:"ReleaseResourcesSupported,omitempty"`
	GsmBearerCapability             *CommonDataTypesExternalSignalInfo    `asn1:"tag:23,context,implicit,optional" json:"GsmBearerCapability,omitempty"`
	ExtCount_                       int64                                 `asn1:"-" json:"-"`
	ExtPresent_                     []bool                                `asn1:"-" json:"-"`
	ExtData_                        [][]byte                              `asn1:"-" json:"-"`
}

// CHAllowedServices represents the ASN.1 type AllowedServices (BIT_STRING).
type CHAllowedServices = runtime.BitString

// CHUnavailabilityCause represents the ASN.1 ENUMERATED type UnavailabilityCause.
type CHUnavailabilityCause int64

const (
	CHUnavailabilityCauseBearerServiceNotProvisioned CHUnavailabilityCause = 1
	CHUnavailabilityCauseTeleserviceNotProvisioned   CHUnavailabilityCause = 2
	CHUnavailabilityCauseAbsentSubscriber            CHUnavailabilityCause = 3
	CHUnavailabilityCauseBusySubscriber              CHUnavailabilityCause = 4
	CHUnavailabilityCauseCallBarred                  CHUnavailabilityCause = 5
	CHUnavailabilityCauseCugReject                   CHUnavailabilityCause = 6
)

func (v CHUnavailabilityCause) String() string {
	switch v {
	case CHUnavailabilityCauseBearerServiceNotProvisioned:
		return "bearerServiceNotProvisioned"
	case CHUnavailabilityCauseTeleserviceNotProvisioned:
		return "teleserviceNotProvisioned"
	case CHUnavailabilityCauseAbsentSubscriber:
		return "absentSubscriber"
	case CHUnavailabilityCauseBusySubscriber:
		return "busySubscriber"
	case CHUnavailabilityCauseCallBarred:
		return "callBarred"
	case CHUnavailabilityCauseCugReject:
		return "cug-Reject"
	default:
		return "unknown"
	}
}

// CHCCBSIndicators represents the ASN.1 type CCBS-Indicators (SEQUENCE).
type CHCCBSIndicators struct {
	CcbsPossible          *struct{}                             `asn1:"tag:0,context,implicit,optional" json:"CcbsPossible,omitempty"`
	KeepCCBSCallIndicator *struct{}                             `asn1:"tag:1,context,implicit,optional" json:"KeepCCBSCallIndicator,omitempty"`
	ExtensionContainer    *ExtensionDataTypesExtensionContainer `asn1:"tag:2,context,implicit,optional" json:"ExtensionContainer,omitempty"`
	ExtCount_             int64                                 `asn1:"-" json:"-"`
	ExtPresent_           []bool                                `asn1:"-" json:"-"`
	ExtData_              [][]byte                              `asn1:"-" json:"-"`
}

// CHRoutingInfo choice constants.
const (
	CHRoutingInfoChoiceRoamingNumber  = 1
	CHRoutingInfoChoiceForwardingData = 2
)

// CHRoutingInfo represents the ASN.1 CHOICE type RoutingInfo.
type CHRoutingInfo struct {
	Choice         int
	RoamingNumber  *CommonDataTypesISDNAddressString `json:"RoamingNumber,omitempty"`
	ForwardingData *CHForwardingData                 `json:"ForwardingData,omitempty"`
}

// NewCHRoutingInfoRoamingNumber creates a CHRoutingInfo with the roamingNumber alternative.
func NewCHRoutingInfoRoamingNumber(v CommonDataTypesISDNAddressString) CHRoutingInfo {
	return CHRoutingInfo{
		Choice:        CHRoutingInfoChoiceRoamingNumber,
		RoamingNumber: &v,
	}
}

// NewCHRoutingInfoForwardingData creates a CHRoutingInfo with the forwardingData alternative.
func NewCHRoutingInfoForwardingData(v CHForwardingData) CHRoutingInfo {
	return CHRoutingInfo{
		Choice:         CHRoutingInfoChoiceForwardingData,
		ForwardingData: &v,
	}
}

// CHForwardingData represents the ASN.1 type ForwardingData (SEQUENCE).
type CHForwardingData struct {
	ForwardedToNumber     *CommonDataTypesISDNAddressString     `asn1:"tag:5,context,implicit,optional" json:"ForwardedToNumber,omitempty"`
	ForwardedToSubaddress *CommonDataTypesISDNSubaddressString  `asn1:"tag:4,context,implicit,optional" json:"ForwardedToSubaddress,omitempty"`
	ForwardingOptions     *SSForwardingOptions                  `asn1:"tag:6,context,implicit,optional" json:"ForwardingOptions,omitempty"`
	ExtensionContainer    *ExtensionDataTypesExtensionContainer `asn1:"tag:7,context,implicit,optional" json:"ExtensionContainer,omitempty"`
	LongForwardedToNumber *CommonDataTypesFTNAddressString      `asn1:"tag:8,context,implicit,optional" json:"LongForwardedToNumber,omitempty"`
	ExtCount_             int64                                 `asn1:"-" json:"-"`
	ExtPresent_           []bool                                `asn1:"-" json:"-"`
	ExtData_              [][]byte                              `asn1:"-" json:"-"`
}

// CHProvideRoamingNumberArg represents the ASN.1 type ProvideRoamingNumberArg (SEQUENCE).
type CHProvideRoamingNumberArg struct {
	Imsi                                    CommonDataTypesIMSI                   `asn1:"tag:0,context,implicit"`
	MscNumber                               CommonDataTypesISDNAddressString      `asn1:"tag:1,context,implicit"`
	Msisdn                                  *CommonDataTypesISDNAddressString     `asn1:"tag:2,context,implicit,optional" json:"Msisdn,omitempty"`
	Lmsi                                    *CommonDataTypesLMSI                  `asn1:"tag:4,context,implicit,optional" json:"Lmsi,omitempty"`
	GsmBearerCapability                     *CommonDataTypesExternalSignalInfo    `asn1:"tag:5,context,implicit,optional" json:"GsmBearerCapability,omitempty"`
	NetworkSignalInfo                       *CommonDataTypesExternalSignalInfo    `asn1:"tag:6,context,implicit,optional" json:"NetworkSignalInfo,omitempty"`
	SuppressionOfAnnouncement               *CHSuppressionOfAnnouncement          `asn1:"tag:7,context,implicit,optional" json:"SuppressionOfAnnouncement,omitempty"`
	GmscAddress                             *CommonDataTypesISDNAddressString     `asn1:"tag:8,context,implicit,optional" json:"GmscAddress,omitempty"`
	CallReferenceNumber                     *CHCallReferenceNumber                `asn1:"tag:9,context,implicit,optional" json:"CallReferenceNumber,omitempty"`
	OrInterrogation                         *struct{}                             `asn1:"tag:10,context,implicit,optional" json:"OrInterrogation,omitempty"`
	ExtensionContainer                      *ExtensionDataTypesExtensionContainer `asn1:"tag:11,context,implicit,optional" json:"ExtensionContainer,omitempty"`
	AlertingPattern                         *CommonDataTypesAlertingPattern       `asn1:"tag:12,context,implicit,optional" json:"AlertingPattern,omitempty"`
	CcbsCall                                *struct{}                             `asn1:"tag:13,context,implicit,optional" json:"CcbsCall,omitempty"`
	SupportedCamelPhasesInInterrogatingNode *MSSupportedCamelPhases               `asn1:"tag:15,context,implicit,optional" json:"SupportedCamelPhasesInInterrogatingNode,omitempty"`
	AdditionalSignalInfo                    *CommonDataTypesExtExternalSignalInfo `asn1:"tag:14,context,implicit,optional" json:"AdditionalSignalInfo,omitempty"`
	OrNotSupportedInGMSC                    *struct{}                             `asn1:"tag:16,context,implicit,optional" json:"OrNotSupportedInGMSC,omitempty"`
	PrePagingSupported                      *struct{}                             `asn1:"tag:17,context,implicit,optional" json:"PrePagingSupported,omitempty"`
	LongFTNSupported                        *struct{}                             `asn1:"tag:18,context,implicit,optional" json:"LongFTNSupported,omitempty"`
	SuppressVTCSI                           *struct{}                             `asn1:"tag:19,context,implicit,optional" json:"SuppressVTCSI,omitempty"`
	OfferedCamel4CSIsInInterrogatingNode    *MSOfferedCamel4CSIs                  `asn1:"tag:20,context,implicit,optional" json:"OfferedCamel4CSIsInInterrogatingNode,omitempty"`
	ExtCount_                               int64                                 `asn1:"-" json:"-"`
	ExtPresent_                             []bool                                `asn1:"-" json:"-"`
	ExtData_                                [][]byte                              `asn1:"-" json:"-"`
}

// CHProvideRoamingNumberRes represents the ASN.1 type ProvideRoamingNumberRes (SEQUENCE).
type CHProvideRoamingNumberRes struct {
	RoamingNumber             CommonDataTypesISDNAddressString      `asn1:""`
	ExtensionContainer        *ExtensionDataTypesExtensionContainer `asn1:",optional" json:"ExtensionContainer,omitempty"`
	ReleaseResourcesSupported *struct{}                             `asn1:",optional" json:"ReleaseResourcesSupported,omitempty"`
	ExtCount_                 int64                                 `asn1:"-" json:"-"`
	ExtPresent_               []bool                                `asn1:"-" json:"-"`
	ExtData_                  [][]byte                              `asn1:"-" json:"-"`
}

// CHResumeCallHandlingArg represents the ASN.1 type ResumeCallHandlingArg (SEQUENCE).
type CHResumeCallHandlingArg struct {
	CallReferenceNumber             *CHCallReferenceNumber                `asn1:"tag:0,context,implicit,optional" json:"CallReferenceNumber,omitempty"`
	BasicServiceGroup               *CommonDataTypesExtBasicServiceCode   `asn1:"tag:1,context,explicit,optional" json:"BasicServiceGroup,omitempty"`
	ForwardingData                  *CHForwardingData                     `asn1:"tag:2,context,implicit,optional" json:"ForwardingData,omitempty"`
	Imsi                            *CommonDataTypesIMSI                  `asn1:"tag:3,context,implicit,optional" json:"Imsi,omitempty"`
	CugCheckInfo                    *CHCUGCheckInfo                       `asn1:"tag:4,context,implicit,optional" json:"CugCheckInfo,omitempty"`
	OCSI                            *MSOCSI                               `asn1:"tag:5,context,implicit,optional" json:"OCSI,omitempty"`
	ExtensionContainer              *ExtensionDataTypesExtensionContainer `asn1:"tag:7,context,implicit,optional" json:"ExtensionContainer,omitempty"`
	CcbsPossible                    *struct{}                             `asn1:"tag:8,context,implicit,optional" json:"CcbsPossible,omitempty"`
	Msisdn                          *CommonDataTypesISDNAddressString     `asn1:"tag:9,context,implicit,optional" json:"Msisdn,omitempty"`
	UuData                          *CHUUData                             `asn1:"tag:10,context,implicit,optional" json:"UuData,omitempty"`
	AllInformationSent              *struct{}                             `asn1:"tag:11,context,implicit,optional" json:"AllInformationSent,omitempty"`
	DCsi                            *MSDCSI                               `asn1:"tag:12,context,implicit,optional" json:"DCsi,omitempty"`
	OBcsmCamelTDPCriteriaList       MSOBcsmCamelTDPCriteriaList           `asn1:"tag:13,context,implicit,optional" json:"OBcsmCamelTDPCriteriaList,omitempty"`
	OBcsmCamelTDPCriteriaListIndef_ bool                                  `asn1:"-" json:"-"`
	BasicServiceGroup2              *CommonDataTypesExtBasicServiceCode   `asn1:"tag:14,context,explicit,optional" json:"BasicServiceGroup2,omitempty"`
	ExtCount_                       int64                                 `asn1:"-" json:"-"`
	ExtPresent_                     []bool                                `asn1:"-" json:"-"`
	ExtData_                        [][]byte                              `asn1:"-" json:"-"`
}

// CHUUData represents the ASN.1 type UU-Data (SEQUENCE).
type CHUUData struct {
	UuIndicator        *CHUUIndicator                        `asn1:"tag:0,context,implicit,optional" json:"UuIndicator,omitempty"`
	Uui                *CHUUI                                `asn1:"tag:1,context,implicit,optional" json:"Uui,omitempty"`
	UusCFInteraction   *struct{}                             `asn1:"tag:2,context,implicit,optional" json:"UusCFInteraction,omitempty"`
	ExtensionContainer *ExtensionDataTypesExtensionContainer `asn1:"tag:3,context,implicit,optional" json:"ExtensionContainer,omitempty"`
	ExtCount_          int64                                 `asn1:"-" json:"-"`
	ExtPresent_        []bool                                `asn1:"-" json:"-"`
	ExtData_           [][]byte                              `asn1:"-" json:"-"`
}

// CHUUIndicator represents the ASN.1 type UUIndicator (OCTET_STRING).
type CHUUIndicator = []byte

// CHUUI represents the ASN.1 type UUI (OCTET_STRING).
type CHUUI = []byte

// CHResumeCallHandlingRes represents the ASN.1 type ResumeCallHandlingRes (SEQUENCE).
type CHResumeCallHandlingRes struct {
	ExtensionContainer *ExtensionDataTypesExtensionContainer `asn1:",optional" json:"ExtensionContainer,omitempty"`
	ExtCount_          int64                                 `asn1:"-" json:"-"`
	ExtPresent_        []bool                                `asn1:"-" json:"-"`
	ExtData_           [][]byte                              `asn1:"-" json:"-"`
}

// CHCamelInfo represents the ASN.1 type CamelInfo (SEQUENCE).
type CHCamelInfo struct {
	SupportedCamelPhases MSSupportedCamelPhases                `asn1:""`
	SuppressTCSI         *struct{}                             `asn1:",optional" json:"SuppressTCSI,omitempty"`
	ExtensionContainer   *ExtensionDataTypesExtensionContainer `asn1:",optional" json:"ExtensionContainer,omitempty"`
	OfferedCamel4CSIs    *MSOfferedCamel4CSIs                  `asn1:"tag:0,context,implicit,optional" json:"OfferedCamel4CSIs,omitempty"`
	ExtCount_            int64                                 `asn1:"-" json:"-"`
	ExtPresent_          []bool                                `asn1:"-" json:"-"`
	ExtData_             [][]byte                              `asn1:"-" json:"-"`
}

// CHExtendedRoutingInfo choice constants.
const (
	CHExtendedRoutingInfoChoiceRoutingInfo      = 1
	CHExtendedRoutingInfoChoiceCamelRoutingInfo = 2
)

// CHExtendedRoutingInfo represents the ASN.1 CHOICE type ExtendedRoutingInfo.
type CHExtendedRoutingInfo struct {
	Choice           int
	RoutingInfo      *CHRoutingInfo      `json:"RoutingInfo,omitempty"`
	CamelRoutingInfo *CHCamelRoutingInfo `json:"CamelRoutingInfo,omitempty"`
}

// NewCHExtendedRoutingInfoRoutingInfo creates a CHExtendedRoutingInfo with the routingInfo alternative.
func NewCHExtendedRoutingInfoRoutingInfo(v CHRoutingInfo) CHExtendedRoutingInfo {
	return CHExtendedRoutingInfo{
		Choice:      CHExtendedRoutingInfoChoiceRoutingInfo,
		RoutingInfo: &v,
	}
}

// NewCHExtendedRoutingInfoCamelRoutingInfo creates a CHExtendedRoutingInfo with the camelRoutingInfo alternative.
func NewCHExtendedRoutingInfoCamelRoutingInfo(v CHCamelRoutingInfo) CHExtendedRoutingInfo {
	return CHExtendedRoutingInfo{
		Choice:           CHExtendedRoutingInfoChoiceCamelRoutingInfo,
		CamelRoutingInfo: &v,
	}
}

// CHCamelRoutingInfo represents the ASN.1 type CamelRoutingInfo (SEQUENCE).
type CHCamelRoutingInfo struct {
	ForwardingData            *CHForwardingData                     `asn1:",optional" json:"ForwardingData,omitempty"`
	GmscCamelSubscriptionInfo CHGmscCamelSubscriptionInfo           `asn1:"tag:0,context,implicit"`
	ExtensionContainer        *ExtensionDataTypesExtensionContainer `asn1:"tag:1,context,implicit,optional" json:"ExtensionContainer,omitempty"`
	ExtCount_                 int64                                 `asn1:"-" json:"-"`
	ExtPresent_               []bool                                `asn1:"-" json:"-"`
	ExtData_                  [][]byte                              `asn1:"-" json:"-"`
}

// CHGmscCamelSubscriptionInfo represents the ASN.1 type GmscCamelSubscriptionInfo (SEQUENCE).
type CHGmscCamelSubscriptionInfo struct {
	TCSI                            *MSTCSI                               `asn1:"tag:0,context,implicit,optional" json:"TCSI,omitempty"`
	OCSI                            *MSOCSI                               `asn1:"tag:1,context,implicit,optional" json:"OCSI,omitempty"`
	ExtensionContainer              *ExtensionDataTypesExtensionContainer `asn1:"tag:2,context,implicit,optional" json:"ExtensionContainer,omitempty"`
	OBcsmCamelTDPCriteriaList       MSOBcsmCamelTDPCriteriaList           `asn1:"tag:3,context,implicit,optional" json:"OBcsmCamelTDPCriteriaList,omitempty"`
	OBcsmCamelTDPCriteriaListIndef_ bool                                  `asn1:"-" json:"-"`
	TBCSMCAMELTDPCriteriaList       MSTBCSMCAMELTDPCriteriaList           `asn1:"tag:4,context,implicit,optional" json:"TBCSMCAMELTDPCriteriaList,omitempty"`
	TBCSMCAMELTDPCriteriaListIndef_ bool                                  `asn1:"-" json:"-"`
	DCsi                            *MSDCSI                               `asn1:"tag:5,context,implicit,optional" json:"DCsi,omitempty"`
	ExtCount_                       int64                                 `asn1:"-" json:"-"`
	ExtPresent_                     []bool                                `asn1:"-" json:"-"`
	ExtData_                        [][]byte                              `asn1:"-" json:"-"`
}

// CHSetReportingStateArg represents the ASN.1 type SetReportingStateArg (SEQUENCE).
type CHSetReportingStateArg struct {
	Imsi               *CommonDataTypesIMSI                  `asn1:"tag:0,context,implicit,optional" json:"Imsi,omitempty"`
	Lmsi               *CommonDataTypesLMSI                  `asn1:"tag:1,context,implicit,optional" json:"Lmsi,omitempty"`
	CcbsMonitoring     *CHReportingState                     `asn1:"tag:2,context,implicit,optional" json:"CcbsMonitoring,omitempty"`
	ExtensionContainer *ExtensionDataTypesExtensionContainer `asn1:"tag:3,context,implicit,optional" json:"ExtensionContainer,omitempty"`
	ExtCount_          int64                                 `asn1:"-" json:"-"`
	ExtPresent_        []bool                                `asn1:"-" json:"-"`
	ExtData_           [][]byte                              `asn1:"-" json:"-"`
}

// CHReportingState represents the ASN.1 ENUMERATED type ReportingState.
type CHReportingState int64

const (
	CHReportingStateStopMonitoring  CHReportingState = 0
	CHReportingStateStartMonitoring CHReportingState = 1
)

func (v CHReportingState) String() string {
	switch v {
	case CHReportingStateStopMonitoring:
		return "stopMonitoring"
	case CHReportingStateStartMonitoring:
		return "startMonitoring"
	default:
		return "unknown"
	}
}

// CHSetReportingStateRes represents the ASN.1 type SetReportingStateRes (SEQUENCE).
type CHSetReportingStateRes struct {
	CcbsSubscriberStatus *CHCCBSSubscriberStatus               `asn1:"tag:0,context,implicit,optional" json:"CcbsSubscriberStatus,omitempty"`
	ExtensionContainer   *ExtensionDataTypesExtensionContainer `asn1:"tag:1,context,implicit,optional" json:"ExtensionContainer,omitempty"`
	ExtCount_            int64                                 `asn1:"-" json:"-"`
	ExtPresent_          []bool                                `asn1:"-" json:"-"`
	ExtData_             [][]byte                              `asn1:"-" json:"-"`
}

// CHCCBSSubscriberStatus represents the ASN.1 ENUMERATED type CCBS-SubscriberStatus.
type CHCCBSSubscriberStatus int64

const (
	CHCCBSSubscriberStatusCcbsNotIdle      CHCCBSSubscriberStatus = 0
	CHCCBSSubscriberStatusCcbsIdle         CHCCBSSubscriberStatus = 1
	CHCCBSSubscriberStatusCcbsNotReachable CHCCBSSubscriberStatus = 2
)

func (v CHCCBSSubscriberStatus) String() string {
	switch v {
	case CHCCBSSubscriberStatusCcbsNotIdle:
		return "ccbsNotIdle"
	case CHCCBSSubscriberStatusCcbsIdle:
		return "ccbsIdle"
	case CHCCBSSubscriberStatusCcbsNotReachable:
		return "ccbsNotReachable"
	default:
		return "unknown"
	}
}

// CHStatusReportArg represents the ASN.1 type StatusReportArg (SEQUENCE).
type CHStatusReportArg struct {
	Imsi               CommonDataTypesIMSI                   `asn1:"tag:0,context,implicit"`
	EventReportData    *CHEventReportData                    `asn1:"tag:1,context,implicit,optional" json:"EventReportData,omitempty"`
	CallReportdata     *CHCallReportData                     `asn1:"tag:2,context,implicit,optional" json:"CallReportdata,omitempty"`
	ExtensionContainer *ExtensionDataTypesExtensionContainer `asn1:"tag:3,context,implicit,optional" json:"ExtensionContainer,omitempty"`
	ExtCount_          int64                                 `asn1:"-" json:"-"`
	ExtPresent_        []bool                                `asn1:"-" json:"-"`
	ExtData_           [][]byte                              `asn1:"-" json:"-"`
}

// CHEventReportData represents the ASN.1 type EventReportData (SEQUENCE).
type CHEventReportData struct {
	CcbsSubscriberStatus *CHCCBSSubscriberStatus               `asn1:"tag:0,context,implicit,optional" json:"CcbsSubscriberStatus,omitempty"`
	ExtensionContainer   *ExtensionDataTypesExtensionContainer `asn1:"tag:1,context,implicit,optional" json:"ExtensionContainer,omitempty"`
	ExtCount_            int64                                 `asn1:"-" json:"-"`
	ExtPresent_          []bool                                `asn1:"-" json:"-"`
	ExtData_             [][]byte                              `asn1:"-" json:"-"`
}

// CHCallReportData represents the ASN.1 type CallReportData (SEQUENCE).
type CHCallReportData struct {
	MonitoringMode     *CHMonitoringMode                     `asn1:"tag:0,context,implicit,optional" json:"MonitoringMode,omitempty"`
	CallOutcome        *CHCallOutcome                        `asn1:"tag:1,context,implicit,optional" json:"CallOutcome,omitempty"`
	ExtensionContainer *ExtensionDataTypesExtensionContainer `asn1:"tag:2,context,implicit,optional" json:"ExtensionContainer,omitempty"`
	ExtCount_          int64                                 `asn1:"-" json:"-"`
	ExtPresent_        []bool                                `asn1:"-" json:"-"`
	ExtData_           [][]byte                              `asn1:"-" json:"-"`
}

// CHMonitoringMode represents the ASN.1 ENUMERATED type MonitoringMode.
type CHMonitoringMode int64

const (
	CHMonitoringModeASide CHMonitoringMode = 0
	CHMonitoringModeBSide CHMonitoringMode = 1
)

func (v CHMonitoringMode) String() string {
	switch v {
	case CHMonitoringModeASide:
		return "a-side"
	case CHMonitoringModeBSide:
		return "b-side"
	default:
		return "unknown"
	}
}

// CHCallOutcome represents the ASN.1 ENUMERATED type CallOutcome.
type CHCallOutcome int64

const (
	CHCallOutcomeSuccess CHCallOutcome = 0
	CHCallOutcomeFailure CHCallOutcome = 1
	CHCallOutcomeBusy    CHCallOutcome = 2
)

func (v CHCallOutcome) String() string {
	switch v {
	case CHCallOutcomeSuccess:
		return "success"
	case CHCallOutcomeFailure:
		return "failure"
	case CHCallOutcomeBusy:
		return "busy"
	default:
		return "unknown"
	}
}

// CHStatusReportRes represents the ASN.1 type StatusReportRes (SEQUENCE).
type CHStatusReportRes struct {
	ExtensionContainer *ExtensionDataTypesExtensionContainer `asn1:"tag:0,context,implicit,optional" json:"ExtensionContainer,omitempty"`
	ExtCount_          int64                                 `asn1:"-" json:"-"`
	ExtPresent_        []bool                                `asn1:"-" json:"-"`
	ExtData_           [][]byte                              `asn1:"-" json:"-"`
}

// CHRemoteUserFreeArg represents the ASN.1 type RemoteUserFreeArg (SEQUENCE).
type CHRemoteUserFreeArg struct {
	Imsi               CommonDataTypesIMSI                   `asn1:"tag:0,context,implicit"`
	CallInfo           CommonDataTypesExternalSignalInfo     `asn1:"tag:1,context,implicit"`
	CcbsFeature        SSCCBSFeature                         `asn1:"tag:2,context,implicit"`
	TranslatedBNumber  CommonDataTypesISDNAddressString      `asn1:"tag:3,context,implicit"`
	ReplaceBNumber     *struct{}                             `asn1:"tag:4,context,implicit,optional" json:"ReplaceBNumber,omitempty"`
	AlertingPattern    *CommonDataTypesAlertingPattern       `asn1:"tag:5,context,implicit,optional" json:"AlertingPattern,omitempty"`
	ExtensionContainer *ExtensionDataTypesExtensionContainer `asn1:"tag:6,context,implicit,optional" json:"ExtensionContainer,omitempty"`
	ExtCount_          int64                                 `asn1:"-" json:"-"`
	ExtPresent_        []bool                                `asn1:"-" json:"-"`
	ExtData_           [][]byte                              `asn1:"-" json:"-"`
}

// CHRemoteUserFreeRes represents the ASN.1 type RemoteUserFreeRes (SEQUENCE).
type CHRemoteUserFreeRes struct {
	RufOutcome         CHRUFOutcome                          `asn1:"tag:0,context,implicit"`
	ExtensionContainer *ExtensionDataTypesExtensionContainer `asn1:"tag:1,context,implicit,optional" json:"ExtensionContainer,omitempty"`
	ExtCount_          int64                                 `asn1:"-" json:"-"`
	ExtPresent_        []bool                                `asn1:"-" json:"-"`
	ExtData_           [][]byte                              `asn1:"-" json:"-"`
}

// CHRUFOutcome represents the ASN.1 ENUMERATED type RUF-Outcome.
type CHRUFOutcome int64

const (
	CHRUFOutcomeAccepted             CHRUFOutcome = 0
	CHRUFOutcomeRejected             CHRUFOutcome = 1
	CHRUFOutcomeNoResponseFromFreeMS CHRUFOutcome = 2
	CHRUFOutcomeNoResponseFromBusyMS CHRUFOutcome = 3
	CHRUFOutcomeUdubFromFreeMS       CHRUFOutcome = 4
	CHRUFOutcomeUdubFromBusyMS       CHRUFOutcome = 5
)

func (v CHRUFOutcome) String() string {
	switch v {
	case CHRUFOutcomeAccepted:
		return "accepted"
	case CHRUFOutcomeRejected:
		return "rejected"
	case CHRUFOutcomeNoResponseFromFreeMS:
		return "noResponseFromFreeMS"
	case CHRUFOutcomeNoResponseFromBusyMS:
		return "noResponseFromBusyMS"
	case CHRUFOutcomeUdubFromFreeMS:
		return "udubFromFreeMS"
	case CHRUFOutcomeUdubFromBusyMS:
		return "udubFromBusyMS"
	default:
		return "unknown"
	}
}

// CHISTAlertArg represents the ASN.1 type IST-AlertArg (SEQUENCE).
type CHISTAlertArg struct {
	Imsi               CommonDataTypesIMSI                   `asn1:"tag:0,context,implicit"`
	ExtensionContainer *ExtensionDataTypesExtensionContainer `asn1:"tag:1,context,implicit,optional" json:"ExtensionContainer,omitempty"`
	ExtCount_          int64                                 `asn1:"-" json:"-"`
	ExtPresent_        []bool                                `asn1:"-" json:"-"`
	ExtData_           [][]byte                              `asn1:"-" json:"-"`
}

// CHISTAlertRes represents the ASN.1 type IST-AlertRes (SEQUENCE).
type CHISTAlertRes struct {
	IstAlertTimer            *MSISTAlertTimerValue                 `asn1:"tag:0,context,implicit,optional" json:"IstAlertTimer,omitempty"`
	IstInformationWithdraw   *struct{}                             `asn1:"tag:1,context,implicit,optional" json:"IstInformationWithdraw,omitempty"`
	CallTerminationIndicator *CHCallTerminationIndicator           `asn1:"tag:2,context,implicit,optional" json:"CallTerminationIndicator,omitempty"`
	ExtensionContainer       *ExtensionDataTypesExtensionContainer `asn1:"tag:3,context,implicit,optional" json:"ExtensionContainer,omitempty"`
	ExtCount_                int64                                 `asn1:"-" json:"-"`
	ExtPresent_              []bool                                `asn1:"-" json:"-"`
	ExtData_                 [][]byte                              `asn1:"-" json:"-"`
}

// CHISTCommandArg represents the ASN.1 type IST-CommandArg (SEQUENCE).
type CHISTCommandArg struct {
	Imsi               CommonDataTypesIMSI                   `asn1:"tag:0,context,implicit"`
	ExtensionContainer *ExtensionDataTypesExtensionContainer `asn1:"tag:1,context,implicit,optional" json:"ExtensionContainer,omitempty"`
	ExtCount_          int64                                 `asn1:"-" json:"-"`
	ExtPresent_        []bool                                `asn1:"-" json:"-"`
	ExtData_           [][]byte                              `asn1:"-" json:"-"`
}

// CHISTCommandRes represents the ASN.1 type IST-CommandRes (SEQUENCE).
type CHISTCommandRes struct {
	ExtensionContainer *ExtensionDataTypesExtensionContainer `asn1:",optional" json:"ExtensionContainer,omitempty"`
	ExtCount_          int64                                 `asn1:"-" json:"-"`
	ExtPresent_        []bool                                `asn1:"-" json:"-"`
	ExtData_           [][]byte                              `asn1:"-" json:"-"`
}

// CHCallTerminationIndicator represents the ASN.1 ENUMERATED type CallTerminationIndicator.
type CHCallTerminationIndicator int64

const (
	CHCallTerminationIndicatorTerminateCallActivityReferred CHCallTerminationIndicator = 0
	CHCallTerminationIndicatorTerminateAllCallActivities    CHCallTerminationIndicator = 1
)

func (v CHCallTerminationIndicator) String() string {
	switch v {
	case CHCallTerminationIndicatorTerminateCallActivityReferred:
		return "terminateCallActivityReferred"
	case CHCallTerminationIndicatorTerminateAllCallActivities:
		return "terminateAllCallActivities"
	default:
		return "unknown"
	}
}

// CHReleaseResourcesArg represents the ASN.1 type ReleaseResourcesArg (SEQUENCE).
type CHReleaseResourcesArg struct {
	Msrn               CommonDataTypesISDNAddressString      `asn1:""`
	ExtensionContainer *ExtensionDataTypesExtensionContainer `asn1:",optional" json:"ExtensionContainer,omitempty"`
	ExtCount_          int64                                 `asn1:"-" json:"-"`
	ExtPresent_        []bool                                `asn1:"-" json:"-"`
	ExtData_           [][]byte                              `asn1:"-" json:"-"`
}

// CHReleaseResourcesRes represents the ASN.1 type ReleaseResourcesRes (SEQUENCE).
type CHReleaseResourcesRes struct {
	ExtensionContainer *ExtensionDataTypesExtensionContainer `asn1:",optional" json:"ExtensionContainer,omitempty"`
	ExtCount_          int64                                 `asn1:"-" json:"-"`
	ExtPresent_        []bool                                `asn1:"-" json:"-"`
	ExtData_           [][]byte                              `asn1:"-" json:"-"`
}

// MarshalBER encodes CHCUGCheckInfo to BER format.
func (v *CHCUGCheckInfo) MarshalBER() ([]byte, error) {
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

// MarshalDER encodes CHCUGCheckInfo to DER format.
func (v *CHCUGCheckInfo) MarshalDER() ([]byte, error) {
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
		return nil, fmt.Errorf("encoding CHCUGCheckInfo as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes CHCUGCheckInfo from BER/DER format.
func (v *CHCUGCheckInfo) UnmarshalBER(data []byte) error {
	*v = CHCUGCheckInfo{}
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding CHCUGCheckInfo SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "CHCUGCheckInfo", Cause: ber.ErrExtraData}
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
	v.CugInterlock = MSCUGInterlock(val_cuginterlock)
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
				// Decode nested SEQUENCE (ExtensionDataTypesExtensionContainer)
				_, n_extensioncontainer, _, tlvErr_extensioncontainer := ber.DecodeTLV(content[offset:])
				if tlvErr_extensioncontainer != nil {
					return fmt.Errorf("decoding extensionContainer: %w", tlvErr_extensioncontainer)
				}
				var dec_extensioncontainer ExtensionDataTypesExtensionContainer
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
			return &ber.DecodeError{Offset: offset, TypeName: "CHCUGCheckInfo", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes CHSendRoutingInfoArg to BER format.
func (v *CHSendRoutingInfoArg) MarshalBER() ([]byte, error) {
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

// MarshalDER encodes CHSendRoutingInfoArg to DER format.
func (v *CHSendRoutingInfoArg) MarshalDER() ([]byte, error) {
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
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
		children = append(children, ext...)
	}
	encoded := ber.EncodeSequence(children)
	if err := ber.ValidateDERElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding CHSendRoutingInfoArg as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes CHSendRoutingInfoArg from BER/DER format.
func (v *CHSendRoutingInfoArg) UnmarshalBER(data []byte) error {
	*v = CHSendRoutingInfoArg{}
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding CHSendRoutingInfoArg SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "CHSendRoutingInfoArg", Cause: ber.ErrExtraData}
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
	v.Msisdn = CommonDataTypesISDNAddressString(rawVal_msisdn)
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
				var dec_cugcheckinfo CHCUGCheckInfo
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
				tmp_numberofforwarding := CHNumberOfForwarding(decVal_numberofforwarding)
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
	v.InterrogationType = CHInterrogationType(decVal_interrogationtype)
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
				tmp_orcapability := CHORPhase(decVal_orcapability)
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
	v.GmscOrGsmSCFAddress = CommonDataTypesISDNAddressString(rawVal_gmscorgsmscfaddress)
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
				tmp_callreferencenumber := CHCallReferenceNumber(rawVal_callreferencenumber)
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
				tmp_forwardingreason := CHForwardingReason(decVal_forwardingreason)
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
				var dec_basicservicegroup CommonDataTypesExtBasicServiceCode
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
				var dec_networksignalinfo CommonDataTypesExternalSignalInfo
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
				var dec_camelinfo CHCamelInfo
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
				var dec_extensioncontainer ExtensionDataTypesExtensionContainer
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
				tmp_alertingpattern := CommonDataTypesAlertingPattern(rawVal_alertingpattern)
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
				tmp_supportedccbsphase := CHSupportedCCBSPhase(decVal_supportedccbsphase)
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
				var dec_additionalsignalinfo CommonDataTypesExtExternalSignalInfo
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
				tmp_istsupportindicator := MSISTSupportIndicator(decVal_istsupportindicator)
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
				tmp_calldiversiontreatmentindicator := CHCallDiversionTreatmentIndicator(rawVal_calldiversiontreatmentindicator)
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
				var dec_basicservicegroup2 CommonDataTypesExtBasicServiceCode
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
				var dec_networksignalinfo2 CommonDataTypesExternalSignalInfo
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
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "CHSendRoutingInfoArg", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes CHSendRoutingInfoRes to BER format.
func (v *CHSendRoutingInfoRes) MarshalBER() ([]byte, error) {
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
		enc_sslist, err := MarshalBERSSSSList(v.SsList)
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
		enc_sslist2, err := MarshalBERSSSSList(v.SsList2)
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

// MarshalDER encodes CHSendRoutingInfoRes to DER format.
func (v *CHSendRoutingInfoRes) MarshalDER() ([]byte, error) {
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
		enc_sslist, err := MarshalDERSSSSList(v.SsList)
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
		enc_sslist2, err := MarshalDERSSSSList(v.SsList2)
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
		return nil, fmt.Errorf("encoding CHSendRoutingInfoRes: %w", tagErr_encoded)
	}
	encoded = retagged_encoded
	if err := ber.ValidateDERElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding CHSendRoutingInfoRes as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes CHSendRoutingInfoRes from BER/DER format.
func (v *CHSendRoutingInfoRes) UnmarshalBER(data []byte) error {
	*v = CHSendRoutingInfoRes{}
	decodedTag, content, total, err := ber.DecodeConstructedContent(data)
	if err != nil {
		return fmt.Errorf("decoding CHSendRoutingInfoRes: %w", err)
	}
	if decodedTag.Class != tag.ClassContextSpecific || decodedTag.Number != 3 || !decodedTag.Constructed {
		return fmt.Errorf("decoding CHSendRoutingInfoRes: %w: expected tag [CONTEXT 3], got %s", ber.ErrInvalidTag, decodedTag)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "CHSendRoutingInfoRes", Cause: ber.ErrExtraData}
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
				tmp_imsi := CommonDataTypesIMSI(rawVal_imsi)
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
				// Decode nested CHOICE (CHExtendedRoutingInfo)
				_, n_extendedroutinginfo, _, tlvErr_extendedroutinginfo := ber.DecodeTLV(content[offset:])
				if tlvErr_extendedroutinginfo != nil {
					return fmt.Errorf("decoding extendedRoutingInfo: %w", tlvErr_extendedroutinginfo)
				}
				var dec_extendedroutinginfo CHExtendedRoutingInfo
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
				var dec_cugcheckinfo CHCUGCheckInfo
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
				var dec_subscriberinfo MSSubscriberInfo
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
				dec_sslist, unmErr := UnmarshalBERSSSSList(reconstructed_sslist)
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
				var dec_basicservice CommonDataTypesExtBasicServiceCode
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
				tmp_vmscaddress := CommonDataTypesISDNAddressString(rawVal_vmscaddress)
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
				var dec_extensioncontainer ExtensionDataTypesExtensionContainer
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
				var dec_naeapreferredci CommonDataTypesNAEAPreferredCI
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
				var dec_ccbsindicators CHCCBSIndicators
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
				tmp_msisdn := CommonDataTypesISDNAddressString(rawVal_msisdn)
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
				tmp_numberportabilitystatus := MSNumberPortabilityStatus(decVal_numberportabilitystatus)
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
				tmp_istalerttimer := MSISTAlertTimerValue(decVal_istalerttimer)
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
				var dec_routinginfo2 CHRoutingInfo
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
				dec_sslist2, unmErr := UnmarshalBERSSSSList(reconstructed_sslist2)
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
				var dec_basicservice2 CommonDataTypesExtBasicServiceCode
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
				tmp_unavailabilitycause := CHUnavailabilityCause(decVal_unavailabilitycause)
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
				var dec_gsmbearercapability CommonDataTypesExternalSignalInfo
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
			return &ber.DecodeError{Offset: offset, TypeName: "CHSendRoutingInfoRes", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes CHCCBSIndicators to BER format.
func (v *CHCCBSIndicators) MarshalBER() ([]byte, error) {
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

// MarshalDER encodes CHCCBSIndicators to DER format.
func (v *CHCCBSIndicators) MarshalDER() ([]byte, error) {
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
		return nil, fmt.Errorf("encoding CHCCBSIndicators as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes CHCCBSIndicators from BER/DER format.
func (v *CHCCBSIndicators) UnmarshalBER(data []byte) error {
	*v = CHCCBSIndicators{}
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding CHCCBSIndicators SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "CHCCBSIndicators", Cause: ber.ErrExtraData}
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
				var dec_extensioncontainer ExtensionDataTypesExtensionContainer
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
			return &ber.DecodeError{Offset: offset, TypeName: "CHCCBSIndicators", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes CHRoutingInfo to BER format.
func (v *CHRoutingInfo) MarshalBER() ([]byte, error) {
	switch v.Choice {
	case CHRoutingInfoChoiceRoamingNumber:
		if v.RoamingNumber == nil {
			return nil, fmt.Errorf("choice CHRoutingInfo: roamingNumber is nil")
		}
		enc_0 := ber.EncodeOctetString([]byte(*v.RoamingNumber))
		return enc_0, nil
	case CHRoutingInfoChoiceForwardingData:
		if v.ForwardingData == nil {
			return nil, fmt.Errorf("choice CHRoutingInfo: forwardingData is nil")
		}
		enc_1, err := v.ForwardingData.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding forwardingData: %w", err)
		}
		return enc_1, nil
	default:
		return nil, fmt.Errorf("unknown choice %d for CHRoutingInfo", v.Choice)
	}
}

// MarshalDER encodes CHRoutingInfo to DER format.
func (v *CHRoutingInfo) MarshalDER() ([]byte, error) {
	switch v.Choice {
	case CHRoutingInfoChoiceForwardingData:
		if v.ForwardingData == nil {
			return nil, fmt.Errorf("choice CHRoutingInfo: forwardingData is nil")
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
		return nil, fmt.Errorf("encoding CHRoutingInfo as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes CHRoutingInfo from BER/DER format.
func (v *CHRoutingInfo) UnmarshalBER(data []byte) error {
	*v = CHRoutingInfo{}
	if len(data) == 0 {
		return fmt.Errorf("empty data for CHRoutingInfo CHOICE")
	}
	choiceData := data
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for CHRoutingInfo: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData)
	if tlvErr != nil {
		return fmt.Errorf("decoding CHRoutingInfo CHOICE: %w", tlvErr)
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "CHRoutingInfo", Cause: ber.ErrExtraData}
	}

	if peekTag.Class == tag.ClassUniversal && peekTag.Number == 4 {
		v.Choice = CHRoutingInfoChoiceRoamingNumber
		decVal, _, osErr := ber.DecodeOctetString(choiceData)
		if osErr != nil {
			return fmt.Errorf("decoding roamingNumber: %w", osErr)
		}
		tmp := CommonDataTypesISDNAddressString(decVal)
		v.RoamingNumber = &tmp
	} else if peekTag.Class == tag.ClassUniversal && peekTag.Number == 16 && peekTag.Constructed == true {
		v.Choice = CHRoutingInfoChoiceForwardingData
		var dec CHForwardingData
		if unmErr := dec.UnmarshalBER(choiceData); unmErr != nil {
			return fmt.Errorf("decoding forwardingData: %w", unmErr)
		}
		v.ForwardingData = &dec
	} else {
		return fmt.Errorf("unknown tag %s for CHRoutingInfo CHOICE", peekTag)
	}
	return nil
}

// MarshalBER encodes CHForwardingData to BER format.
func (v *CHForwardingData) MarshalBER() ([]byte, error) {
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

// MarshalDER encodes CHForwardingData to DER format.
func (v *CHForwardingData) MarshalDER() ([]byte, error) {
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
		return nil, fmt.Errorf("encoding CHForwardingData as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes CHForwardingData from BER/DER format.
func (v *CHForwardingData) UnmarshalBER(data []byte) error {
	*v = CHForwardingData{}
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding CHForwardingData SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "CHForwardingData", Cause: ber.ErrExtraData}
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
				tmp_forwardedtonumber := CommonDataTypesISDNAddressString(rawVal_forwardedtonumber)
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
				tmp_forwardedtosubaddress := CommonDataTypesISDNSubaddressString(rawVal_forwardedtosubaddress)
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
				tmp_forwardingoptions := SSForwardingOptions(rawVal_forwardingoptions)
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
				var dec_extensioncontainer ExtensionDataTypesExtensionContainer
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
				tmp_longforwardedtonumber := CommonDataTypesFTNAddressString(rawVal_longforwardedtonumber)
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
			return &ber.DecodeError{Offset: offset, TypeName: "CHForwardingData", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes CHProvideRoamingNumberArg to BER format.
func (v *CHProvideRoamingNumberArg) MarshalBER() ([]byte, error) {
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

// MarshalDER encodes CHProvideRoamingNumberArg to DER format.
func (v *CHProvideRoamingNumberArg) MarshalDER() ([]byte, error) {
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
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
		children = append(children, ext...)
	}
	encoded := ber.EncodeSequence(children)
	if err := ber.ValidateDERElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding CHProvideRoamingNumberArg as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes CHProvideRoamingNumberArg from BER/DER format.
func (v *CHProvideRoamingNumberArg) UnmarshalBER(data []byte) error {
	*v = CHProvideRoamingNumberArg{}
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding CHProvideRoamingNumberArg SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "CHProvideRoamingNumberArg", Cause: ber.ErrExtraData}
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
	v.Imsi = CommonDataTypesIMSI(rawVal_imsi)
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
	v.MscNumber = CommonDataTypesISDNAddressString(rawVal_mscnumber)
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
				tmp_msisdn := CommonDataTypesISDNAddressString(rawVal_msisdn)
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
				tmp_lmsi := CommonDataTypesLMSI(rawVal_lmsi)
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
				var dec_gsmbearercapability CommonDataTypesExternalSignalInfo
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
				var dec_networksignalinfo CommonDataTypesExternalSignalInfo
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
				tmp_gmscaddress := CommonDataTypesISDNAddressString(rawVal_gmscaddress)
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
				tmp_callreferencenumber := CHCallReferenceNumber(rawVal_callreferencenumber)
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
				var dec_extensioncontainer ExtensionDataTypesExtensionContainer
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
				tmp_alertingpattern := CommonDataTypesAlertingPattern(rawVal_alertingpattern)
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
				var dec_additionalsignalinfo CommonDataTypesExtExternalSignalInfo
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
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "CHProvideRoamingNumberArg", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes CHProvideRoamingNumberRes to BER format.
func (v *CHProvideRoamingNumberRes) MarshalBER() ([]byte, error) {
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

// MarshalDER encodes CHProvideRoamingNumberRes to DER format.
func (v *CHProvideRoamingNumberRes) MarshalDER() ([]byte, error) {
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
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
		children = append(children, ext...)
	}
	encoded := ber.EncodeSequence(children)
	if err := ber.ValidateDERElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding CHProvideRoamingNumberRes as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes CHProvideRoamingNumberRes from BER/DER format.
func (v *CHProvideRoamingNumberRes) UnmarshalBER(data []byte) error {
	*v = CHProvideRoamingNumberRes{}
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding CHProvideRoamingNumberRes SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "CHProvideRoamingNumberRes", Cause: ber.ErrExtraData}
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
	v.RoamingNumber = CommonDataTypesISDNAddressString(val_roamingnumber)
	offset += n
	// Decode extensionContainer
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassUniversal && peekTag.Number == 16 {
				// Decode nested SEQUENCE (ExtensionDataTypesExtensionContainer)
				_, n_extensioncontainer, _, tlvErr_extensioncontainer := ber.DecodeTLV(content[offset:])
				if tlvErr_extensioncontainer != nil {
					return fmt.Errorf("decoding extensionContainer: %w", tlvErr_extensioncontainer)
				}
				var dec_extensioncontainer ExtensionDataTypesExtensionContainer
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
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "CHProvideRoamingNumberRes", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes CHResumeCallHandlingArg to BER format.
func (v *CHResumeCallHandlingArg) MarshalBER() ([]byte, error) {
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
		enc_obcsmcameltdpcriterialist, err := MarshalBERMSOBcsmCamelTDPCriteriaList(v.OBcsmCamelTDPCriteriaList)
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

// MarshalDER encodes CHResumeCallHandlingArg to DER format.
func (v *CHResumeCallHandlingArg) MarshalDER() ([]byte, error) {
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
		enc_obcsmcameltdpcriterialist, err := MarshalDERMSOBcsmCamelTDPCriteriaList(v.OBcsmCamelTDPCriteriaList)
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
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
		children = append(children, ext...)
	}
	encoded := ber.EncodeSequence(children)
	if err := ber.ValidateDERElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding CHResumeCallHandlingArg as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes CHResumeCallHandlingArg from BER/DER format.
func (v *CHResumeCallHandlingArg) UnmarshalBER(data []byte) error {
	*v = CHResumeCallHandlingArg{}
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding CHResumeCallHandlingArg SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "CHResumeCallHandlingArg", Cause: ber.ErrExtraData}
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
				tmp_callreferencenumber := CHCallReferenceNumber(rawVal_callreferencenumber)
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
				var dec_basicservicegroup CommonDataTypesExtBasicServiceCode
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
				var dec_forwardingdata CHForwardingData
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
				tmp_imsi := CommonDataTypesIMSI(rawVal_imsi)
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
				var dec_cugcheckinfo CHCUGCheckInfo
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
				var dec_ocsi MSOCSI
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
				var dec_extensioncontainer ExtensionDataTypesExtensionContainer
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
				tmp_msisdn := CommonDataTypesISDNAddressString(rawVal_msisdn)
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
				var dec_uudata CHUUData
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
				var dec_dcsi MSDCSI
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
				dec_obcsmcameltdpcriterialist, unmErr := UnmarshalBERMSOBcsmCamelTDPCriteriaList(reconstructed_obcsmcameltdpcriterialist)
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
				var dec_basicservicegroup2 CommonDataTypesExtBasicServiceCode
				if unmErr := dec_basicservicegroup2.UnmarshalBER(innerData_basicservicegroup2); unmErr != nil {
					return fmt.Errorf("decoding basicServiceGroup2: %w", unmErr)
				}
				v.BasicServiceGroup2 = &dec_basicservicegroup2
				offset += n_basicservicegroup2
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "CHResumeCallHandlingArg", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes CHUUData to BER format.
func (v *CHUUData) MarshalBER() ([]byte, error) {
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

// MarshalDER encodes CHUUData to DER format.
func (v *CHUUData) MarshalDER() ([]byte, error) {
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
		return nil, fmt.Errorf("encoding CHUUData as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes CHUUData from BER/DER format.
func (v *CHUUData) UnmarshalBER(data []byte) error {
	*v = CHUUData{}
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding CHUUData SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "CHUUData", Cause: ber.ErrExtraData}
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
				tmp_uuindicator := CHUUIndicator(rawVal_uuindicator)
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
				tmp_uui := CHUUI(rawVal_uui)
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
				var dec_extensioncontainer ExtensionDataTypesExtensionContainer
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
			return &ber.DecodeError{Offset: offset, TypeName: "CHUUData", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes CHResumeCallHandlingRes to BER format.
func (v *CHResumeCallHandlingRes) MarshalBER() ([]byte, error) {
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

// MarshalDER encodes CHResumeCallHandlingRes to DER format.
func (v *CHResumeCallHandlingRes) MarshalDER() ([]byte, error) {
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
		return nil, fmt.Errorf("encoding CHResumeCallHandlingRes as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes CHResumeCallHandlingRes from BER/DER format.
func (v *CHResumeCallHandlingRes) UnmarshalBER(data []byte) error {
	*v = CHResumeCallHandlingRes{}
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding CHResumeCallHandlingRes SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "CHResumeCallHandlingRes", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode extensionContainer
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassUniversal && peekTag.Number == 16 {
				// Decode nested SEQUENCE (ExtensionDataTypesExtensionContainer)
				_, n_extensioncontainer, _, tlvErr_extensioncontainer := ber.DecodeTLV(content[offset:])
				if tlvErr_extensioncontainer != nil {
					return fmt.Errorf("decoding extensionContainer: %w", tlvErr_extensioncontainer)
				}
				var dec_extensioncontainer ExtensionDataTypesExtensionContainer
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
			return &ber.DecodeError{Offset: offset, TypeName: "CHResumeCallHandlingRes", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes CHCamelInfo to BER format.
func (v *CHCamelInfo) MarshalBER() ([]byte, error) {
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

// MarshalDER encodes CHCamelInfo to DER format.
func (v *CHCamelInfo) MarshalDER() ([]byte, error) {
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
		return nil, fmt.Errorf("encoding CHCamelInfo as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes CHCamelInfo from BER/DER format.
func (v *CHCamelInfo) UnmarshalBER(data []byte) error {
	*v = CHCamelInfo{}
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding CHCamelInfo SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "CHCamelInfo", Cause: ber.ErrExtraData}
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
				// Decode nested SEQUENCE (ExtensionDataTypesExtensionContainer)
				_, n_extensioncontainer, _, tlvErr_extensioncontainer := ber.DecodeTLV(content[offset:])
				if tlvErr_extensioncontainer != nil {
					return fmt.Errorf("decoding extensionContainer: %w", tlvErr_extensioncontainer)
				}
				var dec_extensioncontainer ExtensionDataTypesExtensionContainer
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
			return &ber.DecodeError{Offset: offset, TypeName: "CHCamelInfo", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes CHExtendedRoutingInfo to BER format.
func (v *CHExtendedRoutingInfo) MarshalBER() ([]byte, error) {
	switch v.Choice {
	case CHExtendedRoutingInfoChoiceRoutingInfo:
		if v.RoutingInfo == nil {
			return nil, fmt.Errorf("choice CHExtendedRoutingInfo: routingInfo is nil")
		}
		enc_0, err := v.RoutingInfo.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding routingInfo: %w", err)
		}
		return enc_0, nil
	case CHExtendedRoutingInfoChoiceCamelRoutingInfo:
		if v.CamelRoutingInfo == nil {
			return nil, fmt.Errorf("choice CHExtendedRoutingInfo: camelRoutingInfo is nil")
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
		return nil, fmt.Errorf("unknown choice %d for CHExtendedRoutingInfo", v.Choice)
	}
}

// MarshalDER encodes CHExtendedRoutingInfo to DER format.
func (v *CHExtendedRoutingInfo) MarshalDER() ([]byte, error) {
	switch v.Choice {
	case CHExtendedRoutingInfoChoiceRoutingInfo:
		if v.RoutingInfo == nil {
			return nil, fmt.Errorf("choice CHExtendedRoutingInfo: routingInfo is nil")
		}
		enc_der_0, err := v.RoutingInfo.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding routingInfo: %w", err)
		}
		if derErr := ber.ValidateDERElement(enc_der_0); derErr != nil {
			return nil, fmt.Errorf("encoding routingInfo as DER: %w", derErr)
		}
		return enc_der_0, nil
	case CHExtendedRoutingInfoChoiceCamelRoutingInfo:
		if v.CamelRoutingInfo == nil {
			return nil, fmt.Errorf("choice CHExtendedRoutingInfo: camelRoutingInfo is nil")
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
		return nil, fmt.Errorf("encoding CHExtendedRoutingInfo as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes CHExtendedRoutingInfo from BER/DER format.
func (v *CHExtendedRoutingInfo) UnmarshalBER(data []byte) error {
	*v = CHExtendedRoutingInfo{}
	if len(data) == 0 {
		return fmt.Errorf("empty data for CHExtendedRoutingInfo CHOICE")
	}
	choiceData := data
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for CHExtendedRoutingInfo: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData)
	if tlvErr != nil {
		return fmt.Errorf("decoding CHExtendedRoutingInfo CHOICE: %w", tlvErr)
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "CHExtendedRoutingInfo", Cause: ber.ErrExtraData}
	}

	if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 8 && peekTag.Constructed == true {
		v.Choice = CHExtendedRoutingInfoChoiceCamelRoutingInfo
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding camelRoutingInfo: %w", tlvErr)
		}
		reconstructed := ber.EncodeSequence(rawVal)
		var dec CHCamelRoutingInfo
		if unmErr := dec.UnmarshalBER(reconstructed); unmErr != nil {
			return fmt.Errorf("decoding camelRoutingInfo: %w", unmErr)
		}
		v.CamelRoutingInfo = &dec
	} else {
		v.Choice = CHExtendedRoutingInfoChoiceRoutingInfo
		var dec CHRoutingInfo
		if unmErr := dec.UnmarshalBER(choiceData); unmErr != nil {
			return fmt.Errorf("decoding routingInfo: %w", unmErr)
		}
		v.RoutingInfo = &dec
	}
	return nil
}

// MarshalBER encodes CHCamelRoutingInfo to BER format.
func (v *CHCamelRoutingInfo) MarshalBER() ([]byte, error) {
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

// MarshalDER encodes CHCamelRoutingInfo to DER format.
func (v *CHCamelRoutingInfo) MarshalDER() ([]byte, error) {
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
		return nil, fmt.Errorf("encoding CHCamelRoutingInfo as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes CHCamelRoutingInfo from BER/DER format.
func (v *CHCamelRoutingInfo) UnmarshalBER(data []byte) error {
	*v = CHCamelRoutingInfo{}
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding CHCamelRoutingInfo SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "CHCamelRoutingInfo", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode forwardingData
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassUniversal && peekTag.Number == 16 {
				// Decode nested SEQUENCE (CHForwardingData)
				_, n_forwardingdata, _, tlvErr_forwardingdata := ber.DecodeTLV(content[offset:])
				if tlvErr_forwardingdata != nil {
					return fmt.Errorf("decoding forwardingData: %w", tlvErr_forwardingdata)
				}
				var dec_forwardingdata CHForwardingData
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
				var dec_extensioncontainer ExtensionDataTypesExtensionContainer
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
			return &ber.DecodeError{Offset: offset, TypeName: "CHCamelRoutingInfo", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes CHGmscCamelSubscriptionInfo to BER format.
func (v *CHGmscCamelSubscriptionInfo) MarshalBER() ([]byte, error) {
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
		enc_obcsmcameltdpcriterialist, err := MarshalBERMSOBcsmCamelTDPCriteriaList(v.OBcsmCamelTDPCriteriaList)
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
		enc_tbcsmcameltdpcriterialist, err := MarshalBERMSTBCSMCAMELTDPCriteriaList(v.TBCSMCAMELTDPCriteriaList)
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

// MarshalDER encodes CHGmscCamelSubscriptionInfo to DER format.
func (v *CHGmscCamelSubscriptionInfo) MarshalDER() ([]byte, error) {
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
		enc_obcsmcameltdpcriterialist, err := MarshalDERMSOBcsmCamelTDPCriteriaList(v.OBcsmCamelTDPCriteriaList)
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
		enc_tbcsmcameltdpcriterialist, err := MarshalDERMSTBCSMCAMELTDPCriteriaList(v.TBCSMCAMELTDPCriteriaList)
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
		return nil, fmt.Errorf("encoding CHGmscCamelSubscriptionInfo as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes CHGmscCamelSubscriptionInfo from BER/DER format.
func (v *CHGmscCamelSubscriptionInfo) UnmarshalBER(data []byte) error {
	*v = CHGmscCamelSubscriptionInfo{}
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding CHGmscCamelSubscriptionInfo SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "CHGmscCamelSubscriptionInfo", Cause: ber.ErrExtraData}
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
				var dec_tcsi MSTCSI
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
				var dec_ocsi MSOCSI
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
				var dec_extensioncontainer ExtensionDataTypesExtensionContainer
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
				dec_obcsmcameltdpcriterialist, unmErr := UnmarshalBERMSOBcsmCamelTDPCriteriaList(reconstructed_obcsmcameltdpcriterialist)
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
				dec_tbcsmcameltdpcriterialist, unmErr := UnmarshalBERMSTBCSMCAMELTDPCriteriaList(reconstructed_tbcsmcameltdpcriterialist)
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
				var dec_dcsi MSDCSI
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
			return &ber.DecodeError{Offset: offset, TypeName: "CHGmscCamelSubscriptionInfo", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes CHSetReportingStateArg to BER format.
func (v *CHSetReportingStateArg) MarshalBER() ([]byte, error) {
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

// MarshalDER encodes CHSetReportingStateArg to DER format.
func (v *CHSetReportingStateArg) MarshalDER() ([]byte, error) {
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
		return nil, fmt.Errorf("encoding CHSetReportingStateArg as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes CHSetReportingStateArg from BER/DER format.
func (v *CHSetReportingStateArg) UnmarshalBER(data []byte) error {
	*v = CHSetReportingStateArg{}
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding CHSetReportingStateArg SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "CHSetReportingStateArg", Cause: ber.ErrExtraData}
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
				tmp_imsi := CommonDataTypesIMSI(rawVal_imsi)
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
				tmp_lmsi := CommonDataTypesLMSI(rawVal_lmsi)
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
				tmp_ccbsmonitoring := CHReportingState(decVal_ccbsmonitoring)
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
				var dec_extensioncontainer ExtensionDataTypesExtensionContainer
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
			return &ber.DecodeError{Offset: offset, TypeName: "CHSetReportingStateArg", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes CHSetReportingStateRes to BER format.
func (v *CHSetReportingStateRes) MarshalBER() ([]byte, error) {
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

// MarshalDER encodes CHSetReportingStateRes to DER format.
func (v *CHSetReportingStateRes) MarshalDER() ([]byte, error) {
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
		return nil, fmt.Errorf("encoding CHSetReportingStateRes as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes CHSetReportingStateRes from BER/DER format.
func (v *CHSetReportingStateRes) UnmarshalBER(data []byte) error {
	*v = CHSetReportingStateRes{}
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding CHSetReportingStateRes SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "CHSetReportingStateRes", Cause: ber.ErrExtraData}
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
				tmp_ccbssubscriberstatus := CHCCBSSubscriberStatus(decVal_ccbssubscriberstatus)
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
				var dec_extensioncontainer ExtensionDataTypesExtensionContainer
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
			return &ber.DecodeError{Offset: offset, TypeName: "CHSetReportingStateRes", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes CHStatusReportArg to BER format.
func (v *CHStatusReportArg) MarshalBER() ([]byte, error) {
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

// MarshalDER encodes CHStatusReportArg to DER format.
func (v *CHStatusReportArg) MarshalDER() ([]byte, error) {
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
		return nil, fmt.Errorf("encoding CHStatusReportArg as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes CHStatusReportArg from BER/DER format.
func (v *CHStatusReportArg) UnmarshalBER(data []byte) error {
	*v = CHStatusReportArg{}
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding CHStatusReportArg SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "CHStatusReportArg", Cause: ber.ErrExtraData}
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
	v.Imsi = CommonDataTypesIMSI(rawVal_imsi)
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
				var dec_eventreportdata CHEventReportData
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
				var dec_callreportdata CHCallReportData
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
				var dec_extensioncontainer ExtensionDataTypesExtensionContainer
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
			return &ber.DecodeError{Offset: offset, TypeName: "CHStatusReportArg", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes CHEventReportData to BER format.
func (v *CHEventReportData) MarshalBER() ([]byte, error) {
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

// MarshalDER encodes CHEventReportData to DER format.
func (v *CHEventReportData) MarshalDER() ([]byte, error) {
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
		return nil, fmt.Errorf("encoding CHEventReportData as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes CHEventReportData from BER/DER format.
func (v *CHEventReportData) UnmarshalBER(data []byte) error {
	*v = CHEventReportData{}
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding CHEventReportData SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "CHEventReportData", Cause: ber.ErrExtraData}
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
				tmp_ccbssubscriberstatus := CHCCBSSubscriberStatus(decVal_ccbssubscriberstatus)
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
				var dec_extensioncontainer ExtensionDataTypesExtensionContainer
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
			return &ber.DecodeError{Offset: offset, TypeName: "CHEventReportData", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes CHCallReportData to BER format.
func (v *CHCallReportData) MarshalBER() ([]byte, error) {
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

// MarshalDER encodes CHCallReportData to DER format.
func (v *CHCallReportData) MarshalDER() ([]byte, error) {
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
		return nil, fmt.Errorf("encoding CHCallReportData as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes CHCallReportData from BER/DER format.
func (v *CHCallReportData) UnmarshalBER(data []byte) error {
	*v = CHCallReportData{}
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding CHCallReportData SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "CHCallReportData", Cause: ber.ErrExtraData}
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
				tmp_monitoringmode := CHMonitoringMode(decVal_monitoringmode)
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
				tmp_calloutcome := CHCallOutcome(decVal_calloutcome)
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
				var dec_extensioncontainer ExtensionDataTypesExtensionContainer
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
			return &ber.DecodeError{Offset: offset, TypeName: "CHCallReportData", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes CHStatusReportRes to BER format.
func (v *CHStatusReportRes) MarshalBER() ([]byte, error) {
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

// MarshalDER encodes CHStatusReportRes to DER format.
func (v *CHStatusReportRes) MarshalDER() ([]byte, error) {
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
		return nil, fmt.Errorf("encoding CHStatusReportRes as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes CHStatusReportRes from BER/DER format.
func (v *CHStatusReportRes) UnmarshalBER(data []byte) error {
	*v = CHStatusReportRes{}
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding CHStatusReportRes SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "CHStatusReportRes", Cause: ber.ErrExtraData}
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
				var dec_extensioncontainer ExtensionDataTypesExtensionContainer
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
			return &ber.DecodeError{Offset: offset, TypeName: "CHStatusReportRes", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes CHRemoteUserFreeArg to BER format.
func (v *CHRemoteUserFreeArg) MarshalBER() ([]byte, error) {
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

// MarshalDER encodes CHRemoteUserFreeArg to DER format.
func (v *CHRemoteUserFreeArg) MarshalDER() ([]byte, error) {
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
		return nil, fmt.Errorf("encoding CHRemoteUserFreeArg as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes CHRemoteUserFreeArg from BER/DER format.
func (v *CHRemoteUserFreeArg) UnmarshalBER(data []byte) error {
	*v = CHRemoteUserFreeArg{}
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding CHRemoteUserFreeArg SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "CHRemoteUserFreeArg", Cause: ber.ErrExtraData}
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
	v.Imsi = CommonDataTypesIMSI(rawVal_imsi)
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
	v.TranslatedBNumber = CommonDataTypesISDNAddressString(rawVal_translatedbnumber)
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
				tmp_alertingpattern := CommonDataTypesAlertingPattern(rawVal_alertingpattern)
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
				var dec_extensioncontainer ExtensionDataTypesExtensionContainer
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
			return &ber.DecodeError{Offset: offset, TypeName: "CHRemoteUserFreeArg", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes CHRemoteUserFreeRes to BER format.
func (v *CHRemoteUserFreeRes) MarshalBER() ([]byte, error) {
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

// MarshalDER encodes CHRemoteUserFreeRes to DER format.
func (v *CHRemoteUserFreeRes) MarshalDER() ([]byte, error) {
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
		return nil, fmt.Errorf("encoding CHRemoteUserFreeRes as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes CHRemoteUserFreeRes from BER/DER format.
func (v *CHRemoteUserFreeRes) UnmarshalBER(data []byte) error {
	*v = CHRemoteUserFreeRes{}
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding CHRemoteUserFreeRes SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "CHRemoteUserFreeRes", Cause: ber.ErrExtraData}
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
	v.RufOutcome = CHRUFOutcome(decVal_rufoutcome)
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
				var dec_extensioncontainer ExtensionDataTypesExtensionContainer
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
			return &ber.DecodeError{Offset: offset, TypeName: "CHRemoteUserFreeRes", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes CHISTAlertArg to BER format.
func (v *CHISTAlertArg) MarshalBER() ([]byte, error) {
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

// MarshalDER encodes CHISTAlertArg to DER format.
func (v *CHISTAlertArg) MarshalDER() ([]byte, error) {
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
		return nil, fmt.Errorf("encoding CHISTAlertArg as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes CHISTAlertArg from BER/DER format.
func (v *CHISTAlertArg) UnmarshalBER(data []byte) error {
	*v = CHISTAlertArg{}
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding CHISTAlertArg SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "CHISTAlertArg", Cause: ber.ErrExtraData}
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
	v.Imsi = CommonDataTypesIMSI(rawVal_imsi)
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
				var dec_extensioncontainer ExtensionDataTypesExtensionContainer
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
			return &ber.DecodeError{Offset: offset, TypeName: "CHISTAlertArg", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes CHISTAlertRes to BER format.
func (v *CHISTAlertRes) MarshalBER() ([]byte, error) {
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

// MarshalDER encodes CHISTAlertRes to DER format.
func (v *CHISTAlertRes) MarshalDER() ([]byte, error) {
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
		return nil, fmt.Errorf("encoding CHISTAlertRes as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes CHISTAlertRes from BER/DER format.
func (v *CHISTAlertRes) UnmarshalBER(data []byte) error {
	*v = CHISTAlertRes{}
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding CHISTAlertRes SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "CHISTAlertRes", Cause: ber.ErrExtraData}
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
				tmp_istalerttimer := MSISTAlertTimerValue(decVal_istalerttimer)
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
				tmp_callterminationindicator := CHCallTerminationIndicator(decVal_callterminationindicator)
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
				var dec_extensioncontainer ExtensionDataTypesExtensionContainer
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
			return &ber.DecodeError{Offset: offset, TypeName: "CHISTAlertRes", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes CHISTCommandArg to BER format.
func (v *CHISTCommandArg) MarshalBER() ([]byte, error) {
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

// MarshalDER encodes CHISTCommandArg to DER format.
func (v *CHISTCommandArg) MarshalDER() ([]byte, error) {
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
		return nil, fmt.Errorf("encoding CHISTCommandArg as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes CHISTCommandArg from BER/DER format.
func (v *CHISTCommandArg) UnmarshalBER(data []byte) error {
	*v = CHISTCommandArg{}
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding CHISTCommandArg SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "CHISTCommandArg", Cause: ber.ErrExtraData}
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
	v.Imsi = CommonDataTypesIMSI(rawVal_imsi)
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
				var dec_extensioncontainer ExtensionDataTypesExtensionContainer
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
			return &ber.DecodeError{Offset: offset, TypeName: "CHISTCommandArg", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes CHISTCommandRes to BER format.
func (v *CHISTCommandRes) MarshalBER() ([]byte, error) {
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

// MarshalDER encodes CHISTCommandRes to DER format.
func (v *CHISTCommandRes) MarshalDER() ([]byte, error) {
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
		return nil, fmt.Errorf("encoding CHISTCommandRes as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes CHISTCommandRes from BER/DER format.
func (v *CHISTCommandRes) UnmarshalBER(data []byte) error {
	*v = CHISTCommandRes{}
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding CHISTCommandRes SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "CHISTCommandRes", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode extensionContainer
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassUniversal && peekTag.Number == 16 {
				// Decode nested SEQUENCE (ExtensionDataTypesExtensionContainer)
				_, n_extensioncontainer, _, tlvErr_extensioncontainer := ber.DecodeTLV(content[offset:])
				if tlvErr_extensioncontainer != nil {
					return fmt.Errorf("decoding extensionContainer: %w", tlvErr_extensioncontainer)
				}
				var dec_extensioncontainer ExtensionDataTypesExtensionContainer
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
			return &ber.DecodeError{Offset: offset, TypeName: "CHISTCommandRes", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes CHReleaseResourcesArg to BER format.
func (v *CHReleaseResourcesArg) MarshalBER() ([]byte, error) {
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

// MarshalDER encodes CHReleaseResourcesArg to DER format.
func (v *CHReleaseResourcesArg) MarshalDER() ([]byte, error) {
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
		return nil, fmt.Errorf("encoding CHReleaseResourcesArg as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes CHReleaseResourcesArg from BER/DER format.
func (v *CHReleaseResourcesArg) UnmarshalBER(data []byte) error {
	*v = CHReleaseResourcesArg{}
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding CHReleaseResourcesArg SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "CHReleaseResourcesArg", Cause: ber.ErrExtraData}
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
	v.Msrn = CommonDataTypesISDNAddressString(val_msrn)
	offset += n
	// Decode extensionContainer
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassUniversal && peekTag.Number == 16 {
				// Decode nested SEQUENCE (ExtensionDataTypesExtensionContainer)
				_, n_extensioncontainer, _, tlvErr_extensioncontainer := ber.DecodeTLV(content[offset:])
				if tlvErr_extensioncontainer != nil {
					return fmt.Errorf("decoding extensionContainer: %w", tlvErr_extensioncontainer)
				}
				var dec_extensioncontainer ExtensionDataTypesExtensionContainer
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
			return &ber.DecodeError{Offset: offset, TypeName: "CHReleaseResourcesArg", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes CHReleaseResourcesRes to BER format.
func (v *CHReleaseResourcesRes) MarshalBER() ([]byte, error) {
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

// MarshalDER encodes CHReleaseResourcesRes to DER format.
func (v *CHReleaseResourcesRes) MarshalDER() ([]byte, error) {
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
		return nil, fmt.Errorf("encoding CHReleaseResourcesRes as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes CHReleaseResourcesRes from BER/DER format.
func (v *CHReleaseResourcesRes) UnmarshalBER(data []byte) error {
	*v = CHReleaseResourcesRes{}
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding CHReleaseResourcesRes SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "CHReleaseResourcesRes", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode extensionContainer
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassUniversal && peekTag.Number == 16 {
				// Decode nested SEQUENCE (ExtensionDataTypesExtensionContainer)
				_, n_extensioncontainer, _, tlvErr_extensioncontainer := ber.DecodeTLV(content[offset:])
				if tlvErr_extensioncontainer != nil {
					return fmt.Errorf("decoding extensionContainer: %w", tlvErr_extensioncontainer)
				}
				var dec_extensioncontainer ExtensionDataTypesExtensionContainer
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
			return &ber.DecodeError{Offset: offset, TypeName: "CHReleaseResourcesRes", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}
