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

// CHCUGCheckInfo represents the ASN.1 type CHCUGCheckInfo (SEQUENCE).
type CHCUGCheckInfo struct {
	CugInterlock       MSCUGInterlock                        `asn1:""`
	CugOutgoingAccess  *struct{}                             `asn1:",optional" json:"CugOutgoingAccess,omitempty"`
	ExtensionContainer *ExtensionDataTypesExtensionContainer `asn1:",optional" json:"ExtensionContainer,omitempty"`
	ExtCount_          int64                                 `asn1:"-" json:"-"`
	ExtPresent_        []bool                                `asn1:"-" json:"-"`
	ExtData_           [][]byte                              `asn1:"-" json:"-"`
}

// CHNumberOfForwarding represents the ASN.1 type CHNumberOfForwarding (INTEGER).
type CHNumberOfForwarding = int64

// CHSendRoutingInfoArg represents the ASN.1 type CHSendRoutingInfoArg (SEQUENCE).
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

// CHSuppressionOfAnnouncement represents the ASN.1 type CHSuppressionOfAnnouncement (NULL).
type CHSuppressionOfAnnouncement = struct{}

// CHSuppressMTSS represents the ASN.1 type CHSuppressMTSS (BIT_STRING).
type CHSuppressMTSS = runtime.BitString

// CHInterrogationType represents the ASN.1 ENUMERATED type CHInterrogationType.
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

// CHORPhase represents the ASN.1 type CHORPhase (INTEGER).
type CHORPhase = int64

// CHCallReferenceNumber represents the ASN.1 type CHCallReferenceNumber (OCTET_STRING).
type CHCallReferenceNumber = []byte

// CHForwardingReason represents the ASN.1 ENUMERATED type CHForwardingReason.
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

// CHSupportedCCBSPhase represents the ASN.1 type CHSupportedCCBSPhase (INTEGER).
type CHSupportedCCBSPhase = int64

// CHCallDiversionTreatmentIndicator represents the ASN.1 type CHCallDiversionTreatmentIndicator (OCTET_STRING).
type CHCallDiversionTreatmentIndicator = []byte

// CHSendRoutingInfoRes represents the ASN.1 type CHSendRoutingInfoRes (SEQUENCE).
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

// CHAllowedServices represents the ASN.1 type CHAllowedServices (BIT_STRING).
type CHAllowedServices = runtime.BitString

// CHUnavailabilityCause represents the ASN.1 ENUMERATED type CHUnavailabilityCause.
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

// CHCCBSIndicators represents the ASN.1 type CHCCBSIndicators (SEQUENCE).
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

// CHRoutingInfo represents the ASN.1 CHOICE type CHRoutingInfo.
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

// CHForwardingData represents the ASN.1 type CHForwardingData (SEQUENCE).
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

// CHProvideRoamingNumberArg represents the ASN.1 type CHProvideRoamingNumberArg (SEQUENCE).
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

// CHProvideRoamingNumberRes represents the ASN.1 type CHProvideRoamingNumberRes (SEQUENCE).
type CHProvideRoamingNumberRes struct {
	RoamingNumber             CommonDataTypesISDNAddressString      `asn1:""`
	ExtensionContainer        *ExtensionDataTypesExtensionContainer `asn1:",optional" json:"ExtensionContainer,omitempty"`
	ReleaseResourcesSupported *struct{}                             `asn1:",optional" json:"ReleaseResourcesSupported,omitempty"`
	ExtCount_                 int64                                 `asn1:"-" json:"-"`
	ExtPresent_               []bool                                `asn1:"-" json:"-"`
	ExtData_                  [][]byte                              `asn1:"-" json:"-"`
}

// CHResumeCallHandlingArg represents the ASN.1 type CHResumeCallHandlingArg (SEQUENCE).
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

// CHUUData represents the ASN.1 type CHUUData (SEQUENCE).
type CHUUData struct {
	UuIndicator        *CHUUIndicator                        `asn1:"tag:0,context,implicit,optional" json:"UuIndicator,omitempty"`
	Uui                *CHUUI                                `asn1:"tag:1,context,implicit,optional" json:"Uui,omitempty"`
	UusCFInteraction   *struct{}                             `asn1:"tag:2,context,implicit,optional" json:"UusCFInteraction,omitempty"`
	ExtensionContainer *ExtensionDataTypesExtensionContainer `asn1:"tag:3,context,implicit,optional" json:"ExtensionContainer,omitempty"`
	ExtCount_          int64                                 `asn1:"-" json:"-"`
	ExtPresent_        []bool                                `asn1:"-" json:"-"`
	ExtData_           [][]byte                              `asn1:"-" json:"-"`
}

// CHUUIndicator represents the ASN.1 type CHUUIndicator (OCTET_STRING).
type CHUUIndicator = []byte

// CHUUI represents the ASN.1 type CHUUI (OCTET_STRING).
type CHUUI = []byte

// CHResumeCallHandlingRes represents the ASN.1 type CHResumeCallHandlingRes (SEQUENCE).
type CHResumeCallHandlingRes struct {
	ExtensionContainer *ExtensionDataTypesExtensionContainer `asn1:",optional" json:"ExtensionContainer,omitempty"`
	ExtCount_          int64                                 `asn1:"-" json:"-"`
	ExtPresent_        []bool                                `asn1:"-" json:"-"`
	ExtData_           [][]byte                              `asn1:"-" json:"-"`
}

// CHCamelInfo represents the ASN.1 type CHCamelInfo (SEQUENCE).
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

// CHExtendedRoutingInfo represents the ASN.1 CHOICE type CHExtendedRoutingInfo.
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

// CHCamelRoutingInfo represents the ASN.1 type CHCamelRoutingInfo (SEQUENCE).
type CHCamelRoutingInfo struct {
	ForwardingData            *CHForwardingData                     `asn1:",optional" json:"ForwardingData,omitempty"`
	GmscCamelSubscriptionInfo CHGmscCamelSubscriptionInfo           `asn1:"tag:0,context,implicit"`
	ExtensionContainer        *ExtensionDataTypesExtensionContainer `asn1:"tag:1,context,implicit,optional" json:"ExtensionContainer,omitempty"`
	ExtCount_                 int64                                 `asn1:"-" json:"-"`
	ExtPresent_               []bool                                `asn1:"-" json:"-"`
	ExtData_                  [][]byte                              `asn1:"-" json:"-"`
}

// CHGmscCamelSubscriptionInfo represents the ASN.1 type CHGmscCamelSubscriptionInfo (SEQUENCE).
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

// CHSetReportingStateArg represents the ASN.1 type CHSetReportingStateArg (SEQUENCE).
type CHSetReportingStateArg struct {
	Imsi               *CommonDataTypesIMSI                  `asn1:"tag:0,context,implicit,optional" json:"Imsi,omitempty"`
	Lmsi               *CommonDataTypesLMSI                  `asn1:"tag:1,context,implicit,optional" json:"Lmsi,omitempty"`
	CcbsMonitoring     *CHReportingState                     `asn1:"tag:2,context,implicit,optional" json:"CcbsMonitoring,omitempty"`
	ExtensionContainer *ExtensionDataTypesExtensionContainer `asn1:"tag:3,context,implicit,optional" json:"ExtensionContainer,omitempty"`
	ExtCount_          int64                                 `asn1:"-" json:"-"`
	ExtPresent_        []bool                                `asn1:"-" json:"-"`
	ExtData_           [][]byte                              `asn1:"-" json:"-"`
}

// CHReportingState represents the ASN.1 ENUMERATED type CHReportingState.
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

// CHSetReportingStateRes represents the ASN.1 type CHSetReportingStateRes (SEQUENCE).
type CHSetReportingStateRes struct {
	CcbsSubscriberStatus *CHCCBSSubscriberStatus               `asn1:"tag:0,context,implicit,optional" json:"CcbsSubscriberStatus,omitempty"`
	ExtensionContainer   *ExtensionDataTypesExtensionContainer `asn1:"tag:1,context,implicit,optional" json:"ExtensionContainer,omitempty"`
	ExtCount_            int64                                 `asn1:"-" json:"-"`
	ExtPresent_          []bool                                `asn1:"-" json:"-"`
	ExtData_             [][]byte                              `asn1:"-" json:"-"`
}

// CHCCBSSubscriberStatus represents the ASN.1 ENUMERATED type CHCCBSSubscriberStatus.
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

// CHStatusReportArg represents the ASN.1 type CHStatusReportArg (SEQUENCE).
type CHStatusReportArg struct {
	Imsi               CommonDataTypesIMSI                   `asn1:"tag:0,context,implicit"`
	EventReportData    *CHEventReportData                    `asn1:"tag:1,context,implicit,optional" json:"EventReportData,omitempty"`
	CallReportdata     *CHCallReportData                     `asn1:"tag:2,context,implicit,optional" json:"CallReportdata,omitempty"`
	ExtensionContainer *ExtensionDataTypesExtensionContainer `asn1:"tag:3,context,implicit,optional" json:"ExtensionContainer,omitempty"`
	ExtCount_          int64                                 `asn1:"-" json:"-"`
	ExtPresent_        []bool                                `asn1:"-" json:"-"`
	ExtData_           [][]byte                              `asn1:"-" json:"-"`
}

// CHEventReportData represents the ASN.1 type CHEventReportData (SEQUENCE).
type CHEventReportData struct {
	CcbsSubscriberStatus *CHCCBSSubscriberStatus               `asn1:"tag:0,context,implicit,optional" json:"CcbsSubscriberStatus,omitempty"`
	ExtensionContainer   *ExtensionDataTypesExtensionContainer `asn1:"tag:1,context,implicit,optional" json:"ExtensionContainer,omitempty"`
	ExtCount_            int64                                 `asn1:"-" json:"-"`
	ExtPresent_          []bool                                `asn1:"-" json:"-"`
	ExtData_             [][]byte                              `asn1:"-" json:"-"`
}

// CHCallReportData represents the ASN.1 type CHCallReportData (SEQUENCE).
type CHCallReportData struct {
	MonitoringMode     *CHMonitoringMode                     `asn1:"tag:0,context,implicit,optional" json:"MonitoringMode,omitempty"`
	CallOutcome        *CHCallOutcome                        `asn1:"tag:1,context,implicit,optional" json:"CallOutcome,omitempty"`
	ExtensionContainer *ExtensionDataTypesExtensionContainer `asn1:"tag:2,context,implicit,optional" json:"ExtensionContainer,omitempty"`
	ExtCount_          int64                                 `asn1:"-" json:"-"`
	ExtPresent_        []bool                                `asn1:"-" json:"-"`
	ExtData_           [][]byte                              `asn1:"-" json:"-"`
}

// CHMonitoringMode represents the ASN.1 ENUMERATED type CHMonitoringMode.
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

// CHCallOutcome represents the ASN.1 ENUMERATED type CHCallOutcome.
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

// CHStatusReportRes represents the ASN.1 type CHStatusReportRes (SEQUENCE).
type CHStatusReportRes struct {
	ExtensionContainer *ExtensionDataTypesExtensionContainer `asn1:"tag:0,context,implicit,optional" json:"ExtensionContainer,omitempty"`
	ExtCount_          int64                                 `asn1:"-" json:"-"`
	ExtPresent_        []bool                                `asn1:"-" json:"-"`
	ExtData_           [][]byte                              `asn1:"-" json:"-"`
}

// CHRemoteUserFreeArg represents the ASN.1 type CHRemoteUserFreeArg (SEQUENCE).
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

// CHRemoteUserFreeRes represents the ASN.1 type CHRemoteUserFreeRes (SEQUENCE).
type CHRemoteUserFreeRes struct {
	RufOutcome         CHRUFOutcome                          `asn1:"tag:0,context,implicit"`
	ExtensionContainer *ExtensionDataTypesExtensionContainer `asn1:"tag:1,context,implicit,optional" json:"ExtensionContainer,omitempty"`
	ExtCount_          int64                                 `asn1:"-" json:"-"`
	ExtPresent_        []bool                                `asn1:"-" json:"-"`
	ExtData_           [][]byte                              `asn1:"-" json:"-"`
}

// CHRUFOutcome represents the ASN.1 ENUMERATED type CHRUFOutcome.
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

// CHISTAlertArg represents the ASN.1 type CHISTAlertArg (SEQUENCE).
type CHISTAlertArg struct {
	Imsi               CommonDataTypesIMSI                   `asn1:"tag:0,context,implicit"`
	ExtensionContainer *ExtensionDataTypesExtensionContainer `asn1:"tag:1,context,implicit,optional" json:"ExtensionContainer,omitempty"`
	ExtCount_          int64                                 `asn1:"-" json:"-"`
	ExtPresent_        []bool                                `asn1:"-" json:"-"`
	ExtData_           [][]byte                              `asn1:"-" json:"-"`
}

// CHISTAlertRes represents the ASN.1 type CHISTAlertRes (SEQUENCE).
type CHISTAlertRes struct {
	IstAlertTimer            *MSISTAlertTimerValue                 `asn1:"tag:0,context,implicit,optional" json:"IstAlertTimer,omitempty"`
	IstInformationWithdraw   *struct{}                             `asn1:"tag:1,context,implicit,optional" json:"IstInformationWithdraw,omitempty"`
	CallTerminationIndicator *CHCallTerminationIndicator           `asn1:"tag:2,context,implicit,optional" json:"CallTerminationIndicator,omitempty"`
	ExtensionContainer       *ExtensionDataTypesExtensionContainer `asn1:"tag:3,context,implicit,optional" json:"ExtensionContainer,omitempty"`
	ExtCount_                int64                                 `asn1:"-" json:"-"`
	ExtPresent_              []bool                                `asn1:"-" json:"-"`
	ExtData_                 [][]byte                              `asn1:"-" json:"-"`
}

// CHISTCommandArg represents the ASN.1 type CHISTCommandArg (SEQUENCE).
type CHISTCommandArg struct {
	Imsi               CommonDataTypesIMSI                   `asn1:"tag:0,context,implicit"`
	ExtensionContainer *ExtensionDataTypesExtensionContainer `asn1:"tag:1,context,implicit,optional" json:"ExtensionContainer,omitempty"`
	ExtCount_          int64                                 `asn1:"-" json:"-"`
	ExtPresent_        []bool                                `asn1:"-" json:"-"`
	ExtData_           [][]byte                              `asn1:"-" json:"-"`
}

// CHISTCommandRes represents the ASN.1 type CHISTCommandRes (SEQUENCE).
type CHISTCommandRes struct {
	ExtensionContainer *ExtensionDataTypesExtensionContainer `asn1:",optional" json:"ExtensionContainer,omitempty"`
	ExtCount_          int64                                 `asn1:"-" json:"-"`
	ExtPresent_        []bool                                `asn1:"-" json:"-"`
	ExtData_           [][]byte                              `asn1:"-" json:"-"`
}

// CHCallTerminationIndicator represents the ASN.1 ENUMERATED type CHCallTerminationIndicator.
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

// CHReleaseResourcesArg represents the ASN.1 type CHReleaseResourcesArg (SEQUENCE).
type CHReleaseResourcesArg struct {
	Msrn               CommonDataTypesISDNAddressString      `asn1:""`
	ExtensionContainer *ExtensionDataTypesExtensionContainer `asn1:",optional" json:"ExtensionContainer,omitempty"`
	ExtCount_          int64                                 `asn1:"-" json:"-"`
	ExtPresent_        []bool                                `asn1:"-" json:"-"`
	ExtData_           [][]byte                              `asn1:"-" json:"-"`
}

// CHReleaseResourcesRes represents the ASN.1 type CHReleaseResourcesRes (SEQUENCE).
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
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes CHCUGCheckInfo from BER/DER format.
func (v *CHCUGCheckInfo) UnmarshalBER(data []byte) error {
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
	enc_msisdn = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, false, enc_msisdn)
	children = append(children, enc_msisdn...)
	if v.CugCheckInfo != nil {
		enc_cugcheckinfo, err := v.CugCheckInfo.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding cug-CheckInfo: %w", err)
		}
		enc_cugcheckinfo = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, true, enc_cugcheckinfo)
		children = append(children, enc_cugcheckinfo...)
	}
	if v.NumberOfForwarding != nil {
		enc_numberofforwarding := ber.EncodeInteger(int64(*v.NumberOfForwarding))
		enc_numberofforwarding = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, false, enc_numberofforwarding)
		children = append(children, enc_numberofforwarding...)
	}
	enc_interrogationtype := ber.EncodeEnumerated(int64(v.InterrogationType))
	enc_interrogationtype = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, false, enc_interrogationtype)
	children = append(children, enc_interrogationtype...)
	if v.OrInterrogation != nil {
		enc_orinterrogation := ber.EncodeNull()
		enc_orinterrogation = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, false, enc_orinterrogation)
		children = append(children, enc_orinterrogation...)
	}
	if v.OrCapability != nil {
		enc_orcapability := ber.EncodeInteger(int64(*v.OrCapability))
		enc_orcapability = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 5, false, enc_orcapability)
		children = append(children, enc_orcapability...)
	}
	enc_gmscorgsmscfaddress := ber.EncodeOctetString([]byte(v.GmscOrGsmSCFAddress))
	enc_gmscorgsmscfaddress = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 6, false, enc_gmscorgsmscfaddress)
	children = append(children, enc_gmscorgsmscfaddress...)
	if v.CallReferenceNumber != nil {
		enc_callreferencenumber := ber.EncodeOctetString([]byte(*v.CallReferenceNumber))
		enc_callreferencenumber = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 7, false, enc_callreferencenumber)
		children = append(children, enc_callreferencenumber...)
	}
	if v.ForwardingReason != nil {
		enc_forwardingreason := ber.EncodeEnumerated(int64(*v.ForwardingReason))
		enc_forwardingreason = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 8, false, enc_forwardingreason)
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
		enc_networksignalinfo = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 10, true, enc_networksignalinfo)
		children = append(children, enc_networksignalinfo...)
	}
	if v.CamelInfo != nil {
		enc_camelinfo, err := v.CamelInfo.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding camelInfo: %w", err)
		}
		enc_camelinfo = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 11, true, enc_camelinfo)
		children = append(children, enc_camelinfo...)
	}
	if v.SuppressionOfAnnouncement != nil {
		enc_suppressionofannouncement := ber.EncodeNull()
		enc_suppressionofannouncement = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 12, false, enc_suppressionofannouncement)
		children = append(children, enc_suppressionofannouncement...)
	}
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding extensionContainer: %w", err)
		}
		enc_extensioncontainer = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 13, true, enc_extensioncontainer)
		children = append(children, enc_extensioncontainer...)
	}
	if v.AlertingPattern != nil {
		enc_alertingpattern := ber.EncodeOctetString([]byte(*v.AlertingPattern))
		enc_alertingpattern = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 14, false, enc_alertingpattern)
		children = append(children, enc_alertingpattern...)
	}
	if v.CcbsCall != nil {
		enc_ccbscall := ber.EncodeNull()
		enc_ccbscall = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 15, false, enc_ccbscall)
		children = append(children, enc_ccbscall...)
	}
	if v.SupportedCCBSPhase != nil {
		enc_supportedccbsphase := ber.EncodeInteger(int64(*v.SupportedCCBSPhase))
		enc_supportedccbsphase = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 16, false, enc_supportedccbsphase)
		children = append(children, enc_supportedccbsphase...)
	}
	if v.AdditionalSignalInfo != nil {
		enc_additionalsignalinfo, err := v.AdditionalSignalInfo.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding additionalSignalInfo: %w", err)
		}
		enc_additionalsignalinfo = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 17, true, enc_additionalsignalinfo)
		children = append(children, enc_additionalsignalinfo...)
	}
	if v.IstSupportIndicator != nil {
		enc_istsupportindicator := ber.EncodeEnumerated(int64(*v.IstSupportIndicator))
		enc_istsupportindicator = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 18, false, enc_istsupportindicator)
		children = append(children, enc_istsupportindicator...)
	}
	if v.PrePagingSupported != nil {
		enc_prepagingsupported := ber.EncodeNull()
		enc_prepagingsupported = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 19, false, enc_prepagingsupported)
		children = append(children, enc_prepagingsupported...)
	}
	if v.CallDiversionTreatmentIndicator != nil {
		enc_calldiversiontreatmentindicator := ber.EncodeOctetString([]byte(*v.CallDiversionTreatmentIndicator))
		enc_calldiversiontreatmentindicator = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 20, false, enc_calldiversiontreatmentindicator)
		children = append(children, enc_calldiversiontreatmentindicator...)
	}
	if v.LongFTNSupported != nil {
		enc_longftnsupported := ber.EncodeNull()
		enc_longftnsupported = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 21, false, enc_longftnsupported)
		children = append(children, enc_longftnsupported...)
	}
	if v.SuppressVTCSI != nil {
		enc_suppressvtcsi := ber.EncodeNull()
		enc_suppressvtcsi = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 22, false, enc_suppressvtcsi)
		children = append(children, enc_suppressvtcsi...)
	}
	if v.SuppressIncomingCallBarring != nil {
		enc_suppressincomingcallbarring := ber.EncodeNull()
		enc_suppressincomingcallbarring = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 23, false, enc_suppressincomingcallbarring)
		children = append(children, enc_suppressincomingcallbarring...)
	}
	if v.GsmSCFInitiatedCall != nil {
		enc_gsmscfinitiatedcall := ber.EncodeNull()
		enc_gsmscfinitiatedcall = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 24, false, enc_gsmscfinitiatedcall)
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
		enc_networksignalinfo2 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 26, true, enc_networksignalinfo2)
		children = append(children, enc_networksignalinfo2...)
	}
	if v.SuppressMTSS != nil {
		enc_suppressmtss := ber.EncodeBitString(v.SuppressMTSS.Bytes, (8-(v.SuppressMTSS.BitLength%8))%8)
		enc_suppressmtss = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 27, false, enc_suppressmtss)
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
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes CHSendRoutingInfoArg from BER/DER format.
func (v *CHSendRoutingInfoArg) UnmarshalBER(data []byte) error {
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
	_, n_msisdn, rawVal_msisdn, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding msisdn: %w", err)
	}
	v.Msisdn = CommonDataTypesISDNAddressString(rawVal_msisdn)
	offset += n_msisdn
	// Decode cug-CheckInfo
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
				_, n_cugcheckinfo, rawVal_cugcheckinfo, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding cug-CheckInfo: %w", err)
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
				_, n_numberofforwarding, rawVal_numberofforwarding, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding numberOfForwarding: %w", err)
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
	_, n_interrogationtype, rawVal_interrogationtype, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding interrogationType: %w", err)
	}
	decVal_interrogationtype, intErr := ber.DecodeIntegerValue(rawVal_interrogationtype)
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
				_, n_orinterrogation, rawVal_orinterrogation, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding or-Interrogation: %w", err)
				}
				_ = rawVal_orinterrogation
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
				_, n_orcapability, rawVal_orcapability, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding or-Capability: %w", err)
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
	_, n_gmscorgsmscfaddress, rawVal_gmscorgsmscfaddress, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding gmsc-OrGsmSCF-Address: %w", err)
	}
	v.GmscOrGsmSCFAddress = CommonDataTypesISDNAddressString(rawVal_gmscorgsmscfaddress)
	offset += n_gmscorgsmscfaddress
	// Decode callReferenceNumber
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 7 {
				_, n_callreferencenumber, rawVal_callreferencenumber, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding callReferenceNumber: %w", err)
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
				_, n_forwardingreason, rawVal_forwardingreason, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding forwardingReason: %w", err)
				}
				decVal_forwardingreason, intErr := ber.DecodeIntegerValue(rawVal_forwardingreason)
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
				_, n_basicservicegroup, innerData_basicservicegroup, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding basicServiceGroup: %w", err)
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
				_, n_networksignalinfo, rawVal_networksignalinfo, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding networkSignalInfo: %w", err)
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
				_, n_camelinfo, rawVal_camelinfo, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding camelInfo: %w", err)
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
				_, n_suppressionofannouncement, rawVal_suppressionofannouncement, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding suppressionOfAnnouncement: %w", err)
				}
				_ = rawVal_suppressionofannouncement
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
				_, n_extensioncontainer, rawVal_extensioncontainer, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding extensionContainer: %w", err)
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
				_, n_alertingpattern, rawVal_alertingpattern, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding alertingPattern: %w", err)
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
				_, n_ccbscall, rawVal_ccbscall, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding ccbs-Call: %w", err)
				}
				_ = rawVal_ccbscall
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
				_, n_supportedccbsphase, rawVal_supportedccbsphase, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding supportedCCBS-Phase: %w", err)
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
				_, n_additionalsignalinfo, rawVal_additionalsignalinfo, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding additionalSignalInfo: %w", err)
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
				_, n_istsupportindicator, rawVal_istsupportindicator, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding istSupportIndicator: %w", err)
				}
				decVal_istsupportindicator, intErr := ber.DecodeIntegerValue(rawVal_istsupportindicator)
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
				_, n_prepagingsupported, rawVal_prepagingsupported, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding pre-pagingSupported: %w", err)
				}
				_ = rawVal_prepagingsupported
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
				_, n_calldiversiontreatmentindicator, rawVal_calldiversiontreatmentindicator, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding callDiversionTreatmentIndicator: %w", err)
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
				_, n_longftnsupported, rawVal_longftnsupported, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding longFTN-Supported: %w", err)
				}
				_ = rawVal_longftnsupported
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
				_, n_suppressvtcsi, rawVal_suppressvtcsi, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding suppress-VT-CSI: %w", err)
				}
				_ = rawVal_suppressvtcsi
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
				_, n_suppressincomingcallbarring, rawVal_suppressincomingcallbarring, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding suppressIncomingCallBarring: %w", err)
				}
				_ = rawVal_suppressincomingcallbarring
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
				_, n_gsmscfinitiatedcall, rawVal_gsmscfinitiatedcall, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding gsmSCF-InitiatedCall: %w", err)
				}
				_ = rawVal_gsmscfinitiatedcall
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
				_, n_basicservicegroup2, innerData_basicservicegroup2, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding basicServiceGroup2: %w", err)
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
				_, n_networksignalinfo2, rawVal_networksignalinfo2, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding networkSignalInfo2: %w", err)
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
				_, n_suppressmtss, rawVal_suppressmtss, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding suppressMTSS: %w", err)
				}
				bsBytes_suppressmtss, bsUnused_suppressmtss, bsErr := ber.DecodeBitStringValue(rawVal_suppressmtss)
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
		enc_imsi = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 9, false, enc_imsi)
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
		enc_cugcheckinfo = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, true, enc_cugcheckinfo)
		children = append(children, enc_cugcheckinfo...)
	}
	if v.CugSubscriptionFlag != nil {
		enc_cugsubscriptionflag := ber.EncodeNull()
		enc_cugsubscriptionflag = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 6, false, enc_cugsubscriptionflag)
		children = append(children, enc_cugsubscriptionflag...)
	}
	if v.SubscriberInfo != nil {
		enc_subscriberinfo, err := v.SubscriberInfo.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding subscriberInfo: %w", err)
		}
		enc_subscriberinfo = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 7, true, enc_subscriberinfo)
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
			enc_sslist = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, true, enc_sslist)
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
		enc_forwardinginterrogationrequired = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, false, enc_forwardinginterrogationrequired)
		children = append(children, enc_forwardinginterrogationrequired...)
	}
	if v.VmscAddress != nil {
		enc_vmscaddress := ber.EncodeOctetString([]byte(*v.VmscAddress))
		enc_vmscaddress = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, false, enc_vmscaddress)
		children = append(children, enc_vmscaddress...)
	}
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding extensionContainer: %w", err)
		}
		enc_extensioncontainer = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, true, enc_extensioncontainer)
		children = append(children, enc_extensioncontainer...)
	}
	if v.NaeaPreferredCI != nil {
		enc_naeapreferredci, err := v.NaeaPreferredCI.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding naea-PreferredCI: %w", err)
		}
		enc_naeapreferredci = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 10, true, enc_naeapreferredci)
		children = append(children, enc_naeapreferredci...)
	}
	if v.CcbsIndicators != nil {
		enc_ccbsindicators, err := v.CcbsIndicators.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding ccbs-Indicators: %w", err)
		}
		enc_ccbsindicators = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 11, true, enc_ccbsindicators)
		children = append(children, enc_ccbsindicators...)
	}
	if v.Msisdn != nil {
		enc_msisdn := ber.EncodeOctetString([]byte(*v.Msisdn))
		enc_msisdn = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 12, false, enc_msisdn)
		children = append(children, enc_msisdn...)
	}
	if v.NumberPortabilityStatus != nil {
		enc_numberportabilitystatus := ber.EncodeEnumerated(int64(*v.NumberPortabilityStatus))
		enc_numberportabilitystatus = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 13, false, enc_numberportabilitystatus)
		children = append(children, enc_numberportabilitystatus...)
	}
	if v.IstAlertTimer != nil {
		enc_istalerttimer := ber.EncodeInteger(int64(*v.IstAlertTimer))
		enc_istalerttimer = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 14, false, enc_istalerttimer)
		children = append(children, enc_istalerttimer...)
	}
	if v.SupportedCamelPhasesInVMSC != nil {
		enc_supportedcamelphasesinvmsc := ber.EncodeBitString(v.SupportedCamelPhasesInVMSC.Bytes, (8-(v.SupportedCamelPhasesInVMSC.BitLength%8))%8)
		enc_supportedcamelphasesinvmsc = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 15, false, enc_supportedcamelphasesinvmsc)
		children = append(children, enc_supportedcamelphasesinvmsc...)
	}
	if v.OfferedCamel4CSIsInVMSC != nil {
		enc_offeredcamel4csisinvmsc := ber.EncodeBitString(v.OfferedCamel4CSIsInVMSC.Bytes, (8-(v.OfferedCamel4CSIsInVMSC.BitLength%8))%8)
		enc_offeredcamel4csisinvmsc = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 16, false, enc_offeredcamel4csisinvmsc)
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
			enc_sslist2 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 18, true, enc_sslist2)
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
		enc_allowedservices = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 20, false, enc_allowedservices)
		children = append(children, enc_allowedservices...)
	}
	if v.UnavailabilityCause != nil {
		enc_unavailabilitycause := ber.EncodeEnumerated(int64(*v.UnavailabilityCause))
		enc_unavailabilitycause = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 21, false, enc_unavailabilitycause)
		children = append(children, enc_unavailabilitycause...)
	}
	if v.ReleaseResourcesSupported != nil {
		enc_releaseresourcessupported := ber.EncodeNull()
		enc_releaseresourcessupported = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 22, false, enc_releaseresourcessupported)
		children = append(children, enc_releaseresourcessupported...)
	}
	if v.GsmBearerCapability != nil {
		enc_gsmbearercapability, err := v.GsmBearerCapability.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding gsm-BearerCapability: %w", err)
		}
		enc_gsmbearercapability = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 23, true, enc_gsmbearercapability)
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
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// ITU-T X.690 (02/2021) Section 10.1 requires DER length forms to be definite.
	derValue := *v
	derValue.SsListIndef_ = false
	derValue.SsList2Indef_ = false
	v = &derValue
	return v.MarshalBER()
}

// UnmarshalBER decodes CHSendRoutingInfoRes from BER/DER format.
func (v *CHSendRoutingInfoRes) UnmarshalBER(data []byte) error {
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
				_, n_imsi, rawVal_imsi, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding imsi: %w", err)
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
				_, n_cugcheckinfo, rawVal_cugcheckinfo, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding cug-CheckInfo: %w", err)
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
				_, n_cugsubscriptionflag, rawVal_cugsubscriptionflag, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding cugSubscriptionFlag: %w", err)
				}
				_ = rawVal_cugsubscriptionflag
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
				_, n_subscriberinfo, rawVal_subscriberinfo, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding subscriberInfo: %w", err)
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
				_, n_sslist, rawVal_sslist, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding ss-List: %w", err)
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
				_, n_basicservice, innerData_basicservice, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding basicService: %w", err)
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
				_, n_forwardinginterrogationrequired, rawVal_forwardinginterrogationrequired, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding forwardingInterrogationRequired: %w", err)
				}
				_ = rawVal_forwardinginterrogationrequired
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
				_, n_vmscaddress, rawVal_vmscaddress, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding vmsc-Address: %w", err)
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
				_, n_extensioncontainer, rawVal_extensioncontainer, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding extensionContainer: %w", err)
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
				_, n_naeapreferredci, rawVal_naeapreferredci, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding naea-PreferredCI: %w", err)
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
				_, n_ccbsindicators, rawVal_ccbsindicators, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding ccbs-Indicators: %w", err)
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
				_, n_msisdn, rawVal_msisdn, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding msisdn: %w", err)
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
				_, n_numberportabilitystatus, rawVal_numberportabilitystatus, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding numberPortabilityStatus: %w", err)
				}
				decVal_numberportabilitystatus, intErr := ber.DecodeIntegerValue(rawVal_numberportabilitystatus)
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
				_, n_istalerttimer, rawVal_istalerttimer, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding istAlertTimer: %w", err)
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
				_, n_supportedcamelphasesinvmsc, rawVal_supportedcamelphasesinvmsc, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding supportedCamelPhasesInVMSC: %w", err)
				}
				bsBytes_supportedcamelphasesinvmsc, bsUnused_supportedcamelphasesinvmsc, bsErr := ber.DecodeBitStringValue(rawVal_supportedcamelphasesinvmsc)
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
				_, n_offeredcamel4csisinvmsc, rawVal_offeredcamel4csisinvmsc, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding offeredCamel4CSIsInVMSC: %w", err)
				}
				bsBytes_offeredcamel4csisinvmsc, bsUnused_offeredcamel4csisinvmsc, bsErr := ber.DecodeBitStringValue(rawVal_offeredcamel4csisinvmsc)
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
				_, n_routinginfo2, innerData_routinginfo2, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding routingInfo2: %w", err)
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
				_, n_sslist2, rawVal_sslist2, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding ss-List2: %w", err)
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
				_, n_basicservice2, innerData_basicservice2, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding basicService2: %w", err)
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
				_, n_allowedservices, rawVal_allowedservices, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding allowedServices: %w", err)
				}
				bsBytes_allowedservices, bsUnused_allowedservices, bsErr := ber.DecodeBitStringValue(rawVal_allowedservices)
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
				_, n_unavailabilitycause, rawVal_unavailabilitycause, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding unavailabilityCause: %w", err)
				}
				decVal_unavailabilitycause, intErr := ber.DecodeIntegerValue(rawVal_unavailabilitycause)
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
				_, n_releaseresourcessupported, rawVal_releaseresourcessupported, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding releaseResourcesSupported: %w", err)
				}
				_ = rawVal_releaseresourcessupported
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
				_, n_gsmbearercapability, rawVal_gsmbearercapability, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding gsm-BearerCapability: %w", err)
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
		enc_ccbspossible = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, false, enc_ccbspossible)
		children = append(children, enc_ccbspossible...)
	}
	if v.KeepCCBSCallIndicator != nil {
		enc_keepccbscallindicator := ber.EncodeNull()
		enc_keepccbscallindicator = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, false, enc_keepccbscallindicator)
		children = append(children, enc_keepccbscallindicator...)
	}
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding extensionContainer: %w", err)
		}
		enc_extensioncontainer = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, true, enc_extensioncontainer)
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
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes CHCCBSIndicators from BER/DER format.
func (v *CHCCBSIndicators) UnmarshalBER(data []byte) error {
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
				_, n_ccbspossible, rawVal_ccbspossible, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding ccbs-Possible: %w", err)
				}
				_ = rawVal_ccbspossible
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
				_, n_keepccbscallindicator, rawVal_keepccbscallindicator, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding keepCCBS-CallIndicator: %w", err)
				}
				_ = rawVal_keepccbscallindicator
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
				_, n_extensioncontainer, rawVal_extensioncontainer, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding extensionContainer: %w", err)
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
		return enc_der_1, nil
	}
	return v.MarshalBER()
}

// UnmarshalBER decodes CHRoutingInfo from BER/DER format.
func (v *CHRoutingInfo) UnmarshalBER(data []byte) error {
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
	} else if peekTag.Class == tag.ClassUniversal && peekTag.Number == 16 {
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
		enc_forwardedtonumber = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 5, false, enc_forwardedtonumber)
		children = append(children, enc_forwardedtonumber...)
	}
	if v.ForwardedToSubaddress != nil {
		enc_forwardedtosubaddress := ber.EncodeOctetString([]byte(*v.ForwardedToSubaddress))
		enc_forwardedtosubaddress = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, false, enc_forwardedtosubaddress)
		children = append(children, enc_forwardedtosubaddress...)
	}
	if v.ForwardingOptions != nil {
		enc_forwardingoptions := ber.EncodeOctetString([]byte(*v.ForwardingOptions))
		enc_forwardingoptions = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 6, false, enc_forwardingoptions)
		children = append(children, enc_forwardingoptions...)
	}
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding extensionContainer: %w", err)
		}
		enc_extensioncontainer = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 7, true, enc_extensioncontainer)
		children = append(children, enc_extensioncontainer...)
	}
	if v.LongForwardedToNumber != nil {
		enc_longforwardedtonumber := ber.EncodeOctetString([]byte(*v.LongForwardedToNumber))
		enc_longforwardedtonumber = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 8, false, enc_longforwardedtonumber)
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
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes CHForwardingData from BER/DER format.
func (v *CHForwardingData) UnmarshalBER(data []byte) error {
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
				_, n_forwardedtonumber, rawVal_forwardedtonumber, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding forwardedToNumber: %w", err)
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
				_, n_forwardedtosubaddress, rawVal_forwardedtosubaddress, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding forwardedToSubaddress: %w", err)
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
				_, n_forwardingoptions, rawVal_forwardingoptions, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding forwardingOptions: %w", err)
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
				_, n_extensioncontainer, rawVal_extensioncontainer, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding extensionContainer: %w", err)
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
				_, n_longforwardedtonumber, rawVal_longforwardedtonumber, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding longForwardedToNumber: %w", err)
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
	enc_imsi = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, false, enc_imsi)
	children = append(children, enc_imsi...)
	enc_mscnumber := ber.EncodeOctetString([]byte(v.MscNumber))
	enc_mscnumber = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, false, enc_mscnumber)
	children = append(children, enc_mscnumber...)
	if v.Msisdn != nil {
		enc_msisdn := ber.EncodeOctetString([]byte(*v.Msisdn))
		enc_msisdn = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, false, enc_msisdn)
		children = append(children, enc_msisdn...)
	}
	if v.Lmsi != nil {
		enc_lmsi := ber.EncodeOctetString([]byte(*v.Lmsi))
		enc_lmsi = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, false, enc_lmsi)
		children = append(children, enc_lmsi...)
	}
	if v.GsmBearerCapability != nil {
		enc_gsmbearercapability, err := v.GsmBearerCapability.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding gsm-BearerCapability: %w", err)
		}
		enc_gsmbearercapability = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 5, true, enc_gsmbearercapability)
		children = append(children, enc_gsmbearercapability...)
	}
	if v.NetworkSignalInfo != nil {
		enc_networksignalinfo, err := v.NetworkSignalInfo.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding networkSignalInfo: %w", err)
		}
		enc_networksignalinfo = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 6, true, enc_networksignalinfo)
		children = append(children, enc_networksignalinfo...)
	}
	if v.SuppressionOfAnnouncement != nil {
		enc_suppressionofannouncement := ber.EncodeNull()
		enc_suppressionofannouncement = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 7, false, enc_suppressionofannouncement)
		children = append(children, enc_suppressionofannouncement...)
	}
	if v.GmscAddress != nil {
		enc_gmscaddress := ber.EncodeOctetString([]byte(*v.GmscAddress))
		enc_gmscaddress = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 8, false, enc_gmscaddress)
		children = append(children, enc_gmscaddress...)
	}
	if v.CallReferenceNumber != nil {
		enc_callreferencenumber := ber.EncodeOctetString([]byte(*v.CallReferenceNumber))
		enc_callreferencenumber = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 9, false, enc_callreferencenumber)
		children = append(children, enc_callreferencenumber...)
	}
	if v.OrInterrogation != nil {
		enc_orinterrogation := ber.EncodeNull()
		enc_orinterrogation = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 10, false, enc_orinterrogation)
		children = append(children, enc_orinterrogation...)
	}
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding extensionContainer: %w", err)
		}
		enc_extensioncontainer = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 11, true, enc_extensioncontainer)
		children = append(children, enc_extensioncontainer...)
	}
	if v.AlertingPattern != nil {
		enc_alertingpattern := ber.EncodeOctetString([]byte(*v.AlertingPattern))
		enc_alertingpattern = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 12, false, enc_alertingpattern)
		children = append(children, enc_alertingpattern...)
	}
	if v.CcbsCall != nil {
		enc_ccbscall := ber.EncodeNull()
		enc_ccbscall = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 13, false, enc_ccbscall)
		children = append(children, enc_ccbscall...)
	}
	if v.SupportedCamelPhasesInInterrogatingNode != nil {
		enc_supportedcamelphasesininterrogatingnode := ber.EncodeBitString(v.SupportedCamelPhasesInInterrogatingNode.Bytes, (8-(v.SupportedCamelPhasesInInterrogatingNode.BitLength%8))%8)
		enc_supportedcamelphasesininterrogatingnode = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 15, false, enc_supportedcamelphasesininterrogatingnode)
		children = append(children, enc_supportedcamelphasesininterrogatingnode...)
	}
	if v.AdditionalSignalInfo != nil {
		enc_additionalsignalinfo, err := v.AdditionalSignalInfo.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding additionalSignalInfo: %w", err)
		}
		enc_additionalsignalinfo = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 14, true, enc_additionalsignalinfo)
		children = append(children, enc_additionalsignalinfo...)
	}
	if v.OrNotSupportedInGMSC != nil {
		enc_ornotsupportedingmsc := ber.EncodeNull()
		enc_ornotsupportedingmsc = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 16, false, enc_ornotsupportedingmsc)
		children = append(children, enc_ornotsupportedingmsc...)
	}
	if v.PrePagingSupported != nil {
		enc_prepagingsupported := ber.EncodeNull()
		enc_prepagingsupported = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 17, false, enc_prepagingsupported)
		children = append(children, enc_prepagingsupported...)
	}
	if v.LongFTNSupported != nil {
		enc_longftnsupported := ber.EncodeNull()
		enc_longftnsupported = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 18, false, enc_longftnsupported)
		children = append(children, enc_longftnsupported...)
	}
	if v.SuppressVTCSI != nil {
		enc_suppressvtcsi := ber.EncodeNull()
		enc_suppressvtcsi = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 19, false, enc_suppressvtcsi)
		children = append(children, enc_suppressvtcsi...)
	}
	if v.OfferedCamel4CSIsInInterrogatingNode != nil {
		enc_offeredcamel4csisininterrogatingnode := ber.EncodeBitString(v.OfferedCamel4CSIsInInterrogatingNode.Bytes, (8-(v.OfferedCamel4CSIsInInterrogatingNode.BitLength%8))%8)
		enc_offeredcamel4csisininterrogatingnode = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 20, false, enc_offeredcamel4csisininterrogatingnode)
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
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes CHProvideRoamingNumberArg from BER/DER format.
func (v *CHProvideRoamingNumberArg) UnmarshalBER(data []byte) error {
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
	_, n_imsi, rawVal_imsi, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding imsi: %w", err)
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
	_, n_mscnumber, rawVal_mscnumber, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding msc-Number: %w", err)
	}
	v.MscNumber = CommonDataTypesISDNAddressString(rawVal_mscnumber)
	offset += n_mscnumber
	// Decode msisdn
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2 {
				_, n_msisdn, rawVal_msisdn, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding msisdn: %w", err)
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
				_, n_lmsi, rawVal_lmsi, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding lmsi: %w", err)
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
				_, n_gsmbearercapability, rawVal_gsmbearercapability, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding gsm-BearerCapability: %w", err)
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
				_, n_networksignalinfo, rawVal_networksignalinfo, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding networkSignalInfo: %w", err)
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
				_, n_suppressionofannouncement, rawVal_suppressionofannouncement, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding suppressionOfAnnouncement: %w", err)
				}
				_ = rawVal_suppressionofannouncement
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
				_, n_gmscaddress, rawVal_gmscaddress, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding gmsc-Address: %w", err)
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
				_, n_callreferencenumber, rawVal_callreferencenumber, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding callReferenceNumber: %w", err)
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
				_, n_orinterrogation, rawVal_orinterrogation, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding or-Interrogation: %w", err)
				}
				_ = rawVal_orinterrogation
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
				_, n_extensioncontainer, rawVal_extensioncontainer, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding extensionContainer: %w", err)
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
				_, n_alertingpattern, rawVal_alertingpattern, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding alertingPattern: %w", err)
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
				_, n_ccbscall, rawVal_ccbscall, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding ccbs-Call: %w", err)
				}
				_ = rawVal_ccbscall
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
				_, n_supportedcamelphasesininterrogatingnode, rawVal_supportedcamelphasesininterrogatingnode, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding supportedCamelPhasesInInterrogatingNode: %w", err)
				}
				bsBytes_supportedcamelphasesininterrogatingnode, bsUnused_supportedcamelphasesininterrogatingnode, bsErr := ber.DecodeBitStringValue(rawVal_supportedcamelphasesininterrogatingnode)
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
				_, n_additionalsignalinfo, rawVal_additionalsignalinfo, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding additionalSignalInfo: %w", err)
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
				_, n_ornotsupportedingmsc, rawVal_ornotsupportedingmsc, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding orNotSupportedInGMSC: %w", err)
				}
				_ = rawVal_ornotsupportedingmsc
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
				_, n_prepagingsupported, rawVal_prepagingsupported, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding pre-pagingSupported: %w", err)
				}
				_ = rawVal_prepagingsupported
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
				_, n_longftnsupported, rawVal_longftnsupported, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding longFTN-Supported: %w", err)
				}
				_ = rawVal_longftnsupported
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
				_, n_suppressvtcsi, rawVal_suppressvtcsi, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding suppress-VT-CSI: %w", err)
				}
				_ = rawVal_suppressvtcsi
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
				_, n_offeredcamel4csisininterrogatingnode, rawVal_offeredcamel4csisininterrogatingnode, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding offeredCamel4CSIsInInterrogatingNode: %w", err)
				}
				bsBytes_offeredcamel4csisininterrogatingnode, bsUnused_offeredcamel4csisininterrogatingnode, bsErr := ber.DecodeBitStringValue(rawVal_offeredcamel4csisininterrogatingnode)
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
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes CHProvideRoamingNumberRes from BER/DER format.
func (v *CHProvideRoamingNumberRes) UnmarshalBER(data []byte) error {
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
		enc_callreferencenumber = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, false, enc_callreferencenumber)
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
		enc_forwardingdata = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, true, enc_forwardingdata)
		children = append(children, enc_forwardingdata...)
	}
	if v.Imsi != nil {
		enc_imsi := ber.EncodeOctetString([]byte(*v.Imsi))
		enc_imsi = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, false, enc_imsi)
		children = append(children, enc_imsi...)
	}
	if v.CugCheckInfo != nil {
		enc_cugcheckinfo, err := v.CugCheckInfo.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding cug-CheckInfo: %w", err)
		}
		enc_cugcheckinfo = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, true, enc_cugcheckinfo)
		children = append(children, enc_cugcheckinfo...)
	}
	if v.OCSI != nil {
		enc_ocsi, err := v.OCSI.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding o-CSI: %w", err)
		}
		enc_ocsi = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 5, true, enc_ocsi)
		children = append(children, enc_ocsi...)
	}
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding extensionContainer: %w", err)
		}
		enc_extensioncontainer = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 7, true, enc_extensioncontainer)
		children = append(children, enc_extensioncontainer...)
	}
	if v.CcbsPossible != nil {
		enc_ccbspossible := ber.EncodeNull()
		enc_ccbspossible = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 8, false, enc_ccbspossible)
		children = append(children, enc_ccbspossible...)
	}
	if v.Msisdn != nil {
		enc_msisdn := ber.EncodeOctetString([]byte(*v.Msisdn))
		enc_msisdn = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 9, false, enc_msisdn)
		children = append(children, enc_msisdn...)
	}
	if v.UuData != nil {
		enc_uudata, err := v.UuData.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding uu-Data: %w", err)
		}
		enc_uudata = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 10, true, enc_uudata)
		children = append(children, enc_uudata...)
	}
	if v.AllInformationSent != nil {
		enc_allinformationsent := ber.EncodeNull()
		enc_allinformationsent = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 11, false, enc_allinformationsent)
		children = append(children, enc_allinformationsent...)
	}
	if v.DCsi != nil {
		enc_dcsi, err := v.DCsi.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding d-csi: %w", err)
		}
		enc_dcsi = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 12, true, enc_dcsi)
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
			enc_obcsmcameltdpcriterialist = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 13, true, enc_obcsmcameltdpcriterialist)
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
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// ITU-T X.690 (02/2021) Section 10.1 requires DER length forms to be definite.
	derValue := *v
	derValue.OBcsmCamelTDPCriteriaListIndef_ = false
	v = &derValue
	return v.MarshalBER()
}

// UnmarshalBER decodes CHResumeCallHandlingArg from BER/DER format.
func (v *CHResumeCallHandlingArg) UnmarshalBER(data []byte) error {
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
				_, n_callreferencenumber, rawVal_callreferencenumber, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding callReferenceNumber: %w", err)
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
				_, n_basicservicegroup, innerData_basicservicegroup, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding basicServiceGroup: %w", err)
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
				_, n_forwardingdata, rawVal_forwardingdata, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding forwardingData: %w", err)
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
				_, n_imsi, rawVal_imsi, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding imsi: %w", err)
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
				_, n_cugcheckinfo, rawVal_cugcheckinfo, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding cug-CheckInfo: %w", err)
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
				_, n_ocsi, rawVal_ocsi, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding o-CSI: %w", err)
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
				_, n_extensioncontainer, rawVal_extensioncontainer, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding extensionContainer: %w", err)
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
				_, n_ccbspossible, rawVal_ccbspossible, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding ccbs-Possible: %w", err)
				}
				_ = rawVal_ccbspossible
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
				_, n_msisdn, rawVal_msisdn, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding msisdn: %w", err)
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
				_, n_uudata, rawVal_uudata, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding uu-Data: %w", err)
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
				_, n_allinformationsent, rawVal_allinformationsent, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding allInformationSent: %w", err)
				}
				_ = rawVal_allinformationsent
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
				_, n_dcsi, rawVal_dcsi, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding d-csi: %w", err)
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
				_, n_obcsmcameltdpcriterialist, rawVal_obcsmcameltdpcriterialist, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding o-BcsmCamelTDPCriteriaList: %w", err)
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
				_, n_basicservicegroup2, innerData_basicservicegroup2, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding basicServiceGroup2: %w", err)
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
		enc_uuindicator = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, false, enc_uuindicator)
		children = append(children, enc_uuindicator...)
	}
	if v.Uui != nil {
		enc_uui := ber.EncodeOctetString([]byte(*v.Uui))
		enc_uui = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, false, enc_uui)
		children = append(children, enc_uui...)
	}
	if v.UusCFInteraction != nil {
		enc_uuscfinteraction := ber.EncodeNull()
		enc_uuscfinteraction = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, false, enc_uuscfinteraction)
		children = append(children, enc_uuscfinteraction...)
	}
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding extensionContainer: %w", err)
		}
		enc_extensioncontainer = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, true, enc_extensioncontainer)
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
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes CHUUData from BER/DER format.
func (v *CHUUData) UnmarshalBER(data []byte) error {
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
				_, n_uuindicator, rawVal_uuindicator, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding uuIndicator: %w", err)
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
				_, n_uui, rawVal_uui, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding uui: %w", err)
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
				_, n_uuscfinteraction, rawVal_uuscfinteraction, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding uusCFInteraction: %w", err)
				}
				_ = rawVal_uuscfinteraction
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
				_, n_extensioncontainer, rawVal_extensioncontainer, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding extensionContainer: %w", err)
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
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes CHResumeCallHandlingRes from BER/DER format.
func (v *CHResumeCallHandlingRes) UnmarshalBER(data []byte) error {
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
		enc_offeredcamel4csis = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, false, enc_offeredcamel4csis)
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
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes CHCamelInfo from BER/DER format.
func (v *CHCamelInfo) UnmarshalBER(data []byte) error {
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
				_, n_offeredcamel4csis, rawVal_offeredcamel4csis, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding offeredCamel4CSIs: %w", err)
				}
				bsBytes_offeredcamel4csis, bsUnused_offeredcamel4csis, bsErr := ber.DecodeBitStringValue(rawVal_offeredcamel4csis)
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
		enc_1 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 8, true, enc_1)
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
		return enc_der_0, nil
	case CHExtendedRoutingInfoChoiceCamelRoutingInfo:
		if v.CamelRoutingInfo == nil {
			return nil, fmt.Errorf("choice CHExtendedRoutingInfo: camelRoutingInfo is nil")
		}
		enc_der_1, err := v.CamelRoutingInfo.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding camelRoutingInfo: %w", err)
		}
		enc_der_1 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 8, true, enc_der_1)
		return enc_der_1, nil
	}
	return v.MarshalBER()
}

// UnmarshalBER decodes CHExtendedRoutingInfo from BER/DER format.
func (v *CHExtendedRoutingInfo) UnmarshalBER(data []byte) error {
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

	if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 8 {
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
	enc_gmsccamelsubscriptioninfo = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, true, enc_gmsccamelsubscriptioninfo)
	children = append(children, enc_gmsccamelsubscriptioninfo...)
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding extensionContainer: %w", err)
		}
		enc_extensioncontainer = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, true, enc_extensioncontainer)
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
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes CHCamelRoutingInfo from BER/DER format.
func (v *CHCamelRoutingInfo) UnmarshalBER(data []byte) error {
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
	_, n_gmsccamelsubscriptioninfo, rawVal_gmsccamelsubscriptioninfo, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding gmscCamelSubscriptionInfo: %w", err)
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
				_, n_extensioncontainer, rawVal_extensioncontainer, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding extensionContainer: %w", err)
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
		enc_tcsi = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, true, enc_tcsi)
		children = append(children, enc_tcsi...)
	}
	if v.OCSI != nil {
		enc_ocsi, err := v.OCSI.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding o-CSI: %w", err)
		}
		enc_ocsi = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, true, enc_ocsi)
		children = append(children, enc_ocsi...)
	}
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding extensionContainer: %w", err)
		}
		enc_extensioncontainer = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, true, enc_extensioncontainer)
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
			enc_obcsmcameltdpcriterialist = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, true, enc_obcsmcameltdpcriterialist)
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
			enc_tbcsmcameltdpcriterialist = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, true, enc_tbcsmcameltdpcriterialist)
		}
		children = append(children, enc_tbcsmcameltdpcriterialist...)
	}
	if v.DCsi != nil {
		enc_dcsi, err := v.DCsi.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding d-csi: %w", err)
		}
		enc_dcsi = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 5, true, enc_dcsi)
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
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// ITU-T X.690 (02/2021) Section 10.1 requires DER length forms to be definite.
	derValue := *v
	derValue.OBcsmCamelTDPCriteriaListIndef_ = false
	derValue.TBCSMCAMELTDPCriteriaListIndef_ = false
	v = &derValue
	return v.MarshalBER()
}

// UnmarshalBER decodes CHGmscCamelSubscriptionInfo from BER/DER format.
func (v *CHGmscCamelSubscriptionInfo) UnmarshalBER(data []byte) error {
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
				_, n_tcsi, rawVal_tcsi, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding t-CSI: %w", err)
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
				_, n_ocsi, rawVal_ocsi, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding o-CSI: %w", err)
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
				_, n_extensioncontainer, rawVal_extensioncontainer, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding extensionContainer: %w", err)
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
				_, n_obcsmcameltdpcriterialist, rawVal_obcsmcameltdpcriterialist, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding o-BcsmCamelTDP-CriteriaList: %w", err)
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
				_, n_tbcsmcameltdpcriterialist, rawVal_tbcsmcameltdpcriterialist, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding t-BCSM-CAMEL-TDP-CriteriaList: %w", err)
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
				_, n_dcsi, rawVal_dcsi, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding d-csi: %w", err)
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
		enc_imsi = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, false, enc_imsi)
		children = append(children, enc_imsi...)
	}
	if v.Lmsi != nil {
		enc_lmsi := ber.EncodeOctetString([]byte(*v.Lmsi))
		enc_lmsi = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, false, enc_lmsi)
		children = append(children, enc_lmsi...)
	}
	if v.CcbsMonitoring != nil {
		enc_ccbsmonitoring := ber.EncodeEnumerated(int64(*v.CcbsMonitoring))
		enc_ccbsmonitoring = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, false, enc_ccbsmonitoring)
		children = append(children, enc_ccbsmonitoring...)
	}
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding extensionContainer: %w", err)
		}
		enc_extensioncontainer = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, true, enc_extensioncontainer)
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
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes CHSetReportingStateArg from BER/DER format.
func (v *CHSetReportingStateArg) UnmarshalBER(data []byte) error {
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
				_, n_imsi, rawVal_imsi, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding imsi: %w", err)
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
				_, n_lmsi, rawVal_lmsi, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding lmsi: %w", err)
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
				_, n_ccbsmonitoring, rawVal_ccbsmonitoring, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding ccbs-Monitoring: %w", err)
				}
				decVal_ccbsmonitoring, intErr := ber.DecodeIntegerValue(rawVal_ccbsmonitoring)
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
				_, n_extensioncontainer, rawVal_extensioncontainer, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding extensionContainer: %w", err)
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
		enc_ccbssubscriberstatus = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, false, enc_ccbssubscriberstatus)
		children = append(children, enc_ccbssubscriberstatus...)
	}
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding extensionContainer: %w", err)
		}
		enc_extensioncontainer = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, true, enc_extensioncontainer)
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
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes CHSetReportingStateRes from BER/DER format.
func (v *CHSetReportingStateRes) UnmarshalBER(data []byte) error {
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
				_, n_ccbssubscriberstatus, rawVal_ccbssubscriberstatus, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding ccbs-SubscriberStatus: %w", err)
				}
				decVal_ccbssubscriberstatus, intErr := ber.DecodeIntegerValue(rawVal_ccbssubscriberstatus)
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
				_, n_extensioncontainer, rawVal_extensioncontainer, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding extensionContainer: %w", err)
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
	enc_imsi = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, false, enc_imsi)
	children = append(children, enc_imsi...)
	if v.EventReportData != nil {
		enc_eventreportdata, err := v.EventReportData.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding eventReportData: %w", err)
		}
		enc_eventreportdata = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, true, enc_eventreportdata)
		children = append(children, enc_eventreportdata...)
	}
	if v.CallReportdata != nil {
		enc_callreportdata, err := v.CallReportdata.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding callReportdata: %w", err)
		}
		enc_callreportdata = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, true, enc_callreportdata)
		children = append(children, enc_callreportdata...)
	}
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding extensionContainer: %w", err)
		}
		enc_extensioncontainer = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, true, enc_extensioncontainer)
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
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes CHStatusReportArg from BER/DER format.
func (v *CHStatusReportArg) UnmarshalBER(data []byte) error {
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
	_, n_imsi, rawVal_imsi, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding imsi: %w", err)
	}
	v.Imsi = CommonDataTypesIMSI(rawVal_imsi)
	offset += n_imsi
	// Decode eventReportData
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
				_, n_eventreportdata, rawVal_eventreportdata, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding eventReportData: %w", err)
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
				_, n_callreportdata, rawVal_callreportdata, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding callReportdata: %w", err)
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
				_, n_extensioncontainer, rawVal_extensioncontainer, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding extensionContainer: %w", err)
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
		enc_ccbssubscriberstatus = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, false, enc_ccbssubscriberstatus)
		children = append(children, enc_ccbssubscriberstatus...)
	}
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding extensionContainer: %w", err)
		}
		enc_extensioncontainer = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, true, enc_extensioncontainer)
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
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes CHEventReportData from BER/DER format.
func (v *CHEventReportData) UnmarshalBER(data []byte) error {
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
				_, n_ccbssubscriberstatus, rawVal_ccbssubscriberstatus, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding ccbs-SubscriberStatus: %w", err)
				}
				decVal_ccbssubscriberstatus, intErr := ber.DecodeIntegerValue(rawVal_ccbssubscriberstatus)
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
				_, n_extensioncontainer, rawVal_extensioncontainer, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding extensionContainer: %w", err)
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
		enc_monitoringmode = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, false, enc_monitoringmode)
		children = append(children, enc_monitoringmode...)
	}
	if v.CallOutcome != nil {
		enc_calloutcome := ber.EncodeEnumerated(int64(*v.CallOutcome))
		enc_calloutcome = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, false, enc_calloutcome)
		children = append(children, enc_calloutcome...)
	}
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding extensionContainer: %w", err)
		}
		enc_extensioncontainer = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, true, enc_extensioncontainer)
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
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes CHCallReportData from BER/DER format.
func (v *CHCallReportData) UnmarshalBER(data []byte) error {
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
				_, n_monitoringmode, rawVal_monitoringmode, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding monitoringMode: %w", err)
				}
				decVal_monitoringmode, intErr := ber.DecodeIntegerValue(rawVal_monitoringmode)
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
				_, n_calloutcome, rawVal_calloutcome, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding callOutcome: %w", err)
				}
				decVal_calloutcome, intErr := ber.DecodeIntegerValue(rawVal_calloutcome)
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
				_, n_extensioncontainer, rawVal_extensioncontainer, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding extensionContainer: %w", err)
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
		enc_extensioncontainer = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, true, enc_extensioncontainer)
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
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes CHStatusReportRes from BER/DER format.
func (v *CHStatusReportRes) UnmarshalBER(data []byte) error {
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
				_, n_extensioncontainer, rawVal_extensioncontainer, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding extensionContainer: %w", err)
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
	enc_imsi = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, false, enc_imsi)
	children = append(children, enc_imsi...)
	enc_callinfo, err := v.CallInfo.MarshalBER()
	if err != nil {
		return nil, fmt.Errorf("encoding callInfo: %w", err)
	}
	enc_callinfo = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, true, enc_callinfo)
	children = append(children, enc_callinfo...)
	enc_ccbsfeature, err := v.CcbsFeature.MarshalBER()
	if err != nil {
		return nil, fmt.Errorf("encoding ccbs-Feature: %w", err)
	}
	enc_ccbsfeature = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, true, enc_ccbsfeature)
	children = append(children, enc_ccbsfeature...)
	enc_translatedbnumber := ber.EncodeOctetString([]byte(v.TranslatedBNumber))
	enc_translatedbnumber = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, false, enc_translatedbnumber)
	children = append(children, enc_translatedbnumber...)
	if v.ReplaceBNumber != nil {
		enc_replacebnumber := ber.EncodeNull()
		enc_replacebnumber = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, false, enc_replacebnumber)
		children = append(children, enc_replacebnumber...)
	}
	if v.AlertingPattern != nil {
		enc_alertingpattern := ber.EncodeOctetString([]byte(*v.AlertingPattern))
		enc_alertingpattern = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 5, false, enc_alertingpattern)
		children = append(children, enc_alertingpattern...)
	}
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding extensionContainer: %w", err)
		}
		enc_extensioncontainer = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 6, true, enc_extensioncontainer)
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
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes CHRemoteUserFreeArg from BER/DER format.
func (v *CHRemoteUserFreeArg) UnmarshalBER(data []byte) error {
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
	_, n_imsi, rawVal_imsi, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding imsi: %w", err)
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
	_, n_callinfo, rawVal_callinfo, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding callInfo: %w", err)
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
	_, n_ccbsfeature, rawVal_ccbsfeature, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding ccbs-Feature: %w", err)
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
	_, n_translatedbnumber, rawVal_translatedbnumber, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding translatedB-Number: %w", err)
	}
	v.TranslatedBNumber = CommonDataTypesISDNAddressString(rawVal_translatedbnumber)
	offset += n_translatedbnumber
	// Decode replaceB-Number
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4 {
				_, n_replacebnumber, rawVal_replacebnumber, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding replaceB-Number: %w", err)
				}
				_ = rawVal_replacebnumber
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
				_, n_alertingpattern, rawVal_alertingpattern, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding alertingPattern: %w", err)
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
				_, n_extensioncontainer, rawVal_extensioncontainer, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding extensionContainer: %w", err)
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
	enc_rufoutcome = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, false, enc_rufoutcome)
	children = append(children, enc_rufoutcome...)
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding extensionContainer: %w", err)
		}
		enc_extensioncontainer = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, true, enc_extensioncontainer)
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
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes CHRemoteUserFreeRes from BER/DER format.
func (v *CHRemoteUserFreeRes) UnmarshalBER(data []byte) error {
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
	_, n_rufoutcome, rawVal_rufoutcome, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding ruf-Outcome: %w", err)
	}
	decVal_rufoutcome, intErr := ber.DecodeIntegerValue(rawVal_rufoutcome)
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
				_, n_extensioncontainer, rawVal_extensioncontainer, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding extensionContainer: %w", err)
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
	enc_imsi = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, false, enc_imsi)
	children = append(children, enc_imsi...)
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding extensionContainer: %w", err)
		}
		enc_extensioncontainer = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, true, enc_extensioncontainer)
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
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes CHISTAlertArg from BER/DER format.
func (v *CHISTAlertArg) UnmarshalBER(data []byte) error {
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
	_, n_imsi, rawVal_imsi, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding imsi: %w", err)
	}
	v.Imsi = CommonDataTypesIMSI(rawVal_imsi)
	offset += n_imsi
	// Decode extensionContainer
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
				_, n_extensioncontainer, rawVal_extensioncontainer, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding extensionContainer: %w", err)
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
		enc_istalerttimer = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, false, enc_istalerttimer)
		children = append(children, enc_istalerttimer...)
	}
	if v.IstInformationWithdraw != nil {
		enc_istinformationwithdraw := ber.EncodeNull()
		enc_istinformationwithdraw = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, false, enc_istinformationwithdraw)
		children = append(children, enc_istinformationwithdraw...)
	}
	if v.CallTerminationIndicator != nil {
		enc_callterminationindicator := ber.EncodeEnumerated(int64(*v.CallTerminationIndicator))
		enc_callterminationindicator = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, false, enc_callterminationindicator)
		children = append(children, enc_callterminationindicator...)
	}
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding extensionContainer: %w", err)
		}
		enc_extensioncontainer = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, true, enc_extensioncontainer)
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
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes CHISTAlertRes from BER/DER format.
func (v *CHISTAlertRes) UnmarshalBER(data []byte) error {
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
				_, n_istalerttimer, rawVal_istalerttimer, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding istAlertTimer: %w", err)
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
				_, n_istinformationwithdraw, rawVal_istinformationwithdraw, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding istInformationWithdraw: %w", err)
				}
				_ = rawVal_istinformationwithdraw
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
				_, n_callterminationindicator, rawVal_callterminationindicator, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding callTerminationIndicator: %w", err)
				}
				decVal_callterminationindicator, intErr := ber.DecodeIntegerValue(rawVal_callterminationindicator)
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
				_, n_extensioncontainer, rawVal_extensioncontainer, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding extensionContainer: %w", err)
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
	enc_imsi = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, false, enc_imsi)
	children = append(children, enc_imsi...)
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding extensionContainer: %w", err)
		}
		enc_extensioncontainer = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, true, enc_extensioncontainer)
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
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes CHISTCommandArg from BER/DER format.
func (v *CHISTCommandArg) UnmarshalBER(data []byte) error {
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
	_, n_imsi, rawVal_imsi, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding imsi: %w", err)
	}
	v.Imsi = CommonDataTypesIMSI(rawVal_imsi)
	offset += n_imsi
	// Decode extensionContainer
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
				_, n_extensioncontainer, rawVal_extensioncontainer, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding extensionContainer: %w", err)
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
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes CHISTCommandRes from BER/DER format.
func (v *CHISTCommandRes) UnmarshalBER(data []byte) error {
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
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes CHReleaseResourcesArg from BER/DER format.
func (v *CHReleaseResourcesArg) UnmarshalBER(data []byte) error {
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
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes CHReleaseResourcesRes from BER/DER format.
func (v *CHReleaseResourcesRes) UnmarshalBER(data []byte) error {
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
