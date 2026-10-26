// Code generated from ASN.1 module "MAP-SM-DataTypes". DO NOT EDIT.

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

const (

	// MaxNumOfSMServingNodeAddresses is the integer constant for maxNumOfSMServingNodeAddresses.
	MaxNumOfSMServingNodeAddresses int64 = 5

	// MaxNumOfDispatchers is the integer constant for maxNumOfDispatchers.
	MaxNumOfDispatchers int64 = 5

	// MaxNumOfAdditionalDispatchers is the integer constant for maxNumOfAdditionalDispatchers.
	MaxNumOfAdditionalDispatchers int64 = 15
)

// RoutingInfoForSMArg represents the ASN.1 type RoutingInfoForSM-Arg (SEQUENCE).
type RoutingInfoForSMArg struct {
	Msisdn                  ISDNAddressString      `asn1:"tag:0,context,implicit"`
	SmRPPRI                 bool                   `asn1:"tag:1,context,implicit"`
	berSmRPPRIRaw_          byte                   `asn1:"-" json:"-"`
	ServiceCentreAddress    AddressString          `asn1:"tag:2,context,implicit"`
	ExtensionContainer      *ExtensionContainer    `asn1:"tag:6,context,implicit,optional" json:"ExtensionContainer,omitempty"`
	GprsSupportIndicator    *struct{}              `asn1:"tag:7,context,implicit,optional" json:"GprsSupportIndicator,omitempty"`
	SmRPMTI                 *SMRPMTI               `asn1:"tag:8,context,implicit,optional" json:"SmRPMTI,omitempty"`
	SmRPSMEA                *SMRPSMEA              `asn1:"tag:9,context,implicit,optional" json:"SmRPSMEA,omitempty"`
	SmDeliveryNotIntended   *SMDeliveryNotIntended `asn1:"tag:10,context,implicit,optional" json:"SmDeliveryNotIntended,omitempty"`
	IpSmGwGuidanceIndicator *struct{}              `asn1:"tag:11,context,implicit,optional" json:"IpSmGwGuidanceIndicator,omitempty"`
	Imsi                    *IMSI                  `asn1:"tag:12,context,implicit,optional" json:"Imsi,omitempty"`
	T4TriggerIndicator      *struct{}              `asn1:"tag:14,context,implicit,optional" json:"T4TriggerIndicator,omitempty"`
	SingleAttemptDelivery   *struct{}              `asn1:"tag:13,context,implicit,optional" json:"SingleAttemptDelivery,omitempty"`
	CorrelationID           *CorrelationID         `asn1:"tag:15,context,implicit,optional" json:"CorrelationID,omitempty"`
	SmsfSupportIndicator    *struct{}              `asn1:"tag:16,context,implicit,optional" json:"SmsfSupportIndicator,omitempty"`
	ExtCount_               int64                  `asn1:"-" json:"-"`
	ExtPresent_             []bool                 `asn1:"-" json:"-"`
	// ExtData_ retains complete unknown addition TLVs in received order. Fresh
	// BER and DER copy admissible elements without inferring a foreign schema.
	ExtData_       [][]byte        `asn1:"-" json:"-"`
	berReplayNode_ *ber.ReplayNode `asn1:"-" json:"-"`
}

// SMDeliveryNotIntended represents the ASN.1 ENUMERATED type SM-DeliveryNotIntended.
type SMDeliveryNotIntended int64

const (
	SMDeliveryNotIntendedOnlyIMSIRequested   SMDeliveryNotIntended = 0
	SMDeliveryNotIntendedOnlyMCCMNCRequested SMDeliveryNotIntended = 1
)

// String returns the ASN.1 named label, or "unknown" for an unlisted value.
func (v SMDeliveryNotIntended) String() string {
	switch v {
	case SMDeliveryNotIntendedOnlyIMSIRequested:
		return "onlyIMSI-requested"
	case SMDeliveryNotIntendedOnlyMCCMNCRequested:
		return "onlyMCC-MNC-requested"
	default:
		return "unknown"
	}
}

// SMRPMTI represents the ASN.1 type SM-RP-MTI (INTEGER).
type SMRPMTI = int64

// SMRPSMEA represents the ASN.1 type SM-RP-SMEA (OCTET_STRING).
type SMRPSMEA = []byte

// RoutingInfoForSMRes represents the ASN.1 type RoutingInfoForSM-Res (SEQUENCE).
type RoutingInfoForSMRes struct {
	Imsi                 IMSI                 `asn1:""`
	LocationInfoWithLMSI LocationInfoWithLMSI `asn1:"tag:0,context,implicit"`
	ExtensionContainer   *ExtensionContainer  `asn1:"tag:4,context,implicit,optional" json:"ExtensionContainer,omitempty"`
	IpSmGwGuidance       *IPSMGWGuidance      `asn1:"tag:5,context,implicit,optional" json:"IpSmGwGuidance,omitempty"`
	ExtCount_            int64                `asn1:"-" json:"-"`
	ExtPresent_          []bool               `asn1:"-" json:"-"`
	// ExtData_ retains complete unknown addition TLVs in received order. Fresh
	// BER and DER copy admissible elements without inferring a foreign schema.
	ExtData_       [][]byte        `asn1:"-" json:"-"`
	berReplayNode_ *ber.ReplayNode `asn1:"-" json:"-"`
}

// IPSMGWGuidance represents the ASN.1 type IP-SM-GW-Guidance (SEQUENCE).
type IPSMGWGuidance struct {
	MinimumDeliveryTimeValue     SMDeliveryTimerValue `asn1:""`
	RecommendedDeliveryTimeValue SMDeliveryTimerValue `asn1:""`
	ExtensionContainer           *ExtensionContainer  `asn1:",optional" json:"ExtensionContainer,omitempty"`
	ExtCount_                    int64                `asn1:"-" json:"-"`
	ExtPresent_                  []bool               `asn1:"-" json:"-"`
	// ExtData_ retains complete unknown addition TLVs in received order. Fresh
	// BER and DER copy admissible elements without inferring a foreign schema.
	ExtData_       [][]byte        `asn1:"-" json:"-"`
	berReplayNode_ *ber.ReplayNode `asn1:"-" json:"-"`
}

// LocationInfoWithLMSI represents the ASN.1 type LocationInfoWithLMSI (SEQUENCE).
type LocationInfoWithLMSI struct {
	NetworkNodeNumber                    ISDNAddressString           `asn1:"tag:1,context,implicit"`
	Lmsi                                 *LMSI                       `asn1:",optional" json:"Lmsi,omitempty"`
	ExtensionContainer                   *ExtensionContainer         `asn1:",optional" json:"ExtensionContainer,omitempty"`
	GprsNodeIndicator                    *struct{}                   `asn1:"tag:5,context,implicit,optional" json:"GprsNodeIndicator,omitempty"`
	AdditionalNumber                     *AdditionalNumber           `asn1:"tag:6,context,explicit,optional" json:"AdditionalNumber,omitempty"`
	NetworkNodeDiameterAddress           *NetworkNodeDiameterAddress `asn1:"tag:7,context,implicit,optional" json:"NetworkNodeDiameterAddress,omitempty"`
	AdditionalNetworkNodeDiameterAddress *NetworkNodeDiameterAddress `asn1:"tag:8,context,implicit,optional" json:"AdditionalNetworkNodeDiameterAddress,omitempty"`
	ThirdNumber                          *AdditionalNumber           `asn1:"tag:9,context,explicit,optional" json:"ThirdNumber,omitempty"`
	ThirdNetworkNodeDiameterAddress      *NetworkNodeDiameterAddress `asn1:"tag:10,context,implicit,optional" json:"ThirdNetworkNodeDiameterAddress,omitempty"`
	ImsNodeIndicator                     *struct{}                   `asn1:"tag:11,context,implicit,optional" json:"ImsNodeIndicator,omitempty"`
	Smsf3gppNumber                       *ISDNAddressString          `asn1:"tag:12,context,implicit,optional" json:"Smsf3gppNumber,omitempty"`
	Smsf3gppDiameterAddress              *NetworkNodeDiameterAddress `asn1:"tag:13,context,implicit,optional" json:"Smsf3gppDiameterAddress,omitempty"`
	SmsfNon3gppNumber                    *ISDNAddressString          `asn1:"tag:14,context,implicit,optional" json:"SmsfNon3gppNumber,omitempty"`
	SmsfNon3gppDiameterAddress           *NetworkNodeDiameterAddress `asn1:"tag:15,context,implicit,optional" json:"SmsfNon3gppDiameterAddress,omitempty"`
	Smsf3gppAddressIndicator             *struct{}                   `asn1:"tag:16,context,implicit,optional" json:"Smsf3gppAddressIndicator,omitempty"`
	SmsfNon3gppAddressIndicator          *struct{}                   `asn1:"tag:17,context,implicit,optional" json:"SmsfNon3gppAddressIndicator,omitempty"`
	ExtCount_                            int64                       `asn1:"-" json:"-"`
	ExtPresent_                          []bool                      `asn1:"-" json:"-"`
	// ExtData_ retains complete unknown addition TLVs in received order. Fresh
	// BER and DER copy admissible elements without inferring a foreign schema.
	ExtData_       [][]byte        `asn1:"-" json:"-"`
	berReplayNode_ *ber.ReplayNode `asn1:"-" json:"-"`
}

// AdditionalNumber choice constants.
const (
	AdditionalNumberChoiceMscNumber  = 1
	AdditionalNumberChoiceSgsnNumber = 2
)

// AdditionalNumber represents the ASN.1 CHOICE type Additional-Number.
type AdditionalNumber struct {
	Choice         int
	berReplayNode_ *ber.ReplayNode    `json:"-"`
	MscNumber      *ISDNAddressString `json:"MscNumber,omitempty"`
	SgsnNumber     *ISDNAddressString `json:"SgsnNumber,omitempty"`
}

// NewAdditionalNumberMscNumber creates a AdditionalNumber with the msc-Number alternative.
func NewAdditionalNumberMscNumber(v ISDNAddressString) AdditionalNumber {
	return AdditionalNumber{
		Choice:    AdditionalNumberChoiceMscNumber,
		MscNumber: &v,
	}
}

// NewAdditionalNumberSgsnNumber creates a AdditionalNumber with the sgsn-Number alternative.
func NewAdditionalNumberSgsnNumber(v ISDNAddressString) AdditionalNumber {
	return AdditionalNumber{
		Choice:     AdditionalNumberChoiceSgsnNumber,
		SgsnNumber: &v,
	}
}

// MOForwardSMArg represents the ASN.1 type MO-ForwardSM-Arg (SEQUENCE).
type MOForwardSMArg struct {
	SmRPDA             SMRPDA              `asn1:""`
	SmRPOA             SMRPOA              `asn1:""`
	SmRPUI             SignalInfo          `asn1:""`
	ExtensionContainer *ExtensionContainer `asn1:",optional" json:"ExtensionContainer,omitempty"`
	Imsi               *IMSI               `asn1:",optional" json:"Imsi,omitempty"`
	CorrelationID      *CorrelationID      `asn1:"tag:0,context,implicit,optional" json:"CorrelationID,omitempty"`
	SmDeliveryOutcome  *SMDeliveryOutcome  `asn1:"tag:1,context,implicit,optional" json:"SmDeliveryOutcome,omitempty"`
	ExtCount_          int64               `asn1:"-" json:"-"`
	ExtPresent_        []bool              `asn1:"-" json:"-"`
	// ExtData_ retains complete unknown addition TLVs in received order. Fresh
	// BER and DER copy admissible elements without inferring a foreign schema.
	ExtData_       [][]byte        `asn1:"-" json:"-"`
	berReplayNode_ *ber.ReplayNode `asn1:"-" json:"-"`
}

// MOForwardSMRes represents the ASN.1 type MO-ForwardSM-Res (SEQUENCE).
type MOForwardSMRes struct {
	SmRPUI             *SignalInfo         `asn1:",optional" json:"SmRPUI,omitempty"`
	ExtensionContainer *ExtensionContainer `asn1:",optional" json:"ExtensionContainer,omitempty"`
	ExtCount_          int64               `asn1:"-" json:"-"`
	ExtPresent_        []bool              `asn1:"-" json:"-"`
	// ExtData_ retains complete unknown addition TLVs in received order. Fresh
	// BER and DER copy admissible elements without inferring a foreign schema.
	ExtData_       [][]byte        `asn1:"-" json:"-"`
	berReplayNode_ *ber.ReplayNode `asn1:"-" json:"-"`
}

// MTForwardSMArg represents the ASN.1 type MT-ForwardSM-Arg (SEQUENCE).
type MTForwardSMArg struct {
	SmRPDA                    SMRPDA                      `asn1:""`
	SmRPOA                    SMRPOA                      `asn1:""`
	SmRPUI                    SignalInfo                  `asn1:""`
	MoreMessagesToSend        *struct{}                   `asn1:",optional" json:"MoreMessagesToSend,omitempty"`
	ExtensionContainer        *ExtensionContainer         `asn1:",optional" json:"ExtensionContainer,omitempty"`
	SmDeliveryTimer           *SMDeliveryTimerValue       `asn1:",optional" json:"SmDeliveryTimer,omitempty"`
	SmDeliveryStartTime       *Time                       `asn1:",optional" json:"SmDeliveryStartTime,omitempty"`
	SmsOverIPOnlyIndicator    *struct{}                   `asn1:"tag:0,context,implicit,optional" json:"SmsOverIPOnlyIndicator,omitempty"`
	CorrelationID             *CorrelationID              `asn1:"tag:1,context,implicit,optional" json:"CorrelationID,omitempty"`
	MaximumRetransmissionTime *Time                       `asn1:"tag:2,context,implicit,optional" json:"MaximumRetransmissionTime,omitempty"`
	SmsGmscAddress            *ISDNAddressString          `asn1:"tag:3,context,implicit,optional" json:"SmsGmscAddress,omitempty"`
	SmsGmscDiameterAddress    *NetworkNodeDiameterAddress `asn1:"tag:4,context,implicit,optional" json:"SmsGmscDiameterAddress,omitempty"`
	ExtCount_                 int64                       `asn1:"-" json:"-"`
	ExtPresent_               []bool                      `asn1:"-" json:"-"`
	// ExtData_ retains complete unknown addition TLVs in received order. Fresh
	// BER and DER copy admissible elements without inferring a foreign schema.
	ExtData_       [][]byte        `asn1:"-" json:"-"`
	berReplayNode_ *ber.ReplayNode `asn1:"-" json:"-"`
}

// CorrelationID represents the ASN.1 type CorrelationID (SEQUENCE).
type CorrelationID struct {
	HlrId          *HLRId          `asn1:"tag:0,context,implicit,optional" json:"HlrId,omitempty"`
	SipUriA        *SIPURI         `asn1:"tag:1,context,implicit,optional" json:"SipUriA,omitempty"`
	SipUriB        SIPURI          `asn1:"tag:2,context,implicit"`
	berReplayNode_ *ber.ReplayNode `asn1:"-" json:"-"`
}

// SIPURI represents the ASN.1 type SIP-URI (OCTET_STRING).
type SIPURI = []byte

// MTForwardSMRes represents the ASN.1 type MT-ForwardSM-Res (SEQUENCE).
type MTForwardSMRes struct {
	SmRPUI             *SignalInfo         `asn1:",optional" json:"SmRPUI,omitempty"`
	ExtensionContainer *ExtensionContainer `asn1:",optional" json:"ExtensionContainer,omitempty"`
	ExtCount_          int64               `asn1:"-" json:"-"`
	ExtPresent_        []bool              `asn1:"-" json:"-"`
	// ExtData_ retains complete unknown addition TLVs in received order. Fresh
	// BER and DER copy admissible elements without inferring a foreign schema.
	ExtData_       [][]byte        `asn1:"-" json:"-"`
	berReplayNode_ *ber.ReplayNode `asn1:"-" json:"-"`
}

// SMRPDA choice constants.
const (
	SMRPDAChoiceImsi                   = 1
	SMRPDAChoiceLmsi                   = 2
	SMRPDAChoiceServiceCentreAddressDA = 3
	SMRPDAChoiceNoSMRPDA               = 4
)

// SMRPDA represents the ASN.1 CHOICE type SM-RP-DA.
type SMRPDA struct {
	Choice                 int
	berReplayNode_         *ber.ReplayNode `json:"-"`
	Imsi                   *IMSI           `json:"Imsi,omitempty"`
	Lmsi                   *LMSI           `json:"Lmsi,omitempty"`
	ServiceCentreAddressDA *AddressString  `json:"ServiceCentreAddressDA,omitempty"`
	NoSMRPDA               *struct{}       `json:"NoSMRPDA,omitempty"`
}

// NewSMRPDAImsi creates a SMRPDA with the imsi alternative.
func NewSMRPDAImsi(v IMSI) SMRPDA {
	return SMRPDA{
		Choice: SMRPDAChoiceImsi,
		Imsi:   &v,
	}
}

// NewSMRPDALmsi creates a SMRPDA with the lmsi alternative.
func NewSMRPDALmsi(v LMSI) SMRPDA {
	return SMRPDA{
		Choice: SMRPDAChoiceLmsi,
		Lmsi:   &v,
	}
}

// NewSMRPDAServiceCentreAddressDA creates a SMRPDA with the serviceCentreAddressDA alternative.
func NewSMRPDAServiceCentreAddressDA(v AddressString) SMRPDA {
	return SMRPDA{
		Choice:                 SMRPDAChoiceServiceCentreAddressDA,
		ServiceCentreAddressDA: &v,
	}
}

// NewSMRPDANoSMRPDA creates a SMRPDA with the noSM-RP-DA alternative.
func NewSMRPDANoSMRPDA(v struct{}) SMRPDA {
	return SMRPDA{
		Choice:   SMRPDAChoiceNoSMRPDA,
		NoSMRPDA: &v,
	}
}

// SMRPOA choice constants.
const (
	SMRPOAChoiceMsisdn                 = 1
	SMRPOAChoiceServiceCentreAddressOA = 2
	SMRPOAChoiceNoSMRPOA               = 3
)

// SMRPOA represents the ASN.1 CHOICE type SM-RP-OA.
type SMRPOA struct {
	Choice                 int
	berReplayNode_         *ber.ReplayNode    `json:"-"`
	Msisdn                 *ISDNAddressString `json:"Msisdn,omitempty"`
	ServiceCentreAddressOA *AddressString     `json:"ServiceCentreAddressOA,omitempty"`
	NoSMRPOA               *struct{}          `json:"NoSMRPOA,omitempty"`
}

// NewSMRPOAMsisdn creates a SMRPOA with the msisdn alternative.
func NewSMRPOAMsisdn(v ISDNAddressString) SMRPOA {
	return SMRPOA{
		Choice: SMRPOAChoiceMsisdn,
		Msisdn: &v,
	}
}

// NewSMRPOAServiceCentreAddressOA creates a SMRPOA with the serviceCentreAddressOA alternative.
func NewSMRPOAServiceCentreAddressOA(v AddressString) SMRPOA {
	return SMRPOA{
		Choice:                 SMRPOAChoiceServiceCentreAddressOA,
		ServiceCentreAddressOA: &v,
	}
}

// NewSMRPOANoSMRPOA creates a SMRPOA with the noSM-RP-OA alternative.
func NewSMRPOANoSMRPOA(v struct{}) SMRPOA {
	return SMRPOA{
		Choice:   SMRPOAChoiceNoSMRPOA,
		NoSMRPOA: &v,
	}
}

// SMDeliveryTimerValue represents the ASN.1 type SM-DeliveryTimerValue (INTEGER).
type SMDeliveryTimerValue = int64

// ReportSMDeliveryStatusArg represents the ASN.1 type ReportSM-DeliveryStatusArg (SEQUENCE).
type ReportSMDeliveryStatusArg struct {
	Msisdn                                 ISDNAddressString             `asn1:""`
	ServiceCentreAddress                   AddressString                 `asn1:""`
	SmDeliveryOutcome                      SMDeliveryOutcome             `asn1:""`
	AbsentSubscriberDiagnosticSM           *AbsentSubscriberDiagnosticSM `asn1:"tag:0,context,implicit,optional" json:"AbsentSubscriberDiagnosticSM,omitempty"`
	ExtensionContainer                     *ExtensionContainer           `asn1:"tag:1,context,implicit,optional" json:"ExtensionContainer,omitempty"`
	GprsSupportIndicator                   *struct{}                     `asn1:"tag:2,context,implicit,optional" json:"GprsSupportIndicator,omitempty"`
	DeliveryOutcomeIndicator               *struct{}                     `asn1:"tag:3,context,implicit,optional" json:"DeliveryOutcomeIndicator,omitempty"`
	AdditionalSMDeliveryOutcome            *SMDeliveryOutcome            `asn1:"tag:4,context,implicit,optional" json:"AdditionalSMDeliveryOutcome,omitempty"`
	AdditionalAbsentSubscriberDiagnosticSM *AbsentSubscriberDiagnosticSM `asn1:"tag:5,context,implicit,optional" json:"AdditionalAbsentSubscriberDiagnosticSM,omitempty"`
	IpSmGwIndicator                        *struct{}                     `asn1:"tag:6,context,implicit,optional" json:"IpSmGwIndicator,omitempty"`
	IpSmGwSmDeliveryOutcome                *SMDeliveryOutcome            `asn1:"tag:7,context,implicit,optional" json:"IpSmGwSmDeliveryOutcome,omitempty"`
	IpSmGwAbsentSubscriberDiagnosticSM     *AbsentSubscriberDiagnosticSM `asn1:"tag:8,context,implicit,optional" json:"IpSmGwAbsentSubscriberDiagnosticSM,omitempty"`
	Imsi                                   *IMSI                         `asn1:"tag:9,context,implicit,optional" json:"Imsi,omitempty"`
	SingleAttemptDelivery                  *struct{}                     `asn1:"tag:10,context,implicit,optional" json:"SingleAttemptDelivery,omitempty"`
	CorrelationID                          *CorrelationID                `asn1:"tag:11,context,implicit,optional" json:"CorrelationID,omitempty"`
	Smsf3gppDeliveryOutcomeIndicator       *struct{}                     `asn1:"tag:12,context,implicit,optional" json:"Smsf3gppDeliveryOutcomeIndicator,omitempty"`
	Smsf3gppDeliveryOutcome                *SMDeliveryOutcome            `asn1:"tag:13,context,implicit,optional" json:"Smsf3gppDeliveryOutcome,omitempty"`
	Smsf3gppAbsentSubscriberDiagSM         *AbsentSubscriberDiagnosticSM `asn1:"tag:14,context,implicit,optional" json:"Smsf3gppAbsentSubscriberDiagSM,omitempty"`
	SmsfNon3gppDeliveryOutcomeIndicator    *struct{}                     `asn1:"tag:15,context,implicit,optional" json:"SmsfNon3gppDeliveryOutcomeIndicator,omitempty"`
	SmsfNon3gppDeliveryOutcome             *SMDeliveryOutcome            `asn1:"tag:16,context,implicit,optional" json:"SmsfNon3gppDeliveryOutcome,omitempty"`
	SmsfNon3gppAbsentSubscriberDiagSM      *AbsentSubscriberDiagnosticSM `asn1:"tag:17,context,implicit,optional" json:"SmsfNon3gppAbsentSubscriberDiagSM,omitempty"`
	FailedSMServingNodes                   *SMServingNodeAddressList     `asn1:"tag:18,context,implicit,optional" json:"FailedSMServingNodes,omitempty"`
	berFailedSMServingNodesIndef_          bool                          `asn1:"-" json:"-"`
	ExtCount_                              int64                         `asn1:"-" json:"-"`
	ExtPresent_                            []bool                        `asn1:"-" json:"-"`
	// ExtData_ retains complete unknown addition TLVs in received order. Fresh
	// BER and DER copy admissible elements without inferring a foreign schema.
	ExtData_       [][]byte        `asn1:"-" json:"-"`
	berReplayNode_ *ber.ReplayNode `asn1:"-" json:"-"`
}

// SMDeliveryOutcome represents the ASN.1 ENUMERATED type SM-DeliveryOutcome.
type SMDeliveryOutcome int64

const (
	SMDeliveryOutcomeMemoryCapacityExceeded SMDeliveryOutcome = 0
	SMDeliveryOutcomeAbsentSubscriber       SMDeliveryOutcome = 1
	SMDeliveryOutcomeSuccessfulTransfer     SMDeliveryOutcome = 2
)

// String returns the ASN.1 named label, or "unknown" for an unlisted value.
func (v SMDeliveryOutcome) String() string {
	switch v {
	case SMDeliveryOutcomeMemoryCapacityExceeded:
		return "memoryCapacityExceeded"
	case SMDeliveryOutcomeAbsentSubscriber:
		return "absentSubscriber"
	case SMDeliveryOutcomeSuccessfulTransfer:
		return "successfulTransfer"
	default:
		return "unknown"
	}
}

// ReportSMDeliveryStatusRes represents the ASN.1 type ReportSM-DeliveryStatusRes (SEQUENCE).
type ReportSMDeliveryStatusRes struct {
	StoredMSISDN                      *ISDNAddressString        `asn1:",optional" json:"StoredMSISDN,omitempty"`
	ExtensionContainer                *ExtensionContainer       `asn1:",optional" json:"ExtensionContainer,omitempty"`
	RegisteredSMServingNodes          *SMServingNodeAddressList `asn1:"tag:0,context,implicit,optional" json:"RegisteredSMServingNodes,omitempty"`
	berRegisteredSMServingNodesIndef_ bool                      `asn1:"-" json:"-"`
	ExtCount_                         int64                     `asn1:"-" json:"-"`
	ExtPresent_                       []bool                    `asn1:"-" json:"-"`
	// ExtData_ retains complete unknown addition TLVs in received order. Fresh
	// BER and DER copy admissible elements without inferring a foreign schema.
	ExtData_       [][]byte        `asn1:"-" json:"-"`
	berReplayNode_ *ber.ReplayNode `asn1:"-" json:"-"`
}

// SMServingNodeAddressList represents the ASN.1 type SMServingNodeAddressList (SEQUENCE_OF).
type SMServingNodeAddressList struct {
	Values         []SMServingNodeAddress `json:"Values"`
	berReplayNode_ *ber.ReplayNode        `json:"-"`
}

// SMServingNodeAddress choice constants.
const (
	SMServingNodeAddressChoiceNetworkNodeNumber = 1
	SMServingNodeAddressChoiceDiameterAddress   = 2
)

// SMServingNodeAddress represents the ASN.1 CHOICE type SMServingNodeAddress.
type SMServingNodeAddress struct {
	Choice            int
	berReplayNode_    *ber.ReplayNode             `json:"-"`
	NetworkNodeNumber *ISDNAddressString          `json:"NetworkNodeNumber,omitempty"`
	DiameterAddress   *NetworkNodeDiameterAddress `json:"DiameterAddress,omitempty"`
}

// NewSMServingNodeAddressNetworkNodeNumber creates a SMServingNodeAddress with the networkNode-Number alternative.
func NewSMServingNodeAddressNetworkNodeNumber(v ISDNAddressString) SMServingNodeAddress {
	return SMServingNodeAddress{
		Choice:            SMServingNodeAddressChoiceNetworkNodeNumber,
		NetworkNodeNumber: &v,
	}
}

// NewSMServingNodeAddressDiameterAddress creates a SMServingNodeAddress with the diameterAddress alternative.
func NewSMServingNodeAddressDiameterAddress(v NetworkNodeDiameterAddress) SMServingNodeAddress {
	return SMServingNodeAddress{
		Choice:          SMServingNodeAddressChoiceDiameterAddress,
		DiameterAddress: &v,
	}
}

// AlertServiceCentreArg represents the ASN.1 type AlertServiceCentreArg (SEQUENCE).
type AlertServiceCentreArg struct {
	Msisdn                    ISDNAddressString           `asn1:""`
	ServiceCentreAddress      AddressString               `asn1:""`
	Imsi                      *IMSI                       `asn1:",optional" json:"Imsi,omitempty"`
	CorrelationID             *CorrelationID              `asn1:",optional" json:"CorrelationID,omitempty"`
	MaximumUeAvailabilityTime *Time                       `asn1:"tag:0,context,implicit,optional" json:"MaximumUeAvailabilityTime,omitempty"`
	SmsGmscAlertEvent         *SmsGmscAlertEvent          `asn1:"tag:1,context,implicit,optional" json:"SmsGmscAlertEvent,omitempty"`
	SmsGmscDiameterAddress    *NetworkNodeDiameterAddress `asn1:"tag:2,context,implicit,optional" json:"SmsGmscDiameterAddress,omitempty"`
	NewSGSNNumber             *ISDNAddressString          `asn1:"tag:3,context,implicit,optional" json:"NewSGSNNumber,omitempty"`
	NewSGSNDiameterAddress    *NetworkNodeDiameterAddress `asn1:"tag:4,context,implicit,optional" json:"NewSGSNDiameterAddress,omitempty"`
	NewMMENumber              *ISDNAddressString          `asn1:"tag:5,context,implicit,optional" json:"NewMMENumber,omitempty"`
	NewMMEDiameterAddress     *NetworkNodeDiameterAddress `asn1:"tag:6,context,implicit,optional" json:"NewMMEDiameterAddress,omitempty"`
	NewMSCNumber              *ISDNAddressString          `asn1:"tag:7,context,implicit,optional" json:"NewMSCNumber,omitempty"`
	ExtCount_                 int64                       `asn1:"-" json:"-"`
	ExtPresent_               []bool                      `asn1:"-" json:"-"`
	// ExtData_ retains complete unknown addition TLVs in received order. Fresh
	// BER and DER copy admissible elements without inferring a foreign schema.
	ExtData_       [][]byte        `asn1:"-" json:"-"`
	berReplayNode_ *ber.ReplayNode `asn1:"-" json:"-"`
}

// SmsGmscAlertEvent represents the ASN.1 ENUMERATED type SmsGmsc-Alert-Event.
type SmsGmscAlertEvent int64

const (
	SmsGmscAlertEventMsAvailableForMtSms   SmsGmscAlertEvent = 0
	SmsGmscAlertEventMsUnderNewServingNode SmsGmscAlertEvent = 1
)

// String returns the ASN.1 named label, or "unknown" for an unlisted value.
func (v SmsGmscAlertEvent) String() string {
	switch v {
	case SmsGmscAlertEventMsAvailableForMtSms:
		return "msAvailableForMtSms"
	case SmsGmscAlertEventMsUnderNewServingNode:
		return "msUnderNewServingNode"
	default:
		return "unknown"
	}
}

// InformServiceCentreArg represents the ASN.1 type InformServiceCentreArg (SEQUENCE).
type InformServiceCentreArg struct {
	StoredMSISDN                            *ISDNAddressString            `asn1:",optional" json:"StoredMSISDN,omitempty"`
	MwStatus                                *MWStatus                     `asn1:",optional" json:"MwStatus,omitempty"`
	ExtensionContainer                      *ExtensionContainer           `asn1:",optional" json:"ExtensionContainer,omitempty"`
	AbsentSubscriberDiagnosticSM            *AbsentSubscriberDiagnosticSM `asn1:",optional" json:"AbsentSubscriberDiagnosticSM,omitempty"`
	AdditionalAbsentSubscriberDiagnosticSM  *AbsentSubscriberDiagnosticSM `asn1:"tag:0,context,implicit,optional" json:"AdditionalAbsentSubscriberDiagnosticSM,omitempty"`
	Smsf3gppAbsentSubscriberDiagnosticSM    *AbsentSubscriberDiagnosticSM `asn1:"tag:1,context,implicit,optional" json:"Smsf3gppAbsentSubscriberDiagnosticSM,omitempty"`
	SmsfNon3gppAbsentSubscriberDiagnosticSM *AbsentSubscriberDiagnosticSM `asn1:"tag:2,context,implicit,optional" json:"SmsfNon3gppAbsentSubscriberDiagnosticSM,omitempty"`
	ExtCount_                               int64                         `asn1:"-" json:"-"`
	ExtPresent_                             []bool                        `asn1:"-" json:"-"`
	// ExtData_ retains complete unknown addition TLVs in received order. Fresh
	// BER and DER copy admissible elements without inferring a foreign schema.
	ExtData_       [][]byte        `asn1:"-" json:"-"`
	berReplayNode_ *ber.ReplayNode `asn1:"-" json:"-"`
}

// MWStatus represents the ASN.1 type MW-Status (BIT_STRING).
type MWStatus = runtime.BitString

const (
	// MWStatusScAddressNotIncluded is position 0 of ASN.1 named bit sc-AddressNotIncluded of MW-Status (ITU-T X.680 (02/2021) §22).
	MWStatusScAddressNotIncluded = 0
	// MWStatusMnrfSet is position 1 of ASN.1 named bit mnrf-Set of MW-Status (ITU-T X.680 (02/2021) §22).
	MWStatusMnrfSet = 1
	// MWStatusMcefSet is position 2 of ASN.1 named bit mcef-Set of MW-Status (ITU-T X.680 (02/2021) §22).
	MWStatusMcefSet = 2
	// MWStatusMnrgSet is position 3 of ASN.1 named bit mnrg-Set of MW-Status (ITU-T X.680 (02/2021) §22).
	MWStatusMnrgSet = 3
	// MWStatusMnr5gSet is position 4 of ASN.1 named bit mnr5g-Set of MW-Status (ITU-T X.680 (02/2021) §22).
	MWStatusMnr5gSet = 4
	// MWStatusMnr5gn3gSet is position 5 of ASN.1 named bit mnr5gn3g-Set of MW-Status (ITU-T X.680 (02/2021) §22).
	MWStatusMnr5gn3gSet = 5
)

// ReadyForSMArg represents the ASN.1 type ReadyForSM-Arg (SEQUENCE).
type ReadyForSMArg struct {
	Imsi                           IMSI                `asn1:"tag:0,context,implicit"`
	AlertReason                    AlertReason         `asn1:""`
	AlertReasonIndicator           *struct{}           `asn1:",optional" json:"AlertReasonIndicator,omitempty"`
	ExtensionContainer             *ExtensionContainer `asn1:",optional" json:"ExtensionContainer,omitempty"`
	AdditionalAlertReasonIndicator *struct{}           `asn1:"tag:1,context,implicit,optional" json:"AdditionalAlertReasonIndicator,omitempty"`
	MaximumUeAvailabilityTime      *Time               `asn1:",optional" json:"MaximumUeAvailabilityTime,omitempty"`
	ExtCount_                      int64               `asn1:"-" json:"-"`
	ExtPresent_                    []bool              `asn1:"-" json:"-"`
	// ExtData_ retains complete unknown addition TLVs in received order. Fresh
	// BER and DER copy admissible elements without inferring a foreign schema.
	ExtData_       [][]byte        `asn1:"-" json:"-"`
	berReplayNode_ *ber.ReplayNode `asn1:"-" json:"-"`
}

// ReadyForSMRes represents the ASN.1 type ReadyForSM-Res (SEQUENCE).
type ReadyForSMRes struct {
	ExtensionContainer *ExtensionContainer `asn1:",optional" json:"ExtensionContainer,omitempty"`
	ExtCount_          int64               `asn1:"-" json:"-"`
	ExtPresent_        []bool              `asn1:"-" json:"-"`
	// ExtData_ retains complete unknown addition TLVs in received order. Fresh
	// BER and DER copy admissible elements without inferring a foreign schema.
	ExtData_       [][]byte        `asn1:"-" json:"-"`
	berReplayNode_ *ber.ReplayNode `asn1:"-" json:"-"`
}

// AlertReason represents the ASN.1 ENUMERATED type AlertReason.
type AlertReason int64

const (
	AlertReasonMsPresent       AlertReason = 0
	AlertReasonMemoryAvailable AlertReason = 1
)

// String returns the ASN.1 named label, or "unknown" for an unlisted value.
func (v AlertReason) String() string {
	switch v {
	case AlertReasonMsPresent:
		return "ms-Present"
	case AlertReasonMemoryAvailable:
		return "memoryAvailable"
	default:
		return "unknown"
	}
}

// MTForwardSMVGCSArg represents the ASN.1 type MT-ForwardSM-VGCS-Arg (SEQUENCE).
type MTForwardSMVGCSArg struct {
	AsciCallReference  ASCICallReference   `asn1:""`
	SmRPOA             SMRPOA              `asn1:""`
	SmRPUI             SignalInfo          `asn1:""`
	ExtensionContainer *ExtensionContainer `asn1:",optional" json:"ExtensionContainer,omitempty"`
	ExtCount_          int64               `asn1:"-" json:"-"`
	ExtPresent_        []bool              `asn1:"-" json:"-"`
	// ExtData_ retains complete unknown addition TLVs in received order. Fresh
	// BER and DER copy admissible elements without inferring a foreign schema.
	ExtData_       [][]byte        `asn1:"-" json:"-"`
	berReplayNode_ *ber.ReplayNode `asn1:"-" json:"-"`
}

// MTForwardSMVGCSRes represents the ASN.1 type MT-ForwardSM-VGCS-Res (SEQUENCE).
type MTForwardSMVGCSRes struct {
	SmRPUI                            *SignalInfo               `asn1:"tag:0,context,implicit,optional" json:"SmRPUI,omitempty"`
	DispatcherList                    *DispatcherList           `asn1:"tag:1,context,implicit,optional" json:"DispatcherList,omitempty"`
	berDispatcherListIndef_           bool                      `asn1:"-" json:"-"`
	OngoingCall                       *struct{}                 `asn1:",optional" json:"OngoingCall,omitempty"`
	ExtensionContainer                *ExtensionContainer       `asn1:"tag:2,context,implicit,optional" json:"ExtensionContainer,omitempty"`
	AdditionalDispatcherList          *AdditionalDispatcherList `asn1:"tag:3,context,implicit,optional" json:"AdditionalDispatcherList,omitempty"`
	berAdditionalDispatcherListIndef_ bool                      `asn1:"-" json:"-"`
	ExtCount_                         int64                     `asn1:"-" json:"-"`
	ExtPresent_                       []bool                    `asn1:"-" json:"-"`
	// ExtData_ retains complete unknown addition TLVs in received order. Fresh
	// BER and DER copy admissible elements without inferring a foreign schema.
	ExtData_       [][]byte        `asn1:"-" json:"-"`
	berReplayNode_ *ber.ReplayNode `asn1:"-" json:"-"`
}

// DispatcherList represents the ASN.1 type DispatcherList (SEQUENCE_OF).
type DispatcherList struct {
	Values         []ISDNAddressString `json:"Values"`
	berReplayNode_ *ber.ReplayNode     `json:"-"`
}

// AdditionalDispatcherList represents the ASN.1 type AdditionalDispatcherList (SEQUENCE_OF).
type AdditionalDispatcherList struct {
	Values         []ISDNAddressString `json:"Values"`
	berReplayNode_ *ber.ReplayNode     `json:"-"`
}

// MarshalBER encodes RoutingInfoForSMArg to BER format.
func (v *RoutingInfoForSMArg) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {

	if v == nil {
		return nil, fmt.Errorf("%w: RoutingInfoForSMArg receiver is nil", ber.ErrInvalidValue)
	}
	return marshalFramedValue(v, v.berReplayNode_, opts, (*RoutingInfoForSMArg).MarshalBER, (*RoutingInfoForSMArg).marshalBER, 3)

}
func (v *RoutingInfoForSMArg) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if len(v.Msisdn) < 1 || len(v.Msisdn) > 9 {
		if constraintErr := checkEncodedLength(opts, s949588_0, "51.5", "msisdn", "SIZE (1..9)", len(v.Msisdn)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	if len(v.Msisdn) < 1 || len(v.Msisdn) > 20 {
		if constraintErr := checkEncodedLength(opts, s949588_0, "51.5", "msisdn", "SIZE (1..20)", len(v.Msisdn)); constraintErr != nil {
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
	var enc_smrppri []byte
	if ber.BERReplayEnabled(opts) && v.berSmRPPRIRaw_ != 0 && v.SmRPPRI {
		enc_smrppri = ber.EncodeBooleanRaw(v.berSmRPPRIRaw_)
	} else {
		enc_smrppri = ber.EncodeBoolean(v.SmRPPRI)
	}
	retagged_enc_smrppri, tagErr_enc_smrppri := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_smrppri)
	if tagErr_enc_smrppri != nil {
		return nil, qualifyBERError(tagErr_enc_smrppri, "sm-RP-PRI", "encoding", false)
	}
	enc_smrppri = retagged_enc_smrppri
	children = append(children, enc_smrppri...)
	if len(v.ServiceCentreAddress) < 1 || len(v.ServiceCentreAddress) > 20 {
		if constraintErr := checkEncodedLength(opts, s949588_0, "51.5", "serviceCentreAddress", "SIZE (1..20)", len(v.ServiceCentreAddress)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_servicecentreaddress, encodeErr_enc_servicecentreaddress := ber.EncodeOctetString([]byte(v.ServiceCentreAddress))
	if encodeErr_enc_servicecentreaddress != nil {
		return nil, qualifyBERError(encodeErr_enc_servicecentreaddress, "serviceCentreAddress", "encoding", false)
	}
	retagged_enc_servicecentreaddress, tagErr_enc_servicecentreaddress := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_servicecentreaddress)
	if tagErr_enc_servicecentreaddress != nil {
		return nil, qualifyBERError(tagErr_enc_servicecentreaddress, "serviceCentreAddress", "encoding", false)
	}
	enc_servicecentreaddress = retagged_enc_servicecentreaddress
	children = append(children, enc_servicecentreaddress...)
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
	if v.GprsSupportIndicator != nil {
		enc_gprssupportindicator := ber.EncodeNull()
		retagged_enc_gprssupportindicator, tagErr_enc_gprssupportindicator := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 7, enc_gprssupportindicator)
		if tagErr_enc_gprssupportindicator != nil {
			return nil, qualifyBERError(tagErr_enc_gprssupportindicator, "gprsSupportIndicator", "encoding", false)
		}
		enc_gprssupportindicator = retagged_enc_gprssupportindicator
		children = append(children, enc_gprssupportindicator...)
	}
	if v.SmRPMTI != nil {
		if !(int64(*v.SmRPMTI) >= 0 && int64(*v.SmRPMTI) <= 10) {
			if constraintErr := checkEncodedValue(opts, s949588_0, "51.4", "sm-RP-MTI", "(0..10)", ber.ObserveInteger(int64(*v.SmRPMTI))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_smrpmti := ber.EncodeInteger(int64(*v.SmRPMTI))
		retagged_enc_smrpmti, tagErr_enc_smrpmti := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 8, enc_smrpmti)
		if tagErr_enc_smrpmti != nil {
			return nil, qualifyBERError(tagErr_enc_smrpmti, "sm-RP-MTI", "encoding", false)
		}
		enc_smrpmti = retagged_enc_smrpmti
		children = append(children, enc_smrpmti...)
	}
	if v.SmRPSMEA != nil {
		if len(*v.SmRPSMEA) < 1 || len(*v.SmRPSMEA) > 12 {
			if constraintErr := checkEncodedLength(opts, s949588_0, "51.5", "sm-RP-SMEA", "SIZE (1..12)", len(*v.SmRPSMEA)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_smrpsmea, encodeErr_enc_smrpsmea := ber.EncodeOctetString([]byte(*v.SmRPSMEA))
		if encodeErr_enc_smrpsmea != nil {
			return nil, qualifyBERError(encodeErr_enc_smrpsmea, "sm-RP-SMEA", "encoding", false)
		}
		retagged_enc_smrpsmea, tagErr_enc_smrpsmea := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 9, enc_smrpsmea)
		if tagErr_enc_smrpsmea != nil {
			return nil, qualifyBERError(tagErr_enc_smrpsmea, "sm-RP-SMEA", "encoding", false)
		}
		enc_smrpsmea = retagged_enc_smrpsmea
		children = append(children, enc_smrpsmea...)
	}
	if v.SmDeliveryNotIntended != nil {
		enc_smdeliverynotintended := ber.EncodeEnumerated(int64(*v.SmDeliveryNotIntended))
		retagged_enc_smdeliverynotintended, tagErr_enc_smdeliverynotintended := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 10, enc_smdeliverynotintended)
		if tagErr_enc_smdeliverynotintended != nil {
			return nil, qualifyBERError(tagErr_enc_smdeliverynotintended, "sm-deliveryNotIntended", "encoding", false)
		}
		enc_smdeliverynotintended = retagged_enc_smdeliverynotintended
		children = append(children, enc_smdeliverynotintended...)
	}
	if v.IpSmGwGuidanceIndicator != nil {
		enc_ipsmgwguidanceindicator := ber.EncodeNull()
		retagged_enc_ipsmgwguidanceindicator, tagErr_enc_ipsmgwguidanceindicator := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 11, enc_ipsmgwguidanceindicator)
		if tagErr_enc_ipsmgwguidanceindicator != nil {
			return nil, qualifyBERError(tagErr_enc_ipsmgwguidanceindicator, "ip-sm-gwGuidanceIndicator", "encoding", false)
		}
		enc_ipsmgwguidanceindicator = retagged_enc_ipsmgwguidanceindicator
		children = append(children, enc_ipsmgwguidanceindicator...)
	}
	if v.Imsi != nil {
		if len(*v.Imsi) < 3 || len(*v.Imsi) > 8 {
			if constraintErr := checkEncodedLength(opts, s949588_0, "51.5", "imsi", "SIZE (3..8)", len(*v.Imsi)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_imsi, encodeErr_enc_imsi := ber.EncodeOctetString([]byte(*v.Imsi))
		if encodeErr_enc_imsi != nil {
			return nil, qualifyBERError(encodeErr_enc_imsi, "imsi", "encoding", false)
		}
		retagged_enc_imsi, tagErr_enc_imsi := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 12, enc_imsi)
		if tagErr_enc_imsi != nil {
			return nil, qualifyBERError(tagErr_enc_imsi, "imsi", "encoding", false)
		}
		enc_imsi = retagged_enc_imsi
		children = append(children, enc_imsi...)
	}
	if v.T4TriggerIndicator != nil {
		enc_t4triggerindicator := ber.EncodeNull()
		retagged_enc_t4triggerindicator, tagErr_enc_t4triggerindicator := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 14, enc_t4triggerindicator)
		if tagErr_enc_t4triggerindicator != nil {
			return nil, qualifyBERError(tagErr_enc_t4triggerindicator, "t4-Trigger-Indicator", "encoding", false)
		}
		enc_t4triggerindicator = retagged_enc_t4triggerindicator
		children = append(children, enc_t4triggerindicator...)
	}
	if v.SingleAttemptDelivery != nil {
		enc_singleattemptdelivery := ber.EncodeNull()
		retagged_enc_singleattemptdelivery, tagErr_enc_singleattemptdelivery := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 13, enc_singleattemptdelivery)
		if tagErr_enc_singleattemptdelivery != nil {
			return nil, qualifyBERError(tagErr_enc_singleattemptdelivery, "singleAttemptDelivery", "encoding", false)
		}
		enc_singleattemptdelivery = retagged_enc_singleattemptdelivery
		children = append(children, enc_singleattemptdelivery...)
	}
	if v.CorrelationID != nil {
		enc_correlationid, err := v.CorrelationID.MarshalBER(ber.ChildEncodeOptions(opts, "correlationID")...)
		if err != nil {
			return nil, qualifyBERError(err, "correlationID", "encoding", false)
		}
		retagged_enc_correlationid, tagErr_enc_correlationid := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 15, enc_correlationid)
		if tagErr_enc_correlationid != nil {
			return nil, qualifyBERError(tagErr_enc_correlationid, "correlationID", "encoding", false)
		}
		enc_correlationid = retagged_enc_correlationid
		ber.RecordGeneratedBERChildPlacement(opts, len(children), enc_correlationid)
		children = append(children, enc_correlationid...)
	}
	if v.SmsfSupportIndicator != nil {
		enc_smsfsupportindicator := ber.EncodeNull()
		retagged_enc_smsfsupportindicator, tagErr_enc_smsfsupportindicator := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 16, enc_smsfsupportindicator)
		if tagErr_enc_smsfsupportindicator != nil {
			return nil, qualifyBERError(tagErr_enc_smsfsupportindicator, "smsf-supportIndicator", "encoding", false)
		}
		enc_smsfsupportindicator = retagged_enc_smsfsupportindicator
		children = append(children, enc_smsfsupportindicator...)
	}
	base_ := -1
	for i, ext := range v.ExtData_ {
		if err := checkOpaqueAddition(ext, opts, s949588_0, children, i, &base_); err != nil {
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
		if i == 0 && ((peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 16) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 15) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 13) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 14) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 12) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 11) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 10) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 9) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 8) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 7) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 6)) {
			if constraintErr := ber.CheckEncodedValue(ber.EncodeRule(opts, s949588_0, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
				return nil, constraintErr
			}
		}
		children = append(children, ext...)
	}
	ber.RecordGeneratedBERContainer(opts, children)
	return ber.EncodeSequence(children)
}
func (v *RoutingInfoForSMArg) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// MarshalDER encodes RoutingInfoForSMArg to DER format.
// Opaque descendants pass generic DER checks; foreign schema rules need a typed binding.
func (v *RoutingInfoForSMArg) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: RoutingInfoForSMArg receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if len(v.Msisdn) < 1 || len(v.Msisdn) > 9 {
		if constraintErr := checkEncodedLength(nil, s949588_0, "51.5", "msisdn", "SIZE (1..9)", len(v.Msisdn)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	if len(v.Msisdn) < 1 || len(v.Msisdn) > 20 {
		if constraintErr := checkEncodedLength(nil, s949588_0, "51.5", "msisdn", "SIZE (1..20)", len(v.Msisdn)); constraintErr != nil {
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
	enc_smrppri := ber.EncodeBoolean(v.SmRPPRI)
	retagged_enc_smrppri, tagErr_enc_smrppri := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_smrppri)
	if tagErr_enc_smrppri != nil {
		return nil, qualifyBERError(tagErr_enc_smrppri, "sm-RP-PRI", "encoding", true)
	}
	enc_smrppri = retagged_enc_smrppri
	children = append(children, enc_smrppri...)
	if len(v.ServiceCentreAddress) < 1 || len(v.ServiceCentreAddress) > 20 {
		if constraintErr := checkEncodedLength(nil, s949588_0, "51.5", "serviceCentreAddress", "SIZE (1..20)", len(v.ServiceCentreAddress)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_servicecentreaddress, encodeErr_enc_servicecentreaddress := ber.EncodeOctetString([]byte(v.ServiceCentreAddress))
	if encodeErr_enc_servicecentreaddress != nil {
		return nil, qualifyBERError(encodeErr_enc_servicecentreaddress, "serviceCentreAddress", "encoding", true)
	}
	retagged_enc_servicecentreaddress, tagErr_enc_servicecentreaddress := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_servicecentreaddress)
	if tagErr_enc_servicecentreaddress != nil {
		return nil, qualifyBERError(tagErr_enc_servicecentreaddress, "serviceCentreAddress", "encoding", true)
	}
	enc_servicecentreaddress = retagged_enc_servicecentreaddress
	children = append(children, enc_servicecentreaddress...)
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
	if v.GprsSupportIndicator != nil {
		enc_gprssupportindicator := ber.EncodeNull()
		retagged_enc_gprssupportindicator, tagErr_enc_gprssupportindicator := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 7, enc_gprssupportindicator)
		if tagErr_enc_gprssupportindicator != nil {
			return nil, qualifyBERError(tagErr_enc_gprssupportindicator, "gprsSupportIndicator", "encoding", true)
		}
		enc_gprssupportindicator = retagged_enc_gprssupportindicator
		children = append(children, enc_gprssupportindicator...)
	}
	if v.SmRPMTI != nil {
		if !(int64(*v.SmRPMTI) >= 0 && int64(*v.SmRPMTI) <= 10) {
			if constraintErr := checkEncodedValue(nil, s949588_0, "51.4", "sm-RP-MTI", "(0..10)", ber.ObserveInteger(int64(*v.SmRPMTI))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_smrpmti := ber.EncodeInteger(int64(*v.SmRPMTI))
		retagged_enc_smrpmti, tagErr_enc_smrpmti := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 8, enc_smrpmti)
		if tagErr_enc_smrpmti != nil {
			return nil, qualifyBERError(tagErr_enc_smrpmti, "sm-RP-MTI", "encoding", true)
		}
		enc_smrpmti = retagged_enc_smrpmti
		children = append(children, enc_smrpmti...)
	}
	if v.SmRPSMEA != nil {
		if len(*v.SmRPSMEA) < 1 || len(*v.SmRPSMEA) > 12 {
			if constraintErr := checkEncodedLength(nil, s949588_0, "51.5", "sm-RP-SMEA", "SIZE (1..12)", len(*v.SmRPSMEA)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_smrpsmea, encodeErr_enc_smrpsmea := ber.EncodeOctetString([]byte(*v.SmRPSMEA))
		if encodeErr_enc_smrpsmea != nil {
			return nil, qualifyBERError(encodeErr_enc_smrpsmea, "sm-RP-SMEA", "encoding", true)
		}
		retagged_enc_smrpsmea, tagErr_enc_smrpsmea := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 9, enc_smrpsmea)
		if tagErr_enc_smrpsmea != nil {
			return nil, qualifyBERError(tagErr_enc_smrpsmea, "sm-RP-SMEA", "encoding", true)
		}
		enc_smrpsmea = retagged_enc_smrpsmea
		children = append(children, enc_smrpsmea...)
	}
	if v.SmDeliveryNotIntended != nil {
		enc_smdeliverynotintended := ber.EncodeEnumerated(int64(*v.SmDeliveryNotIntended))
		retagged_enc_smdeliverynotintended, tagErr_enc_smdeliverynotintended := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 10, enc_smdeliverynotintended)
		if tagErr_enc_smdeliverynotintended != nil {
			return nil, qualifyBERError(tagErr_enc_smdeliverynotintended, "sm-deliveryNotIntended", "encoding", true)
		}
		enc_smdeliverynotintended = retagged_enc_smdeliverynotintended
		children = append(children, enc_smdeliverynotintended...)
	}
	if v.IpSmGwGuidanceIndicator != nil {
		enc_ipsmgwguidanceindicator := ber.EncodeNull()
		retagged_enc_ipsmgwguidanceindicator, tagErr_enc_ipsmgwguidanceindicator := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 11, enc_ipsmgwguidanceindicator)
		if tagErr_enc_ipsmgwguidanceindicator != nil {
			return nil, qualifyBERError(tagErr_enc_ipsmgwguidanceindicator, "ip-sm-gwGuidanceIndicator", "encoding", true)
		}
		enc_ipsmgwguidanceindicator = retagged_enc_ipsmgwguidanceindicator
		children = append(children, enc_ipsmgwguidanceindicator...)
	}
	if v.Imsi != nil {
		if len(*v.Imsi) < 3 || len(*v.Imsi) > 8 {
			if constraintErr := checkEncodedLength(nil, s949588_0, "51.5", "imsi", "SIZE (3..8)", len(*v.Imsi)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_imsi, encodeErr_enc_imsi := ber.EncodeOctetString([]byte(*v.Imsi))
		if encodeErr_enc_imsi != nil {
			return nil, qualifyBERError(encodeErr_enc_imsi, "imsi", "encoding", true)
		}
		retagged_enc_imsi, tagErr_enc_imsi := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 12, enc_imsi)
		if tagErr_enc_imsi != nil {
			return nil, qualifyBERError(tagErr_enc_imsi, "imsi", "encoding", true)
		}
		enc_imsi = retagged_enc_imsi
		children = append(children, enc_imsi...)
	}
	if v.T4TriggerIndicator != nil {
		enc_t4triggerindicator := ber.EncodeNull()
		retagged_enc_t4triggerindicator, tagErr_enc_t4triggerindicator := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 14, enc_t4triggerindicator)
		if tagErr_enc_t4triggerindicator != nil {
			return nil, qualifyBERError(tagErr_enc_t4triggerindicator, "t4-Trigger-Indicator", "encoding", true)
		}
		enc_t4triggerindicator = retagged_enc_t4triggerindicator
		children = append(children, enc_t4triggerindicator...)
	}
	if v.SingleAttemptDelivery != nil {
		enc_singleattemptdelivery := ber.EncodeNull()
		retagged_enc_singleattemptdelivery, tagErr_enc_singleattemptdelivery := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 13, enc_singleattemptdelivery)
		if tagErr_enc_singleattemptdelivery != nil {
			return nil, qualifyBERError(tagErr_enc_singleattemptdelivery, "singleAttemptDelivery", "encoding", true)
		}
		enc_singleattemptdelivery = retagged_enc_singleattemptdelivery
		children = append(children, enc_singleattemptdelivery...)
	}
	if v.CorrelationID != nil {
		enc_correlationid, err := v.CorrelationID.MarshalDER()
		if err != nil {
			return nil, qualifyBERError(err, "correlationID", "encoding", true)
		}
		retagged_enc_correlationid, tagErr_enc_correlationid := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 15, enc_correlationid)
		if tagErr_enc_correlationid != nil {
			return nil, qualifyBERError(tagErr_enc_correlationid, "correlationID", "encoding", true)
		}
		enc_correlationid = retagged_enc_correlationid
		children = append(children, enc_correlationid...)
	}
	if v.SmsfSupportIndicator != nil {
		enc_smsfsupportindicator := ber.EncodeNull()
		retagged_enc_smsfsupportindicator, tagErr_enc_smsfsupportindicator := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 16, enc_smsfsupportindicator)
		if tagErr_enc_smsfsupportindicator != nil {
			return nil, qualifyBERError(tagErr_enc_smsfsupportindicator, "smsf-supportIndicator", "encoding", true)
		}
		enc_smsfsupportindicator = retagged_enc_smsfsupportindicator
		children = append(children, enc_smsfsupportindicator...)
	}
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDEREncodedElement(ext); err != nil {
			return nil, invalidDERAddition(ext, s949588_0, children, i)
		}
		peekTag, _, _, extErr := ber.DecodeEncodedTLV(ext)
		if extErr != nil {
			return nil, extErr
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: only the first addition is restricted.
		if i == 0 && ((peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 16) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 15) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 13) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 14) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 12) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 11) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 10) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 9) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 8) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 7) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 6)) {
			if constraintErr := ber.CheckEncodedValue(ber.EncodeRule(nil, s949588_0, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
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
		return nil, fmt.Errorf("%s: %w", "encoding RoutingInfoForSMArg as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}
func (v *RoutingInfoForSMArg) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	encoded, err := v.MarshalDER()
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBER decodes RoutingInfoForSMArg from BER/DER format.
func (destination *RoutingInfoForSMArg) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if destination == nil {
		return fmt.Errorf("%w: RoutingInfoForSMArg destination is nil", ber.ErrInvalidValue)
	}
	v := new(RoutingInfoForSMArg)

	defer publishDecodedValue(destination, v, &returnErr)

	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	preparedData, preparedOptions, prepareErr := prepareCompositeBER(data, opts, s949588_0, "child", (*RoutingInfoForSMArg).UnmarshalBER)
	if prepareErr != nil {
		return prepareErr
	}
	data, opts = preparedData, preparedOptions

	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
	*v = RoutingInfoForSMArg{}
	defer func() {
		if returnErr == nil {
			returnErr = completeValueBER(data,
				opts, v, &v.berReplayNode_, (*RoutingInfoForSMArg).MarshalBER)
		}

	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("%s: %w", "decoding RoutingInfoForSMArg SEQUENCE", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "RoutingInfoForSMArg", Cause: ber.ErrExtraData}
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
			if constraintErr := checkDecodedLength(opts, s949588_0, "51.5", "msisdn", "SIZE (1..9)", len(v.Msisdn)); constraintErr != nil {
				return constraintErr
			}
		}
		if len(v.Msisdn) < 1 || len(v.Msisdn) > 20 {
			if constraintErr := checkDecodedLength(opts, s949588_0, "51.5", "msisdn", "SIZE (1..20)", len(v.Msisdn)); constraintErr != nil {
				return constraintErr
			}
		}
	}
	// Decode sm-RP-PRI
	if offset >= len(content) {
		return fmt.Errorf("missing required field sm-RP-PRI")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 1 {
			return fmt.Errorf("expected tag [%s %d] for sm-RP-PRI, got %s", "CONTEXT", 1, reqTag_)
		}
	}
	{
		ber.MarkPreflightTarget(opts, "sm-RP-PRI", content[offset:])
		decodedTag_smrppri, n_smrppri, rawVal_smrppri, err := ber.DecodeTLV(content[offset:], opts...)
		if err != nil {
			return qualifyBERError(err, "sm-RP-PRI", "decoding", false)
		}
		if decodedTag_smrppri.Class != tag.ClassContextSpecific || decodedTag_smrppri.Number != 1 || decodedTag_smrppri.Constructed != false {
			return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_smrppri), "sm-RP-PRI", "decoding", false)
		}
		decVal_smrppri, boolErr := ber.DecodeBooleanValue(rawVal_smrppri)
		if boolErr != nil {
			return qualifyBERError(boolErr, "sm-RP-PRI", "decoding", false)
		}
		if len(rawVal_smrppri) == 1 && rawVal_smrppri[0] != 0 && rawVal_smrppri[0] != 0xff {
			ber.MarkBERNonCanonical(opts)
		}
		if len(rawVal_smrppri) == 1 {
			v.berSmRPPRIRaw_ = rawVal_smrppri[0]
		}
		v.SmRPPRI = decVal_smrppri
		if offset < 0 || offset >
			len(content) || n_smrppri < 0 || n_smrppri > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n_smrppri
	}
	// Decode serviceCentreAddress
	if offset >= len(content) {
		return fmt.Errorf("missing required field serviceCentreAddress")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 2 {
			return fmt.Errorf("expected tag [%s %d] for serviceCentreAddress, got %s", "CONTEXT", 2, reqTag_)
		}
	}
	{
		ber.MarkPreflightTarget(opts, "serviceCentreAddress", content[offset:])
		decodedTag_servicecentreaddress, n_servicecentreaddress, rawVal_servicecentreaddress, err := ber.DecodeTLV(content[offset:], opts...)
		if err != nil {
			return qualifyBERError(err, "serviceCentreAddress", "decoding", false)
		}
		if decodedTag_servicecentreaddress.Class != tag.ClassContextSpecific || decodedTag_servicecentreaddress.Number != 2 {
			return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_servicecentreaddress), "serviceCentreAddress", "decoding", false)
		}
		decVal_servicecentreaddress, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_servicecentreaddress.Constructed, rawVal_servicecentreaddress, opts...)
		if octetErr != nil {
			return qualifyBERError(octetErr, "serviceCentreAddress", "decoding", false)
		}
		v.ServiceCentreAddress = AddressString(decVal_servicecentreaddress)
		if offset < 0 || offset >
			len(content) || n_servicecentreaddress < 0 || n_servicecentreaddress >
			len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n_servicecentreaddress
		if len(v.ServiceCentreAddress) < 1 || len(v.ServiceCentreAddress) > 20 {
			if constraintErr := checkDecodedLength(opts, s949588_0, "51.5", "serviceCentreAddress", "SIZE (1..20)", len(v.ServiceCentreAddress)); constraintErr != nil {
				return constraintErr
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
	// Decode gprsSupportIndicator
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 7 {
				ber.MarkPreflightTarget(opts, "gprsSupportIndicator", content[offset:])
				decodedTag_gprssupportindicator, n_gprssupportindicator, rawVal_gprssupportindicator, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "gprsSupportIndicator", "decoding", false)
				}
				if decodedTag_gprssupportindicator.Class != tag.ClassContextSpecific || decodedTag_gprssupportindicator.Number != 7 || decodedTag_gprssupportindicator.Constructed != false {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_gprssupportindicator), "gprsSupportIndicator", "decoding", false)
				}
				if len(rawVal_gprssupportindicator) != 0 {
					return qualifyBERError(fmt.Errorf("%w: NULL content length %d", ber.ErrInvalidValue, len(rawVal_gprssupportindicator)), "gprsSupportIndicator", "decoding", false)
				}
				v.GprsSupportIndicator = &struct{}{}
				if offset < 0 || offset >
					len(content) || n_gprssupportindicator < 0 || n_gprssupportindicator >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_gprssupportindicator
			}
		}
	}
	// Decode sm-RP-MTI
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 8 {
				ber.MarkPreflightTarget(opts, "sm-RP-MTI", content[offset:])
				decodedTag_smrpmti, n_smrpmti, rawVal_smrpmti, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "sm-RP-MTI", "decoding", false)
				}
				if decodedTag_smrpmti.Class != tag.ClassContextSpecific || decodedTag_smrpmti.Number != 8 || decodedTag_smrpmti.Constructed != false {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_smrpmti), "sm-RP-MTI", "decoding", false)
				}
				decVal_smrpmti, intErr := ber.DecodeIntegerValue(rawVal_smrpmti)
				if intErr != nil {
					return qualifyBERError(intErr, "sm-RP-MTI", "decoding", false)
				}
				tmp_smrpmti := SMRPMTI(decVal_smrpmti)
				v.SmRPMTI = &tmp_smrpmti
				if offset < 0 || offset >
					len(content) || n_smrpmti < 0 || n_smrpmti > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_smrpmti
				if !(int64(*v.SmRPMTI) >= 0 && int64(*v.SmRPMTI) <= 10) {
					if constraintErr := checkDecodedValue(opts, s949588_0, "51.4", "sm-RP-MTI", "(0..10)", ber.ObserveInteger(int64(*v.SmRPMTI))); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode sm-RP-SMEA
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 9 {
				ber.MarkPreflightTarget(opts, "sm-RP-SMEA", content[offset:])
				decodedTag_smrpsmea, n_smrpsmea, rawVal_smrpsmea, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "sm-RP-SMEA", "decoding", false)
				}
				if decodedTag_smrpsmea.Class != tag.ClassContextSpecific || decodedTag_smrpsmea.Number != 9 {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_smrpsmea), "sm-RP-SMEA", "decoding", false)
				}
				decVal_smrpsmea, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_smrpsmea.Constructed, rawVal_smrpsmea, opts...)
				if octetErr != nil {
					return qualifyBERError(octetErr, "sm-RP-SMEA", "decoding", false)
				}
				tmp_smrpsmea := SMRPSMEA(decVal_smrpsmea)
				v.SmRPSMEA = &tmp_smrpsmea
				if offset < 0 || offset >
					len(content) || n_smrpsmea < 0 || n_smrpsmea > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_smrpsmea
				if len(*v.SmRPSMEA) < 1 || len(*v.SmRPSMEA) > 12 {
					if constraintErr := checkDecodedLength(opts, s949588_0, "51.5", "sm-RP-SMEA", "SIZE (1..12)", len(*v.SmRPSMEA)); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode sm-deliveryNotIntended
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 10 {
				ber.MarkPreflightTarget(opts, "sm-deliveryNotIntended", content[offset:])
				decodedTag_smdeliverynotintended, n_smdeliverynotintended, rawVal_smdeliverynotintended, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "sm-deliveryNotIntended", "decoding", false)
				}
				if decodedTag_smdeliverynotintended.Class != tag.ClassContextSpecific || decodedTag_smdeliverynotintended.Number != 10 || decodedTag_smdeliverynotintended.Constructed != false {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_smdeliverynotintended), "sm-deliveryNotIntended", "decoding", false)
				}
				decVal_smdeliverynotintended, intErr := ber.DecodeEnumeratedValue(rawVal_smdeliverynotintended)
				if intErr != nil {
					return qualifyBERError(intErr, "sm-deliveryNotIntended", "decoding", false)
				}
				tmp_smdeliverynotintended := SMDeliveryNotIntended(decVal_smdeliverynotintended)
				v.SmDeliveryNotIntended = &tmp_smdeliverynotintended
				if offset < 0 || offset >
					len(content) || n_smdeliverynotintended < 0 || n_smdeliverynotintended >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_smdeliverynotintended
			}
		}
	}
	// Decode ip-sm-gwGuidanceIndicator
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 11 {
				ber.MarkPreflightTarget(opts, "ip-sm-gwGuidanceIndicator", content[offset:])
				decodedTag_ipsmgwguidanceindicator, n_ipsmgwguidanceindicator, rawVal_ipsmgwguidanceindicator, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "ip-sm-gwGuidanceIndicator", "decoding", false)
				}
				if decodedTag_ipsmgwguidanceindicator.Class != tag.ClassContextSpecific || decodedTag_ipsmgwguidanceindicator.Number != 11 || decodedTag_ipsmgwguidanceindicator.Constructed != false {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_ipsmgwguidanceindicator), "ip-sm-gwGuidanceIndicator", "decoding", false)
				}
				if len(rawVal_ipsmgwguidanceindicator) != 0 {
					return qualifyBERError(fmt.Errorf("%w: NULL content length %d", ber.ErrInvalidValue, len(rawVal_ipsmgwguidanceindicator)), "ip-sm-gwGuidanceIndicator", "decoding", false)
				}
				v.IpSmGwGuidanceIndicator = &struct{}{}
				if offset < 0 || offset >
					len(content) || n_ipsmgwguidanceindicator < 0 || n_ipsmgwguidanceindicator >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_ipsmgwguidanceindicator
			}
		}
	}
	// Decode imsi
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 12 {
				ber.MarkPreflightTarget(opts, "imsi", content[offset:])
				decodedTag_imsi, n_imsi, rawVal_imsi, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "imsi", "decoding", false)
				}
				if decodedTag_imsi.Class != tag.ClassContextSpecific || decodedTag_imsi.Number != 12 {
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
					if constraintErr := checkDecodedLength(opts, s949588_0, "51.5", "imsi", "SIZE (3..8)", len(*v.Imsi)); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode t4-Trigger-Indicator
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 14 {
				ber.MarkPreflightTarget(opts, "t4-Trigger-Indicator", content[offset:])
				decodedTag_t4triggerindicator, n_t4triggerindicator, rawVal_t4triggerindicator, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "t4-Trigger-Indicator", "decoding", false)
				}
				if decodedTag_t4triggerindicator.Class != tag.ClassContextSpecific || decodedTag_t4triggerindicator.Number != 14 || decodedTag_t4triggerindicator.Constructed != false {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_t4triggerindicator), "t4-Trigger-Indicator", "decoding", false)
				}
				if len(rawVal_t4triggerindicator) != 0 {
					return qualifyBERError(fmt.Errorf("%w: NULL content length %d", ber.ErrInvalidValue, len(rawVal_t4triggerindicator)), "t4-Trigger-Indicator", "decoding", false)
				}
				v.T4TriggerIndicator = &struct{}{}
				if offset < 0 || offset >
					len(content) || n_t4triggerindicator < 0 || n_t4triggerindicator >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_t4triggerindicator
			}
		}
	}
	// Decode singleAttemptDelivery
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 13 {
				ber.MarkPreflightTarget(opts, "singleAttemptDelivery", content[offset:])
				decodedTag_singleattemptdelivery, n_singleattemptdelivery, rawVal_singleattemptdelivery, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "singleAttemptDelivery", "decoding", false)
				}
				if decodedTag_singleattemptdelivery.Class != tag.ClassContextSpecific || decodedTag_singleattemptdelivery.Number != 13 || decodedTag_singleattemptdelivery.Constructed != false {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_singleattemptdelivery), "singleAttemptDelivery", "decoding", false)
				}
				if len(rawVal_singleattemptdelivery) != 0 {
					return qualifyBERError(fmt.Errorf("%w: NULL content length %d", ber.ErrInvalidValue, len(rawVal_singleattemptdelivery)), "singleAttemptDelivery", "decoding", false)
				}
				v.SingleAttemptDelivery = &struct{}{}
				if offset < 0 || offset >
					len(content) || n_singleattemptdelivery < 0 || n_singleattemptdelivery >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_singleattemptdelivery
			}
		}
	}
	// Decode correlationID
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 15 {
				ber.MarkPreflightTarget(opts, "correlationID", content[offset:])
				decodedTag_correlationid, n_correlationid, rawVal_correlationid, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "correlationID", "decoding", false)
				}
				if decodedTag_correlationid.Class != tag.ClassContextSpecific || decodedTag_correlationid.Number != 15 || decodedTag_correlationid.Constructed != true {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_correlationid), "correlationID", "decoding", false)
				}
				_ = rawVal_correlationid
				if offset < 0 || offset >
					len(content) || n_correlationid < 0 || n_correlationid > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				reconstructed_correlationid, reconstructionErr_correlationid := ber.EncodeImplicitTagWithClass(tag.ClassUniversal, tag.TagSequence, content[offset:offset+n_correlationid])
				if reconstructionErr_correlationid != nil {
					return qualifyBERError(reconstructionErr_correlationid, "correlationID", "decoding", false)
				}
				var dec_correlationid CorrelationID
				if unmErr := dec_correlationid.UnmarshalBER(reconstructed_correlationid, ber.ChildDecodeOptions(opts, "correlationID")...); unmErr != nil {
					return qualifyBERError(unmErr, "correlationID", "decoding", false)
				}
				v.CorrelationID = &dec_correlationid
				if offset < 0 || offset >
					len(content) || n_correlationid < 0 || n_correlationid > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_correlationid
			}
		}
	}
	// Decode smsf-supportIndicator
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 16 {
				ber.MarkPreflightTarget(opts, "smsf-supportIndicator", content[offset:])
				decodedTag_smsfsupportindicator, n_smsfsupportindicator, rawVal_smsfsupportindicator, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "smsf-supportIndicator", "decoding", false)
				}
				if decodedTag_smsfsupportindicator.Class != tag.ClassContextSpecific || decodedTag_smsfsupportindicator.Number != 16 || decodedTag_smsfsupportindicator.Constructed != false {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_smsfsupportindicator), "smsf-supportIndicator", "decoding", false)
				}
				if len(rawVal_smsfsupportindicator) != 0 {
					return qualifyBERError(fmt.Errorf("%w: NULL content length %d", ber.ErrInvalidValue, len(rawVal_smsfsupportindicator)), "smsf-supportIndicator", "decoding", false)
				}
				v.SmsfSupportIndicator = &struct{}{}
				if offset < 0 || offset >
					len(content) || n_smsfsupportindicator < 0 || n_smsfsupportindicator >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_smsfsupportindicator
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		peekTag, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:], opts...)
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "RoutingInfoForSMArg", Cause: extErr_}
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: the first unknown addition must differ from trailing OPTIONAL/DEFAULT tags.
		if len(v.ExtData_) == 0 && ((peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 16) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 15) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 13) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 14) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 12) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 11) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 10) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 9) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 8) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 7) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 6)) {
			if !ber.ToleranceEnabled(opts) {
				return &ber.DecodeError{Offset: offset, TypeName: "RoutingInfoForSMArg", Cause: fmt.Errorf("%w: repeated or out-of-order SEQUENCE component tag %s", ber.ErrInvalidTag, peekTag)}
			}
			if orderErr_ := ber.CheckDecodedValue(ber.DecodeRule(opts, s949588_0, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), fmt.Sprintf("ExtData_[%d]", len(v.ExtData_)), "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); orderErr_ != nil {
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

// MarshalBER encodes RoutingInfoForSMRes to BER format.
func (v *RoutingInfoForSMRes) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {

	if v == nil {
		return nil, fmt.Errorf("%w: RoutingInfoForSMRes receiver is nil", ber.ErrInvalidValue)
	}
	return marshalFramedValue(v, v.berReplayNode_, opts, (*RoutingInfoForSMRes).MarshalBER, (*RoutingInfoForSMRes).marshalBER, 3)

}
func (v *RoutingInfoForSMRes) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if len(v.Imsi) < 3 || len(v.Imsi) > 8 {
		if constraintErr := checkEncodedLength(opts, s949588_1, "51.5", "imsi", "SIZE (3..8)", len(v.Imsi)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_imsi, encodeErr_enc_imsi := ber.EncodeOctetString([]byte(v.Imsi))
	if encodeErr_enc_imsi != nil {
		return nil, qualifyBERError(encodeErr_enc_imsi, "imsi", "encoding", false)
	}
	children = append(children, enc_imsi...)
	enc_locationinfowithlmsi, err := v.LocationInfoWithLMSI.MarshalBER(ber.ChildEncodeOptions(opts, "locationInfoWithLMSI")...)
	if err != nil {
		return nil, qualifyBERError(err, "locationInfoWithLMSI", "encoding", false)
	}
	retagged_enc_locationinfowithlmsi, tagErr_enc_locationinfowithlmsi := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_locationinfowithlmsi)
	if tagErr_enc_locationinfowithlmsi != nil {
		return nil, qualifyBERError(tagErr_enc_locationinfowithlmsi, "locationInfoWithLMSI", "encoding", false)
	}
	enc_locationinfowithlmsi = retagged_enc_locationinfowithlmsi
	ber.RecordGeneratedBERChildPlacement(opts, len(children), enc_locationinfowithlmsi)
	children = append(children, enc_locationinfowithlmsi...)
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
	if v.IpSmGwGuidance != nil {
		enc_ipsmgwguidance, err := v.IpSmGwGuidance.MarshalBER(ber.ChildEncodeOptions(opts, "ip-sm-gwGuidance")...)
		if err != nil {
			return nil, qualifyBERError(err, "ip-sm-gwGuidance", "encoding", false)
		}
		retagged_enc_ipsmgwguidance, tagErr_enc_ipsmgwguidance := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 5, enc_ipsmgwguidance)
		if tagErr_enc_ipsmgwguidance != nil {
			return nil, qualifyBERError(tagErr_enc_ipsmgwguidance, "ip-sm-gwGuidance", "encoding", false)
		}
		enc_ipsmgwguidance = retagged_enc_ipsmgwguidance
		ber.RecordGeneratedBERChildPlacement(opts, len(children), enc_ipsmgwguidance)
		children = append(children, enc_ipsmgwguidance...)
	}
	base_ := -1
	for i, ext := range v.ExtData_ {
		if err := checkOpaqueAddition(ext, opts, s949588_1, children, i, &base_); err != nil {
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
		if i == 0 && ((peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 5) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4)) {
			if constraintErr := ber.CheckEncodedValue(ber.EncodeRule(opts, s949588_1, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
				return nil, constraintErr
			}
		}
		children = append(children, ext...)
	}
	ber.RecordGeneratedBERContainer(opts, children)
	return ber.EncodeSequence(children)
}
func (v *RoutingInfoForSMRes) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// MarshalDER encodes RoutingInfoForSMRes to DER format.
// Opaque descendants pass generic DER checks; foreign schema rules need a typed binding.
func (v *RoutingInfoForSMRes) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: RoutingInfoForSMRes receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if len(v.Imsi) < 3 || len(v.Imsi) > 8 {
		if constraintErr := checkEncodedLength(nil, s949588_1, "51.5", "imsi", "SIZE (3..8)", len(v.Imsi)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_imsi, encodeErr_enc_imsi := ber.EncodeOctetString([]byte(v.Imsi))
	if encodeErr_enc_imsi != nil {
		return nil, qualifyBERError(encodeErr_enc_imsi, "imsi", "encoding", true)
	}
	children = append(children, enc_imsi...)
	enc_locationinfowithlmsi, err := v.LocationInfoWithLMSI.MarshalDER()
	if err != nil {
		return nil, qualifyBERError(err, "locationInfoWithLMSI", "encoding", true)
	}
	retagged_enc_locationinfowithlmsi, tagErr_enc_locationinfowithlmsi := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_locationinfowithlmsi)
	if tagErr_enc_locationinfowithlmsi != nil {
		return nil, qualifyBERError(tagErr_enc_locationinfowithlmsi, "locationInfoWithLMSI", "encoding", true)
	}
	enc_locationinfowithlmsi = retagged_enc_locationinfowithlmsi
	children = append(children, enc_locationinfowithlmsi...)
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
	if v.IpSmGwGuidance != nil {
		enc_ipsmgwguidance, err := v.IpSmGwGuidance.MarshalDER()
		if err != nil {
			return nil, qualifyBERError(err, "ip-sm-gwGuidance", "encoding", true)
		}
		retagged_enc_ipsmgwguidance, tagErr_enc_ipsmgwguidance := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 5, enc_ipsmgwguidance)
		if tagErr_enc_ipsmgwguidance != nil {
			return nil, qualifyBERError(tagErr_enc_ipsmgwguidance, "ip-sm-gwGuidance", "encoding", true)
		}
		enc_ipsmgwguidance = retagged_enc_ipsmgwguidance
		children = append(children, enc_ipsmgwguidance...)
	}
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDEREncodedElement(ext); err != nil {
			return nil, invalidDERAddition(ext, s949588_1, children, i)
		}
		peekTag, _, _, extErr := ber.DecodeEncodedTLV(ext)
		if extErr != nil {
			return nil, extErr
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: only the first addition is restricted.
		if i == 0 && ((peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 5) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4)) {
			if constraintErr := ber.CheckEncodedValue(ber.EncodeRule(nil, s949588_1, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
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
		return nil, fmt.Errorf("%s: %w", "encoding RoutingInfoForSMRes as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}
func (v *RoutingInfoForSMRes) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	encoded, err := v.MarshalDER()
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBER decodes RoutingInfoForSMRes from BER/DER format.
func (destination *RoutingInfoForSMRes) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if destination == nil {
		return fmt.Errorf("%w: RoutingInfoForSMRes destination is nil", ber.ErrInvalidValue)
	}
	v := new(RoutingInfoForSMRes)

	defer publishDecodedValue(destination, v, &returnErr)

	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	preparedData, preparedOptions, prepareErr := prepareCompositeBER(data, opts, s949588_1, "child", (*RoutingInfoForSMRes).UnmarshalBER)
	if prepareErr != nil {
		return prepareErr
	}
	data, opts = preparedData, preparedOptions

	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
	*v = RoutingInfoForSMRes{}
	defer func() {
		if returnErr == nil {
			returnErr = completeValueBER(data,
				opts, v, &v.berReplayNode_, (*RoutingInfoForSMRes).MarshalBER)
		}

	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("%s: %w", "decoding RoutingInfoForSMRes SEQUENCE", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "RoutingInfoForSMRes", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode imsi
	if offset >= len(content) {
		return fmt.Errorf("missing required field imsi")
	}
	{
		ber.MarkPreflightTarget(opts, "imsi", content[offset:])
		val_imsi, n, err := ber.DecodeOctetString(content[offset:], opts...)
		if err != nil {
			return qualifyBERError(err, "imsi", "decoding", false)
		}
		v.Imsi = IMSI(val_imsi)
		if offset > len(content) || n < 0 || n > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n
		if len(v.Imsi) < 3 || len(v.Imsi) > 8 {
			if constraintErr := checkDecodedLength(opts, s949588_1, "51.5", "imsi", "SIZE (3..8)", len(v.Imsi)); constraintErr != nil {
				return constraintErr
			}
		}
	}
	// Decode locationInfoWithLMSI
	if offset >= len(content) {
		return fmt.Errorf("missing required field locationInfoWithLMSI")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 0 {
			return fmt.Errorf("expected tag [%s %d] for locationInfoWithLMSI, got %s", "CONTEXT", 0, reqTag_)
		}
	}
	{
		ber.MarkPreflightTarget(opts, "locationInfoWithLMSI", content[offset:])
		decodedTag_locationinfowithlmsi, n_locationinfowithlmsi, rawVal_locationinfowithlmsi, err := ber.DecodeTLV(content[offset:], opts...)
		if err != nil {
			return qualifyBERError(err, "locationInfoWithLMSI", "decoding", false)
		}
		if decodedTag_locationinfowithlmsi.Class != tag.ClassContextSpecific || decodedTag_locationinfowithlmsi.Number != 0 || decodedTag_locationinfowithlmsi.Constructed != true {
			return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_locationinfowithlmsi), "locationInfoWithLMSI", "decoding", false)
		}
		_ = rawVal_locationinfowithlmsi
		if offset < 0 || offset >
			len(content) || n_locationinfowithlmsi < 0 || n_locationinfowithlmsi >
			len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		reconstructed_locationinfowithlmsi, reconstructionErr_locationinfowithlmsi := ber.EncodeImplicitTagWithClass(tag.ClassUniversal, tag.TagSequence, content[offset:offset+n_locationinfowithlmsi])
		if reconstructionErr_locationinfowithlmsi != nil {
			return qualifyBERError(reconstructionErr_locationinfowithlmsi, "locationInfoWithLMSI", "decoding", false)
		}
		if unmErr := v.LocationInfoWithLMSI.UnmarshalBER(reconstructed_locationinfowithlmsi, ber.ChildDecodeOptions(opts, "locationInfoWithLMSI")...); unmErr != nil {
			return qualifyBERError(unmErr, "locationInfoWithLMSI", "decoding", false)
		}
		if offset < 0 || offset >
			len(content) || n_locationinfowithlmsi < 0 || n_locationinfowithlmsi >
			len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n_locationinfowithlmsi
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
	// Decode ip-sm-gwGuidance
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 5 {
				ber.MarkPreflightTarget(opts, "ip-sm-gwGuidance", content[offset:])
				decodedTag_ipsmgwguidance, n_ipsmgwguidance, rawVal_ipsmgwguidance, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "ip-sm-gwGuidance", "decoding", false)
				}
				if decodedTag_ipsmgwguidance.Class != tag.ClassContextSpecific || decodedTag_ipsmgwguidance.Number != 5 || decodedTag_ipsmgwguidance.Constructed != true {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_ipsmgwguidance), "ip-sm-gwGuidance", "decoding", false)
				}
				_ = rawVal_ipsmgwguidance
				if offset < 0 || offset >
					len(content) || n_ipsmgwguidance < 0 || n_ipsmgwguidance > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				reconstructed_ipsmgwguidance, reconstructionErr_ipsmgwguidance := ber.EncodeImplicitTagWithClass(tag.ClassUniversal, tag.TagSequence, content[offset:offset+n_ipsmgwguidance])
				if reconstructionErr_ipsmgwguidance != nil {
					return qualifyBERError(reconstructionErr_ipsmgwguidance, "ip-sm-gwGuidance", "decoding", false)
				}
				var dec_ipsmgwguidance IPSMGWGuidance
				if unmErr := dec_ipsmgwguidance.UnmarshalBER(reconstructed_ipsmgwguidance, ber.ChildDecodeOptions(opts, "ip-sm-gwGuidance")...); unmErr != nil {
					return qualifyBERError(unmErr, "ip-sm-gwGuidance", "decoding", false)
				}
				v.IpSmGwGuidance = &dec_ipsmgwguidance
				if offset < 0 || offset >
					len(content) || n_ipsmgwguidance < 0 || n_ipsmgwguidance > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_ipsmgwguidance
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		peekTag, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:], opts...)
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "RoutingInfoForSMRes", Cause: extErr_}
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: the first unknown addition must differ from trailing OPTIONAL/DEFAULT tags.
		if len(v.ExtData_) == 0 && ((peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 5) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4)) {
			if !ber.ToleranceEnabled(opts) {
				return &ber.DecodeError{Offset: offset, TypeName: "RoutingInfoForSMRes", Cause: fmt.Errorf("%w: repeated or out-of-order SEQUENCE component tag %s", ber.ErrInvalidTag, peekTag)}
			}
			if orderErr_ := ber.CheckDecodedValue(ber.DecodeRule(opts, s949588_1, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), fmt.Sprintf("ExtData_[%d]", len(v.ExtData_)), "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); orderErr_ != nil {
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

// MarshalBER encodes IPSMGWGuidance to BER format.
func (v *IPSMGWGuidance) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {

	if v == nil {
		return nil, fmt.Errorf("%w: IPSMGWGuidance receiver is nil", ber.ErrInvalidValue)
	}
	return marshalFramedValue(v, v.berReplayNode_, opts, (*IPSMGWGuidance).MarshalBER, (*IPSMGWGuidance).marshalBER, 3)

}
func (v *IPSMGWGuidance) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if !(int64(v.MinimumDeliveryTimeValue) >= 30 && int64(v.MinimumDeliveryTimeValue) <= 600) {
		if constraintErr := checkEncodedValue(opts, s949588_2, "51.4", "minimumDeliveryTimeValue", "(30..600)", ber.ObserveInteger(int64(v.MinimumDeliveryTimeValue))); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_minimumdeliverytimevalue := ber.EncodeInteger(int64(v.MinimumDeliveryTimeValue))
	children = append(children, enc_minimumdeliverytimevalue...)
	if !(int64(v.RecommendedDeliveryTimeValue) >= 30 && int64(v.RecommendedDeliveryTimeValue) <= 600) {
		if constraintErr := checkEncodedValue(opts, s949588_2, "51.4", "recommendedDeliveryTimeValue", "(30..600)", ber.ObserveInteger(int64(v.RecommendedDeliveryTimeValue))); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_recommendeddeliverytimevalue := ber.EncodeInteger(int64(v.RecommendedDeliveryTimeValue))
	children = append(children, enc_recommendeddeliverytimevalue...)
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
		if err := checkOpaqueAddition(ext, opts, s949588_2, children, i, &base_); err != nil {
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
			if constraintErr := ber.CheckEncodedValue(ber.EncodeRule(opts, s949588_2, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
				return nil, constraintErr
			}
		}
		children = append(children, ext...)
	}
	ber.RecordGeneratedBERContainer(opts, children)
	return ber.EncodeSequence(children)
}
func (v *IPSMGWGuidance) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// MarshalDER encodes IPSMGWGuidance to DER format.
// Opaque descendants pass generic DER checks; foreign schema rules need a typed binding.
func (v *IPSMGWGuidance) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: IPSMGWGuidance receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if !(int64(v.MinimumDeliveryTimeValue) >= 30 && int64(v.MinimumDeliveryTimeValue) <= 600) {
		if constraintErr := checkEncodedValue(nil, s949588_2, "51.4", "minimumDeliveryTimeValue", "(30..600)", ber.ObserveInteger(int64(v.MinimumDeliveryTimeValue))); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_minimumdeliverytimevalue := ber.EncodeInteger(int64(v.MinimumDeliveryTimeValue))
	children = append(children, enc_minimumdeliverytimevalue...)
	if !(int64(v.RecommendedDeliveryTimeValue) >= 30 && int64(v.RecommendedDeliveryTimeValue) <= 600) {
		if constraintErr := checkEncodedValue(nil, s949588_2, "51.4", "recommendedDeliveryTimeValue", "(30..600)", ber.ObserveInteger(int64(v.RecommendedDeliveryTimeValue))); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_recommendeddeliverytimevalue := ber.EncodeInteger(int64(v.RecommendedDeliveryTimeValue))
	children = append(children, enc_recommendeddeliverytimevalue...)
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalDER()
		if err != nil {
			return nil, qualifyBERError(err, "extensionContainer", "encoding", true)
		}
		children = append(children, enc_extensioncontainer...)
	}
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDEREncodedElement(ext); err != nil {
			return nil, invalidDERAddition(ext, s949588_2, children, i)
		}
		peekTag, _, _, extErr := ber.DecodeEncodedTLV(ext)
		if extErr != nil {
			return nil, extErr
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: only the first addition is restricted.
		if i == 0 && (peekTag.Class == tag.ClassUniversal && peekTag.Number == 16) {
			if constraintErr := ber.CheckEncodedValue(ber.EncodeRule(nil, s949588_2, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
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
		return nil, fmt.Errorf("%s: %w", "encoding IPSMGWGuidance as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}
func (v *IPSMGWGuidance) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	encoded, err := v.MarshalDER()
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBER decodes IPSMGWGuidance from BER/DER format.
func (destination *IPSMGWGuidance) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if destination == nil {
		return fmt.Errorf("%w: IPSMGWGuidance destination is nil", ber.ErrInvalidValue)
	}
	v := new(IPSMGWGuidance)

	defer publishDecodedValue(destination, v, &returnErr)

	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	preparedData, preparedOptions, prepareErr := prepareCompositeBER(data, opts, s949588_2, "child", (*IPSMGWGuidance).UnmarshalBER)
	if prepareErr != nil {
		return prepareErr
	}
	data, opts = preparedData, preparedOptions

	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
	*v = IPSMGWGuidance{}
	defer func() {
		if returnErr == nil {
			returnErr = completeValueBER(data,
				opts, v, &v.berReplayNode_, (*IPSMGWGuidance).MarshalBER)
		}

	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("%s: %w", "decoding IPSMGWGuidance SEQUENCE", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "IPSMGWGuidance", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode minimumDeliveryTimeValue
	if offset >= len(content) {
		return fmt.Errorf("missing required field minimumDeliveryTimeValue")
	}
	{
		ber.MarkPreflightTarget(opts, "minimumDeliveryTimeValue", content[offset:])
		val_minimumdeliverytimevalue, n, err := ber.DecodeInteger(content[offset:], opts...)
		if err != nil {
			return qualifyBERError(err, "minimumDeliveryTimeValue", "decoding", false)
		}
		v.MinimumDeliveryTimeValue = SMDeliveryTimerValue(val_minimumdeliverytimevalue)
		if offset > len(content) || n < 0 || n > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n
		if !(int64(v.MinimumDeliveryTimeValue) >= 30 && int64(v.MinimumDeliveryTimeValue) <= 600) {
			if constraintErr := checkDecodedValue(opts, s949588_2, "51.4", "minimumDeliveryTimeValue", "(30..600)", ber.ObserveInteger(int64(v.MinimumDeliveryTimeValue))); constraintErr != nil {
				return constraintErr
			}
		}
	}
	// Decode recommendedDeliveryTimeValue
	if offset >= len(content) {
		return fmt.Errorf("missing required field recommendedDeliveryTimeValue")
	}
	{
		ber.MarkPreflightTarget(opts, "recommendedDeliveryTimeValue", content[offset:])
		val_recommendeddeliverytimevalue, n, err := ber.DecodeInteger(content[offset:], opts...)
		if err != nil {
			return qualifyBERError(err, "recommendedDeliveryTimeValue", "decoding", false)
		}
		v.RecommendedDeliveryTimeValue = SMDeliveryTimerValue(val_recommendeddeliverytimevalue)
		if offset < 0 || offset >
			len(content) || n < 0 || n > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n
		if !(int64(v.RecommendedDeliveryTimeValue) >= 30 && int64(v.RecommendedDeliveryTimeValue) <= 600) {
			if constraintErr := checkDecodedValue(opts, s949588_2, "51.4", "recommendedDeliveryTimeValue", "(30..600)", ber.ObserveInteger(int64(v.RecommendedDeliveryTimeValue))); constraintErr != nil {
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
			return &ber.DecodeError{Offset: offset, TypeName: "IPSMGWGuidance", Cause: extErr_}
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: the first unknown addition must differ from trailing OPTIONAL/DEFAULT tags.
		if len(v.ExtData_) == 0 && (peekTag.Class == tag.ClassUniversal && peekTag.Number == 16) {
			if !ber.ToleranceEnabled(opts) {
				return &ber.DecodeError{Offset: offset, TypeName: "IPSMGWGuidance", Cause: fmt.Errorf("%w: repeated or out-of-order SEQUENCE component tag %s", ber.ErrInvalidTag, peekTag)}
			}
			if orderErr_ := ber.CheckDecodedValue(ber.DecodeRule(opts, s949588_2, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), fmt.Sprintf("ExtData_[%d]", len(v.ExtData_)), "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); orderErr_ != nil {
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

// MarshalBER encodes LocationInfoWithLMSI to BER format.
func (v *LocationInfoWithLMSI) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {

	if v == nil {
		return nil, fmt.Errorf("%w: LocationInfoWithLMSI receiver is nil", ber.ErrInvalidValue)
	}
	return marshalFramedValue(v, v.berReplayNode_, opts, (*LocationInfoWithLMSI).MarshalBER, (*LocationInfoWithLMSI).marshalBER, 3)

}
func (v *LocationInfoWithLMSI) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if len(v.NetworkNodeNumber) < 1 || len(v.NetworkNodeNumber) > 9 {
		if constraintErr := checkEncodedLength(opts, s949588_3, "51.5", "networkNode-Number", "SIZE (1..9)", len(v.NetworkNodeNumber)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	if len(v.NetworkNodeNumber) < 1 || len(v.NetworkNodeNumber) > 20 {
		if constraintErr := checkEncodedLength(opts, s949588_3, "51.5", "networkNode-Number", "SIZE (1..20)", len(v.NetworkNodeNumber)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_networknodenumber, encodeErr_enc_networknodenumber := ber.EncodeOctetString([]byte(v.NetworkNodeNumber))
	if encodeErr_enc_networknodenumber != nil {
		return nil, qualifyBERError(encodeErr_enc_networknodenumber, "networkNode-Number", "encoding", false)
	}
	retagged_enc_networknodenumber, tagErr_enc_networknodenumber := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_networknodenumber)
	if tagErr_enc_networknodenumber != nil {
		return nil, qualifyBERError(tagErr_enc_networknodenumber, "networkNode-Number", "encoding", false)
	}
	enc_networknodenumber = retagged_enc_networknodenumber
	children = append(children, enc_networknodenumber...)
	if v.Lmsi != nil {
		if len(*v.Lmsi) < 4 || len(*v.Lmsi) > 4 {
			if constraintErr := checkEncodedLength(opts, s949588_3, "51.5", "lmsi", "SIZE (4)", len(*v.Lmsi)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_lmsi, encodeErr_enc_lmsi := ber.EncodeOctetString([]byte(*v.Lmsi))
		if encodeErr_enc_lmsi != nil {
			return nil, qualifyBERError(encodeErr_enc_lmsi, "lmsi", "encoding", false)
		}
		children = append(children, enc_lmsi...)
	}
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalBER(ber.ChildEncodeOptions(opts, "extensionContainer")...)
		if err != nil {
			return nil, qualifyBERError(err, "extensionContainer", "encoding", false)
		}
		ber.RecordGeneratedBERChildPlacement(opts, len(children), enc_extensioncontainer)
		children = append(children, enc_extensioncontainer...)
	}
	if v.GprsNodeIndicator != nil {
		enc_gprsnodeindicator := ber.EncodeNull()
		retagged_enc_gprsnodeindicator, tagErr_enc_gprsnodeindicator := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 5, enc_gprsnodeindicator)
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
			enc_additionalnumber, encodeErr = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 6, enc_additionalnumber)
			if encodeErr != nil {
				return nil, qualifyBERError(encodeErr, "additional-Number", "encoding", false)
			}
		}
		ber.RecordGeneratedBERChildPlacement(opts, len(children), enc_additionalnumber)
		children = append(children, enc_additionalnumber...)
	}
	if v.NetworkNodeDiameterAddress != nil {
		enc_networknodediameteraddress, err := v.NetworkNodeDiameterAddress.MarshalBER(ber.ChildEncodeOptions(opts, "networkNodeDiameterAddress")...)
		if err != nil {
			return nil, qualifyBERError(err, "networkNodeDiameterAddress", "encoding", false)
		}
		retagged_enc_networknodediameteraddress, tagErr_enc_networknodediameteraddress := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 7, enc_networknodediameteraddress)
		if tagErr_enc_networknodediameteraddress != nil {
			return nil, qualifyBERError(tagErr_enc_networknodediameteraddress, "networkNodeDiameterAddress", "encoding", false)
		}
		enc_networknodediameteraddress = retagged_enc_networknodediameteraddress
		ber.RecordGeneratedBERChildPlacement(opts, len(children), enc_networknodediameteraddress)
		children = append(children, enc_networknodediameteraddress...)
	}
	if v.AdditionalNetworkNodeDiameterAddress != nil {
		enc_additionalnetworknodediameteraddress, err := v.AdditionalNetworkNodeDiameterAddress.MarshalBER(ber.ChildEncodeOptions(opts, "additionalNetworkNodeDiameterAddress")...)
		if err != nil {
			return nil, qualifyBERError(err, "additionalNetworkNodeDiameterAddress", "encoding", false)
		}
		retagged_enc_additionalnetworknodediameteraddress, tagErr_enc_additionalnetworknodediameteraddress := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 8, enc_additionalnetworknodediameteraddress)
		if tagErr_enc_additionalnetworknodediameteraddress != nil {
			return nil, qualifyBERError(tagErr_enc_additionalnetworknodediameteraddress, "additionalNetworkNodeDiameterAddress", "encoding", false)
		}
		enc_additionalnetworknodediameteraddress = retagged_enc_additionalnetworknodediameteraddress
		ber.RecordGeneratedBERChildPlacement(opts, len(children), enc_additionalnetworknodediameteraddress)
		children = append(children, enc_additionalnetworknodediameteraddress...)
	}
	if v.ThirdNumber != nil {
		enc_thirdnumber, err := v.ThirdNumber.MarshalBER(ber.ChildEncodeOptions(opts, "thirdNumber")...)
		if err != nil {
			return nil, qualifyBERError(err, "thirdNumber", "encoding", false)
		}
		{
			var encodeErr error
			enc_thirdnumber, encodeErr = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 9, enc_thirdnumber)
			if encodeErr != nil {
				return nil, qualifyBERError(encodeErr, "thirdNumber", "encoding", false)
			}
		}
		ber.RecordGeneratedBERChildPlacement(opts, len(children), enc_thirdnumber)
		children = append(children, enc_thirdnumber...)
	}
	if v.ThirdNetworkNodeDiameterAddress != nil {
		enc_thirdnetworknodediameteraddress, err := v.ThirdNetworkNodeDiameterAddress.MarshalBER(ber.ChildEncodeOptions(opts, "thirdNetworkNodeDiameterAddress")...)
		if err != nil {
			return nil, qualifyBERError(err, "thirdNetworkNodeDiameterAddress", "encoding", false)
		}
		retagged_enc_thirdnetworknodediameteraddress, tagErr_enc_thirdnetworknodediameteraddress := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 10, enc_thirdnetworknodediameteraddress)
		if tagErr_enc_thirdnetworknodediameteraddress != nil {
			return nil, qualifyBERError(tagErr_enc_thirdnetworknodediameteraddress, "thirdNetworkNodeDiameterAddress", "encoding", false)
		}
		enc_thirdnetworknodediameteraddress = retagged_enc_thirdnetworknodediameteraddress
		ber.RecordGeneratedBERChildPlacement(opts, len(children), enc_thirdnetworknodediameteraddress)
		children = append(children, enc_thirdnetworknodediameteraddress...)
	}
	if v.ImsNodeIndicator != nil {
		enc_imsnodeindicator := ber.EncodeNull()
		retagged_enc_imsnodeindicator, tagErr_enc_imsnodeindicator := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 11, enc_imsnodeindicator)
		if tagErr_enc_imsnodeindicator != nil {
			return nil, qualifyBERError(tagErr_enc_imsnodeindicator, "imsNodeIndicator", "encoding", false)
		}
		enc_imsnodeindicator = retagged_enc_imsnodeindicator
		children = append(children, enc_imsnodeindicator...)
	}
	if v.Smsf3gppNumber != nil {
		if len(*v.Smsf3gppNumber) < 1 || len(*v.Smsf3gppNumber) > 9 {
			if constraintErr := checkEncodedLength(opts, s949588_3, "51.5", "smsf-3gpp-Number", "SIZE (1..9)", len(*v.Smsf3gppNumber)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		if len(*v.Smsf3gppNumber) < 1 || len(*v.Smsf3gppNumber) > 20 {
			if constraintErr := checkEncodedLength(opts, s949588_3, "51.5", "smsf-3gpp-Number", "SIZE (1..20)", len(*v.Smsf3gppNumber)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_smsf3gppnumber, encodeErr_enc_smsf3gppnumber := ber.EncodeOctetString([]byte(*v.Smsf3gppNumber))
		if encodeErr_enc_smsf3gppnumber != nil {
			return nil, qualifyBERError(encodeErr_enc_smsf3gppnumber, "smsf-3gpp-Number", "encoding", false)
		}
		retagged_enc_smsf3gppnumber, tagErr_enc_smsf3gppnumber := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 12, enc_smsf3gppnumber)
		if tagErr_enc_smsf3gppnumber != nil {
			return nil, qualifyBERError(tagErr_enc_smsf3gppnumber, "smsf-3gpp-Number", "encoding", false)
		}
		enc_smsf3gppnumber = retagged_enc_smsf3gppnumber
		children = append(children, enc_smsf3gppnumber...)
	}
	if v.Smsf3gppDiameterAddress != nil {
		enc_smsf3gppdiameteraddress, err := v.Smsf3gppDiameterAddress.MarshalBER(ber.ChildEncodeOptions(opts, "smsf-3gpp-DiameterAddress")...)
		if err != nil {
			return nil, qualifyBERError(err, "smsf-3gpp-DiameterAddress", "encoding", false)
		}
		retagged_enc_smsf3gppdiameteraddress, tagErr_enc_smsf3gppdiameteraddress := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 13, enc_smsf3gppdiameteraddress)
		if tagErr_enc_smsf3gppdiameteraddress != nil {
			return nil, qualifyBERError(tagErr_enc_smsf3gppdiameteraddress, "smsf-3gpp-DiameterAddress", "encoding", false)
		}
		enc_smsf3gppdiameteraddress = retagged_enc_smsf3gppdiameteraddress
		ber.RecordGeneratedBERChildPlacement(opts, len(children), enc_smsf3gppdiameteraddress)
		children = append(children, enc_smsf3gppdiameteraddress...)
	}
	if v.SmsfNon3gppNumber != nil {
		if len(*v.SmsfNon3gppNumber) < 1 || len(*v.SmsfNon3gppNumber) > 9 {
			if constraintErr := checkEncodedLength(opts, s949588_3, "51.5", "smsf-non-3gpp-Number", "SIZE (1..9)", len(*v.SmsfNon3gppNumber)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		if len(*v.SmsfNon3gppNumber) < 1 || len(*v.SmsfNon3gppNumber) > 20 {
			if constraintErr := checkEncodedLength(opts, s949588_3, "51.5", "smsf-non-3gpp-Number", "SIZE (1..20)", len(*v.SmsfNon3gppNumber)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_smsfnon3gppnumber, encodeErr_enc_smsfnon3gppnumber := ber.EncodeOctetString([]byte(*v.SmsfNon3gppNumber))
		if encodeErr_enc_smsfnon3gppnumber != nil {
			return nil, qualifyBERError(encodeErr_enc_smsfnon3gppnumber, "smsf-non-3gpp-Number", "encoding", false)
		}
		retagged_enc_smsfnon3gppnumber, tagErr_enc_smsfnon3gppnumber := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 14, enc_smsfnon3gppnumber)
		if tagErr_enc_smsfnon3gppnumber != nil {
			return nil, qualifyBERError(tagErr_enc_smsfnon3gppnumber, "smsf-non-3gpp-Number", "encoding", false)
		}
		enc_smsfnon3gppnumber = retagged_enc_smsfnon3gppnumber
		children = append(children, enc_smsfnon3gppnumber...)
	}
	if v.SmsfNon3gppDiameterAddress != nil {
		enc_smsfnon3gppdiameteraddress, err := v.SmsfNon3gppDiameterAddress.MarshalBER(ber.ChildEncodeOptions(opts, "smsf-non-3gpp-DiameterAddress")...)
		if err != nil {
			return nil, qualifyBERError(err, "smsf-non-3gpp-DiameterAddress", "encoding", false)
		}
		retagged_enc_smsfnon3gppdiameteraddress, tagErr_enc_smsfnon3gppdiameteraddress := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 15, enc_smsfnon3gppdiameteraddress)
		if tagErr_enc_smsfnon3gppdiameteraddress != nil {
			return nil, qualifyBERError(tagErr_enc_smsfnon3gppdiameteraddress, "smsf-non-3gpp-DiameterAddress", "encoding", false)
		}
		enc_smsfnon3gppdiameteraddress = retagged_enc_smsfnon3gppdiameteraddress
		ber.RecordGeneratedBERChildPlacement(opts, len(children), enc_smsfnon3gppdiameteraddress)
		children = append(children, enc_smsfnon3gppdiameteraddress...)
	}
	if v.Smsf3gppAddressIndicator != nil {
		enc_smsf3gppaddressindicator := ber.EncodeNull()
		retagged_enc_smsf3gppaddressindicator, tagErr_enc_smsf3gppaddressindicator := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 16, enc_smsf3gppaddressindicator)
		if tagErr_enc_smsf3gppaddressindicator != nil {
			return nil, qualifyBERError(tagErr_enc_smsf3gppaddressindicator, "smsf-3gpp-address-indicator", "encoding", false)
		}
		enc_smsf3gppaddressindicator = retagged_enc_smsf3gppaddressindicator
		children = append(children, enc_smsf3gppaddressindicator...)
	}
	if v.SmsfNon3gppAddressIndicator != nil {
		enc_smsfnon3gppaddressindicator := ber.EncodeNull()
		retagged_enc_smsfnon3gppaddressindicator, tagErr_enc_smsfnon3gppaddressindicator := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 17, enc_smsfnon3gppaddressindicator)
		if tagErr_enc_smsfnon3gppaddressindicator != nil {
			return nil, qualifyBERError(tagErr_enc_smsfnon3gppaddressindicator, "smsf-non-3gpp-address-indicator", "encoding", false)
		}
		enc_smsfnon3gppaddressindicator = retagged_enc_smsfnon3gppaddressindicator
		children = append(children, enc_smsfnon3gppaddressindicator...)
	}
	base_ := -1
	for i, ext := range v.ExtData_ {
		if err := checkOpaqueAddition(ext, opts, s949588_3, children, i, &base_); err != nil {
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
		if i == 0 && ((peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 17) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 16) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 15) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 14) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 13) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 12) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 11) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 10) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 9) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 8) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 7) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 6) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 5) || (peekTag.Class == tag.ClassUniversal && peekTag.Number == 16) || (peekTag.Class == tag.ClassUniversal && peekTag.Number == 4)) {
			if constraintErr := ber.CheckEncodedValue(ber.EncodeRule(opts, s949588_3, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
				return nil, constraintErr
			}
		}
		children = append(children, ext...)
	}
	ber.RecordGeneratedBERContainer(opts, children)
	return ber.EncodeSequence(children)
}
func (v *LocationInfoWithLMSI) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// MarshalDER encodes LocationInfoWithLMSI to DER format.
// Opaque descendants pass generic DER checks; foreign schema rules need a typed binding.
func (v *LocationInfoWithLMSI) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: LocationInfoWithLMSI receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if len(v.NetworkNodeNumber) < 1 || len(v.NetworkNodeNumber) > 9 {
		if constraintErr := checkEncodedLength(nil, s949588_3, "51.5", "networkNode-Number", "SIZE (1..9)", len(v.NetworkNodeNumber)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	if len(v.NetworkNodeNumber) < 1 || len(v.NetworkNodeNumber) > 20 {
		if constraintErr := checkEncodedLength(nil, s949588_3, "51.5", "networkNode-Number", "SIZE (1..20)", len(v.NetworkNodeNumber)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_networknodenumber, encodeErr_enc_networknodenumber := ber.EncodeOctetString([]byte(v.NetworkNodeNumber))
	if encodeErr_enc_networknodenumber != nil {
		return nil, qualifyBERError(encodeErr_enc_networknodenumber, "networkNode-Number", "encoding", true)
	}
	retagged_enc_networknodenumber, tagErr_enc_networknodenumber := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_networknodenumber)
	if tagErr_enc_networknodenumber != nil {
		return nil, qualifyBERError(tagErr_enc_networknodenumber, "networkNode-Number", "encoding", true)
	}
	enc_networknodenumber = retagged_enc_networknodenumber
	children = append(children, enc_networknodenumber...)
	if v.Lmsi != nil {
		if len(*v.Lmsi) < 4 || len(*v.Lmsi) > 4 {
			if constraintErr := checkEncodedLength(nil, s949588_3, "51.5", "lmsi", "SIZE (4)", len(*v.Lmsi)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_lmsi, encodeErr_enc_lmsi := ber.EncodeOctetString([]byte(*v.Lmsi))
		if encodeErr_enc_lmsi != nil {
			return nil, qualifyBERError(encodeErr_enc_lmsi, "lmsi", "encoding", true)
		}
		children = append(children, enc_lmsi...)
	}
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalDER()
		if err != nil {
			return nil, qualifyBERError(err, "extensionContainer", "encoding", true)
		}
		children = append(children, enc_extensioncontainer...)
	}
	if v.GprsNodeIndicator != nil {
		enc_gprsnodeindicator := ber.EncodeNull()
		retagged_enc_gprsnodeindicator, tagErr_enc_gprsnodeindicator := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 5, enc_gprsnodeindicator)
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
			enc_additionalnumber, encodeErr = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 6, enc_additionalnumber)
			if encodeErr != nil {
				return nil, qualifyBERError(encodeErr, "additional-Number", "encoding", true)
			}
		}
		children = append(children, enc_additionalnumber...)
	}
	if v.NetworkNodeDiameterAddress != nil {
		enc_networknodediameteraddress, err := v.NetworkNodeDiameterAddress.MarshalDER()
		if err != nil {
			return nil, qualifyBERError(err, "networkNodeDiameterAddress", "encoding", true)
		}
		retagged_enc_networknodediameteraddress, tagErr_enc_networknodediameteraddress := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 7, enc_networknodediameteraddress)
		if tagErr_enc_networknodediameteraddress != nil {
			return nil, qualifyBERError(tagErr_enc_networknodediameteraddress, "networkNodeDiameterAddress", "encoding", true)
		}
		enc_networknodediameteraddress = retagged_enc_networknodediameteraddress
		children = append(children, enc_networknodediameteraddress...)
	}
	if v.AdditionalNetworkNodeDiameterAddress != nil {
		enc_additionalnetworknodediameteraddress, err := v.AdditionalNetworkNodeDiameterAddress.MarshalDER()
		if err != nil {
			return nil, qualifyBERError(err, "additionalNetworkNodeDiameterAddress", "encoding", true)
		}
		retagged_enc_additionalnetworknodediameteraddress, tagErr_enc_additionalnetworknodediameteraddress := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 8, enc_additionalnetworknodediameteraddress)
		if tagErr_enc_additionalnetworknodediameteraddress != nil {
			return nil, qualifyBERError(tagErr_enc_additionalnetworknodediameteraddress, "additionalNetworkNodeDiameterAddress", "encoding", true)
		}
		enc_additionalnetworknodediameteraddress = retagged_enc_additionalnetworknodediameteraddress
		children = append(children, enc_additionalnetworknodediameteraddress...)
	}
	if v.ThirdNumber != nil {
		enc_thirdnumber, err := v.ThirdNumber.MarshalDER()
		if err != nil {
			return nil, qualifyBERError(err, "thirdNumber", "encoding", true)
		}
		{
			var encodeErr error
			enc_thirdnumber, encodeErr = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 9, enc_thirdnumber)
			if encodeErr != nil {
				return nil, qualifyBERError(encodeErr, "thirdNumber", "encoding", true)
			}
		}
		children = append(children, enc_thirdnumber...)
	}
	if v.ThirdNetworkNodeDiameterAddress != nil {
		enc_thirdnetworknodediameteraddress, err := v.ThirdNetworkNodeDiameterAddress.MarshalDER()
		if err != nil {
			return nil, qualifyBERError(err, "thirdNetworkNodeDiameterAddress", "encoding", true)
		}
		retagged_enc_thirdnetworknodediameteraddress, tagErr_enc_thirdnetworknodediameteraddress := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 10, enc_thirdnetworknodediameteraddress)
		if tagErr_enc_thirdnetworknodediameteraddress != nil {
			return nil, qualifyBERError(tagErr_enc_thirdnetworknodediameteraddress, "thirdNetworkNodeDiameterAddress", "encoding", true)
		}
		enc_thirdnetworknodediameteraddress = retagged_enc_thirdnetworknodediameteraddress
		children = append(children, enc_thirdnetworknodediameteraddress...)
	}
	if v.ImsNodeIndicator != nil {
		enc_imsnodeindicator := ber.EncodeNull()
		retagged_enc_imsnodeindicator, tagErr_enc_imsnodeindicator := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 11, enc_imsnodeindicator)
		if tagErr_enc_imsnodeindicator != nil {
			return nil, qualifyBERError(tagErr_enc_imsnodeindicator, "imsNodeIndicator", "encoding", true)
		}
		enc_imsnodeindicator = retagged_enc_imsnodeindicator
		children = append(children, enc_imsnodeindicator...)
	}
	if v.Smsf3gppNumber != nil {
		if len(*v.Smsf3gppNumber) < 1 || len(*v.Smsf3gppNumber) > 9 {
			if constraintErr := checkEncodedLength(nil, s949588_3, "51.5", "smsf-3gpp-Number", "SIZE (1..9)", len(*v.Smsf3gppNumber)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		if len(*v.Smsf3gppNumber) < 1 || len(*v.Smsf3gppNumber) > 20 {
			if constraintErr := checkEncodedLength(nil, s949588_3, "51.5", "smsf-3gpp-Number", "SIZE (1..20)", len(*v.Smsf3gppNumber)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_smsf3gppnumber, encodeErr_enc_smsf3gppnumber := ber.EncodeOctetString([]byte(*v.Smsf3gppNumber))
		if encodeErr_enc_smsf3gppnumber != nil {
			return nil, qualifyBERError(encodeErr_enc_smsf3gppnumber, "smsf-3gpp-Number", "encoding", true)
		}
		retagged_enc_smsf3gppnumber, tagErr_enc_smsf3gppnumber := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 12, enc_smsf3gppnumber)
		if tagErr_enc_smsf3gppnumber != nil {
			return nil, qualifyBERError(tagErr_enc_smsf3gppnumber, "smsf-3gpp-Number", "encoding", true)
		}
		enc_smsf3gppnumber = retagged_enc_smsf3gppnumber
		children = append(children, enc_smsf3gppnumber...)
	}
	if v.Smsf3gppDiameterAddress != nil {
		enc_smsf3gppdiameteraddress, err := v.Smsf3gppDiameterAddress.MarshalDER()
		if err != nil {
			return nil, qualifyBERError(err, "smsf-3gpp-DiameterAddress", "encoding", true)
		}
		retagged_enc_smsf3gppdiameteraddress, tagErr_enc_smsf3gppdiameteraddress := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 13, enc_smsf3gppdiameteraddress)
		if tagErr_enc_smsf3gppdiameteraddress != nil {
			return nil, qualifyBERError(tagErr_enc_smsf3gppdiameteraddress, "smsf-3gpp-DiameterAddress", "encoding", true)
		}
		enc_smsf3gppdiameteraddress = retagged_enc_smsf3gppdiameteraddress
		children = append(children, enc_smsf3gppdiameteraddress...)
	}
	if v.SmsfNon3gppNumber != nil {
		if len(*v.SmsfNon3gppNumber) < 1 || len(*v.SmsfNon3gppNumber) > 9 {
			if constraintErr := checkEncodedLength(nil, s949588_3, "51.5", "smsf-non-3gpp-Number", "SIZE (1..9)", len(*v.SmsfNon3gppNumber)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		if len(*v.SmsfNon3gppNumber) < 1 || len(*v.SmsfNon3gppNumber) > 20 {
			if constraintErr := checkEncodedLength(nil, s949588_3, "51.5", "smsf-non-3gpp-Number", "SIZE (1..20)", len(*v.SmsfNon3gppNumber)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_smsfnon3gppnumber, encodeErr_enc_smsfnon3gppnumber := ber.EncodeOctetString([]byte(*v.SmsfNon3gppNumber))
		if encodeErr_enc_smsfnon3gppnumber != nil {
			return nil, qualifyBERError(encodeErr_enc_smsfnon3gppnumber, "smsf-non-3gpp-Number", "encoding", true)
		}
		retagged_enc_smsfnon3gppnumber, tagErr_enc_smsfnon3gppnumber := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 14, enc_smsfnon3gppnumber)
		if tagErr_enc_smsfnon3gppnumber != nil {
			return nil, qualifyBERError(tagErr_enc_smsfnon3gppnumber, "smsf-non-3gpp-Number", "encoding", true)
		}
		enc_smsfnon3gppnumber = retagged_enc_smsfnon3gppnumber
		children = append(children, enc_smsfnon3gppnumber...)
	}
	if v.SmsfNon3gppDiameterAddress != nil {
		enc_smsfnon3gppdiameteraddress, err := v.SmsfNon3gppDiameterAddress.MarshalDER()
		if err != nil {
			return nil, qualifyBERError(err, "smsf-non-3gpp-DiameterAddress", "encoding", true)
		}
		retagged_enc_smsfnon3gppdiameteraddress, tagErr_enc_smsfnon3gppdiameteraddress := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 15, enc_smsfnon3gppdiameteraddress)
		if tagErr_enc_smsfnon3gppdiameteraddress != nil {
			return nil, qualifyBERError(tagErr_enc_smsfnon3gppdiameteraddress, "smsf-non-3gpp-DiameterAddress", "encoding", true)
		}
		enc_smsfnon3gppdiameteraddress = retagged_enc_smsfnon3gppdiameteraddress
		children = append(children, enc_smsfnon3gppdiameteraddress...)
	}
	if v.Smsf3gppAddressIndicator != nil {
		enc_smsf3gppaddressindicator := ber.EncodeNull()
		retagged_enc_smsf3gppaddressindicator, tagErr_enc_smsf3gppaddressindicator := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 16, enc_smsf3gppaddressindicator)
		if tagErr_enc_smsf3gppaddressindicator != nil {
			return nil, qualifyBERError(tagErr_enc_smsf3gppaddressindicator, "smsf-3gpp-address-indicator", "encoding", true)
		}
		enc_smsf3gppaddressindicator = retagged_enc_smsf3gppaddressindicator
		children = append(children, enc_smsf3gppaddressindicator...)
	}
	if v.SmsfNon3gppAddressIndicator != nil {
		enc_smsfnon3gppaddressindicator := ber.EncodeNull()
		retagged_enc_smsfnon3gppaddressindicator, tagErr_enc_smsfnon3gppaddressindicator := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 17, enc_smsfnon3gppaddressindicator)
		if tagErr_enc_smsfnon3gppaddressindicator != nil {
			return nil, qualifyBERError(tagErr_enc_smsfnon3gppaddressindicator, "smsf-non-3gpp-address-indicator", "encoding", true)
		}
		enc_smsfnon3gppaddressindicator = retagged_enc_smsfnon3gppaddressindicator
		children = append(children, enc_smsfnon3gppaddressindicator...)
	}
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDEREncodedElement(ext); err != nil {
			return nil, invalidDERAddition(ext, s949588_3, children, i)
		}
		peekTag, _, _, extErr := ber.DecodeEncodedTLV(ext)
		if extErr != nil {
			return nil, extErr
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: only the first addition is restricted.
		if i == 0 && ((peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 17) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 16) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 15) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 14) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 13) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 12) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 11) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 10) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 9) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 8) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 7) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 6) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 5) || (peekTag.Class == tag.ClassUniversal && peekTag.Number == 16) || (peekTag.Class == tag.ClassUniversal && peekTag.Number == 4)) {
			if constraintErr := ber.CheckEncodedValue(ber.EncodeRule(nil, s949588_3, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
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
		return nil, fmt.Errorf("%s: %w", "encoding LocationInfoWithLMSI as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}
func (v *LocationInfoWithLMSI) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	encoded, err := v.MarshalDER()
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBER decodes LocationInfoWithLMSI from BER/DER format.
func (destination *LocationInfoWithLMSI) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if destination == nil {
		return fmt.Errorf("%w: LocationInfoWithLMSI destination is nil", ber.ErrInvalidValue)
	}
	v := new(LocationInfoWithLMSI)

	defer publishDecodedValue(destination, v, &returnErr)

	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	preparedData, preparedOptions, prepareErr := prepareCompositeBER(data, opts, s949588_3, "child", (*LocationInfoWithLMSI).UnmarshalBER)
	if prepareErr != nil {
		return prepareErr
	}
	data, opts = preparedData, preparedOptions

	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
	*v = LocationInfoWithLMSI{}
	defer func() {
		if returnErr == nil {
			returnErr = completeValueBER(data,
				opts, v, &v.berReplayNode_, (*LocationInfoWithLMSI).MarshalBER)
		}

	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("%s: %w", "decoding LocationInfoWithLMSI SEQUENCE", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "LocationInfoWithLMSI", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode networkNode-Number
	if offset >= len(content) {
		return fmt.Errorf("missing required field networkNode-Number")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 1 {
			return fmt.Errorf("expected tag [%s %d] for networkNode-Number, got %s", "CONTEXT", 1, reqTag_)
		}
	}
	{
		ber.MarkPreflightTarget(opts, "networkNode-Number", content[offset:])
		decodedTag_networknodenumber, n_networknodenumber, rawVal_networknodenumber, err := ber.DecodeTLV(content[offset:], opts...)
		if err != nil {
			return qualifyBERError(err, "networkNode-Number", "decoding", false)
		}
		if decodedTag_networknodenumber.Class != tag.ClassContextSpecific || decodedTag_networknodenumber.Number != 1 {
			return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_networknodenumber), "networkNode-Number", "decoding", false)
		}
		decVal_networknodenumber, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_networknodenumber.Constructed, rawVal_networknodenumber, opts...)
		if octetErr != nil {
			return qualifyBERError(octetErr, "networkNode-Number", "decoding", false)
		}
		v.NetworkNodeNumber = ISDNAddressString(decVal_networknodenumber)
		if offset > len(content) || n_networknodenumber < 0 || n_networknodenumber > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n_networknodenumber
		if len(v.NetworkNodeNumber) < 1 || len(v.NetworkNodeNumber) > 9 {
			if constraintErr := checkDecodedLength(opts, s949588_3, "51.5", "networkNode-Number", "SIZE (1..9)", len(v.NetworkNodeNumber)); constraintErr != nil {
				return constraintErr
			}
		}
		if len(v.NetworkNodeNumber) < 1 || len(v.NetworkNodeNumber) > 20 {
			if constraintErr := checkDecodedLength(opts, s949588_3, "51.5", "networkNode-Number", "SIZE (1..20)", len(v.NetworkNodeNumber)); constraintErr != nil {
				return constraintErr
			}
		}
	}
	// Decode lmsi
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassUniversal && peekTag.Number == 4 {
				ber.MarkPreflightTarget(opts, "lmsi", content[offset:])
				val_lmsi, n, err := ber.DecodeOctetString(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "lmsi", "decoding", false)
				}
				tmp_lmsi := LMSI(val_lmsi)
				v.Lmsi = &tmp_lmsi
				if offset < 0 || offset >
					len(content) || n < 0 || n > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n
				if len(*v.Lmsi) < 4 || len(*v.Lmsi) > 4 {
					if constraintErr := checkDecodedLength(opts, s949588_3, "51.5", "lmsi", "SIZE (4)", len(*v.Lmsi)); constraintErr != nil {
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
	// Decode gprsNodeIndicator
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 5 {
				ber.MarkPreflightTarget(opts, "gprsNodeIndicator", content[offset:])
				decodedTag_gprsnodeindicator, n_gprsnodeindicator, rawVal_gprsnodeindicator, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "gprsNodeIndicator", "decoding", false)
				}
				if decodedTag_gprsnodeindicator.Class != tag.ClassContextSpecific || decodedTag_gprsnodeindicator.Number != 5 || decodedTag_gprsnodeindicator.Constructed != false {
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
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 6 {
				ber.MarkPreflightTarget(opts, "additional-Number", content[offset:])
				decodedTag_additionalnumber, n_additionalnumber, innerData_additionalnumber, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "additional-Number", "decoding", false)
				}
				if decodedTag_additionalnumber.Class != tag.ClassContextSpecific || decodedTag_additionalnumber.Number != 6 || decodedTag_additionalnumber.Constructed != true {
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
				var dec_additionalnumber AdditionalNumber
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
	// Decode networkNodeDiameterAddress
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 7 {
				ber.MarkPreflightTarget(opts, "networkNodeDiameterAddress", content[offset:])
				decodedTag_networknodediameteraddress, n_networknodediameteraddress, rawVal_networknodediameteraddress, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "networkNodeDiameterAddress", "decoding", false)
				}
				if decodedTag_networknodediameteraddress.Class != tag.ClassContextSpecific || decodedTag_networknodediameteraddress.Number != 7 || decodedTag_networknodediameteraddress.Constructed != true {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_networknodediameteraddress), "networkNodeDiameterAddress", "decoding", false)
				}
				_ = rawVal_networknodediameteraddress
				if offset < 0 || offset >
					len(content) || n_networknodediameteraddress < 0 || n_networknodediameteraddress >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				reconstructed_networknodediameteraddress, reconstructionErr_networknodediameteraddress := ber.EncodeImplicitTagWithClass(tag.ClassUniversal, tag.TagSequence, content[offset:offset+n_networknodediameteraddress])
				if reconstructionErr_networknodediameteraddress != nil {
					return qualifyBERError(reconstructionErr_networknodediameteraddress, "networkNodeDiameterAddress", "decoding", false)
				}
				var dec_networknodediameteraddress NetworkNodeDiameterAddress
				if unmErr := dec_networknodediameteraddress.UnmarshalBER(reconstructed_networknodediameteraddress, ber.ChildDecodeOptions(opts, "networkNodeDiameterAddress")...); unmErr != nil {
					return qualifyBERError(unmErr, "networkNodeDiameterAddress", "decoding", false)
				}
				v.NetworkNodeDiameterAddress = &dec_networknodediameteraddress
				if offset < 0 || offset >
					len(content) || n_networknodediameteraddress < 0 || n_networknodediameteraddress >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_networknodediameteraddress
			}
		}
	}
	// Decode additionalNetworkNodeDiameterAddress
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 8 {
				ber.MarkPreflightTarget(opts, "additionalNetworkNodeDiameterAddress", content[offset:])
				decodedTag_additionalnetworknodediameteraddress, n_additionalnetworknodediameteraddress, rawVal_additionalnetworknodediameteraddress, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "additionalNetworkNodeDiameterAddress", "decoding", false)
				}
				if decodedTag_additionalnetworknodediameteraddress.Class != tag.ClassContextSpecific || decodedTag_additionalnetworknodediameteraddress.Number != 8 || decodedTag_additionalnetworknodediameteraddress.Constructed != true {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_additionalnetworknodediameteraddress), "additionalNetworkNodeDiameterAddress", "decoding", false)
				}
				_ = rawVal_additionalnetworknodediameteraddress
				if offset < 0 || offset >
					len(content) || n_additionalnetworknodediameteraddress < 0 ||
					n_additionalnetworknodediameteraddress > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				reconstructed_additionalnetworknodediameteraddress, reconstructionErr_additionalnetworknodediameteraddress := ber.EncodeImplicitTagWithClass(tag.ClassUniversal, tag.TagSequence, content[offset:offset+n_additionalnetworknodediameteraddress])
				if reconstructionErr_additionalnetworknodediameteraddress != nil {
					return qualifyBERError(reconstructionErr_additionalnetworknodediameteraddress, "additionalNetworkNodeDiameterAddress", "decoding", false)
				}
				var dec_additionalnetworknodediameteraddress NetworkNodeDiameterAddress
				if unmErr := dec_additionalnetworknodediameteraddress.UnmarshalBER(reconstructed_additionalnetworknodediameteraddress, ber.ChildDecodeOptions(opts, "additionalNetworkNodeDiameterAddress")...); unmErr != nil {
					return qualifyBERError(unmErr, "additionalNetworkNodeDiameterAddress", "decoding", false)
				}
				v.AdditionalNetworkNodeDiameterAddress = &dec_additionalnetworknodediameteraddress
				if offset < 0 || offset >
					len(content) || n_additionalnetworknodediameteraddress < 0 ||
					n_additionalnetworknodediameteraddress > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_additionalnetworknodediameteraddress
			}
		}
	}
	// Decode thirdNumber
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 9 {
				ber.MarkPreflightTarget(opts, "thirdNumber", content[offset:])
				decodedTag_thirdnumber, n_thirdnumber, innerData_thirdnumber, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "thirdNumber", "decoding", false)
				}
				if decodedTag_thirdnumber.Class != tag.ClassContextSpecific || decodedTag_thirdnumber.Number != 9 || decodedTag_thirdnumber.Constructed != true {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_thirdnumber), "thirdNumber", "decoding", false)
				}
				_, innerUsed_thirdnumber, _, innerErr_thirdnumber := ber.DecodeTLV(innerData_thirdnumber, opts...)
				if innerErr_thirdnumber != nil {
					return qualifyBERError(innerErr_thirdnumber, "thirdNumber", "decoding", false)
				}
				if innerUsed_thirdnumber != len(innerData_thirdnumber) {
					return qualifyBERError(ber.ErrExtraData, "thirdNumber", "decoding", false)
				}
				// Decode inner value from explicit tag wrapper
				ber.MarkPreflightTarget(opts, "thirdNumber", innerData_thirdnumber)
				var dec_thirdnumber AdditionalNumber
				if unmErr := dec_thirdnumber.UnmarshalBER(innerData_thirdnumber, ber.ChildDecodeOptions(opts, "thirdNumber")...); unmErr != nil {
					return qualifyBERError(unmErr, "thirdNumber", "decoding", false)
				}
				v.ThirdNumber = &dec_thirdnumber
				if offset < 0 || offset >
					len(content) || n_thirdnumber < 0 || n_thirdnumber > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_thirdnumber
			}
		}
	}
	// Decode thirdNetworkNodeDiameterAddress
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 10 {
				ber.MarkPreflightTarget(opts, "thirdNetworkNodeDiameterAddress", content[offset:])
				decodedTag_thirdnetworknodediameteraddress, n_thirdnetworknodediameteraddress, rawVal_thirdnetworknodediameteraddress, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "thirdNetworkNodeDiameterAddress", "decoding", false)
				}
				if decodedTag_thirdnetworknodediameteraddress.Class != tag.ClassContextSpecific || decodedTag_thirdnetworknodediameteraddress.Number != 10 || decodedTag_thirdnetworknodediameteraddress.Constructed != true {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_thirdnetworknodediameteraddress), "thirdNetworkNodeDiameterAddress", "decoding", false)
				}
				_ = rawVal_thirdnetworknodediameteraddress
				if offset < 0 || offset >
					len(content) || n_thirdnetworknodediameteraddress < 0 || n_thirdnetworknodediameteraddress >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				reconstructed_thirdnetworknodediameteraddress, reconstructionErr_thirdnetworknodediameteraddress := ber.EncodeImplicitTagWithClass(tag.ClassUniversal, tag.TagSequence, content[offset:offset+n_thirdnetworknodediameteraddress])
				if reconstructionErr_thirdnetworknodediameteraddress != nil {
					return qualifyBERError(reconstructionErr_thirdnetworknodediameteraddress, "thirdNetworkNodeDiameterAddress", "decoding", false)
				}
				var dec_thirdnetworknodediameteraddress NetworkNodeDiameterAddress
				if unmErr := dec_thirdnetworknodediameteraddress.UnmarshalBER(reconstructed_thirdnetworknodediameteraddress, ber.ChildDecodeOptions(opts, "thirdNetworkNodeDiameterAddress")...); unmErr != nil {
					return qualifyBERError(unmErr, "thirdNetworkNodeDiameterAddress", "decoding", false)
				}
				v.ThirdNetworkNodeDiameterAddress = &dec_thirdnetworknodediameteraddress
				if offset < 0 || offset >
					len(content) || n_thirdnetworknodediameteraddress < 0 || n_thirdnetworknodediameteraddress >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_thirdnetworknodediameteraddress
			}
		}
	}
	// Decode imsNodeIndicator
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 11 {
				ber.MarkPreflightTarget(opts, "imsNodeIndicator", content[offset:])
				decodedTag_imsnodeindicator, n_imsnodeindicator, rawVal_imsnodeindicator, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "imsNodeIndicator", "decoding", false)
				}
				if decodedTag_imsnodeindicator.Class != tag.ClassContextSpecific || decodedTag_imsnodeindicator.Number != 11 || decodedTag_imsnodeindicator.Constructed != false {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_imsnodeindicator), "imsNodeIndicator", "decoding", false)
				}
				if len(rawVal_imsnodeindicator) != 0 {
					return qualifyBERError(fmt.Errorf("%w: NULL content length %d", ber.ErrInvalidValue, len(rawVal_imsnodeindicator)), "imsNodeIndicator", "decoding", false)
				}
				v.ImsNodeIndicator = &struct{}{}
				if offset < 0 || offset >
					len(content) || n_imsnodeindicator < 0 || n_imsnodeindicator >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_imsnodeindicator
			}
		}
	}
	// Decode smsf-3gpp-Number
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 12 {
				ber.MarkPreflightTarget(opts, "smsf-3gpp-Number", content[offset:])
				decodedTag_smsf3gppnumber, n_smsf3gppnumber, rawVal_smsf3gppnumber, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "smsf-3gpp-Number", "decoding", false)
				}
				if decodedTag_smsf3gppnumber.Class != tag.ClassContextSpecific || decodedTag_smsf3gppnumber.Number != 12 {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_smsf3gppnumber), "smsf-3gpp-Number", "decoding", false)
				}
				decVal_smsf3gppnumber, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_smsf3gppnumber.Constructed, rawVal_smsf3gppnumber, opts...)
				if octetErr != nil {
					return qualifyBERError(octetErr, "smsf-3gpp-Number", "decoding", false)
				}
				tmp_smsf3gppnumber := ISDNAddressString(decVal_smsf3gppnumber)
				v.Smsf3gppNumber = &tmp_smsf3gppnumber
				if offset < 0 || offset >
					len(content) || n_smsf3gppnumber < 0 || n_smsf3gppnumber > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_smsf3gppnumber
				if len(*v.Smsf3gppNumber) < 1 || len(*v.Smsf3gppNumber) > 9 {
					if constraintErr := checkDecodedLength(opts, s949588_3, "51.5", "smsf-3gpp-Number", "SIZE (1..9)", len(*v.Smsf3gppNumber)); constraintErr != nil {
						return constraintErr
					}
				}
				if len(*v.Smsf3gppNumber) < 1 || len(*v.Smsf3gppNumber) > 20 {
					if constraintErr := checkDecodedLength(opts, s949588_3, "51.5", "smsf-3gpp-Number", "SIZE (1..20)", len(*v.Smsf3gppNumber)); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode smsf-3gpp-DiameterAddress
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 13 {
				ber.MarkPreflightTarget(opts, "smsf-3gpp-DiameterAddress", content[offset:])
				decodedTag_smsf3gppdiameteraddress, n_smsf3gppdiameteraddress, rawVal_smsf3gppdiameteraddress, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "smsf-3gpp-DiameterAddress", "decoding", false)
				}
				if decodedTag_smsf3gppdiameteraddress.Class != tag.ClassContextSpecific || decodedTag_smsf3gppdiameteraddress.Number != 13 || decodedTag_smsf3gppdiameteraddress.Constructed != true {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_smsf3gppdiameteraddress), "smsf-3gpp-DiameterAddress", "decoding", false)
				}
				_ = rawVal_smsf3gppdiameteraddress
				if offset < 0 || offset >
					len(content) || n_smsf3gppdiameteraddress < 0 || n_smsf3gppdiameteraddress >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				reconstructed_smsf3gppdiameteraddress, reconstructionErr_smsf3gppdiameteraddress := ber.EncodeImplicitTagWithClass(tag.ClassUniversal, tag.TagSequence, content[offset:offset+n_smsf3gppdiameteraddress])
				if reconstructionErr_smsf3gppdiameteraddress != nil {
					return qualifyBERError(reconstructionErr_smsf3gppdiameteraddress, "smsf-3gpp-DiameterAddress", "decoding", false)
				}
				var dec_smsf3gppdiameteraddress NetworkNodeDiameterAddress
				if unmErr := dec_smsf3gppdiameteraddress.UnmarshalBER(reconstructed_smsf3gppdiameteraddress, ber.ChildDecodeOptions(opts, "smsf-3gpp-DiameterAddress")...); unmErr != nil {
					return qualifyBERError(unmErr, "smsf-3gpp-DiameterAddress", "decoding", false)
				}
				v.Smsf3gppDiameterAddress = &dec_smsf3gppdiameteraddress
				if offset < 0 || offset >
					len(content) || n_smsf3gppdiameteraddress < 0 || n_smsf3gppdiameteraddress >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_smsf3gppdiameteraddress
			}
		}
	}
	// Decode smsf-non-3gpp-Number
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 14 {
				ber.MarkPreflightTarget(opts, "smsf-non-3gpp-Number", content[offset:])
				decodedTag_smsfnon3gppnumber, n_smsfnon3gppnumber, rawVal_smsfnon3gppnumber, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "smsf-non-3gpp-Number", "decoding", false)
				}
				if decodedTag_smsfnon3gppnumber.Class != tag.ClassContextSpecific || decodedTag_smsfnon3gppnumber.Number != 14 {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_smsfnon3gppnumber), "smsf-non-3gpp-Number", "decoding", false)
				}
				decVal_smsfnon3gppnumber, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_smsfnon3gppnumber.Constructed, rawVal_smsfnon3gppnumber, opts...)
				if octetErr != nil {
					return qualifyBERError(octetErr, "smsf-non-3gpp-Number", "decoding", false)
				}
				tmp_smsfnon3gppnumber := ISDNAddressString(decVal_smsfnon3gppnumber)
				v.SmsfNon3gppNumber = &tmp_smsfnon3gppnumber
				if offset < 0 || offset >
					len(content) || n_smsfnon3gppnumber < 0 || n_smsfnon3gppnumber >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_smsfnon3gppnumber
				if len(*v.SmsfNon3gppNumber) < 1 || len(*v.SmsfNon3gppNumber) > 9 {
					if constraintErr := checkDecodedLength(opts, s949588_3, "51.5", "smsf-non-3gpp-Number", "SIZE (1..9)", len(*v.SmsfNon3gppNumber)); constraintErr != nil {
						return constraintErr
					}
				}
				if len(*v.SmsfNon3gppNumber) < 1 || len(*v.SmsfNon3gppNumber) > 20 {
					if constraintErr := checkDecodedLength(opts, s949588_3, "51.5", "smsf-non-3gpp-Number", "SIZE (1..20)", len(*v.SmsfNon3gppNumber)); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode smsf-non-3gpp-DiameterAddress
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 15 {
				ber.MarkPreflightTarget(opts, "smsf-non-3gpp-DiameterAddress", content[offset:])
				decodedTag_smsfnon3gppdiameteraddress, n_smsfnon3gppdiameteraddress, rawVal_smsfnon3gppdiameteraddress, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "smsf-non-3gpp-DiameterAddress", "decoding", false)
				}
				if decodedTag_smsfnon3gppdiameteraddress.Class != tag.ClassContextSpecific || decodedTag_smsfnon3gppdiameteraddress.Number != 15 || decodedTag_smsfnon3gppdiameteraddress.Constructed != true {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_smsfnon3gppdiameteraddress), "smsf-non-3gpp-DiameterAddress", "decoding", false)
				}
				_ = rawVal_smsfnon3gppdiameteraddress
				if offset < 0 || offset >
					len(content) || n_smsfnon3gppdiameteraddress < 0 || n_smsfnon3gppdiameteraddress >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				reconstructed_smsfnon3gppdiameteraddress, reconstructionErr_smsfnon3gppdiameteraddress := ber.EncodeImplicitTagWithClass(tag.ClassUniversal, tag.TagSequence, content[offset:offset+n_smsfnon3gppdiameteraddress])
				if reconstructionErr_smsfnon3gppdiameteraddress != nil {
					return qualifyBERError(reconstructionErr_smsfnon3gppdiameteraddress, "smsf-non-3gpp-DiameterAddress", "decoding", false)
				}
				var dec_smsfnon3gppdiameteraddress NetworkNodeDiameterAddress
				if unmErr := dec_smsfnon3gppdiameteraddress.UnmarshalBER(reconstructed_smsfnon3gppdiameteraddress, ber.ChildDecodeOptions(opts, "smsf-non-3gpp-DiameterAddress")...); unmErr != nil {
					return qualifyBERError(unmErr, "smsf-non-3gpp-DiameterAddress", "decoding", false)
				}
				v.SmsfNon3gppDiameterAddress = &dec_smsfnon3gppdiameteraddress
				if offset < 0 || offset >
					len(content) || n_smsfnon3gppdiameteraddress < 0 || n_smsfnon3gppdiameteraddress >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_smsfnon3gppdiameteraddress
			}
		}
	}
	// Decode smsf-3gpp-address-indicator
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 16 {
				ber.MarkPreflightTarget(opts, "smsf-3gpp-address-indicator", content[offset:])
				decodedTag_smsf3gppaddressindicator, n_smsf3gppaddressindicator, rawVal_smsf3gppaddressindicator, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "smsf-3gpp-address-indicator", "decoding", false)
				}
				if decodedTag_smsf3gppaddressindicator.Class != tag.ClassContextSpecific || decodedTag_smsf3gppaddressindicator.Number != 16 || decodedTag_smsf3gppaddressindicator.Constructed != false {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_smsf3gppaddressindicator), "smsf-3gpp-address-indicator", "decoding", false)
				}
				if len(rawVal_smsf3gppaddressindicator) != 0 {
					return qualifyBERError(fmt.Errorf("%w: NULL content length %d", ber.ErrInvalidValue, len(rawVal_smsf3gppaddressindicator)), "smsf-3gpp-address-indicator", "decoding", false)
				}
				v.Smsf3gppAddressIndicator = &struct{}{}
				if offset < 0 || offset >
					len(content) || n_smsf3gppaddressindicator < 0 || n_smsf3gppaddressindicator >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_smsf3gppaddressindicator
			}
		}
	}
	// Decode smsf-non-3gpp-address-indicator
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 17 {
				ber.MarkPreflightTarget(opts, "smsf-non-3gpp-address-indicator", content[offset:])
				decodedTag_smsfnon3gppaddressindicator, n_smsfnon3gppaddressindicator, rawVal_smsfnon3gppaddressindicator, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "smsf-non-3gpp-address-indicator", "decoding", false)
				}
				if decodedTag_smsfnon3gppaddressindicator.Class != tag.ClassContextSpecific || decodedTag_smsfnon3gppaddressindicator.Number != 17 || decodedTag_smsfnon3gppaddressindicator.Constructed != false {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_smsfnon3gppaddressindicator), "smsf-non-3gpp-address-indicator", "decoding", false)
				}
				if len(rawVal_smsfnon3gppaddressindicator) != 0 {
					return qualifyBERError(fmt.Errorf("%w: NULL content length %d", ber.ErrInvalidValue, len(rawVal_smsfnon3gppaddressindicator)), "smsf-non-3gpp-address-indicator", "decoding", false)
				}
				v.SmsfNon3gppAddressIndicator = &struct{}{}
				if offset < 0 || offset >
					len(content) || n_smsfnon3gppaddressindicator < 0 || n_smsfnon3gppaddressindicator >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_smsfnon3gppaddressindicator
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		peekTag, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:], opts...)
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "LocationInfoWithLMSI", Cause: extErr_}
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: the first unknown addition must differ from trailing OPTIONAL/DEFAULT tags.
		if len(v.ExtData_) == 0 && ((peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 17) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 16) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 15) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 14) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 13) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 12) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 11) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 10) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 9) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 8) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 7) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 6) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 5) || (peekTag.Class == tag.ClassUniversal && peekTag.Number == 16) || (peekTag.Class == tag.ClassUniversal && peekTag.Number == 4)) {
			if !ber.ToleranceEnabled(opts) {
				return &ber.DecodeError{Offset: offset, TypeName: "LocationInfoWithLMSI", Cause: fmt.Errorf("%w: repeated or out-of-order SEQUENCE component tag %s", ber.ErrInvalidTag, peekTag)}
			}
			if orderErr_ := ber.CheckDecodedValue(ber.DecodeRule(opts, s949588_3, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), fmt.Sprintf("ExtData_[%d]", len(v.ExtData_)), "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); orderErr_ != nil {
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

// MarshalBER encodes AdditionalNumber to BER format.
func (v *AdditionalNumber) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {

	if v == nil {
		return nil, fmt.Errorf("%w: AdditionalNumber receiver is nil", ber.ErrInvalidValue)
	}
	return marshalFramedValue(v, v.berReplayNode_, opts, (*AdditionalNumber).MarshalBER, (*AdditionalNumber).marshalBER, 3)

}
func (v *AdditionalNumber) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}
func (v *AdditionalNumber) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	switch v.Choice {
	case AdditionalNumberChoiceMscNumber:
		if v.MscNumber == nil {
			return nil, fmt.Errorf("%w: choice AdditionalNumber: msc-Number is nil", ber.ErrInvalidValue)
		}
		enc_0, encodeErr_enc_0 := ber.EncodeOctetString([]byte(*v.MscNumber))
		if encodeErr_enc_0 != nil {
			return nil, qualifyBERError(encodeErr_enc_0, "msc-Number", "encoding", false)
		}
		if len(*v.MscNumber) < 1 || len(*v.MscNumber) > 9 {
			if constraintErr := checkEncodedLength(opts, s949588_4, "51.5", "msc-Number", "SIZE (1..9)", len(*v.MscNumber)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		if len(*v.MscNumber) < 1 || len(*v.MscNumber) > 20 {
			if constraintErr := checkEncodedLength(opts, s949588_4, "51.5", "msc-Number", "SIZE (1..20)", len(*v.MscNumber)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		retagged_enc_0, tagErr_enc_0 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_0)
		if tagErr_enc_0 != nil {
			return nil, qualifyBERError(tagErr_enc_0, "msc-Number", "encoding", false)
		}
		enc_0 = retagged_enc_0
		return enc_0, nil
	case AdditionalNumberChoiceSgsnNumber:
		if v.SgsnNumber == nil {
			return nil, fmt.Errorf("%w: choice AdditionalNumber: sgsn-Number is nil", ber.ErrInvalidValue)
		}
		enc_1, encodeErr_enc_1 := ber.EncodeOctetString([]byte(*v.SgsnNumber))
		if encodeErr_enc_1 != nil {
			return nil, qualifyBERError(encodeErr_enc_1, "sgsn-Number", "encoding", false)
		}
		if len(*v.SgsnNumber) < 1 || len(*v.SgsnNumber) > 9 {
			if constraintErr := checkEncodedLength(opts, s949588_4, "51.5", "sgsn-Number", "SIZE (1..9)", len(*v.SgsnNumber)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		if len(*v.SgsnNumber) < 1 || len(*v.SgsnNumber) > 20 {
			if constraintErr := checkEncodedLength(opts, s949588_4, "51.5", "sgsn-Number", "SIZE (1..20)", len(*v.SgsnNumber)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		retagged_enc_1, tagErr_enc_1 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_1)
		if tagErr_enc_1 != nil {
			return nil, qualifyBERError(tagErr_enc_1, "sgsn-Number", "encoding", false)
		}
		enc_1 = retagged_enc_1
		return enc_1, nil
	default:
		return nil, fmt.Errorf("unknown choice %d for AdditionalNumber", v.Choice)
	}
}

// MarshalDER encodes AdditionalNumber to DER format.
// Opaque descendants pass generic DER checks; foreign schema rules need a typed binding.
func (v *AdditionalNumber) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: AdditionalNumber receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER()
	if err != nil {
		return nil, err
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		switch v.Choice {
		case AdditionalNumberChoiceMscNumber:
			return nil, qualifyBERError(err, "msc-Number", "encoding", true)
		case AdditionalNumberChoiceSgsnNumber:
			return nil, qualifyBERError(err, "sgsn-Number", "encoding", true)
		}
		return nil, fmt.Errorf("%s: %w", "encoding AdditionalNumber as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}

func (v *AdditionalNumber) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	encoded, err := v.MarshalDER()
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBER decodes AdditionalNumber from BER/DER format.
func (destination *AdditionalNumber) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if destination == nil {
		return fmt.Errorf("%w: AdditionalNumber destination is nil", ber.ErrInvalidValue)
	}
	v := new(AdditionalNumber)

	defer publishDecodedValue(destination, v, &returnErr)

	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	preparedData, preparedOptions, prepareErr := prepareCompositeBER(data, opts, s949588_4, "child", (*AdditionalNumber).UnmarshalBER)
	if prepareErr != nil {
		return prepareErr
	}
	data, opts = preparedData, preparedOptions
	defer func() {
		if returnErr == nil {
			returnErr = completeValueBER(data,
				opts, v, &v.berReplayNode_, (*AdditionalNumber).MarshalBER)
		}

	}()

	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
	*v = AdditionalNumber{}
	if len(data) == 0 {
		return fmt.Errorf("empty data for AdditionalNumber CHOICE")
	}
	choiceData := data
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for AdditionalNumber: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData, opts...)
	if tlvErr != nil {
		return fmt.Errorf("%s: %w", "decoding AdditionalNumber CHOICE", qualifyBERError(tlvErr, "", "decoding", false))
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "AdditionalNumber", Cause: ber.ErrExtraData}
	}

	if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
		v.Choice = AdditionalNumberChoiceMscNumber
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
		tmp := ISDNAddressString(decVal)
		v.MscNumber = &tmp
		if len(*v.MscNumber) < 1 || len(*v.MscNumber) > 9 {
			if constraintErr := checkDecodedLength(opts, s949588_4, "51.5", "msc-Number", "SIZE (1..9)", len(*v.MscNumber)); constraintErr != nil {
				return constraintErr
			}
		}
		if len(*v.MscNumber) < 1 || len(*v.MscNumber) > 20 {
			if constraintErr := checkDecodedLength(opts, s949588_4, "51.5", "msc-Number", "SIZE (1..20)", len(*v.MscNumber)); constraintErr != nil {
				return constraintErr
			}
		}
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
		v.Choice = AdditionalNumberChoiceSgsnNumber
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
		tmp := ISDNAddressString(decVal)
		v.SgsnNumber = &tmp
		if len(*v.SgsnNumber) < 1 || len(*v.SgsnNumber) > 9 {
			if constraintErr := checkDecodedLength(opts, s949588_4, "51.5", "sgsn-Number", "SIZE (1..9)", len(*v.SgsnNumber)); constraintErr != nil {
				return constraintErr
			}
		}
		if len(*v.SgsnNumber) < 1 || len(*v.SgsnNumber) > 20 {
			if constraintErr := checkDecodedLength(opts, s949588_4, "51.5", "sgsn-Number", "SIZE (1..20)", len(*v.SgsnNumber)); constraintErr != nil {
				return constraintErr
			}
		}
	} else {
		return fmt.Errorf("unknown tag %s for AdditionalNumber CHOICE", peekTag)
	}
	return nil
}

// MarshalBER encodes MOForwardSMArg to BER format.
func (v *MOForwardSMArg) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {

	if v == nil {
		return nil, fmt.Errorf("%w: MOForwardSMArg receiver is nil", ber.ErrInvalidValue)
	}
	return marshalFramedValue(v, v.berReplayNode_, opts, (*MOForwardSMArg).MarshalBER, (*MOForwardSMArg).marshalBER, 3)

}
func (v *MOForwardSMArg) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	enc_smrpda, err := v.SmRPDA.MarshalBER(ber.ChildEncodeOptions(opts, "sm-RP-DA")...)
	if err != nil {
		return nil, qualifyBERError(err, "sm-RP-DA", "encoding", false)
	}
	ber.RecordGeneratedBERChildPlacement(opts, len(children), enc_smrpda)
	children = append(children, enc_smrpda...)
	enc_smrpoa, err := v.SmRPOA.MarshalBER(ber.ChildEncodeOptions(opts, "sm-RP-OA")...)
	if err != nil {
		return nil, qualifyBERError(err, "sm-RP-OA", "encoding", false)
	}
	ber.RecordGeneratedBERChildPlacement(opts, len(children), enc_smrpoa)
	children = append(children, enc_smrpoa...)
	if len(v.SmRPUI) < 1 || len(v.SmRPUI) > 200 {
		if constraintErr := checkEncodedLength(opts, s949588_5, "51.5", "sm-RP-UI", "SIZE (1..200)", len(v.SmRPUI)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_smrpui, encodeErr_enc_smrpui := ber.EncodeOctetString([]byte(v.SmRPUI))
	if encodeErr_enc_smrpui != nil {
		return nil, qualifyBERError(encodeErr_enc_smrpui, "sm-RP-UI", "encoding", false)
	}
	children = append(children, enc_smrpui...)
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalBER(ber.ChildEncodeOptions(opts, "extensionContainer")...)
		if err != nil {
			return nil, qualifyBERError(err, "extensionContainer", "encoding", false)
		}
		ber.RecordGeneratedBERChildPlacement(opts, len(children), enc_extensioncontainer)
		children = append(children, enc_extensioncontainer...)
	}
	if v.Imsi != nil {
		if len(*v.Imsi) < 3 || len(*v.Imsi) > 8 {
			if constraintErr := checkEncodedLength(opts, s949588_5, "51.5", "imsi", "SIZE (3..8)", len(*v.Imsi)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_imsi, encodeErr_enc_imsi := ber.EncodeOctetString([]byte(*v.Imsi))
		if encodeErr_enc_imsi != nil {
			return nil, qualifyBERError(encodeErr_enc_imsi, "imsi", "encoding", false)
		}
		children = append(children, enc_imsi...)
	}
	if v.CorrelationID != nil {
		enc_correlationid, err := v.CorrelationID.MarshalBER(ber.ChildEncodeOptions(opts, "correlationID")...)
		if err != nil {
			return nil, qualifyBERError(err, "correlationID", "encoding", false)
		}
		retagged_enc_correlationid, tagErr_enc_correlationid := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_correlationid)
		if tagErr_enc_correlationid != nil {
			return nil, qualifyBERError(tagErr_enc_correlationid, "correlationID", "encoding", false)
		}
		enc_correlationid = retagged_enc_correlationid
		ber.RecordGeneratedBERChildPlacement(opts, len(children), enc_correlationid)
		children = append(children, enc_correlationid...)
	}
	if v.SmDeliveryOutcome != nil {
		if int64(*v.SmDeliveryOutcome) != 0 && int64(*v.SmDeliveryOutcome) != 1 && int64(*v.SmDeliveryOutcome) != 2 {
			if constraintErr := checkEncodedValue(opts, s949588_5, "20", "sm-DeliveryOutcome", "ENUMERATED {0, 1, 2}", ber.ObserveInteger(int64(*v.SmDeliveryOutcome))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_smdeliveryoutcome := ber.EncodeEnumerated(int64(*v.SmDeliveryOutcome))
		retagged_enc_smdeliveryoutcome, tagErr_enc_smdeliveryoutcome := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_smdeliveryoutcome)
		if tagErr_enc_smdeliveryoutcome != nil {
			return nil, qualifyBERError(tagErr_enc_smdeliveryoutcome, "sm-DeliveryOutcome", "encoding", false)
		}
		enc_smdeliveryoutcome = retagged_enc_smdeliveryoutcome
		children = append(children, enc_smdeliveryoutcome...)
	}
	base_ := -1
	for i, ext := range v.ExtData_ {
		if err := checkOpaqueAddition(ext, opts, s949588_5, children, i, &base_); err != nil {
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
		if i == 0 && ((peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0) || (peekTag.Class == tag.ClassUniversal && peekTag.Number == 4) || (peekTag.Class == tag.ClassUniversal && peekTag.Number == 16)) {
			if constraintErr := ber.CheckEncodedValue(ber.EncodeRule(opts, s949588_5, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
				return nil, constraintErr
			}
		}
		children = append(children, ext...)
	}
	ber.RecordGeneratedBERContainer(opts, children)
	return ber.EncodeSequence(children)
}
func (v *MOForwardSMArg) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// MarshalDER encodes MOForwardSMArg to DER format.
// Opaque descendants pass generic DER checks; foreign schema rules need a typed binding.
func (v *MOForwardSMArg) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: MOForwardSMArg receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	enc_smrpda, err := v.SmRPDA.MarshalDER()
	if err != nil {
		return nil, qualifyBERError(err, "sm-RP-DA", "encoding", true)
	}
	children = append(children, enc_smrpda...)
	enc_smrpoa, err := v.SmRPOA.MarshalDER()
	if err != nil {
		return nil, qualifyBERError(err, "sm-RP-OA", "encoding", true)
	}
	children = append(children, enc_smrpoa...)
	if len(v.SmRPUI) < 1 || len(v.SmRPUI) > 200 {
		if constraintErr := checkEncodedLength(nil, s949588_5, "51.5", "sm-RP-UI", "SIZE (1..200)", len(v.SmRPUI)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_smrpui, encodeErr_enc_smrpui := ber.EncodeOctetString([]byte(v.SmRPUI))
	if encodeErr_enc_smrpui != nil {
		return nil, qualifyBERError(encodeErr_enc_smrpui, "sm-RP-UI", "encoding", true)
	}
	children = append(children, enc_smrpui...)
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalDER()
		if err != nil {
			return nil, qualifyBERError(err, "extensionContainer", "encoding", true)
		}
		children = append(children, enc_extensioncontainer...)
	}
	if v.Imsi != nil {
		if len(*v.Imsi) < 3 || len(*v.Imsi) > 8 {
			if constraintErr := checkEncodedLength(nil, s949588_5, "51.5", "imsi", "SIZE (3..8)", len(*v.Imsi)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_imsi, encodeErr_enc_imsi := ber.EncodeOctetString([]byte(*v.Imsi))
		if encodeErr_enc_imsi != nil {
			return nil, qualifyBERError(encodeErr_enc_imsi, "imsi", "encoding", true)
		}
		children = append(children, enc_imsi...)
	}
	if v.CorrelationID != nil {
		enc_correlationid, err := v.CorrelationID.MarshalDER()
		if err != nil {
			return nil, qualifyBERError(err, "correlationID", "encoding", true)
		}
		retagged_enc_correlationid, tagErr_enc_correlationid := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_correlationid)
		if tagErr_enc_correlationid != nil {
			return nil, qualifyBERError(tagErr_enc_correlationid, "correlationID", "encoding", true)
		}
		enc_correlationid = retagged_enc_correlationid
		children = append(children, enc_correlationid...)
	}
	if v.SmDeliveryOutcome != nil {
		if int64(*v.SmDeliveryOutcome) != 0 && int64(*v.SmDeliveryOutcome) != 1 && int64(*v.SmDeliveryOutcome) != 2 {
			if constraintErr := checkEncodedValue(nil, s949588_5, "20", "sm-DeliveryOutcome", "ENUMERATED {0, 1, 2}", ber.ObserveInteger(int64(*v.SmDeliveryOutcome))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_smdeliveryoutcome := ber.EncodeEnumerated(int64(*v.SmDeliveryOutcome))
		retagged_enc_smdeliveryoutcome, tagErr_enc_smdeliveryoutcome := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_smdeliveryoutcome)
		if tagErr_enc_smdeliveryoutcome != nil {
			return nil, qualifyBERError(tagErr_enc_smdeliveryoutcome, "sm-DeliveryOutcome", "encoding", true)
		}
		enc_smdeliveryoutcome = retagged_enc_smdeliveryoutcome
		children = append(children, enc_smdeliveryoutcome...)
	}
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDEREncodedElement(ext); err != nil {
			return nil, invalidDERAddition(ext, s949588_5, children, i)
		}
		peekTag, _, _, extErr := ber.DecodeEncodedTLV(ext)
		if extErr != nil {
			return nil, extErr
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: only the first addition is restricted.
		if i == 0 && ((peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0) || (peekTag.Class == tag.ClassUniversal && peekTag.Number == 4) || (peekTag.Class == tag.ClassUniversal && peekTag.Number == 16)) {
			if constraintErr := ber.CheckEncodedValue(ber.EncodeRule(nil, s949588_5, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
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
		return nil, fmt.Errorf("%s: %w", "encoding MOForwardSMArg as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}
func (v *MOForwardSMArg) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	encoded, err := v.MarshalDER()
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBER decodes MOForwardSMArg from BER/DER format.
func (destination *MOForwardSMArg) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if destination == nil {
		return fmt.Errorf("%w: MOForwardSMArg destination is nil", ber.ErrInvalidValue)
	}
	v := new(MOForwardSMArg)

	defer publishDecodedValue(destination, v, &returnErr)

	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	preparedData, preparedOptions, prepareErr := prepareCompositeBER(data, opts, s949588_5, "child", (*MOForwardSMArg).UnmarshalBER)
	if prepareErr != nil {
		return prepareErr
	}
	data, opts = preparedData, preparedOptions

	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
	*v = MOForwardSMArg{}
	defer func() {
		if returnErr == nil {
			returnErr = completeValueBER(data,
				opts, v, &v.berReplayNode_, (*MOForwardSMArg).MarshalBER)
		}

	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("%s: %w", "decoding MOForwardSMArg SEQUENCE", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "MOForwardSMArg", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode sm-RP-DA
	if offset >= len(content) {
		return fmt.Errorf("missing required field sm-RP-DA")
	}
	{
		ber.MarkPreflightTarget(opts, "sm-RP-DA", content[offset:])
		// Decode nested CHOICE (SMRPDA)
		_, n_smrpda, _, tlvErr_smrpda := ber.DecodeTLV(content[offset:], opts...)
		if tlvErr_smrpda != nil {
			return qualifyBERError(tlvErr_smrpda, "sm-RP-DA", "decoding", false)
		}
		if offset > len(content) || n_smrpda < 0 || n_smrpda > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		if unmErr := v.SmRPDA.UnmarshalBER(content[offset:offset+n_smrpda], ber.ChildDecodeOptions(opts, "sm-RP-DA")...); unmErr != nil {
			return qualifyBERError(unmErr, "sm-RP-DA", "decoding", false)
		}
		if offset > len(content) || n_smrpda < 0 || n_smrpda > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n_smrpda
	}
	// Decode sm-RP-OA
	if offset >= len(content) {
		return fmt.Errorf("missing required field sm-RP-OA")
	}
	{
		ber.MarkPreflightTarget(opts, "sm-RP-OA", content[offset:])
		// Decode nested CHOICE (SMRPOA)
		_, n_smrpoa, _, tlvErr_smrpoa := ber.DecodeTLV(content[offset:], opts...)
		if tlvErr_smrpoa != nil {
			return qualifyBERError(tlvErr_smrpoa, "sm-RP-OA", "decoding", false)
		}
		if offset < 0 || offset >
			len(content) || n_smrpoa < 0 || n_smrpoa > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		if unmErr := v.SmRPOA.UnmarshalBER(content[offset:offset+n_smrpoa], ber.ChildDecodeOptions(opts, "sm-RP-OA")...); unmErr != nil {
			return qualifyBERError(unmErr, "sm-RP-OA", "decoding", false)
		}
		if offset < 0 || offset >
			len(content) || n_smrpoa < 0 || n_smrpoa > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n_smrpoa
	}
	// Decode sm-RP-UI
	if offset >= len(content) {
		return fmt.Errorf("missing required field sm-RP-UI")
	}
	{
		ber.MarkPreflightTarget(opts, "sm-RP-UI", content[offset:])
		val_smrpui, n, err := ber.DecodeOctetString(content[offset:], opts...)
		if err != nil {
			return qualifyBERError(err, "sm-RP-UI", "decoding", false)
		}
		v.SmRPUI = SignalInfo(val_smrpui)
		if offset < 0 || offset >
			len(content) || n < 0 || n > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n
		if len(v.SmRPUI) < 1 || len(v.SmRPUI) > 200 {
			if constraintErr := checkDecodedLength(opts, s949588_5, "51.5", "sm-RP-UI", "SIZE (1..200)", len(v.SmRPUI)); constraintErr != nil {
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
	// Decode imsi
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassUniversal && peekTag.Number == 4 {
				ber.MarkPreflightTarget(opts, "imsi", content[offset:])
				val_imsi, n, err := ber.DecodeOctetString(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "imsi", "decoding", false)
				}
				tmp_imsi := IMSI(val_imsi)
				v.Imsi = &tmp_imsi
				if offset < 0 || offset >
					len(content) || n < 0 || n > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n
				if len(*v.Imsi) < 3 || len(*v.Imsi) > 8 {
					if constraintErr := checkDecodedLength(opts, s949588_5, "51.5", "imsi", "SIZE (3..8)", len(*v.Imsi)); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode correlationID
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
				ber.MarkPreflightTarget(opts, "correlationID", content[offset:])
				decodedTag_correlationid, n_correlationid, rawVal_correlationid, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "correlationID", "decoding", false)
				}
				if decodedTag_correlationid.Class != tag.ClassContextSpecific || decodedTag_correlationid.Number != 0 || decodedTag_correlationid.Constructed != true {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_correlationid), "correlationID", "decoding", false)
				}
				_ = rawVal_correlationid
				if offset < 0 || offset >
					len(content) || n_correlationid < 0 || n_correlationid >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				reconstructed_correlationid, reconstructionErr_correlationid := ber.EncodeImplicitTagWithClass(tag.ClassUniversal, tag.TagSequence, content[offset:offset+n_correlationid])
				if reconstructionErr_correlationid != nil {
					return qualifyBERError(reconstructionErr_correlationid, "correlationID", "decoding", false)
				}
				var dec_correlationid CorrelationID
				if unmErr := dec_correlationid.UnmarshalBER(reconstructed_correlationid, ber.ChildDecodeOptions(opts, "correlationID")...); unmErr != nil {
					return qualifyBERError(unmErr, "correlationID", "decoding", false)
				}
				v.CorrelationID = &dec_correlationid
				if offset < 0 || offset >
					len(content) || n_correlationid < 0 || n_correlationid >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_correlationid
			}
		}
	}
	// Decode sm-DeliveryOutcome
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
				ber.MarkPreflightTarget(opts, "sm-DeliveryOutcome", content[offset:])
				decodedTag_smdeliveryoutcome, n_smdeliveryoutcome, rawVal_smdeliveryoutcome, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "sm-DeliveryOutcome", "decoding", false)
				}
				if decodedTag_smdeliveryoutcome.Class != tag.ClassContextSpecific || decodedTag_smdeliveryoutcome.Number != 1 || decodedTag_smdeliveryoutcome.Constructed != false {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_smdeliveryoutcome), "sm-DeliveryOutcome", "decoding", false)
				}
				decVal_smdeliveryoutcome, intErr := ber.DecodeEnumeratedValue(rawVal_smdeliveryoutcome)
				if intErr != nil {
					return qualifyBERError(intErr, "sm-DeliveryOutcome", "decoding", false)
				}
				tmp_smdeliveryoutcome := SMDeliveryOutcome(decVal_smdeliveryoutcome)
				v.SmDeliveryOutcome = &tmp_smdeliveryoutcome
				if offset < 0 || offset >
					len(content) || n_smdeliveryoutcome < 0 || n_smdeliveryoutcome >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_smdeliveryoutcome
				if int64(*v.SmDeliveryOutcome) != 0 && int64(*v.SmDeliveryOutcome) != 1 && int64(*v.SmDeliveryOutcome) != 2 {
					if constraintErr := checkDecodedValue(opts, s949588_5, "20", "sm-DeliveryOutcome", "ENUMERATED {0, 1, 2}", ber.ObserveInteger(int64(*v.SmDeliveryOutcome))); constraintErr != nil {
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
			return &ber.DecodeError{Offset: offset, TypeName: "MOForwardSMArg", Cause: extErr_}
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: the first unknown addition must differ from trailing OPTIONAL/DEFAULT tags.
		if len(v.ExtData_) == 0 && ((peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0) || (peekTag.Class == tag.ClassUniversal && peekTag.Number == 4) || (peekTag.Class == tag.ClassUniversal && peekTag.Number == 16)) {
			if !ber.ToleranceEnabled(opts) {
				return &ber.DecodeError{Offset: offset, TypeName: "MOForwardSMArg", Cause: fmt.Errorf("%w: repeated or out-of-order SEQUENCE component tag %s", ber.ErrInvalidTag, peekTag)}
			}
			if orderErr_ := ber.CheckDecodedValue(ber.DecodeRule(opts, s949588_5, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), fmt.Sprintf("ExtData_[%d]", len(v.ExtData_)), "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); orderErr_ != nil {
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

// MarshalBER encodes MOForwardSMRes to BER format.
func (v *MOForwardSMRes) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {

	if v == nil {
		return nil, fmt.Errorf("%w: MOForwardSMRes receiver is nil", ber.ErrInvalidValue)
	}
	return marshalFramedValue(v, v.berReplayNode_, opts, (*MOForwardSMRes).MarshalBER, (*MOForwardSMRes).marshalBER, 3)

}
func (v *MOForwardSMRes) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if v.SmRPUI != nil {
		if len(*v.SmRPUI) < 1 || len(*v.SmRPUI) > 200 {
			if constraintErr := checkEncodedLength(opts, s949588_6, "51.5", "sm-RP-UI", "SIZE (1..200)", len(*v.SmRPUI)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_smrpui, encodeErr_enc_smrpui := ber.EncodeOctetString([]byte(*v.SmRPUI))
		if encodeErr_enc_smrpui != nil {
			return nil, qualifyBERError(encodeErr_enc_smrpui, "sm-RP-UI", "encoding", false)
		}
		children = append(children, enc_smrpui...)
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
		if err := checkOpaqueAddition(ext, opts, s949588_6, children, i, &base_); err != nil {
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
		if i == 0 && ((peekTag.Class == tag.ClassUniversal && peekTag.Number == 16) || (peekTag.Class == tag.ClassUniversal && peekTag.Number == 4)) {
			if constraintErr := ber.CheckEncodedValue(ber.EncodeRule(opts, s949588_6, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
				return nil, constraintErr
			}
		}
		children = append(children, ext...)
	}
	ber.RecordGeneratedBERContainer(opts, children)
	return ber.EncodeSequence(children)
}
func (v *MOForwardSMRes) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// MarshalDER encodes MOForwardSMRes to DER format.
// Opaque descendants pass generic DER checks; foreign schema rules need a typed binding.
func (v *MOForwardSMRes) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: MOForwardSMRes receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if v.SmRPUI != nil {
		if len(*v.SmRPUI) < 1 || len(*v.SmRPUI) > 200 {
			if constraintErr := checkEncodedLength(nil, s949588_6, "51.5", "sm-RP-UI", "SIZE (1..200)", len(*v.SmRPUI)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_smrpui, encodeErr_enc_smrpui := ber.EncodeOctetString([]byte(*v.SmRPUI))
		if encodeErr_enc_smrpui != nil {
			return nil, qualifyBERError(encodeErr_enc_smrpui, "sm-RP-UI", "encoding", true)
		}
		children = append(children, enc_smrpui...)
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
			return nil, invalidDERAddition(ext, s949588_6, children, i)
		}
		peekTag, _, _, extErr := ber.DecodeEncodedTLV(ext)
		if extErr != nil {
			return nil, extErr
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: only the first addition is restricted.
		if i == 0 && ((peekTag.Class == tag.ClassUniversal && peekTag.Number == 16) || (peekTag.Class == tag.ClassUniversal && peekTag.Number == 4)) {
			if constraintErr := ber.CheckEncodedValue(ber.EncodeRule(nil, s949588_6, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
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
		return nil, fmt.Errorf("%s: %w", "encoding MOForwardSMRes as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}
func (v *MOForwardSMRes) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	encoded, err := v.MarshalDER()
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBER decodes MOForwardSMRes from BER/DER format.
func (destination *MOForwardSMRes) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if destination == nil {
		return fmt.Errorf("%w: MOForwardSMRes destination is nil", ber.ErrInvalidValue)
	}
	v := new(MOForwardSMRes)

	defer publishDecodedValue(destination, v, &returnErr)

	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	preparedData, preparedOptions, prepareErr := prepareCompositeBER(data, opts, s949588_6, "child", (*MOForwardSMRes).UnmarshalBER)
	if prepareErr != nil {
		return prepareErr
	}
	data, opts = preparedData, preparedOptions

	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
	*v = MOForwardSMRes{}
	defer func() {
		if returnErr == nil {
			returnErr = completeValueBER(data,
				opts, v, &v.berReplayNode_, (*MOForwardSMRes).MarshalBER)
		}

	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("%s: %w", "decoding MOForwardSMRes SEQUENCE", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "MOForwardSMRes", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode sm-RP-UI
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassUniversal && peekTag.Number == 4 {
				ber.MarkPreflightTarget(opts, "sm-RP-UI", content[offset:])
				val_smrpui, n, err := ber.DecodeOctetString(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "sm-RP-UI", "decoding", false)
				}
				tmp_smrpui := SignalInfo(val_smrpui)
				v.SmRPUI = &tmp_smrpui
				if offset > len(content) || n < 0 || n > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n
				if len(*v.SmRPUI) < 1 || len(*v.SmRPUI) > 200 {
					if constraintErr := checkDecodedLength(opts, s949588_6, "51.5", "sm-RP-UI", "SIZE (1..200)", len(*v.SmRPUI)); constraintErr != nil {
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
			return &ber.DecodeError{Offset: offset, TypeName: "MOForwardSMRes", Cause: extErr_}
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: the first unknown addition must differ from trailing OPTIONAL/DEFAULT tags.
		if len(v.ExtData_) == 0 && ((peekTag.Class == tag.ClassUniversal && peekTag.Number == 16) || (peekTag.Class == tag.ClassUniversal && peekTag.Number == 4)) {
			if !ber.ToleranceEnabled(opts) {
				return &ber.DecodeError{Offset: offset, TypeName: "MOForwardSMRes", Cause: fmt.Errorf("%w: repeated or out-of-order SEQUENCE component tag %s", ber.ErrInvalidTag, peekTag)}
			}
			if orderErr_ := ber.CheckDecodedValue(ber.DecodeRule(opts, s949588_6, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), fmt.Sprintf("ExtData_[%d]", len(v.ExtData_)), "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); orderErr_ != nil {
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

// MarshalBER encodes MTForwardSMArg to BER format.
func (v *MTForwardSMArg) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {

	if v == nil {
		return nil, fmt.Errorf("%w: MTForwardSMArg receiver is nil", ber.ErrInvalidValue)
	}
	return marshalFramedValue(v, v.berReplayNode_, opts, (*MTForwardSMArg).MarshalBER, (*MTForwardSMArg).marshalBER, 3)

}
func (v *MTForwardSMArg) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	enc_smrpda, err := v.SmRPDA.MarshalBER(ber.ChildEncodeOptions(opts, "sm-RP-DA")...)
	if err != nil {
		return nil, qualifyBERError(err, "sm-RP-DA", "encoding", false)
	}
	ber.RecordGeneratedBERChildPlacement(opts, len(children), enc_smrpda)
	children = append(children, enc_smrpda...)
	enc_smrpoa, err := v.SmRPOA.MarshalBER(ber.ChildEncodeOptions(opts, "sm-RP-OA")...)
	if err != nil {
		return nil, qualifyBERError(err, "sm-RP-OA", "encoding", false)
	}
	ber.RecordGeneratedBERChildPlacement(opts, len(children), enc_smrpoa)
	children = append(children, enc_smrpoa...)
	if len(v.SmRPUI) < 1 || len(v.SmRPUI) > 200 {
		if constraintErr := checkEncodedLength(opts, s949588_7, "51.5", "sm-RP-UI", "SIZE (1..200)", len(v.SmRPUI)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_smrpui, encodeErr_enc_smrpui := ber.EncodeOctetString([]byte(v.SmRPUI))
	if encodeErr_enc_smrpui != nil {
		return nil, qualifyBERError(encodeErr_enc_smrpui, "sm-RP-UI", "encoding", false)
	}
	children = append(children, enc_smrpui...)
	if v.MoreMessagesToSend != nil {
		enc_moremessagestosend := ber.EncodeNull()
		children = append(children, enc_moremessagestosend...)
	}
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalBER(ber.ChildEncodeOptions(opts, "extensionContainer")...)
		if err != nil {
			return nil, qualifyBERError(err, "extensionContainer", "encoding", false)
		}
		ber.RecordGeneratedBERChildPlacement(opts, len(children), enc_extensioncontainer)
		children = append(children, enc_extensioncontainer...)
	}
	if v.SmDeliveryTimer != nil {
		if !(int64(*v.SmDeliveryTimer) >= 30 && int64(*v.SmDeliveryTimer) <= 600) {
			if constraintErr := checkEncodedValue(opts, s949588_7, "51.4", "smDeliveryTimer", "(30..600)", ber.ObserveInteger(int64(*v.SmDeliveryTimer))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_smdeliverytimer := ber.EncodeInteger(int64(*v.SmDeliveryTimer))
		children = append(children, enc_smdeliverytimer...)
	}
	if v.SmDeliveryStartTime != nil {
		if len(*v.SmDeliveryStartTime) < 4 || len(*v.SmDeliveryStartTime) > 4 {
			if constraintErr := checkEncodedLength(opts, s949588_7, "51.5", "smDeliveryStartTime", "SIZE (4)", len(*v.SmDeliveryStartTime)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_smdeliverystarttime, encodeErr_enc_smdeliverystarttime := ber.EncodeOctetString([]byte(*v.SmDeliveryStartTime))
		if encodeErr_enc_smdeliverystarttime != nil {
			return nil, qualifyBERError(encodeErr_enc_smdeliverystarttime, "smDeliveryStartTime", "encoding", false)
		}
		children = append(children, enc_smdeliverystarttime...)
	}
	if v.SmsOverIPOnlyIndicator != nil {
		enc_smsoveriponlyindicator := ber.EncodeNull()
		retagged_enc_smsoveriponlyindicator, tagErr_enc_smsoveriponlyindicator := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_smsoveriponlyindicator)
		if tagErr_enc_smsoveriponlyindicator != nil {
			return nil, qualifyBERError(tagErr_enc_smsoveriponlyindicator, "smsOverIP-OnlyIndicator", "encoding", false)
		}
		enc_smsoveriponlyindicator = retagged_enc_smsoveriponlyindicator
		children = append(children, enc_smsoveriponlyindicator...)
	}
	if v.CorrelationID != nil {
		enc_correlationid, err := v.CorrelationID.MarshalBER(ber.ChildEncodeOptions(opts, "correlationID")...)
		if err != nil {
			return nil, qualifyBERError(err, "correlationID", "encoding", false)
		}
		retagged_enc_correlationid, tagErr_enc_correlationid := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_correlationid)
		if tagErr_enc_correlationid != nil {
			return nil, qualifyBERError(tagErr_enc_correlationid, "correlationID", "encoding", false)
		}
		enc_correlationid = retagged_enc_correlationid
		ber.RecordGeneratedBERChildPlacement(opts, len(children), enc_correlationid)
		children = append(children, enc_correlationid...)
	}
	if v.MaximumRetransmissionTime != nil {
		if len(*v.MaximumRetransmissionTime) < 4 || len(*v.MaximumRetransmissionTime) > 4 {
			if constraintErr := checkEncodedLength(opts, s949588_7, "51.5", "maximumRetransmissionTime", "SIZE (4)", len(*v.MaximumRetransmissionTime)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_maximumretransmissiontime, encodeErr_enc_maximumretransmissiontime := ber.EncodeOctetString([]byte(*v.MaximumRetransmissionTime))
		if encodeErr_enc_maximumretransmissiontime != nil {
			return nil, qualifyBERError(encodeErr_enc_maximumretransmissiontime, "maximumRetransmissionTime", "encoding", false)
		}
		retagged_enc_maximumretransmissiontime, tagErr_enc_maximumretransmissiontime := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_maximumretransmissiontime)
		if tagErr_enc_maximumretransmissiontime != nil {
			return nil, qualifyBERError(tagErr_enc_maximumretransmissiontime, "maximumRetransmissionTime", "encoding", false)
		}
		enc_maximumretransmissiontime = retagged_enc_maximumretransmissiontime
		children = append(children, enc_maximumretransmissiontime...)
	}
	if v.SmsGmscAddress != nil {
		if len(*v.SmsGmscAddress) < 1 || len(*v.SmsGmscAddress) > 9 {
			if constraintErr := checkEncodedLength(opts, s949588_7, "51.5", "smsGmscAddress", "SIZE (1..9)", len(*v.SmsGmscAddress)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		if len(*v.SmsGmscAddress) < 1 || len(*v.SmsGmscAddress) > 20 {
			if constraintErr := checkEncodedLength(opts, s949588_7, "51.5", "smsGmscAddress", "SIZE (1..20)", len(*v.SmsGmscAddress)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_smsgmscaddress, encodeErr_enc_smsgmscaddress := ber.EncodeOctetString([]byte(*v.SmsGmscAddress))
		if encodeErr_enc_smsgmscaddress != nil {
			return nil, qualifyBERError(encodeErr_enc_smsgmscaddress, "smsGmscAddress", "encoding", false)
		}
		retagged_enc_smsgmscaddress, tagErr_enc_smsgmscaddress := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, enc_smsgmscaddress)
		if tagErr_enc_smsgmscaddress != nil {
			return nil, qualifyBERError(tagErr_enc_smsgmscaddress, "smsGmscAddress", "encoding", false)
		}
		enc_smsgmscaddress = retagged_enc_smsgmscaddress
		children = append(children, enc_smsgmscaddress...)
	}
	if v.SmsGmscDiameterAddress != nil {
		enc_smsgmscdiameteraddress, err := v.SmsGmscDiameterAddress.MarshalBER(ber.ChildEncodeOptions(opts, "smsGmscDiameterAddress")...)
		if err != nil {
			return nil, qualifyBERError(err, "smsGmscDiameterAddress", "encoding", false)
		}
		retagged_enc_smsgmscdiameteraddress, tagErr_enc_smsgmscdiameteraddress := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, enc_smsgmscdiameteraddress)
		if tagErr_enc_smsgmscdiameteraddress != nil {
			return nil, qualifyBERError(tagErr_enc_smsgmscdiameteraddress, "smsGmscDiameterAddress", "encoding", false)
		}
		enc_smsgmscdiameteraddress = retagged_enc_smsgmscdiameteraddress
		ber.RecordGeneratedBERChildPlacement(opts, len(children), enc_smsgmscdiameteraddress)
		children = append(children, enc_smsgmscdiameteraddress...)
	}
	base_ := -1
	for i, ext := range v.ExtData_ {
		if err := checkOpaqueAddition(ext, opts, s949588_7, children, i, &base_); err != nil {
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
		if i == 0 && ((peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0) || (peekTag.Class == tag.ClassUniversal && peekTag.Number == 4) || (peekTag.Class == tag.ClassUniversal && peekTag.Number == 2) || (peekTag.Class == tag.ClassUniversal && peekTag.Number == 16) || (peekTag.Class == tag.ClassUniversal && peekTag.Number == 5)) {
			if constraintErr := ber.CheckEncodedValue(ber.EncodeRule(opts, s949588_7, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
				return nil, constraintErr
			}
		}
		children = append(children, ext...)
	}
	ber.RecordGeneratedBERContainer(opts, children)
	return ber.EncodeSequence(children)
}
func (v *MTForwardSMArg) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// MarshalDER encodes MTForwardSMArg to DER format.
// Opaque descendants pass generic DER checks; foreign schema rules need a typed binding.
func (v *MTForwardSMArg) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: MTForwardSMArg receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	enc_smrpda, err := v.SmRPDA.MarshalDER()
	if err != nil {
		return nil, qualifyBERError(err, "sm-RP-DA", "encoding", true)
	}
	children = append(children, enc_smrpda...)
	enc_smrpoa, err := v.SmRPOA.MarshalDER()
	if err != nil {
		return nil, qualifyBERError(err, "sm-RP-OA", "encoding", true)
	}
	children = append(children, enc_smrpoa...)
	if len(v.SmRPUI) < 1 || len(v.SmRPUI) > 200 {
		if constraintErr := checkEncodedLength(nil, s949588_7, "51.5", "sm-RP-UI", "SIZE (1..200)", len(v.SmRPUI)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_smrpui, encodeErr_enc_smrpui := ber.EncodeOctetString([]byte(v.SmRPUI))
	if encodeErr_enc_smrpui != nil {
		return nil, qualifyBERError(encodeErr_enc_smrpui, "sm-RP-UI", "encoding", true)
	}
	children = append(children, enc_smrpui...)
	if v.MoreMessagesToSend != nil {
		enc_moremessagestosend := ber.EncodeNull()
		children = append(children, enc_moremessagestosend...)
	}
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalDER()
		if err != nil {
			return nil, qualifyBERError(err, "extensionContainer", "encoding", true)
		}
		children = append(children, enc_extensioncontainer...)
	}
	if v.SmDeliveryTimer != nil {
		if !(int64(*v.SmDeliveryTimer) >= 30 && int64(*v.SmDeliveryTimer) <= 600) {
			if constraintErr := checkEncodedValue(nil, s949588_7, "51.4", "smDeliveryTimer", "(30..600)", ber.ObserveInteger(int64(*v.SmDeliveryTimer))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_smdeliverytimer := ber.EncodeInteger(int64(*v.SmDeliveryTimer))
		children = append(children, enc_smdeliverytimer...)
	}
	if v.SmDeliveryStartTime != nil {
		if len(*v.SmDeliveryStartTime) < 4 || len(*v.SmDeliveryStartTime) > 4 {
			if constraintErr := checkEncodedLength(nil, s949588_7, "51.5", "smDeliveryStartTime", "SIZE (4)", len(*v.SmDeliveryStartTime)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_smdeliverystarttime, encodeErr_enc_smdeliverystarttime := ber.EncodeOctetString([]byte(*v.SmDeliveryStartTime))
		if encodeErr_enc_smdeliverystarttime != nil {
			return nil, qualifyBERError(encodeErr_enc_smdeliverystarttime, "smDeliveryStartTime", "encoding", true)
		}
		children = append(children, enc_smdeliverystarttime...)
	}
	if v.SmsOverIPOnlyIndicator != nil {
		enc_smsoveriponlyindicator := ber.EncodeNull()
		retagged_enc_smsoveriponlyindicator, tagErr_enc_smsoveriponlyindicator := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_smsoveriponlyindicator)
		if tagErr_enc_smsoveriponlyindicator != nil {
			return nil, qualifyBERError(tagErr_enc_smsoveriponlyindicator, "smsOverIP-OnlyIndicator", "encoding", true)
		}
		enc_smsoveriponlyindicator = retagged_enc_smsoveriponlyindicator
		children = append(children, enc_smsoveriponlyindicator...)
	}
	if v.CorrelationID != nil {
		enc_correlationid, err := v.CorrelationID.MarshalDER()
		if err != nil {
			return nil, qualifyBERError(err, "correlationID", "encoding", true)
		}
		retagged_enc_correlationid, tagErr_enc_correlationid := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_correlationid)
		if tagErr_enc_correlationid != nil {
			return nil, qualifyBERError(tagErr_enc_correlationid, "correlationID", "encoding", true)
		}
		enc_correlationid = retagged_enc_correlationid
		children = append(children, enc_correlationid...)
	}
	if v.MaximumRetransmissionTime != nil {
		if len(*v.MaximumRetransmissionTime) < 4 || len(*v.MaximumRetransmissionTime) > 4 {
			if constraintErr := checkEncodedLength(nil, s949588_7, "51.5", "maximumRetransmissionTime", "SIZE (4)", len(*v.MaximumRetransmissionTime)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_maximumretransmissiontime, encodeErr_enc_maximumretransmissiontime := ber.EncodeOctetString([]byte(*v.MaximumRetransmissionTime))
		if encodeErr_enc_maximumretransmissiontime != nil {
			return nil, qualifyBERError(encodeErr_enc_maximumretransmissiontime, "maximumRetransmissionTime", "encoding", true)
		}
		retagged_enc_maximumretransmissiontime, tagErr_enc_maximumretransmissiontime := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_maximumretransmissiontime)
		if tagErr_enc_maximumretransmissiontime != nil {
			return nil, qualifyBERError(tagErr_enc_maximumretransmissiontime, "maximumRetransmissionTime", "encoding", true)
		}
		enc_maximumretransmissiontime = retagged_enc_maximumretransmissiontime
		children = append(children, enc_maximumretransmissiontime...)
	}
	if v.SmsGmscAddress != nil {
		if len(*v.SmsGmscAddress) < 1 || len(*v.SmsGmscAddress) > 9 {
			if constraintErr := checkEncodedLength(nil, s949588_7, "51.5", "smsGmscAddress", "SIZE (1..9)", len(*v.SmsGmscAddress)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		if len(*v.SmsGmscAddress) < 1 || len(*v.SmsGmscAddress) > 20 {
			if constraintErr := checkEncodedLength(nil, s949588_7, "51.5", "smsGmscAddress", "SIZE (1..20)", len(*v.SmsGmscAddress)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_smsgmscaddress, encodeErr_enc_smsgmscaddress := ber.EncodeOctetString([]byte(*v.SmsGmscAddress))
		if encodeErr_enc_smsgmscaddress != nil {
			return nil, qualifyBERError(encodeErr_enc_smsgmscaddress, "smsGmscAddress", "encoding", true)
		}
		retagged_enc_smsgmscaddress, tagErr_enc_smsgmscaddress := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, enc_smsgmscaddress)
		if tagErr_enc_smsgmscaddress != nil {
			return nil, qualifyBERError(tagErr_enc_smsgmscaddress, "smsGmscAddress", "encoding", true)
		}
		enc_smsgmscaddress = retagged_enc_smsgmscaddress
		children = append(children, enc_smsgmscaddress...)
	}
	if v.SmsGmscDiameterAddress != nil {
		enc_smsgmscdiameteraddress, err := v.SmsGmscDiameterAddress.MarshalDER()
		if err != nil {
			return nil, qualifyBERError(err, "smsGmscDiameterAddress", "encoding", true)
		}
		retagged_enc_smsgmscdiameteraddress, tagErr_enc_smsgmscdiameteraddress := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, enc_smsgmscdiameteraddress)
		if tagErr_enc_smsgmscdiameteraddress != nil {
			return nil, qualifyBERError(tagErr_enc_smsgmscdiameteraddress, "smsGmscDiameterAddress", "encoding", true)
		}
		enc_smsgmscdiameteraddress = retagged_enc_smsgmscdiameteraddress
		children = append(children, enc_smsgmscdiameteraddress...)
	}
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDEREncodedElement(ext); err != nil {
			return nil, invalidDERAddition(ext, s949588_7, children, i)
		}
		peekTag, _, _, extErr := ber.DecodeEncodedTLV(ext)
		if extErr != nil {
			return nil, extErr
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: only the first addition is restricted.
		if i == 0 && ((peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0) || (peekTag.Class == tag.ClassUniversal && peekTag.Number == 4) || (peekTag.Class == tag.ClassUniversal && peekTag.Number == 2) || (peekTag.Class == tag.ClassUniversal && peekTag.Number == 16) || (peekTag.Class == tag.ClassUniversal && peekTag.Number == 5)) {
			if constraintErr := ber.CheckEncodedValue(ber.EncodeRule(nil, s949588_7, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
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
		return nil, fmt.Errorf("%s: %w", "encoding MTForwardSMArg as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}
func (v *MTForwardSMArg) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	encoded, err := v.MarshalDER()
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBER decodes MTForwardSMArg from BER/DER format.
func (destination *MTForwardSMArg) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if destination == nil {
		return fmt.Errorf("%w: MTForwardSMArg destination is nil", ber.ErrInvalidValue)
	}
	v := new(MTForwardSMArg)

	defer publishDecodedValue(destination, v, &returnErr)

	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	preparedData, preparedOptions, prepareErr := prepareCompositeBER(data, opts, s949588_7, "child", (*MTForwardSMArg).UnmarshalBER)
	if prepareErr != nil {
		return prepareErr
	}
	data, opts = preparedData, preparedOptions

	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
	*v = MTForwardSMArg{}
	defer func() {
		if returnErr == nil {
			returnErr = completeValueBER(data,
				opts, v, &v.berReplayNode_, (*MTForwardSMArg).MarshalBER)
		}

	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("%s: %w", "decoding MTForwardSMArg SEQUENCE", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "MTForwardSMArg", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode sm-RP-DA
	if offset >= len(content) {
		return fmt.Errorf("missing required field sm-RP-DA")
	}
	{
		ber.MarkPreflightTarget(opts, "sm-RP-DA", content[offset:])
		// Decode nested CHOICE (SMRPDA)
		_, n_smrpda, _, tlvErr_smrpda := ber.DecodeTLV(content[offset:], opts...)
		if tlvErr_smrpda != nil {
			return qualifyBERError(tlvErr_smrpda, "sm-RP-DA", "decoding", false)
		}
		if offset > len(content) || n_smrpda < 0 || n_smrpda > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		if unmErr := v.SmRPDA.UnmarshalBER(content[offset:offset+n_smrpda], ber.ChildDecodeOptions(opts, "sm-RP-DA")...); unmErr != nil {
			return qualifyBERError(unmErr, "sm-RP-DA", "decoding", false)
		}
		if offset > len(content) || n_smrpda < 0 || n_smrpda > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n_smrpda
	}
	// Decode sm-RP-OA
	if offset >= len(content) {
		return fmt.Errorf("missing required field sm-RP-OA")
	}
	{
		ber.MarkPreflightTarget(opts, "sm-RP-OA", content[offset:])
		// Decode nested CHOICE (SMRPOA)
		_, n_smrpoa, _, tlvErr_smrpoa := ber.DecodeTLV(content[offset:], opts...)
		if tlvErr_smrpoa != nil {
			return qualifyBERError(tlvErr_smrpoa, "sm-RP-OA", "decoding", false)
		}
		if offset < 0 || offset >
			len(content) || n_smrpoa < 0 || n_smrpoa > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		if unmErr := v.SmRPOA.UnmarshalBER(content[offset:offset+n_smrpoa], ber.ChildDecodeOptions(opts, "sm-RP-OA")...); unmErr != nil {
			return qualifyBERError(unmErr, "sm-RP-OA", "decoding", false)
		}
		if offset < 0 || offset >
			len(content) || n_smrpoa < 0 || n_smrpoa > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n_smrpoa
	}
	// Decode sm-RP-UI
	if offset >= len(content) {
		return fmt.Errorf("missing required field sm-RP-UI")
	}
	{
		ber.MarkPreflightTarget(opts, "sm-RP-UI", content[offset:])
		val_smrpui, n, err := ber.DecodeOctetString(content[offset:], opts...)
		if err != nil {
			return qualifyBERError(err, "sm-RP-UI", "decoding", false)
		}
		v.SmRPUI = SignalInfo(val_smrpui)
		if offset < 0 || offset >
			len(content) || n < 0 || n > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n
		if len(v.SmRPUI) < 1 || len(v.SmRPUI) > 200 {
			if constraintErr := checkDecodedLength(opts, s949588_7, "51.5", "sm-RP-UI", "SIZE (1..200)", len(v.SmRPUI)); constraintErr != nil {
				return constraintErr
			}
		}
	}
	// Decode moreMessagesToSend
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassUniversal && peekTag.Number == 5 {
				ber.MarkPreflightTarget(opts, "moreMessagesToSend", content[offset:])
				n, err := ber.DecodeNull(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "moreMessagesToSend", "decoding", false)
				}
				v.MoreMessagesToSend = &struct{}{}
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
	// Decode smDeliveryTimer
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassUniversal && peekTag.Number == 2 {
				ber.MarkPreflightTarget(opts, "smDeliveryTimer", content[offset:])
				val_smdeliverytimer, n, err := ber.DecodeInteger(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "smDeliveryTimer", "decoding", false)
				}
				tmp_smdeliverytimer := SMDeliveryTimerValue(val_smdeliverytimer)
				v.SmDeliveryTimer = &tmp_smdeliverytimer
				if offset < 0 || offset >
					len(content) || n < 0 || n > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n
				if !(int64(*v.SmDeliveryTimer) >= 30 && int64(*v.SmDeliveryTimer) <= 600) {
					if constraintErr := checkDecodedValue(opts, s949588_7, "51.4", "smDeliveryTimer", "(30..600)", ber.ObserveInteger(int64(*v.SmDeliveryTimer))); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode smDeliveryStartTime
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassUniversal && peekTag.Number == 4 {
				ber.MarkPreflightTarget(opts, "smDeliveryStartTime", content[offset:])
				val_smdeliverystarttime, n, err := ber.DecodeOctetString(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "smDeliveryStartTime", "decoding", false)
				}
				tmp_smdeliverystarttime := Time(val_smdeliverystarttime)
				v.SmDeliveryStartTime = &tmp_smdeliverystarttime
				if offset < 0 || offset >
					len(content) || n < 0 || n > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n
				if len(*v.SmDeliveryStartTime) < 4 || len(*v.SmDeliveryStartTime) > 4 {
					if constraintErr := checkDecodedLength(opts, s949588_7, "51.5", "smDeliveryStartTime", "SIZE (4)", len(*v.SmDeliveryStartTime)); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode smsOverIP-OnlyIndicator
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
				ber.MarkPreflightTarget(opts, "smsOverIP-OnlyIndicator", content[offset:])
				decodedTag_smsoveriponlyindicator, n_smsoveriponlyindicator, rawVal_smsoveriponlyindicator, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "smsOverIP-OnlyIndicator", "decoding", false)
				}
				if decodedTag_smsoveriponlyindicator.Class != tag.ClassContextSpecific || decodedTag_smsoveriponlyindicator.Number != 0 || decodedTag_smsoveriponlyindicator.Constructed != false {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_smsoveriponlyindicator), "smsOverIP-OnlyIndicator", "decoding", false)
				}
				if len(rawVal_smsoveriponlyindicator) != 0 {
					return qualifyBERError(fmt.Errorf("%w: NULL content length %d", ber.ErrInvalidValue, len(rawVal_smsoveriponlyindicator)), "smsOverIP-OnlyIndicator", "decoding", false)
				}
				v.SmsOverIPOnlyIndicator = &struct{}{}
				if offset < 0 || offset >
					len(content) || n_smsoveriponlyindicator < 0 || n_smsoveriponlyindicator >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_smsoveriponlyindicator
			}
		}
	}
	// Decode correlationID
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
				ber.MarkPreflightTarget(opts, "correlationID", content[offset:])
				decodedTag_correlationid, n_correlationid, rawVal_correlationid, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "correlationID", "decoding", false)
				}
				if decodedTag_correlationid.Class != tag.ClassContextSpecific || decodedTag_correlationid.Number != 1 || decodedTag_correlationid.Constructed != true {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_correlationid), "correlationID", "decoding", false)
				}
				_ = rawVal_correlationid
				if offset < 0 || offset >
					len(content) || n_correlationid < 0 || n_correlationid >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				reconstructed_correlationid, reconstructionErr_correlationid := ber.EncodeImplicitTagWithClass(tag.ClassUniversal, tag.TagSequence, content[offset:offset+n_correlationid])
				if reconstructionErr_correlationid != nil {
					return qualifyBERError(reconstructionErr_correlationid, "correlationID", "decoding", false)
				}
				var dec_correlationid CorrelationID
				if unmErr := dec_correlationid.UnmarshalBER(reconstructed_correlationid, ber.ChildDecodeOptions(opts, "correlationID")...); unmErr != nil {
					return qualifyBERError(unmErr, "correlationID", "decoding", false)
				}
				v.CorrelationID = &dec_correlationid
				if offset < 0 || offset >
					len(content) || n_correlationid < 0 || n_correlationid >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_correlationid
			}
		}
	}
	// Decode maximumRetransmissionTime
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2 {
				ber.MarkPreflightTarget(opts, "maximumRetransmissionTime", content[offset:])
				decodedTag_maximumretransmissiontime, n_maximumretransmissiontime, rawVal_maximumretransmissiontime, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "maximumRetransmissionTime", "decoding", false)
				}
				if decodedTag_maximumretransmissiontime.Class != tag.ClassContextSpecific || decodedTag_maximumretransmissiontime.Number != 2 {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_maximumretransmissiontime), "maximumRetransmissionTime", "decoding", false)
				}
				decVal_maximumretransmissiontime, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_maximumretransmissiontime.Constructed, rawVal_maximumretransmissiontime, opts...)
				if octetErr != nil {
					return qualifyBERError(octetErr, "maximumRetransmissionTime", "decoding", false)
				}
				tmp_maximumretransmissiontime := Time(decVal_maximumretransmissiontime)
				v.MaximumRetransmissionTime = &tmp_maximumretransmissiontime
				if offset < 0 || offset >
					len(content) || n_maximumretransmissiontime < 0 || n_maximumretransmissiontime >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_maximumretransmissiontime
				if len(*v.MaximumRetransmissionTime) < 4 || len(*v.MaximumRetransmissionTime) > 4 {
					if constraintErr := checkDecodedLength(opts, s949588_7, "51.5", "maximumRetransmissionTime", "SIZE (4)", len(*v.MaximumRetransmissionTime)); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode smsGmscAddress
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3 {
				ber.MarkPreflightTarget(opts, "smsGmscAddress", content[offset:])
				decodedTag_smsgmscaddress, n_smsgmscaddress, rawVal_smsgmscaddress, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "smsGmscAddress", "decoding", false)
				}
				if decodedTag_smsgmscaddress.Class != tag.ClassContextSpecific || decodedTag_smsgmscaddress.Number != 3 {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_smsgmscaddress), "smsGmscAddress", "decoding", false)
				}
				decVal_smsgmscaddress, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_smsgmscaddress.Constructed, rawVal_smsgmscaddress, opts...)
				if octetErr != nil {
					return qualifyBERError(octetErr, "smsGmscAddress", "decoding", false)
				}
				tmp_smsgmscaddress := ISDNAddressString(decVal_smsgmscaddress)
				v.SmsGmscAddress = &tmp_smsgmscaddress
				if offset < 0 || offset >
					len(content) || n_smsgmscaddress < 0 || n_smsgmscaddress >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_smsgmscaddress
				if len(*v.SmsGmscAddress) < 1 || len(*v.SmsGmscAddress) > 9 {
					if constraintErr := checkDecodedLength(opts, s949588_7, "51.5", "smsGmscAddress", "SIZE (1..9)", len(*v.SmsGmscAddress)); constraintErr != nil {
						return constraintErr
					}
				}
				if len(*v.SmsGmscAddress) < 1 || len(*v.SmsGmscAddress) > 20 {
					if constraintErr := checkDecodedLength(opts, s949588_7, "51.5", "smsGmscAddress", "SIZE (1..20)", len(*v.SmsGmscAddress)); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode smsGmscDiameterAddress
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4 {
				ber.MarkPreflightTarget(opts, "smsGmscDiameterAddress", content[offset:])
				decodedTag_smsgmscdiameteraddress, n_smsgmscdiameteraddress, rawVal_smsgmscdiameteraddress, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "smsGmscDiameterAddress", "decoding", false)
				}
				if decodedTag_smsgmscdiameteraddress.Class != tag.ClassContextSpecific || decodedTag_smsgmscdiameteraddress.Number != 4 || decodedTag_smsgmscdiameteraddress.Constructed != true {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_smsgmscdiameteraddress), "smsGmscDiameterAddress", "decoding", false)
				}
				_ = rawVal_smsgmscdiameteraddress
				if offset < 0 || offset >
					len(content) || n_smsgmscdiameteraddress < 0 || n_smsgmscdiameteraddress >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				reconstructed_smsgmscdiameteraddress, reconstructionErr_smsgmscdiameteraddress := ber.EncodeImplicitTagWithClass(tag.ClassUniversal, tag.TagSequence, content[offset:offset+n_smsgmscdiameteraddress])
				if reconstructionErr_smsgmscdiameteraddress != nil {
					return qualifyBERError(reconstructionErr_smsgmscdiameteraddress, "smsGmscDiameterAddress", "decoding", false)
				}
				var dec_smsgmscdiameteraddress NetworkNodeDiameterAddress
				if unmErr := dec_smsgmscdiameteraddress.UnmarshalBER(reconstructed_smsgmscdiameteraddress, ber.ChildDecodeOptions(opts, "smsGmscDiameterAddress")...); unmErr != nil {
					return qualifyBERError(unmErr, "smsGmscDiameterAddress", "decoding", false)
				}
				v.SmsGmscDiameterAddress = &dec_smsgmscdiameteraddress
				if offset < 0 || offset >
					len(content) || n_smsgmscdiameteraddress < 0 || n_smsgmscdiameteraddress >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_smsgmscdiameteraddress
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		peekTag, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:], opts...)
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "MTForwardSMArg", Cause: extErr_}
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: the first unknown addition must differ from trailing OPTIONAL/DEFAULT tags.
		if len(v.ExtData_) == 0 && ((peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0) || (peekTag.Class == tag.ClassUniversal && peekTag.Number == 4) || (peekTag.Class == tag.ClassUniversal && peekTag.Number == 2) || (peekTag.Class == tag.ClassUniversal && peekTag.Number == 16) || (peekTag.Class == tag.ClassUniversal && peekTag.Number == 5)) {
			if !ber.ToleranceEnabled(opts) {
				return &ber.DecodeError{Offset: offset, TypeName: "MTForwardSMArg", Cause: fmt.Errorf("%w: repeated or out-of-order SEQUENCE component tag %s", ber.ErrInvalidTag, peekTag)}
			}
			if orderErr_ := ber.CheckDecodedValue(ber.DecodeRule(opts, s949588_7, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), fmt.Sprintf("ExtData_[%d]", len(v.ExtData_)), "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); orderErr_ != nil {
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

// MarshalBER encodes CorrelationID to BER format.
func (v *CorrelationID) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {

	if v == nil {
		return nil, fmt.Errorf("%w: CorrelationID receiver is nil", ber.ErrInvalidValue)
	}
	return marshalFramedValue(v, v.berReplayNode_, opts, (*CorrelationID).MarshalBER, (*CorrelationID).marshalBER, 3)

}
func (v *CorrelationID) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if v.HlrId != nil {
		if len(*v.HlrId) < 3 || len(*v.HlrId) > 8 {
			if constraintErr := checkEncodedLength(opts, s949588_8, "51.5", "hlr-id", "SIZE (3..8)", len(*v.HlrId)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_hlrid, encodeErr_enc_hlrid := ber.EncodeOctetString([]byte(*v.HlrId))
		if encodeErr_enc_hlrid != nil {
			return nil, qualifyBERError(encodeErr_enc_hlrid, "hlr-id", "encoding", false)
		}
		retagged_enc_hlrid, tagErr_enc_hlrid := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_hlrid)
		if tagErr_enc_hlrid != nil {
			return nil, qualifyBERError(tagErr_enc_hlrid, "hlr-id", "encoding", false)
		}
		enc_hlrid = retagged_enc_hlrid
		children = append(children, enc_hlrid...)
	}
	if v.SipUriA != nil {
		enc_sipuria, encodeErr_enc_sipuria := ber.EncodeOctetString([]byte(*v.SipUriA))
		if encodeErr_enc_sipuria != nil {
			return nil, qualifyBERError(encodeErr_enc_sipuria, "sip-uri-A", "encoding", false)
		}
		retagged_enc_sipuria, tagErr_enc_sipuria := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_sipuria)
		if tagErr_enc_sipuria != nil {
			return nil, qualifyBERError(tagErr_enc_sipuria, "sip-uri-A", "encoding", false)
		}
		enc_sipuria = retagged_enc_sipuria
		children = append(children, enc_sipuria...)
	}
	enc_sipurib, encodeErr_enc_sipurib := ber.EncodeOctetString([]byte(v.SipUriB))
	if encodeErr_enc_sipurib != nil {
		return nil, qualifyBERError(encodeErr_enc_sipurib, "sip-uri-B", "encoding", false)
	}
	retagged_enc_sipurib, tagErr_enc_sipurib := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_sipurib)
	if tagErr_enc_sipurib != nil {
		return nil, qualifyBERError(tagErr_enc_sipurib, "sip-uri-B", "encoding", false)
	}
	enc_sipurib = retagged_enc_sipurib
	children = append(children, enc_sipurib...)
	ber.RecordGeneratedBERContainer(opts, children)
	return ber.EncodeSequence(children)
}
func (v *CorrelationID) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// MarshalDER encodes CorrelationID to DER format.
// Opaque descendants pass generic DER checks; foreign schema rules need a typed binding.
func (v *CorrelationID) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: CorrelationID receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if v.HlrId != nil {
		if len(*v.HlrId) < 3 || len(*v.HlrId) > 8 {
			if constraintErr := checkEncodedLength(nil, s949588_8, "51.5", "hlr-id", "SIZE (3..8)", len(*v.HlrId)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_hlrid, encodeErr_enc_hlrid := ber.EncodeOctetString([]byte(*v.HlrId))
		if encodeErr_enc_hlrid != nil {
			return nil, qualifyBERError(encodeErr_enc_hlrid, "hlr-id", "encoding", true)
		}
		retagged_enc_hlrid, tagErr_enc_hlrid := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_hlrid)
		if tagErr_enc_hlrid != nil {
			return nil, qualifyBERError(tagErr_enc_hlrid, "hlr-id", "encoding", true)
		}
		enc_hlrid = retagged_enc_hlrid
		children = append(children, enc_hlrid...)
	}
	if v.SipUriA != nil {
		enc_sipuria, encodeErr_enc_sipuria := ber.EncodeOctetString([]byte(*v.SipUriA))
		if encodeErr_enc_sipuria != nil {
			return nil, qualifyBERError(encodeErr_enc_sipuria, "sip-uri-A", "encoding", true)
		}
		retagged_enc_sipuria, tagErr_enc_sipuria := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_sipuria)
		if tagErr_enc_sipuria != nil {
			return nil, qualifyBERError(tagErr_enc_sipuria, "sip-uri-A", "encoding", true)
		}
		enc_sipuria = retagged_enc_sipuria
		children = append(children, enc_sipuria...)
	}
	enc_sipurib, encodeErr_enc_sipurib := ber.EncodeOctetString([]byte(v.SipUriB))
	if encodeErr_enc_sipurib != nil {
		return nil, qualifyBERError(encodeErr_enc_sipurib, "sip-uri-B", "encoding", true)
	}
	retagged_enc_sipurib, tagErr_enc_sipurib := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_sipurib)
	if tagErr_enc_sipurib != nil {
		return nil, qualifyBERError(tagErr_enc_sipurib, "sip-uri-B", "encoding", true)
	}
	enc_sipurib = retagged_enc_sipurib
	children = append(children, enc_sipurib...)
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("%s: %w", "encoding CorrelationID as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}
func (v *CorrelationID) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	encoded, err := v.MarshalDER()
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBER decodes CorrelationID from BER/DER format.
func (destination *CorrelationID) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if destination == nil {
		return fmt.Errorf("%w: CorrelationID destination is nil", ber.ErrInvalidValue)
	}
	v := new(CorrelationID)
	defer publishDecodedValue(destination, v, &returnErr)

	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	preparedData, preparedOptions, prepareErr := prepareCompositeBER(data, opts, s949588_8, "child", (*CorrelationID).UnmarshalBER)
	if prepareErr != nil {
		return prepareErr
	}
	data, opts = preparedData, preparedOptions

	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
	*v = CorrelationID{}
	defer func() {
		if returnErr == nil {
			returnErr = completeValueBER(data,
				opts, v, &v.berReplayNode_, (*CorrelationID).MarshalBER)
		}

	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("%s: %w", "decoding CorrelationID SEQUENCE", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "CorrelationID", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode hlr-id
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
				ber.MarkPreflightTarget(opts, "hlr-id", content[offset:])
				decodedTag_hlrid, n_hlrid, rawVal_hlrid, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "hlr-id", "decoding", false)
				}
				if decodedTag_hlrid.Class != tag.ClassContextSpecific || decodedTag_hlrid.Number != 0 {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_hlrid), "hlr-id", "decoding", false)
				}
				decVal_hlrid, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_hlrid.Constructed, rawVal_hlrid, opts...)
				if octetErr != nil {
					return qualifyBERError(octetErr, "hlr-id", "decoding", false)
				}
				tmp_hlrid := HLRId(decVal_hlrid)
				v.HlrId = &tmp_hlrid
				if offset > len(content) || n_hlrid < 0 || n_hlrid > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_hlrid
				if len(*v.HlrId) < 3 || len(*v.HlrId) > 8 {
					if constraintErr := checkDecodedLength(opts, s949588_8, "51.5", "hlr-id", "SIZE (3..8)", len(*v.HlrId)); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode sip-uri-A
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
				ber.MarkPreflightTarget(opts, "sip-uri-A", content[offset:])
				decodedTag_sipuria, n_sipuria, rawVal_sipuria, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "sip-uri-A", "decoding", false)
				}
				if decodedTag_sipuria.Class != tag.ClassContextSpecific || decodedTag_sipuria.Number != 1 {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_sipuria), "sip-uri-A", "decoding", false)
				}
				decVal_sipuria, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_sipuria.Constructed, rawVal_sipuria, opts...)
				if octetErr != nil {
					return qualifyBERError(octetErr, "sip-uri-A", "decoding", false)
				}
				tmp_sipuria := SIPURI(decVal_sipuria)
				v.SipUriA = &tmp_sipuria
				if offset < 0 || offset >
					len(content) || n_sipuria < 0 || n_sipuria > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_sipuria
			}
		}
	}
	// Decode sip-uri-B
	if offset >= len(content) {
		return fmt.Errorf("missing required field sip-uri-B")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 2 {
			return fmt.Errorf("expected tag [%s %d] for sip-uri-B, got %s", "CONTEXT", 2, reqTag_)
		}
	}
	{
		ber.MarkPreflightTarget(opts, "sip-uri-B", content[offset:])
		decodedTag_sipurib, n_sipurib, rawVal_sipurib, err := ber.DecodeTLV(content[offset:], opts...)
		if err != nil {
			return qualifyBERError(err, "sip-uri-B", "decoding", false)
		}
		if decodedTag_sipurib.Class != tag.ClassContextSpecific || decodedTag_sipurib.Number != 2 {
			return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_sipurib), "sip-uri-B", "decoding", false)
		}
		decVal_sipurib, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_sipurib.Constructed, rawVal_sipurib, opts...)
		if octetErr != nil {
			return qualifyBERError(octetErr, "sip-uri-B", "decoding", false)
		}
		v.SipUriB = SIPURI(decVal_sipurib)
		if offset < 0 || offset >
			len(content) || n_sipurib < 0 || n_sipurib > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n_sipurib
	}
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "CorrelationID", Cause: ber.ErrExtraData}
	}
	return nil
}

// MarshalBER encodes MTForwardSMRes to BER format.
func (v *MTForwardSMRes) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {

	if v == nil {
		return nil, fmt.Errorf("%w: MTForwardSMRes receiver is nil", ber.ErrInvalidValue)
	}
	return marshalFramedValue(v, v.berReplayNode_, opts, (*MTForwardSMRes).MarshalBER, (*MTForwardSMRes).marshalBER, 3)

}
func (v *MTForwardSMRes) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if v.SmRPUI != nil {
		if len(*v.SmRPUI) < 1 || len(*v.SmRPUI) > 200 {
			if constraintErr := checkEncodedLength(opts, s949588_9, "51.5", "sm-RP-UI", "SIZE (1..200)", len(*v.SmRPUI)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_smrpui, encodeErr_enc_smrpui := ber.EncodeOctetString([]byte(*v.SmRPUI))
		if encodeErr_enc_smrpui != nil {
			return nil, qualifyBERError(encodeErr_enc_smrpui, "sm-RP-UI", "encoding", false)
		}
		children = append(children, enc_smrpui...)
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
		if err := checkOpaqueAddition(ext, opts, s949588_9, children, i, &base_); err != nil {
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
		if i == 0 && ((peekTag.Class == tag.ClassUniversal && peekTag.Number == 16) || (peekTag.Class == tag.ClassUniversal && peekTag.Number == 4)) {
			if constraintErr := ber.CheckEncodedValue(ber.EncodeRule(opts, s949588_9, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
				return nil, constraintErr
			}
		}
		children = append(children, ext...)
	}
	ber.RecordGeneratedBERContainer(opts, children)
	return ber.EncodeSequence(children)
}
func (v *MTForwardSMRes) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// MarshalDER encodes MTForwardSMRes to DER format.
// Opaque descendants pass generic DER checks; foreign schema rules need a typed binding.
func (v *MTForwardSMRes) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: MTForwardSMRes receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if v.SmRPUI != nil {
		if len(*v.SmRPUI) < 1 || len(*v.SmRPUI) > 200 {
			if constraintErr := checkEncodedLength(nil, s949588_9, "51.5", "sm-RP-UI", "SIZE (1..200)", len(*v.SmRPUI)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_smrpui, encodeErr_enc_smrpui := ber.EncodeOctetString([]byte(*v.SmRPUI))
		if encodeErr_enc_smrpui != nil {
			return nil, qualifyBERError(encodeErr_enc_smrpui, "sm-RP-UI", "encoding", true)
		}
		children = append(children, enc_smrpui...)
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
			return nil, invalidDERAddition(ext, s949588_9, children, i)
		}
		peekTag, _, _, extErr := ber.DecodeEncodedTLV(ext)
		if extErr != nil {
			return nil, extErr
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: only the first addition is restricted.
		if i == 0 && ((peekTag.Class == tag.ClassUniversal && peekTag.Number == 16) || (peekTag.Class == tag.ClassUniversal && peekTag.Number == 4)) {
			if constraintErr := ber.CheckEncodedValue(ber.EncodeRule(nil, s949588_9, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
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
		return nil, fmt.Errorf("%s: %w", "encoding MTForwardSMRes as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}
func (v *MTForwardSMRes) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	encoded, err := v.MarshalDER()
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBER decodes MTForwardSMRes from BER/DER format.
func (destination *MTForwardSMRes) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if destination == nil {
		return fmt.Errorf("%w: MTForwardSMRes destination is nil", ber.ErrInvalidValue)
	}
	v := new(MTForwardSMRes)

	defer publishDecodedValue(destination, v, &returnErr)

	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	preparedData, preparedOptions, prepareErr := prepareCompositeBER(data, opts, s949588_9, "child", (*MTForwardSMRes).UnmarshalBER)
	if prepareErr != nil {
		return prepareErr
	}
	data, opts = preparedData, preparedOptions

	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
	*v = MTForwardSMRes{}
	defer func() {
		if returnErr == nil {
			returnErr = completeValueBER(data,
				opts, v, &v.berReplayNode_, (*MTForwardSMRes).MarshalBER)
		}

	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("%s: %w", "decoding MTForwardSMRes SEQUENCE", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "MTForwardSMRes", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode sm-RP-UI
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassUniversal && peekTag.Number == 4 {
				ber.MarkPreflightTarget(opts, "sm-RP-UI", content[offset:])
				val_smrpui, n, err := ber.DecodeOctetString(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "sm-RP-UI", "decoding", false)
				}
				tmp_smrpui := SignalInfo(val_smrpui)
				v.SmRPUI = &tmp_smrpui
				if offset > len(content) || n < 0 || n > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n
				if len(*v.SmRPUI) < 1 || len(*v.SmRPUI) > 200 {
					if constraintErr := checkDecodedLength(opts, s949588_9, "51.5", "sm-RP-UI", "SIZE (1..200)", len(*v.SmRPUI)); constraintErr != nil {
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
			return &ber.DecodeError{Offset: offset, TypeName: "MTForwardSMRes", Cause: extErr_}
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: the first unknown addition must differ from trailing OPTIONAL/DEFAULT tags.
		if len(v.ExtData_) == 0 && ((peekTag.Class == tag.ClassUniversal && peekTag.Number == 16) || (peekTag.Class == tag.ClassUniversal && peekTag.Number == 4)) {
			if !ber.ToleranceEnabled(opts) {
				return &ber.DecodeError{Offset: offset, TypeName: "MTForwardSMRes", Cause: fmt.Errorf("%w: repeated or out-of-order SEQUENCE component tag %s", ber.ErrInvalidTag, peekTag)}
			}
			if orderErr_ := ber.CheckDecodedValue(ber.DecodeRule(opts, s949588_9, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), fmt.Sprintf("ExtData_[%d]", len(v.ExtData_)), "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); orderErr_ != nil {
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

// MarshalBER encodes SMRPDA to BER format.
func (v *SMRPDA) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {

	if v == nil {
		return nil, fmt.Errorf("%w: SMRPDA receiver is nil", ber.ErrInvalidValue)
	}
	return marshalFramedValue(v, v.berReplayNode_, opts, (*SMRPDA).MarshalBER, (*SMRPDA).marshalBER, 3)

}
func (v *SMRPDA) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}
func (v *SMRPDA) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	switch v.Choice {
	case SMRPDAChoiceImsi:
		if v.Imsi == nil {
			return nil, fmt.Errorf("%w: choice SMRPDA: imsi is nil", ber.ErrInvalidValue)
		}
		enc_0, encodeErr_enc_0 := ber.EncodeOctetString([]byte(*v.Imsi))
		if encodeErr_enc_0 != nil {
			return nil, qualifyBERError(encodeErr_enc_0, "imsi", "encoding", false)
		}
		if len(*v.Imsi) < 3 || len(*v.Imsi) > 8 {
			if constraintErr := checkEncodedLength(opts, s949588_10, "51.5", "imsi", "SIZE (3..8)", len(*v.Imsi)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		retagged_enc_0, tagErr_enc_0 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_0)
		if tagErr_enc_0 != nil {
			return nil, qualifyBERError(tagErr_enc_0, "imsi", "encoding", false)
		}
		enc_0 = retagged_enc_0
		return enc_0, nil
	case SMRPDAChoiceLmsi:
		if v.Lmsi == nil {
			return nil, fmt.Errorf("%w: choice SMRPDA: lmsi is nil", ber.ErrInvalidValue)
		}
		enc_1, encodeErr_enc_1 := ber.EncodeOctetString([]byte(*v.Lmsi))
		if encodeErr_enc_1 != nil {
			return nil, qualifyBERError(encodeErr_enc_1, "lmsi", "encoding", false)
		}
		if len(*v.Lmsi) < 4 || len(*v.Lmsi) > 4 {
			if constraintErr := checkEncodedLength(opts, s949588_10, "51.5", "lmsi", "SIZE (4)", len(*v.Lmsi)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		retagged_enc_1, tagErr_enc_1 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_1)
		if tagErr_enc_1 != nil {
			return nil, qualifyBERError(tagErr_enc_1, "lmsi", "encoding", false)
		}
		enc_1 = retagged_enc_1
		return enc_1, nil
	case SMRPDAChoiceServiceCentreAddressDA:
		if v.ServiceCentreAddressDA == nil {
			return nil, fmt.Errorf("%w: choice SMRPDA: serviceCentreAddressDA is nil", ber.ErrInvalidValue)
		}
		enc_2, encodeErr_enc_2 := ber.EncodeOctetString([]byte(*v.ServiceCentreAddressDA))
		if encodeErr_enc_2 != nil {
			return nil, qualifyBERError(encodeErr_enc_2, "serviceCentreAddressDA", "encoding", false)
		}
		if len(*v.ServiceCentreAddressDA) < 1 || len(*v.ServiceCentreAddressDA) > 20 {
			if constraintErr := checkEncodedLength(opts, s949588_10, "51.5", "serviceCentreAddressDA", "SIZE (1..20)", len(*v.ServiceCentreAddressDA)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		retagged_enc_2, tagErr_enc_2 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, enc_2)
		if tagErr_enc_2 != nil {
			return nil, qualifyBERError(tagErr_enc_2, "serviceCentreAddressDA", "encoding", false)
		}
		enc_2 = retagged_enc_2
		return enc_2, nil
	case SMRPDAChoiceNoSMRPDA:
		enc_3 := ber.EncodeNull()
		retagged_enc_3, tagErr_enc_3 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 5, enc_3)
		if tagErr_enc_3 != nil {
			return nil, qualifyBERError(tagErr_enc_3, "noSM-RP-DA", "encoding", false)
		}
		enc_3 = retagged_enc_3
		return enc_3, nil
	default:
		return nil, fmt.Errorf("unknown choice %d for SMRPDA", v.Choice)
	}
}

// MarshalDER encodes SMRPDA to DER format.
// Opaque descendants pass generic DER checks; foreign schema rules need a typed binding.
func (v *SMRPDA) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: SMRPDA receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER()
	if err != nil {
		return nil, err
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		switch v.Choice {
		case SMRPDAChoiceImsi:
			return nil, qualifyBERError(err, "imsi", "encoding", true)
		case SMRPDAChoiceLmsi:
			return nil, qualifyBERError(err, "lmsi", "encoding", true)
		case SMRPDAChoiceServiceCentreAddressDA:
			return nil, qualifyBERError(err, "serviceCentreAddressDA", "encoding", true)
		case SMRPDAChoiceNoSMRPDA:
			return nil, qualifyBERError(err, "noSM-RP-DA", "encoding", true)
		}
		return nil, fmt.Errorf("%s: %w", "encoding SMRPDA as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}

func (v *SMRPDA) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	encoded, err := v.MarshalDER()
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBER decodes SMRPDA from BER/DER format.
func (destination *SMRPDA) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if destination == nil {
		return fmt.Errorf("%w: SMRPDA destination is nil", ber.ErrInvalidValue)
	}
	v := new(SMRPDA)
	defer publishDecodedValue(destination, v, &returnErr)

	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	preparedData, preparedOptions, prepareErr := prepareCompositeBER(data, opts, s949588_10, "child", (*SMRPDA).UnmarshalBER)
	if prepareErr != nil {
		return prepareErr
	}
	data, opts = preparedData, preparedOptions
	defer func() {
		if returnErr == nil {
			returnErr = completeValueBER(data,
				opts, v, &v.berReplayNode_, (*SMRPDA).MarshalBER)
		}

	}()

	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
	*v = SMRPDA{}
	if len(data) == 0 {
		return fmt.Errorf("empty data for SMRPDA CHOICE")
	}
	choiceData := data
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for SMRPDA: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData, opts...)
	if tlvErr != nil {
		return fmt.Errorf("%s: %w", "decoding SMRPDA CHOICE", qualifyBERError(tlvErr, "", "decoding", false))
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "SMRPDA", Cause: ber.ErrExtraData}
	}

	if (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 5) && peekTag.Constructed != false {
		return qualifyBERError(fmt.Errorf("%w: invalid primitive/constructed form for tag %s", ber.ErrInvalidTag, peekTag), "SMRPDA.noSM-RP-DA", "decoding", false)
	}
	if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
		v.Choice = SMRPDAChoiceImsi
		ber.MarkPreflightTarget(opts, "imsi", choiceData)
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData, opts...)
		if tlvErr != nil {
			return qualifyBERError(tlvErr, "imsi", "decoding", false)
		}
		_ = rawVal
		decVal, octetErr := ber.DecodeImplicitOctetStringValue(peekTag.Constructed, rawVal, opts...)
		if octetErr != nil {
			return qualifyBERError(octetErr, "imsi", "decoding", false)
		}
		tmp := IMSI(decVal)
		v.Imsi = &tmp
		if len(*v.Imsi) < 3 || len(*v.Imsi) > 8 {
			if constraintErr := checkDecodedLength(opts, s949588_10, "51.5", "imsi", "SIZE (3..8)", len(*v.Imsi)); constraintErr != nil {
				return constraintErr
			}
		}
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
		v.Choice = SMRPDAChoiceLmsi
		ber.MarkPreflightTarget(opts, "lmsi", choiceData)
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData, opts...)
		if tlvErr != nil {
			return qualifyBERError(tlvErr, "lmsi", "decoding", false)
		}
		_ = rawVal
		decVal, octetErr := ber.DecodeImplicitOctetStringValue(peekTag.Constructed, rawVal, opts...)
		if octetErr != nil {
			return qualifyBERError(octetErr, "lmsi", "decoding", false)
		}
		tmp := LMSI(decVal)
		v.Lmsi = &tmp
		if len(*v.Lmsi) < 4 || len(*v.Lmsi) > 4 {
			if constraintErr := checkDecodedLength(opts, s949588_10, "51.5", "lmsi", "SIZE (4)", len(*v.Lmsi)); constraintErr != nil {
				return constraintErr
			}
		}
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4 {
		v.Choice = SMRPDAChoiceServiceCentreAddressDA
		ber.MarkPreflightTarget(opts, "serviceCentreAddressDA", choiceData)
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData, opts...)
		if tlvErr != nil {
			return qualifyBERError(tlvErr, "serviceCentreAddressDA", "decoding", false)
		}
		_ = rawVal
		decVal, octetErr := ber.DecodeImplicitOctetStringValue(peekTag.Constructed, rawVal, opts...)
		if octetErr != nil {
			return qualifyBERError(octetErr, "serviceCentreAddressDA", "decoding", false)
		}
		tmp := AddressString(decVal)
		v.ServiceCentreAddressDA = &tmp
		if len(*v.ServiceCentreAddressDA) < 1 || len(*v.ServiceCentreAddressDA) > 20 {
			if constraintErr := checkDecodedLength(opts, s949588_10, "51.5", "serviceCentreAddressDA", "SIZE (1..20)", len(*v.ServiceCentreAddressDA)); constraintErr != nil {
				return constraintErr
			}
		}
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 5 && peekTag.Constructed == false {
		v.Choice = SMRPDAChoiceNoSMRPDA
		ber.MarkPreflightTarget(opts, "noSM-RP-DA", choiceData)
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData, opts...)
		if tlvErr != nil {
			return qualifyBERError(tlvErr, "noSM-RP-DA", "decoding", false)
		}
		_ = rawVal
		if len(rawVal) != 0 {
			return qualifyBERError(fmt.Errorf("%w: NULL content length %d", ber.ErrInvalidValue, len(rawVal)), "noSM-RP-DA", "decoding", false)
		}
		v.NoSMRPDA = &struct{}{}
	} else {
		return fmt.Errorf("unknown tag %s for SMRPDA CHOICE", peekTag)
	}
	return nil
}

// MarshalBER encodes SMRPOA to BER format.
func (v *SMRPOA) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {

	if v == nil {
		return nil, fmt.Errorf("%w: SMRPOA receiver is nil", ber.ErrInvalidValue)
	}
	return marshalFramedValue(v, v.berReplayNode_, opts, (*SMRPOA).MarshalBER, (*SMRPOA).marshalBER, 3)

}
func (v *SMRPOA) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}
func (v *SMRPOA) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	switch v.Choice {
	case SMRPOAChoiceMsisdn:
		if v.Msisdn == nil {
			return nil, fmt.Errorf("%w: choice SMRPOA: msisdn is nil", ber.ErrInvalidValue)
		}
		enc_0, encodeErr_enc_0 := ber.EncodeOctetString([]byte(*v.Msisdn))
		if encodeErr_enc_0 != nil {
			return nil, qualifyBERError(encodeErr_enc_0, "msisdn", "encoding", false)
		}
		if len(*v.Msisdn) < 1 || len(*v.Msisdn) > 9 {
			if constraintErr := checkEncodedLength(opts, s949588_11, "51.5", "msisdn", "SIZE (1..9)", len(*v.Msisdn)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		if len(*v.Msisdn) < 1 || len(*v.Msisdn) > 20 {
			if constraintErr := checkEncodedLength(opts, s949588_11, "51.5", "msisdn", "SIZE (1..20)", len(*v.Msisdn)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		retagged_enc_0, tagErr_enc_0 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_0)
		if tagErr_enc_0 != nil {
			return nil, qualifyBERError(tagErr_enc_0, "msisdn", "encoding", false)
		}
		enc_0 = retagged_enc_0
		return enc_0, nil
	case SMRPOAChoiceServiceCentreAddressOA:
		if v.ServiceCentreAddressOA == nil {
			return nil, fmt.Errorf("%w: choice SMRPOA: serviceCentreAddressOA is nil", ber.ErrInvalidValue)
		}
		enc_1, encodeErr_enc_1 := ber.EncodeOctetString([]byte(*v.ServiceCentreAddressOA))
		if encodeErr_enc_1 != nil {
			return nil, qualifyBERError(encodeErr_enc_1, "serviceCentreAddressOA", "encoding", false)
		}
		if len(*v.ServiceCentreAddressOA) < 1 || len(*v.ServiceCentreAddressOA) > 20 {
			if constraintErr := checkEncodedLength(opts, s949588_11, "51.5", "serviceCentreAddressOA", "SIZE (1..20)", len(*v.ServiceCentreAddressOA)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		retagged_enc_1, tagErr_enc_1 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, enc_1)
		if tagErr_enc_1 != nil {
			return nil, qualifyBERError(tagErr_enc_1, "serviceCentreAddressOA", "encoding", false)
		}
		enc_1 = retagged_enc_1
		return enc_1, nil
	case SMRPOAChoiceNoSMRPOA:
		enc_2 := ber.EncodeNull()
		retagged_enc_2, tagErr_enc_2 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 5, enc_2)
		if tagErr_enc_2 != nil {
			return nil, qualifyBERError(tagErr_enc_2, "noSM-RP-OA", "encoding", false)
		}
		enc_2 = retagged_enc_2
		return enc_2, nil
	default:
		return nil, fmt.Errorf("unknown choice %d for SMRPOA", v.Choice)
	}
}

// MarshalDER encodes SMRPOA to DER format.
// Opaque descendants pass generic DER checks; foreign schema rules need a typed binding.
func (v *SMRPOA) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: SMRPOA receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER()
	if err != nil {
		return nil, err
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		switch v.Choice {
		case SMRPOAChoiceMsisdn:
			return nil, qualifyBERError(err, "msisdn", "encoding", true)
		case SMRPOAChoiceServiceCentreAddressOA:
			return nil, qualifyBERError(err, "serviceCentreAddressOA", "encoding", true)
		case SMRPOAChoiceNoSMRPOA:
			return nil, qualifyBERError(err, "noSM-RP-OA", "encoding", true)
		}
		return nil, fmt.Errorf("%s: %w", "encoding SMRPOA as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}

func (v *SMRPOA) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	encoded, err := v.MarshalDER()
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBER decodes SMRPOA from BER/DER format.
func (destination *SMRPOA) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if destination == nil {
		return fmt.Errorf("%w: SMRPOA destination is nil", ber.ErrInvalidValue)
	}
	v := new(SMRPOA)
	defer publishDecodedValue(destination, v, &returnErr)

	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	preparedData, preparedOptions, prepareErr := prepareCompositeBER(data, opts, s949588_11, "child", (*SMRPOA).UnmarshalBER)
	if prepareErr != nil {
		return prepareErr
	}
	data, opts = preparedData, preparedOptions
	defer func() {
		if returnErr == nil {
			returnErr = completeValueBER(data,
				opts, v, &v.berReplayNode_, (*SMRPOA).MarshalBER)
		}

	}()

	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
	*v = SMRPOA{}
	if len(data) == 0 {
		return fmt.Errorf("empty data for SMRPOA CHOICE")
	}
	choiceData := data
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for SMRPOA: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData, opts...)
	if tlvErr != nil {
		return fmt.Errorf("%s: %w", "decoding SMRPOA CHOICE", qualifyBERError(tlvErr, "", "decoding", false))
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "SMRPOA", Cause: ber.ErrExtraData}
	}

	if (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 5) && peekTag.Constructed != false {
		return qualifyBERError(fmt.Errorf("%w: invalid primitive/constructed form for tag %s", ber.ErrInvalidTag, peekTag), "SMRPOA.noSM-RP-OA", "decoding", false)
	}
	if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2 {
		v.Choice = SMRPOAChoiceMsisdn
		ber.MarkPreflightTarget(opts, "msisdn", choiceData)
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData, opts...)
		if tlvErr != nil {
			return qualifyBERError(tlvErr, "msisdn", "decoding", false)
		}
		_ = rawVal
		decVal, octetErr := ber.DecodeImplicitOctetStringValue(peekTag.Constructed, rawVal, opts...)
		if octetErr != nil {
			return qualifyBERError(octetErr, "msisdn", "decoding", false)
		}
		tmp := ISDNAddressString(decVal)
		v.Msisdn = &tmp
		if len(*v.Msisdn) < 1 || len(*v.Msisdn) > 9 {
			if constraintErr := checkDecodedLength(opts, s949588_11, "51.5", "msisdn", "SIZE (1..9)", len(*v.Msisdn)); constraintErr != nil {
				return constraintErr
			}
		}
		if len(*v.Msisdn) < 1 || len(*v.Msisdn) > 20 {
			if constraintErr := checkDecodedLength(opts, s949588_11, "51.5", "msisdn", "SIZE (1..20)", len(*v.Msisdn)); constraintErr != nil {
				return constraintErr
			}
		}
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4 {
		v.Choice = SMRPOAChoiceServiceCentreAddressOA
		ber.MarkPreflightTarget(opts, "serviceCentreAddressOA", choiceData)
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData, opts...)
		if tlvErr != nil {
			return qualifyBERError(tlvErr, "serviceCentreAddressOA", "decoding", false)
		}
		_ = rawVal
		decVal, octetErr := ber.DecodeImplicitOctetStringValue(peekTag.Constructed, rawVal, opts...)
		if octetErr != nil {
			return qualifyBERError(octetErr, "serviceCentreAddressOA", "decoding", false)
		}
		tmp := AddressString(decVal)
		v.ServiceCentreAddressOA = &tmp
		if len(*v.ServiceCentreAddressOA) < 1 || len(*v.ServiceCentreAddressOA) > 20 {
			if constraintErr := checkDecodedLength(opts, s949588_11, "51.5", "serviceCentreAddressOA", "SIZE (1..20)", len(*v.ServiceCentreAddressOA)); constraintErr != nil {
				return constraintErr
			}
		}
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 5 && peekTag.Constructed == false {
		v.Choice = SMRPOAChoiceNoSMRPOA
		ber.MarkPreflightTarget(opts, "noSM-RP-OA", choiceData)
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData, opts...)
		if tlvErr != nil {
			return qualifyBERError(tlvErr, "noSM-RP-OA", "decoding", false)
		}
		_ = rawVal
		if len(rawVal) != 0 {
			return qualifyBERError(fmt.Errorf("%w: NULL content length %d", ber.ErrInvalidValue, len(rawVal)), "noSM-RP-OA", "decoding", false)
		}
		v.NoSMRPOA = &struct{}{}
	} else {
		return fmt.Errorf("unknown tag %s for SMRPOA CHOICE", peekTag)
	}
	return nil
}

// MarshalBER encodes ReportSMDeliveryStatusArg to BER format.
func (v *ReportSMDeliveryStatusArg) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {

	if v == nil {
		return nil, fmt.Errorf("%w: ReportSMDeliveryStatusArg receiver is nil", ber.ErrInvalidValue)
	}
	return marshalFramedValue(v, v.berReplayNode_, opts, (*ReportSMDeliveryStatusArg).MarshalBER, (*ReportSMDeliveryStatusArg).marshalBER, 3)

}
func (v *ReportSMDeliveryStatusArg) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if len(v.Msisdn) < 1 || len(v.Msisdn) > 9 {
		if constraintErr := checkEncodedLength(opts, s949588_12, "51.5", "msisdn", "SIZE (1..9)", len(v.Msisdn)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	if len(v.Msisdn) < 1 || len(v.Msisdn) > 20 {
		if constraintErr := checkEncodedLength(opts, s949588_12, "51.5", "msisdn", "SIZE (1..20)", len(v.Msisdn)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_msisdn, encodeErr_enc_msisdn := ber.EncodeOctetString([]byte(v.Msisdn))
	if encodeErr_enc_msisdn != nil {
		return nil, qualifyBERError(encodeErr_enc_msisdn, "msisdn", "encoding", false)
	}
	children = append(children, enc_msisdn...)
	if len(v.ServiceCentreAddress) < 1 || len(v.ServiceCentreAddress) > 20 {
		if constraintErr := checkEncodedLength(opts, s949588_12, "51.5", "serviceCentreAddress", "SIZE (1..20)", len(v.ServiceCentreAddress)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_servicecentreaddress, encodeErr_enc_servicecentreaddress := ber.EncodeOctetString([]byte(v.ServiceCentreAddress))
	if encodeErr_enc_servicecentreaddress != nil {
		return nil, qualifyBERError(encodeErr_enc_servicecentreaddress, "serviceCentreAddress", "encoding", false)
	}
	children = append(children, enc_servicecentreaddress...)
	if int64(v.SmDeliveryOutcome) != 0 && int64(v.SmDeliveryOutcome) != 1 && int64(v.SmDeliveryOutcome) != 2 {
		if constraintErr := checkEncodedValue(opts, s949588_12, "20", "sm-DeliveryOutcome", "ENUMERATED {0, 1, 2}", ber.ObserveInteger(int64(v.SmDeliveryOutcome))); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_smdeliveryoutcome := ber.EncodeEnumerated(int64(v.SmDeliveryOutcome))
	children = append(children, enc_smdeliveryoutcome...)
	if v.AbsentSubscriberDiagnosticSM != nil {
		if !(int64(*v.AbsentSubscriberDiagnosticSM) >= 0 && int64(*v.AbsentSubscriberDiagnosticSM) <= 255) {
			if constraintErr := checkEncodedValue(opts, s949588_12, "51.4", "absentSubscriberDiagnosticSM", "(0..255)", ber.ObserveInteger(int64(*v.AbsentSubscriberDiagnosticSM))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_absentsubscriberdiagnosticsm := ber.EncodeInteger(int64(*v.AbsentSubscriberDiagnosticSM))
		retagged_enc_absentsubscriberdiagnosticsm, tagErr_enc_absentsubscriberdiagnosticsm := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_absentsubscriberdiagnosticsm)
		if tagErr_enc_absentsubscriberdiagnosticsm != nil {
			return nil, qualifyBERError(tagErr_enc_absentsubscriberdiagnosticsm, "absentSubscriberDiagnosticSM", "encoding", false)
		}
		enc_absentsubscriberdiagnosticsm = retagged_enc_absentsubscriberdiagnosticsm
		children = append(children, enc_absentsubscriberdiagnosticsm...)
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
	if v.GprsSupportIndicator != nil {
		enc_gprssupportindicator := ber.EncodeNull()
		retagged_enc_gprssupportindicator, tagErr_enc_gprssupportindicator := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_gprssupportindicator)
		if tagErr_enc_gprssupportindicator != nil {
			return nil, qualifyBERError(tagErr_enc_gprssupportindicator, "gprsSupportIndicator", "encoding", false)
		}
		enc_gprssupportindicator = retagged_enc_gprssupportindicator
		children = append(children, enc_gprssupportindicator...)
	}
	if v.DeliveryOutcomeIndicator != nil {
		enc_deliveryoutcomeindicator := ber.EncodeNull()
		retagged_enc_deliveryoutcomeindicator, tagErr_enc_deliveryoutcomeindicator := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, enc_deliveryoutcomeindicator)
		if tagErr_enc_deliveryoutcomeindicator != nil {
			return nil, qualifyBERError(tagErr_enc_deliveryoutcomeindicator, "deliveryOutcomeIndicator", "encoding", false)
		}
		enc_deliveryoutcomeindicator = retagged_enc_deliveryoutcomeindicator
		children = append(children, enc_deliveryoutcomeindicator...)
	}
	if v.AdditionalSMDeliveryOutcome != nil {
		if int64(*v.AdditionalSMDeliveryOutcome) != 0 && int64(*v.AdditionalSMDeliveryOutcome) != 1 && int64(*v.AdditionalSMDeliveryOutcome) != 2 {
			if constraintErr := checkEncodedValue(opts, s949588_12, "20", "additionalSM-DeliveryOutcome", "ENUMERATED {0, 1, 2}", ber.ObserveInteger(int64(*v.AdditionalSMDeliveryOutcome))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_additionalsmdeliveryoutcome := ber.EncodeEnumerated(int64(*v.AdditionalSMDeliveryOutcome))
		retagged_enc_additionalsmdeliveryoutcome, tagErr_enc_additionalsmdeliveryoutcome := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, enc_additionalsmdeliveryoutcome)
		if tagErr_enc_additionalsmdeliveryoutcome != nil {
			return nil, qualifyBERError(tagErr_enc_additionalsmdeliveryoutcome, "additionalSM-DeliveryOutcome", "encoding", false)
		}
		enc_additionalsmdeliveryoutcome = retagged_enc_additionalsmdeliveryoutcome
		children = append(children, enc_additionalsmdeliveryoutcome...)
	}
	if v.AdditionalAbsentSubscriberDiagnosticSM != nil {
		if !(int64(*v.AdditionalAbsentSubscriberDiagnosticSM) >= 0 && int64(*v.AdditionalAbsentSubscriberDiagnosticSM) <= 255) {
			if constraintErr := checkEncodedValue(opts, s949588_12, "51.4", "additionalAbsentSubscriberDiagnosticSM", "(0..255)", ber.ObserveInteger(int64(*v.AdditionalAbsentSubscriberDiagnosticSM))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_additionalabsentsubscriberdiagnosticsm := ber.EncodeInteger(int64(*v.AdditionalAbsentSubscriberDiagnosticSM))
		retagged_enc_additionalabsentsubscriberdiagnosticsm, tagErr_enc_additionalabsentsubscriberdiagnosticsm := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 5, enc_additionalabsentsubscriberdiagnosticsm)
		if tagErr_enc_additionalabsentsubscriberdiagnosticsm != nil {
			return nil, qualifyBERError(tagErr_enc_additionalabsentsubscriberdiagnosticsm, "additionalAbsentSubscriberDiagnosticSM", "encoding", false)
		}
		enc_additionalabsentsubscriberdiagnosticsm = retagged_enc_additionalabsentsubscriberdiagnosticsm
		children = append(children, enc_additionalabsentsubscriberdiagnosticsm...)
	}
	if v.IpSmGwIndicator != nil {
		enc_ipsmgwindicator := ber.EncodeNull()
		retagged_enc_ipsmgwindicator, tagErr_enc_ipsmgwindicator := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 6, enc_ipsmgwindicator)
		if tagErr_enc_ipsmgwindicator != nil {
			return nil, qualifyBERError(tagErr_enc_ipsmgwindicator, "ip-sm-gw-Indicator", "encoding", false)
		}
		enc_ipsmgwindicator = retagged_enc_ipsmgwindicator
		children = append(children, enc_ipsmgwindicator...)
	}
	if v.IpSmGwSmDeliveryOutcome != nil {
		if int64(*v.IpSmGwSmDeliveryOutcome) != 0 && int64(*v.IpSmGwSmDeliveryOutcome) != 1 && int64(*v.IpSmGwSmDeliveryOutcome) != 2 {
			if constraintErr := checkEncodedValue(opts, s949588_12, "20", "ip-sm-gw-sm-deliveryOutcome", "ENUMERATED {0, 1, 2}", ber.ObserveInteger(int64(*v.IpSmGwSmDeliveryOutcome))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_ipsmgwsmdeliveryoutcome := ber.EncodeEnumerated(int64(*v.IpSmGwSmDeliveryOutcome))
		retagged_enc_ipsmgwsmdeliveryoutcome, tagErr_enc_ipsmgwsmdeliveryoutcome := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 7, enc_ipsmgwsmdeliveryoutcome)
		if tagErr_enc_ipsmgwsmdeliveryoutcome != nil {
			return nil, qualifyBERError(tagErr_enc_ipsmgwsmdeliveryoutcome, "ip-sm-gw-sm-deliveryOutcome", "encoding", false)
		}
		enc_ipsmgwsmdeliveryoutcome = retagged_enc_ipsmgwsmdeliveryoutcome
		children = append(children, enc_ipsmgwsmdeliveryoutcome...)
	}
	if v.IpSmGwAbsentSubscriberDiagnosticSM != nil {
		if !(int64(*v.IpSmGwAbsentSubscriberDiagnosticSM) >= 0 && int64(*v.IpSmGwAbsentSubscriberDiagnosticSM) <= 255) {
			if constraintErr := checkEncodedValue(opts, s949588_12, "51.4", "ip-sm-gw-absentSubscriberDiagnosticSM", "(0..255)", ber.ObserveInteger(int64(*v.IpSmGwAbsentSubscriberDiagnosticSM))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_ipsmgwabsentsubscriberdiagnosticsm := ber.EncodeInteger(int64(*v.IpSmGwAbsentSubscriberDiagnosticSM))
		retagged_enc_ipsmgwabsentsubscriberdiagnosticsm, tagErr_enc_ipsmgwabsentsubscriberdiagnosticsm := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 8, enc_ipsmgwabsentsubscriberdiagnosticsm)
		if tagErr_enc_ipsmgwabsentsubscriberdiagnosticsm != nil {
			return nil, qualifyBERError(tagErr_enc_ipsmgwabsentsubscriberdiagnosticsm, "ip-sm-gw-absentSubscriberDiagnosticSM", "encoding", false)
		}
		enc_ipsmgwabsentsubscriberdiagnosticsm = retagged_enc_ipsmgwabsentsubscriberdiagnosticsm
		children = append(children, enc_ipsmgwabsentsubscriberdiagnosticsm...)
	}
	if v.Imsi != nil {
		if len(*v.Imsi) < 3 || len(*v.Imsi) > 8 {
			if constraintErr := checkEncodedLength(opts, s949588_12, "51.5", "imsi", "SIZE (3..8)", len(*v.Imsi)); constraintErr != nil {
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
	if v.SingleAttemptDelivery != nil {
		enc_singleattemptdelivery := ber.EncodeNull()
		retagged_enc_singleattemptdelivery, tagErr_enc_singleattemptdelivery := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 10, enc_singleattemptdelivery)
		if tagErr_enc_singleattemptdelivery != nil {
			return nil, qualifyBERError(tagErr_enc_singleattemptdelivery, "singleAttemptDelivery", "encoding", false)
		}
		enc_singleattemptdelivery = retagged_enc_singleattemptdelivery
		children = append(children, enc_singleattemptdelivery...)
	}
	if v.CorrelationID != nil {
		enc_correlationid, err := v.CorrelationID.MarshalBER(ber.ChildEncodeOptions(opts, "correlationID")...)
		if err != nil {
			return nil, qualifyBERError(err, "correlationID", "encoding", false)
		}
		retagged_enc_correlationid, tagErr_enc_correlationid := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 11, enc_correlationid)
		if tagErr_enc_correlationid != nil {
			return nil, qualifyBERError(tagErr_enc_correlationid, "correlationID", "encoding", false)
		}
		enc_correlationid = retagged_enc_correlationid
		ber.RecordGeneratedBERChildPlacement(opts, len(children), enc_correlationid)
		children = append(children, enc_correlationid...)
	}
	if v.Smsf3gppDeliveryOutcomeIndicator != nil {
		enc_smsf3gppdeliveryoutcomeindicator := ber.EncodeNull()
		retagged_enc_smsf3gppdeliveryoutcomeindicator, tagErr_enc_smsf3gppdeliveryoutcomeindicator := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 12, enc_smsf3gppdeliveryoutcomeindicator)
		if tagErr_enc_smsf3gppdeliveryoutcomeindicator != nil {
			return nil, qualifyBERError(tagErr_enc_smsf3gppdeliveryoutcomeindicator, "smsf-3gpp-deliveryOutcomeIndicator", "encoding", false)
		}
		enc_smsf3gppdeliveryoutcomeindicator = retagged_enc_smsf3gppdeliveryoutcomeindicator
		children = append(children, enc_smsf3gppdeliveryoutcomeindicator...)
	}
	if v.Smsf3gppDeliveryOutcome != nil {
		if int64(*v.Smsf3gppDeliveryOutcome) != 0 && int64(*v.Smsf3gppDeliveryOutcome) != 1 && int64(*v.Smsf3gppDeliveryOutcome) != 2 {
			if constraintErr := checkEncodedValue(opts, s949588_12, "20", "smsf-3gpp-deliveryOutcome", "ENUMERATED {0, 1, 2}", ber.ObserveInteger(int64(*v.Smsf3gppDeliveryOutcome))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_smsf3gppdeliveryoutcome := ber.EncodeEnumerated(int64(*v.Smsf3gppDeliveryOutcome))
		retagged_enc_smsf3gppdeliveryoutcome, tagErr_enc_smsf3gppdeliveryoutcome := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 13, enc_smsf3gppdeliveryoutcome)
		if tagErr_enc_smsf3gppdeliveryoutcome != nil {
			return nil, qualifyBERError(tagErr_enc_smsf3gppdeliveryoutcome, "smsf-3gpp-deliveryOutcome", "encoding", false)
		}
		enc_smsf3gppdeliveryoutcome = retagged_enc_smsf3gppdeliveryoutcome
		children = append(children, enc_smsf3gppdeliveryoutcome...)
	}
	if v.Smsf3gppAbsentSubscriberDiagSM != nil {
		if !(int64(*v.Smsf3gppAbsentSubscriberDiagSM) >= 0 && int64(*v.Smsf3gppAbsentSubscriberDiagSM) <= 255) {
			if constraintErr := checkEncodedValue(opts, s949588_12, "51.4", "smsf-3gpp-absentSubscriberDiagSM", "(0..255)", ber.ObserveInteger(int64(*v.Smsf3gppAbsentSubscriberDiagSM))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_smsf3gppabsentsubscriberdiagsm := ber.EncodeInteger(int64(*v.Smsf3gppAbsentSubscriberDiagSM))
		retagged_enc_smsf3gppabsentsubscriberdiagsm, tagErr_enc_smsf3gppabsentsubscriberdiagsm := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 14, enc_smsf3gppabsentsubscriberdiagsm)
		if tagErr_enc_smsf3gppabsentsubscriberdiagsm != nil {
			return nil, qualifyBERError(tagErr_enc_smsf3gppabsentsubscriberdiagsm, "smsf-3gpp-absentSubscriberDiagSM", "encoding", false)
		}
		enc_smsf3gppabsentsubscriberdiagsm = retagged_enc_smsf3gppabsentsubscriberdiagsm
		children = append(children, enc_smsf3gppabsentsubscriberdiagsm...)
	}
	if v.SmsfNon3gppDeliveryOutcomeIndicator != nil {
		enc_smsfnon3gppdeliveryoutcomeindicator := ber.EncodeNull()
		retagged_enc_smsfnon3gppdeliveryoutcomeindicator, tagErr_enc_smsfnon3gppdeliveryoutcomeindicator := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 15, enc_smsfnon3gppdeliveryoutcomeindicator)
		if tagErr_enc_smsfnon3gppdeliveryoutcomeindicator != nil {
			return nil, qualifyBERError(tagErr_enc_smsfnon3gppdeliveryoutcomeindicator, "smsf-non-3gpp-deliveryOutcomeIndicator", "encoding", false)
		}
		enc_smsfnon3gppdeliveryoutcomeindicator = retagged_enc_smsfnon3gppdeliveryoutcomeindicator
		children = append(children, enc_smsfnon3gppdeliveryoutcomeindicator...)
	}
	if v.SmsfNon3gppDeliveryOutcome != nil {
		if int64(*v.SmsfNon3gppDeliveryOutcome) != 0 && int64(*v.SmsfNon3gppDeliveryOutcome) != 1 && int64(*v.SmsfNon3gppDeliveryOutcome) != 2 {
			if constraintErr := checkEncodedValue(opts, s949588_12, "20", "smsf-non-3gpp-deliveryOutcome", "ENUMERATED {0, 1, 2}", ber.ObserveInteger(int64(*v.SmsfNon3gppDeliveryOutcome))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_smsfnon3gppdeliveryoutcome := ber.EncodeEnumerated(int64(*v.SmsfNon3gppDeliveryOutcome))
		retagged_enc_smsfnon3gppdeliveryoutcome, tagErr_enc_smsfnon3gppdeliveryoutcome := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 16, enc_smsfnon3gppdeliveryoutcome)
		if tagErr_enc_smsfnon3gppdeliveryoutcome != nil {
			return nil, qualifyBERError(tagErr_enc_smsfnon3gppdeliveryoutcome, "smsf-non-3gpp-deliveryOutcome", "encoding", false)
		}
		enc_smsfnon3gppdeliveryoutcome = retagged_enc_smsfnon3gppdeliveryoutcome
		children = append(children, enc_smsfnon3gppdeliveryoutcome...)
	}
	if v.SmsfNon3gppAbsentSubscriberDiagSM != nil {
		if !(int64(*v.SmsfNon3gppAbsentSubscriberDiagSM) >= 0 && int64(*v.SmsfNon3gppAbsentSubscriberDiagSM) <= 255) {
			if constraintErr := checkEncodedValue(opts, s949588_12, "51.4", "smsf-non-3gpp-absentSubscriberDiagSM", "(0..255)", ber.ObserveInteger(int64(*v.SmsfNon3gppAbsentSubscriberDiagSM))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_smsfnon3gppabsentsubscriberdiagsm := ber.EncodeInteger(int64(*v.SmsfNon3gppAbsentSubscriberDiagSM))
		retagged_enc_smsfnon3gppabsentsubscriberdiagsm, tagErr_enc_smsfnon3gppabsentsubscriberdiagsm := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 17, enc_smsfnon3gppabsentsubscriberdiagsm)
		if tagErr_enc_smsfnon3gppabsentsubscriberdiagsm != nil {
			return nil, qualifyBERError(tagErr_enc_smsfnon3gppabsentsubscriberdiagsm, "smsf-non-3gpp-absentSubscriberDiagSM", "encoding", false)
		}
		enc_smsfnon3gppabsentsubscriberdiagsm = retagged_enc_smsfnon3gppabsentsubscriberdiagsm
		children = append(children, enc_smsfnon3gppabsentsubscriberdiagsm...)
	}
	if v.FailedSMServingNodes != nil {
		if len((v.FailedSMServingNodes).Values) < 1 || len((v.FailedSMServingNodes).Values) > 5 {
			if constraintErr := checkEncodedLength(opts, s949588_12, "51.5", "failedSMServingNodes", "SIZE (1..5)", len((v.FailedSMServingNodes).Values)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_failedsmservingnodes, err := MarshalBERSMServingNodeAddressList(v.FailedSMServingNodes, ber.ParentCollectionSizeEncodeOptions(ber.ChildEncodeOptions(opts, "failedSMServingNodes"))...)
		if err != nil {
			return nil, qualifyBERError(err, "failedSMServingNodes", "encoding", false)
		}
		if ber.BERReplayEnabled(opts) && v.berFailedSMServingNodesIndef_ {
			// Strip the outer SEQUENCE tag from marshalBER output to get raw children.
			_, _, seqContent_, tlvErr_ := ber.DecodeEncodedTLV(enc_failedsmservingnodes)
			if tlvErr_ != nil {
				return nil, tlvErr_
			}
			{
				var encodeErr error
				enc_failedsmservingnodes, encodeErr = ber.EncodeConstructedIndefinite(tag.Tag{Class: tag.ClassContextSpecific, Number: 18}, seqContent_)
				if encodeErr != nil {
					return nil, qualifyBERError(encodeErr, "failedSMServingNodes", "encoding", false)
				}
			}
		} else {
			retagged_enc_failedsmservingnodes, tagErr_enc_failedsmservingnodes := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 18, enc_failedsmservingnodes)
			if tagErr_enc_failedsmservingnodes != nil {
				return nil, qualifyBERError(tagErr_enc_failedsmservingnodes, "failedSMServingNodes", "encoding", false)
			}
			enc_failedsmservingnodes = retagged_enc_failedsmservingnodes
		}
		ber.RecordGeneratedBERChildPlacement(opts, len(children), enc_failedsmservingnodes)
		children = append(children, enc_failedsmservingnodes...)
	}
	base_ := -1
	for i, ext := range v.ExtData_ {
		if err := checkOpaqueAddition(ext, opts, s949588_12, children, i, &base_); err != nil {
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
		if i == 0 && ((peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 18) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 17) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 16) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 15) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 14) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 13) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 12) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 11) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 10) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 9) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 8) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 7) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 6) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 5) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0)) {
			if constraintErr := ber.CheckEncodedValue(ber.EncodeRule(opts, s949588_12, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
				return nil, constraintErr
			}
		}
		children = append(children, ext...)
	}
	ber.RecordGeneratedBERContainer(opts, children)
	return ber.EncodeSequence(children)
}
func (v *ReportSMDeliveryStatusArg) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// MarshalDER encodes ReportSMDeliveryStatusArg to DER format.
// Opaque descendants pass generic DER checks; foreign schema rules need a typed binding.
func (v *ReportSMDeliveryStatusArg) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: ReportSMDeliveryStatusArg receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if len(v.Msisdn) < 1 || len(v.Msisdn) > 9 {
		if constraintErr := checkEncodedLength(nil, s949588_12, "51.5", "msisdn", "SIZE (1..9)", len(v.Msisdn)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	if len(v.Msisdn) < 1 || len(v.Msisdn) > 20 {
		if constraintErr := checkEncodedLength(nil, s949588_12, "51.5", "msisdn", "SIZE (1..20)", len(v.Msisdn)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_msisdn, encodeErr_enc_msisdn := ber.EncodeOctetString([]byte(v.Msisdn))
	if encodeErr_enc_msisdn != nil {
		return nil, qualifyBERError(encodeErr_enc_msisdn, "msisdn", "encoding", true)
	}
	children = append(children, enc_msisdn...)
	if len(v.ServiceCentreAddress) < 1 || len(v.ServiceCentreAddress) > 20 {
		if constraintErr := checkEncodedLength(nil, s949588_12, "51.5", "serviceCentreAddress", "SIZE (1..20)", len(v.ServiceCentreAddress)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_servicecentreaddress, encodeErr_enc_servicecentreaddress := ber.EncodeOctetString([]byte(v.ServiceCentreAddress))
	if encodeErr_enc_servicecentreaddress != nil {
		return nil, qualifyBERError(encodeErr_enc_servicecentreaddress, "serviceCentreAddress", "encoding", true)
	}
	children = append(children, enc_servicecentreaddress...)
	if int64(v.SmDeliveryOutcome) != 0 && int64(v.SmDeliveryOutcome) != 1 && int64(v.SmDeliveryOutcome) != 2 {
		if constraintErr := checkEncodedValue(nil, s949588_12, "20", "sm-DeliveryOutcome", "ENUMERATED {0, 1, 2}", ber.ObserveInteger(int64(v.SmDeliveryOutcome))); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_smdeliveryoutcome := ber.EncodeEnumerated(int64(v.SmDeliveryOutcome))
	children = append(children, enc_smdeliveryoutcome...)
	if v.AbsentSubscriberDiagnosticSM != nil {
		if !(int64(*v.AbsentSubscriberDiagnosticSM) >= 0 && int64(*v.AbsentSubscriberDiagnosticSM) <= 255) {
			if constraintErr := checkEncodedValue(nil, s949588_12, "51.4", "absentSubscriberDiagnosticSM", "(0..255)", ber.ObserveInteger(int64(*v.AbsentSubscriberDiagnosticSM))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_absentsubscriberdiagnosticsm := ber.EncodeInteger(int64(*v.AbsentSubscriberDiagnosticSM))
		retagged_enc_absentsubscriberdiagnosticsm, tagErr_enc_absentsubscriberdiagnosticsm := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_absentsubscriberdiagnosticsm)
		if tagErr_enc_absentsubscriberdiagnosticsm != nil {
			return nil, qualifyBERError(tagErr_enc_absentsubscriberdiagnosticsm, "absentSubscriberDiagnosticSM", "encoding", true)
		}
		enc_absentsubscriberdiagnosticsm = retagged_enc_absentsubscriberdiagnosticsm
		children = append(children, enc_absentsubscriberdiagnosticsm...)
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
	if v.GprsSupportIndicator != nil {
		enc_gprssupportindicator := ber.EncodeNull()
		retagged_enc_gprssupportindicator, tagErr_enc_gprssupportindicator := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_gprssupportindicator)
		if tagErr_enc_gprssupportindicator != nil {
			return nil, qualifyBERError(tagErr_enc_gprssupportindicator, "gprsSupportIndicator", "encoding", true)
		}
		enc_gprssupportindicator = retagged_enc_gprssupportindicator
		children = append(children, enc_gprssupportindicator...)
	}
	if v.DeliveryOutcomeIndicator != nil {
		enc_deliveryoutcomeindicator := ber.EncodeNull()
		retagged_enc_deliveryoutcomeindicator, tagErr_enc_deliveryoutcomeindicator := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, enc_deliveryoutcomeindicator)
		if tagErr_enc_deliveryoutcomeindicator != nil {
			return nil, qualifyBERError(tagErr_enc_deliveryoutcomeindicator, "deliveryOutcomeIndicator", "encoding", true)
		}
		enc_deliveryoutcomeindicator = retagged_enc_deliveryoutcomeindicator
		children = append(children, enc_deliveryoutcomeindicator...)
	}
	if v.AdditionalSMDeliveryOutcome != nil {
		if int64(*v.AdditionalSMDeliveryOutcome) != 0 && int64(*v.AdditionalSMDeliveryOutcome) != 1 && int64(*v.AdditionalSMDeliveryOutcome) != 2 {
			if constraintErr := checkEncodedValue(nil, s949588_12, "20", "additionalSM-DeliveryOutcome", "ENUMERATED {0, 1, 2}", ber.ObserveInteger(int64(*v.AdditionalSMDeliveryOutcome))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_additionalsmdeliveryoutcome := ber.EncodeEnumerated(int64(*v.AdditionalSMDeliveryOutcome))
		retagged_enc_additionalsmdeliveryoutcome, tagErr_enc_additionalsmdeliveryoutcome := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, enc_additionalsmdeliveryoutcome)
		if tagErr_enc_additionalsmdeliveryoutcome != nil {
			return nil, qualifyBERError(tagErr_enc_additionalsmdeliveryoutcome, "additionalSM-DeliveryOutcome", "encoding", true)
		}
		enc_additionalsmdeliveryoutcome = retagged_enc_additionalsmdeliveryoutcome
		children = append(children, enc_additionalsmdeliveryoutcome...)
	}
	if v.AdditionalAbsentSubscriberDiagnosticSM != nil {
		if !(int64(*v.AdditionalAbsentSubscriberDiagnosticSM) >= 0 && int64(*v.AdditionalAbsentSubscriberDiagnosticSM) <= 255) {
			if constraintErr := checkEncodedValue(nil, s949588_12, "51.4", "additionalAbsentSubscriberDiagnosticSM", "(0..255)", ber.ObserveInteger(int64(*v.AdditionalAbsentSubscriberDiagnosticSM))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_additionalabsentsubscriberdiagnosticsm := ber.EncodeInteger(int64(*v.AdditionalAbsentSubscriberDiagnosticSM))
		retagged_enc_additionalabsentsubscriberdiagnosticsm, tagErr_enc_additionalabsentsubscriberdiagnosticsm := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 5, enc_additionalabsentsubscriberdiagnosticsm)
		if tagErr_enc_additionalabsentsubscriberdiagnosticsm != nil {
			return nil, qualifyBERError(tagErr_enc_additionalabsentsubscriberdiagnosticsm, "additionalAbsentSubscriberDiagnosticSM", "encoding", true)
		}
		enc_additionalabsentsubscriberdiagnosticsm = retagged_enc_additionalabsentsubscriberdiagnosticsm
		children = append(children, enc_additionalabsentsubscriberdiagnosticsm...)
	}
	if v.IpSmGwIndicator != nil {
		enc_ipsmgwindicator := ber.EncodeNull()
		retagged_enc_ipsmgwindicator, tagErr_enc_ipsmgwindicator := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 6, enc_ipsmgwindicator)
		if tagErr_enc_ipsmgwindicator != nil {
			return nil, qualifyBERError(tagErr_enc_ipsmgwindicator, "ip-sm-gw-Indicator", "encoding", true)
		}
		enc_ipsmgwindicator = retagged_enc_ipsmgwindicator
		children = append(children, enc_ipsmgwindicator...)
	}
	if v.IpSmGwSmDeliveryOutcome != nil {
		if int64(*v.IpSmGwSmDeliveryOutcome) != 0 && int64(*v.IpSmGwSmDeliveryOutcome) != 1 && int64(*v.IpSmGwSmDeliveryOutcome) != 2 {
			if constraintErr := checkEncodedValue(nil, s949588_12, "20", "ip-sm-gw-sm-deliveryOutcome", "ENUMERATED {0, 1, 2}", ber.ObserveInteger(int64(*v.IpSmGwSmDeliveryOutcome))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_ipsmgwsmdeliveryoutcome := ber.EncodeEnumerated(int64(*v.IpSmGwSmDeliveryOutcome))
		retagged_enc_ipsmgwsmdeliveryoutcome, tagErr_enc_ipsmgwsmdeliveryoutcome := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 7, enc_ipsmgwsmdeliveryoutcome)
		if tagErr_enc_ipsmgwsmdeliveryoutcome != nil {
			return nil, qualifyBERError(tagErr_enc_ipsmgwsmdeliveryoutcome, "ip-sm-gw-sm-deliveryOutcome", "encoding", true)
		}
		enc_ipsmgwsmdeliveryoutcome = retagged_enc_ipsmgwsmdeliveryoutcome
		children = append(children, enc_ipsmgwsmdeliveryoutcome...)
	}
	if v.IpSmGwAbsentSubscriberDiagnosticSM != nil {
		if !(int64(*v.IpSmGwAbsentSubscriberDiagnosticSM) >= 0 && int64(*v.IpSmGwAbsentSubscriberDiagnosticSM) <= 255) {
			if constraintErr := checkEncodedValue(nil, s949588_12, "51.4", "ip-sm-gw-absentSubscriberDiagnosticSM", "(0..255)", ber.ObserveInteger(int64(*v.IpSmGwAbsentSubscriberDiagnosticSM))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_ipsmgwabsentsubscriberdiagnosticsm := ber.EncodeInteger(int64(*v.IpSmGwAbsentSubscriberDiagnosticSM))
		retagged_enc_ipsmgwabsentsubscriberdiagnosticsm, tagErr_enc_ipsmgwabsentsubscriberdiagnosticsm := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 8, enc_ipsmgwabsentsubscriberdiagnosticsm)
		if tagErr_enc_ipsmgwabsentsubscriberdiagnosticsm != nil {
			return nil, qualifyBERError(tagErr_enc_ipsmgwabsentsubscriberdiagnosticsm, "ip-sm-gw-absentSubscriberDiagnosticSM", "encoding", true)
		}
		enc_ipsmgwabsentsubscriberdiagnosticsm = retagged_enc_ipsmgwabsentsubscriberdiagnosticsm
		children = append(children, enc_ipsmgwabsentsubscriberdiagnosticsm...)
	}
	if v.Imsi != nil {
		if len(*v.Imsi) < 3 || len(*v.Imsi) > 8 {
			if constraintErr := checkEncodedLength(nil, s949588_12, "51.5", "imsi", "SIZE (3..8)", len(*v.Imsi)); constraintErr != nil {
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
	if v.SingleAttemptDelivery != nil {
		enc_singleattemptdelivery := ber.EncodeNull()
		retagged_enc_singleattemptdelivery, tagErr_enc_singleattemptdelivery := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 10, enc_singleattemptdelivery)
		if tagErr_enc_singleattemptdelivery != nil {
			return nil, qualifyBERError(tagErr_enc_singleattemptdelivery, "singleAttemptDelivery", "encoding", true)
		}
		enc_singleattemptdelivery = retagged_enc_singleattemptdelivery
		children = append(children, enc_singleattemptdelivery...)
	}
	if v.CorrelationID != nil {
		enc_correlationid, err := v.CorrelationID.MarshalDER()
		if err != nil {
			return nil, qualifyBERError(err, "correlationID", "encoding", true)
		}
		retagged_enc_correlationid, tagErr_enc_correlationid := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 11, enc_correlationid)
		if tagErr_enc_correlationid != nil {
			return nil, qualifyBERError(tagErr_enc_correlationid, "correlationID", "encoding", true)
		}
		enc_correlationid = retagged_enc_correlationid
		children = append(children, enc_correlationid...)
	}
	if v.Smsf3gppDeliveryOutcomeIndicator != nil {
		enc_smsf3gppdeliveryoutcomeindicator := ber.EncodeNull()
		retagged_enc_smsf3gppdeliveryoutcomeindicator, tagErr_enc_smsf3gppdeliveryoutcomeindicator := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 12, enc_smsf3gppdeliveryoutcomeindicator)
		if tagErr_enc_smsf3gppdeliveryoutcomeindicator != nil {
			return nil, qualifyBERError(tagErr_enc_smsf3gppdeliveryoutcomeindicator, "smsf-3gpp-deliveryOutcomeIndicator", "encoding", true)
		}
		enc_smsf3gppdeliveryoutcomeindicator = retagged_enc_smsf3gppdeliveryoutcomeindicator
		children = append(children, enc_smsf3gppdeliveryoutcomeindicator...)
	}
	if v.Smsf3gppDeliveryOutcome != nil {
		if int64(*v.Smsf3gppDeliveryOutcome) != 0 && int64(*v.Smsf3gppDeliveryOutcome) != 1 && int64(*v.Smsf3gppDeliveryOutcome) != 2 {
			if constraintErr := checkEncodedValue(nil, s949588_12, "20", "smsf-3gpp-deliveryOutcome", "ENUMERATED {0, 1, 2}", ber.ObserveInteger(int64(*v.Smsf3gppDeliveryOutcome))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_smsf3gppdeliveryoutcome := ber.EncodeEnumerated(int64(*v.Smsf3gppDeliveryOutcome))
		retagged_enc_smsf3gppdeliveryoutcome, tagErr_enc_smsf3gppdeliveryoutcome := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 13, enc_smsf3gppdeliveryoutcome)
		if tagErr_enc_smsf3gppdeliveryoutcome != nil {
			return nil, qualifyBERError(tagErr_enc_smsf3gppdeliveryoutcome, "smsf-3gpp-deliveryOutcome", "encoding", true)
		}
		enc_smsf3gppdeliveryoutcome = retagged_enc_smsf3gppdeliveryoutcome
		children = append(children, enc_smsf3gppdeliveryoutcome...)
	}
	if v.Smsf3gppAbsentSubscriberDiagSM != nil {
		if !(int64(*v.Smsf3gppAbsentSubscriberDiagSM) >= 0 && int64(*v.Smsf3gppAbsentSubscriberDiagSM) <= 255) {
			if constraintErr := checkEncodedValue(nil, s949588_12, "51.4", "smsf-3gpp-absentSubscriberDiagSM", "(0..255)", ber.ObserveInteger(int64(*v.Smsf3gppAbsentSubscriberDiagSM))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_smsf3gppabsentsubscriberdiagsm := ber.EncodeInteger(int64(*v.Smsf3gppAbsentSubscriberDiagSM))
		retagged_enc_smsf3gppabsentsubscriberdiagsm, tagErr_enc_smsf3gppabsentsubscriberdiagsm := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 14, enc_smsf3gppabsentsubscriberdiagsm)
		if tagErr_enc_smsf3gppabsentsubscriberdiagsm != nil {
			return nil, qualifyBERError(tagErr_enc_smsf3gppabsentsubscriberdiagsm, "smsf-3gpp-absentSubscriberDiagSM", "encoding", true)
		}
		enc_smsf3gppabsentsubscriberdiagsm = retagged_enc_smsf3gppabsentsubscriberdiagsm
		children = append(children, enc_smsf3gppabsentsubscriberdiagsm...)
	}
	if v.SmsfNon3gppDeliveryOutcomeIndicator != nil {
		enc_smsfnon3gppdeliveryoutcomeindicator := ber.EncodeNull()
		retagged_enc_smsfnon3gppdeliveryoutcomeindicator, tagErr_enc_smsfnon3gppdeliveryoutcomeindicator := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 15, enc_smsfnon3gppdeliveryoutcomeindicator)
		if tagErr_enc_smsfnon3gppdeliveryoutcomeindicator != nil {
			return nil, qualifyBERError(tagErr_enc_smsfnon3gppdeliveryoutcomeindicator, "smsf-non-3gpp-deliveryOutcomeIndicator", "encoding", true)
		}
		enc_smsfnon3gppdeliveryoutcomeindicator = retagged_enc_smsfnon3gppdeliveryoutcomeindicator
		children = append(children, enc_smsfnon3gppdeliveryoutcomeindicator...)
	}
	if v.SmsfNon3gppDeliveryOutcome != nil {
		if int64(*v.SmsfNon3gppDeliveryOutcome) != 0 && int64(*v.SmsfNon3gppDeliveryOutcome) != 1 && int64(*v.SmsfNon3gppDeliveryOutcome) != 2 {
			if constraintErr := checkEncodedValue(nil, s949588_12, "20", "smsf-non-3gpp-deliveryOutcome", "ENUMERATED {0, 1, 2}", ber.ObserveInteger(int64(*v.SmsfNon3gppDeliveryOutcome))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_smsfnon3gppdeliveryoutcome := ber.EncodeEnumerated(int64(*v.SmsfNon3gppDeliveryOutcome))
		retagged_enc_smsfnon3gppdeliveryoutcome, tagErr_enc_smsfnon3gppdeliveryoutcome := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 16, enc_smsfnon3gppdeliveryoutcome)
		if tagErr_enc_smsfnon3gppdeliveryoutcome != nil {
			return nil, qualifyBERError(tagErr_enc_smsfnon3gppdeliveryoutcome, "smsf-non-3gpp-deliveryOutcome", "encoding", true)
		}
		enc_smsfnon3gppdeliveryoutcome = retagged_enc_smsfnon3gppdeliveryoutcome
		children = append(children, enc_smsfnon3gppdeliveryoutcome...)
	}
	if v.SmsfNon3gppAbsentSubscriberDiagSM != nil {
		if !(int64(*v.SmsfNon3gppAbsentSubscriberDiagSM) >= 0 && int64(*v.SmsfNon3gppAbsentSubscriberDiagSM) <= 255) {
			if constraintErr := checkEncodedValue(nil, s949588_12, "51.4", "smsf-non-3gpp-absentSubscriberDiagSM", "(0..255)", ber.ObserveInteger(int64(*v.SmsfNon3gppAbsentSubscriberDiagSM))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_smsfnon3gppabsentsubscriberdiagsm := ber.EncodeInteger(int64(*v.SmsfNon3gppAbsentSubscriberDiagSM))
		retagged_enc_smsfnon3gppabsentsubscriberdiagsm, tagErr_enc_smsfnon3gppabsentsubscriberdiagsm := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 17, enc_smsfnon3gppabsentsubscriberdiagsm)
		if tagErr_enc_smsfnon3gppabsentsubscriberdiagsm != nil {
			return nil, qualifyBERError(tagErr_enc_smsfnon3gppabsentsubscriberdiagsm, "smsf-non-3gpp-absentSubscriberDiagSM", "encoding", true)
		}
		enc_smsfnon3gppabsentsubscriberdiagsm = retagged_enc_smsfnon3gppabsentsubscriberdiagsm
		children = append(children, enc_smsfnon3gppabsentsubscriberdiagsm...)
	}
	if v.FailedSMServingNodes != nil {
		if len((v.FailedSMServingNodes).Values) < 1 || len((v.FailedSMServingNodes).Values) > 5 {
			if constraintErr := checkEncodedLength(nil, s949588_12, "51.5", "failedSMServingNodes", "SIZE (1..5)", len((v.FailedSMServingNodes).Values)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_failedsmservingnodes, err := MarshalDERSMServingNodeAddressList(v.FailedSMServingNodes)
		if err != nil {
			return nil, qualifyBERError(err, "failedSMServingNodes", "encoding", true)
		}
		retagged_enc_failedsmservingnodes, tagErr_enc_failedsmservingnodes := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 18, enc_failedsmservingnodes)
		if tagErr_enc_failedsmservingnodes != nil {
			return nil, qualifyBERError(tagErr_enc_failedsmservingnodes, "failedSMServingNodes", "encoding", true)
		}
		enc_failedsmservingnodes = retagged_enc_failedsmservingnodes
		children = append(children, enc_failedsmservingnodes...)
	}
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDEREncodedElement(ext); err != nil {
			return nil, invalidDERAddition(ext, s949588_12, children, i)
		}
		peekTag, _, _, extErr := ber.DecodeEncodedTLV(ext)
		if extErr != nil {
			return nil, extErr
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: only the first addition is restricted.
		if i == 0 && ((peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 18) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 17) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 16) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 15) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 14) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 13) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 12) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 11) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 10) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 9) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 8) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 7) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 6) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 5) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0)) {
			if constraintErr := ber.CheckEncodedValue(ber.EncodeRule(nil, s949588_12, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
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
		return nil, fmt.Errorf("%s: %w", "encoding ReportSMDeliveryStatusArg as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}
func (v *ReportSMDeliveryStatusArg) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	encoded, err := v.MarshalDER()
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBER decodes ReportSMDeliveryStatusArg from BER/DER format.
func (destination *ReportSMDeliveryStatusArg) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if destination == nil {
		return fmt.Errorf("%w: ReportSMDeliveryStatusArg destination is nil", ber.ErrInvalidValue)
	}
	v := new(ReportSMDeliveryStatusArg)

	defer publishDecodedValue(destination, v, &returnErr)

	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	preparedData, preparedOptions, prepareErr := prepareCompositeBER(data, opts, s949588_12, "child", (*ReportSMDeliveryStatusArg).UnmarshalBER)
	if prepareErr != nil {
		return prepareErr
	}
	data, opts = preparedData, preparedOptions

	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
	*v = ReportSMDeliveryStatusArg{}
	defer func() {
		if returnErr == nil {
			returnErr = completeValueBER(data,
				opts, v, &v.berReplayNode_, (*ReportSMDeliveryStatusArg).MarshalBER)
		}

	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("%s: %w", "decoding ReportSMDeliveryStatusArg SEQUENCE", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "ReportSMDeliveryStatusArg", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode msisdn
	if offset >= len(content) {
		return fmt.Errorf("missing required field msisdn")
	}
	{
		ber.MarkPreflightTarget(opts, "msisdn", content[offset:])
		val_msisdn, n, err := ber.DecodeOctetString(content[offset:], opts...)
		if err != nil {
			return qualifyBERError(err, "msisdn", "decoding", false)
		}
		v.Msisdn = ISDNAddressString(val_msisdn)
		if offset > len(content) || n < 0 || n > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n
		if len(v.Msisdn) < 1 || len(v.Msisdn) > 9 {
			if constraintErr := checkDecodedLength(opts, s949588_12, "51.5", "msisdn", "SIZE (1..9)", len(v.Msisdn)); constraintErr != nil {
				return constraintErr
			}
		}
		if len(v.Msisdn) < 1 || len(v.Msisdn) > 20 {
			if constraintErr := checkDecodedLength(opts, s949588_12, "51.5", "msisdn", "SIZE (1..20)", len(v.Msisdn)); constraintErr != nil {
				return constraintErr
			}
		}
	}
	// Decode serviceCentreAddress
	if offset >= len(content) {
		return fmt.Errorf("missing required field serviceCentreAddress")
	}
	{
		ber.MarkPreflightTarget(opts, "serviceCentreAddress", content[offset:])
		val_servicecentreaddress, n, err := ber.DecodeOctetString(content[offset:], opts...)
		if err != nil {
			return qualifyBERError(err, "serviceCentreAddress", "decoding", false)
		}
		v.ServiceCentreAddress = AddressString(val_servicecentreaddress)
		if offset < 0 || offset >
			len(content) || n < 0 || n > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n
		if len(v.ServiceCentreAddress) < 1 || len(v.ServiceCentreAddress) > 20 {
			if constraintErr := checkDecodedLength(opts, s949588_12, "51.5", "serviceCentreAddress", "SIZE (1..20)", len(v.ServiceCentreAddress)); constraintErr != nil {
				return constraintErr
			}
		}
	}
	// Decode sm-DeliveryOutcome
	if offset >= len(content) {
		return fmt.Errorf("missing required field sm-DeliveryOutcome")
	}
	{
		ber.MarkPreflightTarget(opts, "sm-DeliveryOutcome", content[offset:])
		val_smdeliveryoutcome, n, err := ber.DecodeEnumerated(content[offset:], opts...)
		if err != nil {
			return qualifyBERError(err, "sm-DeliveryOutcome", "decoding", false)
		}
		v.SmDeliveryOutcome = SMDeliveryOutcome(val_smdeliveryoutcome)
		if offset < 0 || offset >
			len(content) || n < 0 || n > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n
		if int64(v.SmDeliveryOutcome) != 0 && int64(v.SmDeliveryOutcome) != 1 && int64(v.SmDeliveryOutcome) != 2 {
			if constraintErr := checkDecodedValue(opts, s949588_12, "20", "sm-DeliveryOutcome", "ENUMERATED {0, 1, 2}", ber.ObserveInteger(int64(v.SmDeliveryOutcome))); constraintErr != nil {
				return constraintErr
			}
		}
	}
	// Decode absentSubscriberDiagnosticSM
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
				ber.MarkPreflightTarget(opts, "absentSubscriberDiagnosticSM", content[offset:])
				decodedTag_absentsubscriberdiagnosticsm, n_absentsubscriberdiagnosticsm, rawVal_absentsubscriberdiagnosticsm, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "absentSubscriberDiagnosticSM", "decoding", false)
				}
				if decodedTag_absentsubscriberdiagnosticsm.Class != tag.ClassContextSpecific || decodedTag_absentsubscriberdiagnosticsm.Number != 0 || decodedTag_absentsubscriberdiagnosticsm.Constructed != false {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_absentsubscriberdiagnosticsm), "absentSubscriberDiagnosticSM", "decoding", false)
				}
				decVal_absentsubscriberdiagnosticsm, intErr := ber.DecodeIntegerValue(rawVal_absentsubscriberdiagnosticsm)
				if intErr != nil {
					return qualifyBERError(intErr, "absentSubscriberDiagnosticSM", "decoding", false)
				}
				tmp_absentsubscriberdiagnosticsm := AbsentSubscriberDiagnosticSM(decVal_absentsubscriberdiagnosticsm)
				v.AbsentSubscriberDiagnosticSM = &tmp_absentsubscriberdiagnosticsm
				if offset < 0 || offset >
					len(content) || n_absentsubscriberdiagnosticsm < 0 || n_absentsubscriberdiagnosticsm >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_absentsubscriberdiagnosticsm
				if !(int64(*v.AbsentSubscriberDiagnosticSM) >= 0 && int64(*v.AbsentSubscriberDiagnosticSM) <= 255) {
					if constraintErr := checkDecodedValue(opts, s949588_12, "51.4", "absentSubscriberDiagnosticSM", "(0..255)", ber.ObserveInteger(int64(*v.AbsentSubscriberDiagnosticSM))); constraintErr != nil {
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
	// Decode gprsSupportIndicator
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2 {
				ber.MarkPreflightTarget(opts, "gprsSupportIndicator", content[offset:])
				decodedTag_gprssupportindicator, n_gprssupportindicator, rawVal_gprssupportindicator, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "gprsSupportIndicator", "decoding", false)
				}
				if decodedTag_gprssupportindicator.Class != tag.ClassContextSpecific || decodedTag_gprssupportindicator.Number != 2 || decodedTag_gprssupportindicator.Constructed != false {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_gprssupportindicator), "gprsSupportIndicator", "decoding", false)
				}
				if len(rawVal_gprssupportindicator) != 0 {
					return qualifyBERError(fmt.Errorf("%w: NULL content length %d", ber.ErrInvalidValue, len(rawVal_gprssupportindicator)), "gprsSupportIndicator", "decoding", false)
				}
				v.GprsSupportIndicator = &struct{}{}
				if offset < 0 || offset >
					len(content) || n_gprssupportindicator < 0 || n_gprssupportindicator >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_gprssupportindicator
			}
		}
	}
	// Decode deliveryOutcomeIndicator
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3 {
				ber.MarkPreflightTarget(opts, "deliveryOutcomeIndicator", content[offset:])
				decodedTag_deliveryoutcomeindicator, n_deliveryoutcomeindicator, rawVal_deliveryoutcomeindicator, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "deliveryOutcomeIndicator", "decoding", false)
				}
				if decodedTag_deliveryoutcomeindicator.Class != tag.ClassContextSpecific || decodedTag_deliveryoutcomeindicator.Number != 3 || decodedTag_deliveryoutcomeindicator.Constructed != false {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_deliveryoutcomeindicator), "deliveryOutcomeIndicator", "decoding", false)
				}
				if len(rawVal_deliveryoutcomeindicator) != 0 {
					return qualifyBERError(fmt.Errorf("%w: NULL content length %d", ber.ErrInvalidValue, len(rawVal_deliveryoutcomeindicator)), "deliveryOutcomeIndicator", "decoding", false)
				}
				v.DeliveryOutcomeIndicator = &struct{}{}
				if offset < 0 || offset >
					len(content) || n_deliveryoutcomeindicator < 0 || n_deliveryoutcomeindicator >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_deliveryoutcomeindicator
			}
		}
	}
	// Decode additionalSM-DeliveryOutcome
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4 {
				ber.MarkPreflightTarget(opts, "additionalSM-DeliveryOutcome", content[offset:])
				decodedTag_additionalsmdeliveryoutcome, n_additionalsmdeliveryoutcome, rawVal_additionalsmdeliveryoutcome, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "additionalSM-DeliveryOutcome", "decoding", false)
				}
				if decodedTag_additionalsmdeliveryoutcome.Class != tag.ClassContextSpecific || decodedTag_additionalsmdeliveryoutcome.Number != 4 || decodedTag_additionalsmdeliveryoutcome.Constructed != false {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_additionalsmdeliveryoutcome), "additionalSM-DeliveryOutcome", "decoding", false)
				}
				decVal_additionalsmdeliveryoutcome, intErr := ber.DecodeEnumeratedValue(rawVal_additionalsmdeliveryoutcome)
				if intErr != nil {
					return qualifyBERError(intErr, "additionalSM-DeliveryOutcome", "decoding", false)
				}
				tmp_additionalsmdeliveryoutcome := SMDeliveryOutcome(decVal_additionalsmdeliveryoutcome)
				v.AdditionalSMDeliveryOutcome = &tmp_additionalsmdeliveryoutcome
				if offset < 0 || offset >
					len(content) || n_additionalsmdeliveryoutcome < 0 || n_additionalsmdeliveryoutcome >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_additionalsmdeliveryoutcome
				if int64(*v.AdditionalSMDeliveryOutcome) != 0 && int64(*v.AdditionalSMDeliveryOutcome) != 1 && int64(*v.AdditionalSMDeliveryOutcome) != 2 {
					if constraintErr := checkDecodedValue(opts, s949588_12, "20", "additionalSM-DeliveryOutcome", "ENUMERATED {0, 1, 2}", ber.ObserveInteger(int64(*v.AdditionalSMDeliveryOutcome))); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode additionalAbsentSubscriberDiagnosticSM
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 5 {
				ber.MarkPreflightTarget(opts, "additionalAbsentSubscriberDiagnosticSM", content[offset:])
				decodedTag_additionalabsentsubscriberdiagnosticsm, n_additionalabsentsubscriberdiagnosticsm, rawVal_additionalabsentsubscriberdiagnosticsm, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "additionalAbsentSubscriberDiagnosticSM", "decoding", false)
				}
				if decodedTag_additionalabsentsubscriberdiagnosticsm.Class != tag.ClassContextSpecific || decodedTag_additionalabsentsubscriberdiagnosticsm.Number != 5 || decodedTag_additionalabsentsubscriberdiagnosticsm.Constructed != false {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_additionalabsentsubscriberdiagnosticsm), "additionalAbsentSubscriberDiagnosticSM", "decoding", false)
				}
				decVal_additionalabsentsubscriberdiagnosticsm, intErr := ber.DecodeIntegerValue(rawVal_additionalabsentsubscriberdiagnosticsm)
				if intErr != nil {
					return qualifyBERError(intErr, "additionalAbsentSubscriberDiagnosticSM", "decoding", false)
				}
				tmp_additionalabsentsubscriberdiagnosticsm := AbsentSubscriberDiagnosticSM(decVal_additionalabsentsubscriberdiagnosticsm)
				v.AdditionalAbsentSubscriberDiagnosticSM = &tmp_additionalabsentsubscriberdiagnosticsm
				if offset < 0 || offset >
					len(content) || n_additionalabsentsubscriberdiagnosticsm < 0 || n_additionalabsentsubscriberdiagnosticsm >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_additionalabsentsubscriberdiagnosticsm
				if !(int64(*v.AdditionalAbsentSubscriberDiagnosticSM) >= 0 && int64(*v.AdditionalAbsentSubscriberDiagnosticSM) <= 255) {
					if constraintErr := checkDecodedValue(opts, s949588_12, "51.4", "additionalAbsentSubscriberDiagnosticSM", "(0..255)", ber.ObserveInteger(int64(*v.AdditionalAbsentSubscriberDiagnosticSM))); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode ip-sm-gw-Indicator
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 6 {
				ber.MarkPreflightTarget(opts, "ip-sm-gw-Indicator", content[offset:])
				decodedTag_ipsmgwindicator, n_ipsmgwindicator, rawVal_ipsmgwindicator, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "ip-sm-gw-Indicator", "decoding", false)
				}
				if decodedTag_ipsmgwindicator.Class != tag.ClassContextSpecific || decodedTag_ipsmgwindicator.Number != 6 || decodedTag_ipsmgwindicator.Constructed != false {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_ipsmgwindicator), "ip-sm-gw-Indicator", "decoding", false)
				}
				if len(rawVal_ipsmgwindicator) != 0 {
					return qualifyBERError(fmt.Errorf("%w: NULL content length %d", ber.ErrInvalidValue, len(rawVal_ipsmgwindicator)), "ip-sm-gw-Indicator", "decoding", false)
				}
				v.IpSmGwIndicator = &struct{}{}
				if offset < 0 || offset >
					len(content) || n_ipsmgwindicator < 0 || n_ipsmgwindicator > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_ipsmgwindicator
			}
		}
	}
	// Decode ip-sm-gw-sm-deliveryOutcome
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 7 {
				ber.MarkPreflightTarget(opts, "ip-sm-gw-sm-deliveryOutcome", content[offset:])
				decodedTag_ipsmgwsmdeliveryoutcome, n_ipsmgwsmdeliveryoutcome, rawVal_ipsmgwsmdeliveryoutcome, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "ip-sm-gw-sm-deliveryOutcome", "decoding", false)
				}
				if decodedTag_ipsmgwsmdeliveryoutcome.Class != tag.ClassContextSpecific || decodedTag_ipsmgwsmdeliveryoutcome.Number != 7 || decodedTag_ipsmgwsmdeliveryoutcome.Constructed != false {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_ipsmgwsmdeliveryoutcome), "ip-sm-gw-sm-deliveryOutcome", "decoding", false)
				}
				decVal_ipsmgwsmdeliveryoutcome, intErr := ber.DecodeEnumeratedValue(rawVal_ipsmgwsmdeliveryoutcome)
				if intErr != nil {
					return qualifyBERError(intErr, "ip-sm-gw-sm-deliveryOutcome", "decoding", false)
				}
				tmp_ipsmgwsmdeliveryoutcome := SMDeliveryOutcome(decVal_ipsmgwsmdeliveryoutcome)
				v.IpSmGwSmDeliveryOutcome = &tmp_ipsmgwsmdeliveryoutcome
				if offset < 0 || offset >
					len(content) || n_ipsmgwsmdeliveryoutcome < 0 || n_ipsmgwsmdeliveryoutcome >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_ipsmgwsmdeliveryoutcome
				if int64(*v.IpSmGwSmDeliveryOutcome) != 0 && int64(*v.IpSmGwSmDeliveryOutcome) != 1 && int64(*v.IpSmGwSmDeliveryOutcome) != 2 {
					if constraintErr := checkDecodedValue(opts, s949588_12, "20", "ip-sm-gw-sm-deliveryOutcome", "ENUMERATED {0, 1, 2}", ber.ObserveInteger(int64(*v.IpSmGwSmDeliveryOutcome))); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode ip-sm-gw-absentSubscriberDiagnosticSM
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 8 {
				ber.MarkPreflightTarget(opts, "ip-sm-gw-absentSubscriberDiagnosticSM", content[offset:])
				decodedTag_ipsmgwabsentsubscriberdiagnosticsm, n_ipsmgwabsentsubscriberdiagnosticsm, rawVal_ipsmgwabsentsubscriberdiagnosticsm, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "ip-sm-gw-absentSubscriberDiagnosticSM", "decoding", false)
				}
				if decodedTag_ipsmgwabsentsubscriberdiagnosticsm.Class != tag.ClassContextSpecific || decodedTag_ipsmgwabsentsubscriberdiagnosticsm.Number != 8 || decodedTag_ipsmgwabsentsubscriberdiagnosticsm.Constructed != false {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_ipsmgwabsentsubscriberdiagnosticsm), "ip-sm-gw-absentSubscriberDiagnosticSM", "decoding", false)
				}
				decVal_ipsmgwabsentsubscriberdiagnosticsm, intErr := ber.DecodeIntegerValue(rawVal_ipsmgwabsentsubscriberdiagnosticsm)
				if intErr != nil {
					return qualifyBERError(intErr, "ip-sm-gw-absentSubscriberDiagnosticSM", "decoding", false)
				}
				tmp_ipsmgwabsentsubscriberdiagnosticsm := AbsentSubscriberDiagnosticSM(decVal_ipsmgwabsentsubscriberdiagnosticsm)
				v.IpSmGwAbsentSubscriberDiagnosticSM = &tmp_ipsmgwabsentsubscriberdiagnosticsm
				if offset < 0 || offset >
					len(content) || n_ipsmgwabsentsubscriberdiagnosticsm < 0 || n_ipsmgwabsentsubscriberdiagnosticsm >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_ipsmgwabsentsubscriberdiagnosticsm
				if !(int64(*v.IpSmGwAbsentSubscriberDiagnosticSM) >= 0 && int64(*v.IpSmGwAbsentSubscriberDiagnosticSM) <= 255) {
					if constraintErr := checkDecodedValue(opts, s949588_12, "51.4", "ip-sm-gw-absentSubscriberDiagnosticSM", "(0..255)", ber.ObserveInteger(int64(*v.IpSmGwAbsentSubscriberDiagnosticSM))); constraintErr != nil {
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
				if offset < 0 || offset >
					len(content) || n_imsi < 0 || n_imsi > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_imsi
				if len(*v.Imsi) < 3 || len(*v.Imsi) > 8 {
					if constraintErr := checkDecodedLength(opts, s949588_12, "51.5", "imsi", "SIZE (3..8)", len(*v.Imsi)); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode singleAttemptDelivery
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 10 {
				ber.MarkPreflightTarget(opts, "singleAttemptDelivery", content[offset:])
				decodedTag_singleattemptdelivery, n_singleattemptdelivery, rawVal_singleattemptdelivery, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "singleAttemptDelivery", "decoding", false)
				}
				if decodedTag_singleattemptdelivery.Class != tag.ClassContextSpecific || decodedTag_singleattemptdelivery.Number != 10 || decodedTag_singleattemptdelivery.Constructed != false {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_singleattemptdelivery), "singleAttemptDelivery", "decoding", false)
				}
				if len(rawVal_singleattemptdelivery) != 0 {
					return qualifyBERError(fmt.Errorf("%w: NULL content length %d", ber.ErrInvalidValue, len(rawVal_singleattemptdelivery)), "singleAttemptDelivery", "decoding", false)
				}
				v.SingleAttemptDelivery = &struct{}{}
				if offset < 0 || offset >
					len(content) || n_singleattemptdelivery < 0 || n_singleattemptdelivery >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_singleattemptdelivery
			}
		}
	}
	// Decode correlationID
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 11 {
				ber.MarkPreflightTarget(opts, "correlationID", content[offset:])
				decodedTag_correlationid, n_correlationid, rawVal_correlationid, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "correlationID", "decoding", false)
				}
				if decodedTag_correlationid.Class != tag.ClassContextSpecific || decodedTag_correlationid.Number != 11 || decodedTag_correlationid.Constructed != true {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_correlationid), "correlationID", "decoding", false)
				}
				_ = rawVal_correlationid
				if offset < 0 || offset >
					len(content) || n_correlationid < 0 || n_correlationid > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				reconstructed_correlationid, reconstructionErr_correlationid := ber.EncodeImplicitTagWithClass(tag.ClassUniversal, tag.TagSequence, content[offset:offset+n_correlationid])
				if reconstructionErr_correlationid != nil {
					return qualifyBERError(reconstructionErr_correlationid, "correlationID", "decoding", false)
				}
				var dec_correlationid CorrelationID
				if unmErr := dec_correlationid.UnmarshalBER(reconstructed_correlationid, ber.ChildDecodeOptions(opts, "correlationID")...); unmErr != nil {
					return qualifyBERError(unmErr, "correlationID", "decoding", false)
				}
				v.CorrelationID = &dec_correlationid
				if offset < 0 || offset >
					len(content) || n_correlationid < 0 || n_correlationid > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_correlationid
			}
		}
	}
	// Decode smsf-3gpp-deliveryOutcomeIndicator
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 12 {
				ber.MarkPreflightTarget(opts, "smsf-3gpp-deliveryOutcomeIndicator", content[offset:])
				decodedTag_smsf3gppdeliveryoutcomeindicator, n_smsf3gppdeliveryoutcomeindicator, rawVal_smsf3gppdeliveryoutcomeindicator, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "smsf-3gpp-deliveryOutcomeIndicator", "decoding", false)
				}
				if decodedTag_smsf3gppdeliveryoutcomeindicator.Class != tag.ClassContextSpecific || decodedTag_smsf3gppdeliveryoutcomeindicator.Number != 12 || decodedTag_smsf3gppdeliveryoutcomeindicator.Constructed != false {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_smsf3gppdeliveryoutcomeindicator), "smsf-3gpp-deliveryOutcomeIndicator", "decoding", false)
				}
				if len(rawVal_smsf3gppdeliveryoutcomeindicator) != 0 {
					return qualifyBERError(fmt.Errorf("%w: NULL content length %d", ber.ErrInvalidValue, len(rawVal_smsf3gppdeliveryoutcomeindicator)), "smsf-3gpp-deliveryOutcomeIndicator", "decoding", false)
				}
				v.Smsf3gppDeliveryOutcomeIndicator = &struct{}{}
				if offset < 0 || offset >
					len(content) || n_smsf3gppdeliveryoutcomeindicator < 0 || n_smsf3gppdeliveryoutcomeindicator >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_smsf3gppdeliveryoutcomeindicator
			}
		}
	}
	// Decode smsf-3gpp-deliveryOutcome
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 13 {
				ber.MarkPreflightTarget(opts, "smsf-3gpp-deliveryOutcome", content[offset:])
				decodedTag_smsf3gppdeliveryoutcome, n_smsf3gppdeliveryoutcome, rawVal_smsf3gppdeliveryoutcome, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "smsf-3gpp-deliveryOutcome", "decoding", false)
				}
				if decodedTag_smsf3gppdeliveryoutcome.Class != tag.ClassContextSpecific || decodedTag_smsf3gppdeliveryoutcome.Number != 13 || decodedTag_smsf3gppdeliveryoutcome.Constructed != false {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_smsf3gppdeliveryoutcome), "smsf-3gpp-deliveryOutcome", "decoding", false)
				}
				decVal_smsf3gppdeliveryoutcome, intErr := ber.DecodeEnumeratedValue(rawVal_smsf3gppdeliveryoutcome)
				if intErr != nil {
					return qualifyBERError(intErr, "smsf-3gpp-deliveryOutcome", "decoding", false)
				}
				tmp_smsf3gppdeliveryoutcome := SMDeliveryOutcome(decVal_smsf3gppdeliveryoutcome)
				v.Smsf3gppDeliveryOutcome = &tmp_smsf3gppdeliveryoutcome
				if offset < 0 || offset >
					len(content) || n_smsf3gppdeliveryoutcome < 0 || n_smsf3gppdeliveryoutcome >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_smsf3gppdeliveryoutcome
				if int64(*v.Smsf3gppDeliveryOutcome) != 0 && int64(*v.Smsf3gppDeliveryOutcome) != 1 && int64(*v.Smsf3gppDeliveryOutcome) != 2 {
					if constraintErr := checkDecodedValue(opts, s949588_12, "20", "smsf-3gpp-deliveryOutcome", "ENUMERATED {0, 1, 2}", ber.ObserveInteger(int64(*v.Smsf3gppDeliveryOutcome))); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode smsf-3gpp-absentSubscriberDiagSM
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 14 {
				ber.MarkPreflightTarget(opts, "smsf-3gpp-absentSubscriberDiagSM", content[offset:])
				decodedTag_smsf3gppabsentsubscriberdiagsm, n_smsf3gppabsentsubscriberdiagsm, rawVal_smsf3gppabsentsubscriberdiagsm, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "smsf-3gpp-absentSubscriberDiagSM", "decoding", false)
				}
				if decodedTag_smsf3gppabsentsubscriberdiagsm.Class != tag.ClassContextSpecific || decodedTag_smsf3gppabsentsubscriberdiagsm.Number != 14 || decodedTag_smsf3gppabsentsubscriberdiagsm.Constructed != false {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_smsf3gppabsentsubscriberdiagsm), "smsf-3gpp-absentSubscriberDiagSM", "decoding", false)
				}
				decVal_smsf3gppabsentsubscriberdiagsm, intErr := ber.DecodeIntegerValue(rawVal_smsf3gppabsentsubscriberdiagsm)
				if intErr != nil {
					return qualifyBERError(intErr, "smsf-3gpp-absentSubscriberDiagSM", "decoding", false)
				}
				tmp_smsf3gppabsentsubscriberdiagsm := AbsentSubscriberDiagnosticSM(decVal_smsf3gppabsentsubscriberdiagsm)
				v.Smsf3gppAbsentSubscriberDiagSM = &tmp_smsf3gppabsentsubscriberdiagsm
				if offset < 0 || offset >
					len(content) || n_smsf3gppabsentsubscriberdiagsm < 0 || n_smsf3gppabsentsubscriberdiagsm >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_smsf3gppabsentsubscriberdiagsm
				if !(int64(*v.Smsf3gppAbsentSubscriberDiagSM) >= 0 && int64(*v.Smsf3gppAbsentSubscriberDiagSM) <= 255) {
					if constraintErr := checkDecodedValue(opts, s949588_12, "51.4", "smsf-3gpp-absentSubscriberDiagSM", "(0..255)", ber.ObserveInteger(int64(*v.Smsf3gppAbsentSubscriberDiagSM))); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode smsf-non-3gpp-deliveryOutcomeIndicator
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 15 {
				ber.MarkPreflightTarget(opts, "smsf-non-3gpp-deliveryOutcomeIndicator", content[offset:])
				decodedTag_smsfnon3gppdeliveryoutcomeindicator, n_smsfnon3gppdeliveryoutcomeindicator, rawVal_smsfnon3gppdeliveryoutcomeindicator, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "smsf-non-3gpp-deliveryOutcomeIndicator", "decoding", false)
				}
				if decodedTag_smsfnon3gppdeliveryoutcomeindicator.Class != tag.ClassContextSpecific || decodedTag_smsfnon3gppdeliveryoutcomeindicator.Number != 15 || decodedTag_smsfnon3gppdeliveryoutcomeindicator.Constructed != false {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_smsfnon3gppdeliveryoutcomeindicator), "smsf-non-3gpp-deliveryOutcomeIndicator", "decoding", false)
				}
				if len(rawVal_smsfnon3gppdeliveryoutcomeindicator) != 0 {
					return qualifyBERError(fmt.Errorf("%w: NULL content length %d", ber.ErrInvalidValue, len(rawVal_smsfnon3gppdeliveryoutcomeindicator)), "smsf-non-3gpp-deliveryOutcomeIndicator", "decoding", false)
				}
				v.SmsfNon3gppDeliveryOutcomeIndicator = &struct{}{}
				if offset < 0 || offset >
					len(content) || n_smsfnon3gppdeliveryoutcomeindicator < 0 || n_smsfnon3gppdeliveryoutcomeindicator >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_smsfnon3gppdeliveryoutcomeindicator
			}
		}
	}
	// Decode smsf-non-3gpp-deliveryOutcome
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 16 {
				ber.MarkPreflightTarget(opts, "smsf-non-3gpp-deliveryOutcome", content[offset:])
				decodedTag_smsfnon3gppdeliveryoutcome, n_smsfnon3gppdeliveryoutcome, rawVal_smsfnon3gppdeliveryoutcome, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "smsf-non-3gpp-deliveryOutcome", "decoding", false)
				}
				if decodedTag_smsfnon3gppdeliveryoutcome.Class != tag.ClassContextSpecific || decodedTag_smsfnon3gppdeliveryoutcome.Number != 16 || decodedTag_smsfnon3gppdeliveryoutcome.Constructed != false {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_smsfnon3gppdeliveryoutcome), "smsf-non-3gpp-deliveryOutcome", "decoding", false)
				}
				decVal_smsfnon3gppdeliveryoutcome, intErr := ber.DecodeEnumeratedValue(rawVal_smsfnon3gppdeliveryoutcome)
				if intErr != nil {
					return qualifyBERError(intErr, "smsf-non-3gpp-deliveryOutcome", "decoding", false)
				}
				tmp_smsfnon3gppdeliveryoutcome := SMDeliveryOutcome(decVal_smsfnon3gppdeliveryoutcome)
				v.SmsfNon3gppDeliveryOutcome = &tmp_smsfnon3gppdeliveryoutcome
				if offset < 0 || offset >
					len(content) || n_smsfnon3gppdeliveryoutcome < 0 || n_smsfnon3gppdeliveryoutcome >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_smsfnon3gppdeliveryoutcome
				if int64(*v.SmsfNon3gppDeliveryOutcome) != 0 && int64(*v.SmsfNon3gppDeliveryOutcome) != 1 && int64(*v.SmsfNon3gppDeliveryOutcome) != 2 {
					if constraintErr := checkDecodedValue(opts, s949588_12, "20", "smsf-non-3gpp-deliveryOutcome", "ENUMERATED {0, 1, 2}", ber.ObserveInteger(int64(*v.SmsfNon3gppDeliveryOutcome))); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode smsf-non-3gpp-absentSubscriberDiagSM
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 17 {
				ber.MarkPreflightTarget(opts, "smsf-non-3gpp-absentSubscriberDiagSM", content[offset:])
				decodedTag_smsfnon3gppabsentsubscriberdiagsm, n_smsfnon3gppabsentsubscriberdiagsm, rawVal_smsfnon3gppabsentsubscriberdiagsm, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "smsf-non-3gpp-absentSubscriberDiagSM", "decoding", false)
				}
				if decodedTag_smsfnon3gppabsentsubscriberdiagsm.Class != tag.ClassContextSpecific || decodedTag_smsfnon3gppabsentsubscriberdiagsm.Number != 17 || decodedTag_smsfnon3gppabsentsubscriberdiagsm.Constructed != false {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_smsfnon3gppabsentsubscriberdiagsm), "smsf-non-3gpp-absentSubscriberDiagSM", "decoding", false)
				}
				decVal_smsfnon3gppabsentsubscriberdiagsm, intErr := ber.DecodeIntegerValue(rawVal_smsfnon3gppabsentsubscriberdiagsm)
				if intErr != nil {
					return qualifyBERError(intErr, "smsf-non-3gpp-absentSubscriberDiagSM", "decoding", false)
				}
				tmp_smsfnon3gppabsentsubscriberdiagsm := AbsentSubscriberDiagnosticSM(decVal_smsfnon3gppabsentsubscriberdiagsm)
				v.SmsfNon3gppAbsentSubscriberDiagSM = &tmp_smsfnon3gppabsentsubscriberdiagsm
				if offset < 0 || offset >
					len(content) || n_smsfnon3gppabsentsubscriberdiagsm < 0 || n_smsfnon3gppabsentsubscriberdiagsm >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_smsfnon3gppabsentsubscriberdiagsm
				if !(int64(*v.SmsfNon3gppAbsentSubscriberDiagSM) >= 0 && int64(*v.SmsfNon3gppAbsentSubscriberDiagSM) <= 255) {
					if constraintErr := checkDecodedValue(opts, s949588_12, "51.4", "smsf-non-3gpp-absentSubscriberDiagSM", "(0..255)", ber.ObserveInteger(int64(*v.SmsfNon3gppAbsentSubscriberDiagSM))); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode failedSMServingNodes
	v.berFailedSMServingNodesIndef_ = false
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 18 {
				ber.MarkPreflightTarget(opts, "failedSMServingNodes", content[offset:])
				decodedTag_failedsmservingnodes, n_failedsmservingnodes, rawVal_failedsmservingnodes, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "failedSMServingNodes", "decoding", false)
				}
				if decodedTag_failedsmservingnodes.Class != tag.ClassContextSpecific || decodedTag_failedsmservingnodes.Number != 18 || decodedTag_failedsmservingnodes.Constructed != true {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_failedsmservingnodes), "failedSMServingNodes", "decoding", false)
				}
				_ = rawVal_failedsmservingnodes
				if offset < 0 || offset >
					len(content) || n_failedsmservingnodes < 0 || n_failedsmservingnodes >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				reconstructed_failedsmservingnodes, reconstructionErr_failedsmservingnodes := ber.EncodeImplicitTagWithClass(tag.ClassUniversal, tag.TagSequence, content[offset:offset+n_failedsmservingnodes])
				if reconstructionErr_failedsmservingnodes != nil {
					return qualifyBERError(reconstructionErr_failedsmservingnodes, "failedSMServingNodes", "decoding", false)
				}
				dec_failedsmservingnodes, unmErr := UnmarshalBERSMServingNodeAddressList(reconstructed_failedsmservingnodes, ber.ParentCollectionSizeDecodeOptions(ber.ChildDecodeOptions(opts, "failedSMServingNodes"))...)
				if unmErr != nil {
					return qualifyBERError(unmErr, "failedSMServingNodes", "decoding", false)
				}
				v.FailedSMServingNodes = dec_failedsmservingnodes
				{
					_, tagSz_, _ := ber.DecodeTag(content[offset:])
					if offset < 0 || offset >
						len(content) || tagSz_ < 0 || tagSz_ > len(content[offset:]) {
						return fmt.Errorf("invalid BER content window")
					}

					if offset+tagSz_ < len(content) && content[offset+tagSz_] == 0x80 {
						v.berFailedSMServingNodesIndef_ = true
					}
				}
				if offset < 0 || offset >
					len(content) || n_failedsmservingnodes < 0 || n_failedsmservingnodes >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_failedsmservingnodes
				if len((v.FailedSMServingNodes).Values) < 1 || len((v.FailedSMServingNodes).Values) > 5 {
					if constraintErr := checkDecodedLength(opts, s949588_12, "51.5", "failedSMServingNodes", "SIZE (1..5)", len((v.FailedSMServingNodes).Values)); constraintErr != nil {
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
			return &ber.DecodeError{Offset: offset, TypeName: "ReportSMDeliveryStatusArg", Cause: extErr_}
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: the first unknown addition must differ from trailing OPTIONAL/DEFAULT tags.
		if len(v.ExtData_) == 0 && ((peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 18) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 17) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 16) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 15) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 14) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 13) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 12) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 11) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 10) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 9) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 8) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 7) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 6) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 5) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0)) {
			if !ber.ToleranceEnabled(opts) {
				return &ber.DecodeError{Offset: offset, TypeName: "ReportSMDeliveryStatusArg", Cause: fmt.Errorf("%w: repeated or out-of-order SEQUENCE component tag %s", ber.ErrInvalidTag, peekTag)}
			}
			if orderErr_ := ber.CheckDecodedValue(ber.DecodeRule(opts, s949588_12, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), fmt.Sprintf("ExtData_[%d]", len(v.ExtData_)), "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); orderErr_ != nil {
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

// MarshalBER encodes ReportSMDeliveryStatusRes to BER format.
func (v *ReportSMDeliveryStatusRes) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {

	if v == nil {
		return nil, fmt.Errorf("%w: ReportSMDeliveryStatusRes receiver is nil", ber.ErrInvalidValue)
	}
	return marshalFramedValue(v, v.berReplayNode_, opts, (*ReportSMDeliveryStatusRes).MarshalBER, (*ReportSMDeliveryStatusRes).marshalBER, 3)

}
func (v *ReportSMDeliveryStatusRes) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if v.StoredMSISDN != nil {
		if len(*v.StoredMSISDN) < 1 || len(*v.StoredMSISDN) > 9 {
			if constraintErr := checkEncodedLength(opts, s949588_13, "51.5", "storedMSISDN", "SIZE (1..9)", len(*v.StoredMSISDN)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		if len(*v.StoredMSISDN) < 1 || len(*v.StoredMSISDN) > 20 {
			if constraintErr := checkEncodedLength(opts, s949588_13, "51.5", "storedMSISDN", "SIZE (1..20)", len(*v.StoredMSISDN)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_storedmsisdn, encodeErr_enc_storedmsisdn := ber.EncodeOctetString([]byte(*v.StoredMSISDN))
		if encodeErr_enc_storedmsisdn != nil {
			return nil, qualifyBERError(encodeErr_enc_storedmsisdn, "storedMSISDN", "encoding", false)
		}
		children = append(children, enc_storedmsisdn...)
	}
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalBER(ber.ChildEncodeOptions(opts, "extensionContainer")...)
		if err != nil {
			return nil, qualifyBERError(err, "extensionContainer", "encoding", false)
		}
		ber.RecordGeneratedBERChildPlacement(opts, len(children), enc_extensioncontainer)
		children = append(children, enc_extensioncontainer...)
	}
	if v.RegisteredSMServingNodes != nil {
		if len((v.RegisteredSMServingNodes).Values) < 1 || len((v.RegisteredSMServingNodes).Values) > 5 {
			if constraintErr := checkEncodedLength(opts, s949588_13, "51.5", "registeredSMServingNodes", "SIZE (1..5)", len((v.RegisteredSMServingNodes).Values)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_registeredsmservingnodes, err := MarshalBERSMServingNodeAddressList(v.RegisteredSMServingNodes, ber.ParentCollectionSizeEncodeOptions(ber.ChildEncodeOptions(opts, "registeredSMServingNodes"))...)
		if err != nil {
			return nil, qualifyBERError(err, "registeredSMServingNodes", "encoding", false)
		}
		if ber.BERReplayEnabled(opts) && v.berRegisteredSMServingNodesIndef_ {
			// Strip the outer SEQUENCE tag from marshalBER output to get raw children.
			_, _, seqContent_, tlvErr_ := ber.DecodeEncodedTLV(enc_registeredsmservingnodes)
			if tlvErr_ != nil {
				return nil, tlvErr_
			}
			{
				var encodeErr error
				enc_registeredsmservingnodes, encodeErr = ber.EncodeConstructedIndefinite(tag.Tag{Class: tag.ClassContextSpecific, Number: 0}, seqContent_)
				if encodeErr != nil {
					return nil, qualifyBERError(encodeErr, "registeredSMServingNodes", "encoding", false)
				}
			}
		} else {
			retagged_enc_registeredsmservingnodes, tagErr_enc_registeredsmservingnodes := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_registeredsmservingnodes)
			if tagErr_enc_registeredsmservingnodes != nil {
				return nil, qualifyBERError(tagErr_enc_registeredsmservingnodes, "registeredSMServingNodes", "encoding", false)
			}
			enc_registeredsmservingnodes = retagged_enc_registeredsmservingnodes
		}
		ber.RecordGeneratedBERChildPlacement(opts, len(children), enc_registeredsmservingnodes)
		children = append(children, enc_registeredsmservingnodes...)
	}
	base_ := -1
	for i, ext := range v.ExtData_ {
		if err := checkOpaqueAddition(ext, opts, s949588_13, children, i, &base_); err != nil {
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
		if i == 0 && ((peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0) || (peekTag.Class == tag.ClassUniversal && peekTag.Number == 16) || (peekTag.Class == tag.ClassUniversal && peekTag.Number == 4)) {
			if constraintErr := ber.CheckEncodedValue(ber.EncodeRule(opts, s949588_13, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
				return nil, constraintErr
			}
		}
		children = append(children, ext...)
	}
	ber.RecordGeneratedBERContainer(opts, children)
	return ber.EncodeSequence(children)
}
func (v *ReportSMDeliveryStatusRes) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// MarshalDER encodes ReportSMDeliveryStatusRes to DER format.
// Opaque descendants pass generic DER checks; foreign schema rules need a typed binding.
func (v *ReportSMDeliveryStatusRes) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: ReportSMDeliveryStatusRes receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if v.StoredMSISDN != nil {
		if len(*v.StoredMSISDN) < 1 || len(*v.StoredMSISDN) > 9 {
			if constraintErr := checkEncodedLength(nil, s949588_13, "51.5", "storedMSISDN", "SIZE (1..9)", len(*v.StoredMSISDN)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		if len(*v.StoredMSISDN) < 1 || len(*v.StoredMSISDN) > 20 {
			if constraintErr := checkEncodedLength(nil, s949588_13, "51.5", "storedMSISDN", "SIZE (1..20)", len(*v.StoredMSISDN)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_storedmsisdn, encodeErr_enc_storedmsisdn := ber.EncodeOctetString([]byte(*v.StoredMSISDN))
		if encodeErr_enc_storedmsisdn != nil {
			return nil, qualifyBERError(encodeErr_enc_storedmsisdn, "storedMSISDN", "encoding", true)
		}
		children = append(children, enc_storedmsisdn...)
	}
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalDER()
		if err != nil {
			return nil, qualifyBERError(err, "extensionContainer", "encoding", true)
		}
		children = append(children, enc_extensioncontainer...)
	}
	if v.RegisteredSMServingNodes != nil {
		if len((v.RegisteredSMServingNodes).Values) < 1 || len((v.RegisteredSMServingNodes).Values) > 5 {
			if constraintErr := checkEncodedLength(nil, s949588_13, "51.5", "registeredSMServingNodes", "SIZE (1..5)", len((v.RegisteredSMServingNodes).Values)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_registeredsmservingnodes, err := MarshalDERSMServingNodeAddressList(v.RegisteredSMServingNodes)
		if err != nil {
			return nil, qualifyBERError(err, "registeredSMServingNodes", "encoding", true)
		}
		retagged_enc_registeredsmservingnodes, tagErr_enc_registeredsmservingnodes := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_registeredsmservingnodes)
		if tagErr_enc_registeredsmservingnodes != nil {
			return nil, qualifyBERError(tagErr_enc_registeredsmservingnodes, "registeredSMServingNodes", "encoding", true)
		}
		enc_registeredsmservingnodes = retagged_enc_registeredsmservingnodes
		children = append(children, enc_registeredsmservingnodes...)
	}
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDEREncodedElement(ext); err != nil {
			return nil, invalidDERAddition(ext, s949588_13, children, i)
		}
		peekTag, _, _, extErr := ber.DecodeEncodedTLV(ext)
		if extErr != nil {
			return nil, extErr
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: only the first addition is restricted.
		if i == 0 && ((peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0) || (peekTag.Class == tag.ClassUniversal && peekTag.Number == 16) || (peekTag.Class == tag.ClassUniversal && peekTag.Number == 4)) {
			if constraintErr := ber.CheckEncodedValue(ber.EncodeRule(nil, s949588_13, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
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
		return nil, fmt.Errorf("%s: %w", "encoding ReportSMDeliveryStatusRes as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}
func (v *ReportSMDeliveryStatusRes) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	encoded, err := v.MarshalDER()
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBER decodes ReportSMDeliveryStatusRes from BER/DER format.
func (destination *ReportSMDeliveryStatusRes) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if destination == nil {
		return fmt.Errorf("%w: ReportSMDeliveryStatusRes destination is nil", ber.ErrInvalidValue)
	}
	v := new(ReportSMDeliveryStatusRes)

	defer publishDecodedValue(destination, v, &returnErr)

	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	preparedData, preparedOptions, prepareErr := prepareCompositeBER(data, opts, s949588_13, "child", (*ReportSMDeliveryStatusRes).UnmarshalBER)
	if prepareErr != nil {
		return prepareErr
	}
	data, opts = preparedData, preparedOptions

	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
	*v = ReportSMDeliveryStatusRes{}
	defer func() {
		if returnErr == nil {
			returnErr = completeValueBER(data,
				opts, v, &v.berReplayNode_, (*ReportSMDeliveryStatusRes).MarshalBER)
		}

	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("%s: %w", "decoding ReportSMDeliveryStatusRes SEQUENCE", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "ReportSMDeliveryStatusRes", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode storedMSISDN
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassUniversal && peekTag.Number == 4 {
				ber.MarkPreflightTarget(opts, "storedMSISDN", content[offset:])
				val_storedmsisdn, n, err := ber.DecodeOctetString(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "storedMSISDN", "decoding", false)
				}
				tmp_storedmsisdn := ISDNAddressString(val_storedmsisdn)
				v.StoredMSISDN = &tmp_storedmsisdn
				if offset > len(content) || n < 0 || n > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n
				if len(*v.StoredMSISDN) < 1 || len(*v.StoredMSISDN) > 9 {
					if constraintErr := checkDecodedLength(opts, s949588_13, "51.5", "storedMSISDN", "SIZE (1..9)", len(*v.StoredMSISDN)); constraintErr != nil {
						return constraintErr
					}
				}
				if len(*v.StoredMSISDN) < 1 || len(*v.StoredMSISDN) > 20 {
					if constraintErr := checkDecodedLength(opts, s949588_13, "51.5", "storedMSISDN", "SIZE (1..20)", len(*v.StoredMSISDN)); constraintErr != nil {
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
	// Decode registeredSMServingNodes
	v.berRegisteredSMServingNodesIndef_ = false
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
				ber.MarkPreflightTarget(opts, "registeredSMServingNodes", content[offset:])
				decodedTag_registeredsmservingnodes, n_registeredsmservingnodes, rawVal_registeredsmservingnodes, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "registeredSMServingNodes", "decoding", false)
				}
				if decodedTag_registeredsmservingnodes.Class != tag.ClassContextSpecific || decodedTag_registeredsmservingnodes.Number != 0 || decodedTag_registeredsmservingnodes.Constructed != true {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_registeredsmservingnodes), "registeredSMServingNodes", "decoding", false)
				}
				_ = rawVal_registeredsmservingnodes
				if offset < 0 || offset >
					len(content) || n_registeredsmservingnodes < 0 || n_registeredsmservingnodes >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				reconstructed_registeredsmservingnodes, reconstructionErr_registeredsmservingnodes := ber.EncodeImplicitTagWithClass(tag.ClassUniversal, tag.TagSequence, content[offset:offset+n_registeredsmservingnodes])
				if reconstructionErr_registeredsmservingnodes != nil {
					return qualifyBERError(reconstructionErr_registeredsmservingnodes, "registeredSMServingNodes", "decoding", false)
				}
				dec_registeredsmservingnodes, unmErr := UnmarshalBERSMServingNodeAddressList(reconstructed_registeredsmservingnodes, ber.ParentCollectionSizeDecodeOptions(ber.ChildDecodeOptions(opts, "registeredSMServingNodes"))...)
				if unmErr != nil {
					return qualifyBERError(unmErr, "registeredSMServingNodes", "decoding", false)
				}
				v.RegisteredSMServingNodes = dec_registeredsmservingnodes
				{
					_, tagSz_, _ := ber.DecodeTag(content[offset:])
					if offset < 0 || offset >
						len(content) || tagSz_ < 0 || tagSz_ > len(content[offset:]) {
						return fmt.Errorf("invalid BER content window")
					}

					if offset+tagSz_ < len(content) && content[offset+tagSz_] == 0x80 {
						v.berRegisteredSMServingNodesIndef_ = true
					}
				}
				if offset < 0 || offset >
					len(content) || n_registeredsmservingnodes < 0 || n_registeredsmservingnodes >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_registeredsmservingnodes
				if len((v.RegisteredSMServingNodes).Values) < 1 || len((v.RegisteredSMServingNodes).Values) > 5 {
					if constraintErr := checkDecodedLength(opts, s949588_13, "51.5", "registeredSMServingNodes", "SIZE (1..5)", len((v.RegisteredSMServingNodes).Values)); constraintErr != nil {
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
			return &ber.DecodeError{Offset: offset, TypeName: "ReportSMDeliveryStatusRes", Cause: extErr_}
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: the first unknown addition must differ from trailing OPTIONAL/DEFAULT tags.
		if len(v.ExtData_) == 0 && ((peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0) || (peekTag.Class == tag.ClassUniversal && peekTag.Number == 16) || (peekTag.Class == tag.ClassUniversal && peekTag.Number == 4)) {
			if !ber.ToleranceEnabled(opts) {
				return &ber.DecodeError{Offset: offset, TypeName: "ReportSMDeliveryStatusRes", Cause: fmt.Errorf("%w: repeated or out-of-order SEQUENCE component tag %s", ber.ErrInvalidTag, peekTag)}
			}
			if orderErr_ := ber.CheckDecodedValue(ber.DecodeRule(opts, s949588_13, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), fmt.Sprintf("ExtData_[%d]", len(v.ExtData_)), "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); orderErr_ != nil {
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

// MarshalBERSMServingNodeAddressList encodes a SMServingNodeAddressList list to BER.
func MarshalBERSMServingNodeAddressList(collection *SMServingNodeAddressList, opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {

	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	if collection == nil {
		return nil, fmt.Errorf("%w: required collection is nil", ber.ErrInvalidValue)
	}
	return marshalFramedValue(collection, collection.berReplayNode_, opts, MarshalBERSMServingNodeAddressList, marshalBERSMServingNodeAddressList, 3, UnmarshalBERSMServingNodeAddressList)

}
func marshalBERSMServingNodeAddressList(collection *SMServingNodeAddressList, opts ...ber.EncodeOption) ([]byte, error) {
	list := collection.Values
	if len(list) < 1 || len(list) > 5 {
		if constraintErr := checkEncodedCollectionLength(opts, "MAP-SM-DataTypes.marshalBERSMServingNodeAddressList", "51.5", "SMServingNodeAddressList", "SIZE (1..5)", len(list)); constraintErr != nil {
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

func appendBERLinearSMServingNodeAddressList(encoder *ber.LinearEncoder, collection *SMServingNodeAddressList, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := MarshalBERSMServingNodeAddressList(collection, opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// MarshalDERSMServingNodeAddressList encodes a SMServingNodeAddressList list to DER.
func MarshalDERSMServingNodeAddressList(collection *SMServingNodeAddressList) ([]byte, error) {
	if collection == nil {
		return nil, fmt.Errorf("%w: required collection is nil", ber.ErrInvalidValue)
	}
	list := collection.Values
	if len(list) < 1 || len(list) > 5 {
		if constraintErr := checkEncodedCollectionLength(nil, "MAP-SM-DataTypes.SMServingNodeAddressList", "51.5", "SMServingNodeAddressList", "SIZE (1..5)", len(list)); constraintErr != nil {
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
		return nil, fmt.Errorf("%s: %w", "encoding SMServingNodeAddressList as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}

func appendDERLinearSMServingNodeAddressList(encoder *ber.LinearEncoder, collection *SMServingNodeAddressList) ([]byte, error) {
	encoded, err := MarshalDERSMServingNodeAddressList(collection)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBERSMServingNodeAddressList decodes a SMServingNodeAddressList list from BER.
func UnmarshalBERSMServingNodeAddressList(data []byte, opts ...ber.DecodeOption) (returnValue *SMServingNodeAddressList, returnErr error) {
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	preparedData, preparedOptions, prepareErr := prepareValueBER(data, opts, "MAP-SM-DataTypes.SMServingNodeAddressList", "element", func(data []byte,

		probeOpts []ber.DecodeOption) error {
		_, probeErr := UnmarshalBERSMServingNodeAddressList(data, probeOpts...)
		return probeErr
	})
	if prepareErr != nil {
		return nil, prepareErr
	}
	data, opts = preparedData, preparedOptions

	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", "decoding SMServingNodeAddressList", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return nil, &ber.DecodeError{Offset: total, TypeName: "SMServingNodeAddressList", Cause: ber.ErrExtraData}
	}
	var result []SMServingNodeAddress
	offset := 0
	for offset < len(content) {
		elementIndex := len(result)
		_ = elementIndex
		elementData := content[offset:]
		ber.MarkPreflightElement(opts, elementIndex, elementData)
		var elem SMServingNodeAddress
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
	if len(result) < 1 || len(result) > 5 {
		if constraintErr := checkDecodedCollectionLength(opts, "MAP-SM-DataTypes.SMServingNodeAddressList", "51.5", "SMServingNodeAddressList", "SIZE (1..5)", len(result)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	decoded := &SMServingNodeAddressList{Values: result}
	if replayErr := completeValueBER(data,
		opts, decoded, &decoded.berReplayNode_, MarshalBERSMServingNodeAddressList); replayErr != nil {
		return nil, replayErr
	}

	return decoded, nil
}

// MarshalBER encodes SMServingNodeAddress to BER format.
func (v *SMServingNodeAddress) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {

	if v == nil {
		return nil, fmt.Errorf("%w: SMServingNodeAddress receiver is nil", ber.ErrInvalidValue)
	}
	return marshalFramedValue(v, v.berReplayNode_, opts, (*SMServingNodeAddress).MarshalBER, (*SMServingNodeAddress).marshalBER, 3)

}
func (v *SMServingNodeAddress) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}
func (v *SMServingNodeAddress) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	switch v.Choice {
	case SMServingNodeAddressChoiceNetworkNodeNumber:
		if v.NetworkNodeNumber == nil {
			return nil, fmt.Errorf("%w: choice SMServingNodeAddress: networkNode-Number is nil", ber.ErrInvalidValue)
		}
		enc_0, encodeErr_enc_0 := ber.EncodeOctetString([]byte(*v.NetworkNodeNumber))
		if encodeErr_enc_0 != nil {
			return nil, qualifyBERError(encodeErr_enc_0, "networkNode-Number", "encoding", false)
		}
		if len(*v.NetworkNodeNumber) < 1 || len(*v.NetworkNodeNumber) > 9 {
			if constraintErr := checkEncodedLength(opts, s949588_14, "51.5", "networkNode-Number", "SIZE (1..9)", len(*v.NetworkNodeNumber)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		if len(*v.NetworkNodeNumber) < 1 || len(*v.NetworkNodeNumber) > 20 {
			if constraintErr := checkEncodedLength(opts, s949588_14, "51.5", "networkNode-Number", "SIZE (1..20)", len(*v.NetworkNodeNumber)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		retagged_enc_0, tagErr_enc_0 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_0)
		if tagErr_enc_0 != nil {
			return nil, qualifyBERError(tagErr_enc_0, "networkNode-Number", "encoding", false)
		}
		enc_0 = retagged_enc_0
		return enc_0, nil
	case SMServingNodeAddressChoiceDiameterAddress:
		if v.DiameterAddress == nil {
			return nil, fmt.Errorf("%w: choice SMServingNodeAddress: diameterAddress is nil", ber.ErrInvalidValue)
		}
		enc_1, err := v.DiameterAddress.MarshalBER(ber.ChildEncodeOptions(opts, "diameterAddress")...)
		if err != nil {
			return nil, qualifyBERError(err, "diameterAddress", "encoding", false)
		}
		retagged_enc_1, tagErr_enc_1 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_1)
		if tagErr_enc_1 != nil {
			return nil, qualifyBERError(tagErr_enc_1, "diameterAddress", "encoding", false)
		}
		enc_1 = retagged_enc_1
		return enc_1, nil
	default:
		return nil, fmt.Errorf("unknown choice %d for SMServingNodeAddress", v.Choice)
	}
}

// MarshalDER encodes SMServingNodeAddress to DER format.
// Opaque descendants pass generic DER checks; foreign schema rules need a typed binding.
func (v *SMServingNodeAddress) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: SMServingNodeAddress receiver is nil", ber.ErrInvalidValue)
	}
	switch v.Choice {
	case SMServingNodeAddressChoiceDiameterAddress:
		if v.DiameterAddress == nil {
			return nil, fmt.Errorf("%w: choice SMServingNodeAddress: diameterAddress is nil", ber.ErrInvalidValue)
		}
		enc_der_1, err := v.DiameterAddress.MarshalDER()
		if err != nil {
			return nil, qualifyBERError(err, "diameterAddress", "encoding", true)
		}
		retagged_enc_der_1, tagErr_enc_der_1 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_der_1)
		if tagErr_enc_der_1 != nil {
			return nil, qualifyBERError(tagErr_enc_der_1, "diameterAddress", "encoding", true)
		}
		enc_der_1 = retagged_enc_der_1
		if derErr := ber.ValidateDEREncodedElement(enc_der_1); derErr != nil {
			return nil, qualifyBERError(derErr, "diameterAddress", "encoding", true)
		}
		return enc_der_1, nil
	}
	encoded, err := v.marshalBER()
	if err != nil {
		return nil, err
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		switch v.Choice {
		case SMServingNodeAddressChoiceNetworkNodeNumber:
			return nil, qualifyBERError(err, "networkNode-Number", "encoding", true)
		case SMServingNodeAddressChoiceDiameterAddress:
			return nil, qualifyBERError(err, "diameterAddress", "encoding", true)
		}
		return nil, fmt.Errorf("%s: %w", "encoding SMServingNodeAddress as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}

func (v *SMServingNodeAddress) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	encoded, err := v.MarshalDER()
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBER decodes SMServingNodeAddress from BER/DER format.
func (destination *SMServingNodeAddress) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if destination == nil {
		return fmt.Errorf("%w: SMServingNodeAddress destination is nil", ber.ErrInvalidValue)
	}
	v := new(SMServingNodeAddress)

	defer publishDecodedValue(destination, v, &returnErr)

	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	preparedData, preparedOptions, prepareErr := prepareCompositeBER(data, opts, s949588_14, "child", (*SMServingNodeAddress).UnmarshalBER)
	if prepareErr != nil {
		return prepareErr
	}
	data, opts = preparedData, preparedOptions
	defer func() {
		if returnErr == nil {
			returnErr = completeValueBER(data,
				opts, v, &v.berReplayNode_, (*SMServingNodeAddress).MarshalBER)
		}

	}()

	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
	*v = SMServingNodeAddress{}
	if len(data) == 0 {
		return fmt.Errorf("empty data for SMServingNodeAddress CHOICE")
	}
	choiceData := data
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for SMServingNodeAddress: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData, opts...)
	if tlvErr != nil {
		return fmt.Errorf("%s: %w", "decoding SMServingNodeAddress CHOICE", qualifyBERError(tlvErr, "", "decoding", false))
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "SMServingNodeAddress", Cause: ber.ErrExtraData}
	}

	if (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1) && peekTag.Constructed != true {
		return qualifyBERError(fmt.Errorf("%w: invalid primitive/constructed form for tag %s", ber.ErrInvalidTag, peekTag), "SMServingNodeAddress.diameterAddress", "decoding", false)
	}
	if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
		v.Choice = SMServingNodeAddressChoiceNetworkNodeNumber
		ber.MarkPreflightTarget(opts, "networkNode-Number", choiceData)
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData, opts...)
		if tlvErr != nil {
			return qualifyBERError(tlvErr, "networkNode-Number", "decoding", false)
		}
		_ = rawVal
		decVal, octetErr := ber.DecodeImplicitOctetStringValue(peekTag.Constructed, rawVal, opts...)
		if octetErr != nil {
			return qualifyBERError(octetErr, "networkNode-Number", "decoding", false)
		}
		tmp := ISDNAddressString(decVal)
		v.NetworkNodeNumber = &tmp
		if len(*v.NetworkNodeNumber) < 1 || len(*v.NetworkNodeNumber) > 9 {
			if constraintErr := checkDecodedLength(opts, s949588_14, "51.5", "networkNode-Number", "SIZE (1..9)", len(*v.NetworkNodeNumber)); constraintErr != nil {
				return constraintErr
			}
		}
		if len(*v.NetworkNodeNumber) < 1 || len(*v.NetworkNodeNumber) > 20 {
			if constraintErr := checkDecodedLength(opts, s949588_14, "51.5", "networkNode-Number", "SIZE (1..20)", len(*v.NetworkNodeNumber)); constraintErr != nil {
				return constraintErr
			}
		}
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 && peekTag.Constructed == true {
		v.Choice = SMServingNodeAddressChoiceDiameterAddress
		ber.MarkPreflightTarget(opts, "diameterAddress", choiceData)
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData, opts...)
		if tlvErr != nil {
			return qualifyBERError(tlvErr, "diameterAddress", "decoding", false)
		}
		_ = rawVal
		reconstructed, reconstructionErr := ber.EncodeImplicitTagWithClass(tag.ClassUniversal, tag.TagSequence, choiceData)
		if reconstructionErr != nil {
			return reconstructionErr
		}
		var dec NetworkNodeDiameterAddress
		if unmErr := dec.UnmarshalBER(reconstructed, ber.ChildDecodeOptions(opts, "diameterAddress")...); unmErr != nil {
			return qualifyBERError(unmErr, "diameterAddress", "decoding", false)
		}
		v.DiameterAddress = &dec
	} else {
		return fmt.Errorf("unknown tag %s for SMServingNodeAddress CHOICE", peekTag)
	}
	return nil
}

// MarshalBER encodes AlertServiceCentreArg to BER format.
func (v *AlertServiceCentreArg) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {

	if v == nil {
		return nil, fmt.Errorf("%w: AlertServiceCentreArg receiver is nil", ber.ErrInvalidValue)
	}
	return marshalFramedValue(v, v.berReplayNode_, opts, (*AlertServiceCentreArg).MarshalBER, (*AlertServiceCentreArg).marshalBER, 3)

}
func (v *AlertServiceCentreArg) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if len(v.Msisdn) < 1 || len(v.Msisdn) > 9 {
		if constraintErr := checkEncodedLength(opts, s949588_15, "51.5", "msisdn", "SIZE (1..9)", len(v.Msisdn)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	if len(v.Msisdn) < 1 || len(v.Msisdn) > 20 {
		if constraintErr := checkEncodedLength(opts, s949588_15, "51.5", "msisdn", "SIZE (1..20)", len(v.Msisdn)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_msisdn, encodeErr_enc_msisdn := ber.EncodeOctetString([]byte(v.Msisdn))
	if encodeErr_enc_msisdn != nil {
		return nil, qualifyBERError(encodeErr_enc_msisdn, "msisdn", "encoding", false)
	}
	children = append(children, enc_msisdn...)
	if len(v.ServiceCentreAddress) < 1 || len(v.ServiceCentreAddress) > 20 {
		if constraintErr := checkEncodedLength(opts, s949588_15, "51.5", "serviceCentreAddress", "SIZE (1..20)", len(v.ServiceCentreAddress)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_servicecentreaddress, encodeErr_enc_servicecentreaddress := ber.EncodeOctetString([]byte(v.ServiceCentreAddress))
	if encodeErr_enc_servicecentreaddress != nil {
		return nil, qualifyBERError(encodeErr_enc_servicecentreaddress, "serviceCentreAddress", "encoding", false)
	}
	children = append(children, enc_servicecentreaddress...)
	if v.Imsi != nil {
		if len(*v.Imsi) < 3 || len(*v.Imsi) > 8 {
			if constraintErr := checkEncodedLength(opts, s949588_15, "51.5", "imsi", "SIZE (3..8)", len(*v.Imsi)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_imsi, encodeErr_enc_imsi := ber.EncodeOctetString([]byte(*v.Imsi))
		if encodeErr_enc_imsi != nil {
			return nil, qualifyBERError(encodeErr_enc_imsi, "imsi", "encoding", false)
		}
		children = append(children, enc_imsi...)
	}
	if v.CorrelationID != nil {
		enc_correlationid, err := v.CorrelationID.MarshalBER(ber.ChildEncodeOptions(opts, "correlationID")...)
		if err != nil {
			return nil, qualifyBERError(err, "correlationID", "encoding", false)
		}
		ber.RecordGeneratedBERChildPlacement(opts, len(children), enc_correlationid)
		children = append(children, enc_correlationid...)
	}
	if v.MaximumUeAvailabilityTime != nil {
		if len(*v.MaximumUeAvailabilityTime) < 4 || len(*v.MaximumUeAvailabilityTime) > 4 {
			if constraintErr := checkEncodedLength(opts, s949588_15, "51.5", "maximumUeAvailabilityTime", "SIZE (4)", len(*v.MaximumUeAvailabilityTime)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_maximumueavailabilitytime, encodeErr_enc_maximumueavailabilitytime := ber.EncodeOctetString([]byte(*v.MaximumUeAvailabilityTime))
		if encodeErr_enc_maximumueavailabilitytime != nil {
			return nil, qualifyBERError(encodeErr_enc_maximumueavailabilitytime, "maximumUeAvailabilityTime", "encoding", false)
		}
		retagged_enc_maximumueavailabilitytime, tagErr_enc_maximumueavailabilitytime := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_maximumueavailabilitytime)
		if tagErr_enc_maximumueavailabilitytime != nil {
			return nil, qualifyBERError(tagErr_enc_maximumueavailabilitytime, "maximumUeAvailabilityTime", "encoding", false)
		}
		enc_maximumueavailabilitytime = retagged_enc_maximumueavailabilitytime
		children = append(children, enc_maximumueavailabilitytime...)
	}
	if v.SmsGmscAlertEvent != nil {
		if int64(*v.SmsGmscAlertEvent) != 0 && int64(*v.SmsGmscAlertEvent) != 1 {
			if constraintErr := checkEncodedValue(opts, s949588_15, "20", "smsGmscAlertEvent", "ENUMERATED {0, 1}", ber.ObserveInteger(int64(*v.SmsGmscAlertEvent))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_smsgmscalertevent := ber.EncodeEnumerated(int64(*v.SmsGmscAlertEvent))
		retagged_enc_smsgmscalertevent, tagErr_enc_smsgmscalertevent := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_smsgmscalertevent)
		if tagErr_enc_smsgmscalertevent != nil {
			return nil, qualifyBERError(tagErr_enc_smsgmscalertevent, "smsGmscAlertEvent", "encoding", false)
		}
		enc_smsgmscalertevent = retagged_enc_smsgmscalertevent
		children = append(children, enc_smsgmscalertevent...)
	}
	if v.SmsGmscDiameterAddress != nil {
		enc_smsgmscdiameteraddress, err := v.SmsGmscDiameterAddress.MarshalBER(ber.ChildEncodeOptions(opts, "smsGmscDiameterAddress")...)
		if err != nil {
			return nil, qualifyBERError(err, "smsGmscDiameterAddress", "encoding", false)
		}
		retagged_enc_smsgmscdiameteraddress, tagErr_enc_smsgmscdiameteraddress := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_smsgmscdiameteraddress)
		if tagErr_enc_smsgmscdiameteraddress != nil {
			return nil, qualifyBERError(tagErr_enc_smsgmscdiameteraddress, "smsGmscDiameterAddress", "encoding", false)
		}
		enc_smsgmscdiameteraddress = retagged_enc_smsgmscdiameteraddress
		ber.RecordGeneratedBERChildPlacement(opts, len(children), enc_smsgmscdiameteraddress)
		children = append(children, enc_smsgmscdiameteraddress...)
	}
	if v.NewSGSNNumber != nil {
		if len(*v.NewSGSNNumber) < 1 || len(*v.NewSGSNNumber) > 9 {
			if constraintErr := checkEncodedLength(opts, s949588_15, "51.5", "newSGSNNumber", "SIZE (1..9)", len(*v.NewSGSNNumber)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		if len(*v.NewSGSNNumber) < 1 || len(*v.NewSGSNNumber) > 20 {
			if constraintErr := checkEncodedLength(opts, s949588_15, "51.5", "newSGSNNumber", "SIZE (1..20)", len(*v.NewSGSNNumber)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_newsgsnnumber, encodeErr_enc_newsgsnnumber := ber.EncodeOctetString([]byte(*v.NewSGSNNumber))
		if encodeErr_enc_newsgsnnumber != nil {
			return nil, qualifyBERError(encodeErr_enc_newsgsnnumber, "newSGSNNumber", "encoding", false)
		}
		retagged_enc_newsgsnnumber, tagErr_enc_newsgsnnumber := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, enc_newsgsnnumber)
		if tagErr_enc_newsgsnnumber != nil {
			return nil, qualifyBERError(tagErr_enc_newsgsnnumber, "newSGSNNumber", "encoding", false)
		}
		enc_newsgsnnumber = retagged_enc_newsgsnnumber
		children = append(children, enc_newsgsnnumber...)
	}
	if v.NewSGSNDiameterAddress != nil {
		enc_newsgsndiameteraddress, err := v.NewSGSNDiameterAddress.MarshalBER(ber.ChildEncodeOptions(opts, "newSGSNDiameterAddress")...)
		if err != nil {
			return nil, qualifyBERError(err, "newSGSNDiameterAddress", "encoding", false)
		}
		retagged_enc_newsgsndiameteraddress, tagErr_enc_newsgsndiameteraddress := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, enc_newsgsndiameteraddress)
		if tagErr_enc_newsgsndiameteraddress != nil {
			return nil, qualifyBERError(tagErr_enc_newsgsndiameteraddress, "newSGSNDiameterAddress", "encoding", false)
		}
		enc_newsgsndiameteraddress = retagged_enc_newsgsndiameteraddress
		ber.RecordGeneratedBERChildPlacement(opts, len(children), enc_newsgsndiameteraddress)
		children = append(children, enc_newsgsndiameteraddress...)
	}
	if v.NewMMENumber != nil {
		if len(*v.NewMMENumber) < 1 || len(*v.NewMMENumber) > 9 {
			if constraintErr := checkEncodedLength(opts, s949588_15, "51.5", "newMMENumber", "SIZE (1..9)", len(*v.NewMMENumber)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		if len(*v.NewMMENumber) < 1 || len(*v.NewMMENumber) > 20 {
			if constraintErr := checkEncodedLength(opts, s949588_15, "51.5", "newMMENumber", "SIZE (1..20)", len(*v.NewMMENumber)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_newmmenumber, encodeErr_enc_newmmenumber := ber.EncodeOctetString([]byte(*v.NewMMENumber))
		if encodeErr_enc_newmmenumber != nil {
			return nil, qualifyBERError(encodeErr_enc_newmmenumber, "newMMENumber", "encoding", false)
		}
		retagged_enc_newmmenumber, tagErr_enc_newmmenumber := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 5, enc_newmmenumber)
		if tagErr_enc_newmmenumber != nil {
			return nil, qualifyBERError(tagErr_enc_newmmenumber, "newMMENumber", "encoding", false)
		}
		enc_newmmenumber = retagged_enc_newmmenumber
		children = append(children, enc_newmmenumber...)
	}
	if v.NewMMEDiameterAddress != nil {
		enc_newmmediameteraddress, err := v.NewMMEDiameterAddress.MarshalBER(ber.ChildEncodeOptions(opts, "newMMEDiameterAddress")...)
		if err != nil {
			return nil, qualifyBERError(err, "newMMEDiameterAddress", "encoding", false)
		}
		retagged_enc_newmmediameteraddress, tagErr_enc_newmmediameteraddress := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 6, enc_newmmediameteraddress)
		if tagErr_enc_newmmediameteraddress != nil {
			return nil, qualifyBERError(tagErr_enc_newmmediameteraddress, "newMMEDiameterAddress", "encoding", false)
		}
		enc_newmmediameteraddress = retagged_enc_newmmediameteraddress
		ber.RecordGeneratedBERChildPlacement(opts, len(children), enc_newmmediameteraddress)
		children = append(children, enc_newmmediameteraddress...)
	}
	if v.NewMSCNumber != nil {
		if len(*v.NewMSCNumber) < 1 || len(*v.NewMSCNumber) > 9 {
			if constraintErr := checkEncodedLength(opts, s949588_15, "51.5", "newMSCNumber", "SIZE (1..9)", len(*v.NewMSCNumber)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		if len(*v.NewMSCNumber) < 1 || len(*v.NewMSCNumber) > 20 {
			if constraintErr := checkEncodedLength(opts, s949588_15, "51.5", "newMSCNumber", "SIZE (1..20)", len(*v.NewMSCNumber)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_newmscnumber, encodeErr_enc_newmscnumber := ber.EncodeOctetString([]byte(*v.NewMSCNumber))
		if encodeErr_enc_newmscnumber != nil {
			return nil, qualifyBERError(encodeErr_enc_newmscnumber, "newMSCNumber", "encoding", false)
		}
		retagged_enc_newmscnumber, tagErr_enc_newmscnumber := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 7, enc_newmscnumber)
		if tagErr_enc_newmscnumber != nil {
			return nil, qualifyBERError(tagErr_enc_newmscnumber, "newMSCNumber", "encoding", false)
		}
		enc_newmscnumber = retagged_enc_newmscnumber
		children = append(children, enc_newmscnumber...)
	}
	base_ := -1
	for i, ext := range v.ExtData_ {
		if err := checkOpaqueAddition(ext, opts, s949588_15, children, i, &base_); err != nil {
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
		if i == 0 && ((peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 7) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 6) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 5) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0) || (peekTag.Class == tag.ClassUniversal && peekTag.Number == 16) || (peekTag.Class == tag.ClassUniversal && peekTag.Number == 4)) {
			if constraintErr := ber.CheckEncodedValue(ber.EncodeRule(opts, s949588_15, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
				return nil, constraintErr
			}
		}
		children = append(children, ext...)
	}
	ber.RecordGeneratedBERContainer(opts, children)
	return ber.EncodeSequence(children)
}
func (v *AlertServiceCentreArg) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// MarshalDER encodes AlertServiceCentreArg to DER format.
// Opaque descendants pass generic DER checks; foreign schema rules need a typed binding.
func (v *AlertServiceCentreArg) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: AlertServiceCentreArg receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if len(v.Msisdn) < 1 || len(v.Msisdn) > 9 {
		if constraintErr := checkEncodedLength(nil, s949588_15, "51.5", "msisdn", "SIZE (1..9)", len(v.Msisdn)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	if len(v.Msisdn) < 1 || len(v.Msisdn) > 20 {
		if constraintErr := checkEncodedLength(nil, s949588_15, "51.5", "msisdn", "SIZE (1..20)", len(v.Msisdn)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_msisdn, encodeErr_enc_msisdn := ber.EncodeOctetString([]byte(v.Msisdn))
	if encodeErr_enc_msisdn != nil {
		return nil, qualifyBERError(encodeErr_enc_msisdn, "msisdn", "encoding", true)
	}
	children = append(children, enc_msisdn...)
	if len(v.ServiceCentreAddress) < 1 || len(v.ServiceCentreAddress) > 20 {
		if constraintErr := checkEncodedLength(nil, s949588_15, "51.5", "serviceCentreAddress", "SIZE (1..20)", len(v.ServiceCentreAddress)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_servicecentreaddress, encodeErr_enc_servicecentreaddress := ber.EncodeOctetString([]byte(v.ServiceCentreAddress))
	if encodeErr_enc_servicecentreaddress != nil {
		return nil, qualifyBERError(encodeErr_enc_servicecentreaddress, "serviceCentreAddress", "encoding", true)
	}
	children = append(children, enc_servicecentreaddress...)
	if v.Imsi != nil {
		if len(*v.Imsi) < 3 || len(*v.Imsi) > 8 {
			if constraintErr := checkEncodedLength(nil, s949588_15, "51.5", "imsi", "SIZE (3..8)", len(*v.Imsi)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_imsi, encodeErr_enc_imsi := ber.EncodeOctetString([]byte(*v.Imsi))
		if encodeErr_enc_imsi != nil {
			return nil, qualifyBERError(encodeErr_enc_imsi, "imsi", "encoding", true)
		}
		children = append(children, enc_imsi...)
	}
	if v.CorrelationID != nil {
		enc_correlationid, err := v.CorrelationID.MarshalDER()
		if err != nil {
			return nil, qualifyBERError(err, "correlationID", "encoding", true)
		}
		children = append(children, enc_correlationid...)
	}
	if v.MaximumUeAvailabilityTime != nil {
		if len(*v.MaximumUeAvailabilityTime) < 4 || len(*v.MaximumUeAvailabilityTime) > 4 {
			if constraintErr := checkEncodedLength(nil, s949588_15, "51.5", "maximumUeAvailabilityTime", "SIZE (4)", len(*v.MaximumUeAvailabilityTime)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_maximumueavailabilitytime, encodeErr_enc_maximumueavailabilitytime := ber.EncodeOctetString([]byte(*v.MaximumUeAvailabilityTime))
		if encodeErr_enc_maximumueavailabilitytime != nil {
			return nil, qualifyBERError(encodeErr_enc_maximumueavailabilitytime, "maximumUeAvailabilityTime", "encoding", true)
		}
		retagged_enc_maximumueavailabilitytime, tagErr_enc_maximumueavailabilitytime := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_maximumueavailabilitytime)
		if tagErr_enc_maximumueavailabilitytime != nil {
			return nil, qualifyBERError(tagErr_enc_maximumueavailabilitytime, "maximumUeAvailabilityTime", "encoding", true)
		}
		enc_maximumueavailabilitytime = retagged_enc_maximumueavailabilitytime
		children = append(children, enc_maximumueavailabilitytime...)
	}
	if v.SmsGmscAlertEvent != nil {
		if int64(*v.SmsGmscAlertEvent) != 0 && int64(*v.SmsGmscAlertEvent) != 1 {
			if constraintErr := checkEncodedValue(nil, s949588_15, "20", "smsGmscAlertEvent", "ENUMERATED {0, 1}", ber.ObserveInteger(int64(*v.SmsGmscAlertEvent))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_smsgmscalertevent := ber.EncodeEnumerated(int64(*v.SmsGmscAlertEvent))
		retagged_enc_smsgmscalertevent, tagErr_enc_smsgmscalertevent := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_smsgmscalertevent)
		if tagErr_enc_smsgmscalertevent != nil {
			return nil, qualifyBERError(tagErr_enc_smsgmscalertevent, "smsGmscAlertEvent", "encoding", true)
		}
		enc_smsgmscalertevent = retagged_enc_smsgmscalertevent
		children = append(children, enc_smsgmscalertevent...)
	}
	if v.SmsGmscDiameterAddress != nil {
		enc_smsgmscdiameteraddress, err := v.SmsGmscDiameterAddress.MarshalDER()
		if err != nil {
			return nil, qualifyBERError(err, "smsGmscDiameterAddress", "encoding", true)
		}
		retagged_enc_smsgmscdiameteraddress, tagErr_enc_smsgmscdiameteraddress := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_smsgmscdiameteraddress)
		if tagErr_enc_smsgmscdiameteraddress != nil {
			return nil, qualifyBERError(tagErr_enc_smsgmscdiameteraddress, "smsGmscDiameterAddress", "encoding", true)
		}
		enc_smsgmscdiameteraddress = retagged_enc_smsgmscdiameteraddress
		children = append(children, enc_smsgmscdiameteraddress...)
	}
	if v.NewSGSNNumber != nil {
		if len(*v.NewSGSNNumber) < 1 || len(*v.NewSGSNNumber) > 9 {
			if constraintErr := checkEncodedLength(nil, s949588_15, "51.5", "newSGSNNumber", "SIZE (1..9)", len(*v.NewSGSNNumber)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		if len(*v.NewSGSNNumber) < 1 || len(*v.NewSGSNNumber) > 20 {
			if constraintErr := checkEncodedLength(nil, s949588_15, "51.5", "newSGSNNumber", "SIZE (1..20)", len(*v.NewSGSNNumber)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_newsgsnnumber, encodeErr_enc_newsgsnnumber := ber.EncodeOctetString([]byte(*v.NewSGSNNumber))
		if encodeErr_enc_newsgsnnumber != nil {
			return nil, qualifyBERError(encodeErr_enc_newsgsnnumber, "newSGSNNumber", "encoding", true)
		}
		retagged_enc_newsgsnnumber, tagErr_enc_newsgsnnumber := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, enc_newsgsnnumber)
		if tagErr_enc_newsgsnnumber != nil {
			return nil, qualifyBERError(tagErr_enc_newsgsnnumber, "newSGSNNumber", "encoding", true)
		}
		enc_newsgsnnumber = retagged_enc_newsgsnnumber
		children = append(children, enc_newsgsnnumber...)
	}
	if v.NewSGSNDiameterAddress != nil {
		enc_newsgsndiameteraddress, err := v.NewSGSNDiameterAddress.MarshalDER()
		if err != nil {
			return nil, qualifyBERError(err, "newSGSNDiameterAddress", "encoding", true)
		}
		retagged_enc_newsgsndiameteraddress, tagErr_enc_newsgsndiameteraddress := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, enc_newsgsndiameteraddress)
		if tagErr_enc_newsgsndiameteraddress != nil {
			return nil, qualifyBERError(tagErr_enc_newsgsndiameteraddress, "newSGSNDiameterAddress", "encoding", true)
		}
		enc_newsgsndiameteraddress = retagged_enc_newsgsndiameteraddress
		children = append(children, enc_newsgsndiameteraddress...)
	}
	if v.NewMMENumber != nil {
		if len(*v.NewMMENumber) < 1 || len(*v.NewMMENumber) > 9 {
			if constraintErr := checkEncodedLength(nil, s949588_15, "51.5", "newMMENumber", "SIZE (1..9)", len(*v.NewMMENumber)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		if len(*v.NewMMENumber) < 1 || len(*v.NewMMENumber) > 20 {
			if constraintErr := checkEncodedLength(nil, s949588_15, "51.5", "newMMENumber", "SIZE (1..20)", len(*v.NewMMENumber)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_newmmenumber, encodeErr_enc_newmmenumber := ber.EncodeOctetString([]byte(*v.NewMMENumber))
		if encodeErr_enc_newmmenumber != nil {
			return nil, qualifyBERError(encodeErr_enc_newmmenumber, "newMMENumber", "encoding", true)
		}
		retagged_enc_newmmenumber, tagErr_enc_newmmenumber := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 5, enc_newmmenumber)
		if tagErr_enc_newmmenumber != nil {
			return nil, qualifyBERError(tagErr_enc_newmmenumber, "newMMENumber", "encoding", true)
		}
		enc_newmmenumber = retagged_enc_newmmenumber
		children = append(children, enc_newmmenumber...)
	}
	if v.NewMMEDiameterAddress != nil {
		enc_newmmediameteraddress, err := v.NewMMEDiameterAddress.MarshalDER()
		if err != nil {
			return nil, qualifyBERError(err, "newMMEDiameterAddress", "encoding", true)
		}
		retagged_enc_newmmediameteraddress, tagErr_enc_newmmediameteraddress := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 6, enc_newmmediameteraddress)
		if tagErr_enc_newmmediameteraddress != nil {
			return nil, qualifyBERError(tagErr_enc_newmmediameteraddress, "newMMEDiameterAddress", "encoding", true)
		}
		enc_newmmediameteraddress = retagged_enc_newmmediameteraddress
		children = append(children, enc_newmmediameteraddress...)
	}
	if v.NewMSCNumber != nil {
		if len(*v.NewMSCNumber) < 1 || len(*v.NewMSCNumber) > 9 {
			if constraintErr := checkEncodedLength(nil, s949588_15, "51.5", "newMSCNumber", "SIZE (1..9)", len(*v.NewMSCNumber)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		if len(*v.NewMSCNumber) < 1 || len(*v.NewMSCNumber) > 20 {
			if constraintErr := checkEncodedLength(nil, s949588_15, "51.5", "newMSCNumber", "SIZE (1..20)", len(*v.NewMSCNumber)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_newmscnumber, encodeErr_enc_newmscnumber := ber.EncodeOctetString([]byte(*v.NewMSCNumber))
		if encodeErr_enc_newmscnumber != nil {
			return nil, qualifyBERError(encodeErr_enc_newmscnumber, "newMSCNumber", "encoding", true)
		}
		retagged_enc_newmscnumber, tagErr_enc_newmscnumber := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 7, enc_newmscnumber)
		if tagErr_enc_newmscnumber != nil {
			return nil, qualifyBERError(tagErr_enc_newmscnumber, "newMSCNumber", "encoding", true)
		}
		enc_newmscnumber = retagged_enc_newmscnumber
		children = append(children, enc_newmscnumber...)
	}
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDEREncodedElement(ext); err != nil {
			return nil, invalidDERAddition(ext, s949588_15, children, i)
		}
		peekTag, _, _, extErr := ber.DecodeEncodedTLV(ext)
		if extErr != nil {
			return nil, extErr
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: only the first addition is restricted.
		if i == 0 && ((peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 7) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 6) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 5) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0) || (peekTag.Class == tag.ClassUniversal && peekTag.Number == 16) || (peekTag.Class == tag.ClassUniversal && peekTag.Number == 4)) {
			if constraintErr := ber.CheckEncodedValue(ber.EncodeRule(nil, s949588_15, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
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
		return nil, fmt.Errorf("%s: %w", "encoding AlertServiceCentreArg as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}
func (v *AlertServiceCentreArg) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	encoded, err := v.MarshalDER()
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBER decodes AlertServiceCentreArg from BER/DER format.
func (destination *AlertServiceCentreArg) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if destination == nil {
		return fmt.Errorf("%w: AlertServiceCentreArg destination is nil", ber.ErrInvalidValue)
	}
	v := new(AlertServiceCentreArg)

	defer publishDecodedValue(destination, v, &returnErr)

	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	preparedData, preparedOptions, prepareErr := prepareCompositeBER(data, opts, s949588_15, "child", (*AlertServiceCentreArg).UnmarshalBER)
	if prepareErr != nil {
		return prepareErr
	}
	data, opts = preparedData, preparedOptions

	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
	*v = AlertServiceCentreArg{}
	defer func() {
		if returnErr == nil {
			returnErr = completeValueBER(data,
				opts, v, &v.berReplayNode_, (*AlertServiceCentreArg).MarshalBER)
		}

	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("%s: %w", "decoding AlertServiceCentreArg SEQUENCE", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "AlertServiceCentreArg", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode msisdn
	if offset >= len(content) {
		return fmt.Errorf("missing required field msisdn")
	}
	{
		ber.MarkPreflightTarget(opts, "msisdn", content[offset:])
		val_msisdn, n, err := ber.DecodeOctetString(content[offset:], opts...)
		if err != nil {
			return qualifyBERError(err, "msisdn", "decoding", false)
		}
		v.Msisdn = ISDNAddressString(val_msisdn)
		if offset > len(content) || n < 0 || n > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n
		if len(v.Msisdn) < 1 || len(v.Msisdn) > 9 {
			if constraintErr := checkDecodedLength(opts, s949588_15, "51.5", "msisdn", "SIZE (1..9)", len(v.Msisdn)); constraintErr != nil {
				return constraintErr
			}
		}
		if len(v.Msisdn) < 1 || len(v.Msisdn) > 20 {
			if constraintErr := checkDecodedLength(opts, s949588_15, "51.5", "msisdn", "SIZE (1..20)", len(v.Msisdn)); constraintErr != nil {
				return constraintErr
			}
		}
	}
	// Decode serviceCentreAddress
	if offset >= len(content) {
		return fmt.Errorf("missing required field serviceCentreAddress")
	}
	{
		ber.MarkPreflightTarget(opts, "serviceCentreAddress", content[offset:])
		val_servicecentreaddress, n, err := ber.DecodeOctetString(content[offset:], opts...)
		if err != nil {
			return qualifyBERError(err, "serviceCentreAddress", "decoding", false)
		}
		v.ServiceCentreAddress = AddressString(val_servicecentreaddress)
		if offset < 0 || offset >
			len(content) || n < 0 || n > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n
		if len(v.ServiceCentreAddress) < 1 || len(v.ServiceCentreAddress) > 20 {
			if constraintErr := checkDecodedLength(opts, s949588_15, "51.5", "serviceCentreAddress", "SIZE (1..20)", len(v.ServiceCentreAddress)); constraintErr != nil {
				return constraintErr
			}
		}
	}
	// Decode imsi
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassUniversal && peekTag.Number == 4 {
				ber.MarkPreflightTarget(opts, "imsi", content[offset:])
				val_imsi, n, err := ber.DecodeOctetString(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "imsi", "decoding", false)
				}
				tmp_imsi := IMSI(val_imsi)
				v.Imsi = &tmp_imsi
				if offset < 0 || offset >
					len(content) || n < 0 || n > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n
				if len(*v.Imsi) < 3 || len(*v.Imsi) > 8 {
					if constraintErr := checkDecodedLength(opts, s949588_15, "51.5", "imsi", "SIZE (3..8)", len(*v.Imsi)); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode correlationID
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassUniversal && peekTag.Number == 16 {
				ber.MarkPreflightTarget(opts, "correlationID", content[offset:])
				// Decode nested SEQUENCE (CorrelationID)
				_, n_correlationid, _, tlvErr_correlationid := ber.DecodeTLV(content[offset:], opts...)
				if tlvErr_correlationid != nil {
					return qualifyBERError(tlvErr_correlationid, "correlationID", "decoding", false)
				}
				var dec_correlationid CorrelationID
				if offset < 0 || offset >
					len(content) || n_correlationid < 0 || n_correlationid > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				if unmErr := dec_correlationid.UnmarshalBER(content[offset:offset+n_correlationid], ber.ChildDecodeOptions(opts, "correlationID")...); unmErr != nil {
					return qualifyBERError(unmErr, "correlationID", "decoding", false)
				}
				v.CorrelationID = &dec_correlationid
				if offset < 0 || offset >
					len(content) || n_correlationid < 0 || n_correlationid > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_correlationid
			}
		}
	}
	// Decode maximumUeAvailabilityTime
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
				ber.MarkPreflightTarget(opts, "maximumUeAvailabilityTime", content[offset:])
				decodedTag_maximumueavailabilitytime, n_maximumueavailabilitytime, rawVal_maximumueavailabilitytime, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "maximumUeAvailabilityTime", "decoding", false)
				}
				if decodedTag_maximumueavailabilitytime.Class != tag.ClassContextSpecific || decodedTag_maximumueavailabilitytime.Number != 0 {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_maximumueavailabilitytime), "maximumUeAvailabilityTime", "decoding", false)
				}
				decVal_maximumueavailabilitytime, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_maximumueavailabilitytime.Constructed, rawVal_maximumueavailabilitytime, opts...)
				if octetErr != nil {
					return qualifyBERError(octetErr, "maximumUeAvailabilityTime", "decoding", false)
				}
				tmp_maximumueavailabilitytime := Time(decVal_maximumueavailabilitytime)
				v.MaximumUeAvailabilityTime = &tmp_maximumueavailabilitytime
				if offset < 0 || offset >
					len(content) || n_maximumueavailabilitytime < 0 || n_maximumueavailabilitytime >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_maximumueavailabilitytime
				if len(*v.MaximumUeAvailabilityTime) < 4 || len(*v.MaximumUeAvailabilityTime) > 4 {
					if constraintErr := checkDecodedLength(opts, s949588_15, "51.5", "maximumUeAvailabilityTime", "SIZE (4)", len(*v.MaximumUeAvailabilityTime)); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode smsGmscAlertEvent
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
				ber.MarkPreflightTarget(opts, "smsGmscAlertEvent", content[offset:])
				decodedTag_smsgmscalertevent, n_smsgmscalertevent, rawVal_smsgmscalertevent, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "smsGmscAlertEvent", "decoding", false)
				}
				if decodedTag_smsgmscalertevent.Class != tag.ClassContextSpecific || decodedTag_smsgmscalertevent.Number != 1 || decodedTag_smsgmscalertevent.Constructed != false {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_smsgmscalertevent), "smsGmscAlertEvent", "decoding", false)
				}
				decVal_smsgmscalertevent, intErr := ber.DecodeEnumeratedValue(rawVal_smsgmscalertevent)
				if intErr != nil {
					return qualifyBERError(intErr, "smsGmscAlertEvent", "decoding", false)
				}
				tmp_smsgmscalertevent := SmsGmscAlertEvent(decVal_smsgmscalertevent)
				v.SmsGmscAlertEvent = &tmp_smsgmscalertevent
				if offset < 0 || offset >
					len(content) || n_smsgmscalertevent < 0 || n_smsgmscalertevent >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_smsgmscalertevent
				if int64(*v.SmsGmscAlertEvent) != 0 && int64(*v.SmsGmscAlertEvent) != 1 {
					if constraintErr := checkDecodedValue(opts, s949588_15, "20", "smsGmscAlertEvent", "ENUMERATED {0, 1}", ber.ObserveInteger(int64(*v.SmsGmscAlertEvent))); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode smsGmscDiameterAddress
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2 {
				ber.MarkPreflightTarget(opts, "smsGmscDiameterAddress", content[offset:])
				decodedTag_smsgmscdiameteraddress, n_smsgmscdiameteraddress, rawVal_smsgmscdiameteraddress, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "smsGmscDiameterAddress", "decoding", false)
				}
				if decodedTag_smsgmscdiameteraddress.Class != tag.ClassContextSpecific || decodedTag_smsgmscdiameteraddress.Number != 2 || decodedTag_smsgmscdiameteraddress.Constructed != true {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_smsgmscdiameteraddress), "smsGmscDiameterAddress", "decoding", false)
				}
				_ = rawVal_smsgmscdiameteraddress
				if offset < 0 || offset >
					len(content) || n_smsgmscdiameteraddress < 0 || n_smsgmscdiameteraddress >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				reconstructed_smsgmscdiameteraddress, reconstructionErr_smsgmscdiameteraddress := ber.EncodeImplicitTagWithClass(tag.ClassUniversal, tag.TagSequence, content[offset:offset+n_smsgmscdiameteraddress])
				if reconstructionErr_smsgmscdiameteraddress != nil {
					return qualifyBERError(reconstructionErr_smsgmscdiameteraddress, "smsGmscDiameterAddress", "decoding", false)
				}
				var dec_smsgmscdiameteraddress NetworkNodeDiameterAddress
				if unmErr := dec_smsgmscdiameteraddress.UnmarshalBER(reconstructed_smsgmscdiameteraddress, ber.ChildDecodeOptions(opts, "smsGmscDiameterAddress")...); unmErr != nil {
					return qualifyBERError(unmErr, "smsGmscDiameterAddress", "decoding", false)
				}
				v.SmsGmscDiameterAddress = &dec_smsgmscdiameteraddress
				if offset < 0 || offset >
					len(content) || n_smsgmscdiameteraddress < 0 || n_smsgmscdiameteraddress >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_smsgmscdiameteraddress
			}
		}
	}
	// Decode newSGSNNumber
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3 {
				ber.MarkPreflightTarget(opts, "newSGSNNumber", content[offset:])
				decodedTag_newsgsnnumber, n_newsgsnnumber, rawVal_newsgsnnumber, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "newSGSNNumber", "decoding", false)
				}
				if decodedTag_newsgsnnumber.Class != tag.ClassContextSpecific || decodedTag_newsgsnnumber.Number != 3 {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_newsgsnnumber), "newSGSNNumber", "decoding", false)
				}
				decVal_newsgsnnumber, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_newsgsnnumber.Constructed, rawVal_newsgsnnumber, opts...)
				if octetErr != nil {
					return qualifyBERError(octetErr, "newSGSNNumber", "decoding", false)
				}
				tmp_newsgsnnumber := ISDNAddressString(decVal_newsgsnnumber)
				v.NewSGSNNumber = &tmp_newsgsnnumber
				if offset < 0 || offset >
					len(content) || n_newsgsnnumber < 0 || n_newsgsnnumber > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_newsgsnnumber
				if len(*v.NewSGSNNumber) < 1 || len(*v.NewSGSNNumber) > 9 {
					if constraintErr := checkDecodedLength(opts, s949588_15, "51.5", "newSGSNNumber", "SIZE (1..9)", len(*v.NewSGSNNumber)); constraintErr != nil {
						return constraintErr
					}
				}
				if len(*v.NewSGSNNumber) < 1 || len(*v.NewSGSNNumber) > 20 {
					if constraintErr := checkDecodedLength(opts, s949588_15, "51.5", "newSGSNNumber", "SIZE (1..20)", len(*v.NewSGSNNumber)); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode newSGSNDiameterAddress
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4 {
				ber.MarkPreflightTarget(opts, "newSGSNDiameterAddress", content[offset:])
				decodedTag_newsgsndiameteraddress, n_newsgsndiameteraddress, rawVal_newsgsndiameteraddress, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "newSGSNDiameterAddress", "decoding", false)
				}
				if decodedTag_newsgsndiameteraddress.Class != tag.ClassContextSpecific || decodedTag_newsgsndiameteraddress.Number != 4 || decodedTag_newsgsndiameteraddress.Constructed != true {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_newsgsndiameteraddress), "newSGSNDiameterAddress", "decoding", false)
				}
				_ = rawVal_newsgsndiameteraddress
				if offset < 0 || offset >
					len(content) || n_newsgsndiameteraddress < 0 || n_newsgsndiameteraddress >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				reconstructed_newsgsndiameteraddress, reconstructionErr_newsgsndiameteraddress := ber.EncodeImplicitTagWithClass(tag.ClassUniversal, tag.TagSequence, content[offset:offset+n_newsgsndiameteraddress])
				if reconstructionErr_newsgsndiameteraddress != nil {
					return qualifyBERError(reconstructionErr_newsgsndiameteraddress, "newSGSNDiameterAddress", "decoding", false)
				}
				var dec_newsgsndiameteraddress NetworkNodeDiameterAddress
				if unmErr := dec_newsgsndiameteraddress.UnmarshalBER(reconstructed_newsgsndiameteraddress, ber.ChildDecodeOptions(opts, "newSGSNDiameterAddress")...); unmErr != nil {
					return qualifyBERError(unmErr, "newSGSNDiameterAddress", "decoding", false)
				}
				v.NewSGSNDiameterAddress = &dec_newsgsndiameteraddress
				if offset < 0 || offset >
					len(content) || n_newsgsndiameteraddress < 0 || n_newsgsndiameteraddress >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_newsgsndiameteraddress
			}
		}
	}
	// Decode newMMENumber
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 5 {
				ber.MarkPreflightTarget(opts, "newMMENumber", content[offset:])
				decodedTag_newmmenumber, n_newmmenumber, rawVal_newmmenumber, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "newMMENumber", "decoding", false)
				}
				if decodedTag_newmmenumber.Class != tag.ClassContextSpecific || decodedTag_newmmenumber.Number != 5 {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_newmmenumber), "newMMENumber", "decoding", false)
				}
				decVal_newmmenumber, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_newmmenumber.Constructed, rawVal_newmmenumber, opts...)
				if octetErr != nil {
					return qualifyBERError(octetErr, "newMMENumber", "decoding", false)
				}
				tmp_newmmenumber := ISDNAddressString(decVal_newmmenumber)
				v.NewMMENumber = &tmp_newmmenumber
				if offset < 0 || offset >
					len(content) || n_newmmenumber < 0 || n_newmmenumber > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_newmmenumber
				if len(*v.NewMMENumber) < 1 || len(*v.NewMMENumber) > 9 {
					if constraintErr := checkDecodedLength(opts, s949588_15, "51.5", "newMMENumber", "SIZE (1..9)", len(*v.NewMMENumber)); constraintErr != nil {
						return constraintErr
					}
				}
				if len(*v.NewMMENumber) < 1 || len(*v.NewMMENumber) > 20 {
					if constraintErr := checkDecodedLength(opts, s949588_15, "51.5", "newMMENumber", "SIZE (1..20)", len(*v.NewMMENumber)); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode newMMEDiameterAddress
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 6 {
				ber.MarkPreflightTarget(opts, "newMMEDiameterAddress", content[offset:])
				decodedTag_newmmediameteraddress, n_newmmediameteraddress, rawVal_newmmediameteraddress, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "newMMEDiameterAddress", "decoding", false)
				}
				if decodedTag_newmmediameteraddress.Class != tag.ClassContextSpecific || decodedTag_newmmediameteraddress.Number != 6 || decodedTag_newmmediameteraddress.Constructed != true {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_newmmediameteraddress), "newMMEDiameterAddress", "decoding", false)
				}
				_ = rawVal_newmmediameteraddress
				if offset < 0 || offset >
					len(content) || n_newmmediameteraddress < 0 || n_newmmediameteraddress >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				reconstructed_newmmediameteraddress, reconstructionErr_newmmediameteraddress := ber.EncodeImplicitTagWithClass(tag.ClassUniversal, tag.TagSequence, content[offset:offset+n_newmmediameteraddress])
				if reconstructionErr_newmmediameteraddress != nil {
					return qualifyBERError(reconstructionErr_newmmediameteraddress, "newMMEDiameterAddress", "decoding", false)
				}
				var dec_newmmediameteraddress NetworkNodeDiameterAddress
				if unmErr := dec_newmmediameteraddress.UnmarshalBER(reconstructed_newmmediameteraddress, ber.ChildDecodeOptions(opts, "newMMEDiameterAddress")...); unmErr != nil {
					return qualifyBERError(unmErr, "newMMEDiameterAddress", "decoding", false)
				}
				v.NewMMEDiameterAddress = &dec_newmmediameteraddress
				if offset < 0 || offset >
					len(content) || n_newmmediameteraddress < 0 || n_newmmediameteraddress >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_newmmediameteraddress
			}
		}
	}
	// Decode newMSCNumber
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 7 {
				ber.MarkPreflightTarget(opts, "newMSCNumber", content[offset:])
				decodedTag_newmscnumber, n_newmscnumber, rawVal_newmscnumber, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "newMSCNumber", "decoding", false)
				}
				if decodedTag_newmscnumber.Class != tag.ClassContextSpecific || decodedTag_newmscnumber.Number != 7 {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_newmscnumber), "newMSCNumber", "decoding", false)
				}
				decVal_newmscnumber, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_newmscnumber.Constructed, rawVal_newmscnumber, opts...)
				if octetErr != nil {
					return qualifyBERError(octetErr, "newMSCNumber", "decoding", false)
				}
				tmp_newmscnumber := ISDNAddressString(decVal_newmscnumber)
				v.NewMSCNumber = &tmp_newmscnumber
				if offset < 0 || offset >
					len(content) || n_newmscnumber < 0 || n_newmscnumber > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_newmscnumber
				if len(*v.NewMSCNumber) < 1 || len(*v.NewMSCNumber) > 9 {
					if constraintErr := checkDecodedLength(opts, s949588_15, "51.5", "newMSCNumber", "SIZE (1..9)", len(*v.NewMSCNumber)); constraintErr != nil {
						return constraintErr
					}
				}
				if len(*v.NewMSCNumber) < 1 || len(*v.NewMSCNumber) > 20 {
					if constraintErr := checkDecodedLength(opts, s949588_15, "51.5", "newMSCNumber", "SIZE (1..20)", len(*v.NewMSCNumber)); constraintErr != nil {
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
			return &ber.DecodeError{Offset: offset, TypeName: "AlertServiceCentreArg", Cause: extErr_}
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: the first unknown addition must differ from trailing OPTIONAL/DEFAULT tags.
		if len(v.ExtData_) == 0 && ((peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 7) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 6) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 5) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0) || (peekTag.Class == tag.ClassUniversal && peekTag.Number == 16) || (peekTag.Class == tag.ClassUniversal && peekTag.Number == 4)) {
			if !ber.ToleranceEnabled(opts) {
				return &ber.DecodeError{Offset: offset, TypeName: "AlertServiceCentreArg", Cause: fmt.Errorf("%w: repeated or out-of-order SEQUENCE component tag %s", ber.ErrInvalidTag, peekTag)}
			}
			if orderErr_ := ber.CheckDecodedValue(ber.DecodeRule(opts, s949588_15, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), fmt.Sprintf("ExtData_[%d]", len(v.ExtData_)), "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); orderErr_ != nil {
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

// MarshalBER encodes InformServiceCentreArg to BER format.
func (v *InformServiceCentreArg) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {

	if v == nil {
		return nil, fmt.Errorf("%w: InformServiceCentreArg receiver is nil", ber.ErrInvalidValue)
	}
	return marshalFramedValue(v, v.berReplayNode_, opts, (*InformServiceCentreArg).MarshalBER, (*InformServiceCentreArg).marshalBER, 3)

}
func (v *InformServiceCentreArg) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if v.StoredMSISDN != nil {
		if len(*v.StoredMSISDN) < 1 || len(*v.StoredMSISDN) > 9 {
			if constraintErr := checkEncodedLength(opts, s949588_16, "51.5", "storedMSISDN", "SIZE (1..9)", len(*v.StoredMSISDN)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		if len(*v.StoredMSISDN) < 1 || len(*v.StoredMSISDN) > 20 {
			if constraintErr := checkEncodedLength(opts, s949588_16, "51.5", "storedMSISDN", "SIZE (1..20)", len(*v.StoredMSISDN)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_storedmsisdn, encodeErr_enc_storedmsisdn := ber.EncodeOctetString([]byte(*v.StoredMSISDN))
		if encodeErr_enc_storedmsisdn != nil {
			return nil, qualifyBERError(encodeErr_enc_storedmsisdn, "storedMSISDN", "encoding", false)
		}
		children = append(children, enc_storedmsisdn...)
	}
	if v.MwStatus != nil {
		namedBits_MwStatus, namedBitErr_ := normalizeNamedBits(*v.MwStatus, []ber.NamedBitSizeSet{{{Min: 6, Max: 16}}}, opts, "mw-Status", s949588_16)
		if namedBitErr_ != nil {
			return nil, namedBitErr_
		}
		if bitStringErr := ber.ValidateBitStringLength(namedBits_MwStatus.Bytes, namedBits_MwStatus.BitLength); bitStringErr != nil {
			return nil, qualifyBERError(bitStringErr, "mw-Status", "encoding", false)
		}
		// arithmetic pattern BER_BITSTRING_FIELD: 0 <= bit length before modulo and subtraction; gen/codegen.go:750
		if namedBits_MwStatus.BitLength < 0 {
			return nil, fmt.Errorf("negative bit string length")
		}
		if (namedBits_MwStatus).BitLength < 6 || (namedBits_MwStatus).BitLength > 16 {
			if constraintErr := checkEncodedLength(opts, s949588_16, "51.5", "mw-Status", "SIZE (6..16)", namedBitObservedLength(namedBits_MwStatus)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_mwstatus, encodeErr_enc_mwstatus := ber.EncodeBitString(namedBits_MwStatus.Bytes, ber.UnusedBitCount(namedBits_MwStatus.BitLength))
		if encodeErr_enc_mwstatus != nil {
			return nil, qualifyBERError(encodeErr_enc_mwstatus, "mw-Status", "encoding", false)
		}
		children = append(children, enc_mwstatus...)
	}
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalBER(ber.ChildEncodeOptions(opts, "extensionContainer")...)
		if err != nil {
			return nil, qualifyBERError(err, "extensionContainer", "encoding", false)
		}
		ber.RecordGeneratedBERChildPlacement(opts, len(children), enc_extensioncontainer)
		children = append(children, enc_extensioncontainer...)
	}
	if v.AbsentSubscriberDiagnosticSM != nil {
		if !(int64(*v.AbsentSubscriberDiagnosticSM) >= 0 && int64(*v.AbsentSubscriberDiagnosticSM) <= 255) {
			if constraintErr := checkEncodedValue(opts, s949588_16, "51.4", "absentSubscriberDiagnosticSM", "(0..255)", ber.ObserveInteger(int64(*v.AbsentSubscriberDiagnosticSM))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_absentsubscriberdiagnosticsm := ber.EncodeInteger(int64(*v.AbsentSubscriberDiagnosticSM))
		children = append(children, enc_absentsubscriberdiagnosticsm...)
	}
	if v.AdditionalAbsentSubscriberDiagnosticSM != nil {
		if !(int64(*v.AdditionalAbsentSubscriberDiagnosticSM) >= 0 && int64(*v.AdditionalAbsentSubscriberDiagnosticSM) <= 255) {
			if constraintErr := checkEncodedValue(opts, s949588_16, "51.4", "additionalAbsentSubscriberDiagnosticSM", "(0..255)", ber.ObserveInteger(int64(*v.AdditionalAbsentSubscriberDiagnosticSM))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_additionalabsentsubscriberdiagnosticsm := ber.EncodeInteger(int64(*v.AdditionalAbsentSubscriberDiagnosticSM))
		retagged_enc_additionalabsentsubscriberdiagnosticsm, tagErr_enc_additionalabsentsubscriberdiagnosticsm := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_additionalabsentsubscriberdiagnosticsm)
		if tagErr_enc_additionalabsentsubscriberdiagnosticsm != nil {
			return nil, qualifyBERError(tagErr_enc_additionalabsentsubscriberdiagnosticsm, "additionalAbsentSubscriberDiagnosticSM", "encoding", false)
		}
		enc_additionalabsentsubscriberdiagnosticsm = retagged_enc_additionalabsentsubscriberdiagnosticsm
		children = append(children, enc_additionalabsentsubscriberdiagnosticsm...)
	}
	if v.Smsf3gppAbsentSubscriberDiagnosticSM != nil {
		if !(int64(*v.Smsf3gppAbsentSubscriberDiagnosticSM) >= 0 && int64(*v.Smsf3gppAbsentSubscriberDiagnosticSM) <= 255) {
			if constraintErr := checkEncodedValue(opts, s949588_16, "51.4", "smsf3gppAbsentSubscriberDiagnosticSM", "(0..255)", ber.ObserveInteger(int64(*v.Smsf3gppAbsentSubscriberDiagnosticSM))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_smsf3gppabsentsubscriberdiagnosticsm := ber.EncodeInteger(int64(*v.Smsf3gppAbsentSubscriberDiagnosticSM))
		retagged_enc_smsf3gppabsentsubscriberdiagnosticsm, tagErr_enc_smsf3gppabsentsubscriberdiagnosticsm := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_smsf3gppabsentsubscriberdiagnosticsm)
		if tagErr_enc_smsf3gppabsentsubscriberdiagnosticsm != nil {
			return nil, qualifyBERError(tagErr_enc_smsf3gppabsentsubscriberdiagnosticsm, "smsf3gppAbsentSubscriberDiagnosticSM", "encoding", false)
		}
		enc_smsf3gppabsentsubscriberdiagnosticsm = retagged_enc_smsf3gppabsentsubscriberdiagnosticsm
		children = append(children, enc_smsf3gppabsentsubscriberdiagnosticsm...)
	}
	if v.SmsfNon3gppAbsentSubscriberDiagnosticSM != nil {
		if !(int64(*v.SmsfNon3gppAbsentSubscriberDiagnosticSM) >= 0 && int64(*v.SmsfNon3gppAbsentSubscriberDiagnosticSM) <= 255) {
			if constraintErr := checkEncodedValue(opts, s949588_16, "51.4", "smsfNon3gppAbsentSubscriberDiagnosticSM", "(0..255)", ber.ObserveInteger(int64(*v.SmsfNon3gppAbsentSubscriberDiagnosticSM))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_smsfnon3gppabsentsubscriberdiagnosticsm := ber.EncodeInteger(int64(*v.SmsfNon3gppAbsentSubscriberDiagnosticSM))
		retagged_enc_smsfnon3gppabsentsubscriberdiagnosticsm, tagErr_enc_smsfnon3gppabsentsubscriberdiagnosticsm := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_smsfnon3gppabsentsubscriberdiagnosticsm)
		if tagErr_enc_smsfnon3gppabsentsubscriberdiagnosticsm != nil {
			return nil, qualifyBERError(tagErr_enc_smsfnon3gppabsentsubscriberdiagnosticsm, "smsfNon3gppAbsentSubscriberDiagnosticSM", "encoding", false)
		}
		enc_smsfnon3gppabsentsubscriberdiagnosticsm = retagged_enc_smsfnon3gppabsentsubscriberdiagnosticsm
		children = append(children, enc_smsfnon3gppabsentsubscriberdiagnosticsm...)
	}
	base_ := -1
	for i, ext := range v.ExtData_ {
		if err := checkOpaqueAddition(ext, opts, s949588_16, children, i, &base_); err != nil {
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
		if i == 0 && ((peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0) || (peekTag.Class == tag.ClassUniversal && peekTag.Number == 2) || (peekTag.Class == tag.ClassUniversal && peekTag.Number == 16) || (peekTag.Class == tag.ClassUniversal && peekTag.Number == 3) || (peekTag.Class == tag.ClassUniversal && peekTag.Number == 4)) {
			if constraintErr := ber.CheckEncodedValue(ber.EncodeRule(opts, s949588_16, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
				return nil, constraintErr
			}
		}
		children = append(children, ext...)
	}
	ber.RecordGeneratedBERContainer(opts, children)
	return ber.EncodeSequence(children)
}
func (v *InformServiceCentreArg) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// MarshalDER encodes InformServiceCentreArg to DER format.
// Opaque descendants pass generic DER checks; foreign schema rules need a typed binding.
func (v *InformServiceCentreArg) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: InformServiceCentreArg receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if v.StoredMSISDN != nil {
		if len(*v.StoredMSISDN) < 1 || len(*v.StoredMSISDN) > 9 {
			if constraintErr := checkEncodedLength(nil, s949588_16, "51.5", "storedMSISDN", "SIZE (1..9)", len(*v.StoredMSISDN)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		if len(*v.StoredMSISDN) < 1 || len(*v.StoredMSISDN) > 20 {
			if constraintErr := checkEncodedLength(nil, s949588_16, "51.5", "storedMSISDN", "SIZE (1..20)", len(*v.StoredMSISDN)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_storedmsisdn, encodeErr_enc_storedmsisdn := ber.EncodeOctetString([]byte(*v.StoredMSISDN))
		if encodeErr_enc_storedmsisdn != nil {
			return nil, qualifyBERError(encodeErr_enc_storedmsisdn, "storedMSISDN", "encoding", true)
		}
		children = append(children, enc_storedmsisdn...)
	}
	if v.MwStatus != nil {
		namedBits_MwStatus, namedBitErr_ := normalizeNamedBits(*v.MwStatus, []ber.NamedBitSizeSet{{{Min: 6, Max: 16}}}, nil, "mw-Status", s949588_16)
		if namedBitErr_ != nil {
			return nil, namedBitErr_
		}
		if bitStringErr := ber.ValidateBitStringLength(namedBits_MwStatus.Bytes, namedBits_MwStatus.BitLength); bitStringErr != nil {
			return nil, qualifyBERError(bitStringErr, "mw-Status", "encoding", true)
		}
		// arithmetic pattern BER_BITSTRING_FIELD: 0 <= bit length before modulo and subtraction; gen/codegen.go:750
		if namedBits_MwStatus.BitLength < 0 {
			return nil, fmt.Errorf("negative bit string length")
		}
		if (namedBits_MwStatus).BitLength < 6 || (namedBits_MwStatus).BitLength > 16 {
			if constraintErr := checkEncodedLength(nil, s949588_16, "51.5", "mw-Status", "SIZE (6..16)", namedBitObservedLength(namedBits_MwStatus)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_mwstatus, encodeErr_enc_mwstatus := ber.EncodeDERNamedBitString(namedBits_MwStatus.Bytes, namedBits_MwStatus.BitLength)
		if encodeErr_enc_mwstatus != nil {
			return nil, qualifyBERError(encodeErr_enc_mwstatus, "mw-Status", "encoding", true)
		}
		children = append(children, enc_mwstatus...)
	}
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalDER()
		if err != nil {
			return nil, qualifyBERError(err, "extensionContainer", "encoding", true)
		}
		children = append(children, enc_extensioncontainer...)
	}
	if v.AbsentSubscriberDiagnosticSM != nil {
		if !(int64(*v.AbsentSubscriberDiagnosticSM) >= 0 && int64(*v.AbsentSubscriberDiagnosticSM) <= 255) {
			if constraintErr := checkEncodedValue(nil, s949588_16, "51.4", "absentSubscriberDiagnosticSM", "(0..255)", ber.ObserveInteger(int64(*v.AbsentSubscriberDiagnosticSM))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_absentsubscriberdiagnosticsm := ber.EncodeInteger(int64(*v.AbsentSubscriberDiagnosticSM))
		children = append(children, enc_absentsubscriberdiagnosticsm...)
	}
	if v.AdditionalAbsentSubscriberDiagnosticSM != nil {
		if !(int64(*v.AdditionalAbsentSubscriberDiagnosticSM) >= 0 && int64(*v.AdditionalAbsentSubscriberDiagnosticSM) <= 255) {
			if constraintErr := checkEncodedValue(nil, s949588_16, "51.4", "additionalAbsentSubscriberDiagnosticSM", "(0..255)", ber.ObserveInteger(int64(*v.AdditionalAbsentSubscriberDiagnosticSM))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_additionalabsentsubscriberdiagnosticsm := ber.EncodeInteger(int64(*v.AdditionalAbsentSubscriberDiagnosticSM))
		retagged_enc_additionalabsentsubscriberdiagnosticsm, tagErr_enc_additionalabsentsubscriberdiagnosticsm := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_additionalabsentsubscriberdiagnosticsm)
		if tagErr_enc_additionalabsentsubscriberdiagnosticsm != nil {
			return nil, qualifyBERError(tagErr_enc_additionalabsentsubscriberdiagnosticsm, "additionalAbsentSubscriberDiagnosticSM", "encoding", true)
		}
		enc_additionalabsentsubscriberdiagnosticsm = retagged_enc_additionalabsentsubscriberdiagnosticsm
		children = append(children, enc_additionalabsentsubscriberdiagnosticsm...)
	}
	if v.Smsf3gppAbsentSubscriberDiagnosticSM != nil {
		if !(int64(*v.Smsf3gppAbsentSubscriberDiagnosticSM) >= 0 && int64(*v.Smsf3gppAbsentSubscriberDiagnosticSM) <= 255) {
			if constraintErr := checkEncodedValue(nil, s949588_16, "51.4", "smsf3gppAbsentSubscriberDiagnosticSM", "(0..255)", ber.ObserveInteger(int64(*v.Smsf3gppAbsentSubscriberDiagnosticSM))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_smsf3gppabsentsubscriberdiagnosticsm := ber.EncodeInteger(int64(*v.Smsf3gppAbsentSubscriberDiagnosticSM))
		retagged_enc_smsf3gppabsentsubscriberdiagnosticsm, tagErr_enc_smsf3gppabsentsubscriberdiagnosticsm := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_smsf3gppabsentsubscriberdiagnosticsm)
		if tagErr_enc_smsf3gppabsentsubscriberdiagnosticsm != nil {
			return nil, qualifyBERError(tagErr_enc_smsf3gppabsentsubscriberdiagnosticsm, "smsf3gppAbsentSubscriberDiagnosticSM", "encoding", true)
		}
		enc_smsf3gppabsentsubscriberdiagnosticsm = retagged_enc_smsf3gppabsentsubscriberdiagnosticsm
		children = append(children, enc_smsf3gppabsentsubscriberdiagnosticsm...)
	}
	if v.SmsfNon3gppAbsentSubscriberDiagnosticSM != nil {
		if !(int64(*v.SmsfNon3gppAbsentSubscriberDiagnosticSM) >= 0 && int64(*v.SmsfNon3gppAbsentSubscriberDiagnosticSM) <= 255) {
			if constraintErr := checkEncodedValue(nil, s949588_16, "51.4", "smsfNon3gppAbsentSubscriberDiagnosticSM", "(0..255)", ber.ObserveInteger(int64(*v.SmsfNon3gppAbsentSubscriberDiagnosticSM))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_smsfnon3gppabsentsubscriberdiagnosticsm := ber.EncodeInteger(int64(*v.SmsfNon3gppAbsentSubscriberDiagnosticSM))
		retagged_enc_smsfnon3gppabsentsubscriberdiagnosticsm, tagErr_enc_smsfnon3gppabsentsubscriberdiagnosticsm := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_smsfnon3gppabsentsubscriberdiagnosticsm)
		if tagErr_enc_smsfnon3gppabsentsubscriberdiagnosticsm != nil {
			return nil, qualifyBERError(tagErr_enc_smsfnon3gppabsentsubscriberdiagnosticsm, "smsfNon3gppAbsentSubscriberDiagnosticSM", "encoding", true)
		}
		enc_smsfnon3gppabsentsubscriberdiagnosticsm = retagged_enc_smsfnon3gppabsentsubscriberdiagnosticsm
		children = append(children, enc_smsfnon3gppabsentsubscriberdiagnosticsm...)
	}
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDEREncodedElement(ext); err != nil {
			return nil, invalidDERAddition(ext, s949588_16, children, i)
		}
		peekTag, _, _, extErr := ber.DecodeEncodedTLV(ext)
		if extErr != nil {
			return nil, extErr
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: only the first addition is restricted.
		if i == 0 && ((peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0) || (peekTag.Class == tag.ClassUniversal && peekTag.Number == 2) || (peekTag.Class == tag.ClassUniversal && peekTag.Number == 16) || (peekTag.Class == tag.ClassUniversal && peekTag.Number == 3) || (peekTag.Class == tag.ClassUniversal && peekTag.Number == 4)) {
			if constraintErr := ber.CheckEncodedValue(ber.EncodeRule(nil, s949588_16, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
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
		return nil, fmt.Errorf("%s: %w", "encoding InformServiceCentreArg as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}
func (v *InformServiceCentreArg) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	encoded, err := v.MarshalDER()
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBER decodes InformServiceCentreArg from BER/DER format.
func (destination *InformServiceCentreArg) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if destination == nil {
		return fmt.Errorf("%w: InformServiceCentreArg destination is nil", ber.ErrInvalidValue)
	}
	v := new(InformServiceCentreArg)

	defer publishDecodedValue(destination, v, &returnErr)

	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	preparedData, preparedOptions, prepareErr := prepareCompositeBER(data, opts, s949588_16, "child", (*InformServiceCentreArg).UnmarshalBER)
	if prepareErr != nil {
		return prepareErr
	}
	data, opts = preparedData, preparedOptions

	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
	*v = InformServiceCentreArg{}
	defer func() {
		if returnErr == nil {
			returnErr = completeValueBER(data,
				opts, v, &v.berReplayNode_, (*InformServiceCentreArg).MarshalBER)
		}

	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("%s: %w", "decoding InformServiceCentreArg SEQUENCE", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "InformServiceCentreArg", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode storedMSISDN
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassUniversal && peekTag.Number == 4 {
				ber.MarkPreflightTarget(opts, "storedMSISDN", content[offset:])
				val_storedmsisdn, n, err := ber.DecodeOctetString(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "storedMSISDN", "decoding", false)
				}
				tmp_storedmsisdn := ISDNAddressString(val_storedmsisdn)
				v.StoredMSISDN = &tmp_storedmsisdn
				if offset > len(content) || n < 0 || n > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n
				if len(*v.StoredMSISDN) < 1 || len(*v.StoredMSISDN) > 9 {
					if constraintErr := checkDecodedLength(opts, s949588_16, "51.5", "storedMSISDN", "SIZE (1..9)", len(*v.StoredMSISDN)); constraintErr != nil {
						return constraintErr
					}
				}
				if len(*v.StoredMSISDN) < 1 || len(*v.StoredMSISDN) > 20 {
					if constraintErr := checkDecodedLength(opts, s949588_16, "51.5", "storedMSISDN", "SIZE (1..20)", len(*v.StoredMSISDN)); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode mw-Status
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassUniversal && peekTag.Number == 3 {
				ber.MarkPreflightTarget(opts, "mw-Status", content[offset:])
				bsBytes_mwstatus, bsUnused_mwstatus, n, err := ber.DecodeBitString(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "mw-Status", "decoding", false)
				}
				bsBitLength_mwstatus, bsLenErr_mwstatus := ber.BitStringBitLength(len(bsBytes_mwstatus), bsUnused_mwstatus)
				if bsLenErr_mwstatus != nil {
					return qualifyBERError(bsLenErr_mwstatus, "mw-Status", "decoding", false)
				}
				tmp_mwstatus := runtime.BitString{Bytes: bsBytes_mwstatus, BitLength: bsBitLength_mwstatus}
				v.MwStatus = &tmp_mwstatus
				if offset < 0 || offset >
					len(content) || n < 0 || n > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n
				*v.MwStatus = ber.NormalizeNamedBitStringSize(*v.MwStatus, []ber.NamedBitSizeSet{{{Min: 6, Max: 16}}}, opts...)
				if (*v.MwStatus).BitLength < 6 || (*v.MwStatus).BitLength > 16 {
					if constraintErr := checkDecodedLength(opts, s949588_16, "51.5", "mw-Status", "SIZE (6..16)", (*v.MwStatus).BitLength); constraintErr != nil {
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
	// Decode absentSubscriberDiagnosticSM
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassUniversal && peekTag.Number == 2 {
				ber.MarkPreflightTarget(opts, "absentSubscriberDiagnosticSM", content[offset:])
				val_absentsubscriberdiagnosticsm, n, err := ber.DecodeInteger(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "absentSubscriberDiagnosticSM", "decoding", false)
				}
				tmp_absentsubscriberdiagnosticsm := AbsentSubscriberDiagnosticSM(val_absentsubscriberdiagnosticsm)
				v.AbsentSubscriberDiagnosticSM = &tmp_absentsubscriberdiagnosticsm
				if offset < 0 || offset >
					len(content) || n < 0 || n > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n
				if !(int64(*v.AbsentSubscriberDiagnosticSM) >= 0 && int64(*v.AbsentSubscriberDiagnosticSM) <= 255) {
					if constraintErr := checkDecodedValue(opts, s949588_16, "51.4", "absentSubscriberDiagnosticSM", "(0..255)", ber.ObserveInteger(int64(*v.AbsentSubscriberDiagnosticSM))); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode additionalAbsentSubscriberDiagnosticSM
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
				ber.MarkPreflightTarget(opts, "additionalAbsentSubscriberDiagnosticSM", content[offset:])
				decodedTag_additionalabsentsubscriberdiagnosticsm, n_additionalabsentsubscriberdiagnosticsm, rawVal_additionalabsentsubscriberdiagnosticsm, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "additionalAbsentSubscriberDiagnosticSM", "decoding", false)
				}
				if decodedTag_additionalabsentsubscriberdiagnosticsm.Class != tag.ClassContextSpecific || decodedTag_additionalabsentsubscriberdiagnosticsm.Number != 0 || decodedTag_additionalabsentsubscriberdiagnosticsm.Constructed != false {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_additionalabsentsubscriberdiagnosticsm), "additionalAbsentSubscriberDiagnosticSM", "decoding", false)
				}
				decVal_additionalabsentsubscriberdiagnosticsm, intErr := ber.DecodeIntegerValue(rawVal_additionalabsentsubscriberdiagnosticsm)
				if intErr != nil {
					return qualifyBERError(intErr, "additionalAbsentSubscriberDiagnosticSM", "decoding", false)
				}
				tmp_additionalabsentsubscriberdiagnosticsm := AbsentSubscriberDiagnosticSM(decVal_additionalabsentsubscriberdiagnosticsm)
				v.AdditionalAbsentSubscriberDiagnosticSM = &tmp_additionalabsentsubscriberdiagnosticsm
				if offset < 0 || offset >
					len(content) || n_additionalabsentsubscriberdiagnosticsm < 0 ||
					n_additionalabsentsubscriberdiagnosticsm > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_additionalabsentsubscriberdiagnosticsm
				if !(int64(*v.AdditionalAbsentSubscriberDiagnosticSM) >= 0 && int64(*v.AdditionalAbsentSubscriberDiagnosticSM) <= 255) {
					if constraintErr := checkDecodedValue(opts, s949588_16, "51.4", "additionalAbsentSubscriberDiagnosticSM", "(0..255)", ber.ObserveInteger(int64(*v.AdditionalAbsentSubscriberDiagnosticSM))); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode smsf3gppAbsentSubscriberDiagnosticSM
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
				ber.MarkPreflightTarget(opts, "smsf3gppAbsentSubscriberDiagnosticSM", content[offset:])
				decodedTag_smsf3gppabsentsubscriberdiagnosticsm, n_smsf3gppabsentsubscriberdiagnosticsm, rawVal_smsf3gppabsentsubscriberdiagnosticsm, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "smsf3gppAbsentSubscriberDiagnosticSM", "decoding", false)
				}
				if decodedTag_smsf3gppabsentsubscriberdiagnosticsm.Class != tag.ClassContextSpecific || decodedTag_smsf3gppabsentsubscriberdiagnosticsm.Number != 1 || decodedTag_smsf3gppabsentsubscriberdiagnosticsm.Constructed != false {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_smsf3gppabsentsubscriberdiagnosticsm), "smsf3gppAbsentSubscriberDiagnosticSM", "decoding", false)
				}
				decVal_smsf3gppabsentsubscriberdiagnosticsm, intErr := ber.DecodeIntegerValue(rawVal_smsf3gppabsentsubscriberdiagnosticsm)
				if intErr != nil {
					return qualifyBERError(intErr, "smsf3gppAbsentSubscriberDiagnosticSM", "decoding", false)
				}
				tmp_smsf3gppabsentsubscriberdiagnosticsm := AbsentSubscriberDiagnosticSM(decVal_smsf3gppabsentsubscriberdiagnosticsm)
				v.Smsf3gppAbsentSubscriberDiagnosticSM = &tmp_smsf3gppabsentsubscriberdiagnosticsm
				if offset < 0 || offset >
					len(content) || n_smsf3gppabsentsubscriberdiagnosticsm < 0 || n_smsf3gppabsentsubscriberdiagnosticsm >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_smsf3gppabsentsubscriberdiagnosticsm
				if !(int64(*v.Smsf3gppAbsentSubscriberDiagnosticSM) >= 0 && int64(*v.Smsf3gppAbsentSubscriberDiagnosticSM) <= 255) {
					if constraintErr := checkDecodedValue(opts, s949588_16, "51.4", "smsf3gppAbsentSubscriberDiagnosticSM", "(0..255)", ber.ObserveInteger(int64(*v.Smsf3gppAbsentSubscriberDiagnosticSM))); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode smsfNon3gppAbsentSubscriberDiagnosticSM
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2 {
				ber.MarkPreflightTarget(opts, "smsfNon3gppAbsentSubscriberDiagnosticSM", content[offset:])
				decodedTag_smsfnon3gppabsentsubscriberdiagnosticsm, n_smsfnon3gppabsentsubscriberdiagnosticsm, rawVal_smsfnon3gppabsentsubscriberdiagnosticsm, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "smsfNon3gppAbsentSubscriberDiagnosticSM", "decoding", false)
				}
				if decodedTag_smsfnon3gppabsentsubscriberdiagnosticsm.Class != tag.ClassContextSpecific || decodedTag_smsfnon3gppabsentsubscriberdiagnosticsm.Number != 2 || decodedTag_smsfnon3gppabsentsubscriberdiagnosticsm.Constructed != false {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_smsfnon3gppabsentsubscriberdiagnosticsm), "smsfNon3gppAbsentSubscriberDiagnosticSM", "decoding", false)
				}
				decVal_smsfnon3gppabsentsubscriberdiagnosticsm, intErr := ber.DecodeIntegerValue(rawVal_smsfnon3gppabsentsubscriberdiagnosticsm)
				if intErr != nil {
					return qualifyBERError(intErr, "smsfNon3gppAbsentSubscriberDiagnosticSM", "decoding", false)
				}
				tmp_smsfnon3gppabsentsubscriberdiagnosticsm := AbsentSubscriberDiagnosticSM(decVal_smsfnon3gppabsentsubscriberdiagnosticsm)
				v.SmsfNon3gppAbsentSubscriberDiagnosticSM = &tmp_smsfnon3gppabsentsubscriberdiagnosticsm
				if offset < 0 || offset >
					len(content) || n_smsfnon3gppabsentsubscriberdiagnosticsm < 0 ||
					n_smsfnon3gppabsentsubscriberdiagnosticsm > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_smsfnon3gppabsentsubscriberdiagnosticsm
				if !(int64(*v.SmsfNon3gppAbsentSubscriberDiagnosticSM) >= 0 && int64(*v.SmsfNon3gppAbsentSubscriberDiagnosticSM) <= 255) {
					if constraintErr := checkDecodedValue(opts, s949588_16, "51.4", "smsfNon3gppAbsentSubscriberDiagnosticSM", "(0..255)", ber.ObserveInteger(int64(*v.SmsfNon3gppAbsentSubscriberDiagnosticSM))); constraintErr != nil {
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
			return &ber.DecodeError{Offset: offset, TypeName: "InformServiceCentreArg", Cause: extErr_}
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: the first unknown addition must differ from trailing OPTIONAL/DEFAULT tags.
		if len(v.ExtData_) == 0 && ((peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0) || (peekTag.Class == tag.ClassUniversal && peekTag.Number == 2) || (peekTag.Class == tag.ClassUniversal && peekTag.Number == 16) || (peekTag.Class == tag.ClassUniversal && peekTag.Number == 3) || (peekTag.Class == tag.ClassUniversal && peekTag.Number == 4)) {
			if !ber.ToleranceEnabled(opts) {
				return &ber.DecodeError{Offset: offset, TypeName: "InformServiceCentreArg", Cause: fmt.Errorf("%w: repeated or out-of-order SEQUENCE component tag %s", ber.ErrInvalidTag, peekTag)}
			}
			if orderErr_ := ber.CheckDecodedValue(ber.DecodeRule(opts, s949588_16, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), fmt.Sprintf("ExtData_[%d]", len(v.ExtData_)), "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); orderErr_ != nil {
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

// MarshalBER encodes ReadyForSMArg to BER format.
func (v *ReadyForSMArg) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {

	if v == nil {
		return nil, fmt.Errorf("%w: ReadyForSMArg receiver is nil", ber.ErrInvalidValue)
	}
	return marshalFramedValue(v, v.berReplayNode_, opts, (*ReadyForSMArg).MarshalBER, (*ReadyForSMArg).marshalBER, 3)

}
func (v *ReadyForSMArg) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if len(v.Imsi) < 3 || len(v.Imsi) > 8 {
		if constraintErr := checkEncodedLength(opts, s949588_17, "51.5", "imsi", "SIZE (3..8)", len(v.Imsi)); constraintErr != nil {
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
	if int64(v.AlertReason) != 0 && int64(v.AlertReason) != 1 {
		if constraintErr := checkEncodedValue(opts, s949588_17, "20", "alertReason", "ENUMERATED {0, 1}", ber.ObserveInteger(int64(v.AlertReason))); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_alertreason := ber.EncodeEnumerated(int64(v.AlertReason))
	children = append(children, enc_alertreason...)
	if v.AlertReasonIndicator != nil {
		enc_alertreasonindicator := ber.EncodeNull()
		children = append(children, enc_alertreasonindicator...)
	}
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalBER(ber.ChildEncodeOptions(opts, "extensionContainer")...)
		if err != nil {
			return nil, qualifyBERError(err, "extensionContainer", "encoding", false)
		}
		ber.RecordGeneratedBERChildPlacement(opts, len(children), enc_extensioncontainer)
		children = append(children, enc_extensioncontainer...)
	}
	if v.AdditionalAlertReasonIndicator != nil {
		enc_additionalalertreasonindicator := ber.EncodeNull()
		retagged_enc_additionalalertreasonindicator, tagErr_enc_additionalalertreasonindicator := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_additionalalertreasonindicator)
		if tagErr_enc_additionalalertreasonindicator != nil {
			return nil, qualifyBERError(tagErr_enc_additionalalertreasonindicator, "additionalAlertReasonIndicator", "encoding", false)
		}
		enc_additionalalertreasonindicator = retagged_enc_additionalalertreasonindicator
		children = append(children, enc_additionalalertreasonindicator...)
	}
	if v.MaximumUeAvailabilityTime != nil {
		if len(*v.MaximumUeAvailabilityTime) < 4 || len(*v.MaximumUeAvailabilityTime) > 4 {
			if constraintErr := checkEncodedLength(opts, s949588_17, "51.5", "maximumUeAvailabilityTime", "SIZE (4)", len(*v.MaximumUeAvailabilityTime)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_maximumueavailabilitytime, encodeErr_enc_maximumueavailabilitytime := ber.EncodeOctetString([]byte(*v.MaximumUeAvailabilityTime))
		if encodeErr_enc_maximumueavailabilitytime != nil {
			return nil, qualifyBERError(encodeErr_enc_maximumueavailabilitytime, "maximumUeAvailabilityTime", "encoding", false)
		}
		children = append(children, enc_maximumueavailabilitytime...)
	}
	base_ := -1
	for i, ext := range v.ExtData_ {
		if err := checkOpaqueAddition(ext, opts, s949588_17, children, i, &base_); err != nil {
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
		if i == 0 && ((peekTag.Class == tag.ClassUniversal && peekTag.Number == 4) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1) || (peekTag.Class == tag.ClassUniversal && peekTag.Number == 16) || (peekTag.Class == tag.ClassUniversal && peekTag.Number == 5)) {
			if constraintErr := ber.CheckEncodedValue(ber.EncodeRule(opts, s949588_17, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
				return nil, constraintErr
			}
		}
		children = append(children, ext...)
	}
	ber.RecordGeneratedBERContainer(opts, children)
	return ber.EncodeSequence(children)
}
func (v *ReadyForSMArg) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// MarshalDER encodes ReadyForSMArg to DER format.
// Opaque descendants pass generic DER checks; foreign schema rules need a typed binding.
func (v *ReadyForSMArg) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: ReadyForSMArg receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if len(v.Imsi) < 3 || len(v.Imsi) > 8 {
		if constraintErr := checkEncodedLength(nil, s949588_17, "51.5", "imsi", "SIZE (3..8)", len(v.Imsi)); constraintErr != nil {
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
	if int64(v.AlertReason) != 0 && int64(v.AlertReason) != 1 {
		if constraintErr := checkEncodedValue(nil, s949588_17, "20", "alertReason", "ENUMERATED {0, 1}", ber.ObserveInteger(int64(v.AlertReason))); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_alertreason := ber.EncodeEnumerated(int64(v.AlertReason))
	children = append(children, enc_alertreason...)
	if v.AlertReasonIndicator != nil {
		enc_alertreasonindicator := ber.EncodeNull()
		children = append(children, enc_alertreasonindicator...)
	}
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalDER()
		if err != nil {
			return nil, qualifyBERError(err, "extensionContainer", "encoding", true)
		}
		children = append(children, enc_extensioncontainer...)
	}
	if v.AdditionalAlertReasonIndicator != nil {
		enc_additionalalertreasonindicator := ber.EncodeNull()
		retagged_enc_additionalalertreasonindicator, tagErr_enc_additionalalertreasonindicator := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_additionalalertreasonindicator)
		if tagErr_enc_additionalalertreasonindicator != nil {
			return nil, qualifyBERError(tagErr_enc_additionalalertreasonindicator, "additionalAlertReasonIndicator", "encoding", true)
		}
		enc_additionalalertreasonindicator = retagged_enc_additionalalertreasonindicator
		children = append(children, enc_additionalalertreasonindicator...)
	}
	if v.MaximumUeAvailabilityTime != nil {
		if len(*v.MaximumUeAvailabilityTime) < 4 || len(*v.MaximumUeAvailabilityTime) > 4 {
			if constraintErr := checkEncodedLength(nil, s949588_17, "51.5", "maximumUeAvailabilityTime", "SIZE (4)", len(*v.MaximumUeAvailabilityTime)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_maximumueavailabilitytime, encodeErr_enc_maximumueavailabilitytime := ber.EncodeOctetString([]byte(*v.MaximumUeAvailabilityTime))
		if encodeErr_enc_maximumueavailabilitytime != nil {
			return nil, qualifyBERError(encodeErr_enc_maximumueavailabilitytime, "maximumUeAvailabilityTime", "encoding", true)
		}
		children = append(children, enc_maximumueavailabilitytime...)
	}
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDEREncodedElement(ext); err != nil {
			return nil, invalidDERAddition(ext, s949588_17, children, i)
		}
		peekTag, _, _, extErr := ber.DecodeEncodedTLV(ext)
		if extErr != nil {
			return nil, extErr
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: only the first addition is restricted.
		if i == 0 && ((peekTag.Class == tag.ClassUniversal && peekTag.Number == 4) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1) || (peekTag.Class == tag.ClassUniversal && peekTag.Number == 16) || (peekTag.Class == tag.ClassUniversal && peekTag.Number == 5)) {
			if constraintErr := ber.CheckEncodedValue(ber.EncodeRule(nil, s949588_17, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
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
		return nil, fmt.Errorf("%s: %w", "encoding ReadyForSMArg as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}
func (v *ReadyForSMArg) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	encoded, err := v.MarshalDER()
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBER decodes ReadyForSMArg from BER/DER format.
func (destination *ReadyForSMArg) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if destination == nil {
		return fmt.Errorf("%w: ReadyForSMArg destination is nil", ber.ErrInvalidValue)
	}
	v := new(ReadyForSMArg)
	defer publishDecodedValue(destination, v, &returnErr)

	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	preparedData, preparedOptions, prepareErr := prepareCompositeBER(data, opts, s949588_17, "child", (*ReadyForSMArg).UnmarshalBER)
	if prepareErr != nil {
		return prepareErr
	}
	data, opts = preparedData, preparedOptions

	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
	*v = ReadyForSMArg{}
	defer func() {
		if returnErr == nil {
			returnErr = completeValueBER(data,
				opts, v, &v.berReplayNode_, (*ReadyForSMArg).MarshalBER)
		}

	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("%s: %w", "decoding ReadyForSMArg SEQUENCE", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "ReadyForSMArg", Cause: ber.ErrExtraData}
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
			if constraintErr := checkDecodedLength(opts, s949588_17, "51.5", "imsi", "SIZE (3..8)", len(v.Imsi)); constraintErr != nil {
				return constraintErr
			}
		}
	}
	// Decode alertReason
	if offset >= len(content) {
		return fmt.Errorf("missing required field alertReason")
	}
	{
		ber.MarkPreflightTarget(opts, "alertReason", content[offset:])
		val_alertreason, n, err := ber.DecodeEnumerated(content[offset:], opts...)
		if err != nil {
			return qualifyBERError(err, "alertReason", "decoding", false)
		}
		v.AlertReason = AlertReason(val_alertreason)
		if offset < 0 || offset >
			len(content) || n < 0 || n > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n
		if int64(v.AlertReason) != 0 && int64(v.AlertReason) != 1 {
			if constraintErr := checkDecodedValue(opts, s949588_17, "20", "alertReason", "ENUMERATED {0, 1}", ber.ObserveInteger(int64(v.AlertReason))); constraintErr != nil {
				return constraintErr
			}
		}
	}
	// Decode alertReasonIndicator
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassUniversal && peekTag.Number == 5 {
				ber.MarkPreflightTarget(opts, "alertReasonIndicator", content[offset:])
				n, err := ber.DecodeNull(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "alertReasonIndicator", "decoding", false)
				}
				v.AlertReasonIndicator = &struct{}{}
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
	// Decode additionalAlertReasonIndicator
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
				ber.MarkPreflightTarget(opts, "additionalAlertReasonIndicator", content[offset:])
				decodedTag_additionalalertreasonindicator, n_additionalalertreasonindicator, rawVal_additionalalertreasonindicator, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "additionalAlertReasonIndicator", "decoding", false)
				}
				if decodedTag_additionalalertreasonindicator.Class != tag.ClassContextSpecific || decodedTag_additionalalertreasonindicator.Number != 1 || decodedTag_additionalalertreasonindicator.Constructed != false {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_additionalalertreasonindicator), "additionalAlertReasonIndicator", "decoding", false)
				}
				if len(rawVal_additionalalertreasonindicator) != 0 {
					return qualifyBERError(fmt.Errorf("%w: NULL content length %d", ber.ErrInvalidValue, len(rawVal_additionalalertreasonindicator)), "additionalAlertReasonIndicator", "decoding", false)
				}
				v.AdditionalAlertReasonIndicator = &struct{}{}
				if offset < 0 || offset >
					len(content) || n_additionalalertreasonindicator < 0 ||
					n_additionalalertreasonindicator > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_additionalalertreasonindicator
			}
		}
	}
	// Decode maximumUeAvailabilityTime
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassUniversal && peekTag.Number == 4 {
				ber.MarkPreflightTarget(opts, "maximumUeAvailabilityTime", content[offset:])
				val_maximumueavailabilitytime, n, err := ber.DecodeOctetString(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "maximumUeAvailabilityTime", "decoding", false)
				}
				tmp_maximumueavailabilitytime := Time(val_maximumueavailabilitytime)
				v.MaximumUeAvailabilityTime = &tmp_maximumueavailabilitytime
				if offset < 0 || offset >
					len(content) || n < 0 || n > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n
				if len(*v.MaximumUeAvailabilityTime) < 4 || len(*v.MaximumUeAvailabilityTime) > 4 {
					if constraintErr := checkDecodedLength(opts, s949588_17, "51.5", "maximumUeAvailabilityTime", "SIZE (4)", len(*v.MaximumUeAvailabilityTime)); constraintErr != nil {
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
			return &ber.DecodeError{Offset: offset, TypeName: "ReadyForSMArg", Cause: extErr_}
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: the first unknown addition must differ from trailing OPTIONAL/DEFAULT tags.
		if len(v.ExtData_) == 0 && ((peekTag.Class == tag.ClassUniversal && peekTag.Number == 4) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1) || (peekTag.Class == tag.ClassUniversal && peekTag.Number == 16) || (peekTag.Class == tag.ClassUniversal && peekTag.Number == 5)) {
			if !ber.ToleranceEnabled(opts) {
				return &ber.DecodeError{Offset: offset, TypeName: "ReadyForSMArg", Cause: fmt.Errorf("%w: repeated or out-of-order SEQUENCE component tag %s", ber.ErrInvalidTag, peekTag)}
			}
			if orderErr_ := ber.CheckDecodedValue(ber.DecodeRule(opts, s949588_17, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), fmt.Sprintf("ExtData_[%d]", len(v.ExtData_)), "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); orderErr_ != nil {
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

// MarshalBER encodes ReadyForSMRes to BER format.
func (v *ReadyForSMRes) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {

	if v == nil {
		return nil, fmt.Errorf("%w: ReadyForSMRes receiver is nil", ber.ErrInvalidValue)
	}
	return marshalFramedValue(v, v.berReplayNode_, opts, (*ReadyForSMRes).MarshalBER, (*ReadyForSMRes).marshalBER, 3)

}
func (v *ReadyForSMRes) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
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
		if err := checkOpaqueAddition(ext, opts, s949588_18, children, i, &base_); err != nil {
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
			if constraintErr := ber.CheckEncodedValue(ber.EncodeRule(opts, s949588_18, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
				return nil, constraintErr
			}
		}
		children = append(children, ext...)
	}
	ber.RecordGeneratedBERContainer(opts, children)
	return ber.EncodeSequence(children)
}
func (v *ReadyForSMRes) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// MarshalDER encodes ReadyForSMRes to DER format.
// Opaque descendants pass generic DER checks; foreign schema rules need a typed binding.
func (v *ReadyForSMRes) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: ReadyForSMRes receiver is nil", ber.ErrInvalidValue)
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
			return nil, invalidDERAddition(ext, s949588_18, children, i)
		}
		peekTag, _, _, extErr := ber.DecodeEncodedTLV(ext)
		if extErr != nil {
			return nil, extErr
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: only the first addition is restricted.
		if i == 0 && (peekTag.Class == tag.ClassUniversal && peekTag.Number == 16) {
			if constraintErr := ber.CheckEncodedValue(ber.EncodeRule(nil, s949588_18, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
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
		return nil, fmt.Errorf("%s: %w", "encoding ReadyForSMRes as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}
func (v *ReadyForSMRes) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	encoded, err := v.MarshalDER()
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBER decodes ReadyForSMRes from BER/DER format.
func (destination *ReadyForSMRes) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if destination == nil {
		return fmt.Errorf("%w: ReadyForSMRes destination is nil", ber.ErrInvalidValue)
	}
	v := new(ReadyForSMRes)
	defer publishDecodedValue(destination, v, &returnErr)

	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	preparedData, preparedOptions, prepareErr := prepareCompositeBER(data, opts, s949588_18, "child", (*ReadyForSMRes).UnmarshalBER)
	if prepareErr != nil {
		return prepareErr
	}
	data, opts = preparedData, preparedOptions

	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
	*v = ReadyForSMRes{}
	defer func() {
		if returnErr == nil {
			returnErr = completeValueBER(data,
				opts, v, &v.berReplayNode_, (*ReadyForSMRes).MarshalBER)
		}

	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("%s: %w", "decoding ReadyForSMRes SEQUENCE", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "ReadyForSMRes", Cause: ber.ErrExtraData}
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
			return &ber.DecodeError{Offset: offset, TypeName: "ReadyForSMRes", Cause: extErr_}
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: the first unknown addition must differ from trailing OPTIONAL/DEFAULT tags.
		if len(v.ExtData_) == 0 && (peekTag.Class == tag.ClassUniversal && peekTag.Number == 16) {
			if !ber.ToleranceEnabled(opts) {
				return &ber.DecodeError{Offset: offset, TypeName: "ReadyForSMRes", Cause: fmt.Errorf("%w: repeated or out-of-order SEQUENCE component tag %s", ber.ErrInvalidTag, peekTag)}
			}
			if orderErr_ := ber.CheckDecodedValue(ber.DecodeRule(opts, s949588_18, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), fmt.Sprintf("ExtData_[%d]", len(v.ExtData_)), "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); orderErr_ != nil {
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

// MarshalBER encodes MTForwardSMVGCSArg to BER format.
func (v *MTForwardSMVGCSArg) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {

	if v == nil {
		return nil, fmt.Errorf("%w: MTForwardSMVGCSArg receiver is nil", ber.ErrInvalidValue)
	}
	return marshalFramedValue(v, v.berReplayNode_, opts, (*MTForwardSMVGCSArg).MarshalBER, (*MTForwardSMVGCSArg).marshalBER, 3)

}
func (v *MTForwardSMVGCSArg) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if len(v.AsciCallReference) < 1 || len(v.AsciCallReference) > 8 {
		if constraintErr := checkEncodedLength(opts, s949588_19, "51.5", "asciCallReference", "SIZE (1..8)", len(v.AsciCallReference)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_ascicallreference, encodeErr_enc_ascicallreference := ber.EncodeOctetString([]byte(v.AsciCallReference))
	if encodeErr_enc_ascicallreference != nil {
		return nil, qualifyBERError(encodeErr_enc_ascicallreference, "asciCallReference", "encoding", false)
	}
	children = append(children, enc_ascicallreference...)
	enc_smrpoa, err := v.SmRPOA.MarshalBER(ber.ChildEncodeOptions(opts, "sm-RP-OA")...)
	if err != nil {
		return nil, qualifyBERError(err, "sm-RP-OA", "encoding", false)
	}
	ber.RecordGeneratedBERChildPlacement(opts, len(children), enc_smrpoa)
	children = append(children, enc_smrpoa...)
	if len(v.SmRPUI) < 1 || len(v.SmRPUI) > 200 {
		if constraintErr := checkEncodedLength(opts, s949588_19, "51.5", "sm-RP-UI", "SIZE (1..200)", len(v.SmRPUI)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_smrpui, encodeErr_enc_smrpui := ber.EncodeOctetString([]byte(v.SmRPUI))
	if encodeErr_enc_smrpui != nil {
		return nil, qualifyBERError(encodeErr_enc_smrpui, "sm-RP-UI", "encoding", false)
	}
	children = append(children, enc_smrpui...)
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
		if err := checkOpaqueAddition(ext, opts, s949588_19, children, i, &base_); err != nil {
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
			if constraintErr := ber.CheckEncodedValue(ber.EncodeRule(opts, s949588_19, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
				return nil, constraintErr
			}
		}
		children = append(children, ext...)
	}
	ber.RecordGeneratedBERContainer(opts, children)
	return ber.EncodeSequence(children)
}
func (v *MTForwardSMVGCSArg) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// MarshalDER encodes MTForwardSMVGCSArg to DER format.
// Opaque descendants pass generic DER checks; foreign schema rules need a typed binding.
func (v *MTForwardSMVGCSArg) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: MTForwardSMVGCSArg receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if len(v.AsciCallReference) < 1 || len(v.AsciCallReference) > 8 {
		if constraintErr := checkEncodedLength(nil, s949588_19, "51.5", "asciCallReference", "SIZE (1..8)", len(v.AsciCallReference)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_ascicallreference, encodeErr_enc_ascicallreference := ber.EncodeOctetString([]byte(v.AsciCallReference))
	if encodeErr_enc_ascicallreference != nil {
		return nil, qualifyBERError(encodeErr_enc_ascicallreference, "asciCallReference", "encoding", true)
	}
	children = append(children, enc_ascicallreference...)
	enc_smrpoa, err := v.SmRPOA.MarshalDER()
	if err != nil {
		return nil, qualifyBERError(err, "sm-RP-OA", "encoding", true)
	}
	children = append(children, enc_smrpoa...)
	if len(v.SmRPUI) < 1 || len(v.SmRPUI) > 200 {
		if constraintErr := checkEncodedLength(nil, s949588_19, "51.5", "sm-RP-UI", "SIZE (1..200)", len(v.SmRPUI)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_smrpui, encodeErr_enc_smrpui := ber.EncodeOctetString([]byte(v.SmRPUI))
	if encodeErr_enc_smrpui != nil {
		return nil, qualifyBERError(encodeErr_enc_smrpui, "sm-RP-UI", "encoding", true)
	}
	children = append(children, enc_smrpui...)
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalDER()
		if err != nil {
			return nil, qualifyBERError(err, "extensionContainer", "encoding", true)
		}
		children = append(children, enc_extensioncontainer...)
	}
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDEREncodedElement(ext); err != nil {
			return nil, invalidDERAddition(ext, s949588_19, children, i)
		}
		peekTag, _, _, extErr := ber.DecodeEncodedTLV(ext)
		if extErr != nil {
			return nil, extErr
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: only the first addition is restricted.
		if i == 0 && (peekTag.Class == tag.ClassUniversal && peekTag.Number == 16) {
			if constraintErr := ber.CheckEncodedValue(ber.EncodeRule(nil, s949588_19, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
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
		return nil, fmt.Errorf("%s: %w", "encoding MTForwardSMVGCSArg as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}
func (v *MTForwardSMVGCSArg) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	encoded, err := v.MarshalDER()
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBER decodes MTForwardSMVGCSArg from BER/DER format.
func (destination *MTForwardSMVGCSArg) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if destination == nil {
		return fmt.Errorf("%w: MTForwardSMVGCSArg destination is nil", ber.ErrInvalidValue)
	}
	v := new(MTForwardSMVGCSArg)

	defer publishDecodedValue(destination, v, &returnErr)

	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	preparedData, preparedOptions, prepareErr := prepareCompositeBER(data, opts, s949588_19, "child", (*MTForwardSMVGCSArg).UnmarshalBER)
	if prepareErr != nil {
		return prepareErr
	}
	data, opts = preparedData, preparedOptions

	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
	*v = MTForwardSMVGCSArg{}
	defer func() {
		if returnErr == nil {
			returnErr = completeValueBER(data,
				opts, v, &v.berReplayNode_, (*MTForwardSMVGCSArg).MarshalBER)
		}

	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("%s: %w", "decoding MTForwardSMVGCSArg SEQUENCE", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "MTForwardSMVGCSArg", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode asciCallReference
	if offset >= len(content) {
		return fmt.Errorf("missing required field asciCallReference")
	}
	{
		ber.MarkPreflightTarget(opts, "asciCallReference", content[offset:])
		val_ascicallreference, n, err := ber.DecodeOctetString(content[offset:], opts...)
		if err != nil {
			return qualifyBERError(err, "asciCallReference", "decoding", false)
		}
		v.AsciCallReference = ASCICallReference(val_ascicallreference)
		if offset > len(content) || n < 0 || n > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n
		if len(v.AsciCallReference) < 1 || len(v.AsciCallReference) > 8 {
			if constraintErr := checkDecodedLength(opts, s949588_19, "51.5", "asciCallReference", "SIZE (1..8)", len(v.AsciCallReference)); constraintErr != nil {
				return constraintErr
			}
		}
	}
	// Decode sm-RP-OA
	if offset >= len(content) {
		return fmt.Errorf("missing required field sm-RP-OA")
	}
	{
		ber.MarkPreflightTarget(opts, "sm-RP-OA", content[offset:])
		// Decode nested CHOICE (SMRPOA)
		_, n_smrpoa, _, tlvErr_smrpoa := ber.DecodeTLV(content[offset:], opts...)
		if tlvErr_smrpoa != nil {
			return qualifyBERError(tlvErr_smrpoa, "sm-RP-OA", "decoding", false)
		}
		if offset < 0 || offset >
			len(content) || n_smrpoa < 0 || n_smrpoa > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		if unmErr := v.SmRPOA.UnmarshalBER(content[offset:offset+n_smrpoa], ber.ChildDecodeOptions(opts, "sm-RP-OA")...); unmErr != nil {
			return qualifyBERError(unmErr, "sm-RP-OA", "decoding", false)
		}
		if offset < 0 || offset >
			len(content) || n_smrpoa < 0 || n_smrpoa > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n_smrpoa
	}
	// Decode sm-RP-UI
	if offset >= len(content) {
		return fmt.Errorf("missing required field sm-RP-UI")
	}
	{
		ber.MarkPreflightTarget(opts, "sm-RP-UI", content[offset:])
		val_smrpui, n, err := ber.DecodeOctetString(content[offset:], opts...)
		if err != nil {
			return qualifyBERError(err, "sm-RP-UI", "decoding", false)
		}
		v.SmRPUI = SignalInfo(val_smrpui)
		if offset < 0 || offset >
			len(content) || n < 0 || n > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n
		if len(v.SmRPUI) < 1 || len(v.SmRPUI) > 200 {
			if constraintErr := checkDecodedLength(opts, s949588_19, "51.5", "sm-RP-UI", "SIZE (1..200)", len(v.SmRPUI)); constraintErr != nil {
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
			return &ber.DecodeError{Offset: offset, TypeName: "MTForwardSMVGCSArg", Cause: extErr_}
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: the first unknown addition must differ from trailing OPTIONAL/DEFAULT tags.
		if len(v.ExtData_) == 0 && (peekTag.Class == tag.ClassUniversal && peekTag.Number == 16) {
			if !ber.ToleranceEnabled(opts) {
				return &ber.DecodeError{Offset: offset, TypeName: "MTForwardSMVGCSArg", Cause: fmt.Errorf("%w: repeated or out-of-order SEQUENCE component tag %s", ber.ErrInvalidTag, peekTag)}
			}
			if orderErr_ := ber.CheckDecodedValue(ber.DecodeRule(opts, s949588_19, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), fmt.Sprintf("ExtData_[%d]", len(v.ExtData_)), "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); orderErr_ != nil {
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

// MarshalBER encodes MTForwardSMVGCSRes to BER format.
func (v *MTForwardSMVGCSRes) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {

	if v == nil {
		return nil, fmt.Errorf("%w: MTForwardSMVGCSRes receiver is nil", ber.ErrInvalidValue)
	}
	return marshalFramedValue(v, v.berReplayNode_, opts, (*MTForwardSMVGCSRes).MarshalBER, (*MTForwardSMVGCSRes).marshalBER, 3)

}
func (v *MTForwardSMVGCSRes) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if v.SmRPUI != nil {
		if len(*v.SmRPUI) < 1 || len(*v.SmRPUI) > 200 {
			if constraintErr := checkEncodedLength(opts, s949588_20, "51.5", "sm-RP-UI", "SIZE (1..200)", len(*v.SmRPUI)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_smrpui, encodeErr_enc_smrpui := ber.EncodeOctetString([]byte(*v.SmRPUI))
		if encodeErr_enc_smrpui != nil {
			return nil, qualifyBERError(encodeErr_enc_smrpui, "sm-RP-UI", "encoding", false)
		}
		retagged_enc_smrpui, tagErr_enc_smrpui := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_smrpui)
		if tagErr_enc_smrpui != nil {
			return nil, qualifyBERError(tagErr_enc_smrpui, "sm-RP-UI", "encoding", false)
		}
		enc_smrpui = retagged_enc_smrpui
		children = append(children, enc_smrpui...)
	}
	if v.DispatcherList != nil {
		if len((v.DispatcherList).Values) < 1 || len((v.DispatcherList).Values) > 5 {
			if constraintErr := checkEncodedLength(opts, s949588_20, "51.5", "dispatcherList", "SIZE (1..5)", len((v.DispatcherList).Values)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_dispatcherlist, err := MarshalBERDispatcherList(v.DispatcherList, ber.ParentCollectionSizeEncodeOptions(ber.ChildEncodeOptions(opts, "dispatcherList"))...)
		if err != nil {
			return nil, qualifyBERError(err, "dispatcherList", "encoding", false)
		}
		if ber.BERReplayEnabled(opts) && v.berDispatcherListIndef_ {
			// Strip the outer SEQUENCE tag from marshalBER output to get raw children.
			_, _, seqContent_, tlvErr_ := ber.DecodeEncodedTLV(enc_dispatcherlist)
			if tlvErr_ != nil {
				return nil, tlvErr_
			}
			{
				var encodeErr error
				enc_dispatcherlist, encodeErr = ber.EncodeConstructedIndefinite(tag.Tag{Class: tag.ClassContextSpecific, Number: 1}, seqContent_)
				if encodeErr != nil {
					return nil, qualifyBERError(encodeErr, "dispatcherList", "encoding", false)
				}
			}
		} else {
			retagged_enc_dispatcherlist, tagErr_enc_dispatcherlist := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_dispatcherlist)
			if tagErr_enc_dispatcherlist != nil {
				return nil, qualifyBERError(tagErr_enc_dispatcherlist, "dispatcherList", "encoding", false)
			}
			enc_dispatcherlist = retagged_enc_dispatcherlist
		}
		ber.RecordGeneratedBERChildPlacement(opts, len(children), enc_dispatcherlist)
		children = append(children, enc_dispatcherlist...)
	}
	if v.OngoingCall != nil {
		enc_ongoingcall := ber.EncodeNull()
		children = append(children, enc_ongoingcall...)
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
	if v.AdditionalDispatcherList != nil {
		if len((v.AdditionalDispatcherList).Values) < 1 || len((v.AdditionalDispatcherList).Values) > 15 {
			if constraintErr := checkEncodedLength(opts, s949588_20, "51.5", "additionalDispatcherList", "SIZE (1..15)", len((v.AdditionalDispatcherList).Values)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_additionaldispatcherlist, err := MarshalBERAdditionalDispatcherList(v.AdditionalDispatcherList, ber.ParentCollectionSizeEncodeOptions(ber.ChildEncodeOptions(opts, "additionalDispatcherList"))...)
		if err != nil {
			return nil, qualifyBERError(err, "additionalDispatcherList", "encoding", false)
		}
		if ber.BERReplayEnabled(opts) && v.berAdditionalDispatcherListIndef_ {
			// Strip the outer SEQUENCE tag from marshalBER output to get raw children.
			_, _, seqContent_, tlvErr_ := ber.DecodeEncodedTLV(enc_additionaldispatcherlist)
			if tlvErr_ != nil {
				return nil, tlvErr_
			}
			{
				var encodeErr error
				enc_additionaldispatcherlist, encodeErr = ber.EncodeConstructedIndefinite(tag.Tag{Class: tag.ClassContextSpecific, Number: 3}, seqContent_)
				if encodeErr != nil {
					return nil, qualifyBERError(encodeErr, "additionalDispatcherList", "encoding", false)
				}
			}
		} else {
			retagged_enc_additionaldispatcherlist, tagErr_enc_additionaldispatcherlist := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, enc_additionaldispatcherlist)
			if tagErr_enc_additionaldispatcherlist != nil {
				return nil, qualifyBERError(tagErr_enc_additionaldispatcherlist, "additionalDispatcherList", "encoding", false)
			}
			enc_additionaldispatcherlist = retagged_enc_additionaldispatcherlist
		}
		ber.RecordGeneratedBERChildPlacement(opts, len(children), enc_additionaldispatcherlist)
		children = append(children, enc_additionaldispatcherlist...)
	}
	base_ := -1
	for i, ext := range v.ExtData_ {
		if err := checkOpaqueAddition(ext, opts, s949588_20, children, i, &base_); err != nil {
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
		if i == 0 && ((peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2) || (peekTag.Class == tag.ClassUniversal && peekTag.Number == 5) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0)) {
			if constraintErr := ber.CheckEncodedValue(ber.EncodeRule(opts, s949588_20, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
				return nil, constraintErr
			}
		}
		children = append(children, ext...)
	}
	ber.RecordGeneratedBERContainer(opts, children)
	return ber.EncodeSequence(children)
}
func (v *MTForwardSMVGCSRes) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// MarshalDER encodes MTForwardSMVGCSRes to DER format.
// Opaque descendants pass generic DER checks; foreign schema rules need a typed binding.
func (v *MTForwardSMVGCSRes) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: MTForwardSMVGCSRes receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if v.SmRPUI != nil {
		if len(*v.SmRPUI) < 1 || len(*v.SmRPUI) > 200 {
			if constraintErr := checkEncodedLength(nil, s949588_20, "51.5", "sm-RP-UI", "SIZE (1..200)", len(*v.SmRPUI)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_smrpui, encodeErr_enc_smrpui := ber.EncodeOctetString([]byte(*v.SmRPUI))
		if encodeErr_enc_smrpui != nil {
			return nil, qualifyBERError(encodeErr_enc_smrpui, "sm-RP-UI", "encoding", true)
		}
		retagged_enc_smrpui, tagErr_enc_smrpui := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_smrpui)
		if tagErr_enc_smrpui != nil {
			return nil, qualifyBERError(tagErr_enc_smrpui, "sm-RP-UI", "encoding", true)
		}
		enc_smrpui = retagged_enc_smrpui
		children = append(children, enc_smrpui...)
	}
	if v.DispatcherList != nil {
		if len((v.DispatcherList).Values) < 1 || len((v.DispatcherList).Values) > 5 {
			if constraintErr := checkEncodedLength(nil, s949588_20, "51.5", "dispatcherList", "SIZE (1..5)", len((v.DispatcherList).Values)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_dispatcherlist, err := MarshalDERDispatcherList(v.DispatcherList)
		if err != nil {
			return nil, qualifyBERError(err, "dispatcherList", "encoding", true)
		}
		retagged_enc_dispatcherlist, tagErr_enc_dispatcherlist := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_dispatcherlist)
		if tagErr_enc_dispatcherlist != nil {
			return nil, qualifyBERError(tagErr_enc_dispatcherlist, "dispatcherList", "encoding", true)
		}
		enc_dispatcherlist = retagged_enc_dispatcherlist
		children = append(children, enc_dispatcherlist...)
	}
	if v.OngoingCall != nil {
		enc_ongoingcall := ber.EncodeNull()
		children = append(children, enc_ongoingcall...)
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
	if v.AdditionalDispatcherList != nil {
		if len((v.AdditionalDispatcherList).Values) < 1 || len((v.AdditionalDispatcherList).Values) > 15 {
			if constraintErr := checkEncodedLength(nil, s949588_20, "51.5", "additionalDispatcherList", "SIZE (1..15)", len((v.AdditionalDispatcherList).Values)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_additionaldispatcherlist, err := MarshalDERAdditionalDispatcherList(v.AdditionalDispatcherList)
		if err != nil {
			return nil, qualifyBERError(err, "additionalDispatcherList", "encoding", true)
		}
		retagged_enc_additionaldispatcherlist, tagErr_enc_additionaldispatcherlist := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, enc_additionaldispatcherlist)
		if tagErr_enc_additionaldispatcherlist != nil {
			return nil, qualifyBERError(tagErr_enc_additionaldispatcherlist, "additionalDispatcherList", "encoding", true)
		}
		enc_additionaldispatcherlist = retagged_enc_additionaldispatcherlist
		children = append(children, enc_additionaldispatcherlist...)
	}
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDEREncodedElement(ext); err != nil {
			return nil, invalidDERAddition(ext, s949588_20, children, i)
		}
		peekTag, _, _, extErr := ber.DecodeEncodedTLV(ext)
		if extErr != nil {
			return nil, extErr
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: only the first addition is restricted.
		if i == 0 && ((peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2) || (peekTag.Class == tag.ClassUniversal && peekTag.Number == 5) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0)) {
			if constraintErr := ber.CheckEncodedValue(ber.EncodeRule(nil, s949588_20, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
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
		return nil, fmt.Errorf("%s: %w", "encoding MTForwardSMVGCSRes as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}
func (v *MTForwardSMVGCSRes) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	encoded, err := v.MarshalDER()
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBER decodes MTForwardSMVGCSRes from BER/DER format.
func (destination *MTForwardSMVGCSRes) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if destination == nil {
		return fmt.Errorf("%w: MTForwardSMVGCSRes destination is nil", ber.ErrInvalidValue)
	}
	v := new(MTForwardSMVGCSRes)

	defer publishDecodedValue(destination, v, &returnErr)

	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	preparedData, preparedOptions, prepareErr := prepareCompositeBER(data, opts, s949588_20, "child", (*MTForwardSMVGCSRes).UnmarshalBER)
	if prepareErr != nil {
		return prepareErr
	}
	data, opts = preparedData, preparedOptions

	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
	*v = MTForwardSMVGCSRes{}
	defer func() {
		if returnErr == nil {
			returnErr = completeValueBER(data,
				opts, v, &v.berReplayNode_, (*MTForwardSMVGCSRes).MarshalBER)
		}

	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("%s: %w", "decoding MTForwardSMVGCSRes SEQUENCE", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "MTForwardSMVGCSRes", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode sm-RP-UI
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
				ber.MarkPreflightTarget(opts, "sm-RP-UI", content[offset:])
				decodedTag_smrpui, n_smrpui, rawVal_smrpui, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "sm-RP-UI", "decoding", false)
				}
				if decodedTag_smrpui.Class != tag.ClassContextSpecific || decodedTag_smrpui.Number != 0 {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_smrpui), "sm-RP-UI", "decoding", false)
				}
				decVal_smrpui, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_smrpui.Constructed, rawVal_smrpui, opts...)
				if octetErr != nil {
					return qualifyBERError(octetErr, "sm-RP-UI", "decoding", false)
				}
				tmp_smrpui := SignalInfo(decVal_smrpui)
				v.SmRPUI = &tmp_smrpui
				if offset > len(content) || n_smrpui < 0 || n_smrpui > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_smrpui
				if len(*v.SmRPUI) < 1 || len(*v.SmRPUI) > 200 {
					if constraintErr := checkDecodedLength(opts, s949588_20, "51.5", "sm-RP-UI", "SIZE (1..200)", len(*v.SmRPUI)); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode dispatcherList
	v.berDispatcherListIndef_ = false
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
				ber.MarkPreflightTarget(opts, "dispatcherList", content[offset:])
				decodedTag_dispatcherlist, n_dispatcherlist, rawVal_dispatcherlist, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "dispatcherList", "decoding", false)
				}
				if decodedTag_dispatcherlist.Class != tag.ClassContextSpecific || decodedTag_dispatcherlist.Number != 1 || decodedTag_dispatcherlist.Constructed != true {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_dispatcherlist), "dispatcherList", "decoding", false)
				}
				_ = rawVal_dispatcherlist
				if offset < 0 || offset >
					len(content) || n_dispatcherlist < 0 || n_dispatcherlist >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				reconstructed_dispatcherlist, reconstructionErr_dispatcherlist := ber.EncodeImplicitTagWithClass(tag.ClassUniversal, tag.TagSequence, content[offset:offset+n_dispatcherlist])
				if reconstructionErr_dispatcherlist != nil {
					return qualifyBERError(reconstructionErr_dispatcherlist, "dispatcherList", "decoding", false)
				}
				dec_dispatcherlist, unmErr := UnmarshalBERDispatcherList(reconstructed_dispatcherlist, ber.ParentCollectionSizeDecodeOptions(ber.ChildDecodeOptions(opts, "dispatcherList"))...)
				if unmErr != nil {
					return qualifyBERError(unmErr, "dispatcherList", "decoding", false)
				}
				v.DispatcherList = dec_dispatcherlist
				{
					_, tagSz_, _ := ber.DecodeTag(content[offset:])
					if offset < 0 || offset >
						len(content) || tagSz_ < 0 || tagSz_ > len(content[offset:]) {
						return fmt.Errorf("invalid BER content window")
					}

					if offset+tagSz_ < len(content) && content[offset+tagSz_] == 0x80 {
						v.berDispatcherListIndef_ = true
					}
				}
				if offset < 0 || offset >
					len(content) || n_dispatcherlist < 0 || n_dispatcherlist >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_dispatcherlist
				if len((v.DispatcherList).Values) < 1 || len((v.DispatcherList).Values) > 5 {
					if constraintErr := checkDecodedLength(opts, s949588_20, "51.5", "dispatcherList", "SIZE (1..5)", len((v.DispatcherList).Values)); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode ongoingCall
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassUniversal && peekTag.Number == 5 {
				ber.MarkPreflightTarget(opts, "ongoingCall", content[offset:])
				n, err := ber.DecodeNull(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "ongoingCall", "decoding", false)
				}
				v.OngoingCall = &struct{}{}
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
	// Decode additionalDispatcherList
	v.berAdditionalDispatcherListIndef_ = false
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3 {
				ber.MarkPreflightTarget(opts, "additionalDispatcherList", content[offset:])
				decodedTag_additionaldispatcherlist, n_additionaldispatcherlist, rawVal_additionaldispatcherlist, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "additionalDispatcherList", "decoding", false)
				}
				if decodedTag_additionaldispatcherlist.Class != tag.ClassContextSpecific || decodedTag_additionaldispatcherlist.Number != 3 || decodedTag_additionaldispatcherlist.Constructed != true {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_additionaldispatcherlist), "additionalDispatcherList", "decoding", false)
				}
				_ = rawVal_additionaldispatcherlist
				if offset < 0 || offset >
					len(content) || n_additionaldispatcherlist < 0 || n_additionaldispatcherlist >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				reconstructed_additionaldispatcherlist, reconstructionErr_additionaldispatcherlist := ber.EncodeImplicitTagWithClass(tag.ClassUniversal, tag.TagSequence, content[offset:offset+n_additionaldispatcherlist])
				if reconstructionErr_additionaldispatcherlist != nil {
					return qualifyBERError(reconstructionErr_additionaldispatcherlist, "additionalDispatcherList", "decoding", false)
				}
				dec_additionaldispatcherlist, unmErr := UnmarshalBERAdditionalDispatcherList(reconstructed_additionaldispatcherlist, ber.ParentCollectionSizeDecodeOptions(ber.ChildDecodeOptions(opts, "additionalDispatcherList"))...)
				if unmErr != nil {
					return qualifyBERError(unmErr, "additionalDispatcherList", "decoding", false)
				}
				v.AdditionalDispatcherList = dec_additionaldispatcherlist
				{
					_, tagSz_, _ := ber.DecodeTag(content[offset:])
					if offset < 0 || offset >
						len(content) || tagSz_ < 0 || tagSz_ > len(content[offset:]) {
						return fmt.Errorf("invalid BER content window")
					}

					if offset+tagSz_ < len(content) && content[offset+tagSz_] == 0x80 {
						v.berAdditionalDispatcherListIndef_ = true
					}
				}
				if offset < 0 || offset >
					len(content) || n_additionaldispatcherlist < 0 || n_additionaldispatcherlist >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_additionaldispatcherlist
				if len((v.AdditionalDispatcherList).Values) < 1 || len((v.AdditionalDispatcherList).Values) > 15 {
					if constraintErr := checkDecodedLength(opts, s949588_20, "51.5", "additionalDispatcherList", "SIZE (1..15)", len((v.AdditionalDispatcherList).Values)); constraintErr != nil {
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
			return &ber.DecodeError{Offset: offset, TypeName: "MTForwardSMVGCSRes", Cause: extErr_}
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: the first unknown addition must differ from trailing OPTIONAL/DEFAULT tags.
		if len(v.ExtData_) == 0 && ((peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2) || (peekTag.Class == tag.ClassUniversal && peekTag.Number == 5) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0)) {
			if !ber.ToleranceEnabled(opts) {
				return &ber.DecodeError{Offset: offset, TypeName: "MTForwardSMVGCSRes", Cause: fmt.Errorf("%w: repeated or out-of-order SEQUENCE component tag %s", ber.ErrInvalidTag, peekTag)}
			}
			if orderErr_ := ber.CheckDecodedValue(ber.DecodeRule(opts, s949588_20, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), fmt.Sprintf("ExtData_[%d]", len(v.ExtData_)), "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); orderErr_ != nil {
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

// MarshalBERDispatcherList encodes a DispatcherList list to BER.
func MarshalBERDispatcherList(collection *DispatcherList, opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {

	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	if collection == nil {
		return nil, fmt.Errorf("%w: required collection is nil", ber.ErrInvalidValue)
	}
	return marshalFramedValue(collection, collection.berReplayNode_, opts, MarshalBERDispatcherList, marshalBERDispatcherList, 3, UnmarshalBERDispatcherList)

}
func marshalBERDispatcherList(collection *DispatcherList, opts ...ber.EncodeOption) ([]byte, error) {
	list := collection.Values
	if len(list) < 1 || len(list) > 5 {
		if constraintErr := checkEncodedCollectionLength(opts, "MAP-SM-DataTypes.marshalBERDispatcherList", "51.5", "DispatcherList", "SIZE (1..5)", len(list)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	var children []byte
	for elemIndex, elem := range list {
		_ = elemIndex
		if len(elem) < 1 || len(elem) > 9 {
			if constraintErr := checkEncodedLength(opts, "MAP-SM-DataTypes.marshalBERDispatcherList", "51.5", fmt.Sprintf("element[%d]", elemIndex), "SIZE (1..9)", len(elem)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		if len(elem) < 1 || len(elem) > 20 {
			if constraintErr := checkEncodedLength(opts, "MAP-SM-DataTypes.marshalBERDispatcherList", "51.5", fmt.Sprintf("element[%d]", elemIndex), "SIZE (1..20)", len(elem)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		encodedElem, encodeErr_encodedElem := ber.EncodeOctetString([]byte(elem))
		if encodeErr_encodedElem != nil {
			return nil, qualifyBERError(encodeErr_encodedElem, fmt.Sprintf("element[%d]",
				elemIndex),

				"encoding", false)
		}
		children = append(children, encodedElem...)
	}
	ber.RecordGeneratedBERContainer(opts, children)
	return ber.EncodeSequence(children)
}

func appendBERLinearDispatcherList(encoder *ber.LinearEncoder, collection *DispatcherList, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := MarshalBERDispatcherList(collection, opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// MarshalDERDispatcherList encodes a DispatcherList list to DER.
func MarshalDERDispatcherList(collection *DispatcherList) ([]byte, error) {
	if collection == nil {
		return nil, fmt.Errorf("%w: required collection is nil", ber.ErrInvalidValue)
	}
	list := collection.Values
	if len(list) < 1 || len(list) > 5 {
		if constraintErr := checkEncodedCollectionLength(nil, s949588_21, "51.5", "DispatcherList", "SIZE (1..5)", len(list)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	var children []byte
	for elemIndex, elem := range list {
		_ = elemIndex
		if len(elem) < 1 || len(elem) > 9 {
			if constraintErr := checkEncodedLength(nil, s949588_21, "51.5", fmt.Sprintf("element[%d]", elemIndex), "SIZE (1..9)", len(elem)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		if len(elem) < 1 || len(elem) > 20 {
			if constraintErr := checkEncodedLength(nil, s949588_21, "51.5", fmt.Sprintf("element[%d]", elemIndex), "SIZE (1..20)", len(elem)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		encodedElem, encodeErr_encodedElem := ber.EncodeOctetString([]byte(elem))
		if encodeErr_encodedElem != nil {
			return nil, qualifyBERError(encodeErr_encodedElem, fmt.Sprintf("element[%d]",
				elemIndex),

				"encoding", true)
		}
		children = append(children, encodedElem...)
	}
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("%s: %w", "encoding DispatcherList as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}

func appendDERLinearDispatcherList(encoder *ber.LinearEncoder, collection *DispatcherList) ([]byte, error) {
	encoded, err := MarshalDERDispatcherList(collection)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBERDispatcherList decodes a DispatcherList list from BER.
func UnmarshalBERDispatcherList(data []byte, opts ...ber.DecodeOption) (returnValue *DispatcherList, returnErr error) {
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	preparedData, preparedOptions, prepareErr := prepareValueBER(data, opts, s949588_21, "element", func(data []byte,

		probeOpts []ber.DecodeOption) error {
		_, probeErr := UnmarshalBERDispatcherList(data, probeOpts...)
		return probeErr
	})
	if prepareErr != nil {
		return nil, prepareErr
	}
	data, opts = preparedData, preparedOptions

	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", "decoding DispatcherList", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return nil, &ber.DecodeError{Offset: total, TypeName: "DispatcherList", Cause: ber.ErrExtraData}
	}
	var result []ISDNAddressString
	offset := 0
	for offset < len(content) {
		elementIndex := len(result)
		_ = elementIndex
		elementData := content[offset:]
		ber.MarkPreflightElement(opts, elementIndex, elementData)
		val, n, osErr := ber.DecodeOctetString(elementData, opts...)
		if osErr != nil {
			return nil, qualifyBERError(osErr, fmt.Sprintf("element[%d]",
				elementIndex),

				"decoding", false)
		}
		if len(val) < 1 || len(val) > 9 {
			if constraintErr := checkDecodedLength(opts, s949588_21, "51.5", fmt.Sprintf("element[%d]", len(result)), "SIZE (1..9)", len(val)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		if len(val) < 1 || len(val) > 20 {
			if constraintErr := checkDecodedLength(opts, s949588_21, "51.5", fmt.Sprintf("element[%d]", len(result)), "SIZE (1..20)", len(val)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		result = append(result, ISDNAddressString(val))
		if offset < 0 || offset >
			len(content) || n < 0 || n > len(content[offset:]) {
			return nil, fmt.Errorf("invalid BER content window")
		}

		offset += n
	}
	if len(result) < 1 || len(result) > 5 {
		if constraintErr := checkDecodedCollectionLength(opts, s949588_21, "51.5", "DispatcherList", "SIZE (1..5)", len(result)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	decoded := &DispatcherList{Values: result}
	if replayErr := completeValueBER(data,
		opts, decoded, &decoded.berReplayNode_, MarshalBERDispatcherList); replayErr != nil {
		return nil, replayErr
	}

	return decoded, nil
}

// MarshalBERAdditionalDispatcherList encodes a AdditionalDispatcherList list to BER.
func MarshalBERAdditionalDispatcherList(collection *AdditionalDispatcherList, opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {

	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	if collection == nil {
		return nil, fmt.Errorf("%w: required collection is nil", ber.ErrInvalidValue)
	}
	return marshalFramedValue(collection, collection.berReplayNode_, opts, MarshalBERAdditionalDispatcherList, marshalBERAdditionalDispatcherList, 3, UnmarshalBERAdditionalDispatcherList)

}
func marshalBERAdditionalDispatcherList(collection *AdditionalDispatcherList, opts ...ber.EncodeOption) ([]byte, error) {
	list := collection.Values
	if len(list) < 1 || len(list) > 15 {
		if constraintErr := checkEncodedCollectionLength(opts, "MAP-SM-DataTypes.marshalBERAdditionalDispatcherList", "51.5", "AdditionalDispatcherList", "SIZE (1..15)", len(list)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	var children []byte
	for elemIndex, elem := range list {
		_ = elemIndex
		if len(elem) < 1 || len(elem) > 9 {
			if constraintErr := checkEncodedLength(opts, "MAP-SM-DataTypes.marshalBERAdditionalDispatcherList", "51.5", fmt.Sprintf("element[%d]", elemIndex), "SIZE (1..9)", len(elem)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		if len(elem) < 1 || len(elem) > 20 {
			if constraintErr := checkEncodedLength(opts, "MAP-SM-DataTypes.marshalBERAdditionalDispatcherList", "51.5", fmt.Sprintf("element[%d]", elemIndex), "SIZE (1..20)", len(elem)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		encodedElem, encodeErr_encodedElem := ber.EncodeOctetString([]byte(elem))
		if encodeErr_encodedElem != nil {
			return nil, qualifyBERError(encodeErr_encodedElem, fmt.Sprintf("element[%d]",
				elemIndex),

				"encoding", false)
		}
		children = append(children, encodedElem...)
	}
	ber.RecordGeneratedBERContainer(opts, children)
	return ber.EncodeSequence(children)
}

func appendBERLinearAdditionalDispatcherList(encoder *ber.LinearEncoder, collection *AdditionalDispatcherList, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := MarshalBERAdditionalDispatcherList(collection, opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// MarshalDERAdditionalDispatcherList encodes a AdditionalDispatcherList list to DER.
func MarshalDERAdditionalDispatcherList(collection *AdditionalDispatcherList) ([]byte, error) {
	if collection == nil {
		return nil, fmt.Errorf("%w: required collection is nil", ber.ErrInvalidValue)
	}
	list := collection.Values
	if len(list) < 1 || len(list) > 15 {
		if constraintErr := checkEncodedCollectionLength(nil, s949588_22, "51.5", "AdditionalDispatcherList", "SIZE (1..15)", len(list)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	var children []byte
	for elemIndex, elem := range list {
		_ = elemIndex
		if len(elem) < 1 || len(elem) > 9 {
			if constraintErr := checkEncodedLength(nil, s949588_22, "51.5", fmt.Sprintf("element[%d]", elemIndex), "SIZE (1..9)", len(elem)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		if len(elem) < 1 || len(elem) > 20 {
			if constraintErr := checkEncodedLength(nil, s949588_22, "51.5", fmt.Sprintf("element[%d]", elemIndex), "SIZE (1..20)", len(elem)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		encodedElem, encodeErr_encodedElem := ber.EncodeOctetString([]byte(elem))
		if encodeErr_encodedElem != nil {
			return nil, qualifyBERError(encodeErr_encodedElem, fmt.Sprintf("element[%d]",
				elemIndex),

				"encoding", true)
		}
		children = append(children, encodedElem...)
	}
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("%s: %w", "encoding AdditionalDispatcherList as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}

func appendDERLinearAdditionalDispatcherList(encoder *ber.LinearEncoder, collection *AdditionalDispatcherList) ([]byte, error) {
	encoded, err := MarshalDERAdditionalDispatcherList(collection)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBERAdditionalDispatcherList decodes a AdditionalDispatcherList list from BER.
func UnmarshalBERAdditionalDispatcherList(data []byte, opts ...ber.DecodeOption) (returnValue *AdditionalDispatcherList, returnErr error) {
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	preparedData, preparedOptions, prepareErr := prepareValueBER(data, opts, s949588_22, "element", func(data []byte,

		probeOpts []ber.DecodeOption) error {
		_, probeErr := UnmarshalBERAdditionalDispatcherList(data, probeOpts...)
		return probeErr
	})
	if prepareErr != nil {
		return nil, prepareErr
	}
	data, opts = preparedData, preparedOptions

	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", "decoding AdditionalDispatcherList", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return nil, &ber.DecodeError{Offset: total, TypeName: "AdditionalDispatcherList", Cause: ber.ErrExtraData}
	}
	var result []ISDNAddressString
	offset := 0
	for offset < len(content) {
		elementIndex := len(result)
		_ = elementIndex
		elementData := content[offset:]
		ber.MarkPreflightElement(opts, elementIndex, elementData)
		val, n, osErr := ber.DecodeOctetString(elementData, opts...)
		if osErr != nil {
			return nil, qualifyBERError(osErr, fmt.Sprintf("element[%d]",
				elementIndex),

				"decoding", false)
		}
		if len(val) < 1 || len(val) > 9 {
			if constraintErr := checkDecodedLength(opts, s949588_22, "51.5", fmt.Sprintf("element[%d]", len(result)), "SIZE (1..9)", len(val)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		if len(val) < 1 || len(val) > 20 {
			if constraintErr := checkDecodedLength(opts, s949588_22, "51.5", fmt.Sprintf("element[%d]", len(result)), "SIZE (1..20)", len(val)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		result = append(result, ISDNAddressString(val))
		if offset < 0 || offset >
			len(content) || n < 0 || n > len(content[offset:]) {
			return nil, fmt.Errorf("invalid BER content window")
		}

		offset += n
	}
	if len(result) < 1 || len(result) > 15 {
		if constraintErr := checkDecodedCollectionLength(opts, s949588_22, "51.5", "AdditionalDispatcherList", "SIZE (1..15)", len(result)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	decoded := &AdditionalDispatcherList{Values: result}
	if replayErr := completeValueBER(data,
		opts, decoded, &decoded.berReplayNode_, MarshalBERAdditionalDispatcherList); replayErr != nil {
		return nil, replayErr
	}

	return decoded, nil
}

const (
	s949588_0  = "MAP-SM-DataTypes.RoutingInfoForSM-Arg"
	s949588_1  = "MAP-SM-DataTypes.RoutingInfoForSM-Res"
	s949588_2  = "MAP-SM-DataTypes.IP-SM-GW-Guidance"
	s949588_3  = "MAP-SM-DataTypes.LocationInfoWithLMSI"
	s949588_4  = "MAP-SM-DataTypes.Additional-Number"
	s949588_5  = "MAP-SM-DataTypes.MO-ForwardSM-Arg"
	s949588_6  = "MAP-SM-DataTypes.MO-ForwardSM-Res"
	s949588_7  = "MAP-SM-DataTypes.MT-ForwardSM-Arg"
	s949588_8  = "MAP-SM-DataTypes.CorrelationID"
	s949588_9  = "MAP-SM-DataTypes.MT-ForwardSM-Res"
	s949588_10 = "MAP-SM-DataTypes.SM-RP-DA"
	s949588_11 = "MAP-SM-DataTypes.SM-RP-OA"
	s949588_12 = "MAP-SM-DataTypes.ReportSM-DeliveryStatusArg"
	s949588_13 = "MAP-SM-DataTypes.ReportSM-DeliveryStatusRes"
	s949588_14 = "MAP-SM-DataTypes.SMServingNodeAddress"
	s949588_15 = "MAP-SM-DataTypes.AlertServiceCentreArg"
	s949588_16 = "MAP-SM-DataTypes.InformServiceCentreArg"
	s949588_17 = "MAP-SM-DataTypes.ReadyForSM-Arg"
	s949588_18 = "MAP-SM-DataTypes.ReadyForSM-Res"
	s949588_19 = "MAP-SM-DataTypes.MT-ForwardSM-VGCS-Arg"
	s949588_20 = "MAP-SM-DataTypes.MT-ForwardSM-VGCS-Res"
	s949588_21 = "MAP-SM-DataTypes.DispatcherList"
	s949588_22 = "MAP-SM-DataTypes.AdditionalDispatcherList"
)
