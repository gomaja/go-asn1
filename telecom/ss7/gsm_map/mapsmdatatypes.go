// Code generated from ASN.1 module "MAP-SM-DataTypes". DO NOT EDIT.

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

	// MaxNumOfDispatchers is the integer constant for MaxNumOfDispatchers.
	MaxNumOfDispatchers int64 = 5

	// MaxNumOfAdditionalDispatchers is the integer constant for MaxNumOfAdditionalDispatchers.
	MaxNumOfAdditionalDispatchers int64 = 15
)

// RoutingInfoForSMArg represents the ASN.1 type RoutingInfoForSM-Arg (SEQUENCE).
type RoutingInfoForSMArg struct {
	Msisdn                  ISDNAddressString      `asn1:"tag:0,context,implicit"`
	SmRPPRI                 bool                   `asn1:"tag:1,context,implicit"`
	SmRPPRIRaw_             byte                   `asn1:"-" json:"-"`
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
	ExtData_                [][]byte               `asn1:"-" json:"-"`
}

// SMDeliveryNotIntended represents the ASN.1 ENUMERATED type SM-DeliveryNotIntended.
type SMDeliveryNotIntended int64

const (
	SMDeliveryNotIntendedOnlyIMSIRequested   SMDeliveryNotIntended = 0
	SMDeliveryNotIntendedOnlyMCCMNCRequested SMDeliveryNotIntended = 1
)

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
	ExtData_             [][]byte             `asn1:"-" json:"-"`
}

// IPSMGWGuidance represents the ASN.1 type IP-SM-GW-Guidance (SEQUENCE).
type IPSMGWGuidance struct {
	MinimumDeliveryTimeValue     SMDeliveryTimerValue `asn1:""`
	RecommendedDeliveryTimeValue SMDeliveryTimerValue `asn1:""`
	ExtensionContainer           *ExtensionContainer  `asn1:",optional" json:"ExtensionContainer,omitempty"`
	ExtCount_                    int64                `asn1:"-" json:"-"`
	ExtPresent_                  []bool               `asn1:"-" json:"-"`
	ExtData_                     [][]byte             `asn1:"-" json:"-"`
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
	ExtData_                             [][]byte                    `asn1:"-" json:"-"`
}

// AdditionalNumber choice constants.
const (
	AdditionalNumberChoiceMscNumber  = 1
	AdditionalNumberChoiceSgsnNumber = 2
)

// AdditionalNumber represents the ASN.1 CHOICE type Additional-Number.
type AdditionalNumber struct {
	Choice     int
	MscNumber  *ISDNAddressString `json:"MscNumber,omitempty"`
	SgsnNumber *ISDNAddressString `json:"SgsnNumber,omitempty"`
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
	ExtData_           [][]byte            `asn1:"-" json:"-"`
}

// MOForwardSMRes represents the ASN.1 type MO-ForwardSM-Res (SEQUENCE).
type MOForwardSMRes struct {
	SmRPUI             *SignalInfo         `asn1:",optional" json:"SmRPUI,omitempty"`
	ExtensionContainer *ExtensionContainer `asn1:",optional" json:"ExtensionContainer,omitempty"`
	ExtCount_          int64               `asn1:"-" json:"-"`
	ExtPresent_        []bool              `asn1:"-" json:"-"`
	ExtData_           [][]byte            `asn1:"-" json:"-"`
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
	ExtData_                  [][]byte                    `asn1:"-" json:"-"`
}

// CorrelationID represents the ASN.1 type CorrelationID (SEQUENCE).
type CorrelationID struct {
	HlrId   *HLRId  `asn1:"tag:0,context,implicit,optional" json:"HlrId,omitempty"`
	SipUriA *SIPURI `asn1:"tag:1,context,implicit,optional" json:"SipUriA,omitempty"`
	SipUriB SIPURI  `asn1:"tag:2,context,implicit"`
}

// SIPURI represents the ASN.1 type SIP-URI (OCTET_STRING).
type SIPURI = []byte

// MTForwardSMRes represents the ASN.1 type MT-ForwardSM-Res (SEQUENCE).
type MTForwardSMRes struct {
	SmRPUI             *SignalInfo         `asn1:",optional" json:"SmRPUI,omitempty"`
	ExtensionContainer *ExtensionContainer `asn1:",optional" json:"ExtensionContainer,omitempty"`
	ExtCount_          int64               `asn1:"-" json:"-"`
	ExtPresent_        []bool              `asn1:"-" json:"-"`
	ExtData_           [][]byte            `asn1:"-" json:"-"`
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
	Imsi                   *IMSI          `json:"Imsi,omitempty"`
	Lmsi                   *LMSI          `json:"Lmsi,omitempty"`
	ServiceCentreAddressDA *AddressString `json:"ServiceCentreAddressDA,omitempty"`
	NoSMRPDA               *struct{}      `json:"NoSMRPDA,omitempty"`
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
	ExtCount_                              int64                         `asn1:"-" json:"-"`
	ExtPresent_                            []bool                        `asn1:"-" json:"-"`
	ExtData_                               [][]byte                      `asn1:"-" json:"-"`
}

// SMDeliveryOutcome represents the ASN.1 ENUMERATED type SM-DeliveryOutcome.
type SMDeliveryOutcome int64

const (
	SMDeliveryOutcomeMemoryCapacityExceeded SMDeliveryOutcome = 0
	SMDeliveryOutcomeAbsentSubscriber       SMDeliveryOutcome = 1
	SMDeliveryOutcomeSuccessfulTransfer     SMDeliveryOutcome = 2
)

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
	StoredMSISDN       *ISDNAddressString  `asn1:",optional" json:"StoredMSISDN,omitempty"`
	ExtensionContainer *ExtensionContainer `asn1:",optional" json:"ExtensionContainer,omitempty"`
	ExtCount_          int64               `asn1:"-" json:"-"`
	ExtPresent_        []bool              `asn1:"-" json:"-"`
	ExtData_           [][]byte            `asn1:"-" json:"-"`
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
	ExtData_                  [][]byte                    `asn1:"-" json:"-"`
}

// SmsGmscAlertEvent represents the ASN.1 ENUMERATED type SmsGmsc-Alert-Event.
type SmsGmscAlertEvent int64

const (
	SmsGmscAlertEventMsAvailableForMtSms   SmsGmscAlertEvent = 0
	SmsGmscAlertEventMsUnderNewServingNode SmsGmscAlertEvent = 1
)

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
	ExtData_                                [][]byte                      `asn1:"-" json:"-"`
}

// MWStatus represents the ASN.1 type MW-Status (BIT_STRING).
type MWStatus = runtime.BitString

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
	ExtData_                       [][]byte            `asn1:"-" json:"-"`
}

// ReadyForSMRes represents the ASN.1 type ReadyForSM-Res (SEQUENCE).
type ReadyForSMRes struct {
	ExtensionContainer *ExtensionContainer `asn1:",optional" json:"ExtensionContainer,omitempty"`
	ExtCount_          int64               `asn1:"-" json:"-"`
	ExtPresent_        []bool              `asn1:"-" json:"-"`
	ExtData_           [][]byte            `asn1:"-" json:"-"`
}

// AlertReason represents the ASN.1 ENUMERATED type AlertReason.
type AlertReason int64

const (
	AlertReasonMsPresent       AlertReason = 0
	AlertReasonMemoryAvailable AlertReason = 1
)

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
	ExtData_           [][]byte            `asn1:"-" json:"-"`
}

// MTForwardSMVGCSRes represents the ASN.1 type MT-ForwardSM-VGCS-Res (SEQUENCE).
type MTForwardSMVGCSRes struct {
	SmRPUI                         *SignalInfo              `asn1:"tag:0,context,implicit,optional" json:"SmRPUI,omitempty"`
	DispatcherList                 DispatcherList           `asn1:"tag:1,context,implicit,optional" json:"DispatcherList,omitempty"`
	DispatcherListIndef_           bool                     `asn1:"-" json:"-"`
	OngoingCall                    *struct{}                `asn1:",optional" json:"OngoingCall,omitempty"`
	ExtensionContainer             *ExtensionContainer      `asn1:"tag:2,context,implicit,optional" json:"ExtensionContainer,omitempty"`
	AdditionalDispatcherList       AdditionalDispatcherList `asn1:"tag:3,context,implicit,optional" json:"AdditionalDispatcherList,omitempty"`
	AdditionalDispatcherListIndef_ bool                     `asn1:"-" json:"-"`
	ExtCount_                      int64                    `asn1:"-" json:"-"`
	ExtPresent_                    []bool                   `asn1:"-" json:"-"`
	ExtData_                       [][]byte                 `asn1:"-" json:"-"`
}

// DispatcherList represents the ASN.1 type DispatcherList (SEQUENCE_OF).
type DispatcherList = []ISDNAddressString

// AdditionalDispatcherList represents the ASN.1 type AdditionalDispatcherList (SEQUENCE_OF).
type AdditionalDispatcherList = []ISDNAddressString

// MarshalBER encodes RoutingInfoForSMArg to BER format.
func (v *RoutingInfoForSMArg) MarshalBER() ([]byte, error) {
	var children []byte
	enc_msisdn := ber.EncodeOctetString([]byte(v.Msisdn))
	retagged_enc_msisdn, tagErr_enc_msisdn := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_msisdn)
	if tagErr_enc_msisdn != nil {
		return nil, fmt.Errorf("encoding msisdn: %w", tagErr_enc_msisdn)
	}
	enc_msisdn = retagged_enc_msisdn
	children = append(children, enc_msisdn...)
	var enc_smrppri []byte
	if v.SmRPPRIRaw_ != 0 {
		enc_smrppri = ber.EncodeBooleanRaw(v.SmRPPRIRaw_)
	} else {
		enc_smrppri = ber.EncodeBoolean(v.SmRPPRI)
	}
	retagged_enc_smrppri, tagErr_enc_smrppri := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_smrppri)
	if tagErr_enc_smrppri != nil {
		return nil, fmt.Errorf("encoding sm-RP-PRI: %w", tagErr_enc_smrppri)
	}
	enc_smrppri = retagged_enc_smrppri
	children = append(children, enc_smrppri...)
	enc_servicecentreaddress := ber.EncodeOctetString([]byte(v.ServiceCentreAddress))
	retagged_enc_servicecentreaddress, tagErr_enc_servicecentreaddress := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_servicecentreaddress)
	if tagErr_enc_servicecentreaddress != nil {
		return nil, fmt.Errorf("encoding serviceCentreAddress: %w", tagErr_enc_servicecentreaddress)
	}
	enc_servicecentreaddress = retagged_enc_servicecentreaddress
	children = append(children, enc_servicecentreaddress...)
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
	if v.GprsSupportIndicator != nil {
		enc_gprssupportindicator := ber.EncodeNull()
		retagged_enc_gprssupportindicator, tagErr_enc_gprssupportindicator := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 7, enc_gprssupportindicator)
		if tagErr_enc_gprssupportindicator != nil {
			return nil, fmt.Errorf("encoding gprsSupportIndicator: %w", tagErr_enc_gprssupportindicator)
		}
		enc_gprssupportindicator = retagged_enc_gprssupportindicator
		children = append(children, enc_gprssupportindicator...)
	}
	if v.SmRPMTI != nil {
		enc_smrpmti := ber.EncodeInteger(int64(*v.SmRPMTI))
		retagged_enc_smrpmti, tagErr_enc_smrpmti := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 8, enc_smrpmti)
		if tagErr_enc_smrpmti != nil {
			return nil, fmt.Errorf("encoding sm-RP-MTI: %w", tagErr_enc_smrpmti)
		}
		enc_smrpmti = retagged_enc_smrpmti
		children = append(children, enc_smrpmti...)
	}
	if v.SmRPSMEA != nil {
		enc_smrpsmea := ber.EncodeOctetString([]byte(*v.SmRPSMEA))
		retagged_enc_smrpsmea, tagErr_enc_smrpsmea := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 9, enc_smrpsmea)
		if tagErr_enc_smrpsmea != nil {
			return nil, fmt.Errorf("encoding sm-RP-SMEA: %w", tagErr_enc_smrpsmea)
		}
		enc_smrpsmea = retagged_enc_smrpsmea
		children = append(children, enc_smrpsmea...)
	}
	if v.SmDeliveryNotIntended != nil {
		enc_smdeliverynotintended := ber.EncodeEnumerated(int64(*v.SmDeliveryNotIntended))
		retagged_enc_smdeliverynotintended, tagErr_enc_smdeliverynotintended := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 10, enc_smdeliverynotintended)
		if tagErr_enc_smdeliverynotintended != nil {
			return nil, fmt.Errorf("encoding sm-deliveryNotIntended: %w", tagErr_enc_smdeliverynotintended)
		}
		enc_smdeliverynotintended = retagged_enc_smdeliverynotintended
		children = append(children, enc_smdeliverynotintended...)
	}
	if v.IpSmGwGuidanceIndicator != nil {
		enc_ipsmgwguidanceindicator := ber.EncodeNull()
		retagged_enc_ipsmgwguidanceindicator, tagErr_enc_ipsmgwguidanceindicator := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 11, enc_ipsmgwguidanceindicator)
		if tagErr_enc_ipsmgwguidanceindicator != nil {
			return nil, fmt.Errorf("encoding ip-sm-gwGuidanceIndicator: %w", tagErr_enc_ipsmgwguidanceindicator)
		}
		enc_ipsmgwguidanceindicator = retagged_enc_ipsmgwguidanceindicator
		children = append(children, enc_ipsmgwguidanceindicator...)
	}
	if v.Imsi != nil {
		enc_imsi := ber.EncodeOctetString([]byte(*v.Imsi))
		retagged_enc_imsi, tagErr_enc_imsi := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 12, enc_imsi)
		if tagErr_enc_imsi != nil {
			return nil, fmt.Errorf("encoding imsi: %w", tagErr_enc_imsi)
		}
		enc_imsi = retagged_enc_imsi
		children = append(children, enc_imsi...)
	}
	if v.T4TriggerIndicator != nil {
		enc_t4triggerindicator := ber.EncodeNull()
		retagged_enc_t4triggerindicator, tagErr_enc_t4triggerindicator := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 14, enc_t4triggerindicator)
		if tagErr_enc_t4triggerindicator != nil {
			return nil, fmt.Errorf("encoding t4-Trigger-Indicator: %w", tagErr_enc_t4triggerindicator)
		}
		enc_t4triggerindicator = retagged_enc_t4triggerindicator
		children = append(children, enc_t4triggerindicator...)
	}
	if v.SingleAttemptDelivery != nil {
		enc_singleattemptdelivery := ber.EncodeNull()
		retagged_enc_singleattemptdelivery, tagErr_enc_singleattemptdelivery := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 13, enc_singleattemptdelivery)
		if tagErr_enc_singleattemptdelivery != nil {
			return nil, fmt.Errorf("encoding singleAttemptDelivery: %w", tagErr_enc_singleattemptdelivery)
		}
		enc_singleattemptdelivery = retagged_enc_singleattemptdelivery
		children = append(children, enc_singleattemptdelivery...)
	}
	if v.CorrelationID != nil {
		enc_correlationid, err := v.CorrelationID.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding correlationID: %w", err)
		}
		retagged_enc_correlationid, tagErr_enc_correlationid := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 15, enc_correlationid)
		if tagErr_enc_correlationid != nil {
			return nil, fmt.Errorf("encoding correlationID: %w", tagErr_enc_correlationid)
		}
		enc_correlationid = retagged_enc_correlationid
		children = append(children, enc_correlationid...)
	}
	if v.SmsfSupportIndicator != nil {
		enc_smsfsupportindicator := ber.EncodeNull()
		retagged_enc_smsfsupportindicator, tagErr_enc_smsfsupportindicator := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 16, enc_smsfsupportindicator)
		if tagErr_enc_smsfsupportindicator != nil {
			return nil, fmt.Errorf("encoding smsf-supportIndicator: %w", tagErr_enc_smsfsupportindicator)
		}
		enc_smsfsupportindicator = retagged_enc_smsfsupportindicator
		children = append(children, enc_smsfsupportindicator...)
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

// MarshalDER encodes RoutingInfoForSMArg to DER format.
func (v *RoutingInfoForSMArg) MarshalDER() ([]byte, error) {
	var children []byte
	enc_msisdn := ber.EncodeOctetString([]byte(v.Msisdn))
	retagged_enc_msisdn, tagErr_enc_msisdn := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_msisdn)
	if tagErr_enc_msisdn != nil {
		return nil, fmt.Errorf("encoding msisdn: %w", tagErr_enc_msisdn)
	}
	enc_msisdn = retagged_enc_msisdn
	children = append(children, enc_msisdn...)
	enc_smrppri := ber.EncodeBoolean(v.SmRPPRI)
	retagged_enc_smrppri, tagErr_enc_smrppri := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_smrppri)
	if tagErr_enc_smrppri != nil {
		return nil, fmt.Errorf("encoding sm-RP-PRI: %w", tagErr_enc_smrppri)
	}
	enc_smrppri = retagged_enc_smrppri
	children = append(children, enc_smrppri...)
	enc_servicecentreaddress := ber.EncodeOctetString([]byte(v.ServiceCentreAddress))
	retagged_enc_servicecentreaddress, tagErr_enc_servicecentreaddress := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_servicecentreaddress)
	if tagErr_enc_servicecentreaddress != nil {
		return nil, fmt.Errorf("encoding serviceCentreAddress: %w", tagErr_enc_servicecentreaddress)
	}
	enc_servicecentreaddress = retagged_enc_servicecentreaddress
	children = append(children, enc_servicecentreaddress...)
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
	if v.GprsSupportIndicator != nil {
		enc_gprssupportindicator := ber.EncodeNull()
		retagged_enc_gprssupportindicator, tagErr_enc_gprssupportindicator := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 7, enc_gprssupportindicator)
		if tagErr_enc_gprssupportindicator != nil {
			return nil, fmt.Errorf("encoding gprsSupportIndicator: %w", tagErr_enc_gprssupportindicator)
		}
		enc_gprssupportindicator = retagged_enc_gprssupportindicator
		children = append(children, enc_gprssupportindicator...)
	}
	if v.SmRPMTI != nil {
		enc_smrpmti := ber.EncodeInteger(int64(*v.SmRPMTI))
		retagged_enc_smrpmti, tagErr_enc_smrpmti := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 8, enc_smrpmti)
		if tagErr_enc_smrpmti != nil {
			return nil, fmt.Errorf("encoding sm-RP-MTI: %w", tagErr_enc_smrpmti)
		}
		enc_smrpmti = retagged_enc_smrpmti
		children = append(children, enc_smrpmti...)
	}
	if v.SmRPSMEA != nil {
		enc_smrpsmea := ber.EncodeOctetString([]byte(*v.SmRPSMEA))
		retagged_enc_smrpsmea, tagErr_enc_smrpsmea := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 9, enc_smrpsmea)
		if tagErr_enc_smrpsmea != nil {
			return nil, fmt.Errorf("encoding sm-RP-SMEA: %w", tagErr_enc_smrpsmea)
		}
		enc_smrpsmea = retagged_enc_smrpsmea
		children = append(children, enc_smrpsmea...)
	}
	if v.SmDeliveryNotIntended != nil {
		enc_smdeliverynotintended := ber.EncodeEnumerated(int64(*v.SmDeliveryNotIntended))
		retagged_enc_smdeliverynotintended, tagErr_enc_smdeliverynotintended := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 10, enc_smdeliverynotintended)
		if tagErr_enc_smdeliverynotintended != nil {
			return nil, fmt.Errorf("encoding sm-deliveryNotIntended: %w", tagErr_enc_smdeliverynotintended)
		}
		enc_smdeliverynotintended = retagged_enc_smdeliverynotintended
		children = append(children, enc_smdeliverynotintended...)
	}
	if v.IpSmGwGuidanceIndicator != nil {
		enc_ipsmgwguidanceindicator := ber.EncodeNull()
		retagged_enc_ipsmgwguidanceindicator, tagErr_enc_ipsmgwguidanceindicator := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 11, enc_ipsmgwguidanceindicator)
		if tagErr_enc_ipsmgwguidanceindicator != nil {
			return nil, fmt.Errorf("encoding ip-sm-gwGuidanceIndicator: %w", tagErr_enc_ipsmgwguidanceindicator)
		}
		enc_ipsmgwguidanceindicator = retagged_enc_ipsmgwguidanceindicator
		children = append(children, enc_ipsmgwguidanceindicator...)
	}
	if v.Imsi != nil {
		enc_imsi := ber.EncodeOctetString([]byte(*v.Imsi))
		retagged_enc_imsi, tagErr_enc_imsi := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 12, enc_imsi)
		if tagErr_enc_imsi != nil {
			return nil, fmt.Errorf("encoding imsi: %w", tagErr_enc_imsi)
		}
		enc_imsi = retagged_enc_imsi
		children = append(children, enc_imsi...)
	}
	if v.T4TriggerIndicator != nil {
		enc_t4triggerindicator := ber.EncodeNull()
		retagged_enc_t4triggerindicator, tagErr_enc_t4triggerindicator := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 14, enc_t4triggerindicator)
		if tagErr_enc_t4triggerindicator != nil {
			return nil, fmt.Errorf("encoding t4-Trigger-Indicator: %w", tagErr_enc_t4triggerindicator)
		}
		enc_t4triggerindicator = retagged_enc_t4triggerindicator
		children = append(children, enc_t4triggerindicator...)
	}
	if v.SingleAttemptDelivery != nil {
		enc_singleattemptdelivery := ber.EncodeNull()
		retagged_enc_singleattemptdelivery, tagErr_enc_singleattemptdelivery := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 13, enc_singleattemptdelivery)
		if tagErr_enc_singleattemptdelivery != nil {
			return nil, fmt.Errorf("encoding singleAttemptDelivery: %w", tagErr_enc_singleattemptdelivery)
		}
		enc_singleattemptdelivery = retagged_enc_singleattemptdelivery
		children = append(children, enc_singleattemptdelivery...)
	}
	if v.CorrelationID != nil {
		enc_correlationid, err := v.CorrelationID.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding correlationID: %w", err)
		}
		retagged_enc_correlationid, tagErr_enc_correlationid := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 15, enc_correlationid)
		if tagErr_enc_correlationid != nil {
			return nil, fmt.Errorf("encoding correlationID: %w", tagErr_enc_correlationid)
		}
		enc_correlationid = retagged_enc_correlationid
		children = append(children, enc_correlationid...)
	}
	if v.SmsfSupportIndicator != nil {
		enc_smsfsupportindicator := ber.EncodeNull()
		retagged_enc_smsfsupportindicator, tagErr_enc_smsfsupportindicator := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 16, enc_smsfsupportindicator)
		if tagErr_enc_smsfsupportindicator != nil {
			return nil, fmt.Errorf("encoding smsf-supportIndicator: %w", tagErr_enc_smsfsupportindicator)
		}
		enc_smsfsupportindicator = retagged_enc_smsfsupportindicator
		children = append(children, enc_smsfsupportindicator...)
	}
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
		children = append(children, ext...)
	}
	encoded := ber.EncodeSequence(children)
	if err := ber.ValidateDERElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding RoutingInfoForSMArg as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes RoutingInfoForSMArg from BER/DER format.
func (v *RoutingInfoForSMArg) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding RoutingInfoForSMArg SEQUENCE: %w", err)
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
	decodedTag_msisdn, n_msisdn, rawVal_msisdn, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding msisdn: %w", err)
	}
	if decodedTag_msisdn.Class != tag.ClassContextSpecific || decodedTag_msisdn.Number != 0 {
		return fmt.Errorf("decoding msisdn: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_msisdn)
	}
	v.Msisdn = ISDNAddressString(rawVal_msisdn)
	offset += n_msisdn
	// Decode sm-RP-PRI
	if offset >= len(content) {
		return fmt.Errorf("missing required field sm-RP-PRI")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 1 {
			return fmt.Errorf("expected tag [%s %d] for sm-RP-PRI, got %s", "CONTEXT", 1, reqTag_)
		}
	}
	decodedTag_smrppri, n_smrppri, rawVal_smrppri, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding sm-RP-PRI: %w", err)
	}
	if decodedTag_smrppri.Class != tag.ClassContextSpecific || decodedTag_smrppri.Number != 1 || decodedTag_smrppri.Constructed != false {
		return fmt.Errorf("decoding sm-RP-PRI: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_smrppri)
	}
	decVal_smrppri, boolErr := ber.DecodeBooleanValue(rawVal_smrppri)
	if boolErr != nil {
		return fmt.Errorf("decoding sm-RP-PRI: %w", boolErr)
	}
	if len(rawVal_smrppri) == 1 {
		v.SmRPPRIRaw_ = rawVal_smrppri[0]
	}
	v.SmRPPRI = decVal_smrppri
	offset += n_smrppri
	// Decode serviceCentreAddress
	if offset >= len(content) {
		return fmt.Errorf("missing required field serviceCentreAddress")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 2 {
			return fmt.Errorf("expected tag [%s %d] for serviceCentreAddress, got %s", "CONTEXT", 2, reqTag_)
		}
	}
	decodedTag_servicecentreaddress, n_servicecentreaddress, rawVal_servicecentreaddress, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding serviceCentreAddress: %w", err)
	}
	if decodedTag_servicecentreaddress.Class != tag.ClassContextSpecific || decodedTag_servicecentreaddress.Number != 2 {
		return fmt.Errorf("decoding serviceCentreAddress: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_servicecentreaddress)
	}
	v.ServiceCentreAddress = AddressString(rawVal_servicecentreaddress)
	offset += n_servicecentreaddress
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
	// Decode gprsSupportIndicator
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 7 {
				decodedTag_gprssupportindicator, n_gprssupportindicator, rawVal_gprssupportindicator, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding gprsSupportIndicator: %w", err)
				}
				if decodedTag_gprssupportindicator.Class != tag.ClassContextSpecific || decodedTag_gprssupportindicator.Number != 7 || decodedTag_gprssupportindicator.Constructed != false {
					return fmt.Errorf("decoding gprsSupportIndicator: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_gprssupportindicator)
				}
				if len(rawVal_gprssupportindicator) != 0 {
					return fmt.Errorf("decoding gprsSupportIndicator: %w: NULL content length %d", ber.ErrInvalidValue, len(rawVal_gprssupportindicator))
				}
				v.GprsSupportIndicator = &struct{}{}
				offset += n_gprssupportindicator
			}
		}
	}
	// Decode sm-RP-MTI
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 8 {
				decodedTag_smrpmti, n_smrpmti, rawVal_smrpmti, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding sm-RP-MTI: %w", err)
				}
				if decodedTag_smrpmti.Class != tag.ClassContextSpecific || decodedTag_smrpmti.Number != 8 || decodedTag_smrpmti.Constructed != false {
					return fmt.Errorf("decoding sm-RP-MTI: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_smrpmti)
				}
				decVal_smrpmti, intErr := ber.DecodeIntegerValue(rawVal_smrpmti)
				if intErr != nil {
					return fmt.Errorf("decoding sm-RP-MTI: %w", intErr)
				}
				tmp_smrpmti := SMRPMTI(decVal_smrpmti)
				v.SmRPMTI = &tmp_smrpmti
				offset += n_smrpmti
			}
		}
	}
	// Decode sm-RP-SMEA
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 9 {
				decodedTag_smrpsmea, n_smrpsmea, rawVal_smrpsmea, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding sm-RP-SMEA: %w", err)
				}
				if decodedTag_smrpsmea.Class != tag.ClassContextSpecific || decodedTag_smrpsmea.Number != 9 {
					return fmt.Errorf("decoding sm-RP-SMEA: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_smrpsmea)
				}
				tmp_smrpsmea := SMRPSMEA(rawVal_smrpsmea)
				v.SmRPSMEA = &tmp_smrpsmea
				offset += n_smrpsmea
			}
		}
	}
	// Decode sm-deliveryNotIntended
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 10 {
				decodedTag_smdeliverynotintended, n_smdeliverynotintended, rawVal_smdeliverynotintended, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding sm-deliveryNotIntended: %w", err)
				}
				if decodedTag_smdeliverynotintended.Class != tag.ClassContextSpecific || decodedTag_smdeliverynotintended.Number != 10 || decodedTag_smdeliverynotintended.Constructed != false {
					return fmt.Errorf("decoding sm-deliveryNotIntended: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_smdeliverynotintended)
				}
				decVal_smdeliverynotintended, intErr := ber.DecodeIntegerValue(rawVal_smdeliverynotintended)
				if intErr != nil {
					return fmt.Errorf("decoding sm-deliveryNotIntended: %w", intErr)
				}
				tmp_smdeliverynotintended := SMDeliveryNotIntended(decVal_smdeliverynotintended)
				v.SmDeliveryNotIntended = &tmp_smdeliverynotintended
				offset += n_smdeliverynotintended
			}
		}
	}
	// Decode ip-sm-gwGuidanceIndicator
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 11 {
				decodedTag_ipsmgwguidanceindicator, n_ipsmgwguidanceindicator, rawVal_ipsmgwguidanceindicator, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding ip-sm-gwGuidanceIndicator: %w", err)
				}
				if decodedTag_ipsmgwguidanceindicator.Class != tag.ClassContextSpecific || decodedTag_ipsmgwguidanceindicator.Number != 11 || decodedTag_ipsmgwguidanceindicator.Constructed != false {
					return fmt.Errorf("decoding ip-sm-gwGuidanceIndicator: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_ipsmgwguidanceindicator)
				}
				if len(rawVal_ipsmgwguidanceindicator) != 0 {
					return fmt.Errorf("decoding ip-sm-gwGuidanceIndicator: %w: NULL content length %d", ber.ErrInvalidValue, len(rawVal_ipsmgwguidanceindicator))
				}
				v.IpSmGwGuidanceIndicator = &struct{}{}
				offset += n_ipsmgwguidanceindicator
			}
		}
	}
	// Decode imsi
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 12 {
				decodedTag_imsi, n_imsi, rawVal_imsi, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding imsi: %w", err)
				}
				if decodedTag_imsi.Class != tag.ClassContextSpecific || decodedTag_imsi.Number != 12 {
					return fmt.Errorf("decoding imsi: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_imsi)
				}
				tmp_imsi := IMSI(rawVal_imsi)
				v.Imsi = &tmp_imsi
				offset += n_imsi
			}
		}
	}
	// Decode t4-Trigger-Indicator
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 14 {
				decodedTag_t4triggerindicator, n_t4triggerindicator, rawVal_t4triggerindicator, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding t4-Trigger-Indicator: %w", err)
				}
				if decodedTag_t4triggerindicator.Class != tag.ClassContextSpecific || decodedTag_t4triggerindicator.Number != 14 || decodedTag_t4triggerindicator.Constructed != false {
					return fmt.Errorf("decoding t4-Trigger-Indicator: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_t4triggerindicator)
				}
				if len(rawVal_t4triggerindicator) != 0 {
					return fmt.Errorf("decoding t4-Trigger-Indicator: %w: NULL content length %d", ber.ErrInvalidValue, len(rawVal_t4triggerindicator))
				}
				v.T4TriggerIndicator = &struct{}{}
				offset += n_t4triggerindicator
			}
		}
	}
	// Decode singleAttemptDelivery
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 13 {
				decodedTag_singleattemptdelivery, n_singleattemptdelivery, rawVal_singleattemptdelivery, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding singleAttemptDelivery: %w", err)
				}
				if decodedTag_singleattemptdelivery.Class != tag.ClassContextSpecific || decodedTag_singleattemptdelivery.Number != 13 || decodedTag_singleattemptdelivery.Constructed != false {
					return fmt.Errorf("decoding singleAttemptDelivery: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_singleattemptdelivery)
				}
				if len(rawVal_singleattemptdelivery) != 0 {
					return fmt.Errorf("decoding singleAttemptDelivery: %w: NULL content length %d", ber.ErrInvalidValue, len(rawVal_singleattemptdelivery))
				}
				v.SingleAttemptDelivery = &struct{}{}
				offset += n_singleattemptdelivery
			}
		}
	}
	// Decode correlationID
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 15 {
				decodedTag_correlationid, n_correlationid, rawVal_correlationid, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding correlationID: %w", err)
				}
				if decodedTag_correlationid.Class != tag.ClassContextSpecific || decodedTag_correlationid.Number != 15 || decodedTag_correlationid.Constructed != true {
					return fmt.Errorf("decoding correlationID: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_correlationid)
				}
				reconstructed_correlationid := ber.EncodeSequence(rawVal_correlationid)
				var dec_correlationid CorrelationID
				if unmErr := dec_correlationid.UnmarshalBER(reconstructed_correlationid); unmErr != nil {
					return fmt.Errorf("decoding correlationID: %w", unmErr)
				}
				v.CorrelationID = &dec_correlationid
				offset += n_correlationid
			}
		}
	}
	// Decode smsf-supportIndicator
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 16 {
				decodedTag_smsfsupportindicator, n_smsfsupportindicator, rawVal_smsfsupportindicator, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding smsf-supportIndicator: %w", err)
				}
				if decodedTag_smsfsupportindicator.Class != tag.ClassContextSpecific || decodedTag_smsfsupportindicator.Number != 16 || decodedTag_smsfsupportindicator.Constructed != false {
					return fmt.Errorf("decoding smsf-supportIndicator: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_smsfsupportindicator)
				}
				if len(rawVal_smsfsupportindicator) != 0 {
					return fmt.Errorf("decoding smsf-supportIndicator: %w: NULL content length %d", ber.ErrInvalidValue, len(rawVal_smsfsupportindicator))
				}
				v.SmsfSupportIndicator = &struct{}{}
				offset += n_smsfsupportindicator
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "RoutingInfoForSMArg", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes RoutingInfoForSMRes to BER format.
func (v *RoutingInfoForSMRes) MarshalBER() ([]byte, error) {
	var children []byte
	enc_imsi := ber.EncodeOctetString([]byte(v.Imsi))
	children = append(children, enc_imsi...)
	enc_locationinfowithlmsi, err := v.LocationInfoWithLMSI.MarshalBER()
	if err != nil {
		return nil, fmt.Errorf("encoding locationInfoWithLMSI: %w", err)
	}
	retagged_enc_locationinfowithlmsi, tagErr_enc_locationinfowithlmsi := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_locationinfowithlmsi)
	if tagErr_enc_locationinfowithlmsi != nil {
		return nil, fmt.Errorf("encoding locationInfoWithLMSI: %w", tagErr_enc_locationinfowithlmsi)
	}
	enc_locationinfowithlmsi = retagged_enc_locationinfowithlmsi
	children = append(children, enc_locationinfowithlmsi...)
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
	if v.IpSmGwGuidance != nil {
		enc_ipsmgwguidance, err := v.IpSmGwGuidance.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding ip-sm-gwGuidance: %w", err)
		}
		retagged_enc_ipsmgwguidance, tagErr_enc_ipsmgwguidance := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 5, enc_ipsmgwguidance)
		if tagErr_enc_ipsmgwguidance != nil {
			return nil, fmt.Errorf("encoding ip-sm-gwGuidance: %w", tagErr_enc_ipsmgwguidance)
		}
		enc_ipsmgwguidance = retagged_enc_ipsmgwguidance
		children = append(children, enc_ipsmgwguidance...)
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

// MarshalDER encodes RoutingInfoForSMRes to DER format.
func (v *RoutingInfoForSMRes) MarshalDER() ([]byte, error) {
	var children []byte
	enc_imsi := ber.EncodeOctetString([]byte(v.Imsi))
	children = append(children, enc_imsi...)
	enc_locationinfowithlmsi, err := v.LocationInfoWithLMSI.MarshalDER()
	if err != nil {
		return nil, fmt.Errorf("encoding locationInfoWithLMSI: %w", err)
	}
	retagged_enc_locationinfowithlmsi, tagErr_enc_locationinfowithlmsi := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_locationinfowithlmsi)
	if tagErr_enc_locationinfowithlmsi != nil {
		return nil, fmt.Errorf("encoding locationInfoWithLMSI: %w", tagErr_enc_locationinfowithlmsi)
	}
	enc_locationinfowithlmsi = retagged_enc_locationinfowithlmsi
	children = append(children, enc_locationinfowithlmsi...)
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
	if v.IpSmGwGuidance != nil {
		enc_ipsmgwguidance, err := v.IpSmGwGuidance.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding ip-sm-gwGuidance: %w", err)
		}
		retagged_enc_ipsmgwguidance, tagErr_enc_ipsmgwguidance := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 5, enc_ipsmgwguidance)
		if tagErr_enc_ipsmgwguidance != nil {
			return nil, fmt.Errorf("encoding ip-sm-gwGuidance: %w", tagErr_enc_ipsmgwguidance)
		}
		enc_ipsmgwguidance = retagged_enc_ipsmgwguidance
		children = append(children, enc_ipsmgwguidance...)
	}
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
		children = append(children, ext...)
	}
	encoded := ber.EncodeSequence(children)
	if err := ber.ValidateDERElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding RoutingInfoForSMRes as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes RoutingInfoForSMRes from BER/DER format.
func (v *RoutingInfoForSMRes) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding RoutingInfoForSMRes SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "RoutingInfoForSMRes", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode imsi
	if offset >= len(content) {
		return fmt.Errorf("missing required field imsi")
	}
	val_imsi, n, err := ber.DecodeOctetString(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding imsi: %w", err)
	}
	v.Imsi = IMSI(val_imsi)
	offset += n
	// Decode locationInfoWithLMSI
	if offset >= len(content) {
		return fmt.Errorf("missing required field locationInfoWithLMSI")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 0 {
			return fmt.Errorf("expected tag [%s %d] for locationInfoWithLMSI, got %s", "CONTEXT", 0, reqTag_)
		}
	}
	decodedTag_locationinfowithlmsi, n_locationinfowithlmsi, rawVal_locationinfowithlmsi, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding locationInfoWithLMSI: %w", err)
	}
	if decodedTag_locationinfowithlmsi.Class != tag.ClassContextSpecific || decodedTag_locationinfowithlmsi.Number != 0 || decodedTag_locationinfowithlmsi.Constructed != true {
		return fmt.Errorf("decoding locationInfoWithLMSI: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_locationinfowithlmsi)
	}
	reconstructed_locationinfowithlmsi := ber.EncodeSequence(rawVal_locationinfowithlmsi)
	if unmErr := v.LocationInfoWithLMSI.UnmarshalBER(reconstructed_locationinfowithlmsi); unmErr != nil {
		return fmt.Errorf("decoding locationInfoWithLMSI: %w", unmErr)
	}
	offset += n_locationinfowithlmsi
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
	// Decode ip-sm-gwGuidance
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 5 {
				decodedTag_ipsmgwguidance, n_ipsmgwguidance, rawVal_ipsmgwguidance, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding ip-sm-gwGuidance: %w", err)
				}
				if decodedTag_ipsmgwguidance.Class != tag.ClassContextSpecific || decodedTag_ipsmgwguidance.Number != 5 || decodedTag_ipsmgwguidance.Constructed != true {
					return fmt.Errorf("decoding ip-sm-gwGuidance: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_ipsmgwguidance)
				}
				reconstructed_ipsmgwguidance := ber.EncodeSequence(rawVal_ipsmgwguidance)
				var dec_ipsmgwguidance IPSMGWGuidance
				if unmErr := dec_ipsmgwguidance.UnmarshalBER(reconstructed_ipsmgwguidance); unmErr != nil {
					return fmt.Errorf("decoding ip-sm-gwGuidance: %w", unmErr)
				}
				v.IpSmGwGuidance = &dec_ipsmgwguidance
				offset += n_ipsmgwguidance
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "RoutingInfoForSMRes", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes IPSMGWGuidance to BER format.
func (v *IPSMGWGuidance) MarshalBER() ([]byte, error) {
	var children []byte
	enc_minimumdeliverytimevalue := ber.EncodeInteger(int64(v.MinimumDeliveryTimeValue))
	children = append(children, enc_minimumdeliverytimevalue...)
	enc_recommendeddeliverytimevalue := ber.EncodeInteger(int64(v.RecommendedDeliveryTimeValue))
	children = append(children, enc_recommendeddeliverytimevalue...)
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

// MarshalDER encodes IPSMGWGuidance to DER format.
func (v *IPSMGWGuidance) MarshalDER() ([]byte, error) {
	var children []byte
	enc_minimumdeliverytimevalue := ber.EncodeInteger(int64(v.MinimumDeliveryTimeValue))
	children = append(children, enc_minimumdeliverytimevalue...)
	enc_recommendeddeliverytimevalue := ber.EncodeInteger(int64(v.RecommendedDeliveryTimeValue))
	children = append(children, enc_recommendeddeliverytimevalue...)
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
		return nil, fmt.Errorf("encoding IPSMGWGuidance as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes IPSMGWGuidance from BER/DER format.
func (v *IPSMGWGuidance) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding IPSMGWGuidance SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "IPSMGWGuidance", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode minimumDeliveryTimeValue
	if offset >= len(content) {
		return fmt.Errorf("missing required field minimumDeliveryTimeValue")
	}
	val_minimumdeliverytimevalue, n, err := ber.DecodeInteger(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding minimumDeliveryTimeValue: %w", err)
	}
	v.MinimumDeliveryTimeValue = SMDeliveryTimerValue(val_minimumdeliverytimevalue)
	offset += n
	// Decode recommendedDeliveryTimeValue
	if offset >= len(content) {
		return fmt.Errorf("missing required field recommendedDeliveryTimeValue")
	}
	val_recommendeddeliverytimevalue, n, err := ber.DecodeInteger(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding recommendedDeliveryTimeValue: %w", err)
	}
	v.RecommendedDeliveryTimeValue = SMDeliveryTimerValue(val_recommendeddeliverytimevalue)
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
			return &ber.DecodeError{Offset: offset, TypeName: "IPSMGWGuidance", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes LocationInfoWithLMSI to BER format.
func (v *LocationInfoWithLMSI) MarshalBER() ([]byte, error) {
	var children []byte
	enc_networknodenumber := ber.EncodeOctetString([]byte(v.NetworkNodeNumber))
	retagged_enc_networknodenumber, tagErr_enc_networknodenumber := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_networknodenumber)
	if tagErr_enc_networknodenumber != nil {
		return nil, fmt.Errorf("encoding networkNode-Number: %w", tagErr_enc_networknodenumber)
	}
	enc_networknodenumber = retagged_enc_networknodenumber
	children = append(children, enc_networknodenumber...)
	if v.Lmsi != nil {
		enc_lmsi := ber.EncodeOctetString([]byte(*v.Lmsi))
		children = append(children, enc_lmsi...)
	}
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding extensionContainer: %w", err)
		}
		children = append(children, enc_extensioncontainer...)
	}
	if v.GprsNodeIndicator != nil {
		enc_gprsnodeindicator := ber.EncodeNull()
		retagged_enc_gprsnodeindicator, tagErr_enc_gprsnodeindicator := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 5, enc_gprsnodeindicator)
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
		enc_additionalnumber = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 6, enc_additionalnumber)
		children = append(children, enc_additionalnumber...)
	}
	if v.NetworkNodeDiameterAddress != nil {
		enc_networknodediameteraddress, err := v.NetworkNodeDiameterAddress.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding networkNodeDiameterAddress: %w", err)
		}
		retagged_enc_networknodediameteraddress, tagErr_enc_networknodediameteraddress := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 7, enc_networknodediameteraddress)
		if tagErr_enc_networknodediameteraddress != nil {
			return nil, fmt.Errorf("encoding networkNodeDiameterAddress: %w", tagErr_enc_networknodediameteraddress)
		}
		enc_networknodediameteraddress = retagged_enc_networknodediameteraddress
		children = append(children, enc_networknodediameteraddress...)
	}
	if v.AdditionalNetworkNodeDiameterAddress != nil {
		enc_additionalnetworknodediameteraddress, err := v.AdditionalNetworkNodeDiameterAddress.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding additionalNetworkNodeDiameterAddress: %w", err)
		}
		retagged_enc_additionalnetworknodediameteraddress, tagErr_enc_additionalnetworknodediameteraddress := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 8, enc_additionalnetworknodediameteraddress)
		if tagErr_enc_additionalnetworknodediameteraddress != nil {
			return nil, fmt.Errorf("encoding additionalNetworkNodeDiameterAddress: %w", tagErr_enc_additionalnetworknodediameteraddress)
		}
		enc_additionalnetworknodediameteraddress = retagged_enc_additionalnetworknodediameteraddress
		children = append(children, enc_additionalnetworknodediameteraddress...)
	}
	if v.ThirdNumber != nil {
		enc_thirdnumber, err := v.ThirdNumber.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding thirdNumber: %w", err)
		}
		enc_thirdnumber = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 9, enc_thirdnumber)
		children = append(children, enc_thirdnumber...)
	}
	if v.ThirdNetworkNodeDiameterAddress != nil {
		enc_thirdnetworknodediameteraddress, err := v.ThirdNetworkNodeDiameterAddress.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding thirdNetworkNodeDiameterAddress: %w", err)
		}
		retagged_enc_thirdnetworknodediameteraddress, tagErr_enc_thirdnetworknodediameteraddress := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 10, enc_thirdnetworknodediameteraddress)
		if tagErr_enc_thirdnetworknodediameteraddress != nil {
			return nil, fmt.Errorf("encoding thirdNetworkNodeDiameterAddress: %w", tagErr_enc_thirdnetworknodediameteraddress)
		}
		enc_thirdnetworknodediameteraddress = retagged_enc_thirdnetworknodediameteraddress
		children = append(children, enc_thirdnetworknodediameteraddress...)
	}
	if v.ImsNodeIndicator != nil {
		enc_imsnodeindicator := ber.EncodeNull()
		retagged_enc_imsnodeindicator, tagErr_enc_imsnodeindicator := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 11, enc_imsnodeindicator)
		if tagErr_enc_imsnodeindicator != nil {
			return nil, fmt.Errorf("encoding imsNodeIndicator: %w", tagErr_enc_imsnodeindicator)
		}
		enc_imsnodeindicator = retagged_enc_imsnodeindicator
		children = append(children, enc_imsnodeindicator...)
	}
	if v.Smsf3gppNumber != nil {
		enc_smsf3gppnumber := ber.EncodeOctetString([]byte(*v.Smsf3gppNumber))
		retagged_enc_smsf3gppnumber, tagErr_enc_smsf3gppnumber := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 12, enc_smsf3gppnumber)
		if tagErr_enc_smsf3gppnumber != nil {
			return nil, fmt.Errorf("encoding smsf-3gpp-Number: %w", tagErr_enc_smsf3gppnumber)
		}
		enc_smsf3gppnumber = retagged_enc_smsf3gppnumber
		children = append(children, enc_smsf3gppnumber...)
	}
	if v.Smsf3gppDiameterAddress != nil {
		enc_smsf3gppdiameteraddress, err := v.Smsf3gppDiameterAddress.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding smsf-3gpp-DiameterAddress: %w", err)
		}
		retagged_enc_smsf3gppdiameteraddress, tagErr_enc_smsf3gppdiameteraddress := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 13, enc_smsf3gppdiameteraddress)
		if tagErr_enc_smsf3gppdiameteraddress != nil {
			return nil, fmt.Errorf("encoding smsf-3gpp-DiameterAddress: %w", tagErr_enc_smsf3gppdiameteraddress)
		}
		enc_smsf3gppdiameteraddress = retagged_enc_smsf3gppdiameteraddress
		children = append(children, enc_smsf3gppdiameteraddress...)
	}
	if v.SmsfNon3gppNumber != nil {
		enc_smsfnon3gppnumber := ber.EncodeOctetString([]byte(*v.SmsfNon3gppNumber))
		retagged_enc_smsfnon3gppnumber, tagErr_enc_smsfnon3gppnumber := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 14, enc_smsfnon3gppnumber)
		if tagErr_enc_smsfnon3gppnumber != nil {
			return nil, fmt.Errorf("encoding smsf-non-3gpp-Number: %w", tagErr_enc_smsfnon3gppnumber)
		}
		enc_smsfnon3gppnumber = retagged_enc_smsfnon3gppnumber
		children = append(children, enc_smsfnon3gppnumber...)
	}
	if v.SmsfNon3gppDiameterAddress != nil {
		enc_smsfnon3gppdiameteraddress, err := v.SmsfNon3gppDiameterAddress.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding smsf-non-3gpp-DiameterAddress: %w", err)
		}
		retagged_enc_smsfnon3gppdiameteraddress, tagErr_enc_smsfnon3gppdiameteraddress := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 15, enc_smsfnon3gppdiameteraddress)
		if tagErr_enc_smsfnon3gppdiameteraddress != nil {
			return nil, fmt.Errorf("encoding smsf-non-3gpp-DiameterAddress: %w", tagErr_enc_smsfnon3gppdiameteraddress)
		}
		enc_smsfnon3gppdiameteraddress = retagged_enc_smsfnon3gppdiameteraddress
		children = append(children, enc_smsfnon3gppdiameteraddress...)
	}
	if v.Smsf3gppAddressIndicator != nil {
		enc_smsf3gppaddressindicator := ber.EncodeNull()
		retagged_enc_smsf3gppaddressindicator, tagErr_enc_smsf3gppaddressindicator := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 16, enc_smsf3gppaddressindicator)
		if tagErr_enc_smsf3gppaddressindicator != nil {
			return nil, fmt.Errorf("encoding smsf-3gpp-address-indicator: %w", tagErr_enc_smsf3gppaddressindicator)
		}
		enc_smsf3gppaddressindicator = retagged_enc_smsf3gppaddressindicator
		children = append(children, enc_smsf3gppaddressindicator...)
	}
	if v.SmsfNon3gppAddressIndicator != nil {
		enc_smsfnon3gppaddressindicator := ber.EncodeNull()
		retagged_enc_smsfnon3gppaddressindicator, tagErr_enc_smsfnon3gppaddressindicator := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 17, enc_smsfnon3gppaddressindicator)
		if tagErr_enc_smsfnon3gppaddressindicator != nil {
			return nil, fmt.Errorf("encoding smsf-non-3gpp-address-indicator: %w", tagErr_enc_smsfnon3gppaddressindicator)
		}
		enc_smsfnon3gppaddressindicator = retagged_enc_smsfnon3gppaddressindicator
		children = append(children, enc_smsfnon3gppaddressindicator...)
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

// MarshalDER encodes LocationInfoWithLMSI to DER format.
func (v *LocationInfoWithLMSI) MarshalDER() ([]byte, error) {
	var children []byte
	enc_networknodenumber := ber.EncodeOctetString([]byte(v.NetworkNodeNumber))
	retagged_enc_networknodenumber, tagErr_enc_networknodenumber := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_networknodenumber)
	if tagErr_enc_networknodenumber != nil {
		return nil, fmt.Errorf("encoding networkNode-Number: %w", tagErr_enc_networknodenumber)
	}
	enc_networknodenumber = retagged_enc_networknodenumber
	children = append(children, enc_networknodenumber...)
	if v.Lmsi != nil {
		enc_lmsi := ber.EncodeOctetString([]byte(*v.Lmsi))
		children = append(children, enc_lmsi...)
	}
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding extensionContainer: %w", err)
		}
		children = append(children, enc_extensioncontainer...)
	}
	if v.GprsNodeIndicator != nil {
		enc_gprsnodeindicator := ber.EncodeNull()
		retagged_enc_gprsnodeindicator, tagErr_enc_gprsnodeindicator := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 5, enc_gprsnodeindicator)
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
		enc_additionalnumber = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 6, enc_additionalnumber)
		children = append(children, enc_additionalnumber...)
	}
	if v.NetworkNodeDiameterAddress != nil {
		enc_networknodediameteraddress, err := v.NetworkNodeDiameterAddress.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding networkNodeDiameterAddress: %w", err)
		}
		retagged_enc_networknodediameteraddress, tagErr_enc_networknodediameteraddress := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 7, enc_networknodediameteraddress)
		if tagErr_enc_networknodediameteraddress != nil {
			return nil, fmt.Errorf("encoding networkNodeDiameterAddress: %w", tagErr_enc_networknodediameteraddress)
		}
		enc_networknodediameteraddress = retagged_enc_networknodediameteraddress
		children = append(children, enc_networknodediameteraddress...)
	}
	if v.AdditionalNetworkNodeDiameterAddress != nil {
		enc_additionalnetworknodediameteraddress, err := v.AdditionalNetworkNodeDiameterAddress.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding additionalNetworkNodeDiameterAddress: %w", err)
		}
		retagged_enc_additionalnetworknodediameteraddress, tagErr_enc_additionalnetworknodediameteraddress := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 8, enc_additionalnetworknodediameteraddress)
		if tagErr_enc_additionalnetworknodediameteraddress != nil {
			return nil, fmt.Errorf("encoding additionalNetworkNodeDiameterAddress: %w", tagErr_enc_additionalnetworknodediameteraddress)
		}
		enc_additionalnetworknodediameteraddress = retagged_enc_additionalnetworknodediameteraddress
		children = append(children, enc_additionalnetworknodediameteraddress...)
	}
	if v.ThirdNumber != nil {
		enc_thirdnumber, err := v.ThirdNumber.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding thirdNumber: %w", err)
		}
		enc_thirdnumber = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 9, enc_thirdnumber)
		children = append(children, enc_thirdnumber...)
	}
	if v.ThirdNetworkNodeDiameterAddress != nil {
		enc_thirdnetworknodediameteraddress, err := v.ThirdNetworkNodeDiameterAddress.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding thirdNetworkNodeDiameterAddress: %w", err)
		}
		retagged_enc_thirdnetworknodediameteraddress, tagErr_enc_thirdnetworknodediameteraddress := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 10, enc_thirdnetworknodediameteraddress)
		if tagErr_enc_thirdnetworknodediameteraddress != nil {
			return nil, fmt.Errorf("encoding thirdNetworkNodeDiameterAddress: %w", tagErr_enc_thirdnetworknodediameteraddress)
		}
		enc_thirdnetworknodediameteraddress = retagged_enc_thirdnetworknodediameteraddress
		children = append(children, enc_thirdnetworknodediameteraddress...)
	}
	if v.ImsNodeIndicator != nil {
		enc_imsnodeindicator := ber.EncodeNull()
		retagged_enc_imsnodeindicator, tagErr_enc_imsnodeindicator := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 11, enc_imsnodeindicator)
		if tagErr_enc_imsnodeindicator != nil {
			return nil, fmt.Errorf("encoding imsNodeIndicator: %w", tagErr_enc_imsnodeindicator)
		}
		enc_imsnodeindicator = retagged_enc_imsnodeindicator
		children = append(children, enc_imsnodeindicator...)
	}
	if v.Smsf3gppNumber != nil {
		enc_smsf3gppnumber := ber.EncodeOctetString([]byte(*v.Smsf3gppNumber))
		retagged_enc_smsf3gppnumber, tagErr_enc_smsf3gppnumber := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 12, enc_smsf3gppnumber)
		if tagErr_enc_smsf3gppnumber != nil {
			return nil, fmt.Errorf("encoding smsf-3gpp-Number: %w", tagErr_enc_smsf3gppnumber)
		}
		enc_smsf3gppnumber = retagged_enc_smsf3gppnumber
		children = append(children, enc_smsf3gppnumber...)
	}
	if v.Smsf3gppDiameterAddress != nil {
		enc_smsf3gppdiameteraddress, err := v.Smsf3gppDiameterAddress.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding smsf-3gpp-DiameterAddress: %w", err)
		}
		retagged_enc_smsf3gppdiameteraddress, tagErr_enc_smsf3gppdiameteraddress := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 13, enc_smsf3gppdiameteraddress)
		if tagErr_enc_smsf3gppdiameteraddress != nil {
			return nil, fmt.Errorf("encoding smsf-3gpp-DiameterAddress: %w", tagErr_enc_smsf3gppdiameteraddress)
		}
		enc_smsf3gppdiameteraddress = retagged_enc_smsf3gppdiameteraddress
		children = append(children, enc_smsf3gppdiameteraddress...)
	}
	if v.SmsfNon3gppNumber != nil {
		enc_smsfnon3gppnumber := ber.EncodeOctetString([]byte(*v.SmsfNon3gppNumber))
		retagged_enc_smsfnon3gppnumber, tagErr_enc_smsfnon3gppnumber := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 14, enc_smsfnon3gppnumber)
		if tagErr_enc_smsfnon3gppnumber != nil {
			return nil, fmt.Errorf("encoding smsf-non-3gpp-Number: %w", tagErr_enc_smsfnon3gppnumber)
		}
		enc_smsfnon3gppnumber = retagged_enc_smsfnon3gppnumber
		children = append(children, enc_smsfnon3gppnumber...)
	}
	if v.SmsfNon3gppDiameterAddress != nil {
		enc_smsfnon3gppdiameteraddress, err := v.SmsfNon3gppDiameterAddress.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding smsf-non-3gpp-DiameterAddress: %w", err)
		}
		retagged_enc_smsfnon3gppdiameteraddress, tagErr_enc_smsfnon3gppdiameteraddress := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 15, enc_smsfnon3gppdiameteraddress)
		if tagErr_enc_smsfnon3gppdiameteraddress != nil {
			return nil, fmt.Errorf("encoding smsf-non-3gpp-DiameterAddress: %w", tagErr_enc_smsfnon3gppdiameteraddress)
		}
		enc_smsfnon3gppdiameteraddress = retagged_enc_smsfnon3gppdiameteraddress
		children = append(children, enc_smsfnon3gppdiameteraddress...)
	}
	if v.Smsf3gppAddressIndicator != nil {
		enc_smsf3gppaddressindicator := ber.EncodeNull()
		retagged_enc_smsf3gppaddressindicator, tagErr_enc_smsf3gppaddressindicator := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 16, enc_smsf3gppaddressindicator)
		if tagErr_enc_smsf3gppaddressindicator != nil {
			return nil, fmt.Errorf("encoding smsf-3gpp-address-indicator: %w", tagErr_enc_smsf3gppaddressindicator)
		}
		enc_smsf3gppaddressindicator = retagged_enc_smsf3gppaddressindicator
		children = append(children, enc_smsf3gppaddressindicator...)
	}
	if v.SmsfNon3gppAddressIndicator != nil {
		enc_smsfnon3gppaddressindicator := ber.EncodeNull()
		retagged_enc_smsfnon3gppaddressindicator, tagErr_enc_smsfnon3gppaddressindicator := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 17, enc_smsfnon3gppaddressindicator)
		if tagErr_enc_smsfnon3gppaddressindicator != nil {
			return nil, fmt.Errorf("encoding smsf-non-3gpp-address-indicator: %w", tagErr_enc_smsfnon3gppaddressindicator)
		}
		enc_smsfnon3gppaddressindicator = retagged_enc_smsfnon3gppaddressindicator
		children = append(children, enc_smsfnon3gppaddressindicator...)
	}
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
		children = append(children, ext...)
	}
	encoded := ber.EncodeSequence(children)
	if err := ber.ValidateDERElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding LocationInfoWithLMSI as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes LocationInfoWithLMSI from BER/DER format.
func (v *LocationInfoWithLMSI) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding LocationInfoWithLMSI SEQUENCE: %w", err)
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
	decodedTag_networknodenumber, n_networknodenumber, rawVal_networknodenumber, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding networkNode-Number: %w", err)
	}
	if decodedTag_networknodenumber.Class != tag.ClassContextSpecific || decodedTag_networknodenumber.Number != 1 {
		return fmt.Errorf("decoding networkNode-Number: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_networknodenumber)
	}
	v.NetworkNodeNumber = ISDNAddressString(rawVal_networknodenumber)
	offset += n_networknodenumber
	// Decode lmsi
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassUniversal && peekTag.Number == 4 {
				val_lmsi, n, err := ber.DecodeOctetString(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding lmsi: %w", err)
				}
				tmp_lmsi := LMSI(val_lmsi)
				v.Lmsi = &tmp_lmsi
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
	// Decode gprsNodeIndicator
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 5 {
				decodedTag_gprsnodeindicator, n_gprsnodeindicator, rawVal_gprsnodeindicator, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding gprsNodeIndicator: %w", err)
				}
				if decodedTag_gprsnodeindicator.Class != tag.ClassContextSpecific || decodedTag_gprsnodeindicator.Number != 5 || decodedTag_gprsnodeindicator.Constructed != false {
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
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 6 {
				decodedTag_additionalnumber, n_additionalnumber, innerData_additionalnumber, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding additional-Number: %w", err)
				}
				if decodedTag_additionalnumber.Class != tag.ClassContextSpecific || decodedTag_additionalnumber.Number != 6 || decodedTag_additionalnumber.Constructed != true {
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
	// Decode networkNodeDiameterAddress
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 7 {
				decodedTag_networknodediameteraddress, n_networknodediameteraddress, rawVal_networknodediameteraddress, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding networkNodeDiameterAddress: %w", err)
				}
				if decodedTag_networknodediameteraddress.Class != tag.ClassContextSpecific || decodedTag_networknodediameteraddress.Number != 7 || decodedTag_networknodediameteraddress.Constructed != true {
					return fmt.Errorf("decoding networkNodeDiameterAddress: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_networknodediameteraddress)
				}
				reconstructed_networknodediameteraddress := ber.EncodeSequence(rawVal_networknodediameteraddress)
				var dec_networknodediameteraddress NetworkNodeDiameterAddress
				if unmErr := dec_networknodediameteraddress.UnmarshalBER(reconstructed_networknodediameteraddress); unmErr != nil {
					return fmt.Errorf("decoding networkNodeDiameterAddress: %w", unmErr)
				}
				v.NetworkNodeDiameterAddress = &dec_networknodediameteraddress
				offset += n_networknodediameteraddress
			}
		}
	}
	// Decode additionalNetworkNodeDiameterAddress
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 8 {
				decodedTag_additionalnetworknodediameteraddress, n_additionalnetworknodediameteraddress, rawVal_additionalnetworknodediameteraddress, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding additionalNetworkNodeDiameterAddress: %w", err)
				}
				if decodedTag_additionalnetworknodediameteraddress.Class != tag.ClassContextSpecific || decodedTag_additionalnetworknodediameteraddress.Number != 8 || decodedTag_additionalnetworknodediameteraddress.Constructed != true {
					return fmt.Errorf("decoding additionalNetworkNodeDiameterAddress: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_additionalnetworknodediameteraddress)
				}
				reconstructed_additionalnetworknodediameteraddress := ber.EncodeSequence(rawVal_additionalnetworknodediameteraddress)
				var dec_additionalnetworknodediameteraddress NetworkNodeDiameterAddress
				if unmErr := dec_additionalnetworknodediameteraddress.UnmarshalBER(reconstructed_additionalnetworknodediameteraddress); unmErr != nil {
					return fmt.Errorf("decoding additionalNetworkNodeDiameterAddress: %w", unmErr)
				}
				v.AdditionalNetworkNodeDiameterAddress = &dec_additionalnetworknodediameteraddress
				offset += n_additionalnetworknodediameteraddress
			}
		}
	}
	// Decode thirdNumber
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 9 {
				decodedTag_thirdnumber, n_thirdnumber, innerData_thirdnumber, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding thirdNumber: %w", err)
				}
				if decodedTag_thirdnumber.Class != tag.ClassContextSpecific || decodedTag_thirdnumber.Number != 9 || decodedTag_thirdnumber.Constructed != true {
					return fmt.Errorf("decoding thirdNumber: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_thirdnumber)
				}
				// Decode inner value from explicit tag wrapper
				var dec_thirdnumber AdditionalNumber
				if unmErr := dec_thirdnumber.UnmarshalBER(innerData_thirdnumber); unmErr != nil {
					return fmt.Errorf("decoding thirdNumber: %w", unmErr)
				}
				v.ThirdNumber = &dec_thirdnumber
				offset += n_thirdnumber
			}
		}
	}
	// Decode thirdNetworkNodeDiameterAddress
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 10 {
				decodedTag_thirdnetworknodediameteraddress, n_thirdnetworknodediameteraddress, rawVal_thirdnetworknodediameteraddress, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding thirdNetworkNodeDiameterAddress: %w", err)
				}
				if decodedTag_thirdnetworknodediameteraddress.Class != tag.ClassContextSpecific || decodedTag_thirdnetworknodediameteraddress.Number != 10 || decodedTag_thirdnetworknodediameteraddress.Constructed != true {
					return fmt.Errorf("decoding thirdNetworkNodeDiameterAddress: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_thirdnetworknodediameteraddress)
				}
				reconstructed_thirdnetworknodediameteraddress := ber.EncodeSequence(rawVal_thirdnetworknodediameteraddress)
				var dec_thirdnetworknodediameteraddress NetworkNodeDiameterAddress
				if unmErr := dec_thirdnetworknodediameteraddress.UnmarshalBER(reconstructed_thirdnetworknodediameteraddress); unmErr != nil {
					return fmt.Errorf("decoding thirdNetworkNodeDiameterAddress: %w", unmErr)
				}
				v.ThirdNetworkNodeDiameterAddress = &dec_thirdnetworknodediameteraddress
				offset += n_thirdnetworknodediameteraddress
			}
		}
	}
	// Decode imsNodeIndicator
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 11 {
				decodedTag_imsnodeindicator, n_imsnodeindicator, rawVal_imsnodeindicator, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding imsNodeIndicator: %w", err)
				}
				if decodedTag_imsnodeindicator.Class != tag.ClassContextSpecific || decodedTag_imsnodeindicator.Number != 11 || decodedTag_imsnodeindicator.Constructed != false {
					return fmt.Errorf("decoding imsNodeIndicator: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_imsnodeindicator)
				}
				if len(rawVal_imsnodeindicator) != 0 {
					return fmt.Errorf("decoding imsNodeIndicator: %w: NULL content length %d", ber.ErrInvalidValue, len(rawVal_imsnodeindicator))
				}
				v.ImsNodeIndicator = &struct{}{}
				offset += n_imsnodeindicator
			}
		}
	}
	// Decode smsf-3gpp-Number
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 12 {
				decodedTag_smsf3gppnumber, n_smsf3gppnumber, rawVal_smsf3gppnumber, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding smsf-3gpp-Number: %w", err)
				}
				if decodedTag_smsf3gppnumber.Class != tag.ClassContextSpecific || decodedTag_smsf3gppnumber.Number != 12 {
					return fmt.Errorf("decoding smsf-3gpp-Number: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_smsf3gppnumber)
				}
				tmp_smsf3gppnumber := ISDNAddressString(rawVal_smsf3gppnumber)
				v.Smsf3gppNumber = &tmp_smsf3gppnumber
				offset += n_smsf3gppnumber
			}
		}
	}
	// Decode smsf-3gpp-DiameterAddress
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 13 {
				decodedTag_smsf3gppdiameteraddress, n_smsf3gppdiameteraddress, rawVal_smsf3gppdiameteraddress, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding smsf-3gpp-DiameterAddress: %w", err)
				}
				if decodedTag_smsf3gppdiameteraddress.Class != tag.ClassContextSpecific || decodedTag_smsf3gppdiameteraddress.Number != 13 || decodedTag_smsf3gppdiameteraddress.Constructed != true {
					return fmt.Errorf("decoding smsf-3gpp-DiameterAddress: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_smsf3gppdiameteraddress)
				}
				reconstructed_smsf3gppdiameteraddress := ber.EncodeSequence(rawVal_smsf3gppdiameteraddress)
				var dec_smsf3gppdiameteraddress NetworkNodeDiameterAddress
				if unmErr := dec_smsf3gppdiameteraddress.UnmarshalBER(reconstructed_smsf3gppdiameteraddress); unmErr != nil {
					return fmt.Errorf("decoding smsf-3gpp-DiameterAddress: %w", unmErr)
				}
				v.Smsf3gppDiameterAddress = &dec_smsf3gppdiameteraddress
				offset += n_smsf3gppdiameteraddress
			}
		}
	}
	// Decode smsf-non-3gpp-Number
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 14 {
				decodedTag_smsfnon3gppnumber, n_smsfnon3gppnumber, rawVal_smsfnon3gppnumber, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding smsf-non-3gpp-Number: %w", err)
				}
				if decodedTag_smsfnon3gppnumber.Class != tag.ClassContextSpecific || decodedTag_smsfnon3gppnumber.Number != 14 {
					return fmt.Errorf("decoding smsf-non-3gpp-Number: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_smsfnon3gppnumber)
				}
				tmp_smsfnon3gppnumber := ISDNAddressString(rawVal_smsfnon3gppnumber)
				v.SmsfNon3gppNumber = &tmp_smsfnon3gppnumber
				offset += n_smsfnon3gppnumber
			}
		}
	}
	// Decode smsf-non-3gpp-DiameterAddress
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 15 {
				decodedTag_smsfnon3gppdiameteraddress, n_smsfnon3gppdiameteraddress, rawVal_smsfnon3gppdiameteraddress, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding smsf-non-3gpp-DiameterAddress: %w", err)
				}
				if decodedTag_smsfnon3gppdiameteraddress.Class != tag.ClassContextSpecific || decodedTag_smsfnon3gppdiameteraddress.Number != 15 || decodedTag_smsfnon3gppdiameteraddress.Constructed != true {
					return fmt.Errorf("decoding smsf-non-3gpp-DiameterAddress: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_smsfnon3gppdiameteraddress)
				}
				reconstructed_smsfnon3gppdiameteraddress := ber.EncodeSequence(rawVal_smsfnon3gppdiameteraddress)
				var dec_smsfnon3gppdiameteraddress NetworkNodeDiameterAddress
				if unmErr := dec_smsfnon3gppdiameteraddress.UnmarshalBER(reconstructed_smsfnon3gppdiameteraddress); unmErr != nil {
					return fmt.Errorf("decoding smsf-non-3gpp-DiameterAddress: %w", unmErr)
				}
				v.SmsfNon3gppDiameterAddress = &dec_smsfnon3gppdiameteraddress
				offset += n_smsfnon3gppdiameteraddress
			}
		}
	}
	// Decode smsf-3gpp-address-indicator
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 16 {
				decodedTag_smsf3gppaddressindicator, n_smsf3gppaddressindicator, rawVal_smsf3gppaddressindicator, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding smsf-3gpp-address-indicator: %w", err)
				}
				if decodedTag_smsf3gppaddressindicator.Class != tag.ClassContextSpecific || decodedTag_smsf3gppaddressindicator.Number != 16 || decodedTag_smsf3gppaddressindicator.Constructed != false {
					return fmt.Errorf("decoding smsf-3gpp-address-indicator: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_smsf3gppaddressindicator)
				}
				if len(rawVal_smsf3gppaddressindicator) != 0 {
					return fmt.Errorf("decoding smsf-3gpp-address-indicator: %w: NULL content length %d", ber.ErrInvalidValue, len(rawVal_smsf3gppaddressindicator))
				}
				v.Smsf3gppAddressIndicator = &struct{}{}
				offset += n_smsf3gppaddressindicator
			}
		}
	}
	// Decode smsf-non-3gpp-address-indicator
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 17 {
				decodedTag_smsfnon3gppaddressindicator, n_smsfnon3gppaddressindicator, rawVal_smsfnon3gppaddressindicator, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding smsf-non-3gpp-address-indicator: %w", err)
				}
				if decodedTag_smsfnon3gppaddressindicator.Class != tag.ClassContextSpecific || decodedTag_smsfnon3gppaddressindicator.Number != 17 || decodedTag_smsfnon3gppaddressindicator.Constructed != false {
					return fmt.Errorf("decoding smsf-non-3gpp-address-indicator: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_smsfnon3gppaddressindicator)
				}
				if len(rawVal_smsfnon3gppaddressindicator) != 0 {
					return fmt.Errorf("decoding smsf-non-3gpp-address-indicator: %w: NULL content length %d", ber.ErrInvalidValue, len(rawVal_smsfnon3gppaddressindicator))
				}
				v.SmsfNon3gppAddressIndicator = &struct{}{}
				offset += n_smsfnon3gppaddressindicator
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "LocationInfoWithLMSI", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes AdditionalNumber to BER format.
func (v *AdditionalNumber) MarshalBER() ([]byte, error) {
	switch v.Choice {
	case AdditionalNumberChoiceMscNumber:
		if v.MscNumber == nil {
			return nil, fmt.Errorf("choice AdditionalNumber: msc-Number is nil")
		}
		enc_0 := ber.EncodeOctetString([]byte(*v.MscNumber))
		retagged_enc_0, tagErr_enc_0 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_0)
		if tagErr_enc_0 != nil {
			return nil, fmt.Errorf("encoding msc-Number: %w", tagErr_enc_0)
		}
		enc_0 = retagged_enc_0
		return enc_0, nil
	case AdditionalNumberChoiceSgsnNumber:
		if v.SgsnNumber == nil {
			return nil, fmt.Errorf("choice AdditionalNumber: sgsn-Number is nil")
		}
		enc_1 := ber.EncodeOctetString([]byte(*v.SgsnNumber))
		retagged_enc_1, tagErr_enc_1 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_1)
		if tagErr_enc_1 != nil {
			return nil, fmt.Errorf("encoding sgsn-Number: %w", tagErr_enc_1)
		}
		enc_1 = retagged_enc_1
		return enc_1, nil
	default:
		return nil, fmt.Errorf("unknown choice %d for AdditionalNumber", v.Choice)
	}
}

// MarshalDER encodes AdditionalNumber to DER format.
func (v *AdditionalNumber) MarshalDER() ([]byte, error) {
	encoded, err := v.MarshalBER()
	if err != nil {
		return nil, err
	}
	if err := ber.ValidateDERElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding AdditionalNumber as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes AdditionalNumber from BER/DER format.
func (v *AdditionalNumber) UnmarshalBER(data []byte) error {
	if len(data) == 0 {
		return fmt.Errorf("empty data for AdditionalNumber CHOICE")
	}
	choiceData := data
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for AdditionalNumber: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData)
	if tlvErr != nil {
		return fmt.Errorf("decoding AdditionalNumber CHOICE: %w", tlvErr)
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "AdditionalNumber", Cause: ber.ErrExtraData}
	}

	if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
		v.Choice = AdditionalNumberChoiceMscNumber
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding msc-Number: %w", tlvErr)
		}
		tmp := ISDNAddressString(rawVal)
		v.MscNumber = &tmp
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
		v.Choice = AdditionalNumberChoiceSgsnNumber
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding sgsn-Number: %w", tlvErr)
		}
		tmp := ISDNAddressString(rawVal)
		v.SgsnNumber = &tmp
	} else {
		return fmt.Errorf("unknown tag %s for AdditionalNumber CHOICE", peekTag)
	}
	return nil
}

// MarshalBER encodes MOForwardSMArg to BER format.
func (v *MOForwardSMArg) MarshalBER() ([]byte, error) {
	var children []byte
	enc_smrpda, err := v.SmRPDA.MarshalBER()
	if err != nil {
		return nil, fmt.Errorf("encoding sm-RP-DA: %w", err)
	}
	children = append(children, enc_smrpda...)
	enc_smrpoa, err := v.SmRPOA.MarshalBER()
	if err != nil {
		return nil, fmt.Errorf("encoding sm-RP-OA: %w", err)
	}
	children = append(children, enc_smrpoa...)
	enc_smrpui := ber.EncodeOctetString([]byte(v.SmRPUI))
	children = append(children, enc_smrpui...)
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding extensionContainer: %w", err)
		}
		children = append(children, enc_extensioncontainer...)
	}
	if v.Imsi != nil {
		enc_imsi := ber.EncodeOctetString([]byte(*v.Imsi))
		children = append(children, enc_imsi...)
	}
	if v.CorrelationID != nil {
		enc_correlationid, err := v.CorrelationID.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding correlationID: %w", err)
		}
		retagged_enc_correlationid, tagErr_enc_correlationid := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_correlationid)
		if tagErr_enc_correlationid != nil {
			return nil, fmt.Errorf("encoding correlationID: %w", tagErr_enc_correlationid)
		}
		enc_correlationid = retagged_enc_correlationid
		children = append(children, enc_correlationid...)
	}
	if v.SmDeliveryOutcome != nil {
		enc_smdeliveryoutcome := ber.EncodeEnumerated(int64(*v.SmDeliveryOutcome))
		retagged_enc_smdeliveryoutcome, tagErr_enc_smdeliveryoutcome := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_smdeliveryoutcome)
		if tagErr_enc_smdeliveryoutcome != nil {
			return nil, fmt.Errorf("encoding sm-DeliveryOutcome: %w", tagErr_enc_smdeliveryoutcome)
		}
		enc_smdeliveryoutcome = retagged_enc_smdeliveryoutcome
		children = append(children, enc_smdeliveryoutcome...)
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

// MarshalDER encodes MOForwardSMArg to DER format.
func (v *MOForwardSMArg) MarshalDER() ([]byte, error) {
	var children []byte
	enc_smrpda, err := v.SmRPDA.MarshalDER()
	if err != nil {
		return nil, fmt.Errorf("encoding sm-RP-DA: %w", err)
	}
	children = append(children, enc_smrpda...)
	enc_smrpoa, err := v.SmRPOA.MarshalDER()
	if err != nil {
		return nil, fmt.Errorf("encoding sm-RP-OA: %w", err)
	}
	children = append(children, enc_smrpoa...)
	enc_smrpui := ber.EncodeOctetString([]byte(v.SmRPUI))
	children = append(children, enc_smrpui...)
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding extensionContainer: %w", err)
		}
		children = append(children, enc_extensioncontainer...)
	}
	if v.Imsi != nil {
		enc_imsi := ber.EncodeOctetString([]byte(*v.Imsi))
		children = append(children, enc_imsi...)
	}
	if v.CorrelationID != nil {
		enc_correlationid, err := v.CorrelationID.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding correlationID: %w", err)
		}
		retagged_enc_correlationid, tagErr_enc_correlationid := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_correlationid)
		if tagErr_enc_correlationid != nil {
			return nil, fmt.Errorf("encoding correlationID: %w", tagErr_enc_correlationid)
		}
		enc_correlationid = retagged_enc_correlationid
		children = append(children, enc_correlationid...)
	}
	if v.SmDeliveryOutcome != nil {
		enc_smdeliveryoutcome := ber.EncodeEnumerated(int64(*v.SmDeliveryOutcome))
		retagged_enc_smdeliveryoutcome, tagErr_enc_smdeliveryoutcome := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_smdeliveryoutcome)
		if tagErr_enc_smdeliveryoutcome != nil {
			return nil, fmt.Errorf("encoding sm-DeliveryOutcome: %w", tagErr_enc_smdeliveryoutcome)
		}
		enc_smdeliveryoutcome = retagged_enc_smdeliveryoutcome
		children = append(children, enc_smdeliveryoutcome...)
	}
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
		children = append(children, ext...)
	}
	encoded := ber.EncodeSequence(children)
	if err := ber.ValidateDERElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding MOForwardSMArg as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes MOForwardSMArg from BER/DER format.
func (v *MOForwardSMArg) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding MOForwardSMArg SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "MOForwardSMArg", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode sm-RP-DA
	if offset >= len(content) {
		return fmt.Errorf("missing required field sm-RP-DA")
	}
	// Decode nested CHOICE (SMRPDA)
	_, n_smrpda, _, tlvErr_smrpda := ber.DecodeTLV(content[offset:])
	if tlvErr_smrpda != nil {
		return fmt.Errorf("decoding sm-RP-DA: %w", tlvErr_smrpda)
	}
	if unmErr := v.SmRPDA.UnmarshalBER(content[offset : offset+n_smrpda]); unmErr != nil {
		return fmt.Errorf("decoding sm-RP-DA: %w", unmErr)
	}
	offset += n_smrpda
	// Decode sm-RP-OA
	if offset >= len(content) {
		return fmt.Errorf("missing required field sm-RP-OA")
	}
	// Decode nested CHOICE (SMRPOA)
	_, n_smrpoa, _, tlvErr_smrpoa := ber.DecodeTLV(content[offset:])
	if tlvErr_smrpoa != nil {
		return fmt.Errorf("decoding sm-RP-OA: %w", tlvErr_smrpoa)
	}
	if unmErr := v.SmRPOA.UnmarshalBER(content[offset : offset+n_smrpoa]); unmErr != nil {
		return fmt.Errorf("decoding sm-RP-OA: %w", unmErr)
	}
	offset += n_smrpoa
	// Decode sm-RP-UI
	if offset >= len(content) {
		return fmt.Errorf("missing required field sm-RP-UI")
	}
	val_smrpui, n, err := ber.DecodeOctetString(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding sm-RP-UI: %w", err)
	}
	v.SmRPUI = SignalInfo(val_smrpui)
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
	// Decode imsi
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassUniversal && peekTag.Number == 4 {
				val_imsi, n, err := ber.DecodeOctetString(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding imsi: %w", err)
				}
				tmp_imsi := IMSI(val_imsi)
				v.Imsi = &tmp_imsi
				offset += n
			}
		}
	}
	// Decode correlationID
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
				decodedTag_correlationid, n_correlationid, rawVal_correlationid, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding correlationID: %w", err)
				}
				if decodedTag_correlationid.Class != tag.ClassContextSpecific || decodedTag_correlationid.Number != 0 || decodedTag_correlationid.Constructed != true {
					return fmt.Errorf("decoding correlationID: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_correlationid)
				}
				reconstructed_correlationid := ber.EncodeSequence(rawVal_correlationid)
				var dec_correlationid CorrelationID
				if unmErr := dec_correlationid.UnmarshalBER(reconstructed_correlationid); unmErr != nil {
					return fmt.Errorf("decoding correlationID: %w", unmErr)
				}
				v.CorrelationID = &dec_correlationid
				offset += n_correlationid
			}
		}
	}
	// Decode sm-DeliveryOutcome
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
				decodedTag_smdeliveryoutcome, n_smdeliveryoutcome, rawVal_smdeliveryoutcome, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding sm-DeliveryOutcome: %w", err)
				}
				if decodedTag_smdeliveryoutcome.Class != tag.ClassContextSpecific || decodedTag_smdeliveryoutcome.Number != 1 || decodedTag_smdeliveryoutcome.Constructed != false {
					return fmt.Errorf("decoding sm-DeliveryOutcome: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_smdeliveryoutcome)
				}
				decVal_smdeliveryoutcome, intErr := ber.DecodeIntegerValue(rawVal_smdeliveryoutcome)
				if intErr != nil {
					return fmt.Errorf("decoding sm-DeliveryOutcome: %w", intErr)
				}
				tmp_smdeliveryoutcome := SMDeliveryOutcome(decVal_smdeliveryoutcome)
				v.SmDeliveryOutcome = &tmp_smdeliveryoutcome
				offset += n_smdeliveryoutcome
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "MOForwardSMArg", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes MOForwardSMRes to BER format.
func (v *MOForwardSMRes) MarshalBER() ([]byte, error) {
	var children []byte
	if v.SmRPUI != nil {
		enc_smrpui := ber.EncodeOctetString([]byte(*v.SmRPUI))
		children = append(children, enc_smrpui...)
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

// MarshalDER encodes MOForwardSMRes to DER format.
func (v *MOForwardSMRes) MarshalDER() ([]byte, error) {
	var children []byte
	if v.SmRPUI != nil {
		enc_smrpui := ber.EncodeOctetString([]byte(*v.SmRPUI))
		children = append(children, enc_smrpui...)
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
		return nil, fmt.Errorf("encoding MOForwardSMRes as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes MOForwardSMRes from BER/DER format.
func (v *MOForwardSMRes) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding MOForwardSMRes SEQUENCE: %w", err)
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
				val_smrpui, n, err := ber.DecodeOctetString(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding sm-RP-UI: %w", err)
				}
				tmp_smrpui := SignalInfo(val_smrpui)
				v.SmRPUI = &tmp_smrpui
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
			return &ber.DecodeError{Offset: offset, TypeName: "MOForwardSMRes", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes MTForwardSMArg to BER format.
func (v *MTForwardSMArg) MarshalBER() ([]byte, error) {
	var children []byte
	enc_smrpda, err := v.SmRPDA.MarshalBER()
	if err != nil {
		return nil, fmt.Errorf("encoding sm-RP-DA: %w", err)
	}
	children = append(children, enc_smrpda...)
	enc_smrpoa, err := v.SmRPOA.MarshalBER()
	if err != nil {
		return nil, fmt.Errorf("encoding sm-RP-OA: %w", err)
	}
	children = append(children, enc_smrpoa...)
	enc_smrpui := ber.EncodeOctetString([]byte(v.SmRPUI))
	children = append(children, enc_smrpui...)
	if v.MoreMessagesToSend != nil {
		enc_moremessagestosend := ber.EncodeNull()
		children = append(children, enc_moremessagestosend...)
	}
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding extensionContainer: %w", err)
		}
		children = append(children, enc_extensioncontainer...)
	}
	if v.SmDeliveryTimer != nil {
		enc_smdeliverytimer := ber.EncodeInteger(int64(*v.SmDeliveryTimer))
		children = append(children, enc_smdeliverytimer...)
	}
	if v.SmDeliveryStartTime != nil {
		enc_smdeliverystarttime := ber.EncodeOctetString([]byte(*v.SmDeliveryStartTime))
		children = append(children, enc_smdeliverystarttime...)
	}
	if v.SmsOverIPOnlyIndicator != nil {
		enc_smsoveriponlyindicator := ber.EncodeNull()
		retagged_enc_smsoveriponlyindicator, tagErr_enc_smsoveriponlyindicator := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_smsoveriponlyindicator)
		if tagErr_enc_smsoveriponlyindicator != nil {
			return nil, fmt.Errorf("encoding smsOverIP-OnlyIndicator: %w", tagErr_enc_smsoveriponlyindicator)
		}
		enc_smsoveriponlyindicator = retagged_enc_smsoveriponlyindicator
		children = append(children, enc_smsoveriponlyindicator...)
	}
	if v.CorrelationID != nil {
		enc_correlationid, err := v.CorrelationID.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding correlationID: %w", err)
		}
		retagged_enc_correlationid, tagErr_enc_correlationid := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_correlationid)
		if tagErr_enc_correlationid != nil {
			return nil, fmt.Errorf("encoding correlationID: %w", tagErr_enc_correlationid)
		}
		enc_correlationid = retagged_enc_correlationid
		children = append(children, enc_correlationid...)
	}
	if v.MaximumRetransmissionTime != nil {
		enc_maximumretransmissiontime := ber.EncodeOctetString([]byte(*v.MaximumRetransmissionTime))
		retagged_enc_maximumretransmissiontime, tagErr_enc_maximumretransmissiontime := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_maximumretransmissiontime)
		if tagErr_enc_maximumretransmissiontime != nil {
			return nil, fmt.Errorf("encoding maximumRetransmissionTime: %w", tagErr_enc_maximumretransmissiontime)
		}
		enc_maximumretransmissiontime = retagged_enc_maximumretransmissiontime
		children = append(children, enc_maximumretransmissiontime...)
	}
	if v.SmsGmscAddress != nil {
		enc_smsgmscaddress := ber.EncodeOctetString([]byte(*v.SmsGmscAddress))
		retagged_enc_smsgmscaddress, tagErr_enc_smsgmscaddress := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, enc_smsgmscaddress)
		if tagErr_enc_smsgmscaddress != nil {
			return nil, fmt.Errorf("encoding smsGmscAddress: %w", tagErr_enc_smsgmscaddress)
		}
		enc_smsgmscaddress = retagged_enc_smsgmscaddress
		children = append(children, enc_smsgmscaddress...)
	}
	if v.SmsGmscDiameterAddress != nil {
		enc_smsgmscdiameteraddress, err := v.SmsGmscDiameterAddress.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding smsGmscDiameterAddress: %w", err)
		}
		retagged_enc_smsgmscdiameteraddress, tagErr_enc_smsgmscdiameteraddress := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, enc_smsgmscdiameteraddress)
		if tagErr_enc_smsgmscdiameteraddress != nil {
			return nil, fmt.Errorf("encoding smsGmscDiameterAddress: %w", tagErr_enc_smsgmscdiameteraddress)
		}
		enc_smsgmscdiameteraddress = retagged_enc_smsgmscdiameteraddress
		children = append(children, enc_smsgmscdiameteraddress...)
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

// MarshalDER encodes MTForwardSMArg to DER format.
func (v *MTForwardSMArg) MarshalDER() ([]byte, error) {
	var children []byte
	enc_smrpda, err := v.SmRPDA.MarshalDER()
	if err != nil {
		return nil, fmt.Errorf("encoding sm-RP-DA: %w", err)
	}
	children = append(children, enc_smrpda...)
	enc_smrpoa, err := v.SmRPOA.MarshalDER()
	if err != nil {
		return nil, fmt.Errorf("encoding sm-RP-OA: %w", err)
	}
	children = append(children, enc_smrpoa...)
	enc_smrpui := ber.EncodeOctetString([]byte(v.SmRPUI))
	children = append(children, enc_smrpui...)
	if v.MoreMessagesToSend != nil {
		enc_moremessagestosend := ber.EncodeNull()
		children = append(children, enc_moremessagestosend...)
	}
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding extensionContainer: %w", err)
		}
		children = append(children, enc_extensioncontainer...)
	}
	if v.SmDeliveryTimer != nil {
		enc_smdeliverytimer := ber.EncodeInteger(int64(*v.SmDeliveryTimer))
		children = append(children, enc_smdeliverytimer...)
	}
	if v.SmDeliveryStartTime != nil {
		enc_smdeliverystarttime := ber.EncodeOctetString([]byte(*v.SmDeliveryStartTime))
		children = append(children, enc_smdeliverystarttime...)
	}
	if v.SmsOverIPOnlyIndicator != nil {
		enc_smsoveriponlyindicator := ber.EncodeNull()
		retagged_enc_smsoveriponlyindicator, tagErr_enc_smsoveriponlyindicator := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_smsoveriponlyindicator)
		if tagErr_enc_smsoveriponlyindicator != nil {
			return nil, fmt.Errorf("encoding smsOverIP-OnlyIndicator: %w", tagErr_enc_smsoveriponlyindicator)
		}
		enc_smsoveriponlyindicator = retagged_enc_smsoveriponlyindicator
		children = append(children, enc_smsoveriponlyindicator...)
	}
	if v.CorrelationID != nil {
		enc_correlationid, err := v.CorrelationID.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding correlationID: %w", err)
		}
		retagged_enc_correlationid, tagErr_enc_correlationid := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_correlationid)
		if tagErr_enc_correlationid != nil {
			return nil, fmt.Errorf("encoding correlationID: %w", tagErr_enc_correlationid)
		}
		enc_correlationid = retagged_enc_correlationid
		children = append(children, enc_correlationid...)
	}
	if v.MaximumRetransmissionTime != nil {
		enc_maximumretransmissiontime := ber.EncodeOctetString([]byte(*v.MaximumRetransmissionTime))
		retagged_enc_maximumretransmissiontime, tagErr_enc_maximumretransmissiontime := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_maximumretransmissiontime)
		if tagErr_enc_maximumretransmissiontime != nil {
			return nil, fmt.Errorf("encoding maximumRetransmissionTime: %w", tagErr_enc_maximumretransmissiontime)
		}
		enc_maximumretransmissiontime = retagged_enc_maximumretransmissiontime
		children = append(children, enc_maximumretransmissiontime...)
	}
	if v.SmsGmscAddress != nil {
		enc_smsgmscaddress := ber.EncodeOctetString([]byte(*v.SmsGmscAddress))
		retagged_enc_smsgmscaddress, tagErr_enc_smsgmscaddress := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, enc_smsgmscaddress)
		if tagErr_enc_smsgmscaddress != nil {
			return nil, fmt.Errorf("encoding smsGmscAddress: %w", tagErr_enc_smsgmscaddress)
		}
		enc_smsgmscaddress = retagged_enc_smsgmscaddress
		children = append(children, enc_smsgmscaddress...)
	}
	if v.SmsGmscDiameterAddress != nil {
		enc_smsgmscdiameteraddress, err := v.SmsGmscDiameterAddress.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding smsGmscDiameterAddress: %w", err)
		}
		retagged_enc_smsgmscdiameteraddress, tagErr_enc_smsgmscdiameteraddress := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, enc_smsgmscdiameteraddress)
		if tagErr_enc_smsgmscdiameteraddress != nil {
			return nil, fmt.Errorf("encoding smsGmscDiameterAddress: %w", tagErr_enc_smsgmscdiameteraddress)
		}
		enc_smsgmscdiameteraddress = retagged_enc_smsgmscdiameteraddress
		children = append(children, enc_smsgmscdiameteraddress...)
	}
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
		children = append(children, ext...)
	}
	encoded := ber.EncodeSequence(children)
	if err := ber.ValidateDERElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding MTForwardSMArg as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes MTForwardSMArg from BER/DER format.
func (v *MTForwardSMArg) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding MTForwardSMArg SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "MTForwardSMArg", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode sm-RP-DA
	if offset >= len(content) {
		return fmt.Errorf("missing required field sm-RP-DA")
	}
	// Decode nested CHOICE (SMRPDA)
	_, n_smrpda, _, tlvErr_smrpda := ber.DecodeTLV(content[offset:])
	if tlvErr_smrpda != nil {
		return fmt.Errorf("decoding sm-RP-DA: %w", tlvErr_smrpda)
	}
	if unmErr := v.SmRPDA.UnmarshalBER(content[offset : offset+n_smrpda]); unmErr != nil {
		return fmt.Errorf("decoding sm-RP-DA: %w", unmErr)
	}
	offset += n_smrpda
	// Decode sm-RP-OA
	if offset >= len(content) {
		return fmt.Errorf("missing required field sm-RP-OA")
	}
	// Decode nested CHOICE (SMRPOA)
	_, n_smrpoa, _, tlvErr_smrpoa := ber.DecodeTLV(content[offset:])
	if tlvErr_smrpoa != nil {
		return fmt.Errorf("decoding sm-RP-OA: %w", tlvErr_smrpoa)
	}
	if unmErr := v.SmRPOA.UnmarshalBER(content[offset : offset+n_smrpoa]); unmErr != nil {
		return fmt.Errorf("decoding sm-RP-OA: %w", unmErr)
	}
	offset += n_smrpoa
	// Decode sm-RP-UI
	if offset >= len(content) {
		return fmt.Errorf("missing required field sm-RP-UI")
	}
	val_smrpui, n, err := ber.DecodeOctetString(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding sm-RP-UI: %w", err)
	}
	v.SmRPUI = SignalInfo(val_smrpui)
	offset += n
	// Decode moreMessagesToSend
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassUniversal && peekTag.Number == 5 {
				n, err := ber.DecodeNull(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding moreMessagesToSend: %w", err)
				}
				v.MoreMessagesToSend = &struct{}{}
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
	// Decode smDeliveryTimer
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassUniversal && peekTag.Number == 2 {
				val_smdeliverytimer, n, err := ber.DecodeInteger(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding smDeliveryTimer: %w", err)
				}
				tmp_smdeliverytimer := SMDeliveryTimerValue(val_smdeliverytimer)
				v.SmDeliveryTimer = &tmp_smdeliverytimer
				offset += n
			}
		}
	}
	// Decode smDeliveryStartTime
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassUniversal && peekTag.Number == 4 {
				val_smdeliverystarttime, n, err := ber.DecodeOctetString(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding smDeliveryStartTime: %w", err)
				}
				tmp_smdeliverystarttime := Time(val_smdeliverystarttime)
				v.SmDeliveryStartTime = &tmp_smdeliverystarttime
				offset += n
			}
		}
	}
	// Decode smsOverIP-OnlyIndicator
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
				decodedTag_smsoveriponlyindicator, n_smsoveriponlyindicator, rawVal_smsoveriponlyindicator, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding smsOverIP-OnlyIndicator: %w", err)
				}
				if decodedTag_smsoveriponlyindicator.Class != tag.ClassContextSpecific || decodedTag_smsoveriponlyindicator.Number != 0 || decodedTag_smsoveriponlyindicator.Constructed != false {
					return fmt.Errorf("decoding smsOverIP-OnlyIndicator: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_smsoveriponlyindicator)
				}
				if len(rawVal_smsoveriponlyindicator) != 0 {
					return fmt.Errorf("decoding smsOverIP-OnlyIndicator: %w: NULL content length %d", ber.ErrInvalidValue, len(rawVal_smsoveriponlyindicator))
				}
				v.SmsOverIPOnlyIndicator = &struct{}{}
				offset += n_smsoveriponlyindicator
			}
		}
	}
	// Decode correlationID
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
				decodedTag_correlationid, n_correlationid, rawVal_correlationid, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding correlationID: %w", err)
				}
				if decodedTag_correlationid.Class != tag.ClassContextSpecific || decodedTag_correlationid.Number != 1 || decodedTag_correlationid.Constructed != true {
					return fmt.Errorf("decoding correlationID: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_correlationid)
				}
				reconstructed_correlationid := ber.EncodeSequence(rawVal_correlationid)
				var dec_correlationid CorrelationID
				if unmErr := dec_correlationid.UnmarshalBER(reconstructed_correlationid); unmErr != nil {
					return fmt.Errorf("decoding correlationID: %w", unmErr)
				}
				v.CorrelationID = &dec_correlationid
				offset += n_correlationid
			}
		}
	}
	// Decode maximumRetransmissionTime
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2 {
				decodedTag_maximumretransmissiontime, n_maximumretransmissiontime, rawVal_maximumretransmissiontime, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding maximumRetransmissionTime: %w", err)
				}
				if decodedTag_maximumretransmissiontime.Class != tag.ClassContextSpecific || decodedTag_maximumretransmissiontime.Number != 2 {
					return fmt.Errorf("decoding maximumRetransmissionTime: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_maximumretransmissiontime)
				}
				tmp_maximumretransmissiontime := Time(rawVal_maximumretransmissiontime)
				v.MaximumRetransmissionTime = &tmp_maximumretransmissiontime
				offset += n_maximumretransmissiontime
			}
		}
	}
	// Decode smsGmscAddress
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3 {
				decodedTag_smsgmscaddress, n_smsgmscaddress, rawVal_smsgmscaddress, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding smsGmscAddress: %w", err)
				}
				if decodedTag_smsgmscaddress.Class != tag.ClassContextSpecific || decodedTag_smsgmscaddress.Number != 3 {
					return fmt.Errorf("decoding smsGmscAddress: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_smsgmscaddress)
				}
				tmp_smsgmscaddress := ISDNAddressString(rawVal_smsgmscaddress)
				v.SmsGmscAddress = &tmp_smsgmscaddress
				offset += n_smsgmscaddress
			}
		}
	}
	// Decode smsGmscDiameterAddress
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4 {
				decodedTag_smsgmscdiameteraddress, n_smsgmscdiameteraddress, rawVal_smsgmscdiameteraddress, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding smsGmscDiameterAddress: %w", err)
				}
				if decodedTag_smsgmscdiameteraddress.Class != tag.ClassContextSpecific || decodedTag_smsgmscdiameteraddress.Number != 4 || decodedTag_smsgmscdiameteraddress.Constructed != true {
					return fmt.Errorf("decoding smsGmscDiameterAddress: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_smsgmscdiameteraddress)
				}
				reconstructed_smsgmscdiameteraddress := ber.EncodeSequence(rawVal_smsgmscdiameteraddress)
				var dec_smsgmscdiameteraddress NetworkNodeDiameterAddress
				if unmErr := dec_smsgmscdiameteraddress.UnmarshalBER(reconstructed_smsgmscdiameteraddress); unmErr != nil {
					return fmt.Errorf("decoding smsGmscDiameterAddress: %w", unmErr)
				}
				v.SmsGmscDiameterAddress = &dec_smsgmscdiameteraddress
				offset += n_smsgmscdiameteraddress
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "MTForwardSMArg", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes CorrelationID to BER format.
func (v *CorrelationID) MarshalBER() ([]byte, error) {
	var children []byte
	if v.HlrId != nil {
		enc_hlrid := ber.EncodeOctetString([]byte(*v.HlrId))
		retagged_enc_hlrid, tagErr_enc_hlrid := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_hlrid)
		if tagErr_enc_hlrid != nil {
			return nil, fmt.Errorf("encoding hlr-id: %w", tagErr_enc_hlrid)
		}
		enc_hlrid = retagged_enc_hlrid
		children = append(children, enc_hlrid...)
	}
	if v.SipUriA != nil {
		enc_sipuria := ber.EncodeOctetString([]byte(*v.SipUriA))
		retagged_enc_sipuria, tagErr_enc_sipuria := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_sipuria)
		if tagErr_enc_sipuria != nil {
			return nil, fmt.Errorf("encoding sip-uri-A: %w", tagErr_enc_sipuria)
		}
		enc_sipuria = retagged_enc_sipuria
		children = append(children, enc_sipuria...)
	}
	enc_sipurib := ber.EncodeOctetString([]byte(v.SipUriB))
	retagged_enc_sipurib, tagErr_enc_sipurib := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_sipurib)
	if tagErr_enc_sipurib != nil {
		return nil, fmt.Errorf("encoding sip-uri-B: %w", tagErr_enc_sipurib)
	}
	enc_sipurib = retagged_enc_sipurib
	children = append(children, enc_sipurib...)
	return ber.EncodeSequence(children), nil
}

// MarshalDER encodes CorrelationID to DER format.
func (v *CorrelationID) MarshalDER() ([]byte, error) {
	var children []byte
	if v.HlrId != nil {
		enc_hlrid := ber.EncodeOctetString([]byte(*v.HlrId))
		retagged_enc_hlrid, tagErr_enc_hlrid := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_hlrid)
		if tagErr_enc_hlrid != nil {
			return nil, fmt.Errorf("encoding hlr-id: %w", tagErr_enc_hlrid)
		}
		enc_hlrid = retagged_enc_hlrid
		children = append(children, enc_hlrid...)
	}
	if v.SipUriA != nil {
		enc_sipuria := ber.EncodeOctetString([]byte(*v.SipUriA))
		retagged_enc_sipuria, tagErr_enc_sipuria := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_sipuria)
		if tagErr_enc_sipuria != nil {
			return nil, fmt.Errorf("encoding sip-uri-A: %w", tagErr_enc_sipuria)
		}
		enc_sipuria = retagged_enc_sipuria
		children = append(children, enc_sipuria...)
	}
	enc_sipurib := ber.EncodeOctetString([]byte(v.SipUriB))
	retagged_enc_sipurib, tagErr_enc_sipurib := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_sipurib)
	if tagErr_enc_sipurib != nil {
		return nil, fmt.Errorf("encoding sip-uri-B: %w", tagErr_enc_sipurib)
	}
	enc_sipurib = retagged_enc_sipurib
	children = append(children, enc_sipurib...)
	encoded := ber.EncodeSequence(children)
	if err := ber.ValidateDERElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding CorrelationID as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes CorrelationID from BER/DER format.
func (v *CorrelationID) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding CorrelationID SEQUENCE: %w", err)
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
				decodedTag_hlrid, n_hlrid, rawVal_hlrid, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding hlr-id: %w", err)
				}
				if decodedTag_hlrid.Class != tag.ClassContextSpecific || decodedTag_hlrid.Number != 0 {
					return fmt.Errorf("decoding hlr-id: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_hlrid)
				}
				tmp_hlrid := HLRId(rawVal_hlrid)
				v.HlrId = &tmp_hlrid
				offset += n_hlrid
			}
		}
	}
	// Decode sip-uri-A
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
				decodedTag_sipuria, n_sipuria, rawVal_sipuria, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding sip-uri-A: %w", err)
				}
				if decodedTag_sipuria.Class != tag.ClassContextSpecific || decodedTag_sipuria.Number != 1 {
					return fmt.Errorf("decoding sip-uri-A: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_sipuria)
				}
				tmp_sipuria := SIPURI(rawVal_sipuria)
				v.SipUriA = &tmp_sipuria
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
	decodedTag_sipurib, n_sipurib, rawVal_sipurib, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding sip-uri-B: %w", err)
	}
	if decodedTag_sipurib.Class != tag.ClassContextSpecific || decodedTag_sipurib.Number != 2 {
		return fmt.Errorf("decoding sip-uri-B: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_sipurib)
	}
	v.SipUriB = SIPURI(rawVal_sipurib)
	offset += n_sipurib
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "CorrelationID", Cause: ber.ErrExtraData}
	}
	return nil
}

// MarshalBER encodes MTForwardSMRes to BER format.
func (v *MTForwardSMRes) MarshalBER() ([]byte, error) {
	var children []byte
	if v.SmRPUI != nil {
		enc_smrpui := ber.EncodeOctetString([]byte(*v.SmRPUI))
		children = append(children, enc_smrpui...)
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

// MarshalDER encodes MTForwardSMRes to DER format.
func (v *MTForwardSMRes) MarshalDER() ([]byte, error) {
	var children []byte
	if v.SmRPUI != nil {
		enc_smrpui := ber.EncodeOctetString([]byte(*v.SmRPUI))
		children = append(children, enc_smrpui...)
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
		return nil, fmt.Errorf("encoding MTForwardSMRes as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes MTForwardSMRes from BER/DER format.
func (v *MTForwardSMRes) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding MTForwardSMRes SEQUENCE: %w", err)
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
				val_smrpui, n, err := ber.DecodeOctetString(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding sm-RP-UI: %w", err)
				}
				tmp_smrpui := SignalInfo(val_smrpui)
				v.SmRPUI = &tmp_smrpui
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
			return &ber.DecodeError{Offset: offset, TypeName: "MTForwardSMRes", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes SMRPDA to BER format.
func (v *SMRPDA) MarshalBER() ([]byte, error) {
	switch v.Choice {
	case SMRPDAChoiceImsi:
		if v.Imsi == nil {
			return nil, fmt.Errorf("choice SMRPDA: imsi is nil")
		}
		enc_0 := ber.EncodeOctetString([]byte(*v.Imsi))
		retagged_enc_0, tagErr_enc_0 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_0)
		if tagErr_enc_0 != nil {
			return nil, fmt.Errorf("encoding imsi: %w", tagErr_enc_0)
		}
		enc_0 = retagged_enc_0
		return enc_0, nil
	case SMRPDAChoiceLmsi:
		if v.Lmsi == nil {
			return nil, fmt.Errorf("choice SMRPDA: lmsi is nil")
		}
		enc_1 := ber.EncodeOctetString([]byte(*v.Lmsi))
		retagged_enc_1, tagErr_enc_1 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_1)
		if tagErr_enc_1 != nil {
			return nil, fmt.Errorf("encoding lmsi: %w", tagErr_enc_1)
		}
		enc_1 = retagged_enc_1
		return enc_1, nil
	case SMRPDAChoiceServiceCentreAddressDA:
		if v.ServiceCentreAddressDA == nil {
			return nil, fmt.Errorf("choice SMRPDA: serviceCentreAddressDA is nil")
		}
		enc_2 := ber.EncodeOctetString([]byte(*v.ServiceCentreAddressDA))
		retagged_enc_2, tagErr_enc_2 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, enc_2)
		if tagErr_enc_2 != nil {
			return nil, fmt.Errorf("encoding serviceCentreAddressDA: %w", tagErr_enc_2)
		}
		enc_2 = retagged_enc_2
		return enc_2, nil
	case SMRPDAChoiceNoSMRPDA:
		enc_3 := ber.EncodeNull()
		retagged_enc_3, tagErr_enc_3 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 5, enc_3)
		if tagErr_enc_3 != nil {
			return nil, fmt.Errorf("encoding noSM-RP-DA: %w", tagErr_enc_3)
		}
		enc_3 = retagged_enc_3
		return enc_3, nil
	default:
		return nil, fmt.Errorf("unknown choice %d for SMRPDA", v.Choice)
	}
}

// MarshalDER encodes SMRPDA to DER format.
func (v *SMRPDA) MarshalDER() ([]byte, error) {
	encoded, err := v.MarshalBER()
	if err != nil {
		return nil, err
	}
	if err := ber.ValidateDERElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding SMRPDA as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes SMRPDA from BER/DER format.
func (v *SMRPDA) UnmarshalBER(data []byte) error {
	if len(data) == 0 {
		return fmt.Errorf("empty data for SMRPDA CHOICE")
	}
	choiceData := data
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for SMRPDA: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData)
	if tlvErr != nil {
		return fmt.Errorf("decoding SMRPDA CHOICE: %w", tlvErr)
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "SMRPDA", Cause: ber.ErrExtraData}
	}

	if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
		v.Choice = SMRPDAChoiceImsi
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding imsi: %w", tlvErr)
		}
		tmp := IMSI(rawVal)
		v.Imsi = &tmp
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
		v.Choice = SMRPDAChoiceLmsi
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding lmsi: %w", tlvErr)
		}
		tmp := LMSI(rawVal)
		v.Lmsi = &tmp
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4 {
		v.Choice = SMRPDAChoiceServiceCentreAddressDA
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding serviceCentreAddressDA: %w", tlvErr)
		}
		tmp := AddressString(rawVal)
		v.ServiceCentreAddressDA = &tmp
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 5 && peekTag.Constructed == false {
		v.Choice = SMRPDAChoiceNoSMRPDA
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding noSM-RP-DA: %w", tlvErr)
		}
		if len(rawVal) != 0 {
			return fmt.Errorf("decoding noSM-RP-DA: %w: NULL content length %d", ber.ErrInvalidValue, len(rawVal))
		}
		v.NoSMRPDA = &struct{}{}
	} else {
		return fmt.Errorf("unknown tag %s for SMRPDA CHOICE", peekTag)
	}
	return nil
}

// MarshalBER encodes SMRPOA to BER format.
func (v *SMRPOA) MarshalBER() ([]byte, error) {
	switch v.Choice {
	case SMRPOAChoiceMsisdn:
		if v.Msisdn == nil {
			return nil, fmt.Errorf("choice SMRPOA: msisdn is nil")
		}
		enc_0 := ber.EncodeOctetString([]byte(*v.Msisdn))
		retagged_enc_0, tagErr_enc_0 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_0)
		if tagErr_enc_0 != nil {
			return nil, fmt.Errorf("encoding msisdn: %w", tagErr_enc_0)
		}
		enc_0 = retagged_enc_0
		return enc_0, nil
	case SMRPOAChoiceServiceCentreAddressOA:
		if v.ServiceCentreAddressOA == nil {
			return nil, fmt.Errorf("choice SMRPOA: serviceCentreAddressOA is nil")
		}
		enc_1 := ber.EncodeOctetString([]byte(*v.ServiceCentreAddressOA))
		retagged_enc_1, tagErr_enc_1 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, enc_1)
		if tagErr_enc_1 != nil {
			return nil, fmt.Errorf("encoding serviceCentreAddressOA: %w", tagErr_enc_1)
		}
		enc_1 = retagged_enc_1
		return enc_1, nil
	case SMRPOAChoiceNoSMRPOA:
		enc_2 := ber.EncodeNull()
		retagged_enc_2, tagErr_enc_2 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 5, enc_2)
		if tagErr_enc_2 != nil {
			return nil, fmt.Errorf("encoding noSM-RP-OA: %w", tagErr_enc_2)
		}
		enc_2 = retagged_enc_2
		return enc_2, nil
	default:
		return nil, fmt.Errorf("unknown choice %d for SMRPOA", v.Choice)
	}
}

// MarshalDER encodes SMRPOA to DER format.
func (v *SMRPOA) MarshalDER() ([]byte, error) {
	encoded, err := v.MarshalBER()
	if err != nil {
		return nil, err
	}
	if err := ber.ValidateDERElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding SMRPOA as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes SMRPOA from BER/DER format.
func (v *SMRPOA) UnmarshalBER(data []byte) error {
	if len(data) == 0 {
		return fmt.Errorf("empty data for SMRPOA CHOICE")
	}
	choiceData := data
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for SMRPOA: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData)
	if tlvErr != nil {
		return fmt.Errorf("decoding SMRPOA CHOICE: %w", tlvErr)
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "SMRPOA", Cause: ber.ErrExtraData}
	}

	if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2 {
		v.Choice = SMRPOAChoiceMsisdn
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding msisdn: %w", tlvErr)
		}
		tmp := ISDNAddressString(rawVal)
		v.Msisdn = &tmp
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4 {
		v.Choice = SMRPOAChoiceServiceCentreAddressOA
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding serviceCentreAddressOA: %w", tlvErr)
		}
		tmp := AddressString(rawVal)
		v.ServiceCentreAddressOA = &tmp
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 5 && peekTag.Constructed == false {
		v.Choice = SMRPOAChoiceNoSMRPOA
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding noSM-RP-OA: %w", tlvErr)
		}
		if len(rawVal) != 0 {
			return fmt.Errorf("decoding noSM-RP-OA: %w: NULL content length %d", ber.ErrInvalidValue, len(rawVal))
		}
		v.NoSMRPOA = &struct{}{}
	} else {
		return fmt.Errorf("unknown tag %s for SMRPOA CHOICE", peekTag)
	}
	return nil
}

// MarshalBER encodes ReportSMDeliveryStatusArg to BER format.
func (v *ReportSMDeliveryStatusArg) MarshalBER() ([]byte, error) {
	var children []byte
	enc_msisdn := ber.EncodeOctetString([]byte(v.Msisdn))
	children = append(children, enc_msisdn...)
	enc_servicecentreaddress := ber.EncodeOctetString([]byte(v.ServiceCentreAddress))
	children = append(children, enc_servicecentreaddress...)
	enc_smdeliveryoutcome := ber.EncodeEnumerated(int64(v.SmDeliveryOutcome))
	children = append(children, enc_smdeliveryoutcome...)
	if v.AbsentSubscriberDiagnosticSM != nil {
		enc_absentsubscriberdiagnosticsm := ber.EncodeInteger(int64(*v.AbsentSubscriberDiagnosticSM))
		retagged_enc_absentsubscriberdiagnosticsm, tagErr_enc_absentsubscriberdiagnosticsm := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_absentsubscriberdiagnosticsm)
		if tagErr_enc_absentsubscriberdiagnosticsm != nil {
			return nil, fmt.Errorf("encoding absentSubscriberDiagnosticSM: %w", tagErr_enc_absentsubscriberdiagnosticsm)
		}
		enc_absentsubscriberdiagnosticsm = retagged_enc_absentsubscriberdiagnosticsm
		children = append(children, enc_absentsubscriberdiagnosticsm...)
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
	if v.GprsSupportIndicator != nil {
		enc_gprssupportindicator := ber.EncodeNull()
		retagged_enc_gprssupportindicator, tagErr_enc_gprssupportindicator := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_gprssupportindicator)
		if tagErr_enc_gprssupportindicator != nil {
			return nil, fmt.Errorf("encoding gprsSupportIndicator: %w", tagErr_enc_gprssupportindicator)
		}
		enc_gprssupportindicator = retagged_enc_gprssupportindicator
		children = append(children, enc_gprssupportindicator...)
	}
	if v.DeliveryOutcomeIndicator != nil {
		enc_deliveryoutcomeindicator := ber.EncodeNull()
		retagged_enc_deliveryoutcomeindicator, tagErr_enc_deliveryoutcomeindicator := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, enc_deliveryoutcomeindicator)
		if tagErr_enc_deliveryoutcomeindicator != nil {
			return nil, fmt.Errorf("encoding deliveryOutcomeIndicator: %w", tagErr_enc_deliveryoutcomeindicator)
		}
		enc_deliveryoutcomeindicator = retagged_enc_deliveryoutcomeindicator
		children = append(children, enc_deliveryoutcomeindicator...)
	}
	if v.AdditionalSMDeliveryOutcome != nil {
		enc_additionalsmdeliveryoutcome := ber.EncodeEnumerated(int64(*v.AdditionalSMDeliveryOutcome))
		retagged_enc_additionalsmdeliveryoutcome, tagErr_enc_additionalsmdeliveryoutcome := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, enc_additionalsmdeliveryoutcome)
		if tagErr_enc_additionalsmdeliveryoutcome != nil {
			return nil, fmt.Errorf("encoding additionalSM-DeliveryOutcome: %w", tagErr_enc_additionalsmdeliveryoutcome)
		}
		enc_additionalsmdeliveryoutcome = retagged_enc_additionalsmdeliveryoutcome
		children = append(children, enc_additionalsmdeliveryoutcome...)
	}
	if v.AdditionalAbsentSubscriberDiagnosticSM != nil {
		enc_additionalabsentsubscriberdiagnosticsm := ber.EncodeInteger(int64(*v.AdditionalAbsentSubscriberDiagnosticSM))
		retagged_enc_additionalabsentsubscriberdiagnosticsm, tagErr_enc_additionalabsentsubscriberdiagnosticsm := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 5, enc_additionalabsentsubscriberdiagnosticsm)
		if tagErr_enc_additionalabsentsubscriberdiagnosticsm != nil {
			return nil, fmt.Errorf("encoding additionalAbsentSubscriberDiagnosticSM: %w", tagErr_enc_additionalabsentsubscriberdiagnosticsm)
		}
		enc_additionalabsentsubscriberdiagnosticsm = retagged_enc_additionalabsentsubscriberdiagnosticsm
		children = append(children, enc_additionalabsentsubscriberdiagnosticsm...)
	}
	if v.IpSmGwIndicator != nil {
		enc_ipsmgwindicator := ber.EncodeNull()
		retagged_enc_ipsmgwindicator, tagErr_enc_ipsmgwindicator := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 6, enc_ipsmgwindicator)
		if tagErr_enc_ipsmgwindicator != nil {
			return nil, fmt.Errorf("encoding ip-sm-gw-Indicator: %w", tagErr_enc_ipsmgwindicator)
		}
		enc_ipsmgwindicator = retagged_enc_ipsmgwindicator
		children = append(children, enc_ipsmgwindicator...)
	}
	if v.IpSmGwSmDeliveryOutcome != nil {
		enc_ipsmgwsmdeliveryoutcome := ber.EncodeEnumerated(int64(*v.IpSmGwSmDeliveryOutcome))
		retagged_enc_ipsmgwsmdeliveryoutcome, tagErr_enc_ipsmgwsmdeliveryoutcome := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 7, enc_ipsmgwsmdeliveryoutcome)
		if tagErr_enc_ipsmgwsmdeliveryoutcome != nil {
			return nil, fmt.Errorf("encoding ip-sm-gw-sm-deliveryOutcome: %w", tagErr_enc_ipsmgwsmdeliveryoutcome)
		}
		enc_ipsmgwsmdeliveryoutcome = retagged_enc_ipsmgwsmdeliveryoutcome
		children = append(children, enc_ipsmgwsmdeliveryoutcome...)
	}
	if v.IpSmGwAbsentSubscriberDiagnosticSM != nil {
		enc_ipsmgwabsentsubscriberdiagnosticsm := ber.EncodeInteger(int64(*v.IpSmGwAbsentSubscriberDiagnosticSM))
		retagged_enc_ipsmgwabsentsubscriberdiagnosticsm, tagErr_enc_ipsmgwabsentsubscriberdiagnosticsm := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 8, enc_ipsmgwabsentsubscriberdiagnosticsm)
		if tagErr_enc_ipsmgwabsentsubscriberdiagnosticsm != nil {
			return nil, fmt.Errorf("encoding ip-sm-gw-absentSubscriberDiagnosticSM: %w", tagErr_enc_ipsmgwabsentsubscriberdiagnosticsm)
		}
		enc_ipsmgwabsentsubscriberdiagnosticsm = retagged_enc_ipsmgwabsentsubscriberdiagnosticsm
		children = append(children, enc_ipsmgwabsentsubscriberdiagnosticsm...)
	}
	if v.Imsi != nil {
		enc_imsi := ber.EncodeOctetString([]byte(*v.Imsi))
		retagged_enc_imsi, tagErr_enc_imsi := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 9, enc_imsi)
		if tagErr_enc_imsi != nil {
			return nil, fmt.Errorf("encoding imsi: %w", tagErr_enc_imsi)
		}
		enc_imsi = retagged_enc_imsi
		children = append(children, enc_imsi...)
	}
	if v.SingleAttemptDelivery != nil {
		enc_singleattemptdelivery := ber.EncodeNull()
		retagged_enc_singleattemptdelivery, tagErr_enc_singleattemptdelivery := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 10, enc_singleattemptdelivery)
		if tagErr_enc_singleattemptdelivery != nil {
			return nil, fmt.Errorf("encoding singleAttemptDelivery: %w", tagErr_enc_singleattemptdelivery)
		}
		enc_singleattemptdelivery = retagged_enc_singleattemptdelivery
		children = append(children, enc_singleattemptdelivery...)
	}
	if v.CorrelationID != nil {
		enc_correlationid, err := v.CorrelationID.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding correlationID: %w", err)
		}
		retagged_enc_correlationid, tagErr_enc_correlationid := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 11, enc_correlationid)
		if tagErr_enc_correlationid != nil {
			return nil, fmt.Errorf("encoding correlationID: %w", tagErr_enc_correlationid)
		}
		enc_correlationid = retagged_enc_correlationid
		children = append(children, enc_correlationid...)
	}
	if v.Smsf3gppDeliveryOutcomeIndicator != nil {
		enc_smsf3gppdeliveryoutcomeindicator := ber.EncodeNull()
		retagged_enc_smsf3gppdeliveryoutcomeindicator, tagErr_enc_smsf3gppdeliveryoutcomeindicator := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 12, enc_smsf3gppdeliveryoutcomeindicator)
		if tagErr_enc_smsf3gppdeliveryoutcomeindicator != nil {
			return nil, fmt.Errorf("encoding smsf-3gpp-deliveryOutcomeIndicator: %w", tagErr_enc_smsf3gppdeliveryoutcomeindicator)
		}
		enc_smsf3gppdeliveryoutcomeindicator = retagged_enc_smsf3gppdeliveryoutcomeindicator
		children = append(children, enc_smsf3gppdeliveryoutcomeindicator...)
	}
	if v.Smsf3gppDeliveryOutcome != nil {
		enc_smsf3gppdeliveryoutcome := ber.EncodeEnumerated(int64(*v.Smsf3gppDeliveryOutcome))
		retagged_enc_smsf3gppdeliveryoutcome, tagErr_enc_smsf3gppdeliveryoutcome := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 13, enc_smsf3gppdeliveryoutcome)
		if tagErr_enc_smsf3gppdeliveryoutcome != nil {
			return nil, fmt.Errorf("encoding smsf-3gpp-deliveryOutcome: %w", tagErr_enc_smsf3gppdeliveryoutcome)
		}
		enc_smsf3gppdeliveryoutcome = retagged_enc_smsf3gppdeliveryoutcome
		children = append(children, enc_smsf3gppdeliveryoutcome...)
	}
	if v.Smsf3gppAbsentSubscriberDiagSM != nil {
		enc_smsf3gppabsentsubscriberdiagsm := ber.EncodeInteger(int64(*v.Smsf3gppAbsentSubscriberDiagSM))
		retagged_enc_smsf3gppabsentsubscriberdiagsm, tagErr_enc_smsf3gppabsentsubscriberdiagsm := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 14, enc_smsf3gppabsentsubscriberdiagsm)
		if tagErr_enc_smsf3gppabsentsubscriberdiagsm != nil {
			return nil, fmt.Errorf("encoding smsf-3gpp-absentSubscriberDiagSM: %w", tagErr_enc_smsf3gppabsentsubscriberdiagsm)
		}
		enc_smsf3gppabsentsubscriberdiagsm = retagged_enc_smsf3gppabsentsubscriberdiagsm
		children = append(children, enc_smsf3gppabsentsubscriberdiagsm...)
	}
	if v.SmsfNon3gppDeliveryOutcomeIndicator != nil {
		enc_smsfnon3gppdeliveryoutcomeindicator := ber.EncodeNull()
		retagged_enc_smsfnon3gppdeliveryoutcomeindicator, tagErr_enc_smsfnon3gppdeliveryoutcomeindicator := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 15, enc_smsfnon3gppdeliveryoutcomeindicator)
		if tagErr_enc_smsfnon3gppdeliveryoutcomeindicator != nil {
			return nil, fmt.Errorf("encoding smsf-non-3gpp-deliveryOutcomeIndicator: %w", tagErr_enc_smsfnon3gppdeliveryoutcomeindicator)
		}
		enc_smsfnon3gppdeliveryoutcomeindicator = retagged_enc_smsfnon3gppdeliveryoutcomeindicator
		children = append(children, enc_smsfnon3gppdeliveryoutcomeindicator...)
	}
	if v.SmsfNon3gppDeliveryOutcome != nil {
		enc_smsfnon3gppdeliveryoutcome := ber.EncodeEnumerated(int64(*v.SmsfNon3gppDeliveryOutcome))
		retagged_enc_smsfnon3gppdeliveryoutcome, tagErr_enc_smsfnon3gppdeliveryoutcome := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 16, enc_smsfnon3gppdeliveryoutcome)
		if tagErr_enc_smsfnon3gppdeliveryoutcome != nil {
			return nil, fmt.Errorf("encoding smsf-non-3gpp-deliveryOutcome: %w", tagErr_enc_smsfnon3gppdeliveryoutcome)
		}
		enc_smsfnon3gppdeliveryoutcome = retagged_enc_smsfnon3gppdeliveryoutcome
		children = append(children, enc_smsfnon3gppdeliveryoutcome...)
	}
	if v.SmsfNon3gppAbsentSubscriberDiagSM != nil {
		enc_smsfnon3gppabsentsubscriberdiagsm := ber.EncodeInteger(int64(*v.SmsfNon3gppAbsentSubscriberDiagSM))
		retagged_enc_smsfnon3gppabsentsubscriberdiagsm, tagErr_enc_smsfnon3gppabsentsubscriberdiagsm := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 17, enc_smsfnon3gppabsentsubscriberdiagsm)
		if tagErr_enc_smsfnon3gppabsentsubscriberdiagsm != nil {
			return nil, fmt.Errorf("encoding smsf-non-3gpp-absentSubscriberDiagSM: %w", tagErr_enc_smsfnon3gppabsentsubscriberdiagsm)
		}
		enc_smsfnon3gppabsentsubscriberdiagsm = retagged_enc_smsfnon3gppabsentsubscriberdiagsm
		children = append(children, enc_smsfnon3gppabsentsubscriberdiagsm...)
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

// MarshalDER encodes ReportSMDeliveryStatusArg to DER format.
func (v *ReportSMDeliveryStatusArg) MarshalDER() ([]byte, error) {
	var children []byte
	enc_msisdn := ber.EncodeOctetString([]byte(v.Msisdn))
	children = append(children, enc_msisdn...)
	enc_servicecentreaddress := ber.EncodeOctetString([]byte(v.ServiceCentreAddress))
	children = append(children, enc_servicecentreaddress...)
	enc_smdeliveryoutcome := ber.EncodeEnumerated(int64(v.SmDeliveryOutcome))
	children = append(children, enc_smdeliveryoutcome...)
	if v.AbsentSubscriberDiagnosticSM != nil {
		enc_absentsubscriberdiagnosticsm := ber.EncodeInteger(int64(*v.AbsentSubscriberDiagnosticSM))
		retagged_enc_absentsubscriberdiagnosticsm, tagErr_enc_absentsubscriberdiagnosticsm := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_absentsubscriberdiagnosticsm)
		if tagErr_enc_absentsubscriberdiagnosticsm != nil {
			return nil, fmt.Errorf("encoding absentSubscriberDiagnosticSM: %w", tagErr_enc_absentsubscriberdiagnosticsm)
		}
		enc_absentsubscriberdiagnosticsm = retagged_enc_absentsubscriberdiagnosticsm
		children = append(children, enc_absentsubscriberdiagnosticsm...)
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
	if v.GprsSupportIndicator != nil {
		enc_gprssupportindicator := ber.EncodeNull()
		retagged_enc_gprssupportindicator, tagErr_enc_gprssupportindicator := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_gprssupportindicator)
		if tagErr_enc_gprssupportindicator != nil {
			return nil, fmt.Errorf("encoding gprsSupportIndicator: %w", tagErr_enc_gprssupportindicator)
		}
		enc_gprssupportindicator = retagged_enc_gprssupportindicator
		children = append(children, enc_gprssupportindicator...)
	}
	if v.DeliveryOutcomeIndicator != nil {
		enc_deliveryoutcomeindicator := ber.EncodeNull()
		retagged_enc_deliveryoutcomeindicator, tagErr_enc_deliveryoutcomeindicator := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, enc_deliveryoutcomeindicator)
		if tagErr_enc_deliveryoutcomeindicator != nil {
			return nil, fmt.Errorf("encoding deliveryOutcomeIndicator: %w", tagErr_enc_deliveryoutcomeindicator)
		}
		enc_deliveryoutcomeindicator = retagged_enc_deliveryoutcomeindicator
		children = append(children, enc_deliveryoutcomeindicator...)
	}
	if v.AdditionalSMDeliveryOutcome != nil {
		enc_additionalsmdeliveryoutcome := ber.EncodeEnumerated(int64(*v.AdditionalSMDeliveryOutcome))
		retagged_enc_additionalsmdeliveryoutcome, tagErr_enc_additionalsmdeliveryoutcome := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, enc_additionalsmdeliveryoutcome)
		if tagErr_enc_additionalsmdeliveryoutcome != nil {
			return nil, fmt.Errorf("encoding additionalSM-DeliveryOutcome: %w", tagErr_enc_additionalsmdeliveryoutcome)
		}
		enc_additionalsmdeliveryoutcome = retagged_enc_additionalsmdeliveryoutcome
		children = append(children, enc_additionalsmdeliveryoutcome...)
	}
	if v.AdditionalAbsentSubscriberDiagnosticSM != nil {
		enc_additionalabsentsubscriberdiagnosticsm := ber.EncodeInteger(int64(*v.AdditionalAbsentSubscriberDiagnosticSM))
		retagged_enc_additionalabsentsubscriberdiagnosticsm, tagErr_enc_additionalabsentsubscriberdiagnosticsm := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 5, enc_additionalabsentsubscriberdiagnosticsm)
		if tagErr_enc_additionalabsentsubscriberdiagnosticsm != nil {
			return nil, fmt.Errorf("encoding additionalAbsentSubscriberDiagnosticSM: %w", tagErr_enc_additionalabsentsubscriberdiagnosticsm)
		}
		enc_additionalabsentsubscriberdiagnosticsm = retagged_enc_additionalabsentsubscriberdiagnosticsm
		children = append(children, enc_additionalabsentsubscriberdiagnosticsm...)
	}
	if v.IpSmGwIndicator != nil {
		enc_ipsmgwindicator := ber.EncodeNull()
		retagged_enc_ipsmgwindicator, tagErr_enc_ipsmgwindicator := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 6, enc_ipsmgwindicator)
		if tagErr_enc_ipsmgwindicator != nil {
			return nil, fmt.Errorf("encoding ip-sm-gw-Indicator: %w", tagErr_enc_ipsmgwindicator)
		}
		enc_ipsmgwindicator = retagged_enc_ipsmgwindicator
		children = append(children, enc_ipsmgwindicator...)
	}
	if v.IpSmGwSmDeliveryOutcome != nil {
		enc_ipsmgwsmdeliveryoutcome := ber.EncodeEnumerated(int64(*v.IpSmGwSmDeliveryOutcome))
		retagged_enc_ipsmgwsmdeliveryoutcome, tagErr_enc_ipsmgwsmdeliveryoutcome := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 7, enc_ipsmgwsmdeliveryoutcome)
		if tagErr_enc_ipsmgwsmdeliveryoutcome != nil {
			return nil, fmt.Errorf("encoding ip-sm-gw-sm-deliveryOutcome: %w", tagErr_enc_ipsmgwsmdeliveryoutcome)
		}
		enc_ipsmgwsmdeliveryoutcome = retagged_enc_ipsmgwsmdeliveryoutcome
		children = append(children, enc_ipsmgwsmdeliveryoutcome...)
	}
	if v.IpSmGwAbsentSubscriberDiagnosticSM != nil {
		enc_ipsmgwabsentsubscriberdiagnosticsm := ber.EncodeInteger(int64(*v.IpSmGwAbsentSubscriberDiagnosticSM))
		retagged_enc_ipsmgwabsentsubscriberdiagnosticsm, tagErr_enc_ipsmgwabsentsubscriberdiagnosticsm := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 8, enc_ipsmgwabsentsubscriberdiagnosticsm)
		if tagErr_enc_ipsmgwabsentsubscriberdiagnosticsm != nil {
			return nil, fmt.Errorf("encoding ip-sm-gw-absentSubscriberDiagnosticSM: %w", tagErr_enc_ipsmgwabsentsubscriberdiagnosticsm)
		}
		enc_ipsmgwabsentsubscriberdiagnosticsm = retagged_enc_ipsmgwabsentsubscriberdiagnosticsm
		children = append(children, enc_ipsmgwabsentsubscriberdiagnosticsm...)
	}
	if v.Imsi != nil {
		enc_imsi := ber.EncodeOctetString([]byte(*v.Imsi))
		retagged_enc_imsi, tagErr_enc_imsi := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 9, enc_imsi)
		if tagErr_enc_imsi != nil {
			return nil, fmt.Errorf("encoding imsi: %w", tagErr_enc_imsi)
		}
		enc_imsi = retagged_enc_imsi
		children = append(children, enc_imsi...)
	}
	if v.SingleAttemptDelivery != nil {
		enc_singleattemptdelivery := ber.EncodeNull()
		retagged_enc_singleattemptdelivery, tagErr_enc_singleattemptdelivery := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 10, enc_singleattemptdelivery)
		if tagErr_enc_singleattemptdelivery != nil {
			return nil, fmt.Errorf("encoding singleAttemptDelivery: %w", tagErr_enc_singleattemptdelivery)
		}
		enc_singleattemptdelivery = retagged_enc_singleattemptdelivery
		children = append(children, enc_singleattemptdelivery...)
	}
	if v.CorrelationID != nil {
		enc_correlationid, err := v.CorrelationID.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding correlationID: %w", err)
		}
		retagged_enc_correlationid, tagErr_enc_correlationid := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 11, enc_correlationid)
		if tagErr_enc_correlationid != nil {
			return nil, fmt.Errorf("encoding correlationID: %w", tagErr_enc_correlationid)
		}
		enc_correlationid = retagged_enc_correlationid
		children = append(children, enc_correlationid...)
	}
	if v.Smsf3gppDeliveryOutcomeIndicator != nil {
		enc_smsf3gppdeliveryoutcomeindicator := ber.EncodeNull()
		retagged_enc_smsf3gppdeliveryoutcomeindicator, tagErr_enc_smsf3gppdeliveryoutcomeindicator := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 12, enc_smsf3gppdeliveryoutcomeindicator)
		if tagErr_enc_smsf3gppdeliveryoutcomeindicator != nil {
			return nil, fmt.Errorf("encoding smsf-3gpp-deliveryOutcomeIndicator: %w", tagErr_enc_smsf3gppdeliveryoutcomeindicator)
		}
		enc_smsf3gppdeliveryoutcomeindicator = retagged_enc_smsf3gppdeliveryoutcomeindicator
		children = append(children, enc_smsf3gppdeliveryoutcomeindicator...)
	}
	if v.Smsf3gppDeliveryOutcome != nil {
		enc_smsf3gppdeliveryoutcome := ber.EncodeEnumerated(int64(*v.Smsf3gppDeliveryOutcome))
		retagged_enc_smsf3gppdeliveryoutcome, tagErr_enc_smsf3gppdeliveryoutcome := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 13, enc_smsf3gppdeliveryoutcome)
		if tagErr_enc_smsf3gppdeliveryoutcome != nil {
			return nil, fmt.Errorf("encoding smsf-3gpp-deliveryOutcome: %w", tagErr_enc_smsf3gppdeliveryoutcome)
		}
		enc_smsf3gppdeliveryoutcome = retagged_enc_smsf3gppdeliveryoutcome
		children = append(children, enc_smsf3gppdeliveryoutcome...)
	}
	if v.Smsf3gppAbsentSubscriberDiagSM != nil {
		enc_smsf3gppabsentsubscriberdiagsm := ber.EncodeInteger(int64(*v.Smsf3gppAbsentSubscriberDiagSM))
		retagged_enc_smsf3gppabsentsubscriberdiagsm, tagErr_enc_smsf3gppabsentsubscriberdiagsm := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 14, enc_smsf3gppabsentsubscriberdiagsm)
		if tagErr_enc_smsf3gppabsentsubscriberdiagsm != nil {
			return nil, fmt.Errorf("encoding smsf-3gpp-absentSubscriberDiagSM: %w", tagErr_enc_smsf3gppabsentsubscriberdiagsm)
		}
		enc_smsf3gppabsentsubscriberdiagsm = retagged_enc_smsf3gppabsentsubscriberdiagsm
		children = append(children, enc_smsf3gppabsentsubscriberdiagsm...)
	}
	if v.SmsfNon3gppDeliveryOutcomeIndicator != nil {
		enc_smsfnon3gppdeliveryoutcomeindicator := ber.EncodeNull()
		retagged_enc_smsfnon3gppdeliveryoutcomeindicator, tagErr_enc_smsfnon3gppdeliveryoutcomeindicator := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 15, enc_smsfnon3gppdeliveryoutcomeindicator)
		if tagErr_enc_smsfnon3gppdeliveryoutcomeindicator != nil {
			return nil, fmt.Errorf("encoding smsf-non-3gpp-deliveryOutcomeIndicator: %w", tagErr_enc_smsfnon3gppdeliveryoutcomeindicator)
		}
		enc_smsfnon3gppdeliveryoutcomeindicator = retagged_enc_smsfnon3gppdeliveryoutcomeindicator
		children = append(children, enc_smsfnon3gppdeliveryoutcomeindicator...)
	}
	if v.SmsfNon3gppDeliveryOutcome != nil {
		enc_smsfnon3gppdeliveryoutcome := ber.EncodeEnumerated(int64(*v.SmsfNon3gppDeliveryOutcome))
		retagged_enc_smsfnon3gppdeliveryoutcome, tagErr_enc_smsfnon3gppdeliveryoutcome := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 16, enc_smsfnon3gppdeliveryoutcome)
		if tagErr_enc_smsfnon3gppdeliveryoutcome != nil {
			return nil, fmt.Errorf("encoding smsf-non-3gpp-deliveryOutcome: %w", tagErr_enc_smsfnon3gppdeliveryoutcome)
		}
		enc_smsfnon3gppdeliveryoutcome = retagged_enc_smsfnon3gppdeliveryoutcome
		children = append(children, enc_smsfnon3gppdeliveryoutcome...)
	}
	if v.SmsfNon3gppAbsentSubscriberDiagSM != nil {
		enc_smsfnon3gppabsentsubscriberdiagsm := ber.EncodeInteger(int64(*v.SmsfNon3gppAbsentSubscriberDiagSM))
		retagged_enc_smsfnon3gppabsentsubscriberdiagsm, tagErr_enc_smsfnon3gppabsentsubscriberdiagsm := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 17, enc_smsfnon3gppabsentsubscriberdiagsm)
		if tagErr_enc_smsfnon3gppabsentsubscriberdiagsm != nil {
			return nil, fmt.Errorf("encoding smsf-non-3gpp-absentSubscriberDiagSM: %w", tagErr_enc_smsfnon3gppabsentsubscriberdiagsm)
		}
		enc_smsfnon3gppabsentsubscriberdiagsm = retagged_enc_smsfnon3gppabsentsubscriberdiagsm
		children = append(children, enc_smsfnon3gppabsentsubscriberdiagsm...)
	}
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
		children = append(children, ext...)
	}
	encoded := ber.EncodeSequence(children)
	if err := ber.ValidateDERElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding ReportSMDeliveryStatusArg as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes ReportSMDeliveryStatusArg from BER/DER format.
func (v *ReportSMDeliveryStatusArg) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding ReportSMDeliveryStatusArg SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "ReportSMDeliveryStatusArg", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode msisdn
	if offset >= len(content) {
		return fmt.Errorf("missing required field msisdn")
	}
	val_msisdn, n, err := ber.DecodeOctetString(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding msisdn: %w", err)
	}
	v.Msisdn = ISDNAddressString(val_msisdn)
	offset += n
	// Decode serviceCentreAddress
	if offset >= len(content) {
		return fmt.Errorf("missing required field serviceCentreAddress")
	}
	val_servicecentreaddress, n, err := ber.DecodeOctetString(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding serviceCentreAddress: %w", err)
	}
	v.ServiceCentreAddress = AddressString(val_servicecentreaddress)
	offset += n
	// Decode sm-DeliveryOutcome
	if offset >= len(content) {
		return fmt.Errorf("missing required field sm-DeliveryOutcome")
	}
	val_smdeliveryoutcome, n, err := ber.DecodeInteger(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding sm-DeliveryOutcome: %w", err)
	}
	v.SmDeliveryOutcome = SMDeliveryOutcome(val_smdeliveryoutcome)
	offset += n
	// Decode absentSubscriberDiagnosticSM
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
				decodedTag_absentsubscriberdiagnosticsm, n_absentsubscriberdiagnosticsm, rawVal_absentsubscriberdiagnosticsm, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding absentSubscriberDiagnosticSM: %w", err)
				}
				if decodedTag_absentsubscriberdiagnosticsm.Class != tag.ClassContextSpecific || decodedTag_absentsubscriberdiagnosticsm.Number != 0 || decodedTag_absentsubscriberdiagnosticsm.Constructed != false {
					return fmt.Errorf("decoding absentSubscriberDiagnosticSM: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_absentsubscriberdiagnosticsm)
				}
				decVal_absentsubscriberdiagnosticsm, intErr := ber.DecodeIntegerValue(rawVal_absentsubscriberdiagnosticsm)
				if intErr != nil {
					return fmt.Errorf("decoding absentSubscriberDiagnosticSM: %w", intErr)
				}
				tmp_absentsubscriberdiagnosticsm := AbsentSubscriberDiagnosticSM(decVal_absentsubscriberdiagnosticsm)
				v.AbsentSubscriberDiagnosticSM = &tmp_absentsubscriberdiagnosticsm
				offset += n_absentsubscriberdiagnosticsm
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
	// Decode gprsSupportIndicator
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2 {
				decodedTag_gprssupportindicator, n_gprssupportindicator, rawVal_gprssupportindicator, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding gprsSupportIndicator: %w", err)
				}
				if decodedTag_gprssupportindicator.Class != tag.ClassContextSpecific || decodedTag_gprssupportindicator.Number != 2 || decodedTag_gprssupportindicator.Constructed != false {
					return fmt.Errorf("decoding gprsSupportIndicator: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_gprssupportindicator)
				}
				if len(rawVal_gprssupportindicator) != 0 {
					return fmt.Errorf("decoding gprsSupportIndicator: %w: NULL content length %d", ber.ErrInvalidValue, len(rawVal_gprssupportindicator))
				}
				v.GprsSupportIndicator = &struct{}{}
				offset += n_gprssupportindicator
			}
		}
	}
	// Decode deliveryOutcomeIndicator
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3 {
				decodedTag_deliveryoutcomeindicator, n_deliveryoutcomeindicator, rawVal_deliveryoutcomeindicator, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding deliveryOutcomeIndicator: %w", err)
				}
				if decodedTag_deliveryoutcomeindicator.Class != tag.ClassContextSpecific || decodedTag_deliveryoutcomeindicator.Number != 3 || decodedTag_deliveryoutcomeindicator.Constructed != false {
					return fmt.Errorf("decoding deliveryOutcomeIndicator: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_deliveryoutcomeindicator)
				}
				if len(rawVal_deliveryoutcomeindicator) != 0 {
					return fmt.Errorf("decoding deliveryOutcomeIndicator: %w: NULL content length %d", ber.ErrInvalidValue, len(rawVal_deliveryoutcomeindicator))
				}
				v.DeliveryOutcomeIndicator = &struct{}{}
				offset += n_deliveryoutcomeindicator
			}
		}
	}
	// Decode additionalSM-DeliveryOutcome
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4 {
				decodedTag_additionalsmdeliveryoutcome, n_additionalsmdeliveryoutcome, rawVal_additionalsmdeliveryoutcome, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding additionalSM-DeliveryOutcome: %w", err)
				}
				if decodedTag_additionalsmdeliveryoutcome.Class != tag.ClassContextSpecific || decodedTag_additionalsmdeliveryoutcome.Number != 4 || decodedTag_additionalsmdeliveryoutcome.Constructed != false {
					return fmt.Errorf("decoding additionalSM-DeliveryOutcome: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_additionalsmdeliveryoutcome)
				}
				decVal_additionalsmdeliveryoutcome, intErr := ber.DecodeIntegerValue(rawVal_additionalsmdeliveryoutcome)
				if intErr != nil {
					return fmt.Errorf("decoding additionalSM-DeliveryOutcome: %w", intErr)
				}
				tmp_additionalsmdeliveryoutcome := SMDeliveryOutcome(decVal_additionalsmdeliveryoutcome)
				v.AdditionalSMDeliveryOutcome = &tmp_additionalsmdeliveryoutcome
				offset += n_additionalsmdeliveryoutcome
			}
		}
	}
	// Decode additionalAbsentSubscriberDiagnosticSM
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 5 {
				decodedTag_additionalabsentsubscriberdiagnosticsm, n_additionalabsentsubscriberdiagnosticsm, rawVal_additionalabsentsubscriberdiagnosticsm, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding additionalAbsentSubscriberDiagnosticSM: %w", err)
				}
				if decodedTag_additionalabsentsubscriberdiagnosticsm.Class != tag.ClassContextSpecific || decodedTag_additionalabsentsubscriberdiagnosticsm.Number != 5 || decodedTag_additionalabsentsubscriberdiagnosticsm.Constructed != false {
					return fmt.Errorf("decoding additionalAbsentSubscriberDiagnosticSM: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_additionalabsentsubscriberdiagnosticsm)
				}
				decVal_additionalabsentsubscriberdiagnosticsm, intErr := ber.DecodeIntegerValue(rawVal_additionalabsentsubscriberdiagnosticsm)
				if intErr != nil {
					return fmt.Errorf("decoding additionalAbsentSubscriberDiagnosticSM: %w", intErr)
				}
				tmp_additionalabsentsubscriberdiagnosticsm := AbsentSubscriberDiagnosticSM(decVal_additionalabsentsubscriberdiagnosticsm)
				v.AdditionalAbsentSubscriberDiagnosticSM = &tmp_additionalabsentsubscriberdiagnosticsm
				offset += n_additionalabsentsubscriberdiagnosticsm
			}
		}
	}
	// Decode ip-sm-gw-Indicator
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 6 {
				decodedTag_ipsmgwindicator, n_ipsmgwindicator, rawVal_ipsmgwindicator, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding ip-sm-gw-Indicator: %w", err)
				}
				if decodedTag_ipsmgwindicator.Class != tag.ClassContextSpecific || decodedTag_ipsmgwindicator.Number != 6 || decodedTag_ipsmgwindicator.Constructed != false {
					return fmt.Errorf("decoding ip-sm-gw-Indicator: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_ipsmgwindicator)
				}
				if len(rawVal_ipsmgwindicator) != 0 {
					return fmt.Errorf("decoding ip-sm-gw-Indicator: %w: NULL content length %d", ber.ErrInvalidValue, len(rawVal_ipsmgwindicator))
				}
				v.IpSmGwIndicator = &struct{}{}
				offset += n_ipsmgwindicator
			}
		}
	}
	// Decode ip-sm-gw-sm-deliveryOutcome
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 7 {
				decodedTag_ipsmgwsmdeliveryoutcome, n_ipsmgwsmdeliveryoutcome, rawVal_ipsmgwsmdeliveryoutcome, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding ip-sm-gw-sm-deliveryOutcome: %w", err)
				}
				if decodedTag_ipsmgwsmdeliveryoutcome.Class != tag.ClassContextSpecific || decodedTag_ipsmgwsmdeliveryoutcome.Number != 7 || decodedTag_ipsmgwsmdeliveryoutcome.Constructed != false {
					return fmt.Errorf("decoding ip-sm-gw-sm-deliveryOutcome: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_ipsmgwsmdeliveryoutcome)
				}
				decVal_ipsmgwsmdeliveryoutcome, intErr := ber.DecodeIntegerValue(rawVal_ipsmgwsmdeliveryoutcome)
				if intErr != nil {
					return fmt.Errorf("decoding ip-sm-gw-sm-deliveryOutcome: %w", intErr)
				}
				tmp_ipsmgwsmdeliveryoutcome := SMDeliveryOutcome(decVal_ipsmgwsmdeliveryoutcome)
				v.IpSmGwSmDeliveryOutcome = &tmp_ipsmgwsmdeliveryoutcome
				offset += n_ipsmgwsmdeliveryoutcome
			}
		}
	}
	// Decode ip-sm-gw-absentSubscriberDiagnosticSM
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 8 {
				decodedTag_ipsmgwabsentsubscriberdiagnosticsm, n_ipsmgwabsentsubscriberdiagnosticsm, rawVal_ipsmgwabsentsubscriberdiagnosticsm, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding ip-sm-gw-absentSubscriberDiagnosticSM: %w", err)
				}
				if decodedTag_ipsmgwabsentsubscriberdiagnosticsm.Class != tag.ClassContextSpecific || decodedTag_ipsmgwabsentsubscriberdiagnosticsm.Number != 8 || decodedTag_ipsmgwabsentsubscriberdiagnosticsm.Constructed != false {
					return fmt.Errorf("decoding ip-sm-gw-absentSubscriberDiagnosticSM: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_ipsmgwabsentsubscriberdiagnosticsm)
				}
				decVal_ipsmgwabsentsubscriberdiagnosticsm, intErr := ber.DecodeIntegerValue(rawVal_ipsmgwabsentsubscriberdiagnosticsm)
				if intErr != nil {
					return fmt.Errorf("decoding ip-sm-gw-absentSubscriberDiagnosticSM: %w", intErr)
				}
				tmp_ipsmgwabsentsubscriberdiagnosticsm := AbsentSubscriberDiagnosticSM(decVal_ipsmgwabsentsubscriberdiagnosticsm)
				v.IpSmGwAbsentSubscriberDiagnosticSM = &tmp_ipsmgwabsentsubscriberdiagnosticsm
				offset += n_ipsmgwabsentsubscriberdiagnosticsm
			}
		}
	}
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
	// Decode singleAttemptDelivery
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 10 {
				decodedTag_singleattemptdelivery, n_singleattemptdelivery, rawVal_singleattemptdelivery, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding singleAttemptDelivery: %w", err)
				}
				if decodedTag_singleattemptdelivery.Class != tag.ClassContextSpecific || decodedTag_singleattemptdelivery.Number != 10 || decodedTag_singleattemptdelivery.Constructed != false {
					return fmt.Errorf("decoding singleAttemptDelivery: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_singleattemptdelivery)
				}
				if len(rawVal_singleattemptdelivery) != 0 {
					return fmt.Errorf("decoding singleAttemptDelivery: %w: NULL content length %d", ber.ErrInvalidValue, len(rawVal_singleattemptdelivery))
				}
				v.SingleAttemptDelivery = &struct{}{}
				offset += n_singleattemptdelivery
			}
		}
	}
	// Decode correlationID
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 11 {
				decodedTag_correlationid, n_correlationid, rawVal_correlationid, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding correlationID: %w", err)
				}
				if decodedTag_correlationid.Class != tag.ClassContextSpecific || decodedTag_correlationid.Number != 11 || decodedTag_correlationid.Constructed != true {
					return fmt.Errorf("decoding correlationID: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_correlationid)
				}
				reconstructed_correlationid := ber.EncodeSequence(rawVal_correlationid)
				var dec_correlationid CorrelationID
				if unmErr := dec_correlationid.UnmarshalBER(reconstructed_correlationid); unmErr != nil {
					return fmt.Errorf("decoding correlationID: %w", unmErr)
				}
				v.CorrelationID = &dec_correlationid
				offset += n_correlationid
			}
		}
	}
	// Decode smsf-3gpp-deliveryOutcomeIndicator
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 12 {
				decodedTag_smsf3gppdeliveryoutcomeindicator, n_smsf3gppdeliveryoutcomeindicator, rawVal_smsf3gppdeliveryoutcomeindicator, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding smsf-3gpp-deliveryOutcomeIndicator: %w", err)
				}
				if decodedTag_smsf3gppdeliveryoutcomeindicator.Class != tag.ClassContextSpecific || decodedTag_smsf3gppdeliveryoutcomeindicator.Number != 12 || decodedTag_smsf3gppdeliveryoutcomeindicator.Constructed != false {
					return fmt.Errorf("decoding smsf-3gpp-deliveryOutcomeIndicator: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_smsf3gppdeliveryoutcomeindicator)
				}
				if len(rawVal_smsf3gppdeliveryoutcomeindicator) != 0 {
					return fmt.Errorf("decoding smsf-3gpp-deliveryOutcomeIndicator: %w: NULL content length %d", ber.ErrInvalidValue, len(rawVal_smsf3gppdeliveryoutcomeindicator))
				}
				v.Smsf3gppDeliveryOutcomeIndicator = &struct{}{}
				offset += n_smsf3gppdeliveryoutcomeindicator
			}
		}
	}
	// Decode smsf-3gpp-deliveryOutcome
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 13 {
				decodedTag_smsf3gppdeliveryoutcome, n_smsf3gppdeliveryoutcome, rawVal_smsf3gppdeliveryoutcome, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding smsf-3gpp-deliveryOutcome: %w", err)
				}
				if decodedTag_smsf3gppdeliveryoutcome.Class != tag.ClassContextSpecific || decodedTag_smsf3gppdeliveryoutcome.Number != 13 || decodedTag_smsf3gppdeliveryoutcome.Constructed != false {
					return fmt.Errorf("decoding smsf-3gpp-deliveryOutcome: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_smsf3gppdeliveryoutcome)
				}
				decVal_smsf3gppdeliveryoutcome, intErr := ber.DecodeIntegerValue(rawVal_smsf3gppdeliveryoutcome)
				if intErr != nil {
					return fmt.Errorf("decoding smsf-3gpp-deliveryOutcome: %w", intErr)
				}
				tmp_smsf3gppdeliveryoutcome := SMDeliveryOutcome(decVal_smsf3gppdeliveryoutcome)
				v.Smsf3gppDeliveryOutcome = &tmp_smsf3gppdeliveryoutcome
				offset += n_smsf3gppdeliveryoutcome
			}
		}
	}
	// Decode smsf-3gpp-absentSubscriberDiagSM
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 14 {
				decodedTag_smsf3gppabsentsubscriberdiagsm, n_smsf3gppabsentsubscriberdiagsm, rawVal_smsf3gppabsentsubscriberdiagsm, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding smsf-3gpp-absentSubscriberDiagSM: %w", err)
				}
				if decodedTag_smsf3gppabsentsubscriberdiagsm.Class != tag.ClassContextSpecific || decodedTag_smsf3gppabsentsubscriberdiagsm.Number != 14 || decodedTag_smsf3gppabsentsubscriberdiagsm.Constructed != false {
					return fmt.Errorf("decoding smsf-3gpp-absentSubscriberDiagSM: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_smsf3gppabsentsubscriberdiagsm)
				}
				decVal_smsf3gppabsentsubscriberdiagsm, intErr := ber.DecodeIntegerValue(rawVal_smsf3gppabsentsubscriberdiagsm)
				if intErr != nil {
					return fmt.Errorf("decoding smsf-3gpp-absentSubscriberDiagSM: %w", intErr)
				}
				tmp_smsf3gppabsentsubscriberdiagsm := AbsentSubscriberDiagnosticSM(decVal_smsf3gppabsentsubscriberdiagsm)
				v.Smsf3gppAbsentSubscriberDiagSM = &tmp_smsf3gppabsentsubscriberdiagsm
				offset += n_smsf3gppabsentsubscriberdiagsm
			}
		}
	}
	// Decode smsf-non-3gpp-deliveryOutcomeIndicator
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 15 {
				decodedTag_smsfnon3gppdeliveryoutcomeindicator, n_smsfnon3gppdeliveryoutcomeindicator, rawVal_smsfnon3gppdeliveryoutcomeindicator, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding smsf-non-3gpp-deliveryOutcomeIndicator: %w", err)
				}
				if decodedTag_smsfnon3gppdeliveryoutcomeindicator.Class != tag.ClassContextSpecific || decodedTag_smsfnon3gppdeliveryoutcomeindicator.Number != 15 || decodedTag_smsfnon3gppdeliveryoutcomeindicator.Constructed != false {
					return fmt.Errorf("decoding smsf-non-3gpp-deliveryOutcomeIndicator: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_smsfnon3gppdeliveryoutcomeindicator)
				}
				if len(rawVal_smsfnon3gppdeliveryoutcomeindicator) != 0 {
					return fmt.Errorf("decoding smsf-non-3gpp-deliveryOutcomeIndicator: %w: NULL content length %d", ber.ErrInvalidValue, len(rawVal_smsfnon3gppdeliveryoutcomeindicator))
				}
				v.SmsfNon3gppDeliveryOutcomeIndicator = &struct{}{}
				offset += n_smsfnon3gppdeliveryoutcomeindicator
			}
		}
	}
	// Decode smsf-non-3gpp-deliveryOutcome
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 16 {
				decodedTag_smsfnon3gppdeliveryoutcome, n_smsfnon3gppdeliveryoutcome, rawVal_smsfnon3gppdeliveryoutcome, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding smsf-non-3gpp-deliveryOutcome: %w", err)
				}
				if decodedTag_smsfnon3gppdeliveryoutcome.Class != tag.ClassContextSpecific || decodedTag_smsfnon3gppdeliveryoutcome.Number != 16 || decodedTag_smsfnon3gppdeliveryoutcome.Constructed != false {
					return fmt.Errorf("decoding smsf-non-3gpp-deliveryOutcome: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_smsfnon3gppdeliveryoutcome)
				}
				decVal_smsfnon3gppdeliveryoutcome, intErr := ber.DecodeIntegerValue(rawVal_smsfnon3gppdeliveryoutcome)
				if intErr != nil {
					return fmt.Errorf("decoding smsf-non-3gpp-deliveryOutcome: %w", intErr)
				}
				tmp_smsfnon3gppdeliveryoutcome := SMDeliveryOutcome(decVal_smsfnon3gppdeliveryoutcome)
				v.SmsfNon3gppDeliveryOutcome = &tmp_smsfnon3gppdeliveryoutcome
				offset += n_smsfnon3gppdeliveryoutcome
			}
		}
	}
	// Decode smsf-non-3gpp-absentSubscriberDiagSM
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 17 {
				decodedTag_smsfnon3gppabsentsubscriberdiagsm, n_smsfnon3gppabsentsubscriberdiagsm, rawVal_smsfnon3gppabsentsubscriberdiagsm, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding smsf-non-3gpp-absentSubscriberDiagSM: %w", err)
				}
				if decodedTag_smsfnon3gppabsentsubscriberdiagsm.Class != tag.ClassContextSpecific || decodedTag_smsfnon3gppabsentsubscriberdiagsm.Number != 17 || decodedTag_smsfnon3gppabsentsubscriberdiagsm.Constructed != false {
					return fmt.Errorf("decoding smsf-non-3gpp-absentSubscriberDiagSM: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_smsfnon3gppabsentsubscriberdiagsm)
				}
				decVal_smsfnon3gppabsentsubscriberdiagsm, intErr := ber.DecodeIntegerValue(rawVal_smsfnon3gppabsentsubscriberdiagsm)
				if intErr != nil {
					return fmt.Errorf("decoding smsf-non-3gpp-absentSubscriberDiagSM: %w", intErr)
				}
				tmp_smsfnon3gppabsentsubscriberdiagsm := AbsentSubscriberDiagnosticSM(decVal_smsfnon3gppabsentsubscriberdiagsm)
				v.SmsfNon3gppAbsentSubscriberDiagSM = &tmp_smsfnon3gppabsentsubscriberdiagsm
				offset += n_smsfnon3gppabsentsubscriberdiagsm
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "ReportSMDeliveryStatusArg", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes ReportSMDeliveryStatusRes to BER format.
func (v *ReportSMDeliveryStatusRes) MarshalBER() ([]byte, error) {
	var children []byte
	if v.StoredMSISDN != nil {
		enc_storedmsisdn := ber.EncodeOctetString([]byte(*v.StoredMSISDN))
		children = append(children, enc_storedmsisdn...)
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

// MarshalDER encodes ReportSMDeliveryStatusRes to DER format.
func (v *ReportSMDeliveryStatusRes) MarshalDER() ([]byte, error) {
	var children []byte
	if v.StoredMSISDN != nil {
		enc_storedmsisdn := ber.EncodeOctetString([]byte(*v.StoredMSISDN))
		children = append(children, enc_storedmsisdn...)
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
		return nil, fmt.Errorf("encoding ReportSMDeliveryStatusRes as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes ReportSMDeliveryStatusRes from BER/DER format.
func (v *ReportSMDeliveryStatusRes) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding ReportSMDeliveryStatusRes SEQUENCE: %w", err)
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
				val_storedmsisdn, n, err := ber.DecodeOctetString(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding storedMSISDN: %w", err)
				}
				tmp_storedmsisdn := ISDNAddressString(val_storedmsisdn)
				v.StoredMSISDN = &tmp_storedmsisdn
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
			return &ber.DecodeError{Offset: offset, TypeName: "ReportSMDeliveryStatusRes", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes AlertServiceCentreArg to BER format.
func (v *AlertServiceCentreArg) MarshalBER() ([]byte, error) {
	var children []byte
	enc_msisdn := ber.EncodeOctetString([]byte(v.Msisdn))
	children = append(children, enc_msisdn...)
	enc_servicecentreaddress := ber.EncodeOctetString([]byte(v.ServiceCentreAddress))
	children = append(children, enc_servicecentreaddress...)
	if v.Imsi != nil {
		enc_imsi := ber.EncodeOctetString([]byte(*v.Imsi))
		children = append(children, enc_imsi...)
	}
	if v.CorrelationID != nil {
		enc_correlationid, err := v.CorrelationID.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding correlationID: %w", err)
		}
		children = append(children, enc_correlationid...)
	}
	if v.MaximumUeAvailabilityTime != nil {
		enc_maximumueavailabilitytime := ber.EncodeOctetString([]byte(*v.MaximumUeAvailabilityTime))
		retagged_enc_maximumueavailabilitytime, tagErr_enc_maximumueavailabilitytime := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_maximumueavailabilitytime)
		if tagErr_enc_maximumueavailabilitytime != nil {
			return nil, fmt.Errorf("encoding maximumUeAvailabilityTime: %w", tagErr_enc_maximumueavailabilitytime)
		}
		enc_maximumueavailabilitytime = retagged_enc_maximumueavailabilitytime
		children = append(children, enc_maximumueavailabilitytime...)
	}
	if v.SmsGmscAlertEvent != nil {
		enc_smsgmscalertevent := ber.EncodeEnumerated(int64(*v.SmsGmscAlertEvent))
		retagged_enc_smsgmscalertevent, tagErr_enc_smsgmscalertevent := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_smsgmscalertevent)
		if tagErr_enc_smsgmscalertevent != nil {
			return nil, fmt.Errorf("encoding smsGmscAlertEvent: %w", tagErr_enc_smsgmscalertevent)
		}
		enc_smsgmscalertevent = retagged_enc_smsgmscalertevent
		children = append(children, enc_smsgmscalertevent...)
	}
	if v.SmsGmscDiameterAddress != nil {
		enc_smsgmscdiameteraddress, err := v.SmsGmscDiameterAddress.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding smsGmscDiameterAddress: %w", err)
		}
		retagged_enc_smsgmscdiameteraddress, tagErr_enc_smsgmscdiameteraddress := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_smsgmscdiameteraddress)
		if tagErr_enc_smsgmscdiameteraddress != nil {
			return nil, fmt.Errorf("encoding smsGmscDiameterAddress: %w", tagErr_enc_smsgmscdiameteraddress)
		}
		enc_smsgmscdiameteraddress = retagged_enc_smsgmscdiameteraddress
		children = append(children, enc_smsgmscdiameteraddress...)
	}
	if v.NewSGSNNumber != nil {
		enc_newsgsnnumber := ber.EncodeOctetString([]byte(*v.NewSGSNNumber))
		retagged_enc_newsgsnnumber, tagErr_enc_newsgsnnumber := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, enc_newsgsnnumber)
		if tagErr_enc_newsgsnnumber != nil {
			return nil, fmt.Errorf("encoding newSGSNNumber: %w", tagErr_enc_newsgsnnumber)
		}
		enc_newsgsnnumber = retagged_enc_newsgsnnumber
		children = append(children, enc_newsgsnnumber...)
	}
	if v.NewSGSNDiameterAddress != nil {
		enc_newsgsndiameteraddress, err := v.NewSGSNDiameterAddress.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding newSGSNDiameterAddress: %w", err)
		}
		retagged_enc_newsgsndiameteraddress, tagErr_enc_newsgsndiameteraddress := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, enc_newsgsndiameteraddress)
		if tagErr_enc_newsgsndiameteraddress != nil {
			return nil, fmt.Errorf("encoding newSGSNDiameterAddress: %w", tagErr_enc_newsgsndiameteraddress)
		}
		enc_newsgsndiameteraddress = retagged_enc_newsgsndiameteraddress
		children = append(children, enc_newsgsndiameteraddress...)
	}
	if v.NewMMENumber != nil {
		enc_newmmenumber := ber.EncodeOctetString([]byte(*v.NewMMENumber))
		retagged_enc_newmmenumber, tagErr_enc_newmmenumber := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 5, enc_newmmenumber)
		if tagErr_enc_newmmenumber != nil {
			return nil, fmt.Errorf("encoding newMMENumber: %w", tagErr_enc_newmmenumber)
		}
		enc_newmmenumber = retagged_enc_newmmenumber
		children = append(children, enc_newmmenumber...)
	}
	if v.NewMMEDiameterAddress != nil {
		enc_newmmediameteraddress, err := v.NewMMEDiameterAddress.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding newMMEDiameterAddress: %w", err)
		}
		retagged_enc_newmmediameteraddress, tagErr_enc_newmmediameteraddress := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 6, enc_newmmediameteraddress)
		if tagErr_enc_newmmediameteraddress != nil {
			return nil, fmt.Errorf("encoding newMMEDiameterAddress: %w", tagErr_enc_newmmediameteraddress)
		}
		enc_newmmediameteraddress = retagged_enc_newmmediameteraddress
		children = append(children, enc_newmmediameteraddress...)
	}
	if v.NewMSCNumber != nil {
		enc_newmscnumber := ber.EncodeOctetString([]byte(*v.NewMSCNumber))
		retagged_enc_newmscnumber, tagErr_enc_newmscnumber := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 7, enc_newmscnumber)
		if tagErr_enc_newmscnumber != nil {
			return nil, fmt.Errorf("encoding newMSCNumber: %w", tagErr_enc_newmscnumber)
		}
		enc_newmscnumber = retagged_enc_newmscnumber
		children = append(children, enc_newmscnumber...)
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

// MarshalDER encodes AlertServiceCentreArg to DER format.
func (v *AlertServiceCentreArg) MarshalDER() ([]byte, error) {
	var children []byte
	enc_msisdn := ber.EncodeOctetString([]byte(v.Msisdn))
	children = append(children, enc_msisdn...)
	enc_servicecentreaddress := ber.EncodeOctetString([]byte(v.ServiceCentreAddress))
	children = append(children, enc_servicecentreaddress...)
	if v.Imsi != nil {
		enc_imsi := ber.EncodeOctetString([]byte(*v.Imsi))
		children = append(children, enc_imsi...)
	}
	if v.CorrelationID != nil {
		enc_correlationid, err := v.CorrelationID.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding correlationID: %w", err)
		}
		children = append(children, enc_correlationid...)
	}
	if v.MaximumUeAvailabilityTime != nil {
		enc_maximumueavailabilitytime := ber.EncodeOctetString([]byte(*v.MaximumUeAvailabilityTime))
		retagged_enc_maximumueavailabilitytime, tagErr_enc_maximumueavailabilitytime := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_maximumueavailabilitytime)
		if tagErr_enc_maximumueavailabilitytime != nil {
			return nil, fmt.Errorf("encoding maximumUeAvailabilityTime: %w", tagErr_enc_maximumueavailabilitytime)
		}
		enc_maximumueavailabilitytime = retagged_enc_maximumueavailabilitytime
		children = append(children, enc_maximumueavailabilitytime...)
	}
	if v.SmsGmscAlertEvent != nil {
		enc_smsgmscalertevent := ber.EncodeEnumerated(int64(*v.SmsGmscAlertEvent))
		retagged_enc_smsgmscalertevent, tagErr_enc_smsgmscalertevent := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_smsgmscalertevent)
		if tagErr_enc_smsgmscalertevent != nil {
			return nil, fmt.Errorf("encoding smsGmscAlertEvent: %w", tagErr_enc_smsgmscalertevent)
		}
		enc_smsgmscalertevent = retagged_enc_smsgmscalertevent
		children = append(children, enc_smsgmscalertevent...)
	}
	if v.SmsGmscDiameterAddress != nil {
		enc_smsgmscdiameteraddress, err := v.SmsGmscDiameterAddress.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding smsGmscDiameterAddress: %w", err)
		}
		retagged_enc_smsgmscdiameteraddress, tagErr_enc_smsgmscdiameteraddress := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_smsgmscdiameteraddress)
		if tagErr_enc_smsgmscdiameteraddress != nil {
			return nil, fmt.Errorf("encoding smsGmscDiameterAddress: %w", tagErr_enc_smsgmscdiameteraddress)
		}
		enc_smsgmscdiameteraddress = retagged_enc_smsgmscdiameteraddress
		children = append(children, enc_smsgmscdiameteraddress...)
	}
	if v.NewSGSNNumber != nil {
		enc_newsgsnnumber := ber.EncodeOctetString([]byte(*v.NewSGSNNumber))
		retagged_enc_newsgsnnumber, tagErr_enc_newsgsnnumber := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, enc_newsgsnnumber)
		if tagErr_enc_newsgsnnumber != nil {
			return nil, fmt.Errorf("encoding newSGSNNumber: %w", tagErr_enc_newsgsnnumber)
		}
		enc_newsgsnnumber = retagged_enc_newsgsnnumber
		children = append(children, enc_newsgsnnumber...)
	}
	if v.NewSGSNDiameterAddress != nil {
		enc_newsgsndiameteraddress, err := v.NewSGSNDiameterAddress.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding newSGSNDiameterAddress: %w", err)
		}
		retagged_enc_newsgsndiameteraddress, tagErr_enc_newsgsndiameteraddress := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, enc_newsgsndiameteraddress)
		if tagErr_enc_newsgsndiameteraddress != nil {
			return nil, fmt.Errorf("encoding newSGSNDiameterAddress: %w", tagErr_enc_newsgsndiameteraddress)
		}
		enc_newsgsndiameteraddress = retagged_enc_newsgsndiameteraddress
		children = append(children, enc_newsgsndiameteraddress...)
	}
	if v.NewMMENumber != nil {
		enc_newmmenumber := ber.EncodeOctetString([]byte(*v.NewMMENumber))
		retagged_enc_newmmenumber, tagErr_enc_newmmenumber := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 5, enc_newmmenumber)
		if tagErr_enc_newmmenumber != nil {
			return nil, fmt.Errorf("encoding newMMENumber: %w", tagErr_enc_newmmenumber)
		}
		enc_newmmenumber = retagged_enc_newmmenumber
		children = append(children, enc_newmmenumber...)
	}
	if v.NewMMEDiameterAddress != nil {
		enc_newmmediameteraddress, err := v.NewMMEDiameterAddress.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding newMMEDiameterAddress: %w", err)
		}
		retagged_enc_newmmediameteraddress, tagErr_enc_newmmediameteraddress := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 6, enc_newmmediameteraddress)
		if tagErr_enc_newmmediameteraddress != nil {
			return nil, fmt.Errorf("encoding newMMEDiameterAddress: %w", tagErr_enc_newmmediameteraddress)
		}
		enc_newmmediameteraddress = retagged_enc_newmmediameteraddress
		children = append(children, enc_newmmediameteraddress...)
	}
	if v.NewMSCNumber != nil {
		enc_newmscnumber := ber.EncodeOctetString([]byte(*v.NewMSCNumber))
		retagged_enc_newmscnumber, tagErr_enc_newmscnumber := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 7, enc_newmscnumber)
		if tagErr_enc_newmscnumber != nil {
			return nil, fmt.Errorf("encoding newMSCNumber: %w", tagErr_enc_newmscnumber)
		}
		enc_newmscnumber = retagged_enc_newmscnumber
		children = append(children, enc_newmscnumber...)
	}
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
		children = append(children, ext...)
	}
	encoded := ber.EncodeSequence(children)
	if err := ber.ValidateDERElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding AlertServiceCentreArg as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes AlertServiceCentreArg from BER/DER format.
func (v *AlertServiceCentreArg) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding AlertServiceCentreArg SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "AlertServiceCentreArg", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode msisdn
	if offset >= len(content) {
		return fmt.Errorf("missing required field msisdn")
	}
	val_msisdn, n, err := ber.DecodeOctetString(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding msisdn: %w", err)
	}
	v.Msisdn = ISDNAddressString(val_msisdn)
	offset += n
	// Decode serviceCentreAddress
	if offset >= len(content) {
		return fmt.Errorf("missing required field serviceCentreAddress")
	}
	val_servicecentreaddress, n, err := ber.DecodeOctetString(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding serviceCentreAddress: %w", err)
	}
	v.ServiceCentreAddress = AddressString(val_servicecentreaddress)
	offset += n
	// Decode imsi
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassUniversal && peekTag.Number == 4 {
				val_imsi, n, err := ber.DecodeOctetString(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding imsi: %w", err)
				}
				tmp_imsi := IMSI(val_imsi)
				v.Imsi = &tmp_imsi
				offset += n
			}
		}
	}
	// Decode correlationID
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassUniversal && peekTag.Number == 16 {
				// Decode nested SEQUENCE (CorrelationID)
				_, n_correlationid, _, tlvErr_correlationid := ber.DecodeTLV(content[offset:])
				if tlvErr_correlationid != nil {
					return fmt.Errorf("decoding correlationID: %w", tlvErr_correlationid)
				}
				var dec_correlationid CorrelationID
				if unmErr := dec_correlationid.UnmarshalBER(content[offset : offset+n_correlationid]); unmErr != nil {
					return fmt.Errorf("decoding correlationID: %w", unmErr)
				}
				v.CorrelationID = &dec_correlationid
				offset += n_correlationid
			}
		}
	}
	// Decode maximumUeAvailabilityTime
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
				decodedTag_maximumueavailabilitytime, n_maximumueavailabilitytime, rawVal_maximumueavailabilitytime, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding maximumUeAvailabilityTime: %w", err)
				}
				if decodedTag_maximumueavailabilitytime.Class != tag.ClassContextSpecific || decodedTag_maximumueavailabilitytime.Number != 0 {
					return fmt.Errorf("decoding maximumUeAvailabilityTime: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_maximumueavailabilitytime)
				}
				tmp_maximumueavailabilitytime := Time(rawVal_maximumueavailabilitytime)
				v.MaximumUeAvailabilityTime = &tmp_maximumueavailabilitytime
				offset += n_maximumueavailabilitytime
			}
		}
	}
	// Decode smsGmscAlertEvent
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
				decodedTag_smsgmscalertevent, n_smsgmscalertevent, rawVal_smsgmscalertevent, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding smsGmscAlertEvent: %w", err)
				}
				if decodedTag_smsgmscalertevent.Class != tag.ClassContextSpecific || decodedTag_smsgmscalertevent.Number != 1 || decodedTag_smsgmscalertevent.Constructed != false {
					return fmt.Errorf("decoding smsGmscAlertEvent: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_smsgmscalertevent)
				}
				decVal_smsgmscalertevent, intErr := ber.DecodeIntegerValue(rawVal_smsgmscalertevent)
				if intErr != nil {
					return fmt.Errorf("decoding smsGmscAlertEvent: %w", intErr)
				}
				tmp_smsgmscalertevent := SmsGmscAlertEvent(decVal_smsgmscalertevent)
				v.SmsGmscAlertEvent = &tmp_smsgmscalertevent
				offset += n_smsgmscalertevent
			}
		}
	}
	// Decode smsGmscDiameterAddress
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2 {
				decodedTag_smsgmscdiameteraddress, n_smsgmscdiameteraddress, rawVal_smsgmscdiameteraddress, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding smsGmscDiameterAddress: %w", err)
				}
				if decodedTag_smsgmscdiameteraddress.Class != tag.ClassContextSpecific || decodedTag_smsgmscdiameteraddress.Number != 2 || decodedTag_smsgmscdiameteraddress.Constructed != true {
					return fmt.Errorf("decoding smsGmscDiameterAddress: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_smsgmscdiameteraddress)
				}
				reconstructed_smsgmscdiameteraddress := ber.EncodeSequence(rawVal_smsgmscdiameteraddress)
				var dec_smsgmscdiameteraddress NetworkNodeDiameterAddress
				if unmErr := dec_smsgmscdiameteraddress.UnmarshalBER(reconstructed_smsgmscdiameteraddress); unmErr != nil {
					return fmt.Errorf("decoding smsGmscDiameterAddress: %w", unmErr)
				}
				v.SmsGmscDiameterAddress = &dec_smsgmscdiameteraddress
				offset += n_smsgmscdiameteraddress
			}
		}
	}
	// Decode newSGSNNumber
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3 {
				decodedTag_newsgsnnumber, n_newsgsnnumber, rawVal_newsgsnnumber, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding newSGSNNumber: %w", err)
				}
				if decodedTag_newsgsnnumber.Class != tag.ClassContextSpecific || decodedTag_newsgsnnumber.Number != 3 {
					return fmt.Errorf("decoding newSGSNNumber: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_newsgsnnumber)
				}
				tmp_newsgsnnumber := ISDNAddressString(rawVal_newsgsnnumber)
				v.NewSGSNNumber = &tmp_newsgsnnumber
				offset += n_newsgsnnumber
			}
		}
	}
	// Decode newSGSNDiameterAddress
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4 {
				decodedTag_newsgsndiameteraddress, n_newsgsndiameteraddress, rawVal_newsgsndiameteraddress, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding newSGSNDiameterAddress: %w", err)
				}
				if decodedTag_newsgsndiameteraddress.Class != tag.ClassContextSpecific || decodedTag_newsgsndiameteraddress.Number != 4 || decodedTag_newsgsndiameteraddress.Constructed != true {
					return fmt.Errorf("decoding newSGSNDiameterAddress: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_newsgsndiameteraddress)
				}
				reconstructed_newsgsndiameteraddress := ber.EncodeSequence(rawVal_newsgsndiameteraddress)
				var dec_newsgsndiameteraddress NetworkNodeDiameterAddress
				if unmErr := dec_newsgsndiameteraddress.UnmarshalBER(reconstructed_newsgsndiameteraddress); unmErr != nil {
					return fmt.Errorf("decoding newSGSNDiameterAddress: %w", unmErr)
				}
				v.NewSGSNDiameterAddress = &dec_newsgsndiameteraddress
				offset += n_newsgsndiameteraddress
			}
		}
	}
	// Decode newMMENumber
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 5 {
				decodedTag_newmmenumber, n_newmmenumber, rawVal_newmmenumber, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding newMMENumber: %w", err)
				}
				if decodedTag_newmmenumber.Class != tag.ClassContextSpecific || decodedTag_newmmenumber.Number != 5 {
					return fmt.Errorf("decoding newMMENumber: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_newmmenumber)
				}
				tmp_newmmenumber := ISDNAddressString(rawVal_newmmenumber)
				v.NewMMENumber = &tmp_newmmenumber
				offset += n_newmmenumber
			}
		}
	}
	// Decode newMMEDiameterAddress
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 6 {
				decodedTag_newmmediameteraddress, n_newmmediameteraddress, rawVal_newmmediameteraddress, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding newMMEDiameterAddress: %w", err)
				}
				if decodedTag_newmmediameteraddress.Class != tag.ClassContextSpecific || decodedTag_newmmediameteraddress.Number != 6 || decodedTag_newmmediameteraddress.Constructed != true {
					return fmt.Errorf("decoding newMMEDiameterAddress: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_newmmediameteraddress)
				}
				reconstructed_newmmediameteraddress := ber.EncodeSequence(rawVal_newmmediameteraddress)
				var dec_newmmediameteraddress NetworkNodeDiameterAddress
				if unmErr := dec_newmmediameteraddress.UnmarshalBER(reconstructed_newmmediameteraddress); unmErr != nil {
					return fmt.Errorf("decoding newMMEDiameterAddress: %w", unmErr)
				}
				v.NewMMEDiameterAddress = &dec_newmmediameteraddress
				offset += n_newmmediameteraddress
			}
		}
	}
	// Decode newMSCNumber
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 7 {
				decodedTag_newmscnumber, n_newmscnumber, rawVal_newmscnumber, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding newMSCNumber: %w", err)
				}
				if decodedTag_newmscnumber.Class != tag.ClassContextSpecific || decodedTag_newmscnumber.Number != 7 {
					return fmt.Errorf("decoding newMSCNumber: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_newmscnumber)
				}
				tmp_newmscnumber := ISDNAddressString(rawVal_newmscnumber)
				v.NewMSCNumber = &tmp_newmscnumber
				offset += n_newmscnumber
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "AlertServiceCentreArg", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes InformServiceCentreArg to BER format.
func (v *InformServiceCentreArg) MarshalBER() ([]byte, error) {
	var children []byte
	if v.StoredMSISDN != nil {
		enc_storedmsisdn := ber.EncodeOctetString([]byte(*v.StoredMSISDN))
		children = append(children, enc_storedmsisdn...)
	}
	if v.MwStatus != nil {
		enc_mwstatus := ber.EncodeBitString(v.MwStatus.Bytes, (8-(v.MwStatus.BitLength%8))%8)
		children = append(children, enc_mwstatus...)
	}
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding extensionContainer: %w", err)
		}
		children = append(children, enc_extensioncontainer...)
	}
	if v.AbsentSubscriberDiagnosticSM != nil {
		enc_absentsubscriberdiagnosticsm := ber.EncodeInteger(int64(*v.AbsentSubscriberDiagnosticSM))
		children = append(children, enc_absentsubscriberdiagnosticsm...)
	}
	if v.AdditionalAbsentSubscriberDiagnosticSM != nil {
		enc_additionalabsentsubscriberdiagnosticsm := ber.EncodeInteger(int64(*v.AdditionalAbsentSubscriberDiagnosticSM))
		retagged_enc_additionalabsentsubscriberdiagnosticsm, tagErr_enc_additionalabsentsubscriberdiagnosticsm := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_additionalabsentsubscriberdiagnosticsm)
		if tagErr_enc_additionalabsentsubscriberdiagnosticsm != nil {
			return nil, fmt.Errorf("encoding additionalAbsentSubscriberDiagnosticSM: %w", tagErr_enc_additionalabsentsubscriberdiagnosticsm)
		}
		enc_additionalabsentsubscriberdiagnosticsm = retagged_enc_additionalabsentsubscriberdiagnosticsm
		children = append(children, enc_additionalabsentsubscriberdiagnosticsm...)
	}
	if v.Smsf3gppAbsentSubscriberDiagnosticSM != nil {
		enc_smsf3gppabsentsubscriberdiagnosticsm := ber.EncodeInteger(int64(*v.Smsf3gppAbsentSubscriberDiagnosticSM))
		retagged_enc_smsf3gppabsentsubscriberdiagnosticsm, tagErr_enc_smsf3gppabsentsubscriberdiagnosticsm := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_smsf3gppabsentsubscriberdiagnosticsm)
		if tagErr_enc_smsf3gppabsentsubscriberdiagnosticsm != nil {
			return nil, fmt.Errorf("encoding smsf3gppAbsentSubscriberDiagnosticSM: %w", tagErr_enc_smsf3gppabsentsubscriberdiagnosticsm)
		}
		enc_smsf3gppabsentsubscriberdiagnosticsm = retagged_enc_smsf3gppabsentsubscriberdiagnosticsm
		children = append(children, enc_smsf3gppabsentsubscriberdiagnosticsm...)
	}
	if v.SmsfNon3gppAbsentSubscriberDiagnosticSM != nil {
		enc_smsfnon3gppabsentsubscriberdiagnosticsm := ber.EncodeInteger(int64(*v.SmsfNon3gppAbsentSubscriberDiagnosticSM))
		retagged_enc_smsfnon3gppabsentsubscriberdiagnosticsm, tagErr_enc_smsfnon3gppabsentsubscriberdiagnosticsm := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_smsfnon3gppabsentsubscriberdiagnosticsm)
		if tagErr_enc_smsfnon3gppabsentsubscriberdiagnosticsm != nil {
			return nil, fmt.Errorf("encoding smsfNon3gppAbsentSubscriberDiagnosticSM: %w", tagErr_enc_smsfnon3gppabsentsubscriberdiagnosticsm)
		}
		enc_smsfnon3gppabsentsubscriberdiagnosticsm = retagged_enc_smsfnon3gppabsentsubscriberdiagnosticsm
		children = append(children, enc_smsfnon3gppabsentsubscriberdiagnosticsm...)
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

// MarshalDER encodes InformServiceCentreArg to DER format.
func (v *InformServiceCentreArg) MarshalDER() ([]byte, error) {
	var children []byte
	if v.StoredMSISDN != nil {
		enc_storedmsisdn := ber.EncodeOctetString([]byte(*v.StoredMSISDN))
		children = append(children, enc_storedmsisdn...)
	}
	if v.MwStatus != nil {
		enc_mwstatus := ber.EncodeBitString(v.MwStatus.Bytes, (8-(v.MwStatus.BitLength%8))%8)
		children = append(children, enc_mwstatus...)
	}
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding extensionContainer: %w", err)
		}
		children = append(children, enc_extensioncontainer...)
	}
	if v.AbsentSubscriberDiagnosticSM != nil {
		enc_absentsubscriberdiagnosticsm := ber.EncodeInteger(int64(*v.AbsentSubscriberDiagnosticSM))
		children = append(children, enc_absentsubscriberdiagnosticsm...)
	}
	if v.AdditionalAbsentSubscriberDiagnosticSM != nil {
		enc_additionalabsentsubscriberdiagnosticsm := ber.EncodeInteger(int64(*v.AdditionalAbsentSubscriberDiagnosticSM))
		retagged_enc_additionalabsentsubscriberdiagnosticsm, tagErr_enc_additionalabsentsubscriberdiagnosticsm := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_additionalabsentsubscriberdiagnosticsm)
		if tagErr_enc_additionalabsentsubscriberdiagnosticsm != nil {
			return nil, fmt.Errorf("encoding additionalAbsentSubscriberDiagnosticSM: %w", tagErr_enc_additionalabsentsubscriberdiagnosticsm)
		}
		enc_additionalabsentsubscriberdiagnosticsm = retagged_enc_additionalabsentsubscriberdiagnosticsm
		children = append(children, enc_additionalabsentsubscriberdiagnosticsm...)
	}
	if v.Smsf3gppAbsentSubscriberDiagnosticSM != nil {
		enc_smsf3gppabsentsubscriberdiagnosticsm := ber.EncodeInteger(int64(*v.Smsf3gppAbsentSubscriberDiagnosticSM))
		retagged_enc_smsf3gppabsentsubscriberdiagnosticsm, tagErr_enc_smsf3gppabsentsubscriberdiagnosticsm := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_smsf3gppabsentsubscriberdiagnosticsm)
		if tagErr_enc_smsf3gppabsentsubscriberdiagnosticsm != nil {
			return nil, fmt.Errorf("encoding smsf3gppAbsentSubscriberDiagnosticSM: %w", tagErr_enc_smsf3gppabsentsubscriberdiagnosticsm)
		}
		enc_smsf3gppabsentsubscriberdiagnosticsm = retagged_enc_smsf3gppabsentsubscriberdiagnosticsm
		children = append(children, enc_smsf3gppabsentsubscriberdiagnosticsm...)
	}
	if v.SmsfNon3gppAbsentSubscriberDiagnosticSM != nil {
		enc_smsfnon3gppabsentsubscriberdiagnosticsm := ber.EncodeInteger(int64(*v.SmsfNon3gppAbsentSubscriberDiagnosticSM))
		retagged_enc_smsfnon3gppabsentsubscriberdiagnosticsm, tagErr_enc_smsfnon3gppabsentsubscriberdiagnosticsm := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_smsfnon3gppabsentsubscriberdiagnosticsm)
		if tagErr_enc_smsfnon3gppabsentsubscriberdiagnosticsm != nil {
			return nil, fmt.Errorf("encoding smsfNon3gppAbsentSubscriberDiagnosticSM: %w", tagErr_enc_smsfnon3gppabsentsubscriberdiagnosticsm)
		}
		enc_smsfnon3gppabsentsubscriberdiagnosticsm = retagged_enc_smsfnon3gppabsentsubscriberdiagnosticsm
		children = append(children, enc_smsfnon3gppabsentsubscriberdiagnosticsm...)
	}
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
		children = append(children, ext...)
	}
	encoded := ber.EncodeSequence(children)
	if err := ber.ValidateDERElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding InformServiceCentreArg as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes InformServiceCentreArg from BER/DER format.
func (v *InformServiceCentreArg) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding InformServiceCentreArg SEQUENCE: %w", err)
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
				val_storedmsisdn, n, err := ber.DecodeOctetString(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding storedMSISDN: %w", err)
				}
				tmp_storedmsisdn := ISDNAddressString(val_storedmsisdn)
				v.StoredMSISDN = &tmp_storedmsisdn
				offset += n
			}
		}
	}
	// Decode mw-Status
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassUniversal && peekTag.Number == 3 {
				bsBytes_mwstatus, bsUnused_mwstatus, n, err := ber.DecodeBitString(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding mw-Status: %w", err)
				}
				tmp_mwstatus := runtime.BitString{Bytes: bsBytes_mwstatus, BitLength: len(bsBytes_mwstatus)*8 - bsUnused_mwstatus}
				v.MwStatus = &tmp_mwstatus
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
	// Decode absentSubscriberDiagnosticSM
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassUniversal && peekTag.Number == 2 {
				val_absentsubscriberdiagnosticsm, n, err := ber.DecodeInteger(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding absentSubscriberDiagnosticSM: %w", err)
				}
				tmp_absentsubscriberdiagnosticsm := AbsentSubscriberDiagnosticSM(val_absentsubscriberdiagnosticsm)
				v.AbsentSubscriberDiagnosticSM = &tmp_absentsubscriberdiagnosticsm
				offset += n
			}
		}
	}
	// Decode additionalAbsentSubscriberDiagnosticSM
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
				decodedTag_additionalabsentsubscriberdiagnosticsm, n_additionalabsentsubscriberdiagnosticsm, rawVal_additionalabsentsubscriberdiagnosticsm, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding additionalAbsentSubscriberDiagnosticSM: %w", err)
				}
				if decodedTag_additionalabsentsubscriberdiagnosticsm.Class != tag.ClassContextSpecific || decodedTag_additionalabsentsubscriberdiagnosticsm.Number != 0 || decodedTag_additionalabsentsubscriberdiagnosticsm.Constructed != false {
					return fmt.Errorf("decoding additionalAbsentSubscriberDiagnosticSM: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_additionalabsentsubscriberdiagnosticsm)
				}
				decVal_additionalabsentsubscriberdiagnosticsm, intErr := ber.DecodeIntegerValue(rawVal_additionalabsentsubscriberdiagnosticsm)
				if intErr != nil {
					return fmt.Errorf("decoding additionalAbsentSubscriberDiagnosticSM: %w", intErr)
				}
				tmp_additionalabsentsubscriberdiagnosticsm := AbsentSubscriberDiagnosticSM(decVal_additionalabsentsubscriberdiagnosticsm)
				v.AdditionalAbsentSubscriberDiagnosticSM = &tmp_additionalabsentsubscriberdiagnosticsm
				offset += n_additionalabsentsubscriberdiagnosticsm
			}
		}
	}
	// Decode smsf3gppAbsentSubscriberDiagnosticSM
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
				decodedTag_smsf3gppabsentsubscriberdiagnosticsm, n_smsf3gppabsentsubscriberdiagnosticsm, rawVal_smsf3gppabsentsubscriberdiagnosticsm, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding smsf3gppAbsentSubscriberDiagnosticSM: %w", err)
				}
				if decodedTag_smsf3gppabsentsubscriberdiagnosticsm.Class != tag.ClassContextSpecific || decodedTag_smsf3gppabsentsubscriberdiagnosticsm.Number != 1 || decodedTag_smsf3gppabsentsubscriberdiagnosticsm.Constructed != false {
					return fmt.Errorf("decoding smsf3gppAbsentSubscriberDiagnosticSM: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_smsf3gppabsentsubscriberdiagnosticsm)
				}
				decVal_smsf3gppabsentsubscriberdiagnosticsm, intErr := ber.DecodeIntegerValue(rawVal_smsf3gppabsentsubscriberdiagnosticsm)
				if intErr != nil {
					return fmt.Errorf("decoding smsf3gppAbsentSubscriberDiagnosticSM: %w", intErr)
				}
				tmp_smsf3gppabsentsubscriberdiagnosticsm := AbsentSubscriberDiagnosticSM(decVal_smsf3gppabsentsubscriberdiagnosticsm)
				v.Smsf3gppAbsentSubscriberDiagnosticSM = &tmp_smsf3gppabsentsubscriberdiagnosticsm
				offset += n_smsf3gppabsentsubscriberdiagnosticsm
			}
		}
	}
	// Decode smsfNon3gppAbsentSubscriberDiagnosticSM
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2 {
				decodedTag_smsfnon3gppabsentsubscriberdiagnosticsm, n_smsfnon3gppabsentsubscriberdiagnosticsm, rawVal_smsfnon3gppabsentsubscriberdiagnosticsm, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding smsfNon3gppAbsentSubscriberDiagnosticSM: %w", err)
				}
				if decodedTag_smsfnon3gppabsentsubscriberdiagnosticsm.Class != tag.ClassContextSpecific || decodedTag_smsfnon3gppabsentsubscriberdiagnosticsm.Number != 2 || decodedTag_smsfnon3gppabsentsubscriberdiagnosticsm.Constructed != false {
					return fmt.Errorf("decoding smsfNon3gppAbsentSubscriberDiagnosticSM: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_smsfnon3gppabsentsubscriberdiagnosticsm)
				}
				decVal_smsfnon3gppabsentsubscriberdiagnosticsm, intErr := ber.DecodeIntegerValue(rawVal_smsfnon3gppabsentsubscriberdiagnosticsm)
				if intErr != nil {
					return fmt.Errorf("decoding smsfNon3gppAbsentSubscriberDiagnosticSM: %w", intErr)
				}
				tmp_smsfnon3gppabsentsubscriberdiagnosticsm := AbsentSubscriberDiagnosticSM(decVal_smsfnon3gppabsentsubscriberdiagnosticsm)
				v.SmsfNon3gppAbsentSubscriberDiagnosticSM = &tmp_smsfnon3gppabsentsubscriberdiagnosticsm
				offset += n_smsfnon3gppabsentsubscriberdiagnosticsm
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "InformServiceCentreArg", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes ReadyForSMArg to BER format.
func (v *ReadyForSMArg) MarshalBER() ([]byte, error) {
	var children []byte
	enc_imsi := ber.EncodeOctetString([]byte(v.Imsi))
	retagged_enc_imsi, tagErr_enc_imsi := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_imsi)
	if tagErr_enc_imsi != nil {
		return nil, fmt.Errorf("encoding imsi: %w", tagErr_enc_imsi)
	}
	enc_imsi = retagged_enc_imsi
	children = append(children, enc_imsi...)
	enc_alertreason := ber.EncodeEnumerated(int64(v.AlertReason))
	children = append(children, enc_alertreason...)
	if v.AlertReasonIndicator != nil {
		enc_alertreasonindicator := ber.EncodeNull()
		children = append(children, enc_alertreasonindicator...)
	}
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding extensionContainer: %w", err)
		}
		children = append(children, enc_extensioncontainer...)
	}
	if v.AdditionalAlertReasonIndicator != nil {
		enc_additionalalertreasonindicator := ber.EncodeNull()
		retagged_enc_additionalalertreasonindicator, tagErr_enc_additionalalertreasonindicator := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_additionalalertreasonindicator)
		if tagErr_enc_additionalalertreasonindicator != nil {
			return nil, fmt.Errorf("encoding additionalAlertReasonIndicator: %w", tagErr_enc_additionalalertreasonindicator)
		}
		enc_additionalalertreasonindicator = retagged_enc_additionalalertreasonindicator
		children = append(children, enc_additionalalertreasonindicator...)
	}
	if v.MaximumUeAvailabilityTime != nil {
		enc_maximumueavailabilitytime := ber.EncodeOctetString([]byte(*v.MaximumUeAvailabilityTime))
		children = append(children, enc_maximumueavailabilitytime...)
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

// MarshalDER encodes ReadyForSMArg to DER format.
func (v *ReadyForSMArg) MarshalDER() ([]byte, error) {
	var children []byte
	enc_imsi := ber.EncodeOctetString([]byte(v.Imsi))
	retagged_enc_imsi, tagErr_enc_imsi := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_imsi)
	if tagErr_enc_imsi != nil {
		return nil, fmt.Errorf("encoding imsi: %w", tagErr_enc_imsi)
	}
	enc_imsi = retagged_enc_imsi
	children = append(children, enc_imsi...)
	enc_alertreason := ber.EncodeEnumerated(int64(v.AlertReason))
	children = append(children, enc_alertreason...)
	if v.AlertReasonIndicator != nil {
		enc_alertreasonindicator := ber.EncodeNull()
		children = append(children, enc_alertreasonindicator...)
	}
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding extensionContainer: %w", err)
		}
		children = append(children, enc_extensioncontainer...)
	}
	if v.AdditionalAlertReasonIndicator != nil {
		enc_additionalalertreasonindicator := ber.EncodeNull()
		retagged_enc_additionalalertreasonindicator, tagErr_enc_additionalalertreasonindicator := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_additionalalertreasonindicator)
		if tagErr_enc_additionalalertreasonindicator != nil {
			return nil, fmt.Errorf("encoding additionalAlertReasonIndicator: %w", tagErr_enc_additionalalertreasonindicator)
		}
		enc_additionalalertreasonindicator = retagged_enc_additionalalertreasonindicator
		children = append(children, enc_additionalalertreasonindicator...)
	}
	if v.MaximumUeAvailabilityTime != nil {
		enc_maximumueavailabilitytime := ber.EncodeOctetString([]byte(*v.MaximumUeAvailabilityTime))
		children = append(children, enc_maximumueavailabilitytime...)
	}
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
		children = append(children, ext...)
	}
	encoded := ber.EncodeSequence(children)
	if err := ber.ValidateDERElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding ReadyForSMArg as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes ReadyForSMArg from BER/DER format.
func (v *ReadyForSMArg) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding ReadyForSMArg SEQUENCE: %w", err)
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
	decodedTag_imsi, n_imsi, rawVal_imsi, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding imsi: %w", err)
	}
	if decodedTag_imsi.Class != tag.ClassContextSpecific || decodedTag_imsi.Number != 0 {
		return fmt.Errorf("decoding imsi: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_imsi)
	}
	v.Imsi = IMSI(rawVal_imsi)
	offset += n_imsi
	// Decode alertReason
	if offset >= len(content) {
		return fmt.Errorf("missing required field alertReason")
	}
	val_alertreason, n, err := ber.DecodeInteger(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding alertReason: %w", err)
	}
	v.AlertReason = AlertReason(val_alertreason)
	offset += n
	// Decode alertReasonIndicator
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassUniversal && peekTag.Number == 5 {
				n, err := ber.DecodeNull(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding alertReasonIndicator: %w", err)
				}
				v.AlertReasonIndicator = &struct{}{}
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
	// Decode additionalAlertReasonIndicator
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
				decodedTag_additionalalertreasonindicator, n_additionalalertreasonindicator, rawVal_additionalalertreasonindicator, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding additionalAlertReasonIndicator: %w", err)
				}
				if decodedTag_additionalalertreasonindicator.Class != tag.ClassContextSpecific || decodedTag_additionalalertreasonindicator.Number != 1 || decodedTag_additionalalertreasonindicator.Constructed != false {
					return fmt.Errorf("decoding additionalAlertReasonIndicator: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_additionalalertreasonindicator)
				}
				if len(rawVal_additionalalertreasonindicator) != 0 {
					return fmt.Errorf("decoding additionalAlertReasonIndicator: %w: NULL content length %d", ber.ErrInvalidValue, len(rawVal_additionalalertreasonindicator))
				}
				v.AdditionalAlertReasonIndicator = &struct{}{}
				offset += n_additionalalertreasonindicator
			}
		}
	}
	// Decode maximumUeAvailabilityTime
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassUniversal && peekTag.Number == 4 {
				val_maximumueavailabilitytime, n, err := ber.DecodeOctetString(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding maximumUeAvailabilityTime: %w", err)
				}
				tmp_maximumueavailabilitytime := Time(val_maximumueavailabilitytime)
				v.MaximumUeAvailabilityTime = &tmp_maximumueavailabilitytime
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
			return &ber.DecodeError{Offset: offset, TypeName: "ReadyForSMArg", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes ReadyForSMRes to BER format.
func (v *ReadyForSMRes) MarshalBER() ([]byte, error) {
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

// MarshalDER encodes ReadyForSMRes to DER format.
func (v *ReadyForSMRes) MarshalDER() ([]byte, error) {
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
		return nil, fmt.Errorf("encoding ReadyForSMRes as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes ReadyForSMRes from BER/DER format.
func (v *ReadyForSMRes) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding ReadyForSMRes SEQUENCE: %w", err)
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
			return &ber.DecodeError{Offset: offset, TypeName: "ReadyForSMRes", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes MTForwardSMVGCSArg to BER format.
func (v *MTForwardSMVGCSArg) MarshalBER() ([]byte, error) {
	var children []byte
	enc_ascicallreference := ber.EncodeOctetString([]byte(v.AsciCallReference))
	children = append(children, enc_ascicallreference...)
	enc_smrpoa, err := v.SmRPOA.MarshalBER()
	if err != nil {
		return nil, fmt.Errorf("encoding sm-RP-OA: %w", err)
	}
	children = append(children, enc_smrpoa...)
	enc_smrpui := ber.EncodeOctetString([]byte(v.SmRPUI))
	children = append(children, enc_smrpui...)
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

// MarshalDER encodes MTForwardSMVGCSArg to DER format.
func (v *MTForwardSMVGCSArg) MarshalDER() ([]byte, error) {
	var children []byte
	enc_ascicallreference := ber.EncodeOctetString([]byte(v.AsciCallReference))
	children = append(children, enc_ascicallreference...)
	enc_smrpoa, err := v.SmRPOA.MarshalDER()
	if err != nil {
		return nil, fmt.Errorf("encoding sm-RP-OA: %w", err)
	}
	children = append(children, enc_smrpoa...)
	enc_smrpui := ber.EncodeOctetString([]byte(v.SmRPUI))
	children = append(children, enc_smrpui...)
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
		return nil, fmt.Errorf("encoding MTForwardSMVGCSArg as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes MTForwardSMVGCSArg from BER/DER format.
func (v *MTForwardSMVGCSArg) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding MTForwardSMVGCSArg SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "MTForwardSMVGCSArg", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode asciCallReference
	if offset >= len(content) {
		return fmt.Errorf("missing required field asciCallReference")
	}
	val_ascicallreference, n, err := ber.DecodeOctetString(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding asciCallReference: %w", err)
	}
	v.AsciCallReference = ASCICallReference(val_ascicallreference)
	offset += n
	// Decode sm-RP-OA
	if offset >= len(content) {
		return fmt.Errorf("missing required field sm-RP-OA")
	}
	// Decode nested CHOICE (SMRPOA)
	_, n_smrpoa, _, tlvErr_smrpoa := ber.DecodeTLV(content[offset:])
	if tlvErr_smrpoa != nil {
		return fmt.Errorf("decoding sm-RP-OA: %w", tlvErr_smrpoa)
	}
	if unmErr := v.SmRPOA.UnmarshalBER(content[offset : offset+n_smrpoa]); unmErr != nil {
		return fmt.Errorf("decoding sm-RP-OA: %w", unmErr)
	}
	offset += n_smrpoa
	// Decode sm-RP-UI
	if offset >= len(content) {
		return fmt.Errorf("missing required field sm-RP-UI")
	}
	val_smrpui, n, err := ber.DecodeOctetString(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding sm-RP-UI: %w", err)
	}
	v.SmRPUI = SignalInfo(val_smrpui)
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
			return &ber.DecodeError{Offset: offset, TypeName: "MTForwardSMVGCSArg", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes MTForwardSMVGCSRes to BER format.
func (v *MTForwardSMVGCSRes) MarshalBER() ([]byte, error) {
	var children []byte
	if v.SmRPUI != nil {
		enc_smrpui := ber.EncodeOctetString([]byte(*v.SmRPUI))
		retagged_enc_smrpui, tagErr_enc_smrpui := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_smrpui)
		if tagErr_enc_smrpui != nil {
			return nil, fmt.Errorf("encoding sm-RP-UI: %w", tagErr_enc_smrpui)
		}
		enc_smrpui = retagged_enc_smrpui
		children = append(children, enc_smrpui...)
	}
	if v.DispatcherList != nil {
		enc_dispatcherlist, err := MarshalBERDispatcherList(v.DispatcherList)
		if err != nil {
			return nil, fmt.Errorf("encoding dispatcherList: %w", err)
		}
		if v.DispatcherListIndef_ {
			// Strip the outer SEQUENCE tag from marshalBER output to get raw children.
			_, _, seqContent_, tlvErr_ := ber.DecodeTLV(enc_dispatcherlist)
			if tlvErr_ != nil {
				return nil, tlvErr_
			}
			enc_dispatcherlist = ber.EncodeConstructedIndefinite(tag.Tag{Class: tag.ClassContextSpecific, Number: 1}, seqContent_)
		} else {
			retagged_enc_dispatcherlist, tagErr_enc_dispatcherlist := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_dispatcherlist)
			if tagErr_enc_dispatcherlist != nil {
				return nil, fmt.Errorf("encoding dispatcherList: %w", tagErr_enc_dispatcherlist)
			}
			enc_dispatcherlist = retagged_enc_dispatcherlist
		}
		children = append(children, enc_dispatcherlist...)
	}
	if v.OngoingCall != nil {
		enc_ongoingcall := ber.EncodeNull()
		children = append(children, enc_ongoingcall...)
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
	if v.AdditionalDispatcherList != nil {
		enc_additionaldispatcherlist, err := MarshalBERAdditionalDispatcherList(v.AdditionalDispatcherList)
		if err != nil {
			return nil, fmt.Errorf("encoding additionalDispatcherList: %w", err)
		}
		if v.AdditionalDispatcherListIndef_ {
			// Strip the outer SEQUENCE tag from marshalBER output to get raw children.
			_, _, seqContent_, tlvErr_ := ber.DecodeTLV(enc_additionaldispatcherlist)
			if tlvErr_ != nil {
				return nil, tlvErr_
			}
			enc_additionaldispatcherlist = ber.EncodeConstructedIndefinite(tag.Tag{Class: tag.ClassContextSpecific, Number: 3}, seqContent_)
		} else {
			retagged_enc_additionaldispatcherlist, tagErr_enc_additionaldispatcherlist := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, enc_additionaldispatcherlist)
			if tagErr_enc_additionaldispatcherlist != nil {
				return nil, fmt.Errorf("encoding additionalDispatcherList: %w", tagErr_enc_additionaldispatcherlist)
			}
			enc_additionaldispatcherlist = retagged_enc_additionaldispatcherlist
		}
		children = append(children, enc_additionaldispatcherlist...)
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

// MarshalDER encodes MTForwardSMVGCSRes to DER format.
func (v *MTForwardSMVGCSRes) MarshalDER() ([]byte, error) {
	var children []byte
	if v.SmRPUI != nil {
		enc_smrpui := ber.EncodeOctetString([]byte(*v.SmRPUI))
		retagged_enc_smrpui, tagErr_enc_smrpui := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_smrpui)
		if tagErr_enc_smrpui != nil {
			return nil, fmt.Errorf("encoding sm-RP-UI: %w", tagErr_enc_smrpui)
		}
		enc_smrpui = retagged_enc_smrpui
		children = append(children, enc_smrpui...)
	}
	if v.DispatcherList != nil {
		enc_dispatcherlist, err := MarshalDERDispatcherList(v.DispatcherList)
		if err != nil {
			return nil, fmt.Errorf("encoding dispatcherList: %w", err)
		}
		retagged_enc_dispatcherlist, tagErr_enc_dispatcherlist := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_dispatcherlist)
		if tagErr_enc_dispatcherlist != nil {
			return nil, fmt.Errorf("encoding dispatcherList: %w", tagErr_enc_dispatcherlist)
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
			return nil, fmt.Errorf("encoding extensionContainer: %w", err)
		}
		retagged_enc_extensioncontainer, tagErr_enc_extensioncontainer := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_extensioncontainer)
		if tagErr_enc_extensioncontainer != nil {
			return nil, fmt.Errorf("encoding extensionContainer: %w", tagErr_enc_extensioncontainer)
		}
		enc_extensioncontainer = retagged_enc_extensioncontainer
		children = append(children, enc_extensioncontainer...)
	}
	if v.AdditionalDispatcherList != nil {
		enc_additionaldispatcherlist, err := MarshalDERAdditionalDispatcherList(v.AdditionalDispatcherList)
		if err != nil {
			return nil, fmt.Errorf("encoding additionalDispatcherList: %w", err)
		}
		retagged_enc_additionaldispatcherlist, tagErr_enc_additionaldispatcherlist := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, enc_additionaldispatcherlist)
		if tagErr_enc_additionaldispatcherlist != nil {
			return nil, fmt.Errorf("encoding additionalDispatcherList: %w", tagErr_enc_additionaldispatcherlist)
		}
		enc_additionaldispatcherlist = retagged_enc_additionaldispatcherlist
		children = append(children, enc_additionaldispatcherlist...)
	}
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
		children = append(children, ext...)
	}
	encoded := ber.EncodeSequence(children)
	if err := ber.ValidateDERElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding MTForwardSMVGCSRes as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes MTForwardSMVGCSRes from BER/DER format.
func (v *MTForwardSMVGCSRes) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding MTForwardSMVGCSRes SEQUENCE: %w", err)
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
				decodedTag_smrpui, n_smrpui, rawVal_smrpui, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding sm-RP-UI: %w", err)
				}
				if decodedTag_smrpui.Class != tag.ClassContextSpecific || decodedTag_smrpui.Number != 0 {
					return fmt.Errorf("decoding sm-RP-UI: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_smrpui)
				}
				tmp_smrpui := SignalInfo(rawVal_smrpui)
				v.SmRPUI = &tmp_smrpui
				offset += n_smrpui
			}
		}
	}
	// Decode dispatcherList
	v.DispatcherListIndef_ = false
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
				decodedTag_dispatcherlist, n_dispatcherlist, rawVal_dispatcherlist, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding dispatcherList: %w", err)
				}
				if decodedTag_dispatcherlist.Class != tag.ClassContextSpecific || decodedTag_dispatcherlist.Number != 1 || decodedTag_dispatcherlist.Constructed != true {
					return fmt.Errorf("decoding dispatcherList: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_dispatcherlist)
				}
				reconstructed_dispatcherlist := ber.EncodeSequence(rawVal_dispatcherlist)
				dec_dispatcherlist, unmErr := UnmarshalBERDispatcherList(reconstructed_dispatcherlist)
				if unmErr != nil {
					return fmt.Errorf("decoding dispatcherList: %w", unmErr)
				}
				v.DispatcherList = dec_dispatcherlist
				{
					_, tagSz_, _ := ber.DecodeTag(content[offset:])
					if offset+tagSz_ < len(content) && content[offset+tagSz_] == 0x80 {
						v.DispatcherListIndef_ = true
					}
				}
				offset += n_dispatcherlist
			}
		}
	}
	// Decode ongoingCall
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassUniversal && peekTag.Number == 5 {
				n, err := ber.DecodeNull(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding ongoingCall: %w", err)
				}
				v.OngoingCall = &struct{}{}
				offset += n
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
	// Decode additionalDispatcherList
	v.AdditionalDispatcherListIndef_ = false
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3 {
				decodedTag_additionaldispatcherlist, n_additionaldispatcherlist, rawVal_additionaldispatcherlist, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding additionalDispatcherList: %w", err)
				}
				if decodedTag_additionaldispatcherlist.Class != tag.ClassContextSpecific || decodedTag_additionaldispatcherlist.Number != 3 || decodedTag_additionaldispatcherlist.Constructed != true {
					return fmt.Errorf("decoding additionalDispatcherList: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_additionaldispatcherlist)
				}
				reconstructed_additionaldispatcherlist := ber.EncodeSequence(rawVal_additionaldispatcherlist)
				dec_additionaldispatcherlist, unmErr := UnmarshalBERAdditionalDispatcherList(reconstructed_additionaldispatcherlist)
				if unmErr != nil {
					return fmt.Errorf("decoding additionalDispatcherList: %w", unmErr)
				}
				v.AdditionalDispatcherList = dec_additionaldispatcherlist
				{
					_, tagSz_, _ := ber.DecodeTag(content[offset:])
					if offset+tagSz_ < len(content) && content[offset+tagSz_] == 0x80 {
						v.AdditionalDispatcherListIndef_ = true
					}
				}
				offset += n_additionaldispatcherlist
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "MTForwardSMVGCSRes", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBERDispatcherList encodes a DispatcherList list to BER.
func MarshalBERDispatcherList(list DispatcherList) ([]byte, error) {
	var children []byte
	for _, elem := range list {
		children = append(children, ber.EncodeOctetString([]byte(elem))...)
	}
	return ber.EncodeSequence(children), nil
}

// MarshalDERDispatcherList encodes a DispatcherList list to DER.
func MarshalDERDispatcherList(list DispatcherList) ([]byte, error) {
	var children []byte
	for _, elem := range list {
		children = append(children, ber.EncodeOctetString([]byte(elem))...)
	}
	encoded := ber.EncodeSequence(children)
	if err := ber.ValidateDERElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding DispatcherList as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBERDispatcherList decodes a DispatcherList list from BER.
func UnmarshalBERDispatcherList(data []byte) (DispatcherList, error) {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return nil, fmt.Errorf("decoding DispatcherList: %w", err)
	}
	if total != len(data) {
		return nil, &ber.DecodeError{Offset: total, TypeName: "DispatcherList", Cause: ber.ErrExtraData}
	}
	var result DispatcherList
	offset := 0
	for offset < len(content) {
		val, n, osErr := ber.DecodeOctetString(content[offset:])
		if osErr != nil {
			return nil, fmt.Errorf("decoding element: %w", osErr)
		}
		result = append(result, ISDNAddressString(val))
		offset += n
	}
	return result, nil
}

// MarshalBERAdditionalDispatcherList encodes a AdditionalDispatcherList list to BER.
func MarshalBERAdditionalDispatcherList(list AdditionalDispatcherList) ([]byte, error) {
	var children []byte
	for _, elem := range list {
		children = append(children, ber.EncodeOctetString([]byte(elem))...)
	}
	return ber.EncodeSequence(children), nil
}

// MarshalDERAdditionalDispatcherList encodes a AdditionalDispatcherList list to DER.
func MarshalDERAdditionalDispatcherList(list AdditionalDispatcherList) ([]byte, error) {
	var children []byte
	for _, elem := range list {
		children = append(children, ber.EncodeOctetString([]byte(elem))...)
	}
	encoded := ber.EncodeSequence(children)
	if err := ber.ValidateDERElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding AdditionalDispatcherList as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBERAdditionalDispatcherList decodes a AdditionalDispatcherList list from BER.
func UnmarshalBERAdditionalDispatcherList(data []byte) (AdditionalDispatcherList, error) {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return nil, fmt.Errorf("decoding AdditionalDispatcherList: %w", err)
	}
	if total != len(data) {
		return nil, &ber.DecodeError{Offset: total, TypeName: "AdditionalDispatcherList", Cause: ber.ErrExtraData}
	}
	var result AdditionalDispatcherList
	offset := 0
	for offset < len(content) {
		val, n, osErr := ber.DecodeOctetString(content[offset:])
		if osErr != nil {
			return nil, fmt.Errorf("decoding element: %w", osErr)
		}
		result = append(result, ISDNAddressString(val))
		offset += n
	}
	return result, nil
}
