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

	// SMMaxNumOfDispatchers is the integer constant for maxNumOfDispatchers.
	SMMaxNumOfDispatchers int64 = 5

	// SMMaxNumOfAdditionalDispatchers is the integer constant for maxNumOfAdditionalDispatchers.
	SMMaxNumOfAdditionalDispatchers int64 = 15
)

// SMRoutingInfoForSMArg represents the ASN.1 type RoutingInfoForSM-Arg (SEQUENCE).
type SMRoutingInfoForSMArg struct {
	Msisdn                  ISDNAddressString4       `asn1:"tag:0,context,implicit"`
	SmRPPRI                 bool                     `asn1:"tag:1,context,implicit"`
	SmRPPRIRaw_             byte                     `asn1:"-" json:"-"`
	ServiceCentreAddress    AddressString4           `asn1:"tag:2,context,implicit"`
	ExtensionContainer      *ExtensionContainer4     `asn1:"tag:6,context,implicit,optional" json:"ExtensionContainer,omitempty"`
	GprsSupportIndicator    *struct{}                `asn1:"tag:7,context,implicit,optional" json:"GprsSupportIndicator,omitempty"`
	SmRPMTI                 *SMSMRPMTI               `asn1:"tag:8,context,implicit,optional" json:"SmRPMTI,omitempty"`
	SmRPSMEA                *SMSMRPSMEA              `asn1:"tag:9,context,implicit,optional" json:"SmRPSMEA,omitempty"`
	SmDeliveryNotIntended   *SMSMDeliveryNotIntended `asn1:"tag:10,context,implicit,optional" json:"SmDeliveryNotIntended,omitempty"`
	IpSmGwGuidanceIndicator *struct{}                `asn1:"tag:11,context,implicit,optional" json:"IpSmGwGuidanceIndicator,omitempty"`
	Imsi                    *IMSI4                   `asn1:"tag:12,context,implicit,optional" json:"Imsi,omitempty"`
	T4TriggerIndicator      *struct{}                `asn1:"tag:14,context,implicit,optional" json:"T4TriggerIndicator,omitempty"`
	SingleAttemptDelivery   *struct{}                `asn1:"tag:13,context,implicit,optional" json:"SingleAttemptDelivery,omitempty"`
	CorrelationID           *SMCorrelationID         `asn1:"tag:15,context,implicit,optional" json:"CorrelationID,omitempty"`
	ExtCount_               int64                    `asn1:"-" json:"-"`
	ExtPresent_             []bool                   `asn1:"-" json:"-"`
	ExtData_                [][]byte                 `asn1:"-" json:"-"`
}

// SMSMDeliveryNotIntended represents the ASN.1 ENUMERATED type SM-DeliveryNotIntended.
type SMSMDeliveryNotIntended int64

const (
	SMSMDeliveryNotIntendedOnlyIMSIRequested   SMSMDeliveryNotIntended = 0
	SMSMDeliveryNotIntendedOnlyMCCMNCRequested SMSMDeliveryNotIntended = 1
)

func (v SMSMDeliveryNotIntended) String() string {
	switch v {
	case SMSMDeliveryNotIntendedOnlyIMSIRequested:
		return "onlyIMSI-requested"
	case SMSMDeliveryNotIntendedOnlyMCCMNCRequested:
		return "onlyMCC-MNC-requested"
	default:
		return "unknown"
	}
}

// SMSMRPMTI represents the ASN.1 type SM-RP-MTI (INTEGER).
type SMSMRPMTI = int64

// SMSMRPSMEA represents the ASN.1 type SM-RP-SMEA (OCTET_STRING).
type SMSMRPSMEA = []byte

// SMRoutingInfoForSMRes represents the ASN.1 type RoutingInfoForSM-Res (SEQUENCE).
type SMRoutingInfoForSMRes struct {
	Imsi                 IMSI4                  `asn1:""`
	LocationInfoWithLMSI SMLocationInfoWithLMSI `asn1:"tag:0,context,implicit"`
	ExtensionContainer   *ExtensionContainer4   `asn1:"tag:4,context,implicit,optional" json:"ExtensionContainer,omitempty"`
	IpSmGwGuidance       *SMIPSMGWGuidance      `asn1:"tag:5,context,implicit,optional" json:"IpSmGwGuidance,omitempty"`
	ExtCount_            int64                  `asn1:"-" json:"-"`
	ExtPresent_          []bool                 `asn1:"-" json:"-"`
	ExtData_             [][]byte               `asn1:"-" json:"-"`
}

// SMIPSMGWGuidance represents the ASN.1 type IP-SM-GW-Guidance (SEQUENCE).
type SMIPSMGWGuidance struct {
	MinimumDeliveryTimeValue     SMSMDeliveryTimerValue `asn1:""`
	RecommendedDeliveryTimeValue SMSMDeliveryTimerValue `asn1:""`
	ExtensionContainer           *ExtensionContainer4   `asn1:",optional" json:"ExtensionContainer,omitempty"`
	ExtCount_                    int64                  `asn1:"-" json:"-"`
	ExtPresent_                  []bool                 `asn1:"-" json:"-"`
	ExtData_                     [][]byte               `asn1:"-" json:"-"`
}

// SMLocationInfoWithLMSI represents the ASN.1 type LocationInfoWithLMSI (SEQUENCE).
type SMLocationInfoWithLMSI struct {
	NetworkNodeNumber                    ISDNAddressString4           `asn1:"tag:1,context,implicit"`
	Lmsi                                 *LMSI4                       `asn1:",optional" json:"Lmsi,omitempty"`
	ExtensionContainer                   *ExtensionContainer4         `asn1:",optional" json:"ExtensionContainer,omitempty"`
	GprsNodeIndicator                    *struct{}                    `asn1:"tag:5,context,implicit,optional" json:"GprsNodeIndicator,omitempty"`
	AdditionalNumber                     *SMAdditionalNumber          `asn1:"tag:6,context,explicit,optional" json:"AdditionalNumber,omitempty"`
	NetworkNodeDiameterAddress           *NetworkNodeDiameterAddress3 `asn1:"tag:7,context,implicit,optional" json:"NetworkNodeDiameterAddress,omitempty"`
	AdditionalNetworkNodeDiameterAddress *NetworkNodeDiameterAddress3 `asn1:"tag:8,context,implicit,optional" json:"AdditionalNetworkNodeDiameterAddress,omitempty"`
	ThirdNumber                          *SMAdditionalNumber          `asn1:"tag:9,context,explicit,optional" json:"ThirdNumber,omitempty"`
	ThirdNetworkNodeDiameterAddress      *NetworkNodeDiameterAddress3 `asn1:"tag:10,context,implicit,optional" json:"ThirdNetworkNodeDiameterAddress,omitempty"`
	ImsNodeIndicator                     *struct{}                    `asn1:"tag:11,context,implicit,optional" json:"ImsNodeIndicator,omitempty"`
	ExtCount_                            int64                        `asn1:"-" json:"-"`
	ExtPresent_                          []bool                       `asn1:"-" json:"-"`
	ExtData_                             [][]byte                     `asn1:"-" json:"-"`
}

// SMAdditionalNumber choice constants.
const (
	SMAdditionalNumberChoiceMscNumber  = 1
	SMAdditionalNumberChoiceSgsnNumber = 2
)

// SMAdditionalNumber represents the ASN.1 CHOICE type Additional-Number.
type SMAdditionalNumber struct {
	Choice     int
	MscNumber  *ISDNAddressString4 `json:"MscNumber,omitempty"`
	SgsnNumber *ISDNAddressString4 `json:"SgsnNumber,omitempty"`
}

// NewSMAdditionalNumberMscNumber creates a SMAdditionalNumber with the msc-Number alternative.
func NewSMAdditionalNumberMscNumber(v ISDNAddressString4) SMAdditionalNumber {
	return SMAdditionalNumber{
		Choice:    SMAdditionalNumberChoiceMscNumber,
		MscNumber: &v,
	}
}

// NewSMAdditionalNumberSgsnNumber creates a SMAdditionalNumber with the sgsn-Number alternative.
func NewSMAdditionalNumberSgsnNumber(v ISDNAddressString4) SMAdditionalNumber {
	return SMAdditionalNumber{
		Choice:     SMAdditionalNumberChoiceSgsnNumber,
		SgsnNumber: &v,
	}
}

// SMMOForwardSMArg represents the ASN.1 type MO-ForwardSM-Arg (SEQUENCE).
type SMMOForwardSMArg struct {
	SmRPDA             SMSMRPDA             `asn1:""`
	SmRPOA             SMSMRPOA             `asn1:""`
	SmRPUI             SignalInfo4          `asn1:""`
	ExtensionContainer *ExtensionContainer4 `asn1:",optional" json:"ExtensionContainer,omitempty"`
	Imsi               *IMSI4               `asn1:",optional" json:"Imsi,omitempty"`
	CorrelationID      *SMCorrelationID     `asn1:"tag:0,context,implicit,optional" json:"CorrelationID,omitempty"`
	SmDeliveryOutcome  *SMSMDeliveryOutcome `asn1:"tag:1,context,implicit,optional" json:"SmDeliveryOutcome,omitempty"`
	ExtCount_          int64                `asn1:"-" json:"-"`
	ExtPresent_        []bool               `asn1:"-" json:"-"`
	ExtData_           [][]byte             `asn1:"-" json:"-"`
}

// SMMOForwardSMRes represents the ASN.1 type MO-ForwardSM-Res (SEQUENCE).
type SMMOForwardSMRes struct {
	SmRPUI             *SignalInfo4         `asn1:",optional" json:"SmRPUI,omitempty"`
	ExtensionContainer *ExtensionContainer4 `asn1:",optional" json:"ExtensionContainer,omitempty"`
	ExtCount_          int64                `asn1:"-" json:"-"`
	ExtPresent_        []bool               `asn1:"-" json:"-"`
	ExtData_           [][]byte             `asn1:"-" json:"-"`
}

// SMMTForwardSMArg represents the ASN.1 type MT-ForwardSM-Arg (SEQUENCE).
type SMMTForwardSMArg struct {
	SmRPDA                 SMSMRPDA                `asn1:""`
	SmRPOA                 SMSMRPOA                `asn1:""`
	SmRPUI                 SignalInfo4             `asn1:""`
	MoreMessagesToSend     *struct{}               `asn1:",optional" json:"MoreMessagesToSend,omitempty"`
	ExtensionContainer     *ExtensionContainer4    `asn1:",optional" json:"ExtensionContainer,omitempty"`
	SmDeliveryTimer        *SMSMDeliveryTimerValue `asn1:",optional" json:"SmDeliveryTimer,omitempty"`
	SmDeliveryStartTime    *Time3                  `asn1:",optional" json:"SmDeliveryStartTime,omitempty"`
	SmsOverIPOnlyIndicator *struct{}               `asn1:"tag:0,context,implicit,optional" json:"SmsOverIPOnlyIndicator,omitempty"`
	CorrelationID          *SMCorrelationID        `asn1:"tag:1,context,implicit,optional" json:"CorrelationID,omitempty"`
	ExtCount_              int64                   `asn1:"-" json:"-"`
	ExtPresent_            []bool                  `asn1:"-" json:"-"`
	ExtData_               [][]byte                `asn1:"-" json:"-"`
}

// SMCorrelationID represents the ASN.1 type CorrelationID (SEQUENCE).
type SMCorrelationID struct {
	HlrId   *HLRId4   `asn1:"tag:0,context,implicit,optional" json:"HlrId,omitempty"`
	SipUriA *SMSIPURI `asn1:"tag:1,context,implicit,optional" json:"SipUriA,omitempty"`
	SipUriB SMSIPURI  `asn1:"tag:2,context,implicit"`
}

// SMSIPURI represents the ASN.1 type SIP-URI (OCTET_STRING).
type SMSIPURI = []byte

// SMMTForwardSMRes represents the ASN.1 type MT-ForwardSM-Res (SEQUENCE).
type SMMTForwardSMRes struct {
	SmRPUI             *SignalInfo4         `asn1:",optional" json:"SmRPUI,omitempty"`
	ExtensionContainer *ExtensionContainer4 `asn1:",optional" json:"ExtensionContainer,omitempty"`
	ExtCount_          int64                `asn1:"-" json:"-"`
	ExtPresent_        []bool               `asn1:"-" json:"-"`
	ExtData_           [][]byte             `asn1:"-" json:"-"`
}

// SMSMRPDA choice constants.
const (
	SMSMRPDAChoiceImsi                   = 1
	SMSMRPDAChoiceLmsi                   = 2
	SMSMRPDAChoiceServiceCentreAddressDA = 3
	SMSMRPDAChoiceNoSMRPDA               = 4
)

// SMSMRPDA represents the ASN.1 CHOICE type SM-RP-DA.
type SMSMRPDA struct {
	Choice                 int
	Imsi                   *IMSI4          `json:"Imsi,omitempty"`
	Lmsi                   *LMSI4          `json:"Lmsi,omitempty"`
	ServiceCentreAddressDA *AddressString4 `json:"ServiceCentreAddressDA,omitempty"`
	NoSMRPDA               *struct{}       `json:"NoSMRPDA,omitempty"`
}

// NewSMSMRPDAImsi creates a SMSMRPDA with the imsi alternative.
func NewSMSMRPDAImsi(v IMSI4) SMSMRPDA {
	return SMSMRPDA{
		Choice: SMSMRPDAChoiceImsi,
		Imsi:   &v,
	}
}

// NewSMSMRPDALmsi creates a SMSMRPDA with the lmsi alternative.
func NewSMSMRPDALmsi(v LMSI4) SMSMRPDA {
	return SMSMRPDA{
		Choice: SMSMRPDAChoiceLmsi,
		Lmsi:   &v,
	}
}

// NewSMSMRPDAServiceCentreAddressDA creates a SMSMRPDA with the serviceCentreAddressDA alternative.
func NewSMSMRPDAServiceCentreAddressDA(v AddressString4) SMSMRPDA {
	return SMSMRPDA{
		Choice:                 SMSMRPDAChoiceServiceCentreAddressDA,
		ServiceCentreAddressDA: &v,
	}
}

// NewSMSMRPDANoSMRPDA creates a SMSMRPDA with the noSM-RP-DA alternative.
func NewSMSMRPDANoSMRPDA(v struct{}) SMSMRPDA {
	return SMSMRPDA{
		Choice:   SMSMRPDAChoiceNoSMRPDA,
		NoSMRPDA: &v,
	}
}

// SMSMRPOA choice constants.
const (
	SMSMRPOAChoiceMsisdn                 = 1
	SMSMRPOAChoiceServiceCentreAddressOA = 2
	SMSMRPOAChoiceNoSMRPOA               = 3
)

// SMSMRPOA represents the ASN.1 CHOICE type SM-RP-OA.
type SMSMRPOA struct {
	Choice                 int
	Msisdn                 *ISDNAddressString4 `json:"Msisdn,omitempty"`
	ServiceCentreAddressOA *AddressString4     `json:"ServiceCentreAddressOA,omitempty"`
	NoSMRPOA               *struct{}           `json:"NoSMRPOA,omitempty"`
}

// NewSMSMRPOAMsisdn creates a SMSMRPOA with the msisdn alternative.
func NewSMSMRPOAMsisdn(v ISDNAddressString4) SMSMRPOA {
	return SMSMRPOA{
		Choice: SMSMRPOAChoiceMsisdn,
		Msisdn: &v,
	}
}

// NewSMSMRPOAServiceCentreAddressOA creates a SMSMRPOA with the serviceCentreAddressOA alternative.
func NewSMSMRPOAServiceCentreAddressOA(v AddressString4) SMSMRPOA {
	return SMSMRPOA{
		Choice:                 SMSMRPOAChoiceServiceCentreAddressOA,
		ServiceCentreAddressOA: &v,
	}
}

// NewSMSMRPOANoSMRPOA creates a SMSMRPOA with the noSM-RP-OA alternative.
func NewSMSMRPOANoSMRPOA(v struct{}) SMSMRPOA {
	return SMSMRPOA{
		Choice:   SMSMRPOAChoiceNoSMRPOA,
		NoSMRPOA: &v,
	}
}

// SMSMDeliveryTimerValue represents the ASN.1 type SM-DeliveryTimerValue (INTEGER).
type SMSMDeliveryTimerValue = int64

// SMReportSMDeliveryStatusArg represents the ASN.1 type ReportSM-DeliveryStatusArg (SEQUENCE).
type SMReportSMDeliveryStatusArg struct {
	Msisdn                                 ISDNAddressString4             `asn1:""`
	ServiceCentreAddress                   AddressString4                 `asn1:""`
	SmDeliveryOutcome                      SMSMDeliveryOutcome            `asn1:""`
	AbsentSubscriberDiagnosticSM           *AbsentSubscriberDiagnosticSM4 `asn1:"tag:0,context,implicit,optional" json:"AbsentSubscriberDiagnosticSM,omitempty"`
	ExtensionContainer                     *ExtensionContainer4           `asn1:"tag:1,context,implicit,optional" json:"ExtensionContainer,omitempty"`
	GprsSupportIndicator                   *struct{}                      `asn1:"tag:2,context,implicit,optional" json:"GprsSupportIndicator,omitempty"`
	DeliveryOutcomeIndicator               *struct{}                      `asn1:"tag:3,context,implicit,optional" json:"DeliveryOutcomeIndicator,omitempty"`
	AdditionalSMDeliveryOutcome            *SMSMDeliveryOutcome           `asn1:"tag:4,context,implicit,optional" json:"AdditionalSMDeliveryOutcome,omitempty"`
	AdditionalAbsentSubscriberDiagnosticSM *AbsentSubscriberDiagnosticSM4 `asn1:"tag:5,context,implicit,optional" json:"AdditionalAbsentSubscriberDiagnosticSM,omitempty"`
	IpSmGwIndicator                        *struct{}                      `asn1:"tag:6,context,implicit,optional" json:"IpSmGwIndicator,omitempty"`
	IpSmGwSmDeliveryOutcome                *SMSMDeliveryOutcome           `asn1:"tag:7,context,implicit,optional" json:"IpSmGwSmDeliveryOutcome,omitempty"`
	IpSmGwAbsentSubscriberDiagnosticSM     *AbsentSubscriberDiagnosticSM4 `asn1:"tag:8,context,implicit,optional" json:"IpSmGwAbsentSubscriberDiagnosticSM,omitempty"`
	Imsi                                   *IMSI4                         `asn1:"tag:9,context,implicit,optional" json:"Imsi,omitempty"`
	SingleAttemptDelivery                  *struct{}                      `asn1:"tag:10,context,implicit,optional" json:"SingleAttemptDelivery,omitempty"`
	CorrelationID                          *SMCorrelationID               `asn1:"tag:11,context,implicit,optional" json:"CorrelationID,omitempty"`
	ExtCount_                              int64                          `asn1:"-" json:"-"`
	ExtPresent_                            []bool                         `asn1:"-" json:"-"`
	ExtData_                               [][]byte                       `asn1:"-" json:"-"`
}

// SMSMDeliveryOutcome represents the ASN.1 ENUMERATED type SM-DeliveryOutcome.
type SMSMDeliveryOutcome int64

const (
	SMSMDeliveryOutcomeMemoryCapacityExceeded SMSMDeliveryOutcome = 0
	SMSMDeliveryOutcomeAbsentSubscriber       SMSMDeliveryOutcome = 1
	SMSMDeliveryOutcomeSuccessfulTransfer     SMSMDeliveryOutcome = 2
)

func (v SMSMDeliveryOutcome) String() string {
	switch v {
	case SMSMDeliveryOutcomeMemoryCapacityExceeded:
		return "memoryCapacityExceeded"
	case SMSMDeliveryOutcomeAbsentSubscriber:
		return "absentSubscriber"
	case SMSMDeliveryOutcomeSuccessfulTransfer:
		return "successfulTransfer"
	default:
		return "unknown"
	}
}

// SMReportSMDeliveryStatusRes represents the ASN.1 type ReportSM-DeliveryStatusRes (SEQUENCE).
type SMReportSMDeliveryStatusRes struct {
	StoredMSISDN       *ISDNAddressString4  `asn1:",optional" json:"StoredMSISDN,omitempty"`
	ExtensionContainer *ExtensionContainer4 `asn1:",optional" json:"ExtensionContainer,omitempty"`
	ExtCount_          int64                `asn1:"-" json:"-"`
	ExtPresent_        []bool               `asn1:"-" json:"-"`
	ExtData_           [][]byte             `asn1:"-" json:"-"`
}

// SMAlertServiceCentreArg represents the ASN.1 type AlertServiceCentreArg (SEQUENCE).
type SMAlertServiceCentreArg struct {
	Msisdn               ISDNAddressString4 `asn1:""`
	ServiceCentreAddress AddressString4     `asn1:""`
	Imsi                 *IMSI4             `asn1:",optional" json:"Imsi,omitempty"`
	CorrelationID        *SMCorrelationID   `asn1:",optional" json:"CorrelationID,omitempty"`
	ExtCount_            int64              `asn1:"-" json:"-"`
	ExtPresent_          []bool             `asn1:"-" json:"-"`
	ExtData_             [][]byte           `asn1:"-" json:"-"`
}

// SMInformServiceCentreArg represents the ASN.1 type InformServiceCentreArg (SEQUENCE).
type SMInformServiceCentreArg struct {
	StoredMSISDN                           *ISDNAddressString4            `asn1:",optional" json:"StoredMSISDN,omitempty"`
	MwStatus                               *SMMWStatus                    `asn1:",optional" json:"MwStatus,omitempty"`
	ExtensionContainer                     *ExtensionContainer4           `asn1:",optional" json:"ExtensionContainer,omitempty"`
	AbsentSubscriberDiagnosticSM           *AbsentSubscriberDiagnosticSM4 `asn1:",optional" json:"AbsentSubscriberDiagnosticSM,omitempty"`
	AdditionalAbsentSubscriberDiagnosticSM *AbsentSubscriberDiagnosticSM4 `asn1:"tag:0,context,implicit,optional" json:"AdditionalAbsentSubscriberDiagnosticSM,omitempty"`
	ExtCount_                              int64                          `asn1:"-" json:"-"`
	ExtPresent_                            []bool                         `asn1:"-" json:"-"`
	ExtData_                               [][]byte                       `asn1:"-" json:"-"`
}

// SMMWStatus represents the ASN.1 type MW-Status (BIT_STRING).
type SMMWStatus = runtime.BitString

// SMReadyForSMArg represents the ASN.1 type ReadyForSM-Arg (SEQUENCE).
type SMReadyForSMArg struct {
	Imsi                           IMSI4                `asn1:"tag:0,context,implicit"`
	AlertReason                    SMAlertReason        `asn1:""`
	AlertReasonIndicator           *struct{}            `asn1:",optional" json:"AlertReasonIndicator,omitempty"`
	ExtensionContainer             *ExtensionContainer4 `asn1:",optional" json:"ExtensionContainer,omitempty"`
	AdditionalAlertReasonIndicator *struct{}            `asn1:"tag:1,context,implicit,optional" json:"AdditionalAlertReasonIndicator,omitempty"`
	ExtCount_                      int64                `asn1:"-" json:"-"`
	ExtPresent_                    []bool               `asn1:"-" json:"-"`
	ExtData_                       [][]byte             `asn1:"-" json:"-"`
}

// SMReadyForSMRes represents the ASN.1 type ReadyForSM-Res (SEQUENCE).
type SMReadyForSMRes struct {
	ExtensionContainer *ExtensionContainer4 `asn1:",optional" json:"ExtensionContainer,omitempty"`
	ExtCount_          int64                `asn1:"-" json:"-"`
	ExtPresent_        []bool               `asn1:"-" json:"-"`
	ExtData_           [][]byte             `asn1:"-" json:"-"`
}

// SMAlertReason represents the ASN.1 ENUMERATED type AlertReason.
type SMAlertReason int64

const (
	SMAlertReasonMsPresent       SMAlertReason = 0
	SMAlertReasonMemoryAvailable SMAlertReason = 1
)

func (v SMAlertReason) String() string {
	switch v {
	case SMAlertReasonMsPresent:
		return "ms-Present"
	case SMAlertReasonMemoryAvailable:
		return "memoryAvailable"
	default:
		return "unknown"
	}
}

// SMMTForwardSMVGCSArg represents the ASN.1 type MT-ForwardSM-VGCS-Arg (SEQUENCE).
type SMMTForwardSMVGCSArg struct {
	AsciCallReference  ASCICallReference4   `asn1:""`
	SmRPOA             SMSMRPOA             `asn1:""`
	SmRPUI             SignalInfo4          `asn1:""`
	ExtensionContainer *ExtensionContainer4 `asn1:",optional" json:"ExtensionContainer,omitempty"`
	ExtCount_          int64                `asn1:"-" json:"-"`
	ExtPresent_        []bool               `asn1:"-" json:"-"`
	ExtData_           [][]byte             `asn1:"-" json:"-"`
}

// SMMTForwardSMVGCSRes represents the ASN.1 type MT-ForwardSM-VGCS-Res (SEQUENCE).
type SMMTForwardSMVGCSRes struct {
	SmRPUI                         *SignalInfo4               `asn1:"tag:0,context,implicit,optional" json:"SmRPUI,omitempty"`
	DispatcherList                 SMDispatcherList           `asn1:"tag:1,context,implicit,optional" json:"DispatcherList,omitempty"`
	DispatcherListIndef_           bool                       `asn1:"-" json:"-"`
	OngoingCall                    *struct{}                  `asn1:",optional" json:"OngoingCall,omitempty"`
	ExtensionContainer             *ExtensionContainer4       `asn1:"tag:2,context,implicit,optional" json:"ExtensionContainer,omitempty"`
	AdditionalDispatcherList       SMAdditionalDispatcherList `asn1:"tag:3,context,implicit,optional" json:"AdditionalDispatcherList,omitempty"`
	AdditionalDispatcherListIndef_ bool                       `asn1:"-" json:"-"`
	ExtCount_                      int64                      `asn1:"-" json:"-"`
	ExtPresent_                    []bool                     `asn1:"-" json:"-"`
	ExtData_                       [][]byte                   `asn1:"-" json:"-"`
}

// SMDispatcherList represents the ASN.1 type DispatcherList (SEQUENCE_OF).
type SMDispatcherList = []ISDNAddressString4

// SMAdditionalDispatcherList represents the ASN.1 type AdditionalDispatcherList (SEQUENCE_OF).
type SMAdditionalDispatcherList = []ISDNAddressString4

// MarshalBER encodes SMRoutingInfoForSMArg to BER format.
func (v *SMRoutingInfoForSMArg) MarshalBER() ([]byte, error) {
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

// MarshalDER encodes SMRoutingInfoForSMArg to DER format.
func (v *SMRoutingInfoForSMArg) MarshalDER() ([]byte, error) {
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
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
		children = append(children, ext...)
	}
	encoded := ber.EncodeSequence(children)
	if err := ber.ValidateDERElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding SMRoutingInfoForSMArg as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes SMRoutingInfoForSMArg from BER/DER format.
func (v *SMRoutingInfoForSMArg) UnmarshalBER(data []byte) error {
	*v = SMRoutingInfoForSMArg{}
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding SMRoutingInfoForSMArg SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "SMRoutingInfoForSMArg", Cause: ber.ErrExtraData}
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
	v.Msisdn = ISDNAddressString4(rawVal_msisdn)
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
	v.ServiceCentreAddress = AddressString4(rawVal_servicecentreaddress)
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
				var dec_extensioncontainer ExtensionContainer4
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
				tmp_smrpmti := SMSMRPMTI(decVal_smrpmti)
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
				tmp_smrpsmea := SMSMRPSMEA(rawVal_smrpsmea)
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
				decVal_smdeliverynotintended, intErr := ber.DecodeEnumeratedValue(rawVal_smdeliverynotintended)
				if intErr != nil {
					return fmt.Errorf("decoding sm-deliveryNotIntended: %w", intErr)
				}
				tmp_smdeliverynotintended := SMSMDeliveryNotIntended(decVal_smdeliverynotintended)
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
				tmp_imsi := IMSI4(rawVal_imsi)
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
				var dec_correlationid SMCorrelationID
				if unmErr := dec_correlationid.UnmarshalBER(reconstructed_correlationid); unmErr != nil {
					return fmt.Errorf("decoding correlationID: %w", unmErr)
				}
				v.CorrelationID = &dec_correlationid
				offset += n_correlationid
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "SMRoutingInfoForSMArg", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes SMRoutingInfoForSMRes to BER format.
func (v *SMRoutingInfoForSMRes) MarshalBER() ([]byte, error) {
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

// MarshalDER encodes SMRoutingInfoForSMRes to DER format.
func (v *SMRoutingInfoForSMRes) MarshalDER() ([]byte, error) {
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
		return nil, fmt.Errorf("encoding SMRoutingInfoForSMRes as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes SMRoutingInfoForSMRes from BER/DER format.
func (v *SMRoutingInfoForSMRes) UnmarshalBER(data []byte) error {
	*v = SMRoutingInfoForSMRes{}
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding SMRoutingInfoForSMRes SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "SMRoutingInfoForSMRes", Cause: ber.ErrExtraData}
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
	v.Imsi = IMSI4(val_imsi)
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
				var dec_extensioncontainer ExtensionContainer4
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
				var dec_ipsmgwguidance SMIPSMGWGuidance
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
			return &ber.DecodeError{Offset: offset, TypeName: "SMRoutingInfoForSMRes", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes SMIPSMGWGuidance to BER format.
func (v *SMIPSMGWGuidance) MarshalBER() ([]byte, error) {
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

// MarshalDER encodes SMIPSMGWGuidance to DER format.
func (v *SMIPSMGWGuidance) MarshalDER() ([]byte, error) {
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
		return nil, fmt.Errorf("encoding SMIPSMGWGuidance as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes SMIPSMGWGuidance from BER/DER format.
func (v *SMIPSMGWGuidance) UnmarshalBER(data []byte) error {
	*v = SMIPSMGWGuidance{}
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding SMIPSMGWGuidance SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "SMIPSMGWGuidance", Cause: ber.ErrExtraData}
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
	v.MinimumDeliveryTimeValue = SMSMDeliveryTimerValue(val_minimumdeliverytimevalue)
	offset += n
	// Decode recommendedDeliveryTimeValue
	if offset >= len(content) {
		return fmt.Errorf("missing required field recommendedDeliveryTimeValue")
	}
	val_recommendeddeliverytimevalue, n, err := ber.DecodeInteger(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding recommendedDeliveryTimeValue: %w", err)
	}
	v.RecommendedDeliveryTimeValue = SMSMDeliveryTimerValue(val_recommendeddeliverytimevalue)
	offset += n
	// Decode extensionContainer
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassUniversal && peekTag.Number == 16 {
				// Decode nested SEQUENCE (ExtensionContainer4)
				_, n_extensioncontainer, _, tlvErr_extensioncontainer := ber.DecodeTLV(content[offset:])
				if tlvErr_extensioncontainer != nil {
					return fmt.Errorf("decoding extensionContainer: %w", tlvErr_extensioncontainer)
				}
				var dec_extensioncontainer ExtensionContainer4
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
			return &ber.DecodeError{Offset: offset, TypeName: "SMIPSMGWGuidance", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes SMLocationInfoWithLMSI to BER format.
func (v *SMLocationInfoWithLMSI) MarshalBER() ([]byte, error) {
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

// MarshalDER encodes SMLocationInfoWithLMSI to DER format.
func (v *SMLocationInfoWithLMSI) MarshalDER() ([]byte, error) {
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
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
		children = append(children, ext...)
	}
	encoded := ber.EncodeSequence(children)
	if err := ber.ValidateDERElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding SMLocationInfoWithLMSI as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes SMLocationInfoWithLMSI from BER/DER format.
func (v *SMLocationInfoWithLMSI) UnmarshalBER(data []byte) error {
	*v = SMLocationInfoWithLMSI{}
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding SMLocationInfoWithLMSI SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "SMLocationInfoWithLMSI", Cause: ber.ErrExtraData}
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
	v.NetworkNodeNumber = ISDNAddressString4(rawVal_networknodenumber)
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
				tmp_lmsi := LMSI4(val_lmsi)
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
				// Decode nested SEQUENCE (ExtensionContainer4)
				_, n_extensioncontainer, _, tlvErr_extensioncontainer := ber.DecodeTLV(content[offset:])
				if tlvErr_extensioncontainer != nil {
					return fmt.Errorf("decoding extensionContainer: %w", tlvErr_extensioncontainer)
				}
				var dec_extensioncontainer ExtensionContainer4
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
				var dec_additionalnumber SMAdditionalNumber
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
				var dec_networknodediameteraddress NetworkNodeDiameterAddress3
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
				var dec_additionalnetworknodediameteraddress NetworkNodeDiameterAddress3
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
				var dec_thirdnumber SMAdditionalNumber
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
				var dec_thirdnetworknodediameteraddress NetworkNodeDiameterAddress3
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
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "SMLocationInfoWithLMSI", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes SMAdditionalNumber to BER format.
func (v *SMAdditionalNumber) MarshalBER() ([]byte, error) {
	switch v.Choice {
	case SMAdditionalNumberChoiceMscNumber:
		if v.MscNumber == nil {
			return nil, fmt.Errorf("choice SMAdditionalNumber: msc-Number is nil")
		}
		enc_0 := ber.EncodeOctetString([]byte(*v.MscNumber))
		retagged_enc_0, tagErr_enc_0 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_0)
		if tagErr_enc_0 != nil {
			return nil, fmt.Errorf("encoding msc-Number: %w", tagErr_enc_0)
		}
		enc_0 = retagged_enc_0
		return enc_0, nil
	case SMAdditionalNumberChoiceSgsnNumber:
		if v.SgsnNumber == nil {
			return nil, fmt.Errorf("choice SMAdditionalNumber: sgsn-Number is nil")
		}
		enc_1 := ber.EncodeOctetString([]byte(*v.SgsnNumber))
		retagged_enc_1, tagErr_enc_1 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_1)
		if tagErr_enc_1 != nil {
			return nil, fmt.Errorf("encoding sgsn-Number: %w", tagErr_enc_1)
		}
		enc_1 = retagged_enc_1
		return enc_1, nil
	default:
		return nil, fmt.Errorf("unknown choice %d for SMAdditionalNumber", v.Choice)
	}
}

// MarshalDER encodes SMAdditionalNumber to DER format.
func (v *SMAdditionalNumber) MarshalDER() ([]byte, error) {
	encoded, err := v.MarshalBER()
	if err != nil {
		return nil, err
	}
	if err := ber.ValidateDERElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding SMAdditionalNumber as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes SMAdditionalNumber from BER/DER format.
func (v *SMAdditionalNumber) UnmarshalBER(data []byte) error {
	*v = SMAdditionalNumber{}
	if len(data) == 0 {
		return fmt.Errorf("empty data for SMAdditionalNumber CHOICE")
	}
	choiceData := data
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for SMAdditionalNumber: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData)
	if tlvErr != nil {
		return fmt.Errorf("decoding SMAdditionalNumber CHOICE: %w", tlvErr)
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "SMAdditionalNumber", Cause: ber.ErrExtraData}
	}

	if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
		v.Choice = SMAdditionalNumberChoiceMscNumber
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding msc-Number: %w", tlvErr)
		}
		tmp := ISDNAddressString4(rawVal)
		v.MscNumber = &tmp
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
		v.Choice = SMAdditionalNumberChoiceSgsnNumber
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding sgsn-Number: %w", tlvErr)
		}
		tmp := ISDNAddressString4(rawVal)
		v.SgsnNumber = &tmp
	} else {
		return fmt.Errorf("unknown tag %s for SMAdditionalNumber CHOICE", peekTag)
	}
	return nil
}

// MarshalBER encodes SMMOForwardSMArg to BER format.
func (v *SMMOForwardSMArg) MarshalBER() ([]byte, error) {
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

// MarshalDER encodes SMMOForwardSMArg to DER format.
func (v *SMMOForwardSMArg) MarshalDER() ([]byte, error) {
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
		return nil, fmt.Errorf("encoding SMMOForwardSMArg as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes SMMOForwardSMArg from BER/DER format.
func (v *SMMOForwardSMArg) UnmarshalBER(data []byte) error {
	*v = SMMOForwardSMArg{}
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding SMMOForwardSMArg SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "SMMOForwardSMArg", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode sm-RP-DA
	if offset >= len(content) {
		return fmt.Errorf("missing required field sm-RP-DA")
	}
	// Decode nested CHOICE (SMSMRPDA)
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
	// Decode nested CHOICE (SMSMRPOA)
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
	v.SmRPUI = SignalInfo4(val_smrpui)
	offset += n
	// Decode extensionContainer
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassUniversal && peekTag.Number == 16 {
				// Decode nested SEQUENCE (ExtensionContainer4)
				_, n_extensioncontainer, _, tlvErr_extensioncontainer := ber.DecodeTLV(content[offset:])
				if tlvErr_extensioncontainer != nil {
					return fmt.Errorf("decoding extensionContainer: %w", tlvErr_extensioncontainer)
				}
				var dec_extensioncontainer ExtensionContainer4
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
				tmp_imsi := IMSI4(val_imsi)
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
				var dec_correlationid SMCorrelationID
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
				decVal_smdeliveryoutcome, intErr := ber.DecodeEnumeratedValue(rawVal_smdeliveryoutcome)
				if intErr != nil {
					return fmt.Errorf("decoding sm-DeliveryOutcome: %w", intErr)
				}
				tmp_smdeliveryoutcome := SMSMDeliveryOutcome(decVal_smdeliveryoutcome)
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
			return &ber.DecodeError{Offset: offset, TypeName: "SMMOForwardSMArg", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes SMMOForwardSMRes to BER format.
func (v *SMMOForwardSMRes) MarshalBER() ([]byte, error) {
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

// MarshalDER encodes SMMOForwardSMRes to DER format.
func (v *SMMOForwardSMRes) MarshalDER() ([]byte, error) {
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
		return nil, fmt.Errorf("encoding SMMOForwardSMRes as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes SMMOForwardSMRes from BER/DER format.
func (v *SMMOForwardSMRes) UnmarshalBER(data []byte) error {
	*v = SMMOForwardSMRes{}
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding SMMOForwardSMRes SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "SMMOForwardSMRes", Cause: ber.ErrExtraData}
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
				tmp_smrpui := SignalInfo4(val_smrpui)
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
				// Decode nested SEQUENCE (ExtensionContainer4)
				_, n_extensioncontainer, _, tlvErr_extensioncontainer := ber.DecodeTLV(content[offset:])
				if tlvErr_extensioncontainer != nil {
					return fmt.Errorf("decoding extensionContainer: %w", tlvErr_extensioncontainer)
				}
				var dec_extensioncontainer ExtensionContainer4
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
			return &ber.DecodeError{Offset: offset, TypeName: "SMMOForwardSMRes", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes SMMTForwardSMArg to BER format.
func (v *SMMTForwardSMArg) MarshalBER() ([]byte, error) {
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

// MarshalDER encodes SMMTForwardSMArg to DER format.
func (v *SMMTForwardSMArg) MarshalDER() ([]byte, error) {
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
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
		children = append(children, ext...)
	}
	encoded := ber.EncodeSequence(children)
	if err := ber.ValidateDERElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding SMMTForwardSMArg as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes SMMTForwardSMArg from BER/DER format.
func (v *SMMTForwardSMArg) UnmarshalBER(data []byte) error {
	*v = SMMTForwardSMArg{}
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding SMMTForwardSMArg SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "SMMTForwardSMArg", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode sm-RP-DA
	if offset >= len(content) {
		return fmt.Errorf("missing required field sm-RP-DA")
	}
	// Decode nested CHOICE (SMSMRPDA)
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
	// Decode nested CHOICE (SMSMRPOA)
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
	v.SmRPUI = SignalInfo4(val_smrpui)
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
				// Decode nested SEQUENCE (ExtensionContainer4)
				_, n_extensioncontainer, _, tlvErr_extensioncontainer := ber.DecodeTLV(content[offset:])
				if tlvErr_extensioncontainer != nil {
					return fmt.Errorf("decoding extensionContainer: %w", tlvErr_extensioncontainer)
				}
				var dec_extensioncontainer ExtensionContainer4
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
				tmp_smdeliverytimer := SMSMDeliveryTimerValue(val_smdeliverytimer)
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
				tmp_smdeliverystarttime := Time3(val_smdeliverystarttime)
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
				var dec_correlationid SMCorrelationID
				if unmErr := dec_correlationid.UnmarshalBER(reconstructed_correlationid); unmErr != nil {
					return fmt.Errorf("decoding correlationID: %w", unmErr)
				}
				v.CorrelationID = &dec_correlationid
				offset += n_correlationid
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "SMMTForwardSMArg", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes SMCorrelationID to BER format.
func (v *SMCorrelationID) MarshalBER() ([]byte, error) {
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

// MarshalDER encodes SMCorrelationID to DER format.
func (v *SMCorrelationID) MarshalDER() ([]byte, error) {
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
		return nil, fmt.Errorf("encoding SMCorrelationID as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes SMCorrelationID from BER/DER format.
func (v *SMCorrelationID) UnmarshalBER(data []byte) error {
	*v = SMCorrelationID{}
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding SMCorrelationID SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "SMCorrelationID", Cause: ber.ErrExtraData}
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
				tmp_hlrid := HLRId4(rawVal_hlrid)
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
				tmp_sipuria := SMSIPURI(rawVal_sipuria)
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
	v.SipUriB = SMSIPURI(rawVal_sipurib)
	offset += n_sipurib
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "SMCorrelationID", Cause: ber.ErrExtraData}
	}
	return nil
}

// MarshalBER encodes SMMTForwardSMRes to BER format.
func (v *SMMTForwardSMRes) MarshalBER() ([]byte, error) {
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

// MarshalDER encodes SMMTForwardSMRes to DER format.
func (v *SMMTForwardSMRes) MarshalDER() ([]byte, error) {
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
		return nil, fmt.Errorf("encoding SMMTForwardSMRes as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes SMMTForwardSMRes from BER/DER format.
func (v *SMMTForwardSMRes) UnmarshalBER(data []byte) error {
	*v = SMMTForwardSMRes{}
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding SMMTForwardSMRes SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "SMMTForwardSMRes", Cause: ber.ErrExtraData}
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
				tmp_smrpui := SignalInfo4(val_smrpui)
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
				// Decode nested SEQUENCE (ExtensionContainer4)
				_, n_extensioncontainer, _, tlvErr_extensioncontainer := ber.DecodeTLV(content[offset:])
				if tlvErr_extensioncontainer != nil {
					return fmt.Errorf("decoding extensionContainer: %w", tlvErr_extensioncontainer)
				}
				var dec_extensioncontainer ExtensionContainer4
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
			return &ber.DecodeError{Offset: offset, TypeName: "SMMTForwardSMRes", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes SMSMRPDA to BER format.
func (v *SMSMRPDA) MarshalBER() ([]byte, error) {
	switch v.Choice {
	case SMSMRPDAChoiceImsi:
		if v.Imsi == nil {
			return nil, fmt.Errorf("choice SMSMRPDA: imsi is nil")
		}
		enc_0 := ber.EncodeOctetString([]byte(*v.Imsi))
		retagged_enc_0, tagErr_enc_0 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_0)
		if tagErr_enc_0 != nil {
			return nil, fmt.Errorf("encoding imsi: %w", tagErr_enc_0)
		}
		enc_0 = retagged_enc_0
		return enc_0, nil
	case SMSMRPDAChoiceLmsi:
		if v.Lmsi == nil {
			return nil, fmt.Errorf("choice SMSMRPDA: lmsi is nil")
		}
		enc_1 := ber.EncodeOctetString([]byte(*v.Lmsi))
		retagged_enc_1, tagErr_enc_1 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_1)
		if tagErr_enc_1 != nil {
			return nil, fmt.Errorf("encoding lmsi: %w", tagErr_enc_1)
		}
		enc_1 = retagged_enc_1
		return enc_1, nil
	case SMSMRPDAChoiceServiceCentreAddressDA:
		if v.ServiceCentreAddressDA == nil {
			return nil, fmt.Errorf("choice SMSMRPDA: serviceCentreAddressDA is nil")
		}
		enc_2 := ber.EncodeOctetString([]byte(*v.ServiceCentreAddressDA))
		retagged_enc_2, tagErr_enc_2 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, enc_2)
		if tagErr_enc_2 != nil {
			return nil, fmt.Errorf("encoding serviceCentreAddressDA: %w", tagErr_enc_2)
		}
		enc_2 = retagged_enc_2
		return enc_2, nil
	case SMSMRPDAChoiceNoSMRPDA:
		enc_3 := ber.EncodeNull()
		retagged_enc_3, tagErr_enc_3 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 5, enc_3)
		if tagErr_enc_3 != nil {
			return nil, fmt.Errorf("encoding noSM-RP-DA: %w", tagErr_enc_3)
		}
		enc_3 = retagged_enc_3
		return enc_3, nil
	default:
		return nil, fmt.Errorf("unknown choice %d for SMSMRPDA", v.Choice)
	}
}

// MarshalDER encodes SMSMRPDA to DER format.
func (v *SMSMRPDA) MarshalDER() ([]byte, error) {
	encoded, err := v.MarshalBER()
	if err != nil {
		return nil, err
	}
	if err := ber.ValidateDERElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding SMSMRPDA as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes SMSMRPDA from BER/DER format.
func (v *SMSMRPDA) UnmarshalBER(data []byte) error {
	*v = SMSMRPDA{}
	if len(data) == 0 {
		return fmt.Errorf("empty data for SMSMRPDA CHOICE")
	}
	choiceData := data
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for SMSMRPDA: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData)
	if tlvErr != nil {
		return fmt.Errorf("decoding SMSMRPDA CHOICE: %w", tlvErr)
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "SMSMRPDA", Cause: ber.ErrExtraData}
	}

	if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
		v.Choice = SMSMRPDAChoiceImsi
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding imsi: %w", tlvErr)
		}
		tmp := IMSI4(rawVal)
		v.Imsi = &tmp
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
		v.Choice = SMSMRPDAChoiceLmsi
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding lmsi: %w", tlvErr)
		}
		tmp := LMSI4(rawVal)
		v.Lmsi = &tmp
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4 {
		v.Choice = SMSMRPDAChoiceServiceCentreAddressDA
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding serviceCentreAddressDA: %w", tlvErr)
		}
		tmp := AddressString4(rawVal)
		v.ServiceCentreAddressDA = &tmp
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 5 && peekTag.Constructed == false {
		v.Choice = SMSMRPDAChoiceNoSMRPDA
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding noSM-RP-DA: %w", tlvErr)
		}
		if len(rawVal) != 0 {
			return fmt.Errorf("decoding noSM-RP-DA: %w: NULL content length %d", ber.ErrInvalidValue, len(rawVal))
		}
		v.NoSMRPDA = &struct{}{}
	} else {
		return fmt.Errorf("unknown tag %s for SMSMRPDA CHOICE", peekTag)
	}
	return nil
}

// MarshalBER encodes SMSMRPOA to BER format.
func (v *SMSMRPOA) MarshalBER() ([]byte, error) {
	switch v.Choice {
	case SMSMRPOAChoiceMsisdn:
		if v.Msisdn == nil {
			return nil, fmt.Errorf("choice SMSMRPOA: msisdn is nil")
		}
		enc_0 := ber.EncodeOctetString([]byte(*v.Msisdn))
		retagged_enc_0, tagErr_enc_0 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_0)
		if tagErr_enc_0 != nil {
			return nil, fmt.Errorf("encoding msisdn: %w", tagErr_enc_0)
		}
		enc_0 = retagged_enc_0
		return enc_0, nil
	case SMSMRPOAChoiceServiceCentreAddressOA:
		if v.ServiceCentreAddressOA == nil {
			return nil, fmt.Errorf("choice SMSMRPOA: serviceCentreAddressOA is nil")
		}
		enc_1 := ber.EncodeOctetString([]byte(*v.ServiceCentreAddressOA))
		retagged_enc_1, tagErr_enc_1 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, enc_1)
		if tagErr_enc_1 != nil {
			return nil, fmt.Errorf("encoding serviceCentreAddressOA: %w", tagErr_enc_1)
		}
		enc_1 = retagged_enc_1
		return enc_1, nil
	case SMSMRPOAChoiceNoSMRPOA:
		enc_2 := ber.EncodeNull()
		retagged_enc_2, tagErr_enc_2 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 5, enc_2)
		if tagErr_enc_2 != nil {
			return nil, fmt.Errorf("encoding noSM-RP-OA: %w", tagErr_enc_2)
		}
		enc_2 = retagged_enc_2
		return enc_2, nil
	default:
		return nil, fmt.Errorf("unknown choice %d for SMSMRPOA", v.Choice)
	}
}

// MarshalDER encodes SMSMRPOA to DER format.
func (v *SMSMRPOA) MarshalDER() ([]byte, error) {
	encoded, err := v.MarshalBER()
	if err != nil {
		return nil, err
	}
	if err := ber.ValidateDERElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding SMSMRPOA as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes SMSMRPOA from BER/DER format.
func (v *SMSMRPOA) UnmarshalBER(data []byte) error {
	*v = SMSMRPOA{}
	if len(data) == 0 {
		return fmt.Errorf("empty data for SMSMRPOA CHOICE")
	}
	choiceData := data
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for SMSMRPOA: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData)
	if tlvErr != nil {
		return fmt.Errorf("decoding SMSMRPOA CHOICE: %w", tlvErr)
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "SMSMRPOA", Cause: ber.ErrExtraData}
	}

	if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2 {
		v.Choice = SMSMRPOAChoiceMsisdn
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding msisdn: %w", tlvErr)
		}
		tmp := ISDNAddressString4(rawVal)
		v.Msisdn = &tmp
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4 {
		v.Choice = SMSMRPOAChoiceServiceCentreAddressOA
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding serviceCentreAddressOA: %w", tlvErr)
		}
		tmp := AddressString4(rawVal)
		v.ServiceCentreAddressOA = &tmp
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 5 && peekTag.Constructed == false {
		v.Choice = SMSMRPOAChoiceNoSMRPOA
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding noSM-RP-OA: %w", tlvErr)
		}
		if len(rawVal) != 0 {
			return fmt.Errorf("decoding noSM-RP-OA: %w: NULL content length %d", ber.ErrInvalidValue, len(rawVal))
		}
		v.NoSMRPOA = &struct{}{}
	} else {
		return fmt.Errorf("unknown tag %s for SMSMRPOA CHOICE", peekTag)
	}
	return nil
}

// MarshalBER encodes SMReportSMDeliveryStatusArg to BER format.
func (v *SMReportSMDeliveryStatusArg) MarshalBER() ([]byte, error) {
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

// MarshalDER encodes SMReportSMDeliveryStatusArg to DER format.
func (v *SMReportSMDeliveryStatusArg) MarshalDER() ([]byte, error) {
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
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
		children = append(children, ext...)
	}
	encoded := ber.EncodeSequence(children)
	if err := ber.ValidateDERElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding SMReportSMDeliveryStatusArg as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes SMReportSMDeliveryStatusArg from BER/DER format.
func (v *SMReportSMDeliveryStatusArg) UnmarshalBER(data []byte) error {
	*v = SMReportSMDeliveryStatusArg{}
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding SMReportSMDeliveryStatusArg SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "SMReportSMDeliveryStatusArg", Cause: ber.ErrExtraData}
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
	v.Msisdn = ISDNAddressString4(val_msisdn)
	offset += n
	// Decode serviceCentreAddress
	if offset >= len(content) {
		return fmt.Errorf("missing required field serviceCentreAddress")
	}
	val_servicecentreaddress, n, err := ber.DecodeOctetString(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding serviceCentreAddress: %w", err)
	}
	v.ServiceCentreAddress = AddressString4(val_servicecentreaddress)
	offset += n
	// Decode sm-DeliveryOutcome
	if offset >= len(content) {
		return fmt.Errorf("missing required field sm-DeliveryOutcome")
	}
	val_smdeliveryoutcome, n, err := ber.DecodeEnumerated(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding sm-DeliveryOutcome: %w", err)
	}
	v.SmDeliveryOutcome = SMSMDeliveryOutcome(val_smdeliveryoutcome)
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
				tmp_absentsubscriberdiagnosticsm := AbsentSubscriberDiagnosticSM4(decVal_absentsubscriberdiagnosticsm)
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
				var dec_extensioncontainer ExtensionContainer4
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
				decVal_additionalsmdeliveryoutcome, intErr := ber.DecodeEnumeratedValue(rawVal_additionalsmdeliveryoutcome)
				if intErr != nil {
					return fmt.Errorf("decoding additionalSM-DeliveryOutcome: %w", intErr)
				}
				tmp_additionalsmdeliveryoutcome := SMSMDeliveryOutcome(decVal_additionalsmdeliveryoutcome)
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
				tmp_additionalabsentsubscriberdiagnosticsm := AbsentSubscriberDiagnosticSM4(decVal_additionalabsentsubscriberdiagnosticsm)
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
				decVal_ipsmgwsmdeliveryoutcome, intErr := ber.DecodeEnumeratedValue(rawVal_ipsmgwsmdeliveryoutcome)
				if intErr != nil {
					return fmt.Errorf("decoding ip-sm-gw-sm-deliveryOutcome: %w", intErr)
				}
				tmp_ipsmgwsmdeliveryoutcome := SMSMDeliveryOutcome(decVal_ipsmgwsmdeliveryoutcome)
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
				tmp_ipsmgwabsentsubscriberdiagnosticsm := AbsentSubscriberDiagnosticSM4(decVal_ipsmgwabsentsubscriberdiagnosticsm)
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
				tmp_imsi := IMSI4(rawVal_imsi)
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
				var dec_correlationid SMCorrelationID
				if unmErr := dec_correlationid.UnmarshalBER(reconstructed_correlationid); unmErr != nil {
					return fmt.Errorf("decoding correlationID: %w", unmErr)
				}
				v.CorrelationID = &dec_correlationid
				offset += n_correlationid
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "SMReportSMDeliveryStatusArg", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes SMReportSMDeliveryStatusRes to BER format.
func (v *SMReportSMDeliveryStatusRes) MarshalBER() ([]byte, error) {
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

// MarshalDER encodes SMReportSMDeliveryStatusRes to DER format.
func (v *SMReportSMDeliveryStatusRes) MarshalDER() ([]byte, error) {
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
		return nil, fmt.Errorf("encoding SMReportSMDeliveryStatusRes as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes SMReportSMDeliveryStatusRes from BER/DER format.
func (v *SMReportSMDeliveryStatusRes) UnmarshalBER(data []byte) error {
	*v = SMReportSMDeliveryStatusRes{}
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding SMReportSMDeliveryStatusRes SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "SMReportSMDeliveryStatusRes", Cause: ber.ErrExtraData}
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
				tmp_storedmsisdn := ISDNAddressString4(val_storedmsisdn)
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
				// Decode nested SEQUENCE (ExtensionContainer4)
				_, n_extensioncontainer, _, tlvErr_extensioncontainer := ber.DecodeTLV(content[offset:])
				if tlvErr_extensioncontainer != nil {
					return fmt.Errorf("decoding extensionContainer: %w", tlvErr_extensioncontainer)
				}
				var dec_extensioncontainer ExtensionContainer4
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
			return &ber.DecodeError{Offset: offset, TypeName: "SMReportSMDeliveryStatusRes", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes SMAlertServiceCentreArg to BER format.
func (v *SMAlertServiceCentreArg) MarshalBER() ([]byte, error) {
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

// MarshalDER encodes SMAlertServiceCentreArg to DER format.
func (v *SMAlertServiceCentreArg) MarshalDER() ([]byte, error) {
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
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
		children = append(children, ext...)
	}
	encoded := ber.EncodeSequence(children)
	if err := ber.ValidateDERElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding SMAlertServiceCentreArg as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes SMAlertServiceCentreArg from BER/DER format.
func (v *SMAlertServiceCentreArg) UnmarshalBER(data []byte) error {
	*v = SMAlertServiceCentreArg{}
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding SMAlertServiceCentreArg SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "SMAlertServiceCentreArg", Cause: ber.ErrExtraData}
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
	v.Msisdn = ISDNAddressString4(val_msisdn)
	offset += n
	// Decode serviceCentreAddress
	if offset >= len(content) {
		return fmt.Errorf("missing required field serviceCentreAddress")
	}
	val_servicecentreaddress, n, err := ber.DecodeOctetString(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding serviceCentreAddress: %w", err)
	}
	v.ServiceCentreAddress = AddressString4(val_servicecentreaddress)
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
				tmp_imsi := IMSI4(val_imsi)
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
				// Decode nested SEQUENCE (SMCorrelationID)
				_, n_correlationid, _, tlvErr_correlationid := ber.DecodeTLV(content[offset:])
				if tlvErr_correlationid != nil {
					return fmt.Errorf("decoding correlationID: %w", tlvErr_correlationid)
				}
				var dec_correlationid SMCorrelationID
				if unmErr := dec_correlationid.UnmarshalBER(content[offset : offset+n_correlationid]); unmErr != nil {
					return fmt.Errorf("decoding correlationID: %w", unmErr)
				}
				v.CorrelationID = &dec_correlationid
				offset += n_correlationid
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "SMAlertServiceCentreArg", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes SMInformServiceCentreArg to BER format.
func (v *SMInformServiceCentreArg) MarshalBER() ([]byte, error) {
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

// MarshalDER encodes SMInformServiceCentreArg to DER format.
func (v *SMInformServiceCentreArg) MarshalDER() ([]byte, error) {
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
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
		children = append(children, ext...)
	}
	encoded := ber.EncodeSequence(children)
	if err := ber.ValidateDERElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding SMInformServiceCentreArg as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes SMInformServiceCentreArg from BER/DER format.
func (v *SMInformServiceCentreArg) UnmarshalBER(data []byte) error {
	*v = SMInformServiceCentreArg{}
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding SMInformServiceCentreArg SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "SMInformServiceCentreArg", Cause: ber.ErrExtraData}
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
				tmp_storedmsisdn := ISDNAddressString4(val_storedmsisdn)
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
				// Decode nested SEQUENCE (ExtensionContainer4)
				_, n_extensioncontainer, _, tlvErr_extensioncontainer := ber.DecodeTLV(content[offset:])
				if tlvErr_extensioncontainer != nil {
					return fmt.Errorf("decoding extensionContainer: %w", tlvErr_extensioncontainer)
				}
				var dec_extensioncontainer ExtensionContainer4
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
				tmp_absentsubscriberdiagnosticsm := AbsentSubscriberDiagnosticSM4(val_absentsubscriberdiagnosticsm)
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
				tmp_additionalabsentsubscriberdiagnosticsm := AbsentSubscriberDiagnosticSM4(decVal_additionalabsentsubscriberdiagnosticsm)
				v.AdditionalAbsentSubscriberDiagnosticSM = &tmp_additionalabsentsubscriberdiagnosticsm
				offset += n_additionalabsentsubscriberdiagnosticsm
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "SMInformServiceCentreArg", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes SMReadyForSMArg to BER format.
func (v *SMReadyForSMArg) MarshalBER() ([]byte, error) {
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

// MarshalDER encodes SMReadyForSMArg to DER format.
func (v *SMReadyForSMArg) MarshalDER() ([]byte, error) {
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
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
		children = append(children, ext...)
	}
	encoded := ber.EncodeSequence(children)
	if err := ber.ValidateDERElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding SMReadyForSMArg as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes SMReadyForSMArg from BER/DER format.
func (v *SMReadyForSMArg) UnmarshalBER(data []byte) error {
	*v = SMReadyForSMArg{}
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding SMReadyForSMArg SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "SMReadyForSMArg", Cause: ber.ErrExtraData}
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
	v.Imsi = IMSI4(rawVal_imsi)
	offset += n_imsi
	// Decode alertReason
	if offset >= len(content) {
		return fmt.Errorf("missing required field alertReason")
	}
	val_alertreason, n, err := ber.DecodeEnumerated(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding alertReason: %w", err)
	}
	v.AlertReason = SMAlertReason(val_alertreason)
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
				// Decode nested SEQUENCE (ExtensionContainer4)
				_, n_extensioncontainer, _, tlvErr_extensioncontainer := ber.DecodeTLV(content[offset:])
				if tlvErr_extensioncontainer != nil {
					return fmt.Errorf("decoding extensionContainer: %w", tlvErr_extensioncontainer)
				}
				var dec_extensioncontainer ExtensionContainer4
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
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "SMReadyForSMArg", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes SMReadyForSMRes to BER format.
func (v *SMReadyForSMRes) MarshalBER() ([]byte, error) {
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

// MarshalDER encodes SMReadyForSMRes to DER format.
func (v *SMReadyForSMRes) MarshalDER() ([]byte, error) {
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
		return nil, fmt.Errorf("encoding SMReadyForSMRes as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes SMReadyForSMRes from BER/DER format.
func (v *SMReadyForSMRes) UnmarshalBER(data []byte) error {
	*v = SMReadyForSMRes{}
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding SMReadyForSMRes SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "SMReadyForSMRes", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode extensionContainer
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassUniversal && peekTag.Number == 16 {
				// Decode nested SEQUENCE (ExtensionContainer4)
				_, n_extensioncontainer, _, tlvErr_extensioncontainer := ber.DecodeTLV(content[offset:])
				if tlvErr_extensioncontainer != nil {
					return fmt.Errorf("decoding extensionContainer: %w", tlvErr_extensioncontainer)
				}
				var dec_extensioncontainer ExtensionContainer4
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
			return &ber.DecodeError{Offset: offset, TypeName: "SMReadyForSMRes", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes SMMTForwardSMVGCSArg to BER format.
func (v *SMMTForwardSMVGCSArg) MarshalBER() ([]byte, error) {
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

// MarshalDER encodes SMMTForwardSMVGCSArg to DER format.
func (v *SMMTForwardSMVGCSArg) MarshalDER() ([]byte, error) {
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
		return nil, fmt.Errorf("encoding SMMTForwardSMVGCSArg as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes SMMTForwardSMVGCSArg from BER/DER format.
func (v *SMMTForwardSMVGCSArg) UnmarshalBER(data []byte) error {
	*v = SMMTForwardSMVGCSArg{}
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding SMMTForwardSMVGCSArg SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "SMMTForwardSMVGCSArg", Cause: ber.ErrExtraData}
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
	v.AsciCallReference = ASCICallReference4(val_ascicallreference)
	offset += n
	// Decode sm-RP-OA
	if offset >= len(content) {
		return fmt.Errorf("missing required field sm-RP-OA")
	}
	// Decode nested CHOICE (SMSMRPOA)
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
	v.SmRPUI = SignalInfo4(val_smrpui)
	offset += n
	// Decode extensionContainer
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassUniversal && peekTag.Number == 16 {
				// Decode nested SEQUENCE (ExtensionContainer4)
				_, n_extensioncontainer, _, tlvErr_extensioncontainer := ber.DecodeTLV(content[offset:])
				if tlvErr_extensioncontainer != nil {
					return fmt.Errorf("decoding extensionContainer: %w", tlvErr_extensioncontainer)
				}
				var dec_extensioncontainer ExtensionContainer4
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
			return &ber.DecodeError{Offset: offset, TypeName: "SMMTForwardSMVGCSArg", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes SMMTForwardSMVGCSRes to BER format.
func (v *SMMTForwardSMVGCSRes) MarshalBER() ([]byte, error) {
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
		enc_dispatcherlist, err := MarshalBERSMDispatcherList(v.DispatcherList)
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
		enc_additionaldispatcherlist, err := MarshalBERSMAdditionalDispatcherList(v.AdditionalDispatcherList)
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

// MarshalDER encodes SMMTForwardSMVGCSRes to DER format.
func (v *SMMTForwardSMVGCSRes) MarshalDER() ([]byte, error) {
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
		enc_dispatcherlist, err := MarshalDERSMDispatcherList(v.DispatcherList)
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
		enc_additionaldispatcherlist, err := MarshalDERSMAdditionalDispatcherList(v.AdditionalDispatcherList)
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
		return nil, fmt.Errorf("encoding SMMTForwardSMVGCSRes as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes SMMTForwardSMVGCSRes from BER/DER format.
func (v *SMMTForwardSMVGCSRes) UnmarshalBER(data []byte) error {
	*v = SMMTForwardSMVGCSRes{}
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding SMMTForwardSMVGCSRes SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "SMMTForwardSMVGCSRes", Cause: ber.ErrExtraData}
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
				tmp_smrpui := SignalInfo4(rawVal_smrpui)
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
				dec_dispatcherlist, unmErr := UnmarshalBERSMDispatcherList(reconstructed_dispatcherlist)
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
				var dec_extensioncontainer ExtensionContainer4
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
				dec_additionaldispatcherlist, unmErr := UnmarshalBERSMAdditionalDispatcherList(reconstructed_additionaldispatcherlist)
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
			return &ber.DecodeError{Offset: offset, TypeName: "SMMTForwardSMVGCSRes", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBERSMDispatcherList encodes a SMDispatcherList list to BER.
func MarshalBERSMDispatcherList(list SMDispatcherList) ([]byte, error) {
	if len(list) < 1 || len(list) > 5 {
		return nil, fmt.Errorf("SMDispatcherList length %d violates SIZE (1..5)", len(list))
	}
	var children []byte
	for _, elem := range list {
		children = append(children, ber.EncodeOctetString([]byte(elem))...)
	}
	return ber.EncodeSequence(children), nil
}

// MarshalDERSMDispatcherList encodes a SMDispatcherList list to DER.
func MarshalDERSMDispatcherList(list SMDispatcherList) ([]byte, error) {
	if len(list) < 1 || len(list) > 5 {
		return nil, fmt.Errorf("SMDispatcherList length %d violates SIZE (1..5)", len(list))
	}
	var children []byte
	for _, elem := range list {
		children = append(children, ber.EncodeOctetString([]byte(elem))...)
	}
	encoded := ber.EncodeSequence(children)
	if err := ber.ValidateDERElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding SMDispatcherList as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBERSMDispatcherList decodes a SMDispatcherList list from BER.
func UnmarshalBERSMDispatcherList(data []byte) (SMDispatcherList, error) {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return nil, fmt.Errorf("decoding SMDispatcherList: %w", err)
	}
	if total != len(data) {
		return nil, &ber.DecodeError{Offset: total, TypeName: "SMDispatcherList", Cause: ber.ErrExtraData}
	}
	var result SMDispatcherList
	offset := 0
	for offset < len(content) {
		val, n, osErr := ber.DecodeOctetString(content[offset:])
		if osErr != nil {
			return nil, fmt.Errorf("decoding element: %w", osErr)
		}
		result = append(result, ISDNAddressString4(val))
		offset += n
		if len(result) > 5 {
			return nil, fmt.Errorf("SMDispatcherList length %d violates SIZE (1..5)", len(result))
		}
	}
	if len(result) < 1 || len(result) > 5 {
		return nil, fmt.Errorf("SMDispatcherList length %d violates SIZE (1..5)", len(result))
	}
	return result, nil
}

// MarshalBERSMAdditionalDispatcherList encodes a SMAdditionalDispatcherList list to BER.
func MarshalBERSMAdditionalDispatcherList(list SMAdditionalDispatcherList) ([]byte, error) {
	if len(list) < 1 || len(list) > 15 {
		return nil, fmt.Errorf("SMAdditionalDispatcherList length %d violates SIZE (1..15)", len(list))
	}
	var children []byte
	for _, elem := range list {
		children = append(children, ber.EncodeOctetString([]byte(elem))...)
	}
	return ber.EncodeSequence(children), nil
}

// MarshalDERSMAdditionalDispatcherList encodes a SMAdditionalDispatcherList list to DER.
func MarshalDERSMAdditionalDispatcherList(list SMAdditionalDispatcherList) ([]byte, error) {
	if len(list) < 1 || len(list) > 15 {
		return nil, fmt.Errorf("SMAdditionalDispatcherList length %d violates SIZE (1..15)", len(list))
	}
	var children []byte
	for _, elem := range list {
		children = append(children, ber.EncodeOctetString([]byte(elem))...)
	}
	encoded := ber.EncodeSequence(children)
	if err := ber.ValidateDERElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding SMAdditionalDispatcherList as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBERSMAdditionalDispatcherList decodes a SMAdditionalDispatcherList list from BER.
func UnmarshalBERSMAdditionalDispatcherList(data []byte) (SMAdditionalDispatcherList, error) {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return nil, fmt.Errorf("decoding SMAdditionalDispatcherList: %w", err)
	}
	if total != len(data) {
		return nil, &ber.DecodeError{Offset: total, TypeName: "SMAdditionalDispatcherList", Cause: ber.ErrExtraData}
	}
	var result SMAdditionalDispatcherList
	offset := 0
	for offset < len(content) {
		val, n, osErr := ber.DecodeOctetString(content[offset:])
		if osErr != nil {
			return nil, fmt.Errorf("decoding element: %w", osErr)
		}
		result = append(result, ISDNAddressString4(val))
		offset += n
		if len(result) > 15 {
			return nil, fmt.Errorf("SMAdditionalDispatcherList length %d violates SIZE (1..15)", len(result))
		}
	}
	if len(result) < 1 || len(result) > 15 {
		return nil, fmt.Errorf("SMAdditionalDispatcherList length %d violates SIZE (1..15)", len(result))
	}
	return result, nil
}
