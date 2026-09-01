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

	// SMMaxNumOfDispatchers is the integer constant for SMMaxNumOfDispatchers.
	SMMaxNumOfDispatchers int64 = 5

	// SMMaxNumOfAdditionalDispatchers is the integer constant for SMMaxNumOfAdditionalDispatchers.
	SMMaxNumOfAdditionalDispatchers int64 = 15
)

// SMRoutingInfoForSMArg represents the ASN.1 type SMRoutingInfoForSMArg (SEQUENCE).
type SMRoutingInfoForSMArg struct {
	Msisdn                  ISDNAddressString3       `asn1:"tag:0,context,implicit"`
	SmRPPRI                 bool                     `asn1:"tag:1,context,implicit"`
	SmRPPRIRaw_             byte                     `asn1:"-" json:"-"`
	ServiceCentreAddress    AddressString3           `asn1:"tag:2,context,implicit"`
	ExtensionContainer      *ExtensionContainer3     `asn1:"tag:6,context,implicit,optional" json:"ExtensionContainer,omitempty"`
	GprsSupportIndicator    *struct{}                `asn1:"tag:7,context,implicit,optional" json:"GprsSupportIndicator,omitempty"`
	SmRPMTI                 *SMSMRPMTI               `asn1:"tag:8,context,implicit,optional" json:"SmRPMTI,omitempty"`
	SmRPSMEA                *SMSMRPSMEA              `asn1:"tag:9,context,implicit,optional" json:"SmRPSMEA,omitempty"`
	SmDeliveryNotIntended   *SMSMDeliveryNotIntended `asn1:"tag:10,context,implicit,optional" json:"SmDeliveryNotIntended,omitempty"`
	IpSmGwGuidanceIndicator *struct{}                `asn1:"tag:11,context,implicit,optional" json:"IpSmGwGuidanceIndicator,omitempty"`
	Imsi                    *IMSI3                   `asn1:"tag:12,context,implicit,optional" json:"Imsi,omitempty"`
	T4TriggerIndicator      *struct{}                `asn1:"tag:14,context,implicit,optional" json:"T4TriggerIndicator,omitempty"`
	SingleAttemptDelivery   *struct{}                `asn1:"tag:13,context,implicit,optional" json:"SingleAttemptDelivery,omitempty"`
	CorrelationID           *SMCorrelationID         `asn1:"tag:15,context,implicit,optional" json:"CorrelationID,omitempty"`
	ExtCount_               int64                    `asn1:"-" json:"-"`
	ExtPresent_             []bool                   `asn1:"-" json:"-"`
	ExtData_                [][]byte                 `asn1:"-" json:"-"`
}

// SMSMDeliveryNotIntended represents the ASN.1 ENUMERATED type SMSMDeliveryNotIntended.
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

// SMSMRPMTI represents the ASN.1 type SMSMRPMTI (INTEGER).
type SMSMRPMTI = int64

// SMSMRPSMEA represents the ASN.1 type SMSMRPSMEA (OCTET_STRING).
type SMSMRPSMEA = []byte

// SMRoutingInfoForSMRes represents the ASN.1 type SMRoutingInfoForSMRes (SEQUENCE).
type SMRoutingInfoForSMRes struct {
	Imsi                 IMSI3                  `asn1:""`
	LocationInfoWithLMSI SMLocationInfoWithLMSI `asn1:"tag:0,context,implicit"`
	ExtensionContainer   *ExtensionContainer3   `asn1:"tag:4,context,implicit,optional" json:"ExtensionContainer,omitempty"`
	IpSmGwGuidance       *SMIPSMGWGuidance      `asn1:"tag:5,context,implicit,optional" json:"IpSmGwGuidance,omitempty"`
	ExtCount_            int64                  `asn1:"-" json:"-"`
	ExtPresent_          []bool                 `asn1:"-" json:"-"`
	ExtData_             [][]byte               `asn1:"-" json:"-"`
}

// SMIPSMGWGuidance represents the ASN.1 type SMIPSMGWGuidance (SEQUENCE).
type SMIPSMGWGuidance struct {
	MinimumDeliveryTimeValue     SMSMDeliveryTimerValue `asn1:""`
	RecommendedDeliveryTimeValue SMSMDeliveryTimerValue `asn1:""`
	ExtensionContainer           *ExtensionContainer3   `asn1:",optional" json:"ExtensionContainer,omitempty"`
	ExtCount_                    int64                  `asn1:"-" json:"-"`
	ExtPresent_                  []bool                 `asn1:"-" json:"-"`
	ExtData_                     [][]byte               `asn1:"-" json:"-"`
}

// SMLocationInfoWithLMSI represents the ASN.1 type SMLocationInfoWithLMSI (SEQUENCE).
type SMLocationInfoWithLMSI struct {
	NetworkNodeNumber                    ISDNAddressString3                         `asn1:"tag:1,context,implicit"`
	Lmsi                                 *LMSI3                                     `asn1:",optional" json:"Lmsi,omitempty"`
	ExtensionContainer                   *ExtensionContainer3                       `asn1:",optional" json:"ExtensionContainer,omitempty"`
	GprsNodeIndicator                    *struct{}                                  `asn1:"tag:5,context,implicit,optional" json:"GprsNodeIndicator,omitempty"`
	AdditionalNumber                     *SMAdditionalNumber                        `asn1:"tag:6,context,explicit,optional" json:"AdditionalNumber,omitempty"`
	NetworkNodeDiameterAddress           *CommonDataTypesNetworkNodeDiameterAddress `asn1:"tag:7,context,implicit,optional" json:"NetworkNodeDiameterAddress,omitempty"`
	AdditionalNetworkNodeDiameterAddress *CommonDataTypesNetworkNodeDiameterAddress `asn1:"tag:8,context,implicit,optional" json:"AdditionalNetworkNodeDiameterAddress,omitempty"`
	ThirdNumber                          *SMAdditionalNumber                        `asn1:"tag:9,context,explicit,optional" json:"ThirdNumber,omitempty"`
	ThirdNetworkNodeDiameterAddress      *CommonDataTypesNetworkNodeDiameterAddress `asn1:"tag:10,context,implicit,optional" json:"ThirdNetworkNodeDiameterAddress,omitempty"`
	ImsNodeIndicator                     *struct{}                                  `asn1:"tag:11,context,implicit,optional" json:"ImsNodeIndicator,omitempty"`
	ExtCount_                            int64                                      `asn1:"-" json:"-"`
	ExtPresent_                          []bool                                     `asn1:"-" json:"-"`
	ExtData_                             [][]byte                                   `asn1:"-" json:"-"`
}

// SMAdditionalNumber choice constants.
const (
	SMAdditionalNumberChoiceMscNumber  = 1
	SMAdditionalNumberChoiceSgsnNumber = 2
)

// SMAdditionalNumber represents the ASN.1 CHOICE type SMAdditionalNumber.
type SMAdditionalNumber struct {
	Choice     int
	MscNumber  *ISDNAddressString3 `json:"MscNumber,omitempty"`
	SgsnNumber *ISDNAddressString3 `json:"SgsnNumber,omitempty"`
}

// NewSMAdditionalNumberMscNumber creates a SMAdditionalNumber with the msc-Number alternative.
func NewSMAdditionalNumberMscNumber(v ISDNAddressString3) SMAdditionalNumber {
	return SMAdditionalNumber{
		Choice:    SMAdditionalNumberChoiceMscNumber,
		MscNumber: &v,
	}
}

// NewSMAdditionalNumberSgsnNumber creates a SMAdditionalNumber with the sgsn-Number alternative.
func NewSMAdditionalNumberSgsnNumber(v ISDNAddressString3) SMAdditionalNumber {
	return SMAdditionalNumber{
		Choice:     SMAdditionalNumberChoiceSgsnNumber,
		SgsnNumber: &v,
	}
}

// SMMOForwardSMArg represents the ASN.1 type SMMOForwardSMArg (SEQUENCE).
type SMMOForwardSMArg struct {
	SmRPDA             SMSMRPDA             `asn1:""`
	SmRPOA             SMSMRPOA             `asn1:""`
	SmRPUI             SignalInfo3          `asn1:""`
	ExtensionContainer *ExtensionContainer3 `asn1:",optional" json:"ExtensionContainer,omitempty"`
	Imsi               *IMSI3               `asn1:",optional" json:"Imsi,omitempty"`
	CorrelationID      *SMCorrelationID     `asn1:"tag:0,context,implicit,optional" json:"CorrelationID,omitempty"`
	SmDeliveryOutcome  *SMSMDeliveryOutcome `asn1:"tag:1,context,implicit,optional" json:"SmDeliveryOutcome,omitempty"`
	ExtCount_          int64                `asn1:"-" json:"-"`
	ExtPresent_        []bool               `asn1:"-" json:"-"`
	ExtData_           [][]byte             `asn1:"-" json:"-"`
}

// SMMOForwardSMRes represents the ASN.1 type SMMOForwardSMRes (SEQUENCE).
type SMMOForwardSMRes struct {
	SmRPUI             *SignalInfo3         `asn1:",optional" json:"SmRPUI,omitempty"`
	ExtensionContainer *ExtensionContainer3 `asn1:",optional" json:"ExtensionContainer,omitempty"`
	ExtCount_          int64                `asn1:"-" json:"-"`
	ExtPresent_        []bool               `asn1:"-" json:"-"`
	ExtData_           [][]byte             `asn1:"-" json:"-"`
}

// SMMTForwardSMArg represents the ASN.1 type SMMTForwardSMArg (SEQUENCE).
type SMMTForwardSMArg struct {
	SmRPDA                 SMSMRPDA                `asn1:""`
	SmRPOA                 SMSMRPOA                `asn1:""`
	SmRPUI                 SignalInfo3             `asn1:""`
	MoreMessagesToSend     *struct{}               `asn1:",optional" json:"MoreMessagesToSend,omitempty"`
	ExtensionContainer     *ExtensionContainer3    `asn1:",optional" json:"ExtensionContainer,omitempty"`
	SmDeliveryTimer        *SMSMDeliveryTimerValue `asn1:",optional" json:"SmDeliveryTimer,omitempty"`
	SmDeliveryStartTime    *CommonDataTypesTime    `asn1:",optional" json:"SmDeliveryStartTime,omitempty"`
	SmsOverIPOnlyIndicator *struct{}               `asn1:"tag:0,context,implicit,optional" json:"SmsOverIPOnlyIndicator,omitempty"`
	CorrelationID          *SMCorrelationID        `asn1:"tag:1,context,implicit,optional" json:"CorrelationID,omitempty"`
	ExtCount_              int64                   `asn1:"-" json:"-"`
	ExtPresent_            []bool                  `asn1:"-" json:"-"`
	ExtData_               [][]byte                `asn1:"-" json:"-"`
}

// SMCorrelationID represents the ASN.1 type SMCorrelationID (SEQUENCE).
type SMCorrelationID struct {
	HlrId   *HLRId3   `asn1:"tag:0,context,implicit,optional" json:"HlrId,omitempty"`
	SipUriA *SMSIPURI `asn1:"tag:1,context,implicit,optional" json:"SipUriA,omitempty"`
	SipUriB SMSIPURI  `asn1:"tag:2,context,implicit"`
}

// SMSIPURI represents the ASN.1 type SMSIPURI (OCTET_STRING).
type SMSIPURI = []byte

// SMMTForwardSMRes represents the ASN.1 type SMMTForwardSMRes (SEQUENCE).
type SMMTForwardSMRes struct {
	SmRPUI             *SignalInfo3         `asn1:",optional" json:"SmRPUI,omitempty"`
	ExtensionContainer *ExtensionContainer3 `asn1:",optional" json:"ExtensionContainer,omitempty"`
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

// SMSMRPDA represents the ASN.1 CHOICE type SMSMRPDA.
type SMSMRPDA struct {
	Choice                 int
	Imsi                   *IMSI3          `json:"Imsi,omitempty"`
	Lmsi                   *LMSI3          `json:"Lmsi,omitempty"`
	ServiceCentreAddressDA *AddressString3 `json:"ServiceCentreAddressDA,omitempty"`
	NoSMRPDA               *struct{}       `json:"NoSMRPDA,omitempty"`
}

// NewSMSMRPDAImsi creates a SMSMRPDA with the imsi alternative.
func NewSMSMRPDAImsi(v IMSI3) SMSMRPDA {
	return SMSMRPDA{
		Choice: SMSMRPDAChoiceImsi,
		Imsi:   &v,
	}
}

// NewSMSMRPDALmsi creates a SMSMRPDA with the lmsi alternative.
func NewSMSMRPDALmsi(v LMSI3) SMSMRPDA {
	return SMSMRPDA{
		Choice: SMSMRPDAChoiceLmsi,
		Lmsi:   &v,
	}
}

// NewSMSMRPDAServiceCentreAddressDA creates a SMSMRPDA with the serviceCentreAddressDA alternative.
func NewSMSMRPDAServiceCentreAddressDA(v AddressString3) SMSMRPDA {
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

// SMSMRPOA represents the ASN.1 CHOICE type SMSMRPOA.
type SMSMRPOA struct {
	Choice                 int
	Msisdn                 *ISDNAddressString3 `json:"Msisdn,omitempty"`
	ServiceCentreAddressOA *AddressString3     `json:"ServiceCentreAddressOA,omitempty"`
	NoSMRPOA               *struct{}           `json:"NoSMRPOA,omitempty"`
}

// NewSMSMRPOAMsisdn creates a SMSMRPOA with the msisdn alternative.
func NewSMSMRPOAMsisdn(v ISDNAddressString3) SMSMRPOA {
	return SMSMRPOA{
		Choice: SMSMRPOAChoiceMsisdn,
		Msisdn: &v,
	}
}

// NewSMSMRPOAServiceCentreAddressOA creates a SMSMRPOA with the serviceCentreAddressOA alternative.
func NewSMSMRPOAServiceCentreAddressOA(v AddressString3) SMSMRPOA {
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

// SMSMDeliveryTimerValue represents the ASN.1 type SMSMDeliveryTimerValue (INTEGER).
type SMSMDeliveryTimerValue = int64

// SMReportSMDeliveryStatusArg represents the ASN.1 type SMReportSMDeliveryStatusArg (SEQUENCE).
type SMReportSMDeliveryStatusArg struct {
	Msisdn                                 ISDNAddressString3             `asn1:""`
	ServiceCentreAddress                   AddressString3                 `asn1:""`
	SmDeliveryOutcome                      SMSMDeliveryOutcome            `asn1:""`
	AbsentSubscriberDiagnosticSM           *AbsentSubscriberDiagnosticSM3 `asn1:"tag:0,context,implicit,optional" json:"AbsentSubscriberDiagnosticSM,omitempty"`
	ExtensionContainer                     *ExtensionContainer3           `asn1:"tag:1,context,implicit,optional" json:"ExtensionContainer,omitempty"`
	GprsSupportIndicator                   *struct{}                      `asn1:"tag:2,context,implicit,optional" json:"GprsSupportIndicator,omitempty"`
	DeliveryOutcomeIndicator               *struct{}                      `asn1:"tag:3,context,implicit,optional" json:"DeliveryOutcomeIndicator,omitempty"`
	AdditionalSMDeliveryOutcome            *SMSMDeliveryOutcome           `asn1:"tag:4,context,implicit,optional" json:"AdditionalSMDeliveryOutcome,omitempty"`
	AdditionalAbsentSubscriberDiagnosticSM *AbsentSubscriberDiagnosticSM3 `asn1:"tag:5,context,implicit,optional" json:"AdditionalAbsentSubscriberDiagnosticSM,omitempty"`
	IpSmGwIndicator                        *struct{}                      `asn1:"tag:6,context,implicit,optional" json:"IpSmGwIndicator,omitempty"`
	IpSmGwSmDeliveryOutcome                *SMSMDeliveryOutcome           `asn1:"tag:7,context,implicit,optional" json:"IpSmGwSmDeliveryOutcome,omitempty"`
	IpSmGwAbsentSubscriberDiagnosticSM     *AbsentSubscriberDiagnosticSM3 `asn1:"tag:8,context,implicit,optional" json:"IpSmGwAbsentSubscriberDiagnosticSM,omitempty"`
	Imsi                                   *IMSI3                         `asn1:"tag:9,context,implicit,optional" json:"Imsi,omitempty"`
	SingleAttemptDelivery                  *struct{}                      `asn1:"tag:10,context,implicit,optional" json:"SingleAttemptDelivery,omitempty"`
	CorrelationID                          *SMCorrelationID               `asn1:"tag:11,context,implicit,optional" json:"CorrelationID,omitempty"`
	ExtCount_                              int64                          `asn1:"-" json:"-"`
	ExtPresent_                            []bool                         `asn1:"-" json:"-"`
	ExtData_                               [][]byte                       `asn1:"-" json:"-"`
}

// SMSMDeliveryOutcome represents the ASN.1 ENUMERATED type SMSMDeliveryOutcome.
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

// SMReportSMDeliveryStatusRes represents the ASN.1 type SMReportSMDeliveryStatusRes (SEQUENCE).
type SMReportSMDeliveryStatusRes struct {
	StoredMSISDN       *ISDNAddressString3  `asn1:",optional" json:"StoredMSISDN,omitempty"`
	ExtensionContainer *ExtensionContainer3 `asn1:",optional" json:"ExtensionContainer,omitempty"`
	ExtCount_          int64                `asn1:"-" json:"-"`
	ExtPresent_        []bool               `asn1:"-" json:"-"`
	ExtData_           [][]byte             `asn1:"-" json:"-"`
}

// SMAlertServiceCentreArg represents the ASN.1 type SMAlertServiceCentreArg (SEQUENCE).
type SMAlertServiceCentreArg struct {
	Msisdn               ISDNAddressString3 `asn1:""`
	ServiceCentreAddress AddressString3     `asn1:""`
	Imsi                 *IMSI3             `asn1:",optional" json:"Imsi,omitempty"`
	CorrelationID        *SMCorrelationID   `asn1:",optional" json:"CorrelationID,omitempty"`
	ExtCount_            int64              `asn1:"-" json:"-"`
	ExtPresent_          []bool             `asn1:"-" json:"-"`
	ExtData_             [][]byte           `asn1:"-" json:"-"`
}

// SMInformServiceCentreArg represents the ASN.1 type SMInformServiceCentreArg (SEQUENCE).
type SMInformServiceCentreArg struct {
	StoredMSISDN                           *ISDNAddressString3            `asn1:",optional" json:"StoredMSISDN,omitempty"`
	MwStatus                               *SMMWStatus                    `asn1:",optional" json:"MwStatus,omitempty"`
	ExtensionContainer                     *ExtensionContainer3           `asn1:",optional" json:"ExtensionContainer,omitempty"`
	AbsentSubscriberDiagnosticSM           *AbsentSubscriberDiagnosticSM3 `asn1:",optional" json:"AbsentSubscriberDiagnosticSM,omitempty"`
	AdditionalAbsentSubscriberDiagnosticSM *AbsentSubscriberDiagnosticSM3 `asn1:"tag:0,context,implicit,optional" json:"AdditionalAbsentSubscriberDiagnosticSM,omitempty"`
	ExtCount_                              int64                          `asn1:"-" json:"-"`
	ExtPresent_                            []bool                         `asn1:"-" json:"-"`
	ExtData_                               [][]byte                       `asn1:"-" json:"-"`
}

// SMMWStatus represents the ASN.1 type SMMWStatus (BIT_STRING).
type SMMWStatus = runtime.BitString

// SMReadyForSMArg represents the ASN.1 type SMReadyForSMArg (SEQUENCE).
type SMReadyForSMArg struct {
	Imsi                           IMSI3                `asn1:"tag:0,context,implicit"`
	AlertReason                    SMAlertReason        `asn1:""`
	AlertReasonIndicator           *struct{}            `asn1:",optional" json:"AlertReasonIndicator,omitempty"`
	ExtensionContainer             *ExtensionContainer3 `asn1:",optional" json:"ExtensionContainer,omitempty"`
	AdditionalAlertReasonIndicator *struct{}            `asn1:"tag:1,context,implicit,optional" json:"AdditionalAlertReasonIndicator,omitempty"`
	ExtCount_                      int64                `asn1:"-" json:"-"`
	ExtPresent_                    []bool               `asn1:"-" json:"-"`
	ExtData_                       [][]byte             `asn1:"-" json:"-"`
}

// SMReadyForSMRes represents the ASN.1 type SMReadyForSMRes (SEQUENCE).
type SMReadyForSMRes struct {
	ExtensionContainer *ExtensionContainer3 `asn1:",optional" json:"ExtensionContainer,omitempty"`
	ExtCount_          int64                `asn1:"-" json:"-"`
	ExtPresent_        []bool               `asn1:"-" json:"-"`
	ExtData_           [][]byte             `asn1:"-" json:"-"`
}

// SMAlertReason represents the ASN.1 ENUMERATED type SMAlertReason.
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

// SMMTForwardSMVGCSArg represents the ASN.1 type SMMTForwardSMVGCSArg (SEQUENCE).
type SMMTForwardSMVGCSArg struct {
	AsciCallReference  ASCICallReference3   `asn1:""`
	SmRPOA             SMSMRPOA             `asn1:""`
	SmRPUI             SignalInfo3          `asn1:""`
	ExtensionContainer *ExtensionContainer3 `asn1:",optional" json:"ExtensionContainer,omitempty"`
	ExtCount_          int64                `asn1:"-" json:"-"`
	ExtPresent_        []bool               `asn1:"-" json:"-"`
	ExtData_           [][]byte             `asn1:"-" json:"-"`
}

// SMMTForwardSMVGCSRes represents the ASN.1 type SMMTForwardSMVGCSRes (SEQUENCE).
type SMMTForwardSMVGCSRes struct {
	SmRPUI                         *SignalInfo3               `asn1:"tag:0,context,implicit,optional" json:"SmRPUI,omitempty"`
	DispatcherList                 SMDispatcherList           `asn1:"tag:1,context,implicit,optional" json:"DispatcherList,omitempty"`
	DispatcherListIndef_           bool                       `asn1:"-" json:"-"`
	OngoingCall                    *struct{}                  `asn1:",optional" json:"OngoingCall,omitempty"`
	ExtensionContainer             *ExtensionContainer3       `asn1:"tag:2,context,implicit,optional" json:"ExtensionContainer,omitempty"`
	AdditionalDispatcherList       SMAdditionalDispatcherList `asn1:"tag:3,context,implicit,optional" json:"AdditionalDispatcherList,omitempty"`
	AdditionalDispatcherListIndef_ bool                       `asn1:"-" json:"-"`
	ExtCount_                      int64                      `asn1:"-" json:"-"`
	ExtPresent_                    []bool                     `asn1:"-" json:"-"`
	ExtData_                       [][]byte                   `asn1:"-" json:"-"`
}

// SMDispatcherList represents the ASN.1 type SMDispatcherList (SEQUENCE_OF).
type SMDispatcherList = []ISDNAddressString3

// SMAdditionalDispatcherList represents the ASN.1 type SMAdditionalDispatcherList (SEQUENCE_OF).
type SMAdditionalDispatcherList = []ISDNAddressString3

// MarshalBER encodes SMRoutingInfoForSMArg to BER format.
func (v *SMRoutingInfoForSMArg) MarshalBER() ([]byte, error) {
	var children []byte
	enc_msisdn := ber.EncodeOctetString([]byte(v.Msisdn))
	enc_msisdn = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, false, enc_msisdn)
	children = append(children, enc_msisdn...)
	var enc_smrppri []byte
	if v.SmRPPRIRaw_ != 0 {
		enc_smrppri = ber.EncodeBooleanRaw(v.SmRPPRIRaw_)
	} else {
		enc_smrppri = ber.EncodeBoolean(v.SmRPPRI)
	}
	enc_smrppri = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, false, enc_smrppri)
	children = append(children, enc_smrppri...)
	enc_servicecentreaddress := ber.EncodeOctetString([]byte(v.ServiceCentreAddress))
	enc_servicecentreaddress = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, false, enc_servicecentreaddress)
	children = append(children, enc_servicecentreaddress...)
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding extensionContainer: %w", err)
		}
		enc_extensioncontainer = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 6, true, enc_extensioncontainer)
		children = append(children, enc_extensioncontainer...)
	}
	if v.GprsSupportIndicator != nil {
		enc_gprssupportindicator := ber.EncodeNull()
		enc_gprssupportindicator = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 7, false, enc_gprssupportindicator)
		children = append(children, enc_gprssupportindicator...)
	}
	if v.SmRPMTI != nil {
		enc_smrpmti := ber.EncodeInteger(int64(*v.SmRPMTI))
		enc_smrpmti = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 8, false, enc_smrpmti)
		children = append(children, enc_smrpmti...)
	}
	if v.SmRPSMEA != nil {
		enc_smrpsmea := ber.EncodeOctetString([]byte(*v.SmRPSMEA))
		enc_smrpsmea = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 9, false, enc_smrpsmea)
		children = append(children, enc_smrpsmea...)
	}
	if v.SmDeliveryNotIntended != nil {
		enc_smdeliverynotintended := ber.EncodeEnumerated(int64(*v.SmDeliveryNotIntended))
		enc_smdeliverynotintended = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 10, false, enc_smdeliverynotintended)
		children = append(children, enc_smdeliverynotintended...)
	}
	if v.IpSmGwGuidanceIndicator != nil {
		enc_ipsmgwguidanceindicator := ber.EncodeNull()
		enc_ipsmgwguidanceindicator = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 11, false, enc_ipsmgwguidanceindicator)
		children = append(children, enc_ipsmgwguidanceindicator...)
	}
	if v.Imsi != nil {
		enc_imsi := ber.EncodeOctetString([]byte(*v.Imsi))
		enc_imsi = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 12, false, enc_imsi)
		children = append(children, enc_imsi...)
	}
	if v.T4TriggerIndicator != nil {
		enc_t4triggerindicator := ber.EncodeNull()
		enc_t4triggerindicator = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 14, false, enc_t4triggerindicator)
		children = append(children, enc_t4triggerindicator...)
	}
	if v.SingleAttemptDelivery != nil {
		enc_singleattemptdelivery := ber.EncodeNull()
		enc_singleattemptdelivery = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 13, false, enc_singleattemptdelivery)
		children = append(children, enc_singleattemptdelivery...)
	}
	if v.CorrelationID != nil {
		enc_correlationid, err := v.CorrelationID.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding correlationID: %w", err)
		}
		enc_correlationid = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 15, true, enc_correlationid)
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
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes SMRoutingInfoForSMArg from BER/DER format.
func (v *SMRoutingInfoForSMArg) UnmarshalBER(data []byte) error {
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
	_, n_msisdn, rawVal_msisdn, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding msisdn: %w", err)
	}
	v.Msisdn = ISDNAddressString3(rawVal_msisdn)
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
	_, n_smrppri, rawVal_smrppri, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding sm-RP-PRI: %w", err)
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
	_, n_servicecentreaddress, rawVal_servicecentreaddress, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding serviceCentreAddress: %w", err)
	}
	v.ServiceCentreAddress = AddressString3(rawVal_servicecentreaddress)
	offset += n_servicecentreaddress
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
				var dec_extensioncontainer ExtensionContainer3
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
				_, n_gprssupportindicator, rawVal_gprssupportindicator, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding gprsSupportIndicator: %w", err)
				}
				_ = rawVal_gprssupportindicator
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
				_, n_smrpmti, rawVal_smrpmti, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding sm-RP-MTI: %w", err)
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
				_, n_smrpsmea, rawVal_smrpsmea, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding sm-RP-SMEA: %w", err)
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
				_, n_smdeliverynotintended, rawVal_smdeliverynotintended, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding sm-deliveryNotIntended: %w", err)
				}
				decVal_smdeliverynotintended, intErr := ber.DecodeIntegerValue(rawVal_smdeliverynotintended)
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
				_, n_ipsmgwguidanceindicator, rawVal_ipsmgwguidanceindicator, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding ip-sm-gwGuidanceIndicator: %w", err)
				}
				_ = rawVal_ipsmgwguidanceindicator
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
				_, n_imsi, rawVal_imsi, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding imsi: %w", err)
				}
				tmp_imsi := IMSI3(rawVal_imsi)
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
				_, n_t4triggerindicator, rawVal_t4triggerindicator, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding t4-Trigger-Indicator: %w", err)
				}
				_ = rawVal_t4triggerindicator
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
				_, n_singleattemptdelivery, rawVal_singleattemptdelivery, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding singleAttemptDelivery: %w", err)
				}
				_ = rawVal_singleattemptdelivery
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
				_, n_correlationid, rawVal_correlationid, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding correlationID: %w", err)
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
	enc_locationinfowithlmsi = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, true, enc_locationinfowithlmsi)
	children = append(children, enc_locationinfowithlmsi...)
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding extensionContainer: %w", err)
		}
		enc_extensioncontainer = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, true, enc_extensioncontainer)
		children = append(children, enc_extensioncontainer...)
	}
	if v.IpSmGwGuidance != nil {
		enc_ipsmgwguidance, err := v.IpSmGwGuidance.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding ip-sm-gwGuidance: %w", err)
		}
		enc_ipsmgwguidance = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 5, true, enc_ipsmgwguidance)
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
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes SMRoutingInfoForSMRes from BER/DER format.
func (v *SMRoutingInfoForSMRes) UnmarshalBER(data []byte) error {
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
	v.Imsi = IMSI3(val_imsi)
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
	_, n_locationinfowithlmsi, rawVal_locationinfowithlmsi, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding locationInfoWithLMSI: %w", err)
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
				_, n_extensioncontainer, rawVal_extensioncontainer, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding extensionContainer: %w", err)
				}
				reconstructed_extensioncontainer := ber.EncodeSequence(rawVal_extensioncontainer)
				var dec_extensioncontainer ExtensionContainer3
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
				_, n_ipsmgwguidance, rawVal_ipsmgwguidance, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding ip-sm-gwGuidance: %w", err)
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
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes SMIPSMGWGuidance from BER/DER format.
func (v *SMIPSMGWGuidance) UnmarshalBER(data []byte) error {
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
				// Decode nested SEQUENCE (ExtensionContainer3)
				_, n_extensioncontainer, _, tlvErr_extensioncontainer := ber.DecodeTLV(content[offset:])
				if tlvErr_extensioncontainer != nil {
					return fmt.Errorf("decoding extensionContainer: %w", tlvErr_extensioncontainer)
				}
				var dec_extensioncontainer ExtensionContainer3
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
	enc_networknodenumber = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, false, enc_networknodenumber)
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
		enc_gprsnodeindicator = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 5, false, enc_gprsnodeindicator)
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
		enc_networknodediameteraddress = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 7, true, enc_networknodediameteraddress)
		children = append(children, enc_networknodediameteraddress...)
	}
	if v.AdditionalNetworkNodeDiameterAddress != nil {
		enc_additionalnetworknodediameteraddress, err := v.AdditionalNetworkNodeDiameterAddress.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding additionalNetworkNodeDiameterAddress: %w", err)
		}
		enc_additionalnetworknodediameteraddress = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 8, true, enc_additionalnetworknodediameteraddress)
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
		enc_thirdnetworknodediameteraddress = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 10, true, enc_thirdnetworknodediameteraddress)
		children = append(children, enc_thirdnetworknodediameteraddress...)
	}
	if v.ImsNodeIndicator != nil {
		enc_imsnodeindicator := ber.EncodeNull()
		enc_imsnodeindicator = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 11, false, enc_imsnodeindicator)
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
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes SMLocationInfoWithLMSI from BER/DER format.
func (v *SMLocationInfoWithLMSI) UnmarshalBER(data []byte) error {
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
	_, n_networknodenumber, rawVal_networknodenumber, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding networkNode-Number: %w", err)
	}
	v.NetworkNodeNumber = ISDNAddressString3(rawVal_networknodenumber)
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
				tmp_lmsi := LMSI3(val_lmsi)
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
				// Decode nested SEQUENCE (ExtensionContainer3)
				_, n_extensioncontainer, _, tlvErr_extensioncontainer := ber.DecodeTLV(content[offset:])
				if tlvErr_extensioncontainer != nil {
					return fmt.Errorf("decoding extensionContainer: %w", tlvErr_extensioncontainer)
				}
				var dec_extensioncontainer ExtensionContainer3
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
				_, n_gprsnodeindicator, rawVal_gprsnodeindicator, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding gprsNodeIndicator: %w", err)
				}
				_ = rawVal_gprsnodeindicator
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
				_, n_additionalnumber, innerData_additionalnumber, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding additional-Number: %w", err)
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
				_, n_networknodediameteraddress, rawVal_networknodediameteraddress, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding networkNodeDiameterAddress: %w", err)
				}
				reconstructed_networknodediameteraddress := ber.EncodeSequence(rawVal_networknodediameteraddress)
				var dec_networknodediameteraddress CommonDataTypesNetworkNodeDiameterAddress
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
				_, n_additionalnetworknodediameteraddress, rawVal_additionalnetworknodediameteraddress, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding additionalNetworkNodeDiameterAddress: %w", err)
				}
				reconstructed_additionalnetworknodediameteraddress := ber.EncodeSequence(rawVal_additionalnetworknodediameteraddress)
				var dec_additionalnetworknodediameteraddress CommonDataTypesNetworkNodeDiameterAddress
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
				_, n_thirdnumber, innerData_thirdnumber, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding thirdNumber: %w", err)
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
				_, n_thirdnetworknodediameteraddress, rawVal_thirdnetworknodediameteraddress, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding thirdNetworkNodeDiameterAddress: %w", err)
				}
				reconstructed_thirdnetworknodediameteraddress := ber.EncodeSequence(rawVal_thirdnetworknodediameteraddress)
				var dec_thirdnetworknodediameteraddress CommonDataTypesNetworkNodeDiameterAddress
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
				_, n_imsnodeindicator, rawVal_imsnodeindicator, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding imsNodeIndicator: %w", err)
				}
				_ = rawVal_imsnodeindicator
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
		enc_0 := ber.EncodeOctetString([]byte(*v.MscNumber))
		enc_0 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, false, enc_0)
		return enc_0, nil
	case SMAdditionalNumberChoiceSgsnNumber:
		enc_1 := ber.EncodeOctetString([]byte(*v.SgsnNumber))
		enc_1 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, false, enc_1)
		return enc_1, nil
	default:
		return nil, fmt.Errorf("unknown choice %d for SMAdditionalNumber", v.Choice)
	}
}

// MarshalDER encodes SMAdditionalNumber to DER format.
func (v *SMAdditionalNumber) MarshalDER() ([]byte, error) {
	return v.MarshalBER()
}

// UnmarshalBER decodes SMAdditionalNumber from BER/DER format.
func (v *SMAdditionalNumber) UnmarshalBER(data []byte) error {
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
		tmp := ISDNAddressString3(rawVal)
		v.MscNumber = &tmp
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
		v.Choice = SMAdditionalNumberChoiceSgsnNumber
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding sgsn-Number: %w", tlvErr)
		}
		tmp := ISDNAddressString3(rawVal)
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
		enc_correlationid = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, true, enc_correlationid)
		children = append(children, enc_correlationid...)
	}
	if v.SmDeliveryOutcome != nil {
		enc_smdeliveryoutcome := ber.EncodeEnumerated(int64(*v.SmDeliveryOutcome))
		enc_smdeliveryoutcome = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, false, enc_smdeliveryoutcome)
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
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes SMMOForwardSMArg from BER/DER format.
func (v *SMMOForwardSMArg) UnmarshalBER(data []byte) error {
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
	v.SmRPUI = SignalInfo3(val_smrpui)
	offset += n
	// Decode extensionContainer
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassUniversal && peekTag.Number == 16 {
				// Decode nested SEQUENCE (ExtensionContainer3)
				_, n_extensioncontainer, _, tlvErr_extensioncontainer := ber.DecodeTLV(content[offset:])
				if tlvErr_extensioncontainer != nil {
					return fmt.Errorf("decoding extensionContainer: %w", tlvErr_extensioncontainer)
				}
				var dec_extensioncontainer ExtensionContainer3
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
				tmp_imsi := IMSI3(val_imsi)
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
				_, n_correlationid, rawVal_correlationid, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding correlationID: %w", err)
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
				_, n_smdeliveryoutcome, rawVal_smdeliveryoutcome, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding sm-DeliveryOutcome: %w", err)
				}
				decVal_smdeliveryoutcome, intErr := ber.DecodeIntegerValue(rawVal_smdeliveryoutcome)
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
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes SMMOForwardSMRes from BER/DER format.
func (v *SMMOForwardSMRes) UnmarshalBER(data []byte) error {
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
				tmp_smrpui := SignalInfo3(val_smrpui)
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
				// Decode nested SEQUENCE (ExtensionContainer3)
				_, n_extensioncontainer, _, tlvErr_extensioncontainer := ber.DecodeTLV(content[offset:])
				if tlvErr_extensioncontainer != nil {
					return fmt.Errorf("decoding extensionContainer: %w", tlvErr_extensioncontainer)
				}
				var dec_extensioncontainer ExtensionContainer3
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
		enc_smsoveriponlyindicator = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, false, enc_smsoveriponlyindicator)
		children = append(children, enc_smsoveriponlyindicator...)
	}
	if v.CorrelationID != nil {
		enc_correlationid, err := v.CorrelationID.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding correlationID: %w", err)
		}
		enc_correlationid = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, true, enc_correlationid)
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
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes SMMTForwardSMArg from BER/DER format.
func (v *SMMTForwardSMArg) UnmarshalBER(data []byte) error {
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
	v.SmRPUI = SignalInfo3(val_smrpui)
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
				// Decode nested SEQUENCE (ExtensionContainer3)
				_, n_extensioncontainer, _, tlvErr_extensioncontainer := ber.DecodeTLV(content[offset:])
				if tlvErr_extensioncontainer != nil {
					return fmt.Errorf("decoding extensionContainer: %w", tlvErr_extensioncontainer)
				}
				var dec_extensioncontainer ExtensionContainer3
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
				tmp_smdeliverystarttime := CommonDataTypesTime(val_smdeliverystarttime)
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
				_, n_smsoveriponlyindicator, rawVal_smsoveriponlyindicator, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding smsOverIP-OnlyIndicator: %w", err)
				}
				_ = rawVal_smsoveriponlyindicator
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
				_, n_correlationid, rawVal_correlationid, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding correlationID: %w", err)
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
		enc_hlrid = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, false, enc_hlrid)
		children = append(children, enc_hlrid...)
	}
	if v.SipUriA != nil {
		enc_sipuria := ber.EncodeOctetString([]byte(*v.SipUriA))
		enc_sipuria = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, false, enc_sipuria)
		children = append(children, enc_sipuria...)
	}
	enc_sipurib := ber.EncodeOctetString([]byte(v.SipUriB))
	enc_sipurib = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, false, enc_sipurib)
	children = append(children, enc_sipurib...)
	return ber.EncodeSequence(children), nil
}

// MarshalDER encodes SMCorrelationID to DER format.
func (v *SMCorrelationID) MarshalDER() ([]byte, error) {
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes SMCorrelationID from BER/DER format.
func (v *SMCorrelationID) UnmarshalBER(data []byte) error {
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
				_, n_hlrid, rawVal_hlrid, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding hlr-id: %w", err)
				}
				tmp_hlrid := HLRId3(rawVal_hlrid)
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
				_, n_sipuria, rawVal_sipuria, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding sip-uri-A: %w", err)
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
	_, n_sipurib, rawVal_sipurib, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding sip-uri-B: %w", err)
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
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes SMMTForwardSMRes from BER/DER format.
func (v *SMMTForwardSMRes) UnmarshalBER(data []byte) error {
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
				tmp_smrpui := SignalInfo3(val_smrpui)
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
				// Decode nested SEQUENCE (ExtensionContainer3)
				_, n_extensioncontainer, _, tlvErr_extensioncontainer := ber.DecodeTLV(content[offset:])
				if tlvErr_extensioncontainer != nil {
					return fmt.Errorf("decoding extensionContainer: %w", tlvErr_extensioncontainer)
				}
				var dec_extensioncontainer ExtensionContainer3
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
		enc_0 := ber.EncodeOctetString([]byte(*v.Imsi))
		enc_0 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, false, enc_0)
		return enc_0, nil
	case SMSMRPDAChoiceLmsi:
		enc_1 := ber.EncodeOctetString([]byte(*v.Lmsi))
		enc_1 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, false, enc_1)
		return enc_1, nil
	case SMSMRPDAChoiceServiceCentreAddressDA:
		enc_2 := ber.EncodeOctetString([]byte(*v.ServiceCentreAddressDA))
		enc_2 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, false, enc_2)
		return enc_2, nil
	case SMSMRPDAChoiceNoSMRPDA:
		enc_3 := ber.EncodeNull()
		enc_3 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 5, false, enc_3)
		return enc_3, nil
	default:
		return nil, fmt.Errorf("unknown choice %d for SMSMRPDA", v.Choice)
	}
}

// MarshalDER encodes SMSMRPDA to DER format.
func (v *SMSMRPDA) MarshalDER() ([]byte, error) {
	return v.MarshalBER()
}

// UnmarshalBER decodes SMSMRPDA from BER/DER format.
func (v *SMSMRPDA) UnmarshalBER(data []byte) error {
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
		tmp := IMSI3(rawVal)
		v.Imsi = &tmp
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
		v.Choice = SMSMRPDAChoiceLmsi
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding lmsi: %w", tlvErr)
		}
		tmp := LMSI3(rawVal)
		v.Lmsi = &tmp
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4 {
		v.Choice = SMSMRPDAChoiceServiceCentreAddressDA
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding serviceCentreAddressDA: %w", tlvErr)
		}
		tmp := AddressString3(rawVal)
		v.ServiceCentreAddressDA = &tmp
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 5 {
		v.Choice = SMSMRPDAChoiceNoSMRPDA
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding noSM-RP-DA: %w", tlvErr)
		}
		_ = rawVal // NULL has no content
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
		enc_0 := ber.EncodeOctetString([]byte(*v.Msisdn))
		enc_0 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, false, enc_0)
		return enc_0, nil
	case SMSMRPOAChoiceServiceCentreAddressOA:
		enc_1 := ber.EncodeOctetString([]byte(*v.ServiceCentreAddressOA))
		enc_1 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, false, enc_1)
		return enc_1, nil
	case SMSMRPOAChoiceNoSMRPOA:
		enc_2 := ber.EncodeNull()
		enc_2 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 5, false, enc_2)
		return enc_2, nil
	default:
		return nil, fmt.Errorf("unknown choice %d for SMSMRPOA", v.Choice)
	}
}

// MarshalDER encodes SMSMRPOA to DER format.
func (v *SMSMRPOA) MarshalDER() ([]byte, error) {
	return v.MarshalBER()
}

// UnmarshalBER decodes SMSMRPOA from BER/DER format.
func (v *SMSMRPOA) UnmarshalBER(data []byte) error {
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
		tmp := ISDNAddressString3(rawVal)
		v.Msisdn = &tmp
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4 {
		v.Choice = SMSMRPOAChoiceServiceCentreAddressOA
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding serviceCentreAddressOA: %w", tlvErr)
		}
		tmp := AddressString3(rawVal)
		v.ServiceCentreAddressOA = &tmp
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 5 {
		v.Choice = SMSMRPOAChoiceNoSMRPOA
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding noSM-RP-OA: %w", tlvErr)
		}
		_ = rawVal // NULL has no content
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
		enc_absentsubscriberdiagnosticsm = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, false, enc_absentsubscriberdiagnosticsm)
		children = append(children, enc_absentsubscriberdiagnosticsm...)
	}
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding extensionContainer: %w", err)
		}
		enc_extensioncontainer = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, true, enc_extensioncontainer)
		children = append(children, enc_extensioncontainer...)
	}
	if v.GprsSupportIndicator != nil {
		enc_gprssupportindicator := ber.EncodeNull()
		enc_gprssupportindicator = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, false, enc_gprssupportindicator)
		children = append(children, enc_gprssupportindicator...)
	}
	if v.DeliveryOutcomeIndicator != nil {
		enc_deliveryoutcomeindicator := ber.EncodeNull()
		enc_deliveryoutcomeindicator = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, false, enc_deliveryoutcomeindicator)
		children = append(children, enc_deliveryoutcomeindicator...)
	}
	if v.AdditionalSMDeliveryOutcome != nil {
		enc_additionalsmdeliveryoutcome := ber.EncodeEnumerated(int64(*v.AdditionalSMDeliveryOutcome))
		enc_additionalsmdeliveryoutcome = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, false, enc_additionalsmdeliveryoutcome)
		children = append(children, enc_additionalsmdeliveryoutcome...)
	}
	if v.AdditionalAbsentSubscriberDiagnosticSM != nil {
		enc_additionalabsentsubscriberdiagnosticsm := ber.EncodeInteger(int64(*v.AdditionalAbsentSubscriberDiagnosticSM))
		enc_additionalabsentsubscriberdiagnosticsm = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 5, false, enc_additionalabsentsubscriberdiagnosticsm)
		children = append(children, enc_additionalabsentsubscriberdiagnosticsm...)
	}
	if v.IpSmGwIndicator != nil {
		enc_ipsmgwindicator := ber.EncodeNull()
		enc_ipsmgwindicator = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 6, false, enc_ipsmgwindicator)
		children = append(children, enc_ipsmgwindicator...)
	}
	if v.IpSmGwSmDeliveryOutcome != nil {
		enc_ipsmgwsmdeliveryoutcome := ber.EncodeEnumerated(int64(*v.IpSmGwSmDeliveryOutcome))
		enc_ipsmgwsmdeliveryoutcome = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 7, false, enc_ipsmgwsmdeliveryoutcome)
		children = append(children, enc_ipsmgwsmdeliveryoutcome...)
	}
	if v.IpSmGwAbsentSubscriberDiagnosticSM != nil {
		enc_ipsmgwabsentsubscriberdiagnosticsm := ber.EncodeInteger(int64(*v.IpSmGwAbsentSubscriberDiagnosticSM))
		enc_ipsmgwabsentsubscriberdiagnosticsm = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 8, false, enc_ipsmgwabsentsubscriberdiagnosticsm)
		children = append(children, enc_ipsmgwabsentsubscriberdiagnosticsm...)
	}
	if v.Imsi != nil {
		enc_imsi := ber.EncodeOctetString([]byte(*v.Imsi))
		enc_imsi = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 9, false, enc_imsi)
		children = append(children, enc_imsi...)
	}
	if v.SingleAttemptDelivery != nil {
		enc_singleattemptdelivery := ber.EncodeNull()
		enc_singleattemptdelivery = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 10, false, enc_singleattemptdelivery)
		children = append(children, enc_singleattemptdelivery...)
	}
	if v.CorrelationID != nil {
		enc_correlationid, err := v.CorrelationID.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding correlationID: %w", err)
		}
		enc_correlationid = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 11, true, enc_correlationid)
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
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes SMReportSMDeliveryStatusArg from BER/DER format.
func (v *SMReportSMDeliveryStatusArg) UnmarshalBER(data []byte) error {
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
	v.Msisdn = ISDNAddressString3(val_msisdn)
	offset += n
	// Decode serviceCentreAddress
	if offset >= len(content) {
		return fmt.Errorf("missing required field serviceCentreAddress")
	}
	val_servicecentreaddress, n, err := ber.DecodeOctetString(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding serviceCentreAddress: %w", err)
	}
	v.ServiceCentreAddress = AddressString3(val_servicecentreaddress)
	offset += n
	// Decode sm-DeliveryOutcome
	if offset >= len(content) {
		return fmt.Errorf("missing required field sm-DeliveryOutcome")
	}
	val_smdeliveryoutcome, n, err := ber.DecodeInteger(content[offset:])
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
				_, n_absentsubscriberdiagnosticsm, rawVal_absentsubscriberdiagnosticsm, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding absentSubscriberDiagnosticSM: %w", err)
				}
				decVal_absentsubscriberdiagnosticsm, intErr := ber.DecodeIntegerValue(rawVal_absentsubscriberdiagnosticsm)
				if intErr != nil {
					return fmt.Errorf("decoding absentSubscriberDiagnosticSM: %w", intErr)
				}
				tmp_absentsubscriberdiagnosticsm := AbsentSubscriberDiagnosticSM3(decVal_absentsubscriberdiagnosticsm)
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
				_, n_extensioncontainer, rawVal_extensioncontainer, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding extensionContainer: %w", err)
				}
				reconstructed_extensioncontainer := ber.EncodeSequence(rawVal_extensioncontainer)
				var dec_extensioncontainer ExtensionContainer3
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
				_, n_gprssupportindicator, rawVal_gprssupportindicator, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding gprsSupportIndicator: %w", err)
				}
				_ = rawVal_gprssupportindicator
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
				_, n_deliveryoutcomeindicator, rawVal_deliveryoutcomeindicator, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding deliveryOutcomeIndicator: %w", err)
				}
				_ = rawVal_deliveryoutcomeindicator
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
				_, n_additionalsmdeliveryoutcome, rawVal_additionalsmdeliveryoutcome, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding additionalSM-DeliveryOutcome: %w", err)
				}
				decVal_additionalsmdeliveryoutcome, intErr := ber.DecodeIntegerValue(rawVal_additionalsmdeliveryoutcome)
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
				_, n_additionalabsentsubscriberdiagnosticsm, rawVal_additionalabsentsubscriberdiagnosticsm, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding additionalAbsentSubscriberDiagnosticSM: %w", err)
				}
				decVal_additionalabsentsubscriberdiagnosticsm, intErr := ber.DecodeIntegerValue(rawVal_additionalabsentsubscriberdiagnosticsm)
				if intErr != nil {
					return fmt.Errorf("decoding additionalAbsentSubscriberDiagnosticSM: %w", intErr)
				}
				tmp_additionalabsentsubscriberdiagnosticsm := AbsentSubscriberDiagnosticSM3(decVal_additionalabsentsubscriberdiagnosticsm)
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
				_, n_ipsmgwindicator, rawVal_ipsmgwindicator, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding ip-sm-gw-Indicator: %w", err)
				}
				_ = rawVal_ipsmgwindicator
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
				_, n_ipsmgwsmdeliveryoutcome, rawVal_ipsmgwsmdeliveryoutcome, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding ip-sm-gw-sm-deliveryOutcome: %w", err)
				}
				decVal_ipsmgwsmdeliveryoutcome, intErr := ber.DecodeIntegerValue(rawVal_ipsmgwsmdeliveryoutcome)
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
				_, n_ipsmgwabsentsubscriberdiagnosticsm, rawVal_ipsmgwabsentsubscriberdiagnosticsm, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding ip-sm-gw-absentSubscriberDiagnosticSM: %w", err)
				}
				decVal_ipsmgwabsentsubscriberdiagnosticsm, intErr := ber.DecodeIntegerValue(rawVal_ipsmgwabsentsubscriberdiagnosticsm)
				if intErr != nil {
					return fmt.Errorf("decoding ip-sm-gw-absentSubscriberDiagnosticSM: %w", intErr)
				}
				tmp_ipsmgwabsentsubscriberdiagnosticsm := AbsentSubscriberDiagnosticSM3(decVal_ipsmgwabsentsubscriberdiagnosticsm)
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
				_, n_imsi, rawVal_imsi, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding imsi: %w", err)
				}
				tmp_imsi := IMSI3(rawVal_imsi)
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
				_, n_singleattemptdelivery, rawVal_singleattemptdelivery, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding singleAttemptDelivery: %w", err)
				}
				_ = rawVal_singleattemptdelivery
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
				_, n_correlationid, rawVal_correlationid, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding correlationID: %w", err)
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
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes SMReportSMDeliveryStatusRes from BER/DER format.
func (v *SMReportSMDeliveryStatusRes) UnmarshalBER(data []byte) error {
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
				tmp_storedmsisdn := ISDNAddressString3(val_storedmsisdn)
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
				// Decode nested SEQUENCE (ExtensionContainer3)
				_, n_extensioncontainer, _, tlvErr_extensioncontainer := ber.DecodeTLV(content[offset:])
				if tlvErr_extensioncontainer != nil {
					return fmt.Errorf("decoding extensionContainer: %w", tlvErr_extensioncontainer)
				}
				var dec_extensioncontainer ExtensionContainer3
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
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes SMAlertServiceCentreArg from BER/DER format.
func (v *SMAlertServiceCentreArg) UnmarshalBER(data []byte) error {
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
	v.Msisdn = ISDNAddressString3(val_msisdn)
	offset += n
	// Decode serviceCentreAddress
	if offset >= len(content) {
		return fmt.Errorf("missing required field serviceCentreAddress")
	}
	val_servicecentreaddress, n, err := ber.DecodeOctetString(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding serviceCentreAddress: %w", err)
	}
	v.ServiceCentreAddress = AddressString3(val_servicecentreaddress)
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
				tmp_imsi := IMSI3(val_imsi)
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
		enc_additionalabsentsubscriberdiagnosticsm = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, false, enc_additionalabsentsubscriberdiagnosticsm)
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
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes SMInformServiceCentreArg from BER/DER format.
func (v *SMInformServiceCentreArg) UnmarshalBER(data []byte) error {
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
				tmp_storedmsisdn := ISDNAddressString3(val_storedmsisdn)
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
				// Decode nested SEQUENCE (ExtensionContainer3)
				_, n_extensioncontainer, _, tlvErr_extensioncontainer := ber.DecodeTLV(content[offset:])
				if tlvErr_extensioncontainer != nil {
					return fmt.Errorf("decoding extensionContainer: %w", tlvErr_extensioncontainer)
				}
				var dec_extensioncontainer ExtensionContainer3
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
				tmp_absentsubscriberdiagnosticsm := AbsentSubscriberDiagnosticSM3(val_absentsubscriberdiagnosticsm)
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
				_, n_additionalabsentsubscriberdiagnosticsm, rawVal_additionalabsentsubscriberdiagnosticsm, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding additionalAbsentSubscriberDiagnosticSM: %w", err)
				}
				decVal_additionalabsentsubscriberdiagnosticsm, intErr := ber.DecodeIntegerValue(rawVal_additionalabsentsubscriberdiagnosticsm)
				if intErr != nil {
					return fmt.Errorf("decoding additionalAbsentSubscriberDiagnosticSM: %w", intErr)
				}
				tmp_additionalabsentsubscriberdiagnosticsm := AbsentSubscriberDiagnosticSM3(decVal_additionalabsentsubscriberdiagnosticsm)
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
	enc_imsi = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, false, enc_imsi)
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
		enc_additionalalertreasonindicator = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, false, enc_additionalalertreasonindicator)
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
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes SMReadyForSMArg from BER/DER format.
func (v *SMReadyForSMArg) UnmarshalBER(data []byte) error {
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
	_, n_imsi, rawVal_imsi, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding imsi: %w", err)
	}
	v.Imsi = IMSI3(rawVal_imsi)
	offset += n_imsi
	// Decode alertReason
	if offset >= len(content) {
		return fmt.Errorf("missing required field alertReason")
	}
	val_alertreason, n, err := ber.DecodeInteger(content[offset:])
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
				// Decode nested SEQUENCE (ExtensionContainer3)
				_, n_extensioncontainer, _, tlvErr_extensioncontainer := ber.DecodeTLV(content[offset:])
				if tlvErr_extensioncontainer != nil {
					return fmt.Errorf("decoding extensionContainer: %w", tlvErr_extensioncontainer)
				}
				var dec_extensioncontainer ExtensionContainer3
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
				_, n_additionalalertreasonindicator, rawVal_additionalalertreasonindicator, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding additionalAlertReasonIndicator: %w", err)
				}
				_ = rawVal_additionalalertreasonindicator
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
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes SMReadyForSMRes from BER/DER format.
func (v *SMReadyForSMRes) UnmarshalBER(data []byte) error {
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
				// Decode nested SEQUENCE (ExtensionContainer3)
				_, n_extensioncontainer, _, tlvErr_extensioncontainer := ber.DecodeTLV(content[offset:])
				if tlvErr_extensioncontainer != nil {
					return fmt.Errorf("decoding extensionContainer: %w", tlvErr_extensioncontainer)
				}
				var dec_extensioncontainer ExtensionContainer3
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
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes SMMTForwardSMVGCSArg from BER/DER format.
func (v *SMMTForwardSMVGCSArg) UnmarshalBER(data []byte) error {
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
	v.AsciCallReference = ASCICallReference3(val_ascicallreference)
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
	v.SmRPUI = SignalInfo3(val_smrpui)
	offset += n
	// Decode extensionContainer
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassUniversal && peekTag.Number == 16 {
				// Decode nested SEQUENCE (ExtensionContainer3)
				_, n_extensioncontainer, _, tlvErr_extensioncontainer := ber.DecodeTLV(content[offset:])
				if tlvErr_extensioncontainer != nil {
					return fmt.Errorf("decoding extensionContainer: %w", tlvErr_extensioncontainer)
				}
				var dec_extensioncontainer ExtensionContainer3
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
		enc_smrpui = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, false, enc_smrpui)
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
			enc_dispatcherlist = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, true, enc_dispatcherlist)
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
		enc_extensioncontainer = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, true, enc_extensioncontainer)
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
			enc_additionaldispatcherlist = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, true, enc_additionaldispatcherlist)
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
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// ITU-T X.690 (02/2021) Section 10.1 requires DER length forms to be definite.
	derValue := *v
	derValue.DispatcherListIndef_ = false
	derValue.AdditionalDispatcherListIndef_ = false
	v = &derValue
	return v.MarshalBER()
}

// UnmarshalBER decodes SMMTForwardSMVGCSRes from BER/DER format.
func (v *SMMTForwardSMVGCSRes) UnmarshalBER(data []byte) error {
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
				_, n_smrpui, rawVal_smrpui, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding sm-RP-UI: %w", err)
				}
				tmp_smrpui := SignalInfo3(rawVal_smrpui)
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
				_, n_dispatcherlist, rawVal_dispatcherlist, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding dispatcherList: %w", err)
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
				_, n_extensioncontainer, rawVal_extensioncontainer, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding extensionContainer: %w", err)
				}
				reconstructed_extensioncontainer := ber.EncodeSequence(rawVal_extensioncontainer)
				var dec_extensioncontainer ExtensionContainer3
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
				_, n_additionaldispatcherlist, rawVal_additionaldispatcherlist, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding additionalDispatcherList: %w", err)
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
	var children []byte
	for _, elem := range list {
		children = append(children, ber.EncodeOctetString([]byte(elem))...)
	}
	return ber.EncodeSequence(children), nil
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
		result = append(result, ISDNAddressString3(val))
		offset += n
	}
	return result, nil
}

// MarshalBERSMAdditionalDispatcherList encodes a SMAdditionalDispatcherList list to BER.
func MarshalBERSMAdditionalDispatcherList(list SMAdditionalDispatcherList) ([]byte, error) {
	var children []byte
	for _, elem := range list {
		children = append(children, ber.EncodeOctetString([]byte(elem))...)
	}
	return ber.EncodeSequence(children), nil
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
		result = append(result, ISDNAddressString3(val))
		offset += n
	}
	return result, nil
}
