// Code generated from ASN.1 module "MAP-SM-DataTypes". DO NOT EDIT.

package v21_map_sm_datatypes

import (
	"fmt"

	"github.com/gomaja/go-asn1/runtime"
	"github.com/gomaja/go-asn1/runtime/ber"
	"github.com/gomaja/go-asn1/runtime/tag"
	"github.com/gomaja/go-asn1/telecom/ss7/gsm_map/v21_map_commondatatypes"
	"github.com/gomaja/go-asn1/telecom/ss7/gsm_map/v21_map_er_datatypes"
	"github.com/gomaja/go-asn1/telecom/ss7/gsm_map/v21_map_extensiondatatypes"
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
	Msisdn                  v21_map_commondatatypes.CommonDataTypesISDNAddressString         `asn1:"tag:0,context,implicit"`
	SmRPPRI                 bool                                                             `asn1:"tag:1,context,implicit"`
	SmRPPRIRaw_             byte                                                             `asn1:"-" json:"-"`
	ServiceCentreAddress    v21_map_commondatatypes.CommonDataTypesAddressString             `asn1:"tag:2,context,implicit"`
	ExtensionContainer      *v21_map_extensiondatatypes.ExtensionDataTypesExtensionContainer `asn1:"tag:6,context,implicit,optional" json:"ExtensionContainer,omitempty"`
	GprsSupportIndicator    *struct{}                                                        `asn1:"tag:7,context,implicit,optional" json:"GprsSupportIndicator,omitempty"`
	SmRPMTI                 *SMSMRPMTI                                                       `asn1:"tag:8,context,implicit,optional" json:"SmRPMTI,omitempty"`
	SmRPSMEA                *SMSMRPSMEA                                                      `asn1:"tag:9,context,implicit,optional" json:"SmRPSMEA,omitempty"`
	SmDeliveryNotIntended   *SMSMDeliveryNotIntended                                         `asn1:"tag:10,context,implicit,optional" json:"SmDeliveryNotIntended,omitempty"`
	IpSmGwGuidanceIndicator *struct{}                                                        `asn1:"tag:11,context,implicit,optional" json:"IpSmGwGuidanceIndicator,omitempty"`
	Imsi                    *v21_map_commondatatypes.CommonDataTypesIMSI                     `asn1:"tag:12,context,implicit,optional" json:"Imsi,omitempty"`
	T4TriggerIndicator      *struct{}                                                        `asn1:"tag:14,context,implicit,optional" json:"T4TriggerIndicator,omitempty"`
	SingleAttemptDelivery   *struct{}                                                        `asn1:"tag:13,context,implicit,optional" json:"SingleAttemptDelivery,omitempty"`
	CorrelationID           *SMCorrelationID                                                 `asn1:"tag:15,context,implicit,optional" json:"CorrelationID,omitempty"`
	SmsfSupportIndicator    *struct{}                                                        `asn1:"tag:16,context,implicit,optional" json:"SmsfSupportIndicator,omitempty"`
	ExtCount_               int64                                                            `asn1:"-" json:"-"`
	ExtPresent_             []bool                                                           `asn1:"-" json:"-"`
	ExtData_                [][]byte                                                         `asn1:"-" json:"-"`
	berReplayNode_          *ber.ReplayNode                                                  `asn1:"-" json:"-"`
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
	Imsi                 v21_map_commondatatypes.CommonDataTypesIMSI                      `asn1:""`
	LocationInfoWithLMSI SMLocationInfoWithLMSI                                           `asn1:"tag:0,context,implicit"`
	ExtensionContainer   *v21_map_extensiondatatypes.ExtensionDataTypesExtensionContainer `asn1:"tag:4,context,implicit,optional" json:"ExtensionContainer,omitempty"`
	IpSmGwGuidance       *SMIPSMGWGuidance                                                `asn1:"tag:5,context,implicit,optional" json:"IpSmGwGuidance,omitempty"`
	ExtCount_            int64                                                            `asn1:"-" json:"-"`
	ExtPresent_          []bool                                                           `asn1:"-" json:"-"`
	ExtData_             [][]byte                                                         `asn1:"-" json:"-"`
	berReplayNode_       *ber.ReplayNode                                                  `asn1:"-" json:"-"`
}

// SMIPSMGWGuidance represents the ASN.1 type IP-SM-GW-Guidance (SEQUENCE).
type SMIPSMGWGuidance struct {
	MinimumDeliveryTimeValue     SMSMDeliveryTimerValue                                           `asn1:""`
	RecommendedDeliveryTimeValue SMSMDeliveryTimerValue                                           `asn1:""`
	ExtensionContainer           *v21_map_extensiondatatypes.ExtensionDataTypesExtensionContainer `asn1:",optional" json:"ExtensionContainer,omitempty"`
	ExtCount_                    int64                                                            `asn1:"-" json:"-"`
	ExtPresent_                  []bool                                                           `asn1:"-" json:"-"`
	ExtData_                     [][]byte                                                         `asn1:"-" json:"-"`
	berReplayNode_               *ber.ReplayNode                                                  `asn1:"-" json:"-"`
}

// SMLocationInfoWithLMSI represents the ASN.1 type LocationInfoWithLMSI (SEQUENCE).
type SMLocationInfoWithLMSI struct {
	NetworkNodeNumber                    v21_map_commondatatypes.CommonDataTypesISDNAddressString           `asn1:"tag:1,context,implicit"`
	Lmsi                                 *v21_map_commondatatypes.CommonDataTypesLMSI                       `asn1:",optional" json:"Lmsi,omitempty"`
	ExtensionContainer                   *v21_map_extensiondatatypes.ExtensionDataTypesExtensionContainer   `asn1:",optional" json:"ExtensionContainer,omitempty"`
	GprsNodeIndicator                    *struct{}                                                          `asn1:"tag:5,context,implicit,optional" json:"GprsNodeIndicator,omitempty"`
	AdditionalNumber                     *SMAdditionalNumber                                                `asn1:"tag:6,context,explicit,optional" json:"AdditionalNumber,omitempty"`
	NetworkNodeDiameterAddress           *v21_map_commondatatypes.CommonDataTypesNetworkNodeDiameterAddress `asn1:"tag:7,context,implicit,optional" json:"NetworkNodeDiameterAddress,omitempty"`
	AdditionalNetworkNodeDiameterAddress *v21_map_commondatatypes.CommonDataTypesNetworkNodeDiameterAddress `asn1:"tag:8,context,implicit,optional" json:"AdditionalNetworkNodeDiameterAddress,omitempty"`
	ThirdNumber                          *SMAdditionalNumber                                                `asn1:"tag:9,context,explicit,optional" json:"ThirdNumber,omitempty"`
	ThirdNetworkNodeDiameterAddress      *v21_map_commondatatypes.CommonDataTypesNetworkNodeDiameterAddress `asn1:"tag:10,context,implicit,optional" json:"ThirdNetworkNodeDiameterAddress,omitempty"`
	ImsNodeIndicator                     *struct{}                                                          `asn1:"tag:11,context,implicit,optional" json:"ImsNodeIndicator,omitempty"`
	Smsf3gppNumber                       *v21_map_commondatatypes.CommonDataTypesISDNAddressString          `asn1:"tag:12,context,implicit,optional" json:"Smsf3gppNumber,omitempty"`
	Smsf3gppDiameterAddress              *v21_map_commondatatypes.CommonDataTypesNetworkNodeDiameterAddress `asn1:"tag:13,context,implicit,optional" json:"Smsf3gppDiameterAddress,omitempty"`
	SmsfNon3gppNumber                    *v21_map_commondatatypes.CommonDataTypesISDNAddressString          `asn1:"tag:14,context,implicit,optional" json:"SmsfNon3gppNumber,omitempty"`
	SmsfNon3gppDiameterAddress           *v21_map_commondatatypes.CommonDataTypesNetworkNodeDiameterAddress `asn1:"tag:15,context,implicit,optional" json:"SmsfNon3gppDiameterAddress,omitempty"`
	Smsf3gppAddressIndicator             *struct{}                                                          `asn1:"tag:16,context,implicit,optional" json:"Smsf3gppAddressIndicator,omitempty"`
	SmsfNon3gppAddressIndicator          *struct{}                                                          `asn1:"tag:17,context,implicit,optional" json:"SmsfNon3gppAddressIndicator,omitempty"`
	ExtCount_                            int64                                                              `asn1:"-" json:"-"`
	ExtPresent_                          []bool                                                             `asn1:"-" json:"-"`
	ExtData_                             [][]byte                                                           `asn1:"-" json:"-"`
	berReplayNode_                       *ber.ReplayNode                                                    `asn1:"-" json:"-"`
}

// SMAdditionalNumber choice constants.
const (
	SMAdditionalNumberChoiceMscNumber  = 1
	SMAdditionalNumberChoiceSgsnNumber = 2
)

// SMAdditionalNumber represents the ASN.1 CHOICE type Additional-Number.
type SMAdditionalNumber struct {
	Choice         int
	berReplayNode_ *ber.ReplayNode                                           `json:"-"`
	MscNumber      *v21_map_commondatatypes.CommonDataTypesISDNAddressString `json:"MscNumber,omitempty"`
	SgsnNumber     *v21_map_commondatatypes.CommonDataTypesISDNAddressString `json:"SgsnNumber,omitempty"`
}

// NewSMAdditionalNumberMscNumber creates a SMAdditionalNumber with the msc-Number alternative.
func NewSMAdditionalNumberMscNumber(v v21_map_commondatatypes.CommonDataTypesISDNAddressString) SMAdditionalNumber {
	return SMAdditionalNumber{
		Choice:    SMAdditionalNumberChoiceMscNumber,
		MscNumber: &v,
	}
}

// NewSMAdditionalNumberSgsnNumber creates a SMAdditionalNumber with the sgsn-Number alternative.
func NewSMAdditionalNumberSgsnNumber(v v21_map_commondatatypes.CommonDataTypesISDNAddressString) SMAdditionalNumber {
	return SMAdditionalNumber{
		Choice:     SMAdditionalNumberChoiceSgsnNumber,
		SgsnNumber: &v,
	}
}

// SMMOForwardSMArg represents the ASN.1 type MO-ForwardSM-Arg (SEQUENCE).
type SMMOForwardSMArg struct {
	SmRPDA             SMSMRPDA                                                         `asn1:""`
	SmRPOA             SMSMRPOA                                                         `asn1:""`
	SmRPUI             v21_map_commondatatypes.CommonDataTypesSignalInfo                `asn1:""`
	ExtensionContainer *v21_map_extensiondatatypes.ExtensionDataTypesExtensionContainer `asn1:",optional" json:"ExtensionContainer,omitempty"`
	Imsi               *v21_map_commondatatypes.CommonDataTypesIMSI                     `asn1:",optional" json:"Imsi,omitempty"`
	CorrelationID      *SMCorrelationID                                                 `asn1:"tag:0,context,implicit,optional" json:"CorrelationID,omitempty"`
	SmDeliveryOutcome  *SMSMDeliveryOutcome                                             `asn1:"tag:1,context,implicit,optional" json:"SmDeliveryOutcome,omitempty"`
	ExtCount_          int64                                                            `asn1:"-" json:"-"`
	ExtPresent_        []bool                                                           `asn1:"-" json:"-"`
	ExtData_           [][]byte                                                         `asn1:"-" json:"-"`
	berReplayNode_     *ber.ReplayNode                                                  `asn1:"-" json:"-"`
}

// SMMOForwardSMRes represents the ASN.1 type MO-ForwardSM-Res (SEQUENCE).
type SMMOForwardSMRes struct {
	SmRPUI             *v21_map_commondatatypes.CommonDataTypesSignalInfo               `asn1:",optional" json:"SmRPUI,omitempty"`
	ExtensionContainer *v21_map_extensiondatatypes.ExtensionDataTypesExtensionContainer `asn1:",optional" json:"ExtensionContainer,omitempty"`
	ExtCount_          int64                                                            `asn1:"-" json:"-"`
	ExtPresent_        []bool                                                           `asn1:"-" json:"-"`
	ExtData_           [][]byte                                                         `asn1:"-" json:"-"`
	berReplayNode_     *ber.ReplayNode                                                  `asn1:"-" json:"-"`
}

// SMMTForwardSMArg represents the ASN.1 type MT-ForwardSM-Arg (SEQUENCE).
type SMMTForwardSMArg struct {
	SmRPDA                    SMSMRPDA                                                           `asn1:""`
	SmRPOA                    SMSMRPOA                                                           `asn1:""`
	SmRPUI                    v21_map_commondatatypes.CommonDataTypesSignalInfo                  `asn1:""`
	MoreMessagesToSend        *struct{}                                                          `asn1:",optional" json:"MoreMessagesToSend,omitempty"`
	ExtensionContainer        *v21_map_extensiondatatypes.ExtensionDataTypesExtensionContainer   `asn1:",optional" json:"ExtensionContainer,omitempty"`
	SmDeliveryTimer           *SMSMDeliveryTimerValue                                            `asn1:",optional" json:"SmDeliveryTimer,omitempty"`
	SmDeliveryStartTime       *v21_map_commondatatypes.CommonDataTypesTime                       `asn1:",optional" json:"SmDeliveryStartTime,omitempty"`
	SmsOverIPOnlyIndicator    *struct{}                                                          `asn1:"tag:0,context,implicit,optional" json:"SmsOverIPOnlyIndicator,omitempty"`
	CorrelationID             *SMCorrelationID                                                   `asn1:"tag:1,context,implicit,optional" json:"CorrelationID,omitempty"`
	MaximumRetransmissionTime *v21_map_commondatatypes.CommonDataTypesTime                       `asn1:"tag:2,context,implicit,optional" json:"MaximumRetransmissionTime,omitempty"`
	SmsGmscAddress            *v21_map_commondatatypes.CommonDataTypesISDNAddressString          `asn1:"tag:3,context,implicit,optional" json:"SmsGmscAddress,omitempty"`
	SmsGmscDiameterAddress    *v21_map_commondatatypes.CommonDataTypesNetworkNodeDiameterAddress `asn1:"tag:4,context,implicit,optional" json:"SmsGmscDiameterAddress,omitempty"`
	ExtCount_                 int64                                                              `asn1:"-" json:"-"`
	ExtPresent_               []bool                                                             `asn1:"-" json:"-"`
	ExtData_                  [][]byte                                                           `asn1:"-" json:"-"`
	berReplayNode_            *ber.ReplayNode                                                    `asn1:"-" json:"-"`
}

// SMCorrelationID represents the ASN.1 type CorrelationID (SEQUENCE).
type SMCorrelationID struct {
	HlrId          *v21_map_commondatatypes.CommonDataTypesHLRId `asn1:"tag:0,context,implicit,optional" json:"HlrId,omitempty"`
	SipUriA        *SMSIPURI                                     `asn1:"tag:1,context,implicit,optional" json:"SipUriA,omitempty"`
	SipUriB        SMSIPURI                                      `asn1:"tag:2,context,implicit"`
	berReplayNode_ *ber.ReplayNode                               `asn1:"-" json:"-"`
}

// SMSIPURI represents the ASN.1 type SIP-URI (OCTET_STRING).
type SMSIPURI = []byte

// SMMTForwardSMRes represents the ASN.1 type MT-ForwardSM-Res (SEQUENCE).
type SMMTForwardSMRes struct {
	SmRPUI             *v21_map_commondatatypes.CommonDataTypesSignalInfo               `asn1:",optional" json:"SmRPUI,omitempty"`
	ExtensionContainer *v21_map_extensiondatatypes.ExtensionDataTypesExtensionContainer `asn1:",optional" json:"ExtensionContainer,omitempty"`
	ExtCount_          int64                                                            `asn1:"-" json:"-"`
	ExtPresent_        []bool                                                           `asn1:"-" json:"-"`
	ExtData_           [][]byte                                                         `asn1:"-" json:"-"`
	berReplayNode_     *ber.ReplayNode                                                  `asn1:"-" json:"-"`
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
	berReplayNode_         *ber.ReplayNode                                       `json:"-"`
	Imsi                   *v21_map_commondatatypes.CommonDataTypesIMSI          `json:"Imsi,omitempty"`
	Lmsi                   *v21_map_commondatatypes.CommonDataTypesLMSI          `json:"Lmsi,omitempty"`
	ServiceCentreAddressDA *v21_map_commondatatypes.CommonDataTypesAddressString `json:"ServiceCentreAddressDA,omitempty"`
	NoSMRPDA               *struct{}                                             `json:"NoSMRPDA,omitempty"`
}

// NewSMSMRPDAImsi creates a SMSMRPDA with the imsi alternative.
func NewSMSMRPDAImsi(v v21_map_commondatatypes.CommonDataTypesIMSI) SMSMRPDA {
	return SMSMRPDA{
		Choice: SMSMRPDAChoiceImsi,
		Imsi:   &v,
	}
}

// NewSMSMRPDALmsi creates a SMSMRPDA with the lmsi alternative.
func NewSMSMRPDALmsi(v v21_map_commondatatypes.CommonDataTypesLMSI) SMSMRPDA {
	return SMSMRPDA{
		Choice: SMSMRPDAChoiceLmsi,
		Lmsi:   &v,
	}
}

// NewSMSMRPDAServiceCentreAddressDA creates a SMSMRPDA with the serviceCentreAddressDA alternative.
func NewSMSMRPDAServiceCentreAddressDA(v v21_map_commondatatypes.CommonDataTypesAddressString) SMSMRPDA {
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
	berReplayNode_         *ber.ReplayNode                                           `json:"-"`
	Msisdn                 *v21_map_commondatatypes.CommonDataTypesISDNAddressString `json:"Msisdn,omitempty"`
	ServiceCentreAddressOA *v21_map_commondatatypes.CommonDataTypesAddressString     `json:"ServiceCentreAddressOA,omitempty"`
	NoSMRPOA               *struct{}                                                 `json:"NoSMRPOA,omitempty"`
}

// NewSMSMRPOAMsisdn creates a SMSMRPOA with the msisdn alternative.
func NewSMSMRPOAMsisdn(v v21_map_commondatatypes.CommonDataTypesISDNAddressString) SMSMRPOA {
	return SMSMRPOA{
		Choice: SMSMRPOAChoiceMsisdn,
		Msisdn: &v,
	}
}

// NewSMSMRPOAServiceCentreAddressOA creates a SMSMRPOA with the serviceCentreAddressOA alternative.
func NewSMSMRPOAServiceCentreAddressOA(v v21_map_commondatatypes.CommonDataTypesAddressString) SMSMRPOA {
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
	Msisdn                                 v21_map_commondatatypes.CommonDataTypesISDNAddressString         `asn1:""`
	ServiceCentreAddress                   v21_map_commondatatypes.CommonDataTypesAddressString             `asn1:""`
	SmDeliveryOutcome                      SMSMDeliveryOutcome                                              `asn1:""`
	AbsentSubscriberDiagnosticSM           *v21_map_er_datatypes.ERAbsentSubscriberDiagnosticSM             `asn1:"tag:0,context,implicit,optional" json:"AbsentSubscriberDiagnosticSM,omitempty"`
	ExtensionContainer                     *v21_map_extensiondatatypes.ExtensionDataTypesExtensionContainer `asn1:"tag:1,context,implicit,optional" json:"ExtensionContainer,omitempty"`
	GprsSupportIndicator                   *struct{}                                                        `asn1:"tag:2,context,implicit,optional" json:"GprsSupportIndicator,omitempty"`
	DeliveryOutcomeIndicator               *struct{}                                                        `asn1:"tag:3,context,implicit,optional" json:"DeliveryOutcomeIndicator,omitempty"`
	AdditionalSMDeliveryOutcome            *SMSMDeliveryOutcome                                             `asn1:"tag:4,context,implicit,optional" json:"AdditionalSMDeliveryOutcome,omitempty"`
	AdditionalAbsentSubscriberDiagnosticSM *v21_map_er_datatypes.ERAbsentSubscriberDiagnosticSM             `asn1:"tag:5,context,implicit,optional" json:"AdditionalAbsentSubscriberDiagnosticSM,omitempty"`
	IpSmGwIndicator                        *struct{}                                                        `asn1:"tag:6,context,implicit,optional" json:"IpSmGwIndicator,omitempty"`
	IpSmGwSmDeliveryOutcome                *SMSMDeliveryOutcome                                             `asn1:"tag:7,context,implicit,optional" json:"IpSmGwSmDeliveryOutcome,omitempty"`
	IpSmGwAbsentSubscriberDiagnosticSM     *v21_map_er_datatypes.ERAbsentSubscriberDiagnosticSM             `asn1:"tag:8,context,implicit,optional" json:"IpSmGwAbsentSubscriberDiagnosticSM,omitempty"`
	Imsi                                   *v21_map_commondatatypes.CommonDataTypesIMSI                     `asn1:"tag:9,context,implicit,optional" json:"Imsi,omitempty"`
	SingleAttemptDelivery                  *struct{}                                                        `asn1:"tag:10,context,implicit,optional" json:"SingleAttemptDelivery,omitempty"`
	CorrelationID                          *SMCorrelationID                                                 `asn1:"tag:11,context,implicit,optional" json:"CorrelationID,omitempty"`
	Smsf3gppDeliveryOutcomeIndicator       *struct{}                                                        `asn1:"tag:12,context,implicit,optional" json:"Smsf3gppDeliveryOutcomeIndicator,omitempty"`
	Smsf3gppDeliveryOutcome                *SMSMDeliveryOutcome                                             `asn1:"tag:13,context,implicit,optional" json:"Smsf3gppDeliveryOutcome,omitempty"`
	Smsf3gppAbsentSubscriberDiagSM         *v21_map_er_datatypes.ERAbsentSubscriberDiagnosticSM             `asn1:"tag:14,context,implicit,optional" json:"Smsf3gppAbsentSubscriberDiagSM,omitempty"`
	SmsfNon3gppDeliveryOutcomeIndicator    *struct{}                                                        `asn1:"tag:15,context,implicit,optional" json:"SmsfNon3gppDeliveryOutcomeIndicator,omitempty"`
	SmsfNon3gppDeliveryOutcome             *SMSMDeliveryOutcome                                             `asn1:"tag:16,context,implicit,optional" json:"SmsfNon3gppDeliveryOutcome,omitempty"`
	SmsfNon3gppAbsentSubscriberDiagSM      *v21_map_er_datatypes.ERAbsentSubscriberDiagnosticSM             `asn1:"tag:17,context,implicit,optional" json:"SmsfNon3gppAbsentSubscriberDiagSM,omitempty"`
	ExtCount_                              int64                                                            `asn1:"-" json:"-"`
	ExtPresent_                            []bool                                                           `asn1:"-" json:"-"`
	ExtData_                               [][]byte                                                         `asn1:"-" json:"-"`
	berReplayNode_                         *ber.ReplayNode                                                  `asn1:"-" json:"-"`
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
	StoredMSISDN       *v21_map_commondatatypes.CommonDataTypesISDNAddressString        `asn1:",optional" json:"StoredMSISDN,omitempty"`
	ExtensionContainer *v21_map_extensiondatatypes.ExtensionDataTypesExtensionContainer `asn1:",optional" json:"ExtensionContainer,omitempty"`
	ExtCount_          int64                                                            `asn1:"-" json:"-"`
	ExtPresent_        []bool                                                           `asn1:"-" json:"-"`
	ExtData_           [][]byte                                                         `asn1:"-" json:"-"`
	berReplayNode_     *ber.ReplayNode                                                  `asn1:"-" json:"-"`
}

// SMAlertServiceCentreArg represents the ASN.1 type AlertServiceCentreArg (SEQUENCE).
type SMAlertServiceCentreArg struct {
	Msisdn                    v21_map_commondatatypes.CommonDataTypesISDNAddressString           `asn1:""`
	ServiceCentreAddress      v21_map_commondatatypes.CommonDataTypesAddressString               `asn1:""`
	Imsi                      *v21_map_commondatatypes.CommonDataTypesIMSI                       `asn1:",optional" json:"Imsi,omitempty"`
	CorrelationID             *SMCorrelationID                                                   `asn1:",optional" json:"CorrelationID,omitempty"`
	MaximumUeAvailabilityTime *v21_map_commondatatypes.CommonDataTypesTime                       `asn1:"tag:0,context,implicit,optional" json:"MaximumUeAvailabilityTime,omitempty"`
	SmsGmscAlertEvent         *SMSmsGmscAlertEvent                                               `asn1:"tag:1,context,implicit,optional" json:"SmsGmscAlertEvent,omitempty"`
	SmsGmscDiameterAddress    *v21_map_commondatatypes.CommonDataTypesNetworkNodeDiameterAddress `asn1:"tag:2,context,implicit,optional" json:"SmsGmscDiameterAddress,omitempty"`
	NewSGSNNumber             *v21_map_commondatatypes.CommonDataTypesISDNAddressString          `asn1:"tag:3,context,implicit,optional" json:"NewSGSNNumber,omitempty"`
	NewSGSNDiameterAddress    *v21_map_commondatatypes.CommonDataTypesNetworkNodeDiameterAddress `asn1:"tag:4,context,implicit,optional" json:"NewSGSNDiameterAddress,omitempty"`
	NewMMENumber              *v21_map_commondatatypes.CommonDataTypesISDNAddressString          `asn1:"tag:5,context,implicit,optional" json:"NewMMENumber,omitempty"`
	NewMMEDiameterAddress     *v21_map_commondatatypes.CommonDataTypesNetworkNodeDiameterAddress `asn1:"tag:6,context,implicit,optional" json:"NewMMEDiameterAddress,omitempty"`
	NewMSCNumber              *v21_map_commondatatypes.CommonDataTypesISDNAddressString          `asn1:"tag:7,context,implicit,optional" json:"NewMSCNumber,omitempty"`
	ExtCount_                 int64                                                              `asn1:"-" json:"-"`
	ExtPresent_               []bool                                                             `asn1:"-" json:"-"`
	ExtData_                  [][]byte                                                           `asn1:"-" json:"-"`
	berReplayNode_            *ber.ReplayNode                                                    `asn1:"-" json:"-"`
}

// SMSmsGmscAlertEvent represents the ASN.1 ENUMERATED type SmsGmsc-Alert-Event.
type SMSmsGmscAlertEvent int64

const (
	SMSmsGmscAlertEventMsAvailableForMtSms   SMSmsGmscAlertEvent = 0
	SMSmsGmscAlertEventMsUnderNewServingNode SMSmsGmscAlertEvent = 1
)

func (v SMSmsGmscAlertEvent) String() string {
	switch v {
	case SMSmsGmscAlertEventMsAvailableForMtSms:
		return "msAvailableForMtSms"
	case SMSmsGmscAlertEventMsUnderNewServingNode:
		return "msUnderNewServingNode"
	default:
		return "unknown"
	}
}

// SMInformServiceCentreArg represents the ASN.1 type InformServiceCentreArg (SEQUENCE).
type SMInformServiceCentreArg struct {
	StoredMSISDN                            *v21_map_commondatatypes.CommonDataTypesISDNAddressString        `asn1:",optional" json:"StoredMSISDN,omitempty"`
	MwStatus                                *SMMWStatus                                                      `asn1:",optional" json:"MwStatus,omitempty"`
	ExtensionContainer                      *v21_map_extensiondatatypes.ExtensionDataTypesExtensionContainer `asn1:",optional" json:"ExtensionContainer,omitempty"`
	AbsentSubscriberDiagnosticSM            *v21_map_er_datatypes.ERAbsentSubscriberDiagnosticSM             `asn1:",optional" json:"AbsentSubscriberDiagnosticSM,omitempty"`
	AdditionalAbsentSubscriberDiagnosticSM  *v21_map_er_datatypes.ERAbsentSubscriberDiagnosticSM             `asn1:"tag:0,context,implicit,optional" json:"AdditionalAbsentSubscriberDiagnosticSM,omitempty"`
	Smsf3gppAbsentSubscriberDiagnosticSM    *v21_map_er_datatypes.ERAbsentSubscriberDiagnosticSM             `asn1:"tag:1,context,implicit,optional" json:"Smsf3gppAbsentSubscriberDiagnosticSM,omitempty"`
	SmsfNon3gppAbsentSubscriberDiagnosticSM *v21_map_er_datatypes.ERAbsentSubscriberDiagnosticSM             `asn1:"tag:2,context,implicit,optional" json:"SmsfNon3gppAbsentSubscriberDiagnosticSM,omitempty"`
	ExtCount_                               int64                                                            `asn1:"-" json:"-"`
	ExtPresent_                             []bool                                                           `asn1:"-" json:"-"`
	ExtData_                                [][]byte                                                         `asn1:"-" json:"-"`
	berReplayNode_                          *ber.ReplayNode                                                  `asn1:"-" json:"-"`
}

// SMMWStatus represents the ASN.1 type MW-Status (BIT_STRING).
type SMMWStatus = runtime.BitString

const (
	// SMMWStatusScAddressNotIncluded is position 0 of ASN.1 named bit sc-AddressNotIncluded of MW-Status (ITU-T X.680 (02/2021) §22).
	SMMWStatusScAddressNotIncluded = 0
	// SMMWStatusMnrfSet is position 1 of ASN.1 named bit mnrf-Set of MW-Status (ITU-T X.680 (02/2021) §22).
	SMMWStatusMnrfSet = 1
	// SMMWStatusMcefSet is position 2 of ASN.1 named bit mcef-Set of MW-Status (ITU-T X.680 (02/2021) §22).
	SMMWStatusMcefSet = 2
	// SMMWStatusMnrgSet is position 3 of ASN.1 named bit mnrg-Set of MW-Status (ITU-T X.680 (02/2021) §22).
	SMMWStatusMnrgSet = 3
	// SMMWStatusMnr5gSet is position 4 of ASN.1 named bit mnr5g-Set of MW-Status (ITU-T X.680 (02/2021) §22).
	SMMWStatusMnr5gSet = 4
	// SMMWStatusMnr5gn3gSet is position 5 of ASN.1 named bit mnr5gn3g-Set of MW-Status (ITU-T X.680 (02/2021) §22).
	SMMWStatusMnr5gn3gSet = 5
)

// SMReadyForSMArg represents the ASN.1 type ReadyForSM-Arg (SEQUENCE).
type SMReadyForSMArg struct {
	Imsi                           v21_map_commondatatypes.CommonDataTypesIMSI                      `asn1:"tag:0,context,implicit"`
	AlertReason                    SMAlertReason                                                    `asn1:""`
	AlertReasonIndicator           *struct{}                                                        `asn1:",optional" json:"AlertReasonIndicator,omitempty"`
	ExtensionContainer             *v21_map_extensiondatatypes.ExtensionDataTypesExtensionContainer `asn1:",optional" json:"ExtensionContainer,omitempty"`
	AdditionalAlertReasonIndicator *struct{}                                                        `asn1:"tag:1,context,implicit,optional" json:"AdditionalAlertReasonIndicator,omitempty"`
	MaximumUeAvailabilityTime      *v21_map_commondatatypes.CommonDataTypesTime                     `asn1:",optional" json:"MaximumUeAvailabilityTime,omitempty"`
	ExtCount_                      int64                                                            `asn1:"-" json:"-"`
	ExtPresent_                    []bool                                                           `asn1:"-" json:"-"`
	ExtData_                       [][]byte                                                         `asn1:"-" json:"-"`
	berReplayNode_                 *ber.ReplayNode                                                  `asn1:"-" json:"-"`
}

// SMReadyForSMRes represents the ASN.1 type ReadyForSM-Res (SEQUENCE).
type SMReadyForSMRes struct {
	ExtensionContainer *v21_map_extensiondatatypes.ExtensionDataTypesExtensionContainer `asn1:",optional" json:"ExtensionContainer,omitempty"`
	ExtCount_          int64                                                            `asn1:"-" json:"-"`
	ExtPresent_        []bool                                                           `asn1:"-" json:"-"`
	ExtData_           [][]byte                                                         `asn1:"-" json:"-"`
	berReplayNode_     *ber.ReplayNode                                                  `asn1:"-" json:"-"`
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
	AsciCallReference  v21_map_commondatatypes.CommonDataTypesASCICallReference         `asn1:""`
	SmRPOA             SMSMRPOA                                                         `asn1:""`
	SmRPUI             v21_map_commondatatypes.CommonDataTypesSignalInfo                `asn1:""`
	ExtensionContainer *v21_map_extensiondatatypes.ExtensionDataTypesExtensionContainer `asn1:",optional" json:"ExtensionContainer,omitempty"`
	ExtCount_          int64                                                            `asn1:"-" json:"-"`
	ExtPresent_        []bool                                                           `asn1:"-" json:"-"`
	ExtData_           [][]byte                                                         `asn1:"-" json:"-"`
	berReplayNode_     *ber.ReplayNode                                                  `asn1:"-" json:"-"`
}

// SMMTForwardSMVGCSRes represents the ASN.1 type MT-ForwardSM-VGCS-Res (SEQUENCE).
type SMMTForwardSMVGCSRes struct {
	SmRPUI                         *v21_map_commondatatypes.CommonDataTypesSignalInfo               `asn1:"tag:0,context,implicit,optional" json:"SmRPUI,omitempty"`
	DispatcherList                 *SMDispatcherList                                                `asn1:"tag:1,context,implicit,optional" json:"DispatcherList,omitempty"`
	DispatcherListIndef_           bool                                                             `asn1:"-" json:"-"`
	OngoingCall                    *struct{}                                                        `asn1:",optional" json:"OngoingCall,omitempty"`
	ExtensionContainer             *v21_map_extensiondatatypes.ExtensionDataTypesExtensionContainer `asn1:"tag:2,context,implicit,optional" json:"ExtensionContainer,omitempty"`
	AdditionalDispatcherList       *SMAdditionalDispatcherList                                      `asn1:"tag:3,context,implicit,optional" json:"AdditionalDispatcherList,omitempty"`
	AdditionalDispatcherListIndef_ bool                                                             `asn1:"-" json:"-"`
	ExtCount_                      int64                                                            `asn1:"-" json:"-"`
	ExtPresent_                    []bool                                                           `asn1:"-" json:"-"`
	ExtData_                       [][]byte                                                         `asn1:"-" json:"-"`
	berReplayNode_                 *ber.ReplayNode                                                  `asn1:"-" json:"-"`
}

// SMDispatcherList represents the ASN.1 type DispatcherList (SEQUENCE_OF).
type SMDispatcherList struct {
	Values         []v21_map_commondatatypes.CommonDataTypesISDNAddressString `json:"Values"`
	berReplayNode_ *ber.ReplayNode                                            `json:"-"`
}

// SMAdditionalDispatcherList represents the ASN.1 type AdditionalDispatcherList (SEQUENCE_OF).
type SMAdditionalDispatcherList struct {
	Values         []v21_map_commondatatypes.CommonDataTypesISDNAddressString `json:"Values"`
	berReplayNode_ *ber.ReplayNode                                            `json:"-"`
}

// MarshalBER encodes SMRoutingInfoForSMArg to BER format.
func (v *SMRoutingInfoForSMArg) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: SMRoutingInfoForSMArg receiver is nil", ber.ErrInvalidValue)
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
func (v *SMRoutingInfoForSMArg) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if len(v.Msisdn) < 1 || len(v.Msisdn) > 9 {
		if constraintErr := ber.CheckEncodedLength(opts, "msisdn", "SIZE (1..9)", len(v.Msisdn)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	if len(v.Msisdn) < 1 || len(v.Msisdn) > 20 {
		if constraintErr := ber.CheckEncodedLength(opts, "msisdn", "SIZE (1..20)", len(v.Msisdn)); constraintErr != nil {
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
	if ber.BERReplayEnabled(opts) && v.SmRPPRIRaw_ != 0 && v.SmRPPRI {
		enc_smrppri = ber.EncodeBooleanRaw(v.SmRPPRIRaw_)
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
		if constraintErr := ber.CheckEncodedLength(opts, "serviceCentreAddress", "SIZE (1..20)", len(v.ServiceCentreAddress)); constraintErr != nil {
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
			if constraintErr := ber.CheckEncodedValue(opts, "sm-RP-MTI", "(0..10)", fmt.Sprint(int64(*v.SmRPMTI))); constraintErr != nil {
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
			if constraintErr := ber.CheckEncodedLength(opts, "sm-RP-SMEA", "SIZE (1..12)", len(*v.SmRPSMEA)); constraintErr != nil {
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
			if constraintErr := ber.CheckEncodedLength(opts, "imsi", "SIZE (3..8)", len(*v.Imsi)); constraintErr != nil {
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
	for i, ext := range v.ExtData_ {
		if err := ber.CheckBEROpaqueReplay(opts...); err != nil {
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
		if i == 0 && ((peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 16) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 15) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 13) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 14) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 12) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 11) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 10) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 9) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 8) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 7) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 6)) {
			if constraintErr := ber.CheckEncodedValue(opts, "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
				return nil, constraintErr
			}
		}
		children = append(children, ext...)
	}
	ber.RecordGeneratedBERContainer(opts, children)
	return ber.EncodeSequence(children)
}
func (v *SMRoutingInfoForSMArg) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// MarshalDER encodes SMRoutingInfoForSMArg to DER format.
func (v *SMRoutingInfoForSMArg) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: SMRoutingInfoForSMArg receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if len(v.Msisdn) < 1 || len(v.Msisdn) > 9 {
		if constraintErr := ber.CheckEncodedLength(nil, "msisdn", "SIZE (1..9)", len(v.Msisdn)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	if len(v.Msisdn) < 1 || len(v.Msisdn) > 20 {
		if constraintErr := ber.CheckEncodedLength(nil, "msisdn", "SIZE (1..20)", len(v.Msisdn)); constraintErr != nil {
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
		if constraintErr := ber.CheckEncodedLength(nil, "serviceCentreAddress", "SIZE (1..20)", len(v.ServiceCentreAddress)); constraintErr != nil {
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
			if constraintErr := ber.CheckEncodedValue(nil, "sm-RP-MTI", "(0..10)", fmt.Sprint(int64(*v.SmRPMTI))); constraintErr != nil {
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
			if constraintErr := ber.CheckEncodedLength(nil, "sm-RP-SMEA", "SIZE (1..12)", len(*v.SmRPSMEA)); constraintErr != nil {
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
			if constraintErr := ber.CheckEncodedLength(nil, "imsi", "SIZE (3..8)", len(*v.Imsi)); constraintErr != nil {
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
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
		peekTag, _, _, extErr := ber.DecodeEncodedTLV(ext)
		if extErr != nil {
			return nil, extErr
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: only the first addition is restricted.
		if i == 0 && ((peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 16) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 15) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 13) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 14) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 12) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 11) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 10) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 9) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 8) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 7) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 6)) {
			if constraintErr := ber.CheckEncodedValue(nil, "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
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
		return nil, fmt.Errorf("%s: %w", "encoding SMRoutingInfoForSMArg as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}
func (v *SMRoutingInfoForSMArg) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	encoded, err := v.MarshalDER()
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBER decodes SMRoutingInfoForSMArg from BER/DER format.
func (v *SMRoutingInfoForSMArg) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: SMRoutingInfoForSMArg destination is nil", ber.ErrInvalidValue)
	}
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
			var probe SMRoutingInfoForSMArg
			return probe.UnmarshalBER(data, probeOpts...)
		})
	}
	data, opts = preparedData, preparedOptions
	*v = SMRoutingInfoForSMArg{}
	defer func() {
		if returnErr != nil || !ber.BERNeedsPreservation(opts) {
			return
		}
		v.berReplayNode_ = ber.CaptureGeneratedBERReplay(data, opts)
		returnErr = ber.CompleteGeneratedBERDecode(opts, v, func(base *SMRoutingInfoForSMArg, replayOpts ...ber.EncodeOption) ([]byte, error) {
			return base.MarshalBER(replayOpts...)
		})
	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("%s: %w", "decoding SMRoutingInfoForSMArg SEQUENCE", qualifyBERError(err, "", "decoding", false))
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
		v.Msisdn = v21_map_commondatatypes.CommonDataTypesISDNAddressString(decVal_msisdn)
		if offset > len(content) || n_msisdn < 0 || n_msisdn > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n_msisdn
		if len(v.Msisdn) < 1 || len(v.Msisdn) > 9 {
			if constraintErr := ber.CheckDecodedLength(opts, "msisdn", "SIZE (1..9)", len(v.Msisdn)); constraintErr != nil {
				return constraintErr
			}
		}
		if len(v.Msisdn) < 1 || len(v.Msisdn) > 20 {
			if constraintErr := ber.CheckDecodedLength(opts, "msisdn", "SIZE (1..20)", len(v.Msisdn)); constraintErr != nil {
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
			v.SmRPPRIRaw_ = rawVal_smrppri[0]
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
		v.ServiceCentreAddress = v21_map_commondatatypes.CommonDataTypesAddressString(decVal_servicecentreaddress)
		if offset < 0 || offset >
			len(content) || n_servicecentreaddress < 0 || n_servicecentreaddress >
			len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n_servicecentreaddress
		if len(v.ServiceCentreAddress) < 1 || len(v.ServiceCentreAddress) > 20 {
			if constraintErr := ber.CheckDecodedLength(opts, "serviceCentreAddress", "SIZE (1..20)", len(v.ServiceCentreAddress)); constraintErr != nil {
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
				tmp_smrpmti := SMSMRPMTI(decVal_smrpmti)
				v.SmRPMTI = &tmp_smrpmti
				if offset < 0 || offset >
					len(content) || n_smrpmti < 0 || n_smrpmti > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_smrpmti
				if !(int64(*v.SmRPMTI) >= 0 && int64(*v.SmRPMTI) <= 10) {
					if constraintErr := ber.CheckDecodedValue(opts, "sm-RP-MTI", "(0..10)", fmt.Sprint(int64(*v.SmRPMTI))); constraintErr != nil {
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
				tmp_smrpsmea := SMSMRPSMEA(decVal_smrpsmea)
				v.SmRPSMEA = &tmp_smrpsmea
				if offset < 0 || offset >
					len(content) || n_smrpsmea < 0 || n_smrpsmea > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_smrpsmea
				if len(*v.SmRPSMEA) < 1 || len(*v.SmRPSMEA) > 12 {
					if constraintErr := ber.CheckDecodedLength(opts, "sm-RP-SMEA", "SIZE (1..12)", len(*v.SmRPSMEA)); constraintErr != nil {
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
				tmp_smdeliverynotintended := SMSMDeliveryNotIntended(decVal_smdeliverynotintended)
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
				tmp_imsi := v21_map_commondatatypes.CommonDataTypesIMSI(decVal_imsi)
				v.Imsi = &tmp_imsi
				if offset < 0 || offset >
					len(content) || n_imsi < 0 || n_imsi > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_imsi
				if len(*v.Imsi) < 3 || len(*v.Imsi) > 8 {
					if constraintErr := ber.CheckDecodedLength(opts, "imsi", "SIZE (3..8)", len(*v.Imsi)); constraintErr != nil {
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
				var dec_correlationid SMCorrelationID
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
			return &ber.DecodeError{Offset: offset, TypeName: "SMRoutingInfoForSMArg", Cause: extErr_}
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: the first unknown addition must differ from trailing OPTIONAL/DEFAULT tags.
		if len(v.ExtData_) == 0 && ((peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 16) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 15) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 13) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 14) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 12) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 11) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 10) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 9) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 8) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 7) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 6)) {
			if !ber.ConstraintToleranceEnabled(opts) {
				return &ber.DecodeError{Offset: offset, TypeName: "SMRoutingInfoForSMArg", Cause: fmt.Errorf("%w: repeated or out-of-order SEQUENCE component tag %s", ber.ErrInvalidTag, peekTag)}
			}
			if orderErr_ := ber.CheckDecodedValue(opts, fmt.Sprintf("ExtData_[%d]", len(v.ExtData_)), "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); orderErr_ != nil {
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

// MarshalBER encodes SMRoutingInfoForSMRes to BER format.
func (v *SMRoutingInfoForSMRes) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: SMRoutingInfoForSMRes receiver is nil", ber.ErrInvalidValue)
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
func (v *SMRoutingInfoForSMRes) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if len(v.Imsi) < 3 || len(v.Imsi) > 8 {
		if constraintErr := ber.CheckEncodedLength(opts, "imsi", "SIZE (3..8)", len(v.Imsi)); constraintErr != nil {
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
	for i, ext := range v.ExtData_ {
		if err := ber.CheckBEROpaqueReplay(opts...); err != nil {
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
		if i == 0 && ((peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 5) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4)) {
			if constraintErr := ber.CheckEncodedValue(opts, "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
				return nil, constraintErr
			}
		}
		children = append(children, ext...)
	}
	ber.RecordGeneratedBERContainer(opts, children)
	return ber.EncodeSequence(children)
}
func (v *SMRoutingInfoForSMRes) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// MarshalDER encodes SMRoutingInfoForSMRes to DER format.
func (v *SMRoutingInfoForSMRes) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: SMRoutingInfoForSMRes receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if len(v.Imsi) < 3 || len(v.Imsi) > 8 {
		if constraintErr := ber.CheckEncodedLength(nil, "imsi", "SIZE (3..8)", len(v.Imsi)); constraintErr != nil {
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
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
		peekTag, _, _, extErr := ber.DecodeEncodedTLV(ext)
		if extErr != nil {
			return nil, extErr
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: only the first addition is restricted.
		if i == 0 && ((peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 5) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4)) {
			if constraintErr := ber.CheckEncodedValue(nil, "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
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
		return nil, fmt.Errorf("%s: %w", "encoding SMRoutingInfoForSMRes as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}
func (v *SMRoutingInfoForSMRes) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	encoded, err := v.MarshalDER()
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBER decodes SMRoutingInfoForSMRes from BER/DER format.
func (v *SMRoutingInfoForSMRes) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: SMRoutingInfoForSMRes destination is nil", ber.ErrInvalidValue)
	}
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
			var probe SMRoutingInfoForSMRes
			return probe.UnmarshalBER(data, probeOpts...)
		})
	}
	data, opts = preparedData, preparedOptions
	*v = SMRoutingInfoForSMRes{}
	defer func() {
		if returnErr != nil || !ber.BERNeedsPreservation(opts) {
			return
		}
		v.berReplayNode_ = ber.CaptureGeneratedBERReplay(data, opts)
		returnErr = ber.CompleteGeneratedBERDecode(opts, v, func(base *SMRoutingInfoForSMRes, replayOpts ...ber.EncodeOption) ([]byte, error) {
			return base.MarshalBER(replayOpts...)
		})
	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("%s: %w", "decoding SMRoutingInfoForSMRes SEQUENCE", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "SMRoutingInfoForSMRes", Cause: ber.ErrExtraData}
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
		v.Imsi = v21_map_commondatatypes.CommonDataTypesIMSI(val_imsi)
		if offset > len(content) || n < 0 || n > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n
		if len(v.Imsi) < 3 || len(v.Imsi) > 8 {
			if constraintErr := ber.CheckDecodedLength(opts, "imsi", "SIZE (3..8)", len(v.Imsi)); constraintErr != nil {
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
				var dec_ipsmgwguidance SMIPSMGWGuidance
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
			return &ber.DecodeError{Offset: offset, TypeName: "SMRoutingInfoForSMRes", Cause: extErr_}
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: the first unknown addition must differ from trailing OPTIONAL/DEFAULT tags.
		if len(v.ExtData_) == 0 && ((peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 5) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4)) {
			if !ber.ConstraintToleranceEnabled(opts) {
				return &ber.DecodeError{Offset: offset, TypeName: "SMRoutingInfoForSMRes", Cause: fmt.Errorf("%w: repeated or out-of-order SEQUENCE component tag %s", ber.ErrInvalidTag, peekTag)}
			}
			if orderErr_ := ber.CheckDecodedValue(opts, fmt.Sprintf("ExtData_[%d]", len(v.ExtData_)), "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); orderErr_ != nil {
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

// MarshalBER encodes SMIPSMGWGuidance to BER format.
func (v *SMIPSMGWGuidance) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: SMIPSMGWGuidance receiver is nil", ber.ErrInvalidValue)
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
func (v *SMIPSMGWGuidance) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if !(int64(v.MinimumDeliveryTimeValue) >= 30 && int64(v.MinimumDeliveryTimeValue) <= 600) {
		if constraintErr := ber.CheckEncodedValue(opts, "minimumDeliveryTimeValue", "(30..600)", fmt.Sprint(int64(v.MinimumDeliveryTimeValue))); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_minimumdeliverytimevalue := ber.EncodeInteger(int64(v.MinimumDeliveryTimeValue))
	children = append(children, enc_minimumdeliverytimevalue...)
	if !(int64(v.RecommendedDeliveryTimeValue) >= 30 && int64(v.RecommendedDeliveryTimeValue) <= 600) {
		if constraintErr := ber.CheckEncodedValue(opts, "recommendedDeliveryTimeValue", "(30..600)", fmt.Sprint(int64(v.RecommendedDeliveryTimeValue))); constraintErr != nil {
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
	for i, ext := range v.ExtData_ {
		if err := ber.CheckBEROpaqueReplay(opts...); err != nil {
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
		if i == 0 && (peekTag.Class == tag.ClassUniversal && peekTag.Number == 16) {
			if constraintErr := ber.CheckEncodedValue(opts, "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
				return nil, constraintErr
			}
		}
		children = append(children, ext...)
	}
	ber.RecordGeneratedBERContainer(opts, children)
	return ber.EncodeSequence(children)
}
func (v *SMIPSMGWGuidance) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// MarshalDER encodes SMIPSMGWGuidance to DER format.
func (v *SMIPSMGWGuidance) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: SMIPSMGWGuidance receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if !(int64(v.MinimumDeliveryTimeValue) >= 30 && int64(v.MinimumDeliveryTimeValue) <= 600) {
		if constraintErr := ber.CheckEncodedValue(nil, "minimumDeliveryTimeValue", "(30..600)", fmt.Sprint(int64(v.MinimumDeliveryTimeValue))); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_minimumdeliverytimevalue := ber.EncodeInteger(int64(v.MinimumDeliveryTimeValue))
	children = append(children, enc_minimumdeliverytimevalue...)
	if !(int64(v.RecommendedDeliveryTimeValue) >= 30 && int64(v.RecommendedDeliveryTimeValue) <= 600) {
		if constraintErr := ber.CheckEncodedValue(nil, "recommendedDeliveryTimeValue", "(30..600)", fmt.Sprint(int64(v.RecommendedDeliveryTimeValue))); constraintErr != nil {
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
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
		peekTag, _, _, extErr := ber.DecodeEncodedTLV(ext)
		if extErr != nil {
			return nil, extErr
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: only the first addition is restricted.
		if i == 0 && (peekTag.Class == tag.ClassUniversal && peekTag.Number == 16) {
			if constraintErr := ber.CheckEncodedValue(nil, "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
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
		return nil, fmt.Errorf("%s: %w", "encoding SMIPSMGWGuidance as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}
func (v *SMIPSMGWGuidance) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	encoded, err := v.MarshalDER()
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBER decodes SMIPSMGWGuidance from BER/DER format.
func (v *SMIPSMGWGuidance) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: SMIPSMGWGuidance destination is nil", ber.ErrInvalidValue)
	}
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
			var probe SMIPSMGWGuidance
			return probe.UnmarshalBER(data, probeOpts...)
		})
	}
	data, opts = preparedData, preparedOptions
	*v = SMIPSMGWGuidance{}
	defer func() {
		if returnErr != nil || !ber.BERNeedsPreservation(opts) {
			return
		}
		v.berReplayNode_ = ber.CaptureGeneratedBERReplay(data, opts)
		returnErr = ber.CompleteGeneratedBERDecode(opts, v, func(base *SMIPSMGWGuidance, replayOpts ...ber.EncodeOption) ([]byte, error) {
			return base.MarshalBER(replayOpts...)
		})
	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("%s: %w", "decoding SMIPSMGWGuidance SEQUENCE", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "SMIPSMGWGuidance", Cause: ber.ErrExtraData}
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
		v.MinimumDeliveryTimeValue = SMSMDeliveryTimerValue(val_minimumdeliverytimevalue)
		if offset > len(content) || n < 0 || n > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n
		if !(int64(v.MinimumDeliveryTimeValue) >= 30 && int64(v.MinimumDeliveryTimeValue) <= 600) {
			if constraintErr := ber.CheckDecodedValue(opts, "minimumDeliveryTimeValue", "(30..600)", fmt.Sprint(int64(v.MinimumDeliveryTimeValue))); constraintErr != nil {
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
		v.RecommendedDeliveryTimeValue = SMSMDeliveryTimerValue(val_recommendeddeliverytimevalue)
		if offset < 0 || offset >
			len(content) || n < 0 || n > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n
		if !(int64(v.RecommendedDeliveryTimeValue) >= 30 && int64(v.RecommendedDeliveryTimeValue) <= 600) {
			if constraintErr := ber.CheckDecodedValue(opts, "recommendedDeliveryTimeValue", "(30..600)", fmt.Sprint(int64(v.RecommendedDeliveryTimeValue))); constraintErr != nil {
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
				// Decode nested SEQUENCE (__asn1pkg_v21_map_extensiondatatypes.ExtensionDataTypesExtensionContainer)
				_, n_extensioncontainer, _, tlvErr_extensioncontainer := ber.DecodeTLV(content[offset:], opts...)
				if tlvErr_extensioncontainer != nil {
					return qualifyBERError(tlvErr_extensioncontainer, "extensionContainer", "decoding", false)
				}
				var dec_extensioncontainer v21_map_extensiondatatypes.ExtensionDataTypesExtensionContainer
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
			return &ber.DecodeError{Offset: offset, TypeName: "SMIPSMGWGuidance", Cause: extErr_}
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: the first unknown addition must differ from trailing OPTIONAL/DEFAULT tags.
		if len(v.ExtData_) == 0 && (peekTag.Class == tag.ClassUniversal && peekTag.Number == 16) {
			if !ber.ConstraintToleranceEnabled(opts) {
				return &ber.DecodeError{Offset: offset, TypeName: "SMIPSMGWGuidance", Cause: fmt.Errorf("%w: repeated or out-of-order SEQUENCE component tag %s", ber.ErrInvalidTag, peekTag)}
			}
			if orderErr_ := ber.CheckDecodedValue(opts, fmt.Sprintf("ExtData_[%d]", len(v.ExtData_)), "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); orderErr_ != nil {
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

// MarshalBER encodes SMLocationInfoWithLMSI to BER format.
func (v *SMLocationInfoWithLMSI) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: SMLocationInfoWithLMSI receiver is nil", ber.ErrInvalidValue)
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
func (v *SMLocationInfoWithLMSI) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if len(v.NetworkNodeNumber) < 1 || len(v.NetworkNodeNumber) > 9 {
		if constraintErr := ber.CheckEncodedLength(opts, "networkNode-Number", "SIZE (1..9)", len(v.NetworkNodeNumber)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	if len(v.NetworkNodeNumber) < 1 || len(v.NetworkNodeNumber) > 20 {
		if constraintErr := ber.CheckEncodedLength(opts, "networkNode-Number", "SIZE (1..20)", len(v.NetworkNodeNumber)); constraintErr != nil {
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
			if constraintErr := ber.CheckEncodedLength(opts, "lmsi", "SIZE (4)", len(*v.Lmsi)); constraintErr != nil {
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
			if constraintErr := ber.CheckEncodedLength(opts, "smsf-3gpp-Number", "SIZE (1..9)", len(*v.Smsf3gppNumber)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		if len(*v.Smsf3gppNumber) < 1 || len(*v.Smsf3gppNumber) > 20 {
			if constraintErr := ber.CheckEncodedLength(opts, "smsf-3gpp-Number", "SIZE (1..20)", len(*v.Smsf3gppNumber)); constraintErr != nil {
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
			if constraintErr := ber.CheckEncodedLength(opts, "smsf-non-3gpp-Number", "SIZE (1..9)", len(*v.SmsfNon3gppNumber)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		if len(*v.SmsfNon3gppNumber) < 1 || len(*v.SmsfNon3gppNumber) > 20 {
			if constraintErr := ber.CheckEncodedLength(opts, "smsf-non-3gpp-Number", "SIZE (1..20)", len(*v.SmsfNon3gppNumber)); constraintErr != nil {
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
	for i, ext := range v.ExtData_ {
		if err := ber.CheckBEROpaqueReplay(opts...); err != nil {
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
		if i == 0 && ((peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 17) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 16) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 15) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 14) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 13) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 12) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 11) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 10) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 9) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 8) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 7) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 6) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 5) || (peekTag.Class == tag.ClassUniversal && peekTag.Number == 16) || (peekTag.Class == tag.ClassUniversal && peekTag.Number == 4)) {
			if constraintErr := ber.CheckEncodedValue(opts, "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
				return nil, constraintErr
			}
		}
		children = append(children, ext...)
	}
	ber.RecordGeneratedBERContainer(opts, children)
	return ber.EncodeSequence(children)
}
func (v *SMLocationInfoWithLMSI) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// MarshalDER encodes SMLocationInfoWithLMSI to DER format.
func (v *SMLocationInfoWithLMSI) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: SMLocationInfoWithLMSI receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if len(v.NetworkNodeNumber) < 1 || len(v.NetworkNodeNumber) > 9 {
		if constraintErr := ber.CheckEncodedLength(nil, "networkNode-Number", "SIZE (1..9)", len(v.NetworkNodeNumber)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	if len(v.NetworkNodeNumber) < 1 || len(v.NetworkNodeNumber) > 20 {
		if constraintErr := ber.CheckEncodedLength(nil, "networkNode-Number", "SIZE (1..20)", len(v.NetworkNodeNumber)); constraintErr != nil {
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
			if constraintErr := ber.CheckEncodedLength(nil, "lmsi", "SIZE (4)", len(*v.Lmsi)); constraintErr != nil {
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
			if constraintErr := ber.CheckEncodedLength(nil, "smsf-3gpp-Number", "SIZE (1..9)", len(*v.Smsf3gppNumber)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		if len(*v.Smsf3gppNumber) < 1 || len(*v.Smsf3gppNumber) > 20 {
			if constraintErr := ber.CheckEncodedLength(nil, "smsf-3gpp-Number", "SIZE (1..20)", len(*v.Smsf3gppNumber)); constraintErr != nil {
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
			if constraintErr := ber.CheckEncodedLength(nil, "smsf-non-3gpp-Number", "SIZE (1..9)", len(*v.SmsfNon3gppNumber)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		if len(*v.SmsfNon3gppNumber) < 1 || len(*v.SmsfNon3gppNumber) > 20 {
			if constraintErr := ber.CheckEncodedLength(nil, "smsf-non-3gpp-Number", "SIZE (1..20)", len(*v.SmsfNon3gppNumber)); constraintErr != nil {
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
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
		peekTag, _, _, extErr := ber.DecodeEncodedTLV(ext)
		if extErr != nil {
			return nil, extErr
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: only the first addition is restricted.
		if i == 0 && ((peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 17) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 16) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 15) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 14) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 13) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 12) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 11) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 10) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 9) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 8) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 7) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 6) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 5) || (peekTag.Class == tag.ClassUniversal && peekTag.Number == 16) || (peekTag.Class == tag.ClassUniversal && peekTag.Number == 4)) {
			if constraintErr := ber.CheckEncodedValue(nil, "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
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
		return nil, fmt.Errorf("%s: %w", "encoding SMLocationInfoWithLMSI as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}
func (v *SMLocationInfoWithLMSI) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	encoded, err := v.MarshalDER()
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBER decodes SMLocationInfoWithLMSI from BER/DER format.
func (v *SMLocationInfoWithLMSI) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: SMLocationInfoWithLMSI destination is nil", ber.ErrInvalidValue)
	}
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
			var probe SMLocationInfoWithLMSI
			return probe.UnmarshalBER(data, probeOpts...)
		})
	}
	data, opts = preparedData, preparedOptions
	*v = SMLocationInfoWithLMSI{}
	defer func() {
		if returnErr != nil || !ber.BERNeedsPreservation(opts) {
			return
		}
		v.berReplayNode_ = ber.CaptureGeneratedBERReplay(data, opts)
		returnErr = ber.CompleteGeneratedBERDecode(opts, v, func(base *SMLocationInfoWithLMSI, replayOpts ...ber.EncodeOption) ([]byte, error) {
			return base.MarshalBER(replayOpts...)
		})
	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("%s: %w", "decoding SMLocationInfoWithLMSI SEQUENCE", qualifyBERError(err, "", "decoding", false))
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
		v.NetworkNodeNumber = v21_map_commondatatypes.CommonDataTypesISDNAddressString(decVal_networknodenumber)
		if offset > len(content) || n_networknodenumber < 0 || n_networknodenumber > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n_networknodenumber
		if len(v.NetworkNodeNumber) < 1 || len(v.NetworkNodeNumber) > 9 {
			if constraintErr := ber.CheckDecodedLength(opts, "networkNode-Number", "SIZE (1..9)", len(v.NetworkNodeNumber)); constraintErr != nil {
				return constraintErr
			}
		}
		if len(v.NetworkNodeNumber) < 1 || len(v.NetworkNodeNumber) > 20 {
			if constraintErr := ber.CheckDecodedLength(opts, "networkNode-Number", "SIZE (1..20)", len(v.NetworkNodeNumber)); constraintErr != nil {
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
				tmp_lmsi := v21_map_commondatatypes.CommonDataTypesLMSI(val_lmsi)
				v.Lmsi = &tmp_lmsi
				if offset < 0 || offset >
					len(content) || n < 0 || n > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n
				if len(*v.Lmsi) < 4 || len(*v.Lmsi) > 4 {
					if constraintErr := ber.CheckDecodedLength(opts, "lmsi", "SIZE (4)", len(*v.Lmsi)); constraintErr != nil {
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
				// Decode nested SEQUENCE (__asn1pkg_v21_map_extensiondatatypes.ExtensionDataTypesExtensionContainer)
				_, n_extensioncontainer, _, tlvErr_extensioncontainer := ber.DecodeTLV(content[offset:], opts...)
				if tlvErr_extensioncontainer != nil {
					return qualifyBERError(tlvErr_extensioncontainer, "extensionContainer", "decoding", false)
				}
				var dec_extensioncontainer v21_map_extensiondatatypes.ExtensionDataTypesExtensionContainer
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
				var dec_additionalnumber SMAdditionalNumber
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
				var dec_networknodediameteraddress v21_map_commondatatypes.CommonDataTypesNetworkNodeDiameterAddress
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
					len(content) || n_additionalnetworknodediameteraddress < 0 || n_additionalnetworknodediameteraddress >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				reconstructed_additionalnetworknodediameteraddress, reconstructionErr_additionalnetworknodediameteraddress := ber.EncodeImplicitTagWithClass(tag.ClassUniversal, tag.TagSequence, content[offset:offset+n_additionalnetworknodediameteraddress])
				if reconstructionErr_additionalnetworknodediameteraddress != nil {
					return qualifyBERError(reconstructionErr_additionalnetworknodediameteraddress, "additionalNetworkNodeDiameterAddress", "decoding", false)
				}
				var dec_additionalnetworknodediameteraddress v21_map_commondatatypes.CommonDataTypesNetworkNodeDiameterAddress
				if unmErr := dec_additionalnetworknodediameteraddress.UnmarshalBER(reconstructed_additionalnetworknodediameteraddress, ber.ChildDecodeOptions(opts, "additionalNetworkNodeDiameterAddress")...); unmErr != nil {
					return qualifyBERError(unmErr, "additionalNetworkNodeDiameterAddress", "decoding", false)
				}
				v.AdditionalNetworkNodeDiameterAddress = &dec_additionalnetworknodediameteraddress
				if offset < 0 || offset >
					len(content) || n_additionalnetworknodediameteraddress < 0 || n_additionalnetworknodediameteraddress >
					len(content[offset:]) {
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
				var dec_thirdnumber SMAdditionalNumber
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
				var dec_thirdnetworknodediameteraddress v21_map_commondatatypes.CommonDataTypesNetworkNodeDiameterAddress
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
				tmp_smsf3gppnumber := v21_map_commondatatypes.CommonDataTypesISDNAddressString(decVal_smsf3gppnumber)
				v.Smsf3gppNumber = &tmp_smsf3gppnumber
				if offset < 0 || offset >
					len(content) || n_smsf3gppnumber < 0 || n_smsf3gppnumber > len(
					content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_smsf3gppnumber
				if len(*v.Smsf3gppNumber) < 1 || len(*v.Smsf3gppNumber) > 9 {
					if constraintErr := ber.CheckDecodedLength(opts, "smsf-3gpp-Number", "SIZE (1..9)", len(*v.Smsf3gppNumber)); constraintErr != nil {
						return constraintErr
					}
				}
				if len(*v.Smsf3gppNumber) < 1 || len(*v.Smsf3gppNumber) > 20 {
					if constraintErr := ber.CheckDecodedLength(opts, "smsf-3gpp-Number", "SIZE (1..20)", len(*v.Smsf3gppNumber)); constraintErr != nil {
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
				var dec_smsf3gppdiameteraddress v21_map_commondatatypes.CommonDataTypesNetworkNodeDiameterAddress
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
				tmp_smsfnon3gppnumber := v21_map_commondatatypes.CommonDataTypesISDNAddressString(decVal_smsfnon3gppnumber)
				v.SmsfNon3gppNumber = &tmp_smsfnon3gppnumber
				if offset < 0 || offset >
					len(content) || n_smsfnon3gppnumber < 0 || n_smsfnon3gppnumber >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_smsfnon3gppnumber
				if len(*v.SmsfNon3gppNumber) < 1 || len(*v.SmsfNon3gppNumber) > 9 {
					if constraintErr := ber.CheckDecodedLength(opts, "smsf-non-3gpp-Number", "SIZE (1..9)", len(*v.SmsfNon3gppNumber)); constraintErr != nil {
						return constraintErr
					}
				}
				if len(*v.SmsfNon3gppNumber) < 1 || len(*v.SmsfNon3gppNumber) > 20 {
					if constraintErr := ber.CheckDecodedLength(opts, "smsf-non-3gpp-Number", "SIZE (1..20)", len(*v.SmsfNon3gppNumber)); constraintErr != nil {
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
				var dec_smsfnon3gppdiameteraddress v21_map_commondatatypes.CommonDataTypesNetworkNodeDiameterAddress
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
			return &ber.DecodeError{Offset: offset, TypeName: "SMLocationInfoWithLMSI", Cause: extErr_}
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: the first unknown addition must differ from trailing OPTIONAL/DEFAULT tags.
		if len(v.ExtData_) == 0 && ((peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 17) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 16) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 15) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 14) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 13) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 12) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 11) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 10) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 9) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 8) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 7) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 6) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 5) || (peekTag.Class == tag.ClassUniversal && peekTag.Number == 16) || (peekTag.Class == tag.ClassUniversal && peekTag.Number == 4)) {
			if !ber.ConstraintToleranceEnabled(opts) {
				return &ber.DecodeError{Offset: offset, TypeName: "SMLocationInfoWithLMSI", Cause: fmt.Errorf("%w: repeated or out-of-order SEQUENCE component tag %s", ber.ErrInvalidTag, peekTag)}
			}
			if orderErr_ := ber.CheckDecodedValue(opts, fmt.Sprintf("ExtData_[%d]", len(v.ExtData_)), "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); orderErr_ != nil {
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

// MarshalBER encodes SMAdditionalNumber to BER format.
func (v *SMAdditionalNumber) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: SMAdditionalNumber receiver is nil", ber.ErrInvalidValue)
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
func (v *SMAdditionalNumber) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}
func (v *SMAdditionalNumber) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	switch v.Choice {
	case SMAdditionalNumberChoiceMscNumber:
		if v.MscNumber == nil {
			return nil, fmt.Errorf("%w: choice SMAdditionalNumber: msc-Number is nil", ber.ErrInvalidValue)
		}
		enc_0, encodeErr_enc_0 := ber.EncodeOctetString([]byte(*v.MscNumber))
		if encodeErr_enc_0 != nil {
			return nil, qualifyBERError(encodeErr_enc_0, "msc-Number", "encoding", false)
		}
		if len(*v.MscNumber) < 1 || len(*v.MscNumber) > 9 {
			if constraintErr := ber.CheckEncodedLength(opts, "msc-Number", "SIZE (1..9)", len(*v.MscNumber)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		if len(*v.MscNumber) < 1 || len(*v.MscNumber) > 20 {
			if constraintErr := ber.CheckEncodedLength(opts, "msc-Number", "SIZE (1..20)", len(*v.MscNumber)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		retagged_enc_0, tagErr_enc_0 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_0)
		if tagErr_enc_0 != nil {
			return nil, qualifyBERError(tagErr_enc_0, "msc-Number", "encoding", false)
		}
		enc_0 = retagged_enc_0
		return enc_0, nil
	case SMAdditionalNumberChoiceSgsnNumber:
		if v.SgsnNumber == nil {
			return nil, fmt.Errorf("%w: choice SMAdditionalNumber: sgsn-Number is nil", ber.ErrInvalidValue)
		}
		enc_1, encodeErr_enc_1 := ber.EncodeOctetString([]byte(*v.SgsnNumber))
		if encodeErr_enc_1 != nil {
			return nil, qualifyBERError(encodeErr_enc_1, "sgsn-Number", "encoding", false)
		}
		if len(*v.SgsnNumber) < 1 || len(*v.SgsnNumber) > 9 {
			if constraintErr := ber.CheckEncodedLength(opts, "sgsn-Number", "SIZE (1..9)", len(*v.SgsnNumber)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		if len(*v.SgsnNumber) < 1 || len(*v.SgsnNumber) > 20 {
			if constraintErr := ber.CheckEncodedLength(opts, "sgsn-Number", "SIZE (1..20)", len(*v.SgsnNumber)); constraintErr != nil {
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
		return nil, fmt.Errorf("unknown choice %d for SMAdditionalNumber", v.Choice)
	}
}

// MarshalDER encodes SMAdditionalNumber to DER format.
func (v *SMAdditionalNumber) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: SMAdditionalNumber receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER()
	if err != nil {
		return nil, err
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		switch v.Choice {
		case SMAdditionalNumberChoiceMscNumber:
			return nil, qualifyBERError(err, "msc-Number", "encoding", true)
		case SMAdditionalNumberChoiceSgsnNumber:
			return nil, qualifyBERError(err, "sgsn-Number", "encoding", true)
		}
		return nil, fmt.Errorf("%s: %w", "encoding SMAdditionalNumber as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}

func (v *SMAdditionalNumber) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	encoded, err := v.MarshalDER()
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBER decodes SMAdditionalNumber from BER/DER format.
func (v *SMAdditionalNumber) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: SMAdditionalNumber destination is nil", ber.ErrInvalidValue)
	}
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
		returnErr = ber.CompleteGeneratedBERDecode(opts, v, func(base *SMAdditionalNumber, replayOpts ...ber.EncodeOption) ([]byte, error) {
			return base.MarshalBER(replayOpts...)
		})
	}()
	preparedData, preparedOptions, prepareErr := ber.PrepareGeneratedBERInput(data, opts)
	if prepareErr != nil {
		return ber.DiagnosePreflight(prepareErr, data, opts, "child", func(probeOpts []ber.DecodeOption) error {
			var probe SMAdditionalNumber
			return probe.UnmarshalBER(data, probeOpts...)
		})
	}
	data, opts = preparedData, preparedOptions
	*v = SMAdditionalNumber{}
	if len(data) == 0 {
		return fmt.Errorf("empty data for SMAdditionalNumber CHOICE")
	}
	choiceData := data
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for SMAdditionalNumber: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData, opts...)
	if tlvErr != nil {
		return fmt.Errorf("%s: %w", "decoding SMAdditionalNumber CHOICE", qualifyBERError(tlvErr, "", "decoding", false))
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "SMAdditionalNumber", Cause: ber.ErrExtraData}
	}

	if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
		v.Choice = SMAdditionalNumberChoiceMscNumber
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
			if constraintErr := ber.CheckDecodedLength(opts, "msc-Number", "SIZE (1..9)", len(*v.MscNumber)); constraintErr != nil {
				return constraintErr
			}
		}
		if len(*v.MscNumber) < 1 || len(*v.MscNumber) > 20 {
			if constraintErr := ber.CheckDecodedLength(opts, "msc-Number", "SIZE (1..20)", len(*v.MscNumber)); constraintErr != nil {
				return constraintErr
			}
		}
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
		v.Choice = SMAdditionalNumberChoiceSgsnNumber
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
			if constraintErr := ber.CheckDecodedLength(opts, "sgsn-Number", "SIZE (1..9)", len(*v.SgsnNumber)); constraintErr != nil {
				return constraintErr
			}
		}
		if len(*v.SgsnNumber) < 1 || len(*v.SgsnNumber) > 20 {
			if constraintErr := ber.CheckDecodedLength(opts, "sgsn-Number", "SIZE (1..20)", len(*v.SgsnNumber)); constraintErr != nil {
				return constraintErr
			}
		}
	} else {
		return fmt.Errorf("unknown tag %s for SMAdditionalNumber CHOICE", peekTag)
	}
	return nil
}

// MarshalBER encodes SMMOForwardSMArg to BER format.
func (v *SMMOForwardSMArg) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: SMMOForwardSMArg receiver is nil", ber.ErrInvalidValue)
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
func (v *SMMOForwardSMArg) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
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
		if constraintErr := ber.CheckEncodedLength(opts, "sm-RP-UI", "SIZE (1..200)", len(v.SmRPUI)); constraintErr != nil {
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
			if constraintErr := ber.CheckEncodedLength(opts, "imsi", "SIZE (3..8)", len(*v.Imsi)); constraintErr != nil {
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
			if constraintErr := ber.CheckEncodedValue(opts, "sm-DeliveryOutcome", "ENUMERATED {0, 1, 2}", fmt.Sprint(int64(*v.SmDeliveryOutcome))); constraintErr != nil {
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
	for i, ext := range v.ExtData_ {
		if err := ber.CheckBEROpaqueReplay(opts...); err != nil {
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
		if i == 0 && ((peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0) || (peekTag.Class == tag.ClassUniversal && peekTag.Number == 4) || (peekTag.Class == tag.ClassUniversal && peekTag.Number == 16)) {
			if constraintErr := ber.CheckEncodedValue(opts, "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
				return nil, constraintErr
			}
		}
		children = append(children, ext...)
	}
	ber.RecordGeneratedBERContainer(opts, children)
	return ber.EncodeSequence(children)
}
func (v *SMMOForwardSMArg) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// MarshalDER encodes SMMOForwardSMArg to DER format.
func (v *SMMOForwardSMArg) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: SMMOForwardSMArg receiver is nil", ber.ErrInvalidValue)
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
		if constraintErr := ber.CheckEncodedLength(nil, "sm-RP-UI", "SIZE (1..200)", len(v.SmRPUI)); constraintErr != nil {
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
			if constraintErr := ber.CheckEncodedLength(nil, "imsi", "SIZE (3..8)", len(*v.Imsi)); constraintErr != nil {
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
			if constraintErr := ber.CheckEncodedValue(nil, "sm-DeliveryOutcome", "ENUMERATED {0, 1, 2}", fmt.Sprint(int64(*v.SmDeliveryOutcome))); constraintErr != nil {
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
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
		peekTag, _, _, extErr := ber.DecodeEncodedTLV(ext)
		if extErr != nil {
			return nil, extErr
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: only the first addition is restricted.
		if i == 0 && ((peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0) || (peekTag.Class == tag.ClassUniversal && peekTag.Number == 4) || (peekTag.Class == tag.ClassUniversal && peekTag.Number == 16)) {
			if constraintErr := ber.CheckEncodedValue(nil, "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
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
		return nil, fmt.Errorf("%s: %w", "encoding SMMOForwardSMArg as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}
func (v *SMMOForwardSMArg) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	encoded, err := v.MarshalDER()
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBER decodes SMMOForwardSMArg from BER/DER format.
func (v *SMMOForwardSMArg) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: SMMOForwardSMArg destination is nil", ber.ErrInvalidValue)
	}
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
			var probe SMMOForwardSMArg
			return probe.UnmarshalBER(data, probeOpts...)
		})
	}
	data, opts = preparedData, preparedOptions
	*v = SMMOForwardSMArg{}
	defer func() {
		if returnErr != nil || !ber.BERNeedsPreservation(opts) {
			return
		}
		v.berReplayNode_ = ber.CaptureGeneratedBERReplay(data, opts)
		returnErr = ber.CompleteGeneratedBERDecode(opts, v, func(base *SMMOForwardSMArg, replayOpts ...ber.EncodeOption) ([]byte, error) {
			return base.MarshalBER(replayOpts...)
		})
	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("%s: %w", "decoding SMMOForwardSMArg SEQUENCE", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "SMMOForwardSMArg", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode sm-RP-DA
	if offset >= len(content) {
		return fmt.Errorf("missing required field sm-RP-DA")
	}
	{
		ber.MarkPreflightTarget(opts, "sm-RP-DA", content[offset:])
		// Decode nested CHOICE (SMSMRPDA)
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
		// Decode nested CHOICE (SMSMRPOA)
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
		v.SmRPUI = v21_map_commondatatypes.CommonDataTypesSignalInfo(val_smrpui)
		if offset < 0 || offset >
			len(content) || n < 0 || n > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n
		if len(v.SmRPUI) < 1 || len(v.SmRPUI) > 200 {
			if constraintErr := ber.CheckDecodedLength(opts, "sm-RP-UI", "SIZE (1..200)", len(v.SmRPUI)); constraintErr != nil {
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
				// Decode nested SEQUENCE (__asn1pkg_v21_map_extensiondatatypes.ExtensionDataTypesExtensionContainer)
				_, n_extensioncontainer, _, tlvErr_extensioncontainer := ber.DecodeTLV(content[offset:], opts...)
				if tlvErr_extensioncontainer != nil {
					return qualifyBERError(tlvErr_extensioncontainer, "extensionContainer", "decoding", false)
				}
				var dec_extensioncontainer v21_map_extensiondatatypes.ExtensionDataTypesExtensionContainer
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
				tmp_imsi := v21_map_commondatatypes.CommonDataTypesIMSI(val_imsi)
				v.Imsi = &tmp_imsi
				if offset < 0 || offset >
					len(content) || n < 0 || n > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n
				if len(*v.Imsi) < 3 || len(*v.Imsi) > 8 {
					if constraintErr := ber.CheckDecodedLength(opts, "imsi", "SIZE (3..8)", len(*v.Imsi)); constraintErr != nil {
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
				var dec_correlationid SMCorrelationID
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
				tmp_smdeliveryoutcome := SMSMDeliveryOutcome(decVal_smdeliveryoutcome)
				v.SmDeliveryOutcome = &tmp_smdeliveryoutcome
				if offset < 0 || offset >
					len(content) || n_smdeliveryoutcome < 0 || n_smdeliveryoutcome >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_smdeliveryoutcome
				if int64(*v.SmDeliveryOutcome) != 0 && int64(*v.SmDeliveryOutcome) != 1 && int64(*v.SmDeliveryOutcome) != 2 {
					if constraintErr := ber.CheckDecodedValue(opts, "sm-DeliveryOutcome", "ENUMERATED {0, 1, 2}", fmt.Sprint(int64(*v.SmDeliveryOutcome))); constraintErr != nil {
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
			return &ber.DecodeError{Offset: offset, TypeName: "SMMOForwardSMArg", Cause: extErr_}
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: the first unknown addition must differ from trailing OPTIONAL/DEFAULT tags.
		if len(v.ExtData_) == 0 && ((peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0) || (peekTag.Class == tag.ClassUniversal && peekTag.Number == 4) || (peekTag.Class == tag.ClassUniversal && peekTag.Number == 16)) {
			if !ber.ConstraintToleranceEnabled(opts) {
				return &ber.DecodeError{Offset: offset, TypeName: "SMMOForwardSMArg", Cause: fmt.Errorf("%w: repeated or out-of-order SEQUENCE component tag %s", ber.ErrInvalidTag, peekTag)}
			}
			if orderErr_ := ber.CheckDecodedValue(opts, fmt.Sprintf("ExtData_[%d]", len(v.ExtData_)), "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); orderErr_ != nil {
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

// MarshalBER encodes SMMOForwardSMRes to BER format.
func (v *SMMOForwardSMRes) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: SMMOForwardSMRes receiver is nil", ber.ErrInvalidValue)
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
func (v *SMMOForwardSMRes) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if v.SmRPUI != nil {
		if len(*v.SmRPUI) < 1 || len(*v.SmRPUI) > 200 {
			if constraintErr := ber.CheckEncodedLength(opts, "sm-RP-UI", "SIZE (1..200)", len(*v.SmRPUI)); constraintErr != nil {
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
	for i, ext := range v.ExtData_ {
		if err := ber.CheckBEROpaqueReplay(opts...); err != nil {
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
		if i == 0 && ((peekTag.Class == tag.ClassUniversal && peekTag.Number == 16) || (peekTag.Class == tag.ClassUniversal && peekTag.Number == 4)) {
			if constraintErr := ber.CheckEncodedValue(opts, "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
				return nil, constraintErr
			}
		}
		children = append(children, ext...)
	}
	ber.RecordGeneratedBERContainer(opts, children)
	return ber.EncodeSequence(children)
}
func (v *SMMOForwardSMRes) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// MarshalDER encodes SMMOForwardSMRes to DER format.
func (v *SMMOForwardSMRes) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: SMMOForwardSMRes receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if v.SmRPUI != nil {
		if len(*v.SmRPUI) < 1 || len(*v.SmRPUI) > 200 {
			if constraintErr := ber.CheckEncodedLength(nil, "sm-RP-UI", "SIZE (1..200)", len(*v.SmRPUI)); constraintErr != nil {
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
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
		peekTag, _, _, extErr := ber.DecodeEncodedTLV(ext)
		if extErr != nil {
			return nil, extErr
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: only the first addition is restricted.
		if i == 0 && ((peekTag.Class == tag.ClassUniversal && peekTag.Number == 16) || (peekTag.Class == tag.ClassUniversal && peekTag.Number == 4)) {
			if constraintErr := ber.CheckEncodedValue(nil, "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
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
		return nil, fmt.Errorf("%s: %w", "encoding SMMOForwardSMRes as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}
func (v *SMMOForwardSMRes) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	encoded, err := v.MarshalDER()
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBER decodes SMMOForwardSMRes from BER/DER format.
func (v *SMMOForwardSMRes) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: SMMOForwardSMRes destination is nil", ber.ErrInvalidValue)
	}
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
			var probe SMMOForwardSMRes
			return probe.UnmarshalBER(data, probeOpts...)
		})
	}
	data, opts = preparedData, preparedOptions
	*v = SMMOForwardSMRes{}
	defer func() {
		if returnErr != nil || !ber.BERNeedsPreservation(opts) {
			return
		}
		v.berReplayNode_ = ber.CaptureGeneratedBERReplay(data, opts)
		returnErr = ber.CompleteGeneratedBERDecode(opts, v, func(base *SMMOForwardSMRes, replayOpts ...ber.EncodeOption) ([]byte, error) {
			return base.MarshalBER(replayOpts...)
		})
	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("%s: %w", "decoding SMMOForwardSMRes SEQUENCE", qualifyBERError(err, "", "decoding", false))
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
				ber.MarkPreflightTarget(opts, "sm-RP-UI", content[offset:])
				val_smrpui, n, err := ber.DecodeOctetString(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "sm-RP-UI", "decoding", false)
				}
				tmp_smrpui := v21_map_commondatatypes.CommonDataTypesSignalInfo(val_smrpui)
				v.SmRPUI = &tmp_smrpui
				if offset > len(content) || n < 0 || n > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n
				if len(*v.SmRPUI) < 1 || len(*v.SmRPUI) > 200 {
					if constraintErr := ber.CheckDecodedLength(opts, "sm-RP-UI", "SIZE (1..200)", len(*v.SmRPUI)); constraintErr != nil {
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
				// Decode nested SEQUENCE (__asn1pkg_v21_map_extensiondatatypes.ExtensionDataTypesExtensionContainer)
				_, n_extensioncontainer, _, tlvErr_extensioncontainer := ber.DecodeTLV(content[offset:], opts...)
				if tlvErr_extensioncontainer != nil {
					return qualifyBERError(tlvErr_extensioncontainer, "extensionContainer", "decoding", false)
				}
				var dec_extensioncontainer v21_map_extensiondatatypes.ExtensionDataTypesExtensionContainer
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
			return &ber.DecodeError{Offset: offset, TypeName: "SMMOForwardSMRes", Cause: extErr_}
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: the first unknown addition must differ from trailing OPTIONAL/DEFAULT tags.
		if len(v.ExtData_) == 0 && ((peekTag.Class == tag.ClassUniversal && peekTag.Number == 16) || (peekTag.Class == tag.ClassUniversal && peekTag.Number == 4)) {
			if !ber.ConstraintToleranceEnabled(opts) {
				return &ber.DecodeError{Offset: offset, TypeName: "SMMOForwardSMRes", Cause: fmt.Errorf("%w: repeated or out-of-order SEQUENCE component tag %s", ber.ErrInvalidTag, peekTag)}
			}
			if orderErr_ := ber.CheckDecodedValue(opts, fmt.Sprintf("ExtData_[%d]", len(v.ExtData_)), "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); orderErr_ != nil {
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

// MarshalBER encodes SMMTForwardSMArg to BER format.
func (v *SMMTForwardSMArg) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: SMMTForwardSMArg receiver is nil", ber.ErrInvalidValue)
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
func (v *SMMTForwardSMArg) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
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
		if constraintErr := ber.CheckEncodedLength(opts, "sm-RP-UI", "SIZE (1..200)", len(v.SmRPUI)); constraintErr != nil {
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
			if constraintErr := ber.CheckEncodedValue(opts, "smDeliveryTimer", "(30..600)", fmt.Sprint(int64(*v.SmDeliveryTimer))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_smdeliverytimer := ber.EncodeInteger(int64(*v.SmDeliveryTimer))
		children = append(children, enc_smdeliverytimer...)
	}
	if v.SmDeliveryStartTime != nil {
		if len(*v.SmDeliveryStartTime) < 4 || len(*v.SmDeliveryStartTime) > 4 {
			if constraintErr := ber.CheckEncodedLength(opts, "smDeliveryStartTime", "SIZE (4)", len(*v.SmDeliveryStartTime)); constraintErr != nil {
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
			if constraintErr := ber.CheckEncodedLength(opts, "maximumRetransmissionTime", "SIZE (4)", len(*v.MaximumRetransmissionTime)); constraintErr != nil {
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
			if constraintErr := ber.CheckEncodedLength(opts, "smsGmscAddress", "SIZE (1..9)", len(*v.SmsGmscAddress)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		if len(*v.SmsGmscAddress) < 1 || len(*v.SmsGmscAddress) > 20 {
			if constraintErr := ber.CheckEncodedLength(opts, "smsGmscAddress", "SIZE (1..20)", len(*v.SmsGmscAddress)); constraintErr != nil {
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
	for i, ext := range v.ExtData_ {
		if err := ber.CheckBEROpaqueReplay(opts...); err != nil {
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
		if i == 0 && ((peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0) || (peekTag.Class == tag.ClassUniversal && peekTag.Number == 4) || (peekTag.Class == tag.ClassUniversal && peekTag.Number == 2) || (peekTag.Class == tag.ClassUniversal && peekTag.Number == 16) || (peekTag.Class == tag.ClassUniversal && peekTag.Number == 5)) {
			if constraintErr := ber.CheckEncodedValue(opts, "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
				return nil, constraintErr
			}
		}
		children = append(children, ext...)
	}
	ber.RecordGeneratedBERContainer(opts, children)
	return ber.EncodeSequence(children)
}
func (v *SMMTForwardSMArg) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// MarshalDER encodes SMMTForwardSMArg to DER format.
func (v *SMMTForwardSMArg) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: SMMTForwardSMArg receiver is nil", ber.ErrInvalidValue)
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
		if constraintErr := ber.CheckEncodedLength(nil, "sm-RP-UI", "SIZE (1..200)", len(v.SmRPUI)); constraintErr != nil {
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
			if constraintErr := ber.CheckEncodedValue(nil, "smDeliveryTimer", "(30..600)", fmt.Sprint(int64(*v.SmDeliveryTimer))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_smdeliverytimer := ber.EncodeInteger(int64(*v.SmDeliveryTimer))
		children = append(children, enc_smdeliverytimer...)
	}
	if v.SmDeliveryStartTime != nil {
		if len(*v.SmDeliveryStartTime) < 4 || len(*v.SmDeliveryStartTime) > 4 {
			if constraintErr := ber.CheckEncodedLength(nil, "smDeliveryStartTime", "SIZE (4)", len(*v.SmDeliveryStartTime)); constraintErr != nil {
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
			if constraintErr := ber.CheckEncodedLength(nil, "maximumRetransmissionTime", "SIZE (4)", len(*v.MaximumRetransmissionTime)); constraintErr != nil {
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
			if constraintErr := ber.CheckEncodedLength(nil, "smsGmscAddress", "SIZE (1..9)", len(*v.SmsGmscAddress)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		if len(*v.SmsGmscAddress) < 1 || len(*v.SmsGmscAddress) > 20 {
			if constraintErr := ber.CheckEncodedLength(nil, "smsGmscAddress", "SIZE (1..20)", len(*v.SmsGmscAddress)); constraintErr != nil {
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
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
		peekTag, _, _, extErr := ber.DecodeEncodedTLV(ext)
		if extErr != nil {
			return nil, extErr
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: only the first addition is restricted.
		if i == 0 && ((peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0) || (peekTag.Class == tag.ClassUniversal && peekTag.Number == 4) || (peekTag.Class == tag.ClassUniversal && peekTag.Number == 2) || (peekTag.Class == tag.ClassUniversal && peekTag.Number == 16) || (peekTag.Class == tag.ClassUniversal && peekTag.Number == 5)) {
			if constraintErr := ber.CheckEncodedValue(nil, "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
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
		return nil, fmt.Errorf("%s: %w", "encoding SMMTForwardSMArg as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}
func (v *SMMTForwardSMArg) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	encoded, err := v.MarshalDER()
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBER decodes SMMTForwardSMArg from BER/DER format.
func (v *SMMTForwardSMArg) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: SMMTForwardSMArg destination is nil", ber.ErrInvalidValue)
	}
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
			var probe SMMTForwardSMArg
			return probe.UnmarshalBER(data, probeOpts...)
		})
	}
	data, opts = preparedData, preparedOptions
	*v = SMMTForwardSMArg{}
	defer func() {
		if returnErr != nil || !ber.BERNeedsPreservation(opts) {
			return
		}
		v.berReplayNode_ = ber.CaptureGeneratedBERReplay(data, opts)
		returnErr = ber.CompleteGeneratedBERDecode(opts, v, func(base *SMMTForwardSMArg, replayOpts ...ber.EncodeOption) ([]byte, error) {
			return base.MarshalBER(replayOpts...)
		})
	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("%s: %w", "decoding SMMTForwardSMArg SEQUENCE", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "SMMTForwardSMArg", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode sm-RP-DA
	if offset >= len(content) {
		return fmt.Errorf("missing required field sm-RP-DA")
	}
	{
		ber.MarkPreflightTarget(opts, "sm-RP-DA", content[offset:])
		// Decode nested CHOICE (SMSMRPDA)
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
		// Decode nested CHOICE (SMSMRPOA)
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
		v.SmRPUI = v21_map_commondatatypes.CommonDataTypesSignalInfo(val_smrpui)
		if offset < 0 || offset >
			len(content) || n < 0 || n > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n
		if len(v.SmRPUI) < 1 || len(v.SmRPUI) > 200 {
			if constraintErr := ber.CheckDecodedLength(opts, "sm-RP-UI", "SIZE (1..200)", len(v.SmRPUI)); constraintErr != nil {
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
				// Decode nested SEQUENCE (__asn1pkg_v21_map_extensiondatatypes.ExtensionDataTypesExtensionContainer)
				_, n_extensioncontainer, _, tlvErr_extensioncontainer := ber.DecodeTLV(content[offset:], opts...)
				if tlvErr_extensioncontainer != nil {
					return qualifyBERError(tlvErr_extensioncontainer, "extensionContainer", "decoding", false)
				}
				var dec_extensioncontainer v21_map_extensiondatatypes.ExtensionDataTypesExtensionContainer
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
				tmp_smdeliverytimer := SMSMDeliveryTimerValue(val_smdeliverytimer)
				v.SmDeliveryTimer = &tmp_smdeliverytimer
				if offset < 0 || offset >
					len(content) || n < 0 || n > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n
				if !(int64(*v.SmDeliveryTimer) >= 30 && int64(*v.SmDeliveryTimer) <= 600) {
					if constraintErr := ber.CheckDecodedValue(opts, "smDeliveryTimer", "(30..600)", fmt.Sprint(int64(*v.SmDeliveryTimer))); constraintErr != nil {
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
				tmp_smdeliverystarttime := v21_map_commondatatypes.CommonDataTypesTime(val_smdeliverystarttime)
				v.SmDeliveryStartTime = &tmp_smdeliverystarttime
				if offset < 0 || offset >
					len(content) || n < 0 || n > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n
				if len(*v.SmDeliveryStartTime) < 4 || len(*v.SmDeliveryStartTime) > 4 {
					if constraintErr := ber.CheckDecodedLength(opts, "smDeliveryStartTime", "SIZE (4)", len(*v.SmDeliveryStartTime)); constraintErr != nil {
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
				var dec_correlationid SMCorrelationID
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
				tmp_maximumretransmissiontime := v21_map_commondatatypes.CommonDataTypesTime(decVal_maximumretransmissiontime)
				v.MaximumRetransmissionTime = &tmp_maximumretransmissiontime
				if offset < 0 || offset >
					len(content) || n_maximumretransmissiontime < 0 || n_maximumretransmissiontime >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_maximumretransmissiontime
				if len(*v.MaximumRetransmissionTime) < 4 || len(*v.MaximumRetransmissionTime) > 4 {
					if constraintErr := ber.CheckDecodedLength(opts, "maximumRetransmissionTime", "SIZE (4)", len(*v.MaximumRetransmissionTime)); constraintErr != nil {
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
				tmp_smsgmscaddress := v21_map_commondatatypes.CommonDataTypesISDNAddressString(decVal_smsgmscaddress)
				v.SmsGmscAddress = &tmp_smsgmscaddress
				if offset < 0 || offset >
					len(content) || n_smsgmscaddress < 0 || n_smsgmscaddress >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_smsgmscaddress
				if len(*v.SmsGmscAddress) < 1 || len(*v.SmsGmscAddress) > 9 {
					if constraintErr := ber.CheckDecodedLength(opts, "smsGmscAddress", "SIZE (1..9)", len(*v.SmsGmscAddress)); constraintErr != nil {
						return constraintErr
					}
				}
				if len(*v.SmsGmscAddress) < 1 || len(*v.SmsGmscAddress) > 20 {
					if constraintErr := ber.CheckDecodedLength(opts, "smsGmscAddress", "SIZE (1..20)", len(*v.SmsGmscAddress)); constraintErr != nil {
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
				var dec_smsgmscdiameteraddress v21_map_commondatatypes.CommonDataTypesNetworkNodeDiameterAddress
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
			return &ber.DecodeError{Offset: offset, TypeName: "SMMTForwardSMArg", Cause: extErr_}
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: the first unknown addition must differ from trailing OPTIONAL/DEFAULT tags.
		if len(v.ExtData_) == 0 && ((peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0) || (peekTag.Class == tag.ClassUniversal && peekTag.Number == 4) || (peekTag.Class == tag.ClassUniversal && peekTag.Number == 2) || (peekTag.Class == tag.ClassUniversal && peekTag.Number == 16) || (peekTag.Class == tag.ClassUniversal && peekTag.Number == 5)) {
			if !ber.ConstraintToleranceEnabled(opts) {
				return &ber.DecodeError{Offset: offset, TypeName: "SMMTForwardSMArg", Cause: fmt.Errorf("%w: repeated or out-of-order SEQUENCE component tag %s", ber.ErrInvalidTag, peekTag)}
			}
			if orderErr_ := ber.CheckDecodedValue(opts, fmt.Sprintf("ExtData_[%d]", len(v.ExtData_)), "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); orderErr_ != nil {
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

// MarshalBER encodes SMCorrelationID to BER format.
func (v *SMCorrelationID) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: SMCorrelationID receiver is nil", ber.ErrInvalidValue)
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
func (v *SMCorrelationID) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if v.HlrId != nil {
		if len(*v.HlrId) < 3 || len(*v.HlrId) > 8 {
			if constraintErr := ber.CheckEncodedLength(opts, "hlr-id", "SIZE (3..8)", len(*v.HlrId)); constraintErr != nil {
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
func (v *SMCorrelationID) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// MarshalDER encodes SMCorrelationID to DER format.
func (v *SMCorrelationID) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: SMCorrelationID receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if v.HlrId != nil {
		if len(*v.HlrId) < 3 || len(*v.HlrId) > 8 {
			if constraintErr := ber.CheckEncodedLength(nil, "hlr-id", "SIZE (3..8)", len(*v.HlrId)); constraintErr != nil {
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
		return nil, fmt.Errorf("%s: %w", "encoding SMCorrelationID as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}
func (v *SMCorrelationID) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	encoded, err := v.MarshalDER()
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBER decodes SMCorrelationID from BER/DER format.
func (v *SMCorrelationID) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: SMCorrelationID destination is nil", ber.ErrInvalidValue)
	}
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
			var probe SMCorrelationID
			return probe.UnmarshalBER(data, probeOpts...)
		})
	}
	data, opts = preparedData, preparedOptions
	*v = SMCorrelationID{}
	defer func() {
		if returnErr != nil || !ber.BERNeedsPreservation(opts) {
			return
		}
		v.berReplayNode_ = ber.CaptureGeneratedBERReplay(data, opts)
		returnErr = ber.CompleteGeneratedBERDecode(opts, v, func(base *SMCorrelationID, replayOpts ...ber.EncodeOption) ([]byte, error) {
			return base.MarshalBER(replayOpts...)
		})
	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("%s: %w", "decoding SMCorrelationID SEQUENCE", qualifyBERError(err, "", "decoding", false))
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
				tmp_hlrid := v21_map_commondatatypes.CommonDataTypesHLRId(decVal_hlrid)
				v.HlrId = &tmp_hlrid
				if offset > len(content) || n_hlrid < 0 || n_hlrid > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_hlrid
				if len(*v.HlrId) < 3 || len(*v.HlrId) > 8 {
					if constraintErr := ber.CheckDecodedLength(opts, "hlr-id", "SIZE (3..8)", len(*v.HlrId)); constraintErr != nil {
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
				tmp_sipuria := SMSIPURI(decVal_sipuria)
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
		v.SipUriB = SMSIPURI(decVal_sipurib)
		if offset < 0 || offset >
			len(content) || n_sipurib < 0 || n_sipurib > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n_sipurib
	}
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "SMCorrelationID", Cause: ber.ErrExtraData}
	}
	return nil
}

// MarshalBER encodes SMMTForwardSMRes to BER format.
func (v *SMMTForwardSMRes) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: SMMTForwardSMRes receiver is nil", ber.ErrInvalidValue)
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
func (v *SMMTForwardSMRes) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if v.SmRPUI != nil {
		if len(*v.SmRPUI) < 1 || len(*v.SmRPUI) > 200 {
			if constraintErr := ber.CheckEncodedLength(opts, "sm-RP-UI", "SIZE (1..200)", len(*v.SmRPUI)); constraintErr != nil {
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
	for i, ext := range v.ExtData_ {
		if err := ber.CheckBEROpaqueReplay(opts...); err != nil {
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
		if i == 0 && ((peekTag.Class == tag.ClassUniversal && peekTag.Number == 16) || (peekTag.Class == tag.ClassUniversal && peekTag.Number == 4)) {
			if constraintErr := ber.CheckEncodedValue(opts, "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
				return nil, constraintErr
			}
		}
		children = append(children, ext...)
	}
	ber.RecordGeneratedBERContainer(opts, children)
	return ber.EncodeSequence(children)
}
func (v *SMMTForwardSMRes) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// MarshalDER encodes SMMTForwardSMRes to DER format.
func (v *SMMTForwardSMRes) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: SMMTForwardSMRes receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if v.SmRPUI != nil {
		if len(*v.SmRPUI) < 1 || len(*v.SmRPUI) > 200 {
			if constraintErr := ber.CheckEncodedLength(nil, "sm-RP-UI", "SIZE (1..200)", len(*v.SmRPUI)); constraintErr != nil {
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
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
		peekTag, _, _, extErr := ber.DecodeEncodedTLV(ext)
		if extErr != nil {
			return nil, extErr
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: only the first addition is restricted.
		if i == 0 && ((peekTag.Class == tag.ClassUniversal && peekTag.Number == 16) || (peekTag.Class == tag.ClassUniversal && peekTag.Number == 4)) {
			if constraintErr := ber.CheckEncodedValue(nil, "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
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
		return nil, fmt.Errorf("%s: %w", "encoding SMMTForwardSMRes as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}
func (v *SMMTForwardSMRes) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	encoded, err := v.MarshalDER()
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBER decodes SMMTForwardSMRes from BER/DER format.
func (v *SMMTForwardSMRes) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: SMMTForwardSMRes destination is nil", ber.ErrInvalidValue)
	}
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
			var probe SMMTForwardSMRes
			return probe.UnmarshalBER(data, probeOpts...)
		})
	}
	data, opts = preparedData, preparedOptions
	*v = SMMTForwardSMRes{}
	defer func() {
		if returnErr != nil || !ber.BERNeedsPreservation(opts) {
			return
		}
		v.berReplayNode_ = ber.CaptureGeneratedBERReplay(data, opts)
		returnErr = ber.CompleteGeneratedBERDecode(opts, v, func(base *SMMTForwardSMRes, replayOpts ...ber.EncodeOption) ([]byte, error) {
			return base.MarshalBER(replayOpts...)
		})
	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("%s: %w", "decoding SMMTForwardSMRes SEQUENCE", qualifyBERError(err, "", "decoding", false))
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
				ber.MarkPreflightTarget(opts, "sm-RP-UI", content[offset:])
				val_smrpui, n, err := ber.DecodeOctetString(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "sm-RP-UI", "decoding", false)
				}
				tmp_smrpui := v21_map_commondatatypes.CommonDataTypesSignalInfo(val_smrpui)
				v.SmRPUI = &tmp_smrpui
				if offset > len(content) || n < 0 || n > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n
				if len(*v.SmRPUI) < 1 || len(*v.SmRPUI) > 200 {
					if constraintErr := ber.CheckDecodedLength(opts, "sm-RP-UI", "SIZE (1..200)", len(*v.SmRPUI)); constraintErr != nil {
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
				// Decode nested SEQUENCE (__asn1pkg_v21_map_extensiondatatypes.ExtensionDataTypesExtensionContainer)
				_, n_extensioncontainer, _, tlvErr_extensioncontainer := ber.DecodeTLV(content[offset:], opts...)
				if tlvErr_extensioncontainer != nil {
					return qualifyBERError(tlvErr_extensioncontainer, "extensionContainer", "decoding", false)
				}
				var dec_extensioncontainer v21_map_extensiondatatypes.ExtensionDataTypesExtensionContainer
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
			return &ber.DecodeError{Offset: offset, TypeName: "SMMTForwardSMRes", Cause: extErr_}
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: the first unknown addition must differ from trailing OPTIONAL/DEFAULT tags.
		if len(v.ExtData_) == 0 && ((peekTag.Class == tag.ClassUniversal && peekTag.Number == 16) || (peekTag.Class == tag.ClassUniversal && peekTag.Number == 4)) {
			if !ber.ConstraintToleranceEnabled(opts) {
				return &ber.DecodeError{Offset: offset, TypeName: "SMMTForwardSMRes", Cause: fmt.Errorf("%w: repeated or out-of-order SEQUENCE component tag %s", ber.ErrInvalidTag, peekTag)}
			}
			if orderErr_ := ber.CheckDecodedValue(opts, fmt.Sprintf("ExtData_[%d]", len(v.ExtData_)), "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); orderErr_ != nil {
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

// MarshalBER encodes SMSMRPDA to BER format.
func (v *SMSMRPDA) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: SMSMRPDA receiver is nil", ber.ErrInvalidValue)
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
func (v *SMSMRPDA) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}
func (v *SMSMRPDA) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	switch v.Choice {
	case SMSMRPDAChoiceImsi:
		if v.Imsi == nil {
			return nil, fmt.Errorf("%w: choice SMSMRPDA: imsi is nil", ber.ErrInvalidValue)
		}
		enc_0, encodeErr_enc_0 := ber.EncodeOctetString([]byte(*v.Imsi))
		if encodeErr_enc_0 != nil {
			return nil, qualifyBERError(encodeErr_enc_0, "imsi", "encoding", false)
		}
		if len(*v.Imsi) < 3 || len(*v.Imsi) > 8 {
			if constraintErr := ber.CheckEncodedLength(opts, "imsi", "SIZE (3..8)", len(*v.Imsi)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		retagged_enc_0, tagErr_enc_0 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_0)
		if tagErr_enc_0 != nil {
			return nil, qualifyBERError(tagErr_enc_0, "imsi", "encoding", false)
		}
		enc_0 = retagged_enc_0
		return enc_0, nil
	case SMSMRPDAChoiceLmsi:
		if v.Lmsi == nil {
			return nil, fmt.Errorf("%w: choice SMSMRPDA: lmsi is nil", ber.ErrInvalidValue)
		}
		enc_1, encodeErr_enc_1 := ber.EncodeOctetString([]byte(*v.Lmsi))
		if encodeErr_enc_1 != nil {
			return nil, qualifyBERError(encodeErr_enc_1, "lmsi", "encoding", false)
		}
		if len(*v.Lmsi) < 4 || len(*v.Lmsi) > 4 {
			if constraintErr := ber.CheckEncodedLength(opts, "lmsi", "SIZE (4)", len(*v.Lmsi)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		retagged_enc_1, tagErr_enc_1 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_1)
		if tagErr_enc_1 != nil {
			return nil, qualifyBERError(tagErr_enc_1, "lmsi", "encoding", false)
		}
		enc_1 = retagged_enc_1
		return enc_1, nil
	case SMSMRPDAChoiceServiceCentreAddressDA:
		if v.ServiceCentreAddressDA == nil {
			return nil, fmt.Errorf("%w: choice SMSMRPDA: serviceCentreAddressDA is nil", ber.ErrInvalidValue)
		}
		enc_2, encodeErr_enc_2 := ber.EncodeOctetString([]byte(*v.ServiceCentreAddressDA))
		if encodeErr_enc_2 != nil {
			return nil, qualifyBERError(encodeErr_enc_2, "serviceCentreAddressDA", "encoding", false)
		}
		if len(*v.ServiceCentreAddressDA) < 1 || len(*v.ServiceCentreAddressDA) > 20 {
			if constraintErr := ber.CheckEncodedLength(opts, "serviceCentreAddressDA", "SIZE (1..20)", len(*v.ServiceCentreAddressDA)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		retagged_enc_2, tagErr_enc_2 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, enc_2)
		if tagErr_enc_2 != nil {
			return nil, qualifyBERError(tagErr_enc_2, "serviceCentreAddressDA", "encoding", false)
		}
		enc_2 = retagged_enc_2
		return enc_2, nil
	case SMSMRPDAChoiceNoSMRPDA:
		enc_3 := ber.EncodeNull()
		retagged_enc_3, tagErr_enc_3 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 5, enc_3)
		if tagErr_enc_3 != nil {
			return nil, qualifyBERError(tagErr_enc_3, "noSM-RP-DA", "encoding", false)
		}
		enc_3 = retagged_enc_3
		return enc_3, nil
	default:
		return nil, fmt.Errorf("unknown choice %d for SMSMRPDA", v.Choice)
	}
}

// MarshalDER encodes SMSMRPDA to DER format.
func (v *SMSMRPDA) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: SMSMRPDA receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER()
	if err != nil {
		return nil, err
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		switch v.Choice {
		case SMSMRPDAChoiceImsi:
			return nil, qualifyBERError(err, "imsi", "encoding", true)
		case SMSMRPDAChoiceLmsi:
			return nil, qualifyBERError(err, "lmsi", "encoding", true)
		case SMSMRPDAChoiceServiceCentreAddressDA:
			return nil, qualifyBERError(err, "serviceCentreAddressDA", "encoding", true)
		case SMSMRPDAChoiceNoSMRPDA:
			return nil, qualifyBERError(err, "noSM-RP-DA", "encoding", true)
		}
		return nil, fmt.Errorf("%s: %w", "encoding SMSMRPDA as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}

func (v *SMSMRPDA) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	encoded, err := v.MarshalDER()
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBER decodes SMSMRPDA from BER/DER format.
func (v *SMSMRPDA) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: SMSMRPDA destination is nil", ber.ErrInvalidValue)
	}
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
		returnErr = ber.CompleteGeneratedBERDecode(opts, v, func(base *SMSMRPDA, replayOpts ...ber.EncodeOption) ([]byte, error) {
			return base.MarshalBER(replayOpts...)
		})
	}()
	preparedData, preparedOptions, prepareErr := ber.PrepareGeneratedBERInput(data, opts)
	if prepareErr != nil {
		return ber.DiagnosePreflight(prepareErr, data, opts, "child", func(probeOpts []ber.DecodeOption) error {
			var probe SMSMRPDA
			return probe.UnmarshalBER(data, probeOpts...)
		})
	}
	data, opts = preparedData, preparedOptions
	*v = SMSMRPDA{}
	if len(data) == 0 {
		return fmt.Errorf("empty data for SMSMRPDA CHOICE")
	}
	choiceData := data
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for SMSMRPDA: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData, opts...)
	if tlvErr != nil {
		return fmt.Errorf("%s: %w", "decoding SMSMRPDA CHOICE", qualifyBERError(tlvErr, "", "decoding", false))
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "SMSMRPDA", Cause: ber.ErrExtraData}
	}

	if (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 5) && peekTag.Constructed != false {
		return qualifyBERError(fmt.Errorf("%w: invalid primitive/constructed form for tag %s", ber.ErrInvalidTag, peekTag), "SMSMRPDA.noSM-RP-DA", "decoding", false)
	}
	if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
		v.Choice = SMSMRPDAChoiceImsi
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
		tmp := v21_map_commondatatypes.CommonDataTypesIMSI(decVal)
		v.Imsi = &tmp
		if len(*v.Imsi) < 3 || len(*v.Imsi) > 8 {
			if constraintErr := ber.CheckDecodedLength(opts, "imsi", "SIZE (3..8)", len(*v.Imsi)); constraintErr != nil {
				return constraintErr
			}
		}
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
		v.Choice = SMSMRPDAChoiceLmsi
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
		tmp := v21_map_commondatatypes.CommonDataTypesLMSI(decVal)
		v.Lmsi = &tmp
		if len(*v.Lmsi) < 4 || len(*v.Lmsi) > 4 {
			if constraintErr := ber.CheckDecodedLength(opts, "lmsi", "SIZE (4)", len(*v.Lmsi)); constraintErr != nil {
				return constraintErr
			}
		}
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4 {
		v.Choice = SMSMRPDAChoiceServiceCentreAddressDA
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
		tmp := v21_map_commondatatypes.CommonDataTypesAddressString(decVal)
		v.ServiceCentreAddressDA = &tmp
		if len(*v.ServiceCentreAddressDA) < 1 || len(*v.ServiceCentreAddressDA) > 20 {
			if constraintErr := ber.CheckDecodedLength(opts, "serviceCentreAddressDA", "SIZE (1..20)", len(*v.ServiceCentreAddressDA)); constraintErr != nil {
				return constraintErr
			}
		}
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 5 && peekTag.Constructed == false {
		v.Choice = SMSMRPDAChoiceNoSMRPDA
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
		return fmt.Errorf("unknown tag %s for SMSMRPDA CHOICE", peekTag)
	}
	return nil
}

// MarshalBER encodes SMSMRPOA to BER format.
func (v *SMSMRPOA) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: SMSMRPOA receiver is nil", ber.ErrInvalidValue)
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
func (v *SMSMRPOA) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}
func (v *SMSMRPOA) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	switch v.Choice {
	case SMSMRPOAChoiceMsisdn:
		if v.Msisdn == nil {
			return nil, fmt.Errorf("%w: choice SMSMRPOA: msisdn is nil", ber.ErrInvalidValue)
		}
		enc_0, encodeErr_enc_0 := ber.EncodeOctetString([]byte(*v.Msisdn))
		if encodeErr_enc_0 != nil {
			return nil, qualifyBERError(encodeErr_enc_0, "msisdn", "encoding", false)
		}
		if len(*v.Msisdn) < 1 || len(*v.Msisdn) > 9 {
			if constraintErr := ber.CheckEncodedLength(opts, "msisdn", "SIZE (1..9)", len(*v.Msisdn)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		if len(*v.Msisdn) < 1 || len(*v.Msisdn) > 20 {
			if constraintErr := ber.CheckEncodedLength(opts, "msisdn", "SIZE (1..20)", len(*v.Msisdn)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		retagged_enc_0, tagErr_enc_0 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_0)
		if tagErr_enc_0 != nil {
			return nil, qualifyBERError(tagErr_enc_0, "msisdn", "encoding", false)
		}
		enc_0 = retagged_enc_0
		return enc_0, nil
	case SMSMRPOAChoiceServiceCentreAddressOA:
		if v.ServiceCentreAddressOA == nil {
			return nil, fmt.Errorf("%w: choice SMSMRPOA: serviceCentreAddressOA is nil", ber.ErrInvalidValue)
		}
		enc_1, encodeErr_enc_1 := ber.EncodeOctetString([]byte(*v.ServiceCentreAddressOA))
		if encodeErr_enc_1 != nil {
			return nil, qualifyBERError(encodeErr_enc_1, "serviceCentreAddressOA", "encoding", false)
		}
		if len(*v.ServiceCentreAddressOA) < 1 || len(*v.ServiceCentreAddressOA) > 20 {
			if constraintErr := ber.CheckEncodedLength(opts, "serviceCentreAddressOA", "SIZE (1..20)", len(*v.ServiceCentreAddressOA)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		retagged_enc_1, tagErr_enc_1 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, enc_1)
		if tagErr_enc_1 != nil {
			return nil, qualifyBERError(tagErr_enc_1, "serviceCentreAddressOA", "encoding", false)
		}
		enc_1 = retagged_enc_1
		return enc_1, nil
	case SMSMRPOAChoiceNoSMRPOA:
		enc_2 := ber.EncodeNull()
		retagged_enc_2, tagErr_enc_2 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 5, enc_2)
		if tagErr_enc_2 != nil {
			return nil, qualifyBERError(tagErr_enc_2, "noSM-RP-OA", "encoding", false)
		}
		enc_2 = retagged_enc_2
		return enc_2, nil
	default:
		return nil, fmt.Errorf("unknown choice %d for SMSMRPOA", v.Choice)
	}
}

// MarshalDER encodes SMSMRPOA to DER format.
func (v *SMSMRPOA) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: SMSMRPOA receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER()
	if err != nil {
		return nil, err
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		switch v.Choice {
		case SMSMRPOAChoiceMsisdn:
			return nil, qualifyBERError(err, "msisdn", "encoding", true)
		case SMSMRPOAChoiceServiceCentreAddressOA:
			return nil, qualifyBERError(err, "serviceCentreAddressOA", "encoding", true)
		case SMSMRPOAChoiceNoSMRPOA:
			return nil, qualifyBERError(err, "noSM-RP-OA", "encoding", true)
		}
		return nil, fmt.Errorf("%s: %w", "encoding SMSMRPOA as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}

func (v *SMSMRPOA) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	encoded, err := v.MarshalDER()
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBER decodes SMSMRPOA from BER/DER format.
func (v *SMSMRPOA) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: SMSMRPOA destination is nil", ber.ErrInvalidValue)
	}
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
		returnErr = ber.CompleteGeneratedBERDecode(opts, v, func(base *SMSMRPOA, replayOpts ...ber.EncodeOption) ([]byte, error) {
			return base.MarshalBER(replayOpts...)
		})
	}()
	preparedData, preparedOptions, prepareErr := ber.PrepareGeneratedBERInput(data, opts)
	if prepareErr != nil {
		return ber.DiagnosePreflight(prepareErr, data, opts, "child", func(probeOpts []ber.DecodeOption) error {
			var probe SMSMRPOA
			return probe.UnmarshalBER(data, probeOpts...)
		})
	}
	data, opts = preparedData, preparedOptions
	*v = SMSMRPOA{}
	if len(data) == 0 {
		return fmt.Errorf("empty data for SMSMRPOA CHOICE")
	}
	choiceData := data
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for SMSMRPOA: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData, opts...)
	if tlvErr != nil {
		return fmt.Errorf("%s: %w", "decoding SMSMRPOA CHOICE", qualifyBERError(tlvErr, "", "decoding", false))
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "SMSMRPOA", Cause: ber.ErrExtraData}
	}

	if (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 5) && peekTag.Constructed != false {
		return qualifyBERError(fmt.Errorf("%w: invalid primitive/constructed form for tag %s", ber.ErrInvalidTag, peekTag), "SMSMRPOA.noSM-RP-OA", "decoding", false)
	}
	if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2 {
		v.Choice = SMSMRPOAChoiceMsisdn
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
		tmp := v21_map_commondatatypes.CommonDataTypesISDNAddressString(decVal)
		v.Msisdn = &tmp
		if len(*v.Msisdn) < 1 || len(*v.Msisdn) > 9 {
			if constraintErr := ber.CheckDecodedLength(opts, "msisdn", "SIZE (1..9)", len(*v.Msisdn)); constraintErr != nil {
				return constraintErr
			}
		}
		if len(*v.Msisdn) < 1 || len(*v.Msisdn) > 20 {
			if constraintErr := ber.CheckDecodedLength(opts, "msisdn", "SIZE (1..20)", len(*v.Msisdn)); constraintErr != nil {
				return constraintErr
			}
		}
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4 {
		v.Choice = SMSMRPOAChoiceServiceCentreAddressOA
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
		tmp := v21_map_commondatatypes.CommonDataTypesAddressString(decVal)
		v.ServiceCentreAddressOA = &tmp
		if len(*v.ServiceCentreAddressOA) < 1 || len(*v.ServiceCentreAddressOA) > 20 {
			if constraintErr := ber.CheckDecodedLength(opts, "serviceCentreAddressOA", "SIZE (1..20)", len(*v.ServiceCentreAddressOA)); constraintErr != nil {
				return constraintErr
			}
		}
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 5 && peekTag.Constructed == false {
		v.Choice = SMSMRPOAChoiceNoSMRPOA
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
		return fmt.Errorf("unknown tag %s for SMSMRPOA CHOICE", peekTag)
	}
	return nil
}

// MarshalBER encodes SMReportSMDeliveryStatusArg to BER format.
func (v *SMReportSMDeliveryStatusArg) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: SMReportSMDeliveryStatusArg receiver is nil", ber.ErrInvalidValue)
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
func (v *SMReportSMDeliveryStatusArg) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if len(v.Msisdn) < 1 || len(v.Msisdn) > 9 {
		if constraintErr := ber.CheckEncodedLength(opts, "msisdn", "SIZE (1..9)", len(v.Msisdn)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	if len(v.Msisdn) < 1 || len(v.Msisdn) > 20 {
		if constraintErr := ber.CheckEncodedLength(opts, "msisdn", "SIZE (1..20)", len(v.Msisdn)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_msisdn, encodeErr_enc_msisdn := ber.EncodeOctetString([]byte(v.Msisdn))
	if encodeErr_enc_msisdn != nil {
		return nil, qualifyBERError(encodeErr_enc_msisdn, "msisdn", "encoding", false)
	}
	children = append(children, enc_msisdn...)
	if len(v.ServiceCentreAddress) < 1 || len(v.ServiceCentreAddress) > 20 {
		if constraintErr := ber.CheckEncodedLength(opts, "serviceCentreAddress", "SIZE (1..20)", len(v.ServiceCentreAddress)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_servicecentreaddress, encodeErr_enc_servicecentreaddress := ber.EncodeOctetString([]byte(v.ServiceCentreAddress))
	if encodeErr_enc_servicecentreaddress != nil {
		return nil, qualifyBERError(encodeErr_enc_servicecentreaddress, "serviceCentreAddress", "encoding", false)
	}
	children = append(children, enc_servicecentreaddress...)
	if int64(v.SmDeliveryOutcome) != 0 && int64(v.SmDeliveryOutcome) != 1 && int64(v.SmDeliveryOutcome) != 2 {
		if constraintErr := ber.CheckEncodedValue(opts, "sm-DeliveryOutcome", "ENUMERATED {0, 1, 2}", fmt.Sprint(int64(v.SmDeliveryOutcome))); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_smdeliveryoutcome := ber.EncodeEnumerated(int64(v.SmDeliveryOutcome))
	children = append(children, enc_smdeliveryoutcome...)
	if v.AbsentSubscriberDiagnosticSM != nil {
		if !(int64(*v.AbsentSubscriberDiagnosticSM) >= 0 && int64(*v.AbsentSubscriberDiagnosticSM) <= 255) {
			if constraintErr := ber.CheckEncodedValue(opts, "absentSubscriberDiagnosticSM", "(0..255)", fmt.Sprint(int64(*v.AbsentSubscriberDiagnosticSM))); constraintErr != nil {
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
			if constraintErr := ber.CheckEncodedValue(opts, "additionalSM-DeliveryOutcome", "ENUMERATED {0, 1, 2}", fmt.Sprint(int64(*v.AdditionalSMDeliveryOutcome))); constraintErr != nil {
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
			if constraintErr := ber.CheckEncodedValue(opts, "additionalAbsentSubscriberDiagnosticSM", "(0..255)", fmt.Sprint(int64(*v.AdditionalAbsentSubscriberDiagnosticSM))); constraintErr != nil {
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
			if constraintErr := ber.CheckEncodedValue(opts, "ip-sm-gw-sm-deliveryOutcome", "ENUMERATED {0, 1, 2}", fmt.Sprint(int64(*v.IpSmGwSmDeliveryOutcome))); constraintErr != nil {
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
			if constraintErr := ber.CheckEncodedValue(opts, "ip-sm-gw-absentSubscriberDiagnosticSM", "(0..255)", fmt.Sprint(int64(*v.IpSmGwAbsentSubscriberDiagnosticSM))); constraintErr != nil {
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
			if constraintErr := ber.CheckEncodedLength(opts, "imsi", "SIZE (3..8)", len(*v.Imsi)); constraintErr != nil {
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
			if constraintErr := ber.CheckEncodedValue(opts, "smsf-3gpp-deliveryOutcome", "ENUMERATED {0, 1, 2}", fmt.Sprint(int64(*v.Smsf3gppDeliveryOutcome))); constraintErr != nil {
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
			if constraintErr := ber.CheckEncodedValue(opts, "smsf-3gpp-absentSubscriberDiagSM", "(0..255)", fmt.Sprint(int64(*v.Smsf3gppAbsentSubscriberDiagSM))); constraintErr != nil {
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
			if constraintErr := ber.CheckEncodedValue(opts, "smsf-non-3gpp-deliveryOutcome", "ENUMERATED {0, 1, 2}", fmt.Sprint(int64(*v.SmsfNon3gppDeliveryOutcome))); constraintErr != nil {
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
			if constraintErr := ber.CheckEncodedValue(opts, "smsf-non-3gpp-absentSubscriberDiagSM", "(0..255)", fmt.Sprint(int64(*v.SmsfNon3gppAbsentSubscriberDiagSM))); constraintErr != nil {
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
	for i, ext := range v.ExtData_ {
		if err := ber.CheckBEROpaqueReplay(opts...); err != nil {
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
		if i == 0 && ((peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 17) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 16) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 15) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 14) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 13) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 12) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 11) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 10) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 9) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 8) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 7) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 6) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 5) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0)) {
			if constraintErr := ber.CheckEncodedValue(opts, "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
				return nil, constraintErr
			}
		}
		children = append(children, ext...)
	}
	ber.RecordGeneratedBERContainer(opts, children)
	return ber.EncodeSequence(children)
}
func (v *SMReportSMDeliveryStatusArg) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// MarshalDER encodes SMReportSMDeliveryStatusArg to DER format.
func (v *SMReportSMDeliveryStatusArg) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: SMReportSMDeliveryStatusArg receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if len(v.Msisdn) < 1 || len(v.Msisdn) > 9 {
		if constraintErr := ber.CheckEncodedLength(nil, "msisdn", "SIZE (1..9)", len(v.Msisdn)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	if len(v.Msisdn) < 1 || len(v.Msisdn) > 20 {
		if constraintErr := ber.CheckEncodedLength(nil, "msisdn", "SIZE (1..20)", len(v.Msisdn)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_msisdn, encodeErr_enc_msisdn := ber.EncodeOctetString([]byte(v.Msisdn))
	if encodeErr_enc_msisdn != nil {
		return nil, qualifyBERError(encodeErr_enc_msisdn, "msisdn", "encoding", true)
	}
	children = append(children, enc_msisdn...)
	if len(v.ServiceCentreAddress) < 1 || len(v.ServiceCentreAddress) > 20 {
		if constraintErr := ber.CheckEncodedLength(nil, "serviceCentreAddress", "SIZE (1..20)", len(v.ServiceCentreAddress)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_servicecentreaddress, encodeErr_enc_servicecentreaddress := ber.EncodeOctetString([]byte(v.ServiceCentreAddress))
	if encodeErr_enc_servicecentreaddress != nil {
		return nil, qualifyBERError(encodeErr_enc_servicecentreaddress, "serviceCentreAddress", "encoding", true)
	}
	children = append(children, enc_servicecentreaddress...)
	if int64(v.SmDeliveryOutcome) != 0 && int64(v.SmDeliveryOutcome) != 1 && int64(v.SmDeliveryOutcome) != 2 {
		if constraintErr := ber.CheckEncodedValue(nil, "sm-DeliveryOutcome", "ENUMERATED {0, 1, 2}", fmt.Sprint(int64(v.SmDeliveryOutcome))); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_smdeliveryoutcome := ber.EncodeEnumerated(int64(v.SmDeliveryOutcome))
	children = append(children, enc_smdeliveryoutcome...)
	if v.AbsentSubscriberDiagnosticSM != nil {
		if !(int64(*v.AbsentSubscriberDiagnosticSM) >= 0 && int64(*v.AbsentSubscriberDiagnosticSM) <= 255) {
			if constraintErr := ber.CheckEncodedValue(nil, "absentSubscriberDiagnosticSM", "(0..255)", fmt.Sprint(int64(*v.AbsentSubscriberDiagnosticSM))); constraintErr != nil {
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
			if constraintErr := ber.CheckEncodedValue(nil, "additionalSM-DeliveryOutcome", "ENUMERATED {0, 1, 2}", fmt.Sprint(int64(*v.AdditionalSMDeliveryOutcome))); constraintErr != nil {
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
			if constraintErr := ber.CheckEncodedValue(nil, "additionalAbsentSubscriberDiagnosticSM", "(0..255)", fmt.Sprint(int64(*v.AdditionalAbsentSubscriberDiagnosticSM))); constraintErr != nil {
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
			if constraintErr := ber.CheckEncodedValue(nil, "ip-sm-gw-sm-deliveryOutcome", "ENUMERATED {0, 1, 2}", fmt.Sprint(int64(*v.IpSmGwSmDeliveryOutcome))); constraintErr != nil {
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
			if constraintErr := ber.CheckEncodedValue(nil, "ip-sm-gw-absentSubscriberDiagnosticSM", "(0..255)", fmt.Sprint(int64(*v.IpSmGwAbsentSubscriberDiagnosticSM))); constraintErr != nil {
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
			if constraintErr := ber.CheckEncodedLength(nil, "imsi", "SIZE (3..8)", len(*v.Imsi)); constraintErr != nil {
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
			if constraintErr := ber.CheckEncodedValue(nil, "smsf-3gpp-deliveryOutcome", "ENUMERATED {0, 1, 2}", fmt.Sprint(int64(*v.Smsf3gppDeliveryOutcome))); constraintErr != nil {
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
			if constraintErr := ber.CheckEncodedValue(nil, "smsf-3gpp-absentSubscriberDiagSM", "(0..255)", fmt.Sprint(int64(*v.Smsf3gppAbsentSubscriberDiagSM))); constraintErr != nil {
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
			if constraintErr := ber.CheckEncodedValue(nil, "smsf-non-3gpp-deliveryOutcome", "ENUMERATED {0, 1, 2}", fmt.Sprint(int64(*v.SmsfNon3gppDeliveryOutcome))); constraintErr != nil {
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
			if constraintErr := ber.CheckEncodedValue(nil, "smsf-non-3gpp-absentSubscriberDiagSM", "(0..255)", fmt.Sprint(int64(*v.SmsfNon3gppAbsentSubscriberDiagSM))); constraintErr != nil {
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
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDEREncodedElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
		peekTag, _, _, extErr := ber.DecodeEncodedTLV(ext)
		if extErr != nil {
			return nil, extErr
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: only the first addition is restricted.
		if i == 0 && ((peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 17) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 16) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 15) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 14) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 13) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 12) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 11) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 10) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 9) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 8) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 7) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 6) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 5) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0)) {
			if constraintErr := ber.CheckEncodedValue(nil, "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
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
		return nil, fmt.Errorf("%s: %w", "encoding SMReportSMDeliveryStatusArg as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}
func (v *SMReportSMDeliveryStatusArg) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	encoded, err := v.MarshalDER()
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBER decodes SMReportSMDeliveryStatusArg from BER/DER format.
func (v *SMReportSMDeliveryStatusArg) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: SMReportSMDeliveryStatusArg destination is nil", ber.ErrInvalidValue)
	}
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
			var probe SMReportSMDeliveryStatusArg
			return probe.UnmarshalBER(data, probeOpts...)
		})
	}
	data, opts = preparedData, preparedOptions
	*v = SMReportSMDeliveryStatusArg{}
	defer func() {
		if returnErr != nil || !ber.BERNeedsPreservation(opts) {
			return
		}
		v.berReplayNode_ = ber.CaptureGeneratedBERReplay(data, opts)
		returnErr = ber.CompleteGeneratedBERDecode(opts, v, func(base *SMReportSMDeliveryStatusArg, replayOpts ...ber.EncodeOption) ([]byte, error) {
			return base.MarshalBER(replayOpts...)
		})
	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("%s: %w", "decoding SMReportSMDeliveryStatusArg SEQUENCE", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "SMReportSMDeliveryStatusArg", Cause: ber.ErrExtraData}
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
		v.Msisdn = v21_map_commondatatypes.CommonDataTypesISDNAddressString(val_msisdn)
		if offset > len(content) || n < 0 || n > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n
		if len(v.Msisdn) < 1 || len(v.Msisdn) > 9 {
			if constraintErr := ber.CheckDecodedLength(opts, "msisdn", "SIZE (1..9)", len(v.Msisdn)); constraintErr != nil {
				return constraintErr
			}
		}
		if len(v.Msisdn) < 1 || len(v.Msisdn) > 20 {
			if constraintErr := ber.CheckDecodedLength(opts, "msisdn", "SIZE (1..20)", len(v.Msisdn)); constraintErr != nil {
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
		v.ServiceCentreAddress = v21_map_commondatatypes.CommonDataTypesAddressString(val_servicecentreaddress)
		if offset < 0 || offset >
			len(content) || n < 0 || n > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n
		if len(v.ServiceCentreAddress) < 1 || len(v.ServiceCentreAddress) > 20 {
			if constraintErr := ber.CheckDecodedLength(opts, "serviceCentreAddress", "SIZE (1..20)", len(v.ServiceCentreAddress)); constraintErr != nil {
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
		v.SmDeliveryOutcome = SMSMDeliveryOutcome(val_smdeliveryoutcome)
		if offset < 0 || offset >
			len(content) || n < 0 || n > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n
		if int64(v.SmDeliveryOutcome) != 0 && int64(v.SmDeliveryOutcome) != 1 && int64(v.SmDeliveryOutcome) != 2 {
			if constraintErr := ber.CheckDecodedValue(opts, "sm-DeliveryOutcome", "ENUMERATED {0, 1, 2}", fmt.Sprint(int64(v.SmDeliveryOutcome))); constraintErr != nil {
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
				tmp_absentsubscriberdiagnosticsm := v21_map_er_datatypes.ERAbsentSubscriberDiagnosticSM(decVal_absentsubscriberdiagnosticsm)
				v.AbsentSubscriberDiagnosticSM = &tmp_absentsubscriberdiagnosticsm
				if offset < 0 || offset >
					len(content) || n_absentsubscriberdiagnosticsm < 0 || n_absentsubscriberdiagnosticsm >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_absentsubscriberdiagnosticsm
				if !(int64(*v.AbsentSubscriberDiagnosticSM) >= 0 && int64(*v.AbsentSubscriberDiagnosticSM) <= 255) {
					if constraintErr := ber.CheckDecodedValue(opts, "absentSubscriberDiagnosticSM", "(0..255)", fmt.Sprint(int64(*v.AbsentSubscriberDiagnosticSM))); constraintErr != nil {
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
				tmp_additionalsmdeliveryoutcome := SMSMDeliveryOutcome(decVal_additionalsmdeliveryoutcome)
				v.AdditionalSMDeliveryOutcome = &tmp_additionalsmdeliveryoutcome
				if offset < 0 || offset >
					len(content) || n_additionalsmdeliveryoutcome < 0 || n_additionalsmdeliveryoutcome >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_additionalsmdeliveryoutcome
				if int64(*v.AdditionalSMDeliveryOutcome) != 0 && int64(*v.AdditionalSMDeliveryOutcome) != 1 && int64(*v.AdditionalSMDeliveryOutcome) != 2 {
					if constraintErr := ber.CheckDecodedValue(opts, "additionalSM-DeliveryOutcome", "ENUMERATED {0, 1, 2}", fmt.Sprint(int64(*v.AdditionalSMDeliveryOutcome))); constraintErr != nil {
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
				tmp_additionalabsentsubscriberdiagnosticsm := v21_map_er_datatypes.ERAbsentSubscriberDiagnosticSM(decVal_additionalabsentsubscriberdiagnosticsm)
				v.AdditionalAbsentSubscriberDiagnosticSM = &tmp_additionalabsentsubscriberdiagnosticsm
				if offset < 0 || offset >
					len(content) || n_additionalabsentsubscriberdiagnosticsm < 0 || n_additionalabsentsubscriberdiagnosticsm >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_additionalabsentsubscriberdiagnosticsm
				if !(int64(*v.AdditionalAbsentSubscriberDiagnosticSM) >= 0 && int64(*v.AdditionalAbsentSubscriberDiagnosticSM) <= 255) {
					if constraintErr := ber.CheckDecodedValue(opts, "additionalAbsentSubscriberDiagnosticSM", "(0..255)", fmt.Sprint(int64(*v.AdditionalAbsentSubscriberDiagnosticSM))); constraintErr != nil {
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
				tmp_ipsmgwsmdeliveryoutcome := SMSMDeliveryOutcome(decVal_ipsmgwsmdeliveryoutcome)
				v.IpSmGwSmDeliveryOutcome = &tmp_ipsmgwsmdeliveryoutcome
				if offset < 0 || offset >
					len(content) || n_ipsmgwsmdeliveryoutcome < 0 || n_ipsmgwsmdeliveryoutcome >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_ipsmgwsmdeliveryoutcome
				if int64(*v.IpSmGwSmDeliveryOutcome) != 0 && int64(*v.IpSmGwSmDeliveryOutcome) != 1 && int64(*v.IpSmGwSmDeliveryOutcome) != 2 {
					if constraintErr := ber.CheckDecodedValue(opts, "ip-sm-gw-sm-deliveryOutcome", "ENUMERATED {0, 1, 2}", fmt.Sprint(int64(*v.IpSmGwSmDeliveryOutcome))); constraintErr != nil {
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
				tmp_ipsmgwabsentsubscriberdiagnosticsm := v21_map_er_datatypes.ERAbsentSubscriberDiagnosticSM(decVal_ipsmgwabsentsubscriberdiagnosticsm)
				v.IpSmGwAbsentSubscriberDiagnosticSM = &tmp_ipsmgwabsentsubscriberdiagnosticsm
				if offset < 0 || offset >
					len(content) || n_ipsmgwabsentsubscriberdiagnosticsm < 0 || n_ipsmgwabsentsubscriberdiagnosticsm >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_ipsmgwabsentsubscriberdiagnosticsm
				if !(int64(*v.IpSmGwAbsentSubscriberDiagnosticSM) >= 0 && int64(*v.IpSmGwAbsentSubscriberDiagnosticSM) <= 255) {
					if constraintErr := ber.CheckDecodedValue(opts, "ip-sm-gw-absentSubscriberDiagnosticSM", "(0..255)", fmt.Sprint(int64(*v.IpSmGwAbsentSubscriberDiagnosticSM))); constraintErr != nil {
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
				tmp_imsi := v21_map_commondatatypes.CommonDataTypesIMSI(decVal_imsi)
				v.Imsi = &tmp_imsi
				if offset < 0 || offset >
					len(content) || n_imsi < 0 || n_imsi > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_imsi
				if len(*v.Imsi) < 3 || len(*v.Imsi) > 8 {
					if constraintErr := ber.CheckDecodedLength(opts, "imsi", "SIZE (3..8)", len(*v.Imsi)); constraintErr != nil {
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
				var dec_correlationid SMCorrelationID
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
				tmp_smsf3gppdeliveryoutcome := SMSMDeliveryOutcome(decVal_smsf3gppdeliveryoutcome)
				v.Smsf3gppDeliveryOutcome = &tmp_smsf3gppdeliveryoutcome
				if offset < 0 || offset >
					len(content) || n_smsf3gppdeliveryoutcome < 0 || n_smsf3gppdeliveryoutcome >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_smsf3gppdeliveryoutcome
				if int64(*v.Smsf3gppDeliveryOutcome) != 0 && int64(*v.Smsf3gppDeliveryOutcome) != 1 && int64(*v.Smsf3gppDeliveryOutcome) != 2 {
					if constraintErr := ber.CheckDecodedValue(opts, "smsf-3gpp-deliveryOutcome", "ENUMERATED {0, 1, 2}", fmt.Sprint(int64(*v.Smsf3gppDeliveryOutcome))); constraintErr != nil {
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
				tmp_smsf3gppabsentsubscriberdiagsm := v21_map_er_datatypes.ERAbsentSubscriberDiagnosticSM(decVal_smsf3gppabsentsubscriberdiagsm)
				v.Smsf3gppAbsentSubscriberDiagSM = &tmp_smsf3gppabsentsubscriberdiagsm
				if offset < 0 || offset >
					len(content) || n_smsf3gppabsentsubscriberdiagsm < 0 || n_smsf3gppabsentsubscriberdiagsm >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_smsf3gppabsentsubscriberdiagsm
				if !(int64(*v.Smsf3gppAbsentSubscriberDiagSM) >= 0 && int64(*v.Smsf3gppAbsentSubscriberDiagSM) <= 255) {
					if constraintErr := ber.CheckDecodedValue(opts, "smsf-3gpp-absentSubscriberDiagSM", "(0..255)", fmt.Sprint(int64(*v.Smsf3gppAbsentSubscriberDiagSM))); constraintErr != nil {
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
				tmp_smsfnon3gppdeliveryoutcome := SMSMDeliveryOutcome(decVal_smsfnon3gppdeliveryoutcome)
				v.SmsfNon3gppDeliveryOutcome = &tmp_smsfnon3gppdeliveryoutcome
				if offset < 0 || offset >
					len(content) || n_smsfnon3gppdeliveryoutcome < 0 || n_smsfnon3gppdeliveryoutcome >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_smsfnon3gppdeliveryoutcome
				if int64(*v.SmsfNon3gppDeliveryOutcome) != 0 && int64(*v.SmsfNon3gppDeliveryOutcome) != 1 && int64(*v.SmsfNon3gppDeliveryOutcome) != 2 {
					if constraintErr := ber.CheckDecodedValue(opts, "smsf-non-3gpp-deliveryOutcome", "ENUMERATED {0, 1, 2}", fmt.Sprint(int64(*v.SmsfNon3gppDeliveryOutcome))); constraintErr != nil {
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
				tmp_smsfnon3gppabsentsubscriberdiagsm := v21_map_er_datatypes.ERAbsentSubscriberDiagnosticSM(decVal_smsfnon3gppabsentsubscriberdiagsm)
				v.SmsfNon3gppAbsentSubscriberDiagSM = &tmp_smsfnon3gppabsentsubscriberdiagsm
				if offset < 0 || offset >
					len(content) || n_smsfnon3gppabsentsubscriberdiagsm < 0 || n_smsfnon3gppabsentsubscriberdiagsm >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_smsfnon3gppabsentsubscriberdiagsm
				if !(int64(*v.SmsfNon3gppAbsentSubscriberDiagSM) >= 0 && int64(*v.SmsfNon3gppAbsentSubscriberDiagSM) <= 255) {
					if constraintErr := ber.CheckDecodedValue(opts, "smsf-non-3gpp-absentSubscriberDiagSM", "(0..255)", fmt.Sprint(int64(*v.SmsfNon3gppAbsentSubscriberDiagSM))); constraintErr != nil {
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
			return &ber.DecodeError{Offset: offset, TypeName: "SMReportSMDeliveryStatusArg", Cause: extErr_}
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: the first unknown addition must differ from trailing OPTIONAL/DEFAULT tags.
		if len(v.ExtData_) == 0 && ((peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 17) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 16) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 15) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 14) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 13) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 12) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 11) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 10) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 9) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 8) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 7) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 6) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 5) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0)) {
			if !ber.ConstraintToleranceEnabled(opts) {
				return &ber.DecodeError{Offset: offset, TypeName: "SMReportSMDeliveryStatusArg", Cause: fmt.Errorf("%w: repeated or out-of-order SEQUENCE component tag %s", ber.ErrInvalidTag, peekTag)}
			}
			if orderErr_ := ber.CheckDecodedValue(opts, fmt.Sprintf("ExtData_[%d]", len(v.ExtData_)), "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); orderErr_ != nil {
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

// MarshalBER encodes SMReportSMDeliveryStatusRes to BER format.
func (v *SMReportSMDeliveryStatusRes) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: SMReportSMDeliveryStatusRes receiver is nil", ber.ErrInvalidValue)
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
func (v *SMReportSMDeliveryStatusRes) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if v.StoredMSISDN != nil {
		if len(*v.StoredMSISDN) < 1 || len(*v.StoredMSISDN) > 9 {
			if constraintErr := ber.CheckEncodedLength(opts, "storedMSISDN", "SIZE (1..9)", len(*v.StoredMSISDN)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		if len(*v.StoredMSISDN) < 1 || len(*v.StoredMSISDN) > 20 {
			if constraintErr := ber.CheckEncodedLength(opts, "storedMSISDN", "SIZE (1..20)", len(*v.StoredMSISDN)); constraintErr != nil {
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
	for i, ext := range v.ExtData_ {
		if err := ber.CheckBEROpaqueReplay(opts...); err != nil {
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
		if i == 0 && ((peekTag.Class == tag.ClassUniversal && peekTag.Number == 16) || (peekTag.Class == tag.ClassUniversal && peekTag.Number == 4)) {
			if constraintErr := ber.CheckEncodedValue(opts, "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
				return nil, constraintErr
			}
		}
		children = append(children, ext...)
	}
	ber.RecordGeneratedBERContainer(opts, children)
	return ber.EncodeSequence(children)
}
func (v *SMReportSMDeliveryStatusRes) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// MarshalDER encodes SMReportSMDeliveryStatusRes to DER format.
func (v *SMReportSMDeliveryStatusRes) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: SMReportSMDeliveryStatusRes receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if v.StoredMSISDN != nil {
		if len(*v.StoredMSISDN) < 1 || len(*v.StoredMSISDN) > 9 {
			if constraintErr := ber.CheckEncodedLength(nil, "storedMSISDN", "SIZE (1..9)", len(*v.StoredMSISDN)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		if len(*v.StoredMSISDN) < 1 || len(*v.StoredMSISDN) > 20 {
			if constraintErr := ber.CheckEncodedLength(nil, "storedMSISDN", "SIZE (1..20)", len(*v.StoredMSISDN)); constraintErr != nil {
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
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDEREncodedElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
		peekTag, _, _, extErr := ber.DecodeEncodedTLV(ext)
		if extErr != nil {
			return nil, extErr
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: only the first addition is restricted.
		if i == 0 && ((peekTag.Class == tag.ClassUniversal && peekTag.Number == 16) || (peekTag.Class == tag.ClassUniversal && peekTag.Number == 4)) {
			if constraintErr := ber.CheckEncodedValue(nil, "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
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
		return nil, fmt.Errorf("%s: %w", "encoding SMReportSMDeliveryStatusRes as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}
func (v *SMReportSMDeliveryStatusRes) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	encoded, err := v.MarshalDER()
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBER decodes SMReportSMDeliveryStatusRes from BER/DER format.
func (v *SMReportSMDeliveryStatusRes) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: SMReportSMDeliveryStatusRes destination is nil", ber.ErrInvalidValue)
	}
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
			var probe SMReportSMDeliveryStatusRes
			return probe.UnmarshalBER(data, probeOpts...)
		})
	}
	data, opts = preparedData, preparedOptions
	*v = SMReportSMDeliveryStatusRes{}
	defer func() {
		if returnErr != nil || !ber.BERNeedsPreservation(opts) {
			return
		}
		v.berReplayNode_ = ber.CaptureGeneratedBERReplay(data, opts)
		returnErr = ber.CompleteGeneratedBERDecode(opts, v, func(base *SMReportSMDeliveryStatusRes, replayOpts ...ber.EncodeOption) ([]byte, error) {
			return base.MarshalBER(replayOpts...)
		})
	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("%s: %w", "decoding SMReportSMDeliveryStatusRes SEQUENCE", qualifyBERError(err, "", "decoding", false))
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
				ber.MarkPreflightTarget(opts, "storedMSISDN", content[offset:])
				val_storedmsisdn, n, err := ber.DecodeOctetString(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "storedMSISDN", "decoding", false)
				}
				tmp_storedmsisdn := v21_map_commondatatypes.CommonDataTypesISDNAddressString(val_storedmsisdn)
				v.StoredMSISDN = &tmp_storedmsisdn
				if offset > len(content) || n < 0 || n > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n
				if len(*v.StoredMSISDN) < 1 || len(*v.StoredMSISDN) > 9 {
					if constraintErr := ber.CheckDecodedLength(opts, "storedMSISDN", "SIZE (1..9)", len(*v.StoredMSISDN)); constraintErr != nil {
						return constraintErr
					}
				}
				if len(*v.StoredMSISDN) < 1 || len(*v.StoredMSISDN) > 20 {
					if constraintErr := ber.CheckDecodedLength(opts, "storedMSISDN", "SIZE (1..20)", len(*v.StoredMSISDN)); constraintErr != nil {
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
				// Decode nested SEQUENCE (__asn1pkg_v21_map_extensiondatatypes.ExtensionDataTypesExtensionContainer)
				_, n_extensioncontainer, _, tlvErr_extensioncontainer := ber.DecodeTLV(content[offset:], opts...)
				if tlvErr_extensioncontainer != nil {
					return qualifyBERError(tlvErr_extensioncontainer, "extensionContainer", "decoding", false)
				}
				var dec_extensioncontainer v21_map_extensiondatatypes.ExtensionDataTypesExtensionContainer
				if offset < 0 || offset >
					len(content) || n_extensioncontainer < 0 || n_extensioncontainer > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				if unmErr := dec_extensioncontainer.UnmarshalBER(content[offset:offset+n_extensioncontainer], ber.ChildDecodeOptions(opts, "extensionContainer")...); unmErr != nil {
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
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		peekTag, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:], opts...)
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "SMReportSMDeliveryStatusRes", Cause: extErr_}
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: the first unknown addition must differ from trailing OPTIONAL/DEFAULT tags.
		if len(v.ExtData_) == 0 && ((peekTag.Class == tag.ClassUniversal && peekTag.Number == 16) || (peekTag.Class == tag.ClassUniversal && peekTag.Number == 4)) {
			if !ber.ConstraintToleranceEnabled(opts) {
				return &ber.DecodeError{Offset: offset, TypeName: "SMReportSMDeliveryStatusRes", Cause: fmt.Errorf("%w: repeated or out-of-order SEQUENCE component tag %s", ber.ErrInvalidTag, peekTag)}
			}
			if orderErr_ := ber.CheckDecodedValue(opts, fmt.Sprintf("ExtData_[%d]", len(v.ExtData_)), "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); orderErr_ != nil {
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

// MarshalBER encodes SMAlertServiceCentreArg to BER format.
func (v *SMAlertServiceCentreArg) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: SMAlertServiceCentreArg receiver is nil", ber.ErrInvalidValue)
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
func (v *SMAlertServiceCentreArg) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if len(v.Msisdn) < 1 || len(v.Msisdn) > 9 {
		if constraintErr := ber.CheckEncodedLength(opts, "msisdn", "SIZE (1..9)", len(v.Msisdn)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	if len(v.Msisdn) < 1 || len(v.Msisdn) > 20 {
		if constraintErr := ber.CheckEncodedLength(opts, "msisdn", "SIZE (1..20)", len(v.Msisdn)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_msisdn, encodeErr_enc_msisdn := ber.EncodeOctetString([]byte(v.Msisdn))
	if encodeErr_enc_msisdn != nil {
		return nil, qualifyBERError(encodeErr_enc_msisdn, "msisdn", "encoding", false)
	}
	children = append(children, enc_msisdn...)
	if len(v.ServiceCentreAddress) < 1 || len(v.ServiceCentreAddress) > 20 {
		if constraintErr := ber.CheckEncodedLength(opts, "serviceCentreAddress", "SIZE (1..20)", len(v.ServiceCentreAddress)); constraintErr != nil {
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
			if constraintErr := ber.CheckEncodedLength(opts, "imsi", "SIZE (3..8)", len(*v.Imsi)); constraintErr != nil {
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
			if constraintErr := ber.CheckEncodedLength(opts, "maximumUeAvailabilityTime", "SIZE (4)", len(*v.MaximumUeAvailabilityTime)); constraintErr != nil {
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
			if constraintErr := ber.CheckEncodedValue(opts, "smsGmscAlertEvent", "ENUMERATED {0, 1}", fmt.Sprint(int64(*v.SmsGmscAlertEvent))); constraintErr != nil {
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
			if constraintErr := ber.CheckEncodedLength(opts, "newSGSNNumber", "SIZE (1..9)", len(*v.NewSGSNNumber)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		if len(*v.NewSGSNNumber) < 1 || len(*v.NewSGSNNumber) > 20 {
			if constraintErr := ber.CheckEncodedLength(opts, "newSGSNNumber", "SIZE (1..20)", len(*v.NewSGSNNumber)); constraintErr != nil {
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
			if constraintErr := ber.CheckEncodedLength(opts, "newMMENumber", "SIZE (1..9)", len(*v.NewMMENumber)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		if len(*v.NewMMENumber) < 1 || len(*v.NewMMENumber) > 20 {
			if constraintErr := ber.CheckEncodedLength(opts, "newMMENumber", "SIZE (1..20)", len(*v.NewMMENumber)); constraintErr != nil {
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
			if constraintErr := ber.CheckEncodedLength(opts, "newMSCNumber", "SIZE (1..9)", len(*v.NewMSCNumber)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		if len(*v.NewMSCNumber) < 1 || len(*v.NewMSCNumber) > 20 {
			if constraintErr := ber.CheckEncodedLength(opts, "newMSCNumber", "SIZE (1..20)", len(*v.NewMSCNumber)); constraintErr != nil {
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
	for i, ext := range v.ExtData_ {
		if err := ber.CheckBEROpaqueReplay(opts...); err != nil {
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
		if i == 0 && ((peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 7) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 6) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 5) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0) || (peekTag.Class == tag.ClassUniversal && peekTag.Number == 16) || (peekTag.Class == tag.ClassUniversal && peekTag.Number == 4)) {
			if constraintErr := ber.CheckEncodedValue(opts, "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
				return nil, constraintErr
			}
		}
		children = append(children, ext...)
	}
	ber.RecordGeneratedBERContainer(opts, children)
	return ber.EncodeSequence(children)
}
func (v *SMAlertServiceCentreArg) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// MarshalDER encodes SMAlertServiceCentreArg to DER format.
func (v *SMAlertServiceCentreArg) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: SMAlertServiceCentreArg receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if len(v.Msisdn) < 1 || len(v.Msisdn) > 9 {
		if constraintErr := ber.CheckEncodedLength(nil, "msisdn", "SIZE (1..9)", len(v.Msisdn)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	if len(v.Msisdn) < 1 || len(v.Msisdn) > 20 {
		if constraintErr := ber.CheckEncodedLength(nil, "msisdn", "SIZE (1..20)", len(v.Msisdn)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_msisdn, encodeErr_enc_msisdn := ber.EncodeOctetString([]byte(v.Msisdn))
	if encodeErr_enc_msisdn != nil {
		return nil, qualifyBERError(encodeErr_enc_msisdn, "msisdn", "encoding", true)
	}
	children = append(children, enc_msisdn...)
	if len(v.ServiceCentreAddress) < 1 || len(v.ServiceCentreAddress) > 20 {
		if constraintErr := ber.CheckEncodedLength(nil, "serviceCentreAddress", "SIZE (1..20)", len(v.ServiceCentreAddress)); constraintErr != nil {
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
			if constraintErr := ber.CheckEncodedLength(nil, "imsi", "SIZE (3..8)", len(*v.Imsi)); constraintErr != nil {
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
			if constraintErr := ber.CheckEncodedLength(nil, "maximumUeAvailabilityTime", "SIZE (4)", len(*v.MaximumUeAvailabilityTime)); constraintErr != nil {
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
			if constraintErr := ber.CheckEncodedValue(nil, "smsGmscAlertEvent", "ENUMERATED {0, 1}", fmt.Sprint(int64(*v.SmsGmscAlertEvent))); constraintErr != nil {
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
			if constraintErr := ber.CheckEncodedLength(nil, "newSGSNNumber", "SIZE (1..9)", len(*v.NewSGSNNumber)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		if len(*v.NewSGSNNumber) < 1 || len(*v.NewSGSNNumber) > 20 {
			if constraintErr := ber.CheckEncodedLength(nil, "newSGSNNumber", "SIZE (1..20)", len(*v.NewSGSNNumber)); constraintErr != nil {
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
			if constraintErr := ber.CheckEncodedLength(nil, "newMMENumber", "SIZE (1..9)", len(*v.NewMMENumber)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		if len(*v.NewMMENumber) < 1 || len(*v.NewMMENumber) > 20 {
			if constraintErr := ber.CheckEncodedLength(nil, "newMMENumber", "SIZE (1..20)", len(*v.NewMMENumber)); constraintErr != nil {
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
			if constraintErr := ber.CheckEncodedLength(nil, "newMSCNumber", "SIZE (1..9)", len(*v.NewMSCNumber)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		if len(*v.NewMSCNumber) < 1 || len(*v.NewMSCNumber) > 20 {
			if constraintErr := ber.CheckEncodedLength(nil, "newMSCNumber", "SIZE (1..20)", len(*v.NewMSCNumber)); constraintErr != nil {
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
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
		peekTag, _, _, extErr := ber.DecodeEncodedTLV(ext)
		if extErr != nil {
			return nil, extErr
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: only the first addition is restricted.
		if i == 0 && ((peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 7) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 6) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 5) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0) || (peekTag.Class == tag.ClassUniversal && peekTag.Number == 16) || (peekTag.Class == tag.ClassUniversal && peekTag.Number == 4)) {
			if constraintErr := ber.CheckEncodedValue(nil, "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
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
		return nil, fmt.Errorf("%s: %w", "encoding SMAlertServiceCentreArg as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}
func (v *SMAlertServiceCentreArg) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	encoded, err := v.MarshalDER()
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBER decodes SMAlertServiceCentreArg from BER/DER format.
func (v *SMAlertServiceCentreArg) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: SMAlertServiceCentreArg destination is nil", ber.ErrInvalidValue)
	}
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
			var probe SMAlertServiceCentreArg
			return probe.UnmarshalBER(data, probeOpts...)
		})
	}
	data, opts = preparedData, preparedOptions
	*v = SMAlertServiceCentreArg{}
	defer func() {
		if returnErr != nil || !ber.BERNeedsPreservation(opts) {
			return
		}
		v.berReplayNode_ = ber.CaptureGeneratedBERReplay(data, opts)
		returnErr = ber.CompleteGeneratedBERDecode(opts, v, func(base *SMAlertServiceCentreArg, replayOpts ...ber.EncodeOption) ([]byte, error) {
			return base.MarshalBER(replayOpts...)
		})
	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("%s: %w", "decoding SMAlertServiceCentreArg SEQUENCE", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "SMAlertServiceCentreArg", Cause: ber.ErrExtraData}
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
		v.Msisdn = v21_map_commondatatypes.CommonDataTypesISDNAddressString(val_msisdn)
		if offset > len(content) || n < 0 || n > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n
		if len(v.Msisdn) < 1 || len(v.Msisdn) > 9 {
			if constraintErr := ber.CheckDecodedLength(opts, "msisdn", "SIZE (1..9)", len(v.Msisdn)); constraintErr != nil {
				return constraintErr
			}
		}
		if len(v.Msisdn) < 1 || len(v.Msisdn) > 20 {
			if constraintErr := ber.CheckDecodedLength(opts, "msisdn", "SIZE (1..20)", len(v.Msisdn)); constraintErr != nil {
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
		v.ServiceCentreAddress = v21_map_commondatatypes.CommonDataTypesAddressString(val_servicecentreaddress)
		if offset < 0 || offset >
			len(content) || n < 0 || n > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n
		if len(v.ServiceCentreAddress) < 1 || len(v.ServiceCentreAddress) > 20 {
			if constraintErr := ber.CheckDecodedLength(opts, "serviceCentreAddress", "SIZE (1..20)", len(v.ServiceCentreAddress)); constraintErr != nil {
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
				tmp_imsi := v21_map_commondatatypes.CommonDataTypesIMSI(val_imsi)
				v.Imsi = &tmp_imsi
				if offset < 0 || offset >
					len(content) || n < 0 || n > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n
				if len(*v.Imsi) < 3 || len(*v.Imsi) > 8 {
					if constraintErr := ber.CheckDecodedLength(opts, "imsi", "SIZE (3..8)", len(*v.Imsi)); constraintErr != nil {
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
				// Decode nested SEQUENCE (SMCorrelationID)
				_, n_correlationid, _, tlvErr_correlationid := ber.DecodeTLV(content[offset:], opts...)
				if tlvErr_correlationid != nil {
					return qualifyBERError(tlvErr_correlationid, "correlationID", "decoding", false)
				}
				var dec_correlationid SMCorrelationID
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
				tmp_maximumueavailabilitytime := v21_map_commondatatypes.CommonDataTypesTime(decVal_maximumueavailabilitytime)
				v.MaximumUeAvailabilityTime = &tmp_maximumueavailabilitytime
				if offset < 0 || offset >
					len(content) || n_maximumueavailabilitytime < 0 || n_maximumueavailabilitytime >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_maximumueavailabilitytime
				if len(*v.MaximumUeAvailabilityTime) < 4 || len(*v.MaximumUeAvailabilityTime) > 4 {
					if constraintErr := ber.CheckDecodedLength(opts, "maximumUeAvailabilityTime", "SIZE (4)", len(*v.MaximumUeAvailabilityTime)); constraintErr != nil {
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
				tmp_smsgmscalertevent := SMSmsGmscAlertEvent(decVal_smsgmscalertevent)
				v.SmsGmscAlertEvent = &tmp_smsgmscalertevent
				if offset < 0 || offset >
					len(content) || n_smsgmscalertevent < 0 || n_smsgmscalertevent >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_smsgmscalertevent
				if int64(*v.SmsGmscAlertEvent) != 0 && int64(*v.SmsGmscAlertEvent) != 1 {
					if constraintErr := ber.CheckDecodedValue(opts, "smsGmscAlertEvent", "ENUMERATED {0, 1}", fmt.Sprint(int64(*v.SmsGmscAlertEvent))); constraintErr != nil {
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
				var dec_smsgmscdiameteraddress v21_map_commondatatypes.CommonDataTypesNetworkNodeDiameterAddress
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
				tmp_newsgsnnumber := v21_map_commondatatypes.CommonDataTypesISDNAddressString(decVal_newsgsnnumber)
				v.NewSGSNNumber = &tmp_newsgsnnumber
				if offset < 0 || offset >
					len(content) || n_newsgsnnumber < 0 || n_newsgsnnumber > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_newsgsnnumber
				if len(*v.NewSGSNNumber) < 1 || len(*v.NewSGSNNumber) > 9 {
					if constraintErr := ber.CheckDecodedLength(opts, "newSGSNNumber", "SIZE (1..9)", len(*v.NewSGSNNumber)); constraintErr != nil {
						return constraintErr
					}
				}
				if len(*v.NewSGSNNumber) < 1 || len(*v.NewSGSNNumber) > 20 {
					if constraintErr := ber.CheckDecodedLength(opts, "newSGSNNumber", "SIZE (1..20)", len(*v.NewSGSNNumber)); constraintErr != nil {
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
				var dec_newsgsndiameteraddress v21_map_commondatatypes.CommonDataTypesNetworkNodeDiameterAddress
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
				tmp_newmmenumber := v21_map_commondatatypes.CommonDataTypesISDNAddressString(decVal_newmmenumber)
				v.NewMMENumber = &tmp_newmmenumber
				if offset < 0 || offset >
					len(content) || n_newmmenumber < 0 || n_newmmenumber > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_newmmenumber
				if len(*v.NewMMENumber) < 1 || len(*v.NewMMENumber) > 9 {
					if constraintErr := ber.CheckDecodedLength(opts, "newMMENumber", "SIZE (1..9)", len(*v.NewMMENumber)); constraintErr != nil {
						return constraintErr
					}
				}
				if len(*v.NewMMENumber) < 1 || len(*v.NewMMENumber) > 20 {
					if constraintErr := ber.CheckDecodedLength(opts, "newMMENumber", "SIZE (1..20)", len(*v.NewMMENumber)); constraintErr != nil {
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
				var dec_newmmediameteraddress v21_map_commondatatypes.CommonDataTypesNetworkNodeDiameterAddress
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
				tmp_newmscnumber := v21_map_commondatatypes.CommonDataTypesISDNAddressString(decVal_newmscnumber)
				v.NewMSCNumber = &tmp_newmscnumber
				if offset < 0 || offset >
					len(content) || n_newmscnumber < 0 || n_newmscnumber > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_newmscnumber
				if len(*v.NewMSCNumber) < 1 || len(*v.NewMSCNumber) > 9 {
					if constraintErr := ber.CheckDecodedLength(opts, "newMSCNumber", "SIZE (1..9)", len(*v.NewMSCNumber)); constraintErr != nil {
						return constraintErr
					}
				}
				if len(*v.NewMSCNumber) < 1 || len(*v.NewMSCNumber) > 20 {
					if constraintErr := ber.CheckDecodedLength(opts, "newMSCNumber", "SIZE (1..20)", len(*v.NewMSCNumber)); constraintErr != nil {
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
			return &ber.DecodeError{Offset: offset, TypeName: "SMAlertServiceCentreArg", Cause: extErr_}
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: the first unknown addition must differ from trailing OPTIONAL/DEFAULT tags.
		if len(v.ExtData_) == 0 && ((peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 7) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 6) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 5) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0) || (peekTag.Class == tag.ClassUniversal && peekTag.Number == 16) || (peekTag.Class == tag.ClassUniversal && peekTag.Number == 4)) {
			if !ber.ConstraintToleranceEnabled(opts) {
				return &ber.DecodeError{Offset: offset, TypeName: "SMAlertServiceCentreArg", Cause: fmt.Errorf("%w: repeated or out-of-order SEQUENCE component tag %s", ber.ErrInvalidTag, peekTag)}
			}
			if orderErr_ := ber.CheckDecodedValue(opts, fmt.Sprintf("ExtData_[%d]", len(v.ExtData_)), "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); orderErr_ != nil {
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

// MarshalBER encodes SMInformServiceCentreArg to BER format.
func (v *SMInformServiceCentreArg) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: SMInformServiceCentreArg receiver is nil", ber.ErrInvalidValue)
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
func (v *SMInformServiceCentreArg) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if v.StoredMSISDN != nil {
		if len(*v.StoredMSISDN) < 1 || len(*v.StoredMSISDN) > 9 {
			if constraintErr := ber.CheckEncodedLength(opts, "storedMSISDN", "SIZE (1..9)", len(*v.StoredMSISDN)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		if len(*v.StoredMSISDN) < 1 || len(*v.StoredMSISDN) > 20 {
			if constraintErr := ber.CheckEncodedLength(opts, "storedMSISDN", "SIZE (1..20)", len(*v.StoredMSISDN)); constraintErr != nil {
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
		if bitStringErr := ber.ValidateBitStringLength(v.MwStatus.Bytes, v.MwStatus.BitLength); bitStringErr != nil {
			return nil, qualifyBERError(bitStringErr, "mw-Status", "encoding", false)
		}
		// arithmetic pattern BER_BITSTRING_FIELD: 0 <= bit length before modulo and subtraction; gen/codegen.go:743
		if v.MwStatus.BitLength < 0 {
			return nil, fmt.Errorf("negative bit string length")
		}
		if (*v.MwStatus).BitLength < 6 || (*v.MwStatus).BitLength > 16 {
			if constraintErr := ber.CheckEncodedLength(opts, "mw-Status", "SIZE (6..16)", (*v.MwStatus).BitLength); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_mwstatus, encodeErr_enc_mwstatus := ber.EncodeBitString(v.MwStatus.Bytes, ber.UnusedBitCount(v.MwStatus.BitLength))
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
			if constraintErr := ber.CheckEncodedValue(opts, "absentSubscriberDiagnosticSM", "(0..255)", fmt.Sprint(int64(*v.AbsentSubscriberDiagnosticSM))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_absentsubscriberdiagnosticsm := ber.EncodeInteger(int64(*v.AbsentSubscriberDiagnosticSM))
		children = append(children, enc_absentsubscriberdiagnosticsm...)
	}
	if v.AdditionalAbsentSubscriberDiagnosticSM != nil {
		if !(int64(*v.AdditionalAbsentSubscriberDiagnosticSM) >= 0 && int64(*v.AdditionalAbsentSubscriberDiagnosticSM) <= 255) {
			if constraintErr := ber.CheckEncodedValue(opts, "additionalAbsentSubscriberDiagnosticSM", "(0..255)", fmt.Sprint(int64(*v.AdditionalAbsentSubscriberDiagnosticSM))); constraintErr != nil {
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
			if constraintErr := ber.CheckEncodedValue(opts, "smsf3gppAbsentSubscriberDiagnosticSM", "(0..255)", fmt.Sprint(int64(*v.Smsf3gppAbsentSubscriberDiagnosticSM))); constraintErr != nil {
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
			if constraintErr := ber.CheckEncodedValue(opts, "smsfNon3gppAbsentSubscriberDiagnosticSM", "(0..255)", fmt.Sprint(int64(*v.SmsfNon3gppAbsentSubscriberDiagnosticSM))); constraintErr != nil {
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
	for i, ext := range v.ExtData_ {
		if err := ber.CheckBEROpaqueReplay(opts...); err != nil {
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
		if i == 0 && ((peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0) || (peekTag.Class == tag.ClassUniversal && peekTag.Number == 2) || (peekTag.Class == tag.ClassUniversal && peekTag.Number == 16) || (peekTag.Class == tag.ClassUniversal && peekTag.Number == 3) || (peekTag.Class == tag.ClassUniversal && peekTag.Number == 4)) {
			if constraintErr := ber.CheckEncodedValue(opts, "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
				return nil, constraintErr
			}
		}
		children = append(children, ext...)
	}
	ber.RecordGeneratedBERContainer(opts, children)
	return ber.EncodeSequence(children)
}
func (v *SMInformServiceCentreArg) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// MarshalDER encodes SMInformServiceCentreArg to DER format.
func (v *SMInformServiceCentreArg) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: SMInformServiceCentreArg receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if v.StoredMSISDN != nil {
		if len(*v.StoredMSISDN) < 1 || len(*v.StoredMSISDN) > 9 {
			if constraintErr := ber.CheckEncodedLength(nil, "storedMSISDN", "SIZE (1..9)", len(*v.StoredMSISDN)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		if len(*v.StoredMSISDN) < 1 || len(*v.StoredMSISDN) > 20 {
			if constraintErr := ber.CheckEncodedLength(nil, "storedMSISDN", "SIZE (1..20)", len(*v.StoredMSISDN)); constraintErr != nil {
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
		if bitStringErr := ber.ValidateBitStringLength(v.MwStatus.Bytes, v.MwStatus.BitLength); bitStringErr != nil {
			return nil, qualifyBERError(bitStringErr, "mw-Status", "encoding", true)
		}
		if bitStringErr := ber.ValidateDERBitString(v.MwStatus.Bytes, v.MwStatus.BitLength); bitStringErr != nil {
			return nil, qualifyBERError(bitStringErr, "mw-Status", "encoding", true)
		}
		// arithmetic pattern BER_BITSTRING_FIELD: 0 <= bit length before modulo and subtraction; gen/codegen.go:743
		if v.MwStatus.BitLength < 0 {
			return nil, fmt.Errorf("negative bit string length")
		}
		if (*v.MwStatus).BitLength < 6 || (*v.MwStatus).BitLength > 16 {
			if constraintErr := ber.CheckEncodedLength(nil, "mw-Status", "SIZE (6..16)", (*v.MwStatus).BitLength); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_mwstatus, encodeErr_enc_mwstatus := ber.EncodeDERNamedBitString(v.MwStatus.Bytes, v.MwStatus.BitLength)
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
			if constraintErr := ber.CheckEncodedValue(nil, "absentSubscriberDiagnosticSM", "(0..255)", fmt.Sprint(int64(*v.AbsentSubscriberDiagnosticSM))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_absentsubscriberdiagnosticsm := ber.EncodeInteger(int64(*v.AbsentSubscriberDiagnosticSM))
		children = append(children, enc_absentsubscriberdiagnosticsm...)
	}
	if v.AdditionalAbsentSubscriberDiagnosticSM != nil {
		if !(int64(*v.AdditionalAbsentSubscriberDiagnosticSM) >= 0 && int64(*v.AdditionalAbsentSubscriberDiagnosticSM) <= 255) {
			if constraintErr := ber.CheckEncodedValue(nil, "additionalAbsentSubscriberDiagnosticSM", "(0..255)", fmt.Sprint(int64(*v.AdditionalAbsentSubscriberDiagnosticSM))); constraintErr != nil {
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
			if constraintErr := ber.CheckEncodedValue(nil, "smsf3gppAbsentSubscriberDiagnosticSM", "(0..255)", fmt.Sprint(int64(*v.Smsf3gppAbsentSubscriberDiagnosticSM))); constraintErr != nil {
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
			if constraintErr := ber.CheckEncodedValue(nil, "smsfNon3gppAbsentSubscriberDiagnosticSM", "(0..255)", fmt.Sprint(int64(*v.SmsfNon3gppAbsentSubscriberDiagnosticSM))); constraintErr != nil {
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
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
		peekTag, _, _, extErr := ber.DecodeEncodedTLV(ext)
		if extErr != nil {
			return nil, extErr
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: only the first addition is restricted.
		if i == 0 && ((peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0) || (peekTag.Class == tag.ClassUniversal && peekTag.Number == 2) || (peekTag.Class == tag.ClassUniversal && peekTag.Number == 16) || (peekTag.Class == tag.ClassUniversal && peekTag.Number == 3) || (peekTag.Class == tag.ClassUniversal && peekTag.Number == 4)) {
			if constraintErr := ber.CheckEncodedValue(nil, "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
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
		return nil, fmt.Errorf("%s: %w", "encoding SMInformServiceCentreArg as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}
func (v *SMInformServiceCentreArg) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	encoded, err := v.MarshalDER()
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBER decodes SMInformServiceCentreArg from BER/DER format.
func (v *SMInformServiceCentreArg) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: SMInformServiceCentreArg destination is nil", ber.ErrInvalidValue)
	}
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
			var probe SMInformServiceCentreArg
			return probe.UnmarshalBER(data, probeOpts...)
		})
	}
	data, opts = preparedData, preparedOptions
	*v = SMInformServiceCentreArg{}
	defer func() {
		if returnErr != nil || !ber.BERNeedsPreservation(opts) {
			return
		}
		v.berReplayNode_ = ber.CaptureGeneratedBERReplay(data, opts)
		returnErr = ber.CompleteGeneratedBERDecode(opts, v, func(base *SMInformServiceCentreArg, replayOpts ...ber.EncodeOption) ([]byte, error) {
			return base.MarshalBER(replayOpts...)
		})
	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("%s: %w", "decoding SMInformServiceCentreArg SEQUENCE", qualifyBERError(err, "", "decoding", false))
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
				ber.MarkPreflightTarget(opts, "storedMSISDN", content[offset:])
				val_storedmsisdn, n, err := ber.DecodeOctetString(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "storedMSISDN", "decoding", false)
				}
				tmp_storedmsisdn := v21_map_commondatatypes.CommonDataTypesISDNAddressString(val_storedmsisdn)
				v.StoredMSISDN = &tmp_storedmsisdn
				if offset > len(content) || n < 0 || n > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n
				if len(*v.StoredMSISDN) < 1 || len(*v.StoredMSISDN) > 9 {
					if constraintErr := ber.CheckDecodedLength(opts, "storedMSISDN", "SIZE (1..9)", len(*v.StoredMSISDN)); constraintErr != nil {
						return constraintErr
					}
				}
				if len(*v.StoredMSISDN) < 1 || len(*v.StoredMSISDN) > 20 {
					if constraintErr := ber.CheckDecodedLength(opts, "storedMSISDN", "SIZE (1..20)", len(*v.StoredMSISDN)); constraintErr != nil {
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
					if constraintErr := ber.CheckDecodedLength(opts, "mw-Status", "SIZE (6..16)", (*v.MwStatus).BitLength); constraintErr != nil {
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
				// Decode nested SEQUENCE (__asn1pkg_v21_map_extensiondatatypes.ExtensionDataTypesExtensionContainer)
				_, n_extensioncontainer, _, tlvErr_extensioncontainer := ber.DecodeTLV(content[offset:], opts...)
				if tlvErr_extensioncontainer != nil {
					return qualifyBERError(tlvErr_extensioncontainer, "extensionContainer", "decoding", false)
				}
				var dec_extensioncontainer v21_map_extensiondatatypes.ExtensionDataTypesExtensionContainer
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
				tmp_absentsubscriberdiagnosticsm := v21_map_er_datatypes.ERAbsentSubscriberDiagnosticSM(val_absentsubscriberdiagnosticsm)
				v.AbsentSubscriberDiagnosticSM = &tmp_absentsubscriberdiagnosticsm
				if offset < 0 || offset >
					len(content) || n < 0 || n > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n
				if !(int64(*v.AbsentSubscriberDiagnosticSM) >= 0 && int64(*v.AbsentSubscriberDiagnosticSM) <= 255) {
					if constraintErr := ber.CheckDecodedValue(opts, "absentSubscriberDiagnosticSM", "(0..255)", fmt.Sprint(int64(*v.AbsentSubscriberDiagnosticSM))); constraintErr != nil {
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
				tmp_additionalabsentsubscriberdiagnosticsm := v21_map_er_datatypes.ERAbsentSubscriberDiagnosticSM(decVal_additionalabsentsubscriberdiagnosticsm)
				v.AdditionalAbsentSubscriberDiagnosticSM = &tmp_additionalabsentsubscriberdiagnosticsm
				if offset < 0 || offset >
					len(content) || n_additionalabsentsubscriberdiagnosticsm < 0 || n_additionalabsentsubscriberdiagnosticsm >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_additionalabsentsubscriberdiagnosticsm
				if !(int64(*v.AdditionalAbsentSubscriberDiagnosticSM) >= 0 && int64(*v.AdditionalAbsentSubscriberDiagnosticSM) <= 255) {
					if constraintErr := ber.CheckDecodedValue(opts, "additionalAbsentSubscriberDiagnosticSM", "(0..255)", fmt.Sprint(int64(*v.AdditionalAbsentSubscriberDiagnosticSM))); constraintErr != nil {
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
				tmp_smsf3gppabsentsubscriberdiagnosticsm := v21_map_er_datatypes.ERAbsentSubscriberDiagnosticSM(decVal_smsf3gppabsentsubscriberdiagnosticsm)
				v.Smsf3gppAbsentSubscriberDiagnosticSM = &tmp_smsf3gppabsentsubscriberdiagnosticsm
				if offset < 0 || offset >
					len(content) || n_smsf3gppabsentsubscriberdiagnosticsm < 0 || n_smsf3gppabsentsubscriberdiagnosticsm >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_smsf3gppabsentsubscriberdiagnosticsm
				if !(int64(*v.Smsf3gppAbsentSubscriberDiagnosticSM) >= 0 && int64(*v.Smsf3gppAbsentSubscriberDiagnosticSM) <= 255) {
					if constraintErr := ber.CheckDecodedValue(opts, "smsf3gppAbsentSubscriberDiagnosticSM", "(0..255)", fmt.Sprint(int64(*v.Smsf3gppAbsentSubscriberDiagnosticSM))); constraintErr != nil {
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
				tmp_smsfnon3gppabsentsubscriberdiagnosticsm := v21_map_er_datatypes.ERAbsentSubscriberDiagnosticSM(decVal_smsfnon3gppabsentsubscriberdiagnosticsm)
				v.SmsfNon3gppAbsentSubscriberDiagnosticSM = &tmp_smsfnon3gppabsentsubscriberdiagnosticsm
				if offset < 0 || offset >
					len(content) || n_smsfnon3gppabsentsubscriberdiagnosticsm < 0 ||
					n_smsfnon3gppabsentsubscriberdiagnosticsm > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_smsfnon3gppabsentsubscriberdiagnosticsm
				if !(int64(*v.SmsfNon3gppAbsentSubscriberDiagnosticSM) >= 0 && int64(*v.SmsfNon3gppAbsentSubscriberDiagnosticSM) <= 255) {
					if constraintErr := ber.CheckDecodedValue(opts, "smsfNon3gppAbsentSubscriberDiagnosticSM", "(0..255)", fmt.Sprint(int64(*v.SmsfNon3gppAbsentSubscriberDiagnosticSM))); constraintErr != nil {
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
			return &ber.DecodeError{Offset: offset, TypeName: "SMInformServiceCentreArg", Cause: extErr_}
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: the first unknown addition must differ from trailing OPTIONAL/DEFAULT tags.
		if len(v.ExtData_) == 0 && ((peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0) || (peekTag.Class == tag.ClassUniversal && peekTag.Number == 2) || (peekTag.Class == tag.ClassUniversal && peekTag.Number == 16) || (peekTag.Class == tag.ClassUniversal && peekTag.Number == 3) || (peekTag.Class == tag.ClassUniversal && peekTag.Number == 4)) {
			if !ber.ConstraintToleranceEnabled(opts) {
				return &ber.DecodeError{Offset: offset, TypeName: "SMInformServiceCentreArg", Cause: fmt.Errorf("%w: repeated or out-of-order SEQUENCE component tag %s", ber.ErrInvalidTag, peekTag)}
			}
			if orderErr_ := ber.CheckDecodedValue(opts, fmt.Sprintf("ExtData_[%d]", len(v.ExtData_)), "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); orderErr_ != nil {
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

// MarshalBER encodes SMReadyForSMArg to BER format.
func (v *SMReadyForSMArg) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: SMReadyForSMArg receiver is nil", ber.ErrInvalidValue)
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
func (v *SMReadyForSMArg) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if len(v.Imsi) < 3 || len(v.Imsi) > 8 {
		if constraintErr := ber.CheckEncodedLength(opts, "imsi", "SIZE (3..8)", len(v.Imsi)); constraintErr != nil {
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
		if constraintErr := ber.CheckEncodedValue(opts, "alertReason", "ENUMERATED {0, 1}", fmt.Sprint(int64(v.AlertReason))); constraintErr != nil {
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
			if constraintErr := ber.CheckEncodedLength(opts, "maximumUeAvailabilityTime", "SIZE (4)", len(*v.MaximumUeAvailabilityTime)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_maximumueavailabilitytime, encodeErr_enc_maximumueavailabilitytime := ber.EncodeOctetString([]byte(*v.MaximumUeAvailabilityTime))
		if encodeErr_enc_maximumueavailabilitytime != nil {
			return nil, qualifyBERError(encodeErr_enc_maximumueavailabilitytime, "maximumUeAvailabilityTime", "encoding", false)
		}
		children = append(children, enc_maximumueavailabilitytime...)
	}
	for i, ext := range v.ExtData_ {
		if err := ber.CheckBEROpaqueReplay(opts...); err != nil {
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
		if i == 0 && ((peekTag.Class == tag.ClassUniversal && peekTag.Number == 4) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1) || (peekTag.Class == tag.ClassUniversal && peekTag.Number == 16) || (peekTag.Class == tag.ClassUniversal && peekTag.Number == 5)) {
			if constraintErr := ber.CheckEncodedValue(opts, "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
				return nil, constraintErr
			}
		}
		children = append(children, ext...)
	}
	ber.RecordGeneratedBERContainer(opts, children)
	return ber.EncodeSequence(children)
}
func (v *SMReadyForSMArg) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// MarshalDER encodes SMReadyForSMArg to DER format.
func (v *SMReadyForSMArg) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: SMReadyForSMArg receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if len(v.Imsi) < 3 || len(v.Imsi) > 8 {
		if constraintErr := ber.CheckEncodedLength(nil, "imsi", "SIZE (3..8)", len(v.Imsi)); constraintErr != nil {
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
		if constraintErr := ber.CheckEncodedValue(nil, "alertReason", "ENUMERATED {0, 1}", fmt.Sprint(int64(v.AlertReason))); constraintErr != nil {
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
			if constraintErr := ber.CheckEncodedLength(nil, "maximumUeAvailabilityTime", "SIZE (4)", len(*v.MaximumUeAvailabilityTime)); constraintErr != nil {
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
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
		peekTag, _, _, extErr := ber.DecodeEncodedTLV(ext)
		if extErr != nil {
			return nil, extErr
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: only the first addition is restricted.
		if i == 0 && ((peekTag.Class == tag.ClassUniversal && peekTag.Number == 4) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1) || (peekTag.Class == tag.ClassUniversal && peekTag.Number == 16) || (peekTag.Class == tag.ClassUniversal && peekTag.Number == 5)) {
			if constraintErr := ber.CheckEncodedValue(nil, "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
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
		return nil, fmt.Errorf("%s: %w", "encoding SMReadyForSMArg as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}
func (v *SMReadyForSMArg) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	encoded, err := v.MarshalDER()
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBER decodes SMReadyForSMArg from BER/DER format.
func (v *SMReadyForSMArg) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: SMReadyForSMArg destination is nil", ber.ErrInvalidValue)
	}
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
			var probe SMReadyForSMArg
			return probe.UnmarshalBER(data, probeOpts...)
		})
	}
	data, opts = preparedData, preparedOptions
	*v = SMReadyForSMArg{}
	defer func() {
		if returnErr != nil || !ber.BERNeedsPreservation(opts) {
			return
		}
		v.berReplayNode_ = ber.CaptureGeneratedBERReplay(data, opts)
		returnErr = ber.CompleteGeneratedBERDecode(opts, v, func(base *SMReadyForSMArg, replayOpts ...ber.EncodeOption) ([]byte, error) {
			return base.MarshalBER(replayOpts...)
		})
	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("%s: %w", "decoding SMReadyForSMArg SEQUENCE", qualifyBERError(err, "", "decoding", false))
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
		v.Imsi = v21_map_commondatatypes.CommonDataTypesIMSI(decVal_imsi)
		if offset > len(content) || n_imsi < 0 || n_imsi > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n_imsi
		if len(v.Imsi) < 3 || len(v.Imsi) > 8 {
			if constraintErr := ber.CheckDecodedLength(opts, "imsi", "SIZE (3..8)", len(v.Imsi)); constraintErr != nil {
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
		v.AlertReason = SMAlertReason(val_alertreason)
		if offset < 0 || offset >
			len(content) || n < 0 || n > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n
		if int64(v.AlertReason) != 0 && int64(v.AlertReason) != 1 {
			if constraintErr := ber.CheckDecodedValue(opts, "alertReason", "ENUMERATED {0, 1}", fmt.Sprint(int64(v.AlertReason))); constraintErr != nil {
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
				// Decode nested SEQUENCE (__asn1pkg_v21_map_extensiondatatypes.ExtensionDataTypesExtensionContainer)
				_, n_extensioncontainer, _, tlvErr_extensioncontainer := ber.DecodeTLV(content[offset:], opts...)
				if tlvErr_extensioncontainer != nil {
					return qualifyBERError(tlvErr_extensioncontainer, "extensionContainer", "decoding", false)
				}
				var dec_extensioncontainer v21_map_extensiondatatypes.ExtensionDataTypesExtensionContainer
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
				tmp_maximumueavailabilitytime := v21_map_commondatatypes.CommonDataTypesTime(val_maximumueavailabilitytime)
				v.MaximumUeAvailabilityTime = &tmp_maximumueavailabilitytime
				if offset < 0 || offset >
					len(content) || n < 0 || n > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n
				if len(*v.MaximumUeAvailabilityTime) < 4 || len(*v.MaximumUeAvailabilityTime) > 4 {
					if constraintErr := ber.CheckDecodedLength(opts, "maximumUeAvailabilityTime", "SIZE (4)", len(*v.MaximumUeAvailabilityTime)); constraintErr != nil {
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
			return &ber.DecodeError{Offset: offset, TypeName: "SMReadyForSMArg", Cause: extErr_}
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: the first unknown addition must differ from trailing OPTIONAL/DEFAULT tags.
		if len(v.ExtData_) == 0 && ((peekTag.Class == tag.ClassUniversal && peekTag.Number == 4) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1) || (peekTag.Class == tag.ClassUniversal && peekTag.Number == 16) || (peekTag.Class == tag.ClassUniversal && peekTag.Number == 5)) {
			if !ber.ConstraintToleranceEnabled(opts) {
				return &ber.DecodeError{Offset: offset, TypeName: "SMReadyForSMArg", Cause: fmt.Errorf("%w: repeated or out-of-order SEQUENCE component tag %s", ber.ErrInvalidTag, peekTag)}
			}
			if orderErr_ := ber.CheckDecodedValue(opts, fmt.Sprintf("ExtData_[%d]", len(v.ExtData_)), "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); orderErr_ != nil {
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

// MarshalBER encodes SMReadyForSMRes to BER format.
func (v *SMReadyForSMRes) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: SMReadyForSMRes receiver is nil", ber.ErrInvalidValue)
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
func (v *SMReadyForSMRes) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
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
	for i, ext := range v.ExtData_ {
		if err := ber.CheckBEROpaqueReplay(opts...); err != nil {
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
		if i == 0 && (peekTag.Class == tag.ClassUniversal && peekTag.Number == 16) {
			if constraintErr := ber.CheckEncodedValue(opts, "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
				return nil, constraintErr
			}
		}
		children = append(children, ext...)
	}
	ber.RecordGeneratedBERContainer(opts, children)
	return ber.EncodeSequence(children)
}
func (v *SMReadyForSMRes) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// MarshalDER encodes SMReadyForSMRes to DER format.
func (v *SMReadyForSMRes) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: SMReadyForSMRes receiver is nil", ber.ErrInvalidValue)
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
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
		peekTag, _, _, extErr := ber.DecodeEncodedTLV(ext)
		if extErr != nil {
			return nil, extErr
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: only the first addition is restricted.
		if i == 0 && (peekTag.Class == tag.ClassUniversal && peekTag.Number == 16) {
			if constraintErr := ber.CheckEncodedValue(nil, "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
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
		return nil, fmt.Errorf("%s: %w", "encoding SMReadyForSMRes as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}
func (v *SMReadyForSMRes) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	encoded, err := v.MarshalDER()
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBER decodes SMReadyForSMRes from BER/DER format.
func (v *SMReadyForSMRes) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: SMReadyForSMRes destination is nil", ber.ErrInvalidValue)
	}
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
			var probe SMReadyForSMRes
			return probe.UnmarshalBER(data, probeOpts...)
		})
	}
	data, opts = preparedData, preparedOptions
	*v = SMReadyForSMRes{}
	defer func() {
		if returnErr != nil || !ber.BERNeedsPreservation(opts) {
			return
		}
		v.berReplayNode_ = ber.CaptureGeneratedBERReplay(data, opts)
		returnErr = ber.CompleteGeneratedBERDecode(opts, v, func(base *SMReadyForSMRes, replayOpts ...ber.EncodeOption) ([]byte, error) {
			return base.MarshalBER(replayOpts...)
		})
	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("%s: %w", "decoding SMReadyForSMRes SEQUENCE", qualifyBERError(err, "", "decoding", false))
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
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		peekTag, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:], opts...)
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "SMReadyForSMRes", Cause: extErr_}
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: the first unknown addition must differ from trailing OPTIONAL/DEFAULT tags.
		if len(v.ExtData_) == 0 && (peekTag.Class == tag.ClassUniversal && peekTag.Number == 16) {
			if !ber.ConstraintToleranceEnabled(opts) {
				return &ber.DecodeError{Offset: offset, TypeName: "SMReadyForSMRes", Cause: fmt.Errorf("%w: repeated or out-of-order SEQUENCE component tag %s", ber.ErrInvalidTag, peekTag)}
			}
			if orderErr_ := ber.CheckDecodedValue(opts, fmt.Sprintf("ExtData_[%d]", len(v.ExtData_)), "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); orderErr_ != nil {
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

// MarshalBER encodes SMMTForwardSMVGCSArg to BER format.
func (v *SMMTForwardSMVGCSArg) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: SMMTForwardSMVGCSArg receiver is nil", ber.ErrInvalidValue)
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
func (v *SMMTForwardSMVGCSArg) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if len(v.AsciCallReference) < 1 || len(v.AsciCallReference) > 8 {
		if constraintErr := ber.CheckEncodedLength(opts, "asciCallReference", "SIZE (1..8)", len(v.AsciCallReference)); constraintErr != nil {
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
		if constraintErr := ber.CheckEncodedLength(opts, "sm-RP-UI", "SIZE (1..200)", len(v.SmRPUI)); constraintErr != nil {
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
	for i, ext := range v.ExtData_ {
		if err := ber.CheckBEROpaqueReplay(opts...); err != nil {
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
		if i == 0 && (peekTag.Class == tag.ClassUniversal && peekTag.Number == 16) {
			if constraintErr := ber.CheckEncodedValue(opts, "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
				return nil, constraintErr
			}
		}
		children = append(children, ext...)
	}
	ber.RecordGeneratedBERContainer(opts, children)
	return ber.EncodeSequence(children)
}
func (v *SMMTForwardSMVGCSArg) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// MarshalDER encodes SMMTForwardSMVGCSArg to DER format.
func (v *SMMTForwardSMVGCSArg) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: SMMTForwardSMVGCSArg receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if len(v.AsciCallReference) < 1 || len(v.AsciCallReference) > 8 {
		if constraintErr := ber.CheckEncodedLength(nil, "asciCallReference", "SIZE (1..8)", len(v.AsciCallReference)); constraintErr != nil {
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
		if constraintErr := ber.CheckEncodedLength(nil, "sm-RP-UI", "SIZE (1..200)", len(v.SmRPUI)); constraintErr != nil {
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
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
		peekTag, _, _, extErr := ber.DecodeEncodedTLV(ext)
		if extErr != nil {
			return nil, extErr
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: only the first addition is restricted.
		if i == 0 && (peekTag.Class == tag.ClassUniversal && peekTag.Number == 16) {
			if constraintErr := ber.CheckEncodedValue(nil, "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
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
		return nil, fmt.Errorf("%s: %w", "encoding SMMTForwardSMVGCSArg as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}
func (v *SMMTForwardSMVGCSArg) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	encoded, err := v.MarshalDER()
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBER decodes SMMTForwardSMVGCSArg from BER/DER format.
func (v *SMMTForwardSMVGCSArg) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: SMMTForwardSMVGCSArg destination is nil", ber.ErrInvalidValue)
	}
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
			var probe SMMTForwardSMVGCSArg
			return probe.UnmarshalBER(data, probeOpts...)
		})
	}
	data, opts = preparedData, preparedOptions
	*v = SMMTForwardSMVGCSArg{}
	defer func() {
		if returnErr != nil || !ber.BERNeedsPreservation(opts) {
			return
		}
		v.berReplayNode_ = ber.CaptureGeneratedBERReplay(data, opts)
		returnErr = ber.CompleteGeneratedBERDecode(opts, v, func(base *SMMTForwardSMVGCSArg, replayOpts ...ber.EncodeOption) ([]byte, error) {
			return base.MarshalBER(replayOpts...)
		})
	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("%s: %w", "decoding SMMTForwardSMVGCSArg SEQUENCE", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "SMMTForwardSMVGCSArg", Cause: ber.ErrExtraData}
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
		v.AsciCallReference = v21_map_commondatatypes.CommonDataTypesASCICallReference(val_ascicallreference)
		if offset > len(content) || n < 0 || n > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n
		if len(v.AsciCallReference) < 1 || len(v.AsciCallReference) > 8 {
			if constraintErr := ber.CheckDecodedLength(opts, "asciCallReference", "SIZE (1..8)", len(v.AsciCallReference)); constraintErr != nil {
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
		// Decode nested CHOICE (SMSMRPOA)
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
		v.SmRPUI = v21_map_commondatatypes.CommonDataTypesSignalInfo(val_smrpui)
		if offset < 0 || offset >
			len(content) || n < 0 || n > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n
		if len(v.SmRPUI) < 1 || len(v.SmRPUI) > 200 {
			if constraintErr := ber.CheckDecodedLength(opts, "sm-RP-UI", "SIZE (1..200)", len(v.SmRPUI)); constraintErr != nil {
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
				// Decode nested SEQUENCE (__asn1pkg_v21_map_extensiondatatypes.ExtensionDataTypesExtensionContainer)
				_, n_extensioncontainer, _, tlvErr_extensioncontainer := ber.DecodeTLV(content[offset:], opts...)
				if tlvErr_extensioncontainer != nil {
					return qualifyBERError(tlvErr_extensioncontainer, "extensionContainer", "decoding", false)
				}
				var dec_extensioncontainer v21_map_extensiondatatypes.ExtensionDataTypesExtensionContainer
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
			return &ber.DecodeError{Offset: offset, TypeName: "SMMTForwardSMVGCSArg", Cause: extErr_}
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: the first unknown addition must differ from trailing OPTIONAL/DEFAULT tags.
		if len(v.ExtData_) == 0 && (peekTag.Class == tag.ClassUniversal && peekTag.Number == 16) {
			if !ber.ConstraintToleranceEnabled(opts) {
				return &ber.DecodeError{Offset: offset, TypeName: "SMMTForwardSMVGCSArg", Cause: fmt.Errorf("%w: repeated or out-of-order SEQUENCE component tag %s", ber.ErrInvalidTag, peekTag)}
			}
			if orderErr_ := ber.CheckDecodedValue(opts, fmt.Sprintf("ExtData_[%d]", len(v.ExtData_)), "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); orderErr_ != nil {
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

// MarshalBER encodes SMMTForwardSMVGCSRes to BER format.
func (v *SMMTForwardSMVGCSRes) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: SMMTForwardSMVGCSRes receiver is nil", ber.ErrInvalidValue)
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
func (v *SMMTForwardSMVGCSRes) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if v.SmRPUI != nil {
		if len(*v.SmRPUI) < 1 || len(*v.SmRPUI) > 200 {
			if constraintErr := ber.CheckEncodedLength(opts, "sm-RP-UI", "SIZE (1..200)", len(*v.SmRPUI)); constraintErr != nil {
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
			if constraintErr := ber.CheckEncodedLength(opts, "dispatcherList", "SIZE (1..5)", len((v.DispatcherList).Values)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_dispatcherlist, err := MarshalBERSMDispatcherList(v.DispatcherList, ber.ParentCollectionSizeEncodeOptions(ber.ChildEncodeOptions(opts, "dispatcherList"))...)
		if err != nil {
			return nil, qualifyBERError(err, "dispatcherList", "encoding", false)
		}
		if ber.BERReplayEnabled(opts) && v.DispatcherListIndef_ {
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
			if constraintErr := ber.CheckEncodedLength(opts, "additionalDispatcherList", "SIZE (1..15)", len((v.AdditionalDispatcherList).Values)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_additionaldispatcherlist, err := MarshalBERSMAdditionalDispatcherList(v.AdditionalDispatcherList, ber.ParentCollectionSizeEncodeOptions(ber.ChildEncodeOptions(opts, "additionalDispatcherList"))...)
		if err != nil {
			return nil, qualifyBERError(err, "additionalDispatcherList", "encoding", false)
		}
		if ber.BERReplayEnabled(opts) && v.AdditionalDispatcherListIndef_ {
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
	for i, ext := range v.ExtData_ {
		if err := ber.CheckBEROpaqueReplay(opts...); err != nil {
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
		if i == 0 && ((peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2) || (peekTag.Class == tag.ClassUniversal && peekTag.Number == 5) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0)) {
			if constraintErr := ber.CheckEncodedValue(opts, "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
				return nil, constraintErr
			}
		}
		children = append(children, ext...)
	}
	ber.RecordGeneratedBERContainer(opts, children)
	return ber.EncodeSequence(children)
}
func (v *SMMTForwardSMVGCSRes) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// MarshalDER encodes SMMTForwardSMVGCSRes to DER format.
func (v *SMMTForwardSMVGCSRes) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: SMMTForwardSMVGCSRes receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if v.SmRPUI != nil {
		if len(*v.SmRPUI) < 1 || len(*v.SmRPUI) > 200 {
			if constraintErr := ber.CheckEncodedLength(nil, "sm-RP-UI", "SIZE (1..200)", len(*v.SmRPUI)); constraintErr != nil {
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
			if constraintErr := ber.CheckEncodedLength(nil, "dispatcherList", "SIZE (1..5)", len((v.DispatcherList).Values)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_dispatcherlist, err := MarshalDERSMDispatcherList(v.DispatcherList)
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
			if constraintErr := ber.CheckEncodedLength(nil, "additionalDispatcherList", "SIZE (1..15)", len((v.AdditionalDispatcherList).Values)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_additionaldispatcherlist, err := MarshalDERSMAdditionalDispatcherList(v.AdditionalDispatcherList)
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
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
		peekTag, _, _, extErr := ber.DecodeEncodedTLV(ext)
		if extErr != nil {
			return nil, extErr
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: only the first addition is restricted.
		if i == 0 && ((peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2) || (peekTag.Class == tag.ClassUniversal && peekTag.Number == 5) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0)) {
			if constraintErr := ber.CheckEncodedValue(nil, "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
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
		return nil, fmt.Errorf("%s: %w", "encoding SMMTForwardSMVGCSRes as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}
func (v *SMMTForwardSMVGCSRes) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	encoded, err := v.MarshalDER()
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBER decodes SMMTForwardSMVGCSRes from BER/DER format.
func (v *SMMTForwardSMVGCSRes) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: SMMTForwardSMVGCSRes destination is nil", ber.ErrInvalidValue)
	}
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
			var probe SMMTForwardSMVGCSRes
			return probe.UnmarshalBER(data, probeOpts...)
		})
	}
	data, opts = preparedData, preparedOptions
	*v = SMMTForwardSMVGCSRes{}
	defer func() {
		if returnErr != nil || !ber.BERNeedsPreservation(opts) {
			return
		}
		v.berReplayNode_ = ber.CaptureGeneratedBERReplay(data, opts)
		returnErr = ber.CompleteGeneratedBERDecode(opts, v, func(base *SMMTForwardSMVGCSRes, replayOpts ...ber.EncodeOption) ([]byte, error) {
			return base.MarshalBER(replayOpts...)
		})
	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("%s: %w", "decoding SMMTForwardSMVGCSRes SEQUENCE", qualifyBERError(err, "", "decoding", false))
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
				tmp_smrpui := v21_map_commondatatypes.CommonDataTypesSignalInfo(decVal_smrpui)
				v.SmRPUI = &tmp_smrpui
				if offset > len(content) || n_smrpui < 0 || n_smrpui > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_smrpui
				if len(*v.SmRPUI) < 1 || len(*v.SmRPUI) > 200 {
					if constraintErr := ber.CheckDecodedLength(opts, "sm-RP-UI", "SIZE (1..200)", len(*v.SmRPUI)); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode dispatcherList
	v.DispatcherListIndef_ = false
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
					len(content) || n_dispatcherlist < 0 || n_dispatcherlist > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				reconstructed_dispatcherlist, reconstructionErr_dispatcherlist := ber.EncodeImplicitTagWithClass(tag.ClassUniversal, tag.TagSequence, content[offset:offset+n_dispatcherlist])
				if reconstructionErr_dispatcherlist != nil {
					return qualifyBERError(reconstructionErr_dispatcherlist, "dispatcherList", "decoding", false)
				}
				dec_dispatcherlist, unmErr := UnmarshalBERSMDispatcherList(reconstructed_dispatcherlist, ber.ParentCollectionSizeDecodeOptions(ber.ChildDecodeOptions(opts, "dispatcherList"))...)
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
						v.DispatcherListIndef_ = true
					}
				}
				if offset < 0 || offset >
					len(content) || n_dispatcherlist < 0 || n_dispatcherlist > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_dispatcherlist
				if len((v.DispatcherList).Values) < 1 || len((v.DispatcherList).Values) > 5 {
					if constraintErr := ber.CheckDecodedLength(opts, "dispatcherList", "SIZE (1..5)", len((v.DispatcherList).Values)); constraintErr != nil {
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
	// Decode additionalDispatcherList
	v.AdditionalDispatcherListIndef_ = false
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
				dec_additionaldispatcherlist, unmErr := UnmarshalBERSMAdditionalDispatcherList(reconstructed_additionaldispatcherlist, ber.ParentCollectionSizeDecodeOptions(ber.ChildDecodeOptions(opts, "additionalDispatcherList"))...)
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
						v.AdditionalDispatcherListIndef_ = true
					}
				}
				if offset < 0 || offset >
					len(content) || n_additionaldispatcherlist < 0 || n_additionaldispatcherlist >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_additionaldispatcherlist
				if len((v.AdditionalDispatcherList).Values) < 1 || len((v.AdditionalDispatcherList).Values) > 15 {
					if constraintErr := ber.CheckDecodedLength(opts, "additionalDispatcherList", "SIZE (1..15)", len((v.AdditionalDispatcherList).Values)); constraintErr != nil {
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
			return &ber.DecodeError{Offset: offset, TypeName: "SMMTForwardSMVGCSRes", Cause: extErr_}
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: the first unknown addition must differ from trailing OPTIONAL/DEFAULT tags.
		if len(v.ExtData_) == 0 && ((peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2) || (peekTag.Class == tag.ClassUniversal && peekTag.Number == 5) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0)) {
			if !ber.ConstraintToleranceEnabled(opts) {
				return &ber.DecodeError{Offset: offset, TypeName: "SMMTForwardSMVGCSRes", Cause: fmt.Errorf("%w: repeated or out-of-order SEQUENCE component tag %s", ber.ErrInvalidTag, peekTag)}
			}
			if orderErr_ := ber.CheckDecodedValue(opts, fmt.Sprintf("ExtData_[%d]", len(v.ExtData_)), "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); orderErr_ != nil {
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

// MarshalBERSMDispatcherList encodes a SMDispatcherList list to BER.
func MarshalBERSMDispatcherList(collection *SMDispatcherList, opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	if collection == nil {
		return nil, fmt.Errorf("%w: required collection is nil", ber.ErrInvalidValue)
	}
	if collection.berReplayNode_ == nil {
		return marshalBERSMDispatcherList(collection, opts...)
	}
	var replayErr error
	opts, replayErr = ber.PrepareBERReplay(collection.berReplayNode_, opts, func(mode ber.EncodeOption) ([]byte, error) {
		return MarshalBERSMDispatcherList(collection, []ber.EncodeOption{mode}...)
	}, collection)
	if replayErr != nil {
		return nil, replayErr
	}
	if replayBytes, ok := ber.PreparedBERReplay(collection.berReplayNode_, opts); ok {
		return replayBytes, nil
	}
	encoded, err := marshalBERSMDispatcherList(collection, opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBERNode(encoded, collection.berReplayNode_, opts), nil
}
func marshalBERSMDispatcherList(collection *SMDispatcherList, opts ...ber.EncodeOption) ([]byte, error) {
	list := collection.Values
	if len(list) < 1 || len(list) > 5 {
		if constraintErr := ber.CheckEncodedCollectionLength(opts, "DispatcherList", "SIZE (1..5)", len(list)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	var children []byte
	for elemIndex, elem := range list {
		_ = elemIndex
		if len(elem) < 1 || len(elem) > 9 {
			if constraintErr := ber.CheckEncodedLength(opts, fmt.Sprintf("element[%d]", elemIndex), "SIZE (1..9)", len(elem)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		if len(elem) < 1 || len(elem) > 20 {
			if constraintErr := ber.CheckEncodedLength(opts, fmt.Sprintf("element[%d]", elemIndex), "SIZE (1..20)", len(elem)); constraintErr != nil {
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

func appendBERLinearSMDispatcherList(encoder *ber.LinearEncoder, collection *SMDispatcherList, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := MarshalBERSMDispatcherList(collection, opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// MarshalDERSMDispatcherList encodes a SMDispatcherList list to DER.
func MarshalDERSMDispatcherList(collection *SMDispatcherList) ([]byte, error) {
	if collection == nil {
		return nil, fmt.Errorf("%w: required collection is nil", ber.ErrInvalidValue)
	}
	list := collection.Values
	if len(list) < 1 || len(list) > 5 {
		if constraintErr := ber.CheckEncodedCollectionLength(nil, "DispatcherList", "SIZE (1..5)", len(list)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	var children []byte
	for elemIndex, elem := range list {
		_ = elemIndex
		if len(elem) < 1 || len(elem) > 9 {
			if constraintErr := ber.CheckEncodedLength(nil, fmt.Sprintf("element[%d]", elemIndex), "SIZE (1..9)", len(elem)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		if len(elem) < 1 || len(elem) > 20 {
			if constraintErr := ber.CheckEncodedLength(nil, fmt.Sprintf("element[%d]", elemIndex), "SIZE (1..20)", len(elem)); constraintErr != nil {
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
		return nil, fmt.Errorf("%s: %w", "encoding SMDispatcherList as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}

func appendDERLinearSMDispatcherList(encoder *ber.LinearEncoder, collection *SMDispatcherList) ([]byte, error) {
	encoded, err := MarshalDERSMDispatcherList(collection)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBERSMDispatcherList decodes a SMDispatcherList list from BER.
func UnmarshalBERSMDispatcherList(data []byte, opts ...ber.DecodeOption) (returnValue *SMDispatcherList, returnErr error) {
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
			_, probeErr := UnmarshalBERSMDispatcherList(data, probeOpts...)
			return probeErr
		})
	}
	data, opts = preparedData, preparedOptions
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", "decoding SMDispatcherList", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return nil, &ber.DecodeError{Offset: total, TypeName: "SMDispatcherList", Cause: ber.ErrExtraData}
	}
	var result []v21_map_commondatatypes.CommonDataTypesISDNAddressString
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
			if constraintErr := ber.CheckDecodedLength(opts, fmt.Sprintf("element[%d]", len(result)), "SIZE (1..9)", len(val)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		if len(val) < 1 || len(val) > 20 {
			if constraintErr := ber.CheckDecodedLength(opts, fmt.Sprintf("element[%d]", len(result)), "SIZE (1..20)", len(val)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		result = append(result, v21_map_commondatatypes.CommonDataTypesISDNAddressString(val))
		if offset < 0 || offset >
			len(content) || n < 0 || n > len(content[offset:]) {
			return nil, fmt.Errorf("invalid BER content window")
		}

		offset += n
	}
	if len(result) < 1 || len(result) > 5 {
		if constraintErr := ber.CheckDecodedCollectionLength(opts, "DispatcherList", "SIZE (1..5)", len(result)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	decoded := &SMDispatcherList{Values: result}
	if ber.BERNeedsPreservation(opts) {
		decoded.berReplayNode_ = ber.CaptureGeneratedBERReplay(data, opts)
		if replayErr := ber.CompleteGeneratedBERDecode(opts, decoded, func(base *SMDispatcherList, replayOpts ...ber.EncodeOption) ([]byte, error) {
			return MarshalBERSMDispatcherList(base, replayOpts...)
		}); replayErr != nil {
			return nil, replayErr
		}
	}
	return decoded, nil
}

// MarshalBERSMAdditionalDispatcherList encodes a SMAdditionalDispatcherList list to BER.
func MarshalBERSMAdditionalDispatcherList(collection *SMAdditionalDispatcherList, opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	if collection == nil {
		return nil, fmt.Errorf("%w: required collection is nil", ber.ErrInvalidValue)
	}
	if collection.berReplayNode_ == nil {
		return marshalBERSMAdditionalDispatcherList(collection, opts...)
	}
	var replayErr error
	opts, replayErr = ber.PrepareBERReplay(collection.berReplayNode_, opts, func(mode ber.EncodeOption) ([]byte, error) {
		return MarshalBERSMAdditionalDispatcherList(collection, []ber.EncodeOption{mode}...)
	}, collection)
	if replayErr != nil {
		return nil, replayErr
	}
	if replayBytes, ok := ber.PreparedBERReplay(collection.berReplayNode_, opts); ok {
		return replayBytes, nil
	}
	encoded, err := marshalBERSMAdditionalDispatcherList(collection, opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBERNode(encoded, collection.berReplayNode_, opts), nil
}
func marshalBERSMAdditionalDispatcherList(collection *SMAdditionalDispatcherList, opts ...ber.EncodeOption) ([]byte, error) {
	list := collection.Values
	if len(list) < 1 || len(list) > 15 {
		if constraintErr := ber.CheckEncodedCollectionLength(opts, "AdditionalDispatcherList", "SIZE (1..15)", len(list)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	var children []byte
	for elemIndex, elem := range list {
		_ = elemIndex
		if len(elem) < 1 || len(elem) > 9 {
			if constraintErr := ber.CheckEncodedLength(opts, fmt.Sprintf("element[%d]", elemIndex), "SIZE (1..9)", len(elem)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		if len(elem) < 1 || len(elem) > 20 {
			if constraintErr := ber.CheckEncodedLength(opts, fmt.Sprintf("element[%d]", elemIndex), "SIZE (1..20)", len(elem)); constraintErr != nil {
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

func appendBERLinearSMAdditionalDispatcherList(encoder *ber.LinearEncoder, collection *SMAdditionalDispatcherList, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := MarshalBERSMAdditionalDispatcherList(collection, opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// MarshalDERSMAdditionalDispatcherList encodes a SMAdditionalDispatcherList list to DER.
func MarshalDERSMAdditionalDispatcherList(collection *SMAdditionalDispatcherList) ([]byte, error) {
	if collection == nil {
		return nil, fmt.Errorf("%w: required collection is nil", ber.ErrInvalidValue)
	}
	list := collection.Values
	if len(list) < 1 || len(list) > 15 {
		if constraintErr := ber.CheckEncodedCollectionLength(nil, "AdditionalDispatcherList", "SIZE (1..15)", len(list)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	var children []byte
	for elemIndex, elem := range list {
		_ = elemIndex
		if len(elem) < 1 || len(elem) > 9 {
			if constraintErr := ber.CheckEncodedLength(nil, fmt.Sprintf("element[%d]", elemIndex), "SIZE (1..9)", len(elem)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		if len(elem) < 1 || len(elem) > 20 {
			if constraintErr := ber.CheckEncodedLength(nil, fmt.Sprintf("element[%d]", elemIndex), "SIZE (1..20)", len(elem)); constraintErr != nil {
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
		return nil, fmt.Errorf("%s: %w", "encoding SMAdditionalDispatcherList as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}

func appendDERLinearSMAdditionalDispatcherList(encoder *ber.LinearEncoder, collection *SMAdditionalDispatcherList) ([]byte, error) {
	encoded, err := MarshalDERSMAdditionalDispatcherList(collection)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBERSMAdditionalDispatcherList decodes a SMAdditionalDispatcherList list from BER.
func UnmarshalBERSMAdditionalDispatcherList(data []byte, opts ...ber.DecodeOption) (returnValue *SMAdditionalDispatcherList, returnErr error) {
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
			_, probeErr := UnmarshalBERSMAdditionalDispatcherList(data, probeOpts...)
			return probeErr
		})
	}
	data, opts = preparedData, preparedOptions
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", "decoding SMAdditionalDispatcherList", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return nil, &ber.DecodeError{Offset: total, TypeName: "SMAdditionalDispatcherList", Cause: ber.ErrExtraData}
	}
	var result []v21_map_commondatatypes.CommonDataTypesISDNAddressString
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
			if constraintErr := ber.CheckDecodedLength(opts, fmt.Sprintf("element[%d]", len(result)), "SIZE (1..9)", len(val)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		if len(val) < 1 || len(val) > 20 {
			if constraintErr := ber.CheckDecodedLength(opts, fmt.Sprintf("element[%d]", len(result)), "SIZE (1..20)", len(val)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		result = append(result, v21_map_commondatatypes.CommonDataTypesISDNAddressString(val))
		if offset < 0 || offset >
			len(content) || n < 0 || n > len(content[offset:]) {
			return nil, fmt.Errorf("invalid BER content window")
		}

		offset += n
	}
	if len(result) < 1 || len(result) > 15 {
		if constraintErr := ber.CheckDecodedCollectionLength(opts, "AdditionalDispatcherList", "SIZE (1..15)", len(result)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	decoded := &SMAdditionalDispatcherList{Values: result}
	if ber.BERNeedsPreservation(opts) {
		decoded.berReplayNode_ = ber.CaptureGeneratedBERReplay(data, opts)
		if replayErr := ber.CompleteGeneratedBERDecode(opts, decoded, func(base *SMAdditionalDispatcherList, replayOpts ...ber.EncodeOption) ([]byte, error) {
			return MarshalBERSMAdditionalDispatcherList(base, replayOpts...)
		}); replayErr != nil {
			return nil, replayErr
		}
	}
	return decoded, nil
}
