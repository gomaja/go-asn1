// Code generated from ASN.1 module "MAP-ER-DataTypes". DO NOT EDIT.

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

// RoamingNotAllowedParam represents the ASN.1 type RoamingNotAllowedParam (SEQUENCE).
type RoamingNotAllowedParam struct {
	RoamingNotAllowedCause           RoamingNotAllowedCause            `asn1:""`
	ExtensionContainer               *ExtensionContainer               `asn1:",optional" json:"ExtensionContainer,omitempty"`
	AdditionalRoamingNotAllowedCause *AdditionalRoamingNotAllowedCause `asn1:"tag:0,context,implicit,optional" json:"AdditionalRoamingNotAllowedCause,omitempty"`
	ExtCount_                        int64                             `asn1:"-" json:"-"`
	ExtPresent_                      []bool                            `asn1:"-" json:"-"`
	ExtData_                         [][]byte                          `asn1:"-" json:"-"`
	berOriginal_                     []byte                            `asn1:"-" json:"-"`
	berSnapshot_                     []byte                            `asn1:"-" json:"-"`
}

// AdditionalRoamingNotAllowedCause represents the ASN.1 ENUMERATED type AdditionalRoamingNotAllowedCause.
type AdditionalRoamingNotAllowedCause int64

const (
	AdditionalRoamingNotAllowedCauseSupportedRATTypesNotAllowed AdditionalRoamingNotAllowedCause = 0
)

func (v AdditionalRoamingNotAllowedCause) String() string {
	switch v {
	case AdditionalRoamingNotAllowedCauseSupportedRATTypesNotAllowed:
		return "supportedRAT-TypesNotAllowed"
	default:
		return "unknown"
	}
}

// RoamingNotAllowedCause represents the ASN.1 ENUMERATED type RoamingNotAllowedCause.
type RoamingNotAllowedCause int64

const (
	RoamingNotAllowedCausePlmnRoamingNotAllowed     RoamingNotAllowedCause = 0
	RoamingNotAllowedCauseOperatorDeterminedBarring RoamingNotAllowedCause = 3
)

func (v RoamingNotAllowedCause) String() string {
	switch v {
	case RoamingNotAllowedCausePlmnRoamingNotAllowed:
		return "plmnRoamingNotAllowed"
	case RoamingNotAllowedCauseOperatorDeterminedBarring:
		return "operatorDeterminedBarring"
	default:
		return "unknown"
	}
}

// CallBarredParam choice constants.
const (
	CallBarredParamChoiceCallBarringCause          = 1
	CallBarredParamChoiceExtensibleCallBarredParam = 2
)

// CallBarredParam represents the ASN.1 CHOICE type CallBarredParam.
type CallBarredParam struct {
	Choice                    int
	berOriginal_              []byte                     `json:"-"`
	berSnapshot_              []byte                     `json:"-"`
	CallBarringCause          *CallBarringCause          `json:"CallBarringCause,omitempty"`
	ExtensibleCallBarredParam *ExtensibleCallBarredParam `json:"ExtensibleCallBarredParam,omitempty"`
}

// NewCallBarredParamCallBarringCause creates a CallBarredParam with the callBarringCause alternative.
func NewCallBarredParamCallBarringCause(v CallBarringCause) CallBarredParam {
	return CallBarredParam{
		Choice:           CallBarredParamChoiceCallBarringCause,
		CallBarringCause: &v,
	}
}

// NewCallBarredParamExtensibleCallBarredParam creates a CallBarredParam with the extensibleCallBarredParam alternative.
func NewCallBarredParamExtensibleCallBarredParam(v ExtensibleCallBarredParam) CallBarredParam {
	return CallBarredParam{
		Choice:                    CallBarredParamChoiceExtensibleCallBarredParam,
		ExtensibleCallBarredParam: &v,
	}
}

// CallBarringCause represents the ASN.1 ENUMERATED type CallBarringCause.
type CallBarringCause int64

const (
	CallBarringCauseBarringServiceActive CallBarringCause = 0
	CallBarringCauseOperatorBarring      CallBarringCause = 1
)

func (v CallBarringCause) String() string {
	switch v {
	case CallBarringCauseBarringServiceActive:
		return "barringServiceActive"
	case CallBarringCauseOperatorBarring:
		return "operatorBarring"
	default:
		return "unknown"
	}
}

// ExtensibleCallBarredParam represents the ASN.1 type ExtensibleCallBarredParam (SEQUENCE).
type ExtensibleCallBarredParam struct {
	CallBarringCause              *CallBarringCause   `asn1:",optional" json:"CallBarringCause,omitempty"`
	ExtensionContainer            *ExtensionContainer `asn1:",optional" json:"ExtensionContainer,omitempty"`
	UnauthorisedMessageOriginator *struct{}           `asn1:"tag:1,context,implicit,optional" json:"UnauthorisedMessageOriginator,omitempty"`
	AnonymousCallRejection        *struct{}           `asn1:"tag:2,context,implicit,optional" json:"AnonymousCallRejection,omitempty"`
	ExtCount_                     int64               `asn1:"-" json:"-"`
	ExtPresent_                   []bool              `asn1:"-" json:"-"`
	ExtData_                      [][]byte            `asn1:"-" json:"-"`
	berOriginal_                  []byte              `asn1:"-" json:"-"`
	berSnapshot_                  []byte              `asn1:"-" json:"-"`
}

// CUGRejectParam represents the ASN.1 type CUG-RejectParam (SEQUENCE).
type CUGRejectParam struct {
	CugRejectCause     *CUGRejectCause     `asn1:",optional" json:"CugRejectCause,omitempty"`
	ExtensionContainer *ExtensionContainer `asn1:",optional" json:"ExtensionContainer,omitempty"`
	ExtCount_          int64               `asn1:"-" json:"-"`
	ExtPresent_        []bool              `asn1:"-" json:"-"`
	ExtData_           [][]byte            `asn1:"-" json:"-"`
	berOriginal_       []byte              `asn1:"-" json:"-"`
	berSnapshot_       []byte              `asn1:"-" json:"-"`
}

// CUGRejectCause represents the ASN.1 ENUMERATED type CUG-RejectCause.
type CUGRejectCause int64

const (
	CUGRejectCauseIncomingCallsBarredWithinCUG                CUGRejectCause = 0
	CUGRejectCauseSubscriberNotMemberOfCUG                    CUGRejectCause = 1
	CUGRejectCauseRequestedBasicServiceViolatesCUGConstraints CUGRejectCause = 5
	CUGRejectCauseCalledPartySSInteractionViolation           CUGRejectCause = 7
)

func (v CUGRejectCause) String() string {
	switch v {
	case CUGRejectCauseIncomingCallsBarredWithinCUG:
		return "incomingCallsBarredWithinCUG"
	case CUGRejectCauseSubscriberNotMemberOfCUG:
		return "subscriberNotMemberOfCUG"
	case CUGRejectCauseRequestedBasicServiceViolatesCUGConstraints:
		return "requestedBasicServiceViolatesCUG-Constraints"
	case CUGRejectCauseCalledPartySSInteractionViolation:
		return "calledPartySS-InteractionViolation"
	default:
		return "unknown"
	}
}

// SSIncompatibilityCause represents the ASN.1 type SS-IncompatibilityCause (SEQUENCE).
type SSIncompatibilityCause struct {
	SsCode       *SSCode           `asn1:"tag:1,context,implicit,optional" json:"SsCode,omitempty"`
	BasicService *BasicServiceCode `asn1:",optional" json:"BasicService,omitempty"`
	SsStatus     *SSStatus         `asn1:"tag:4,context,implicit,optional" json:"SsStatus,omitempty"`
	ExtCount_    int64             `asn1:"-" json:"-"`
	ExtPresent_  []bool            `asn1:"-" json:"-"`
	ExtData_     [][]byte          `asn1:"-" json:"-"`
	berOriginal_ []byte            `asn1:"-" json:"-"`
	berSnapshot_ []byte            `asn1:"-" json:"-"`
}

// PWRegistrationFailureCause represents the ASN.1 ENUMERATED type PW-RegistrationFailureCause.
type PWRegistrationFailureCause int64

const (
	PWRegistrationFailureCauseUndetermined         PWRegistrationFailureCause = 0
	PWRegistrationFailureCauseInvalidFormat        PWRegistrationFailureCause = 1
	PWRegistrationFailureCauseNewPasswordsMismatch PWRegistrationFailureCause = 2
)

func (v PWRegistrationFailureCause) String() string {
	switch v {
	case PWRegistrationFailureCauseUndetermined:
		return "undetermined"
	case PWRegistrationFailureCauseInvalidFormat:
		return "invalidFormat"
	case PWRegistrationFailureCauseNewPasswordsMismatch:
		return "newPasswordsMismatch"
	default:
		return "unknown"
	}
}

// SMEnumeratedDeliveryFailureCause represents the ASN.1 ENUMERATED type SM-EnumeratedDeliveryFailureCause.
type SMEnumeratedDeliveryFailureCause int64

const (
	SMEnumeratedDeliveryFailureCauseMemoryCapacityExceeded    SMEnumeratedDeliveryFailureCause = 0
	SMEnumeratedDeliveryFailureCauseEquipmentProtocolError    SMEnumeratedDeliveryFailureCause = 1
	SMEnumeratedDeliveryFailureCauseEquipmentNotSMEquipped    SMEnumeratedDeliveryFailureCause = 2
	SMEnumeratedDeliveryFailureCauseUnknownServiceCentre      SMEnumeratedDeliveryFailureCause = 3
	SMEnumeratedDeliveryFailureCauseScCongestion              SMEnumeratedDeliveryFailureCause = 4
	SMEnumeratedDeliveryFailureCauseInvalidSMEAddress         SMEnumeratedDeliveryFailureCause = 5
	SMEnumeratedDeliveryFailureCauseSubscriberNotSCSubscriber SMEnumeratedDeliveryFailureCause = 6
)

func (v SMEnumeratedDeliveryFailureCause) String() string {
	switch v {
	case SMEnumeratedDeliveryFailureCauseMemoryCapacityExceeded:
		return "memoryCapacityExceeded"
	case SMEnumeratedDeliveryFailureCauseEquipmentProtocolError:
		return "equipmentProtocolError"
	case SMEnumeratedDeliveryFailureCauseEquipmentNotSMEquipped:
		return "equipmentNotSM-Equipped"
	case SMEnumeratedDeliveryFailureCauseUnknownServiceCentre:
		return "unknownServiceCentre"
	case SMEnumeratedDeliveryFailureCauseScCongestion:
		return "sc-Congestion"
	case SMEnumeratedDeliveryFailureCauseInvalidSMEAddress:
		return "invalidSME-Address"
	case SMEnumeratedDeliveryFailureCauseSubscriberNotSCSubscriber:
		return "subscriberNotSC-Subscriber"
	default:
		return "unknown"
	}
}

// SMDeliveryFailureCause represents the ASN.1 type SM-DeliveryFailureCause (SEQUENCE).
type SMDeliveryFailureCause struct {
	SmEnumeratedDeliveryFailureCause SMEnumeratedDeliveryFailureCause `asn1:""`
	DiagnosticInfo                   *SignalInfo                      `asn1:",optional" json:"DiagnosticInfo,omitempty"`
	ExtensionContainer               *ExtensionContainer              `asn1:",optional" json:"ExtensionContainer,omitempty"`
	ExtCount_                        int64                            `asn1:"-" json:"-"`
	ExtPresent_                      []bool                           `asn1:"-" json:"-"`
	ExtData_                         [][]byte                         `asn1:"-" json:"-"`
	berOriginal_                     []byte                           `asn1:"-" json:"-"`
	berSnapshot_                     []byte                           `asn1:"-" json:"-"`
}

// AbsentSubscriberSMParam represents the ASN.1 type AbsentSubscriberSM-Param (SEQUENCE).
type AbsentSubscriberSMParam struct {
	AbsentSubscriberDiagnosticSM           *AbsentSubscriberDiagnosticSM `asn1:",optional" json:"AbsentSubscriberDiagnosticSM,omitempty"`
	ExtensionContainer                     *ExtensionContainer           `asn1:",optional" json:"ExtensionContainer,omitempty"`
	AdditionalAbsentSubscriberDiagnosticSM *AbsentSubscriberDiagnosticSM `asn1:"tag:0,context,implicit,optional" json:"AdditionalAbsentSubscriberDiagnosticSM,omitempty"`
	Imsi                                   *IMSI                         `asn1:"tag:1,context,implicit,optional" json:"Imsi,omitempty"`
	RequestedRetransmissionTime            *Time                         `asn1:"tag:2,context,implicit,optional" json:"RequestedRetransmissionTime,omitempty"`
	UserIdentifierAlert                    *IMSI                         `asn1:"tag:3,context,implicit,optional" json:"UserIdentifierAlert,omitempty"`
	ExtCount_                              int64                         `asn1:"-" json:"-"`
	ExtPresent_                            []bool                        `asn1:"-" json:"-"`
	ExtData_                               [][]byte                      `asn1:"-" json:"-"`
	berOriginal_                           []byte                        `asn1:"-" json:"-"`
	berSnapshot_                           []byte                        `asn1:"-" json:"-"`
}

// AbsentSubscriberDiagnosticSM represents the ASN.1 type AbsentSubscriberDiagnosticSM (INTEGER).
type AbsentSubscriberDiagnosticSM = int64

// SystemFailureParam choice constants.
const (
	SystemFailureParamChoiceNetworkResource              = 1
	SystemFailureParamChoiceExtensibleSystemFailureParam = 2
)

// SystemFailureParam represents the ASN.1 CHOICE type SystemFailureParam.
type SystemFailureParam struct {
	Choice                       int
	berOriginal_                 []byte                        `json:"-"`
	berSnapshot_                 []byte                        `json:"-"`
	NetworkResource              *NetworkResource              `json:"NetworkResource,omitempty"`
	ExtensibleSystemFailureParam *ExtensibleSystemFailureParam `json:"ExtensibleSystemFailureParam,omitempty"`
}

// NewSystemFailureParamNetworkResource creates a SystemFailureParam with the networkResource alternative.
func NewSystemFailureParamNetworkResource(v NetworkResource) SystemFailureParam {
	return SystemFailureParam{
		Choice:          SystemFailureParamChoiceNetworkResource,
		NetworkResource: &v,
	}
}

// NewSystemFailureParamExtensibleSystemFailureParam creates a SystemFailureParam with the extensibleSystemFailureParam alternative.
func NewSystemFailureParamExtensibleSystemFailureParam(v ExtensibleSystemFailureParam) SystemFailureParam {
	return SystemFailureParam{
		Choice:                       SystemFailureParamChoiceExtensibleSystemFailureParam,
		ExtensibleSystemFailureParam: &v,
	}
}

// ExtensibleSystemFailureParam represents the ASN.1 type ExtensibleSystemFailureParam (SEQUENCE).
type ExtensibleSystemFailureParam struct {
	NetworkResource           *NetworkResource           `asn1:",optional" json:"NetworkResource,omitempty"`
	ExtensionContainer        *ExtensionContainer        `asn1:",optional" json:"ExtensionContainer,omitempty"`
	AdditionalNetworkResource *AdditionalNetworkResource `asn1:"tag:0,context,implicit,optional" json:"AdditionalNetworkResource,omitempty"`
	FailureCauseParam         *FailureCauseParam         `asn1:"tag:1,context,implicit,optional" json:"FailureCauseParam,omitempty"`
	ExtCount_                 int64                      `asn1:"-" json:"-"`
	ExtPresent_               []bool                     `asn1:"-" json:"-"`
	ExtData_                  [][]byte                   `asn1:"-" json:"-"`
	berOriginal_              []byte                     `asn1:"-" json:"-"`
	berSnapshot_              []byte                     `asn1:"-" json:"-"`
}

// FailureCauseParam represents the ASN.1 ENUMERATED type FailureCauseParam.
type FailureCauseParam int64

const (
	FailureCauseParamLimitReachedOnNumberOfConcurrentLocationRequests FailureCauseParam = 0
)

func (v FailureCauseParam) String() string {
	switch v {
	case FailureCauseParamLimitReachedOnNumberOfConcurrentLocationRequests:
		return "limitReachedOnNumberOfConcurrentLocationRequests"
	default:
		return "unknown"
	}
}

// DataMissingParam represents the ASN.1 type DataMissingParam (SEQUENCE).
type DataMissingParam struct {
	ExtensionContainer *ExtensionContainer `asn1:",optional" json:"ExtensionContainer,omitempty"`
	ExtCount_          int64               `asn1:"-" json:"-"`
	ExtPresent_        []bool              `asn1:"-" json:"-"`
	ExtData_           [][]byte            `asn1:"-" json:"-"`
	berOriginal_       []byte              `asn1:"-" json:"-"`
	berSnapshot_       []byte              `asn1:"-" json:"-"`
}

// UnexpectedDataParam represents the ASN.1 type UnexpectedDataParam (SEQUENCE).
type UnexpectedDataParam struct {
	ExtensionContainer   *ExtensionContainer `asn1:",optional" json:"ExtensionContainer,omitempty"`
	UnexpectedSubscriber *struct{}           `asn1:"tag:0,context,implicit,optional" json:"UnexpectedSubscriber,omitempty"`
	ExtCount_            int64               `asn1:"-" json:"-"`
	ExtPresent_          []bool              `asn1:"-" json:"-"`
	ExtData_             [][]byte            `asn1:"-" json:"-"`
	berOriginal_         []byte              `asn1:"-" json:"-"`
	berSnapshot_         []byte              `asn1:"-" json:"-"`
}

// FacilityNotSupParam represents the ASN.1 type FacilityNotSupParam (SEQUENCE).
type FacilityNotSupParam struct {
	ExtensionContainer                           *ExtensionContainer `asn1:",optional" json:"ExtensionContainer,omitempty"`
	ShapeOfLocationEstimateNotSupported          *struct{}           `asn1:"tag:0,context,implicit,optional" json:"ShapeOfLocationEstimateNotSupported,omitempty"`
	NeededLcsCapabilityNotSupportedInServingNode *struct{}           `asn1:"tag:1,context,implicit,optional" json:"NeededLcsCapabilityNotSupportedInServingNode,omitempty"`
	ExtCount_                                    int64               `asn1:"-" json:"-"`
	ExtPresent_                                  []bool              `asn1:"-" json:"-"`
	ExtData_                                     [][]byte            `asn1:"-" json:"-"`
	berOriginal_                                 []byte              `asn1:"-" json:"-"`
	berSnapshot_                                 []byte              `asn1:"-" json:"-"`
}

// ORNotAllowedParam represents the ASN.1 type OR-NotAllowedParam (SEQUENCE).
type ORNotAllowedParam struct {
	ExtensionContainer *ExtensionContainer `asn1:",optional" json:"ExtensionContainer,omitempty"`
	ExtCount_          int64               `asn1:"-" json:"-"`
	ExtPresent_        []bool              `asn1:"-" json:"-"`
	ExtData_           [][]byte            `asn1:"-" json:"-"`
	berOriginal_       []byte              `asn1:"-" json:"-"`
	berSnapshot_       []byte              `asn1:"-" json:"-"`
}

// UnknownSubscriberParam represents the ASN.1 type UnknownSubscriberParam (SEQUENCE).
type UnknownSubscriberParam struct {
	ExtensionContainer          *ExtensionContainer          `asn1:",optional" json:"ExtensionContainer,omitempty"`
	UnknownSubscriberDiagnostic *UnknownSubscriberDiagnostic `asn1:",optional" json:"UnknownSubscriberDiagnostic,omitempty"`
	ExtCount_                   int64                        `asn1:"-" json:"-"`
	ExtPresent_                 []bool                       `asn1:"-" json:"-"`
	ExtData_                    [][]byte                     `asn1:"-" json:"-"`
	berOriginal_                []byte                       `asn1:"-" json:"-"`
	berSnapshot_                []byte                       `asn1:"-" json:"-"`
}

// UnknownSubscriberDiagnostic represents the ASN.1 ENUMERATED type UnknownSubscriberDiagnostic.
type UnknownSubscriberDiagnostic int64

const (
	UnknownSubscriberDiagnosticImsiUnknown                UnknownSubscriberDiagnostic = 0
	UnknownSubscriberDiagnosticGprsEpsSubscriptionUnknown UnknownSubscriberDiagnostic = 1
	UnknownSubscriberDiagnosticNpdbMismatch               UnknownSubscriberDiagnostic = 2
)

func (v UnknownSubscriberDiagnostic) String() string {
	switch v {
	case UnknownSubscriberDiagnosticImsiUnknown:
		return "imsiUnknown"
	case UnknownSubscriberDiagnosticGprsEpsSubscriptionUnknown:
		return "gprs-eps-SubscriptionUnknown"
	case UnknownSubscriberDiagnosticNpdbMismatch:
		return "npdbMismatch"
	default:
		return "unknown"
	}
}

// NumberChangedParam represents the ASN.1 type NumberChangedParam (SEQUENCE).
type NumberChangedParam struct {
	ExtensionContainer *ExtensionContainer `asn1:",optional" json:"ExtensionContainer,omitempty"`
	ExtCount_          int64               `asn1:"-" json:"-"`
	ExtPresent_        []bool              `asn1:"-" json:"-"`
	ExtData_           [][]byte            `asn1:"-" json:"-"`
	berOriginal_       []byte              `asn1:"-" json:"-"`
	berSnapshot_       []byte              `asn1:"-" json:"-"`
}

// UnidentifiedSubParam represents the ASN.1 type UnidentifiedSubParam (SEQUENCE).
type UnidentifiedSubParam struct {
	ExtensionContainer *ExtensionContainer `asn1:",optional" json:"ExtensionContainer,omitempty"`
	ExtCount_          int64               `asn1:"-" json:"-"`
	ExtPresent_        []bool              `asn1:"-" json:"-"`
	ExtData_           [][]byte            `asn1:"-" json:"-"`
	berOriginal_       []byte              `asn1:"-" json:"-"`
	berSnapshot_       []byte              `asn1:"-" json:"-"`
}

// IllegalSubscriberParam represents the ASN.1 type IllegalSubscriberParam (SEQUENCE).
type IllegalSubscriberParam struct {
	ExtensionContainer *ExtensionContainer `asn1:",optional" json:"ExtensionContainer,omitempty"`
	ExtCount_          int64               `asn1:"-" json:"-"`
	ExtPresent_        []bool              `asn1:"-" json:"-"`
	ExtData_           [][]byte            `asn1:"-" json:"-"`
	berOriginal_       []byte              `asn1:"-" json:"-"`
	berSnapshot_       []byte              `asn1:"-" json:"-"`
}

// IllegalEquipmentParam represents the ASN.1 type IllegalEquipmentParam (SEQUENCE).
type IllegalEquipmentParam struct {
	ExtensionContainer *ExtensionContainer `asn1:",optional" json:"ExtensionContainer,omitempty"`
	ExtCount_          int64               `asn1:"-" json:"-"`
	ExtPresent_        []bool              `asn1:"-" json:"-"`
	ExtData_           [][]byte            `asn1:"-" json:"-"`
	berOriginal_       []byte              `asn1:"-" json:"-"`
	berSnapshot_       []byte              `asn1:"-" json:"-"`
}

// BearerServNotProvParam represents the ASN.1 type BearerServNotProvParam (SEQUENCE).
type BearerServNotProvParam struct {
	ExtensionContainer *ExtensionContainer `asn1:",optional" json:"ExtensionContainer,omitempty"`
	ExtCount_          int64               `asn1:"-" json:"-"`
	ExtPresent_        []bool              `asn1:"-" json:"-"`
	ExtData_           [][]byte            `asn1:"-" json:"-"`
	berOriginal_       []byte              `asn1:"-" json:"-"`
	berSnapshot_       []byte              `asn1:"-" json:"-"`
}

// TeleservNotProvParam represents the ASN.1 type TeleservNotProvParam (SEQUENCE).
type TeleservNotProvParam struct {
	ExtensionContainer *ExtensionContainer `asn1:",optional" json:"ExtensionContainer,omitempty"`
	ExtCount_          int64               `asn1:"-" json:"-"`
	ExtPresent_        []bool              `asn1:"-" json:"-"`
	ExtData_           [][]byte            `asn1:"-" json:"-"`
	berOriginal_       []byte              `asn1:"-" json:"-"`
	berSnapshot_       []byte              `asn1:"-" json:"-"`
}

// TracingBufferFullParam represents the ASN.1 type TracingBufferFullParam (SEQUENCE).
type TracingBufferFullParam struct {
	ExtensionContainer *ExtensionContainer `asn1:",optional" json:"ExtensionContainer,omitempty"`
	ExtCount_          int64               `asn1:"-" json:"-"`
	ExtPresent_        []bool              `asn1:"-" json:"-"`
	ExtData_           [][]byte            `asn1:"-" json:"-"`
	berOriginal_       []byte              `asn1:"-" json:"-"`
	berSnapshot_       []byte              `asn1:"-" json:"-"`
}

// NoRoamingNbParam represents the ASN.1 type NoRoamingNbParam (SEQUENCE).
type NoRoamingNbParam struct {
	ExtensionContainer *ExtensionContainer `asn1:",optional" json:"ExtensionContainer,omitempty"`
	ExtCount_          int64               `asn1:"-" json:"-"`
	ExtPresent_        []bool              `asn1:"-" json:"-"`
	ExtData_           [][]byte            `asn1:"-" json:"-"`
	berOriginal_       []byte              `asn1:"-" json:"-"`
	berSnapshot_       []byte              `asn1:"-" json:"-"`
}

// AbsentSubscriberParam represents the ASN.1 type AbsentSubscriberParam (SEQUENCE).
type AbsentSubscriberParam struct {
	ExtensionContainer     *ExtensionContainer     `asn1:",optional" json:"ExtensionContainer,omitempty"`
	AbsentSubscriberReason *AbsentSubscriberReason `asn1:"tag:0,context,implicit,optional" json:"AbsentSubscriberReason,omitempty"`
	ExtCount_              int64                   `asn1:"-" json:"-"`
	ExtPresent_            []bool                  `asn1:"-" json:"-"`
	ExtData_               [][]byte                `asn1:"-" json:"-"`
	berOriginal_           []byte                  `asn1:"-" json:"-"`
	berSnapshot_           []byte                  `asn1:"-" json:"-"`
}

// AbsentSubscriberReason represents the ASN.1 ENUMERATED type AbsentSubscriberReason.
type AbsentSubscriberReason int64

const (
	AbsentSubscriberReasonImsiDetach     AbsentSubscriberReason = 0
	AbsentSubscriberReasonRestrictedArea AbsentSubscriberReason = 1
	AbsentSubscriberReasonNoPageResponse AbsentSubscriberReason = 2
	AbsentSubscriberReasonPurgedMS       AbsentSubscriberReason = 3
	AbsentSubscriberReasonMtRoamingRetry AbsentSubscriberReason = 4
	AbsentSubscriberReasonBusySubscriber AbsentSubscriberReason = 5
)

func (v AbsentSubscriberReason) String() string {
	switch v {
	case AbsentSubscriberReasonImsiDetach:
		return "imsiDetach"
	case AbsentSubscriberReasonRestrictedArea:
		return "restrictedArea"
	case AbsentSubscriberReasonNoPageResponse:
		return "noPageResponse"
	case AbsentSubscriberReasonPurgedMS:
		return "purgedMS"
	case AbsentSubscriberReasonMtRoamingRetry:
		return "mtRoamingRetry"
	case AbsentSubscriberReasonBusySubscriber:
		return "busySubscriber"
	default:
		return "unknown"
	}
}

// BusySubscriberParam represents the ASN.1 type BusySubscriberParam (SEQUENCE).
type BusySubscriberParam struct {
	ExtensionContainer *ExtensionContainer `asn1:",optional" json:"ExtensionContainer,omitempty"`
	CcbsPossible       *struct{}           `asn1:"tag:0,context,implicit,optional" json:"CcbsPossible,omitempty"`
	CcbsBusy           *struct{}           `asn1:"tag:1,context,implicit,optional" json:"CcbsBusy,omitempty"`
	ExtCount_          int64               `asn1:"-" json:"-"`
	ExtPresent_        []bool              `asn1:"-" json:"-"`
	ExtData_           [][]byte            `asn1:"-" json:"-"`
	berOriginal_       []byte              `asn1:"-" json:"-"`
	berSnapshot_       []byte              `asn1:"-" json:"-"`
}

// NoSubscriberReplyParam represents the ASN.1 type NoSubscriberReplyParam (SEQUENCE).
type NoSubscriberReplyParam struct {
	ExtensionContainer *ExtensionContainer `asn1:",optional" json:"ExtensionContainer,omitempty"`
	ExtCount_          int64               `asn1:"-" json:"-"`
	ExtPresent_        []bool              `asn1:"-" json:"-"`
	ExtData_           [][]byte            `asn1:"-" json:"-"`
	berOriginal_       []byte              `asn1:"-" json:"-"`
	berSnapshot_       []byte              `asn1:"-" json:"-"`
}

// ForwardingViolationParam represents the ASN.1 type ForwardingViolationParam (SEQUENCE).
type ForwardingViolationParam struct {
	ExtensionContainer *ExtensionContainer `asn1:",optional" json:"ExtensionContainer,omitempty"`
	ExtCount_          int64               `asn1:"-" json:"-"`
	ExtPresent_        []bool              `asn1:"-" json:"-"`
	ExtData_           [][]byte            `asn1:"-" json:"-"`
	berOriginal_       []byte              `asn1:"-" json:"-"`
	berSnapshot_       []byte              `asn1:"-" json:"-"`
}

// ForwardingFailedParam represents the ASN.1 type ForwardingFailedParam (SEQUENCE).
type ForwardingFailedParam struct {
	ExtensionContainer *ExtensionContainer `asn1:",optional" json:"ExtensionContainer,omitempty"`
	ExtCount_          int64               `asn1:"-" json:"-"`
	ExtPresent_        []bool              `asn1:"-" json:"-"`
	ExtData_           [][]byte            `asn1:"-" json:"-"`
	berOriginal_       []byte              `asn1:"-" json:"-"`
	berSnapshot_       []byte              `asn1:"-" json:"-"`
}

// ATINotAllowedParam represents the ASN.1 type ATI-NotAllowedParam (SEQUENCE).
type ATINotAllowedParam struct {
	ExtensionContainer *ExtensionContainer `asn1:",optional" json:"ExtensionContainer,omitempty"`
	ExtCount_          int64               `asn1:"-" json:"-"`
	ExtPresent_        []bool              `asn1:"-" json:"-"`
	ExtData_           [][]byte            `asn1:"-" json:"-"`
	berOriginal_       []byte              `asn1:"-" json:"-"`
	berSnapshot_       []byte              `asn1:"-" json:"-"`
}

// ATSINotAllowedParam represents the ASN.1 type ATSI-NotAllowedParam (SEQUENCE).
type ATSINotAllowedParam struct {
	ExtensionContainer *ExtensionContainer `asn1:",optional" json:"ExtensionContainer,omitempty"`
	ExtCount_          int64               `asn1:"-" json:"-"`
	ExtPresent_        []bool              `asn1:"-" json:"-"`
	ExtData_           [][]byte            `asn1:"-" json:"-"`
	berOriginal_       []byte              `asn1:"-" json:"-"`
	berSnapshot_       []byte              `asn1:"-" json:"-"`
}

// ATMNotAllowedParam represents the ASN.1 type ATM-NotAllowedParam (SEQUENCE).
type ATMNotAllowedParam struct {
	ExtensionContainer *ExtensionContainer `asn1:",optional" json:"ExtensionContainer,omitempty"`
	ExtCount_          int64               `asn1:"-" json:"-"`
	ExtPresent_        []bool              `asn1:"-" json:"-"`
	ExtData_           [][]byte            `asn1:"-" json:"-"`
	berOriginal_       []byte              `asn1:"-" json:"-"`
	berSnapshot_       []byte              `asn1:"-" json:"-"`
}

// IllegalSSOperationParam represents the ASN.1 type IllegalSS-OperationParam (SEQUENCE).
type IllegalSSOperationParam struct {
	ExtensionContainer *ExtensionContainer `asn1:",optional" json:"ExtensionContainer,omitempty"`
	ExtCount_          int64               `asn1:"-" json:"-"`
	ExtPresent_        []bool              `asn1:"-" json:"-"`
	ExtData_           [][]byte            `asn1:"-" json:"-"`
	berOriginal_       []byte              `asn1:"-" json:"-"`
	berSnapshot_       []byte              `asn1:"-" json:"-"`
}

// SSNotAvailableParam represents the ASN.1 type SS-NotAvailableParam (SEQUENCE).
type SSNotAvailableParam struct {
	ExtensionContainer *ExtensionContainer `asn1:",optional" json:"ExtensionContainer,omitempty"`
	ExtCount_          int64               `asn1:"-" json:"-"`
	ExtPresent_        []bool              `asn1:"-" json:"-"`
	ExtData_           [][]byte            `asn1:"-" json:"-"`
	berOriginal_       []byte              `asn1:"-" json:"-"`
	berSnapshot_       []byte              `asn1:"-" json:"-"`
}

// SSSubscriptionViolationParam represents the ASN.1 type SS-SubscriptionViolationParam (SEQUENCE).
type SSSubscriptionViolationParam struct {
	ExtensionContainer *ExtensionContainer `asn1:",optional" json:"ExtensionContainer,omitempty"`
	ExtCount_          int64               `asn1:"-" json:"-"`
	ExtPresent_        []bool              `asn1:"-" json:"-"`
	ExtData_           [][]byte            `asn1:"-" json:"-"`
	berOriginal_       []byte              `asn1:"-" json:"-"`
	berSnapshot_       []byte              `asn1:"-" json:"-"`
}

// InformationNotAvailableParam represents the ASN.1 type InformationNotAvailableParam (SEQUENCE).
type InformationNotAvailableParam struct {
	ExtensionContainer *ExtensionContainer `asn1:",optional" json:"ExtensionContainer,omitempty"`
	ExtCount_          int64               `asn1:"-" json:"-"`
	ExtPresent_        []bool              `asn1:"-" json:"-"`
	ExtData_           [][]byte            `asn1:"-" json:"-"`
	berOriginal_       []byte              `asn1:"-" json:"-"`
	berSnapshot_       []byte              `asn1:"-" json:"-"`
}

// SubBusyForMTSMSParam represents the ASN.1 type SubBusyForMT-SMS-Param (SEQUENCE).
type SubBusyForMTSMSParam struct {
	ExtensionContainer      *ExtensionContainer `asn1:",optional" json:"ExtensionContainer,omitempty"`
	GprsConnectionSuspended *struct{}           `asn1:",optional" json:"GprsConnectionSuspended,omitempty"`
	ExtCount_               int64               `asn1:"-" json:"-"`
	ExtPresent_             []bool              `asn1:"-" json:"-"`
	ExtData_                [][]byte            `asn1:"-" json:"-"`
	berOriginal_            []byte              `asn1:"-" json:"-"`
	berSnapshot_            []byte              `asn1:"-" json:"-"`
}

// MessageWaitListFullParam represents the ASN.1 type MessageWaitListFullParam (SEQUENCE).
type MessageWaitListFullParam struct {
	ExtensionContainer *ExtensionContainer `asn1:",optional" json:"ExtensionContainer,omitempty"`
	ExtCount_          int64               `asn1:"-" json:"-"`
	ExtPresent_        []bool              `asn1:"-" json:"-"`
	ExtData_           [][]byte            `asn1:"-" json:"-"`
	berOriginal_       []byte              `asn1:"-" json:"-"`
	berSnapshot_       []byte              `asn1:"-" json:"-"`
}

// ResourceLimitationParam represents the ASN.1 type ResourceLimitationParam (SEQUENCE).
type ResourceLimitationParam struct {
	ExtensionContainer *ExtensionContainer `asn1:",optional" json:"ExtensionContainer,omitempty"`
	ExtCount_          int64               `asn1:"-" json:"-"`
	ExtPresent_        []bool              `asn1:"-" json:"-"`
	ExtData_           [][]byte            `asn1:"-" json:"-"`
	berOriginal_       []byte              `asn1:"-" json:"-"`
	berSnapshot_       []byte              `asn1:"-" json:"-"`
}

// NoGroupCallNbParam represents the ASN.1 type NoGroupCallNbParam (SEQUENCE).
type NoGroupCallNbParam struct {
	ExtensionContainer *ExtensionContainer `asn1:",optional" json:"ExtensionContainer,omitempty"`
	ExtCount_          int64               `asn1:"-" json:"-"`
	ExtPresent_        []bool              `asn1:"-" json:"-"`
	ExtData_           [][]byte            `asn1:"-" json:"-"`
	berOriginal_       []byte              `asn1:"-" json:"-"`
	berSnapshot_       []byte              `asn1:"-" json:"-"`
}

// IncompatibleTerminalParam represents the ASN.1 type IncompatibleTerminalParam (SEQUENCE).
type IncompatibleTerminalParam struct {
	ExtensionContainer *ExtensionContainer `asn1:",optional" json:"ExtensionContainer,omitempty"`
	ExtCount_          int64               `asn1:"-" json:"-"`
	ExtPresent_        []bool              `asn1:"-" json:"-"`
	ExtData_           [][]byte            `asn1:"-" json:"-"`
	berOriginal_       []byte              `asn1:"-" json:"-"`
	berSnapshot_       []byte              `asn1:"-" json:"-"`
}

// ShortTermDenialParam represents the ASN.1 type ShortTermDenialParam (SEQUENCE).
type ShortTermDenialParam struct {
	ExtCount_    int64    `asn1:"-" json:"-"`
	ExtPresent_  []bool   `asn1:"-" json:"-"`
	ExtData_     [][]byte `asn1:"-" json:"-"`
	berOriginal_ []byte   `asn1:"-" json:"-"`
	berSnapshot_ []byte   `asn1:"-" json:"-"`
}

// LongTermDenialParam represents the ASN.1 type LongTermDenialParam (SEQUENCE).
type LongTermDenialParam struct {
	ExtCount_    int64    `asn1:"-" json:"-"`
	ExtPresent_  []bool   `asn1:"-" json:"-"`
	ExtData_     [][]byte `asn1:"-" json:"-"`
	berOriginal_ []byte   `asn1:"-" json:"-"`
	berSnapshot_ []byte   `asn1:"-" json:"-"`
}

// UnauthorizedRequestingNetworkParam represents the ASN.1 type UnauthorizedRequestingNetwork-Param (SEQUENCE).
type UnauthorizedRequestingNetworkParam struct {
	ExtensionContainer *ExtensionContainer `asn1:",optional" json:"ExtensionContainer,omitempty"`
	ExtCount_          int64               `asn1:"-" json:"-"`
	ExtPresent_        []bool              `asn1:"-" json:"-"`
	ExtData_           [][]byte            `asn1:"-" json:"-"`
	berOriginal_       []byte              `asn1:"-" json:"-"`
	berSnapshot_       []byte              `asn1:"-" json:"-"`
}

// UnauthorizedLCSClientParam represents the ASN.1 type UnauthorizedLCSClient-Param (SEQUENCE).
type UnauthorizedLCSClientParam struct {
	UnauthorizedLCSClientDiagnostic *UnauthorizedLCSClientDiagnostic `asn1:"tag:0,context,implicit,optional" json:"UnauthorizedLCSClientDiagnostic,omitempty"`
	ExtensionContainer              *ExtensionContainer              `asn1:"tag:1,context,implicit,optional" json:"ExtensionContainer,omitempty"`
	ExtCount_                       int64                            `asn1:"-" json:"-"`
	ExtPresent_                     []bool                           `asn1:"-" json:"-"`
	ExtData_                        [][]byte                         `asn1:"-" json:"-"`
	berOriginal_                    []byte                           `asn1:"-" json:"-"`
	berSnapshot_                    []byte                           `asn1:"-" json:"-"`
}

// UnauthorizedLCSClientDiagnostic represents the ASN.1 ENUMERATED type UnauthorizedLCSClient-Diagnostic.
type UnauthorizedLCSClientDiagnostic int64

const (
	UnauthorizedLCSClientDiagnosticNoAdditionalInformation                        UnauthorizedLCSClientDiagnostic = 0
	UnauthorizedLCSClientDiagnosticClientNotInMSPrivacyExceptionList              UnauthorizedLCSClientDiagnostic = 1
	UnauthorizedLCSClientDiagnosticCallToClientNotSetup                           UnauthorizedLCSClientDiagnostic = 2
	UnauthorizedLCSClientDiagnosticPrivacyOverrideNotApplicable                   UnauthorizedLCSClientDiagnostic = 3
	UnauthorizedLCSClientDiagnosticDisallowedByLocalRegulatoryRequirements        UnauthorizedLCSClientDiagnostic = 4
	UnauthorizedLCSClientDiagnosticUnauthorizedPrivacyClass                       UnauthorizedLCSClientDiagnostic = 5
	UnauthorizedLCSClientDiagnosticUnauthorizedCallSessionUnrelatedExternalClient UnauthorizedLCSClientDiagnostic = 6
	UnauthorizedLCSClientDiagnosticUnauthorizedCallSessionRelatedExternalClient   UnauthorizedLCSClientDiagnostic = 7
)

func (v UnauthorizedLCSClientDiagnostic) String() string {
	switch v {
	case UnauthorizedLCSClientDiagnosticNoAdditionalInformation:
		return "noAdditionalInformation"
	case UnauthorizedLCSClientDiagnosticClientNotInMSPrivacyExceptionList:
		return "clientNotInMSPrivacyExceptionList"
	case UnauthorizedLCSClientDiagnosticCallToClientNotSetup:
		return "callToClientNotSetup"
	case UnauthorizedLCSClientDiagnosticPrivacyOverrideNotApplicable:
		return "privacyOverrideNotApplicable"
	case UnauthorizedLCSClientDiagnosticDisallowedByLocalRegulatoryRequirements:
		return "disallowedByLocalRegulatoryRequirements"
	case UnauthorizedLCSClientDiagnosticUnauthorizedPrivacyClass:
		return "unauthorizedPrivacyClass"
	case UnauthorizedLCSClientDiagnosticUnauthorizedCallSessionUnrelatedExternalClient:
		return "unauthorizedCallSessionUnrelatedExternalClient"
	case UnauthorizedLCSClientDiagnosticUnauthorizedCallSessionRelatedExternalClient:
		return "unauthorizedCallSessionRelatedExternalClient"
	default:
		return "unknown"
	}
}

// PositionMethodFailureParam represents the ASN.1 type PositionMethodFailure-Param (SEQUENCE).
type PositionMethodFailureParam struct {
	PositionMethodFailureDiagnostic *PositionMethodFailureDiagnostic `asn1:"tag:0,context,implicit,optional" json:"PositionMethodFailureDiagnostic,omitempty"`
	ExtensionContainer              *ExtensionContainer              `asn1:"tag:1,context,implicit,optional" json:"ExtensionContainer,omitempty"`
	ExtCount_                       int64                            `asn1:"-" json:"-"`
	ExtPresent_                     []bool                           `asn1:"-" json:"-"`
	ExtData_                        [][]byte                         `asn1:"-" json:"-"`
	berOriginal_                    []byte                           `asn1:"-" json:"-"`
	berSnapshot_                    []byte                           `asn1:"-" json:"-"`
}

// PositionMethodFailureDiagnostic represents the ASN.1 ENUMERATED type PositionMethodFailure-Diagnostic.
type PositionMethodFailureDiagnostic int64

const (
	PositionMethodFailureDiagnosticCongestion                               PositionMethodFailureDiagnostic = 0
	PositionMethodFailureDiagnosticInsufficientResources                    PositionMethodFailureDiagnostic = 1
	PositionMethodFailureDiagnosticInsufficientMeasurementData              PositionMethodFailureDiagnostic = 2
	PositionMethodFailureDiagnosticInconsistentMeasurementData              PositionMethodFailureDiagnostic = 3
	PositionMethodFailureDiagnosticLocationProcedureNotCompleted            PositionMethodFailureDiagnostic = 4
	PositionMethodFailureDiagnosticLocationProcedureNotSupportedByTargetMS  PositionMethodFailureDiagnostic = 5
	PositionMethodFailureDiagnosticQoSNotAttainable                         PositionMethodFailureDiagnostic = 6
	PositionMethodFailureDiagnosticPositionMethodNotAvailableInNetwork      PositionMethodFailureDiagnostic = 7
	PositionMethodFailureDiagnosticPositionMethodNotAvailableInLocationArea PositionMethodFailureDiagnostic = 8
)

func (v PositionMethodFailureDiagnostic) String() string {
	switch v {
	case PositionMethodFailureDiagnosticCongestion:
		return "congestion"
	case PositionMethodFailureDiagnosticInsufficientResources:
		return "insufficientResources"
	case PositionMethodFailureDiagnosticInsufficientMeasurementData:
		return "insufficientMeasurementData"
	case PositionMethodFailureDiagnosticInconsistentMeasurementData:
		return "inconsistentMeasurementData"
	case PositionMethodFailureDiagnosticLocationProcedureNotCompleted:
		return "locationProcedureNotCompleted"
	case PositionMethodFailureDiagnosticLocationProcedureNotSupportedByTargetMS:
		return "locationProcedureNotSupportedByTargetMS"
	case PositionMethodFailureDiagnosticQoSNotAttainable:
		return "qoSNotAttainable"
	case PositionMethodFailureDiagnosticPositionMethodNotAvailableInNetwork:
		return "positionMethodNotAvailableInNetwork"
	case PositionMethodFailureDiagnosticPositionMethodNotAvailableInLocationArea:
		return "positionMethodNotAvailableInLocationArea"
	default:
		return "unknown"
	}
}

// UnknownOrUnreachableLCSClientParam represents the ASN.1 type UnknownOrUnreachableLCSClient-Param (SEQUENCE).
type UnknownOrUnreachableLCSClientParam struct {
	ExtensionContainer *ExtensionContainer `asn1:",optional" json:"ExtensionContainer,omitempty"`
	ExtCount_          int64               `asn1:"-" json:"-"`
	ExtPresent_        []bool              `asn1:"-" json:"-"`
	ExtData_           [][]byte            `asn1:"-" json:"-"`
	berOriginal_       []byte              `asn1:"-" json:"-"`
	berSnapshot_       []byte              `asn1:"-" json:"-"`
}

// MMEventNotSupportedParam represents the ASN.1 type MM-EventNotSupported-Param (SEQUENCE).
type MMEventNotSupportedParam struct {
	ExtensionContainer *ExtensionContainer `asn1:",optional" json:"ExtensionContainer,omitempty"`
	ExtCount_          int64               `asn1:"-" json:"-"`
	ExtPresent_        []bool              `asn1:"-" json:"-"`
	ExtData_           [][]byte            `asn1:"-" json:"-"`
	berOriginal_       []byte              `asn1:"-" json:"-"`
	berSnapshot_       []byte              `asn1:"-" json:"-"`
}

// TargetCellOutsideGCAParam represents the ASN.1 type TargetCellOutsideGCA-Param (SEQUENCE).
type TargetCellOutsideGCAParam struct {
	ExtensionContainer *ExtensionContainer `asn1:",optional" json:"ExtensionContainer,omitempty"`
	ExtCount_          int64               `asn1:"-" json:"-"`
	ExtPresent_        []bool              `asn1:"-" json:"-"`
	ExtData_           [][]byte            `asn1:"-" json:"-"`
	berOriginal_       []byte              `asn1:"-" json:"-"`
	berSnapshot_       []byte              `asn1:"-" json:"-"`
}

// OngoingGroupCallParam represents the ASN.1 type OngoingGroupCallParam (SEQUENCE).
type OngoingGroupCallParam struct {
	ExtensionContainer *ExtensionContainer `asn1:",optional" json:"ExtensionContainer,omitempty"`
	ExtCount_          int64               `asn1:"-" json:"-"`
	ExtPresent_        []bool              `asn1:"-" json:"-"`
	ExtData_           [][]byte            `asn1:"-" json:"-"`
	berOriginal_       []byte              `asn1:"-" json:"-"`
	berSnapshot_       []byte              `asn1:"-" json:"-"`
}

// MarshalBER encodes RoamingNotAllowedParam to BER format.
func (v *RoamingNotAllowedParam) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: RoamingNotAllowedParam receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *RoamingNotAllowedParam) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if int64(v.RoamingNotAllowedCause) != 0 && int64(v.RoamingNotAllowedCause) != 3 {
		if constraintErr := ber.CheckEncodedValue(opts, "roamingNotAllowedCause", "ENUMERATED {0, 3}", fmt.Sprint(int64(v.RoamingNotAllowedCause))); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_roamingnotallowedcause := ber.EncodeEnumerated(int64(v.RoamingNotAllowedCause))
	children = append(children, enc_roamingnotallowedcause...)
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalBER(ber.ChildEncodeOptions(opts, "extensionContainer")...)
		if err != nil {
			return nil, fmt.Errorf("encoding extensionContainer: %w", err)
		}
		children = append(children, enc_extensioncontainer...)
	}
	if v.AdditionalRoamingNotAllowedCause != nil {
		enc_additionalroamingnotallowedcause := ber.EncodeEnumerated(int64(*v.AdditionalRoamingNotAllowedCause))
		retagged_enc_additionalroamingnotallowedcause, tagErr_enc_additionalroamingnotallowedcause := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_additionalroamingnotallowedcause)
		if tagErr_enc_additionalroamingnotallowedcause != nil {
			return nil, fmt.Errorf("encoding additionalRoamingNotAllowedCause: %w", tagErr_enc_additionalroamingnotallowedcause)
		}
		enc_additionalroamingnotallowedcause = retagged_enc_additionalroamingnotallowedcause
		children = append(children, enc_additionalroamingnotallowedcause...)
	}
	for i, ext := range v.ExtData_ {
		_, n, _, extErr := ber.DecodeEncodedTLV(ext)
		if extErr != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, extErr)
		}
		if n != len(ext) {
			return nil, fmt.Errorf("encoding extension %d: %w", i, ber.ErrExtraData)
		}
		children = append(children, ext...)
	}
	return ber.EncodeSequence(children)
}

// MarshalDER encodes RoamingNotAllowedParam to DER format.
func (v *RoamingNotAllowedParam) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: RoamingNotAllowedParam receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if int64(v.RoamingNotAllowedCause) != 0 && int64(v.RoamingNotAllowedCause) != 3 {
		if constraintErr := ber.CheckEncodedValue(nil, "roamingNotAllowedCause", "ENUMERATED {0, 3}", fmt.Sprint(int64(v.RoamingNotAllowedCause))); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_roamingnotallowedcause := ber.EncodeEnumerated(int64(v.RoamingNotAllowedCause))
	children = append(children, enc_roamingnotallowedcause...)
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding extensionContainer: %w", err)
		}
		children = append(children, enc_extensioncontainer...)
	}
	if v.AdditionalRoamingNotAllowedCause != nil {
		enc_additionalroamingnotallowedcause := ber.EncodeEnumerated(int64(*v.AdditionalRoamingNotAllowedCause))
		retagged_enc_additionalroamingnotallowedcause, tagErr_enc_additionalroamingnotallowedcause := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_additionalroamingnotallowedcause)
		if tagErr_enc_additionalroamingnotallowedcause != nil {
			return nil, fmt.Errorf("encoding additionalRoamingNotAllowedCause: %w", tagErr_enc_additionalroamingnotallowedcause)
		}
		enc_additionalroamingnotallowedcause = retagged_enc_additionalroamingnotallowedcause
		children = append(children, enc_additionalroamingnotallowedcause...)
	}
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDEREncodedElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
		children = append(children, ext...)
	}
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding RoamingNotAllowedParam as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes RoamingNotAllowedParam from BER/DER format.
func (v *RoamingNotAllowedParam) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: RoamingNotAllowedParam destination is nil", ber.ErrInvalidValue)
	}
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = RoamingNotAllowedParam{}
	defer func() {
		if returnErr != nil || !ber.BERNeedsPreservation(opts) {
			return
		}
		var snapshotReports ber.ViolationLog
		snapshot, snapshotErr := v.marshalBER(ber.WithConstraintTolerance(&snapshotReports))
		if snapshotErr != nil {
			returnErr = snapshotErr
			return
		}
		v.berOriginal_ = append([]byte(nil), data...)
		v.berSnapshot_ = snapshot
	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("decoding RoamingNotAllowedParam SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "RoamingNotAllowedParam", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode roamingNotAllowedCause
	if offset >= len(content) {
		return fmt.Errorf("missing required field roamingNotAllowedCause")
	}
	val_roamingnotallowedcause, n, err := ber.DecodeEnumerated(content[offset:], opts...)
	if err != nil {
		return fmt.Errorf("decoding roamingNotAllowedCause: %w", err)
	}
	v.RoamingNotAllowedCause = RoamingNotAllowedCause(val_roamingnotallowedcause)
	if offset > len(content) || n < 0 || n > len(content[offset:]) {
		return fmt.Errorf("invalid BER content window")
	}

	offset += n
	if int64(v.RoamingNotAllowedCause) != 0 && int64(v.RoamingNotAllowedCause) != 3 {
		if constraintErr := ber.CheckDecodedValue(opts, "roamingNotAllowedCause", "ENUMERATED {0, 3}", fmt.Sprint(int64(v.RoamingNotAllowedCause))); constraintErr != nil {
			return constraintErr
		}
	}
	// Decode extensionContainer
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassUniversal && peekTag.Number == 16 {
				// Decode nested SEQUENCE (ExtensionContainer)
				_, n_extensioncontainer, _, tlvErr_extensioncontainer := ber.DecodeTLV(content[offset:], opts...)
				if tlvErr_extensioncontainer != nil {
					return fmt.Errorf("decoding extensionContainer: %w", tlvErr_extensioncontainer)
				}
				var dec_extensioncontainer ExtensionContainer
				if offset < 0 || offset >
					len(content) || n_extensioncontainer < 0 || n_extensioncontainer >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				if unmErr := dec_extensioncontainer.UnmarshalBER(content[offset:offset+n_extensioncontainer], ber.ChildDecodeOptions(opts, "extensionContainer")...); unmErr != nil {
					return fmt.Errorf("decoding extensionContainer: %w", unmErr)
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
	// Decode additionalRoamingNotAllowedCause
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
				decodedTag_additionalroamingnotallowedcause, n_additionalroamingnotallowedcause, rawVal_additionalroamingnotallowedcause, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding additionalRoamingNotAllowedCause: %w", err)
				}
				if decodedTag_additionalroamingnotallowedcause.Class != tag.ClassContextSpecific || decodedTag_additionalroamingnotallowedcause.Number != 0 || decodedTag_additionalroamingnotallowedcause.Constructed != false {
					return fmt.Errorf("decoding additionalRoamingNotAllowedCause: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_additionalroamingnotallowedcause)
				}
				decVal_additionalroamingnotallowedcause, intErr := ber.DecodeEnumeratedValue(rawVal_additionalroamingnotallowedcause)
				if intErr != nil {
					return fmt.Errorf("decoding additionalRoamingNotAllowedCause: %w", intErr)
				}
				tmp_additionalroamingnotallowedcause := AdditionalRoamingNotAllowedCause(decVal_additionalroamingnotallowedcause)
				v.AdditionalRoamingNotAllowedCause = &tmp_additionalroamingnotallowedcause
				if offset < 0 || offset >
					len(content) || n_additionalroamingnotallowedcause < 0 || n_additionalroamingnotallowedcause >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_additionalroamingnotallowedcause
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:], opts...)
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "RoamingNotAllowedParam", Cause: extErr_}
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

// MarshalBER encodes CallBarredParam to BER format.
func (v *CallBarredParam) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: CallBarredParam receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *CallBarredParam) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	switch v.Choice {
	case CallBarredParamChoiceCallBarringCause:
		if v.CallBarringCause == nil {
			return nil, fmt.Errorf("%w: choice CallBarredParam: callBarringCause is nil", ber.ErrInvalidValue)
		}
		enc_0 := ber.EncodeEnumerated(int64(*v.CallBarringCause))
		if int64(*v.CallBarringCause) != 0 && int64(*v.CallBarringCause) != 1 {
			if constraintErr := ber.CheckEncodedValue(opts, "callBarringCause", "ENUMERATED {0, 1}", fmt.Sprint(int64(*v.CallBarringCause))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		return enc_0, nil
	case CallBarredParamChoiceExtensibleCallBarredParam:
		if v.ExtensibleCallBarredParam == nil {
			return nil, fmt.Errorf("%w: choice CallBarredParam: extensibleCallBarredParam is nil", ber.ErrInvalidValue)
		}
		enc_1, err := v.ExtensibleCallBarredParam.MarshalBER(ber.ChildEncodeOptions(opts, "extensibleCallBarredParam")...)
		if err != nil {
			return nil, fmt.Errorf("encoding extensibleCallBarredParam: %w", err)
		}
		return enc_1, nil
	default:
		return nil, fmt.Errorf("unknown choice %d for CallBarredParam", v.Choice)
	}
}

// MarshalDER encodes CallBarredParam to DER format.
func (v *CallBarredParam) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: CallBarredParam receiver is nil", ber.ErrInvalidValue)
	}
	switch v.Choice {
	case CallBarredParamChoiceExtensibleCallBarredParam:
		if v.ExtensibleCallBarredParam == nil {
			return nil, fmt.Errorf("%w: choice CallBarredParam: extensibleCallBarredParam is nil", ber.ErrInvalidValue)
		}
		enc_der_1, err := v.ExtensibleCallBarredParam.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding extensibleCallBarredParam: %w", err)
		}
		if derErr := ber.ValidateDEREncodedElement(enc_der_1); derErr != nil {
			return nil, fmt.Errorf("encoding extensibleCallBarredParam as DER: %w", derErr)
		}
		return enc_der_1, nil
	}
	encoded, err := v.marshalBER()
	if err != nil {
		return nil, err
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding CallBarredParam as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes CallBarredParam from BER/DER format.
func (v *CallBarredParam) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: CallBarredParam destination is nil", ber.ErrInvalidValue)
	}
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	defer func() {
		if returnErr != nil || !ber.BERNeedsPreservation(opts) {
			return
		}
		var snapshotReports ber.ViolationLog
		snapshot, snapshotErr := v.marshalBER(ber.WithConstraintTolerance(&snapshotReports))
		if snapshotErr != nil {
			returnErr = snapshotErr
			return
		}
		v.berOriginal_ = append([]byte(nil), data...)
		v.berSnapshot_ = snapshot
	}()
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = CallBarredParam{}
	if len(data) == 0 {
		return fmt.Errorf("empty data for CallBarredParam CHOICE")
	}
	choiceData := data
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for CallBarredParam: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData, opts...)
	if tlvErr != nil {
		return fmt.Errorf("decoding CallBarredParam CHOICE: %w", tlvErr)
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "CallBarredParam", Cause: ber.ErrExtraData}
	}

	if peekTag.Class == tag.ClassUniversal && peekTag.Number == 10 && peekTag.Constructed == false {
		v.Choice = CallBarredParamChoiceCallBarringCause
		decVal, _, intErr := ber.DecodeEnumerated(choiceData, opts...)
		if intErr != nil {
			return fmt.Errorf("decoding callBarringCause: %w", intErr)
		}
		tmp := CallBarringCause(decVal)
		v.CallBarringCause = &tmp
		if int64(*v.CallBarringCause) != 0 && int64(*v.CallBarringCause) != 1 {
			if constraintErr := ber.CheckDecodedValue(opts, "callBarringCause", "ENUMERATED {0, 1}", fmt.Sprint(int64(*v.CallBarringCause))); constraintErr != nil {
				return constraintErr
			}
		}
	} else if peekTag.Class == tag.ClassUniversal && peekTag.Number == 16 && peekTag.Constructed == true {
		v.Choice = CallBarredParamChoiceExtensibleCallBarredParam
		var dec ExtensibleCallBarredParam
		if unmErr := dec.UnmarshalBER(choiceData, ber.ChildDecodeOptions(opts, "extensibleCallBarredParam")...); unmErr != nil {
			return fmt.Errorf("decoding extensibleCallBarredParam: %w", unmErr)
		}
		v.ExtensibleCallBarredParam = &dec
	} else {
		return fmt.Errorf("unknown tag %s for CallBarredParam CHOICE", peekTag)
	}
	return nil
}

// MarshalBER encodes ExtensibleCallBarredParam to BER format.
func (v *ExtensibleCallBarredParam) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: ExtensibleCallBarredParam receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *ExtensibleCallBarredParam) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if v.CallBarringCause != nil {
		if int64(*v.CallBarringCause) != 0 && int64(*v.CallBarringCause) != 1 {
			if constraintErr := ber.CheckEncodedValue(opts, "callBarringCause", "ENUMERATED {0, 1}", fmt.Sprint(int64(*v.CallBarringCause))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_callbarringcause := ber.EncodeEnumerated(int64(*v.CallBarringCause))
		children = append(children, enc_callbarringcause...)
	}
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalBER(ber.ChildEncodeOptions(opts, "extensionContainer")...)
		if err != nil {
			return nil, fmt.Errorf("encoding extensionContainer: %w", err)
		}
		children = append(children, enc_extensioncontainer...)
	}
	if v.UnauthorisedMessageOriginator != nil {
		enc_unauthorisedmessageoriginator := ber.EncodeNull()
		retagged_enc_unauthorisedmessageoriginator, tagErr_enc_unauthorisedmessageoriginator := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_unauthorisedmessageoriginator)
		if tagErr_enc_unauthorisedmessageoriginator != nil {
			return nil, fmt.Errorf("encoding unauthorisedMessageOriginator: %w", tagErr_enc_unauthorisedmessageoriginator)
		}
		enc_unauthorisedmessageoriginator = retagged_enc_unauthorisedmessageoriginator
		children = append(children, enc_unauthorisedmessageoriginator...)
	}
	if v.AnonymousCallRejection != nil {
		enc_anonymouscallrejection := ber.EncodeNull()
		retagged_enc_anonymouscallrejection, tagErr_enc_anonymouscallrejection := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_anonymouscallrejection)
		if tagErr_enc_anonymouscallrejection != nil {
			return nil, fmt.Errorf("encoding anonymousCallRejection: %w", tagErr_enc_anonymouscallrejection)
		}
		enc_anonymouscallrejection = retagged_enc_anonymouscallrejection
		children = append(children, enc_anonymouscallrejection...)
	}
	for i, ext := range v.ExtData_ {
		_, n, _, extErr := ber.DecodeEncodedTLV(ext)
		if extErr != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, extErr)
		}
		if n != len(ext) {
			return nil, fmt.Errorf("encoding extension %d: %w", i, ber.ErrExtraData)
		}
		children = append(children, ext...)
	}
	return ber.EncodeSequence(children)
}

// MarshalDER encodes ExtensibleCallBarredParam to DER format.
func (v *ExtensibleCallBarredParam) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: ExtensibleCallBarredParam receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if v.CallBarringCause != nil {
		if int64(*v.CallBarringCause) != 0 && int64(*v.CallBarringCause) != 1 {
			if constraintErr := ber.CheckEncodedValue(nil, "callBarringCause", "ENUMERATED {0, 1}", fmt.Sprint(int64(*v.CallBarringCause))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_callbarringcause := ber.EncodeEnumerated(int64(*v.CallBarringCause))
		children = append(children, enc_callbarringcause...)
	}
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding extensionContainer: %w", err)
		}
		children = append(children, enc_extensioncontainer...)
	}
	if v.UnauthorisedMessageOriginator != nil {
		enc_unauthorisedmessageoriginator := ber.EncodeNull()
		retagged_enc_unauthorisedmessageoriginator, tagErr_enc_unauthorisedmessageoriginator := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_unauthorisedmessageoriginator)
		if tagErr_enc_unauthorisedmessageoriginator != nil {
			return nil, fmt.Errorf("encoding unauthorisedMessageOriginator: %w", tagErr_enc_unauthorisedmessageoriginator)
		}
		enc_unauthorisedmessageoriginator = retagged_enc_unauthorisedmessageoriginator
		children = append(children, enc_unauthorisedmessageoriginator...)
	}
	if v.AnonymousCallRejection != nil {
		enc_anonymouscallrejection := ber.EncodeNull()
		retagged_enc_anonymouscallrejection, tagErr_enc_anonymouscallrejection := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_anonymouscallrejection)
		if tagErr_enc_anonymouscallrejection != nil {
			return nil, fmt.Errorf("encoding anonymousCallRejection: %w", tagErr_enc_anonymouscallrejection)
		}
		enc_anonymouscallrejection = retagged_enc_anonymouscallrejection
		children = append(children, enc_anonymouscallrejection...)
	}
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDEREncodedElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
		children = append(children, ext...)
	}
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding ExtensibleCallBarredParam as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes ExtensibleCallBarredParam from BER/DER format.
func (v *ExtensibleCallBarredParam) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: ExtensibleCallBarredParam destination is nil", ber.ErrInvalidValue)
	}
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = ExtensibleCallBarredParam{}
	defer func() {
		if returnErr != nil || !ber.BERNeedsPreservation(opts) {
			return
		}
		var snapshotReports ber.ViolationLog
		snapshot, snapshotErr := v.marshalBER(ber.WithConstraintTolerance(&snapshotReports))
		if snapshotErr != nil {
			returnErr = snapshotErr
			return
		}
		v.berOriginal_ = append([]byte(nil), data...)
		v.berSnapshot_ = snapshot
	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("decoding ExtensibleCallBarredParam SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "ExtensibleCallBarredParam", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode callBarringCause
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassUniversal && peekTag.Number == 10 {
				val_callbarringcause, n, err := ber.DecodeEnumerated(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding callBarringCause: %w", err)
				}
				tmp_callbarringcause := CallBarringCause(val_callbarringcause)
				v.CallBarringCause = &tmp_callbarringcause
				if offset > len(content) || n < 0 || n > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n
				if int64(*v.CallBarringCause) != 0 && int64(*v.CallBarringCause) != 1 {
					if constraintErr := ber.CheckDecodedValue(opts, "callBarringCause", "ENUMERATED {0, 1}", fmt.Sprint(int64(*v.CallBarringCause))); constraintErr != nil {
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
				// Decode nested SEQUENCE (ExtensionContainer)
				_, n_extensioncontainer, _, tlvErr_extensioncontainer := ber.DecodeTLV(content[offset:], opts...)
				if tlvErr_extensioncontainer != nil {
					return fmt.Errorf("decoding extensionContainer: %w", tlvErr_extensioncontainer)
				}
				var dec_extensioncontainer ExtensionContainer
				if offset < 0 || offset >
					len(content) || n_extensioncontainer < 0 || n_extensioncontainer >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				if unmErr := dec_extensioncontainer.UnmarshalBER(content[offset:offset+n_extensioncontainer], ber.ChildDecodeOptions(opts, "extensionContainer")...); unmErr != nil {
					return fmt.Errorf("decoding extensionContainer: %w", unmErr)
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
	// Decode unauthorisedMessageOriginator
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
				decodedTag_unauthorisedmessageoriginator, n_unauthorisedmessageoriginator, rawVal_unauthorisedmessageoriginator, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding unauthorisedMessageOriginator: %w", err)
				}
				if decodedTag_unauthorisedmessageoriginator.Class != tag.ClassContextSpecific || decodedTag_unauthorisedmessageoriginator.Number != 1 || decodedTag_unauthorisedmessageoriginator.Constructed != false {
					return fmt.Errorf("decoding unauthorisedMessageOriginator: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_unauthorisedmessageoriginator)
				}
				if len(rawVal_unauthorisedmessageoriginator) != 0 {
					return fmt.Errorf("decoding unauthorisedMessageOriginator: %w: NULL content length %d", ber.ErrInvalidValue, len(rawVal_unauthorisedmessageoriginator))
				}
				v.UnauthorisedMessageOriginator = &struct{}{}
				if offset < 0 || offset >
					len(content) || n_unauthorisedmessageoriginator < 0 || n_unauthorisedmessageoriginator >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_unauthorisedmessageoriginator
			}
		}
	}
	// Decode anonymousCallRejection
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2 {
				decodedTag_anonymouscallrejection, n_anonymouscallrejection, rawVal_anonymouscallrejection, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding anonymousCallRejection: %w", err)
				}
				if decodedTag_anonymouscallrejection.Class != tag.ClassContextSpecific || decodedTag_anonymouscallrejection.Number != 2 || decodedTag_anonymouscallrejection.Constructed != false {
					return fmt.Errorf("decoding anonymousCallRejection: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_anonymouscallrejection)
				}
				if len(rawVal_anonymouscallrejection) != 0 {
					return fmt.Errorf("decoding anonymousCallRejection: %w: NULL content length %d", ber.ErrInvalidValue, len(rawVal_anonymouscallrejection))
				}
				v.AnonymousCallRejection = &struct{}{}
				if offset < 0 || offset >
					len(content) || n_anonymouscallrejection < 0 || n_anonymouscallrejection >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_anonymouscallrejection
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:], opts...)
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "ExtensibleCallBarredParam", Cause: extErr_}
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

// MarshalBER encodes CUGRejectParam to BER format.
func (v *CUGRejectParam) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: CUGRejectParam receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *CUGRejectParam) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if v.CugRejectCause != nil {
		if int64(*v.CugRejectCause) != 0 && int64(*v.CugRejectCause) != 1 && int64(*v.CugRejectCause) != 5 && int64(*v.CugRejectCause) != 7 {
			if constraintErr := ber.CheckEncodedValue(opts, "cug-RejectCause", "ENUMERATED {0, 1, 5, 7}", fmt.Sprint(int64(*v.CugRejectCause))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_cugrejectcause := ber.EncodeEnumerated(int64(*v.CugRejectCause))
		children = append(children, enc_cugrejectcause...)
	}
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalBER(ber.ChildEncodeOptions(opts, "extensionContainer")...)
		if err != nil {
			return nil, fmt.Errorf("encoding extensionContainer: %w", err)
		}
		children = append(children, enc_extensioncontainer...)
	}
	for i, ext := range v.ExtData_ {
		_, n, _, extErr := ber.DecodeEncodedTLV(ext)
		if extErr != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, extErr)
		}
		if n != len(ext) {
			return nil, fmt.Errorf("encoding extension %d: %w", i, ber.ErrExtraData)
		}
		children = append(children, ext...)
	}
	return ber.EncodeSequence(children)
}

// MarshalDER encodes CUGRejectParam to DER format.
func (v *CUGRejectParam) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: CUGRejectParam receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if v.CugRejectCause != nil {
		if int64(*v.CugRejectCause) != 0 && int64(*v.CugRejectCause) != 1 && int64(*v.CugRejectCause) != 5 && int64(*v.CugRejectCause) != 7 {
			if constraintErr := ber.CheckEncodedValue(nil, "cug-RejectCause", "ENUMERATED {0, 1, 5, 7}", fmt.Sprint(int64(*v.CugRejectCause))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_cugrejectcause := ber.EncodeEnumerated(int64(*v.CugRejectCause))
		children = append(children, enc_cugrejectcause...)
	}
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding extensionContainer: %w", err)
		}
		children = append(children, enc_extensioncontainer...)
	}
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDEREncodedElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
		children = append(children, ext...)
	}
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding CUGRejectParam as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes CUGRejectParam from BER/DER format.
func (v *CUGRejectParam) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: CUGRejectParam destination is nil", ber.ErrInvalidValue)
	}
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = CUGRejectParam{}
	defer func() {
		if returnErr != nil || !ber.BERNeedsPreservation(opts) {
			return
		}
		var snapshotReports ber.ViolationLog
		snapshot, snapshotErr := v.marshalBER(ber.WithConstraintTolerance(&snapshotReports))
		if snapshotErr != nil {
			returnErr = snapshotErr
			return
		}
		v.berOriginal_ = append([]byte(nil), data...)
		v.berSnapshot_ = snapshot
	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("decoding CUGRejectParam SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "CUGRejectParam", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode cug-RejectCause
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassUniversal && peekTag.Number == 10 {
				val_cugrejectcause, n, err := ber.DecodeEnumerated(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding cug-RejectCause: %w", err)
				}
				tmp_cugrejectcause := CUGRejectCause(val_cugrejectcause)
				v.CugRejectCause = &tmp_cugrejectcause
				if offset > len(content) || n < 0 || n > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n
				if int64(*v.CugRejectCause) != 0 && int64(*v.CugRejectCause) != 1 && int64(*v.CugRejectCause) != 5 && int64(*v.CugRejectCause) != 7 {
					if constraintErr := ber.CheckDecodedValue(opts, "cug-RejectCause", "ENUMERATED {0, 1, 5, 7}", fmt.Sprint(int64(*v.CugRejectCause))); constraintErr != nil {
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
				// Decode nested SEQUENCE (ExtensionContainer)
				_, n_extensioncontainer, _, tlvErr_extensioncontainer := ber.DecodeTLV(content[offset:], opts...)
				if tlvErr_extensioncontainer != nil {
					return fmt.Errorf("decoding extensionContainer: %w", tlvErr_extensioncontainer)
				}
				var dec_extensioncontainer ExtensionContainer
				if offset < 0 || offset >
					len(content) || n_extensioncontainer < 0 || n_extensioncontainer >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				if unmErr := dec_extensioncontainer.UnmarshalBER(content[offset:offset+n_extensioncontainer], ber.ChildDecodeOptions(opts, "extensionContainer")...); unmErr != nil {
					return fmt.Errorf("decoding extensionContainer: %w", unmErr)
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
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:], opts...)
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "CUGRejectParam", Cause: extErr_}
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

// MarshalBER encodes SSIncompatibilityCause to BER format.
func (v *SSIncompatibilityCause) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: SSIncompatibilityCause receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *SSIncompatibilityCause) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if v.SsCode != nil {
		if len(*v.SsCode) < 1 || len(*v.SsCode) > 1 {
			if constraintErr := ber.CheckEncodedLength(opts, "ss-Code", "SIZE (1)", len(*v.SsCode)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_sscode, encodeErr_enc_sscode := ber.EncodeOctetString([]byte(*v.SsCode))
		if encodeErr_enc_sscode != nil {
			return nil, fmt.Errorf("encoding ss-Code: %w", encodeErr_enc_sscode)
		}
		retagged_enc_sscode, tagErr_enc_sscode := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_sscode)
		if tagErr_enc_sscode != nil {
			return nil, fmt.Errorf("encoding ss-Code: %w", tagErr_enc_sscode)
		}
		enc_sscode = retagged_enc_sscode
		children = append(children, enc_sscode...)
	}
	if v.BasicService != nil {
		enc_basicservice, err := v.BasicService.MarshalBER(ber.ChildEncodeOptions(opts, "basicService")...)
		if err != nil {
			return nil, fmt.Errorf("encoding basicService: %w", err)
		}
		children = append(children, enc_basicservice...)
	}
	if v.SsStatus != nil {
		if len(*v.SsStatus) < 1 || len(*v.SsStatus) > 1 {
			if constraintErr := ber.CheckEncodedLength(opts, "ss-Status", "SIZE (1)", len(*v.SsStatus)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_ssstatus, encodeErr_enc_ssstatus := ber.EncodeOctetString([]byte(*v.SsStatus))
		if encodeErr_enc_ssstatus != nil {
			return nil, fmt.Errorf("encoding ss-Status: %w", encodeErr_enc_ssstatus)
		}
		retagged_enc_ssstatus, tagErr_enc_ssstatus := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, enc_ssstatus)
		if tagErr_enc_ssstatus != nil {
			return nil, fmt.Errorf("encoding ss-Status: %w", tagErr_enc_ssstatus)
		}
		enc_ssstatus = retagged_enc_ssstatus
		children = append(children, enc_ssstatus...)
	}
	for i, ext := range v.ExtData_ {
		_, n, _, extErr := ber.DecodeEncodedTLV(ext)
		if extErr != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, extErr)
		}
		if n != len(ext) {
			return nil, fmt.Errorf("encoding extension %d: %w", i, ber.ErrExtraData)
		}
		children = append(children, ext...)
	}
	return ber.EncodeSequence(children)
}

// MarshalDER encodes SSIncompatibilityCause to DER format.
func (v *SSIncompatibilityCause) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: SSIncompatibilityCause receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if v.SsCode != nil {
		if len(*v.SsCode) < 1 || len(*v.SsCode) > 1 {
			if constraintErr := ber.CheckEncodedLength(nil, "ss-Code", "SIZE (1)", len(*v.SsCode)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_sscode, encodeErr_enc_sscode := ber.EncodeOctetString([]byte(*v.SsCode))
		if encodeErr_enc_sscode != nil {
			return nil, fmt.Errorf("encoding ss-Code: %w", encodeErr_enc_sscode)
		}
		retagged_enc_sscode, tagErr_enc_sscode := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_sscode)
		if tagErr_enc_sscode != nil {
			return nil, fmt.Errorf("encoding ss-Code: %w", tagErr_enc_sscode)
		}
		enc_sscode = retagged_enc_sscode
		children = append(children, enc_sscode...)
	}
	if v.BasicService != nil {
		enc_basicservice, err := v.BasicService.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding basicService: %w", err)
		}
		children = append(children, enc_basicservice...)
	}
	if v.SsStatus != nil {
		if len(*v.SsStatus) < 1 || len(*v.SsStatus) > 1 {
			if constraintErr := ber.CheckEncodedLength(nil, "ss-Status", "SIZE (1)", len(*v.SsStatus)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_ssstatus, encodeErr_enc_ssstatus := ber.EncodeOctetString([]byte(*v.SsStatus))
		if encodeErr_enc_ssstatus != nil {
			return nil, fmt.Errorf("encoding ss-Status: %w", encodeErr_enc_ssstatus)
		}
		retagged_enc_ssstatus, tagErr_enc_ssstatus := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, enc_ssstatus)
		if tagErr_enc_ssstatus != nil {
			return nil, fmt.Errorf("encoding ss-Status: %w", tagErr_enc_ssstatus)
		}
		enc_ssstatus = retagged_enc_ssstatus
		children = append(children, enc_ssstatus...)
	}
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDEREncodedElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
		children = append(children, ext...)
	}
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding SSIncompatibilityCause as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes SSIncompatibilityCause from BER/DER format.
func (v *SSIncompatibilityCause) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: SSIncompatibilityCause destination is nil", ber.ErrInvalidValue)
	}
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = SSIncompatibilityCause{}
	defer func() {
		if returnErr != nil || !ber.BERNeedsPreservation(opts) {
			return
		}
		var snapshotReports ber.ViolationLog
		snapshot, snapshotErr := v.marshalBER(ber.WithConstraintTolerance(&snapshotReports))
		if snapshotErr != nil {
			returnErr = snapshotErr
			return
		}
		v.berOriginal_ = append([]byte(nil), data...)
		v.berSnapshot_ = snapshot
	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("decoding SSIncompatibilityCause SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "SSIncompatibilityCause", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode ss-Code
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
				decodedTag_sscode, n_sscode, rawVal_sscode, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding ss-Code: %w", err)
				}
				if decodedTag_sscode.Class != tag.ClassContextSpecific || decodedTag_sscode.Number != 1 {
					return fmt.Errorf("decoding ss-Code: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_sscode)
				}
				decVal_sscode, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_sscode.Constructed, rawVal_sscode, opts...)
				if octetErr != nil {
					return fmt.Errorf("decoding ss-Code: %w", octetErr)
				}
				tmp_sscode := SSCode(decVal_sscode)
				v.SsCode = &tmp_sscode
				if offset > len(content) || n_sscode < 0 || n_sscode > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_sscode
				if len(*v.SsCode) < 1 || len(*v.SsCode) > 1 {
					if constraintErr := ber.CheckDecodedLength(opts, "ss-Code", "SIZE (1)", len(*v.SsCode)); constraintErr != nil {
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
			if (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3) {
				// Decode nested CHOICE (BasicServiceCode)
				_, n_basicservice, _, tlvErr_basicservice := ber.DecodeTLV(content[offset:], opts...)
				if tlvErr_basicservice != nil {
					return fmt.Errorf("decoding basicService: %w", tlvErr_basicservice)
				}
				var dec_basicservice BasicServiceCode
				if offset < 0 || offset >
					len(content) || n_basicservice < 0 || n_basicservice > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				if unmErr := dec_basicservice.UnmarshalBER(content[offset:offset+n_basicservice], ber.ChildDecodeOptions(opts, "basicService")...); unmErr != nil {
					return fmt.Errorf("decoding basicService: %w", unmErr)
				}
				v.BasicService = &dec_basicservice
				if offset < 0 || offset >
					len(content) || n_basicservice < 0 || n_basicservice > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_basicservice
			}
		}
	}
	// Decode ss-Status
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4 {
				decodedTag_ssstatus, n_ssstatus, rawVal_ssstatus, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding ss-Status: %w", err)
				}
				if decodedTag_ssstatus.Class != tag.ClassContextSpecific || decodedTag_ssstatus.Number != 4 {
					return fmt.Errorf("decoding ss-Status: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_ssstatus)
				}
				decVal_ssstatus, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_ssstatus.Constructed, rawVal_ssstatus, opts...)
				if octetErr != nil {
					return fmt.Errorf("decoding ss-Status: %w", octetErr)
				}
				tmp_ssstatus := SSStatus(decVal_ssstatus)
				v.SsStatus = &tmp_ssstatus
				if offset < 0 || offset >
					len(content) || n_ssstatus < 0 || n_ssstatus > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_ssstatus
				if len(*v.SsStatus) < 1 || len(*v.SsStatus) > 1 {
					if constraintErr := ber.CheckDecodedLength(opts, "ss-Status", "SIZE (1)", len(*v.SsStatus)); constraintErr != nil {
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
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:], opts...)
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "SSIncompatibilityCause", Cause: extErr_}
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

// MarshalBER encodes SMDeliveryFailureCause to BER format.
func (v *SMDeliveryFailureCause) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: SMDeliveryFailureCause receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *SMDeliveryFailureCause) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if int64(v.SmEnumeratedDeliveryFailureCause) != 0 && int64(v.SmEnumeratedDeliveryFailureCause) != 1 && int64(v.SmEnumeratedDeliveryFailureCause) != 2 && int64(v.SmEnumeratedDeliveryFailureCause) != 3 && int64(v.SmEnumeratedDeliveryFailureCause) != 4 && int64(v.SmEnumeratedDeliveryFailureCause) != 5 && int64(v.SmEnumeratedDeliveryFailureCause) != 6 {
		if constraintErr := ber.CheckEncodedValue(opts, "sm-EnumeratedDeliveryFailureCause", "ENUMERATED {0, 1, 2, 3, 4, 5, 6}", fmt.Sprint(int64(v.SmEnumeratedDeliveryFailureCause))); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_smenumerateddeliveryfailurecause := ber.EncodeEnumerated(int64(v.SmEnumeratedDeliveryFailureCause))
	children = append(children, enc_smenumerateddeliveryfailurecause...)
	if v.DiagnosticInfo != nil {
		if len(*v.DiagnosticInfo) < 1 || len(*v.DiagnosticInfo) > 200 {
			if constraintErr := ber.CheckEncodedLength(opts, "diagnosticInfo", "SIZE (1..200)", len(*v.DiagnosticInfo)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_diagnosticinfo, encodeErr_enc_diagnosticinfo := ber.EncodeOctetString([]byte(*v.DiagnosticInfo))
		if encodeErr_enc_diagnosticinfo != nil {
			return nil, fmt.Errorf("encoding diagnosticInfo: %w", encodeErr_enc_diagnosticinfo)
		}
		children = append(children, enc_diagnosticinfo...)
	}
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalBER(ber.ChildEncodeOptions(opts, "extensionContainer")...)
		if err != nil {
			return nil, fmt.Errorf("encoding extensionContainer: %w", err)
		}
		children = append(children, enc_extensioncontainer...)
	}
	for i, ext := range v.ExtData_ {
		_, n, _, extErr := ber.DecodeEncodedTLV(ext)
		if extErr != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, extErr)
		}
		if n != len(ext) {
			return nil, fmt.Errorf("encoding extension %d: %w", i, ber.ErrExtraData)
		}
		children = append(children, ext...)
	}
	return ber.EncodeSequence(children)
}

// MarshalDER encodes SMDeliveryFailureCause to DER format.
func (v *SMDeliveryFailureCause) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: SMDeliveryFailureCause receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if int64(v.SmEnumeratedDeliveryFailureCause) != 0 && int64(v.SmEnumeratedDeliveryFailureCause) != 1 && int64(v.SmEnumeratedDeliveryFailureCause) != 2 && int64(v.SmEnumeratedDeliveryFailureCause) != 3 && int64(v.SmEnumeratedDeliveryFailureCause) != 4 && int64(v.SmEnumeratedDeliveryFailureCause) != 5 && int64(v.SmEnumeratedDeliveryFailureCause) != 6 {
		if constraintErr := ber.CheckEncodedValue(nil, "sm-EnumeratedDeliveryFailureCause", "ENUMERATED {0, 1, 2, 3, 4, 5, 6}", fmt.Sprint(int64(v.SmEnumeratedDeliveryFailureCause))); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_smenumerateddeliveryfailurecause := ber.EncodeEnumerated(int64(v.SmEnumeratedDeliveryFailureCause))
	children = append(children, enc_smenumerateddeliveryfailurecause...)
	if v.DiagnosticInfo != nil {
		if len(*v.DiagnosticInfo) < 1 || len(*v.DiagnosticInfo) > 200 {
			if constraintErr := ber.CheckEncodedLength(nil, "diagnosticInfo", "SIZE (1..200)", len(*v.DiagnosticInfo)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_diagnosticinfo, encodeErr_enc_diagnosticinfo := ber.EncodeOctetString([]byte(*v.DiagnosticInfo))
		if encodeErr_enc_diagnosticinfo != nil {
			return nil, fmt.Errorf("encoding diagnosticInfo: %w", encodeErr_enc_diagnosticinfo)
		}
		children = append(children, enc_diagnosticinfo...)
	}
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding extensionContainer: %w", err)
		}
		children = append(children, enc_extensioncontainer...)
	}
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDEREncodedElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
		children = append(children, ext...)
	}
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding SMDeliveryFailureCause as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes SMDeliveryFailureCause from BER/DER format.
func (v *SMDeliveryFailureCause) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: SMDeliveryFailureCause destination is nil", ber.ErrInvalidValue)
	}
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = SMDeliveryFailureCause{}
	defer func() {
		if returnErr != nil || !ber.BERNeedsPreservation(opts) {
			return
		}
		var snapshotReports ber.ViolationLog
		snapshot, snapshotErr := v.marshalBER(ber.WithConstraintTolerance(&snapshotReports))
		if snapshotErr != nil {
			returnErr = snapshotErr
			return
		}
		v.berOriginal_ = append([]byte(nil), data...)
		v.berSnapshot_ = snapshot
	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("decoding SMDeliveryFailureCause SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "SMDeliveryFailureCause", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode sm-EnumeratedDeliveryFailureCause
	if offset >= len(content) {
		return fmt.Errorf("missing required field sm-EnumeratedDeliveryFailureCause")
	}
	val_smenumerateddeliveryfailurecause, n, err := ber.DecodeEnumerated(content[offset:], opts...)
	if err != nil {
		return fmt.Errorf("decoding sm-EnumeratedDeliveryFailureCause: %w", err)
	}
	v.SmEnumeratedDeliveryFailureCause = SMEnumeratedDeliveryFailureCause(val_smenumerateddeliveryfailurecause)
	if offset > len(content) || n < 0 || n > len(content[offset:]) {
		return fmt.Errorf("invalid BER content window")
	}

	offset += n
	if int64(v.SmEnumeratedDeliveryFailureCause) != 0 && int64(v.SmEnumeratedDeliveryFailureCause) != 1 && int64(v.SmEnumeratedDeliveryFailureCause) != 2 && int64(v.SmEnumeratedDeliveryFailureCause) != 3 && int64(v.SmEnumeratedDeliveryFailureCause) != 4 && int64(v.SmEnumeratedDeliveryFailureCause) != 5 && int64(v.SmEnumeratedDeliveryFailureCause) != 6 {
		if constraintErr := ber.CheckDecodedValue(opts, "sm-EnumeratedDeliveryFailureCause", "ENUMERATED {0, 1, 2, 3, 4, 5, 6}", fmt.Sprint(int64(v.SmEnumeratedDeliveryFailureCause))); constraintErr != nil {
			return constraintErr
		}
	}
	// Decode diagnosticInfo
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassUniversal && peekTag.Number == 4 {
				val_diagnosticinfo, n, err := ber.DecodeOctetString(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding diagnosticInfo: %w", err)
				}
				tmp_diagnosticinfo := SignalInfo(val_diagnosticinfo)
				v.DiagnosticInfo = &tmp_diagnosticinfo
				if offset < 0 || offset >
					len(content) || n < 0 || n > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n
				if len(*v.DiagnosticInfo) < 1 || len(*v.DiagnosticInfo) > 200 {
					if constraintErr := ber.CheckDecodedLength(opts, "diagnosticInfo", "SIZE (1..200)", len(*v.DiagnosticInfo)); constraintErr != nil {
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
				// Decode nested SEQUENCE (ExtensionContainer)
				_, n_extensioncontainer, _, tlvErr_extensioncontainer := ber.DecodeTLV(content[offset:], opts...)
				if tlvErr_extensioncontainer != nil {
					return fmt.Errorf("decoding extensionContainer: %w", tlvErr_extensioncontainer)
				}
				var dec_extensioncontainer ExtensionContainer
				if offset < 0 || offset >
					len(content) || n_extensioncontainer < 0 || n_extensioncontainer >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				if unmErr := dec_extensioncontainer.UnmarshalBER(content[offset:offset+n_extensioncontainer], ber.ChildDecodeOptions(opts, "extensionContainer")...); unmErr != nil {
					return fmt.Errorf("decoding extensionContainer: %w", unmErr)
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
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:], opts...)
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "SMDeliveryFailureCause", Cause: extErr_}
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

// MarshalBER encodes AbsentSubscriberSMParam to BER format.
func (v *AbsentSubscriberSMParam) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: AbsentSubscriberSMParam receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *AbsentSubscriberSMParam) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if v.AbsentSubscriberDiagnosticSM != nil {
		if !(int64(*v.AbsentSubscriberDiagnosticSM) >= 0 && int64(*v.AbsentSubscriberDiagnosticSM) <= 255) {
			if constraintErr := ber.CheckEncodedValue(opts, "absentSubscriberDiagnosticSM", "(0..255)", fmt.Sprint(int64(*v.AbsentSubscriberDiagnosticSM))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_absentsubscriberdiagnosticsm := ber.EncodeInteger(int64(*v.AbsentSubscriberDiagnosticSM))
		children = append(children, enc_absentsubscriberdiagnosticsm...)
	}
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalBER(ber.ChildEncodeOptions(opts, "extensionContainer")...)
		if err != nil {
			return nil, fmt.Errorf("encoding extensionContainer: %w", err)
		}
		children = append(children, enc_extensioncontainer...)
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
			return nil, fmt.Errorf("encoding additionalAbsentSubscriberDiagnosticSM: %w", tagErr_enc_additionalabsentsubscriberdiagnosticsm)
		}
		enc_additionalabsentsubscriberdiagnosticsm = retagged_enc_additionalabsentsubscriberdiagnosticsm
		children = append(children, enc_additionalabsentsubscriberdiagnosticsm...)
	}
	if v.Imsi != nil {
		if len(*v.Imsi) < 3 || len(*v.Imsi) > 8 {
			if constraintErr := ber.CheckEncodedLength(opts, "imsi", "SIZE (3..8)", len(*v.Imsi)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_imsi, encodeErr_enc_imsi := ber.EncodeOctetString([]byte(*v.Imsi))
		if encodeErr_enc_imsi != nil {
			return nil, fmt.Errorf("encoding imsi: %w", encodeErr_enc_imsi)
		}
		retagged_enc_imsi, tagErr_enc_imsi := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_imsi)
		if tagErr_enc_imsi != nil {
			return nil, fmt.Errorf("encoding imsi: %w", tagErr_enc_imsi)
		}
		enc_imsi = retagged_enc_imsi
		children = append(children, enc_imsi...)
	}
	if v.RequestedRetransmissionTime != nil {
		if len(*v.RequestedRetransmissionTime) < 4 || len(*v.RequestedRetransmissionTime) > 4 {
			if constraintErr := ber.CheckEncodedLength(opts, "requestedRetransmissionTime", "SIZE (4)", len(*v.RequestedRetransmissionTime)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_requestedretransmissiontime, encodeErr_enc_requestedretransmissiontime := ber.EncodeOctetString([]byte(*v.RequestedRetransmissionTime))
		if encodeErr_enc_requestedretransmissiontime != nil {
			return nil, fmt.Errorf("encoding requestedRetransmissionTime: %w", encodeErr_enc_requestedretransmissiontime)
		}
		retagged_enc_requestedretransmissiontime, tagErr_enc_requestedretransmissiontime := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_requestedretransmissiontime)
		if tagErr_enc_requestedretransmissiontime != nil {
			return nil, fmt.Errorf("encoding requestedRetransmissionTime: %w", tagErr_enc_requestedretransmissiontime)
		}
		enc_requestedretransmissiontime = retagged_enc_requestedretransmissiontime
		children = append(children, enc_requestedretransmissiontime...)
	}
	if v.UserIdentifierAlert != nil {
		if len(*v.UserIdentifierAlert) < 3 || len(*v.UserIdentifierAlert) > 8 {
			if constraintErr := ber.CheckEncodedLength(opts, "userIdentifierAlert", "SIZE (3..8)", len(*v.UserIdentifierAlert)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_useridentifieralert, encodeErr_enc_useridentifieralert := ber.EncodeOctetString([]byte(*v.UserIdentifierAlert))
		if encodeErr_enc_useridentifieralert != nil {
			return nil, fmt.Errorf("encoding userIdentifierAlert: %w", encodeErr_enc_useridentifieralert)
		}
		retagged_enc_useridentifieralert, tagErr_enc_useridentifieralert := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, enc_useridentifieralert)
		if tagErr_enc_useridentifieralert != nil {
			return nil, fmt.Errorf("encoding userIdentifierAlert: %w", tagErr_enc_useridentifieralert)
		}
		enc_useridentifieralert = retagged_enc_useridentifieralert
		children = append(children, enc_useridentifieralert...)
	}
	for i, ext := range v.ExtData_ {
		_, n, _, extErr := ber.DecodeEncodedTLV(ext)
		if extErr != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, extErr)
		}
		if n != len(ext) {
			return nil, fmt.Errorf("encoding extension %d: %w", i, ber.ErrExtraData)
		}
		children = append(children, ext...)
	}
	return ber.EncodeSequence(children)
}

// MarshalDER encodes AbsentSubscriberSMParam to DER format.
func (v *AbsentSubscriberSMParam) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: AbsentSubscriberSMParam receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if v.AbsentSubscriberDiagnosticSM != nil {
		if !(int64(*v.AbsentSubscriberDiagnosticSM) >= 0 && int64(*v.AbsentSubscriberDiagnosticSM) <= 255) {
			if constraintErr := ber.CheckEncodedValue(nil, "absentSubscriberDiagnosticSM", "(0..255)", fmt.Sprint(int64(*v.AbsentSubscriberDiagnosticSM))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_absentsubscriberdiagnosticsm := ber.EncodeInteger(int64(*v.AbsentSubscriberDiagnosticSM))
		children = append(children, enc_absentsubscriberdiagnosticsm...)
	}
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding extensionContainer: %w", err)
		}
		children = append(children, enc_extensioncontainer...)
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
			return nil, fmt.Errorf("encoding additionalAbsentSubscriberDiagnosticSM: %w", tagErr_enc_additionalabsentsubscriberdiagnosticsm)
		}
		enc_additionalabsentsubscriberdiagnosticsm = retagged_enc_additionalabsentsubscriberdiagnosticsm
		children = append(children, enc_additionalabsentsubscriberdiagnosticsm...)
	}
	if v.Imsi != nil {
		if len(*v.Imsi) < 3 || len(*v.Imsi) > 8 {
			if constraintErr := ber.CheckEncodedLength(nil, "imsi", "SIZE (3..8)", len(*v.Imsi)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_imsi, encodeErr_enc_imsi := ber.EncodeOctetString([]byte(*v.Imsi))
		if encodeErr_enc_imsi != nil {
			return nil, fmt.Errorf("encoding imsi: %w", encodeErr_enc_imsi)
		}
		retagged_enc_imsi, tagErr_enc_imsi := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_imsi)
		if tagErr_enc_imsi != nil {
			return nil, fmt.Errorf("encoding imsi: %w", tagErr_enc_imsi)
		}
		enc_imsi = retagged_enc_imsi
		children = append(children, enc_imsi...)
	}
	if v.RequestedRetransmissionTime != nil {
		if len(*v.RequestedRetransmissionTime) < 4 || len(*v.RequestedRetransmissionTime) > 4 {
			if constraintErr := ber.CheckEncodedLength(nil, "requestedRetransmissionTime", "SIZE (4)", len(*v.RequestedRetransmissionTime)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_requestedretransmissiontime, encodeErr_enc_requestedretransmissiontime := ber.EncodeOctetString([]byte(*v.RequestedRetransmissionTime))
		if encodeErr_enc_requestedretransmissiontime != nil {
			return nil, fmt.Errorf("encoding requestedRetransmissionTime: %w", encodeErr_enc_requestedretransmissiontime)
		}
		retagged_enc_requestedretransmissiontime, tagErr_enc_requestedretransmissiontime := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_requestedretransmissiontime)
		if tagErr_enc_requestedretransmissiontime != nil {
			return nil, fmt.Errorf("encoding requestedRetransmissionTime: %w", tagErr_enc_requestedretransmissiontime)
		}
		enc_requestedretransmissiontime = retagged_enc_requestedretransmissiontime
		children = append(children, enc_requestedretransmissiontime...)
	}
	if v.UserIdentifierAlert != nil {
		if len(*v.UserIdentifierAlert) < 3 || len(*v.UserIdentifierAlert) > 8 {
			if constraintErr := ber.CheckEncodedLength(nil, "userIdentifierAlert", "SIZE (3..8)", len(*v.UserIdentifierAlert)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_useridentifieralert, encodeErr_enc_useridentifieralert := ber.EncodeOctetString([]byte(*v.UserIdentifierAlert))
		if encodeErr_enc_useridentifieralert != nil {
			return nil, fmt.Errorf("encoding userIdentifierAlert: %w", encodeErr_enc_useridentifieralert)
		}
		retagged_enc_useridentifieralert, tagErr_enc_useridentifieralert := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, enc_useridentifieralert)
		if tagErr_enc_useridentifieralert != nil {
			return nil, fmt.Errorf("encoding userIdentifierAlert: %w", tagErr_enc_useridentifieralert)
		}
		enc_useridentifieralert = retagged_enc_useridentifieralert
		children = append(children, enc_useridentifieralert...)
	}
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDEREncodedElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
		children = append(children, ext...)
	}
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding AbsentSubscriberSMParam as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes AbsentSubscriberSMParam from BER/DER format.
func (v *AbsentSubscriberSMParam) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: AbsentSubscriberSMParam destination is nil", ber.ErrInvalidValue)
	}
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = AbsentSubscriberSMParam{}
	defer func() {
		if returnErr != nil || !ber.BERNeedsPreservation(opts) {
			return
		}
		var snapshotReports ber.ViolationLog
		snapshot, snapshotErr := v.marshalBER(ber.WithConstraintTolerance(&snapshotReports))
		if snapshotErr != nil {
			returnErr = snapshotErr
			return
		}
		v.berOriginal_ = append([]byte(nil), data...)
		v.berSnapshot_ = snapshot
	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("decoding AbsentSubscriberSMParam SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "AbsentSubscriberSMParam", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode absentSubscriberDiagnosticSM
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassUniversal && peekTag.Number == 2 {
				val_absentsubscriberdiagnosticsm, n, err := ber.DecodeInteger(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding absentSubscriberDiagnosticSM: %w", err)
				}
				tmp_absentsubscriberdiagnosticsm := AbsentSubscriberDiagnosticSM(val_absentsubscriberdiagnosticsm)
				v.AbsentSubscriberDiagnosticSM = &tmp_absentsubscriberdiagnosticsm
				if offset > len(content) || n < 0 || n > len(content[offset:]) {
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
	// Decode extensionContainer
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassUniversal && peekTag.Number == 16 {
				// Decode nested SEQUENCE (ExtensionContainer)
				_, n_extensioncontainer, _, tlvErr_extensioncontainer := ber.DecodeTLV(content[offset:], opts...)
				if tlvErr_extensioncontainer != nil {
					return fmt.Errorf("decoding extensionContainer: %w", tlvErr_extensioncontainer)
				}
				var dec_extensioncontainer ExtensionContainer
				if offset < 0 || offset >
					len(content) || n_extensioncontainer < 0 || n_extensioncontainer >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				if unmErr := dec_extensioncontainer.UnmarshalBER(content[offset:offset+n_extensioncontainer], ber.ChildDecodeOptions(opts, "extensionContainer")...); unmErr != nil {
					return fmt.Errorf("decoding extensionContainer: %w", unmErr)
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
	// Decode additionalAbsentSubscriberDiagnosticSM
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
				decodedTag_additionalabsentsubscriberdiagnosticsm, n_additionalabsentsubscriberdiagnosticsm, rawVal_additionalabsentsubscriberdiagnosticsm, err := ber.DecodeTLV(content[offset:], opts...)
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
				if offset < 0 || offset >
					len(content) || n_additionalabsentsubscriberdiagnosticsm < 0 ||
					n_additionalabsentsubscriberdiagnosticsm > len(content[offset:]) {
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
	// Decode imsi
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
				decodedTag_imsi, n_imsi, rawVal_imsi, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding imsi: %w", err)
				}
				if decodedTag_imsi.Class != tag.ClassContextSpecific || decodedTag_imsi.Number != 1 {
					return fmt.Errorf("decoding imsi: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_imsi)
				}
				decVal_imsi, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_imsi.Constructed, rawVal_imsi, opts...)
				if octetErr != nil {
					return fmt.Errorf("decoding imsi: %w", octetErr)
				}
				tmp_imsi := IMSI(decVal_imsi)
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
	// Decode requestedRetransmissionTime
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2 {
				decodedTag_requestedretransmissiontime, n_requestedretransmissiontime, rawVal_requestedretransmissiontime, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding requestedRetransmissionTime: %w", err)
				}
				if decodedTag_requestedretransmissiontime.Class != tag.ClassContextSpecific || decodedTag_requestedretransmissiontime.Number != 2 {
					return fmt.Errorf("decoding requestedRetransmissionTime: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_requestedretransmissiontime)
				}
				decVal_requestedretransmissiontime, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_requestedretransmissiontime.Constructed, rawVal_requestedretransmissiontime, opts...)
				if octetErr != nil {
					return fmt.Errorf("decoding requestedRetransmissionTime: %w", octetErr)
				}
				tmp_requestedretransmissiontime := Time(decVal_requestedretransmissiontime)
				v.RequestedRetransmissionTime = &tmp_requestedretransmissiontime
				if offset < 0 || offset >
					len(content) || n_requestedretransmissiontime < 0 || n_requestedretransmissiontime >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_requestedretransmissiontime
				if len(*v.RequestedRetransmissionTime) < 4 || len(*v.RequestedRetransmissionTime) > 4 {
					if constraintErr := ber.CheckDecodedLength(opts, "requestedRetransmissionTime", "SIZE (4)", len(*v.RequestedRetransmissionTime)); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode userIdentifierAlert
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3 {
				decodedTag_useridentifieralert, n_useridentifieralert, rawVal_useridentifieralert, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding userIdentifierAlert: %w", err)
				}
				if decodedTag_useridentifieralert.Class != tag.ClassContextSpecific || decodedTag_useridentifieralert.Number != 3 {
					return fmt.Errorf("decoding userIdentifierAlert: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_useridentifieralert)
				}
				decVal_useridentifieralert, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_useridentifieralert.Constructed, rawVal_useridentifieralert, opts...)
				if octetErr != nil {
					return fmt.Errorf("decoding userIdentifierAlert: %w", octetErr)
				}
				tmp_useridentifieralert := IMSI(decVal_useridentifieralert)
				v.UserIdentifierAlert = &tmp_useridentifieralert
				if offset < 0 || offset >
					len(content) || n_useridentifieralert < 0 || n_useridentifieralert >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_useridentifieralert
				if len(*v.UserIdentifierAlert) < 3 || len(*v.UserIdentifierAlert) > 8 {
					if constraintErr := ber.CheckDecodedLength(opts, "userIdentifierAlert", "SIZE (3..8)", len(*v.UserIdentifierAlert)); constraintErr != nil {
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
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:], opts...)
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "AbsentSubscriberSMParam", Cause: extErr_}
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

// MarshalBER encodes SystemFailureParam to BER format.
func (v *SystemFailureParam) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: SystemFailureParam receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *SystemFailureParam) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	switch v.Choice {
	case SystemFailureParamChoiceNetworkResource:
		if v.NetworkResource == nil {
			return nil, fmt.Errorf("%w: choice SystemFailureParam: networkResource is nil", ber.ErrInvalidValue)
		}
		enc_0 := ber.EncodeEnumerated(int64(*v.NetworkResource))
		if int64(*v.NetworkResource) != 0 && int64(*v.NetworkResource) != 1 && int64(*v.NetworkResource) != 2 && int64(*v.NetworkResource) != 3 && int64(*v.NetworkResource) != 4 && int64(*v.NetworkResource) != 5 && int64(*v.NetworkResource) != 6 && int64(*v.NetworkResource) != 7 {
			if constraintErr := ber.CheckEncodedValue(opts, "networkResource", "ENUMERATED {0, 1, 2, 3, 4, 5, 6, 7}", fmt.Sprint(int64(*v.NetworkResource))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		return enc_0, nil
	case SystemFailureParamChoiceExtensibleSystemFailureParam:
		if v.ExtensibleSystemFailureParam == nil {
			return nil, fmt.Errorf("%w: choice SystemFailureParam: extensibleSystemFailureParam is nil", ber.ErrInvalidValue)
		}
		enc_1, err := v.ExtensibleSystemFailureParam.MarshalBER(ber.ChildEncodeOptions(opts, "extensibleSystemFailureParam")...)
		if err != nil {
			return nil, fmt.Errorf("encoding extensibleSystemFailureParam: %w", err)
		}
		return enc_1, nil
	default:
		return nil, fmt.Errorf("unknown choice %d for SystemFailureParam", v.Choice)
	}
}

// MarshalDER encodes SystemFailureParam to DER format.
func (v *SystemFailureParam) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: SystemFailureParam receiver is nil", ber.ErrInvalidValue)
	}
	switch v.Choice {
	case SystemFailureParamChoiceExtensibleSystemFailureParam:
		if v.ExtensibleSystemFailureParam == nil {
			return nil, fmt.Errorf("%w: choice SystemFailureParam: extensibleSystemFailureParam is nil", ber.ErrInvalidValue)
		}
		enc_der_1, err := v.ExtensibleSystemFailureParam.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding extensibleSystemFailureParam: %w", err)
		}
		if derErr := ber.ValidateDEREncodedElement(enc_der_1); derErr != nil {
			return nil, fmt.Errorf("encoding extensibleSystemFailureParam as DER: %w", derErr)
		}
		return enc_der_1, nil
	}
	encoded, err := v.marshalBER()
	if err != nil {
		return nil, err
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding SystemFailureParam as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes SystemFailureParam from BER/DER format.
func (v *SystemFailureParam) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: SystemFailureParam destination is nil", ber.ErrInvalidValue)
	}
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	defer func() {
		if returnErr != nil || !ber.BERNeedsPreservation(opts) {
			return
		}
		var snapshotReports ber.ViolationLog
		snapshot, snapshotErr := v.marshalBER(ber.WithConstraintTolerance(&snapshotReports))
		if snapshotErr != nil {
			returnErr = snapshotErr
			return
		}
		v.berOriginal_ = append([]byte(nil), data...)
		v.berSnapshot_ = snapshot
	}()
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = SystemFailureParam{}
	if len(data) == 0 {
		return fmt.Errorf("empty data for SystemFailureParam CHOICE")
	}
	choiceData := data
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for SystemFailureParam: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData, opts...)
	if tlvErr != nil {
		return fmt.Errorf("decoding SystemFailureParam CHOICE: %w", tlvErr)
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "SystemFailureParam", Cause: ber.ErrExtraData}
	}

	if peekTag.Class == tag.ClassUniversal && peekTag.Number == 10 && peekTag.Constructed == false {
		v.Choice = SystemFailureParamChoiceNetworkResource
		decVal, _, intErr := ber.DecodeEnumerated(choiceData, opts...)
		if intErr != nil {
			return fmt.Errorf("decoding networkResource: %w", intErr)
		}
		tmp := NetworkResource(decVal)
		v.NetworkResource = &tmp
		if int64(*v.NetworkResource) != 0 && int64(*v.NetworkResource) != 1 && int64(*v.NetworkResource) != 2 && int64(*v.NetworkResource) != 3 && int64(*v.NetworkResource) != 4 && int64(*v.NetworkResource) != 5 && int64(*v.NetworkResource) != 6 && int64(*v.NetworkResource) != 7 {
			if constraintErr := ber.CheckDecodedValue(opts, "networkResource", "ENUMERATED {0, 1, 2, 3, 4, 5, 6, 7}", fmt.Sprint(int64(*v.NetworkResource))); constraintErr != nil {
				return constraintErr
			}
		}
	} else if peekTag.Class == tag.ClassUniversal && peekTag.Number == 16 && peekTag.Constructed == true {
		v.Choice = SystemFailureParamChoiceExtensibleSystemFailureParam
		var dec ExtensibleSystemFailureParam
		if unmErr := dec.UnmarshalBER(choiceData, ber.ChildDecodeOptions(opts, "extensibleSystemFailureParam")...); unmErr != nil {
			return fmt.Errorf("decoding extensibleSystemFailureParam: %w", unmErr)
		}
		v.ExtensibleSystemFailureParam = &dec
	} else {
		return fmt.Errorf("unknown tag %s for SystemFailureParam CHOICE", peekTag)
	}
	return nil
}

// MarshalBER encodes ExtensibleSystemFailureParam to BER format.
func (v *ExtensibleSystemFailureParam) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: ExtensibleSystemFailureParam receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *ExtensibleSystemFailureParam) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if v.NetworkResource != nil {
		if int64(*v.NetworkResource) != 0 && int64(*v.NetworkResource) != 1 && int64(*v.NetworkResource) != 2 && int64(*v.NetworkResource) != 3 && int64(*v.NetworkResource) != 4 && int64(*v.NetworkResource) != 5 && int64(*v.NetworkResource) != 6 && int64(*v.NetworkResource) != 7 {
			if constraintErr := ber.CheckEncodedValue(opts, "networkResource", "ENUMERATED {0, 1, 2, 3, 4, 5, 6, 7}", fmt.Sprint(int64(*v.NetworkResource))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_networkresource := ber.EncodeEnumerated(int64(*v.NetworkResource))
		children = append(children, enc_networkresource...)
	}
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalBER(ber.ChildEncodeOptions(opts, "extensionContainer")...)
		if err != nil {
			return nil, fmt.Errorf("encoding extensionContainer: %w", err)
		}
		children = append(children, enc_extensioncontainer...)
	}
	if v.AdditionalNetworkResource != nil {
		enc_additionalnetworkresource := ber.EncodeEnumerated(int64(*v.AdditionalNetworkResource))
		retagged_enc_additionalnetworkresource, tagErr_enc_additionalnetworkresource := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_additionalnetworkresource)
		if tagErr_enc_additionalnetworkresource != nil {
			return nil, fmt.Errorf("encoding additionalNetworkResource: %w", tagErr_enc_additionalnetworkresource)
		}
		enc_additionalnetworkresource = retagged_enc_additionalnetworkresource
		children = append(children, enc_additionalnetworkresource...)
	}
	if v.FailureCauseParam != nil {
		enc_failurecauseparam := ber.EncodeEnumerated(int64(*v.FailureCauseParam))
		retagged_enc_failurecauseparam, tagErr_enc_failurecauseparam := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_failurecauseparam)
		if tagErr_enc_failurecauseparam != nil {
			return nil, fmt.Errorf("encoding failureCauseParam: %w", tagErr_enc_failurecauseparam)
		}
		enc_failurecauseparam = retagged_enc_failurecauseparam
		children = append(children, enc_failurecauseparam...)
	}
	for i, ext := range v.ExtData_ {
		_, n, _, extErr := ber.DecodeEncodedTLV(ext)
		if extErr != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, extErr)
		}
		if n != len(ext) {
			return nil, fmt.Errorf("encoding extension %d: %w", i, ber.ErrExtraData)
		}
		children = append(children, ext...)
	}
	return ber.EncodeSequence(children)
}

// MarshalDER encodes ExtensibleSystemFailureParam to DER format.
func (v *ExtensibleSystemFailureParam) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: ExtensibleSystemFailureParam receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if v.NetworkResource != nil {
		if int64(*v.NetworkResource) != 0 && int64(*v.NetworkResource) != 1 && int64(*v.NetworkResource) != 2 && int64(*v.NetworkResource) != 3 && int64(*v.NetworkResource) != 4 && int64(*v.NetworkResource) != 5 && int64(*v.NetworkResource) != 6 && int64(*v.NetworkResource) != 7 {
			if constraintErr := ber.CheckEncodedValue(nil, "networkResource", "ENUMERATED {0, 1, 2, 3, 4, 5, 6, 7}", fmt.Sprint(int64(*v.NetworkResource))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_networkresource := ber.EncodeEnumerated(int64(*v.NetworkResource))
		children = append(children, enc_networkresource...)
	}
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding extensionContainer: %w", err)
		}
		children = append(children, enc_extensioncontainer...)
	}
	if v.AdditionalNetworkResource != nil {
		enc_additionalnetworkresource := ber.EncodeEnumerated(int64(*v.AdditionalNetworkResource))
		retagged_enc_additionalnetworkresource, tagErr_enc_additionalnetworkresource := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_additionalnetworkresource)
		if tagErr_enc_additionalnetworkresource != nil {
			return nil, fmt.Errorf("encoding additionalNetworkResource: %w", tagErr_enc_additionalnetworkresource)
		}
		enc_additionalnetworkresource = retagged_enc_additionalnetworkresource
		children = append(children, enc_additionalnetworkresource...)
	}
	if v.FailureCauseParam != nil {
		enc_failurecauseparam := ber.EncodeEnumerated(int64(*v.FailureCauseParam))
		retagged_enc_failurecauseparam, tagErr_enc_failurecauseparam := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_failurecauseparam)
		if tagErr_enc_failurecauseparam != nil {
			return nil, fmt.Errorf("encoding failureCauseParam: %w", tagErr_enc_failurecauseparam)
		}
		enc_failurecauseparam = retagged_enc_failurecauseparam
		children = append(children, enc_failurecauseparam...)
	}
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDEREncodedElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
		children = append(children, ext...)
	}
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding ExtensibleSystemFailureParam as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes ExtensibleSystemFailureParam from BER/DER format.
func (v *ExtensibleSystemFailureParam) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: ExtensibleSystemFailureParam destination is nil", ber.ErrInvalidValue)
	}
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = ExtensibleSystemFailureParam{}
	defer func() {
		if returnErr != nil || !ber.BERNeedsPreservation(opts) {
			return
		}
		var snapshotReports ber.ViolationLog
		snapshot, snapshotErr := v.marshalBER(ber.WithConstraintTolerance(&snapshotReports))
		if snapshotErr != nil {
			returnErr = snapshotErr
			return
		}
		v.berOriginal_ = append([]byte(nil), data...)
		v.berSnapshot_ = snapshot
	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("decoding ExtensibleSystemFailureParam SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "ExtensibleSystemFailureParam", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode networkResource
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassUniversal && peekTag.Number == 10 {
				val_networkresource, n, err := ber.DecodeEnumerated(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding networkResource: %w", err)
				}
				tmp_networkresource := NetworkResource(val_networkresource)
				v.NetworkResource = &tmp_networkresource
				if offset > len(content) || n < 0 || n > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n
				if int64(*v.NetworkResource) != 0 && int64(*v.NetworkResource) != 1 && int64(*v.NetworkResource) != 2 && int64(*v.NetworkResource) != 3 && int64(*v.NetworkResource) != 4 && int64(*v.NetworkResource) != 5 && int64(*v.NetworkResource) != 6 && int64(*v.NetworkResource) != 7 {
					if constraintErr := ber.CheckDecodedValue(opts, "networkResource", "ENUMERATED {0, 1, 2, 3, 4, 5, 6, 7}", fmt.Sprint(int64(*v.NetworkResource))); constraintErr != nil {
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
				// Decode nested SEQUENCE (ExtensionContainer)
				_, n_extensioncontainer, _, tlvErr_extensioncontainer := ber.DecodeTLV(content[offset:], opts...)
				if tlvErr_extensioncontainer != nil {
					return fmt.Errorf("decoding extensionContainer: %w", tlvErr_extensioncontainer)
				}
				var dec_extensioncontainer ExtensionContainer
				if offset < 0 || offset >
					len(content) || n_extensioncontainer < 0 || n_extensioncontainer > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				if unmErr := dec_extensioncontainer.UnmarshalBER(content[offset:offset+n_extensioncontainer], ber.ChildDecodeOptions(opts, "extensionContainer")...); unmErr != nil {
					return fmt.Errorf("decoding extensionContainer: %w", unmErr)
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
	// Decode additionalNetworkResource
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
				decodedTag_additionalnetworkresource, n_additionalnetworkresource, rawVal_additionalnetworkresource, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding additionalNetworkResource: %w", err)
				}
				if decodedTag_additionalnetworkresource.Class != tag.ClassContextSpecific || decodedTag_additionalnetworkresource.Number != 0 || decodedTag_additionalnetworkresource.Constructed != false {
					return fmt.Errorf("decoding additionalNetworkResource: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_additionalnetworkresource)
				}
				decVal_additionalnetworkresource, intErr := ber.DecodeEnumeratedValue(rawVal_additionalnetworkresource)
				if intErr != nil {
					return fmt.Errorf("decoding additionalNetworkResource: %w", intErr)
				}
				tmp_additionalnetworkresource := AdditionalNetworkResource(decVal_additionalnetworkresource)
				v.AdditionalNetworkResource = &tmp_additionalnetworkresource
				if offset < 0 || offset >
					len(content) || n_additionalnetworkresource < 0 || n_additionalnetworkresource >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_additionalnetworkresource
			}
		}
	}
	// Decode failureCauseParam
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
				decodedTag_failurecauseparam, n_failurecauseparam, rawVal_failurecauseparam, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding failureCauseParam: %w", err)
				}
				if decodedTag_failurecauseparam.Class != tag.ClassContextSpecific || decodedTag_failurecauseparam.Number != 1 || decodedTag_failurecauseparam.Constructed != false {
					return fmt.Errorf("decoding failureCauseParam: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_failurecauseparam)
				}
				decVal_failurecauseparam, intErr := ber.DecodeEnumeratedValue(rawVal_failurecauseparam)
				if intErr != nil {
					return fmt.Errorf("decoding failureCauseParam: %w", intErr)
				}
				tmp_failurecauseparam := FailureCauseParam(decVal_failurecauseparam)
				v.FailureCauseParam = &tmp_failurecauseparam
				if offset < 0 || offset >
					len(content) || n_failurecauseparam < 0 || n_failurecauseparam > len(
					content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_failurecauseparam
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:], opts...)
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "ExtensibleSystemFailureParam", Cause: extErr_}
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

// MarshalBER encodes DataMissingParam to BER format.
func (v *DataMissingParam) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: DataMissingParam receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *DataMissingParam) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalBER(ber.ChildEncodeOptions(opts, "extensionContainer")...)
		if err != nil {
			return nil, fmt.Errorf("encoding extensionContainer: %w", err)
		}
		children = append(children, enc_extensioncontainer...)
	}
	for i, ext := range v.ExtData_ {
		_, n, _, extErr := ber.DecodeEncodedTLV(ext)
		if extErr != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, extErr)
		}
		if n != len(ext) {
			return nil, fmt.Errorf("encoding extension %d: %w", i, ber.ErrExtraData)
		}
		children = append(children, ext...)
	}
	return ber.EncodeSequence(children)
}

// MarshalDER encodes DataMissingParam to DER format.
func (v *DataMissingParam) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: DataMissingParam receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding extensionContainer: %w", err)
		}
		children = append(children, enc_extensioncontainer...)
	}
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDEREncodedElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
		children = append(children, ext...)
	}
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding DataMissingParam as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes DataMissingParam from BER/DER format.
func (v *DataMissingParam) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: DataMissingParam destination is nil", ber.ErrInvalidValue)
	}
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = DataMissingParam{}
	defer func() {
		if returnErr != nil || !ber.BERNeedsPreservation(opts) {
			return
		}
		var snapshotReports ber.ViolationLog
		snapshot, snapshotErr := v.marshalBER(ber.WithConstraintTolerance(&snapshotReports))
		if snapshotErr != nil {
			returnErr = snapshotErr
			return
		}
		v.berOriginal_ = append([]byte(nil), data...)
		v.berSnapshot_ = snapshot
	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("decoding DataMissingParam SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "DataMissingParam", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode extensionContainer
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassUniversal && peekTag.Number == 16 {
				// Decode nested SEQUENCE (ExtensionContainer)
				_, n_extensioncontainer, _, tlvErr_extensioncontainer := ber.DecodeTLV(content[offset:], opts...)
				if tlvErr_extensioncontainer != nil {
					return fmt.Errorf("decoding extensionContainer: %w", tlvErr_extensioncontainer)
				}
				var dec_extensioncontainer ExtensionContainer
				if offset > len(content) || n_extensioncontainer < 0 || n_extensioncontainer > len(
					content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				if unmErr := dec_extensioncontainer.UnmarshalBER(content[offset:offset+n_extensioncontainer], ber.ChildDecodeOptions(opts, "extensionContainer")...); unmErr != nil {
					return fmt.Errorf("decoding extensionContainer: %w", unmErr)
				}
				v.ExtensionContainer = &dec_extensioncontainer
				if offset > len(content) || n_extensioncontainer < 0 || n_extensioncontainer > len(
					content[offset:]) {
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
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:], opts...)
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "DataMissingParam", Cause: extErr_}
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

// MarshalBER encodes UnexpectedDataParam to BER format.
func (v *UnexpectedDataParam) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: UnexpectedDataParam receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *UnexpectedDataParam) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalBER(ber.ChildEncodeOptions(opts, "extensionContainer")...)
		if err != nil {
			return nil, fmt.Errorf("encoding extensionContainer: %w", err)
		}
		children = append(children, enc_extensioncontainer...)
	}
	if v.UnexpectedSubscriber != nil {
		enc_unexpectedsubscriber := ber.EncodeNull()
		retagged_enc_unexpectedsubscriber, tagErr_enc_unexpectedsubscriber := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_unexpectedsubscriber)
		if tagErr_enc_unexpectedsubscriber != nil {
			return nil, fmt.Errorf("encoding unexpectedSubscriber: %w", tagErr_enc_unexpectedsubscriber)
		}
		enc_unexpectedsubscriber = retagged_enc_unexpectedsubscriber
		children = append(children, enc_unexpectedsubscriber...)
	}
	for i, ext := range v.ExtData_ {
		_, n, _, extErr := ber.DecodeEncodedTLV(ext)
		if extErr != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, extErr)
		}
		if n != len(ext) {
			return nil, fmt.Errorf("encoding extension %d: %w", i, ber.ErrExtraData)
		}
		children = append(children, ext...)
	}
	return ber.EncodeSequence(children)
}

// MarshalDER encodes UnexpectedDataParam to DER format.
func (v *UnexpectedDataParam) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: UnexpectedDataParam receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding extensionContainer: %w", err)
		}
		children = append(children, enc_extensioncontainer...)
	}
	if v.UnexpectedSubscriber != nil {
		enc_unexpectedsubscriber := ber.EncodeNull()
		retagged_enc_unexpectedsubscriber, tagErr_enc_unexpectedsubscriber := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_unexpectedsubscriber)
		if tagErr_enc_unexpectedsubscriber != nil {
			return nil, fmt.Errorf("encoding unexpectedSubscriber: %w", tagErr_enc_unexpectedsubscriber)
		}
		enc_unexpectedsubscriber = retagged_enc_unexpectedsubscriber
		children = append(children, enc_unexpectedsubscriber...)
	}
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDEREncodedElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
		children = append(children, ext...)
	}
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding UnexpectedDataParam as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes UnexpectedDataParam from BER/DER format.
func (v *UnexpectedDataParam) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: UnexpectedDataParam destination is nil", ber.ErrInvalidValue)
	}
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = UnexpectedDataParam{}
	defer func() {
		if returnErr != nil || !ber.BERNeedsPreservation(opts) {
			return
		}
		var snapshotReports ber.ViolationLog
		snapshot, snapshotErr := v.marshalBER(ber.WithConstraintTolerance(&snapshotReports))
		if snapshotErr != nil {
			returnErr = snapshotErr
			return
		}
		v.berOriginal_ = append([]byte(nil), data...)
		v.berSnapshot_ = snapshot
	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("decoding UnexpectedDataParam SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "UnexpectedDataParam", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode extensionContainer
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassUniversal && peekTag.Number == 16 {
				// Decode nested SEQUENCE (ExtensionContainer)
				_, n_extensioncontainer, _, tlvErr_extensioncontainer := ber.DecodeTLV(content[offset:], opts...)
				if tlvErr_extensioncontainer != nil {
					return fmt.Errorf("decoding extensionContainer: %w", tlvErr_extensioncontainer)
				}
				var dec_extensioncontainer ExtensionContainer
				if offset > len(content) || n_extensioncontainer < 0 || n_extensioncontainer > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				if unmErr := dec_extensioncontainer.UnmarshalBER(content[offset:offset+n_extensioncontainer], ber.ChildDecodeOptions(opts, "extensionContainer")...); unmErr != nil {
					return fmt.Errorf("decoding extensionContainer: %w", unmErr)
				}
				v.ExtensionContainer = &dec_extensioncontainer
				if offset > len(content) || n_extensioncontainer < 0 || n_extensioncontainer > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_extensioncontainer
			}
		}
	}
	// Decode unexpectedSubscriber
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
				decodedTag_unexpectedsubscriber, n_unexpectedsubscriber, rawVal_unexpectedsubscriber, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding unexpectedSubscriber: %w", err)
				}
				if decodedTag_unexpectedsubscriber.Class != tag.ClassContextSpecific || decodedTag_unexpectedsubscriber.Number != 0 || decodedTag_unexpectedsubscriber.Constructed != false {
					return fmt.Errorf("decoding unexpectedSubscriber: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_unexpectedsubscriber)
				}
				if len(rawVal_unexpectedsubscriber) != 0 {
					return fmt.Errorf("decoding unexpectedSubscriber: %w: NULL content length %d", ber.ErrInvalidValue, len(rawVal_unexpectedsubscriber))
				}
				v.UnexpectedSubscriber = &struct{}{}
				if offset < 0 || offset >
					len(content) || n_unexpectedsubscriber < 0 || n_unexpectedsubscriber >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_unexpectedsubscriber
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:], opts...)
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "UnexpectedDataParam", Cause: extErr_}
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

// MarshalBER encodes FacilityNotSupParam to BER format.
func (v *FacilityNotSupParam) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: FacilityNotSupParam receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *FacilityNotSupParam) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalBER(ber.ChildEncodeOptions(opts, "extensionContainer")...)
		if err != nil {
			return nil, fmt.Errorf("encoding extensionContainer: %w", err)
		}
		children = append(children, enc_extensioncontainer...)
	}
	if v.ShapeOfLocationEstimateNotSupported != nil {
		enc_shapeoflocationestimatenotsupported := ber.EncodeNull()
		retagged_enc_shapeoflocationestimatenotsupported, tagErr_enc_shapeoflocationestimatenotsupported := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_shapeoflocationestimatenotsupported)
		if tagErr_enc_shapeoflocationestimatenotsupported != nil {
			return nil, fmt.Errorf("encoding shapeOfLocationEstimateNotSupported: %w", tagErr_enc_shapeoflocationestimatenotsupported)
		}
		enc_shapeoflocationestimatenotsupported = retagged_enc_shapeoflocationestimatenotsupported
		children = append(children, enc_shapeoflocationestimatenotsupported...)
	}
	if v.NeededLcsCapabilityNotSupportedInServingNode != nil {
		enc_neededlcscapabilitynotsupportedinservingnode := ber.EncodeNull()
		retagged_enc_neededlcscapabilitynotsupportedinservingnode, tagErr_enc_neededlcscapabilitynotsupportedinservingnode := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_neededlcscapabilitynotsupportedinservingnode)
		if tagErr_enc_neededlcscapabilitynotsupportedinservingnode != nil {
			return nil, fmt.Errorf("encoding neededLcsCapabilityNotSupportedInServingNode: %w", tagErr_enc_neededlcscapabilitynotsupportedinservingnode)
		}
		enc_neededlcscapabilitynotsupportedinservingnode = retagged_enc_neededlcscapabilitynotsupportedinservingnode
		children = append(children, enc_neededlcscapabilitynotsupportedinservingnode...)
	}
	for i, ext := range v.ExtData_ {
		_, n, _, extErr := ber.DecodeEncodedTLV(ext)
		if extErr != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, extErr)
		}
		if n != len(ext) {
			return nil, fmt.Errorf("encoding extension %d: %w", i, ber.ErrExtraData)
		}
		children = append(children, ext...)
	}
	return ber.EncodeSequence(children)
}

// MarshalDER encodes FacilityNotSupParam to DER format.
func (v *FacilityNotSupParam) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: FacilityNotSupParam receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding extensionContainer: %w", err)
		}
		children = append(children, enc_extensioncontainer...)
	}
	if v.ShapeOfLocationEstimateNotSupported != nil {
		enc_shapeoflocationestimatenotsupported := ber.EncodeNull()
		retagged_enc_shapeoflocationestimatenotsupported, tagErr_enc_shapeoflocationestimatenotsupported := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_shapeoflocationestimatenotsupported)
		if tagErr_enc_shapeoflocationestimatenotsupported != nil {
			return nil, fmt.Errorf("encoding shapeOfLocationEstimateNotSupported: %w", tagErr_enc_shapeoflocationestimatenotsupported)
		}
		enc_shapeoflocationestimatenotsupported = retagged_enc_shapeoflocationestimatenotsupported
		children = append(children, enc_shapeoflocationestimatenotsupported...)
	}
	if v.NeededLcsCapabilityNotSupportedInServingNode != nil {
		enc_neededlcscapabilitynotsupportedinservingnode := ber.EncodeNull()
		retagged_enc_neededlcscapabilitynotsupportedinservingnode, tagErr_enc_neededlcscapabilitynotsupportedinservingnode := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_neededlcscapabilitynotsupportedinservingnode)
		if tagErr_enc_neededlcscapabilitynotsupportedinservingnode != nil {
			return nil, fmt.Errorf("encoding neededLcsCapabilityNotSupportedInServingNode: %w", tagErr_enc_neededlcscapabilitynotsupportedinservingnode)
		}
		enc_neededlcscapabilitynotsupportedinservingnode = retagged_enc_neededlcscapabilitynotsupportedinservingnode
		children = append(children, enc_neededlcscapabilitynotsupportedinservingnode...)
	}
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDEREncodedElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
		children = append(children, ext...)
	}
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding FacilityNotSupParam as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes FacilityNotSupParam from BER/DER format.
func (v *FacilityNotSupParam) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: FacilityNotSupParam destination is nil", ber.ErrInvalidValue)
	}
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = FacilityNotSupParam{}
	defer func() {
		if returnErr != nil || !ber.BERNeedsPreservation(opts) {
			return
		}
		var snapshotReports ber.ViolationLog
		snapshot, snapshotErr := v.marshalBER(ber.WithConstraintTolerance(&snapshotReports))
		if snapshotErr != nil {
			returnErr = snapshotErr
			return
		}
		v.berOriginal_ = append([]byte(nil), data...)
		v.berSnapshot_ = snapshot
	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("decoding FacilityNotSupParam SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "FacilityNotSupParam", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode extensionContainer
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassUniversal && peekTag.Number == 16 {
				// Decode nested SEQUENCE (ExtensionContainer)
				_, n_extensioncontainer, _, tlvErr_extensioncontainer := ber.DecodeTLV(content[offset:], opts...)
				if tlvErr_extensioncontainer != nil {
					return fmt.Errorf("decoding extensionContainer: %w", tlvErr_extensioncontainer)
				}
				var dec_extensioncontainer ExtensionContainer
				if offset > len(content) || n_extensioncontainer < 0 || n_extensioncontainer > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				if unmErr := dec_extensioncontainer.UnmarshalBER(content[offset:offset+n_extensioncontainer], ber.ChildDecodeOptions(opts, "extensionContainer")...); unmErr != nil {
					return fmt.Errorf("decoding extensionContainer: %w", unmErr)
				}
				v.ExtensionContainer = &dec_extensioncontainer
				if offset > len(content) || n_extensioncontainer < 0 || n_extensioncontainer > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_extensioncontainer
			}
		}
	}
	// Decode shapeOfLocationEstimateNotSupported
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
				decodedTag_shapeoflocationestimatenotsupported, n_shapeoflocationestimatenotsupported, rawVal_shapeoflocationestimatenotsupported, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding shapeOfLocationEstimateNotSupported: %w", err)
				}
				if decodedTag_shapeoflocationestimatenotsupported.Class != tag.ClassContextSpecific || decodedTag_shapeoflocationestimatenotsupported.Number != 0 || decodedTag_shapeoflocationestimatenotsupported.Constructed != false {
					return fmt.Errorf("decoding shapeOfLocationEstimateNotSupported: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_shapeoflocationestimatenotsupported)
				}
				if len(rawVal_shapeoflocationestimatenotsupported) != 0 {
					return fmt.Errorf("decoding shapeOfLocationEstimateNotSupported: %w: NULL content length %d", ber.ErrInvalidValue, len(rawVal_shapeoflocationestimatenotsupported))
				}
				v.ShapeOfLocationEstimateNotSupported = &struct{}{}
				if offset < 0 || offset >
					len(content) || n_shapeoflocationestimatenotsupported < 0 ||
					n_shapeoflocationestimatenotsupported > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_shapeoflocationestimatenotsupported
			}
		}
	}
	// Decode neededLcsCapabilityNotSupportedInServingNode
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
				decodedTag_neededlcscapabilitynotsupportedinservingnode, n_neededlcscapabilitynotsupportedinservingnode, rawVal_neededlcscapabilitynotsupportedinservingnode, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding neededLcsCapabilityNotSupportedInServingNode: %w", err)
				}
				if decodedTag_neededlcscapabilitynotsupportedinservingnode.Class != tag.ClassContextSpecific || decodedTag_neededlcscapabilitynotsupportedinservingnode.Number != 1 || decodedTag_neededlcscapabilitynotsupportedinservingnode.Constructed != false {
					return fmt.Errorf("decoding neededLcsCapabilityNotSupportedInServingNode: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_neededlcscapabilitynotsupportedinservingnode)
				}
				if len(rawVal_neededlcscapabilitynotsupportedinservingnode) != 0 {
					return fmt.Errorf("decoding neededLcsCapabilityNotSupportedInServingNode: %w: NULL content length %d", ber.ErrInvalidValue, len(rawVal_neededlcscapabilitynotsupportedinservingnode))
				}
				v.NeededLcsCapabilityNotSupportedInServingNode = &struct{}{}
				if offset < 0 || offset >
					len(content) || n_neededlcscapabilitynotsupportedinservingnode <
					0 || n_neededlcscapabilitynotsupportedinservingnode > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_neededlcscapabilitynotsupportedinservingnode
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:], opts...)
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "FacilityNotSupParam", Cause: extErr_}
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

// MarshalBER encodes ORNotAllowedParam to BER format.
func (v *ORNotAllowedParam) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: ORNotAllowedParam receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *ORNotAllowedParam) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalBER(ber.ChildEncodeOptions(opts, "extensionContainer")...)
		if err != nil {
			return nil, fmt.Errorf("encoding extensionContainer: %w", err)
		}
		children = append(children, enc_extensioncontainer...)
	}
	for i, ext := range v.ExtData_ {
		_, n, _, extErr := ber.DecodeEncodedTLV(ext)
		if extErr != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, extErr)
		}
		if n != len(ext) {
			return nil, fmt.Errorf("encoding extension %d: %w", i, ber.ErrExtraData)
		}
		children = append(children, ext...)
	}
	return ber.EncodeSequence(children)
}

// MarshalDER encodes ORNotAllowedParam to DER format.
func (v *ORNotAllowedParam) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: ORNotAllowedParam receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding extensionContainer: %w", err)
		}
		children = append(children, enc_extensioncontainer...)
	}
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDEREncodedElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
		children = append(children, ext...)
	}
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding ORNotAllowedParam as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes ORNotAllowedParam from BER/DER format.
func (v *ORNotAllowedParam) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: ORNotAllowedParam destination is nil", ber.ErrInvalidValue)
	}
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = ORNotAllowedParam{}
	defer func() {
		if returnErr != nil || !ber.BERNeedsPreservation(opts) {
			return
		}
		var snapshotReports ber.ViolationLog
		snapshot, snapshotErr := v.marshalBER(ber.WithConstraintTolerance(&snapshotReports))
		if snapshotErr != nil {
			returnErr = snapshotErr
			return
		}
		v.berOriginal_ = append([]byte(nil), data...)
		v.berSnapshot_ = snapshot
	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("decoding ORNotAllowedParam SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "ORNotAllowedParam", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode extensionContainer
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassUniversal && peekTag.Number == 16 {
				// Decode nested SEQUENCE (ExtensionContainer)
				_, n_extensioncontainer, _, tlvErr_extensioncontainer := ber.DecodeTLV(content[offset:], opts...)
				if tlvErr_extensioncontainer != nil {
					return fmt.Errorf("decoding extensionContainer: %w", tlvErr_extensioncontainer)
				}
				var dec_extensioncontainer ExtensionContainer
				if offset > len(content) || n_extensioncontainer < 0 || n_extensioncontainer > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				if unmErr := dec_extensioncontainer.UnmarshalBER(content[offset:offset+n_extensioncontainer], ber.ChildDecodeOptions(opts, "extensionContainer")...); unmErr != nil {
					return fmt.Errorf("decoding extensionContainer: %w", unmErr)
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
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:], opts...)
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "ORNotAllowedParam", Cause: extErr_}
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

// MarshalBER encodes UnknownSubscriberParam to BER format.
func (v *UnknownSubscriberParam) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: UnknownSubscriberParam receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *UnknownSubscriberParam) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalBER(ber.ChildEncodeOptions(opts, "extensionContainer")...)
		if err != nil {
			return nil, fmt.Errorf("encoding extensionContainer: %w", err)
		}
		children = append(children, enc_extensioncontainer...)
	}
	if v.UnknownSubscriberDiagnostic != nil {
		enc_unknownsubscriberdiagnostic := ber.EncodeEnumerated(int64(*v.UnknownSubscriberDiagnostic))
		children = append(children, enc_unknownsubscriberdiagnostic...)
	}
	for i, ext := range v.ExtData_ {
		_, n, _, extErr := ber.DecodeEncodedTLV(ext)
		if extErr != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, extErr)
		}
		if n != len(ext) {
			return nil, fmt.Errorf("encoding extension %d: %w", i, ber.ErrExtraData)
		}
		children = append(children, ext...)
	}
	return ber.EncodeSequence(children)
}

// MarshalDER encodes UnknownSubscriberParam to DER format.
func (v *UnknownSubscriberParam) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: UnknownSubscriberParam receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding extensionContainer: %w", err)
		}
		children = append(children, enc_extensioncontainer...)
	}
	if v.UnknownSubscriberDiagnostic != nil {
		enc_unknownsubscriberdiagnostic := ber.EncodeEnumerated(int64(*v.UnknownSubscriberDiagnostic))
		children = append(children, enc_unknownsubscriberdiagnostic...)
	}
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDEREncodedElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
		children = append(children, ext...)
	}
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding UnknownSubscriberParam as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes UnknownSubscriberParam from BER/DER format.
func (v *UnknownSubscriberParam) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: UnknownSubscriberParam destination is nil", ber.ErrInvalidValue)
	}
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = UnknownSubscriberParam{}
	defer func() {
		if returnErr != nil || !ber.BERNeedsPreservation(opts) {
			return
		}
		var snapshotReports ber.ViolationLog
		snapshot, snapshotErr := v.marshalBER(ber.WithConstraintTolerance(&snapshotReports))
		if snapshotErr != nil {
			returnErr = snapshotErr
			return
		}
		v.berOriginal_ = append([]byte(nil), data...)
		v.berSnapshot_ = snapshot
	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("decoding UnknownSubscriberParam SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "UnknownSubscriberParam", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode extensionContainer
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassUniversal && peekTag.Number == 16 {
				// Decode nested SEQUENCE (ExtensionContainer)
				_, n_extensioncontainer, _, tlvErr_extensioncontainer := ber.DecodeTLV(content[offset:], opts...)
				if tlvErr_extensioncontainer != nil {
					return fmt.Errorf("decoding extensionContainer: %w", tlvErr_extensioncontainer)
				}
				var dec_extensioncontainer ExtensionContainer
				if offset > len(content) || n_extensioncontainer < 0 || n_extensioncontainer > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				if unmErr := dec_extensioncontainer.UnmarshalBER(content[offset:offset+n_extensioncontainer], ber.ChildDecodeOptions(opts, "extensionContainer")...); unmErr != nil {
					return fmt.Errorf("decoding extensionContainer: %w", unmErr)
				}
				v.ExtensionContainer = &dec_extensioncontainer
				if offset > len(content) || n_extensioncontainer < 0 || n_extensioncontainer > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_extensioncontainer
			}
		}
	}
	// Decode unknownSubscriberDiagnostic
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassUniversal && peekTag.Number == 10 {
				val_unknownsubscriberdiagnostic, n, err := ber.DecodeEnumerated(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding unknownSubscriberDiagnostic: %w", err)
				}
				tmp_unknownsubscriberdiagnostic := UnknownSubscriberDiagnostic(val_unknownsubscriberdiagnostic)
				v.UnknownSubscriberDiagnostic = &tmp_unknownsubscriberdiagnostic
				if offset < 0 || offset >
					len(content) || n < 0 || n > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:], opts...)
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "UnknownSubscriberParam", Cause: extErr_}
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

// MarshalBER encodes NumberChangedParam to BER format.
func (v *NumberChangedParam) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: NumberChangedParam receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *NumberChangedParam) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalBER(ber.ChildEncodeOptions(opts, "extensionContainer")...)
		if err != nil {
			return nil, fmt.Errorf("encoding extensionContainer: %w", err)
		}
		children = append(children, enc_extensioncontainer...)
	}
	for i, ext := range v.ExtData_ {
		_, n, _, extErr := ber.DecodeEncodedTLV(ext)
		if extErr != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, extErr)
		}
		if n != len(ext) {
			return nil, fmt.Errorf("encoding extension %d: %w", i, ber.ErrExtraData)
		}
		children = append(children, ext...)
	}
	return ber.EncodeSequence(children)
}

// MarshalDER encodes NumberChangedParam to DER format.
func (v *NumberChangedParam) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: NumberChangedParam receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding extensionContainer: %w", err)
		}
		children = append(children, enc_extensioncontainer...)
	}
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDEREncodedElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
		children = append(children, ext...)
	}
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding NumberChangedParam as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes NumberChangedParam from BER/DER format.
func (v *NumberChangedParam) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: NumberChangedParam destination is nil", ber.ErrInvalidValue)
	}
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = NumberChangedParam{}
	defer func() {
		if returnErr != nil || !ber.BERNeedsPreservation(opts) {
			return
		}
		var snapshotReports ber.ViolationLog
		snapshot, snapshotErr := v.marshalBER(ber.WithConstraintTolerance(&snapshotReports))
		if snapshotErr != nil {
			returnErr = snapshotErr
			return
		}
		v.berOriginal_ = append([]byte(nil), data...)
		v.berSnapshot_ = snapshot
	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("decoding NumberChangedParam SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "NumberChangedParam", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode extensionContainer
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassUniversal && peekTag.Number == 16 {
				// Decode nested SEQUENCE (ExtensionContainer)
				_, n_extensioncontainer, _, tlvErr_extensioncontainer := ber.DecodeTLV(content[offset:], opts...)
				if tlvErr_extensioncontainer != nil {
					return fmt.Errorf("decoding extensionContainer: %w", tlvErr_extensioncontainer)
				}
				var dec_extensioncontainer ExtensionContainer
				if offset > len(content) || n_extensioncontainer < 0 || n_extensioncontainer > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				if unmErr := dec_extensioncontainer.UnmarshalBER(content[offset:offset+n_extensioncontainer], ber.ChildDecodeOptions(opts, "extensionContainer")...); unmErr != nil {
					return fmt.Errorf("decoding extensionContainer: %w", unmErr)
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
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:], opts...)
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "NumberChangedParam", Cause: extErr_}
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

// MarshalBER encodes UnidentifiedSubParam to BER format.
func (v *UnidentifiedSubParam) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: UnidentifiedSubParam receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *UnidentifiedSubParam) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalBER(ber.ChildEncodeOptions(opts, "extensionContainer")...)
		if err != nil {
			return nil, fmt.Errorf("encoding extensionContainer: %w", err)
		}
		children = append(children, enc_extensioncontainer...)
	}
	for i, ext := range v.ExtData_ {
		_, n, _, extErr := ber.DecodeEncodedTLV(ext)
		if extErr != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, extErr)
		}
		if n != len(ext) {
			return nil, fmt.Errorf("encoding extension %d: %w", i, ber.ErrExtraData)
		}
		children = append(children, ext...)
	}
	return ber.EncodeSequence(children)
}

// MarshalDER encodes UnidentifiedSubParam to DER format.
func (v *UnidentifiedSubParam) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: UnidentifiedSubParam receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding extensionContainer: %w", err)
		}
		children = append(children, enc_extensioncontainer...)
	}
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDEREncodedElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
		children = append(children, ext...)
	}
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding UnidentifiedSubParam as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes UnidentifiedSubParam from BER/DER format.
func (v *UnidentifiedSubParam) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: UnidentifiedSubParam destination is nil", ber.ErrInvalidValue)
	}
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = UnidentifiedSubParam{}
	defer func() {
		if returnErr != nil || !ber.BERNeedsPreservation(opts) {
			return
		}
		var snapshotReports ber.ViolationLog
		snapshot, snapshotErr := v.marshalBER(ber.WithConstraintTolerance(&snapshotReports))
		if snapshotErr != nil {
			returnErr = snapshotErr
			return
		}
		v.berOriginal_ = append([]byte(nil), data...)
		v.berSnapshot_ = snapshot
	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("decoding UnidentifiedSubParam SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "UnidentifiedSubParam", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode extensionContainer
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassUniversal && peekTag.Number == 16 {
				// Decode nested SEQUENCE (ExtensionContainer)
				_, n_extensioncontainer, _, tlvErr_extensioncontainer := ber.DecodeTLV(content[offset:], opts...)
				if tlvErr_extensioncontainer != nil {
					return fmt.Errorf("decoding extensionContainer: %w", tlvErr_extensioncontainer)
				}
				var dec_extensioncontainer ExtensionContainer
				if offset > len(content) || n_extensioncontainer < 0 || n_extensioncontainer > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				if unmErr := dec_extensioncontainer.UnmarshalBER(content[offset:offset+n_extensioncontainer], ber.ChildDecodeOptions(opts, "extensionContainer")...); unmErr != nil {
					return fmt.Errorf("decoding extensionContainer: %w", unmErr)
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
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:], opts...)
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "UnidentifiedSubParam", Cause: extErr_}
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

// MarshalBER encodes IllegalSubscriberParam to BER format.
func (v *IllegalSubscriberParam) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: IllegalSubscriberParam receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *IllegalSubscriberParam) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalBER(ber.ChildEncodeOptions(opts, "extensionContainer")...)
		if err != nil {
			return nil, fmt.Errorf("encoding extensionContainer: %w", err)
		}
		children = append(children, enc_extensioncontainer...)
	}
	for i, ext := range v.ExtData_ {
		_, n, _, extErr := ber.DecodeEncodedTLV(ext)
		if extErr != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, extErr)
		}
		if n != len(ext) {
			return nil, fmt.Errorf("encoding extension %d: %w", i, ber.ErrExtraData)
		}
		children = append(children, ext...)
	}
	return ber.EncodeSequence(children)
}

// MarshalDER encodes IllegalSubscriberParam to DER format.
func (v *IllegalSubscriberParam) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: IllegalSubscriberParam receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding extensionContainer: %w", err)
		}
		children = append(children, enc_extensioncontainer...)
	}
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDEREncodedElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
		children = append(children, ext...)
	}
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding IllegalSubscriberParam as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes IllegalSubscriberParam from BER/DER format.
func (v *IllegalSubscriberParam) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: IllegalSubscriberParam destination is nil", ber.ErrInvalidValue)
	}
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = IllegalSubscriberParam{}
	defer func() {
		if returnErr != nil || !ber.BERNeedsPreservation(opts) {
			return
		}
		var snapshotReports ber.ViolationLog
		snapshot, snapshotErr := v.marshalBER(ber.WithConstraintTolerance(&snapshotReports))
		if snapshotErr != nil {
			returnErr = snapshotErr
			return
		}
		v.berOriginal_ = append([]byte(nil), data...)
		v.berSnapshot_ = snapshot
	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("decoding IllegalSubscriberParam SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "IllegalSubscriberParam", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode extensionContainer
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassUniversal && peekTag.Number == 16 {
				// Decode nested SEQUENCE (ExtensionContainer)
				_, n_extensioncontainer, _, tlvErr_extensioncontainer := ber.DecodeTLV(content[offset:], opts...)
				if tlvErr_extensioncontainer != nil {
					return fmt.Errorf("decoding extensionContainer: %w", tlvErr_extensioncontainer)
				}
				var dec_extensioncontainer ExtensionContainer
				if offset > len(content) || n_extensioncontainer < 0 || n_extensioncontainer > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				if unmErr := dec_extensioncontainer.UnmarshalBER(content[offset:offset+n_extensioncontainer], ber.ChildDecodeOptions(opts, "extensionContainer")...); unmErr != nil {
					return fmt.Errorf("decoding extensionContainer: %w", unmErr)
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
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:], opts...)
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "IllegalSubscriberParam", Cause: extErr_}
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

// MarshalBER encodes IllegalEquipmentParam to BER format.
func (v *IllegalEquipmentParam) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: IllegalEquipmentParam receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *IllegalEquipmentParam) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalBER(ber.ChildEncodeOptions(opts, "extensionContainer")...)
		if err != nil {
			return nil, fmt.Errorf("encoding extensionContainer: %w", err)
		}
		children = append(children, enc_extensioncontainer...)
	}
	for i, ext := range v.ExtData_ {
		_, n, _, extErr := ber.DecodeEncodedTLV(ext)
		if extErr != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, extErr)
		}
		if n != len(ext) {
			return nil, fmt.Errorf("encoding extension %d: %w", i, ber.ErrExtraData)
		}
		children = append(children, ext...)
	}
	return ber.EncodeSequence(children)
}

// MarshalDER encodes IllegalEquipmentParam to DER format.
func (v *IllegalEquipmentParam) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: IllegalEquipmentParam receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding extensionContainer: %w", err)
		}
		children = append(children, enc_extensioncontainer...)
	}
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDEREncodedElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
		children = append(children, ext...)
	}
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding IllegalEquipmentParam as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes IllegalEquipmentParam from BER/DER format.
func (v *IllegalEquipmentParam) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: IllegalEquipmentParam destination is nil", ber.ErrInvalidValue)
	}
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = IllegalEquipmentParam{}
	defer func() {
		if returnErr != nil || !ber.BERNeedsPreservation(opts) {
			return
		}
		var snapshotReports ber.ViolationLog
		snapshot, snapshotErr := v.marshalBER(ber.WithConstraintTolerance(&snapshotReports))
		if snapshotErr != nil {
			returnErr = snapshotErr
			return
		}
		v.berOriginal_ = append([]byte(nil), data...)
		v.berSnapshot_ = snapshot
	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("decoding IllegalEquipmentParam SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "IllegalEquipmentParam", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode extensionContainer
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassUniversal && peekTag.Number == 16 {
				// Decode nested SEQUENCE (ExtensionContainer)
				_, n_extensioncontainer, _, tlvErr_extensioncontainer := ber.DecodeTLV(content[offset:], opts...)
				if tlvErr_extensioncontainer != nil {
					return fmt.Errorf("decoding extensionContainer: %w", tlvErr_extensioncontainer)
				}
				var dec_extensioncontainer ExtensionContainer
				if offset > len(content) || n_extensioncontainer < 0 || n_extensioncontainer > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				if unmErr := dec_extensioncontainer.UnmarshalBER(content[offset:offset+n_extensioncontainer], ber.ChildDecodeOptions(opts, "extensionContainer")...); unmErr != nil {
					return fmt.Errorf("decoding extensionContainer: %w", unmErr)
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
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:], opts...)
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "IllegalEquipmentParam", Cause: extErr_}
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

// MarshalBER encodes BearerServNotProvParam to BER format.
func (v *BearerServNotProvParam) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: BearerServNotProvParam receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *BearerServNotProvParam) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalBER(ber.ChildEncodeOptions(opts, "extensionContainer")...)
		if err != nil {
			return nil, fmt.Errorf("encoding extensionContainer: %w", err)
		}
		children = append(children, enc_extensioncontainer...)
	}
	for i, ext := range v.ExtData_ {
		_, n, _, extErr := ber.DecodeEncodedTLV(ext)
		if extErr != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, extErr)
		}
		if n != len(ext) {
			return nil, fmt.Errorf("encoding extension %d: %w", i, ber.ErrExtraData)
		}
		children = append(children, ext...)
	}
	return ber.EncodeSequence(children)
}

// MarshalDER encodes BearerServNotProvParam to DER format.
func (v *BearerServNotProvParam) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: BearerServNotProvParam receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding extensionContainer: %w", err)
		}
		children = append(children, enc_extensioncontainer...)
	}
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDEREncodedElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
		children = append(children, ext...)
	}
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding BearerServNotProvParam as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes BearerServNotProvParam from BER/DER format.
func (v *BearerServNotProvParam) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: BearerServNotProvParam destination is nil", ber.ErrInvalidValue)
	}
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = BearerServNotProvParam{}
	defer func() {
		if returnErr != nil || !ber.BERNeedsPreservation(opts) {
			return
		}
		var snapshotReports ber.ViolationLog
		snapshot, snapshotErr := v.marshalBER(ber.WithConstraintTolerance(&snapshotReports))
		if snapshotErr != nil {
			returnErr = snapshotErr
			return
		}
		v.berOriginal_ = append([]byte(nil), data...)
		v.berSnapshot_ = snapshot
	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("decoding BearerServNotProvParam SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "BearerServNotProvParam", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode extensionContainer
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassUniversal && peekTag.Number == 16 {
				// Decode nested SEQUENCE (ExtensionContainer)
				_, n_extensioncontainer, _, tlvErr_extensioncontainer := ber.DecodeTLV(content[offset:], opts...)
				if tlvErr_extensioncontainer != nil {
					return fmt.Errorf("decoding extensionContainer: %w", tlvErr_extensioncontainer)
				}
				var dec_extensioncontainer ExtensionContainer
				if offset > len(content) || n_extensioncontainer < 0 || n_extensioncontainer > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				if unmErr := dec_extensioncontainer.UnmarshalBER(content[offset:offset+n_extensioncontainer], ber.ChildDecodeOptions(opts, "extensionContainer")...); unmErr != nil {
					return fmt.Errorf("decoding extensionContainer: %w", unmErr)
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
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:], opts...)
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "BearerServNotProvParam", Cause: extErr_}
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

// MarshalBER encodes TeleservNotProvParam to BER format.
func (v *TeleservNotProvParam) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: TeleservNotProvParam receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *TeleservNotProvParam) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalBER(ber.ChildEncodeOptions(opts, "extensionContainer")...)
		if err != nil {
			return nil, fmt.Errorf("encoding extensionContainer: %w", err)
		}
		children = append(children, enc_extensioncontainer...)
	}
	for i, ext := range v.ExtData_ {
		_, n, _, extErr := ber.DecodeEncodedTLV(ext)
		if extErr != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, extErr)
		}
		if n != len(ext) {
			return nil, fmt.Errorf("encoding extension %d: %w", i, ber.ErrExtraData)
		}
		children = append(children, ext...)
	}
	return ber.EncodeSequence(children)
}

// MarshalDER encodes TeleservNotProvParam to DER format.
func (v *TeleservNotProvParam) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: TeleservNotProvParam receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding extensionContainer: %w", err)
		}
		children = append(children, enc_extensioncontainer...)
	}
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDEREncodedElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
		children = append(children, ext...)
	}
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding TeleservNotProvParam as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes TeleservNotProvParam from BER/DER format.
func (v *TeleservNotProvParam) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: TeleservNotProvParam destination is nil", ber.ErrInvalidValue)
	}
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = TeleservNotProvParam{}
	defer func() {
		if returnErr != nil || !ber.BERNeedsPreservation(opts) {
			return
		}
		var snapshotReports ber.ViolationLog
		snapshot, snapshotErr := v.marshalBER(ber.WithConstraintTolerance(&snapshotReports))
		if snapshotErr != nil {
			returnErr = snapshotErr
			return
		}
		v.berOriginal_ = append([]byte(nil), data...)
		v.berSnapshot_ = snapshot
	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("decoding TeleservNotProvParam SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "TeleservNotProvParam", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode extensionContainer
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassUniversal && peekTag.Number == 16 {
				// Decode nested SEQUENCE (ExtensionContainer)
				_, n_extensioncontainer, _, tlvErr_extensioncontainer := ber.DecodeTLV(content[offset:], opts...)
				if tlvErr_extensioncontainer != nil {
					return fmt.Errorf("decoding extensionContainer: %w", tlvErr_extensioncontainer)
				}
				var dec_extensioncontainer ExtensionContainer
				if offset > len(content) || n_extensioncontainer < 0 || n_extensioncontainer > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				if unmErr := dec_extensioncontainer.UnmarshalBER(content[offset:offset+n_extensioncontainer], ber.ChildDecodeOptions(opts, "extensionContainer")...); unmErr != nil {
					return fmt.Errorf("decoding extensionContainer: %w", unmErr)
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
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:], opts...)
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "TeleservNotProvParam", Cause: extErr_}
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

// MarshalBER encodes TracingBufferFullParam to BER format.
func (v *TracingBufferFullParam) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: TracingBufferFullParam receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *TracingBufferFullParam) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalBER(ber.ChildEncodeOptions(opts, "extensionContainer")...)
		if err != nil {
			return nil, fmt.Errorf("encoding extensionContainer: %w", err)
		}
		children = append(children, enc_extensioncontainer...)
	}
	for i, ext := range v.ExtData_ {
		_, n, _, extErr := ber.DecodeEncodedTLV(ext)
		if extErr != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, extErr)
		}
		if n != len(ext) {
			return nil, fmt.Errorf("encoding extension %d: %w", i, ber.ErrExtraData)
		}
		children = append(children, ext...)
	}
	return ber.EncodeSequence(children)
}

// MarshalDER encodes TracingBufferFullParam to DER format.
func (v *TracingBufferFullParam) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: TracingBufferFullParam receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding extensionContainer: %w", err)
		}
		children = append(children, enc_extensioncontainer...)
	}
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDEREncodedElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
		children = append(children, ext...)
	}
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding TracingBufferFullParam as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes TracingBufferFullParam from BER/DER format.
func (v *TracingBufferFullParam) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: TracingBufferFullParam destination is nil", ber.ErrInvalidValue)
	}
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = TracingBufferFullParam{}
	defer func() {
		if returnErr != nil || !ber.BERNeedsPreservation(opts) {
			return
		}
		var snapshotReports ber.ViolationLog
		snapshot, snapshotErr := v.marshalBER(ber.WithConstraintTolerance(&snapshotReports))
		if snapshotErr != nil {
			returnErr = snapshotErr
			return
		}
		v.berOriginal_ = append([]byte(nil), data...)
		v.berSnapshot_ = snapshot
	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("decoding TracingBufferFullParam SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "TracingBufferFullParam", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode extensionContainer
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassUniversal && peekTag.Number == 16 {
				// Decode nested SEQUENCE (ExtensionContainer)
				_, n_extensioncontainer, _, tlvErr_extensioncontainer := ber.DecodeTLV(content[offset:], opts...)
				if tlvErr_extensioncontainer != nil {
					return fmt.Errorf("decoding extensionContainer: %w", tlvErr_extensioncontainer)
				}
				var dec_extensioncontainer ExtensionContainer
				if offset > len(content) || n_extensioncontainer < 0 || n_extensioncontainer > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				if unmErr := dec_extensioncontainer.UnmarshalBER(content[offset:offset+n_extensioncontainer], ber.ChildDecodeOptions(opts, "extensionContainer")...); unmErr != nil {
					return fmt.Errorf("decoding extensionContainer: %w", unmErr)
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
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:], opts...)
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "TracingBufferFullParam", Cause: extErr_}
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

// MarshalBER encodes NoRoamingNbParam to BER format.
func (v *NoRoamingNbParam) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: NoRoamingNbParam receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *NoRoamingNbParam) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalBER(ber.ChildEncodeOptions(opts, "extensionContainer")...)
		if err != nil {
			return nil, fmt.Errorf("encoding extensionContainer: %w", err)
		}
		children = append(children, enc_extensioncontainer...)
	}
	for i, ext := range v.ExtData_ {
		_, n, _, extErr := ber.DecodeEncodedTLV(ext)
		if extErr != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, extErr)
		}
		if n != len(ext) {
			return nil, fmt.Errorf("encoding extension %d: %w", i, ber.ErrExtraData)
		}
		children = append(children, ext...)
	}
	return ber.EncodeSequence(children)
}

// MarshalDER encodes NoRoamingNbParam to DER format.
func (v *NoRoamingNbParam) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: NoRoamingNbParam receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding extensionContainer: %w", err)
		}
		children = append(children, enc_extensioncontainer...)
	}
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDEREncodedElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
		children = append(children, ext...)
	}
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding NoRoamingNbParam as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes NoRoamingNbParam from BER/DER format.
func (v *NoRoamingNbParam) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: NoRoamingNbParam destination is nil", ber.ErrInvalidValue)
	}
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = NoRoamingNbParam{}
	defer func() {
		if returnErr != nil || !ber.BERNeedsPreservation(opts) {
			return
		}
		var snapshotReports ber.ViolationLog
		snapshot, snapshotErr := v.marshalBER(ber.WithConstraintTolerance(&snapshotReports))
		if snapshotErr != nil {
			returnErr = snapshotErr
			return
		}
		v.berOriginal_ = append([]byte(nil), data...)
		v.berSnapshot_ = snapshot
	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("decoding NoRoamingNbParam SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "NoRoamingNbParam", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode extensionContainer
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassUniversal && peekTag.Number == 16 {
				// Decode nested SEQUENCE (ExtensionContainer)
				_, n_extensioncontainer, _, tlvErr_extensioncontainer := ber.DecodeTLV(content[offset:], opts...)
				if tlvErr_extensioncontainer != nil {
					return fmt.Errorf("decoding extensionContainer: %w", tlvErr_extensioncontainer)
				}
				var dec_extensioncontainer ExtensionContainer
				if offset > len(content) || n_extensioncontainer < 0 || n_extensioncontainer > len(
					content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				if unmErr := dec_extensioncontainer.UnmarshalBER(content[offset:offset+n_extensioncontainer], ber.ChildDecodeOptions(opts, "extensionContainer")...); unmErr != nil {
					return fmt.Errorf("decoding extensionContainer: %w", unmErr)
				}
				v.ExtensionContainer = &dec_extensioncontainer
				if offset > len(content) || n_extensioncontainer < 0 || n_extensioncontainer > len(
					content[offset:]) {
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
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:], opts...)
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "NoRoamingNbParam", Cause: extErr_}
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

// MarshalBER encodes AbsentSubscriberParam to BER format.
func (v *AbsentSubscriberParam) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: AbsentSubscriberParam receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *AbsentSubscriberParam) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalBER(ber.ChildEncodeOptions(opts, "extensionContainer")...)
		if err != nil {
			return nil, fmt.Errorf("encoding extensionContainer: %w", err)
		}
		children = append(children, enc_extensioncontainer...)
	}
	if v.AbsentSubscriberReason != nil {
		enc_absentsubscriberreason := ber.EncodeEnumerated(int64(*v.AbsentSubscriberReason))
		retagged_enc_absentsubscriberreason, tagErr_enc_absentsubscriberreason := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_absentsubscriberreason)
		if tagErr_enc_absentsubscriberreason != nil {
			return nil, fmt.Errorf("encoding absentSubscriberReason: %w", tagErr_enc_absentsubscriberreason)
		}
		enc_absentsubscriberreason = retagged_enc_absentsubscriberreason
		children = append(children, enc_absentsubscriberreason...)
	}
	for i, ext := range v.ExtData_ {
		_, n, _, extErr := ber.DecodeEncodedTLV(ext)
		if extErr != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, extErr)
		}
		if n != len(ext) {
			return nil, fmt.Errorf("encoding extension %d: %w", i, ber.ErrExtraData)
		}
		children = append(children, ext...)
	}
	return ber.EncodeSequence(children)
}

// MarshalDER encodes AbsentSubscriberParam to DER format.
func (v *AbsentSubscriberParam) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: AbsentSubscriberParam receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding extensionContainer: %w", err)
		}
		children = append(children, enc_extensioncontainer...)
	}
	if v.AbsentSubscriberReason != nil {
		enc_absentsubscriberreason := ber.EncodeEnumerated(int64(*v.AbsentSubscriberReason))
		retagged_enc_absentsubscriberreason, tagErr_enc_absentsubscriberreason := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_absentsubscriberreason)
		if tagErr_enc_absentsubscriberreason != nil {
			return nil, fmt.Errorf("encoding absentSubscriberReason: %w", tagErr_enc_absentsubscriberreason)
		}
		enc_absentsubscriberreason = retagged_enc_absentsubscriberreason
		children = append(children, enc_absentsubscriberreason...)
	}
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDEREncodedElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
		children = append(children, ext...)
	}
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding AbsentSubscriberParam as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes AbsentSubscriberParam from BER/DER format.
func (v *AbsentSubscriberParam) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: AbsentSubscriberParam destination is nil", ber.ErrInvalidValue)
	}
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = AbsentSubscriberParam{}
	defer func() {
		if returnErr != nil || !ber.BERNeedsPreservation(opts) {
			return
		}
		var snapshotReports ber.ViolationLog
		snapshot, snapshotErr := v.marshalBER(ber.WithConstraintTolerance(&snapshotReports))
		if snapshotErr != nil {
			returnErr = snapshotErr
			return
		}
		v.berOriginal_ = append([]byte(nil), data...)
		v.berSnapshot_ = snapshot
	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("decoding AbsentSubscriberParam SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "AbsentSubscriberParam", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode extensionContainer
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassUniversal && peekTag.Number == 16 {
				// Decode nested SEQUENCE (ExtensionContainer)
				_, n_extensioncontainer, _, tlvErr_extensioncontainer := ber.DecodeTLV(content[offset:], opts...)
				if tlvErr_extensioncontainer != nil {
					return fmt.Errorf("decoding extensionContainer: %w", tlvErr_extensioncontainer)
				}
				var dec_extensioncontainer ExtensionContainer
				if offset > len(content) || n_extensioncontainer < 0 || n_extensioncontainer > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				if unmErr := dec_extensioncontainer.UnmarshalBER(content[offset:offset+n_extensioncontainer], ber.ChildDecodeOptions(opts, "extensionContainer")...); unmErr != nil {
					return fmt.Errorf("decoding extensionContainer: %w", unmErr)
				}
				v.ExtensionContainer = &dec_extensioncontainer
				if offset > len(content) || n_extensioncontainer < 0 || n_extensioncontainer > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_extensioncontainer
			}
		}
	}
	// Decode absentSubscriberReason
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
				decodedTag_absentsubscriberreason, n_absentsubscriberreason, rawVal_absentsubscriberreason, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding absentSubscriberReason: %w", err)
				}
				if decodedTag_absentsubscriberreason.Class != tag.ClassContextSpecific || decodedTag_absentsubscriberreason.Number != 0 || decodedTag_absentsubscriberreason.Constructed != false {
					return fmt.Errorf("decoding absentSubscriberReason: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_absentsubscriberreason)
				}
				decVal_absentsubscriberreason, intErr := ber.DecodeEnumeratedValue(rawVal_absentsubscriberreason)
				if intErr != nil {
					return fmt.Errorf("decoding absentSubscriberReason: %w", intErr)
				}
				tmp_absentsubscriberreason := AbsentSubscriberReason(decVal_absentsubscriberreason)
				v.AbsentSubscriberReason = &tmp_absentsubscriberreason
				if offset < 0 || offset >
					len(content) || n_absentsubscriberreason < 0 || n_absentsubscriberreason >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_absentsubscriberreason
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:], opts...)
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "AbsentSubscriberParam", Cause: extErr_}
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

// MarshalBER encodes BusySubscriberParam to BER format.
func (v *BusySubscriberParam) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: BusySubscriberParam receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *BusySubscriberParam) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalBER(ber.ChildEncodeOptions(opts, "extensionContainer")...)
		if err != nil {
			return nil, fmt.Errorf("encoding extensionContainer: %w", err)
		}
		children = append(children, enc_extensioncontainer...)
	}
	if v.CcbsPossible != nil {
		enc_ccbspossible := ber.EncodeNull()
		retagged_enc_ccbspossible, tagErr_enc_ccbspossible := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_ccbspossible)
		if tagErr_enc_ccbspossible != nil {
			return nil, fmt.Errorf("encoding ccbs-Possible: %w", tagErr_enc_ccbspossible)
		}
		enc_ccbspossible = retagged_enc_ccbspossible
		children = append(children, enc_ccbspossible...)
	}
	if v.CcbsBusy != nil {
		enc_ccbsbusy := ber.EncodeNull()
		retagged_enc_ccbsbusy, tagErr_enc_ccbsbusy := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_ccbsbusy)
		if tagErr_enc_ccbsbusy != nil {
			return nil, fmt.Errorf("encoding ccbs-Busy: %w", tagErr_enc_ccbsbusy)
		}
		enc_ccbsbusy = retagged_enc_ccbsbusy
		children = append(children, enc_ccbsbusy...)
	}
	for i, ext := range v.ExtData_ {
		_, n, _, extErr := ber.DecodeEncodedTLV(ext)
		if extErr != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, extErr)
		}
		if n != len(ext) {
			return nil, fmt.Errorf("encoding extension %d: %w", i, ber.ErrExtraData)
		}
		children = append(children, ext...)
	}
	return ber.EncodeSequence(children)
}

// MarshalDER encodes BusySubscriberParam to DER format.
func (v *BusySubscriberParam) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: BusySubscriberParam receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding extensionContainer: %w", err)
		}
		children = append(children, enc_extensioncontainer...)
	}
	if v.CcbsPossible != nil {
		enc_ccbspossible := ber.EncodeNull()
		retagged_enc_ccbspossible, tagErr_enc_ccbspossible := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_ccbspossible)
		if tagErr_enc_ccbspossible != nil {
			return nil, fmt.Errorf("encoding ccbs-Possible: %w", tagErr_enc_ccbspossible)
		}
		enc_ccbspossible = retagged_enc_ccbspossible
		children = append(children, enc_ccbspossible...)
	}
	if v.CcbsBusy != nil {
		enc_ccbsbusy := ber.EncodeNull()
		retagged_enc_ccbsbusy, tagErr_enc_ccbsbusy := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_ccbsbusy)
		if tagErr_enc_ccbsbusy != nil {
			return nil, fmt.Errorf("encoding ccbs-Busy: %w", tagErr_enc_ccbsbusy)
		}
		enc_ccbsbusy = retagged_enc_ccbsbusy
		children = append(children, enc_ccbsbusy...)
	}
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDEREncodedElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
		children = append(children, ext...)
	}
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding BusySubscriberParam as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes BusySubscriberParam from BER/DER format.
func (v *BusySubscriberParam) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: BusySubscriberParam destination is nil", ber.ErrInvalidValue)
	}
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = BusySubscriberParam{}
	defer func() {
		if returnErr != nil || !ber.BERNeedsPreservation(opts) {
			return
		}
		var snapshotReports ber.ViolationLog
		snapshot, snapshotErr := v.marshalBER(ber.WithConstraintTolerance(&snapshotReports))
		if snapshotErr != nil {
			returnErr = snapshotErr
			return
		}
		v.berOriginal_ = append([]byte(nil), data...)
		v.berSnapshot_ = snapshot
	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("decoding BusySubscriberParam SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "BusySubscriberParam", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode extensionContainer
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassUniversal && peekTag.Number == 16 {
				// Decode nested SEQUENCE (ExtensionContainer)
				_, n_extensioncontainer, _, tlvErr_extensioncontainer := ber.DecodeTLV(content[offset:], opts...)
				if tlvErr_extensioncontainer != nil {
					return fmt.Errorf("decoding extensionContainer: %w", tlvErr_extensioncontainer)
				}
				var dec_extensioncontainer ExtensionContainer
				if offset > len(content) || n_extensioncontainer < 0 || n_extensioncontainer > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				if unmErr := dec_extensioncontainer.UnmarshalBER(content[offset:offset+n_extensioncontainer], ber.ChildDecodeOptions(opts, "extensionContainer")...); unmErr != nil {
					return fmt.Errorf("decoding extensionContainer: %w", unmErr)
				}
				v.ExtensionContainer = &dec_extensioncontainer
				if offset > len(content) || n_extensioncontainer < 0 || n_extensioncontainer > len(content[offset:]) {
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
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
				decodedTag_ccbspossible, n_ccbspossible, rawVal_ccbspossible, err := ber.DecodeTLV(content[offset:], opts...)
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
				if offset < 0 || offset >
					len(content) || n_ccbspossible < 0 || n_ccbspossible > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_ccbspossible
			}
		}
	}
	// Decode ccbs-Busy
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
				decodedTag_ccbsbusy, n_ccbsbusy, rawVal_ccbsbusy, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding ccbs-Busy: %w", err)
				}
				if decodedTag_ccbsbusy.Class != tag.ClassContextSpecific || decodedTag_ccbsbusy.Number != 1 || decodedTag_ccbsbusy.Constructed != false {
					return fmt.Errorf("decoding ccbs-Busy: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_ccbsbusy)
				}
				if len(rawVal_ccbsbusy) != 0 {
					return fmt.Errorf("decoding ccbs-Busy: %w: NULL content length %d", ber.ErrInvalidValue, len(rawVal_ccbsbusy))
				}
				v.CcbsBusy = &struct{}{}
				if offset < 0 || offset >
					len(content) || n_ccbsbusy < 0 || n_ccbsbusy > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_ccbsbusy
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:], opts...)
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "BusySubscriberParam", Cause: extErr_}
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

// MarshalBER encodes NoSubscriberReplyParam to BER format.
func (v *NoSubscriberReplyParam) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: NoSubscriberReplyParam receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *NoSubscriberReplyParam) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalBER(ber.ChildEncodeOptions(opts, "extensionContainer")...)
		if err != nil {
			return nil, fmt.Errorf("encoding extensionContainer: %w", err)
		}
		children = append(children, enc_extensioncontainer...)
	}
	for i, ext := range v.ExtData_ {
		_, n, _, extErr := ber.DecodeEncodedTLV(ext)
		if extErr != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, extErr)
		}
		if n != len(ext) {
			return nil, fmt.Errorf("encoding extension %d: %w", i, ber.ErrExtraData)
		}
		children = append(children, ext...)
	}
	return ber.EncodeSequence(children)
}

// MarshalDER encodes NoSubscriberReplyParam to DER format.
func (v *NoSubscriberReplyParam) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: NoSubscriberReplyParam receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding extensionContainer: %w", err)
		}
		children = append(children, enc_extensioncontainer...)
	}
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDEREncodedElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
		children = append(children, ext...)
	}
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding NoSubscriberReplyParam as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes NoSubscriberReplyParam from BER/DER format.
func (v *NoSubscriberReplyParam) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: NoSubscriberReplyParam destination is nil", ber.ErrInvalidValue)
	}
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = NoSubscriberReplyParam{}
	defer func() {
		if returnErr != nil || !ber.BERNeedsPreservation(opts) {
			return
		}
		var snapshotReports ber.ViolationLog
		snapshot, snapshotErr := v.marshalBER(ber.WithConstraintTolerance(&snapshotReports))
		if snapshotErr != nil {
			returnErr = snapshotErr
			return
		}
		v.berOriginal_ = append([]byte(nil), data...)
		v.berSnapshot_ = snapshot
	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("decoding NoSubscriberReplyParam SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "NoSubscriberReplyParam", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode extensionContainer
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassUniversal && peekTag.Number == 16 {
				// Decode nested SEQUENCE (ExtensionContainer)
				_, n_extensioncontainer, _, tlvErr_extensioncontainer := ber.DecodeTLV(content[offset:], opts...)
				if tlvErr_extensioncontainer != nil {
					return fmt.Errorf("decoding extensionContainer: %w", tlvErr_extensioncontainer)
				}
				var dec_extensioncontainer ExtensionContainer
				if offset > len(content) || n_extensioncontainer < 0 || n_extensioncontainer > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				if unmErr := dec_extensioncontainer.UnmarshalBER(content[offset:offset+n_extensioncontainer], ber.ChildDecodeOptions(opts, "extensionContainer")...); unmErr != nil {
					return fmt.Errorf("decoding extensionContainer: %w", unmErr)
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
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:], opts...)
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "NoSubscriberReplyParam", Cause: extErr_}
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

// MarshalBER encodes ForwardingViolationParam to BER format.
func (v *ForwardingViolationParam) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: ForwardingViolationParam receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *ForwardingViolationParam) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalBER(ber.ChildEncodeOptions(opts, "extensionContainer")...)
		if err != nil {
			return nil, fmt.Errorf("encoding extensionContainer: %w", err)
		}
		children = append(children, enc_extensioncontainer...)
	}
	for i, ext := range v.ExtData_ {
		_, n, _, extErr := ber.DecodeEncodedTLV(ext)
		if extErr != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, extErr)
		}
		if n != len(ext) {
			return nil, fmt.Errorf("encoding extension %d: %w", i, ber.ErrExtraData)
		}
		children = append(children, ext...)
	}
	return ber.EncodeSequence(children)
}

// MarshalDER encodes ForwardingViolationParam to DER format.
func (v *ForwardingViolationParam) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: ForwardingViolationParam receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding extensionContainer: %w", err)
		}
		children = append(children, enc_extensioncontainer...)
	}
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDEREncodedElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
		children = append(children, ext...)
	}
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding ForwardingViolationParam as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes ForwardingViolationParam from BER/DER format.
func (v *ForwardingViolationParam) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: ForwardingViolationParam destination is nil", ber.ErrInvalidValue)
	}
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = ForwardingViolationParam{}
	defer func() {
		if returnErr != nil || !ber.BERNeedsPreservation(opts) {
			return
		}
		var snapshotReports ber.ViolationLog
		snapshot, snapshotErr := v.marshalBER(ber.WithConstraintTolerance(&snapshotReports))
		if snapshotErr != nil {
			returnErr = snapshotErr
			return
		}
		v.berOriginal_ = append([]byte(nil), data...)
		v.berSnapshot_ = snapshot
	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("decoding ForwardingViolationParam SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "ForwardingViolationParam", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode extensionContainer
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassUniversal && peekTag.Number == 16 {
				// Decode nested SEQUENCE (ExtensionContainer)
				_, n_extensioncontainer, _, tlvErr_extensioncontainer := ber.DecodeTLV(content[offset:], opts...)
				if tlvErr_extensioncontainer != nil {
					return fmt.Errorf("decoding extensionContainer: %w", tlvErr_extensioncontainer)
				}
				var dec_extensioncontainer ExtensionContainer
				if offset > len(content) || n_extensioncontainer < 0 || n_extensioncontainer > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				if unmErr := dec_extensioncontainer.UnmarshalBER(content[offset:offset+n_extensioncontainer], ber.ChildDecodeOptions(opts, "extensionContainer")...); unmErr != nil {
					return fmt.Errorf("decoding extensionContainer: %w", unmErr)
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
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:], opts...)
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "ForwardingViolationParam", Cause: extErr_}
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

// MarshalBER encodes ForwardingFailedParam to BER format.
func (v *ForwardingFailedParam) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: ForwardingFailedParam receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *ForwardingFailedParam) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalBER(ber.ChildEncodeOptions(opts, "extensionContainer")...)
		if err != nil {
			return nil, fmt.Errorf("encoding extensionContainer: %w", err)
		}
		children = append(children, enc_extensioncontainer...)
	}
	for i, ext := range v.ExtData_ {
		_, n, _, extErr := ber.DecodeEncodedTLV(ext)
		if extErr != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, extErr)
		}
		if n != len(ext) {
			return nil, fmt.Errorf("encoding extension %d: %w", i, ber.ErrExtraData)
		}
		children = append(children, ext...)
	}
	return ber.EncodeSequence(children)
}

// MarshalDER encodes ForwardingFailedParam to DER format.
func (v *ForwardingFailedParam) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: ForwardingFailedParam receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding extensionContainer: %w", err)
		}
		children = append(children, enc_extensioncontainer...)
	}
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDEREncodedElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
		children = append(children, ext...)
	}
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding ForwardingFailedParam as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes ForwardingFailedParam from BER/DER format.
func (v *ForwardingFailedParam) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: ForwardingFailedParam destination is nil", ber.ErrInvalidValue)
	}
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = ForwardingFailedParam{}
	defer func() {
		if returnErr != nil || !ber.BERNeedsPreservation(opts) {
			return
		}
		var snapshotReports ber.ViolationLog
		snapshot, snapshotErr := v.marshalBER(ber.WithConstraintTolerance(&snapshotReports))
		if snapshotErr != nil {
			returnErr = snapshotErr
			return
		}
		v.berOriginal_ = append([]byte(nil), data...)
		v.berSnapshot_ = snapshot
	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("decoding ForwardingFailedParam SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "ForwardingFailedParam", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode extensionContainer
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassUniversal && peekTag.Number == 16 {
				// Decode nested SEQUENCE (ExtensionContainer)
				_, n_extensioncontainer, _, tlvErr_extensioncontainer := ber.DecodeTLV(content[offset:], opts...)
				if tlvErr_extensioncontainer != nil {
					return fmt.Errorf("decoding extensionContainer: %w", tlvErr_extensioncontainer)
				}
				var dec_extensioncontainer ExtensionContainer
				if offset > len(content) || n_extensioncontainer < 0 || n_extensioncontainer > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				if unmErr := dec_extensioncontainer.UnmarshalBER(content[offset:offset+n_extensioncontainer], ber.ChildDecodeOptions(opts, "extensionContainer")...); unmErr != nil {
					return fmt.Errorf("decoding extensionContainer: %w", unmErr)
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
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:], opts...)
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "ForwardingFailedParam", Cause: extErr_}
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

// MarshalBER encodes ATINotAllowedParam to BER format.
func (v *ATINotAllowedParam) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: ATINotAllowedParam receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *ATINotAllowedParam) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalBER(ber.ChildEncodeOptions(opts, "extensionContainer")...)
		if err != nil {
			return nil, fmt.Errorf("encoding extensionContainer: %w", err)
		}
		children = append(children, enc_extensioncontainer...)
	}
	for i, ext := range v.ExtData_ {
		_, n, _, extErr := ber.DecodeEncodedTLV(ext)
		if extErr != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, extErr)
		}
		if n != len(ext) {
			return nil, fmt.Errorf("encoding extension %d: %w", i, ber.ErrExtraData)
		}
		children = append(children, ext...)
	}
	return ber.EncodeSequence(children)
}

// MarshalDER encodes ATINotAllowedParam to DER format.
func (v *ATINotAllowedParam) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: ATINotAllowedParam receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding extensionContainer: %w", err)
		}
		children = append(children, enc_extensioncontainer...)
	}
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDEREncodedElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
		children = append(children, ext...)
	}
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding ATINotAllowedParam as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes ATINotAllowedParam from BER/DER format.
func (v *ATINotAllowedParam) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: ATINotAllowedParam destination is nil", ber.ErrInvalidValue)
	}
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = ATINotAllowedParam{}
	defer func() {
		if returnErr != nil || !ber.BERNeedsPreservation(opts) {
			return
		}
		var snapshotReports ber.ViolationLog
		snapshot, snapshotErr := v.marshalBER(ber.WithConstraintTolerance(&snapshotReports))
		if snapshotErr != nil {
			returnErr = snapshotErr
			return
		}
		v.berOriginal_ = append([]byte(nil), data...)
		v.berSnapshot_ = snapshot
	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("decoding ATINotAllowedParam SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "ATINotAllowedParam", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode extensionContainer
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassUniversal && peekTag.Number == 16 {
				// Decode nested SEQUENCE (ExtensionContainer)
				_, n_extensioncontainer, _, tlvErr_extensioncontainer := ber.DecodeTLV(content[offset:], opts...)
				if tlvErr_extensioncontainer != nil {
					return fmt.Errorf("decoding extensionContainer: %w", tlvErr_extensioncontainer)
				}
				var dec_extensioncontainer ExtensionContainer
				if offset > len(content) || n_extensioncontainer < 0 || n_extensioncontainer > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				if unmErr := dec_extensioncontainer.UnmarshalBER(content[offset:offset+n_extensioncontainer], ber.ChildDecodeOptions(opts, "extensionContainer")...); unmErr != nil {
					return fmt.Errorf("decoding extensionContainer: %w", unmErr)
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
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:], opts...)
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "ATINotAllowedParam", Cause: extErr_}
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

// MarshalBER encodes ATSINotAllowedParam to BER format.
func (v *ATSINotAllowedParam) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: ATSINotAllowedParam receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *ATSINotAllowedParam) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalBER(ber.ChildEncodeOptions(opts, "extensionContainer")...)
		if err != nil {
			return nil, fmt.Errorf("encoding extensionContainer: %w", err)
		}
		children = append(children, enc_extensioncontainer...)
	}
	for i, ext := range v.ExtData_ {
		_, n, _, extErr := ber.DecodeEncodedTLV(ext)
		if extErr != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, extErr)
		}
		if n != len(ext) {
			return nil, fmt.Errorf("encoding extension %d: %w", i, ber.ErrExtraData)
		}
		children = append(children, ext...)
	}
	return ber.EncodeSequence(children)
}

// MarshalDER encodes ATSINotAllowedParam to DER format.
func (v *ATSINotAllowedParam) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: ATSINotAllowedParam receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding extensionContainer: %w", err)
		}
		children = append(children, enc_extensioncontainer...)
	}
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDEREncodedElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
		children = append(children, ext...)
	}
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding ATSINotAllowedParam as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes ATSINotAllowedParam from BER/DER format.
func (v *ATSINotAllowedParam) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: ATSINotAllowedParam destination is nil", ber.ErrInvalidValue)
	}
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = ATSINotAllowedParam{}
	defer func() {
		if returnErr != nil || !ber.BERNeedsPreservation(opts) {
			return
		}
		var snapshotReports ber.ViolationLog
		snapshot, snapshotErr := v.marshalBER(ber.WithConstraintTolerance(&snapshotReports))
		if snapshotErr != nil {
			returnErr = snapshotErr
			return
		}
		v.berOriginal_ = append([]byte(nil), data...)
		v.berSnapshot_ = snapshot
	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("decoding ATSINotAllowedParam SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "ATSINotAllowedParam", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode extensionContainer
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassUniversal && peekTag.Number == 16 {
				// Decode nested SEQUENCE (ExtensionContainer)
				_, n_extensioncontainer, _, tlvErr_extensioncontainer := ber.DecodeTLV(content[offset:], opts...)
				if tlvErr_extensioncontainer != nil {
					return fmt.Errorf("decoding extensionContainer: %w", tlvErr_extensioncontainer)
				}
				var dec_extensioncontainer ExtensionContainer
				if offset > len(content) || n_extensioncontainer < 0 || n_extensioncontainer > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				if unmErr := dec_extensioncontainer.UnmarshalBER(content[offset:offset+n_extensioncontainer], ber.ChildDecodeOptions(opts, "extensionContainer")...); unmErr != nil {
					return fmt.Errorf("decoding extensionContainer: %w", unmErr)
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
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:], opts...)
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "ATSINotAllowedParam", Cause: extErr_}
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

// MarshalBER encodes ATMNotAllowedParam to BER format.
func (v *ATMNotAllowedParam) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: ATMNotAllowedParam receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *ATMNotAllowedParam) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalBER(ber.ChildEncodeOptions(opts, "extensionContainer")...)
		if err != nil {
			return nil, fmt.Errorf("encoding extensionContainer: %w", err)
		}
		children = append(children, enc_extensioncontainer...)
	}
	for i, ext := range v.ExtData_ {
		_, n, _, extErr := ber.DecodeEncodedTLV(ext)
		if extErr != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, extErr)
		}
		if n != len(ext) {
			return nil, fmt.Errorf("encoding extension %d: %w", i, ber.ErrExtraData)
		}
		children = append(children, ext...)
	}
	return ber.EncodeSequence(children)
}

// MarshalDER encodes ATMNotAllowedParam to DER format.
func (v *ATMNotAllowedParam) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: ATMNotAllowedParam receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding extensionContainer: %w", err)
		}
		children = append(children, enc_extensioncontainer...)
	}
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDEREncodedElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
		children = append(children, ext...)
	}
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding ATMNotAllowedParam as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes ATMNotAllowedParam from BER/DER format.
func (v *ATMNotAllowedParam) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: ATMNotAllowedParam destination is nil", ber.ErrInvalidValue)
	}
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = ATMNotAllowedParam{}
	defer func() {
		if returnErr != nil || !ber.BERNeedsPreservation(opts) {
			return
		}
		var snapshotReports ber.ViolationLog
		snapshot, snapshotErr := v.marshalBER(ber.WithConstraintTolerance(&snapshotReports))
		if snapshotErr != nil {
			returnErr = snapshotErr
			return
		}
		v.berOriginal_ = append([]byte(nil), data...)
		v.berSnapshot_ = snapshot
	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("decoding ATMNotAllowedParam SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "ATMNotAllowedParam", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode extensionContainer
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassUniversal && peekTag.Number == 16 {
				// Decode nested SEQUENCE (ExtensionContainer)
				_, n_extensioncontainer, _, tlvErr_extensioncontainer := ber.DecodeTLV(content[offset:], opts...)
				if tlvErr_extensioncontainer != nil {
					return fmt.Errorf("decoding extensionContainer: %w", tlvErr_extensioncontainer)
				}
				var dec_extensioncontainer ExtensionContainer
				if offset > len(content) || n_extensioncontainer < 0 || n_extensioncontainer > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				if unmErr := dec_extensioncontainer.UnmarshalBER(content[offset:offset+n_extensioncontainer], ber.ChildDecodeOptions(opts, "extensionContainer")...); unmErr != nil {
					return fmt.Errorf("decoding extensionContainer: %w", unmErr)
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
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:], opts...)
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "ATMNotAllowedParam", Cause: extErr_}
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

// MarshalBER encodes IllegalSSOperationParam to BER format.
func (v *IllegalSSOperationParam) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: IllegalSSOperationParam receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *IllegalSSOperationParam) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalBER(ber.ChildEncodeOptions(opts, "extensionContainer")...)
		if err != nil {
			return nil, fmt.Errorf("encoding extensionContainer: %w", err)
		}
		children = append(children, enc_extensioncontainer...)
	}
	for i, ext := range v.ExtData_ {
		_, n, _, extErr := ber.DecodeEncodedTLV(ext)
		if extErr != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, extErr)
		}
		if n != len(ext) {
			return nil, fmt.Errorf("encoding extension %d: %w", i, ber.ErrExtraData)
		}
		children = append(children, ext...)
	}
	return ber.EncodeSequence(children)
}

// MarshalDER encodes IllegalSSOperationParam to DER format.
func (v *IllegalSSOperationParam) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: IllegalSSOperationParam receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding extensionContainer: %w", err)
		}
		children = append(children, enc_extensioncontainer...)
	}
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDEREncodedElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
		children = append(children, ext...)
	}
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding IllegalSSOperationParam as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes IllegalSSOperationParam from BER/DER format.
func (v *IllegalSSOperationParam) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: IllegalSSOperationParam destination is nil", ber.ErrInvalidValue)
	}
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = IllegalSSOperationParam{}
	defer func() {
		if returnErr != nil || !ber.BERNeedsPreservation(opts) {
			return
		}
		var snapshotReports ber.ViolationLog
		snapshot, snapshotErr := v.marshalBER(ber.WithConstraintTolerance(&snapshotReports))
		if snapshotErr != nil {
			returnErr = snapshotErr
			return
		}
		v.berOriginal_ = append([]byte(nil), data...)
		v.berSnapshot_ = snapshot
	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("decoding IllegalSSOperationParam SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "IllegalSSOperationParam", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode extensionContainer
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassUniversal && peekTag.Number == 16 {
				// Decode nested SEQUENCE (ExtensionContainer)
				_, n_extensioncontainer, _, tlvErr_extensioncontainer := ber.DecodeTLV(content[offset:], opts...)
				if tlvErr_extensioncontainer != nil {
					return fmt.Errorf("decoding extensionContainer: %w", tlvErr_extensioncontainer)
				}
				var dec_extensioncontainer ExtensionContainer
				if offset > len(content) || n_extensioncontainer < 0 || n_extensioncontainer > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				if unmErr := dec_extensioncontainer.UnmarshalBER(content[offset:offset+n_extensioncontainer], ber.ChildDecodeOptions(opts, "extensionContainer")...); unmErr != nil {
					return fmt.Errorf("decoding extensionContainer: %w", unmErr)
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
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:], opts...)
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "IllegalSSOperationParam", Cause: extErr_}
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

// MarshalBER encodes SSNotAvailableParam to BER format.
func (v *SSNotAvailableParam) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: SSNotAvailableParam receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *SSNotAvailableParam) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalBER(ber.ChildEncodeOptions(opts, "extensionContainer")...)
		if err != nil {
			return nil, fmt.Errorf("encoding extensionContainer: %w", err)
		}
		children = append(children, enc_extensioncontainer...)
	}
	for i, ext := range v.ExtData_ {
		_, n, _, extErr := ber.DecodeEncodedTLV(ext)
		if extErr != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, extErr)
		}
		if n != len(ext) {
			return nil, fmt.Errorf("encoding extension %d: %w", i, ber.ErrExtraData)
		}
		children = append(children, ext...)
	}
	return ber.EncodeSequence(children)
}

// MarshalDER encodes SSNotAvailableParam to DER format.
func (v *SSNotAvailableParam) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: SSNotAvailableParam receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding extensionContainer: %w", err)
		}
		children = append(children, enc_extensioncontainer...)
	}
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDEREncodedElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
		children = append(children, ext...)
	}
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding SSNotAvailableParam as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes SSNotAvailableParam from BER/DER format.
func (v *SSNotAvailableParam) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: SSNotAvailableParam destination is nil", ber.ErrInvalidValue)
	}
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = SSNotAvailableParam{}
	defer func() {
		if returnErr != nil || !ber.BERNeedsPreservation(opts) {
			return
		}
		var snapshotReports ber.ViolationLog
		snapshot, snapshotErr := v.marshalBER(ber.WithConstraintTolerance(&snapshotReports))
		if snapshotErr != nil {
			returnErr = snapshotErr
			return
		}
		v.berOriginal_ = append([]byte(nil), data...)
		v.berSnapshot_ = snapshot
	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("decoding SSNotAvailableParam SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "SSNotAvailableParam", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode extensionContainer
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassUniversal && peekTag.Number == 16 {
				// Decode nested SEQUENCE (ExtensionContainer)
				_, n_extensioncontainer, _, tlvErr_extensioncontainer := ber.DecodeTLV(content[offset:], opts...)
				if tlvErr_extensioncontainer != nil {
					return fmt.Errorf("decoding extensionContainer: %w", tlvErr_extensioncontainer)
				}
				var dec_extensioncontainer ExtensionContainer
				if offset > len(content) || n_extensioncontainer < 0 || n_extensioncontainer > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				if unmErr := dec_extensioncontainer.UnmarshalBER(content[offset:offset+n_extensioncontainer], ber.ChildDecodeOptions(opts, "extensionContainer")...); unmErr != nil {
					return fmt.Errorf("decoding extensionContainer: %w", unmErr)
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
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:], opts...)
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "SSNotAvailableParam", Cause: extErr_}
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

// MarshalBER encodes SSSubscriptionViolationParam to BER format.
func (v *SSSubscriptionViolationParam) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: SSSubscriptionViolationParam receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *SSSubscriptionViolationParam) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalBER(ber.ChildEncodeOptions(opts, "extensionContainer")...)
		if err != nil {
			return nil, fmt.Errorf("encoding extensionContainer: %w", err)
		}
		children = append(children, enc_extensioncontainer...)
	}
	for i, ext := range v.ExtData_ {
		_, n, _, extErr := ber.DecodeEncodedTLV(ext)
		if extErr != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, extErr)
		}
		if n != len(ext) {
			return nil, fmt.Errorf("encoding extension %d: %w", i, ber.ErrExtraData)
		}
		children = append(children, ext...)
	}
	return ber.EncodeSequence(children)
}

// MarshalDER encodes SSSubscriptionViolationParam to DER format.
func (v *SSSubscriptionViolationParam) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: SSSubscriptionViolationParam receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding extensionContainer: %w", err)
		}
		children = append(children, enc_extensioncontainer...)
	}
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDEREncodedElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
		children = append(children, ext...)
	}
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding SSSubscriptionViolationParam as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes SSSubscriptionViolationParam from BER/DER format.
func (v *SSSubscriptionViolationParam) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: SSSubscriptionViolationParam destination is nil", ber.ErrInvalidValue)
	}
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = SSSubscriptionViolationParam{}
	defer func() {
		if returnErr != nil || !ber.BERNeedsPreservation(opts) {
			return
		}
		var snapshotReports ber.ViolationLog
		snapshot, snapshotErr := v.marshalBER(ber.WithConstraintTolerance(&snapshotReports))
		if snapshotErr != nil {
			returnErr = snapshotErr
			return
		}
		v.berOriginal_ = append([]byte(nil), data...)
		v.berSnapshot_ = snapshot
	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("decoding SSSubscriptionViolationParam SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "SSSubscriptionViolationParam", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode extensionContainer
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassUniversal && peekTag.Number == 16 {
				// Decode nested SEQUENCE (ExtensionContainer)
				_, n_extensioncontainer, _, tlvErr_extensioncontainer := ber.DecodeTLV(content[offset:], opts...)
				if tlvErr_extensioncontainer != nil {
					return fmt.Errorf("decoding extensionContainer: %w", tlvErr_extensioncontainer)
				}
				var dec_extensioncontainer ExtensionContainer
				if offset > len(content) || n_extensioncontainer < 0 || n_extensioncontainer > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				if unmErr := dec_extensioncontainer.UnmarshalBER(content[offset:offset+n_extensioncontainer], ber.ChildDecodeOptions(opts, "extensionContainer")...); unmErr != nil {
					return fmt.Errorf("decoding extensionContainer: %w", unmErr)
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
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:], opts...)
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "SSSubscriptionViolationParam", Cause: extErr_}
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

// MarshalBER encodes InformationNotAvailableParam to BER format.
func (v *InformationNotAvailableParam) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: InformationNotAvailableParam receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *InformationNotAvailableParam) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalBER(ber.ChildEncodeOptions(opts, "extensionContainer")...)
		if err != nil {
			return nil, fmt.Errorf("encoding extensionContainer: %w", err)
		}
		children = append(children, enc_extensioncontainer...)
	}
	for i, ext := range v.ExtData_ {
		_, n, _, extErr := ber.DecodeEncodedTLV(ext)
		if extErr != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, extErr)
		}
		if n != len(ext) {
			return nil, fmt.Errorf("encoding extension %d: %w", i, ber.ErrExtraData)
		}
		children = append(children, ext...)
	}
	return ber.EncodeSequence(children)
}

// MarshalDER encodes InformationNotAvailableParam to DER format.
func (v *InformationNotAvailableParam) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: InformationNotAvailableParam receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding extensionContainer: %w", err)
		}
		children = append(children, enc_extensioncontainer...)
	}
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDEREncodedElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
		children = append(children, ext...)
	}
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding InformationNotAvailableParam as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes InformationNotAvailableParam from BER/DER format.
func (v *InformationNotAvailableParam) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: InformationNotAvailableParam destination is nil", ber.ErrInvalidValue)
	}
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = InformationNotAvailableParam{}
	defer func() {
		if returnErr != nil || !ber.BERNeedsPreservation(opts) {
			return
		}
		var snapshotReports ber.ViolationLog
		snapshot, snapshotErr := v.marshalBER(ber.WithConstraintTolerance(&snapshotReports))
		if snapshotErr != nil {
			returnErr = snapshotErr
			return
		}
		v.berOriginal_ = append([]byte(nil), data...)
		v.berSnapshot_ = snapshot
	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("decoding InformationNotAvailableParam SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "InformationNotAvailableParam", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode extensionContainer
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassUniversal && peekTag.Number == 16 {
				// Decode nested SEQUENCE (ExtensionContainer)
				_, n_extensioncontainer, _, tlvErr_extensioncontainer := ber.DecodeTLV(content[offset:], opts...)
				if tlvErr_extensioncontainer != nil {
					return fmt.Errorf("decoding extensionContainer: %w", tlvErr_extensioncontainer)
				}
				var dec_extensioncontainer ExtensionContainer
				if offset > len(content) || n_extensioncontainer < 0 || n_extensioncontainer > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				if unmErr := dec_extensioncontainer.UnmarshalBER(content[offset:offset+n_extensioncontainer], ber.ChildDecodeOptions(opts, "extensionContainer")...); unmErr != nil {
					return fmt.Errorf("decoding extensionContainer: %w", unmErr)
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
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:], opts...)
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "InformationNotAvailableParam", Cause: extErr_}
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

// MarshalBER encodes SubBusyForMTSMSParam to BER format.
func (v *SubBusyForMTSMSParam) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: SubBusyForMTSMSParam receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *SubBusyForMTSMSParam) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalBER(ber.ChildEncodeOptions(opts, "extensionContainer")...)
		if err != nil {
			return nil, fmt.Errorf("encoding extensionContainer: %w", err)
		}
		children = append(children, enc_extensioncontainer...)
	}
	if v.GprsConnectionSuspended != nil {
		enc_gprsconnectionsuspended := ber.EncodeNull()
		children = append(children, enc_gprsconnectionsuspended...)
	}
	for i, ext := range v.ExtData_ {
		_, n, _, extErr := ber.DecodeEncodedTLV(ext)
		if extErr != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, extErr)
		}
		if n != len(ext) {
			return nil, fmt.Errorf("encoding extension %d: %w", i, ber.ErrExtraData)
		}
		children = append(children, ext...)
	}
	return ber.EncodeSequence(children)
}

// MarshalDER encodes SubBusyForMTSMSParam to DER format.
func (v *SubBusyForMTSMSParam) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: SubBusyForMTSMSParam receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding extensionContainer: %w", err)
		}
		children = append(children, enc_extensioncontainer...)
	}
	if v.GprsConnectionSuspended != nil {
		enc_gprsconnectionsuspended := ber.EncodeNull()
		children = append(children, enc_gprsconnectionsuspended...)
	}
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDEREncodedElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
		children = append(children, ext...)
	}
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding SubBusyForMTSMSParam as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes SubBusyForMTSMSParam from BER/DER format.
func (v *SubBusyForMTSMSParam) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: SubBusyForMTSMSParam destination is nil", ber.ErrInvalidValue)
	}
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = SubBusyForMTSMSParam{}
	defer func() {
		if returnErr != nil || !ber.BERNeedsPreservation(opts) {
			return
		}
		var snapshotReports ber.ViolationLog
		snapshot, snapshotErr := v.marshalBER(ber.WithConstraintTolerance(&snapshotReports))
		if snapshotErr != nil {
			returnErr = snapshotErr
			return
		}
		v.berOriginal_ = append([]byte(nil), data...)
		v.berSnapshot_ = snapshot
	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("decoding SubBusyForMTSMSParam SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "SubBusyForMTSMSParam", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode extensionContainer
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassUniversal && peekTag.Number == 16 {
				// Decode nested SEQUENCE (ExtensionContainer)
				_, n_extensioncontainer, _, tlvErr_extensioncontainer := ber.DecodeTLV(content[offset:], opts...)
				if tlvErr_extensioncontainer != nil {
					return fmt.Errorf("decoding extensionContainer: %w", tlvErr_extensioncontainer)
				}
				var dec_extensioncontainer ExtensionContainer
				if offset > len(content) || n_extensioncontainer < 0 || n_extensioncontainer > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				if unmErr := dec_extensioncontainer.UnmarshalBER(content[offset:offset+n_extensioncontainer], ber.ChildDecodeOptions(opts, "extensionContainer")...); unmErr != nil {
					return fmt.Errorf("decoding extensionContainer: %w", unmErr)
				}
				v.ExtensionContainer = &dec_extensioncontainer
				if offset > len(content) || n_extensioncontainer < 0 || n_extensioncontainer > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_extensioncontainer
			}
		}
	}
	// Decode gprsConnectionSuspended
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassUniversal && peekTag.Number == 5 {
				n, err := ber.DecodeNull(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding gprsConnectionSuspended: %w", err)
				}
				v.GprsConnectionSuspended = &struct{}{}
				if offset < 0 || offset >
					len(content) || n < 0 || n > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:], opts...)
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "SubBusyForMTSMSParam", Cause: extErr_}
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

// MarshalBER encodes MessageWaitListFullParam to BER format.
func (v *MessageWaitListFullParam) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: MessageWaitListFullParam receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *MessageWaitListFullParam) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalBER(ber.ChildEncodeOptions(opts, "extensionContainer")...)
		if err != nil {
			return nil, fmt.Errorf("encoding extensionContainer: %w", err)
		}
		children = append(children, enc_extensioncontainer...)
	}
	for i, ext := range v.ExtData_ {
		_, n, _, extErr := ber.DecodeEncodedTLV(ext)
		if extErr != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, extErr)
		}
		if n != len(ext) {
			return nil, fmt.Errorf("encoding extension %d: %w", i, ber.ErrExtraData)
		}
		children = append(children, ext...)
	}
	return ber.EncodeSequence(children)
}

// MarshalDER encodes MessageWaitListFullParam to DER format.
func (v *MessageWaitListFullParam) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: MessageWaitListFullParam receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding extensionContainer: %w", err)
		}
		children = append(children, enc_extensioncontainer...)
	}
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDEREncodedElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
		children = append(children, ext...)
	}
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding MessageWaitListFullParam as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes MessageWaitListFullParam from BER/DER format.
func (v *MessageWaitListFullParam) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: MessageWaitListFullParam destination is nil", ber.ErrInvalidValue)
	}
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = MessageWaitListFullParam{}
	defer func() {
		if returnErr != nil || !ber.BERNeedsPreservation(opts) {
			return
		}
		var snapshotReports ber.ViolationLog
		snapshot, snapshotErr := v.marshalBER(ber.WithConstraintTolerance(&snapshotReports))
		if snapshotErr != nil {
			returnErr = snapshotErr
			return
		}
		v.berOriginal_ = append([]byte(nil), data...)
		v.berSnapshot_ = snapshot
	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("decoding MessageWaitListFullParam SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "MessageWaitListFullParam", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode extensionContainer
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassUniversal && peekTag.Number == 16 {
				// Decode nested SEQUENCE (ExtensionContainer)
				_, n_extensioncontainer, _, tlvErr_extensioncontainer := ber.DecodeTLV(content[offset:], opts...)
				if tlvErr_extensioncontainer != nil {
					return fmt.Errorf("decoding extensionContainer: %w", tlvErr_extensioncontainer)
				}
				var dec_extensioncontainer ExtensionContainer
				if offset > len(content) || n_extensioncontainer < 0 || n_extensioncontainer > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				if unmErr := dec_extensioncontainer.UnmarshalBER(content[offset:offset+n_extensioncontainer], ber.ChildDecodeOptions(opts, "extensionContainer")...); unmErr != nil {
					return fmt.Errorf("decoding extensionContainer: %w", unmErr)
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
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:], opts...)
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "MessageWaitListFullParam", Cause: extErr_}
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

// MarshalBER encodes ResourceLimitationParam to BER format.
func (v *ResourceLimitationParam) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: ResourceLimitationParam receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *ResourceLimitationParam) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalBER(ber.ChildEncodeOptions(opts, "extensionContainer")...)
		if err != nil {
			return nil, fmt.Errorf("encoding extensionContainer: %w", err)
		}
		children = append(children, enc_extensioncontainer...)
	}
	for i, ext := range v.ExtData_ {
		_, n, _, extErr := ber.DecodeEncodedTLV(ext)
		if extErr != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, extErr)
		}
		if n != len(ext) {
			return nil, fmt.Errorf("encoding extension %d: %w", i, ber.ErrExtraData)
		}
		children = append(children, ext...)
	}
	return ber.EncodeSequence(children)
}

// MarshalDER encodes ResourceLimitationParam to DER format.
func (v *ResourceLimitationParam) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: ResourceLimitationParam receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding extensionContainer: %w", err)
		}
		children = append(children, enc_extensioncontainer...)
	}
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDEREncodedElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
		children = append(children, ext...)
	}
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding ResourceLimitationParam as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes ResourceLimitationParam from BER/DER format.
func (v *ResourceLimitationParam) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: ResourceLimitationParam destination is nil", ber.ErrInvalidValue)
	}
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = ResourceLimitationParam{}
	defer func() {
		if returnErr != nil || !ber.BERNeedsPreservation(opts) {
			return
		}
		var snapshotReports ber.ViolationLog
		snapshot, snapshotErr := v.marshalBER(ber.WithConstraintTolerance(&snapshotReports))
		if snapshotErr != nil {
			returnErr = snapshotErr
			return
		}
		v.berOriginal_ = append([]byte(nil), data...)
		v.berSnapshot_ = snapshot
	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("decoding ResourceLimitationParam SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "ResourceLimitationParam", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode extensionContainer
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassUniversal && peekTag.Number == 16 {
				// Decode nested SEQUENCE (ExtensionContainer)
				_, n_extensioncontainer, _, tlvErr_extensioncontainer := ber.DecodeTLV(content[offset:], opts...)
				if tlvErr_extensioncontainer != nil {
					return fmt.Errorf("decoding extensionContainer: %w", tlvErr_extensioncontainer)
				}
				var dec_extensioncontainer ExtensionContainer
				if offset > len(content) || n_extensioncontainer < 0 || n_extensioncontainer > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				if unmErr := dec_extensioncontainer.UnmarshalBER(content[offset:offset+n_extensioncontainer], ber.ChildDecodeOptions(opts, "extensionContainer")...); unmErr != nil {
					return fmt.Errorf("decoding extensionContainer: %w", unmErr)
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
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:], opts...)
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "ResourceLimitationParam", Cause: extErr_}
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

// MarshalBER encodes NoGroupCallNbParam to BER format.
func (v *NoGroupCallNbParam) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: NoGroupCallNbParam receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *NoGroupCallNbParam) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalBER(ber.ChildEncodeOptions(opts, "extensionContainer")...)
		if err != nil {
			return nil, fmt.Errorf("encoding extensionContainer: %w", err)
		}
		children = append(children, enc_extensioncontainer...)
	}
	for i, ext := range v.ExtData_ {
		_, n, _, extErr := ber.DecodeEncodedTLV(ext)
		if extErr != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, extErr)
		}
		if n != len(ext) {
			return nil, fmt.Errorf("encoding extension %d: %w", i, ber.ErrExtraData)
		}
		children = append(children, ext...)
	}
	return ber.EncodeSequence(children)
}

// MarshalDER encodes NoGroupCallNbParam to DER format.
func (v *NoGroupCallNbParam) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: NoGroupCallNbParam receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding extensionContainer: %w", err)
		}
		children = append(children, enc_extensioncontainer...)
	}
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDEREncodedElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
		children = append(children, ext...)
	}
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding NoGroupCallNbParam as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes NoGroupCallNbParam from BER/DER format.
func (v *NoGroupCallNbParam) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: NoGroupCallNbParam destination is nil", ber.ErrInvalidValue)
	}
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = NoGroupCallNbParam{}
	defer func() {
		if returnErr != nil || !ber.BERNeedsPreservation(opts) {
			return
		}
		var snapshotReports ber.ViolationLog
		snapshot, snapshotErr := v.marshalBER(ber.WithConstraintTolerance(&snapshotReports))
		if snapshotErr != nil {
			returnErr = snapshotErr
			return
		}
		v.berOriginal_ = append([]byte(nil), data...)
		v.berSnapshot_ = snapshot
	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("decoding NoGroupCallNbParam SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "NoGroupCallNbParam", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode extensionContainer
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassUniversal && peekTag.Number == 16 {
				// Decode nested SEQUENCE (ExtensionContainer)
				_, n_extensioncontainer, _, tlvErr_extensioncontainer := ber.DecodeTLV(content[offset:], opts...)
				if tlvErr_extensioncontainer != nil {
					return fmt.Errorf("decoding extensionContainer: %w", tlvErr_extensioncontainer)
				}
				var dec_extensioncontainer ExtensionContainer
				if offset > len(content) || n_extensioncontainer < 0 || n_extensioncontainer > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				if unmErr := dec_extensioncontainer.UnmarshalBER(content[offset:offset+n_extensioncontainer], ber.ChildDecodeOptions(opts, "extensionContainer")...); unmErr != nil {
					return fmt.Errorf("decoding extensionContainer: %w", unmErr)
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
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:], opts...)
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "NoGroupCallNbParam", Cause: extErr_}
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

// MarshalBER encodes IncompatibleTerminalParam to BER format.
func (v *IncompatibleTerminalParam) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: IncompatibleTerminalParam receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *IncompatibleTerminalParam) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalBER(ber.ChildEncodeOptions(opts, "extensionContainer")...)
		if err != nil {
			return nil, fmt.Errorf("encoding extensionContainer: %w", err)
		}
		children = append(children, enc_extensioncontainer...)
	}
	for i, ext := range v.ExtData_ {
		_, n, _, extErr := ber.DecodeEncodedTLV(ext)
		if extErr != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, extErr)
		}
		if n != len(ext) {
			return nil, fmt.Errorf("encoding extension %d: %w", i, ber.ErrExtraData)
		}
		children = append(children, ext...)
	}
	return ber.EncodeSequence(children)
}

// MarshalDER encodes IncompatibleTerminalParam to DER format.
func (v *IncompatibleTerminalParam) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: IncompatibleTerminalParam receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding extensionContainer: %w", err)
		}
		children = append(children, enc_extensioncontainer...)
	}
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDEREncodedElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
		children = append(children, ext...)
	}
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding IncompatibleTerminalParam as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes IncompatibleTerminalParam from BER/DER format.
func (v *IncompatibleTerminalParam) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: IncompatibleTerminalParam destination is nil", ber.ErrInvalidValue)
	}
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = IncompatibleTerminalParam{}
	defer func() {
		if returnErr != nil || !ber.BERNeedsPreservation(opts) {
			return
		}
		var snapshotReports ber.ViolationLog
		snapshot, snapshotErr := v.marshalBER(ber.WithConstraintTolerance(&snapshotReports))
		if snapshotErr != nil {
			returnErr = snapshotErr
			return
		}
		v.berOriginal_ = append([]byte(nil), data...)
		v.berSnapshot_ = snapshot
	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("decoding IncompatibleTerminalParam SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "IncompatibleTerminalParam", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode extensionContainer
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassUniversal && peekTag.Number == 16 {
				// Decode nested SEQUENCE (ExtensionContainer)
				_, n_extensioncontainer, _, tlvErr_extensioncontainer := ber.DecodeTLV(content[offset:], opts...)
				if tlvErr_extensioncontainer != nil {
					return fmt.Errorf("decoding extensionContainer: %w", tlvErr_extensioncontainer)
				}
				var dec_extensioncontainer ExtensionContainer
				if offset > len(content) || n_extensioncontainer < 0 || n_extensioncontainer > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				if unmErr := dec_extensioncontainer.UnmarshalBER(content[offset:offset+n_extensioncontainer], ber.ChildDecodeOptions(opts, "extensionContainer")...); unmErr != nil {
					return fmt.Errorf("decoding extensionContainer: %w", unmErr)
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
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:], opts...)
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "IncompatibleTerminalParam", Cause: extErr_}
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

// MarshalBER encodes ShortTermDenialParam to BER format.
func (v *ShortTermDenialParam) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: ShortTermDenialParam receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *ShortTermDenialParam) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	for i, ext := range v.ExtData_ {
		_, n, _, extErr := ber.DecodeEncodedTLV(ext)
		if extErr != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, extErr)
		}
		if n != len(ext) {
			return nil, fmt.Errorf("encoding extension %d: %w", i, ber.ErrExtraData)
		}
		children = append(children, ext...)
	}
	return ber.EncodeSequence(children)
}

// MarshalDER encodes ShortTermDenialParam to DER format.
func (v *ShortTermDenialParam) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: ShortTermDenialParam receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDEREncodedElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
		children = append(children, ext...)
	}
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding ShortTermDenialParam as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes ShortTermDenialParam from BER/DER format.
func (v *ShortTermDenialParam) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: ShortTermDenialParam destination is nil", ber.ErrInvalidValue)
	}
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = ShortTermDenialParam{}
	defer func() {
		if returnErr != nil || !ber.BERNeedsPreservation(opts) {
			return
		}
		var snapshotReports ber.ViolationLog
		snapshot, snapshotErr := v.marshalBER(ber.WithConstraintTolerance(&snapshotReports))
		if snapshotErr != nil {
			returnErr = snapshotErr
			return
		}
		v.berOriginal_ = append([]byte(nil), data...)
		v.berSnapshot_ = snapshot
	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("decoding ShortTermDenialParam SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "ShortTermDenialParam", Cause: ber.ErrExtraData}
	}
	offset := 0
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:], opts...)
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "ShortTermDenialParam", Cause: extErr_}
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

// MarshalBER encodes LongTermDenialParam to BER format.
func (v *LongTermDenialParam) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: LongTermDenialParam receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *LongTermDenialParam) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	for i, ext := range v.ExtData_ {
		_, n, _, extErr := ber.DecodeEncodedTLV(ext)
		if extErr != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, extErr)
		}
		if n != len(ext) {
			return nil, fmt.Errorf("encoding extension %d: %w", i, ber.ErrExtraData)
		}
		children = append(children, ext...)
	}
	return ber.EncodeSequence(children)
}

// MarshalDER encodes LongTermDenialParam to DER format.
func (v *LongTermDenialParam) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: LongTermDenialParam receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDEREncodedElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
		children = append(children, ext...)
	}
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding LongTermDenialParam as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes LongTermDenialParam from BER/DER format.
func (v *LongTermDenialParam) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: LongTermDenialParam destination is nil", ber.ErrInvalidValue)
	}
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = LongTermDenialParam{}
	defer func() {
		if returnErr != nil || !ber.BERNeedsPreservation(opts) {
			return
		}
		var snapshotReports ber.ViolationLog
		snapshot, snapshotErr := v.marshalBER(ber.WithConstraintTolerance(&snapshotReports))
		if snapshotErr != nil {
			returnErr = snapshotErr
			return
		}
		v.berOriginal_ = append([]byte(nil), data...)
		v.berSnapshot_ = snapshot
	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("decoding LongTermDenialParam SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "LongTermDenialParam", Cause: ber.ErrExtraData}
	}
	offset := 0
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:], opts...)
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "LongTermDenialParam", Cause: extErr_}
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

// MarshalBER encodes UnauthorizedRequestingNetworkParam to BER format.
func (v *UnauthorizedRequestingNetworkParam) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: UnauthorizedRequestingNetworkParam receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *UnauthorizedRequestingNetworkParam) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalBER(ber.ChildEncodeOptions(opts, "extensionContainer")...)
		if err != nil {
			return nil, fmt.Errorf("encoding extensionContainer: %w", err)
		}
		children = append(children, enc_extensioncontainer...)
	}
	for i, ext := range v.ExtData_ {
		_, n, _, extErr := ber.DecodeEncodedTLV(ext)
		if extErr != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, extErr)
		}
		if n != len(ext) {
			return nil, fmt.Errorf("encoding extension %d: %w", i, ber.ErrExtraData)
		}
		children = append(children, ext...)
	}
	return ber.EncodeSequence(children)
}

// MarshalDER encodes UnauthorizedRequestingNetworkParam to DER format.
func (v *UnauthorizedRequestingNetworkParam) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: UnauthorizedRequestingNetworkParam receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding extensionContainer: %w", err)
		}
		children = append(children, enc_extensioncontainer...)
	}
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDEREncodedElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
		children = append(children, ext...)
	}
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding UnauthorizedRequestingNetworkParam as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes UnauthorizedRequestingNetworkParam from BER/DER format.
func (v *UnauthorizedRequestingNetworkParam) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: UnauthorizedRequestingNetworkParam destination is nil", ber.ErrInvalidValue)
	}
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = UnauthorizedRequestingNetworkParam{}
	defer func() {
		if returnErr != nil || !ber.BERNeedsPreservation(opts) {
			return
		}
		var snapshotReports ber.ViolationLog
		snapshot, snapshotErr := v.marshalBER(ber.WithConstraintTolerance(&snapshotReports))
		if snapshotErr != nil {
			returnErr = snapshotErr
			return
		}
		v.berOriginal_ = append([]byte(nil), data...)
		v.berSnapshot_ = snapshot
	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("decoding UnauthorizedRequestingNetworkParam SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "UnauthorizedRequestingNetworkParam", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode extensionContainer
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassUniversal && peekTag.Number == 16 {
				// Decode nested SEQUENCE (ExtensionContainer)
				_, n_extensioncontainer, _, tlvErr_extensioncontainer := ber.DecodeTLV(content[offset:], opts...)
				if tlvErr_extensioncontainer != nil {
					return fmt.Errorf("decoding extensionContainer: %w", tlvErr_extensioncontainer)
				}
				var dec_extensioncontainer ExtensionContainer
				if offset > len(content) || n_extensioncontainer < 0 || n_extensioncontainer > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				if unmErr := dec_extensioncontainer.UnmarshalBER(content[offset:offset+n_extensioncontainer], ber.ChildDecodeOptions(opts, "extensionContainer")...); unmErr != nil {
					return fmt.Errorf("decoding extensionContainer: %w", unmErr)
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
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:], opts...)
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "UnauthorizedRequestingNetworkParam", Cause: extErr_}
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

// MarshalBER encodes UnauthorizedLCSClientParam to BER format.
func (v *UnauthorizedLCSClientParam) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: UnauthorizedLCSClientParam receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *UnauthorizedLCSClientParam) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if v.UnauthorizedLCSClientDiagnostic != nil {
		enc_unauthorizedlcsclientdiagnostic := ber.EncodeEnumerated(int64(*v.UnauthorizedLCSClientDiagnostic))
		retagged_enc_unauthorizedlcsclientdiagnostic, tagErr_enc_unauthorizedlcsclientdiagnostic := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_unauthorizedlcsclientdiagnostic)
		if tagErr_enc_unauthorizedlcsclientdiagnostic != nil {
			return nil, fmt.Errorf("encoding unauthorizedLCSClient-Diagnostic: %w", tagErr_enc_unauthorizedlcsclientdiagnostic)
		}
		enc_unauthorizedlcsclientdiagnostic = retagged_enc_unauthorizedlcsclientdiagnostic
		children = append(children, enc_unauthorizedlcsclientdiagnostic...)
	}
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalBER(ber.ChildEncodeOptions(opts, "extensionContainer")...)
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
		_, n, _, extErr := ber.DecodeEncodedTLV(ext)
		if extErr != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, extErr)
		}
		if n != len(ext) {
			return nil, fmt.Errorf("encoding extension %d: %w", i, ber.ErrExtraData)
		}
		children = append(children, ext...)
	}
	return ber.EncodeSequence(children)
}

// MarshalDER encodes UnauthorizedLCSClientParam to DER format.
func (v *UnauthorizedLCSClientParam) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: UnauthorizedLCSClientParam receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if v.UnauthorizedLCSClientDiagnostic != nil {
		enc_unauthorizedlcsclientdiagnostic := ber.EncodeEnumerated(int64(*v.UnauthorizedLCSClientDiagnostic))
		retagged_enc_unauthorizedlcsclientdiagnostic, tagErr_enc_unauthorizedlcsclientdiagnostic := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_unauthorizedlcsclientdiagnostic)
		if tagErr_enc_unauthorizedlcsclientdiagnostic != nil {
			return nil, fmt.Errorf("encoding unauthorizedLCSClient-Diagnostic: %w", tagErr_enc_unauthorizedlcsclientdiagnostic)
		}
		enc_unauthorizedlcsclientdiagnostic = retagged_enc_unauthorizedlcsclientdiagnostic
		children = append(children, enc_unauthorizedlcsclientdiagnostic...)
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
		if err := ber.ValidateDEREncodedElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
		children = append(children, ext...)
	}
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding UnauthorizedLCSClientParam as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes UnauthorizedLCSClientParam from BER/DER format.
func (v *UnauthorizedLCSClientParam) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: UnauthorizedLCSClientParam destination is nil", ber.ErrInvalidValue)
	}
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = UnauthorizedLCSClientParam{}
	defer func() {
		if returnErr != nil || !ber.BERNeedsPreservation(opts) {
			return
		}
		var snapshotReports ber.ViolationLog
		snapshot, snapshotErr := v.marshalBER(ber.WithConstraintTolerance(&snapshotReports))
		if snapshotErr != nil {
			returnErr = snapshotErr
			return
		}
		v.berOriginal_ = append([]byte(nil), data...)
		v.berSnapshot_ = snapshot
	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("decoding UnauthorizedLCSClientParam SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "UnauthorizedLCSClientParam", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode unauthorizedLCSClient-Diagnostic
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
				decodedTag_unauthorizedlcsclientdiagnostic, n_unauthorizedlcsclientdiagnostic, rawVal_unauthorizedlcsclientdiagnostic, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding unauthorizedLCSClient-Diagnostic: %w", err)
				}
				if decodedTag_unauthorizedlcsclientdiagnostic.Class != tag.ClassContextSpecific || decodedTag_unauthorizedlcsclientdiagnostic.Number != 0 || decodedTag_unauthorizedlcsclientdiagnostic.Constructed != false {
					return fmt.Errorf("decoding unauthorizedLCSClient-Diagnostic: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_unauthorizedlcsclientdiagnostic)
				}
				decVal_unauthorizedlcsclientdiagnostic, intErr := ber.DecodeEnumeratedValue(rawVal_unauthorizedlcsclientdiagnostic)
				if intErr != nil {
					return fmt.Errorf("decoding unauthorizedLCSClient-Diagnostic: %w", intErr)
				}
				tmp_unauthorizedlcsclientdiagnostic := UnauthorizedLCSClientDiagnostic(decVal_unauthorizedlcsclientdiagnostic)
				v.UnauthorizedLCSClientDiagnostic = &tmp_unauthorizedlcsclientdiagnostic
				if offset > len(content) || n_unauthorizedlcsclientdiagnostic < 0 || n_unauthorizedlcsclientdiagnostic >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_unauthorizedlcsclientdiagnostic
			}
		}
	}
	// Decode extensionContainer
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
				decodedTag_extensioncontainer, n_extensioncontainer, rawVal_extensioncontainer, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding extensionContainer: %w", err)
				}
				if decodedTag_extensioncontainer.Class != tag.ClassContextSpecific || decodedTag_extensioncontainer.Number != 1 || decodedTag_extensioncontainer.Constructed != true {
					return fmt.Errorf("decoding extensionContainer: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_extensioncontainer)
				}
				reconstructed_extensioncontainer, reconstructionErr_extensioncontainer := ber.EncodeSequence(rawVal_extensioncontainer)
				if reconstructionErr_extensioncontainer != nil {
					return fmt.Errorf("decoding extensionContainer: %w", reconstructionErr_extensioncontainer)
				}
				var dec_extensioncontainer ExtensionContainer
				if unmErr := dec_extensioncontainer.UnmarshalBER(reconstructed_extensioncontainer, ber.ChildDecodeOptions(opts, "extensionContainer")...); unmErr != nil {
					return fmt.Errorf("decoding extensionContainer: %w", unmErr)
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
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:], opts...)
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "UnauthorizedLCSClientParam", Cause: extErr_}
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

// MarshalBER encodes PositionMethodFailureParam to BER format.
func (v *PositionMethodFailureParam) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: PositionMethodFailureParam receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *PositionMethodFailureParam) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if v.PositionMethodFailureDiagnostic != nil {
		enc_positionmethodfailurediagnostic := ber.EncodeEnumerated(int64(*v.PositionMethodFailureDiagnostic))
		retagged_enc_positionmethodfailurediagnostic, tagErr_enc_positionmethodfailurediagnostic := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_positionmethodfailurediagnostic)
		if tagErr_enc_positionmethodfailurediagnostic != nil {
			return nil, fmt.Errorf("encoding positionMethodFailure-Diagnostic: %w", tagErr_enc_positionmethodfailurediagnostic)
		}
		enc_positionmethodfailurediagnostic = retagged_enc_positionmethodfailurediagnostic
		children = append(children, enc_positionmethodfailurediagnostic...)
	}
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalBER(ber.ChildEncodeOptions(opts, "extensionContainer")...)
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
		_, n, _, extErr := ber.DecodeEncodedTLV(ext)
		if extErr != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, extErr)
		}
		if n != len(ext) {
			return nil, fmt.Errorf("encoding extension %d: %w", i, ber.ErrExtraData)
		}
		children = append(children, ext...)
	}
	return ber.EncodeSequence(children)
}

// MarshalDER encodes PositionMethodFailureParam to DER format.
func (v *PositionMethodFailureParam) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: PositionMethodFailureParam receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if v.PositionMethodFailureDiagnostic != nil {
		enc_positionmethodfailurediagnostic := ber.EncodeEnumerated(int64(*v.PositionMethodFailureDiagnostic))
		retagged_enc_positionmethodfailurediagnostic, tagErr_enc_positionmethodfailurediagnostic := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_positionmethodfailurediagnostic)
		if tagErr_enc_positionmethodfailurediagnostic != nil {
			return nil, fmt.Errorf("encoding positionMethodFailure-Diagnostic: %w", tagErr_enc_positionmethodfailurediagnostic)
		}
		enc_positionmethodfailurediagnostic = retagged_enc_positionmethodfailurediagnostic
		children = append(children, enc_positionmethodfailurediagnostic...)
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
		if err := ber.ValidateDEREncodedElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
		children = append(children, ext...)
	}
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding PositionMethodFailureParam as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes PositionMethodFailureParam from BER/DER format.
func (v *PositionMethodFailureParam) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: PositionMethodFailureParam destination is nil", ber.ErrInvalidValue)
	}
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = PositionMethodFailureParam{}
	defer func() {
		if returnErr != nil || !ber.BERNeedsPreservation(opts) {
			return
		}
		var snapshotReports ber.ViolationLog
		snapshot, snapshotErr := v.marshalBER(ber.WithConstraintTolerance(&snapshotReports))
		if snapshotErr != nil {
			returnErr = snapshotErr
			return
		}
		v.berOriginal_ = append([]byte(nil), data...)
		v.berSnapshot_ = snapshot
	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("decoding PositionMethodFailureParam SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "PositionMethodFailureParam", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode positionMethodFailure-Diagnostic
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
				decodedTag_positionmethodfailurediagnostic, n_positionmethodfailurediagnostic, rawVal_positionmethodfailurediagnostic, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding positionMethodFailure-Diagnostic: %w", err)
				}
				if decodedTag_positionmethodfailurediagnostic.Class != tag.ClassContextSpecific || decodedTag_positionmethodfailurediagnostic.Number != 0 || decodedTag_positionmethodfailurediagnostic.Constructed != false {
					return fmt.Errorf("decoding positionMethodFailure-Diagnostic: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_positionmethodfailurediagnostic)
				}
				decVal_positionmethodfailurediagnostic, intErr := ber.DecodeEnumeratedValue(rawVal_positionmethodfailurediagnostic)
				if intErr != nil {
					return fmt.Errorf("decoding positionMethodFailure-Diagnostic: %w", intErr)
				}
				tmp_positionmethodfailurediagnostic := PositionMethodFailureDiagnostic(decVal_positionmethodfailurediagnostic)
				v.PositionMethodFailureDiagnostic = &tmp_positionmethodfailurediagnostic
				if offset > len(content) || n_positionmethodfailurediagnostic < 0 || n_positionmethodfailurediagnostic >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_positionmethodfailurediagnostic
			}
		}
	}
	// Decode extensionContainer
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
				decodedTag_extensioncontainer, n_extensioncontainer, rawVal_extensioncontainer, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding extensionContainer: %w", err)
				}
				if decodedTag_extensioncontainer.Class != tag.ClassContextSpecific || decodedTag_extensioncontainer.Number != 1 || decodedTag_extensioncontainer.Constructed != true {
					return fmt.Errorf("decoding extensionContainer: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_extensioncontainer)
				}
				reconstructed_extensioncontainer, reconstructionErr_extensioncontainer := ber.EncodeSequence(rawVal_extensioncontainer)
				if reconstructionErr_extensioncontainer != nil {
					return fmt.Errorf("decoding extensionContainer: %w", reconstructionErr_extensioncontainer)
				}
				var dec_extensioncontainer ExtensionContainer
				if unmErr := dec_extensioncontainer.UnmarshalBER(reconstructed_extensioncontainer, ber.ChildDecodeOptions(opts, "extensionContainer")...); unmErr != nil {
					return fmt.Errorf("decoding extensionContainer: %w", unmErr)
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
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:], opts...)
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "PositionMethodFailureParam", Cause: extErr_}
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

// MarshalBER encodes UnknownOrUnreachableLCSClientParam to BER format.
func (v *UnknownOrUnreachableLCSClientParam) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: UnknownOrUnreachableLCSClientParam receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *UnknownOrUnreachableLCSClientParam) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalBER(ber.ChildEncodeOptions(opts, "extensionContainer")...)
		if err != nil {
			return nil, fmt.Errorf("encoding extensionContainer: %w", err)
		}
		children = append(children, enc_extensioncontainer...)
	}
	for i, ext := range v.ExtData_ {
		_, n, _, extErr := ber.DecodeEncodedTLV(ext)
		if extErr != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, extErr)
		}
		if n != len(ext) {
			return nil, fmt.Errorf("encoding extension %d: %w", i, ber.ErrExtraData)
		}
		children = append(children, ext...)
	}
	return ber.EncodeSequence(children)
}

// MarshalDER encodes UnknownOrUnreachableLCSClientParam to DER format.
func (v *UnknownOrUnreachableLCSClientParam) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: UnknownOrUnreachableLCSClientParam receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding extensionContainer: %w", err)
		}
		children = append(children, enc_extensioncontainer...)
	}
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDEREncodedElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
		children = append(children, ext...)
	}
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding UnknownOrUnreachableLCSClientParam as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes UnknownOrUnreachableLCSClientParam from BER/DER format.
func (v *UnknownOrUnreachableLCSClientParam) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: UnknownOrUnreachableLCSClientParam destination is nil", ber.ErrInvalidValue)
	}
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = UnknownOrUnreachableLCSClientParam{}
	defer func() {
		if returnErr != nil || !ber.BERNeedsPreservation(opts) {
			return
		}
		var snapshotReports ber.ViolationLog
		snapshot, snapshotErr := v.marshalBER(ber.WithConstraintTolerance(&snapshotReports))
		if snapshotErr != nil {
			returnErr = snapshotErr
			return
		}
		v.berOriginal_ = append([]byte(nil), data...)
		v.berSnapshot_ = snapshot
	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("decoding UnknownOrUnreachableLCSClientParam SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "UnknownOrUnreachableLCSClientParam", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode extensionContainer
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassUniversal && peekTag.Number == 16 {
				// Decode nested SEQUENCE (ExtensionContainer)
				_, n_extensioncontainer, _, tlvErr_extensioncontainer := ber.DecodeTLV(content[offset:], opts...)
				if tlvErr_extensioncontainer != nil {
					return fmt.Errorf("decoding extensionContainer: %w", tlvErr_extensioncontainer)
				}
				var dec_extensioncontainer ExtensionContainer
				if offset > len(content) || n_extensioncontainer < 0 || n_extensioncontainer > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				if unmErr := dec_extensioncontainer.UnmarshalBER(content[offset:offset+n_extensioncontainer], ber.ChildDecodeOptions(opts, "extensionContainer")...); unmErr != nil {
					return fmt.Errorf("decoding extensionContainer: %w", unmErr)
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
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:], opts...)
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "UnknownOrUnreachableLCSClientParam", Cause: extErr_}
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

// MarshalBER encodes MMEventNotSupportedParam to BER format.
func (v *MMEventNotSupportedParam) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: MMEventNotSupportedParam receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *MMEventNotSupportedParam) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalBER(ber.ChildEncodeOptions(opts, "extensionContainer")...)
		if err != nil {
			return nil, fmt.Errorf("encoding extensionContainer: %w", err)
		}
		children = append(children, enc_extensioncontainer...)
	}
	for i, ext := range v.ExtData_ {
		_, n, _, extErr := ber.DecodeEncodedTLV(ext)
		if extErr != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, extErr)
		}
		if n != len(ext) {
			return nil, fmt.Errorf("encoding extension %d: %w", i, ber.ErrExtraData)
		}
		children = append(children, ext...)
	}
	return ber.EncodeSequence(children)
}

// MarshalDER encodes MMEventNotSupportedParam to DER format.
func (v *MMEventNotSupportedParam) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: MMEventNotSupportedParam receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding extensionContainer: %w", err)
		}
		children = append(children, enc_extensioncontainer...)
	}
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDEREncodedElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
		children = append(children, ext...)
	}
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding MMEventNotSupportedParam as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes MMEventNotSupportedParam from BER/DER format.
func (v *MMEventNotSupportedParam) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: MMEventNotSupportedParam destination is nil", ber.ErrInvalidValue)
	}
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = MMEventNotSupportedParam{}
	defer func() {
		if returnErr != nil || !ber.BERNeedsPreservation(opts) {
			return
		}
		var snapshotReports ber.ViolationLog
		snapshot, snapshotErr := v.marshalBER(ber.WithConstraintTolerance(&snapshotReports))
		if snapshotErr != nil {
			returnErr = snapshotErr
			return
		}
		v.berOriginal_ = append([]byte(nil), data...)
		v.berSnapshot_ = snapshot
	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("decoding MMEventNotSupportedParam SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "MMEventNotSupportedParam", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode extensionContainer
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassUniversal && peekTag.Number == 16 {
				// Decode nested SEQUENCE (ExtensionContainer)
				_, n_extensioncontainer, _, tlvErr_extensioncontainer := ber.DecodeTLV(content[offset:], opts...)
				if tlvErr_extensioncontainer != nil {
					return fmt.Errorf("decoding extensionContainer: %w", tlvErr_extensioncontainer)
				}
				var dec_extensioncontainer ExtensionContainer
				if offset > len(content) || n_extensioncontainer < 0 || n_extensioncontainer > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				if unmErr := dec_extensioncontainer.UnmarshalBER(content[offset:offset+n_extensioncontainer], ber.ChildDecodeOptions(opts, "extensionContainer")...); unmErr != nil {
					return fmt.Errorf("decoding extensionContainer: %w", unmErr)
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
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:], opts...)
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "MMEventNotSupportedParam", Cause: extErr_}
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

// MarshalBER encodes TargetCellOutsideGCAParam to BER format.
func (v *TargetCellOutsideGCAParam) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: TargetCellOutsideGCAParam receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *TargetCellOutsideGCAParam) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalBER(ber.ChildEncodeOptions(opts, "extensionContainer")...)
		if err != nil {
			return nil, fmt.Errorf("encoding extensionContainer: %w", err)
		}
		children = append(children, enc_extensioncontainer...)
	}
	for i, ext := range v.ExtData_ {
		_, n, _, extErr := ber.DecodeEncodedTLV(ext)
		if extErr != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, extErr)
		}
		if n != len(ext) {
			return nil, fmt.Errorf("encoding extension %d: %w", i, ber.ErrExtraData)
		}
		children = append(children, ext...)
	}
	return ber.EncodeSequence(children)
}

// MarshalDER encodes TargetCellOutsideGCAParam to DER format.
func (v *TargetCellOutsideGCAParam) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: TargetCellOutsideGCAParam receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding extensionContainer: %w", err)
		}
		children = append(children, enc_extensioncontainer...)
	}
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDEREncodedElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
		children = append(children, ext...)
	}
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding TargetCellOutsideGCAParam as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes TargetCellOutsideGCAParam from BER/DER format.
func (v *TargetCellOutsideGCAParam) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: TargetCellOutsideGCAParam destination is nil", ber.ErrInvalidValue)
	}
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = TargetCellOutsideGCAParam{}
	defer func() {
		if returnErr != nil || !ber.BERNeedsPreservation(opts) {
			return
		}
		var snapshotReports ber.ViolationLog
		snapshot, snapshotErr := v.marshalBER(ber.WithConstraintTolerance(&snapshotReports))
		if snapshotErr != nil {
			returnErr = snapshotErr
			return
		}
		v.berOriginal_ = append([]byte(nil), data...)
		v.berSnapshot_ = snapshot
	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("decoding TargetCellOutsideGCAParam SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "TargetCellOutsideGCAParam", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode extensionContainer
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassUniversal && peekTag.Number == 16 {
				// Decode nested SEQUENCE (ExtensionContainer)
				_, n_extensioncontainer, _, tlvErr_extensioncontainer := ber.DecodeTLV(content[offset:], opts...)
				if tlvErr_extensioncontainer != nil {
					return fmt.Errorf("decoding extensionContainer: %w", tlvErr_extensioncontainer)
				}
				var dec_extensioncontainer ExtensionContainer
				if offset > len(content) || n_extensioncontainer < 0 || n_extensioncontainer > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				if unmErr := dec_extensioncontainer.UnmarshalBER(content[offset:offset+n_extensioncontainer], ber.ChildDecodeOptions(opts, "extensionContainer")...); unmErr != nil {
					return fmt.Errorf("decoding extensionContainer: %w", unmErr)
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
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:], opts...)
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "TargetCellOutsideGCAParam", Cause: extErr_}
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

// MarshalBER encodes OngoingGroupCallParam to BER format.
func (v *OngoingGroupCallParam) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: OngoingGroupCallParam receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *OngoingGroupCallParam) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalBER(ber.ChildEncodeOptions(opts, "extensionContainer")...)
		if err != nil {
			return nil, fmt.Errorf("encoding extensionContainer: %w", err)
		}
		children = append(children, enc_extensioncontainer...)
	}
	for i, ext := range v.ExtData_ {
		_, n, _, extErr := ber.DecodeEncodedTLV(ext)
		if extErr != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, extErr)
		}
		if n != len(ext) {
			return nil, fmt.Errorf("encoding extension %d: %w", i, ber.ErrExtraData)
		}
		children = append(children, ext...)
	}
	return ber.EncodeSequence(children)
}

// MarshalDER encodes OngoingGroupCallParam to DER format.
func (v *OngoingGroupCallParam) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: OngoingGroupCallParam receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding extensionContainer: %w", err)
		}
		children = append(children, enc_extensioncontainer...)
	}
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDEREncodedElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
		children = append(children, ext...)
	}
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding OngoingGroupCallParam as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes OngoingGroupCallParam from BER/DER format.
func (v *OngoingGroupCallParam) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: OngoingGroupCallParam destination is nil", ber.ErrInvalidValue)
	}
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = OngoingGroupCallParam{}
	defer func() {
		if returnErr != nil || !ber.BERNeedsPreservation(opts) {
			return
		}
		var snapshotReports ber.ViolationLog
		snapshot, snapshotErr := v.marshalBER(ber.WithConstraintTolerance(&snapshotReports))
		if snapshotErr != nil {
			returnErr = snapshotErr
			return
		}
		v.berOriginal_ = append([]byte(nil), data...)
		v.berSnapshot_ = snapshot
	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("decoding OngoingGroupCallParam SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "OngoingGroupCallParam", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode extensionContainer
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassUniversal && peekTag.Number == 16 {
				// Decode nested SEQUENCE (ExtensionContainer)
				_, n_extensioncontainer, _, tlvErr_extensioncontainer := ber.DecodeTLV(content[offset:], opts...)
				if tlvErr_extensioncontainer != nil {
					return fmt.Errorf("decoding extensionContainer: %w", tlvErr_extensioncontainer)
				}
				var dec_extensioncontainer ExtensionContainer
				if offset > len(content) || n_extensioncontainer < 0 || n_extensioncontainer > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				if unmErr := dec_extensioncontainer.UnmarshalBER(content[offset:offset+n_extensioncontainer], ber.ChildDecodeOptions(opts, "extensionContainer")...); unmErr != nil {
					return fmt.Errorf("decoding extensionContainer: %w", unmErr)
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
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:], opts...)
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "OngoingGroupCallParam", Cause: extErr_}
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
