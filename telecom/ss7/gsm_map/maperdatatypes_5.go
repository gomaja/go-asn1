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

// RoamingNotAllowedParam5 represents the ASN.1 type RoamingNotAllowedParam (SEQUENCE).
type RoamingNotAllowedParam5 struct {
	RoamingNotAllowedCause           RoamingNotAllowedCause5            `asn1:""`
	ExtensionContainer               *ExtensionContainer5               `asn1:",optional" json:"ExtensionContainer,omitempty"`
	AdditionalRoamingNotAllowedCause *AdditionalRoamingNotAllowedCause5 `asn1:"tag:0,context,implicit,optional" json:"AdditionalRoamingNotAllowedCause,omitempty"`
	ExtCount_                        int64                              `asn1:"-" json:"-"`
	ExtPresent_                      []bool                             `asn1:"-" json:"-"`
	ExtData_                         [][]byte                           `asn1:"-" json:"-"`
	berOriginal_                     []byte                             `asn1:"-" json:"-"`
	berSnapshot_                     []byte                             `asn1:"-" json:"-"`
}

// AdditionalRoamingNotAllowedCause5 represents the ASN.1 ENUMERATED type AdditionalRoamingNotAllowedCause.
type AdditionalRoamingNotAllowedCause5 int64

const (
	AdditionalRoamingNotAllowedCause5SupportedRATTypesNotAllowed AdditionalRoamingNotAllowedCause5 = 0
)

func (v AdditionalRoamingNotAllowedCause5) String() string {
	switch v {
	case AdditionalRoamingNotAllowedCause5SupportedRATTypesNotAllowed:
		return "supportedRAT-TypesNotAllowed"
	default:
		return "unknown"
	}
}

// RoamingNotAllowedCause5 represents the ASN.1 ENUMERATED type RoamingNotAllowedCause.
type RoamingNotAllowedCause5 int64

const (
	RoamingNotAllowedCause5PlmnRoamingNotAllowed     RoamingNotAllowedCause5 = 0
	RoamingNotAllowedCause5OperatorDeterminedBarring RoamingNotAllowedCause5 = 3
)

func (v RoamingNotAllowedCause5) String() string {
	switch v {
	case RoamingNotAllowedCause5PlmnRoamingNotAllowed:
		return "plmnRoamingNotAllowed"
	case RoamingNotAllowedCause5OperatorDeterminedBarring:
		return "operatorDeterminedBarring"
	default:
		return "unknown"
	}
}

// CallBarredParam5 choice constants.
const (
	CallBarredParam5ChoiceCallBarringCause          = 1
	CallBarredParam5ChoiceExtensibleCallBarredParam = 2
)

// CallBarredParam5 represents the ASN.1 CHOICE type CallBarredParam.
type CallBarredParam5 struct {
	Choice                    int
	berOriginal_              []byte                      `json:"-"`
	berSnapshot_              []byte                      `json:"-"`
	CallBarringCause          *CallBarringCause5          `json:"CallBarringCause,omitempty"`
	ExtensibleCallBarredParam *ExtensibleCallBarredParam5 `json:"ExtensibleCallBarredParam,omitempty"`
}

// NewCallBarredParam5CallBarringCause creates a CallBarredParam5 with the callBarringCause alternative.
func NewCallBarredParam5CallBarringCause(v CallBarringCause5) CallBarredParam5 {
	return CallBarredParam5{
		Choice:           CallBarredParam5ChoiceCallBarringCause,
		CallBarringCause: &v,
	}
}

// NewCallBarredParam5ExtensibleCallBarredParam creates a CallBarredParam5 with the extensibleCallBarredParam alternative.
func NewCallBarredParam5ExtensibleCallBarredParam(v ExtensibleCallBarredParam5) CallBarredParam5 {
	return CallBarredParam5{
		Choice:                    CallBarredParam5ChoiceExtensibleCallBarredParam,
		ExtensibleCallBarredParam: &v,
	}
}

// CallBarringCause5 represents the ASN.1 ENUMERATED type CallBarringCause.
type CallBarringCause5 int64

const (
	CallBarringCause5BarringServiceActive CallBarringCause5 = 0
	CallBarringCause5OperatorBarring      CallBarringCause5 = 1
)

func (v CallBarringCause5) String() string {
	switch v {
	case CallBarringCause5BarringServiceActive:
		return "barringServiceActive"
	case CallBarringCause5OperatorBarring:
		return "operatorBarring"
	default:
		return "unknown"
	}
}

// ExtensibleCallBarredParam5 represents the ASN.1 type ExtensibleCallBarredParam (SEQUENCE).
type ExtensibleCallBarredParam5 struct {
	CallBarringCause              *CallBarringCause5   `asn1:",optional" json:"CallBarringCause,omitempty"`
	ExtensionContainer            *ExtensionContainer5 `asn1:",optional" json:"ExtensionContainer,omitempty"`
	UnauthorisedMessageOriginator *struct{}            `asn1:"tag:1,context,implicit,optional" json:"UnauthorisedMessageOriginator,omitempty"`
	ExtCount_                     int64                `asn1:"-" json:"-"`
	ExtPresent_                   []bool               `asn1:"-" json:"-"`
	ExtData_                      [][]byte             `asn1:"-" json:"-"`
	berOriginal_                  []byte               `asn1:"-" json:"-"`
	berSnapshot_                  []byte               `asn1:"-" json:"-"`
}

// CUGRejectParam5 represents the ASN.1 type CUG-RejectParam (SEQUENCE).
type CUGRejectParam5 struct {
	CugRejectCause     *CUGRejectCause5     `asn1:",optional" json:"CugRejectCause,omitempty"`
	ExtensionContainer *ExtensionContainer5 `asn1:",optional" json:"ExtensionContainer,omitempty"`
	ExtCount_          int64                `asn1:"-" json:"-"`
	ExtPresent_        []bool               `asn1:"-" json:"-"`
	ExtData_           [][]byte             `asn1:"-" json:"-"`
	berOriginal_       []byte               `asn1:"-" json:"-"`
	berSnapshot_       []byte               `asn1:"-" json:"-"`
}

// CUGRejectCause5 represents the ASN.1 ENUMERATED type CUG-RejectCause.
type CUGRejectCause5 int64

const (
	CUGRejectCause5IncomingCallsBarredWithinCUG                CUGRejectCause5 = 0
	CUGRejectCause5SubscriberNotMemberOfCUG                    CUGRejectCause5 = 1
	CUGRejectCause5RequestedBasicServiceViolatesCUGConstraints CUGRejectCause5 = 5
	CUGRejectCause5CalledPartySSInteractionViolation           CUGRejectCause5 = 7
)

func (v CUGRejectCause5) String() string {
	switch v {
	case CUGRejectCause5IncomingCallsBarredWithinCUG:
		return "incomingCallsBarredWithinCUG"
	case CUGRejectCause5SubscriberNotMemberOfCUG:
		return "subscriberNotMemberOfCUG"
	case CUGRejectCause5RequestedBasicServiceViolatesCUGConstraints:
		return "requestedBasicServiceViolatesCUG-Constraints"
	case CUGRejectCause5CalledPartySSInteractionViolation:
		return "calledPartySS-InteractionViolation"
	default:
		return "unknown"
	}
}

// SSIncompatibilityCause5 represents the ASN.1 type SS-IncompatibilityCause (SEQUENCE).
type SSIncompatibilityCause5 struct {
	SsCode       *SSCode5           `asn1:"tag:1,context,implicit,optional" json:"SsCode,omitempty"`
	BasicService *BasicServiceCode5 `asn1:",optional" json:"BasicService,omitempty"`
	SsStatus     *SSStatus5         `asn1:"tag:4,context,implicit,optional" json:"SsStatus,omitempty"`
	ExtCount_    int64              `asn1:"-" json:"-"`
	ExtPresent_  []bool             `asn1:"-" json:"-"`
	ExtData_     [][]byte           `asn1:"-" json:"-"`
	berOriginal_ []byte             `asn1:"-" json:"-"`
	berSnapshot_ []byte             `asn1:"-" json:"-"`
}

// PWRegistrationFailureCause5 represents the ASN.1 ENUMERATED type PW-RegistrationFailureCause.
type PWRegistrationFailureCause5 int64

const (
	PWRegistrationFailureCause5Undetermined         PWRegistrationFailureCause5 = 0
	PWRegistrationFailureCause5InvalidFormat        PWRegistrationFailureCause5 = 1
	PWRegistrationFailureCause5NewPasswordsMismatch PWRegistrationFailureCause5 = 2
)

func (v PWRegistrationFailureCause5) String() string {
	switch v {
	case PWRegistrationFailureCause5Undetermined:
		return "undetermined"
	case PWRegistrationFailureCause5InvalidFormat:
		return "invalidFormat"
	case PWRegistrationFailureCause5NewPasswordsMismatch:
		return "newPasswordsMismatch"
	default:
		return "unknown"
	}
}

// SMEnumeratedDeliveryFailureCause5 represents the ASN.1 ENUMERATED type SM-EnumeratedDeliveryFailureCause.
type SMEnumeratedDeliveryFailureCause5 int64

const (
	SMEnumeratedDeliveryFailureCause5MemoryCapacityExceeded    SMEnumeratedDeliveryFailureCause5 = 0
	SMEnumeratedDeliveryFailureCause5EquipmentProtocolError    SMEnumeratedDeliveryFailureCause5 = 1
	SMEnumeratedDeliveryFailureCause5EquipmentNotSMEquipped    SMEnumeratedDeliveryFailureCause5 = 2
	SMEnumeratedDeliveryFailureCause5UnknownServiceCentre      SMEnumeratedDeliveryFailureCause5 = 3
	SMEnumeratedDeliveryFailureCause5ScCongestion              SMEnumeratedDeliveryFailureCause5 = 4
	SMEnumeratedDeliveryFailureCause5InvalidSMEAddress         SMEnumeratedDeliveryFailureCause5 = 5
	SMEnumeratedDeliveryFailureCause5SubscriberNotSCSubscriber SMEnumeratedDeliveryFailureCause5 = 6
)

func (v SMEnumeratedDeliveryFailureCause5) String() string {
	switch v {
	case SMEnumeratedDeliveryFailureCause5MemoryCapacityExceeded:
		return "memoryCapacityExceeded"
	case SMEnumeratedDeliveryFailureCause5EquipmentProtocolError:
		return "equipmentProtocolError"
	case SMEnumeratedDeliveryFailureCause5EquipmentNotSMEquipped:
		return "equipmentNotSM-Equipped"
	case SMEnumeratedDeliveryFailureCause5UnknownServiceCentre:
		return "unknownServiceCentre"
	case SMEnumeratedDeliveryFailureCause5ScCongestion:
		return "sc-Congestion"
	case SMEnumeratedDeliveryFailureCause5InvalidSMEAddress:
		return "invalidSME-Address"
	case SMEnumeratedDeliveryFailureCause5SubscriberNotSCSubscriber:
		return "subscriberNotSC-Subscriber"
	default:
		return "unknown"
	}
}

// SMDeliveryFailureCause5 represents the ASN.1 type SM-DeliveryFailureCause (SEQUENCE).
type SMDeliveryFailureCause5 struct {
	SmEnumeratedDeliveryFailureCause SMEnumeratedDeliveryFailureCause5 `asn1:""`
	DiagnosticInfo                   *SignalInfo5                      `asn1:",optional" json:"DiagnosticInfo,omitempty"`
	ExtensionContainer               *ExtensionContainer5              `asn1:",optional" json:"ExtensionContainer,omitempty"`
	ExtCount_                        int64                             `asn1:"-" json:"-"`
	ExtPresent_                      []bool                            `asn1:"-" json:"-"`
	ExtData_                         [][]byte                          `asn1:"-" json:"-"`
	berOriginal_                     []byte                            `asn1:"-" json:"-"`
	berSnapshot_                     []byte                            `asn1:"-" json:"-"`
}

// AbsentSubscriberSMParam5 represents the ASN.1 type AbsentSubscriberSM-Param (SEQUENCE).
type AbsentSubscriberSMParam5 struct {
	AbsentSubscriberDiagnosticSM           *AbsentSubscriberDiagnosticSM5 `asn1:",optional" json:"AbsentSubscriberDiagnosticSM,omitempty"`
	ExtensionContainer                     *ExtensionContainer5           `asn1:",optional" json:"ExtensionContainer,omitempty"`
	AdditionalAbsentSubscriberDiagnosticSM *AbsentSubscriberDiagnosticSM5 `asn1:"tag:0,context,implicit,optional" json:"AdditionalAbsentSubscriberDiagnosticSM,omitempty"`
	ExtCount_                              int64                          `asn1:"-" json:"-"`
	ExtPresent_                            []bool                         `asn1:"-" json:"-"`
	ExtData_                               [][]byte                       `asn1:"-" json:"-"`
	berOriginal_                           []byte                         `asn1:"-" json:"-"`
	berSnapshot_                           []byte                         `asn1:"-" json:"-"`
}

// AbsentSubscriberDiagnosticSM5 represents the ASN.1 type AbsentSubscriberDiagnosticSM (INTEGER).
type AbsentSubscriberDiagnosticSM5 = int64

// SystemFailureParam5 choice constants.
const (
	SystemFailureParam5ChoiceNetworkResource              = 1
	SystemFailureParam5ChoiceExtensibleSystemFailureParam = 2
)

// SystemFailureParam5 represents the ASN.1 CHOICE type SystemFailureParam.
type SystemFailureParam5 struct {
	Choice                       int
	berOriginal_                 []byte                         `json:"-"`
	berSnapshot_                 []byte                         `json:"-"`
	NetworkResource              *NetworkResource5              `json:"NetworkResource,omitempty"`
	ExtensibleSystemFailureParam *ExtensibleSystemFailureParam5 `json:"ExtensibleSystemFailureParam,omitempty"`
}

// NewSystemFailureParam5NetworkResource creates a SystemFailureParam5 with the networkResource alternative.
func NewSystemFailureParam5NetworkResource(v NetworkResource5) SystemFailureParam5 {
	return SystemFailureParam5{
		Choice:          SystemFailureParam5ChoiceNetworkResource,
		NetworkResource: &v,
	}
}

// NewSystemFailureParam5ExtensibleSystemFailureParam creates a SystemFailureParam5 with the extensibleSystemFailureParam alternative.
func NewSystemFailureParam5ExtensibleSystemFailureParam(v ExtensibleSystemFailureParam5) SystemFailureParam5 {
	return SystemFailureParam5{
		Choice:                       SystemFailureParam5ChoiceExtensibleSystemFailureParam,
		ExtensibleSystemFailureParam: &v,
	}
}

// ExtensibleSystemFailureParam5 represents the ASN.1 type ExtensibleSystemFailureParam (SEQUENCE).
type ExtensibleSystemFailureParam5 struct {
	NetworkResource           *NetworkResource5           `asn1:",optional" json:"NetworkResource,omitempty"`
	ExtensionContainer        *ExtensionContainer5        `asn1:",optional" json:"ExtensionContainer,omitempty"`
	AdditionalNetworkResource *AdditionalNetworkResource5 `asn1:"tag:0,context,implicit,optional" json:"AdditionalNetworkResource,omitempty"`
	FailureCauseParam         *FailureCauseParam4         `asn1:"tag:1,context,implicit,optional" json:"FailureCauseParam,omitempty"`
	ExtCount_                 int64                       `asn1:"-" json:"-"`
	ExtPresent_               []bool                      `asn1:"-" json:"-"`
	ExtData_                  [][]byte                    `asn1:"-" json:"-"`
	berOriginal_              []byte                      `asn1:"-" json:"-"`
	berSnapshot_              []byte                      `asn1:"-" json:"-"`
}

// FailureCauseParam4 represents the ASN.1 ENUMERATED type FailureCauseParam.
type FailureCauseParam4 int64

const (
	FailureCauseParam4LimitReachedOnNumberOfConcurrentLocationRequests FailureCauseParam4 = 0
)

func (v FailureCauseParam4) String() string {
	switch v {
	case FailureCauseParam4LimitReachedOnNumberOfConcurrentLocationRequests:
		return "limitReachedOnNumberOfConcurrentLocationRequests"
	default:
		return "unknown"
	}
}

// DataMissingParam5 represents the ASN.1 type DataMissingParam (SEQUENCE).
type DataMissingParam5 struct {
	ExtensionContainer *ExtensionContainer5 `asn1:",optional" json:"ExtensionContainer,omitempty"`
	ExtCount_          int64                `asn1:"-" json:"-"`
	ExtPresent_        []bool               `asn1:"-" json:"-"`
	ExtData_           [][]byte             `asn1:"-" json:"-"`
	berOriginal_       []byte               `asn1:"-" json:"-"`
	berSnapshot_       []byte               `asn1:"-" json:"-"`
}

// UnexpectedDataParam5 represents the ASN.1 type UnexpectedDataParam (SEQUENCE).
type UnexpectedDataParam5 struct {
	ExtensionContainer *ExtensionContainer5 `asn1:",optional" json:"ExtensionContainer,omitempty"`
	ExtCount_          int64                `asn1:"-" json:"-"`
	ExtPresent_        []bool               `asn1:"-" json:"-"`
	ExtData_           [][]byte             `asn1:"-" json:"-"`
	berOriginal_       []byte               `asn1:"-" json:"-"`
	berSnapshot_       []byte               `asn1:"-" json:"-"`
}

// FacilityNotSupParam5 represents the ASN.1 type FacilityNotSupParam (SEQUENCE).
type FacilityNotSupParam5 struct {
	ExtensionContainer                           *ExtensionContainer5 `asn1:",optional" json:"ExtensionContainer,omitempty"`
	ShapeOfLocationEstimateNotSupported          *struct{}            `asn1:"tag:0,context,implicit,optional" json:"ShapeOfLocationEstimateNotSupported,omitempty"`
	NeededLcsCapabilityNotSupportedInServingNode *struct{}            `asn1:"tag:1,context,implicit,optional" json:"NeededLcsCapabilityNotSupportedInServingNode,omitempty"`
	ExtCount_                                    int64                `asn1:"-" json:"-"`
	ExtPresent_                                  []bool               `asn1:"-" json:"-"`
	ExtData_                                     [][]byte             `asn1:"-" json:"-"`
	berOriginal_                                 []byte               `asn1:"-" json:"-"`
	berSnapshot_                                 []byte               `asn1:"-" json:"-"`
}

// ORNotAllowedParam5 represents the ASN.1 type OR-NotAllowedParam (SEQUENCE).
type ORNotAllowedParam5 struct {
	ExtensionContainer *ExtensionContainer5 `asn1:",optional" json:"ExtensionContainer,omitempty"`
	ExtCount_          int64                `asn1:"-" json:"-"`
	ExtPresent_        []bool               `asn1:"-" json:"-"`
	ExtData_           [][]byte             `asn1:"-" json:"-"`
	berOriginal_       []byte               `asn1:"-" json:"-"`
	berSnapshot_       []byte               `asn1:"-" json:"-"`
}

// UnknownSubscriberParam5 represents the ASN.1 type UnknownSubscriberParam (SEQUENCE).
type UnknownSubscriberParam5 struct {
	ExtensionContainer          *ExtensionContainer5          `asn1:",optional" json:"ExtensionContainer,omitempty"`
	UnknownSubscriberDiagnostic *UnknownSubscriberDiagnostic5 `asn1:",optional" json:"UnknownSubscriberDiagnostic,omitempty"`
	ExtCount_                   int64                         `asn1:"-" json:"-"`
	ExtPresent_                 []bool                        `asn1:"-" json:"-"`
	ExtData_                    [][]byte                      `asn1:"-" json:"-"`
	berOriginal_                []byte                        `asn1:"-" json:"-"`
	berSnapshot_                []byte                        `asn1:"-" json:"-"`
}

// UnknownSubscriberDiagnostic5 represents the ASN.1 ENUMERATED type UnknownSubscriberDiagnostic.
type UnknownSubscriberDiagnostic5 int64

const (
	UnknownSubscriberDiagnostic5ImsiUnknown                UnknownSubscriberDiagnostic5 = 0
	UnknownSubscriberDiagnostic5GprsEpsSubscriptionUnknown UnknownSubscriberDiagnostic5 = 1
	UnknownSubscriberDiagnostic5NpdbMismatch               UnknownSubscriberDiagnostic5 = 2
)

func (v UnknownSubscriberDiagnostic5) String() string {
	switch v {
	case UnknownSubscriberDiagnostic5ImsiUnknown:
		return "imsiUnknown"
	case UnknownSubscriberDiagnostic5GprsEpsSubscriptionUnknown:
		return "gprs-eps-SubscriptionUnknown"
	case UnknownSubscriberDiagnostic5NpdbMismatch:
		return "npdbMismatch"
	default:
		return "unknown"
	}
}

// NumberChangedParam5 represents the ASN.1 type NumberChangedParam (SEQUENCE).
type NumberChangedParam5 struct {
	ExtensionContainer *ExtensionContainer5 `asn1:",optional" json:"ExtensionContainer,omitempty"`
	ExtCount_          int64                `asn1:"-" json:"-"`
	ExtPresent_        []bool               `asn1:"-" json:"-"`
	ExtData_           [][]byte             `asn1:"-" json:"-"`
	berOriginal_       []byte               `asn1:"-" json:"-"`
	berSnapshot_       []byte               `asn1:"-" json:"-"`
}

// UnidentifiedSubParam5 represents the ASN.1 type UnidentifiedSubParam (SEQUENCE).
type UnidentifiedSubParam5 struct {
	ExtensionContainer *ExtensionContainer5 `asn1:",optional" json:"ExtensionContainer,omitempty"`
	ExtCount_          int64                `asn1:"-" json:"-"`
	ExtPresent_        []bool               `asn1:"-" json:"-"`
	ExtData_           [][]byte             `asn1:"-" json:"-"`
	berOriginal_       []byte               `asn1:"-" json:"-"`
	berSnapshot_       []byte               `asn1:"-" json:"-"`
}

// IllegalSubscriberParam5 represents the ASN.1 type IllegalSubscriberParam (SEQUENCE).
type IllegalSubscriberParam5 struct {
	ExtensionContainer *ExtensionContainer5 `asn1:",optional" json:"ExtensionContainer,omitempty"`
	ExtCount_          int64                `asn1:"-" json:"-"`
	ExtPresent_        []bool               `asn1:"-" json:"-"`
	ExtData_           [][]byte             `asn1:"-" json:"-"`
	berOriginal_       []byte               `asn1:"-" json:"-"`
	berSnapshot_       []byte               `asn1:"-" json:"-"`
}

// IllegalEquipmentParam5 represents the ASN.1 type IllegalEquipmentParam (SEQUENCE).
type IllegalEquipmentParam5 struct {
	ExtensionContainer *ExtensionContainer5 `asn1:",optional" json:"ExtensionContainer,omitempty"`
	ExtCount_          int64                `asn1:"-" json:"-"`
	ExtPresent_        []bool               `asn1:"-" json:"-"`
	ExtData_           [][]byte             `asn1:"-" json:"-"`
	berOriginal_       []byte               `asn1:"-" json:"-"`
	berSnapshot_       []byte               `asn1:"-" json:"-"`
}

// BearerServNotProvParam5 represents the ASN.1 type BearerServNotProvParam (SEQUENCE).
type BearerServNotProvParam5 struct {
	ExtensionContainer *ExtensionContainer5 `asn1:",optional" json:"ExtensionContainer,omitempty"`
	ExtCount_          int64                `asn1:"-" json:"-"`
	ExtPresent_        []bool               `asn1:"-" json:"-"`
	ExtData_           [][]byte             `asn1:"-" json:"-"`
	berOriginal_       []byte               `asn1:"-" json:"-"`
	berSnapshot_       []byte               `asn1:"-" json:"-"`
}

// TeleservNotProvParam5 represents the ASN.1 type TeleservNotProvParam (SEQUENCE).
type TeleservNotProvParam5 struct {
	ExtensionContainer *ExtensionContainer5 `asn1:",optional" json:"ExtensionContainer,omitempty"`
	ExtCount_          int64                `asn1:"-" json:"-"`
	ExtPresent_        []bool               `asn1:"-" json:"-"`
	ExtData_           [][]byte             `asn1:"-" json:"-"`
	berOriginal_       []byte               `asn1:"-" json:"-"`
	berSnapshot_       []byte               `asn1:"-" json:"-"`
}

// TracingBufferFullParam5 represents the ASN.1 type TracingBufferFullParam (SEQUENCE).
type TracingBufferFullParam5 struct {
	ExtensionContainer *ExtensionContainer5 `asn1:",optional" json:"ExtensionContainer,omitempty"`
	ExtCount_          int64                `asn1:"-" json:"-"`
	ExtPresent_        []bool               `asn1:"-" json:"-"`
	ExtData_           [][]byte             `asn1:"-" json:"-"`
	berOriginal_       []byte               `asn1:"-" json:"-"`
	berSnapshot_       []byte               `asn1:"-" json:"-"`
}

// NoRoamingNbParam5 represents the ASN.1 type NoRoamingNbParam (SEQUENCE).
type NoRoamingNbParam5 struct {
	ExtensionContainer *ExtensionContainer5 `asn1:",optional" json:"ExtensionContainer,omitempty"`
	ExtCount_          int64                `asn1:"-" json:"-"`
	ExtPresent_        []bool               `asn1:"-" json:"-"`
	ExtData_           [][]byte             `asn1:"-" json:"-"`
	berOriginal_       []byte               `asn1:"-" json:"-"`
	berSnapshot_       []byte               `asn1:"-" json:"-"`
}

// AbsentSubscriberParam5 represents the ASN.1 type AbsentSubscriberParam (SEQUENCE).
type AbsentSubscriberParam5 struct {
	ExtensionContainer     *ExtensionContainer5     `asn1:",optional" json:"ExtensionContainer,omitempty"`
	AbsentSubscriberReason *AbsentSubscriberReason5 `asn1:"tag:0,context,implicit,optional" json:"AbsentSubscriberReason,omitempty"`
	ExtCount_              int64                    `asn1:"-" json:"-"`
	ExtPresent_            []bool                   `asn1:"-" json:"-"`
	ExtData_               [][]byte                 `asn1:"-" json:"-"`
	berOriginal_           []byte                   `asn1:"-" json:"-"`
	berSnapshot_           []byte                   `asn1:"-" json:"-"`
}

// AbsentSubscriberReason5 represents the ASN.1 ENUMERATED type AbsentSubscriberReason.
type AbsentSubscriberReason5 int64

const (
	AbsentSubscriberReason5ImsiDetach     AbsentSubscriberReason5 = 0
	AbsentSubscriberReason5RestrictedArea AbsentSubscriberReason5 = 1
	AbsentSubscriberReason5NoPageResponse AbsentSubscriberReason5 = 2
	AbsentSubscriberReason5PurgedMS       AbsentSubscriberReason5 = 3
	AbsentSubscriberReason5MtRoamingRetry AbsentSubscriberReason5 = 4
	AbsentSubscriberReason5BusySubscriber AbsentSubscriberReason5 = 5
)

func (v AbsentSubscriberReason5) String() string {
	switch v {
	case AbsentSubscriberReason5ImsiDetach:
		return "imsiDetach"
	case AbsentSubscriberReason5RestrictedArea:
		return "restrictedArea"
	case AbsentSubscriberReason5NoPageResponse:
		return "noPageResponse"
	case AbsentSubscriberReason5PurgedMS:
		return "purgedMS"
	case AbsentSubscriberReason5MtRoamingRetry:
		return "mtRoamingRetry"
	case AbsentSubscriberReason5BusySubscriber:
		return "busySubscriber"
	default:
		return "unknown"
	}
}

// BusySubscriberParam5 represents the ASN.1 type BusySubscriberParam (SEQUENCE).
type BusySubscriberParam5 struct {
	ExtensionContainer *ExtensionContainer5 `asn1:",optional" json:"ExtensionContainer,omitempty"`
	CcbsPossible       *struct{}            `asn1:"tag:0,context,implicit,optional" json:"CcbsPossible,omitempty"`
	CcbsBusy           *struct{}            `asn1:"tag:1,context,implicit,optional" json:"CcbsBusy,omitempty"`
	ExtCount_          int64                `asn1:"-" json:"-"`
	ExtPresent_        []bool               `asn1:"-" json:"-"`
	ExtData_           [][]byte             `asn1:"-" json:"-"`
	berOriginal_       []byte               `asn1:"-" json:"-"`
	berSnapshot_       []byte               `asn1:"-" json:"-"`
}

// NoSubscriberReplyParam5 represents the ASN.1 type NoSubscriberReplyParam (SEQUENCE).
type NoSubscriberReplyParam5 struct {
	ExtensionContainer *ExtensionContainer5 `asn1:",optional" json:"ExtensionContainer,omitempty"`
	ExtCount_          int64                `asn1:"-" json:"-"`
	ExtPresent_        []bool               `asn1:"-" json:"-"`
	ExtData_           [][]byte             `asn1:"-" json:"-"`
	berOriginal_       []byte               `asn1:"-" json:"-"`
	berSnapshot_       []byte               `asn1:"-" json:"-"`
}

// ForwardingViolationParam5 represents the ASN.1 type ForwardingViolationParam (SEQUENCE).
type ForwardingViolationParam5 struct {
	ExtensionContainer *ExtensionContainer5 `asn1:",optional" json:"ExtensionContainer,omitempty"`
	ExtCount_          int64                `asn1:"-" json:"-"`
	ExtPresent_        []bool               `asn1:"-" json:"-"`
	ExtData_           [][]byte             `asn1:"-" json:"-"`
	berOriginal_       []byte               `asn1:"-" json:"-"`
	berSnapshot_       []byte               `asn1:"-" json:"-"`
}

// ForwardingFailedParam5 represents the ASN.1 type ForwardingFailedParam (SEQUENCE).
type ForwardingFailedParam5 struct {
	ExtensionContainer *ExtensionContainer5 `asn1:",optional" json:"ExtensionContainer,omitempty"`
	ExtCount_          int64                `asn1:"-" json:"-"`
	ExtPresent_        []bool               `asn1:"-" json:"-"`
	ExtData_           [][]byte             `asn1:"-" json:"-"`
	berOriginal_       []byte               `asn1:"-" json:"-"`
	berSnapshot_       []byte               `asn1:"-" json:"-"`
}

// ATINotAllowedParam5 represents the ASN.1 type ATI-NotAllowedParam (SEQUENCE).
type ATINotAllowedParam5 struct {
	ExtensionContainer *ExtensionContainer5 `asn1:",optional" json:"ExtensionContainer,omitempty"`
	ExtCount_          int64                `asn1:"-" json:"-"`
	ExtPresent_        []bool               `asn1:"-" json:"-"`
	ExtData_           [][]byte             `asn1:"-" json:"-"`
	berOriginal_       []byte               `asn1:"-" json:"-"`
	berSnapshot_       []byte               `asn1:"-" json:"-"`
}

// ATSINotAllowedParam5 represents the ASN.1 type ATSI-NotAllowedParam (SEQUENCE).
type ATSINotAllowedParam5 struct {
	ExtensionContainer *ExtensionContainer5 `asn1:",optional" json:"ExtensionContainer,omitempty"`
	ExtCount_          int64                `asn1:"-" json:"-"`
	ExtPresent_        []bool               `asn1:"-" json:"-"`
	ExtData_           [][]byte             `asn1:"-" json:"-"`
	berOriginal_       []byte               `asn1:"-" json:"-"`
	berSnapshot_       []byte               `asn1:"-" json:"-"`
}

// ATMNotAllowedParam5 represents the ASN.1 type ATM-NotAllowedParam (SEQUENCE).
type ATMNotAllowedParam5 struct {
	ExtensionContainer *ExtensionContainer5 `asn1:",optional" json:"ExtensionContainer,omitempty"`
	ExtCount_          int64                `asn1:"-" json:"-"`
	ExtPresent_        []bool               `asn1:"-" json:"-"`
	ExtData_           [][]byte             `asn1:"-" json:"-"`
	berOriginal_       []byte               `asn1:"-" json:"-"`
	berSnapshot_       []byte               `asn1:"-" json:"-"`
}

// IllegalSSOperationParam5 represents the ASN.1 type IllegalSS-OperationParam (SEQUENCE).
type IllegalSSOperationParam5 struct {
	ExtensionContainer *ExtensionContainer5 `asn1:",optional" json:"ExtensionContainer,omitempty"`
	ExtCount_          int64                `asn1:"-" json:"-"`
	ExtPresent_        []bool               `asn1:"-" json:"-"`
	ExtData_           [][]byte             `asn1:"-" json:"-"`
	berOriginal_       []byte               `asn1:"-" json:"-"`
	berSnapshot_       []byte               `asn1:"-" json:"-"`
}

// SSNotAvailableParam5 represents the ASN.1 type SS-NotAvailableParam (SEQUENCE).
type SSNotAvailableParam5 struct {
	ExtensionContainer *ExtensionContainer5 `asn1:",optional" json:"ExtensionContainer,omitempty"`
	ExtCount_          int64                `asn1:"-" json:"-"`
	ExtPresent_        []bool               `asn1:"-" json:"-"`
	ExtData_           [][]byte             `asn1:"-" json:"-"`
	berOriginal_       []byte               `asn1:"-" json:"-"`
	berSnapshot_       []byte               `asn1:"-" json:"-"`
}

// SSSubscriptionViolationParam5 represents the ASN.1 type SS-SubscriptionViolationParam (SEQUENCE).
type SSSubscriptionViolationParam5 struct {
	ExtensionContainer *ExtensionContainer5 `asn1:",optional" json:"ExtensionContainer,omitempty"`
	ExtCount_          int64                `asn1:"-" json:"-"`
	ExtPresent_        []bool               `asn1:"-" json:"-"`
	ExtData_           [][]byte             `asn1:"-" json:"-"`
	berOriginal_       []byte               `asn1:"-" json:"-"`
	berSnapshot_       []byte               `asn1:"-" json:"-"`
}

// InformationNotAvailableParam5 represents the ASN.1 type InformationNotAvailableParam (SEQUENCE).
type InformationNotAvailableParam5 struct {
	ExtensionContainer *ExtensionContainer5 `asn1:",optional" json:"ExtensionContainer,omitempty"`
	ExtCount_          int64                `asn1:"-" json:"-"`
	ExtPresent_        []bool               `asn1:"-" json:"-"`
	ExtData_           [][]byte             `asn1:"-" json:"-"`
	berOriginal_       []byte               `asn1:"-" json:"-"`
	berSnapshot_       []byte               `asn1:"-" json:"-"`
}

// SubBusyForMTSMSParam5 represents the ASN.1 type SubBusyForMT-SMS-Param (SEQUENCE).
type SubBusyForMTSMSParam5 struct {
	ExtensionContainer      *ExtensionContainer5 `asn1:",optional" json:"ExtensionContainer,omitempty"`
	GprsConnectionSuspended *struct{}            `asn1:",optional" json:"GprsConnectionSuspended,omitempty"`
	ExtCount_               int64                `asn1:"-" json:"-"`
	ExtPresent_             []bool               `asn1:"-" json:"-"`
	ExtData_                [][]byte             `asn1:"-" json:"-"`
	berOriginal_            []byte               `asn1:"-" json:"-"`
	berSnapshot_            []byte               `asn1:"-" json:"-"`
}

// MessageWaitListFullParam5 represents the ASN.1 type MessageWaitListFullParam (SEQUENCE).
type MessageWaitListFullParam5 struct {
	ExtensionContainer *ExtensionContainer5 `asn1:",optional" json:"ExtensionContainer,omitempty"`
	ExtCount_          int64                `asn1:"-" json:"-"`
	ExtPresent_        []bool               `asn1:"-" json:"-"`
	ExtData_           [][]byte             `asn1:"-" json:"-"`
	berOriginal_       []byte               `asn1:"-" json:"-"`
	berSnapshot_       []byte               `asn1:"-" json:"-"`
}

// ResourceLimitationParam5 represents the ASN.1 type ResourceLimitationParam (SEQUENCE).
type ResourceLimitationParam5 struct {
	ExtensionContainer *ExtensionContainer5 `asn1:",optional" json:"ExtensionContainer,omitempty"`
	ExtCount_          int64                `asn1:"-" json:"-"`
	ExtPresent_        []bool               `asn1:"-" json:"-"`
	ExtData_           [][]byte             `asn1:"-" json:"-"`
	berOriginal_       []byte               `asn1:"-" json:"-"`
	berSnapshot_       []byte               `asn1:"-" json:"-"`
}

// NoGroupCallNbParam5 represents the ASN.1 type NoGroupCallNbParam (SEQUENCE).
type NoGroupCallNbParam5 struct {
	ExtensionContainer *ExtensionContainer5 `asn1:",optional" json:"ExtensionContainer,omitempty"`
	ExtCount_          int64                `asn1:"-" json:"-"`
	ExtPresent_        []bool               `asn1:"-" json:"-"`
	ExtData_           [][]byte             `asn1:"-" json:"-"`
	berOriginal_       []byte               `asn1:"-" json:"-"`
	berSnapshot_       []byte               `asn1:"-" json:"-"`
}

// IncompatibleTerminalParam5 represents the ASN.1 type IncompatibleTerminalParam (SEQUENCE).
type IncompatibleTerminalParam5 struct {
	ExtensionContainer *ExtensionContainer5 `asn1:",optional" json:"ExtensionContainer,omitempty"`
	ExtCount_          int64                `asn1:"-" json:"-"`
	ExtPresent_        []bool               `asn1:"-" json:"-"`
	ExtData_           [][]byte             `asn1:"-" json:"-"`
	berOriginal_       []byte               `asn1:"-" json:"-"`
	berSnapshot_       []byte               `asn1:"-" json:"-"`
}

// ShortTermDenialParam5 represents the ASN.1 type ShortTermDenialParam (SEQUENCE).
type ShortTermDenialParam5 struct {
	ExtCount_    int64    `asn1:"-" json:"-"`
	ExtPresent_  []bool   `asn1:"-" json:"-"`
	ExtData_     [][]byte `asn1:"-" json:"-"`
	berOriginal_ []byte   `asn1:"-" json:"-"`
	berSnapshot_ []byte   `asn1:"-" json:"-"`
}

// LongTermDenialParam5 represents the ASN.1 type LongTermDenialParam (SEQUENCE).
type LongTermDenialParam5 struct {
	ExtCount_    int64    `asn1:"-" json:"-"`
	ExtPresent_  []bool   `asn1:"-" json:"-"`
	ExtData_     [][]byte `asn1:"-" json:"-"`
	berOriginal_ []byte   `asn1:"-" json:"-"`
	berSnapshot_ []byte   `asn1:"-" json:"-"`
}

// UnauthorizedRequestingNetworkParam5 represents the ASN.1 type UnauthorizedRequestingNetwork-Param (SEQUENCE).
type UnauthorizedRequestingNetworkParam5 struct {
	ExtensionContainer *ExtensionContainer5 `asn1:",optional" json:"ExtensionContainer,omitempty"`
	ExtCount_          int64                `asn1:"-" json:"-"`
	ExtPresent_        []bool               `asn1:"-" json:"-"`
	ExtData_           [][]byte             `asn1:"-" json:"-"`
	berOriginal_       []byte               `asn1:"-" json:"-"`
	berSnapshot_       []byte               `asn1:"-" json:"-"`
}

// UnauthorizedLCSClientParam5 represents the ASN.1 type UnauthorizedLCSClient-Param (SEQUENCE).
type UnauthorizedLCSClientParam5 struct {
	UnauthorizedLCSClientDiagnostic *UnauthorizedLCSClientDiagnostic5 `asn1:"tag:0,context,implicit,optional" json:"UnauthorizedLCSClientDiagnostic,omitempty"`
	ExtensionContainer              *ExtensionContainer5              `asn1:"tag:1,context,implicit,optional" json:"ExtensionContainer,omitempty"`
	ExtCount_                       int64                             `asn1:"-" json:"-"`
	ExtPresent_                     []bool                            `asn1:"-" json:"-"`
	ExtData_                        [][]byte                          `asn1:"-" json:"-"`
	berOriginal_                    []byte                            `asn1:"-" json:"-"`
	berSnapshot_                    []byte                            `asn1:"-" json:"-"`
}

// UnauthorizedLCSClientDiagnostic5 represents the ASN.1 ENUMERATED type UnauthorizedLCSClient-Diagnostic.
type UnauthorizedLCSClientDiagnostic5 int64

const (
	UnauthorizedLCSClientDiagnostic5NoAdditionalInformation                        UnauthorizedLCSClientDiagnostic5 = 0
	UnauthorizedLCSClientDiagnostic5ClientNotInMSPrivacyExceptionList              UnauthorizedLCSClientDiagnostic5 = 1
	UnauthorizedLCSClientDiagnostic5CallToClientNotSetup                           UnauthorizedLCSClientDiagnostic5 = 2
	UnauthorizedLCSClientDiagnostic5PrivacyOverrideNotApplicable                   UnauthorizedLCSClientDiagnostic5 = 3
	UnauthorizedLCSClientDiagnostic5DisallowedByLocalRegulatoryRequirements        UnauthorizedLCSClientDiagnostic5 = 4
	UnauthorizedLCSClientDiagnostic5UnauthorizedPrivacyClass                       UnauthorizedLCSClientDiagnostic5 = 5
	UnauthorizedLCSClientDiagnostic5UnauthorizedCallSessionUnrelatedExternalClient UnauthorizedLCSClientDiagnostic5 = 6
	UnauthorizedLCSClientDiagnostic5UnauthorizedCallSessionRelatedExternalClient   UnauthorizedLCSClientDiagnostic5 = 7
)

func (v UnauthorizedLCSClientDiagnostic5) String() string {
	switch v {
	case UnauthorizedLCSClientDiagnostic5NoAdditionalInformation:
		return "noAdditionalInformation"
	case UnauthorizedLCSClientDiagnostic5ClientNotInMSPrivacyExceptionList:
		return "clientNotInMSPrivacyExceptionList"
	case UnauthorizedLCSClientDiagnostic5CallToClientNotSetup:
		return "callToClientNotSetup"
	case UnauthorizedLCSClientDiagnostic5PrivacyOverrideNotApplicable:
		return "privacyOverrideNotApplicable"
	case UnauthorizedLCSClientDiagnostic5DisallowedByLocalRegulatoryRequirements:
		return "disallowedByLocalRegulatoryRequirements"
	case UnauthorizedLCSClientDiagnostic5UnauthorizedPrivacyClass:
		return "unauthorizedPrivacyClass"
	case UnauthorizedLCSClientDiagnostic5UnauthorizedCallSessionUnrelatedExternalClient:
		return "unauthorizedCallSessionUnrelatedExternalClient"
	case UnauthorizedLCSClientDiagnostic5UnauthorizedCallSessionRelatedExternalClient:
		return "unauthorizedCallSessionRelatedExternalClient"
	default:
		return "unknown"
	}
}

// PositionMethodFailureParam5 represents the ASN.1 type PositionMethodFailure-Param (SEQUENCE).
type PositionMethodFailureParam5 struct {
	PositionMethodFailureDiagnostic *PositionMethodFailureDiagnostic5 `asn1:"tag:0,context,implicit,optional" json:"PositionMethodFailureDiagnostic,omitempty"`
	ExtensionContainer              *ExtensionContainer5              `asn1:"tag:1,context,implicit,optional" json:"ExtensionContainer,omitempty"`
	ExtCount_                       int64                             `asn1:"-" json:"-"`
	ExtPresent_                     []bool                            `asn1:"-" json:"-"`
	ExtData_                        [][]byte                          `asn1:"-" json:"-"`
	berOriginal_                    []byte                            `asn1:"-" json:"-"`
	berSnapshot_                    []byte                            `asn1:"-" json:"-"`
}

// PositionMethodFailureDiagnostic5 represents the ASN.1 ENUMERATED type PositionMethodFailure-Diagnostic.
type PositionMethodFailureDiagnostic5 int64

const (
	PositionMethodFailureDiagnostic5Congestion                               PositionMethodFailureDiagnostic5 = 0
	PositionMethodFailureDiagnostic5InsufficientResources                    PositionMethodFailureDiagnostic5 = 1
	PositionMethodFailureDiagnostic5InsufficientMeasurementData              PositionMethodFailureDiagnostic5 = 2
	PositionMethodFailureDiagnostic5InconsistentMeasurementData              PositionMethodFailureDiagnostic5 = 3
	PositionMethodFailureDiagnostic5LocationProcedureNotCompleted            PositionMethodFailureDiagnostic5 = 4
	PositionMethodFailureDiagnostic5LocationProcedureNotSupportedByTargetMS  PositionMethodFailureDiagnostic5 = 5
	PositionMethodFailureDiagnostic5QoSNotAttainable                         PositionMethodFailureDiagnostic5 = 6
	PositionMethodFailureDiagnostic5PositionMethodNotAvailableInNetwork      PositionMethodFailureDiagnostic5 = 7
	PositionMethodFailureDiagnostic5PositionMethodNotAvailableInLocationArea PositionMethodFailureDiagnostic5 = 8
)

func (v PositionMethodFailureDiagnostic5) String() string {
	switch v {
	case PositionMethodFailureDiagnostic5Congestion:
		return "congestion"
	case PositionMethodFailureDiagnostic5InsufficientResources:
		return "insufficientResources"
	case PositionMethodFailureDiagnostic5InsufficientMeasurementData:
		return "insufficientMeasurementData"
	case PositionMethodFailureDiagnostic5InconsistentMeasurementData:
		return "inconsistentMeasurementData"
	case PositionMethodFailureDiagnostic5LocationProcedureNotCompleted:
		return "locationProcedureNotCompleted"
	case PositionMethodFailureDiagnostic5LocationProcedureNotSupportedByTargetMS:
		return "locationProcedureNotSupportedByTargetMS"
	case PositionMethodFailureDiagnostic5QoSNotAttainable:
		return "qoSNotAttainable"
	case PositionMethodFailureDiagnostic5PositionMethodNotAvailableInNetwork:
		return "positionMethodNotAvailableInNetwork"
	case PositionMethodFailureDiagnostic5PositionMethodNotAvailableInLocationArea:
		return "positionMethodNotAvailableInLocationArea"
	default:
		return "unknown"
	}
}

// UnknownOrUnreachableLCSClientParam5 represents the ASN.1 type UnknownOrUnreachableLCSClient-Param (SEQUENCE).
type UnknownOrUnreachableLCSClientParam5 struct {
	ExtensionContainer *ExtensionContainer5 `asn1:",optional" json:"ExtensionContainer,omitempty"`
	ExtCount_          int64                `asn1:"-" json:"-"`
	ExtPresent_        []bool               `asn1:"-" json:"-"`
	ExtData_           [][]byte             `asn1:"-" json:"-"`
	berOriginal_       []byte               `asn1:"-" json:"-"`
	berSnapshot_       []byte               `asn1:"-" json:"-"`
}

// MMEventNotSupportedParam5 represents the ASN.1 type MM-EventNotSupported-Param (SEQUENCE).
type MMEventNotSupportedParam5 struct {
	ExtensionContainer *ExtensionContainer5 `asn1:",optional" json:"ExtensionContainer,omitempty"`
	ExtCount_          int64                `asn1:"-" json:"-"`
	ExtPresent_        []bool               `asn1:"-" json:"-"`
	ExtData_           [][]byte             `asn1:"-" json:"-"`
	berOriginal_       []byte               `asn1:"-" json:"-"`
	berSnapshot_       []byte               `asn1:"-" json:"-"`
}

// TargetCellOutsideGCAParam5 represents the ASN.1 type TargetCellOutsideGCA-Param (SEQUENCE).
type TargetCellOutsideGCAParam5 struct {
	ExtensionContainer *ExtensionContainer5 `asn1:",optional" json:"ExtensionContainer,omitempty"`
	ExtCount_          int64                `asn1:"-" json:"-"`
	ExtPresent_        []bool               `asn1:"-" json:"-"`
	ExtData_           [][]byte             `asn1:"-" json:"-"`
	berOriginal_       []byte               `asn1:"-" json:"-"`
	berSnapshot_       []byte               `asn1:"-" json:"-"`
}

// OngoingGroupCallParam5 represents the ASN.1 type OngoingGroupCallParam (SEQUENCE).
type OngoingGroupCallParam5 struct {
	ExtensionContainer *ExtensionContainer5 `asn1:",optional" json:"ExtensionContainer,omitempty"`
	ExtCount_          int64                `asn1:"-" json:"-"`
	ExtPresent_        []bool               `asn1:"-" json:"-"`
	ExtData_           [][]byte             `asn1:"-" json:"-"`
	berOriginal_       []byte               `asn1:"-" json:"-"`
	berSnapshot_       []byte               `asn1:"-" json:"-"`
}

// MarshalBER encodes RoamingNotAllowedParam5 to BER format.
func (v *RoamingNotAllowedParam5) MarshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: RoamingNotAllowedParam5 receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *RoamingNotAllowedParam5) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	enc_roamingnotallowedcause := ber.EncodeEnumerated(int64(v.RoamingNotAllowedCause))
	children = append(children, enc_roamingnotallowedcause...)
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalBER(opts...)
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
		_, n, _, extErr := ber.DecodeTLV(ext)
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

// MarshalDER encodes RoamingNotAllowedParam5 to DER format.
func (v *RoamingNotAllowedParam5) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: RoamingNotAllowedParam5 receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
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
		return nil, fmt.Errorf("encoding RoamingNotAllowedParam5 as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes RoamingNotAllowedParam5 from BER/DER format.
func (v *RoamingNotAllowedParam5) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: RoamingNotAllowedParam5 destination is nil", ber.ErrInvalidValue)
	}
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = RoamingNotAllowedParam5{}
	defer func() {
		if returnErr != nil || !ber.ConstraintToleranceEnabled(opts) {
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
		return fmt.Errorf("decoding RoamingNotAllowedParam5 SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "RoamingNotAllowedParam5", Cause: ber.ErrExtraData}
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
	v.RoamingNotAllowedCause = RoamingNotAllowedCause5(val_roamingnotallowedcause)
	if offset < 0 || offset >
		len(content) || n < 0 || n > len(content[offset:]) {
		return fmt.Errorf("invalid BER content window")
	}

	offset += n
	// Decode extensionContainer
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassUniversal && peekTag.Number == 16 {
				// Decode nested SEQUENCE (ExtensionContainer5)
				_, n_extensioncontainer, _, tlvErr_extensioncontainer := ber.DecodeTLV(content[offset:], opts...)
				if tlvErr_extensioncontainer != nil {
					return fmt.Errorf("decoding extensionContainer: %w", tlvErr_extensioncontainer)
				}
				var dec_extensioncontainer ExtensionContainer5
				if offset < 0 || offset >
					len(content) || n_extensioncontainer < 0 || n_extensioncontainer >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				if unmErr := dec_extensioncontainer.UnmarshalBER(content[offset:offset+n_extensioncontainer], ber.ChildDecodeOptions(opts, "extensioncontainer")...); unmErr != nil {
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
				tmp_additionalroamingnotallowedcause := AdditionalRoamingNotAllowedCause5(decVal_additionalroamingnotallowedcause)
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
			return &ber.DecodeError{Offset: offset, TypeName: "RoamingNotAllowedParam5", Cause: extErr_}
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

// MarshalBER encodes CallBarredParam5 to BER format.
func (v *CallBarredParam5) MarshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: CallBarredParam5 receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *CallBarredParam5) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	switch v.Choice {
	case CallBarredParam5ChoiceCallBarringCause:
		if v.CallBarringCause == nil {
			return nil, fmt.Errorf("%w: choice CallBarredParam5: callBarringCause is nil", ber.ErrInvalidValue)
		}
		enc_0 := ber.EncodeEnumerated(int64(*v.CallBarringCause))
		return enc_0, nil
	case CallBarredParam5ChoiceExtensibleCallBarredParam:
		if v.ExtensibleCallBarredParam == nil {
			return nil, fmt.Errorf("%w: choice CallBarredParam5: extensibleCallBarredParam is nil", ber.ErrInvalidValue)
		}
		enc_1, err := v.ExtensibleCallBarredParam.MarshalBER(opts...)
		if err != nil {
			return nil, fmt.Errorf("encoding extensibleCallBarredParam: %w", err)
		}
		return enc_1, nil
	default:
		return nil, fmt.Errorf("unknown choice %d for CallBarredParam5", v.Choice)
	}
}

// MarshalDER encodes CallBarredParam5 to DER format.
func (v *CallBarredParam5) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: CallBarredParam5 receiver is nil", ber.ErrInvalidValue)
	}
	switch v.Choice {
	case CallBarredParam5ChoiceExtensibleCallBarredParam:
		if v.ExtensibleCallBarredParam == nil {
			return nil, fmt.Errorf("%w: choice CallBarredParam5: extensibleCallBarredParam is nil", ber.ErrInvalidValue)
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
	encoded, err := v.MarshalBER()
	if err != nil {
		return nil, err
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding CallBarredParam5 as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes CallBarredParam5 from BER/DER format.
func (v *CallBarredParam5) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: CallBarredParam5 destination is nil", ber.ErrInvalidValue)
	}
	defer func() {
		if returnErr != nil || !ber.ConstraintToleranceEnabled(opts) {
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
	*v = CallBarredParam5{}
	if len(data) == 0 {
		return fmt.Errorf("empty data for CallBarredParam5 CHOICE")
	}
	choiceData := data
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for CallBarredParam5: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData, opts...)
	if tlvErr != nil {
		return fmt.Errorf("decoding CallBarredParam5 CHOICE: %w", tlvErr)
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "CallBarredParam5", Cause: ber.ErrExtraData}
	}

	if peekTag.Class == tag.ClassUniversal && peekTag.Number == 10 && peekTag.Constructed == false {
		v.Choice = CallBarredParam5ChoiceCallBarringCause
		decVal, _, intErr := ber.DecodeEnumerated(choiceData, opts...)
		if intErr != nil {
			return fmt.Errorf("decoding callBarringCause: %w", intErr)
		}
		tmp := CallBarringCause5(decVal)
		v.CallBarringCause = &tmp
	} else if peekTag.Class == tag.ClassUniversal && peekTag.Number == 16 && peekTag.Constructed == true {
		v.Choice = CallBarredParam5ChoiceExtensibleCallBarredParam
		var dec ExtensibleCallBarredParam5
		if unmErr := dec.UnmarshalBER(choiceData, opts...); unmErr != nil {
			return fmt.Errorf("decoding extensibleCallBarredParam: %w", unmErr)
		}
		v.ExtensibleCallBarredParam = &dec
	} else {
		return fmt.Errorf("unknown tag %s for CallBarredParam5 CHOICE", peekTag)
	}
	return nil
}

// MarshalBER encodes ExtensibleCallBarredParam5 to BER format.
func (v *ExtensibleCallBarredParam5) MarshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: ExtensibleCallBarredParam5 receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *ExtensibleCallBarredParam5) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if v.CallBarringCause != nil {
		enc_callbarringcause := ber.EncodeEnumerated(int64(*v.CallBarringCause))
		children = append(children, enc_callbarringcause...)
	}
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalBER(opts...)
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
	return ber.EncodeSequence(children)
}

// MarshalDER encodes ExtensibleCallBarredParam5 to DER format.
func (v *ExtensibleCallBarredParam5) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: ExtensibleCallBarredParam5 receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if v.CallBarringCause != nil {
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
		return nil, fmt.Errorf("encoding ExtensibleCallBarredParam5 as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes ExtensibleCallBarredParam5 from BER/DER format.
func (v *ExtensibleCallBarredParam5) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: ExtensibleCallBarredParam5 destination is nil", ber.ErrInvalidValue)
	}
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = ExtensibleCallBarredParam5{}
	defer func() {
		if returnErr != nil || !ber.ConstraintToleranceEnabled(opts) {
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
		return fmt.Errorf("decoding ExtensibleCallBarredParam5 SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "ExtensibleCallBarredParam5", Cause: ber.ErrExtraData}
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
				tmp_callbarringcause := CallBarringCause5(val_callbarringcause)
				v.CallBarringCause = &tmp_callbarringcause
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
				// Decode nested SEQUENCE (ExtensionContainer5)
				_, n_extensioncontainer, _, tlvErr_extensioncontainer := ber.DecodeTLV(content[offset:], opts...)
				if tlvErr_extensioncontainer != nil {
					return fmt.Errorf("decoding extensionContainer: %w", tlvErr_extensioncontainer)
				}
				var dec_extensioncontainer ExtensionContainer5
				if offset < 0 || offset >
					len(content) || n_extensioncontainer < 0 || n_extensioncontainer >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				if unmErr := dec_extensioncontainer.UnmarshalBER(content[offset:offset+n_extensioncontainer], ber.ChildDecodeOptions(opts, "extensioncontainer")...); unmErr != nil {
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
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:], opts...)
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "ExtensibleCallBarredParam5", Cause: extErr_}
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

// MarshalBER encodes CUGRejectParam5 to BER format.
func (v *CUGRejectParam5) MarshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: CUGRejectParam5 receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *CUGRejectParam5) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if v.CugRejectCause != nil {
		enc_cugrejectcause := ber.EncodeEnumerated(int64(*v.CugRejectCause))
		children = append(children, enc_cugrejectcause...)
	}
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalBER(opts...)
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
	return ber.EncodeSequence(children)
}

// MarshalDER encodes CUGRejectParam5 to DER format.
func (v *CUGRejectParam5) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: CUGRejectParam5 receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if v.CugRejectCause != nil {
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
		return nil, fmt.Errorf("encoding CUGRejectParam5 as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes CUGRejectParam5 from BER/DER format.
func (v *CUGRejectParam5) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: CUGRejectParam5 destination is nil", ber.ErrInvalidValue)
	}
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = CUGRejectParam5{}
	defer func() {
		if returnErr != nil || !ber.ConstraintToleranceEnabled(opts) {
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
		return fmt.Errorf("decoding CUGRejectParam5 SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "CUGRejectParam5", Cause: ber.ErrExtraData}
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
				tmp_cugrejectcause := CUGRejectCause5(val_cugrejectcause)
				v.CugRejectCause = &tmp_cugrejectcause
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
				// Decode nested SEQUENCE (ExtensionContainer5)
				_, n_extensioncontainer, _, tlvErr_extensioncontainer := ber.DecodeTLV(content[offset:], opts...)
				if tlvErr_extensioncontainer != nil {
					return fmt.Errorf("decoding extensionContainer: %w", tlvErr_extensioncontainer)
				}
				var dec_extensioncontainer ExtensionContainer5
				if offset < 0 || offset >
					len(content) || n_extensioncontainer < 0 || n_extensioncontainer >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				if unmErr := dec_extensioncontainer.UnmarshalBER(content[offset:offset+n_extensioncontainer], ber.ChildDecodeOptions(opts, "extensioncontainer")...); unmErr != nil {
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
			return &ber.DecodeError{Offset: offset, TypeName: "CUGRejectParam5", Cause: extErr_}
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

// MarshalBER encodes SSIncompatibilityCause5 to BER format.
func (v *SSIncompatibilityCause5) MarshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: SSIncompatibilityCause5 receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *SSIncompatibilityCause5) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
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
		enc_basicservice, err := v.BasicService.MarshalBER(opts...)
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
		_, n, _, extErr := ber.DecodeTLV(ext)
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

// MarshalDER encodes SSIncompatibilityCause5 to DER format.
func (v *SSIncompatibilityCause5) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: SSIncompatibilityCause5 receiver is nil", ber.ErrInvalidValue)
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
		return nil, fmt.Errorf("encoding SSIncompatibilityCause5 as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes SSIncompatibilityCause5 from BER/DER format.
func (v *SSIncompatibilityCause5) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: SSIncompatibilityCause5 destination is nil", ber.ErrInvalidValue)
	}
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = SSIncompatibilityCause5{}
	defer func() {
		if returnErr != nil || !ber.ConstraintToleranceEnabled(opts) {
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
		return fmt.Errorf("decoding SSIncompatibilityCause5 SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "SSIncompatibilityCause5", Cause: ber.ErrExtraData}
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
				tmp_sscode := SSCode5(rawVal_sscode)
				v.SsCode = &tmp_sscode
				if offset < 0 || offset >
					len(content) || n_sscode < 0 || n_sscode > len(content[offset:]) {
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
				// Decode nested CHOICE (BasicServiceCode5)
				_, n_basicservice, _, tlvErr_basicservice := ber.DecodeTLV(content[offset:], opts...)
				if tlvErr_basicservice != nil {
					return fmt.Errorf("decoding basicService: %w", tlvErr_basicservice)
				}
				var dec_basicservice BasicServiceCode5
				if offset < 0 || offset >
					len(content) || n_basicservice < 0 || n_basicservice > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				if unmErr := dec_basicservice.UnmarshalBER(content[offset:offset+n_basicservice], ber.ChildDecodeOptions(opts, "basicservice")...); unmErr != nil {
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
				tmp_ssstatus := SSStatus5(rawVal_ssstatus)
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
			return &ber.DecodeError{Offset: offset, TypeName: "SSIncompatibilityCause5", Cause: extErr_}
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

// MarshalBER encodes SMDeliveryFailureCause5 to BER format.
func (v *SMDeliveryFailureCause5) MarshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: SMDeliveryFailureCause5 receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *SMDeliveryFailureCause5) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
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
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalBER(opts...)
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
	return ber.EncodeSequence(children)
}

// MarshalDER encodes SMDeliveryFailureCause5 to DER format.
func (v *SMDeliveryFailureCause5) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: SMDeliveryFailureCause5 receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
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
		return nil, fmt.Errorf("encoding SMDeliveryFailureCause5 as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes SMDeliveryFailureCause5 from BER/DER format.
func (v *SMDeliveryFailureCause5) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: SMDeliveryFailureCause5 destination is nil", ber.ErrInvalidValue)
	}
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = SMDeliveryFailureCause5{}
	defer func() {
		if returnErr != nil || !ber.ConstraintToleranceEnabled(opts) {
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
		return fmt.Errorf("decoding SMDeliveryFailureCause5 SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "SMDeliveryFailureCause5", Cause: ber.ErrExtraData}
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
	v.SmEnumeratedDeliveryFailureCause = SMEnumeratedDeliveryFailureCause5(val_smenumerateddeliveryfailurecause)
	if offset < 0 || offset >
		len(content) || n < 0 || n > len(content[offset:]) {
		return fmt.Errorf("invalid BER content window")
	}

	offset += n
	// Decode diagnosticInfo
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassUniversal && peekTag.Number == 4 {
				val_diagnosticinfo, n, err := ber.DecodeOctetString(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding diagnosticInfo: %w", err)
				}
				tmp_diagnosticinfo := SignalInfo5(val_diagnosticinfo)
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
				// Decode nested SEQUENCE (ExtensionContainer5)
				_, n_extensioncontainer, _, tlvErr_extensioncontainer := ber.DecodeTLV(content[offset:], opts...)
				if tlvErr_extensioncontainer != nil {
					return fmt.Errorf("decoding extensionContainer: %w", tlvErr_extensioncontainer)
				}
				var dec_extensioncontainer ExtensionContainer5
				if offset < 0 || offset >
					len(content) || n_extensioncontainer < 0 || n_extensioncontainer >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				if unmErr := dec_extensioncontainer.UnmarshalBER(content[offset:offset+n_extensioncontainer], ber.ChildDecodeOptions(opts, "extensioncontainer")...); unmErr != nil {
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
			return &ber.DecodeError{Offset: offset, TypeName: "SMDeliveryFailureCause5", Cause: extErr_}
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

// MarshalBER encodes AbsentSubscriberSMParam5 to BER format.
func (v *AbsentSubscriberSMParam5) MarshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: AbsentSubscriberSMParam5 receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *AbsentSubscriberSMParam5) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
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
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalBER(opts...)
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
	return ber.EncodeSequence(children)
}

// MarshalDER encodes AbsentSubscriberSMParam5 to DER format.
func (v *AbsentSubscriberSMParam5) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: AbsentSubscriberSMParam5 receiver is nil", ber.ErrInvalidValue)
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
		return nil, fmt.Errorf("encoding AbsentSubscriberSMParam5 as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes AbsentSubscriberSMParam5 from BER/DER format.
func (v *AbsentSubscriberSMParam5) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: AbsentSubscriberSMParam5 destination is nil", ber.ErrInvalidValue)
	}
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = AbsentSubscriberSMParam5{}
	defer func() {
		if returnErr != nil || !ber.ConstraintToleranceEnabled(opts) {
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
		return fmt.Errorf("decoding AbsentSubscriberSMParam5 SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "AbsentSubscriberSMParam5", Cause: ber.ErrExtraData}
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
				tmp_absentsubscriberdiagnosticsm := AbsentSubscriberDiagnosticSM5(val_absentsubscriberdiagnosticsm)
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
	// Decode extensionContainer
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassUniversal && peekTag.Number == 16 {
				// Decode nested SEQUENCE (ExtensionContainer5)
				_, n_extensioncontainer, _, tlvErr_extensioncontainer := ber.DecodeTLV(content[offset:], opts...)
				if tlvErr_extensioncontainer != nil {
					return fmt.Errorf("decoding extensionContainer: %w", tlvErr_extensioncontainer)
				}
				var dec_extensioncontainer ExtensionContainer5
				if offset < 0 || offset >
					len(content) || n_extensioncontainer < 0 || n_extensioncontainer >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				if unmErr := dec_extensioncontainer.UnmarshalBER(content[offset:offset+n_extensioncontainer], ber.ChildDecodeOptions(opts, "extensioncontainer")...); unmErr != nil {
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
				tmp_additionalabsentsubscriberdiagnosticsm := AbsentSubscriberDiagnosticSM5(decVal_additionalabsentsubscriberdiagnosticsm)
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
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:], opts...)
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "AbsentSubscriberSMParam5", Cause: extErr_}
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

// MarshalBER encodes SystemFailureParam5 to BER format.
func (v *SystemFailureParam5) MarshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: SystemFailureParam5 receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *SystemFailureParam5) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	switch v.Choice {
	case SystemFailureParam5ChoiceNetworkResource:
		if v.NetworkResource == nil {
			return nil, fmt.Errorf("%w: choice SystemFailureParam5: networkResource is nil", ber.ErrInvalidValue)
		}
		enc_0 := ber.EncodeEnumerated(int64(*v.NetworkResource))
		return enc_0, nil
	case SystemFailureParam5ChoiceExtensibleSystemFailureParam:
		if v.ExtensibleSystemFailureParam == nil {
			return nil, fmt.Errorf("%w: choice SystemFailureParam5: extensibleSystemFailureParam is nil", ber.ErrInvalidValue)
		}
		enc_1, err := v.ExtensibleSystemFailureParam.MarshalBER(opts...)
		if err != nil {
			return nil, fmt.Errorf("encoding extensibleSystemFailureParam: %w", err)
		}
		return enc_1, nil
	default:
		return nil, fmt.Errorf("unknown choice %d for SystemFailureParam5", v.Choice)
	}
}

// MarshalDER encodes SystemFailureParam5 to DER format.
func (v *SystemFailureParam5) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: SystemFailureParam5 receiver is nil", ber.ErrInvalidValue)
	}
	switch v.Choice {
	case SystemFailureParam5ChoiceExtensibleSystemFailureParam:
		if v.ExtensibleSystemFailureParam == nil {
			return nil, fmt.Errorf("%w: choice SystemFailureParam5: extensibleSystemFailureParam is nil", ber.ErrInvalidValue)
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
	encoded, err := v.MarshalBER()
	if err != nil {
		return nil, err
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding SystemFailureParam5 as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes SystemFailureParam5 from BER/DER format.
func (v *SystemFailureParam5) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: SystemFailureParam5 destination is nil", ber.ErrInvalidValue)
	}
	defer func() {
		if returnErr != nil || !ber.ConstraintToleranceEnabled(opts) {
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
	*v = SystemFailureParam5{}
	if len(data) == 0 {
		return fmt.Errorf("empty data for SystemFailureParam5 CHOICE")
	}
	choiceData := data
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for SystemFailureParam5: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData, opts...)
	if tlvErr != nil {
		return fmt.Errorf("decoding SystemFailureParam5 CHOICE: %w", tlvErr)
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "SystemFailureParam5", Cause: ber.ErrExtraData}
	}

	if peekTag.Class == tag.ClassUniversal && peekTag.Number == 10 && peekTag.Constructed == false {
		v.Choice = SystemFailureParam5ChoiceNetworkResource
		decVal, _, intErr := ber.DecodeEnumerated(choiceData, opts...)
		if intErr != nil {
			return fmt.Errorf("decoding networkResource: %w", intErr)
		}
		tmp := NetworkResource5(decVal)
		v.NetworkResource = &tmp
	} else if peekTag.Class == tag.ClassUniversal && peekTag.Number == 16 && peekTag.Constructed == true {
		v.Choice = SystemFailureParam5ChoiceExtensibleSystemFailureParam
		var dec ExtensibleSystemFailureParam5
		if unmErr := dec.UnmarshalBER(choiceData, opts...); unmErr != nil {
			return fmt.Errorf("decoding extensibleSystemFailureParam: %w", unmErr)
		}
		v.ExtensibleSystemFailureParam = &dec
	} else {
		return fmt.Errorf("unknown tag %s for SystemFailureParam5 CHOICE", peekTag)
	}
	return nil
}

// MarshalBER encodes ExtensibleSystemFailureParam5 to BER format.
func (v *ExtensibleSystemFailureParam5) MarshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: ExtensibleSystemFailureParam5 receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *ExtensibleSystemFailureParam5) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if v.NetworkResource != nil {
		enc_networkresource := ber.EncodeEnumerated(int64(*v.NetworkResource))
		children = append(children, enc_networkresource...)
	}
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalBER(opts...)
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
		_, n, _, extErr := ber.DecodeTLV(ext)
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

// MarshalDER encodes ExtensibleSystemFailureParam5 to DER format.
func (v *ExtensibleSystemFailureParam5) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: ExtensibleSystemFailureParam5 receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if v.NetworkResource != nil {
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
		return nil, fmt.Errorf("encoding ExtensibleSystemFailureParam5 as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes ExtensibleSystemFailureParam5 from BER/DER format.
func (v *ExtensibleSystemFailureParam5) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: ExtensibleSystemFailureParam5 destination is nil", ber.ErrInvalidValue)
	}
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = ExtensibleSystemFailureParam5{}
	defer func() {
		if returnErr != nil || !ber.ConstraintToleranceEnabled(opts) {
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
		return fmt.Errorf("decoding ExtensibleSystemFailureParam5 SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "ExtensibleSystemFailureParam5", Cause: ber.ErrExtraData}
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
				tmp_networkresource := NetworkResource5(val_networkresource)
				v.NetworkResource = &tmp_networkresource
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
				// Decode nested SEQUENCE (ExtensionContainer5)
				_, n_extensioncontainer, _, tlvErr_extensioncontainer := ber.DecodeTLV(content[offset:], opts...)
				if tlvErr_extensioncontainer != nil {
					return fmt.Errorf("decoding extensionContainer: %w", tlvErr_extensioncontainer)
				}
				var dec_extensioncontainer ExtensionContainer5
				if offset < 0 || offset >
					len(content) || n_extensioncontainer < 0 || n_extensioncontainer > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				if unmErr := dec_extensioncontainer.UnmarshalBER(content[offset:offset+n_extensioncontainer], ber.ChildDecodeOptions(opts, "extensioncontainer")...); unmErr != nil {
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
				tmp_additionalnetworkresource := AdditionalNetworkResource5(decVal_additionalnetworkresource)
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
				tmp_failurecauseparam := FailureCauseParam4(decVal_failurecauseparam)
				v.FailureCauseParam = &tmp_failurecauseparam
				if offset < 0 || offset >
					len(content) || n_failurecauseparam < 0 || n_failurecauseparam > len(content[offset:]) {
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
			return &ber.DecodeError{Offset: offset, TypeName: "ExtensibleSystemFailureParam5", Cause: extErr_}
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

// MarshalBER encodes DataMissingParam5 to BER format.
func (v *DataMissingParam5) MarshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: DataMissingParam5 receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *DataMissingParam5) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalBER(opts...)
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
	return ber.EncodeSequence(children)
}

// MarshalDER encodes DataMissingParam5 to DER format.
func (v *DataMissingParam5) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: DataMissingParam5 receiver is nil", ber.ErrInvalidValue)
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
		return nil, fmt.Errorf("encoding DataMissingParam5 as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes DataMissingParam5 from BER/DER format.
func (v *DataMissingParam5) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: DataMissingParam5 destination is nil", ber.ErrInvalidValue)
	}
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = DataMissingParam5{}
	defer func() {
		if returnErr != nil || !ber.ConstraintToleranceEnabled(opts) {
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
		return fmt.Errorf("decoding DataMissingParam5 SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "DataMissingParam5", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode extensionContainer
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassUniversal && peekTag.Number == 16 {
				// Decode nested SEQUENCE (ExtensionContainer5)
				_, n_extensioncontainer, _, tlvErr_extensioncontainer := ber.DecodeTLV(content[offset:], opts...)
				if tlvErr_extensioncontainer != nil {
					return fmt.Errorf("decoding extensionContainer: %w", tlvErr_extensioncontainer)
				}
				var dec_extensioncontainer ExtensionContainer5
				if offset < 0 || offset >
					len(content) || n_extensioncontainer < 0 || n_extensioncontainer >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				if unmErr := dec_extensioncontainer.UnmarshalBER(content[offset:offset+n_extensioncontainer], ber.ChildDecodeOptions(opts, "extensioncontainer")...); unmErr != nil {
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
			return &ber.DecodeError{Offset: offset, TypeName: "DataMissingParam5", Cause: extErr_}
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

// MarshalBER encodes UnexpectedDataParam5 to BER format.
func (v *UnexpectedDataParam5) MarshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: UnexpectedDataParam5 receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *UnexpectedDataParam5) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalBER(opts...)
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
	return ber.EncodeSequence(children)
}

// MarshalDER encodes UnexpectedDataParam5 to DER format.
func (v *UnexpectedDataParam5) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: UnexpectedDataParam5 receiver is nil", ber.ErrInvalidValue)
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
		return nil, fmt.Errorf("encoding UnexpectedDataParam5 as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes UnexpectedDataParam5 from BER/DER format.
func (v *UnexpectedDataParam5) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: UnexpectedDataParam5 destination is nil", ber.ErrInvalidValue)
	}
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = UnexpectedDataParam5{}
	defer func() {
		if returnErr != nil || !ber.ConstraintToleranceEnabled(opts) {
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
		return fmt.Errorf("decoding UnexpectedDataParam5 SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "UnexpectedDataParam5", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode extensionContainer
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassUniversal && peekTag.Number == 16 {
				// Decode nested SEQUENCE (ExtensionContainer5)
				_, n_extensioncontainer, _, tlvErr_extensioncontainer := ber.DecodeTLV(content[offset:], opts...)
				if tlvErr_extensioncontainer != nil {
					return fmt.Errorf("decoding extensionContainer: %w", tlvErr_extensioncontainer)
				}
				var dec_extensioncontainer ExtensionContainer5
				if offset < 0 || offset >
					len(content) || n_extensioncontainer < 0 || n_extensioncontainer >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				if unmErr := dec_extensioncontainer.UnmarshalBER(content[offset:offset+n_extensioncontainer], ber.ChildDecodeOptions(opts, "extensioncontainer")...); unmErr != nil {
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
			return &ber.DecodeError{Offset: offset, TypeName: "UnexpectedDataParam5", Cause: extErr_}
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

// MarshalBER encodes FacilityNotSupParam5 to BER format.
func (v *FacilityNotSupParam5) MarshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: FacilityNotSupParam5 receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *FacilityNotSupParam5) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalBER(opts...)
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
		_, n, _, extErr := ber.DecodeTLV(ext)
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

// MarshalDER encodes FacilityNotSupParam5 to DER format.
func (v *FacilityNotSupParam5) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: FacilityNotSupParam5 receiver is nil", ber.ErrInvalidValue)
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
		return nil, fmt.Errorf("encoding FacilityNotSupParam5 as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes FacilityNotSupParam5 from BER/DER format.
func (v *FacilityNotSupParam5) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: FacilityNotSupParam5 destination is nil", ber.ErrInvalidValue)
	}
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = FacilityNotSupParam5{}
	defer func() {
		if returnErr != nil || !ber.ConstraintToleranceEnabled(opts) {
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
		return fmt.Errorf("decoding FacilityNotSupParam5 SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "FacilityNotSupParam5", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode extensionContainer
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassUniversal && peekTag.Number == 16 {
				// Decode nested SEQUENCE (ExtensionContainer5)
				_, n_extensioncontainer, _, tlvErr_extensioncontainer := ber.DecodeTLV(content[offset:], opts...)
				if tlvErr_extensioncontainer != nil {
					return fmt.Errorf("decoding extensionContainer: %w", tlvErr_extensioncontainer)
				}
				var dec_extensioncontainer ExtensionContainer5
				if offset < 0 || offset >
					len(content) || n_extensioncontainer < 0 || n_extensioncontainer >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				if unmErr := dec_extensioncontainer.UnmarshalBER(content[offset:offset+n_extensioncontainer], ber.ChildDecodeOptions(opts, "extensioncontainer")...); unmErr != nil {
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
			return &ber.DecodeError{Offset: offset, TypeName: "FacilityNotSupParam5", Cause: extErr_}
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

// MarshalBER encodes ORNotAllowedParam5 to BER format.
func (v *ORNotAllowedParam5) MarshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: ORNotAllowedParam5 receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *ORNotAllowedParam5) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalBER(opts...)
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
	return ber.EncodeSequence(children)
}

// MarshalDER encodes ORNotAllowedParam5 to DER format.
func (v *ORNotAllowedParam5) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: ORNotAllowedParam5 receiver is nil", ber.ErrInvalidValue)
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
		return nil, fmt.Errorf("encoding ORNotAllowedParam5 as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes ORNotAllowedParam5 from BER/DER format.
func (v *ORNotAllowedParam5) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: ORNotAllowedParam5 destination is nil", ber.ErrInvalidValue)
	}
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = ORNotAllowedParam5{}
	defer func() {
		if returnErr != nil || !ber.ConstraintToleranceEnabled(opts) {
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
		return fmt.Errorf("decoding ORNotAllowedParam5 SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "ORNotAllowedParam5", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode extensionContainer
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassUniversal && peekTag.Number == 16 {
				// Decode nested SEQUENCE (ExtensionContainer5)
				_, n_extensioncontainer, _, tlvErr_extensioncontainer := ber.DecodeTLV(content[offset:], opts...)
				if tlvErr_extensioncontainer != nil {
					return fmt.Errorf("decoding extensionContainer: %w", tlvErr_extensioncontainer)
				}
				var dec_extensioncontainer ExtensionContainer5
				if offset < 0 || offset >
					len(content) || n_extensioncontainer < 0 || n_extensioncontainer >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				if unmErr := dec_extensioncontainer.UnmarshalBER(content[offset:offset+n_extensioncontainer], ber.ChildDecodeOptions(opts, "extensioncontainer")...); unmErr != nil {
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
			return &ber.DecodeError{Offset: offset, TypeName: "ORNotAllowedParam5", Cause: extErr_}
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

// MarshalBER encodes UnknownSubscriberParam5 to BER format.
func (v *UnknownSubscriberParam5) MarshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: UnknownSubscriberParam5 receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *UnknownSubscriberParam5) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalBER(opts...)
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
		_, n, _, extErr := ber.DecodeTLV(ext)
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

// MarshalDER encodes UnknownSubscriberParam5 to DER format.
func (v *UnknownSubscriberParam5) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: UnknownSubscriberParam5 receiver is nil", ber.ErrInvalidValue)
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
		return nil, fmt.Errorf("encoding UnknownSubscriberParam5 as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes UnknownSubscriberParam5 from BER/DER format.
func (v *UnknownSubscriberParam5) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: UnknownSubscriberParam5 destination is nil", ber.ErrInvalidValue)
	}
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = UnknownSubscriberParam5{}
	defer func() {
		if returnErr != nil || !ber.ConstraintToleranceEnabled(opts) {
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
		return fmt.Errorf("decoding UnknownSubscriberParam5 SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "UnknownSubscriberParam5", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode extensionContainer
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassUniversal && peekTag.Number == 16 {
				// Decode nested SEQUENCE (ExtensionContainer5)
				_, n_extensioncontainer, _, tlvErr_extensioncontainer := ber.DecodeTLV(content[offset:], opts...)
				if tlvErr_extensioncontainer != nil {
					return fmt.Errorf("decoding extensionContainer: %w", tlvErr_extensioncontainer)
				}
				var dec_extensioncontainer ExtensionContainer5
				if offset < 0 || offset >
					len(content) || n_extensioncontainer < 0 || n_extensioncontainer >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				if unmErr := dec_extensioncontainer.UnmarshalBER(content[offset:offset+n_extensioncontainer], ber.ChildDecodeOptions(opts, "extensioncontainer")...); unmErr != nil {
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
	// Decode unknownSubscriberDiagnostic
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassUniversal && peekTag.Number == 10 {
				val_unknownsubscriberdiagnostic, n, err := ber.DecodeEnumerated(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding unknownSubscriberDiagnostic: %w", err)
				}
				tmp_unknownsubscriberdiagnostic := UnknownSubscriberDiagnostic5(val_unknownsubscriberdiagnostic)
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
			return &ber.DecodeError{Offset: offset, TypeName: "UnknownSubscriberParam5", Cause: extErr_}
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

// MarshalBER encodes NumberChangedParam5 to BER format.
func (v *NumberChangedParam5) MarshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: NumberChangedParam5 receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *NumberChangedParam5) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalBER(opts...)
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
	return ber.EncodeSequence(children)
}

// MarshalDER encodes NumberChangedParam5 to DER format.
func (v *NumberChangedParam5) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: NumberChangedParam5 receiver is nil", ber.ErrInvalidValue)
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
		return nil, fmt.Errorf("encoding NumberChangedParam5 as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes NumberChangedParam5 from BER/DER format.
func (v *NumberChangedParam5) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: NumberChangedParam5 destination is nil", ber.ErrInvalidValue)
	}
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = NumberChangedParam5{}
	defer func() {
		if returnErr != nil || !ber.ConstraintToleranceEnabled(opts) {
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
		return fmt.Errorf("decoding NumberChangedParam5 SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "NumberChangedParam5", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode extensionContainer
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassUniversal && peekTag.Number == 16 {
				// Decode nested SEQUENCE (ExtensionContainer5)
				_, n_extensioncontainer, _, tlvErr_extensioncontainer := ber.DecodeTLV(content[offset:], opts...)
				if tlvErr_extensioncontainer != nil {
					return fmt.Errorf("decoding extensionContainer: %w", tlvErr_extensioncontainer)
				}
				var dec_extensioncontainer ExtensionContainer5
				if offset < 0 || offset >
					len(content) || n_extensioncontainer < 0 || n_extensioncontainer >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				if unmErr := dec_extensioncontainer.UnmarshalBER(content[offset:offset+n_extensioncontainer], ber.ChildDecodeOptions(opts, "extensioncontainer")...); unmErr != nil {
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
			return &ber.DecodeError{Offset: offset, TypeName: "NumberChangedParam5", Cause: extErr_}
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

// MarshalBER encodes UnidentifiedSubParam5 to BER format.
func (v *UnidentifiedSubParam5) MarshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: UnidentifiedSubParam5 receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *UnidentifiedSubParam5) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalBER(opts...)
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
	return ber.EncodeSequence(children)
}

// MarshalDER encodes UnidentifiedSubParam5 to DER format.
func (v *UnidentifiedSubParam5) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: UnidentifiedSubParam5 receiver is nil", ber.ErrInvalidValue)
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
		return nil, fmt.Errorf("encoding UnidentifiedSubParam5 as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes UnidentifiedSubParam5 from BER/DER format.
func (v *UnidentifiedSubParam5) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: UnidentifiedSubParam5 destination is nil", ber.ErrInvalidValue)
	}
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = UnidentifiedSubParam5{}
	defer func() {
		if returnErr != nil || !ber.ConstraintToleranceEnabled(opts) {
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
		return fmt.Errorf("decoding UnidentifiedSubParam5 SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "UnidentifiedSubParam5", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode extensionContainer
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassUniversal && peekTag.Number == 16 {
				// Decode nested SEQUENCE (ExtensionContainer5)
				_, n_extensioncontainer, _, tlvErr_extensioncontainer := ber.DecodeTLV(content[offset:], opts...)
				if tlvErr_extensioncontainer != nil {
					return fmt.Errorf("decoding extensionContainer: %w", tlvErr_extensioncontainer)
				}
				var dec_extensioncontainer ExtensionContainer5
				if offset < 0 || offset >
					len(content) || n_extensioncontainer < 0 || n_extensioncontainer >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				if unmErr := dec_extensioncontainer.UnmarshalBER(content[offset:offset+n_extensioncontainer], ber.ChildDecodeOptions(opts, "extensioncontainer")...); unmErr != nil {
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
			return &ber.DecodeError{Offset: offset, TypeName: "UnidentifiedSubParam5", Cause: extErr_}
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

// MarshalBER encodes IllegalSubscriberParam5 to BER format.
func (v *IllegalSubscriberParam5) MarshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: IllegalSubscriberParam5 receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *IllegalSubscriberParam5) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalBER(opts...)
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
	return ber.EncodeSequence(children)
}

// MarshalDER encodes IllegalSubscriberParam5 to DER format.
func (v *IllegalSubscriberParam5) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: IllegalSubscriberParam5 receiver is nil", ber.ErrInvalidValue)
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
		return nil, fmt.Errorf("encoding IllegalSubscriberParam5 as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes IllegalSubscriberParam5 from BER/DER format.
func (v *IllegalSubscriberParam5) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: IllegalSubscriberParam5 destination is nil", ber.ErrInvalidValue)
	}
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = IllegalSubscriberParam5{}
	defer func() {
		if returnErr != nil || !ber.ConstraintToleranceEnabled(opts) {
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
		return fmt.Errorf("decoding IllegalSubscriberParam5 SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "IllegalSubscriberParam5", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode extensionContainer
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassUniversal && peekTag.Number == 16 {
				// Decode nested SEQUENCE (ExtensionContainer5)
				_, n_extensioncontainer, _, tlvErr_extensioncontainer := ber.DecodeTLV(content[offset:], opts...)
				if tlvErr_extensioncontainer != nil {
					return fmt.Errorf("decoding extensionContainer: %w", tlvErr_extensioncontainer)
				}
				var dec_extensioncontainer ExtensionContainer5
				if offset < 0 || offset >
					len(content) || n_extensioncontainer < 0 || n_extensioncontainer >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				if unmErr := dec_extensioncontainer.UnmarshalBER(content[offset:offset+n_extensioncontainer], ber.ChildDecodeOptions(opts, "extensioncontainer")...); unmErr != nil {
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
			return &ber.DecodeError{Offset: offset, TypeName: "IllegalSubscriberParam5", Cause: extErr_}
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

// MarshalBER encodes IllegalEquipmentParam5 to BER format.
func (v *IllegalEquipmentParam5) MarshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: IllegalEquipmentParam5 receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *IllegalEquipmentParam5) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalBER(opts...)
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
	return ber.EncodeSequence(children)
}

// MarshalDER encodes IllegalEquipmentParam5 to DER format.
func (v *IllegalEquipmentParam5) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: IllegalEquipmentParam5 receiver is nil", ber.ErrInvalidValue)
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
		return nil, fmt.Errorf("encoding IllegalEquipmentParam5 as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes IllegalEquipmentParam5 from BER/DER format.
func (v *IllegalEquipmentParam5) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: IllegalEquipmentParam5 destination is nil", ber.ErrInvalidValue)
	}
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = IllegalEquipmentParam5{}
	defer func() {
		if returnErr != nil || !ber.ConstraintToleranceEnabled(opts) {
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
		return fmt.Errorf("decoding IllegalEquipmentParam5 SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "IllegalEquipmentParam5", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode extensionContainer
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassUniversal && peekTag.Number == 16 {
				// Decode nested SEQUENCE (ExtensionContainer5)
				_, n_extensioncontainer, _, tlvErr_extensioncontainer := ber.DecodeTLV(content[offset:], opts...)
				if tlvErr_extensioncontainer != nil {
					return fmt.Errorf("decoding extensionContainer: %w", tlvErr_extensioncontainer)
				}
				var dec_extensioncontainer ExtensionContainer5
				if offset < 0 || offset >
					len(content) || n_extensioncontainer < 0 || n_extensioncontainer >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				if unmErr := dec_extensioncontainer.UnmarshalBER(content[offset:offset+n_extensioncontainer], ber.ChildDecodeOptions(opts, "extensioncontainer")...); unmErr != nil {
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
			return &ber.DecodeError{Offset: offset, TypeName: "IllegalEquipmentParam5", Cause: extErr_}
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

// MarshalBER encodes BearerServNotProvParam5 to BER format.
func (v *BearerServNotProvParam5) MarshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: BearerServNotProvParam5 receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *BearerServNotProvParam5) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalBER(opts...)
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
	return ber.EncodeSequence(children)
}

// MarshalDER encodes BearerServNotProvParam5 to DER format.
func (v *BearerServNotProvParam5) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: BearerServNotProvParam5 receiver is nil", ber.ErrInvalidValue)
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
		return nil, fmt.Errorf("encoding BearerServNotProvParam5 as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes BearerServNotProvParam5 from BER/DER format.
func (v *BearerServNotProvParam5) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: BearerServNotProvParam5 destination is nil", ber.ErrInvalidValue)
	}
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = BearerServNotProvParam5{}
	defer func() {
		if returnErr != nil || !ber.ConstraintToleranceEnabled(opts) {
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
		return fmt.Errorf("decoding BearerServNotProvParam5 SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "BearerServNotProvParam5", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode extensionContainer
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassUniversal && peekTag.Number == 16 {
				// Decode nested SEQUENCE (ExtensionContainer5)
				_, n_extensioncontainer, _, tlvErr_extensioncontainer := ber.DecodeTLV(content[offset:], opts...)
				if tlvErr_extensioncontainer != nil {
					return fmt.Errorf("decoding extensionContainer: %w", tlvErr_extensioncontainer)
				}
				var dec_extensioncontainer ExtensionContainer5
				if offset < 0 || offset >
					len(content) || n_extensioncontainer < 0 || n_extensioncontainer >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				if unmErr := dec_extensioncontainer.UnmarshalBER(content[offset:offset+n_extensioncontainer], ber.ChildDecodeOptions(opts, "extensioncontainer")...); unmErr != nil {
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
			return &ber.DecodeError{Offset: offset, TypeName: "BearerServNotProvParam5", Cause: extErr_}
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

// MarshalBER encodes TeleservNotProvParam5 to BER format.
func (v *TeleservNotProvParam5) MarshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: TeleservNotProvParam5 receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *TeleservNotProvParam5) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalBER(opts...)
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
	return ber.EncodeSequence(children)
}

// MarshalDER encodes TeleservNotProvParam5 to DER format.
func (v *TeleservNotProvParam5) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: TeleservNotProvParam5 receiver is nil", ber.ErrInvalidValue)
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
		return nil, fmt.Errorf("encoding TeleservNotProvParam5 as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes TeleservNotProvParam5 from BER/DER format.
func (v *TeleservNotProvParam5) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: TeleservNotProvParam5 destination is nil", ber.ErrInvalidValue)
	}
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = TeleservNotProvParam5{}
	defer func() {
		if returnErr != nil || !ber.ConstraintToleranceEnabled(opts) {
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
		return fmt.Errorf("decoding TeleservNotProvParam5 SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "TeleservNotProvParam5", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode extensionContainer
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassUniversal && peekTag.Number == 16 {
				// Decode nested SEQUENCE (ExtensionContainer5)
				_, n_extensioncontainer, _, tlvErr_extensioncontainer := ber.DecodeTLV(content[offset:], opts...)
				if tlvErr_extensioncontainer != nil {
					return fmt.Errorf("decoding extensionContainer: %w", tlvErr_extensioncontainer)
				}
				var dec_extensioncontainer ExtensionContainer5
				if offset < 0 || offset >
					len(content) || n_extensioncontainer < 0 || n_extensioncontainer >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				if unmErr := dec_extensioncontainer.UnmarshalBER(content[offset:offset+n_extensioncontainer], ber.ChildDecodeOptions(opts, "extensioncontainer")...); unmErr != nil {
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
			return &ber.DecodeError{Offset: offset, TypeName: "TeleservNotProvParam5", Cause: extErr_}
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

// MarshalBER encodes TracingBufferFullParam5 to BER format.
func (v *TracingBufferFullParam5) MarshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: TracingBufferFullParam5 receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *TracingBufferFullParam5) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalBER(opts...)
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
	return ber.EncodeSequence(children)
}

// MarshalDER encodes TracingBufferFullParam5 to DER format.
func (v *TracingBufferFullParam5) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: TracingBufferFullParam5 receiver is nil", ber.ErrInvalidValue)
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
		return nil, fmt.Errorf("encoding TracingBufferFullParam5 as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes TracingBufferFullParam5 from BER/DER format.
func (v *TracingBufferFullParam5) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: TracingBufferFullParam5 destination is nil", ber.ErrInvalidValue)
	}
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = TracingBufferFullParam5{}
	defer func() {
		if returnErr != nil || !ber.ConstraintToleranceEnabled(opts) {
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
		return fmt.Errorf("decoding TracingBufferFullParam5 SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "TracingBufferFullParam5", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode extensionContainer
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassUniversal && peekTag.Number == 16 {
				// Decode nested SEQUENCE (ExtensionContainer5)
				_, n_extensioncontainer, _, tlvErr_extensioncontainer := ber.DecodeTLV(content[offset:], opts...)
				if tlvErr_extensioncontainer != nil {
					return fmt.Errorf("decoding extensionContainer: %w", tlvErr_extensioncontainer)
				}
				var dec_extensioncontainer ExtensionContainer5
				if offset < 0 || offset >
					len(content) || n_extensioncontainer < 0 || n_extensioncontainer >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				if unmErr := dec_extensioncontainer.UnmarshalBER(content[offset:offset+n_extensioncontainer], ber.ChildDecodeOptions(opts, "extensioncontainer")...); unmErr != nil {
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
			return &ber.DecodeError{Offset: offset, TypeName: "TracingBufferFullParam5", Cause: extErr_}
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

// MarshalBER encodes NoRoamingNbParam5 to BER format.
func (v *NoRoamingNbParam5) MarshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: NoRoamingNbParam5 receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *NoRoamingNbParam5) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalBER(opts...)
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
	return ber.EncodeSequence(children)
}

// MarshalDER encodes NoRoamingNbParam5 to DER format.
func (v *NoRoamingNbParam5) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: NoRoamingNbParam5 receiver is nil", ber.ErrInvalidValue)
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
		return nil, fmt.Errorf("encoding NoRoamingNbParam5 as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes NoRoamingNbParam5 from BER/DER format.
func (v *NoRoamingNbParam5) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: NoRoamingNbParam5 destination is nil", ber.ErrInvalidValue)
	}
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = NoRoamingNbParam5{}
	defer func() {
		if returnErr != nil || !ber.ConstraintToleranceEnabled(opts) {
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
		return fmt.Errorf("decoding NoRoamingNbParam5 SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "NoRoamingNbParam5", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode extensionContainer
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassUniversal && peekTag.Number == 16 {
				// Decode nested SEQUENCE (ExtensionContainer5)
				_, n_extensioncontainer, _, tlvErr_extensioncontainer := ber.DecodeTLV(content[offset:], opts...)
				if tlvErr_extensioncontainer != nil {
					return fmt.Errorf("decoding extensionContainer: %w", tlvErr_extensioncontainer)
				}
				var dec_extensioncontainer ExtensionContainer5
				if offset < 0 || offset >
					len(content) || n_extensioncontainer < 0 || n_extensioncontainer >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				if unmErr := dec_extensioncontainer.UnmarshalBER(content[offset:offset+n_extensioncontainer], ber.ChildDecodeOptions(opts, "extensioncontainer")...); unmErr != nil {
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
			return &ber.DecodeError{Offset: offset, TypeName: "NoRoamingNbParam5", Cause: extErr_}
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

// MarshalBER encodes AbsentSubscriberParam5 to BER format.
func (v *AbsentSubscriberParam5) MarshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: AbsentSubscriberParam5 receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *AbsentSubscriberParam5) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalBER(opts...)
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
		_, n, _, extErr := ber.DecodeTLV(ext)
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

// MarshalDER encodes AbsentSubscriberParam5 to DER format.
func (v *AbsentSubscriberParam5) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: AbsentSubscriberParam5 receiver is nil", ber.ErrInvalidValue)
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
		return nil, fmt.Errorf("encoding AbsentSubscriberParam5 as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes AbsentSubscriberParam5 from BER/DER format.
func (v *AbsentSubscriberParam5) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: AbsentSubscriberParam5 destination is nil", ber.ErrInvalidValue)
	}
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = AbsentSubscriberParam5{}
	defer func() {
		if returnErr != nil || !ber.ConstraintToleranceEnabled(opts) {
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
		return fmt.Errorf("decoding AbsentSubscriberParam5 SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "AbsentSubscriberParam5", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode extensionContainer
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassUniversal && peekTag.Number == 16 {
				// Decode nested SEQUENCE (ExtensionContainer5)
				_, n_extensioncontainer, _, tlvErr_extensioncontainer := ber.DecodeTLV(content[offset:], opts...)
				if tlvErr_extensioncontainer != nil {
					return fmt.Errorf("decoding extensionContainer: %w", tlvErr_extensioncontainer)
				}
				var dec_extensioncontainer ExtensionContainer5
				if offset < 0 || offset >
					len(content) || n_extensioncontainer < 0 || n_extensioncontainer >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				if unmErr := dec_extensioncontainer.UnmarshalBER(content[offset:offset+n_extensioncontainer], ber.ChildDecodeOptions(opts, "extensioncontainer")...); unmErr != nil {
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
				tmp_absentsubscriberreason := AbsentSubscriberReason5(decVal_absentsubscriberreason)
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
			return &ber.DecodeError{Offset: offset, TypeName: "AbsentSubscriberParam5", Cause: extErr_}
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

// MarshalBER encodes BusySubscriberParam5 to BER format.
func (v *BusySubscriberParam5) MarshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: BusySubscriberParam5 receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *BusySubscriberParam5) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalBER(opts...)
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
		_, n, _, extErr := ber.DecodeTLV(ext)
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

// MarshalDER encodes BusySubscriberParam5 to DER format.
func (v *BusySubscriberParam5) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: BusySubscriberParam5 receiver is nil", ber.ErrInvalidValue)
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
		return nil, fmt.Errorf("encoding BusySubscriberParam5 as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes BusySubscriberParam5 from BER/DER format.
func (v *BusySubscriberParam5) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: BusySubscriberParam5 destination is nil", ber.ErrInvalidValue)
	}
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = BusySubscriberParam5{}
	defer func() {
		if returnErr != nil || !ber.ConstraintToleranceEnabled(opts) {
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
		return fmt.Errorf("decoding BusySubscriberParam5 SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "BusySubscriberParam5", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode extensionContainer
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassUniversal && peekTag.Number == 16 {
				// Decode nested SEQUENCE (ExtensionContainer5)
				_, n_extensioncontainer, _, tlvErr_extensioncontainer := ber.DecodeTLV(content[offset:], opts...)
				if tlvErr_extensioncontainer != nil {
					return fmt.Errorf("decoding extensionContainer: %w", tlvErr_extensioncontainer)
				}
				var dec_extensioncontainer ExtensionContainer5
				if offset < 0 || offset >
					len(content) || n_extensioncontainer < 0 || n_extensioncontainer >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				if unmErr := dec_extensioncontainer.UnmarshalBER(content[offset:offset+n_extensioncontainer], ber.ChildDecodeOptions(opts, "extensioncontainer")...); unmErr != nil {
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
			return &ber.DecodeError{Offset: offset, TypeName: "BusySubscriberParam5", Cause: extErr_}
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

// MarshalBER encodes NoSubscriberReplyParam5 to BER format.
func (v *NoSubscriberReplyParam5) MarshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: NoSubscriberReplyParam5 receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *NoSubscriberReplyParam5) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalBER(opts...)
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
	return ber.EncodeSequence(children)
}

// MarshalDER encodes NoSubscriberReplyParam5 to DER format.
func (v *NoSubscriberReplyParam5) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: NoSubscriberReplyParam5 receiver is nil", ber.ErrInvalidValue)
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
		return nil, fmt.Errorf("encoding NoSubscriberReplyParam5 as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes NoSubscriberReplyParam5 from BER/DER format.
func (v *NoSubscriberReplyParam5) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: NoSubscriberReplyParam5 destination is nil", ber.ErrInvalidValue)
	}
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = NoSubscriberReplyParam5{}
	defer func() {
		if returnErr != nil || !ber.ConstraintToleranceEnabled(opts) {
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
		return fmt.Errorf("decoding NoSubscriberReplyParam5 SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "NoSubscriberReplyParam5", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode extensionContainer
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassUniversal && peekTag.Number == 16 {
				// Decode nested SEQUENCE (ExtensionContainer5)
				_, n_extensioncontainer, _, tlvErr_extensioncontainer := ber.DecodeTLV(content[offset:], opts...)
				if tlvErr_extensioncontainer != nil {
					return fmt.Errorf("decoding extensionContainer: %w", tlvErr_extensioncontainer)
				}
				var dec_extensioncontainer ExtensionContainer5
				if offset < 0 || offset >
					len(content) || n_extensioncontainer < 0 || n_extensioncontainer >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				if unmErr := dec_extensioncontainer.UnmarshalBER(content[offset:offset+n_extensioncontainer], ber.ChildDecodeOptions(opts, "extensioncontainer")...); unmErr != nil {
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
			return &ber.DecodeError{Offset: offset, TypeName: "NoSubscriberReplyParam5", Cause: extErr_}
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

// MarshalBER encodes ForwardingViolationParam5 to BER format.
func (v *ForwardingViolationParam5) MarshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: ForwardingViolationParam5 receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *ForwardingViolationParam5) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalBER(opts...)
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
	return ber.EncodeSequence(children)
}

// MarshalDER encodes ForwardingViolationParam5 to DER format.
func (v *ForwardingViolationParam5) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: ForwardingViolationParam5 receiver is nil", ber.ErrInvalidValue)
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
		return nil, fmt.Errorf("encoding ForwardingViolationParam5 as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes ForwardingViolationParam5 from BER/DER format.
func (v *ForwardingViolationParam5) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: ForwardingViolationParam5 destination is nil", ber.ErrInvalidValue)
	}
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = ForwardingViolationParam5{}
	defer func() {
		if returnErr != nil || !ber.ConstraintToleranceEnabled(opts) {
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
		return fmt.Errorf("decoding ForwardingViolationParam5 SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "ForwardingViolationParam5", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode extensionContainer
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassUniversal && peekTag.Number == 16 {
				// Decode nested SEQUENCE (ExtensionContainer5)
				_, n_extensioncontainer, _, tlvErr_extensioncontainer := ber.DecodeTLV(content[offset:], opts...)
				if tlvErr_extensioncontainer != nil {
					return fmt.Errorf("decoding extensionContainer: %w", tlvErr_extensioncontainer)
				}
				var dec_extensioncontainer ExtensionContainer5
				if offset < 0 || offset >
					len(content) || n_extensioncontainer < 0 || n_extensioncontainer >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				if unmErr := dec_extensioncontainer.UnmarshalBER(content[offset:offset+n_extensioncontainer], ber.ChildDecodeOptions(opts, "extensioncontainer")...); unmErr != nil {
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
			return &ber.DecodeError{Offset: offset, TypeName: "ForwardingViolationParam5", Cause: extErr_}
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

// MarshalBER encodes ForwardingFailedParam5 to BER format.
func (v *ForwardingFailedParam5) MarshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: ForwardingFailedParam5 receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *ForwardingFailedParam5) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalBER(opts...)
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
	return ber.EncodeSequence(children)
}

// MarshalDER encodes ForwardingFailedParam5 to DER format.
func (v *ForwardingFailedParam5) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: ForwardingFailedParam5 receiver is nil", ber.ErrInvalidValue)
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
		return nil, fmt.Errorf("encoding ForwardingFailedParam5 as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes ForwardingFailedParam5 from BER/DER format.
func (v *ForwardingFailedParam5) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: ForwardingFailedParam5 destination is nil", ber.ErrInvalidValue)
	}
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = ForwardingFailedParam5{}
	defer func() {
		if returnErr != nil || !ber.ConstraintToleranceEnabled(opts) {
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
		return fmt.Errorf("decoding ForwardingFailedParam5 SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "ForwardingFailedParam5", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode extensionContainer
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassUniversal && peekTag.Number == 16 {
				// Decode nested SEQUENCE (ExtensionContainer5)
				_, n_extensioncontainer, _, tlvErr_extensioncontainer := ber.DecodeTLV(content[offset:], opts...)
				if tlvErr_extensioncontainer != nil {
					return fmt.Errorf("decoding extensionContainer: %w", tlvErr_extensioncontainer)
				}
				var dec_extensioncontainer ExtensionContainer5
				if offset < 0 || offset >
					len(content) || n_extensioncontainer < 0 || n_extensioncontainer >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				if unmErr := dec_extensioncontainer.UnmarshalBER(content[offset:offset+n_extensioncontainer], ber.ChildDecodeOptions(opts, "extensioncontainer")...); unmErr != nil {
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
			return &ber.DecodeError{Offset: offset, TypeName: "ForwardingFailedParam5", Cause: extErr_}
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

// MarshalBER encodes ATINotAllowedParam5 to BER format.
func (v *ATINotAllowedParam5) MarshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: ATINotAllowedParam5 receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *ATINotAllowedParam5) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalBER(opts...)
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
	return ber.EncodeSequence(children)
}

// MarshalDER encodes ATINotAllowedParam5 to DER format.
func (v *ATINotAllowedParam5) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: ATINotAllowedParam5 receiver is nil", ber.ErrInvalidValue)
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
		return nil, fmt.Errorf("encoding ATINotAllowedParam5 as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes ATINotAllowedParam5 from BER/DER format.
func (v *ATINotAllowedParam5) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: ATINotAllowedParam5 destination is nil", ber.ErrInvalidValue)
	}
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = ATINotAllowedParam5{}
	defer func() {
		if returnErr != nil || !ber.ConstraintToleranceEnabled(opts) {
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
		return fmt.Errorf("decoding ATINotAllowedParam5 SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "ATINotAllowedParam5", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode extensionContainer
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassUniversal && peekTag.Number == 16 {
				// Decode nested SEQUENCE (ExtensionContainer5)
				_, n_extensioncontainer, _, tlvErr_extensioncontainer := ber.DecodeTLV(content[offset:], opts...)
				if tlvErr_extensioncontainer != nil {
					return fmt.Errorf("decoding extensionContainer: %w", tlvErr_extensioncontainer)
				}
				var dec_extensioncontainer ExtensionContainer5
				if offset < 0 || offset >
					len(content) || n_extensioncontainer < 0 || n_extensioncontainer >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				if unmErr := dec_extensioncontainer.UnmarshalBER(content[offset:offset+n_extensioncontainer], ber.ChildDecodeOptions(opts, "extensioncontainer")...); unmErr != nil {
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
			return &ber.DecodeError{Offset: offset, TypeName: "ATINotAllowedParam5", Cause: extErr_}
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

// MarshalBER encodes ATSINotAllowedParam5 to BER format.
func (v *ATSINotAllowedParam5) MarshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: ATSINotAllowedParam5 receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *ATSINotAllowedParam5) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalBER(opts...)
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
	return ber.EncodeSequence(children)
}

// MarshalDER encodes ATSINotAllowedParam5 to DER format.
func (v *ATSINotAllowedParam5) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: ATSINotAllowedParam5 receiver is nil", ber.ErrInvalidValue)
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
		return nil, fmt.Errorf("encoding ATSINotAllowedParam5 as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes ATSINotAllowedParam5 from BER/DER format.
func (v *ATSINotAllowedParam5) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: ATSINotAllowedParam5 destination is nil", ber.ErrInvalidValue)
	}
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = ATSINotAllowedParam5{}
	defer func() {
		if returnErr != nil || !ber.ConstraintToleranceEnabled(opts) {
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
		return fmt.Errorf("decoding ATSINotAllowedParam5 SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "ATSINotAllowedParam5", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode extensionContainer
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassUniversal && peekTag.Number == 16 {
				// Decode nested SEQUENCE (ExtensionContainer5)
				_, n_extensioncontainer, _, tlvErr_extensioncontainer := ber.DecodeTLV(content[offset:], opts...)
				if tlvErr_extensioncontainer != nil {
					return fmt.Errorf("decoding extensionContainer: %w", tlvErr_extensioncontainer)
				}
				var dec_extensioncontainer ExtensionContainer5
				if offset < 0 || offset >
					len(content) || n_extensioncontainer < 0 || n_extensioncontainer >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				if unmErr := dec_extensioncontainer.UnmarshalBER(content[offset:offset+n_extensioncontainer], ber.ChildDecodeOptions(opts, "extensioncontainer")...); unmErr != nil {
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
			return &ber.DecodeError{Offset: offset, TypeName: "ATSINotAllowedParam5", Cause: extErr_}
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

// MarshalBER encodes ATMNotAllowedParam5 to BER format.
func (v *ATMNotAllowedParam5) MarshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: ATMNotAllowedParam5 receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *ATMNotAllowedParam5) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalBER(opts...)
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
	return ber.EncodeSequence(children)
}

// MarshalDER encodes ATMNotAllowedParam5 to DER format.
func (v *ATMNotAllowedParam5) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: ATMNotAllowedParam5 receiver is nil", ber.ErrInvalidValue)
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
		return nil, fmt.Errorf("encoding ATMNotAllowedParam5 as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes ATMNotAllowedParam5 from BER/DER format.
func (v *ATMNotAllowedParam5) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: ATMNotAllowedParam5 destination is nil", ber.ErrInvalidValue)
	}
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = ATMNotAllowedParam5{}
	defer func() {
		if returnErr != nil || !ber.ConstraintToleranceEnabled(opts) {
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
		return fmt.Errorf("decoding ATMNotAllowedParam5 SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "ATMNotAllowedParam5", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode extensionContainer
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassUniversal && peekTag.Number == 16 {
				// Decode nested SEQUENCE (ExtensionContainer5)
				_, n_extensioncontainer, _, tlvErr_extensioncontainer := ber.DecodeTLV(content[offset:], opts...)
				if tlvErr_extensioncontainer != nil {
					return fmt.Errorf("decoding extensionContainer: %w", tlvErr_extensioncontainer)
				}
				var dec_extensioncontainer ExtensionContainer5
				if offset < 0 || offset >
					len(content) || n_extensioncontainer < 0 || n_extensioncontainer >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				if unmErr := dec_extensioncontainer.UnmarshalBER(content[offset:offset+n_extensioncontainer], ber.ChildDecodeOptions(opts, "extensioncontainer")...); unmErr != nil {
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
			return &ber.DecodeError{Offset: offset, TypeName: "ATMNotAllowedParam5", Cause: extErr_}
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

// MarshalBER encodes IllegalSSOperationParam5 to BER format.
func (v *IllegalSSOperationParam5) MarshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: IllegalSSOperationParam5 receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *IllegalSSOperationParam5) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalBER(opts...)
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
	return ber.EncodeSequence(children)
}

// MarshalDER encodes IllegalSSOperationParam5 to DER format.
func (v *IllegalSSOperationParam5) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: IllegalSSOperationParam5 receiver is nil", ber.ErrInvalidValue)
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
		return nil, fmt.Errorf("encoding IllegalSSOperationParam5 as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes IllegalSSOperationParam5 from BER/DER format.
func (v *IllegalSSOperationParam5) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: IllegalSSOperationParam5 destination is nil", ber.ErrInvalidValue)
	}
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = IllegalSSOperationParam5{}
	defer func() {
		if returnErr != nil || !ber.ConstraintToleranceEnabled(opts) {
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
		return fmt.Errorf("decoding IllegalSSOperationParam5 SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "IllegalSSOperationParam5", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode extensionContainer
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassUniversal && peekTag.Number == 16 {
				// Decode nested SEQUENCE (ExtensionContainer5)
				_, n_extensioncontainer, _, tlvErr_extensioncontainer := ber.DecodeTLV(content[offset:], opts...)
				if tlvErr_extensioncontainer != nil {
					return fmt.Errorf("decoding extensionContainer: %w", tlvErr_extensioncontainer)
				}
				var dec_extensioncontainer ExtensionContainer5
				if offset < 0 || offset >
					len(content) || n_extensioncontainer < 0 || n_extensioncontainer >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				if unmErr := dec_extensioncontainer.UnmarshalBER(content[offset:offset+n_extensioncontainer], ber.ChildDecodeOptions(opts, "extensioncontainer")...); unmErr != nil {
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
			return &ber.DecodeError{Offset: offset, TypeName: "IllegalSSOperationParam5", Cause: extErr_}
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

// MarshalBER encodes SSNotAvailableParam5 to BER format.
func (v *SSNotAvailableParam5) MarshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: SSNotAvailableParam5 receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *SSNotAvailableParam5) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalBER(opts...)
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
	return ber.EncodeSequence(children)
}

// MarshalDER encodes SSNotAvailableParam5 to DER format.
func (v *SSNotAvailableParam5) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: SSNotAvailableParam5 receiver is nil", ber.ErrInvalidValue)
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
		return nil, fmt.Errorf("encoding SSNotAvailableParam5 as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes SSNotAvailableParam5 from BER/DER format.
func (v *SSNotAvailableParam5) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: SSNotAvailableParam5 destination is nil", ber.ErrInvalidValue)
	}
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = SSNotAvailableParam5{}
	defer func() {
		if returnErr != nil || !ber.ConstraintToleranceEnabled(opts) {
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
		return fmt.Errorf("decoding SSNotAvailableParam5 SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "SSNotAvailableParam5", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode extensionContainer
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassUniversal && peekTag.Number == 16 {
				// Decode nested SEQUENCE (ExtensionContainer5)
				_, n_extensioncontainer, _, tlvErr_extensioncontainer := ber.DecodeTLV(content[offset:], opts...)
				if tlvErr_extensioncontainer != nil {
					return fmt.Errorf("decoding extensionContainer: %w", tlvErr_extensioncontainer)
				}
				var dec_extensioncontainer ExtensionContainer5
				if offset < 0 || offset >
					len(content) || n_extensioncontainer < 0 || n_extensioncontainer >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				if unmErr := dec_extensioncontainer.UnmarshalBER(content[offset:offset+n_extensioncontainer], ber.ChildDecodeOptions(opts, "extensioncontainer")...); unmErr != nil {
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
			return &ber.DecodeError{Offset: offset, TypeName: "SSNotAvailableParam5", Cause: extErr_}
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

// MarshalBER encodes SSSubscriptionViolationParam5 to BER format.
func (v *SSSubscriptionViolationParam5) MarshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: SSSubscriptionViolationParam5 receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *SSSubscriptionViolationParam5) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalBER(opts...)
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
	return ber.EncodeSequence(children)
}

// MarshalDER encodes SSSubscriptionViolationParam5 to DER format.
func (v *SSSubscriptionViolationParam5) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: SSSubscriptionViolationParam5 receiver is nil", ber.ErrInvalidValue)
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
		return nil, fmt.Errorf("encoding SSSubscriptionViolationParam5 as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes SSSubscriptionViolationParam5 from BER/DER format.
func (v *SSSubscriptionViolationParam5) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: SSSubscriptionViolationParam5 destination is nil", ber.ErrInvalidValue)
	}
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = SSSubscriptionViolationParam5{}
	defer func() {
		if returnErr != nil || !ber.ConstraintToleranceEnabled(opts) {
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
		return fmt.Errorf("decoding SSSubscriptionViolationParam5 SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "SSSubscriptionViolationParam5", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode extensionContainer
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassUniversal && peekTag.Number == 16 {
				// Decode nested SEQUENCE (ExtensionContainer5)
				_, n_extensioncontainer, _, tlvErr_extensioncontainer := ber.DecodeTLV(content[offset:], opts...)
				if tlvErr_extensioncontainer != nil {
					return fmt.Errorf("decoding extensionContainer: %w", tlvErr_extensioncontainer)
				}
				var dec_extensioncontainer ExtensionContainer5
				if offset < 0 || offset >
					len(content) || n_extensioncontainer < 0 || n_extensioncontainer > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				if unmErr := dec_extensioncontainer.UnmarshalBER(content[offset:offset+n_extensioncontainer], ber.ChildDecodeOptions(opts, "extensioncontainer")...); unmErr != nil {
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
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:], opts...)
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "SSSubscriptionViolationParam5", Cause: extErr_}
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

// MarshalBER encodes InformationNotAvailableParam5 to BER format.
func (v *InformationNotAvailableParam5) MarshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: InformationNotAvailableParam5 receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *InformationNotAvailableParam5) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalBER(opts...)
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
	return ber.EncodeSequence(children)
}

// MarshalDER encodes InformationNotAvailableParam5 to DER format.
func (v *InformationNotAvailableParam5) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: InformationNotAvailableParam5 receiver is nil", ber.ErrInvalidValue)
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
		return nil, fmt.Errorf("encoding InformationNotAvailableParam5 as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes InformationNotAvailableParam5 from BER/DER format.
func (v *InformationNotAvailableParam5) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: InformationNotAvailableParam5 destination is nil", ber.ErrInvalidValue)
	}
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = InformationNotAvailableParam5{}
	defer func() {
		if returnErr != nil || !ber.ConstraintToleranceEnabled(opts) {
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
		return fmt.Errorf("decoding InformationNotAvailableParam5 SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "InformationNotAvailableParam5", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode extensionContainer
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassUniversal && peekTag.Number == 16 {
				// Decode nested SEQUENCE (ExtensionContainer5)
				_, n_extensioncontainer, _, tlvErr_extensioncontainer := ber.DecodeTLV(content[offset:], opts...)
				if tlvErr_extensioncontainer != nil {
					return fmt.Errorf("decoding extensionContainer: %w", tlvErr_extensioncontainer)
				}
				var dec_extensioncontainer ExtensionContainer5
				if offset < 0 || offset >
					len(content) || n_extensioncontainer < 0 || n_extensioncontainer > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				if unmErr := dec_extensioncontainer.UnmarshalBER(content[offset:offset+n_extensioncontainer], ber.ChildDecodeOptions(opts, "extensioncontainer")...); unmErr != nil {
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
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:], opts...)
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "InformationNotAvailableParam5", Cause: extErr_}
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

// MarshalBER encodes SubBusyForMTSMSParam5 to BER format.
func (v *SubBusyForMTSMSParam5) MarshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: SubBusyForMTSMSParam5 receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *SubBusyForMTSMSParam5) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalBER(opts...)
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
		_, n, _, extErr := ber.DecodeTLV(ext)
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

// MarshalDER encodes SubBusyForMTSMSParam5 to DER format.
func (v *SubBusyForMTSMSParam5) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: SubBusyForMTSMSParam5 receiver is nil", ber.ErrInvalidValue)
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
		return nil, fmt.Errorf("encoding SubBusyForMTSMSParam5 as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes SubBusyForMTSMSParam5 from BER/DER format.
func (v *SubBusyForMTSMSParam5) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: SubBusyForMTSMSParam5 destination is nil", ber.ErrInvalidValue)
	}
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = SubBusyForMTSMSParam5{}
	defer func() {
		if returnErr != nil || !ber.ConstraintToleranceEnabled(opts) {
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
		return fmt.Errorf("decoding SubBusyForMTSMSParam5 SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "SubBusyForMTSMSParam5", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode extensionContainer
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassUniversal && peekTag.Number == 16 {
				// Decode nested SEQUENCE (ExtensionContainer5)
				_, n_extensioncontainer, _, tlvErr_extensioncontainer := ber.DecodeTLV(content[offset:], opts...)
				if tlvErr_extensioncontainer != nil {
					return fmt.Errorf("decoding extensionContainer: %w", tlvErr_extensioncontainer)
				}
				var dec_extensioncontainer ExtensionContainer5
				if offset < 0 || offset >
					len(content) || n_extensioncontainer < 0 || n_extensioncontainer >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				if unmErr := dec_extensioncontainer.UnmarshalBER(content[offset:offset+n_extensioncontainer], ber.ChildDecodeOptions(opts, "extensioncontainer")...); unmErr != nil {
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
			return &ber.DecodeError{Offset: offset, TypeName: "SubBusyForMTSMSParam5", Cause: extErr_}
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

// MarshalBER encodes MessageWaitListFullParam5 to BER format.
func (v *MessageWaitListFullParam5) MarshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: MessageWaitListFullParam5 receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *MessageWaitListFullParam5) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalBER(opts...)
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
	return ber.EncodeSequence(children)
}

// MarshalDER encodes MessageWaitListFullParam5 to DER format.
func (v *MessageWaitListFullParam5) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: MessageWaitListFullParam5 receiver is nil", ber.ErrInvalidValue)
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
		return nil, fmt.Errorf("encoding MessageWaitListFullParam5 as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes MessageWaitListFullParam5 from BER/DER format.
func (v *MessageWaitListFullParam5) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: MessageWaitListFullParam5 destination is nil", ber.ErrInvalidValue)
	}
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = MessageWaitListFullParam5{}
	defer func() {
		if returnErr != nil || !ber.ConstraintToleranceEnabled(opts) {
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
		return fmt.Errorf("decoding MessageWaitListFullParam5 SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "MessageWaitListFullParam5", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode extensionContainer
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassUniversal && peekTag.Number == 16 {
				// Decode nested SEQUENCE (ExtensionContainer5)
				_, n_extensioncontainer, _, tlvErr_extensioncontainer := ber.DecodeTLV(content[offset:], opts...)
				if tlvErr_extensioncontainer != nil {
					return fmt.Errorf("decoding extensionContainer: %w", tlvErr_extensioncontainer)
				}
				var dec_extensioncontainer ExtensionContainer5
				if offset < 0 || offset >
					len(content) || n_extensioncontainer < 0 || n_extensioncontainer >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				if unmErr := dec_extensioncontainer.UnmarshalBER(content[offset:offset+n_extensioncontainer], ber.ChildDecodeOptions(opts, "extensioncontainer")...); unmErr != nil {
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
			return &ber.DecodeError{Offset: offset, TypeName: "MessageWaitListFullParam5", Cause: extErr_}
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

// MarshalBER encodes ResourceLimitationParam5 to BER format.
func (v *ResourceLimitationParam5) MarshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: ResourceLimitationParam5 receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *ResourceLimitationParam5) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalBER(opts...)
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
	return ber.EncodeSequence(children)
}

// MarshalDER encodes ResourceLimitationParam5 to DER format.
func (v *ResourceLimitationParam5) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: ResourceLimitationParam5 receiver is nil", ber.ErrInvalidValue)
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
		return nil, fmt.Errorf("encoding ResourceLimitationParam5 as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes ResourceLimitationParam5 from BER/DER format.
func (v *ResourceLimitationParam5) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: ResourceLimitationParam5 destination is nil", ber.ErrInvalidValue)
	}
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = ResourceLimitationParam5{}
	defer func() {
		if returnErr != nil || !ber.ConstraintToleranceEnabled(opts) {
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
		return fmt.Errorf("decoding ResourceLimitationParam5 SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "ResourceLimitationParam5", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode extensionContainer
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassUniversal && peekTag.Number == 16 {
				// Decode nested SEQUENCE (ExtensionContainer5)
				_, n_extensioncontainer, _, tlvErr_extensioncontainer := ber.DecodeTLV(content[offset:], opts...)
				if tlvErr_extensioncontainer != nil {
					return fmt.Errorf("decoding extensionContainer: %w", tlvErr_extensioncontainer)
				}
				var dec_extensioncontainer ExtensionContainer5
				if offset < 0 || offset >
					len(content) || n_extensioncontainer < 0 || n_extensioncontainer >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				if unmErr := dec_extensioncontainer.UnmarshalBER(content[offset:offset+n_extensioncontainer], ber.ChildDecodeOptions(opts, "extensioncontainer")...); unmErr != nil {
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
			return &ber.DecodeError{Offset: offset, TypeName: "ResourceLimitationParam5", Cause: extErr_}
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

// MarshalBER encodes NoGroupCallNbParam5 to BER format.
func (v *NoGroupCallNbParam5) MarshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: NoGroupCallNbParam5 receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *NoGroupCallNbParam5) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalBER(opts...)
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
	return ber.EncodeSequence(children)
}

// MarshalDER encodes NoGroupCallNbParam5 to DER format.
func (v *NoGroupCallNbParam5) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: NoGroupCallNbParam5 receiver is nil", ber.ErrInvalidValue)
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
		return nil, fmt.Errorf("encoding NoGroupCallNbParam5 as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes NoGroupCallNbParam5 from BER/DER format.
func (v *NoGroupCallNbParam5) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: NoGroupCallNbParam5 destination is nil", ber.ErrInvalidValue)
	}
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = NoGroupCallNbParam5{}
	defer func() {
		if returnErr != nil || !ber.ConstraintToleranceEnabled(opts) {
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
		return fmt.Errorf("decoding NoGroupCallNbParam5 SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "NoGroupCallNbParam5", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode extensionContainer
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassUniversal && peekTag.Number == 16 {
				// Decode nested SEQUENCE (ExtensionContainer5)
				_, n_extensioncontainer, _, tlvErr_extensioncontainer := ber.DecodeTLV(content[offset:], opts...)
				if tlvErr_extensioncontainer != nil {
					return fmt.Errorf("decoding extensionContainer: %w", tlvErr_extensioncontainer)
				}
				var dec_extensioncontainer ExtensionContainer5
				if offset < 0 || offset >
					len(content) || n_extensioncontainer < 0 || n_extensioncontainer >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				if unmErr := dec_extensioncontainer.UnmarshalBER(content[offset:offset+n_extensioncontainer], ber.ChildDecodeOptions(opts, "extensioncontainer")...); unmErr != nil {
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
			return &ber.DecodeError{Offset: offset, TypeName: "NoGroupCallNbParam5", Cause: extErr_}
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

// MarshalBER encodes IncompatibleTerminalParam5 to BER format.
func (v *IncompatibleTerminalParam5) MarshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: IncompatibleTerminalParam5 receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *IncompatibleTerminalParam5) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalBER(opts...)
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
	return ber.EncodeSequence(children)
}

// MarshalDER encodes IncompatibleTerminalParam5 to DER format.
func (v *IncompatibleTerminalParam5) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: IncompatibleTerminalParam5 receiver is nil", ber.ErrInvalidValue)
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
		return nil, fmt.Errorf("encoding IncompatibleTerminalParam5 as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes IncompatibleTerminalParam5 from BER/DER format.
func (v *IncompatibleTerminalParam5) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: IncompatibleTerminalParam5 destination is nil", ber.ErrInvalidValue)
	}
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = IncompatibleTerminalParam5{}
	defer func() {
		if returnErr != nil || !ber.ConstraintToleranceEnabled(opts) {
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
		return fmt.Errorf("decoding IncompatibleTerminalParam5 SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "IncompatibleTerminalParam5", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode extensionContainer
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassUniversal && peekTag.Number == 16 {
				// Decode nested SEQUENCE (ExtensionContainer5)
				_, n_extensioncontainer, _, tlvErr_extensioncontainer := ber.DecodeTLV(content[offset:], opts...)
				if tlvErr_extensioncontainer != nil {
					return fmt.Errorf("decoding extensionContainer: %w", tlvErr_extensioncontainer)
				}
				var dec_extensioncontainer ExtensionContainer5
				if offset < 0 || offset >
					len(content) || n_extensioncontainer < 0 || n_extensioncontainer >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				if unmErr := dec_extensioncontainer.UnmarshalBER(content[offset:offset+n_extensioncontainer], ber.ChildDecodeOptions(opts, "extensioncontainer")...); unmErr != nil {
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
			return &ber.DecodeError{Offset: offset, TypeName: "IncompatibleTerminalParam5", Cause: extErr_}
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

// MarshalBER encodes ShortTermDenialParam5 to BER format.
func (v *ShortTermDenialParam5) MarshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: ShortTermDenialParam5 receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *ShortTermDenialParam5) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
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
	return ber.EncodeSequence(children)
}

// MarshalDER encodes ShortTermDenialParam5 to DER format.
func (v *ShortTermDenialParam5) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: ShortTermDenialParam5 receiver is nil", ber.ErrInvalidValue)
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
		return nil, fmt.Errorf("encoding ShortTermDenialParam5 as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes ShortTermDenialParam5 from BER/DER format.
func (v *ShortTermDenialParam5) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: ShortTermDenialParam5 destination is nil", ber.ErrInvalidValue)
	}
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = ShortTermDenialParam5{}
	defer func() {
		if returnErr != nil || !ber.ConstraintToleranceEnabled(opts) {
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
		return fmt.Errorf("decoding ShortTermDenialParam5 SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "ShortTermDenialParam5", Cause: ber.ErrExtraData}
	}
	offset := 0
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:], opts...)
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "ShortTermDenialParam5", Cause: extErr_}
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

// MarshalBER encodes LongTermDenialParam5 to BER format.
func (v *LongTermDenialParam5) MarshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: LongTermDenialParam5 receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *LongTermDenialParam5) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
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
	return ber.EncodeSequence(children)
}

// MarshalDER encodes LongTermDenialParam5 to DER format.
func (v *LongTermDenialParam5) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: LongTermDenialParam5 receiver is nil", ber.ErrInvalidValue)
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
		return nil, fmt.Errorf("encoding LongTermDenialParam5 as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes LongTermDenialParam5 from BER/DER format.
func (v *LongTermDenialParam5) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: LongTermDenialParam5 destination is nil", ber.ErrInvalidValue)
	}
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = LongTermDenialParam5{}
	defer func() {
		if returnErr != nil || !ber.ConstraintToleranceEnabled(opts) {
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
		return fmt.Errorf("decoding LongTermDenialParam5 SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "LongTermDenialParam5", Cause: ber.ErrExtraData}
	}
	offset := 0
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:], opts...)
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "LongTermDenialParam5", Cause: extErr_}
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

// MarshalBER encodes UnauthorizedRequestingNetworkParam5 to BER format.
func (v *UnauthorizedRequestingNetworkParam5) MarshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: UnauthorizedRequestingNetworkParam5 receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *UnauthorizedRequestingNetworkParam5) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalBER(opts...)
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
	return ber.EncodeSequence(children)
}

// MarshalDER encodes UnauthorizedRequestingNetworkParam5 to DER format.
func (v *UnauthorizedRequestingNetworkParam5) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: UnauthorizedRequestingNetworkParam5 receiver is nil", ber.ErrInvalidValue)
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
		return nil, fmt.Errorf("encoding UnauthorizedRequestingNetworkParam5 as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes UnauthorizedRequestingNetworkParam5 from BER/DER format.
func (v *UnauthorizedRequestingNetworkParam5) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: UnauthorizedRequestingNetworkParam5 destination is nil", ber.ErrInvalidValue)
	}
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = UnauthorizedRequestingNetworkParam5{}
	defer func() {
		if returnErr != nil || !ber.ConstraintToleranceEnabled(opts) {
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
		return fmt.Errorf("decoding UnauthorizedRequestingNetworkParam5 SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "UnauthorizedRequestingNetworkParam5", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode extensionContainer
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassUniversal && peekTag.Number == 16 {
				// Decode nested SEQUENCE (ExtensionContainer5)
				_, n_extensioncontainer, _, tlvErr_extensioncontainer := ber.DecodeTLV(content[offset:], opts...)
				if tlvErr_extensioncontainer != nil {
					return fmt.Errorf("decoding extensionContainer: %w", tlvErr_extensioncontainer)
				}
				var dec_extensioncontainer ExtensionContainer5
				if offset < 0 || offset >
					len(content) || n_extensioncontainer < 0 || n_extensioncontainer > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				if unmErr := dec_extensioncontainer.UnmarshalBER(content[offset:offset+n_extensioncontainer], ber.ChildDecodeOptions(opts, "extensioncontainer")...); unmErr != nil {
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
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:], opts...)
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "UnauthorizedRequestingNetworkParam5", Cause: extErr_}
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

// MarshalBER encodes UnauthorizedLCSClientParam5 to BER format.
func (v *UnauthorizedLCSClientParam5) MarshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: UnauthorizedLCSClientParam5 receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *UnauthorizedLCSClientParam5) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
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
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalBER(opts...)
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
	return ber.EncodeSequence(children)
}

// MarshalDER encodes UnauthorizedLCSClientParam5 to DER format.
func (v *UnauthorizedLCSClientParam5) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: UnauthorizedLCSClientParam5 receiver is nil", ber.ErrInvalidValue)
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
		return nil, fmt.Errorf("encoding UnauthorizedLCSClientParam5 as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes UnauthorizedLCSClientParam5 from BER/DER format.
func (v *UnauthorizedLCSClientParam5) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: UnauthorizedLCSClientParam5 destination is nil", ber.ErrInvalidValue)
	}
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = UnauthorizedLCSClientParam5{}
	defer func() {
		if returnErr != nil || !ber.ConstraintToleranceEnabled(opts) {
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
		return fmt.Errorf("decoding UnauthorizedLCSClientParam5 SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "UnauthorizedLCSClientParam5", Cause: ber.ErrExtraData}
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
				tmp_unauthorizedlcsclientdiagnostic := UnauthorizedLCSClientDiagnostic5(decVal_unauthorizedlcsclientdiagnostic)
				v.UnauthorizedLCSClientDiagnostic = &tmp_unauthorizedlcsclientdiagnostic
				if offset < 0 || offset >
					len(content) || n_unauthorizedlcsclientdiagnostic < 0 || n_unauthorizedlcsclientdiagnostic >
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
				var dec_extensioncontainer ExtensionContainer5
				if unmErr := dec_extensioncontainer.UnmarshalBER(reconstructed_extensioncontainer, ber.ChildDecodeOptions(opts, "extensioncontainer")...); unmErr != nil {
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
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:], opts...)
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "UnauthorizedLCSClientParam5", Cause: extErr_}
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

// MarshalBER encodes PositionMethodFailureParam5 to BER format.
func (v *PositionMethodFailureParam5) MarshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: PositionMethodFailureParam5 receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *PositionMethodFailureParam5) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
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
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalBER(opts...)
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
	return ber.EncodeSequence(children)
}

// MarshalDER encodes PositionMethodFailureParam5 to DER format.
func (v *PositionMethodFailureParam5) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: PositionMethodFailureParam5 receiver is nil", ber.ErrInvalidValue)
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
		return nil, fmt.Errorf("encoding PositionMethodFailureParam5 as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes PositionMethodFailureParam5 from BER/DER format.
func (v *PositionMethodFailureParam5) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: PositionMethodFailureParam5 destination is nil", ber.ErrInvalidValue)
	}
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = PositionMethodFailureParam5{}
	defer func() {
		if returnErr != nil || !ber.ConstraintToleranceEnabled(opts) {
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
		return fmt.Errorf("decoding PositionMethodFailureParam5 SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "PositionMethodFailureParam5", Cause: ber.ErrExtraData}
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
				tmp_positionmethodfailurediagnostic := PositionMethodFailureDiagnostic5(decVal_positionmethodfailurediagnostic)
				v.PositionMethodFailureDiagnostic = &tmp_positionmethodfailurediagnostic
				if offset < 0 || offset >
					len(content) || n_positionmethodfailurediagnostic < 0 || n_positionmethodfailurediagnostic >
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
				var dec_extensioncontainer ExtensionContainer5
				if unmErr := dec_extensioncontainer.UnmarshalBER(reconstructed_extensioncontainer, ber.ChildDecodeOptions(opts, "extensioncontainer")...); unmErr != nil {
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
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:], opts...)
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "PositionMethodFailureParam5", Cause: extErr_}
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

// MarshalBER encodes UnknownOrUnreachableLCSClientParam5 to BER format.
func (v *UnknownOrUnreachableLCSClientParam5) MarshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: UnknownOrUnreachableLCSClientParam5 receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *UnknownOrUnreachableLCSClientParam5) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalBER(opts...)
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
	return ber.EncodeSequence(children)
}

// MarshalDER encodes UnknownOrUnreachableLCSClientParam5 to DER format.
func (v *UnknownOrUnreachableLCSClientParam5) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: UnknownOrUnreachableLCSClientParam5 receiver is nil", ber.ErrInvalidValue)
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
		return nil, fmt.Errorf("encoding UnknownOrUnreachableLCSClientParam5 as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes UnknownOrUnreachableLCSClientParam5 from BER/DER format.
func (v *UnknownOrUnreachableLCSClientParam5) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: UnknownOrUnreachableLCSClientParam5 destination is nil", ber.ErrInvalidValue)
	}
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = UnknownOrUnreachableLCSClientParam5{}
	defer func() {
		if returnErr != nil || !ber.ConstraintToleranceEnabled(opts) {
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
		return fmt.Errorf("decoding UnknownOrUnreachableLCSClientParam5 SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "UnknownOrUnreachableLCSClientParam5", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode extensionContainer
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassUniversal && peekTag.Number == 16 {
				// Decode nested SEQUENCE (ExtensionContainer5)
				_, n_extensioncontainer, _, tlvErr_extensioncontainer := ber.DecodeTLV(content[offset:], opts...)
				if tlvErr_extensioncontainer != nil {
					return fmt.Errorf("decoding extensionContainer: %w", tlvErr_extensioncontainer)
				}
				var dec_extensioncontainer ExtensionContainer5
				if offset < 0 || offset >
					len(content) || n_extensioncontainer < 0 || n_extensioncontainer > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				if unmErr := dec_extensioncontainer.UnmarshalBER(content[offset:offset+n_extensioncontainer], ber.ChildDecodeOptions(opts, "extensioncontainer")...); unmErr != nil {
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
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:], opts...)
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "UnknownOrUnreachableLCSClientParam5", Cause: extErr_}
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

// MarshalBER encodes MMEventNotSupportedParam5 to BER format.
func (v *MMEventNotSupportedParam5) MarshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: MMEventNotSupportedParam5 receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *MMEventNotSupportedParam5) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalBER(opts...)
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
	return ber.EncodeSequence(children)
}

// MarshalDER encodes MMEventNotSupportedParam5 to DER format.
func (v *MMEventNotSupportedParam5) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: MMEventNotSupportedParam5 receiver is nil", ber.ErrInvalidValue)
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
		return nil, fmt.Errorf("encoding MMEventNotSupportedParam5 as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes MMEventNotSupportedParam5 from BER/DER format.
func (v *MMEventNotSupportedParam5) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: MMEventNotSupportedParam5 destination is nil", ber.ErrInvalidValue)
	}
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = MMEventNotSupportedParam5{}
	defer func() {
		if returnErr != nil || !ber.ConstraintToleranceEnabled(opts) {
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
		return fmt.Errorf("decoding MMEventNotSupportedParam5 SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "MMEventNotSupportedParam5", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode extensionContainer
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassUniversal && peekTag.Number == 16 {
				// Decode nested SEQUENCE (ExtensionContainer5)
				_, n_extensioncontainer, _, tlvErr_extensioncontainer := ber.DecodeTLV(content[offset:], opts...)
				if tlvErr_extensioncontainer != nil {
					return fmt.Errorf("decoding extensionContainer: %w", tlvErr_extensioncontainer)
				}
				var dec_extensioncontainer ExtensionContainer5
				if offset < 0 || offset >
					len(content) || n_extensioncontainer < 0 || n_extensioncontainer >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				if unmErr := dec_extensioncontainer.UnmarshalBER(content[offset:offset+n_extensioncontainer], ber.ChildDecodeOptions(opts, "extensioncontainer")...); unmErr != nil {
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
			return &ber.DecodeError{Offset: offset, TypeName: "MMEventNotSupportedParam5", Cause: extErr_}
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

// MarshalBER encodes TargetCellOutsideGCAParam5 to BER format.
func (v *TargetCellOutsideGCAParam5) MarshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: TargetCellOutsideGCAParam5 receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *TargetCellOutsideGCAParam5) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalBER(opts...)
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
	return ber.EncodeSequence(children)
}

// MarshalDER encodes TargetCellOutsideGCAParam5 to DER format.
func (v *TargetCellOutsideGCAParam5) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: TargetCellOutsideGCAParam5 receiver is nil", ber.ErrInvalidValue)
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
		return nil, fmt.Errorf("encoding TargetCellOutsideGCAParam5 as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes TargetCellOutsideGCAParam5 from BER/DER format.
func (v *TargetCellOutsideGCAParam5) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: TargetCellOutsideGCAParam5 destination is nil", ber.ErrInvalidValue)
	}
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = TargetCellOutsideGCAParam5{}
	defer func() {
		if returnErr != nil || !ber.ConstraintToleranceEnabled(opts) {
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
		return fmt.Errorf("decoding TargetCellOutsideGCAParam5 SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "TargetCellOutsideGCAParam5", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode extensionContainer
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassUniversal && peekTag.Number == 16 {
				// Decode nested SEQUENCE (ExtensionContainer5)
				_, n_extensioncontainer, _, tlvErr_extensioncontainer := ber.DecodeTLV(content[offset:], opts...)
				if tlvErr_extensioncontainer != nil {
					return fmt.Errorf("decoding extensionContainer: %w", tlvErr_extensioncontainer)
				}
				var dec_extensioncontainer ExtensionContainer5
				if offset < 0 || offset >
					len(content) || n_extensioncontainer < 0 || n_extensioncontainer >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				if unmErr := dec_extensioncontainer.UnmarshalBER(content[offset:offset+n_extensioncontainer], ber.ChildDecodeOptions(opts, "extensioncontainer")...); unmErr != nil {
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
			return &ber.DecodeError{Offset: offset, TypeName: "TargetCellOutsideGCAParam5", Cause: extErr_}
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

// MarshalBER encodes OngoingGroupCallParam5 to BER format.
func (v *OngoingGroupCallParam5) MarshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: OngoingGroupCallParam5 receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *OngoingGroupCallParam5) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalBER(opts...)
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
	return ber.EncodeSequence(children)
}

// MarshalDER encodes OngoingGroupCallParam5 to DER format.
func (v *OngoingGroupCallParam5) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: OngoingGroupCallParam5 receiver is nil", ber.ErrInvalidValue)
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
		return nil, fmt.Errorf("encoding OngoingGroupCallParam5 as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes OngoingGroupCallParam5 from BER/DER format.
func (v *OngoingGroupCallParam5) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: OngoingGroupCallParam5 destination is nil", ber.ErrInvalidValue)
	}
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = OngoingGroupCallParam5{}
	defer func() {
		if returnErr != nil || !ber.ConstraintToleranceEnabled(opts) {
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
		return fmt.Errorf("decoding OngoingGroupCallParam5 SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "OngoingGroupCallParam5", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode extensionContainer
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassUniversal && peekTag.Number == 16 {
				// Decode nested SEQUENCE (ExtensionContainer5)
				_, n_extensioncontainer, _, tlvErr_extensioncontainer := ber.DecodeTLV(content[offset:], opts...)
				if tlvErr_extensioncontainer != nil {
					return fmt.Errorf("decoding extensionContainer: %w", tlvErr_extensioncontainer)
				}
				var dec_extensioncontainer ExtensionContainer5
				if offset < 0 || offset >
					len(content) || n_extensioncontainer < 0 || n_extensioncontainer >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				if unmErr := dec_extensioncontainer.UnmarshalBER(content[offset:offset+n_extensioncontainer], ber.ChildDecodeOptions(opts, "extensioncontainer")...); unmErr != nil {
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
			return &ber.DecodeError{Offset: offset, TypeName: "OngoingGroupCallParam5", Cause: extErr_}
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
