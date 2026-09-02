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

// RoamingNotAllowedParam4 represents the ASN.1 type RoamingNotAllowedParam (SEQUENCE).
type RoamingNotAllowedParam4 struct {
	RoamingNotAllowedCause           RoamingNotAllowedCause4            `asn1:""`
	ExtensionContainer               *ExtensionContainer4               `asn1:",optional" json:"ExtensionContainer,omitempty"`
	AdditionalRoamingNotAllowedCause *AdditionalRoamingNotAllowedCause4 `asn1:"tag:0,context,implicit,optional" json:"AdditionalRoamingNotAllowedCause,omitempty"`
	ExtCount_                        int64                              `asn1:"-" json:"-"`
	ExtPresent_                      []bool                             `asn1:"-" json:"-"`
	ExtData_                         [][]byte                           `asn1:"-" json:"-"`
}

// AdditionalRoamingNotAllowedCause4 represents the ASN.1 ENUMERATED type AdditionalRoamingNotAllowedCause.
type AdditionalRoamingNotAllowedCause4 int64

const (
	AdditionalRoamingNotAllowedCause4SupportedRATTypesNotAllowed AdditionalRoamingNotAllowedCause4 = 0
)

func (v AdditionalRoamingNotAllowedCause4) String() string {
	switch v {
	case AdditionalRoamingNotAllowedCause4SupportedRATTypesNotAllowed:
		return "supportedRAT-TypesNotAllowed"
	default:
		return "unknown"
	}
}

// RoamingNotAllowedCause4 represents the ASN.1 ENUMERATED type RoamingNotAllowedCause.
type RoamingNotAllowedCause4 int64

const (
	RoamingNotAllowedCause4PlmnRoamingNotAllowed     RoamingNotAllowedCause4 = 0
	RoamingNotAllowedCause4OperatorDeterminedBarring RoamingNotAllowedCause4 = 3
)

func (v RoamingNotAllowedCause4) String() string {
	switch v {
	case RoamingNotAllowedCause4PlmnRoamingNotAllowed:
		return "plmnRoamingNotAllowed"
	case RoamingNotAllowedCause4OperatorDeterminedBarring:
		return "operatorDeterminedBarring"
	default:
		return "unknown"
	}
}

// CallBarredParam4 choice constants.
const (
	CallBarredParam4ChoiceCallBarringCause          = 1
	CallBarredParam4ChoiceExtensibleCallBarredParam = 2
)

// CallBarredParam4 represents the ASN.1 CHOICE type CallBarredParam.
type CallBarredParam4 struct {
	Choice                    int
	CallBarringCause          *CallBarringCause4          `json:"CallBarringCause,omitempty"`
	ExtensibleCallBarredParam *ExtensibleCallBarredParam4 `json:"ExtensibleCallBarredParam,omitempty"`
}

// NewCallBarredParam4CallBarringCause creates a CallBarredParam4 with the callBarringCause alternative.
func NewCallBarredParam4CallBarringCause(v CallBarringCause4) CallBarredParam4 {
	return CallBarredParam4{
		Choice:           CallBarredParam4ChoiceCallBarringCause,
		CallBarringCause: &v,
	}
}

// NewCallBarredParam4ExtensibleCallBarredParam creates a CallBarredParam4 with the extensibleCallBarredParam alternative.
func NewCallBarredParam4ExtensibleCallBarredParam(v ExtensibleCallBarredParam4) CallBarredParam4 {
	return CallBarredParam4{
		Choice:                    CallBarredParam4ChoiceExtensibleCallBarredParam,
		ExtensibleCallBarredParam: &v,
	}
}

// CallBarringCause4 represents the ASN.1 ENUMERATED type CallBarringCause.
type CallBarringCause4 int64

const (
	CallBarringCause4BarringServiceActive CallBarringCause4 = 0
	CallBarringCause4OperatorBarring      CallBarringCause4 = 1
)

func (v CallBarringCause4) String() string {
	switch v {
	case CallBarringCause4BarringServiceActive:
		return "barringServiceActive"
	case CallBarringCause4OperatorBarring:
		return "operatorBarring"
	default:
		return "unknown"
	}
}

// ExtensibleCallBarredParam4 represents the ASN.1 type ExtensibleCallBarredParam (SEQUENCE).
type ExtensibleCallBarredParam4 struct {
	CallBarringCause              *CallBarringCause4   `asn1:",optional" json:"CallBarringCause,omitempty"`
	ExtensionContainer            *ExtensionContainer4 `asn1:",optional" json:"ExtensionContainer,omitempty"`
	UnauthorisedMessageOriginator *struct{}            `asn1:"tag:1,context,implicit,optional" json:"UnauthorisedMessageOriginator,omitempty"`
	ExtCount_                     int64                `asn1:"-" json:"-"`
	ExtPresent_                   []bool               `asn1:"-" json:"-"`
	ExtData_                      [][]byte             `asn1:"-" json:"-"`
}

// CUGRejectParam4 represents the ASN.1 type CUG-RejectParam (SEQUENCE).
type CUGRejectParam4 struct {
	CugRejectCause     *CUGRejectCause4     `asn1:",optional" json:"CugRejectCause,omitempty"`
	ExtensionContainer *ExtensionContainer4 `asn1:",optional" json:"ExtensionContainer,omitempty"`
	ExtCount_          int64                `asn1:"-" json:"-"`
	ExtPresent_        []bool               `asn1:"-" json:"-"`
	ExtData_           [][]byte             `asn1:"-" json:"-"`
}

// CUGRejectCause4 represents the ASN.1 ENUMERATED type CUG-RejectCause.
type CUGRejectCause4 int64

const (
	CUGRejectCause4IncomingCallsBarredWithinCUG                CUGRejectCause4 = 0
	CUGRejectCause4SubscriberNotMemberOfCUG                    CUGRejectCause4 = 1
	CUGRejectCause4RequestedBasicServiceViolatesCUGConstraints CUGRejectCause4 = 5
	CUGRejectCause4CalledPartySSInteractionViolation           CUGRejectCause4 = 7
)

func (v CUGRejectCause4) String() string {
	switch v {
	case CUGRejectCause4IncomingCallsBarredWithinCUG:
		return "incomingCallsBarredWithinCUG"
	case CUGRejectCause4SubscriberNotMemberOfCUG:
		return "subscriberNotMemberOfCUG"
	case CUGRejectCause4RequestedBasicServiceViolatesCUGConstraints:
		return "requestedBasicServiceViolatesCUG-Constraints"
	case CUGRejectCause4CalledPartySSInteractionViolation:
		return "calledPartySS-InteractionViolation"
	default:
		return "unknown"
	}
}

// SSIncompatibilityCause4 represents the ASN.1 type SS-IncompatibilityCause (SEQUENCE).
type SSIncompatibilityCause4 struct {
	SsCode       *SSCode4           `asn1:"tag:1,context,implicit,optional" json:"SsCode,omitempty"`
	BasicService *BasicServiceCode4 `asn1:",optional" json:"BasicService,omitempty"`
	SsStatus     *SSStatus4         `asn1:"tag:4,context,implicit,optional" json:"SsStatus,omitempty"`
	ExtCount_    int64              `asn1:"-" json:"-"`
	ExtPresent_  []bool             `asn1:"-" json:"-"`
	ExtData_     [][]byte           `asn1:"-" json:"-"`
}

// PWRegistrationFailureCause4 represents the ASN.1 ENUMERATED type PW-RegistrationFailureCause.
type PWRegistrationFailureCause4 int64

const (
	PWRegistrationFailureCause4Undetermined         PWRegistrationFailureCause4 = 0
	PWRegistrationFailureCause4InvalidFormat        PWRegistrationFailureCause4 = 1
	PWRegistrationFailureCause4NewPasswordsMismatch PWRegistrationFailureCause4 = 2
)

func (v PWRegistrationFailureCause4) String() string {
	switch v {
	case PWRegistrationFailureCause4Undetermined:
		return "undetermined"
	case PWRegistrationFailureCause4InvalidFormat:
		return "invalidFormat"
	case PWRegistrationFailureCause4NewPasswordsMismatch:
		return "newPasswordsMismatch"
	default:
		return "unknown"
	}
}

// SMEnumeratedDeliveryFailureCause4 represents the ASN.1 ENUMERATED type SM-EnumeratedDeliveryFailureCause.
type SMEnumeratedDeliveryFailureCause4 int64

const (
	SMEnumeratedDeliveryFailureCause4MemoryCapacityExceeded    SMEnumeratedDeliveryFailureCause4 = 0
	SMEnumeratedDeliveryFailureCause4EquipmentProtocolError    SMEnumeratedDeliveryFailureCause4 = 1
	SMEnumeratedDeliveryFailureCause4EquipmentNotSMEquipped    SMEnumeratedDeliveryFailureCause4 = 2
	SMEnumeratedDeliveryFailureCause4UnknownServiceCentre      SMEnumeratedDeliveryFailureCause4 = 3
	SMEnumeratedDeliveryFailureCause4ScCongestion              SMEnumeratedDeliveryFailureCause4 = 4
	SMEnumeratedDeliveryFailureCause4InvalidSMEAddress         SMEnumeratedDeliveryFailureCause4 = 5
	SMEnumeratedDeliveryFailureCause4SubscriberNotSCSubscriber SMEnumeratedDeliveryFailureCause4 = 6
)

func (v SMEnumeratedDeliveryFailureCause4) String() string {
	switch v {
	case SMEnumeratedDeliveryFailureCause4MemoryCapacityExceeded:
		return "memoryCapacityExceeded"
	case SMEnumeratedDeliveryFailureCause4EquipmentProtocolError:
		return "equipmentProtocolError"
	case SMEnumeratedDeliveryFailureCause4EquipmentNotSMEquipped:
		return "equipmentNotSM-Equipped"
	case SMEnumeratedDeliveryFailureCause4UnknownServiceCentre:
		return "unknownServiceCentre"
	case SMEnumeratedDeliveryFailureCause4ScCongestion:
		return "sc-Congestion"
	case SMEnumeratedDeliveryFailureCause4InvalidSMEAddress:
		return "invalidSME-Address"
	case SMEnumeratedDeliveryFailureCause4SubscriberNotSCSubscriber:
		return "subscriberNotSC-Subscriber"
	default:
		return "unknown"
	}
}

// SMDeliveryFailureCause4 represents the ASN.1 type SM-DeliveryFailureCause (SEQUENCE).
type SMDeliveryFailureCause4 struct {
	SmEnumeratedDeliveryFailureCause SMEnumeratedDeliveryFailureCause4 `asn1:""`
	DiagnosticInfo                   *SignalInfo4                      `asn1:",optional" json:"DiagnosticInfo,omitempty"`
	ExtensionContainer               *ExtensionContainer4              `asn1:",optional" json:"ExtensionContainer,omitempty"`
	ExtCount_                        int64                             `asn1:"-" json:"-"`
	ExtPresent_                      []bool                            `asn1:"-" json:"-"`
	ExtData_                         [][]byte                          `asn1:"-" json:"-"`
}

// AbsentSubscriberSMParam4 represents the ASN.1 type AbsentSubscriberSM-Param (SEQUENCE).
type AbsentSubscriberSMParam4 struct {
	AbsentSubscriberDiagnosticSM           *AbsentSubscriberDiagnosticSM4 `asn1:",optional" json:"AbsentSubscriberDiagnosticSM,omitempty"`
	ExtensionContainer                     *ExtensionContainer4           `asn1:",optional" json:"ExtensionContainer,omitempty"`
	AdditionalAbsentSubscriberDiagnosticSM *AbsentSubscriberDiagnosticSM4 `asn1:"tag:0,context,implicit,optional" json:"AdditionalAbsentSubscriberDiagnosticSM,omitempty"`
	ExtCount_                              int64                          `asn1:"-" json:"-"`
	ExtPresent_                            []bool                         `asn1:"-" json:"-"`
	ExtData_                               [][]byte                       `asn1:"-" json:"-"`
}

// AbsentSubscriberDiagnosticSM4 represents the ASN.1 type AbsentSubscriberDiagnosticSM (INTEGER).
type AbsentSubscriberDiagnosticSM4 = int64

// SystemFailureParam4 choice constants.
const (
	SystemFailureParam4ChoiceNetworkResource              = 1
	SystemFailureParam4ChoiceExtensibleSystemFailureParam = 2
)

// SystemFailureParam4 represents the ASN.1 CHOICE type SystemFailureParam.
type SystemFailureParam4 struct {
	Choice                       int
	NetworkResource              *NetworkResource4              `json:"NetworkResource,omitempty"`
	ExtensibleSystemFailureParam *ExtensibleSystemFailureParam4 `json:"ExtensibleSystemFailureParam,omitempty"`
}

// NewSystemFailureParam4NetworkResource creates a SystemFailureParam4 with the networkResource alternative.
func NewSystemFailureParam4NetworkResource(v NetworkResource4) SystemFailureParam4 {
	return SystemFailureParam4{
		Choice:          SystemFailureParam4ChoiceNetworkResource,
		NetworkResource: &v,
	}
}

// NewSystemFailureParam4ExtensibleSystemFailureParam creates a SystemFailureParam4 with the extensibleSystemFailureParam alternative.
func NewSystemFailureParam4ExtensibleSystemFailureParam(v ExtensibleSystemFailureParam4) SystemFailureParam4 {
	return SystemFailureParam4{
		Choice:                       SystemFailureParam4ChoiceExtensibleSystemFailureParam,
		ExtensibleSystemFailureParam: &v,
	}
}

// ExtensibleSystemFailureParam4 represents the ASN.1 type ExtensibleSystemFailureParam (SEQUENCE).
type ExtensibleSystemFailureParam4 struct {
	NetworkResource           *NetworkResource4           `asn1:",optional" json:"NetworkResource,omitempty"`
	ExtensionContainer        *ExtensionContainer4        `asn1:",optional" json:"ExtensionContainer,omitempty"`
	AdditionalNetworkResource *AdditionalNetworkResource4 `asn1:"tag:0,context,implicit,optional" json:"AdditionalNetworkResource,omitempty"`
	FailureCauseParam         *FailureCauseParam3         `asn1:"tag:1,context,implicit,optional" json:"FailureCauseParam,omitempty"`
	ExtCount_                 int64                       `asn1:"-" json:"-"`
	ExtPresent_               []bool                      `asn1:"-" json:"-"`
	ExtData_                  [][]byte                    `asn1:"-" json:"-"`
}

// FailureCauseParam3 represents the ASN.1 ENUMERATED type FailureCauseParam.
type FailureCauseParam3 int64

const (
	FailureCauseParam3LimitReachedOnNumberOfConcurrentLocationRequests FailureCauseParam3 = 0
)

func (v FailureCauseParam3) String() string {
	switch v {
	case FailureCauseParam3LimitReachedOnNumberOfConcurrentLocationRequests:
		return "limitReachedOnNumberOfConcurrentLocationRequests"
	default:
		return "unknown"
	}
}

// DataMissingParam4 represents the ASN.1 type DataMissingParam (SEQUENCE).
type DataMissingParam4 struct {
	ExtensionContainer *ExtensionContainer4 `asn1:",optional" json:"ExtensionContainer,omitempty"`
	ExtCount_          int64                `asn1:"-" json:"-"`
	ExtPresent_        []bool               `asn1:"-" json:"-"`
	ExtData_           [][]byte             `asn1:"-" json:"-"`
}

// UnexpectedDataParam4 represents the ASN.1 type UnexpectedDataParam (SEQUENCE).
type UnexpectedDataParam4 struct {
	ExtensionContainer *ExtensionContainer4 `asn1:",optional" json:"ExtensionContainer,omitempty"`
	ExtCount_          int64                `asn1:"-" json:"-"`
	ExtPresent_        []bool               `asn1:"-" json:"-"`
	ExtData_           [][]byte             `asn1:"-" json:"-"`
}

// FacilityNotSupParam4 represents the ASN.1 type FacilityNotSupParam (SEQUENCE).
type FacilityNotSupParam4 struct {
	ExtensionContainer                           *ExtensionContainer4 `asn1:",optional" json:"ExtensionContainer,omitempty"`
	ShapeOfLocationEstimateNotSupported          *struct{}            `asn1:"tag:0,context,implicit,optional" json:"ShapeOfLocationEstimateNotSupported,omitempty"`
	NeededLcsCapabilityNotSupportedInServingNode *struct{}            `asn1:"tag:1,context,implicit,optional" json:"NeededLcsCapabilityNotSupportedInServingNode,omitempty"`
	ExtCount_                                    int64                `asn1:"-" json:"-"`
	ExtPresent_                                  []bool               `asn1:"-" json:"-"`
	ExtData_                                     [][]byte             `asn1:"-" json:"-"`
}

// ORNotAllowedParam4 represents the ASN.1 type OR-NotAllowedParam (SEQUENCE).
type ORNotAllowedParam4 struct {
	ExtensionContainer *ExtensionContainer4 `asn1:",optional" json:"ExtensionContainer,omitempty"`
	ExtCount_          int64                `asn1:"-" json:"-"`
	ExtPresent_        []bool               `asn1:"-" json:"-"`
	ExtData_           [][]byte             `asn1:"-" json:"-"`
}

// UnknownSubscriberParam4 represents the ASN.1 type UnknownSubscriberParam (SEQUENCE).
type UnknownSubscriberParam4 struct {
	ExtensionContainer          *ExtensionContainer4          `asn1:",optional" json:"ExtensionContainer,omitempty"`
	UnknownSubscriberDiagnostic *UnknownSubscriberDiagnostic4 `asn1:",optional" json:"UnknownSubscriberDiagnostic,omitempty"`
	ExtCount_                   int64                         `asn1:"-" json:"-"`
	ExtPresent_                 []bool                        `asn1:"-" json:"-"`
	ExtData_                    [][]byte                      `asn1:"-" json:"-"`
}

// UnknownSubscriberDiagnostic4 represents the ASN.1 ENUMERATED type UnknownSubscriberDiagnostic.
type UnknownSubscriberDiagnostic4 int64

const (
	UnknownSubscriberDiagnostic4ImsiUnknown                UnknownSubscriberDiagnostic4 = 0
	UnknownSubscriberDiagnostic4GprsEpsSubscriptionUnknown UnknownSubscriberDiagnostic4 = 1
	UnknownSubscriberDiagnostic4NpdbMismatch               UnknownSubscriberDiagnostic4 = 2
)

func (v UnknownSubscriberDiagnostic4) String() string {
	switch v {
	case UnknownSubscriberDiagnostic4ImsiUnknown:
		return "imsiUnknown"
	case UnknownSubscriberDiagnostic4GprsEpsSubscriptionUnknown:
		return "gprs-eps-SubscriptionUnknown"
	case UnknownSubscriberDiagnostic4NpdbMismatch:
		return "npdbMismatch"
	default:
		return "unknown"
	}
}

// NumberChangedParam4 represents the ASN.1 type NumberChangedParam (SEQUENCE).
type NumberChangedParam4 struct {
	ExtensionContainer *ExtensionContainer4 `asn1:",optional" json:"ExtensionContainer,omitempty"`
	ExtCount_          int64                `asn1:"-" json:"-"`
	ExtPresent_        []bool               `asn1:"-" json:"-"`
	ExtData_           [][]byte             `asn1:"-" json:"-"`
}

// UnidentifiedSubParam4 represents the ASN.1 type UnidentifiedSubParam (SEQUENCE).
type UnidentifiedSubParam4 struct {
	ExtensionContainer *ExtensionContainer4 `asn1:",optional" json:"ExtensionContainer,omitempty"`
	ExtCount_          int64                `asn1:"-" json:"-"`
	ExtPresent_        []bool               `asn1:"-" json:"-"`
	ExtData_           [][]byte             `asn1:"-" json:"-"`
}

// IllegalSubscriberParam4 represents the ASN.1 type IllegalSubscriberParam (SEQUENCE).
type IllegalSubscriberParam4 struct {
	ExtensionContainer *ExtensionContainer4 `asn1:",optional" json:"ExtensionContainer,omitempty"`
	ExtCount_          int64                `asn1:"-" json:"-"`
	ExtPresent_        []bool               `asn1:"-" json:"-"`
	ExtData_           [][]byte             `asn1:"-" json:"-"`
}

// IllegalEquipmentParam4 represents the ASN.1 type IllegalEquipmentParam (SEQUENCE).
type IllegalEquipmentParam4 struct {
	ExtensionContainer *ExtensionContainer4 `asn1:",optional" json:"ExtensionContainer,omitempty"`
	ExtCount_          int64                `asn1:"-" json:"-"`
	ExtPresent_        []bool               `asn1:"-" json:"-"`
	ExtData_           [][]byte             `asn1:"-" json:"-"`
}

// BearerServNotProvParam4 represents the ASN.1 type BearerServNotProvParam (SEQUENCE).
type BearerServNotProvParam4 struct {
	ExtensionContainer *ExtensionContainer4 `asn1:",optional" json:"ExtensionContainer,omitempty"`
	ExtCount_          int64                `asn1:"-" json:"-"`
	ExtPresent_        []bool               `asn1:"-" json:"-"`
	ExtData_           [][]byte             `asn1:"-" json:"-"`
}

// TeleservNotProvParam4 represents the ASN.1 type TeleservNotProvParam (SEQUENCE).
type TeleservNotProvParam4 struct {
	ExtensionContainer *ExtensionContainer4 `asn1:",optional" json:"ExtensionContainer,omitempty"`
	ExtCount_          int64                `asn1:"-" json:"-"`
	ExtPresent_        []bool               `asn1:"-" json:"-"`
	ExtData_           [][]byte             `asn1:"-" json:"-"`
}

// TracingBufferFullParam4 represents the ASN.1 type TracingBufferFullParam (SEQUENCE).
type TracingBufferFullParam4 struct {
	ExtensionContainer *ExtensionContainer4 `asn1:",optional" json:"ExtensionContainer,omitempty"`
	ExtCount_          int64                `asn1:"-" json:"-"`
	ExtPresent_        []bool               `asn1:"-" json:"-"`
	ExtData_           [][]byte             `asn1:"-" json:"-"`
}

// NoRoamingNbParam4 represents the ASN.1 type NoRoamingNbParam (SEQUENCE).
type NoRoamingNbParam4 struct {
	ExtensionContainer *ExtensionContainer4 `asn1:",optional" json:"ExtensionContainer,omitempty"`
	ExtCount_          int64                `asn1:"-" json:"-"`
	ExtPresent_        []bool               `asn1:"-" json:"-"`
	ExtData_           [][]byte             `asn1:"-" json:"-"`
}

// AbsentSubscriberParam4 represents the ASN.1 type AbsentSubscriberParam (SEQUENCE).
type AbsentSubscriberParam4 struct {
	ExtensionContainer     *ExtensionContainer4     `asn1:",optional" json:"ExtensionContainer,omitempty"`
	AbsentSubscriberReason *AbsentSubscriberReason4 `asn1:"tag:0,context,implicit,optional" json:"AbsentSubscriberReason,omitempty"`
	ExtCount_              int64                    `asn1:"-" json:"-"`
	ExtPresent_            []bool                   `asn1:"-" json:"-"`
	ExtData_               [][]byte                 `asn1:"-" json:"-"`
}

// AbsentSubscriberReason4 represents the ASN.1 ENUMERATED type AbsentSubscriberReason.
type AbsentSubscriberReason4 int64

const (
	AbsentSubscriberReason4ImsiDetach     AbsentSubscriberReason4 = 0
	AbsentSubscriberReason4RestrictedArea AbsentSubscriberReason4 = 1
	AbsentSubscriberReason4NoPageResponse AbsentSubscriberReason4 = 2
	AbsentSubscriberReason4PurgedMS       AbsentSubscriberReason4 = 3
	AbsentSubscriberReason4MtRoamingRetry AbsentSubscriberReason4 = 4
	AbsentSubscriberReason4BusySubscriber AbsentSubscriberReason4 = 5
)

func (v AbsentSubscriberReason4) String() string {
	switch v {
	case AbsentSubscriberReason4ImsiDetach:
		return "imsiDetach"
	case AbsentSubscriberReason4RestrictedArea:
		return "restrictedArea"
	case AbsentSubscriberReason4NoPageResponse:
		return "noPageResponse"
	case AbsentSubscriberReason4PurgedMS:
		return "purgedMS"
	case AbsentSubscriberReason4MtRoamingRetry:
		return "mtRoamingRetry"
	case AbsentSubscriberReason4BusySubscriber:
		return "busySubscriber"
	default:
		return "unknown"
	}
}

// BusySubscriberParam4 represents the ASN.1 type BusySubscriberParam (SEQUENCE).
type BusySubscriberParam4 struct {
	ExtensionContainer *ExtensionContainer4 `asn1:",optional" json:"ExtensionContainer,omitempty"`
	CcbsPossible       *struct{}            `asn1:"tag:0,context,implicit,optional" json:"CcbsPossible,omitempty"`
	CcbsBusy           *struct{}            `asn1:"tag:1,context,implicit,optional" json:"CcbsBusy,omitempty"`
	ExtCount_          int64                `asn1:"-" json:"-"`
	ExtPresent_        []bool               `asn1:"-" json:"-"`
	ExtData_           [][]byte             `asn1:"-" json:"-"`
}

// NoSubscriberReplyParam4 represents the ASN.1 type NoSubscriberReplyParam (SEQUENCE).
type NoSubscriberReplyParam4 struct {
	ExtensionContainer *ExtensionContainer4 `asn1:",optional" json:"ExtensionContainer,omitempty"`
	ExtCount_          int64                `asn1:"-" json:"-"`
	ExtPresent_        []bool               `asn1:"-" json:"-"`
	ExtData_           [][]byte             `asn1:"-" json:"-"`
}

// ForwardingViolationParam4 represents the ASN.1 type ForwardingViolationParam (SEQUENCE).
type ForwardingViolationParam4 struct {
	ExtensionContainer *ExtensionContainer4 `asn1:",optional" json:"ExtensionContainer,omitempty"`
	ExtCount_          int64                `asn1:"-" json:"-"`
	ExtPresent_        []bool               `asn1:"-" json:"-"`
	ExtData_           [][]byte             `asn1:"-" json:"-"`
}

// ForwardingFailedParam4 represents the ASN.1 type ForwardingFailedParam (SEQUENCE).
type ForwardingFailedParam4 struct {
	ExtensionContainer *ExtensionContainer4 `asn1:",optional" json:"ExtensionContainer,omitempty"`
	ExtCount_          int64                `asn1:"-" json:"-"`
	ExtPresent_        []bool               `asn1:"-" json:"-"`
	ExtData_           [][]byte             `asn1:"-" json:"-"`
}

// ATINotAllowedParam4 represents the ASN.1 type ATI-NotAllowedParam (SEQUENCE).
type ATINotAllowedParam4 struct {
	ExtensionContainer *ExtensionContainer4 `asn1:",optional" json:"ExtensionContainer,omitempty"`
	ExtCount_          int64                `asn1:"-" json:"-"`
	ExtPresent_        []bool               `asn1:"-" json:"-"`
	ExtData_           [][]byte             `asn1:"-" json:"-"`
}

// ATSINotAllowedParam4 represents the ASN.1 type ATSI-NotAllowedParam (SEQUENCE).
type ATSINotAllowedParam4 struct {
	ExtensionContainer *ExtensionContainer4 `asn1:",optional" json:"ExtensionContainer,omitempty"`
	ExtCount_          int64                `asn1:"-" json:"-"`
	ExtPresent_        []bool               `asn1:"-" json:"-"`
	ExtData_           [][]byte             `asn1:"-" json:"-"`
}

// ATMNotAllowedParam4 represents the ASN.1 type ATM-NotAllowedParam (SEQUENCE).
type ATMNotAllowedParam4 struct {
	ExtensionContainer *ExtensionContainer4 `asn1:",optional" json:"ExtensionContainer,omitempty"`
	ExtCount_          int64                `asn1:"-" json:"-"`
	ExtPresent_        []bool               `asn1:"-" json:"-"`
	ExtData_           [][]byte             `asn1:"-" json:"-"`
}

// IllegalSSOperationParam4 represents the ASN.1 type IllegalSS-OperationParam (SEQUENCE).
type IllegalSSOperationParam4 struct {
	ExtensionContainer *ExtensionContainer4 `asn1:",optional" json:"ExtensionContainer,omitempty"`
	ExtCount_          int64                `asn1:"-" json:"-"`
	ExtPresent_        []bool               `asn1:"-" json:"-"`
	ExtData_           [][]byte             `asn1:"-" json:"-"`
}

// SSNotAvailableParam4 represents the ASN.1 type SS-NotAvailableParam (SEQUENCE).
type SSNotAvailableParam4 struct {
	ExtensionContainer *ExtensionContainer4 `asn1:",optional" json:"ExtensionContainer,omitempty"`
	ExtCount_          int64                `asn1:"-" json:"-"`
	ExtPresent_        []bool               `asn1:"-" json:"-"`
	ExtData_           [][]byte             `asn1:"-" json:"-"`
}

// SSSubscriptionViolationParam4 represents the ASN.1 type SS-SubscriptionViolationParam (SEQUENCE).
type SSSubscriptionViolationParam4 struct {
	ExtensionContainer *ExtensionContainer4 `asn1:",optional" json:"ExtensionContainer,omitempty"`
	ExtCount_          int64                `asn1:"-" json:"-"`
	ExtPresent_        []bool               `asn1:"-" json:"-"`
	ExtData_           [][]byte             `asn1:"-" json:"-"`
}

// InformationNotAvailableParam4 represents the ASN.1 type InformationNotAvailableParam (SEQUENCE).
type InformationNotAvailableParam4 struct {
	ExtensionContainer *ExtensionContainer4 `asn1:",optional" json:"ExtensionContainer,omitempty"`
	ExtCount_          int64                `asn1:"-" json:"-"`
	ExtPresent_        []bool               `asn1:"-" json:"-"`
	ExtData_           [][]byte             `asn1:"-" json:"-"`
}

// SubBusyForMTSMSParam4 represents the ASN.1 type SubBusyForMT-SMS-Param (SEQUENCE).
type SubBusyForMTSMSParam4 struct {
	ExtensionContainer      *ExtensionContainer4 `asn1:",optional" json:"ExtensionContainer,omitempty"`
	GprsConnectionSuspended *struct{}            `asn1:",optional" json:"GprsConnectionSuspended,omitempty"`
	ExtCount_               int64                `asn1:"-" json:"-"`
	ExtPresent_             []bool               `asn1:"-" json:"-"`
	ExtData_                [][]byte             `asn1:"-" json:"-"`
}

// MessageWaitListFullParam4 represents the ASN.1 type MessageWaitListFullParam (SEQUENCE).
type MessageWaitListFullParam4 struct {
	ExtensionContainer *ExtensionContainer4 `asn1:",optional" json:"ExtensionContainer,omitempty"`
	ExtCount_          int64                `asn1:"-" json:"-"`
	ExtPresent_        []bool               `asn1:"-" json:"-"`
	ExtData_           [][]byte             `asn1:"-" json:"-"`
}

// ResourceLimitationParam4 represents the ASN.1 type ResourceLimitationParam (SEQUENCE).
type ResourceLimitationParam4 struct {
	ExtensionContainer *ExtensionContainer4 `asn1:",optional" json:"ExtensionContainer,omitempty"`
	ExtCount_          int64                `asn1:"-" json:"-"`
	ExtPresent_        []bool               `asn1:"-" json:"-"`
	ExtData_           [][]byte             `asn1:"-" json:"-"`
}

// NoGroupCallNbParam4 represents the ASN.1 type NoGroupCallNbParam (SEQUENCE).
type NoGroupCallNbParam4 struct {
	ExtensionContainer *ExtensionContainer4 `asn1:",optional" json:"ExtensionContainer,omitempty"`
	ExtCount_          int64                `asn1:"-" json:"-"`
	ExtPresent_        []bool               `asn1:"-" json:"-"`
	ExtData_           [][]byte             `asn1:"-" json:"-"`
}

// IncompatibleTerminalParam4 represents the ASN.1 type IncompatibleTerminalParam (SEQUENCE).
type IncompatibleTerminalParam4 struct {
	ExtensionContainer *ExtensionContainer4 `asn1:",optional" json:"ExtensionContainer,omitempty"`
	ExtCount_          int64                `asn1:"-" json:"-"`
	ExtPresent_        []bool               `asn1:"-" json:"-"`
	ExtData_           [][]byte             `asn1:"-" json:"-"`
}

// ShortTermDenialParam4 represents the ASN.1 type ShortTermDenialParam (SEQUENCE).
type ShortTermDenialParam4 struct {
	ExtCount_   int64    `asn1:"-" json:"-"`
	ExtPresent_ []bool   `asn1:"-" json:"-"`
	ExtData_    [][]byte `asn1:"-" json:"-"`
}

// LongTermDenialParam4 represents the ASN.1 type LongTermDenialParam (SEQUENCE).
type LongTermDenialParam4 struct {
	ExtCount_   int64    `asn1:"-" json:"-"`
	ExtPresent_ []bool   `asn1:"-" json:"-"`
	ExtData_    [][]byte `asn1:"-" json:"-"`
}

// UnauthorizedRequestingNetworkParam4 represents the ASN.1 type UnauthorizedRequestingNetwork-Param (SEQUENCE).
type UnauthorizedRequestingNetworkParam4 struct {
	ExtensionContainer *ExtensionContainer4 `asn1:",optional" json:"ExtensionContainer,omitempty"`
	ExtCount_          int64                `asn1:"-" json:"-"`
	ExtPresent_        []bool               `asn1:"-" json:"-"`
	ExtData_           [][]byte             `asn1:"-" json:"-"`
}

// UnauthorizedLCSClientParam4 represents the ASN.1 type UnauthorizedLCSClient-Param (SEQUENCE).
type UnauthorizedLCSClientParam4 struct {
	UnauthorizedLCSClientDiagnostic *UnauthorizedLCSClientDiagnostic4 `asn1:"tag:0,context,implicit,optional" json:"UnauthorizedLCSClientDiagnostic,omitempty"`
	ExtensionContainer              *ExtensionContainer4              `asn1:"tag:1,context,implicit,optional" json:"ExtensionContainer,omitempty"`
	ExtCount_                       int64                             `asn1:"-" json:"-"`
	ExtPresent_                     []bool                            `asn1:"-" json:"-"`
	ExtData_                        [][]byte                          `asn1:"-" json:"-"`
}

// UnauthorizedLCSClientDiagnostic4 represents the ASN.1 ENUMERATED type UnauthorizedLCSClient-Diagnostic.
type UnauthorizedLCSClientDiagnostic4 int64

const (
	UnauthorizedLCSClientDiagnostic4NoAdditionalInformation                        UnauthorizedLCSClientDiagnostic4 = 0
	UnauthorizedLCSClientDiagnostic4ClientNotInMSPrivacyExceptionList              UnauthorizedLCSClientDiagnostic4 = 1
	UnauthorizedLCSClientDiagnostic4CallToClientNotSetup                           UnauthorizedLCSClientDiagnostic4 = 2
	UnauthorizedLCSClientDiagnostic4PrivacyOverrideNotApplicable                   UnauthorizedLCSClientDiagnostic4 = 3
	UnauthorizedLCSClientDiagnostic4DisallowedByLocalRegulatoryRequirements        UnauthorizedLCSClientDiagnostic4 = 4
	UnauthorizedLCSClientDiagnostic4UnauthorizedPrivacyClass                       UnauthorizedLCSClientDiagnostic4 = 5
	UnauthorizedLCSClientDiagnostic4UnauthorizedCallSessionUnrelatedExternalClient UnauthorizedLCSClientDiagnostic4 = 6
	UnauthorizedLCSClientDiagnostic4UnauthorizedCallSessionRelatedExternalClient   UnauthorizedLCSClientDiagnostic4 = 7
)

func (v UnauthorizedLCSClientDiagnostic4) String() string {
	switch v {
	case UnauthorizedLCSClientDiagnostic4NoAdditionalInformation:
		return "noAdditionalInformation"
	case UnauthorizedLCSClientDiagnostic4ClientNotInMSPrivacyExceptionList:
		return "clientNotInMSPrivacyExceptionList"
	case UnauthorizedLCSClientDiagnostic4CallToClientNotSetup:
		return "callToClientNotSetup"
	case UnauthorizedLCSClientDiagnostic4PrivacyOverrideNotApplicable:
		return "privacyOverrideNotApplicable"
	case UnauthorizedLCSClientDiagnostic4DisallowedByLocalRegulatoryRequirements:
		return "disallowedByLocalRegulatoryRequirements"
	case UnauthorizedLCSClientDiagnostic4UnauthorizedPrivacyClass:
		return "unauthorizedPrivacyClass"
	case UnauthorizedLCSClientDiagnostic4UnauthorizedCallSessionUnrelatedExternalClient:
		return "unauthorizedCallSessionUnrelatedExternalClient"
	case UnauthorizedLCSClientDiagnostic4UnauthorizedCallSessionRelatedExternalClient:
		return "unauthorizedCallSessionRelatedExternalClient"
	default:
		return "unknown"
	}
}

// PositionMethodFailureParam4 represents the ASN.1 type PositionMethodFailure-Param (SEQUENCE).
type PositionMethodFailureParam4 struct {
	PositionMethodFailureDiagnostic *PositionMethodFailureDiagnostic4 `asn1:"tag:0,context,implicit,optional" json:"PositionMethodFailureDiagnostic,omitempty"`
	ExtensionContainer              *ExtensionContainer4              `asn1:"tag:1,context,implicit,optional" json:"ExtensionContainer,omitempty"`
	ExtCount_                       int64                             `asn1:"-" json:"-"`
	ExtPresent_                     []bool                            `asn1:"-" json:"-"`
	ExtData_                        [][]byte                          `asn1:"-" json:"-"`
}

// PositionMethodFailureDiagnostic4 represents the ASN.1 ENUMERATED type PositionMethodFailure-Diagnostic.
type PositionMethodFailureDiagnostic4 int64

const (
	PositionMethodFailureDiagnostic4Congestion                               PositionMethodFailureDiagnostic4 = 0
	PositionMethodFailureDiagnostic4InsufficientResources                    PositionMethodFailureDiagnostic4 = 1
	PositionMethodFailureDiagnostic4InsufficientMeasurementData              PositionMethodFailureDiagnostic4 = 2
	PositionMethodFailureDiagnostic4InconsistentMeasurementData              PositionMethodFailureDiagnostic4 = 3
	PositionMethodFailureDiagnostic4LocationProcedureNotCompleted            PositionMethodFailureDiagnostic4 = 4
	PositionMethodFailureDiagnostic4LocationProcedureNotSupportedByTargetMS  PositionMethodFailureDiagnostic4 = 5
	PositionMethodFailureDiagnostic4QoSNotAttainable                         PositionMethodFailureDiagnostic4 = 6
	PositionMethodFailureDiagnostic4PositionMethodNotAvailableInNetwork      PositionMethodFailureDiagnostic4 = 7
	PositionMethodFailureDiagnostic4PositionMethodNotAvailableInLocationArea PositionMethodFailureDiagnostic4 = 8
)

func (v PositionMethodFailureDiagnostic4) String() string {
	switch v {
	case PositionMethodFailureDiagnostic4Congestion:
		return "congestion"
	case PositionMethodFailureDiagnostic4InsufficientResources:
		return "insufficientResources"
	case PositionMethodFailureDiagnostic4InsufficientMeasurementData:
		return "insufficientMeasurementData"
	case PositionMethodFailureDiagnostic4InconsistentMeasurementData:
		return "inconsistentMeasurementData"
	case PositionMethodFailureDiagnostic4LocationProcedureNotCompleted:
		return "locationProcedureNotCompleted"
	case PositionMethodFailureDiagnostic4LocationProcedureNotSupportedByTargetMS:
		return "locationProcedureNotSupportedByTargetMS"
	case PositionMethodFailureDiagnostic4QoSNotAttainable:
		return "qoSNotAttainable"
	case PositionMethodFailureDiagnostic4PositionMethodNotAvailableInNetwork:
		return "positionMethodNotAvailableInNetwork"
	case PositionMethodFailureDiagnostic4PositionMethodNotAvailableInLocationArea:
		return "positionMethodNotAvailableInLocationArea"
	default:
		return "unknown"
	}
}

// UnknownOrUnreachableLCSClientParam4 represents the ASN.1 type UnknownOrUnreachableLCSClient-Param (SEQUENCE).
type UnknownOrUnreachableLCSClientParam4 struct {
	ExtensionContainer *ExtensionContainer4 `asn1:",optional" json:"ExtensionContainer,omitempty"`
	ExtCount_          int64                `asn1:"-" json:"-"`
	ExtPresent_        []bool               `asn1:"-" json:"-"`
	ExtData_           [][]byte             `asn1:"-" json:"-"`
}

// MMEventNotSupportedParam4 represents the ASN.1 type MM-EventNotSupported-Param (SEQUENCE).
type MMEventNotSupportedParam4 struct {
	ExtensionContainer *ExtensionContainer4 `asn1:",optional" json:"ExtensionContainer,omitempty"`
	ExtCount_          int64                `asn1:"-" json:"-"`
	ExtPresent_        []bool               `asn1:"-" json:"-"`
	ExtData_           [][]byte             `asn1:"-" json:"-"`
}

// TargetCellOutsideGCAParam4 represents the ASN.1 type TargetCellOutsideGCA-Param (SEQUENCE).
type TargetCellOutsideGCAParam4 struct {
	ExtensionContainer *ExtensionContainer4 `asn1:",optional" json:"ExtensionContainer,omitempty"`
	ExtCount_          int64                `asn1:"-" json:"-"`
	ExtPresent_        []bool               `asn1:"-" json:"-"`
	ExtData_           [][]byte             `asn1:"-" json:"-"`
}

// OngoingGroupCallParam4 represents the ASN.1 type OngoingGroupCallParam (SEQUENCE).
type OngoingGroupCallParam4 struct {
	ExtensionContainer *ExtensionContainer4 `asn1:",optional" json:"ExtensionContainer,omitempty"`
	ExtCount_          int64                `asn1:"-" json:"-"`
	ExtPresent_        []bool               `asn1:"-" json:"-"`
	ExtData_           [][]byte             `asn1:"-" json:"-"`
}

// MarshalBER encodes RoamingNotAllowedParam4 to BER format.
func (v *RoamingNotAllowedParam4) MarshalBER() ([]byte, error) {
	var children []byte
	enc_roamingnotallowedcause := ber.EncodeEnumerated(int64(v.RoamingNotAllowedCause))
	children = append(children, enc_roamingnotallowedcause...)
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalBER()
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
	return ber.EncodeSequence(children), nil
}

// MarshalDER encodes RoamingNotAllowedParam4 to DER format.
func (v *RoamingNotAllowedParam4) MarshalDER() ([]byte, error) {
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
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
		children = append(children, ext...)
	}
	encoded := ber.EncodeSequence(children)
	if err := ber.ValidateDERElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding RoamingNotAllowedParam4 as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes RoamingNotAllowedParam4 from BER/DER format.
func (v *RoamingNotAllowedParam4) UnmarshalBER(data []byte) error {
	*v = RoamingNotAllowedParam4{}
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding RoamingNotAllowedParam4 SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "RoamingNotAllowedParam4", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode roamingNotAllowedCause
	if offset >= len(content) {
		return fmt.Errorf("missing required field roamingNotAllowedCause")
	}
	val_roamingnotallowedcause, n, err := ber.DecodeEnumerated(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding roamingNotAllowedCause: %w", err)
	}
	v.RoamingNotAllowedCause = RoamingNotAllowedCause4(val_roamingnotallowedcause)
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
	// Decode additionalRoamingNotAllowedCause
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
				decodedTag_additionalroamingnotallowedcause, n_additionalroamingnotallowedcause, rawVal_additionalroamingnotallowedcause, err := ber.DecodeTLV(content[offset:])
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
				tmp_additionalroamingnotallowedcause := AdditionalRoamingNotAllowedCause4(decVal_additionalroamingnotallowedcause)
				v.AdditionalRoamingNotAllowedCause = &tmp_additionalroamingnotallowedcause
				offset += n_additionalroamingnotallowedcause
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "RoamingNotAllowedParam4", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes CallBarredParam4 to BER format.
func (v *CallBarredParam4) MarshalBER() ([]byte, error) {
	switch v.Choice {
	case CallBarredParam4ChoiceCallBarringCause:
		if v.CallBarringCause == nil {
			return nil, fmt.Errorf("choice CallBarredParam4: callBarringCause is nil")
		}
		enc_0 := ber.EncodeEnumerated(int64(*v.CallBarringCause))
		return enc_0, nil
	case CallBarredParam4ChoiceExtensibleCallBarredParam:
		if v.ExtensibleCallBarredParam == nil {
			return nil, fmt.Errorf("choice CallBarredParam4: extensibleCallBarredParam is nil")
		}
		enc_1, err := v.ExtensibleCallBarredParam.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding extensibleCallBarredParam: %w", err)
		}
		return enc_1, nil
	default:
		return nil, fmt.Errorf("unknown choice %d for CallBarredParam4", v.Choice)
	}
}

// MarshalDER encodes CallBarredParam4 to DER format.
func (v *CallBarredParam4) MarshalDER() ([]byte, error) {
	switch v.Choice {
	case CallBarredParam4ChoiceExtensibleCallBarredParam:
		if v.ExtensibleCallBarredParam == nil {
			return nil, fmt.Errorf("choice CallBarredParam4: extensibleCallBarredParam is nil")
		}
		enc_der_1, err := v.ExtensibleCallBarredParam.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding extensibleCallBarredParam: %w", err)
		}
		if derErr := ber.ValidateDERElement(enc_der_1); derErr != nil {
			return nil, fmt.Errorf("encoding extensibleCallBarredParam as DER: %w", derErr)
		}
		return enc_der_1, nil
	}
	encoded, err := v.MarshalBER()
	if err != nil {
		return nil, err
	}
	if err := ber.ValidateDERElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding CallBarredParam4 as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes CallBarredParam4 from BER/DER format.
func (v *CallBarredParam4) UnmarshalBER(data []byte) error {
	*v = CallBarredParam4{}
	if len(data) == 0 {
		return fmt.Errorf("empty data for CallBarredParam4 CHOICE")
	}
	choiceData := data
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for CallBarredParam4: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData)
	if tlvErr != nil {
		return fmt.Errorf("decoding CallBarredParam4 CHOICE: %w", tlvErr)
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "CallBarredParam4", Cause: ber.ErrExtraData}
	}

	if peekTag.Class == tag.ClassUniversal && peekTag.Number == 10 && peekTag.Constructed == false {
		v.Choice = CallBarredParam4ChoiceCallBarringCause
		decVal, _, intErr := ber.DecodeEnumerated(choiceData)
		if intErr != nil {
			return fmt.Errorf("decoding callBarringCause: %w", intErr)
		}
		tmp := CallBarringCause4(decVal)
		v.CallBarringCause = &tmp
	} else if peekTag.Class == tag.ClassUniversal && peekTag.Number == 16 && peekTag.Constructed == true {
		v.Choice = CallBarredParam4ChoiceExtensibleCallBarredParam
		var dec ExtensibleCallBarredParam4
		if unmErr := dec.UnmarshalBER(choiceData); unmErr != nil {
			return fmt.Errorf("decoding extensibleCallBarredParam: %w", unmErr)
		}
		v.ExtensibleCallBarredParam = &dec
	} else {
		return fmt.Errorf("unknown tag %s for CallBarredParam4 CHOICE", peekTag)
	}
	return nil
}

// MarshalBER encodes ExtensibleCallBarredParam4 to BER format.
func (v *ExtensibleCallBarredParam4) MarshalBER() ([]byte, error) {
	var children []byte
	if v.CallBarringCause != nil {
		enc_callbarringcause := ber.EncodeEnumerated(int64(*v.CallBarringCause))
		children = append(children, enc_callbarringcause...)
	}
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalBER()
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
	return ber.EncodeSequence(children), nil
}

// MarshalDER encodes ExtensibleCallBarredParam4 to DER format.
func (v *ExtensibleCallBarredParam4) MarshalDER() ([]byte, error) {
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
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
		children = append(children, ext...)
	}
	encoded := ber.EncodeSequence(children)
	if err := ber.ValidateDERElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding ExtensibleCallBarredParam4 as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes ExtensibleCallBarredParam4 from BER/DER format.
func (v *ExtensibleCallBarredParam4) UnmarshalBER(data []byte) error {
	*v = ExtensibleCallBarredParam4{}
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding ExtensibleCallBarredParam4 SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "ExtensibleCallBarredParam4", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode callBarringCause
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassUniversal && peekTag.Number == 10 {
				val_callbarringcause, n, err := ber.DecodeEnumerated(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding callBarringCause: %w", err)
				}
				tmp_callbarringcause := CallBarringCause4(val_callbarringcause)
				v.CallBarringCause = &tmp_callbarringcause
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
	// Decode unauthorisedMessageOriginator
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
				decodedTag_unauthorisedmessageoriginator, n_unauthorisedmessageoriginator, rawVal_unauthorisedmessageoriginator, err := ber.DecodeTLV(content[offset:])
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
				offset += n_unauthorisedmessageoriginator
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "ExtensibleCallBarredParam4", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes CUGRejectParam4 to BER format.
func (v *CUGRejectParam4) MarshalBER() ([]byte, error) {
	var children []byte
	if v.CugRejectCause != nil {
		enc_cugrejectcause := ber.EncodeEnumerated(int64(*v.CugRejectCause))
		children = append(children, enc_cugrejectcause...)
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

// MarshalDER encodes CUGRejectParam4 to DER format.
func (v *CUGRejectParam4) MarshalDER() ([]byte, error) {
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
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
		children = append(children, ext...)
	}
	encoded := ber.EncodeSequence(children)
	if err := ber.ValidateDERElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding CUGRejectParam4 as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes CUGRejectParam4 from BER/DER format.
func (v *CUGRejectParam4) UnmarshalBER(data []byte) error {
	*v = CUGRejectParam4{}
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding CUGRejectParam4 SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "CUGRejectParam4", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode cug-RejectCause
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassUniversal && peekTag.Number == 10 {
				val_cugrejectcause, n, err := ber.DecodeEnumerated(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding cug-RejectCause: %w", err)
				}
				tmp_cugrejectcause := CUGRejectCause4(val_cugrejectcause)
				v.CugRejectCause = &tmp_cugrejectcause
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
			return &ber.DecodeError{Offset: offset, TypeName: "CUGRejectParam4", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes SSIncompatibilityCause4 to BER format.
func (v *SSIncompatibilityCause4) MarshalBER() ([]byte, error) {
	var children []byte
	if v.SsCode != nil {
		enc_sscode := ber.EncodeOctetString([]byte(*v.SsCode))
		retagged_enc_sscode, tagErr_enc_sscode := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_sscode)
		if tagErr_enc_sscode != nil {
			return nil, fmt.Errorf("encoding ss-Code: %w", tagErr_enc_sscode)
		}
		enc_sscode = retagged_enc_sscode
		children = append(children, enc_sscode...)
	}
	if v.BasicService != nil {
		enc_basicservice, err := v.BasicService.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding basicService: %w", err)
		}
		children = append(children, enc_basicservice...)
	}
	if v.SsStatus != nil {
		enc_ssstatus := ber.EncodeOctetString([]byte(*v.SsStatus))
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
	return ber.EncodeSequence(children), nil
}

// MarshalDER encodes SSIncompatibilityCause4 to DER format.
func (v *SSIncompatibilityCause4) MarshalDER() ([]byte, error) {
	var children []byte
	if v.SsCode != nil {
		enc_sscode := ber.EncodeOctetString([]byte(*v.SsCode))
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
		enc_ssstatus := ber.EncodeOctetString([]byte(*v.SsStatus))
		retagged_enc_ssstatus, tagErr_enc_ssstatus := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, enc_ssstatus)
		if tagErr_enc_ssstatus != nil {
			return nil, fmt.Errorf("encoding ss-Status: %w", tagErr_enc_ssstatus)
		}
		enc_ssstatus = retagged_enc_ssstatus
		children = append(children, enc_ssstatus...)
	}
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
		children = append(children, ext...)
	}
	encoded := ber.EncodeSequence(children)
	if err := ber.ValidateDERElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding SSIncompatibilityCause4 as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes SSIncompatibilityCause4 from BER/DER format.
func (v *SSIncompatibilityCause4) UnmarshalBER(data []byte) error {
	*v = SSIncompatibilityCause4{}
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding SSIncompatibilityCause4 SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "SSIncompatibilityCause4", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode ss-Code
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
				decodedTag_sscode, n_sscode, rawVal_sscode, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding ss-Code: %w", err)
				}
				if decodedTag_sscode.Class != tag.ClassContextSpecific || decodedTag_sscode.Number != 1 {
					return fmt.Errorf("decoding ss-Code: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_sscode)
				}
				tmp_sscode := SSCode4(rawVal_sscode)
				v.SsCode = &tmp_sscode
				offset += n_sscode
			}
		}
	}
	// Decode basicService
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3) {
				// Decode nested CHOICE (BasicServiceCode4)
				_, n_basicservice, _, tlvErr_basicservice := ber.DecodeTLV(content[offset:])
				if tlvErr_basicservice != nil {
					return fmt.Errorf("decoding basicService: %w", tlvErr_basicservice)
				}
				var dec_basicservice BasicServiceCode4
				if unmErr := dec_basicservice.UnmarshalBER(content[offset : offset+n_basicservice]); unmErr != nil {
					return fmt.Errorf("decoding basicService: %w", unmErr)
				}
				v.BasicService = &dec_basicservice
				offset += n_basicservice
			}
		}
	}
	// Decode ss-Status
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4 {
				decodedTag_ssstatus, n_ssstatus, rawVal_ssstatus, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding ss-Status: %w", err)
				}
				if decodedTag_ssstatus.Class != tag.ClassContextSpecific || decodedTag_ssstatus.Number != 4 {
					return fmt.Errorf("decoding ss-Status: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_ssstatus)
				}
				tmp_ssstatus := SSStatus4(rawVal_ssstatus)
				v.SsStatus = &tmp_ssstatus
				offset += n_ssstatus
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "SSIncompatibilityCause4", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes SMDeliveryFailureCause4 to BER format.
func (v *SMDeliveryFailureCause4) MarshalBER() ([]byte, error) {
	var children []byte
	enc_smenumerateddeliveryfailurecause := ber.EncodeEnumerated(int64(v.SmEnumeratedDeliveryFailureCause))
	children = append(children, enc_smenumerateddeliveryfailurecause...)
	if v.DiagnosticInfo != nil {
		enc_diagnosticinfo := ber.EncodeOctetString([]byte(*v.DiagnosticInfo))
		children = append(children, enc_diagnosticinfo...)
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

// MarshalDER encodes SMDeliveryFailureCause4 to DER format.
func (v *SMDeliveryFailureCause4) MarshalDER() ([]byte, error) {
	var children []byte
	enc_smenumerateddeliveryfailurecause := ber.EncodeEnumerated(int64(v.SmEnumeratedDeliveryFailureCause))
	children = append(children, enc_smenumerateddeliveryfailurecause...)
	if v.DiagnosticInfo != nil {
		enc_diagnosticinfo := ber.EncodeOctetString([]byte(*v.DiagnosticInfo))
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
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
		children = append(children, ext...)
	}
	encoded := ber.EncodeSequence(children)
	if err := ber.ValidateDERElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding SMDeliveryFailureCause4 as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes SMDeliveryFailureCause4 from BER/DER format.
func (v *SMDeliveryFailureCause4) UnmarshalBER(data []byte) error {
	*v = SMDeliveryFailureCause4{}
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding SMDeliveryFailureCause4 SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "SMDeliveryFailureCause4", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode sm-EnumeratedDeliveryFailureCause
	if offset >= len(content) {
		return fmt.Errorf("missing required field sm-EnumeratedDeliveryFailureCause")
	}
	val_smenumerateddeliveryfailurecause, n, err := ber.DecodeEnumerated(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding sm-EnumeratedDeliveryFailureCause: %w", err)
	}
	v.SmEnumeratedDeliveryFailureCause = SMEnumeratedDeliveryFailureCause4(val_smenumerateddeliveryfailurecause)
	offset += n
	// Decode diagnosticInfo
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassUniversal && peekTag.Number == 4 {
				val_diagnosticinfo, n, err := ber.DecodeOctetString(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding diagnosticInfo: %w", err)
				}
				tmp_diagnosticinfo := SignalInfo4(val_diagnosticinfo)
				v.DiagnosticInfo = &tmp_diagnosticinfo
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
			return &ber.DecodeError{Offset: offset, TypeName: "SMDeliveryFailureCause4", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes AbsentSubscriberSMParam4 to BER format.
func (v *AbsentSubscriberSMParam4) MarshalBER() ([]byte, error) {
	var children []byte
	if v.AbsentSubscriberDiagnosticSM != nil {
		enc_absentsubscriberdiagnosticsm := ber.EncodeInteger(int64(*v.AbsentSubscriberDiagnosticSM))
		children = append(children, enc_absentsubscriberdiagnosticsm...)
	}
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding extensionContainer: %w", err)
		}
		children = append(children, enc_extensioncontainer...)
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

// MarshalDER encodes AbsentSubscriberSMParam4 to DER format.
func (v *AbsentSubscriberSMParam4) MarshalDER() ([]byte, error) {
	var children []byte
	if v.AbsentSubscriberDiagnosticSM != nil {
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
		return nil, fmt.Errorf("encoding AbsentSubscriberSMParam4 as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes AbsentSubscriberSMParam4 from BER/DER format.
func (v *AbsentSubscriberSMParam4) UnmarshalBER(data []byte) error {
	*v = AbsentSubscriberSMParam4{}
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding AbsentSubscriberSMParam4 SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "AbsentSubscriberSMParam4", Cause: ber.ErrExtraData}
	}
	offset := 0
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
			return &ber.DecodeError{Offset: offset, TypeName: "AbsentSubscriberSMParam4", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes SystemFailureParam4 to BER format.
func (v *SystemFailureParam4) MarshalBER() ([]byte, error) {
	switch v.Choice {
	case SystemFailureParam4ChoiceNetworkResource:
		if v.NetworkResource == nil {
			return nil, fmt.Errorf("choice SystemFailureParam4: networkResource is nil")
		}
		enc_0 := ber.EncodeEnumerated(int64(*v.NetworkResource))
		return enc_0, nil
	case SystemFailureParam4ChoiceExtensibleSystemFailureParam:
		if v.ExtensibleSystemFailureParam == nil {
			return nil, fmt.Errorf("choice SystemFailureParam4: extensibleSystemFailureParam is nil")
		}
		enc_1, err := v.ExtensibleSystemFailureParam.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding extensibleSystemFailureParam: %w", err)
		}
		return enc_1, nil
	default:
		return nil, fmt.Errorf("unknown choice %d for SystemFailureParam4", v.Choice)
	}
}

// MarshalDER encodes SystemFailureParam4 to DER format.
func (v *SystemFailureParam4) MarshalDER() ([]byte, error) {
	switch v.Choice {
	case SystemFailureParam4ChoiceExtensibleSystemFailureParam:
		if v.ExtensibleSystemFailureParam == nil {
			return nil, fmt.Errorf("choice SystemFailureParam4: extensibleSystemFailureParam is nil")
		}
		enc_der_1, err := v.ExtensibleSystemFailureParam.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding extensibleSystemFailureParam: %w", err)
		}
		if derErr := ber.ValidateDERElement(enc_der_1); derErr != nil {
			return nil, fmt.Errorf("encoding extensibleSystemFailureParam as DER: %w", derErr)
		}
		return enc_der_1, nil
	}
	encoded, err := v.MarshalBER()
	if err != nil {
		return nil, err
	}
	if err := ber.ValidateDERElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding SystemFailureParam4 as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes SystemFailureParam4 from BER/DER format.
func (v *SystemFailureParam4) UnmarshalBER(data []byte) error {
	*v = SystemFailureParam4{}
	if len(data) == 0 {
		return fmt.Errorf("empty data for SystemFailureParam4 CHOICE")
	}
	choiceData := data
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for SystemFailureParam4: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData)
	if tlvErr != nil {
		return fmt.Errorf("decoding SystemFailureParam4 CHOICE: %w", tlvErr)
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "SystemFailureParam4", Cause: ber.ErrExtraData}
	}

	if peekTag.Class == tag.ClassUniversal && peekTag.Number == 10 && peekTag.Constructed == false {
		v.Choice = SystemFailureParam4ChoiceNetworkResource
		decVal, _, intErr := ber.DecodeEnumerated(choiceData)
		if intErr != nil {
			return fmt.Errorf("decoding networkResource: %w", intErr)
		}
		tmp := NetworkResource4(decVal)
		v.NetworkResource = &tmp
	} else if peekTag.Class == tag.ClassUniversal && peekTag.Number == 16 && peekTag.Constructed == true {
		v.Choice = SystemFailureParam4ChoiceExtensibleSystemFailureParam
		var dec ExtensibleSystemFailureParam4
		if unmErr := dec.UnmarshalBER(choiceData); unmErr != nil {
			return fmt.Errorf("decoding extensibleSystemFailureParam: %w", unmErr)
		}
		v.ExtensibleSystemFailureParam = &dec
	} else {
		return fmt.Errorf("unknown tag %s for SystemFailureParam4 CHOICE", peekTag)
	}
	return nil
}

// MarshalBER encodes ExtensibleSystemFailureParam4 to BER format.
func (v *ExtensibleSystemFailureParam4) MarshalBER() ([]byte, error) {
	var children []byte
	if v.NetworkResource != nil {
		enc_networkresource := ber.EncodeEnumerated(int64(*v.NetworkResource))
		children = append(children, enc_networkresource...)
	}
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalBER()
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
	return ber.EncodeSequence(children), nil
}

// MarshalDER encodes ExtensibleSystemFailureParam4 to DER format.
func (v *ExtensibleSystemFailureParam4) MarshalDER() ([]byte, error) {
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
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
		children = append(children, ext...)
	}
	encoded := ber.EncodeSequence(children)
	if err := ber.ValidateDERElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding ExtensibleSystemFailureParam4 as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes ExtensibleSystemFailureParam4 from BER/DER format.
func (v *ExtensibleSystemFailureParam4) UnmarshalBER(data []byte) error {
	*v = ExtensibleSystemFailureParam4{}
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding ExtensibleSystemFailureParam4 SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "ExtensibleSystemFailureParam4", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode networkResource
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassUniversal && peekTag.Number == 10 {
				val_networkresource, n, err := ber.DecodeEnumerated(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding networkResource: %w", err)
				}
				tmp_networkresource := NetworkResource4(val_networkresource)
				v.NetworkResource = &tmp_networkresource
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
	// Decode additionalNetworkResource
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
				decodedTag_additionalnetworkresource, n_additionalnetworkresource, rawVal_additionalnetworkresource, err := ber.DecodeTLV(content[offset:])
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
				tmp_additionalnetworkresource := AdditionalNetworkResource4(decVal_additionalnetworkresource)
				v.AdditionalNetworkResource = &tmp_additionalnetworkresource
				offset += n_additionalnetworkresource
			}
		}
	}
	// Decode failureCauseParam
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
				decodedTag_failurecauseparam, n_failurecauseparam, rawVal_failurecauseparam, err := ber.DecodeTLV(content[offset:])
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
				tmp_failurecauseparam := FailureCauseParam3(decVal_failurecauseparam)
				v.FailureCauseParam = &tmp_failurecauseparam
				offset += n_failurecauseparam
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "ExtensibleSystemFailureParam4", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes DataMissingParam4 to BER format.
func (v *DataMissingParam4) MarshalBER() ([]byte, error) {
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

// MarshalDER encodes DataMissingParam4 to DER format.
func (v *DataMissingParam4) MarshalDER() ([]byte, error) {
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
		return nil, fmt.Errorf("encoding DataMissingParam4 as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes DataMissingParam4 from BER/DER format.
func (v *DataMissingParam4) UnmarshalBER(data []byte) error {
	*v = DataMissingParam4{}
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding DataMissingParam4 SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "DataMissingParam4", Cause: ber.ErrExtraData}
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
			return &ber.DecodeError{Offset: offset, TypeName: "DataMissingParam4", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes UnexpectedDataParam4 to BER format.
func (v *UnexpectedDataParam4) MarshalBER() ([]byte, error) {
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

// MarshalDER encodes UnexpectedDataParam4 to DER format.
func (v *UnexpectedDataParam4) MarshalDER() ([]byte, error) {
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
		return nil, fmt.Errorf("encoding UnexpectedDataParam4 as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes UnexpectedDataParam4 from BER/DER format.
func (v *UnexpectedDataParam4) UnmarshalBER(data []byte) error {
	*v = UnexpectedDataParam4{}
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding UnexpectedDataParam4 SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "UnexpectedDataParam4", Cause: ber.ErrExtraData}
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
			return &ber.DecodeError{Offset: offset, TypeName: "UnexpectedDataParam4", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes FacilityNotSupParam4 to BER format.
func (v *FacilityNotSupParam4) MarshalBER() ([]byte, error) {
	var children []byte
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalBER()
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
	return ber.EncodeSequence(children), nil
}

// MarshalDER encodes FacilityNotSupParam4 to DER format.
func (v *FacilityNotSupParam4) MarshalDER() ([]byte, error) {
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
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
		children = append(children, ext...)
	}
	encoded := ber.EncodeSequence(children)
	if err := ber.ValidateDERElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding FacilityNotSupParam4 as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes FacilityNotSupParam4 from BER/DER format.
func (v *FacilityNotSupParam4) UnmarshalBER(data []byte) error {
	*v = FacilityNotSupParam4{}
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding FacilityNotSupParam4 SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "FacilityNotSupParam4", Cause: ber.ErrExtraData}
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
	// Decode shapeOfLocationEstimateNotSupported
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
				decodedTag_shapeoflocationestimatenotsupported, n_shapeoflocationestimatenotsupported, rawVal_shapeoflocationestimatenotsupported, err := ber.DecodeTLV(content[offset:])
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
				offset += n_shapeoflocationestimatenotsupported
			}
		}
	}
	// Decode neededLcsCapabilityNotSupportedInServingNode
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
				decodedTag_neededlcscapabilitynotsupportedinservingnode, n_neededlcscapabilitynotsupportedinservingnode, rawVal_neededlcscapabilitynotsupportedinservingnode, err := ber.DecodeTLV(content[offset:])
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
				offset += n_neededlcscapabilitynotsupportedinservingnode
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "FacilityNotSupParam4", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes ORNotAllowedParam4 to BER format.
func (v *ORNotAllowedParam4) MarshalBER() ([]byte, error) {
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

// MarshalDER encodes ORNotAllowedParam4 to DER format.
func (v *ORNotAllowedParam4) MarshalDER() ([]byte, error) {
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
		return nil, fmt.Errorf("encoding ORNotAllowedParam4 as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes ORNotAllowedParam4 from BER/DER format.
func (v *ORNotAllowedParam4) UnmarshalBER(data []byte) error {
	*v = ORNotAllowedParam4{}
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding ORNotAllowedParam4 SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "ORNotAllowedParam4", Cause: ber.ErrExtraData}
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
			return &ber.DecodeError{Offset: offset, TypeName: "ORNotAllowedParam4", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes UnknownSubscriberParam4 to BER format.
func (v *UnknownSubscriberParam4) MarshalBER() ([]byte, error) {
	var children []byte
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalBER()
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
	return ber.EncodeSequence(children), nil
}

// MarshalDER encodes UnknownSubscriberParam4 to DER format.
func (v *UnknownSubscriberParam4) MarshalDER() ([]byte, error) {
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
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
		children = append(children, ext...)
	}
	encoded := ber.EncodeSequence(children)
	if err := ber.ValidateDERElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding UnknownSubscriberParam4 as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes UnknownSubscriberParam4 from BER/DER format.
func (v *UnknownSubscriberParam4) UnmarshalBER(data []byte) error {
	*v = UnknownSubscriberParam4{}
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding UnknownSubscriberParam4 SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "UnknownSubscriberParam4", Cause: ber.ErrExtraData}
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
	// Decode unknownSubscriberDiagnostic
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassUniversal && peekTag.Number == 10 {
				val_unknownsubscriberdiagnostic, n, err := ber.DecodeEnumerated(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding unknownSubscriberDiagnostic: %w", err)
				}
				tmp_unknownsubscriberdiagnostic := UnknownSubscriberDiagnostic4(val_unknownsubscriberdiagnostic)
				v.UnknownSubscriberDiagnostic = &tmp_unknownsubscriberdiagnostic
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
			return &ber.DecodeError{Offset: offset, TypeName: "UnknownSubscriberParam4", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes NumberChangedParam4 to BER format.
func (v *NumberChangedParam4) MarshalBER() ([]byte, error) {
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

// MarshalDER encodes NumberChangedParam4 to DER format.
func (v *NumberChangedParam4) MarshalDER() ([]byte, error) {
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
		return nil, fmt.Errorf("encoding NumberChangedParam4 as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes NumberChangedParam4 from BER/DER format.
func (v *NumberChangedParam4) UnmarshalBER(data []byte) error {
	*v = NumberChangedParam4{}
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding NumberChangedParam4 SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "NumberChangedParam4", Cause: ber.ErrExtraData}
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
			return &ber.DecodeError{Offset: offset, TypeName: "NumberChangedParam4", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes UnidentifiedSubParam4 to BER format.
func (v *UnidentifiedSubParam4) MarshalBER() ([]byte, error) {
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

// MarshalDER encodes UnidentifiedSubParam4 to DER format.
func (v *UnidentifiedSubParam4) MarshalDER() ([]byte, error) {
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
		return nil, fmt.Errorf("encoding UnidentifiedSubParam4 as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes UnidentifiedSubParam4 from BER/DER format.
func (v *UnidentifiedSubParam4) UnmarshalBER(data []byte) error {
	*v = UnidentifiedSubParam4{}
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding UnidentifiedSubParam4 SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "UnidentifiedSubParam4", Cause: ber.ErrExtraData}
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
			return &ber.DecodeError{Offset: offset, TypeName: "UnidentifiedSubParam4", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes IllegalSubscriberParam4 to BER format.
func (v *IllegalSubscriberParam4) MarshalBER() ([]byte, error) {
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

// MarshalDER encodes IllegalSubscriberParam4 to DER format.
func (v *IllegalSubscriberParam4) MarshalDER() ([]byte, error) {
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
		return nil, fmt.Errorf("encoding IllegalSubscriberParam4 as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes IllegalSubscriberParam4 from BER/DER format.
func (v *IllegalSubscriberParam4) UnmarshalBER(data []byte) error {
	*v = IllegalSubscriberParam4{}
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding IllegalSubscriberParam4 SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "IllegalSubscriberParam4", Cause: ber.ErrExtraData}
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
			return &ber.DecodeError{Offset: offset, TypeName: "IllegalSubscriberParam4", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes IllegalEquipmentParam4 to BER format.
func (v *IllegalEquipmentParam4) MarshalBER() ([]byte, error) {
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

// MarshalDER encodes IllegalEquipmentParam4 to DER format.
func (v *IllegalEquipmentParam4) MarshalDER() ([]byte, error) {
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
		return nil, fmt.Errorf("encoding IllegalEquipmentParam4 as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes IllegalEquipmentParam4 from BER/DER format.
func (v *IllegalEquipmentParam4) UnmarshalBER(data []byte) error {
	*v = IllegalEquipmentParam4{}
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding IllegalEquipmentParam4 SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "IllegalEquipmentParam4", Cause: ber.ErrExtraData}
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
			return &ber.DecodeError{Offset: offset, TypeName: "IllegalEquipmentParam4", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes BearerServNotProvParam4 to BER format.
func (v *BearerServNotProvParam4) MarshalBER() ([]byte, error) {
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

// MarshalDER encodes BearerServNotProvParam4 to DER format.
func (v *BearerServNotProvParam4) MarshalDER() ([]byte, error) {
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
		return nil, fmt.Errorf("encoding BearerServNotProvParam4 as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes BearerServNotProvParam4 from BER/DER format.
func (v *BearerServNotProvParam4) UnmarshalBER(data []byte) error {
	*v = BearerServNotProvParam4{}
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding BearerServNotProvParam4 SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "BearerServNotProvParam4", Cause: ber.ErrExtraData}
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
			return &ber.DecodeError{Offset: offset, TypeName: "BearerServNotProvParam4", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes TeleservNotProvParam4 to BER format.
func (v *TeleservNotProvParam4) MarshalBER() ([]byte, error) {
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

// MarshalDER encodes TeleservNotProvParam4 to DER format.
func (v *TeleservNotProvParam4) MarshalDER() ([]byte, error) {
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
		return nil, fmt.Errorf("encoding TeleservNotProvParam4 as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes TeleservNotProvParam4 from BER/DER format.
func (v *TeleservNotProvParam4) UnmarshalBER(data []byte) error {
	*v = TeleservNotProvParam4{}
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding TeleservNotProvParam4 SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "TeleservNotProvParam4", Cause: ber.ErrExtraData}
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
			return &ber.DecodeError{Offset: offset, TypeName: "TeleservNotProvParam4", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes TracingBufferFullParam4 to BER format.
func (v *TracingBufferFullParam4) MarshalBER() ([]byte, error) {
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

// MarshalDER encodes TracingBufferFullParam4 to DER format.
func (v *TracingBufferFullParam4) MarshalDER() ([]byte, error) {
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
		return nil, fmt.Errorf("encoding TracingBufferFullParam4 as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes TracingBufferFullParam4 from BER/DER format.
func (v *TracingBufferFullParam4) UnmarshalBER(data []byte) error {
	*v = TracingBufferFullParam4{}
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding TracingBufferFullParam4 SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "TracingBufferFullParam4", Cause: ber.ErrExtraData}
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
			return &ber.DecodeError{Offset: offset, TypeName: "TracingBufferFullParam4", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes NoRoamingNbParam4 to BER format.
func (v *NoRoamingNbParam4) MarshalBER() ([]byte, error) {
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

// MarshalDER encodes NoRoamingNbParam4 to DER format.
func (v *NoRoamingNbParam4) MarshalDER() ([]byte, error) {
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
		return nil, fmt.Errorf("encoding NoRoamingNbParam4 as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes NoRoamingNbParam4 from BER/DER format.
func (v *NoRoamingNbParam4) UnmarshalBER(data []byte) error {
	*v = NoRoamingNbParam4{}
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding NoRoamingNbParam4 SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "NoRoamingNbParam4", Cause: ber.ErrExtraData}
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
			return &ber.DecodeError{Offset: offset, TypeName: "NoRoamingNbParam4", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes AbsentSubscriberParam4 to BER format.
func (v *AbsentSubscriberParam4) MarshalBER() ([]byte, error) {
	var children []byte
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalBER()
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
	return ber.EncodeSequence(children), nil
}

// MarshalDER encodes AbsentSubscriberParam4 to DER format.
func (v *AbsentSubscriberParam4) MarshalDER() ([]byte, error) {
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
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
		children = append(children, ext...)
	}
	encoded := ber.EncodeSequence(children)
	if err := ber.ValidateDERElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding AbsentSubscriberParam4 as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes AbsentSubscriberParam4 from BER/DER format.
func (v *AbsentSubscriberParam4) UnmarshalBER(data []byte) error {
	*v = AbsentSubscriberParam4{}
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding AbsentSubscriberParam4 SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "AbsentSubscriberParam4", Cause: ber.ErrExtraData}
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
	// Decode absentSubscriberReason
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
				decodedTag_absentsubscriberreason, n_absentsubscriberreason, rawVal_absentsubscriberreason, err := ber.DecodeTLV(content[offset:])
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
				tmp_absentsubscriberreason := AbsentSubscriberReason4(decVal_absentsubscriberreason)
				v.AbsentSubscriberReason = &tmp_absentsubscriberreason
				offset += n_absentsubscriberreason
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "AbsentSubscriberParam4", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes BusySubscriberParam4 to BER format.
func (v *BusySubscriberParam4) MarshalBER() ([]byte, error) {
	var children []byte
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalBER()
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
	return ber.EncodeSequence(children), nil
}

// MarshalDER encodes BusySubscriberParam4 to DER format.
func (v *BusySubscriberParam4) MarshalDER() ([]byte, error) {
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
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
		children = append(children, ext...)
	}
	encoded := ber.EncodeSequence(children)
	if err := ber.ValidateDERElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding BusySubscriberParam4 as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes BusySubscriberParam4 from BER/DER format.
func (v *BusySubscriberParam4) UnmarshalBER(data []byte) error {
	*v = BusySubscriberParam4{}
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding BusySubscriberParam4 SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "BusySubscriberParam4", Cause: ber.ErrExtraData}
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
	// Decode ccbs-Busy
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
				decodedTag_ccbsbusy, n_ccbsbusy, rawVal_ccbsbusy, err := ber.DecodeTLV(content[offset:])
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
				offset += n_ccbsbusy
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "BusySubscriberParam4", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes NoSubscriberReplyParam4 to BER format.
func (v *NoSubscriberReplyParam4) MarshalBER() ([]byte, error) {
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

// MarshalDER encodes NoSubscriberReplyParam4 to DER format.
func (v *NoSubscriberReplyParam4) MarshalDER() ([]byte, error) {
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
		return nil, fmt.Errorf("encoding NoSubscriberReplyParam4 as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes NoSubscriberReplyParam4 from BER/DER format.
func (v *NoSubscriberReplyParam4) UnmarshalBER(data []byte) error {
	*v = NoSubscriberReplyParam4{}
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding NoSubscriberReplyParam4 SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "NoSubscriberReplyParam4", Cause: ber.ErrExtraData}
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
			return &ber.DecodeError{Offset: offset, TypeName: "NoSubscriberReplyParam4", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes ForwardingViolationParam4 to BER format.
func (v *ForwardingViolationParam4) MarshalBER() ([]byte, error) {
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

// MarshalDER encodes ForwardingViolationParam4 to DER format.
func (v *ForwardingViolationParam4) MarshalDER() ([]byte, error) {
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
		return nil, fmt.Errorf("encoding ForwardingViolationParam4 as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes ForwardingViolationParam4 from BER/DER format.
func (v *ForwardingViolationParam4) UnmarshalBER(data []byte) error {
	*v = ForwardingViolationParam4{}
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding ForwardingViolationParam4 SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "ForwardingViolationParam4", Cause: ber.ErrExtraData}
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
			return &ber.DecodeError{Offset: offset, TypeName: "ForwardingViolationParam4", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes ForwardingFailedParam4 to BER format.
func (v *ForwardingFailedParam4) MarshalBER() ([]byte, error) {
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

// MarshalDER encodes ForwardingFailedParam4 to DER format.
func (v *ForwardingFailedParam4) MarshalDER() ([]byte, error) {
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
		return nil, fmt.Errorf("encoding ForwardingFailedParam4 as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes ForwardingFailedParam4 from BER/DER format.
func (v *ForwardingFailedParam4) UnmarshalBER(data []byte) error {
	*v = ForwardingFailedParam4{}
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding ForwardingFailedParam4 SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "ForwardingFailedParam4", Cause: ber.ErrExtraData}
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
			return &ber.DecodeError{Offset: offset, TypeName: "ForwardingFailedParam4", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes ATINotAllowedParam4 to BER format.
func (v *ATINotAllowedParam4) MarshalBER() ([]byte, error) {
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

// MarshalDER encodes ATINotAllowedParam4 to DER format.
func (v *ATINotAllowedParam4) MarshalDER() ([]byte, error) {
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
		return nil, fmt.Errorf("encoding ATINotAllowedParam4 as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes ATINotAllowedParam4 from BER/DER format.
func (v *ATINotAllowedParam4) UnmarshalBER(data []byte) error {
	*v = ATINotAllowedParam4{}
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding ATINotAllowedParam4 SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "ATINotAllowedParam4", Cause: ber.ErrExtraData}
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
			return &ber.DecodeError{Offset: offset, TypeName: "ATINotAllowedParam4", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes ATSINotAllowedParam4 to BER format.
func (v *ATSINotAllowedParam4) MarshalBER() ([]byte, error) {
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

// MarshalDER encodes ATSINotAllowedParam4 to DER format.
func (v *ATSINotAllowedParam4) MarshalDER() ([]byte, error) {
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
		return nil, fmt.Errorf("encoding ATSINotAllowedParam4 as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes ATSINotAllowedParam4 from BER/DER format.
func (v *ATSINotAllowedParam4) UnmarshalBER(data []byte) error {
	*v = ATSINotAllowedParam4{}
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding ATSINotAllowedParam4 SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "ATSINotAllowedParam4", Cause: ber.ErrExtraData}
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
			return &ber.DecodeError{Offset: offset, TypeName: "ATSINotAllowedParam4", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes ATMNotAllowedParam4 to BER format.
func (v *ATMNotAllowedParam4) MarshalBER() ([]byte, error) {
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

// MarshalDER encodes ATMNotAllowedParam4 to DER format.
func (v *ATMNotAllowedParam4) MarshalDER() ([]byte, error) {
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
		return nil, fmt.Errorf("encoding ATMNotAllowedParam4 as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes ATMNotAllowedParam4 from BER/DER format.
func (v *ATMNotAllowedParam4) UnmarshalBER(data []byte) error {
	*v = ATMNotAllowedParam4{}
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding ATMNotAllowedParam4 SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "ATMNotAllowedParam4", Cause: ber.ErrExtraData}
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
			return &ber.DecodeError{Offset: offset, TypeName: "ATMNotAllowedParam4", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes IllegalSSOperationParam4 to BER format.
func (v *IllegalSSOperationParam4) MarshalBER() ([]byte, error) {
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

// MarshalDER encodes IllegalSSOperationParam4 to DER format.
func (v *IllegalSSOperationParam4) MarshalDER() ([]byte, error) {
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
		return nil, fmt.Errorf("encoding IllegalSSOperationParam4 as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes IllegalSSOperationParam4 from BER/DER format.
func (v *IllegalSSOperationParam4) UnmarshalBER(data []byte) error {
	*v = IllegalSSOperationParam4{}
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding IllegalSSOperationParam4 SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "IllegalSSOperationParam4", Cause: ber.ErrExtraData}
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
			return &ber.DecodeError{Offset: offset, TypeName: "IllegalSSOperationParam4", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes SSNotAvailableParam4 to BER format.
func (v *SSNotAvailableParam4) MarshalBER() ([]byte, error) {
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

// MarshalDER encodes SSNotAvailableParam4 to DER format.
func (v *SSNotAvailableParam4) MarshalDER() ([]byte, error) {
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
		return nil, fmt.Errorf("encoding SSNotAvailableParam4 as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes SSNotAvailableParam4 from BER/DER format.
func (v *SSNotAvailableParam4) UnmarshalBER(data []byte) error {
	*v = SSNotAvailableParam4{}
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding SSNotAvailableParam4 SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "SSNotAvailableParam4", Cause: ber.ErrExtraData}
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
			return &ber.DecodeError{Offset: offset, TypeName: "SSNotAvailableParam4", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes SSSubscriptionViolationParam4 to BER format.
func (v *SSSubscriptionViolationParam4) MarshalBER() ([]byte, error) {
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

// MarshalDER encodes SSSubscriptionViolationParam4 to DER format.
func (v *SSSubscriptionViolationParam4) MarshalDER() ([]byte, error) {
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
		return nil, fmt.Errorf("encoding SSSubscriptionViolationParam4 as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes SSSubscriptionViolationParam4 from BER/DER format.
func (v *SSSubscriptionViolationParam4) UnmarshalBER(data []byte) error {
	*v = SSSubscriptionViolationParam4{}
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding SSSubscriptionViolationParam4 SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "SSSubscriptionViolationParam4", Cause: ber.ErrExtraData}
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
			return &ber.DecodeError{Offset: offset, TypeName: "SSSubscriptionViolationParam4", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes InformationNotAvailableParam4 to BER format.
func (v *InformationNotAvailableParam4) MarshalBER() ([]byte, error) {
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

// MarshalDER encodes InformationNotAvailableParam4 to DER format.
func (v *InformationNotAvailableParam4) MarshalDER() ([]byte, error) {
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
		return nil, fmt.Errorf("encoding InformationNotAvailableParam4 as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes InformationNotAvailableParam4 from BER/DER format.
func (v *InformationNotAvailableParam4) UnmarshalBER(data []byte) error {
	*v = InformationNotAvailableParam4{}
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding InformationNotAvailableParam4 SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "InformationNotAvailableParam4", Cause: ber.ErrExtraData}
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
			return &ber.DecodeError{Offset: offset, TypeName: "InformationNotAvailableParam4", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes SubBusyForMTSMSParam4 to BER format.
func (v *SubBusyForMTSMSParam4) MarshalBER() ([]byte, error) {
	var children []byte
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalBER()
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
	return ber.EncodeSequence(children), nil
}

// MarshalDER encodes SubBusyForMTSMSParam4 to DER format.
func (v *SubBusyForMTSMSParam4) MarshalDER() ([]byte, error) {
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
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
		children = append(children, ext...)
	}
	encoded := ber.EncodeSequence(children)
	if err := ber.ValidateDERElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding SubBusyForMTSMSParam4 as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes SubBusyForMTSMSParam4 from BER/DER format.
func (v *SubBusyForMTSMSParam4) UnmarshalBER(data []byte) error {
	*v = SubBusyForMTSMSParam4{}
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding SubBusyForMTSMSParam4 SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "SubBusyForMTSMSParam4", Cause: ber.ErrExtraData}
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
	// Decode gprsConnectionSuspended
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassUniversal && peekTag.Number == 5 {
				n, err := ber.DecodeNull(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding gprsConnectionSuspended: %w", err)
				}
				v.GprsConnectionSuspended = &struct{}{}
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
			return &ber.DecodeError{Offset: offset, TypeName: "SubBusyForMTSMSParam4", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes MessageWaitListFullParam4 to BER format.
func (v *MessageWaitListFullParam4) MarshalBER() ([]byte, error) {
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

// MarshalDER encodes MessageWaitListFullParam4 to DER format.
func (v *MessageWaitListFullParam4) MarshalDER() ([]byte, error) {
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
		return nil, fmt.Errorf("encoding MessageWaitListFullParam4 as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes MessageWaitListFullParam4 from BER/DER format.
func (v *MessageWaitListFullParam4) UnmarshalBER(data []byte) error {
	*v = MessageWaitListFullParam4{}
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding MessageWaitListFullParam4 SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "MessageWaitListFullParam4", Cause: ber.ErrExtraData}
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
			return &ber.DecodeError{Offset: offset, TypeName: "MessageWaitListFullParam4", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes ResourceLimitationParam4 to BER format.
func (v *ResourceLimitationParam4) MarshalBER() ([]byte, error) {
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

// MarshalDER encodes ResourceLimitationParam4 to DER format.
func (v *ResourceLimitationParam4) MarshalDER() ([]byte, error) {
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
		return nil, fmt.Errorf("encoding ResourceLimitationParam4 as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes ResourceLimitationParam4 from BER/DER format.
func (v *ResourceLimitationParam4) UnmarshalBER(data []byte) error {
	*v = ResourceLimitationParam4{}
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding ResourceLimitationParam4 SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "ResourceLimitationParam4", Cause: ber.ErrExtraData}
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
			return &ber.DecodeError{Offset: offset, TypeName: "ResourceLimitationParam4", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes NoGroupCallNbParam4 to BER format.
func (v *NoGroupCallNbParam4) MarshalBER() ([]byte, error) {
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

// MarshalDER encodes NoGroupCallNbParam4 to DER format.
func (v *NoGroupCallNbParam4) MarshalDER() ([]byte, error) {
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
		return nil, fmt.Errorf("encoding NoGroupCallNbParam4 as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes NoGroupCallNbParam4 from BER/DER format.
func (v *NoGroupCallNbParam4) UnmarshalBER(data []byte) error {
	*v = NoGroupCallNbParam4{}
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding NoGroupCallNbParam4 SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "NoGroupCallNbParam4", Cause: ber.ErrExtraData}
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
			return &ber.DecodeError{Offset: offset, TypeName: "NoGroupCallNbParam4", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes IncompatibleTerminalParam4 to BER format.
func (v *IncompatibleTerminalParam4) MarshalBER() ([]byte, error) {
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

// MarshalDER encodes IncompatibleTerminalParam4 to DER format.
func (v *IncompatibleTerminalParam4) MarshalDER() ([]byte, error) {
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
		return nil, fmt.Errorf("encoding IncompatibleTerminalParam4 as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes IncompatibleTerminalParam4 from BER/DER format.
func (v *IncompatibleTerminalParam4) UnmarshalBER(data []byte) error {
	*v = IncompatibleTerminalParam4{}
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding IncompatibleTerminalParam4 SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "IncompatibleTerminalParam4", Cause: ber.ErrExtraData}
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
			return &ber.DecodeError{Offset: offset, TypeName: "IncompatibleTerminalParam4", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes ShortTermDenialParam4 to BER format.
func (v *ShortTermDenialParam4) MarshalBER() ([]byte, error) {
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
	return ber.EncodeSequence(children), nil
}

// MarshalDER encodes ShortTermDenialParam4 to DER format.
func (v *ShortTermDenialParam4) MarshalDER() ([]byte, error) {
	var children []byte
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
		children = append(children, ext...)
	}
	encoded := ber.EncodeSequence(children)
	if err := ber.ValidateDERElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding ShortTermDenialParam4 as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes ShortTermDenialParam4 from BER/DER format.
func (v *ShortTermDenialParam4) UnmarshalBER(data []byte) error {
	*v = ShortTermDenialParam4{}
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding ShortTermDenialParam4 SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "ShortTermDenialParam4", Cause: ber.ErrExtraData}
	}
	offset := 0
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "ShortTermDenialParam4", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes LongTermDenialParam4 to BER format.
func (v *LongTermDenialParam4) MarshalBER() ([]byte, error) {
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
	return ber.EncodeSequence(children), nil
}

// MarshalDER encodes LongTermDenialParam4 to DER format.
func (v *LongTermDenialParam4) MarshalDER() ([]byte, error) {
	var children []byte
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
		children = append(children, ext...)
	}
	encoded := ber.EncodeSequence(children)
	if err := ber.ValidateDERElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding LongTermDenialParam4 as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes LongTermDenialParam4 from BER/DER format.
func (v *LongTermDenialParam4) UnmarshalBER(data []byte) error {
	*v = LongTermDenialParam4{}
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding LongTermDenialParam4 SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "LongTermDenialParam4", Cause: ber.ErrExtraData}
	}
	offset := 0
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "LongTermDenialParam4", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes UnauthorizedRequestingNetworkParam4 to BER format.
func (v *UnauthorizedRequestingNetworkParam4) MarshalBER() ([]byte, error) {
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

// MarshalDER encodes UnauthorizedRequestingNetworkParam4 to DER format.
func (v *UnauthorizedRequestingNetworkParam4) MarshalDER() ([]byte, error) {
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
		return nil, fmt.Errorf("encoding UnauthorizedRequestingNetworkParam4 as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes UnauthorizedRequestingNetworkParam4 from BER/DER format.
func (v *UnauthorizedRequestingNetworkParam4) UnmarshalBER(data []byte) error {
	*v = UnauthorizedRequestingNetworkParam4{}
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding UnauthorizedRequestingNetworkParam4 SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "UnauthorizedRequestingNetworkParam4", Cause: ber.ErrExtraData}
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
			return &ber.DecodeError{Offset: offset, TypeName: "UnauthorizedRequestingNetworkParam4", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes UnauthorizedLCSClientParam4 to BER format.
func (v *UnauthorizedLCSClientParam4) MarshalBER() ([]byte, error) {
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

// MarshalDER encodes UnauthorizedLCSClientParam4 to DER format.
func (v *UnauthorizedLCSClientParam4) MarshalDER() ([]byte, error) {
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
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
		children = append(children, ext...)
	}
	encoded := ber.EncodeSequence(children)
	if err := ber.ValidateDERElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding UnauthorizedLCSClientParam4 as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes UnauthorizedLCSClientParam4 from BER/DER format.
func (v *UnauthorizedLCSClientParam4) UnmarshalBER(data []byte) error {
	*v = UnauthorizedLCSClientParam4{}
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding UnauthorizedLCSClientParam4 SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "UnauthorizedLCSClientParam4", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode unauthorizedLCSClient-Diagnostic
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
				decodedTag_unauthorizedlcsclientdiagnostic, n_unauthorizedlcsclientdiagnostic, rawVal_unauthorizedlcsclientdiagnostic, err := ber.DecodeTLV(content[offset:])
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
				tmp_unauthorizedlcsclientdiagnostic := UnauthorizedLCSClientDiagnostic4(decVal_unauthorizedlcsclientdiagnostic)
				v.UnauthorizedLCSClientDiagnostic = &tmp_unauthorizedlcsclientdiagnostic
				offset += n_unauthorizedlcsclientdiagnostic
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
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "UnauthorizedLCSClientParam4", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes PositionMethodFailureParam4 to BER format.
func (v *PositionMethodFailureParam4) MarshalBER() ([]byte, error) {
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

// MarshalDER encodes PositionMethodFailureParam4 to DER format.
func (v *PositionMethodFailureParam4) MarshalDER() ([]byte, error) {
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
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
		children = append(children, ext...)
	}
	encoded := ber.EncodeSequence(children)
	if err := ber.ValidateDERElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding PositionMethodFailureParam4 as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes PositionMethodFailureParam4 from BER/DER format.
func (v *PositionMethodFailureParam4) UnmarshalBER(data []byte) error {
	*v = PositionMethodFailureParam4{}
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding PositionMethodFailureParam4 SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "PositionMethodFailureParam4", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode positionMethodFailure-Diagnostic
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
				decodedTag_positionmethodfailurediagnostic, n_positionmethodfailurediagnostic, rawVal_positionmethodfailurediagnostic, err := ber.DecodeTLV(content[offset:])
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
				tmp_positionmethodfailurediagnostic := PositionMethodFailureDiagnostic4(decVal_positionmethodfailurediagnostic)
				v.PositionMethodFailureDiagnostic = &tmp_positionmethodfailurediagnostic
				offset += n_positionmethodfailurediagnostic
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
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "PositionMethodFailureParam4", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes UnknownOrUnreachableLCSClientParam4 to BER format.
func (v *UnknownOrUnreachableLCSClientParam4) MarshalBER() ([]byte, error) {
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

// MarshalDER encodes UnknownOrUnreachableLCSClientParam4 to DER format.
func (v *UnknownOrUnreachableLCSClientParam4) MarshalDER() ([]byte, error) {
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
		return nil, fmt.Errorf("encoding UnknownOrUnreachableLCSClientParam4 as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes UnknownOrUnreachableLCSClientParam4 from BER/DER format.
func (v *UnknownOrUnreachableLCSClientParam4) UnmarshalBER(data []byte) error {
	*v = UnknownOrUnreachableLCSClientParam4{}
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding UnknownOrUnreachableLCSClientParam4 SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "UnknownOrUnreachableLCSClientParam4", Cause: ber.ErrExtraData}
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
			return &ber.DecodeError{Offset: offset, TypeName: "UnknownOrUnreachableLCSClientParam4", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes MMEventNotSupportedParam4 to BER format.
func (v *MMEventNotSupportedParam4) MarshalBER() ([]byte, error) {
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

// MarshalDER encodes MMEventNotSupportedParam4 to DER format.
func (v *MMEventNotSupportedParam4) MarshalDER() ([]byte, error) {
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
		return nil, fmt.Errorf("encoding MMEventNotSupportedParam4 as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes MMEventNotSupportedParam4 from BER/DER format.
func (v *MMEventNotSupportedParam4) UnmarshalBER(data []byte) error {
	*v = MMEventNotSupportedParam4{}
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding MMEventNotSupportedParam4 SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "MMEventNotSupportedParam4", Cause: ber.ErrExtraData}
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
			return &ber.DecodeError{Offset: offset, TypeName: "MMEventNotSupportedParam4", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes TargetCellOutsideGCAParam4 to BER format.
func (v *TargetCellOutsideGCAParam4) MarshalBER() ([]byte, error) {
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

// MarshalDER encodes TargetCellOutsideGCAParam4 to DER format.
func (v *TargetCellOutsideGCAParam4) MarshalDER() ([]byte, error) {
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
		return nil, fmt.Errorf("encoding TargetCellOutsideGCAParam4 as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes TargetCellOutsideGCAParam4 from BER/DER format.
func (v *TargetCellOutsideGCAParam4) UnmarshalBER(data []byte) error {
	*v = TargetCellOutsideGCAParam4{}
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding TargetCellOutsideGCAParam4 SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "TargetCellOutsideGCAParam4", Cause: ber.ErrExtraData}
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
			return &ber.DecodeError{Offset: offset, TypeName: "TargetCellOutsideGCAParam4", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes OngoingGroupCallParam4 to BER format.
func (v *OngoingGroupCallParam4) MarshalBER() ([]byte, error) {
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

// MarshalDER encodes OngoingGroupCallParam4 to DER format.
func (v *OngoingGroupCallParam4) MarshalDER() ([]byte, error) {
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
		return nil, fmt.Errorf("encoding OngoingGroupCallParam4 as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes OngoingGroupCallParam4 from BER/DER format.
func (v *OngoingGroupCallParam4) UnmarshalBER(data []byte) error {
	*v = OngoingGroupCallParam4{}
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding OngoingGroupCallParam4 SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "OngoingGroupCallParam4", Cause: ber.ErrExtraData}
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
			return &ber.DecodeError{Offset: offset, TypeName: "OngoingGroupCallParam4", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}
