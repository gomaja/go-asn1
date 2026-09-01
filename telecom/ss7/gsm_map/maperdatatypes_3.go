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

// RoamingNotAllowedParam3 represents the ASN.1 type RoamingNotAllowedParam3 (SEQUENCE).
type RoamingNotAllowedParam3 struct {
	RoamingNotAllowedCause           RoamingNotAllowedCause3            `asn1:""`
	ExtensionContainer               *ExtensionContainer3               `asn1:",optional" json:"ExtensionContainer,omitempty"`
	AdditionalRoamingNotAllowedCause *AdditionalRoamingNotAllowedCause3 `asn1:"tag:0,context,implicit,optional" json:"AdditionalRoamingNotAllowedCause,omitempty"`
	ExtCount_                        int64                              `asn1:"-" json:"-"`
	ExtPresent_                      []bool                             `asn1:"-" json:"-"`
	ExtData_                         [][]byte                           `asn1:"-" json:"-"`
}

// AdditionalRoamingNotAllowedCause3 represents the ASN.1 ENUMERATED type AdditionalRoamingNotAllowedCause3.
type AdditionalRoamingNotAllowedCause3 int64

const (
	AdditionalRoamingNotAllowedCause3SupportedRATTypesNotAllowed AdditionalRoamingNotAllowedCause3 = 0
)

func (v AdditionalRoamingNotAllowedCause3) String() string {
	switch v {
	case AdditionalRoamingNotAllowedCause3SupportedRATTypesNotAllowed:
		return "supportedRAT-TypesNotAllowed"
	default:
		return "unknown"
	}
}

// RoamingNotAllowedCause3 represents the ASN.1 ENUMERATED type RoamingNotAllowedCause3.
type RoamingNotAllowedCause3 int64

const (
	RoamingNotAllowedCause3PlmnRoamingNotAllowed     RoamingNotAllowedCause3 = 0
	RoamingNotAllowedCause3OperatorDeterminedBarring RoamingNotAllowedCause3 = 3
)

func (v RoamingNotAllowedCause3) String() string {
	switch v {
	case RoamingNotAllowedCause3PlmnRoamingNotAllowed:
		return "plmnRoamingNotAllowed"
	case RoamingNotAllowedCause3OperatorDeterminedBarring:
		return "operatorDeterminedBarring"
	default:
		return "unknown"
	}
}

// CallBarredParam3 choice constants.
const (
	CallBarredParam3ChoiceCallBarringCause          = 1
	CallBarredParam3ChoiceExtensibleCallBarredParam = 2
)

// CallBarredParam3 represents the ASN.1 CHOICE type CallBarredParam3.
type CallBarredParam3 struct {
	Choice                    int
	CallBarringCause          *CallBarringCause3          `json:"CallBarringCause,omitempty"`
	ExtensibleCallBarredParam *ExtensibleCallBarredParam3 `json:"ExtensibleCallBarredParam,omitempty"`
}

// NewCallBarredParam3CallBarringCause creates a CallBarredParam3 with the callBarringCause alternative.
func NewCallBarredParam3CallBarringCause(v CallBarringCause3) CallBarredParam3 {
	return CallBarredParam3{
		Choice:           CallBarredParam3ChoiceCallBarringCause,
		CallBarringCause: &v,
	}
}

// NewCallBarredParam3ExtensibleCallBarredParam creates a CallBarredParam3 with the extensibleCallBarredParam alternative.
func NewCallBarredParam3ExtensibleCallBarredParam(v ExtensibleCallBarredParam3) CallBarredParam3 {
	return CallBarredParam3{
		Choice:                    CallBarredParam3ChoiceExtensibleCallBarredParam,
		ExtensibleCallBarredParam: &v,
	}
}

// CallBarringCause3 represents the ASN.1 ENUMERATED type CallBarringCause3.
type CallBarringCause3 int64

const (
	CallBarringCause3BarringServiceActive CallBarringCause3 = 0
	CallBarringCause3OperatorBarring      CallBarringCause3 = 1
)

func (v CallBarringCause3) String() string {
	switch v {
	case CallBarringCause3BarringServiceActive:
		return "barringServiceActive"
	case CallBarringCause3OperatorBarring:
		return "operatorBarring"
	default:
		return "unknown"
	}
}

// ExtensibleCallBarredParam3 represents the ASN.1 type ExtensibleCallBarredParam3 (SEQUENCE).
type ExtensibleCallBarredParam3 struct {
	CallBarringCause              *CallBarringCause3   `asn1:",optional" json:"CallBarringCause,omitempty"`
	ExtensionContainer            *ExtensionContainer3 `asn1:",optional" json:"ExtensionContainer,omitempty"`
	UnauthorisedMessageOriginator *struct{}            `asn1:"tag:1,context,implicit,optional" json:"UnauthorisedMessageOriginator,omitempty"`
	AnonymousCallRejection        *struct{}            `asn1:"tag:2,context,implicit,optional" json:"AnonymousCallRejection,omitempty"`
	ExtCount_                     int64                `asn1:"-" json:"-"`
	ExtPresent_                   []bool               `asn1:"-" json:"-"`
	ExtData_                      [][]byte             `asn1:"-" json:"-"`
}

// CUGRejectParam3 represents the ASN.1 type CUGRejectParam3 (SEQUENCE).
type CUGRejectParam3 struct {
	CugRejectCause     *CUGRejectCause3     `asn1:",optional" json:"CugRejectCause,omitempty"`
	ExtensionContainer *ExtensionContainer3 `asn1:",optional" json:"ExtensionContainer,omitempty"`
	ExtCount_          int64                `asn1:"-" json:"-"`
	ExtPresent_        []bool               `asn1:"-" json:"-"`
	ExtData_           [][]byte             `asn1:"-" json:"-"`
}

// CUGRejectCause3 represents the ASN.1 ENUMERATED type CUGRejectCause3.
type CUGRejectCause3 int64

const (
	CUGRejectCause3IncomingCallsBarredWithinCUG                CUGRejectCause3 = 0
	CUGRejectCause3SubscriberNotMemberOfCUG                    CUGRejectCause3 = 1
	CUGRejectCause3RequestedBasicServiceViolatesCUGConstraints CUGRejectCause3 = 5
	CUGRejectCause3CalledPartySSInteractionViolation           CUGRejectCause3 = 7
)

func (v CUGRejectCause3) String() string {
	switch v {
	case CUGRejectCause3IncomingCallsBarredWithinCUG:
		return "incomingCallsBarredWithinCUG"
	case CUGRejectCause3SubscriberNotMemberOfCUG:
		return "subscriberNotMemberOfCUG"
	case CUGRejectCause3RequestedBasicServiceViolatesCUGConstraints:
		return "requestedBasicServiceViolatesCUG-Constraints"
	case CUGRejectCause3CalledPartySSInteractionViolation:
		return "calledPartySS-InteractionViolation"
	default:
		return "unknown"
	}
}

// SSIncompatibilityCause3 represents the ASN.1 type SSIncompatibilityCause3 (SEQUENCE).
type SSIncompatibilityCause3 struct {
	SsCode       *SSCode3           `asn1:"tag:1,context,implicit,optional" json:"SsCode,omitempty"`
	BasicService *BasicServiceCode3 `asn1:",optional" json:"BasicService,omitempty"`
	SsStatus     *SSStatus3         `asn1:"tag:4,context,implicit,optional" json:"SsStatus,omitempty"`
	ExtCount_    int64              `asn1:"-" json:"-"`
	ExtPresent_  []bool             `asn1:"-" json:"-"`
	ExtData_     [][]byte           `asn1:"-" json:"-"`
}

// PWRegistrationFailureCause3 represents the ASN.1 ENUMERATED type PWRegistrationFailureCause3.
type PWRegistrationFailureCause3 int64

const (
	PWRegistrationFailureCause3Undetermined         PWRegistrationFailureCause3 = 0
	PWRegistrationFailureCause3InvalidFormat        PWRegistrationFailureCause3 = 1
	PWRegistrationFailureCause3NewPasswordsMismatch PWRegistrationFailureCause3 = 2
)

func (v PWRegistrationFailureCause3) String() string {
	switch v {
	case PWRegistrationFailureCause3Undetermined:
		return "undetermined"
	case PWRegistrationFailureCause3InvalidFormat:
		return "invalidFormat"
	case PWRegistrationFailureCause3NewPasswordsMismatch:
		return "newPasswordsMismatch"
	default:
		return "unknown"
	}
}

// SMEnumeratedDeliveryFailureCause3 represents the ASN.1 ENUMERATED type SMEnumeratedDeliveryFailureCause3.
type SMEnumeratedDeliveryFailureCause3 int64

const (
	SMEnumeratedDeliveryFailureCause3MemoryCapacityExceeded    SMEnumeratedDeliveryFailureCause3 = 0
	SMEnumeratedDeliveryFailureCause3EquipmentProtocolError    SMEnumeratedDeliveryFailureCause3 = 1
	SMEnumeratedDeliveryFailureCause3EquipmentNotSMEquipped    SMEnumeratedDeliveryFailureCause3 = 2
	SMEnumeratedDeliveryFailureCause3UnknownServiceCentre      SMEnumeratedDeliveryFailureCause3 = 3
	SMEnumeratedDeliveryFailureCause3ScCongestion              SMEnumeratedDeliveryFailureCause3 = 4
	SMEnumeratedDeliveryFailureCause3InvalidSMEAddress         SMEnumeratedDeliveryFailureCause3 = 5
	SMEnumeratedDeliveryFailureCause3SubscriberNotSCSubscriber SMEnumeratedDeliveryFailureCause3 = 6
)

func (v SMEnumeratedDeliveryFailureCause3) String() string {
	switch v {
	case SMEnumeratedDeliveryFailureCause3MemoryCapacityExceeded:
		return "memoryCapacityExceeded"
	case SMEnumeratedDeliveryFailureCause3EquipmentProtocolError:
		return "equipmentProtocolError"
	case SMEnumeratedDeliveryFailureCause3EquipmentNotSMEquipped:
		return "equipmentNotSM-Equipped"
	case SMEnumeratedDeliveryFailureCause3UnknownServiceCentre:
		return "unknownServiceCentre"
	case SMEnumeratedDeliveryFailureCause3ScCongestion:
		return "sc-Congestion"
	case SMEnumeratedDeliveryFailureCause3InvalidSMEAddress:
		return "invalidSME-Address"
	case SMEnumeratedDeliveryFailureCause3SubscriberNotSCSubscriber:
		return "subscriberNotSC-Subscriber"
	default:
		return "unknown"
	}
}

// SMDeliveryFailureCause3 represents the ASN.1 type SMDeliveryFailureCause3 (SEQUENCE).
type SMDeliveryFailureCause3 struct {
	SmEnumeratedDeliveryFailureCause SMEnumeratedDeliveryFailureCause3 `asn1:""`
	DiagnosticInfo                   *SignalInfo3                      `asn1:",optional" json:"DiagnosticInfo,omitempty"`
	ExtensionContainer               *ExtensionContainer3              `asn1:",optional" json:"ExtensionContainer,omitempty"`
	ExtCount_                        int64                             `asn1:"-" json:"-"`
	ExtPresent_                      []bool                            `asn1:"-" json:"-"`
	ExtData_                         [][]byte                          `asn1:"-" json:"-"`
}

// AbsentSubscriberSMParam3 represents the ASN.1 type AbsentSubscriberSMParam3 (SEQUENCE).
type AbsentSubscriberSMParam3 struct {
	AbsentSubscriberDiagnosticSM           *AbsentSubscriberDiagnosticSM3 `asn1:",optional" json:"AbsentSubscriberDiagnosticSM,omitempty"`
	ExtensionContainer                     *ExtensionContainer3           `asn1:",optional" json:"ExtensionContainer,omitempty"`
	AdditionalAbsentSubscriberDiagnosticSM *AbsentSubscriberDiagnosticSM3 `asn1:"tag:0,context,implicit,optional" json:"AdditionalAbsentSubscriberDiagnosticSM,omitempty"`
	Imsi                                   *IMSI3                         `asn1:"tag:1,context,implicit,optional" json:"Imsi,omitempty"`
	ExtCount_                              int64                          `asn1:"-" json:"-"`
	ExtPresent_                            []bool                         `asn1:"-" json:"-"`
	ExtData_                               [][]byte                       `asn1:"-" json:"-"`
}

// AbsentSubscriberDiagnosticSM3 represents the ASN.1 type AbsentSubscriberDiagnosticSM3 (INTEGER).
type AbsentSubscriberDiagnosticSM3 = int64

// SystemFailureParam3 choice constants.
const (
	SystemFailureParam3ChoiceNetworkResource              = 1
	SystemFailureParam3ChoiceExtensibleSystemFailureParam = 2
)

// SystemFailureParam3 represents the ASN.1 CHOICE type SystemFailureParam3.
type SystemFailureParam3 struct {
	Choice                       int
	NetworkResource              *NetworkResource3              `json:"NetworkResource,omitempty"`
	ExtensibleSystemFailureParam *ExtensibleSystemFailureParam3 `json:"ExtensibleSystemFailureParam,omitempty"`
}

// NewSystemFailureParam3NetworkResource creates a SystemFailureParam3 with the networkResource alternative.
func NewSystemFailureParam3NetworkResource(v NetworkResource3) SystemFailureParam3 {
	return SystemFailureParam3{
		Choice:          SystemFailureParam3ChoiceNetworkResource,
		NetworkResource: &v,
	}
}

// NewSystemFailureParam3ExtensibleSystemFailureParam creates a SystemFailureParam3 with the extensibleSystemFailureParam alternative.
func NewSystemFailureParam3ExtensibleSystemFailureParam(v ExtensibleSystemFailureParam3) SystemFailureParam3 {
	return SystemFailureParam3{
		Choice:                       SystemFailureParam3ChoiceExtensibleSystemFailureParam,
		ExtensibleSystemFailureParam: &v,
	}
}

// ExtensibleSystemFailureParam3 represents the ASN.1 type ExtensibleSystemFailureParam3 (SEQUENCE).
type ExtensibleSystemFailureParam3 struct {
	NetworkResource           *NetworkResource3           `asn1:",optional" json:"NetworkResource,omitempty"`
	ExtensionContainer        *ExtensionContainer3        `asn1:",optional" json:"ExtensionContainer,omitempty"`
	AdditionalNetworkResource *AdditionalNetworkResource3 `asn1:"tag:0,context,implicit,optional" json:"AdditionalNetworkResource,omitempty"`
	FailureCauseParam         *ERFailureCauseParam        `asn1:"tag:1,context,implicit,optional" json:"FailureCauseParam,omitempty"`
	ExtCount_                 int64                       `asn1:"-" json:"-"`
	ExtPresent_               []bool                      `asn1:"-" json:"-"`
	ExtData_                  [][]byte                    `asn1:"-" json:"-"`
}

// ERFailureCauseParam represents the ASN.1 ENUMERATED type ERFailureCauseParam.
type ERFailureCauseParam int64

const (
	ERFailureCauseParamLimitReachedOnNumberOfConcurrentLocationRequests ERFailureCauseParam = 0
)

func (v ERFailureCauseParam) String() string {
	switch v {
	case ERFailureCauseParamLimitReachedOnNumberOfConcurrentLocationRequests:
		return "limitReachedOnNumberOfConcurrentLocationRequests"
	default:
		return "unknown"
	}
}

// DataMissingParam3 represents the ASN.1 type DataMissingParam3 (SEQUENCE).
type DataMissingParam3 struct {
	ExtensionContainer *ExtensionContainer3 `asn1:",optional" json:"ExtensionContainer,omitempty"`
	ExtCount_          int64                `asn1:"-" json:"-"`
	ExtPresent_        []bool               `asn1:"-" json:"-"`
	ExtData_           [][]byte             `asn1:"-" json:"-"`
}

// UnexpectedDataParam3 represents the ASN.1 type UnexpectedDataParam3 (SEQUENCE).
type UnexpectedDataParam3 struct {
	ExtensionContainer   *ExtensionContainer3 `asn1:",optional" json:"ExtensionContainer,omitempty"`
	UnexpectedSubscriber *struct{}            `asn1:"tag:0,context,implicit,optional" json:"UnexpectedSubscriber,omitempty"`
	ExtCount_            int64                `asn1:"-" json:"-"`
	ExtPresent_          []bool               `asn1:"-" json:"-"`
	ExtData_             [][]byte             `asn1:"-" json:"-"`
}

// FacilityNotSupParam3 represents the ASN.1 type FacilityNotSupParam3 (SEQUENCE).
type FacilityNotSupParam3 struct {
	ExtensionContainer                           *ExtensionContainer3 `asn1:",optional" json:"ExtensionContainer,omitempty"`
	ShapeOfLocationEstimateNotSupported          *struct{}            `asn1:"tag:0,context,implicit,optional" json:"ShapeOfLocationEstimateNotSupported,omitempty"`
	NeededLcsCapabilityNotSupportedInServingNode *struct{}            `asn1:"tag:1,context,implicit,optional" json:"NeededLcsCapabilityNotSupportedInServingNode,omitempty"`
	ExtCount_                                    int64                `asn1:"-" json:"-"`
	ExtPresent_                                  []bool               `asn1:"-" json:"-"`
	ExtData_                                     [][]byte             `asn1:"-" json:"-"`
}

// ORNotAllowedParam3 represents the ASN.1 type ORNotAllowedParam3 (SEQUENCE).
type ORNotAllowedParam3 struct {
	ExtensionContainer *ExtensionContainer3 `asn1:",optional" json:"ExtensionContainer,omitempty"`
	ExtCount_          int64                `asn1:"-" json:"-"`
	ExtPresent_        []bool               `asn1:"-" json:"-"`
	ExtData_           [][]byte             `asn1:"-" json:"-"`
}

// UnknownSubscriberParam3 represents the ASN.1 type UnknownSubscriberParam3 (SEQUENCE).
type UnknownSubscriberParam3 struct {
	ExtensionContainer          *ExtensionContainer3          `asn1:",optional" json:"ExtensionContainer,omitempty"`
	UnknownSubscriberDiagnostic *UnknownSubscriberDiagnostic3 `asn1:",optional" json:"UnknownSubscriberDiagnostic,omitempty"`
	ExtCount_                   int64                         `asn1:"-" json:"-"`
	ExtPresent_                 []bool                        `asn1:"-" json:"-"`
	ExtData_                    [][]byte                      `asn1:"-" json:"-"`
}

// UnknownSubscriberDiagnostic3 represents the ASN.1 ENUMERATED type UnknownSubscriberDiagnostic3.
type UnknownSubscriberDiagnostic3 int64

const (
	UnknownSubscriberDiagnostic3ImsiUnknown                UnknownSubscriberDiagnostic3 = 0
	UnknownSubscriberDiagnostic3GprsEpsSubscriptionUnknown UnknownSubscriberDiagnostic3 = 1
	UnknownSubscriberDiagnostic3NpdbMismatch               UnknownSubscriberDiagnostic3 = 2
)

func (v UnknownSubscriberDiagnostic3) String() string {
	switch v {
	case UnknownSubscriberDiagnostic3ImsiUnknown:
		return "imsiUnknown"
	case UnknownSubscriberDiagnostic3GprsEpsSubscriptionUnknown:
		return "gprs-eps-SubscriptionUnknown"
	case UnknownSubscriberDiagnostic3NpdbMismatch:
		return "npdbMismatch"
	default:
		return "unknown"
	}
}

// NumberChangedParam3 represents the ASN.1 type NumberChangedParam3 (SEQUENCE).
type NumberChangedParam3 struct {
	ExtensionContainer *ExtensionContainer3 `asn1:",optional" json:"ExtensionContainer,omitempty"`
	ExtCount_          int64                `asn1:"-" json:"-"`
	ExtPresent_        []bool               `asn1:"-" json:"-"`
	ExtData_           [][]byte             `asn1:"-" json:"-"`
}

// UnidentifiedSubParam3 represents the ASN.1 type UnidentifiedSubParam3 (SEQUENCE).
type UnidentifiedSubParam3 struct {
	ExtensionContainer *ExtensionContainer3 `asn1:",optional" json:"ExtensionContainer,omitempty"`
	ExtCount_          int64                `asn1:"-" json:"-"`
	ExtPresent_        []bool               `asn1:"-" json:"-"`
	ExtData_           [][]byte             `asn1:"-" json:"-"`
}

// IllegalSubscriberParam3 represents the ASN.1 type IllegalSubscriberParam3 (SEQUENCE).
type IllegalSubscriberParam3 struct {
	ExtensionContainer *ExtensionContainer3 `asn1:",optional" json:"ExtensionContainer,omitempty"`
	ExtCount_          int64                `asn1:"-" json:"-"`
	ExtPresent_        []bool               `asn1:"-" json:"-"`
	ExtData_           [][]byte             `asn1:"-" json:"-"`
}

// IllegalEquipmentParam3 represents the ASN.1 type IllegalEquipmentParam3 (SEQUENCE).
type IllegalEquipmentParam3 struct {
	ExtensionContainer *ExtensionContainer3 `asn1:",optional" json:"ExtensionContainer,omitempty"`
	ExtCount_          int64                `asn1:"-" json:"-"`
	ExtPresent_        []bool               `asn1:"-" json:"-"`
	ExtData_           [][]byte             `asn1:"-" json:"-"`
}

// BearerServNotProvParam3 represents the ASN.1 type BearerServNotProvParam3 (SEQUENCE).
type BearerServNotProvParam3 struct {
	ExtensionContainer *ExtensionContainer3 `asn1:",optional" json:"ExtensionContainer,omitempty"`
	ExtCount_          int64                `asn1:"-" json:"-"`
	ExtPresent_        []bool               `asn1:"-" json:"-"`
	ExtData_           [][]byte             `asn1:"-" json:"-"`
}

// TeleservNotProvParam3 represents the ASN.1 type TeleservNotProvParam3 (SEQUENCE).
type TeleservNotProvParam3 struct {
	ExtensionContainer *ExtensionContainer3 `asn1:",optional" json:"ExtensionContainer,omitempty"`
	ExtCount_          int64                `asn1:"-" json:"-"`
	ExtPresent_        []bool               `asn1:"-" json:"-"`
	ExtData_           [][]byte             `asn1:"-" json:"-"`
}

// TracingBufferFullParam3 represents the ASN.1 type TracingBufferFullParam3 (SEQUENCE).
type TracingBufferFullParam3 struct {
	ExtensionContainer *ExtensionContainer3 `asn1:",optional" json:"ExtensionContainer,omitempty"`
	ExtCount_          int64                `asn1:"-" json:"-"`
	ExtPresent_        []bool               `asn1:"-" json:"-"`
	ExtData_           [][]byte             `asn1:"-" json:"-"`
}

// NoRoamingNbParam3 represents the ASN.1 type NoRoamingNbParam3 (SEQUENCE).
type NoRoamingNbParam3 struct {
	ExtensionContainer *ExtensionContainer3 `asn1:",optional" json:"ExtensionContainer,omitempty"`
	ExtCount_          int64                `asn1:"-" json:"-"`
	ExtPresent_        []bool               `asn1:"-" json:"-"`
	ExtData_           [][]byte             `asn1:"-" json:"-"`
}

// AbsentSubscriberParam3 represents the ASN.1 type AbsentSubscriberParam3 (SEQUENCE).
type AbsentSubscriberParam3 struct {
	ExtensionContainer     *ExtensionContainer3     `asn1:",optional" json:"ExtensionContainer,omitempty"`
	AbsentSubscriberReason *AbsentSubscriberReason3 `asn1:"tag:0,context,implicit,optional" json:"AbsentSubscriberReason,omitempty"`
	ExtCount_              int64                    `asn1:"-" json:"-"`
	ExtPresent_            []bool                   `asn1:"-" json:"-"`
	ExtData_               [][]byte                 `asn1:"-" json:"-"`
}

// AbsentSubscriberReason3 represents the ASN.1 ENUMERATED type AbsentSubscriberReason3.
type AbsentSubscriberReason3 int64

const (
	AbsentSubscriberReason3ImsiDetach     AbsentSubscriberReason3 = 0
	AbsentSubscriberReason3RestrictedArea AbsentSubscriberReason3 = 1
	AbsentSubscriberReason3NoPageResponse AbsentSubscriberReason3 = 2
	AbsentSubscriberReason3PurgedMS       AbsentSubscriberReason3 = 3
	AbsentSubscriberReason3MtRoamingRetry AbsentSubscriberReason3 = 4
	AbsentSubscriberReason3BusySubscriber AbsentSubscriberReason3 = 5
)

func (v AbsentSubscriberReason3) String() string {
	switch v {
	case AbsentSubscriberReason3ImsiDetach:
		return "imsiDetach"
	case AbsentSubscriberReason3RestrictedArea:
		return "restrictedArea"
	case AbsentSubscriberReason3NoPageResponse:
		return "noPageResponse"
	case AbsentSubscriberReason3PurgedMS:
		return "purgedMS"
	case AbsentSubscriberReason3MtRoamingRetry:
		return "mtRoamingRetry"
	case AbsentSubscriberReason3BusySubscriber:
		return "busySubscriber"
	default:
		return "unknown"
	}
}

// BusySubscriberParam3 represents the ASN.1 type BusySubscriberParam3 (SEQUENCE).
type BusySubscriberParam3 struct {
	ExtensionContainer *ExtensionContainer3 `asn1:",optional" json:"ExtensionContainer,omitempty"`
	CcbsPossible       *struct{}            `asn1:"tag:0,context,implicit,optional" json:"CcbsPossible,omitempty"`
	CcbsBusy           *struct{}            `asn1:"tag:1,context,implicit,optional" json:"CcbsBusy,omitempty"`
	ExtCount_          int64                `asn1:"-" json:"-"`
	ExtPresent_        []bool               `asn1:"-" json:"-"`
	ExtData_           [][]byte             `asn1:"-" json:"-"`
}

// NoSubscriberReplyParam3 represents the ASN.1 type NoSubscriberReplyParam3 (SEQUENCE).
type NoSubscriberReplyParam3 struct {
	ExtensionContainer *ExtensionContainer3 `asn1:",optional" json:"ExtensionContainer,omitempty"`
	ExtCount_          int64                `asn1:"-" json:"-"`
	ExtPresent_        []bool               `asn1:"-" json:"-"`
	ExtData_           [][]byte             `asn1:"-" json:"-"`
}

// ForwardingViolationParam3 represents the ASN.1 type ForwardingViolationParam3 (SEQUENCE).
type ForwardingViolationParam3 struct {
	ExtensionContainer *ExtensionContainer3 `asn1:",optional" json:"ExtensionContainer,omitempty"`
	ExtCount_          int64                `asn1:"-" json:"-"`
	ExtPresent_        []bool               `asn1:"-" json:"-"`
	ExtData_           [][]byte             `asn1:"-" json:"-"`
}

// ForwardingFailedParam3 represents the ASN.1 type ForwardingFailedParam3 (SEQUENCE).
type ForwardingFailedParam3 struct {
	ExtensionContainer *ExtensionContainer3 `asn1:",optional" json:"ExtensionContainer,omitempty"`
	ExtCount_          int64                `asn1:"-" json:"-"`
	ExtPresent_        []bool               `asn1:"-" json:"-"`
	ExtData_           [][]byte             `asn1:"-" json:"-"`
}

// ATINotAllowedParam3 represents the ASN.1 type ATINotAllowedParam3 (SEQUENCE).
type ATINotAllowedParam3 struct {
	ExtensionContainer *ExtensionContainer3 `asn1:",optional" json:"ExtensionContainer,omitempty"`
	ExtCount_          int64                `asn1:"-" json:"-"`
	ExtPresent_        []bool               `asn1:"-" json:"-"`
	ExtData_           [][]byte             `asn1:"-" json:"-"`
}

// ATSINotAllowedParam3 represents the ASN.1 type ATSINotAllowedParam3 (SEQUENCE).
type ATSINotAllowedParam3 struct {
	ExtensionContainer *ExtensionContainer3 `asn1:",optional" json:"ExtensionContainer,omitempty"`
	ExtCount_          int64                `asn1:"-" json:"-"`
	ExtPresent_        []bool               `asn1:"-" json:"-"`
	ExtData_           [][]byte             `asn1:"-" json:"-"`
}

// ATMNotAllowedParam3 represents the ASN.1 type ATMNotAllowedParam3 (SEQUENCE).
type ATMNotAllowedParam3 struct {
	ExtensionContainer *ExtensionContainer3 `asn1:",optional" json:"ExtensionContainer,omitempty"`
	ExtCount_          int64                `asn1:"-" json:"-"`
	ExtPresent_        []bool               `asn1:"-" json:"-"`
	ExtData_           [][]byte             `asn1:"-" json:"-"`
}

// IllegalSSOperationParam3 represents the ASN.1 type IllegalSSOperationParam3 (SEQUENCE).
type IllegalSSOperationParam3 struct {
	ExtensionContainer *ExtensionContainer3 `asn1:",optional" json:"ExtensionContainer,omitempty"`
	ExtCount_          int64                `asn1:"-" json:"-"`
	ExtPresent_        []bool               `asn1:"-" json:"-"`
	ExtData_           [][]byte             `asn1:"-" json:"-"`
}

// SSNotAvailableParam3 represents the ASN.1 type SSNotAvailableParam3 (SEQUENCE).
type SSNotAvailableParam3 struct {
	ExtensionContainer *ExtensionContainer3 `asn1:",optional" json:"ExtensionContainer,omitempty"`
	ExtCount_          int64                `asn1:"-" json:"-"`
	ExtPresent_        []bool               `asn1:"-" json:"-"`
	ExtData_           [][]byte             `asn1:"-" json:"-"`
}

// SSSubscriptionViolationParam3 represents the ASN.1 type SSSubscriptionViolationParam3 (SEQUENCE).
type SSSubscriptionViolationParam3 struct {
	ExtensionContainer *ExtensionContainer3 `asn1:",optional" json:"ExtensionContainer,omitempty"`
	ExtCount_          int64                `asn1:"-" json:"-"`
	ExtPresent_        []bool               `asn1:"-" json:"-"`
	ExtData_           [][]byte             `asn1:"-" json:"-"`
}

// InformationNotAvailableParam3 represents the ASN.1 type InformationNotAvailableParam3 (SEQUENCE).
type InformationNotAvailableParam3 struct {
	ExtensionContainer *ExtensionContainer3 `asn1:",optional" json:"ExtensionContainer,omitempty"`
	ExtCount_          int64                `asn1:"-" json:"-"`
	ExtPresent_        []bool               `asn1:"-" json:"-"`
	ExtData_           [][]byte             `asn1:"-" json:"-"`
}

// SubBusyForMTSMSParam3 represents the ASN.1 type SubBusyForMTSMSParam3 (SEQUENCE).
type SubBusyForMTSMSParam3 struct {
	ExtensionContainer      *ExtensionContainer3 `asn1:",optional" json:"ExtensionContainer,omitempty"`
	GprsConnectionSuspended *struct{}            `asn1:",optional" json:"GprsConnectionSuspended,omitempty"`
	ExtCount_               int64                `asn1:"-" json:"-"`
	ExtPresent_             []bool               `asn1:"-" json:"-"`
	ExtData_                [][]byte             `asn1:"-" json:"-"`
}

// MessageWaitListFullParam3 represents the ASN.1 type MessageWaitListFullParam3 (SEQUENCE).
type MessageWaitListFullParam3 struct {
	ExtensionContainer *ExtensionContainer3 `asn1:",optional" json:"ExtensionContainer,omitempty"`
	ExtCount_          int64                `asn1:"-" json:"-"`
	ExtPresent_        []bool               `asn1:"-" json:"-"`
	ExtData_           [][]byte             `asn1:"-" json:"-"`
}

// ResourceLimitationParam3 represents the ASN.1 type ResourceLimitationParam3 (SEQUENCE).
type ResourceLimitationParam3 struct {
	ExtensionContainer *ExtensionContainer3 `asn1:",optional" json:"ExtensionContainer,omitempty"`
	ExtCount_          int64                `asn1:"-" json:"-"`
	ExtPresent_        []bool               `asn1:"-" json:"-"`
	ExtData_           [][]byte             `asn1:"-" json:"-"`
}

// NoGroupCallNbParam3 represents the ASN.1 type NoGroupCallNbParam3 (SEQUENCE).
type NoGroupCallNbParam3 struct {
	ExtensionContainer *ExtensionContainer3 `asn1:",optional" json:"ExtensionContainer,omitempty"`
	ExtCount_          int64                `asn1:"-" json:"-"`
	ExtPresent_        []bool               `asn1:"-" json:"-"`
	ExtData_           [][]byte             `asn1:"-" json:"-"`
}

// IncompatibleTerminalParam3 represents the ASN.1 type IncompatibleTerminalParam3 (SEQUENCE).
type IncompatibleTerminalParam3 struct {
	ExtensionContainer *ExtensionContainer3 `asn1:",optional" json:"ExtensionContainer,omitempty"`
	ExtCount_          int64                `asn1:"-" json:"-"`
	ExtPresent_        []bool               `asn1:"-" json:"-"`
	ExtData_           [][]byte             `asn1:"-" json:"-"`
}

// ShortTermDenialParam3 represents the ASN.1 type ShortTermDenialParam3 (SEQUENCE).
type ShortTermDenialParam3 struct {
	ExtCount_   int64    `asn1:"-" json:"-"`
	ExtPresent_ []bool   `asn1:"-" json:"-"`
	ExtData_    [][]byte `asn1:"-" json:"-"`
}

// LongTermDenialParam3 represents the ASN.1 type LongTermDenialParam3 (SEQUENCE).
type LongTermDenialParam3 struct {
	ExtCount_   int64    `asn1:"-" json:"-"`
	ExtPresent_ []bool   `asn1:"-" json:"-"`
	ExtData_    [][]byte `asn1:"-" json:"-"`
}

// UnauthorizedRequestingNetworkParam3 represents the ASN.1 type UnauthorizedRequestingNetworkParam3 (SEQUENCE).
type UnauthorizedRequestingNetworkParam3 struct {
	ExtensionContainer *ExtensionContainer3 `asn1:",optional" json:"ExtensionContainer,omitempty"`
	ExtCount_          int64                `asn1:"-" json:"-"`
	ExtPresent_        []bool               `asn1:"-" json:"-"`
	ExtData_           [][]byte             `asn1:"-" json:"-"`
}

// UnauthorizedLCSClientParam3 represents the ASN.1 type UnauthorizedLCSClientParam3 (SEQUENCE).
type UnauthorizedLCSClientParam3 struct {
	UnauthorizedLCSClientDiagnostic *UnauthorizedLCSClientDiagnostic3 `asn1:"tag:0,context,implicit,optional" json:"UnauthorizedLCSClientDiagnostic,omitempty"`
	ExtensionContainer              *ExtensionContainer3              `asn1:"tag:1,context,implicit,optional" json:"ExtensionContainer,omitempty"`
	ExtCount_                       int64                             `asn1:"-" json:"-"`
	ExtPresent_                     []bool                            `asn1:"-" json:"-"`
	ExtData_                        [][]byte                          `asn1:"-" json:"-"`
}

// UnauthorizedLCSClientDiagnostic3 represents the ASN.1 ENUMERATED type UnauthorizedLCSClientDiagnostic3.
type UnauthorizedLCSClientDiagnostic3 int64

const (
	UnauthorizedLCSClientDiagnostic3NoAdditionalInformation                        UnauthorizedLCSClientDiagnostic3 = 0
	UnauthorizedLCSClientDiagnostic3ClientNotInMSPrivacyExceptionList              UnauthorizedLCSClientDiagnostic3 = 1
	UnauthorizedLCSClientDiagnostic3CallToClientNotSetup                           UnauthorizedLCSClientDiagnostic3 = 2
	UnauthorizedLCSClientDiagnostic3PrivacyOverrideNotApplicable                   UnauthorizedLCSClientDiagnostic3 = 3
	UnauthorizedLCSClientDiagnostic3DisallowedByLocalRegulatoryRequirements        UnauthorizedLCSClientDiagnostic3 = 4
	UnauthorizedLCSClientDiagnostic3UnauthorizedPrivacyClass                       UnauthorizedLCSClientDiagnostic3 = 5
	UnauthorizedLCSClientDiagnostic3UnauthorizedCallSessionUnrelatedExternalClient UnauthorizedLCSClientDiagnostic3 = 6
	UnauthorizedLCSClientDiagnostic3UnauthorizedCallSessionRelatedExternalClient   UnauthorizedLCSClientDiagnostic3 = 7
)

func (v UnauthorizedLCSClientDiagnostic3) String() string {
	switch v {
	case UnauthorizedLCSClientDiagnostic3NoAdditionalInformation:
		return "noAdditionalInformation"
	case UnauthorizedLCSClientDiagnostic3ClientNotInMSPrivacyExceptionList:
		return "clientNotInMSPrivacyExceptionList"
	case UnauthorizedLCSClientDiagnostic3CallToClientNotSetup:
		return "callToClientNotSetup"
	case UnauthorizedLCSClientDiagnostic3PrivacyOverrideNotApplicable:
		return "privacyOverrideNotApplicable"
	case UnauthorizedLCSClientDiagnostic3DisallowedByLocalRegulatoryRequirements:
		return "disallowedByLocalRegulatoryRequirements"
	case UnauthorizedLCSClientDiagnostic3UnauthorizedPrivacyClass:
		return "unauthorizedPrivacyClass"
	case UnauthorizedLCSClientDiagnostic3UnauthorizedCallSessionUnrelatedExternalClient:
		return "unauthorizedCallSessionUnrelatedExternalClient"
	case UnauthorizedLCSClientDiagnostic3UnauthorizedCallSessionRelatedExternalClient:
		return "unauthorizedCallSessionRelatedExternalClient"
	default:
		return "unknown"
	}
}

// PositionMethodFailureParam3 represents the ASN.1 type PositionMethodFailureParam3 (SEQUENCE).
type PositionMethodFailureParam3 struct {
	PositionMethodFailureDiagnostic *PositionMethodFailureDiagnostic3 `asn1:"tag:0,context,implicit,optional" json:"PositionMethodFailureDiagnostic,omitempty"`
	ExtensionContainer              *ExtensionContainer3              `asn1:"tag:1,context,implicit,optional" json:"ExtensionContainer,omitempty"`
	ExtCount_                       int64                             `asn1:"-" json:"-"`
	ExtPresent_                     []bool                            `asn1:"-" json:"-"`
	ExtData_                        [][]byte                          `asn1:"-" json:"-"`
}

// PositionMethodFailureDiagnostic3 represents the ASN.1 ENUMERATED type PositionMethodFailureDiagnostic3.
type PositionMethodFailureDiagnostic3 int64

const (
	PositionMethodFailureDiagnostic3Congestion                               PositionMethodFailureDiagnostic3 = 0
	PositionMethodFailureDiagnostic3InsufficientResources                    PositionMethodFailureDiagnostic3 = 1
	PositionMethodFailureDiagnostic3InsufficientMeasurementData              PositionMethodFailureDiagnostic3 = 2
	PositionMethodFailureDiagnostic3InconsistentMeasurementData              PositionMethodFailureDiagnostic3 = 3
	PositionMethodFailureDiagnostic3LocationProcedureNotCompleted            PositionMethodFailureDiagnostic3 = 4
	PositionMethodFailureDiagnostic3LocationProcedureNotSupportedByTargetMS  PositionMethodFailureDiagnostic3 = 5
	PositionMethodFailureDiagnostic3QoSNotAttainable                         PositionMethodFailureDiagnostic3 = 6
	PositionMethodFailureDiagnostic3PositionMethodNotAvailableInNetwork      PositionMethodFailureDiagnostic3 = 7
	PositionMethodFailureDiagnostic3PositionMethodNotAvailableInLocationArea PositionMethodFailureDiagnostic3 = 8
)

func (v PositionMethodFailureDiagnostic3) String() string {
	switch v {
	case PositionMethodFailureDiagnostic3Congestion:
		return "congestion"
	case PositionMethodFailureDiagnostic3InsufficientResources:
		return "insufficientResources"
	case PositionMethodFailureDiagnostic3InsufficientMeasurementData:
		return "insufficientMeasurementData"
	case PositionMethodFailureDiagnostic3InconsistentMeasurementData:
		return "inconsistentMeasurementData"
	case PositionMethodFailureDiagnostic3LocationProcedureNotCompleted:
		return "locationProcedureNotCompleted"
	case PositionMethodFailureDiagnostic3LocationProcedureNotSupportedByTargetMS:
		return "locationProcedureNotSupportedByTargetMS"
	case PositionMethodFailureDiagnostic3QoSNotAttainable:
		return "qoSNotAttainable"
	case PositionMethodFailureDiagnostic3PositionMethodNotAvailableInNetwork:
		return "positionMethodNotAvailableInNetwork"
	case PositionMethodFailureDiagnostic3PositionMethodNotAvailableInLocationArea:
		return "positionMethodNotAvailableInLocationArea"
	default:
		return "unknown"
	}
}

// UnknownOrUnreachableLCSClientParam3 represents the ASN.1 type UnknownOrUnreachableLCSClientParam3 (SEQUENCE).
type UnknownOrUnreachableLCSClientParam3 struct {
	ExtensionContainer *ExtensionContainer3 `asn1:",optional" json:"ExtensionContainer,omitempty"`
	ExtCount_          int64                `asn1:"-" json:"-"`
	ExtPresent_        []bool               `asn1:"-" json:"-"`
	ExtData_           [][]byte             `asn1:"-" json:"-"`
}

// MMEventNotSupportedParam3 represents the ASN.1 type MMEventNotSupportedParam3 (SEQUENCE).
type MMEventNotSupportedParam3 struct {
	ExtensionContainer *ExtensionContainer3 `asn1:",optional" json:"ExtensionContainer,omitempty"`
	ExtCount_          int64                `asn1:"-" json:"-"`
	ExtPresent_        []bool               `asn1:"-" json:"-"`
	ExtData_           [][]byte             `asn1:"-" json:"-"`
}

// TargetCellOutsideGCAParam3 represents the ASN.1 type TargetCellOutsideGCAParam3 (SEQUENCE).
type TargetCellOutsideGCAParam3 struct {
	ExtensionContainer *ExtensionContainer3 `asn1:",optional" json:"ExtensionContainer,omitempty"`
	ExtCount_          int64                `asn1:"-" json:"-"`
	ExtPresent_        []bool               `asn1:"-" json:"-"`
	ExtData_           [][]byte             `asn1:"-" json:"-"`
}

// OngoingGroupCallParam3 represents the ASN.1 type OngoingGroupCallParam3 (SEQUENCE).
type OngoingGroupCallParam3 struct {
	ExtensionContainer *ExtensionContainer3 `asn1:",optional" json:"ExtensionContainer,omitempty"`
	ExtCount_          int64                `asn1:"-" json:"-"`
	ExtPresent_        []bool               `asn1:"-" json:"-"`
	ExtData_           [][]byte             `asn1:"-" json:"-"`
}

// MarshalBER encodes RoamingNotAllowedParam3 to BER format.
func (v *RoamingNotAllowedParam3) MarshalBER() ([]byte, error) {
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
		enc_additionalroamingnotallowedcause = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, false, enc_additionalroamingnotallowedcause)
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

// MarshalDER encodes RoamingNotAllowedParam3 to DER format.
func (v *RoamingNotAllowedParam3) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes RoamingNotAllowedParam3 from BER/DER format.
func (v *RoamingNotAllowedParam3) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding RoamingNotAllowedParam3 SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "RoamingNotAllowedParam3", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode roamingNotAllowedCause
	if offset >= len(content) {
		return fmt.Errorf("missing required field roamingNotAllowedCause")
	}
	val_roamingnotallowedcause, n, err := ber.DecodeInteger(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding roamingNotAllowedCause: %w", err)
	}
	v.RoamingNotAllowedCause = RoamingNotAllowedCause3(val_roamingnotallowedcause)
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
	// Decode additionalRoamingNotAllowedCause
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
				_, n_additionalroamingnotallowedcause, rawVal_additionalroamingnotallowedcause, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding additionalRoamingNotAllowedCause: %w", err)
				}
				decVal_additionalroamingnotallowedcause, intErr := ber.DecodeIntegerValue(rawVal_additionalroamingnotallowedcause)
				if intErr != nil {
					return fmt.Errorf("decoding additionalRoamingNotAllowedCause: %w", intErr)
				}
				tmp_additionalroamingnotallowedcause := AdditionalRoamingNotAllowedCause3(decVal_additionalroamingnotallowedcause)
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
			return &ber.DecodeError{Offset: offset, TypeName: "RoamingNotAllowedParam3", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes CallBarredParam3 to BER format.
func (v *CallBarredParam3) MarshalBER() ([]byte, error) {
	switch v.Choice {
	case CallBarredParam3ChoiceCallBarringCause:
		if v.CallBarringCause == nil {
			return nil, fmt.Errorf("choice CallBarredParam3: callBarringCause is nil")
		}
		enc_0 := ber.EncodeEnumerated(int64(*v.CallBarringCause))
		return enc_0, nil
	case CallBarredParam3ChoiceExtensibleCallBarredParam:
		if v.ExtensibleCallBarredParam == nil {
			return nil, fmt.Errorf("choice CallBarredParam3: extensibleCallBarredParam is nil")
		}
		enc_1, err := v.ExtensibleCallBarredParam.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding extensibleCallBarredParam: %w", err)
		}
		return enc_1, nil
	default:
		return nil, fmt.Errorf("unknown choice %d for CallBarredParam3", v.Choice)
	}
}

// MarshalDER encodes CallBarredParam3 to DER format.
func (v *CallBarredParam3) MarshalDER() ([]byte, error) {
	switch v.Choice {
	case CallBarredParam3ChoiceExtensibleCallBarredParam:
		if v.ExtensibleCallBarredParam == nil {
			return nil, fmt.Errorf("choice CallBarredParam3: extensibleCallBarredParam is nil")
		}
		enc_der_1, err := v.ExtensibleCallBarredParam.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding extensibleCallBarredParam: %w", err)
		}
		return enc_der_1, nil
	}
	return v.MarshalBER()
}

// UnmarshalBER decodes CallBarredParam3 from BER/DER format.
func (v *CallBarredParam3) UnmarshalBER(data []byte) error {
	if len(data) == 0 {
		return fmt.Errorf("empty data for CallBarredParam3 CHOICE")
	}
	choiceData := data
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for CallBarredParam3: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData)
	if tlvErr != nil {
		return fmt.Errorf("decoding CallBarredParam3 CHOICE: %w", tlvErr)
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "CallBarredParam3", Cause: ber.ErrExtraData}
	}

	if peekTag.Class == tag.ClassUniversal && peekTag.Number == 10 {
		v.Choice = CallBarredParam3ChoiceCallBarringCause
		decVal, _, intErr := ber.DecodeInteger(choiceData)
		if intErr != nil {
			return fmt.Errorf("decoding callBarringCause: %w", intErr)
		}
		tmp := CallBarringCause3(decVal)
		v.CallBarringCause = &tmp
	} else if peekTag.Class == tag.ClassUniversal && peekTag.Number == 16 {
		v.Choice = CallBarredParam3ChoiceExtensibleCallBarredParam
		var dec ExtensibleCallBarredParam3
		if unmErr := dec.UnmarshalBER(choiceData); unmErr != nil {
			return fmt.Errorf("decoding extensibleCallBarredParam: %w", unmErr)
		}
		v.ExtensibleCallBarredParam = &dec
	} else {
		return fmt.Errorf("unknown tag %s for CallBarredParam3 CHOICE", peekTag)
	}
	return nil
}

// MarshalBER encodes ExtensibleCallBarredParam3 to BER format.
func (v *ExtensibleCallBarredParam3) MarshalBER() ([]byte, error) {
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
		enc_unauthorisedmessageoriginator = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, false, enc_unauthorisedmessageoriginator)
		children = append(children, enc_unauthorisedmessageoriginator...)
	}
	if v.AnonymousCallRejection != nil {
		enc_anonymouscallrejection := ber.EncodeNull()
		enc_anonymouscallrejection = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, false, enc_anonymouscallrejection)
		children = append(children, enc_anonymouscallrejection...)
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

// MarshalDER encodes ExtensibleCallBarredParam3 to DER format.
func (v *ExtensibleCallBarredParam3) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes ExtensibleCallBarredParam3 from BER/DER format.
func (v *ExtensibleCallBarredParam3) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding ExtensibleCallBarredParam3 SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "ExtensibleCallBarredParam3", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode callBarringCause
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassUniversal && peekTag.Number == 10 {
				val_callbarringcause, n, err := ber.DecodeInteger(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding callBarringCause: %w", err)
				}
				tmp_callbarringcause := CallBarringCause3(val_callbarringcause)
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
	// Decode unauthorisedMessageOriginator
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
				_, n_unauthorisedmessageoriginator, rawVal_unauthorisedmessageoriginator, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding unauthorisedMessageOriginator: %w", err)
				}
				_ = rawVal_unauthorisedmessageoriginator
				v.UnauthorisedMessageOriginator = &struct{}{}
				offset += n_unauthorisedmessageoriginator
			}
		}
	}
	// Decode anonymousCallRejection
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2 {
				_, n_anonymouscallrejection, rawVal_anonymouscallrejection, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding anonymousCallRejection: %w", err)
				}
				_ = rawVal_anonymouscallrejection
				v.AnonymousCallRejection = &struct{}{}
				offset += n_anonymouscallrejection
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "ExtensibleCallBarredParam3", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes CUGRejectParam3 to BER format.
func (v *CUGRejectParam3) MarshalBER() ([]byte, error) {
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

// MarshalDER encodes CUGRejectParam3 to DER format.
func (v *CUGRejectParam3) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes CUGRejectParam3 from BER/DER format.
func (v *CUGRejectParam3) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding CUGRejectParam3 SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "CUGRejectParam3", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode cug-RejectCause
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassUniversal && peekTag.Number == 10 {
				val_cugrejectcause, n, err := ber.DecodeInteger(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding cug-RejectCause: %w", err)
				}
				tmp_cugrejectcause := CUGRejectCause3(val_cugrejectcause)
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
			return &ber.DecodeError{Offset: offset, TypeName: "CUGRejectParam3", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes SSIncompatibilityCause3 to BER format.
func (v *SSIncompatibilityCause3) MarshalBER() ([]byte, error) {
	var children []byte
	if v.SsCode != nil {
		enc_sscode := ber.EncodeOctetString([]byte(*v.SsCode))
		enc_sscode = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, false, enc_sscode)
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
		enc_ssstatus = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, false, enc_ssstatus)
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

// MarshalDER encodes SSIncompatibilityCause3 to DER format.
func (v *SSIncompatibilityCause3) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes SSIncompatibilityCause3 from BER/DER format.
func (v *SSIncompatibilityCause3) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding SSIncompatibilityCause3 SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "SSIncompatibilityCause3", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode ss-Code
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
				_, n_sscode, rawVal_sscode, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding ss-Code: %w", err)
				}
				tmp_sscode := SSCode3(rawVal_sscode)
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
				// Decode nested CHOICE (BasicServiceCode3)
				_, n_basicservice, _, tlvErr_basicservice := ber.DecodeTLV(content[offset:])
				if tlvErr_basicservice != nil {
					return fmt.Errorf("decoding basicService: %w", tlvErr_basicservice)
				}
				var dec_basicservice BasicServiceCode3
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
				_, n_ssstatus, rawVal_ssstatus, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding ss-Status: %w", err)
				}
				tmp_ssstatus := SSStatus3(rawVal_ssstatus)
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
			return &ber.DecodeError{Offset: offset, TypeName: "SSIncompatibilityCause3", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes SMDeliveryFailureCause3 to BER format.
func (v *SMDeliveryFailureCause3) MarshalBER() ([]byte, error) {
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

// MarshalDER encodes SMDeliveryFailureCause3 to DER format.
func (v *SMDeliveryFailureCause3) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes SMDeliveryFailureCause3 from BER/DER format.
func (v *SMDeliveryFailureCause3) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding SMDeliveryFailureCause3 SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "SMDeliveryFailureCause3", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode sm-EnumeratedDeliveryFailureCause
	if offset >= len(content) {
		return fmt.Errorf("missing required field sm-EnumeratedDeliveryFailureCause")
	}
	val_smenumerateddeliveryfailurecause, n, err := ber.DecodeInteger(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding sm-EnumeratedDeliveryFailureCause: %w", err)
	}
	v.SmEnumeratedDeliveryFailureCause = SMEnumeratedDeliveryFailureCause3(val_smenumerateddeliveryfailurecause)
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
				tmp_diagnosticinfo := SignalInfo3(val_diagnosticinfo)
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
			return &ber.DecodeError{Offset: offset, TypeName: "SMDeliveryFailureCause3", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes AbsentSubscriberSMParam3 to BER format.
func (v *AbsentSubscriberSMParam3) MarshalBER() ([]byte, error) {
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
		enc_additionalabsentsubscriberdiagnosticsm = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, false, enc_additionalabsentsubscriberdiagnosticsm)
		children = append(children, enc_additionalabsentsubscriberdiagnosticsm...)
	}
	if v.Imsi != nil {
		enc_imsi := ber.EncodeOctetString([]byte(*v.Imsi))
		enc_imsi = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, false, enc_imsi)
		children = append(children, enc_imsi...)
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

// MarshalDER encodes AbsentSubscriberSMParam3 to DER format.
func (v *AbsentSubscriberSMParam3) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes AbsentSubscriberSMParam3 from BER/DER format.
func (v *AbsentSubscriberSMParam3) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding AbsentSubscriberSMParam3 SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "AbsentSubscriberSMParam3", Cause: ber.ErrExtraData}
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
				tmp_absentsubscriberdiagnosticsm := AbsentSubscriberDiagnosticSM3(val_absentsubscriberdiagnosticsm)
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
	// Decode imsi
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
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
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "AbsentSubscriberSMParam3", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes SystemFailureParam3 to BER format.
func (v *SystemFailureParam3) MarshalBER() ([]byte, error) {
	switch v.Choice {
	case SystemFailureParam3ChoiceNetworkResource:
		if v.NetworkResource == nil {
			return nil, fmt.Errorf("choice SystemFailureParam3: networkResource is nil")
		}
		enc_0 := ber.EncodeEnumerated(int64(*v.NetworkResource))
		return enc_0, nil
	case SystemFailureParam3ChoiceExtensibleSystemFailureParam:
		if v.ExtensibleSystemFailureParam == nil {
			return nil, fmt.Errorf("choice SystemFailureParam3: extensibleSystemFailureParam is nil")
		}
		enc_1, err := v.ExtensibleSystemFailureParam.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding extensibleSystemFailureParam: %w", err)
		}
		return enc_1, nil
	default:
		return nil, fmt.Errorf("unknown choice %d for SystemFailureParam3", v.Choice)
	}
}

// MarshalDER encodes SystemFailureParam3 to DER format.
func (v *SystemFailureParam3) MarshalDER() ([]byte, error) {
	switch v.Choice {
	case SystemFailureParam3ChoiceExtensibleSystemFailureParam:
		if v.ExtensibleSystemFailureParam == nil {
			return nil, fmt.Errorf("choice SystemFailureParam3: extensibleSystemFailureParam is nil")
		}
		enc_der_1, err := v.ExtensibleSystemFailureParam.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding extensibleSystemFailureParam: %w", err)
		}
		return enc_der_1, nil
	}
	return v.MarshalBER()
}

// UnmarshalBER decodes SystemFailureParam3 from BER/DER format.
func (v *SystemFailureParam3) UnmarshalBER(data []byte) error {
	if len(data) == 0 {
		return fmt.Errorf("empty data for SystemFailureParam3 CHOICE")
	}
	choiceData := data
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for SystemFailureParam3: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData)
	if tlvErr != nil {
		return fmt.Errorf("decoding SystemFailureParam3 CHOICE: %w", tlvErr)
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "SystemFailureParam3", Cause: ber.ErrExtraData}
	}

	if peekTag.Class == tag.ClassUniversal && peekTag.Number == 10 {
		v.Choice = SystemFailureParam3ChoiceNetworkResource
		decVal, _, intErr := ber.DecodeInteger(choiceData)
		if intErr != nil {
			return fmt.Errorf("decoding networkResource: %w", intErr)
		}
		tmp := NetworkResource3(decVal)
		v.NetworkResource = &tmp
	} else if peekTag.Class == tag.ClassUniversal && peekTag.Number == 16 {
		v.Choice = SystemFailureParam3ChoiceExtensibleSystemFailureParam
		var dec ExtensibleSystemFailureParam3
		if unmErr := dec.UnmarshalBER(choiceData); unmErr != nil {
			return fmt.Errorf("decoding extensibleSystemFailureParam: %w", unmErr)
		}
		v.ExtensibleSystemFailureParam = &dec
	} else {
		return fmt.Errorf("unknown tag %s for SystemFailureParam3 CHOICE", peekTag)
	}
	return nil
}

// MarshalBER encodes ExtensibleSystemFailureParam3 to BER format.
func (v *ExtensibleSystemFailureParam3) MarshalBER() ([]byte, error) {
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
		enc_additionalnetworkresource = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, false, enc_additionalnetworkresource)
		children = append(children, enc_additionalnetworkresource...)
	}
	if v.FailureCauseParam != nil {
		enc_failurecauseparam := ber.EncodeEnumerated(int64(*v.FailureCauseParam))
		enc_failurecauseparam = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, false, enc_failurecauseparam)
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

// MarshalDER encodes ExtensibleSystemFailureParam3 to DER format.
func (v *ExtensibleSystemFailureParam3) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes ExtensibleSystemFailureParam3 from BER/DER format.
func (v *ExtensibleSystemFailureParam3) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding ExtensibleSystemFailureParam3 SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "ExtensibleSystemFailureParam3", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode networkResource
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassUniversal && peekTag.Number == 10 {
				val_networkresource, n, err := ber.DecodeInteger(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding networkResource: %w", err)
				}
				tmp_networkresource := NetworkResource3(val_networkresource)
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
	// Decode additionalNetworkResource
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
				_, n_additionalnetworkresource, rawVal_additionalnetworkresource, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding additionalNetworkResource: %w", err)
				}
				decVal_additionalnetworkresource, intErr := ber.DecodeIntegerValue(rawVal_additionalnetworkresource)
				if intErr != nil {
					return fmt.Errorf("decoding additionalNetworkResource: %w", intErr)
				}
				tmp_additionalnetworkresource := AdditionalNetworkResource3(decVal_additionalnetworkresource)
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
				_, n_failurecauseparam, rawVal_failurecauseparam, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding failureCauseParam: %w", err)
				}
				decVal_failurecauseparam, intErr := ber.DecodeIntegerValue(rawVal_failurecauseparam)
				if intErr != nil {
					return fmt.Errorf("decoding failureCauseParam: %w", intErr)
				}
				tmp_failurecauseparam := ERFailureCauseParam(decVal_failurecauseparam)
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
			return &ber.DecodeError{Offset: offset, TypeName: "ExtensibleSystemFailureParam3", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes DataMissingParam3 to BER format.
func (v *DataMissingParam3) MarshalBER() ([]byte, error) {
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

// MarshalDER encodes DataMissingParam3 to DER format.
func (v *DataMissingParam3) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes DataMissingParam3 from BER/DER format.
func (v *DataMissingParam3) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding DataMissingParam3 SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "DataMissingParam3", Cause: ber.ErrExtraData}
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
			return &ber.DecodeError{Offset: offset, TypeName: "DataMissingParam3", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes UnexpectedDataParam3 to BER format.
func (v *UnexpectedDataParam3) MarshalBER() ([]byte, error) {
	var children []byte
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding extensionContainer: %w", err)
		}
		children = append(children, enc_extensioncontainer...)
	}
	if v.UnexpectedSubscriber != nil {
		enc_unexpectedsubscriber := ber.EncodeNull()
		enc_unexpectedsubscriber = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, false, enc_unexpectedsubscriber)
		children = append(children, enc_unexpectedsubscriber...)
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

// MarshalDER encodes UnexpectedDataParam3 to DER format.
func (v *UnexpectedDataParam3) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes UnexpectedDataParam3 from BER/DER format.
func (v *UnexpectedDataParam3) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding UnexpectedDataParam3 SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "UnexpectedDataParam3", Cause: ber.ErrExtraData}
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
	// Decode unexpectedSubscriber
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
				_, n_unexpectedsubscriber, rawVal_unexpectedsubscriber, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding unexpectedSubscriber: %w", err)
				}
				_ = rawVal_unexpectedsubscriber
				v.UnexpectedSubscriber = &struct{}{}
				offset += n_unexpectedsubscriber
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "UnexpectedDataParam3", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes FacilityNotSupParam3 to BER format.
func (v *FacilityNotSupParam3) MarshalBER() ([]byte, error) {
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
		enc_shapeoflocationestimatenotsupported = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, false, enc_shapeoflocationestimatenotsupported)
		children = append(children, enc_shapeoflocationestimatenotsupported...)
	}
	if v.NeededLcsCapabilityNotSupportedInServingNode != nil {
		enc_neededlcscapabilitynotsupportedinservingnode := ber.EncodeNull()
		enc_neededlcscapabilitynotsupportedinservingnode = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, false, enc_neededlcscapabilitynotsupportedinservingnode)
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

// MarshalDER encodes FacilityNotSupParam3 to DER format.
func (v *FacilityNotSupParam3) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes FacilityNotSupParam3 from BER/DER format.
func (v *FacilityNotSupParam3) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding FacilityNotSupParam3 SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "FacilityNotSupParam3", Cause: ber.ErrExtraData}
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
	// Decode shapeOfLocationEstimateNotSupported
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
				_, n_shapeoflocationestimatenotsupported, rawVal_shapeoflocationestimatenotsupported, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding shapeOfLocationEstimateNotSupported: %w", err)
				}
				_ = rawVal_shapeoflocationestimatenotsupported
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
				_, n_neededlcscapabilitynotsupportedinservingnode, rawVal_neededlcscapabilitynotsupportedinservingnode, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding neededLcsCapabilityNotSupportedInServingNode: %w", err)
				}
				_ = rawVal_neededlcscapabilitynotsupportedinservingnode
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
			return &ber.DecodeError{Offset: offset, TypeName: "FacilityNotSupParam3", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes ORNotAllowedParam3 to BER format.
func (v *ORNotAllowedParam3) MarshalBER() ([]byte, error) {
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

// MarshalDER encodes ORNotAllowedParam3 to DER format.
func (v *ORNotAllowedParam3) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes ORNotAllowedParam3 from BER/DER format.
func (v *ORNotAllowedParam3) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding ORNotAllowedParam3 SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "ORNotAllowedParam3", Cause: ber.ErrExtraData}
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
			return &ber.DecodeError{Offset: offset, TypeName: "ORNotAllowedParam3", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes UnknownSubscriberParam3 to BER format.
func (v *UnknownSubscriberParam3) MarshalBER() ([]byte, error) {
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

// MarshalDER encodes UnknownSubscriberParam3 to DER format.
func (v *UnknownSubscriberParam3) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes UnknownSubscriberParam3 from BER/DER format.
func (v *UnknownSubscriberParam3) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding UnknownSubscriberParam3 SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "UnknownSubscriberParam3", Cause: ber.ErrExtraData}
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
	// Decode unknownSubscriberDiagnostic
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassUniversal && peekTag.Number == 10 {
				val_unknownsubscriberdiagnostic, n, err := ber.DecodeInteger(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding unknownSubscriberDiagnostic: %w", err)
				}
				tmp_unknownsubscriberdiagnostic := UnknownSubscriberDiagnostic3(val_unknownsubscriberdiagnostic)
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
			return &ber.DecodeError{Offset: offset, TypeName: "UnknownSubscriberParam3", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes NumberChangedParam3 to BER format.
func (v *NumberChangedParam3) MarshalBER() ([]byte, error) {
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

// MarshalDER encodes NumberChangedParam3 to DER format.
func (v *NumberChangedParam3) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes NumberChangedParam3 from BER/DER format.
func (v *NumberChangedParam3) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding NumberChangedParam3 SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "NumberChangedParam3", Cause: ber.ErrExtraData}
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
			return &ber.DecodeError{Offset: offset, TypeName: "NumberChangedParam3", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes UnidentifiedSubParam3 to BER format.
func (v *UnidentifiedSubParam3) MarshalBER() ([]byte, error) {
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

// MarshalDER encodes UnidentifiedSubParam3 to DER format.
func (v *UnidentifiedSubParam3) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes UnidentifiedSubParam3 from BER/DER format.
func (v *UnidentifiedSubParam3) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding UnidentifiedSubParam3 SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "UnidentifiedSubParam3", Cause: ber.ErrExtraData}
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
			return &ber.DecodeError{Offset: offset, TypeName: "UnidentifiedSubParam3", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes IllegalSubscriberParam3 to BER format.
func (v *IllegalSubscriberParam3) MarshalBER() ([]byte, error) {
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

// MarshalDER encodes IllegalSubscriberParam3 to DER format.
func (v *IllegalSubscriberParam3) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes IllegalSubscriberParam3 from BER/DER format.
func (v *IllegalSubscriberParam3) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding IllegalSubscriberParam3 SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "IllegalSubscriberParam3", Cause: ber.ErrExtraData}
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
			return &ber.DecodeError{Offset: offset, TypeName: "IllegalSubscriberParam3", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes IllegalEquipmentParam3 to BER format.
func (v *IllegalEquipmentParam3) MarshalBER() ([]byte, error) {
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

// MarshalDER encodes IllegalEquipmentParam3 to DER format.
func (v *IllegalEquipmentParam3) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes IllegalEquipmentParam3 from BER/DER format.
func (v *IllegalEquipmentParam3) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding IllegalEquipmentParam3 SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "IllegalEquipmentParam3", Cause: ber.ErrExtraData}
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
			return &ber.DecodeError{Offset: offset, TypeName: "IllegalEquipmentParam3", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes BearerServNotProvParam3 to BER format.
func (v *BearerServNotProvParam3) MarshalBER() ([]byte, error) {
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

// MarshalDER encodes BearerServNotProvParam3 to DER format.
func (v *BearerServNotProvParam3) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes BearerServNotProvParam3 from BER/DER format.
func (v *BearerServNotProvParam3) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding BearerServNotProvParam3 SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "BearerServNotProvParam3", Cause: ber.ErrExtraData}
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
			return &ber.DecodeError{Offset: offset, TypeName: "BearerServNotProvParam3", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes TeleservNotProvParam3 to BER format.
func (v *TeleservNotProvParam3) MarshalBER() ([]byte, error) {
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

// MarshalDER encodes TeleservNotProvParam3 to DER format.
func (v *TeleservNotProvParam3) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes TeleservNotProvParam3 from BER/DER format.
func (v *TeleservNotProvParam3) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding TeleservNotProvParam3 SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "TeleservNotProvParam3", Cause: ber.ErrExtraData}
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
			return &ber.DecodeError{Offset: offset, TypeName: "TeleservNotProvParam3", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes TracingBufferFullParam3 to BER format.
func (v *TracingBufferFullParam3) MarshalBER() ([]byte, error) {
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

// MarshalDER encodes TracingBufferFullParam3 to DER format.
func (v *TracingBufferFullParam3) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes TracingBufferFullParam3 from BER/DER format.
func (v *TracingBufferFullParam3) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding TracingBufferFullParam3 SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "TracingBufferFullParam3", Cause: ber.ErrExtraData}
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
			return &ber.DecodeError{Offset: offset, TypeName: "TracingBufferFullParam3", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes NoRoamingNbParam3 to BER format.
func (v *NoRoamingNbParam3) MarshalBER() ([]byte, error) {
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

// MarshalDER encodes NoRoamingNbParam3 to DER format.
func (v *NoRoamingNbParam3) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes NoRoamingNbParam3 from BER/DER format.
func (v *NoRoamingNbParam3) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding NoRoamingNbParam3 SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "NoRoamingNbParam3", Cause: ber.ErrExtraData}
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
			return &ber.DecodeError{Offset: offset, TypeName: "NoRoamingNbParam3", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes AbsentSubscriberParam3 to BER format.
func (v *AbsentSubscriberParam3) MarshalBER() ([]byte, error) {
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
		enc_absentsubscriberreason = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, false, enc_absentsubscriberreason)
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

// MarshalDER encodes AbsentSubscriberParam3 to DER format.
func (v *AbsentSubscriberParam3) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes AbsentSubscriberParam3 from BER/DER format.
func (v *AbsentSubscriberParam3) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding AbsentSubscriberParam3 SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "AbsentSubscriberParam3", Cause: ber.ErrExtraData}
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
	// Decode absentSubscriberReason
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
				_, n_absentsubscriberreason, rawVal_absentsubscriberreason, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding absentSubscriberReason: %w", err)
				}
				decVal_absentsubscriberreason, intErr := ber.DecodeIntegerValue(rawVal_absentsubscriberreason)
				if intErr != nil {
					return fmt.Errorf("decoding absentSubscriberReason: %w", intErr)
				}
				tmp_absentsubscriberreason := AbsentSubscriberReason3(decVal_absentsubscriberreason)
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
			return &ber.DecodeError{Offset: offset, TypeName: "AbsentSubscriberParam3", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes BusySubscriberParam3 to BER format.
func (v *BusySubscriberParam3) MarshalBER() ([]byte, error) {
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
		enc_ccbspossible = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, false, enc_ccbspossible)
		children = append(children, enc_ccbspossible...)
	}
	if v.CcbsBusy != nil {
		enc_ccbsbusy := ber.EncodeNull()
		enc_ccbsbusy = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, false, enc_ccbsbusy)
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

// MarshalDER encodes BusySubscriberParam3 to DER format.
func (v *BusySubscriberParam3) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes BusySubscriberParam3 from BER/DER format.
func (v *BusySubscriberParam3) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding BusySubscriberParam3 SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "BusySubscriberParam3", Cause: ber.ErrExtraData}
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
	// Decode ccbs-Busy
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
				_, n_ccbsbusy, rawVal_ccbsbusy, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding ccbs-Busy: %w", err)
				}
				_ = rawVal_ccbsbusy
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
			return &ber.DecodeError{Offset: offset, TypeName: "BusySubscriberParam3", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes NoSubscriberReplyParam3 to BER format.
func (v *NoSubscriberReplyParam3) MarshalBER() ([]byte, error) {
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

// MarshalDER encodes NoSubscriberReplyParam3 to DER format.
func (v *NoSubscriberReplyParam3) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes NoSubscriberReplyParam3 from BER/DER format.
func (v *NoSubscriberReplyParam3) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding NoSubscriberReplyParam3 SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "NoSubscriberReplyParam3", Cause: ber.ErrExtraData}
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
			return &ber.DecodeError{Offset: offset, TypeName: "NoSubscriberReplyParam3", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes ForwardingViolationParam3 to BER format.
func (v *ForwardingViolationParam3) MarshalBER() ([]byte, error) {
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

// MarshalDER encodes ForwardingViolationParam3 to DER format.
func (v *ForwardingViolationParam3) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes ForwardingViolationParam3 from BER/DER format.
func (v *ForwardingViolationParam3) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding ForwardingViolationParam3 SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "ForwardingViolationParam3", Cause: ber.ErrExtraData}
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
			return &ber.DecodeError{Offset: offset, TypeName: "ForwardingViolationParam3", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes ForwardingFailedParam3 to BER format.
func (v *ForwardingFailedParam3) MarshalBER() ([]byte, error) {
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

// MarshalDER encodes ForwardingFailedParam3 to DER format.
func (v *ForwardingFailedParam3) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes ForwardingFailedParam3 from BER/DER format.
func (v *ForwardingFailedParam3) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding ForwardingFailedParam3 SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "ForwardingFailedParam3", Cause: ber.ErrExtraData}
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
			return &ber.DecodeError{Offset: offset, TypeName: "ForwardingFailedParam3", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes ATINotAllowedParam3 to BER format.
func (v *ATINotAllowedParam3) MarshalBER() ([]byte, error) {
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

// MarshalDER encodes ATINotAllowedParam3 to DER format.
func (v *ATINotAllowedParam3) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes ATINotAllowedParam3 from BER/DER format.
func (v *ATINotAllowedParam3) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding ATINotAllowedParam3 SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "ATINotAllowedParam3", Cause: ber.ErrExtraData}
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
			return &ber.DecodeError{Offset: offset, TypeName: "ATINotAllowedParam3", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes ATSINotAllowedParam3 to BER format.
func (v *ATSINotAllowedParam3) MarshalBER() ([]byte, error) {
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

// MarshalDER encodes ATSINotAllowedParam3 to DER format.
func (v *ATSINotAllowedParam3) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes ATSINotAllowedParam3 from BER/DER format.
func (v *ATSINotAllowedParam3) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding ATSINotAllowedParam3 SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "ATSINotAllowedParam3", Cause: ber.ErrExtraData}
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
			return &ber.DecodeError{Offset: offset, TypeName: "ATSINotAllowedParam3", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes ATMNotAllowedParam3 to BER format.
func (v *ATMNotAllowedParam3) MarshalBER() ([]byte, error) {
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

// MarshalDER encodes ATMNotAllowedParam3 to DER format.
func (v *ATMNotAllowedParam3) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes ATMNotAllowedParam3 from BER/DER format.
func (v *ATMNotAllowedParam3) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding ATMNotAllowedParam3 SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "ATMNotAllowedParam3", Cause: ber.ErrExtraData}
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
			return &ber.DecodeError{Offset: offset, TypeName: "ATMNotAllowedParam3", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes IllegalSSOperationParam3 to BER format.
func (v *IllegalSSOperationParam3) MarshalBER() ([]byte, error) {
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

// MarshalDER encodes IllegalSSOperationParam3 to DER format.
func (v *IllegalSSOperationParam3) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes IllegalSSOperationParam3 from BER/DER format.
func (v *IllegalSSOperationParam3) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding IllegalSSOperationParam3 SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "IllegalSSOperationParam3", Cause: ber.ErrExtraData}
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
			return &ber.DecodeError{Offset: offset, TypeName: "IllegalSSOperationParam3", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes SSNotAvailableParam3 to BER format.
func (v *SSNotAvailableParam3) MarshalBER() ([]byte, error) {
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

// MarshalDER encodes SSNotAvailableParam3 to DER format.
func (v *SSNotAvailableParam3) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes SSNotAvailableParam3 from BER/DER format.
func (v *SSNotAvailableParam3) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding SSNotAvailableParam3 SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "SSNotAvailableParam3", Cause: ber.ErrExtraData}
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
			return &ber.DecodeError{Offset: offset, TypeName: "SSNotAvailableParam3", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes SSSubscriptionViolationParam3 to BER format.
func (v *SSSubscriptionViolationParam3) MarshalBER() ([]byte, error) {
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

// MarshalDER encodes SSSubscriptionViolationParam3 to DER format.
func (v *SSSubscriptionViolationParam3) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes SSSubscriptionViolationParam3 from BER/DER format.
func (v *SSSubscriptionViolationParam3) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding SSSubscriptionViolationParam3 SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "SSSubscriptionViolationParam3", Cause: ber.ErrExtraData}
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
			return &ber.DecodeError{Offset: offset, TypeName: "SSSubscriptionViolationParam3", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes InformationNotAvailableParam3 to BER format.
func (v *InformationNotAvailableParam3) MarshalBER() ([]byte, error) {
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

// MarshalDER encodes InformationNotAvailableParam3 to DER format.
func (v *InformationNotAvailableParam3) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes InformationNotAvailableParam3 from BER/DER format.
func (v *InformationNotAvailableParam3) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding InformationNotAvailableParam3 SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "InformationNotAvailableParam3", Cause: ber.ErrExtraData}
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
			return &ber.DecodeError{Offset: offset, TypeName: "InformationNotAvailableParam3", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes SubBusyForMTSMSParam3 to BER format.
func (v *SubBusyForMTSMSParam3) MarshalBER() ([]byte, error) {
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

// MarshalDER encodes SubBusyForMTSMSParam3 to DER format.
func (v *SubBusyForMTSMSParam3) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes SubBusyForMTSMSParam3 from BER/DER format.
func (v *SubBusyForMTSMSParam3) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding SubBusyForMTSMSParam3 SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "SubBusyForMTSMSParam3", Cause: ber.ErrExtraData}
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
			return &ber.DecodeError{Offset: offset, TypeName: "SubBusyForMTSMSParam3", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes MessageWaitListFullParam3 to BER format.
func (v *MessageWaitListFullParam3) MarshalBER() ([]byte, error) {
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

// MarshalDER encodes MessageWaitListFullParam3 to DER format.
func (v *MessageWaitListFullParam3) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes MessageWaitListFullParam3 from BER/DER format.
func (v *MessageWaitListFullParam3) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding MessageWaitListFullParam3 SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "MessageWaitListFullParam3", Cause: ber.ErrExtraData}
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
			return &ber.DecodeError{Offset: offset, TypeName: "MessageWaitListFullParam3", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes ResourceLimitationParam3 to BER format.
func (v *ResourceLimitationParam3) MarshalBER() ([]byte, error) {
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

// MarshalDER encodes ResourceLimitationParam3 to DER format.
func (v *ResourceLimitationParam3) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes ResourceLimitationParam3 from BER/DER format.
func (v *ResourceLimitationParam3) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding ResourceLimitationParam3 SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "ResourceLimitationParam3", Cause: ber.ErrExtraData}
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
			return &ber.DecodeError{Offset: offset, TypeName: "ResourceLimitationParam3", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes NoGroupCallNbParam3 to BER format.
func (v *NoGroupCallNbParam3) MarshalBER() ([]byte, error) {
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

// MarshalDER encodes NoGroupCallNbParam3 to DER format.
func (v *NoGroupCallNbParam3) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes NoGroupCallNbParam3 from BER/DER format.
func (v *NoGroupCallNbParam3) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding NoGroupCallNbParam3 SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "NoGroupCallNbParam3", Cause: ber.ErrExtraData}
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
			return &ber.DecodeError{Offset: offset, TypeName: "NoGroupCallNbParam3", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes IncompatibleTerminalParam3 to BER format.
func (v *IncompatibleTerminalParam3) MarshalBER() ([]byte, error) {
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

// MarshalDER encodes IncompatibleTerminalParam3 to DER format.
func (v *IncompatibleTerminalParam3) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes IncompatibleTerminalParam3 from BER/DER format.
func (v *IncompatibleTerminalParam3) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding IncompatibleTerminalParam3 SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "IncompatibleTerminalParam3", Cause: ber.ErrExtraData}
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
			return &ber.DecodeError{Offset: offset, TypeName: "IncompatibleTerminalParam3", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes ShortTermDenialParam3 to BER format.
func (v *ShortTermDenialParam3) MarshalBER() ([]byte, error) {
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

// MarshalDER encodes ShortTermDenialParam3 to DER format.
func (v *ShortTermDenialParam3) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes ShortTermDenialParam3 from BER/DER format.
func (v *ShortTermDenialParam3) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding ShortTermDenialParam3 SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "ShortTermDenialParam3", Cause: ber.ErrExtraData}
	}
	offset := 0
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "ShortTermDenialParam3", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes LongTermDenialParam3 to BER format.
func (v *LongTermDenialParam3) MarshalBER() ([]byte, error) {
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

// MarshalDER encodes LongTermDenialParam3 to DER format.
func (v *LongTermDenialParam3) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes LongTermDenialParam3 from BER/DER format.
func (v *LongTermDenialParam3) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding LongTermDenialParam3 SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "LongTermDenialParam3", Cause: ber.ErrExtraData}
	}
	offset := 0
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "LongTermDenialParam3", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes UnauthorizedRequestingNetworkParam3 to BER format.
func (v *UnauthorizedRequestingNetworkParam3) MarshalBER() ([]byte, error) {
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

// MarshalDER encodes UnauthorizedRequestingNetworkParam3 to DER format.
func (v *UnauthorizedRequestingNetworkParam3) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes UnauthorizedRequestingNetworkParam3 from BER/DER format.
func (v *UnauthorizedRequestingNetworkParam3) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding UnauthorizedRequestingNetworkParam3 SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "UnauthorizedRequestingNetworkParam3", Cause: ber.ErrExtraData}
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
			return &ber.DecodeError{Offset: offset, TypeName: "UnauthorizedRequestingNetworkParam3", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes UnauthorizedLCSClientParam3 to BER format.
func (v *UnauthorizedLCSClientParam3) MarshalBER() ([]byte, error) {
	var children []byte
	if v.UnauthorizedLCSClientDiagnostic != nil {
		enc_unauthorizedlcsclientdiagnostic := ber.EncodeEnumerated(int64(*v.UnauthorizedLCSClientDiagnostic))
		enc_unauthorizedlcsclientdiagnostic = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, false, enc_unauthorizedlcsclientdiagnostic)
		children = append(children, enc_unauthorizedlcsclientdiagnostic...)
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

// MarshalDER encodes UnauthorizedLCSClientParam3 to DER format.
func (v *UnauthorizedLCSClientParam3) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes UnauthorizedLCSClientParam3 from BER/DER format.
func (v *UnauthorizedLCSClientParam3) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding UnauthorizedLCSClientParam3 SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "UnauthorizedLCSClientParam3", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode unauthorizedLCSClient-Diagnostic
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
				_, n_unauthorizedlcsclientdiagnostic, rawVal_unauthorizedlcsclientdiagnostic, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding unauthorizedLCSClient-Diagnostic: %w", err)
				}
				decVal_unauthorizedlcsclientdiagnostic, intErr := ber.DecodeIntegerValue(rawVal_unauthorizedlcsclientdiagnostic)
				if intErr != nil {
					return fmt.Errorf("decoding unauthorizedLCSClient-Diagnostic: %w", intErr)
				}
				tmp_unauthorizedlcsclientdiagnostic := UnauthorizedLCSClientDiagnostic3(decVal_unauthorizedlcsclientdiagnostic)
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
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "UnauthorizedLCSClientParam3", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes PositionMethodFailureParam3 to BER format.
func (v *PositionMethodFailureParam3) MarshalBER() ([]byte, error) {
	var children []byte
	if v.PositionMethodFailureDiagnostic != nil {
		enc_positionmethodfailurediagnostic := ber.EncodeEnumerated(int64(*v.PositionMethodFailureDiagnostic))
		enc_positionmethodfailurediagnostic = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, false, enc_positionmethodfailurediagnostic)
		children = append(children, enc_positionmethodfailurediagnostic...)
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

// MarshalDER encodes PositionMethodFailureParam3 to DER format.
func (v *PositionMethodFailureParam3) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes PositionMethodFailureParam3 from BER/DER format.
func (v *PositionMethodFailureParam3) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding PositionMethodFailureParam3 SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "PositionMethodFailureParam3", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode positionMethodFailure-Diagnostic
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
				_, n_positionmethodfailurediagnostic, rawVal_positionmethodfailurediagnostic, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding positionMethodFailure-Diagnostic: %w", err)
				}
				decVal_positionmethodfailurediagnostic, intErr := ber.DecodeIntegerValue(rawVal_positionmethodfailurediagnostic)
				if intErr != nil {
					return fmt.Errorf("decoding positionMethodFailure-Diagnostic: %w", intErr)
				}
				tmp_positionmethodfailurediagnostic := PositionMethodFailureDiagnostic3(decVal_positionmethodfailurediagnostic)
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
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "PositionMethodFailureParam3", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes UnknownOrUnreachableLCSClientParam3 to BER format.
func (v *UnknownOrUnreachableLCSClientParam3) MarshalBER() ([]byte, error) {
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

// MarshalDER encodes UnknownOrUnreachableLCSClientParam3 to DER format.
func (v *UnknownOrUnreachableLCSClientParam3) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes UnknownOrUnreachableLCSClientParam3 from BER/DER format.
func (v *UnknownOrUnreachableLCSClientParam3) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding UnknownOrUnreachableLCSClientParam3 SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "UnknownOrUnreachableLCSClientParam3", Cause: ber.ErrExtraData}
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
			return &ber.DecodeError{Offset: offset, TypeName: "UnknownOrUnreachableLCSClientParam3", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes MMEventNotSupportedParam3 to BER format.
func (v *MMEventNotSupportedParam3) MarshalBER() ([]byte, error) {
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

// MarshalDER encodes MMEventNotSupportedParam3 to DER format.
func (v *MMEventNotSupportedParam3) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes MMEventNotSupportedParam3 from BER/DER format.
func (v *MMEventNotSupportedParam3) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding MMEventNotSupportedParam3 SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "MMEventNotSupportedParam3", Cause: ber.ErrExtraData}
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
			return &ber.DecodeError{Offset: offset, TypeName: "MMEventNotSupportedParam3", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes TargetCellOutsideGCAParam3 to BER format.
func (v *TargetCellOutsideGCAParam3) MarshalBER() ([]byte, error) {
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

// MarshalDER encodes TargetCellOutsideGCAParam3 to DER format.
func (v *TargetCellOutsideGCAParam3) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes TargetCellOutsideGCAParam3 from BER/DER format.
func (v *TargetCellOutsideGCAParam3) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding TargetCellOutsideGCAParam3 SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "TargetCellOutsideGCAParam3", Cause: ber.ErrExtraData}
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
			return &ber.DecodeError{Offset: offset, TypeName: "TargetCellOutsideGCAParam3", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes OngoingGroupCallParam3 to BER format.
func (v *OngoingGroupCallParam3) MarshalBER() ([]byte, error) {
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

// MarshalDER encodes OngoingGroupCallParam3 to DER format.
func (v *OngoingGroupCallParam3) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes OngoingGroupCallParam3 from BER/DER format.
func (v *OngoingGroupCallParam3) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding OngoingGroupCallParam3 SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "OngoingGroupCallParam3", Cause: ber.ErrExtraData}
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
			return &ber.DecodeError{Offset: offset, TypeName: "OngoingGroupCallParam3", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}
